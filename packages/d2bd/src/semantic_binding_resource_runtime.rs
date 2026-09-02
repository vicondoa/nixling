//! Core-owned reconciliation for non-audio semantic Binding children.
//!
//! Provider controllers remain the authority for their Service and Binding
//! semantics. Telemetry Service/Binding rows use the shared Runner and the
//! authenticated ResourceService path; the remaining Device Binding
//! compatibility lane is isolated under its explicitly named watcher.

use std::{collections::BTreeSet, sync::Arc};

use d2b_contracts_provider::v3::semantic_services::{
    SemanticFamily, child_resources::BindingChildSet,
    security_key::SECURITY_KEY_BINDING_RESOURCE_TYPE, telemetry::TELEMETRY_BINDING_RESOURCE_TYPE,
    usb::USB_BINDING_RESOURCE_TYPE,
};
use d2b_contracts_resource::v3::{
    CanonicalJsonValue, ResourceEnvelope, ResourceRef, ResourceTypeName, ZoneId,
};
use d2b_core_controller::{
    ControllerDescriptor, ControllerExecutionPolicy, ControllerIdentity, ControllerSelector,
    ControllerVerb, DependencySnapshot, DrainResult, FinalizeResult, HandlerFailure,
    ObservationResult, ReconcileContext, ReconcilePlan, ReconcileReason, ReconcileResult,
    ResourceReconciler, ResourceRegistration, ResourceSnapshot, ResyncPolicy, SelectorField,
    UpdateAssessment, UpdateAssessmentState, UpgradePlan, UpgradeStage, ValidationResult,
};
use d2b_provider_device_security_key::SecurityKeyController;
use d2b_provider_device_usbip::binding_child_resources;
use d2b_provider_observability_otel::TelemetryBindingController;
use d2b_resource_api::{
    RedbBackend, ResourceApiClient, service::UnavailableUpgradeDispatcher, watch::ResourceWatch,
};
use d2b_resource_store::{
    StoreListRequest, StoreOperationContext, StoreProjection, StoreWatchRequest, StoredResource,
};
use d2b_resource_store_redb::RedbResourceStore;

use crate::binding_child_resource_runtime::{
    BindingChildOwner, binding_children_ready, has_binding_child_finalizer, list_binding_children,
    reconcile_binding_children, update_binding_child_finalizer,
};

type SemanticBindingDescriptor = (&'static str, &'static str, &'static str, SemanticFamily);

const SEMANTIC_BINDINGS: [SemanticBindingDescriptor; 2] = [
    (
        "usb.d2bus.org.UsbService",
        USB_BINDING_RESOURCE_TYPE,
        "Provider/device-usbip",
        SemanticFamily::Usb,
    ),
    (
        "security-key.d2bus.org.SecurityKeyService",
        SECURITY_KEY_BINDING_RESOURCE_TYPE,
        "Provider/device-security-key",
        SemanticFamily::SecurityKey,
    ),
];

const TELEMETRY_BINDING: SemanticBindingDescriptor = (
    "telemetry.d2bus.org.TelemetryService",
    TELEMETRY_BINDING_RESOURCE_TYPE,
    "Provider/observability-otel",
    SemanticFamily::Telemetry,
);

/// Stable failures from the semantic Binding child adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SemanticBindingRuntimeError {
    /// A resource body or reference was malformed.
    InvalidResource,
    /// A Binding's Service or target relationship was not admitted.
    InvalidRelationship,
    /// The backing store could not be relisted.
    Store,
    /// Core rejected the desired child set or a mutation failed.
    Reconcile,
}

impl core::fmt::Display for SemanticBindingRuntimeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidResource => "semantic-binding-resource-invalid",
            Self::InvalidRelationship => "semantic-binding-relationship-invalid",
            Self::Store => "semantic-binding-store-failed",
            Self::Reconcile => "semantic-binding-reconcile-failed",
        })
    }
}

impl std::error::Error for SemanticBindingRuntimeError {}

/// Build the signed descriptor used by the shared Runner for telemetry
/// Service/Binding rows.
pub(crate) fn telemetry_controller_descriptor(
    identity: ControllerIdentity,
) -> Result<ControllerDescriptor, SemanticBindingRuntimeError> {
    let resources = [TELEMETRY_BINDING.0, TELEMETRY_BINDING.1]
        .into_iter()
        .map(|resource_type| {
            ResourceRegistration::new(
                ResourceTypeName::parse(resource_type)
                    .expect("telemetry ResourceType is canonical"),
                vec![1],
                5_000,
                3,
            )
            .map_err(|_| SemanticBindingRuntimeError::InvalidResource)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let selectors = resources
        .iter()
        .flat_map(|resource| {
            [
                SelectorField::Spec,
                SelectorField::Status,
                SelectorField::Metadata,
                SelectorField::Finalizers,
                SelectorField::Deletion,
            ]
            .into_iter()
            .map(move |field| {
                ControllerSelector::new(resource.resource_type().clone(), field, None)
                    .expect("telemetry selector is bounded")
            })
        })
        .collect::<Vec<_>>();
    ControllerDescriptor::new(
        identity,
        resources,
        vec!["resource-service".to_owned(), "telemetry-stream".to_owned()],
        vec!["system".to_owned()],
        vec![
            ControllerVerb::ReadSpec,
            ControllerVerb::ReadStatus,
            ControllerVerb::WriteStatus,
            ControllerVerb::AddFinalizer,
            ControllerVerb::RemoveFinalizer,
        ],
        selectors,
        Vec::new(),
        true,
        vec![crate::binding_child_resource_runtime::BINDING_CHILD_FINALIZER.to_owned()],
        vec!["telemetry.d2bus.org/telemetry-controller.v1".to_owned()],
        vec!["sha256:0000000000000000000000000000000000000000000000000000000000000001"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        ControllerExecutionPolicy::new(
            1,
            1,
            256,
            8,
            256,
            ResyncPolicy::new(None, 5_000).expect("telemetry resync policy"),
        )
        .map_err(|_| SemanticBindingRuntimeError::InvalidResource)?,
    )
    .map_err(|_| SemanticBindingRuntimeError::InvalidResource)
}

/// ResourceService-backed telemetry handler for the shared Runner.
pub(crate) struct TelemetryResourceReconciler {
    store: Arc<RedbResourceStore>,
    client: Arc<ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>>,
    reconcile_lock: Arc<tokio::sync::Mutex<()>>,
    identity: ControllerIdentity,
}

impl TelemetryResourceReconciler {
    pub(crate) fn new(
        store: Arc<RedbResourceStore>,
        client: Arc<ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>>,
        identity: ControllerIdentity,
    ) -> Self {
        Self {
            store,
            client,
            reconcile_lock: Arc::new(tokio::sync::Mutex::new(())),
            identity,
        }
    }

    async fn reconcile_snapshot(&self) -> Result<(), SemanticBindingRuntimeError> {
        let _guard = self.reconcile_lock.lock().await;
        reconcile_telemetry_binding_resources(
            &self.store,
            &self.client,
            &self.store.identity().zone(),
        )
        .await
    }

    fn target_is_telemetry(target: &ResourceSnapshot) -> bool {
        matches!(
            target.key().resource_ref().resource_type().as_str(),
            TELEMETRY_BINDING_RESOURCE_TYPE | "telemetry.d2bus.org.TelemetryService"
        )
    }
}

impl ResourceReconciler for TelemetryResourceReconciler {
    type Error = SemanticBindingRuntimeError;

    fn classify_error(&self, _error: &Self::Error) -> HandlerFailure {
        HandlerFailure::retryable()
    }

    fn describe(
        &self,
    ) -> impl std::future::Future<Output = Result<ControllerDescriptor, Self::Error>> + Send {
        std::future::ready(telemetry_controller_descriptor(self.identity.clone()))
    }

    fn validate_spec(
        &self,
        _context: &ReconcileContext,
        resource: &ResourceSnapshot,
    ) -> impl std::future::Future<Output = Result<ValidationResult, Self::Error>> + Send {
        let result = if !Self::target_is_telemetry(resource) {
            ValidationResult::Invalid {
                reason: ReconcileReason::InvalidSpec,
            }
        } else if ResourceEnvelope::from_json(resource.canonical_json()).is_ok() {
            ValidationResult::Valid
        } else {
            ValidationResult::Invalid {
                reason: ReconcileReason::InvalidSpec,
            }
        };
        std::future::ready(Ok(result))
    }

    fn plan(
        &self,
        _context: &ReconcileContext,
        resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
    ) -> impl std::future::Future<Output = Result<ReconcilePlan, Self::Error>> + Send {
        let result = ReconcilePlan::new(
            vec![format!(
                "telemetry-resource:{}",
                resource.key().resource_ref().resource_type().as_str()
            )],
            false,
        )
        .map_err(|_| SemanticBindingRuntimeError::InvalidResource);
        std::future::ready(result)
    }

    fn reconcile(
        &self,
        context: &ReconcileContext,
        _resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
        _plan: &ReconcilePlan,
    ) -> impl std::future::Future<Output = Result<ReconcileResult, Self::Error>> + Send {
        let result = context
            .authorize_effect()
            .map(|_| ReconcileResult::converged(context.revision(), context.generation()))
            .map_err(|_| SemanticBindingRuntimeError::InvalidResource);
        std::future::ready(result)
    }

    fn execute_effect(
        &self,
        _context: &ReconcileContext,
        _resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
        _plan: &ReconcilePlan,
    ) -> impl std::future::Future<Output = Result<ReconcileResult, Self::Error>> + Send {
        let future = async move {
            self.reconcile_snapshot().await?;
            Ok(ReconcileResult::converged(
                _resource.revision(),
                _resource.generation(),
            ))
        };
        future
    }

    fn observe(
        &self,
        _context: &ReconcileContext,
        resource: &ResourceSnapshot,
    ) -> impl std::future::Future<Output = Result<ObservationResult, Self::Error>> + Send {
        std::future::ready(Ok(ObservationResult::new(ReconcileResult::converged(
            resource.revision(),
            resource.generation(),
        ))))
    }

    fn finalize(
        &self,
        _context: &ReconcileContext,
        resource: &ResourceSnapshot,
    ) -> impl std::future::Future<Output = Result<FinalizeResult, Self::Error>> + Send {
        std::future::ready(Ok(FinalizeResult::new(ReconcileResult::converged(
            resource.revision(),
            resource.generation(),
        ))))
    }

    fn execute_finalize(
        &self,
        _context: &ReconcileContext,
        resource: &ResourceSnapshot,
    ) -> impl std::future::Future<Output = Result<ReconcileResult, Self::Error>> + Send {
        let future = async move {
            self.reconcile_snapshot().await?;
            Ok(ReconcileResult::converged(
                resource.revision(),
                resource.generation(),
            ))
        };
        future
    }

    fn health(
        &self,
    ) -> impl std::future::Future<
        Output = Result<d2b_core_controller::ControllerHealth, Self::Error>,
    > + Send {
        std::future::ready(Ok(d2b_core_controller::ControllerHealth::Healthy))
    }

    fn drain(
        &self,
        _deadline_tick: u64,
    ) -> impl std::future::Future<Output = Result<DrainResult, Self::Error>> + Send {
        std::future::ready(Ok(DrainResult::Drained))
    }

    fn assess_update(
        &self,
        _context: &ReconcileContext,
        _resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
    ) -> impl std::future::Future<Output = Result<UpdateAssessment, Self::Error>> + Send {
        std::future::ready(
            UpdateAssessment::new(UpdateAssessmentState::Current, Vec::new(), true)
                .map_err(|_| SemanticBindingRuntimeError::InvalidResource),
        )
    }

    fn plan_upgrade(
        &self,
        _context: &ReconcileContext,
        resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
    ) -> impl std::future::Future<Output = Result<UpgradePlan, Self::Error>> + Send {
        std::future::ready(
            UpgradePlan::new(
                d2b_core_controller::DisruptionClass::Restart,
                true,
                vec![UpgradeStage::Restart(resource.key().resource_ref().clone())],
            )
            .map_err(|_| SemanticBindingRuntimeError::InvalidResource),
        )
    }

    fn execute_upgrade(
        &self,
        _context: &ReconcileContext,
        resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
        _plan: &UpgradePlan,
    ) -> impl std::future::Future<Output = Result<ReconcileResult, Self::Error>> + Send {
        std::future::ready(Ok(ReconcileResult::converged(
            resource.revision(),
            resource.generation(),
        )))
    }
}

async fn list_binding_owners_for(
    store: &RedbResourceStore,
    zone: &ZoneId,
    descriptors: &[SemanticBindingDescriptor],
) -> Result<Vec<BindingChildOwner>, SemanticBindingRuntimeError> {
    let mut services = BTreeSet::new();
    let mut targets = BTreeSet::new();
    let mut bindings = Vec::new();
    for (service_type, binding_type, expected_provider, _) in descriptors {
        for resource in list_resources(
            store,
            zone,
            ResourceTypeName::parse(*service_type).expect("closed semantic Service type"),
            "service",
        )
        .await?
        {
            if !deletion_requested(&resource)
                && binding_provider_ref(&resource).ok().flatten().as_deref()
                    == Some(*expected_provider)
            {
                services.insert(resource.resource_ref);
            }
        }
        bindings.extend(
            list_resources(
                store,
                zone,
                ResourceTypeName::parse(*binding_type).expect("closed semantic Binding type"),
                "binding",
            )
            .await?,
        );
    }
    for resource_type in ["Guest", "User", "Zone"] {
        for resource in list_resources(
            store,
            zone,
            ResourceTypeName::parse(resource_type).expect("closed target ResourceType"),
            "target",
        )
        .await?
        {
            if !deletion_requested(&resource) {
                targets.insert(resource.resource_ref);
            }
        }
    }

    let mut owners = Vec::with_capacity(bindings.len());
    for resource in bindings {
        if resource.zone != *zone {
            owners.push(fenced_owner(resource));
            continue;
        }
        let family = match semantic_family(&resource) {
            Ok(family) => family,
            Err(_) => {
                owners.push(fenced_owner(resource));
                continue;
            }
        };
        let expected_provider = descriptors
            .iter()
            .find(|(_, _, _, candidate)| *candidate == family)
            .map(|(_, _, provider, _)| *provider)
            .ok_or(SemanticBindingRuntimeError::InvalidResource)?;
        let provider_ref = match binding_provider_ref(&resource) {
            Ok(Some(provider_ref)) => provider_ref,
            Ok(None) | Err(_) => {
                owners.push(fenced_owner(resource));
                continue;
            }
        };
        if provider_ref != expected_provider {
            continue;
        }
        if deletion_requested(&resource) {
            owners.push(BindingChildOwner {
                resource,
                desired: None,
                fenced: false,
            });
            continue;
        }
        let (_, service_ref, target_ref) = match binding_relationship(&resource) {
            Ok(relationship) => relationship,
            Err(_) => {
                owners.push(fenced_owner(resource));
                continue;
            }
        };
        let user_ref = if family == SemanticFamily::SecurityKey {
            match binding_user_ref(&resource) {
                Ok(user_ref) => user_ref,
                Err(_) => {
                    owners.push(fenced_owner(resource));
                    continue;
                }
            }
        } else {
            None
        };
        if !services.contains(&service_ref)
            || !targets.contains(&target_ref)
            || user_ref
                .as_ref()
                .is_some_and(|user_ref| !targets.contains(user_ref))
        {
            owners.push(fenced_owner(resource));
            continue;
        }
        let children = match family {
            SemanticFamily::Usb => {
                binding_child_resources(&resource.resource_ref, &service_ref, &target_ref)
                    .map_err(|_| SemanticBindingRuntimeError::InvalidRelationship)
            }
            SemanticFamily::SecurityKey => user_ref
                .as_ref()
                .ok_or(SemanticBindingRuntimeError::InvalidRelationship)
                .and_then(|user_ref| {
                    SecurityKeyController::child_resources_for_user(
                        &resource.resource_ref,
                        &service_ref,
                        &target_ref,
                        user_ref,
                    )
                    .map_err(|_| SemanticBindingRuntimeError::InvalidRelationship)
                }),
            SemanticFamily::Telemetry => TelemetryBindingController::child_resources(
                &resource.resource_ref,
                &service_ref,
                &target_ref,
            )
            .map_err(|_| SemanticBindingRuntimeError::InvalidRelationship),
            _ => Err(SemanticBindingRuntimeError::InvalidResource),
        };
        match children {
            Ok(children) => owners.push(BindingChildOwner {
                resource,
                desired: Some(children),
                fenced: false,
            }),
            Err(_) => owners.push(fenced_owner(resource)),
        }
    }
    Ok(owners)
}

fn fenced_owner(resource: StoredResource) -> BindingChildOwner {
    BindingChildOwner {
        resource,
        desired: None,
        fenced: true,
    }
}

/// Relist and reconcile all non-audio semantic Binding children once.
pub(crate) async fn reconcile_semantic_binding_resources(
    store: &RedbResourceStore,
    client: &ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>,
    zone: &ZoneId,
) -> Result<(), SemanticBindingRuntimeError> {
    reconcile_binding_owner_set(store, client, zone, &SEMANTIC_BINDINGS).await
}

/// Relist and reconcile telemetry Service/Binding children through the
/// ResourceService-backed shared controller lane.
pub(crate) async fn reconcile_telemetry_binding_resources(
    store: &RedbResourceStore,
    client: &ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>,
    zone: &ZoneId,
) -> Result<(), SemanticBindingRuntimeError> {
    reconcile_telemetry_services(store, client, zone).await?;
    reconcile_binding_owner_set(store, client, zone, &[TELEMETRY_BINDING]).await
}

async fn reconcile_telemetry_services(
    store: &RedbResourceStore,
    client: &ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>,
    zone: &ZoneId,
) -> Result<(), SemanticBindingRuntimeError> {
    let services = list_resources(
        store,
        zone,
        ResourceTypeName::parse(TELEMETRY_BINDING.0).expect("telemetry Service type"),
        "telemetry-service",
    )
    .await?;
    let endpoints = list_resources(
        store,
        zone,
        ResourceTypeName::parse("Endpoint").expect("Endpoint type"),
        "telemetry-service-endpoints",
    )
    .await?;
    for service in services {
        let (phase, projection) = telemetry_service_status(&service, &endpoints);
        let resource = sanitized_status_resource(&service)?;
        crate::resource_runtime::persist_resource_status_with_projection(
            client,
            &resource,
            &serde_json::json!({ "phase": phase }),
            Some(&projection),
        )
        .await
        .map_err(|_| SemanticBindingRuntimeError::Reconcile)?;
    }
    Ok(())
}

fn telemetry_service_status(
    service: &StoredResource,
    endpoints: &[StoredResource],
) -> (&'static str, serde_json::Value) {
    let Ok(envelope) = ResourceEnvelope::from_json(&service.canonical_json) else {
        return ("Degraded", serde_json::json!({}));
    };
    let Ok(spec) =
        serde_json::from_slice::<serde_json::Value>(&envelope.spec().base().to_canonical_bytes())
    else {
        return ("Degraded", serde_json::json!({}));
    };
    let role = match spec.get("serviceRole").and_then(serde_json::Value::as_str) {
        Some("authority") | Some("projection") => spec
            .get("serviceRole")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("authority"),
        _ => return ("Degraded", serde_json::json!({})),
    };
    if role == "projection" {
        return (
            "Ready",
            serde_json::json!({
                "serviceRole": "projection",
                "serviceReadiness": "Ready"
            }),
        );
    }
    let refs = spec
        .get("ingestEndpointRefs")
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|value| {
                    value
                        .as_str()
                        .and_then(|value| ResourceRef::parse(value).ok())
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let ready = !refs.is_empty()
        && refs.iter().all(|endpoint_ref| {
            endpoints.iter().any(|endpoint| {
                endpoint.resource_ref == *endpoint_ref
                    && !deletion_requested(endpoint)
                    && status_ready(endpoint)
            })
        });
    let phase = if ready { "Ready" } else { "Pending" };
    (
        phase,
        serde_json::json!({
            "serviceRole": "authority",
            "serviceReadiness": phase
        }),
    )
}

fn status_ready(resource: &StoredResource) -> bool {
    serde_json::from_slice::<serde_json::Value>(&resource.canonical_json)
        .ok()
        .and_then(|value| value.pointer("/status/phase").cloned())
        .and_then(|value| value.as_str().map(|value| value == "Ready"))
        .unwrap_or(false)
}

async fn reconcile_binding_owner_set(
    store: &RedbResourceStore,
    client: &ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>,
    zone: &ZoneId,
    descriptors: &[SemanticBindingDescriptor],
) -> Result<(), SemanticBindingRuntimeError> {
    let owners = list_binding_owners_for(store, zone, descriptors).await?;
    for owner in &owners {
        if owner.desired.is_some() && !owner.fenced {
            update_binding_child_finalizer(client, &owner.resource, true)
                .await
                .map_err(|_| SemanticBindingRuntimeError::Reconcile)?;
        }
    }
    let converged = reconcile_binding_children(store, client, zone, &owners)
        .await
        .map_err(|_| SemanticBindingRuntimeError::Reconcile)?;
    let children = list_binding_children(store, zone)
        .await
        .map_err(|_| SemanticBindingRuntimeError::Reconcile)?;

    // Finalizer removal is deliberately a second phase: all owned children
    // must be absent after their own finalizers have drained.
    for owner in &owners {
        if !owner.fenced
            && owner.desired.is_none()
            && converged.contains(&owner.resource.resource_ref)
            && has_binding_child_finalizer(&owner.resource)
        {
            update_binding_child_finalizer(client, &owner.resource, false)
                .await
                .map_err(|_| SemanticBindingRuntimeError::Reconcile)?;
        }
    }

    // Finalizer updates advance the parent revision, so relist before writing
    // the layered Binding status with an exact UID/revision precondition.
    let refreshed = list_binding_owners_for(store, zone, descriptors).await?;
    for owner in &refreshed {
        if owner.fenced {
            if let Err(error) = persist_fenced_binding_status(client, owner).await {
                tracing::warn!(
                    error = %error,
                    binding = %owner.resource.resource_ref,
                    "fenced semantic Binding status persistence failed"
                );
            }
            continue;
        }
        let Some(desired) = owner.desired.as_ref() else {
            continue;
        };
        let converged = converged.contains(&owner.resource.resource_ref);
        let ready = converged && binding_children_ready(owner, &children);
        persist_semantic_binding_status(client, owner, desired, converged, ready).await?;
    }
    Ok(())
}

async fn persist_fenced_binding_status(
    client: &ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>,
    owner: &BindingChildOwner,
) -> Result<(), SemanticBindingRuntimeError> {
    let family = semantic_family(&owner.resource)?;
    let status = serde_json::json!({ "phase": "Degraded" });
    let projection = semantic_binding_status_projection(family, "Degraded");
    let resource = sanitized_status_resource(&owner.resource)?;
    crate::resource_runtime::persist_resource_status_with_projection(
        client,
        &resource,
        &status,
        Some(&projection),
    )
    .await
    .map_err(|_| SemanticBindingRuntimeError::Reconcile)
}

async fn persist_semantic_binding_status(
    client: &ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>,
    owner: &BindingChildOwner,
    desired: &BindingChildSet,
    converged: bool,
    ready: bool,
) -> Result<(), SemanticBindingRuntimeError> {
    let phase = if ready {
        "Ready"
    } else if converged {
        "Degraded"
    } else {
        "Pending"
    };
    let status = serde_json::json!({ "phase": phase });
    let projection = semantic_binding_status_projection(desired.family(), phase);
    let resource = sanitized_status_resource(&owner.resource)?;
    crate::resource_runtime::persist_resource_status_with_projection(
        client,
        &resource,
        &status,
        Some(&projection),
    )
    .await
    .map_err(|_| SemanticBindingRuntimeError::Reconcile)
}

fn sanitized_status_resource(
    resource: &StoredResource,
) -> Result<StoredResource, SemanticBindingRuntimeError> {
    let mut value = serde_json::from_slice::<serde_json::Value>(&resource.canonical_json)
        .map_err(|_| SemanticBindingRuntimeError::InvalidResource)?;
    if let Some(status) = value.get_mut("status") {
        redact_json_fields(status);
    }
    let canonical = CanonicalJsonValue::parse(
        &serde_json::to_vec(&value).map_err(|_| SemanticBindingRuntimeError::InvalidResource)?,
    )
    .map_err(|_| SemanticBindingRuntimeError::InvalidResource)?
    .to_canonical_bytes();
    let envelope = ResourceEnvelope::from_json(&canonical)
        .map_err(|_| SemanticBindingRuntimeError::InvalidResource)?;
    let mut sanitized = resource.clone();
    sanitized.canonical_json = canonical;
    sanitized.payload_digest = envelope
        .digest()
        .map_err(|_| SemanticBindingRuntimeError::InvalidResource)?;
    Ok(sanitized)
}

fn redact_json_fields(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(object) => {
            let keys = object
                .iter()
                .filter_map(|(key, value)| {
                    (is_sensitive_key(key) || contains_sensitive_text(value)).then_some(key.clone())
                })
                .collect::<Vec<_>>();
            for key in keys {
                object.remove(&key);
            }
            for value in object.values_mut() {
                redact_json_fields(value);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                redact_json_fields(value);
            }
        }
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => {}
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        "credential",
        "secret",
        "token",
        "password",
        "privatekey",
        "accesskey",
        "apikey",
        "rawkey",
    ]
    .iter()
    .any(|part| key == *part || key.contains(part))
}

fn contains_sensitive_text(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(value) => {
            let value = value.to_ascii_lowercase();
            value.contains("-----begin")
                || value.contains("bearer ")
                || value.contains("secret")
                || value.contains("credential")
                || value.contains("privatekey")
                || value.contains("?sv=") && value.contains("&sig=")
        }
        serde_json::Value::Array(values) => values.iter().any(contains_sensitive_text),
        serde_json::Value::Object(values) => values.values().any(contains_sensitive_text),
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
            false
        }
    }
}

fn semantic_binding_status_projection(family: SemanticFamily, phase: &str) -> serde_json::Value {
    match family {
        SemanticFamily::Usb => serde_json::json!({ "attachmentPhase": phase }),
        SemanticFamily::SecurityKey => serde_json::json!({
            "attachment": { "phase": phase }
        }),
        SemanticFamily::Telemetry => serde_json::json!({}),
        SemanticFamily::Audio => serde_json::json!({}),
        _ => serde_json::json!({}),
    }
}

/// Build a watch covering authored semantic Bindings, their Services, and
/// Core-owned child resources.
pub(crate) fn device_binding_watch_request(zone: &ZoneId) -> StoreWatchRequest {
    let mut resource_types = Vec::with_capacity(9);
    for (service_type, binding_type, _, _) in SEMANTIC_BINDINGS {
        resource_types
            .push(ResourceTypeName::parse(service_type).expect("closed semantic Service type"));
        resource_types
            .push(ResourceTypeName::parse(binding_type).expect("closed semantic Binding type"));
    }
    resource_types.extend(
        ["Process", "EphemeralProcess", "Endpoint"]
            .into_iter()
            .map(|resource_type| {
                ResourceTypeName::parse(resource_type).expect("closed child type")
            }),
    );
    StoreWatchRequest {
        operation: StoreOperationContext {
            operation_id: "semantic-binding-resource-watch".to_owned(),
            idempotency_key: None,
            correlation_id: "semantic-binding-resource-watch".to_owned(),
            trace_id: None,
            deadline_ms: 10_000,
        },
        zone: zone.clone(),
        resource_types,
        resource_names: Vec::new(),
        filters: Vec::new(),
        after_revision: d2b_contracts_resource::v3::ZoneRevision::new(0),
        initial_credits: 64,
        projection: StoreProjection::Full,
    }
}

/// Run the watch-driven Device Binding reconciliation loop.
pub(crate) async fn run_device_binding_watch(
    mut watch: ResourceWatch,
    store: std::sync::Arc<RedbResourceStore>,
    zone: ZoneId,
    client: std::sync::Arc<ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>>,
) {
    loop {
        let Some(batch) = watch.recv().await else {
            if watch.resume().await.is_err() {
                return;
            }
            continue;
        };
        let revision = batch.revision();
        if let Err(error) =
            reconcile_semantic_binding_resources(&store, client.as_ref(), &zone).await
        {
            tracing::warn!(
                error = %error,
                "semantic Binding child reconciliation failed after watch event"
            );
            if watch.resume().await.is_err() {
                return;
            }
            continue;
        }
        if watch.acknowledge(revision).await.is_err() && watch.resume().await.is_err() {
            return;
        }
    }
}

fn binding_relationship(
    resource: &StoredResource,
) -> Result<(SemanticFamily, ResourceRef, ResourceRef), SemanticBindingRuntimeError> {
    let envelope = ResourceEnvelope::from_json(&resource.canonical_json)
        .map_err(|_| SemanticBindingRuntimeError::InvalidResource)?;
    let spec: serde_json::Value =
        serde_json::from_slice(&envelope.spec().base().to_canonical_bytes())
            .map_err(|_| SemanticBindingRuntimeError::InvalidResource)?;
    let family = semantic_family(resource)?;
    let service_ref = value_ref(spec.get("serviceRef"))?;
    let target = match family {
        SemanticFamily::Usb => value_ref(spec.get("guestRef"))?,
        SemanticFamily::SecurityKey => {
            let target = spec
                .get("target")
                .and_then(serde_json::Value::as_object)
                .ok_or(SemanticBindingRuntimeError::InvalidResource)?;
            value_ref(target.get("guestRef"))?
        }
        SemanticFamily::Telemetry => value_ref(spec.get("producerRef"))?,
        SemanticFamily::Audio => {
            return Err(SemanticBindingRuntimeError::InvalidRelationship);
        }
        _ => return Err(SemanticBindingRuntimeError::InvalidResource),
    };
    Ok((family, service_ref, target))
}

fn semantic_family(
    resource: &StoredResource,
) -> Result<SemanticFamily, SemanticBindingRuntimeError> {
    SEMANTIC_BINDINGS
        .iter()
        .chain(std::iter::once(&TELEMETRY_BINDING))
        .find(|(_, binding_type, _, _)| {
            resource.resource_ref.resource_type().as_str() == *binding_type
        })
        .map(|(_, _, _, family)| *family)
        .ok_or(SemanticBindingRuntimeError::InvalidResource)
}

fn binding_user_ref(
    resource: &StoredResource,
) -> Result<Option<ResourceRef>, SemanticBindingRuntimeError> {
    let envelope = ResourceEnvelope::from_json(&resource.canonical_json)
        .map_err(|_| SemanticBindingRuntimeError::InvalidResource)?;
    let spec: serde_json::Value =
        serde_json::from_slice(&envelope.spec().base().to_canonical_bytes())
            .map_err(|_| SemanticBindingRuntimeError::InvalidResource)?;
    let Some(target) = spec.get("target").and_then(serde_json::Value::as_object) else {
        return Ok(None);
    };
    let Some(value) = target.get("userRef") else {
        return Ok(None);
    };
    Ok(Some(value_ref(Some(value))?))
}

fn binding_provider_ref(
    resource: &StoredResource,
) -> Result<Option<String>, SemanticBindingRuntimeError> {
    let envelope = ResourceEnvelope::from_json(&resource.canonical_json)
        .map_err(|_| SemanticBindingRuntimeError::InvalidResource)?;
    Ok(envelope
        .spec()
        .provider_ref()
        .map(ResourceRef::to_canonical_string))
}

fn value_ref(
    value: Option<&serde_json::Value>,
) -> Result<ResourceRef, SemanticBindingRuntimeError> {
    let value = value
        .and_then(serde_json::Value::as_str)
        .ok_or(SemanticBindingRuntimeError::InvalidResource)?;
    ResourceRef::parse(value).map_err(|_| SemanticBindingRuntimeError::InvalidResource)
}

fn deletion_requested(resource: &StoredResource) -> bool {
    serde_json::from_slice::<serde_json::Value>(&resource.canonical_json)
        .ok()
        .and_then(|value| value.get("metadata").cloned())
        .and_then(|metadata| metadata.get("deletionRequestedAt").cloned())
        .is_some_and(|value| !value.is_null())
}

async fn list_resources(
    store: &RedbResourceStore,
    zone: &ZoneId,
    resource_type: ResourceTypeName,
    suffix: &'static str,
) -> Result<Vec<StoredResource>, SemanticBindingRuntimeError> {
    let mut request = StoreListRequest {
        operation: StoreOperationContext {
            operation_id: format!("semantic-binding-reconcile:{suffix}"),
            idempotency_key: None,
            correlation_id: format!("semantic-binding-reconcile:{suffix}"),
            trace_id: None,
            deadline_ms: 10_000,
        },
        zone: zone.clone(),
        resource_types: vec![resource_type],
        resource_names: Vec::new(),
        filters: Vec::new(),
        page_size: 256,
        cursor: None,
        projection: StoreProjection::Full,
    };
    let mut resources = Vec::new();
    loop {
        let page = store
            .list(request.clone())
            .await
            .map_err(|_| SemanticBindingRuntimeError::Store)?;
        resources.extend(page.resources);
        let Some(cursor) = page.next_cursor else {
            break;
        };
        request.cursor = Some(cursor);
    }
    Ok(resources)
}

#[cfg(test)]
mod tests {
    use super::*;
    use d2b_contracts_resource::v3::{
        CanonicalJsonValue, ResourceGeneration, ResourceUid, ZoneRevision,
    };

    fn resource(resource_ref: &str, spec: serde_json::Value) -> StoredResource {
        let resource_ref = ResourceRef::parse(resource_ref).expect("resource ref");
        let zone = ZoneId::parse("dev").expect("zone");
        let value = serde_json::json!({
            "apiVersion": "resources.d2bus.org/v3",
            "type": resource_ref.resource_type().as_str(),
            "metadata": {
                "name": resource_ref.name().as_str(),
                "zone": zone.as_str(),
                "ownerRef": null,
                "labels": {},
                "annotations": {},
                "finalizers": [],
                "managedBy": "controller",
                "configurationGeneration": 1,
                "deletionRequestedAt": null,
                "createdAt": "2026-08-19T00:00:00.000Z",
                "updatedAt": "2026-08-19T00:00:00.000Z",
                "generation": 1,
                "revision": 1,
                "uid": "123e4567-e89b-42d3-a456-426614174000"
            },
            "spec": spec,
            "status": {
                "observedGeneration": 0,
                "phase": "Pending",
                "conditions": [],
                "lastReconciledAt": null,
                "startedAt": null,
                "completedAt": null,
                "outcome": null,
                "update": {
                    "dependencies": {"count": 0, "refs": []},
                    "disruption": "None",
                    "lastAssessedAt": null,
                    "observedGeneration": 0,
                    "operationId": null,
                    "owned": {"count": 0, "refs": []},
                    "preserveState": true,
                    "reasons": [],
                    "state": "Unknown",
                    "targetGeneration": 1
                },
                "resource": {}
            }
        });
        let canonical =
            CanonicalJsonValue::parse(&serde_json::to_vec(&value).expect("serialize resource"))
                .expect("canonical resource")
                .to_canonical_bytes();
        StoredResource {
            resource_ref,
            zone,
            uid: ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").expect("uid"),
            generation: ResourceGeneration::new(1).expect("generation"),
            revision: ZoneRevision::new(1),
            canonical_json: canonical,
            payload_digest: "sha256:test".to_owned(),
        }
    }

    #[test]
    fn binding_relationships_use_each_family_contract() {
        let usb = resource(
            "usb.d2bus.org.UsbBinding/work",
            serde_json::json!({
                "serviceRef": "usb.d2bus.org.UsbService/work",
                "guestRef": "Guest/work"
            }),
        );
        assert_eq!(
            binding_relationship(&usb).expect("USB relationship"),
            (
                SemanticFamily::Usb,
                ResourceRef::parse("usb.d2bus.org.UsbService/work").unwrap(),
                ResourceRef::parse("Guest/work").unwrap(),
            )
        );

        let security = resource(
            "security-key.d2bus.org.SecurityKeyBinding/key",
            serde_json::json!({
                "serviceRef": "security-key.d2bus.org.SecurityKeyService/key",
                "target": {
                    "guestRef": "Guest/work",
                    "userRef": "User/operator"
                }
            }),
        );
        assert_eq!(
            binding_relationship(&security).expect("security-key relationship"),
            (
                SemanticFamily::SecurityKey,
                ResourceRef::parse("security-key.d2bus.org.SecurityKeyService/key").unwrap(),
                ResourceRef::parse("Guest/work").unwrap(),
            )
        );

        let telemetry = resource(
            "telemetry.d2bus.org.TelemetryBinding/metrics",
            serde_json::json!({
                "serviceRef": "telemetry.d2bus.org.TelemetryService/ingest",
                "producerRef": "Zone/dev"
            }),
        );
        assert_eq!(
            binding_relationship(&telemetry).expect("telemetry relationship"),
            (
                SemanticFamily::Telemetry,
                ResourceRef::parse("telemetry.d2bus.org.TelemetryService/ingest").unwrap(),
                ResourceRef::parse("Zone/dev").unwrap(),
            )
        );
    }

    #[test]
    fn malformed_relationships_fail_closed_without_auto_binding() {
        let service = resource(
            "usb.d2bus.org.UsbService/work",
            serde_json::json!({"mode": "authority"}),
        );
        assert!(binding_relationship(&service).is_err());

        let binding = resource(
            "usb.d2bus.org.UsbBinding/work",
            serde_json::json!({"serviceRef": "usb.d2bus.org.UsbService/work"}),
        );
        assert_eq!(
            binding_relationship(&binding),
            Err(SemanticBindingRuntimeError::InvalidResource)
        );
    }

    #[test]
    fn provider_ref_is_read_from_the_reserved_spec_layer() {
        let service = resource(
            "usb.d2bus.org.UsbService/work",
            serde_json::json!({
                "providerRef": "Provider/device-usbip",
                "mode": "authority"
            }),
        );

        assert_eq!(
            binding_provider_ref(&service).unwrap().as_deref(),
            Some("Provider/device-usbip")
        );
    }

    #[test]
    fn status_projections_use_only_frozen_common_fields() {
        for (family, expected) in [
            (SemanticFamily::Usb, vec!["attachmentPhase"]),
            (SemanticFamily::SecurityKey, vec!["attachment"]),
            (SemanticFamily::Telemetry, Vec::new()),
        ] {
            let projection = semantic_binding_status_projection(family, "Ready");
            let names = projection
                .as_object()
                .expect("status projection object")
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>();
            assert_eq!(names, expected);
            family
                .contract()
                .binding()
                .status()
                .validate_names(names)
                .expect("projection matches the frozen status schema");
        }
    }

    #[test]
    fn watch_covers_all_semantic_bindings_and_core_children() {
        let request = device_binding_watch_request(&ZoneId::parse("dev").unwrap());
        let types = request
            .resource_types
            .iter()
            .map(ResourceTypeName::as_str)
            .collect::<Vec<_>>();
        assert_eq!(
            types,
            vec![
                "usb.d2bus.org.UsbService",
                "usb.d2bus.org.UsbBinding",
                "security-key.d2bus.org.SecurityKeyService",
                "security-key.d2bus.org.SecurityKeyBinding",
                "Process",
                "EphemeralProcess",
                "Endpoint",
            ]
        );
    }

    #[test]
    fn telemetry_descriptor_is_owned_by_the_shared_runner_not_legacy_watch() {
        let identity = ControllerIdentity::new(
            ZoneId::parse("dev").unwrap(),
            ResourceRef::parse("Process/otel-controller").unwrap(),
            d2b_contracts_resource::v3::ControllerGeneration::new(1).unwrap(),
            ResourceRef::parse("Provider/observability-otel").unwrap(),
            d2b_contracts_resource::v3::ResourceGeneration::new(1).unwrap(),
            ResourceRef::parse("Process/otel-controller").unwrap(),
            ResourceRef::parse("Host/host-system").unwrap(),
            None,
        )
        .unwrap();
        let descriptor = telemetry_controller_descriptor(identity).unwrap();
        assert_eq!(
            descriptor
                .resource_types()
                .map(ResourceTypeName::as_str)
                .collect::<Vec<_>>(),
            vec![
                "telemetry.d2bus.org.TelemetryBinding",
                "telemetry.d2bus.org.TelemetryService",
            ]
        );
        assert!(descriptor.consumes_owner_triggers());
    }

    #[test]
    fn semantic_status_projection_removes_credential_bytes_but_keeps_identity() {
        let resource = resource(
            "telemetry.d2bus.org.TelemetryBinding/metrics",
            serde_json::json!({
                "providerRef": "Provider/observability-otel",
                "serviceRef": "telemetry.d2bus.org.TelemetryService/ingest",
                "producerRef": "Zone/dev"
            }),
        );
        let mut value =
            serde_json::from_slice::<serde_json::Value>(&resource.canonical_json).unwrap();
        value["status"]["credentialBytes"] = serde_json::json!("should-not-persist");
        let mut resource = resource;
        resource.canonical_json = CanonicalJsonValue::parse(
            &serde_json::to_vec(&value).expect("serialize status canary"),
        )
        .unwrap()
        .to_canonical_bytes();
        let sanitized = sanitized_status_resource(&resource).unwrap();
        let rendered = String::from_utf8(sanitized.canonical_json).unwrap();
        assert!(rendered.contains("TelemetryBinding") || rendered.contains("telemetry"));
        assert!(!rendered.contains("credentialBytes"));
        assert!(!rendered.contains("should-not-persist"));
    }

    #[test]
    fn telemetry_service_status_is_bounded_and_endpoint_driven() {
        let service = resource(
            "telemetry.d2bus.org.TelemetryService/ingest",
            serde_json::json!({
                "providerRef": "Provider/observability-otel",
                "serviceRole": "authority",
                "ingestEndpointRefs": ["Endpoint/ingest"],
                "signals": ["metrics"],
                "quota": {},
                "policy": {}
            }),
        );
        let endpoint = resource(
            "Endpoint/ingest",
            serde_json::json!({
                "providerRef": "Provider/observability-otel",
                "producerRef": "Process/collector",
                "endpointClass": "service",
                "transport": "unix",
                "purpose": "ingest",
                "serviceFingerprint": null,
                "locality": "host-local",
                "visibility": "zone",
                "attachmentPolicy": {
                    "supported": true,
                    "maxAttachments": 1
                },
                "consumerPolicy": {
                    "allowedSubjects": [],
                    "allowedProviderComponents": [],
                    "allowedOperations": ["resolve"]
                },
                "lifecyclePolicy": "recycle-with-producer"
            }),
        );
        let (phase, projection) = telemetry_service_status(&service, &[endpoint]);
        assert_eq!(phase, "Pending");
        assert_eq!(projection["serviceRole"], "authority");
        assert_eq!(projection["serviceReadiness"], "Pending");
    }
}
