//! Core-owned reconciliation for non-audio semantic Binding children.
//!
//! Provider controllers remain the authority for their Service and Binding
//! semantics. Telemetry Service/Binding rows use the shared Runner and the
//! authenticated ResourceService path. USBIP and SecurityKey rows are owned
//! by their Provider-specific shared Runner handlers.

use std::sync::Arc;

use d2b_contracts_provider::v3::semantic_services::{
    SemanticFamily, child_resources::BindingChildSet,
    telemetry::TELEMETRY_BINDING_RESOURCE_TYPE,
};
use d2b_contracts_resource::v3::{
    CanonicalJsonValue, ResourceEnvelope, ResourceRef, ResourceTypeName, ZoneId,
};
use d2b_core_controller::{
    ControllerDescriptor, ControllerExecutionPolicy, ControllerIdentity, ControllerSelector,
    ControllerVerb, DependencySnapshot, DrainResult, FinalizeResult, HandlerFailure,
    ObservationResult, ReconcileContext, ReconcileDisposition, ReconcilePlan, ReconcileReason,
    ReconcileResult,
    ResourceReconciler, ResourceRegistration, ResourceSnapshot, ResyncPolicy, SelectorField,
    UpdateAssessment, UpdateAssessmentState, UpgradePlan, UpgradeStage, ValidationResult,
};
use d2b_provider_observability_otel::TelemetryBindingController;
use d2b_resource_api::{
    RedbBackend, ResourceApiClient, service::UnavailableUpgradeDispatcher,
};
use d2b_resource_store::{
    StoreErrorKind, StoreGetRequest, StoreOperationContext, StoreProjection, StoredResource,
};
use d2b_resource_store_redb::RedbResourceStore;

use crate::binding_child_resource_runtime::{
    BindingChildOwner, binding_children_ready, has_binding_child_finalizer, list_binding_children,
    reconcile_binding_children, update_binding_child_finalizer,
};

type SemanticBindingDescriptor = (&'static str, &'static str, &'static str, SemanticFamily);

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
    /// Core rejected the desired child set or a mutation failed.
    Reconcile,
}

impl core::fmt::Display for SemanticBindingRuntimeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidResource => "semantic-binding-resource-invalid",
            Self::InvalidRelationship => "semantic-binding-relationship-invalid",
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
    let provider_filter = identity.provider_ref().to_canonical_string();
    let selectors = resources
        .iter()
        .flat_map(|resource| {
            let provider_filter = provider_filter.clone();
            [
                SelectorField::Spec,
                SelectorField::Status,
                SelectorField::Metadata,
                SelectorField::Finalizers,
                SelectorField::Deletion,
            ]
            .into_iter()
            .map(move |field| {
                let exact_value = (field == SelectorField::Spec)
                    .then(|| provider_filter.clone());
                ControllerSelector::new(resource.resource_type().clone(), field, exact_value)
                    .expect("telemetry selector is bounded")
            })
        })
        .collect::<Vec<_>>();
    let dependency_selectors = [
        "telemetry.d2bus.org.TelemetryService",
        "Endpoint",
        "Guest",
        "User",
        "Zone",
    ]
    .into_iter()
    .map(|resource_type| {
        ControllerSelector::new(
            ResourceTypeName::parse(resource_type)
                .expect("telemetry dependency type is canonical"),
            SelectorField::Metadata,
            None,
        )
        .expect("telemetry dependency selector is bounded")
    })
    .collect();
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
        dependency_selectors,
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

    async fn reconcile_target(
        &self,
        resource: &ResourceSnapshot,
        dependencies: &[DependencySnapshot],
    ) -> Result<(), SemanticBindingRuntimeError> {
        let _guard = self.reconcile_lock.lock().await;
        let resource = stored_resource_from_snapshot(resource)?;
        let dependencies = dependencies
            .iter()
            .map(|dependency| stored_resource_from_snapshot(dependency.resource()))
            .collect::<Result<Vec<_>, _>>()?;
        reconcile_telemetry_resource(
            &self.store,
            &self.client,
            &self.store.identity().zone(),
            &resource,
            &dependencies,
        )
        .await
    }

    fn target_is_telemetry(target: &ResourceSnapshot) -> bool {
        matches!(
            target.key().resource_ref().resource_type().as_str(),
            TELEMETRY_BINDING_RESOURCE_TYPE | "telemetry.d2bus.org.TelemetryService"
        )
    }

    fn first_finalizer_batch(
        resource: &ResourceSnapshot,
    ) -> Result<Option<d2b_core_controller::ResourceMutationBatch>, SemanticBindingRuntimeError>
    {
        if resource.key().resource_ref().resource_type().as_str()
            != TELEMETRY_BINDING_RESOURCE_TYPE
            || resource.deleting()
            || binding_has_finalizer(resource)
        {
            return Ok(None);
        }
        let mutation = d2b_core_controller::MutationIntent::new(
            resource.key().resource_ref().clone(),
            Some(resource.key().uid().clone()),
            Some(resource.revision()),
            d2b_core_controller::MutationIntentKind::UpdateFinalizers,
            Some(finalizer_payload(resource)?),
        )
        .map_err(|_| SemanticBindingRuntimeError::InvalidResource)?;
        d2b_core_controller::ResourceMutationBatch::new(vec![mutation])
            .map(Some)
            .map_err(|_| SemanticBindingRuntimeError::InvalidResource)
    }
}

fn stored_resource_from_snapshot(
    resource: &ResourceSnapshot,
) -> Result<StoredResource, SemanticBindingRuntimeError> {
    let envelope = ResourceEnvelope::from_json(resource.canonical_json())
        .map_err(|_| SemanticBindingRuntimeError::InvalidResource)?;
    let payload_digest = envelope
        .digest()
        .map_err(|_| SemanticBindingRuntimeError::InvalidResource)?;
    Ok(StoredResource {
        resource_ref: resource.key().resource_ref().clone(),
        zone: resource.key().zone().clone(),
        uid: resource.key().uid().clone(),
        generation: resource.generation(),
        revision: resource.revision(),
        canonical_json: resource.canonical_json().to_vec(),
        payload_digest,
    })
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
        resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
        _plan: &ReconcilePlan,
    ) -> impl std::future::Future<Output = Result<ReconcileResult, Self::Error>> + Send {
        let result = context
            .authorize_effect()
            .map_err(|_| SemanticBindingRuntimeError::InvalidResource)
            .and_then(|_| {
                if let Some(batch) = Self::first_finalizer_batch(resource)? {
                    return ReconcileResult::new(
                        context.revision(),
                        context.generation(),
                        Some(batch),
                        None,
                        ReconcileDisposition::Pending,
                        None,
                        None,
                        d2b_core_controller::StatusPersistence::NotRequested,
                    )
                    .map_err(|_| SemanticBindingRuntimeError::InvalidResource);
                }
                Ok(ReconcileResult::converged(
                    context.revision(),
                    context.generation(),
                ))
            });
        std::future::ready(result)
    }

    fn execute_effect(
        &self,
        _context: &ReconcileContext,
        resource: &ResourceSnapshot,
        dependencies: &[DependencySnapshot],
        _plan: &ReconcilePlan,
    ) -> impl std::future::Future<Output = Result<ReconcileResult, Self::Error>> + Send {
        let future = async move {
            self.reconcile_target(resource, dependencies).await?;
            Ok(ReconcileResult::converged(
                resource.revision(),
                resource.generation(),
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
            self.reconcile_target(resource, &[]).await?;
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

fn fenced_owner(resource: StoredResource) -> BindingChildOwner {
    BindingChildOwner {
        resource,
        desired: None,
        fenced: true,
    }
}

/// Reconcile one fresh telemetry Service or Binding target through the
/// ResourceService-backed shared controller lane.
pub(crate) async fn reconcile_telemetry_resource(
    store: &RedbResourceStore,
    client: &ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>,
    zone: &ZoneId,
    resource: &StoredResource,
    dependencies: &[StoredResource],
) -> Result<(), SemanticBindingRuntimeError> {
    if resource.zone != *zone {
        return Err(SemanticBindingRuntimeError::InvalidResource);
    }
    match resource.resource_ref.resource_type().as_str() {
        service_type if service_type == TELEMETRY_BINDING.0 => {
            if deletion_requested(resource) {
                return Ok(());
            }
            let endpoints = fresh_telemetry_endpoints(store, zone, resource).await?;
            let (phase, projection) = telemetry_service_status(resource, &endpoints);
            let resource = sanitized_status_resource(resource)?;
            crate::resource_runtime::persist_resource_status_with_projection(
                client,
                &resource,
                &serde_json::json!({ "phase": phase }),
                Some(&projection),
            )
            .await
            .map_err(|_| SemanticBindingRuntimeError::Reconcile)
        }
        binding_type if binding_type == TELEMETRY_BINDING.1 => {
            let owner = telemetry_binding_owner(resource, dependencies)?;
            reconcile_telemetry_binding_owner(store, client, zone, &owner).await
        }
        _ => Err(SemanticBindingRuntimeError::InvalidResource),
    }
}

async fn fresh_telemetry_endpoints(
    store: &RedbResourceStore,
    zone: &ZoneId,
    service: &StoredResource,
) -> Result<Vec<StoredResource>, SemanticBindingRuntimeError> {
    let Some(endpoint_refs) = telemetry_endpoint_refs(service) else {
        return Ok(Vec::new());
    };
    let mut endpoints = Vec::with_capacity(endpoint_refs.len());
    for endpoint_ref in endpoint_refs {
        match store
            .get(StoreGetRequest {
                operation: StoreOperationContext {
                    operation_id: "telemetry-endpoint-read".to_owned(),
                    idempotency_key: None,
                    correlation_id: "telemetry-endpoint-read".to_owned(),
                    trace_id: None,
                    deadline_ms: 10_000,
                },
                zone: zone.clone(),
                target: endpoint_ref,
                expected_uid: None,
                projection: StoreProjection::Full,
            })
            .await
        {
            Ok(endpoint) => endpoints.push(endpoint),
            Err(error) if error.kind() == StoreErrorKind::ResourceNotFound => {}
            Err(_) => return Err(SemanticBindingRuntimeError::Reconcile),
        }
    }
    Ok(endpoints)
}

fn telemetry_endpoint_refs(service: &StoredResource) -> Option<Vec<ResourceRef>> {
    let envelope = ResourceEnvelope::from_json(&service.canonical_json).ok()?;
    let spec: serde_json::Value =
        serde_json::from_slice(&envelope.spec().base().to_canonical_bytes()).ok()?;
    spec.get("ingestEndpointRefs")
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str().and_then(|value| ResourceRef::parse(value).ok()))
                .collect()
        })
}

fn telemetry_binding_owner(
    resource: &StoredResource,
    dependencies: &[StoredResource],
) -> Result<BindingChildOwner, SemanticBindingRuntimeError> {
    if resource.resource_ref.resource_type().as_str() != TELEMETRY_BINDING.1 {
        return Err(SemanticBindingRuntimeError::InvalidResource);
    }
    if deletion_requested(resource) {
        return Ok(BindingChildOwner {
            resource: resource.clone(),
            desired: None,
            fenced: false,
        });
    }
    if binding_provider_ref(resource)?.as_deref() != Some(TELEMETRY_BINDING.2) {
        return Ok(fenced_owner(resource.clone()));
    }
    let (_, service_ref, target_ref) = match binding_relationship(resource) {
        Ok(relationship) => relationship,
        Err(_) => return Ok(fenced_owner(resource.clone())),
    };
    let dependency_present = |reference: &ResourceRef| {
        dependencies.iter().any(|dependency| {
            dependency.resource_ref == *reference && !deletion_requested(dependency)
        })
    };
    if !dependency_present(&service_ref) || !dependency_present(&target_ref) {
        return Ok(fenced_owner(resource.clone()));
    }
    let desired = TelemetryBindingController::child_resources(
        &resource.resource_ref,
        &service_ref,
        &target_ref,
    )
    .map_err(|_| SemanticBindingRuntimeError::InvalidRelationship)?;
    Ok(BindingChildOwner {
        resource: resource.clone(),
        desired: Some(desired),
        fenced: false,
    })
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

async fn reconcile_telemetry_binding_owner(
    store: &RedbResourceStore,
    client: &ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>,
    zone: &ZoneId,
    owner: &BindingChildOwner,
) -> Result<(), SemanticBindingRuntimeError> {
    if owner.fenced {
        persist_fenced_binding_status(client, owner).await?;
        return Ok(());
    }
    if owner.desired.is_some() && !has_binding_child_finalizer(&owner.resource) {
        update_binding_child_finalizer(client, &owner.resource, true)
            .await
            .map_err(|_| SemanticBindingRuntimeError::Reconcile)?;
        return Ok(());
    }
    let converged = reconcile_binding_children(store, client, zone, std::slice::from_ref(owner))
        .await
        .map_err(|_| SemanticBindingRuntimeError::Reconcile)?;
    let children = list_binding_children(store, zone)
        .await
        .map_err(|_| SemanticBindingRuntimeError::Reconcile)?;
    if owner.desired.is_none() {
        if converged.contains(&owner.resource.resource_ref)
            && has_binding_child_finalizer(&owner.resource)
        {
            update_binding_child_finalizer(client, &owner.resource, false)
                .await
                .map_err(|_| SemanticBindingRuntimeError::Reconcile)?;
        }
        return Ok(());
    }
    if !converged.contains(&owner.resource.resource_ref) {
        return Ok(());
    }
    let desired = owner
        .desired
        .as_ref()
        .expect("non-deleting telemetry owner has desired children");
    let ready = binding_children_ready(owner, &children);
    persist_semantic_binding_status(client, owner, desired, true, ready).await
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

fn semantic_binding_status_projection(family: SemanticFamily, _phase: &str) -> serde_json::Value {
    match family {
        SemanticFamily::Telemetry => serde_json::json!({}),
        _ => serde_json::json!({}),
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
        SemanticFamily::Telemetry => value_ref(spec.get("producerRef"))?,
        _ => return Err(SemanticBindingRuntimeError::InvalidResource),
    };
    Ok((family, service_ref, target))
}

fn semantic_family(
    resource: &StoredResource,
) -> Result<SemanticFamily, SemanticBindingRuntimeError> {
    std::iter::once(&TELEMETRY_BINDING)
        .find(|(_, binding_type, _, _)| {
            resource.resource_ref.resource_type().as_str() == *binding_type
        })
        .map(|(_, _, _, family)| *family)
        .ok_or(SemanticBindingRuntimeError::InvalidResource)
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

fn binding_has_finalizer(resource: &ResourceSnapshot) -> bool {
    serde_json::from_slice::<serde_json::Value>(resource.canonical_json())
        .ok()
        .and_then(|value| value.pointer("/metadata/finalizers").cloned())
        .and_then(|value| value.as_array().cloned())
        .is_some_and(|values| {
            values
                .iter()
                .any(|value| {
                    value.as_str()
                        == Some(crate::binding_child_resource_runtime::BINDING_CHILD_FINALIZER)
                })
        })
}

fn finalizer_payload(
    resource: &ResourceSnapshot,
) -> Result<Vec<u8>, SemanticBindingRuntimeError> {
    let value = serde_json::from_slice::<serde_json::Value>(resource.canonical_json())
        .map_err(|_| SemanticBindingRuntimeError::InvalidResource)?;
    let mut finalizers = value
        .pointer("/metadata/finalizers")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let finalizer = crate::binding_child_resource_runtime::BINDING_CHILD_FINALIZER;
    if !finalizers
        .iter()
        .any(|value| value.as_str() == Some(finalizer))
    {
        finalizers.push(serde_json::Value::String(finalizer.to_owned()));
    }
    CanonicalJsonValue::parse(
        &serde_json::to_vec(&serde_json::json!({
            "metadata": {"finalizers": finalizers}
        }))
        .map_err(|_| SemanticBindingRuntimeError::InvalidResource)?,
    )
    .map(|value| value.to_canonical_bytes())
    .map_err(|_| SemanticBindingRuntimeError::InvalidResource)
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
    fn telemetry_descriptor_uses_the_shared_runner() {
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

    #[test]
    fn telemetry_first_pass_returns_only_one_exact_finalizer_mutation() {
        let target = ResourceRef::parse(
            "telemetry.d2bus.org.TelemetryBinding/metrics",
        )
        .unwrap();
        let snapshot = ResourceSnapshot::new(
            d2b_core_controller::ResourceKey::new(
                ZoneId::parse("dev").unwrap(),
                target.clone(),
                ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap(),
            ),
            ZoneRevision::new(7),
            ResourceGeneration::new(1).unwrap(),
            serde_json::to_vec(&serde_json::json!({
                "metadata": {"finalizers": []}
            }))
            .unwrap(),
            false,
        );
        let batch = TelemetryResourceReconciler::first_finalizer_batch(&snapshot)
            .unwrap()
            .expect("first pass enrolls the exact finalizer");
        assert_eq!(batch.mutations().len(), 1);
        assert_eq!(batch.mutations()[0].target(), &target);
        assert_eq!(
            batch.mutations()[0].kind(),
            d2b_core_controller::MutationIntentKind::UpdateFinalizers
        );
    }

}
