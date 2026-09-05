//! Daemon-owned reconciliation for `NixosGeneration` resources.
//!
//! The activation Provider is a fixed daemon composition.  This module owns
//! only the Zone-scoped durable-resource adapter: it applies the pure
//! activation policy to the fresh target and routes effects through the shared
//! Runner and existing broker boundary.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use d2b_contracts_broker::broker_wire::{
    ApplyHostGenerationHandoffResponse, BrokerCallerRole, BrokerRequest, BrokerResponse,
};
use d2b_contracts_broker::host_generation::{
    ApplyHostGenerationHandoff, HandoffCallerRole, HandoffState, HostGenerationHandoffIntent,
    SourceGenerationCompatibilityFloorV1, target_fingerprint,
};
use d2b_contracts_resource::resource_proto as wire;
use d2b_contracts_resource::v3::{
    ActivationDetail, ActivationMode, ActivationOutcomeCode, CanonicalJsonValue,
    NixosGenerationSpec, ResourceEnvelope, ResourcePhase, ResourceRef, ResourceTypeName,
    ResourceUid, ZoneId, ZoneRevision,
};
use d2b_core_controller::{
    ControllerDescriptor, ControllerExecutionPolicy, ControllerIdentity, ControllerSelector,
    ControllerVerb, DependencySnapshot, DrainResult, FinalizeResult, HandlerFailure,
    ObservationResult, ReconcileContext, ReconcileDisposition, ReconcilePlan, ReconcileReason,
    ReconcileResult, ResourceReconciler, ResourceRegistration, ResourceSnapshot, ResyncPolicy,
    SelectorField, UpdateAssessment, UpdateAssessmentState, UpgradePlan, UpgradeStage,
    ValidationResult,
};
use d2b_provider_activation_nixos::{
    ActivationApplicationVerifier, ActivationCaller, ActivationController, CallerRole,
    FailClosedActivationVerifier, GenerationObservation, GenerationPhase,
    activation_runner_ref, activation_runner_spec,
};
use d2b_resource_api::{RedbBackend, ResourceApiClient, service::UnavailableUpgradeDispatcher};
use d2b_resource_store::{
    StoreErrorKind, StoreGetRequest, StoreListRequest, StoreOperationContext, StoreProjection,
    StoredResource,
};
use d2b_resource_store_redb::RedbResourceStore;

use crate::{ServerState, dispatch_broker_request_as};

#[async_trait::async_trait]
pub(crate) trait ActivationResourceClient: Send + Sync {
    async fn create(&self, request: wire::CreateRequest) -> Result<wire::CreateResponse, ()>;

    async fn update_status(
        &self,
        request: wire::UpdateStatusRequest,
    ) -> Result<wire::UpdateStatusResponse, ()>;

    async fn update_finalizers(
        &self,
        request: wire::UpdateFinalizersRequest,
    ) -> Result<wire::UpdateFinalizersResponse, ()>;

    async fn delete(&self, request: wire::DeleteRequest) -> Result<wire::DeleteResponse, ()>;
}

#[async_trait::async_trait]
impl ActivationResourceClient for ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher> {
    async fn create(&self, request: wire::CreateRequest) -> Result<wire::CreateResponse, ()> {
        Ok(ResourceApiClient::create(self, request).await)
    }

    async fn update_status(
        &self,
        request: wire::UpdateStatusRequest,
    ) -> Result<wire::UpdateStatusResponse, ()> {
        Ok(ResourceApiClient::update_status(self, request).await)
    }

    async fn update_finalizers(
        &self,
        request: wire::UpdateFinalizersRequest,
    ) -> Result<wire::UpdateFinalizersResponse, ()> {
        Ok(ResourceApiClient::update_finalizers(self, request).await)
    }

    async fn delete(&self, request: wire::DeleteRequest) -> Result<wire::DeleteResponse, ()> {
        Ok(ResourceApiClient::delete(self, request).await)
    }
}

const ACTIVATION_TYPE: &str = "activation-nixos.d2bus.org.NixosGeneration";
const ACTIVATION_FINALIZER: &str = "activation-nixos.d2bus.org/cleanup";
const RETAINED_GENERATIONS: usize = 3;

/// Stable failures for the daemon-owned activation path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActivationResourceRuntimeError {
    /// A durable resource did not decode as the closed activation contract.
    InvalidResource,
    /// The durable store could not be listed or watched.
    Store,
    /// The activation policy refused the resource.
    Policy,
}

impl core::fmt::Display for ActivationResourceRuntimeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidResource => "activation-resource-invalid",
            Self::Store => "activation-resource-store-failed",
            Self::Policy => "activation-resource-policy-failed",
        })
    }
}

impl std::error::Error for ActivationResourceRuntimeError {}

/// Build the signed descriptor used by the shared Runner for
/// `NixosGeneration` resources.
pub(crate) fn activation_controller_descriptor(
    identity: ControllerIdentity,
) -> Result<ControllerDescriptor, ActivationResourceRuntimeError> {
    let resource_type =
        ResourceTypeName::parse(ACTIVATION_TYPE).expect("activation ResourceType is canonical");
    let resource = ResourceRegistration::new(resource_type.clone(), vec![1], 5_000, 3)
        .map_err(|_| ActivationResourceRuntimeError::InvalidResource)?;
    let provider_filter = identity.provider_ref().to_canonical_string();
    let selectors = [
        SelectorField::Spec,
        SelectorField::Status,
        SelectorField::Metadata,
        SelectorField::Finalizers,
        SelectorField::Deletion,
    ]
    .into_iter()
    .map(|field| {
        let exact_value = (field == SelectorField::Spec).then(|| provider_filter.clone());
        ControllerSelector::new(resource_type.clone(), field, exact_value)
            .expect("activation selector is bounded")
    })
    .collect();
    let dependency_selectors = ["Process", "EphemeralProcess"]
        .into_iter()
        .map(|resource_type| {
            ControllerSelector::new(
                ResourceTypeName::parse(resource_type)
                    .expect("activation dependency type is canonical"),
                SelectorField::Metadata,
                None,
            )
            .expect("activation dependency selector is bounded")
        })
        .collect();
    ControllerDescriptor::new(
        identity,
        vec![resource],
        vec![
            "resource-service".to_owned(),
            "activation-effect".to_owned(),
        ],
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
        vec![ACTIVATION_FINALIZER.to_owned()],
        vec!["activation-nixos.d2bus.org/activation-controller.v1".to_owned()],
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
            ResyncPolicy::new(None, 5_000).expect("activation resync policy"),
        )
        .map_err(|_| ActivationResourceRuntimeError::InvalidResource)?,
    )
    .map_err(|_| ActivationResourceRuntimeError::InvalidResource)
}

/// ResourceService-backed activation handler for the shared Runner.
pub(crate) struct ActivationResourceReconciler {
    store: Arc<RedbResourceStore>,
    client: Arc<ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>>,
    state: Arc<ServerState>,
    runtime: Arc<tokio::sync::Mutex<ActivationResourceRuntime>>,
    identity: ControllerIdentity,
}

impl ActivationResourceReconciler {
    pub(crate) fn new(
        store: Arc<RedbResourceStore>,
        client: Arc<ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>>,
        state: Arc<ServerState>,
        identity: ControllerIdentity,
    ) -> Self {
        Self::with_verifier(
            store,
            client,
            state,
            identity,
            Arc::new(FailClosedActivationVerifier),
        )
    }

    pub(crate) fn with_verifier(
        store: Arc<RedbResourceStore>,
        client: Arc<ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>>,
        state: Arc<ServerState>,
        identity: ControllerIdentity,
        verifier: Arc<dyn ActivationApplicationVerifier>,
    ) -> Self {
        let mut runtime = ActivationResourceRuntime::new(store.identity().zone().clone());
        runtime.set_status_client(Arc::clone(&client));
        runtime.set_verifier(verifier);
        Self {
            store,
            client,
            state,
            runtime: Arc::new(tokio::sync::Mutex::new(runtime)),
            identity,
        }
    }

    async fn reconcile_target(
        &self,
        resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
    ) -> Result<(), ActivationResourceRuntimeError> {
        let resource = stored_resource_from_snapshot(resource)?;
        let resources = fresh_generation_siblings(&self.store, &resource).await?;
        let mut process_resources: Vec<StoredResource> = Vec::new();
        let runner_ref = activation_runner_ref(&resource.resource_ref);
        let runner = self
            .store
            .get(StoreGetRequest {
                operation: StoreOperationContext {
                    operation_id: "activation-runner-read".to_owned(),
                    idempotency_key: None,
                    correlation_id: "activation-runner-read".to_owned(),
                    trace_id: None,
                    deadline_ms: 10_000,
                },
                zone: resource.zone.clone(),
                target: runner_ref,
                expected_uid: None,
                projection: StoreProjection::Full,
            })
            .await;
        match runner {
            Ok(runner) if !process_resources.iter().any(|current| {
                current.resource_ref == runner.resource_ref && current.uid == runner.uid
            }) =>
            {
                process_resources.push(runner);
            }
            Ok(_) => {}
            Err(error) if error.kind() == StoreErrorKind::ResourceNotFound => {}
            Err(_) => return Err(ActivationResourceRuntimeError::Store),
        }
        let mut runtime = self.runtime.lock().await;
        runtime.set_status_client(Arc::clone(&self.client));
        runtime
            .reconcile(
                Arc::clone(&self.state),
                resources,
                process_resources,
                Some(&resource.resource_ref),
            )
            .await
    }
}

async fn fresh_generation_siblings(
    store: &RedbResourceStore,
    target: &StoredResource,
) -> Result<Vec<StoredResource>, ActivationResourceRuntimeError> {
    let target_spec = decode_activation_spec(target)?;
    let execution_ref = target_spec.execution_ref().clone();
    let mut request = StoreListRequest {
        operation: StoreOperationContext {
            operation_id: "activation-generation-siblings".to_owned(),
            idempotency_key: None,
            correlation_id: "activation-generation-siblings".to_owned(),
            trace_id: None,
            deadline_ms: 10_000,
        },
        zone: target.zone.clone(),
        resource_types: vec![
            ResourceTypeName::parse(ACTIVATION_TYPE)
                .expect("activation ResourceType is canonical"),
        ],
        resource_names: Vec::new(),
        filters: Vec::new(),
        page_size: 256,
        cursor: None,
        projection: StoreProjection::BaseOnly,
    };
    let mut candidates = BTreeMap::<ResourceRef, ResourceUid>::new();
    loop {
        let page = store
            .list(request.clone())
            .await
            .map_err(|_| ActivationResourceRuntimeError::Store)?;
        for resource in page.resources {
            if decode_activation_spec(&resource)?.execution_ref() == &execution_ref {
                candidates.insert(resource.resource_ref, resource.uid);
            }
        }
        let Some(cursor) = page.next_cursor else {
            break;
        };
        request.cursor = Some(cursor);
    }
    candidates
        .entry(target.resource_ref.clone())
        .or_insert_with(|| target.uid.clone());

    let mut siblings = Vec::with_capacity(candidates.len());
    for (resource_ref, uid) in candidates {
        let resource = store
            .get(StoreGetRequest {
                operation: StoreOperationContext {
                    operation_id: "activation-generation-sibling".to_owned(),
                    idempotency_key: None,
                    correlation_id: "activation-generation-sibling".to_owned(),
                    trace_id: None,
                    deadline_ms: 10_000,
                },
                zone: target.zone.clone(),
                target: resource_ref.clone(),
                expected_uid: Some(uid.clone()),
                projection: StoreProjection::Full,
            })
            .await;
        match resource {
            Ok(resource) => {
                if decode_activation_spec(&resource)?.execution_ref() == &execution_ref {
                    siblings.push(resource);
                } else if resource_ref == target.resource_ref {
                    return Err(ActivationResourceRuntimeError::InvalidResource);
                }
            }
            Err(error)
                if error.kind() == StoreErrorKind::ResourceNotFound
                    && resource_ref != target.resource_ref => {}
            Err(_) => return Err(ActivationResourceRuntimeError::Store),
        }
    }
    if siblings
        .iter()
        .all(|resource| resource.resource_ref != target.resource_ref)
    {
        return Err(ActivationResourceRuntimeError::Store);
    }
    Ok(siblings)
}

fn stored_resource_from_snapshot(
    resource: &ResourceSnapshot,
) -> Result<StoredResource, ActivationResourceRuntimeError> {
    let envelope = ResourceEnvelope::from_json(resource.canonical_json())
        .map_err(|_| ActivationResourceRuntimeError::InvalidResource)?;
    let payload_digest = envelope
        .digest()
        .map_err(|_| ActivationResourceRuntimeError::InvalidResource)?;
    Ok(StoredResource {
        resource_ref: resource.key().resource_ref().clone(),
        zone: resource.key().zone().clone(),
        uid: resource.key().uid().clone(),
        owner_uid: resource.owner_uid().cloned(),
        owner_generation: resource.owner_generation(),
        generation: resource.generation(),
        revision: resource.revision(),
        canonical_json: resource.canonical_json().to_vec(),
        payload_digest,
    })
}

impl ResourceReconciler for ActivationResourceReconciler {
    type Error = ActivationResourceRuntimeError;

    fn classify_error(&self, _error: &Self::Error) -> HandlerFailure {
        HandlerFailure::retryable()
    }

    fn describe(
        &self,
    ) -> impl std::future::Future<Output = Result<ControllerDescriptor, Self::Error>> + Send {
        std::future::ready(activation_controller_descriptor(self.identity.clone()))
    }

    fn validate_spec(
        &self,
        _context: &ReconcileContext,
        resource: &ResourceSnapshot,
    ) -> impl std::future::Future<Output = Result<ValidationResult, Self::Error>> + Send {
        let valid = resource.key().resource_ref().resource_type().as_str() == ACTIVATION_TYPE
            && ResourceEnvelope::from_json(resource.canonical_json()).is_ok();
        std::future::ready(Ok(if valid {
            ValidationResult::Valid
        } else {
            ValidationResult::Invalid {
                reason: ReconcileReason::InvalidSpec,
            }
        }))
    }

    fn plan(
        &self,
        _context: &ReconcileContext,
        _resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
    ) -> impl std::future::Future<Output = Result<ReconcilePlan, Self::Error>> + Send {
        std::future::ready(
            ReconcilePlan::new(vec!["activation-nixos-resource".to_owned()], false)
                .map_err(|_| ActivationResourceRuntimeError::InvalidResource),
        )
    }

    fn reconcile(
        &self,
        context: &ReconcileContext,
        resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
        _plan: &ReconcilePlan,
    ) -> impl std::future::Future<Output = Result<ReconcileResult, Self::Error>> + Send {
        let result = (|| {
            context
                .authorize_effect()
                .map_err(|_| ActivationResourceRuntimeError::Policy)?;
            if !resource_has_finalizer(resource) && !resource.deleting() {
                let mutation = d2b_core_controller::MutationIntent::new(
                    resource.key().resource_ref().clone(),
                    Some(resource.key().uid().clone()),
                    Some(resource.revision()),
                    d2b_core_controller::MutationIntentKind::UpdateFinalizers,
                    Some(finalizer_payload(resource)?),
                )
                .map_err(|_| ActivationResourceRuntimeError::InvalidResource)?;
                let batch = d2b_core_controller::ResourceMutationBatch::new(vec![mutation])
                    .map_err(|_| ActivationResourceRuntimeError::InvalidResource)?;
                return ReconcileResult::new(
                    resource.revision(),
                    resource.generation(),
                    Some(batch),
                    None,
                    ReconcileDisposition::Pending,
                    None,
                    None,
                    d2b_core_controller::StatusPersistence::NotRequested,
                )
                .map_err(|_| ActivationResourceRuntimeError::InvalidResource);
            }
            Ok(ReconcileResult::converged(
                resource.revision(),
                resource.generation(),
            ))
        })();
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
                .map_err(|_| ActivationResourceRuntimeError::InvalidResource),
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
            .map_err(|_| ActivationResourceRuntimeError::InvalidResource),
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

fn resource_has_finalizer(resource: &ResourceSnapshot) -> bool {
    serde_json::from_slice::<serde_json::Value>(resource.canonical_json())
        .ok()
        .and_then(|value| value.pointer("/metadata/finalizers").cloned())
        .and_then(|value| value.as_array().cloned())
        .is_some_and(|values| {
            values
                .iter()
                .any(|value| value.as_str() == Some(ACTIVATION_FINALIZER))
        })
}

fn finalizer_payload(
    resource: &ResourceSnapshot,
) -> Result<Vec<u8>, ActivationResourceRuntimeError> {
    let value = serde_json::from_slice::<serde_json::Value>(resource.canonical_json())
        .map_err(|_| ActivationResourceRuntimeError::InvalidResource)?;
    let mut finalizers = value
        .pointer("/metadata/finalizers")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !finalizers.iter().any(|value| value.as_str() == Some(ACTIVATION_FINALIZER)) {
        finalizers.push(serde_json::Value::String(ACTIVATION_FINALIZER.to_owned()));
    }
    CanonicalJsonValue::parse(
        &serde_json::to_vec(&serde_json::json!({
            "metadata": {"finalizers": finalizers}
        }))
        .map_err(|_| ActivationResourceRuntimeError::InvalidResource)?,
    )
    .map(|value| value.to_canonical_bytes())
    .map_err(|_| ActivationResourceRuntimeError::InvalidResource)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DesiredRecord {
    resource: StoredResource,
    spec: NixosGenerationSpec,
    ordinal: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RunnerObservation {
    phase: ResourcePhase,
    outcome: Option<ActivationOutcomeCode>,
}

impl DesiredRecord {
    fn key(&self) -> ResourceRef {
        self.resource.resource_ref.clone()
    }

    fn same_desired_state(&self, other: &Self) -> bool {
        self.resource.zone == other.resource.zone
            && self.resource.resource_ref == other.resource.resource_ref
            && self.resource.uid == other.resource.uid
            && self.resource.generation == other.resource.generation
            && self.spec == other.spec
            && self.ordinal == other.ordinal
    }

    fn deletion_requested(&self) -> bool {
        metadata_value(&self.resource, "deletionRequestedAt")
            .is_some_and(|value| !matches!(value, CanonicalJsonValue::Null))
    }

    fn has_finalizer(&self) -> bool {
        metadata_value(&self.resource, "finalizers").is_some_and(|value| {
            matches!(
                value,
                CanonicalJsonValue::Array(values)
                    if values.iter().any(|value| {
                        matches!(value, CanonicalJsonValue::String(value) if value == ACTIVATION_FINALIZER)
                    })
            )
        })
    }
}

/// Durable activation registry for one Zone.
pub(crate) struct ActivationResourceRuntime {
    zone: ZoneId,
    controller: ActivationController,
    records: BTreeMap<ResourceRef, DesiredRecord>,
    status_client: Option<Arc<dyn ActivationResourceClient>>,
    verifier: Arc<dyn ActivationApplicationVerifier>,
}

impl core::fmt::Debug for ActivationResourceRuntime {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ActivationResourceRuntime")
            .field("zone", &self.zone)
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl ActivationResourceRuntime {
    /// Construct a registry over the fixed activation Provider policy.
    pub(crate) fn new(zone: ZoneId) -> Self {
        Self {
            zone,
            controller: ActivationController::new(RETAINED_GENERATIONS),
            records: BTreeMap::new(),
            status_client: None,
            verifier: Arc::new(FailClosedActivationVerifier),
        }
    }

    pub(crate) fn set_status_client<C>(&mut self, status_client: Arc<C>)
    where
        C: ActivationResourceClient + 'static,
    {
        self.status_client = Some(status_client);
    }

    #[allow(dead_code)]
    pub(crate) fn set_verifier(
        &mut self,
        verifier: Arc<dyn ActivationApplicationVerifier>,
    ) {
        self.verifier = verifier;
    }

    fn application_is_verified(
        &self,
        request: &d2b_provider_activation_nixos::RunnerRequest,
    ) -> bool {
        self.verifier
            .verify_application(&self.controller, request)
            .is_ok()
    }

    fn runner_client(
        &self,
        _execution_ref: &ResourceRef,
    ) -> Option<Arc<dyn ActivationResourceClient>> {
        self.status_client.clone()
    }

    /// Reconcile one fresh activation target.
    pub(crate) async fn reconcile(
        &mut self,
        state: Arc<ServerState>,
        resources: Vec<StoredResource>,
        process_resources: Vec<StoredResource>,
        target: Option<&ResourceRef>,
    ) -> Result<(), ActivationResourceRuntimeError> {
        let desired = decode_resources(&self.zone, resources)?;
        let desired_keys = desired.keys().cloned().collect::<BTreeSet<_>>();
        let target_execution_ref = target
            .and_then(|target| desired.get(target))
            .map(|record| record.spec.execution_ref().clone());
        if target.is_some() && target_execution_ref.is_none() {
            return Err(ActivationResourceRuntimeError::InvalidResource);
        }
        if let Some(execution_ref) = target_execution_ref.as_ref() {
            self.records.retain(|key, record| {
                record.spec.execution_ref() != execution_ref || desired_keys.contains(key)
            });
        } else {
            self.records.retain(|key, _| desired_keys.contains(key));
        }
        let observations_by_target = desired.values().fold(
            BTreeMap::<ResourceRef, Vec<GenerationObservation>>::new(),
            |mut observations, record| {
                observations
                    .entry(record.spec.execution_ref().clone())
                    .or_default()
                    .push(GenerationObservation::terminal(
                        record.resource.resource_ref.name().as_str(),
                        generation_phase(
                            status_phase(&record.resource).unwrap_or(ResourcePhase::Pending),
                        ),
                        record.ordinal,
                    ));
                observations
            },
        );

        for (key, mut record) in desired {
            if !selected_target(target, &key) {
                self.records.insert(key, record);
                continue;
            }
            let replace = self
                .records
                .get(&key)
                .is_some_and(|current| !current.same_desired_state(&record));
            if replace {
                self.records.remove(&key);
            }

            if !record.deletion_requested() && !record.has_finalizer() {
                record = self.ensure_finalizer(&record).await?;
                self.records.insert(key, record);
                return Ok(());
            }

            if record.deletion_requested() {
                if let Some(child) = find_runner_resource(&record, &process_resources) {
                    if !matches!(
                        status_phase(child).unwrap_or(ResourcePhase::Pending),
                        ResourcePhase::Deleted
                    ) {
                        if metadata_value(child, "deletionRequestedAt")
                            .is_none_or(|value| matches!(value, CanonicalJsonValue::Null))
                        {
                            if let Some(client) = self.runner_client(record.spec.execution_ref()) {
                                self.request_delete_stored(client.as_ref(), child).await?;
                                self.records.insert(key, record);
                                return Ok(());
                            }
                        }
                        self.records.insert(key, record);
                        continue;
                    }
                }
                if status_phase(&record.resource) != Some(ResourcePhase::Deleted) {
                    record = self
                        .publish_status(
                            &record,
                            ResourcePhase::Deleted,
                            ActivationDetail::Superseded,
                            None,
                        )
                        .await?;
                    self.records.insert(key, record);
                    return Ok(());
                }
                if record.has_finalizer() {
                    record = self.remove_finalizer(&record).await?;
                    self.records.insert(key, record);
                    return Ok(());
                }
                self.records.insert(key, record);
                continue;
            }

            let phase = status_phase(&record.resource).unwrap_or(ResourcePhase::Pending);
            if matches!(phase, ResourcePhase::Ready | ResourcePhase::Succeeded) {
                self.records.insert(key, record);
                continue;
            }

            let observed = GenerationObservation::terminal(
                record.resource.resource_ref.name().as_str(),
                generation_phase(phase),
                record.ordinal,
            );
            let prior = observations_by_target
                .get(record.spec.execution_ref())
                .cloned()
                .unwrap_or_default();
            let caller =
                ActivationCaller::new(CallerRole::Lifecycle, record.spec.execution_ref().clone());
            let planned = self
                .controller
                .reconcile(&record.spec, &caller, &prior, observed.clone())
                .map_err(|_| ActivationResourceRuntimeError::Policy)?;

            if planned.runner_requests().is_empty() {
                if record.spec.activation_mode() == ActivationMode::Adopt
                    && !matches!(phase, ResourcePhase::Ready | ResourcePhase::Succeeded)
                {
                    let applied = self
                        .controller
                        .apply_runner_result(&record.spec, ActivationOutcomeCode::Adopted, observed)
                        .map_err(|_| ActivationResourceRuntimeError::Policy)?;
                    record = self
                        .publish_status(
                            &record,
                            applied.phase(),
                            ActivationDetail::Adopted,
                            applied.audit_codes().first().copied(),
                        )
                        .await?;
                    self.records.insert(key, record);
                    return Ok(());
                }
                self.records.insert(key, record);
                continue;
            }

            let request = planned.runner_requests()[0].clone();
            if request.execution_ref.resource_type().as_str() == "Host" {
                let outcome = self.execute_runner(&state, &record, &request, &prior).await;
                let applied = self
                    .controller
                    .apply_runner_result(&record.spec, outcome, observed)
                    .map_err(|_| ActivationResourceRuntimeError::Policy)?;
                let detail =
                    activation_detail(record.spec.activation_mode(), outcome, applied.phase());
                record = self
                    .publish_status(
                        &record,
                        applied.phase(),
                        detail,
                        applied.audit_codes().first().copied(),
                    )
                    .await?;
                self.records.insert(key, record);
                return Ok(());
            }
            if !self.application_is_verified(&request) {
                let applied = self
                    .controller
                    .apply_runner_result(
                        &record.spec,
                        ActivationOutcomeCode::HelperRefused,
                        observed,
                    )
                    .map_err(|_| ActivationResourceRuntimeError::Policy)?;
                let detail = activation_detail(
                    record.spec.activation_mode(),
                    ActivationOutcomeCode::HelperRefused,
                    applied.phase(),
                );
                record = self
                    .publish_status(
                        &record,
                        applied.phase(),
                        detail,
                        applied.audit_codes().first().copied(),
                    )
                    .await?;
                self.records.insert(key, record);
                return Ok(());
            }
            let runner = find_runner_observation(&record, &process_resources);
            if runner.is_none() {
                self.create_runner(&record, &request).await?;
                self.records.insert(key, record);
                return Ok(());
            }
            let runner = runner.expect("checked above");
            if runner.phase == ResourcePhase::Pending {
                record = self
                    .publish_status(
                        &record,
                        ResourcePhase::Pending,
                        ActivationDetail::Staged,
                        None,
                    )
                    .await?;
                self.records.insert(key, record);
                return Ok(());
            }
            if runner.phase == ResourcePhase::Ready {
                record = self
                    .publish_status(
                        &record,
                        ResourcePhase::Pending,
                        ActivationDetail::Applying,
                        None,
                    )
                    .await?;
                self.records.insert(key, record);
                return Ok(());
            }
            let outcome = runner.outcome.unwrap_or_else(|| {
                if runner.phase == ResourcePhase::Succeeded {
                    ActivationOutcomeCode::Succeeded
                } else {
                    ActivationOutcomeCode::HelperFailed
                }
            });
            let applied = self
                .controller
                .apply_runner_result(&record.spec, outcome, observed)
                .map_err(|_| ActivationResourceRuntimeError::Policy)?;
            let detail = activation_detail(record.spec.activation_mode(), outcome, applied.phase());
            record = self
                .publish_status(
                    &record,
                    applied.phase(),
                    detail,
                    applied.audit_codes().first().copied(),
                )
                .await?;
            self.records.insert(key, record);
            return Ok(());
        }

        self.apply_retention(target_execution_ref.as_ref()).await?;
        Ok(())
    }

    async fn execute_runner(
        &self,
        state: &ServerState,
        record: &DesiredRecord,
        request: &d2b_provider_activation_nixos::RunnerRequest,
        prior: &[GenerationObservation],
    ) -> ActivationOutcomeCode {
        if request.system_artifact_id != *record.spec.system_artifact_id()
            || request.execution_ref != *record.spec.execution_ref()
            || request.activation_mode != record.spec.activation_mode()
            || request.target_generation != record.ordinal
        {
            return ActivationOutcomeCode::TargetMismatch;
        }
        if !self.application_is_verified(request) {
            return ActivationOutcomeCode::HelperRefused;
        }
        match request.execution_ref.resource_type().as_str() {
            "Host" => self
                .execute_host_handoff(state, record, prior)
                .unwrap_or(ActivationOutcomeCode::HelperFailed),
            _ => ActivationOutcomeCode::TargetMismatch,
        }
    }

    fn execute_host_handoff(
        &self,
        state: &ServerState,
        record: &DesiredRecord,
        prior: &[GenerationObservation],
    ) -> Result<ActivationOutcomeCode, ActivationResourceRuntimeError> {
        let source_generation = record
            .spec
            .prior_generation_ref()
            .and_then(|reference| {
                prior
                    .iter()
                    .find(|observation| observation.name() == reference.name().as_str())
                    .map(GenerationObservation::ordinal)
            })
            .unwrap_or_else(|| record.ordinal.saturating_sub(1));
        if source_generation == 0 || record.ordinal <= source_generation {
            return Ok(ActivationOutcomeCode::StaleGeneration);
        }
        let compatibility = SourceGenerationCompatibilityFloorV1::new(
            source_generation,
            target_fingerprint(
                record.spec.execution_ref(),
                record.spec.system_artifact_id(),
                record.ordinal,
            ),
        )
        .map_err(|_| ActivationResourceRuntimeError::Policy)?;
        let request = BrokerRequest::ApplyHostGenerationHandoff(ApplyHostGenerationHandoff {
            caller_role: HandoffCallerRole::Lifecycle,
            target: record.spec.execution_ref().clone(),
            intent: HostGenerationHandoffIntent {
                source_generation,
                target_generation: record.ordinal,
                system_artifact_id: record.spec.system_artifact_id().clone(),
                activation_mode: record.spec.activation_mode(),
                compatibility,
            },
        });
        match dispatch_broker_request_as(
            state,
            request,
            BrokerCallerRole::AdminUid {
                uid: state.daemon_uid,
            },
        ) {
            Ok(BrokerResponse::ApplyHostGenerationHandoff(response)) => {
                Ok(host_handoff_outcome(&response))
            }
            Ok(BrokerResponse::Error(_)) | Ok(_) | Err(_) => {
                Ok(ActivationOutcomeCode::HelperFailed)
            }
        }
    }

    async fn apply_retention(
        &self,
        execution_ref: Option<&ResourceRef>,
    ) -> Result<(), ActivationResourceRuntimeError> {
        let observations = self
            .records
            .values()
            .filter(|record| {
                execution_ref.is_none_or(|execution_ref| {
                    record.spec.execution_ref() == execution_ref
                })
            })
            .map(|record| {
                GenerationObservation::terminal(
                    record.resource.resource_ref.name().as_str(),
                    generation_phase(
                        status_phase(&record.resource).unwrap_or(ResourcePhase::Pending),
                    ),
                    record.ordinal,
                )
            })
            .collect::<Vec<_>>();
        let delete_names = self.controller.retention_plan(&observations);
        for name in delete_names.delete_names().iter().take(1) {
            if let Some(record) = self
                .records
                .values()
                .find(|record| {
                    record.resource.resource_ref.name().as_str() == name
                        && execution_ref.is_none_or(|execution_ref| {
                            record.spec.execution_ref() == execution_ref
                        })
                })
                .cloned()
            {
                if !record.deletion_requested() {
                    self.request_delete(&record).await?;
                    break;
                }
            }
        }
        Ok(())
    }

    async fn publish_status(
        &self,
        record: &DesiredRecord,
        phase: ResourcePhase,
        detail: ActivationDetail,
        outcome: Option<ActivationOutcomeCode>,
    ) -> Result<DesiredRecord, ActivationResourceRuntimeError> {
        let Some(client) = &self.status_client else {
            return Ok(record.clone());
        };
        update_status(client.as_ref(), record, phase, detail, outcome).await
    }

    async fn ensure_finalizer(
        &self,
        record: &DesiredRecord,
    ) -> Result<DesiredRecord, ActivationResourceRuntimeError> {
        let Some(client) = &self.status_client else {
            return Ok(record.clone());
        };
        update_finalizers(client.as_ref(), record, true).await
    }

    async fn remove_finalizer(
        &self,
        record: &DesiredRecord,
    ) -> Result<DesiredRecord, ActivationResourceRuntimeError> {
        let Some(client) = &self.status_client else {
            return Ok(record.clone());
        };
        if !record.has_finalizer() {
            return Ok(record.clone());
        }
        update_finalizers(client.as_ref(), record, false).await
    }

    async fn request_delete(
        &self,
        record: &DesiredRecord,
    ) -> Result<(), ActivationResourceRuntimeError> {
        let Some(client) = &self.status_client else {
            return Ok(());
        };
        delete_resource(client.as_ref(), record).await
    }

    async fn create_runner(
        &self,
        record: &DesiredRecord,
        request: &d2b_provider_activation_nixos::RunnerRequest,
    ) -> Result<(), ActivationResourceRuntimeError> {
        let Some(client) = self.runner_client(&request.execution_ref) else {
            return Ok(());
        };
        let mut spec = serde_json::to_value(activation_runner_spec(request))
            .map_err(|_| ActivationResourceRuntimeError::InvalidResource)?;
        let spec_object = spec
            .as_object_mut()
            .ok_or(ActivationResourceRuntimeError::InvalidResource)?;
        spec_object.insert(
            "providerRef".to_owned(),
            serde_json::json!("Provider/system-minijail"),
        );
        let child_ref = activation_runner_ref(&record.key());
        let payload = serde_json::json!({
            "apiVersion": "resources.d2bus.org/v3",
            "metadata": {
                "createdAt": "1970-01-01T00:00:00.000Z",
                "deletionRequestedAt": null,
                "finalizers": [],
                "generation": 1,
                "managedBy": "controller",
                "name": child_ref.name().as_str(),
                "ownerRef": record.key().to_canonical_string(),
                "revision": 1,
                "updatedAt": "1970-01-01T00:00:00.000Z",
                "zone": self.zone.as_str()
            },
            "spec": spec,
            "status": {
                "completedAt": null,
                "conditions": [],
                "lastReconciledAt": null,
                "observedGeneration": 0,
                "outcome": null,
                "phase": "Pending",
                "resource": {},
                "startedAt": null,
                "update": {
                    "dependencies": {"count": 0, "refs": []},
                    "disruption": "None",
                    "lastAssessedAt": null,
                    "operationId": null,
                    "owned": {"count": 0, "refs": []},
                    "preserveState": true,
                    "reasons": [],
                    "state": "Unknown",
                    "targetGeneration": 1
                }
            },
            "type": "EphemeralProcess"
        });
        let canonical = CanonicalJsonValue::parse(
            &serde_json::to_vec(&payload)
                .map_err(|_| ActivationResourceRuntimeError::InvalidResource)?,
        )
        .map_err(|_| ActivationResourceRuntimeError::InvalidResource)?
        .to_canonical_bytes();
        let mut identity = wire::ResourceIdentity::new();
        identity.zone = self.zone.as_str().to_owned();
        identity.resource_type = "EphemeralProcess".to_owned();
        identity.name = child_ref.name().as_str().to_owned();
        let mut body = wire::ResourceEnvelopeBytes::new();
        body.identity = protobuf::MessageField::some(identity.clone());
        body.payload_digest = d2b_contracts_resource::v3::canonical_digest(
            d2b_contracts_resource::v3::RESOURCE_ENVELOPE_DOMAIN_TAG,
            &canonical,
        );
        body.canonical_json = canonical;
        let mut precondition = wire::Precondition::new();
        precondition.kind =
            protobuf::EnumOrUnknown::new(wire::PreconditionKind::PRECONDITION_KIND_CREATE_ABSENT);
        let mut mutation = wire::Mutation::new();
        mutation.kind = protobuf::EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_CREATE);
        mutation.target = protobuf::MessageField::some(identity);
        mutation.precondition = protobuf::MessageField::some(precondition);
        mutation.resource = protobuf::MessageField::some(body);
        let operation = format!(
            "activation-runner-create-{}-{}",
            child_ref.to_canonical_string(),
            record.resource.uid.as_str()
        );
        let mut request_wire = wire::CreateRequest::new();
        request_wire.meta = protobuf::MessageField::some(request_meta(&operation));
        request_wire.mutation = protobuf::MessageField::some(mutation);
        let response = client
            .create(request_wire)
            .await
            .map_err(|_| ActivationResourceRuntimeError::Store)?;
        if let Some(error) = response.error.as_ref() {
            if error.kind.enum_value().ok()
                != Some(wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_ALREADY_EXISTS)
            {
                return Err(ActivationResourceRuntimeError::Store);
            }
        }
        Ok(())
    }

    async fn request_delete_stored(
        &self,
        client: &dyn ActivationResourceClient,
        resource: &StoredResource,
    ) -> Result<(), ActivationResourceRuntimeError> {
        delete_stored_resource(client, resource).await
    }
}

fn selected_target(target: Option<&ResourceRef>, candidate: &ResourceRef) -> bool {
    target.is_none_or(|target| target == candidate)
}

fn host_handoff_outcome(response: &ApplyHostGenerationHandoffResponse) -> ActivationOutcomeCode {
    match response.state {
        HandoffState::Completed => {
            if response.target_generation == response.source_generation {
                ActivationOutcomeCode::StaleGeneration
            } else {
                ActivationOutcomeCode::Succeeded
            }
        }
        HandoffState::Refused => ActivationOutcomeCode::HelperRefused,
        HandoffState::RolledBack => ActivationOutcomeCode::RolledBack,
        _ => ActivationOutcomeCode::HelperFailed,
    }
}

fn activation_detail(
    mode: ActivationMode,
    outcome: ActivationOutcomeCode,
    phase: ResourcePhase,
) -> ActivationDetail {
    if outcome == ActivationOutcomeCode::Adopted {
        return ActivationDetail::Adopted;
    }
    if outcome == ActivationOutcomeCode::RolledBack {
        return ActivationDetail::RolledBack;
    }
    if outcome.is_success() {
        return match mode {
            ActivationMode::Boot => ActivationDetail::BootDefault,
            ActivationMode::Switch | ActivationMode::Test => ActivationDetail::Applied,
            ActivationMode::Adopt => ActivationDetail::Adopted,
        };
    }
    if phase == ResourcePhase::Ready {
        ActivationDetail::Superseded
    } else {
        ActivationDetail::Planning
    }
}

fn generation_phase(phase: ResourcePhase) -> GenerationPhase {
    match phase {
        ResourcePhase::Pending => GenerationPhase::Pending,
        ResourcePhase::Ready => GenerationPhase::Ready,
        ResourcePhase::Succeeded => GenerationPhase::Succeeded,
        ResourcePhase::Failed => GenerationPhase::Failed,
        ResourcePhase::Degraded => GenerationPhase::Degraded,
        ResourcePhase::Deleted => GenerationPhase::Deleted,
        ResourcePhase::Unknown => GenerationPhase::Pending,
    }
}

fn metadata_value(resource: &StoredResource, key: &str) -> Option<CanonicalJsonValue> {
    let value = CanonicalJsonValue::parse(&resource.canonical_json).ok()?;
    let CanonicalJsonValue::Object(root) = value else {
        return None;
    };
    let CanonicalJsonValue::Object(metadata) = root.get("metadata")? else {
        return None;
    };
    metadata.get(key).cloned()
}

fn status_phase(resource: &StoredResource) -> Option<ResourcePhase> {
    let value = CanonicalJsonValue::parse(&resource.canonical_json).ok()?;
    let CanonicalJsonValue::Object(root) = value else {
        return None;
    };
    let CanonicalJsonValue::Object(status) = root.get("status")? else {
        return None;
    };
    let CanonicalJsonValue::String(phase) = status.get("phase")? else {
        return None;
    };
    match phase.as_str() {
        "Pending" => Some(ResourcePhase::Pending),
        "Ready" => Some(ResourcePhase::Ready),
        "Succeeded" => Some(ResourcePhase::Succeeded),
        "Degraded" => Some(ResourcePhase::Degraded),
        "Failed" => Some(ResourcePhase::Failed),
        "Deleted" => Some(ResourcePhase::Deleted),
        "Unknown" => Some(ResourcePhase::Unknown),
        _ => None,
    }
}

fn find_runner_resource<'a>(
    record: &DesiredRecord,
    process_resources: &'a [StoredResource],
) -> Option<&'a StoredResource> {
    let expected = activation_runner_ref(&record.key());
    process_resources.iter().find(|resource| {
        resource.zone == record.resource.zone
            && resource.resource_ref == expected
            && resource_execution_ref(resource).as_ref() == Some(record.spec.execution_ref())
            && metadata_value(resource, "ownerRef").is_some_and(|owner| {
                matches!(
                    owner,
                    CanonicalJsonValue::String(value)
                        if value == record.key().to_canonical_string()
                )
            })
    })
}

fn resource_execution_ref(resource: &StoredResource) -> Option<ResourceRef> {
    let envelope = ResourceEnvelope::from_json(&resource.canonical_json).ok()?;
    match envelope.spec().base().get("executionRef") {
        Some(CanonicalJsonValue::String(value)) => ResourceRef::parse(value).ok(),
        _ => None,
    }
}

fn find_runner_observation(
    record: &DesiredRecord,
    process_resources: &[StoredResource],
) -> Option<RunnerObservation> {
    let resource = find_runner_resource(record, process_resources)?;
    Some(RunnerObservation {
        phase: status_phase(resource).unwrap_or(ResourcePhase::Pending),
        outcome: status_outcome(resource),
    })
}

fn status_outcome(resource: &StoredResource) -> Option<ActivationOutcomeCode> {
    let value = CanonicalJsonValue::parse(&resource.canonical_json).ok()?;
    let CanonicalJsonValue::Object(root) = value else {
        return None;
    };
    let CanonicalJsonValue::Object(status) = root.get("status")? else {
        return None;
    };
    let CanonicalJsonValue::Object(outcome) = status.get("outcome")? else {
        return None;
    };
    let CanonicalJsonValue::String(code) = outcome.get("code")? else {
        return None;
    };
    match code.as_str() {
        "succeeded" | "process-exited" => Some(ActivationOutcomeCode::Succeeded),
        "runtime-deadline" => Some(ActivationOutcomeCode::HelperFailed),
        "adopted" => Some(ActivationOutcomeCode::Adopted),
        "target-mismatch" => Some(ActivationOutcomeCode::TargetMismatch),
        "helper-refused" => Some(ActivationOutcomeCode::HelperRefused),
        _ => None,
    }
}

fn ordinal_from_resource(resource: &StoredResource) -> u64 {
    resource
        .resource_ref
        .name()
        .as_str()
        .rsplit('-')
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or_else(|| resource.generation.get())
}

fn decode_resources(
    zone: &ZoneId,
    resources: Vec<StoredResource>,
) -> Result<BTreeMap<ResourceRef, DesiredRecord>, ActivationResourceRuntimeError> {
    let mut desired = BTreeMap::new();
    for resource in resources {
        if resource.zone != *zone {
            return Err(ActivationResourceRuntimeError::InvalidResource);
        }
        if resource.resource_ref.resource_type().as_str() != ACTIVATION_TYPE {
            continue;
        }
        let spec = decode_activation_spec(&resource)?;
        let record = DesiredRecord {
            ordinal: ordinal_from_resource(&resource),
            resource,
            spec,
        };
        if desired.insert(record.key(), record).is_some() {
            return Err(ActivationResourceRuntimeError::InvalidResource);
        }
    }
    Ok(desired)
}

fn decode_activation_spec(
    resource: &StoredResource,
) -> Result<NixosGenerationSpec, ActivationResourceRuntimeError> {
    let envelope = ResourceEnvelope::from_json(&resource.canonical_json)
        .map_err(|_| ActivationResourceRuntimeError::InvalidResource)?;
    serde_json::from_slice::<NixosGenerationSpec>(
        &envelope.spec().base_with_provider_ref().to_canonical_bytes(),
    )
    .map_err(|_| ActivationResourceRuntimeError::InvalidResource)
}

fn phase_json(phase: ResourcePhase) -> CanonicalJsonValue {
    CanonicalJsonValue::String(
        match phase {
            ResourcePhase::Pending => "Pending",
            ResourcePhase::Ready => "Ready",
            ResourcePhase::Succeeded => "Succeeded",
            ResourcePhase::Degraded => "Degraded",
            ResourcePhase::Failed => "Failed",
            ResourcePhase::Deleted => "Deleted",
            ResourcePhase::Unknown => "Unknown",
        }
        .to_owned(),
    )
}

fn detail_json(detail: ActivationDetail) -> CanonicalJsonValue {
    CanonicalJsonValue::String(
        match detail {
            ActivationDetail::Planning => "planning",
            ActivationDetail::Staged => "staged",
            ActivationDetail::Applying => "applying",
            ActivationDetail::Applied => "applied",
            ActivationDetail::BootDefault => "boot-default",
            ActivationDetail::Adopted => "adopted",
            ActivationDetail::RolledBack => "rolled-back",
            ActivationDetail::Superseded => "superseded",
        }
        .to_owned(),
    )
}

fn outcome_json(outcome: ActivationOutcomeCode) -> CanonicalJsonValue {
    CanonicalJsonValue::String(
        match outcome {
            ActivationOutcomeCode::Succeeded => "succeeded",
            ActivationOutcomeCode::Adopted => "adopted",
            ActivationOutcomeCode::Unauthorized => "unauthorized",
            ActivationOutcomeCode::StaleGeneration => "stale-generation",
            ActivationOutcomeCode::TargetMismatch => "target-mismatch",
            ActivationOutcomeCode::HelperRefused => "helper-refused",
            ActivationOutcomeCode::HelperFailed => "helper-failed",
            ActivationOutcomeCode::RolledBack => "rolled-back",
        }
        .to_owned(),
    )
}

fn now_timestamp() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let seconds = millis / 1_000;
    let day = seconds / 86_400;
    let day_seconds = seconds % 86_400;
    let (year, month, day_of_month) = civil_from_days(day as i64);
    let hour = day_seconds / 3_600;
    let minute = (day_seconds % 3_600) / 60;
    let second = day_seconds % 60;
    format!(
        "{year:04}-{month:02}-{day_of_month:02}T{hour:02}:{minute:02}:{second:02}.{:03}Z",
        millis % 1_000
    )
}

fn civil_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = year + i64::from(month <= 2);
    (year, month, day)
}

async fn update_status(
    client: &dyn ActivationResourceClient,
    record: &DesiredRecord,
    phase: ResourcePhase,
    detail: ActivationDetail,
    outcome: Option<ActivationOutcomeCode>,
) -> Result<DesiredRecord, ActivationResourceRuntimeError> {
    let canonical = status_payload(record, phase, detail, outcome)?;
    let envelope = ResourceEnvelope::from_json(&canonical)
        .map_err(|_| ActivationResourceRuntimeError::InvalidResource)?;
    let digest = envelope
        .digest()
        .map_err(|_| ActivationResourceRuntimeError::InvalidResource)?;
    let mut resource = wire::ResourceEnvelopeBytes::new();
    resource.identity = protobuf::MessageField::some(resource_identity(record));
    resource.canonical_json = canonical;
    resource.payload_digest = digest;

    let mut mutation = wire::Mutation::new();
    mutation.kind = protobuf::EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_UPDATE_STATUS);
    mutation.target = protobuf::MessageField::some(resource_identity(record));
    mutation.precondition = protobuf::MessageField::some(exact_precondition(record));
    mutation.resource = protobuf::MessageField::some(resource);
    let operation = format!(
        "activation-runtime-status-{}-{}",
        record.key().to_canonical_string(),
        record.resource.revision.get()
    );
    let mut request = wire::UpdateStatusRequest::new();
    request.meta = protobuf::MessageField::some(request_meta(&operation));
    request.mutation = protobuf::MessageField::some(mutation);
    let response = client
        .update_status(request)
        .await
        .map_err(|_| ActivationResourceRuntimeError::Store)?;
    if response.error.is_some() {
        return Err(ActivationResourceRuntimeError::Store);
    }
    let response_resource = response
        .resource
        .as_ref()
        .ok_or(ActivationResourceRuntimeError::Store)?;
    let mut updated = record.clone();
    updated.resource.canonical_json = response_resource.canonical_json.clone();
    updated.resource.payload_digest = response_resource.payload_digest.clone();
    updated.resource.revision = ZoneRevision::new(response.revision);
    Ok(updated)
}

fn status_payload(
    record: &DesiredRecord,
    phase: ResourcePhase,
    detail: ActivationDetail,
    outcome: Option<ActivationOutcomeCode>,
) -> Result<Vec<u8>, ActivationResourceRuntimeError> {
    let mut value = CanonicalJsonValue::parse(&record.resource.canonical_json)
        .map_err(|_| ActivationResourceRuntimeError::InvalidResource)?;
    let CanonicalJsonValue::Object(root) = &mut value else {
        return Err(ActivationResourceRuntimeError::InvalidResource);
    };
    let Some(CanonicalJsonValue::Object(status)) = root.get_mut("status") else {
        return Err(ActivationResourceRuntimeError::InvalidResource);
    };
    redact_status_fields(status);
    let now = now_timestamp();
    status.insert("phase".to_owned(), phase_json(phase));
    status.insert(
        "observedGeneration".to_owned(),
        CanonicalJsonValue::Integer(record.resource.generation.get() as i64),
    );
    status.insert(
        "lastReconciledAt".to_owned(),
        CanonicalJsonValue::String(now.clone()),
    );
    status.insert(
        "outcome".to_owned(),
        outcome
            .map(|outcome| {
                let mut result = BTreeMap::new();
                result.insert("code".to_owned(), outcome_json(outcome));
                result.insert(
                    "message".to_owned(),
                    CanonicalJsonValue::String(activation_outcome_message(outcome).to_owned()),
                );
                result.insert("retryable".to_owned(), CanonicalJsonValue::Bool(false));
                result.insert(
                    "occurredAt".to_owned(),
                    CanonicalJsonValue::String(now.clone()),
                );
                CanonicalJsonValue::Object(result)
            })
            .unwrap_or(CanonicalJsonValue::Null),
    );
    let resource_status = match status.get_mut("resource") {
        Some(CanonicalJsonValue::Object(resource_status)) => resource_status,
        Some(_) => return Err(ActivationResourceRuntimeError::InvalidResource),
        None => {
            status.insert(
                "resource".to_owned(),
                CanonicalJsonValue::Object(BTreeMap::new()),
            );
            match status.get_mut("resource") {
                Some(CanonicalJsonValue::Object(resource_status)) => resource_status,
                _ => return Err(ActivationResourceRuntimeError::InvalidResource),
            }
        }
    };
    resource_status.insert("activationDetail".to_owned(), detail_json(detail));
    resource_status.insert(
        "observedGeneration".to_owned(),
        CanonicalJsonValue::Integer(record.resource.generation.get() as i64),
    );
    if let Some(outcome) = outcome {
        resource_status.insert("outcome".to_owned(), outcome_json(outcome));
    } else {
        resource_status.remove("outcome");
    }
    let canonical = value.to_canonical_bytes();
    ResourceEnvelope::from_json(&canonical)
        .map_err(|_| ActivationResourceRuntimeError::InvalidResource)?;
    Ok(canonical)
}

fn redact_status_fields(status: &mut BTreeMap<String, CanonicalJsonValue>) {
    let sensitive = status
        .iter()
        .filter_map(|(key, value)| {
            (is_sensitive_status_key(key) || contains_sensitive_status_text(value))
                .then_some(key.clone())
        })
        .collect::<Vec<_>>();
    for key in sensitive {
        status.remove(&key);
    }
    for value in status.values_mut() {
        if let CanonicalJsonValue::Object(object) = value {
            redact_status_fields(object);
        } else if let CanonicalJsonValue::Array(values) = value {
            for value in values {
                if let CanonicalJsonValue::Object(object) = value {
                    redact_status_fields(object);
                }
            }
        }
    }
}

fn is_sensitive_status_key(key: &str) -> bool {
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

fn contains_sensitive_status_text(value: &CanonicalJsonValue) -> bool {
    match value {
        CanonicalJsonValue::String(value) => {
            let value = value.to_ascii_lowercase();
            value.contains("-----begin")
                || value.contains("bearer ")
                || value.contains("clientsecret")
                || value.contains("privatekey")
                || value.contains("secret")
                || value.contains("credential")
                || value.contains("?sv=") && value.contains("&sig=")
        }
        CanonicalJsonValue::Array(values) => values.iter().any(contains_sensitive_status_text),
        CanonicalJsonValue::Object(values) => values.values().any(contains_sensitive_status_text),
        CanonicalJsonValue::Null | CanonicalJsonValue::Bool(_) | CanonicalJsonValue::Integer(_) => {
            false
        }
    }
}

fn activation_outcome_message(outcome: ActivationOutcomeCode) -> &'static str {
    match outcome {
        ActivationOutcomeCode::Succeeded => "target generation activated",
        ActivationOutcomeCode::Adopted => "existing target generation adopted",
        ActivationOutcomeCode::Unauthorized => "activation caller was not authorized",
        ActivationOutcomeCode::StaleGeneration => "target generation is stale",
        ActivationOutcomeCode::TargetMismatch => "activation target did not match",
        ActivationOutcomeCode::HelperRefused => "target activation helper refused the request",
        ActivationOutcomeCode::HelperFailed => "target activation helper failed",
        ActivationOutcomeCode::RolledBack => "target activation rolled back to the source",
    }
}

async fn update_finalizers(
    client: &dyn ActivationResourceClient,
    record: &DesiredRecord,
    add: bool,
) -> Result<DesiredRecord, ActivationResourceRuntimeError> {
    let mut mutation = wire::Mutation::new();
    mutation.kind =
        protobuf::EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_UPDATE_FINALIZERS);
    mutation.target = protobuf::MessageField::some(resource_identity(record));
    mutation.precondition = protobuf::MessageField::some(exact_precondition(record));
    if add {
        mutation
            .add_finalizers
            .push(ACTIVATION_FINALIZER.to_owned());
    } else {
        mutation
            .remove_finalizers
            .push(ACTIVATION_FINALIZER.to_owned());
    }
    let operation = format!(
        "activation-runtime-finalizer-{}-{}-{}",
        record.key().to_canonical_string(),
        record.resource.revision.get(),
        if add { "add" } else { "remove" }
    );
    let mut request = wire::UpdateFinalizersRequest::new();
    request.meta = protobuf::MessageField::some(request_meta(&operation));
    request.mutation = protobuf::MessageField::some(mutation);
    let response = client
        .update_finalizers(request)
        .await
        .map_err(|_| ActivationResourceRuntimeError::Store)?;
    if response.error.is_some() {
        return Err(ActivationResourceRuntimeError::Store);
    }
    let response_resource = response
        .resource
        .as_ref()
        .ok_or(ActivationResourceRuntimeError::Store)?;
    let mut updated = record.clone();
    updated.resource.canonical_json = response_resource.canonical_json.clone();
    updated.resource.payload_digest = response_resource.payload_digest.clone();
    updated.resource.revision = ZoneRevision::new(response.revision);
    Ok(updated)
}

async fn delete_resource(
    client: &dyn ActivationResourceClient,
    record: &DesiredRecord,
) -> Result<(), ActivationResourceRuntimeError> {
    let mut mutation = wire::Mutation::new();
    mutation.kind = protobuf::EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_DELETE);
    mutation.target = protobuf::MessageField::some(resource_identity(record));
    mutation.precondition = protobuf::MessageField::some(exact_precondition(record));
    let operation = format!(
        "activation-runtime-delete-{}-{}",
        record.key().to_canonical_string(),
        record.resource.revision.get()
    );
    let mut request = wire::DeleteRequest::new();
    request.meta = protobuf::MessageField::some(request_meta(&operation));
    request.mutation = protobuf::MessageField::some(mutation);
    let response = client
        .delete(request)
        .await
        .map_err(|_| ActivationResourceRuntimeError::Store)?;
    if response.error.is_some() {
        return Err(ActivationResourceRuntimeError::Store);
    }
    Ok(())
}

async fn delete_stored_resource(
    client: &dyn ActivationResourceClient,
    resource: &StoredResource,
) -> Result<(), ActivationResourceRuntimeError> {
    let mut mutation = wire::Mutation::new();
    mutation.kind = protobuf::EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_DELETE);
    mutation.target = protobuf::MessageField::some(stored_resource_identity(resource));
    mutation.precondition = protobuf::MessageField::some(stored_exact_precondition(resource));
    let operation = format!(
        "activation-runner-delete-{}-{}",
        resource.resource_ref.to_canonical_string(),
        resource.revision.get()
    );
    let mut request = wire::DeleteRequest::new();
    request.meta = protobuf::MessageField::some(request_meta(&operation));
    request.mutation = protobuf::MessageField::some(mutation);
    let response = client
        .delete(request)
        .await
        .map_err(|_| ActivationResourceRuntimeError::Store)?;
    if response.error.is_some() {
        return Err(ActivationResourceRuntimeError::Store);
    }
    Ok(())
}

fn resource_identity(record: &DesiredRecord) -> wire::ResourceIdentity {
    let mut identity = wire::ResourceIdentity::new();
    identity.zone = record.resource.zone.to_canonical_string();
    identity.resource_type = record
        .resource
        .resource_ref
        .resource_type()
        .to_canonical_string();
    identity.name = record.resource.resource_ref.name().to_canonical_string();
    identity.uid = Some(record.resource.uid.as_str().to_owned());
    identity.generation = Some(record.resource.generation.get());
    identity.revision = Some(record.resource.revision.get());
    identity
}

fn exact_precondition(record: &DesiredRecord) -> wire::Precondition {
    let mut precondition = wire::Precondition::new();
    precondition.kind =
        protobuf::EnumOrUnknown::new(wire::PreconditionKind::PRECONDITION_KIND_EXACT_REVISION);
    precondition.expected_revision = Some(record.resource.revision.get());
    precondition.expected_uid = Some(record.resource.uid.as_str().to_owned());
    precondition
}

fn stored_resource_identity(resource: &StoredResource) -> wire::ResourceIdentity {
    let mut identity = wire::ResourceIdentity::new();
    identity.zone = resource.zone.to_canonical_string();
    identity.resource_type = resource.resource_ref.resource_type().to_canonical_string();
    identity.name = resource.resource_ref.name().to_canonical_string();
    identity.uid = Some(resource.uid.as_str().to_owned());
    identity.generation = Some(resource.generation.get());
    identity.revision = Some(resource.revision.get());
    identity
}

pub(crate) fn stored_resource_from_wire(
    resource: &wire::ResourceEnvelopeBytes,
) -> Option<StoredResource> {
    let identity = resource.identity.as_ref()?;
    let uid = ResourceUid::parse(identity.uid.as_deref()?).ok()?;
    let generation =
        d2b_contracts_resource::v3::ResourceGeneration::new(identity.generation?).ok()?;
    let revision = ZoneRevision::new(identity.revision?);
    let zone = ZoneId::parse(&identity.zone).ok()?;
    let resource_ref_text = format!("{}/{}", identity.resource_type, identity.name);
    let resource_ref = ResourceRef::parse(&resource_ref_text).ok()?;
    Some(StoredResource {
        resource_ref,
        zone,
        uid,
        owner_uid: None,
        owner_generation: None,
        generation,
        revision,
        canonical_json: resource.canonical_json.clone(),
        payload_digest: resource.payload_digest.clone(),
    })
}

fn stored_exact_precondition(resource: &StoredResource) -> wire::Precondition {
    let mut precondition = wire::Precondition::new();
    precondition.kind =
        protobuf::EnumOrUnknown::new(wire::PreconditionKind::PRECONDITION_KIND_EXACT_REVISION);
    precondition.expected_revision = Some(resource.revision.get());
    precondition.expected_uid = Some(resource.uid.as_str().to_owned());
    precondition
}

fn request_meta(operation: &str) -> wire::RequestMeta {
    let mut meta = wire::RequestMeta::new();
    meta.operation_id = operation.to_owned();
    meta.idempotency_key = operation.to_owned();
    meta.correlation_id = operation.to_owned();
    meta.trace_id = operation.to_owned();
    meta.deadline_ms = 10_000;
    meta
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    #[derive(Default)]
    struct RecordingActivationClient {
        creates: Mutex<Vec<String>>,
        deletes: Mutex<Vec<String>>,
    }

    struct AllowActivationVerifier;

    impl ActivationApplicationVerifier for AllowActivationVerifier {
        fn verify_application(
            &self,
            _controller: &ActivationController,
            _request: &d2b_provider_activation_nixos::RunnerRequest,
        ) -> Result<(), d2b_provider_activation_nixos::ActivationVerificationError> {
            Ok(())
        }
    }

    fn mutation_target(mutation: Option<&wire::Mutation>) -> String {
        mutation
            .and_then(|mutation| mutation.target.as_ref())
            .map(|target| format!("{}/{}", target.resource_type, target.name))
            .expect("activation mutation target")
    }

    #[async_trait::async_trait]
    impl ActivationResourceClient for RecordingActivationClient {
        async fn create(
            &self,
            request: wire::CreateRequest,
        ) -> Result<wire::CreateResponse, ()> {
            self.creates
                .lock()
                .unwrap()
                .push(mutation_target(request.mutation.as_ref()));
            Ok(wire::CreateResponse::new())
        }

        async fn update_status(
            &self,
            _request: wire::UpdateStatusRequest,
        ) -> Result<wire::UpdateStatusResponse, ()> {
            Ok(wire::UpdateStatusResponse::new())
        }

        async fn update_finalizers(
            &self,
            _request: wire::UpdateFinalizersRequest,
        ) -> Result<wire::UpdateFinalizersResponse, ()> {
            Ok(wire::UpdateFinalizersResponse::new())
        }

        async fn delete(
            &self,
            request: wire::DeleteRequest,
        ) -> Result<wire::DeleteResponse, ()> {
            self.deletes
                .lock()
                .unwrap()
                .push(mutation_target(request.mutation.as_ref()));
            Ok(wire::DeleteResponse::new())
        }
    }

    fn test_server_state() -> (Arc<crate::ServerState>, tempfile::TempDir) {
        let directory = tempfile::tempdir().expect("temporary activation state");
        let broker_reap_log = d2bd_runtime::supervisor::pidfd_table::BrokerReapLog::new();
        let state = crate::ServerState {
            config: crate::DaemonConfig::default(),
            daemon_uid: 0,
            daemon_state_dir: directory.path().to_path_buf(),
            pidfd_table: Arc::new(
                d2bd_runtime::supervisor::pidfd_table::PidfdTable::new(
                    directory.path().join("pidfd-table.json"),
                )
                .with_broker_reap_log(Arc::clone(&broker_reap_log)),
            ),
            broker_reap_log,
            metrics_registry: Arc::new(d2bd_runtime::metrics::Registry::new()),
            daemon_audit: Arc::new(d2bd_runtime::daemon_audit::DaemonAuditLog::no_op()),
            exec_sessions: Arc::new(crate::exec_session::SessionTable::new(
                crate::exec_session::ExecSessionCaps::default(),
            )),
            conn_semaphore: d2bd_runtime::concurrency::ConnSemaphore::new(8),
            op_locks: d2bd_runtime::concurrency::OpLockManager::new(),
            public_status_read_model: Arc::new(
                d2bd_runtime::public_read_model::PublicStatusReadModel::new(),
            ),
            provider_runtime: Arc::new(crate::provider_registry::ProviderRuntime::new()),
            resource_plane: Arc::new(Mutex::new(None)),
            interaction_runtime: Arc::new(tokio::sync::Mutex::new(None)),
            interaction_listeners: Arc::new(Mutex::new(None)),
            typed_shell_session_targets: d2bd_runtime::typed_shell_targets::new_cache(),
            zone_coordinator: d2bd_runtime::zone_authority::new_coordinator(),
            config_staging: Arc::new(Mutex::new(Default::default())),
            guest_component_sessions: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            guest_component_session_locks: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            console_sessions: Arc::new(Mutex::new(
                crate::console_session::ConsoleSessionTable::default(),
            )),
            security_key_sessions: Arc::new(parking_lot::Mutex::new(
                crate::security_key::SkSessionTable::default(),
            )),
            unsafe_local_helpers: Arc::new(
                d2bd_runtime::unsafe_local_helper::HelperRegistry::new(0, []),
            ),
        };
        (Arc::new(state), directory)
    }

    fn generation_resource(
        name: &str,
        execution_ref: &str,
        ordinal: u64,
        prior: Option<&str>,
        phase: &str,
        deletion_requested: bool,
    ) -> StoredResource {
        let execution_ref = ResourceRef::parse(execution_ref).expect("execution ref");
        let prior = prior.map(|name| {
            ResourceRef::parse(&format!("{ACTIVATION_TYPE}/{name}")).expect("prior generation ref")
        });
        let spec = NixosGenerationSpec::new(
            ResourceRef::parse("Provider/activation-nixos").expect("activation provider"),
            execution_ref,
            "system-artifact",
            ActivationMode::Switch,
            prior,
        )
        .expect("activation spec");
        let uid = ResourceUid::parse(format!(
            "00000000-0000-4000-8000-{ordinal:012x}"
        ))
        .expect("generation UID");
        let resource_ref =
            ResourceRef::parse(&format!("{ACTIVATION_TYPE}/{name}")).expect("generation ref");
        let body = serde_json::json!({
            "apiVersion": "resources.d2bus.org/v3",
            "type": ACTIVATION_TYPE,
            "metadata": {
                "createdAt": "2026-09-03T00:00:00.000Z",
                "updatedAt": "2026-09-03T00:00:00.000Z",
                "managedBy": "controller",
                "ownerRef": null,
                "name": name,
                "zone": "dev",
                "uid": uid.as_str(),
                "generation": 1,
                "revision": ordinal.max(1),
                "finalizers": [ACTIVATION_FINALIZER],
                "deletionRequestedAt": if deletion_requested {
                    serde_json::Value::String("2026-09-03T00:00:00.000Z".to_owned())
                } else {
                    serde_json::Value::Null
                }
            },
            "spec": serde_json::to_value(spec).expect("activation spec JSON"),
            "status": {
                "phase": phase,
                "observedGeneration": 0,
                "lastReconciledAt": null,
                "startedAt": null,
                "completedAt": null,
                "outcome": null,
                "conditions": [],
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
        let canonical = CanonicalJsonValue::parse(
            &serde_json::to_vec(&body).expect("generation JSON"),
        )
        .expect("canonical generation JSON")
        .to_canonical_bytes();
        let payload_digest = ResourceEnvelope::from_json(&canonical)
            .expect("generation envelope")
            .digest()
            .expect("generation digest");
        StoredResource {
            resource_ref,
            zone: ZoneId::parse("dev").expect("generation zone"),
            uid,
            owner_uid: None,
            owner_generation: None,
            generation: d2b_contracts_resource::v3::ResourceGeneration::new(1)
                .expect("generation ordinal"),
            revision: ZoneRevision::new(ordinal.max(1)),
            canonical_json: canonical,
            payload_digest,
        }
    }

    fn insert_records(runtime: &mut ActivationResourceRuntime, resources: Vec<StoredResource>) {
        runtime
            .records
            .extend(decode_resources(&ZoneId::parse("dev").unwrap(), resources).unwrap());
    }

    #[test]
    fn generation_ordinals_are_taken_from_bounded_names() {
        let resource_ref =
            ResourceRef::parse("activation-nixos.d2bus.org.NixosGeneration/dev-vm--gen-7")
                .expect("valid generation reference");
        let resource = StoredResource {
            resource_ref,
            zone: ZoneId::parse("dev").expect("zone"),
            uid: d2b_contracts_resource::v3::ResourceUid::parse(
                "123e4567-e89b-42d3-a456-426614174000",
            )
            .expect("uid"),
            owner_uid: None,
            owner_generation: None,
            generation: d2b_contracts_resource::v3::ResourceGeneration::new(1).expect("generation"),
            revision: ZoneRevision::new(1),
            canonical_json: Vec::new(),
            payload_digest: "sha256:".to_owned(),
        };
        assert_eq!(ordinal_from_resource(&resource), 7);
    }

    #[test]
    fn boot_success_projects_the_durable_default_without_live_activation_detail() {
        assert_eq!(
            activation_detail(
                ActivationMode::Boot,
                ActivationOutcomeCode::Succeeded,
                ResourcePhase::Succeeded,
            ),
            ActivationDetail::BootDefault
        );
        assert_eq!(
            activation_detail(
                ActivationMode::Switch,
                ActivationOutcomeCode::Succeeded,
                ResourcePhase::Succeeded,
            ),
            ActivationDetail::Applied
        );
    }

    #[test]
    fn activation_runtime_deadline_is_not_success() {
        let resource = StoredResource {
            resource_ref: ResourceRef::parse("EphemeralProcess/activation").expect("ref"),
            zone: ZoneId::parse("dev").expect("zone"),
            uid: d2b_contracts_resource::v3::ResourceUid::parse(
                "123e4567-e89b-42d3-a456-426614174000",
            )
            .expect("uid"),
            owner_uid: None,
            owner_generation: None,
            generation: d2b_contracts_resource::v3::ResourceGeneration::new(1).expect("generation"),
            revision: ZoneRevision::new(1),
            canonical_json: br#"{"status":{"outcome":{"code":"runtime-deadline"}}}"#.to_vec(),
            payload_digest: "sha256:".to_owned(),
        };
        assert_eq!(
            status_outcome(&resource),
            Some(ActivationOutcomeCode::HelperFailed)
        );
    }

    #[test]
    fn activation_descriptor_owns_only_generation_resources() {
        let identity = ControllerIdentity::new(
            ZoneId::parse("dev").unwrap(),
            ResourceRef::parse("Process/activation-controller").unwrap(),
            d2b_contracts_resource::v3::ControllerGeneration::new(1).unwrap(),
            ResourceRef::parse("Provider/activation-nixos").unwrap(),
            d2b_contracts_resource::v3::ResourceGeneration::new(1).unwrap(),
            ResourceRef::parse("Process/activation-controller").unwrap(),
            ResourceRef::parse("Host/host-system").unwrap(),
            None,
        )
        .unwrap();
        let descriptor = activation_controller_descriptor(identity).unwrap();
        assert_eq!(
            descriptor
                .resource_types()
                .map(ResourceTypeName::as_str)
                .collect::<Vec<_>>(),
            vec![ACTIVATION_TYPE]
        );
        assert_eq!(descriptor.finalizers(), &[ACTIVATION_FINALIZER.to_owned()]);
        assert!(descriptor.consumes_owner_triggers());
    }

    #[test]
    fn activation_status_drops_credential_material_before_projection() {
        let mut status = BTreeMap::from([
            (
                "credentialBytes".to_owned(),
                CanonicalJsonValue::String("credential-value".to_owned()),
            ),
            (
                "outcome".to_owned(),
                CanonicalJsonValue::Object(BTreeMap::from([(
                    "message".to_owned(),
                    CanonicalJsonValue::String("secret-value".to_owned()),
                )])),
            ),
            (
                "phase".to_owned(),
                CanonicalJsonValue::String("Pending".to_owned()),
            ),
        ]);
        redact_status_fields(&mut status);
        assert!(!status.contains_key("credentialBytes"));
        assert!(!status.contains_key("outcome"));
        assert_eq!(
            status.get("phase"),
            Some(&CanonicalJsonValue::String("Pending".to_owned()))
        );
    }

    #[test]
    fn production_activation_path_invokes_the_verification_gate() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct CountingVerifier {
            calls: Arc<AtomicUsize>,
        }

        impl ActivationApplicationVerifier for CountingVerifier {
            fn verify_application(
                &self,
                _controller: &ActivationController,
                _request: &d2b_provider_activation_nixos::RunnerRequest,
            ) -> Result<(), d2b_provider_activation_nixos::ActivationVerificationError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }

        let calls = Arc::new(AtomicUsize::new(0));
        let mut runtime = ActivationResourceRuntime::new(ZoneId::parse("dev").unwrap());
        runtime.set_verifier(Arc::new(CountingVerifier {
            calls: Arc::clone(&calls),
        }));
        let request = d2b_provider_activation_nixos::RunnerRequest {
            runner_name: d2b_contracts_resource::v3::ResourceName::parse("runner").unwrap(),
            execution_ref: ResourceRef::parse("Host/host-system").unwrap(),
            system_artifact_id: d2b_contracts_resource::v3::ArtifactId::parse("system").unwrap(),
            activation_mode: ActivationMode::Switch,
            target_generation: 1,
            start_root: true,
        };
        assert!(runtime.application_is_verified(&request));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn missing_activation_verification_fails_closed() {
        let runtime = ActivationResourceRuntime::new(ZoneId::parse("dev").unwrap());
        let request = d2b_provider_activation_nixos::RunnerRequest {
            runner_name: d2b_contracts_resource::v3::ResourceName::parse("runner").unwrap(),
            execution_ref: ResourceRef::parse("Host/host-system").unwrap(),
            system_artifact_id: d2b_contracts_resource::v3::ArtifactId::parse("system").unwrap(),
            activation_mode: ActivationMode::Switch,
            target_generation: 1,
            start_root: true,
        };
        assert!(!runtime.application_is_verified(&request));
    }

    #[test]
    fn activation_pass_selects_only_the_hinted_resource_identity() {
        let target =
            ResourceRef::parse("activation-nixos.d2bus.org.NixosGeneration/target").unwrap();
        let sibling =
            ResourceRef::parse("activation-nixos.d2bus.org.NixosGeneration/sibling").unwrap();
        assert!(selected_target(Some(&target), &target));
        assert!(!selected_target(Some(&target), &sibling));
        assert!(selected_target(None, &sibling));
    }

    #[tokio::test]
    async fn production_target_reconcile_uses_prior_sibling_without_touching_other_execution() {
        let (state, _directory) = test_server_state();
        let client = Arc::new(RecordingActivationClient::default());
        let mut runtime = ActivationResourceRuntime::new(ZoneId::parse("dev").unwrap());
        runtime.set_status_client(Arc::clone(&client));
        runtime.set_verifier(Arc::new(AllowActivationVerifier));
        let prior = generation_resource("gen-1", "Guest/dev-vm", 1, None, "Succeeded", false);
        let target = generation_resource(
            "gen-2",
            "Guest/dev-vm",
            2,
            Some("gen-1"),
            "Pending",
            false,
        );
        let other = generation_resource(
            "other-9",
            "Guest/other-vm",
            9,
            None,
            "Pending",
            false,
        );
        insert_records(&mut runtime, vec![other.clone()]);
        runtime
            .reconcile(
                state,
                vec![prior.clone(), target.clone(), other.clone()],
                Vec::new(),
                Some(&target.resource_ref),
            )
            .await
            .expect("target generation reconciles with its prior sibling");
        assert_eq!(
            client.creates.lock().unwrap().as_slice(),
            &[format!(
                "EphemeralProcess/{}",
                activation_runner_ref(&target.resource_ref).name().as_str()
            )]
        );
        assert!(runtime.records.contains_key(&prior.resource_ref));
        assert!(runtime.records.contains_key(&target.resource_ref));
        assert!(runtime.records.contains_key(&other.resource_ref));
        assert!(client.deletes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn production_target_reconcile_rejects_missing_or_cross_execution_prior() {
        let (state, _directory) = test_server_state();
        let client = Arc::new(RecordingActivationClient::default());
        let mut runtime = ActivationResourceRuntime::new(ZoneId::parse("dev").unwrap());
        runtime.set_status_client(Arc::clone(&client));
        runtime.set_verifier(Arc::new(AllowActivationVerifier));
        let target = generation_resource(
            "gen-2",
            "Guest/dev-vm",
            2,
            Some("gen-1"),
            "Pending",
            false,
        );
        let wrong_execution = generation_resource(
            "gen-1",
            "Guest/other-vm",
            1,
            None,
            "Succeeded",
            false,
        );
        assert_eq!(
            runtime
                .reconcile(
                    state,
                    vec![target.clone(), wrong_execution],
                    Vec::new(),
                    Some(&target.resource_ref),
                )
                .await,
            Err(ActivationResourceRuntimeError::Policy)
        );
        assert!(client.creates.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn production_target_retention_deletes_only_old_terminal_same_execution_sibling() {
        let client = Arc::new(RecordingActivationClient::default());
        let mut runtime = ActivationResourceRuntime::new(ZoneId::parse("dev").unwrap());
        runtime.set_status_client(Arc::clone(&client));
        let execution_ref = ResourceRef::parse("Guest/dev-vm").unwrap();
        let resources = vec![
            generation_resource("gen-1", "Guest/dev-vm", 1, None, "Succeeded", false),
            generation_resource("gen-2", "Guest/dev-vm", 2, None, "Succeeded", false),
            generation_resource("gen-3", "Guest/dev-vm", 3, None, "Succeeded", false),
            generation_resource("gen-4", "Guest/dev-vm", 4, None, "Ready", false),
            generation_resource("other-1", "Guest/other-vm", 1, None, "Succeeded", false),
        ];
        insert_records(&mut runtime, resources);
        runtime
            .apply_retention(Some(&execution_ref))
            .await
            .expect("target-scoped retention succeeds");
        assert_eq!(
            client.deletes.lock().unwrap().as_slice(),
            &["activation-nixos.d2bus.org.NixosGeneration/gen-1".to_owned()]
        );
    }
}
