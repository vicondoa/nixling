//! Zone resource reconciliation and scoped session admission for Credential
//! Providers.

use std::sync::Arc;

use async_trait::async_trait;
use d2b_contracts_provider::v3::{
    credential::{
        CREDENTIAL_SERVICE_NAME, CredentialMethod, CredentialOutcomeCode, CredentialRequest,
        CredentialSpec, MetadataResponse, PlacementBinding,
        decode_outer, encode_outer,
    },
    credential_controller::{
        CREDENTIAL_PROVIDER_REVOKE_FINALIZER, CredentialIdempotencyKey, CredentialProviderKind,
    },
};
use d2b_contracts_resource::resource_proto as wire;
use d2b_contracts_resource::v3::{
    CanonicalJsonValue, DesiredLifecycle, ResourceEnvelope, ResourcePhase, ResourceRef,
    ResourceTypeName, ZoneId, canonical_digest,
    execution_policy::{
        BoundedToken, BudgetSpec, DurationMs, ExecutionDomain,
    },
    identity::ReconnectGeneration,
    process::{
        AdoptionPolicy, EnvironmentClass, ExecutionSpec, HealthCheckSpec, NamespaceClass,
        NetworkUsageSpec, ProcessClass, ProcessSpec, ReadinessClass, ReadinessSpec,
        RestartPolicySpec, SandboxSpec, TelemetrySpec,
    },
};
use d2b_core_controller::{
    ControllerDescriptor, ControllerExecutionPolicy, ControllerIdentity, ControllerSelector,
    ControllerVerb, DependencySnapshot, DisruptionClass, DrainResult, FinalizeResult,
    HandlerFailure, ObservationResult, ReconcileContext, ReconcileDisposition, ReconcilePlan,
    ReconcileReason, ReconcileResult, ResourceMutationBatch, ResourceReconciler,
    ResourceRegistration, ResourceSnapshot, ResyncPolicy, SelectorField, UpdateAssessment,
    UpdateAssessmentState, UpgradePlan, UpgradeStage, ValidationResult,
};
use d2b_provider_transport_azure_relay::{
    RelayCredentialError, RelayCredentialLease, ScopedCredentialClient, ScopedCredentialRequest,
};
use d2b_resource_api::{RedbBackend, ResourceApiClient, service::UnavailableUpgradeDispatcher};
use d2b_resource_store::{
    StoreError, StoreFilter, StoreListRequest, StoreListResult, StoreOperationContext,
    StoreProjection, StoredResource,
};
use d2b_resource_store_redb::RedbResourceStore;
use d2b_session::{ComponentSessionDriver, SessionTtrpcClient};

const CREDENTIAL_RESOURCE_TYPE: &str = "Credential";
const PROCESS_RESOURCE_TYPE: &str = "Process";

/// Stable failures from the Credential resource adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CredentialResourceRuntimeError {
    /// A resource or identity failed closed validation.
    InvalidResource,
    /// The Zone resource store could not be read.
    Store,
    /// A bounded cleanup or Resource API operation failed.
    Cleanup,
    /// A typed Credential session refused or could not confirm revocation.
    Revocation,
}

impl core::fmt::Display for CredentialResourceRuntimeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidResource => "credential-resource-invalid",
            Self::Store => "credential-resource-store-failed",
            Self::Cleanup => "credential-resource-cleanup-failed",
            Self::Revocation => "credential-revocation-unconfirmed",
        })
    }
}

impl std::error::Error for CredentialResourceRuntimeError {}

#[async_trait]
pub(crate) trait CredentialResourceStore: Send + Sync {
    async fn list(&self, request: StoreListRequest) -> Result<StoreListResult, StoreError>;
}

#[async_trait]
impl CredentialResourceStore for RedbResourceStore {
    async fn list(&self, request: StoreListRequest) -> Result<StoreListResult, StoreError> {
        RedbResourceStore::list(self, request).await
    }
}

#[async_trait]
pub(crate) trait CredentialResourceClient: Send + Sync {
    async fn delete(&self, request: wire::DeleteRequest) -> wire::DeleteResponse;

    async fn update_finalizers(
        &self,
        request: wire::UpdateFinalizersRequest,
    ) -> wire::UpdateFinalizersResponse;
}

#[async_trait]
impl CredentialResourceClient for ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher> {
    async fn delete(&self, request: wire::DeleteRequest) -> wire::DeleteResponse {
        ResourceApiClient::delete(self, request).await
    }

    async fn update_finalizers(
        &self,
        request: wire::UpdateFinalizersRequest,
    ) -> wire::UpdateFinalizersResponse {
        ResourceApiClient::update_finalizers(self, request).await
    }
}

/// Exact non-secret input for one provider-side RevokeToken call.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CredentialRevocationRequest {
    zone: ZoneId,
    credential_ref: ResourceRef,
    credential_uid: d2b_contracts_resource::v3::ResourceUid,
    credential_generation: d2b_contracts_resource::v3::ResourceGeneration,
    provider_ref: ResourceRef,
    provider_generation: d2b_contracts_resource::v3::ResourceGeneration,
    controller_generation: d2b_contracts_resource::v3::ControllerGeneration,
    session_generation: ReconnectGeneration,
    operation_id: String,
    idempotency_key: String,
    deadline_ms: u64,
}

impl core::fmt::Debug for CredentialRevocationRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CredentialRevocationRequest")
            .field("credential_ref", &"<redacted>")
            .field("credential_uid", &"<redacted>")
            .field("credential_generation", &self.credential_generation)
            .field("provider_ref", &"<redacted>")
            .field("provider_generation", &self.provider_generation)
            .field("controller_generation", &self.controller_generation)
            .field("session_generation", &self.session_generation)
            .field("operation_id", &"<redacted>")
            .field("idempotency_key", &"<redacted>")
            .field("deadline_ms", &self.deadline_ms)
            .finish()
    }
}

impl CredentialRevocationRequest {
    fn new(
        resource: &ResourceSnapshot,
        provider_ref: &ResourceRef,
        identity: &ControllerIdentity,
        session_generation: ReconnectGeneration,
    ) -> Result<Self, CredentialResourceRuntimeError> {
        if identity.zone() != resource.key().zone()
            || identity.provider_ref() != provider_ref
            || session_generation.get() == 0
        {
            return Err(CredentialResourceRuntimeError::InvalidResource);
        }
        let rotation_generation = credential_lease_generation(resource).unwrap_or(1);
        let operation_id = credential_revoke_operation_id(
            resource,
            provider_ref,
            identity.provider_generation(),
            identity.controller_generation(),
        );
        let idempotency_key = CredentialIdempotencyKey::derive(
            resource.key().uid(),
            rotation_generation,
            CredentialMethod::RevokeToken,
        )
        .map_err(|_| CredentialResourceRuntimeError::Revocation)?
        .request_value();
        Ok(Self {
            zone: resource.key().zone().clone(),
            credential_ref: resource.key().resource_ref().clone(),
            credential_uid: resource.key().uid().clone(),
            credential_generation: resource.generation(),
            provider_ref: provider_ref.clone(),
            provider_generation: identity.provider_generation(),
            controller_generation: identity.controller_generation(),
            session_generation,
            operation_id,
            idempotency_key,
            deadline_ms: 10_000,
        })
    }
}

/// Provider-side revocation result. Only confirmed outcomes may unblock
/// Process cleanup and finalizer release.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CredentialRevocationOutcome {
    Revoked,
    AlreadyRevoked,
    Uncertain,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CredentialRevocationEvidence {
    operation_id: String,
    outcome: CredentialRevocationOutcome,
    session_generation: ReconnectGeneration,
}

impl CredentialRevocationEvidence {
    fn confirmed(
        request: &CredentialRevocationRequest,
        outcome: CredentialRevocationOutcome,
    ) -> Self {
        Self {
            operation_id: request.operation_id.clone(),
            outcome,
            session_generation: request.session_generation,
        }
    }

    fn outcome_code(&self) -> &'static str {
        match self.outcome {
            CredentialRevocationOutcome::Revoked => "revoked",
            CredentialRevocationOutcome::AlreadyRevoked => "already-revoked",
            CredentialRevocationOutcome::Uncertain => "uncertain",
        }
    }
}

impl core::fmt::Debug for CredentialRevocationEvidence {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CredentialRevocationEvidence")
            .field("operation_id", &"<redacted>")
            .field("outcome", &self.outcome)
            .field("session_generation", &self.session_generation)
            .finish()
    }
}

/// Typed Credential session used by the resource controller's cleanup effect.
#[async_trait]
pub(crate) trait CredentialSession: Send + Sync {
    fn session_generation(&self) -> Option<ReconnectGeneration>;

    async fn revoke_credential(
        &self,
        request: &CredentialRevocationRequest,
    ) -> Result<CredentialRevocationOutcome, CredentialResourceRuntimeError>;
}

/// One authenticated Provider ComponentSession used for typed Credential calls.
///
/// The session driver is supplied by the daemon's ProviderSupervisor handoff.
/// This adapter owns only the generated ttrpc client and a single-flight gate;
/// Resource status remains the durable evidence owner.
pub(crate) struct ComponentCredentialSession {
    route: d2b_session::AuthenticatedSessionRouteBinding,
    driver: Arc<dyn ComponentSessionDriver>,
    client: Arc<SessionTtrpcClient>,
    gate: tokio::sync::Mutex<()>,
}

impl ComponentCredentialSession {
    pub(crate) fn new(
        route: d2b_session::AuthenticatedSessionRouteBinding,
        driver: Arc<dyn ComponentSessionDriver>,
    ) -> Result<Self, CredentialResourceRuntimeError> {
        if route.provider_ref().is_none()
            || route.reconnect_generation().get() == 0
            || driver.generation() != route.reconnect_generation().get()
            || !route.liveness().is_live()
            || route.service().as_str() != CREDENTIAL_SERVICE_NAME
        {
            return Err(CredentialResourceRuntimeError::InvalidResource);
        }
        let client_driver = Arc::clone(&driver);
        Ok(Self {
            route,
            driver: client_driver,
            client: Arc::new(SessionTtrpcClient::new(driver)),
            gate: tokio::sync::Mutex::new(()),
        })
    }
}

#[async_trait]
impl CredentialSession for ComponentCredentialSession {
    fn session_generation(&self) -> Option<ReconnectGeneration> {
        self.route
            .liveness()
            .is_live()
            .then_some(self.route.reconnect_generation())
    }

    async fn revoke_credential(
        &self,
        request: &CredentialRevocationRequest,
    ) -> Result<CredentialRevocationOutcome, CredentialResourceRuntimeError> {
        let Some(provider_ref) = self.route.provider_ref() else {
            return Err(CredentialResourceRuntimeError::InvalidResource);
        };
        if request.credential_ref.resource_type().as_str() != CREDENTIAL_RESOURCE_TYPE
            || &request.zone != self.route.zone()
            || &request.provider_ref != provider_ref
            || self.route.provider_generation() != Some(request.provider_generation)
            || self.route.controller_generation() != Some(request.controller_generation)
        {
            return Err(CredentialResourceRuntimeError::InvalidResource);
        }
        if request.session_generation != self.route.reconnect_generation() {
            return Ok(CredentialRevocationOutcome::Uncertain);
        }
        let _gate = self.gate.lock().await;
        if !self.route.liveness().is_live()
            || self.driver.generation() != self.route.reconnect_generation().get()
        {
            return Ok(CredentialRevocationOutcome::Uncertain);
        }
        let now_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| CredentialResourceRuntimeError::Revocation)?
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        let expiry = now_unix_ms.saturating_add(request.deadline_ms);
        if expiry <= now_unix_ms {
            return Ok(CredentialRevocationOutcome::Uncertain);
        }
        let typed = CredentialRequest::new(
            request.credential_ref.clone(),
            request.operation_id.clone(),
            request.idempotency_key.clone(),
            expiry,
            expiry,
        )
        .map_err(|_| CredentialResourceRuntimeError::Revocation)?;
        let mut rpc = ttrpc::proto::Request::new();
        rpc.set_service("d2b.credential.v3.CredentialService".to_owned());
        rpc.set_method("RevokeToken".to_owned());
        rpc.timeout_nano = i64::try_from(request.deadline_ms.saturating_mul(1_000_000))
            .unwrap_or(i64::MAX);
        rpc.metadata = vec![
            ttrpc::proto::KeyValue {
                key: "d2b.credential.zone".to_owned(),
                value: request.zone.as_str().to_owned(),
                ..Default::default()
            },
            ttrpc::proto::KeyValue {
                key: "d2b.credential.provider".to_owned(),
                value: request.provider_ref.to_canonical_string(),
                ..Default::default()
            },
            ttrpc::proto::KeyValue {
                key: "d2b.credential.uid".to_owned(),
                value: request.credential_uid.as_str().to_owned(),
                ..Default::default()
            },
            ttrpc::proto::KeyValue {
                key: "d2b.credential.generation".to_owned(),
                value: request.credential_generation.get().to_string(),
                ..Default::default()
            },
            ttrpc::proto::KeyValue {
                key: "d2b.credential.provider-generation".to_owned(),
                value: request.provider_generation.get().to_string(),
                ..Default::default()
            },
            ttrpc::proto::KeyValue {
                key: "d2b.credential.controller-generation".to_owned(),
                value: request.controller_generation.get().to_string(),
                ..Default::default()
            },
            ttrpc::proto::KeyValue {
                key: "d2b.credential.session-generation".to_owned(),
                value: request.session_generation.get().to_string(),
                ..Default::default()
            },
        ];
        rpc.payload = encode_outer(&typed)
            .map_err(|_| CredentialResourceRuntimeError::Revocation)?;
        let response = match self.client.client().request(rpc).await {
            Ok(response) => response,
            Err(_) => return Ok(CredentialRevocationOutcome::Uncertain),
        };
        let metadata: MetadataResponse = decode_outer(&response.payload)
            .map_err(|_| CredentialResourceRuntimeError::Revocation)?;
        if metadata.metadata.state != d2b_contracts_provider::v3::credential::CredentialLeaseState::Revoked {
            return Ok(CredentialRevocationOutcome::Uncertain);
        }
        match metadata.metadata.outcome {
            CredentialOutcomeCode::Revoked => Ok(CredentialRevocationOutcome::Revoked),
            CredentialOutcomeCode::AlreadyRevoked => {
                Ok(CredentialRevocationOutcome::AlreadyRevoked)
            }
            CredentialOutcomeCode::Success => Ok(CredentialRevocationOutcome::Uncertain),
        }
    }
}

/// Registry populated by authenticated ProviderSupervisor session handoffs.
#[derive(Clone, Default)]
pub(crate) struct CredentialSessionRegistry {
    sessions: Arc<
        std::sync::Mutex<
            std::collections::BTreeMap<
                ResourceRef,
                (ReconnectGeneration, Arc<dyn CredentialSession>),
            >,
        >,
    >,
}

impl CredentialSessionRegistry {
    pub(crate) fn register(
        &self,
        provider_ref: ResourceRef,
        session_generation: ReconnectGeneration,
        session: Arc<dyn CredentialSession>,
    ) -> Result<(), CredentialResourceRuntimeError> {
        if provider_ref.resource_type().as_str() != "Provider" || session_generation.get() == 0 {
            return Err(CredentialResourceRuntimeError::InvalidResource);
        }
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| CredentialResourceRuntimeError::Revocation)?;
        if sessions
            .get(&provider_ref)
            .is_some_and(|(generation, _)| *generation > session_generation)
        {
            return Err(CredentialResourceRuntimeError::InvalidResource);
        }
        sessions.insert(provider_ref, (session_generation, session));
        Ok(())
    }

    pub(crate) fn remove(
        &self,
        provider_ref: &ResourceRef,
        session_generation: ReconnectGeneration,
    ) {
        if let Ok(mut sessions) = self.sessions.lock() {
            if sessions
                .get(provider_ref)
                .is_some_and(|(generation, _)| *generation == session_generation)
            {
                sessions.remove(provider_ref);
            }
        }
    }

    pub(crate) fn for_provider(
        &self,
        provider_ref: ResourceRef,
    ) -> Arc<dyn CredentialSession> {
        Arc::new(RegistryCredentialSession {
            provider_ref,
            sessions: Arc::clone(&self.sessions),
        })
    }
}

struct RegistryCredentialSession {
    provider_ref: ResourceRef,
    sessions: Arc<
        std::sync::Mutex<
            std::collections::BTreeMap<
                ResourceRef,
                (ReconnectGeneration, Arc<dyn CredentialSession>),
            >,
        >,
    >,
}

#[async_trait]
impl CredentialSession for RegistryCredentialSession {
    fn session_generation(&self) -> Option<ReconnectGeneration> {
        self.sessions
            .lock()
            .ok()
            .and_then(|sessions| sessions.get(&self.provider_ref).map(|(generation, _)| *generation))
    }

    async fn revoke_credential(
        &self,
        request: &CredentialRevocationRequest,
    ) -> Result<CredentialRevocationOutcome, CredentialResourceRuntimeError> {
        if request.provider_ref != self.provider_ref {
            return Err(CredentialResourceRuntimeError::InvalidResource);
        }
        let current = self
            .sessions
            .lock()
            .map_err(|_| CredentialResourceRuntimeError::Revocation)?
            .get(&self.provider_ref)
            .map(|(generation, session)| (*generation, Arc::clone(session)));
        match current {
            Some((generation, session)) if generation == request.session_generation => {
                session.revoke_credential(request).await
            }
            Some(_) | None => Ok(CredentialRevocationOutcome::Uncertain),
        }
    }
}

/// Build the exact descriptor shared by one Credential Provider controller.
pub(crate) fn credential_controller_descriptor(
    identity: ControllerIdentity,
) -> Result<ControllerDescriptor, CredentialResourceRuntimeError> {
    let credential_type =
        ResourceTypeName::parse(CREDENTIAL_RESOURCE_TYPE).expect("Credential ResourceType");
    let provider_filter = identity.provider_ref().to_canonical_string();
    let resource = ResourceRegistration::new(credential_type.clone(), vec![1], 5_000, 3)
        .map_err(|_| CredentialResourceRuntimeError::InvalidResource)?;
    let selectors = [
        SelectorField::Spec,
        SelectorField::Status,
        SelectorField::Metadata,
        SelectorField::Finalizers,
        SelectorField::Deletion,
    ]
    .into_iter()
    .map(|field| {
        ControllerSelector::new(
            credential_type.clone(),
            field,
            Some(provider_filter.clone()),
        )
        .expect("Credential selector is bounded")
    })
    .collect();
    let dependency_selectors = ["Provider", "Host", "Guest", PROCESS_RESOURCE_TYPE, "User"]
        .into_iter()
        .map(|resource_type| {
            ControllerSelector::new(
                ResourceTypeName::parse(resource_type).expect("dependency ResourceType"),
                SelectorField::Metadata,
                None,
            )
            .expect("Credential dependency selector is bounded")
        })
        .collect();
    let execution = ControllerExecutionPolicy::new(
        8,
        8,
        256,
        8,
        256,
        ResyncPolicy::new(Some(30_000), 5_000).expect("Credential resync policy"),
    )
    .map_err(|_| CredentialResourceRuntimeError::InvalidResource)?;
    ControllerDescriptor::new(
        identity,
        vec![resource],
        vec![
            "resource-service".to_owned(),
            "credential-service".to_owned(),
            "credential-delivery".to_owned(),
        ],
        vec!["system".to_owned(), "user".to_owned()],
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
        vec![CREDENTIAL_PROVIDER_REVOKE_FINALIZER.to_owned()],
        vec![CREDENTIAL_SERVICE_NAME.to_owned()],
        vec!["sha256:0000000000000000000000000000000000000000000000000000000000000001".to_owned()],
        execution,
    )
    .map_err(|_| CredentialResourceRuntimeError::InvalidResource)
}

/// ResourceService-backed Credential handler for the shared Runner.
pub(crate) struct CredentialResourceReconciler<
    S = RedbResourceStore,
    C = ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>,
> {
    store: Arc<S>,
    client: Arc<C>,
    identity: ControllerIdentity,
    provider_ref: ResourceRef,
    provider_kind: CredentialProviderKind,
    credential_session: Arc<dyn CredentialSession>,
}

impl<S, C> CredentialResourceReconciler<S, C>
where
    S: CredentialResourceStore + 'static,
    C: CredentialResourceClient + 'static,
{
    pub(crate) fn new(
        store: Arc<S>,
        client: Arc<C>,
        identity: ControllerIdentity,
        provider_ref: ResourceRef,
        credential_session: Arc<dyn CredentialSession>,
    ) -> Result<Self, CredentialResourceRuntimeError> {
        let provider_kind =
            provider_kind(&provider_ref).ok_or(CredentialResourceRuntimeError::InvalidResource)?;
        Ok(Self {
            store,
            client,
            identity,
            provider_ref,
            provider_kind,
            credential_session,
        })
    }

    fn owns(&self, resource: &ResourceSnapshot) -> Result<bool, CredentialResourceRuntimeError> {
        if resource.key().resource_ref().resource_type().as_str() != CREDENTIAL_RESOURCE_TYPE {
            return Ok(false);
        }
        let value = serde_json::from_slice::<serde_json::Value>(resource.canonical_json())
            .map_err(|_| CredentialResourceRuntimeError::InvalidResource)?;
        Ok(value
            .pointer("/spec/providerRef")
            .and_then(serde_json::Value::as_str)
            .and_then(|value| ResourceRef::parse(value).ok())
            .is_some_and(|provider| provider == self.provider_ref))
    }

    fn should_run(&self, context: &ReconcileContext, resource: &ResourceSnapshot) -> bool {
        if context.reasons().iter().any(|reason| {
            matches!(
                reason,
                d2b_core_controller::CoreTriggerReason::StartupRelist
                    | d2b_core_controller::CoreTriggerReason::SpecGenerationChanged
                    | d2b_core_controller::CoreTriggerReason::DependencyChanged
                    | d2b_core_controller::CoreTriggerReason::DependencyReady
                    | d2b_core_controller::CoreTriggerReason::ProviderGenerationChanged
                    | d2b_core_controller::CoreTriggerReason::PolicyChanged
                    | d2b_core_controller::CoreTriggerReason::SecurityPolicyChanged
                    | d2b_core_controller::CoreTriggerReason::RetryDue
                    | d2b_core_controller::CoreTriggerReason::ManualReconcile
            )
        }) {
            return true;
        }
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(resource.canonical_json())
        else {
            return true;
        };
        let observed = value
            .pointer("/status/observedGeneration")
            .and_then(serde_json::Value::as_u64);
        let phase = value
            .pointer("/status/phase")
            .and_then(serde_json::Value::as_str);
        observed != Some(resource.generation().get())
            || !matches!(phase, Some("Ready" | "Degraded"))
    }

    fn first_finalizer_batch(
        &self,
        resource: &ResourceSnapshot,
    ) -> Result<Option<ResourceMutationBatch>, CredentialResourceRuntimeError> {
        if resource.deleting() || has_finalizer(resource) {
            return Ok(None);
        }
        let mutation = d2b_core_controller::MutationIntent::new(
            resource.key().resource_ref().clone(),
            Some(resource.key().uid().clone()),
            Some(resource.revision()),
            d2b_core_controller::MutationIntentKind::UpdateFinalizers,
            Some(finalizer_payload(resource)?),
        )
        .map_err(|_| CredentialResourceRuntimeError::InvalidResource)?;
        ResourceMutationBatch::new(vec![mutation])
            .map(Some)
            .map_err(|_| CredentialResourceRuntimeError::InvalidResource)
    }

    async fn managed_identity_child_batch(
        &self,
        dependencies: &[DependencySnapshot],
        resource: &ResourceSnapshot,
    ) -> Result<Option<ResourceMutationBatch>, CredentialResourceRuntimeError> {
        if self.provider_kind != CredentialProviderKind::ManagedIdentity
            || !dependency_ready(dependencies, &self.provider_ref)
        {
            return Ok(None);
        }
        let spec = credential_spec(resource)?;
        let execution_ref = credential_execution_ref(&spec)?;
        if !dependency_ready(dependencies, execution_ref) {
            return Ok(None);
        }
        let child_ref = managed_identity_agent_ref(resource)?;
        let children = self.owned_processes(resource).await?;
        let child = children
            .iter()
            .find(|child| child.resource_ref == child_ref);
        let Some(child) = child else {
            let mutation = d2b_core_controller::MutationIntent::new(
                child_ref,
                None,
                None,
                d2b_core_controller::MutationIntentKind::Create,
                Some(managed_identity_agent_payload(resource)?),
            )
            .map_err(|_| CredentialResourceRuntimeError::InvalidResource)?;
            return ResourceMutationBatch::new(vec![mutation])
                .map(Some)
                .map_err(|_| CredentialResourceRuntimeError::InvalidResource);
        };
        if managed_identity_agent_matches(child, resource) || deletion_requested(child) {
            return Ok(None);
        }
        let mutation = d2b_core_controller::MutationIntent::new(
            child.resource_ref.clone(),
            Some(child.uid.clone()),
            Some(child.revision),
            d2b_core_controller::MutationIntentKind::Delete,
            None,
        )
        .map_err(|_| CredentialResourceRuntimeError::InvalidResource)?;
        ResourceMutationBatch::new(vec![mutation])
            .map(Some)
            .map_err(|_| CredentialResourceRuntimeError::InvalidResource)
    }

    async fn owned_processes(
        &self,
        owner: &ResourceSnapshot,
    ) -> Result<Vec<StoredResource>, CredentialResourceRuntimeError> {
        let mut resources = Vec::new();
        let mut cursor = None;
        loop {
            let operation_id = credential_process_list_operation_id(owner);
            let page = self
                .store
                .list(StoreListRequest {
                    operation: StoreOperationContext {
                        operation_id: operation_id.clone(),
                        idempotency_key: None,
                        correlation_id: operation_id,
                        trace_id: None,
                        deadline_ms: 5_000,
                    },
                    zone: owner.key().zone().clone(),
                    resource_types: vec![
                        ResourceTypeName::parse(PROCESS_RESOURCE_TYPE)
                            .expect("Process ResourceType"),
                    ],
                    resource_names: Vec::new(),
                    filters: vec![StoreFilter {
                        field: "owner.resourceUid".to_owned(),
                        values: vec![owner.key().uid().as_str().to_owned()],
                    }],
                    page_size: 256,
                    cursor,
                    projection: StoreProjection::Full,
                })
                .await
                .map_err(|_| CredentialResourceRuntimeError::Store)?;
            resources.extend(page.resources);
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        Ok(resources
            .into_iter()
            .filter(|resource| owner_ref(resource).as_ref() == Some(owner.key().resource_ref()))
            .collect())
    }

    async fn request_process_deletion(
        &self,
        resource: &StoredResource,
    ) -> Result<(), CredentialResourceRuntimeError> {
        let mut mutation = wire::Mutation::new();
        mutation.kind = protobuf::EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_DELETE);
        mutation.target = protobuf::MessageField::some(resource_identity(resource));
        mutation.precondition = protobuf::MessageField::some(exact_precondition_stored(resource));
        let operation = credential_process_delete_operation_id(resource);
        let mut request = wire::DeleteRequest::new();
        request.meta = protobuf::MessageField::some(
            d2bd_runtime::resource_runtime_support::public_request_meta(&operation),
        );
        request.mutation = protobuf::MessageField::some(mutation);
        if self.client.delete(request).await.error.is_some() {
            return Err(CredentialResourceRuntimeError::Cleanup);
        }
        Ok(())
    }

    async fn release_finalizer(
        &self,
        resource: &ResourceSnapshot,
    ) -> Result<(), CredentialResourceRuntimeError> {
        let mut mutation = wire::Mutation::new();
        mutation.kind =
            protobuf::EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_UPDATE_FINALIZERS);
        mutation.target = protobuf::MessageField::some(resource_identity_snapshot(resource));
        mutation.precondition = protobuf::MessageField::some(exact_precondition_snapshot(resource));
        mutation
            .remove_finalizers
            .push(CREDENTIAL_PROVIDER_REVOKE_FINALIZER.to_owned());
        let operation = credential_finalizer_release_operation_id(resource);
        let mut request = wire::UpdateFinalizersRequest::new();
        request.meta = protobuf::MessageField::some(
            d2bd_runtime::resource_runtime_support::public_request_meta(&operation),
        );
        request.mutation = protobuf::MessageField::some(mutation);
        if self.client.update_finalizers(request).await.error.is_some() {
            return Err(CredentialResourceRuntimeError::Cleanup);
        }
        Ok(())
    }
}

impl<S, C> ResourceReconciler for CredentialResourceReconciler<S, C>
where
    S: CredentialResourceStore + 'static,
    C: CredentialResourceClient + 'static,
{
    type Error = CredentialResourceRuntimeError;

    fn classify_error(&self, error: &Self::Error) -> HandlerFailure {
        if matches!(error, Self::Error::InvalidResource) {
            HandlerFailure::terminal()
        } else {
            HandlerFailure::retryable()
        }
    }

    fn describe(
        &self,
    ) -> impl std::future::Future<Output = Result<ControllerDescriptor, Self::Error>> + Send {
        std::future::ready(credential_controller_descriptor(self.identity.clone()))
    }

    fn validate_spec(
        &self,
        _context: &ReconcileContext,
        resource: &ResourceSnapshot,
    ) -> impl std::future::Future<Output = Result<ValidationResult, Self::Error>> + Send {
        let result = match credential_spec(resource) {
            Ok(spec)
                if serde_json::from_slice::<serde_json::Value>(resource.canonical_json())
                    .ok()
                    .and_then(|value| {
                        value
                            .pointer("/spec/providerRef")
                            .and_then(serde_json::Value::as_str)
                            .and_then(|provider| ResourceRef::parse(provider).ok())
                    })
                    .is_some_and(|provider| provider == self.provider_ref)
                    && credential_scope_valid(self.provider_kind, &spec) =>
            {
                ValidationResult::Valid
            }
            _ => ValidationResult::Invalid {
                reason: ReconcileReason::InvalidSpec,
            },
        };
        std::future::ready(Ok(result))
    }

    fn plan(
        &self,
        context: &ReconcileContext,
        resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
    ) -> impl std::future::Future<Output = Result<ReconcilePlan, Self::Error>> + Send {
        let result = self.owns(resource).and_then(|owned| {
            if owned && self.should_run(context, resource) {
                ReconcilePlan::new(
                    vec![format!(
                        "credential-reconcile-{}",
                        self.provider_kind.as_str()
                    )],
                    false,
                )
            } else {
                ReconcilePlan::new(Vec::new(), true)
            }
            .map_err(|_| CredentialResourceRuntimeError::InvalidResource)
        });
        std::future::ready(result)
    }

    fn reconcile(
        &self,
        context: &ReconcileContext,
        resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
        plan: &ReconcilePlan,
    ) -> impl std::future::Future<Output = Result<ReconcileResult, Self::Error>> + Send {
        let result = async move {
            if !self.owns(resource)? || plan.is_no_op() {
                return Ok(ReconcileResult::converged(
                    resource.revision(),
                    resource.generation(),
                ));
            }
            context
                .authorize_effect()
                .map_err(|_| CredentialResourceRuntimeError::InvalidResource)?;
            if let Some(batch) = self.first_finalizer_batch(resource)? {
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
                .map_err(|_| CredentialResourceRuntimeError::InvalidResource);
            }
            if let Some(batch) = self
                .managed_identity_child_batch(_dependencies, resource)
                .await?
            {
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
                .map_err(|_| CredentialResourceRuntimeError::InvalidResource);
            }
            Ok(ReconcileResult::converged(
                resource.revision(),
                resource.generation(),
            ))
        };
        result
    }

    fn execute_effect(
        &self,
        context: &ReconcileContext,
        resource: &ResourceSnapshot,
        dependencies: &[DependencySnapshot],
        _plan: &ReconcilePlan,
    ) -> impl std::future::Future<Output = Result<ReconcileResult, Self::Error>> + Send {
        let provider_ref = self.provider_ref.clone();
        let provider_ready = dependencies.iter().any(|dependency| {
            dependency.resource().key().resource_ref() == &provider_ref
                && serde_json::from_slice::<serde_json::Value>(
                    dependency.resource().canonical_json(),
                )
                .ok()
                .and_then(|value| {
                    (value
                        .pointer("/status/phase")
                        .and_then(serde_json::Value::as_str)
                        == Some("Ready")
                        && value
                            .pointer("/status/observedGeneration")
                            .and_then(serde_json::Value::as_u64)
                            == Some(dependency.resource().generation().get()))
                    .then_some(())
                })
                .is_some()
        });
        let provider_kind = self.provider_kind;
        let result = async move {
            context
                .authorize_effect()
                .map_err(|_| CredentialResourceRuntimeError::InvalidResource)?;
            let (phase, outcome, disposition) = if provider_ready
                && provider_kind == CredentialProviderKind::ManagedIdentity
            {
                let children = self.owned_processes(resource).await?;
                let child_ref = managed_identity_agent_ref(resource)?;
                match children.iter().find(|child| child.resource_ref == child_ref) {
                    Some(child) if managed_identity_agent_ready(child) => (
                        ResourcePhase::Ready,
                        "success",
                        ReconcileDisposition::Converged,
                    ),
                    Some(child) if deletion_requested(child) => (
                        ResourcePhase::Degraded,
                        "credential-agent-draining",
                        ReconcileDisposition::Pending,
                    ),
                    Some(_) => (
                        ResourcePhase::Degraded,
                        "credential-agent-unavailable",
                        ReconcileDisposition::Pending,
                    ),
                    None => (
                        ResourcePhase::Pending,
                        "credential-agent-pending",
                        ReconcileDisposition::Pending,
                    ),
                }
            } else if provider_ready {
                (ResourcePhase::Ready, "success", ReconcileDisposition::Converged)
            } else {
                (
                    ResourcePhase::Degraded,
                    "credential-provider-unavailable",
                    ReconcileDisposition::Degraded,
                )
            };
            let status = credential_status_candidate(
                resource,
                phase,
                outcome,
                false,
                None,
            )?;
            ReconcileResult::new(
                resource.revision(),
                resource.generation(),
                None,
                Some(status),
                disposition,
                None,
                None,
                d2b_core_controller::StatusPersistence::Pending,
            )
            .map_err(|_| CredentialResourceRuntimeError::InvalidResource)
        };
        result
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

    fn prepare_finalize(
        &self,
        _context: &ReconcileContext,
        resource: &ResourceSnapshot,
    ) -> impl std::future::Future<Output = Result<ReconcileResult, Self::Error>> + Send {
        std::future::ready(Ok(ReconcileResult::converged(
            resource.revision(),
            resource.generation(),
        )))
    }

    fn execute_finalize(
        &self,
        context: &ReconcileContext,
        resource: &ResourceSnapshot,
    ) -> impl std::future::Future<Output = Result<ReconcileResult, Self::Error>> + Send {
        let future = async move {
            context
                .authorize_effect()
                .map_err(|_| CredentialResourceRuntimeError::InvalidResource)?;
            let lease_state = lease_state(resource);
            if matches!(lease_state.as_deref(), Some("Active" | "Unknown")) {
                let Some(session_generation) = self.credential_session.session_generation() else {
                    let status = credential_status_candidate(
                        resource,
                        ResourcePhase::Degraded,
                        "credential-revocation-uncertain",
                        false,
                        None,
                    )?;
                    return ReconcileResult::new(
                        resource.revision(),
                        resource.generation(),
                        None,
                        Some(status),
                        ReconcileDisposition::Degraded,
                        None,
                        None,
                        d2b_core_controller::StatusPersistence::Pending,
                    )
                    .map_err(|_| CredentialResourceRuntimeError::InvalidResource);
                };
                let request = CredentialRevocationRequest::new(
                    resource,
                    &self.provider_ref,
                    &self.identity,
                    session_generation,
                )?;
                let outcome = self.credential_session.revoke_credential(&request).await?;
                let evidence = CredentialRevocationEvidence::confirmed(&request, outcome);
                let (phase, outcome_code, lease_revoked) = match outcome {
                    CredentialRevocationOutcome::Revoked
                    | CredentialRevocationOutcome::AlreadyRevoked => (
                        ResourcePhase::Pending,
                        "credential-lease-revoked",
                        true,
                    ),
                    CredentialRevocationOutcome::Uncertain => (
                        ResourcePhase::Degraded,
                        "credential-revocation-uncertain",
                        false,
                    ),
                };
                let status = credential_status_candidate(
                    resource,
                    phase,
                    outcome_code,
                    lease_revoked,
                    Some(&evidence),
                )?;
                return ReconcileResult::new(
                    resource.revision(),
                    resource.generation(),
                    None,
                    Some(status),
                    ReconcileDisposition::Pending,
                    None,
                    None,
                    d2b_core_controller::StatusPersistence::Pending,
                )
                .map_err(|_| CredentialResourceRuntimeError::InvalidResource);
            }
            let children = self.owned_processes(resource).await?;
            if let Some(child) = children.iter().find(|child| !deletion_requested(child)) {
                self.request_process_deletion(child).await?;
                return Ok(ReconcileResult::converged(
                    resource.revision(),
                    resource.generation(),
                ));
            }
            if !children.is_empty() {
                return Ok(ReconcileResult::converged(
                    resource.revision(),
                    resource.generation(),
                ));
            }
            self.release_finalizer(resource).await?;
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
                .map_err(|_| CredentialResourceRuntimeError::InvalidResource),
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
                DisruptionClass::Restart,
                true,
                vec![UpgradeStage::Restart(resource.key().resource_ref().clone())],
            )
            .map_err(|_| CredentialResourceRuntimeError::InvalidResource),
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

fn provider_kind(provider_ref: &ResourceRef) -> Option<CredentialProviderKind> {
    match provider_ref.to_canonical_string().as_str() {
        "Provider/credential-secret-service" => Some(CredentialProviderKind::SecretService),
        "Provider/credential-entra" => Some(CredentialProviderKind::Entra),
        "Provider/credential-managed-identity" => Some(CredentialProviderKind::ManagedIdentity),
        _ => None,
    }
}

pub(crate) fn is_credential_provider_ref(provider_ref: &ResourceRef) -> bool {
    provider_kind(provider_ref).is_some()
}

fn credential_spec(
    resource: &ResourceSnapshot,
) -> Result<CredentialSpec, CredentialResourceRuntimeError> {
    let envelope = ResourceEnvelope::from_json(resource.canonical_json())
        .map_err(|_| CredentialResourceRuntimeError::InvalidResource)?;
    if envelope.resource_type().as_str() != CREDENTIAL_RESOURCE_TYPE
        || envelope.metadata().zone() != resource.key().zone()
        || envelope.metadata().uid() != resource.key().uid()
        || envelope.metadata().generation() != resource.generation()
        || envelope.metadata().revision() != resource.revision()
    {
        return Err(CredentialResourceRuntimeError::InvalidResource);
    }
    serde_json::from_slice(&envelope.spec().base().to_canonical_bytes())
        .map_err(|_| CredentialResourceRuntimeError::InvalidResource)
}

fn dependency_ready(dependencies: &[DependencySnapshot], target: &ResourceRef) -> bool {
    dependencies.iter().any(|dependency| {
        let resource = dependency.resource();
        resource.key().resource_ref() == target
            && serde_json::from_slice::<serde_json::Value>(resource.canonical_json())
                .ok()
                .is_some_and(|value| {
                    value
                        .pointer("/status/phase")
                        .and_then(serde_json::Value::as_str)
                        == Some("Ready")
                        && value
                            .pointer("/status/observedGeneration")
                            .and_then(serde_json::Value::as_u64)
                            == Some(resource.generation().get())
                })
    })
}

fn credential_execution_ref(
    spec: &CredentialSpec,
) -> Result<&ResourceRef, CredentialResourceRuntimeError> {
    let execution_ref = spec
        .scope()
        .execution_ref()
        .ok_or(CredentialResourceRuntimeError::InvalidResource)?;
    if !matches!(
        execution_ref.resource_type().as_str(),
        "Host" | "Guest"
    ) {
        return Err(CredentialResourceRuntimeError::InvalidResource);
    }
    Ok(execution_ref)
}

fn credential_scope_valid(provider_kind: CredentialProviderKind, spec: &CredentialSpec) -> bool {
    let Some(execution_ref) = spec.scope().execution_ref() else {
        return false;
    };
    match provider_kind {
        CredentialProviderKind::SecretService => {
            spec.scope().domain_filter() == Some(ExecutionDomain::User)
                && spec.scope().user_ref().is_some()
                && matches!(
                    execution_ref.resource_type().as_str(),
                    "Host" | "Guest"
                )
        }
        CredentialProviderKind::Entra => {
            execution_ref.resource_type().as_str() == "Guest"
                && spec.scope().domain_filter() != Some(ExecutionDomain::User)
        }
        CredentialProviderKind::ManagedIdentity => {
            matches!(
                execution_ref.resource_type().as_str(),
                "Host" | "Guest"
            ) && spec.scope().domain_filter() != Some(ExecutionDomain::User)
        }
    }
}

fn managed_identity_agent_ref(
    resource: &ResourceSnapshot,
) -> Result<ResourceRef, CredentialResourceRuntimeError> {
    let value = format!(
        "{PROCESS_RESOURCE_TYPE}/mi-agent-{}",
        resource.key().resource_ref().name().as_str()
    );
    ResourceRef::parse(&value)
    .map_err(|_| CredentialResourceRuntimeError::InvalidResource)
}

fn managed_identity_agent_payload(
    resource: &ResourceSnapshot,
) -> Result<Vec<u8>, CredentialResourceRuntimeError> {
    let spec = credential_spec(resource)?;
    let execution_ref = credential_execution_ref(&spec)?.clone();
    if spec.scope().domain_filter() == Some(ExecutionDomain::User) {
        return Err(CredentialResourceRuntimeError::InvalidResource);
    }
    let placement = match execution_ref.resource_type().as_str() {
        "Host" => PlacementBinding::HostSystem,
        "Guest" => PlacementBinding::GuestAgent,
        _ => return Err(CredentialResourceRuntimeError::InvalidResource),
    };
    let zone_ref = format!("Zone/{}", resource.key().zone().as_str());
    let placement = d2b_provider_credential_managed_identity::ManagedIdentityPlacement::new(
        placement,
        execution_ref.clone(),
        ResourceRef::parse(&zone_ref)
            .map_err(|_| CredentialResourceRuntimeError::InvalidResource)?,
    )
    .map_err(|_| CredentialResourceRuntimeError::InvalidResource)?;
    let controller =
        d2b_provider_credential_managed_identity::ManagedIdentityController::new(placement);
    let agent = controller
        .plan_agent(resource.key().resource_ref().clone(), true, true)
        .map_err(|_| CredentialResourceRuntimeError::InvalidResource)?
        .ok_or(CredentialResourceRuntimeError::InvalidResource)?;
    let execution = ExecutionSpec::new(
        agent.execution_ref().clone(),
        Some(ExecutionDomain::System),
        None,
        ProcessClass::Service,
        BoundedToken::parse(agent.binary())
            .map_err(|_| CredentialResourceRuntimeError::InvalidResource)?,
        None,
        Vec::new(),
        Vec::new(),
        SandboxSpec::new(
            vec![
                NamespaceClass::Mount,
                NamespaceClass::Pid,
                NamespaceClass::Ipc,
            ],
            Vec::new(),
            BoundedToken::parse("strict")
                .map_err(|_| CredentialResourceRuntimeError::InvalidResource)?,
            true,
            false,
            EnvironmentClass::Minimal,
            true,
            Some("0022".to_owned()),
            0,
            None,
        )
        .map_err(|_| CredentialResourceRuntimeError::InvalidResource)?,
        BudgetSpec::default(),
        Some(
            NetworkUsageSpec::new(None, Vec::new(), false)
                .map_err(|_| CredentialResourceRuntimeError::InvalidResource)?,
        ),
        Vec::new(),
        TelemetrySpec::default(),
    )
    .map_err(|_| CredentialResourceRuntimeError::InvalidResource)?;
    let process = ProcessSpec::new(
        execution,
        DesiredLifecycle::Running,
        RestartPolicySpec::default(),
        ReadinessSpec::new(
            DurationMs::parse("0s", 0, 300_000)
                .map_err(|_| CredentialResourceRuntimeError::InvalidResource)?,
            DurationMs::parse("30s", 1_000, 300_000)
                .map_err(|_| CredentialResourceRuntimeError::InvalidResource)?,
            3,
            1,
            ReadinessClass::ProviderDefined,
        )
        .map_err(|_| CredentialResourceRuntimeError::InvalidResource)?,
        HealthCheckSpec::default(),
        AdoptionPolicy::AdoptOnRestart,
        DurationMs::parse("30s", 0, 3_600_000)
            .map_err(|_| CredentialResourceRuntimeError::InvalidResource)?,
    )
    .map_err(|_| CredentialResourceRuntimeError::InvalidResource)?;
    let mut process_spec =
        serde_json::to_value(process).map_err(|_| CredentialResourceRuntimeError::InvalidResource)?;
    let process_spec = process_spec
        .as_object_mut()
        .ok_or(CredentialResourceRuntimeError::InvalidResource)?;
    process_spec.insert(
        "providerRef".to_owned(),
        serde_json::Value::String("Provider/system-systemd".to_owned()),
    );
    let child_ref = managed_identity_agent_ref(resource)?;
    let value = serde_json::json!({
        "apiVersion": "resources.d2bus.org/v3",
        "type": PROCESS_RESOURCE_TYPE,
        "metadata": {
            "name": child_ref.name().as_str(),
            "zone": resource.key().zone().as_str(),
            "ownerRef": resource.key().resource_ref().to_canonical_string(),
            "finalizers": [],
            "deletionRequestedAt": null,
            "createdAt": "1970-01-01T00:00:00.000Z",
            "updatedAt": "1970-01-01T00:00:00.000Z",
            "generation": 1,
            "revision": 1,
            "managedBy": "controller"
        },
        "spec": process_spec,
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
    let bytes =
        serde_json::to_vec(&value).map_err(|_| CredentialResourceRuntimeError::InvalidResource)?;
    CanonicalJsonValue::parse(&bytes)
        .map(|value| value.to_canonical_bytes())
        .map_err(|_| CredentialResourceRuntimeError::InvalidResource)
}

fn managed_identity_agent_matches(
    resource: &StoredResource,
    owner: &ResourceSnapshot,
) -> bool {
    let Ok(expected_ref) = managed_identity_agent_ref(owner) else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&resource.canonical_json) else {
        return false;
    };
    resource.zone == *owner.key().zone()
        && resource.resource_ref == expected_ref
        && value.get("type").and_then(serde_json::Value::as_str) == Some(PROCESS_RESOURCE_TYPE)
        && value
            .pointer("/metadata/ownerRef")
            .and_then(serde_json::Value::as_str)
            == Some(owner.key().resource_ref().to_canonical_string().as_str())
        && value
            .pointer("/spec/providerRef")
            .and_then(serde_json::Value::as_str)
            == Some("Provider/system-systemd")
        && value
            .pointer("/spec/template")
            .and_then(serde_json::Value::as_str)
            == Some(d2b_provider_credential_managed_identity::AGENT_BINARY)
        && value
            .pointer("/spec/processClass")
            .and_then(serde_json::Value::as_str)
            == Some("service")
        && value
            .pointer("/spec/domain")
            .and_then(serde_json::Value::as_str)
            == Some("system")
        && value
            .pointer("/spec/networkUsage/allowEgress")
            .and_then(serde_json::Value::as_bool)
            == Some(false)
}

fn managed_identity_agent_ready(resource: &StoredResource) -> bool {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&resource.canonical_json) else {
        return false;
    };
    value
        .pointer("/status/phase")
        .and_then(serde_json::Value::as_str)
        == Some("Ready")
        && value
            .pointer("/status/observedGeneration")
            .and_then(serde_json::Value::as_u64)
            == Some(resource.generation.get())
        && !deletion_requested(resource)
}

fn has_finalizer(resource: &ResourceSnapshot) -> bool {
    serde_json::from_slice::<serde_json::Value>(resource.canonical_json())
        .ok()
        .and_then(|value| value.pointer("/metadata/finalizers").cloned())
        .and_then(|value| value.as_array().cloned())
        .is_some_and(|values| {
            values
                .iter()
                .any(|value| value.as_str() == Some(CREDENTIAL_PROVIDER_REVOKE_FINALIZER))
        })
}

fn finalizer_payload(
    resource: &ResourceSnapshot,
) -> Result<Vec<u8>, CredentialResourceRuntimeError> {
    let value = serde_json::from_slice::<serde_json::Value>(resource.canonical_json())
        .map_err(|_| CredentialResourceRuntimeError::InvalidResource)?;
    let mut finalizers = value
        .pointer("/metadata/finalizers")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !finalizers
        .iter()
        .any(|value| value.as_str() == Some(CREDENTIAL_PROVIDER_REVOKE_FINALIZER))
    {
        finalizers.push(serde_json::Value::String(
            CREDENTIAL_PROVIDER_REVOKE_FINALIZER.to_owned(),
        ));
    }
    let payload = serde_json::to_vec(&serde_json::json!({
        "metadata": {"finalizers": finalizers}
    }))
    .map_err(|_| CredentialResourceRuntimeError::InvalidResource)?;
    CanonicalJsonValue::parse(&payload)
        .map(|value| value.to_canonical_bytes())
        .map_err(|_| CredentialResourceRuntimeError::InvalidResource)
}

fn owner_ref(resource: &StoredResource) -> Option<ResourceRef> {
    serde_json::from_slice::<serde_json::Value>(&resource.canonical_json)
        .ok()
        .and_then(|value| {
            value
                .pointer("/metadata/ownerRef")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| ResourceRef::parse(value).ok())
        })
}

fn credential_process_list_operation_id(owner: &ResourceSnapshot) -> String {
    let preimage = format!(
        "{}:{}:{}:{}",
        owner.key().resource_ref().to_canonical_string(),
        owner.key().uid().as_str(),
        owner.generation().get(),
        owner.revision().get(),
    );
    format!(
        "credential-process-list-{}",
        canonical_digest("d2b:credential-process-list/v1", preimage.as_bytes())
    )
}

fn credential_process_delete_operation_id(resource: &StoredResource) -> String {
    let preimage = format!(
        "{}:{}:{}:{}",
        resource.resource_ref.to_canonical_string(),
        resource.uid.as_str(),
        resource.generation.get(),
        resource.revision.get(),
    );
    format!(
        "credential-process-delete-{}",
        canonical_digest("d2b:credential-process-delete/v1", preimage.as_bytes())
    )
}

fn credential_finalizer_release_operation_id(resource: &ResourceSnapshot) -> String {
    let preimage = format!(
        "{}:{}:{}",
        resource.key().resource_ref().to_canonical_string(),
        resource.key().uid().as_str(),
        resource.revision().get(),
    );
    format!(
        "credential-finalizer-release-{}",
        canonical_digest("d2b:credential-finalizer-release/v1", preimage.as_bytes())
    )
}

fn deletion_requested(resource: &StoredResource) -> bool {
    serde_json::from_slice::<serde_json::Value>(&resource.canonical_json)
        .ok()
        .and_then(|value| value.pointer("/metadata/deletionRequestedAt").cloned())
        .is_some_and(|value| !value.is_null())
}

fn resource_identity(resource: &StoredResource) -> wire::ResourceIdentity {
    let mut identity = wire::ResourceIdentity::new();
    identity.zone = resource.zone.as_str().to_owned();
    identity.resource_type = resource.resource_ref.resource_type().as_str().to_owned();
    identity.name = resource.resource_ref.name().as_str().to_owned();
    identity.uid = Some(resource.uid.as_str().to_owned());
    identity.generation = Some(resource.generation.get());
    identity.revision = Some(resource.revision.get());
    identity
}

fn resource_identity_snapshot(resource: &ResourceSnapshot) -> wire::ResourceIdentity {
    let mut identity = wire::ResourceIdentity::new();
    identity.zone = resource.key().zone().as_str().to_owned();
    identity.resource_type = resource
        .key()
        .resource_ref()
        .resource_type()
        .as_str()
        .to_owned();
    identity.name = resource.key().resource_ref().name().as_str().to_owned();
    identity.uid = Some(resource.key().uid().as_str().to_owned());
    identity.generation = Some(resource.generation().get());
    identity.revision = Some(resource.revision().get());
    identity
}

fn exact_precondition_stored(resource: &StoredResource) -> wire::Precondition {
    exact_precondition(resource.uid.as_str(), resource.revision.get())
}

fn exact_precondition_snapshot(resource: &ResourceSnapshot) -> wire::Precondition {
    exact_precondition(resource.key().uid().as_str(), resource.revision().get())
}

fn exact_precondition(uid: &str, revision: u64) -> wire::Precondition {
    let mut precondition = wire::Precondition::new();
    precondition.kind =
        protobuf::EnumOrUnknown::new(wire::PreconditionKind::PRECONDITION_KIND_EXACT_REVISION);
    precondition.expected_uid = Some(uid.to_owned());
    precondition.expected_revision = Some(revision);
    precondition
}

fn lease_state(resource: &ResourceSnapshot) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(resource.canonical_json())
        .ok()
        .and_then(|value| {
            value
                .pointer("/status/resource/credential/leaseState")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
}

fn credential_lease_generation(resource: &ResourceSnapshot) -> Option<u64> {
    serde_json::from_slice::<serde_json::Value>(resource.canonical_json())
        .ok()
        .and_then(|value| {
            value
                .pointer("/status/resource/credential/rotationGeneration")
                .and_then(serde_json::Value::as_u64)
                .filter(|generation| *generation != 0)
        })
}

fn credential_revoke_operation_id(
    resource: &ResourceSnapshot,
    provider_ref: &ResourceRef,
    provider_generation: d2b_contracts_resource::v3::ResourceGeneration,
    controller_generation: d2b_contracts_resource::v3::ControllerGeneration,
) -> String {
    let preimage = format!(
        "{}:{}:{}:{}:{}:{}",
        resource.key().zone().as_str(),
        resource.key().uid().as_str(),
        resource.generation().get(),
        provider_ref.to_canonical_string(),
        provider_generation.get(),
        controller_generation.get(),
    );
    format!(
        "credential-revoke-{}",
        canonical_digest("d2b:credential-revoke/v1", preimage.as_bytes())
    )
}

fn credential_status_candidate(
    resource: &ResourceSnapshot,
    phase: ResourcePhase,
    outcome: &str,
    lease_revoked: bool,
    revocation: Option<&CredentialRevocationEvidence>,
) -> Result<Vec<u8>, CredentialResourceRuntimeError> {
    let mut value = serde_json::from_slice::<serde_json::Value>(resource.canonical_json())
        .map_err(|_| CredentialResourceRuntimeError::InvalidResource)?;
    let root = value
        .as_object_mut()
        .ok_or(CredentialResourceRuntimeError::InvalidResource)?;
    let status = root
        .entry("status".to_owned())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()))
        .as_object_mut()
        .ok_or(CredentialResourceRuntimeError::InvalidResource)?;
    redact_status_map(status);
    status.insert(
        "phase".to_owned(),
        serde_json::Value::String(phase_name(phase).to_owned()),
    );
    status.insert(
        "observedGeneration".to_owned(),
        serde_json::Value::Number(resource.generation().get().into()),
    );
    status.insert(
        "outcome".to_owned(),
        serde_json::json!({
            "code": outcome,
            "message": outcome,
            "retryable": phase == ResourcePhase::Degraded,
        }),
    );
    if let Some(credential) = status
        .get_mut("resource")
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|resource| resource.get_mut("credential"))
        .and_then(serde_json::Value::as_object_mut)
    {
        if lease_revoked {
            credential.insert(
                "leaseState".to_owned(),
                serde_json::Value::String("Revoked".to_owned()),
            );
        }
        if let Some(revocation) = revocation {
            credential.insert(
                "revocation".to_owned(),
                serde_json::json!({
                    "operationId": revocation.operation_id,
                    "outcome": revocation.outcome_code(),
                    "sessionGeneration": revocation.session_generation.get(),
                }),
            );
        }
    }
    let status = value
        .get("status")
        .cloned()
        .ok_or(CredentialResourceRuntimeError::InvalidResource)?;
    let canonical =
        serde_json::to_vec(&status).map_err(|_| CredentialResourceRuntimeError::InvalidResource)?;
    CanonicalJsonValue::parse(&canonical)
        .map(|value| value.to_canonical_bytes())
        .map_err(|_| CredentialResourceRuntimeError::InvalidResource)
}

fn redact_status_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(object) => {
            let keys = object.keys().cloned().collect::<Vec<_>>();
            for key in keys {
                if forbidden_status_key(&key)
                    || object
                        .get(&key)
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(
                        d2b_contracts_provider::v3::credential_controller::contains_sensitive_shape,
                    )
                {
                    object.remove(&key);
                    continue;
                }
                if let Some(child) = object.get_mut(&key) {
                    redact_status_value(child);
                }
            }
        }
        serde_json::Value::Array(values) => values.retain(|value| {
            !value.as_str().is_some_and(
                d2b_contracts_provider::v3::credential_controller::contains_sensitive_shape,
            )
        }),
        _ => {}
    }
}

fn redact_status_map(status: &mut serde_json::Map<String, serde_json::Value>) {
    let mut value = serde_json::Value::Object(std::mem::take(status));
    redact_status_value(&mut value);
    if let serde_json::Value::Object(redacted) = value {
        *status = redacted;
    }
}

fn forbidden_status_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        "tokenbytes",
        "token_bytes",
        "secret",
        "password",
        "privatekey",
        "keymaterial",
        "credentialref",
        "credentialuid",
        "resourcename",
        "resource_name",
        "argv",
        "environment",
        "socket",
        "hostpath",
        "endpointuri",
    ]
    .iter()
    .any(|marker| key.contains(marker))
}

fn phase_name(phase: ResourcePhase) -> &'static str {
    match phase {
        ResourcePhase::Pending => "Pending",
        ResourcePhase::Ready => "Ready",
        ResourcePhase::Succeeded => "Succeeded",
        ResourcePhase::Degraded => "Degraded",
        ResourcePhase::Failed => "Failed",
        ResourcePhase::Deleted => "Deleted",
        ResourcePhase::Unknown => "Unknown",
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CredentialCleanupAction {
    RevokeLease,
    DeleteProcess,
    ReleaseFinalizer,
}

#[cfg(test)]
fn cleanup_action(
    lease_active: bool,
    revocation_confirmed: bool,
    process_deleted: bool,
) -> CredentialCleanupAction {
    if lease_active && !revocation_confirmed {
        CredentialCleanupAction::RevokeLease
    } else if !process_deleted {
        CredentialCleanupAction::DeleteProcess
    } else {
        CredentialCleanupAction::ReleaseFinalizer
    }
}

/// A same-Zone ResourceService gate around a typed Credential ComponentSession.
///
/// The delegate owns the sensitive delivery channel. This adapter only verifies
/// the current Credential row and exact Guest scope before forwarding the
/// already-authorized request.
pub(crate) struct SameZoneScopedCredentialClient {
    zone: ZoneId,
    route: d2b_session::AuthenticatedSessionRouteBinding,
    execution_ref: ResourceRef,
    resource: Arc<dyn CredentialResourceReader>,
    delegate: Arc<dyn ScopedCredentialClient>,
}

#[async_trait]
trait CredentialResourceReader: Send + Sync {
    async fn get(&self, request: wire::GetRequest) -> wire::GetResponse;
}

struct ComponentSessionCredentialResourceReader {
    client: d2b_resource_api::generated::d2b_resource_v3_ttrpc::ResourceServiceClient,
}

#[async_trait]
impl CredentialResourceReader for ComponentSessionCredentialResourceReader {
    async fn get(&self, request: wire::GetRequest) -> wire::GetResponse {
        self.client
            .get(ttrpc::context::Context::default(), &request)
            .await
            .unwrap_or_else(|_| {
                let mut response = wire::GetResponse::new();
                response.error = protobuf::MessageField::some(wire::ResourceError {
                    kind: protobuf::EnumOrUnknown::new(
                        wire::ResourceErrorKind::RESOURCE_ERROR_KIND_INTERNAL_INTEGRITY_FAILURE,
                    ),
                    ..wire::ResourceError::new()
                });
                response
            })
    }
}

impl core::fmt::Debug for SameZoneScopedCredentialClient {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SameZoneScopedCredentialClient(<redacted>)")
    }
}

impl SameZoneScopedCredentialClient {
    pub(crate) fn with_component_session(
        zone: ZoneId,
        session: &d2bd_runtime::guest_component_session::GuestComponentSessionClient,
        delegate: Arc<dyn ScopedCredentialClient>,
    ) -> Result<Self, RelayCredentialError> {
        let route = session.route_binding();
        if session.identity().zone() != &zone
            || session.generation() == 0
            || !route.liveness().is_live()
            || session.identity().validate_route(&route).is_err()
            || route.context().execution_ref() != Some(session.identity().guest_ref())
        {
            return Err(RelayCredentialError::InvalidScope);
        }
        Ok(Self::with_resource_reader(
            zone,
            route,
            session.identity().guest_ref().clone(),
            Arc::new(ComponentSessionCredentialResourceReader {
                client: session.resource_service_client(),
            }),
            delegate,
        ))
    }

    fn with_resource_reader(
        zone: ZoneId,
        route: d2b_session::AuthenticatedSessionRouteBinding,
        execution_ref: ResourceRef,
        resource: Arc<dyn CredentialResourceReader>,
        delegate: Arc<dyn ScopedCredentialClient>,
    ) -> Self {
        Self {
            zone,
            route,
            execution_ref,
            resource,
            delegate,
        }
    }

    fn validate_request_scope(
        request: &ScopedCredentialRequest,
        expected_zone: &ZoneId,
    ) -> Result<(), RelayCredentialError> {
        if request.zone() != expected_zone
            || request.execution_ref().resource_type().as_str() != "Guest"
            || request.credential_ref().resource_type().as_str() != CREDENTIAL_RESOURCE_TYPE
            || request.binding().zone() != Some(expected_zone)
        {
            return Err(RelayCredentialError::InvalidScope);
        }
        Ok(())
    }
}

#[async_trait]
impl ScopedCredentialClient for SameZoneScopedCredentialClient {
    async fn read_credential(
        &self,
        request: &ScopedCredentialRequest,
    ) -> Result<RelayCredentialLease, RelayCredentialError> {
        Self::validate_request_scope(request, &self.zone)?;
        if !self.route.liveness().is_live()
            || request.execution_ref() != &self.execution_ref
            || request.binding().reconnect_generation() != self.route.reconnect_generation().get()
        {
            return Err(RelayCredentialError::InvalidScope);
        }
        let response = self.resource.get({
                let mut get = wire::GetRequest::new();
                get.meta = protobuf::MessageField::some(
                    d2bd_runtime::resource_runtime_support::public_request_meta(
                        "credential-scoped-read",
                    ),
                );
                get.target = protobuf::MessageField::some(scoped_identity(request));
                let mut projection = wire::Projection::new();
                projection.kind =
                    protobuf::EnumOrUnknown::new(wire::ProjectionKind::PROJECTION_KIND_FULL);
                get.projection = protobuf::MessageField::some(projection);
                get
            })
            .await;
        let Some(resource) = response.resource.as_ref() else {
            return Err(RelayCredentialError::Unavailable);
        };
        let value = serde_json::from_slice::<serde_json::Value>(&resource.canonical_json)
            .map_err(|_| RelayCredentialError::Unavailable)?;
        if response.error.is_some()
            || value
                .pointer("/metadata/zone")
                .and_then(serde_json::Value::as_str)
                != Some(request.zone().as_str())
            || value
                .pointer("/spec/scope/executionRef")
                .and_then(serde_json::Value::as_str)
                != Some(request.execution_ref().to_canonical_string().as_str())
            || !value
                .pointer("/spec/allowedOperations")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|operations| {
                    operations
                        .iter()
                        .any(|operation| operation.as_str() == Some("acquire-token"))
                })
            || value
                .pointer("/status/phase")
                .and_then(serde_json::Value::as_str)
                != Some("Ready")
            || value
                .pointer("/metadata/deletionRequestedAt")
                .is_some_and(|deletion| !deletion.is_null())
        {
            return Err(RelayCredentialError::InvalidScope);
        }
        let lease = self.delegate.read_credential(request).await?;
        if lease.binding() != Some(request.binding()) || lease.role() != request.role() {
            return Err(RelayCredentialError::BindingMismatch);
        }
        Ok(lease)
    }

    async fn revoke_credential(
        &self,
        lease: RelayCredentialLease,
    ) -> Result<(), RelayCredentialError> {
        self.delegate.revoke_credential(lease).await
    }
}

fn scoped_identity(request: &ScopedCredentialRequest) -> wire::ResourceIdentity {
    let mut identity = wire::ResourceIdentity::new();
    identity.zone = request.zone().as_str().to_owned();
    identity.resource_type = request.credential_ref().resource_type().as_str().to_owned();
    identity.name = request.credential_ref().name().as_str().to_owned();
    identity
}

#[cfg(test)]
mod tests {
    use super::*;
    use d2b_contracts_provider::v3::credential::CredentialWire;
    use d2b_contracts_resource::v3::{
        ControllerGeneration, ResourceGeneration, ResourcePhase, ResourceRef, ResourceUid, ZoneId,
        ZoneRevision,
    };
    use d2b_core_controller::{
        CommitOutcome, ControllerIdentity, ControllerSource, DependencySnapshot, FreshSnapshot,
        InitialList, InitialResource, MutationIntent, MutationIntentKind, ReconcilePlan,
        ReconcileProjection, ReconcileResult, ResourceKey, ResourceMutationBatch, ResourceSnapshot,
        Runner, RunnerConfig, SourceError, StatusPersistence, WatchEvent, WatchFailure,
    };
    use d2b_provider_transport_azure_relay::{RelayCredentialBinding, RelayCredentialRole};
    use serde_json::json;
    use ttrpc::proto::Codec;

    fn identity() -> ControllerIdentity {
        ControllerIdentity::new(
            ZoneId::parse("dev").unwrap(),
            ResourceRef::parse("Process/credential-controller").unwrap(),
            ControllerGeneration::new(1).unwrap(),
            ResourceRef::parse("Provider/credential-managed-identity").unwrap(),
            ResourceGeneration::new(1).unwrap(),
            ResourceRef::parse("Process/credential-controller").unwrap(),
            ResourceRef::parse("Host/host-system").unwrap(),
            None,
        )
        .unwrap()
    }

    fn resource() -> ResourceSnapshot {
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        ResourceSnapshot::new(
            ResourceKey::new(
                ZoneId::parse("dev").unwrap(),
                ResourceRef::parse("Credential/relay").unwrap(),
                uid,
            ),
            ZoneRevision::new(3),
            ResourceGeneration::new(1).unwrap(),
            serde_json::to_vec(&json!({
                "apiVersion": "resources.d2bus.org/v3",
                "type": "Credential",
                "metadata": {
                    "name": "relay",
                    "zone": "dev",
                    "uid": "123e4567-e89b-42d3-a456-426614174000",
                    "generation": 1,
                    "revision": 3,
                    "finalizers": [],
                    "labels": {},
                    "annotations": {},
                    "ownerRef": null,
                    "managedBy": "controller",
                    "configurationGeneration": 1,
                    "deletionRequestedAt": null,
                    "createdAt": "1970-01-01T00:00:00.000Z",
                    "updatedAt": "1970-01-01T00:00:00.000Z"
                },
                "spec": {
                    "providerRef": "Provider/credential-managed-identity",
                    "scope": {"executionRef": "Guest/gateway", "domainFilter": "system"},
                    "allowedOperations": ["acquire-token"],
                    "audience": "relay"
                },
                "status": {
                    "phase": "Pending",
                    "observedGeneration": 0,
                    "conditions": [],
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
                    "resource": {
                        "credential": {
                            "leaseState": "Active",
                            "leaseHandle": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        },
                        "tokenBytes": "credential-secret-canary"
                    }
                }
            }))
            .unwrap(),
            false,
        )
    }

    #[test]
    fn descriptor_is_credential_only_and_has_the_exact_finalizer() {
        let descriptor = credential_controller_descriptor(identity()).unwrap();
        assert_eq!(
            descriptor
                .resource_types()
                .map(|resource_type| resource_type.as_str())
                .collect::<Vec<_>>(),
            vec!["Credential"]
        );
        assert_eq!(
            descriptor.finalizers(),
            &[CREDENTIAL_PROVIDER_REVOKE_FINALIZER.to_owned()]
        );
        assert!(descriptor.consumes_owner_triggers());
        assert!(
            descriptor
                .watch_selectors()
                .iter()
                .all(|selector| selector.exact_value()
                    == Some("Provider/credential-managed-identity"))
        );
        assert_eq!(
            descriptor
                .dependency_selectors()
                .iter()
                .map(|selector| selector.resource_type().as_str())
                .collect::<Vec<_>>(),
            vec!["Guest", "Host", "Process", "Provider", "User"]
        );
    }

    #[test]
    fn first_pass_enrolls_one_finalizer_transaction() {
        let target = resource();
        let payload = finalizer_payload(&target).expect("finalizer payload");
        let mutation = MutationIntent::new(
            target.key().resource_ref().clone(),
            Some(target.key().uid().clone()),
            Some(target.revision()),
            MutationIntentKind::UpdateFinalizers,
            Some(payload),
        )
        .expect("finalizer mutation");
        let result = ResourceMutationBatch::new(vec![mutation]).expect("one mutation transaction");
        assert_eq!(
            result.mutations().first().unwrap().kind(),
            MutationIntentKind::UpdateFinalizers
        );
    }

    #[test]
    fn status_redaction_removes_secret_bytes_but_keeps_opaque_lease_metadata() {
        let status =
            credential_status_candidate(&resource(), ResourcePhase::Ready, "success", false, None)
                .expect("status");
        let text = String::from_utf8(status).unwrap();
        assert!(!text.contains("credential-secret-canary"));
        assert!(text.contains("leaseHandle"));
        assert!(text.contains("sha256:aaaaaaaa"));
        assert!(!text.contains("123e4567-e89b-42d3-a456-426614174000"));
    }

    #[test]
    fn cleanup_orders_process_deletion_before_finalizer_release() {
        assert_eq!(
            cleanup_action(true, false, false),
            CredentialCleanupAction::RevokeLease
        );
        assert_eq!(
            cleanup_action(false, true, true),
            CredentialCleanupAction::ReleaseFinalizer
        );
        assert_eq!(
            cleanup_action(false, true, false),
            CredentialCleanupAction::DeleteProcess
        );
    }

    #[derive(Clone, Default)]
    struct RecordingCredentialSession {
        operations:
            Arc<std::sync::Mutex<std::collections::BTreeMap<String, CredentialRevocationOutcome>>>,
        attempts: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait]
    impl CredentialSession for RecordingCredentialSession {
        fn session_generation(&self) -> Option<ReconnectGeneration> {
            Some(ReconnectGeneration::new(7).expect("recording session generation"))
        }

        async fn revoke_credential(
            &self,
            request: &CredentialRevocationRequest,
        ) -> Result<CredentialRevocationOutcome, CredentialResourceRuntimeError> {
            self.attempts
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut operations = self.operations.lock().unwrap();
            if operations
                .insert(
                    request.operation_id.clone(),
                    CredentialRevocationOutcome::Revoked,
                )
                .is_some()
            {
                Ok(CredentialRevocationOutcome::AlreadyRevoked)
            } else {
                Ok(CredentialRevocationOutcome::Revoked)
            }
        }
    }

    struct UncertainCredentialSession;

    #[async_trait]
    impl CredentialSession for UncertainCredentialSession {
        fn session_generation(&self) -> Option<ReconnectGeneration> {
            None
        }

        async fn revoke_credential(
            &self,
            _request: &CredentialRevocationRequest,
        ) -> Result<CredentialRevocationOutcome, CredentialResourceRuntimeError> {
            Ok(CredentialRevocationOutcome::Uncertain)
        }
    }

    #[tokio::test]
    async fn revoke_session_deduplicates_the_fenced_operation_identity() {
        let session = RecordingCredentialSession::default();
        let target = resource();
        let request = CredentialRevocationRequest::new(
            &target,
            &ResourceRef::parse("Provider/credential-managed-identity").unwrap(),
            &identity(),
            ReconnectGeneration::new(7).unwrap(),
        )
        .expect("revocation request");
        assert_eq!(
            session.revoke_credential(&request).await.unwrap(),
            CredentialRevocationOutcome::Revoked
        );
        assert_eq!(
            session.revoke_credential(&request).await.unwrap(),
            CredentialRevocationOutcome::AlreadyRevoked
        );
        assert_eq!(session.operations.lock().unwrap().len(), 1);
        assert!(!format!("{request:?}").contains(target.key().uid().as_str()));
        let rejoined = CredentialRevocationRequest::new(
            &target,
            &ResourceRef::parse("Provider/credential-managed-identity").unwrap(),
            &identity(),
            ReconnectGeneration::new(8).unwrap(),
        )
        .expect("rejoined revocation request");
        assert_eq!(request.operation_id, rejoined.operation_id);
        assert_eq!(request.idempotency_key, rejoined.idempotency_key);
        assert_ne!(request.session_generation, rejoined.session_generation);
    }

    #[tokio::test]
    async fn provider_route_generation_mismatch_is_uncertain() {
        let provider_ref =
            ResourceRef::parse("Provider/credential-managed-identity").unwrap();
        let driver = Arc::new(FakeCredentialDriver::new(9));
        let route = d2b_session::AuthenticatedSessionRouteBinding::for_test(
            Some(provider_ref.clone()),
            CREDENTIAL_SERVICE_NAME,
            9,
            Some(1),
            Some(1),
        );
        let session = ComponentCredentialSession::new(route, driver).unwrap();
        let request = CredentialRevocationRequest::new(
            &resource(),
            &provider_ref,
            &identity_for_provider("Provider/credential-managed-identity"),
            ReconnectGeneration::new(8).unwrap(),
        )
        .unwrap();
        assert_eq!(
            session.revoke_credential(&request).await.unwrap(),
            CredentialRevocationOutcome::Uncertain
        );
    }

    #[test]
    fn revocation_request_rejects_cross_provider_or_zero_session_identity() {
        let target = resource();
        let provider = ResourceRef::parse("Provider/credential-managed-identity").unwrap();
        assert_eq!(
            CredentialRevocationRequest::new(
                &target,
                &provider,
                &identity_for_provider("Provider/credential-entra"),
                ReconnectGeneration::new(7).unwrap(),
            )
            .unwrap_err(),
            CredentialResourceRuntimeError::InvalidResource
        );
    }

    #[derive(Default)]
    struct TestCredentialStore {
        resources: std::sync::Mutex<Vec<(StoredResource, Option<ResourceUid>)>>,
    }

    impl TestCredentialStore {
        fn with_children(children: Vec<(StoredResource, ResourceUid)>) -> Self {
            Self {
                resources: std::sync::Mutex::new(
                    children
                        .into_iter()
                        .map(|(resource, owner_uid)| (resource, Some(owner_uid)))
                        .collect(),
                ),
            }
        }
    }

    #[async_trait]
    impl CredentialResourceStore for TestCredentialStore {
        async fn list(&self, request: StoreListRequest) -> Result<StoreListResult, StoreError> {
            let resource_type = request.resource_types.first().map(ResourceTypeName::as_str);
            let owner_uid = request
                .filters
                .iter()
                .find(|filter| filter.field == "owner.resourceUid")
                .and_then(|filter| filter.values.first());
            let resources = self
                .resources
                .lock()
                .unwrap()
                .iter()
                .filter(|(resource, stored_owner_uid)| {
                    resource.zone == request.zone
                        && resource_type.is_none_or(|resource_type| {
                            resource.resource_ref.resource_type().as_str() == resource_type
                        })
                        && owner_uid.is_none_or(|owner_uid| {
                            stored_owner_uid
                                .as_ref()
                                .is_some_and(|stored| stored.as_str() == owner_uid)
                        })
                })
                .map(|(resource, _)| resource.clone())
                .collect();
            Ok(StoreListResult {
                resources,
                snapshot_revision: ZoneRevision::new(20),
                next_cursor: None,
                truncated: false,
            })
        }
    }

    #[derive(Default)]
    struct TestCredentialClient {
        deletes: std::sync::Mutex<Vec<wire::ResourceIdentity>>,
        finalizer_updates: std::sync::Mutex<Vec<wire::ResourceIdentity>>,
        operations: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait]
    impl CredentialResourceClient for TestCredentialClient {
        async fn delete(&self, request: wire::DeleteRequest) -> wire::DeleteResponse {
            if let Some(meta) = request.meta.as_ref() {
                self.operations
                    .lock()
                    .unwrap()
                    .push(meta.operation_id.clone());
            }
            if let Some(mutation) = request.mutation.as_ref() {
                if let Some(target) = mutation.target.as_ref() {
                    self.deletes.lock().unwrap().push(target.clone());
                }
            }
            wire::DeleteResponse::new()
        }

        async fn update_finalizers(
            &self,
            request: wire::UpdateFinalizersRequest,
        ) -> wire::UpdateFinalizersResponse {
            if let Some(meta) = request.meta.as_ref() {
                self.operations
                    .lock()
                    .unwrap()
                    .push(meta.operation_id.clone());
            }
            if let Some(mutation) = request.mutation.as_ref() {
                if let Some(target) = mutation.target.as_ref() {
                    self.finalizer_updates.lock().unwrap().push(target.clone());
                }
            }
            wire::UpdateFinalizersResponse::new()
        }
    }

    #[derive(Clone, Debug)]
    struct TestCommit {
        operation_id: String,
        mutation_kind: Option<MutationIntentKind>,
        status_candidate: Option<Vec<u8>>,
    }

    struct TestRunnerSource {
        target: Option<ResourceSnapshot>,
        dependencies: Vec<DependencySnapshot>,
        events: std::sync::Mutex<std::collections::VecDeque<WatchEvent>>,
        late_create: bool,
        late_signal_sent: std::sync::atomic::AtomicBool,
        initial_lists: std::sync::atomic::AtomicUsize,
        registered: std::sync::atomic::AtomicUsize,
        watches: std::sync::atomic::AtomicUsize,
        accepted_effects: std::sync::atomic::AtomicUsize,
        completed_effects: std::sync::atomic::AtomicUsize,
        commits: std::sync::Mutex<Vec<TestCommit>>,
    }

    impl TestRunnerSource {
        fn new(target: Option<ResourceSnapshot>, dependencies: Vec<DependencySnapshot>) -> Self {
            let mut events = std::collections::VecDeque::new();
            events.push_back(WatchEvent::Closed);
            Self {
                target,
                dependencies,
                events: std::sync::Mutex::new(events),
                late_create: false,
                late_signal_sent: std::sync::atomic::AtomicBool::new(false),
                initial_lists: std::sync::atomic::AtomicUsize::new(0),
                registered: std::sync::atomic::AtomicUsize::new(0),
                watches: std::sync::atomic::AtomicUsize::new(0),
                accepted_effects: std::sync::atomic::AtomicUsize::new(0),
                completed_effects: std::sync::atomic::AtomicUsize::new(0),
                commits: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn late_create(
            target: ResourceSnapshot,
            dependencies: Vec<DependencySnapshot>,
        ) -> Self {
            let mut source = Self::new(Some(target), dependencies);
            source.late_create = true;
            source
        }

        fn commits(&self) -> Vec<TestCommit> {
            self.commits.lock().unwrap().clone()
        }
    }

    struct FakeCredentialDriver {
        generation: u64,
        responses: std::sync::Arc<(
            tokio::sync::Mutex<std::collections::VecDeque<Vec<u8>>>,
            tokio::sync::Notify,
        )>,
        requests: std::sync::Arc<std::sync::Mutex<Vec<(String, String, u64)>>>,
    }

    impl FakeCredentialDriver {
        fn new(generation: u64) -> Self {
            Self {
                generation,
                responses: std::sync::Arc::new((
                    tokio::sync::Mutex::new(std::collections::VecDeque::new()),
                    tokio::sync::Notify::new(),
                )),
                requests: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }
    }

    #[async_trait]
    impl d2b_session::ComponentSessionDriver for FakeCredentialDriver {
        fn generation(&self) -> u64 {
            self.generation
        }

        async fn start_ttrpc(
            &self,
            _request_id: d2b_contracts_zone_session::v3::component_session::RequestId,
            frame: Vec<u8>,
        ) -> d2b_session::Result<()> {
            let header = ttrpc::proto::MessageHeader::from(&frame);
            let request = ttrpc::Request::decode(&frame[ttrpc::proto::MESSAGE_HEADER_LENGTH..])
                .map_err(|_| d2b_session::SessionError::new(
                    d2b_contracts_zone_session::v3::component_session::SessionErrorCode::RecordMalformed,
                ))?;
            let typed = CredentialRequest::decode_wire(&request.payload).map_err(|_| {
                d2b_session::SessionError::new(
                    d2b_contracts_zone_session::v3::component_session::SessionErrorCode::RecordMalformed,
                )
            })?;
            let session_generation = request
                .metadata
                .iter()
                .find(|value| value.key == "d2b.credential.session-generation")
                .and_then(|value| value.value.parse::<u64>().ok())
                .expect("provider route session generation");
            self.requests.lock().unwrap().push((
                typed.operation_id().to_owned(),
                typed.idempotency_key().to_owned(),
                session_generation,
            ));
            let metadata = MetadataResponse {
                metadata: d2b_contracts_provider::v3::credential::CredentialMetadata {
                    lease_handle: d2b_contracts_provider::v3::credential::CredentialLeaseHandle::parse(
                        "provider-lease",
                    )
                    .unwrap(),
                    rotation_generation: 1,
                    source_version:
                        d2b_contracts_provider::v3::credential::CredentialSourceVersion::parse(
                            "provider-source",
                        )
                        .unwrap(),
                    expires_at_unix_ms: u64::MAX,
                    state: d2b_contracts_provider::v3::credential::CredentialLeaseState::Revoked,
                    outcome: CredentialOutcomeCode::Revoked,
                },
            };
            let response_payload = encode_outer(&metadata).map_err(|_| {
                d2b_session::SessionError::new(
                    d2b_contracts_zone_session::v3::component_session::SessionErrorCode::RecordMalformed,
                )
            })?;
            let mut response = ttrpc::Response::new();
            response.set_status(ttrpc::get_status(ttrpc::Code::OK, ""));
            response.payload = response_payload;
            let encoded = response.encode().map_err(|_| {
                d2b_session::SessionError::new(
                    d2b_contracts_zone_session::v3::component_session::SessionErrorCode::RecordMalformed,
                )
            })?;
            let mut response_frame =
                Vec::from(ttrpc::proto::MessageHeader::new_response(
                    header.stream_id,
                    encoded.len() as u32,
                ));
            response_frame.extend(encoded);
            let (queue, notify) = &*self.responses;
            queue.lock().await.push_back(response_frame);
            notify.notify_one();
            Ok(())
        }

        async fn complete_ttrpc(
            &self,
            _request_id: d2b_contracts_zone_session::v3::component_session::RequestId,
        ) -> d2b_session::Result<bool> {
            Ok(true)
        }

        async fn cancel(
            &self,
            _generation: u64,
            _request_id: d2b_contracts_zone_session::v3::component_session::RequestId,
        ) -> d2b_session::Result<()> {
            Ok(())
        }

        async fn send_ttrpc(&self, _frame: Vec<u8>) -> d2b_session::Result<()> {
            Ok(())
        }

        async fn receive_ttrpc(&self) -> d2b_session::Result<Vec<u8>> {
            loop {
                let (queue, notify) = &*self.responses;
                if let Some(frame) = queue.lock().await.pop_front() {
                    return Ok(frame);
                }
                notify.notified().await;
            }
        }

        async fn register_inbound_call(
            &self,
            _request_id: d2b_contracts_zone_session::v3::component_session::RequestId,
        ) -> d2b_session::Result<d2b_session::Cancellation> {
            Err(d2b_session::SessionError::new(
                d2b_contracts_zone_session::v3::component_session::SessionErrorCode::Cancelled,
            ))
        }

        async fn mark_inbound_dispatched(
            &self,
            _request_id: d2b_contracts_zone_session::v3::component_session::RequestId,
        ) -> d2b_session::Result<()> {
            Ok(())
        }

        async fn complete_inbound_call(
            &self,
            _request_id: d2b_contracts_zone_session::v3::component_session::RequestId,
        ) -> d2b_session::Result<bool> {
            Ok(true)
        }

        async fn remove_inbound_call(
            &self,
            _request_id: d2b_contracts_zone_session::v3::component_session::RequestId,
        ) -> d2b_session::Result<bool> {
            Ok(true)
        }

        async fn send_attachments(
            &self,
            _attachments: Vec<d2b_session::OwnedAttachment>,
        ) -> d2b_session::Result<()> {
            Ok(())
        }

        async fn receive_attachments(
            &self,
        ) -> d2b_session::Result<Vec<d2b_session::OwnedAttachment>> {
            Ok(Vec::new())
        }

        async fn open_named_stream(
            &self,
            _stream: d2b_session::StreamId,
            _send_credit: u32,
            _receive_credit: u32,
        ) -> d2b_session::Result<()> {
            Ok(())
        }

        async fn send_named_stream(
            &self,
            _stream: d2b_session::StreamId,
            _bytes: Vec<u8>,
        ) -> d2b_session::Result<()> {
            Ok(())
        }

        async fn receive_named_stream(&self) -> d2b_session::Result<d2b_session::StreamEvent> {
            Err(d2b_session::SessionError::new(
                d2b_contracts_zone_session::v3::component_session::SessionErrorCode::Cancelled,
            ))
        }

        async fn grant_named_stream_credit(
            &self,
            _stream: d2b_session::StreamId,
            _bytes: u32,
        ) -> d2b_session::Result<()> {
            Ok(())
        }

        async fn close_named_stream(
            &self,
            _stream: d2b_session::StreamId,
        ) -> d2b_session::Result<()> {
            Ok(())
        }

        async fn reset_named_stream(
            &self,
            _stream: d2b_session::StreamId,
        ) -> d2b_session::Result<()> {
            Ok(())
        }

        async fn drive_keepalive(&self, _now: std::time::Instant) -> d2b_session::Result<()> {
            Ok(())
        }

        async fn receive_control(&self) -> d2b_session::Result<d2b_session::SessionEvent> {
            Err(d2b_session::SessionError::new(
                d2b_contracts_zone_session::v3::component_session::SessionErrorCode::Cancelled,
            ))
        }

        async fn close(
            &self,
            _reason: d2b_contracts_zone_session::v3::component_session::CloseReason,
            _remediation: d2b_contracts_zone_session::v3::component_session::Remediation,
        ) -> d2b_session::Result<()> {
            Ok(())
        }
    }

    impl ControllerSource for TestRunnerSource {
        fn register(
            &self,
            _descriptor: &ControllerDescriptor,
        ) -> impl std::future::Future<Output = Result<(), SourceError>> + Send {
            self.registered
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            std::future::ready(Ok(()))
        }

        fn list_initial(
            &self,
            _descriptor: &ControllerDescriptor,
        ) -> impl std::future::Future<Output = Result<InitialList, SourceError>> + Send {
            let first_list =
                self.initial_lists
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    == 0;
            let resources = self
                .target
                .as_ref()
                .filter(|_| !(self.late_create && first_list))
                .map(|target| {
                    vec![InitialResource::new(
                        target.key().clone(),
                        target.revision(),
                    )]
                })
                .unwrap_or_default();
            std::future::ready(Ok(InitialList {
                resources,
                snapshot_revision: ZoneRevision::new(20),
            }))
        }

        fn open_watch(
            &self,
            _descriptor: &ControllerDescriptor,
            _after_revision: ZoneRevision,
        ) -> impl std::future::Future<Output = Result<(), SourceError>> + Send {
            self.watches
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            std::future::ready(Ok(()))
        }

        fn receive_watch(
            &self,
        ) -> impl std::future::Future<Output = Result<WatchEvent, WatchFailure>> + Send {
            if self.late_create
                && !self
                    .late_signal_sent
                    .swap(true, std::sync::atomic::Ordering::Relaxed)
            {
                return std::future::ready(Err(WatchFailure::Disconnected));
            }
            std::future::ready(Ok(self
                .events
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(WatchEvent::Closed)))
        }

        fn read_fresh(
            &self,
            _key: &ResourceKey,
        ) -> impl std::future::Future<Output = Result<FreshSnapshot, SourceError>> + Send {
            let result = self
                .target
                .clone()
                .map(|target| FreshSnapshot::Present {
                    target,
                    dependencies: self.dependencies.clone(),
                })
                .ok_or(SourceError::Unavailable);
            std::future::ready(result)
        }

        fn write_starting(
            &self,
            _context: &ReconcileContext,
        ) -> impl std::future::Future<Output = Result<(), SourceError>> + Send {
            std::future::ready(Ok(()))
        }

        fn accept_effect(
            &self,
            _context: &ReconcileContext,
            _plan: &ReconcilePlan,
        ) -> impl std::future::Future<Output = Result<(), SourceError>> + Send {
            self.accepted_effects
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            std::future::ready(Ok(()))
        }

        fn complete_effect(
            &self,
            _context: &ReconcileContext,
            _result: &ReconcileResult,
        ) -> impl std::future::Future<Output = Result<(), SourceError>> + Send {
            self.completed_effects
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            std::future::ready(Ok(()))
        }

        fn commit_result(
            &self,
            context: &ReconcileContext,
            result: &ReconcileResult,
        ) -> impl std::future::Future<Output = Result<CommitOutcome, SourceError>> + Send {
            self.commits.lock().unwrap().push(TestCommit {
                operation_id: context.operation().operation_id().to_owned(),
                mutation_kind: result
                    .mutation_batch()
                    .and_then(|batch| batch.mutations().first())
                    .map(MutationIntent::kind),
                status_candidate: result.status_candidate().map(ToOwned::to_owned),
            });
            std::future::ready(Ok(CommitOutcome::Committed(result.processed_revision())))
        }

        fn complete_expedited(
            &self,
            _context: &ReconcileContext,
            _projection: &ReconcileProjection,
            _status_persistence: StatusPersistence,
        ) -> impl std::future::Future<Output = Result<(), SourceError>> + Send {
            std::future::ready(Ok(()))
        }

        fn persist_outcome(
            &self,
            _projection: &ReconcileProjection,
        ) -> impl std::future::Future<Output = Result<(), SourceError>> + Send {
            std::future::ready(Ok(()))
        }

        fn checkpoint(
            &self,
            _context: &ReconcileContext,
            _revision: ZoneRevision,
        ) -> impl std::future::Future<Output = Result<(), SourceError>> + Send {
            std::future::ready(Ok(()))
        }

        fn schedule_requeue(
            &self,
            _key: &ResourceKey,
            _at_tick: u64,
        ) -> impl std::future::Future<Output = Result<(), SourceError>> + Send {
            std::future::ready(Ok(()))
        }
    }

    fn identity_for_provider(provider: &str) -> ControllerIdentity {
        ControllerIdentity::new(
            ZoneId::parse("dev").unwrap(),
            ResourceRef::parse("Process/credential-controller").unwrap(),
            ControllerGeneration::new(1).unwrap(),
            ResourceRef::parse(provider).unwrap(),
            ResourceGeneration::new(1).unwrap(),
            ResourceRef::parse("Process/credential-controller").unwrap(),
            ResourceRef::parse("Host/host-system").unwrap(),
            None,
        )
        .unwrap()
    }

    fn runner_config() -> RunnerConfig {
        RunnerConfig {
            policy_revision: 1,
            api_revision: 1,
            configuration_revision: d2b_contracts_resource::v3::ConfigurationGeneration::new(1)
                .unwrap(),
            deadline_tick: 60_000,
            max_attempts: 3,
        }
    }

    fn deleting_resource(lease_state: &str) -> ResourceSnapshot {
        let mut value: serde_json::Value =
            serde_json::from_slice(resource().canonical_json()).unwrap();
        value["metadata"]["finalizers"] = serde_json::json!([CREDENTIAL_PROVIDER_REVOKE_FINALIZER]);
        value["metadata"]["deletionRequestedAt"] =
            serde_json::Value::String("1970-01-01T00:00:01.000Z".to_owned());
        value["metadata"]["revision"] = serde_json::json!(4);
        value["status"]["resource"]["credential"]["leaseState"] =
            serde_json::Value::String(lease_state.to_owned());
        ResourceSnapshot::new(
            resource().key().clone(),
            ZoneRevision::new(4),
            resource().generation(),
            serde_json::to_vec(&value).unwrap(),
            true,
        )
    }

    fn process_child(owner: &ResourceSnapshot, deletion_requested: bool) -> StoredResource {
        let child_ref = ResourceRef::parse("Process/mi-agent-relay").unwrap();
        let canonical_json = serde_json::to_vec(&serde_json::json!({
            "type": "Process",
            "metadata": {
                "name": child_ref.name().as_str(),
                "zone": owner.key().zone().as_str(),
                "ownerRef": owner.key().resource_ref().to_canonical_string(),
                "deletionRequestedAt": deletion_requested
                    .then_some("1970-01-01T00:00:02.000Z"),
            },
            "status": {"phase": "Ready", "observedGeneration": 1}
        }))
        .unwrap();
        StoredResource {
            resource_ref: child_ref,
            zone: owner.key().zone().clone(),
            uid: ResourceUid::parse("223e4567-e89b-42d3-a456-426614174001").unwrap(),
            generation: ResourceGeneration::new(1).unwrap(),
            revision: ZoneRevision::new(5),
            canonical_json,
            payload_digest:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
        }
    }

    fn resource_for_provider(provider: &str) -> ResourceSnapshot {
        let mut value: serde_json::Value =
            serde_json::from_slice(resource().canonical_json()).unwrap();
        value["spec"]["providerRef"] = serde_json::Value::String(provider.to_owned());
        match provider {
            "Provider/credential-secret-service" => {
                value["spec"]["scope"]["domainFilter"] =
                    serde_json::Value::String("user".to_owned());
                value["spec"]["scope"]["userRef"] =
                    serde_json::Value::String("User/example".to_owned());
            }
            "Provider/credential-entra" => {
                value["spec"]["scope"]["domainFilter"] =
                    serde_json::Value::String("system".to_owned());
            }
            "Provider/credential-managed-identity" => {}
            _ => panic!("test provider"),
        }
        ResourceSnapshot::new(
            resource().key().clone(),
            resource().revision(),
            resource().generation(),
            serde_json::to_vec(&value).unwrap(),
            false,
        )
    }

    fn credential_reconciler_for(
        store: Arc<TestCredentialStore>,
        client: Arc<TestCredentialClient>,
        session: Arc<RecordingCredentialSession>,
        provider: &str,
    ) -> CredentialResourceReconciler<TestCredentialStore, TestCredentialClient> {
        let provider_ref = ResourceRef::parse(provider).unwrap();
        CredentialResourceReconciler::new(
            store,
            client,
            identity_for_provider(provider),
            provider_ref,
            session,
        )
        .unwrap()
    }

    fn credential_reconciler(
        store: Arc<TestCredentialStore>,
        client: Arc<TestCredentialClient>,
        session: Arc<RecordingCredentialSession>,
    ) -> CredentialResourceReconciler<TestCredentialStore, TestCredentialClient> {
        credential_reconciler_for(
            store,
            client,
            session,
            "Provider/credential-managed-identity",
        )
    }

    #[tokio::test]
    async fn runner_first_pass_only_enrolls_the_exact_finalizer() {
        let source = Arc::new(TestRunnerSource::new(Some(resource()), Vec::new()));
        let reconciler = Arc::new(credential_reconciler(
            Arc::new(TestCredentialStore::default()),
            Arc::new(TestCredentialClient::default()),
            Arc::new(RecordingCredentialSession::default()),
        ));
        Runner::new(reconciler, Arc::clone(&source), runner_config())
            .run()
            .await
            .expect("runner");
        let commits = source.commits();
        assert_eq!(commits.len(), 1);
        assert!(!commits[0].operation_id.is_empty());
        assert_eq!(
            commits[0].mutation_kind,
            Some(MutationIntentKind::UpdateFinalizers)
        );
        assert!(commits[0].status_candidate.is_none());
        assert_eq!(
            source
                .accepted_effects
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[tokio::test]
    async fn runner_rejoin_reuses_one_durable_revoke_operation_and_persists_evidence() {
        let session = Arc::new(RecordingCredentialSession::default());
        let mut operation_ids = Vec::new();
        for _ in 0..2 {
            let source = Arc::new(TestRunnerSource::new(
                Some(deleting_resource("Active")),
                Vec::new(),
            ));
            let reconciler = Arc::new(credential_reconciler(
                Arc::new(TestCredentialStore::default()),
                Arc::new(TestCredentialClient::default()),
                Arc::clone(&session),
            ));
            Runner::new(reconciler, source.clone(), runner_config())
                .run()
                .await
                .expect("runner");
            let commits = source.commits();
            assert_eq!(commits.len(), 1);
            operation_ids.push(commits[0].operation_id.clone());
            let status = String::from_utf8(commits[0].status_candidate.clone().unwrap()).unwrap();
            assert!(status.contains("revocation"));
            assert!(status.contains("revoked"));
            assert!(!status.contains("credential-secret-canary"));
        }
        assert_eq!(
            session.attempts.load(std::sync::atomic::Ordering::Relaxed),
            2
        );
        assert_eq!(session.operations.lock().unwrap().len(), 1);
        assert_eq!(operation_ids[0], operation_ids[1]);
    }

    #[tokio::test]
    async fn uncertain_revoke_evidence_retains_the_finalizer_and_lease() {
        let source = Arc::new(TestRunnerSource::new(
            Some(deleting_resource("Active")),
            Vec::new(),
        ));
        let provider_ref =
            ResourceRef::parse("Provider/credential-managed-identity").unwrap();
        let client = Arc::new(TestCredentialClient::default());
        let reconciler = Arc::new(
            CredentialResourceReconciler::new(
                Arc::new(TestCredentialStore::default()),
                Arc::clone(&client),
                identity_for_provider("Provider/credential-managed-identity"),
                provider_ref,
                Arc::new(UncertainCredentialSession),
            )
            .unwrap(),
        );
        Runner::new(reconciler, source.clone(), runner_config())
            .run()
            .await
            .expect("uncertain revoke runner");
        let status = String::from_utf8(source.commits()[0].status_candidate.clone().unwrap())
            .unwrap();
        assert!(status.contains("\"outcome\":\"uncertain\""));
        assert!(status.contains("\"leaseState\":\"Active\""));
        assert!(client.finalizer_updates.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn runner_keeps_finalizer_until_revocation_and_process_child_cleanup_complete() {
        let deleting = deleting_resource("Revoked");
        let child = process_child(&deleting, false);
        let client = Arc::new(TestCredentialClient::default());
        let first_source = Arc::new(TestRunnerSource::new(Some(deleting.clone()), Vec::new()));
        let first = Arc::new(credential_reconciler(
            Arc::new(TestCredentialStore::with_children(vec![(
                child.clone(),
                deleting.key().uid().clone(),
            )])),
            Arc::clone(&client),
            Arc::new(RecordingCredentialSession::default()),
        ));
        Runner::new(first, first_source, runner_config())
            .run()
            .await
            .expect("child deletion runner");
        assert_eq!(client.deletes.lock().unwrap().len(), 1);
        assert!(client.finalizer_updates.lock().unwrap().is_empty());
        assert_eq!(client.operations.lock().unwrap().len(), 1);

        let second_source = Arc::new(TestRunnerSource::new(Some(deleting.clone()), Vec::new()));
        let second = Arc::new(credential_reconciler(
            Arc::new(TestCredentialStore::with_children(vec![(
                process_child(&deleting, true),
                deleting.key().uid().clone(),
            )])),
            Arc::clone(&client),
            Arc::new(RecordingCredentialSession::default()),
        ));
        Runner::new(second, second_source, runner_config())
            .run()
            .await
            .expect("finalizer release runner");
        assert!(client.finalizer_updates.lock().unwrap().is_empty());

        let third_source = Arc::new(TestRunnerSource::new(Some(deleting), Vec::new()));
        let third = Arc::new(credential_reconciler(
            Arc::new(TestCredentialStore::default()),
            Arc::clone(&client),
            Arc::new(RecordingCredentialSession::default()),
        ));
        Runner::new(third, third_source, runner_config())
            .run()
            .await
            .expect("confirmed child removal runner");
        assert_eq!(client.finalizer_updates.lock().unwrap().len(), 1);
        assert_eq!(client.operations.lock().unwrap().len(), 2);
        let operations = client.operations.lock().unwrap();
        assert_ne!(operations[0], operations[1]);
    }

    #[tokio::test]
    async fn composed_runner_revokes_then_cleans_the_managed_identity_child() {
        let provider_ref =
            ResourceRef::parse("Provider/credential-managed-identity").unwrap();
        let driver = Arc::new(FakeCredentialDriver::new(9));
        let route = d2b_session::AuthenticatedSessionRouteBinding::for_test(
            Some(provider_ref.clone()),
            CREDENTIAL_SERVICE_NAME,
            9,
            Some(1),
            Some(1),
        );
        let session = Arc::new(
            ComponentCredentialSession::new(route, driver.clone()).unwrap(),
        );
        let registry = CredentialSessionRegistry::default();
        registry
            .register(
                provider_ref.clone(),
                ReconnectGeneration::new(9).unwrap(),
                session,
            )
            .unwrap();
        let client = Arc::new(TestCredentialClient::default());

        let active = deleting_resource("Active");
        let expected_revoke = CredentialRevocationRequest::new(
            &active,
            &provider_ref,
            &identity_for_provider("Provider/credential-managed-identity"),
            ReconnectGeneration::new(9).unwrap(),
        )
        .unwrap();
        let revoke_source = Arc::new(TestRunnerSource::new(Some(active.clone()), Vec::new()));
        let revoke = Arc::new(CredentialResourceReconciler::new(
            Arc::new(TestCredentialStore::default()),
            Arc::clone(&client),
            identity_for_provider("Provider/credential-managed-identity"),
            provider_ref.clone(),
            registry.for_provider(provider_ref.clone()),
        )
        .unwrap());
        Runner::new(revoke, revoke_source.clone(), runner_config())
            .run()
            .await
            .expect("composed revoke runner");
        let commits = revoke_source.commits();
        assert_eq!(commits.len(), 1);
        assert!(String::from_utf8(commits[0].status_candidate.clone().unwrap())
            .unwrap()
            .contains("\"outcome\":\"revoked\""));
        assert_eq!(driver.requests.lock().unwrap().len(), 1);
        assert_eq!(
            driver.requests.lock().unwrap()[0],
            (
                expected_revoke.operation_id.clone(),
                expected_revoke.idempotency_key.clone(),
                9,
            )
        );

        let rejoined_driver = Arc::new(FakeCredentialDriver::new(10));
        let rejoined_route = d2b_session::AuthenticatedSessionRouteBinding::for_test(
            Some(provider_ref.clone()),
            CREDENTIAL_SERVICE_NAME,
            10,
            Some(1),
            Some(1),
        );
        let rejoined_session = Arc::new(
            ComponentCredentialSession::new(rejoined_route, rejoined_driver.clone()).unwrap(),
        );
        registry
            .register(
                provider_ref.clone(),
                ReconnectGeneration::new(10).unwrap(),
                rejoined_session,
            )
            .unwrap();
        let rejoined_source = Arc::new(TestRunnerSource::new(
            Some(active.clone()),
            Vec::new(),
        ));
        let rejoined = Arc::new(CredentialResourceReconciler::new(
            Arc::new(TestCredentialStore::default()),
            Arc::clone(&client),
            identity_for_provider("Provider/credential-managed-identity"),
            provider_ref.clone(),
            registry.for_provider(provider_ref.clone()),
        )
        .unwrap());
        Runner::new(rejoined, rejoined_source.clone(), runner_config())
            .run()
            .await
            .expect("composed provider rejoin runner");
        assert!(String::from_utf8(
            rejoined_source.commits()[0]
                .status_candidate
                .clone()
                .unwrap(),
        )
        .unwrap()
        .contains("\"outcome\":\"revoked\""));
        assert_eq!(rejoined_driver.requests.lock().unwrap().len(), 1);
        assert_eq!(
            rejoined_driver.requests.lock().unwrap()[0].0,
            expected_revoke.operation_id
        );
        assert_eq!(rejoined_driver.requests.lock().unwrap()[0].2, 10);

        let revoked = deleting_resource("Revoked");
        let delete_source = Arc::new(TestRunnerSource::new(Some(revoked.clone()), Vec::new()));
        let delete = Arc::new(CredentialResourceReconciler::new(
            Arc::new(TestCredentialStore::with_children(vec![(
                process_child(&revoked, false),
                revoked.key().uid().clone(),
            )])),
            Arc::clone(&client),
            identity_for_provider("Provider/credential-managed-identity"),
            provider_ref.clone(),
            registry.for_provider(provider_ref.clone()),
        )
        .unwrap());
        Runner::new(delete, delete_source, runner_config())
            .run()
            .await
            .expect("composed child-delete runner");
        assert_eq!(client.deletes.lock().unwrap().len(), 1);
        assert!(client.finalizer_updates.lock().unwrap().is_empty());

        let retained_source = Arc::new(TestRunnerSource::new(Some(revoked.clone()), Vec::new()));
        let retained = Arc::new(CredentialResourceReconciler::new(
            Arc::new(TestCredentialStore::with_children(vec![(
                process_child(&revoked, true),
                revoked.key().uid().clone(),
            )])),
            Arc::clone(&client),
            identity_for_provider("Provider/credential-managed-identity"),
            provider_ref.clone(),
            registry.for_provider(provider_ref.clone()),
        )
        .unwrap());
        Runner::new(retained, retained_source, runner_config())
            .run()
            .await
            .expect("composed retained-finalizer runner");
        assert!(client.finalizer_updates.lock().unwrap().is_empty());

        let clear_source = Arc::new(TestRunnerSource::new(Some(revoked.clone()), Vec::new()));
        let clear = Arc::new(CredentialResourceReconciler::new(
            Arc::new(TestCredentialStore::default()),
            Arc::clone(&client),
            identity_for_provider("Provider/credential-managed-identity"),
            provider_ref,
            registry.for_provider(
                ResourceRef::parse("Provider/credential-managed-identity").unwrap(),
            ),
        )
        .unwrap());
        Runner::new(clear, clear_source, runner_config())
            .run()
            .await
            .expect("composed clear-finalizer runner");
        assert_eq!(client.finalizer_updates.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn empty_provider_watches_register_before_any_credential_exists() {
        for provider in [
            "Provider/credential-secret-service",
            "Provider/credential-entra",
            "Provider/credential-managed-identity",
        ] {
            let source = Arc::new(TestRunnerSource::new(None, Vec::new()));
            let provider_ref = ResourceRef::parse(provider).unwrap();
            let reconciler = Arc::new(
                CredentialResourceReconciler::new(
                    Arc::new(TestCredentialStore::default()),
                    Arc::new(TestCredentialClient::default()),
                    identity_for_provider(provider),
                    provider_ref,
                    Arc::new(RecordingCredentialSession::default()),
                )
                .unwrap(),
            );
            Runner::new(reconciler, Arc::clone(&source), runner_config())
                .run()
                .await
                .expect("empty provider runner");
            assert_eq!(
                source.registered.load(std::sync::atomic::Ordering::Relaxed),
                1
            );
            assert_eq!(source.watches.load(std::sync::atomic::Ordering::Relaxed), 1);
        }
    }

    #[tokio::test]
    async fn empty_provider_watches_admit_a_later_credential_create_for_each_provider() {
        for provider in [
            "Provider/credential-secret-service",
            "Provider/credential-entra",
            "Provider/credential-managed-identity",
        ] {
            let source = Arc::new(TestRunnerSource::late_create(
                resource_for_provider(provider),
                Vec::new(),
            ));
            let reconciler = Arc::new(credential_reconciler_for(
                Arc::new(TestCredentialStore::default()),
                Arc::new(TestCredentialClient::default()),
                Arc::new(RecordingCredentialSession::default()),
                provider,
            ));
            Runner::new(reconciler, Arc::clone(&source), runner_config())
                .run()
                .await
                .expect("later Credential create runner");
            assert_eq!(source.commits().len(), 1);
            assert_eq!(
                source.commits()[0].mutation_kind,
                Some(MutationIntentKind::UpdateFinalizers)
            );
            assert_eq!(
                source
                    .registered
                    .load(std::sync::atomic::Ordering::Relaxed),
                1
            );
        }
    }

    #[test]
    fn confirmed_revocation_evidence_is_persisted_without_identity_or_secret_bytes() {
        let target = resource();
        let request = CredentialRevocationRequest::new(
            &target,
            &ResourceRef::parse("Provider/credential-managed-identity").unwrap(),
            &identity(),
            ReconnectGeneration::new(7).unwrap(),
        )
        .expect("revocation request");
        let evidence =
            CredentialRevocationEvidence::confirmed(&request, CredentialRevocationOutcome::Revoked);
        let status = credential_status_candidate(
            &target,
            ResourcePhase::Pending,
            "credential-lease-revoked",
            true,
            Some(&evidence),
        )
        .expect("status");
        let text = String::from_utf8(status).unwrap();
        assert!(text.contains("revocation"));
        assert!(text.contains("revoked"));
        assert!(text.contains("sessionGeneration"));
        assert!(!text.contains(target.key().uid().as_str()));
        assert!(!text.contains("credential-secret-canary"));
    }

    #[test]
    fn managed_identity_agent_payload_is_owner_bound_and_egress_denied() {
        let payload = managed_identity_agent_payload(&resource()).expect("agent payload");
        let value: serde_json::Value = serde_json::from_slice(&payload).expect("agent JSON");
        let mut process_value = value["spec"].clone();
        process_value
            .as_object_mut()
            .expect("Process spec object")
            .remove("providerRef");
        serde_json::from_value::<ProcessSpec>(process_value).expect("valid Process spec");
        assert_eq!(value["type"], "Process");
        assert_eq!(value["metadata"]["ownerRef"], "Credential/relay");
        assert_eq!(
            value["spec"]["executionRef"],
            "Guest/gateway"
        );
        assert_eq!(value["spec"]["providerRef"], "Provider/system-systemd");
        assert_eq!(value["spec"]["processClass"], "service");
        assert_eq!(
            value["spec"]["template"],
            d2b_provider_credential_managed_identity::AGENT_BINARY
        );
        assert_eq!(value["spec"]["domain"], "system");
        assert_eq!(value["spec"]["networkUsage"]["allowEgress"], false);
        assert_eq!(
            value["spec"]["sandbox"]["namespaceClasses"],
            serde_json::json!(["mount", "pid", "ipc"])
        );
        assert!(!payload.windows(1).any(|window| window == b"credential-secret-canary"));
    }

    #[test]
    fn managed_identity_agent_readiness_requires_current_ready_status() {
        let mut child = managed_identity_agent_process("Ready", 1);
        assert!(managed_identity_agent_ready(&child));
        child.canonical_json =
            serde_json::to_vec(&serde_json::json!({
                "metadata": {"generation": 1},
                "status": {"phase": "Ready", "observedGeneration": 0}
            }))
            .unwrap();
        assert!(!managed_identity_agent_ready(&child));
        child.canonical_json =
            serde_json::to_vec(&serde_json::json!({
                "metadata": {"generation": 1},
                "status": {"phase": "Degraded", "observedGeneration": 1}
            }))
            .unwrap();
        assert!(!managed_identity_agent_ready(&child));
    }

    #[test]
    fn managed_identity_agent_matching_is_exactly_scoped_to_the_credential() {
        let owner = resource();
        let payload = managed_identity_agent_payload(&owner).expect("agent payload");
        let child = StoredResource {
            resource_ref: managed_identity_agent_ref(&owner).unwrap(),
            zone: ZoneId::parse("dev").unwrap(),
            uid: ResourceUid::parse("223e4567-e89b-42d3-a456-426614174001").unwrap(),
            generation: ResourceGeneration::new(1).unwrap(),
            revision: ZoneRevision::new(2),
            canonical_json: payload,
            payload_digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_owned(),
        };
        assert!(managed_identity_agent_matches(&child, &owner));
        let foreign_owner = ResourceSnapshot::new(
            ResourceKey::new(
                ZoneId::parse("dev").unwrap(),
                ResourceRef::parse("Credential/other").unwrap(),
                ResourceUid::parse("323e4567-e89b-42d3-a456-426614174002").unwrap(),
            ),
            ZoneRevision::new(3),
            ResourceGeneration::new(1).unwrap(),
            serde_json::to_vec(&serde_json::json!({
                "apiVersion": "resources.d2bus.org/v3",
                "type": "Credential",
                "metadata": {
                    "name": "other",
                    "zone": "dev",
                    "uid": "323e4567-e89b-42d3-a456-426614174002",
                    "generation": 1,
                    "revision": 3,
                    "finalizers": [],
                    "labels": {},
                    "annotations": {},
                    "ownerRef": null,
                    "managedBy": "controller",
                    "configurationGeneration": 1,
                    "deletionRequestedAt": null,
                    "createdAt": "1970-01-01T00:00:00.000Z",
                    "updatedAt": "1970-01-01T00:00:00.000Z"
                },
                "spec": {
                    "providerRef": "Provider/credential-managed-identity",
                    "scope": {"executionRef": "Guest/gateway", "domainFilter": "system"},
                    "allowedOperations": ["acquire-token"],
                    "audience": "relay"
                },
                "status": {
                    "phase": "Pending",
                    "observedGeneration": 0,
                    "conditions": [],
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
            }))
            .unwrap(),
            false,
        );
        assert!(!managed_identity_agent_matches(&child, &foreign_owner));
    }

    #[test]
    fn credential_scope_validation_rejects_user_or_host_mismatches() {
        let user_scope: CredentialSpec = serde_json::from_value(json!({
            "scope": {
                "executionRef": "Guest/gateway",
                "domainFilter": "user",
                "userRef": "User/example"
            },
            "audience": "relay",
            "allowedOperations": ["acquire-token"]
        }))
        .expect("user scope");
        assert!(credential_scope_valid(
            CredentialProviderKind::SecretService,
            &user_scope
        ));
        assert!(!credential_scope_valid(
            CredentialProviderKind::ManagedIdentity,
            &user_scope
        ));

        let host_scope: CredentialSpec = serde_json::from_value(json!({
            "scope": {
                "executionRef": "Host/host-system",
                "domainFilter": "system"
            },
            "audience": "relay",
            "allowedOperations": ["acquire-token"]
        }))
        .expect("host scope");
        assert!(credential_scope_valid(
            CredentialProviderKind::ManagedIdentity,
            &host_scope
        ));
        assert!(!credential_scope_valid(
            CredentialProviderKind::Entra,
            &host_scope
        ));
    }

    #[test]
    fn scoped_resource_client_rejects_wrong_zone_or_execution_before_session() {
        let request = ScopedCredentialRequest::new(
            ZoneId::parse("other").unwrap(),
            ResourceRef::parse("Credential/relay").unwrap(),
            ResourceRef::parse("Guest/gateway").unwrap(),
            RelayCredentialRole::Send,
            RelayCredentialBinding::new_scoped(
                ZoneId::parse("other").unwrap(),
                "link",
                "session",
                1,
            )
            .unwrap(),
            1_000,
        )
        .unwrap();
        assert!(
            SameZoneScopedCredentialClient::validate_request_scope(
                &request,
                &ZoneId::parse("dev").unwrap()
            )
            .is_err()
        );
    }

    struct NeverCredentialResourceReader;

    #[async_trait]
    impl CredentialResourceReader for NeverCredentialResourceReader {
        async fn get(&self, _request: wire::GetRequest) -> wire::GetResponse {
            panic!("invalid scoped request reached ResourceService")
        }
    }

    struct NeverScopedCredentialDelegate;

    #[async_trait]
    impl ScopedCredentialClient for NeverScopedCredentialDelegate {
        async fn read_credential(
            &self,
            _request: &ScopedCredentialRequest,
        ) -> Result<RelayCredentialLease, RelayCredentialError> {
            Err(RelayCredentialError::Unavailable)
        }

        async fn revoke_credential(
            &self,
            _lease: RelayCredentialLease,
        ) -> Result<(), RelayCredentialError> {
            Err(RelayCredentialError::Unavailable)
        }
    }

    #[tokio::test]
    async fn scoped_resource_client_rejects_wrong_guest_or_reconnect_before_resource_read() {
        let zone = ZoneId::parse("dev").unwrap();
        let route = d2b_session::AuthenticatedSessionRouteBinding::for_test(
            Some(ResourceRef::parse("Provider/relay").unwrap()),
            "d2b.resource.v3",
            7,
            Some(1),
            Some(1),
        );
        let client = SameZoneScopedCredentialClient::with_resource_reader(
            zone.clone(),
            route,
            ResourceRef::parse("Guest/gateway").unwrap(),
            Arc::new(NeverCredentialResourceReader),
            Arc::new(NeverScopedCredentialDelegate),
        );
        let wrong_guest = ScopedCredentialRequest::new(
            zone.clone(),
            ResourceRef::parse("Credential/relay").unwrap(),
            ResourceRef::parse("Guest/other").unwrap(),
            RelayCredentialRole::Send,
            RelayCredentialBinding::new_scoped(zone.clone(), "link", "session", 7).unwrap(),
            1_000,
        )
        .unwrap();
        assert_eq!(
            client.read_credential(&wrong_guest).await.unwrap_err(),
            RelayCredentialError::InvalidScope
        );
        let stale_session = ScopedCredentialRequest::new(
            zone.clone(),
            ResourceRef::parse("Credential/relay").unwrap(),
            ResourceRef::parse("Guest/gateway").unwrap(),
            RelayCredentialRole::Send,
            RelayCredentialBinding::new_scoped(zone, "link", "session", 6).unwrap(),
            1_000,
        )
        .unwrap();
        assert_eq!(
            client.read_credential(&stale_session).await.unwrap_err(),
            RelayCredentialError::InvalidScope
        );
    }

    fn managed_identity_agent_process(phase: &str, observed_generation: u64) -> StoredResource {
        let resource_ref = ResourceRef::parse("Process/mi-agent-relay").unwrap();
        let zone = ZoneId::parse("dev").unwrap();
        let canonical_json = serde_json::to_vec(&serde_json::json!({
            "type": "Process",
            "metadata": {
                "name": "mi-agent-relay",
                "zone": "dev",
                "generation": 1
            },
            "status": {
                "phase": phase,
                "observedGeneration": observed_generation
            }
        }))
        .unwrap();
        StoredResource {
            resource_ref,
            zone,
            uid: ResourceUid::parse("223e4567-e89b-42d3-a456-426614174001").unwrap(),
            generation: ResourceGeneration::new(1).unwrap(),
            revision: ZoneRevision::new(2),
            canonical_json,
            payload_digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_owned(),
        }
    }
}
