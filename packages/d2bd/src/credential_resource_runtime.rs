//! Zone resource reconciliation and scoped session admission for Credential
//! Providers.

use std::sync::Arc;

use async_trait::async_trait;
use d2b_contracts_provider::v3::{
    credential::{CREDENTIAL_SERVICE_NAME, CredentialSpec, PlacementBinding},
    credential_controller::{CREDENTIAL_PROVIDER_REVOKE_FINALIZER, CredentialProviderKind},
};
use d2b_contracts_resource::resource_proto as wire;
use d2b_contracts_resource::v3::{
    CanonicalJsonValue, DesiredLifecycle, ResourceEnvelope, ResourcePhase, ResourceRef,
    ResourceTypeName, ZoneId,
    execution_policy::{
        BoundedToken, BudgetSpec, DurationMs, ExecutionDomain,
    },
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
    StoreFilter, StoreListRequest, StoreOperationContext, StoreProjection, StoredResource,
};
use d2b_resource_store_redb::RedbResourceStore;

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
}

impl core::fmt::Display for CredentialResourceRuntimeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidResource => "credential-resource-invalid",
            Self::Store => "credential-resource-store-failed",
            Self::Cleanup => "credential-resource-cleanup-failed",
        })
    }
}

impl std::error::Error for CredentialResourceRuntimeError {}

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
pub(crate) struct CredentialResourceReconciler {
    store: Arc<RedbResourceStore>,
    client: Arc<ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>>,
    identity: ControllerIdentity,
    provider_ref: ResourceRef,
    provider_kind: CredentialProviderKind,
}

impl CredentialResourceReconciler {
    pub(crate) fn new(
        store: Arc<RedbResourceStore>,
        client: Arc<ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>>,
        identity: ControllerIdentity,
        provider_ref: ResourceRef,
    ) -> Result<Self, CredentialResourceRuntimeError> {
        let provider_kind =
            provider_kind(&provider_ref).ok_or(CredentialResourceRuntimeError::InvalidResource)?;
        Ok(Self {
            store,
            client,
            identity,
            provider_ref,
            provider_kind,
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
            let page = self
                .store
                .list(StoreListRequest {
                    operation: StoreOperationContext {
                        operation_id: "credential-cleanup-process-list".to_owned(),
                        idempotency_key: None,
                        correlation_id: "credential-cleanup-process-list".to_owned(),
                        trace_id: None,
                        deadline_ms: 5_000,
                    },
                    zone: self.store.identity().zone().clone(),
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
        let operation = format!(
            "credential-process-delete-{}",
            resource.resource_ref.name().as_str()
        );
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
        let operation = "credential-provider-revoke-finalizer";
        let mut request = wire::UpdateFinalizersRequest::new();
        request.meta = protobuf::MessageField::some(
            d2bd_runtime::resource_runtime_support::public_request_meta(operation),
        );
        request.mutation = protobuf::MessageField::some(mutation);
        if self.client.update_finalizers(request).await.error.is_some() {
            return Err(CredentialResourceRuntimeError::Cleanup);
        }
        Ok(())
    }
}

impl ResourceReconciler for CredentialResourceReconciler {
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
                let status = credential_status_candidate(
                    resource,
                    ResourcePhase::Degraded,
                    "credential-lease-revoked",
                    true,
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

fn credential_status_candidate(
    resource: &ResourceSnapshot,
    phase: ResourcePhase,
    outcome: &str,
    lease_revoked: bool,
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
    if lease_revoked {
        if let Some(credential) = status
            .get_mut("resource")
            .and_then(serde_json::Value::as_object_mut)
            .and_then(|resource| resource.get_mut("credential"))
            .and_then(serde_json::Value::as_object_mut)
        {
            credential.insert(
                "leaseState".to_owned(),
                serde_json::Value::String("Revoked".to_owned()),
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
    resource: Arc<dyn CredentialResourceReader>,
    delegate: Arc<dyn ScopedCredentialClient>,
}

#[async_trait]
trait CredentialResourceReader: Send + Sync {
    async fn get(&self, request: wire::GetRequest) -> wire::GetResponse;
}

#[async_trait]
impl CredentialResourceReader for ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher> {
    async fn get(&self, request: wire::GetRequest) -> wire::GetResponse {
        ResourceApiClient::get(self, request).await
    }
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
    #[allow(dead_code)]
    pub(crate) fn new(
        zone: ZoneId,
        resource: Arc<ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>>,
        delegate: Arc<dyn ScopedCredentialClient>,
    ) -> Self {
        Self::with_resource_reader(zone, resource, delegate)
    }

    pub(crate) fn with_component_session(
        zone: ZoneId,
        session: &d2bd_runtime::guest_component_session::GuestComponentSessionClient,
        delegate: Arc<dyn ScopedCredentialClient>,
    ) -> Result<Self, RelayCredentialError> {
        if session.identity().zone() != &zone
            || session.generation() == 0
            || session
                .identity()
                .validate_route(&session.route_binding())
                .is_err()
        {
            return Err(RelayCredentialError::InvalidScope);
        }
        Ok(Self::with_resource_reader(
            zone,
            Arc::new(ComponentSessionCredentialResourceReader {
                client: session.resource_service_client(),
            }),
            delegate,
        ))
    }

    fn with_resource_reader(
        zone: ZoneId,
        resource: Arc<dyn CredentialResourceReader>,
        delegate: Arc<dyn ScopedCredentialClient>,
    ) -> Self {
        Self {
            zone,
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
    use d2b_contracts_resource::v3::{
        ControllerGeneration, ResourceGeneration, ResourcePhase, ResourceRef, ResourceUid, ZoneId,
        ZoneRevision,
    };
    use d2b_core_controller::{
        ControllerIdentity, MutationIntent, MutationIntentKind, ResourceKey, ResourceMutationBatch,
        ResourceSnapshot,
    };
    use d2b_provider_transport_azure_relay::{RelayCredentialBinding, RelayCredentialRole};
    use serde_json::json;

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
            credential_status_candidate(&resource(), ResourcePhase::Ready, "success", false)
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
