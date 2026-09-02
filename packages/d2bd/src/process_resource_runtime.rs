//! Daemon-owned reconciliation for generic `Process` resources.
//!
//! The fixed process Providers are composed once by `d2bd`; this module is
//! only the Zone-scoped durable-resource adapter. It relists and watches the
//! store, resolves typed specs, and routes every lifecycle effect through the
//! already composed Provider supervisors.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use d2b_contracts_resource::resource_proto as wire;
use d2b_contracts_resource::v3::{
    CanonicalJsonValue, ControllerGeneration, ResourceEnvelope, ResourceGeneration, ResourcePhase,
    ResourceRef, ResourceTypeName, ResourceUid, SchemaFingerprint, ZoneId, ZoneRevision,
    canonical_digest,
    process::{EphemeralProcessSpec, ProcessSpec, RestartClass},
};
use d2b_core_controller::{
    ChangeField as SelectorField, ChangeRecord, CommitOutcome, ControllerDescriptor,
    ControllerExecutionPolicy, ControllerIdentity, ControllerVerb, CoreTriggerReason,
    DependencySnapshot, DrainResult, FinalizeResult, FreshSnapshot, InitialList, InitialResource,
    MutationIntentKind,
    ObservationResult, OperationContext, ProcessSchedulingClass, ReconcileContext,
    ReconcileDisposition, ReconcilePlan, ReconcileReason, ReconcileResult, RegisteredControllerApi,
    ResourceKey, ResourceMutationBatch, ResourceReconciler, ResourceRegistration, ResourceSnapshot,
    ResyncPolicy, SourceError, StatusPersistence, UpdateAssessment,
    UpdateAssessmentState, UpgradePlan, ValidationResult, WatchFailure,
    WatchSelector as ControllerSelector,
};
use d2b_process_conformance::{AdoptionCandidate, GuestExecutionBinding};
use d2b_resource_api::{
    RedbBackend, ResourceApiClient, ResourceStoreBackend,
    service::{UnavailableUpgradeDispatcher, UpgradeDispatcher},
    watch::ResourceWatch,
};
use d2b_resource_store::{
    StoreError, StoreErrorKind, StoreGetRequest, StoreListRequest, StoreOperationContext,
    StoreProjection, StoreWatchRequest, StoredResource,
};
use d2b_resource_store_redb::{
    AuthorityOperationState, ChangeEvent, RedbResourceStore, SharedChangeBatch,
    AuthorityOperationCapability,
};
use sha2::{Digest, Sha256};

use crate::process_provider_runtime::{
    GUEST_EXECUTION_UNAVAILABLE, ProcessResourceContext, ProductionProcessProviders,
    ProviderAdoption, ProviderLiveness, execution_target_allowed,
};
use d2bd_runtime::guest_resource_runtime::SessionBoundStore;
use d2bd_runtime::target_runtime::DaemonMode;

const PROCESS_TYPE: &str = "Process";
const EPHEMERAL_PROCESS_TYPE: &str = "EphemeralProcess";
const MINIJAIL_PROVIDER: &str = "system-minijail";
const SYSTEMD_PROVIDER: &str = "system-systemd";
const PROCESS_RUNTIME_FINALIZER: &str = "process-runtime.d2bus.org/cleanup";
const MINIJAIL_PROCESS_FINALIZER: &str = "process.system-minijail/cleanup";
const SYSTEMD_PROCESS_FINALIZER: &str = "process.system-systemd/cleanup";
#[allow(dead_code)]
const WAYLAND_SESSION_TYPE: &str = "display-wayland.d2bus.org.WaylandSession";
#[allow(dead_code)]
const WAYLAND_SESSION_FINALIZER: &str = "display-wayland.d2bus.org/proxy-stopped";
pub(crate) const PROCESS_RESTART_ANNOTATION: &str = "d2b.d2bus.org/restart-generation";

/// Stable failures for the daemon-owned generic process path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProcessResourceRuntimeError {
    /// A durable resource did not decode as the closed Process contract.
    InvalidResource,
    /// The resource selected a Provider not owned by this runtime.
    UnsupportedProvider,
    /// The trusted bundle did not contain the requested template binding.
    TemplateUnavailable,
    /// A process identity was ambiguous during adoption or stop.
    IdentityAmbiguous,
    /// A Provider effect failed.
    ProviderEffect,
    /// A static controller has no committed Provider identity projection.
    ProviderIdentityUnavailable,
    /// The durable store could not be listed or watched.
    Store,
}

impl core::fmt::Display for ProcessResourceRuntimeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidResource => "process-resource-invalid",
            Self::UnsupportedProvider => "process-resource-provider-unsupported",
            Self::TemplateUnavailable => "process-resource-template-unavailable",
            Self::IdentityAmbiguous => "process-resource-identity-ambiguous",
            Self::ProviderEffect => "process-resource-provider-effect-failed",
            Self::ProviderIdentityUnavailable => "process-resource-provider-identity-unavailable",
            Self::Store => "process-resource-store-failed",
        })
    }
}

impl std::error::Error for ProcessResourceRuntimeError {}

#[async_trait::async_trait]
pub(crate) trait ProcessResourceClient: Send + Sync {
    async fn update_status(&self, request: wire::UpdateStatusRequest)
    -> wire::UpdateStatusResponse;

    async fn update_finalizers(
        &self,
        request: wire::UpdateFinalizersRequest,
    ) -> wire::UpdateFinalizersResponse;

    async fn delete(&self, request: wire::DeleteRequest) -> wire::DeleteResponse;
}

#[async_trait::async_trait]
impl<S, U> ProcessResourceClient for ResourceApiClient<S, U>
where
    S: ResourceStoreBackend + 'static,
    U: UpgradeDispatcher + 'static,
{
    async fn update_status(
        &self,
        request: wire::UpdateStatusRequest,
    ) -> wire::UpdateStatusResponse {
        ResourceApiClient::update_status(self, request).await
    }

    async fn update_finalizers(
        &self,
        request: wire::UpdateFinalizersRequest,
    ) -> wire::UpdateFinalizersResponse {
        ResourceApiClient::update_finalizers(self, request).await
    }

    async fn delete(&self, request: wire::DeleteRequest) -> wire::DeleteResponse {
        ResourceApiClient::delete(self, request).await
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DesiredProcess {
    Process(ProcessSpec),
    Ephemeral(EphemeralProcessSpec),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DesiredRecord {
    resource: StoredResource,
    provider_ref: ResourceRef,
    process: DesiredProcess,
    zone_uid: Option<ResourceUid>,
    policy_revision: Option<u64>,
    provider_assignment_generation: Option<ResourceGeneration>,
    controller_provider_uid: Option<ResourceUid>,
    controller_provider_generation: Option<ResourceGeneration>,
}

impl DesiredRecord {
    fn key(&self) -> ResourceRef {
        self.resource.resource_ref.clone()
    }

    fn is_running(&self) -> bool {
        match &self.process {
            DesiredProcess::Process(spec) => {
                spec.desired_lifecycle()
                    == d2b_contracts_resource::v3::process::DesiredLifecycle::Running
            }
            DesiredProcess::Ephemeral(_) => true,
        }
    }

    fn same_desired_state(&self, other: &Self) -> bool {
        self.resource.zone == other.resource.zone
            && self.resource.resource_ref == other.resource.resource_ref
            && self.resource.uid == other.resource.uid
            && self.resource.generation == other.resource.generation
            && self.zone_uid == other.zone_uid
            && self.policy_revision == other.policy_revision
            && self.provider_assignment_generation == other.provider_assignment_generation
            && restart_annotation(&self.resource) == restart_annotation(&other.resource)
            && self.provider_ref == other.provider_ref
            && self.owner_ref() == other.owner_ref()
            && self.process == other.process
            && self.controller_provider_uid == other.controller_provider_uid
            && self.controller_provider_generation == other.controller_provider_generation
    }

    fn owner_ref(&self) -> Option<ResourceRef> {
        let CanonicalJsonValue::Object(root) =
            CanonicalJsonValue::parse(&self.resource.canonical_json).ok()?
        else {
            return None;
        };
        let CanonicalJsonValue::Object(metadata) = root.get("metadata")? else {
            return None;
        };
        let CanonicalJsonValue::String(owner) = metadata.get("ownerRef")? else {
            return None;
        };
        ResourceRef::parse(owner).ok()
    }

    fn deletion_requested(&self) -> bool {
        metadata_value(&self.resource, "deletionRequestedAt")
            .is_some_and(|value| !matches!(value, CanonicalJsonValue::Null))
    }

    fn has_runtime_finalizer(&self) -> bool {
        metadata_value(&self.resource, "finalizers").is_some_and(|value| {
            matches!(
                value,
                CanonicalJsonValue::Array(values)
                    if values.iter().any(|value| {
                        matches!(
                            value,
                            CanonicalJsonValue::String(value)
                                if process_finalizer_names()
                                    .iter()
                                    .any(|expected| value == expected)
                        )
                    })
            )
        })
    }
}

const fn process_finalizer_names() -> [&'static str; 3] {
    [
        PROCESS_RUNTIME_FINALIZER,
        MINIJAIL_PROCESS_FINALIZER,
        SYSTEMD_PROCESS_FINALIZER,
    ]
}

fn process_finalizer(provider_ref: &ResourceRef) -> Option<&'static str> {
    match provider_ref.name().as_str() {
        MINIJAIL_PROVIDER => Some(MINIJAIL_PROCESS_FINALIZER),
        SYSTEMD_PROVIDER => Some(SYSTEMD_PROCESS_FINALIZER),
        _ => None,
    }
}

fn active_process_finalizer(record: &DesiredRecord) -> Option<&'static str> {
    let value = metadata_value(&record.resource, "finalizers")?;
    let CanonicalJsonValue::Array(values) = value else {
        return None;
    };
    process_finalizer(&record.provider_ref)
        .into_iter()
        .chain([PROCESS_RUNTIME_FINALIZER])
        .find(|expected| {
            values.iter().any(
                |value| matches!(value, CanonicalJsonValue::String(value) if value == expected),
            )
        })
}

/// Durable generic process registry for one Zone.
pub(crate) struct ProcessResourceRuntime {
    zone: ZoneId,
    target: Option<ResourceRef>,
    providers: Arc<ProductionProcessProviders>,
    records: BTreeMap<ResourceRef, DesiredRecord>,
    terminal: BTreeSet<ResourceRef>,
    terminal_failed: BTreeSet<ResourceRef>,
    restart_counts: BTreeMap<ResourceRef, u32>,
    started_at: BTreeMap<ResourceRef, Instant>,
    completed_at: BTreeMap<ResourceRef, Instant>,
    next_restart_at: BTreeMap<ResourceRef, Instant>,
    controller_generation: ControllerGeneration,
    controller_provider_identities: BTreeMap<ResourceRef, (ResourceUid, ResourceGeneration)>,
    guest_execution: Option<GuestExecutionBinding>,
    zone_uid: Option<ResourceUid>,
    policy_revision: Option<u64>,
    /// Optional owner and target selector for resources using a shared Host
    /// execution reference, retained across relist/watch passes.
    target_owner_ref: Option<ResourceRef>,
    target_ref: Option<ResourceRef>,
    guest_descriptor_digests: BTreeMap<ResourceRef, SchemaFingerprint>,
    owner_uids: BTreeMap<ResourceRef, ResourceUid>,
    status_client: Option<Arc<dyn ProcessResourceClient>>,
    liveness_waker: Option<Arc<dyn Fn(ResourceKey, ZoneRevision) + Send + Sync>>,
    last_adopted: Option<bool>,
}

impl core::fmt::Debug for ProcessResourceRuntime {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProcessResourceRuntime")
            .field("zone", &self.zone)
            .field("record_count", &self.records.len())
            .finish()
    }
}

fn scoped_target_ref(
    record: &DesiredRecord,
    target_owner_ref: Option<&ResourceRef>,
    target_ref: Option<&ResourceRef>,
) -> Option<ResourceRef> {
    let owner = record.owner_ref();
    match (target_owner_ref, target_ref, owner.as_ref()) {
        (Some(expected_owner), Some(target), Some(owner)) if expected_owner == owner => {
            Some(target.clone())
        }
        _ => match (&record.process, owner) {
            (DesiredProcess::Process(spec), Some(owner))
                if owner.resource_type().as_str() == "Guest"
                    && spec.execution().template().as_str() == "cloud-hypervisor-runner"
                    && record.resource.resource_ref.name().as_str()
                        == format!("{}-vmm", owner.name().as_str()) =>
            {
                Some(owner)
            }
            _ => None,
        },
    }
}

impl ProcessResourceRuntime {
    /// Construct a registry over the daemon-owned fixed Providers.
    pub(crate) fn new(zone: ZoneId, providers: Arc<ProductionProcessProviders>) -> Self {
        Self::new_for_target(zone, providers, None)
    }

    pub(crate) fn new_for_target(
        zone: ZoneId,
        providers: Arc<ProductionProcessProviders>,
        target: Option<ResourceRef>,
    ) -> Self {
        Self {
            zone,
            target,
            providers,
            records: BTreeMap::new(),
            terminal: BTreeSet::new(),
            terminal_failed: BTreeSet::new(),
            restart_counts: BTreeMap::new(),
            started_at: BTreeMap::new(),
            completed_at: BTreeMap::new(),
            next_restart_at: BTreeMap::new(),
            controller_generation: ControllerGeneration::new(1)
                .expect("controller generation one is valid"),
            controller_provider_identities: BTreeMap::new(),
            guest_execution: None,
            zone_uid: None,
            policy_revision: None,
            target_owner_ref: None,
            target_ref: None,
            guest_descriptor_digests: BTreeMap::new(),
            owner_uids: BTreeMap::new(),
            status_client: None,
            liveness_waker: None,
            last_adopted: None,
        }
    }

    pub(crate) fn set_controller_generation(&mut self, generation: ControllerGeneration) {
        self.controller_generation = generation;
    }

    pub(crate) fn set_controller_provider_identities(
        &mut self,
        identities: BTreeMap<ResourceRef, (ResourceUid, ResourceGeneration)>,
    ) {
        self.controller_provider_identities = identities;
    }

    pub(crate) fn set_guest_execution_binding(&mut self, binding: GuestExecutionBinding) {
        self.guest_execution = Some(binding);
    }

    pub(crate) fn set_lifecycle_identity(&mut self, zone_uid: ResourceUid, policy_revision: u64) {
        self.zone_uid = Some(zone_uid);
        self.policy_revision = Some(policy_revision);
    }

    pub(crate) fn set_target_scope(
        &mut self,
        target_owner_ref: Option<ResourceRef>,
        target_ref: Option<ResourceRef>,
    ) {
        self.target_owner_ref = target_owner_ref;
        self.target_ref = target_ref;
    }

    pub(crate) fn set_guest_descriptor_digests(
        &mut self,
        descriptors: BTreeMap<ResourceRef, SchemaFingerprint>,
    ) {
        self.guest_descriptor_digests = descriptors;
    }

    pub(crate) fn set_owner_uids(&mut self, owner_uids: BTreeMap<ResourceRef, ResourceUid>) {
        self.owner_uids = owner_uids;
    }

    pub(crate) fn set_status_client<C>(&mut self, status_client: Arc<C>)
    where
        C: ProcessResourceClient + 'static,
    {
        self.status_client = Some(status_client);
    }

    pub(crate) fn set_liveness_waker(
        &mut self,
        liveness_waker: Arc<dyn Fn(ResourceKey, ZoneRevision) + Send + Sync>,
    ) {
        self.liveness_waker = Some(liveness_waker);
    }

    fn without_status_client(&mut self) {
        self.status_client = None;
    }

    fn for_pass(&self) -> Self {
        Self {
            zone: self.zone.clone(),
            target: self.target.clone(),
            providers: Arc::clone(&self.providers),
            records: BTreeMap::new(),
            terminal: BTreeSet::new(),
            terminal_failed: BTreeSet::new(),
            restart_counts: BTreeMap::new(),
            started_at: BTreeMap::new(),
            completed_at: BTreeMap::new(),
            next_restart_at: BTreeMap::new(),
            controller_generation: self.controller_generation,
            controller_provider_identities: self.controller_provider_identities.clone(),
            guest_execution: self.guest_execution.clone(),
            zone_uid: self.zone_uid.clone(),
            policy_revision: self.policy_revision,
            target_owner_ref: self.target_owner_ref.clone(),
            target_ref: self.target_ref.clone(),
            guest_descriptor_digests: self.guest_descriptor_digests.clone(),
            owner_uids: self.owner_uids.clone(),
            status_client: self.status_client.clone(),
            liveness_waker: self.liveness_waker.clone(),
            last_adopted: None,
        }
    }

    fn last_adopted(&self) -> Option<bool> {
        self.last_adopted
    }

    fn context<'a>(&self, record: &'a DesiredRecord) -> ProcessResourceContext<'a> {
        let target_ref = scoped_target_ref(
            record,
            self.target_owner_ref.as_ref(),
            self.target_ref.as_ref(),
        );
        let owner_ref = record.owner_ref();
        ProcessResourceContext::new(
            self.zone.clone(),
            &record.resource.resource_ref,
            &record.resource.uid,
            record.resource.generation,
            record.resource.revision,
            &record.provider_ref,
            self.controller_generation,
            target_ref,
        )
        .with_guest_execution(self.guest_execution.as_ref())
        .with_lifecycle_identity(
            self.zone_uid.clone(),
            self.policy_revision,
            self.guest_execution
                .as_ref()
                .map(GuestExecutionBinding::provider_generation),
        )
        .with_owner_ref(owner_ref.clone())
        .with_owner_uid(
            owner_ref
                .as_ref()
                .and_then(|owner| self.owner_uids.get(owner))
                .cloned(),
        )
        .with_guest_descriptor_digest(
            owner_ref
                .as_ref()
                .and_then(|owner| self.guest_descriptor_digests.get(owner)),
        )
        .with_provider_identity(
            record.controller_provider_uid.as_ref(),
            record.controller_provider_generation,
        )
    }

    /// Reconcile a complete durable Process/EphemeralProcess snapshot.
    pub(crate) async fn reconcile(
        &mut self,
        snapshot: Vec<StoredResource>,
    ) -> Result<(), ProcessResourceRuntimeError> {
        let mut desired = decode_snapshot(
            &self.zone,
            self.target.as_ref(),
            snapshot,
            self.providers.mode(),
        )?;
        let provider_assignment_generation = self
            .guest_execution
            .as_ref()
            .map(GuestExecutionBinding::provider_generation);
        for record in desired.values_mut() {
            record.zone_uid = self.zone_uid.clone();
            record.policy_revision = self.policy_revision;
            record.provider_assignment_generation = provider_assignment_generation;
            self.restart_counts
                .entry(record.resource.resource_ref.clone())
                .or_insert_with(|| persisted_restart_count(&record.resource, &record.process));
        }
        let desired_keys = desired.keys().cloned().collect::<BTreeSet<_>>();
        let removed = self
            .records
            .keys()
            .filter(|key| !desired_keys.contains(*key))
            .cloned()
            .collect::<Vec<_>>();
        for key in removed {
            if let Some(record) = self.records.get(&key).cloned() {
                self.stop_record(&record).await?;
                self.records.remove(&key);
            }

            self.terminal.remove(&key);
            self.terminal_failed.remove(&key);
            self.restart_counts.remove(&key);
            self.started_at.remove(&key);
            self.completed_at.remove(&key);
            self.next_restart_at.remove(&key);
        }

        let mut desired = desired.into_values().collect::<Vec<_>>();
        desired.sort_by_key(|record| {
            (
                ProcessSchedulingClass::classify(
                    record.deletion_requested(),
                    is_static_controller(record),
                )
                .rank(),
                record.key(),
            )
        });
        for mut record in desired {
            let key = record.resource.resource_ref.clone();
            let provider_identity_ref = if is_static_controller(&record) {
                record
                    .owner_ref()
                    .filter(|owner| owner.resource_type().as_str() == "Provider")
            } else {
                Some(record.provider_ref.clone())
            };
            let provider_identity = provider_identity_ref
                .as_ref()
                .and_then(|provider| self.controller_provider_identities.get(provider).cloned());
            record.controller_provider_uid = provider_identity.as_ref().map(|(uid, _)| uid.clone());
            record.controller_provider_generation =
                provider_identity.map(|(_, generation)| generation);
            let was_present = self.records.contains_key(&key);
            let replace = self
                .records
                .get(&key)
                .is_some_and(|current| !current.same_desired_state(&record));
            if replace {
                if let Some(current) = self.records.get(&key).cloned() {
                    self.stop_record(&current).await.inspect_err(|error| {
                        tracing::warn!(
                            process = %key.name().as_str(),
                            error = ?error,
                            "Process replacement stop failed",
                        );
                    })?;
                    self.providers
                        .finalize_resource(self.context(&current))
                        .await
                        .inspect_err(|error| {
                            tracing::warn!(
                                process = %key.name().as_str(),
                                error,
                                "Process replacement finalization failed",
                            );
                        })
                        .map_err(map_provider_error)?;
                    self.records.remove(&key);
                }
                self.terminal.remove(&key);
                self.terminal_failed.remove(&key);
                self.restart_counts.remove(&key);
                self.started_at.remove(&key);
                self.completed_at.remove(&key);
                self.next_restart_at.remove(&key);
            }

            if !was_present
                && !replace
                && !self.providers.has_active_resource_in_zone(
                    &self.zone,
                    self.zone_uid.as_ref(),
                    &key,
                )
            {
                match status_phase(&record.resource) {
                    Some(ResourcePhase::Succeeded) => {
                        self.terminal.insert(key.clone());
                        self.completed_at.insert(key.clone(), Instant::now());
                    }
                    Some(ResourcePhase::Failed) => {
                        self.terminal.insert(key.clone());
                        self.terminal_failed.insert(key.clone());
                        self.completed_at.insert(key.clone(), Instant::now());
                    }
                    _ => {}
                }
            }

            if !record.deletion_requested()
                && !record.has_runtime_finalizer()
                && !self.terminal.contains(&key)
            {
                record = self.ensure_finalizer(&record).await?;
            }

            if record.deletion_requested() {
                if !self.providers.has_active_resource_in_zone(
                    &self.zone,
                    self.zone_uid.as_ref(),
                    &key,
                ) {
                    match &record.process {
                        DesiredProcess::Process(spec) => {
                            let adoption_result = self
                                .providers
                                .adopt_resource(self.context(&record), spec)
                                .await;
                            if let Err(error) = &adoption_result {
                                tracing::warn!(
                                    process = %record.resource.resource_ref,
                                    error,
                                    "Process deletion adoption failed",
                                );
                            }
                            let adoption = deletion_adoption(adoption_result)?;
                            if let Some(candidate) = stale_candidate_for_deletion(adoption)? {
                                let provider_ref = self.context(&record).provider_ref.clone();
                                self.providers
                                    .stop_stale_resource(&provider_ref, &candidate)
                                    .await
                                    .map_err(map_provider_error)?;
                            }
                        }
                        DesiredProcess::Ephemeral(spec) => {
                            let adoption = deletion_adoption(
                                self.providers
                                    .adopt_ephemeral_resource(self.context(&record), spec)
                                    .await,
                            )?;
                            if let Some(candidate) = stale_candidate_for_deletion(adoption)? {
                                let provider_ref = self.context(&record).provider_ref.clone();
                                self.providers
                                    .stop_stale_resource(&provider_ref, &candidate)
                                    .await
                                    .map_err(map_provider_error)?;
                            }
                        }
                    }
                }
                if self.providers.has_active_resource_in_zone(
                    &self.zone,
                    self.zone_uid.as_ref(),
                    &key,
                ) {
                    self.stop_record(&record).await?;
                }
                self.providers
                    .finalize_resource(self.context(&record))
                    .await
                    .inspect_err(|error| {
                        tracing::warn!(
                            process = %record.resource.resource_ref,
                            error,
                            "Process deletion provider finalization failed",
                        );
                    })
                    .map_err(map_provider_error)?;
                record = self
                    .publish_status(&record, ResourcePhase::Deleted, None)
                    .await?;
                record = self.remove_finalizer(&record).await.inspect_err(|error| {
                    tracing::warn!(
                        process = %record.resource.resource_ref,
                        error = ?error,
                        "Process deletion finalizer removal failed",
                    );
                })?;
                self.terminal.insert(key.clone());
                self.records.insert(key, record);
                continue;
            }

            if self.terminal.contains(&key) {
                if self.ephemeral_ttl_elapsed(&key, &record) {
                    self.request_delete(&record).await?;
                }
                self.records.insert(key, record);
                continue;
            }

            if let DesiredProcess::Ephemeral(spec) = &record.process
                && self.providers.has_active_resource_in_zone(
                    &self.zone,
                    self.zone_uid.as_ref(),
                    &key,
                )
                && self.started_at.get(&key).is_some_and(|started| {
                    started.elapsed() >= Duration::from_millis(spec.runtime_deadline().as_millis())
                })
            {
                self.stop_record(&record).await?;
                self.providers
                    .finalize_resource(self.context(&record))
                    .await
                    .map_err(map_provider_error)?;
                self.completed_at.insert(key.clone(), Instant::now());
                self.terminal_failed.insert(key.clone());
                self.terminal.insert(key.clone());
                record = self
                    .publish_status(
                        &record,
                        ResourcePhase::Failed,
                        Some(OutcomeState::failure(
                            "runtime-deadline",
                            "ephemeral process reached its runtime deadline",
                        )),
                    )
                    .await?;
                self.records.insert(key, record);
                continue;
            }

            if !record.is_running() {
                if self.providers.has_active_resource_in_zone(
                    &self.zone,
                    self.zone_uid.as_ref(),
                    &key,
                ) {
                    self.stop_record(&record).await?;
                    self.providers
                        .finalize_resource(self.context(&record))
                        .await
                        .map_err(map_provider_error)?;
                }
                record = self
                    .publish_status(&record, ResourcePhase::Succeeded, None)
                    .await?;
                self.records.insert(key.clone(), record);
                self.terminal.remove(&key);
                self.terminal_failed.remove(&key);
                self.restart_counts.remove(&key);
                self.started_at.remove(&key);
                self.completed_at.remove(&key);
                self.next_restart_at.remove(&key);
                continue;
            }

            if let Some(restart_at) = self.next_restart_at.get(&key).copied() {
                if Instant::now() < restart_at {
                    self.records.insert(key, record);
                    continue;
                }
                self.next_restart_at.remove(&key);
                match self.start_record(&record).await {
                    Ok(adopted) => {
                        self.last_adopted = Some(adopted);
                        self.started_at.insert(key.clone(), Instant::now());
                        record = self
                            .publish_status(
                                &record,
                                ResourcePhase::Ready,
                                Some(OutcomeState::ready(adopted)),
                            )
                            .await?;
                        self.records.insert(key, record);
                    }
                    Err(error) => {
                        if self.status_client.is_none() {
                            return Err(error);
                        }
                        self.handle_start_failure(key, record, error).await?;
                    }
                }
                continue;
            }

            if self
                .started_at
                .get(&key)
                .is_some_and(|started| restart_reset_due(&record.process, *started))
            {
                self.restart_counts.insert(key.clone(), 0);
            }

            if was_present && !replace {
                let liveness = if controller_requires_stop(
                    &record,
                    self.providers
                        .controller_bootstrap_present(&self.zone, &key),
                ) {
                    self.stop_record(&record).await?;
                    ProviderLiveness::Exited
                } else {
                    self.probe_record(&record).await?
                };
                match liveness {
                    ProviderLiveness::Alive => {}
                    ProviderLiveness::Unknown => {
                        self.terminal.insert(key.clone());
                        self.terminal_failed.insert(key.clone());
                        self.completed_at.insert(key.clone(), Instant::now());
                        record = self
                            .publish_status(
                                &record,
                                ResourcePhase::Failed,
                                Some(OutcomeState::failure(
                                    "identity-ambiguous",
                                    "provider identity could not be verified safely",
                                )),
                            )
                            .await?;
                        self.records.insert(key, record);
                    }
                    ProviderLiveness::Exited => {
                        self.providers
                            .finalize_resource(self.context(&record))
                            .await
                            .map_err(map_provider_error)?;
                        let restart = match &record.process {
                            DesiredProcess::Process(spec) => {
                                spec.restart_policy().class() != RestartClass::Never
                                    && spec.restart_policy().max_restarts().is_none_or(|max| {
                                        self.restart_counts.get(&key).copied().unwrap_or(0) < max
                                    })
                            }
                            DesiredProcess::Ephemeral(_) => false,
                        };
                        if restart {
                            let restart_count = self.restart_counts.entry(key.clone()).or_default();
                            *restart_count = restart_count.saturating_add(1);
                            let delay = restart_delay(&record.process, *restart_count);
                            self.next_restart_at
                                .insert(key.clone(), Instant::now() + delay);
                            record = self
                                .publish_status(
                                    &record,
                                    ResourcePhase::Degraded,
                                    Some(OutcomeState::retry(
                                        "process-exited",
                                        "process exited and is awaiting restart",
                                        delay,
                                    )),
                                )
                                .await?;
                            self.records.insert(key, record);
                        } else {
                            self.terminal.insert(key.clone());
                            self.completed_at.insert(key.clone(), Instant::now());
                            record = self
                                .publish_status(
                                    &record,
                                    ResourcePhase::Succeeded,
                                    Some(OutcomeState::success(
                                        "process-exited",
                                        "process reached a terminal exit",
                                    )),
                                )
                                .await?;
                            self.records.insert(key, record);
                        }
                    }
                }
                continue;
            }

            record = self
                .publish_status(&record, ResourcePhase::Pending, None)
                .await?;
            match self.start_record(&record).await {
                Ok(adopted) => {
                    self.last_adopted = Some(adopted);
                    self.started_at.insert(key.clone(), Instant::now());
                    record = self
                        .publish_status(
                            &record,
                            ResourcePhase::Ready,
                            Some(OutcomeState::ready(adopted)),
                        )
                        .await?;
                    self.records.insert(key, record);
                }
                Err(error) => {
                    if self.status_client.is_none() {
                        return Err(error);
                    }
                    self.handle_start_failure(key, record, error).await?;
                }
            }
        }
        Ok(())
    }

    async fn start_record(
        &self,
        record: &DesiredRecord,
    ) -> Result<bool, ProcessResourceRuntimeError> {
        if !controller_provider_identity_available(record) {
            self.stop_record(record).await?;
            return Err(ProcessResourceRuntimeError::ProviderIdentityUnavailable);
        }
        let adoption = match &record.process {
            DesiredProcess::Process(spec)
                if spec.adoption_policy()
                    == d2b_contracts_resource::v3::process::AdoptionPolicy::NeverAdopt =>
            {
                if self.providers.has_active_resource_in_zone(
                    &self.zone,
                    self.zone_uid.as_ref(),
                    &record.resource.resource_ref,
                ) {
                    self.stop_record(record).await?;
                    self.providers
                        .finalize_resource(self.context(record))
                        .await
                        .map_err(map_provider_error)?;
                }
                ProviderAdoption::Absent
            }
            DesiredProcess::Process(spec) => self
                .providers
                .adopt_resource(self.context(record), spec)
                .await
                .map_err(|error| {
                    tracing::warn!(
                        zone = %self.zone.as_str(),
                        resource_type = %record.key().resource_type().as_str(),
                        error = %error,
                        "Process Provider adoption probe failed",
                    );
                    map_provider_error(error)
                })?,
            DesiredProcess::Ephemeral(spec) => self
                .providers
                .adopt_ephemeral_resource(self.context(record), spec)
                .await
                .map_err(map_provider_error)?,
        };
        if let Some(plan) = start_record_plan(&adoption, &record.process)? {
            if plan.adopted {
                if let ProviderAdoption::Adopted(report) = &adoption {
                    self.register_liveness_waiter(record, report.identity)?;
                }
                return Ok(true);
            }
            let DesiredProcess::Process(spec) = &record.process else {
                unreachable!("controller bootstrap restart plan requires Process");
            };
            for effect in plan.effects {
                match effect {
                    StartRecordEffect::StopAndFinalize => {
                        // The Provider owns exact stop and finalization before
                        // the replacement launch can proceed.
                        self.providers
                            .stop_resource(
                                self.context(record),
                                spec,
                                process_drain_timeout(spec),
                                Duration::from_secs(30),
                            )
                            .await
                            .map_err(map_provider_error)?;
                    }
                    StartRecordEffect::Launch => {
                        self.launch_record(record).await?;
                    }
                }
            }
            return Ok(false);
        }
        match adoption {
            ProviderAdoption::Adopted(_) | ProviderAdoption::ControllerBootstrapMissing => {
                unreachable!("handled by start record plan")
            }
            ProviderAdoption::Quarantined(_) => Err(ProcessResourceRuntimeError::IdentityAmbiguous),
            ProviderAdoption::Stale { candidate } => {
                let provider_ref = self.context(record).provider_ref.clone();
                self.providers
                    .stop_stale_resource(&provider_ref, &candidate)
                    .await
                    .map_err(map_provider_error)?;
                self.launch_record(record).await?;
                Ok(false)
            }
            ProviderAdoption::Absent => {
                self.launch_record(record).await?;
                Ok(false)
            }
        }
    }

    async fn launch_record(
        &self,
        record: &DesiredRecord,
    ) -> Result<d2b_process_conformance::ProcessIdentityDigest, ProcessResourceRuntimeError> {
        if is_static_controller(record)
            && (record.controller_provider_uid.is_none()
                || record.controller_provider_generation.is_none())
        {
            return Err(ProcessResourceRuntimeError::ProviderIdentityUnavailable);
        }
        let launch = match &record.process {
            DesiredProcess::Process(spec) => self
                .providers
                .launch_resource(self.context(record), spec, launch_timeout(&record.process))
                .await
                .map_err(|error| {
                    tracing::warn!(
                        zone = %self.zone.as_str(),
                        resource_type = %record.key().resource_type().as_str(),
                        error = %error,
                        "Process Provider launch failed",
                    );
                    map_provider_error(error)
                })?,
            DesiredProcess::Ephemeral(spec) => self
                .providers
                .launch_ephemeral_resource(
                    self.context(record),
                    spec,
                    launch_timeout(&record.process),
                )
                .await
                .map_err(map_provider_error)?,
        };
        self.register_liveness_waiter(record, launch.identity)?;
        Ok(launch.identity)
    }

    fn register_liveness_waiter(
        &self,
        record: &DesiredRecord,
        identity: d2b_process_conformance::ProcessIdentityDigest,
    ) -> Result<(), ProcessResourceRuntimeError> {
        let Some(waker) = self.liveness_waker.clone() else {
            return Ok(());
        };
        self.providers
            .spawn_resource_waiter(&self.context(record), identity, waker)
            .map_err(|_| ProcessResourceRuntimeError::ProviderEffect)
    }

    async fn handle_start_failure(
        &mut self,
        key: ResourceRef,
        mut record: DesiredRecord,
        error: ProcessResourceRuntimeError,
    ) -> Result<(), ProcessResourceRuntimeError> {
        let identity_failure = matches!(
            error,
            ProcessResourceRuntimeError::IdentityAmbiguous
                | ProcessResourceRuntimeError::ProviderIdentityUnavailable
                | ProcessResourceRuntimeError::TemplateUnavailable
        );
        let restart = !identity_failure
            && matches!(
                &record.process,
                DesiredProcess::Process(spec)
                    if spec.restart_policy().class() != RestartClass::Never
                        && spec.restart_policy().max_restarts().is_none_or(|max| {
                            self.restart_counts.get(&key).copied().unwrap_or(0) < max
                        })
            );
        if restart {
            let restart_count = self.restart_counts.entry(key.clone()).or_default();
            *restart_count = restart_count.saturating_add(1);
            let delay = restart_delay(&record.process, *restart_count);
            self.next_restart_at
                .insert(key.clone(), Instant::now() + delay);
            record = self
                .publish_status(
                    &record,
                    ResourcePhase::Degraded,
                    Some(OutcomeState::retry(
                        "provider-start-failed",
                        "provider failed to start the process",
                        delay,
                    )),
                )
                .await?;
        } else {
            self.terminal.insert(key.clone());
            self.terminal_failed.insert(key.clone());
            self.completed_at.insert(key.clone(), Instant::now());
            record = self
                .publish_status(
                    &record,
                    ResourcePhase::Failed,
                    Some(OutcomeState::failure(
                        start_failure_code(error),
                        start_failure_message(error),
                    )),
                )
                .await?;
        }
        self.records.insert(key, record);
        Ok(())
    }

    async fn publish_status(
        &self,
        record: &DesiredRecord,
        phase: ResourcePhase,
        outcome: Option<OutcomeState>,
    ) -> Result<DesiredRecord, ProcessResourceRuntimeError> {
        let Some(client) = &self.status_client else {
            return Ok(record.clone());
        };
        update_status(
            client.as_ref(),
            record,
            phase,
            self.restart_counts
                .get(&record.resource.resource_ref)
                .copied()
                .unwrap_or(0),
            outcome,
        )
        .await
    }

    async fn ensure_finalizer(
        &self,
        record: &DesiredRecord,
    ) -> Result<DesiredRecord, ProcessResourceRuntimeError> {
        let Some(client) = &self.status_client else {
            return Ok(record.clone());
        };
        if record.has_runtime_finalizer() {
            return Ok(record.clone());
        }
        let finalizer =
            process_finalizer(&record.provider_ref).unwrap_or(PROCESS_RUNTIME_FINALIZER);
        update_finalizers(client.as_ref(), record, finalizer, true).await
    }

    async fn remove_finalizer(
        &self,
        record: &DesiredRecord,
    ) -> Result<DesiredRecord, ProcessResourceRuntimeError> {
        let Some(client) = &self.status_client else {
            return Ok(record.clone());
        };
        if !record.has_runtime_finalizer() {
            return Ok(record.clone());
        }
        let finalizer = active_process_finalizer(record).unwrap_or_else(|| {
            process_finalizer(&record.provider_ref).unwrap_or(PROCESS_RUNTIME_FINALIZER)
        });
        update_finalizers(client.as_ref(), record, finalizer, false).await
    }

    fn ephemeral_ttl_elapsed(&self, key: &ResourceRef, record: &DesiredRecord) -> bool {
        let DesiredProcess::Ephemeral(spec) = &record.process else {
            return false;
        };
        if self.status_client.is_none() {
            return false;
        }
        if self.terminal_failed.contains(key) && spec.incident_hold() {
            return false;
        }
        if ephemeral_status_ttl_elapsed(&record.resource, &record.process) {
            return true;
        }
        let Some(completed_at) = self.completed_at.get(key) else {
            return false;
        };
        let ttl = if self.terminal_failed.contains(key) {
            spec.failed_ttl().as_millis()
        } else {
            spec.successful_ttl().as_millis()
        };
        completed_at.elapsed() >= Duration::from_millis(ttl)
    }

    async fn request_delete(
        &self,
        record: &DesiredRecord,
    ) -> Result<(), ProcessResourceRuntimeError> {
        let Some(client) = &self.status_client else {
            return Ok(());
        };
        delete_resource(client.as_ref(), record).await
    }

    async fn observe_existing_record(
        &mut self,
        record: &DesiredRecord,
    ) -> Result<ProviderLiveness, ProcessResourceRuntimeError> {
        let adoption = match &record.process {
            DesiredProcess::Process(spec) => self
                .providers
                .adopt_resource(self.context(record), spec)
                .await
                .map_err(map_provider_error)?,
            DesiredProcess::Ephemeral(spec) => self
                .providers
                .adopt_ephemeral_resource(self.context(record), spec)
                .await
                .map_err(map_provider_error)?,
        };
        match adoption {
            ProviderAdoption::Adopted(report) => {
                self.last_adopted = Some(true);
                self.register_liveness_waiter(record, report.identity)?;
                Ok(ProviderLiveness::Alive)
            }
            ProviderAdoption::Absent => Ok(ProviderLiveness::Exited),
            ProviderAdoption::Stale { candidate } => {
                self.providers
                    .stop_stale_resource(&record.provider_ref, &candidate)
                    .await
                    .map_err(map_provider_error)?;
                Ok(ProviderLiveness::Exited)
            }
            ProviderAdoption::ControllerBootstrapMissing => {
                if matches!(&record.process, DesiredProcess::Process(_)) {
                    self.stop_record(record).await?;
                    self.providers
                        .finalize_resource(self.context(record))
                        .await
                        .map_err(map_provider_error)?;
                }
                Ok(ProviderLiveness::Exited)
            }
            ProviderAdoption::Quarantined(_) => Ok(ProviderLiveness::Unknown),
        }
    }

    async fn probe_record(
        &self,
        record: &DesiredRecord,
    ) -> Result<ProviderLiveness, ProcessResourceRuntimeError> {
        let liveness = match &record.process {
            DesiredProcess::Process(spec) => self
                .providers
                .probe_resource(self.context(record), spec)
                .await
                .map_err(map_provider_error)?,
            DesiredProcess::Ephemeral(spec) => self
                .providers
                .probe_ephemeral_resource(self.context(record), spec)
                .await
                .map_err(map_provider_error)?,
        };
        Ok(liveness)
    }

    async fn stop_record(&self, record: &DesiredRecord) -> Result<(), ProcessResourceRuntimeError> {
        if !self.providers.has_active_resource_in_zone(
            &self.zone,
            self.zone_uid.as_ref(),
            &record.resource.resource_ref,
        ) {
            return Ok(());
        }
        match &record.process {
            DesiredProcess::Process(spec) => self
                .providers
                .stop_resource(
                    self.context(record),
                    spec,
                    process_drain_timeout(spec),
                    Duration::from_secs(30),
                )
                .await
                .map_err(map_provider_error)?,
            DesiredProcess::Ephemeral(spec) => self
                .providers
                .stop_ephemeral_resource(
                    self.context(record),
                    spec,
                    Duration::from_secs(30),
                    Duration::from_secs(30),
                )
                .await
                .map_err(map_provider_error)?,
        };
        Ok(())
    }
}

/// Build the one shared descriptor for the Process Provider family.
pub(crate) fn process_controller_descriptor(
    identity: ControllerIdentity,
) -> Result<ControllerDescriptor, ProcessResourceRuntimeError> {
    let process = ResourceTypeName::parse(PROCESS_TYPE)
        .map_err(|_| ProcessResourceRuntimeError::InvalidResource)?;
    let ephemeral = ResourceTypeName::parse(EPHEMERAL_PROCESS_TYPE)
        .map_err(|_| ProcessResourceRuntimeError::InvalidResource)?;
    let resources = vec![
        ResourceRegistration::new(process.clone(), vec![1], 5_000, 3)
            .map_err(|_| ProcessResourceRuntimeError::InvalidResource)?,
        ResourceRegistration::new(ephemeral.clone(), vec![1], 5_000, 3)
            .map_err(|_| ProcessResourceRuntimeError::InvalidResource)?,
    ];
    let selectors = [process, ephemeral]
        .into_iter()
        .flat_map(|resource_type| {
            [
                SelectorField::Spec,
                SelectorField::Status,
                SelectorField::Metadata,
                SelectorField::Finalizers,
                SelectorField::Deletion,
            ]
            .into_iter()
            .map(move |field| ControllerSelector::new(resource_type.clone(), field, None))
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ProcessResourceRuntimeError::InvalidResource)?;
    let dependency_selectors = [PROCESS_TYPE, EPHEMERAL_PROCESS_TYPE]
        .into_iter()
        .map(|resource_type| {
            ControllerSelector::new(
                ResourceTypeName::parse(resource_type).expect("static Process resource type"),
                SelectorField::Metadata,
                None,
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ProcessResourceRuntimeError::InvalidResource)?;
    ControllerDescriptor::new(
        identity,
        resources,
        vec!["process".to_owned()],
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
        false,
        Vec::new(),
        vec!["d2b.process.v3".to_owned()],
        vec!["resources.d2bus.org/v3".to_owned()],
        ControllerExecutionPolicy::new(
            8,
            8,
            256,
            8,
            256,
            ResyncPolicy::new(None, 5_000)
                .map_err(|_| ProcessResourceRuntimeError::InvalidResource)?,
        )
        .map_err(|_| ProcessResourceRuntimeError::InvalidResource)?,
    )
    .map_err(|_| ProcessResourceRuntimeError::InvalidResource)
}

/// Typed Process/EphemeralProcess handler hosted by the shared Runner.
pub(crate) struct ProcessResourceReconciler {
    descriptor: ControllerDescriptor,
    runtime: Arc<ProcessResourceRuntime>,
}

impl std::fmt::Debug for ProcessResourceReconciler {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProcessResourceReconciler")
            .field("descriptor", &self.descriptor)
            .finish()
    }
}

impl ProcessResourceReconciler {
    /// Bind one Process Provider family handler to the daemon's effect ports.
    pub(crate) fn new(
        descriptor: ControllerDescriptor,
        runtime: ProcessResourceRuntime,
    ) -> Arc<Self> {
        Arc::new(Self {
            descriptor,
            runtime: Arc::new(runtime),
        })
    }

    fn stored_resource(
        &self,
        resource: &ResourceSnapshot,
    ) -> Result<StoredResource, ProcessResourceRuntimeError> {
        let envelope = ResourceEnvelope::from_json(resource.canonical_json())
            .map_err(|_| ProcessResourceRuntimeError::InvalidResource)?;
        let payload_digest = envelope
            .digest()
            .map_err(|_| ProcessResourceRuntimeError::InvalidResource)?;
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

    fn desired(
        &self,
        resource: &ResourceSnapshot,
    ) -> Result<Option<(StoredResource, ResourceRef, DesiredProcess)>, ProcessResourceRuntimeError>
    {
        if !matches!(
            resource.key().resource_ref().resource_type().as_str(),
            PROCESS_TYPE | EPHEMERAL_PROCESS_TYPE
        ) {
            return Err(ProcessResourceRuntimeError::InvalidResource);
        }
        let stored = self.stored_resource(resource)?;
        let envelope = ResourceEnvelope::from_json(resource.canonical_json())
            .map_err(|_| ProcessResourceRuntimeError::InvalidResource)?;
        let provider_ref = envelope
            .spec()
            .provider_ref()
            .cloned()
            .ok_or(ProcessResourceRuntimeError::InvalidResource)?;
        if provider_ref.resource_type().as_str() != "Provider" {
            return Err(ProcessResourceRuntimeError::InvalidResource);
        }
        if !matches!(
            provider_ref.name().as_str(),
            MINIJAIL_PROVIDER | SYSTEMD_PROVIDER
        ) {
            return Err(ProcessResourceRuntimeError::UnsupportedProvider);
        }
        let execution_ref = envelope
            .spec()
            .base()
            .get("executionRef")
            .and_then(|value| match value {
                CanonicalJsonValue::String(value) => ResourceRef::parse(value).ok(),
                _ => None,
            })
            .ok_or(ProcessResourceRuntimeError::InvalidResource)?;
        let target_matches = if let Some(target) = self.runtime.target.as_ref() {
            execution_ref == *target
        } else {
            execution_ref.resource_type().as_str() == "Host"
        };
        if !target_matches
            || !execution_target_allowed(self.runtime.providers.mode(), &execution_ref)
        {
            return Ok(None);
        }
        let process = match resource.key().resource_ref().resource_type().as_str() {
            PROCESS_TYPE => DesiredProcess::Process(
                serde_json::from_slice(&envelope.spec().base().to_canonical_bytes())
                    .map_err(|_| ProcessResourceRuntimeError::InvalidResource)?,
            ),
            EPHEMERAL_PROCESS_TYPE => DesiredProcess::Ephemeral(
                serde_json::from_slice(&envelope.spec().base().to_canonical_bytes())
                    .map_err(|_| ProcessResourceRuntimeError::InvalidResource)?,
            ),
            _ => unreachable!("resource type was checked above"),
        };
        Ok(Some((stored, provider_ref, process)))
    }

    fn desired_record(
        &self,
        resource: &ResourceSnapshot,
    ) -> Result<Option<DesiredRecord>, ProcessResourceRuntimeError> {
        let Some((stored, provider_ref, process)) = self.desired(resource)? else {
            return Ok(None);
        };
        let provider_identity_ref = if is_static_controller_from_resource(&stored, &process) {
            metadata_owner_ref_for_resource(&stored)
        } else {
            Some(provider_ref.clone())
        };
        let provider_identity = provider_identity_ref
            .as_ref()
            .and_then(|provider| self.runtime.controller_provider_identities.get(provider))
            .cloned();
        Ok(Some(DesiredRecord {
            resource: stored,
            provider_ref,
            process,
            zone_uid: self.runtime.zone_uid.clone(),
            policy_revision: self.runtime.policy_revision,
            provider_assignment_generation: self
                .runtime
                .guest_execution
                .as_ref()
                .map(GuestExecutionBinding::provider_generation),
            controller_provider_uid: provider_identity.as_ref().map(|(uid, _)| uid.clone()),
            controller_provider_generation: provider_identity.map(|(_, generation)| generation),
        }))
    }

    fn no_op(&self) -> ReconcilePlan {
        ReconcilePlan::new(Vec::new(), true).expect("empty Process plan is bounded")
    }

    fn effect_plan(&self, stored: &StoredResource) -> ReconcilePlan {
        ReconcilePlan::new(vec![lifecycle_effect_id(stored)], false)
            .expect("Process effect plan is bounded")
    }

    fn observation_plan(&self) -> ReconcilePlan {
        ReconcilePlan::new(Vec::new(), false)
            .expect("Process observation plan is bounded")
    }

    fn observation_required(
        &self,
        stored: &StoredResource,
    ) -> bool {
        status_phase(stored) == Some(ResourcePhase::Ready)
            && status_observed_generation(stored) == Some(stored.generation)
            && status_has_started_at(stored)
    }

    fn needs_effect(
        &self,
        stored: &StoredResource,
        provider_ref: &ResourceRef,
        process: &DesiredProcess,
        retry_due: bool,
    ) -> bool {
        let key = &stored.resource_ref;
        let running = match process {
            DesiredProcess::Process(spec) => {
                spec.desired_lifecycle()
                    == d2b_contracts_resource::v3::process::DesiredLifecycle::Running
            }
            DesiredProcess::Ephemeral(_) => true,
        };
        if !running {
            return self.runtime.providers.has_active_resource_in_zone(
                &self.runtime.zone,
                self.runtime.zone_uid.as_ref(),
                key,
            );
        }
        let phase = status_phase(stored);
        let observed_generation = status_observed_generation(stored);
        let active = self.runtime.providers.has_active_resource_in_zone(
            &self.runtime.zone,
            self.runtime.zone_uid.as_ref(),
            key,
        );
        if matches!(
            phase,
            Some(ResourcePhase::Succeeded | ResourcePhase::Failed)
        ) {
            return false;
        }
        if phase == Some(ResourcePhase::Degraded) && !retry_due && !status_retry_due(stored) {
            return false;
        }
        if matches!(process, DesiredProcess::Ephemeral(_))
            && matches!(
                phase,
                Some(ResourcePhase::Succeeded | ResourcePhase::Failed)
            )
            && !ephemeral_status_ttl_elapsed(stored, process)
        {
            return false;
        }
        !active
            || observed_generation != Some(stored.generation)
            || !matches!(phase, Some(ResourcePhase::Ready))
            || active_process_finalizer_for_values(stored, provider_ref).is_none()
    }

    async fn observe_liveness(
        &self,
        context: &ReconcileContext,
        resource: &ResourceSnapshot,
    ) -> Result<ReconcileResult, ProcessResourceRuntimeError> {
        let Some(record) = self.desired_record(resource)? else {
            return Ok(ReconcileResult::converged(
                resource.revision(),
                resource.generation(),
            ));
        };
        let mut runtime = self.runtime.for_pass();
        runtime.without_status_client();
        match runtime.observe_existing_record(&record).await? {
            ProviderLiveness::Alive => Ok(ReconcileResult::converged(
                resource.revision(),
                resource.generation(),
            )),
            ProviderLiveness::Unknown => {
                let canonical = status_payload(
                    &record,
                    ResourcePhase::Failed,
                    persisted_restart_count(&record.resource, &record.process),
                    Some(OutcomeState::failure(
                        "identity-ambiguous",
                        "provider identity could not be verified safely",
                    )),
                )?;
                let status = status_candidate_from_resource(&canonical)?;
                ReconcileResult::new(
                    resource.revision(),
                    resource.generation(),
                    None,
                    Some(status),
                    ReconcileDisposition::Pending,
                    None,
                    None,
                    StatusPersistence::Pending,
                )
                .map_err(|_| ProcessResourceRuntimeError::InvalidResource)
            }
            ProviderLiveness::Exited => {
                let restart_count =
                    persisted_restart_count(&record.resource, &record.process);
                let (phase, outcome, next_tick) = match &record.process {
                    DesiredProcess::Ephemeral(_) => (
                        ResourcePhase::Succeeded,
                        OutcomeState::success(
                            "process-exited",
                            "ephemeral process reached a terminal exit",
                        ),
                        None,
                    ),
                    DesiredProcess::Process(_) if process_restart_allowed(
                        &record.process,
                        restart_count,
                    ) =>
                    {
                        let next_restart_count = restart_count.saturating_add(1);
                        let delay = restart_delay(&record.process, next_restart_count);
                        let delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);
                        (
                            ResourcePhase::Degraded,
                            OutcomeState::retry(
                                "process-exited",
                                "process exited and is awaiting restart",
                                delay,
                            ),
                            Some(context.now_tick().saturating_add(delay_ms)),
                        )
                    }
                    DesiredProcess::Process(_) => (
                        ResourcePhase::Succeeded,
                        OutcomeState::success(
                            "process-exited",
                            "process reached a terminal exit",
                        ),
                        None,
                    ),
                };
                let restart_count = if phase == ResourcePhase::Degraded {
                    restart_count.saturating_add(1)
                } else {
                    restart_count
                };
                let canonical =
                    status_payload(&record, phase, restart_count, Some(outcome))?;
                let status = status_candidate_from_resource(&canonical)?;
                ReconcileResult::new(
                    resource.revision(),
                    resource.generation(),
                    None,
                    Some(status),
                    if next_tick.is_some() {
                        ReconcileDisposition::RequeueAt
                    } else {
                        ReconcileDisposition::Pending
                    },
                    next_tick,
                    None,
                    StatusPersistence::Pending,
                )
                .map_err(|_| ProcessResourceRuntimeError::InvalidResource)
            }
        }
    }
}

impl ResourceReconciler for ProcessResourceReconciler {
    type Error = ProcessResourceRuntimeError;

    fn classify_error(&self, error: &Self::Error) -> d2b_core_controller::HandlerFailure {
        match error {
            ProcessResourceRuntimeError::InvalidResource
            | ProcessResourceRuntimeError::UnsupportedProvider => {
                d2b_core_controller::HandlerFailure::terminal()
            }
            _ => d2b_core_controller::HandlerFailure::retryable(),
        }
    }

    fn describe(&self) -> impl Future<Output = Result<ControllerDescriptor, Self::Error>> + Send {
        std::future::ready(Ok(self.descriptor.clone()))
    }

    fn validate_spec(
        &self,
        _context: &ReconcileContext,
        resource: &ResourceSnapshot,
    ) -> impl Future<Output = Result<ValidationResult, Self::Error>> + Send {
        std::future::ready(
            self.desired(resource)
                .map(|_| ValidationResult::Valid)
                .or_else(|_| {
                    Ok(ValidationResult::Invalid {
                        reason: ReconcileReason::InvalidSpec,
                    })
                }),
        )
    }

    async fn plan(
        &self,
        context: &ReconcileContext,
        resource: &ResourceSnapshot,
        dependencies: &[DependencySnapshot],
    ) -> Result<ReconcilePlan, Self::Error> {
        let Some((stored, provider_ref, process)) = self.desired(resource)? else {
            return Ok(self.no_op());
        };
        if active_process_finalizer_for_values(&stored, &provider_ref).is_none() {
            return Ok(ReconcilePlan::new(Vec::new(), false)
                .expect("finalizer enrollment plan is bounded"));
        }
        if static_controller_waits_for_workload_cleanup(resource, dependencies) {
            return Ok(self.no_op());
        }
        if matches!(process, DesiredProcess::Ephemeral(_))
            && matches!(
                status_phase(&stored),
                Some(ResourcePhase::Succeeded | ResourcePhase::Failed)
            )
            && ephemeral_status_ttl_elapsed(&stored, &process)
        {
            return Ok(
                ReconcilePlan::new(Vec::new(), false).expect("ephemeral cleanup plan is bounded")
            );
        }
        if self.observation_required(&stored) {
            return Ok(self.observation_plan());
        }
        if !self.needs_effect(
            &stored,
            &provider_ref,
            &process,
            context.reasons().contains(CoreTriggerReason::RetryDue),
        ) {
            return Ok(self.no_op());
        }
        Ok(self.effect_plan(&stored))
    }

    fn reconcile(
        &self,
        context: &ReconcileContext,
        resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
        _plan: &ReconcilePlan,
    ) -> impl Future<Output = Result<ReconcileResult, Self::Error>> + Send {
        let result = async {
            let Some((stored, provider_ref, process)) = self.desired(resource)? else {
                return Ok(ReconcileResult::converged(
                    resource.revision(),
                    resource.generation(),
                ));
            };
            if active_process_finalizer_for_values(&stored, &provider_ref).is_none() {
                let finalizer =
                    process_finalizer(&provider_ref).unwrap_or(PROCESS_RUNTIME_FINALIZER);
                let canonical = finalizer_candidate(resource.canonical_json(), finalizer, true)?;
                let mutation = d2b_core_controller::MutationIntent::new(
                    resource.key().resource_ref().clone(),
                    Some(resource.key().uid().clone()),
                    Some(resource.revision()),
                    d2b_core_controller::MutationIntentKind::UpdateFinalizers,
                    Some(canonical),
                )
                .map_err(|_| ProcessResourceRuntimeError::InvalidResource)?;
                let batch = ResourceMutationBatch::new(vec![mutation])
                    .map_err(|_| ProcessResourceRuntimeError::InvalidResource)?;
                return ReconcileResult::new(
                    resource.revision(),
                    resource.generation(),
                    Some(batch),
                    None,
                    ReconcileDisposition::Pending,
                    None,
                    None,
                    StatusPersistence::NotRequested,
                )
                .map_err(|_| ProcessResourceRuntimeError::InvalidResource);
            }
            if matches!(process, DesiredProcess::Ephemeral(_))
                && matches!(
                    status_phase(&stored),
                    Some(ResourcePhase::Succeeded | ResourcePhase::Failed)
                )
                && ephemeral_status_ttl_elapsed(&stored, &process)
            {
                let mutation = d2b_core_controller::MutationIntent::new(
                    resource.key().resource_ref().clone(),
                    Some(resource.key().uid().clone()),
                    Some(resource.revision()),
                    d2b_core_controller::MutationIntentKind::Delete,
                    None,
                )
                .map_err(|_| ProcessResourceRuntimeError::InvalidResource)?;
                let batch = ResourceMutationBatch::new(vec![mutation])
                    .map_err(|_| ProcessResourceRuntimeError::InvalidResource)?;
                return ReconcileResult::new(
                    resource.revision(),
                    resource.generation(),
                    Some(batch),
                    None,
                    ReconcileDisposition::Pending,
                    None,
                    None,
                    StatusPersistence::NotRequested,
                )
                .map_err(|_| ProcessResourceRuntimeError::InvalidResource);
            }
            if self.observation_required(&stored) {
                return self.observe_liveness(context, resource).await;
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
        _context: &ReconcileContext,
        resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
        _plan: &ReconcilePlan,
    ) -> impl Future<Output = Result<ReconcileResult, Self::Error>> + Send {
        let result = async {
            let Some(record) = self.desired_record(resource)? else {
                return Ok(ReconcileResult::converged(
                    resource.revision(),
                    resource.generation(),
                ));
            };
            let mut runtime = self.runtime.for_pass();
            runtime.without_status_client();
            runtime.reconcile(vec![record.resource.clone()]).await?;
            let adopted = runtime.last_adopted().unwrap_or(false);
            let active = runtime.providers.has_active_resource_in_zone(
                &runtime.zone,
                runtime.zone_uid.as_ref(),
                &record.resource.resource_ref,
            );
            let restart_count = runtime
                .restart_counts
                .get(&record.resource.resource_ref)
                .copied()
                .unwrap_or_else(|| persisted_restart_count(&record.resource, &record.process));
            let (phase, outcome) = match &record.process {
                DesiredProcess::Process(spec)
                    if spec.desired_lifecycle()
                        == d2b_contracts_resource::v3::process::DesiredLifecycle::Stopped =>
                {
                    (
                        ResourcePhase::Succeeded,
                        OutcomeState::success("process-stopped", "process lifecycle is stopped"),
                    )
                }
                DesiredProcess::Ephemeral(_) if !active => (
                    ResourcePhase::Succeeded,
                    OutcomeState::success(
                        "process-exited",
                        "ephemeral process reached a terminal exit",
                    ),
                ),
                _ if active => (ResourcePhase::Ready, OutcomeState::ready(adopted)),
                _ => (
                    ResourcePhase::Failed,
                    OutcomeState::failure(
                        "provider-start-failed",
                        "the Provider did not retain a verified process identity",
                    ),
                ),
            };
            let canonical = status_payload(&record, phase, restart_count, Some(outcome))?;
            let status = status_candidate_from_resource(&canonical)?;
            ReconcileResult::new(
                resource.revision(),
                resource.generation(),
                None,
                Some(status),
                ReconcileDisposition::Pending,
                None,
                None,
                StatusPersistence::Pending,
            )
            .map_err(|_| ProcessResourceRuntimeError::InvalidResource)
        };
        result
    }

    fn observe(
        &self,
        context: &ReconcileContext,
        resource: &ResourceSnapshot,
    ) -> impl Future<Output = Result<ObservationResult, Self::Error>> + Send {
        let result = async {
            Ok(ObservationResult::new(
                self.observe_liveness(context, resource).await?,
            ))
        };
        result
    }

    fn finalize(
        &self,
        _context: &ReconcileContext,
        resource: &ResourceSnapshot,
    ) -> impl Future<Output = Result<FinalizeResult, Self::Error>> + Send {
        std::future::ready(Ok(FinalizeResult::new(ReconcileResult::converged(
            resource.revision(),
            resource.generation(),
        ))))
    }

    fn prepare_finalize(
        &self,
        _context: &ReconcileContext,
        resource: &ResourceSnapshot,
    ) -> impl Future<Output = Result<ReconcileResult, Self::Error>> + Send {
        std::future::ready(Ok(ReconcileResult::converged(
            resource.revision(),
            resource.generation(),
        )))
    }

    fn execute_finalize(
        &self,
        _context: &ReconcileContext,
        resource: &ResourceSnapshot,
    ) -> impl Future<Output = Result<ReconcileResult, Self::Error>> + Send {
        let result = async {
            if resource.canonical_json().is_empty() {
                return Ok(ReconcileResult::converged(
                    resource.revision(),
                    resource.generation(),
                ));
            }
            let Some(record) = self.desired_record(resource)? else {
                return Ok(ReconcileResult::converged(
                    resource.revision(),
                    resource.generation(),
                ));
            };
            let mut runtime = self.runtime.for_pass();
            runtime.without_status_client();
            runtime.reconcile(vec![record.resource.clone()]).await?;
            let Some(finalizer) =
                active_process_finalizer_for_values(&record.resource, &record.provider_ref)
            else {
                return Ok(ReconcileResult::converged(
                    resource.revision(),
                    resource.generation(),
                ));
            };
            let canonical = finalizer_candidate(resource.canonical_json(), finalizer, false)?;
            let mutation = d2b_core_controller::MutationIntent::new(
                resource.key().resource_ref().clone(),
                Some(resource.key().uid().clone()),
                Some(resource.revision()),
                MutationIntentKind::UpdateFinalizers,
                Some(canonical),
            )
            .map_err(|_| ProcessResourceRuntimeError::InvalidResource)?;
            let batch = ResourceMutationBatch::new(vec![mutation])
                .map_err(|_| ProcessResourceRuntimeError::InvalidResource)?;
            Ok(ReconcileResult::new(
                resource.revision(),
                resource.generation(),
                Some(batch),
                None,
                ReconcileDisposition::Finalized,
                None,
                None,
                StatusPersistence::NotRequested,
            )
            .map_err(|_| ProcessResourceRuntimeError::InvalidResource)?)
        };
        result
    }

    fn health(
        &self,
    ) -> impl Future<Output = Result<d2b_core_controller::ControllerHealth, Self::Error>> + Send
    {
        std::future::ready(Ok(d2b_core_controller::ControllerHealth::Healthy))
    }

    fn drain(
        &self,
        _deadline_tick: u64,
    ) -> impl Future<Output = Result<DrainResult, Self::Error>> + Send {
        std::future::ready(Ok(DrainResult::Drained))
    }

    fn assess_update(
        &self,
        _context: &ReconcileContext,
        _resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
    ) -> impl Future<Output = Result<UpdateAssessment, Self::Error>> + Send {
        std::future::ready(
            UpdateAssessment::new(UpdateAssessmentState::Current, Vec::new(), true)
                .map_err(|_| ProcessResourceRuntimeError::InvalidResource),
        )
    }

    fn plan_upgrade(
        &self,
        _context: &ReconcileContext,
        resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
    ) -> impl Future<Output = Result<UpgradePlan, Self::Error>> + Send {
        std::future::ready(
            UpgradePlan::new(
                d2b_core_controller::DisruptionClass::None,
                true,
                vec![d2b_core_controller::UpgradeStage::Recycle(
                    resource.key().resource_ref().clone(),
                )],
            )
            .map_err(|_| ProcessResourceRuntimeError::InvalidResource),
        )
    }

    fn execute_upgrade(
        &self,
        _context: &ReconcileContext,
        resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
        _plan: &UpgradePlan,
    ) -> impl Future<Output = Result<ReconcileResult, Self::Error>> + Send {
        std::future::ready(Ok(ReconcileResult::converged(
            resource.revision(),
            resource.generation(),
        )))
    }
}

fn static_controller_waits_for_workload_cleanup(
    resource: &ResourceSnapshot,
    dependencies: &[DependencySnapshot],
) -> bool {
    if !snapshot_is_static_controller(resource) {
        return false;
    }
    dependencies.iter().any(|dependency| {
        let resource = dependency.resource();
        matches!(
            resource.key().resource_ref().resource_type().as_str(),
            PROCESS_TYPE | EPHEMERAL_PROCESS_TYPE
        ) && resource.deleting()
            && !snapshot_is_static_controller(resource)
    })
}

fn snapshot_is_static_controller(resource: &ResourceSnapshot) -> bool {
    let Ok(envelope) = ResourceEnvelope::from_json(resource.canonical_json()) else {
        return false;
    };
    let Some(owner) = envelope.metadata().owner_ref() else {
        return false;
    };
    if owner.resource_type().as_str() != "Provider" {
        return false;
    }
    serde_json::from_slice::<ProcessSpec>(&envelope.spec().base().to_canonical_bytes())
        .ok()
        .is_some_and(|spec| {
            spec.execution().process_class()
                == d2b_contracts_resource::v3::process::ProcessClass::Controller
        })
}

fn is_static_controller_from_resource(
    resource: &StoredResource,
    process: &DesiredProcess,
) -> bool {
    let DesiredProcess::Process(spec) = process else {
        return false;
    };
    spec.execution().process_class()
        == d2b_contracts_resource::v3::process::ProcessClass::Controller
        && metadata_owner_ref_for_resource(resource)
            .is_some_and(|owner| owner.resource_type().as_str() == "Provider")
}

fn metadata_owner_ref_for_resource(resource: &StoredResource) -> Option<ResourceRef> {
    let value = metadata_value(resource, "ownerRef")?;
    let CanonicalJsonValue::String(value) = value else {
        return None;
    };
    ResourceRef::parse(&value).ok()
}

fn launch_timeout(process: &DesiredProcess) -> Duration {
    match process {
        DesiredProcess::Process(_) => Duration::from_secs(30),
        DesiredProcess::Ephemeral(spec) => Duration::from_millis(spec.start_deadline().as_millis()),
    }
}

fn process_drain_timeout(spec: &ProcessSpec) -> Duration {
    Duration::from_millis(spec.drain_timeout().as_millis())
}

#[derive(Debug, Clone)]
struct OutcomeState {
    code: &'static str,
    message: &'static str,
    retryable: bool,
    retry_after_ms: Option<u32>,
    adopted: Option<bool>,
}

impl OutcomeState {
    fn ready(adopted: bool) -> Self {
        Self {
            code: "process-ready",
            message: if adopted {
                "process was adopted by its Provider"
            } else {
                "process was launched by its Provider"
            },
            retryable: false,
            retry_after_ms: None,
            adopted: Some(adopted),
        }
    }

    fn success(code: &'static str, message: &'static str) -> Self {
        Self {
            code,
            message,
            retryable: false,
            retry_after_ms: None,
            adopted: None,
        }
    }

    fn failure(code: &'static str, message: &'static str) -> Self {
        Self {
            code,
            message,
            retryable: false,
            retry_after_ms: None,
            adopted: None,
        }
    }

    fn retry(code: &'static str, message: &'static str, delay: Duration) -> Self {
        let retry_after_ms = u32::try_from(delay.as_millis()).ok();
        Self {
            code,
            message,
            retryable: true,
            retry_after_ms,
            adopted: None,
        }
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

fn status_observed_generation(resource: &StoredResource) -> Option<ResourceGeneration> {
    let value = CanonicalJsonValue::parse(&resource.canonical_json).ok()?;
    let CanonicalJsonValue::Object(root) = value else {
        return None;
    };
    let CanonicalJsonValue::Object(status) = root.get("status")? else {
        return None;
    };
    let CanonicalJsonValue::Integer(generation) = status.get("observedGeneration")? else {
        return None;
    };
    u64::try_from(*generation)
        .ok()
        .and_then(|generation| ResourceGeneration::new(generation).ok())
}

fn status_has_started_at(resource: &StoredResource) -> bool {
    matches!(
        status_value(resource, "startedAt"),
        Some(CanonicalJsonValue::String(value)) if !value.is_empty()
    )
}

fn status_restart_count(resource: &StoredResource) -> u32 {
    let Some(CanonicalJsonValue::Object(value)) = status_value(resource, "resource") else {
        return 0;
    };
    match value.get("restartCount") {
        Some(CanonicalJsonValue::Integer(count)) => u32::try_from(*count).unwrap_or(0),
        _ => 0,
    }
}

fn lifecycle_effect_id(resource: &StoredResource) -> String {
    format!("process-lifecycle-restart-{}", status_restart_count(resource))
}

fn restart_count_reset_due(resource: &StoredResource, process: &DesiredProcess) -> bool {
    let DesiredProcess::Process(spec) = process else {
        return false;
    };
    let Some(CanonicalJsonValue::String(started_at)) = status_value(resource, "startedAt") else {
        return false;
    };
    let Some(started_at) = timestamp_millis(&started_at) else {
        return false;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    started_at
        .checked_add(u128::from(spec.restart_policy().reset_after().as_millis()))
        .is_none_or(|reset_at| reset_at <= now)
}

fn persisted_restart_count(resource: &StoredResource, process: &DesiredProcess) -> u32 {
    if restart_count_reset_due(resource, process) {
        0
    } else {
        status_restart_count(resource)
    }
}

fn status_retry_due(resource: &StoredResource) -> bool {
    let Some(CanonicalJsonValue::Object(outcome)) = status_value(resource, "outcome") else {
        return true;
    };
    let retryable = matches!(
        outcome.get("retryable"),
        Some(CanonicalJsonValue::Bool(true))
    );
    if !retryable {
        return true;
    }
    let Some(CanonicalJsonValue::Integer(delay)) = outcome.get("retryAfterMs") else {
        return true;
    };
    let Some(CanonicalJsonValue::String(occurred_at)) = outcome.get("occurredAt") else {
        return true;
    };
    let Some(occurred_at) = timestamp_millis(occurred_at) else {
        return true;
    };
    let Ok(delay) = u128::try_from(*delay) else {
        return true;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    occurred_at
        .checked_add(delay)
        .is_none_or(|due_at| due_at <= now)
}

fn process_restart_allowed(process: &DesiredProcess, restart_count: u32) -> bool {
    matches!(
        process,
        DesiredProcess::Process(spec)
            if spec.restart_policy().class() != RestartClass::Never
                && spec
                    .restart_policy()
                    .max_restarts()
                    .is_none_or(|max| restart_count < max)
    )
}

fn active_process_finalizer_for_values(
    resource: &StoredResource,
    provider_ref: &ResourceRef,
) -> Option<&'static str> {
    let value = metadata_value(resource, "finalizers")?;
    let CanonicalJsonValue::Array(values) = value else {
        return None;
    };
    process_finalizer(provider_ref)
        .into_iter()
        .chain([PROCESS_RUNTIME_FINALIZER])
        .find(|expected| {
            values.iter().any(
                |value| matches!(value, CanonicalJsonValue::String(value) if value == *expected),
            )
        })
}

fn timestamp_millis(value: &str) -> Option<u128> {
    if value.len() != 24
        || value.as_bytes().get(4) != Some(&b'-')
        || value.as_bytes().get(7) != Some(&b'-')
        || value.as_bytes().get(10) != Some(&b'T')
        || value.as_bytes().get(13) != Some(&b':')
        || value.as_bytes().get(16) != Some(&b':')
        || value.as_bytes().get(19) != Some(&b'.')
        || value.as_bytes().get(23) != Some(&b'Z')
    {
        return None;
    }
    let number = |start: usize, end: usize| value.get(start..end)?.parse::<i64>().ok();
    let year = number(0, 4)?;
    let month = number(5, 7)?;
    let day = number(8, 10)?;
    let hour = number(11, 13)?;
    let minute = number(14, 16)?;
    let second = number(17, 19)?;
    let millis = number(20, 23)?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
        || millis > 999
    {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(hour.checked_mul(3_600)?)?
        .checked_add(minute.checked_mul(60)?)?
        .checked_add(second)?;
    u128::try_from(seconds).ok().and_then(|seconds| {
        u128::try_from(millis)
            .ok()
            .map(|millis| seconds * 1_000 + millis)
    })
}

fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    let year = year.checked_sub(i64::from(month <= 2))?;
    let era = if year >= 0 {
        year / 400
    } else {
        (year - 399) / 400
    };
    let year_of_era = year - era * 400;
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era.checked_mul(146_097)
        .and_then(|value| value.checked_add(day_of_era))
        .and_then(|value| value.checked_sub(719_468))
}

fn ephemeral_status_ttl_elapsed(resource: &StoredResource, process: &DesiredProcess) -> bool {
    let DesiredProcess::Ephemeral(spec) = process else {
        return false;
    };
    if spec.incident_hold() {
        return false;
    }
    let eligible_at = match status_value(resource, "cleanupEligibleAt") {
        Some(CanonicalJsonValue::String(eligible_at)) => timestamp_millis(&eligible_at),
        _ => {
            let phase = status_phase(resource);
            let ttl = match phase {
                Some(ResourcePhase::Succeeded) => spec.successful_ttl(),
                Some(ResourcePhase::Failed) => spec.failed_ttl(),
                _ => return false,
            };
            match status_value(resource, "completedAt") {
                Some(CanonicalJsonValue::String(completed_at)) => timestamp_millis(&completed_at)
                    .and_then(|completed_at| {
                        completed_at.checked_add(u128::from(ttl.as_millis()))
                    }),
                _ => None,
            }
        }
    };
    let Some(eligible_at) = eligible_at else {
        return false;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    eligible_at <= now
}

fn status_value(resource: &StoredResource, key: &str) -> Option<CanonicalJsonValue> {
    let value = CanonicalJsonValue::parse(&resource.canonical_json).ok()?;
    let CanonicalJsonValue::Object(root) = value else {
        return None;
    };
    let CanonicalJsonValue::Object(status) = root.get("status")? else {
        return None;
    };
    status.get(key).cloned()
}

fn finalizer_candidate(
    canonical: &[u8],
    finalizer: &str,
    add: bool,
) -> Result<Vec<u8>, ProcessResourceRuntimeError> {
    let mut value = CanonicalJsonValue::parse(canonical)
        .map_err(|_| ProcessResourceRuntimeError::InvalidResource)?;
    let CanonicalJsonValue::Object(root) = &mut value else {
        return Err(ProcessResourceRuntimeError::InvalidResource);
    };
    let Some(CanonicalJsonValue::Object(metadata)) = root.get_mut("metadata") else {
        return Err(ProcessResourceRuntimeError::InvalidResource);
    };
    let Some(CanonicalJsonValue::Array(finalizers)) = metadata.get_mut("finalizers") else {
        return Err(ProcessResourceRuntimeError::InvalidResource);
    };
    if add {
        if !finalizers
            .iter()
            .any(|value| matches!(value, CanonicalJsonValue::String(value) if value == finalizer))
        {
            finalizers.push(CanonicalJsonValue::String(finalizer.to_owned()));
        }
    } else {
        finalizers.retain(
            |value| !matches!(value, CanonicalJsonValue::String(value) if value == finalizer),
        );
    }
    Ok(value.to_canonical_bytes())
}

fn restart_reset_due(process: &DesiredProcess, started: Instant) -> bool {
    match process {
        DesiredProcess::Process(spec) => {
            started.elapsed()
                >= Duration::from_millis(spec.restart_policy().reset_after().as_millis())
        }
        DesiredProcess::Ephemeral(_) => false,
    }
}

fn restart_delay(process: &DesiredProcess, restart_count: u32) -> Duration {
    let DesiredProcess::Process(spec) = process else {
        return Duration::ZERO;
    };
    let policy = spec.restart_policy();
    let base = policy.backoff_base().as_millis();
    let max = policy.backoff_max().as_millis();
    let multiplier = u64::from(policy.backoff_multiplier_milli());
    let mut delay = base;
    for _ in 1..restart_count {
        delay = delay
            .saturating_mul(multiplier)
            .saturating_div(1_000)
            .min(max);
    }
    Duration::from_millis(delay.min(max))
}

fn start_failure_code(error: ProcessResourceRuntimeError) -> &'static str {
    match error {
        ProcessResourceRuntimeError::TemplateUnavailable => "template-unavailable",
        ProcessResourceRuntimeError::IdentityAmbiguous => "identity-ambiguous",
        ProcessResourceRuntimeError::UnsupportedProvider => "provider-unsupported",
        ProcessResourceRuntimeError::InvalidResource => "resource-invalid",
        ProcessResourceRuntimeError::ProviderEffect => "provider-start-failed",
        ProcessResourceRuntimeError::ProviderIdentityUnavailable => "provider-identity-unavailable",
        ProcessResourceRuntimeError::Store => "store-failed",
    }
}

fn start_failure_message(error: ProcessResourceRuntimeError) -> &'static str {
    match error {
        ProcessResourceRuntimeError::TemplateUnavailable => {
            "the trusted process template binding is unavailable"
        }
        ProcessResourceRuntimeError::IdentityAmbiguous => {
            "the process identity could not be verified safely"
        }
        ProcessResourceRuntimeError::UnsupportedProvider => {
            "the process Provider is not owned by the daemon"
        }
        ProcessResourceRuntimeError::InvalidResource => "the process resource is invalid",
        ProcessResourceRuntimeError::ProviderEffect => "the Provider failed to start the process",
        ProcessResourceRuntimeError::ProviderIdentityUnavailable => {
            "the committed Provider identity is unavailable"
        }
        ProcessResourceRuntimeError::Store => "the durable resource store failed",
    }
}

fn stale_candidate_for_deletion(
    adoption: ProviderAdoption,
) -> Result<Option<AdoptionCandidate>, ProcessResourceRuntimeError> {
    match adoption {
        ProviderAdoption::Quarantined(_) => Err(ProcessResourceRuntimeError::IdentityAmbiguous),
        ProviderAdoption::Stale { candidate } => Ok(Some(candidate)),
        ProviderAdoption::Adopted(_)
        | ProviderAdoption::ControllerBootstrapMissing
        | ProviderAdoption::Absent => Ok(None),
    }
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

fn now_timestamp() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    timestamp_from_millis(millis)
}

fn timestamp_from_millis(millis: u128) -> String {
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
    client: &dyn ProcessResourceClient,
    record: &DesiredRecord,
    phase: ResourcePhase,
    restart_count: u32,
    outcome: Option<OutcomeState>,
) -> Result<DesiredRecord, ProcessResourceRuntimeError> {
    let canonical = status_payload(record, phase, restart_count, outcome)?;
    let envelope = ResourceEnvelope::from_json(&canonical)
        .map_err(|_| ProcessResourceRuntimeError::InvalidResource)?;
    let digest = envelope
        .digest()
        .map_err(|_| ProcessResourceRuntimeError::InvalidResource)?;
    let mut resource = wire::ResourceEnvelopeBytes::new();
    resource.identity = protobuf::MessageField::some(resource_identity(record));
    resource.canonical_json = canonical;
    resource.payload_digest = digest;

    let mut mutation = wire::Mutation::new();
    mutation.kind = protobuf::EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_UPDATE_STATUS);
    mutation.target = protobuf::MessageField::some(resource_identity(record));
    mutation.precondition = protobuf::MessageField::some(exact_precondition(record));
    mutation.resource = protobuf::MessageField::some(resource);
    let operation = process_mutation_operation_id(record, "status");
    let mut request = wire::UpdateStatusRequest::new();
    request.meta = protobuf::MessageField::some(request_meta(&operation));
    request.mutation = protobuf::MessageField::some(mutation);
    let response = client.update_status(request).await;
    if response.error.is_some() {
        return Err(ProcessResourceRuntimeError::Store);
    }
    let response_resource = response
        .resource
        .as_ref()
        .ok_or(ProcessResourceRuntimeError::Store)?;
    let mut updated = record.clone();
    updated.resource.canonical_json = response_resource.canonical_json.clone();
    updated.resource.payload_digest = response_resource.payload_digest.clone();
    updated.resource.revision = ZoneRevision::new(response.revision);
    Ok(updated)
}

fn status_payload(
    record: &DesiredRecord,
    phase: ResourcePhase,
    restart_count: u32,
    outcome: Option<OutcomeState>,
) -> Result<Vec<u8>, ProcessResourceRuntimeError> {
    let mut value = CanonicalJsonValue::parse(&record.resource.canonical_json)
        .map_err(|_| ProcessResourceRuntimeError::InvalidResource)?;
    let CanonicalJsonValue::Object(root) = &mut value else {
        return Err(ProcessResourceRuntimeError::InvalidResource);
    };
    let Some(CanonicalJsonValue::Object(status)) = root.get_mut("status") else {
        return Err(ProcessResourceRuntimeError::InvalidResource);
    };
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
    let new_run = outcome.as_ref().is_some_and(|outcome| {
        matches!(
            outcome.code,
            "process-started" | "process-restarted" | "process-ready"
        )
    });
    if phase == ResourcePhase::Ready
        && (new_run
            || status
                .get("startedAt")
                .is_none_or(|value| matches!(value, CanonicalJsonValue::Null)))
    {
        status.insert(
            "startedAt".to_owned(),
            CanonicalJsonValue::String(now.clone()),
        );
    }
    let terminal = matches!(
        phase,
        ResourcePhase::Succeeded | ResourcePhase::Failed | ResourcePhase::Deleted
    );
    let completed_at = status
        .get("completedAt")
        .filter(|value| !matches!(value, CanonicalJsonValue::Null))
        .cloned()
        .unwrap_or_else(|| CanonicalJsonValue::String(now.clone()));
    if terminal && matches!(phase, ResourcePhase::Succeeded | ResourcePhase::Failed) {
        status.insert("completedAt".to_owned(), completed_at.clone());
        if let DesiredProcess::Ephemeral(spec) = &record.process {
            if spec.incident_hold() {
                status.insert("cleanupEligibleAt".to_owned(), CanonicalJsonValue::Null);
            } else if let CanonicalJsonValue::String(completed_at) = completed_at {
                let eligible = timestamp_millis(&completed_at)
                    .and_then(|millis| {
                        millis.checked_add(if phase == ResourcePhase::Failed {
                            u128::from(spec.failed_ttl().as_millis())
                        } else {
                            u128::from(spec.successful_ttl().as_millis())
                        })
                    })
                    .map(|millis| timestamp_from_millis(millis))
                    .unwrap_or_else(|| now.clone());
                status.insert(
                    "cleanupEligibleAt".to_owned(),
                    CanonicalJsonValue::String(eligible),
                );
            }
        }
    } else if phase == ResourcePhase::Deleted {
        status.insert("cleanupEligibleAt".to_owned(), CanonicalJsonValue::Null);
    }
    status.insert(
        "outcome".to_owned(),
        outcome
            .as_ref()
            .map(|outcome| {
                let mut result = BTreeMap::new();
                result.insert(
                    "code".to_owned(),
                    CanonicalJsonValue::String(outcome.code.to_owned()),
                );
                result.insert(
                    "message".to_owned(),
                    CanonicalJsonValue::String(outcome.message.to_owned()),
                );
                result.insert(
                    "retryable".to_owned(),
                    CanonicalJsonValue::Bool(outcome.retryable),
                );
                result.insert(
                    "occurredAt".to_owned(),
                    CanonicalJsonValue::String(now.clone()),
                );
                if let Some(retry_after_ms) = outcome.retry_after_ms {
                    result.insert(
                        "retryAfterMs".to_owned(),
                        CanonicalJsonValue::Integer(i64::from(retry_after_ms)),
                    );
                }
                CanonicalJsonValue::Object(result)
            })
            .unwrap_or(CanonicalJsonValue::Null),
    );
    let Some(CanonicalJsonValue::Object(resource_status)) = status.get_mut("resource") else {
        return Err(ProcessResourceRuntimeError::InvalidResource);
    };
    resource_status.insert(
        "provider".to_owned(),
        CanonicalJsonValue::String(record.provider_ref.to_canonical_string()),
    );
    resource_status.insert(
        "restartCount".to_owned(),
        CanonicalJsonValue::Integer(i64::from(restart_count)),
    );
    if let Some(adopted) = outcome.as_ref().and_then(|outcome| outcome.adopted) {
        resource_status.insert("adopted".to_owned(), CanonicalJsonValue::Bool(adopted));
    }
    if let Some(CanonicalJsonValue::Object(update)) = status.get_mut("update") {
        update.insert(
            "operationId".to_owned(),
            CanonicalJsonValue::String(process_operation_id(record, "status")),
        );
    }
    if let Some(CanonicalJsonValue::Object(update)) = status.get_mut("update") {
        update.insert(
            "observedGeneration".to_owned(),
            CanonicalJsonValue::Integer(record.resource.generation.get() as i64),
        );
        update.insert("lastAssessedAt".to_owned(), CanonicalJsonValue::String(now));
    }
    let canonical = value.to_canonical_bytes();
    ResourceEnvelope::from_json(&canonical)
        .map_err(|_| ProcessResourceRuntimeError::InvalidResource)?;
    Ok(canonical)
}

fn status_candidate_from_resource(
    canonical: &[u8],
) -> Result<Vec<u8>, ProcessResourceRuntimeError> {
    let value = CanonicalJsonValue::parse(canonical)
        .map_err(|_| ProcessResourceRuntimeError::InvalidResource)?;
    let CanonicalJsonValue::Object(root) = value else {
        return Err(ProcessResourceRuntimeError::InvalidResource);
    };
    let status = root
        .get("status")
        .cloned()
        .ok_or(ProcessResourceRuntimeError::InvalidResource)?;
    match status {
        CanonicalJsonValue::Object(status) => {
            Ok(CanonicalJsonValue::Object(status).to_canonical_bytes())
        }
        _ => Err(ProcessResourceRuntimeError::InvalidResource),
    }
}

async fn update_finalizers(
    client: &dyn ProcessResourceClient,
    record: &DesiredRecord,
    finalizer: &str,
    add: bool,
) -> Result<DesiredRecord, ProcessResourceRuntimeError> {
    let mut mutation = wire::Mutation::new();
    mutation.kind =
        protobuf::EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_UPDATE_FINALIZERS);
    mutation.target = protobuf::MessageField::some(resource_identity(record));
    mutation.precondition = protobuf::MessageField::some(exact_precondition(record));
    if add {
        mutation.add_finalizers.push(finalizer.to_owned());
    } else {
        mutation.remove_finalizers.push(finalizer.to_owned());
    }
    let operation = process_mutation_operation_id(
        record,
        if add {
            "finalizer-add"
        } else {
            "finalizer-remove"
        },
    );
    let mut request = wire::UpdateFinalizersRequest::new();
    request.meta = protobuf::MessageField::some(request_meta(&operation));
    request.mutation = protobuf::MessageField::some(mutation);
    let response = client.update_finalizers(request).await;
    if response.error.is_some() {
        return Err(ProcessResourceRuntimeError::Store);
    }
    let response_resource = response
        .resource
        .as_ref()
        .ok_or(ProcessResourceRuntimeError::Store)?;
    let mut updated = record.clone();
    updated.resource.canonical_json = response_resource.canonical_json.clone();
    updated.resource.payload_digest = response_resource.payload_digest.clone();
    updated.resource.revision = ZoneRevision::new(response.revision);
    Ok(updated)
}

async fn delete_resource(
    client: &dyn ProcessResourceClient,
    record: &DesiredRecord,
) -> Result<(), ProcessResourceRuntimeError> {
    let mut mutation = wire::Mutation::new();
    mutation.kind = protobuf::EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_DELETE);
    mutation.target = protobuf::MessageField::some(resource_identity(record));
    mutation.precondition = protobuf::MessageField::some(exact_precondition(record));
    let operation = process_mutation_operation_id(record, "delete");
    let mut request = wire::DeleteRequest::new();
    request.meta = protobuf::MessageField::some(request_meta(&operation));
    request.mutation = protobuf::MessageField::some(mutation);
    let response = client.delete(request).await;
    if response.error.is_some() {
        return Err(ProcessResourceRuntimeError::Store);
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

fn request_meta(operation: &str) -> wire::RequestMeta {
    let mut meta = wire::RequestMeta::new();
    meta.operation_id = operation.to_owned();
    meta.idempotency_key = operation.to_owned();
    meta.correlation_id = operation.to_owned();
    meta.trace_id = operation.to_owned();
    meta.deadline_ms = 10_000;
    meta
}

fn process_operation_id(record: &DesiredRecord, action: &str) -> String {
    let (template, execution_ref) = match &record.process {
        DesiredProcess::Process(spec) => (
            spec.execution().template().as_str().to_owned(),
            spec.execution().execution_ref().to_canonical_string(),
        ),
        DesiredProcess::Ephemeral(spec) => (
            spec.execution().template().as_str().to_owned(),
            spec.execution().execution_ref().to_canonical_string(),
        ),
    };
    let digest = Sha256::digest(
        format!(
            "d2bd:process-lifecycle:v5:{action}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            record.resource.zone.as_str(),
            record.key().to_canonical_string(),
            record.resource.uid.as_str(),
            record.resource.generation.get(),
            record.provider_ref.to_canonical_string(),
            record
                .owner_ref()
                .map(|owner| owner.to_canonical_string())
                .unwrap_or_else(|| "unowned".to_owned()),
            execution_ref,
            template,
            record
                .zone_uid
                .as_ref()
                .map(ResourceUid::as_str)
                .unwrap_or("unbound"),
            record
                .policy_revision
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unbound".to_owned()),
            record
                .provider_assignment_generation
                .map(|value| value.get().to_string())
                .unwrap_or_else(|| "unbound".to_owned()),
            record
                .controller_provider_uid
                .as_ref()
                .map(ResourceUid::as_str)
                .unwrap_or("unbound"),
            record
                .controller_provider_generation
                .map(|value| value.get().to_string())
                .unwrap_or_else(|| "unbound".to_owned()),
            status_restart_count(&record.resource),
        )
        .as_bytes(),
    );
    format!("process-lifecycle-{digest:x}")
}

fn process_mutation_operation_id(record: &DesiredRecord, action: &str) -> String {
    let digest = Sha256::digest(
        format!(
            "d2bd:process-mutation:v1:{action}:{}:{}:{}:{}",
            process_operation_id(record, action),
            record.resource.revision.get(),
            record.resource.uid.as_str(),
            record.resource.generation.get(),
        )
        .as_bytes(),
    );
    format!("process-mutation-{digest:x}")
}

fn map_provider_error(error: String) -> ProcessResourceRuntimeError {
    if error.contains("template-not-found") {
        ProcessResourceRuntimeError::TemplateUnavailable
    } else if error.contains("quarantined")
        || error.contains("identity")
        || error.contains("ambiguous")
    {
        ProcessResourceRuntimeError::IdentityAmbiguous
    } else {
        ProcessResourceRuntimeError::ProviderEffect
    }
}

fn is_static_controller(record: &DesiredRecord) -> bool {
    matches!(
        &record.process,
        DesiredProcess::Process(spec)
            if spec.execution().process_class()
                == d2b_contracts_resource::v3::process::ProcessClass::Controller
            && record
                .owner_ref()
                .is_some_and(|owner| owner.resource_type().as_str() == "Provider")
    )
}

fn controller_provider_identity_available(record: &DesiredRecord) -> bool {
    !is_static_controller(record)
        || (record.controller_provider_uid.is_some()
            && record.controller_provider_generation.is_some())
}

fn controller_requires_stop(record: &DesiredRecord, bootstrap_present: bool) -> bool {
    is_static_controller(record)
        && (!bootstrap_present || !controller_provider_identity_available(record))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StartRecordEffect {
    StopAndFinalize,
    Launch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StartRecordPlan {
    adopted: bool,
    effects: &'static [StartRecordEffect],
}

const NO_START_RECORD_EFFECTS: &[StartRecordEffect] = &[];
const CONTROLLER_BOOTSTRAP_RESTART_EFFECTS: &[StartRecordEffect] = &[
    StartRecordEffect::StopAndFinalize,
    StartRecordEffect::Launch,
];

/// Select the bounded lifecycle effects for an adoption result.
///
/// The concrete Provider calls remain in `start_record`; this small plan keeps
/// the restart ordering executable without replacing the production Provider
/// composition with a test-only mock.
fn start_record_plan(
    adoption: &ProviderAdoption,
    process: &DesiredProcess,
) -> Result<Option<StartRecordPlan>, ProcessResourceRuntimeError> {
    match adoption {
        ProviderAdoption::Adopted(_) => Ok(Some(StartRecordPlan {
            adopted: true,
            effects: NO_START_RECORD_EFFECTS,
        })),
        ProviderAdoption::ControllerBootstrapMissing => match process {
            DesiredProcess::Process(_) => Ok(Some(StartRecordPlan {
                adopted: false,
                effects: CONTROLLER_BOOTSTRAP_RESTART_EFFECTS,
            })),
            DesiredProcess::Ephemeral(_) => Err(ProcessResourceRuntimeError::TemplateUnavailable),
        },
        ProviderAdoption::Absent
        | ProviderAdoption::Stale { .. }
        | ProviderAdoption::Quarantined(_) => Ok(None),
    }
}

fn deletion_adoption(
    result: Result<ProviderAdoption, String>,
) -> Result<ProviderAdoption, ProcessResourceRuntimeError> {
    match result {
        Ok(adoption) => Ok(adoption),
        Err(error) if error == GUEST_EXECUTION_UNAVAILABLE => {
            Err(ProcessResourceRuntimeError::ProviderEffect)
        }
        Err(error) => Err(map_provider_error(error)),
    }
}

fn decode_snapshot(
    zone: &ZoneId,
    target: Option<&ResourceRef>,
    resources: Vec<StoredResource>,
    mode: DaemonMode,
) -> Result<BTreeMap<ResourceRef, DesiredRecord>, ProcessResourceRuntimeError> {
    let mut desired = BTreeMap::new();
    for resource in resources {
        if resource.zone != *zone {
            return Err(ProcessResourceRuntimeError::InvalidResource);
        }
        let resource_type = resource.resource_ref.resource_type().as_str();
        let envelope = ResourceEnvelope::from_json(&resource.canonical_json)
            .map_err(|_| ProcessResourceRuntimeError::InvalidResource)?;
        let provider_ref = envelope
            .spec()
            .provider_ref()
            .cloned()
            .ok_or(ProcessResourceRuntimeError::InvalidResource)?;
        let execution_ref = envelope
            .spec()
            .base()
            .get("executionRef")
            .and_then(|value| match value {
                CanonicalJsonValue::String(value) => ResourceRef::parse(value).ok(),
                _ => None,
            })
            .ok_or(ProcessResourceRuntimeError::InvalidResource)?;
        let target_matches = if let Some(target) = target {
            execution_ref == *target
        } else {
            execution_ref.resource_type().as_str() == "Host"
        };
        if !target_matches {
            continue;
        }
        if provider_ref.resource_type().as_str() != "Provider"
            || !matches!(
                provider_ref.name().as_str(),
                MINIJAIL_PROVIDER | SYSTEMD_PROVIDER
            )
        {
            return Err(ProcessResourceRuntimeError::UnsupportedProvider);
        }
        let process = match resource_type {
            PROCESS_TYPE => DesiredProcess::Process(
                serde_json::from_slice(&envelope.spec().base().to_canonical_bytes())
                    .map_err(|_| ProcessResourceRuntimeError::InvalidResource)?,
            ),
            EPHEMERAL_PROCESS_TYPE => DesiredProcess::Ephemeral(
                serde_json::from_slice(&envelope.spec().base().to_canonical_bytes())
                    .map_err(|_| ProcessResourceRuntimeError::InvalidResource)?,
            ),
            _ => continue,
        };
        if mode == DaemonMode::Host
            && match &process {
                DesiredProcess::Process(spec) => {
                    spec.execution().execution_ref().resource_type().as_str() == "Guest"
                }
                DesiredProcess::Ephemeral(spec) => {
                    spec.execution().execution_ref().resource_type().as_str() == "Guest"
                }
            }
        {
            // A Host Process controller cannot reconcile a Guest-local child.
            // Leave the intent pending for the authenticated Guest controller
            // rather than claiming failure or running it through host effects.
            continue;
        }
        let record = DesiredRecord {
            resource: resource.clone(),
            provider_ref,
            process,
            zone_uid: None,
            policy_revision: None,
            provider_assignment_generation: None,
            controller_provider_uid: None,
            controller_provider_generation: None,
        };
        if desired.insert(record.key(), record).is_some() {
            return Err(ProcessResourceRuntimeError::InvalidResource);
        }
    }
    Ok(desired)
}

fn restart_annotation(resource: &StoredResource) -> Option<String> {
    let value = CanonicalJsonValue::parse(&resource.canonical_json).ok()?;
    let CanonicalJsonValue::Object(root) = value else {
        return None;
    };
    let CanonicalJsonValue::Object(metadata) = root.get("metadata")? else {
        return None;
    };
    let CanonicalJsonValue::Object(annotations) = metadata.get("annotations")? else {
        return None;
    };
    match annotations.get(PROCESS_RESTART_ANNOTATION) {
        Some(CanonicalJsonValue::String(value)) => Some(value.clone()),
        _ => None,
    }
}

/// Build the generic Process relist request.
pub(crate) fn process_list_request(zone: &ZoneId) -> StoreListRequest {
    StoreListRequest {
        operation: StoreOperationContext {
            operation_id: "process-resource-reconcile".to_owned(),
            idempotency_key: None,
            correlation_id: "process-resource-reconcile".to_owned(),
            trace_id: None,
            deadline_ms: 10_000,
        },
        zone: zone.clone(),
        resource_types: vec![
            ResourceTypeName::parse(PROCESS_TYPE).expect("static Process type"),
            ResourceTypeName::parse(EPHEMERAL_PROCESS_TYPE).expect("static EphemeralProcess type"),
        ],
        resource_names: Vec::new(),
        filters: Vec::new(),
        page_size: 256,
        cursor: None,
        projection: StoreProjection::Full,
    }
}

/// Relist all generic Process resources, preserving snapshot pagination.
pub(crate) async fn list_process_snapshot(
    store: &RedbResourceStore,
    zone: &ZoneId,
) -> Result<Vec<StoredResource>, ProcessResourceRuntimeError> {
    let mut request = process_list_request(zone);
    let mut resources = Vec::new();
    loop {
        let result = store
            .list(request.clone())
            .await
            .map_err(|_| ProcessResourceRuntimeError::Store)?;
        resources.extend(result.resources);
        let Some(cursor) = result.next_cursor else {
            break;
        };
        request.cursor = Some(cursor);
    }
    Ok(resources)
}

/// Relist generic Process resources through a session-bound Resource API
/// backend. This mirrors the concrete Zone-store helper while preserving the
/// backend's reconnect fence.
#[allow(dead_code)]
pub(crate) async fn list_process_snapshot_backend<S: ResourceStoreBackend>(
    store: &S,
    zone: &ZoneId,
) -> Result<Vec<StoredResource>, ProcessResourceRuntimeError> {
    let mut request = process_list_request(zone);
    let mut resources = Vec::new();
    loop {
        let result = store
            .list(request.clone())
            .await
            .map_err(|_| ProcessResourceRuntimeError::Store)?;
        resources.extend(result.resources);
        let Some(cursor) = result.next_cursor else {
            break;
        };
        request.cursor = Some(cursor);
    }
    Ok(resources)
}

/// Drain a deleted WaylandSession through its durable Process and Endpoint
/// children before releasing the session finalizer.
#[allow(dead_code)]
pub(crate) async fn reconcile_wayland_session_deletion(
    client: &ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>,
    store: &RedbResourceStore,
    zone: &ZoneId,
    session_ref: &ResourceRef,
) -> Result<(), ProcessResourceRuntimeError> {
    for _ in 0..8 {
        let session = match store
            .get(StoreGetRequest {
                operation: cleanup_operation("wayland-session-get", session_ref, 0),
                zone: zone.clone(),
                target: session_ref.clone(),
                expected_uid: None,
                projection: StoreProjection::Full,
            })
            .await
        {
            Ok(resource) => resource,
            Err(error) if error.kind() == StoreErrorKind::ResourceNotFound => return Ok(()),
            Err(_) => return Err(ProcessResourceRuntimeError::Store),
        };
        if session.resource_ref.resource_type().as_str() != WAYLAND_SESSION_TYPE
            || !metadata_deletion_requested(&session)
        {
            return Ok(());
        }

        let children = list_cleanup_children(store, zone).await?;
        let owned_processes = children
            .iter()
            .filter(|resource| {
                resource.resource_ref.resource_type().as_str() == PROCESS_TYPE
                    && metadata_owner_ref(resource).as_ref() == Some(session_ref)
            })
            .cloned()
            .collect::<Vec<_>>();
        let owned_endpoints = children
            .iter()
            .filter(|resource| {
                resource.resource_ref.resource_type().as_str() == "Endpoint"
                    && metadata_owner_ref(resource).as_ref() == Some(session_ref)
            })
            .cloned()
            .collect::<Vec<_>>();
        let mut changed = false;

        for process in &owned_processes {
            if !metadata_deletion_requested(process) {
                changed |=
                    request_cleanup_delete(client, process, "wayland-child-process-delete").await;
            } else if matches!(
                status_phase(process),
                Some(ResourcePhase::Succeeded | ResourcePhase::Failed | ResourcePhase::Deleted)
            ) && !owned_endpoints.iter().any(|endpoint| {
                endpoint_producer_ref(endpoint).as_ref() == Some(&process.resource_ref)
            }) {
                changed |=
                    request_cleanup_delete(client, process, "wayland-child-process-drain").await;
            }
        }

        for endpoint in &owned_endpoints {
            let producer = endpoint_producer_ref(endpoint);
            let producer_terminal = producer.as_ref().is_none_or(|producer| {
                owned_processes
                    .iter()
                    .find(|process| &process.resource_ref == producer)
                    .is_none_or(|process| {
                        matches!(
                            status_phase(process),
                            Some(
                                ResourcePhase::Succeeded
                                    | ResourcePhase::Failed
                                    | ResourcePhase::Deleted
                            )
                        )
                    })
            });
            if producer_terminal && !metadata_deletion_requested(endpoint) {
                changed |=
                    request_cleanup_delete(client, endpoint, "wayland-child-endpoint-delete").await;
            } else if producer_terminal && metadata_deletion_requested(endpoint) {
                changed |=
                    request_cleanup_delete(client, endpoint, "wayland-child-endpoint-drain").await;
            }
        }

        let refreshed_children = list_cleanup_children(store, zone).await?;
        let remaining = refreshed_children.iter().any(|resource| {
            matches!(
                resource.resource_ref.resource_type().as_str(),
                PROCESS_TYPE | "Endpoint"
            ) && metadata_owner_ref(resource).as_ref() == Some(session_ref)
        });
        if !remaining {
            let current = store
                .get(StoreGetRequest {
                    operation: cleanup_operation("wayland-session-finalizer-get", session_ref, 0),
                    zone: zone.clone(),
                    target: session_ref.clone(),
                    expected_uid: None,
                    projection: StoreProjection::Full,
                })
                .await
                .map_err(|_| ProcessResourceRuntimeError::Store)?;
            if metadata_has_finalizer(&current, WAYLAND_SESSION_FINALIZER) {
                changed |=
                    request_cleanup_finalizer(client, &current, WAYLAND_SESSION_FINALIZER, false)
                        .await;
            } else {
                changed |= request_cleanup_delete(client, &current, "wayland-session-delete").await;
            }
        }
        if !changed {
            break;
        }
    }
    Ok(())
}

#[allow(dead_code)]
async fn list_cleanup_children(
    store: &RedbResourceStore,
    zone: &ZoneId,
) -> Result<Vec<StoredResource>, ProcessResourceRuntimeError> {
    let mut request = StoreListRequest {
        operation: StoreOperationContext {
            operation_id: "wayland-session-cleanup-list".to_owned(),
            idempotency_key: None,
            correlation_id: "wayland-session-cleanup-list".to_owned(),
            trace_id: None,
            deadline_ms: 10_000,
        },
        zone: zone.clone(),
        resource_types: vec![
            ResourceTypeName::parse(PROCESS_TYPE).expect("static Process type"),
            ResourceTypeName::parse("Endpoint").expect("static Endpoint type"),
        ],
        resource_names: Vec::new(),
        filters: Vec::new(),
        page_size: 256,
        cursor: None,
        projection: StoreProjection::Full,
    };
    let mut resources = Vec::new();
    loop {
        let result = store
            .list(request.clone())
            .await
            .map_err(|_| ProcessResourceRuntimeError::Store)?;
        resources.extend(result.resources);
        let Some(cursor) = result.next_cursor else {
            break;
        };
        request.cursor = Some(cursor);
    }
    Ok(resources)
}

#[allow(dead_code)]
fn cleanup_operation(
    action: &str,
    resource_ref: &ResourceRef,
    revision: u64,
) -> StoreOperationContext {
    let operation_id = cleanup_operation_id(action, resource_ref, revision);
    StoreOperationContext {
        operation_id: operation_id.clone(),
        idempotency_key: None,
        correlation_id: operation_id,
        trace_id: None,
        deadline_ms: 10_000,
    }
}

#[allow(dead_code)]
fn cleanup_operation_id(action: &str, resource_ref: &ResourceRef, revision: u64) -> String {
    let mut digest = Sha256::new();
    digest.update(action.as_bytes());
    digest.update([0]);
    digest.update(resource_ref.to_canonical_string().as_bytes());
    digest.update(revision.to_be_bytes());
    let digest = digest.finalize();
    let suffix = digest
        .iter()
        .take(12)
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{action}-{suffix}")
}

#[allow(dead_code)]
fn metadata_deletion_requested(resource: &StoredResource) -> bool {
    metadata_value(resource, "deletionRequestedAt")
        .is_some_and(|value| !matches!(value, CanonicalJsonValue::Null))
}

#[allow(dead_code)]
fn metadata_has_finalizer(resource: &StoredResource, expected: &str) -> bool {
    metadata_value(resource, "finalizers").is_some_and(|value| {
        matches!(
            value,
            CanonicalJsonValue::Array(values)
                if values.iter().any(|value| {
                    matches!(value, CanonicalJsonValue::String(value) if value == expected)
                })
        )
    })
}

#[allow(dead_code)]
fn metadata_owner_ref(resource: &StoredResource) -> Option<ResourceRef> {
    let CanonicalJsonValue::String(value) = metadata_value(resource, "ownerRef")? else {
        return None;
    };
    ResourceRef::parse(&value).ok()
}

#[allow(dead_code)]
fn endpoint_producer_ref(resource: &StoredResource) -> Option<ResourceRef> {
    let value = CanonicalJsonValue::parse(&resource.canonical_json).ok()?;
    let CanonicalJsonValue::Object(root) = value else {
        return None;
    };
    let CanonicalJsonValue::Object(spec) = root.get("spec")? else {
        return None;
    };
    let CanonicalJsonValue::String(value) = spec.get("producerRef")? else {
        return None;
    };
    ResourceRef::parse(&value).ok()
}

#[allow(dead_code)]
fn cleanup_wire_identity(resource: &StoredResource) -> wire::ResourceIdentity {
    let mut identity = wire::ResourceIdentity::new();
    identity.zone = resource.zone.as_str().to_owned();
    identity.resource_type = resource.resource_ref.resource_type().as_str().to_owned();
    identity.name = resource.resource_ref.name().as_str().to_owned();
    identity.uid = Some(resource.uid.as_str().to_owned());
    identity.generation = Some(resource.generation.get());
    identity.revision = Some(resource.revision.get());
    identity
}

#[allow(dead_code)]
async fn request_cleanup_delete(
    client: &ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>,
    resource: &StoredResource,
    action: &str,
) -> bool {
    let mut mutation = wire::Mutation::new();
    mutation.kind = protobuf::EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_DELETE);
    mutation.target = protobuf::MessageField::some(cleanup_wire_identity(resource));
    let mut precondition = wire::Precondition::new();
    precondition.kind =
        protobuf::EnumOrUnknown::new(wire::PreconditionKind::PRECONDITION_KIND_EXACT_REVISION);
    precondition.expected_revision = Some(resource.revision.get());
    precondition.expected_uid = Some(resource.uid.as_str().to_owned());
    mutation.precondition = protobuf::MessageField::some(precondition);
    let mut request = wire::DeleteRequest::new();
    request.meta = protobuf::MessageField::some(request_meta(&cleanup_operation_id(
        action,
        &resource.resource_ref,
        resource.revision.get(),
    )));
    request.mutation = protobuf::MessageField::some(mutation);
    client.delete(request).await.error.is_none()
}

#[allow(dead_code)]
async fn request_cleanup_finalizer(
    client: &ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>,
    resource: &StoredResource,
    finalizer: &str,
    add: bool,
) -> bool {
    let mut mutation = wire::Mutation::new();
    mutation.kind =
        protobuf::EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_UPDATE_FINALIZERS);
    mutation.target = protobuf::MessageField::some(cleanup_wire_identity(resource));
    let mut precondition = wire::Precondition::new();
    precondition.kind =
        protobuf::EnumOrUnknown::new(wire::PreconditionKind::PRECONDITION_KIND_EXACT_REVISION);
    precondition.expected_revision = Some(resource.revision.get());
    precondition.expected_uid = Some(resource.uid.as_str().to_owned());
    mutation.precondition = protobuf::MessageField::some(precondition);
    if add {
        mutation.add_finalizers.push(finalizer.to_owned());
    } else {
        mutation.remove_finalizers.push(finalizer.to_owned());
    }
    let mut request = wire::UpdateFinalizersRequest::new();
    let action = if add {
        "wayland-session-finalizer-add"
    } else {
        "wayland-session-finalizer-remove"
    };
    request.meta = protobuf::MessageField::some(request_meta(&cleanup_operation_id(
        action,
        &resource.resource_ref,
        resource.revision.get(),
    )));
    request.mutation = protobuf::MessageField::some(mutation);
    client.update_finalizers(request).await.error.is_none()
}

pub(crate) fn controller_provider_refs(resources: &[StoredResource]) -> BTreeSet<ResourceRef> {
    resources
        .iter()
        .filter(|resource| {
            matches!(
                resource.resource_ref.resource_type().as_str(),
                PROCESS_TYPE | EPHEMERAL_PROCESS_TYPE
            )
        })
        .filter_map(|resource| {
            let envelope = ResourceEnvelope::from_json(&resource.canonical_json).ok()?;
            let provider = envelope.spec().provider_ref()?.clone();
            let process = resource.resource_ref.resource_type().as_str() == PROCESS_TYPE;
            let is_controller = process
                && serde_json::from_slice::<ProcessSpec>(
                    &envelope.spec().base().to_canonical_bytes(),
                )
                .ok()
                .is_some_and(|spec| {
                    spec.execution().process_class()
                        == d2b_contracts_resource::v3::process::ProcessClass::Controller
                });
            if is_controller {
                let owner = envelope.metadata().owner_ref()?.clone();
                if owner.resource_type().as_str() == "Provider" {
                    return Some(owner);
                }
            }
            Some(provider)
        })
        .collect()
}

struct GuestProcessSource {
    zone: ZoneId,
    target_ref: Option<ResourceRef>,
    guest_execution: GuestExecutionBinding,
    descriptor: Mutex<Option<ControllerDescriptor>>,
    store: Arc<d2bd_runtime::guest_resource_runtime::SessionBoundStore>,
    client: Arc<
        ResourceApiClient<
            d2bd_runtime::guest_resource_runtime::SessionBoundStore,
            UnavailableUpgradeDispatcher,
        >,
    >,
    watch: tokio::sync::Mutex<Option<ResourceWatch>>,
    pending: tokio::sync::Mutex<VecDeque<(ChangeRecord, OperationContext, ZoneRevision)>>,
    acknowledge_after: tokio::sync::Mutex<Option<ZoneRevision>>,
    watch_open: AtomicBool,
    watch_stop: tokio::sync::Notify,
    accepted: tokio::sync::Mutex<BTreeMap<String, GuestAcceptedEffect>>,
}

struct GuestAcceptedEffect {
    capability: AuthorityOperationCapability,
    target: ResourceKey,
}

fn guest_operation_class(context: &ReconcileContext) -> &'static str {
    if context
        .reasons()
        .contains(d2b_core_controller::CoreTriggerReason::UpgradeRequested)
    {
        "upgrade"
    } else if context
        .reasons()
        .contains(d2b_core_controller::CoreTriggerReason::DeletionRequested)
        || context
            .reasons()
            .contains(d2b_core_controller::CoreTriggerReason::FinalizerRequired)
    {
        "finalize"
    } else {
        "reconcile"
    }
}

fn append_guest_claim_text(material: &mut Vec<u8>, value: &str) {
    material.extend_from_slice(&(value.len() as u64).to_be_bytes());
    material.extend_from_slice(value.as_bytes());
}

fn guest_effect_claim_digest(
    source: &GuestProcessSource,
    context: &ReconcileContext,
    plan: &ReconcilePlan,
) -> String {
    let mut material = Vec::new();
    append_guest_claim_text(&mut material, guest_operation_class(context));
    append_guest_claim_text(&mut material, context.target().uid().as_str());
    material.extend_from_slice(&context.generation().get().to_be_bytes());
    for effect_id in plan.effect_ids() {
        append_guest_claim_text(&mut material, effect_id);
    }
    append_guest_claim_text(
        &mut material,
        source.guest_execution.target_uid().as_str(),
    );
    append_guest_claim_text(
        &mut material,
        &source.guest_execution.boot_identity_digest().to_hex(),
    );
    material.extend_from_slice(
        &source
            .guest_execution
            .session_generation()
            .get()
            .to_be_bytes(),
    );
    material.extend_from_slice(
        &source
            .guest_execution
            .assignment_epoch()
            .to_be_bytes(),
    );
    material.extend_from_slice(
        &source
            .guest_execution
            .provider_generation()
            .get()
            .to_be_bytes(),
    );
    material.extend_from_slice(
        &source
            .guest_execution
            .controller_generation()
            .get()
            .to_be_bytes(),
    );
    append_guest_claim_text(
        &mut material,
        &context.identity().controller_ref().to_canonical_string(),
    );
    if let Some(target_ref) = source.target_ref.as_ref() {
        append_guest_claim_text(&mut material, &target_ref.to_canonical_string());
    } else {
        append_guest_claim_text(&mut material, "unbound");
    }
    canonical_digest("d2b:guest-controller-effect-claim/v1", &material)
}

fn guest_result_state(
    disposition: ReconcileDisposition,
) -> AuthorityOperationState {
    match disposition {
        ReconcileDisposition::Converged | ReconcileDisposition::Finalized => {
            AuthorityOperationState::EffectConfirmed
        }
        ReconcileDisposition::Pending
        | ReconcileDisposition::Degraded
        | ReconcileDisposition::RequeueAt => AuthorityOperationState::Pending,
        ReconcileDisposition::FailedRetryable => AuthorityOperationState::EffectRetryable,
        ReconcileDisposition::FailedTerminal => AuthorityOperationState::EffectTerminal,
    }
}

fn guest_projection_state(
    projection: &d2b_core_controller::ReconcileProjection,
) -> AuthorityOperationState {
    match projection.disposition() {
        d2b_core_controller::ProjectionDisposition::Converged => {
            AuthorityOperationState::EffectConfirmed
        }
        d2b_core_controller::ProjectionDisposition::Failed
            if matches!(
                projection.reason(),
                d2b_core_controller::ReconcileReason::HandlerTerminal
                    | d2b_core_controller::ReconcileReason::HandlerExhausted
                    | d2b_core_controller::ReconcileReason::InvalidSpec
            ) =>
        {
            AuthorityOperationState::EffectTerminal
        }
        d2b_core_controller::ProjectionDisposition::Failed => {
            AuthorityOperationState::EffectRetryable
        }
        d2b_core_controller::ProjectionDisposition::Progressing
        | d2b_core_controller::ProjectionDisposition::Blocked
        | d2b_core_controller::ProjectionDisposition::UpgradeRequired => {
            AuthorityOperationState::Pending
        }
    }
}

fn guest_store_error(error: &StoreError, fallback: ZoneRevision) -> SourceError {
    match error.kind() {
        StoreErrorKind::ResourceConflict
        | StoreErrorKind::ResourceAlreadyExists
        | StoreErrorKind::ResourceNotFound
        | StoreErrorKind::ResourceFinalizerDenied => {
            SourceError::Conflict(error.current_revision().unwrap_or(fallback))
        }
        StoreErrorKind::Backpressure | StoreErrorKind::StoreBackpressure => {
            SourceError::Backpressure
        }
        StoreErrorKind::Timeout => SourceError::Timeout,
        StoreErrorKind::Cancelled => SourceError::Cancelled,
        StoreErrorKind::ResourcePlaneUnavailable => SourceError::Unavailable,
        _ => SourceError::Integrity,
    }
}

impl std::fmt::Debug for GuestProcessSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GuestProcessSource")
            .field(
                "has_descriptor",
                &self
                    .descriptor
                    .lock()
                    .map(|value| value.is_some())
                    .unwrap_or(false),
            )
            .finish()
    }
}

impl GuestProcessSource {
    fn new(
        zone: ZoneId,
        target_ref: Option<ResourceRef>,
        guest_execution: GuestExecutionBinding,
        store: Arc<d2bd_runtime::guest_resource_runtime::SessionBoundStore>,
        client: Arc<
            ResourceApiClient<
                d2bd_runtime::guest_resource_runtime::SessionBoundStore,
                UnavailableUpgradeDispatcher,
            >,
        >,
    ) -> Arc<Self> {
        Arc::new(Self {
            zone,
            target_ref,
            guest_execution,
            descriptor: Mutex::new(None),
            store,
            client,
            watch: tokio::sync::Mutex::new(None),
            pending: tokio::sync::Mutex::new(VecDeque::new()),
            acknowledge_after: tokio::sync::Mutex::new(None),
            watch_open: AtomicBool::new(false),
            watch_stop: tokio::sync::Notify::new(),
            accepted: tokio::sync::Mutex::new(BTreeMap::new()),
        })
    }

    fn descriptor(&self) -> Result<ControllerDescriptor, WatchFailure> {
        self.descriptor
            .lock()
            .map_err(|_| WatchFailure::Fatal)?
            .clone()
            .ok_or(WatchFailure::Fatal)
    }

    async fn list_initial_resources(
        &self,
        descriptor: &ControllerDescriptor,
    ) -> Result<InitialList, SourceError> {
        let mut cursor = None;
        let mut resources = Vec::new();
        let mut snapshot_revision = None;
        loop {
            let page = self
                .store
                .list(StoreListRequest {
                    operation: StoreOperationContext {
                        operation_id: "guest-process-initial-list".to_owned(),
                        idempotency_key: None,
                        correlation_id: "guest-process-initial-list".to_owned(),
                        trace_id: None,
                        deadline_ms: 10_000,
                    },
                    zone: descriptor.identity().zone().clone(),
                    resource_types: descriptor.resource_types().cloned().collect(),
                    resource_names: Vec::new(),
                    filters: Vec::new(),
                    page_size: 256,
                    cursor: cursor.take(),
                    projection: StoreProjection::MetadataOnly,
                })
                .await
                .map_err(|_| SourceError::Unavailable)?;
            if snapshot_revision.is_some_and(|revision| revision != page.snapshot_revision) {
                return Err(SourceError::Conflict(page.snapshot_revision));
            }
            snapshot_revision = Some(page.snapshot_revision);
            resources.extend(page.resources);
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        let revision = snapshot_revision.unwrap_or(ZoneRevision::new(1));
        Ok(InitialList {
            resources: resources
                .into_iter()
                .map(|resource| {
                    InitialResource::new(
                        ResourceKey::new(resource.zone, resource.resource_ref, resource.uid),
                        revision,
                    )
                })
                .collect(),
            snapshot_revision: revision,
        })
    }

    async fn list_dependencies(
        &self,
        descriptor: &ControllerDescriptor,
    ) -> Result<Vec<DependencySnapshot>, SourceError> {
        let mut resource_types = descriptor
            .dependency_selectors()
            .iter()
            .map(|selector| selector.resource_type().clone())
            .collect::<Vec<_>>();
        resource_types.sort();
        resource_types.dedup();
        if resource_types.is_empty() {
            return Ok(Vec::new());
        }
        let mut cursor = None;
        let mut resources = Vec::new();
        let mut snapshot_revision = None;
        loop {
            let page = self
                .store
                .list(StoreListRequest {
                    operation: StoreOperationContext {
                        operation_id: "guest-process-dependencies".to_owned(),
                        idempotency_key: None,
                        correlation_id: "guest-process-dependencies".to_owned(),
                        trace_id: None,
                        deadline_ms: 10_000,
                    },
                    zone: descriptor.identity().zone().clone(),
                    resource_types: resource_types.clone(),
                    resource_names: Vec::new(),
                    filters: Vec::new(),
                    page_size: 256,
                    cursor: cursor.take(),
                    projection: StoreProjection::Full,
                })
                .await
                .map_err(|_| SourceError::Unavailable)?;
            if snapshot_revision.is_some_and(|revision| revision != page.snapshot_revision) {
                return Err(SourceError::Conflict(page.snapshot_revision));
            }
            snapshot_revision = Some(page.snapshot_revision);
            resources.extend(page.resources);
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        Ok(resources
            .into_iter()
            .filter(|resource| {
                descriptor.dependency_selectors().iter().any(|selector| {
                    selector.resource_type() == resource.resource_ref.resource_type()
                })
            })
            .map(|resource| {
                DependencySnapshot::new(ResourceSnapshot::new(
                    ResourceKey::new(
                        resource.zone,
                        resource.resource_ref,
                        resource.uid,
                    ),
                    resource.revision,
                    resource.generation,
                    resource.canonical_json.clone(),
                    resource_deleting(&resource.canonical_json),
                ))
            })
            .collect())
    }

    fn watch_request(
        descriptor: &ControllerDescriptor,
        after_revision: ZoneRevision,
    ) -> StoreWatchRequest {
        StoreWatchRequest {
            operation: StoreOperationContext {
                operation_id: "guest-process-watch".to_owned(),
                idempotency_key: None,
                correlation_id: "guest-process-watch".to_owned(),
                trace_id: None,
                deadline_ms: 10_000,
            },
            zone: descriptor.identity().zone().clone(),
            resource_types: descriptor.resource_types().cloned().collect(),
            resource_names: Vec::new(),
            filters: Vec::new(),
            after_revision,
            initial_credits: descriptor.initial_watch_credits(),
            projection: StoreProjection::Full,
        }
    }

    async fn supersede_pending_effects(
        &self,
        target: &ResourceKey,
        generation: ResourceGeneration,
        current_operation_id: &str,
        revision: ZoneRevision,
    ) -> Result<(), SourceError> {
        let operations = self
            .store
            .authority_operations()
            .await
            .map_err(|error| guest_store_error(&error, revision))?;
        for operation in operations {
            if operation.operation_id == current_operation_id
                || operation.state != AuthorityOperationState::Pending
            {
                continue;
            }
            let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&operation.payload) else {
                continue;
            };
            if payload.get("resourceUid").and_then(serde_json::Value::as_str)
                != Some(target.uid().as_str())
                || payload.get("generation").and_then(serde_json::Value::as_u64)
                    != Some(generation.get())
            {
                continue;
            }
            let Some(binding_digest) = payload
                .get("storeBindingDigest")
                .and_then(serde_json::Value::as_str)
            else {
                continue;
            };
            let Ok(capability) = self
                .store
                .resume_authority_operation(operation.operation_id, binding_digest)
                .await
            else {
                continue;
            };
            capability
                .record_effect(AuthorityOperationState::EffectRetryable)
                .await
                .map_err(|error| guest_store_error(&error, revision))?;
        }
        Ok(())
    }

    async fn record_effect_for_operation(
        &self,
        operation_id: &str,
        state: AuthorityOperationState,
        revision: ZoneRevision,
    ) -> Result<(), SourceError> {
        let accepted = self.accepted.lock().await.remove(operation_id);
        if let Some(accepted) = accepted {
            accepted
                .capability
                .record_effect(state)
                .await
                .map_err(|error| guest_store_error(&error, revision))?;
        }
        Ok(())
    }

    async fn record_effect_for_target(
        &self,
        target: &ResourceKey,
        state: AuthorityOperationState,
        revision: ZoneRevision,
    ) -> Result<(), SourceError> {
        let operation_id = {
            self.accepted
                .lock()
                .await
                .iter()
                .find(|(_, accepted)| accepted.target == *target)
                .map(|(operation_id, _)| operation_id.clone())
        };
        if let Some(operation_id) = operation_id {
            self.record_effect_for_operation(&operation_id, state, revision)
                .await?;
        }
        Ok(())
    }

    fn changes_for_batch(
        &self,
        descriptor: &ControllerDescriptor,
        batch: &SharedChangeBatch,
    ) -> Result<Vec<(ChangeRecord, OperationContext, ZoneRevision)>, WatchFailure> {
        batch
            .entries()
            .filter(|entry| {
                descriptor
                    .resource_types()
                    .any(|resource_type| resource_type == entry.resource_type())
            })
            .map(|entry| {
                let target = ResourceKey::new(
                    descriptor.identity().zone().clone(),
                    ResourceRef::new(
                        entry.resource_type().clone(),
                        entry.resource_name().clone(),
                    ),
                    entry.resource_uid().clone(),
                );
                let generation = entry
                    .new_generation()
                    .or(entry.old_generation())
                    .unwrap_or_else(|| ResourceGeneration::new(1).expect("one is valid"));
                let event = entry.event();
                let (field, reason) = match event {
                    ChangeEvent::Created | ChangeEvent::SpecUpdated => (
                        SelectorField::Spec,
                        CoreTriggerReason::SpecGenerationChanged,
                    ),
                    ChangeEvent::StatusUpdated => (
                        SelectorField::Status,
                        CoreTriggerReason::ExecutionStatusChanged,
                    ),
                    ChangeEvent::MetadataUpdated => (
                        SelectorField::Metadata,
                        CoreTriggerReason::ManualReconcile,
                    ),
                    ChangeEvent::FinalizersUpdated => (
                        SelectorField::Finalizers,
                        CoreTriggerReason::FinalizerRequired,
                    ),
                    ChangeEvent::DeletionRequested | ChangeEvent::Deleted => (
                        SelectorField::Deletion,
                        CoreTriggerReason::DeletionRequested,
                    ),
                };
                let operation = OperationContext::new(
                    entry.operation_id().to_owned(),
                    entry.operation_id().to_owned(),
                    entry.correlation_id().to_owned(),
                    None,
                )
                .map_err(|_| WatchFailure::Fatal)?;
                Ok((
                    ChangeRecord {
                        target,
                        revision: batch.revision(),
                        generation,
                        observed_generation: watch_observed_generation(
                            entry.canonical_resource(),
                            generation,
                        ),
                        fields: BTreeSet::from([field]),
                        reasons: BTreeSet::from([reason]),
                        type_is_bound: true,
                        relevant_field_changed: true,
                        own_status_only: event == ChangeEvent::StatusUpdated,
                        owner_consumer_exists: false,
                        dependency_consumer_exists: false,
                        controller_generation_current: true,
                        conditions_require_work: false,
                        unknown_requires_observation: false,
                    },
                    operation,
                    batch.revision(),
                ))
            })
            .collect()
    }

    async fn next_change(
        &self,
    ) -> Result<Option<(ChangeRecord, OperationContext)>, WatchFailure> {
        loop {
            if let Some(revision) = self.acknowledge_after.lock().await.take() {
                let mut watch = self.watch.lock().await;
                if let Some(watch) = watch.as_mut() {
                    let _ = watch.acknowledge(revision).await;
                }
            }
            if let Some((change, operation, revision)) = self.pending.lock().await.pop_front() {
                let next_is_different = self
                    .pending
                    .lock()
                    .await
                    .front()
                    .is_none_or(|next| next.2 != revision);
                if next_is_different {
                    *self.acknowledge_after.lock().await = Some(revision);
                }
                return Ok(Some((change, operation)));
            }
            if self.store.ensure_session_current().is_err() {
                return Err(WatchFailure::Disconnected);
            }
            if !self.watch_open.load(Ordering::Acquire) {
                let mut watch = self.watch.lock().await;
                watch.take();
                return Ok(None);
            }
            let mut watch_guard = self.watch.lock().await;
            let Some(watch) = watch_guard.as_mut() else {
                return Ok(None);
            };
            if !self.watch_open.load(Ordering::Acquire) {
                watch_guard.take();
                return Ok(None);
            }
            let batch = tokio::select! {
                batch = watch.recv() => batch,
                _ = self.watch_stop.notified() => {
                    watch_guard.take();
                    return Ok(None);
                },
            };
            let Some(batch) = batch else {
                if !self.watch_open.load(Ordering::Acquire) {
                    watch_guard.take();
                    return Ok(None);
                }
                match watch.resume().await {
                    Ok(()) => continue,
                    Err(error) if error.kind() == StoreErrorKind::RevisionExpired => {
                        self.watch_open.store(false, Ordering::Release);
                        return Err(WatchFailure::RevisionExpired);
                    }
                    Err(_) => {
                        self.watch_open.store(false, Ordering::Release);
                        return Err(WatchFailure::Disconnected);
                    }
                }
            };
            let descriptor = self.descriptor()?;
            let changes = self.changes_for_batch(&descriptor, &batch)?;
            if changes.is_empty() {
                let _ = watch.acknowledge(batch.revision()).await;
                continue;
            }
            let mut changes = changes.into_iter();
            let first = changes.next().expect("nonempty watch changes");
            let remaining = changes.collect::<Vec<_>>();
            if remaining.is_empty() {
                *self.acknowledge_after.lock().await = Some(batch.revision());
            } else {
                self.pending.lock().await.extend(remaining);
            }
            return Ok(Some((first.0, first.1)));
        }
    }
}

impl RegisteredControllerApi for GuestProcessSource {
    fn register(
        &self,
        descriptor: &ControllerDescriptor,
    ) -> impl Future<Output = Result<(), SourceError>> + Send {
        let descriptor = descriptor.clone();
        async move {
            if descriptor.identity().zone() != &self.zone {
                return Err(SourceError::Integrity);
            }
            *self.descriptor.lock().map_err(|_| SourceError::Integrity)? = Some(descriptor);
            Ok(())
        }
    }

    fn list_initial(
        &self,
        descriptor: &ControllerDescriptor,
    ) -> impl Future<Output = Result<InitialList, SourceError>> + Send {
        let descriptor = descriptor.clone();
        async move { self.list_initial_resources(&descriptor).await }
    }

    fn open_watch(
        &self,
        descriptor: &ControllerDescriptor,
        after_revision: ZoneRevision,
    ) -> impl Future<Output = Result<(), SourceError>> + Send {
        let descriptor = descriptor.clone();
        async move {
            if self.descriptor().map_err(|_| SourceError::Integrity)? != descriptor {
                return Err(SourceError::Integrity);
            }
            let watch = self
                .store
                .open_resource_watch(Self::watch_request(&descriptor, after_revision))
                .await
                .map_err(|_| SourceError::Unavailable)?;
            *self.watch.lock().await = Some(watch);
            self.pending.lock().await.clear();
            *self.acknowledge_after.lock().await = None;
            self.watch_open.store(true, Ordering::Release);
            Ok(())
        }
    }

    fn stop_watch(&self) {
        self.watch_open.store(false, Ordering::Release);
        self.watch_stop.notify_one();
    }

    fn has_watch_stream(&self) -> bool {
        self.watch_open.load(Ordering::Acquire)
    }

    fn receive_watch_change(
        &self,
    ) -> impl Future<Output = Result<Option<(ChangeRecord, OperationContext)>, WatchFailure>> + Send
    {
        self.next_change()
    }

    fn read_fresh(
        &self,
        key: &ResourceKey,
    ) -> impl Future<Output = Result<FreshSnapshot, SourceError>> + Send {
        let key = key.clone();
        let descriptor = self.descriptor().map_err(|_| SourceError::Integrity);
        async move {
            let descriptor = descriptor?;
            match self
                .store
                .get(StoreGetRequest {
                    operation: StoreOperationContext {
                        operation_id: "guest-process-fresh-read".to_owned(),
                        idempotency_key: None,
                        correlation_id: "guest-process-fresh-read".to_owned(),
                        trace_id: None,
                        deadline_ms: 10_000,
                    },
                    zone: key.zone().clone(),
                    target: key.resource_ref().clone(),
                    expected_uid: Some(key.uid().clone()),
                    projection: StoreProjection::Full,
                })
                .await
            {
                Ok(resource) => Ok(FreshSnapshot::Present {
                    target: ResourceSnapshot::new(
                        key,
                        resource.revision,
                        resource.generation,
                        resource.canonical_json.clone(),
                        resource_deleting(&resource.canonical_json),
                    ),
                    dependencies: self.list_dependencies(&descriptor).await?,
                }),
                Err(error) if error.kind() == StoreErrorKind::ResourceNotFound => {
                    Ok(FreshSnapshot::Deleted {
                        key,
                        revision: error.current_revision().unwrap_or(ZoneRevision::new(1)),
                        generation: ResourceGeneration::new(1).expect("one is valid"),
                    })
                }
                Err(_) => Err(SourceError::Unavailable),
            }
        }
    }

    fn write_starting(
        &self,
        context: &ReconcileContext,
    ) -> impl Future<Output = Result<(), SourceError>> + Send {
        let operation_id = context.operation().operation_id().to_owned();
        async move {
            self.accepted.lock().await.remove(&operation_id);
            Ok(())
        }
    }

    fn accept_effect(
        &self,
        context: &ReconcileContext,
        plan: &ReconcilePlan,
    ) -> impl Future<Output = Result<(), SourceError>> + Send {
        let target = context.target().clone();
        let generation = context.generation();
        let revision = context.revision();
        let operation_id = format!(
            "effect:{}",
            guest_effect_claim_digest(self, context, plan)
        );
        let claim_digest = operation_id
            .strip_prefix("effect:")
            .unwrap_or_default()
            .to_owned();
        let effect_ids = plan.effect_ids().to_vec();
        let operation_class = guest_operation_class(context);
        let controller_ref = context.identity().controller_ref().to_canonical_string();
        let target_ref = self
            .target_ref
            .as_ref()
            .map(ResourceRef::to_canonical_string)
            .unwrap_or_else(|| "unbound".to_owned());
        let guest_execution = self.guest_execution.clone();
        async move {
            let store_binding_digest = self
                .store
                .authority_binding_digest(&claim_digest)
                .map_err(|error| guest_store_error(&error, revision))?;
            self.supersede_pending_effects(
                &target,
                generation,
                &operation_id,
                revision,
            )
            .await?;
            let payload = serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "kind": "controller-effect",
                "state": "pending",
                "operationClass": operation_class,
                "effectIds": effect_ids,
                "resourceUid": target.uid().as_str(),
                "generation": generation.get(),
                "operationId": operation_id,
                "claimDigest": claim_digest,
                "storeBindingDigest": store_binding_digest,
                "assignment": {
                    "resourceUid": target.uid().as_str(),
                    "resourceRevision": revision.get(),
                    "providerGeneration": guest_execution.provider_generation().get(),
                    "controllerGeneration": guest_execution.controller_generation().get(),
                    "controllerRole": controller_ref,
                    "target": target_ref,
                    "sessionGeneration": guest_execution.session_generation().get(),
                    "epoch": guest_execution.assignment_epoch(),
                    "scope": "primary",
                },
                "guestExecution": {
                    "targetUid": guest_execution.target_uid().as_str(),
                    "bootIdentityDigest": guest_execution.boot_identity_digest().to_hex(),
                    "sessionGeneration": guest_execution.session_generation().get(),
                    "assignmentEpoch": guest_execution.assignment_epoch(),
                    "providerGeneration": guest_execution.provider_generation().get(),
                    "controllerGeneration": guest_execution.controller_generation().get(),
                },
            }))
            .map_err(|_| SourceError::Integrity)?;
            let capability = self
                .store
                .prepare_authority_operation(operation_id, payload, &claim_digest)
                .await
                .map_err(|error| guest_store_error(&error, revision))?;
            self.accepted.lock().await.insert(
                context.operation().operation_id().to_owned(),
                GuestAcceptedEffect {
                    capability,
                    target,
                },
            );
            Ok(())
        }
    }

    fn complete_effect(
        &self,
        context: &ReconcileContext,
        result: &ReconcileResult,
    ) -> impl Future<Output = Result<(), SourceError>> + Send {
        let operation_id = context.operation().operation_id().to_owned();
        let state = guest_result_state(result.disposition());
        let revision = context.revision();
        async move {
            self.record_effect_for_operation(&operation_id, state, revision)
                .await
        }
    }

    fn commit_result(
        &self,
        context: &ReconcileContext,
        result: &ReconcileResult,
    ) -> impl Future<Output = Result<CommitOutcome, SourceError>> + Send {
        let key = context.target().clone();
        let mutation = result
            .mutation_batch()
            .and_then(|batch| batch.mutations().first().cloned());
        let status = result.status_candidate().map(ToOwned::to_owned);
        async move {
            let resource = self.current_resource(&key).await?;
            if let Some(mutation) = mutation.as_ref() {
                match mutation.kind() {
                    MutationIntentKind::Delete => {
                        let response = self.client.delete(delete_request(&resource)).await;
                        return response_to_commit(response.error.is_some(), response.revision);
                    }
                    MutationIntentKind::UpdateFinalizers => {
                        let desired = mutation
                            .canonical_resource()
                            .ok_or(SourceError::Integrity)?;
                        let (add, remove) = finalizer_delta(&resource.canonical_json, desired)?;
                        let response = self
                            .client
                            .update_finalizers(finalizer_request(&resource, add, remove))
                            .await;
                        return response_to_commit(response.error.is_some(), response.revision);
                    }
                    _ => return Err(SourceError::Integrity),
                }
            }
            if let Some(status) = status.as_deref() {
                let canonical = merge_status_candidate(&resource, status)?;
                let response = self
                    .client
                    .update_status(status_request(&resource, canonical)?)
                    .await;
                return response_to_commit(response.error.is_some(), response.revision);
            }
            Ok(CommitOutcome::Committed(resource.revision))
        }
    }

    fn complete_expedited(
        &self,
        context: &ReconcileContext,
        projection: &d2b_core_controller::ReconcileProjection,
        _status_persistence: StatusPersistence,
    ) -> impl Future<Output = Result<(), SourceError>> + Send {
        let operation_id = context.operation().operation_id().to_owned();
        let state = guest_projection_state(projection);
        let revision = context.revision();
        async move {
            self.record_effect_for_operation(&operation_id, state, revision)
                .await
        }
    }

    fn persist_outcome(
        &self,
        projection: &d2b_core_controller::ReconcileProjection,
    ) -> impl Future<Output = Result<(), SourceError>> + Send {
        let target = projection.target().clone();
        let phase = projection.phase();
        async move {
            let resource = self.current_resource(&target).await?;
            let canonical = status_phase_candidate(&resource, phase)?;
            let response = self
                .client
                .update_status(status_request(&resource, canonical)?)
                .await;
            if response.error.is_some() {
                Err(SourceError::Unavailable)
            } else {
                self.record_effect_for_target(
                    &target,
                    guest_projection_state(projection),
                    resource.revision,
                )
                .await
            }
        }
    }

    fn checkpoint(
        &self,
        _context: &ReconcileContext,
        _revision: ZoneRevision,
    ) -> impl Future<Output = Result<(), SourceError>> + Send {
        std::future::ready(Ok(()))
    }

    fn schedule_requeue(
        &self,
        _key: &ResourceKey,
        _at_tick: u64,
    ) -> impl Future<Output = Result<(), SourceError>> + Send {
        std::future::ready(Ok(()))
    }
}

impl GuestProcessSource {
    async fn current_resource(&self, key: &ResourceKey) -> Result<StoredResource, SourceError> {
        self.store
            .get(StoreGetRequest {
                operation: StoreOperationContext {
                    operation_id: "guest-process-current-resource".to_owned(),
                    idempotency_key: None,
                    correlation_id: "guest-process-current-resource".to_owned(),
                    trace_id: None,
                    deadline_ms: 10_000,
                },
                zone: key.zone().clone(),
                target: key.resource_ref().clone(),
                expected_uid: Some(key.uid().clone()),
                projection: StoreProjection::Full,
            })
            .await
            .map_err(|error| {
                if error.kind() == StoreErrorKind::ResourceConflict {
                    SourceError::Conflict(error.current_revision().unwrap_or(key_revision(key)))
                } else {
                    SourceError::Unavailable
                }
            })
    }
}

fn key_revision(_key: &ResourceKey) -> ZoneRevision {
    ZoneRevision::new(1)
}

fn watch_observed_generation(
    canonical_resource: Option<&[u8]>,
    fallback: ResourceGeneration,
) -> d2b_contracts_resource::v3::ObservedGeneration {
    canonical_resource
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(bytes).ok())
        .and_then(|value| {
            value
                .pointer("/status/observedGeneration")
                .and_then(serde_json::Value::as_u64)
                .map(d2b_contracts_resource::v3::ObservedGeneration::new)
        })
        .unwrap_or_else(|| {
            d2b_contracts_resource::v3::ObservedGeneration::new(fallback.get().saturating_sub(1))
        })
}

fn resource_deleting(canonical_resource: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(canonical_resource)
        .ok()
        .and_then(|value| value.pointer("/metadata/deletionRequestedAt").cloned())
        .is_some_and(|value| !value.is_null())
}

fn response_to_commit(failed: bool, revision: u64) -> Result<CommitOutcome, SourceError> {
    if failed {
        Err(SourceError::Unavailable)
    } else {
        Ok(CommitOutcome::Committed(ZoneRevision::new(revision)))
    }
}

fn status_phase_candidate(
    resource: &StoredResource,
    phase: ResourcePhase,
) -> Result<Vec<u8>, SourceError> {
    let mut value =
        CanonicalJsonValue::parse(&resource.canonical_json).map_err(|_| SourceError::Integrity)?;
    let CanonicalJsonValue::Object(root) = &mut value else {
        return Err(SourceError::Integrity);
    };
    let Some(CanonicalJsonValue::Object(status)) = root.get_mut("status") else {
        return Err(SourceError::Integrity);
    };
    status.insert("phase".to_owned(), phase_json(phase));
    status.insert(
        "observedGeneration".to_owned(),
        CanonicalJsonValue::Integer(resource.generation.get() as i64),
    );
    status.insert(
        "lastReconciledAt".to_owned(),
        CanonicalJsonValue::String(now_timestamp()),
    );
    Ok(value.to_canonical_bytes())
}

fn merge_status_candidate(
    resource: &StoredResource,
    candidate: &[u8],
) -> Result<Vec<u8>, SourceError> {
    let mut value =
        CanonicalJsonValue::parse(&resource.canonical_json).map_err(|_| SourceError::Integrity)?;
    let candidate = CanonicalJsonValue::parse(candidate).map_err(|_| SourceError::Integrity)?;
    let CanonicalJsonValue::Object(root) = &mut value else {
        return Err(SourceError::Integrity);
    };
    let CanonicalJsonValue::Object(candidate) = candidate else {
        return Err(SourceError::Integrity);
    };
    root.insert("status".to_owned(), CanonicalJsonValue::Object(candidate));
    Ok(value.to_canonical_bytes())
}

fn finalizer_delta(
    current: &[u8],
    desired: &[u8],
) -> Result<(Vec<String>, Vec<String>), SourceError> {
    let current = CanonicalJsonValue::parse(current).map_err(|_| SourceError::Integrity)?;
    let desired = CanonicalJsonValue::parse(desired).map_err(|_| SourceError::Integrity)?;
    let finalizers = |value: &CanonicalJsonValue| -> Result<BTreeSet<String>, SourceError> {
        let CanonicalJsonValue::Object(root) = value else {
            return Err(SourceError::Integrity);
        };
        let CanonicalJsonValue::Object(metadata) =
            root.get("metadata").ok_or(SourceError::Integrity)?
        else {
            return Err(SourceError::Integrity);
        };
        let CanonicalJsonValue::Array(values) =
            metadata.get("finalizers").ok_or(SourceError::Integrity)?
        else {
            return Err(SourceError::Integrity);
        };
        values
            .iter()
            .map(|value| match value {
                CanonicalJsonValue::String(value) => Ok(value.clone()),
                _ => Err(SourceError::Integrity),
            })
            .collect()
    };
    let current = finalizers(&current)?;
    let desired = finalizers(&desired)?;
    Ok((
        desired.difference(&current).cloned().collect(),
        current.difference(&desired).cloned().collect(),
    ))
}

fn snapshot_wire_identity(resource: &StoredResource) -> wire::ResourceIdentity {
    let mut identity = wire::ResourceIdentity::new();
    identity.zone = resource.zone.as_str().to_owned();
    identity.resource_type = resource.resource_ref.resource_type().as_str().to_owned();
    identity.name = resource.resource_ref.name().as_str().to_owned();
    identity.uid = Some(resource.uid.as_str().to_owned());
    identity.generation = Some(resource.generation.get());
    identity.revision = Some(resource.revision.get());
    identity
}

fn guest_request_meta(action: &str, resource: &StoredResource) -> wire::RequestMeta {
    let operation = format!(
        "guest-process-{action}-{}-{}",
        resource.resource_ref.to_canonical_string(),
        resource.revision.get()
    );
    let mut meta = wire::RequestMeta::new();
    meta.operation_id = operation.clone();
    meta.idempotency_key = operation.clone();
    meta.correlation_id = operation;
    meta.deadline_ms = 10_000;
    meta
}

fn exact_snapshot_precondition(resource: &StoredResource) -> wire::Precondition {
    let mut precondition = wire::Precondition::new();
    precondition.kind =
        protobuf::EnumOrUnknown::new(wire::PreconditionKind::PRECONDITION_KIND_EXACT_REVISION);
    precondition.expected_revision = Some(resource.revision.get());
    precondition.expected_uid = Some(resource.uid.as_str().to_owned());
    precondition
}

fn delete_request(resource: &StoredResource) -> wire::DeleteRequest {
    let mut mutation = wire::Mutation::new();
    mutation.kind = protobuf::EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_DELETE);
    mutation.target = protobuf::MessageField::some(snapshot_wire_identity(resource));
    mutation.precondition = protobuf::MessageField::some(exact_snapshot_precondition(resource));
    let mut request = wire::DeleteRequest::new();
    request.meta = protobuf::MessageField::some(guest_request_meta("delete", resource));
    request.mutation = protobuf::MessageField::some(mutation);
    request
}

fn finalizer_request(
    resource: &StoredResource,
    add: Vec<String>,
    remove: Vec<String>,
) -> wire::UpdateFinalizersRequest {
    let mut mutation = wire::Mutation::new();
    mutation.kind =
        protobuf::EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_UPDATE_FINALIZERS);
    mutation.target = protobuf::MessageField::some(snapshot_wire_identity(resource));
    mutation.precondition = protobuf::MessageField::some(exact_snapshot_precondition(resource));
    mutation.add_finalizers = add;
    mutation.remove_finalizers = remove;
    let mut request = wire::UpdateFinalizersRequest::new();
    request.meta = protobuf::MessageField::some(guest_request_meta("finalizers", resource));
    request.mutation = protobuf::MessageField::some(mutation);
    request
}

fn status_request(
    resource: &StoredResource,
    canonical: Vec<u8>,
) -> Result<wire::UpdateStatusRequest, SourceError> {
    let envelope = ResourceEnvelope::from_json(&canonical).map_err(|_| SourceError::Integrity)?;
    let digest = envelope.digest().map_err(|_| SourceError::Integrity)?;
    let mut body = wire::ResourceEnvelopeBytes::new();
    body.identity = protobuf::MessageField::some(snapshot_wire_identity(resource));
    body.canonical_json = canonical;
    body.payload_digest = digest;
    let mut mutation = wire::Mutation::new();
    mutation.kind = protobuf::EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_UPDATE_STATUS);
    mutation.target = protobuf::MessageField::some(snapshot_wire_identity(resource));
    mutation.precondition = protobuf::MessageField::some(exact_snapshot_precondition(resource));
    mutation.resource = protobuf::MessageField::some(body);
    let mut request = wire::UpdateStatusRequest::new();
    request.meta = protobuf::MessageField::some(guest_request_meta("status", resource));
    request.mutation = protobuf::MessageField::some(mutation);
    Ok(request)
}

/// Run Guest-local Process/EphemeralProcess reconciliation through the
/// shared Runner and the session-bound watch.
pub(crate) async fn run_guest_process_reconciliation(
    mut runtime: ProcessResourceRuntime,
    store: Arc<SessionBoundStore>,
    client: Arc<ResourceApiClient<SessionBoundStore, UnavailableUpgradeDispatcher>>,
    zone: ZoneId,
) {
    runtime.set_status_client(Arc::clone(&client));
    let controller_ref = match ResourceRef::parse("Process/guest-process-controller") {
        Ok(value) => value,
        Err(_) => return,
    };
    let provider_ref = match ResourceRef::parse("Provider/system-core") {
        Ok(value) => value,
        Err(_) => return,
    };
    let host_ref = match ResourceRef::parse("Host/host-system") {
        Ok(value) => value,
        Err(_) => return,
    };
    let controller_generation = runtime.controller_generation;
    let guest_execution = runtime
        .guest_execution
        .as_ref()
        .cloned();
    let Some(guest_execution) = guest_execution else {
        return;
    };
    let provider_generation = guest_execution.provider_generation();
    let identity = match ControllerIdentity::new(
        zone.clone(),
        controller_ref.clone(),
        controller_generation,
        provider_ref,
        provider_generation,
        controller_ref,
        host_ref,
        runtime.target.clone(),
    ) {
        Ok(identity) => identity,
        Err(_) => return,
    };
    let descriptor = match process_controller_descriptor(identity) {
        Ok(descriptor) => descriptor,
        Err(_) => return,
    };
    let target = runtime.target.clone();
    let api = GuestProcessSource::new(
        zone,
        target,
        guest_execution,
        store,
        client,
    );
    let source = d2b_core_controller::CoreControllerSource::new(descriptor.clone(), api);
    let wake_source = Arc::downgrade(&source);
    runtime.set_liveness_waker(Arc::new(move |key, revision| {
        if let Some(source) = wake_source.upgrade() {
            let _ = source.dispatch_observation(key, revision);
        }
    }));
    let handler = ProcessResourceReconciler::new(descriptor.clone(), runtime);
    let runner = d2b_core_controller::Runner::new(
        handler,
        source,
        d2b_core_controller::RunnerConfig {
            policy_revision: 1,
            api_revision: 1,
            configuration_revision: d2b_contracts_resource::v3::ConfigurationGeneration::new(1)
                .expect("one is valid"),
            deadline_tick: 5_000,
            max_attempts: 3,
        },
    );
    if let Err(error) = runner.run().await {
        tracing::warn!(error = %error, "Guest Process shared runner stopped");
    }
}

#[cfg(test)]
mod tests {
    use d2b_process_conformance::{
        AdoptionCandidate, AdoptionCondition, ObservedIdentity, ProcessIdentityDigest,
        ProcessPhaseClass, ProcessStatusReport, WaitReapOwner, testing::fixtures,
    };

    use super::*;

    #[test]
    fn process_requests_use_both_generic_resource_types() {
        let zone = ZoneId::parse("test").expect("valid zone");
        let request = process_list_request(&zone);
        assert_eq!(request.resource_types.len(), 2);
        assert_eq!(request.resource_types[0].as_str(), PROCESS_TYPE);
        assert_eq!(request.resource_types[1].as_str(), EPHEMERAL_PROCESS_TYPE);
    }

    #[test]
    fn unsupported_provider_is_rejected_before_lifecycle_effects() {
        let provider = ResourceRef::parse("Provider/audio-pipewire").expect("valid provider");
        assert_eq!(
            provider.name().as_str(),
            "audio-pipewire",
            "the decoder keeps Provider identity opaque until the fixed allow-list"
        );
    }

    #[test]
    fn deletion_retains_finalizer_when_guest_execution_is_unavailable() {
        assert!(matches!(
            deletion_adoption(Err(GUEST_EXECUTION_UNAVAILABLE.to_owned())),
            Err(ProcessResourceRuntimeError::ProviderEffect)
        ));
        assert!(matches!(
            deletion_adoption(Err("provider-ticket:other".to_owned())),
            Err(ProcessResourceRuntimeError::ProviderEffect)
        ));
    }

    fn adopted_report() -> ProcessStatusReport {
        ProcessStatusReport {
            provider: d2b_contracts_resource::v3::execution_policy::BoundedToken::parse(
                "system-minijail",
            )
            .expect("provider token"),
            identity: ProcessIdentityDigest::from_bytes([0x51; 32]),
            wait_reap_owner: WaitReapOwner::Local,
            execution_ref: ResourceRef::parse("Host/host-system").expect("execution ref"),
            domain: d2b_contracts_resource::v3::execution_policy::ExecutionDomain::System,
            user_ref: None,
            digests: fixtures::compiled_digests(),
            phase: ProcessPhaseClass::Ready,
            last_exit: None,
            adoption: AdoptionCondition::Adopted,
        }
    }

    #[test]
    fn missing_controller_bootstrap_stops_before_fresh_launch() {
        let controller = serde_json::from_str::<ProcessSpec>(
            r#"{"executionRef":"Host/host-system","processClass":"controller","template":"controller-main"}"#,
        )
        .expect("static controller process");
        assert_eq!(
            controller.execution().process_class(),
            d2b_contracts_resource::v3::process::ProcessClass::Controller
        );
        assert_eq!(
            controller.execution().template().as_str(),
            "controller-main"
        );
        let adoption = ProviderAdoption::ControllerBootstrapMissing;
        let plan = start_record_plan(&adoption, &DesiredProcess::Process(controller))
            .expect("controller restart plan")
            .expect("controller restart action");
        assert!(!plan.adopted);

        let mut effects = Vec::new();
        for effect in plan.effects {
            effects.push(match effect {
                StartRecordEffect::StopAndFinalize => "stop-and-finalize",
                StartRecordEffect::Launch => "launch",
            });
        }
        assert_eq!(effects, ["stop-and-finalize", "launch"]);
    }

    #[test]
    fn ordinary_process_adoption_remains_adopted_without_a_second_launch() {
        let worker = serde_json::from_str::<ProcessSpec>(
            r#"{"executionRef":"Host/host-system","processClass":"worker","template":"reaction"}"#,
        )
        .expect("ordinary process");
        let adoption = ProviderAdoption::Adopted(adopted_report());
        let plan = start_record_plan(&adoption, &DesiredProcess::Process(worker))
            .expect("ordinary adoption plan")
            .expect("ordinary adoption result");
        assert!(plan.adopted);
        assert!(plan.effects.is_empty());
    }

    #[test]
    fn stale_deletion_selects_exact_candidate_but_ambiguity_blocks() {
        let candidate = AdoptionCandidate {
            identity: ProcessIdentityDigest::from_bytes([0x42; 32]),
            observed: ObservedIdentity::from_verified([
                d2b_process_conformance::IdentityBinding::Pid,
                d2b_process_conformance::IdentityBinding::ProcessStartTime,
                d2b_process_conformance::IdentityBinding::Cgroup,
                d2b_process_conformance::IdentityBinding::Template,
                d2b_process_conformance::IdentityBinding::Generation,
            ]),
            wait_reap_owner: WaitReapOwner::Local,
        };
        let report = ProcessStatusReport {
            provider: d2b_contracts_resource::v3::execution_policy::BoundedToken::parse(
                "system-minijail",
            )
            .expect("provider token"),
            identity: candidate.identity,
            wait_reap_owner: WaitReapOwner::Local,
            execution_ref: ResourceRef::parse("Host/host-system").expect("execution ref"),
            domain: d2b_contracts_resource::v3::execution_policy::ExecutionDomain::System,
            user_ref: None,
            digests: fixtures::compiled_digests(),
            phase: ProcessPhaseClass::Unknown,
            last_exit: None,
            adoption: AdoptionCondition::Quarantined,
        };
        assert_eq!(
            stale_candidate_for_deletion(ProviderAdoption::Stale {
                candidate: candidate.clone(),
            })
            .expect("stale candidate")
            .expect("exact stale candidate")
            .identity,
            candidate.identity
        );
        assert_eq!(
            stale_candidate_for_deletion(ProviderAdoption::Quarantined(report)),
            Err(ProcessResourceRuntimeError::IdentityAmbiguous)
        );
    }

    #[test]
    fn status_projection_keeps_the_complete_envelope_valid() {
        let resource_ref = ResourceRef::parse("Process/status-projection").expect("resource ref");
        let process = serde_json::from_str::<ProcessSpec>(
            r#"{"executionRef":"Host/host-system","processClass":"worker","template":"reaction"}"#,
        )
        .expect("minimal Process spec");
        let resource = StoredResource {
            resource_ref: resource_ref.clone(),
            zone: ZoneId::parse("dev").expect("zone"),
            uid: d2b_contracts_resource::v3::ResourceUid::parse(
                "123e4567-e89b-42d3-a456-426614174000",
            )
            .expect("uid"),
            generation: d2b_contracts_resource::v3::ResourceGeneration::new(1).expect("generation"),
            revision: ZoneRevision::new(1),
            canonical_json: br#"{"apiVersion":"resources.d2bus.org/v3","metadata":{"configurationGeneration":1,"createdAt":"2026-07-22T00:00:00.000Z","deletionRequestedAt":null,"finalizers":[],"generation":1,"managedBy":"configuration","name":"status-projection","ownerRef":null,"revision":1,"uid":"123e4567-e89b-42d3-a456-426614174000","updatedAt":"2026-07-22T00:00:00.000Z","zone":"dev"},"spec":{"executionRef":"Host/host-system","processClass":"worker","template":"reaction"},"status":{"completedAt":null,"conditions":[],"lastReconciledAt":null,"observedGeneration":0,"outcome":null,"phase":"Pending","resource":{},"startedAt":null,"update":{"dependencies":{"count":0,"refs":[]},"disruption":"None","lastAssessedAt":null,"observedGeneration":0,"operationId":null,"owned":{"count":0,"refs":[]},"preserveState":true,"reasons":[],"state":"Unknown","targetGeneration":1}},"type":"Process"}"#.to_vec(),
            payload_digest: "sha256:".to_owned(),
        };
        let record = DesiredRecord {
            resource,
            provider_ref: ResourceRef::parse("Provider/system-minijail").expect("provider ref"),
            process: DesiredProcess::Process(process),
            zone_uid: None,
            policy_revision: None,
            provider_assignment_generation: None,
            controller_provider_uid: None,
            controller_provider_generation: None,
        };
        let canonical = status_payload(
            &record,
            ResourcePhase::Ready,
            2,
            Some(OutcomeState::ready(false)),
        )
        .expect("status payload");
        let envelope = ResourceEnvelope::from_json(&canonical).expect("valid envelope");
        assert_eq!(envelope.status().phase(), ResourcePhase::Ready);
        assert_eq!(
            envelope
                .status()
                .resource()
                .get("restartCount")
                .and_then(|value| match value {
                    CanonicalJsonValue::Integer(value) => Some(*value),
                    _ => None,
                }),
            Some(2)
        );
        assert!(d2b_contracts_resource::v3::Timestamp::parse(now_timestamp()).is_ok());
        assert_eq!(record.key(), resource_ref);
        let operation_id = process_operation_id(&record, "status");
        assert!(operation_id.starts_with("process-lifecycle-"));
        let mut recreated = record.clone();
        recreated.resource.uid =
            ResourceUid::parse("223e4567-e89b-42d3-a456-426614174000").expect("new UID");
        assert_ne!(
            operation_id,
            process_operation_id(&recreated, "status"),
            "recreated Process resources must not reuse lifecycle operation identity"
        );
        let mut policy_changed = record.clone();
        policy_changed.policy_revision = Some(2);
        assert_ne!(
            operation_id,
            process_operation_id(&policy_changed, "status"),
            "policy revision must fence Process lifecycle operations"
        );
    }

    #[test]
    fn lifecycle_effects_use_contract_deadlines() {
        let ephemeral = serde_json::from_str::<EphemeralProcessSpec>(
            r#"{"executionRef":"Host/host-system","processClass":"worker","template":"reaction","startDeadline":"7s","runtimeDeadline":"5m","successfulTtl":"1h","failedTtl":"24h","incidentHold":false}"#,
        )
        .expect("ephemeral process spec");
        assert_eq!(
            launch_timeout(&DesiredProcess::Ephemeral(ephemeral)),
            Duration::from_secs(7)
        );

        let process = serde_json::from_str::<ProcessSpec>(
            r#"{"executionRef":"Host/host-system","processClass":"controller","template":"controller-main","drainTimeout":"11s"}"#,
        )
        .expect("process spec");
        assert_eq!(process_drain_timeout(&process), Duration::from_secs(11));
    }

    #[test]
    fn guest_target_selector_is_limited_to_known_guest_scoped_processes() {
        let session_ref =
            ResourceRef::parse("display-wayland.d2bus.org.WaylandSession/display-wayland")
                .expect("session ref");
        let guest_ref = ResourceRef::parse("Guest/work").expect("guest ref");
        let provider_ref = ResourceRef::parse("Provider/system-minijail").expect("provider ref");
        let process = serde_json::from_str::<ProcessSpec>(
            r#"{"executionRef":"Host/host-system","processClass":"worker","template":"reaction"}"#,
        )
        .expect("process");
        let make_record = |owner_ref: &str| DesiredRecord {
            resource: StoredResource {
                resource_ref: ResourceRef::parse("Process/worker").expect("process ref"),
                zone: ZoneId::parse("work").expect("zone"),
                uid: d2b_contracts_resource::v3::ResourceUid::parse(
                    "123e4567-e89b-42d3-a456-426614174000",
                )
                .expect("uid"),
                generation: d2b_contracts_resource::v3::ResourceGeneration::new(1)
                    .expect("generation"),
                revision: ZoneRevision::new(1),
                canonical_json: format!(r#"{{"metadata":{{"ownerRef":"{owner_ref}"}}}}"#)
                    .into_bytes(),
                payload_digest: "sha256:".to_owned(),
            },
            provider_ref: provider_ref.clone(),
            process: DesiredProcess::Process(process.clone()),
            zone_uid: None,
            policy_revision: None,
            provider_assignment_generation: None,
            controller_provider_uid: None,
            controller_provider_generation: None,
        };

        assert_eq!(
            scoped_target_ref(
                &make_record(session_ref.to_canonical_string().as_str()),
                Some(&session_ref),
                Some(&guest_ref),
            ),
            Some(guest_ref.clone())
        );
        assert_eq!(
            scoped_target_ref(
                &make_record("Provider/other"),
                Some(&session_ref),
                Some(&guest_ref),
            ),
            None
        );

        let vmm = serde_json::from_str::<ProcessSpec>(
            r#"{"executionRef":"Host/host-system","processClass":"worker","template":"cloud-hypervisor-runner"}"#,
        )
        .expect("VMM process");
        let vmm_owner = ResourceRef::parse("Guest/acceptance-guest").expect("Guest owner");
        let mut vmm_record = make_record(vmm_owner.to_canonical_string().as_str());
        vmm_record.resource.resource_ref =
            ResourceRef::parse("Process/acceptance-guest-vmm").expect("VMM ref");
        vmm_record.process = DesiredProcess::Process(vmm);
        assert_eq!(scoped_target_ref(&vmm_record, None, None), Some(vmm_owner));
    }

    fn identity_record(revision: u64) -> DesiredRecord {
        let resource_ref = ResourceRef::parse("Process/identity").expect("resource ref");
        let process = serde_json::from_str::<ProcessSpec>(
            r#"{"executionRef":"Host/host-system","processClass":"worker","template":"reaction"}"#,
        )
        .expect("process spec");
        DesiredRecord {
            resource: StoredResource {
                resource_ref,
                zone: ZoneId::parse("work").expect("zone"),
                uid: d2b_contracts_resource::v3::ResourceUid::parse(
                    "123e4567-e89b-42d3-a456-426614174000",
                )
                .expect("uid"),
                generation: d2b_contracts_resource::v3::ResourceGeneration::new(1)
                    .expect("generation"),
                revision: ZoneRevision::new(revision),
                canonical_json: br#"{"metadata":{"finalizers":[]}}"#.to_vec(),
                payload_digest: "sha256:".to_owned(),
            },
            provider_ref: ResourceRef::parse("Provider/system-minijail").expect("provider ref"),
            process: DesiredProcess::Process(process),
            zone_uid: None,
            policy_revision: Some(1),
            provider_assignment_generation: Some(
                d2b_contracts_resource::v3::ResourceGeneration::new(2).expect("generation"),
            ),
            controller_provider_uid: None,
            controller_provider_generation: None,
        }
    }

    #[test]
    fn runtime_effect_identity_does_not_change_when_only_revision_advances() {
        let first = identity_record(3);
        let second = identity_record(9);
        assert_eq!(
            process_operation_id(&first, "launch"),
            process_operation_id(&second, "launch")
        );
        assert_ne!(
            process_mutation_operation_id(&first, "status"),
            process_mutation_operation_id(&second, "status")
        );
    }

    #[test]
    fn restart_launch_effect_identity_changes_after_persisted_exit() {
        let mut first = identity_record(3);
        first.resource.canonical_json =
            br#"{"status":{"resource":{"restartCount":0}}}"#.to_vec();
        let mut restarted = identity_record(9);
        restarted.resource.canonical_json =
            br#"{"status":{"resource":{"restartCount":1}}}"#.to_vec();
        assert_eq!(lifecycle_effect_id(&first.resource), "process-lifecycle-restart-0");
        assert_eq!(
            lifecycle_effect_id(&restarted.resource),
            "process-lifecycle-restart-1"
        );
    }

    #[test]
    fn provider_finalizer_candidate_keeps_exact_runtime_owner() {
        let record = identity_record(1);
        let snapshot = ResourceSnapshot::new(
            ResourceKey::new(
                record.resource.zone.clone(),
                record.resource.resource_ref.clone(),
                record.resource.uid.clone(),
            ),
            record.resource.revision,
            record.resource.generation,
            br#"{"metadata":{"finalizers":[]}}"#.to_vec(),
            false,
        );
        let candidate =
            finalizer_candidate(snapshot.canonical_json(), MINIJAIL_PROCESS_FINALIZER, true)
                .expect("finalizer candidate");
        let value: serde_json::Value = serde_json::from_slice(&candidate).expect("candidate JSON");
        assert_eq!(
            value["metadata"]["finalizers"],
            serde_json::json!([MINIJAIL_PROCESS_FINALIZER])
        );
    }

    #[test]
    fn persisted_ephemeral_cleanup_eligibility_is_authoritative() {
        let mut record = identity_record(1);
        record.resource.resource_ref =
            ResourceRef::parse("EphemeralProcess/finished").expect("ephemeral ref");
        record.resource.canonical_json =
            br#"{"status":{"cleanupEligibleAt":"1970-01-01T00:00:00.000Z"}}"#.to_vec();
        record.process = DesiredProcess::Ephemeral(
            serde_json::from_str(
                r#"{"executionRef":"Host/host-system","processClass":"worker","template":"reaction","incidentHold":false}"#,
            )
            .expect("ephemeral spec"),
        );
        assert!(ephemeral_status_ttl_elapsed(
            &record.resource,
            &record.process
        ));
    }

    #[test]
    fn process_descriptor_uses_one_shared_runner_for_both_resource_types() {
        let identity = ControllerIdentity::new(
            ZoneId::parse("work").expect("zone"),
            ResourceRef::parse("Process/process-controller").expect("controller"),
            ControllerGeneration::new(3).expect("controller generation"),
            ResourceRef::parse("Provider/system-core").expect("provider"),
            d2b_contracts_resource::v3::ResourceGeneration::new(4).expect("provider generation"),
            ResourceRef::parse("Process/process-controller").expect("process"),
            ResourceRef::parse("Host/host-system").expect("host"),
            None,
        )
        .expect("controller identity");
        let descriptor = process_controller_descriptor(identity).expect("descriptor");
        assert_eq!(
            descriptor
                .resource_types()
                .map(|resource_type| resource_type.as_str())
                .collect::<Vec<_>>(),
            vec![EPHEMERAL_PROCESS_TYPE, PROCESS_TYPE]
        );
        assert!(descriptor.finalizers().is_empty(        ));
    }

    #[test]
    fn persisted_ephemeral_completed_at_falls_back_when_cleanup_deadline_is_missing() {
        let mut record = identity_record(1);
        record.resource.resource_ref =
            ResourceRef::parse("EphemeralProcess/completed").expect("ephemeral ref");
        record.resource.canonical_json =
            br#"{"status":{"phase":"Succeeded","completedAt":"1970-01-01T00:00:00.000Z"}}"#
                .to_vec();
        record.process = DesiredProcess::Ephemeral(
            serde_json::from_str(
                r#"{"executionRef":"Host/host-system","processClass":"worker","template":"reaction","successfulTtl":"1s","incidentHold":false}"#,
            )
            .expect("ephemeral spec"),
        );
        assert!(ephemeral_status_ttl_elapsed(
            &record.resource,
            &record.process
        ));
    }
}
