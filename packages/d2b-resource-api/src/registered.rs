//! Production Core source adapter for one redb-backed Zone store.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use d2b_contracts_resource::v3::{
    DEFAULT_REQUEST_DEADLINE_MS, FinalizerId, MAX_LIST_PAGE_SIZE, ObservedGeneration,
    ResourceEnvelope, ResourceGeneration, ResourcePhase, ResourceRef, ResourceUid, ZoneId,
    ZoneRevision, canonical_digest,
};
use d2b_core_controller::{
    ChangeField, ChangeRecord, CommitOutcome, ControllerDescriptor, CoreTriggerReason,
    DependencySnapshot, FreshSnapshot, InitialList, InitialResource, OperationContext,
    ReconcileContext, ReconcilePlan, ReconcileProjection, ReconcileResult, RegisteredControllerApi,
    ResourceKey, SourceError, StatusPersistence, WatchFailure,
};
use d2b_resource_store::{
    ExpectedRevision, ResourceAssignmentFence, ResourceAssignmentScope, ResourceMutationKind,
    StoreCommitResult, StoreError, StoreErrorKind, StoreFilter, StoreGetRequest, StoreListRequest,
    StoreMutation, StoreOperationContext, StoreProjection, StoreWatchRequest, StoredResource,
};
use d2b_resource_store_redb::{ChangeEvent, RedbResourceStore, SharedChangeBatch};
use serde_json::Value;

use crate::authz::{
    ApiMethod, AuthorizationRequest, AuthorizationState, AuthorizationTarget, ResourceVerb,
};
use crate::service::{ResourceService, UpgradeDispatcher};
use crate::store::{CheckedResourceStore, StoreBindingError};
use crate::watch::{ResourceWatch, WatchService};

const TRANSIENT_RETRY_ATTEMPTS: usize = 4;
const TRANSIENT_RETRY_BUDGET: Duration = Duration::from_secs(1);

/// Per-reconcile assignment evidence supplied by the Zone-owned authority.
pub type AssignmentFenceResolver = Arc<
    dyn Fn(
            ResourceRef,
            ResourceUid,
            ZoneRevision,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<ResourceAssignmentFence, SourceError>> + Send,
            >,
        > + Send
        + Sync,
>;

/// Optional production-path observer for durable effect acceptance timing.
pub type EffectAcceptanceObserver = Arc<dyn Fn(&ResourceUid) + Send + Sync>;

/// Optional production-path observer for completed controller passes.
pub type CheckpointObserver = Arc<dyn Fn(&ResourceUid) + Send + Sync>;

/// Optional production-path observer for a durable watch change handed to
/// Core before queue admission.
pub type WatchChangeObserver = Arc<dyn Fn(&ChangeRecord) + Send + Sync>;

async fn retry_source_backpressure<T, F, Fut>(
    mut operation: F,
) -> Result<T, SourceError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, SourceError>>,
{
    match tokio::time::timeout(TRANSIENT_RETRY_BUDGET, async {
        for attempt in 0..TRANSIENT_RETRY_ATTEMPTS {
            match operation().await {
                Ok(value) => return Ok(value),
                Err(SourceError::Backpressure) => {
                    if attempt + 1 == TRANSIENT_RETRY_ATTEMPTS {
                        return Err(SourceError::Backpressure);
                    }
                    tokio::task::yield_now().await;
                }
                Err(error) => return Err(error),
            }
        }
        Err(SourceError::Backpressure)
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(SourceError::Timeout),
    }
}

/// A production `RegisteredControllerApi` backed by one owned redb store.
///
/// The mutation issuer is paired with the acceptor installed in the store by
/// the trusted Zone runtime. No database handle, path, or reusable credential
/// is exposed through the Core source trait.
pub struct RedbRegisteredControllerApi {
    store: Arc<RedbResourceStore>,
    commit: Option<NativeCommitPath>,
    descriptor: Mutex<Option<ControllerDescriptor>>,
    watch: tokio::sync::Mutex<Option<ResourceWatch>>,
    pending: tokio::sync::Mutex<VecDeque<(ChangeRecord, OperationContext, ZoneRevision)>>,
    acknowledge_after: tokio::sync::Mutex<Option<ZoneRevision>>,
    watch_open: AtomicBool,
    watch_stopped: AtomicBool,
    effect_acceptances_in_flight: AtomicUsize,
    watch_stop: tokio::sync::Notify,
    accepted:
        Arc<Mutex<BTreeMap<String, Arc<d2b_resource_store_redb::AuthorityOperationCapability>>>>,
    watch_change_observer: Option<WatchChangeObserver>,
}

struct NativeCommitPath {
    checked: Arc<CheckedResourceStore<crate::store::RedbBackend>>,
    authorizer: Arc<crate::authz::NativeAuthorizer>,
    subject: Arc<crate::AuthenticatedSubjectContext>,
    state: AuthorizationState,
    zone_uid: Option<ResourceUid>,
    assignments: Arc<Mutex<BTreeMap<ResourceRef, ResourceAssignmentFence>>>,
    assignment_resolver: Option<AssignmentFenceResolver>,
    effect_acceptance_observer: Option<EffectAcceptanceObserver>,
    checkpoint_observer: Option<CheckpointObserver>,
    require_assignment: bool,
}

impl core::fmt::Debug for RedbRegisteredControllerApi {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RedbRegisteredControllerApi")
            .field("has_store", &true)
            .field("has_commit_path", &self.commit.is_some())
            .field(
                "has_descriptor",
                &self
                    .descriptor
                    .lock()
                    .map(|value| value.is_some())
                    .unwrap_or(false),
            )
            .field("watch_open", &self.watch_open.load(Ordering::Acquire))
            .finish()
    }
}

impl RedbRegisteredControllerApi {
    /// Bind an adapter through the ResourceService's single native-authorizer
    /// store binding and an authenticated controller identity.
    pub fn with_identity<U>(
        service: &ResourceService<crate::store::RedbBackend, U>,
        subject: crate::AuthenticatedSubjectContext,
        state: AuthorizationState,
        assignments: Vec<(ResourceRef, ResourceAssignmentFence)>,
    ) -> Result<Self, StoreBindingError>
    where
        U: UpgradeDispatcher,
    {
        let checked = service.checked_store();
        let backend = checked.backend();
        let store = backend.store_arc();
        if subject.claims().zone_ref().resource_type().as_str() != "Zone"
            || subject.authorization_state() != &state
        {
            return Err(StoreBindingError);
        }
        let zone = ZoneId::parse(subject.claims().zone_ref().name().as_str())
            .map_err(|_| StoreBindingError)?;
        if zone != *store.identity().zone() {
            return Err(StoreBindingError);
        }
        Ok(Self {
            store,
            commit: Some(NativeCommitPath {
                checked: Arc::new(checked),
                authorizer: service.authorizer_arc(),
                subject: Arc::new(subject),
                state,
                zone_uid: service.zone_uid(),
                assignments: Arc::new(Mutex::new(assignments.into_iter().collect())),
                assignment_resolver: None,
                effect_acceptance_observer: None,
                checkpoint_observer: None,
                require_assignment: true,
            }),
            descriptor: Mutex::new(None),
            watch: tokio::sync::Mutex::new(None),
            pending: tokio::sync::Mutex::new(VecDeque::new()),
            acknowledge_after: tokio::sync::Mutex::new(None),
            watch_open: AtomicBool::new(false),
            watch_stopped: AtomicBool::new(false),
            effect_acceptances_in_flight: AtomicUsize::new(0),
            watch_stop: tokio::sync::Notify::new(),
            accepted: Arc::new(Mutex::new(BTreeMap::new())),
            watch_change_observer: None,
        })
    }

    #[cfg(test)]
    fn for_test_watch(store: Arc<RedbResourceStore>) -> Self {
        Self {
            store,
            commit: None,
            descriptor: Mutex::new(None),
            watch: tokio::sync::Mutex::new(None),
            pending: tokio::sync::Mutex::new(VecDeque::new()),
            acknowledge_after: tokio::sync::Mutex::new(None),
            watch_open: AtomicBool::new(false),
            watch_stopped: AtomicBool::new(false),
            effect_acceptances_in_flight: AtomicUsize::new(0),
            watch_stop: tokio::sync::Notify::new(),
            accepted: Arc::new(Mutex::new(BTreeMap::new())),
            watch_change_observer: None,
        }
    }

    #[cfg(test)]
    fn for_test_unassigned<U>(
        service: &ResourceService<crate::store::RedbBackend, U>,
        subject: crate::AuthenticatedSubjectContext,
        state: AuthorizationState,
    ) -> Result<Self, StoreBindingError>
    where
        U: UpgradeDispatcher,
    {
        let checked = service.checked_store();
        let backend = checked.backend();
        let store = backend.store_arc();
        Ok(Self {
            store,
            commit: Some(NativeCommitPath {
                checked: Arc::new(checked),
                authorizer: service.authorizer_arc(),
                subject: Arc::new(subject),
                state,
                zone_uid: service.zone_uid(),
                assignments: Arc::new(Mutex::new(BTreeMap::new())),
                assignment_resolver: None,
                effect_acceptance_observer: None,
                checkpoint_observer: None,
                require_assignment: false,
            }),
            descriptor: Mutex::new(None),
            watch: tokio::sync::Mutex::new(None),
            pending: tokio::sync::Mutex::new(VecDeque::new()),
            acknowledge_after: tokio::sync::Mutex::new(None),
            watch_open: AtomicBool::new(false),
            watch_stopped: AtomicBool::new(false),
            effect_acceptances_in_flight: AtomicUsize::new(0),
            watch_stop: tokio::sync::Notify::new(),
            accepted: Arc::new(Mutex::new(BTreeMap::new())),
            watch_change_observer: None,
        })
    }

    /// Borrow the store used by this adapter.
    pub fn store(&self) -> &Arc<RedbResourceStore> {
        &self.store
    }

    /// Refresh assignment evidence for every fresh target and commit.
    pub fn with_assignment_fence_resolver(
        mut self,
        resolver: AssignmentFenceResolver,
    ) -> Self {
        if let Some(commit) = self.commit.as_mut() {
            commit.assignment_resolver = Some(resolver);
        }
        self
    }

    /// Attach a non-authorizing observer to the durable effect acceptance
    /// boundary for production-path measurements.
    pub fn with_effect_acceptance_observer(
        mut self,
        observer: EffectAcceptanceObserver,
    ) -> Self {
        if let Some(commit) = self.commit.as_mut() {
            commit.effect_acceptance_observer = Some(observer);
        }
        self
    }

    /// Attach a non-authorizing observer to the completed-pass boundary.
    pub fn with_checkpoint_observer(mut self, observer: CheckpointObserver) -> Self {
        if let Some(commit) = self.commit.as_mut() {
            commit.checkpoint_observer = Some(observer);
        }
        self
    }

    /// Attach a non-authorizing observer to the Core watch handoff boundary.
    pub fn with_watch_change_observer(mut self, observer: WatchChangeObserver) -> Self {
        self.watch_change_observer = Some(observer);
        self
    }

    async fn refresh_assignment(
        &self,
        target: &ResourceRef,
        uid: &ResourceUid,
        revision: ZoneRevision,
    ) -> Result<(), SourceError> {
        let Some(commit) = self.commit.as_ref() else {
            return Ok(());
        };
        let Some(resolver) = commit.assignment_resolver.clone() else {
            return Ok(());
        };
        let fence = resolver(target.clone(), uid.clone(), revision).await?;
        if fence.resource_uid != *uid
            || fence.resource_revision != revision
            || fence.provider_generation.get() == 0
            || fence.controller_generation.get() == 0
            || fence.session_generation.get() == 0
            || fence.epoch == 0
        {
            return Err(SourceError::Integrity);
        }
        commit
            .assignments
            .lock()
            .map_err(|_| SourceError::Integrity)?
            .insert(target.clone(), fence);
        Ok(())
    }

    fn descriptor(&self) -> Result<ControllerDescriptor, SourceError> {
        self.descriptor
            .lock()
            .map_err(|_| SourceError::Integrity)?
            .clone()
            .ok_or(SourceError::Integrity)
    }

    fn operation(label: impl Into<String>) -> StoreOperationContext {
        let operation_id = label.into();
        StoreOperationContext {
            correlation_id: operation_id.clone(),
            operation_id,
            idempotency_key: None,
            trace_id: None,
            deadline_ms: DEFAULT_REQUEST_DEADLINE_MS,
        }
    }

    async fn list_all(
        &self,
        zone: &ZoneId,
        resource_types: Vec<d2b_contracts_resource::v3::ResourceTypeName>,
        projection: StoreProjection,
        label: &str,
    ) -> Result<(Vec<StoredResource>, ZoneRevision), SourceError> {
        let mut restarts = 0;
        'relist: loop {
            let mut cursor = None;
            let mut snapshot_revision = None;
            let mut resources = Vec::new();
            loop {
                let page = match self
                    .store
                    .list(StoreListRequest {
                        operation: Self::operation(format!("{label}:{}", resources.len())),
                        zone: zone.clone(),
                        resource_types: resource_types.clone(),
                        resource_names: Vec::new(),
                        filters: Vec::new(),
                        page_size: MAX_LIST_PAGE_SIZE,
                        cursor: cursor.take(),
                        projection,
                    })
                    .await
                {
                    Ok(page) => page,
                    Err(error)
                        if error.kind() == StoreErrorKind::RevisionExpired && restarts < 3 =>
                    {
                        restarts += 1;
                        continue 'relist;
                    }
                    Err(error) => {
                        return Err(source_error(
                            error,
                            snapshot_revision.unwrap_or_else(|| ZoneRevision::new(1)),
                        ));
                    }
                };
                if let Some(expected) = snapshot_revision
                    && page.snapshot_revision != expected
                {
                    return Err(SourceError::Conflict(page.snapshot_revision));
                }
                snapshot_revision = Some(page.snapshot_revision);
                resources.extend(page.resources);
                match page.next_cursor {
                    Some(next) => cursor = Some(next),
                    None => {
                        return Ok((resources, snapshot_revision.unwrap_or(ZoneRevision::new(0))));
                    }
                }
            }
        }
    }

    async fn read_target(
        &self,
        key: &ResourceKey,
    ) -> Result<Result<StoredResource, ZoneRevision>, SourceError> {
        let retry_deadline = tokio::time::Instant::now() + TRANSIENT_RETRY_BUDGET;
        for attempt in 0..TRANSIENT_RETRY_ATTEMPTS {
            match self
                .store
                .get(StoreGetRequest {
                    operation: Self::operation(format!(
                        "fresh:{}",
                        key.resource_ref().to_canonical_string()
                    )),
                    zone: key.zone().clone(),
                    target: key.resource_ref().clone(),
                    expected_uid: Some(key.uid().clone()),
                    projection: StoreProjection::Full,
                })
                .await
            {
                Ok(resource) => return Ok(Ok(resource)),
                Err(error) if error.kind() == StoreErrorKind::ResourceNotFound => {
                    let revision = match error.current_revision() {
                        Some(revision) => revision,
                        None => self
                            .store
                            .runtime_metadata()
                            .await
                            .map(|metadata| metadata.current_revision)
                            .map_err(|metadata_error| {
                                source_error(metadata_error, ZoneRevision::new(1))
                            })?,
                    };
                    return Ok(Err(revision));
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        StoreErrorKind::Backpressure | StoreErrorKind::StoreBackpressure
                    )
                        && attempt + 1 < TRANSIENT_RETRY_ATTEMPTS
                        && tokio::time::Instant::now() < retry_deadline =>
                {
                    tokio::task::yield_now().await;
                }
                Err(error) if error.kind() == StoreErrorKind::Timeout => {
                    return Err(SourceError::Timeout);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        StoreErrorKind::Backpressure | StoreErrorKind::StoreBackpressure
                    ) =>
                {
                    return Err(SourceError::Backpressure);
                }
                Err(error) => return Err(source_error(error, ZoneRevision::new(1))),
            }
        }
        Err(SourceError::Backpressure)
    }

    async fn dependencies(
        &self,
        descriptor: &ControllerDescriptor,
        zone: &ZoneId,
    ) -> Result<Vec<DependencySnapshot>, SourceError> {
        let mut types = descriptor
            .dependency_selectors()
            .iter()
            .map(|selector| selector.resource_type().clone())
            .collect::<Vec<_>>();
        types.sort();
        types.dedup();
        if types.is_empty() {
            return Ok(Vec::new());
        }
        let (resources, _) = self
            .list_all(zone, types, StoreProjection::BaseOnly, "dependencies")
            .await?;
        Ok(resources
            .into_iter()
            .filter(|resource| {
                descriptor.dependency_selectors().iter().any(|selector| {
                    selector.resource_type() == resource.resource_ref.resource_type()
                        && selector_matches(selector, resource)
                })
            })
            .map(|resource| DependencySnapshot::new(snapshot_from_resource(resource)))
            .collect())
    }

    fn changes_for_batch(
        &self,
        descriptor: &ControllerDescriptor,
        batch: &SharedChangeBatch,
    ) -> Result<Vec<(ChangeRecord, OperationContext, ZoneRevision)>, WatchFailure> {
        let mut changes = Vec::new();
        for entry in batch.entries() {
            let mut entry_changes = change_for_entry(
                self.store.identity().zone(),
                descriptor,
                entry,
                batch.revision(),
            );
            for (change, suffix) in entry_changes.drain(..) {
                let operation_id = format!("watch:{}:{}", batch.revision().get(), suffix);
                let operation = OperationContext::new(
                    operation_id.clone(),
                    operation_id,
                    entry.correlation_id().to_owned(),
                    None,
                )
                .map_err(|_| WatchFailure::Fatal)?;
                changes.push((change, operation, batch.revision()));
            }
        }
        Ok(changes)
    }

    async fn commit_mutations(
        &self,
        context: &ReconcileContext,
        mutations: Vec<StoreMutation>,
        deferred_status: bool,
    ) -> Result<CommitOutcome, SourceError> {
        if mutations.is_empty() {
            return Ok(if deferred_status {
                CommitOutcome::CommittedStatusPending(context.revision())
            } else {
                CommitOutcome::Committed(context.revision())
            });
        }
        let operation = StoreOperationContext {
            operation_id: Self::resource_operation_id(context),
            idempotency_key: Some(context.operation().idempotency_key().to_owned()),
            correlation_id: canonical_digest(
                "d2b:controller-correlation/v1",
                context.operation().correlation_id().as_bytes(),
            ),
            trace_id: context.operation().trace_id().map(str::to_owned),
            deadline_ms: DEFAULT_REQUEST_DEADLINE_MS,
        };
        let outcome = self
            .commit_store_mutations(
                context.target().zone(),
                context.revision(),
                context.target().uid(),
                operation,
                mutations,
            )
            .await?;
        Ok(match outcome {
            CommitOutcome::Committed(revision) if deferred_status => {
                CommitOutcome::CommittedStatusPending(revision)
            }
            other => other,
        })
    }

    async fn commit_store_mutations(
        &self,
        zone: &ZoneId,
        fallback_revision: ZoneRevision,
        context_uid: &ResourceUid,
        operation: StoreOperationContext,
        mutations: Vec<StoreMutation>,
    ) -> Result<CommitOutcome, SourceError> {
        let Some(commit) = self.commit.as_ref() else {
            return Err(SourceError::Integrity);
        };
        let mut mutations = mutations;
        let resolver = commit.assignment_resolver.clone();
        for mutation in &mut mutations {
            let fence = if let Some(resolver) = resolver.as_ref() {
                let expected_revision = match mutation.expected {
                    ExpectedRevision::Exact(revision) => revision,
                    ExpectedRevision::CreateAbsent => return Err(SourceError::Integrity),
                };
                let fence = resolver(
                    mutation.target.clone(),
                    mutation
                        .expected_uid
                        .clone()
                        .unwrap_or_else(|| context_uid.clone()),
                    expected_revision,
                )
                .await?;
                let expected_uid = mutation
                    .expected_uid
                    .as_ref()
                    .unwrap_or(context_uid);
                if fence.resource_uid != *expected_uid
                    || fence.resource_revision != expected_revision
                    || fence.provider_generation.get() == 0
                    || fence.controller_generation.get() == 0
                    || fence.session_generation.get() == 0
                    || fence.epoch == 0
                {
                    return Err(SourceError::Integrity);
                }
                commit
                    .assignments
                    .lock()
                    .map_err(|_| SourceError::Integrity)?
                    .insert(mutation.target.clone(), fence.clone());
                Some(fence)
            } else {
                commit
                    .assignments
                    .lock()
                    .map_err(|_| SourceError::Integrity)?
                    .get(&mutation.target)
                    .cloned()
            };
            if let Some(mut fence) = fence {
                match &mut fence.scope {
                    ResourceAssignmentScope::Primary => {
                        fence.resource_revision = match mutation.expected {
                            ExpectedRevision::Exact(revision) => revision,
                            ExpectedRevision::CreateAbsent => return Err(SourceError::Integrity),
                        };
                    }
                    ResourceAssignmentScope::OwnerChild { owner_revision, .. } => {
                        fence.resource_revision = fallback_revision;
                        *owner_revision = fallback_revision;
                    }
                }
                mutation.assignment = Some(fence);
            } else if commit.require_assignment {
                return Err(SourceError::Integrity);
            }
        }
        let mut targets = Vec::with_capacity(mutations.len() * 2);
        for mutation in &mutations {
            targets.push(AuthorizationTarget {
                resource_type: mutation.target.resource_type().clone(),
                resource_name: Some(mutation.target.name().clone()),
                verb: resource_verb(mutation.kind),
                subresource: match mutation.kind {
                    ResourceMutationKind::UpdateStatus => Some("status".to_owned()),
                    ResourceMutationKind::UpdateFinalizers => Some("finalizers".to_owned()),
                    _ => None,
                },
                execution_ref: commit.subject.claims().execution_ref().cloned(),
            });
            if let Some(owner) = mutation.owner.as_ref() {
                targets.push(AuthorizationTarget {
                    resource_type: owner.resource_type().clone(),
                    resource_name: Some(owner.name().clone()),
                    verb: ResourceVerb::Get,
                    subresource: Some("owner".to_owned()),
                    execution_ref: commit.subject.claims().execution_ref().cloned(),
                });
            }
        }
        let result = retry_source_backpressure(|| async {
            let grant = commit
                .authorizer
                .authorize(
                    commit.subject.claims(),
                    &AuthorizationRequest {
                        method: ApiMethod::CommitBatch,
                        zone: zone.clone(),
                        targets: targets.clone(),
                    },
                    &commit.state,
                )
                .map_err(|_| SourceError::Integrity)?;
            let admitted = if let Some(zone_uid) = commit.zone_uid.clone() {
                grant.admit_with_zone_uid(mutations.clone(), operation.clone(), zone_uid)
            } else {
                grant.admit(mutations.clone(), operation.clone())
            }
            .map_err(|_| SourceError::Integrity)?;
            commit.checked.commit(admitted).await.map_err(|error| {
                if is_conflict(&error) {
                    SourceError::Conflict(error.current_revision().unwrap_or(fallback_revision))
                } else {
                    source_error(error, fallback_revision)
                }
            })
        })
        .await;
        match result {
            Ok(StoreCommitResult { revision, .. }) => Ok(CommitOutcome::Committed(revision)),
            Err(SourceError::Conflict(revision)) => Ok(CommitOutcome::Conflict(revision)),
            Err(error) => Err(error),
        }
    }

    fn resource_operation_id(context: &ReconcileContext) -> String {
        canonical_digest(
            "d2b:controller-resource-operation/v1",
            format!(
                "{}:{}:{}",
                context.operation().operation_id(),
                context.attempt(),
                context.revision().get(),
            )
            .as_bytes(),
        )
    }

    fn effect_identity(
        &self,
        context: &ReconcileContext,
        plan: &ReconcilePlan,
    ) -> Result<(String, String, &'static str, Vec<String>), SourceError> {
        let Some(commit) = self.commit.as_ref() else {
            return Err(SourceError::Integrity);
        };
        let assignments = commit
            .assignments
            .lock()
            .map_err(|_| SourceError::Integrity)?;
        let assignment = assignments.get(context.target().resource_ref());
        if commit.require_assignment && assignment.is_none() {
            return Err(SourceError::Integrity);
        }
        if assignment.is_some_and(|assignment| assignment.resource_uid != *context.target().uid()) {
            return Err(SourceError::Integrity);
        }
        let operation_class = operation_class(context);
        let claim_digest = effect_claim_digest(
            operation_class,
            context.target().uid(),
            context.generation(),
            plan.effect_ids(),
            assignment,
        );
        Ok((
            format!("effect:{claim_digest}"),
            claim_digest,
            operation_class,
            plan.effect_ids().to_vec(),
        ))
    }

    async fn finalizer_first(
        &self,
        descriptor: &ControllerDescriptor,
        context: &ReconcileContext,
    ) -> Result<Option<StoreMutation>, SourceError> {
        if context
            .reasons()
            .contains(d2b_core_controller::CoreTriggerReason::DeletionRequested)
            || context
                .reasons()
                .contains(d2b_core_controller::CoreTriggerReason::FinalizerRequired)
        {
            return Ok(None);
        }
        let finalizers = descriptor
            .finalizers()
            .iter()
            .map(|value| FinalizerId::parse(value.clone()).map_err(|_| SourceError::Integrity))
            .collect::<Result<BTreeSet<_>, _>>()?;
        if finalizers.is_empty() {
            return Ok(None);
        }
        let resource = match self.read_target(context.target()).await? {
            Ok(resource) => resource,
            Err(_) => return Ok(None),
        };
        let current = finalizer_set(&resource.canonical_json)?;
        let missing = finalizers.difference(&current).cloned().collect::<Vec<_>>();
        if missing.is_empty() {
            return Ok(None);
        }
        Ok(Some(StoreMutation {
            kind: ResourceMutationKind::UpdateFinalizers,
            zone: context.target().zone().clone(),
            target: context.target().resource_ref().clone(),
            expected: ExpectedRevision::Exact(resource.revision),
            expected_uid: Some(resource.uid),
            owner: None,
            canonical_resource: None,
            add_finalizers: missing,
            remove_finalizers: Vec::new(),
            wait_for_reconcile: false,
            reconcile_deadline_ms: None,
            configuration_generation: None,
            assignment: None,
        }))
    }

    async fn persist_projection_status(
        &self,
        projection: &ReconcileProjection,
    ) -> Result<(), SourceError> {
        if projection.event_only() {
            return Ok(());
        }
        let current = match self.read_target(projection.target()).await? {
            Ok(resource) => resource,
            Err(revision) => return Err(SourceError::Conflict(revision)),
        };
        if current.uid != *projection.target().uid() || current.revision != projection.revision() {
            return Err(SourceError::Conflict(current.revision));
        }
        let mut resource =
            d2b_contracts_resource::v3::CanonicalJsonValue::parse(&current.canonical_json)
                .map_err(|_| SourceError::Integrity)?;
        let canonical_resource = {
            let d2b_contracts_resource::v3::CanonicalJsonValue::Object(root) = &mut resource else {
                return Err(SourceError::Integrity);
            };
            let Some(d2b_contracts_resource::v3::CanonicalJsonValue::Object(status)) =
                root.get_mut("status")
            else {
                return Err(SourceError::Integrity);
            };
            status.insert(
                "phase".to_owned(),
                d2b_contracts_resource::v3::CanonicalJsonValue::String(format!(
                    "{}",
                    resource_phase_name(projection.phase())
                )),
            );
            resource.to_canonical_bytes()
        };
        let mutation = StoreMutation {
            kind: ResourceMutationKind::UpdateStatus,
            zone: current.zone.clone(),
            target: current.resource_ref.clone(),
            expected: ExpectedRevision::Exact(current.revision),
            expected_uid: Some(current.uid.clone()),
            owner: None,
            canonical_resource: Some(canonical_resource),
            add_finalizers: Vec::new(),
            remove_finalizers: Vec::new(),
            wait_for_reconcile: false,
            reconcile_deadline_ms: None,
            configuration_generation: None,
            assignment: None,
        };
        let operation_id = format!(
            "projection-{}-{}",
            projection.revision().get(),
            current.uid.as_str()
        );
        let operation = StoreOperationContext {
            operation_id,
            idempotency_key: None,
            correlation_id: canonical_digest(
                "d2b:projection-correlation/v1",
                projection.reason_code().as_bytes(),
            ),
            trace_id: None,
            deadline_ms: DEFAULT_REQUEST_DEADLINE_MS,
        };
        match self
            .commit_store_mutations(
                &current.zone,
                current.revision,
                &current.uid,
                operation,
                vec![mutation],
            )
            .await?
        {
            CommitOutcome::Committed(_) | CommitOutcome::CommittedStatusPending(_) => Ok(()),
            CommitOutcome::Conflict(revision) => Err(SourceError::Conflict(revision)),
        }
    }

    fn effect_capability(
        &self,
        operation_id: &str,
    ) -> Result<Option<Arc<d2b_resource_store_redb::AuthorityOperationCapability>>, SourceError>
    {
        self.accepted
            .lock()
            .map_err(|_| SourceError::Integrity)
            .map(|mut accepted| accepted.remove(operation_id))
    }

    async fn record_effect_state(
        &self,
        operation_id: &str,
        revision: ZoneRevision,
        state: d2b_resource_store_redb::AuthorityOperationState,
    ) -> Result<(), SourceError> {
        if let Some(capability) = self.effect_capability(operation_id)? {
            capability
                .record_effect(state)
                .await
                .map_err(|error| source_error(error, revision))?;
        }
        Ok(())
    }
}

impl<U> ResourceService<crate::store::RedbBackend, U>
where
    U: UpgradeDispatcher,
{
    /// Construct the distinct Core source adapter from the service's existing
    /// NativeAuthorizer/store binding and an explicit authenticated identity.
    pub fn registered_controller_api(
        &self,
        subject: crate::AuthenticatedSubjectContext,
        state: AuthorizationState,
        assignments: Vec<(ResourceRef, ResourceAssignmentFence)>,
    ) -> Result<RedbRegisteredControllerApi, StoreBindingError> {
        RedbRegisteredControllerApi::with_identity(self, subject, state, assignments)
    }
}

impl RegisteredControllerApi for RedbRegisteredControllerApi {
    fn register(
        &self,
        descriptor: &ControllerDescriptor,
    ) -> impl Future<Output = Result<(), SourceError>> + Send {
        let result = validate_descriptor(descriptor, self.store.identity().zone());
        async move {
            result?;
            let mut registered = self.descriptor.lock().map_err(|_| SourceError::Integrity)?;
            if registered
                .as_ref()
                .is_some_and(|current| current != descriptor)
            {
                return Err(SourceError::Integrity);
            }
            *registered = Some(descriptor.clone());
            Ok(())
        }
    }

    fn list_initial(
        &self,
        descriptor: &ControllerDescriptor,
    ) -> impl Future<Output = Result<InitialList, SourceError>> + Send {
        let descriptor = descriptor.clone();
        async move {
            if self.descriptor()? != descriptor {
                return Err(SourceError::Integrity);
            }
            let (resources, snapshot_revision) = self
                .list_all(
                    self.store.identity().zone(),
                    descriptor.resource_types().cloned().collect(),
                    StoreProjection::MetadataOnly,
                    "initial",
                )
                .await?;
            Ok(InitialList {
                resources: resources
                    .into_iter()
                    .filter(|resource| {
                        descriptor
                            .resource_types()
                            .any(|resource_type| resource.resource_ref.resource_type() == resource_type)
                    })
                    .map(|resource| {
                        InitialResource::new(
                            ResourceKey::new(resource.zone, resource.resource_ref, resource.uid),
                            snapshot_revision,
                        )
                    })
                    .collect(),
                snapshot_revision,
            })
        }
    }

    fn open_watch(
        &self,
        descriptor: &ControllerDescriptor,
        after_revision: ZoneRevision,
    ) -> impl Future<Output = Result<(), SourceError>> + Send {
        let descriptor = descriptor.clone();
        async move {
            if self.descriptor()? != descriptor {
                return Err(SourceError::Integrity);
            }
            let (resource_types, filters) = if descriptor.consumes_owner_triggers() {
                (
                    Vec::new(),
                    vec![StoreFilter {
                        field: "resource-or-owner.type".to_owned(),
                        values: descriptor
                            .resource_types()
                            .map(|resource_type| resource_type.as_str().to_owned())
                            .collect(),
                    }],
                )
            } else {
                (descriptor.resource_types().cloned().collect(), Vec::new())
            };
            let request = StoreWatchRequest {
                operation: Self::operation(format!(
                    "watch-open:{}:{}",
                    descriptor.identity().controller_ref().to_canonical_string(),
                    after_revision.get()
                )),
                zone: self.store.identity().zone().clone(),
                resource_types,
                resource_names: Vec::new(),
                filters,
                after_revision,
                initial_credits: descriptor.initial_watch_credits(),
                projection: StoreProjection::Full,
            };
            let watch = WatchService::new(Arc::clone(&self.store))
                .open(request)
                .await
                .map_err(|error| source_error(error, after_revision))?;
            *self.watch.lock().await = Some(watch);
            self.pending.lock().await.clear();
            *self.acknowledge_after.lock().await = None;
            self.watch_stopped.store(false, Ordering::Release);
            self.watch_open.store(true, Ordering::Release);
            Ok(())
        }
    }

    fn has_watch_stream(&self) -> bool {
        self.watch_open.load(Ordering::Acquire)
    }

    fn stop_watch(&self) {
        self.watch_stopped.store(true, Ordering::Release);
        self.watch_open.store(false, Ordering::Release);
        self.watch_stop.notify_waiters();
    }

    fn receive_watch_change(
        &self,
    ) -> impl Future<Output = Result<Option<(ChangeRecord, OperationContext)>, WatchFailure>> + Send
    {
        async move {
            loop {
                if let Some(revision) = self.acknowledge_after.lock().await.take() {
                    let mut watch = self.watch.lock().await;
                    if let Some(watch) = watch.as_mut() {
                        let _ = watch.acknowledge(revision).await;
                    }
                }
                let pending_change = { self.pending.lock().await.pop_front() };
                if let Some((change, operation, revision)) = pending_change {
                    let next_is_different = {
                        self.pending
                            .lock()
                            .await
                            .front()
                            .is_none_or(|next| next.2 != revision)
                    };
                    if next_is_different {
                        *self.acknowledge_after.lock().await = Some(revision);
                    }
                    return Ok(Some((change, operation)));
                }
                let descriptor = self.descriptor().map_err(|_| WatchFailure::Fatal)?;
                let batch = {
                    let mut watch_guard = self.watch.lock().await;
                    let Some(watch) = watch_guard.as_mut() else {
                        return Ok(None);
                    };
                    if self.watch_stopped.load(Ordering::Acquire) {
                        watch_guard.take();
                        return Ok(None);
                    }
                    tokio::select! {
                        batch = watch.recv() => batch,
                        _ = self.watch_stop.notified() => {
                            watch_guard.take();
                            return Ok(None);
                        },
                    }
                };
                let Some(batch) = batch else {
                    let mut watch = self.watch.lock().await;
                    let Some(watch) = watch.as_mut() else {
                        self.watch_open.store(false, Ordering::Release);
                        return Err(WatchFailure::Disconnected);
                    };
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
                let changes = self.changes_for_batch(&descriptor, &batch)?;
                if let Some(observer) = self.watch_change_observer.as_ref() {
                    for (change, _, _) in &changes {
                        observer(change);
                    }
                }
                if changes.is_empty() {
                    let mut watch = self.watch.lock().await;
                    if let Some(watch) = watch.as_mut() {
                        let _ = watch.acknowledge(batch.revision()).await;
                    }
                    continue;
                }
                self.pending.lock().await.extend(changes);
            }
        }
    }

    fn read_fresh(
        &self,
        key: &ResourceKey,
    ) -> impl Future<Output = Result<FreshSnapshot, SourceError>> + Send {
        let key = key.clone();
        async move {
            let descriptor = self.descriptor()?;
            match self.read_target(&key).await? {
                Ok(resource) => {
                    Ok(FreshSnapshot::Present {
                        target: snapshot_from_resource(resource),
                        dependencies: self.dependencies(&descriptor, key.zone()).await?,
                    })
                }
                Err(revision) => Ok(FreshSnapshot::Deleted {
                    key,
                    revision,
                    generation: ResourceGeneration::new(1).expect("one is valid"),
                }),
            }
        }
    }

    fn write_starting(
        &self,
        context: &ReconcileContext,
    ) -> impl Future<Output = Result<(), SourceError>> + Send {
        let operation_id = context.operation().operation_id().to_owned();
        let accepted = Arc::clone(&self.accepted);
        async move {
            accepted
                .lock()
                .map_err(|_| SourceError::Integrity)?
                .remove(&operation_id);
            Ok(())
        }
    }

    fn accept_effect(
        &self,
        context: &ReconcileContext,
        plan: &ReconcilePlan,
    ) -> impl Future<Output = Result<(), SourceError>> + Send {
        let target = context.target().resource_ref().clone();
        let uid = context.target().uid().clone();
        let revision = context.revision();
        let store = Arc::clone(&self.store);
        let accepted = self.accepted.clone();
        let accepting = self.commit.is_some();
        if accepting {
            self.effect_acceptances_in_flight
                .fetch_add(1, Ordering::AcqRel);
        }
        async move {
            let result = async {
                self.refresh_assignment(&target, &uid, revision).await?;
                let effect_identity = self.effect_identity(context, plan);
                let (authority_operation_id, claim_digest, operation_class, effect_ids) =
                    effect_identity?;
                let payload = serde_json::to_vec(&serde_json::json!({
                    "version": 1,
                    "kind": "controller-effect",
                    "state": "pending",
                    "operationClass": operation_class,
                    "effectIds": effect_ids,
                    "resourceUid": context.target().uid().as_str(),
                    "generation": context.generation().get(),
                    "operationId": authority_operation_id,
                    "claimDigest": claim_digest,
                    "storeBindingDigest": store.authority_binding_digest(&claim_digest),
                }))
                .map_err(|_| SourceError::Integrity)?;
                let capability = store
                    .prepare_authority_operation(
                        authority_operation_id.clone(),
                        payload,
                        &claim_digest,
                    )
                    .await
                    .map_err(|error| source_error(error, context.revision()))?;
                if let Some(observer) = self
                    .commit
                    .as_ref()
                    .and_then(|commit| commit.effect_acceptance_observer.clone())
                {
                    observer(context.target().uid());
                }
                accepted
                    .lock()
                    .map_err(|_| SourceError::Integrity)?
                    .insert(
                        context.operation().operation_id().to_owned(),
                        Arc::new(capability),
                    );
                Ok(())
            }
            .await;
            if accepting {
                self.effect_acceptances_in_flight
                    .fetch_sub(1, Ordering::AcqRel);
            }
            result
        }
    }

    fn verify_expedited_commit(
        &self,
        context: &ReconcileContext,
    ) -> impl Future<Output = Result<bool, SourceError>> + Send {
        async move {
            match self.read_target(context.target()).await? {
                Ok(resource)
                    if resource.uid == *context.target().uid()
                        && resource.generation == context.generation()
                        && resource.revision == context.revision() =>
                {
                    Ok(true)
                }
                Ok(_) | Err(_) => Ok(false),
            }
        }
    }

    fn commit_result(
        &self,
        context: &ReconcileContext,
        result: &ReconcileResult,
    ) -> impl Future<Output = Result<CommitOutcome, SourceError>> + Send {
        async move {
            while self
                .effect_acceptances_in_flight
                .load(Ordering::Acquire)
                != 0
            {
                tokio::task::yield_now().await;
            }
            let descriptor = self.descriptor()?;
            if let Some(finalizer) = self.finalizer_first(&descriptor, context).await? {
                return self
                    .commit_mutations(
                        context,
                        vec![finalizer],
                        result.status_candidate().is_some(),
                    )
                    .await;
            }
            let mut mutations = Vec::new();
            if let Some(batch) = result.mutation_batch() {
                for intent in batch.mutations() {
                    mutations.push(self.store_mutation(context, intent).await?);
                }
            }
            let mut deferred_status = false;
            if let Some(candidate) = result.status_candidate() {
                if mutations
                    .iter()
                    .any(|mutation| mutation.target == *context.target().resource_ref())
                {
                    // Preserve the one-transaction contract: self-mutation
                    // commits first, and the watch-driven fresh pass projects
                    // the status afterward.
                    deferred_status = true;
                } else {
                    mutations.push(self.status_mutation(context, candidate).await?);
                }
            }
            self.commit_mutations(context, mutations, deferred_status)
                .await
        }
    }

    fn complete_expedited(
        &self,
        context: &ReconcileContext,
        projection: &ReconcileProjection,
        status_persistence: StatusPersistence,
    ) -> impl Future<Output = Result<(), SourceError>> + Send {
        async move {
            self.record_effect_state(
                context.operation().operation_id(),
                context.revision(),
                projection_state(projection.disposition(), projection.reason()),
            )
            .await?;
            if status_persistence != StatusPersistence::Pending {
                self.persist_projection_status(projection).await?;
            }
            Ok(())
        }
    }

    fn complete_effect(
        &self,
        context: &ReconcileContext,
        result: &ReconcileResult,
    ) -> impl Future<Output = Result<(), SourceError>> + Send {
        async move {
            self.record_effect_state(
                context.operation().operation_id(),
                context.revision(),
                result_state(result.disposition()),
            )
            .await
        }
    }

    fn persist_outcome(
        &self,
        projection: &ReconcileProjection,
    ) -> impl Future<Output = Result<(), SourceError>> + Send {
        self.persist_projection_status(projection)
    }

    fn checkpoint(
        &self,
        context: &ReconcileContext,
        _revision: ZoneRevision,
    ) -> impl Future<Output = Result<(), SourceError>> + Send {
        if let Some(observer) = self
            .commit
            .as_ref()
            .and_then(|commit| commit.checkpoint_observer.clone())
        {
            observer(context.target().uid());
        }
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

impl RedbRegisteredControllerApi {
    async fn store_mutation(
        &self,
        context: &ReconcileContext,
        intent: &d2b_core_controller::MutationIntent,
    ) -> Result<StoreMutation, SourceError> {
        let kind = match intent.kind() {
            d2b_core_controller::MutationIntentKind::Create => ResourceMutationKind::Create,
            d2b_core_controller::MutationIntentKind::UpdateSpec => ResourceMutationKind::UpdateSpec,
            d2b_core_controller::MutationIntentKind::UpdateStatus => {
                ResourceMutationKind::UpdateStatus
            }
            d2b_core_controller::MutationIntentKind::UpdateMetadata => {
                ResourceMutationKind::UpdateMetadata
            }
            d2b_core_controller::MutationIntentKind::UpdateFinalizers => {
                ResourceMutationKind::UpdateFinalizers
            }
            d2b_core_controller::MutationIntentKind::Delete => ResourceMutationKind::Delete,
        };
        let target = intent.target().clone();
        let (expected, expected_uid) = if kind == ResourceMutationKind::Create {
            (ExpectedRevision::CreateAbsent, None)
        } else {
            (
                ExpectedRevision::Exact(intent.expected_revision().ok_or(SourceError::Integrity)?),
                Some(
                    intent
                        .expected_uid()
                        .cloned()
                        .ok_or(SourceError::Integrity)?,
                ),
            )
        };
        if kind == ResourceMutationKind::UpdateFinalizers {
            return self
                .finalizer_delta(
                    context,
                    target,
                    expected,
                    expected_uid,
                    intent.canonical_resource(),
                )
                .await;
        }
        let canonical_resource = intent.canonical_resource().map(ToOwned::to_owned);
        let owner = if matches!(
            kind,
            ResourceMutationKind::Create | ResourceMutationKind::UpdateMetadata
        ) {
            canonical_resource
                .as_deref()
                .and_then(|bytes| ResourceEnvelope::from_json(bytes).ok())
                .and_then(|envelope| envelope.metadata().owner_ref().cloned())
        } else {
            None
        };
        Ok(StoreMutation {
            kind,
            zone: context.target().zone().clone(),
            target,
            expected,
            expected_uid,
            owner,
            canonical_resource,
            add_finalizers: Vec::new(),
            remove_finalizers: Vec::new(),
            wait_for_reconcile: false,
            reconcile_deadline_ms: None,
            configuration_generation: None,
            assignment: None,
        })
    }

    async fn finalizer_delta(
        &self,
        context: &ReconcileContext,
        target: ResourceRef,
        expected: ExpectedRevision,
        expected_uid: Option<ResourceUid>,
        desired: Option<&[u8]>,
    ) -> Result<StoreMutation, SourceError> {
        let key = ResourceKey::new(
            context.target().zone().clone(),
            target.clone(),
            expected_uid
                .clone()
                .unwrap_or_else(|| context.target().uid().clone()),
        );
        let current = match self.read_target(&key).await? {
            Ok(resource) => resource,
            Err(_) => return Err(SourceError::Conflict(context.revision())),
        };
        let current_finalizers = finalizer_set(&current.canonical_json)?;
        if desired.is_none() && !deleting(&current.canonical_json) {
            return Err(SourceError::Integrity);
        }
        let desired_finalizers = if let Some(bytes) = desired {
            finalizer_set(bytes)?
        } else {
            let descriptor = self.descriptor()?;
            let owned = descriptor
                .finalizers()
                .iter()
                .map(|value| FinalizerId::parse(value.clone()).map_err(|_| SourceError::Integrity))
                .collect::<Result<BTreeSet<_>, _>>()?;
            current_finalizers
                .difference(&owned)
                .cloned()
                .collect::<BTreeSet<_>>()
        };
        let add_finalizers = desired_finalizers
            .difference(&current_finalizers)
            .cloned()
            .collect::<Vec<_>>();
        let remove_finalizers = current_finalizers
            .difference(&desired_finalizers)
            .cloned()
            .collect::<Vec<_>>();
        if add_finalizers.is_empty() && remove_finalizers.is_empty() {
            return Err(SourceError::Conflict(current.revision));
        }
        Ok(StoreMutation {
            kind: ResourceMutationKind::UpdateFinalizers,
            zone: current.zone,
            target,
            expected,
            expected_uid,
            owner: None,
            canonical_resource: None,
            add_finalizers,
            remove_finalizers,
            wait_for_reconcile: false,
            reconcile_deadline_ms: None,
            configuration_generation: None,
            assignment: None,
        })
    }

    async fn status_mutation(
        &self,
        context: &ReconcileContext,
        candidate: &[u8],
    ) -> Result<StoreMutation, SourceError> {
        let current = match self.read_target(context.target()).await? {
            Ok(resource) => resource,
            Err(_) => return Err(SourceError::Conflict(context.revision())),
        };
        let canonical_resource = merge_status(&current.canonical_json, candidate)?;
        Ok(StoreMutation {
            kind: ResourceMutationKind::UpdateStatus,
            zone: context.target().zone().clone(),
            target: context.target().resource_ref().clone(),
            expected: ExpectedRevision::Exact(current.revision),
            expected_uid: Some(current.uid),
            owner: None,
            canonical_resource: Some(canonical_resource),
            add_finalizers: Vec::new(),
            remove_finalizers: Vec::new(),
            wait_for_reconcile: false,
            reconcile_deadline_ms: None,
            configuration_generation: None,
            assignment: None,
        })
    }
}

fn validate_descriptor(
    descriptor: &ControllerDescriptor,
    zone: &ZoneId,
) -> Result<(), SourceError> {
    if descriptor.identity().zone() != zone
        || d2b_core_controller::WatchPlan::new(
            descriptor.resource_types().cloned().collect(),
            descriptor.watch_selectors().to_vec(),
            descriptor.consumes_owner_triggers(),
        )
        .is_err()
    {
        return Err(SourceError::Integrity);
    }
    for finalizer in descriptor.finalizers() {
        FinalizerId::parse(finalizer.clone()).map_err(|_| SourceError::Integrity)?;
    }
    Ok(())
}

fn snapshot_from_resource(resource: StoredResource) -> d2b_core_controller::ResourceSnapshot {
    let StoredResource {
        resource_ref,
        zone,
        uid,
        generation,
        revision,
        canonical_json,
        ..
    } = resource;
    let deleting = deleting(&canonical_json);
    d2b_core_controller::ResourceSnapshot::new(
        ResourceKey::new(zone, resource_ref, uid),
        revision,
        generation,
        canonical_json,
        deleting,
    )
}

fn deleting(bytes: &[u8]) -> bool {
    serde_json::from_slice::<Value>(bytes)
        .ok()
        .and_then(|value| value.pointer("/metadata/deletionRequestedAt").cloned())
        .is_some_and(|value| !value.is_null())
}

fn observed_generation(bytes: Option<&[u8]>, fallback: ResourceGeneration) -> ObservedGeneration {
    bytes
        .and_then(|bytes| ResourceEnvelope::from_json(bytes).ok())
        .map(|envelope| envelope.status().observed_generation())
        .unwrap_or_else(|| ObservedGeneration::new(fallback.get().saturating_sub(1)))
}

fn selector_matches(
    selector: &d2b_core_controller::WatchSelector,
    resource: &StoredResource,
) -> bool {
    let Some(expected) = selector.exact_value() else {
        return true;
    };
    match selector.field() {
        ChangeField::Metadata => resource.resource_ref.name().as_str() == expected,
        ChangeField::Spec
        | ChangeField::Status
        | ChangeField::Finalizers
        | ChangeField::Deletion => serde_json::from_slice::<Value>(&resource.canonical_json)
            .ok()
            .is_some_and(|value| {
                let field = match selector.field() {
                    ChangeField::Spec => "/spec",
                    ChangeField::Status => "/status",
                    ChangeField::Finalizers => "/metadata/finalizers",
                    ChangeField::Deletion => "/metadata/deletionRequestedAt",
                    ChangeField::Metadata => unreachable!(),
                };
                value.pointer(field).is_some_and(|value| {
                    value.as_str() == Some(expected) || value.to_string() == expected
                })
            }),
    }
}

fn change_for_entry(
    zone: &ZoneId,
    descriptor: &ControllerDescriptor,
    entry: &d2b_resource_store_redb::ChangeEntry,
    revision: ZoneRevision,
) -> Vec<(ChangeRecord, String)> {
    let mut changes = Vec::new();
    let target = ResourceKey::new(
        zone.clone(),
        ResourceRef::new(entry.resource_type().clone(), entry.resource_name().clone()),
        entry.resource_uid().clone(),
    );
    let generation = entry
        .new_generation()
        .or(entry.old_generation())
        .unwrap_or_else(|| ResourceGeneration::new(1).expect("one is valid"));
    let event = entry.event();
    let (field, reason) = match event {
        ChangeEvent::Created | ChangeEvent::SpecUpdated => {
            (ChangeField::Spec, CoreTriggerReason::SpecGenerationChanged)
        }
        ChangeEvent::StatusUpdated => (
            ChangeField::Status,
            CoreTriggerReason::ExecutionStatusChanged,
        ),
        ChangeEvent::MetadataUpdated => (ChangeField::Metadata, CoreTriggerReason::ManualReconcile),
        ChangeEvent::FinalizersUpdated => (
            ChangeField::Finalizers,
            CoreTriggerReason::FinalizerRequired,
        ),
        ChangeEvent::DeletionRequested | ChangeEvent::Deleted => {
            (ChangeField::Deletion, CoreTriggerReason::DeletionRequested)
        }
    };
    if descriptor
        .resource_types()
        .any(|resource_type| resource_type == entry.resource_type())
        && descriptor
            .watch_selectors()
            .iter()
            .any(|selector| selector_matches_event(selector, entry))
    {
        changes.push((
            ChangeRecord {
                target,
                revision,
                generation,
                observed_generation: observed_generation(entry.canonical_resource(), generation),
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
            format!("child:{}", entry.ordinal()),
        ));
    }
    let previous = entry
        .previous_owner_ref()
        .zip(entry.previous_owner_uid())
        .map(|(owner_ref, owner_uid)| (owner_ref.clone(), owner_uid.clone()));
    let current = entry
        .owner_ref()
        .zip(entry.owner_uid())
        .map(|(owner_ref, owner_uid)| (owner_ref.clone(), owner_uid.clone()))
        .or_else(|| {
            (event == ChangeEvent::Deleted || event == ChangeEvent::DeletionRequested)
                .then_some(previous.clone())
                .flatten()
        });
    if let Some((owner_ref, owner_uid)) =
        previous.filter(|previous| current.as_ref() != Some(previous))
    {
        push_owner_change(
            zone,
            descriptor,
            &mut changes,
            owner_ref,
            owner_uid,
            revision,
            entry.ordinal(),
            "old",
        );
    }
    if let Some((owner_ref, owner_uid)) = current {
        push_owner_change(
            zone,
            descriptor,
            &mut changes,
            owner_ref,
            owner_uid,
            revision,
            entry.ordinal(),
            "new",
        );
    }
    changes
}

fn push_owner_change(
    zone: &ZoneId,
    descriptor: &ControllerDescriptor,
    changes: &mut Vec<(ChangeRecord, String)>,
    owner_ref: ResourceRef,
    owner_uid: ResourceUid,
    revision: ZoneRevision,
    ordinal: u32,
    suffix: &str,
) {
    if !descriptor.consumes_owner_triggers()
        || !descriptor
            .resource_types()
            .any(|resource_type| resource_type == owner_ref.resource_type())
    {
        return;
    }

    changes.push((
        ChangeRecord {
            target: ResourceKey::new(zone.clone(), owner_ref, owner_uid),
            revision,
            generation: ResourceGeneration::new(1).expect("one is valid"),
            observed_generation: ObservedGeneration::new(0),
            fields: BTreeSet::from([ChangeField::Metadata]),
            reasons: BTreeSet::from([CoreTriggerReason::OwnedResourceChanged]),
            type_is_bound: true,
            relevant_field_changed: true,
            own_status_only: false,
            owner_consumer_exists: true,
            dependency_consumer_exists: false,
            controller_generation_current: true,
            conditions_require_work: false,
            unknown_requires_observation: false,
        },
        format!("owner:{suffix}:{ordinal}"),
    ));
}

fn selector_matches_event(
    selector: &d2b_core_controller::WatchSelector,
    entry: &d2b_resource_store_redb::ChangeEntry,
) -> bool {
    if selector.resource_type() != entry.resource_type() {
        return false;
    }
    if matches!(
        entry.event(),
        ChangeEvent::FinalizersUpdated | ChangeEvent::DeletionRequested | ChangeEvent::Deleted
    ) {
        return true;
    }
    let selected = match entry.event() {
        ChangeEvent::Created | ChangeEvent::SpecUpdated => ChangeField::Spec,
        ChangeEvent::StatusUpdated => ChangeField::Status,
        ChangeEvent::MetadataUpdated => ChangeField::Metadata,
        ChangeEvent::FinalizersUpdated => ChangeField::Finalizers,
        ChangeEvent::DeletionRequested | ChangeEvent::Deleted => ChangeField::Deletion,
    };
    if selector.field() != selected
        && !(selected == ChangeField::Deletion && selector.field() == ChangeField::Metadata)
    {
        return false;
    }
    let Some(expected) = selector.exact_value() else {
        return true;
    };
    match selector.field() {
        ChangeField::Metadata => entry.resource_name().as_str() == expected,
        ChangeField::Spec | ChangeField::Status => entry
            .canonical_resource()
            .and_then(|bytes| serde_json::from_slice::<Value>(bytes).ok())
            .and_then(|value| {
                let field = if selector.field() == ChangeField::Spec {
                    "spec"
                } else {
                    "status"
                };
                value.get(field).cloned()
            })
            .is_some_and(|value| value.as_str() == Some(expected) || value.to_string() == expected),
        ChangeField::Finalizers | ChangeField::Deletion => true,
    }
}

fn finalizer_set(bytes: &[u8]) -> Result<BTreeSet<FinalizerId>, SourceError> {
    serde_json::from_slice::<Value>(bytes)
        .map_err(|_| SourceError::Integrity)?
        .pointer("/metadata/finalizers")
        .and_then(Value::as_array)
        .ok_or(SourceError::Integrity)?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or(SourceError::Integrity)
                .and_then(|value| {
                    FinalizerId::parse(value.to_owned()).map_err(|_| SourceError::Integrity)
                })
        })
        .collect()
}

fn merge_status(current: &[u8], candidate: &[u8]) -> Result<Vec<u8>, SourceError> {
    let mut resource = d2b_contracts_resource::v3::CanonicalJsonValue::parse(current)
        .map_err(|_| SourceError::Integrity)?;
    let status = d2b_contracts_resource::v3::CanonicalJsonValue::parse(candidate)
        .map_err(|_| SourceError::Integrity)?;
    let d2b_contracts_resource::v3::CanonicalJsonValue::Object(status) = status else {
        return Err(SourceError::Integrity);
    };
    let d2b_contracts_resource::v3::CanonicalJsonValue::Object(root) = &mut resource else {
        return Err(SourceError::Integrity);
    };
    root.insert(
        "status".to_owned(),
        d2b_contracts_resource::v3::CanonicalJsonValue::Object(status),
    );
    Ok(resource.to_canonical_bytes())
}

fn is_conflict(error: &StoreError) -> bool {
    matches!(
        error.kind(),
        StoreErrorKind::ResourceConflict
            | StoreErrorKind::ResourceAlreadyExists
            | StoreErrorKind::ResourceNotFound
            | StoreErrorKind::ResourceFinalizerDenied
    )
}

const fn resource_phase_name(phase: ResourcePhase) -> &'static str {
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

const fn resource_verb(kind: ResourceMutationKind) -> ResourceVerb {
    match kind {
        ResourceMutationKind::Create => ResourceVerb::Create,
        ResourceMutationKind::UpdateSpec => ResourceVerb::UpdateSpec,
        ResourceMutationKind::UpdateStatus => ResourceVerb::UpdateStatus,
        ResourceMutationKind::UpdateMetadata => ResourceVerb::UpdateMetadata,
        ResourceMutationKind::UpdateFinalizers => ResourceVerb::UpdateFinalizers,
        ResourceMutationKind::Delete => ResourceVerb::Delete,
    }
}

fn operation_class(context: &ReconcileContext) -> &'static str {
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

fn append_text(material: &mut Vec<u8>, value: &str) {
    material.extend_from_slice(&(value.len() as u64).to_be_bytes());
    material.extend_from_slice(value.as_bytes());
}

fn append_assignment_identity(material: &mut Vec<u8>, fence: &ResourceAssignmentFence) {
    append_text(material, fence.resource_uid.as_str());
    material.extend_from_slice(&fence.provider_generation.get().to_be_bytes());
    material.extend_from_slice(&fence.controller_generation.get().to_be_bytes());
    append_text(material, &fence.controller_role.to_canonical_string());
    append_text(material, &fence.target.to_canonical_string());
    material.extend_from_slice(&fence.session_generation.get().to_be_bytes());
    material.extend_from_slice(&fence.epoch.to_be_bytes());
    match &fence.scope {
        ResourceAssignmentScope::Primary => append_text(material, "primary"),
        ResourceAssignmentScope::OwnerChild {
            owner_ref,
            owner_uid,
            owner_generation,
            ..
        } => {
            append_text(material, "owner-child");
            append_text(material, &owner_ref.to_canonical_string());
            append_text(material, owner_uid.as_str());
            material.extend_from_slice(&owner_generation.get().to_be_bytes());
        }
    }
}

fn effect_claim_digest(
    operation_class: &str,
    resource_uid: &ResourceUid,
    generation: ResourceGeneration,
    effect_ids: &[String],
    assignment: Option<&ResourceAssignmentFence>,
) -> String {
    let mut material = Vec::new();
    append_text(&mut material, operation_class);
    append_text(&mut material, resource_uid.as_str());
    material.extend_from_slice(&generation.get().to_be_bytes());
    for effect_id in effect_ids {
        append_text(&mut material, effect_id);
    }
    match assignment {
        Some(assignment) => append_assignment_identity(&mut material, assignment),
        None => append_text(&mut material, "unassigned"),
    }
    canonical_digest("d2b:controller-effect-claim/v2", &material)
}

const fn projection_state(
    disposition: d2b_core_controller::ProjectionDisposition,
    reason: d2b_core_controller::ReconcileReason,
) -> d2b_resource_store_redb::AuthorityOperationState {
    match disposition {
        d2b_core_controller::ProjectionDisposition::Converged => {
            d2b_resource_store_redb::AuthorityOperationState::EffectConfirmed
        }
        d2b_core_controller::ProjectionDisposition::Failed
            if matches!(
                reason,
                d2b_core_controller::ReconcileReason::HandlerTerminal
                    | d2b_core_controller::ReconcileReason::HandlerExhausted
                    | d2b_core_controller::ReconcileReason::InvalidSpec
            ) =>
        {
            d2b_resource_store_redb::AuthorityOperationState::EffectTerminal
        }
        d2b_core_controller::ProjectionDisposition::Failed
            if matches!(
                reason,
                d2b_core_controller::ReconcileReason::HandlerRetryable
                    | d2b_core_controller::ReconcileReason::DeadlineExceeded
                    | d2b_core_controller::ReconcileReason::Cancelled
                    | d2b_core_controller::ReconcileReason::ConflictExhausted
            ) =>
        {
            d2b_resource_store_redb::AuthorityOperationState::EffectRetryable
        }
        d2b_core_controller::ProjectionDisposition::Failed
        | d2b_core_controller::ProjectionDisposition::Progressing
        | d2b_core_controller::ProjectionDisposition::Blocked
        | d2b_core_controller::ProjectionDisposition::UpgradeRequired => {
            d2b_resource_store_redb::AuthorityOperationState::Pending
        }
    }
}

const fn result_state(
    disposition: d2b_core_controller::ReconcileDisposition,
) -> d2b_resource_store_redb::AuthorityOperationState {
    match disposition {
        d2b_core_controller::ReconcileDisposition::Converged
        | d2b_core_controller::ReconcileDisposition::Finalized => {
            d2b_resource_store_redb::AuthorityOperationState::EffectConfirmed
        }
        d2b_core_controller::ReconcileDisposition::Pending
        | d2b_core_controller::ReconcileDisposition::Degraded
        | d2b_core_controller::ReconcileDisposition::RequeueAt => {
            d2b_resource_store_redb::AuthorityOperationState::Pending
        }
        d2b_core_controller::ReconcileDisposition::FailedRetryable => {
            d2b_resource_store_redb::AuthorityOperationState::EffectRetryable
        }
        d2b_core_controller::ReconcileDisposition::FailedTerminal => {
            d2b_resource_store_redb::AuthorityOperationState::EffectTerminal
        }
    }
}

fn source_error(error: StoreError, fallback: ZoneRevision) -> SourceError {
    match error.kind() {
        StoreErrorKind::ResourceConflict
        | StoreErrorKind::ResourceAlreadyExists
        | StoreErrorKind::ResourceNotFound
        | StoreErrorKind::ResourceFinalizerDenied => {
            SourceError::Conflict(error.current_revision().unwrap_or(fallback))
        }
        StoreErrorKind::RevisionExpired => {
            SourceError::Conflict(error.current_revision().unwrap_or(fallback))
        }
        StoreErrorKind::Backpressure | StoreErrorKind::StoreBackpressure => {
            SourceError::Backpressure
        }
        StoreErrorKind::Timeout => SourceError::Timeout,
        StoreErrorKind::Cancelled => SourceError::Cancelled,
        StoreErrorKind::InternalIntegrityFailure
        | StoreErrorKind::StoreIntegrityFailure
        | StoreErrorKind::ResourceSchemaInvalid
        | StoreErrorKind::ResourceRefInvalid => SourceError::Integrity,
        _ => SourceError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use crate::authz::{
        ApiCatalog, BindingScope, BootstrapPhase, BoundSubject, CompiledRole, CompiledRoleBinding,
        NativeAuthorizer, PolicyRule, PolicySet, RelayGrantAuthority, ResourceVerb,
    };
    use crate::identity::issue_test_subject;
    use d2b_contracts_resource::v3::identity::{
        AuthenticatedSubjectContext as SessionClaims, BindingDigest, EvidenceClass, Locality,
        ReconnectGeneration, ServiceName, SessionBinding, SessionPurpose, TranscriptHash,
        TransportBinding,
    };
    use d2b_contracts_resource::v3::{
        CanonicalJsonValue, ConfigurationGeneration, ControllerGeneration,
        RESOURCE_ENVELOPE_DOMAIN_TAG, ResourceTypeName, SchemaFingerprint, Timestamp,
    };
    use d2b_core_controller::{
        ChangeField, ControllerExecutionPolicy, ControllerHealth, ControllerIdentity,
        ControllerSource, ControllerVerb, CoreControllerSource, DisruptionClass, DrainResult,
        FinalizeResult, MutationIntent, MutationIntentKind, ReconcileResult, ResourceReconciler,
        ResourceRegistration, ResyncPolicy, UpgradePlan, UpgradeStage, ValidationResult,
        WatchSelector,
    };
    use d2b_resource_store::mutation_seal::{MutationSealIssuer, mutation_seal_pair};
    use d2b_resource_store::{
        AdmittedAuthorization, AdmittedAuthorizationTarget, AdmittedVerb, ExpectedRevision,
        MutationSealBody, PolicySnapshot, PreparedStoreMutation, SealedMutation, StoreMutation,
        StoreSlot,
    };
    use d2b_resource_store_redb::{
        BackupRow, DecodedKey, DecodedKeyComponent, DecodedValue, KeyComponent, KeySpace,
        StoreIdentity, ValueKind, encode_key, encode_value, write_provisioning_marker,
    };
    use sha2::{Digest, Sha256};

    fn identity() -> StoreIdentity {
        StoreIdentity::new(
            StoreSlot::new(0).unwrap(),
            ResourceUid::parse("11111111-1111-4111-8111-111111111111").unwrap(),
            ZoneId::parse("work").unwrap(),
            ResourceUid::parse("22222222-2222-4222-8222-222222222222").unwrap(),
            Timestamp::parse("2026-07-31T00:00:00.000Z").unwrap(),
            PolicySnapshot {
                policy_revision: 7,
                api_catalog_revision: 8,
                active_configuration_revision: ConfigurationGeneration::new(9).unwrap(),
                controller_generation: None,
            },
        )
    }

    fn descriptor() -> ControllerDescriptor {
        let resource_type = ResourceTypeName::parse("Host").unwrap();
        ControllerDescriptor::new(
            ControllerIdentity::new(
                ZoneId::parse("work").unwrap(),
                ResourceRef::parse("Process/controller").unwrap(),
                ControllerGeneration::new(1).unwrap(),
                ResourceRef::parse("Provider/system-core").unwrap(),
                ResourceGeneration::new(1).unwrap(),
                ResourceRef::parse("Process/controller").unwrap(),
                ResourceRef::parse("Host/system").unwrap(),
                None,
            )
            .unwrap(),
            vec![ResourceRegistration::new(resource_type.clone(), vec![1], 5_000, 3).unwrap()],
            vec!["resource-api".to_owned()],
            vec!["host".to_owned()],
            vec![ControllerVerb::ReadSpec, ControllerVerb::WriteStatus],
            vec![WatchSelector::new(resource_type, ChangeField::Spec, None).unwrap()],
            Vec::new(),
            true,
            vec!["core.controller".to_owned()],
            vec!["service.v1".to_owned()],
            vec!["schema.v1".to_owned()],
            ControllerExecutionPolicy::new(
                1,
                1,
                32,
                2,
                16,
                ResyncPolicy::new(None, 5_000).unwrap(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn canonical_host(name: &str, owner: Option<&str>) -> Vec<u8> {
        let raw = format!(
            r#"{{"apiVersion":"resources.d2bus.org/v3","metadata":{{"configurationGeneration":7,"createdAt":"2026-07-22T00:00:00.000Z","deletionRequestedAt":null,"finalizers":[],"generation":1,"managedBy":"configuration","name":"{name}","ownerRef":null,"revision":1,"uid":"123e4567-e89b-42d3-a456-426614174000","updatedAt":"2026-07-22T00:00:00.000Z","zone":"work"}},"spec":{{"providerRef":"Provider/system-core","updatePolicy":{{"disruptive":"manual","nonDisruptive":"automatic"}}}},"status":{{"completedAt":null,"conditions":[],"lastReconciledAt":null,"observedGeneration":0,"outcome":null,"phase":"Pending","resource":{{}},"update":{{"dependencies":{{"count":0,"refs":[]}},"disruption":"None","lastAssessedAt":null,"observedGeneration":0,"operationId":null,"owned":{{"count":0,"refs":[]}},"preserveState":true,"reasons":[],"state":"Unknown","targetGeneration":1}}}},"type":"Host"}}"#
        );
        let mut value = CanonicalJsonValue::parse(raw.as_bytes()).unwrap();
        let CanonicalJsonValue::Object(root) = &mut value else {
            unreachable!()
        };
        let CanonicalJsonValue::Object(metadata) = root.get_mut("metadata").unwrap() else {
            unreachable!()
        };
        metadata.remove("uid");
        if let Some(owner) = owner {
            metadata.insert(
                "ownerRef".to_owned(),
                CanonicalJsonValue::String(owner.to_owned()),
            );
        }
        value.to_canonical_bytes()
    }

    fn verified_create(
        issuer: &MutationSealIssuer,
        target: ResourceRef,
        canonical: Vec<u8>,
        owner: Option<&str>,
        operation_id: &str,
    ) -> SealedMutation {
        issuer.seal(verified_create_body(target, canonical, owner, operation_id))
    }

    fn verified_create_from_slot(
        slot: &Arc<Mutex<Option<MutationSealIssuer>>>,
        target: ResourceRef,
        canonical: Vec<u8>,
        owner: Option<&str>,
        operation_id: &str,
    ) -> SealedMutation {
        slot.lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .seal(verified_create_body(target, canonical, owner, operation_id))
    }

    fn verified_create_body(
        target: ResourceRef,
        canonical: Vec<u8>,
        owner: Option<&str>,
        operation_id: &str,
    ) -> MutationSealBody {
        let digest = canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &canonical);
        MutationSealBody {
            mutations: vec![PreparedStoreMutation::new(
                StoreMutation {
                    kind: ResourceMutationKind::Create,
                    zone: ZoneId::parse("work").unwrap(),
                    target: target.clone(),
                    expected: ExpectedRevision::CreateAbsent,
                    expected_uid: None,
                    owner: owner.map(|owner| ResourceRef::parse(owner).unwrap()),
                    canonical_resource: Some(canonical),
                    add_finalizers: Vec::new(),
                    remove_finalizers: Vec::new(),
                    wait_for_reconcile: false,
                    reconcile_deadline_ms: None,
                    configuration_generation: None,
                    assignment: None,
                },
                None,
                Some(digest),
            )],
            authorization: AdmittedAuthorization {
                zone: ZoneId::parse("work").unwrap(),
                subject_ref: ResourceRef::parse("Provider/system-core").unwrap(),
                subject_uid: ResourceUid::parse("33333333-3333-4333-8333-333333333333").unwrap(),
                targets: vec![AdmittedAuthorizationTarget {
                    resource_type: target.resource_type().clone(),
                    resource_name: Some(target.name().clone()),
                    verb: AdmittedVerb::Create,
                    subresource: None,
                    execution_ref: None,
                }],
            },
            policy_snapshot: PolicySnapshot {
                policy_revision: 7,
                api_catalog_revision: 8,
                active_configuration_revision: ConfigurationGeneration::new(9).unwrap(),
                controller_generation: None,
            },
            operation: StoreOperationContext {
                operation_id: operation_id.to_owned(),
                idempotency_key: Some(operation_id.to_owned()),
                correlation_id: operation_id.to_owned(),
                trace_id: None,
                deadline_ms: 1_000,
            },
        }
    }

    async fn test_store() -> (
        tempfile::TempDir,
        Arc<RedbResourceStore>,
        MutationSealIssuer,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(directory.path().join("store.redb"))
            .unwrap();
        let mut marker = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(directory.path().join("store.marker"))
            .unwrap();
        let identity = identity();
        write_provisioning_marker(&mut marker, &identity).unwrap();
        let (issuer, acceptor) = mutation_seal_pair(identity.seal_identity());
        let store = RedbResourceStore::provision_owned(file, marker, identity, acceptor)
            .await
            .unwrap();
        (directory, Arc::new(store), issuer)
    }

    async fn large_relist_store() -> (tempfile::TempDir, Arc<RedbResourceStore>) {
        const RESOURCE_COUNT: usize = 10_000;
        let (_source_directory, source, issuer) = test_store().await;
        let mut seed_resource = CanonicalJsonValue::parse(&canonical_host("seed", None)).unwrap();
        let CanonicalJsonValue::Object(seed_root) = &mut seed_resource else {
            panic!("large relist seed root shape");
        };
        let CanonicalJsonValue::Object(seed_status) = seed_root.get_mut("status").unwrap() else {
            panic!("large relist seed status shape");
        };
        seed_status.insert("startedAt".to_owned(), CanonicalJsonValue::Null);
        source
            .commit_verified(verified_create(
                &issuer,
                ResourceRef::parse("Host/seed").unwrap(),
                seed_resource.to_canonical_bytes(),
                None,
                "relist-seed",
            ))
            .await
            .unwrap();
        let mut backup = source.logical_backup().await.unwrap();
        let source = match Arc::try_unwrap(source) {
            Ok(source) => source,
            Err(_) => panic!("large relist source has outstanding references"),
        };
        source.shutdown().await.unwrap();

        let resource_table = backup
            .tables
            .iter()
            .find(|table| table.name == "resources")
            .unwrap();
        let base_resource_row = resource_table.rows[0].clone();
        let base_resource_value = DecodedValue::decode(&base_resource_row.value).unwrap();
        let mut base_record: Value =
            serde_json::from_slice(base_resource_value.canonical_json()).unwrap();
        let base_resource_key = DecodedKey::decode(&base_resource_row.key).unwrap();
        let [
            DecodedKeyComponent::Text(resource_type),
            DecodedKeyComponent::Text(resource_name),
        ] = base_resource_key.components()
        else {
            panic!("large relist resource key shape");
        };
        assert_eq!(resource_type, "Host");
        assert_eq!(resource_name, "seed");
        let controller_binding = base_record["controller_binding_id"]
            .as_str()
            .unwrap()
            .to_owned();

        let mut resource_rows = Vec::with_capacity(RESOURCE_COUNT);
        let mut type_rows = Vec::with_capacity(RESOURCE_COUNT);
        let mut controller_rows = Vec::with_capacity(RESOURCE_COUNT);
        for index in 0..RESOURCE_COUNT {
            if index == 0 {
                resource_rows.push(base_resource_row.clone());
                let base_type = backup
                    .tables
                    .iter()
                    .find(|table| table.name == "type_index")
                    .unwrap()
                    .rows[0]
                    .clone();
                type_rows.push(base_type);
                let base_controller = backup
                    .tables
                    .iter()
                    .find(|table| table.name == "controller_index")
                    .unwrap()
                    .rows[0]
                    .clone();
                controller_rows.push(base_controller);
                continue;
            }
            let name = format!("relist-{index:05}");
            let uid = ResourceUid::parse(format!("123e4567-e89b-42d3-a456-{index:012x}")).unwrap();
            let mut resource = CanonicalJsonValue::parse(&canonical_host(&name, None)).unwrap();
            let CanonicalJsonValue::Object(root) = &mut resource else {
                panic!("large relist resource root shape");
            };
            let CanonicalJsonValue::Object(status) = root.get_mut("status").unwrap() else {
                panic!("large relist status shape");
            };
            status.insert("startedAt".to_owned(), CanonicalJsonValue::Null);
            let CanonicalJsonValue::Object(metadata) = root.get_mut("metadata").unwrap() else {
                panic!("large relist metadata shape");
            };
            metadata.insert(
                "uid".to_owned(),
                CanonicalJsonValue::String(uid.as_str().to_owned()),
            );
            let canonical = resource.to_canonical_bytes();
            let payload_digest = ResourceEnvelope::from_json(&canonical)
                .unwrap()
                .digest()
                .unwrap();

            base_record["canonical_json"] = serde_json::to_value(&canonical).unwrap();
            base_record["payload_digest"] = Value::String(payload_digest);
            let record_json = CanonicalJsonValue::parse(&serde_json::to_vec(&base_record).unwrap())
                .unwrap()
                .to_canonical_bytes();
            let resource_key = encode_key(
                KeySpace::Resources,
                &[KeyComponent::Text("Host"), KeyComponent::Text(&name)],
            )
            .unwrap()
            .into_bytes();
            resource_rows.push(BackupRow {
                key: resource_key,
                value: encode_value(ValueKind::ResourceRecord, &record_json)
                    .unwrap()
                    .into_bytes(),
            });

            let uid_json = serde_json::to_vec(uid.as_str()).unwrap();
            let type_key = encode_key(
                KeySpace::TypeIndex,
                &[KeyComponent::Text("Host"), KeyComponent::Text(&name)],
            )
            .unwrap()
            .into_bytes();
            type_rows.push(BackupRow {
                key: type_key,
                value: encode_value(ValueKind::TypeIndexRecord, &uid_json)
                    .unwrap()
                    .into_bytes(),
            });

            let controller_key = encode_key(
                KeySpace::ControllerIndex,
                &[
                    KeyComponent::Text(&controller_binding),
                    KeyComponent::Text("Host"),
                    KeyComponent::Text(&name),
                ],
            )
            .unwrap()
            .into_bytes();
            controller_rows.push(BackupRow {
                key: controller_key,
                value: encode_value(ValueKind::ControllerIndexRecord, &uid_json)
                    .unwrap()
                    .into_bytes(),
            });
        }
        resource_rows.sort_by(|left, right| left.key.cmp(&right.key));
        type_rows.sort_by(|left, right| left.key.cmp(&right.key));
        controller_rows.sort_by(|left, right| left.key.cmp(&right.key));
        for (table_name, rows) in [
            ("resources", resource_rows),
            ("type_index", type_rows),
            ("controller_index", controller_rows),
        ] {
            let table = backup
                .tables
                .iter_mut()
                .find(|table| table.name == table_name)
                .unwrap();
            table.rows = rows;
            table.checksum = backup_checksum(&table.rows);
        }
        backup.validate().unwrap();

        let directory = tempfile::tempdir().unwrap();
        let store_identity = identity();
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(directory.path().join("store.redb"))
            .unwrap();
        let mut marker = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(directory.path().join("store.marker"))
            .unwrap();
        write_provisioning_marker(&mut marker, &store_identity).unwrap();
        let (_issuer, acceptor) = mutation_seal_pair(store_identity.seal_identity());
        let store =
            RedbResourceStore::restore_owned(file, marker, backup, store_identity, acceptor)
                .await
                .unwrap();
        (directory, Arc::new(store))
    }

    fn backup_checksum(rows: &[BackupRow]) -> String {
        let mut digest = Sha256::new();
        for row in rows {
            digest.update((row.key.len() as u64).to_be_bytes());
            digest.update(&row.key);
            digest.update((row.value.len() as u64).to_be_bytes());
            digest.update(&row.value);
        }
        format!("sha256:{:x}", digest.finalize())
    }

    async fn authorized_test_setup() -> (
        tempfile::TempDir,
        Arc<RedbResourceStore>,
        ResourceService<crate::store::RedbBackend>,
        crate::AuthenticatedSubjectContext,
        AuthorizationState,
        Arc<Mutex<Option<MutationSealIssuer>>>,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(directory.path().join("store.redb"))
            .unwrap();
        let mut marker = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(directory.path().join("store.marker"))
            .unwrap();
        let store_identity = identity();
        let catalog = ApiCatalog::standard();
        let subject_claims = Arc::new(
            SessionClaims::new(
                ResourceRef::parse("User/alice").unwrap(),
                ResourceUid::parse("33333333-3333-4333-8333-333333333333").unwrap(),
                ResourceRef::parse("Zone/work").unwrap(),
                EvidenceClass::UnixPeer,
                SessionPurpose::parse("resource-api").unwrap(),
                ServiceName::parse("d2b.resource.v3").unwrap(),
                SessionBinding::new(
                    SchemaFingerprint::parse(format!("sha256:{}", "1".repeat(64))).unwrap(),
                    TransportBinding::new(
                        Locality::Local,
                        BindingDigest::parse(format!("sha256:{}", "2".repeat(64))).unwrap(),
                    ),
                    ReconnectGeneration::new(1).unwrap(),
                    TranscriptHash::from_bytes([3; 32]),
                ),
            )
            .with_controller_generation(ControllerGeneration::new(1).unwrap()),
        );
        let host = ResourceTypeName::parse("Host").unwrap();
        let role = CompiledRole::new(
            ResourceRef::parse("Role/reconciler-test").unwrap(),
            vec![
                PolicyRule::new(
                    &catalog,
                    [host.clone()],
                    [
                        ResourceVerb::Get,
                        ResourceVerb::List,
                        ResourceVerb::Watch,
                        ResourceVerb::Create,
                        ResourceVerb::UpdateSpec,
                        ResourceVerb::UpdateMetadata,
                        ResourceVerb::Delete,
                    ],
                    [],
                    [],
                    [],
                    [ZoneId::parse("work").unwrap()],
                    [],
                )
                .unwrap(),
                PolicyRule::new(
                    &catalog,
                    [host.clone()],
                    [ResourceVerb::UpdateStatus],
                    [],
                    ["status".to_owned()],
                    [],
                    [ZoneId::parse("work").unwrap()],
                    [],
                )
                .unwrap(),
                PolicyRule::new(
                    &catalog,
                    [host.clone()],
                    [ResourceVerb::UpdateFinalizers],
                    [],
                    ["finalizers".to_owned()],
                    [],
                    [ZoneId::parse("work").unwrap()],
                    [],
                )
                .unwrap(),
                PolicyRule::new(
                    &catalog,
                    [host],
                    [ResourceVerb::Get],
                    [],
                    ["owner".to_owned()],
                    [],
                    [ZoneId::parse("work").unwrap()],
                    [],
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let binding = CompiledRoleBinding::new(
            role.role_ref.clone(),
            [BoundSubject {
                subject_ref: subject_claims.subject_ref().clone(),
                subject_uid: subject_claims.subject_uid().clone(),
            }],
            BindingScope::default(),
            RelayGrantAuthority::None,
        )
        .unwrap();
        let authorizer = Arc::new(
            NativeAuthorizer::new(
                catalog,
                Some(
                    PolicySet::new(&ApiCatalog::standard(), 7, vec![role], vec![binding]).unwrap(),
                ),
            )
            .unwrap(),
        );
        let acceptor = authorizer
            .take_store_seal(store_identity.seal_identity())
            .unwrap();
        write_provisioning_marker(&mut marker, &store_identity).unwrap();
        let store = Arc::new(
            RedbResourceStore::provision_owned(file, marker, store_identity, acceptor)
                .await
                .unwrap(),
        );
        let backend = Arc::new(crate::store::RedbBackend::from_arc(Arc::clone(&store)));
        let service = ResourceService::new_with_zone_uid(
            backend,
            authorizer.clone(),
            Some(ResourceUid::parse("22222222-2222-4222-8222-222222222222").unwrap()),
        )
        .unwrap();
        let state = AuthorizationState {
            snapshot: PolicySnapshot {
                policy_revision: 7,
                api_catalog_revision: 8,
                active_configuration_revision: ConfigurationGeneration::new(9).unwrap(),
                controller_generation: None,
            },
            zone_policy_revision: ZoneRevision::new(7),
            bootstrap_phase: BootstrapPhase::Disabled,
            now_tick: 1,
        };
        let subject = issue_test_subject(subject_claims, state.clone());
        let slot = authorizer.test_store_seal_issuer_slot();
        (directory, store, service, subject, state, slot)
    }

    fn primary_assignment(
        resource_uid: ResourceUid,
        revision: ZoneRevision,
    ) -> ResourceAssignmentFence {
        ResourceAssignmentFence {
            resource_uid,
            resource_revision: revision,
            provider_generation: ResourceGeneration::new(1).unwrap(),
            controller_generation: ControllerGeneration::new(1).unwrap(),
            controller_role: ResourceRef::parse("Process/controller").unwrap(),
            target: ResourceRef::parse("Host/system").unwrap(),
            session_generation: ReconnectGeneration::new(1).unwrap(),
            epoch: 1,
            scope: ResourceAssignmentScope::Primary,
        }
    }

    #[tokio::test]
    async fn transient_backpressure_retry_is_bounded_and_timeout_is_not_retried() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let retry_attempts = Arc::clone(&attempts);
        let started = Instant::now();
        let result = retry_source_backpressure(|| {
            let attempts = Arc::clone(&retry_attempts);
            async move {
                attempts.fetch_add(1, Ordering::AcqRel);
                Err::<(), SourceError>(SourceError::Backpressure)
            }
        })
        .await;
        assert!(matches!(result, Err(SourceError::Backpressure)));
        assert_eq!(
            attempts.load(Ordering::Acquire),
            TRANSIENT_RETRY_ATTEMPTS
        );
        assert!(started.elapsed() < Duration::from_secs(1));

        let attempts = Arc::new(AtomicUsize::new(0));
        let timeout_attempts = Arc::clone(&attempts);
        let result = retry_source_backpressure(|| {
            let attempts = Arc::clone(&timeout_attempts);
            async move {
                attempts.fetch_add(1, Ordering::AcqRel);
                Err::<(), SourceError>(SourceError::Timeout)
            }
        })
        .await;
        assert!(matches!(result, Err(SourceError::Timeout)));
        assert_eq!(attempts.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn transient_backpressure_retry_returns_after_a_bounded_success() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let retry_attempts = Arc::clone(&attempts);
        let result = retry_source_backpressure(|| {
            let attempts = Arc::clone(&retry_attempts);
            async move {
                let attempt = attempts.fetch_add(1, Ordering::AcqRel);
                if attempt < 2 {
                    Err(SourceError::Backpressure)
                } else {
                    Ok::<_, SourceError>(42)
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(result, 42);
        assert_eq!(attempts.load(Ordering::Acquire), 3);
    }

    #[tokio::test]
    async fn registered_api_lists_and_delivers_store_changes_through_core_shape() {
        let (_directory, store, issuer) = test_store().await;
        for (name, owner, operation) in [
            ("owner", None, "create-owner"),
            ("child", Some("Host/owner"), "create-child"),
        ] {
            let target = ResourceRef::parse(&format!("Host/{name}")).unwrap();
            store
                .commit_verified(verified_create(
                    &issuer,
                    target,
                    canonical_host(name, owner),
                    owner,
                    operation,
                ))
                .await
                .unwrap();
        }

        let api = RedbRegisteredControllerApi::for_test_watch(Arc::clone(&store));
        let descriptor = descriptor();
        api.register(&descriptor).await.unwrap();
        let initial = api.list_initial(&descriptor).await.unwrap();
        assert_eq!(initial.resources.len(), 2);
        assert!(initial.snapshot_revision.get() >= 2);
        api.open_watch(&descriptor, ZoneRevision::new(0))
            .await
            .unwrap();

        let first = api.receive_watch_change().await.unwrap().unwrap();
        let second = api.receive_watch_change().await.unwrap().unwrap();
        let third = api.receive_watch_change().await.unwrap().unwrap();
        assert_eq!(
            first.0.target.resource_ref().to_canonical_string(),
            "Host/owner"
        );
        assert_eq!(
            second.0.target.resource_ref().to_canonical_string(),
            "Host/child"
        );
        assert_eq!(
            third.0.target.resource_ref().to_canonical_string(),
            "Host/owner"
        );
        assert!(
            third
                .0
                .reasons
                .contains(&CoreTriggerReason::OwnedResourceChanged)
        );
    }

    #[tokio::test]
    async fn core_source_consumes_the_registered_store_watch() {
        let (_directory, store, issuer) = test_store().await;
        let target = ResourceRef::parse("Host/owner").unwrap();
        store
            .commit_verified(verified_create(
                &issuer,
                target,
                canonical_host("owner", None),
                None,
                "create-owner",
            ))
            .await
            .unwrap();
        let api = Arc::new(RedbRegisteredControllerApi::for_test_watch(store));
        let descriptor = descriptor();
        let source = CoreControllerSource::new(descriptor.clone(), Arc::clone(&api));
        source.register(&descriptor).await.unwrap();
        let initial = source.list_initial(&descriptor).await.unwrap();
        source
            .open_watch(&descriptor, ZoneRevision::new(0))
            .await
            .unwrap();
        assert_eq!(initial.resources.len(), 1);
        let d2b_core_controller::WatchEvent::Hint(hint) = source.receive_watch().await.unwrap()
        else {
            panic!("store watch must produce a controller hint");
        };
        assert_eq!(
            hint.key().resource_ref().to_canonical_string(),
            "Host/owner"
        );
        assert_eq!(hint.revision(), ZoneRevision::new(1));
    }

    #[derive(Debug)]
    struct TestHandlerError;

    impl core::fmt::Display for TestHandlerError {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter.write_str("test handler failed")
        }
    }

    impl std::error::Error for TestHandlerError {}

    struct MutationHandler {
        descriptor: ControllerDescriptor,
        effect_only: bool,
        fail_effect: Option<Arc<AtomicBool>>,
    }

    impl ResourceReconciler for MutationHandler {
        type Error = TestHandlerError;

        fn describe(
            &self,
        ) -> impl Future<Output = Result<ControllerDescriptor, Self::Error>> + Send {
            std::future::ready(Ok(self.descriptor.clone()))
        }

        fn validate_spec(
            &self,
            _context: &ReconcileContext,
            _resource: &d2b_core_controller::ResourceSnapshot,
        ) -> impl Future<Output = Result<ValidationResult, Self::Error>> + Send {
            std::future::ready(Ok(ValidationResult::Valid))
        }

        fn plan(
            &self,
            _context: &ReconcileContext,
            _resource: &d2b_core_controller::ResourceSnapshot,
            _dependencies: &[DependencySnapshot],
        ) -> impl Future<Output = Result<ReconcilePlan, Self::Error>> + Send {
            std::future::ready(
                ReconcilePlan::new(vec!["mutation".to_owned()], false)
                    .map_err(|_| TestHandlerError),
            )
        }

        fn reconcile(
            &self,
            _context: &ReconcileContext,
            resource: &d2b_core_controller::ResourceSnapshot,
            _dependencies: &[DependencySnapshot],
            _plan: &ReconcilePlan,
        ) -> impl Future<Output = Result<ReconcileResult, Self::Error>> + Send {
            if self.effect_only {
                return std::future::ready(Ok(ReconcileResult::converged(
                    resource.revision(),
                    resource.generation(),
                )));
            }
            let mutation = MutationIntent::new(
                resource.key().resource_ref().clone(),
                Some(resource.key().uid().clone()),
                Some(resource.revision()),
                MutationIntentKind::UpdateSpec,
                Some(resource.canonical_json().to_vec()),
            )
            .map_err(|_| TestHandlerError)
            .and_then(|mutation| {
                ReconcileResult::converged(resource.revision(), resource.generation())
                    .with_mutation_batch(
                        d2b_core_controller::ResourceMutationBatch::new(vec![mutation])
                            .map_err(|_| TestHandlerError)?,
                    )
                    .map_err(|_| TestHandlerError)
            });
            std::future::ready(mutation)
        }

        fn execute_effect(
            &self,
            _context: &ReconcileContext,
            resource: &d2b_core_controller::ResourceSnapshot,
            _dependencies: &[DependencySnapshot],
            _plan: &ReconcilePlan,
        ) -> impl Future<Output = Result<ReconcileResult, Self::Error>> + Send {
            if self
                .fail_effect
                .as_ref()
                .is_some_and(|failed| failed.swap(false, Ordering::AcqRel))
            {
                return std::future::ready(Err(TestHandlerError));
            }
            std::future::ready(Ok(ReconcileResult::converged(
                resource.revision(),
                resource.generation(),
            )))
        }

        fn observe(
            &self,
            _context: &ReconcileContext,
            resource: &d2b_core_controller::ResourceSnapshot,
        ) -> impl Future<Output = Result<d2b_core_controller::ObservationResult, Self::Error>> + Send
        {
            std::future::ready(Ok(d2b_core_controller::ObservationResult::new(
                ReconcileResult::converged(resource.revision(), resource.generation()),
            )))
        }

        fn finalize(
            &self,
            _context: &ReconcileContext,
            resource: &d2b_core_controller::ResourceSnapshot,
        ) -> impl Future<Output = Result<FinalizeResult, Self::Error>> + Send {
            std::future::ready(Ok(FinalizeResult::new(ReconcileResult::converged(
                resource.revision(),
                resource.generation(),
            ))))
        }

        fn health(&self) -> impl Future<Output = Result<ControllerHealth, Self::Error>> + Send {
            std::future::ready(Ok(ControllerHealth::Healthy))
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
            _resource: &d2b_core_controller::ResourceSnapshot,
            _dependencies: &[DependencySnapshot],
        ) -> impl Future<Output = Result<d2b_core_controller::UpdateAssessment, Self::Error>> + Send
        {
            std::future::ready(
                d2b_core_controller::UpdateAssessment::new(
                    d2b_core_controller::UpdateAssessmentState::Current,
                    Vec::new(),
                    true,
                )
                .map_err(|_| TestHandlerError),
            )
        }

        fn plan_upgrade(
            &self,
            _context: &ReconcileContext,
            resource: &d2b_core_controller::ResourceSnapshot,
            _dependencies: &[DependencySnapshot],
        ) -> impl Future<Output = Result<UpgradePlan, Self::Error>> + Send {
            std::future::ready(
                UpgradePlan::new(
                    DisruptionClass::Restart,
                    true,
                    vec![UpgradeStage::Restart(resource.key().resource_ref().clone())],
                )
                .map_err(|_| TestHandlerError),
            )
        }

        fn execute_upgrade(
            &self,
            _context: &ReconcileContext,
            resource: &d2b_core_controller::ResourceSnapshot,
            _dependencies: &[DependencySnapshot],
            _plan: &UpgradePlan,
        ) -> impl Future<Output = Result<ReconcileResult, Self::Error>> + Send {
            std::future::ready(Ok(ReconcileResult::converged(
                resource.revision(),
                resource.generation(),
            )))
        }
    }

    #[tokio::test]
    async fn registered_api_commits_finalizer_before_handler_mutation() {
        let (_directory, store, service, subject, state, issuer_slot) =
            authorized_test_setup().await;
        let target = ResourceRef::parse("Host/owner").unwrap();
        store
            .commit_verified(verified_create_from_slot(
                &issuer_slot,
                target,
                canonical_host("owner", None),
                None,
                "create-owner",
            ))
            .await
            .unwrap();
        let api = Arc::new(
            RedbRegisteredControllerApi::for_test_unassigned(&service, subject, state).unwrap(),
        );
        let descriptor = descriptor();
        let source = CoreControllerSource::new(descriptor.clone(), Arc::clone(&api));
        let runner = d2b_core_controller::Runner::new(
            Arc::new(MutationHandler {
                descriptor: descriptor.clone(),
                effect_only: false,
                fail_effect: None,
            }),
            Arc::clone(&source),
            d2b_core_controller::RunnerConfig {
                policy_revision: 7,
                api_revision: 8,
                configuration_revision: ConfigurationGeneration::new(9).unwrap(),
                deadline_tick: 5_000,
                max_attempts: 3,
            },
        )
        .run();
        let runner_task = tokio::spawn(runner);
        let mut finalizer_seen = false;
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let resource = store
                    .get(StoreGetRequest {
                        operation: StoreOperationContext {
                            operation_id: "observe-finalizer".to_owned(),
                            idempotency_key: None,
                            correlation_id: "observe-finalizer".to_owned(),
                            trace_id: None,
                            deadline_ms: 1_000,
                        },
                        zone: ZoneId::parse("work").unwrap(),
                        target: ResourceRef::parse("Host/owner").unwrap(),
                        expected_uid: None,
                        projection: StoreProjection::Full,
                    })
                    .await
                    .unwrap();
                finalizer_seen = finalizer_set(&resource.canonical_json)
                    .unwrap()
                    .contains(&FinalizerId::parse("core.controller").unwrap());
                if finalizer_seen {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(finalizer_seen);
        source.close_watch().unwrap();
        let report = runner_task.await.unwrap().unwrap();
        assert_eq!(report.dispatched, 1);
        assert_eq!(report.checkpointed, 1);
        assert_eq!(
            store.runtime_metadata().await.unwrap().current_revision,
            ZoneRevision::new(2)
        );
        assert!(store.authority_operations().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn registered_api_uses_explicit_identity_and_shared_authorizer_seal_for_effects() {
        let (_directory, store, service, subject, state, issuer_slot) =
            authorized_test_setup().await;
        let target = ResourceRef::parse("Host/owner").unwrap();
        store
            .commit_verified(verified_create_from_slot(
                &issuer_slot,
                target.clone(),
                canonical_host("owner", None),
                None,
                "create-owner",
            ))
            .await
            .unwrap();
        let stored = store
            .get(StoreGetRequest {
                operation: StoreOperationContext {
                    operation_id: "read-owner".to_owned(),
                    idempotency_key: None,
                    correlation_id: "read-owner".to_owned(),
                    trace_id: None,
                    deadline_ms: 1_000,
                },
                zone: ZoneId::parse("work").unwrap(),
                target: target.clone(),
                expected_uid: None,
                projection: StoreProjection::Full,
            })
            .await
            .unwrap();
        let uid = stored.uid.clone();
        let assignment = primary_assignment(uid.clone(), stored.revision);
        let api = Arc::new(
            service
                .registered_controller_api(subject, state, vec![(target.clone(), assignment)])
                .unwrap(),
        );
        let descriptor = descriptor();
        let source = CoreControllerSource::new(descriptor.clone(), Arc::clone(&api));
        let runner = d2b_core_controller::Runner::new(
            Arc::new(MutationHandler {
                descriptor: descriptor.clone(),
                effect_only: true,
                fail_effect: None,
            }),
            Arc::clone(&source),
            d2b_core_controller::RunnerConfig {
                policy_revision: 7,
                api_revision: 8,
                configuration_revision: ConfigurationGeneration::new(9).unwrap(),
                deadline_tick: 5_000,
                max_attempts: 3,
            },
        )
        .run();
        let runner_task = tokio::spawn(runner);
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let rows = store.authority_operations().await.unwrap();
                if rows.iter().any(|row| {
                    row.state == d2b_resource_store_redb::AuthorityOperationState::EffectConfirmed
                }) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        source.close_watch().unwrap();
        let report = runner_task.await.unwrap().unwrap();
        assert!(report.checkpointed >= 1);
        let rows = store.authority_operations().await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].state,
            d2b_resource_store_redb::AuthorityOperationState::EffectConfirmed
        );
        let payload: Value = serde_json::from_slice(&rows[0].payload).unwrap();
        assert_eq!(payload["resourceUid"], uid.as_str());
        assert_eq!(payload["operationClass"], "reconcile");
    }

    #[tokio::test]
    async fn production_mutations_fail_closed_without_a_matching_assignment_fence() {
        let (_directory, store, service, subject, state, issuer_slot) =
            authorized_test_setup().await;
        let target = ResourceRef::parse("Host/owner").unwrap();
        store
            .commit_verified(verified_create_from_slot(
                &issuer_slot,
                target.clone(),
                canonical_host("owner", None),
                None,
                "create-owner",
            ))
            .await
            .unwrap();
        let stored = store
            .get(StoreGetRequest {
                operation: StoreOperationContext {
                    operation_id: "read-owner".to_owned(),
                    idempotency_key: None,
                    correlation_id: "read-owner".to_owned(),
                    trace_id: None,
                    deadline_ms: 1_000,
                },
                zone: ZoneId::parse("work").unwrap(),
                target: target.clone(),
                expected_uid: None,
                projection: StoreProjection::Full,
            })
            .await
            .unwrap();
        let api = service
            .registered_controller_api(subject, state, Vec::new())
            .unwrap();
        let key = ResourceKey::new(stored.zone, stored.resource_ref, stored.uid);
        assert_eq!(
            api.persist_outcome(&ReconcileProjection::new(
                key,
                ZoneRevision::new(1),
                ResourcePhase::Failed,
                d2b_core_controller::ProjectionDisposition::Failed,
                d2b_core_controller::ReconcileReason::HandlerTerminal,
                false,
            ))
            .await
            .unwrap_err(),
            SourceError::Integrity
        );
    }

    #[tokio::test]
    async fn registered_api_refreshes_assignment_at_each_effect_boundary() {
        let (_directory, store, service, subject, state, issuer_slot) =
            authorized_test_setup().await;
        let target = ResourceRef::parse("Host/owner").unwrap();
        store
            .commit_verified(verified_create_from_slot(
                &issuer_slot,
                target.clone(),
                canonical_host("owner", None),
                None,
                "create-owner",
            ))
            .await
            .unwrap();
        let stored = store
            .get(StoreGetRequest {
                operation: StoreOperationContext {
                    operation_id: "read-owner".to_owned(),
                    idempotency_key: None,
                    correlation_id: "read-owner".to_owned(),
                    trace_id: None,
                    deadline_ms: 1_000,
                },
                zone: ZoneId::parse("work").unwrap(),
                target: target.clone(),
                expected_uid: None,
                projection: StoreProjection::Full,
            })
            .await
            .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver_calls = Arc::clone(&calls);
        let api = RedbRegisteredControllerApi::with_identity(
            &service,
            subject,
            state,
            Vec::new(),
        )
        .unwrap()
        .with_assignment_fence_resolver(Arc::new(move |target, uid, revision| {
            let calls = Arc::clone(&resolver_calls);
            Box::pin(async move {
                calls.fetch_add(1, Ordering::AcqRel);
                let _ = target;
                Ok(primary_assignment(uid, revision))
            })
        }));
        let key = ResourceKey::new(
            stored.zone.clone(),
            stored.resource_ref.clone(),
            stored.uid.clone(),
        );
        api.register(&descriptor()).await.unwrap();
        api.read_fresh(&key).await.unwrap();
        assert_eq!(calls.load(Ordering::Acquire), 0);
        api.refresh_assignment(&target, &stored.uid, stored.revision)
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::Acquire), 1);
        api.refresh_assignment(&target, &stored.uid, stored.revision)
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::Acquire), 2);
    }

    #[tokio::test]
    async fn relist_rejoins_a_pending_effect_without_creating_a_duplicate_row() {
        let (_directory, store, service, subject, state, issuer_slot) =
            authorized_test_setup().await;
        let target = ResourceRef::parse("Host/owner").unwrap();
        store
            .commit_verified(verified_create_from_slot(
                &issuer_slot,
                target.clone(),
                canonical_host("owner", None),
                None,
                "create-owner",
            ))
            .await
            .unwrap();
        let stored = store
            .get(StoreGetRequest {
                operation: StoreOperationContext {
                    operation_id: "read-owner".to_owned(),
                    idempotency_key: None,
                    correlation_id: "read-owner".to_owned(),
                    trace_id: None,
                    deadline_ms: 1_000,
                },
                zone: ZoneId::parse("work").unwrap(),
                target: target.clone(),
                expected_uid: None,
                projection: StoreProjection::Full,
            })
            .await
            .unwrap();
        let assignment = primary_assignment(stored.uid.clone(), stored.revision);
        let second_subject = issue_test_subject(subject.claims().clone(), state.clone());
        let api = Arc::new(
            service
                .registered_controller_api(
                    subject,
                    state.clone(),
                    vec![(target.clone(), assignment.clone())],
                )
                .unwrap(),
        );
        let descriptor = descriptor();
        let source = CoreControllerSource::new(descriptor.clone(), Arc::clone(&api));
        let first_failure = Arc::new(AtomicBool::new(true));
        let first_runner = d2b_core_controller::Runner::new(
            Arc::new(MutationHandler {
                descriptor: descriptor.clone(),
                effect_only: true,
                fail_effect: Some(first_failure),
            }),
            Arc::clone(&source),
            d2b_core_controller::RunnerConfig {
                policy_revision: 7,
                api_revision: 8,
                configuration_revision: ConfigurationGeneration::new(9).unwrap(),
                deadline_tick: 5_000,
                max_attempts: 1,
            },
        )
        .run();
        let first_task = tokio::spawn(first_runner);
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let rows = store.authority_operations().await.unwrap();
                if rows.len() == 1
                    && rows[0].state == d2b_resource_store_redb::AuthorityOperationState::Pending
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        source.close_watch().unwrap();
        first_task.await.unwrap().unwrap();

        let api = Arc::new(
            service
                .registered_controller_api(
                    second_subject,
                    state,
                    vec![(target.clone(), assignment)],
                )
                .unwrap(),
        );
        let source = CoreControllerSource::new(descriptor.clone(), Arc::clone(&api));
        let second_task = tokio::spawn(
            d2b_core_controller::Runner::new(
                Arc::new(MutationHandler {
                    descriptor: descriptor.clone(),
                    effect_only: true,
                    fail_effect: None,
                }),
                Arc::clone(&source),
                d2b_core_controller::RunnerConfig {
                    policy_revision: 7,
                    api_revision: 8,
                    configuration_revision: ConfigurationGeneration::new(9).unwrap(),
                    deadline_tick: 5_000,
                    max_attempts: 1,
                },
            )
            .run(),
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let rows = store.authority_operations().await.unwrap();
                if rows.len() == 1
                    && rows[0].state
                        == d2b_resource_store_redb::AuthorityOperationState::EffectConfirmed
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        source.close_watch().unwrap();
        second_task.await.unwrap().unwrap();
        let rows = store.authority_operations().await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].state,
            d2b_resource_store_redb::AuthorityOperationState::EffectConfirmed
        );
    }

    #[tokio::test]
    async fn core_redb_relist_handles_ten_thousand_resources_with_one_hundred_watches() {
        const RESOURCE_COUNT: usize = 10_000;
        const WATCH_COUNT: usize = 100;
        let (_directory, store) = large_relist_store().await;
        let effect_ids = vec!["relist-proof".to_owned()];
        let resource_uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let claim_digest = effect_claim_digest(
            "reconcile",
            &resource_uid,
            ResourceGeneration::new(1).unwrap(),
            &effect_ids,
            None,
        );
        let operation_id = format!("effect:{claim_digest}");
        let payload = serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "kind": "controller-effect",
            "state": "pending",
            "operationClass": "reconcile",
            "effectIds": effect_ids,
            "resourceUid": resource_uid.as_str(),
            "generation": 1,
            "operationId": operation_id,
            "claimDigest": claim_digest,
            "storeBindingDigest": store.authority_binding_digest(&claim_digest),
        }))
        .unwrap();
        store
            .prepare_authority_operation(operation_id.clone(), payload, &claim_digest)
            .await
            .unwrap();
        let descriptor = descriptor();
        let snapshot_revision = store.runtime_metadata().await.unwrap().current_revision;
        let mut sources = Vec::with_capacity(WATCH_COUNT);
        for _ in 0..WATCH_COUNT {
            let api = Arc::new(RedbRegisteredControllerApi::for_test_watch(Arc::clone(
                &store,
            )));
            let source = CoreControllerSource::new(descriptor.clone(), api);
            source.register(&descriptor).await.unwrap();
            source
                .open_watch(&descriptor, snapshot_revision)
                .await
                .unwrap();
            sources.push(source);
        }
        assert_eq!(
            store.watch_signals().unwrap().current_registrations,
            WATCH_COUNT as u64
        );

        let started = Instant::now();
        let initial = sources[0].list_initial(&descriptor).await.unwrap();
        sources[0]
            .open_watch(&descriptor, initial.snapshot_revision)
            .await
            .unwrap();
        let elapsed = started.elapsed();
        assert_eq!(initial.resources.len(), RESOURCE_COUNT);
        assert!(
            elapsed <= Duration::from_secs(5),
            "Core+redb relist/rebuild took {elapsed:?} for {RESOURCE_COUNT} resources and {WATCH_COUNT} watches"
        );
        let rows = store.authority_operations().await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].operation_id, operation_id);
        assert_eq!(
            rows[0].state,
            d2b_resource_store_redb::AuthorityOperationState::Pending
        );
        drop(sources);
    }

    #[test]
    fn status_candidates_are_merged_without_replacing_resource_identity() {
        let current = canonical_host("status", None);
        let merged = merge_status(
            &current,
            br#"{"conditions":[],"observedGeneration":1,"phase":"Ready"}"#,
        )
        .unwrap();
        let value: Value = serde_json::from_slice(&merged).unwrap();
        assert_eq!(value["metadata"]["name"], "status");
        assert_eq!(value["status"]["phase"], "Ready");
        assert!(value["metadata"]["uid"].is_null());
    }

    #[tokio::test]
    async fn ordinary_projection_persists_only_bounded_status_observation() {
        let (_directory, store, service, subject, state, issuer_slot) =
            authorized_test_setup().await;
        let target = ResourceRef::parse("Host/owner").unwrap();
        store
            .commit_verified(verified_create_from_slot(
                &issuer_slot,
                target.clone(),
                canonical_host("owner", None),
                None,
                "create-owner",
            ))
            .await
            .unwrap();
        let stored = store
            .get(StoreGetRequest {
                operation: StoreOperationContext {
                    operation_id: "read-owner".to_owned(),
                    idempotency_key: None,
                    correlation_id: "read-owner".to_owned(),
                    trace_id: None,
                    deadline_ms: 1_000,
                },
                zone: ZoneId::parse("work").unwrap(),
                target: target.clone(),
                expected_uid: None,
                projection: StoreProjection::Full,
            })
            .await
            .unwrap();
        let key = ResourceKey::new(
            stored.zone.clone(),
            stored.resource_ref.clone(),
            stored.uid.clone(),
        );
        let api =
            RedbRegisteredControllerApi::for_test_unassigned(&service, subject, state).unwrap();
        api.persist_outcome(&ReconcileProjection::new(
            key,
            stored.revision,
            d2b_contracts_resource::v3::ResourcePhase::Failed,
            d2b_core_controller::ProjectionDisposition::Failed,
            d2b_core_controller::ReconcileReason::HandlerTerminal,
            false,
        ))
        .await
        .unwrap();
        let updated = store
            .get(StoreGetRequest {
                operation: StoreOperationContext {
                    operation_id: "read-owner-after".to_owned(),
                    idempotency_key: None,
                    correlation_id: "read-owner-after".to_owned(),
                    trace_id: None,
                    deadline_ms: 1_000,
                },
                zone: ZoneId::parse("work").unwrap(),
                target,
                expected_uid: Some(stored.uid),
                projection: StoreProjection::Full,
            })
            .await
            .unwrap();
        let value: Value = serde_json::from_slice(&updated.canonical_json).unwrap();
        assert_eq!(value["status"]["phase"], "Failed");
        assert_eq!(updated.revision, ZoneRevision::new(2));
    }

    #[test]
    fn effect_lifecycle_keeps_running_pending_and_only_marks_uncertainty_retryable() {
        assert_eq!(
            result_state(d2b_core_controller::ReconcileDisposition::Pending),
            d2b_resource_store_redb::AuthorityOperationState::Pending
        );
        assert_eq!(
            result_state(d2b_core_controller::ReconcileDisposition::RequeueAt),
            d2b_resource_store_redb::AuthorityOperationState::Pending
        );
        assert_eq!(
            result_state(d2b_core_controller::ReconcileDisposition::Degraded),
            d2b_resource_store_redb::AuthorityOperationState::Pending
        );
        assert_eq!(
            result_state(d2b_core_controller::ReconcileDisposition::FailedRetryable),
            d2b_resource_store_redb::AuthorityOperationState::EffectRetryable
        );
        assert_eq!(
            result_state(d2b_core_controller::ReconcileDisposition::Converged),
            d2b_resource_store_redb::AuthorityOperationState::EffectConfirmed
        );
        assert_eq!(
            result_state(d2b_core_controller::ReconcileDisposition::Finalized),
            d2b_resource_store_redb::AuthorityOperationState::EffectConfirmed
        );
        assert_eq!(
            result_state(d2b_core_controller::ReconcileDisposition::FailedTerminal),
            d2b_resource_store_redb::AuthorityOperationState::EffectTerminal
        );

        assert_eq!(
            projection_state(
                d2b_core_controller::ProjectionDisposition::Progressing,
                d2b_core_controller::ReconcileReason::ReconcilePass,
            ),
            d2b_resource_store_redb::AuthorityOperationState::Pending
        );
        assert_eq!(
            projection_state(
                d2b_core_controller::ProjectionDisposition::Blocked,
                d2b_core_controller::ReconcileReason::ReconcilePass,
            ),
            d2b_resource_store_redb::AuthorityOperationState::Pending
        );
        assert_eq!(
            projection_state(
                d2b_core_controller::ProjectionDisposition::UpgradeRequired,
                d2b_core_controller::ReconcileReason::UpgradeRequired,
            ),
            d2b_resource_store_redb::AuthorityOperationState::Pending
        );
        assert_eq!(
            projection_state(
                d2b_core_controller::ProjectionDisposition::Failed,
                d2b_core_controller::ReconcileReason::HandlerRetryable,
            ),
            d2b_resource_store_redb::AuthorityOperationState::EffectRetryable
        );
        assert_eq!(
            projection_state(
                d2b_core_controller::ProjectionDisposition::Failed,
                d2b_core_controller::ReconcileReason::HandlerTerminal,
            ),
            d2b_resource_store_redb::AuthorityOperationState::EffectTerminal
        );
    }

    #[test]
    fn effect_identity_ignores_resource_revisions_but_keeps_assignment_fences() {
        let resource_uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let target = ResourceRef::parse("Host/system").unwrap();
        let controller = ResourceRef::parse("Process/controller").unwrap();
        let mut fence = ResourceAssignmentFence {
            resource_uid: resource_uid.clone(),
            resource_revision: ZoneRevision::new(7),
            provider_generation: ResourceGeneration::new(2).unwrap(),
            controller_generation: ControllerGeneration::new(3).unwrap(),
            controller_role: controller,
            target,
            session_generation: ReconnectGeneration::new(4).unwrap(),
            epoch: 5,
            scope: ResourceAssignmentScope::Primary,
        };
        let effects = vec!["effect-a".to_owned(), "effect-b".to_owned()];
        let first = effect_claim_digest(
            "reconcile",
            &resource_uid,
            ResourceGeneration::new(6).unwrap(),
            &effects,
            Some(&fence),
        );
        fence.resource_revision = ZoneRevision::new(99);
        let second = effect_claim_digest(
            "reconcile",
            &resource_uid,
            ResourceGeneration::new(6).unwrap(),
            &effects,
            Some(&fence),
        );
        assert_eq!(first, second);

        fence.scope = ResourceAssignmentScope::OwnerChild {
            owner_ref: ResourceRef::parse("Host/owner").unwrap(),
            owner_uid: resource_uid.clone(),
            owner_revision: ZoneRevision::new(7),
            owner_generation: ResourceGeneration::new(6).unwrap(),
        };
        let owner_first = effect_claim_digest(
            "reconcile",
            &resource_uid,
            ResourceGeneration::new(6).unwrap(),
            &effects,
            Some(&fence),
        );
        if let ResourceAssignmentScope::OwnerChild { owner_revision, .. } = &mut fence.scope {
            *owner_revision = ZoneRevision::new(99);
        }
        let owner_second = effect_claim_digest(
            "reconcile",
            &resource_uid,
            ResourceGeneration::new(6).unwrap(),
            &effects,
            Some(&fence),
        );
        assert_eq!(owner_first, owner_second);

        fence.epoch = 6;
        let changed_assignment = effect_claim_digest(
            "reconcile",
            &resource_uid,
            ResourceGeneration::new(6).unwrap(),
            &effects,
            Some(&fence),
        );
        assert_ne!(first, changed_assignment);
        assert_ne!(
            first,
            effect_claim_digest(
                "reconcile",
                &resource_uid,
                ResourceGeneration::new(7).unwrap(),
                &effects,
                Some(&fence),
            )
        );
    }
}
