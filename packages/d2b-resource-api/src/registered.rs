//! Production Core source adapter for one redb-backed Zone store.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
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
use d2b_resource_store::mutation_seal::MutationSealIssuer;
use d2b_resource_store::{
    AdmittedAuthorization, AdmittedAuthorizationTarget, AdmittedVerb, ExpectedRevision,
    MutationSealBody, PolicySnapshot, PreparedStoreMutation, ResourceMutationKind,
    StoreCommitResult, StoreError, StoreErrorKind, StoreFilter, StoreGetRequest, StoreListRequest,
    StoreMutation, StoreOperationContext, StoreProjection, StoreWatchRequest, StoredResource,
};
use d2b_resource_store_redb::{ChangeEvent, RedbResourceStore, SharedChangeBatch};
use serde_json::Value;

use crate::watch::{ResourceWatch, WatchService};

/// A production `RegisteredControllerApi` backed by one owned redb store.
///
/// The mutation issuer is paired with the acceptor installed in the store by
/// the trusted Zone runtime. No database handle, path, or reusable credential
/// is exposed through the Core source trait.
pub struct RedbRegisteredControllerApi {
    store: Arc<RedbResourceStore>,
    seal_issuer: MutationSealIssuer,
    subject_ref: ResourceRef,
    subject_uid: ResourceUid,
    descriptor: Mutex<Option<ControllerDescriptor>>,
    watch: tokio::sync::Mutex<Option<ResourceWatch>>,
    pending: tokio::sync::Mutex<VecDeque<(ChangeRecord, OperationContext, ZoneRevision)>>,
    acknowledge_after: tokio::sync::Mutex<Option<ZoneRevision>>,
    watch_open: AtomicBool,
    watch_stopped: AtomicBool,
    watch_stop: tokio::sync::Notify,
    accepted:
        Arc<Mutex<BTreeMap<String, Arc<d2b_resource_store_redb::AuthorityOperationCapability>>>>,
}

impl core::fmt::Debug for RedbRegisteredControllerApi {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RedbRegisteredControllerApi")
            .field("has_store", &true)
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
    /// Bind an adapter to a store and its paired mutation issuer.
    pub fn new(store: Arc<RedbResourceStore>, seal_issuer: MutationSealIssuer) -> Self {
        Self::with_identity(
            store,
            seal_issuer,
            ResourceRef::parse("Process/registered-controller")
                .expect("the built-in controller subject is valid"),
            ResourceUid::parse("99999999-9999-4999-8999-999999999999")
                .expect("the built-in controller subject UID is valid"),
        )
    }

    /// Bind an adapter with the authenticated controller identity supplied by
    /// the trusted composition root.
    pub fn with_identity(
        store: Arc<RedbResourceStore>,
        seal_issuer: MutationSealIssuer,
        subject_ref: ResourceRef,
        subject_uid: ResourceUid,
    ) -> Self {
        Self {
            store,
            seal_issuer,
            subject_ref,
            subject_uid,
            descriptor: Mutex::new(None),
            watch: tokio::sync::Mutex::new(None),
            pending: tokio::sync::Mutex::new(VecDeque::new()),
            acknowledge_after: tokio::sync::Mutex::new(None),
            watch_open: AtomicBool::new(false),
            watch_stopped: AtomicBool::new(false),
            watch_stop: tokio::sync::Notify::new(),
            accepted: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Borrow the store used by this adapter.
    pub fn store(&self) -> &Arc<RedbResourceStore> {
        &self.store
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

    async fn policy_snapshot(&self) -> Result<PolicySnapshot, SourceError> {
        self.store
            .runtime_metadata()
            .await
            .map(|metadata| metadata.policy_snapshot)
            .map_err(|error| source_error(error, ZoneRevision::new(0)))
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
            Ok(resource) => Ok(Ok(resource)),
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
                Ok(Err(revision))
            }
            Err(error) => Err(source_error(error, ZoneRevision::new(1))),
        }
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
        operation: StoreOperationContext,
        mutations: Vec<StoreMutation>,
    ) -> Result<CommitOutcome, SourceError> {
        let policy_snapshot = self.policy_snapshot().await?;
        let authorization = AdmittedAuthorization {
            zone: zone.clone(),
            subject_ref: self.subject_ref.clone(),
            subject_uid: self.subject_uid.clone(),
            targets: mutations
                .iter()
                .map(|mutation| AdmittedAuthorizationTarget {
                    resource_type: mutation.target.resource_type().clone(),
                    resource_name: Some(mutation.target.name().clone()),
                    verb: admitted_verb(mutation.kind),
                    subresource: match mutation.kind {
                        ResourceMutationKind::UpdateStatus => Some("status".to_owned()),
                        ResourceMutationKind::UpdateFinalizers => Some("finalizers".to_owned()),
                        _ => None,
                    },
                    execution_ref: None,
                })
                .collect(),
        };
        let prepared = mutations
            .into_iter()
            .map(|mutation| {
                let (uid, digest) = prepared_identity(&mutation)?;
                Ok(PreparedStoreMutation::new(mutation, uid, digest))
            })
            .collect::<Result<Vec<_>, SourceError>>()?;
        let result = self
            .store
            .commit_verified(self.seal_issuer.seal(MutationSealBody {
                mutations: prepared,
                authorization,
                policy_snapshot,
                operation,
            }))
            .await;
        match result {
            Ok(StoreCommitResult { revision, .. }) => Ok(CommitOutcome::Committed(revision)),
            Err(error) if is_conflict(&error) => Ok(CommitOutcome::Conflict(
                error.current_revision().unwrap_or(fallback_revision),
            )),
            Err(error) => Err(source_error(error, fallback_revision)),
        }
    }

    fn resource_operation_id(context: &ReconcileContext) -> String {
        format!(
            "resource:{}:{}",
            context.operation().operation_id(),
            context.attempt()
        )
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
            Err(_) => return Ok(()),
        };
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
            .commit_store_mutations(&current.zone, current.revision, operation, vec![mutation])
            .await?
        {
            CommitOutcome::Committed(_) | CommitOutcome::CommittedStatusPending(_) => Ok(()),
            CommitOutcome::Conflict(_) => Ok(()),
        }
    }

    async fn effect_capability(
        &self,
        operation_id: &str,
        revision: ZoneRevision,
    ) -> Result<Option<Arc<d2b_resource_store_redb::AuthorityOperationCapability>>, SourceError>
    {
        if let Some(capability) = self
            .accepted
            .lock()
            .map_err(|_| SourceError::Integrity)?
            .remove(operation_id)
        {
            return Ok(Some(capability));
        }
        let authority_id = format!("effect:{operation_id}");
        let Some(row) = self
            .store
            .authority_operations()
            .await
            .map_err(|error| source_error(error, revision))?
            .into_iter()
            .find(|row| row.operation_id == authority_id)
        else {
            return Ok(None);
        };
        let payload: Value =
            serde_json::from_slice(&row.payload).map_err(|_| SourceError::Integrity)?;
        let claim_digest = payload
            .get("claimDigest")
            .and_then(Value::as_str)
            .ok_or(SourceError::Integrity)?;
        self.store
            .resume_authority_operation(
                authority_id,
                &self.store.authority_binding_digest(claim_digest),
            )
            .await
            .map(Arc::new)
            .map(Some)
            .map_err(|error| source_error(error, revision))
    }

    async fn record_effect_state(
        &self,
        operation_id: &str,
        revision: ZoneRevision,
        state: d2b_resource_store_redb::AuthorityOperationState,
    ) -> Result<(), SourceError> {
        if let Some(capability) = self.effect_capability(operation_id, revision).await? {
            capability
                .record_effect(state)
                .await
                .map_err(|error| source_error(error, revision))?;
        }
        Ok(())
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
                    StoreProjection::Full,
                    "initial",
                )
                .await?;
            Ok(InitialList {
                resources: resources
                    .into_iter()
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
                    let mut watch = self.watch.lock().await;
                    let Some(watch) = watch.as_mut() else {
                        return Ok(None);
                    };
                    if self.watch_stopped.load(Ordering::Acquire) {
                        return Ok(None);
                    }
                    tokio::select! {
                        batch = watch.recv() => batch,
                        _ = self.watch_stop.notified() => return Ok(None),
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
                Ok(resource) => Ok(FreshSnapshot::Present {
                    target: snapshot_from_resource(resource),
                    dependencies: self.dependencies(&descriptor, key.zone()).await?,
                }),
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
        _context: &ReconcileContext,
    ) -> impl Future<Output = Result<(), SourceError>> + Send {
        std::future::ready(Ok(()))
    }

    fn accept_effect(
        &self,
        context: &ReconcileContext,
        plan: &ReconcilePlan,
    ) -> impl Future<Output = Result<(), SourceError>> + Send {
        let operation_id = context.operation().operation_id().to_owned();
        let authority_operation_id = format!("effect:{operation_id}");
        let effect_identity = plan.effect_ids().join("\0");
        let claim_digest = canonical_digest(
            "d2b:controller-effect-claim/v1",
            format!(
                "{}:{}:{}:{}:{}",
                context.target().uid().as_str(),
                context.generation().get(),
                context.revision().get(),
                plan.effect_count(),
                effect_identity,
            )
            .as_bytes(),
        );
        let store = Arc::clone(&self.store);
        let accepted = self.accepted.clone();
        async move {
            let payload = serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "kind": "controller-effect",
                "state": "pending",
                "zone": context.target().zone().as_str(),
                "resourceUid": context.target().uid().as_str(),
                "generation": context.generation().get(),
                "revision": context.revision().get(),
                "operationId": operation_id,
                "claimDigest": claim_digest,
                "storeBindingDigest": store.authority_binding_digest(&claim_digest),
                "effectCount": plan.effect_count(),
            }))
            .map_err(|_| SourceError::Integrity)?;
            let capability = store
                .prepare_authority_operation(authority_operation_id.clone(), payload, &claim_digest)
                .await
                .map_err(|error| source_error(error, context.revision()))?;
            accepted.lock().map_err(|_| SourceError::Integrity)?.insert(
                context.operation().operation_id().to_owned(),
                Arc::new(capability),
            );
            Ok(())
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
                projection_state(projection.disposition()),
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

fn prepared_identity(
    mutation: &StoreMutation,
) -> Result<(Option<ResourceUid>, Option<String>), SourceError> {
    let Some(bytes) = mutation.canonical_resource.as_deref() else {
        return Ok((mutation.expected_uid.clone(), None));
    };
    let digest = if mutation.kind == ResourceMutationKind::Create {
        let value = d2b_contracts_resource::v3::CanonicalJsonValue::parse(bytes)
            .map_err(|_| SourceError::Integrity)?;
        canonical_digest(
            d2b_contracts_resource::v3::RESOURCE_ENVELOPE_DOMAIN_TAG,
            &value.to_canonical_bytes(),
        )
    } else {
        ResourceEnvelope::from_json(bytes)
            .map_err(|_| SourceError::Integrity)?
            .digest()
            .map_err(|_| SourceError::Integrity)?
    };
    Ok((mutation.expected_uid.clone(), Some(digest)))
}

fn admitted_verb(kind: ResourceMutationKind) -> AdmittedVerb {
    match kind {
        ResourceMutationKind::Create => AdmittedVerb::Create,
        ResourceMutationKind::UpdateSpec => AdmittedVerb::UpdateSpec,
        ResourceMutationKind::UpdateStatus => AdmittedVerb::UpdateStatus,
        ResourceMutationKind::UpdateMetadata => AdmittedVerb::UpdateMetadata,
        ResourceMutationKind::UpdateFinalizers => AdmittedVerb::UpdateFinalizers,
        ResourceMutationKind::Delete => AdmittedVerb::Delete,
    }
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

const fn projection_state(
    disposition: d2b_core_controller::ProjectionDisposition,
) -> d2b_resource_store_redb::AuthorityOperationState {
    match disposition {
        d2b_core_controller::ProjectionDisposition::Converged => {
            d2b_resource_store_redb::AuthorityOperationState::EffectConfirmed
        }
        d2b_core_controller::ProjectionDisposition::Failed => {
            d2b_resource_store_redb::AuthorityOperationState::EffectTerminal
        }
        d2b_core_controller::ProjectionDisposition::Progressing
        | d2b_core_controller::ProjectionDisposition::Blocked
        | d2b_core_controller::ProjectionDisposition::UpgradeRequired => {
            d2b_resource_store_redb::AuthorityOperationState::EffectRetryable
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
        | d2b_core_controller::ReconcileDisposition::RequeueAt
        | d2b_core_controller::ReconcileDisposition::FailedRetryable => {
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
    use std::time::Duration;

    use d2b_contracts_resource::v3::{
        CanonicalJsonValue, ConfigurationGeneration, ControllerGeneration,
        RESOURCE_ENVELOPE_DOMAIN_TAG, ResourceTypeName, Timestamp,
    };
    use d2b_core_controller::{
        ChangeField, ControllerExecutionPolicy, ControllerHealth, ControllerIdentity,
        ControllerSource, ControllerVerb, CoreControllerSource, DisruptionClass, DrainResult,
        FinalizeResult, MutationIntent, MutationIntentKind, ReconcileResult, ResourceReconciler,
        ResourceRegistration, ResyncPolicy, UpgradePlan, UpgradeStage, ValidationResult,
        WatchSelector,
    };
    use d2b_resource_store::mutation_seal::mutation_seal_pair;
    use d2b_resource_store::{SealedMutation, StoreMutation, StoreSlot};
    use d2b_resource_store_redb::{StoreIdentity, write_provisioning_marker};

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
        let digest = canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &canonical);
        issuer.seal(MutationSealBody {
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
        })
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
        let api = RedbRegisteredControllerApi::new(Arc::clone(&store), issuer);
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
        let api = Arc::new(RedbRegisteredControllerApi::new(store, issuer));
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
        let api = Arc::new(RedbRegisteredControllerApi::new(Arc::clone(&store), issuer));
        let descriptor = descriptor();
        let source = CoreControllerSource::new(descriptor.clone(), Arc::clone(&api));
        let runner = d2b_core_controller::Runner::new(
            Arc::new(MutationHandler {
                descriptor: descriptor.clone(),
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
        let (_directory, store, issuer) = test_store().await;
        let target = ResourceRef::parse("Host/owner").unwrap();
        store
            .commit_verified(verified_create(
                &issuer,
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
        let api = RedbRegisteredControllerApi::new(store.clone(), issuer);
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
}
