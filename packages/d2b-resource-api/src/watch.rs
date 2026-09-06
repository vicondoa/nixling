//! Resource-API watch ownership over the concrete store stream.
//!
//! The wire service returns a stream name and snapshot revision, while the
//! authenticated bus owns the actual delivery task.  This module keeps that
//! handoff explicit: registration and replay are performed by the store
//! actor, and acknowledgements return to that same actor.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use d2b_contracts_resource::v3::{ResourceRef, ResourceUid, ZoneRevision};
use d2b_resource_store::{StoreError, StoreErrorKind, StoreWatchReceipt, StoreWatchRequest};
use d2b_resource_store_redb::{
    ChangeEvent, OwnerChangeEvent, RedbResourceStore, SharedChangeBatch, WatchRegistrationId,
    WatchSignals, WatchStream,
};
use serde_json::json;

/// One immutable encoded watch delivery.
#[derive(Clone, PartialEq, Eq)]
pub struct WatchFrame {
    revision: ZoneRevision,
    payload: Arc<[u8]>,
    owner_hints: Vec<WatchOwnerHint>,
}

impl core::fmt::Debug for WatchFrame {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("WatchFrame")
            .field("revision", &self.revision)
            .field("payload_bytes", &self.payload.len())
            .field("owner_hint_count", &self.owner_hints.len())
            .finish()
    }
}

impl WatchFrame {
    /// Return the durable revision represented by this frame.
    pub const fn revision(&self) -> ZoneRevision {
        self.revision
    }

    /// Borrow the bounded wire payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Borrow owner notifications carried by this frame.
    pub fn owner_hints(&self) -> &[WatchOwnerHint] {
        &self.owner_hints
    }
}

/// A bounded owner notification extracted from a committed change.
///
/// Deletion rows may not retain the historical owner reference in their
/// payload.  The immutable owner UID is still carried, allowing the
/// controller to resolve the owner from its index before relisting.
#[derive(Clone, PartialEq, Eq)]
pub struct WatchOwnerHint {
    owner_ref: Option<ResourceRef>,
    owner_uid: ResourceUid,
    child_ref: ResourceRef,
    child_uid: ResourceUid,
    revision: ZoneRevision,
    event: ChangeEvent,
    owner_event: OwnerChangeEvent,
}

impl core::fmt::Debug for WatchOwnerHint {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("WatchOwnerHint")
            .field("has_owner_ref", &self.owner_ref.is_some())
            .field("child_kind", &self.child_ref.resource_type())
            .field("revision", &self.revision)
            .field("event", &self.event)
            .field("owner_event", &self.owner_event)
            .finish()
    }
}

impl WatchOwnerHint {
    /// Return the owner reference when the committed envelope retained it.
    pub const fn owner_ref(&self) -> Option<&ResourceRef> {
        self.owner_ref.as_ref()
    }

    /// Borrow the immutable owner UID binding.
    pub const fn owner_uid(&self) -> &ResourceUid {
        &self.owner_uid
    }

    /// Borrow the changed child reference.
    pub const fn child_ref(&self) -> &ResourceRef {
        &self.child_ref
    }

    /// Borrow the immutable child UID.
    pub const fn child_uid(&self) -> &ResourceUid {
        &self.child_uid
    }

    /// Return the durable revision carrying this hint.
    pub const fn revision(&self) -> ZoneRevision {
        self.revision
    }

    /// Return the child-change event.
    pub const fn event(&self) -> ChangeEvent {
        self.event
    }

    /// Return the owner-trigger event, including reparent transitions.
    pub const fn owner_event(&self) -> OwnerChangeEvent {
        self.owner_event
    }
}

/// Closed failures returned by a named-stream delivery sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchSinkError {
    /// The sink is waiting for transport credit.
    Backpressure,
    /// The authenticated destination or stream is gone.
    Closed,
    /// The sink cannot carry one complete watch frame.
    FrameTooLarge,
}

impl core::fmt::Display for WatchSinkError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Backpressure => "watch sink is backpressured",
            Self::Closed => "watch sink is closed",
            Self::FrameTooLarge => "watch frame exceeds sink bounds",
        })
    }
}

impl std::error::Error for WatchSinkError {}

/// Sink implemented by the authenticated bus named-stream adapter.
pub trait WatchSink: Send + Sync {
    fn send(&self, frame: WatchFrame) -> impl Future<Output = Result<(), WatchSinkError>> + Send;
}

/// Failure returned by the complete watch-to-sink handoff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchPumpError {
    Store(StoreError),
    Sink(WatchSinkError),
}

impl core::fmt::Display for WatchPumpError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Store(error) => {
                write!(formatter, "watch store failed: {}", error.kind().as_str())
            }
            Self::Sink(error) => write!(formatter, "watch sink failed: {error}"),
        }
    }
}

impl std::error::Error for WatchPumpError {}

/// One authenticated resource watch with an owned delivery stream.
pub struct ResourceWatch {
    store: Arc<RedbResourceStore>,
    request: StoreWatchRequest,
    receipt: StoreWatchReceipt,
    stream: WatchStream,
    last_acknowledged: AtomicU64,
}

impl core::fmt::Debug for ResourceWatch {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ResourceWatch")
            .field("registration", &self.stream.id())
            .field("receipt", &self.receipt)
            .finish()
    }
}

impl ResourceWatch {
    fn new(
        store: Arc<RedbResourceStore>,
        request: StoreWatchRequest,
        receipt: StoreWatchReceipt,
        stream: WatchStream,
    ) -> Self {
        let last_acknowledged = request.after_revision.get();
        Self {
            store,
            request,
            receipt,
            stream,
            last_acknowledged: AtomicU64::new(last_acknowledged),
        }
    }

    /// The receipt returned to the authenticated stream owner.
    pub const fn receipt(&self) -> &StoreWatchReceipt {
        &self.receipt
    }

    /// The opaque registration id used for acknowledgements.
    pub const fn id(&self) -> WatchRegistrationId {
        self.stream.id()
    }

    /// Receive the next shared immutable change batch.
    pub async fn recv(&mut self) -> Option<SharedChangeBatch> {
        self.stream.recv().await
    }

    /// Receive and encode one complete immutable batch for a transport sink.
    pub async fn recv_frame(&mut self) -> Result<Option<WatchFrame>, StoreError> {
        let Some(batch) = self.recv().await else {
            return Ok(None);
        };
        encode_frame(batch).map(Some)
    }

    /// Acknowledge all batches through `revision`.
    pub async fn acknowledge(&self, revision: ZoneRevision) -> Result<(), StoreError> {
        self.store.acknowledge_watch(self.id(), revision).await?;
        self.last_acknowledged
            .fetch_max(revision.get(), Ordering::AcqRel);
        Ok(())
    }

    /// Pump the watch into one bounded sink, acknowledging only after the
    /// sink accepts the frame.
    ///
    /// A closed storage sender is the deterministic slow-watcher handoff.  The
    /// next registration starts at the last acknowledged cursor, so replay
    /// and live delivery remain one ordered sequence.
    pub async fn pump_to<S: WatchSink>(&mut self, sink: &S) -> Result<(), WatchPumpError> {
        loop {
            let Some(frame) = self.recv_frame().await.map_err(WatchPumpError::Store)? else {
                self.reopen_after_eviction()
                    .await
                    .map_err(WatchPumpError::Store)?;
                continue;
            };
            let revision = frame.revision();
            sink.send(frame).await.map_err(WatchPumpError::Sink)?;
            self.last_acknowledged
                .fetch_max(revision.get(), Ordering::AcqRel);
            match self.acknowledge(revision).await {
                Ok(()) => {}
                Err(error)
                    if error.reason_code() == "watch-registration-missing"
                        || error.kind() == StoreErrorKind::StoreBackpressure =>
                {
                    self.reopen_after_eviction()
                        .await
                        .map_err(WatchPumpError::Store)?;
                }
                Err(error) => return Err(WatchPumpError::Store(error)),
            }
        }
    }

    /// Reopen an evicted watch from its last acknowledged revision.
    pub async fn resume(&mut self) -> Result<(), StoreError> {
        self.reopen_after_eviction().await
    }

    async fn reopen_after_eviction(&mut self) -> Result<(), StoreError> {
        let mut request = self.request.clone();
        request.after_revision = ZoneRevision::new(self.last_acknowledged.load(Ordering::Acquire));
        self.store.unregister_watch_now(self.id());
        let (receipt, stream) = self.store.watch_stream(request.clone()).await?;
        self.request = request;
        self.receipt = receipt;
        self.stream = stream;
        Ok(())
    }

    /// Explicitly close the watch and release its global budget.
    pub async fn close(self) -> Result<Option<ZoneRevision>, StoreError> {
        let id = self.id();
        self.store.unregister_watch(id).await
    }
}

impl Drop for ResourceWatch {
    fn drop(&mut self) {
        self.store.unregister_watch_now(self.id());
    }
}

/// Resource-API watch adapter for one already-authorized Zone store.
pub struct WatchService {
    store: Arc<RedbResourceStore>,
}

impl core::fmt::Debug for WatchService {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("WatchService(<redacted>)")
    }
}

impl WatchService {
    /// Bind the adapter to the one store selected by the authenticated Zone.
    pub const fn new(store: Arc<RedbResourceStore>) -> Self {
        Self { store }
    }

    /// Register, replay, and return an owned stream without a replay/live gap.
    pub async fn open(&self, request: StoreWatchRequest) -> Result<ResourceWatch, StoreError> {
        let (receipt, stream) = self.store.watch_stream(request.clone()).await?;
        Ok(ResourceWatch::new(
            Arc::clone(&self.store),
            request,
            receipt,
            stream,
        ))
    }

    /// Return the fixed-cardinality store watch saturation snapshot.
    pub fn signals(&self) -> Result<WatchSignals, StoreError> {
        self.store.watch_signals()
    }
}

fn encode_frame(batch: SharedChangeBatch) -> Result<WatchFrame, StoreError> {
    let mut entries = Vec::new();
    let mut owner_hints = Vec::new();
    for entry in batch.entries() {
        let value = serde_json::to_value(entry).map_err(|_| frame_integrity())?;
        owner_hints.extend(owner_hints_for_entry(entry, batch.revision()));
        entries.push(value);
    }
    let owner_hints_wire = owner_hints
        .iter()
        .map(|hint| {
            json!({
                "ownerRef": hint.owner_ref().map(ResourceRef::to_canonical_string),
                "ownerUid": hint.owner_uid().as_str(),
                "childRef": hint.child_ref().to_canonical_string(),
                "childUid": hint.child_uid().as_str(),
                "revision": hint.revision().get(),
                "event": hint.event(),
                "ownerEvent": hint.owner_event(),
            })
        })
        .collect::<Vec<_>>();
    let payload = serde_json::to_vec(&json!({
        "revision": batch.revision().get(),
        "entries": entries,
        "ownerHints": owner_hints_wire,
    }))
    .map_err(|_| frame_integrity())?;
    Ok(WatchFrame {
        revision: batch.revision(),
        payload: Arc::from(payload),
        owner_hints,
    })
}

fn owner_hints_for_entry(
    entry: &d2b_resource_store_redb::ChangeEntry,
    revision: ZoneRevision,
) -> Vec<WatchOwnerHint> {
    let child_ref = ResourceRef::new(entry.resource_type().clone(), entry.resource_name().clone());
    let mut hints = Vec::new();
    let current_owner = entry
        .owner_ref()
        .zip(entry.owner_uid())
        .map(|(owner_ref, owner_uid)| (owner_ref.clone(), owner_uid.clone()));
    let current_owner = current_owner.or_else(|| {
        (entry.event() == ChangeEvent::Deleted || entry.event() == ChangeEvent::DeletionRequested)
            .then(|| {
                entry
                    .previous_owner_ref()
                    .zip(entry.previous_owner_uid())
                    .map(|(owner_ref, owner_uid)| (owner_ref.clone(), owner_uid.clone()))
            })
            .flatten()
    });
    if let (Some(owner_ref), Some(owner_uid)) =
        (entry.previous_owner_ref(), entry.previous_owner_uid())
    {
        if current_owner.as_ref() != Some(&(owner_ref.clone(), owner_uid.clone())) {
            hints.push(WatchOwnerHint {
                owner_ref: Some(owner_ref.clone()),
                owner_uid: owner_uid.clone(),
                child_ref: child_ref.clone(),
                child_uid: entry.resource_uid().clone(),
                revision,
                event: ChangeEvent::MetadataUpdated,
                owner_event: OwnerChangeEvent::Reparented,
            });
        }
    }
    if let Some((owner_ref, owner_uid)) = current_owner {
        hints.push(WatchOwnerHint {
            owner_ref: Some(owner_ref),
            owner_uid,
            child_ref,
            child_uid: entry.resource_uid().clone(),
            revision,
            event: entry.event(),
            owner_event: owner_change_event(entry.event()),
        });
    }

    const fn owner_change_event(event: ChangeEvent) -> OwnerChangeEvent {
        match event {
            ChangeEvent::Created => OwnerChangeEvent::Created,
            ChangeEvent::SpecUpdated => OwnerChangeEvent::SpecUpdated,
            ChangeEvent::StatusUpdated => OwnerChangeEvent::StatusUpdated,
            ChangeEvent::MetadataUpdated => OwnerChangeEvent::MetadataUpdated,
            ChangeEvent::FinalizersUpdated => OwnerChangeEvent::FinalizersUpdated,
            ChangeEvent::DeletionRequested => OwnerChangeEvent::DeletionRequested,
            ChangeEvent::Deleted => OwnerChangeEvent::Deleted,
        }
    }
    hints
}

fn frame_integrity() -> StoreError {
    StoreError::new(
        StoreErrorKind::StoreIntegrityFailure,
        None,
        None,
        d2b_contracts_resource::v3::RetryClass::Never,
        "watch-frame-encoding-failed",
    )
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::path::{Path, PathBuf};
    use std::sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    };
    use std::time::Duration;

    use d2b_contracts_resource::v3::{
        CanonicalJsonValue, ConfigurationGeneration, RESOURCE_ENVELOPE_DOMAIN_TAG, ResourceRef,
        ResourceTypeName, ResourceUid, Timestamp, ZoneId, canonical_digest,
    };
    use d2b_resource_store::mutation_seal::{MutationSealBody, mutation_seal_pair};
    use d2b_resource_store::{
        AdmittedAuthorization, AdmittedAuthorizationTarget, AdmittedVerb, ExpectedRevision,
        PolicySnapshot, PreparedStoreMutation, ResourceMutationKind, StoreMutation,
        StoreOperationContext, StoreProjection, StoreSlot,
    };
    use d2b_resource_store_redb::{StoreIdentity, write_provisioning_marker};
    use serde_json::Value;

    use super::*;

    #[test]
    fn watch_adapter_has_no_public_selector_or_path_surface() {
        let source = include_str!("watch.rs");
        assert!(!source.contains(&["host_pa", "th"].concat()));
        assert!(!source.contains(&["pa", "th_template"].concat()));
        assert!(source.contains("acknowledge"));
        assert!(source.contains("unregister_watch_now"));
        assert!(source.contains("pump_to"));
    }

    struct CollectSink {
        frames: Mutex<Vec<WatchFrame>>,
        limit: usize,
    }

    impl CollectSink {
        fn new(limit: usize) -> Arc<Self> {
            Arc::new(Self {
                frames: Mutex::new(Vec::new()),
                limit,
            })
        }

        fn revisions(&self) -> Vec<ZoneRevision> {
            self.frames
                .lock()
                .unwrap()
                .iter()
                .map(WatchFrame::revision)
                .collect()
        }
    }

    impl WatchSink for CollectSink {
        #[allow(clippy::manual_async_fn)]
        fn send(
            &self,
            frame: WatchFrame,
        ) -> impl Future<Output = Result<(), WatchSinkError>> + Send {
            async move {
                let mut frames = self.frames.lock().unwrap();
                if frames.len() >= self.limit {
                    return Err(WatchSinkError::Closed);
                }
                frames.push(frame);
                if frames.len() >= self.limit {
                    Err(WatchSinkError::Closed)
                } else {
                    Ok(())
                }
            }
        }
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "d2b-resource-api-watch-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn test_identity() -> StoreIdentity {
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

    async fn test_store() -> (
        TestDirectory,
        Arc<RedbResourceStore>,
        d2b_resource_store::mutation_seal::MutationSealIssuer,
    ) {
        let directory = TestDirectory::new();
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
        let identity = test_identity();
        write_provisioning_marker(&mut marker, &identity).unwrap();
        let (issuer, acceptor) = mutation_seal_pair(identity.seal_identity());
        let store = RedbResourceStore::provision_owned(file, marker, identity, acceptor)
            .await
            .unwrap();
        (directory, Arc::new(store), issuer)
    }

    fn operation(id: &str) -> StoreOperationContext {
        StoreOperationContext {
            operation_id: id.to_owned(),
            idempotency_key: Some(format!("key-{id}")),
            correlation_id: format!("correlation-{id}"),
            trace_id: None,
            deadline_ms: 1_000,
        }
    }

    fn canonical_host(name: &str, owner: Option<&str>) -> Vec<u8> {
        let raw = format!(
            r#"{{"apiVersion":"resources.d2bus.org/v3","metadata":{{"configurationGeneration":7,"createdAt":"2026-07-22T00:00:00.000Z","deletionRequestedAt":null,"finalizers":[],"generation":1,"managedBy":"configuration","name":"{name}","ownerRef":null,"revision":1,"uid":"123e4567-e89b-42d3-a456-426614174000","updatedAt":"2026-07-22T00:00:00.000Z","zone":"work"}},"spec":{{"providerRef":"Provider/system-core","updatePolicy":{{"disruptive":"manual","nonDisruptive":"automatic"}}}},"status":{{"completedAt":null,"conditions":[],"lastReconciledAt":null,"observedGeneration":0,"outcome":null,"phase":"Pending","resource":{{}},"startedAt":null,"update":{{"dependencies":{{"count":0,"refs":[]}},"disruption":"None","lastAssessedAt":null,"observedGeneration":0,"operationId":null,"owned":{{"count":0,"refs":[]}},"preserveState":true,"reasons":[],"state":"Unknown","targetGeneration":1}}}},"type":"Host"}}"#
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

    async fn commit_host(
        store: &RedbResourceStore,
        issuer: &d2b_resource_store::mutation_seal::MutationSealIssuer,
        name: &str,
        owner: Option<&str>,
        operation_id: &str,
    ) -> ZoneRevision {
        let target = ResourceRef::parse(&format!("Host/{name}")).unwrap();
        let canonical = canonical_host(name, owner);
        let digest = canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &canonical);
        let body = MutationSealBody {
            mutations: vec![PreparedStoreMutation::new(
                StoreMutation {
                    kind: ResourceMutationKind::Create,
                    zone: ZoneId::parse("work").unwrap(),
                    target: target.clone(),
                    expected: ExpectedRevision::CreateAbsent,
                    expected_uid: None,
                    owner: owner.map(ResourceRef::parse).transpose().unwrap(),
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
                    resource_type: ResourceTypeName::parse("Host").unwrap(),
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
            operation: operation(operation_id),
        };
        store
            .commit_verified(issuer.seal(body))
            .await
            .unwrap()
            .revision
    }

    fn watch_request(after_revision: u64, initial_credits: u32) -> StoreWatchRequest {
        StoreWatchRequest {
            operation: operation("watch"),
            zone: ZoneId::parse("work").unwrap(),
            resource_types: vec![ResourceTypeName::parse("Host").unwrap()],
            resource_names: Vec::new(),
            filters: Vec::new(),
            after_revision: ZoneRevision::new(after_revision),
            initial_credits,
            projection: StoreProjection::Full,
        }
    }

    #[tokio::test]
    async fn production_watch_frames_preserve_replay_live_order_and_owner_hints() {
        let (_directory, store, issuer) = test_store().await;
        let service = WatchService::new(Arc::clone(&store));
        let mut watch = service.open(watch_request(0, 4)).await.unwrap();
        let sink = CollectSink::new(2);
        let sink_for_task = Arc::clone(&sink);
        let pump = tokio::spawn(async move { watch.pump_to(sink_for_task.as_ref()).await });

        let owner_revision = commit_host(&store, &issuer, "owner", None, "owner").await;
        let child_revision =
            commit_host(&store, &issuer, "child", Some("Host/owner"), "child").await;
        let result = tokio::time::timeout(Duration::from_secs(1), pump)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result, Err(WatchPumpError::Sink(WatchSinkError::Closed)));
        assert_eq!(
            sink.revisions(),
            vec![owner_revision, child_revision],
            "replay and live batches must have one monotonic handoff"
        );
        let frames = sink.frames.lock().unwrap();
        assert!(frames[0].owner_hints().is_empty());
        assert_eq!(frames[1].owner_hints().len(), 1);
        let hint = &frames[1].owner_hints()[0];
        assert_eq!(
            hint.owner_ref().map(ResourceRef::to_canonical_string),
            Some("Host/owner".to_owned())
        );
        assert_eq!(hint.child_ref().to_canonical_string(), "Host/child");
        assert_eq!(hint.event(), ChangeEvent::Created);
        assert_eq!(
            serde_json::from_slice::<Value>(frames[1].payload()).unwrap()["ownerHints"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            frames[1].owner_hints()[0].owner_event(),
            OwnerChangeEvent::Created
        );
    }

    #[tokio::test]
    async fn production_watch_resumes_after_deterministic_slow_eviction() {
        let (_directory, store, issuer) = test_store().await;
        let service = WatchService::new(Arc::clone(&store));
        let mut watch = service.open(watch_request(0, 1)).await.unwrap();
        let rejected = service
            .open(watch_request(0, 0))
            .await
            .expect_err("zero-credit admission is typed backpressure");
        assert_eq!(rejected.kind(), StoreErrorKind::StoreBackpressure);
        let first = commit_host(&store, &issuer, "first", None, "first").await;
        watch.recv_frame().await.unwrap().expect("first delivery");
        watch.acknowledge(first).await.unwrap();
        let second = commit_host(&store, &issuer, "second", None, "second").await;
        let third = commit_host(&store, &issuer, "third", None, "third").await;
        let signals = store.watch_signals().unwrap();
        assert_eq!(signals.current_registrations, 0);
        assert_eq!(signals.budget_used, 0);
        assert_eq!(signals.budget_capacity, 1024);
        assert!(signals.admission_rejections >= 1);
        assert_eq!(signals.slow_watcher_evictions, 1);

        let sink = CollectSink::new(2);
        let result = watch.pump_to(sink.as_ref()).await;
        assert_eq!(result, Err(WatchPumpError::Sink(WatchSinkError::Closed)));
        assert_eq!(sink.revisions(), vec![second, third]);
        watch.close().await.unwrap();
        let signals = store.watch_signals().unwrap();
        assert_eq!(signals.current_registrations, 0);
        assert_eq!(signals.budget_used, 0);
        assert!(signals.replay_work >= 1);
    }
}
