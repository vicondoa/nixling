//! Fair single-writer actor, bounded reads, replay, and shared live delivery.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use d2b_audit::OperationIdentity;
use d2b_audit::{DurabilityEvidence, DurabilityOutcome, Reconciliation, ZoneOperationKey};
use d2b_contracts_resource::v3::{
    ResourceRef, ResourceTypeName, ResourceUid, ZoneId, ZoneRevision,
};
use d2b_resource_store::{
    ExpectedRevision, ResourceMutationKind, StoreError, StoreFilter, StoreGetRequest,
    StoreInspectSchemaRequest, StoreListRequest, StoreListResult, StoreProjection,
    StoreResolveRequest, StoreResolvedIdentity, StoredResource, StoredSchema,
};
use redb::{Database, ReadableDatabase};
use tokio::sync::{OwnedSemaphorePermit, mpsc, oneshot};

use crate::BrokerEvidenceIndex;
use crate::ValueKind;
#[cfg(test)]
use crate::audit::NoopMutationAudit;
use crate::audit::{
    DurableMutationAudit, opaque_digest, resource_mutation_record,
    resource_mutation_record_with_identity,
};
use crate::backup::LogicalBackup;
#[cfg(test)]
use crate::metrics::NoopStoreTelemetry;
use crate::metrics::{StoreMetric, StoreTelemetry};
use crate::revision_log::{WatchCoordinator, WatchRegistrationId, WatchSelector, WatchStream};
use crate::tracing::{STORE_READ_SPAN, STORE_WRITE_SPAN};
use crate::transaction::{
    API_SCHEMAS, AuditOutboxRecord, ChangeBatch, CommittedGroup, RESOURCES, ResourceRecord,
    StoreMeta, VerifiedWrite, apply_group_with_hook, audit_outbox_for_operation,
    audit_outbox_pending, authority_operations, authority_update, backpressure,
    current_meta, decode, mark_audit_outbox_complete, pending_audit_outboxes,
    pending_deferred_activation_operation_ids, resource_key, stored_resource, timeout,
    validate_deferred_broker_evidence_marker, assignment_fence, authority_prepare_batch,
};
use d2b_resource_store::mutation_seal::OpenedMutation;

/// Bounded public writer admission queue.
pub const WRITE_QUEUE_CAPACITY: usize = 256;
/// Maximum independent mutation requests in one crash-safe commit.
pub const GROUP_COMMIT_MAX: usize = 16;
/// Dedicated blocking MVCC read workers.
pub const READ_POOL_THREADS: usize = 4;
/// Maximum read transactions admitted at once.
pub const MAX_CONCURRENT_READS: usize = 16;
/// Worker-enforced lifetime ceiling for an admitted read transaction.
pub const READ_LIFETIME: Duration = Duration::from_millis(250);
/// Worker-enforced lifetime ceiling for one bounded relist page.
pub const LIST_READ_LIFETIME: Duration = Duration::from_secs(1);

pub(crate) type CommitFence = Arc<dyn Fn() -> Result<(), StoreError> + Send + Sync>;

/// Lightweight filtered view over one immutable decoded batch.
#[derive(Clone)]
pub struct SharedChangeBatch {
    batch: Arc<ChangeBatch>,
    indices: Arc<[usize]>,
}

impl core::fmt::Debug for SharedChangeBatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SharedChangeBatch")
            .field("revision", &self.revision())
            .field("entry_count", &self.indices.len())
            .finish()
    }
}

impl SharedChangeBatch {
    pub fn revision(&self) -> ZoneRevision {
        self.batch.revision()
    }

    pub(crate) fn batch_arc(&self) -> Arc<ChangeBatch> {
        Arc::clone(&self.batch)
    }

    pub fn entries(&self) -> impl ExactSizeIterator<Item = &crate::transaction::ChangeEntry> {
        self.indices
            .iter()
            .map(|index| &self.batch.entries()[*index])
    }

    pub fn shares_batch_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.batch, &other.batch)
    }
}

/// Fixed-cardinality backend signal snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendSignals {
    pub revision_range_seeks: u64,
    pub replay_rows_scanned: u64,
    pub replay_rows_decoded: u64,
    pub shared_immutable_batches: u64,
    pub fanout_references: u64,
    pub writer_queue_depth: u64,
    pub writer_queue_capacity: u64,
}

#[derive(Default)]
pub(crate) struct SignalCounters {
    revision_range_seeks: AtomicU64,
    replay_rows_scanned: AtomicU64,
    replay_rows_decoded: AtomicU64,
    shared_immutable_batches: AtomicU64,
    fanout_references: AtomicU64,
    writer_queue_depth: AtomicU64,
}

#[derive(Clone)]
struct AuditIntent {
    zone: String,
    operation_id: String,
    correlation_id: String,
    subject_digest: String,
    policy_revision: u64,
    mutations: Vec<AuditMutation>,
}

#[derive(Clone)]
struct AuditMutation {
    verb: &'static str,
    resource_type: &'static str,
    resource_uid: Option<String>,
    target_digest: String,
    generation: u64,
    expected_revision: u64,
}

fn audit_intent(body: &d2b_resource_store::mutation_seal::MutationSealBody) -> AuditIntent {
    let mutations = body
        .mutations
        .iter()
        .map(|prepared| {
            let mutation = prepared.mutation();
            let resource_uid = (mutation.kind != ResourceMutationKind::Create)
                .then(|| {
                    prepared
                        .resource_uid()
                        .or(mutation.expected_uid.as_ref())
                        .map(|uid| uid.as_str().to_owned())
                })
                .flatten();
            AuditMutation {
                verb: mutation_audit_verb(mutation.kind),
                resource_type: audit_resource_type(mutation.target.resource_type().as_str()),
                resource_uid,
                target_digest: opaque_digest(&mutation.target.to_canonical_string()),
                generation: 0,
                expected_revision: match mutation.expected {
                    ExpectedRevision::CreateAbsent => 0,
                    ExpectedRevision::Exact(revision) => revision.get(),
                },
            }
        })
        .collect();
    AuditIntent {
        zone: body.authorization.zone.as_str().to_owned(),
        operation_id: body.operation.operation_id.clone(),
        correlation_id: body.operation.correlation_id.clone(),
        subject_digest: opaque_digest(&body.authorization.subject_ref.to_canonical_string()),
        policy_revision: body.policy_snapshot.policy_revision,
        mutations,
    }
}

const fn mutation_audit_verb(kind: ResourceMutationKind) -> &'static str {
    match kind {
        ResourceMutationKind::Create => "create",
        ResourceMutationKind::UpdateSpec => "update-spec",
        ResourceMutationKind::UpdateStatus => "update-status",
        ResourceMutationKind::UpdateMetadata => "update-metadata",
        ResourceMutationKind::UpdateFinalizers => "update-finalizers",
        ResourceMutationKind::Delete => "delete",
    }
}

fn recover_pending_audit_outboxes(
    database: &redb::Database,
    audit: &dyn DurableMutationAudit,
    broker_evidence: &BrokerEvidenceIndex,
) -> Result<(), StoreError> {
    if !audit.enabled() {
        return Ok(());
    }
    for outbox in pending_audit_outboxes(database)? {
        let key = outbox_join_key(&outbox)?;
        if verify_broker_evidence(&outbox, &key, broker_evidence)?
            == BrokerEvidenceVerification::Deferred
        {
            continue;
        }
        append_audit_outbox(database, audit, &outbox, &key)?;
        mark_audit_outbox_complete(database, &outbox.operation_id)?;
    }
    Ok(())
}

fn outbox_join_key(outbox: &AuditOutboxRecord) -> Result<ZoneOperationKey, StoreError> {
    let operation = outbox
        .operation_identity
        .clone()
        .or_else(|| OperationIdentity::derive(&outbox.operation_id).ok())
        .ok_or_else(|| crate::transaction::durability_failure("audit-operation-key-invalid"))?;
    let zone = d2b_audit::ZoneId::derive(&outbox.zone)
        .map_err(|_| crate::transaction::durability_failure("audit-zone-invalid"))?;
    Ok(ZoneOperationKey::new(zone, operation))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BrokerEvidenceVerification {
    Ready,
    Deferred,
}

fn verify_broker_evidence(
    outbox: &AuditOutboxRecord,
    key: &ZoneOperationKey,
    broker_evidence: &BrokerEvidenceIndex,
) -> Result<BrokerEvidenceVerification, StoreError> {
    let deferred_marker = validate_deferred_broker_evidence_marker(outbox)?;
    if !outbox.requires_broker {
        return Ok(BrokerEvidenceVerification::Ready);
    }
    let effect_durable = outbox
        .mutations
        .iter()
        .all(|mutation| mutation.outcome == "ok");
    let resource = DurabilityEvidence {
        key: key.clone(),
        outcome: if effect_durable {
            DurabilityOutcome::Success
        } else {
            DurabilityOutcome::Failure
        },
        effect_durable,
    };
    let Some(broker) = broker_evidence.get(key)? else {
        if effect_durable && deferred_marker {
            return Ok(BrokerEvidenceVerification::Deferred);
        }
        if effect_durable {
            return Err(crate::transaction::durability_failure(
                "audit-broker-evidence-missing",
            ));
        }
        return Ok(BrokerEvidenceVerification::Ready);
    };
    if !matches!(
        d2b_audit::reconcile_durability(Some(&broker), Some(&resource)),
        Reconciliation::Success | Reconciliation::Failure
    ) {
        return Err(crate::transaction::durability_failure(
            "audit-domain-integrity-failure",
        ));
    }
    Ok(BrokerEvidenceVerification::Ready)
}

fn append_audit_outbox(
    database: &redb::Database,
    audit: &dyn DurableMutationAudit,
    outbox: &AuditOutboxRecord,
    join_key: &ZoneOperationKey,
) -> Result<(), StoreError> {
    let operation_identity = join_key.operation().clone();
    let mut previous_hash = audit
        .previous_hash()
        .map_err(|_| crate::transaction::durability_failure("audit-unavailable"))?;
    for mutation in &outbox.mutations {
        if let Some(record_hash) = mutation.record_hash.as_ref() {
            let persisted = audit
                .existing_mutation_hash(join_key, &mutation.mutation_id)
                .map_err(|_| crate::transaction::durability_failure("audit-unavailable"))?;
            if persisted.as_ref() != Some(record_hash) {
                return Err(crate::transaction::durability_failure(
                    "audit-outbox-progress-membership-mismatch",
                ));
            }
            if let Some(predecessor) = mutation.previous_hash.as_ref() {
                let persisted_predecessor = audit
                    .existing_mutation_predecessor(join_key, &mutation.mutation_id)
                    .map_err(|_| crate::transaction::durability_failure("audit-unavailable"))?;
                if persisted_predecessor.as_ref() != Some(predecessor) {
                    return Err(crate::transaction::durability_failure(
                        "audit-outbox-progress-predecessor-mismatch",
                    ));
                }
            }
            previous_hash = record_hash.clone();
            continue;
        }
        if let Some(existing) = audit
            .existing_mutation_hash(join_key, &mutation.mutation_id)
            .map_err(|_| crate::transaction::durability_failure("audit-unavailable"))?
        {
            if let Some(predecessor) = mutation.previous_hash.as_ref() {
                let persisted_predecessor = audit
                    .existing_mutation_predecessor(join_key, &mutation.mutation_id)
                    .map_err(|_| crate::transaction::durability_failure("audit-unavailable"))?;
                if persisted_predecessor.as_ref() != Some(predecessor) {
                    return Err(crate::transaction::durability_failure(
                        "audit-outbox-progress-predecessor-mismatch",
                    ));
                }
            }
            previous_hash = existing;
            continue;
        }
        let predecessor = mutation
            .previous_hash
            .clone()
            .unwrap_or_else(|| previous_hash.clone());
        let record = resource_mutation_record_with_identity(
            mutation.timestamp_ms,
            outbox.zone.clone(),
            operation_identity.as_str().to_owned(),
            outbox.correlation_id.clone(),
            "resource-store",
            predecessor.clone(),
            mutation.verb.clone(),
            audit_resource_type(&mutation.resource_type),
            mutation
                .resource_uid
                .clone()
                .unwrap_or_else(|| mutation.target_digest.clone()),
            mutation.generation,
            mutation.expected_revision,
            outbox.resulting_revision,
            outbox.subject_digest.clone(),
            outbox.policy_revision,
            mutation.outcome.clone(),
            mutation.error_code.clone(),
            Some(mutation.mutation_id.clone()),
            Some(mutation.ordinal),
        )
        .map_err(|_| crate::transaction::durability_failure("audit-record-invalid"))?;
        audit
            .append_before_commit(&record)
            .map_err(|_| crate::transaction::durability_failure("audit-unavailable"))?;
        crate::transaction::mark_audit_outbox_progress(
            database,
            &outbox.operation_id,
            mutation.ordinal,
            &predecessor,
            record.record_hash(),
        )?;
        previous_hash = record.record_hash().clone();
    }
    Ok(())
}

impl SignalCounters {
    pub(crate) fn snapshot(&self) -> BackendSignals {
        BackendSignals {
            revision_range_seeks: self.revision_range_seeks.load(Ordering::Relaxed),
            replay_rows_scanned: self.replay_rows_scanned.load(Ordering::Relaxed),
            replay_rows_decoded: self.replay_rows_decoded.load(Ordering::Relaxed),
            shared_immutable_batches: self.shared_immutable_batches.load(Ordering::Relaxed),
            fanout_references: self.fanout_references.load(Ordering::Relaxed),
            writer_queue_depth: self.writer_queue_depth.load(Ordering::Relaxed),
            writer_queue_capacity: WRITE_QUEUE_CAPACITY as u64,
        }
    }

    fn record_shared_batch(&self) {
        self.shared_immutable_batches
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_fanout_reference(&self) {
        self.fanout_references.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) struct WriterHandle {
    sender: Option<mpsc::Sender<WriterCommand>>,
    signals: Arc<SignalCounters>,
    telemetry: Arc<dyn StoreTelemetry>,
    audit_intents: Arc<std::sync::Mutex<BTreeMap<u64, AuditIntent>>>,
    next_sequence: AtomicU64,
    write_permits: Arc<tokio::sync::Semaphore>,
    thread: Option<std::thread::JoinHandle<()>>,
    quarantined: Arc<AtomicBool>,
}

impl WriterHandle {
    pub(crate) fn start_with_ports(
        database: Arc<Database>,
        signals: Arc<SignalCounters>,
        watch_coordinator: Arc<std::sync::Mutex<WatchCoordinator>>,
        telemetry: Arc<dyn StoreTelemetry>,
        audit: Arc<dyn DurableMutationAudit>,
        broker_evidence: Arc<BrokerEvidenceIndex>,
    ) -> Result<Self, StoreError> {
        let (sender, receiver) = mpsc::channel(WRITE_QUEUE_CAPACITY);
        crate::transaction::set_clean_shutdown(&database, false)?;
        recover_pending_audit_outboxes(&database, audit.as_ref(), &broker_evidence)?;
        let actor_signals = Arc::clone(&signals);
        let actor_telemetry = Arc::clone(&telemetry);
        let actor_audit = Arc::clone(&audit);
        let audit_intents = Arc::new(std::sync::Mutex::new(BTreeMap::new()));
        let actor_audit_intents = Arc::clone(&audit_intents);
        let quarantined = Arc::new(AtomicBool::new(false));
        let actor_quarantined = Arc::clone(&quarantined);
        let actor_watch_coordinator = Arc::clone(&watch_coordinator);
        let actor_broker_evidence = Arc::clone(&broker_evidence);
        let thread = std::thread::Builder::new()
            .name("d2b-redb-writer".to_owned())
            .spawn(move || {
                WriterActor::new_with_ports(
                    database,
                    receiver,
                    actor_signals,
                    actor_quarantined,
                    actor_watch_coordinator,
                    actor_telemetry,
                    actor_audit,
                    actor_audit_intents,
                    actor_broker_evidence,
                )
                .run();
            })
            .map_err(|_| crate::transaction::integrity("writer-actor-start-failed"))?;
        Ok(Self {
            sender: Some(sender),
            signals,
            telemetry,
            audit_intents,
            next_sequence: AtomicU64::new(0),
            write_permits: Arc::new(tokio::sync::Semaphore::new(WRITE_QUEUE_CAPACITY)),
            thread: Some(thread),
            quarantined,
        })
    }

    pub(crate) async fn commit(
        &self,
        opened: OpenedMutation,
    ) -> Result<d2b_resource_store::StoreCommitResult, StoreError> {
        self.commit_with_fence(opened, None).await
    }

    pub(crate) async fn commit_with_fence(
        &self,
        opened: OpenedMutation,
        commit_fence: Option<CommitFence>,
    ) -> Result<d2b_resource_store::StoreCommitResult, StoreError> {
        if self.quarantined.load(Ordering::Acquire) {
            return Err(crate::transaction::quarantined());
        }
        if opened.body().mutations.is_empty() {
            return Err(crate::transaction::integrity("empty-verified-mutation"));
        }
        if opened.body().mutations.len() > d2b_contracts_resource::v3::MAX_BATCH_MUTATIONS {
            return Err(crate::transaction::integrity(
                "verified-mutation-over-limit",
            ));
        }
        let sender = self
            .sender
            .as_ref()
            .ok_or_else(|| crate::transaction::integrity("writer-closed"))?;
        let queue_permit = Arc::clone(&self.write_permits)
            .try_acquire_owned()
            .map_err(|_| backpressure())?;
        let (response, receiver) = oneshot::channel();
        let sequence = self.next_sequence.fetch_add(1, Ordering::Relaxed);
        let intent = audit_intent(opened.body());
        let principal = opened.body().authorization.subject_uid.as_str().to_owned();
        let mut resources = opened
            .body()
            .mutations
            .iter()
            .flat_map(|prepared| {
                [
                    Some(prepared.mutation().target.clone()),
                    prepared.mutation().owner.clone(),
                ]
            })
            .flatten()
            .collect::<Vec<_>>();
        resources.sort();
        resources.dedup();
        self.signals
            .writer_queue_depth
            .fetch_add(1, Ordering::Relaxed);
        self.telemetry.metric(
            StoreMetric::QueueDepth,
            BTreeMap::from([("operation".to_owned(), "write".to_owned())]),
            self.signals.writer_queue_depth.load(Ordering::Relaxed) as f64,
        );
        {
            let mut audit_intents = match self.audit_intents.lock() {
                Ok(intents) => intents,
                Err(_) => {
                    self.signals
                        .writer_queue_depth
                        .fetch_sub(1, Ordering::Relaxed);
                    return Err(crate::transaction::integrity(
                        "audit-intent-registry-poisoned",
                    ));
                }
            };
            audit_intents.insert(sequence, intent);
        }
        if let Err(error) = sender.try_send(WriterCommand::Commit(Box::new(WriteRequest {
            sequence,
            principal,
            resources,
            mutation: VerifiedWrite::from_opened(opened),
            commit_fence,
            queue_permit,
            response,
        }))) {
            self.signals
                .writer_queue_depth
                .fetch_sub(1, Ordering::Relaxed);
            let _ = self
                .audit_intents
                .lock()
                .map(|mut intents| intents.remove(&sequence));
            return Err(match error {
                mpsc::error::TrySendError::Full(_) => backpressure(),
                mpsc::error::TrySendError::Closed(_) => {
                    crate::transaction::integrity("writer-closed")
                }
            });
        }
        match receiver.await {
            Ok(result) => result,
            Err(_) => {
                let _ = self
                    .audit_intents
                    .lock()
                    .map(|mut intents| intents.remove(&sequence));
                Err(crate::transaction::integrity("writer-response-closed"))
            }
        }
    }

    pub(crate) async fn authority_prepare(
        &self,
        operation_id: String,
        payload: Vec<u8>,
        request_digest: String,
    ) -> Result<(), StoreError> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .as_ref()
            .ok_or_else(|| crate::transaction::integrity("writer-closed"))?
            .send(WriterCommand::AuthorityPrepare {
                operation_id,
                payload,
                request_digest,
                response,
            })
            .await
            .map_err(|_| crate::transaction::integrity("writer-closed"))?;
        receiver
            .await
            .map_err(|_| crate::transaction::integrity("authority-response-closed"))?
    }

    pub(crate) async fn authority_update(
        &self,
        operation_id: String,
        state: crate::AuthorityOperationState,
    ) -> Result<(), StoreError> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .as_ref()
            .ok_or_else(|| crate::transaction::integrity("writer-closed"))?
            .send(WriterCommand::AuthorityUpdate {
                operation_id,
                state: authority_state_name(state),
                response,
            })
            .await
            .map_err(|_| crate::transaction::integrity("writer-closed"))?;
        receiver
            .await
            .map_err(|_| crate::transaction::integrity("authority-response-closed"))?
    }

    pub(crate) async fn ingest_broker_evidence(
        &self,
        operation_id: String,
        evidence: DurabilityEvidence,
    ) -> Result<(), StoreError> {
        if self.quarantined.load(Ordering::Acquire) {
            return Err(crate::transaction::quarantined());
        }
        let (response, receiver) = oneshot::channel();
        self.sender
            .as_ref()
            .ok_or_else(|| crate::transaction::integrity("writer-closed"))?
            .send(WriterCommand::IngestBrokerEvidence {
                operation_id,
                evidence,
                response,
            })
            .await
            .map_err(|_| crate::transaction::integrity("writer-closed"))?;
        receiver
            .await
            .map_err(|_| crate::transaction::integrity("broker-evidence-response-closed"))?
    }

    pub(crate) async fn audit_outbox_pending(
        &self,
        operation_id: String,
    ) -> Result<bool, StoreError> {
        if self.quarantined.load(Ordering::Acquire) {
            return Err(crate::transaction::quarantined());
        }
        let (response, receiver) = oneshot::channel();
        self.sender
            .as_ref()
            .ok_or_else(|| crate::transaction::integrity("writer-closed"))?
            .send(WriterCommand::AuditOutboxPending {
                operation_id,
                response,
            })
            .await
            .map_err(|_| crate::transaction::integrity("writer-closed"))?;
        receiver
            .await
            .map_err(|_| crate::transaction::integrity("audit-outbox-response-closed"))?
    }

    pub(crate) async fn pending_deferred_activation_operation_ids(
        &self,
        zone: ZoneId,
    ) -> Result<Vec<String>, StoreError> {
        if self.quarantined.load(Ordering::Acquire) {
            return Err(crate::transaction::quarantined());
        }
        let (response, receiver) = oneshot::channel();
        self.sender
            .as_ref()
            .ok_or_else(|| crate::transaction::integrity("writer-closed"))?
            .send(WriterCommand::PendingDeferredActivationOperationIds { zone, response })
            .await
            .map_err(|_| crate::transaction::integrity("writer-closed"))?;
        receiver
            .await
            .map_err(|_| crate::transaction::integrity("audit-outbox-response-closed"))?
    }

    pub(crate) async fn replay(
        &self,
        after_revision: u64,
        resource_types: BTreeSet<ResourceTypeName>,
        visit: impl FnMut(SharedChangeBatch) -> Result<(), StoreError> + Send + 'static,
    ) -> Result<ZoneRevision, StoreError> {
        if self.quarantined.load(Ordering::Acquire) {
            return Err(crate::transaction::quarantined());
        }
        let (response, ready) = oneshot::channel();
        self.sender
            .as_ref()
            .ok_or_else(|| crate::transaction::integrity("writer-closed"))?
            .send(WriterCommand::Replay {
                after_revision,
                resource_types,
                visit: Box::new(visit),
                response,
            })
            .await
            .map_err(|_| crate::transaction::integrity("writer-closed"))?;
        let high_water = ready
            .await
            .map_err(|_| crate::transaction::integrity("watch-replay-closed"))??;
        Ok(ZoneRevision::new(high_water))
    }

    pub(crate) async fn watch(
        &self,
        after_revision: ZoneRevision,
        selector: WatchSelector,
        initial_credits: u32,
    ) -> Result<(WatchStream, ZoneRevision), StoreError> {
        if self.quarantined.load(Ordering::Acquire) {
            return Err(crate::transaction::quarantined());
        }
        let (response, receiver) = oneshot::channel();
        self.sender
            .as_ref()
            .ok_or_else(|| crate::transaction::integrity("writer-closed"))?
            .send(WriterCommand::Watch {
                after_revision,
                selector,
                initial_credits,
                response,
            })
            .await
            .map_err(|_| crate::transaction::integrity("writer-closed"))?;
        receiver
            .await
            .map_err(|_| crate::transaction::integrity("watch-response-closed"))?
    }

    pub(crate) async fn acknowledge_watch(
        &self,
        id: WatchRegistrationId,
        revision: ZoneRevision,
    ) -> Result<(), StoreError> {
        if self.quarantined.load(Ordering::Acquire) {
            return Err(crate::transaction::quarantined());
        }
        let (response, receiver) = oneshot::channel();
        self.sender
            .as_ref()
            .ok_or_else(|| crate::transaction::integrity("writer-closed"))?
            .send(WriterCommand::AcknowledgeWatch {
                id,
                revision,
                response,
            })
            .await
            .map_err(|_| crate::transaction::integrity("writer-closed"))?;
        receiver
            .await
            .map_err(|_| crate::transaction::integrity("watch-ack-response-closed"))?
    }

    pub(crate) async fn unregister_watch(
        &self,
        id: WatchRegistrationId,
    ) -> Result<Option<ZoneRevision>, StoreError> {
        if self.quarantined.load(Ordering::Acquire) {
            return Err(crate::transaction::quarantined());
        }
        let (response, receiver) = oneshot::channel();
        self.sender
            .as_ref()
            .ok_or_else(|| crate::transaction::integrity("writer-closed"))?
            .send(WriterCommand::UnregisterWatch { id, response })
            .await
            .map_err(|_| crate::transaction::integrity("writer-closed"))?;
        receiver
            .await
            .map_err(|_| crate::transaction::integrity("watch-unregister-response-closed"))?
    }

    pub(crate) async fn backup(
        &self,
        identity: crate::StoreIdentity,
    ) -> Result<LogicalBackup, StoreError> {
        if self.quarantined.load(Ordering::Acquire) {
            return Err(crate::transaction::quarantined());
        }
        let (response, receiver) = oneshot::channel();
        self.sender
            .as_ref()
            .ok_or_else(|| crate::transaction::integrity("writer-closed"))?
            .send(WriterCommand::Backup { identity, response })
            .await
            .map_err(|_| crate::transaction::integrity("writer-closed"))?;
        receiver
            .await
            .map_err(|_| crate::transaction::integrity("writer-backup-response-closed"))?
    }

    pub(crate) async fn shutdown(&mut self) -> Result<(), StoreError> {
        let sender = self
            .sender
            .take()
            .ok_or_else(|| crate::transaction::integrity("writer-closed"))?;
        let (response, receiver) = oneshot::channel();
        sender
            .send(WriterCommand::Shutdown { response })
            .await
            .map_err(|_| crate::transaction::integrity("writer-closed"))?;
        receiver
            .await
            .map_err(|_| crate::transaction::integrity("writer-shutdown-response-closed"))??;
        if self
            .thread
            .take()
            .ok_or_else(|| crate::transaction::integrity("writer-thread-missing"))?
            .join()
            .is_err()
        {
            return Err(crate::transaction::integrity("writer-thread-failed"));
        }
        Ok(())
    }
}

impl Drop for WriterHandle {
    fn drop(&mut self) {
        self.sender.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        if let Ok(mut intents) = self.audit_intents.lock() {
            intents.clear();
        }
    }
}

pub(crate) struct WriteRequest {
    pub(crate) sequence: u64,
    pub(crate) principal: String,
    pub(crate) resources: Vec<ResourceRef>,
    pub(crate) mutation: VerifiedWrite,
    pub(crate) commit_fence: Option<CommitFence>,
    pub(crate) queue_permit: OwnedSemaphorePermit,
    pub(crate) response: oneshot::Sender<Result<d2b_resource_store::StoreCommitResult, StoreError>>,
}

enum WriterCommand {
    Commit(Box<WriteRequest>),
    Replay {
        after_revision: u64,
        resource_types: BTreeSet<ResourceTypeName>,
        visit: Box<dyn FnMut(SharedChangeBatch) -> Result<(), StoreError> + Send>,
        response: oneshot::Sender<Result<u64, StoreError>>,
    },
    Watch {
        after_revision: ZoneRevision,
        selector: WatchSelector,
        initial_credits: u32,
        response: oneshot::Sender<Result<(WatchStream, ZoneRevision), StoreError>>,
    },
    AcknowledgeWatch {
        id: WatchRegistrationId,
        revision: ZoneRevision,
        response: oneshot::Sender<Result<(), StoreError>>,
    },
    UnregisterWatch {
        id: WatchRegistrationId,
        response: oneshot::Sender<Result<Option<ZoneRevision>, StoreError>>,
    },
    Backup {
        identity: crate::StoreIdentity,
        response: oneshot::Sender<Result<LogicalBackup, StoreError>>,
    },
    AuthorityPrepare {
        operation_id: String,
        payload: Vec<u8>,
        request_digest: String,
        response: oneshot::Sender<Result<(), StoreError>>,
    },
    AuthorityUpdate {
        operation_id: String,
        state: String,
        response: oneshot::Sender<Result<(), StoreError>>,
    },
    IngestBrokerEvidence {
        operation_id: String,
        evidence: DurabilityEvidence,
        response: oneshot::Sender<Result<(), StoreError>>,
    },
    AuditOutboxPending {
        operation_id: String,
        response: oneshot::Sender<Result<bool, StoreError>>,
    },
    PendingDeferredActivationOperationIds {
        zone: ZoneId,
        response: oneshot::Sender<Result<Vec<String>, StoreError>>,
    },
    Shutdown {
        response: oneshot::Sender<Result<(), StoreError>>,
    },
}

#[derive(Default)]
struct FairScheduler {
    queues: BTreeMap<String, VecDeque<WriteRequest>>,
    ring: VecDeque<String>,
    len: usize,
}

impl FairScheduler {
    fn push(&mut self, request: WriteRequest) {
        let principal = request.principal.clone();
        let queue = self.queues.entry(principal.clone()).or_default();
        if queue.is_empty() {
            self.ring.push_back(principal);
        }
        queue.push_back(request);
        self.len += 1;
    }

    fn pop_group(&mut self) -> Vec<WriteRequest> {
        let mut group = Vec::with_capacity(GROUP_COMMIT_MAX);
        let mut resources = BTreeSet::new();
        let mut stalled = 0;
        while group.len() < GROUP_COMMIT_MAX && !self.ring.is_empty() {
            if stalled >= self.ring.len() {
                break;
            }
            let principal = self.ring.pop_front().expect("ring is nonempty");
            let request = self
                .queues
                .get_mut(&principal)
                .and_then(VecDeque::pop_front)
                .expect("active principal has a request");
            if request
                .resources
                .iter()
                .any(|resource| resources.contains(resource))
                || self.has_earlier_resource(request.sequence, &request.resources)
            {
                self.queues
                    .get_mut(&principal)
                    .expect("principal queue exists")
                    .push_front(request);
                self.ring.push_back(principal);
                stalled += 1;
                continue;
            }
            resources.extend(request.resources.iter().cloned());
            self.len -= 1;
            stalled = 0;
            if self
                .queues
                .get(&principal)
                .is_some_and(|queue| !queue.is_empty())
            {
                self.ring.push_back(principal);
            } else {
                self.queues.remove(&principal);
            }
            group.push(request);
        }
        group
    }

    fn has_earlier_resource(&self, sequence: u64, resources: &[ResourceRef]) -> bool {
        self.queues.values().any(|queue| {
            queue.iter().any(|request| {
                request.sequence < sequence
                    && request
                        .resources
                        .iter()
                        .any(|candidate| resources.contains(candidate))
            })
        })
    }
}

struct WriterActor {
    database: Arc<Database>,
    receiver: mpsc::Receiver<WriterCommand>,
    scheduler: FairScheduler,
    signals: Arc<SignalCounters>,
    sequence: u64,
    quarantined: Arc<AtomicBool>,
    watch_coordinator: Arc<std::sync::Mutex<WatchCoordinator>>,
    telemetry: Arc<dyn StoreTelemetry>,
    audit: Arc<dyn DurableMutationAudit>,
    audit_intents: Arc<std::sync::Mutex<BTreeMap<u64, AuditIntent>>>,
    broker_evidence: Arc<BrokerEvidenceIndex>,
}

impl WriterActor {
    #[cfg(test)]
    fn new(
        database: Arc<Database>,
        receiver: mpsc::Receiver<WriterCommand>,
        signals: Arc<SignalCounters>,
        quarantined: Arc<AtomicBool>,
        watch_coordinator: Arc<std::sync::Mutex<WatchCoordinator>>,
    ) -> Self {
        Self::new_with_ports(
            database,
            receiver,
            signals,
            quarantined,
            watch_coordinator,
            Arc::new(NoopStoreTelemetry),
            Arc::new(NoopMutationAudit),
            Arc::new(std::sync::Mutex::new(BTreeMap::new())),
            Arc::new(BrokerEvidenceIndex::default()),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_ports(
        database: Arc<Database>,
        receiver: mpsc::Receiver<WriterCommand>,
        signals: Arc<SignalCounters>,
        quarantined: Arc<AtomicBool>,
        watch_coordinator: Arc<std::sync::Mutex<WatchCoordinator>>,
        telemetry: Arc<dyn StoreTelemetry>,
        audit: Arc<dyn DurableMutationAudit>,
        audit_intents: Arc<std::sync::Mutex<BTreeMap<u64, AuditIntent>>>,
        broker_evidence: Arc<BrokerEvidenceIndex>,
    ) -> Self {
        Self {
            database,
            receiver,
            scheduler: FairScheduler::default(),
            signals,
            sequence: 0,
            quarantined,
            watch_coordinator,
            telemetry,
            audit,
            audit_intents,
            broker_evidence,
        }
    }

    fn run(mut self) {
        let mut deferred = None;
        loop {
            let command = deferred.take().or_else(|| self.receiver.blocking_recv());
            let Some(command) = command else {
                self.clear_all_audit_intents();
                break;
            };
            match command {
                WriterCommand::Commit(request) => {
                    self.enqueue(*request);
                    while self.scheduler.len < WRITE_QUEUE_CAPACITY {
                        match self.receiver.try_recv() {
                            Ok(WriterCommand::Commit(request)) => self.enqueue(*request),
                            Ok(control) => {
                                deferred = Some(control);
                                break;
                            }
                            Err(_) => break,
                        }
                    }
                    self.flush();
                }
                WriterCommand::Replay {
                    after_revision,
                    resource_types,
                    mut visit,
                    response,
                } => {
                    let started = Instant::now();
                    let high_water = current_meta(&self.database).map(|meta| meta.current_revision);
                    let replayed = match high_water {
                        Ok(high_water) => {
                            replay_after(&self.database, after_revision, &self.signals, |batch| {
                                let batch = Arc::new(batch);
                                let Some(filtered) = filter_batch(batch, &resource_types) else {
                                    return Ok(());
                                };
                                self.signals.record_shared_batch();
                                self.signals.record_fanout_reference();
                                visit(filtered)
                            })
                            .map(|()| high_water)
                        }
                        Err(error) => Err(error),
                    };
                    if let Err(error) = &replayed
                        && error.kind() == d2b_resource_store::StoreErrorKind::StoreIntegrityFailure
                    {
                        self.quarantine(error.clone());
                    }
                    let outcome = if replayed.is_ok() { "ok" } else { "error" };
                    let elapsed = elapsed_seconds(started);
                    self.telemetry.metric(
                        StoreMetric::ReadDuration,
                        BTreeMap::from([("operation".to_owned(), "scan".to_owned())]),
                        elapsed,
                    );
                    self.telemetry.span(
                        STORE_READ_SPAN,
                        BTreeMap::from([
                            ("operation".to_owned(), "scan".to_owned()),
                            ("outcome".to_owned(), outcome.to_owned()),
                        ]),
                        None,
                    );
                    let _ = response.send(replayed);
                }
                WriterCommand::Watch {
                    after_revision,
                    selector,
                    initial_credits,
                    response,
                } => {
                    let result = self
                        .watch_coordinator
                        .lock()
                        .map_err(|_| crate::transaction::integrity("watch-coordinator-poisoned"))
                        .and_then(|mut coordinator| {
                            coordinator.register_and_replay(
                                &self.database,
                                after_revision,
                                selector,
                                initial_credits,
                            )
                        });
                    if let Err(error) = &result
                        && error.kind() == d2b_resource_store::StoreErrorKind::StoreIntegrityFailure
                    {
                        self.quarantine(error.clone());
                    }
                    if result.is_ok()
                        && let Ok(coordinator) = self.watch_coordinator.lock()
                    {
                        self.telemetry.metric(
                            StoreMetric::WatchActive,
                            BTreeMap::new(),
                            coordinator.signals().current_registrations as f64,
                        );
                    }
                    let _ = response.send(result);
                }
                WriterCommand::AcknowledgeWatch {
                    id,
                    revision,
                    response,
                } => {
                    let result = self
                        .watch_coordinator
                        .lock()
                        .map_err(|_| crate::transaction::integrity("watch-coordinator-poisoned"))
                        .and_then(|mut coordinator| coordinator.acknowledge(id, revision));
                    let _ = response.send(result);
                }
                WriterCommand::UnregisterWatch { id, response } => {
                    let result = self
                        .watch_coordinator
                        .lock()
                        .map_err(|_| crate::transaction::integrity("watch-coordinator-poisoned"))
                        .map(|mut coordinator| coordinator.unregister(id));
                    if result.is_ok()
                        && let Ok(coordinator) = self.watch_coordinator.lock()
                    {
                        self.telemetry.metric(
                            StoreMetric::WatchActive,
                            BTreeMap::new(),
                            coordinator.signals().current_registrations as f64,
                        );
                    }
                    let _ = response.send(result);
                }
                WriterCommand::Backup { identity, response } => {
                    let started = Instant::now();
                    let backup = LogicalBackup::from_database(&self.database, &identity);
                    let outcome = if backup.is_ok() { "ok" } else { "error" };
                    self.telemetry.metric(
                        StoreMetric::BackupDuration,
                        BTreeMap::from([("outcome".to_owned(), outcome.to_owned())]),
                        elapsed_seconds(started),
                    );
                    if let Err(error) = &backup
                        && error.kind() == d2b_resource_store::StoreErrorKind::StoreIntegrityFailure
                    {
                        self.quarantine(error.clone());
                    }
                    let _ = response.send(backup);
                }
                WriterCommand::AuthorityPrepare {
                    operation_id,
                    payload,
                    request_digest,
                    response,
                } => {
                    let mut requests = vec![(operation_id, payload, request_digest)];
                    let mut responses = vec![response];
                    for _ in 0..8 {
                        match self.receiver.try_recv() {
                            Err(mpsc::error::TryRecvError::Empty) => {
                                std::thread::yield_now();
                            }
                            Err(mpsc::error::TryRecvError::Disconnected) => break,
                            Ok(WriterCommand::AuthorityPrepare {
                                operation_id,
                                payload,
                                request_digest,
                                response,
                            }) => {
                                requests.push((operation_id, payload, request_digest));
                                responses.push(response);
                            }
                            Ok(control) => {
                                deferred = Some(control);
                                break;
                            }
                        }
                    }
                    let result = authority_prepare_batch(&self.database, &requests);
                    if let Err(error) = &result
                        && error.kind() == d2b_resource_store::StoreErrorKind::StoreIntegrityFailure
                    {
                        self.quarantine(error.clone());
                    }
                    for response in responses {
                        let _ = response.send(result.clone());
                    }
                }
                WriterCommand::AuthorityUpdate {
                    operation_id,
                    state,
                    response,
                } => {
                    let result = authority_update(&self.database, &operation_id, &state);
                    if let Err(error) = &result
                        && error.kind() == d2b_resource_store::StoreErrorKind::StoreIntegrityFailure
                    {
                        self.quarantine(error.clone());
                    }
                    let _ = response.send(result);
                }
                WriterCommand::IngestBrokerEvidence {
                    operation_id,
                    evidence,
                    response,
                } => {
                    let result = self.broker_evidence.insert(evidence).and_then(|_| {
                        let Some(outbox) =
                            audit_outbox_for_operation(&self.database, &operation_id)?
                        else {
                            return Ok(());
                        };
                        let key = outbox_join_key(&outbox)?;
                        if verify_broker_evidence(&outbox, &key, &self.broker_evidence)?
                            == BrokerEvidenceVerification::Deferred
                        {
                            return Ok(());
                        }
                        append_audit_outbox(&self.database, self.audit.as_ref(), &outbox, &key)?;
                        mark_audit_outbox_complete(&self.database, &operation_id)
                    });
                    if let Err(error) = &result
                        && error.kind() == d2b_resource_store::StoreErrorKind::StoreIntegrityFailure
                    {
                        self.quarantine(error.clone());
                    }
                    let _ = response.send(result);
                }
                WriterCommand::AuditOutboxPending {
                    operation_id,
                    response,
                } => {
                    let result = audit_outbox_pending(&self.database, &operation_id);
                    if let Err(error) = &result
                        && error.kind() == d2b_resource_store::StoreErrorKind::StoreIntegrityFailure
                    {
                        self.quarantine(error.clone());
                    }
                    let _ = response.send(result);
                }
                WriterCommand::PendingDeferredActivationOperationIds { zone, response } => {
                    let result = pending_deferred_activation_operation_ids(&self.database, &zone);
                    if let Err(error) = &result
                        && error.kind() == d2b_resource_store::StoreErrorKind::StoreIntegrityFailure
                    {
                        self.quarantine(error.clone());
                    }
                    let _ = response.send(result);
                }
                WriterCommand::Shutdown { response } => {
                    let result = if self.quarantined.load(Ordering::Acquire) {
                        Err(crate::transaction::quarantined())
                    } else {
                        crate::transaction::set_clean_shutdown(&self.database, true)
                    };
                    let stop = result.is_ok();
                    let _ = response.send(result);
                    if stop {
                        break;
                    }
                }
            }
        }
    }

    fn enqueue(&mut self, request: WriteRequest) {
        self.sequence = self.sequence.max(request.sequence.wrapping_add(1));
        self.scheduler.push(request);
    }

    fn flush(&mut self) {
        while self.scheduler.len > 0 {
            let requests = self.scheduler.pop_group();
            if requests.is_empty() {
                return;
            }
            self.signals.writer_queue_depth.fetch_sub(
                u64::try_from(requests.len()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
            let mut accepted = Vec::with_capacity(requests.len());
            for request in requests {
                let sequence = request.sequence;
                let fence_result = request
                    .commit_fence
                    .as_ref()
                    .map_or(Ok(()), |fence| fence());
                if let Err(error) = fence_result {
                    self.clear_audit_intents(&[sequence]);
                    drop(request.queue_permit);
                    let _ = request.response.send(Err(error));
                } else {
                    accepted.push(request);
                }
            }
            if accepted.is_empty() {
                continue;
            }
            let started = Instant::now();
            let request_count = accepted.len();
            let sequences = accepted
                .iter()
                .map(|request| request.sequence)
                .collect::<Vec<_>>();
            let owned = accepted
                .into_iter()
                .map(|request| {
                    drop(request.queue_permit);
                    (request.mutation, request.response)
                })
                .collect::<Vec<_>>();
            let (mutations, responses): (Vec<_>, Vec<_>) = owned.into_iter().unzip();
            self.telemetry.metric(
                StoreMetric::GroupCommitSize,
                BTreeMap::new(),
                request_count as f64,
            );
            match apply_group_with_hook(&self.database, mutations, |committed| {
                self.append_mutation_audits(&sequences, committed)
            }) {
                Ok(CommittedGroup { results, batch, .. }) => {
                    let outcome = commit_outcome(&results);
                    self.telemetry.metric(
                        StoreMetric::WriteDuration,
                        BTreeMap::from([
                            ("kind".to_owned(), commit_kind(request_count).to_owned()),
                            ("outcome".to_owned(), outcome.to_owned()),
                        ]),
                        elapsed_seconds(started),
                    );
                    self.telemetry.span(
                        STORE_WRITE_SPAN,
                        BTreeMap::from([
                            ("kind".to_owned(), commit_kind(request_count).to_owned()),
                            ("outcome".to_owned(), outcome.to_owned()),
                        ]),
                        None,
                    );
                    if outcome == "conflict" {
                        self.telemetry.metric(
                            StoreMetric::Conflict,
                            BTreeMap::from([("resource_type".to_owned(), "vendor".to_owned())]),
                            1.0,
                        );
                    }
                    let integrity_error = results.iter().find_map(|result| match result {
                        Err(error)
                            if error.kind()
                                == d2b_resource_store::StoreErrorKind::StoreIntegrityFailure =>
                        {
                            Some(error.clone())
                        }
                        _ => None,
                    });
                    if let Some(batch) = batch
                        && let Err(error) = self.dispatch_live(batch)
                    {
                        for response in responses {
                            let _ = response.send(Err(error.clone()));
                        }
                        self.quarantine(error);
                        return;
                    }
                    if let Ok(meta) = current_meta(&self.database) {
                        self.telemetry.metric(
                            StoreMetric::Revision,
                            BTreeMap::new(),
                            meta.current_revision as f64,
                        );
                    }
                    for (response, result) in responses.into_iter().zip(results) {
                        let _ = response.send(result);
                    }
                    if let Some(error) = integrity_error {
                        self.quarantine(error);
                        return;
                    }
                }
                Err(error) => {
                    self.clear_audit_intents(&sequences);
                    self.telemetry.metric(
                        StoreMetric::WriteDuration,
                        BTreeMap::from([
                            ("kind".to_owned(), commit_kind(request_count).to_owned()),
                            ("outcome".to_owned(), "error".to_owned()),
                        ]),
                        elapsed_seconds(started),
                    );
                    self.telemetry.span(
                        STORE_WRITE_SPAN,
                        BTreeMap::from([
                            ("kind".to_owned(), commit_kind(request_count).to_owned()),
                            ("outcome".to_owned(), "error".to_owned()),
                        ]),
                        None,
                    );
                    for response in responses {
                        let _ = response.send(Err(error.clone()));
                    }
                    if error.kind() == d2b_resource_store::StoreErrorKind::StoreIntegrityFailure {
                        self.quarantine(error);
                        return;
                    }
                }
            }
        }
    }

    fn append_mutation_audits(
        &self,
        sequences: &[u64],
        committed: &CommittedGroup,
    ) -> Result<(), StoreError> {
        let mut intents = self.audit_intents.lock().map_err(|_| {
            crate::transaction::durability_failure("audit-intent-registry-poisoned")
        })?;
        if !self.audit.enabled() {
            for sequence in sequences {
                if let Some(intent) = intents.get(sequence)
                    && audit_outbox_pending(&self.database, &intent.operation_id)?
                {
                    mark_audit_outbox_complete(&self.database, &intent.operation_id)?;
                }
                intents.remove(sequence);
            }
            return Ok(());
        }
        if committed.results.len() != sequences.len() {
            return Err(crate::transaction::durability_failure(
                "audit-result-count-mismatch",
            ));
        }
        let snapshots = sequences
            .iter()
            .map(|sequence| intents.get(sequence).cloned())
            .collect::<Vec<_>>();
        drop(intents);
        let mut previous_hash = self
            .audit
            .previous_hash()
            .map_err(|_| crate::transaction::durability_failure("audit-unavailable"))?;
        let mut append = |zone: String,
                          operation_id: String,
                          correlation_id: String,
                          subject_digest: String,
                          policy_revision: u64,
                          mutation: AuditMutation,
                          outcome: &'static str,
                          error_code: Option<String>,
                          resulting_revision: u64|
         -> Result<(), StoreError> {
            let record = resource_mutation_record(
                unix_timestamp_ms(),
                zone,
                operation_id,
                correlation_id,
                "resource-store",
                previous_hash.clone(),
                mutation.verb,
                mutation.resource_type,
                mutation.resource_uid.unwrap_or(mutation.target_digest),
                mutation.generation,
                mutation.expected_revision,
                resulting_revision,
                subject_digest,
                policy_revision,
                outcome,
                error_code,
            )
            .map_err(|_| crate::transaction::durability_failure("audit-record-invalid"))?;
            self.audit
                .append_before_commit(&record)
                .map_err(|_| crate::transaction::durability_failure("audit-unavailable"))?;
            previous_hash = record.record_hash().clone();
            Ok(())
        };
        for ((sequence, intent), result) in sequences.iter().zip(snapshots).zip(&committed.results)
        {
            let outcome = result
                .as_ref()
                .map(|_| "ok")
                .unwrap_or_else(|error| audit_failure_outcome(error));
            let error_code = result
                .as_ref()
                .err()
                .map(|error| error.reason_code().to_owned());
            let resulting_revision = match result {
                Ok(commit) => commit.revision.get(),
                Err(_) => committed.resulting_revision,
            };
            if let Some(intent) = intent {
                if let Some(outbox) =
                    audit_outbox_for_operation(&self.database, &intent.operation_id)?
                {
                    let key = outbox_join_key(&outbox)?;
                    if verify_broker_evidence(&outbox, &key, &self.broker_evidence)?
                        == BrokerEvidenceVerification::Deferred
                    {
                        continue;
                    }
                    append_audit_outbox(&self.database, self.audit.as_ref(), &outbox, &key)?;
                    mark_audit_outbox_complete(&self.database, &intent.operation_id)?;
                    continue;
                }
                let outbox_pending =
                    result.is_ok() && audit_outbox_pending(&self.database, &intent.operation_id)?;
                if result.is_ok() && !outbox_pending {
                    continue;
                }
                let resources = result.as_ref().ok().map(|commit| &commit.resources);
                let mut mutations = intent.mutations;
                if mutations.is_empty() {
                    mutations.push(AuditMutation {
                        verb: "update-spec",
                        resource_type: "vendor",
                        resource_uid: None,
                        target_digest: opaque_digest(&format!("writer-target-{sequence}")),
                        generation: 0,
                        expected_revision: 0,
                    });
                }
                for (index, mutation) in mutations.into_iter().enumerate() {
                    let (resource_uid, generation) = resources
                        .and_then(|resources| resources.get(index))
                        .map(|resource| {
                            (
                                Some(resource.uid.as_str().to_owned()),
                                resource.generation.get(),
                            )
                        })
                        .unwrap_or((mutation.resource_uid.clone(), mutation.generation));
                    let mutation = AuditMutation {
                        resource_uid,
                        generation,
                        ..mutation
                    };
                    append(
                        intent.zone.clone(),
                        intent.operation_id.clone(),
                        intent.correlation_id.clone(),
                        intent.subject_digest.clone(),
                        intent.policy_revision,
                        mutation,
                        outcome,
                        error_code.clone(),
                        resulting_revision,
                    )?;
                }
                if outbox_pending {
                    mark_audit_outbox_complete(&self.database, &intent.operation_id)?;
                }
            } else {
                #[cfg(not(test))]
                {
                    return Err(crate::transaction::durability_failure(
                        "audit-mutation-target-missing",
                    ));
                }
                #[cfg(test)]
                {
                    let target_digest = opaque_digest(&format!("writer-target-{sequence}"));
                    append(
                        "unknown".to_owned(),
                        format!("writer-{}", sequence),
                        format!("writer-correlation-{}", sequence),
                        opaque_digest(&format!("writer-subject-{sequence}")),
                        0,
                        AuditMutation {
                            verb: "update-spec",
                            resource_type: "vendor",
                            resource_uid: None,
                            target_digest,
                            generation: 0,
                            expected_revision: 0,
                        },
                        outcome,
                        error_code.clone(),
                        resulting_revision,
                    )?;
                }
            }
        }
        let mut intents = self.audit_intents.lock().map_err(|_| {
            crate::transaction::durability_failure("audit-intent-registry-poisoned")
        })?;
        for sequence in sequences {
            intents.remove(sequence);
        }
        Ok(())
    }

    fn clear_audit_intents(&self, sequences: &[u64]) {
        if let Ok(mut intents) = self.audit_intents.lock() {
            for sequence in sequences {
                intents.remove(sequence);
            }
        }
    }

    fn clear_all_audit_intents(&self) {
        if let Ok(mut intents) = self.audit_intents.lock() {
            intents.clear();
        }
    }

    fn dispatch_live(&self, batch: ChangeBatch) -> Result<(), StoreError> {
        let Some(shared) = shared_batch(batch) else {
            return Ok(());
        };
        let fanout = self
            .watch_coordinator
            .lock()
            .map_err(|_| crate::transaction::integrity("watch-coordinator-poisoned"))?
            .dispatch(shared);
        if fanout != 0 {
            self.signals.record_shared_batch();
            self.signals
                .fanout_references
                .fetch_add(fanout, Ordering::Relaxed);
        }
        Ok(())
    }

    fn quarantine(&mut self, error: StoreError) {
        self.quarantined.store(true, Ordering::Release);
        self.receiver.close();
        while self.scheduler.len > 0 {
            let requests = self.scheduler.pop_group();
            self.signals.writer_queue_depth.fetch_sub(
                u64::try_from(requests.len()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
            for request in requests {
                self.clear_audit_intents(&[request.sequence]);
                let _ = request
                    .response
                    .send(Err(crate::transaction::quarantined()));
            }
        }
        while let Ok(command) = self.receiver.try_recv() {
            match command {
                WriterCommand::Commit(request) => {
                    self.clear_audit_intents(&[request.sequence]);
                    self.signals
                        .writer_queue_depth
                        .fetch_sub(1, Ordering::Relaxed);
                    let _ = request
                        .response
                        .send(Err(crate::transaction::quarantined()));
                }
                WriterCommand::Replay { response, .. } => {
                    let _ = response.send(Err(crate::transaction::quarantined()));
                }
                WriterCommand::Watch { response, .. } => {
                    let _ = response.send(Err(crate::transaction::quarantined()));
                }
                WriterCommand::AcknowledgeWatch { response, .. } => {
                    let _ = response.send(Err(crate::transaction::quarantined()));
                }
                WriterCommand::UnregisterWatch { response, .. } => {
                    let _ = response.send(Err(crate::transaction::quarantined()));
                }
                WriterCommand::Backup { response, .. } => {
                    let _ = response.send(Err(crate::transaction::quarantined()));
                }
                WriterCommand::AuthorityPrepare { response, .. } => {
                    let _ = response.send(Err(crate::transaction::quarantined()));
                }
                WriterCommand::AuthorityUpdate { response, .. } => {
                    let _ = response.send(Err(crate::transaction::quarantined()));
                }
                WriterCommand::IngestBrokerEvidence { response, .. } => {
                    let _ = response.send(Err(crate::transaction::quarantined()));
                }
                WriterCommand::AuditOutboxPending { response, .. } => {
                    let _ = response.send(Err(crate::transaction::quarantined()));
                }
                WriterCommand::PendingDeferredActivationOperationIds { response, .. } => {
                    let _ = response.send(Err(crate::transaction::quarantined()));
                }
                WriterCommand::Shutdown { response } => {
                    let _ = response.send(Err(error.clone()));
                }
            }
        }
        self.clear_all_audit_intents();
    }
}

pub(crate) fn filter_batch(
    batch: Arc<ChangeBatch>,
    resource_types: &BTreeSet<ResourceTypeName>,
) -> Option<SharedChangeBatch> {
    filter_batch_with(batch, |entry| {
        resource_types.contains(entry.resource_type())
    })
}

pub(crate) fn filter_batch_with(
    batch: Arc<ChangeBatch>,
    mut matches: impl FnMut(&crate::transaction::ChangeEntry) -> bool,
) -> Option<SharedChangeBatch> {
    let indices = batch
        .entries()
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| matches(entry).then_some(index))
        .collect::<Vec<_>>();
    (!indices.is_empty()).then(|| SharedChangeBatch {
        batch,
        indices: Arc::from(indices),
    })
}

pub(crate) fn shared_batch(batch: ChangeBatch) -> Option<SharedChangeBatch> {
    filter_batch_with(Arc::new(batch), |_| true)
}

pub(crate) fn replay_after<F>(
    database: &Database,
    after_revision: u64,
    signals: &SignalCounters,
    visit: F,
) -> Result<(), StoreError>
where
    F: FnMut(ChangeBatch) -> Result<(), StoreError>,
{
    let mut replay = crate::revision_log::ReplaySignals::default();
    let result = crate::revision_log::stream_after(database, after_revision, &mut replay, visit);
    signals
        .revision_range_seeks
        .fetch_add(replay.range_seeks(), Ordering::Relaxed);
    signals
        .replay_rows_scanned
        .fetch_add(replay.rows_scanned(), Ordering::Relaxed);
    signals
        .replay_rows_decoded
        .fetch_add(replay.rows_decoded(), Ordering::Relaxed);
    result
}

fn elapsed_seconds(started: Instant) -> f64 {
    started.elapsed().as_secs_f64()
}

fn unix_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
}

fn commit_kind(request_count: usize) -> &'static str {
    if request_count == 1 {
        "single"
    } else {
        "group"
    }
}

fn authority_state_name(state: crate::AuthorityOperationState) -> String {
    match state {
        crate::AuthorityOperationState::Pending => "pending",
        crate::AuthorityOperationState::EffectConfirmed => "effect-confirmed",
        crate::AuthorityOperationState::EffectRetryable => "effect-retryable",
        crate::AuthorityOperationState::EffectTerminal => "effect-terminal",
        crate::AuthorityOperationState::Closing => "closing",
        crate::AuthorityOperationState::Closed => "closed",
        crate::AuthorityOperationState::Released => "released",
    }
    .to_owned()
}

fn parse_authority_state(state: &str) -> Result<crate::AuthorityOperationState, StoreError> {
    match state {
        "pending" => Ok(crate::AuthorityOperationState::Pending),
        "effect-confirmed" => Ok(crate::AuthorityOperationState::EffectConfirmed),
        "effect-retryable" => Ok(crate::AuthorityOperationState::EffectRetryable),
        "effect-terminal" => Ok(crate::AuthorityOperationState::EffectTerminal),
        "closing" => Ok(crate::AuthorityOperationState::Closing),
        "closed" => Ok(crate::AuthorityOperationState::Closed),
        "released" => Ok(crate::AuthorityOperationState::Released),
        _ => Err(crate::transaction::integrity(
            "authority-operation-state-invalid",
        )),
    }
}

fn commit_outcome(
    results: &[Result<d2b_resource_store::StoreCommitResult, StoreError>],
) -> &'static str {
    if results.iter().all(Result::is_ok) {
        return "ok";
    }
    if results.iter().any(|result| {
        result.as_ref().err().is_some_and(|error| {
            error.kind() == d2b_resource_store::StoreErrorKind::ResourceConflict
        })
    }) {
        "conflict"
    } else {
        "error"
    }
}

fn audit_failure_outcome(error: &StoreError) -> &'static str {
    if error.kind() == d2b_resource_store::StoreErrorKind::AuthorizationDenied {
        "denied"
    } else {
        "error"
    }
}

fn audit_resource_type(resource_type: &str) -> &'static str {
    match resource_type {
        "Zone" => "Zone",
        "ZoneLink" => "ZoneLink",
        "Provider" => "Provider",
        "Role" => "Role",
        "RoleBinding" => "RoleBinding",
        "Quota" => "Quota",
        "EmergencyPolicy" => "EmergencyPolicy",
        "Host" => "Host",
        "Guest" => "Guest",
        "Process" => "Process",
        "EphemeralProcess" => "EphemeralProcess",
        "Volume" => "Volume",
        "Network" => "Network",
        "Device" => "Device",
        "User" => "User",
        "Credential" => "Credential",
        "Endpoint" => "Endpoint",
        "ResourceExport" => "ResourceExport",
        "ResourceImport" => "ResourceImport",
        _ => "vendor",
    }
}

pub(crate) struct ReadPool {
    senders: Vec<std::sync::mpsc::SyncSender<ReadWork>>,
    next_worker: AtomicU64,
    zone: ZoneId,
    permits: Arc<tokio::sync::Semaphore>,
    threads: Vec<std::thread::JoinHandle<()>>,
    telemetry: Arc<dyn StoreTelemetry>,
}

impl ReadPool {
    pub(crate) fn start_with_telemetry(
        database: Arc<Database>,
        zone: ZoneId,
        telemetry: Arc<dyn StoreTelemetry>,
    ) -> Result<Self, StoreError> {
        let per_worker_capacity = MAX_CONCURRENT_READS / READ_POOL_THREADS;
        debug_assert_eq!(
            per_worker_capacity * READ_POOL_THREADS,
            MAX_CONCURRENT_READS
        );
        let mut senders = Vec::with_capacity(READ_POOL_THREADS);
        let mut threads: Vec<std::thread::JoinHandle<()>> = Vec::with_capacity(READ_POOL_THREADS);
        for index in 0..READ_POOL_THREADS {
            let database = Arc::clone(&database);
            let (sender, receiver) = std::sync::mpsc::sync_channel(per_worker_capacity);
            let thread = match std::thread::Builder::new()
                .name(format!("d2b-redb-read-{index}"))
                .spawn(move || read_worker(database, receiver))
            {
                Ok(thread) => thread,
                Err(_) => {
                    senders.clear();
                    for thread in threads {
                        let _ = thread.join();
                    }
                    return Err(crate::transaction::integrity("read-pool-start-failed"));
                }
            };
            senders.push(sender);
            threads.push(thread);
        }
        Ok(Self {
            senders,
            next_worker: AtomicU64::new(0),
            zone,
            permits: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_READS)),
            threads,
            telemetry,
        })
    }

    async fn submit<T>(
        &self,
        operation: &'static str,
        make: impl FnOnce(oneshot::Sender<Result<T, StoreError>>) -> ReadCommand,
    ) -> Result<T, StoreError> {
        self.submit_with_hold_for(operation, make, None, READ_LIFETIME)
            .await
    }

    async fn submit_with_lifetime<T>(
        &self,
        operation: &'static str,
        make: impl FnOnce(oneshot::Sender<Result<T, StoreError>>) -> ReadCommand,
        lifetime: Duration,
    ) -> Result<T, StoreError> {
        self.submit_with_hold_for(operation, make, None, lifetime)
            .await
    }

    async fn submit_with_hold_for<T>(
        &self,
        operation: &'static str,
        make: impl FnOnce(oneshot::Sender<Result<T, StoreError>>) -> ReadCommand,
        hold: Option<ReadHold>,
        lifetime: Duration,
    ) -> Result<T, StoreError> {
        let started = Instant::now();
        let permit = Arc::clone(&self.permits)
            .try_acquire_owned()
            .map_err(|_| backpressure())?;
        let (response, receiver) = oneshot::channel();
        let deadline = Instant::now() + lifetime;
        let worker = usize::try_from(
            self.next_worker.fetch_add(1, Ordering::Relaxed) % READ_POOL_THREADS as u64,
        )
        .expect("read-worker index fits usize");
        self.senders[worker]
            .try_send(ReadWork {
                command: make(response),
                deadline,
                permit,
                hold,
            })
            .map_err(|error| match error {
                std::sync::mpsc::TrySendError::Full(_) => backpressure(),
                std::sync::mpsc::TrySendError::Disconnected(_) => {
                    crate::transaction::integrity("read-pool-closed")
                }
            })?;
        let result = tokio::time::timeout(lifetime + Duration::from_millis(25), receiver)
            .await
            .map_err(|_| timeout())?
            .map_err(|_| crate::transaction::integrity("read-response-closed"))?;
        let outcome = if result.is_ok() { "ok" } else { "error" };
        self.telemetry.metric(
            StoreMetric::ReadDuration,
            BTreeMap::from([("operation".to_owned(), operation.to_owned())]),
            elapsed_seconds(started),
        );
        self.telemetry.span(
            STORE_READ_SPAN,
            BTreeMap::from([
                ("operation".to_owned(), operation.to_owned()),
                ("outcome".to_owned(), outcome.to_owned()),
            ]),
            None,
        );
        result
    }

    pub(crate) async fn get(&self, request: StoreGetRequest) -> Result<StoredResource, StoreError> {
        self.validate_zone(&request.zone)?;
        self.submit("get", |response| ReadCommand::Get { request, response })
            .await
    }

    pub(crate) async fn list(
        &self,
        request: StoreListRequest,
    ) -> Result<StoreListResult, StoreError> {
        self.validate_zone(&request.zone)?;
        self.submit_with_lifetime(
            "list",
            |response| ReadCommand::List { request, response },
            LIST_READ_LIFETIME,
        )
        .await
    }

    pub(crate) async fn resolve(
        &self,
        request: StoreResolveRequest,
    ) -> Result<StoreResolvedIdentity, StoreError> {
        self.validate_zone(&request.zone)?;
        self.submit("get", |response| ReadCommand::Resolve { request, response })
            .await
    }

    pub(crate) async fn assignment_fence(
        &self,
        zone: ZoneId,
        target: ResourceRef,
    ) -> Result<Option<d2b_resource_store::ResourceAssignmentFence>, StoreError> {
        self.validate_zone(&zone)?;
        self.submit("get", |response| ReadCommand::Assignment {
            target,
            response,
        })
        .await
    }

    pub(crate) async fn inspect_schema(
        &self,
        request: StoreInspectSchemaRequest,
    ) -> Result<StoredSchema, StoreError> {
        self.validate_zone(&request.zone)?;
        self.submit("scan", |response| ReadCommand::InspectSchema {
            request,
            response,
        })
        .await
    }

    pub(crate) async fn meta(&self) -> Result<StoreMeta, StoreError> {
        self.submit("scan", |response| ReadCommand::Meta { response })
            .await
    }

    pub(crate) async fn authority_operations(
        &self,
    ) -> Result<Vec<crate::AuthorityOperation>, StoreError> {
        self.submit_with_lifetime(
            "scan",
            |response| ReadCommand::AuthorityOperations { response },
            LIST_READ_LIFETIME,
        )
        .await
    }

    fn validate_zone(&self, zone: &ZoneId) -> Result<(), StoreError> {
        if zone != &self.zone {
            return Err(crate::transaction::integrity("request-zone-mismatch"));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) async fn expiry_probe(
        &self,
        started: oneshot::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
        completed: oneshot::Sender<()>,
    ) -> Result<(), StoreError> {
        self.submit_with_hold_for(
            "scan",
            |response| ReadCommand::NeverRespond { response },
            Some(ReadHold {
                started,
                release,
                completed,
            }),
            READ_LIFETIME,
        )
        .await
    }

    #[cfg(test)]
    pub(crate) fn available_permits(&self) -> usize {
        self.permits.available_permits()
    }
}

impl Drop for ReadPool {
    fn drop(&mut self) {
        self.senders.clear();
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

impl ReadPool {
    pub(crate) fn shutdown(&mut self) -> Result<(), StoreError> {
        self.senders.clear();
        for thread in self.threads.drain(..) {
            if thread.join().is_err() {
                return Err(crate::transaction::integrity("read-worker-failed"));
            }
        }
        Ok(())
    }
}

struct ReadWork {
    command: ReadCommand,
    deadline: Instant,
    permit: OwnedSemaphorePermit,
    hold: Option<ReadHold>,
}

#[cfg(test)]
struct ReadHold {
    started: oneshot::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
    completed: oneshot::Sender<()>,
}

#[cfg(not(test))]
struct ReadHold;

enum ReadCommand {
    Get {
        request: StoreGetRequest,
        response: oneshot::Sender<Result<StoredResource, StoreError>>,
    },
    List {
        request: StoreListRequest,
        response: oneshot::Sender<Result<StoreListResult, StoreError>>,
    },
    Resolve {
        request: StoreResolveRequest,
        response: oneshot::Sender<Result<StoreResolvedIdentity, StoreError>>,
    },
    Assignment {
        target: ResourceRef,
        response:
            oneshot::Sender<Result<Option<d2b_resource_store::ResourceAssignmentFence>, StoreError>>,
    },
    InspectSchema {
        request: StoreInspectSchemaRequest,
        response: oneshot::Sender<Result<StoredSchema, StoreError>>,
    },
    Meta {
        response: oneshot::Sender<Result<StoreMeta, StoreError>>,
    },
    AuthorityOperations {
        response: oneshot::Sender<Result<Vec<crate::AuthorityOperation>, StoreError>>,
    },
    #[cfg(test)]
    NeverRespond {
        response: oneshot::Sender<Result<(), StoreError>>,
    },
}

fn read_worker(database: Arc<Database>, receiver: std::sync::mpsc::Receiver<ReadWork>) {
    loop {
        let command = receiver.recv();
        let Ok(ReadWork {
            command,
            deadline,
            permit,
            hold,
        }) = command
        else {
            return;
        };
        if Instant::now() >= deadline {
            send_read_result(command, Err(timeout()));
            drop(permit);
            #[cfg(test)]
            if let Some(hold) = hold {
                let _ = hold.completed.send(());
            }
            #[cfg(not(test))]
            let _ = hold;
            continue;
        }
        #[cfg(test)]
        let mut completed: Option<oneshot::Sender<()>> = None;
        match command {
            ReadCommand::Get { request, response } => {
                let _ = response.send(read_get(&database, request, deadline));
            }
            ReadCommand::List { request, response } => {
                let _ = response.send(read_list(&database, request, deadline));
            }
            ReadCommand::Resolve { request, response } => {
                let result = read_get(
                    &database,
                    StoreGetRequest {
                        operation: request.operation,
                        zone: request.zone,
                        target: request.target,
                        expected_uid: request.expected_uid,
                        projection: StoreProjection::MetadataOnly,
                    },
                    deadline,
                )
                .map(|resource| StoreResolvedIdentity {
                    zone: resource.zone,
                    resource_ref: resource.resource_ref,
                    uid: resource.uid,
                    generation: resource.generation,
                    revision: resource.revision,
                });
                let _ = response.send(result);
            }
            ReadCommand::Assignment { target, response } => {
                let result = read_assignment(&database, target, deadline);
                let _ = response.send(result);
            }
            ReadCommand::InspectSchema { request, response } => {
                let _ = response.send(read_schema(&database, request, deadline));
            }
            ReadCommand::Meta { response } => {
                let result = if Instant::now() >= deadline {
                    Err(timeout())
                } else {
                    current_meta(&database)
                };
                let _ = response.send(result);
            }
            ReadCommand::AuthorityOperations { response } => {
                let result = authority_operations(&database).and_then(|rows| {
                    rows.into_iter()
                        .map(|(operation_id, payload, state)| {
                            Ok(crate::AuthorityOperation {
                                operation_id,
                                payload,
                                state: parse_authority_state(&state)?,
                            })
                        })
                        .collect()
                });
                let _ = response.send(result);
            }
            #[cfg(test)]
            ReadCommand::NeverRespond { response } => {
                if let Some(hold) = hold {
                    let _ = hold.started.send(());
                    let _ = hold.release.recv();
                    completed = Some(hold.completed);
                }
                let _ = response.send(Err(timeout()));
            }
        }
        drop(permit);
        #[cfg(test)]
        if let Some(completed) = completed {
            let _ = completed.send(());
        }
        #[cfg(not(test))]
        let _ = hold;
    }
}

fn send_read_result(command: ReadCommand, result: Result<(), StoreError>) {
    match command {
        ReadCommand::Get { response, .. } => {
            let _ = response.send(Err(result.unwrap_err()));
        }
        ReadCommand::List { response, .. } => {
            let _ = response.send(Err(result.unwrap_err()));
        }
        ReadCommand::Resolve { response, .. } => {
            let _ = response.send(Err(result.unwrap_err()));
        }
        ReadCommand::Assignment { response, .. } => {
            let _ = response.send(Err(result.unwrap_err()));
        }
        ReadCommand::InspectSchema { response, .. } => {
            let _ = response.send(Err(result.unwrap_err()));
        }
        ReadCommand::Meta { response } => {
            let _ = response.send(Err(result.unwrap_err()));
        }
        ReadCommand::AuthorityOperations { response } => {
            let _ = response.send(Err(result.unwrap_err()));
        }
        #[cfg(test)]
        ReadCommand::NeverRespond { response } => {
            let _ = response.send(result);
        }
    }
}

fn read_get(
    database: &Database,
    request: StoreGetRequest,
    deadline: Instant,
) -> Result<StoredResource, StoreError> {
    check_deadline(deadline)?;
    let read = database
        .begin_read()
        .map_err(crate::transaction::integrity)?;
    let table = read
        .open_table(RESOURCES)
        .map_err(crate::transaction::integrity)?;
    let key = resource_key(&request.target)?;
    let bytes = table
        .get(key.as_slice())
        .map_err(crate::transaction::integrity)?
        .ok_or_else(not_found)?;
    check_deadline(deadline)?;
    let record: ResourceRecord = decode(ValueKind::ResourceRecord, bytes.value())?;
    let mut resource = stored_resource(&request.zone, &request.target, &record)?;
    if request
        .expected_uid
        .as_ref()
        .is_some_and(|uid| uid != &resource.uid)
    {
        return Err(not_found());
    }
    project_resource(&mut resource, request.projection)?;
    Ok(resource)
}

fn read_assignment(
    database: &Database,
    target: ResourceRef,
    deadline: Instant,
) -> Result<Option<d2b_resource_store::ResourceAssignmentFence>, StoreError> {
    check_deadline(deadline)?;
    let read = database
        .begin_read()
        .map_err(crate::transaction::integrity)?;
    let table = read
        .open_table(RESOURCES)
        .map_err(crate::transaction::integrity)?;
    let key = resource_key(&target)?;
    let Some(bytes) = table
        .get(key.as_slice())
        .map_err(crate::transaction::integrity)?
    else {
        return Ok(None);
    };
    check_deadline(deadline)?;
    let record: ResourceRecord = decode(ValueKind::ResourceRecord, bytes.value())?;
    record
        .assignment
        .as_ref()
        .map(assignment_fence)
        .transpose()
}

fn read_list(
    database: &Database,
    request: StoreListRequest,
    deadline: Instant,
) -> Result<StoreListResult, StoreError> {
    check_deadline(deadline)?;
    let read = database
        .begin_read()
        .map_err(crate::transaction::integrity)?;
    let table = read
        .open_table(RESOURCES)
        .map_err(crate::transaction::integrity)?;
    let meta = crate::transaction::read_meta(&read)?;
    let snapshot_revision = meta.current_revision;
    let selector_digest = list_selector_digest(&request);
    let mut resources = Vec::new();
    let after_key = match request.cursor.as_deref() {
        Some(cursor) => {
            let cursor = decode_list_cursor(cursor)?;
            if cursor.selector_digest != selector_digest {
                return Err(crate::transaction::integrity(
                    "list-cursor-selector-mismatch",
                ));
            }
            if cursor.snapshot_revision != snapshot_revision {
                return Err(crate::transaction::revision_expired(snapshot_revision));
            }
            cursor.after_key
        }
        None => Vec::new(),
    };
    let page_size = usize::try_from(request.page_size)
        .map_err(crate::transaction::integrity)?
        .max(1);
    for row in table
        .range(after_key.as_slice()..)
        .map_err(crate::transaction::integrity)?
    {
        check_deadline(deadline)?;
        let (key, value) = row.map_err(crate::transaction::integrity)?;
        if !after_key.is_empty() && key.value() <= after_key.as_slice() {
            continue;
        }
        let resource_ref = crate::transaction::resource_ref_from_key(key.value())?;
        let resource_type = resource_ref.resource_type().as_str();
        let name = resource_ref.name().as_str();
        if !request.resource_types.is_empty()
            && !request
                .resource_types
                .iter()
                .any(|candidate| candidate.as_str() == resource_type)
        {
            continue;
        }
        if !request.resource_names.is_empty()
            && !request
                .resource_names
                .iter()
                .any(|candidate| candidate.as_str() == name)
        {
            continue;
        }
        let (mut resource, owner_uid) = if request.projection == StoreProjection::MetadataOnly {
            stored_metadata_resource_from_frame(&request.zone, &resource_ref, value.value())?
        } else {
            let record: ResourceRecord = decode(ValueKind::ResourceRecord, value.value())?;
            let owner_uid = record.owner_uid.clone();
            (
                stored_resource(&request.zone, &resource_ref, &record)?,
                owner_uid,
            )
        };
        if !filters_match(
            &request.filters,
            resource_type,
            name,
            &resource.uid,
            owner_uid.as_deref(),
        ) {
            continue;
        }

        if request.projection != StoreProjection::MetadataOnly {
            project_resource(&mut resource, request.projection)?;
        }
        resources.push((key.value().to_vec(), resource));
        if resources.len() > page_size {
            break;
        }
    }
    let truncated = resources.len() > page_size;
    resources.truncate(page_size);
    let next_cursor = if truncated {
        let after_key = resources
            .last()
            .ok_or_else(|| crate::transaction::integrity("list-page-state-invalid"))?
            .0
            .clone();
        Some(encode_list_cursor(
            snapshot_revision,
            &selector_digest,
            &after_key,
        ))
    } else {
        None
    };
    let resources = resources
        .into_iter()
        .map(|(_, resource)| resource)
        .collect();
    Ok(StoreListResult {
        resources,
        snapshot_revision: ZoneRevision::new(snapshot_revision),
        next_cursor,
        truncated,
    })
}

fn stored_metadata_resource_from_frame(
    zone: &ZoneId,
    resource_ref: &ResourceRef,
    frame: &[u8],
) -> Result<(StoredResource, Option<String>), StoreError> {
    // Resource rows are validated at admission and when the store opens. The
    // metadata-only relist path decodes just the bounded fields it returns so
    // large snapshot rebuilds do not parse each full envelope twice.
    if frame.len() < 7
        || frame[0] != crate::values::VALUE_FORMAT_VERSION
        || u16::from_be_bytes([frame[1], frame[2]]) != ValueKind::ResourceRecord.discriminant()
    {
        return Err(crate::transaction::integrity("table-value-kind-mismatch"));
    }
    let payload_length =
        usize::try_from(u32::from_be_bytes([frame[3], frame[4], frame[5], frame[6]]))
            .map_err(crate::transaction::integrity)?;
    if payload_length > crate::values::MAX_VALUE_PAYLOAD_BYTES || frame.len() != 7 + payload_length
    {
        return Err(crate::transaction::integrity("value-frame-length-mismatch"));
    }
    let value: serde_json::Value = serde_json::from_slice(&frame[7..])
        .map_err(|_| crate::transaction::integrity("stored-resource-envelope-invalid"))?;
    let canonical_json = value
        .get("canonical_json")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| crate::transaction::integrity("stored-resource-canonical-json-missing"))?
        .iter()
        .map(|value| {
            value
                .as_u64()
                .and_then(|value| u8::try_from(value).ok())
                .ok_or_else(|| {
                    crate::transaction::integrity("stored-resource-canonical-json-invalid")
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let payload_digest = value
        .get("payload_digest")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| crate::transaction::integrity("stored-resource-payload-digest-missing"))?
        .to_owned();
    let owner_uid = value
        .get("owner_uid")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let resource: serde_json::Value = serde_json::from_slice(&canonical_json)
        .map_err(|_| crate::transaction::integrity("stored-resource-envelope-invalid"))?;
    let metadata = resource
        .get("metadata")
        .cloned()
        .ok_or_else(|| crate::transaction::integrity("stored-resource-metadata-missing"))?;
    let uid = metadata
        .get("uid")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| ResourceUid::parse(value.to_owned()).ok())
        .ok_or_else(|| crate::transaction::integrity("stored-resource-uid-invalid"))?;
    let generation = metadata
        .get("generation")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| d2b_contracts_resource::v3::ResourceGeneration::new(value).ok())
        .ok_or_else(|| crate::transaction::integrity("stored-resource-generation-invalid"))?;
    let revision = metadata
        .get("revision")
        .and_then(serde_json::Value::as_u64)
        .map(ZoneRevision::new)
        .ok_or_else(|| crate::transaction::integrity("stored-resource-revision-invalid"))?;
    let resource_type = resource
        .get("type")
        .cloned()
        .ok_or_else(|| crate::transaction::integrity("stored-resource-type-missing"))?;
    let canonical_json = serde_json::to_vec(&serde_json::json!({
        "apiVersion": "resources.d2bus.org/v3",
        "metadata": metadata,
        "type": resource_type,
    }))
    .map_err(|_| crate::transaction::integrity("stored-resource-metadata-invalid"))?;
    Ok((
        StoredResource {
            resource_ref: resource_ref.clone(),
            zone: zone.clone(),
            uid,
            generation,
            revision,
            canonical_json,
            payload_digest,
        },
        owner_uid,
    ))
}

struct ListCursor {
    snapshot_revision: u64,
    selector_digest: String,
    after_key: Vec<u8>,
}

fn list_selector_digest(request: &StoreListRequest) -> String {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(request.zone.as_str().as_bytes());
    digest.update([request.projection as u8]);
    for resource_type in &request.resource_types {
        digest.update(resource_type.as_str().as_bytes());
        digest.update([0]);
    }
    for name in &request.resource_names {
        digest.update(name.as_str().as_bytes());
        digest.update([0]);
    }
    for filter in &request.filters {
        digest.update(filter.field.as_bytes());
        digest.update([0]);
        for value in &filter.values {
            digest.update(value.as_bytes());
            digest.update([0]);
        }
    }
    format!("{:x}", digest.finalize())
}

fn encode_list_cursor(revision: u64, selector_digest: &str, after_key: &[u8]) -> String {
    format!("v1.{revision}.{selector_digest}.{}", hex_encode(after_key))
}

fn decode_list_cursor(value: &str) -> Result<ListCursor, StoreError> {
    let mut parts = value.split('.');
    if parts.next() != Some("v1") {
        return Err(crate::transaction::integrity("list-cursor-invalid"));
    }
    let snapshot_revision = parts
        .next()
        .ok_or_else(|| crate::transaction::integrity("list-cursor-invalid"))?
        .parse()
        .map_err(|_| crate::transaction::integrity("list-cursor-invalid"))?;
    let selector_digest = parts
        .next()
        .filter(|digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| crate::transaction::integrity("list-cursor-invalid"))?
        .to_owned();
    let after_key = hex_decode(
        parts
            .next()
            .ok_or_else(|| crate::transaction::integrity("list-cursor-invalid"))?,
    )?;
    if parts.next().is_some() {
        return Err(crate::transaction::integrity("list-cursor-invalid"));
    }
    crate::transaction::resource_ref_from_key(&after_key)?;
    Ok(ListCursor {
        snapshot_revision,
        selector_digest,
        after_key,
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn hex_decode(value: &str) -> Result<Vec<u8>, StoreError> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(crate::transaction::integrity("list-cursor-invalid"));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair)
                .map_err(|_| crate::transaction::integrity("list-cursor-invalid"))?;
            u8::from_str_radix(text, 16)
                .map_err(|_| crate::transaction::integrity("list-cursor-invalid"))
        })
        .collect()
}

fn filters_match(
    filters: &[StoreFilter],
    resource_type: &str,
    name: &str,
    uid: &ResourceUid,
    owner_uid: Option<&str>,
) -> bool {
    filters.iter().all(|filter| match filter.field.as_str() {
        "metadata.name" => filter.values.iter().any(|value| value == name),
        "type" => filter.values.iter().any(|value| value == resource_type),
        "assignment.resourceUid" => filter.values.iter().any(|value| value == uid.as_str()),
        "owner.resourceUid" => filter
            .values
            .iter()
            .any(|value| owner_uid == Some(value.as_str())),
        _ => false,
    })
}

fn project_resource(
    resource: &mut StoredResource,
    projection: StoreProjection,
) -> Result<(), StoreError> {
    if projection == StoreProjection::Full {
        return Ok(());
    }
    let mut value = d2b_contracts_resource::v3::CanonicalJsonValue::parse(&resource.canonical_json)
        .map_err(crate::transaction::integrity)?;
    let d2b_contracts_resource::v3::CanonicalJsonValue::Object(root) = &mut value else {
        return Err(crate::transaction::integrity(
            "stored-resource-envelope-invalid",
        ));
    };
    match projection {
        StoreProjection::Full => unreachable!("full projection returned above"),
        StoreProjection::BaseOnly => {
            if let Some(d2b_contracts_resource::v3::CanonicalJsonValue::Object(spec)) =
                root.get_mut("spec")
            {
                spec.remove("provider");
            }
            if let Some(d2b_contracts_resource::v3::CanonicalJsonValue::Object(status)) =
                root.get_mut("status")
            {
                status.remove("provider");
            }
        }
        StoreProjection::MetadataOnly => {
            root.retain(|key, _| matches!(key.as_str(), "apiVersion" | "metadata" | "type"));
        }
    }
    resource.canonical_json = value.to_canonical_bytes();
    Ok(())
}

fn read_schema(
    database: &Database,
    request: StoreInspectSchemaRequest,
    deadline: Instant,
) -> Result<StoredSchema, StoreError> {
    check_deadline(deadline)?;
    let read = database
        .begin_read()
        .map_err(crate::transaction::integrity)?;
    let table = read
        .open_table(API_SCHEMAS)
        .map_err(crate::transaction::integrity)?;
    let key = crate::transaction::api_schema_key_for_type(&request.resource_type)
        .map_err(|_| not_found())?;
    let bytes = table
        .get(key.as_slice())
        .map_err(crate::transaction::integrity)?
        .ok_or_else(not_found)?;
    let decoded =
        crate::DecodedValue::decode(bytes.value()).map_err(crate::transaction::integrity)?;
    if decoded.kind() != ValueKind::ApiSchemaRecord {
        return Err(crate::transaction::integrity("table-value-kind-mismatch"));
    }
    let canonical_json = decoded.canonical_json().to_vec();
    let payload_digest = crate::transaction::api_schema_digest_for_type(&request.resource_type)
        .map_err(|_| not_found())?;
    Ok(StoredSchema {
        resource_type: request.resource_type,
        canonical_json,
        payload_digest,
    })
}

fn check_deadline(deadline: Instant) -> Result<(), StoreError> {
    if Instant::now() >= deadline {
        return Err(timeout());
    }
    Ok(())
}

fn not_found() -> StoreError {
    d2b_resource_store::StoreError::new(
        d2b_resource_store::StoreErrorKind::ResourceNotFound,
        None,
        None,
        d2b_contracts_resource::v3::RetryClass::Never,
        "resource-not-found",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{ChangeEntry, ChangeEvent, REVISION_LOG, encode, revision_key};
    use d2b_contracts_resource::v3::{ResourceGeneration, ResourceName, ResourceUid};
    use std::fs::OpenOptions;

    fn database(label: &str) -> (tempfile::TempDir, Arc<Database>) {
        let directory = tempfile::tempdir().unwrap();
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(directory.path().join(format!("{label}.redb")))
            .unwrap();
        let backend = redb::backends::FileBackend::new(file).unwrap();
        let database = Database::builder().create_with_backend(backend).unwrap();
        (directory, Arc::new(database))
    }

    fn batch(revision: u64) -> ChangeBatch {
        ChangeBatch::new(
            ZoneRevision::new(revision),
            vec![
                ChangeEntry::new(
                    0,
                    ResourceTypeName::parse("Process").unwrap(),
                    ResourceName::parse("worker").unwrap(),
                    ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap(),
                    ChangeEvent::Created,
                    None,
                    Some(ResourceGeneration::new(1).unwrap()),
                    None,
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                        .to_owned(),
                    None,
                    "op".to_owned(),
                    "corr".to_owned(),
                )
                .unwrap(),
            ],
        )
        .unwrap()
    }

    #[test]
    fn assignment_filter_is_exact_and_does_not_widen_a_watch() {
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        assert!(filters_match(
            &[StoreFilter {
                field: "assignment.resourceUid".to_owned(),
                values: vec![uid.as_str().to_owned()],
            }],
            "Process",
            "worker",
            &uid,
            None,
        ));
        assert!(!filters_match(
            &[StoreFilter {
                field: "assignment.resourceUid".to_owned(),
                values: vec!["223e4567-e89b-42d3-a456-426614174001".to_owned(),],
            }],
            "Process",
            "worker",
            &uid,
            None,
        ));
    }

    #[test]
    fn owner_filter_matches_only_the_exact_owner_uid() {
        let child_uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let owner_uid = ResourceUid::parse("223e4567-e89b-42d3-a456-426614174001").unwrap();
        let filter = [StoreFilter {
            field: "owner.resourceUid".to_owned(),
            values: vec![owner_uid.as_str().to_owned()],
        }];
        assert!(filters_match(
            &filter,
            "Process",
            "worker",
            &child_uid,
            Some(owner_uid.as_str()),
        ));
        assert!(!filters_match(
            &filter, "Process", "worker", &child_uid, None,
        ));
    }

    #[test]
    fn range_seek_never_scans_or_decodes_a_corrupt_older_envelope() {
        let (_directory, database) = database("range-seek-corrupt-old");
        let write = database.begin_write().unwrap();
        {
            let mut table = write.open_table(REVISION_LOG).unwrap();
            table
                .insert(
                    revision_key(1).unwrap().as_slice(),
                    b"not-a-value".as_slice(),
                )
                .unwrap();
            let current = encode(ValueKind::ChangeBatch, &batch(2)).unwrap();
            table
                .insert(revision_key(2).unwrap().as_slice(), current.as_slice())
                .unwrap();
        }
        write.commit().unwrap();

        let signals = SignalCounters::default();
        let mut revisions = Vec::new();
        replay_after(&database, 1, &signals, |batch| {
            revisions.push(batch.revision().get());
            Ok(())
        })
        .unwrap();
        assert_eq!(revisions, [2]);
        let signals = signals.snapshot();
        assert_eq!(signals.revision_range_seeks, 1);
        assert_eq!(signals.replay_rows_scanned, 1);
        assert_eq!(signals.replay_rows_decoded, 1);
    }

    #[test]
    fn filtered_views_share_one_batch_and_nonmatches_are_absent() {
        let process = batch(1).entries()[0].clone();
        let device = ChangeEntry::new(
            1,
            ResourceTypeName::parse("Device").unwrap(),
            ResourceName::parse("gpu").unwrap(),
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174001").unwrap(),
            ChangeEvent::Created,
            None,
            Some(ResourceGeneration::new(1).unwrap()),
            None,
            "sha256:0000000000000000000000000000000000000000000000000000000000000001".to_owned(),
            None,
            "op".to_owned(),
            "corr".to_owned(),
        )
        .unwrap();
        let mixed =
            Arc::new(ChangeBatch::new(ZoneRevision::new(1), vec![process, device]).unwrap());
        let all = filter_batch(
            Arc::clone(&mixed),
            &BTreeSet::from([
                ResourceTypeName::parse("Process").unwrap(),
                ResourceTypeName::parse("Device").unwrap(),
            ]),
        )
        .unwrap();
        let process = filter_batch(
            Arc::clone(&mixed),
            &BTreeSet::from([ResourceTypeName::parse("Process").unwrap()]),
        )
        .unwrap();
        let absent = filter_batch(
            mixed,
            &BTreeSet::from([ResourceTypeName::parse("Volume").unwrap()]),
        );

        assert!(all.shares_batch_with(&process));
        assert_eq!(all.entries().len(), 2);
        assert_eq!(process.entries().len(), 1);
        assert!(absent.is_none());
    }

    #[test]
    fn fair_scheduler_round_robins_principals_and_preserves_resource_order() {
        let permits = Arc::new(tokio::sync::Semaphore::new(3));
        let request = |sequence, principal: &str, resource: &str| {
            crate::transaction::empty_write_request_for_test(
                sequence,
                principal,
                ResourceRef::parse(resource).unwrap(),
                Arc::clone(&permits).try_acquire_owned().unwrap(),
            )
        };
        let mut scheduler = FairScheduler::default();
        scheduler.push(request(0, "alice", "Process/shared"));
        scheduler.push(request(1, "alice", "Process/shared"));
        scheduler.push(request(2, "bob", "Process/other"));

        let first = scheduler.pop_group();
        assert_eq!(first.len(), 2);
        assert_eq!(first[0].sequence, 0);
        assert_eq!(first[1].principal, "bob");
        let second = scheduler.pop_group();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].sequence, 1);
    }

    #[test]
    fn engine_failure_quarantines_actor_and_rejects_queued_writes() {
        let (_directory, database) = database("quarantine-on-engine-failure");
        let (_command_sender, command_receiver) = mpsc::channel(1);
        let signals = Arc::new(SignalCounters::default());
        let quarantined = Arc::new(AtomicBool::new(false));
        let permits = Arc::new(tokio::sync::Semaphore::new(2));
        let first = crate::transaction::empty_write_request_for_test(
            0,
            "alice",
            ResourceRef::parse("Process/first").unwrap(),
            Arc::clone(&permits).try_acquire_owned().unwrap(),
        );
        let second = crate::transaction::empty_write_request_for_test(
            1,
            "bob",
            ResourceRef::parse("Process/first").unwrap(),
            Arc::clone(&permits).try_acquire_owned().unwrap(),
        );
        let (second_response, second_result) = oneshot::channel();
        let mut second = second;
        second.response = second_response;
        let watch_coordinator = Arc::new(std::sync::Mutex::new(WatchCoordinator::default()));
        let mut actor = WriterActor::new(
            database,
            command_receiver,
            Arc::clone(&signals),
            Arc::clone(&quarantined),
            watch_coordinator,
        );
        actor.scheduler.push(first);
        actor.scheduler.push(second);
        signals.writer_queue_depth.store(2, Ordering::Relaxed);
        crate::transaction::fail_next_apply_group_for_test();
        actor.flush();

        assert!(quarantined.load(Ordering::Acquire));
        assert_eq!(actor.scheduler.len, 0);
        assert_eq!(signals.writer_queue_depth.load(Ordering::Relaxed), 0);
        assert_eq!(
            second_result.blocking_recv().unwrap().unwrap_err().kind(),
            d2b_resource_store::StoreErrorKind::StoreQuarantined
        );
    }

    #[test]
    fn durable_audit_failure_blocks_the_store_commit() {
        struct RejectingAudit(AtomicU64);

        impl DurableMutationAudit for RejectingAudit {
            fn append_before_commit(
                &self,
                _record: &d2b_audit::AuditRecord,
            ) -> Result<(), d2b_audit::AuditRecordError> {
                self.0.fetch_add(1, Ordering::Relaxed);
                Err(d2b_audit::AuditRecordError::Serialization)
            }

            fn existing_mutation_hash(
                &self,
                _key: &d2b_audit::ZoneOperationKey,
                _mutation_id: &str,
            ) -> Result<Option<d2b_audit::AuditHash>, d2b_audit::AuditRecordError> {
                Ok(None)
            }

            fn existing_mutation_predecessor(
                &self,
                _key: &d2b_audit::ZoneOperationKey,
                _mutation_id: &str,
            ) -> Result<Option<d2b_audit::AuditHash>, d2b_audit::AuditRecordError> {
                Ok(None)
            }
        }

        let (_directory, database) = database("audit-before-commit");
        let identity = crate::StoreIdentity::new(
            d2b_resource_store::StoreSlot::new(0).unwrap(),
            d2b_contracts_resource::v3::ResourceUid::parse("11111111-1111-4111-8111-111111111111")
                .unwrap(),
            ZoneId::parse("work").unwrap(),
            d2b_contracts_resource::v3::ResourceUid::parse("22222222-2222-4222-8222-222222222222")
                .unwrap(),
            d2b_contracts_resource::v3::Timestamp::parse("2026-07-31T00:00:00.000Z").unwrap(),
            d2b_resource_store::PolicySnapshot {
                policy_revision: 1,
                api_catalog_revision: 1,
                active_configuration_revision:
                    d2b_contracts_resource::v3::ConfigurationGeneration::new(1).unwrap(),
                controller_generation: None,
            },
        );
        crate::transaction::initialize(&database, &identity).unwrap();

        let (_command_sender, command_receiver) = mpsc::channel(1);
        let signals = Arc::new(SignalCounters::default());
        let quarantined = Arc::new(AtomicBool::new(false));
        let permits = Arc::new(tokio::sync::Semaphore::new(1));
        let request = crate::transaction::empty_write_request_for_test(
            0,
            "subject",
            ResourceRef::parse("Process/first").unwrap(),
            Arc::clone(&permits).try_acquire_owned().unwrap(),
        );
        let (response, result) = oneshot::channel();
        let mut request = request;
        request.response = response;
        let audit = Arc::new(RejectingAudit(AtomicU64::new(0)));
        let watch_coordinator = Arc::new(std::sync::Mutex::new(WatchCoordinator::default()));
        let mut actor = WriterActor::new_with_ports(
            database.clone(),
            command_receiver,
            signals,
            quarantined,
            watch_coordinator,
            Arc::new(NoopStoreTelemetry),
            audit.clone(),
            Arc::new(std::sync::Mutex::new(BTreeMap::new())),
            Arc::new(BrokerEvidenceIndex::default()),
        );
        actor.scheduler.push(request);
        actor.flush();

        assert_eq!(audit.0.load(Ordering::Relaxed), 1);
        assert_eq!(
            crate::transaction::current_meta(&database)
                .unwrap()
                .current_revision,
            0
        );
        assert_eq!(
            result.blocking_recv().unwrap().unwrap_err().kind(),
            d2b_resource_store::StoreErrorKind::StoreIntegrityFailure
        );
    }
}
