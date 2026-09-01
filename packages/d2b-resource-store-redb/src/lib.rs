//! Production redb backend for one Zone resource store.

pub mod actor;
pub mod audit;
pub mod backup;
pub mod keys;
pub mod metrics;
pub mod migration;
pub mod ownership;
pub mod revision_log;
pub mod schema;
pub mod tracing;
mod transaction;
pub mod values;

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use actor::{ReadPool, SignalCounters, WriterHandle};
use d2b_audit::{
    AuditHash, AuditRecord, AuditRecordError, AuditRecordFields, AuditSink, AuditWriteClass,
    AuditWriteOutcome, DurabilityEvidence, ZoneOperationKey,
};
use d2b_contracts_resource::v3::{
    ConfigurationGeneration, ControllerGeneration, ResourceUid, Timestamp, ZoneId, ZoneRevision,
    canonical_digest, identity::STANDARD_RESOURCE_TYPES,
};
use d2b_resource_store::MutationSealBody;
use d2b_resource_store::mutation_seal::{MutationSealAcceptor, SealedMutation};
use d2b_resource_store::{
    PolicySnapshot, StoreCommitResult, StoreError, StoreGetRequest, StoreInspectSchemaRequest,
    StoreListRequest, StoreListResult, StoreResolveRequest, StoreResolvedIdentity,
    StoreSealIdentity, StoreSlot, StoreWatchReceipt, StoreWatchRequest, StoredResource,
    StoredSchema,
};
use d2b_telemetry::BoundedEmitter;
use redb::Database;
use redb::backends::FileBackend;
use rustix::io::{FdFlags, fcntl_getfd};
use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, recvmsg};

use crate::audit::DurableMutationAudit;
#[cfg(test)]
use crate::audit::NoopMutationAudit;
use crate::metrics::{EmitterStoreTelemetry, NoopStoreTelemetry, StoreTelemetry};

pub use actor::{
    BackendSignals, GROUP_COMMIT_MAX, MAX_CONCURRENT_READS, READ_LIFETIME, READ_POOL_THREADS,
    SharedChangeBatch, WRITE_QUEUE_CAPACITY,
};
pub use backup::{
    BackupRow, BackupTable, LOGICAL_BACKUP_FORMAT_VERSION, LogicalBackup, MAX_LOGICAL_BACKUP_BYTES,
    MAX_LOGICAL_BACKUP_ROWS, MAX_PUBLICATION_NAME_BYTES, PublicationState, publication_state,
    publish_staged, sync_staged_file,
};
pub use keys::{
    DecodedKey, DecodedKeyComponent, EncodedKey, KeyCodecError, KeyComponent, KeySpace,
    MAX_ENCODED_KEY_BYTES, MAX_KEY_COMPONENTS, MAX_TEXT_COMPONENT_BYTES, encode_key,
};
pub use migration::{
    CURRENT_PHYSICAL_SCHEMA_VERSION, DEFAULT_ACTIVE_FILE_NAME, DEFAULT_PRIOR_FILE_NAME,
    DEFAULT_STAGED_FILE_NAME, MigrationOutcome, MigrationStep, REGISTERED_MIGRATIONS,
    RecoveryOutcome, migration_chain, recover_owned, restore_owned, upgrade_owned,
    upgrade_owned_after_backup,
};
pub use ownership::{
    MAX_OWNER_CHAIN_DEPTH, OwnerBinding, OwnerChangeEvent, OwnerIndex, OwnerIndexMutation,
    OwnershipError, ReverseOwnerEntry,
};
pub use revision_log::{
    MAX_COMPACTION_BYTES_PER_TRANSACTION, MAX_COMPACTION_ROWS_PER_TRANSACTION,
    MAX_INITIAL_WATCH_CREDITS, MAX_RETAINED_RESUME_CURSORS, MAX_WATCH_REGISTRATIONS,
    WATCH_ADMISSION_CAPACITY, WatchCoordinator, WatchRegistrationId, WatchSelector, WatchSignals,
    WatchStream, compact,
};
pub use schema::{TABLE_SCHEMAS, TableSchema};
pub use transaction::{ChangeBatch, ChangeEntry, ChangeEvent};
pub use values::{
    DecodedValue, EncodedValue, MAX_ENCODED_VALUE_BYTES, MAX_VALUE_PAYLOAD_BYTES, ValueCodecError,
    ValueKind, encode_value,
};

/// Bound redb's page cache so database scale cannot turn into process RSS.
pub(crate) const REDB_CACHE_SIZE: usize = 4 * 1024 * 1024;

/// Synchronized broker terminal evidence shared by every Zone store opened by
/// one daemon. The index is live: broker responses can be ingested after
/// startup without rebuilding the store or restarting the daemon.
pub struct BrokerEvidenceIndex {
    entries: RwLock<BTreeMap<ZoneOperationKey, DurabilityEvidence>>,
}

impl core::fmt::Debug for BrokerEvidenceIndex {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BrokerEvidenceIndex")
            .field(
                "entry_count",
                &self
                    .entries
                    .read()
                    .map(|entries| entries.len())
                    .unwrap_or(0),
            )
            .finish()
    }
}

impl Default for BrokerEvidenceIndex {
    fn default() -> Self {
        Self::new(BTreeMap::new())
    }
}

impl BrokerEvidenceIndex {
    /// Construct a live index from strict startup evidence.
    pub fn new(entries: BTreeMap<ZoneOperationKey, DurabilityEvidence>) -> Self {
        Self {
            entries: RwLock::new(entries),
        }
    }

    /// Insert one terminal broker result before a matching outbox is cleared.
    pub fn insert(&self, evidence: DurabilityEvidence) -> Result<(), StoreError> {
        let mut entries = self
            .entries
            .write()
            .map_err(|_| transaction::durability_failure("broker-evidence-index-poisoned"))?;
        if let Some(existing) = entries.get(&evidence.key) {
            if existing == &evidence {
                return Ok(());
            }
            if !(existing.outcome == d2b_audit::DurabilityOutcome::Failure
                && !existing.effect_durable
                && evidence.outcome == d2b_audit::DurabilityOutcome::Success
                && evidence.effect_durable)
            {
                return Err(transaction::durability_failure(
                    "audit-broker-evidence-conflict",
                ));
            }
        }
        entries.insert(evidence.key.clone(), evidence);
        Ok(())
    }

    /// Look up one canonical Zone-operation evidence row.
    pub fn get(&self, key: &ZoneOperationKey) -> Result<Option<DurabilityEvidence>, StoreError> {
        self.entries
            .read()
            .map(|entries| entries.get(key).cloned())
            .map_err(|_| transaction::durability_failure("broker-evidence-index-poisoned"))
    }

    /// Return the number of live evidence rows.
    pub fn len(&self) -> Result<usize, StoreError> {
        self.entries
            .read()
            .map(|entries| entries.len())
            .map_err(|_| transaction::durability_failure("broker-evidence-index-poisoned"))
    }

    /// Return whether the live evidence index has no rows.
    pub fn is_empty(&self) -> Result<bool, StoreError> {
        self.len().map(|len| len == 0)
    }
}

struct StorePorts {
    telemetry: Arc<dyn StoreTelemetry>,
    audit: Arc<dyn DurableMutationAudit>,
    broker_evidence: Arc<BrokerEvidenceIndex>,
}

/// Adapter for an audit sink whose directory was provisioned by its owner.
///
/// Resource-store mutations are standard resource-plane events, not
/// privileged host mutations.  The adapter is intentionally separate from
/// the legacy privileged broker adapter.
#[allow(dead_code)]
struct StandardAuditSinkMutationAudit {
    sink: Arc<AuditSink>,
}

impl DurableMutationAudit for StandardAuditSinkMutationAudit {
    fn previous_hash(&self) -> Result<AuditHash, AuditRecordError> {
        self.sink
            .chain_head()
            .map_err(|_| AuditRecordError::Serialization)
    }

    fn append_before_commit(&self, record: &AuditRecord) -> Result<(), AuditRecordError> {
        let class = audit_write_class(record);
        match self
            .sink
            .append(class, record)
            .map_err(|_| AuditRecordError::Serialization)?
        {
            AuditWriteOutcome::Written => Ok(()),
            AuditWriteOutcome::RateLimited | AuditWriteOutcome::DroppedUnavailable => {
                Err(AuditRecordError::Serialization)
            }
        }
    }

    fn existing_mutation_hash(
        &self,
        key: &ZoneOperationKey,
        mutation_id: &str,
    ) -> Result<Option<AuditHash>, AuditRecordError> {
        self.sink
            .mutation_record_hash(key, mutation_id)
            .map_err(|_| AuditRecordError::Serialization)
    }

    fn existing_mutation_predecessor(
        &self,
        key: &ZoneOperationKey,
        mutation_id: &str,
    ) -> Result<Option<AuditHash>, AuditRecordError> {
        self.sink
            .mutation_record_predecessor(key, mutation_id)
            .map_err(|_| AuditRecordError::Serialization)
    }
}

#[allow(dead_code)]
fn audit_write_class(record: &AuditRecord) -> AuditWriteClass {
    let AuditRecordFields::ResourceMutation(fields) = record.fields() else {
        return AuditWriteClass::Standard;
    };
    if fields.outcome == "denied"
        || fields.resource_type.as_str() == STANDARD_RESOURCE_TYPES[4]
        || matches!(
            fields.resource_type.as_str(),
            "Zone"
                | "ZoneLink"
                | "Provider"
                | "Role"
                | "Quota"
                | "EmergencyPolicy"
                | "Credential"
                | "ResourceExport"
                | "ResourceImport"
        )
    {
        AuditWriteClass::Privileged
    } else {
        AuditWriteClass::Standard
    }
}

impl StorePorts {
    #[cfg(not(test))]
    fn production(file: &File) -> Result<Self, StoreError> {
        let state_dir = store_state_dir(file)?;
        let sink = Arc::new(
            AuditSink::open(state_dir.join("audit"))
                .map_err(|_| transaction::durability_failure("audit-owner-unavailable"))?,
        );
        Self::production_with_audit_and_telemetry(
            file,
            sink,
            Arc::new(BrokerEvidenceIndex::default()),
            state_dir.join("telemetry").join("emitter.sock"),
        )
    }

    fn production_with_audit(
        file: &File,
        sink: Arc<AuditSink>,
        broker_evidence: Arc<BrokerEvidenceIndex>,
    ) -> Result<Self, StoreError> {
        Self::production_with_audit_and_telemetry(
            file,
            sink,
            broker_evidence,
            store_state_dir(file)?
                .join("telemetry")
                .join("emitter.sock"),
        )
    }

    fn production_with_audit_and_telemetry(
        _file: &File,
        sink: Arc<AuditSink>,
        broker_evidence: Arc<BrokerEvidenceIndex>,
        telemetry_path: PathBuf,
    ) -> Result<Self, StoreError> {
        let telemetry = match BoundedEmitter::with_default_capacity(telemetry_path) {
            Ok(emitter) => Arc::new(EmitterStoreTelemetry::new(emitter)) as Arc<dyn StoreTelemetry>,
            Err(_) => Arc::new(NoopStoreTelemetry) as Arc<dyn StoreTelemetry>,
        };
        Ok(Self {
            telemetry,
            audit: Arc::new(StandardAuditSinkMutationAudit { sink }),
            broker_evidence,
        })
    }

    #[cfg(test)]
    fn with_audit_sink(file: &File, sink: Arc<AuditSink>) -> Result<Self, StoreError> {
        let telemetry_emitter = BoundedEmitter::with_default_capacity(
            store_state_dir(file)?
                .join("telemetry")
                .join("emitter.sock"),
        )
        .map_err(|_| transaction::durability_failure("telemetry-unavailable"))?;
        let _ = file;
        Ok(Self {
            telemetry: Arc::new(EmitterStoreTelemetry::new(telemetry_emitter)),
            audit: Arc::new(StandardAuditSinkMutationAudit { sink }),
            broker_evidence: Arc::new(BrokerEvidenceIndex::default()),
        })
    }

    #[cfg(test)]
    fn for_file(_file: &File) -> Result<Self, StoreError> {
        Ok(Self {
            telemetry: Arc::new(NoopStoreTelemetry),
            audit: Arc::new(NoopMutationAudit),
            broker_evidence: Arc::new(BrokerEvidenceIndex::default()),
        })
    }

    #[cfg(not(test))]
    fn for_file(file: &File) -> Result<Self, StoreError> {
        Self::production(file)
    }
}

fn store_state_dir(file: &File) -> Result<PathBuf, StoreError> {
    let fd_path = Path::new("/proc/self/fd").join(file.as_raw_fd().to_string());
    let target = std::fs::read_link(fd_path)
        .map_err(|_| transaction::durability_failure("audit-owner-unavailable"))?;
    if !target.is_absolute() || target.to_string_lossy().contains(" (deleted)") {
        return Err(transaction::durability_failure("audit-owner-unavailable"));
    }
    target
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| transaction::durability_failure("audit-owner-unavailable"))
}

/// Immutable identity and generation binding for one already-provisioned store.
#[derive(Clone, PartialEq, Eq)]
pub struct StoreIdentity {
    slot: StoreSlot,
    store_uuid: ResourceUid,
    zone: ZoneId,
    zone_uid: ResourceUid,
    store_epoch: u64,
    created_at: String,
    revisions: PolicySnapshot,
}

/// Mutable revision metadata rehydrated from one opened Zone store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreRuntimeMetadata {
    /// Store UID read from the durable metadata row.
    pub store_uid: ResourceUid,
    /// Zone self-resource UID read from the durable metadata row.
    pub zone_uid: ResourceUid,
    /// Store identity epoch read from the durable metadata row.
    pub store_epoch: u64,
    pub current_revision: ZoneRevision,
    pub compaction_floor: ZoneRevision,
    pub policy_snapshot: PolicySnapshot,
}

/// Durable lifecycle state for an authority operation row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityOperationState {
    Pending,
    EffectConfirmed,
    EffectRetryable,
    EffectTerminal,
    Closing,
    Closed,
    Released,
}

/// Opaque authority operation row returned by the Zone store.
///
/// The payload is typed and validated by the Core authority adapter. The
/// redb layer only persists it in the existing operation ledger and never
/// interprets it as an authorization proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityOperation {
    pub operation_id: String,
    pub payload: Vec<u8>,
    pub state: AuthorityOperationState,
}

static NEXT_AUTHORITY_CAPABILITY_NONCE: AtomicU64 = AtomicU64::new(1);

/// Opaque lifecycle authority for one prepared operation and one opened store.
///
/// The operation id is private and every transition is selected from this
/// capability. There is no public store-wide or bare-operation-id mutation
/// method.
pub struct AuthorityOperationCapability {
    store: Arc<RedbResourceStore>,
    nonce: u64,
    operation_id: String,
    binding_digest: String,
}

impl core::fmt::Debug for AuthorityOperationCapability {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AuthorityOperationCapability(<store-bound>)")
    }
}

impl StoreIdentity {
    pub fn new(
        slot: StoreSlot,
        store_uuid: ResourceUid,
        zone: ZoneId,
        zone_uid: ResourceUid,
        created_at: Timestamp,
        revisions: PolicySnapshot,
    ) -> Self {
        Self {
            slot,
            store_uuid,
            zone,
            zone_uid,
            store_epoch: 1,
            created_at: created_at.as_str().to_owned(),
            revisions,
        }
    }

    pub const fn zone(&self) -> &ZoneId {
        &self.zone
    }

    pub const fn zone_uid(&self) -> &ResourceUid {
        &self.zone_uid
    }

    /// Borrow the immutable physical store UID.
    pub const fn store_uid(&self) -> &ResourceUid {
        &self.store_uuid
    }

    /// Return the immutable store identity epoch.
    pub const fn store_epoch(&self) -> u64 {
        self.store_epoch
    }

    /// Bind the identity to a nonzero store epoch.
    pub fn with_store_epoch(mut self, store_epoch: u64) -> Self {
        self.store_epoch = store_epoch;
        self
    }

    pub(crate) const fn store_uuid(&self) -> &ResourceUid {
        &self.store_uuid
    }

    pub(crate) fn created_at(&self) -> &str {
        &self.created_at
    }

    pub const fn slot(&self) -> StoreSlot {
        self.slot
    }

    /// Replace only the mutable revision snapshot before provisioning a new
    /// store. Existing stores rehydrate this value from durable metadata.
    pub fn with_revisions(mut self, revisions: PolicySnapshot) -> Self {
        self.revisions = revisions;
        self
    }

    pub fn seal_identity(&self) -> StoreSealIdentity {
        StoreSealIdentity::new(self.slot, self.zone.clone(), self.store_uuid.clone())
            .with_store_epoch(self.store_epoch)
    }
}

impl core::fmt::Debug for StoreIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("StoreIdentity(<redacted>)")
    }
}

/// One concrete backend whose mutation authority is instance-bound.
pub struct RedbResourceStore {
    identity: StoreIdentity,
    authority_capability_nonce: u64,
    recovered_after_crash: bool,
    broker_evidence: Arc<BrokerEvidenceIndex>,
    writer: WriterHandle,
    reads: ReadPool,
    signals: Arc<SignalCounters>,
    seal: MutationSealAcceptor,
    watch_coordinator: Arc<Mutex<WatchCoordinator>>,
    retained_watch_streams: Mutex<BTreeMap<WatchRegistrationId, WatchStream>>,
}

impl core::fmt::Debug for RedbResourceStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RedbResourceStore(<redacted>)")
    }
}

impl RedbResourceStore {
    /// Initialize one unpublished empty database after validating its durable marker.
    pub async fn provision_owned(
        file: File,
        marker: File,
        identity: StoreIdentity,
        acceptor: MutationSealAcceptor,
    ) -> Result<Self, StoreError> {
        Self::provision_owned_with_ports(file, marker, identity, acceptor, None).await
    }

    /// Provision a Zone store with its production-owned durable audit sink.
    pub async fn provision_owned_with_audit(
        file: File,
        marker: File,
        identity: StoreIdentity,
        acceptor: MutationSealAcceptor,
        audit_sink: Arc<AuditSink>,
    ) -> Result<Self, StoreError> {
        Self::provision_owned_with_audit_and_evidence(
            file,
            marker,
            identity,
            acceptor,
            audit_sink,
            Arc::new(BrokerEvidenceIndex::default()),
        )
        .await
    }

    /// Provision a Zone store with audit and broker reconciliation evidence.
    pub async fn provision_owned_with_audit_and_evidence(
        file: File,
        marker: File,
        identity: StoreIdentity,
        acceptor: MutationSealAcceptor,
        audit_sink: Arc<AuditSink>,
        broker_evidence: Arc<BrokerEvidenceIndex>,
    ) -> Result<Self, StoreError> {
        let ports = StorePorts::production_with_audit(&file, audit_sink, broker_evidence)?;
        Self::provision_owned_with_ports(file, marker, identity, acceptor, Some(ports)).await
    }

    /// Provision a Zone store with explicitly owned audit and telemetry
    /// destinations.
    pub async fn provision_owned_with_audit_and_evidence_and_telemetry(
        file: File,
        marker: File,
        identity: StoreIdentity,
        acceptor: MutationSealAcceptor,
        audit_sink: Arc<AuditSink>,
        broker_evidence: Arc<BrokerEvidenceIndex>,
        telemetry_path: impl AsRef<Path>,
    ) -> Result<Self, StoreError> {
        let ports = StorePorts::production_with_audit_and_telemetry(
            &file,
            audit_sink,
            broker_evidence,
            telemetry_path.as_ref().to_path_buf(),
        )?;
        Self::provision_owned_with_ports(file, marker, identity, acceptor, Some(ports)).await
    }

    #[cfg(test)]
    pub(crate) async fn provision_owned_with_test_ports(
        file: File,
        marker: File,
        identity: StoreIdentity,
        acceptor: MutationSealAcceptor,
        telemetry: Arc<dyn StoreTelemetry>,
        audit: Arc<dyn DurableMutationAudit>,
    ) -> Result<Self, StoreError> {
        Self::provision_owned_with_ports(
            file,
            marker,
            identity,
            acceptor,
            Some(StorePorts {
                telemetry,
                audit,
                broker_evidence: Arc::new(BrokerEvidenceIndex::default()),
            }),
        )
        .await
    }

    async fn provision_owned_with_ports(
        file: File,
        mut marker: File,
        identity: StoreIdentity,
        acceptor: MutationSealAcceptor,
        ports: Option<StorePorts>,
    ) -> Result<Self, StoreError> {
        let slot = identity.slot();
        validate_acceptor(&identity, &acceptor)?;
        validate_owned_file(&file).map_err(|error| error.with_store_slot(slot))?;
        validate_owned_file(&marker).map_err(|error| error.with_store_slot(slot))?;
        if file
            .metadata()
            .map_err(transaction::integrity)
            .map_err(|error| error.with_store_slot(slot))?
            .len()
            != 0
        {
            return Err(
                transaction::integrity("provision-database-not-empty").with_store_slot(slot)
            );
        }
        validate_provisioning_marker(&mut marker, &identity)
            .map_err(|error| error.with_store_slot(slot))?;
        let ports = ports
            .map_or_else(|| StorePorts::for_file(&file), Ok)
            .map_err(|error| error.with_store_slot(slot))?;
        let open_identity = identity.clone();
        let database = tokio::task::spawn_blocking(move || {
            let backend = FileBackend::new(file).map_err(transaction::integrity)?;
            let database = Database::builder()
                .set_cache_size(REDB_CACHE_SIZE)
                .create_with_backend(backend)
                .map_err(transaction::integrity)?;
            transaction::initialize(&database, &open_identity)?;
            Ok::<_, StoreError>(database)
        })
        .await
        .map_err(|_| {
            transaction::integrity("database-provision-task-failed").with_store_slot(slot)
        })?
        .map_err(|error| error.with_store_slot(slot))?;
        Self::start(database, identity, false, acceptor, ports)
            .map_err(|error| error.with_store_slot(slot))
    }

    /// Consume an already-provisioned nonempty database file.
    ///
    /// Empty existing files are quarantined rather than initialized.
    pub async fn open_owned(
        file: File,
        identity: StoreIdentity,
        acceptor: MutationSealAcceptor,
    ) -> Result<Self, StoreError> {
        Self::open_owned_with_ports(file, identity, acceptor, None).await
    }

    /// Open a Zone store with its production-owned durable audit sink.
    pub async fn open_owned_with_audit(
        file: File,
        identity: StoreIdentity,
        acceptor: MutationSealAcceptor,
        audit_sink: Arc<AuditSink>,
    ) -> Result<Self, StoreError> {
        Self::open_owned_with_audit_and_evidence(
            file,
            identity,
            acceptor,
            audit_sink,
            Arc::new(BrokerEvidenceIndex::default()),
        )
        .await
    }

    /// Open a Zone store with audit and broker reconciliation evidence.
    pub async fn open_owned_with_audit_and_evidence(
        file: File,
        identity: StoreIdentity,
        acceptor: MutationSealAcceptor,
        audit_sink: Arc<AuditSink>,
        broker_evidence: Arc<BrokerEvidenceIndex>,
    ) -> Result<Self, StoreError> {
        let ports = StorePorts::production_with_audit(&file, audit_sink, broker_evidence)?;
        Self::open_owned_with_ports(file, identity, acceptor, Some(ports)).await
    }

    /// Open a Zone store with explicitly owned audit and telemetry
    /// destinations.
    pub async fn open_owned_with_audit_and_evidence_and_telemetry(
        file: File,
        identity: StoreIdentity,
        acceptor: MutationSealAcceptor,
        audit_sink: Arc<AuditSink>,
        broker_evidence: Arc<BrokerEvidenceIndex>,
        telemetry_path: impl AsRef<Path>,
    ) -> Result<Self, StoreError> {
        let ports = StorePorts::production_with_audit_and_telemetry(
            &file,
            audit_sink,
            broker_evidence,
            telemetry_path.as_ref().to_path_buf(),
        )?;
        Self::open_owned_with_ports(file, identity, acceptor, Some(ports)).await
    }

    #[cfg(test)]
    pub(crate) async fn open_owned_with_test_ports(
        file: File,
        identity: StoreIdentity,
        acceptor: MutationSealAcceptor,
        telemetry: Arc<dyn StoreTelemetry>,
        audit: Arc<dyn DurableMutationAudit>,
    ) -> Result<Self, StoreError> {
        Self::open_owned_with_ports(
            file,
            identity,
            acceptor,
            Some(StorePorts {
                telemetry,
                audit,
                broker_evidence: Arc::new(BrokerEvidenceIndex::default()),
            }),
        )
        .await
    }

    async fn open_owned_with_ports(
        file: File,
        identity: StoreIdentity,
        acceptor: MutationSealAcceptor,
        ports: Option<StorePorts>,
    ) -> Result<Self, StoreError> {
        let slot = identity.slot();
        validate_acceptor(&identity, &acceptor)?;
        validate_owned_file(&file).map_err(|error| error.with_store_slot(slot))?;
        if file
            .metadata()
            .map_err(transaction::integrity)
            .map_err(|error| error.with_store_slot(slot))?
            .len()
            == 0
        {
            return Err(
                transaction::quarantined_reason("provisioned-store-empty").with_store_slot(slot)
            );
        }
        let ports = ports
            .map_or_else(|| StorePorts::for_file(&file), Ok)
            .map_err(|error| error.with_store_slot(slot))?;
        let open_identity = identity.clone();
        let database = tokio::task::spawn_blocking(move || {
            let backend = FileBackend::new(file).map_err(transaction::integrity)?;
            let database = Database::builder()
                .set_cache_size(REDB_CACHE_SIZE)
                .create_with_backend(backend)
                .map_err(transaction::integrity)?;
            let meta = transaction::normalize_and_validate(
                &database,
                &open_identity,
                migration::CURRENT_PHYSICAL_SCHEMA_VERSION,
                false,
            )?;
            let recovered_after_crash = !meta.clean_shutdown;
            let mut open_identity = open_identity;
            open_identity.revisions = policy_snapshot_from_meta(&meta)?;
            Ok::<_, StoreError>((database, recovered_after_crash, open_identity))
        })
        .await
        .map_err(|_| transaction::integrity("database-open-task-failed").with_store_slot(slot))?
        .map_err(|error| error.with_store_slot(slot))?;
        let (database, recovered_after_crash, identity) = database;
        Self::start(database, identity, recovered_after_crash, acceptor, ports)
            .map_err(|error| error.with_store_slot(slot))
    }

    fn start(
        database: Database,
        identity: StoreIdentity,
        recovered_after_crash: bool,
        seal: MutationSealAcceptor,
        ports: StorePorts,
    ) -> Result<Self, StoreError> {
        let database = Arc::new(database);
        let signals = Arc::new(SignalCounters::default());
        let reads = ReadPool::start_with_telemetry(
            Arc::clone(&database),
            identity.zone.clone(),
            Arc::clone(&ports.telemetry),
        )?;
        let watch_coordinator = Arc::new(Mutex::new(WatchCoordinator::default()));
        let writer = WriterHandle::start_with_ports(
            database,
            Arc::clone(&signals),
            Arc::clone(&watch_coordinator),
            ports.telemetry,
            ports.audit,
            Arc::clone(&ports.broker_evidence),
        )?;
        Ok(Self {
            identity,
            authority_capability_nonce: NEXT_AUTHORITY_CAPABILITY_NONCE
                .fetch_add(1, Ordering::Relaxed),
            recovered_after_crash,
            broker_evidence: ports.broker_evidence,
            writer,
            reads,
            signals,
            seal,
            watch_coordinator,
            retained_watch_streams: Mutex::new(BTreeMap::new()),
        })
    }

    /// Policy-neutral replay/live primitive for a future watch coordinator.
    pub async fn replay_backend(
        &self,
        after_revision: u64,
        resource_types: impl IntoIterator<Item = d2b_contracts_resource::v3::ResourceTypeName>,
        visit: impl FnMut(SharedChangeBatch) -> Result<(), StoreError> + Send + 'static,
    ) -> Result<d2b_contracts_resource::v3::ZoneRevision, StoreError> {
        let meta = self.reads.meta().await?;
        if after_revision < meta.compaction_floor {
            return Err(transaction::revision_expired(meta.current_revision));
        }
        self.writer
            .replay(after_revision, resource_types.into_iter().collect(), visit)
            .await
    }

    /// Capture a consistent logical snapshot while the writer owns ordering.
    pub async fn logical_backup(&self) -> Result<LogicalBackup, StoreError> {
        self.writer.backup(self.identity.clone()).await
    }

    /// Alias used by storage owners when exporting the logical image.
    pub async fn backup(&self) -> Result<LogicalBackup, StoreError> {
        self.logical_backup().await
    }

    pub fn signals(&self) -> BackendSignals {
        self.signals.snapshot()
    }

    pub const fn identity(&self) -> &StoreIdentity {
        &self.identity
    }

    /// Return the live broker evidence index shared with this store.
    pub fn broker_evidence_index(&self) -> Arc<BrokerEvidenceIndex> {
        Arc::clone(&self.broker_evidence)
    }

    /// Ingest one terminal broker result and drain matching audit outboxes.
    pub async fn ingest_broker_evidence(
        &self,
        operation_id: &str,
        evidence: DurabilityEvidence,
    ) -> Result<(), StoreError> {
        let expected_key = ZoneOperationKey::derive(self.identity.zone.as_str(), operation_id)
            .map_err(|_| transaction::durability_failure("audit-operation-key-invalid"))?;
        if evidence.key != expected_key {
            return Err(transaction::durability_failure(
                "audit-broker-evidence-key-mismatch",
            ));
        }
        self.writer
            .ingest_broker_evidence(operation_id.to_owned(), evidence)
            .await
    }

    /// Return whether one operation still has a pending audit outbox.
    pub async fn audit_outbox_pending(&self, operation_id: &str) -> Result<bool, StoreError> {
        self.writer
            .audit_outbox_pending(operation_id.to_owned())
            .await
    }

    /// Return every pending trusted-deferred activation outbox in Zone order.
    pub async fn pending_deferred_activation_operation_ids(
        &self,
    ) -> Result<Vec<String>, StoreError> {
        self.writer
            .pending_deferred_activation_operation_ids(self.identity.zone.clone())
            .await
    }

    /// Refuse publication while any trusted-deferred activation outbox remains.
    pub async fn require_no_pending_deferred_activation_outboxes(&self) -> Result<(), StoreError> {
        if self
            .pending_deferred_activation_operation_ids()
            .await?
            .is_empty()
        {
            Ok(())
        } else {
            Err(transaction::integrity("audit-deferred-evidence-pending"))
        }
    }

    /// Whether the existing store lacked a clean-shutdown marker when opened.
    pub const fn recovered_after_crash(&self) -> bool {
        self.recovered_after_crash
    }

    /// Read the current durable revision snapshot after startup.
    pub async fn runtime_metadata(&self) -> Result<StoreRuntimeMetadata, StoreError> {
        let meta = self.reads.meta().await?;
        Ok(StoreRuntimeMetadata {
            store_uid: ResourceUid::parse(meta.store_uuid.clone())
                .map_err(|_| transaction::integrity("store-meta-store-uid-invalid"))?,
            zone_uid: ResourceUid::parse(meta.zone_uid.clone())
                .map_err(|_| transaction::integrity("store-meta-zone-uid-invalid"))?,
            store_epoch: meta.store_epoch,
            current_revision: ZoneRevision::new(meta.current_revision),
            compaction_floor: ZoneRevision::new(meta.compaction_floor),
            policy_snapshot: policy_snapshot_from_meta(&meta)?,
        })
    }

    /// Derive the store-bound digest used to validate authority rows.
    pub fn authority_binding_digest(&self, claim_digest: &str) -> String {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.identity.store_uuid.to_canonical_string().as_bytes());
        bytes.extend_from_slice(self.identity.zone_uid.to_canonical_string().as_bytes());
        bytes.extend_from_slice(claim_digest.as_bytes());
        canonical_digest("d2b:authority-store-binding/v1", &bytes)
    }

    /// Read authority rows before new admission on restart.
    pub async fn authority_operations(&self) -> Result<Vec<AuthorityOperation>, StoreError> {
        self.reads.authority_operations().await
    }

    /// Prepare one Core-validated authority operation and return its
    /// operation-specific store-bound capability.
    pub async fn prepare_authority_operation(
        self: &Arc<Self>,
        operation_id: String,
        payload: Vec<u8>,
        claim_digest: &str,
    ) -> Result<AuthorityOperationCapability, StoreError> {
        let expected_binding = self.authority_binding_digest(claim_digest);
        let envelope: serde_json::Value = serde_json::from_slice(&payload)
            .map_err(|_| transaction::integrity("authority-operation-payload-invalid"))?;
        if envelope
            .get("claimDigest")
            .and_then(serde_json::Value::as_str)
            != Some(claim_digest)
            || envelope
                .get("storeBindingDigest")
                .and_then(serde_json::Value::as_str)
                != Some(expected_binding.as_str())
        {
            return Err(transaction::integrity(
                "authority-operation-claim-envelope-invalid",
            ));
        }
        let request_digest = transaction::authority_payload_digest_value(&envelope)?;
        self.writer
            .authority_prepare(operation_id.clone(), payload, request_digest)
            .await?;
        Ok(AuthorityOperationCapability {
            store: Arc::clone(self),
            nonce: self.authority_capability_nonce,
            operation_id,
            binding_digest: expected_binding,
        })
    }

    /// Resume a non-terminal operation with a capability bound to its
    /// committed row and store instance.
    pub async fn resume_authority_operation(
        self: &Arc<Self>,
        operation_id: String,
        binding_digest: &str,
    ) -> Result<AuthorityOperationCapability, StoreError> {
        let row = self
            .authority_operations()
            .await?
            .into_iter()
            .find(|row| row.operation_id == operation_id)
            .ok_or_else(|| transaction::integrity("authority-operation-missing"))?;
        if matches!(
            row.state,
            AuthorityOperationState::Released | AuthorityOperationState::Closed
        ) {
            return Err(transaction::integrity("authority-operation-terminal"));
        }
        let payload: serde_json::Value = serde_json::from_slice(&row.payload)
            .map_err(|_| transaction::integrity("authority-operation-payload-invalid"))?;
        if payload
            .get("storeBindingDigest")
            .and_then(serde_json::Value::as_str)
            != Some(binding_digest)
        {
            return Err(transaction::integrity(
                "authority-operation-capability-mismatch",
            ));
        }
        Ok(AuthorityOperationCapability {
            store: Arc::clone(self),
            nonce: self.authority_capability_nonce,
            operation_id,
            binding_digest: binding_digest.to_owned(),
        })
    }

    /// Persist a clean-shutdown marker and join the owned worker threads.
    pub async fn shutdown(mut self) -> Result<(), StoreError> {
        if let Ok(mut streams) = self.retained_watch_streams.lock() {
            streams.clear();
        }
        self.reads.shutdown()?;
        self.writer.shutdown().await
    }

    /// Restore a validated logical image into a new owned descriptor.
    ///
    /// The target descriptor must be empty and the marker must already have
    /// been provisioned for the same store identity.  Publication of the
    /// staged descriptor remains an fd-relative storage-owner operation.
    pub async fn restore_owned(
        file: File,
        marker: File,
        backup: LogicalBackup,
        identity: StoreIdentity,
        acceptor: MutationSealAcceptor,
    ) -> Result<Self, StoreError> {
        Self::restore_owned_with_ports(file, marker, backup, identity, acceptor, None).await
    }

    /// Restore a logical image with the production-owned audit sink.
    pub async fn restore_owned_with_audit(
        file: File,
        marker: File,
        backup: LogicalBackup,
        identity: StoreIdentity,
        acceptor: MutationSealAcceptor,
        audit_sink: Arc<AuditSink>,
    ) -> Result<Self, StoreError> {
        let ports = StorePorts::production_with_audit(
            &file,
            audit_sink,
            Arc::new(BrokerEvidenceIndex::default()),
        )?;
        Self::restore_owned_with_ports(file, marker, backup, identity, acceptor, Some(ports)).await
    }

    async fn restore_owned_with_ports(
        file: File,
        mut marker: File,
        backup: LogicalBackup,
        identity: StoreIdentity,
        acceptor: MutationSealAcceptor,
        ports: Option<StorePorts>,
    ) -> Result<Self, StoreError> {
        let slot = identity.slot();
        validate_acceptor(&identity, &acceptor)?;
        validate_owned_file(&file).map_err(|error| error.with_store_slot(slot))?;
        validate_owned_file(&marker).map_err(|error| error.with_store_slot(slot))?;
        validate_provisioning_marker(&mut marker, &identity)
            .map_err(|error| error.with_store_slot(slot))?;
        if file
            .metadata()
            .map_err(transaction::integrity)
            .map_err(|error| error.with_store_slot(slot))?
            .len()
            != 0
        {
            return Err(
                transaction::quarantined_reason("restore-target-not-empty").with_store_slot(slot)
            );
        }
        let ports = ports
            .map_or_else(|| StorePorts::for_file(&file), Ok)
            .map_err(|error| error.with_store_slot(slot))?;
        let open_identity = identity.clone();
        let database =
            tokio::task::spawn_blocking(move || backup.restore_file(file, &open_identity))
                .await
                .map_err(|_| {
                    transaction::integrity("database-restore-task-failed").with_store_slot(slot)
                })?
                .map_err(|error| error.with_store_slot(slot))?;
        Self::start(database, identity, false, acceptor, ports)
            .map_err(|error| error.with_store_slot(slot))
    }
}

impl AuthorityOperationCapability {
    pub async fn record_effect(&self, state: AuthorityOperationState) -> Result<(), StoreError> {
        self.store
            .writer
            .authority_update(self.operation_id.clone(), state)
            .await
    }

    pub async fn record_close(&self) -> Result<(), StoreError> {
        self.store
            .writer
            .authority_update(self.operation_id.clone(), AuthorityOperationState::Closing)
            .await
    }

    pub async fn release(&self) -> Result<(), StoreError> {
        self.store
            .writer
            .authority_update(self.operation_id.clone(), AuthorityOperationState::Released)
            .await
    }

    pub const fn nonce(&self) -> u64 {
        self.nonce
    }

    pub fn matches_binding_digest(&self, binding_digest: &str) -> bool {
        self.binding_digest == binding_digest
    }
}

fn policy_snapshot_from_meta(meta: &transaction::StoreMeta) -> Result<PolicySnapshot, StoreError> {
    Ok(PolicySnapshot {
        policy_revision: meta.policy_revision,
        api_catalog_revision: meta.api_catalog_revision,
        active_configuration_revision: ConfigurationGeneration::new(
            meta.active_configuration_revision,
        )
        .map_err(|_| transaction::integrity("store-active-configuration-revision-invalid"))?,
        controller_generation: meta
            .controller_generation
            .map(ControllerGeneration::new)
            .transpose()
            .map_err(|_| transaction::integrity("store-controller-generation-invalid"))?,
    })
}

impl RedbResourceStore {
    pub async fn get(&self, request: StoreGetRequest) -> Result<StoredResource, StoreError> {
        self.reads.get(request).await
    }

    pub async fn list(&self, request: StoreListRequest) -> Result<StoreListResult, StoreError> {
        self.reads.list(request).await
    }

    /// Open a watch and return its stream to the caller that owns delivery.
    ///
    /// Registration, replay, and the writer's live-delivery boundary execute
    /// in the same actor, so no commit can fall between registration and the
    /// replay high-water mark.
    pub async fn watch_stream(
        &self,
        request: StoreWatchRequest,
    ) -> Result<(StoreWatchReceipt, WatchStream), StoreError> {
        if request.zone != self.identity.zone {
            return Err(transaction::integrity("request-zone-mismatch"));
        }
        let selector = WatchSelector::new(
            request.resource_types,
            request.resource_names,
            request.filters,
        );
        let (stream, snapshot_revision) = self
            .writer
            .watch(request.after_revision, selector, request.initial_credits)
            .await?;
        let receipt = StoreWatchReceipt {
            stream_name: Self::stream_name(stream.id()),
            snapshot_revision,
        };
        Ok((receipt, stream))
    }

    /// Register a watch for the resource API and retain its stream by id.
    ///
    /// The API's current receipt-only contract hands the stream to a named
    /// bus layer later.  [`Self::take_watch_stream`] is the single transfer
    /// point for that handoff.
    pub async fn watch(&self, request: StoreWatchRequest) -> Result<StoreWatchReceipt, StoreError> {
        let (receipt, stream) = self.watch_stream(request).await?;
        let id = stream.id();
        let mut retained = match self.retained_watch_streams.lock() {
            Ok(retained) => retained,
            Err(_) => {
                self.unregister_watch_now(id);
                return Err(transaction::integrity("watch-stream-registry-poisoned"));
            }
        };
        if retained.insert(id, stream).is_some() {
            drop(retained);
            self.unregister_watch_now(id);
            return Err(transaction::integrity("watch-registration-duplicate"));
        }
        Ok(receipt)
    }

    /// Transfer a receipt-created stream to the bus/session owner.
    pub fn take_watch_stream(
        &self,
        id: WatchRegistrationId,
    ) -> Result<Option<WatchStream>, StoreError> {
        self.retained_watch_streams
            .lock()
            .map_err(|_| transaction::integrity("watch-stream-registry-poisoned"))
            .map(|mut streams| streams.remove(&id))
    }

    /// Transfer a receipt-created stream by its opaque receipt name.
    pub fn take_watch_stream_named(&self, name: &str) -> Result<Option<WatchStream>, StoreError> {
        let id = name
            .strip_prefix("watch-")
            .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
            .and_then(|value| value.parse::<u64>().ok())
            .map(WatchRegistrationId::from_raw)
            .ok_or_else(|| transaction::integrity("watch-stream-name-invalid"))?;
        if Self::stream_name(id) != name {
            return Err(transaction::integrity("watch-stream-name-invalid"));
        }
        self.take_watch_stream(id)
    }

    /// Acknowledge all queued deliveries through `revision`.
    pub async fn acknowledge_watch(
        &self,
        id: WatchRegistrationId,
        revision: d2b_contracts_resource::v3::ZoneRevision,
    ) -> Result<(), StoreError> {
        self.writer.acknowledge_watch(id, revision).await
    }

    /// Unregister a watch and release all of its global budget.
    pub async fn unregister_watch(
        &self,
        id: WatchRegistrationId,
    ) -> Result<Option<d2b_contracts_resource::v3::ZoneRevision>, StoreError> {
        self.retained_watch_streams
            .lock()
            .map_err(|_| transaction::integrity("watch-stream-registry-poisoned"))?
            .remove(&id);
        self.writer.unregister_watch(id).await
    }

    /// Unregister a watch from a synchronous owner-drop path.
    pub fn unregister_watch_now(&self, id: WatchRegistrationId) {
        if let Ok(mut streams) = self.retained_watch_streams.lock() {
            streams.remove(&id);
        }
        if let Ok(mut coordinator) = self.watch_coordinator.lock() {
            let _ = coordinator.unregister(id);
        }
    }

    /// Return the fixed-cardinality watch saturation snapshot.
    pub fn watch_signals(&self) -> Result<WatchSignals, StoreError> {
        self.watch_coordinator
            .lock()
            .map_err(|_| transaction::integrity("watch-coordinator-poisoned"))
            .map(|coordinator| coordinator.signals())
    }

    pub async fn resolve_ref(
        &self,
        request: StoreResolveRequest,
    ) -> Result<StoreResolvedIdentity, StoreError> {
        self.reads.resolve(request).await
    }

    fn stream_name(id: WatchRegistrationId) -> String {
        format!("watch-{}", id.get())
    }

    pub async fn inspect_schema(
        &self,
        request: StoreInspectSchemaRequest,
    ) -> Result<StoredSchema, StoreError> {
        self.reads.inspect_schema(request).await
    }
}

impl RedbResourceStore {
    /// Commit only evidence opened by this store's paired acceptor.
    pub async fn commit_verified(
        &self,
        sealed: SealedMutation,
    ) -> Result<StoreCommitResult, StoreError> {
        let opened = self.seal.open(sealed)?;
        self.writer.commit(opened).await
    }

    /// Commit evidence after an owner has applied additional validation to
    /// the opened mutation body.
    pub async fn commit_verified_with<F>(
        &self,
        sealed: SealedMutation,
        validate: F,
    ) -> Result<StoreCommitResult, StoreError>
    where
        F: FnOnce(&MutationSealBody) -> Result<(), StoreError>,
    {
        let opened = self.seal.open(sealed)?;
        validate(opened.body())?;
        self.writer.commit(opened).await
    }

    /// Commit evidence with a final serialized-writer fence.
    pub async fn commit_verified_with_fence<F>(
        &self,
        sealed: SealedMutation,
        validate: F,
        commit_fence: impl Fn() -> Result<(), StoreError> + Send + Sync + 'static,
    ) -> Result<StoreCommitResult, StoreError>
    where
        F: FnOnce(&MutationSealBody) -> Result<(), StoreError>,
    {
        let opened = self.seal.open(sealed)?;
        validate(opened.body())?;
        self.writer
            .commit_with_fence(opened, Some(Arc::new(commit_fence)))
            .await
    }
}

fn validate_acceptor(
    identity: &StoreIdentity,
    acceptor: &MutationSealAcceptor,
) -> Result<(), StoreError> {
    if identity.store_epoch == 0 {
        return Err(transaction::integrity("store-epoch-invalid").with_store_slot(identity.slot()));
    }
    if let Err(mismatch) = acceptor.diagnose(&identity.seal_identity()) {
        return Err(transaction::integrity(mismatch.reason_code()).with_store_slot(identity.slot()));
    }
    if acceptor.declared_slot() != identity.slot() {
        return Err(
            transaction::integrity("mutation-seal-acceptor-slot-mismatch")
                .with_store_slot(identity.slot()),
        );
    }
    Ok(())
}

/// Publish marker bytes for a storage owner before initial database creation.
pub fn write_provisioning_marker(
    marker: &mut File,
    identity: &StoreIdentity,
) -> Result<(), StoreError> {
    let slot = identity.slot();
    validate_owned_file(marker).map_err(|error| error.with_store_slot(slot))?;
    if marker
        .metadata()
        .map_err(transaction::integrity)
        .map_err(|error| error.with_store_slot(slot))?
        .len()
        != 0
    {
        return Err(transaction::integrity("provision-marker-not-empty").with_store_slot(slot));
    }
    marker
        .write_all(provisioning_marker_bytes(identity).as_bytes())
        .and_then(|()| marker.sync_all())
        .map_err(transaction::durability_failure)
        .map_err(|error| error.with_store_slot(slot))
}

pub(crate) fn validate_provisioning_marker(
    marker: &mut File,
    identity: &StoreIdentity,
) -> Result<(), StoreError> {
    marker
        .seek(SeekFrom::Start(0))
        .map_err(transaction::integrity)?;
    let mut bytes = Vec::new();
    marker
        .take(4096)
        .read_to_end(&mut bytes)
        .map_err(transaction::integrity)?;
    if bytes != provisioning_marker_bytes(identity).as_bytes() {
        return Err(transaction::quarantined_reason(
            "provision-marker-identity-mismatch",
        ));
    }
    Ok(())
}

fn provisioning_marker_bytes(identity: &StoreIdentity) -> String {
    format!(
        "d2b-redb-store/v2\n{}\n{}\n{}\n{}\n{}\n",
        identity.store_uuid.as_str(),
        identity.zone.as_str(),
        identity.zone_uid.as_str(),
        identity.store_epoch,
        identity.created_at
    )
}

fn validate_owned_file(file: &File) -> Result<(), StoreError> {
    let metadata = file.metadata().map_err(transaction::integrity)?;
    if !metadata.file_type().is_file() {
        return Err(transaction::integrity("database-fd-is-not-regular"));
    }
    if !fcntl_getfd(file)
        .map_err(transaction::integrity)?
        .contains(FdFlags::CLOEXEC)
    {
        return Err(transaction::integrity("database-fd-missing-cloexec"));
    }
    Ok(())
}

/// Atomically receive exactly one database fd with `MSG_CMSG_CLOEXEC`.
pub fn receive_database_file(socket: impl AsFd) -> Result<File, StoreError> {
    let mut payload = [0_u8; 1];
    let mut iov = [rustix::io::IoSliceMut::new(&mut payload)];
    let mut control_bytes = vec![0_u8; rustix::cmsg_space!(ScmRights(2))];
    let mut control = RecvAncillaryBuffer::new(&mut control_bytes);
    let result = recvmsg(socket, &mut iov, &mut control, RecvFlags::CMSG_CLOEXEC)
        .map_err(transaction::integrity)?;
    const MSG_CTRUNC: RecvFlags = RecvFlags::from_bits_retain(0x08);
    if result.bytes != 1 || result.flags.contains(RecvFlags::TRUNC | MSG_CTRUNC) {
        return Err(transaction::integrity("database-fd-frame-invalid"));
    }
    let mut received = Vec::<OwnedFd>::new();
    for message in control.drain() {
        if let RecvAncillaryMessage::ScmRights(files) = message {
            received.extend(files);
        } else {
            return Err(transaction::integrity("database-fd-control-invalid"));
        }
    }
    if received.len() != 1 {
        return Err(transaction::integrity("database-fd-count-invalid"));
    }
    let file = File::from(received.pop().expect("one fd was checked"));
    validate_owned_file(&file)?;
    Ok(file)
}

#[cfg(test)]
mod tests;
