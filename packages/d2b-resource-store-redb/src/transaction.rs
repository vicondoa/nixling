//! Persisted store DTOs, recovery validation, and crash-safe write transactions.

use d2b_audit::{AuditHash, OperationIdentity};
use d2b_contracts_resource::v3::identity::{ReconnectGeneration, STANDARD_RESOURCE_TYPES};
use d2b_contracts_resource::v3::process::PROCESS_RESOURCE_TYPE;
use d2b_contracts_resource::v3::{
    CanonicalJsonValue, ControllerGeneration, FinalizerId, RESOURCE_ENVELOPE_DOMAIN_TAG,
    ResourceEnvelope, ResourceGeneration, ResourceName, ResourceRef, ResourceTypeName, ResourceUid,
    RetryClass, Timestamp, ZoneId, ZoneRevision, canonical_digest,
    is_resource_activation_operation_id,
};
use d2b_resource_store::{
    AdmittedAuthorization, ExpectedRevision, MutationOrdinal, PolicySnapshot,
    ResourceAssignmentFence, ResourceAssignmentScope, ResourceMutationKind, StoreCommitResult,
    StoreError, StoreErrorKind, StoreMutation, StoreOperationContext, StoredResource,
};
use redb::{
    Database, Durability, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition,
};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{DecodedKey, KeyComponent, KeySpace, ValueKind, encode_key, encode_value};
use d2b_resource_store::mutation_seal::OpenedMutation;

pub(crate) const STORE_META: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("store_meta");
pub(crate) const API_SCHEMAS: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("api_schemas");
pub(crate) const RESOURCES: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("resources");
pub(crate) const TYPE_INDEX: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("type_index");
pub(crate) const OWNER_INDEX: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("owner_index");
pub(crate) const PRODUCER_INDEX: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("producer_index");
pub(crate) const CONTROLLER_INDEX: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("controller_index");
pub(crate) const REVISION_LOG: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("revision_log");
pub(crate) const OPERATIONS: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("operations");
pub(crate) const ZONE_LINK_CURSORS: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("zone_link_cursors");

pub(crate) const ALL_TABLES: [TableDefinition<'static, &[u8], &[u8]>; 10] = [
    STORE_META,
    API_SCHEMAS,
    RESOURCES,
    TYPE_INDEX,
    OWNER_INDEX,
    PRODUCER_INDEX,
    CONTROLLER_INDEX,
    REVISION_LOG,
    OPERATIONS,
    ZONE_LINK_CURSORS,
];

pub(crate) const PHYSICAL_SCHEMA_VERSION: u32 = 2;
const STANDARD_SCHEMA_VERSION: &str = "1.0";
const RESOURCE_SCHEMA_DOMAIN_TAG: &str = "d2b:v3:resource-schema";
pub(crate) const UNINTERPRETABLE_REQUEST_DIGEST_REASON: &str =
    "operation-request-digest-uninterpretable";

/// The standard ResourceType catalog bound by a freshly provisioned store.
pub(crate) const STANDARD_SCHEMA_CATALOG: [&str; 19] = STANDARD_RESOURCE_TYPES;
/// Qualified interaction ResourceTypes whose schemas are committed with the
/// production Resource plane and therefore may be persisted in every Zone
/// store.
pub(crate) const QUALIFIED_SCHEMA_CATALOG: [&str; 2] = [
    "display-wayland.d2bus.org.WaylandPolicy",
    "display-wayland.d2bus.org.WaylandSession",
];
/// The complete schema catalog installed in a current physical store.
pub(crate) const INSTALLED_SCHEMA_CATALOG: [&str; 21] = [
    "Zone",
    "ZoneLink",
    "Provider",
    "Role",
    "RoleBinding",
    "Quota",
    "EmergencyPolicy",
    "Host",
    "Guest",
    PROCESS_RESOURCE_TYPE,
    "EphemeralProcess",
    "Volume",
    "Network",
    "Device",
    "User",
    "Credential",
    "Endpoint",
    "ResourceExport",
    "ResourceImport",
    "display-wayland.d2bus.org.WaylandPolicy",
    "display-wayland.d2bus.org.WaylandSession",
];

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WaylandPolicySpec {
    allow_globals: Vec<String>,
    deny_globals: Vec<String>,
    max_versions: std::collections::BTreeMap<String, u32>,
    dmabuf_allow: Vec<String>,
    dmabuf_deny: Vec<String>,
    defaults: WaylandPolicyDefaults,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WaylandPolicyDefaults {
    accelerated_rendering: WaylandPolicyDecision,
    clipboard_boundary: WaylandClipboardBoundary,
    high_risk: WaylandPolicyDecision,
    app_defaults: WaylandPolicyDecision,
    off_defaults: WaylandPolicyDecision,
    unclassified: WaylandPolicyDecision,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum WaylandPolicyDecision {
    Allow,
    Deny,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum WaylandClipboardBoundary {
    Deny,
    Virtualize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WaylandSessionSpec {
    guest_ref: ResourceRef,
    host_ref: ResourceRef,
    user_ref: ResourceRef,
    policy_ref: ResourceRef,
    identity: WaylandDisplayIdentity,
    cross_domain_trusted: bool,
    #[serde(default)]
    reconnect_generation: Option<u64>,
    virgl_video: bool,
    filter: WaylandFilterSpec,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WaylandDisplayIdentity {
    label: String,
    active_color: String,
    inactive_color: String,
    urgent_color: String,
    border_enabled: bool,
    border_width: u32,
    label_enabled: bool,
    label_text: Option<String>,
    label_position: WaylandLabelPosition,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum WaylandLabelPosition {
    TopLeft,
    TopCenter,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WaylandFilterSpec {
    allow_globals: Vec<String>,
    deny_globals: Vec<String>,
    max_versions: std::collections::BTreeMap<String, u32>,
    dmabuf_allow: Vec<String>,
    dmabuf_deny: Vec<String>,
    debug_logging: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoreMeta {
    pub store_uuid: String,
    pub zone_name: String,
    pub zone_uid: String,
    #[serde(default = "default_store_epoch")]
    pub store_epoch: u64,
    pub created_at: String,
    pub schema_version: u32,
    pub current_revision: u64,
    pub compaction_floor: u64,
    pub active_configuration_revision: u64,
    pub policy_revision: u64,
    pub api_catalog_revision: u64,
    pub controller_generation: Option<u64>,
    pub clean_shutdown: bool,
    pub backup_generation: u64,
}

fn default_store_epoch() -> u64 {
    1
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResourceRecord {
    pub canonical_json: Vec<u8>,
    pub owner_uid: Option<String>,
    #[serde(default)]
    pub owner_generation: Option<u64>,
    pub controller_binding_id: String,
    pub payload_digest: String,
    #[serde(default)]
    pub assignment: Option<AssignmentRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AssignmentRecord {
    pub resource_uid: String,
    pub resource_revision: u64,
    pub provider_generation: u64,
    pub controller_generation: u64,
    pub controller_role: String,
    pub target: String,
    pub session_generation: u64,
    pub epoch: u64,
    pub phase: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnerIndexRecord {
    pub resource_type: String,
    pub resource_name: String,
    pub latest_revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProducerIndexRecord {
    pub endpoint_type: String,
    pub endpoint_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OperationRecord {
    pub request_digest: String,
    pub resource_uids: Vec<String>,
    pub resources: Vec<OperationResourceRecord>,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    pub accepted_revision: u64,
    pub finished_revision: u64,
    /// A durable post-commit audit outbox entry.
    ///
    /// Older operation rows omit this field.  A pending value is cleared only
    /// after the corresponding audit records have reached their sink.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_outbox: Option<AuditOutboxRecord>,
    /// A typed Core authority lifecycle row stored in the same operation
    /// ledger. The payload is opaque to redb and validated by Core.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<AuthorityOperationStorage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AuthorityOperationStorage {
    pub payload: Vec<u8>,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OperationResourceRecord {
    pub resource_type: String,
    pub resource_name: String,
    pub zone: String,
    pub canonical_json: Vec<u8>,
    pub payload_digest: String,
}

/// The metadata needed to reconstruct a resource-mutation audit record after
/// a daemon restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AuditOutboxRecord {
    pub zone: String,
    pub operation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_identity: Option<OperationIdentity>,
    pub correlation_id: String,
    pub subject_digest: String,
    pub policy_revision: u64,
    pub resulting_revision: u64,
    /// Whether a matching broker durability record is required before this
    /// outbox may be acknowledged.
    #[serde(default)]
    pub requires_broker: bool,
    /// Store-derived marker authorizing deferred broker evidence for a
    /// successful system-core activation operation.
    #[serde(default)]
    pub defer_broker_evidence: bool,
    pub mutations: Vec<AuditOutboxMutation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AuditOutboxMutation {
    pub verb: String,
    pub resource_type: String,
    #[serde(default)]
    pub resource_uid: Option<String>,
    pub target_digest: String,
    pub generation: u64,
    pub expected_revision: u64,
    #[serde(default)]
    pub mutation_id: String,
    #[serde(default)]
    pub ordinal: u32,
    #[serde(default)]
    pub timestamp_ms: u64,
    #[serde(default = "default_audit_outcome")]
    pub outcome: String,
    #[serde(default)]
    pub error_code: Option<String>,
    /// Hash that preceded this mutation's durable audit record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_hash: Option<AuditHash>,
    /// Durable hash of this mutation's audit record, when already appended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_hash: Option<AuditHash>,
}

fn default_audit_outcome() -> String {
    "ok".to_owned()
}

/// Closed resource mutation event persisted in the revision log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChangeEvent {
    Created,
    SpecUpdated,
    StatusUpdated,
    MetadataUpdated,
    FinalizersUpdated,
    DeletionRequested,
    Deleted,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
struct ChangeIdentity(String);

impl ChangeIdentity {
    fn parse(value: impl Into<String>) -> Result<Self, StoreError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 512
            || value.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(integrity("change-identity-invalid"));
        }
        Ok(Self(value))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Debug for ChangeIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ChangeIdentity(<redacted>)")
    }
}

/// One validated entry in a bounded revision batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChangeEntry {
    ordinal: u32,
    resource_type: ResourceTypeName,
    resource_name: ResourceName,
    resource_uid: ResourceUid,
    event: ChangeEvent,
    old_generation: Option<ResourceGeneration>,
    new_generation: Option<ResourceGeneration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_owner_ref: Option<ResourceRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_owner_uid: Option<ResourceUid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner_ref: Option<ResourceRef>,
    owner_uid: Option<ResourceUid>,
    payload_digest: String,
    canonical_resource: Option<Vec<u8>>,
    operation_id: ChangeIdentity,
    correlation_id: ChangeIdentity,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangeEntryWire {
    ordinal: u32,
    resource_type: ResourceTypeName,
    resource_name: ResourceName,
    resource_uid: ResourceUid,
    event: ChangeEvent,
    old_generation: Option<ResourceGeneration>,
    new_generation: Option<ResourceGeneration>,
    #[serde(default)]
    previous_owner_ref: Option<ResourceRef>,
    #[serde(default)]
    previous_owner_uid: Option<ResourceUid>,
    #[serde(default)]
    owner_ref: Option<ResourceRef>,
    owner_uid: Option<ResourceUid>,
    payload_digest: String,
    canonical_resource: Option<Vec<u8>>,
    operation_id: ChangeIdentity,
    correlation_id: ChangeIdentity,
}

impl<'de> Deserialize<'de> for ChangeEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ChangeEntryWire::deserialize(deserializer)?;
        let entry = Self::new(
            wire.ordinal,
            wire.resource_type,
            wire.resource_name,
            wire.resource_uid,
            wire.event,
            wire.old_generation,
            wire.new_generation,
            wire.owner_uid,
            wire.payload_digest,
            wire.canonical_resource,
            wire.operation_id.0,
            wire.correlation_id.0,
        )
        .map_err(serde::de::Error::custom)?;
        Ok(entry.with_owners(
            wire.previous_owner_ref,
            wire.previous_owner_uid,
            wire.owner_ref,
        ))
    }
}

impl ChangeEntry {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        ordinal: u32,
        resource_type: ResourceTypeName,
        resource_name: ResourceName,
        resource_uid: ResourceUid,
        event: ChangeEvent,
        old_generation: Option<ResourceGeneration>,
        new_generation: Option<ResourceGeneration>,
        owner_uid: Option<ResourceUid>,
        payload_digest: String,
        canonical_resource: Option<Vec<u8>>,
        operation_id: String,
        correlation_id: String,
    ) -> Result<Self, StoreError> {
        if usize::try_from(ordinal).map_or(true, |ordinal| {
            ordinal
                >= crate::actor::GROUP_COMMIT_MAX * d2b_contracts_resource::v3::MAX_BATCH_MUTATIONS
        }) || !valid_digest(&payload_digest)
        {
            return Err(integrity("change-entry-invalid"));
        }
        Ok(Self {
            ordinal,
            resource_type,
            resource_name,
            resource_uid,
            event,
            old_generation,
            new_generation,
            previous_owner_ref: None,
            previous_owner_uid: None,
            owner_ref: None,
            owner_uid,
            payload_digest,
            canonical_resource,
            operation_id: ChangeIdentity::parse(operation_id)?,
            correlation_id: ChangeIdentity::parse(correlation_id)?,
        })
    }

    pub(crate) fn with_owners(
        mut self,
        previous_owner_ref: Option<ResourceRef>,
        previous_owner_uid: Option<ResourceUid>,
        owner_ref: Option<ResourceRef>,
    ) -> Self {
        self.previous_owner_ref = previous_owner_ref;
        self.previous_owner_uid = previous_owner_uid;
        self.owner_ref = owner_ref;
        self
    }

    pub const fn ordinal(&self) -> u32 {
        self.ordinal
    }

    pub const fn resource_type(&self) -> &ResourceTypeName {
        &self.resource_type
    }

    pub const fn resource_name(&self) -> &ResourceName {
        &self.resource_name
    }

    pub const fn resource_uid(&self) -> &ResourceUid {
        &self.resource_uid
    }

    pub fn owner_uid(&self) -> Option<&ResourceUid> {
        self.owner_uid.as_ref()
    }

    pub fn previous_owner_ref(&self) -> Option<&ResourceRef> {
        self.previous_owner_ref.as_ref()
    }

    pub fn previous_owner_uid(&self) -> Option<&ResourceUid> {
        self.previous_owner_uid.as_ref()
    }

    pub fn owner_ref(&self) -> Option<&ResourceRef> {
        self.owner_ref.as_ref()
    }

    pub const fn old_generation(&self) -> Option<ResourceGeneration> {
        self.old_generation
    }

    pub const fn new_generation(&self) -> Option<ResourceGeneration> {
        self.new_generation
    }

    pub fn canonical_resource(&self) -> Option<&[u8]> {
        self.canonical_resource.as_deref()
    }

    pub fn operation_id(&self) -> &str {
        self.operation_id.as_str()
    }

    pub fn correlation_id(&self) -> &str {
        self.correlation_id.as_str()
    }

    pub const fn event(&self) -> ChangeEvent {
        self.event
    }
}

/// One validated, nonempty revision batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChangeBatch {
    revision: ZoneRevision,
    entries: Vec<ChangeEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangeBatchWire {
    revision: ZoneRevision,
    entries: Vec<ChangeEntry>,
}

impl<'de> Deserialize<'de> for ChangeBatch {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ChangeBatchWire::deserialize(deserializer)?;
        Self::new(wire.revision, wire.entries).map_err(serde::de::Error::custom)
    }
}

impl ChangeBatch {
    pub(crate) fn new(
        revision: ZoneRevision,
        entries: Vec<ChangeEntry>,
    ) -> Result<Self, StoreError> {
        let max = crate::actor::GROUP_COMMIT_MAX * d2b_contracts_resource::v3::MAX_BATCH_MUTATIONS;
        if revision.get() == 0
            || entries.len() > max
            || entries
                .iter()
                .enumerate()
                .any(|(ordinal, entry)| entry.ordinal as usize != ordinal)
        {
            return Err(integrity("change-batch-invalid"));
        }
        Ok(Self { revision, entries })
    }

    pub const fn revision(&self) -> ZoneRevision {
        self.revision
    }

    pub fn entries(&self) -> &[ChangeEntry] {
        &self.entries
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommittedGroup {
    pub results: Vec<Result<StoreCommitResult, StoreError>>,
    pub batch: Option<ChangeBatch>,
    pub resulting_revision: u64,
}

pub(crate) struct VerifiedWrite {
    authorization: AdmittedAuthorization,
    policy_snapshot: PolicySnapshot,
    operation: StoreOperationContext,
    mutations: Vec<VerifiedPreparedMutation>,
}

pub(crate) struct VerifiedPreparedMutation {
    mutation: StoreMutation,
    resource_uid: Option<ResourceUid>,
    prepared_payload_digest: Option<String>,
}

fn audit_outbox_for(
    verified: &VerifiedWrite,
    resources: &[StoredResource],
    resulting_revision: u64,
    timestamp_ms: u64,
) -> Result<AuditOutboxRecord, StoreError> {
    if verified.mutations.len() != resources.len() {
        return Err(integrity("audit-outbox-resource-count-mismatch"));
    }
    let mutations = verified
        .mutations
        .iter()
        .zip(resources)
        .enumerate()
        .map(|(ordinal, (prepared, resource))| {
            let mutation = prepared.mutation();
            let resource_type = resource.resource_ref.resource_type().as_str().to_owned();
            let target_digest = crate::audit::opaque_digest(&mutation.target.to_canonical_string());
            AuditOutboxMutation {
                verb: mutation_audit_verb(mutation.kind).to_owned(),
                resource_type,
                resource_uid: Some(resource.uid.as_str().to_owned()),
                target_digest,
                generation: resource.generation.get(),
                expected_revision: match mutation.expected {
                    ExpectedRevision::CreateAbsent => 0,
                    ExpectedRevision::Exact(revision) => revision.get(),
                },
                mutation_id: audit_mutation_id(
                    &verified.operation.operation_id,
                    ordinal as u32,
                    resulting_revision,
                ),
                ordinal: ordinal as u32,
                timestamp_ms,
                outcome: "ok".to_owned(),
                error_code: None,
                previous_hash: None,
                record_hash: None,
            }
        })
        .collect::<Vec<_>>();
    let requires_broker = requires_broker_audit_for_write(verified);
    Ok(AuditOutboxRecord {
        zone: verified.authorization.zone.as_str().to_owned(),
        operation_id: verified.operation.operation_id.clone(),
        operation_identity: Some(
            OperationIdentity::derive(&verified.operation.operation_id)
                .map_err(|_| integrity("audit-operation-identity-invalid"))?,
        ),
        correlation_id: verified.operation.correlation_id.clone(),
        subject_digest: crate::audit::opaque_digest(
            &verified.authorization.subject_ref.to_canonical_string(),
        ),
        policy_revision: verified.policy_snapshot.policy_revision,
        resulting_revision,
        requires_broker,
        defer_broker_evidence: requires_broker
            && is_trusted_activation_subject(
                &verified.authorization.subject_ref,
                &verified.operation.operation_id,
            ),
        mutations,
    })
}

fn audit_outbox_for_failure(
    verified: &VerifiedWrite,
    resulting_revision: u64,
    timestamp_ms: u64,
    outcome: &str,
    error_code: &str,
) -> Result<AuditOutboxRecord, StoreError> {
    let mutations = verified
        .mutations
        .iter()
        .enumerate()
        .map(|(ordinal, prepared)| {
            let mutation = prepared.mutation();
            AuditOutboxMutation {
                verb: mutation_audit_verb(mutation.kind).to_owned(),
                resource_type: mutation.target.resource_type().as_str().to_owned(),
                resource_uid: mutation
                    .expected_uid
                    .as_ref()
                    .map(|uid| uid.as_str().to_owned()),
                target_digest: crate::audit::opaque_digest(&mutation.target.to_canonical_string()),
                generation: 0,
                expected_revision: match mutation.expected {
                    ExpectedRevision::CreateAbsent => 0,
                    ExpectedRevision::Exact(revision) => revision.get(),
                },
                mutation_id: audit_mutation_id(
                    &verified.operation.operation_id,
                    ordinal as u32,
                    resulting_revision,
                ),
                ordinal: ordinal as u32,
                timestamp_ms,
                outcome: outcome.to_owned(),
                error_code: Some(error_code.to_owned()),
                previous_hash: None,
                record_hash: None,
            }
        })
        .collect::<Vec<_>>();
    Ok(AuditOutboxRecord {
        zone: verified.authorization.zone.as_str().to_owned(),
        operation_id: verified.operation.operation_id.clone(),
        operation_identity: Some(
            OperationIdentity::derive(&verified.operation.operation_id)
                .map_err(|_| integrity("audit-operation-identity-invalid"))?,
        ),
        correlation_id: verified.operation.correlation_id.clone(),
        subject_digest: crate::audit::opaque_digest(
            &verified.authorization.subject_ref.to_canonical_string(),
        ),
        policy_revision: verified.policy_snapshot.policy_revision,
        resulting_revision,
        requires_broker: requires_broker_audit_for_write(verified),
        defer_broker_evidence: false,
        mutations,
    })
}

const SYSTEM_CORE_SUBJECT_REF: &str = "Provider/system-core";

fn is_trusted_activation_subject(subject_ref: &ResourceRef, operation_id: &str) -> bool {
    subject_ref.to_canonical_string() == SYSTEM_CORE_SUBJECT_REF
        && is_resource_activation_operation_id(operation_id)
}

pub(crate) fn validate_deferred_broker_evidence_marker(
    outbox: &AuditOutboxRecord,
) -> Result<bool, StoreError> {
    if !outbox.defer_broker_evidence {
        return Ok(false);
    }
    if !is_resource_activation_operation_id(&outbox.operation_id)
        || outbox.subject_digest != crate::audit::opaque_digest(SYSTEM_CORE_SUBJECT_REF)
        || !outbox.requires_broker
        || !outbox
            .mutations
            .iter()
            .all(|mutation| mutation.outcome == "ok")
    {
        return Err(integrity("audit-deferred-evidence-marker-invalid"));
    }
    Ok(true)
}

fn audit_mutation_id(operation_id: &str, ordinal: u32, revision: u64) -> String {
    canonical_digest(
        "d2b:resource-audit-mutation:v1",
        format!("{operation_id}:{revision}:{ordinal}").as_bytes(),
    )
}

fn requires_broker_audit(resource_type: &str) -> bool {
    matches!(
        resource_type,
        "Zone"
            | "ZoneLink"
            | "Provider"
            | "Role"
            | "RoleBinding"
            | "Quota"
            | "EmergencyPolicy"
            | "Credential"
            | "ResourceExport"
            | "ResourceImport"
    )
}

fn is_system_core_subject(subject_ref: &ResourceRef) -> bool {
    subject_ref.to_canonical_string() == SYSTEM_CORE_SUBJECT_REF
}

fn is_internal_projection(subject_ref: &ResourceRef, mutation: &StoreMutation) -> bool {
    is_system_core_subject(subject_ref)
        && matches!(
            mutation.kind,
            ResourceMutationKind::UpdateStatus | ResourceMutationKind::UpdateFinalizers
        )
}

fn requires_broker_audit_for_write(verified: &VerifiedWrite) -> bool {
    verified.mutations.iter().any(|prepared| {
        let mutation = prepared.mutation();
        requires_broker_audit(mutation.target.resource_type().as_str())
            && !is_internal_projection(&verified.authorization.subject_ref, mutation)
    })
}

fn requires_broker_audit_for_outbox(outbox: &AuditOutboxRecord) -> bool {
    let system_core_subject =
        outbox.subject_digest == crate::audit::opaque_digest(SYSTEM_CORE_SUBJECT_REF);
    outbox.mutations.iter().any(|mutation| {
        requires_broker_audit(mutation.resource_type.as_str())
            && !(system_core_subject
                && matches!(
                    mutation.verb.as_str(),
                    "update-status" | "update-finalizers"
                ))
    })
}

fn failed_operation_record(
    verified: &VerifiedWrite,
    current_revision: u64,
    error: &StoreError,
) -> Result<OperationRecord, StoreError> {
    let outcome = if error.kind() == StoreErrorKind::AuthorizationDenied {
        "denied"
    } else {
        "error"
    };
    let request_digest = operation_digest(verified).unwrap_or_else(|_| {
        canonical_digest(
            "d2b:failed-resource-operation:v1",
            verified.operation.operation_id.as_bytes(),
        )
    });
    Ok(OperationRecord {
        request_digest,
        resource_uids: Vec::new(),
        resources: Vec::new(),
        outcome: outcome.to_owned(),
        error_code: Some(error.reason_code().to_owned()),
        accepted_revision: current_revision,
        finished_revision: current_revision,
        audit_outbox: Some(audit_outbox_for_failure(
            verified,
            current_revision,
            audit_now_ms(),
            outcome,
            error.reason_code(),
        )?),
        authority: None,
    })
}

fn audit_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
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

struct FinalizedMutation {
    canonical_json: Vec<u8>,
    payload_digest: String,
}

type StagedResourceState = Option<(ResourceRecord, ResourceEnvelope)>;

#[cfg(test)]
pub(crate) fn empty_write_request_for_test(
    sequence: u64,
    principal: &str,
    resource: ResourceRef,
    queue_permit: tokio::sync::OwnedSemaphorePermit,
) -> crate::actor::WriteRequest {
    let (response, _receiver) = tokio::sync::oneshot::channel();
    crate::actor::WriteRequest {
        sequence,
        principal: principal.to_owned(),
        resources: vec![resource],
        mutation: VerifiedWrite {
            authorization: AdmittedAuthorization {
                zone: ZoneId::parse("work").unwrap(),
                subject_ref: ResourceRef::parse("Provider/system-core").unwrap(),
                subject_uid: ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap(),
                targets: Vec::new(),
            },
            policy_snapshot: PolicySnapshot {
                policy_revision: 1,
                api_catalog_revision: 1,
                active_configuration_revision:
                    d2b_contracts_resource::v3::ConfigurationGeneration::new(1).unwrap(),
                controller_generation: None,
            },
            operation: StoreOperationContext {
                operation_id: format!("op-{sequence}"),
                idempotency_key: None,
                correlation_id: format!("corr-{sequence}"),
                trace_id: None,
                deadline_ms: 1,
            },
            mutations: Vec::new(),
        },
        commit_fence: None,
        queue_permit,
        response,
    }
}

impl VerifiedPreparedMutation {
    fn mutation(&self) -> &StoreMutation {
        &self.mutation
    }

    fn resource_uid(&self) -> Option<&ResourceUid> {
        self.resource_uid.as_ref()
    }

    fn prepared_payload_digest(&self) -> Option<&str> {
        self.prepared_payload_digest.as_deref()
    }
}

impl VerifiedWrite {
    pub(crate) fn from_opened(opened: OpenedMutation) -> Self {
        let body = opened.into_body();
        Self {
            authorization: body.authorization,
            policy_snapshot: body.policy_snapshot,
            operation: body.operation,
            mutations: body
                .mutations
                .into_iter()
                .map(|prepared| VerifiedPreparedMutation {
                    mutation: prepared.mutation().clone(),
                    resource_uid: prepared.resource_uid().cloned(),
                    prepared_payload_digest: prepared.payload_digest().map(str::to_owned),
                })
                .collect(),
        }
    }
}

pub(crate) fn initialize(
    database: &Database,
    identity: &crate::StoreIdentity,
) -> Result<(), StoreError> {
    let mut write = database.begin_write().map_err(integrity)?;
    set_full_durability(&mut write)?;
    for definition in ALL_TABLES {
        drop(write.open_table(definition).map_err(integrity)?);
    }
    let mut meta = write.open_table(STORE_META).map_err(integrity)?;
    let key = meta_key();
    if meta.get(key.as_slice()).map_err(integrity)?.is_some() {
        return Err(integrity("store-meta-already-exists"));
    }
    let record = StoreMeta {
        store_uuid: identity.store_uuid.as_str().to_owned(),
        zone_name: identity.zone.as_str().to_owned(),
        zone_uid: identity.zone_uid.as_str().to_owned(),
        store_epoch: identity.store_epoch(),
        created_at: identity.created_at.clone(),
        schema_version: PHYSICAL_SCHEMA_VERSION,
        current_revision: 0,
        compaction_floor: 0,
        active_configuration_revision: identity.revisions.active_configuration_revision.get(),
        policy_revision: identity.revisions.policy_revision,
        api_catalog_revision: identity.revisions.api_catalog_revision,
        controller_generation: identity
            .revisions
            .controller_generation
            .map(ControllerGeneration::get),
        clean_shutdown: false,
        backup_generation: 0,
    };
    let value = encode(ValueKind::StoreMetaScalar, &record)?;
    meta.insert(key.as_slice(), value.as_slice())
        .map_err(integrity)?;
    drop(meta);
    let mut schemas = write.open_table(API_SCHEMAS).map_err(integrity)?;
    for resource_type in INSTALLED_SCHEMA_CATALOG {
        let schema = api_schema_record(resource_type)?;
        let schema_key = api_schema_key(resource_type)?;
        let schema_value = encode(ValueKind::ApiSchemaRecord, &schema)?;
        schemas
            .insert(schema_key.as_slice(), schema_value.as_slice())
            .map_err(integrity)?;
    }
    drop(schemas);
    write.commit().map_err(integrity)
}

/// Idempotently install the current standard schema catalog in a legacy
/// physical-v1 store.
///
/// The first v1 stores predate the catalog rows and therefore have an empty
/// `api_schemas` table.  Only that exact legacy shape is backfilled.  A
/// partial or otherwise populated table is never rewritten because doing so
/// could hide catalog corruption or discard a Provider-owned row.
pub(crate) fn backfill_schema_catalog(database: &Database) -> Result<(), StoreError> {
    {
        let read = database.begin_read().map_err(integrity)?;
        let meta = read_meta(&read)?;
        if meta.schema_version != PHYSICAL_SCHEMA_VERSION {
            return Ok(());
        }

        let table = read.open_table(API_SCHEMAS).map_err(integrity)?;
        let count = table.len().map_err(integrity)?;
        if count == INSTALLED_SCHEMA_CATALOG.len() as u64 {
            return Ok(());
        }
        if count != 0 && count != STANDARD_SCHEMA_CATALOG.len() as u64 {
            return Err(integrity("api-schema-catalog-migration-ambiguous"));
        }
        if count == STANDARD_SCHEMA_CATALOG.len() as u64 {
            let mut types = std::collections::BTreeSet::new();
            for row in table.iter().map_err(integrity)? {
                let (_key, value) = row.map_err(integrity)?;
                let schema: ApiSchemaRecord = decode(ValueKind::ApiSchemaRecord, value.value())?;
                types.insert(schema.resource_type);
            }
            if types.len() != STANDARD_SCHEMA_CATALOG.len()
                || STANDARD_SCHEMA_CATALOG.iter().any(|resource_type| {
                    !types.contains(
                        &ResourceTypeName::parse(*resource_type).expect("standard catalog type"),
                    )
                })
            {
                return Err(integrity("api-schema-catalog-migration-ambiguous"));
            }
        }
    }

    let mut write = database.begin_write().map_err(integrity)?;
    set_full_durability(&mut write)?;
    let meta = read_meta_in_write(&write)?;
    if meta.schema_version != PHYSICAL_SCHEMA_VERSION {
        write.abort().map_err(integrity)?;
        return Ok(());
    }
    let mut schemas = write.open_table(API_SCHEMAS).map_err(integrity)?;
    let count = schemas.len().map_err(integrity)?;
    if count == INSTALLED_SCHEMA_CATALOG.len() as u64 {
        drop(schemas);
        write.abort().map_err(integrity)?;
        return Ok(());
    }
    if count != 0 && count != STANDARD_SCHEMA_CATALOG.len() as u64 {
        return Err(integrity("api-schema-catalog-migration-ambiguous"));
    }
    let resource_types = if count == 0 {
        &INSTALLED_SCHEMA_CATALOG[..]
    } else {
        &QUALIFIED_SCHEMA_CATALOG[..]
    };
    for resource_type in resource_types {
        let schema = api_schema_record(resource_type)?;
        let key = api_schema_key(resource_type)?;
        let value = encode(ValueKind::ApiSchemaRecord, &schema)?;
        schemas
            .insert(key.as_slice(), value.as_slice())
            .map_err(integrity)?;
    }
    drop(schemas);
    write.commit().map_err(integrity)
}

/// Normalize pre-U4 audit outboxes before consistency validation.
///
/// Old valid stores may contain a pending outbox without the typed operation
/// identity or deterministic replay metadata. Missing values are derived from
/// the durable operation key and persisted atomically. Any contradictory or
/// malformed value remains a quarantine-worthy integrity failure. An invalid
/// request digest cannot be normalized because the authoritative request
/// fields needed to prove replay equivalence are not persisted.
pub(crate) fn normalize_audit_outboxes(database: &Database) -> Result<(), StoreError> {
    let read = database.begin_read().map_err(integrity)?;
    let meta = read_meta(&read)?;
    let operations = read.open_table(OPERATIONS).map_err(integrity)?;
    let mut updates = Vec::new();
    for row in operations.iter().map_err(integrity)? {
        let (key, value) = row.map_err(integrity)?;
        let operation_id = operation_id_from_key(key.value())?;
        let mut operation: OperationRecord = decode(ValueKind::OperationRecord, value.value())?;
        if !valid_digest(&operation.request_digest) {
            return Err(quarantined_reason(UNINTERPRETABLE_REQUEST_DIGEST_REASON));
        }
        let Some(outbox) = operation.audit_outbox.as_mut() else {
            continue;
        };
        let expected_identity = OperationIdentity::derive(&operation_id)
            .map_err(|_| integrity("audit-operation-identity-invalid"))?;
        if outbox.operation_id.is_empty() {
            outbox.operation_id = operation_id.clone();
        }
        if outbox.operation_id != operation_id
            || outbox.zone != meta.zone_name
            || outbox.correlation_id.is_empty()
            || outbox.correlation_id.len() > 512
            || outbox
                .correlation_id
                .bytes()
                .any(|byte| byte.is_ascii_control())
            || outbox.mutations.is_empty()
            || outbox.mutations.len() > d2b_contracts_resource::v3::MAX_BATCH_MUTATIONS
        {
            return Err(integrity("audit-outbox-record-invalid"));
        }
        if let Some(identity) = &outbox.operation_identity
            && identity != &expected_identity
        {
            return Err(integrity("audit-operation-identity-mismatch"));
        }
        let mut changed = outbox.operation_identity.is_none();
        outbox.operation_identity = Some(expected_identity);
        if !valid_digest(&outbox.subject_digest) {
            outbox.subject_digest = crate::audit::opaque_digest(&outbox.subject_digest);
            changed = true;
        }
        if outbox.resulting_revision > meta.current_revision {
            return Err(integrity("audit-outbox-revision-invalid"));
        }
        let timestamp_ms = audit_now_ms();
        for (ordinal, mutation) in outbox.mutations.iter_mut().enumerate() {
            if mutation.mutation_id.is_empty() {
                mutation.mutation_id =
                    audit_mutation_id(&operation_id, ordinal as u32, outbox.resulting_revision);
                changed = true;
            } else if !valid_digest(&mutation.mutation_id) {
                mutation.mutation_id = canonical_digest(
                    "d2b:resource-audit-legacy-mutation:v1",
                    mutation.mutation_id.as_bytes(),
                );
                changed = true;
            }
            if !valid_digest(&mutation.target_digest) {
                mutation.target_digest = crate::audit::opaque_digest(&mutation.target_digest);
                changed = true;
            }
            if mutation.timestamp_ms == 0 {
                mutation.timestamp_ms = timestamp_ms;
                changed = true;
            }
            if mutation.ordinal != ordinal as u32 {
                mutation.ordinal = ordinal as u32;
                changed = true;
            }
            if mutation.outcome.is_empty() {
                mutation.outcome = default_audit_outcome();
                changed = true;
            }
        }
        let required_broker =
            outbox.requires_broker || requires_broker_audit_for_outbox(&outbox);
        if required_broker != outbox.requires_broker {
            outbox.requires_broker = required_broker;
            changed = true;
        }
        if changed {
            updates.push((key.value().to_vec(), operation));
        }
    }
    drop(operations);
    drop(read);
    if updates.is_empty() {
        return Ok(());
    }
    let mut write = database.begin_write().map_err(integrity)?;
    set_full_durability(&mut write)?;
    let mut table = write.open_table(OPERATIONS).map_err(integrity)?;
    for (key, operation) in updates {
        let value = encode(ValueKind::OperationRecord, &operation)?;
        table
            .insert(key.as_slice(), value.as_slice())
            .map_err(integrity)?;
    }
    drop(table);
    write.commit().map_err(integrity)
}

/// Normalize legacy audit rows before applying the strict store checks.
///
/// Read-only table and identity admission is completed before any repair. A
/// current schema store can therefore be repaired in place only after it has
/// been admitted, while older supported schemas are normalized before their
/// migration copy is accepted.
pub(crate) fn normalize_and_validate(
    database: &Database,
    identity: &crate::StoreIdentity,
    expected_schema_version: u32,
    require_revision_match: bool,
) -> Result<StoreMeta, StoreError> {
    let admitted_meta = {
        let read = database.begin_read().map_err(integrity)?;
        validate_table_set(&read)?;
        let meta = read_meta(&read)?;
        if meta.schema_version != expected_schema_version {
            return Err(integrity("store-schema-version-mismatch"));
        }
        validate_store_identity(&meta, identity)?;
        if require_revision_match && !revisions_match(&meta, identity.revisions) {
            return Err(integrity("store-identity-mismatch"));
        }
        meta
    };

    if expected_schema_version == PHYSICAL_SCHEMA_VERSION {
        backfill_schema_catalog(database)?;
    }
    normalize_audit_outboxes(database)?;

    let meta = {
        let read = database.begin_read().map_err(integrity)?;
        validate_table_set(&read)?;
        let meta = read_meta(&read)?;
        if meta.schema_version != expected_schema_version {
            return Err(integrity("store-schema-version-mismatch"));
        }
        validate_store_identity(&meta, identity)?;
        meta
    };
    debug_assert_eq!(admitted_meta.schema_version, meta.schema_version);
    if require_revision_match && !revisions_match(&meta, identity.revisions) {
        return Err(integrity("store-identity-mismatch"));
    }
    if meta.schema_version == PHYSICAL_SCHEMA_VERSION {
        validate_consistency(database)?;
    }
    Ok(meta)
}

#[cfg(test)]
pub(crate) fn validate_identity(
    database: &Database,
    identity: &crate::StoreIdentity,
) -> Result<StoreMeta, StoreError> {
    let meta = validate_identity_for_open(database, identity)?;
    if !revisions_match(&meta, identity.revisions) {
        return Err(integrity("store-identity-mismatch"));
    }
    Ok(meta)
}

#[cfg(test)]
pub(crate) fn validate_identity_for_open(
    database: &Database,
    identity: &crate::StoreIdentity,
) -> Result<StoreMeta, StoreError> {
    let read = database.begin_read().map_err(integrity)?;
    validate_table_set(&read)?;
    let table = read.open_table(STORE_META).map_err(integrity)?;
    let bytes = table
        .get(meta_key().as_slice())
        .map_err(integrity)?
        .ok_or_else(|| integrity("store-meta-missing"))?;
    let meta: StoreMeta = decode(ValueKind::StoreMetaScalar, bytes.value())?;
    if meta.schema_version != PHYSICAL_SCHEMA_VERSION {
        return Err(integrity("store-schema-version-mismatch"));
    }
    validate_store_identity(&meta, identity)?;
    Ok(meta)
}

fn validate_table_set(read: &redb::ReadTransaction) -> Result<(), StoreError> {
    if read.list_tables().map_err(integrity)?.count() != ALL_TABLES.len()
        || ALL_TABLES
            .iter()
            .any(|definition| read.open_table(*definition).is_err())
    {
        return Err(integrity("physical-table-set-invalid"));
    }
    Ok(())
}

fn validate_store_identity(
    meta: &StoreMeta,
    identity: &crate::StoreIdentity,
) -> Result<(), StoreError> {
    if meta.store_uuid != identity.store_uuid.as_str()
        || meta.zone_name != identity.zone.as_str()
        || meta.zone_uid != identity.zone_uid.as_str()
        || meta.store_epoch == 0
        || meta.store_epoch != identity.store_epoch()
        || meta.created_at != identity.created_at
        || meta.compaction_floor > meta.current_revision
    {
        return Err(integrity("store-identity-mismatch"));
    }
    Ok(())
}

pub(crate) fn validate_consistency(database: &Database) -> Result<(), StoreError> {
    let read = database.begin_read().map_err(integrity)?;
    let meta = read_meta(&read)?;
    let revisions = read.open_table(REVISION_LOG).map_err(integrity)?;
    let mut revision_count = 0_u64;
    for row in revisions.iter().map_err(integrity)? {
        let (key, value) = row.map_err(integrity)?;
        let decoded = DecodedKey::decode(key.value()).map_err(integrity)?;
        let [crate::DecodedKeyComponent::U64(revision)] = decoded.components() else {
            return Err(integrity("revision-key-shape-invalid"));
        };
        if *revision <= meta.compaction_floor || *revision > meta.current_revision {
            return Err(integrity("revision-log-range-invalid"));
        }
        let batch: ChangeBatch = decode(ValueKind::ChangeBatch, value.value())?;
        if batch.revision().get() != *revision {
            return Err(integrity("revision-log-key-value-mismatch"));
        }
        validate_change_batch(&batch, &meta)?;
        revision_count += 1;
    }
    if revision_count != meta.current_revision.saturating_sub(meta.compaction_floor) {
        return Err(integrity("revision-log-not-contiguous"));
    }

    let resources = read.open_table(RESOURCES).map_err(integrity)?;
    let types = read.open_table(TYPE_INDEX).map_err(integrity)?;
    let owners = read.open_table(OWNER_INDEX).map_err(integrity)?;
    let producers = read.open_table(PRODUCER_INDEX).map_err(integrity)?;
    let controllers = read.open_table(CONTROLLER_INDEX).map_err(integrity)?;
    let mut expected_owners = 0_u64;
    let mut expected_producers = 0_u64;
    for row in resources.iter().map_err(integrity)? {
        let (key, value) = row.map_err(integrity)?;
        let resource_ref = resource_ref_from_key(key.value())?;
        let record: ResourceRecord = decode(ValueKind::ResourceRecord, value.value())?;
        let envelope = ResourceEnvelope::from_json(&record.canonical_json)
            .map_err(|_| integrity("stored-resource-envelope-invalid"))?;
        if envelope.resource_type() != resource_ref.resource_type()
            || envelope.metadata().name() != resource_ref.name()
            || envelope.metadata().zone().as_str() != meta.zone_name
            || envelope.metadata().revision().get() > meta.current_revision
            || envelope.canonical_bytes().map_err(integrity)? != record.canonical_json
            || envelope.digest().map_err(integrity)? != record.payload_digest
        {
            return Err(integrity("stored-resource-identity-invalid"));
        }
        let uid = envelope.metadata().uid();
        let expected_owner_uid = envelope
            .metadata()
            .owner_ref()
            .map(|owner| resolve_uid_in_read(&types, owner))
            .transpose()?
            .map(|uid| uid.as_str().to_owned());
        if record.owner_uid != expected_owner_uid
            || record.controller_binding_id
                != controller_binding_id(&envelope, record.assignment.as_ref())
        {
            return Err(integrity("stored-resource-derived-fields-invalid"));
        }
        if let Some(assignment) = &record.assignment {
            if assignment.resource_uid != uid.as_str()
                || assignment.resource_revision != envelope.metadata().revision().get()
                || assignment.provider_generation == 0
                || assignment.controller_generation == 0
                || assignment.session_generation == 0
                || assignment.epoch == 0
                || !matches!(
                    assignment.phase.as_str(),
                    "assigned" | "draining" | "revoked" | "stale" | "quarantined" | "released"
                )
                || ResourceRef::parse(&assignment.controller_role).map_or(true, |role| {
                    role.resource_type().as_str() != PROCESS_RESOURCE_TYPE
                })
                || ResourceRef::parse(&assignment.target).is_err()
            {
                return Err(integrity("stored-assignment-invalid"));
            }
        }
        let type_value = types
            .get(type_index_key(&resource_ref)?.as_slice())
            .map_err(integrity)?
            .ok_or_else(|| integrity("type-index-entry-missing"))?;
        let indexed_uid: String = decode(ValueKind::TypeIndexRecord, type_value.value())?;
        if indexed_uid != uid.as_str() {
            return Err(integrity("type-index-entry-mismatch"));
        }
        let controller_key = encode_key(
            KeySpace::ControllerIndex,
            &[
                KeyComponent::Text(&record.controller_binding_id),
                KeyComponent::Text(resource_ref.resource_type().as_str()),
                KeyComponent::Text(resource_ref.name().as_str()),
            ],
        )
        .map_err(integrity)?;
        let controller_value = controllers
            .get(controller_key.as_bytes())
            .map_err(integrity)?
            .ok_or_else(|| integrity("controller-index-entry-missing"))?;
        let controller_uid: String =
            decode(ValueKind::ControllerIndexRecord, controller_value.value())?;
        if controller_uid != uid.as_str() {
            return Err(integrity("controller-index-entry-mismatch"));
        }
        if let Some(owner_uid) = &record.owner_uid {
            expected_owners += 1;
            let owner_key = encode_key(
                KeySpace::OwnerIndex,
                &[
                    KeyComponent::Text(owner_uid),
                    KeyComponent::Text(uid.as_str()),
                ],
            )
            .map_err(integrity)?;
            let owner_value = owners
                .get(owner_key.as_bytes())
                .map_err(integrity)?
                .ok_or_else(|| integrity("owner-index-entry-missing"))?;
            let owner_record: OwnerIndexRecord =
                decode(ValueKind::OwnerIndexRecord, owner_value.value())?;
            if owner_record.resource_type != resource_ref.resource_type().as_str()
                || owner_record.resource_name != resource_ref.name().as_str()
                || owner_record.latest_revision != envelope.metadata().revision().get()
            {
                return Err(integrity("owner-index-entry-mismatch"));
            }
        }
        if let Some(producer_ref) = endpoint_producer(&envelope)? {
            expected_producers += 1;
            let producer_uid = types
                .get(type_index_key(&producer_ref)?.as_slice())
                .map_err(integrity)?
                .ok_or_else(|| integrity("producer-resource-missing"))?;
            let producer_uid: String = decode(ValueKind::TypeIndexRecord, producer_uid.value())?;
            let producer_key = encode_key(
                KeySpace::ProducerIndex,
                &[
                    KeyComponent::Text(&producer_uid),
                    KeyComponent::Text(uid.as_str()),
                ],
            )
            .map_err(integrity)?;
            let producer_value = producers
                .get(producer_key.as_bytes())
                .map_err(integrity)?
                .ok_or_else(|| integrity("producer-index-entry-missing"))?;
            let producer_record: ProducerIndexRecord =
                decode(ValueKind::ProducerIndexRecord, producer_value.value())?;
            if producer_record.endpoint_type != resource_ref.resource_type().as_str()
                || producer_record.endpoint_name != resource_ref.name().as_str()
            {
                return Err(integrity("producer-index-entry-mismatch"));
            }
        }
    }
    let resource_count = resources.len().map_err(integrity)?;
    if types.len().map_err(integrity)? != resource_count
        || controllers.len().map_err(integrity)? != resource_count
        || owners.len().map_err(integrity)? != expected_owners
        || producers.len().map_err(integrity)? != expected_producers
    {
        return Err(integrity("resource-index-count-mismatch"));
    }
    let operations = read.open_table(OPERATIONS).map_err(integrity)?;
    for row in operations.iter().map_err(integrity)? {
        let (key, value) = row.map_err(integrity)?;
        let operation_id = operation_id_from_key(key.value())?;
        let operation: OperationRecord = decode(ValueKind::OperationRecord, value.value())?;
        if operation.request_digest.is_empty()
            || !valid_digest(&operation.request_digest)
            || !matches!(operation.outcome.as_str(), "committed" | "denied" | "error")
            || (operation.outcome == "committed" && operation.error_code.is_some())
            || operation.error_code.as_deref().is_some_and(|code| {
                code.is_empty()
                    || code.len() > 128
                    || !code.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'-' | b'_' | b'.')
                    })
            })
            || (operation.outcome == "committed"
                && operation.resources.len() != operation.resource_uids.len())
            || (operation.outcome != "committed"
                && (!operation.resources.is_empty() || !operation.resource_uids.is_empty()))
            || operation.accepted_revision > operation.finished_revision
            || operation.finished_revision > meta.current_revision
        {
            return Err(integrity("operation-revision-invalid"));
        }
        for (resource, uid) in operation.resources.iter().zip(&operation.resource_uids) {
            let resource_ref = ResourceRef::parse(&format!(
                "{}/{}",
                resource.resource_type, resource.resource_name
            ))
            .map_err(integrity)?;
            let zone = ZoneId::parse(&resource.zone).map_err(integrity)?;
            let stored = operation_resource(resource)?;
            if stored.resource_ref != resource_ref
                || stored.zone != zone
                || stored.uid.as_str() != uid
                || !valid_digest(&resource.payload_digest)
            {
                return Err(integrity("operation-resource-invalid"));
            }
        }
        if operation_id.is_empty() {
            return Err(integrity("operation-key-invalid"));
        }
        if let Some(outbox) = &operation.audit_outbox {
            validate_audit_outbox(outbox, &operation_id, &meta)?;
        }
        if let Some(authority) = &operation.authority {
            validate_authority_operation(authority)?;
            if !operation.resources.is_empty() || !operation.resource_uids.is_empty() {
                return Err(integrity("authority-operation-resource-mix"));
            }
        }
    }

    fn validate_authority_operation(
        authority: &AuthorityOperationStorage,
    ) -> Result<(), StoreError> {
        if authority.payload.is_empty() || authority.payload.len() > 64 * 1024 {
            return Err(integrity("authority-operation-payload-invalid"));
        }
        if !matches!(
            authority.state.as_str(),
            "pending"
                | "effect-confirmed"
                | "effect-retryable"
                | "effect-terminal"
                | "closing"
                | "closed"
                | "released"
        ) {
            return Err(integrity("authority-operation-state-invalid"));
        }
        Ok(())
    }
    validate_api_schemas(&read, &meta)?;
    validate_zone_link_cursors(&read, &meta)?;
    Ok(())
}

pub(crate) fn resource_ref_from_key(bytes: &[u8]) -> Result<ResourceRef, StoreError> {
    let decoded = DecodedKey::decode(bytes).map_err(integrity)?;
    if decoded.key_space() != KeySpace::Resources {
        return Err(integrity("resource-key-space-invalid"));
    }
    let [
        crate::DecodedKeyComponent::Text(resource_type),
        crate::DecodedKeyComponent::Text(resource_name),
    ] = decoded.components()
    else {
        return Err(integrity("resource-key-shape-invalid"));
    };
    ResourceRef::parse(&format!("{resource_type}/{resource_name}")).map_err(integrity)
}

fn resolve_uid_in_read(
    types: &impl ReadableTable<&'static [u8], &'static [u8]>,
    resource_ref: &ResourceRef,
) -> Result<ResourceUid, StoreError> {
    let value = types
        .get(type_index_key(resource_ref)?.as_slice())
        .map_err(integrity)?
        .ok_or_else(|| integrity("owner-resource-missing"))?;
    let uid: String = decode(ValueKind::TypeIndexRecord, value.value())?;
    ResourceUid::parse(uid).map_err(integrity)
}

fn operation_id_from_key(bytes: &[u8]) -> Result<String, StoreError> {
    let decoded = DecodedKey::decode(bytes).map_err(integrity)?;
    if decoded.key_space() != KeySpace::Operations {
        return Err(integrity("operation-key-space-invalid"));
    }
    let [crate::DecodedKeyComponent::Text(operation_id)] = decoded.components() else {
        return Err(integrity("operation-key-shape-invalid"));
    };
    Ok((*operation_id).to_owned())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApiSchemaRecord {
    #[serde(rename = "resourceType", alias = "x-d2b-resource-type")]
    resource_type: ResourceTypeName,
    #[serde(rename = "schemaDigest", alias = "x-d2b-schema-digest", default)]
    schema_digest: String,
    #[serde(rename = "schemaVersion", default)]
    schema_version: String,
    #[serde(rename = "validatorFingerprint", alias = "x-d2b-schema-fingerprint")]
    validator_fingerprint: String,
    #[serde(rename = "additionalProperties", default)]
    additional_properties: Option<bool>,
    #[serde(default)]
    properties: std::collections::BTreeMap<String, CanonicalJsonValue>,
    #[serde(default)]
    required: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ZoneLinkCursorRecord {
    link_epoch: u64,
    sent: u64,
    acked: u64,
    received: u64,
    applied: u64,
}

fn schema_digest_for_type(resource_type: &str) -> Result<String, StoreError> {
    if !INSTALLED_SCHEMA_CATALOG.contains(&resource_type) {
        return Err(integrity("api-schema-resource-type-unknown"));
    }
    let descriptor = serde_json::json!({
        "resourceType": resource_type,
        "schemaVersion": STANDARD_SCHEMA_VERSION,
        "validator": "d2b-resource-store-redb/standard",
    });
    let bytes = d2b_contracts_resource::v3::canonical_json_bytes(&descriptor).map_err(integrity)?;
    Ok(canonical_digest(RESOURCE_SCHEMA_DOMAIN_TAG, &bytes))
}

fn api_schema_key(resource_type: &str) -> Result<Vec<u8>, StoreError> {
    let digest = schema_digest_for_type(resource_type)?;
    encode_key(KeySpace::ApiSchemas, &[KeyComponent::Text(&digest)])
        .map(|key| key.into_bytes())
        .map_err(integrity)
}

fn api_schema_record(resource_type: &str) -> Result<ApiSchemaRecord, StoreError> {
    let resource_type = ResourceTypeName::parse(resource_type).map_err(integrity)?;
    let schema_digest = schema_digest_for_type(resource_type.as_str())?;
    Ok(ApiSchemaRecord {
        resource_type,
        schema_digest: schema_digest.clone(),
        schema_version: STANDARD_SCHEMA_VERSION.to_owned(),
        validator_fingerprint: schema_digest,
        additional_properties: Some(false),
        properties: std::collections::BTreeMap::new(),
        required: Vec::new(),
    })
}

fn validate_audit_outbox(
    outbox: &AuditOutboxRecord,
    operation_id: &str,
    meta: &StoreMeta,
) -> Result<(), StoreError> {
    let expected_identity = OperationIdentity::derive(&outbox.operation_id)
        .map_err(|_| integrity("audit-operation-identity-invalid"))?;
    if outbox.operation_identity.as_ref() != Some(&expected_identity)
        || outbox.zone != meta.zone_name
        || outbox.operation_id != operation_id
        || outbox.correlation_id.is_empty()
        || outbox.correlation_id.len() > 512
        || outbox
            .correlation_id
            .bytes()
            .any(|byte| byte.is_ascii_control())
        || !valid_digest(&outbox.subject_digest)
        || outbox.resulting_revision > meta.current_revision
        || outbox.mutations.is_empty()
        || outbox.mutations.len() > d2b_contracts_resource::v3::MAX_BATCH_MUTATIONS
    {
        return Err(integrity("audit-outbox-record-invalid"));
    }
    for mutation in &outbox.mutations {
        if !matches!(
            mutation.verb.as_str(),
            "create"
                | "update-spec"
                | "update-status"
                | "update-metadata"
                | "update-finalizers"
                | "delete"
        ) || ResourceTypeName::parse(mutation.resource_type.clone()).is_err()
            || mutation
                .resource_uid
                .as_ref()
                .is_some_and(|uid| ResourceUid::parse(uid.clone()).is_err())
            || !valid_digest(&mutation.target_digest)
            || mutation.mutation_id.is_empty()
            || !valid_digest(&mutation.mutation_id)
            || mutation.ordinal >= d2b_contracts_resource::v3::MAX_BATCH_MUTATIONS as u32
            || mutation.timestamp_ms == 0
            || !matches!(mutation.outcome.as_str(), "ok" | "denied" | "error")
            || mutation.error_code.as_deref().is_some_and(|code| {
                code.is_empty()
                    || code.len() > 128
                    || !code.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'-' | b'_' | b'.')
                    })
            })
        {
            return Err(integrity("audit-outbox-mutation-invalid"));
        }
    }
    validate_deferred_broker_evidence_marker(outbox)?;
    Ok(())
}

pub(crate) fn api_schema_key_for_type(
    resource_type: &ResourceTypeName,
) -> Result<Vec<u8>, StoreError> {
    api_schema_key(resource_type.as_str())
}

pub(crate) fn api_schema_digest_for_type(
    resource_type: &ResourceTypeName,
) -> Result<String, StoreError> {
    schema_digest_for_type(resource_type.as_str())
}

fn validate_api_schemas(read: &redb::ReadTransaction, _meta: &StoreMeta) -> Result<(), StoreError> {
    let table = read.open_table(API_SCHEMAS).map_err(integrity)?;
    let mut resource_types = std::collections::BTreeSet::new();
    for row in table.iter().map_err(integrity)? {
        let (key, value) = row.map_err(integrity)?;
        let decoded = DecodedKey::decode(key.value()).map_err(integrity)?;
        if decoded.key_space() != KeySpace::ApiSchemas {
            return Err(integrity("api-schema-key-space-invalid"));
        }
        let [crate::DecodedKeyComponent::Text(schema_key)] = decoded.components() else {
            return Err(integrity("api-schema-key-shape-invalid"));
        };
        let schema: ApiSchemaRecord = decode(ValueKind::ApiSchemaRecord, value.value())?;
        let expected_digest = schema_digest_for_type(schema.resource_type.as_str())?;
        if schema.schema_digest.as_str() != schema_key.as_str()
            || schema.schema_digest != expected_digest
            || schema.schema_version != STANDARD_SCHEMA_VERSION
            || !valid_digest(&schema.validator_fingerprint)
            || schema.additional_properties == Some(true)
            || !schema
                .required
                .iter()
                .all(|field| schema.properties.contains_key(field))
        {
            return Err(integrity("api-schema-record-invalid"));
        }
        resource_types.insert(schema.resource_type);
    }
    if table.len().map_err(integrity)? != INSTALLED_SCHEMA_CATALOG.len() as u64
        || resource_types.len() != INSTALLED_SCHEMA_CATALOG.len()
        || INSTALLED_SCHEMA_CATALOG.iter().any(|resource_type| {
            !resource_types
                .contains(&ResourceTypeName::parse(*resource_type).expect("standard catalog type"))
        })
    {
        return Err(integrity("api-schema-catalog-invalid"));
    }
    Ok(())
}

fn validate_zone_link_cursors(
    read: &redb::ReadTransaction,
    meta: &StoreMeta,
) -> Result<(), StoreError> {
    let table = read.open_table(ZONE_LINK_CURSORS).map_err(integrity)?;
    for row in table.iter().map_err(integrity)? {
        let (key, value) = row.map_err(integrity)?;
        let decoded = DecodedKey::decode(key.value()).map_err(integrity)?;
        if decoded.key_space() != KeySpace::ZoneLinkCursors {
            return Err(integrity("zone-link-cursor-key-space-invalid"));
        }
        let [crate::DecodedKeyComponent::Text(peer_zone_uid)] = decoded.components() else {
            return Err(integrity("zone-link-cursor-key-shape-invalid"));
        };
        ResourceUid::parse((*peer_zone_uid).to_owned())
            .map_err(|_| integrity("zone-link-cursor-peer-invalid"))?;
        let cursor: ZoneLinkCursorRecord = decode(ValueKind::ZoneLinkCursor, value.value())?;
        if cursor.link_epoch == 0
            || cursor.acked > cursor.sent
            || cursor.applied > cursor.received
            || cursor.sent > meta.current_revision
            || cursor.received > meta.current_revision
        {
            return Err(integrity("zone-link-cursor-record-invalid"));
        }
    }
    Ok(())
}

fn validate_change_batch(batch: &ChangeBatch, meta: &StoreMeta) -> Result<(), StoreError> {
    if batch.entries().iter().any(|entry| {
        entry.canonical_resource.as_ref().is_some_and(|bytes| {
            ResourceEnvelope::from_json(bytes).map_or(true, |envelope| {
                envelope.resource_type() != entry.resource_type()
                    || envelope.metadata().name() != entry.resource_name()
                    || envelope.metadata().uid() != &entry.resource_uid
                    || envelope.metadata().revision() != batch.revision()
                    || envelope.digest().ok().as_deref() != Some(entry.payload_digest.as_str())
                    || entry
                        .owner_ref
                        .as_ref()
                        .is_some_and(|owner| envelope.metadata().owner_ref() != Some(owner))
            })
        }) || entry.event == ChangeEvent::Deleted && entry.canonical_resource.is_some()
            || entry.new_generation.is_none() && entry.event != ChangeEvent::Deleted
            || entry.old_generation.is_none() && !matches!(entry.event, ChangeEvent::Created)
            || entry.previous_owner_ref.is_some() != entry.previous_owner_uid.is_some()
            || entry.operation_id.as_str().is_empty()
            || entry.correlation_id.as_str().is_empty()
    }) || batch.revision().get() > meta.current_revision
    {
        return Err(integrity("change-batch-content-invalid"));
    }
    Ok(())
}

fn validate_active_schema(
    write: &redb::WriteTransaction,
    envelope: &ResourceEnvelope,
) -> Result<(), StoreError> {
    if let Some(contract) = d2b_contracts_provider::v3::catalog()
        .into_iter()
        .flat_map(|pair| [pair.service(), pair.binding()])
        .find(|contract| contract.resource_type() == envelope.resource_type())
    {
        contract
            .schema_contract(std::iter::empty())
            .map_err(|_| schema_invalid("resource-schema-contract-invalid"))?
            .validate_envelope(envelope)
            .map_err(|_| schema_invalid("resource-schema-invalid"))?;
        return Ok(());
    }

    let standard = validate_standard_base(envelope)?;
    let schemas = write.open_table(API_SCHEMAS).map_err(integrity)?;
    let key = api_schema_key_for_type(envelope.resource_type())
        .map_err(|_| schema_invalid("resource-type-schema-not-installed"))?;
    let value = schemas
        .get(key.as_slice())
        .map_err(integrity)?
        .ok_or_else(|| schema_invalid("resource-type-schema-not-installed"))?;
    let schema: ApiSchemaRecord = decode(ValueKind::ApiSchemaRecord, value.value())?;
    let expected_digest = api_schema_digest_for_type(envelope.resource_type())
        .map_err(|_| schema_invalid("resource-type-schema-not-installed"))?;
    if schema.resource_type != *envelope.resource_type()
        || schema.schema_digest != expected_digest
        || !valid_digest(&schema.schema_digest)
        || schema.schema_version != STANDARD_SCHEMA_VERSION
        || !valid_digest(&schema.validator_fingerprint)
        || schema.additional_properties == Some(true)
        || !schema
            .required
            .iter()
            .all(|field| schema.properties.contains_key(field))
    {
        return Err(schema_invalid("resource-schema-record-invalid"));
    }
    if standard {
        if envelope.spec().provider().is_some() || envelope.status().provider().is_some() {
            return Err(schema_invalid("provider-schema-not-installed"));
        }
    } else if !validate_qualified_base(envelope)? {
        return Err(schema_invalid("resource-base-schema-invalid"));
    }
    Ok(())
}

fn validate_standard_base(envelope: &ResourceEnvelope) -> Result<bool, StoreError> {
    let bytes = if envelope.resource_type().as_str() == "Endpoint" {
        envelope
            .spec()
            .canonical_bytes()
            .map_err(|_| schema_invalid("resource-base-schema-invalid"))?
    } else {
        envelope.spec().base().to_canonical_bytes()
    };
    validate_standard_base_bytes(envelope.resource_type().as_str(), &bytes)
}

fn validate_standard_base_bytes(resource_type: &str, bytes: &[u8]) -> Result<bool, StoreError> {
    let valid = match resource_type {
        "Zone" => {
            serde_json::from_slice::<d2b_contracts_zone_session::v3::zone::ZoneSpec>(bytes).is_ok()
        }
        "ZoneLink" => {
            serde_json::from_slice::<d2b_contracts_zone_session::v3::zone_link::ZoneLinkSpec>(bytes)
                .is_ok()
        }
        "Provider" => {
            serde_json::from_slice::<d2b_contracts_provider::v3::provider::ProviderSpec>(bytes)
                .is_ok()
        }
        "Role" => {
            serde_json::from_slice::<d2b_contracts_zone_session::v3::role::RoleSpec>(bytes).is_ok()
        }
        "RoleBinding" => serde_json::from_slice::<
            d2b_contracts_zone_session::v3::role_binding::RoleBindingSpec,
        >(bytes)
        .is_ok(),
        "Quota" => {
            serde_json::from_slice::<d2b_contracts_resource::v3::quota::QuotaSpec>(bytes).is_ok()
        }
        "EmergencyPolicy" => serde_json::from_slice::<
            d2b_contracts_zone_session::v3::emergency_policy::EmergencyPolicySpec,
        >(bytes)
        .is_ok(),
        "Host" => {
            serde_json::from_slice::<d2b_contracts_resource::v3::host::HostSpec>(bytes).is_ok()
        }
        "Guest" => {
            serde_json::from_slice::<d2b_contracts_resource::v3::guest::GuestSpec>(bytes).is_ok()
        }
        PROCESS_RESOURCE_TYPE => {
            serde_json::from_slice::<d2b_contracts_resource::v3::process::ProcessSpec>(bytes)
                .is_ok()
        }
        "EphemeralProcess" => serde_json::from_slice::<
            d2b_contracts_resource::v3::process::EphemeralProcessSpec,
        >(bytes)
        .is_ok(),
        "Volume" => {
            serde_json::from_slice::<d2b_contracts_resource::v3::volume::VolumeSpec>(bytes).is_ok()
        }
        "Network" => {
            serde_json::from_slice::<d2b_contracts_resource::v3::network::NetworkSpec>(bytes)
                .is_ok()
        }
        "Device" => {
            serde_json::from_slice::<d2b_contracts_resource::v3::device::DeviceSpec>(bytes).is_ok()
        }
        "User" => {
            serde_json::from_slice::<d2b_contracts_resource::v3::user::UserSpec>(bytes).is_ok()
        }
        "Credential" => {
            serde_json::from_slice::<d2b_contracts_provider::v3::credential::CredentialSpec>(bytes)
                .is_ok()
        }
        "Endpoint" => {
            serde_json::from_slice::<d2b_contracts_resource::v3::endpoint::EndpointSpec>(bytes)
                .is_ok()
        }
        "ResourceExport" => serde_json::from_slice::<
            d2b_contracts_zone_session::v3::resource_export::ResourceExportSpec,
        >(bytes)
        .is_ok(),
        "ResourceImport" => serde_json::from_slice::<
            d2b_contracts_zone_session::v3::resource_import::ResourceImportSpec,
        >(bytes)
        .is_ok(),
        _ => return Ok(false),
    };
    if !valid {
        return Err(schema_invalid("resource-base-schema-invalid"));
    }
    Ok(true)
}

fn validate_qualified_base(envelope: &ResourceEnvelope) -> Result<bool, StoreError> {
    let bytes = envelope.spec().base().to_canonical_bytes();
    match envelope.resource_type().as_str() {
        "display-wayland.d2bus.org.WaylandPolicy" => {
            let policy = serde_json::from_slice::<WaylandPolicySpec>(&bytes).ok();
            Ok(policy.is_some_and(|policy| {
                valid_wayland_filter(
                    &policy.allow_globals,
                    &policy.deny_globals,
                    &policy.max_versions,
                    &policy.dmabuf_allow,
                    &policy.dmabuf_deny,
                ) && valid_wayland_policy_defaults(&policy.defaults)
            }))
        }
        "display-wayland.d2bus.org.WaylandSession" => {
            let session = serde_json::from_slice::<WaylandSessionSpec>(&bytes).ok();
            Ok(session.is_some_and(valid_wayland_session))
        }
        _ => Ok(false),
    }
}

fn valid_wayland_session(session: WaylandSessionSpec) -> bool {
    let _virgl_video = session.virgl_video;
    let _debug_logging = session.filter.debug_logging;
    session.guest_ref.resource_type().as_str() == "Guest"
        && session.host_ref.resource_type().as_str() == "Host"
        && session.user_ref.resource_type().as_str() == "User"
        && session.policy_ref.resource_type().as_str() == "display-wayland.d2bus.org.WaylandPolicy"
        && session.cross_domain_trusted
        && session
            .reconnect_generation
            .is_none_or(|generation| generation > 0)
        && valid_wayland_identity(&session.identity)
        && valid_wayland_filter(
            &session.filter.allow_globals,
            &session.filter.deny_globals,
            &session.filter.max_versions,
            &session.filter.dmabuf_allow,
            &session.filter.dmabuf_deny,
        )
}

fn valid_wayland_identity(identity: &WaylandDisplayIdentity) -> bool {
    let _presentation = (identity.border_enabled, identity.label_enabled);
    valid_wayland_label(&identity.label)
        && valid_wayland_color(&identity.active_color)
        && valid_wayland_color(&identity.inactive_color)
        && valid_wayland_color(&identity.urgent_color)
        && identity.border_width <= 64
        && matches!(
            identity.label_position,
            WaylandLabelPosition::TopLeft | WaylandLabelPosition::TopCenter
        )
        && identity
            .label_text
            .as_deref()
            .is_none_or(|text| !text.is_empty() && text.len() <= 64)
}

fn valid_wayland_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_lowercase())
        && value.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
}

fn valid_wayland_color(value: &str) -> bool {
    value.len() == 7
        && value.starts_with('#')
        && value[1..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_wayland_filter(
    allow_globals: &[String],
    deny_globals: &[String],
    max_versions: &std::collections::BTreeMap<String, u32>,
    dmabuf_allow: &[String],
    dmabuf_deny: &[String],
) -> bool {
    allow_globals.len() <= 128
        && deny_globals.len() <= 128
        && max_versions.len() <= 128
        && max_versions.values().all(|version| *version > 0)
        && dmabuf_allow.len() <= 64
        && dmabuf_deny.len() <= 64
        && allow_globals
            .iter()
            .chain(deny_globals)
            .all(|value| !value.is_empty() && value.len() <= 63)
        && dmabuf_allow
            .iter()
            .chain(dmabuf_deny)
            .all(|value| !value.is_empty() && value.chars().count() <= 63)
}

fn valid_wayland_policy_defaults(defaults: &WaylandPolicyDefaults) -> bool {
    let _ = (
        &defaults.accelerated_rendering,
        &defaults.clipboard_boundary,
        &defaults.high_risk,
        &defaults.app_defaults,
        &defaults.off_defaults,
        &defaults.unclassified,
    );
    true
}

fn schema_invalid(reason: &'static str) -> StoreError {
    error(StoreErrorKind::ResourceSchemaInvalid, None, reason)
}

fn valid_digest(value: &str) -> bool {
    d2b_audit::is_canonical_digest(value)
}

pub(crate) fn current_meta(database: &Database) -> Result<StoreMeta, StoreError> {
    let read = database.begin_read().map_err(integrity)?;
    read_meta(&read)
}

pub(crate) fn authority_prepare_batch(
    database: &Database,
    requests: &[(String, Vec<u8>, String)],
) -> Result<(), StoreError> {
    if requests.is_empty() {
        return Err(integrity("authority-operation-batch-empty"));
    }
    if requests.len() > 128 {
        return Err(integrity("authority-operation-batch-bound"));
    }
    let mut write = database.begin_write().map_err(integrity)?;
    set_full_durability(&mut write)?;
    let current_revision = read_meta_in_write(&write)?.current_revision;
    let mut table = write.open_table(OPERATIONS).map_err(integrity)?;
    for (operation_id, payload, request_digest) in requests {
        if operation_id.is_empty() || operation_id.len() > 512 {
            return Err(integrity("authority-operation-id-invalid"));
        }
        if payload.is_empty() || payload.len() > 64 * 1024 {
            return Err(integrity("authority-operation-payload-invalid"));
        }
        if !valid_digest(request_digest) {
            return Err(integrity("authority-operation-digest-invalid"));
        }
        let key = operation_key(operation_id)?;
        let existing = table
            .get(key.as_slice())
            .map_err(integrity)?
            .map(|value| decode::<OperationRecord>(ValueKind::OperationRecord, value.value()))
            .transpose()?;
        if let Some(existing) = existing {
            let Some(authority) = existing.authority else {
                return Err(conflict(
                    current_revision,
                    0,
                    "authority-operation-id-reused",
                ));
            };
            if authority_payload_digest(&authority.payload)?.as_str() == request_digest {
                if matches!(
                    authority.state.as_str(),
                    "effect-confirmed" | "effect-terminal" | "released" | "closed"
                ) {
                    return Err(conflict(
                        current_revision,
                        0,
                        "authority-operation-id-reused",
                    ));
                }
                continue;
            }
            return Err(conflict(
                current_revision,
                0,
                "authority-operation-id-reused",
            ));
        }
        let operation = OperationRecord {
            request_digest: request_digest.clone(),
            resource_uids: Vec::new(),
            resources: Vec::new(),
            outcome: "committed".to_owned(),
            error_code: None,
            accepted_revision: current_revision,
            finished_revision: current_revision,
            audit_outbox: None,
            authority: Some(AuthorityOperationStorage {
                payload: payload.clone(),
                state: "pending".to_owned(),
            }),
        };
        let value = encode(ValueKind::OperationRecord, &operation)?;
        table
            .insert(key.as_slice(), value.as_slice())
            .map_err(integrity)?;
    }
    drop(table);
    write.commit().map_err(integrity)
}

pub(crate) fn authority_payload_digest(payload: &[u8]) -> Result<String, StoreError> {
    let value: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|_| integrity("authority-operation-payload-invalid"))?;
    authority_payload_digest_value(&value)
}

pub(crate) fn authority_payload_digest_value(
    value: &serde_json::Value,
) -> Result<String, StoreError> {
    let mut value = value.clone();
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "state".to_owned(),
            serde_json::Value::String("pending".to_owned()),
        );
    }
    let normalized =
        serde_json::to_vec(&value).map_err(|_| integrity("authority-operation-payload-invalid"))?;
    Ok(canonical_digest("d2b:authority-operation/v1", &normalized))
}

pub(crate) fn authority_update(
    database: &Database,
    operation_id: &str,
    state: &str,
) -> Result<(), StoreError> {
    if !matches!(
        state,
        "pending"
            | "effect-confirmed"
            | "effect-retryable"
            | "effect-terminal"
            | "closing"
            | "closed"
            | "released"
    ) {
        return Err(integrity("authority-operation-state-invalid"));
    }
    let key = operation_key(operation_id)?;
    let mut write = database.begin_write().map_err(integrity)?;
    set_full_durability(&mut write)?;
    let mut operation = {
        let table = write.open_table(OPERATIONS).map_err(integrity)?;
        let value = table
            .get(key.as_slice())
            .map_err(integrity)?
            .ok_or_else(|| integrity("authority-operation-missing"))?;
        decode::<OperationRecord>(ValueKind::OperationRecord, value.value())?
    };
    let authority = operation
        .authority
        .as_mut()
        .ok_or_else(|| integrity("authority-operation-missing"))?;
    if !authority_state_transition_allowed(&authority.state, state) {
        return Err(integrity("authority-operation-state-transition-invalid"));
    }
    if authority.state == state {
        write.abort().map_err(integrity)?;
        return Ok(());
    }
    authority.state = state.to_owned();
    if let Ok(mut payload) = serde_json::from_slice::<serde_json::Value>(&authority.payload)
        && let Some(object) = payload.as_object_mut()
        && object.contains_key("state")
    {
        object.insert(
            "state".to_owned(),
            serde_json::Value::String(state.to_owned()),
        );
        authority.payload = serde_json::to_vec(&payload)
            .map_err(|_| integrity("authority-operation-payload-invalid"))?;
        operation.request_digest =
            canonical_digest("d2b:authority-operation/v1", &authority.payload);
    }
    let value = encode(ValueKind::OperationRecord, &operation)?;
    write
        .open_table(OPERATIONS)
        .map_err(integrity)?
        .insert(key.as_slice(), value.as_slice())
        .map_err(integrity)?;
    write.commit().map_err(integrity)
}

fn authority_state_transition_allowed(current: &str, next: &str) -> bool {
    if current == next {
        return true;
    }
    matches!(
        (current, next),
        (
            "pending",
            "effect-confirmed" | "effect-retryable" | "effect-terminal" | "closing"
        ) | (
            "effect-confirmed" | "effect-retryable" | "effect-terminal",
            "effect-confirmed" | "effect-retryable" | "effect-terminal" | "closing"
        ) | ("closing", "closed" | "released")
            | ("closed", "released")
    )
}

pub(crate) fn authority_operations(
    database: &Database,
) -> Result<Vec<(String, Vec<u8>, String)>, StoreError> {
    let read = database.begin_read().map_err(integrity)?;
    let table = read.open_table(OPERATIONS).map_err(integrity)?;
    table
        .iter()
        .map_err(integrity)?
        .map(|row| {
            let (key, value) = row.map_err(integrity)?;
            let operation_id = operation_id_from_key(key.value())?;
            let operation: OperationRecord = decode(ValueKind::OperationRecord, value.value())?;
            Ok(operation
                .authority
                .map(|authority| (operation_id, authority.payload, authority.state)))
        })
        .filter_map(|row| match row {
            Ok(Some(value)) => Some(Ok(value)),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        })
        .collect()
}

/// Return committed operations whose audit record has not been acknowledged
/// by the durable sink.
pub(crate) fn pending_audit_outboxes(
    database: &Database,
) -> Result<Vec<AuditOutboxRecord>, StoreError> {
    let read = database.begin_read().map_err(integrity)?;
    let operations = read.open_table(OPERATIONS).map_err(integrity)?;
    operations
        .iter()
        .map_err(integrity)?
        .map(|row| {
            let (_, value) = row.map_err(integrity)?;
            let operation: OperationRecord = decode(ValueKind::OperationRecord, value.value())?;
            Ok(operation.audit_outbox)
        })
        .filter_map(|result| match result {
            Ok(Some(outbox)) => Some(Ok(outbox)),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        })
        .collect()
}

pub(crate) const MAX_PENDING_DEFERRED_ACTIVATION_OUTBOXES: usize = 256;

pub(crate) fn pending_deferred_activation_operation_ids(
    database: &Database,
    zone: &ZoneId,
) -> Result<Vec<String>, StoreError> {
    let read = database.begin_read().map_err(integrity)?;
    let meta = read_meta(&read)?;
    if meta.zone_name != zone.as_str() {
        return Err(integrity("audit-outbox-zone-mismatch"));
    }
    let operations = read.open_table(OPERATIONS).map_err(integrity)?;
    let mut operation_ids = Vec::new();
    for row in operations.iter().map_err(integrity)? {
        let (key, value) = row.map_err(integrity)?;
        let operation_id = operation_id_from_key(key.value())?;
        let operation: OperationRecord = decode(ValueKind::OperationRecord, value.value())?;
        let Some(outbox) = operation.audit_outbox else {
            continue;
        };
        validate_audit_outbox(&outbox, &operation_id, &meta)?;
        if validate_deferred_broker_evidence_marker(&outbox)? {
            operation_ids.push(operation_id);
            if operation_ids.len() > MAX_PENDING_DEFERRED_ACTIVATION_OUTBOXES {
                return Err(integrity("audit-deferred-evidence-list-bounded"));
            }
        }
    }
    operation_ids.sort();
    Ok(operation_ids)
}

pub(crate) fn audit_outbox_pending(
    database: &Database,
    operation_id: &str,
) -> Result<bool, StoreError> {
    let read = database.begin_read().map_err(integrity)?;
    let table = read.open_table(OPERATIONS).map_err(integrity)?;
    let key = operation_key(operation_id)?;
    let Some(value) = table.get(key.as_slice()).map_err(integrity)? else {
        return Ok(false);
    };
    let operation: OperationRecord = decode(ValueKind::OperationRecord, value.value())?;
    Ok(operation.audit_outbox.is_some())
}

pub(crate) fn audit_outbox_for_operation(
    database: &Database,
    operation_id: &str,
) -> Result<Option<AuditOutboxRecord>, StoreError> {
    let read = database.begin_read().map_err(integrity)?;
    let table = read.open_table(OPERATIONS).map_err(integrity)?;
    let key = operation_key(operation_id)?;
    let Some(value) = table.get(key.as_slice()).map_err(integrity)? else {
        return Ok(None);
    };
    let operation: OperationRecord = decode(ValueKind::OperationRecord, value.value())?;
    Ok(operation.audit_outbox)
}

/// Clear one audit outbox entry after its records have been durably written.
pub(crate) fn mark_audit_outbox_complete(
    database: &Database,
    operation_id: &str,
) -> Result<(), StoreError> {
    #[cfg(test)]
    if FAIL_NEXT_AUDIT_OUTBOX_CLEAR.swap(false, std::sync::atomic::Ordering::SeqCst) {
        return Err(durability_failure("injected-audit-outbox-clear-failure"));
    }

    let mut write = database.begin_write().map_err(integrity)?;
    set_full_durability(&mut write)?;
    let key = operation_key(operation_id)?;
    let mut operation = {
        let table = write.open_table(OPERATIONS).map_err(integrity)?;
        let bytes = table
            .get(key.as_slice())
            .map_err(integrity)?
            .ok_or_else(|| integrity("audit-outbox-operation-missing"))?;
        decode::<OperationRecord>(ValueKind::OperationRecord, bytes.value())?
    };
    if operation.audit_outbox.is_none() {
        write.abort().map_err(integrity)?;
        return Ok(());
    }
    operation.audit_outbox = None;
    let value = encode(ValueKind::OperationRecord, &operation)?;
    write
        .open_table(OPERATIONS)
        .map_err(integrity)?
        .insert(key.as_slice(), value.as_slice())
        .map_err(integrity)?;
    write.commit().map_err(integrity)
}

/// Persist the predecessor and record hash after one outbox mutation reaches
/// the external sink. A crash after the append therefore leaves enough
/// evidence for recovery to query or replay the exact mutation without
/// rebuilding it against a newer chain head.
pub(crate) fn mark_audit_outbox_progress(
    database: &Database,
    operation_id: &str,
    ordinal: u32,
    previous_hash: &AuditHash,
    record_hash: &AuditHash,
) -> Result<(), StoreError> {
    let mut write = database.begin_write().map_err(integrity)?;
    set_full_durability(&mut write)?;
    let key = operation_key(operation_id)?;
    let mut operation = {
        let table = write.open_table(OPERATIONS).map_err(integrity)?;
        let bytes = table
            .get(key.as_slice())
            .map_err(integrity)?
            .ok_or_else(|| integrity("audit-outbox-operation-missing"))?;
        decode::<OperationRecord>(ValueKind::OperationRecord, bytes.value())?
    };
    let Some(outbox) = operation.audit_outbox.as_mut() else {
        write.abort().map_err(integrity)?;
        return Ok(());
    };
    let mutation = outbox
        .mutations
        .iter_mut()
        .find(|mutation| mutation.ordinal == ordinal)
        .ok_or_else(|| integrity("audit-outbox-mutation-missing"))?;
    if mutation
        .previous_hash
        .as_ref()
        .is_some_and(|value| value != previous_hash)
        || mutation
            .record_hash
            .as_ref()
            .is_some_and(|value| value != record_hash)
    {
        return Err(integrity("audit-outbox-hash-conflict"));
    }
    mutation.previous_hash = Some(previous_hash.clone());
    mutation.record_hash = Some(record_hash.clone());
    let value = encode(ValueKind::OperationRecord, &operation)?;
    write
        .open_table(OPERATIONS)
        .map_err(integrity)?
        .insert(key.as_slice(), value.as_slice())
        .map_err(integrity)?;
    write.commit().map_err(integrity)
}

pub(crate) fn read_meta(read: &redb::ReadTransaction) -> Result<StoreMeta, StoreError> {
    let table = read.open_table(STORE_META).map_err(integrity)?;
    let bytes = table
        .get(meta_key().as_slice())
        .map_err(integrity)?
        .ok_or_else(|| integrity("store-meta-missing"))?;
    decode(ValueKind::StoreMetaScalar, bytes.value())
}

pub(crate) fn set_clean_shutdown(
    database: &Database,
    clean_shutdown: bool,
) -> Result<(), StoreError> {
    let mut write = database.begin_write().map_err(integrity)?;
    set_full_durability(&mut write)?;
    let mut meta = read_meta_in_write(&write)?;
    if meta.clean_shutdown == clean_shutdown {
        write.abort().map_err(integrity)?;
        return Ok(());
    }
    meta.clean_shutdown = clean_shutdown;
    let value = encode(ValueKind::StoreMetaScalar, &meta)?;
    write
        .open_table(STORE_META)
        .map_err(integrity)?
        .insert(meta_key().as_slice(), value.as_slice())
        .map_err(integrity)?;
    write.commit().map_err(integrity)
}

fn replayed_operation_failure(operation: &OperationRecord) -> StoreError {
    let kind = if operation.outcome == "denied" {
        StoreErrorKind::AuthorizationDenied
    } else {
        match operation.error_code.as_deref() {
            Some("resource-not-found") => StoreErrorKind::ResourceNotFound,
            Some("resource-already-exists") => StoreErrorKind::ResourceAlreadyExists,
            Some("resource-conflict")
            | Some("operation-id-reused")
            | Some("assignment-required")
            | Some("assignment-owner-missing")
            | Some("owner-child-binding-mismatch")
            | Some("same-batch-create-followup-unsupported")
            | Some("same-batch-delete-recreate-unsupported") => StoreErrorKind::ResourceConflict,
            Some("resource-schema-invalid") => StoreErrorKind::ResourceSchemaInvalid,
            Some("resource-ref-invalid") => StoreErrorKind::ResourceRefInvalid,
            Some("resource-owner-cycle") => StoreErrorKind::ResourceOwnerCycle,
            Some("resource-owner-depth") => StoreErrorKind::ResourceOwnerDepth,
            Some("resource-finalizer-denied") => StoreErrorKind::ResourceFinalizerDenied,
            Some("resource-controller-mismatch") => StoreErrorKind::ResourceControllerMismatch,
            Some("resource-status-owner-mismatch") => StoreErrorKind::ResourceStatusOwnerMismatch,
            Some("status-oversize") => StoreErrorKind::StatusOversize,
            Some("status-provider-schema-invalid") => StoreErrorKind::StatusProviderSchemaInvalid,
            Some("status-provider-overlap") => StoreErrorKind::StatusProviderOverlap,
            Some("spec-provider-schema-invalid") => StoreErrorKind::SpecProviderSchemaInvalid,
            Some("spec-provider-shadow") => StoreErrorKind::SpecProviderShadow,
            Some("unsupported-capability") => StoreErrorKind::UnsupportedCapability,
            Some("expedited-not-authorized") => StoreErrorKind::ExpeditedNotAuthorized,
            Some("expedited-quota-exceeded") => StoreErrorKind::ExpeditedQuotaExceeded,
            _ => StoreErrorKind::InternalIntegrityFailure,
        }
    };
    let reason = match kind {
        StoreErrorKind::AuthorizationDenied => "operation-replayed-denied",
        StoreErrorKind::ResourceNotFound => "resource-not-found",
        StoreErrorKind::ResourceAlreadyExists => "resource-already-exists",
        StoreErrorKind::ResourceConflict => "resource-conflict",
        StoreErrorKind::ResourceSchemaInvalid => "resource-schema-invalid",
        StoreErrorKind::ResourceRefInvalid => "resource-ref-invalid",
        StoreErrorKind::ResourceOwnerCycle => "resource-owner-cycle",
        StoreErrorKind::ResourceOwnerDepth => "resource-owner-depth",
        StoreErrorKind::ResourceFinalizerDenied => "resource-finalizer-denied",
        StoreErrorKind::ResourceControllerMismatch => "resource-controller-mismatch",
        StoreErrorKind::ResourceStatusOwnerMismatch => "resource-status-owner-mismatch",
        StoreErrorKind::StatusOversize => "status-oversize",
        StoreErrorKind::StatusProviderSchemaInvalid => "status-provider-schema-invalid",
        StoreErrorKind::StatusProviderOverlap => "status-provider-overlap",
        StoreErrorKind::SpecProviderSchemaInvalid => "spec-provider-schema-invalid",
        StoreErrorKind::SpecProviderShadow => "spec-provider-shadow",
        StoreErrorKind::UnsupportedCapability => "unsupported-capability",
        StoreErrorKind::ExpeditedNotAuthorized => "expedited-not-authorized",
        StoreErrorKind::ExpeditedQuotaExceeded => "expedited-quota-exceeded",
        _ => "operation-replayed-error",
    };
    let retry_class = if matches!(
        kind,
        StoreErrorKind::AuthorizationDenied | StoreErrorKind::ResourceConflict
    ) {
        RetryClass::Reauthorize
    } else {
        RetryClass::Never
    };
    StoreError::new(
        kind,
        Some(ZoneRevision::new(operation.finished_revision)),
        None,
        retry_class,
        reason,
    )
}

fn request_digest_matches(persisted: &str, candidates: &[String; 2]) -> bool {
    candidates.iter().any(|candidate| candidate == persisted)
}

fn authority_status_continuation_allowed(
    authority: &AuthorityOperationStorage,
    verified: &VerifiedWrite,
) -> bool {
    if !matches!(
        authority.state.as_str(),
        "pending" | "effect-retryable" | "effect-confirmed" | "effect-terminal"
    )
        || verified.mutations.len() != 1
    {
        return false;
    }
    let prepared = &verified.mutations[0];
    if prepared.mutation.kind != ResourceMutationKind::UpdateStatus
        || prepared.mutation.assignment.is_none()
    {
        return false;
    }
    let Some(expected_uid) = prepared.resource_uid.as_ref() else {
        return false;
    };
    let Some(canonical_resource) = prepared.mutation.canonical_resource.as_ref() else {
        return false;
    };
    let Ok(resource) = serde_json::from_slice::<serde_json::Value>(canonical_resource) else {
        return false;
    };
    let Some(payload) = serde_json::from_slice::<serde_json::Value>(&authority.payload).ok()
    else {
        return false;
    };
    payload
        .get("operationId")
        .and_then(serde_json::Value::as_str)
        == Some(verified.operation.operation_id.as_str())
        && payload
            .get("resourceUid")
            .and_then(serde_json::Value::as_str)
            == Some(expected_uid.as_str())
        && payload
            .get("generation")
            .and_then(serde_json::Value::as_u64)
            == resource
                .get("metadata")
                .and_then(|metadata| metadata.get("generation"))
                .and_then(serde_json::Value::as_u64)
}

#[cfg(test)]
pub(crate) fn apply_group(
    database: &Database,
    group: Vec<VerifiedWrite>,
) -> Result<CommittedGroup, StoreError> {
    apply_group_with_hook(database, group, |_| Ok(()))
}

pub(crate) fn apply_group_with_hook(
    database: &Database,
    group: Vec<VerifiedWrite>,
    after_commit: impl FnOnce(&CommittedGroup) -> Result<(), StoreError>,
) -> Result<CommittedGroup, StoreError> {
    #[cfg(test)]
    if FAIL_NEXT_APPLY_GROUP.swap(false, std::sync::atomic::Ordering::SeqCst) {
        return Err(durability_failure("injected-commit-failure"));
    }
    if group.is_empty() {
        let committed = CommittedGroup {
            results: Vec::new(),
            batch: None,
            resulting_revision: current_meta(database)?.current_revision,
        };
        after_commit(&committed)?;
        return Ok(committed);
    }

    let mut write = database.begin_write().map_err(integrity)?;
    set_full_durability(&mut write)?;
    let mut meta = read_meta_in_write(&write)?;
    let Some(revision) = meta.current_revision.checked_add(1) else {
        return Err(integrity("zone-revision-exhausted"));
    };
    let mut results = Vec::with_capacity(group.len());
    let mut entries = Vec::new();
    let mut accepted_targets = std::collections::BTreeSet::new();
    let mut failed_operations = Vec::new();
    let mut seen_operations = std::collections::BTreeMap::<String, String>::new();

    for verified in group {
        // Resolve an existing operation before policy or payload validation.
        // A terminal row is authoritative for retries, including retries
        // whose current admission snapshot is stale or whose payload is no
        // longer valid.
        let operation_id = verified.operation.operation_id.clone();
        let request_digests = operation_digests(&verified)?;
        let request_digest = request_digests[0].clone();
        let operation_key_bytes = operation_key(&operation_id)?;
        let mut retained_authority = None;
        if let Some(previous_digest) =
            seen_operations.insert(operation_id.clone(), request_digest.clone())
        {
            let reason = if previous_digest == request_digest {
                "operation-duplicate-in-group"
            } else {
                "operation-id-reused"
            };
            results.push(Err(conflict(meta.current_revision, 0, reason)));
            continue;
        }
        {
            let operations = write.open_table(OPERATIONS).map_err(integrity)?;
            if let Some(bytes) = operations
                .get(operation_key_bytes.as_slice())
                .map_err(integrity)?
            {
                let prior: OperationRecord = decode(ValueKind::OperationRecord, bytes.value())?;
                if let Some(authority) = prior.authority.as_ref()
                    && authority_status_continuation_allowed(authority, &verified)
                {
                    retained_authority = Some(authority.clone());
                } else {
                    if !request_digest_matches(&prior.request_digest, &request_digests) {
                        results.push(Err(conflict(
                            meta.current_revision,
                            0,
                            "operation-id-reused",
                        )));
                    } else if prior.outcome == "committed" {
                        results.push(Ok(StoreCommitResult {
                            resources: prior
                                .resources
                                .iter()
                                .map(operation_resource)
                                .collect::<Result<Vec<_>, _>>()?,
                            revision: ZoneRevision::new(prior.finished_revision),
                        }));
                    } else {
                        results.push(Err(replayed_operation_failure(&prior)));
                    }
                    continue;
                }
            }
        }

        let snapshot = verified.policy_snapshot;
        if verified.mutations.is_empty()
            || verified.mutations.len() > d2b_contracts_resource::v3::MAX_BATCH_MUTATIONS
        {
            results.push(Err(integrity("empty-verified-mutation")));
            continue;
        }
        if !revisions_match(&meta, snapshot) {
            let error = authorization_denied(meta.current_revision);
            results.push(Err(error.clone()));
            if !verified.mutations.is_empty() {
                failed_operations.push((
                    operation_key(&verified.operation.operation_id)?,
                    failed_operation_record(&verified, meta.current_revision, &error)?,
                ));
            }
            continue;
        }
        if let Err(error) = validate_prepared_payloads(&verified) {
            results.push(Err(error.clone()));
            if !verified.mutations.is_empty() {
                failed_operations.push((
                    operation_key(&verified.operation.operation_id)?,
                    failed_operation_record(&verified, meta.current_revision, &error)?,
                ));
            }
            continue;
        }
        let operation_id = verified.operation.operation_id.clone();
        let correlation_id = verified.operation.correlation_id.clone();
        let request_digests = operation_digests(&verified)?;
        let request_digest = request_digests[0].clone();
        let operation_key_bytes = operation_key(&operation_id)?;
        {
            let operations = write.open_table(OPERATIONS).map_err(integrity)?;
            if let Some(bytes) = operations
                .get(operation_key_bytes.as_slice())
                .map_err(integrity)?
            {
                let prior: OperationRecord = decode(ValueKind::OperationRecord, bytes.value())?;
                if let Some(authority) = prior.authority.as_ref()
                    && authority_status_continuation_allowed(authority, &verified)
                {
                    retained_authority = Some(authority.clone());
                } else {
                    if request_digest_matches(&prior.request_digest, &request_digests) {
                        if prior.outcome != "committed" {
                            results.push(Err(replayed_operation_failure(&prior)));
                            continue;
                        }
                        results.push(Ok(StoreCommitResult {
                            resources: prior
                                .resources
                                .iter()
                                .map(operation_resource)
                                .collect::<Result<Vec<_>, _>>()?,
                            revision: ZoneRevision::new(prior.finished_revision),
                        }));
                    } else {
                        let error = conflict(meta.current_revision, 0, "operation-id-reused");
                        results.push(Err(error.clone()));
                    }
                    continue;
                }
            }
        }

        let result_index = results.len();
        results.push(Err(integrity("unresolved-write-result")));
        let mut verified = verified;
        for prepared in &mut verified.mutations {
            if prepared.mutation.kind == ResourceMutationKind::Create {
                prepared.resource_uid = if prepared.mutation.target.resource_type().as_str()
                    == "Zone"
                    && prepared.mutation.target.name().as_str() == meta.zone_name
                {
                    Some(ResourceUid::parse(meta.zone_uid.clone()).map_err(integrity)?)
                } else {
                    Some(mint_resource_uid()?)
                };
            }
        }
        let finalized =
            match validate_verified_write(&write, &verified, revision, &accepted_targets) {
                Ok(finalized) => finalized,
                Err(error) => {
                    results[result_index] = Err(error.clone());
                    failed_operations.push((
                        operation_key_bytes.clone(),
                        failed_operation_record(&verified, meta.current_revision, &error)?,
                    ));
                    continue;
                }
            };
        let mut simulated = read_simulated_state(&write)?;
        if let Err(error) = validate_structural_group(&verified, &mut simulated) {
            results[result_index] = Err(error.clone());
            failed_operations.push((
                operation_key_bytes.clone(),
                failed_operation_record(&verified, meta.current_revision, &error)?,
            ));
            continue;
        }
        let mut group_resources = Vec::new();
        let mut group_entries = Vec::new();
        for (ordinal, prepared) in verified.mutations.iter().enumerate() {
            let (resource, entry) = apply_prepared(
                &write,
                prepared,
                finalized
                    .get(ordinal)
                    .ok_or_else(|| integrity("finalized-mutation-missing"))?
                    .as_ref(),
                revision,
                u32::try_from(ordinal).map_err(integrity)?,
                &operation_id,
                &correlation_id,
            )?;
            group_resources.push(resource);
            group_entries.push(entry);
        }
        let operation = OperationRecord {
            request_digest,
            resource_uids: group_resources
                .iter()
                .map(|resource| resource.uid.as_str().to_owned())
                .collect(),
            resources: group_resources
                .iter()
                .map(|resource| OperationResourceRecord {
                    resource_type: resource.resource_ref.resource_type().as_str().to_owned(),
                    resource_name: resource.resource_ref.name().as_str().to_owned(),
                    zone: resource.zone.as_str().to_owned(),
                    canonical_json: resource.canonical_json.clone(),
                    payload_digest: resource.payload_digest.clone(),
                })
                .collect(),
            outcome: "committed".to_owned(),
            error_code: None,
            accepted_revision: revision,
            finished_revision: revision,
            audit_outbox: Some(audit_outbox_for(
                &verified,
                &group_resources,
                revision,
                audit_now_ms(),
            )?),
            authority: retained_authority,
        };
        let operation_value = encode(ValueKind::OperationRecord, &operation)?;
        write
            .open_table(OPERATIONS)
            .map_err(integrity)?
            .insert(operation_key_bytes.as_slice(), operation_value.as_slice())
            .map_err(integrity)?;
        results[result_index] = Ok(StoreCommitResult {
            resources: group_resources.clone(),
            revision: ZoneRevision::new(revision),
        });
        accepted_targets.extend(
            verified
                .mutations
                .iter()
                .map(|prepared| prepared.mutation().target.clone()),
        );
        entries.extend(group_entries);
    }

    for (operation_key, operation) in failed_operations {
        let operation_value = encode(ValueKind::OperationRecord, &operation)?;
        write
            .open_table(OPERATIONS)
            .map_err(integrity)?
            .insert(operation_key.as_slice(), operation_value.as_slice())
            .map_err(integrity)?;
    }

    if entries.is_empty() {
        let committed = CommittedGroup {
            results,
            batch: None,
            resulting_revision: meta.current_revision,
        };
        write.commit().map_err(integrity)?;
        after_commit(&committed)?;
        return Ok(committed);
    }
    for (ordinal, entry) in entries.iter_mut().enumerate() {
        entry.ordinal = u32::try_from(ordinal).map_err(integrity)?;
    }
    let batch = ChangeBatch::new(ZoneRevision::new(revision), entries)?;
    let batch_key = revision_key(revision)?;
    let batch_value = encode(ValueKind::ChangeBatch, &batch)?;
    write
        .open_table(REVISION_LOG)
        .map_err(integrity)?
        .insert(batch_key.as_slice(), batch_value.as_slice())
        .map_err(integrity)?;
    meta.current_revision = revision;
    let meta_value = encode(ValueKind::StoreMetaScalar, &meta)?;
    write
        .open_table(STORE_META)
        .map_err(integrity)?
        .insert(meta_key().as_slice(), meta_value.as_slice())
        .map_err(integrity)?;
    let committed = CommittedGroup {
        results,
        batch: Some(batch.clone()),
        resulting_revision: revision,
    };
    write.commit().map_err(integrity)?;
    // The database commit/abort is the authority boundary.  The callback may
    // write the external audit sink only after that transaction outcome.
    after_commit(&committed)?;
    Ok(committed)
}

#[cfg(test)]
static FAIL_NEXT_APPLY_GROUP: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
static FAIL_NEXT_AUDIT_OUTBOX_CLEAR: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
pub(crate) fn fail_next_apply_group_for_test() {
    FAIL_NEXT_APPLY_GROUP.store(true, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
pub(crate) fn fail_next_audit_outbox_clear_for_test() {
    FAIL_NEXT_AUDIT_OUTBOX_CLEAR.store(true, std::sync::atomic::Ordering::SeqCst);
}

fn read_simulated_state(
    write: &redb::WriteTransaction,
) -> Result<std::collections::BTreeMap<ResourceRef, (ResourceUid, Option<ResourceRef>)>, StoreError>
{
    let table = write.open_table(RESOURCES).map_err(integrity)?;
    table
        .iter()
        .map_err(integrity)?
        .map(|row| {
            let (key, value) = row.map_err(integrity)?;
            let resource_ref = resource_ref_from_key(key.value())?;
            let record: ResourceRecord = decode(ValueKind::ResourceRecord, value.value())?;
            let envelope = ResourceEnvelope::from_json(&record.canonical_json)
                .map_err(|_| integrity("stored-resource-envelope-invalid"))?;
            Ok((
                resource_ref,
                (
                    envelope.metadata().uid().clone(),
                    envelope.metadata().owner_ref().cloned(),
                ),
            ))
        })
        .collect()
}

fn validate_structural_group(
    verified: &VerifiedWrite,
    state: &mut std::collections::BTreeMap<ResourceRef, (ResourceUid, Option<ResourceRef>)>,
) -> Result<(), StoreError> {
    for prepared in &verified.mutations {
        let mutation = prepared.mutation();
        if mutation.kind == ResourceMutationKind::Delete {
            continue;
        }
        let (uid, owner) = if mutation.kind == ResourceMutationKind::UpdateFinalizers {
            state
                .get(&mutation.target)
                .map(|(uid, owner)| (uid.clone(), owner.clone()))
                .ok_or_else(|| integrity("mutation-resource-uid-missing"))?
        } else {
            (
                prepared
                    .resource_uid()
                    .cloned()
                    .ok_or_else(|| integrity("mutation-resource-uid-missing"))?,
                mutation.owner.clone(),
            )
        };
        if let Some(owner) = &owner {
            if !state.contains_key(owner) {
                return Err(error(
                    StoreErrorKind::ResourceRefInvalid,
                    None,
                    "owner-ref-not-found",
                ));
            }
            if owner == &mutation.target || owner_path_reaches(state, owner, &mutation.target) {
                return Err(error(
                    StoreErrorKind::ResourceOwnerCycle,
                    None,
                    "resource-owner-cycle",
                ));
            }
            if owner_path_depth(state, owner)? >= crate::MAX_OWNER_CHAIN_DEPTH {
                return Err(error(
                    StoreErrorKind::ResourceOwnerDepth,
                    None,
                    "resource-owner-depth",
                ));
            }
        }
        state.insert(mutation.target.clone(), (uid, owner));
    }
    Ok(())
}

fn owner_path_reaches(
    state: &std::collections::BTreeMap<ResourceRef, (ResourceUid, Option<ResourceRef>)>,
    start: &ResourceRef,
    target: &ResourceRef,
) -> bool {
    let mut cursor = Some(start);
    let mut visited = std::collections::BTreeSet::new();
    while let Some(resource_ref) = cursor {
        if resource_ref == target || !visited.insert(resource_ref.clone()) {
            return true;
        }
        cursor = state
            .get(resource_ref)
            .and_then(|(_, owner)| owner.as_ref());
    }
    false
}

fn owner_path_depth(
    state: &std::collections::BTreeMap<ResourceRef, (ResourceUid, Option<ResourceRef>)>,
    start: &ResourceRef,
) -> Result<usize, StoreError> {
    let mut cursor = Some(start);
    let mut visited = std::collections::BTreeSet::new();
    let mut depth = 0;
    while let Some(resource_ref) = cursor {
        if !visited.insert(resource_ref.clone()) {
            return Err(error(
                StoreErrorKind::ResourceOwnerCycle,
                None,
                "resource-owner-cycle",
            ));
        }
        depth += 1;
        cursor = state
            .get(resource_ref)
            .and_then(|(_, owner)| owner.as_ref());
    }
    Ok(depth)
}

fn operation_resource(record: &OperationResourceRecord) -> Result<StoredResource, StoreError> {
    let resource_ref = ResourceRef::parse(&format!(
        "{}/{}",
        record.resource_type, record.resource_name
    ))
    .map_err(integrity)?;
    let envelope = ResourceEnvelope::from_json(&record.canonical_json)
        .map_err(|_| integrity("operation-resource-envelope-invalid"))?;
    let zone = ZoneId::parse(&record.zone).map_err(integrity)?;
    if envelope.resource_type() != resource_ref.resource_type()
        || envelope.metadata().name() != resource_ref.name()
        || envelope.metadata().zone() != &zone
        || envelope.digest().map_err(integrity)? != record.payload_digest
    {
        return Err(integrity("operation-resource-invalid"));
    }
    Ok(StoredResource {
        resource_ref,
        zone,
        uid: envelope.metadata().uid().clone(),
        owner_uid: None,
        owner_generation: None,
        generation: envelope.metadata().generation(),
        revision: envelope.metadata().revision(),
        canonical_json: record.canonical_json.clone(),
        payload_digest: record.payload_digest.clone(),
    })
}

fn apply_prepared(
    write: &redb::WriteTransaction,
    prepared: &VerifiedPreparedMutation,
    finalized: Option<&FinalizedMutation>,
    revision: u64,
    ordinal: u32,
    operation_id: &str,
    correlation_id: &str,
) -> Result<(StoredResource, ChangeEntry), StoreError> {
    let mutation = prepared.mutation();
    let key = resource_key(&mutation.target)?;
    let previous = {
        let resources = write.open_table(RESOURCES).map_err(integrity)?;
        resources
            .get(key.as_slice())
            .map_err(integrity)?
            .map(|bytes| decode::<ResourceRecord>(ValueKind::ResourceRecord, bytes.value()))
            .transpose()?
    };
    let previous_envelope = previous
        .as_ref()
        .map(|record| {
            ResourceEnvelope::from_json(&record.canonical_json)
                .map_err(|_| integrity("stored-resource-envelope-invalid"))
        })
        .transpose()?;
    let previous_resource = previous
        .as_ref()
        .map(|record| stored_resource(&mutation.zone, &mutation.target, record))
        .transpose()?;

    if mutation.kind == ResourceMutationKind::Delete {
        let Some(old) = previous_resource else {
            return Err(error(
                StoreErrorKind::ResourceNotFound,
                None,
                "resource-not-found",
            ));
        };
        let old_record = previous.as_ref().expect("previous resource was checked");
        let old_envelope = previous_envelope
            .as_ref()
            .ok_or_else(|| integrity("stored-resource-envelope-invalid"))?;
        let old_owner_ref = old_envelope.metadata().owner_ref().cloned();
        let old_owner_uid = parse_optional_uid(old_record.owner_uid.as_deref())?;
        if !deletion_requested(&old_record.canonical_json)?
            && (has_finalizers(&old_record.canonical_json)?
                || owned_children_remain(write, &mutation.target)?
                || produced_endpoints_remain(write, &old.uid)?)
        {
            let canonical_json = merge_deletion_request(&old_record.canonical_json, revision)?;
            let envelope = ResourceEnvelope::from_json(&canonical_json)
                .map_err(|_| integrity("stored-resource-envelope-invalid"))?;
            validate_active_schema(write, &envelope)?;
            let payload_digest = envelope.digest().map_err(integrity)?;
            let record = ResourceRecord {
                canonical_json: canonical_json.clone(),
                owner_uid: old_record.owner_uid.clone(),
                owner_generation: old_record.owner_generation,
                controller_binding_id: old_record.controller_binding_id.clone(),
                payload_digest: payload_digest.clone(),
                assignment: old_record
                    .assignment
                    .as_ref()
                    .map(|assignment| assignment_rebound_to_revision(assignment, revision)),
            };
            write
                .open_table(RESOURCES)
                .map_err(integrity)?
                .insert(
                    key.as_slice(),
                    encode(ValueKind::ResourceRecord, &record)?.as_slice(),
                )
                .map_err(integrity)?;
            let resource = stored_resource(&mutation.zone, &mutation.target, &record)?;
            return Ok((
                resource.clone(),
                ChangeEntry::new(
                    ordinal,
                    mutation.target.resource_type().clone(),
                    mutation.target.name().clone(),
                    old.uid.clone(),
                    ChangeEvent::DeletionRequested,
                    Some(old.generation),
                    Some(resource.generation),
                    old_owner_uid.clone(),
                    payload_digest,
                    Some(canonical_json),
                    operation_id.to_owned(),
                    correlation_id.to_owned(),
                )?
                .with_owners(
                    old_owner_ref.clone(),
                    old_owner_uid.clone(),
                    old_owner_ref,
                ),
            ));
        }
        if has_finalizers(&old_record.canonical_json)? {
            return Err(error(
                StoreErrorKind::ResourceFinalizerDenied,
                None,
                "resource-finalizers-remain",
            ));
        }
        if owned_children_remain(write, &mutation.target)? {
            return Err(error(
                StoreErrorKind::ResourceFinalizerDenied,
                None,
                "owned-children-remain",
            ));
        }
        if produced_endpoints_remain(write, &old.uid)? {
            return Err(error(
                StoreErrorKind::ResourceFinalizerDenied,
                None,
                "produced-endpoints-remain",
            ));
        }
        remove_indexes(write, &old, old_record, &old_envelope)?;
        write
            .open_table(RESOURCES)
            .map_err(integrity)?
            .remove(key.as_slice())
            .map_err(integrity)?;
        return Ok((
            old.clone(),
            ChangeEntry::new(
                ordinal,
                mutation.target.resource_type().clone(),
                mutation.target.name().clone(),
                old.uid.clone(),
                ChangeEvent::Deleted,
                Some(old.generation),
                None,
                old_owner_uid.clone(),
                old.payload_digest.clone(),
                None,
                operation_id.to_owned(),
                correlation_id.to_owned(),
            )?
            .with_owners(old_owner_ref, old_owner_uid, None),
        ));
    }

    let finalized = finalized.ok_or_else(|| integrity("finalized-mutation-missing"))?;
    let canonical_json = finalized.canonical_json.clone();
    let envelope = ResourceEnvelope::from_json(&canonical_json)
        .map_err(|_| integrity("stored-resource-envelope-invalid"))?;
    validate_active_schema(write, &envelope)?;
    let uid = envelope.metadata().uid().clone();
    let effective_owner = if matches!(
        mutation.kind,
        ResourceMutationKind::Create | ResourceMutationKind::UpdateMetadata
    ) {
        mutation.owner.clone()
    } else {
        previous_envelope
            .as_ref()
            .and_then(|envelope| envelope.metadata().owner_ref().cloned())
    };
    if envelope.resource_type() != mutation.target.resource_type()
        || envelope.metadata().name() != mutation.target.name()
        || envelope.metadata().zone() != &mutation.zone
        || envelope.metadata().owner_ref() != effective_owner.as_ref()
    {
        return Err(integrity("mutation-resource-identity-mismatch"));
    }
    let (owner_uid, owner_generation) = if mutation.kind == ResourceMutationKind::UpdateStatus {
        previous
            .as_ref()
            .map(|record| (record.owner_uid.clone(), record.owner_generation))
            .unwrap_or((None, None))
    } else {
        let owner_uid = match &effective_owner {
            Some(owner_ref) => Some(resolve_uid_in_write(write, owner_ref)?.as_str().to_owned()),
            None => None,
        };
        let owner_generation = effective_owner
            .as_ref()
            .map(|owner_ref| resolve_generation_in_write(write, owner_ref))
            .transpose()?
            .map(|generation| generation.get());
        (owner_uid, owner_generation)
    };
    let previous_owner_ref = previous_envelope
        .as_ref()
        .and_then(|envelope| envelope.metadata().owner_ref().cloned());
    let previous_owner_uid = previous
        .as_ref()
        .map(|record| parse_optional_uid(record.owner_uid.as_deref()))
        .transpose()?
        .flatten();
    if let (Some(previous_resource), Some(previous_record)) = (&previous_resource, &previous) {
        remove_indexes(
            write,
            previous_resource,
            previous_record,
            previous_envelope
                .as_ref()
                .ok_or_else(|| integrity("stored-resource-envelope-invalid"))?,
        )?;
    }
    let payload_digest = envelope.digest().map_err(integrity)?;
    if payload_digest != finalized.payload_digest {
        return Err(integrity("finalized-payload-digest-mismatch"));
    }
    let assignment = match mutation.assignment.as_ref() {
        Some(fence) if matches!(&fence.scope, ResourceAssignmentScope::Primary) => {
            Some(assignment_record(
                fence,
                &uid,
                revision,
                previous_resource.as_ref().map(|resource| resource.revision),
            )?)
        }
        Some(_) | None => previous
            .as_ref()
            .and_then(|record| record.assignment.clone()),
    }
    .map(|assignment| assignment_rebound_to_revision(&assignment, revision));
    let record = ResourceRecord {
        canonical_json: canonical_json.clone(),
        owner_uid: owner_uid.clone(),
        owner_generation,
        controller_binding_id: controller_binding_id(&envelope, assignment.as_ref()),
        payload_digest: payload_digest.clone(),
        assignment,
    };
    if mutation.kind == ResourceMutationKind::UpdateFinalizers
        && deletion_requested(&canonical_json)?
        && !has_finalizers(&canonical_json)?
        && !owned_children_remain(write, &mutation.target)?
        && !produced_endpoints_remain(write, &uid)?
    {
        write
            .open_table(RESOURCES)
            .map_err(integrity)?
            .remove(resource_key(&mutation.target)?.as_slice())
            .map_err(integrity)?;
        let resource = stored_resource(&mutation.zone, &mutation.target, &record)?;
        return Ok((
            resource.clone(),
            ChangeEntry::new(
                ordinal,
                mutation.target.resource_type().clone(),
                mutation.target.name().clone(),
                uid,
                ChangeEvent::Deleted,
                previous_resource
                    .as_ref()
                    .map(|resource| resource.generation),
                None,
                parse_optional_uid(owner_uid.as_deref())?,
                payload_digest,
                None,
                operation_id.to_owned(),
                correlation_id.to_owned(),
            )?
            .with_owners(previous_owner_ref, previous_owner_uid, None),
        ));
    }
    let producer = endpoint_producer(&envelope)?;
    insert_resource_and_indexes(
        write,
        &mutation.target,
        &uid,
        revision,
        &record,
        producer.as_ref(),
    )?;
    let resource = stored_resource(&mutation.zone, &mutation.target, &record)?;
    let event = match mutation.kind {
        ResourceMutationKind::Create => ChangeEvent::Created,
        ResourceMutationKind::UpdateSpec => ChangeEvent::SpecUpdated,
        ResourceMutationKind::UpdateStatus => ChangeEvent::StatusUpdated,
        ResourceMutationKind::UpdateMetadata => ChangeEvent::MetadataUpdated,
        ResourceMutationKind::UpdateFinalizers => ChangeEvent::FinalizersUpdated,
        ResourceMutationKind::Delete => unreachable!("delete returned above"),
    };
    Ok((
        resource.clone(),
        ChangeEntry::new(
            ordinal,
            mutation.target.resource_type().clone(),
            mutation.target.name().clone(),
            uid,
            event,
            previous_resource
                .as_ref()
                .map(|resource| resource.generation),
            Some(resource.generation),
            parse_optional_uid(owner_uid.as_deref())?,
            payload_digest,
            Some(canonical_json),
            operation_id.to_owned(),
            correlation_id.to_owned(),
        )?
        .with_owners(previous_owner_ref, previous_owner_uid, effective_owner),
    ))
}

fn staged_state_after_mutation(
    prepared: &VerifiedPreparedMutation,
    finalized: &FinalizedMutation,
    previous: Option<&(ResourceRecord, ResourceEnvelope)>,
    revision: u64,
    uid: &ResourceUid,
) -> Result<(ResourceRecord, ResourceEnvelope), StoreError> {
    let envelope = ResourceEnvelope::from_json(&finalized.canonical_json)
        .map_err(|_| integrity("stored-resource-envelope-invalid"))?;
    let assignment = match prepared.mutation().assignment.as_ref() {
        Some(fence) if matches!(&fence.scope, ResourceAssignmentScope::Primary) => {
            Some(assignment_record(
                fence,
                uid,
                revision,
                previous.map(|(_, envelope)| envelope.metadata().revision()),
            )?)
        }
        Some(_) | None => previous.and_then(|(record, _)| record.assignment.clone()),
    }
    .map(|assignment| assignment_rebound_to_revision(&assignment, revision));
    let mut record = previous
        .map(|(record, _)| record.clone())
        .unwrap_or_else(|| ResourceRecord {
            canonical_json: Vec::new(),
            owner_uid: None,
            owner_generation: None,
            controller_binding_id: String::new(),
            payload_digest: String::new(),
            assignment: None,
        });
    record.canonical_json = finalized.canonical_json.clone();
    record.payload_digest = finalized.payload_digest.clone();
    record.assignment = assignment;
    record.controller_binding_id = controller_binding_id(&envelope, record.assignment.as_ref());
    Ok((record, envelope))
}

fn validate_verified_write(
    write: &redb::WriteTransaction,
    verified: &VerifiedWrite,
    revision: u64,
    accepted_targets: &std::collections::BTreeSet<ResourceRef>,
) -> Result<Vec<Option<FinalizedMutation>>, StoreError> {
    let meta = read_meta_in_write(write)?;
    if verified.authorization.zone.as_str() != meta.zone_name {
        return Err(integrity("mutation-zone-mismatch"));
    }
    let mut staged = std::collections::BTreeMap::<ResourceRef, StagedResourceState>::new();
    let mut created_targets = std::collections::BTreeSet::new();
    let mut finalized = Vec::with_capacity(verified.mutations.len());
    for (ordinal, prepared) in verified.mutations.iter().enumerate() {
        let mutation = prepared.mutation();
        let ordinal = u32::try_from(ordinal).map_err(integrity)?;
        if accepted_targets.contains(&mutation.target) {
            return Err(conflict(
                meta.current_revision,
                ordinal,
                "group-resource-conflict",
            ));
        }
        if mutation.zone != verified.authorization.zone {
            return Err(integrity("mutation-zone-mismatch"));
        }
        if created_targets.contains(&mutation.target) {
            return Err(conflict(
                meta.current_revision,
                ordinal,
                "same-batch-create-followup-unsupported",
            ));
        }
        if mutation.kind == ResourceMutationKind::Create
            && staged
                .get(&mutation.target)
                .is_some_and(|state| state.is_none())
        {
            return Err(conflict(
                meta.current_revision,
                ordinal,
                "same-batch-delete-recreate-unsupported",
            ));
        }
        // A single verified operation may touch one target more than once.
        // Later mutations must see the earlier staged envelope and assignment,
        // not the transaction's original snapshot.
        let current_state = staged_or_current_record_in_write(write, &staged, &mutation.target)?;
        let current = current_state.as_ref().map(|(_, envelope)| {
            (
                envelope.metadata().uid().clone(),
                envelope.metadata().revision().get(),
            )
        });
        if !authorization_matches(&verified.authorization, mutation) {
            return Err(authorization_denied(meta.current_revision));
        }
        if let Some(fence) = &mutation.assignment {
            match &fence.scope {
                ResourceAssignmentScope::Primary => {
                    validate_primary_assignment_fence(
                        current_state.as_ref(),
                        fence,
                        meta.current_revision,
                        ordinal,
                    )?;
                }
                ResourceAssignmentScope::OwnerChild {
                    owner_ref,
                    owner_uid,
                    owner_revision,
                    owner_generation,
                } => {
                    validate_owner_child_assignment_fence(
                        write,
                        current_state.as_ref(),
                        mutation,
                        fence,
                        owner_ref,
                        owner_uid,
                        *owner_revision,
                        *owner_generation,
                        meta.current_revision,
                        ordinal,
                    )?;
                }
            }
        } else if matches!(
            mutation.kind,
            ResourceMutationKind::UpdateStatus | ResourceMutationKind::UpdateFinalizers
        ) && current_state
            .as_ref()
            .is_some_and(|(record, _)| record.assignment.is_some())
        {
            return Err(conflict(
                current.as_ref().map_or(0, |(_, revision)| *revision),
                ordinal,
                "assignment-required",
            ));
        }
        match mutation.expected {
            ExpectedRevision::CreateAbsent if current.is_some() => {
                return Err(error(
                    StoreErrorKind::ResourceAlreadyExists,
                    current.map(|(_, revision)| ZoneRevision::new(revision)),
                    "resource-already-exists",
                ));
            }
            ExpectedRevision::Exact(expected)
                if current
                    .as_ref()
                    .is_none_or(|(_, current_revision)| *current_revision != expected.get()) =>
            {
                return Err(conflict(
                    current.as_ref().map_or(0, |(_, revision)| *revision),
                    ordinal,
                    "resource-revision-changed",
                ));
            }
            ExpectedRevision::CreateAbsent | ExpectedRevision::Exact(_) => {}
        }
        if mutation.expected_uid.as_ref().is_some_and(|expected| {
            current
                .as_ref()
                .is_none_or(|(current_uid, _)| current_uid != expected)
        }) {
            return Err(conflict(
                current.as_ref().map_or(0, |(_, revision)| *revision),
                ordinal,
                "resource-uid-changed",
            ));
        }
        if mutation.kind != ResourceMutationKind::Delete
            && mutation.kind != ResourceMutationKind::Create
            && mutation.kind != ResourceMutationKind::UpdateFinalizers
        {
            let prepared_uid = prepared
                .resource_uid()
                .ok_or_else(|| integrity("mutation-resource-uid-missing"))?;
            if current
                .as_ref()
                .is_none_or(|(current_uid, _)| current_uid != prepared_uid)
            {
                return Err(conflict(
                    current.as_ref().map_or(0, |(_, revision)| *revision),
                    ordinal,
                    "resource-uid-changed",
                ));
            }
        }

        if mutation.kind == ResourceMutationKind::Delete {
            if current.is_none() {
                return Err(error(
                    StoreErrorKind::ResourceNotFound,
                    None,
                    "resource-not-found",
                ));
            }
            let (record, envelope) = current_state
                .as_ref()
                .cloned()
                .ok_or_else(|| integrity("mutation-current-resource-missing"))?;
            if deletion_requested(&record.canonical_json)? {
                if has_finalizers(&record.canonical_json)? {
                    return Err(error(
                        StoreErrorKind::ResourceFinalizerDenied,
                        None,
                        "resource-finalizers-remain",
                    ));
                }
                if owned_children_remain(write, &mutation.target)? {
                    return Err(error(
                        StoreErrorKind::ResourceFinalizerDenied,
                        None,
                        "owned-children-remain",
                    ));
                }
                if produced_endpoints_remain(write, envelope.metadata().uid())? {
                    return Err(error(
                        StoreErrorKind::ResourceFinalizerDenied,
                        None,
                        "produced-endpoints-remain",
                    ));
                }
            }
            staged.insert(mutation.target.clone(), None);
            finalized.push(None);
            continue;
        }

        if mutation.kind == ResourceMutationKind::UpdateFinalizers {
            if current.is_none() {
                return Err(error(
                    StoreErrorKind::ResourceNotFound,
                    None,
                    "resource-not-found",
                ));
            }
            if mutation.canonical_resource.is_some() {
                return Err(integrity("finalizer-mutation-body-present"));
            }
            let uid = current
                .as_ref()
                .map(|(uid, _)| uid.clone())
                .ok_or_else(|| integrity("mutation-resource-uid-missing"))?;
            if prepared
                .resource_uid()
                .is_some_and(|prepared_uid| prepared_uid != &uid)
            {
                return Err(conflict(
                    current.as_ref().map_or(0, |(_, revision)| *revision),
                    ordinal,
                    "resource-uid-changed",
                ));
            }
            let previous = current_state.as_ref().map(|(record, _)| record.clone());
            let finalized_mutation =
                finalize_authorized_mutation(prepared, previous.as_ref(), revision, &uid)?;
            let staged_state = staged_state_after_mutation(
                prepared,
                &finalized_mutation,
                current_state.as_ref(),
                revision,
                &uid,
            )?;
            finalized.push(Some(finalized_mutation));
            staged.insert(mutation.target.clone(), Some(staged_state));
            continue;
        }

        let bytes = mutation
            .canonical_resource
            .as_deref()
            .ok_or_else(|| integrity("mutation-resource-body-missing"))?;
        let uid = prepared
            .resource_uid()
            .cloned()
            .ok_or_else(|| integrity("mutation-resource-uid-missing"))?;
        if mutation.kind != ResourceMutationKind::Create {
            let envelope = ResourceEnvelope::from_json(bytes)
                .map_err(|_| integrity("stored-resource-envelope-invalid"))?;
            if envelope.resource_type() != mutation.target.resource_type()
                || envelope.metadata().name() != mutation.target.name()
                || envelope.metadata().zone() != &mutation.zone
            {
                return Err(integrity("mutation-resource-identity-mismatch"));
            }
            if envelope.metadata().uid() != &uid {
                return Err(integrity("mutation-resource-uid-mismatch"));
            }
        }
        if mutation
            .expected_uid
            .as_ref()
            .is_some_and(|expected| expected != &uid)
        {
            return Err(conflict(
                current.as_ref().map_or(0, |(_, revision)| *revision),
                ordinal,
                "resource-uid-changed",
            ));
        }
        let current_owner = current_state
            .as_ref()
            .and_then(|(_, envelope)| envelope.metadata().owner_ref().cloned());
        let owner = if mutation.kind == ResourceMutationKind::Create
            || mutation.kind == ResourceMutationKind::UpdateMetadata
        {
            mutation.owner.as_ref()
        } else {
            current_owner.as_ref()
        };
        if let Some(owner_ref) = owner {
            let owner_uid = if let Some(owner) = staged.get(owner_ref) {
                owner
                    .as_ref()
                    .map(|(_, envelope)| envelope.metadata().uid().clone())
            } else {
                current_identity_in_write(write, owner_ref)?.map(|(uid, _)| uid)
            };
            if owner_uid.is_none() {
                return Err(error(
                    StoreErrorKind::ResourceRefInvalid,
                    None,
                    "owner-ref-not-found",
                ));
            }
            if owner_uid.as_ref() == Some(&uid)
                || owner_chain_reaches(write, &staged, owner_ref, &uid)?
            {
                return Err(error(
                    StoreErrorKind::ResourceOwnerCycle,
                    None,
                    "resource-owner-cycle",
                ));
            }
        }
        let previous = if mutation.kind == ResourceMutationKind::Create {
            None
        } else {
            current_state.as_ref().map(|(record, _)| record.clone())
        };
        let finalized_mutation =
            finalize_authorized_mutation(prepared, previous.as_ref(), revision, &uid)?;
        let staged_state = staged_state_after_mutation(
            prepared,
            &finalized_mutation,
            current_state.as_ref(),
            revision,
            &uid,
        )?;
        finalized.push(Some(finalized_mutation));
        staged.insert(mutation.target.clone(), Some(staged_state));
        if mutation.kind == ResourceMutationKind::Create {
            created_targets.insert(mutation.target.clone());
        }
    }
    Ok(finalized)
}

fn validate_primary_assignment_fence(
    current_state: Option<&(ResourceRecord, ResourceEnvelope)>,
    fence: &ResourceAssignmentFence,
    current_revision: u64,
    ordinal: u32,
) -> Result<(), StoreError> {
    let Some((record, envelope)) = current_state else {
        return Err(conflict(
            current_revision,
            ordinal,
            "assignment-resource-missing",
        ));
    };
    if fence.resource_uid != *envelope.metadata().uid()
        || fence.resource_revision != envelope.metadata().revision()
    {
        return Err(conflict(
            envelope.metadata().revision().get(),
            ordinal,
            "stale-assignment",
        ));
    }
    if record.assignment.as_ref().is_some_and(|current| {
        !assignment_matches(current, fence) && !assignment_replacement_allowed(current, fence)
    }) {
        return Err(conflict(
            envelope.metadata().revision().get(),
            ordinal,
            "stale-assignment",
        ));
    }
    Ok(())
}

fn validate_owner_child_assignment_fence(
    write: &redb::WriteTransaction,
    current_child: Option<&(ResourceRecord, ResourceEnvelope)>,
    mutation: &StoreMutation,
    fence: &ResourceAssignmentFence,
    owner_ref: &ResourceRef,
    owner_uid: &ResourceUid,
    owner_revision: ZoneRevision,
    owner_generation: ResourceGeneration,
    current_revision: u64,
    ordinal: u32,
) -> Result<(), StoreError> {
    if mutation.target.resource_type().as_str() != PROCESS_RESOURCE_TYPE
        || fence.resource_uid != *owner_uid
        || fence.resource_revision != owner_revision
    {
        return Err(conflict(current_revision, ordinal, "stale-assignment"));
    }
    // The owner fence is captured before the batch starts. A preceding
    // status/finalizer write may rebind the staged assignment revision, but it
    // must not make the already-admitted child fence stale mid-batch.
    let owner_state = current_record_in_write(write, owner_ref)?;
    let Some((owner_record, owner_envelope)) = owner_state.as_ref() else {
        return Err(conflict(
            current_revision,
            ordinal,
            "assignment-owner-missing",
        ));
    };
    if owner_envelope.metadata().uid() != owner_uid
        || owner_envelope.metadata().revision() != owner_revision
        || owner_envelope.metadata().generation() != owner_generation
        || owner_envelope.metadata().zone() != &mutation.zone
        || !owner_record
            .assignment
            .as_ref()
            .is_some_and(|assignment| assignment_matches(assignment, fence))
    {
        return Err(conflict(
            owner_envelope.metadata().revision().get(),
            ordinal,
            "stale-assignment",
        ));
    }
    match mutation.kind {
        ResourceMutationKind::Create => {
            if mutation.owner.as_ref() != Some(owner_ref) {
                return Err(conflict(
                    owner_envelope.metadata().revision().get(),
                    ordinal,
                    "owner-child-binding-mismatch",
                ));
            }
        }
        ResourceMutationKind::UpdateSpec | ResourceMutationKind::Delete => {
            let Some((child_record, child_envelope)) = current_child else {
                return Err(conflict(
                    owner_envelope.metadata().revision().get(),
                    ordinal,
                    "assignment-resource-missing",
                ));
            };
            if child_envelope.metadata().owner_ref() != Some(owner_ref)
                || child_record.owner_uid.as_deref() != Some(owner_uid.as_str())
            {
                return Err(conflict(
                    child_envelope.metadata().revision().get(),
                    ordinal,
                    "owner-child-binding-mismatch",
                ));
            }
        }
        ResourceMutationKind::UpdateStatus
        | ResourceMutationKind::UpdateMetadata
        | ResourceMutationKind::UpdateFinalizers => {
            return Err(authorization_denied(current_revision));
        }
    }
    Ok(())
}

fn validate_prepared_payloads(verified: &VerifiedWrite) -> Result<(), StoreError> {
    for prepared in &verified.mutations {
        validate_prepared_source_digest(prepared)?;
    }
    Ok(())
}

fn validate_prepared_source_digest(prepared: &VerifiedPreparedMutation) -> Result<(), StoreError> {
    let mutation = prepared.mutation();
    let Some(bytes) = mutation.canonical_resource.as_deref() else {
        if prepared.prepared_payload_digest().is_some() {
            return Err(integrity("mutation-payload-digest-without-body"));
        }
        return Ok(());
    };
    let expected = prepared
        .prepared_payload_digest()
        .ok_or_else(|| integrity("mutation-payload-digest-missing"))?;
    let digest = if mutation.kind == ResourceMutationKind::Create {
        let value = CanonicalJsonValue::parse(bytes)
            .map_err(|_| integrity("stored-resource-envelope-invalid"))?;
        canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &value.to_canonical_bytes())
    } else {
        let envelope = ResourceEnvelope::from_json(bytes)
            .map_err(|_| integrity("stored-resource-envelope-invalid"))?;
        envelope.digest().map_err(integrity)?
    };
    if digest != expected {
        return Err(integrity("mutation-payload-digest-mismatch"));
    }
    Ok(())
}

fn authorization_matches(authorization: &AdmittedAuthorization, mutation: &StoreMutation) -> bool {
    let verb = match mutation.kind {
        ResourceMutationKind::Create => d2b_resource_store::AdmittedVerb::Create,
        ResourceMutationKind::UpdateSpec => d2b_resource_store::AdmittedVerb::UpdateSpec,
        ResourceMutationKind::UpdateStatus => d2b_resource_store::AdmittedVerb::UpdateStatus,
        ResourceMutationKind::UpdateMetadata => d2b_resource_store::AdmittedVerb::UpdateMetadata,
        ResourceMutationKind::UpdateFinalizers => {
            d2b_resource_store::AdmittedVerb::UpdateFinalizers
        }
        ResourceMutationKind::Delete => d2b_resource_store::AdmittedVerb::Delete,
    };
    authorization.targets.iter().any(|target| {
        target.resource_type == *mutation.target.resource_type()
            && target
                .resource_name
                .as_ref()
                .is_none_or(|name| name == mutation.target.name())
            && target.verb == verb
    })
}

fn owner_chain_reaches(
    write: &redb::WriteTransaction,
    staged: &std::collections::BTreeMap<ResourceRef, StagedResourceState>,
    owner_ref: &ResourceRef,
    child_uid: &ResourceUid,
) -> Result<bool, StoreError> {
    let mut current = Some(owner_ref.clone());
    let mut depth = 0_usize;
    let mut visited = std::collections::BTreeSet::new();
    while let Some(resource_ref) = current {
        depth += 1;
        if depth > crate::MAX_OWNER_CHAIN_DEPTH {
            return Err(error(
                StoreErrorKind::ResourceOwnerDepth,
                None,
                "resource-owner-depth",
            ));
        }
        let uid = if let Some(staged_state) = staged.get(&resource_ref) {
            staged_state
                .as_ref()
                .map(|(_, envelope)| envelope.metadata().uid().clone())
        } else {
            current_identity_in_write(write, &resource_ref)?.map(|(uid, _)| uid)
        };
        let Some(uid) = uid else {
            return Ok(false);
        };
        if &uid == child_uid || !visited.insert(uid) {
            return Ok(true);
        }
        current = if let Some(staged_state) = staged.get(&resource_ref) {
            staged_state
                .as_ref()
                .and_then(|(_, envelope)| envelope.metadata().owner_ref().cloned())
        } else {
            current_owner_ref_in_write(write, &resource_ref)?
        };
    }
    Ok(false)
}

fn staged_or_current_record_in_write(
    write: &redb::WriteTransaction,
    staged: &std::collections::BTreeMap<ResourceRef, StagedResourceState>,
    resource_ref: &ResourceRef,
) -> Result<StagedResourceState, StoreError> {
    if let Some(state) = staged.get(resource_ref) {
        return Ok(state.clone());
    }
    current_record_in_write(write, resource_ref)
}

fn current_owner_ref_in_write(
    write: &redb::WriteTransaction,
    resource_ref: &ResourceRef,
) -> Result<Option<ResourceRef>, StoreError> {
    Ok(current_record_in_write(write, resource_ref)?
        .and_then(|(_, envelope)| envelope.metadata().owner_ref().cloned()))
}

fn current_identity_in_write(
    write: &redb::WriteTransaction,
    resource_ref: &ResourceRef,
) -> Result<Option<(ResourceUid, u64)>, StoreError> {
    Ok(
        current_record_in_write(write, resource_ref)?.map(|(_, envelope)| {
            (
                envelope.metadata().uid().clone(),
                envelope.metadata().revision().get(),
            )
        }),
    )
}

fn current_record_in_write(
    write: &redb::WriteTransaction,
    resource_ref: &ResourceRef,
) -> Result<Option<(ResourceRecord, ResourceEnvelope)>, StoreError> {
    let table = write.open_table(RESOURCES).map_err(integrity)?;
    let key = resource_key(resource_ref)?;
    table
        .get(key.as_slice())
        .map_err(integrity)?
        .map(|bytes| {
            let record: ResourceRecord = decode(ValueKind::ResourceRecord, bytes.value())?;
            let envelope = ResourceEnvelope::from_json(&record.canonical_json)
                .map_err(|_| integrity("stored-resource-envelope-invalid"))?;
            Ok((record, envelope))
        })
        .transpose()
}

fn revisions_match(meta: &StoreMeta, snapshot: PolicySnapshot) -> bool {
    meta.policy_revision == snapshot.policy_revision
        && meta.api_catalog_revision == snapshot.api_catalog_revision
        && meta.active_configuration_revision == snapshot.active_configuration_revision.get()
        && meta.controller_generation
            == snapshot
                .controller_generation
                .map(ControllerGeneration::get)
}

pub(crate) fn read_meta_in_write(write: &redb::WriteTransaction) -> Result<StoreMeta, StoreError> {
    let table = write.open_table(STORE_META).map_err(integrity)?;
    let bytes = table
        .get(meta_key().as_slice())
        .map_err(integrity)?
        .ok_or_else(|| integrity("store-meta-missing"))?;
    decode(ValueKind::StoreMetaScalar, bytes.value())
}

fn resolve_uid_in_write(
    write: &redb::WriteTransaction,
    resource_ref: &ResourceRef,
) -> Result<ResourceUid, StoreError> {
    let table = write.open_table(TYPE_INDEX).map_err(integrity)?;
    let key = type_index_key(resource_ref)?;
    let bytes = table
        .get(key.as_slice())
        .map_err(integrity)?
        .ok_or_else(|| {
            error(
                StoreErrorKind::ResourceRefInvalid,
                None,
                "owner-ref-not-found",
            )
        })?;
    let uid: String = decode(ValueKind::TypeIndexRecord, bytes.value())?;
    ResourceUid::parse(uid).map_err(|_| integrity("type-index-uid-invalid"))
}

fn resolve_generation_in_write(
    write: &redb::WriteTransaction,
    resource_ref: &ResourceRef,
) -> Result<ResourceGeneration, StoreError> {
    current_record_in_write(write, resource_ref)?
        .map(|(_, envelope)| envelope.metadata().generation())
        .ok_or_else(|| {
            error(
                StoreErrorKind::ResourceRefInvalid,
                None,
                "owner-ref-not-found",
            )
        })
}

fn insert_resource_and_indexes(
    write: &redb::WriteTransaction,
    resource_ref: &ResourceRef,
    uid: &ResourceUid,
    revision: u64,
    record: &ResourceRecord,
    producer: Option<&ResourceRef>,
) -> Result<(), StoreError> {
    let resource_key = resource_key(resource_ref)?;
    let resource_value = encode(ValueKind::ResourceRecord, record)?;
    write
        .open_table(RESOURCES)
        .map_err(integrity)?
        .insert(resource_key.as_slice(), resource_value.as_slice())
        .map_err(integrity)?;
    let type_key = type_index_key(resource_ref)?;
    let type_value = encode(ValueKind::TypeIndexRecord, &uid.as_str())?;
    write
        .open_table(TYPE_INDEX)
        .map_err(integrity)?
        .insert(type_key.as_slice(), type_value.as_slice())
        .map_err(integrity)?;
    if let Some(owner_uid) = &record.owner_uid {
        let owner_key = encode_key(
            KeySpace::OwnerIndex,
            &[
                KeyComponent::Text(owner_uid),
                KeyComponent::Text(uid.as_str()),
            ],
        )
        .map_err(integrity)?;
        let owner_value = encode(
            ValueKind::OwnerIndexRecord,
            &OwnerIndexRecord {
                resource_type: resource_ref.resource_type().as_str().to_owned(),
                resource_name: resource_ref.name().as_str().to_owned(),
                latest_revision: revision,
            },
        )?;
        write
            .open_table(OWNER_INDEX)
            .map_err(integrity)?
            .insert(owner_key.as_bytes(), owner_value.as_slice())
            .map_err(integrity)?;
    }
    if let Some(producer_ref) = producer {
        let producer_uid = resolve_uid_in_write(write, producer_ref)?;
        let producer_key = encode_key(
            KeySpace::ProducerIndex,
            &[
                KeyComponent::Text(producer_uid.as_str()),
                KeyComponent::Text(uid.as_str()),
            ],
        )
        .map_err(integrity)?;
        let producer_value = encode(
            ValueKind::ProducerIndexRecord,
            &ProducerIndexRecord {
                endpoint_type: resource_ref.resource_type().as_str().to_owned(),
                endpoint_name: resource_ref.name().as_str().to_owned(),
            },
        )?;
        write
            .open_table(PRODUCER_INDEX)
            .map_err(integrity)?
            .insert(producer_key.as_bytes(), producer_value.as_slice())
            .map_err(integrity)?;
    }
    let controller_key = encode_key(
        KeySpace::ControllerIndex,
        &[
            KeyComponent::Text(&record.controller_binding_id),
            KeyComponent::Text(resource_ref.resource_type().as_str()),
            KeyComponent::Text(resource_ref.name().as_str()),
        ],
    )
    .map_err(integrity)?;
    let controller_value = encode(ValueKind::ControllerIndexRecord, &uid.as_str())?;
    write
        .open_table(CONTROLLER_INDEX)
        .map_err(integrity)?
        .insert(controller_key.as_bytes(), controller_value.as_slice())
        .map_err(integrity)?;
    Ok(())
}

fn remove_indexes(
    write: &redb::WriteTransaction,
    resource: &StoredResource,
    record: &ResourceRecord,
    envelope: &ResourceEnvelope,
) -> Result<(), StoreError> {
    write
        .open_table(TYPE_INDEX)
        .map_err(integrity)?
        .remove(type_index_key(&resource.resource_ref)?.as_slice())
        .map_err(integrity)?;
    if let Some(owner_uid) = &record.owner_uid {
        let key = encode_key(
            KeySpace::OwnerIndex,
            &[
                KeyComponent::Text(owner_uid),
                KeyComponent::Text(resource.uid.as_str()),
            ],
        )
        .map_err(integrity)?;
        write
            .open_table(OWNER_INDEX)
            .map_err(integrity)?
            .remove(key.as_bytes())
            .map_err(integrity)?;
    }
    if let Some(producer_ref) = endpoint_producer(envelope)? {
        let producer_uid = resolve_uid_in_write(write, &producer_ref)?;
        let key = encode_key(
            KeySpace::ProducerIndex,
            &[
                KeyComponent::Text(producer_uid.as_str()),
                KeyComponent::Text(resource.uid.as_str()),
            ],
        )
        .map_err(integrity)?;
        write
            .open_table(PRODUCER_INDEX)
            .map_err(integrity)?
            .remove(key.as_bytes())
            .map_err(integrity)?;
    }
    let controller_key = encode_key(
        KeySpace::ControllerIndex,
        &[
            KeyComponent::Text(&record.controller_binding_id),
            KeyComponent::Text(resource.resource_ref.resource_type().as_str()),
            KeyComponent::Text(resource.resource_ref.name().as_str()),
        ],
    )
    .map_err(integrity)?;
    write
        .open_table(CONTROLLER_INDEX)
        .map_err(integrity)?
        .remove(controller_key.as_bytes())
        .map_err(integrity)?;
    Ok(())
}

fn produced_endpoints_remain(
    write: &redb::WriteTransaction,
    producer_uid: &ResourceUid,
) -> Result<bool, StoreError> {
    let table = write.open_table(PRODUCER_INDEX).map_err(integrity)?;
    for row in table.iter().map_err(integrity)? {
        let (key, _) = row.map_err(integrity)?;
        let decoded = DecodedKey::decode(key.value()).map_err(integrity)?;
        let [
            crate::DecodedKeyComponent::Text(indexed_producer_uid),
            crate::DecodedKeyComponent::Text(_),
        ] = decoded.components()
        else {
            return Err(integrity("producer-index-key-shape-invalid"));
        };
        if indexed_producer_uid == producer_uid.as_str() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn endpoint_producer(envelope: &ResourceEnvelope) -> Result<Option<ResourceRef>, StoreError> {
    if envelope.resource_type().as_str() != "Endpoint" {
        return Ok(None);
    }
    match envelope.spec().base().get("producerRef") {
        Some(CanonicalJsonValue::String(reference)) => ResourceRef::parse(reference)
            .map(Some)
            .map_err(|_| integrity("endpoint-producer-ref-invalid")),
        _ => Err(integrity("endpoint-producer-ref-missing")),
    }
}

fn owned_children_remain(
    write: &redb::WriteTransaction,
    target: &ResourceRef,
) -> Result<bool, StoreError> {
    let table = write.open_table(RESOURCES).map_err(integrity)?;
    for row in table.iter().map_err(integrity)? {
        let (_, value) = row.map_err(integrity)?;
        let record: ResourceRecord = decode(ValueKind::ResourceRecord, value.value())?;
        let envelope = ResourceEnvelope::from_json(&record.canonical_json)
            .map_err(|_| integrity("stored-resource-envelope-invalid"))?;
        if envelope.metadata().owner_ref() == Some(target) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn finalize_authorized_mutation(
    prepared: &VerifiedPreparedMutation,
    previous: Option<&ResourceRecord>,
    revision: u64,
    resource_uid: &ResourceUid,
) -> Result<FinalizedMutation, StoreError> {
    let mutation = prepared.mutation();
    let canonical_json = merge_authorized_mutation(prepared, previous, revision)?;
    let envelope = ResourceEnvelope::from_json(&canonical_json)
        .map_err(|_| integrity("stored-resource-envelope-invalid"))?;

    let effective_owner = if matches!(
        mutation.kind,
        ResourceMutationKind::Create | ResourceMutationKind::UpdateMetadata
    ) {
        mutation.owner.clone()
    } else {
        let previous = previous.ok_or_else(|| integrity("mutation-current-resource-missing"))?;
        ResourceEnvelope::from_json(&previous.canonical_json)
            .map_err(|_| integrity("stored-resource-envelope-invalid"))?
            .metadata()
            .owner_ref()
            .cloned()
    };
    if envelope.resource_type() != mutation.target.resource_type()
        || envelope.metadata().name() != mutation.target.name()
        || envelope.metadata().zone() != &mutation.zone
        || envelope.metadata().uid() != resource_uid
        || envelope.metadata().owner_ref() != effective_owner.as_ref()
    {
        return Err(integrity("mutation-resource-identity-mismatch"));
    }

    Ok(FinalizedMutation {
        canonical_json,
        payload_digest: envelope.digest().map_err(integrity)?,
    })
}

fn merge_authorized_mutation(
    prepared: &VerifiedPreparedMutation,
    previous: Option<&ResourceRecord>,
    revision: u64,
) -> Result<Vec<u8>, StoreError> {
    let mutation = prepared.mutation();
    if mutation.kind == ResourceMutationKind::Create {
        let source = mutation
            .canonical_resource
            .as_deref()
            .ok_or_else(|| integrity("mutation-resource-body-missing"))?;
        let mut value = CanonicalJsonValue::parse(source)
            .map_err(|_| integrity("mutation-resource-envelope-invalid"))?;
        let uid = prepared
            .resource_uid()
            .cloned()
            .ok_or_else(|| integrity("mutation-resource-uid-missing"))?;
        let metadata = metadata_object_mut(&mut value)?;
        metadata.insert(
            "name".to_owned(),
            CanonicalJsonValue::String(mutation.target.name().as_str().to_owned()),
        );
        metadata.insert(
            "zone".to_owned(),
            CanonicalJsonValue::String(mutation.zone.as_str().to_owned()),
        );
        metadata.insert(
            "ownerRef".to_owned(),
            mutation
                .owner
                .as_ref()
                .map_or(CanonicalJsonValue::Null, |owner| {
                    CanonicalJsonValue::String(owner.to_canonical_string())
                }),
        );
        metadata.insert(
            "uid".to_owned(),
            CanonicalJsonValue::String(uid.as_str().to_owned()),
        );
        metadata.insert("generation".to_owned(), CanonicalJsonValue::Integer(1));
        metadata.insert(
            "revision".to_owned(),
            CanonicalJsonValue::Integer(
                i64::try_from(revision).map_err(|_| integrity("zone-revision-out-of-range"))?,
            ),
        );
        let now = canonical_timestamp()?;
        metadata.insert(
            "createdAt".to_owned(),
            CanonicalJsonValue::String(now.clone()),
        );
        metadata.insert("updatedAt".to_owned(), CanonicalJsonValue::String(now));
        metadata.insert(
            "finalizers".to_owned(),
            CanonicalJsonValue::Array(Vec::new()),
        );
        metadata.insert("deletionRequestedAt".to_owned(), CanonicalJsonValue::Null);
        metadata.insert(
            "managedBy".to_owned(),
            CanonicalJsonValue::String(
                if mutation.configuration_generation.is_some() {
                    "configuration"
                } else {
                    "api"
                }
                .to_owned(),
            ),
        );
        if let Some(configuration_generation) = mutation.configuration_generation {
            metadata.insert(
                "configurationGeneration".to_owned(),
                CanonicalJsonValue::Integer(
                    i64::try_from(configuration_generation.get())
                        .map_err(|_| integrity("configuration-generation-out-of-range"))?,
                ),
            );
        } else {
            metadata.remove("configurationGeneration");
        }
        for field in ["controllerGeneration", "providerGeneration"] {
            metadata.remove(field);
        }
        let CanonicalJsonValue::Object(root) = &mut value else {
            return Err(integrity("mutation-resource-envelope-invalid"));
        };
        root.insert(
            "type".to_owned(),
            CanonicalJsonValue::String(mutation.target.resource_type().as_str().to_owned()),
        );
        let canonical = value.to_canonical_bytes();
        let envelope = ResourceEnvelope::from_json(&canonical)
            .map_err(|_| integrity("mutation-resource-envelope-invalid"))?;
        if envelope.metadata().uid() != &uid {
            return Err(integrity("mutation-resource-uid-mismatch"));
        }
        return Ok(canonical);
    }

    let previous = previous.ok_or_else(|| integrity("mutation-current-resource-missing"))?;
    let mut stored = CanonicalJsonValue::parse(&previous.canonical_json)
        .map_err(|_| integrity("stored-resource-envelope-invalid"))?;
    match mutation.kind {
        ResourceMutationKind::UpdateSpec => {
            let caller = mutation_body_object(mutation)?;
            replace_layer(&mut stored, &caller, "spec")?;
            bump_generation(&mut stored)?;
        }
        ResourceMutationKind::UpdateStatus => {
            let caller = mutation_body_object(mutation)?;
            replace_layer(&mut stored, &caller, "status")?;
        }
        ResourceMutationKind::UpdateMetadata => {
            let caller = mutation_body_object(mutation)?;
            let caller_metadata = caller
                .get("metadata")
                .and_then(|value| match value {
                    CanonicalJsonValue::Object(value) => Some(value),
                    _ => None,
                })
                .ok_or_else(|| integrity("mutation-resource-metadata-missing"))?;
            let stored_metadata = metadata_object_mut(&mut stored)?;
            for field in ["ownerRef", "labels", "annotations"] {
                match caller_metadata.get(field) {
                    Some(value) => {
                        stored_metadata.insert(field.to_owned(), value.clone());
                    }
                    None => {
                        stored_metadata.remove(field);
                    }
                }
            }
        }
        ResourceMutationKind::UpdateFinalizers => {
            apply_finalizer_delta(&mut stored, mutation)?;
        }
        ResourceMutationKind::Create | ResourceMutationKind::Delete => {
            unreachable!("create and delete have dedicated transitions")
        }
    }
    let metadata = metadata_object_mut(&mut stored)?;
    metadata.insert(
        "revision".to_owned(),
        CanonicalJsonValue::Integer(
            i64::try_from(revision).map_err(|_| integrity("zone-revision-out-of-range"))?,
        ),
    );
    metadata.insert(
        "updatedAt".to_owned(),
        CanonicalJsonValue::String(canonical_timestamp()?),
    );
    Ok(stored.to_canonical_bytes())
}

fn merge_deletion_request(bytes: &[u8], revision: u64) -> Result<Vec<u8>, StoreError> {
    let mut value = CanonicalJsonValue::parse(bytes)
        .map_err(|_| integrity("stored-resource-envelope-invalid"))?;
    let timestamp = canonical_timestamp()?;
    let metadata = metadata_object_mut(&mut value)?;
    metadata.insert(
        "deletionRequestedAt".to_owned(),
        CanonicalJsonValue::String(timestamp.clone()),
    );
    metadata.insert(
        "updatedAt".to_owned(),
        CanonicalJsonValue::String(timestamp),
    );
    metadata.insert(
        "revision".to_owned(),
        CanonicalJsonValue::Integer(
            i64::try_from(revision).map_err(|_| integrity("zone-revision-out-of-range"))?,
        ),
    );
    Ok(value.to_canonical_bytes())
}

fn mutation_body_object(
    mutation: &StoreMutation,
) -> Result<std::collections::BTreeMap<String, CanonicalJsonValue>, StoreError> {
    let bytes = mutation
        .canonical_resource
        .as_deref()
        .ok_or_else(|| integrity("mutation-resource-body-missing"))?;
    let value = CanonicalJsonValue::parse(bytes)
        .map_err(|_| integrity("mutation-resource-envelope-invalid"))?;
    let CanonicalJsonValue::Object(root) = value else {
        return Err(integrity("mutation-resource-envelope-invalid"));
    };
    Ok(root)
}

fn replace_layer(
    stored: &mut CanonicalJsonValue,
    caller: &std::collections::BTreeMap<String, CanonicalJsonValue>,
    layer: &str,
) -> Result<(), StoreError> {
    let CanonicalJsonValue::Object(root) = stored else {
        return Err(integrity("stored-resource-envelope-invalid"));
    };
    let value = caller
        .get(layer)
        .cloned()
        .ok_or_else(|| integrity("mutation-authorized-layer-missing"))?;
    root.insert(layer.to_owned(), value);
    Ok(())
}

fn metadata_object_mut(
    value: &mut CanonicalJsonValue,
) -> Result<&mut std::collections::BTreeMap<String, CanonicalJsonValue>, StoreError> {
    let CanonicalJsonValue::Object(root) = value else {
        return Err(integrity("mutation-resource-envelope-invalid"));
    };
    let Some(CanonicalJsonValue::Object(metadata)) = root.get_mut("metadata") else {
        return Err(integrity("mutation-resource-metadata-missing"));
    };
    Ok(metadata)
}

fn bump_generation(value: &mut CanonicalJsonValue) -> Result<(), StoreError> {
    let metadata = metadata_object_mut(value)?;
    let generation = match metadata.get("generation") {
        Some(CanonicalJsonValue::Integer(generation)) => *generation,
        _ => return Err(integrity("stored-resource-generation-invalid")),
    };
    metadata.insert(
        "generation".to_owned(),
        CanonicalJsonValue::Integer(
            generation
                .checked_add(1)
                .ok_or_else(|| integrity("resource-generation-exhausted"))?,
        ),
    );
    Ok(())
}

fn apply_finalizer_delta(
    value: &mut CanonicalJsonValue,
    mutation: &StoreMutation,
) -> Result<(), StoreError> {
    let metadata = metadata_object_mut(value)?;
    let Some(CanonicalJsonValue::Array(current)) = metadata.get("finalizers") else {
        return Err(integrity("stored-resource-finalizers-invalid"));
    };
    let mut finalizers = current
        .iter()
        .map(|value| match value {
            CanonicalJsonValue::String(value) => FinalizerId::parse(value.clone())
                .map_err(|_| integrity("stored-resource-finalizers-invalid")),
            _ => Err(integrity("stored-resource-finalizers-invalid")),
        })
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    for finalizer in &mutation.remove_finalizers {
        finalizers.remove(finalizer);
    }
    finalizers.extend(mutation.add_finalizers.iter().cloned());
    if finalizers.len() > d2b_contracts_resource::v3::resource::MAX_FINALIZERS {
        return Err(error(
            StoreErrorKind::ResourceSchemaInvalid,
            None,
            "too-many-finalizers",
        ));
    }
    metadata.insert(
        "finalizers".to_owned(),
        CanonicalJsonValue::Array(
            finalizers
                .into_iter()
                .map(|finalizer| CanonicalJsonValue::String(finalizer.to_canonical_string()))
                .collect(),
        ),
    );
    Ok(())
}

fn deletion_requested(bytes: &[u8]) -> Result<bool, StoreError> {
    let value = CanonicalJsonValue::parse(bytes)
        .map_err(|_| integrity("stored-resource-envelope-invalid"))?;
    let CanonicalJsonValue::Object(root) = value else {
        return Err(integrity("stored-resource-envelope-invalid"));
    };
    let Some(CanonicalJsonValue::Object(metadata)) = root.get("metadata") else {
        return Err(integrity("stored-resource-metadata-missing"));
    };
    match metadata.get("deletionRequestedAt") {
        Some(CanonicalJsonValue::Null) => Ok(false),
        Some(CanonicalJsonValue::String(value)) => {
            Timestamp::parse(value.clone()).map_err(integrity)?;
            Ok(true)
        }
        _ => Err(integrity("stored-resource-deletion-state-invalid")),
    }
}

fn has_finalizers(bytes: &[u8]) -> Result<bool, StoreError> {
    let value = CanonicalJsonValue::parse(bytes)
        .map_err(|_| integrity("stored-resource-envelope-invalid"))?;
    let CanonicalJsonValue::Object(root) = value else {
        return Err(integrity("stored-resource-envelope-invalid"));
    };
    let Some(CanonicalJsonValue::Object(metadata)) = root.get("metadata") else {
        return Err(integrity("stored-resource-metadata-missing"));
    };
    match metadata.get("finalizers") {
        Some(CanonicalJsonValue::Array(values)) => Ok(!values.is_empty()),
        _ => Err(integrity("stored-resource-finalizers-invalid")),
    }
}

fn parse_optional_uid(value: Option<&str>) -> Result<Option<ResourceUid>, StoreError> {
    value
        .map(|value| ResourceUid::parse(value.to_owned()).map_err(integrity))
        .transpose()
}

fn mint_resource_uid() -> Result<ResourceUid, StoreError> {
    use std::io::Read as _;

    let mut bytes = [0_u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut bytes))
        .map_err(|_| integrity("resource-uid-entropy-unavailable"))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let rendered = format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    );
    ResourceUid::parse(rendered).map_err(|_| integrity("resource-uid-mint-invalid"))
}

fn canonical_timestamp() -> Result<String, StoreError> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| integrity("system-clock-invalid"))?;
    let seconds = elapsed.as_secs();
    let days = i64::try_from(seconds / 86_400).map_err(integrity)?;
    let seconds_of_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    let rendered = format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{:03}Z",
        elapsed.subsec_millis()
    );
    Timestamp::parse(rendered.clone()).map_err(integrity)?;
    Ok(rendered)
}

fn civil_from_days(days_since_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if month <= 2 { y + 1 } else { y } as i32;
    (year, month, day)
}

pub(crate) fn stored_resource(
    zone: &ZoneId,
    resource_ref: &ResourceRef,
    record: &ResourceRecord,
) -> Result<StoredResource, StoreError> {
    let envelope = ResourceEnvelope::from_json(&record.canonical_json)
        .map_err(|_| integrity("stored-resource-envelope-invalid"))?;
    let owner_uid = record
        .owner_uid
        .as_deref()
        .map(|value| {
            ResourceUid::parse(value.to_owned())
                .map_err(|_| integrity("stored-resource-owner-uid-invalid"))
        })
        .transpose()?;
    let owner_generation = record
        .owner_generation
        .map(|value| {
            ResourceGeneration::new(value)
                .map_err(|_| integrity("stored-resource-owner-generation-invalid"))
        })
        .transpose()?;
    Ok(StoredResource {
        resource_ref: resource_ref.clone(),
        zone: zone.clone(),
        uid: envelope.metadata().uid().clone(),
        owner_uid,
        owner_generation,
        generation: envelope.metadata().generation(),
        revision: envelope.metadata().revision(),
        canonical_json: record.canonical_json.clone(),
        payload_digest: record.payload_digest.clone(),
    })
}

fn controller_binding_id(
    envelope: &ResourceEnvelope,
    assignment: Option<&AssignmentRecord>,
) -> String {
    if let Some(assignment) = assignment {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(assignment.controller_role.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(assignment.target.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&assignment.epoch.to_be_bytes());
        return canonical_digest("d2b:v3:assignment-binding", &bytes);
    }
    envelope.spec().provider_ref().cloned().map_or_else(
        || envelope.resource_type().as_str().to_owned(),
        |provider| provider.to_canonical_string(),
    )
}

fn assignment_record(
    fence: &ResourceAssignmentFence,
    uid: &ResourceUid,
    new_revision: u64,
    current_resource_revision: Option<ZoneRevision>,
) -> Result<AssignmentRecord, StoreError> {
    if fence.epoch == 0
        || fence.resource_uid != *uid
        || current_resource_revision != Some(fence.resource_revision)
        || fence.controller_role.resource_type().as_str() != PROCESS_RESOURCE_TYPE
        || !matches!(
            fence.target.resource_type().as_str(),
            "Zone" | "Host" | "Guest"
        )
    {
        return Err(integrity("assignment-fence-invalid"));
    }
    Ok(AssignmentRecord {
        resource_uid: fence.resource_uid.as_str().to_owned(),
        resource_revision: new_revision,
        provider_generation: fence.provider_generation.get(),
        controller_generation: fence.controller_generation.get(),
        controller_role: fence.controller_role.to_canonical_string(),
        target: fence.target.to_canonical_string(),
        session_generation: fence.session_generation.get(),
        epoch: fence.epoch,
        phase: "assigned".to_owned(),
    })
}

pub(crate) fn assignment_fence(
    record: &AssignmentRecord,
) -> Result<ResourceAssignmentFence, StoreError> {
    if record.phase != "assigned" {
        return Err(integrity("stored-assignment-not-active"));
    }
    Ok(ResourceAssignmentFence {
        resource_uid: ResourceUid::parse(record.resource_uid.clone())
            .map_err(|_| integrity("stored-assignment-invalid"))?,
        resource_revision: ZoneRevision::new(record.resource_revision),
        provider_generation: ResourceGeneration::new(record.provider_generation)
            .map_err(|_| integrity("stored-assignment-invalid"))?,
        controller_generation: ControllerGeneration::new(record.controller_generation)
            .map_err(|_| integrity("stored-assignment-invalid"))?,
        controller_role: ResourceRef::parse(&record.controller_role)
            .map_err(|_| integrity("stored-assignment-invalid"))?,
        target: ResourceRef::parse(&record.target)
            .map_err(|_| integrity("stored-assignment-invalid"))?,
        session_generation: ReconnectGeneration::new(record.session_generation)
            .map_err(|_| integrity("stored-assignment-invalid"))?,
        epoch: record.epoch,
        scope: ResourceAssignmentScope::Primary,
    })
}

fn assignment_matches(record: &AssignmentRecord, fence: &ResourceAssignmentFence) -> bool {
    record.resource_uid == fence.resource_uid.as_str()
        && record.provider_generation == fence.provider_generation.get()
        && record.controller_generation == fence.controller_generation.get()
        && record.controller_role == fence.controller_role.to_canonical_string()
        && record.target == fence.target.to_canonical_string()
        && record.session_generation == fence.session_generation.get()
        && record.epoch == fence.epoch
        && record.phase == "assigned"
}

fn assignment_rebound_to_revision(
    assignment: &AssignmentRecord,
    revision: u64,
) -> AssignmentRecord {
    let mut rebound = assignment.clone();
    rebound.resource_revision = revision;
    rebound
}

fn assignment_replacement_allowed(
    record: &AssignmentRecord,
    fence: &ResourceAssignmentFence,
) -> bool {
    // Core's registry makes drain/release the authority for a newer epoch.
    // The store serializes that successor with the resource write, replacing
    // the old assignment before either writer can observe a later revision.
    record.resource_uid == fence.resource_uid.as_str() && fence.epoch > record.epoch
}

fn operation_digests(verified: &VerifiedWrite) -> Result<[String; 2], StoreError> {
    Ok([
        operation_digest(verified)?,
        legacy_operation_digest(verified)?,
    ])
}

fn operation_digest(verified: &VerifiedWrite) -> Result<String, StoreError> {
    use sha2::{Digest, Sha256};

    let mut digest = Sha256::new();
    digest_field(&mut digest, verified.operation.operation_id.as_bytes())?;
    digest_optional_field(
        &mut digest,
        verified
            .operation
            .idempotency_key
            .as_deref()
            .map(str::as_bytes),
    )?;
    digest_field(&mut digest, verified.authorization.zone.as_str().as_bytes())?;
    digest_field(
        &mut digest,
        verified
            .authorization
            .subject_ref
            .to_canonical_string()
            .as_bytes(),
    )?;
    digest.update(verified.authorization.subject_uid.as_str().as_bytes());
    digest.update(
        u32::try_from(verified.mutations.len())
            .map_err(|_| integrity("operation-request-too-large"))?
            .to_be_bytes(),
    );
    for mutation in &verified.mutations {
        let prepared = mutation.mutation();
        digest_field(&mut digest, prepared.zone.as_str().as_bytes())?;
        digest_field(
            &mut digest,
            prepared.target.to_canonical_string().as_bytes(),
        )?;
        digest.update([mutation_kind_discriminant(prepared.kind)]);
        match prepared.expected {
            ExpectedRevision::CreateAbsent => digest.update([0]),
            ExpectedRevision::Exact(revision) => {
                digest.update([1]);
                digest.update(revision.get().to_be_bytes());
            }
        }
        digest_optional_field(
            &mut digest,
            prepared
                .expected_uid
                .as_ref()
                .map(|uid| uid.as_str().as_bytes()),
        )?;
        if let Some(fence) = &prepared.assignment {
            digest.update([1]);
            digest_field(&mut digest, fence.resource_uid.as_str().as_bytes())?;
            digest.update(fence.resource_revision.get().to_be_bytes());
            digest.update(fence.provider_generation.get().to_be_bytes());
            digest.update(fence.controller_generation.get().to_be_bytes());
            digest_field(
                &mut digest,
                fence.controller_role.to_canonical_string().as_bytes(),
            )?;
            digest_field(&mut digest, fence.target.to_canonical_string().as_bytes())?;
            digest.update(fence.session_generation.get().to_be_bytes());
            digest.update(fence.epoch.to_be_bytes());
            match &fence.scope {
                ResourceAssignmentScope::Primary => {}
                ResourceAssignmentScope::OwnerChild {
                    owner_ref,
                    owner_uid,
                    owner_revision,
                    owner_generation,
                } => {
                    digest.update([1]);
                    digest_field(&mut digest, owner_ref.to_canonical_string().as_bytes())?;
                    digest_field(&mut digest, owner_uid.as_str().as_bytes())?;
                    digest.update(owner_revision.get().to_be_bytes());
                    digest.update(owner_generation.get().to_be_bytes());
                }
            }
        } else {
            digest.update([0]);
        }
        digest_optional_field(
            &mut digest,
            prepared
                .owner
                .as_ref()
                .map(|owner| owner.to_canonical_string())
                .as_deref()
                .map(str::as_bytes),
        )?;
        let request_body = canonical_request_body(prepared)?;
        digest_optional_field(&mut digest, request_body.as_deref())?;
        digest_finalizers(&mut digest, &prepared.add_finalizers)?;
        digest_finalizers(&mut digest, &prepared.remove_finalizers)?;
        digest.update([u8::from(prepared.wait_for_reconcile)]);
        digest_optional_u64(&mut digest, prepared.reconcile_deadline_ms);
        if prepared.kind != ResourceMutationKind::Create {
            digest_optional_field(
                &mut digest,
                mutation.resource_uid().map(|uid| uid.as_str().as_bytes()),
            )?;
        }
        // A create body is normalized above before fingerprinting, so its
        // supplied digest may include a store-minted UID and is intentionally
        // ignored. A body-less create still needs the caller-supplied digest
        // in the request fingerprint so it cannot replay a different request.
        if prepared.kind != ResourceMutationKind::Create
            || mutation.mutation.canonical_resource.is_none()
        {
            digest_optional_field(
                &mut digest,
                mutation.prepared_payload_digest().map(str::as_bytes),
            )?;
        }
    }
    Ok(format!("sha256:{:x}", digest.finalize()))
}

/// The request fingerprint used before the U4 durability changes.  Durable
/// operation rows did not carry an algorithm tag, so retries must compare
/// against this shape as well as the current fingerprint.
fn legacy_operation_digest(verified: &VerifiedWrite) -> Result<String, StoreError> {
    use sha2::{Digest, Sha256};

    let mut digest = Sha256::new();
    digest_field(&mut digest, verified.operation.operation_id.as_bytes())?;
    digest_optional_field(
        &mut digest,
        verified
            .operation
            .idempotency_key
            .as_deref()
            .map(str::as_bytes),
    )?;
    digest_field(&mut digest, verified.operation.correlation_id.as_bytes())?;
    digest_optional_field(
        &mut digest,
        verified.operation.trace_id.as_deref().map(str::as_bytes),
    )?;
    digest.update(verified.operation.deadline_ms.to_be_bytes());
    digest_field(&mut digest, verified.authorization.zone.as_str().as_bytes())?;
    digest_field(
        &mut digest,
        verified
            .authorization
            .subject_ref
            .to_canonical_string()
            .as_bytes(),
    )?;
    digest.update(verified.authorization.subject_uid.as_str().as_bytes());
    digest.update(verified.policy_snapshot.policy_revision.to_be_bytes());
    digest.update(verified.policy_snapshot.api_catalog_revision.to_be_bytes());
    digest.update(
        verified
            .policy_snapshot
            .active_configuration_revision
            .get()
            .to_be_bytes(),
    );
    digest_optional_u64(
        &mut digest,
        verified
            .policy_snapshot
            .controller_generation
            .map(ControllerGeneration::get),
    );
    digest.update(
        u32::try_from(verified.mutations.len())
            .map_err(|_| integrity("operation-request-too-large"))?
            .to_be_bytes(),
    );
    for mutation in &verified.mutations {
        let prepared = mutation.mutation();
        digest_field(&mut digest, prepared.zone.as_str().as_bytes())?;
        digest_field(
            &mut digest,
            prepared.target.to_canonical_string().as_bytes(),
        )?;
        digest.update([mutation_kind_discriminant(prepared.kind)]);
        match prepared.expected {
            ExpectedRevision::CreateAbsent => digest.update([0]),
            ExpectedRevision::Exact(revision) => {
                digest.update([1]);
                digest.update(revision.get().to_be_bytes());
            }
        }
        digest_optional_field(
            &mut digest,
            prepared
                .expected_uid
                .as_ref()
                .map(|uid| uid.as_str().as_bytes()),
        )?;
        digest_optional_field(
            &mut digest,
            prepared
                .owner
                .as_ref()
                .map(|owner| owner.to_canonical_string())
                .as_deref()
                .map(str::as_bytes),
        )?;
        let request_body = canonical_request_body(prepared)?;
        digest_optional_field(&mut digest, request_body.as_deref())?;
        digest_finalizers(&mut digest, &prepared.add_finalizers)?;
        digest_finalizers(&mut digest, &prepared.remove_finalizers)?;
        digest.update([u8::from(prepared.wait_for_reconcile)]);
        digest_optional_u64(&mut digest, prepared.reconcile_deadline_ms);
        if prepared.kind != ResourceMutationKind::Create {
            digest_optional_field(
                &mut digest,
                mutation.resource_uid().map(|uid| uid.as_str().as_bytes()),
            )?;
            digest_optional_field(
                &mut digest,
                mutation.prepared_payload_digest().map(str::as_bytes),
            )?;
        }
    }
    Ok(format!("sha256:{:x}", digest.finalize()))
}

fn digest_field(digest: &mut sha2::Sha256, bytes: &[u8]) -> Result<(), StoreError> {
    use sha2::Digest;
    digest.update(
        u32::try_from(bytes.len())
            .map_err(|_| integrity("operation-request-too-large"))?
            .to_be_bytes(),
    );
    digest.update(bytes);
    Ok(())
}

fn digest_optional_field(
    digest: &mut sha2::Sha256,
    bytes: Option<&[u8]>,
) -> Result<(), StoreError> {
    use sha2::Digest;
    match bytes {
        Some(bytes) => {
            digest.update([1]);
            digest_field(digest, bytes)
        }
        None => {
            digest.update([0]);
            Ok(())
        }
    }
}

fn digest_optional_u64(digest: &mut sha2::Sha256, value: Option<u64>) {
    use sha2::Digest;
    match value {
        Some(value) => {
            digest.update([1]);
            digest.update(value.to_be_bytes());
        }
        None => digest.update([0]),
    }
}

fn digest_finalizers(
    digest: &mut sha2::Sha256,
    finalizers: &[FinalizerId],
) -> Result<(), StoreError> {
    use sha2::Digest;
    digest.update(
        u32::try_from(finalizers.len())
            .map_err(|_| integrity("operation-request-too-large"))?
            .to_be_bytes(),
    );
    for finalizer in finalizers {
        digest_field(digest, finalizer.as_str().as_bytes())?;
    }
    Ok(())
}

fn canonical_request_body(mutation: &StoreMutation) -> Result<Option<Vec<u8>>, StoreError> {
    let Some(bytes) = mutation.canonical_resource.as_deref() else {
        return Ok(None);
    };
    if mutation.kind != ResourceMutationKind::Create {
        return Ok(Some(bytes.to_vec()));
    }
    // Request fingerprinting runs before payload validation. If the body is
    // malformed, hash its bounded raw bytes so an existing terminal row can
    // still be compared and replayed instead of being revalidated first.
    let mut value = match CanonicalJsonValue::parse(bytes) {
        Ok(value) => value,
        Err(_) => return Ok(Some(bytes.to_vec())),
    };
    let metadata = match metadata_object_mut(&mut value) {
        Ok(metadata) => metadata,
        Err(_) => return Ok(Some(bytes.to_vec())),
    };
    for field in [
        "uid",
        "generation",
        "revision",
        "createdAt",
        "updatedAt",
        "finalizers",
        "deletionRequestedAt",
        "managedBy",
        "configurationGeneration",
        "controllerGeneration",
        "providerGeneration",
    ] {
        metadata.remove(field);
    }
    Ok(Some(value.to_canonical_bytes()))
}

const fn mutation_kind_discriminant(kind: ResourceMutationKind) -> u8 {
    match kind {
        ResourceMutationKind::Create => 0,
        ResourceMutationKind::UpdateSpec => 1,
        ResourceMutationKind::UpdateStatus => 2,
        ResourceMutationKind::UpdateMetadata => 3,
        ResourceMutationKind::UpdateFinalizers => 4,
        ResourceMutationKind::Delete => 5,
    }
}

pub(crate) fn resource_key(resource_ref: &ResourceRef) -> Result<Vec<u8>, StoreError> {
    encode_key(
        KeySpace::Resources,
        &[
            KeyComponent::Text(resource_ref.resource_type().as_str()),
            KeyComponent::Text(resource_ref.name().as_str()),
        ],
    )
    .map(|key| key.into_bytes())
    .map_err(integrity)
}

pub(crate) fn type_index_key(resource_ref: &ResourceRef) -> Result<Vec<u8>, StoreError> {
    encode_key(
        KeySpace::TypeIndex,
        &[
            KeyComponent::Text(resource_ref.resource_type().as_str()),
            KeyComponent::Text(resource_ref.name().as_str()),
        ],
    )
    .map(|key| key.into_bytes())
    .map_err(integrity)
}

pub(crate) fn revision_key(revision: u64) -> Result<Vec<u8>, StoreError> {
    encode_key(KeySpace::RevisionLog, &[KeyComponent::U64(revision)])
        .map(|key| key.into_bytes())
        .map_err(integrity)
}

fn operation_key(operation_id: &str) -> Result<Vec<u8>, StoreError> {
    encode_key(KeySpace::Operations, &[KeyComponent::Text(operation_id)])
        .map(|key| key.into_bytes())
        .map_err(integrity)
}

pub(crate) fn meta_key() -> Vec<u8> {
    encode_key(KeySpace::StoreMeta, &[KeyComponent::Text("store")])
        .expect("the fixed store-meta key is valid")
        .into_bytes()
}

pub(crate) fn encode<T: Serialize>(kind: ValueKind, value: &T) -> Result<Vec<u8>, StoreError> {
    let json = d2b_contracts_resource::v3::canonical_json_bytes(value).map_err(integrity)?;
    encode_value(kind, &json)
        .map(|value| value.into_bytes())
        .map_err(integrity)
}

pub(crate) fn decode<T>(kind: ValueKind, bytes: &[u8]) -> Result<T, StoreError>
where
    T: for<'de> Deserialize<'de>,
{
    let decoded = crate::DecodedValue::decode(bytes).map_err(integrity)?;
    if decoded.kind() != kind {
        return Err(integrity("table-value-kind-mismatch"));
    }
    serde_json::from_slice(decoded.canonical_json()).map_err(integrity)
}

pub(crate) fn integrity<T>(detail: T) -> StoreError
where
    T: core::fmt::Display + 'static,
{
    let reason = (&detail as &dyn std::any::Any)
        .downcast_ref::<&'static str>()
        .copied()
        .unwrap_or("redb-engine-failure");
    error(StoreErrorKind::StoreIntegrityFailure, None, reason)
}

pub(crate) fn integrity_reason(reason: &'static str) -> StoreError {
    error(StoreErrorKind::StoreIntegrityFailure, None, reason)
}

pub(crate) fn durability_failure(_detail: impl core::fmt::Display) -> StoreError {
    eprintln!("redb durability failure: {_detail}");
    integrity_reason("redb-durability-failure")
}

pub(crate) fn quarantined() -> StoreError {
    quarantined_reason("redb-store-quarantined")
}

pub(crate) fn quarantined_reason(reason: &'static str) -> StoreError {
    error(StoreErrorKind::StoreQuarantined, None, reason)
}

pub(crate) fn set_full_durability(write: &mut redb::WriteTransaction) -> Result<(), StoreError> {
    write
        .set_durability(Durability::Immediate)
        .map_err(integrity)
}

pub(crate) fn backpressure() -> StoreError {
    error(
        StoreErrorKind::StoreBackpressure,
        None,
        "redb-store-backpressure",
    )
}

pub(crate) fn timeout() -> StoreError {
    error(StoreErrorKind::Timeout, None, "redb-read-lifetime-exceeded")
}

pub(crate) fn revision_expired(current_revision: u64) -> StoreError {
    error(
        StoreErrorKind::RevisionExpired,
        Some(ZoneRevision::new(current_revision)),
        "redb-revision-expired",
    )
}

fn authorization_denied(current_revision: u64) -> StoreError {
    StoreError::new(
        StoreErrorKind::AuthorizationDenied,
        Some(ZoneRevision::new(current_revision)),
        None,
        RetryClass::Reauthorize,
        "store-generation-recheck-failed",
    )
}

fn conflict(current_revision: u64, ordinal: u32, reason: &'static str) -> StoreError {
    StoreError::batch_conflict(
        ZoneRevision::new(current_revision),
        MutationOrdinal::new(ordinal)
            .unwrap_or_else(|_| MutationOrdinal::new(0).expect("zero is a valid mutation ordinal")),
        RetryClass::Reauthorize,
        reason,
    )
}

fn error(
    kind: StoreErrorKind,
    current_revision: Option<ZoneRevision>,
    reason: &'static str,
) -> StoreError {
    StoreError::new(kind, current_revision, None, RetryClass::Never, reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use d2b_contracts_resource::v3::identity::ReconnectGeneration;
    use d2b_contracts_resource::v3::{
        ConfigurationGeneration, ResourceGeneration, ResourceName, ResourcePhase, ResourceTypeName,
        Timestamp,
    };
    use d2b_resource_store::{
        AdmittedAuthorizationTarget, AdmittedVerb, ResourceAssignmentFence,
        ResourceAssignmentScope, ResourceMutationKind, StoreSlot,
    };
    use redb::ReadableTableMetadata;
    use std::fs::OpenOptions;

    const ENDPOINT_SPEC: &[u8] = br#"{"attachmentPolicy":{"maxAttachments":0,"supported":false},"consumerPolicy":{},"endpointClass":"service","lifecyclePolicy":"recycle-with-producer","locality":"zone-local","producerRef":"Process/wayland-proxy","providerRef":"Provider/display-wayland","purpose":"wayland-control","transport":"opaque-carriage","visibility":"provider"}"#;

    fn endpoint_resource_value(spec: &[u8]) -> CanonicalJsonValue {
        let mut value = CanonicalJsonValue::parse(RESOURCE).unwrap();
        let CanonicalJsonValue::Object(root) = &mut value else {
            unreachable!()
        };
        root.insert(
            "type".to_owned(),
            CanonicalJsonValue::String("Endpoint".to_owned()),
        );
        let CanonicalJsonValue::Object(metadata) = root.get_mut("metadata").unwrap() else {
            unreachable!()
        };
        metadata.insert(
            "name".to_owned(),
            CanonicalJsonValue::String("wayland-endpoint".to_owned()),
        );
        root.insert("spec".to_owned(), CanonicalJsonValue::parse(spec).unwrap());
        value
    }

    const RESOURCE: &[u8] = br#"{"apiVersion":"resources.d2bus.org/v3","metadata":{"configurationGeneration":7,"createdAt":"2026-07-22T00:00:00.000Z","deletionRequestedAt":null,"finalizers":[],"generation":1,"managedBy":"configuration","name":"host-system","ownerRef":null,"revision":1,"uid":"123e4567-e89b-42d3-a456-426614174000","updatedAt":"2026-07-22T00:00:00.000Z","zone":"dev"},"spec":{"providerRef":"Provider/system-core","updatePolicy":{"disruptive":"manual","nonDisruptive":"automatic"}},"status":{"completedAt":null,"conditions":[],"lastReconciledAt":null,"observedGeneration":0,"outcome":null,"phase":"Pending","resource":{},"startedAt":null,"update":{"dependencies":{"count":0,"refs":[]},"disruption":"None","lastAssessedAt":null,"observedGeneration":0,"operationId":null,"owned":{"count":0,"refs":[]},"preserveState":true,"reasons":[],"state":"Unknown","targetGeneration":1}},"type":"Host"}"#;

    fn fixture() -> (tempfile::TempDir, Database, crate::StoreIdentity) {
        let directory = tempfile::tempdir().unwrap();
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(directory.path().join("store.redb"))
            .unwrap();
        let database = Database::builder().create_file(file).unwrap();
        let identity = crate::StoreIdentity::new(
            StoreSlot::new(0).unwrap(),
            ResourceUid::parse("11111111-1111-4111-8111-111111111111").unwrap(),
            ZoneId::parse("dev").unwrap(),
            ResourceUid::parse("22222222-2222-4222-8222-222222222222").unwrap(),
            Timestamp::parse("2026-07-31T00:00:00.000Z").unwrap(),
            PolicySnapshot {
                policy_revision: 7,
                api_catalog_revision: 8,
                active_configuration_revision: ConfigurationGeneration::new(9).unwrap(),
                controller_generation: None,
            },
        );
        initialize(&database, &identity).unwrap();
        (directory, database, identity)
    }

    fn verified(operation_id: &str, mutation: StoreMutation, uid: ResourceUid) -> VerifiedWrite {
        let verb = match mutation.kind {
            ResourceMutationKind::Create => AdmittedVerb::Create,
            ResourceMutationKind::UpdateSpec => AdmittedVerb::UpdateSpec,
            ResourceMutationKind::UpdateStatus => AdmittedVerb::UpdateStatus,
            ResourceMutationKind::UpdateMetadata => AdmittedVerb::UpdateMetadata,
            ResourceMutationKind::UpdateFinalizers => AdmittedVerb::UpdateFinalizers,
            ResourceMutationKind::Delete => AdmittedVerb::Delete,
        };
        let payload_digest = mutation.canonical_resource.as_deref().map(|bytes| {
            ResourceEnvelope::from_json(bytes)
                .unwrap()
                .digest()
                .unwrap()
        });
        let resource_uid = (mutation.kind != ResourceMutationKind::UpdateFinalizers).then_some(uid);
        VerifiedWrite {
            authorization: AdmittedAuthorization {
                zone: ZoneId::parse("dev").unwrap(),
                subject_ref: ResourceRef::parse("Provider/system-core").unwrap(),
                subject_uid: ResourceUid::parse("33333333-3333-4333-8333-333333333333").unwrap(),
                targets: vec![AdmittedAuthorizationTarget {
                    resource_type: mutation.target.resource_type().clone(),
                    resource_name: Some(mutation.target.name().clone()),
                    verb,
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
                idempotency_key: None,
                correlation_id: format!("corr-{operation_id}"),
                trace_id: None,
                deadline_ms: 1_000,
            },
            mutations: vec![VerifiedPreparedMutation {
                mutation,
                resource_uid,
                prepared_payload_digest: payload_digest,
            }],
        }
    }

    fn create_mutation(target: ResourceRef) -> StoreMutation {
        StoreMutation {
            kind: ResourceMutationKind::Create,
            zone: ZoneId::parse("dev").unwrap(),
            target,
            expected: ExpectedRevision::CreateAbsent,
            expected_uid: None,
            owner: None,
            canonical_resource: Some(RESOURCE.to_vec()),
            add_finalizers: Vec::new(),
            remove_finalizers: Vec::new(),
            wait_for_reconcile: false,
            reconcile_deadline_ms: None,
            configuration_generation: None,
            assignment: None,
        }
    }

    fn create_mutation_with_uid(target: ResourceRef, uid: &ResourceUid) -> StoreMutation {
        let mut mutation = create_mutation(target);
        mutation.canonical_resource = Some(
            String::from_utf8(RESOURCE.to_vec())
                .unwrap()
                .replace("123e4567-e89b-42d3-a456-426614174000", uid.as_str())
                .into_bytes(),
        );
        mutation
    }

    fn canonical_resource(value: serde_json::Value) -> Vec<u8> {
        let bytes = serde_json::to_vec(&value).unwrap();
        CanonicalJsonValue::parse(&bytes)
            .unwrap()
            .to_canonical_bytes()
    }

    fn guest_body(name: &str) -> Vec<u8> {
        let mut value: serde_json::Value = serde_json::from_slice(RESOURCE).unwrap();
        value["type"] = serde_json::Value::String("Guest".to_owned());
        value["metadata"]["name"] = serde_json::Value::String(name.to_owned());
        value["spec"] =
            serde_json::to_value(d2b_contracts_resource::v3::guest::GuestSpec::system_default())
                .unwrap();
        canonical_resource(value)
    }

    fn process_body(name: &str, owner: Option<&ResourceRef>) -> Vec<u8> {
        process_body_with_uid(
            name,
            owner,
            &ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap(),
        )
    }

    fn process_body_with_uid(
        name: &str,
        owner: Option<&ResourceRef>,
        uid: &ResourceUid,
    ) -> Vec<u8> {
        let mut value: serde_json::Value = serde_json::from_slice(RESOURCE).unwrap();
        value["type"] = serde_json::Value::String("Process".to_owned());
        value["metadata"]["name"] = serde_json::Value::String(name.to_owned());
        value["metadata"]["uid"] = serde_json::Value::String(uid.as_str().to_owned());
        value["metadata"]["ownerRef"] = owner.map_or(serde_json::Value::Null, |owner| {
            serde_json::Value::String(owner.to_canonical_string())
        });
        let execution = d2b_contracts_resource::v3::process::ExecutionSpec::minimal(
            ResourceRef::parse("Host/host-system").unwrap(),
            d2b_contracts_resource::v3::process::ProcessClass::Service,
            d2b_contracts_resource::v3::execution_policy::BoundedToken::parse("test").unwrap(),
        )
        .unwrap();
        value["spec"] = serde_json::to_value(
            d2b_contracts_resource::v3::process::ProcessSpec::minimal(execution),
        )
        .unwrap();
        canonical_resource(value)
    }

    fn create_mutation_with_body(target: ResourceRef, body: Vec<u8>) -> StoreMutation {
        let mut mutation = create_mutation(target);
        mutation.canonical_resource = Some(body);
        mutation
    }

    fn primary_fence(
        resource_uid: ResourceUid,
        resource_revision: ZoneRevision,
        target: ResourceRef,
    ) -> ResourceAssignmentFence {
        ResourceAssignmentFence {
            resource_uid,
            resource_revision,
            provider_generation: ResourceGeneration::new(2).unwrap(),
            controller_generation: ControllerGeneration::new(3).unwrap(),
            controller_role: ResourceRef::parse("Process/process-controller").unwrap(),
            target,
            session_generation: ReconnectGeneration::new(4).unwrap(),
            epoch: 1,
            scope: ResourceAssignmentScope::Primary,
        }
    }

    fn owner_child_fence(
        owner_ref: ResourceRef,
        owner_uid: ResourceUid,
        owner_revision: ZoneRevision,
        owner_generation: ResourceGeneration,
        target: ResourceRef,
    ) -> ResourceAssignmentFence {
        ResourceAssignmentFence {
            resource_uid: owner_uid.clone(),
            resource_revision: owner_revision,
            provider_generation: ResourceGeneration::new(2).unwrap(),
            controller_generation: ControllerGeneration::new(3).unwrap(),
            controller_role: ResourceRef::parse("Process/process-controller").unwrap(),
            target,
            session_generation: ReconnectGeneration::new(4).unwrap(),
            epoch: 1,
            scope: ResourceAssignmentScope::OwnerChild {
                owner_ref,
                owner_uid,
                owner_revision,
                owner_generation,
            },
        }
    }

    #[test]
    fn stored_resource_retains_the_persisted_owner_generation_fence() {
        let owner_uid = ResourceUid::parse("223e4567-e89b-42d3-a456-426614174001").unwrap();
        let resource = stored_resource(
            &ZoneId::parse("dev").unwrap(),
            &ResourceRef::parse("Volume/runtime-state").unwrap(),
            &ResourceRecord {
                canonical_json: RESOURCE.to_vec(),
                owner_uid: Some(owner_uid.as_str().to_owned()),
                owner_generation: Some(7),
                controller_binding_id: "Provider/volume-local".to_owned(),
                payload_digest: ResourceEnvelope::from_json(RESOURCE)
                    .unwrap()
                    .digest()
                    .unwrap(),
                assignment: None,
            },
        )
        .unwrap();
        assert_eq!(resource.owner_uid, Some(owner_uid));
        assert_eq!(
            resource.owner_generation,
            Some(ResourceGeneration::new(7).unwrap())
        );
    }

    #[test]
    fn controller_session_evidence_update_preserves_the_persisted_owner_incarnation() {
        let (_directory, database, _identity) = fixture();
        let owner = ResourceRef::parse("Guest/owner").unwrap();
        let child = ResourceRef::parse("Process/child").unwrap();
        apply_group(
            &database,
            vec![verified(
                "owner-create",
                create_mutation_with_body(owner.clone(), guest_body("owner")),
                ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap(),
            )],
        )
        .unwrap();

        let child_body = process_body(child.name().as_str(), Some(&owner));
        let mut child_create = create_mutation_with_body(child.clone(), child_body.clone());
        child_create.owner = Some(owner.clone());
        let child_uid =
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        apply_group(
            &database,
            vec![verified("child-create", child_create, child_uid.clone())],
        )
        .unwrap();

        let owner_record = {
            let read = database.begin_read().unwrap();
            let table = read.open_table(RESOURCES).unwrap();
            let value = table
                .get(resource_key(&owner).unwrap().as_slice())
                .unwrap()
                .unwrap();
            decode::<ResourceRecord>(ValueKind::ResourceRecord, value.value()).unwrap()
        };
        let owner_uid = ResourceEnvelope::from_json(&owner_record.canonical_json)
            .unwrap()
            .metadata()
            .uid()
            .clone();

        let mut status_body = CanonicalJsonValue::parse(&child_body).unwrap();
        let CanonicalJsonValue::Object(root) = &mut status_body else {
            unreachable!();
        };
        let CanonicalJsonValue::Object(status) = root.get_mut("status").unwrap() else {
            unreachable!();
        };
        status.insert(
            "phase".to_owned(),
            CanonicalJsonValue::String("Ready".to_owned()),
        );
        let mut status = create_mutation_with_body(child.clone(), status_body.to_canonical_bytes());
        status.kind = ResourceMutationKind::UpdateStatus;
        status.expected = ExpectedRevision::Exact(ZoneRevision::new(2));
        status.expected_uid = Some(child_uid.clone());
        status.owner = None;
        apply_group(
            &database,
            vec![verified("controller-session-evidence", status, child_uid)],
        )
        .unwrap();

        let read = database.begin_read().unwrap();
        let table = read.open_table(RESOURCES).unwrap();
        let value = table
            .get(resource_key(&child).unwrap().as_slice())
            .unwrap()
            .unwrap();
        let child_record: ResourceRecord =
            decode(ValueKind::ResourceRecord, value.value()).unwrap();
        assert_eq!(child_record.owner_uid, Some(owner_uid.as_str().to_owned()));
        assert_eq!(child_record.owner_generation, Some(1));
    }

    fn stored_envelope(database: &Database, target: &ResourceRef) -> ResourceEnvelope {
        let read = database.begin_read().unwrap();
        let table = read.open_table(RESOURCES).unwrap();
        let value = table
            .get(resource_key(target).unwrap().as_slice())
            .unwrap()
            .unwrap();
        let record: ResourceRecord = decode(ValueKind::ResourceRecord, value.value()).unwrap();
        ResourceEnvelope::from_json(&record.canonical_json).unwrap()
    }

    fn rewrite_request_digest(database: &Database, operation_id: &str, request_digest: String) {
        let key = operation_key(operation_id).unwrap();
        let mut write = database.begin_write().unwrap();
        set_full_durability(&mut write).unwrap();
        let mut operation = {
            let table = write.open_table(OPERATIONS).unwrap();
            let value = table.get(key.as_slice()).unwrap().unwrap();
            decode::<OperationRecord>(ValueKind::OperationRecord, value.value()).unwrap()
        };
        operation.request_digest = request_digest;
        let value = encode(ValueKind::OperationRecord, &operation).unwrap();
        write
            .open_table(OPERATIONS)
            .unwrap()
            .insert(key.as_slice(), value.as_slice())
            .unwrap();
        write.commit().unwrap();
    }

    #[test]
    fn configuration_provenance_applies_only_when_creating_a_resource() {
        let (_directory, database, _identity) = fixture();
        let configured_target = ResourceRef::parse("Host/configured").unwrap();
        let configured_uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174010").unwrap();
        let configured_body = String::from_utf8(RESOURCE.to_vec())
            .unwrap()
            .replace("host-system", "configured")
            .into_bytes();
        let mut configured_create =
            create_mutation_with_body(configured_target.clone(), configured_body);
        configured_create.configuration_generation = Some(ConfigurationGeneration::new(9).unwrap());
        apply_group(
            &database,
            vec![verified(
                "create-configured",
                configured_create,
                configured_uid,
            )],
        )
        .unwrap()
        .results[0]
            .as_ref()
            .unwrap();
        let configured = stored_envelope(&database, &configured_target);
        assert_eq!(
            configured.metadata().managed_by(),
            d2b_contracts_resource::v3::ManagedBy::Configuration
        );
        assert_eq!(
            configured.metadata().configuration_generation(),
            Some(ConfigurationGeneration::new(9).unwrap())
        );

        let api_target = ResourceRef::parse("Host/api-owned").unwrap();
        let api_uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174011").unwrap();
        let api_body = String::from_utf8(RESOURCE.to_vec())
            .unwrap()
            .replace("host-system", "api-owned")
            .into_bytes();
        apply_group(
            &database,
            vec![verified(
                "create-api-owned",
                create_mutation_with_body(api_target.clone(), api_body),
                api_uid,
            )],
        )
        .unwrap()
        .results[0]
            .as_ref()
            .unwrap();
        let api = stored_envelope(&database, &api_target);
        let mut update =
            create_mutation_with_body(api_target.clone(), api.canonical_bytes().unwrap());
        update.kind = ResourceMutationKind::UpdateSpec;
        update.expected = ExpectedRevision::Exact(api.metadata().revision());
        update.expected_uid = Some(api.metadata().uid().clone());
        update.configuration_generation = Some(ConfigurationGeneration::new(10).unwrap());
        apply_group(
            &database,
            vec![verified(
                "update-api-owned",
                update,
                api.metadata().uid().clone(),
            )],
        )
        .unwrap()
        .results[0]
            .as_ref()
            .unwrap();
        let updated = stored_envelope(&database, &api_target);
        assert_eq!(
            updated.metadata().managed_by(),
            d2b_contracts_resource::v3::ManagedBy::Api
        );
        assert_eq!(updated.metadata().configuration_generation(), None);
    }

    #[test]
    fn qualified_wayland_validator_accepts_schema_defaults() {
        let policy: WaylandPolicySpec = serde_json::from_value(serde_json::json!({
            "allowGlobals": [],
            "denyGlobals": [],
            "maxVersions": {},
            "dmabufAllow": [],
            "dmabufDeny": [],
            "defaults": {
                "acceleratedRendering": "deny",
                "clipboardBoundary": "virtualize",
                "highRisk": "deny",
                "appDefaults": "deny",
                "offDefaults": "deny",
                "unclassified": "deny"
            }
        }))
        .unwrap();
        assert!(valid_wayland_policy_defaults(&policy.defaults));

        let session: WaylandSessionSpec = serde_json::from_value(serde_json::json!({
            "guestRef": "Guest/guest",
            "hostRef": "Host/host",
            "userRef": "User/alice",
            "policyRef": "display-wayland.d2bus.org.WaylandPolicy/policy",
            "identity": {
                "label": "session",
                "activeColor": "#112233",
                "inactiveColor": "#223344",
                "urgentColor": "#334455",
                "borderEnabled": true,
                "borderWidth": 1,
                "labelEnabled": true,
                "labelText": "session",
                "labelPosition": "top-left"
            },
            "crossDomainTrusted": true,
            "virglVideo": false,
            "filter": {
                "allowGlobals": [],
                "denyGlobals": [],
                "maxVersions": {},
                "dmabufAllow": [],
                "dmabufDeny": [],
                "debugLogging": false
            }
        }))
        .unwrap();
        assert!(valid_wayland_session(session));

        let dmabuf_entry = "a".repeat(63);
        assert!(valid_wayland_filter(
            &[],
            &[],
            &std::collections::BTreeMap::new(),
            std::slice::from_ref(&dmabuf_entry),
            &[],
        ));
        assert!(!valid_wayland_filter(
            &[],
            &[],
            &std::collections::BTreeMap::new(),
            &[format!("{dmabuf_entry}a")],
            &[],
        ));
        assert!(!valid_wayland_filter(
            &[],
            &[],
            &std::collections::BTreeMap::from([("xdg_shell".to_owned(), 0)]),
            &[],
            &[],
        ));
        assert!(valid_wayland_filter(
            &[],
            &[],
            &std::collections::BTreeMap::from([("xdg_shell".to_owned(), 1)]),
            &[],
            &[],
        ));
    }

    #[test]
    fn verified_write_atomically_updates_resource_indexes_revision_and_operation() {
        let (_directory, database, identity) = fixture();
        let target = ResourceRef::parse("Host/host-system").unwrap();
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let outcome = apply_group(
            &database,
            vec![verified(
                "create-host",
                create_mutation(target.clone()),
                uid,
            )],
        )
        .unwrap();
        let result = outcome.results[0].as_ref().unwrap();
        assert_eq!(result.revision, ZoneRevision::new(1));
        assert_eq!(result.resources.len(), 1);
        assert_eq!(result.resources[0].revision, ZoneRevision::new(1));
        assert_eq!(outcome.batch.as_ref().unwrap().revision().get(), 1);

        let read = database.begin_read().unwrap();
        assert_eq!(read.open_table(RESOURCES).unwrap().len().unwrap(), 1);
        assert_eq!(read.open_table(TYPE_INDEX).unwrap().len().unwrap(), 1);
        assert_eq!(read.open_table(CONTROLLER_INDEX).unwrap().len().unwrap(), 1);
        assert_eq!(read.open_table(REVISION_LOG).unwrap().len().unwrap(), 1);
        assert_eq!(read.open_table(OPERATIONS).unwrap().len().unwrap(), 1);
        drop(read);
        assert_eq!(current_meta(&database).unwrap().current_revision, 1);
        assert_eq!(
            validate_identity(&database, &identity).unwrap().zone_name,
            "dev"
        );
    }

    #[test]
    fn valid_pre_u4_digest_replays_original_terminal_outcomes_after_normalization() {
        let (_directory, database, _identity) = fixture();

        let committed_target = ResourceRef::parse("Host/host-system").unwrap();
        let committed_uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let committed = verified(
            "legacy-committed",
            create_mutation_with_uid(committed_target.clone(), &committed_uid),
            committed_uid.clone(),
        );
        let committed_digest = legacy_operation_digest(&committed).unwrap();
        let committed_result = apply_group(&database, vec![committed]).unwrap();
        rewrite_request_digest(&database, "legacy-committed", committed_digest);

        let mut denied = verified(
            "legacy-denied",
            create_mutation_with_uid(committed_target.clone(), &committed_uid),
            committed_uid.clone(),
        );
        denied.policy_snapshot.policy_revision = 999;
        let denied_digest = legacy_operation_digest(&denied).unwrap();
        let denied_result = apply_group(&database, vec![denied]).unwrap();
        rewrite_request_digest(&database, "legacy-denied", denied_digest);

        let mut missing = create_mutation(ResourceRef::parse("Host/missing").unwrap());
        missing.kind = ResourceMutationKind::Delete;
        missing.canonical_resource = None;
        let missing = verified(
            "legacy-error",
            missing,
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174001").unwrap(),
        );
        let missing_digest = legacy_operation_digest(&missing).unwrap();
        let missing_result = apply_group(&database, vec![missing]).unwrap();
        rewrite_request_digest(&database, "legacy-error", missing_digest);

        normalize_audit_outboxes(&database).unwrap();

        let committed_retry = verified(
            "legacy-committed",
            create_mutation_with_uid(
                committed_target.clone(),
                &ResourceUid::parse("123e4567-e89b-42d3-a456-426614174099").unwrap(),
            ),
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174099").unwrap(),
        );
        let replayed_committed = apply_group(&database, vec![committed_retry]).unwrap();
        assert_eq!(replayed_committed.results, committed_result.results);

        let mut denied_retry = verified(
            "legacy-denied",
            create_mutation_with_uid(
                committed_target.clone(),
                &ResourceUid::parse("123e4567-e89b-42d3-a456-426614174099").unwrap(),
            ),
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174099").unwrap(),
        );
        denied_retry.policy_snapshot.policy_revision = 999;
        let replayed_denied = apply_group(&database, vec![denied_retry]).unwrap();
        assert_eq!(
            replayed_denied.results[0]
                .as_ref()
                .unwrap_err()
                .reason_code(),
            "operation-replayed-denied"
        );
        assert_eq!(
            denied_result.results[0].as_ref().unwrap_err().reason_code(),
            "store-generation-recheck-failed"
        );

        let mut missing_retry = create_mutation(ResourceRef::parse("Host/missing").unwrap());
        missing_retry.kind = ResourceMutationKind::Delete;
        missing_retry.canonical_resource = None;
        let missing_retry = verified(
            "legacy-error",
            missing_retry,
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174001").unwrap(),
        );
        let replayed_error = apply_group(&database, vec![missing_retry]).unwrap();
        assert_eq!(
            replayed_error.results[0]
                .as_ref()
                .unwrap_err()
                .reason_code(),
            "resource-not-found"
        );
        assert_eq!(
            missing_result.results[0]
                .as_ref()
                .unwrap_err()
                .reason_code(),
            "resource-not-found"
        );

        let mut mismatched = create_mutation_with_uid(
            committed_target,
            &ResourceUid::parse("123e4567-e89b-42d3-a456-426614174099").unwrap(),
        );
        mismatched.canonical_resource = Some(
            String::from_utf8(mismatched.canonical_resource.take().unwrap())
                .unwrap()
                .replace(
                    "\"nonDisruptive\":\"automatic\"",
                    "\"nonDisruptive\":\"manual\"",
                )
                .into_bytes(),
        );
        let mismatched = verified(
            "legacy-committed",
            mismatched,
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174099").unwrap(),
        );
        let outcome = apply_group(&database, vec![mismatched]).unwrap();
        assert_eq!(
            outcome.results[0].as_ref().unwrap_err().reason_code(),
            "operation-id-reused"
        );
    }

    #[test]
    fn conflicting_create_cannot_mutate_any_table_or_allocate_a_revision() {
        let (_directory, database, _identity) = fixture();
        let target = ResourceRef::parse("Host/host-system").unwrap();
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        apply_group(
            &database,
            vec![verified(
                "create-host",
                create_mutation(target.clone()),
                uid.clone(),
            )],
        )
        .unwrap();
        let outcome = apply_group(
            &database,
            vec![verified("conflict", create_mutation(target), uid)],
        )
        .unwrap();
        assert_eq!(
            outcome.results[0].as_ref().unwrap_err().kind(),
            StoreErrorKind::ResourceAlreadyExists
        );
        assert!(outcome.batch.is_none());
        assert_eq!(current_meta(&database).unwrap().current_revision, 1);
        let read = database.begin_read().unwrap();
        assert_eq!(read.open_table(RESOURCES).unwrap().len().unwrap(), 1);
        assert_eq!(read.open_table(REVISION_LOG).unwrap().len().unwrap(), 1);
        assert_eq!(read.open_table(OPERATIONS).unwrap().len().unwrap(), 2);
    }

    #[test]
    fn generation_recheck_failure_happens_inside_the_write_transaction() {
        let (_directory, database, _identity) = fixture();
        let target = ResourceRef::parse("Host/host-system").unwrap();
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let mut request = verified("stale-policy", create_mutation(target), uid);
        request.policy_snapshot.policy_revision = 99;
        let outcome = apply_group(&database, vec![request]).unwrap();
        assert_eq!(
            outcome.results[0].as_ref().unwrap_err().kind(),
            StoreErrorKind::AuthorizationDenied
        );
        assert_eq!(current_meta(&database).unwrap().current_revision, 0);
        let read = database.begin_read().unwrap();
        assert_eq!(read.open_table(RESOURCES).unwrap().len().unwrap(), 0);
        assert_eq!(read.open_table(OPERATIONS).unwrap().len().unwrap(), 1);
        assert_eq!(read.open_table(REVISION_LOG).unwrap().len().unwrap(), 0);
    }

    #[test]
    fn failed_operation_retry_replays_the_persisted_failure() {
        let (_directory, database, _identity) = fixture();
        let target = ResourceRef::parse("Host/host-system").unwrap();
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let mut request = verified("failed-retry", create_mutation(target), uid);
        request.policy_snapshot.policy_revision = 99;
        let first = apply_group(&database, vec![request]).unwrap();
        assert_eq!(
            first.results[0].as_ref().unwrap_err().kind(),
            StoreErrorKind::AuthorizationDenied
        );

        let target = ResourceRef::parse("Host/host-system").unwrap();
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let mut retry = verified("failed-retry", create_mutation(target), uid);
        retry.policy_snapshot.policy_revision = 99;
        let second = apply_group(&database, vec![retry]).unwrap();
        assert_eq!(
            second.results[0].as_ref().unwrap_err().kind(),
            StoreErrorKind::AuthorizationDenied
        );
    }

    #[test]
    fn assignment_required_failure_replay_remains_a_retryable_conflict() {
        let (_directory, database, _identity) = fixture();
        let target = ResourceRef::parse("Host/host-system").unwrap();
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let seeded = apply_group(
            &database,
            vec![verified(
                "assignment-required-seed",
                create_mutation(target.clone()),
                uid.clone(),
            )],
        )
        .unwrap();
        let uid = seeded.results[0].as_ref().unwrap().resources[0].uid.clone();

        let mut assigned_finalizers = create_mutation(target.clone());
        assigned_finalizers.kind = ResourceMutationKind::UpdateFinalizers;
        assigned_finalizers.expected = ExpectedRevision::Exact(ZoneRevision::new(1));
        assigned_finalizers.expected_uid = Some(uid.clone());
        assigned_finalizers.canonical_resource = None;
        assigned_finalizers.add_finalizers =
            vec![FinalizerId::parse("core.controller-test").unwrap()];
        assigned_finalizers.assignment = Some(primary_fence(
            uid.clone(),
            ZoneRevision::new(1),
            target.clone(),
        ));
        let assigned = apply_group(
            &database,
            vec![verified(
                "assignment-required-install",
                assigned_finalizers,
                uid.clone(),
            )],
        )
        .unwrap();
        assert!(
            assigned.results[0].is_ok(),
            "assignment install failed: {:?}",
            assigned.results[0]
        );

        let mut unassigned_status = create_mutation(target.clone());
        unassigned_status.kind = ResourceMutationKind::UpdateStatus;
        unassigned_status.expected = ExpectedRevision::Exact(ZoneRevision::new(2));
        unassigned_status.expected_uid = Some(uid.clone());
        let first = apply_group(
            &database,
            vec![verified(
                "assignment-required-replay",
                unassigned_status.clone(),
                uid.clone(),
            )],
        )
        .unwrap();
        let first_error = first.results[0].as_ref().unwrap_err();
        assert_eq!(first_error.kind(), StoreErrorKind::ResourceConflict);
        assert_eq!(first_error.reason_code(), "assignment-required");
        assert_eq!(first_error.retry_class(), RetryClass::Reauthorize);

        let second = apply_group(
            &database,
            vec![verified(
                "assignment-required-replay",
                unassigned_status,
                uid,
            )],
        )
        .unwrap();
        let replayed_error = second.results[0].as_ref().unwrap_err();
        assert_eq!(replayed_error.kind(), StoreErrorKind::ResourceConflict);
        assert_eq!(replayed_error.reason_code(), "resource-conflict");
        assert_eq!(
            replayed_error.current_revision(),
            Some(ZoneRevision::new(2))
        );
        assert_eq!(replayed_error.retry_class(), RetryClass::Reauthorize);
    }

    #[test]
    fn controller_generation_recheck_is_part_of_the_same_write_transaction() {
        let (_directory, database, _identity) = fixture();
        let target = ResourceRef::parse("Host/host-system").unwrap();
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let mut request = verified("stale-controller", create_mutation(target), uid);
        request.policy_snapshot.controller_generation = Some(ControllerGeneration::new(2).unwrap());
        let outcome = apply_group(&database, vec![request]).unwrap();
        assert_eq!(
            outcome.results[0].as_ref().unwrap_err().kind(),
            StoreErrorKind::AuthorizationDenied
        );
        assert_eq!(current_meta(&database).unwrap().current_revision, 0);
    }

    #[test]
    fn failed_request_does_not_abort_an_independent_request_in_the_group() {
        let (_directory, database, _identity) = fixture();
        let first_target = ResourceRef::parse("Host/host-system").unwrap();
        let first_uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        apply_group(
            &database,
            vec![verified(
                "seed-host",
                create_mutation(first_target.clone()),
                first_uid.clone(),
            )],
        )
        .unwrap();

        let second_target = ResourceRef::parse("Host/host-backup").unwrap();
        let second_uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174001").unwrap();
        let mut second_mutation = create_mutation(second_target.clone());
        second_mutation.canonical_resource = Some(
            String::from_utf8(RESOURCE.to_vec())
                .unwrap()
                .replace("host-system", "host-backup")
                .replace(first_uid.as_str(), second_uid.as_str())
                .into_bytes(),
        );
        let outcome = apply_group(
            &database,
            vec![
                verified("independent-success", second_mutation, second_uid.clone()),
                verified(
                    "expected-conflict",
                    create_mutation(first_target),
                    first_uid,
                ),
            ],
        )
        .unwrap();
        assert_eq!(outcome.results[0].as_ref().unwrap().revision.get(), 2);
        assert_eq!(
            outcome.results[1].as_ref().unwrap_err().kind(),
            StoreErrorKind::ResourceAlreadyExists
        );
        assert_eq!(current_meta(&database).unwrap().current_revision, 2);
        let read = database.begin_read().unwrap();
        assert_eq!(read.open_table(RESOURCES).unwrap().len().unwrap(), 2);
        assert_eq!(read.open_table(OPERATIONS).unwrap().len().unwrap(), 3);
        assert_eq!(read.open_table(REVISION_LOG).unwrap().len().unwrap(), 2);
        let stored = read
            .open_table(RESOURCES)
            .unwrap()
            .get(resource_key(&second_target).unwrap().as_slice())
            .unwrap();
        assert!(stored.is_some());
    }

    #[test]
    fn expected_uid_mismatch_cannot_replace_an_existing_resource() {
        let (_directory, database, _identity) = fixture();
        let target = ResourceRef::parse("Host/host-system").unwrap();
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let created = apply_group(
            &database,
            vec![verified(
                "seed-host",
                create_mutation(target.clone()),
                uid.clone(),
            )],
        )
        .unwrap();
        let mut update = create_mutation(target);
        update.kind = ResourceMutationKind::UpdateSpec;
        update.expected = ExpectedRevision::Exact(ZoneRevision::new(1));
        update.expected_uid =
            Some(ResourceUid::parse("123e4567-e89b-42d3-a456-426614174099").unwrap());
        let outcome = apply_group(&database, vec![verified("wrong-uid", update, uid)]).unwrap();
        assert_eq!(
            outcome.results[0].as_ref().unwrap_err().kind(),
            StoreErrorKind::ResourceConflict
        );
        assert_eq!(current_meta(&database).unwrap().current_revision, 1);
        assert_eq!(created.results[0].as_ref().unwrap().revision.get(), 1);
    }

    #[test]
    fn assignment_fence_rebinds_sequential_writes_and_rejects_stale_successors() {
        let (_directory, database, _identity) = fixture();
        let target = ResourceRef::parse("Host/host-system").unwrap();
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let seeded = apply_group(
            &database,
            vec![verified(
                "assignment-seed",
                create_mutation(target.clone()),
                uid.clone(),
            )],
        )
        .unwrap();
        let uid = seeded.results[0].as_ref().unwrap().resources[0].uid.clone();

        let fence = ResourceAssignmentFence {
            resource_uid: uid.clone(),
            resource_revision: ZoneRevision::new(1),
            provider_generation: ResourceGeneration::new(2).unwrap(),
            controller_generation: ControllerGeneration::new(3).unwrap(),
            controller_role: ResourceRef::parse("Process/process-controller").unwrap(),
            target: target.clone(),
            session_generation: ReconnectGeneration::new(4).unwrap(),
            epoch: 1,
            scope: ResourceAssignmentScope::Primary,
        };
        let mut first = create_mutation(target.clone());
        first.kind = ResourceMutationKind::UpdateFinalizers;
        first.expected = ExpectedRevision::Exact(ZoneRevision::new(1));
        first.expected_uid = Some(uid.clone());
        first.canonical_resource = None;
        first.add_finalizers = vec![FinalizerId::parse("core.controller-test").unwrap()];
        first.assignment = Some(fence.clone());
        let committed = apply_group(
            &database,
            vec![verified("assignment-first", first, uid.clone())],
        )
        .unwrap();
        assert_eq!(
            committed.results[0].as_ref().unwrap().revision,
            ZoneRevision::new(2)
        );

        let unrelated_target = ResourceRef::parse("Host/unrelated").unwrap();
        let unrelated_uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174001").unwrap();
        apply_group(
            &database,
            vec![verified(
                "assignment-gap",
                create_mutation_with_uid(unrelated_target, &unrelated_uid),
                unrelated_uid,
            )],
        )
        .unwrap();

        let mut status_body = CanonicalJsonValue::parse(RESOURCE).unwrap();
        let CanonicalJsonValue::Object(root) = &mut status_body else {
            unreachable!()
        };
        let CanonicalJsonValue::Object(metadata) = root.get_mut("metadata").unwrap() else {
            unreachable!()
        };
        metadata.insert(
            "uid".to_owned(),
            CanonicalJsonValue::String(uid.as_str().to_owned()),
        );
        let CanonicalJsonValue::Object(status) = root.get_mut("status").unwrap() else {
            unreachable!()
        };
        status.insert(
            "phase".to_owned(),
            CanonicalJsonValue::String("Ready".to_owned()),
        );
        let mut sequential = create_mutation(target.clone());
        sequential.kind = ResourceMutationKind::UpdateStatus;
        sequential.expected = ExpectedRevision::Exact(ZoneRevision::new(2));
        sequential.expected_uid = Some(uid.clone());
        sequential.canonical_resource = Some(status_body.to_canonical_bytes());
        sequential.assignment = Some(ResourceAssignmentFence {
            resource_revision: ZoneRevision::new(2),
            scope: ResourceAssignmentScope::Primary,
            ..fence.clone()
        });
        let sequential_commit = apply_group(
            &database,
            vec![verified("assignment-sequential", sequential, uid.clone())],
        )
        .unwrap();
        assert_eq!(
            sequential_commit.results[0].as_ref().unwrap().revision,
            ZoneRevision::new(4)
        );

        let mut stale = create_mutation(target.clone());
        stale.kind = ResourceMutationKind::UpdateFinalizers;
        stale.expected = ExpectedRevision::Exact(ZoneRevision::new(4));
        stale.expected_uid = Some(uid.clone());
        stale.canonical_resource = None;
        stale.add_finalizers = vec![FinalizerId::parse("core.controller-stale").unwrap()];
        stale.assignment = Some(fence.clone());
        let rejected = apply_group(
            &database,
            vec![verified("assignment-stale", stale, uid.clone())],
        )
        .unwrap();
        assert_eq!(
            rejected.results[0].as_ref().unwrap_err().reason_code(),
            "stale-assignment"
        );
        let mut successor = create_mutation(target);
        successor.kind = ResourceMutationKind::UpdateFinalizers;
        successor.expected = ExpectedRevision::Exact(ZoneRevision::new(4));
        successor.expected_uid = Some(uid.clone());
        successor.canonical_resource = None;
        successor.add_finalizers = vec![FinalizerId::parse("core.controller-successor").unwrap()];
        successor.assignment = Some(ResourceAssignmentFence {
            resource_revision: ZoneRevision::new(4),
            epoch: 2,
            scope: ResourceAssignmentScope::Primary,
            ..fence
        });
        let successor_commit = apply_group(
            &database,
            vec![verified("assignment-successor", successor, uid)],
        )
        .unwrap();
        assert_eq!(
            successor_commit.results[0].as_ref().unwrap().revision,
            ZoneRevision::new(5)
        );
        assert_eq!(current_meta(&database).unwrap().current_revision, 5);
        assert_eq!(
            database
                .begin_read()
                .unwrap()
                .open_table(REVISION_LOG)
                .unwrap()
                .len()
                .unwrap(),
            5
        );
        validate_consistency(&database).unwrap();
    }

    #[test]
    fn scoped_commit_batch_persists_fenced_status_finalizer_index_and_revision_atomically() {
        let (_directory, database, _identity) = fixture();
        let target = ResourceRef::parse("Host/host-system").unwrap();
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let seeded = apply_group(
            &database,
            vec![verified(
                "multi-assignment-seed",
                create_mutation(target.clone()),
                uid.clone(),
            )],
        )
        .unwrap();
        let uid = seeded.results[0].as_ref().unwrap().resources[0].uid.clone();

        let fence = ResourceAssignmentFence {
            resource_uid: uid.clone(),
            resource_revision: ZoneRevision::new(1),
            provider_generation: ResourceGeneration::new(2).unwrap(),
            controller_generation: ControllerGeneration::new(3).unwrap(),
            controller_role: ResourceRef::parse("Process/process-controller").unwrap(),
            target: target.clone(),
            session_generation: ReconnectGeneration::new(4).unwrap(),
            epoch: 1,
            scope: ResourceAssignmentScope::Primary,
        };
        let mut assignment_seed = create_mutation(target.clone());
        assignment_seed.kind = ResourceMutationKind::UpdateFinalizers;
        assignment_seed.expected = ExpectedRevision::Exact(ZoneRevision::new(1));
        assignment_seed.expected_uid = Some(uid.clone());
        assignment_seed.canonical_resource = None;
        assignment_seed.add_finalizers = vec![FinalizerId::parse("core.controller-seed").unwrap()];
        assignment_seed.assignment = Some(fence.clone());
        apply_group(
            &database,
            vec![verified(
                "multi-assignment-bind",
                assignment_seed,
                uid.clone(),
            )],
        )
        .unwrap();

        let mut status_body = CanonicalJsonValue::parse(RESOURCE).unwrap();
        let CanonicalJsonValue::Object(root) = &mut status_body else {
            unreachable!()
        };
        let CanonicalJsonValue::Object(metadata) = root.get_mut("metadata").unwrap() else {
            unreachable!()
        };
        metadata.insert(
            "uid".to_owned(),
            CanonicalJsonValue::String(uid.as_str().to_owned()),
        );
        let CanonicalJsonValue::Object(status) = root.get_mut("status").unwrap() else {
            unreachable!()
        };
        status.insert(
            "phase".to_owned(),
            CanonicalJsonValue::String("Ready".to_owned()),
        );

        let mut status = create_mutation(target.clone());
        status.kind = ResourceMutationKind::UpdateStatus;
        status.expected = ExpectedRevision::Exact(ZoneRevision::new(2));
        status.expected_uid = Some(uid.clone());
        status.canonical_resource = Some(status_body.to_canonical_bytes());
        status.assignment = Some(ResourceAssignmentFence {
            resource_revision: ZoneRevision::new(2),
            scope: ResourceAssignmentScope::Primary,
            ..fence.clone()
        });
        let mut finalizers = create_mutation(target.clone());
        finalizers.kind = ResourceMutationKind::UpdateFinalizers;
        finalizers.expected = ExpectedRevision::Exact(ZoneRevision::new(3));
        finalizers.expected_uid = Some(uid.clone());
        finalizers.canonical_resource = None;
        finalizers.add_finalizers = vec![FinalizerId::parse("core.controller-batch").unwrap()];
        finalizers.assignment = Some(ResourceAssignmentFence {
            resource_revision: ZoneRevision::new(3),
            scope: ResourceAssignmentScope::Primary,
            ..fence
        });

        let mut batch = verified("multi-assignment-batch", status, uid.clone());
        let finalizer_write = verified("multi-assignment-batch", finalizers, uid.clone());
        batch
            .authorization
            .targets
            .extend(finalizer_write.authorization.targets);
        batch.mutations.extend(finalizer_write.mutations);
        let committed = apply_group(&database, vec![batch]).unwrap();

        assert_eq!(
            committed.results[0].as_ref().unwrap().revision,
            ZoneRevision::new(3)
        );
        let envelope = stored_envelope(&database, &target);
        assert_eq!(envelope.status().phase(), ResourcePhase::Ready);
        let stored = serde_json::to_value(&envelope).unwrap();
        assert!(
            stored["metadata"]["finalizers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|finalizer| finalizer == "core.controller-batch")
        );
        assert_eq!(envelope.metadata().revision(), ZoneRevision::new(3));
        let read = database.begin_read().unwrap();
        assert_eq!(read.open_table(TYPE_INDEX).unwrap().len().unwrap(), 1);
        assert_eq!(read.open_table(CONTROLLER_INDEX).unwrap().len().unwrap(), 1);
        assert_eq!(read.open_table(REVISION_LOG).unwrap().len().unwrap(), 3);
        validate_consistency(&database).unwrap();
    }

    #[test]
    fn assignment_fences_reject_lower_epoch_inside_multi_mutation_batch() {
        let (_directory, database, _identity) = fixture();
        let target = ResourceRef::parse("Host/host-system").unwrap();
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let seeded = apply_group(
            &database,
            vec![verified(
                "multi-epoch-seed",
                create_mutation(target.clone()),
                uid.clone(),
            )],
        )
        .unwrap();
        let uid = seeded.results[0].as_ref().unwrap().resources[0].uid.clone();

        let fence = ResourceAssignmentFence {
            resource_uid: uid.clone(),
            resource_revision: ZoneRevision::new(1),
            provider_generation: ResourceGeneration::new(2).unwrap(),
            controller_generation: ControllerGeneration::new(3).unwrap(),
            controller_role: ResourceRef::parse("Process/process-controller").unwrap(),
            target: target.clone(),
            session_generation: ReconnectGeneration::new(4).unwrap(),
            epoch: 1,
            scope: ResourceAssignmentScope::Primary,
        };
        let mut assignment_seed = create_mutation(target.clone());
        assignment_seed.kind = ResourceMutationKind::UpdateFinalizers;
        assignment_seed.expected = ExpectedRevision::Exact(ZoneRevision::new(1));
        assignment_seed.expected_uid = Some(uid.clone());
        assignment_seed.canonical_resource = None;
        assignment_seed.add_finalizers =
            vec![FinalizerId::parse("core.controller-epoch-seed").unwrap()];
        assignment_seed.assignment = Some(fence.clone());
        apply_group(
            &database,
            vec![verified("multi-epoch-bind", assignment_seed, uid.clone())],
        )
        .unwrap();

        let mut successor = create_mutation(target.clone());
        successor.kind = ResourceMutationKind::UpdateFinalizers;
        successor.expected = ExpectedRevision::Exact(ZoneRevision::new(2));
        successor.expected_uid = Some(uid.clone());
        successor.canonical_resource = None;
        successor.add_finalizers =
            vec![FinalizerId::parse("core.controller-epoch-successor").unwrap()];
        successor.assignment = Some(ResourceAssignmentFence {
            resource_revision: ZoneRevision::new(2),
            epoch: 2,
            scope: ResourceAssignmentScope::Primary,
            ..fence.clone()
        });

        let mut stale = create_mutation(target);
        stale.kind = ResourceMutationKind::UpdateFinalizers;
        stale.expected = ExpectedRevision::Exact(ZoneRevision::new(3));
        stale.expected_uid = Some(uid.clone());
        stale.canonical_resource = None;
        stale.add_finalizers = vec![FinalizerId::parse("core.controller-epoch-stale").unwrap()];
        stale.assignment = Some(fence);

        let mut batch = verified("multi-epoch-batch", successor, uid.clone());
        let stale_write = verified("multi-epoch-batch", stale, uid);
        batch
            .authorization
            .targets
            .extend(stale_write.authorization.targets);
        batch.mutations.extend(stale_write.mutations);
        let outcome = apply_group(&database, vec![batch]).unwrap();

        assert_eq!(
            outcome.results[0].as_ref().unwrap_err().reason_code(),
            "stale-assignment"
        );
        assert_eq!(current_meta(&database).unwrap().current_revision, 2);
        validate_consistency(&database).unwrap();
    }

    #[test]
    fn prepared_uid_mismatch_cannot_replace_an_existing_resource() {
        let (_directory, database, _identity) = fixture();
        let target = ResourceRef::parse("Host/host-system").unwrap();
        let requested_uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        apply_group(
            &database,
            vec![verified(
                "seed-host",
                create_mutation(target.clone()),
                requested_uid,
            )],
        )
        .unwrap();
        let current_uid = stored_envelope(&database, &target).metadata().uid().clone();

        let prepared_uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174099").unwrap();
        let mut update = create_mutation_with_uid(target.clone(), &prepared_uid);
        update.kind = ResourceMutationKind::UpdateSpec;
        update.expected = ExpectedRevision::Exact(ZoneRevision::new(1));
        update.expected_uid = Some(current_uid.clone());
        let outcome = apply_group(
            &database,
            vec![verified("prepared-uid-mismatch", update, prepared_uid)],
        )
        .unwrap();
        assert_eq!(
            outcome.results[0].as_ref().unwrap_err().reason_code(),
            "resource-uid-changed"
        );
        assert_eq!(
            stored_envelope(&database, &target).metadata().uid(),
            &current_uid
        );
    }

    #[test]
    fn idempotent_replay_returns_the_original_committed_resources() {
        let (_directory, database, _identity) = fixture();
        let target = ResourceRef::parse("Host/host-system").unwrap();
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let first = apply_group(
            &database,
            vec![verified(
                "idempotent-create",
                create_mutation_with_uid(target.clone(), &uid),
                uid.clone(),
            )],
        )
        .unwrap();
        let replay_uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174099").unwrap();
        let replay = apply_group(
            &database,
            vec![verified(
                "idempotent-create",
                create_mutation_with_uid(target.clone(), &replay_uid),
                replay_uid,
            )],
        )
        .unwrap();
        assert!(replay.batch.is_none());
        assert_eq!(replay.results[0], first.results[0]);
        let persisted_digest = stored_envelope(&database, &target).digest().unwrap();
        assert_eq!(
            first.results[0].as_ref().unwrap().resources[0].payload_digest,
            persisted_digest
        );
        assert_eq!(
            replay.results[0].as_ref().unwrap().resources[0].payload_digest,
            persisted_digest
        );
        assert_eq!(current_meta(&database).unwrap().current_revision, 1);
    }

    #[test]
    fn terminal_denial_replays_before_policy_validation() {
        let (_directory, database, _identity) = fixture();
        let target = ResourceRef::parse("Host/host-system").unwrap();
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let mut denied = verified(
            "terminal-denial",
            create_mutation_with_uid(target.clone(), &uid),
            uid.clone(),
        );
        denied.policy_snapshot.policy_revision = 999;
        let first = apply_group(&database, vec![denied]).unwrap();
        assert_eq!(
            first.results[0].as_ref().unwrap_err().reason_code(),
            "store-generation-recheck-failed"
        );

        let replay = apply_group(
            &database,
            vec![verified(
                "terminal-denial",
                create_mutation_with_uid(target, &uid),
                uid,
            )],
        )
        .unwrap();
        assert_eq!(
            replay.results[0].as_ref().unwrap_err().reason_code(),
            "operation-replayed-denied"
        );
    }

    #[test]
    fn status_update_preserves_spec_and_store_metadata() {
        let (_directory, database, _identity) = fixture();
        let target = ResourceRef::parse("Host/host-system").unwrap();
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        apply_group(
            &database,
            vec![verified(
                "seed-host",
                create_mutation(target.clone()),
                uid.clone(),
            )],
        )
        .unwrap();
        let before = stored_envelope(&database, &target);
        let uid = before.metadata().uid().clone();
        let mut body = CanonicalJsonValue::parse(RESOURCE).unwrap();
        let CanonicalJsonValue::Object(root) = &mut body else {
            unreachable!()
        };
        let CanonicalJsonValue::Object(metadata) = root.get_mut("metadata").unwrap() else {
            unreachable!()
        };
        metadata.insert(
            "uid".to_owned(),
            CanonicalJsonValue::String(uid.as_str().to_owned()),
        );
        root.insert(
            "spec".to_owned(),
            CanonicalJsonValue::Object(Default::default()),
        );
        let mut update = create_mutation(target.clone());
        update.kind = ResourceMutationKind::UpdateStatus;
        update.expected = ExpectedRevision::Exact(ZoneRevision::new(1));
        update.expected_uid = Some(uid.clone());
        update.canonical_resource = Some(body.to_canonical_bytes());
        apply_group(&database, vec![verified("update-status", update, uid)])
            .unwrap()
            .results[0]
            .as_ref()
            .unwrap();
        let after = stored_envelope(&database, &target);

        assert_eq!(after.spec(), before.spec());
        assert_eq!(after.metadata().uid(), before.metadata().uid());
        assert_eq!(
            after.metadata().generation(),
            before.metadata().generation()
        );
        assert_eq!(after.metadata().revision(), ZoneRevision::new(2));
    }

    #[test]
    fn finalizer_delta_and_two_step_delete_preserve_resource_until_clear() {
        let (_directory, database, _identity) = fixture();
        let target = ResourceRef::parse("Host/host-system").unwrap();
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        apply_group(
            &database,
            vec![verified(
                "seed-host",
                create_mutation(target.clone()),
                uid.clone(),
            )],
        )
        .unwrap();
        let uid = stored_envelope(&database, &target).metadata().uid().clone();
        let finalizer = FinalizerId::parse("core.cleanup").unwrap();
        let mut add = create_mutation(target.clone());
        add.kind = ResourceMutationKind::UpdateFinalizers;
        add.expected = ExpectedRevision::Exact(ZoneRevision::new(1));
        add.expected_uid = Some(uid.clone());
        add.canonical_resource = None;
        add.add_finalizers = vec![finalizer.clone()];
        apply_group(&database, vec![verified("add-finalizer", add, uid.clone())])
            .unwrap()
            .results[0]
            .as_ref()
            .unwrap();
        assert!(
            has_finalizers(
                &stored_envelope(&database, &target)
                    .canonical_bytes()
                    .unwrap()
            )
            .unwrap()
        );

        let mut delete = create_mutation(target.clone());
        delete.kind = ResourceMutationKind::Delete;
        delete.expected = ExpectedRevision::Exact(ZoneRevision::new(2));
        delete.expected_uid = Some(uid.clone());
        delete.canonical_resource = None;
        apply_group(
            &database,
            vec![verified("request-delete", delete, uid.clone())],
        )
        .unwrap();
        let requested = stored_envelope(&database, &target);
        assert!(deletion_requested(&requested.canonical_bytes().unwrap()).unwrap());

        let mut blocked = create_mutation(target.clone());
        blocked.kind = ResourceMutationKind::Delete;
        blocked.expected = ExpectedRevision::Exact(ZoneRevision::new(3));
        blocked.expected_uid = Some(uid.clone());
        blocked.canonical_resource = None;
        let outcome = apply_group(
            &database,
            vec![verified("blocked-delete", blocked, uid.clone())],
        )
        .unwrap();
        assert_eq!(
            outcome.results[0].as_ref().unwrap_err().kind(),
            StoreErrorKind::ResourceFinalizerDenied
        );

        let mut remove = create_mutation(target.clone());
        remove.kind = ResourceMutationKind::UpdateFinalizers;
        remove.expected = ExpectedRevision::Exact(ZoneRevision::new(3));
        remove.expected_uid = Some(uid.clone());
        remove.canonical_resource = None;
        remove.remove_finalizers = vec![finalizer];
        apply_group(
            &database,
            vec![verified("remove-finalizer", remove, uid.clone())],
        )
        .unwrap();
        let read = database.begin_read().unwrap();
        assert!(
            read.open_table(RESOURCES)
                .unwrap()
                .get(resource_key(&target).unwrap().as_slice())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn finalizer_only_update_uses_stored_uid_without_prepared_uid() {
        let (_directory, database, _identity) = fixture();
        let target = ResourceRef::parse("Host/host-system").unwrap();
        let requested_uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        apply_group(
            &database,
            vec![verified(
                "seed-finalizer-target",
                create_mutation(target.clone()),
                requested_uid,
            )],
        )
        .unwrap();
        let stored_uid = stored_envelope(&database, &target).metadata().uid().clone();

        let mut finalizer = create_mutation(target.clone());
        finalizer.kind = ResourceMutationKind::UpdateFinalizers;
        finalizer.expected = ExpectedRevision::Exact(ZoneRevision::new(1));
        finalizer.canonical_resource = None;
        finalizer.add_finalizers = vec![FinalizerId::parse("core.cleanup").unwrap()];
        let request = verified(
            "finalizer-without-prepared-uid",
            finalizer,
            stored_uid.clone(),
        );
        assert!(request.mutations[0].resource_uid.is_none());

        let result = apply_group(&database, vec![request])
            .unwrap()
            .results
            .remove(0)
            .unwrap();
        assert_eq!(result.resources[0].uid, stored_uid);
        assert!(has_finalizers(&result.resources[0].canonical_json).unwrap());
    }

    #[test]
    fn operation_digest_covers_expected_uid_and_finalizer_delta() {
        let target = ResourceRef::parse("Host/host-system").unwrap();
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let mut first = create_mutation(target.clone());
        first.kind = ResourceMutationKind::UpdateFinalizers;
        first.expected = ExpectedRevision::Exact(ZoneRevision::new(1));
        first.expected_uid = Some(uid.clone());
        first.canonical_resource = None;
        first.add_finalizers = vec![FinalizerId::parse("core.first").unwrap()];
        let first = verified("same-operation", first, uid.clone());
        let mut changed_uid = create_mutation(target.clone());
        changed_uid.kind = ResourceMutationKind::UpdateFinalizers;
        changed_uid.expected = ExpectedRevision::Exact(ZoneRevision::new(1));
        changed_uid.expected_uid =
            Some(ResourceUid::parse("123e4567-e89b-42d3-a456-426614174099").unwrap());
        changed_uid.canonical_resource = None;
        changed_uid.add_finalizers = vec![FinalizerId::parse("core.first").unwrap()];
        let changed_uid = verified("same-operation", changed_uid, uid.clone());
        let mut changed_delta = create_mutation(target);
        changed_delta.kind = ResourceMutationKind::UpdateFinalizers;
        changed_delta.expected = ExpectedRevision::Exact(ZoneRevision::new(1));
        changed_delta.expected_uid = Some(uid.clone());
        changed_delta.canonical_resource = None;
        changed_delta.add_finalizers = vec![FinalizerId::parse("core.second").unwrap()];
        let changed_delta = verified("same-operation", changed_delta, uid);

        assert_ne!(
            operation_digest(&first).unwrap(),
            operation_digest(&changed_uid).unwrap()
        );
        assert_ne!(
            operation_digest(&first).unwrap(),
            operation_digest(&changed_delta).unwrap()
        );
    }

    #[test]
    fn create_operation_digest_ignores_sealed_uid_but_detects_caller_input_changes() {
        let target = ResourceRef::parse("Host/host-system").unwrap();
        let first_uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let retry_uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174099").unwrap();
        let first = verified(
            "same-create-operation",
            create_mutation_with_uid(target.clone(), &first_uid),
            first_uid,
        );
        let retry = verified(
            "same-create-operation",
            create_mutation_with_uid(target.clone(), &retry_uid),
            retry_uid.clone(),
        );
        let mut changed_mutation = create_mutation_with_uid(target, &retry_uid);
        changed_mutation.canonical_resource = Some(
            String::from_utf8(changed_mutation.canonical_resource.take().unwrap())
                .unwrap()
                .replace(
                    "\"nonDisruptive\":\"automatic\"",
                    "\"nonDisruptive\":\"manual\"",
                )
                .into_bytes(),
        );
        let changed = verified("same-create-operation", changed_mutation, retry_uid);

        assert_eq!(
            operation_digest(&first).unwrap(),
            operation_digest(&retry).unwrap()
        );
        assert_ne!(
            operation_digest(&first).unwrap(),
            operation_digest(&changed).unwrap()
        );
    }

    #[test]
    fn producer_index_uses_producer_uid_as_its_first_component() {
        let (_directory, database, _identity) = fixture();
        let producer_uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174010").unwrap();
        let endpoint_uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174011").unwrap();
        let key = encode_key(
            KeySpace::ProducerIndex,
            &[
                KeyComponent::Text(producer_uid.as_str()),
                KeyComponent::Text(endpoint_uid.as_str()),
            ],
        )
        .unwrap();
        let value = encode(
            ValueKind::ProducerIndexRecord,
            &ProducerIndexRecord {
                endpoint_type: "Endpoint".to_owned(),
                endpoint_name: "worker".to_owned(),
            },
        )
        .unwrap();
        let write = database.begin_write().unwrap();
        write
            .open_table(PRODUCER_INDEX)
            .unwrap()
            .insert(key.as_bytes(), value.as_slice())
            .unwrap();
        write.commit().unwrap();
        let write = database.begin_write().unwrap();
        assert!(produced_endpoints_remain(&write, &producer_uid).unwrap());
        assert!(!produced_endpoints_remain(&write, &endpoint_uid).unwrap());
        write.abort().unwrap();
    }

    #[test]
    fn endpoint_producer_ref_is_required_and_strict() {
        let mut value = CanonicalJsonValue::parse(RESOURCE).unwrap();
        let CanonicalJsonValue::Object(root) = &mut value else {
            unreachable!()
        };
        root.insert(
            "type".to_owned(),
            CanonicalJsonValue::String("Endpoint".to_owned()),
        );
        {
            let CanonicalJsonValue::Object(spec) = root.get_mut("spec").unwrap() else {
                unreachable!()
            };
            spec.remove("providerRef");
            spec.remove("updatePolicy");
        }
        let missing = ResourceEnvelope::from_json(&value.to_canonical_bytes()).unwrap();
        assert_eq!(
            endpoint_producer(&missing).unwrap_err().reason_code(),
            "endpoint-producer-ref-missing"
        );
        let CanonicalJsonValue::Object(root) = &mut value else {
            unreachable!()
        };
        let CanonicalJsonValue::Object(spec) = root.get_mut("spec").unwrap() else {
            unreachable!()
        };
        spec.insert(
            "producerRef".to_owned(),
            CanonicalJsonValue::String("not-a-ref".to_owned()),
        );
        let malformed = ResourceEnvelope::from_json(&value.to_canonical_bytes()).unwrap();
        assert_eq!(
            endpoint_producer(&malformed).unwrap_err().reason_code(),
            "endpoint-producer-ref-invalid"
        );
    }

    #[test]
    fn endpoint_standard_validation_uses_full_spec_and_keeps_reserved_fields_out_of_base() {
        let valid_value = endpoint_resource_value(ENDPOINT_SPEC);
        let valid = ResourceEnvelope::from_json(&valid_value.to_canonical_bytes()).unwrap();
        assert_eq!(valid.spec().canonical_bytes().unwrap(), ENDPOINT_SPEC);
        assert_eq!(
            valid.spec().provider_ref().unwrap().to_canonical_string(),
            "Provider/display-wayland"
        );
        assert!(valid.spec().base().get("providerRef").is_none());
        assert!(validate_standard_base(&valid).unwrap());

        let mut missing_value = valid_value.clone();
        let CanonicalJsonValue::Object(root) = &mut missing_value else {
            unreachable!()
        };
        let CanonicalJsonValue::Object(spec) = root.get_mut("spec").unwrap() else {
            unreachable!()
        };
        spec.remove("providerRef");
        let missing = ResourceEnvelope::from_json(&missing_value.to_canonical_bytes()).unwrap();
        assert_eq!(
            validate_standard_base(&missing).unwrap_err().reason_code(),
            "resource-base-schema-invalid"
        );

        let mut invalid_value = valid_value;
        let CanonicalJsonValue::Object(root) = &mut invalid_value else {
            unreachable!()
        };
        let CanonicalJsonValue::Object(spec) = root.get_mut("spec").unwrap() else {
            unreachable!()
        };
        spec.insert(
            "providerRef".to_owned(),
            CanonicalJsonValue::String("Host/host-system".to_owned()),
        );
        assert!(ResourceEnvelope::from_json(&invalid_value.to_canonical_bytes()).is_err());
    }

    #[test]
    fn endpoint_create_admission_accepts_reserved_provider_ref() {
        let (_directory, database, _identity) = fixture();
        let producer = ResourceRef::parse("Host/host-system").unwrap();
        let producer_uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174001").unwrap();
        apply_group(
            &database,
            vec![verified(
                "seed-endpoint-producer",
                create_mutation(producer),
                producer_uid,
            )],
        )
        .unwrap()
        .results[0]
            .as_ref()
            .unwrap();

        let target = ResourceRef::parse("Endpoint/wayland-endpoint").unwrap();
        let mut mutation = create_mutation(target.clone());
        let mut endpoint_value = endpoint_resource_value(ENDPOINT_SPEC);
        let CanonicalJsonValue::Object(root) = &mut endpoint_value else {
            unreachable!()
        };
        let CanonicalJsonValue::Object(spec) = root.get_mut("spec").unwrap() else {
            unreachable!()
        };
        spec.insert(
            "producerRef".to_owned(),
            CanonicalJsonValue::String("Host/host-system".to_owned()),
        );
        mutation.canonical_resource = Some(endpoint_value.to_canonical_bytes());
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174002").unwrap();

        let committed =
            apply_group(&database, vec![verified("create-endpoint", mutation, uid)]).unwrap();
        committed.results[0].as_ref().unwrap();
        let stored = stored_envelope(&database, &target);
        assert_eq!(
            stored.spec().provider_ref().unwrap().to_canonical_string(),
            "Provider/display-wayland"
        );
        assert!(stored.spec().base().get("providerRef").is_none());
    }

    #[test]
    fn active_schema_rejects_unknown_base_fields_before_mutation() {
        let (_directory, database, _identity) = fixture();
        let target = ResourceRef::parse("Host/host-system").unwrap();
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        apply_group(
            &database,
            vec![verified("seed-host", create_mutation(target.clone()), uid)],
        )
        .unwrap();
        let uid = stored_envelope(&database, &target).metadata().uid().clone();
        let mut value = CanonicalJsonValue::parse(RESOURCE).unwrap();
        let CanonicalJsonValue::Object(root) = &mut value else {
            unreachable!()
        };
        let CanonicalJsonValue::Object(metadata) = root.get_mut("metadata").unwrap() else {
            unreachable!()
        };
        metadata.insert(
            "uid".to_owned(),
            CanonicalJsonValue::String(uid.as_str().to_owned()),
        );
        let CanonicalJsonValue::Object(spec) = root.get_mut("spec").unwrap() else {
            unreachable!()
        };
        spec.insert(
            "unknownHostField".to_owned(),
            CanonicalJsonValue::Bool(true),
        );
        let mut update = create_mutation(target);
        update.kind = ResourceMutationKind::UpdateSpec;
        update.expected = ExpectedRevision::Exact(ZoneRevision::new(1));
        update.expected_uid = Some(uid.clone());
        update.canonical_resource = Some(value.to_canonical_bytes());
        let error = apply_group(&database, vec![verified("bad-schema", update, uid)]).unwrap_err();
        assert_eq!(error.kind(), StoreErrorKind::ResourceSchemaInvalid);
        assert_eq!(current_meta(&database).unwrap().current_revision, 1);
    }

    #[test]
    fn every_standard_catalog_type_has_a_closed_base_validator() {
        for resource_type in STANDARD_SCHEMA_CATALOG {
            let result = validate_standard_base_bytes(resource_type, b"{}");
            assert!(
                !matches!(result, Ok(false)),
                "catalog type {resource_type} must have a validator binding"
            );
        }
        assert!(!validate_standard_base_bytes("vendor.d2bus.org.Extension", b"{}").unwrap());
    }

    #[test]
    fn change_log_types_reject_unknown_events_zero_generations_and_oversize_batches() {
        assert!(serde_json::from_str::<ChangeEvent>("\"invented\"").is_err());
        assert!(serde_json::from_str::<ResourceGeneration>("0").is_err());
        assert!(ChangeBatch::new(ZoneRevision::new(0), Vec::new()).is_err());
        let entry = ChangeEntry::new(
            0,
            ResourceTypeName::parse("Host").unwrap(),
            ResourceName::parse("host-system").unwrap(),
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap(),
            ChangeEvent::Created,
            None,
            Some(ResourceGeneration::new(1).unwrap()),
            None,
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
            None,
            "op".to_owned(),
            "corr".to_owned(),
        )
        .unwrap();
        let mut entries =
            vec![
                entry.clone();
                crate::GROUP_COMMIT_MAX * d2b_contracts_resource::v3::MAX_BATCH_MUTATIONS + 1
            ];
        for (ordinal, entry) in entries.iter_mut().enumerate() {
            entry.ordinal = u32::try_from(ordinal).unwrap();
        }
        assert!(ChangeBatch::new(ZoneRevision::new(1), entries).is_err());
    }

    #[test]
    fn change_entries_retain_old_and_new_owner_bindings() {
        let old_owner = ResourceRef::parse("Host/old-owner").unwrap();
        let new_owner = ResourceRef::parse("Host/new-owner").unwrap();
        let entry = ChangeEntry::new(
            0,
            ResourceTypeName::parse("Process").unwrap(),
            ResourceName::parse("worker").unwrap(),
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap(),
            ChangeEvent::MetadataUpdated,
            Some(ResourceGeneration::new(1).unwrap()),
            Some(ResourceGeneration::new(2).unwrap()),
            Some(ResourceUid::parse("123e4567-e89b-42d3-a456-426614174002").unwrap()),
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
            Some(RESOURCE.to_vec()),
            "reparent".to_owned(),
            "reparent-correlation".to_owned(),
        )
        .unwrap()
        .with_owners(
            Some(old_owner.clone()),
            Some(ResourceUid::parse("123e4567-e89b-42d3-a456-426614174001").unwrap()),
            Some(new_owner.clone()),
        );
        let encoded = serde_json::to_vec(&entry).unwrap();
        let decoded: ChangeEntry = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.previous_owner_ref(), Some(&old_owner));
        assert_eq!(decoded.owner_ref(), Some(&new_owner));
        assert_eq!(
            decoded.previous_owner_uid().unwrap().as_str(),
            "123e4567-e89b-42d3-a456-426614174001"
        );
        assert_eq!(
            decoded.owner_uid().unwrap().as_str(),
            "123e4567-e89b-42d3-a456-426614174002"
        );
    }

    #[test]
    fn recovery_rejects_derived_resource_drift_and_invalid_auxiliary_tables() {
        let (_directory, database, _identity) = fixture();
        let target = ResourceRef::parse("Host/host-system").unwrap();
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        apply_group(
            &database,
            vec![verified("seed-host", create_mutation(target.clone()), uid)],
        )
        .unwrap();
        let write = database.begin_write().unwrap();
        let mut resources = write.open_table(RESOURCES).unwrap();
        let key = resource_key(&target).unwrap();
        let current = resources.get(key.as_slice()).unwrap().unwrap();
        let mut record: ResourceRecord =
            decode(ValueKind::ResourceRecord, current.value()).unwrap();
        record.payload_digest =
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned();
        drop(current);
        resources
            .insert(
                key.as_slice(),
                encode(ValueKind::ResourceRecord, &record)
                    .unwrap()
                    .as_slice(),
            )
            .unwrap();
        drop(resources);
        write.commit().unwrap();
        assert_eq!(
            validate_consistency(&database).unwrap_err().reason_code(),
            "stored-resource-identity-invalid"
        );

        let (_directory, database, identity) = fixture();
        let write = database.begin_write().unwrap();
        let schema_key = encode_key(KeySpace::ApiSchemas, &[KeyComponent::Text("Host")]).unwrap();
        let schema = encode(
            ValueKind::ApiSchemaRecord,
            &serde_json::json!({
                "resourceType": "Guest",
                "validatorFingerprint": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            }),
        )
        .unwrap();
        write
            .open_table(API_SCHEMAS)
            .unwrap()
            .insert(schema_key.as_bytes(), schema.as_slice())
            .unwrap();
        write.commit().unwrap();
        assert_eq!(
            validate_consistency(&database).unwrap_err().reason_code(),
            "api-schema-record-invalid"
        );
        assert_eq!(
            validate_identity(&database, &identity).unwrap().zone_name,
            "dev"
        );
    }

    #[test]
    fn identity_gate_rejects_foreign_store_before_any_legacy_repair() {
        let (directory, database, identity) = fixture();
        let target = ResourceRef::parse("Host/host-system").unwrap();
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let operation = verified(
            "foreign-legacy",
            create_mutation_with_uid(target, &uid),
            uid,
        );
        let legacy_digest = legacy_operation_digest(&operation).unwrap();
        apply_group(&database, vec![operation]).unwrap();
        rewrite_request_digest(&database, "foreign-legacy", legacy_digest);

        let mut write = database.begin_write().unwrap();
        set_full_durability(&mut write).unwrap();
        let mut meta = read_meta_in_write(&write).unwrap();
        meta.store_uuid = "33333333-3333-4333-8333-333333333333".to_owned();
        let value = encode(ValueKind::StoreMetaScalar, &meta).unwrap();
        write
            .open_table(STORE_META)
            .unwrap()
            .insert(meta_key().as_slice(), value.as_slice())
            .unwrap();
        write.commit().unwrap();

        let before = std::fs::read(directory.path().join("store.redb")).unwrap();
        let error = normalize_and_validate(&database, &identity, PHYSICAL_SCHEMA_VERSION, false)
            .unwrap_err();
        assert_eq!(error.reason_code(), "store-identity-mismatch");
        assert_eq!(
            std::fs::read(directory.path().join("store.redb")).unwrap(),
            before
        );
    }

    #[test]
    fn owner_child_process_mutations_use_the_parent_assignment_and_owner_index() {
        let (_directory, database, _identity) = fixture();
        let owner_ref = ResourceRef::parse("Guest/guest").unwrap();
        let owner_placeholder = ResourceUid::parse("323e4567-e89b-42d3-a456-426614174002").unwrap();
        let owner = apply_group(
            &database,
            vec![verified(
                "owner-create",
                create_mutation_with_body(owner_ref.clone(), guest_body("guest")),
                owner_placeholder,
            )],
        )
        .unwrap()
        .results[0]
            .as_ref()
            .unwrap()
            .resources[0]
            .clone();
        let owner_uid = owner.uid.clone();
        let target = ResourceRef::parse("Host/host-system").unwrap();

        let mut bind = create_mutation(owner_ref.clone());
        bind.kind = ResourceMutationKind::UpdateFinalizers;
        bind.expected = ExpectedRevision::Exact(owner.revision);
        bind.expected_uid = Some(owner_uid.clone());
        bind.canonical_resource = None;
        bind.add_finalizers = vec![FinalizerId::parse("core.owner-child-test").unwrap()];
        bind.assignment = Some(primary_fence(
            owner_uid.clone(),
            owner.revision,
            target.clone(),
        ));
        apply_group(
            &database,
            vec![verified("owner-bind", bind, owner_uid.clone())],
        )
        .unwrap();
        let mut owner_revision = ZoneRevision::new(2);
        let owner_generation = ResourceGeneration::new(1).unwrap();

        let child_ref = ResourceRef::parse("Process/guest-vmm").unwrap();
        let child_placeholder = ResourceUid::parse("423e4567-e89b-42d3-a456-426614174003").unwrap();
        let mut create = create_mutation_with_body(
            child_ref.clone(),
            process_body("guest-vmm", Some(&owner_ref)),
        );
        create.owner = Some(owner_ref.clone());
        create.assignment = Some(owner_child_fence(
            owner_ref.clone(),
            owner_uid.clone(),
            owner_revision,
            owner_generation,
            target.clone(),
        ));
        let mut owner_status = create_mutation_with_body(
            owner_ref.clone(),
            stored_envelope(&database, &owner_ref)
                .canonical_bytes()
                .unwrap(),
        );
        owner_status.kind = ResourceMutationKind::UpdateStatus;
        owner_status.expected = ExpectedRevision::Exact(owner_revision);
        owner_status.expected_uid = Some(owner_uid.clone());
        owner_status.assignment = Some(primary_fence(
            owner_uid.clone(),
            owner_revision,
            target.clone(),
        ));
        let mut batch = verified("owner-first-child-batch", owner_status, owner_uid.clone());
        let child_write = verified("owner-first-child-batch", create, child_placeholder);
        batch
            .authorization
            .targets
            .extend(child_write.authorization.targets);
        batch.mutations.extend(child_write.mutations);
        let child = apply_group(&database, vec![batch]).unwrap().results[0]
            .as_ref()
            .unwrap()
            .resources[1]
            .clone();
        assert_eq!(child.resource_ref, child_ref);
        assert_eq!(
            child.owner_generation,
            Some(owner.generation)
        );
        assert_eq!(
            stored_envelope(&database, &child_ref)
                .metadata()
                .owner_ref(),
            Some(&owner_ref)
        );
        owner_revision = ZoneRevision::new(3);

        let mut update = create_mutation_with_body(
            child_ref.clone(),
            process_body_with_uid("guest-vmm", Some(&owner_ref), &child.uid),
        );
        update.kind = ResourceMutationKind::UpdateSpec;
        update.expected = ExpectedRevision::Exact(child.revision);
        update.expected_uid = Some(child.uid.clone());
        update.owner = None;
        update.assignment = Some(owner_child_fence(
            owner_ref.clone(),
            owner_uid.clone(),
            owner_revision,
            owner_generation,
            target.clone(),
        ));
        let updated = apply_group(
            &database,
            vec![verified("child-update", update, child.uid.clone())],
        )
        .unwrap()
        .results[0]
            .as_ref()
            .unwrap()
            .resources[0]
            .clone();
            assert_eq!(updated.owner_generation, Some(owner.generation));

            let mut request_delete = create_mutation(child_ref.clone());
        request_delete.kind = ResourceMutationKind::Delete;
        request_delete.expected = ExpectedRevision::Exact(updated.revision);
        request_delete.expected_uid = Some(child.uid.clone());
        request_delete.canonical_resource = None;
        request_delete.assignment = Some(owner_child_fence(
            owner_ref.clone(),
            owner_uid.clone(),
            owner_revision,
            owner_generation,
            target.clone(),
        ));
        apply_group(
            &database,
            vec![verified(
                "child-delete-request",
                request_delete,
                child.uid.clone(),
            )],
        )
        .unwrap();

        let read = database.begin_read().unwrap();
        assert_eq!(read.open_table(OWNER_INDEX).unwrap().len().unwrap(), 0);
        assert!(
            read.open_table(RESOURCES)
                .unwrap()
                .get(resource_key(&child_ref).unwrap().as_slice())
                .unwrap()
                .is_none()
        );
        validate_consistency(&database).unwrap();
    }

    #[test]
    fn owner_child_create_rejects_same_batch_follow_up() {
        let (_directory, database, _identity) = fixture();
        let owner_ref = ResourceRef::parse("Guest/guest").unwrap();
        let owner = apply_group(
            &database,
            vec![verified(
                "staged-owner-create",
                create_mutation_with_body(owner_ref.clone(), guest_body("guest")),
                ResourceUid::parse("323e4567-e89b-42d3-a456-426614174002").unwrap(),
            )],
        )
        .unwrap()
        .results[0]
            .as_ref()
            .unwrap()
            .resources[0]
            .clone();
        let owner_uid = owner.uid.clone();
        let assignment_target = ResourceRef::parse("Host/host-system").unwrap();
        let mut bind = create_mutation(owner_ref.clone());
        bind.kind = ResourceMutationKind::UpdateFinalizers;
        bind.expected = ExpectedRevision::Exact(owner.revision);
        bind.expected_uid = Some(owner_uid.clone());
        bind.canonical_resource = None;
        bind.add_finalizers = vec![FinalizerId::parse("core.staged-owner-child").unwrap()];
        bind.assignment = Some(primary_fence(
            owner_uid.clone(),
            owner.revision,
            assignment_target.clone(),
        ));
        apply_group(
            &database,
            vec![verified("staged-owner-bind", bind, owner_uid.clone())],
        )
        .unwrap();

        let owner_revision = ZoneRevision::new(2);
        let owner_generation = ResourceGeneration::new(1).unwrap();
        let make_batch = |operation_id: &str,
                          child_name: &str,
                          child_uid: &ResourceUid,
                          follow_up: ResourceMutationKind| {
            let child_ref =
                ResourceRef::parse(&format!("{}/{}", PROCESS_RESOURCE_TYPE, child_name)).unwrap();
            let mut create = create_mutation_with_body(
                child_ref.clone(),
                process_body(child_name, Some(&owner_ref)),
            );
            create.owner = Some(owner_ref.clone());
            create.assignment = Some(owner_child_fence(
                owner_ref.clone(),
                owner_uid.clone(),
                owner_revision,
                owner_generation,
                assignment_target.clone(),
            ));
            let mut follow = create_mutation_with_body(
                child_ref,
                process_body_with_uid(child_name, Some(&owner_ref), child_uid),
            );
            follow.kind = follow_up;
            follow.expected = ExpectedRevision::Exact(ZoneRevision::new(3));
            follow.expected_uid = Some(child_uid.clone());
            follow.owner = None;
            follow.canonical_resource = (follow_up != ResourceMutationKind::Delete).then_some(
                process_body_with_uid(child_name, Some(&owner_ref), child_uid),
            );
            follow.assignment = Some(owner_child_fence(
                owner_ref.clone(),
                owner_uid.clone(),
                owner_revision,
                owner_generation,
                assignment_target.clone(),
            ));

            let mut batch = verified(operation_id, create, child_uid.clone());
            let follow_batch = verified(operation_id, follow, child_uid.clone());
            batch
                .authorization
                .targets
                .extend(follow_batch.authorization.targets);
            batch.mutations.extend(follow_batch.mutations);
            batch
        };
        for (operation_id, child_name, follow_up) in [
            (
                "staged-owner-update",
                "staged-update",
                ResourceMutationKind::UpdateSpec,
            ),
            (
                "staged-owner-delete",
                "staged-delete",
                ResourceMutationKind::Delete,
            ),
        ] {
            let child_uid = ResourceUid::parse(if follow_up == ResourceMutationKind::UpdateSpec {
                "423e4567-e89b-42d3-a456-426614174003"
            } else {
                "523e4567-e89b-42d3-a456-426614174004"
            })
            .unwrap();
            let child_ref =
                ResourceRef::parse(&format!("{PROCESS_RESOURCE_TYPE}/{child_name}")).unwrap();
            let revision_before = current_meta(&database).unwrap().current_revision;
            let batch = make_batch(operation_id, child_name, &child_uid, follow_up);

            let outcome = apply_group(&database, vec![batch]).unwrap();
            assert!(outcome.batch.is_none());
            let error = outcome.results[0].as_ref().unwrap_err();
            assert_eq!(error.kind(), StoreErrorKind::ResourceConflict);
            assert_eq!(
                error.reason_code(),
                "same-batch-create-followup-unsupported"
            );
            assert_eq!(
                current_meta(&database).unwrap().current_revision,
                revision_before
            );
            assert!(
                database
                    .begin_read()
                    .unwrap()
                    .open_table(RESOURCES)
                    .unwrap()
                    .get(resource_key(&child_ref).unwrap().as_slice())
                    .unwrap()
                    .is_none()
            );

            let replay = apply_group(
                &database,
                vec![make_batch(operation_id, child_name, &child_uid, follow_up)],
            )
            .unwrap();
            let replay_error = replay.results[0].as_ref().unwrap_err();
            assert_eq!(replay_error.kind(), StoreErrorKind::ResourceConflict);
            assert_eq!(replay_error.reason_code(), "resource-conflict");
            assert_eq!(
                current_meta(&database).unwrap().current_revision,
                revision_before
            );
            assert!(
                database
                    .begin_read()
                    .unwrap()
                    .open_table(RESOURCES)
                    .unwrap()
                    .get(resource_key(&child_ref).unwrap().as_slice())
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn same_batch_delete_recreate_rejects_before_apply_and_replays_conflict() {
        let (_directory, database, _identity) = fixture();
        let target = ResourceRef::parse("Host/host-system").unwrap();
        let seeded = apply_group(
            &database,
            vec![verified(
                "recycle-seed",
                create_mutation(target.clone()),
                ResourceUid::parse("323e4567-e89b-42d3-a456-426614174002").unwrap(),
            )],
        )
        .unwrap();
        let original = seeded.results[0].as_ref().unwrap().resources[0].clone();
        let original_body = stored_envelope(&database, &target)
            .canonical_bytes()
            .unwrap();
        let replacement_uid = ResourceUid::parse("423e4567-e89b-42d3-a456-426614174003").unwrap();
        let make_batch = || {
            let mut delete = create_mutation(target.clone());
            delete.kind = ResourceMutationKind::Delete;
            delete.expected = ExpectedRevision::Exact(original.revision);
            delete.expected_uid = Some(original.uid.clone());
            delete.canonical_resource = None;

            let create = create_mutation_with_uid(target.clone(), &replacement_uid);
            let mut batch = verified("delete-recreate", delete, original.uid.clone());
            let create_write = verified("delete-recreate", create, replacement_uid.clone());
            batch
                .authorization
                .targets
                .extend(create_write.authorization.targets);
            batch.mutations.extend(create_write.mutations);
            batch
        };
        let revision_before = current_meta(&database).unwrap().current_revision;
        let outcome = apply_group(&database, vec![make_batch()]).unwrap();
        assert!(outcome.batch.is_none());
        let error = outcome.results[0].as_ref().unwrap_err();
        assert_eq!(error.kind(), StoreErrorKind::ResourceConflict);
        assert_eq!(
            error.reason_code(),
            "same-batch-delete-recreate-unsupported"
        );
        assert_eq!(
            current_meta(&database).unwrap().current_revision,
            revision_before
        );
        assert_eq!(
            stored_envelope(&database, &target)
                .canonical_bytes()
                .unwrap(),
            original_body
        );

        let replay = apply_group(&database, vec![make_batch()]).unwrap();
        let replay_error = replay.results[0].as_ref().unwrap_err();
        assert_eq!(replay_error.kind(), StoreErrorKind::ResourceConflict);
        assert_eq!(replay_error.reason_code(), "resource-conflict");
        assert_eq!(
            current_meta(&database).unwrap().current_revision,
            revision_before
        );
        assert_eq!(
            stored_envelope(&database, &target)
                .canonical_bytes()
                .unwrap(),
            original_body
        );
        validate_consistency(&database).unwrap();
    }

    #[test]
    fn owner_child_fences_reject_foreign_owner_stale_identity_and_unowned_children() {
        let (_directory, database, _identity) = fixture();
        let owner_ref = ResourceRef::parse("Guest/guest").unwrap();
        let owner = apply_group(
            &database,
            vec![verified(
                "failure-owner-create",
                create_mutation_with_body(owner_ref.clone(), guest_body("guest")),
                ResourceUid::parse("323e4567-e89b-42d3-a456-426614174002").unwrap(),
            )],
        )
        .unwrap()
        .results[0]
            .as_ref()
            .unwrap()
            .resources[0]
            .clone();
        let owner_uid = owner.uid.clone();
        let target = ResourceRef::parse("Host/host-system").unwrap();
        let mut bind = create_mutation(owner_ref.clone());
        bind.kind = ResourceMutationKind::UpdateFinalizers;
        bind.expected = ExpectedRevision::Exact(owner.revision);
        bind.expected_uid = Some(owner_uid.clone());
        bind.canonical_resource = None;
        bind.add_finalizers = vec![FinalizerId::parse("core.owner-child-failure").unwrap()];
        bind.assignment = Some(primary_fence(
            owner_uid.clone(),
            owner.revision,
            target.clone(),
        ));
        apply_group(
            &database,
            vec![verified("failure-owner-bind", bind, owner_uid.clone())],
        )
        .unwrap();

        let owner_revision = ZoneRevision::new(2);
        let owner_generation = ResourceGeneration::new(1).unwrap();
        let child_target = ResourceRef::parse("Process/rejected").unwrap();
        let mut successor_epoch = create_mutation_with_body(
            ResourceRef::parse("Process/successor-epoch").unwrap(),
            process_body("successor-epoch", Some(&owner_ref)),
        );
        successor_epoch.owner = Some(owner_ref.clone());
        let mut successor_fence = owner_child_fence(
            owner_ref.clone(),
            owner_uid.clone(),
            owner_revision,
            owner_generation,
            target.clone(),
        );
        successor_fence.epoch = 2;
        successor_epoch.assignment = Some(successor_fence);
        let rejected = apply_group(
            &database,
            vec![verified(
                "failure-successor-child",
                successor_epoch,
                owner_uid.clone(),
            )],
        )
        .unwrap();
        assert_eq!(
            rejected.results[0].as_ref().unwrap_err().reason_code(),
            "stale-assignment"
        );

        let mut foreign = create_mutation_with_body(
            child_target.clone(),
            process_body(
                "rejected",
                Some(&ResourceRef::parse("Guest/sibling").unwrap()),
            ),
        );
        foreign.owner = Some(ResourceRef::parse("Guest/sibling").unwrap());
        foreign.assignment = Some(owner_child_fence(
            ResourceRef::parse("Guest/sibling").unwrap(),
            owner_uid.clone(),
            owner_revision,
            owner_generation,
            target.clone(),
        ));
        let foreign_replay = foreign.clone();
        let rejected = apply_group(
            &database,
            vec![verified(
                "failure-foreign-owner",
                foreign,
                owner_uid.clone(),
            )],
        )
        .unwrap();
        assert_eq!(
            rejected.results[0].as_ref().unwrap_err().reason_code(),
            "assignment-owner-missing"
        );
        let replayed = apply_group(
            &database,
            vec![verified(
                "failure-foreign-owner",
                foreign_replay,
                owner_uid.clone(),
            )],
        )
        .unwrap();
        assert_eq!(
            replayed.results[0].as_ref().unwrap_err().kind(),
            StoreErrorKind::ResourceConflict
        );

        let mut stale_revision = create_mutation_with_body(
            ResourceRef::parse("Process/stale-revision").unwrap(),
            process_body("stale-revision", Some(&owner_ref)),
        );
        stale_revision.owner = Some(owner_ref.clone());
        stale_revision.assignment = Some(owner_child_fence(
            owner_ref.clone(),
            owner_uid.clone(),
            ZoneRevision::new(1),
            owner_generation,
            target.clone(),
        ));
        let rejected = apply_group(
            &database,
            vec![verified(
                "failure-stale-owner-revision",
                stale_revision,
                owner_uid.clone(),
            )],
        )
        .unwrap();
        assert_eq!(
            rejected.results[0].as_ref().unwrap_err().reason_code(),
            "stale-assignment"
        );

        let forged_uid = ResourceUid::parse("523e4567-e89b-42d3-a456-426614174004").unwrap();
        let mut stale_uid = create_mutation_with_body(
            ResourceRef::parse("Process/stale-uid").unwrap(),
            process_body("stale-uid", Some(&owner_ref)),
        );
        stale_uid.owner = Some(owner_ref.clone());
        stale_uid.assignment = Some(owner_child_fence(
            owner_ref.clone(),
            forged_uid,
            owner_revision,
            owner_generation,
            target.clone(),
        ));
        let rejected = apply_group(
            &database,
            vec![verified(
                "failure-stale-owner-uid",
                stale_uid,
                owner_uid.clone(),
            )],
        )
        .unwrap();
        assert_eq!(
            rejected.results[0].as_ref().unwrap_err().reason_code(),
            "stale-assignment"
        );

        let mut wrong_type = create_mutation_with_body(
            ResourceRef::parse("Host/rejected").unwrap(),
            guest_body("rejected"),
        );
        wrong_type.owner = Some(owner_ref.clone());
        wrong_type.assignment = Some(owner_child_fence(
            owner_ref.clone(),
            owner_uid.clone(),
            owner_revision,
            owner_generation,
            target.clone(),
        ));
        let rejected = apply_group(
            &database,
            vec![verified(
                "failure-wrong-child-type",
                wrong_type,
                owner_uid.clone(),
            )],
        )
        .unwrap();
        assert_eq!(
            rejected.results[0].as_ref().unwrap_err().reason_code(),
            "stale-assignment"
        );

        let ownerless_target = ResourceRef::parse("Process/ownerless").unwrap();
        let ownerless =
            create_mutation_with_body(ownerless_target.clone(), process_body("ownerless", None));
        apply_group(
            &database,
            vec![verified(
                "failure-ownerless-create",
                ownerless,
                ResourceUid::parse("623e4567-e89b-42d3-a456-426614174005").unwrap(),
            )],
        )
        .unwrap();
        let mut ownerless_update =
            create_mutation_with_body(ownerless_target.clone(), process_body("ownerless", None));
        ownerless_update.kind = ResourceMutationKind::UpdateSpec;
        ownerless_update.expected = ExpectedRevision::Exact(ZoneRevision::new(3));
        ownerless_update.expected_uid = Some(
            stored_envelope(&database, &ownerless_target)
                .metadata()
                .uid()
                .clone(),
        );
        ownerless_update.assignment = Some(owner_child_fence(
            owner_ref.clone(),
            owner_uid.clone(),
            owner_revision,
            owner_generation,
            target.clone(),
        ));
        let ownerless_uid = ownerless_update.expected_uid.clone().unwrap();
        let ownerless_replay = ownerless_update.clone();
        let rejected = apply_group(
            &database,
            vec![verified(
                "failure-ownerless-update",
                ownerless_update,
                ownerless_uid.clone(),
            )],
        )
        .unwrap();
        assert_eq!(
            rejected.results[0].as_ref().unwrap_err().reason_code(),
            "owner-child-binding-mismatch"
        );
        let replayed = apply_group(
            &database,
            vec![verified(
                "failure-ownerless-update",
                ownerless_replay,
                ownerless_uid,
            )],
        )
        .unwrap();
        assert_eq!(
            replayed.results[0].as_ref().unwrap_err().kind(),
            StoreErrorKind::ResourceConflict
        );

        let sibling_ref = ResourceRef::parse("Guest/sibling").unwrap();
        apply_group(
            &database,
            vec![verified(
                "failure-sibling-create",
                create_mutation_with_body(sibling_ref.clone(), guest_body("sibling")),
                ResourceUid::parse("723e4567-e89b-42d3-a456-426614174006").unwrap(),
            )],
        )
        .unwrap();
        let sibling_child_target = ResourceRef::parse("Process/sibling-child").unwrap();
        let mut sibling_child = create_mutation_with_body(
            sibling_child_target.clone(),
            process_body("sibling-child", Some(&sibling_ref)),
        );
        sibling_child.owner = Some(sibling_ref);
        apply_group(
            &database,
            vec![verified(
                "failure-sibling-child-create",
                sibling_child,
                ResourceUid::parse("823e4567-e89b-42d3-a456-426614174007").unwrap(),
            )],
        )
        .unwrap();
        let sibling_child_uid = stored_envelope(&database, &sibling_child_target)
            .metadata()
            .uid()
            .clone();
        let mut sibling_update = create_mutation_with_body(
            sibling_child_target,
            process_body_with_uid(
                "sibling-child",
                Some(&ResourceRef::parse("Guest/sibling").unwrap()),
                &sibling_child_uid,
            ),
        );
        sibling_update.kind = ResourceMutationKind::UpdateSpec;
        sibling_update.expected = ExpectedRevision::Exact(ZoneRevision::new(5));
        sibling_update.expected_uid = Some(sibling_child_uid.clone());
        sibling_update.assignment = Some(owner_child_fence(
            owner_ref,
            owner_uid,
            owner_revision,
            owner_generation,
            target,
        ));
        let rejected = apply_group(
            &database,
            vec![verified(
                "failure-sibling-child-update",
                sibling_update,
                sibling_child_uid,
            )],
        )
        .unwrap();
        assert_eq!(
            rejected.results[0].as_ref().unwrap_err().reason_code(),
            "owner-child-binding-mismatch"
        );
    }
}
