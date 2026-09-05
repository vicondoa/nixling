//! Storage-neutral resource store contract.
//!
//! This crate intentionally contains no database or executor dependency.

pub mod error;
pub mod mutation_seal;

use d2b_contracts_resource::v3::identity::ReconnectGeneration;
use d2b_contracts_resource::v3::{
    ConfigurationGeneration, ControllerGeneration, FinalizerId, ResourceGeneration, ResourceName,
    ResourceRef, ResourceTypeName, ResourceUid, ZoneId, ZoneRevision,
};

pub use error::{
    MAX_STORE_SLOTS, MutationOrdinal, MutationOrdinalError, SealIdentityMismatch, StoreError,
    StoreErrorKind, StoreSlot, StoreSlotError,
};
pub use mutation_seal::{MutationSealBody, OpenedMutation, SealedMutation, StoreSealIdentity};

/// Exact optimistic precondition for a mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedRevision {
    CreateAbsent,
    Exact(ZoneRevision),
}

/// Status projection selected before reading a resource body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreProjection {
    Full,
    BaseOnly,
    MetadataOnly,
}

/// Exact-match indexed filter.
#[derive(Clone, PartialEq, Eq)]
pub struct StoreFilter {
    pub field: String,
    pub values: Vec<String>,
}

impl core::fmt::Debug for StoreFilter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StoreFilter")
            .field("value_count", &self.values.len())
            .finish()
    }
}

/// One resource body returned by the store.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredResource {
    pub resource_ref: ResourceRef,
    pub zone: ZoneId,
    pub uid: ResourceUid,
    /// Internal store binding for the singular owner, when one exists.
    pub owner_uid: Option<ResourceUid>,
    /// Resource generation captured when the singular owner binding was written.
    pub owner_generation: Option<ResourceGeneration>,
    pub generation: ResourceGeneration,
    pub revision: ZoneRevision,
    pub canonical_json: Vec<u8>,
    pub payload_digest: String,
}

impl core::fmt::Debug for StoredResource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StoredResource")
            .field("generation", &self.generation)
            .field("revision", &self.revision)
            .field(
                "canonical_json",
                &format_args!("<{} bytes>", self.canonical_json.len()),
            )
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct StoreGetRequest {
    pub operation: StoreOperationContext,
    pub zone: ZoneId,
    pub target: ResourceRef,
    pub expected_uid: Option<ResourceUid>,
    pub projection: StoreProjection,
}

impl core::fmt::Debug for StoreGetRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StoreGetRequest")
            .field("has_expected_uid", &self.expected_uid.is_some())
            .field("projection", &self.projection)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct StoreListRequest {
    pub operation: StoreOperationContext,
    pub zone: ZoneId,
    pub resource_types: Vec<ResourceTypeName>,
    pub resource_names: Vec<ResourceName>,
    pub filters: Vec<StoreFilter>,
    pub page_size: u32,
    pub cursor: Option<String>,
    pub projection: StoreProjection,
}

impl core::fmt::Debug for StoreListRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StoreListRequest")
            .field("resource_type_count", &self.resource_types.len())
            .field("resource_name_count", &self.resource_names.len())
            .field("filter_count", &self.filters.len())
            .field("page_size", &self.page_size)
            .field("has_cursor", &self.cursor.is_some())
            .field("projection", &self.projection)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct StoreListResult {
    pub resources: Vec<StoredResource>,
    pub snapshot_revision: ZoneRevision,
    pub next_cursor: Option<String>,
    pub truncated: bool,
}

impl core::fmt::Debug for StoreListResult {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StoreListResult")
            .field("resource_count", &self.resources.len())
            .field("snapshot_revision", &self.snapshot_revision)
            .field("has_next_cursor", &self.next_cursor.is_some())
            .field("truncated", &self.truncated)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct StoreWatchRequest {
    pub operation: StoreOperationContext,
    pub zone: ZoneId,
    pub resource_types: Vec<ResourceTypeName>,
    pub resource_names: Vec<ResourceName>,
    pub filters: Vec<StoreFilter>,
    pub after_revision: ZoneRevision,
    pub initial_credits: u32,
    pub projection: StoreProjection,
}

impl core::fmt::Debug for StoreWatchRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StoreWatchRequest")
            .field("resource_type_count", &self.resource_types.len())
            .field("resource_name_count", &self.resource_names.len())
            .field("filter_count", &self.filters.len())
            .field("after_revision", &self.after_revision)
            .field("initial_credits", &self.initial_credits)
            .field("projection", &self.projection)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct StoreWatchReceipt {
    pub stream_name: String,
    pub snapshot_revision: ZoneRevision,
}

impl core::fmt::Debug for StoreWatchReceipt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StoreWatchReceipt")
            .field("snapshot_revision", &self.snapshot_revision)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct StoreResolveRequest {
    pub operation: StoreOperationContext,
    pub zone: ZoneId,
    pub target: ResourceRef,
    pub expected_uid: Option<ResourceUid>,
}

impl core::fmt::Debug for StoreResolveRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StoreResolveRequest")
            .field("has_expected_uid", &self.expected_uid.is_some())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct StoreResolvedIdentity {
    pub zone: ZoneId,
    pub resource_ref: ResourceRef,
    pub uid: ResourceUid,
    pub generation: ResourceGeneration,
    pub revision: ZoneRevision,
}

impl core::fmt::Debug for StoreResolvedIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StoreResolvedIdentity")
            .field("generation", &self.generation)
            .field("revision", &self.revision)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct StoreInspectSchemaRequest {
    pub operation: StoreOperationContext,
    pub zone: ZoneId,
    pub resource_type: ResourceTypeName,
}

impl core::fmt::Debug for StoreInspectSchemaRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("StoreInspectSchemaRequest(<redacted>)")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct StoredSchema {
    pub resource_type: ResourceTypeName,
    pub canonical_json: Vec<u8>,
    pub payload_digest: String,
}

impl core::fmt::Debug for StoredSchema {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StoredSchema")
            .field(
                "canonical_json",
                &format_args!("<{} bytes>", self.canonical_json.len()),
            )
            .finish()
    }
}

/// One full replacement mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceMutationKind {
    Create,
    UpdateSpec,
    UpdateStatus,
    UpdateMetadata,
    UpdateFinalizers,
    Delete,
}

/// Structurally decoded mutation; authorization is attached only by admission.
#[derive(Clone, PartialEq, Eq)]
pub struct StoreMutation {
    pub kind: ResourceMutationKind,
    pub zone: ZoneId,
    pub target: ResourceRef,
    pub expected: ExpectedRevision,
    pub expected_uid: Option<ResourceUid>,
    pub owner: Option<ResourceRef>,
    pub canonical_resource: Option<Vec<u8>>,
    pub add_finalizers: Vec<FinalizerId>,
    pub remove_finalizers: Vec<FinalizerId>,
    pub wait_for_reconcile: bool,
    pub reconcile_deadline_ms: Option<u64>,
    /// Core-assigned configuration generation for an internal bundle apply.
    ///
    /// Public Resource API mutations always leave this unset.
    pub configuration_generation: Option<ConfigurationGeneration>,
    /// Optional Core-issued assignment fence for controller-owned writes.
    pub assignment: Option<ResourceAssignmentFence>,
}

impl core::fmt::Debug for StoreMutation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StoreMutation")
            .field("kind", &self.kind)
            .field("expected", &self.expected)
            .field("has_expected_uid", &self.expected_uid.is_some())
            .field("has_owner", &self.owner.is_some())
            .field("has_canonical_resource", &self.canonical_resource.is_some())
            .field("add_finalizer_count", &self.add_finalizers.len())
            .field("remove_finalizer_count", &self.remove_finalizers.len())
            .field("wait_for_reconcile", &self.wait_for_reconcile)
            .field(
                "has_reconcile_deadline",
                &self.reconcile_deadline_ms.is_some(),
            )
            .field("has_assignment_fence", &self.assignment.is_some())
            .finish()
    }
}

/// Storage-neutral assignment evidence attached to one controller mutation.
#[derive(Clone, PartialEq, Eq)]
pub struct ResourceAssignmentFence {
    pub resource_uid: ResourceUid,
    pub resource_revision: ZoneRevision,
    pub provider_generation: ResourceGeneration,
    pub controller_generation: ControllerGeneration,
    pub controller_role: ResourceRef,
    pub target: ResourceRef,
    pub session_generation: ReconnectGeneration,
    pub epoch: u64,
    pub scope: ResourceAssignmentScope,
}

/// The primary or owner-child target bound to an assignment fence.
#[derive(Clone, PartialEq, Eq)]
pub enum ResourceAssignmentScope {
    /// The assigned resource itself.
    Primary,
    /// A child bound to the exact assigned resource identity.
    OwnerChild {
        owner_ref: ResourceRef,
        owner_uid: ResourceUid,
        owner_revision: ZoneRevision,
        owner_generation: ResourceGeneration,
    },
}

impl core::fmt::Debug for ResourceAssignmentScope {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Primary => formatter.write_str("ResourceAssignmentScope::Primary"),
            Self::OwnerChild {
                owner_revision,
                owner_generation,
                ..
            } => formatter
                .debug_struct("ResourceAssignmentScope::OwnerChild")
                .field("owner_ref", &"<redacted>")
                .field("owner_uid", &"<redacted>")
                .field("owner_revision", owner_revision)
                .field("owner_generation", owner_generation)
                .finish(),
        }
    }
}

impl core::fmt::Debug for ResourceAssignmentFence {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ResourceAssignmentFence")
            .field("resource_uid", &"<redacted>")
            .field("resource_revision", &self.resource_revision)
            .field("provider_generation", &self.provider_generation)
            .field("controller_generation", &self.controller_generation)
            .field("controller_role", &"<redacted>")
            .field("target", &"<redacted>")
            .field("session_generation", &self.session_generation)
            .field("epoch", &"<redacted>")
            .field("scope", &self.scope)
            .finish()
    }
}

/// Backend-ready mutation carrying the final canonical identity and digest.
pub struct PreparedStoreMutation {
    mutation: StoreMutation,
    resource_uid: Option<ResourceUid>,
    payload_digest: Option<String>,
}

impl PreparedStoreMutation {
    pub const fn new(
        mutation: StoreMutation,
        resource_uid: Option<ResourceUid>,
        payload_digest: Option<String>,
    ) -> Self {
        Self {
            mutation,
            resource_uid,
            payload_digest,
        }
    }

    pub const fn mutation(&self) -> &StoreMutation {
        &self.mutation
    }

    /// Final UID used by the resource record and every UID-keyed index.
    pub const fn resource_uid(&self) -> Option<&ResourceUid> {
        self.resource_uid.as_ref()
    }

    /// Digest of the final canonical bytes persisted by the backend.
    pub fn payload_digest(&self) -> Option<&str> {
        self.payload_digest.as_deref()
    }
}

impl core::fmt::Debug for PreparedStoreMutation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PreparedStoreMutation")
            .field("kind", &self.mutation.kind)
            .field("has_resource_uid", &self.resource_uid.is_some())
            .field("has_payload_digest", &self.payload_digest.is_some())
            .finish()
    }
}

/// Closed operation admitted by the evaluator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmittedVerb {
    Get,
    List,
    Watch,
    Create,
    UpdateSpec,
    UpdateStatus,
    UpdateMetadata,
    UpdateFinalizers,
    Delete,
    UseCredential,
    AdminCredential,
}

/// Exact target attributes evaluated before a mutation was queued.
#[derive(Clone, PartialEq, Eq)]
pub struct AdmittedAuthorizationTarget {
    pub resource_type: ResourceTypeName,
    pub resource_name: Option<ResourceName>,
    pub verb: AdmittedVerb,
    pub subresource: Option<String>,
    pub execution_ref: Option<ResourceRef>,
}

impl core::fmt::Debug for AdmittedAuthorizationTarget {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AdmittedAuthorizationTarget")
            .field("verb", &self.verb)
            .field("has_resource_name", &self.resource_name.is_some())
            .field("has_subresource", &self.subresource.is_some())
            .field("has_execution_ref", &self.execution_ref.is_some())
            .finish()
    }
}

/// Exact authenticated and target attributes captured at admission.
#[derive(Clone, PartialEq, Eq)]
pub struct AdmittedAuthorization {
    pub zone: ZoneId,
    pub subject_ref: ResourceRef,
    pub subject_uid: ResourceUid,
    pub targets: Vec<AdmittedAuthorizationTarget>,
}

impl core::fmt::Debug for AdmittedAuthorization {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AdmittedAuthorization")
            .field("target_count", &self.targets.len())
            .finish()
    }
}

/// Revisions that the write transaction must compare for equality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicySnapshot {
    pub policy_revision: u64,
    pub api_catalog_revision: u64,
    pub active_configuration_revision: ConfigurationGeneration,
    pub controller_generation: Option<ControllerGeneration>,
}

/// Fixed operation metadata captured before queueing.
#[derive(Clone, PartialEq, Eq)]
pub struct StoreOperationContext {
    pub operation_id: String,
    pub idempotency_key: Option<String>,
    pub correlation_id: String,
    pub trace_id: Option<String>,
    pub deadline_ms: u64,
}

impl core::fmt::Debug for StoreOperationContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StoreOperationContext")
            .field("has_idempotency_key", &self.idempotency_key.is_some())
            .field("has_trace_id", &self.trace_id.is_some())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct StoreCommitResult {
    pub resources: Vec<StoredResource>,
    pub revision: ZoneRevision,
}

impl core::fmt::Debug for StoreCommitResult {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StoreCommitResult")
            .field("resource_count", &self.resources.len())
            .field("revision", &self.revision)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZONE_SENTINEL: &str = "zone-debug-sentinel";
    const NAME_SENTINEL: &str = "name-debug-sentinel";
    const REF_SENTINEL: &str = "Host/ref-debug-sentinel";
    const UID_SENTINEL: &str = "feedface-feed-4bad-8dad-deadbeef0001";
    const TYPE_SENTINEL: &str = "debug-sentinel.d2bus.org.Widget";
    const PAYLOAD_SENTINEL: &str = "payload-debug-sentinel";
    const DIGEST_SENTINEL: &str = "digest-debug-sentinel";
    const OPERATION_SENTINEL: &str = "operation-debug-sentinel";
    const FILTER_SENTINEL: &str = "filter-debug-sentinel";
    const CURSOR_SENTINEL: &str = "cursor-debug-sentinel";
    const STREAM_SENTINEL: &str = "stream-debug-sentinel";
    const SUBRESOURCE_SENTINEL: &str = "subresource-debug-sentinel";

    fn operation() -> StoreOperationContext {
        StoreOperationContext {
            operation_id: OPERATION_SENTINEL.to_owned(),
            idempotency_key: Some(OPERATION_SENTINEL.to_owned()),
            correlation_id: OPERATION_SENTINEL.to_owned(),
            trace_id: Some(OPERATION_SENTINEL.to_owned()),
            deadline_ms: 10,
        }
    }

    #[test]
    fn store_debug_surfaces_expose_only_whitelisted_diagnostics() {
        let zone = ZoneId::parse(ZONE_SENTINEL).unwrap();
        let resource_ref = ResourceRef::parse(REF_SENTINEL).unwrap();
        let uid = ResourceUid::parse(UID_SENTINEL).unwrap();
        let resource_type = ResourceTypeName::parse(TYPE_SENTINEL).unwrap();
        let resource_name = ResourceName::parse(NAME_SENTINEL).unwrap();
        let filter = StoreFilter {
            field: FILTER_SENTINEL.to_owned(),
            values: vec![FILTER_SENTINEL.to_owned()],
        };
        let resource = StoredResource {
            resource_ref: resource_ref.clone(),
            zone: zone.clone(),
            uid: uid.clone(),
            owner_uid: None,
            owner_generation: None,
            generation: ResourceGeneration::new(3).unwrap(),
            revision: ZoneRevision::new(5),
            canonical_json: PAYLOAD_SENTINEL.as_bytes().to_vec(),
            payload_digest: DIGEST_SENTINEL.to_owned(),
        };
        let get = StoreGetRequest {
            operation: operation(),
            zone: zone.clone(),
            target: resource_ref.clone(),
            expected_uid: Some(uid.clone()),
            projection: StoreProjection::Full,
        };
        let list = StoreListRequest {
            operation: operation(),
            zone: zone.clone(),
            resource_types: vec![resource_type.clone()],
            resource_names: vec![resource_name.clone()],
            filters: vec![filter.clone()],
            page_size: 10,
            cursor: Some(CURSOR_SENTINEL.to_owned()),
            projection: StoreProjection::BaseOnly,
        };
        let list_result = StoreListResult {
            resources: vec![resource.clone()],
            snapshot_revision: ZoneRevision::new(6),
            next_cursor: Some(CURSOR_SENTINEL.to_owned()),
            truncated: true,
        };
        let watch = StoreWatchRequest {
            operation: operation(),
            zone: zone.clone(),
            resource_types: vec![resource_type.clone()],
            resource_names: vec![resource_name.clone()],
            filters: vec![filter.clone()],
            after_revision: ZoneRevision::new(7),
            initial_credits: 8,
            projection: StoreProjection::MetadataOnly,
        };
        let watch_receipt = StoreWatchReceipt {
            stream_name: STREAM_SENTINEL.to_owned(),
            snapshot_revision: ZoneRevision::new(8),
        };
        let resolve = StoreResolveRequest {
            operation: operation(),
            zone: zone.clone(),
            target: resource_ref.clone(),
            expected_uid: Some(uid.clone()),
        };
        let resolved = StoreResolvedIdentity {
            zone: zone.clone(),
            resource_ref: resource_ref.clone(),
            uid: uid.clone(),
            generation: ResourceGeneration::new(9).unwrap(),
            revision: ZoneRevision::new(10),
        };
        let inspect = StoreInspectSchemaRequest {
            operation: operation(),
            zone: zone.clone(),
            resource_type: resource_type.clone(),
        };
        let schema = StoredSchema {
            resource_type: resource_type.clone(),
            canonical_json: PAYLOAD_SENTINEL.as_bytes().to_vec(),
            payload_digest: DIGEST_SENTINEL.to_owned(),
        };
        let mutation = StoreMutation {
            kind: ResourceMutationKind::UpdateSpec,
            zone: zone.clone(),
            target: resource_ref.clone(),
            expected: ExpectedRevision::Exact(ZoneRevision::new(11)),
            expected_uid: Some(uid.clone()),
            owner: Some(ResourceRef::parse("Process/owner-debug-sentinel").unwrap()),
            canonical_resource: Some(PAYLOAD_SENTINEL.as_bytes().to_vec()),
            add_finalizers: Vec::new(),
            remove_finalizers: Vec::new(),
            wait_for_reconcile: true,
            reconcile_deadline_ms: Some(12),
            configuration_generation: None,
            assignment: None,
        };
        let admitted_target = AdmittedAuthorizationTarget {
            resource_type,
            resource_name: Some(resource_name),
            verb: AdmittedVerb::UpdateSpec,
            subresource: Some(SUBRESOURCE_SENTINEL.to_owned()),
            execution_ref: Some(ResourceRef::parse("Process/exec-debug-sentinel").unwrap()),
        };
        let authorization = AdmittedAuthorization {
            zone,
            subject_ref: ResourceRef::parse("User/subject-debug-sentinel").unwrap(),
            subject_uid: uid,
            targets: vec![admitted_target.clone()],
        };
        let commit = StoreCommitResult {
            resources: vec![resource.clone()],
            revision: ZoneRevision::new(13),
        };

        let rendered = [
            format!("{filter:?}"),
            format!("{resource:?}"),
            format!("{get:?}"),
            format!("{list:?}"),
            format!("{list_result:?}"),
            format!("{watch:?}"),
            format!("{watch_receipt:?}"),
            format!("{resolve:?}"),
            format!("{resolved:?}"),
            format!("{inspect:?}"),
            format!("{schema:?}"),
            format!("{mutation:?}"),
            format!("{admitted_target:?}"),
            format!("{authorization:?}"),
            format!("{:?}", operation()),
            format!("{commit:?}"),
        ];
        let protected = [
            ZONE_SENTINEL,
            NAME_SENTINEL,
            REF_SENTINEL,
            UID_SENTINEL,
            TYPE_SENTINEL,
            PAYLOAD_SENTINEL,
            DIGEST_SENTINEL,
            OPERATION_SENTINEL,
            FILTER_SENTINEL,
            CURSOR_SENTINEL,
            STREAM_SENTINEL,
            SUBRESOURCE_SENTINEL,
            "owner-debug-sentinel",
            "exec-debug-sentinel",
            "subject-debug-sentinel",
        ];
        for diagnostic in rendered {
            for sentinel in protected {
                assert!(!diagnostic.contains(sentinel), "{diagnostic}");
            }
        }
    }
}
