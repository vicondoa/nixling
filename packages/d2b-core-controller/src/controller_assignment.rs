//! Single-owner Provider controller assignment and fenced ResourceClient leases.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
};

use d2b_contracts_provider::v3::{
    ComponentType, ControllerInstanceScope, ControllerTargetKind, ProviderManifest,
};
use d2b_contracts_resource::v3::identity::ReconnectGeneration;
use d2b_contracts_resource::v3::process::PROCESS_RESOURCE_TYPE;
use d2b_contracts_resource::v3::{
    CanonicalJsonValue, ControllerGeneration, PlacementAnchor, PlacementTarget,
    PlacementTargetKind, ResourceEnvelope, ResourceGeneration, ResourceName, ResourceRef,
    ResourceTypeName, ResourceUid, ZoneId, ZoneRevision,
};
use serde_json::{Map, Value, json};

/// Maximum encoded assignment evidence carried by one scoped commit.
pub const MAX_SCOPED_COMMIT_TRANSPORT_BYTES: usize = 64 * 1024;
/// Maximum encoded controller assignment grant.
pub const MAX_CONTROLLER_ASSIGNMENT_GRANT_BYTES: usize = 64 * 1024;
/// Named stream channel carrying Core-to-controller assignment grants.
pub const CONTROLLER_ASSIGNMENT_STREAM_ID: u16 = 0x0101;
/// Initial credit used for the bounded assignment stream.
pub const CONTROLLER_ASSIGNMENT_STREAM_CREDIT: u32 = 256 * 1024;
/// Maximum ResourceTypes retained by one assignment grant.
pub const MAX_ASSIGNMENT_GRANT_RESOURCE_TYPES: usize = 64;
/// Maximum verbs retained by one assignment grant.
pub const MAX_ASSIGNMENT_GRANT_VERBS: usize = 16;
/// Maximum scope entries retained by one assignment grant.
pub const MAX_ASSIGNMENT_GRANT_SCOPES: usize = 2;

/// The maximum number of assignments held by one Zone authority.
pub const MAX_ASSIGNMENTS: usize = 16_384;
/// Maximum child ownership entries retained by one assignment.
pub const MAX_ASSIGNED_CHILDREN: usize = 4_096;
/// Assignment-bound query filter for the primary resource UID.
pub const ASSIGNMENT_UID_FILTER: &str = "assignment.resourceUid";
/// Assignment-bound query filter for an owned child resource UID.
pub const OWNER_UID_FILTER: &str = "owner.resourceUid";

/// A monotonically increasing, nonzero assignment epoch.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AssignmentEpoch(u64);

impl AssignmentEpoch {
    /// Construct a nonzero epoch.
    pub fn new(value: u64) -> Result<Self, AssignmentError> {
        if value == 0 {
            return Err(AssignmentError::EpochExhausted);
        }
        Ok(Self(value))
    }

    /// Return the opaque epoch ordinal.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Debug for AssignmentEpoch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AssignmentEpoch(<redacted>)")
    }
}

/// The exact target selected by a contract-owned placement anchor.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AssignmentTarget {
    /// The Zone singleton target.
    Zone(ZoneId),
    /// One exact Host or Guest execution target.
    Execution {
        /// The target kind.
        kind: PlacementTargetKind,
        /// The exact target reference.
        reference: ResourceRef,
    },
}

impl AssignmentTarget {
    fn from_placement(target: PlacementTarget) -> Self {
        match target {
            PlacementTarget::Zone(zone) => Self::Zone(zone),
            PlacementTarget::Execution { kind, reference } => Self::Execution { kind, reference },
        }
    }

    fn target_kind(&self) -> Option<ControllerTargetKind> {
        match self {
            Self::Zone(_) => Some(ControllerTargetKind::Zone),
            Self::Execution {
                kind: PlacementTargetKind::Host,
                ..
            } => Some(ControllerTargetKind::Host),
            Self::Execution {
                kind: PlacementTargetKind::Guest,
                ..
            } => Some(ControllerTargetKind::Guest),
        }
    }

    /// Borrow the exact execution target reference, when present.
    pub fn execution_ref(&self) -> Option<&ResourceRef> {
        match self {
            Self::Zone(_) => None,
            Self::Execution { reference, .. } => Some(reference),
        }
    }
}

impl fmt::Debug for AssignmentTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zone(_) => formatter.write_str("AssignmentTarget::Zone(<redacted>)"),
            Self::Execution { kind, .. } => formatter
                .debug_struct("AssignmentTarget::Execution")
                .field("kind", kind)
                .finish_non_exhaustive(),
        }
    }
}

/// Exact identity of one authenticated controller session.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ControllerSessionBinding {
    session_owner: ResourceRef,
    provider_ref: ResourceRef,
    controller_role: ResourceRef,
    target: AssignmentTarget,
    provider_generation: ResourceGeneration,
    controller_generation: ControllerGeneration,
    session_generation: ReconnectGeneration,
}

impl ControllerSessionBinding {
    /// Construct an exact controller-session binding.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_owner: ResourceRef,
        provider_ref: ResourceRef,
        controller_role: ResourceRef,
        target: AssignmentTarget,
        provider_generation: ResourceGeneration,
        controller_generation: ControllerGeneration,
        session_generation: ReconnectGeneration,
    ) -> Result<Self, AssignmentError> {
        if session_owner.resource_type().as_str() != PROCESS_RESOURCE_TYPE
            || provider_ref.resource_type().as_str() != "Provider"
            || controller_role.resource_type().as_str() != PROCESS_RESOURCE_TYPE
            || provider_generation.get() == 0
            || controller_generation.get() == 0
            || session_generation.get() == 0
            || !assignment_target_reference_matches_kind(&target)
        {
            return Err(AssignmentError::SessionBindingMismatch);
        }
        Ok(Self {
            session_owner,
            provider_ref,
            controller_role,
            target,
            provider_generation,
            controller_generation,
            session_generation,
        })
    }

    /// Borrow the Process resource that owns the authenticated session.
    pub const fn session_owner(&self) -> &ResourceRef {
        &self.session_owner
    }

    /// Borrow the Provider bound to the session.
    pub const fn provider_ref(&self) -> &ResourceRef {
        &self.provider_ref
    }

    /// Borrow the signed controller role.
    pub const fn controller_role(&self) -> &ResourceRef {
        &self.controller_role
    }

    /// Borrow the exact placement target.
    pub const fn target(&self) -> &AssignmentTarget {
        &self.target
    }

    /// Return the Provider generation bound to the session.
    pub const fn provider_generation(&self) -> ResourceGeneration {
        self.provider_generation
    }

    /// Return the Core controller generation bound to the session.
    pub const fn controller_generation(&self) -> ControllerGeneration {
        self.controller_generation
    }

    /// Return the authenticated reconnect generation.
    pub const fn session_generation(&self) -> ReconnectGeneration {
        self.session_generation
    }
}

impl fmt::Debug for ControllerSessionBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControllerSessionBinding")
            .field("session_owner", &"<redacted>")
            .field("provider_ref", &"<redacted>")
            .field("controller_role", &"<redacted>")
            .field("target", &self.target)
            .field("provider_generation", &self.provider_generation)
            .field("controller_generation", &self.controller_generation)
            .field("session_generation", &self.session_generation)
            .finish()
    }
}

fn assignment_target_reference_matches_kind(target: &AssignmentTarget) -> bool {
    match target {
        AssignmentTarget::Zone(_) => true,
        AssignmentTarget::Execution {
            kind: PlacementTargetKind::Host,
            reference,
        } => reference.resource_type().as_str() == "Host",
        AssignmentTarget::Execution {
            kind: PlacementTargetKind::Guest,
            reference,
        } => reference.resource_type().as_str() == "Guest",
    }
}

/// One resource-plane operation a controller lease may perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AssignmentVerb {
    Get,
    List,
    Watch,
    Create,
    UpdateSpec,
    UpdateStatus,
    UpdateMetadata,
    UpdateFinalizers,
    Delete,
    CommitBatch,
}

impl AssignmentVerb {
    /// Whether this operation can mutate durable resource state.
    pub const fn is_mutating(self) -> bool {
        !matches!(self, Self::Get | Self::List | Self::Watch)
    }
}

/// Lifecycle of one resource's controller assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignmentPhase {
    Pending,
    Assigned,
    Draining,
    Revoked,
    Stale,
    Quarantined,
    Released,
}

impl AssignmentPhase {
    const fn code(self) -> u8 {
        match self {
            Self::Pending => 0,
            Self::Assigned => 1,
            Self::Draining => 2,
            Self::Revoked => 3,
            Self::Stale => 4,
            Self::Quarantined => 5,
            Self::Released => 6,
        }
    }

    fn from_code(value: u8) -> Self {
        match value {
            1 => Self::Assigned,
            2 => Self::Draining,
            3 => Self::Revoked,
            4 => Self::Stale,
            5 => Self::Quarantined,
            6 => Self::Released,
            _ => Self::Pending,
        }
    }

    const fn admits_watch(self) -> bool {
        matches!(self, Self::Assigned)
    }

    const fn admits_mutation(self) -> bool {
        matches!(self, Self::Assigned)
    }

    const fn owns_target(self) -> bool {
        matches!(self, Self::Assigned | Self::Draining)
    }
}

/// Closed assignment or lease failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignmentError {
    InvalidRole,
    ProviderGenerationMismatch,
    ControllerGenerationMismatch,
    SessionGenerationInvalid,
    SessionBindingMismatch,
    ResourceTypeUnowned,
    PlacementAnchorMissing,
    PlacementTargetInvalid,
    TargetKindUnsupported,
    TargetNotReady,
    AssignmentConflict,
    AssignmentLimit,
    AssignmentMissing,
    AssignmentNotDraining,
    AssignmentNotReleased,
    ChildrenRemain,
    ChildLimit,
    StaleAssignment,
    SessionRevoked,
    ResourceRevisionMismatch,
    ResourceUidMismatch,
    ResourceNotAssigned,
    TargetMismatch,
    VerbNotAllowed,
    QueryWidened,
    EpochExhausted,
    RoleContractInvalid,
    ProviderRefMismatch,
    ControllerRoleMismatch,
}

/// Failure while decoding the assignment evidence carried by the existing
/// Resource CommitBatch transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignmentTransportError {
    Malformed,
    TooLarge,
}

impl AssignmentTransportError {
    /// Return the stable identity-free reason code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Malformed => "assignment-transport-malformed",
            Self::TooLarge => "assignment-transport-too-large",
        }
    }
}

impl fmt::Display for AssignmentTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for AssignmentTransportError {}

impl AssignmentError {
    /// Return the stable identity-free reason code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidRole => "assignment-role-invalid",
            Self::ProviderGenerationMismatch => "assignment-provider-generation-mismatch",
            Self::ControllerGenerationMismatch => "assignment-controller-generation-mismatch",
            Self::SessionGenerationInvalid => "assignment-session-generation-invalid",
            Self::SessionBindingMismatch => "assignment-session-binding-mismatch",
            Self::ResourceTypeUnowned => "assignment-resource-type-unowned",
            Self::PlacementAnchorMissing => "assignment-placement-anchor-missing",
            Self::PlacementTargetInvalid => "assignment-placement-target-invalid",
            Self::TargetKindUnsupported => "assignment-target-kind-unsupported",
            Self::TargetNotReady => "assignment-target-not-ready",
            Self::AssignmentConflict => "assignment-conflict",
            Self::AssignmentLimit => "assignment-limit",
            Self::AssignmentMissing => "assignment-missing",
            Self::AssignmentNotDraining => "assignment-not-draining",
            Self::AssignmentNotReleased => "assignment-not-released",
            Self::ChildrenRemain => "assignment-children-remain",
            Self::ChildLimit => "assignment-child-limit",
            Self::StaleAssignment => "assignment-stale",
            Self::SessionRevoked => "assignment-session-revoked",
            Self::ResourceRevisionMismatch => "assignment-resource-revision-mismatch",
            Self::ResourceUidMismatch => "assignment-resource-uid-mismatch",
            Self::ResourceNotAssigned => "assignment-resource-not-assigned",
            Self::TargetMismatch => "assignment-target-mismatch",
            Self::VerbNotAllowed => "assignment-verb-not-allowed",
            Self::QueryWidened => "assignment-query-widened",
            Self::EpochExhausted => "assignment-epoch-exhausted",
            Self::RoleContractInvalid => "assignment-role-contract-invalid",
            Self::ProviderRefMismatch => "assignment-provider-ref-mismatch",
            Self::ControllerRoleMismatch => "assignment-controller-role-mismatch",
        }
    }
}

impl fmt::Display for AssignmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for AssignmentError {}

/// An immutable assignment identity carried by every controller admission.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AssignmentIdentity {
    resource_uid: ResourceUid,
    resource_revision: ZoneRevision,
    session: ControllerSessionBinding,
    epoch: AssignmentEpoch,
}

impl AssignmentIdentity {
    /// Construct one identity from authoritative committed values.
    fn new(
        resource_uid: ResourceUid,
        resource_revision: ZoneRevision,
        session: ControllerSessionBinding,
        epoch: AssignmentEpoch,
    ) -> Self {
        Self {
            resource_uid,
            resource_revision,
            session,
            epoch,
        }
    }
}

/// Assignment and mutation evidence forwarded through the existing Resource
/// CommitBatch RPC after bus admission.
#[derive(Clone, PartialEq, Eq)]
pub struct ScopedCommitTransport {
    assignment: AssignmentIdentity,
    mutations: Vec<ScopedResourceMutation>,
}

impl ScopedCommitTransport {
    /// Construct transport evidence from one admitted assignment call.
    pub fn new(
        assignment: AssignmentIdentity,
        mutations: Vec<ScopedResourceMutation>,
    ) -> Result<Self, AssignmentTransportError> {
        if mutations.is_empty()
            || mutations.len() > 128
            || mutations.iter().any(|mutation| {
                mutation.assignment() != &assignment || !transport_mutation_is_valid(mutation)
            })
        {
            return Err(AssignmentTransportError::Malformed);
        }
        Ok(Self {
            assignment,
            mutations,
        })
    }

    /// Borrow the admitted assignment.
    pub const fn assignment(&self) -> &AssignmentIdentity {
        &self.assignment
    }

    /// Borrow the admitted mutations.
    pub fn mutations(&self) -> &[ScopedResourceMutation] {
        &self.mutations
    }

    /// Encode the evidence as bounded canonical JSON bytes.
    pub fn encode(&self) -> Result<Vec<u8>, AssignmentTransportError> {
        let value = json!({
            "version": 1,
            "assignment": encode_assignment(&self.assignment),
            "mutations": self
                .mutations
                .iter()
                .map(encode_mutation)
                .collect::<Vec<_>>(),
        });
        encode_bounded_json(&value, MAX_SCOPED_COMMIT_TRANSPORT_BYTES)
    }

    /// Decode bounded evidence produced by [`Self::encode`].
    pub fn decode(bytes: &[u8]) -> Result<Self, AssignmentTransportError> {
        if bytes.is_empty() || bytes.len() > MAX_SCOPED_COMMIT_TRANSPORT_BYTES {
            return Err(AssignmentTransportError::TooLarge);
        }
        CanonicalJsonValue::parse(bytes).map_err(|_| AssignmentTransportError::Malformed)?;
        let value = serde_json::from_slice::<Value>(bytes)
            .map_err(|_| AssignmentTransportError::Malformed)?;
        let object = value
            .as_object()
            .ok_or(AssignmentTransportError::Malformed)?;
        require_exact_keys(object, &["version", "assignment", "mutations"])?;
        if object.get("version").and_then(Value::as_u64) != Some(1) {
            return Err(AssignmentTransportError::Malformed);
        }
        let assignment = decode_assignment(
            object
                .get("assignment")
                .ok_or(AssignmentTransportError::Malformed)?,
        )?;
        let mutation_values = object
            .get("mutations")
            .and_then(Value::as_array)
            .ok_or(AssignmentTransportError::Malformed)?;
        if mutation_values.is_empty() || mutation_values.len() > 128 {
            return Err(AssignmentTransportError::Malformed);
        }
        let mutations = mutation_values
            .iter()
            .map(|value| {
                let object = value
                    .as_object()
                    .ok_or(AssignmentTransportError::Malformed)?;
                let scope = match object.get("scope") {
                    None => ScopedResourceScope::Primary,
                    Some(scope) => decode_scoped_resource_scope(scope)?,
                };
                if matches!(scope, ScopedResourceScope::Primary) {
                    require_exact_keys(object, &["target", "verb"])?;
                } else {
                    require_exact_keys(object, &["target", "verb", "scope"])?;
                }
                let target = ResourceRef::parse(
                    object
                        .get("target")
                        .and_then(Value::as_str)
                        .ok_or(AssignmentTransportError::Malformed)?,
                )
                .map_err(|_| AssignmentTransportError::Malformed)?;
                let verb = decode_assignment_verb(
                    object
                        .get("verb")
                        .and_then(Value::as_str)
                        .ok_or(AssignmentTransportError::Malformed)?,
                )?;
                Ok(ScopedResourceMutation {
                    assignment: assignment.clone(),
                    target,
                    verb,
                    scope,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(assignment, mutations)
    }
}

fn transport_mutation_is_valid(mutation: &ScopedResourceMutation) -> bool {
    match mutation.scope() {
        ScopedResourceScope::Primary => matches!(
            mutation.verb(),
            AssignmentVerb::Create
                | AssignmentVerb::UpdateStatus
                | AssignmentVerb::UpdateFinalizers
        ),
        ScopedResourceScope::OwnerChild(scope) => {
            scope.owner_uid() == mutation.assignment().resource_uid()
                && scope.owner_revision() == mutation.assignment().resource_revision()
                && mutation.target().resource_type().as_str() == PROCESS_RESOURCE_TYPE
                && matches!(
                    mutation.verb(),
                    AssignmentVerb::Create | AssignmentVerb::UpdateSpec | AssignmentVerb::Delete
                )
        }
    }
}

fn owner_child_process_verbs() -> BTreeSet<AssignmentVerb> {
    BTreeSet::from([
        AssignmentVerb::Create,
        AssignmentVerb::UpdateSpec,
        AssignmentVerb::Delete,
    ])
}

impl fmt::Debug for ScopedCommitTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScopedCommitTransport")
            .field("mutation_count", &self.mutations.len())
            .finish()
    }
}

fn encode_assignment(identity: &AssignmentIdentity) -> Value {
    let target = match identity.target() {
        AssignmentTarget::Zone(zone) => json!({
            "kind": "zone",
            "zone": zone.as_str(),
        }),
        AssignmentTarget::Execution { kind, reference } => json!({
            "kind": "execution",
            "targetKind": match kind {
                PlacementTargetKind::Host => "host",
                PlacementTargetKind::Guest => "guest",
            },
            "reference": reference.to_canonical_string(),
        }),
    };
    json!({
        "resourceUid": identity.resource_uid().as_str(),
        "resourceRevision": identity.resource_revision().get(),
        "providerRef": identity.session_binding().provider_ref().to_canonical_string(),
        "providerGeneration": identity.provider_generation().get(),
        "controllerGeneration": identity.controller_generation().get(),
        "controllerRole": identity.controller_role().to_canonical_string(),
        "target": target,
        "sessionOwner": identity.session_owner().to_canonical_string(),
        "sessionGeneration": identity.session_generation().get(),
        "epoch": identity.epoch().get(),
    })
}

fn encode_mutation(mutation: &ScopedResourceMutation) -> Value {
    let mut value = json!({
        "target": mutation.target().to_canonical_string(),
        "verb": encode_assignment_verb(mutation.verb()),
    })
    .as_object()
    .cloned()
    .expect("scoped mutation encoding is an object");
    if let ScopedResourceScope::OwnerChild(scope) = mutation.scope() {
        value.insert("scope".to_owned(), encode_owner_child_scope(scope));
    }
    Value::Object(value)
}

fn encode_owner_child_scope(scope: &OwnerChildScope) -> Value {
    json!({
        "kind": "owner-child",
        "ownerRef": scope.owner_ref().to_canonical_string(),
        "ownerUid": scope.owner_uid().as_str(),
        "ownerRevision": scope.owner_revision().get(),
        "ownerGeneration": scope.owner_generation().get(),
    })
}

fn decode_scoped_resource_scope(
    value: &Value,
) -> Result<ScopedResourceScope, AssignmentTransportError> {
    let object = value
        .as_object()
        .ok_or(AssignmentTransportError::Malformed)?;
    require_exact_keys(
        object,
        &[
            "kind",
            "ownerRef",
            "ownerUid",
            "ownerRevision",
            "ownerGeneration",
        ],
    )?;
    if object.get("kind").and_then(Value::as_str) != Some("owner-child") {
        return Err(AssignmentTransportError::Malformed);
    }
    let owner_ref = ResourceRef::parse(
        object
            .get("ownerRef")
            .and_then(Value::as_str)
            .ok_or(AssignmentTransportError::Malformed)?,
    )
    .map_err(|_| AssignmentTransportError::Malformed)?;
    let owner_uid = ResourceUid::parse(
        object
            .get("ownerUid")
            .and_then(Value::as_str)
            .ok_or(AssignmentTransportError::Malformed)?,
    )
    .map_err(|_| AssignmentTransportError::Malformed)?;
    let owner_revision = ZoneRevision::new(
        object
            .get("ownerRevision")
            .and_then(Value::as_u64)
            .filter(|revision| *revision != 0)
            .ok_or(AssignmentTransportError::Malformed)?,
    );
    let owner_generation = ResourceGeneration::new(
        object
            .get("ownerGeneration")
            .and_then(Value::as_u64)
            .ok_or(AssignmentTransportError::Malformed)?,
    )
    .map_err(|_| AssignmentTransportError::Malformed)?;
    Ok(ScopedResourceScope::OwnerChild(OwnerChildScope {
        owner_ref,
        owner_uid,
        owner_revision,
        owner_generation,
    }))
}

fn encode_assignment_verb(verb: AssignmentVerb) -> &'static str {
    match verb {
        AssignmentVerb::Get => "Get",
        AssignmentVerb::List => "List",
        AssignmentVerb::Watch => "Watch",
        AssignmentVerb::Create => "Create",
        AssignmentVerb::UpdateSpec => "UpdateSpec",
        AssignmentVerb::UpdateStatus => "UpdateStatus",
        AssignmentVerb::UpdateMetadata => "UpdateMetadata",
        AssignmentVerb::UpdateFinalizers => "UpdateFinalizers",
        AssignmentVerb::Delete => "Delete",
        AssignmentVerb::CommitBatch => "CommitBatch",
    }
}

fn decode_assignment_verb(value: &str) -> Result<AssignmentVerb, AssignmentTransportError> {
    match value {
        "Get" => Ok(AssignmentVerb::Get),
        "List" => Ok(AssignmentVerb::List),
        "Watch" => Ok(AssignmentVerb::Watch),
        "Create" => Ok(AssignmentVerb::Create),
        "UpdateSpec" => Ok(AssignmentVerb::UpdateSpec),
        "UpdateStatus" => Ok(AssignmentVerb::UpdateStatus),
        "UpdateMetadata" => Ok(AssignmentVerb::UpdateMetadata),
        "UpdateFinalizers" => Ok(AssignmentVerb::UpdateFinalizers),
        "Delete" => Ok(AssignmentVerb::Delete),
        "CommitBatch" => Ok(AssignmentVerb::CommitBatch),
        _ => Err(AssignmentTransportError::Malformed),
    }
}

fn decode_assignment(value: &Value) -> Result<AssignmentIdentity, AssignmentTransportError> {
    let object = value
        .as_object()
        .ok_or(AssignmentTransportError::Malformed)?;
    require_exact_keys(
        object,
        &[
            "resourceUid",
            "resourceRevision",
            "providerRef",
            "providerGeneration",
            "controllerGeneration",
            "controllerRole",
            "target",
            "sessionOwner",
            "sessionGeneration",
            "epoch",
        ],
    )?;
    let provider_ref = ResourceRef::parse(
        object
            .get("providerRef")
            .and_then(Value::as_str)
            .ok_or(AssignmentTransportError::Malformed)?,
    )
    .map_err(|_| AssignmentTransportError::Malformed)?;
    let target = decode_assignment_target(
        object
            .get("target")
            .ok_or(AssignmentTransportError::Malformed)?,
    )?;
    let provider_generation = ResourceGeneration::new(
        object
            .get("providerGeneration")
            .and_then(Value::as_u64)
            .ok_or(AssignmentTransportError::Malformed)?,
    )
    .map_err(|_| AssignmentTransportError::Malformed)?;
    let controller_generation = ControllerGeneration::new(
        object
            .get("controllerGeneration")
            .and_then(Value::as_u64)
            .ok_or(AssignmentTransportError::Malformed)?,
    )
    .map_err(|_| AssignmentTransportError::Malformed)?;
    let controller_role = ResourceRef::parse(
        object
            .get("controllerRole")
            .and_then(Value::as_str)
            .ok_or(AssignmentTransportError::Malformed)?,
    )
    .map_err(|_| AssignmentTransportError::Malformed)?;
    let session_owner = ResourceRef::parse(
        object
            .get("sessionOwner")
            .and_then(Value::as_str)
            .ok_or(AssignmentTransportError::Malformed)?,
    )
    .map_err(|_| AssignmentTransportError::Malformed)?;
    let session_generation = ReconnectGeneration::new(
        object
            .get("sessionGeneration")
            .and_then(Value::as_u64)
            .ok_or(AssignmentTransportError::Malformed)?,
    )
    .map_err(|_| AssignmentTransportError::Malformed)?;
    let session = ControllerSessionBinding::new(
        session_owner,
        provider_ref,
        controller_role,
        target,
        provider_generation,
        controller_generation,
        session_generation,
    )
    .map_err(|_| AssignmentTransportError::Malformed)?;
    Ok(AssignmentIdentity::new(
        ResourceUid::parse(
            object
                .get("resourceUid")
                .and_then(Value::as_str)
                .ok_or(AssignmentTransportError::Malformed)?,
        )
        .map_err(|_| AssignmentTransportError::Malformed)?,
        ZoneRevision::new(
            object
                .get("resourceRevision")
                .and_then(Value::as_u64)
                .ok_or(AssignmentTransportError::Malformed)?,
        ),
        session,
        AssignmentEpoch::new(
            object
                .get("epoch")
                .and_then(Value::as_u64)
                .ok_or(AssignmentTransportError::Malformed)?,
        )
        .map_err(|_| AssignmentTransportError::Malformed)?,
    ))
}

fn decode_assignment_target(value: &Value) -> Result<AssignmentTarget, AssignmentTransportError> {
    let object = value
        .as_object()
        .ok_or(AssignmentTransportError::Malformed)?;
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .ok_or(AssignmentTransportError::Malformed)?;
    match kind {
        "zone" => {
            require_exact_keys(object, &["kind", "zone"])?;
            Ok(AssignmentTarget::Zone(
                ZoneId::parse(
                    object
                        .get("zone")
                        .and_then(Value::as_str)
                        .ok_or(AssignmentTransportError::Malformed)?,
                )
                .map_err(|_| AssignmentTransportError::Malformed)?,
            ))
        }
        "execution" => {
            require_exact_keys(object, &["kind", "targetKind", "reference"])?;
            let reference = ResourceRef::parse(
                object
                    .get("reference")
                    .and_then(Value::as_str)
                    .ok_or(AssignmentTransportError::Malformed)?,
            )
            .map_err(|_| AssignmentTransportError::Malformed)?;
            let target_kind = match object
                .get("targetKind")
                .and_then(Value::as_str)
                .ok_or(AssignmentTransportError::Malformed)?
            {
                "host" => PlacementTargetKind::Host,
                "guest" => PlacementTargetKind::Guest,
                _ => return Err(AssignmentTransportError::Malformed),
            };
            if (target_kind == PlacementTargetKind::Host
                && reference.resource_type().as_str() != "Host")
                || (target_kind == PlacementTargetKind::Guest
                    && reference.resource_type().as_str() != "Guest")
            {
                return Err(AssignmentTransportError::Malformed);
            }
            Ok(AssignmentTarget::Execution {
                kind: target_kind,
                reference,
            })
        }
        _ => Err(AssignmentTransportError::Malformed),
    }
}

fn require_exact_keys(
    object: &Map<String, Value>,
    expected: &[&str],
) -> Result<(), AssignmentTransportError> {
    if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
        return Err(AssignmentTransportError::Malformed);
    }
    Ok(())
}

fn encode_bounded_json(
    value: &Value,
    max_bytes: usize,
) -> Result<Vec<u8>, AssignmentTransportError> {
    let bytes = serde_json::to_vec(value).map_err(|_| AssignmentTransportError::Malformed)?;
    let bytes = CanonicalJsonValue::parse(&bytes)
        .map_err(|_| AssignmentTransportError::Malformed)?
        .to_canonical_bytes();
    if bytes.len() > max_bytes {
        return Err(AssignmentTransportError::TooLarge);
    }
    Ok(bytes)
}

impl AssignmentIdentity {
    /// Borrow the assigned resource UID.
    pub const fn resource_uid(&self) -> &ResourceUid {
        &self.resource_uid
    }

    /// Return the committed resource revision bound by this identity.
    pub const fn resource_revision(&self) -> ZoneRevision {
        self.resource_revision
    }

    /// Return the Provider generation bound by this identity.
    pub const fn provider_generation(&self) -> ResourceGeneration {
        self.session.provider_generation()
    }

    /// Return the Core controller generation bound by this identity.
    pub const fn controller_generation(&self) -> ControllerGeneration {
        self.session.controller_generation()
    }

    /// Borrow the signed controller role.
    pub const fn controller_role(&self) -> &ResourceRef {
        self.session.controller_role()
    }

    /// Borrow the exact assigned target.
    pub const fn target(&self) -> &AssignmentTarget {
        self.session.target()
    }

    /// Borrow the Process resource that owns the authenticated session.
    pub const fn session_owner(&self) -> &ResourceRef {
        self.session.session_owner()
    }

    /// Borrow the exact controller-session binding.
    pub const fn session_binding(&self) -> &ControllerSessionBinding {
        &self.session
    }

    /// Return the authenticated ComponentSession generation.
    pub const fn session_generation(&self) -> ReconnectGeneration {
        self.session.session_generation()
    }

    /// Return the assignment epoch.
    pub const fn epoch(&self) -> AssignmentEpoch {
        self.epoch
    }
}

impl fmt::Debug for AssignmentIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AssignmentIdentity")
            .field("resource_uid", &"<redacted>")
            .field("resource_revision", &self.resource_revision)
            .field("session", &self.session)
            .field("epoch", &self.epoch)
            .finish()
    }
}

/// The signed role and placement contract used for assignment admission.
#[derive(Clone, PartialEq, Eq)]
pub struct ControllerRoleContract {
    provider_ref: ResourceRef,
    role_ref: ResourceRef,
    scope: ControllerInstanceScope,
    supported_target_kinds: BTreeSet<ControllerTargetKind>,
    resource_types: BTreeSet<ResourceTypeName>,
    placements: BTreeMap<ResourceTypeName, PlacementAnchor>,
}

impl ControllerRoleContract {
    /// Derive one role contract from a trusted signed Provider manifest.
    pub fn from_signed_manifest(
        provider_ref: ResourceRef,
        role_ref: ResourceRef,
        manifest: &ProviderManifest,
    ) -> Result<Self, AssignmentError> {
        if provider_ref.resource_type().as_str() != "Provider"
            || role_ref.resource_type().as_str() != PROCESS_RESOURCE_TYPE
            || manifest.validate_installation_contract().is_err()
        {
            return Err(AssignmentError::InvalidRole);
        }
        let component = manifest
            .components()
            .iter()
            .find(|component| {
                component.component_type() == ComponentType::Controller
                    && component.component_id().as_str() == role_ref.name().as_str()
            })
            .ok_or(AssignmentError::InvalidRole)?;
        let scope = component
            .instance_scope()
            .ok_or(AssignmentError::RoleContractInvalid)?;
        let mut placements = BTreeMap::new();
        for resource_type in component.exported_resource_types() {
            let binding = manifest
                .binding_for(resource_type)
                .ok_or(AssignmentError::PlacementAnchorMissing)?;
            let anchor = *binding
                .placement_anchor()
                .ok_or(AssignmentError::PlacementAnchorMissing)?;
            placements.insert(resource_type.clone(), anchor);
        }
        Ok(Self {
            provider_ref,
            role_ref,
            scope,
            supported_target_kinds: component.supported_target_kinds().clone(),
            resource_types: component.exported_resource_types().clone(),
            placements,
        })
    }

    /// Borrow the Provider resource selected by this signed role.
    pub const fn provider_ref(&self) -> &ResourceRef {
        &self.provider_ref
    }

    /// Borrow the controller role reference.
    pub const fn role_ref(&self) -> &ResourceRef {
        &self.role_ref
    }

    /// Return the closed instance scope.
    pub const fn scope(&self) -> ControllerInstanceScope {
        self.scope
    }

    /// Borrow the exclusively owned ResourceTypes.
    pub const fn resource_types(&self) -> &BTreeSet<ResourceTypeName> {
        &self.resource_types
    }

    fn placement_for(&self, resource_type: &ResourceTypeName) -> Option<PlacementAnchor> {
        self.placements.get(resource_type).copied()
    }

    fn supports_target(&self, target: &AssignmentTarget) -> bool {
        target
            .target_kind()
            .is_some_and(|kind| self.supported_target_kinds.contains(&kind))
    }
}

impl fmt::Debug for ControllerRoleContract {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControllerRoleContract")
            .field("scope", &self.scope)
            .field("resource_type_count", &self.resource_types.len())
            .field("target_kind_count", &self.supported_target_kinds.len())
            .finish()
    }
}

/// Trusted inputs for one assignment admission.
pub struct AssignmentRequest<'a> {
    resource: &'a ResourceEnvelope,
    role: &'a ControllerRoleContract,
    provider_generation: ResourceGeneration,
    controller_generation: ControllerGeneration,
    session_generation: ReconnectGeneration,
    target_ready: bool,
    expected_target: Option<AssignmentTarget>,
    session_owner: ResourceRef,
}

impl<'a> AssignmentRequest<'a> {
    /// Bind a committed resource to a signed role and authenticated session.
    pub fn new(
        resource: &'a ResourceEnvelope,
        role: &'a ControllerRoleContract,
        provider_generation: ResourceGeneration,
        controller_generation: ControllerGeneration,
        session_generation: ReconnectGeneration,
        target_ready: bool,
    ) -> Self {
        Self {
            resource,
            role,
            provider_generation,
            controller_generation,
            session_generation,
            target_ready,
            expected_target: None,
            session_owner: role.role_ref().clone(),
        }
    }

    /// Require the resolved placement to match the authenticated controller
    /// Process target exactly.
    pub fn with_expected_target(mut self, target: AssignmentTarget) -> Self {
        self.expected_target = Some(target);
        self
    }

    /// Bind the request to the Process resource that owns the session.
    pub fn with_session_owner(mut self, session_owner: ResourceRef) -> Self {
        self.session_owner = session_owner;
        self
    }

    /// Return the authenticated session generation requested for admission.
    pub const fn session_generation(&self) -> ReconnectGeneration {
        self.session_generation
    }

    /// Borrow the Process resource that owns the requested session.
    pub const fn session_owner(&self) -> &ResourceRef {
        &self.session_owner
    }

    /// Borrow the explicitly resolved target, when one was supplied.
    pub const fn expected_target(&self) -> Option<&AssignmentTarget> {
        self.expected_target.as_ref()
    }

    /// Build the exact session binding requested by this admission.
    pub fn session_binding(&self) -> Result<ControllerSessionBinding, AssignmentError> {
        ControllerSessionBinding::new(
            self.session_owner.clone(),
            self.role.provider_ref.clone(),
            self.role.role_ref.clone(),
            self.expected_target
                .clone()
                .ok_or(AssignmentError::SessionBindingMismatch)?,
            self.provider_generation,
            self.controller_generation,
            self.session_generation,
        )
    }
}

/// The exact owner identity bound to an owner-child admission.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnerChildScope {
    owner_ref: ResourceRef,
    owner_uid: ResourceUid,
    owner_revision: ZoneRevision,
    owner_generation: ResourceGeneration,
}

impl OwnerChildScope {
    /// Borrow the exact owner reference.
    pub const fn owner_ref(&self) -> &ResourceRef {
        &self.owner_ref
    }

    /// Borrow the immutable owner UID.
    pub const fn owner_uid(&self) -> &ResourceUid {
        &self.owner_uid
    }

    /// Return the owner revision captured at assignment time.
    pub const fn owner_revision(&self) -> ZoneRevision {
        self.owner_revision
    }

    /// Return the owner generation captured at assignment time.
    pub const fn owner_generation(&self) -> ResourceGeneration {
        self.owner_generation
    }
}

impl fmt::Debug for OwnerChildScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnerChildScope")
            .field("owner_ref", &"<redacted>")
            .field("owner_uid", &"<redacted>")
            .field("owner_revision", &self.owner_revision)
            .field("owner_generation", &self.owner_generation)
            .finish()
    }
}

/// The non-widenable scope of an assignment-scoped query or mutation.
#[derive(Clone, PartialEq, Eq)]
pub enum ScopedResourceScope {
    /// The assigned resource itself.
    Primary,
    /// A child resource owned by the exact assigned resource identity.
    OwnerChild(OwnerChildScope),
}

impl ScopedResourceScope {
    /// Borrow the owner-child scope when this is a child admission.
    pub const fn owner_child(&self) -> Option<&OwnerChildScope> {
        match self {
            Self::Primary => None,
            Self::OwnerChild(scope) => Some(scope),
        }
    }
}

impl fmt::Debug for ScopedResourceScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Primary => formatter.write_str("ScopedResourceScope::Primary"),
            Self::OwnerChild(scope) => formatter
                .debug_tuple("ScopedResourceScope::OwnerChild")
                .field(scope)
                .finish(),
        }
    }
}

/// A controller's non-widenable query scope.
#[derive(Clone, PartialEq, Eq)]
pub struct ScopedResourceQuery {
    assignment: AssignmentIdentity,
    resource_types: Vec<ResourceTypeName>,
    resource_names: Vec<ResourceName>,
    filters: Vec<ScopedResourceFilter>,
    scope: ScopedResourceScope,
}

impl ScopedResourceQuery {
    /// Borrow the immutable assignment evidence.
    pub const fn assignment(&self) -> &AssignmentIdentity {
        &self.assignment
    }

    /// Borrow the exact ResourceType selector.
    pub fn resource_types(&self) -> &[ResourceTypeName] {
        &self.resource_types
    }

    /// Borrow the exact resource-name selector.
    pub fn resource_names(&self) -> &[ResourceName] {
        &self.resource_names
    }

    /// Borrow the assignment-bound filters.
    pub fn filters(&self) -> &[ScopedResourceFilter] {
        &self.filters
    }

    /// Borrow the exact scope minted by the assignment lease.
    pub const fn scope(&self) -> &ScopedResourceScope {
        &self.scope
    }

    /// Borrow the owner-child scope when this is an owner-child query.
    pub const fn owner_child_scope(&self) -> Option<&OwnerChildScope> {
        self.scope.owner_child()
    }

    /// Consume the query while retaining its exact scope.
    pub fn into_parts_with_scope(
        self,
    ) -> (
        AssignmentIdentity,
        Vec<ResourceTypeName>,
        Vec<ResourceName>,
        Vec<ScopedResourceFilter>,
        ScopedResourceScope,
    ) {
        (
            self.assignment,
            self.resource_types,
            self.resource_names,
            self.filters,
            self.scope,
        )
    }
}

impl fmt::Debug for ScopedResourceQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScopedResourceQuery")
            .field("resource_type_count", &self.resource_types.len())
            .field("resource_name_count", &self.resource_names.len())
            .field("filter_count", &self.filters.len())
            .finish()
    }
}

/// One exact filter minted by a controller assignment.
#[derive(Clone, PartialEq, Eq)]
pub struct ScopedResourceFilter {
    field: String,
    values: Vec<String>,
    assignment_bound: bool,
}

impl ScopedResourceFilter {
    /// Construct a caller-supplied narrowing filter. It cannot name the
    /// assignment field; Core appends that filter itself.
    pub fn narrow(field: impl Into<String>, values: Vec<String>) -> Result<Self, AssignmentError> {
        let field = field.into();
        if field.is_empty()
            || field.len() > 64
            || !field
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
            || values.is_empty()
            || values.len() > 64
            || values.iter().any(|value| {
                value.is_empty()
                    || value.len() > 128
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_graphic() || byte == b' ')
            })
            || matches!(field.as_str(), ASSIGNMENT_UID_FILTER | OWNER_UID_FILTER)
        {
            return Err(AssignmentError::QueryWidened);
        }
        Ok(Self {
            field,
            values,
            assignment_bound: false,
        })
    }

    /// Borrow the indexed field.
    pub fn field(&self) -> &str {
        &self.field
    }

    /// Borrow the accepted values.
    pub fn values(&self) -> &[String] {
        &self.values
    }

    /// Whether this filter was minted by the assignment authority.
    pub const fn assignment_bound(&self) -> bool {
        self.assignment_bound
    }
}

impl fmt::Debug for ScopedResourceFilter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScopedResourceFilter")
            .field("field", &self.field)
            .field("value_count", &self.values.len())
            .field("assignment_bound", &self.assignment_bound)
            .finish()
    }
}

/// A single-resource mutation admitted by a controller lease.
#[derive(Clone, PartialEq, Eq)]
pub struct ScopedResourceMutation {
    assignment: AssignmentIdentity,
    target: ResourceRef,
    verb: AssignmentVerb,
    scope: ScopedResourceScope,
}

impl ScopedResourceMutation {
    /// Borrow the assignment evidence.
    pub const fn assignment(&self) -> &AssignmentIdentity {
        &self.assignment
    }

    /// Borrow the exact target.
    pub const fn target(&self) -> &ResourceRef {
        &self.target
    }

    /// Return the admitted verb.
    pub const fn verb(&self) -> AssignmentVerb {
        self.verb
    }

    /// Borrow the exact scope minted by the assignment lease.
    pub const fn scope(&self) -> &ScopedResourceScope {
        &self.scope
    }
}

impl fmt::Debug for ScopedResourceMutation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScopedResourceMutation")
            .field("target", &"<redacted>")
            .field("verb", &self.verb)
            .field("scope", &self.scope)
            .finish()
    }
}

/// The exact query and mutation scope carried by an assignment grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AssignmentScope {
    /// The assigned primary resource.
    Primary,
    /// Process children owned by the assigned resource.
    OwnerChildProcess,
}

fn encode_assignment_scope(scope: AssignmentScope) -> &'static str {
    match scope {
        AssignmentScope::Primary => "primary",
        AssignmentScope::OwnerChildProcess => "owner-child-process",
    }
}

fn decode_assignment_scope(value: &str) -> Result<AssignmentScope, AssignmentTransportError> {
    match value {
        "primary" => Ok(AssignmentScope::Primary),
        "owner-child-process" => Ok(AssignmentScope::OwnerChildProcess),
        _ => Err(AssignmentTransportError::Malformed),
    }
}

/// Expected identity and exact authority shape for one controller session.
#[derive(Clone, PartialEq, Eq)]
pub struct ControllerAssignmentExpectation {
    session_owner: Option<ResourceRef>,
    provider_ref: ResourceRef,
    controller_role: ResourceRef,
    target: Option<AssignmentTarget>,
    target_kind: Option<ControllerTargetKind>,
    provider_generation: Option<ResourceGeneration>,
    controller_generation: Option<ControllerGeneration>,
    session_generation: ReconnectGeneration,
    resource_types: BTreeSet<ResourceTypeName>,
    primary_verbs: BTreeSet<AssignmentVerb>,
    owner_child_process_verbs: BTreeSet<AssignmentVerb>,
    scopes: BTreeSet<AssignmentScope>,
}

impl ControllerAssignmentExpectation {
    /// Construct one exact controller-session grant expectation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider_ref: ResourceRef,
        controller_role: ResourceRef,
        target: AssignmentTarget,
        provider_generation: ResourceGeneration,
        controller_generation: ControllerGeneration,
        session_generation: ReconnectGeneration,
        resource_types: BTreeSet<ResourceTypeName>,
        primary_verbs: BTreeSet<AssignmentVerb>,
        owner_child_process_verbs: BTreeSet<AssignmentVerb>,
        scopes: BTreeSet<AssignmentScope>,
    ) -> Result<Self, AssignmentError> {
        Self::new_inner(
            provider_ref,
            controller_role,
            Some(target),
            None,
            Some(provider_generation),
            Some(controller_generation),
            session_generation,
            resource_types,
            primary_verbs,
            owner_child_process_verbs,
            scopes,
        )
    }

    /// Construct an expectation that validates the session and role
    /// generations while leaving exact target selection to Core.
    #[allow(clippy::too_many_arguments)]
    pub fn new_without_target(
        provider_ref: ResourceRef,
        controller_role: ResourceRef,
        provider_generation: ResourceGeneration,
        controller_generation: ControllerGeneration,
        session_generation: ReconnectGeneration,
        resource_types: BTreeSet<ResourceTypeName>,
        primary_verbs: BTreeSet<AssignmentVerb>,
        owner_child_process_verbs: BTreeSet<AssignmentVerb>,
        scopes: BTreeSet<AssignmentScope>,
    ) -> Result<Self, AssignmentError> {
        Self::new_inner(
            provider_ref,
            controller_role,
            None,
            None,
            Some(provider_generation),
            Some(controller_generation),
            session_generation,
            resource_types,
            primary_verbs,
            owner_child_process_verbs,
            scopes,
        )
    }

    /// Construct an expectation for a controller that learns Provider and
    /// controller generations from Core's exact grants.
    pub fn new_for_session(
        provider_ref: ResourceRef,
        controller_role: ResourceRef,
        session_generation: ReconnectGeneration,
        resource_types: BTreeSet<ResourceTypeName>,
        primary_verbs: BTreeSet<AssignmentVerb>,
        owner_child_process_verbs: BTreeSet<AssignmentVerb>,
        scopes: BTreeSet<AssignmentScope>,
    ) -> Result<Self, AssignmentError> {
        Self::new_inner(
            provider_ref,
            controller_role,
            None,
            None,
            None,
            None,
            session_generation,
            resource_types,
            primary_verbs,
            owner_child_process_verbs,
            scopes,
        )
    }

    /// Construct an expectation that validates one target kind while Core
    /// supplies the exact target reference in each grant.
    pub fn new_for_session_with_target_kind(
        provider_ref: ResourceRef,
        controller_role: ResourceRef,
        target_kind: ControllerTargetKind,
        session_generation: ReconnectGeneration,
        resource_types: BTreeSet<ResourceTypeName>,
        primary_verbs: BTreeSet<AssignmentVerb>,
        owner_child_process_verbs: BTreeSet<AssignmentVerb>,
        scopes: BTreeSet<AssignmentScope>,
    ) -> Result<Self, AssignmentError> {
        Self::new_inner(
            provider_ref,
            controller_role,
            None,
            Some(target_kind),
            None,
            None,
            session_generation,
            resource_types,
            primary_verbs,
            owner_child_process_verbs,
            scopes,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_inner(
        provider_ref: ResourceRef,
        controller_role: ResourceRef,
        target: Option<AssignmentTarget>,
        target_kind: Option<ControllerTargetKind>,
        provider_generation: Option<ResourceGeneration>,
        controller_generation: Option<ControllerGeneration>,
        session_generation: ReconnectGeneration,
        resource_types: BTreeSet<ResourceTypeName>,
        primary_verbs: BTreeSet<AssignmentVerb>,
        owner_child_process_verbs: BTreeSet<AssignmentVerb>,
        scopes: BTreeSet<AssignmentScope>,
    ) -> Result<Self, AssignmentError> {
        if provider_ref.resource_type().as_str() != "Provider"
            || controller_role.resource_type().as_str() != PROCESS_RESOURCE_TYPE
            || provider_generation.is_some_and(|generation| generation.get() == 0)
            || controller_generation.is_some_and(|generation| generation.get() == 0)
            || session_generation.get() == 0
            || resource_types.is_empty()
            || resource_types.len() > MAX_ASSIGNMENT_GRANT_RESOURCE_TYPES
            || primary_verbs.is_empty()
            || primary_verbs.len() > MAX_ASSIGNMENT_GRANT_VERBS
            || owner_child_process_verbs.len() > MAX_ASSIGNMENT_GRANT_VERBS
            || scopes.is_empty()
            || scopes.len() > MAX_ASSIGNMENT_GRANT_SCOPES
            || !scopes.contains(&AssignmentScope::Primary)
            || (scopes.contains(&AssignmentScope::OwnerChildProcess)
                != !owner_child_process_verbs.is_empty())
            || owner_child_process_verbs.iter().any(|verb| {
                !matches!(
                    verb,
                    AssignmentVerb::Create | AssignmentVerb::UpdateSpec | AssignmentVerb::Delete
                )
            })
        {
            return Err(AssignmentError::RoleContractInvalid);
        }
        Ok(Self {
            session_owner: None,
            provider_ref,
            controller_role,
            target,
            target_kind,
            provider_generation,
            controller_generation,
            session_generation,
            resource_types,
            primary_verbs,
            owner_child_process_verbs,
            scopes,
        })
    }

    /// Bind the expectation to the exact Process session owner.
    pub fn with_session_owner(
        mut self,
        session_owner: ResourceRef,
    ) -> Result<Self, AssignmentError> {
        if session_owner.resource_type().as_str() != PROCESS_RESOURCE_TYPE {
            return Err(AssignmentError::SessionBindingMismatch);
        }
        self.session_owner = Some(session_owner);
        Ok(self)
    }

    /// Borrow the exact Process session owner.
    pub const fn session_owner(&self) -> Option<&ResourceRef> {
        self.session_owner.as_ref()
    }

    /// Borrow the exact primary-scope verbs.
    pub const fn primary_verbs(&self) -> &BTreeSet<AssignmentVerb> {
        &self.primary_verbs
    }

    /// Borrow the exact owner-child-process verbs.
    pub const fn owner_child_process_verbs(&self) -> &BTreeSet<AssignmentVerb> {
        &self.owner_child_process_verbs
    }
}

impl fmt::Debug for ControllerAssignmentExpectation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControllerAssignmentExpectation")
            .field("resource_type_count", &self.resource_types.len())
            .field("primary_verb_count", &self.primary_verbs.len())
            .field(
                "owner_child_process_verb_count",
                &self.owner_child_process_verbs.len(),
            )
            .field("scope_count", &self.scopes.len())
            .finish()
    }
}

/// A bounded, identity-complete assignment delivered to one controller.
///
/// This is transport data, not a Core admission capability. The controller
/// may retain the value for its current session, but it cannot use it after
/// the exact controller-session binding is revoked.
#[derive(Clone, PartialEq, Eq)]
pub struct ControllerAssignmentGrant {
    provider_ref: ResourceRef,
    assignment: AssignmentIdentity,
    resource_ref: ResourceRef,
    resource_generation: ResourceGeneration,
    resource_types: BTreeSet<ResourceTypeName>,
    primary_verbs: BTreeSet<AssignmentVerb>,
    owner_child_process_verbs: BTreeSet<AssignmentVerb>,
    scopes: BTreeSet<AssignmentScope>,
}

impl ControllerAssignmentGrant {
    /// Build a grant from one admitted Core ResourceClient lease.
    pub fn from_lease(lease: &ResourceClientLease) -> Self {
        let owner_child_process_verbs = lease.owner_child_process_verbs.clone();
        let scopes = if owner_child_process_verbs.is_empty() {
            BTreeSet::from([AssignmentScope::Primary])
        } else {
            BTreeSet::from([AssignmentScope::Primary, AssignmentScope::OwnerChildProcess])
        };
        Self {
            provider_ref: lease.provider_ref.clone(),
            assignment: lease.identity.clone(),
            resource_ref: lease.resource_ref.clone(),
            resource_generation: lease.resource_generation,
            resource_types: lease.resource_types.clone(),
            primary_verbs: lease.primary_verbs().clone(),
            owner_child_process_verbs,
            scopes,
        }
    }

    /// Construct a decoded grant after validating its bounded shape.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider_ref: ResourceRef,
        assignment: AssignmentIdentity,
        resource_ref: ResourceRef,
        resource_generation: ResourceGeneration,
        resource_types: BTreeSet<ResourceTypeName>,
        primary_verbs: BTreeSet<AssignmentVerb>,
        owner_child_process_verbs: BTreeSet<AssignmentVerb>,
        scopes: BTreeSet<AssignmentScope>,
    ) -> Result<Self, AssignmentTransportError> {
        if provider_ref.resource_type().as_str() != "Provider"
            || resource_ref.resource_type().as_str() == "Provider"
            || resource_generation.get() == 0
            || resource_types.is_empty()
            || resource_types.len() > MAX_ASSIGNMENT_GRANT_RESOURCE_TYPES
            || !resource_types.contains(resource_ref.resource_type())
            || assignment.session_binding().provider_ref() != &provider_ref
            || primary_verbs.is_empty()
            || primary_verbs.len() > MAX_ASSIGNMENT_GRANT_VERBS
            || owner_child_process_verbs.len() > MAX_ASSIGNMENT_GRANT_VERBS
            || scopes.is_empty()
            || scopes.len() > MAX_ASSIGNMENT_GRANT_SCOPES
            || !scopes.contains(&AssignmentScope::Primary)
            || (scopes.contains(&AssignmentScope::OwnerChildProcess)
                != !owner_child_process_verbs.is_empty())
            || owner_child_process_verbs.iter().any(|verb| {
                !matches!(
                    verb,
                    AssignmentVerb::Create | AssignmentVerb::UpdateSpec | AssignmentVerb::Delete
                )
            })
        {
            return Err(AssignmentTransportError::Malformed);
        }
        Ok(Self {
            provider_ref,
            assignment,
            resource_ref,
            resource_generation,
            resource_types,
            primary_verbs,
            owner_child_process_verbs,
            scopes,
        })
    }

    /// Borrow the Provider ResourceRef bound by Core.
    pub const fn provider_ref(&self) -> &ResourceRef {
        &self.provider_ref
    }

    /// Borrow the complete assignment identity.
    pub const fn assignment(&self) -> &AssignmentIdentity {
        &self.assignment
    }

    /// Borrow the Process resource that owns the authenticated session.
    pub const fn session_owner(&self) -> &ResourceRef {
        self.assignment.session_owner()
    }

    /// Borrow the exact controller-session binding.
    pub const fn session_binding(&self) -> &ControllerSessionBinding {
        self.assignment.session_binding()
    }

    /// Borrow the exact assigned ResourceRef.
    pub const fn resource_ref(&self) -> &ResourceRef {
        &self.resource_ref
    }

    /// Return the assigned resource generation.
    pub const fn resource_generation(&self) -> ResourceGeneration {
        self.resource_generation
    }

    /// Borrow the exact ResourceTypes allowed by the grant.
    pub const fn resource_types(&self) -> &BTreeSet<ResourceTypeName> {
        &self.resource_types
    }

    /// Borrow the exact primary-scope verbs allowed by the grant.
    pub const fn primary_verbs(&self) -> &BTreeSet<AssignmentVerb> {
        &self.primary_verbs
    }

    /// Borrow the exact owner-child-process verbs allowed by the grant.
    pub const fn owner_child_process_verbs(&self) -> &BTreeSet<AssignmentVerb> {
        &self.owner_child_process_verbs
    }

    /// Borrow the exact query and mutation scopes allowed by the grant.
    pub const fn scopes(&self) -> &BTreeSet<AssignmentScope> {
        &self.scopes
    }

    /// Validate this grant against the controller's authenticated session.
    pub fn validate_for(
        &self,
        expected: &ControllerAssignmentExpectation,
    ) -> Result<(), AssignmentError> {
        if self.provider_ref != expected.provider_ref {
            return Err(AssignmentError::ProviderRefMismatch);
        }
        if self.assignment.controller_role() != &expected.controller_role {
            return Err(AssignmentError::ControllerRoleMismatch);
        }
        if expected
            .provider_generation
            .is_some_and(|generation| self.assignment.provider_generation() != generation)
        {
            return Err(AssignmentError::ProviderGenerationMismatch);
        }
        if expected
            .controller_generation
            .is_some_and(|generation| self.assignment.controller_generation() != generation)
        {
            return Err(AssignmentError::ControllerGenerationMismatch);
        }
        if self.assignment.session_generation() != expected.session_generation {
            return Err(AssignmentError::SessionBindingMismatch);
        }
        if expected
            .target
            .as_ref()
            .is_some_and(|target| self.assignment.target() != target)
        {
            return Err(AssignmentError::TargetMismatch);
        }
        if expected
            .target_kind
            .is_some_and(|kind| self.assignment.target().target_kind() != Some(kind))
        {
            return Err(AssignmentError::TargetMismatch);
        }
        if expected
            .session_owner
            .as_ref()
            .is_some_and(|owner| self.assignment.session_owner() != owner)
        {
            return Err(AssignmentError::SessionBindingMismatch);
        }
        if self.resource_types != expected.resource_types
            || self.primary_verbs != expected.primary_verbs
            || self.owner_child_process_verbs != expected.owner_child_process_verbs
            || self.scopes != expected.scopes
        {
            return Err(AssignmentError::QueryWidened);
        }
        Ok(())
    }

    /// Encode this grant as bounded canonical JSON.
    pub fn encode(&self) -> Result<Vec<u8>, AssignmentTransportError> {
        let value = json!({
            "version": 1,
            "providerRef": self.provider_ref.to_canonical_string(),
            "assignment": encode_assignment(&self.assignment),
            "resourceRef": self.resource_ref.to_canonical_string(),
            "resourceGeneration": self.resource_generation.get(),
            "resourceTypes": self.resource_types
                .iter()
                .map(|resource_type| resource_type.as_str())
                .collect::<Vec<_>>(),
            "primaryVerbs": self.primary_verbs
                .iter()
                .map(|verb| encode_assignment_verb(*verb))
                .collect::<Vec<_>>(),
            "ownerChildProcessVerbs": self.owner_child_process_verbs
                .iter()
                .map(|verb| encode_assignment_verb(*verb))
                .collect::<Vec<_>>(),
            "scopes": self.scopes
                .iter()
                .map(|scope| encode_assignment_scope(*scope))
                .collect::<Vec<_>>(),
        });
        encode_bounded_json(&value, MAX_CONTROLLER_ASSIGNMENT_GRANT_BYTES)
    }

    /// Decode one bounded canonical grant.
    pub fn decode(bytes: &[u8]) -> Result<Self, AssignmentTransportError> {
        if bytes.is_empty() || bytes.len() > MAX_CONTROLLER_ASSIGNMENT_GRANT_BYTES {
            return Err(AssignmentTransportError::TooLarge);
        }
        CanonicalJsonValue::parse(bytes).map_err(|_| AssignmentTransportError::Malformed)?;
        let value = serde_json::from_slice::<Value>(bytes)
            .map_err(|_| AssignmentTransportError::Malformed)?;
        let object = value
            .as_object()
            .ok_or(AssignmentTransportError::Malformed)?;
        require_exact_keys(
            object,
            &[
                "version",
                "providerRef",
                "assignment",
                "resourceRef",
                "resourceGeneration",
                "resourceTypes",
                "primaryVerbs",
                "ownerChildProcessVerbs",
                "scopes",
            ],
        )?;
        if object.get("version").and_then(Value::as_u64) != Some(1) {
            return Err(AssignmentTransportError::Malformed);
        }
        let provider_ref = ResourceRef::parse(
            object
                .get("providerRef")
                .and_then(Value::as_str)
                .ok_or(AssignmentTransportError::Malformed)?,
        )
        .map_err(|_| AssignmentTransportError::Malformed)?;
        let assignment = decode_assignment(
            object
                .get("assignment")
                .ok_or(AssignmentTransportError::Malformed)?,
        )?;
        let resource_ref = ResourceRef::parse(
            object
                .get("resourceRef")
                .and_then(Value::as_str)
                .ok_or(AssignmentTransportError::Malformed)?,
        )
        .map_err(|_| AssignmentTransportError::Malformed)?;
        let resource_generation = ResourceGeneration::new(
            object
                .get("resourceGeneration")
                .and_then(Value::as_u64)
                .ok_or(AssignmentTransportError::Malformed)?,
        )
        .map_err(|_| AssignmentTransportError::Malformed)?;
        let resource_types = decode_string_set(
            object
                .get("resourceTypes")
                .and_then(Value::as_array)
                .ok_or(AssignmentTransportError::Malformed)?,
            MAX_ASSIGNMENT_GRANT_RESOURCE_TYPES,
            |value| ResourceTypeName::parse(value).map_err(|_| AssignmentTransportError::Malformed),
        )?;
        let primary_verbs = decode_string_set(
            object
                .get("primaryVerbs")
                .and_then(Value::as_array)
                .ok_or(AssignmentTransportError::Malformed)?,
            MAX_ASSIGNMENT_GRANT_VERBS,
            decode_assignment_verb,
        )?;
        let owner_child_process_values = object
            .get("ownerChildProcessVerbs")
            .and_then(Value::as_array)
            .ok_or(AssignmentTransportError::Malformed)?;
        let owner_child_process_verbs = if owner_child_process_values.is_empty() {
            BTreeSet::new()
        } else {
            decode_string_set(
                owner_child_process_values,
                MAX_ASSIGNMENT_GRANT_VERBS,
                decode_assignment_verb,
            )?
        };
        let scopes = decode_string_set(
            object
                .get("scopes")
                .and_then(Value::as_array)
                .ok_or(AssignmentTransportError::Malformed)?,
            MAX_ASSIGNMENT_GRANT_SCOPES,
            decode_assignment_scope,
        )?;
        Self::new(
            provider_ref,
            assignment,
            resource_ref,
            resource_generation,
            resource_types,
            primary_verbs,
            owner_child_process_verbs,
            scopes,
        )
    }

    /// Encode a bounded revocation notice for this assignment identity.
    pub fn encode_revocation(
        provider_ref: &ResourceRef,
        assignment: &AssignmentIdentity,
    ) -> Result<Vec<u8>, AssignmentTransportError> {
        if provider_ref.resource_type().as_str() != "Provider" {
            return Err(AssignmentTransportError::Malformed);
        }
        let value = json!({
            "version": 1,
            "kind": "revoke",
            "providerRef": provider_ref.to_canonical_string(),
            "assignment": encode_assignment(assignment),
        });
        encode_bounded_json(&value, MAX_CONTROLLER_ASSIGNMENT_GRANT_BYTES)
    }
}

impl fmt::Debug for ControllerAssignmentGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControllerAssignmentGrant")
            .field("resource_generation", &self.resource_generation)
            .field("resource_type_count", &self.resource_types.len())
            .field("primary_verb_count", &self.primary_verbs.len())
            .field(
                "owner_child_process_verb_count",
                &self.owner_child_process_verbs.len(),
            )
            .field("scope_count", &self.scopes.len())
            .finish()
    }
}

fn decode_string_set<T>(
    values: &[Value],
    limit: usize,
    decode: impl Fn(&str) -> Result<T, AssignmentTransportError>,
) -> Result<BTreeSet<T>, AssignmentTransportError>
where
    T: Clone + Ord,
{
    if values.is_empty() || values.len() > limit {
        return Err(AssignmentTransportError::Malformed);
    }
    let mut decoded = BTreeSet::new();
    let mut previous = None;
    for value in values {
        let value = value.as_str().ok_or(AssignmentTransportError::Malformed)?;
        let value = decode(value)?;
        if previous.as_ref().is_some_and(|previous| previous >= &value) || !decoded.insert(value) {
            return Err(AssignmentTransportError::Malformed);
        }
        previous = decoded.last().cloned();
    }
    Ok(decoded)
}

/// Result of accepting one assignment grant delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantDisposition {
    /// The exact grant was retained for the active session.
    Installed,
    /// The exact grant was already retained.
    Duplicate,
    /// The exact grant identity was revoked.
    Revoked,
}

/// Error from decoding or admitting one remote assignment grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignmentGrantError {
    /// The bounded transport payload was invalid.
    Transport(AssignmentTransportError),
    /// The decoded grant failed the session's exact authority expectation.
    Assignment(AssignmentError),
}

impl fmt::Display for AssignmentGrantError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => error.fmt(formatter),
            Self::Assignment(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for AssignmentGrantError {}

#[derive(Clone)]
struct RevokedAssignmentObservation {
    identity: AssignmentIdentity,
    resource_ref: Option<ResourceRef>,
}

/// Controller-side retention for grants bound to one authenticated session.
pub struct ControllerAssignmentGrantStore {
    expectation: ControllerAssignmentExpectation,
    active: bool,
    grants: BTreeMap<ResourceUid, ControllerAssignmentGrant>,
    revoked: BTreeMap<ResourceUid, RevokedAssignmentObservation>,
    provider_generation: Option<ResourceGeneration>,
    controller_generation: Option<ControllerGeneration>,
    session_owner: Option<ResourceRef>,
    target: Option<AssignmentTarget>,
    last_epoch: Option<AssignmentEpoch>,
}

impl ControllerAssignmentGrantStore {
    /// Construct an empty active store for one exact session generation.
    pub fn new(expectation: ControllerAssignmentExpectation) -> Result<Self, AssignmentError> {
        Ok(Self {
            expectation,
            active: true,
            grants: BTreeMap::new(),
            revoked: BTreeMap::new(),
            provider_generation: None,
            controller_generation: None,
            session_owner: None,
            target: None,
            last_epoch: None,
        })
    }

    /// Accept one already-decoded grant.
    pub fn accept(
        &mut self,
        grant: ControllerAssignmentGrant,
    ) -> Result<GrantDisposition, AssignmentError> {
        if !self.active {
            return Err(AssignmentError::SessionRevoked);
        }
        grant.validate_for(&self.expectation)?;
        if let Some(revoked) = self.revoked.get(grant.assignment.resource_uid()) {
            if revoked.identity == grant.assignment {
                return Err(AssignmentError::StaleAssignment);
            }
            if revoked
                .resource_ref
                .as_ref()
                .is_some_and(|resource_ref| resource_ref != grant.resource_ref())
            {
                return Err(AssignmentError::AssignmentConflict);
            }
        }
        if let Some(existing) = self.grants.get(grant.assignment.resource_uid()) {
            return if existing == &grant {
                Ok(GrantDisposition::Duplicate)
            } else {
                Err(AssignmentError::AssignmentConflict)
            };
        }
        if self
            .provider_generation
            .is_some_and(|generation| grant.assignment.provider_generation() != generation)
        {
            return Err(AssignmentError::ProviderGenerationMismatch);
        }
        if self
            .controller_generation
            .is_some_and(|generation| grant.assignment.controller_generation() != generation)
        {
            return Err(AssignmentError::ControllerGenerationMismatch);
        }
        if self
            .session_owner
            .as_ref()
            .is_some_and(|owner| grant.assignment.session_owner() != owner)
        {
            return Err(AssignmentError::SessionBindingMismatch);
        }
        if self
            .target
            .as_ref()
            .is_some_and(|target| grant.assignment.target() != target)
        {
            return Err(AssignmentError::TargetMismatch);
        }
        if self
            .revoked
            .get(grant.assignment.resource_uid())
            .is_some_and(|revoked| grant.assignment.epoch() <= revoked.identity.epoch())
        {
            return Err(AssignmentError::StaleAssignment);
        }
        if self
            .last_epoch
            .is_some_and(|epoch| grant.assignment.epoch() <= epoch)
        {
            return Err(AssignmentError::StaleAssignment);
        }
        if !self.revoked.contains_key(grant.assignment.resource_uid())
            && self.tracked_len() >= MAX_ASSIGNMENTS
        {
            return Err(AssignmentError::AssignmentLimit);
        }
        self.provider_generation = Some(grant.assignment.provider_generation());
        self.controller_generation = Some(grant.assignment.controller_generation());
        self.session_owner = Some(grant.assignment.session_owner().clone());
        self.target = Some(grant.assignment.target().clone());
        self.last_epoch = Some(grant.assignment.epoch());
        self.grants
            .insert(grant.assignment.resource_uid().clone(), grant);
        Ok(GrantDisposition::Installed)
    }

    /// Revoke one exact assignment while preserving its last observation.
    pub fn revoke_assignment(
        &mut self,
        provider_ref: &ResourceRef,
        assignment: AssignmentIdentity,
    ) -> Result<GrantDisposition, AssignmentError> {
        if !self.active {
            return Err(AssignmentError::SessionRevoked);
        }
        if provider_ref != &self.expectation.provider_ref {
            return Err(AssignmentError::ProviderRefMismatch);
        }
        self.validate_identity(&assignment)?;
        if self
            .provider_generation
            .is_some_and(|generation| assignment.provider_generation() != generation)
        {
            return Err(AssignmentError::ProviderGenerationMismatch);
        }
        if self
            .controller_generation
            .is_some_and(|generation| assignment.controller_generation() != generation)
        {
            return Err(AssignmentError::ControllerGenerationMismatch);
        }
        if self
            .session_owner
            .as_ref()
            .is_some_and(|owner| assignment.session_owner() != owner)
        {
            return Err(AssignmentError::SessionBindingMismatch);
        }
        if self
            .target
            .as_ref()
            .is_some_and(|target| assignment.target() != target)
        {
            return Err(AssignmentError::TargetMismatch);
        }
        if let Some(existing) = self.grants.get(assignment.resource_uid())
            && existing.assignment != assignment
        {
            if self
                .revoked
                .get(assignment.resource_uid())
                .is_some_and(|revoked| revoked.identity == assignment)
            {
                return Ok(GrantDisposition::Duplicate);
            }
            return Err(AssignmentError::AssignmentConflict);
        }
        if let Some(existing) = self.revoked.get(assignment.resource_uid())
            && existing.identity == assignment
            && self.grants.get(assignment.resource_uid()).is_none()
        {
            return Ok(GrantDisposition::Duplicate);
        }
        if self
            .revoked
            .get(assignment.resource_uid())
            .is_some_and(|revoked| assignment.epoch() <= revoked.identity.epoch())
        {
            return Err(AssignmentError::StaleAssignment);
        }
        let had_revoked_observation = self.revoked.contains_key(assignment.resource_uid());
        let revoked_resource_ref = self
            .grants
            .remove(assignment.resource_uid())
            .map(|grant| grant.resource_ref().clone())
            .or_else(|| {
                self.revoked
                    .get(assignment.resource_uid())
                    .and_then(|observation| observation.resource_ref.clone())
            });
        if revoked_resource_ref.is_none()
            && !had_revoked_observation
            && self.tracked_len() >= MAX_ASSIGNMENTS
        {
            return Err(AssignmentError::AssignmentLimit);
        }
        self.revoked.insert(
            assignment.resource_uid().clone(),
            RevokedAssignmentObservation {
                identity: assignment,
                resource_ref: revoked_resource_ref,
            },
        );
        Ok(GrantDisposition::Revoked)
    }

    fn tracked_len(&self) -> usize {
        self.grants.len()
            + self
                .revoked
                .keys()
                .filter(|resource_uid| !self.grants.contains_key(*resource_uid))
                .count()
    }

    /// Decode and accept one bounded transport payload.
    pub fn accept_encoded(
        &mut self,
        bytes: &[u8],
    ) -> Result<GrantDisposition, AssignmentGrantError> {
        if bytes.is_empty() || bytes.len() > MAX_CONTROLLER_ASSIGNMENT_GRANT_BYTES {
            return Err(AssignmentGrantError::Transport(
                AssignmentTransportError::TooLarge,
            ));
        }
        CanonicalJsonValue::parse(bytes)
            .map_err(|_| AssignmentGrantError::Transport(AssignmentTransportError::Malformed))?;
        let value = serde_json::from_slice::<Value>(bytes)
            .map_err(|_| AssignmentGrantError::Transport(AssignmentTransportError::Malformed))?;
        let object = value.as_object().ok_or(AssignmentGrantError::Transport(
            AssignmentTransportError::Malformed,
        ))?;
        if object.get("kind").and_then(Value::as_str) == Some("revoke") {
            require_exact_keys(object, &["version", "kind", "providerRef", "assignment"])
                .map_err(AssignmentGrantError::Transport)?;
            if object.get("version").and_then(Value::as_u64) != Some(1) {
                return Err(AssignmentGrantError::Transport(
                    AssignmentTransportError::Malformed,
                ));
            }
            let provider_ref = ResourceRef::parse(
                object.get("providerRef").and_then(Value::as_str).ok_or(
                    AssignmentGrantError::Transport(AssignmentTransportError::Malformed),
                )?,
            )
            .map_err(|_| AssignmentGrantError::Transport(AssignmentTransportError::Malformed))?;
            let assignment = decode_assignment(object.get("assignment").ok_or(
                AssignmentGrantError::Transport(AssignmentTransportError::Malformed),
            )?)
            .map_err(AssignmentGrantError::Transport)?;
            return self
                .revoke_assignment(&provider_ref, assignment)
                .map_err(AssignmentGrantError::Assignment);
        }
        let grant =
            ControllerAssignmentGrant::decode(bytes).map_err(AssignmentGrantError::Transport)?;
        self.accept(grant).map_err(AssignmentGrantError::Assignment)
    }

    /// Revoke all retained authority while preserving last observations.
    pub fn revoke(&mut self) {
        self.active = false;
    }

    /// Whether the store can still authorize the current session.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Return the number of retained assignments.
    pub fn len(&self) -> usize {
        self.grants.len()
    }

    /// Whether no assignment observations are retained.
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    /// Borrow an assignment only while the session remains active.
    pub fn get(&self, resource_uid: &ResourceUid) -> Option<&ControllerAssignmentGrant> {
        if !self.active {
            return None;
        }
        self.grants.get(resource_uid)
    }

    fn validate_identity(&self, assignment: &AssignmentIdentity) -> Result<(), AssignmentError> {
        if assignment.controller_role() != &self.expectation.controller_role {
            return Err(AssignmentError::ControllerRoleMismatch);
        }
        if self
            .expectation
            .provider_generation
            .is_some_and(|generation| assignment.provider_generation() != generation)
        {
            return Err(AssignmentError::ProviderGenerationMismatch);
        }
        if self
            .expectation
            .controller_generation
            .is_some_and(|generation| assignment.controller_generation() != generation)
        {
            return Err(AssignmentError::ControllerGenerationMismatch);
        }
        if assignment.session_generation() != self.expectation.session_generation {
            return Err(AssignmentError::SessionBindingMismatch);
        }
        if self
            .expectation
            .session_owner
            .as_ref()
            .is_some_and(|owner| assignment.session_owner() != owner)
        {
            return Err(AssignmentError::SessionBindingMismatch);
        }
        if self
            .expectation
            .target
            .as_ref()
            .is_some_and(|target| assignment.target() != target)
        {
            return Err(AssignmentError::TargetMismatch);
        }
        if self
            .expectation
            .target_kind
            .is_some_and(|kind| assignment.target().target_kind() != Some(kind))
        {
            return Err(AssignmentError::TargetMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for ControllerAssignmentGrantStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControllerAssignmentGrantStore")
            .field("active", &self.active)
            .field("grant_count", &self.grants.len())
            .finish()
    }
}

/// A non-clonable ResourceClient capability minted for one assignment.
pub struct ResourceClientLease {
    identity: AssignmentIdentity,
    provider_ref: ResourceRef,
    resource_ref: ResourceRef,
    resource_generation: ResourceGeneration,
    resource_types: BTreeSet<ResourceTypeName>,
    state: Arc<AssignmentLeaseState>,
    allowed_verbs: BTreeSet<AssignmentVerb>,
    owner_child_process_verbs: BTreeSet<AssignmentVerb>,
}

impl ResourceClientLease {
    /// Borrow the complete immutable assignment identity.
    pub const fn identity(&self) -> &AssignmentIdentity {
        &self.identity
    }

    /// Borrow the Provider ResourceRef bound by Core.
    pub const fn provider_ref(&self) -> &ResourceRef {
        &self.provider_ref
    }

    /// Build the bounded transport grant for this assignment.
    pub fn assignment_grant(&self) -> ControllerAssignmentGrant {
        ControllerAssignmentGrant::from_lease(self)
    }

    /// Borrow the exact primary-scope verbs admitted by Core.
    pub const fn primary_verbs(&self) -> &BTreeSet<AssignmentVerb> {
        &self.allowed_verbs
    }

    /// Borrow the exact owner-child-process verbs admitted by the lease
    /// contract.
    pub const fn owner_child_process_verbs(&self) -> &BTreeSet<AssignmentVerb> {
        &self.owner_child_process_verbs
    }

    /// Borrow the exact assigned resource target.
    pub const fn resource_ref(&self) -> &ResourceRef {
        &self.resource_ref
    }

    /// Return the assigned resource generation bound to child admissions.
    pub const fn resource_generation(&self) -> ResourceGeneration {
        self.resource_generation
    }

    /// Borrow the exact assigned placement target.
    pub const fn target(&self) -> &AssignmentTarget {
        self.identity.target()
    }

    /// Return the current lease phase.
    pub fn phase(&self) -> AssignmentPhase {
        AssignmentPhase::from_code(self.state.phase.load(Ordering::Acquire))
    }

    fn ensure_watch(&self) -> Result<(), AssignmentError> {
        let phase = self.phase();
        if phase.admits_watch() {
            return Ok(());
        }
        Err(match phase {
            AssignmentPhase::Revoked => AssignmentError::SessionRevoked,
            AssignmentPhase::Stale
            | AssignmentPhase::Draining
            | AssignmentPhase::Released
            | AssignmentPhase::Quarantined => AssignmentError::StaleAssignment,
            AssignmentPhase::Pending => AssignmentError::AssignmentMissing,
            AssignmentPhase::Assigned => AssignmentError::StaleAssignment,
        })
    }

    fn ensure_mutation(&self) -> Result<(), AssignmentError> {
        let phase = self.phase();
        if phase.admits_mutation() {
            return Ok(());
        }
        Err(match phase {
            AssignmentPhase::Revoked => AssignmentError::SessionRevoked,
            _ => AssignmentError::StaleAssignment,
        })
    }

    /// Mint a query whose assignment filter cannot be removed or widened.
    pub fn query(
        &self,
        resource_types: Vec<ResourceTypeName>,
        resource_names: Vec<ResourceName>,
        filters: Vec<ScopedResourceFilter>,
    ) -> Result<ScopedResourceQuery, AssignmentError> {
        self.ensure_watch()?;
        if resource_types
            .iter()
            .any(|resource_type| !self.resource_types.contains(resource_type))
        {
            return Err(AssignmentError::QueryWidened);
        }
        if filters
            .iter()
            .any(|filter| matches!(filter.field(), ASSIGNMENT_UID_FILTER | OWNER_UID_FILTER))
        {
            return Err(AssignmentError::QueryWidened);
        }
        let mut filters = filters;
        filters.push(ScopedResourceFilter {
            field: ASSIGNMENT_UID_FILTER.to_owned(),
            values: vec![self.identity.resource_uid().as_str().to_owned()],
            assignment_bound: true,
        });
        Ok(ScopedResourceQuery {
            assignment: self.identity.clone(),
            resource_types,
            resource_names,
            filters,
            scope: ScopedResourceScope::Primary,
        })
    }

    /// Mint a query limited to Process children owned by this assignment.
    pub fn child_query(
        &self,
        resource_types: Vec<ResourceTypeName>,
        resource_names: Vec<ResourceName>,
        filters: Vec<ScopedResourceFilter>,
    ) -> Result<ScopedResourceQuery, AssignmentError> {
        self.ensure_watch()?;
        if self.owner_child_process_verbs.is_empty()
            || resource_types.is_empty()
            || resource_types
                .iter()
                .any(|resource_type| resource_type.as_str() != PROCESS_RESOURCE_TYPE)
            || filters
                .iter()
                .any(|filter| matches!(filter.field(), ASSIGNMENT_UID_FILTER | OWNER_UID_FILTER))
        {
            return Err(AssignmentError::QueryWidened);
        }
        let owner_scope = self.owner_child_scope();
        let mut filters = filters;
        filters.push(ScopedResourceFilter {
            field: OWNER_UID_FILTER.to_owned(),
            values: vec![owner_scope.owner_uid().as_str().to_owned()],
            assignment_bound: true,
        });
        Ok(ScopedResourceQuery {
            assignment: self.identity.clone(),
            resource_types,
            resource_names,
            filters,
            scope: ScopedResourceScope::OwnerChild(owner_scope),
        })
    }

    /// Admit a mutation against the resource owned by this lease.
    pub fn mutation(
        &self,
        target: ResourceRef,
        verb: AssignmentVerb,
    ) -> Result<ScopedResourceMutation, AssignmentError> {
        self.ensure_mutation()?;
        if verb == AssignmentVerb::CommitBatch || !self.allowed_verbs.contains(&verb) {
            return Err(AssignmentError::VerbNotAllowed);
        }
        if target != self.resource_ref {
            return Err(AssignmentError::ResourceNotAssigned);
        }
        Ok(ScopedResourceMutation {
            assignment: self.identity.clone(),
            target,
            verb,
            scope: ScopedResourceScope::Primary,
        })
    }

    /// Admit a mutation against one Process child owned by this lease.
    ///
    /// Successful commit receipts must be handed to
    /// [`ControllerAssignmentRegistry::record_child`] and
    /// [`ControllerAssignmentRegistry::remove_child`] by the controller
    /// owner. Minting this capability does not pre-account a child that may
    /// never commit.
    pub fn child_mutation(
        &self,
        target: ResourceRef,
        verb: AssignmentVerb,
    ) -> Result<ScopedResourceMutation, AssignmentError> {
        self.ensure_mutation()?;
        if !self.owner_child_process_verbs.contains(&verb) {
            return Err(AssignmentError::VerbNotAllowed);
        }
        if target.resource_type().as_str() != PROCESS_RESOURCE_TYPE {
            return Err(AssignmentError::QueryWidened);
        }
        Ok(ScopedResourceMutation {
            assignment: self.identity.clone(),
            target,
            verb,
            scope: ScopedResourceScope::OwnerChild(self.owner_child_scope()),
        })
    }

    fn owner_child_scope(&self) -> OwnerChildScope {
        OwnerChildScope {
            owner_ref: self.resource_ref.clone(),
            owner_uid: self.identity.resource_uid().clone(),
            owner_revision: self.identity.resource_revision(),
            owner_generation: self.resource_generation,
        }
    }

    /// Verify that a placement target remains exactly the admitted target.
    pub fn target_for(&self, target: PlacementTarget) -> Result<(), AssignmentError> {
        if self.target() == &AssignmentTarget::from_placement(target) {
            Ok(())
        } else {
            Err(AssignmentError::TargetMismatch)
        }
    }
}

impl fmt::Debug for ResourceClientLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResourceClientLease")
            .field("resource_ref", &"<redacted>")
            .field("phase", &self.phase())
            .field("resource_type_count", &self.resource_types.len())
            .field("primary_verb_count", &self.allowed_verbs.len())
            .field(
                "owner_child_process_verb_count",
                &self.owner_child_process_verbs.len(),
            )
            .finish()
    }
}

struct AssignmentRecord {
    identity: AssignmentIdentity,
    provider_ref: ResourceRef,
    allowed_verbs: BTreeSet<AssignmentVerb>,
    state: Arc<AssignmentLeaseState>,
    children: BTreeSet<ResourceUid>,
}

struct AssignmentLeaseState {
    phase: AtomicU8,
    stale_observation: AtomicBool,
}

impl AssignmentLeaseState {
    fn new(phase: AssignmentPhase) -> Self {
        Self {
            phase: AtomicU8::new(phase.code()),
            stale_observation: AtomicBool::new(false),
        }
    }

    fn phase(&self) -> AssignmentPhase {
        AssignmentPhase::from_code(self.phase.load(Ordering::Acquire))
    }

    fn set_phase(&self, phase: AssignmentPhase) {
        self.phase.store(phase.code(), Ordering::Release);
    }

    fn mark_stale(&self) {
        self.stale_observation.store(true, Ordering::Release);
    }
}

/// Core's single-owner assignment registry.
#[derive(Default)]
pub struct ControllerAssignmentRegistry {
    records: BTreeMap<ResourceUid, AssignmentRecord>,
    active_targets: BTreeMap<(ResourceTypeName, AssignmentTarget), BTreeSet<ResourceUid>>,
    next_epoch: u64,
}

impl fmt::Debug for ControllerAssignmentRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControllerAssignmentRegistry")
            .field("assignment_count", &self.records.len())
            .field("active_target_count", &self.active_targets.len())
            .finish()
    }
}

impl ControllerAssignmentRegistry {
    /// Reserve the next assignment epoch after all durable observations.
    pub fn reserve_epoch_after(&mut self, floor: u64) -> Result<u64, AssignmentError> {
        if self.next_epoch < floor {
            self.next_epoch = floor;
        }
        let epoch = self
            .next_epoch
            .checked_add(1)
            .ok_or(AssignmentError::EpochExhausted)?;
        self.next_epoch = epoch;
        AssignmentEpoch::new(epoch).map(|value| value.get())
    }

    /// Admit one resource from the committed store snapshot.
    pub fn admit(
        &mut self,
        request: AssignmentRequest<'_>,
    ) -> Result<ResourceClientLease, AssignmentError> {
        let resource_type = request.resource.resource_type().clone();
        if !request.role.resource_types.contains(&resource_type) {
            return Err(AssignmentError::ResourceTypeUnowned);
        }
        if request.resource.spec().provider_ref() != Some(request.role.provider_ref()) {
            return Err(AssignmentError::InvalidRole);
        }
        let placement_anchor = request
            .role
            .placement_for(&resource_type)
            .ok_or(AssignmentError::PlacementAnchorMissing)?;
        let target = AssignmentTarget::from_placement(
            placement_anchor
                .resolve(request.resource)
                .map_err(|_| AssignmentError::PlacementTargetInvalid)?,
        );
        if request
            .expected_target
            .as_ref()
            .is_some_and(|expected| expected != &target)
        {
            return Err(AssignmentError::TargetMismatch);
        }
        if !request.role.supports_target(&target) {
            return Err(AssignmentError::TargetKindUnsupported);
        }
        if matches!(
            request.role.scope(),
            ControllerInstanceScope::ZoneSingleton
                if !matches!(target, AssignmentTarget::Zone(_))
        ) || matches!(
            request.role.scope(),
            ControllerInstanceScope::FixedExecutionTarget
                if !matches!(target, AssignmentTarget::Execution { .. })
        ) {
            return Err(AssignmentError::RoleContractInvalid);
        }
        if !request.target_ready {
            return Err(AssignmentError::TargetNotReady);
        }
        let session = ControllerSessionBinding::new(
            request.session_owner.clone(),
            request.role.provider_ref.clone(),
            request.role.role_ref.clone(),
            target.clone(),
            request.provider_generation,
            request.controller_generation,
            request.session_generation,
        )?;
        if let Some(existing) = self.records.get(request.resource.metadata().uid()) {
            if matches!(
                existing.state.phase(),
                AssignmentPhase::Revoked | AssignmentPhase::Released | AssignmentPhase::Quarantined
            ) {
                self.records.remove(request.resource.metadata().uid());
                self.remove_active_target_for_uid(request.resource.metadata().uid());
            } else {
                return Err(AssignmentError::AssignmentConflict);
            }
        }
        if self.records.len() >= MAX_ASSIGNMENTS {
            return Err(AssignmentError::AssignmentLimit);
        }
        let target_key = (resource_type.clone(), target.clone());
        if self
            .active_targets
            .get(&target_key)
            .is_some_and(|uids| {
                uids.iter().any(|uid| {
                    self.records.get(uid).is_some_and(|record| {
                        record.state.phase().owns_target()
                            && (record.provider_ref != *request.role.provider_ref()
                                || record.identity.controller_role() != request.role.role_ref()
                                || record.identity.target() != &target
                                || record.identity.session_binding() != &session)
                    })
                })
            })
            // A per-resource target role intentionally allows multiple
            // resources at one target. The key is therefore only used for
            // conflicting fixed/Zone singleton controller sessions.
            && matches!(
                request.role.scope(),
                ControllerInstanceScope::ZoneSingleton
                    | ControllerInstanceScope::FixedExecutionTarget
            )
        {
            return Err(AssignmentError::AssignmentConflict);
        }
        let epoch_value = self
            .next_epoch
            .checked_add(1)
            .ok_or(AssignmentError::EpochExhausted)?;
        self.next_epoch = epoch_value;
        let epoch = AssignmentEpoch::new(epoch_value)?;
        let identity = AssignmentIdentity::new(
            request.resource.metadata().uid().clone(),
            request.resource.metadata().revision(),
            session,
            epoch,
        );
        let primary_verbs = BTreeSet::from([
            AssignmentVerb::Get,
            AssignmentVerb::List,
            AssignmentVerb::Watch,
            AssignmentVerb::Create,
            AssignmentVerb::UpdateStatus,
            AssignmentVerb::UpdateFinalizers,
            AssignmentVerb::CommitBatch,
        ]);
        let state = Arc::new(AssignmentLeaseState::new(AssignmentPhase::Assigned));
        self.records.insert(
            identity.resource_uid().clone(),
            AssignmentRecord {
                identity: identity.clone(),
                provider_ref: request.role.provider_ref.clone(),
                allowed_verbs: primary_verbs.clone(),
                state: Arc::clone(&state),
                children: BTreeSet::new(),
            },
        );
        self.active_targets
            .entry(target_key)
            .or_default()
            .insert(identity.resource_uid().clone());
        Ok(ResourceClientLease {
            identity,
            provider_ref: request.role.provider_ref.clone(),
            resource_ref: ResourceRef::new(
                resource_type.clone(),
                request.resource.metadata().name().clone(),
            ),
            resource_generation: request.resource.metadata().generation(),
            resource_types: request.role.resource_types.clone(),
            state,
            allowed_verbs: primary_verbs,
            owner_child_process_verbs: owner_child_process_verbs(),
        })
    }

    /// Rebind one live lease to the resource revision produced by its last
    /// successful write without changing its assignment epoch.
    pub fn rebind_revision(
        &mut self,
        lease: &mut ResourceClientLease,
        revision: ZoneRevision,
    ) -> Result<(), AssignmentError> {
        let record = self
            .records
            .get_mut(lease.identity.resource_uid())
            .ok_or(AssignmentError::AssignmentMissing)?;
        if record.identity != lease.identity {
            return Err(AssignmentError::StaleAssignment);
        }
        if record.state.phase() == AssignmentPhase::Revoked {
            return Err(AssignmentError::SessionRevoked);
        }
        if record.state.phase() != AssignmentPhase::Assigned {
            return Err(AssignmentError::StaleAssignment);
        }
        if revision < lease.identity.resource_revision() {
            return Err(AssignmentError::ResourceRevisionMismatch);
        }
        if revision == lease.identity.resource_revision() {
            return Ok(());
        }
        let mut identity = lease.identity.clone();
        identity.resource_revision = revision;
        record.identity = identity.clone();
        lease.identity = identity;
        Ok(())
    }

    /// Return the current phase for an assignment identity.
    pub fn phase(&self, identity: &AssignmentIdentity) -> Option<AssignmentPhase> {
        self.records
            .get(identity.resource_uid())
            .filter(|record| record.identity == *identity)
            .map(|record| record.state.phase())
    }

    /// Mark an assignment as draining before target or generation handoff.
    pub fn begin_drain(&mut self, identity: &AssignmentIdentity) -> Result<(), AssignmentError> {
        let record = self.record_mut(identity)?;
        if record.state.phase() != AssignmentPhase::Assigned {
            return Err(AssignmentError::AssignmentNotDraining);
        }
        record.state.set_phase(AssignmentPhase::Draining);
        record.state.mark_stale();
        Ok(())
    }

    /// Release a drained or revoked assignment and its target index.
    pub fn release(&mut self, identity: &AssignmentIdentity) -> Result<(), AssignmentError> {
        let record = self.record_mut(identity)?;
        if !matches!(
            record.state.phase(),
            AssignmentPhase::Draining | AssignmentPhase::Revoked | AssignmentPhase::Quarantined
        ) {
            return Err(AssignmentError::AssignmentNotReleased);
        }
        if !record.children.is_empty() {
            return Err(AssignmentError::ChildrenRemain);
        }
        record.state.set_phase(AssignmentPhase::Released);
        self.remove_active_target(identity);
        Ok(())
    }

    /// Quarantine an assignment whose target or child ownership is ambiguous.
    pub fn quarantine(&mut self, identity: &AssignmentIdentity) -> Result<(), AssignmentError> {
        let record = self.record_mut(identity)?;
        record.state.set_phase(AssignmentPhase::Quarantined);
        record.state.mark_stale();
        self.remove_active_target(identity);
        Ok(())
    }

    /// Record one child resource in the assignment's narrow owner index.
    pub fn record_child(
        &mut self,
        identity: &AssignmentIdentity,
        child_uid: ResourceUid,
    ) -> Result<(), AssignmentError> {
        let record = self.record_mut(identity)?;
        if record.children.len() >= MAX_ASSIGNED_CHILDREN {
            return Err(AssignmentError::ChildLimit);
        }
        record.children.insert(child_uid);
        Ok(())
    }

    /// Remove one child after its terminal deletion is committed.
    pub fn remove_child(
        &mut self,
        identity: &AssignmentIdentity,
        child_uid: &ResourceUid,
    ) -> Result<(), AssignmentError> {
        let record = self.record_mut(identity)?;
        if !record.children.remove(child_uid) {
            return Err(AssignmentError::AssignmentMissing);
        }
        Ok(())
    }

    /// Return the currently indexed child UIDs.
    pub fn child_uids(&self, identity: &AssignmentIdentity) -> Option<&BTreeSet<ResourceUid>> {
        self.records
            .get(identity.resource_uid())
            .filter(|record| record.identity == *identity)
            .map(|record| &record.children)
    }

    /// Revoke all assignments bound to a disconnected session generation.
    pub fn revoke_session(&mut self, generation: ReconnectGeneration) {
        let revoked = self
            .records
            .values_mut()
            .filter_map(|record| {
                if record.identity.session_generation() == generation
                    && matches!(
                        record.state.phase(),
                        AssignmentPhase::Assigned | AssignmentPhase::Draining
                    )
                {
                    record.state.set_phase(AssignmentPhase::Revoked);
                    record.state.mark_stale();
                    Some(record.identity.resource_uid().clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        for resource_uid in revoked {
            self.remove_active_target_for_uid(&resource_uid);
        }
    }

    /// Revoke assignments for one exact authenticated controller session
    /// without touching another controller that reused a session generation.
    pub fn revoke_session_for(&mut self, session: &ControllerSessionBinding) {
        let revoked = self
            .records
            .values_mut()
            .filter_map(|record| {
                if record.provider_ref == *session.provider_ref()
                    && record.identity.session_binding() == session
                    && matches!(
                        record.state.phase(),
                        AssignmentPhase::Assigned | AssignmentPhase::Draining
                    )
                {
                    record.state.set_phase(AssignmentPhase::Revoked);
                    record.state.mark_stale();
                    Some(record.identity.resource_uid().clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        for resource_uid in revoked {
            self.remove_active_target_for_uid(&resource_uid);
        }
    }

    /// Revoke one exact assignment identity.
    pub fn revoke_assignment(&mut self, identity: &AssignmentIdentity) {
        let revoked = self
            .records
            .get(identity.resource_uid())
            .is_some_and(|record| {
                if record.identity == *identity
                    && matches!(
                        record.state.phase(),
                        AssignmentPhase::Assigned | AssignmentPhase::Draining
                    )
                {
                    record.state.set_phase(AssignmentPhase::Revoked);
                    record.state.mark_stale();
                    true
                } else {
                    false
                }
            });
        if revoked {
            self.remove_active_target(identity);
        }
    }

    /// Validate a writer against every assignment fence.
    pub fn validate_writer(
        &self,
        identity: &AssignmentIdentity,
        uid: &ResourceUid,
        revision: ZoneRevision,
        verb: AssignmentVerb,
    ) -> Result<(), AssignmentError> {
        let record = self
            .records
            .get(identity.resource_uid())
            .ok_or(AssignmentError::AssignmentMissing)?;
        if record.identity != *identity {
            return Err(AssignmentError::StaleAssignment);
        }
        if record.state.phase() == AssignmentPhase::Revoked {
            return Err(AssignmentError::SessionRevoked);
        }
        if !record.state.phase().admits_mutation() {
            return Err(AssignmentError::StaleAssignment);
        }
        if record.identity.resource_uid() != uid {
            return Err(AssignmentError::ResourceUidMismatch);
        }
        if record.identity.resource_revision() != revision {
            return Err(AssignmentError::ResourceRevisionMismatch);
        }
        if !record.allowed_verbs.contains(&verb) {
            return Err(AssignmentError::VerbNotAllowed);
        }
        Ok(())
    }

    /// Validate a read or mutation lease without a new resource snapshot.
    pub fn validate_scope(
        &self,
        identity: &AssignmentIdentity,
        verb: AssignmentVerb,
    ) -> Result<(), AssignmentError> {
        let record = self
            .records
            .get(identity.resource_uid())
            .ok_or(AssignmentError::AssignmentMissing)?;
        if record.identity != *identity {
            return Err(AssignmentError::StaleAssignment);
        }
        if record.state.phase() == AssignmentPhase::Revoked {
            return Err(AssignmentError::SessionRevoked);
        }
        if !record.state.phase().admits_watch()
            && matches!(
                verb,
                AssignmentVerb::Get | AssignmentVerb::List | AssignmentVerb::Watch
            )
        {
            return Err(AssignmentError::StaleAssignment);
        }
        if !record.state.phase().admits_mutation() && verb.is_mutating() {
            return Err(AssignmentError::StaleAssignment);
        }
        if !record.allowed_verbs.contains(&verb) {
            return Err(AssignmentError::VerbNotAllowed);
        }
        Ok(())
    }

    /// Whether the last committed observation must be retained as stale.
    pub fn observation_is_stale(&self, identity: &AssignmentIdentity) -> bool {
        self.records
            .get(identity.resource_uid())
            .filter(|record| record.identity == *identity)
            .is_some_and(|record| record.state.stale_observation.load(Ordering::Acquire))
    }

    fn record_mut(
        &mut self,
        identity: &AssignmentIdentity,
    ) -> Result<&mut AssignmentRecord, AssignmentError> {
        let record = self
            .records
            .get_mut(identity.resource_uid())
            .ok_or(AssignmentError::AssignmentMissing)?;
        if record.identity != *identity {
            return Err(AssignmentError::StaleAssignment);
        }
        Ok(record)
    }

    fn remove_active_target(&mut self, identity: &AssignmentIdentity) {
        self.remove_active_target_for_uid(identity.resource_uid());
    }

    fn remove_active_target_for_uid(&mut self, resource_uid: &ResourceUid) {
        self.active_targets.retain(|_, uids| {
            uids.remove(resource_uid);
            !uids.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use d2b_contracts_provider::v3::{
        ArtifactDigest, ArtifactDigestSet, BinaryRef, CompatibilityRange, ComponentDescriptor,
        ComponentExecution, ComponentTargetCapability, ComponentType, ControllerInstanceScope,
        ControllerTargetKind, EffectPortClass, PolicyEvaluation, ProviderManifest,
        ResourceApiBinding, RevocationState, SignatureState, TargetRuntimeArtifacts, TrustEvidence,
        UpgradeDisposition, UpgradePolicy,
    };
    use d2b_contracts_resource::v3::execution_policy::BoundedToken;
    use d2b_contracts_resource::v3::identity::ReconnectGeneration;
    use d2b_contracts_resource::v3::{
        ControllerGeneration, PlacementAnchor, PlacementTarget, ResourceEnvelope,
        ResourceGeneration, ResourceRef, ResourceTypeName, ResourceUid, SchemaFingerprint,
        SchemaVersion, ZoneRevision,
    };

    use super::{
        AssignmentEpoch, AssignmentError, AssignmentPhase, AssignmentRequest, AssignmentTarget,
        AssignmentVerb, ControllerAssignmentExpectation, ControllerAssignmentGrant,
        ControllerAssignmentGrantStore, ControllerAssignmentRegistry, ControllerRoleContract,
        ControllerSessionBinding, GrantDisposition, PROCESS_RESOURCE_TYPE, ScopedCommitTransport,
        ScopedResourceFilter,
    };

    const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    fn digest() -> ArtifactDigest {
        ArtifactDigest::parse(DIGEST).unwrap()
    }

    fn fingerprint() -> SchemaFingerprint {
        SchemaFingerprint::parse(DIGEST).unwrap()
    }

    fn manifest() -> ProviderManifest {
        let process = ResourceTypeName::parse(PROCESS_RESOURCE_TYPE).unwrap();
        let component = ComponentDescriptor::new(
            BoundedToken::parse("process-controller").unwrap(),
            ComponentType::Controller,
            [process.clone()],
            [],
            [d2b_contracts_resource::v3::ExecutionDomain::System],
            8,
            digest(),
            [],
            false,
        )
        .unwrap()
        .with_execution(ComponentExecution::Launchable {
            binary_ref: BinaryRef::parse("process-controller").unwrap(),
        })
        .with_controller_placement(
            ControllerInstanceScope::PerResourceTarget,
            [ControllerTargetKind::Host, ControllerTargetKind::Guest],
        )
        .unwrap()
        .with_target_capabilities([
            ComponentTargetCapability::new(
                ControllerTargetKind::Host,
                digest(),
                [EffectPortClass::Process],
            )
            .unwrap(),
            ComponentTargetCapability::new(
                ControllerTargetKind::Guest,
                digest(),
                [EffectPortClass::Process],
            )
            .unwrap(),
        ])
        .unwrap();
        let binding = ResourceApiBinding::new_with_placement(
            process,
            SchemaVersion::new(1, 0).unwrap(),
            fingerprint(),
            SchemaVersion::new(1, 0).unwrap(),
            fingerprint(),
            Default::default(),
            None,
            None,
            d2b_contracts_resource::v3::PlacementAnchor::ExecutionRef,
        )
        .unwrap();
        let trust = TrustEvidence {
            publisher: BoundedToken::parse("trusted").unwrap(),
            root_epoch: 1,
            publisher_trusted: true,
            signature: SignatureState::Valid,
            revocation: RevocationState::Clear,
            emergency_deny: false,
            provenance: PolicyEvaluation::Accepted,
            sbom: PolicyEvaluation::Accepted,
            license: PolicyEvaluation::Accepted,
            vulnerability: PolicyEvaluation::Accepted,
            conformance: PolicyEvaluation::Accepted,
            support_channel: BoundedToken::parse("stable").unwrap(),
        };
        ProviderManifest::new(
            d2b_contracts_resource::v3::ArtifactId::parse("provider-runtime").unwrap(),
            ArtifactDigestSet {
                executable: digest(),
                config: digest(),
                schema: digest(),
                service: digest(),
            },
            trust,
            CompatibilityRange {
                api_major: 3,
                api_minor: 0,
                descriptor_fingerprint: fingerprint(),
                state_schema_version: SchemaVersion::new(1, 0).unwrap(),
            },
            [component],
            [binding],
            [],
            UpgradePolicy {
                drain_before_upgrade: true,
                max_automatic_disposition: UpgradeDisposition::InPlace,
                preserves_durable_state: true,
            },
        )
        .unwrap()
        .with_target_runtime_artifacts([
            TargetRuntimeArtifacts::new(ControllerTargetKind::Host, digest(), digest()).unwrap(),
            TargetRuntimeArtifacts::new(ControllerTargetKind::Guest, digest(), digest()).unwrap(),
        ])
        .unwrap()
    }

    fn process(name: &str, execution_ref: &str, revision: u64) -> ResourceEnvelope {
        let uid = if name.contains("guest") {
            if name.contains("second") {
                "323e4567-e89b-42d3-a456-426614174002"
            } else {
                "223e4567-e89b-42d3-a456-426614174001"
            }
        } else {
            "123e4567-e89b-42d3-a456-426614174000"
        };
        let value = serde_json::json!({
            "apiVersion": "resources.d2bus.org/v3",
            "type": PROCESS_RESOURCE_TYPE,
            "metadata": {
                "name": name,
                "zone": "dev",
                "uid": uid,
                "generation": 1,
                "revision": revision,
                "ownerRef": null,
                "finalizers": [],
                "deletionRequestedAt": null,
                "createdAt": "2026-07-22T00:00:00.000Z",
                "updatedAt": "2026-07-22T00:00:00.000Z",
                "managedBy": "api",
                "configurationGeneration": null,
                "controllerGeneration": null,
                "providerGeneration": null
            },
            "spec": {
                "providerRef": "Provider/provider-runtime",
                "executionRef": execution_ref,
                "argv": ["true"]
            },
            "status": {
                "completedAt": null,
                "conditions": [],
                "lastReconciledAt": null,
                "observedGeneration": 0,
                "outcome": null,
                "phase": "Pending",
                "resource": {},
                "startedAt": null,
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
                }
            }
        });
        ResourceEnvelope::from_json(&serde_json::to_vec(&value).unwrap()).unwrap()
    }

    fn guest(name: &str, uid: &str, execution_ref: &str, revision: u64) -> ResourceEnvelope {
        let value = serde_json::json!({
            "apiVersion": "resources.d2bus.org/v3",
            "type": "Guest",
            "metadata": {
                "name": name,
                "zone": "dev",
                "uid": uid,
                "generation": 1,
                "revision": revision,
                "ownerRef": null,
                "finalizers": [],
                "deletionRequestedAt": null,
                "createdAt": "2026-07-22T00:00:00.000Z",
                "updatedAt": "2026-07-22T00:00:00.000Z",
                "managedBy": "api",
                "configurationGeneration": null,
                "controllerGeneration": null,
                "providerGeneration": null
            },
            "spec": {
                "providerRef": "Provider/provider-runtime",
                "executionRef": execution_ref
            },
            "status": {
                "completedAt": null,
                "conditions": [],
                "lastReconciledAt": null,
                "observedGeneration": 0,
                "outcome": null,
                "phase": "Pending",
                "resource": {},
                "startedAt": null,
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
                }
            }
        });
        ResourceEnvelope::from_json(&serde_json::to_vec(&value).unwrap()).unwrap()
    }

    fn role() -> ControllerRoleContract {
        ControllerRoleContract::from_signed_manifest(
            ResourceRef::parse("Provider/provider-runtime").unwrap(),
            ResourceRef::parse("Process/process-controller").unwrap(),
            &manifest(),
        )
        .unwrap()
    }

    fn request<'a>(
        resource: &'a ResourceEnvelope,
        role: &'a ControllerRoleContract,
        provider_generation: u64,
        controller_generation: u64,
        session_generation: u64,
    ) -> AssignmentRequest<'a> {
        AssignmentRequest::new(
            resource,
            role,
            ResourceGeneration::new(provider_generation).unwrap(),
            ControllerGeneration::new(controller_generation).unwrap(),
            ReconnectGeneration::new(session_generation).unwrap(),
            true,
        )
    }

    #[test]
    fn host_and_guest_resources_have_one_disjoint_target_assignment() {
        let host = process("host-process", "Host/host-system", 11);
        let guest = process("guest-process", "Guest/dev-vm", 12);
        let guest_second = process("guest-process-second", "Guest/dev-vm", 13);
        let role = role();
        let mut registry = ControllerAssignmentRegistry::default();
        let host_lease = registry.admit(request(&host, &role, 2, 3, 4)).unwrap();
        let guest_lease = registry.admit(request(&guest, &role, 2, 3, 5)).unwrap();
        let guest_second_lease = registry
            .admit(request(&guest_second, &role, 2, 3, 6))
            .unwrap();

        assert_ne!(
            host_lease.identity().target(),
            guest_lease.identity().target()
        );
        assert_eq!(
            guest_lease.identity().target(),
            guest_second_lease.identity().target()
        );
        assert_ne!(
            host_lease.identity().epoch(),
            guest_lease.identity().epoch()
        );
        assert_eq!(host_lease.phase(), AssignmentPhase::Assigned);
        assert_eq!(guest_lease.phase(), AssignmentPhase::Assigned);
        assert_eq!(
            host_lease.target(),
            &AssignmentTarget::Execution {
                kind: d2b_contracts_resource::v3::PlacementTargetKind::Host,
                reference: ResourceRef::parse("Host/host-system").unwrap(),
            }
        );
    }

    #[test]
    fn stale_assignment_epoch_rejects_status_and_finalizer_writers() {
        let resource = process("process", "Guest/dev-vm", 7);
        let role = role();
        let mut registry = ControllerAssignmentRegistry::default();
        let old = registry.admit(request(&resource, &role, 1, 1, 1)).unwrap();
        registry.begin_drain(old.identity()).unwrap();
        registry.release(old.identity()).unwrap();
        let new = registry.admit(request(&resource, &role, 1, 1, 2)).unwrap();

        assert_eq!(
            registry.validate_writer(
                old.identity(),
                &resource.metadata().uid().clone(),
                resource.metadata().revision(),
                AssignmentVerb::UpdateStatus,
            ),
            Err(AssignmentError::StaleAssignment)
        );
        assert!(
            registry
                .validate_writer(
                    new.identity(),
                    &resource.metadata().uid().clone(),
                    resource.metadata().revision(),
                    AssignmentVerb::UpdateFinalizers,
                )
                .is_ok()
        );
    }

    #[test]
    fn scoped_commit_transport_round_trips_assignment_and_mutations() {
        let resource = process("process", "Guest/dev-vm", 7);
        let role = role();
        let mut registry = ControllerAssignmentRegistry::default();
        let lease = registry.admit(request(&resource, &role, 1, 1, 1)).unwrap();
        let target = ResourceRef::new(
            resource.resource_type().clone(),
            resource.metadata().name().clone(),
        );
        let mutation = lease
            .mutation(target, AssignmentVerb::UpdateStatus)
            .unwrap();
        let transport =
            ScopedCommitTransport::new(lease.identity().clone(), vec![mutation]).unwrap();
        let decoded = ScopedCommitTransport::decode(&transport.encode().unwrap()).unwrap();

        assert_eq!(decoded.assignment(), lease.identity());
        assert_eq!(decoded.mutations(), transport.mutations());
    }

    #[test]
    fn scoped_commit_transport_round_trips_owner_child_scope() {
        let owner = process("process", "Guest/dev-vm", 7);
        let role = role();
        let mut registry = ControllerAssignmentRegistry::default();
        let lease = registry.admit(request(&owner, &role, 1, 1, 1)).unwrap();
        let mutation = lease
            .child_mutation(
                ResourceRef::parse("Process/process-vmm").unwrap(),
                AssignmentVerb::Create,
            )
            .unwrap();
        let transport =
            ScopedCommitTransport::new(lease.identity().clone(), vec![mutation]).unwrap();
        let encoded = transport.encode().unwrap();
        let decoded = ScopedCommitTransport::decode(&encoded).unwrap();
        let scope = decoded.mutations()[0].scope().owner_child().unwrap();

        assert_eq!(decoded.assignment(), lease.identity());
        assert_eq!(scope.owner_ref(), lease.resource_ref());
        assert_eq!(scope.owner_uid(), owner.metadata().uid());
        assert_eq!(scope.owner_revision(), owner.metadata().revision());
        assert_eq!(scope.owner_generation(), owner.metadata().generation());
    }

    #[test]
    fn same_epoch_rebind_updates_the_active_writer_revision() {
        let resource = process("process", "Guest/dev-vm", 7);
        let role = role();
        let mut registry = ControllerAssignmentRegistry::default();
        let mut lease = registry.admit(request(&resource, &role, 1, 1, 1)).unwrap();
        let stale = lease.identity().clone();

        registry
            .rebind_revision(&mut lease, ZoneRevision::new(8))
            .unwrap();

        assert_eq!(lease.identity().resource_revision(), ZoneRevision::new(8));
        assert!(
            registry
                .validate_writer(
                    lease.identity(),
                    resource.metadata().uid(),
                    ZoneRevision::new(8),
                    AssignmentVerb::UpdateStatus,
                )
                .is_ok()
        );
        assert_eq!(
            registry.validate_writer(
                &stale,
                resource.metadata().uid(),
                ZoneRevision::new(7),
                AssignmentVerb::UpdateStatus,
            ),
            Err(AssignmentError::StaleAssignment)
        );
    }

    #[test]
    fn released_assignment_allows_successor_at_the_current_revision() {
        let resource = process("process", "Guest/dev-vm", 7);
        let role = role();
        let mut registry = ControllerAssignmentRegistry::default();
        let mut old = registry.admit(request(&resource, &role, 1, 1, 1)).unwrap();
        registry
            .rebind_revision(&mut old, ZoneRevision::new(8))
            .unwrap();
        registry.begin_drain(old.identity()).unwrap();
        registry.release(old.identity()).unwrap();

        let current = process("process", "Guest/dev-vm", 8);
        let successor = registry.admit(request(&current, &role, 2, 2, 2)).unwrap();
        assert_eq!(
            successor.identity().resource_revision(),
            ZoneRevision::new(8)
        );
        assert!(
            registry
                .validate_writer(
                    successor.identity(),
                    current.metadata().uid(),
                    ZoneRevision::new(8),
                    AssignmentVerb::UpdateFinalizers,
                )
                .is_ok()
        );
    }

    #[test]
    fn disconnected_session_revokes_mutation_but_keeps_stale_observation() {
        let resource = process("process", "Guest/dev-vm", 7);
        let role = role();
        let mut registry = ControllerAssignmentRegistry::default();
        let lease = registry.admit(request(&resource, &role, 1, 1, 9)).unwrap();
        registry.revoke_session(ReconnectGeneration::new(9).unwrap());

        assert_eq!(
            registry.phase(lease.identity()),
            Some(AssignmentPhase::Revoked)
        );
        assert_eq!(lease.phase(), AssignmentPhase::Revoked);
        assert_eq!(
            lease.mutation(
                ResourceRef::parse("Process/process").unwrap(),
                AssignmentVerb::UpdateStatus,
            ),
            Err(AssignmentError::SessionRevoked)
        );
        assert_eq!(
            lease.child_query(
                vec![ResourceTypeName::parse(PROCESS_RESOURCE_TYPE).unwrap()],
                Vec::new(),
                Vec::new(),
            ),
            Err(AssignmentError::SessionRevoked)
        );
        assert_eq!(
            lease.child_mutation(
                ResourceRef::parse("Process/process-child").unwrap(),
                AssignmentVerb::Create,
            ),
            Err(AssignmentError::SessionRevoked)
        );
        assert_eq!(
            registry.validate_writer(
                lease.identity(),
                resource.metadata().uid(),
                resource.metadata().revision(),
                AssignmentVerb::UpdateStatus,
            ),
            Err(AssignmentError::SessionRevoked)
        );
        assert!(registry.observation_is_stale(lease.identity()));
    }

    #[test]
    fn disconnected_assignment_can_be_replaced_by_a_new_session() {
        let resource = process("process", "Guest/dev-vm", 7);
        let role = role();
        let mut registry = ControllerAssignmentRegistry::default();
        let old = registry.admit(request(&resource, &role, 1, 1, 1)).unwrap();
        registry.revoke_session(ReconnectGeneration::new(1).unwrap());

        let replacement = registry.admit(request(&resource, &role, 2, 2, 2)).unwrap();
        assert_ne!(old.identity().epoch(), replacement.identity().epoch());
        assert_eq!(
            replacement.identity().session_generation(),
            ReconnectGeneration::new(2).unwrap()
        );
    }

    #[test]
    fn scoped_session_revocation_does_not_touch_another_target() {
        let first_resource = process("guest-process", "Guest/dev-vm", 7);
        let second_resource = process("guest-process-second", "Guest/other-vm", 8);
        let role = role();
        let mut registry = ControllerAssignmentRegistry::default();
        let first = registry
            .admit(request(&first_resource, &role, 1, 1, 1))
            .unwrap();
        let second = registry
            .admit(request(&second_resource, &role, 1, 1, 1))
            .unwrap();

        registry.revoke_session_for(first.identity().session_binding());

        assert_eq!(first.phase(), AssignmentPhase::Revoked);
        assert_eq!(second.phase(), AssignmentPhase::Assigned);
    }

    #[test]
    fn exact_session_revocation_does_not_touch_same_generation_owner() {
        let first_resource = process("guest-process", "Guest/dev-vm", 7);
        let second_resource = process("guest-process-second", "Guest/dev-vm", 8);
        let role = role();
        let first_owner = ResourceRef::parse("Process/controller-first").unwrap();
        let second_owner = ResourceRef::parse("Process/controller-second").unwrap();
        let mut registry = ControllerAssignmentRegistry::default();
        let first = registry
            .admit(request(&first_resource, &role, 1, 1, 1).with_session_owner(first_owner.clone()))
            .unwrap();
        let second = registry
            .admit(
                request(&second_resource, &role, 1, 1, 1).with_session_owner(second_owner.clone()),
            )
            .unwrap();

        let first_session = ControllerSessionBinding::new(
            first_owner,
            role.provider_ref().clone(),
            role.role_ref().clone(),
            first.target().clone(),
            first.identity().provider_generation(),
            first.identity().controller_generation(),
            first.identity().session_generation(),
        )
        .unwrap();
        registry.revoke_session_for(&first_session);

        assert_eq!(first.phase(), AssignmentPhase::Revoked);
        assert_eq!(second.phase(), AssignmentPhase::Assigned);
        assert!(
            registry
                .validate_scope(second.identity(), AssignmentVerb::Watch)
                .is_ok()
        );
    }

    #[test]
    fn partial_delivery_rollback_revokes_an_admitted_unsent_lease() {
        let resource = process("process", "Guest/dev-vm", 7);
        let role = role();
        let mut registry = ControllerAssignmentRegistry::default();
        let lease = registry.admit(request(&resource, &role, 1, 1, 1)).unwrap();

        registry.revoke_assignment(lease.identity());

        assert_eq!(lease.phase(), AssignmentPhase::Revoked);
        assert_eq!(
            lease.mutation(
                ResourceRef::parse("Process/process").unwrap(),
                AssignmentVerb::UpdateStatus,
            ),
            Err(AssignmentError::SessionRevoked)
        );
        assert_eq!(
            registry.validate_scope(lease.identity(), AssignmentVerb::Watch),
            Err(AssignmentError::SessionRevoked)
        );
    }

    #[test]
    fn fixed_target_controller_accepts_multiple_resources_in_one_session() {
        let process_type = ResourceTypeName::parse(PROCESS_RESOURCE_TYPE).unwrap();
        let role = ControllerRoleContract {
            provider_ref: ResourceRef::parse("Provider/provider-runtime").unwrap(),
            role_ref: ResourceRef::parse("Process/process-controller").unwrap(),
            scope: ControllerInstanceScope::FixedExecutionTarget,
            supported_target_kinds: BTreeSet::from([ControllerTargetKind::Host]),
            resource_types: BTreeSet::from([process_type.clone()]),
            placements: BTreeMap::from([(process_type, PlacementAnchor::ExecutionRef)]),
        };
        let first = process("guest-process", "Host/host-system", 7);
        let second = process("guest-process-second", "Host/host-system", 8);
        let mut registry = ControllerAssignmentRegistry::default();

        registry.admit(request(&first, &role, 1, 1, 1)).unwrap();
        registry.admit(request(&second, &role, 1, 1, 1)).unwrap();
    }

    #[test]
    fn exact_revocation_allows_fixed_target_session_replacement_without_touching_sibling() {
        let guest_type = ResourceTypeName::parse("Guest").unwrap();
        let role = ControllerRoleContract {
            provider_ref: ResourceRef::parse("Provider/provider-runtime").unwrap(),
            role_ref: ResourceRef::parse("Process/process-controller").unwrap(),
            scope: ControllerInstanceScope::FixedExecutionTarget,
            supported_target_kinds: BTreeSet::from([ControllerTargetKind::Host]),
            resource_types: BTreeSet::from([guest_type.clone()]),
            placements: BTreeMap::from([(guest_type, PlacementAnchor::ExecutionRef)]),
        };
        let first_resource = guest(
            "guest-first",
            "223e4567-e89b-42d3-a456-426614174001",
            "Host/host-system",
            7,
        );
        let second_resource = guest(
            "guest-second",
            "323e4567-e89b-42d3-a456-426614174002",
            "Host/host-system",
            8,
        );
        let unrelated_resource = guest(
            "guest-unrelated",
            "123e4567-e89b-42d3-a456-426614174000",
            "Host/other-system",
            9,
        );
        let first_owner = ResourceRef::parse("Process/controller-first").unwrap();
        let replacement_owner = ResourceRef::parse("Process/controller-replacement").unwrap();
        let unrelated_owner = ResourceRef::parse("Process/controller-unrelated").unwrap();
        let mut registry = ControllerAssignmentRegistry::default();

        let first = registry
            .admit(request(&first_resource, &role, 1, 1, 7).with_session_owner(first_owner.clone()))
            .unwrap();
        let second = registry
            .admit(
                request(&second_resource, &role, 1, 1, 7).with_session_owner(first_owner.clone()),
            )
            .unwrap();
        let unrelated = registry
            .admit(request(&unrelated_resource, &role, 1, 1, 7).with_session_owner(unrelated_owner))
            .unwrap();

        registry.revoke_session_for(first.identity().session_binding());

        assert_eq!(first.phase(), AssignmentPhase::Revoked);
        assert_eq!(second.phase(), AssignmentPhase::Revoked);
        assert_eq!(unrelated.phase(), AssignmentPhase::Assigned);
        assert!(
            registry
                .validate_scope(unrelated.identity(), AssignmentVerb::Watch)
                .is_ok()
        );

        let replacement_first = registry
            .admit(
                request(&first_resource, &role, 2, 2, 7)
                    .with_session_owner(replacement_owner.clone()),
            )
            .unwrap();
        let replacement_second = registry
            .admit(request(&second_resource, &role, 2, 2, 7).with_session_owner(replacement_owner))
            .unwrap();

        assert_eq!(replacement_first.phase(), AssignmentPhase::Assigned);
        assert_eq!(replacement_second.phase(), AssignmentPhase::Assigned);
        assert_ne!(
            replacement_first.identity().epoch(),
            first.identity().epoch()
        );
        assert_ne!(
            replacement_second.identity().epoch(),
            second.identity().epoch()
        );
        assert_eq!(
            replacement_first.identity().session_generation(),
            ReconnectGeneration::new(7).unwrap()
        );
        assert_eq!(
            replacement_second.identity().session_generation(),
            ReconnectGeneration::new(7).unwrap()
        );
    }

    #[test]
    fn guest_lease_cannot_widen_to_host_or_foreign_resource() {
        let resource = process("process", "Guest/dev-vm", 7);
        let role = role();
        let mut registry = ControllerAssignmentRegistry::default();
        let lease = registry.admit(request(&resource, &role, 1, 1, 1)).unwrap();
        let query = lease
            .query(
                vec![ResourceTypeName::parse(PROCESS_RESOURCE_TYPE).unwrap()],
                vec![],
                vec![
                    ScopedResourceFilter::narrow("metadata.name", vec!["process".to_owned()])
                        .unwrap(),
                ],
            )
            .unwrap();
        assert!(
            query
                .filters()
                .iter()
                .any(|filter| filter.field() == "metadata.name")
        );
        assert!(
            query
                .filters()
                .iter()
                .any(|filter| filter.field() == "assignment.resourceUid"
                    && filter.assignment_bound())
        );
        assert_eq!(
            lease.query(
                vec![ResourceTypeName::parse("Host").unwrap()],
                vec![],
                vec![],
            ),
            Err(AssignmentError::QueryWidened)
        );
        assert_eq!(
            lease.mutation(
                ResourceRef::parse("Process/other").unwrap(),
                AssignmentVerb::UpdateStatus,
            ),
            Err(AssignmentError::ResourceNotAssigned)
        );
        assert_eq!(
            lease.target_for(PlacementTarget::Execution {
                kind: d2b_contracts_resource::v3::PlacementTargetKind::Host,
                reference: ResourceRef::parse("Host/host-system").unwrap(),
            }),
            Err(AssignmentError::TargetMismatch)
        );
    }

    #[test]
    fn assigned_lease_mints_an_exact_process_child_scope() {
        let owner = process("process", "Guest/dev-vm", 7);
        let role = role();
        let mut registry = ControllerAssignmentRegistry::default();
        let lease = registry.admit(request(&owner, &role, 1, 1, 1)).unwrap();
        let process_type = ResourceTypeName::parse(PROCESS_RESOURCE_TYPE).unwrap();

        let query = lease
            .child_query(vec![process_type.clone()], vec![], vec![])
            .unwrap();
        assert_eq!(query.resource_types(), &[process_type]);
        let owner_filter = query
            .filters()
            .iter()
            .find(|filter| filter.field() == "owner.resourceUid")
            .expect("owner UID filter");
        assert!(owner_filter.assignment_bound());
        assert_eq!(
            owner_filter.values(),
            &[owner.metadata().uid().as_str().to_owned()]
        );
        assert_eq!(
            query.owner_child_scope().unwrap().owner_ref(),
            &ResourceRef::new(
                owner.resource_type().clone(),
                owner.metadata().name().clone()
            )
        );

        let child = lease
            .child_mutation(
                ResourceRef::parse("Process/process-vmm").unwrap(),
                AssignmentVerb::Create,
            )
            .unwrap();
        assert_eq!(
            child.target(),
            &ResourceRef::parse("Process/process-vmm").unwrap()
        );
        let child_scope = child.scope().owner_child().unwrap();
        assert_eq!(child_scope.owner_uid(), owner.metadata().uid());
        assert_eq!(child_scope.owner_revision(), owner.metadata().revision());
        assert_eq!(
            child_scope.owner_generation(),
            owner.metadata().generation()
        );
        assert_eq!(
            lease.child_mutation(
                ResourceRef::parse("Process/process-vmm").unwrap(),
                AssignmentVerb::UpdateStatus,
            ),
            Err(AssignmentError::VerbNotAllowed)
        );
        assert_eq!(
            lease.child_mutation(
                ResourceRef::parse("Host/process-vmm").unwrap(),
                AssignmentVerb::Create,
            ),
            Err(AssignmentError::QueryWidened)
        );
        assert_eq!(
            lease.child_query(Vec::new(), Vec::new(), Vec::new()),
            Err(AssignmentError::QueryWidened)
        );
        assert_eq!(
            lease.child_query(
                vec![ResourceTypeName::parse("Host").unwrap()],
                Vec::new(),
                Vec::new(),
            ),
            Err(AssignmentError::QueryWidened)
        );
        assert_eq!(
            lease.child_mutation(
                ResourceRef::parse("Process/process-vmm").unwrap(),
                AssignmentVerb::UpdateFinalizers,
            ),
            Err(AssignmentError::VerbNotAllowed)
        );
        for field in [super::ASSIGNMENT_UID_FILTER, super::OWNER_UID_FILTER] {
            let forged = ScopedResourceFilter {
                field: field.to_owned(),
                values: vec![owner.metadata().uid().as_str().to_owned()],
                assignment_bound: false,
            };
            assert_eq!(
                lease.child_query(
                    vec![ResourceTypeName::parse(PROCESS_RESOURCE_TYPE).unwrap()],
                    Vec::new(),
                    vec![forged],
                ),
                Err(AssignmentError::QueryWidened)
            );
        }
        assert_eq!(
            lease.mutation(
                ResourceRef::new(
                    owner.resource_type().clone(),
                    owner.metadata().name().clone()
                ),
                AssignmentVerb::UpdateSpec,
            ),
            Err(AssignmentError::VerbNotAllowed)
        );
        assert_eq!(
            lease.mutation(
                ResourceRef::new(
                    owner.resource_type().clone(),
                    owner.metadata().name().clone()
                ),
                AssignmentVerb::Delete,
            ),
            Err(AssignmentError::VerbNotAllowed)
        );
        registry.begin_drain(lease.identity()).unwrap();
        assert_eq!(
            lease.child_query(
                vec![ResourceTypeName::parse(PROCESS_RESOURCE_TYPE).unwrap()],
                Vec::new(),
                Vec::new(),
            ),
            Err(AssignmentError::StaleAssignment)
        );
        assert_eq!(
            lease.child_mutation(
                ResourceRef::parse("Process/process-vmm").unwrap(),
                AssignmentVerb::Create,
            ),
            Err(AssignmentError::StaleAssignment)
        );
    }

    #[test]
    fn target_handoff_requires_drain_and_release_before_reassignment() {
        let resource = process("process", "Guest/dev-vm", 7);
        let role = role();
        let mut registry = ControllerAssignmentRegistry::default();
        let old = registry.admit(request(&resource, &role, 1, 1, 1)).unwrap();
        assert_eq!(
            registry
                .admit(request(&resource, &role, 2, 2, 2))
                .unwrap_err(),
            AssignmentError::AssignmentConflict
        );
        registry.begin_drain(old.identity()).unwrap();
        assert_eq!(
            registry
                .admit(request(&resource, &role, 2, 2, 2))
                .unwrap_err(),
            AssignmentError::AssignmentConflict
        );
        registry.release(old.identity()).unwrap();
        let replacement = registry.admit(request(&resource, &role, 2, 2, 2)).unwrap();
        assert_eq!(replacement.identity().provider_generation().get(), 2);
        assert_eq!(replacement.identity().controller_generation().get(), 2);
    }

    #[test]
    fn child_index_must_drain_before_parent_release() {
        let resource = process("process", "Guest/dev-vm", 7);
        let role = role();
        let mut registry = ControllerAssignmentRegistry::default();
        let lease = registry.admit(request(&resource, &role, 1, 1, 1)).unwrap();
        let child = ResourceUid::parse("423e4567-e89b-42d3-a456-426614174003").unwrap();
        registry
            .record_child(lease.identity(), child.clone())
            .unwrap();
        registry.begin_drain(lease.identity()).unwrap();
        assert_eq!(
            registry.release(lease.identity()),
            Err(AssignmentError::ChildrenRemain)
        );
        assert_eq!(registry.child_uids(lease.identity()).unwrap().len(), 1);
        registry.remove_child(lease.identity(), &child).unwrap();
        registry.release(lease.identity()).unwrap();
    }

    #[test]
    fn ambiguous_or_unready_targets_fail_closed_without_fallback() {
        let resource = process("process", "Guest/dev-vm", 7);
        let role = role();
        let mut registry = ControllerAssignmentRegistry::default();
        assert_eq!(
            registry
                .admit(AssignmentRequest::new(
                    &resource,
                    &role,
                    ResourceGeneration::new(1).unwrap(),
                    ControllerGeneration::new(1).unwrap(),
                    ReconnectGeneration::new(1).unwrap(),
                    false,
                ))
                .unwrap_err(),
            AssignmentError::TargetNotReady
        );
        let invalid = process("process", "User/not-a-target", 7);
        assert_eq!(
            registry
                .admit(request(&invalid, &role, 1, 1, 1))
                .unwrap_err(),
            AssignmentError::PlacementTargetInvalid
        );
        let wrong_target = process("process", "Guest/dev-vm", 7);
        assert_eq!(
            registry
                .admit(request(&wrong_target, &role, 1, 1, 1).with_expected_target(
                    AssignmentTarget::Execution {
                        kind: d2b_contracts_resource::v3::PlacementTargetKind::Host,
                        reference: ResourceRef::parse("Host/other").unwrap(),
                    },
                ))
                .unwrap_err(),
            AssignmentError::TargetMismatch
        );
    }

    #[test]
    fn assignment_grant_round_trips_exact_identity_and_scope() {
        let resource = process("process", "Guest/dev-vm", 7);
        let role = role();
        let mut registry = ControllerAssignmentRegistry::default();
        let lease = registry.admit(request(&resource, &role, 2, 3, 4)).unwrap();

        let grant = ControllerAssignmentGrant::from_lease(&lease);
        let decoded = ControllerAssignmentGrant::decode(&grant.encode().unwrap()).unwrap();

        assert_eq!(decoded, grant);
        assert_eq!(decoded.resource_ref(), lease.resource_ref());
        assert_eq!(decoded.resource_generation(), lease.resource_generation());
        assert_eq!(decoded.provider_ref(), role.provider_ref());
        assert_eq!(decoded.assignment().session_owner(), role.role_ref());
        assert_eq!(decoded.primary_verbs(), lease.primary_verbs());
        assert!(
            decoded
                .scopes()
                .contains(&super::AssignmentScope::OwnerChildProcess)
        );
        assert!(
            !decoded
                .primary_verbs()
                .contains(&AssignmentVerb::UpdateSpec)
        );
        assert!(!decoded.primary_verbs().contains(&AssignmentVerb::Delete));
        assert_eq!(
            decoded.owner_child_process_verbs(),
            &BTreeSet::from([
                AssignmentVerb::Create,
                AssignmentVerb::UpdateSpec,
                AssignmentVerb::Delete,
            ])
        );
    }

    #[test]
    fn assignment_grant_store_is_idempotent_but_rejects_identity_mismatch() {
        let resource = process("process", "Guest/dev-vm", 7);
        let role = role();
        let mut registry = ControllerAssignmentRegistry::default();
        let lease = registry.admit(request(&resource, &role, 2, 3, 4)).unwrap();
        let grant = ControllerAssignmentGrant::from_lease(&lease);
        let expectation = ControllerAssignmentExpectation::new(
            role.provider_ref().clone(),
            role.role_ref().clone(),
            lease.target().clone(),
            lease.identity().provider_generation(),
            lease.identity().controller_generation(),
            lease.identity().session_generation(),
            grant.resource_types().clone(),
            grant.primary_verbs().clone(),
            grant.owner_child_process_verbs().clone(),
            grant.scopes().clone(),
        )
        .unwrap();
        let mut store = ControllerAssignmentGrantStore::new(expectation).unwrap();

        assert_eq!(
            store.accept(grant.clone()).unwrap(),
            GrantDisposition::Installed
        );
        assert_eq!(store.accept(grant).unwrap(), GrantDisposition::Duplicate);

        let mut stale = ControllerAssignmentGrant::decode(
            &ControllerAssignmentGrant::from_lease(&lease)
                .encode()
                .unwrap(),
        )
        .unwrap();
        stale.assignment.session.session_generation = ReconnectGeneration::new(5).unwrap();
        assert_eq!(
            store.accept(stale).unwrap_err(),
            AssignmentError::SessionBindingMismatch
        );
    }

    #[test]
    fn assignment_grant_store_binds_same_generation_to_exact_session_owner() {
        let first_resource = process("guest-process", "Guest/dev-vm", 7);
        let second_resource = process("guest-process-second", "Guest/dev-vm", 8);
        let role = role();
        let first_owner = ResourceRef::parse("Process/controller-first").unwrap();
        let second_owner = ResourceRef::parse("Process/controller-second").unwrap();
        let mut registry = ControllerAssignmentRegistry::default();
        let first_lease = registry
            .admit(request(&first_resource, &role, 2, 3, 1).with_session_owner(first_owner.clone()))
            .unwrap();
        let second_lease = registry
            .admit(request(&second_resource, &role, 2, 3, 1).with_session_owner(second_owner))
            .unwrap();
        let first_grant = ControllerAssignmentGrant::from_lease(&first_lease);
        let second_grant = ControllerAssignmentGrant::from_lease(&second_lease);
        let expectation = ControllerAssignmentExpectation::new(
            role.provider_ref().clone(),
            role.role_ref().clone(),
            first_lease.target().clone(),
            first_lease.identity().provider_generation(),
            first_lease.identity().controller_generation(),
            first_lease.identity().session_generation(),
            first_grant.resource_types().clone(),
            first_grant.primary_verbs().clone(),
            first_grant.owner_child_process_verbs().clone(),
            first_grant.scopes().clone(),
        )
        .unwrap()
        .with_session_owner(first_owner)
        .unwrap();
        let mut store = ControllerAssignmentGrantStore::new(expectation).unwrap();

        assert_eq!(
            store.accept(second_grant).unwrap_err(),
            AssignmentError::SessionBindingMismatch
        );
        assert_eq!(
            store.accept(first_grant).unwrap(),
            GrantDisposition::Installed
        );
    }

    #[test]
    fn assignment_grant_store_rejects_wrong_generation_target_epoch_and_widening() {
        let resource = process("process", "Guest/dev-vm", 7);
        let role = role();
        let mut registry = ControllerAssignmentRegistry::default();
        let lease = registry.admit(request(&resource, &role, 2, 3, 4)).unwrap();
        let grant = ControllerAssignmentGrant::from_lease(&lease);
        let expectation = ControllerAssignmentExpectation::new(
            role.provider_ref().clone(),
            role.role_ref().clone(),
            lease.target().clone(),
            lease.identity().provider_generation(),
            lease.identity().controller_generation(),
            lease.identity().session_generation(),
            grant.resource_types().clone(),
            grant.primary_verbs().clone(),
            grant.owner_child_process_verbs().clone(),
            grant.scopes().clone(),
        )
        .unwrap();

        let mut wrong_provider_generation =
            ControllerAssignmentGrantStore::new(expectation.clone()).unwrap();
        let mut forged = grant.clone();
        forged.assignment.session.provider_generation = ResourceGeneration::new(9).unwrap();
        assert_eq!(
            wrong_provider_generation.accept(forged).unwrap_err(),
            AssignmentError::ProviderGenerationMismatch
        );

        let mut wrong_controller_generation =
            ControllerAssignmentGrantStore::new(expectation.clone()).unwrap();
        let mut forged = grant.clone();
        forged.assignment.session.controller_generation = ControllerGeneration::new(9).unwrap();
        assert_eq!(
            wrong_controller_generation.accept(forged).unwrap_err(),
            AssignmentError::ControllerGenerationMismatch
        );

        let mut wrong_target = ControllerAssignmentGrantStore::new(expectation).unwrap();
        let mut forged = grant.clone();
        forged.assignment.session.target = AssignmentTarget::Execution {
            kind: d2b_contracts_resource::v3::PlacementTargetKind::Host,
            reference: ResourceRef::parse("Host/other").unwrap(),
        };
        assert_eq!(
            wrong_target.accept(forged).unwrap_err(),
            AssignmentError::TargetMismatch
        );

        let mut installed = ControllerAssignmentGrantStore::new(
            ControllerAssignmentExpectation::new_without_target(
                role.provider_ref().clone(),
                role.role_ref().clone(),
                lease.identity().provider_generation(),
                lease.identity().controller_generation(),
                lease.identity().session_generation(),
                grant.resource_types().clone(),
                grant.primary_verbs().clone(),
                grant.owner_child_process_verbs().clone(),
                grant.scopes().clone(),
            )
            .unwrap(),
        )
        .unwrap();
        installed.accept(grant.clone()).unwrap();
        let mut stale = grant.clone();
        stale.assignment.epoch = AssignmentEpoch::new(99).unwrap();
        assert_eq!(
            installed.accept(stale).unwrap_err(),
            AssignmentError::AssignmentConflict
        );
        let mut widened = grant.clone();
        widened
            .resource_types
            .insert(ResourceTypeName::parse("Host").unwrap());
        assert_eq!(
            installed.accept(widened).unwrap_err(),
            AssignmentError::QueryWidened
        );

        let mut widened_primary = grant.clone();
        widened_primary
            .primary_verbs
            .insert(AssignmentVerb::UpdateSpec);
        assert_eq!(
            ControllerAssignmentGrantStore::new(
                ControllerAssignmentExpectation::new_without_target(
                    role.provider_ref().clone(),
                    role.role_ref().clone(),
                    lease.identity().provider_generation(),
                    lease.identity().controller_generation(),
                    lease.identity().session_generation(),
                    grant.resource_types().clone(),
                    grant.primary_verbs().clone(),
                    grant.owner_child_process_verbs().clone(),
                    grant.scopes().clone(),
                )
                .unwrap(),
            )
            .unwrap()
            .accept(widened_primary)
            .unwrap_err(),
            AssignmentError::QueryWidened
        );

        let mut missing_owner_verb = grant.clone();
        missing_owner_verb
            .owner_child_process_verbs
            .remove(&AssignmentVerb::Delete);
        assert_eq!(
            ControllerAssignmentGrantStore::new(
                ControllerAssignmentExpectation::new_without_target(
                    role.provider_ref().clone(),
                    role.role_ref().clone(),
                    lease.identity().provider_generation(),
                    lease.identity().controller_generation(),
                    lease.identity().session_generation(),
                    grant.resource_types().clone(),
                    grant.primary_verbs().clone(),
                    grant.owner_child_process_verbs().clone(),
                    grant.scopes().clone(),
                )
                .unwrap(),
            )
            .unwrap()
            .accept(missing_owner_verb)
            .unwrap_err(),
            AssignmentError::QueryWidened
        );
    }

    #[test]
    fn assignment_grant_transport_rejects_oversized_and_reordered_payloads() {
        let resource = process("process", "Guest/dev-vm", 7);
        let role = role();
        let mut registry = ControllerAssignmentRegistry::default();
        let lease = registry.admit(request(&resource, &role, 2, 3, 4)).unwrap();
        let grant = ControllerAssignmentGrant::from_lease(&lease);
        assert_eq!(
            ControllerAssignmentGrant::decode(&vec![
                0;
                super::MAX_CONTROLLER_ASSIGNMENT_GRANT_BYTES
                    + 1
            ])
            .unwrap_err(),
            super::AssignmentTransportError::TooLarge
        );

        let mut value: serde_json::Value =
            serde_json::from_slice(&grant.encode().unwrap()).unwrap();
        value["primaryVerbs"].as_array_mut().unwrap().reverse();
        assert_eq!(
            ControllerAssignmentGrant::decode(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
            super::AssignmentTransportError::Malformed
        );
        let mut value: serde_json::Value =
            serde_json::from_slice(&grant.encode().unwrap()).unwrap();
        value["ownerChildProcessVerbs"]
            .as_array_mut()
            .unwrap()
            .reverse();
        let canonical = super::CanonicalJsonValue::parse(&serde_json::to_vec(&value).unwrap())
            .unwrap()
            .to_canonical_bytes();
        assert_eq!(
            ControllerAssignmentGrant::decode(&canonical).unwrap_err(),
            super::AssignmentTransportError::Malformed
        );
        let mut legacy: serde_json::Value =
            serde_json::from_slice(&grant.encode().unwrap()).unwrap();
        let primary = legacy
            .as_object_mut()
            .unwrap()
            .remove("primaryVerbs")
            .unwrap();
        legacy
            .as_object_mut()
            .unwrap()
            .insert("allowedVerbs".to_owned(), primary);
        assert_eq!(
            ControllerAssignmentGrant::decode(
                &super::CanonicalJsonValue::parse(&serde_json::to_vec(&legacy).unwrap())
                    .unwrap()
                    .to_canonical_bytes(),
            )
            .unwrap_err(),
            super::AssignmentTransportError::Malformed
        );

        let second = process("guest-process-second", "Guest/dev-vm", 8);
        let second_lease = registry.admit(request(&second, &role, 2, 3, 4)).unwrap();
        let first_grant = ControllerAssignmentGrant::from_lease(&lease);
        let second_grant = ControllerAssignmentGrant::from_lease(&second_lease);
        let expectation = ControllerAssignmentExpectation::new(
            role.provider_ref().clone(),
            role.role_ref().clone(),
            lease.target().clone(),
            lease.identity().provider_generation(),
            lease.identity().controller_generation(),
            lease.identity().session_generation(),
            first_grant.resource_types().clone(),
            first_grant.primary_verbs().clone(),
            first_grant.owner_child_process_verbs().clone(),
            first_grant.scopes().clone(),
        )
        .unwrap();
        let mut store = ControllerAssignmentGrantStore::new(expectation).unwrap();
        store.accept(second_grant).unwrap();
        assert_eq!(
            store.accept(first_grant).unwrap_err(),
            AssignmentError::StaleAssignment
        );
    }

    #[test]
    fn assignment_grant_revocation_preserves_observation_without_authority() {
        let resource = process("process", "Guest/dev-vm", 7);
        let replacement_resource = process("process", "Guest/dev-vm", 8);
        let role = role();
        let mut registry = ControllerAssignmentRegistry::default();
        let lease = registry.admit(request(&resource, &role, 2, 3, 4)).unwrap();
        let grant = ControllerAssignmentGrant::from_lease(&lease);
        let expectation = ControllerAssignmentExpectation::new_without_target(
            role.provider_ref().clone(),
            role.role_ref().clone(),
            lease.identity().provider_generation(),
            lease.identity().controller_generation(),
            lease.identity().session_generation(),
            grant.resource_types().clone(),
            grant.primary_verbs().clone(),
            grant.owner_child_process_verbs().clone(),
            grant.scopes().clone(),
        )
        .unwrap();
        let mut store = ControllerAssignmentGrantStore::new(expectation).unwrap();
        store.accept(grant.clone()).unwrap();
        let revocation =
            ControllerAssignmentGrant::encode_revocation(lease.provider_ref(), lease.identity())
                .unwrap();

        assert_eq!(
            store.accept_encoded(&revocation).unwrap(),
            GrantDisposition::Revoked
        );
        assert!(store.get(lease.identity().resource_uid()).is_none());
        assert_eq!(
            store.accept_encoded(&revocation).unwrap(),
            GrantDisposition::Duplicate
        );
        assert_eq!(
            store.accept(grant.clone()).unwrap_err(),
            AssignmentError::StaleAssignment
        );
        registry.revoke_assignment(lease.identity());
        let replacement = registry
            .admit(request(&replacement_resource, &role, 2, 3, 4))
            .unwrap();
        let replacement_grant = replacement.assignment_grant();
        assert_eq!(
            store.accept(replacement_grant.clone()).unwrap(),
            GrantDisposition::Installed
        );
        assert_eq!(
            store.accept(replacement_grant).unwrap(),
            GrantDisposition::Duplicate
        );
        assert!(store.get(replacement.identity().resource_uid()).is_some());
        assert_eq!(
            store.accept(grant).unwrap_err(),
            AssignmentError::StaleAssignment
        );
        store.revoke();
        assert!(!store.is_active());
        assert!(store.get(lease.identity().resource_uid()).is_none());
        assert_eq!(
            store.accept_encoded(&revocation).unwrap_err(),
            super::AssignmentGrantError::Assignment(AssignmentError::SessionRevoked)
        );
    }
}
