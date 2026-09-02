//! Owner reverse index, bounded propagation, and desired-child repair plans.

use std::collections::{BTreeMap, BTreeSet};

use d2b_contracts_resource::v3::{ResourceRef, ResourceUid, ZoneRevision};

use crate::{controller_assignment::OwnerChildScope, hints::HintTarget};

/// Maximum dependency references on one owned child.
pub const MAX_OWNER_CHILD_DEPENDENCIES: usize = 64;
/// Maximum related children in one atomic create batch.
pub const MAX_OWNER_CHILD_BATCH: usize = 128;

const MAX_OWNER_DEPENDENCIES: usize = MAX_OWNER_CHILD_DEPENDENCIES;
const MAX_OWNER_BATCH_CHILDREN: usize = MAX_OWNER_CHILD_BATCH;

/// Closed Process scheduling class used by Core-owned ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProcessSchedulingClass {
    /// A deletion or finalizer pass that must drain first.
    DeletionRequested,
    /// A normal workload Process or EphemeralProcess.
    Workload,
    /// A static Provider-controller Process.
    ProviderController,
}

impl ProcessSchedulingClass {
    /// Classify a Process without inspecting implementation-specific fields.
    pub const fn classify(deletion_requested: bool, provider_controller: bool) -> Self {
        if deletion_requested {
            Self::DeletionRequested
        } else if provider_controller {
            Self::ProviderController
        } else {
            Self::Workload
        }
    }

    /// Return the stable scheduling rank.
    pub const fn rank(self) -> u8 {
        match self {
            Self::DeletionRequested => 0,
            Self::Workload => 1,
            Self::ProviderController => 2,
        }
    }
}

/// Provider-neutral child kind used for deterministic Core ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OwnedChildKind {
    /// A generic leaf or an extension ResourceType.
    Other,
    /// A setup or backing Volume.
    Volume,
    /// A long-lived or ephemeral Process.
    Process,
    /// An Endpoint produced by another child.
    Endpoint,
}

impl OwnedChildKind {
    /// Infer the standard kind from a ResourceRef.
    pub fn from_resource_ref(target: &ResourceRef) -> Self {
        match target.resource_type().as_str() {
            "Volume" => Self::Volume,
            "Process" | "EphemeralProcess" => Self::Process,
            "Endpoint" => Self::Endpoint,
            _ => Self::Other,
        }
    }

    /// Return the stable dependency-first creation rank.
    pub const fn creation_rank(self) -> u8 {
        match self {
            Self::Other | Self::Volume => 0,
            Self::Process => 1,
            Self::Endpoint => 2,
        }
    }

    /// Return the stable dependent-first deletion rank.
    pub const fn deletion_rank(self) -> u8 {
        match self {
            Self::Other => 0,
            Self::Endpoint => 1,
            Self::Process => 2,
            Self::Volume => 3,
        }
    }
}

/// Canonical owner propagation limits supplied by the controller toolkit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerLimits {
    max_depth: usize,
    max_work_items: usize,
}

impl OwnerLimits {
    /// Bind the canonical toolkit limits without redefining them in Core.
    pub fn new(max_depth: usize, max_work_items: usize) -> Result<Self, OwnerGraphError> {
        if max_depth == 0 || max_work_items == 0 || max_depth > max_work_items {
            return Err(OwnerGraphError::InvalidLimits);
        }
        Ok(Self {
            max_depth,
            max_work_items,
        })
    }
}

/// One desired child body and digest.
#[derive(Clone, PartialEq, Eq)]
pub struct DesiredChild {
    target: ResourceRef,
    canonical_resource: Vec<u8>,
    payload_digest: String,
    kind: OwnedChildKind,
    dependencies: BTreeSet<ResourceRef>,
}

impl DesiredChild {
    /// Construct a desired child.
    pub fn new(
        target: ResourceRef,
        canonical_resource: Vec<u8>,
        payload_digest: impl Into<String>,
    ) -> Result<Self, OwnerReconcileError> {
        let payload_digest = payload_digest.into();
        if canonical_resource.is_empty() || payload_digest.is_empty() || payload_digest.len() > 128
        {
            return Err(OwnerReconcileError::InvalidChild);
        }
        let kind = OwnedChildKind::from_resource_ref(&target);
        Ok(Self {
            target,
            canonical_resource,
            payload_digest,
            kind,
            dependencies: BTreeSet::new(),
        })
    }

    /// Override the inferred standard kind for a generic child.
    pub const fn with_kind(mut self, kind: OwnedChildKind) -> Self {
        self.kind = kind;
        self
    }

    /// Attach UID-free dependency references used for ordering.
    pub fn with_dependencies(
        mut self,
        dependencies: impl IntoIterator<Item = ResourceRef>,
    ) -> Result<Self, OwnerReconcileError> {
        let dependencies = dependencies.into_iter().collect::<BTreeSet<_>>();
        if dependencies.len() > MAX_OWNER_DEPENDENCIES || dependencies.contains(&self.target) {
            return Err(OwnerReconcileError::InvalidChild);
        }
        self.dependencies = dependencies;
        Ok(self)
    }

    /// Construct a child with its standard kind and dependency edges.
    pub fn with_kind_and_dependencies(
        target: ResourceRef,
        canonical_resource: Vec<u8>,
        payload_digest: impl Into<String>,
        kind: OwnedChildKind,
        dependencies: impl IntoIterator<Item = ResourceRef>,
    ) -> Result<Self, OwnerReconcileError> {
        Self::new(target, canonical_resource, payload_digest)?
            .with_kind(kind)
            .with_dependencies(dependencies)
    }

    /// Borrow the target reference.
    pub const fn target(&self) -> &ResourceRef {
        &self.target
    }

    /// Borrow the canonical desired child body.
    pub fn canonical_resource(&self) -> &[u8] {
        &self.canonical_resource
    }

    /// Borrow the desired body digest.
    pub fn payload_digest(&self) -> &str {
        &self.payload_digest
    }

    /// Return the provider-neutral child kind.
    pub const fn kind(&self) -> OwnedChildKind {
        self.kind
    }

    /// Borrow dependency references used for deterministic ordering.
    pub fn dependencies(&self) -> &BTreeSet<ResourceRef> {
        &self.dependencies
    }
}

impl core::fmt::Debug for DesiredChild {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DesiredChild")
            .field("target_type", self.target.resource_type())
            .field(
                "canonical_resource",
                &format_args!("<{} bytes>", self.canonical_resource.len()),
            )
            .field("has_payload_digest", &true)
            .finish()
    }
}

/// Provider-neutral UID-free child intent accepted by Core.
pub type OwnedChildIntent = DesiredChild;

/// One complete observed child-index row.
#[derive(Clone, PartialEq, Eq)]
pub struct ObservedChild {
    target: HintTarget,
    revision: ZoneRevision,
    payload_digest: String,
    deletion_requested: bool,
    deletion_ready: bool,
    owner_ref: Option<ResourceRef>,
    owner_uid: Option<ResourceUid>,
    owner_generation: Option<d2b_contracts_resource::v3::ResourceGeneration>,
    generation: Option<d2b_contracts_resource::v3::ResourceGeneration>,
    kind: OwnedChildKind,
    dependencies: BTreeSet<ResourceRef>,
}

impl ObservedChild {
    /// Construct an observed index row.
    pub fn new(
        target: HintTarget,
        revision: ZoneRevision,
        payload_digest: impl Into<String>,
        deletion_requested: bool,
    ) -> Result<Self, OwnerReconcileError> {
        Self::with_deletion_state(target, revision, payload_digest, deletion_requested, false)
    }

    /// Construct an observed index row with the complete deletion state.
    pub fn with_deletion_state(
        target: HintTarget,
        revision: ZoneRevision,
        payload_digest: impl Into<String>,
        deletion_requested: bool,
        deletion_ready: bool,
    ) -> Result<Self, OwnerReconcileError> {
        let payload_digest = payload_digest.into();
        if revision.get() == 0
            || payload_digest.is_empty()
            || payload_digest.len() > 128
            || deletion_ready && !deletion_requested
        {
            return Err(OwnerReconcileError::InvalidChild);
        }
        let kind = OwnedChildKind::from_resource_ref(target.resource_ref());
        Ok(Self {
            kind,
            target,
            revision,
            payload_digest,
            deletion_requested,
            deletion_ready,
            owner_ref: None,
            owner_uid: None,
            owner_generation: None,
            generation: None,
            dependencies: BTreeSet::new(),
        })
    }

    /// Construct an observed child with the exact admitted owner identity.
    pub fn with_owner(
        target: HintTarget,
        owner: &HintTarget,
        owner_generation: d2b_contracts_resource::v3::ResourceGeneration,
        revision: ZoneRevision,
        payload_digest: impl Into<String>,
        deletion_requested: bool,
    ) -> Result<Self, OwnerReconcileError> {
        Self::with_owner_and_dependencies(
            target,
            owner,
            owner_generation,
            revision,
            payload_digest,
            deletion_requested,
            false,
            std::iter::empty(),
        )
    }

    /// Construct an observed child with owner identity and dependency edges.
    #[allow(clippy::too_many_arguments)]
    pub fn with_owner_and_dependencies(
        target: HintTarget,
        owner: &HintTarget,
        owner_generation: d2b_contracts_resource::v3::ResourceGeneration,
        revision: ZoneRevision,
        payload_digest: impl Into<String>,
        deletion_requested: bool,
        deletion_ready: bool,
        dependencies: impl IntoIterator<Item = ResourceRef>,
    ) -> Result<Self, OwnerReconcileError> {
        Self::with_owner_identity(
            target,
            owner.resource_ref().clone(),
            owner.uid().clone(),
            owner_generation,
            revision,
            payload_digest,
            deletion_requested,
            deletion_ready,
            dependencies,
        )
    }

    /// Construct an observed child from explicit owner identity values.
    #[allow(clippy::too_many_arguments)]
    pub fn with_owner_identity(
        target: HintTarget,
        owner_ref: ResourceRef,
        owner_uid: ResourceUid,
        owner_generation: d2b_contracts_resource::v3::ResourceGeneration,
        revision: ZoneRevision,
        payload_digest: impl Into<String>,
        deletion_requested: bool,
        deletion_ready: bool,
        dependencies: impl IntoIterator<Item = ResourceRef>,
    ) -> Result<Self, OwnerReconcileError> {
        let dependencies = dependencies.into_iter().collect::<BTreeSet<_>>();
        if dependencies.len() > MAX_OWNER_DEPENDENCIES
            || dependencies.contains(target.resource_ref())
        {
            return Err(OwnerReconcileError::InvalidChild);
        }
        let mut observed = Self::with_deletion_state(
            target,
            revision,
            payload_digest,
            deletion_requested,
            deletion_ready,
        )?;
        observed.owner_ref = Some(owner_ref);
        observed.owner_uid = Some(owner_uid);
        observed.owner_generation = Some(owner_generation);
        observed.dependencies = dependencies;
        Ok(observed)
    }

    /// Attach dependency references to an existing observation.
    pub fn with_dependencies(
        mut self,
        dependencies: impl IntoIterator<Item = ResourceRef>,
    ) -> Result<Self, OwnerReconcileError> {
        let dependencies = dependencies.into_iter().collect::<BTreeSet<_>>();
        if dependencies.len() > MAX_OWNER_DEPENDENCIES
            || dependencies.contains(self.target.resource_ref())
        {
            return Err(OwnerReconcileError::InvalidChild);
        }
        self.dependencies = dependencies;
        Ok(self)
    }

    /// Override the inferred standard kind for an observation.
    pub const fn with_kind(mut self, kind: OwnedChildKind) -> Self {
        self.kind = kind;
        self
    }

    /// Attach an observed child desired-state generation.
    pub const fn with_generation(
        mut self,
        generation: d2b_contracts_resource::v3::ResourceGeneration,
    ) -> Self {
        self.generation = Some(generation);
        self
    }

    /// Attach an observed owner reference when the owner UID is not in the
    /// Resource envelope.
    pub fn with_owner_ref(mut self, owner_ref: ResourceRef) -> Self {
        self.owner_ref = Some(owner_ref);
        self
    }

    /// Attach the observed owner UID used by exact stale-incarnation fencing.
    pub fn with_owner_uid(mut self, owner_uid: ResourceUid) -> Self {
        self.owner_uid = Some(owner_uid);
        self
    }

    /// Attach the observed owner generation used by exact fencing.
    pub const fn with_owner_generation(
        mut self,
        owner_generation: d2b_contracts_resource::v3::ResourceGeneration,
    ) -> Self {
        self.owner_generation = Some(owner_generation);
        self
    }

    /// Borrow the indexed target.
    pub const fn target(&self) -> &HintTarget {
        &self.target
    }

    /// Borrow the observed body digest.
    pub fn payload_digest(&self) -> &str {
        &self.payload_digest
    }

    /// Whether the Resource API has requested deletion for this child.
    pub const fn deletion_requested(&self) -> bool {
        self.deletion_requested
    }

    /// Whether the child has no remaining finalizers and can be physically
    /// deleted on the next exact mutation.
    pub const fn deletion_ready(&self) -> bool {
        self.deletion_ready
    }

    /// Borrow the observed singular owner reference, when supplied.
    pub fn owner_ref(&self) -> Option<&ResourceRef> {
        self.owner_ref.as_ref()
    }

    /// Borrow the observed owner UID, when supplied.
    pub fn owner_uid(&self) -> Option<&ResourceUid> {
        self.owner_uid.as_ref()
    }

    /// Return the observed owner generation, when supplied.
    pub const fn owner_generation(&self) -> Option<d2b_contracts_resource::v3::ResourceGeneration> {
        self.owner_generation
    }

    /// Return the observed child desired-state generation, when supplied.
    pub const fn generation(&self) -> Option<d2b_contracts_resource::v3::ResourceGeneration> {
        self.generation
    }

    /// Return the provider-neutral child kind.
    pub const fn kind(&self) -> OwnedChildKind {
        self.kind
    }

    /// Borrow dependency references used for deterministic ordering.
    pub fn dependencies(&self) -> &BTreeSet<ResourceRef> {
        &self.dependencies
    }
}

impl core::fmt::Debug for ObservedChild {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ObservedChild")
            .field("target", &self.target)
            .field("revision", &self.revision)
            .field("has_payload_digest", &true)
            .field("deletion_requested", &self.deletion_requested)
            .finish()
    }
}

/// One optimistic owner repair operation.
#[derive(Clone, PartialEq, Eq)]
pub enum OwnerMutation {
    Create {
        target: ResourceRef,
        canonical_resource: Vec<u8>,
    },
    Repair {
        target: ResourceRef,
        expected_uid: ResourceUid,
        expected_revision: ZoneRevision,
        canonical_resource: Vec<u8>,
    },
    RequestDeletion {
        target: ResourceRef,
        expected_uid: ResourceUid,
        expected_revision: ZoneRevision,
    },
    Delete {
        target: ResourceRef,
        expected_uid: ResourceUid,
        expected_revision: ZoneRevision,
    },
}

impl core::fmt::Debug for OwnerMutation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Create {
                target,
                canonical_resource,
            } => f
                .debug_struct("OwnerMutation::Create")
                .field("target_type", target.resource_type())
                .field(
                    "canonical_resource",
                    &format_args!("<{} bytes>", canonical_resource.len()),
                )
                .finish(),
            Self::Repair {
                target,
                expected_revision,
                canonical_resource,
                ..
            } => f
                .debug_struct("OwnerMutation::Repair")
                .field("target_type", target.resource_type())
                .field("has_expected_uid", &true)
                .field("expected_revision", expected_revision)
                .field(
                    "canonical_resource",
                    &format_args!("<{} bytes>", canonical_resource.len()),
                )
                .finish(),
            Self::RequestDeletion {
                target,
                expected_revision,
                ..
            } => f
                .debug_struct("OwnerMutation::RequestDeletion")
                .field("target_type", target.resource_type())
                .field("has_expected_uid", &true)
                .field("expected_revision", expected_revision)
                .finish(),
            Self::Delete {
                target,
                expected_revision,
                ..
            } => f
                .debug_struct("OwnerMutation::Delete")
                .field("target_type", target.resource_type())
                .field("has_expected_uid", &true)
                .field("expected_revision", expected_revision)
                .finish(),
        }
    }
}

/// Complete desired-vs-observed owner plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerReconcilePlan {
    owner: HintTarget,
    mutations: Vec<OwnerMutation>,
    pending: bool,
    creation_order: Vec<ResourceRef>,
    deletion_order: Vec<ResourceRef>,
    create_batch: Option<OwnerChildBatch>,
}

impl OwnerReconcilePlan {
    /// Borrow the owner incarnation this plan addresses.
    pub const fn owner(&self) -> &HintTarget {
        &self.owner
    }

    /// Borrow optimistic operations.
    pub fn mutations(&self) -> &[OwnerMutation] {
        &self.mutations
    }

    /// Borrow deterministic dependency-first creation order.
    pub fn creation_order(&self) -> &[ResourceRef] {
        &self.creation_order
    }

    /// Alias for callers that name the operation a create order.
    pub fn create_order(&self) -> &[ResourceRef] {
        self.creation_order()
    }

    /// Borrow deterministic dependent-first deletion order.
    pub fn deletion_order(&self) -> &[ResourceRef] {
        &self.deletion_order
    }

    /// Alias for callers that name the operation a delete order.
    pub fn teardown_order(&self) -> &[ResourceRef] {
        self.deletion_order()
    }

    /// Borrow the bounded UID-free create batch, when creates are pending.
    pub const fn create_batch(&self) -> Option<&OwnerChildBatch> {
        self.create_batch.as_ref()
    }

    /// Alias for callers that refer to the related-resource operation as a
    /// CommitBatch.
    pub const fn batch(&self) -> Option<&OwnerChildBatch> {
        self.create_batch()
    }

    /// Borrow the teardown projection for this plan.
    pub fn teardown_plan(&self) -> TeardownPlan {
        TeardownPlan {
            order: self.deletion_order.clone(),
        }
    }

    /// Return the deterministic creation rank for one child reference.
    pub fn creation_rank(&self, target: &ResourceRef) -> Option<usize> {
        self.creation_order
            .iter()
            .position(|candidate| candidate == target)
    }

    /// Return the deterministic deletion rank for one child reference.
    pub fn deletion_rank(&self, target: &ResourceRef) -> Option<usize> {
        self.deletion_order
            .iter()
            .position(|candidate| candidate == target)
    }

    /// Whether the complete child set is converged.
    pub fn is_converged(&self) -> bool {
        self.mutations.is_empty() && !self.pending
    }
}

/// A bounded, UID-free related-child create batch.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnerChildBatch {
    owner: HintTarget,
    owner_generation: d2b_contracts_resource::v3::ResourceGeneration,
    children: Vec<DesiredChild>,
    refs: Vec<ResourceRef>,
}

impl OwnerChildBatch {
    /// Construct a deterministic batch from UID-free desired children.
    pub fn new(
        owner: HintTarget,
        owner_generation: d2b_contracts_resource::v3::ResourceGeneration,
        children: impl IntoIterator<Item = DesiredChild>,
    ) -> Result<Self, OwnerReconcileError> {
        let mut children = children.into_iter().collect::<Vec<_>>();
        if children.is_empty() || children.len() > MAX_OWNER_BATCH_CHILDREN {
            return Err(OwnerReconcileError::InvalidBatch);
        }
        for child in &children {
            if child.target() == owner.resource_ref() {
                return Err(OwnerReconcileError::InvalidChild);
            }
            validate_desired_child(&owner, child)?;
        }
        let mut by_ref = BTreeMap::new();
        for child in children {
            if by_ref.insert(child.target().clone(), child).is_some() {
                return Err(OwnerReconcileError::DuplicateChild);
            }
        }
        children = ordered_desired_children(by_ref)?;
        let refs = children
            .iter()
            .map(|child| child.target().clone())
            .collect::<Vec<_>>();
        Ok(Self {
            owner,
            owner_generation,
            children,
            refs,
        })
    }

    /// Borrow the exact owner incarnation for this batch.
    pub const fn owner(&self) -> &HintTarget {
        &self.owner
    }

    /// Return owner generation captured for uncertain-response fencing.
    pub const fn owner_generation(&self) -> d2b_contracts_resource::v3::ResourceGeneration {
        self.owner_generation
    }

    /// Borrow children in deterministic dependency-first order.
    pub fn children(&self) -> &[DesiredChild] {
        &self.children
    }

    /// Borrow child ResourceRefs in batch order.
    pub fn refs(&self) -> &[ResourceRef] {
        &self.refs
    }

    /// Borrow the batch addresses under Resource API terminology.
    pub fn resource_refs(&self) -> &[ResourceRef] {
        &self.refs
    }

    /// Return whether the batch has no children.
    pub const fn is_empty(&self) -> bool {
        self.children.is_empty()
    }

    /// Return the number of child creates in the batch.
    pub const fn len(&self) -> usize {
        self.children.len()
    }

    /// Resolve one CommitBatch result against this exact batch.
    pub fn resolve(
        &self,
        result: &OwnerBatchResult,
        relisted: &[ObservedChild],
    ) -> Result<OwnerBatchRecovery, OwnerReconcileError> {
        result.resolve(self, relisted)
    }
}

impl core::fmt::Debug for OwnerChildBatch {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("OwnerChildBatch")
            .field("child_count", &self.children.len())
            .finish_non_exhaustive()
    }
}

/// One Resource API identity returned for a committed child create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerChildIdentity {
    target: ResourceRef,
    uid: ResourceUid,
    revision: ZoneRevision,
}

impl OwnerChildIdentity {
    /// Construct one returned child identity.
    pub fn new(target: ResourceRef, uid: ResourceUid, revision: ZoneRevision) -> Self {
        Self {
            target,
            uid,
            revision,
        }
    }

    /// Borrow the returned child ResourceRef.
    pub const fn target(&self) -> &ResourceRef {
        &self.target
    }

    /// Borrow the returned child ResourceRef under its API name.
    pub const fn resource_ref(&self) -> &ResourceRef {
        &self.target
    }

    /// Borrow the store-assigned child UID.
    pub const fn uid(&self) -> &ResourceUid {
        &self.uid
    }

    /// Return the durable child revision.
    pub const fn revision(&self) -> ZoneRevision {
        self.revision
    }
}

impl From<(ResourceRef, ResourceUid)> for OwnerChildIdentity {
    fn from((target, uid): (ResourceRef, ResourceUid)) -> Self {
        Self::new(target, uid, ZoneRevision::new(1))
    }
}

impl From<(ResourceRef, ResourceUid, ZoneRevision)> for OwnerChildIdentity {
    fn from((target, uid, revision): (ResourceRef, ResourceUid, ZoneRevision)) -> Self {
        Self::new(target, uid, revision)
    }
}

/// Pure result of a related-child CommitBatch call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnerBatchResult {
    /// The Resource API durably committed the complete batch.
    Committed(Vec<OwnerChildIdentity>),
    /// The transport outcome is unknown and requires a deterministic relist.
    Uncertain,
}

impl OwnerBatchResult {
    /// Construct a committed result from the returned UID/revision mapping.
    pub fn committed(identities: impl IntoIterator<Item = impl Into<OwnerChildIdentity>>) -> Self {
        Self::Committed(identities.into_iter().map(Into::into).collect())
    }

    /// Construct a committed result from a UID-only map.
    pub fn committed_uids(
        identities: impl IntoIterator<Item = (ResourceRef, ResourceUid)>,
    ) -> Self {
        Self::committed(identities)
    }

    /// Construct an uncertain post-dispatch result.
    pub const fn uncertain() -> Self {
        Self::Uncertain
    }

    /// Whether the response must be repaired by relisting.
    pub const fn is_uncertain(&self) -> bool {
        matches!(self, Self::Uncertain)
    }

    /// Whether the Resource API returned a complete committed mapping.
    pub const fn is_committed(&self) -> bool {
        matches!(self, Self::Committed(_))
    }

    /// Borrow returned identities for a committed response.
    pub fn identities(&self) -> &[OwnerChildIdentity] {
        match self {
            Self::Committed(identities) => identities,
            Self::Uncertain => &[],
        }
    }

    /// Resolve a response against one exact batch and, when uncertain, its
    /// complete deterministic relist.
    pub fn resolve(
        &self,
        batch: &OwnerChildBatch,
        relisted: &[ObservedChild],
    ) -> Result<OwnerBatchRecovery, OwnerReconcileError> {
        match self {
            Self::Committed(identities) => {
                validate_batch_identities(batch, identities)?;
                let mut identities = identities.clone();
                identities.sort_by(|left, right| left.target.cmp(&right.target));
                Ok(OwnerBatchRecovery {
                    identities,
                    was_relisted: false,
                })
            }
            Self::Uncertain => {
                if relisted.len() != batch.len() {
                    return Err(OwnerReconcileError::BatchIncomplete);
                }
                let mut identities = Vec::with_capacity(relisted.len());
                let expected = batch.refs().iter().collect::<BTreeSet<_>>();
                let mut seen = BTreeSet::new();
                for child in relisted {
                    validate_observed_owner(
                        batch.owner(),
                        child,
                        true,
                        Some(batch.owner_generation()),
                    )?;
                    if !expected.contains(child.target().resource_ref()) {
                        return Err(OwnerReconcileError::BatchUnexpected);
                    }
                    if !seen.insert(child.target().resource_ref().clone()) {
                        return Err(OwnerReconcileError::BatchDuplicate);
                    }
                    identities.push(OwnerChildIdentity::new(
                        child.target().resource_ref().clone(),
                        child.target().uid().clone(),
                        child.revision,
                    ));
                }
                if seen.len() != expected.len() {
                    return Err(OwnerReconcileError::BatchIncomplete);
                }
                identities.sort_by(|left, right| left.target.cmp(&right.target));
                Ok(OwnerBatchRecovery {
                    identities,
                    was_relisted: true,
                })
            }
        }
    }
}

/// Validated mapping of one batch to its committed child incarnations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerBatchRecovery {
    identities: Vec<OwnerChildIdentity>,
    was_relisted: bool,
}

impl OwnerBatchRecovery {
    /// Borrow all identities in deterministic ResourceRef order.
    pub fn identities(&self) -> &[OwnerChildIdentity] {
        &self.identities
    }

    /// Whether the mapping came from an uncertain-response relist.
    pub const fn was_relisted(&self) -> bool {
        self.was_relisted
    }

    /// Resolve one child UID from the recovered mapping.
    pub fn uid(&self, target: &ResourceRef) -> Option<&ResourceUid> {
        self.identities
            .iter()
            .find(|identity| &identity.target == target)
            .map(|identity| &identity.uid)
    }

    /// Return the complete recovered UID mapping.
    pub fn uids(&self) -> BTreeMap<ResourceRef, ResourceUid> {
        self.identities
            .iter()
            .map(|identity| (identity.target.clone(), identity.uid.clone()))
            .collect()
    }

    /// Resolve one child revision from the recovered mapping.
    pub fn revision(&self, target: &ResourceRef) -> Option<ZoneRevision> {
        self.identities
            .iter()
            .find(|identity| &identity.target == target)
            .map(OwnerChildIdentity::revision)
    }
}

/// Bounded child-first teardown order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeardownPlan {
    order: Vec<ResourceRef>,
}

impl TeardownPlan {
    /// Borrow the dependent-first deletion order.
    pub fn order(&self) -> &[ResourceRef] {
        &self.order
    }

    /// Borrow the order under its ResourceRef terminology.
    pub fn refs(&self) -> &[ResourceRef] {
        &self.order
    }

    /// Borrow the resources in child-first order.
    pub fn resources(&self) -> &[ResourceRef] {
        &self.order
    }

    /// Return the number of resources in the plan.
    pub const fn len(&self) -> usize {
        self.order.len()
    }

    /// Whether the plan is empty.
    pub const fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

/// Complete owner index, replaced only by an authoritative relist.
pub struct OwnerIndex {
    limits: OwnerLimits,
    children: BTreeMap<HintTarget, BTreeMap<ResourceRef, ObservedChild>>,
    owner_generations: BTreeMap<HintTarget, d2b_contracts_resource::v3::ResourceGeneration>,
    owner_revisions: BTreeMap<HintTarget, ZoneRevision>,
}

impl OwnerIndex {
    /// Construct an index bound by toolkit-owned limits.
    pub fn new(limits: OwnerLimits) -> Self {
        Self {
            limits,
            children: BTreeMap::new(),
            owner_generations: BTreeMap::new(),
            owner_revisions: BTreeMap::new(),
        }
    }

    /// Replace one owner's complete child set.
    pub fn relist(
        &mut self,
        owner: HintTarget,
        observed: Vec<ObservedChild>,
    ) -> Result<(), OwnerReconcileError> {
        self.relist_inner(owner, None, None, observed, false)
    }

    /// Replace an owner's complete relist while requiring its generation.
    pub fn relist_with_owner_generation(
        &mut self,
        owner: HintTarget,
        owner_generation: d2b_contracts_resource::v3::ResourceGeneration,
        observed: Vec<ObservedChild>,
    ) -> Result<(), OwnerReconcileError> {
        self.relist_inner(owner, Some(owner_generation), None, observed, true)
    }

    /// Replace a relist after validating the exact U10 owner-child admission.
    pub fn relist_for_admission(
        &mut self,
        owner: HintTarget,
        scope: &OwnerChildScope,
        observed: Vec<ObservedChild>,
    ) -> Result<(), OwnerReconcileError> {
        if scope.owner_ref() != owner.resource_ref() || scope.owner_uid() != owner.uid() {
            return Err(OwnerReconcileError::StaleOwner);
        }
        self.relist_inner(
            owner,
            Some(scope.owner_generation()),
            Some(scope.owner_revision()),
            observed,
            true,
        )
    }

    fn relist_inner(
        &mut self,
        owner: HintTarget,
        owner_generation: Option<d2b_contracts_resource::v3::ResourceGeneration>,
        owner_revision: Option<ZoneRevision>,
        observed: Vec<ObservedChild>,
        require_owner_identity: bool,
    ) -> Result<(), OwnerReconcileError> {
        if observed.len() > self.limits.max_work_items
            || owner_generation.is_some_and(|generation| generation.get() == 0)
            || owner_revision.is_some_and(|revision| revision.get() == 0)
        {
            return Err(OwnerReconcileError::InvalidChild);
        }
        let expected_generation =
            owner_generation.or_else(|| self.owner_generations.get(&owner).copied());
        let require_owner_identity = require_owner_identity || expected_generation.is_some();
        let mut indexed = BTreeMap::new();
        for child in observed {
            validate_observed_owner(&owner, &child, require_owner_identity, expected_generation)?;
            let child_ref = child.target.resource_ref().clone();
            if indexed.insert(child_ref, child).is_some() {
                return Err(OwnerReconcileError::DuplicateChild);
            }
        }
        if let Some(generation) = owner_generation {
            self.owner_generations.insert(owner.clone(), generation);
            if owner_revision.is_none() {
                self.owner_revisions.remove(&owner);
            }
        }
        if let Some(revision) = owner_revision {
            self.owner_revisions.insert(owner.clone(), revision);
        }
        self.children.insert(owner, indexed);
        Ok(())
    }

    /// Compare complete desired children with the latest relist.
    pub fn plan(
        &self,
        owner: &HintTarget,
        desired: Vec<DesiredChild>,
    ) -> Result<OwnerReconcilePlan, OwnerReconcileError> {
        if desired.len() > self.limits.max_work_items {
            return Err(OwnerReconcileError::TooManyChildren);
        }
        let mut desired_by_ref = BTreeMap::new();
        for child in desired {
            if &child.target == owner.resource_ref() {
                return Err(OwnerReconcileError::InvalidChild);
            }
            validate_desired_child(owner, &child)?;
            if desired_by_ref.insert(child.target.clone(), child).is_some() {
                return Err(OwnerReconcileError::DuplicateChild);
            }
        }
        let observed = self
            .children
            .get(owner)
            .cloned()
            .ok_or(OwnerReconcileError::OwnerNotRelisted)?;
        let mut mutations = Vec::new();
        let mut create_children = Vec::new();
        let mut pending = false;
        for (target, desired) in &desired_by_ref {
            match observed.get(target) {
                None => {
                    create_children.push(desired.clone());
                    mutations.push(OwnerMutation::Create {
                        target: target.clone(),
                        canonical_resource: desired.canonical_resource.clone(),
                    });
                }
                Some(actual) if actual.deletion_requested => {
                    // A deleting child cannot be recreated in place. Wait for
                    // the next authoritative relist before declaring the
                    // owner converged.
                    pending = true;
                }
                Some(actual) if actual.payload_digest != desired.payload_digest => {
                    mutations.push(OwnerMutation::Repair {
                        target: target.clone(),
                        expected_uid: actual.target.uid().clone(),
                        expected_revision: actual.revision,
                        canonical_resource: desired.canonical_resource.clone(),
                    });
                }
                Some(_) => {}
            }
        }
        for (target, actual) in &observed {
            if !desired_by_ref.contains_key(target) && !actual.deletion_requested {
                mutations.push(OwnerMutation::RequestDeletion {
                    target: target.clone(),
                    expected_uid: actual.target.uid().clone(),
                    expected_revision: actual.revision,
                });
            } else if !desired_by_ref.contains_key(target) {
                if actual.deletion_ready() {
                    mutations.push(OwnerMutation::Delete {
                        target: target.clone(),
                        expected_uid: actual.target.uid().clone(),
                        expected_revision: actual.revision,
                    });
                } else {
                    pending = true;
                }
            }
        }
        let creation_order = ordered_desired_refs(
            &desired_by_ref,
            self.limits.max_work_items,
            self.limits.max_depth,
        )?;
        let deletion_order = ordered_observed_refs(
            &observed,
            desired_by_ref.keys(),
            self.limits.max_work_items,
            self.limits.max_depth,
        )?;
        let creation_positions = creation_order
            .iter()
            .enumerate()
            .map(|(index, target)| (target.clone(), index))
            .collect::<BTreeMap<_, _>>();
        let deletion_positions = deletion_order
            .iter()
            .enumerate()
            .map(|(index, target)| (target.clone(), index))
            .collect::<BTreeMap<_, _>>();
        mutations.sort_by_key(|mutation| {
            let (target, deleting, kind) =
                mutation_sort_parts(mutation, &desired_by_ref, &observed);
            let position = if deleting {
                deletion_positions
                    .get(target)
                    .copied()
                    .unwrap_or(usize::MAX)
            } else {
                creation_positions
                    .get(target)
                    .copied()
                    .unwrap_or(usize::MAX)
            };
            (
                deleting,
                position,
                if deleting {
                    kind.deletion_rank()
                } else {
                    kind.creation_rank()
                },
                target.clone(),
            )
        });
        let create_batch = if create_children.is_empty() {
            None
        } else {
            let owner_generation = self
                .owner_generations
                .get(owner)
                .copied()
                .ok_or(OwnerReconcileError::OwnerIdentityMissing)?;
            Some(OwnerChildBatch::new(
                owner.clone(),
                owner_generation,
                create_children,
            )?)
        };
        Ok(OwnerReconcilePlan {
            owner: owner.clone(),
            mutations,
            pending,
            creation_order,
            deletion_order,
            create_batch,
        })
    }

    /// Plan a complete UID-free child intent set.
    pub fn plan_intents(
        &self,
        owner: &HintTarget,
        desired: impl IntoIterator<Item = OwnedChildIntent>,
    ) -> Result<OwnerReconcilePlan, OwnerReconcileError> {
        self.plan(owner, desired.into_iter().collect())
    }

    /// Return the pending atomic UID-free create batch for an owner.
    pub fn plan_batch(
        &self,
        owner: &HintTarget,
        desired: impl IntoIterator<Item = OwnedChildIntent>,
    ) -> Result<Option<OwnerChildBatch>, OwnerReconcileError> {
        Ok(self.plan_intents(owner, desired)?.create_batch().cloned())
    }

    /// Validate a plan against an admitted owner-child identity.
    pub fn plan_for_admission(
        &self,
        owner: &HintTarget,
        scope: &OwnerChildScope,
        desired: Vec<DesiredChild>,
    ) -> Result<OwnerReconcilePlan, OwnerReconcileError> {
        if scope.owner_ref() != owner.resource_ref() || scope.owner_uid() != owner.uid() {
            return Err(OwnerReconcileError::StaleOwner);
        }
        if self.owner_revisions.get(owner) != Some(&scope.owner_revision()) {
            return Err(OwnerReconcileError::StaleRevision);
        }
        if self.owner_generations.get(owner) != Some(&scope.owner_generation()) {
            return Err(OwnerReconcileError::StaleGeneration);
        }
        self.plan(owner, desired)
    }

    /// Resolve an uncertain batch and install its complete relist atomically.
    pub fn recover_batch(
        &mut self,
        batch: &OwnerChildBatch,
        result: &OwnerBatchResult,
        relisted: &[ObservedChild],
    ) -> Result<OwnerBatchRecovery, OwnerReconcileError> {
        let recovery = result.resolve(batch, relisted)?;
        if result.is_uncertain() {
            let mut merged = self
                .children
                .get(batch.owner())
                .cloned()
                .ok_or(OwnerReconcileError::OwnerNotRelisted)?;
            for child in relisted {
                merged.insert(child.target().resource_ref().clone(), child.clone());
            }
            self.relist(batch.owner.clone(), merged.into_values().collect())?;
        }
        Ok(recovery)
    }

    /// Return the bounded child-first teardown projection.
    pub fn teardown_plan(&self, owner: &HintTarget) -> Result<TeardownPlan, OwnerReconcileError> {
        Ok(self.plan(owner, Vec::new())?.teardown_plan())
    }

    /// Number of children in the latest complete relist.
    pub fn child_count(&self, owner: &HintTarget) -> usize {
        self.children.get(owner).map_or(0, BTreeMap::len)
    }

    /// Return the owner generation captured by the latest strict relist.
    pub fn owner_generation(
        &self,
        owner: &HintTarget,
    ) -> Option<d2b_contracts_resource::v3::ResourceGeneration> {
        self.owner_generations.get(owner).copied()
    }

    /// Return the owner revision captured by the latest admitted relist.
    pub fn owner_revision(&self, owner: &HintTarget) -> Option<ZoneRevision> {
        self.owner_revisions.get(owner).copied()
    }
}

fn validate_desired_child(
    owner: &HintTarget,
    child: &DesiredChild,
) -> Result<(), OwnerReconcileError> {
    let value = d2b_contracts_resource::v3::CanonicalJsonValue::parse(child.canonical_resource())
        .map_err(|_| OwnerReconcileError::InvalidChild)?;
    let d2b_contracts_resource::v3::CanonicalJsonValue::Object(root) = value else {
        return Err(OwnerReconcileError::InvalidChild);
    };
    if let Some(resource_type) = root.get("type")
        && resource_type
            != &d2b_contracts_resource::v3::CanonicalJsonValue::String(
                child.target().resource_type().to_canonical_string(),
            )
    {
        return Err(OwnerReconcileError::IdentityMismatch);
    }
    let Some(metadata) = root.get("metadata") else {
        return Ok(());
    };
    let d2b_contracts_resource::v3::CanonicalJsonValue::Object(metadata) = metadata else {
        return Err(OwnerReconcileError::InvalidChild);
    };
    if let Some(zone) = metadata.get("zone")
        && zone
            != &d2b_contracts_resource::v3::CanonicalJsonValue::String(
                owner.zone().as_str().to_owned(),
            )
    {
        return Err(OwnerReconcileError::CrossZone);
    }
    if let Some(owner_ref) = metadata.get("ownerRef")
        && owner_ref
            != &d2b_contracts_resource::v3::CanonicalJsonValue::String(
                owner.resource_ref().to_canonical_string(),
            )
    {
        return Err(OwnerReconcileError::ForeignOwner);
    }
    if let Some(uid) = metadata.get("uid")
        && !matches!(uid, d2b_contracts_resource::v3::CanonicalJsonValue::Null)
    {
        return Err(OwnerReconcileError::UidInDesiredChild);
    }
    if let Some(name) = metadata.get("name")
        && name
            != &d2b_contracts_resource::v3::CanonicalJsonValue::String(
                child.target().name().as_str().to_owned(),
            )
    {
        return Err(OwnerReconcileError::IdentityMismatch);
    }
    Ok(())
}

fn validate_observed_owner(
    owner: &HintTarget,
    child: &ObservedChild,
    require_owner_identity: bool,
    owner_generation: Option<d2b_contracts_resource::v3::ResourceGeneration>,
) -> Result<(), OwnerReconcileError> {
    if child.target.zone() != owner.zone() {
        return Err(OwnerReconcileError::CrossZone);
    }
    if child.target.resource_ref() == owner.resource_ref() {
        return Err(OwnerReconcileError::InvalidChild);
    }
    if require_owner_identity
        && (child.owner_ref.is_none()
            || child.owner_uid.is_none()
            || child.owner_generation.is_none())
    {
        return Err(OwnerReconcileError::OwnerIdentityMissing);
    }
    if child
        .owner_ref
        .as_ref()
        .is_some_and(|owner_ref| owner_ref != owner.resource_ref())
    {
        return Err(OwnerReconcileError::ForeignOwner);
    }
    if child
        .owner_uid
        .as_ref()
        .is_some_and(|owner_uid| owner_uid != owner.uid())
    {
        return Err(OwnerReconcileError::StaleOwner);
    }
    if let Some(expected) = owner_generation {
        match child.owner_generation {
            Some(observed) if observed != expected => {
                return Err(OwnerReconcileError::StaleGeneration);
            }
            None => return Err(OwnerReconcileError::OwnerIdentityMissing),
            Some(_) => {}
        }
    }
    if child
        .dependencies
        .iter()
        .any(|dependency| dependency == child.target.resource_ref())
    {
        return Err(OwnerReconcileError::InvalidChild);
    }
    Ok(())
}

fn validate_batch_identities(
    batch: &OwnerChildBatch,
    identities: &[OwnerChildIdentity],
) -> Result<(), OwnerReconcileError> {
    if identities.len() != batch.len() {
        return Err(OwnerReconcileError::BatchIncomplete);
    }
    let expected = batch.refs().iter().collect::<BTreeSet<_>>();
    let mut seen_refs = BTreeSet::new();
    let mut seen_uids = BTreeSet::new();
    for identity in identities {
        if identity.revision.get() == 0 {
            return Err(OwnerReconcileError::InvalidRevision);
        }
        if !expected.contains(&identity.target) {
            return Err(OwnerReconcileError::BatchUnexpected);
        }
        if !seen_refs.insert(identity.target.clone()) {
            return Err(OwnerReconcileError::BatchDuplicate);
        }
        if !seen_uids.insert(identity.uid.clone()) {
            return Err(OwnerReconcileError::BatchIdentityConflict);
        }
    }
    Ok(())
}

fn ordered_desired_children(
    desired: BTreeMap<ResourceRef, DesiredChild>,
) -> Result<Vec<DesiredChild>, OwnerReconcileError> {
    let order = ordered_desired_refs(&desired, MAX_OWNER_BATCH_CHILDREN, MAX_OWNER_BATCH_CHILDREN)?;
    order
        .into_iter()
        .map(|target| {
            desired
                .get(&target)
                .cloned()
                .ok_or(OwnerReconcileError::InvalidChild)
        })
        .collect()
}

fn ordered_desired_refs(
    desired: &BTreeMap<ResourceRef, DesiredChild>,
    max_items: usize,
    max_depth: usize,
) -> Result<Vec<ResourceRef>, OwnerReconcileError> {
    let nodes = desired
        .iter()
        .map(|(target, child)| (target.clone(), (child.kind, child.dependencies.clone())))
        .collect::<BTreeMap<_, _>>();
    topological_order(nodes, false, max_items, max_depth)
}

fn ordered_observed_refs<'a>(
    observed: &BTreeMap<ResourceRef, ObservedChild>,
    desired: impl Iterator<Item = &'a ResourceRef>,
    max_items: usize,
    max_depth: usize,
) -> Result<Vec<ResourceRef>, OwnerReconcileError> {
    let desired = desired.cloned().collect::<BTreeSet<_>>();
    let nodes = observed
        .iter()
        .filter(|(target, _)| !desired.contains(*target))
        .map(|(target, child)| (target.clone(), (child.kind, child.dependencies.clone())))
        .collect::<BTreeMap<_, _>>();
    topological_order(nodes, true, max_items, max_depth)
}

fn topological_order(
    nodes: BTreeMap<ResourceRef, (OwnedChildKind, BTreeSet<ResourceRef>)>,
    deleting: bool,
    max_items: usize,
    max_depth: usize,
) -> Result<Vec<ResourceRef>, OwnerReconcileError> {
    if nodes.len() > max_items {
        return Err(OwnerReconcileError::TooManyChildren);
    }
    if max_depth == 0 {
        return Err(OwnerReconcileError::DependencyDepthExceeded);
    }
    let mut ordered = Vec::with_capacity(nodes.len());
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let mut candidates = nodes.keys().cloned().collect::<Vec<_>>();
    candidates.sort_by_key(|target| {
        let kind = nodes
            .get(target)
            .map(|(kind, _)| *kind)
            .unwrap_or(OwnedChildKind::Other);
        if deleting {
            (kind.deletion_rank(), target.clone())
        } else {
            (kind.creation_rank(), target.clone())
        }
    });
    for target in candidates {
        if deleting {
            visit_deletion(
                &target,
                &nodes,
                &mut visiting,
                &mut visited,
                &mut ordered,
                1,
                max_depth,
            )?;
        } else {
            visit_creation(
                &target,
                &nodes,
                &mut visiting,
                &mut visited,
                &mut ordered,
                1,
                max_depth,
            )?;
        }
    }
    Ok(ordered)
}

fn visit_creation(
    target: &ResourceRef,
    nodes: &BTreeMap<ResourceRef, (OwnedChildKind, BTreeSet<ResourceRef>)>,
    visiting: &mut BTreeSet<ResourceRef>,
    visited: &mut BTreeSet<ResourceRef>,
    ordered: &mut Vec<ResourceRef>,
    depth: usize,
    max_depth: usize,
) -> Result<(), OwnerReconcileError> {
    if visited.contains(target) {
        return Ok(());
    }
    if !visiting.insert(target.clone()) {
        return Err(OwnerReconcileError::DependencyCycle);
    }
    if depth > max_depth {
        return Err(OwnerReconcileError::DependencyDepthExceeded);
    }
    if let Some((_, dependencies)) = nodes.get(target) {
        let mut dependencies = dependencies
            .iter()
            .filter(|dependency| nodes.contains_key(*dependency))
            .cloned()
            .collect::<Vec<_>>();
        dependencies.sort_by_key(|dependency| {
            let kind = nodes
                .get(dependency)
                .map(|(kind, _)| *kind)
                .unwrap_or(OwnedChildKind::Other);
            (kind.creation_rank(), dependency.clone())
        });
        for dependency in dependencies {
            visit_creation(
                &dependency,
                nodes,
                visiting,
                visited,
                ordered,
                depth + 1,
                max_depth,
            )?;
        }
    }
    visiting.remove(target);
    visited.insert(target.clone());
    ordered.push(target.clone());
    Ok(())
}

fn visit_deletion(
    target: &ResourceRef,
    nodes: &BTreeMap<ResourceRef, (OwnedChildKind, BTreeSet<ResourceRef>)>,
    visiting: &mut BTreeSet<ResourceRef>,
    visited: &mut BTreeSet<ResourceRef>,
    ordered: &mut Vec<ResourceRef>,
    depth: usize,
    max_depth: usize,
) -> Result<(), OwnerReconcileError> {
    if visited.contains(target) {
        return Ok(());
    }
    if !visiting.insert(target.clone()) {
        return Err(OwnerReconcileError::DependencyCycle);
    }
    if depth > max_depth {
        return Err(OwnerReconcileError::DependencyDepthExceeded);
    }
    let mut dependents = nodes
        .iter()
        .filter(|(_, (_, dependencies))| dependencies.contains(target))
        .map(|(dependent, (kind, _))| (dependent.clone(), *kind))
        .collect::<Vec<_>>();
    dependents.sort_by_key(|(dependent, kind)| (kind.deletion_rank(), dependent.clone()));
    for (dependent, _) in dependents {
        visit_deletion(
            &dependent,
            nodes,
            visiting,
            visited,
            ordered,
            depth + 1,
            max_depth,
        )?;
    }
    visiting.remove(target);
    visited.insert(target.clone());
    ordered.push(target.clone());
    Ok(())
}

fn mutation_sort_parts<'a>(
    mutation: &'a OwnerMutation,
    desired: &'a BTreeMap<ResourceRef, DesiredChild>,
    observed: &'a BTreeMap<ResourceRef, ObservedChild>,
) -> (&'a ResourceRef, bool, OwnedChildKind) {
    match mutation {
        OwnerMutation::Create { target, .. } | OwnerMutation::Repair { target, .. } => (
            target,
            false,
            desired
                .get(target)
                .map(DesiredChild::kind)
                .unwrap_or_else(|| OwnedChildKind::from_resource_ref(target)),
        ),
        OwnerMutation::RequestDeletion { target, .. } | OwnerMutation::Delete { target, .. } => (
            target,
            true,
            observed
                .get(target)
                .map(ObservedChild::kind)
                .unwrap_or_else(|| OwnedChildKind::from_resource_ref(target)),
        ),
    }
}

/// One owner-change trigger.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnerTrigger {
    owner: HintTarget,
    child: HintTarget,
    revision: ZoneRevision,
    depth: usize,
}

impl OwnerTrigger {
    /// Borrow the owner target.
    pub const fn owner(&self) -> &HintTarget {
        &self.owner
    }

    /// Borrow the changed child at this hop.
    pub const fn child(&self) -> &HintTarget {
        &self.child
    }

    /// Return the coalesced revision.
    pub const fn revision(&self) -> ZoneRevision {
        self.revision
    }

    /// Return one-based ancestor depth.
    pub const fn depth(&self) -> usize {
        self.depth
    }

    /// Coalesce the same immutable owner-child binding.
    pub fn coalesce(&mut self, newer: Self) -> Result<(), OwnerGraphError> {
        if self.owner != newer.owner || self.child != newer.child || self.depth != newer.depth {
            return Err(OwnerGraphError::DifferentBinding);
        }
        self.revision = self.revision.max(newer.revision);
        Ok(())
    }
}

impl core::fmt::Debug for OwnerTrigger {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OwnerTrigger")
            .field("owner", &self.owner)
            .field("child", &self.child)
            .field("revision", &self.revision)
            .field("depth", &self.depth)
            .finish()
    }
}

/// Acyclic singular-owner graph.
pub struct OwnerGraph {
    limits: OwnerLimits,
    parents: BTreeMap<HintTarget, HintTarget>,
}

impl OwnerGraph {
    /// Construct an owner graph bound by toolkit-owned limits.
    pub fn new(limits: OwnerLimits) -> Self {
        Self {
            limits,
            parents: BTreeMap::new(),
        }
    }

    /// Bind one child to one same-Zone owner.
    pub fn bind(&mut self, child: HintTarget, owner: HintTarget) -> Result<(), OwnerGraphError> {
        if child == owner || child.zone() != owner.zone() {
            return Err(OwnerGraphError::InvalidBinding);
        }
        let previous = self.parents.insert(child.clone(), owner);
        if self
            .parents
            .keys()
            .any(|candidate| self.validate_from(candidate).is_err())
        {
            if let Some(previous) = previous {
                self.parents.insert(child, previous);
            } else {
                self.parents.remove(&child);
            }
            return Err(OwnerGraphError::CycleOrDepth);
        }
        Ok(())
    }

    /// Remove a child binding.
    pub fn unbind(&mut self, child: &HintTarget) -> bool {
        self.parents.remove(child).is_some()
    }

    /// Propagate one durable mutation to every bounded ancestor.
    pub fn propagate(
        &self,
        changed_child: &HintTarget,
        revision: ZoneRevision,
    ) -> Result<Vec<OwnerTrigger>, OwnerGraphError> {
        if revision.get() == 0 {
            return Err(OwnerGraphError::InvalidRevision);
        }
        let mut triggers = Vec::new();
        let mut child = changed_child.clone();
        let mut visited = BTreeSet::from([child.clone()]);
        while let Some(owner) = self.parents.get(&child) {
            if !visited.insert(owner.clone()) {
                return Err(OwnerGraphError::CycleOrDepth);
            }
            let depth = triggers.len() + 1;
            if depth > self.limits.max_depth || depth > self.limits.max_work_items {
                return Err(OwnerGraphError::CycleOrDepth);
            }
            triggers.push(OwnerTrigger {
                owner: owner.clone(),
                child: child.clone(),
                revision,
                depth,
            });
            child = owner.clone();
        }
        Ok(triggers)
    }

    /// Remove every binding whose child or owner belongs to a withdrawn set.
    pub fn withdraw(&mut self, resources: &BTreeSet<HintTarget>) -> usize {
        let before = self.parents.len();
        self.parents
            .retain(|child, owner| !resources.contains(child) && !resources.contains(owner));
        before - self.parents.len()
    }

    fn validate_from(&self, child: &HintTarget) -> Result<(), OwnerGraphError> {
        let mut current = child;
        let mut visited = BTreeSet::from([child.clone()]);
        let mut depth = 0;
        while let Some(owner) = self.parents.get(current) {
            depth += 1;
            if depth > self.limits.max_depth || !visited.insert(owner.clone()) {
                return Err(OwnerGraphError::CycleOrDepth);
            }
            current = owner;
        }
        Ok(())
    }
}

/// Invalid desired/observed child set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerReconcileError {
    InvalidChild,
    DuplicateChild,
    TooManyChildren,
    OwnerNotRelisted,
    IdentityMismatch,
    ForeignOwner,
    CrossZone,
    StaleOwner,
    StaleGeneration,
    StaleRevision,
    OwnerIdentityMissing,
    UidInDesiredChild,
    InvalidBatch,
    BatchIncomplete,
    BatchUnexpected,
    BatchDuplicate,
    BatchIdentityConflict,
    InvalidRevision,
    DependencyCycle,
    DependencyDepthExceeded,
}

impl core::fmt::Display for OwnerReconcileError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::InvalidChild => "owner child is malformed, cross-Zone, or over the bound",
            Self::DuplicateChild => "complete owner child set contains a duplicate reference",
            Self::TooManyChildren => "owner desired child set exceeds its work bound",
            Self::OwnerNotRelisted => {
                "owner planning requires a complete authoritative child relist"
            }
            Self::IdentityMismatch => "owner child identity does not match its ResourceRef",
            Self::ForeignOwner => "owner child names a foreign owner",
            Self::CrossZone => "owner child is outside the owner's Zone",
            Self::StaleOwner => "owner child carries a stale owner incarnation",
            Self::StaleGeneration => "owner child carries a stale owner generation",
            Self::StaleRevision => "owner admission carries a stale owner revision",
            Self::OwnerIdentityMissing => "owner child lacks exact owner identity",
            Self::UidInDesiredChild => "UID-free desired child contains a store UID",
            Self::InvalidBatch => "owner child batch is empty or exceeds its bound",
            Self::BatchIncomplete => "owner child batch result is incomplete",
            Self::BatchUnexpected => "owner child batch result names an unexpected child",
            Self::BatchDuplicate => "owner child batch result repeats a child reference",
            Self::BatchIdentityConflict => {
                "owner child batch result reuses one UID for multiple references"
            }
            Self::InvalidRevision => "owner child batch result lacks a durable revision",
            Self::DependencyCycle => "owner child dependency graph is cyclic",
            Self::DependencyDepthExceeded => "owner child dependency graph exceeds its depth bound",
        })
    }
}

impl std::error::Error for OwnerReconcileError {}

/// Invalid singular-owner graph operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerGraphError {
    InvalidLimits,
    InvalidBinding,
    InvalidRevision,
    CycleOrDepth,
    DifferentBinding,
}

impl core::fmt::Display for OwnerGraphError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::InvalidLimits => "owner propagation limits are empty or inconsistent",
            Self::InvalidBinding => "owner binding is self-owned or cross-Zone",
            Self::InvalidRevision => "owner propagation requires a durable revision",
            Self::CycleOrDepth => "owner propagation is cyclic or exceeds its depth bound",
            Self::DifferentBinding => "only one immutable owner-child binding may coalesce",
        })
    }
}

impl std::error::Error for OwnerGraphError {}

#[cfg(test)]
mod tests {
    use d2b_contracts_resource::v3::{ResourceUid, ZoneId};

    use super::*;

    fn target(zone: &str, resource_type: &str, name: &str, suffix: u8) -> HintTarget {
        HintTarget::new(
            ZoneId::parse(zone).unwrap(),
            ResourceRef::parse(&format!("{resource_type}/{name}")).unwrap(),
            ResourceUid::parse(format!("123e4567-e89b-42d3-a456-4266141740{suffix:02}")).unwrap(),
        )
    }

    fn desired(resource_type: &str, name: &str, digest: &str) -> DesiredChild {
        DesiredChild::new(
            ResourceRef::parse(&format!("{resource_type}/{name}")).unwrap(),
            format!("{{\"name\":\"{name}\"}}").into_bytes(),
            digest,
        )
        .unwrap()
    }

    fn limits() -> OwnerLimits {
        OwnerLimits::new(8, 64).unwrap()
    }

    fn observed(
        resource_type: &str,
        name: &str,
        suffix: u8,
        revision: u64,
        digest: &str,
    ) -> ObservedChild {
        ObservedChild::new(
            target("work", resource_type, name, suffix),
            ZoneRevision::new(revision),
            digest,
            false,
        )
        .unwrap()
    }

    fn observed_deleting(
        resource_type: &str,
        name: &str,
        suffix: u8,
        revision: u64,
        digest: &str,
    ) -> ObservedChild {
        ObservedChild::new(
            target("work", resource_type, name, suffix),
            ZoneRevision::new(revision),
            digest,
            true,
        )
        .unwrap()
    }

    #[test]
    fn complete_relist_drives_create_repair_and_delete_plan() {
        let owner = target("work", "Guest", "desktop", 1);
        let mut index = OwnerIndex::new(limits());
        index
            .relist_with_owner_generation(
                owner.clone(),
                d2b_contracts_resource::v3::ResourceGeneration::new(1).unwrap(),
                vec![
                    ObservedChild::with_owner(
                        target("work", "Process", "drifted", 2),
                        &owner,
                        d2b_contracts_resource::v3::ResourceGeneration::new(1).unwrap(),
                        ZoneRevision::new(4),
                        "old",
                        false,
                    )
                    .unwrap(),
                    ObservedChild::with_owner(
                        target("work", "Process", "extra", 3),
                        &owner,
                        d2b_contracts_resource::v3::ResourceGeneration::new(1).unwrap(),
                        ZoneRevision::new(5),
                        "extra",
                        false,
                    )
                    .unwrap(),
                ],
            )
            .unwrap();
        let plan = index
            .plan(
                &owner,
                vec![
                    desired("Process", "missing", "new"),
                    desired("Process", "drifted", "new"),
                ],
            )
            .unwrap();

        assert_eq!(plan.mutations().len(), 3);
        assert!(matches!(plan.mutations()[0], OwnerMutation::Repair { .. }));
        assert!(matches!(plan.mutations()[1], OwnerMutation::Create { .. }));
        assert!(matches!(
            plan.mutations()[2],
            OwnerMutation::RequestDeletion { .. }
        ));
    }

    #[test]
    fn uncertain_batch_recovery_preserves_existing_siblings() {
        let owner = target("work", "Guest", "desktop", 1);
        let owner_generation = d2b_contracts_resource::v3::ResourceGeneration::new(1).unwrap();
        let existing = ObservedChild::with_owner(
            target("work", "Process", "existing", 2),
            &owner,
            owner_generation,
            ZoneRevision::new(4),
            "existing",
            false,
        )
        .unwrap();
        let mut index = OwnerIndex::new(limits());
        index
            .relist_with_owner_generation(owner.clone(), owner_generation, vec![existing])
            .unwrap();
        let desired = vec![
            desired("Process", "existing", "existing"),
            desired("Process", "missing", "missing"),
        ];
        let batch = index
            .plan(&owner, desired.clone())
            .unwrap()
            .create_batch()
            .cloned()
            .unwrap();
        let recovered = ObservedChild::with_owner(
            target("work", "Process", "missing", 3),
            &owner,
            owner_generation,
            ZoneRevision::new(5),
            "missing",
            false,
        )
        .unwrap();

        index
            .recover_batch(&batch, &OwnerBatchResult::uncertain(), &[recovered])
            .unwrap();

        assert_eq!(index.child_count(&owner), 2);
        assert!(index.plan(&owner, desired).unwrap().is_converged());
    }

    #[test]
    fn repair_and_delete_keep_exact_uid_revision_preconditions() {
        let owner = target("work", "Guest", "desktop", 1);
        let drifted = observed("Process", "app", 2, 9, "old");
        let expected_uid = drifted.target().uid().clone();
        let mut index = OwnerIndex::new(limits());
        index.relist(owner.clone(), vec![drifted]).unwrap();

        let repair = index
            .plan(&owner, vec![desired("Process", "app", "new")])
            .unwrap();
        assert!(matches!(
            &repair.mutations()[0],
            OwnerMutation::Repair {
                expected_uid: uid,
                expected_revision,
                ..
            } if uid == &expected_uid && *expected_revision == ZoneRevision::new(9)
        ));

        let delete = index.plan(&owner, Vec::new()).unwrap();
        assert!(matches!(
            &delete.mutations()[0],
            OwnerMutation::RequestDeletion {
                expected_uid: uid,
                expected_revision,
                ..
            } if uid == &expected_uid && *expected_revision == ZoneRevision::new(9)
        ));
    }

    #[test]
    fn authoritative_relist_replaces_stale_children() {
        let owner = target("work", "Guest", "desktop", 1);
        let mut index = OwnerIndex::new(limits());
        index
            .relist(owner.clone(), vec![observed("Process", "old", 2, 2, "old")])
            .unwrap();
        index
            .relist(owner.clone(), vec![observed("Process", "new", 3, 3, "new")])
            .unwrap();

        assert_eq!(index.child_count(&owner), 1);
        let plan = index
            .plan(&owner, vec![desired("Process", "new", "new")])
            .unwrap();
        assert!(plan.is_converged());
    }

    #[test]
    fn deleting_children_keep_owner_pending_until_relisted_absent() {
        let owner = target("work", "Guest", "desktop", 1);
        let mut index = OwnerIndex::new(limits());
        index
            .relist(
                owner.clone(),
                vec![observed_deleting("Endpoint", "endpoint", 2, 2, "current")],
            )
            .unwrap();

        let plan = index.plan(&owner, Vec::new()).unwrap();
        assert!(plan.mutations().is_empty());
        assert!(!plan.is_converged());

        index.relist(owner.clone(), Vec::new()).unwrap();
        assert!(index.plan(&owner, Vec::new()).unwrap().is_converged());
    }

    #[test]
    fn planning_fails_closed_until_the_owner_index_is_relisted() {
        let owner = target("work", "Guest", "desktop", 1);
        let index = OwnerIndex::new(limits());

        assert_eq!(
            index
                .plan(&owner, vec![desired("Process", "app", "new")])
                .unwrap_err(),
            OwnerReconcileError::OwnerNotRelisted
        );
    }

    #[test]
    fn owner_cannot_be_listed_as_its_own_child() {
        let owner = target("work", "Guest", "desktop", 1);
        let mut index = OwnerIndex::new(limits());

        assert_eq!(
            index
                .relist(
                    owner.clone(),
                    vec![
                        ObservedChild::new(
                            target("work", "Guest", "desktop", 2),
                            ZoneRevision::new(1),
                            "digest",
                            false,
                        )
                        .unwrap(),
                    ],
                )
                .unwrap_err(),
            OwnerReconcileError::InvalidChild
        );
        index.relist(owner.clone(), Vec::new()).unwrap();
        assert_eq!(
            index
                .plan(&owner, vec![desired("Guest", "desktop", "digest")])
                .unwrap_err(),
            OwnerReconcileError::InvalidChild
        );
    }

    #[test]
    fn child_mutation_propagates_through_each_ancestor() {
        let zone = target("work", "Zone", "work", 1);
        let guest = target("work", "Guest", "desktop", 2);
        let process = target("work", "Process", "app", 3);
        let endpoint = target("work", "Endpoint", "socket", 4);
        let mut graph = OwnerGraph::new(limits());
        graph.bind(endpoint.clone(), process.clone()).unwrap();
        graph.bind(process.clone(), guest.clone()).unwrap();
        graph.bind(guest.clone(), zone.clone()).unwrap();

        let triggers = graph.propagate(&endpoint, ZoneRevision::new(11)).unwrap();
        assert_eq!(triggers.len(), 3);
        assert_eq!(triggers[0].owner(), &process);
        assert_eq!(triggers[1].owner(), &guest);
        assert_eq!(triggers[2].owner(), &zone);
        assert_eq!(triggers[2].depth(), 3);
    }

    #[test]
    fn owner_propagation_requires_a_durable_revision() {
        let child = target("work", "Process", "child", 1);
        let graph = OwnerGraph::new(limits());

        assert_eq!(
            graph.propagate(&child, ZoneRevision::new(0)).unwrap_err(),
            OwnerGraphError::InvalidRevision
        );
    }

    #[test]
    fn owner_graph_rejects_cross_zone_and_cycles() {
        let one = target("work", "Process", "one", 1);
        let two = target("work", "Process", "two", 2);
        let foreign = target("personal", "Process", "foreign", 3);
        let mut graph = OwnerGraph::new(limits());
        assert_eq!(
            graph.bind(one.clone(), foreign).unwrap_err(),
            OwnerGraphError::InvalidBinding
        );
        graph.bind(one.clone(), two.clone()).unwrap();
        assert_eq!(
            graph.bind(two, one).unwrap_err(),
            OwnerGraphError::CycleOrDepth
        );
    }

    #[test]
    fn owner_trigger_coalescing_keeps_high_water_revision() {
        let owner = target("work", "Guest", "desktop", 1);
        let child = target("work", "Process", "app", 2);
        let mut trigger = OwnerTrigger {
            owner: owner.clone(),
            child: child.clone(),
            revision: ZoneRevision::new(4),
            depth: 1,
        };
        trigger
            .coalesce(OwnerTrigger {
                owner,
                child,
                revision: ZoneRevision::new(8),
                depth: 1,
            })
            .unwrap();
        assert_eq!(trigger.revision(), ZoneRevision::new(8));
    }

    #[test]
    fn process_scheduling_prioritizes_deletion_then_workload_then_controller() {
        assert_eq!(
            ProcessSchedulingClass::classify(true, true),
            ProcessSchedulingClass::DeletionRequested
        );
        assert_eq!(
            ProcessSchedulingClass::classify(false, false),
            ProcessSchedulingClass::Workload
        );
        assert_eq!(
            ProcessSchedulingClass::classify(false, true),
            ProcessSchedulingClass::ProviderController
        );
        assert!(
            ProcessSchedulingClass::DeletionRequested.rank()
                < ProcessSchedulingClass::Workload.rank()
        );
        assert!(
            ProcessSchedulingClass::Workload.rank()
                < ProcessSchedulingClass::ProviderController.rank()
        );
    }

    #[test]
    fn owner_chain_depth_bound_is_enforced_during_binding() {
        let resources: Vec<_> = (0..=9)
            .map(|index| {
                target(
                    "work",
                    "Process",
                    &format!("node-{index}"),
                    u8::try_from(index + 1).unwrap(),
                )
            })
            .collect();
        let mut graph = OwnerGraph::new(limits());
        for pair in resources.windows(2).take(limits().max_depth) {
            graph.bind(pair[0].clone(), pair[1].clone()).unwrap();
        }
        assert_eq!(
            graph
                .bind(
                    resources[limits().max_depth].clone(),
                    resources[limits().max_depth + 1].clone(),
                )
                .unwrap_err(),
            OwnerGraphError::CycleOrDepth
        );
    }

    #[test]
    fn owner_diagnostics_redact_body_digest_names_and_uids() {
        const NAME: &str = "owner-debug-sentinel";
        const UID: &str = "deadbeef-dead-4bad-8bad-deadbeef0008";
        const BODY: &str = "owner-body-debug-sentinel";
        const DIGEST: &str = "owner-digest-debug-sentinel";
        let desired = DesiredChild::new(
            ResourceRef::parse(&format!("Process/{NAME}")).unwrap(),
            BODY.as_bytes().to_vec(),
            DIGEST,
        )
        .unwrap();
        let observed = ObservedChild::new(
            HintTarget::new(
                ZoneId::parse("work").unwrap(),
                ResourceRef::parse(&format!("Process/{NAME}")).unwrap(),
                ResourceUid::parse(UID).unwrap(),
            ),
            ZoneRevision::new(3),
            DIGEST,
            false,
        )
        .unwrap();
        assert_eq!(desired.target().name().as_str(), NAME);
        assert_eq!(desired.canonical_resource(), BODY.as_bytes());
        assert_eq!(desired.payload_digest(), DIGEST);
        assert_eq!(observed.target().uid().as_str(), UID);
        assert_eq!(observed.payload_digest(), DIGEST);

        for debug in [format!("{desired:?}"), format!("{observed:?}")] {
            for sentinel in [NAME, UID, BODY, DIGEST] {
                assert!(!debug.contains(sentinel), "{debug}");
            }
        }
    }
}
