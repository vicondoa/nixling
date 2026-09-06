//! Status-first Guest drain, finalization, and disruptive upgrade planning.

use std::{collections::BTreeSet, fmt};

use d2b_contracts_resource::v3::{ResourceRef, ResourceUid, ZoneRevision};

use crate::identity::ChildRole;

/// Maximum direct children accepted by one lifecycle plan.
const MAX_LIFECYCLE_CHILDREN: usize = 128;

/// Observed state of the authenticated Guest-control session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// The session is live and can drain Guest-local Resources.
    Active,
    /// The session was closed by the controller.
    Closed,
    /// The session is known to be dead.
    Dead,
    /// The controller cannot prove whether the session is live.
    Unknown,
}

/// Observed state of the Guest VMM Process.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// The Process is running with optional exact identity evidence.
    Running {
        /// The Process Provider has verified the complete local identity.
        identity_verified: bool,
    },
    /// The Process is stopped.
    Stopped,
    /// The Process row or realization is absent.
    Absent,
    /// The Process state is not safe to mutate.
    Unknown,
}

impl fmt::Debug for ProcessState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Running { identity_verified } => formatter
                .debug_struct("ProcessState::Running")
                .field("identity_verified", identity_verified)
                .finish(),
            Self::Stopped => formatter.write_str("ProcessState::Stopped"),
            Self::Absent => formatter.write_str("ProcessState::Absent"),
            Self::Unknown => formatter.write_str("ProcessState::Unknown"),
        }
    }
}

impl ProcessState {
    /// Whether the Process is proven stopped or absent.
    pub const fn is_stopped_or_absent(self) -> bool {
        matches!(self, Self::Stopped | Self::Absent)
    }
}

/// Exact identity fence for one Guest-owned direct child.
#[derive(Clone, PartialEq, Eq)]
pub struct FencedChild {
    role: ChildRole,
    target: ResourceRef,
    uid: ResourceUid,
    revision: ZoneRevision,
    deletion_requested: bool,
    finalizers_pending: bool,
}

impl FencedChild {
    /// Construct a direct-child fence.
    pub fn new(
        role: ChildRole,
        target: ResourceRef,
        uid: ResourceUid,
        revision: ZoneRevision,
    ) -> Result<Self, LifecyclePlanError> {
        if target.resource_type().as_str() != role.resource_type() || revision.get() == 0 {
            return Err(LifecyclePlanError::ChildInvalid);
        }
        Ok(Self {
            role,
            target,
            uid,
            revision,
            deletion_requested: false,
            finalizers_pending: false,
        })
    }

    /// Mark that Core has already requested deletion for this child.
    pub const fn with_deletion_requested(mut self, value: bool) -> Self {
        self.deletion_requested = value;
        self
    }

    /// Mark that a child finalizer still blocks physical removal.
    pub const fn with_finalizers_pending(mut self, value: bool) -> Self {
        self.finalizers_pending = value;
        self
    }

    /// Return the fixed direct-child role.
    pub const fn role(&self) -> ChildRole {
        self.role
    }

    /// Borrow the child ResourceRef.
    pub const fn target(&self) -> &ResourceRef {
        &self.target
    }

    /// Borrow the exact child UID fence.
    pub const fn uid(&self) -> &ResourceUid {
        &self.uid
    }

    /// Return the exact child revision fence.
    pub const fn revision(&self) -> ZoneRevision {
        self.revision
    }

    /// Whether deletion has already been requested.
    pub const fn deletion_requested(&self) -> bool {
        self.deletion_requested
    }

    /// Whether a child finalizer remains.
    pub const fn finalizers_pending(&self) -> bool {
        self.finalizers_pending
    }
}

impl fmt::Debug for FencedChild {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FencedChild")
            .field("role", &self.role)
            .field("resource_type", &self.target.resource_type())
            .field("has_uid", &true)
            .field("revision", &self.revision)
            .field("deletion_requested", &self.deletion_requested)
            .field("finalizers_pending", &self.finalizers_pending)
            .finish()
    }
}

/// Snapshot consumed by the pure Guest finalization planner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestFinalizationInput {
    guest_uid: ResourceUid,
    session: SessionState,
    guest_local_drained: bool,
    process: ProcessState,
    direct_children: Vec<FencedChild>,
    transitive_descendants_present: bool,
    host_backed_volume_present: bool,
    foreign_children_present: bool,
}

impl GuestFinalizationInput {
    /// Construct one bounded finalization observation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        guest_uid: ResourceUid,
        session: SessionState,
        guest_local_drained: bool,
        process: ProcessState,
        direct_children: Vec<FencedChild>,
        transitive_descendants_present: bool,
        host_backed_volume_present: bool,
        foreign_children_present: bool,
    ) -> Result<Self, LifecyclePlanError> {
        if direct_children.len() > MAX_LIFECYCLE_CHILDREN {
            return Err(LifecyclePlanError::ChildLimit);
        }
        let mut refs = BTreeSet::new();
        let mut roles = BTreeSet::new();
        for child in &direct_children {
            if !refs.insert(child.target.clone()) || !roles.insert(child.role) {
                return Err(LifecyclePlanError::ChildDuplicate);
            }
        }
        Ok(Self {
            guest_uid,
            session,
            guest_local_drained,
            process,
            direct_children,
            transitive_descendants_present,
            host_backed_volume_present,
            foreign_children_present,
        })
    }

    /// Mark the running VMM identity as locally verified by the Process
    /// Provider.
    pub const fn with_verified_process_identity(mut self) -> Self {
        self.process = ProcessState::Running {
            identity_verified: true,
        };
        self
    }

    /// Borrow the Guest UID fence.
    pub const fn guest_uid(&self) -> &ResourceUid {
        &self.guest_uid
    }

    /// Return the observed session state.
    pub const fn session(&self) -> SessionState {
        self.session
    }

    /// Whether Guest-local Resources are drained.
    pub const fn guest_local_drained(&self) -> bool {
        self.guest_local_drained
    }

    /// Return the Process observation.
    pub const fn process(&self) -> ProcessState {
        self.process
    }

    /// Borrow observed direct children.
    pub fn direct_children(&self) -> &[FencedChild] {
        &self.direct_children
    }

    /// Whether transitive descendants remain.
    pub const fn transitive_descendants_present(&self) -> bool {
        self.transitive_descendants_present
    }

    /// Whether a host-backed Guest Volume remains.
    pub const fn host_backed_volume_present(&self) -> bool {
        self.host_backed_volume_present
    }

    /// Whether a foreign child was observed.
    pub const fn foreign_children_present(&self) -> bool {
        self.foreign_children_present
    }
}

/// One status-first finalization action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinalizationStep {
    /// Drain target-local Guest Resources over the live session.
    DrainGuestLocal,
    /// Close the authenticated Guest-control session.
    CloseSession,
    /// Request the VMM Process to stop using its exact child fence.
    StopVmm {
        /// Exact Process child fence.
        child: FencedChild,
    },
    /// Recycle the VMM Process through its exact Resource API identity.
    RecycleVmm {
        /// Exact Process child fence.
        child: FencedChild,
    },
    /// Request deletion of one direct child using its exact fence.
    DeleteChild(FencedChild),
    /// Wait for transitive owned descendants to disappear.
    WaitForDescendants,
    /// Invalidate the prior session generation before a replacement.
    InvalidateSession {
        /// Prior session generation, when known.
        previous_generation: Option<u64>,
        /// Minimum generation accepted for a replacement session.
        next_generation: u64,
    },
    /// Clear the Guest controller finalizer.
    ClearGuestFinalizer,
}

/// Bounded reason why a Guest finalizer cannot be cleared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalizationBlockReason {
    /// Session liveness or safe absence could not be proven.
    SessionUnavailable,
    /// Exact Process identity was not available.
    ProcessIdentityAmbiguous,
    /// A child finalizer or deletion request remains pending.
    ChildFinalizer,
    /// A transitive descendant remains.
    TransitiveDescendant,
    /// A foreign child prevents an ownership-safe decision.
    ForeignChild,
    /// A host-backed Guest Volume remains.
    HostBackedVolume,
}

/// Finalization planner disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalizationDisposition {
    /// Actions were planned and another observation is required.
    Progressing,
    /// The controller must retain its finalizer and expose the reason.
    Blocked(FinalizationBlockReason),
    /// The finalizer may be cleared after the planned actions.
    Complete,
}

/// Result of one pure finalization planning pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestFinalizationPlan {
    guest_uid: ResourceUid,
    disposition: FinalizationDisposition,
    steps: Vec<FinalizationStep>,
}

impl GuestFinalizationPlan {
    /// Borrow the Guest UID fence.
    pub const fn guest_uid(&self) -> &ResourceUid {
        &self.guest_uid
    }

    /// Return the planner disposition.
    pub const fn disposition(&self) -> FinalizationDisposition {
        self.disposition
    }

    /// Borrow ordered finalization steps.
    pub fn steps(&self) -> &[FinalizationStep] {
        &self.steps
    }
}

/// Plan a status-first, reverse-order Guest deletion.
pub fn plan_finalization(
    input: GuestFinalizationInput,
) -> Result<GuestFinalizationPlan, LifecyclePlanError> {
    if input.foreign_children_present {
        return Ok(blocked_plan(
            input.guest_uid,
            FinalizationBlockReason::ForeignChild,
        ));
    }
    let dead_session_without_absence_proof = matches!(input.session, SessionState::Dead)
        && (matches!(
            input.process,
            ProcessState::Running {
                identity_verified: false
            }
        ) || input.process.is_stopped_or_absent() && input.host_backed_volume_present);
    if matches!(input.session, SessionState::Unknown) || dead_session_without_absence_proof {
        return Ok(blocked_plan(
            input.guest_uid,
            FinalizationBlockReason::SessionUnavailable,
        ));
    }
    let process_child = input
        .direct_children
        .iter()
        .find(|child| child.role == ChildRole::VmmProcess)
        .cloned();
    if matches!(input.process, ProcessState::Running { .. }) && process_child.is_none() {
        return Ok(blocked_plan(
            input.guest_uid,
            FinalizationBlockReason::ProcessIdentityAmbiguous,
        ));
    }
    if matches!(input.process, ProcessState::Unknown)
        || matches!(
            input.process,
            ProcessState::Running {
                identity_verified: false
            }
        )
    {
        return Ok(blocked_plan(
            input.guest_uid,
            FinalizationBlockReason::ProcessIdentityAmbiguous,
        ));
    }
    let mut steps = Vec::new();
    if matches!(input.session, SessionState::Active) {
        steps.push(if input.guest_local_drained {
            FinalizationStep::CloseSession
        } else {
            FinalizationStep::DrainGuestLocal
        });
        return Ok(GuestFinalizationPlan {
            guest_uid: input.guest_uid,
            disposition: FinalizationDisposition::Progressing,
            steps,
        });
    }
    if let (
        Some(child),
        ProcessState::Running {
            identity_verified: true,
        },
    ) = (process_child.clone(), input.process)
    {
        steps.push(FinalizationStep::StopVmm { child });
        return Ok(GuestFinalizationPlan {
            guest_uid: input.guest_uid,
            disposition: FinalizationDisposition::Progressing,
            steps,
        });
    }
    if input
        .direct_children
        .iter()
        .any(|child| child.deletion_requested && child.finalizers_pending)
    {
        return Ok(blocked_plan(
            input.guest_uid,
            FinalizationBlockReason::ChildFinalizer,
        ));
    }

    let mut children = input.direct_children;
    children.sort_by_key(|child| (deletion_rank(child.role), child.target.clone()));
    if let Some(child) = children
        .iter()
        .find(|child| !child.deletion_requested)
        .cloned()
    {
        steps.push(FinalizationStep::DeleteChild(child));
        return Ok(GuestFinalizationPlan {
            guest_uid: input.guest_uid,
            disposition: FinalizationDisposition::Progressing,
            steps,
        });
    }

    if !children.is_empty() {
        steps.push(FinalizationStep::WaitForDescendants);
        return Ok(GuestFinalizationPlan {
            guest_uid: input.guest_uid,
            disposition: FinalizationDisposition::Blocked(
                FinalizationBlockReason::TransitiveDescendant,
            ),
            steps,
        });
    }

    if input.transitive_descendants_present {
        steps.push(FinalizationStep::WaitForDescendants);
        return Ok(GuestFinalizationPlan {
            guest_uid: input.guest_uid,
            disposition: FinalizationDisposition::Blocked(
                FinalizationBlockReason::TransitiveDescendant,
            ),
            steps,
        });
    }
    if input.host_backed_volume_present {
        return Ok(GuestFinalizationPlan {
            guest_uid: input.guest_uid,
            disposition: FinalizationDisposition::Blocked(
                FinalizationBlockReason::HostBackedVolume,
            ),
            steps,
        });
    }
    if steps.is_empty() {
        steps.push(FinalizationStep::ClearGuestFinalizer);
        return Ok(GuestFinalizationPlan {
            guest_uid: input.guest_uid,
            disposition: FinalizationDisposition::Complete,
            steps,
        });
    }
    Ok(GuestFinalizationPlan {
        guest_uid: input.guest_uid,
        disposition: FinalizationDisposition::Progressing,
        steps,
    })
}

fn blocked_plan(guest_uid: ResourceUid, reason: FinalizationBlockReason) -> GuestFinalizationPlan {
    GuestFinalizationPlan {
        guest_uid,
        disposition: FinalizationDisposition::Blocked(reason),
        steps: Vec::new(),
    }
}

fn deletion_rank(role: ChildRole) -> u8 {
    match role {
        ChildRole::ChApiEndpoint => 0,
        ChildRole::GuestControlEndpoint => 1,
        ChildRole::VmmProcess => 2,
        ChildRole::SystemVolume => 3,
    }
}

/// Infer one fixed direct-child role from its deterministic ResourceRef.
pub fn child_role_for_ref(target: &ResourceRef) -> Option<ChildRole> {
    [
        ChildRole::VmmProcess,
        ChildRole::ChApiEndpoint,
        ChildRole::GuestControlEndpoint,
        ChildRole::SystemVolume,
    ]
    .into_iter()
    .find(|role| {
        target.resource_type().as_str() == role.resource_type()
            && target
                .name()
                .as_str()
                .strip_suffix(&format!("-{}", role.suffix()))
                .is_some()
    })
}

/// Disruptive update that requires a VMM realization recycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeReason {
    /// The selected system image or artifact generation changed.
    ImageOrSystemGenerationChanged,
    /// The selected Provider generation changed.
    ProviderGenerationChanged,
    /// An immutable Guest spec field changed.
    SpecChanged,
}

/// One upgrade plan for a Guest incarnation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestUpgradePlan {
    guest_ref: ResourceRef,
    guest_uid: ResourceUid,
    reason: UpgradeReason,
    durable_volumes: Vec<FencedChild>,
    transient_children: Vec<FencedChild>,
    previous_session_generation: Option<u64>,
    next_session_generation: u64,
    steps: Vec<FinalizationStep>,
}

impl GuestUpgradePlan {
    /// Borrow the Guest ResourceRef.
    pub const fn guest_ref(&self) -> &ResourceRef {
        &self.guest_ref
    }

    /// Borrow the Guest UID fence.
    pub const fn guest_uid(&self) -> &ResourceUid {
        &self.guest_uid
    }

    /// Return the disruptive reason.
    pub const fn reason(&self) -> UpgradeReason {
        self.reason
    }

    /// Borrow durable child Volumes whose UIDs must be preserved.
    pub fn durable_volumes(&self) -> &[FencedChild] {
        &self.durable_volumes
    }

    /// Borrow transient Process and Endpoint children to recycle.
    pub fn transient_children(&self) -> &[FencedChild] {
        &self.transient_children
    }

    /// Return the prior session generation.
    pub const fn previous_session_generation(&self) -> Option<u64> {
        self.previous_session_generation
    }

    /// Return the minimum accepted replacement session generation.
    pub const fn next_session_generation(&self) -> u64 {
        self.next_session_generation
    }

    /// Whether durable state is preserved.
    pub const fn preserve_state(&self) -> bool {
        true
    }

    /// Borrow ordered recycle steps.
    pub fn steps(&self) -> &[FinalizationStep] {
        &self.steps
    }
}

/// Plan a D091 recycle while preserving Guest and durable Volume identities.
pub fn plan_upgrade(
    guest_ref: ResourceRef,
    guest_uid: ResourceUid,
    children: impl IntoIterator<Item = FencedChild>,
    previous_session_generation: Option<u64>,
    reason: UpgradeReason,
) -> Result<GuestUpgradePlan, LifecyclePlanError> {
    if guest_ref.resource_type().as_str() != "Guest" {
        return Err(LifecyclePlanError::GuestInvalid);
    }
    let mut children = children.into_iter().collect::<Vec<_>>();
    if children.len() > MAX_LIFECYCLE_CHILDREN {
        return Err(LifecyclePlanError::ChildLimit);
    }
    let mut refs = BTreeSet::new();
    let mut roles = BTreeSet::new();
    for child in &children {
        if !refs.insert(child.target.clone()) || !roles.insert(child.role) {
            return Err(LifecyclePlanError::ChildDuplicate);
        }
    }
    children.sort_by_key(|child| (upgrade_rank(child.role), child.target.clone()));
    let durable_volumes = children
        .iter()
        .filter(|child| child.role == ChildRole::SystemVolume)
        .cloned()
        .collect::<Vec<_>>();
    let transient_children = children
        .into_iter()
        .filter(|child| child.role != ChildRole::SystemVolume)
        .collect::<Vec<_>>();
    let next_session_generation = previous_session_generation
        .unwrap_or(0)
        .saturating_add(1)
        .max(1);
    let mut steps = Vec::new();
    if !transient_children.is_empty() {
        steps.push(FinalizationStep::DrainGuestLocal);
        steps.push(FinalizationStep::CloseSession);
        steps.push(FinalizationStep::InvalidateSession {
            previous_generation: previous_session_generation,
            next_generation: next_session_generation,
        });
    }
    if let Some(process) = transient_children
        .iter()
        .find(|child| child.role == ChildRole::VmmProcess)
    {
        if process.deletion_requested() || process.finalizers_pending() {
            return Err(LifecyclePlanError::ChildFinalizer);
        }
        steps.push(FinalizationStep::RecycleVmm {
            child: process.clone(),
        });
    }
    steps.extend(
        transient_children
            .iter()
            .filter(|child| child.role != ChildRole::VmmProcess)
            .cloned()
            .map(FinalizationStep::DeleteChild),
    );
    if let Some(process) = transient_children
        .iter()
        .find(|child| child.role == ChildRole::VmmProcess)
    {
        steps.push(FinalizationStep::DeleteChild(process.clone()));
    }
    Ok(GuestUpgradePlan {
        guest_ref,
        guest_uid,
        reason,
        durable_volumes,
        transient_children,
        previous_session_generation,
        next_session_generation,
        steps,
    })
}

/// Return whether a reconnect generation is strictly newer than the prior
/// session generation.
pub const fn session_generation_is_fresh(previous: Option<u64>, candidate: u64) -> bool {
    let previous = match previous {
        Some(value) => value,
        None => 0,
    };
    candidate != 0 && candidate > previous
}

fn upgrade_rank(role: ChildRole) -> u8 {
    match role {
        ChildRole::ChApiEndpoint => 0,
        ChildRole::GuestControlEndpoint => 1,
        ChildRole::VmmProcess => 2,
        ChildRole::SystemVolume => 3,
    }
}

/// Failure while building a bounded lifecycle plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecyclePlanError {
    /// The Guest ResourceRef was invalid.
    GuestInvalid,
    /// A direct child role and ResourceType did not match.
    ChildInvalid,
    /// A direct child role or ResourceRef was duplicated.
    ChildDuplicate,
    /// The direct child bound was exceeded.
    ChildLimit,
    /// A child finalizer already blocks an upgrade.
    ChildFinalizer,
}

impl fmt::Display for LifecyclePlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::GuestInvalid => "cloud-hypervisor-guest-invalid",
            Self::ChildInvalid => "cloud-hypervisor-child-invalid",
            Self::ChildDuplicate => "cloud-hypervisor-child-duplicate",
            Self::ChildLimit => "cloud-hypervisor-child-limit",
            Self::ChildFinalizer => "cloud-hypervisor-child-finalizer-pending",
        })
    }
}

impl std::error::Error for LifecyclePlanError {}
