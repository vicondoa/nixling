//! Identity-bound context supplied to one reconcile pass.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use d2b_contracts_resource::v3::{
    ConfigurationGeneration, ResourceGeneration, ResourceUid, ZoneId, ZoneRevision,
};

use crate::{ControllerIdentity, ResourceKey, TriggerSet};

/// Fresh target body read immediately before a handler starts.
#[derive(Clone, PartialEq, Eq)]
pub struct ResourceSnapshot {
    key: ResourceKey,
    revision: ZoneRevision,
    generation: ResourceGeneration,
    canonical_json: Vec<u8>,
    deleting: bool,
}

impl ResourceSnapshot {
    /// Construct a fresh resource snapshot.
    pub fn new(
        key: ResourceKey,
        revision: ZoneRevision,
        generation: ResourceGeneration,
        canonical_json: Vec<u8>,
        deleting: bool,
    ) -> Self {
        Self {
            key,
            revision,
            generation,
            canonical_json,
            deleting,
        }
    }

    /// Borrow the immutable identity.
    pub const fn key(&self) -> &ResourceKey {
        &self.key
    }

    /// Return the fresh revision.
    pub const fn revision(&self) -> ZoneRevision {
        self.revision
    }

    /// Return the desired-state generation.
    pub const fn generation(&self) -> ResourceGeneration {
        self.generation
    }

    /// Borrow canonical resource bytes.
    pub fn canonical_json(&self) -> &[u8] {
        &self.canonical_json
    }

    /// Whether deletion has been requested.
    pub const fn deleting(&self) -> bool {
        self.deleting
    }
}

impl core::fmt::Debug for ResourceSnapshot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ResourceSnapshot")
            .field("key", &self.key)
            .field("revision", &self.revision)
            .field("generation", &self.generation)
            .field(
                "canonical_json",
                &format_args!("<{} bytes>", self.canonical_json.len()),
            )
            .field("deleting", &self.deleting)
            .finish()
    }
}

/// Base-only dependency snapshot from the same Zone as the target.
#[derive(Clone, PartialEq, Eq)]
pub struct DependencySnapshot {
    resource: ResourceSnapshot,
}

impl DependencySnapshot {
    /// Wrap a base-only dependency resource.
    pub fn new(resource: ResourceSnapshot) -> Self {
        Self { resource }
    }

    /// Borrow the dependency resource.
    pub const fn resource(&self) -> &ResourceSnapshot {
        &self.resource
    }
}

impl core::fmt::Debug for DependencySnapshot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DependencySnapshot")
            .field("resource", &self.resource)
            .finish()
    }
}

/// Correlation identifiers fixed for one pass.
#[derive(Clone, PartialEq, Eq)]
pub struct OperationContext {
    operation_id: String,
    idempotency_key: String,
    correlation_id: String,
    trace_id: Option<String>,
}

impl OperationContext {
    /// Construct bounded opaque identifiers.
    pub fn new(
        operation_id: impl Into<String>,
        idempotency_key: impl Into<String>,
        correlation_id: impl Into<String>,
        trace_id: Option<String>,
    ) -> Result<Self, ContextError> {
        let value = Self {
            operation_id: operation_id.into(),
            idempotency_key: idempotency_key.into(),
            correlation_id: correlation_id.into(),
            trace_id,
        };
        if [
            value.operation_id.as_str(),
            value.idempotency_key.as_str(),
            value.correlation_id.as_str(),
        ]
        .into_iter()
        .any(|field| field.is_empty() || field.len() > 256)
            || value
                .trace_id
                .as_ref()
                .is_some_and(|field| field.is_empty() || field.len() > 256)
        {
            return Err(ContextError::InvalidOperationIdentity);
        }
        Ok(value)
    }

    /// Borrow the operation ID for protocol correlation.
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Borrow the idempotency key.
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    /// Borrow the request correlation ID.
    pub fn correlation_id(&self) -> &str {
        &self.correlation_id
    }

    /// Borrow the optional trace ID.
    pub fn trace_id(&self) -> Option<&str> {
        self.trace_id.as_deref()
    }
}

impl core::fmt::Debug for OperationContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OperationContext(<redacted>)")
    }
}

/// Cloneable cancellation signal carrying no authority.
#[derive(Default)]
struct CancellationState {
    cancelled: AtomicBool,
    notify: tokio::sync::Notify,
}

#[derive(Clone, Default)]
pub struct Cancellation(Arc<CancellationState>);

impl Cancellation {
    /// Mark the pass cancelled.
    pub fn cancel(&self) {
        if !self.0.cancelled.swap(true, Ordering::AcqRel) {
            self.0.notify.notify_waiters();
        }
    }

    /// Observe cancellation.
    pub fn is_cancelled(&self) -> bool {
        self.0.cancelled.load(Ordering::Acquire)
    }

    /// Wait until cancellation is requested.
    pub async fn cancelled(&self) {
        loop {
            let notified = self.0.notify.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }

    pub(crate) fn shares_state(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl core::fmt::Debug for Cancellation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Cancellation")
            .field(&self.is_cancelled())
            .finish()
    }
}

/// Typed durable-commit evidence consumed by an expedited pass.
///
/// The fields remain private. The toolkit's trusted source adapter issues
/// proofs only after verifying the matching committed revision.
///
/// Foreign controller code cannot forge a committed proof:
///
/// ```compile_fail
/// use d2b_contracts_resource::v3::{
///     ResourceGeneration,
///     ResourceUid,
///     ZoneId,
///     ZoneRevision,
/// };
/// use d2b_controller_toolkit::CommittedRevisionProof;
///
/// let _ = CommittedRevisionProof {
///     zone: ZoneId::parse("work").unwrap(),
///     resource_uid: ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap(),
///     generation: ResourceGeneration::new(1).unwrap(),
///     revision: ZoneRevision::new(1),
///     operation_id: String::from("operation"),
/// };
/// ```
pub struct CommittedRevisionProof {
    zone: ZoneId,
    resource_uid: ResourceUid,
    generation: ResourceGeneration,
    revision: ZoneRevision,
    operation_id: String,
}

impl CommittedRevisionProof {
    pub(crate) fn issue(
        zone: ZoneId,
        resource_uid: ResourceUid,
        generation: ResourceGeneration,
        revision: ZoneRevision,
        operation_id: String,
    ) -> Self {
        Self {
            zone,
            resource_uid,
            generation,
            revision,
            operation_id,
        }
    }

    pub(crate) const fn zone(&self) -> &ZoneId {
        &self.zone
    }

    pub(crate) const fn generation(&self) -> ResourceGeneration {
        self.generation
    }

    pub(crate) const fn revision(&self) -> ZoneRevision {
        self.revision
    }

    pub(crate) fn operation_id(&self) -> &str {
        &self.operation_id
    }
}

impl core::fmt::Debug for CommittedRevisionProof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CommittedRevisionProof")
            .field("has_zone", &true)
            .field("has_resource_uid", &true)
            .field("generation", &self.generation)
            .field("revision", &self.revision)
            .field("has_operation_id", &true)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EffectGate {
    Ordinary,
    ExpeditedPending,
    ExpeditedCommitted,
}

/// A borrowed proof that external effects are permitted for this pass.
pub struct EffectPermit<'context> {
    _context: &'context ReconcileContext,
}

impl core::fmt::Debug for EffectPermit<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EffectPermit(<redacted>)")
    }
}

/// One fresh, Zone-checked reconcile invocation context.
pub struct ReconcileContext {
    identity: ControllerIdentity,
    target: ResourceKey,
    revision: ZoneRevision,
    generation: ResourceGeneration,
    reasons: TriggerSet,
    high_water_revision: ZoneRevision,
    operation: OperationContext,
    attempt: u32,
    now_tick: u64,
    deadline_tick: u64,
    cancellation: Cancellation,
    policy_revision: u64,
    api_revision: u64,
    configuration_revision: ConfigurationGeneration,
    effect_gate: EffectGate,
}

impl ReconcileContext {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn ordinary(
        identity: ControllerIdentity,
        target: &ResourceSnapshot,
        dependencies: &[DependencySnapshot],
        reasons: TriggerSet,
        high_water_revision: ZoneRevision,
        operation: OperationContext,
        attempt: u32,
        now_tick: u64,
        deadline_tick: u64,
        cancellation: Cancellation,
        policy_revision: u64,
        api_revision: u64,
        configuration_revision: ConfigurationGeneration,
    ) -> Result<Self, ContextError> {
        Self::new(
            identity,
            target,
            dependencies,
            reasons,
            high_water_revision,
            operation,
            attempt,
            now_tick,
            deadline_tick,
            cancellation,
            policy_revision,
            api_revision,
            configuration_revision,
            EffectGate::Ordinary,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn expedited_pending(
        identity: ControllerIdentity,
        target: &ResourceSnapshot,
        dependencies: &[DependencySnapshot],
        reasons: TriggerSet,
        high_water_revision: ZoneRevision,
        operation: OperationContext,
        attempt: u32,
        now_tick: u64,
        deadline_tick: u64,
        cancellation: Cancellation,
        policy_revision: u64,
        api_revision: u64,
        configuration_revision: ConfigurationGeneration,
    ) -> Result<Self, ContextError> {
        Self::new(
            identity,
            target,
            dependencies,
            reasons,
            high_water_revision,
            operation,
            attempt,
            now_tick,
            deadline_tick,
            cancellation,
            policy_revision,
            api_revision,
            configuration_revision,
            EffectGate::ExpeditedPending,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        identity: ControllerIdentity,
        target: &ResourceSnapshot,
        dependencies: &[DependencySnapshot],
        reasons: TriggerSet,
        high_water_revision: ZoneRevision,
        operation: OperationContext,
        attempt: u32,
        now_tick: u64,
        deadline_tick: u64,
        cancellation: Cancellation,
        policy_revision: u64,
        api_revision: u64,
        configuration_revision: ConfigurationGeneration,
        effect_gate: EffectGate,
    ) -> Result<Self, ContextError> {
        if identity.zone() != target.key.zone()
            || dependencies
                .iter()
                .any(|dependency| dependency.resource.key.zone() != target.key.zone())
        {
            return Err(ContextError::ZoneMismatch);
        }
        if high_water_revision < target.revision {
            return Err(ContextError::HighWaterBehindSnapshot);
        }
        Ok(Self {
            identity,
            target: target.key.clone(),
            revision: target.revision,
            generation: target.generation,
            reasons,
            high_water_revision,
            operation,
            attempt,
            now_tick,
            deadline_tick,
            cancellation,
            policy_revision,
            api_revision,
            configuration_revision,
            effect_gate,
        })
    }

    pub(crate) fn bind_committed_proof(
        mut self,
        proof: CommittedRevisionProof,
    ) -> Result<Self, ContextError> {
        if self.effect_gate != EffectGate::ExpeditedPending {
            return Err(ContextError::UnexpectedCommitProof);
        }
        if proof.zone != *self.target.zone() {
            return Err(ContextError::ZoneMismatch);
        }
        if proof.resource_uid != *self.target.uid()
            || proof.generation != self.generation
            || proof.revision != self.revision
            || proof.operation_id != self.operation.operation_id
        {
            return Err(ContextError::CommitProofMismatch);
        }
        self.effect_gate = EffectGate::ExpeditedCommitted;
        Ok(self)
    }

    /// Borrow the registered identity.
    pub const fn identity(&self) -> &ControllerIdentity {
        &self.identity
    }

    /// Borrow the target key.
    pub const fn target(&self) -> &ResourceKey {
        &self.target
    }

    /// Return the fresh target revision.
    pub const fn revision(&self) -> ZoneRevision {
        self.revision
    }

    /// Return the target generation.
    pub const fn generation(&self) -> ResourceGeneration {
        self.generation
    }

    /// Borrow all coalesced reasons.
    pub const fn reasons(&self) -> &TriggerSet {
        &self.reasons
    }

    /// Return the admitted high-water revision.
    pub const fn high_water_revision(&self) -> ZoneRevision {
        self.high_water_revision
    }

    /// Borrow operation correlation.
    pub const fn operation(&self) -> &OperationContext {
        &self.operation
    }

    /// Return the one-based attempt number.
    pub const fn attempt(&self) -> u32 {
        self.attempt
    }

    /// Return the monotonic tick at which this worker began.
    pub const fn now_tick(&self) -> u64 {
        self.now_tick
    }

    /// Return the monotonic deadline tick.
    pub const fn deadline_tick(&self) -> u64 {
        self.deadline_tick
    }

    /// Borrow cancellation state.
    pub const fn cancellation(&self) -> &Cancellation {
        &self.cancellation
    }

    /// Return policy, API, and configuration revisions.
    pub const fn revisions(&self) -> (u64, u64, ConfigurationGeneration) {
        (
            self.policy_revision,
            self.api_revision,
            self.configuration_revision,
        )
    }

    /// Whether this pass is bound to an expedited committed mutation.
    pub const fn is_expedited(&self) -> bool {
        matches!(
            self.effect_gate,
            EffectGate::ExpeditedPending | EffectGate::ExpeditedCommitted
        )
    }

    /// Borrow a non-reusable effect permit after all gates pass.
    pub fn authorize_effect(&self) -> Result<EffectPermit<'_>, ContextError> {
        match self.effect_gate {
            EffectGate::Ordinary | EffectGate::ExpeditedCommitted => {
                Ok(EffectPermit { _context: self })
            }
            EffectGate::ExpeditedPending => Err(ContextError::CommitProofRequired),
        }
    }
}

impl core::fmt::Debug for ReconcileContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReconcileContext")
            .field("identity", &self.identity)
            .field("target", &self.target)
            .field("revision", &self.revision)
            .field("generation", &self.generation)
            .field("reasons", &self.reasons)
            .field("high_water_revision", &self.high_water_revision)
            .field("operation", &self.operation)
            .field("attempt", &self.attempt)
            .field("now_tick", &self.now_tick)
            .field("deadline_tick", &self.deadline_tick)
            .field("cancellation", &self.cancellation)
            .field("policy_revision", &self.policy_revision)
            .field("api_revision", &self.api_revision)
            .field("configuration_revision", &self.configuration_revision)
            .field("effect_gate", &self.effect_gate)
            .finish()
    }
}

/// Invalid context or expedited proof binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextError {
    ZoneMismatch,
    HighWaterBehindSnapshot,
    InvalidControllerIdentity,
    InvalidOperationIdentity,
    CommitProofRequired,
    UnexpectedCommitProof,
    CommitProofMismatch,
}

impl core::fmt::Display for ContextError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::ZoneMismatch => "reconcile inputs must have one registered Zone",
            Self::HighWaterBehindSnapshot => "high-water revision is behind the fresh snapshot",
            Self::InvalidControllerIdentity => {
                "controller identity must bind Process, Provider, Host, and optional Guest types"
            }
            Self::InvalidOperationIdentity => "operation identity is empty or oversized",
            Self::CommitProofRequired => "expedited effects require durable commit proof",
            Self::UnexpectedCommitProof => "commit proof is not valid for this pass",
            Self::CommitProofMismatch => "commit proof does not match the fresh target",
        })
    }
}

impl std::error::Error for ContextError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TriggerReason;
    use d2b_contracts_resource::v3::{ControllerGeneration, ResourceRef};

    fn key(zone: &str, name: &str, uid: &str) -> ResourceKey {
        ResourceKey::new(
            ZoneId::parse(zone).unwrap(),
            ResourceRef::parse(&format!("Process/{name}")).unwrap(),
            ResourceUid::parse(uid).unwrap(),
        )
    }

    fn snapshot(zone: &str, name: &str, uid: &str) -> ResourceSnapshot {
        ResourceSnapshot::new(
            key(zone, name, uid),
            ZoneRevision::new(4),
            ResourceGeneration::new(2).unwrap(),
            b"{}".to_vec(),
            false,
        )
    }

    fn identity(zone: &str) -> ControllerIdentity {
        ControllerIdentity::new(
            ZoneId::parse(zone).unwrap(),
            ResourceRef::parse("Process/controller").unwrap(),
            ControllerGeneration::new(3).unwrap(),
            ResourceRef::parse("Provider/runtime").unwrap(),
            ResourceGeneration::new(4).unwrap(),
            ResourceRef::parse("Process/controller").unwrap(),
            ResourceRef::parse("Host/system").unwrap(),
            None,
        )
        .unwrap()
    }

    fn operation() -> OperationContext {
        OperationContext::new("op-1", "idem-1", "corr-1", None).unwrap()
    }

    fn pending_context() -> ReconcileContext {
        let target = snapshot("work", "app", "123e4567-e89b-42d3-a456-426614174000");
        ReconcileContext::expedited_pending(
            identity("work"),
            &target,
            &[],
            TriggerSet::new([TriggerReason::ExpeditedMutation]),
            ZoneRevision::new(4),
            operation(),
            1,
            0,
            20,
            Cancellation::default(),
            5,
            6,
            ConfigurationGeneration::new(7).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn trigger_union_keeps_non_droppable_causes() {
        let mut reasons = TriggerSet::new([
            TriggerReason::SpecGenerationChanged,
            TriggerReason::OwnedResourceChanged,
        ]);
        reasons.union_with(&TriggerSet::new([
            TriggerReason::DeletionRequested,
            TriggerReason::PolicyChanged,
        ]));

        assert_eq!(reasons.len(), 4);
        for reason in [
            TriggerReason::OwnedResourceChanged,
            TriggerReason::DeletionRequested,
            TriggerReason::PolicyChanged,
        ] {
            assert!(reasons.contains(reason));
            assert!(reason.is_non_droppable());
        }
    }

    #[test]
    fn controller_identity_rejects_type_confusion_before_registration() {
        assert_eq!(
            ControllerIdentity::new(
                ZoneId::parse("work").unwrap(),
                ResourceRef::parse("Process/controller").unwrap(),
                ControllerGeneration::new(3).unwrap(),
                ResourceRef::parse("Guest/not-a-provider").unwrap(),
                ResourceGeneration::new(4).unwrap(),
                ResourceRef::parse("Process/controller").unwrap(),
                ResourceRef::parse("Host/system").unwrap(),
                None,
            )
            .unwrap_err(),
            ContextError::InvalidControllerIdentity
        );
    }

    #[test]
    fn zone_mismatch_is_rejected_before_context_mint() {
        let target = snapshot("work", "app", "123e4567-e89b-42d3-a456-426614174000");
        let dependency = DependencySnapshot::new(snapshot(
            "personal",
            "dependency",
            "123e4567-e89b-42d3-a456-426614174001",
        ));
        let result = ReconcileContext::ordinary(
            identity("work"),
            &target,
            &[dependency],
            TriggerSet::new([TriggerReason::DependencyChanged]),
            ZoneRevision::new(4),
            operation(),
            1,
            0,
            20,
            Cancellation::default(),
            5,
            6,
            ConfigurationGeneration::new(7).unwrap(),
        );

        assert_eq!(result.unwrap_err(), ContextError::ZoneMismatch);
    }

    #[test]
    fn expedited_effect_is_denied_until_matching_proof_is_consumed() {
        let pending = pending_context();
        assert_eq!(
            pending.authorize_effect().unwrap_err(),
            ContextError::CommitProofRequired
        );

        let proof = CommittedRevisionProof::issue(
            ZoneId::parse("work").unwrap(),
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap(),
            ResourceGeneration::new(2).unwrap(),
            ZoneRevision::new(4),
            "op-1".to_owned(),
        );
        let committed = pending.bind_committed_proof(proof).unwrap();
        assert!(committed.authorize_effect().is_ok());
    }

    #[test]
    fn mismatched_proof_never_mints_effect_permission() {
        let proof = CommittedRevisionProof::issue(
            ZoneId::parse("work").unwrap(),
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174009").unwrap(),
            ResourceGeneration::new(2).unwrap(),
            ZoneRevision::new(4),
            "op-1".to_owned(),
        );
        assert_eq!(
            pending_context().bind_committed_proof(proof).unwrap_err(),
            ContextError::CommitProofMismatch
        );
    }

    #[test]
    fn foreign_zone_proof_never_mints_effect_permission() {
        let proof = CommittedRevisionProof::issue(
            ZoneId::parse("personal").unwrap(),
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap(),
            ResourceGeneration::new(2).unwrap(),
            ZoneRevision::new(4),
            "op-1".to_owned(),
        );

        assert_eq!(
            pending_context().bind_committed_proof(proof).unwrap_err(),
            ContextError::ZoneMismatch
        );
    }

    #[test]
    fn protected_context_diagnostics_are_redacted() {
        const ZONE: &str = "debug-zone-sentinel";
        const NAME: &str = "debug-name-sentinel";
        const UID: &str = "deadbeef-dead-4bad-8bad-deadbeef0001";
        const OPERATION: &str = "debug-operation-sentinel";

        let target = snapshot(ZONE, NAME, UID);
        let context = ReconcileContext::ordinary(
            identity(ZONE),
            &target,
            &[],
            TriggerSet::new([TriggerReason::ManualReconcile]),
            ZoneRevision::new(4),
            OperationContext::new(OPERATION, OPERATION, OPERATION, Some(OPERATION.to_owned()))
                .unwrap(),
            1,
            0,
            20,
            Cancellation::default(),
            5,
            6,
            ConfigurationGeneration::new(7).unwrap(),
        )
        .unwrap();

        assert_eq!(context.target().zone().as_str(), ZONE);
        assert_eq!(context.target().resource_ref().name().as_str(), NAME);
        assert_eq!(context.target().uid().as_str(), UID);
        assert_eq!(context.operation().operation_id(), OPERATION);
        let debug = format!("{context:?}");
        for sentinel in [ZONE, NAME, UID, OPERATION] {
            assert!(!debug.contains(sentinel), "{debug}");
        }
    }
}
