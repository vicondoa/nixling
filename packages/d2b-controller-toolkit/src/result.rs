//! Bounded handler plans, results, projections, and upgrade contracts.

use d2b_contracts_resource::v3::{
    MAX_BATCH_MUTATIONS, MAX_REQUEST_CANONICAL_BYTES, ResourceGeneration, ResourcePhase,
    ResourceRef, ResourceUid, ZoneRevision, resource::MAX_RESOURCE_ENVELOPE_BYTES,
    resource_status::MAX_STATUS_BYTES,
};
use std::collections::BTreeSet;

use crate::ResourceKey;

/// Structurally typed mutation operation emitted by a controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationIntentKind {
    Create,
    UpdateSpec,
    UpdateStatus,
    UpdateMetadata,
    UpdateFinalizers,
    Delete,
}

/// One optimistic resource mutation with no direct store handle.
#[derive(Clone, PartialEq, Eq)]
pub struct MutationIntent {
    target: ResourceRef,
    expected_uid: Option<ResourceUid>,
    expected_revision: Option<ZoneRevision>,
    kind: MutationIntentKind,
    canonical_resource: Option<Vec<u8>>,
}

impl MutationIntent {
    /// Construct a mutation intent. `None` revision is valid only for create.
    pub fn new(
        target: ResourceRef,
        expected_uid: Option<ResourceUid>,
        expected_revision: Option<ZoneRevision>,
        kind: MutationIntentKind,
        canonical_resource: Option<Vec<u8>>,
    ) -> Result<Self, ResultError> {
        if matches!(kind, MutationIntentKind::Create) != expected_revision.is_none() {
            return Err(ResultError::InvalidExpectedRevision);
        }
        if expected_revision.is_some_and(|revision| revision.get() == 0) {
            return Err(ResultError::InvalidExpectedRevision);
        }
        if matches!(kind, MutationIntentKind::Create) != expected_uid.is_none() {
            return Err(ResultError::InvalidExpectedUid);
        }
        if canonical_resource.as_ref().is_some_and(Vec::is_empty) {
            return Err(ResultError::EmptyMutationPayload);
        }
        if canonical_resource
            .as_ref()
            .is_some_and(|payload| payload.len() > MAX_RESOURCE_ENVELOPE_BYTES)
        {
            return Err(ResultError::MutationPayloadTooLarge);
        }
        Ok(Self {
            target,
            expected_uid,
            expected_revision,
            kind,
            canonical_resource,
        })
    }

    /// Borrow the target reference.
    pub const fn target(&self) -> &ResourceRef {
        &self.target
    }

    /// Borrow the expected UID.
    pub fn expected_uid(&self) -> Option<&ResourceUid> {
        self.expected_uid.as_ref()
    }

    /// Return the exact optimistic revision, if this is not a create.
    pub const fn expected_revision(&self) -> Option<ZoneRevision> {
        self.expected_revision
    }

    /// Return the mutation class.
    pub const fn kind(&self) -> MutationIntentKind {
        self.kind
    }

    /// Borrow canonical replacement bytes.
    pub fn canonical_resource(&self) -> Option<&[u8]> {
        self.canonical_resource.as_deref()
    }
}

impl core::fmt::Debug for MutationIntent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MutationIntent")
            .field("target_type", self.target.resource_type())
            .field("has_expected_uid", &self.expected_uid.is_some())
            .field("expected_revision", &self.expected_revision)
            .field("kind", &self.kind)
            .field(
                "canonical_resource",
                &self
                    .canonical_resource
                    .as_ref()
                    .map(|bytes| format_args!("<{} bytes>", bytes.len()).to_string()),
            )
            .finish()
    }
}

/// Atomic, bounded mutation batch.
#[derive(Clone, PartialEq, Eq)]
pub struct ResourceMutationBatch {
    mutations: Vec<MutationIntent>,
}

impl ResourceMutationBatch {
    /// Validate a nonempty batch against the contract bound.
    pub fn new(mutations: Vec<MutationIntent>) -> Result<Self, ResultError> {
        if mutations.is_empty() {
            return Err(ResultError::EmptyMutationBatch);
        }
        if mutations.len() > MAX_BATCH_MUTATIONS {
            return Err(ResultError::MutationBatchTooLarge);
        }
        let mut targets = BTreeSet::new();
        if mutations
            .iter()
            .any(|mutation| !targets.insert(&mutation.target))
        {
            return Err(ResultError::DuplicateMutationTarget);
        }
        if total_payload_bytes(&mutations) > MAX_REQUEST_CANONICAL_BYTES {
            return Err(ResultError::MutationBatchPayloadTooLarge);
        }
        Ok(Self { mutations })
    }

    /// Borrow mutations in transaction order.
    pub fn mutations(&self) -> &[MutationIntent] {
        &self.mutations
    }

    /// Return the total canonical payload size in this transaction.
    pub fn payload_bytes(&self) -> usize {
        total_payload_bytes(&self.mutations)
    }

    pub(crate) fn validate_against(
        &self,
        target: &ResourceKey,
        revision: ZoneRevision,
    ) -> Result<(), ResultError> {
        if self.mutations.iter().any(|mutation| {
            mutation.target == *target.resource_ref()
                && (mutation.expected_uid.as_ref() != Some(target.uid())
                    || mutation.expected_revision != Some(revision))
        }) {
            return Err(ResultError::MutationFenceMismatch);
        }
        Ok(())
    }
}

fn total_payload_bytes(mutations: &[MutationIntent]) -> usize {
    mutations
        .iter()
        .filter_map(|mutation| mutation.canonical_resource.as_ref())
        .fold(0usize, |total, payload| total.saturating_add(payload.len()))
}

impl core::fmt::Debug for ResourceMutationBatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ResourceMutationBatch")
            .field("mutation_count", &self.mutations.len())
            .finish()
    }
}

/// One ordinary reconcile disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileDisposition {
    Converged,
    Pending,
    Degraded,
    FailedRetryable,
    FailedTerminal,
    RequeueAt,
    Finalized,
}

impl ReconcileDisposition {
    /// Whether a no-mutation result is terminal and may be checkpointed.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Converged | Self::Degraded | Self::FailedTerminal | Self::Finalized
        )
    }
}

/// Whether an emitted status candidate has reached durable storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusPersistence {
    NotRequested,
    Pending,
}

/// Expedited one-pass projection disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionDisposition {
    Converged,
    Progressing,
    Blocked,
    UpgradeRequired,
    Failed,
}

/// Closed, redacted pass outcome reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileReason {
    Deleted,
    InvalidSpec,
    UpgradeRequired,
    ReconcilePass,
    HandlerRetryable,
    HandlerExhausted,
    HandlerTerminal,
    DeadlineExceeded,
    Cancelled,
    ConflictExhausted,
}

impl ReconcileReason {
    /// Return the bounded stable reason code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Deleted => "deleted",
            Self::InvalidSpec => "invalid-spec",
            Self::UpgradeRequired => "upgrade-required",
            Self::ReconcilePass => "reconcile-pass",
            Self::HandlerRetryable => "handler-retryable",
            Self::HandlerExhausted => "handler-exhausted",
            Self::HandlerTerminal => "handler-terminal",
            Self::DeadlineExceeded => "deadline-exceeded",
            Self::Cancelled => "cancelled",
            Self::ConflictExhausted => "conflict-exhausted",
        }
    }

    /// Return generic operator remediation with no resource identity.
    pub const fn remediation(self) -> &'static str {
        match self {
            Self::Deleted | Self::ReconcilePass => "no remediation required",
            Self::InvalidSpec => "correct the declared specification and retry reconciliation",
            Self::UpgradeRequired => "schedule the required upgrade operation",
            Self::HandlerRetryable => "check controller health and retry reconciliation",
            Self::HandlerExhausted => {
                "check controller health before explicitly retrying reconciliation"
            }
            Self::HandlerTerminal => "check controller configuration before retrying",
            Self::DeadlineExceeded => "check controller dependencies and retry reconciliation",
            Self::Cancelled => "retry reconciliation after shutdown completes",
            Self::ConflictExhausted => "inspect concurrent updates and retry reconciliation",
        }
    }
}

/// Bounded response returned by an expedited pass.
#[derive(Clone, PartialEq, Eq)]
pub struct ReconcileProjection {
    target: ResourceKey,
    revision: ZoneRevision,
    phase: ResourcePhase,
    disposition: ProjectionDisposition,
    reason: ReconcileReason,
    event_only: bool,
}

impl ReconcileProjection {
    /// Construct a projection containing no unbounded Provider payload.
    pub fn new(
        target: ResourceKey,
        revision: ZoneRevision,
        phase: ResourcePhase,
        disposition: ProjectionDisposition,
        reason: ReconcileReason,
        event_only: bool,
    ) -> Self {
        Self {
            target,
            revision,
            phase,
            disposition,
            reason,
            event_only,
        }
    }

    /// Borrow the target.
    pub const fn target(&self) -> &ResourceKey {
        &self.target
    }

    /// Return the projected revision.
    pub const fn revision(&self) -> ZoneRevision {
        self.revision
    }

    /// Return the projected phase.
    pub const fn phase(&self) -> ResourcePhase {
        self.phase
    }

    /// Return the one-pass disposition.
    pub const fn disposition(&self) -> ProjectionDisposition {
        self.disposition
    }

    /// Return the closed failure or progress reason.
    pub const fn reason(&self) -> ReconcileReason {
        self.reason
    }

    /// Return the bounded stable reason code.
    pub const fn reason_code(&self) -> &'static str {
        self.reason.code()
    }

    /// Return generic remediation guidance.
    pub const fn remediation(&self) -> &'static str {
        self.reason.remediation()
    }

    /// Whether this projection came from a deletion event without an object body.
    pub const fn event_only(&self) -> bool {
        self.event_only
    }
}

impl core::fmt::Debug for ReconcileProjection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReconcileProjection")
            .field("target", &self.target)
            .field("revision", &self.revision)
            .field("phase", &self.phase)
            .field("disposition", &self.disposition)
            .field("reason_code", &self.reason.code())
            .field("event_only", &self.event_only)
            .finish()
    }
}

/// Complete output of one handler pass.
#[derive(Clone, PartialEq, Eq)]
pub struct ReconcileResult {
    processed_revision: ZoneRevision,
    processed_generation: ResourceGeneration,
    /// The only Resource API mutation transaction in this result.
    mutation_batch: Option<ResourceMutationBatch>,
    /// A status projection committed with the result transaction when present.
    status_candidate: Option<Vec<u8>>,
    disposition: ReconcileDisposition,
    next_tick: Option<u64>,
    projection: Option<ReconcileProjection>,
    status_persistence: StatusPersistence,
}

impl ReconcileResult {
    /// Construct and validate a reconcile result.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        processed_revision: ZoneRevision,
        processed_generation: ResourceGeneration,
        mutation_batch: Option<ResourceMutationBatch>,
        status_candidate: Option<Vec<u8>>,
        disposition: ReconcileDisposition,
        next_tick: Option<u64>,
        projection: Option<ReconcileProjection>,
        status_persistence: StatusPersistence,
    ) -> Result<Self, ResultError> {
        if matches!(disposition, ReconcileDisposition::RequeueAt) != next_tick.is_some() {
            return Err(ResultError::InvalidRequeue);
        }
        if status_candidate.as_ref().is_some_and(Vec::is_empty) {
            return Err(ResultError::EmptyStatusCandidate);
        }
        if status_candidate
            .as_ref()
            .is_some_and(|candidate| candidate.len() > MAX_STATUS_BYTES)
        {
            return Err(ResultError::StatusCandidateTooLarge);
        }
        if status_candidate.is_some() && status_persistence != StatusPersistence::Pending {
            return Err(ResultError::InvalidStatusPersistence);
        }
        if status_candidate.is_none() && status_persistence == StatusPersistence::Pending {
            return Err(ResultError::InvalidStatusPersistence);
        }
        Ok(Self {
            processed_revision,
            processed_generation,
            mutation_batch,
            status_candidate,
            disposition,
            next_tick,
            projection,
            status_persistence,
        })
    }

    /// Build a terminal no-mutation convergence result.
    pub fn converged(revision: ZoneRevision, generation: ResourceGeneration) -> ReconcileResult {
        Self {
            processed_revision: revision,
            processed_generation: generation,
            mutation_batch: None,
            status_candidate: None,
            disposition: ReconcileDisposition::Converged,
            next_tick: None,
            projection: None,
            status_persistence: StatusPersistence::NotRequested,
        }
    }

    /// Build a non-mutating upgrade-required outcome.
    pub fn upgrade_required(
        revision: ZoneRevision,
        generation: ResourceGeneration,
        projection: Option<ReconcileProjection>,
    ) -> Self {
        Self {
            processed_revision: revision,
            processed_generation: generation,
            mutation_batch: None,
            status_candidate: None,
            disposition: ReconcileDisposition::Pending,
            next_tick: None,
            projection,
            status_persistence: StatusPersistence::NotRequested,
        }
    }

    /// Build a terminal schema or semantic validation failure.
    pub fn failed_terminal(
        revision: ZoneRevision,
        generation: ResourceGeneration,
        projection: Option<ReconcileProjection>,
    ) -> Self {
        Self {
            processed_revision: revision,
            processed_generation: generation,
            mutation_batch: None,
            status_candidate: None,
            disposition: ReconcileDisposition::FailedTerminal,
            next_tick: None,
            projection,
            status_persistence: StatusPersistence::NotRequested,
        }
    }

    /// Return the exact processed revision.
    pub const fn processed_revision(&self) -> ZoneRevision {
        self.processed_revision
    }

    /// Return the exact processed generation.
    pub const fn processed_generation(&self) -> ResourceGeneration {
        self.processed_generation
    }

    /// Borrow the optional atomic mutation batch.
    pub const fn mutation_batch(&self) -> Option<&ResourceMutationBatch> {
        self.mutation_batch.as_ref()
    }

    /// Attach the single Resource API mutation transaction to this result.
    pub fn with_mutation_batch(
        mut self,
        mutation_batch: ResourceMutationBatch,
    ) -> Result<Self, ResultError> {
        if self.mutation_batch.is_some() {
            return Err(ResultError::MultipleMutationTransactions);
        }
        self.mutation_batch = Some(mutation_batch);
        Ok(self)
    }

    /// Return the number of Resource API mutation transactions in this result.
    pub const fn mutation_transaction_count(&self) -> usize {
        if self.mutation_batch.is_some() { 1 } else { 0 }
    }

    /// Borrow a layered status candidate.
    pub fn status_candidate(&self) -> Option<&[u8]> {
        self.status_candidate.as_deref()
    }

    /// Return the disposition.
    pub const fn disposition(&self) -> ReconcileDisposition {
        self.disposition
    }

    /// Return the monotonic requeue tick.
    pub const fn next_tick(&self) -> Option<u64> {
        self.next_tick
    }

    /// Borrow the expedited projection.
    pub const fn projection(&self) -> Option<&ReconcileProjection> {
        self.projection.as_ref()
    }

    /// Return status persistence state.
    pub const fn status_persistence(&self) -> StatusPersistence {
        self.status_persistence
    }

    pub(crate) fn attach_projection(
        &mut self,
        projection: ReconcileProjection,
    ) -> Result<(), ResultError> {
        if self.projection.is_some() || projection.revision != self.processed_revision {
            return Err(ResultError::InvalidProjection);
        }
        self.projection = Some(projection);
        Ok(())
    }

    /// Whether durable commit is required before checkpoint.
    pub fn requires_commit(&self) -> bool {
        self.mutation_batch.is_some() || self.status_candidate.is_some()
    }
}

impl core::fmt::Debug for ReconcileResult {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReconcileResult")
            .field("processed_revision", &self.processed_revision)
            .field("processed_generation", &self.processed_generation)
            .field("has_mutation_batch", &self.mutation_batch.is_some())
            .field(
                "status_candidate",
                &self
                    .status_candidate
                    .as_ref()
                    .map(|bytes| format_args!("<{} bytes>", bytes.len()).to_string()),
            )
            .field("disposition", &self.disposition)
            .field("next_tick", &self.next_tick)
            .field("projection", &self.projection)
            .field("status_persistence", &self.status_persistence)
            .finish()
    }
}

/// Result of schema and semantic validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationResult {
    Valid,
    Invalid { reason: ReconcileReason },
}

/// Effect-free plan produced before ordinary or expedited reconcile.
///
/// A non-no-op plan with no effect IDs is a mutation-only pass and does not
/// require operation-ledger acceptance.
#[derive(Clone, PartialEq, Eq)]
pub struct ReconcilePlan {
    effect_ids: Vec<String>,
    no_op: bool,
}

impl ReconcilePlan {
    /// Construct a bounded plan.
    pub fn new(effect_ids: Vec<String>, no_op: bool) -> Result<Self, ResultError> {
        if effect_ids.len() > 64
            || effect_ids
                .iter()
                .any(|effect| effect.is_empty() || effect.len() > 256)
        {
            return Err(ResultError::PlanTooLarge);
        }
        Ok(Self { effect_ids, no_op })
    }

    /// Whether the handler can converge without an external effect.
    pub const fn is_no_op(&self) -> bool {
        self.no_op
    }

    /// Number of planned effect identities.
    pub fn effect_count(&self) -> usize {
        self.effect_ids.len()
    }
}

impl core::fmt::Debug for ReconcilePlan {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReconcilePlan")
            .field("effect_count", &self.effect_ids.len())
            .field("no_op", &self.no_op)
            .finish()
    }
}

/// External observation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationResult {
    result: ReconcileResult,
}

impl ObservationResult {
    /// Wrap a normal result from an observe pass.
    pub fn new(result: ReconcileResult) -> Self {
        Self { result }
    }

    /// Consume the observation.
    pub fn into_result(self) -> ReconcileResult {
        self.result
    }
}

/// Finalizer result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizeResult {
    result: ReconcileResult,
}

impl FinalizeResult {
    /// Wrap a normal result from a finalize pass.
    pub fn new(result: ReconcileResult) -> Self {
        Self { result }
    }

    /// Consume the finalizer result.
    pub fn into_result(self) -> ReconcileResult {
        self.result
    }
}

/// Closed controller health state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControllerHealth {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Drain completion state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainResult {
    Drained,
    DeadlineExceeded,
}

/// Update-currency assessment state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateAssessmentState {
    Current,
    NonDisruptive,
    UpgradeRequired,
}

/// One bounded update assessment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateAssessment {
    state: UpdateAssessmentState,
    reason_codes: Vec<&'static str>,
    preserve_state: bool,
}

impl UpdateAssessment {
    /// Construct an assessment.
    pub fn new(
        state: UpdateAssessmentState,
        reason_codes: Vec<&'static str>,
        preserve_state: bool,
    ) -> Result<Self, ResultError> {
        if reason_codes.len() > 32
            || reason_codes
                .iter()
                .any(|reason| reason.is_empty() || reason.len() > 64)
        {
            return Err(ResultError::InvalidReasonCode);
        }
        Ok(Self {
            state,
            reason_codes,
            preserve_state,
        })
    }

    /// Return the assessment state.
    pub const fn state(&self) -> UpdateAssessmentState {
        self.state
    }

    /// Whether stateful backing must survive a disruptive update.
    pub const fn preserve_state(&self) -> bool {
        self.preserve_state
    }

    /// Borrow stable assessment reason codes.
    pub fn reason_codes(&self) -> &[&'static str] {
        &self.reason_codes
    }
}

/// Disruption class for an explicit upgrade plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisruptionClass {
    None,
    Restart,
    Recycle,
    Replace,
}

/// One topologically ordered upgrade action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpgradeStage {
    Drain(ResourceRef),
    Recycle(ResourceRef),
    Restart(ResourceRef),
}

/// Bounded disruptive-upgrade plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradePlan {
    disruption: DisruptionClass,
    preserve_state: bool,
    stages: Vec<UpgradeStage>,
    preserved_resources: Vec<ResourceRef>,
}

impl UpgradePlan {
    /// Construct an ordered plan.
    pub fn new(
        disruption: DisruptionClass,
        preserve_state: bool,
        stages: Vec<UpgradeStage>,
    ) -> Result<Self, ResultError> {
        if stages.is_empty() || stages.len() > 192 {
            return Err(ResultError::InvalidUpgradePlan);
        }
        Ok(Self {
            disruption,
            preserve_state,
            stages,
            preserved_resources: Vec::new(),
        })
    }

    /// Bind durable state and identity resources that the plan must preserve.
    pub fn with_preserved_resources(
        mut self,
        mut resources: Vec<ResourceRef>,
    ) -> Result<Self, ResultError> {
        resources.sort();
        let original_len = resources.len();
        resources.dedup();
        if resources.len() != original_len || resources.len() > 64 || !self.preserve_state {
            return Err(ResultError::InvalidUpgradePlan);
        }
        self.preserved_resources = resources;
        Ok(self)
    }

    /// Return the disruption class.
    pub const fn disruption(&self) -> DisruptionClass {
        self.disruption
    }

    /// Whether durable backing is preserved.
    pub const fn preserve_state(&self) -> bool {
        self.preserve_state
    }

    /// Borrow ordered stages.
    pub fn stages(&self) -> &[UpgradeStage] {
        &self.stages
    }

    /// Borrow durable state and identity resources protected by the plan.
    pub fn preserved_resources(&self) -> &[ResourceRef] {
        &self.preserved_resources
    }
}

/// Invalid bounded result shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultError {
    InvalidExpectedRevision,
    InvalidExpectedUid,
    EmptyMutationPayload,
    MutationPayloadTooLarge,
    EmptyMutationBatch,
    MutationBatchTooLarge,
    MutationBatchPayloadTooLarge,
    DuplicateMutationTarget,
    MutationFenceMismatch,
    MultipleMutationTransactions,
    InvalidRequeue,
    EmptyStatusCandidate,
    StatusCandidateTooLarge,
    InvalidStatusPersistence,
    InvalidReasonCode,
    InvalidProjection,
    PlanTooLarge,
    InvalidUpgradePlan,
}

impl core::fmt::Display for ResultError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::InvalidExpectedRevision => "mutation expected revision does not match its kind",
            Self::InvalidExpectedUid => "mutation expected UID does not match its kind",
            Self::EmptyMutationPayload => "canonical mutation payload must not be empty",
            Self::MutationPayloadTooLarge => {
                "canonical mutation payload exceeds the resource bound"
            }
            Self::EmptyMutationBatch => "mutation batch must not be empty",
            Self::MutationBatchTooLarge => "mutation batch exceeds the contract bound",
            Self::MutationBatchPayloadTooLarge => {
                "mutation batch payload exceeds the request bound"
            }
            Self::DuplicateMutationTarget => "mutation batch contains a duplicate target",
            Self::MutationFenceMismatch => "self mutation fence does not match the fresh target",
            Self::MultipleMutationTransactions => {
                "reconcile result must contain at most one mutation transaction"
            }
            Self::InvalidRequeue => "requeue-at disposition requires exactly one next tick",
            Self::EmptyStatusCandidate => "status candidate must not be empty",
            Self::StatusCandidateTooLarge => "status candidate exceeds the status bound",
            Self::InvalidStatusPersistence => "status candidate persistence must remain pending",
            Self::InvalidReasonCode => "reason code is empty, oversized, or malformed",
            Self::InvalidProjection => "projection is duplicated or revision-mismatched",
            Self::PlanTooLarge => "reconcile plan exceeds its bound",
            Self::InvalidUpgradePlan => "upgrade plan is empty or exceeds its bound",
        })
    }
}

impl std::error::Error for ResultError {}

#[cfg(test)]
mod tests {
    use super::*;
    use d2b_contracts_resource::v3::{ResourceTypeName, ZoneId};

    fn key() -> ResourceKey {
        ResourceKey::new(
            ZoneId::parse("work").unwrap(),
            ResourceRef::parse("Process/app").unwrap(),
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap(),
        )
    }

    #[test]
    fn mutation_batch_enforces_nonempty_contract_bound() {
        assert_eq!(
            ResourceMutationBatch::new(Vec::new()).unwrap_err(),
            ResultError::EmptyMutationBatch
        );
        let mutation = MutationIntent::new(
            ResourceRef::parse("Process/app").unwrap(),
            None,
            None,
            MutationIntentKind::Create,
            Some(b"{}".to_vec()),
        )
        .unwrap();
        assert!(ResourceMutationBatch::new(vec![mutation; MAX_BATCH_MUTATIONS + 1]).is_err());
    }

    #[test]
    fn multiple_mutations_are_one_transaction_and_second_transaction_is_rejected() {
        let first = MutationIntent::new(
            ResourceRef::parse("Process/first").unwrap(),
            None,
            None,
            MutationIntentKind::Create,
            Some(b"{}".to_vec()),
        )
        .unwrap();
        let second = MutationIntent::new(
            ResourceRef::parse("Process/second").unwrap(),
            None,
            None,
            MutationIntentKind::Create,
            Some(b"{}".to_vec()),
        )
        .unwrap();
        let batch = ResourceMutationBatch::new(vec![first, second]).unwrap();
        assert_eq!(batch.mutations().len(), 2);

        let result =
            ReconcileResult::converged(ZoneRevision::new(1), ResourceGeneration::new(1).unwrap())
                .with_mutation_batch(batch.clone())
                .unwrap();
        assert_eq!(result.mutation_transaction_count(), 1);
        assert_eq!(
            result.with_mutation_batch(batch).unwrap_err(),
            ResultError::MultipleMutationTransactions
        );
    }

    #[test]
    fn mutation_items_require_exact_update_uid_and_unique_targets() {
        let target = ResourceRef::parse("Process/app").unwrap();
        assert_eq!(
            MutationIntent::new(
                target.clone(),
                None,
                Some(ZoneRevision::new(2)),
                MutationIntentKind::UpdateSpec,
                Some(b"{}".to_vec()),
            )
            .unwrap_err(),
            ResultError::InvalidExpectedUid
        );
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let first = MutationIntent::new(
            target.clone(),
            Some(uid.clone()),
            Some(ZoneRevision::new(2)),
            MutationIntentKind::UpdateSpec,
            Some(b"{}".to_vec()),
        )
        .unwrap();
        let second = MutationIntent::new(
            target,
            Some(uid),
            Some(ZoneRevision::new(2)),
            MutationIntentKind::UpdateStatus,
            Some(b"{}".to_vec()),
        )
        .unwrap();
        assert_eq!(
            ResourceMutationBatch::new(vec![first, second]).unwrap_err(),
            ResultError::DuplicateMutationTarget
        );
    }

    #[test]
    fn mutation_batch_bounds_total_payload_bytes() {
        let first = MutationIntent::new(
            ResourceRef::parse("Process/first").unwrap(),
            None,
            None,
            MutationIntentKind::Create,
            Some(vec![0; 200_000]),
        )
        .unwrap();
        let second = MutationIntent::new(
            ResourceRef::parse("Process/second").unwrap(),
            None,
            None,
            MutationIntentKind::Create,
            Some(vec![0; 200_000]),
        )
        .unwrap();
        let third = MutationIntent::new(
            ResourceRef::parse("Process/third").unwrap(),
            None,
            None,
            MutationIntentKind::Create,
            Some(vec![0; 200_000]),
        )
        .unwrap();
        assert_eq!(
            ResourceMutationBatch::new(vec![first, second, third]).unwrap_err(),
            ResultError::MutationBatchPayloadTooLarge
        );
    }

    #[test]
    fn self_mutations_must_match_the_fresh_uid_and_revision() {
        let mutation = MutationIntent::new(
            ResourceRef::parse("Process/app").unwrap(),
            Some(ResourceUid::parse("123e4567-e89b-42d3-a456-426614174001").unwrap()),
            Some(ZoneRevision::new(2)),
            MutationIntentKind::UpdateSpec,
            Some(b"{}".to_vec()),
        )
        .unwrap();
        let batch = ResourceMutationBatch::new(vec![mutation]).unwrap();
        assert_eq!(
            batch.validate_against(&key(), ZoneRevision::new(2)),
            Err(ResultError::MutationFenceMismatch)
        );
    }

    #[test]
    fn create_and_update_revision_shapes_are_distinct() {
        let target = ResourceRef::parse("Process/app").unwrap();
        assert!(
            MutationIntent::new(
                target.clone(),
                None,
                Some(ZoneRevision::new(2)),
                MutationIntentKind::Create,
                Some(b"{}".to_vec()),
            )
            .is_err()
        );
        assert!(
            MutationIntent::new(
                target,
                None,
                None,
                MutationIntentKind::UpdateStatus,
                Some(b"{}".to_vec()),
            )
            .is_err()
        );
    }

    #[test]
    fn status_candidate_is_explicitly_not_persisted_by_handler() {
        let result = ReconcileResult::new(
            ZoneRevision::new(2),
            ResourceGeneration::new(1).unwrap(),
            None,
            Some(b"{}".to_vec()),
            ReconcileDisposition::Pending,
            None,
            None,
            StatusPersistence::Pending,
        )
        .unwrap();

        assert_eq!(result.status_persistence(), StatusPersistence::Pending);
        assert!(result.requires_commit());
    }

    #[test]
    fn requeue_disposition_requires_one_tick() {
        assert_eq!(
            ReconcileResult::new(
                ZoneRevision::new(2),
                ResourceGeneration::new(1).unwrap(),
                None,
                None,
                ReconcileDisposition::RequeueAt,
                None,
                None,
                StatusPersistence::NotRequested,
            )
            .unwrap_err(),
            ResultError::InvalidRequeue
        );
    }

    #[test]
    fn mutation_and_status_payloads_enforce_contract_byte_bounds() {
        assert_eq!(
            MutationIntent::new(
                ResourceRef::parse("Process/app").unwrap(),
                None,
                None,
                MutationIntentKind::Create,
                Some(vec![0; MAX_RESOURCE_ENVELOPE_BYTES + 1]),
            )
            .unwrap_err(),
            ResultError::MutationPayloadTooLarge
        );
        assert_eq!(
            ReconcileResult::new(
                ZoneRevision::new(2),
                ResourceGeneration::new(1).unwrap(),
                None,
                Some(vec![0; MAX_STATUS_BYTES + 1]),
                ReconcileDisposition::Pending,
                None,
                None,
                StatusPersistence::Pending,
            )
            .unwrap_err(),
            ResultError::StatusCandidateTooLarge
        );
    }

    #[test]
    fn deletion_projection_can_be_event_only() {
        let projection = ReconcileProjection::new(
            key(),
            ZoneRevision::new(7),
            ResourcePhase::Deleted,
            ProjectionDisposition::Converged,
            ReconcileReason::Deleted,
            true,
        );

        assert!(projection.event_only());
        assert_eq!(projection.phase(), ResourcePhase::Deleted);
        assert_eq!(
            projection.target().resource_ref().resource_type(),
            &ResourceTypeName::parse("Process").unwrap()
        );
    }

    #[test]
    fn upgrade_plan_pins_preserve_state_and_order() {
        let guest = ResourceRef::parse("Guest/work").unwrap();
        let device = ResourceRef::parse("Device/gpu").unwrap();
        let state = ResourceRef::parse("Volume/state").unwrap();
        let tpm = ResourceRef::parse("Device/tpm").unwrap();
        let plan = UpgradePlan::new(
            DisruptionClass::Recycle,
            true,
            vec![
                UpgradeStage::Drain(guest.clone()),
                UpgradeStage::Recycle(device),
                UpgradeStage::Restart(guest),
            ],
        )
        .unwrap()
        .with_preserved_resources(vec![state.clone(), tpm.clone()])
        .unwrap();

        assert!(plan.preserve_state());
        assert_eq!(plan.stages().len(), 3);
        assert!(matches!(plan.stages()[0], UpgradeStage::Drain(_)));
        assert!(matches!(plan.stages()[2], UpgradeStage::Restart(_)));
        assert_eq!(plan.preserved_resources(), &[tpm, state]);
    }

    #[test]
    fn result_debug_never_includes_mutation_or_status_payload() {
        const PAYLOAD: &str = "result-debug-payload-sentinel";
        let mutation = MutationIntent::new(
            ResourceRef::parse("Process/app").unwrap(),
            None,
            None,
            MutationIntentKind::Create,
            Some(PAYLOAD.as_bytes().to_vec()),
        )
        .unwrap();
        let result = ReconcileResult::new(
            ZoneRevision::new(2),
            ResourceGeneration::new(1).unwrap(),
            Some(ResourceMutationBatch::new(vec![mutation]).unwrap()),
            Some(PAYLOAD.as_bytes().to_vec()),
            ReconcileDisposition::Pending,
            None,
            None,
            StatusPersistence::Pending,
        )
        .unwrap();

        assert_eq!(
            result.mutation_batch().unwrap().mutations()[0].canonical_resource(),
            Some(PAYLOAD.as_bytes())
        );
        assert_eq!(result.status_candidate(), Some(PAYLOAD.as_bytes()));
        let debug = format!("{result:?}");
        assert!(!debug.contains(PAYLOAD), "{debug}");
        assert!(debug.contains("<29 bytes>"), "{debug}");
    }
}
