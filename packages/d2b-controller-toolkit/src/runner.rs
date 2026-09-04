//! Store-watch driven async controller loop.

use std::{
    collections::HashSet,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use d2b_contracts_resource::v3::{
    ConfigurationGeneration, ResourceGeneration, ResourcePhase, ZoneId, ZoneRevision,
};

use crate::{
    Cancellation, CommittedRevisionProof, ContextError, ControllerDescriptor, ControllerHealth,
    ControllerIdentity, DependencySnapshot, DrainResult, FinalizeResult, ObservationResult,
    OperationContext, PendingQueue, PriorityLane, ProjectionDisposition, QueueError, QueueHint,
    QueuedWork, ReconcileContext, ReconcileDisposition, ReconcilePlan, ReconcileProjection,
    ReconcileReason, ReconcileResult, ResourceKey, ResourceSnapshot, StatusPersistence,
    TriggerReason, TriggerSet, UpdateAssessment, UpdateAssessmentState, UpgradePlan,
    ValidationResult,
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
};

/// Initial list entry.
#[derive(Clone, PartialEq, Eq)]
pub struct InitialResource {
    key: ResourceKey,
    revision: ZoneRevision,
}

impl InitialResource {
    /// Construct a listed identity at its snapshot revision.
    pub fn new(key: ResourceKey, revision: ZoneRevision) -> Self {
        Self { key, revision }
    }
}

impl core::fmt::Debug for InitialResource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InitialResource")
            .field("key", &self.key)
            .field("revision", &self.revision)
            .finish()
    }
}

/// Complete initial list plus the durable snapshot revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitialList {
    pub resources: Vec<InitialResource>,
    pub snapshot_revision: ZoneRevision,
}

/// Store-contract watch hint.
#[derive(Clone, PartialEq, Eq)]
pub struct WatchHint {
    key: ResourceKey,
    revision: ZoneRevision,
    reasons: TriggerSet,
    lane: PriorityLane,
    operation: OperationContext,
}

impl WatchHint {
    /// Construct a watch hint.
    pub fn new(
        key: ResourceKey,
        revision: ZoneRevision,
        reasons: TriggerSet,
        lane: PriorityLane,
        operation: OperationContext,
    ) -> Self {
        Self {
            key,
            revision,
            reasons,
            lane,
            operation,
        }
    }

    /// Borrow the watched resource identity.
    pub const fn key(&self) -> &ResourceKey {
        &self.key
    }

    /// Return the watched high-water revision.
    pub const fn revision(&self) -> ZoneRevision {
        self.revision
    }

    /// Borrow the coalesced trigger reasons.
    pub const fn reasons(&self) -> &TriggerSet {
        &self.reasons
    }

    /// Return the selected priority lane.
    pub const fn lane(&self) -> PriorityLane {
        self.lane
    }

    fn into_queue_hint(self) -> Result<QueueHint, QueueError> {
        QueueHint::new(
            self.key,
            self.revision,
            self.reasons,
            self.lane,
            self.operation,
        )
    }
}

impl core::fmt::Debug for WatchHint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WatchHint")
            .field("key", &self.key)
            .field("revision", &self.revision)
            .field("reasons", &self.reasons)
            .field("lane", &self.lane)
            .field("operation", &self.operation)
            .finish()
    }
}

/// One watch receiver event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchEvent {
    Hint(Box<WatchHint>),
    Closed,
}

/// Recoverable or fatal watch failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchFailure {
    Disconnected,
    RevisionExpired,
    Fatal,
}

/// Fresh read after a queue item wins dispatch.
#[derive(Clone, PartialEq, Eq)]
pub enum FreshSnapshot {
    Present {
        target: ResourceSnapshot,
        dependencies: Vec<DependencySnapshot>,
    },
    Deleted {
        key: ResourceKey,
        revision: ZoneRevision,
        generation: ResourceGeneration,
    },
}

impl core::fmt::Debug for FreshSnapshot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Present {
                target,
                dependencies,
            } => f
                .debug_struct("FreshSnapshot::Present")
                .field("target", target)
                .field("dependency_count", &dependencies.len())
                .finish(),
            Self::Deleted {
                key,
                revision,
                generation,
            } => f
                .debug_struct("FreshSnapshot::Deleted")
                .field("key", key)
                .field("revision", revision)
                .field("generation", generation)
                .finish(),
        }
    }
}

/// Expedited admission decision.
pub enum CommitDecision {
    Committed(CommittedRevisionProof),
    Abort,
}

impl CommitDecision {
    /// Borrow the committed Zone when durable evidence is present.
    pub const fn zone(&self) -> Option<&ZoneId> {
        match self {
            Self::Committed(proof) => Some(proof.zone()),
            Self::Abort => None,
        }
    }

    /// Borrow the operation ID for protocol correlation.
    pub fn operation_id(&self) -> Option<&str> {
        match self {
            Self::Committed(proof) => Some(proof.operation_id()),
            Self::Abort => None,
        }
    }
}

impl core::fmt::Debug for CommitDecision {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Committed(proof) => f
                .debug_struct("CommitDecision::Committed")
                .field("has_zone", &true)
                .field("has_resource_uid", &true)
                .field("generation", &proof.generation())
                .field("revision", &proof.revision())
                .field("has_operation_id", &true)
                .finish(),
            Self::Abort => f.write_str("CommitDecision::Abort"),
        }
    }
}

/// Durable commit outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitOutcome {
    Committed(ZoneRevision),
    CommittedStatusPending(ZoneRevision),
    Conflict(ZoneRevision),
}

/// Store-contract error with no backend handle or path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceError {
    Unavailable,
    Backpressure,
    Conflict(ZoneRevision),
    Cancelled,
    Timeout,
    Integrity,
}

impl core::fmt::Display for SourceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "resource plane unavailable",
            Self::Backpressure => "resource plane backpressure",
            Self::Conflict(_) => "resource revision conflict",
            Self::Cancelled => "resource operation cancelled",
            Self::Timeout => "resource operation timed out",
            Self::Integrity => "resource plane integrity failure",
        })
    }
}

impl std::error::Error for SourceError {}

/// Capability-limited store/watch seam used by the runner.
///
/// Implementations adapt the registered resource API. No method exposes a
/// database transaction, path, socket, or reusable authorization credential.
pub trait ControllerSource: Send + Sync + 'static {
    fn register(
        &self,
        descriptor: &ControllerDescriptor,
    ) -> impl Future<Output = Result<(), SourceError>> + Send;

    fn list_initial(
        &self,
        descriptor: &ControllerDescriptor,
    ) -> impl Future<Output = Result<InitialList, SourceError>> + Send;

    fn open_watch(
        &self,
        descriptor: &ControllerDescriptor,
        after_revision: ZoneRevision,
    ) -> impl Future<Output = Result<(), SourceError>> + Send;

    fn receive_watch(&self) -> impl Future<Output = Result<WatchEvent, WatchFailure>> + Send;

    fn read_fresh(
        &self,
        key: &ResourceKey,
    ) -> impl Future<Output = Result<FreshSnapshot, SourceError>> + Send;

    fn write_starting(
        &self,
        context: &ReconcileContext,
    ) -> impl Future<Output = Result<(), SourceError>> + Send;

    /// Durably accept the planned effect before the handler can start it.
    ///
    /// This is an operation-ledger transaction, not a Resource API mutation.
    /// Implementations must make acceptance idempotent for the context's
    /// operation identity.
    fn accept_effect(
        &self,
        _context: &ReconcileContext,
        _plan: &ReconcilePlan,
    ) -> impl Future<Output = Result<(), SourceError>> + Send {
        std::future::ready(Ok(()))
    }

    /// Persist the terminal lifecycle state of an accepted ordinary effect.
    fn complete_effect(
        &self,
        _context: &ReconcileContext,
        _result: &ReconcileResult,
    ) -> impl Future<Output = Result<(), SourceError>> + Send {
        std::future::ready(Ok(()))
    }

    /// Verify that the fresh target is the durable commit associated with the
    /// expedited operation.
    fn verify_expedited_commit(
        &self,
        _context: &ReconcileContext,
    ) -> impl Future<Output = Result<bool, SourceError>> + Send {
        std::future::ready(Ok(false))
    }

    /// Convert trusted durable verification into the private commit proof.
    fn await_expedited_commit(
        &self,
        context: &ReconcileContext,
    ) -> impl Future<Output = Result<CommitDecision, SourceError>> + Send {
        async move {
            if !self.verify_expedited_commit(context).await? {
                return Ok(CommitDecision::Abort);
            }
            Ok(CommitDecision::Committed(CommittedRevisionProof::issue(
                context.target().zone().clone(),
                context.target().uid().clone(),
                context.generation(),
                context.revision(),
                context.operation().operation_id().to_owned(),
            )))
        }
    }

    fn commit_result(
        &self,
        context: &ReconcileContext,
        result: &ReconcileResult,
    ) -> impl Future<Output = Result<CommitOutcome, SourceError>> + Send;

    fn complete_expedited(
        &self,
        context: &ReconcileContext,
        projection: &ReconcileProjection,
        status_persistence: StatusPersistence,
    ) -> impl Future<Output = Result<(), SourceError>> + Send;

    fn persist_outcome(
        &self,
        projection: &ReconcileProjection,
    ) -> impl Future<Output = Result<(), SourceError>> + Send;

    fn checkpoint(
        &self,
        context: &ReconcileContext,
        revision: ZoneRevision,
    ) -> impl Future<Output = Result<(), SourceError>> + Send;

    fn schedule_requeue(
        &self,
        key: &ResourceKey,
        at_tick: u64,
    ) -> impl Future<Output = Result<(), SourceError>> + Send;
}

/// Closed retry class for redacted controller failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandlerErrorClass {
    Retryable,
    Terminal,
}

/// Redacted handler failure propagated through worker completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandlerFailure {
    class: HandlerErrorClass,
    reason: ReconcileReason,
}

impl HandlerFailure {
    /// Construct a retryable handler failure.
    pub const fn retryable() -> Self {
        Self {
            class: HandlerErrorClass::Retryable,
            reason: ReconcileReason::HandlerRetryable,
        }
    }

    /// Construct a terminal handler failure.
    pub const fn terminal() -> Self {
        Self {
            class: HandlerErrorClass::Terminal,
            reason: ReconcileReason::HandlerTerminal,
        }
    }

    /// Return the closed retry class.
    pub const fn class(self) -> HandlerErrorClass {
        self.class
    }

    /// Return the closed redacted reason.
    pub const fn reason(self) -> ReconcileReason {
        self.reason
    }
}

/// Official asynchronous controller handler surface.
pub trait ResourceReconciler: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Map implementation errors into the closed redacted retry contract.
    fn classify_error(&self, _error: &Self::Error) -> HandlerFailure {
        HandlerFailure::retryable()
    }

    fn describe(&self) -> impl Future<Output = Result<ControllerDescriptor, Self::Error>> + Send;

    fn validate_spec(
        &self,
        context: &ReconcileContext,
        resource: &ResourceSnapshot,
    ) -> impl Future<Output = Result<ValidationResult, Self::Error>> + Send;

    fn plan(
        &self,
        context: &ReconcileContext,
        resource: &ResourceSnapshot,
        dependencies: &[DependencySnapshot],
    ) -> impl Future<Output = Result<ReconcilePlan, Self::Error>> + Send;

    /// Prepare resource mutations and the pass disposition without effects.
    fn reconcile(
        &self,
        context: &ReconcileContext,
        resource: &ResourceSnapshot,
        dependencies: &[DependencySnapshot],
        plan: &ReconcilePlan,
    ) -> impl Future<Output = Result<ReconcileResult, Self::Error>> + Send;

    /// Execute an accepted external effect and return its observation/status.
    fn execute_effect(
        &self,
        context: &ReconcileContext,
        resource: &ResourceSnapshot,
        dependencies: &[DependencySnapshot],
        plan: &ReconcilePlan,
    ) -> impl Future<Output = Result<ReconcileResult, Self::Error>> + Send {
        async move { self.reconcile(context, resource, dependencies, plan).await }
    }

    fn observe(
        &self,
        context: &ReconcileContext,
        resource: &ResourceSnapshot,
    ) -> impl Future<Output = Result<ObservationResult, Self::Error>> + Send;

    /// Legacy finalizer handler. New implementations split preparation and
    /// cleanup through [`Self::prepare_finalize`] and
    /// [`Self::execute_finalize`].
    fn finalize(
        &self,
        context: &ReconcileContext,
        deleting_resource: &ResourceSnapshot,
    ) -> impl Future<Output = Result<FinalizeResult, Self::Error>> + Send;

    /// Prepare finalization without starting cleanup effects.
    fn prepare_finalize(
        &self,
        _context: &ReconcileContext,
        deleting_resource: &ResourceSnapshot,
    ) -> impl Future<Output = Result<ReconcileResult, Self::Error>> + Send {
        std::future::ready(Ok(ReconcileResult::converged(
            deleting_resource.revision(),
            deleting_resource.generation(),
        )))
    }

    /// Execute finalization after operation acceptance.
    fn execute_finalize(
        &self,
        context: &ReconcileContext,
        deleting_resource: &ResourceSnapshot,
    ) -> impl Future<Output = Result<ReconcileResult, Self::Error>> + Send {
        async move {
            Ok(self
                .finalize(context, deleting_resource)
                .await?
                .into_result())
        }
    }

    fn health(&self) -> impl Future<Output = Result<ControllerHealth, Self::Error>> + Send;

    fn drain(
        &self,
        deadline_tick: u64,
    ) -> impl Future<Output = Result<DrainResult, Self::Error>> + Send;

    fn assess_update(
        &self,
        context: &ReconcileContext,
        resource: &ResourceSnapshot,
        dependencies: &[DependencySnapshot],
    ) -> impl Future<Output = Result<UpdateAssessment, Self::Error>> + Send;

    fn plan_upgrade(
        &self,
        context: &ReconcileContext,
        resource: &ResourceSnapshot,
        dependencies: &[DependencySnapshot],
    ) -> impl Future<Output = Result<UpgradePlan, Self::Error>> + Send;

    fn execute_upgrade(
        &self,
        context: &ReconcileContext,
        resource: &ResourceSnapshot,
        dependencies: &[DependencySnapshot],
        plan: &UpgradePlan,
    ) -> impl Future<Output = Result<ReconcileResult, Self::Error>> + Send;
}

/// Revisions and deadlines fixed by the registered session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunnerConfig {
    pub policy_revision: u64,
    pub api_revision: u64,
    pub configuration_revision: ConfigurationGeneration,
    pub deadline_tick: u64,
    pub max_attempts: u32,
}

/// Successful loop summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RunnerReport {
    pub dispatched: usize,
    pub checkpointed: usize,
    pub conflicts_retried: usize,
    pub relists: usize,
    pub handler_retries: usize,
    pub handler_failures: usize,
    pub committed_status_pending: usize,
}

/// Closed runner counter labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunnerCounter {
    QueueAdmitted,
    QueueCoalesced,
    QueueRejected,
    Relist,
    Retry,
    Exhaustion,
    WatchFailure,
}

/// Closed observation outcome labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunnerOutcome {
    Accepted,
    Coalesced,
    Rejected,
    Retrying,
    Exhausted,
    Failed,
    Succeeded,
}

/// Closed observation reason labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunnerObservationReason {
    None,
    Backpressure,
    WatchDisconnected,
    RevisionExpired,
    WatchFatal,
    Handler,
    Conflict,
    Deadline,
    Cancellation,
}

/// One cardinality-safe runner observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunnerObservation {
    pub counter: Option<RunnerCounter>,
    pub lane: Option<PriorityLane>,
    pub outcome: RunnerOutcome,
    pub reason: RunnerObservationReason,
    pub queue_depth: usize,
    pub active_workers: usize,
}

/// Continuous cardinality-safe runner observer.
pub trait RunnerObserver: Send + Sync + 'static {
    fn observe(&self, observation: RunnerObservation);
}

#[derive(Debug, Default)]
struct NoopObserver;

impl RunnerObserver for NoopObserver {
    fn observe(&self, _observation: RunnerObservation) {}
}

/// Injectable monotonic clock used for pass deadlines.
pub trait MonotonicClock: Send + Sync + 'static {
    fn now_tick(&self) -> u64;
    fn sleep_until(&self, deadline_tick: u64) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

#[derive(Debug)]
struct TokioClock {
    epoch: Instant,
}

impl Default for TokioClock {
    fn default() -> Self {
        Self {
            epoch: Instant::now(),
        }
    }
}

impl MonotonicClock for TokioClock {
    fn now_tick(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn sleep_until(&self, deadline_tick: u64) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        let delay = deadline_tick.saturating_sub(self.now_tick());
        Box::pin(tokio::time::sleep(Duration::from_millis(delay)))
    }
}

/// Controller-loop failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunnerError {
    InvalidDescriptor,
    Controller,
    Source(SourceError),
    Queue(QueueError),
    Context(ContextError),
    Cancelled,
    TaskFailed,
}

impl core::fmt::Display for RunnerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidDescriptor => f.write_str("controller descriptor bounds are invalid"),
            Self::Controller => f.write_str("controller handler failed"),
            Self::Source(error) => write!(f, "controller source failed: {error}"),
            Self::Queue(error) => write!(f, "controller queue failed: {error}"),
            Self::Context(error) => write!(f, "reconcile context failed: {error}"),
            Self::Cancelled => f.write_str("controller runner cancelled"),
            Self::TaskFailed => f.write_str("controller task failed"),
        }
    }
}

impl std::error::Error for RunnerError {}

impl From<SourceError> for RunnerError {
    fn from(value: SourceError) -> Self {
        Self::Source(value)
    }
}

impl From<QueueError> for RunnerError {
    fn from(value: QueueError) -> Self {
        Self::Queue(value)
    }
}

impl From<ContextError> for RunnerError {
    fn from(value: ContextError) -> Self {
        Self::Context(value)
    }
}

/// Terminal runner failure with the complete report accumulated before exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerFailure {
    error: RunnerError,
    report: RunnerReport,
    failed_key: Option<ResourceKey>,
    failed_operation: Option<&'static str>,
}

impl RunnerFailure {
    /// Return the terminal failure class.
    pub const fn error(&self) -> RunnerError {
        self.error
    }

    /// Return the final report snapshot.
    pub const fn report(&self) -> RunnerReport {
        self.report
    }

    /// Return the resource whose worker surfaced a source failure, if any.
    pub fn failed_key(&self) -> Option<&ResourceKey> {
        self.failed_key.as_ref()
    }

    /// Return the bounded source operation that surfaced a worker failure.
    pub const fn failed_operation(&self) -> Option<&'static str> {
        self.failed_operation
    }
}

impl core::fmt::Display for RunnerFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.error.fmt(f)
    }
}

impl std::error::Error for RunnerFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Async orchestration loop.
pub struct Runner<R, S> {
    reconciler: Arc<R>,
    source: Arc<S>,
    config: RunnerConfig,
    clock: Arc<dyn MonotonicClock>,
    observer: Arc<dyn RunnerObserver>,
}

type RunnerStartupCallback = Box<dyn FnOnce(Result<(), RunnerError>) + Send + 'static>;

impl<R, S> Runner<R, S>
where
    R: ResourceReconciler,
    S: ControllerSource,
{
    /// Bind a reconciler to its capability-limited source.
    pub fn new(reconciler: Arc<R>, source: Arc<S>, config: RunnerConfig) -> Self {
        Self {
            reconciler,
            source,
            config,
            clock: Arc::new(TokioClock::default()),
            observer: Arc::new(NoopObserver),
        }
    }

    /// Replace the default monotonic clock.
    pub fn with_clock(mut self, clock: Arc<dyn MonotonicClock>) -> Self {
        self.clock = clock;
        self
    }

    /// Attach a continuous cardinality-safe observer.
    pub fn with_observer(mut self, observer: Arc<dyn RunnerObserver>) -> Self {
        self.observer = observer;
        self
    }

    /// Register, list, watch, and reconcile until the watch closes and work drains.
    pub fn run(&self) -> RunnerFuture {
        self.run_with_startup_callback(None)
    }

    /// Register, list, and open the watch before reporting startup success.
    ///
    /// The callback is invoked exactly once for startup success or for a
    /// failure before the initial watch is admitted. Later runner failures
    /// remain the returned future's result.
    pub fn run_with_startup<F>(&self, startup: F) -> RunnerFuture
    where
        F: FnOnce(Result<(), RunnerError>) + Send + 'static,
    {
        self.run_with_startup_callback(Some(Box::new(startup)))
    }

    fn run_with_startup_callback(
        &self,
        mut startup: Option<RunnerStartupCallback>,
    ) -> RunnerFuture {
        let runner = Self {
            reconciler: Arc::clone(&self.reconciler),
            source: Arc::clone(&self.source),
            config: self.config,
            clock: Arc::clone(&self.clock),
            observer: Arc::clone(&self.observer),
        };
        let shutdown = Cancellation::default();
        let run_shutdown = shutdown.clone();
        let observer = Arc::clone(&self.observer);
        RunnerFuture {
            shutdown,
            inner: Box::pin(async move {
                let result = runner.run_inner(run_shutdown, &mut startup).await;
                observer.observe(RunnerObservation {
                    counter: None,
                    lane: None,
                    outcome: if result.is_ok() {
                        RunnerOutcome::Succeeded
                    } else {
                        RunnerOutcome::Failed
                    },
                    reason: match &result {
                        Err(failure) if failure.error() == RunnerError::Cancelled => {
                            RunnerObservationReason::Cancellation
                        }
                        Err(failure)
                            if failure.error() == RunnerError::Source(SourceError::Timeout) =>
                        {
                            RunnerObservationReason::Deadline
                        }
                        _ => RunnerObservationReason::None,
                    },
                    queue_depth: 0,
                    active_workers: 0,
                });
                result
            }),
        }
    }

    async fn run_inner(
        &self,
        shutdown: Cancellation,
        startup: &mut Option<RunnerStartupCallback>,
    ) -> Result<RunnerReport, RunnerFailure> {
        let mut report = RunnerReport::default();
        let mut failed_key = None;
        let mut failed_operation = None;
        match self
            .run_loop(
                shutdown,
                &mut report,
                startup,
                &mut failed_key,
                &mut failed_operation,
            )
            .await
        {
            Ok(()) => Ok(report),
            Err(error) => {
                if let Some(startup) = startup.take() {
                    startup(Err(error));
                }
                Err(RunnerFailure {
                    error,
                    report,
                    failed_key,
                    failed_operation,
                })
            }
        }
    }

    async fn run_loop(
        &self,
        shutdown: Cancellation,
        report: &mut RunnerReport,
        startup: &mut Option<RunnerStartupCallback>,
        failed_key: &mut Option<ResourceKey>,
        failed_operation: &mut Option<&'static str>,
    ) -> Result<(), RunnerError> {
        let startup_deadline = phase_deadline(self.clock.as_ref(), self.config.deadline_tick);
        let descriptor = bounded_phase(
            self.clock.as_ref(),
            startup_deadline,
            &shutdown,
            self.reconciler.describe(),
        )
        .await
        .map_err(phase_runner_error)?
        .map_err(|_| RunnerError::Controller)?;
        if self.config.max_attempts == 0 {
            return Err(RunnerError::InvalidDescriptor);
        }
        bounded_source(
            self.clock.as_ref(),
            startup_deadline,
            &shutdown,
            self.source.register(&descriptor),
        )
        .await?;
        let initial = bounded_source(
            self.clock.as_ref(),
            startup_deadline,
            &shutdown,
            self.source.list_initial(&descriptor),
        )
        .await?;
        bounded_source(
            self.clock.as_ref(),
            startup_deadline,
            &shutdown,
            self.source
                .open_watch(&descriptor, initial.snapshot_revision),
        )
        .await?;
        if let Some(startup) = startup.take() {
            startup(Ok(()));
        }

        let queue = Arc::new(PendingQueue::new(
            descriptor.max_pending_resources(),
            descriptor.max_expedited_per_resource(),
        ));
        queue.rebuild(initial_hints(&descriptor, initial.resources)?)?;

        let semaphore = Arc::new(Semaphore::new(descriptor.reconcile_concurrency()));
        let mut workers = OwnedWorkers::default();
        let mut watchers = JoinSet::new();
        spawn_watch(
            &mut watchers,
            Arc::clone(&self.source),
            Arc::clone(&self.clock),
            descriptor.execution().resync().resync_interval_ticks(),
            shutdown.clone(),
        );
        let mut watch_closed = false;
        let mut requeues = JoinSet::<(ResourceKey, ZoneRevision, OperationContext)>::new();
        let mut scheduled_keys = HashSet::new();

        loop {
            while let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() {
                let Some(work) = queue.pop_ready() else {
                    break;
                };
                report.dispatched += 1;
                let resource_policy = descriptor
                    .resources()
                    .iter()
                    .find(|policy| {
                        policy.resource_type() == work.key().resource_ref().resource_type()
                    })
                    .ok_or(RunnerError::InvalidDescriptor)?;
                workers.spawn(
                    WorkerRuntime {
                        reconciler: Arc::clone(&self.reconciler),
                        source: Arc::clone(&self.source),
                        clock: Arc::clone(&self.clock),
                        identity: descriptor.identity().clone(),
                        config: RunnerConfig {
                            deadline_tick: self
                                .config
                                .deadline_tick
                                .min(resource_policy.deadline_ticks()),
                            max_attempts: self
                                .config
                                .max_attempts
                                .min(resource_policy.max_attempts()),
                            ..self.config
                        },
                    },
                    work,
                    permit,
                );
                observe_gauge(
                    self.observer.as_ref(),
                    queue.resource_count(),
                    workers.len(),
                );
            }

            if watch_closed && workers.is_empty() && queue.is_empty() && requeues.is_empty() {
                watchers.shutdown().await;
                requeues.shutdown().await;
                return Ok(());
            }

            tokio::select! {
                biased;
                _ = shutdown.cancelled() => {
                    workers.shutdown().await;
                    watchers.shutdown().await;
                    requeues.shutdown().await;
                    return Err(RunnerError::Cancelled);
                }
                completion = workers.join_next(), if !workers.is_empty() => {
                    let completion = completion.ok_or(RunnerError::TaskFailed)??;
                    let key = completion.work.key().clone();
                    match completion.outcome {
                        WorkerOutcome::Done { checkpointed, status_pending, requeue_at } => {
                            queue.finish(&key)?;
                            if let Some(at_tick) = requeue_at {
                                if scheduled_keys.insert(key.clone()) {
                                    let clock = Arc::clone(&self.clock);
                                    let operation = completion.work.operation().clone();
                                    let revision = completion.work.high_water_revision();
                                    requeues.spawn(async move {
                                        clock.sleep_until(at_tick).await;
                                        (key, revision, operation)
                                    });
                                }
                            }
                            report.checkpointed += usize::from(checkpointed);
                            report.committed_status_pending += usize::from(status_pending);
                        }
                        WorkerOutcome::Retry { revision, reason } => {
                            if completion.work.attempt()
                                >= descriptor_attempt_bound(
                                    &descriptor,
                                    completion.work.key(),
                                    self.config.max_attempts,
                                )?
                            {
                                let persisted_reason =
                                    if reason == ReconcileReason::HandlerRetryable {
                                        ReconcileReason::HandlerExhausted
                                    } else {
                                        reason
                                    };
                                persist_exhaustion(
                                    self.source.as_ref(),
                                    self.clock.as_ref(),
                                    phase_deadline(self.clock.as_ref(), self.config.deadline_tick),
                                    &shutdown,
                                    completion.work.key(),
                                    revision.max(completion.work.high_water_revision()),
                                    persisted_reason,
                                ).await?;
                                queue.finish(&key)?;
                                report.handler_failures += 1;
                                observe_counter(
                                    self.observer.as_ref(),
                                    RunnerCounter::Exhaustion,
                                    Some(completion.work.lane()),
                                    RunnerOutcome::Exhausted,
                                    if reason == ReconcileReason::ConflictExhausted {
                                        RunnerObservationReason::Conflict
                                    } else {
                                        RunnerObservationReason::Handler
                                    },
                                    queue.resource_count(),
                                    workers.len(),
                                );
                            } else {
                                let lane = completion.work.lane();
                                queue.retry(completion.work, revision)?;
                                if reason == ReconcileReason::ConflictExhausted {
                                    report.conflicts_retried += 1;
                                } else {
                                    report.handler_retries += 1;
                                }
                                observe_counter(
                                    self.observer.as_ref(),
                                    RunnerCounter::Retry,
                                    Some(lane),
                                    RunnerOutcome::Retrying,
                                    if reason == ReconcileReason::ConflictExhausted {
                                        RunnerObservationReason::Conflict
                                    } else {
                                        RunnerObservationReason::Handler
                                    },
                                    queue.resource_count(),
                                    workers.len(),
                                );
                            }
                        }
                        WorkerOutcome::Terminal { projection } => {
                            bounded_source(
                                self.clock.as_ref(),
                                phase_deadline(self.clock.as_ref(), self.config.deadline_tick),
                                &shutdown,
                                self.source.persist_outcome(&projection),
                            ).await?;
                            queue.finish(&key)?;
                            report.handler_failures += 1;
                            observe_counter(
                                self.observer.as_ref(),
                                RunnerCounter::Exhaustion,
                                Some(completion.work.lane()),
                                RunnerOutcome::Exhausted,
                                RunnerObservationReason::Handler,
                                queue.resource_count(),
                                workers.len(),
                            );
                        }
                        WorkerOutcome::SourceFailed { error, operation } => {
                            *failed_key = Some(key.clone());
                            *failed_operation = Some(operation);
                            queue.finish(&key)?;
                            return Err(RunnerError::Source(error));
                        }
                    }
                    observe_gauge(
                        self.observer.as_ref(),
                        queue.resource_count(),
                        workers.len(),
                    );
                }
                scheduled = requeues.join_next(), if !requeues.is_empty() => {
                    let (key, revision, operation) = scheduled
                        .ok_or(RunnerError::TaskFailed)?
                        .map_err(|_| RunnerError::TaskFailed)?;
                    let hint = QueueHint::new(
                        key.clone(),
                        revision,
                        TriggerSet::new([TriggerReason::RetryDue]),
                        PriorityLane::Ordinary,
                        operation.clone(),
                    )?;
                    match queue.push(hint) {
                        Ok(_) => {
                            scheduled_keys.remove(&key);
                        }
                        Err(QueueError::Backpressure) => {
                            let clock = Arc::clone(&self.clock);
                            requeues.spawn(async move {
                                let retry_at = clock.now_tick().saturating_add(1);
                                clock.sleep_until(retry_at).await;
                                (key, revision, operation)
                            });
                        }
                        Err(error) => return Err(error.into()),
                    }
                    observe_gauge(
                        self.observer.as_ref(),
                        queue.resource_count(),
                        workers.len(),
                    );
                }
                watched = watchers.join_next(), if !watchers.is_empty() => {
                    let watched = watched
                        .ok_or(RunnerError::TaskFailed)?
                        .map_err(|_| RunnerError::TaskFailed)?;
                    match watched {
                Ok(WatchEvent::Hint(hint)) => {
                    if !descriptor_owns_key(&descriptor, &hint.key) {
                        return Err(RunnerError::Source(SourceError::Integrity));
                    }
                    let lane = hint.lane;
                    match queue.push((*hint).into_queue_hint()?) {
                        Ok(outcome) => {
                            observe_counter(
                                self.observer.as_ref(),
                                match outcome {
                                    crate::QueuePushOutcome::Admitted => RunnerCounter::QueueAdmitted,
                                    crate::QueuePushOutcome::Coalesced => RunnerCounter::QueueCoalesced,
                                },
                                Some(lane),
                                match outcome {
                                    crate::QueuePushOutcome::Admitted => RunnerOutcome::Accepted,
                                    crate::QueuePushOutcome::Coalesced => RunnerOutcome::Coalesced,
                                },
                                RunnerObservationReason::None,
                                queue.resource_count(),
                                workers.len(),
                            );
                        }
                        Err(error) => {
                            observe_counter(
                                self.observer.as_ref(),
                                RunnerCounter::QueueRejected,
                                Some(lane),
                                RunnerOutcome::Rejected,
                                RunnerObservationReason::Backpressure,
                                queue.resource_count(),
                                workers.len(),
                            );
                            return Err(error.into());
                        }
                    }
                    spawn_watch(
                        &mut watchers,
                        Arc::clone(&self.source),
                        Arc::clone(&self.clock),
                        descriptor.execution().resync().resync_interval_ticks(),
                        shutdown.clone(),
                    );
                }
                Ok(WatchEvent::Closed) => {
                    watch_closed = true;
                }
                Err(failure @ (WatchFailure::Disconnected | WatchFailure::RevisionExpired)) => {
                    observe_counter(
                        self.observer.as_ref(),
                        RunnerCounter::WatchFailure,
                        None,
                        RunnerOutcome::Failed,
                        match failure {
                            WatchFailure::Disconnected => RunnerObservationReason::WatchDisconnected,
                            WatchFailure::RevisionExpired => RunnerObservationReason::RevisionExpired,
                            WatchFailure::Fatal => RunnerObservationReason::WatchFatal,
                        },
                        queue.resource_count(),
                        workers.len(),
                    );
                    let relist = bounded_source(
                        self.clock.as_ref(),
                        phase_deadline(self.clock.as_ref(), self.config.deadline_tick),
                        &shutdown,
                        self.source.list_initial(&descriptor),
                    ).await?;
                    bounded_source(
                        self.clock.as_ref(),
                        phase_deadline(self.clock.as_ref(), self.config.deadline_tick),
                        &shutdown,
                        self.source.open_watch(&descriptor, relist.snapshot_revision),
                    ).await?;
                    queue.rebuild(initial_hints(&descriptor, relist.resources)?)?;
                    report.relists += 1;
                    watch_closed = false;
                    observe_counter(
                        self.observer.as_ref(),
                        RunnerCounter::Relist,
                        None,
                        RunnerOutcome::Accepted,
                        RunnerObservationReason::None,
                        queue.resource_count(),
                        workers.len(),
                    );
                    spawn_watch(
                        &mut watchers,
                        Arc::clone(&self.source),
                        Arc::clone(&self.clock),
                        descriptor.execution().resync().resync_interval_ticks(),
                        shutdown.clone(),
                    );
                }
                Err(WatchFailure::Fatal) => {
                    observe_counter(
                        self.observer.as_ref(),
                        RunnerCounter::WatchFailure,
                        None,
                        RunnerOutcome::Failed,
                        RunnerObservationReason::WatchFatal,
                        queue.resource_count(),
                        workers.len(),
                    );
                    return Err(RunnerError::Source(SourceError::Integrity));
                }
                    }
                }
            }
        }
    }
}

/// Executor-native future returned by [`Runner::run`].
pub struct RunnerFuture {
    shutdown: Cancellation,
    inner: Pin<Box<dyn Future<Output = Result<RunnerReport, RunnerFailure>> + Send>>,
}

impl RunnerFuture {
    /// Request cancellation and retain the future for a joined shutdown.
    pub fn cancel(&self) {
        self.shutdown.cancel();
    }
}

impl Future for RunnerFuture {
    type Output = Result<RunnerReport, RunnerFailure>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.as_mut().poll(context)
    }
}

impl Drop for RunnerFuture {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

impl core::fmt::Debug for RunnerFuture {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RunnerFuture(<redacted>)")
    }
}

fn descriptor_owns_key(descriptor: &ControllerDescriptor, key: &ResourceKey) -> bool {
    key.zone() == descriptor.identity().zone()
        && descriptor
            .resource_types()
            .any(|resource_type| resource_type == key.resource_ref().resource_type())
}

fn descriptor_attempt_bound(
    descriptor: &ControllerDescriptor,
    key: &ResourceKey,
    configured_bound: u32,
) -> Result<u32, RunnerError> {
    descriptor
        .resources()
        .iter()
        .find(|policy| policy.resource_type() == key.resource_ref().resource_type())
        .map(|policy| configured_bound.min(policy.max_attempts()))
        .ok_or(RunnerError::InvalidDescriptor)
}

fn initial_hints(
    descriptor: &ControllerDescriptor,
    resources: Vec<InitialResource>,
) -> Result<Vec<QueueHint>, RunnerError> {
    resources
        .into_iter()
        .map(|resource| {
            if !descriptor_owns_key(descriptor, &resource.key) {
                return Err(RunnerError::Source(SourceError::Integrity));
            }
            let canonical = resource.key.resource_ref().to_canonical_string();
            Ok(QueueHint::new(
                resource.key,
                resource.revision,
                TriggerSet::new([TriggerReason::StartupRelist]),
                PriorityLane::Ordinary,
                OperationContext::new(
                    format!("startup:{canonical}"),
                    format!("startup:{canonical}"),
                    format!("startup:{canonical}"),
                    None,
                )
                .map_err(|_| QueueError::InvalidHint)?,
            )?)
        })
        .collect()
}

struct WorkerCompletion {
    work: QueuedWork,
    outcome: WorkerOutcome,
    cancellation: Cancellation,
}

struct WorkerRuntime<R, S> {
    reconciler: Arc<R>,
    source: Arc<S>,
    clock: Arc<dyn MonotonicClock>,
    identity: ControllerIdentity,
    config: RunnerConfig,
}

enum WorkerOutcome {
    Done {
        checkpointed: bool,
        status_pending: bool,
        requeue_at: Option<u64>,
    },
    Retry {
        revision: ZoneRevision,
        reason: ReconcileReason,
    },
    Terminal {
        projection: ReconcileProjection,
    },
    SourceFailed {
        error: SourceError,
        operation: &'static str,
    },
}

#[derive(Default)]
struct OwnedWorkers {
    tasks: JoinSet<WorkerCompletion>,
    cancellations: Vec<Cancellation>,
}

impl OwnedWorkers {
    fn spawn<R, S>(
        &mut self,
        runtime: WorkerRuntime<R, S>,
        work: QueuedWork,
        permit: OwnedSemaphorePermit,
    ) where
        R: ResourceReconciler,
        S: ControllerSource,
    {
        let cancellation = Cancellation::default();
        self.cancellations.push(cancellation.clone());
        self.tasks.spawn(async move {
            let _permit = permit;
            let now_tick = runtime.clock.now_tick();
            let deadline_tick =
                phase_deadline(runtime.clock.as_ref(), runtime.config.deadline_tick);
            let work_config = RunnerConfig {
                deadline_tick,
                ..runtime.config
            };
            let outcome = match bounded_phase(
                runtime.clock.as_ref(),
                deadline_tick,
                &cancellation,
                execute_work_inner(
                    runtime.reconciler,
                    runtime.source,
                    runtime.identity,
                    work_config,
                    &work,
                    cancellation.clone(),
                    now_tick,
                ),
            )
            .await
            {
                Ok(outcome) => outcome,
                Err(PhaseStop::Deadline) => {
                    cancellation.cancel();
                    WorkerOutcome::Retry {
                        revision: work.high_water_revision(),
                        reason: ReconcileReason::DeadlineExceeded,
                    }
                }
                Err(PhaseStop::Cancelled) => {
                    cancellation.cancel();
                    WorkerOutcome::Terminal {
                        projection: failure_projection(
                            work.key().clone(),
                            work.high_water_revision(),
                            ReconcileReason::Cancelled,
                        ),
                    }
                }
            };
            WorkerCompletion {
                work,
                outcome,
                cancellation,
            }
        });
    }

    fn len(&self) -> usize {
        self.tasks.len()
    }

    fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    async fn join_next(&mut self) -> Option<Result<WorkerCompletion, RunnerError>> {
        let completion = self
            .tasks
            .join_next()
            .await
            .map(|result| result.map_err(|_| RunnerError::TaskFailed));
        if let Some(Ok(completion)) = completion.as_ref()
            && let Some(index) = self
                .cancellations
                .iter()
                .position(|candidate| candidate.shares_state(&completion.cancellation))
        {
            self.cancellations.swap_remove(index);
        }
        completion
    }

    fn cancel_all(&self) {
        for cancellation in &self.cancellations {
            cancellation.cancel();
        }
    }

    async fn shutdown(&mut self) {
        self.cancel_all();
        self.tasks.shutdown().await;
        self.cancellations.clear();
    }
}

impl Drop for OwnedWorkers {
    fn drop(&mut self) {
        self.cancel_all();
        self.tasks.abort_all();
    }
}

fn spawn_watch<S>(
    watchers: &mut JoinSet<Result<WatchEvent, WatchFailure>>,
    source: Arc<S>,
    clock: Arc<dyn MonotonicClock>,
    resync_interval_ticks: u64,
    shutdown: Cancellation,
) where
    S: ControllerSource,
{
    watchers.spawn(async move {
        let deadline = clock.now_tick().saturating_add(resync_interval_ticks);
        match bounded_phase(clock.as_ref(), deadline, &shutdown, source.receive_watch()).await {
            Ok(event) => event,
            Err(PhaseStop::Deadline) => Err(WatchFailure::RevisionExpired),
            Err(PhaseStop::Cancelled) => Err(WatchFailure::Fatal),
        }
    });
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PhaseStop {
    Deadline,
    Cancelled,
}

fn phase_deadline(clock: &dyn MonotonicClock, budget_ticks: u64) -> u64 {
    clock.now_tick().saturating_add(budget_ticks.max(1))
}

async fn bounded_phase<F>(
    clock: &dyn MonotonicClock,
    deadline_tick: u64,
    cancellation: &Cancellation,
    future: F,
) -> Result<F::Output, PhaseStop>
where
    F: Future + Send,
{
    if cancellation.is_cancelled() {
        return Err(PhaseStop::Cancelled);
    }
    if clock.now_tick() >= deadline_tick {
        return Err(PhaseStop::Deadline);
    }
    tokio::select! {
        value = future => Ok(value),
        _ = cancellation.cancelled() => Err(PhaseStop::Cancelled),
        _ = clock.sleep_until(deadline_tick) => Err(PhaseStop::Deadline),
    }
}

async fn bounded_source<F, T>(
    clock: &dyn MonotonicClock,
    deadline_tick: u64,
    cancellation: &Cancellation,
    future: F,
) -> Result<T, RunnerError>
where
    F: Future<Output = Result<T, SourceError>> + Send,
{
    match bounded_phase(clock, deadline_tick, cancellation, future).await {
        Ok(result) => result.map_err(RunnerError::Source),
        Err(PhaseStop::Deadline) => Err(RunnerError::Source(SourceError::Timeout)),
        Err(PhaseStop::Cancelled) => Err(RunnerError::Cancelled),
    }
}

fn phase_runner_error(stop: PhaseStop) -> RunnerError {
    match stop {
        PhaseStop::Deadline => RunnerError::Source(SourceError::Timeout),
        PhaseStop::Cancelled => RunnerError::Cancelled,
    }
}

fn failure_projection(
    key: ResourceKey,
    revision: ZoneRevision,
    reason: ReconcileReason,
) -> ReconcileProjection {
    ReconcileProjection::new(
        key,
        revision,
        ResourcePhase::Failed,
        ProjectionDisposition::Failed,
        reason,
        false,
    )
}

async fn persist_exhaustion<S>(
    source: &S,
    clock: &dyn MonotonicClock,
    deadline_tick: u64,
    cancellation: &Cancellation,
    key: &ResourceKey,
    revision: ZoneRevision,
    reason: ReconcileReason,
) -> Result<(), RunnerError>
where
    S: ControllerSource,
{
    let projection = failure_projection(key.clone(), revision, reason);
    bounded_source(
        clock,
        deadline_tick,
        cancellation,
        source.persist_outcome(&projection),
    )
    .await
}

fn observe_counter(
    observer: &dyn RunnerObserver,
    counter: RunnerCounter,
    lane: Option<PriorityLane>,
    outcome: RunnerOutcome,
    reason: RunnerObservationReason,
    queue_depth: usize,
    active_workers: usize,
) {
    observer.observe(RunnerObservation {
        counter: Some(counter),
        lane,
        outcome,
        reason,
        queue_depth,
        active_workers,
    });
}

fn observe_gauge(observer: &dyn RunnerObserver, queue_depth: usize, active_workers: usize) {
    observer.observe(RunnerObservation {
        counter: None,
        lane: None,
        outcome: RunnerOutcome::Accepted,
        reason: RunnerObservationReason::None,
        queue_depth,
        active_workers,
    });
}

fn handler_outcome<R>(
    reconciler: &R,
    error: &R::Error,
    key: &ResourceKey,
    revision: ZoneRevision,
) -> WorkerOutcome
where
    R: ResourceReconciler,
{
    let failure = reconciler.classify_error(error);
    match failure.class() {
        HandlerErrorClass::Retryable => WorkerOutcome::Retry {
            revision,
            reason: failure.reason(),
        },
        HandlerErrorClass::Terminal => WorkerOutcome::Terminal {
            projection: failure_projection(key.clone(), revision, failure.reason()),
        },
    }
}

async fn execute_work_inner<R, S>(
    reconciler: Arc<R>,
    source: Arc<S>,
    identity: ControllerIdentity,
    config: RunnerConfig,
    work: &QueuedWork,
    cancellation: Cancellation,
    now_tick: u64,
) -> WorkerOutcome
where
    R: ResourceReconciler,
    S: ControllerSource,
{
    let fresh = match source.read_fresh(work.key()).await {
        Ok(fresh) => fresh,
        Err(SourceError::Conflict(revision)) => {
            return WorkerOutcome::Retry {
                revision,
                reason: ReconcileReason::ConflictExhausted,
            };
        }
        Err(error) => {
            return WorkerOutcome::SourceFailed {
                error,
                operation: "read_fresh",
            };
        }
    };
    let (target, dependencies, event_only) = match fresh {
        FreshSnapshot::Present {
            target,
            dependencies,
        } => {
            if target.key() != work.key() {
                return WorkerOutcome::SourceFailed {
                    error: SourceError::Integrity,
                    operation: "read_fresh_identity",
                };
            }
            (target, dependencies, false)
        }
        FreshSnapshot::Deleted {
            key,
            revision,
            generation,
        } => {
            if &key != work.key() {
                return WorkerOutcome::SourceFailed {
                    error: SourceError::Integrity,
                    operation: "read_fresh_deleted_identity",
                };
            }
            (
                ResourceSnapshot::new(key, revision, generation, Vec::new(), true),
                Vec::new(),
                true,
            )
        }
    };

    let context_result = if work.lane() == PriorityLane::Expedited {
        ReconcileContext::expedited_pending(
            identity,
            &target,
            &dependencies,
            work.reasons().clone(),
            work.high_water_revision().max(target.revision()),
            work.operation().clone(),
            work.attempt(),
            now_tick,
            config.deadline_tick,
            cancellation.clone(),
            config.policy_revision,
            config.api_revision,
            config.configuration_revision,
        )
    } else {
        ReconcileContext::ordinary(
            identity,
            &target,
            &dependencies,
            work.reasons().clone(),
            work.high_water_revision().max(target.revision()),
            work.operation().clone(),
            work.attempt(),
            now_tick,
            config.deadline_tick,
            cancellation,
            config.policy_revision,
            config.api_revision,
            config.configuration_revision,
        )
    };
    let mut context = match context_result {
        Ok(context) => context,
        Err(_) => {
            return WorkerOutcome::Terminal {
                projection: failure_projection(
                    target.key().clone(),
                    target.revision(),
                    ReconcileReason::HandlerTerminal,
                ),
            };
        }
    };

    let deleting = target.deleting()
        || work.reasons().contains(TriggerReason::DeletionRequested);
    let validation = if deleting {
        ValidationResult::Valid
    } else {
        match reconciler.validate_spec(&context, &target).await {
            Ok(validation) => validation,
            Err(error) => {
                return handler_outcome(
                    reconciler.as_ref(),
                    &error,
                    target.key(),
                    target.revision(),
                );
            }
        }
    };
    let expedited_plan = if work.lane() == PriorityLane::Expedited
        && !deleting
        && matches!(validation, ValidationResult::Valid)
    {
        match reconciler.plan(&context, &target, &dependencies).await {
            Ok(plan) => Some(plan),
            Err(error) => {
                return handler_outcome(
                    reconciler.as_ref(),
                    &error,
                    target.key(),
                    target.revision(),
                );
            }
        }
    } else {
        None
    };

    if work.lane() == PriorityLane::Expedited {
        match source.await_expedited_commit(&context).await {
            Ok(CommitDecision::Committed(proof)) => {
                context = match context.bind_committed_proof(proof) {
                    Ok(context) => context,
                    Err(_) => {
                        return WorkerOutcome::Terminal {
                            projection: failure_projection(
                                target.key().clone(),
                                target.revision(),
                                ReconcileReason::HandlerTerminal,
                            ),
                        };
                    }
                };
            }
            Ok(CommitDecision::Abort) => {
                return WorkerOutcome::Done {
                    checkpointed: false,
                    status_pending: false,
                    requeue_at: None,
                };
            }
            Err(error) => {
                return WorkerOutcome::SourceFailed {
                    error,
                    operation: "await_expedited_commit",
                };
            }
        }
    }

    if let ValidationResult::Invalid { reason } = validation {
        let projection = Some(failure_projection(
            target.key().clone(),
            target.revision(),
            reason,
        ));
        return persist_result(
            source.as_ref(),
            &context,
            ReconcileResult::failed_terminal(target.revision(), target.generation(), projection),
        )
        .await;
    }

    if deleting {
        let prepared = match reconciler.prepare_finalize(&context, &target).await {
            Ok(result) => result,
            Err(error) => {
                return handler_outcome(
                    reconciler.as_ref(),
                    &error,
                    target.key(),
                    target.revision(),
                );
            }
        };
        if prepared.requires_commit() {
            return persist_result(source.as_ref(), &context, prepared).await;
        }
        let finalize_plan =
            ReconcilePlan::new(vec!["finalize".to_owned()], false).expect("bounded finalize plan");
        if !event_only {
            match source.accept_effect(&context, &finalize_plan).await {
                Ok(()) => {}
                Err(SourceError::Conflict(revision)) => {
                    return WorkerOutcome::Retry {
                        revision,
                        reason: ReconcileReason::ConflictExhausted,
                    };
                }
                Err(error) => {
                    return WorkerOutcome::SourceFailed {
                        error,
                        operation: "accept_effect_finalize",
                    };
                }
            }
        }
        let mut result = match reconciler.execute_finalize(&context, &target).await {
            Ok(result) => result,
            Err(error) => {
                return handler_outcome(
                    reconciler.as_ref(),
                    &error,
                    target.key(),
                    target.revision(),
                );
            }
        };
        if event_only && result.projection().is_none() {
            result = prepared;
        }
        if result.mutation_batch().is_some_and(|batch| {
            batch.mutations().iter().any(|mutation| {
                mutation.kind() != crate::MutationIntentKind::UpdateFinalizers
                    || mutation.target() != target.key().resource_ref()
            })
        }) {
            return WorkerOutcome::Terminal {
                projection: failure_projection(
                    target.key().clone(),
                    target.revision(),
                    ReconcileReason::HandlerTerminal,
                ),
            };
        }
        return persist_result(source.as_ref(), &context, result).await;
    }

    if work.reasons().contains(TriggerReason::UpgradeRequested) {
        let plan = match reconciler
            .plan_upgrade(&context, &target, &dependencies)
            .await
        {
            Ok(plan) => plan,
            Err(error) => {
                return handler_outcome(
                    reconciler.as_ref(),
                    &error,
                    target.key(),
                    target.revision(),
                );
            }
        };
        let acceptance_plan =
            ReconcilePlan::new(vec!["upgrade".to_owned()], false).expect("bounded upgrade plan");
        match source.accept_effect(&context, &acceptance_plan).await {
            Ok(()) => {}
            Err(SourceError::Conflict(revision)) => {
                return WorkerOutcome::Retry {
                    revision,
                    reason: ReconcileReason::ConflictExhausted,
                };
            }
            Err(error) => {
                return WorkerOutcome::SourceFailed {
                    error,
                    operation: "accept_effect_upgrade",
                };
            }
        }
        let result = match reconciler
            .execute_upgrade(&context, &target, &dependencies, &plan)
            .await
        {
            Ok(result) => result,
            Err(error) => {
                return handler_outcome(
                    reconciler.as_ref(),
                    &error,
                    target.key(),
                    target.revision(),
                );
            }
        };
        if result.mutation_batch().is_some() {
            return WorkerOutcome::Terminal {
                projection: failure_projection(
                    target.key().clone(),
                    target.revision(),
                    ReconcileReason::HandlerTerminal,
                ),
            };
        }
        return persist_result(source.as_ref(), &context, result).await;
    }

    if work.reasons().contains(TriggerReason::ScheduledObserve) {
        let result = match reconciler.observe(&context, &target).await {
            Ok(result) => result.into_result(),
            Err(error) => {
                return handler_outcome(
                    reconciler.as_ref(),
                    &error,
                    target.key(),
                    target.revision(),
                );
            }
        };
        return persist_result(source.as_ref(), &context, result).await;
    }

    if work.reasons().requires_update_assessment() {
        let assessment = match reconciler
            .assess_update(&context, &target, &dependencies)
            .await
        {
            Ok(assessment) => assessment,
            Err(error) => {
                return handler_outcome(
                    reconciler.as_ref(),
                    &error,
                    target.key(),
                    target.revision(),
                );
            }
        };
        if assessment.state() == UpdateAssessmentState::UpgradeRequired {
            let projection = if work.lane() == PriorityLane::Expedited {
                Some(ReconcileProjection::new(
                    target.key().clone(),
                    target.revision(),
                    ResourcePhase::Pending,
                    ProjectionDisposition::UpgradeRequired,
                    ReconcileReason::UpgradeRequired,
                    false,
                ))
            } else {
                None
            };
            return persist_result(
                source.as_ref(),
                &context,
                ReconcileResult::upgrade_required(
                    target.revision(),
                    target.generation(),
                    projection,
                ),
            )
            .await;
        }
    }

    let plan = if let Some(plan) = expedited_plan {
        plan
    } else {
        match reconciler.plan(&context, &target, &dependencies).await {
            Ok(plan) => plan,
            Err(error) => {
                return handler_outcome(
                    reconciler.as_ref(),
                    &error,
                    target.key(),
                    target.revision(),
                );
            }
        }
    };

    if plan.is_no_op() {
        return persist_result(
            source.as_ref(),
            &context,
            ReconcileResult::converged(target.revision(), target.generation()),
        )
        .await;
    }

    let prepared = match reconciler
        .reconcile(&context, &target, &dependencies, &plan)
        .await
    {
        Ok(result) => result,
        Err(error) => {
            return handler_outcome(reconciler.as_ref(), &error, target.key(), target.revision());
        }
    };
    if prepared.requires_commit() {
        return persist_result(source.as_ref(), &context, prepared).await;
    }

    let result = if plan.effect_count() > 0 {
        match source.accept_effect(&context, &plan).await {
            Ok(()) => {}
            Err(SourceError::Conflict(revision)) => {
                return WorkerOutcome::Retry {
                    revision,
                    reason: ReconcileReason::ConflictExhausted,
                };
            }
            Err(error) => {
                return WorkerOutcome::SourceFailed {
                    error,
                    operation: "accept_effect",
                };
            }
        }
        match reconciler
            .execute_effect(&context, &target, &dependencies, &plan)
            .await
        {
            Ok(result) => result,
            Err(error) => {
                return handler_outcome(
                    reconciler.as_ref(),
                    &error,
                    target.key(),
                    target.revision(),
                );
            }
        }
    } else {
        prepared
    };
    if result.mutation_batch().is_some() {
        return WorkerOutcome::Terminal {
            projection: failure_projection(
                target.key().clone(),
                target.revision(),
                ReconcileReason::HandlerTerminal,
            ),
        };
    }
    persist_result(source.as_ref(), &context, result).await
}

async fn persist_result<S>(
    source: &S,
    context: &ReconcileContext,
    mut result: ReconcileResult,
) -> WorkerOutcome
where
    S: ControllerSource,
{
    if result.processed_revision() != context.revision()
        || result.processed_generation() != context.generation()
        || result.projection().is_some_and(|projection| {
            projection.target() != context.target() || projection.revision() != context.revision()
        })
        || result.mutation_batch().is_some_and(|batch| {
            batch
                .validate_against(context.target(), context.revision())
                .is_err()
        })
    {
        return WorkerOutcome::Terminal {
            projection: failure_projection(
                context.target().clone(),
                context.revision(),
                ReconcileReason::HandlerTerminal,
            ),
        };
    }
    if result.projection().is_none()
        && (context.is_expedited()
            || matches!(
                result.disposition(),
                ReconcileDisposition::FailedRetryable | ReconcileDisposition::FailedTerminal
            ))
    {
        let (phase, disposition) = match result.disposition() {
            ReconcileDisposition::Converged => {
                (ResourcePhase::Ready, ProjectionDisposition::Converged)
            }
            ReconcileDisposition::Pending | ReconcileDisposition::RequeueAt => {
                (ResourcePhase::Pending, ProjectionDisposition::Progressing)
            }
            ReconcileDisposition::Degraded => {
                (ResourcePhase::Degraded, ProjectionDisposition::Blocked)
            }
            ReconcileDisposition::FailedRetryable | ReconcileDisposition::FailedTerminal => {
                (ResourcePhase::Failed, ProjectionDisposition::Failed)
            }
            ReconcileDisposition::Finalized => {
                (ResourcePhase::Deleted, ProjectionDisposition::Converged)
            }
        };
        let reason = match result.disposition() {
            ReconcileDisposition::FailedRetryable => ReconcileReason::HandlerRetryable,
            ReconcileDisposition::FailedTerminal => ReconcileReason::HandlerTerminal,
            _ => ReconcileReason::ReconcilePass,
        };
        let projection = ReconcileProjection::new(
            context.target().clone(),
            context.revision(),
            phase,
            disposition,
            reason,
            false,
        );
        if result.attach_projection(projection).is_err() {
            return WorkerOutcome::Terminal {
                projection: failure_projection(
                    context.target().clone(),
                    context.revision(),
                    ReconcileReason::HandlerTerminal,
                ),
            };
        }
    }

    let requeue_at = result.next_tick();
    if result.requires_commit() {
        match source.commit_result(context, &result).await {
            Ok(CommitOutcome::Committed(revision)) => {
                if revision < context.revision() {
                    return WorkerOutcome::SourceFailed {
                        error: SourceError::Integrity,
                        operation: "commit_revision_regressed",
                    };
                }
                if context.is_expedited()
                    && result.mutation_batch().is_none()
                    && let Err(error) = persist_projection(source, context, &result, None).await
                {
                    return WorkerOutcome::SourceFailed {
                        error,
                        operation: "persist_projection_expedited",
                    };
                }
                if !context.is_expedited() {
                    if let Err(error) = source.complete_effect(context, &result).await {
                        return WorkerOutcome::SourceFailed {
                            error,
                            operation: "complete_effect_after_commit",
                        };
                    }
                }
                if let Err(error) = source.checkpoint(context, revision).await {
                    return WorkerOutcome::SourceFailed {
                        error,
                        operation: "checkpoint_after_commit",
                    };
                }
                return WorkerOutcome::Done {
                    checkpointed: true,
                    status_pending: false,
                    requeue_at,
                };
            }
            Ok(CommitOutcome::CommittedStatusPending(revision)) => {
                if revision < context.revision() {
                    return WorkerOutcome::SourceFailed {
                        error: SourceError::Integrity,
                        operation: "commit_status_revision_regressed",
                    };
                }
                if context.is_expedited()
                    && result.mutation_batch().is_none()
                    && let Err(error) = persist_projection(
                        source,
                        context,
                        &result,
                        Some(StatusPersistence::Pending),
                    )
                    .await
                {
                    return WorkerOutcome::SourceFailed {
                        error,
                        operation: "persist_projection_pending",
                    };
                }
                if !context.is_expedited() {
                    if let Err(error) = source.complete_effect(context, &result).await {
                        return WorkerOutcome::SourceFailed {
                            error,
                            operation: "complete_effect_after_pending_commit",
                        };
                    }
                }
                if let Err(error) = source.checkpoint(context, revision).await {
                    return WorkerOutcome::SourceFailed {
                        error,
                        operation: "checkpoint_after_pending_commit",
                    };
                }
                return WorkerOutcome::Done {
                    checkpointed: true,
                    status_pending: true,
                    requeue_at,
                };
            }
            Ok(CommitOutcome::Conflict(revision)) | Err(SourceError::Conflict(revision)) => {
                return WorkerOutcome::Retry {
                    revision,
                    reason: ReconcileReason::ConflictExhausted,
                };
            }
            Err(error) => {
                return WorkerOutcome::SourceFailed {
                    error,
                    operation: "commit_result",
                };
            }
        }
    }

    if let Err(error) = persist_projection(source, context, &result, None).await {
        return WorkerOutcome::SourceFailed {
            error,
            operation: "persist_projection",
        };
    }
    if !context.is_expedited() {
        if let Err(error) = source.complete_effect(context, &result).await {
            return WorkerOutcome::SourceFailed {
                error,
                operation: "complete_effect",
            };
        }
    }
    if result.disposition().is_terminal()
        || result.next_tick().is_some()
        || result.disposition() == ReconcileDisposition::Pending
    {
        if let Err(error) = source
            .checkpoint(context, result.processed_revision())
            .await
        {
            return WorkerOutcome::SourceFailed {
                error,
                operation: "checkpoint",
            };
        }
        return WorkerOutcome::Done {
            checkpointed: true,
            status_pending: false,
            requeue_at,
        };
    }
    if result.disposition() == ReconcileDisposition::FailedRetryable {
        return WorkerOutcome::Retry {
            revision: result.processed_revision(),
            reason: ReconcileReason::HandlerRetryable,
        };
    }
    WorkerOutcome::Done {
        checkpointed: false,
        status_pending: false,
        requeue_at: None,
    }
}

async fn persist_projection<S>(
    source: &S,
    context: &ReconcileContext,
    result: &ReconcileResult,
    status_override: Option<StatusPersistence>,
) -> Result<(), SourceError>
where
    S: ControllerSource,
{
    if let Some(projection) = result.projection() {
        if context.is_expedited() {
            source
                .complete_expedited(
                    context,
                    projection,
                    status_override.unwrap_or(result.status_persistence()),
                )
                .await
        } else {
            source.persist_outcome(projection).await
        }
    } else if context.is_expedited() {
        Err(SourceError::Integrity)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, VecDeque},
        sync::{
            Mutex,
            atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
            mpsc,
        },
        thread,
        time::Duration,
    };

    use d2b_contracts_resource::v3::{
        ControllerGeneration, ResourceRef, ResourceTypeName, ResourceUid, ZoneId,
    };

    use super::*;
    use crate::{
        ControllerExecutionPolicy, ControllerSelector, ControllerVerb, DescriptorError,
        DisruptionClass, MutationIntent, MutationIntentKind, ReconcileDisposition,
        ResourceMutationBatch, ResourceRegistration, ResyncPolicy, SelectorField,
        StatusPersistence, UpgradeStage,
    };

    type FreshMap = BTreeMap<ResourceKey, FreshSnapshot>;
    type Harness = (
        Arc<FakeReconciler>,
        mpsc::Receiver<(ResourceKey, &'static str)>,
        Arc<FakeSource>,
        tokio::sync::mpsc::UnboundedSender<Result<WatchEvent, WatchFailure>>,
    );

    fn block_on<F: Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(8)
            .enable_all()
            .build()
            .unwrap()
            .block_on(future)
    }

    struct FakeSource {
        initial: Mutex<VecDeque<InitialList>>,
        fresh: Mutex<FreshMap>,
        watch_rx: tokio::sync::Mutex<
            tokio::sync::mpsc::UnboundedReceiver<Result<WatchEvent, WatchFailure>>,
        >,
        commit_released: AtomicBool,
        commit_notify: tokio::sync::Notify,
        block_reads: AtomicBool,
        reads_started: AtomicUsize,
        read_notify: tokio::sync::Notify,
        abort_expedited: AtomicBool,
        expedited_gate_error: AtomicBool,
        effect_acceptance_conflicts_remaining: AtomicUsize,
        conflicts_remaining: AtomicUsize,
        commit_status_pending: AtomicBool,
        commit_revision: AtomicU64,
        commits: AtomicUsize,
        effect_acceptances: AtomicUsize,
        expedited_completions: AtomicUsize,
        pending_completions: AtomicUsize,
        persisted_outcomes: Mutex<Vec<ReconcileProjection>>,
        checkpoints: AtomicUsize,
        starting: AtomicUsize,
        requeues: AtomicUsize,
        watch_opens: AtomicUsize,
    }

    impl FakeSource {
        fn new(
            initial: Vec<InitialList>,
            fresh: FreshMap,
        ) -> (
            Arc<Self>,
            tokio::sync::mpsc::UnboundedSender<Result<WatchEvent, WatchFailure>>,
        ) {
            let (watch_tx, watch_rx) = tokio::sync::mpsc::unbounded_channel();
            (
                Arc::new(Self {
                    initial: Mutex::new(initial.into()),
                    fresh: Mutex::new(fresh),
                    watch_rx: tokio::sync::Mutex::new(watch_rx),
                    commit_released: AtomicBool::new(false),
                    commit_notify: tokio::sync::Notify::new(),
                    block_reads: AtomicBool::new(false),
                    reads_started: AtomicUsize::new(0),
                    read_notify: tokio::sync::Notify::new(),
                    abort_expedited: AtomicBool::new(false),
                    expedited_gate_error: AtomicBool::new(false),
                    effect_acceptance_conflicts_remaining: AtomicUsize::new(0),
                    conflicts_remaining: AtomicUsize::new(0),
                    commit_status_pending: AtomicBool::new(false),
                    commit_revision: AtomicU64::new(10),
                    commits: AtomicUsize::new(0),
                    effect_acceptances: AtomicUsize::new(0),
                    expedited_completions: AtomicUsize::new(0),
                    pending_completions: AtomicUsize::new(0),
                    persisted_outcomes: Mutex::new(Vec::new()),
                    checkpoints: AtomicUsize::new(0),
                    starting: AtomicUsize::new(0),
                    requeues: AtomicUsize::new(0),
                    watch_opens: AtomicUsize::new(0),
                }),
                watch_tx,
            )
        }

        fn release_commit_gate(&self) {
            self.commit_released.store(true, Ordering::Release);
            self.commit_notify.notify_waiters();
        }
    }

    impl ControllerSource for FakeSource {
        fn register(
            &self,
            _descriptor: &ControllerDescriptor,
        ) -> impl Future<Output = Result<(), SourceError>> + Send {
            std::future::ready(Ok(()))
        }

        fn list_initial(
            &self,
            _descriptor: &ControllerDescriptor,
        ) -> impl Future<Output = Result<InitialList, SourceError>> + Send {
            std::future::ready(
                self.initial
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .pop_front()
                    .ok_or(SourceError::Unavailable),
            )
        }

        fn open_watch(
            &self,
            _descriptor: &ControllerDescriptor,
            _after_revision: ZoneRevision,
        ) -> impl Future<Output = Result<(), SourceError>> + Send {
            self.watch_opens.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(()))
        }

        async fn receive_watch(&self) -> Result<WatchEvent, WatchFailure> {
            self.watch_rx
                .lock()
                .await
                .recv()
                .await
                .unwrap_or(Ok(WatchEvent::Closed))
        }

        async fn read_fresh(&self, key: &ResourceKey) -> Result<FreshSnapshot, SourceError> {
            self.reads_started.fetch_add(1, Ordering::SeqCst);
            while self.block_reads.load(Ordering::Acquire) {
                let notified = self.read_notify.notified();
                if !self.block_reads.load(Ordering::Acquire) {
                    break;
                }
                notified.await;
            }
            self.fresh
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get(key)
                .cloned()
                .ok_or(SourceError::Unavailable)
        }

        fn write_starting(
            &self,
            _context: &ReconcileContext,
        ) -> impl Future<Output = Result<(), SourceError>> + Send {
            self.starting.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(()))
        }

        fn accept_effect(
            &self,
            _context: &ReconcileContext,
            _plan: &ReconcilePlan,
        ) -> impl Future<Output = Result<(), SourceError>> + Send {
            let remaining = self
                .effect_acceptance_conflicts_remaining
                .load(Ordering::SeqCst);
            if remaining > 0 {
                self.effect_acceptance_conflicts_remaining
                    .fetch_sub(1, Ordering::SeqCst);
                return std::future::ready(Err(SourceError::Conflict(ZoneRevision::new(9))));
            }
            self.effect_acceptances.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(()))
        }

        async fn await_expedited_commit(
            &self,
            context: &ReconcileContext,
        ) -> Result<CommitDecision, SourceError> {
            while !self.commit_released.load(Ordering::Acquire) {
                let notified = self.commit_notify.notified();
                if self.commit_released.load(Ordering::Acquire) {
                    break;
                }
                notified.await;
            }
            if self.expedited_gate_error.load(Ordering::SeqCst) {
                return Err(SourceError::Unavailable);
            }
            Ok(if self.abort_expedited.load(Ordering::SeqCst) {
                CommitDecision::Abort
            } else {
                CommitDecision::Committed(CommittedRevisionProof::issue(
                    context.target().zone().clone(),
                    context.target().uid().clone(),
                    context.generation(),
                    context.revision(),
                    context.operation().operation_id().to_owned(),
                ))
            })
        }

        fn commit_result(
            &self,
            _context: &ReconcileContext,
            result: &ReconcileResult,
        ) -> impl Future<Output = Result<CommitOutcome, SourceError>> + Send {
            self.commits.fetch_add(1, Ordering::SeqCst);
            let remaining = self.conflicts_remaining.load(Ordering::SeqCst);
            let outcome = if remaining > 0 {
                self.conflicts_remaining.fetch_sub(1, Ordering::SeqCst);
                CommitOutcome::Conflict(ZoneRevision::new(9))
            } else if self.commit_status_pending.load(Ordering::SeqCst)
                || result.status_persistence() == StatusPersistence::Pending
            {
                CommitOutcome::CommittedStatusPending(ZoneRevision::new(
                    self.commit_revision.load(Ordering::SeqCst),
                ))
            } else {
                CommitOutcome::Committed(ZoneRevision::new(
                    self.commit_revision.load(Ordering::SeqCst),
                ))
            };
            std::future::ready(Ok(outcome))
        }

        fn complete_expedited(
            &self,
            _context: &ReconcileContext,
            _projection: &ReconcileProjection,
            status_persistence: StatusPersistence,
        ) -> impl Future<Output = Result<(), SourceError>> + Send {
            self.expedited_completions.fetch_add(1, Ordering::SeqCst);
            if status_persistence == StatusPersistence::Pending {
                self.pending_completions.fetch_add(1, Ordering::SeqCst);
            }
            std::future::ready(Ok(()))
        }

        fn checkpoint(
            &self,
            _context: &ReconcileContext,
            _revision: ZoneRevision,
        ) -> impl Future<Output = Result<(), SourceError>> + Send {
            self.checkpoints.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(()))
        }

        fn persist_outcome(
            &self,
            projection: &ReconcileProjection,
        ) -> impl Future<Output = Result<(), SourceError>> + Send {
            self.persisted_outcomes
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(projection.clone());
            std::future::ready(Ok(()))
        }

        fn schedule_requeue(
            &self,
            _key: &ResourceKey,
            _at_tick: u64,
        ) -> impl Future<Output = Result<(), SourceError>> + Send {
            self.requeues.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(()))
        }
    }

    #[derive(Debug)]
    struct FakeError;

    impl core::fmt::Display for FakeError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("fake handler failed")
        }
    }

    impl std::error::Error for FakeError {}

    struct FakeReconciler {
        descriptor: ControllerDescriptor,
        entered_tx: mpsc::Sender<(ResourceKey, &'static str)>,
        release: Arc<Semaphore>,
        active: AtomicUsize,
        max_active: AtomicUsize,
        plan_count: AtomicUsize,
        assess_count: AtomicUsize,
        reconcile_count: AtomicUsize,
        observe_count: AtomicUsize,
        upgrade_count: AtomicUsize,
        finalizer_count: AtomicUsize,
        validation_valid: AtomicBool,
        handler_failures_remaining: AtomicUsize,
        handler_failure_terminal: AtomicBool,
        block_handlers: AtomicBool,
        no_op_after_first: AtomicBool,
        mutation_only: AtomicBool,
        assessment_state: Mutex<UpdateAssessmentState>,
        requeue_at: Mutex<Option<u64>>,
    }

    #[derive(Default)]
    struct RecordingObserver(Mutex<Vec<RunnerObservation>>);

    impl RunnerObserver for RecordingObserver {
        fn observe(&self, observation: RunnerObservation) {
            self.0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(observation);
        }
    }

    struct ActiveGuard<'a>(&'a AtomicUsize);

    impl Drop for ActiveGuard<'_> {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    impl FakeReconciler {
        async fn enter(&self, key: &ResourceKey, action: &'static str) {
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            let _active = ActiveGuard(&self.active);
            self.max_active.fetch_max(active, Ordering::SeqCst);
            self.entered_tx.send((key.clone(), action)).unwrap();
            if self.block_handlers.load(Ordering::SeqCst) {
                self.release.acquire().await.unwrap().forget();
            }
        }

        fn release(&self, count: usize) {
            self.release.add_permits(count);
        }
    }

    impl ResourceReconciler for FakeReconciler {
        type Error = FakeError;

        fn classify_error(&self, _error: &Self::Error) -> HandlerFailure {
            if self.handler_failure_terminal.load(Ordering::SeqCst) {
                HandlerFailure::terminal()
            } else {
                HandlerFailure::retryable()
            }
        }

        fn describe(
            &self,
        ) -> impl Future<Output = Result<ControllerDescriptor, Self::Error>> + Send {
            std::future::ready(Ok(self.descriptor.clone()))
        }

        fn validate_spec(
            &self,
            _context: &ReconcileContext,
            _resource: &ResourceSnapshot,
        ) -> impl Future<Output = Result<ValidationResult, Self::Error>> + Send {
            std::future::ready(Ok(if self.validation_valid.load(Ordering::SeqCst) {
                ValidationResult::Valid
            } else {
                ValidationResult::Invalid {
                    reason: ReconcileReason::InvalidSpec,
                }
            }))
        }

        fn plan(
            &self,
            _context: &ReconcileContext,
            _resource: &ResourceSnapshot,
            _dependencies: &[DependencySnapshot],
        ) -> impl Future<Output = Result<ReconcilePlan, Self::Error>> + Send {
            let failures = self.handler_failures_remaining.load(Ordering::SeqCst);
            if failures > 0 {
                self.handler_failures_remaining
                    .fetch_sub(1, Ordering::SeqCst);
                return std::future::ready(Err(FakeError));
            }
            let count = self.plan_count.fetch_add(1, Ordering::SeqCst);
            let mutation_only = self.mutation_only.load(Ordering::SeqCst);
            let requeue_at = self
                .requeue_at
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_some();
            std::future::ready(
                ReconcilePlan::new(
                    if mutation_only || requeue_at {
                        Vec::new()
                    } else if count > 0 && self.no_op_after_first.load(Ordering::SeqCst) {
                        Vec::new()
                    } else {
                        vec!["effect".to_owned()]
                    },
                    !mutation_only
                        && !requeue_at
                        && count > 0
                        && self.no_op_after_first.load(Ordering::SeqCst),
                )
                .map_err(|_| FakeError),
            )
        }

        async fn reconcile(
            &self,
            _context: &ReconcileContext,
            resource: &ResourceSnapshot,
            _dependencies: &[DependencySnapshot],
            _plan: &ReconcilePlan,
        ) -> Result<ReconcileResult, Self::Error> {
            if self.mutation_only.load(Ordering::SeqCst) {
                self.enter(resource.key(), "reconcile").await;
                self.reconcile_count.fetch_add(1, Ordering::SeqCst);
                let mutation = MutationIntent::new(
                    resource.key().resource_ref().clone(),
                    Some(resource.key().uid().clone()),
                    Some(resource.revision()),
                    MutationIntentKind::UpdateSpec,
                    Some(b"{}".to_vec()),
                )
                .map_err(|_| FakeError)?;
                return ReconcileResult::new(
                    resource.revision(),
                    resource.generation(),
                    Some(ResourceMutationBatch::new(vec![mutation]).map_err(|_| FakeError)?),
                    None,
                    ReconcileDisposition::Converged,
                    None,
                    None,
                    StatusPersistence::NotRequested,
                )
                .map_err(|_| FakeError);
            }
            let requeue_at = self
                .requeue_at
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
            if let Some(next_tick) = requeue_at {
                return ReconcileResult::new(
                    resource.revision(),
                    resource.generation(),
                    None,
                    None,
                    ReconcileDisposition::RequeueAt,
                    Some(next_tick),
                    None,
                    StatusPersistence::NotRequested,
                )
                .map_err(|_| FakeError);
            }
            Ok(ReconcileResult::converged(
                resource.revision(),
                resource.generation(),
            ))
        }

        async fn execute_effect(
            &self,
            context: &ReconcileContext,
            resource: &ResourceSnapshot,
            _dependencies: &[DependencySnapshot],
            _plan: &ReconcilePlan,
        ) -> Result<ReconcileResult, Self::Error> {
            context.authorize_effect().map_err(|_| FakeError)?;
            self.enter(resource.key(), "reconcile").await;
            self.reconcile_count.fetch_add(1, Ordering::SeqCst);
            ReconcileResult::new(
                resource.revision(),
                resource.generation(),
                None,
                Some(b"{}".to_vec()),
                ReconcileDisposition::Pending,
                None,
                None,
                StatusPersistence::Pending,
            )
            .map_err(|_| FakeError)
        }

        async fn observe(
            &self,
            context: &ReconcileContext,
            resource: &ResourceSnapshot,
        ) -> Result<ObservationResult, Self::Error> {
            context.authorize_effect().map_err(|_| FakeError)?;
            self.observe_count.fetch_add(1, Ordering::SeqCst);
            self.enter(resource.key(), "observe").await;
            Ok(ObservationResult::new(ReconcileResult::converged(
                resource.revision(),
                resource.generation(),
            )))
        }

        fn finalize(
            &self,
            context: &ReconcileContext,
            resource: &ResourceSnapshot,
        ) -> impl Future<Output = Result<FinalizeResult, Self::Error>> + Send {
            if context.authorize_effect().is_err() {
                return std::future::ready(Err(FakeError));
            }
            self.finalizer_count.fetch_add(1, Ordering::SeqCst);
            std::future::ready(finalizer_result(resource).map(FinalizeResult::new))
        }

        fn prepare_finalize(
            &self,
            _context: &ReconcileContext,
            resource: &ResourceSnapshot,
        ) -> impl Future<Output = Result<ReconcileResult, Self::Error>> + Send {
            let result = if resource.canonical_json().is_empty() {
                finalizer_result(resource)
            } else {
                Ok(ReconcileResult::converged(
                    resource.revision(),
                    resource.generation(),
                ))
            };
            std::future::ready(result)
        }

        async fn execute_finalize(
            &self,
            context: &ReconcileContext,
            resource: &ResourceSnapshot,
        ) -> Result<ReconcileResult, Self::Error> {
            Ok(self.finalize(context, resource).await?.into_result())
        }

        fn health(&self) -> impl Future<Output = Result<ControllerHealth, Self::Error>> + Send {
            std::future::ready(Ok(ControllerHealth::Healthy))
        }

        fn drain(
            &self,
            _deadline_tick: u64,
        ) -> impl Future<Output = Result<DrainResult, Self::Error>> + Send {
            std::future::ready(Ok(DrainResult::Drained))
        }

        fn assess_update(
            &self,
            _context: &ReconcileContext,
            _resource: &ResourceSnapshot,
            _dependencies: &[DependencySnapshot],
        ) -> impl Future<Output = Result<UpdateAssessment, Self::Error>> + Send {
            self.assess_count.fetch_add(1, Ordering::SeqCst);
            let state = *self
                .assessment_state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            std::future::ready(
                UpdateAssessment::new(state, Vec::new(), true).map_err(|_| FakeError),
            )
        }

        fn plan_upgrade(
            &self,
            _context: &ReconcileContext,
            resource: &ResourceSnapshot,
            _dependencies: &[DependencySnapshot],
        ) -> impl Future<Output = Result<UpgradePlan, Self::Error>> + Send {
            std::future::ready(
                UpgradePlan::new(
                    DisruptionClass::Recycle,
                    true,
                    vec![
                        UpgradeStage::Drain(resource.key().resource_ref().clone()),
                        UpgradeStage::Recycle(resource.key().resource_ref().clone()),
                        UpgradeStage::Restart(resource.key().resource_ref().clone()),
                    ],
                )
                .map_err(|_| FakeError),
            )
        }

        async fn execute_upgrade(
            &self,
            context: &ReconcileContext,
            resource: &ResourceSnapshot,
            _dependencies: &[DependencySnapshot],
            _plan: &UpgradePlan,
        ) -> Result<ReconcileResult, Self::Error> {
            context.authorize_effect().map_err(|_| FakeError)?;
            self.enter(resource.key(), "upgrade").await;
            self.upgrade_count.fetch_add(1, Ordering::SeqCst);
            Ok(ReconcileResult::converged(
                resource.revision(),
                resource.generation(),
            ))
        }
    }

    fn finalizer_result(resource: &ResourceSnapshot) -> Result<ReconcileResult, FakeError> {
        let projection = ReconcileProjection::new(
            resource.key().clone(),
            resource.revision(),
            ResourcePhase::Deleted,
            ProjectionDisposition::Converged,
            ReconcileReason::Deleted,
            resource.canonical_json().is_empty(),
        );
        ReconcileResult::new(
            resource.revision(),
            resource.generation(),
            None,
            None,
            ReconcileDisposition::Finalized,
            None,
            Some(projection),
            StatusPersistence::NotRequested,
        )
        .map_err(|_| FakeError)
    }

    fn key(name: &str, suffix: u8) -> ResourceKey {
        ResourceKey::new(
            ZoneId::parse("work").unwrap(),
            ResourceRef::parse(&format!("Process/{name}")).unwrap(),
            ResourceUid::parse(format!("123e4567-e89b-42d3-a456-4266141740{suffix:02}")).unwrap(),
        )
    }

    fn identity() -> ControllerIdentity {
        ControllerIdentity::new(
            ZoneId::parse("work").unwrap(),
            ResourceRef::parse("Process/controller").unwrap(),
            ControllerGeneration::new(1).unwrap(),
            ResourceRef::parse("Provider/runtime").unwrap(),
            ResourceGeneration::new(1).unwrap(),
            ResourceRef::parse("Process/controller").unwrap(),
            ResourceRef::parse("Host/system").unwrap(),
            None,
        )
        .unwrap()
    }

    fn descriptor(
        identity: ControllerIdentity,
        resource_types: Vec<ResourceTypeName>,
        concurrency: usize,
        max_pending: usize,
        max_expedited: usize,
        watch_credits: u32,
    ) -> Result<ControllerDescriptor, DescriptorError> {
        let resources = resource_types
            .iter()
            .cloned()
            .map(|resource_type| ResourceRegistration::new(resource_type, vec![1], 30_000, 3))
            .collect::<Result<Vec<_>, _>>()?;
        let selectors = resource_types
            .into_iter()
            .map(|resource_type| ControllerSelector::new(resource_type, SelectorField::Spec, None))
            .collect::<Result<Vec<_>, _>>()?;
        ControllerDescriptor::new(
            identity,
            resources,
            vec!["resource-api".to_owned()],
            vec!["host".to_owned()],
            vec![ControllerVerb::ReadSpec, ControllerVerb::WriteStatus],
            selectors,
            vec![
                ControllerSelector::new(
                    ResourceTypeName::parse("Host").unwrap(),
                    SelectorField::Status,
                    None,
                )
                .unwrap(),
            ],
            true,
            vec!["d2b.io/controller".to_owned()],
            vec!["service.v1".to_owned()],
            vec!["schema.v1".to_owned()],
            ControllerExecutionPolicy::new(
                concurrency,
                concurrency,
                max_pending,
                max_expedited,
                watch_credits,
                ResyncPolicy::new(Some(10_000), 30_000)?,
            )?,
        )
    }

    fn resource(key: ResourceKey, revision: u64) -> FreshSnapshot {
        FreshSnapshot::Present {
            target: ResourceSnapshot::new(
                key,
                ZoneRevision::new(revision),
                ResourceGeneration::new(1).unwrap(),
                b"{}".to_vec(),
                false,
            ),
            dependencies: Vec::new(),
        }
    }

    fn initial(keys: &[ResourceKey]) -> InitialList {
        InitialList {
            resources: keys
                .iter()
                .cloned()
                .map(|key| InitialResource::new(key, ZoneRevision::new(1)))
                .collect(),
            snapshot_revision: ZoneRevision::new(1),
        }
    }

    fn harness(keys: Vec<ResourceKey>, concurrency: usize) -> Harness {
        let fresh = keys
            .iter()
            .cloned()
            .map(|key| (key.clone(), resource(key, 1)))
            .collect();
        let (source, watch_tx) = FakeSource::new(vec![initial(&keys)], fresh);
        let (entered_tx, entered_rx) = mpsc::channel();
        let reconciler = Arc::new(FakeReconciler {
            descriptor: descriptor(
                identity(),
                vec![ResourceTypeName::parse("Process").unwrap()],
                concurrency,
                32,
                2,
                16,
            )
            .unwrap(),
            entered_tx,
            release: Arc::new(Semaphore::new(0)),
            active: AtomicUsize::new(0),
            max_active: AtomicUsize::new(0),
            plan_count: AtomicUsize::new(0),
            assess_count: AtomicUsize::new(0),
            reconcile_count: AtomicUsize::new(0),
            observe_count: AtomicUsize::new(0),
            upgrade_count: AtomicUsize::new(0),
            finalizer_count: AtomicUsize::new(0),
            validation_valid: AtomicBool::new(true),
            handler_failures_remaining: AtomicUsize::new(0),
            handler_failure_terminal: AtomicBool::new(false),
            block_handlers: AtomicBool::new(true),
            no_op_after_first: AtomicBool::new(false),
            mutation_only: AtomicBool::new(false),
            assessment_state: Mutex::new(UpdateAssessmentState::Current),
            requeue_at: Mutex::new(None),
        });
        (reconciler, entered_rx, source, watch_tx)
    }

    fn config() -> RunnerConfig {
        RunnerConfig {
            policy_revision: 1,
            api_revision: 2,
            configuration_revision: ConfigurationGeneration::new(3).unwrap(),
            deadline_tick: 30_000,
            max_attempts: 3,
        }
    }

    fn run_in_thread(
        reconciler: Arc<FakeReconciler>,
        source: Arc<FakeSource>,
    ) -> thread::JoinHandle<Result<RunnerReport, RunnerFailure>> {
        run_with_config_in_thread(reconciler, source, config())
    }

    fn run_with_config_in_thread(
        reconciler: Arc<FakeReconciler>,
        source: Arc<FakeSource>,
        config: RunnerConfig,
    ) -> thread::JoinHandle<Result<RunnerReport, RunnerFailure>> {
        thread::spawn(move || block_on(Runner::new(reconciler, source, config).run()))
    }

    fn wait_for(counter: &AtomicUsize, expected: usize) {
        for _ in 0..400 {
            if counter.load(Ordering::SeqCst) >= expected {
                return;
            }
            thread::sleep(Duration::from_millis(5));
        }
        panic!("counter did not reach {expected}");
    }

    fn wait_for_outcomes(source: &FakeSource, expected: usize) {
        for _ in 0..400 {
            if source
                .persisted_outcomes
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len()
                >= expected
            {
                return;
            }
            thread::sleep(Duration::from_millis(5));
        }
        panic!("persisted outcomes did not reach {expected}");
    }

    fn wait_for_counter(observer: &RecordingObserver, counter: RunnerCounter) {
        for _ in 0..400 {
            if observer
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .iter()
                .any(|observation| observation.counter == Some(counter))
            {
                return;
            }
            thread::sleep(Duration::from_millis(5));
        }
        panic!("observer did not receive {counter:?}");
    }

    #[test]
    fn runtime_dependent_pending_futures_run_on_the_callers_executor() {
        let (reconciler, entered, source, watch_tx) = harness(vec![key("app", 1)], 1);
        block_on(async {
            let runner = tokio::spawn(Runner::new(Arc::clone(&reconciler), source, config()).run());
            tokio::task::spawn_blocking(move || entered.recv_timeout(Duration::from_secs(2)))
                .await
                .unwrap()
                .unwrap();
            reconciler.release(1);
            watch_tx.send(Ok(WatchEvent::Closed)).unwrap();
            assert_eq!(runner.await.unwrap().unwrap().checkpointed, 1);
        });
    }

    #[test]
    fn effect_acceptance_precedes_handler_effects() {
        let (reconciler, entered, source, watch_tx) = harness(vec![key("app", 1)], 1);
        let runner = run_in_thread(Arc::clone(&reconciler), Arc::clone(&source));

        entered.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(source.effect_acceptances.load(Ordering::SeqCst), 1);
        reconciler.release(1);
        watch_tx.send(Ok(WatchEvent::Closed)).unwrap();

        runner.join().unwrap().unwrap();
    }

    #[test]
    fn effect_acceptance_conflict_reenters_before_starting_handler() {
        let (reconciler, _entered, source, watch_tx) = harness(vec![key("app", 1)], 1);
        reconciler.block_handlers.store(false, Ordering::SeqCst);
        source
            .effect_acceptance_conflicts_remaining
            .store(1, Ordering::SeqCst);
        let runner = run_in_thread(Arc::clone(&reconciler), Arc::clone(&source));

        watch_tx.send(Ok(WatchEvent::Closed)).unwrap();
        let report = runner.join().unwrap().unwrap();
        assert_eq!(report.dispatched, 2);
        assert_eq!(report.conflicts_retried, 1);
        assert_eq!(reconciler.reconcile_count.load(Ordering::SeqCst), 1);
        assert_eq!(source.effect_acceptances.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn mutation_only_pass_skips_effect_acceptance() {
        let (reconciler, _entered, source, watch_tx) = harness(vec![key("app", 1)], 1);
        reconciler.block_handlers.store(false, Ordering::SeqCst);
        reconciler.mutation_only.store(true, Ordering::SeqCst);
        let runner = run_in_thread(Arc::clone(&reconciler), Arc::clone(&source));

        watch_tx.send(Ok(WatchEvent::Closed)).unwrap();
        let report = runner.join().unwrap().unwrap();
        assert_eq!(report.dispatched, 1);
        assert_eq!(source.effect_acceptances.load(Ordering::SeqCst), 0);
        assert_eq!(source.commits.load(Ordering::SeqCst), 1);
        assert_eq!(reconciler.reconcile_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn dropping_runner_future_cancels_owned_pending_tasks() {
        let (reconciler, entered, source, _watch_tx) = harness(vec![key("app", 1)], 1);
        block_on(async {
            let runner = tokio::spawn(Runner::new(Arc::clone(&reconciler), source, config()).run());
            tokio::task::spawn_blocking(move || entered.recv_timeout(Duration::from_secs(2)))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(reconciler.active.load(Ordering::SeqCst), 1);
            runner.abort();
            assert!(runner.await.unwrap_err().is_cancelled());
            for _ in 0..100 {
                if reconciler.active.load(Ordering::SeqCst) == 0 {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            panic!("worker task survived RunnerFuture drop");
        });
    }

    #[test]
    fn runner_cancellation_joins_owned_pending_tasks() {
        let (reconciler, entered, source, _watch_tx) = harness(vec![key("app", 1)], 1);
        block_on(async {
            let future = Runner::new(Arc::clone(&reconciler), source, config()).run();
            let shutdown = future.shutdown.clone();
            let runner = tokio::spawn(future);
            tokio::task::spawn_blocking(move || entered.recv_timeout(Duration::from_secs(2)))
                .await
                .unwrap()
                .unwrap();
            shutdown.cancel();
            assert_eq!(
                runner.await.unwrap().unwrap_err().error(),
                RunnerError::Cancelled
            );
            assert_eq!(reconciler.active.load(Ordering::SeqCst), 0);
        });
    }

    #[test]
    fn runner_shutdown_cancels_a_pending_source_phase() {
        let (reconciler, _entered, source, _watch_tx) = harness(vec![key("app", 1)], 1);
        source.block_reads.store(true, Ordering::Release);
        block_on(async {
            let future = Runner::new(reconciler, Arc::clone(&source), config()).run();
            let shutdown = future.shutdown.clone();
            let runner = tokio::spawn(future);
            for _ in 0..100 {
                if source.reads_started.load(Ordering::SeqCst) > 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert_eq!(source.reads_started.load(Ordering::SeqCst), 1);
            shutdown.cancel();
            assert_eq!(
                runner.await.unwrap().unwrap_err().error(),
                RunnerError::Cancelled
            );
        });
    }

    #[test]
    fn observer_reports_queue_coalescing_depth_and_active_workers() {
        let target = key("app", 1);
        let (reconciler, entered, source, watch_tx) = harness(Vec::new(), 1);
        source
            .fresh
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(target.clone(), resource(target.clone(), 2));
        let observer = Arc::new(RecordingObserver::default());
        let run_observer: Arc<dyn RunnerObserver> = observer.clone();
        let run_reconciler = Arc::clone(&reconciler);
        let runner = thread::spawn(move || {
            block_on(
                Runner::new(run_reconciler, source, config())
                    .with_observer(run_observer)
                    .run(),
            )
        });
        for operation in ["first", "second", "third"] {
            watch_tx
                .send(Ok(WatchEvent::Hint(Box::new(WatchHint::new(
                    target.clone(),
                    ZoneRevision::new(2),
                    TriggerSet::new([TriggerReason::DependencyChanged]),
                    PriorityLane::Ordinary,
                    OperationContext::new(operation, operation, operation, None).unwrap(),
                )))))
                .unwrap();
            if operation == "first" {
                entered.recv_timeout(Duration::from_secs(2)).unwrap();
            }
        }

        wait_for_counter(observer.as_ref(), RunnerCounter::QueueCoalesced);
        let observations = observer
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(observations.iter().any(|observation| {
            observation.counter == Some(RunnerCounter::QueueAdmitted)
                && observation.lane == Some(PriorityLane::Ordinary)
        }));
        assert!(
            observations
                .iter()
                .any(|observation| observation.active_workers == 1)
        );
        assert!(
            observations
                .iter()
                .any(|observation| observation.queue_depth >= 1)
        );
        drop(observations);

        reconciler.release(1);
        entered.recv_timeout(Duration::from_secs(2)).unwrap();
        reconciler.release(1);
        watch_tx.send(Ok(WatchEvent::Closed)).unwrap();
        runner.join().unwrap().unwrap();
    }

    #[test]
    fn startup_callback_retains_initial_source_failure_kind() {
        let (reconciler, _entered, source, _watch_tx) = harness(Vec::new(), 1);
        source
            .initial
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        let startup = Arc::new(Mutex::new(None));
        let startup_result = Arc::clone(&startup);
        let result = block_on(
            Runner::new(reconciler, source, config()).run_with_startup(move |result| {
                *startup_result
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(result);
            }),
        );
        assert_eq!(
            startup
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_ref()
                .copied(),
            Some(Err(RunnerError::Source(SourceError::Unavailable)))
        );
        assert_eq!(
            result.unwrap_err().error(),
            RunnerError::Source(SourceError::Unavailable)
        );
    }

    #[test]
    fn observer_retains_watch_failure_signal_when_runner_returns_error() {
        let (reconciler, _entered, source, watch_tx) = harness(Vec::new(), 1);
        let observer = Arc::new(RecordingObserver::default());
        let run_observer: Arc<dyn RunnerObserver> = observer.clone();
        let runner = thread::spawn(move || {
            block_on(
                Runner::new(reconciler, source, config())
                    .with_observer(run_observer)
                    .run(),
            )
        });
        watch_tx.send(Err(WatchFailure::Fatal)).unwrap();

        assert_eq!(
            runner.join().unwrap().unwrap_err().error(),
            RunnerError::Source(SourceError::Integrity)
        );
        let observations = observer
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(observations.iter().any(|observation| {
            observation.counter == Some(RunnerCounter::WatchFailure)
                && observation.reason == RunnerObservationReason::WatchFatal
        }));
        assert!(observations.iter().any(|observation| {
            observation.counter.is_none() && observation.outcome == RunnerOutcome::Failed
        }));
    }

    #[test]
    fn initial_list_rejects_keys_outside_the_registered_zone() {
        let (reconciler, _entered, _source, _watch_tx) = harness(Vec::new(), 1);
        let foreign = ResourceKey::new(
            ZoneId::parse("personal").unwrap(),
            ResourceRef::parse("Process/app").unwrap(),
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174001").unwrap(),
        );

        assert_eq!(
            initial_hints(
                &reconciler.descriptor,
                vec![InitialResource::new(foreign, ZoneRevision::new(1))]
            )
            .unwrap_err(),
            RunnerError::Source(SourceError::Integrity)
        );
    }

    #[test]
    fn watch_rejects_keys_outside_registered_ownership() {
        let (reconciler, _entered, source, watch_tx) = harness(Vec::new(), 1);
        let runner = Runner::new(reconciler, source, config()).run();
        watch_tx
            .send(Ok(WatchEvent::Hint(Box::new(WatchHint::new(
                ResourceKey::new(
                    ZoneId::parse("personal").unwrap(),
                    ResourceRef::parse("Process/app").unwrap(),
                    ResourceUid::parse("123e4567-e89b-42d3-a456-426614174001").unwrap(),
                ),
                ZoneRevision::new(1),
                TriggerSet::new([TriggerReason::DependencyChanged]),
                PriorityLane::Ordinary,
                OperationContext::new("watch", "watch", "watch", None).unwrap(),
            )))))
            .unwrap();

        assert_eq!(
            block_on(runner).unwrap_err().error(),
            RunnerError::Source(SourceError::Integrity)
        );
    }

    #[test]
    fn fresh_read_rejects_a_different_resource_key() {
        let requested = key("requested", 1);
        let (reconciler, _entered, source, watch_tx) = harness(vec![requested.clone()], 1);
        source
            .fresh
            .lock()
            .unwrap()
            .insert(requested, resource(key("other", 2), 1));
        let runner = Runner::new(reconciler, source, config()).run();
        watch_tx.send(Ok(WatchEvent::Closed)).unwrap();

        assert_eq!(
            block_on(runner).unwrap_err().error(),
            RunnerError::Source(SourceError::Integrity)
        );
    }

    #[test]
    fn committed_revision_cannot_move_checkpoint_backwards() {
        let (reconciler, entered, source, watch_tx) = harness(vec![key("app", 1)], 1);
        source.commit_revision.store(0, Ordering::SeqCst);
        let runner = run_in_thread(Arc::clone(&reconciler), source);

        entered.recv_timeout(Duration::from_secs(2)).unwrap();
        reconciler.release(1);
        watch_tx.send(Ok(WatchEvent::Closed)).unwrap();

        assert_eq!(
            runner.join().unwrap().unwrap_err().error(),
            RunnerError::Source(SourceError::Integrity)
        );
    }

    #[test]
    fn independent_resources_contend_on_the_configured_semaphore() {
        let keys = vec![key("one", 1), key("two", 2), key("three", 3)];
        let (reconciler, entered, source, watch_tx) = harness(keys, 2);
        let runner = run_in_thread(Arc::clone(&reconciler), source);

        entered.recv_timeout(Duration::from_secs(2)).unwrap();
        entered.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            entered.recv_timeout(Duration::from_millis(100)).is_err(),
            "a third handler bypassed the semaphore"
        );
        assert_eq!(reconciler.max_active.load(Ordering::SeqCst), 2);
        reconciler.release(2);
        entered.recv_timeout(Duration::from_secs(2)).unwrap();
        reconciler.release(1);
        watch_tx.send(Ok(WatchEvent::Closed)).unwrap();

        let report = runner.join().unwrap().unwrap();
        assert_eq!(report.dispatched, 3);
        assert_eq!(report.checkpointed, 3);
    }

    #[test]
    fn duplicate_hint_contends_with_running_handler_and_stays_single_flight() {
        let target = key("app", 1);
        let (reconciler, entered, source, watch_tx) = harness(vec![target.clone()], 2);
        let runner = run_in_thread(Arc::clone(&reconciler), source);

        entered.recv_timeout(Duration::from_secs(2)).unwrap();
        watch_tx
            .send(Ok(WatchEvent::Hint(Box::new(WatchHint::new(
                target,
                ZoneRevision::new(2),
                TriggerSet::new([TriggerReason::DependencyChanged]),
                PriorityLane::Ordinary,
                OperationContext::new("watch", "watch", "watch", None).unwrap(),
            )))))
            .unwrap();
        assert!(
            entered.recv_timeout(Duration::from_millis(100)).is_err(),
            "the same resource ran concurrently"
        );
        reconciler.release(1);
        entered.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(reconciler.max_active.load(Ordering::SeqCst), 1);
        reconciler.release(1);
        watch_tx.send(Ok(WatchEvent::Closed)).unwrap();

        let report = runner.join().unwrap().unwrap();
        assert_eq!(report.dispatched, 2);
    }

    #[test]
    fn expedited_plan_finishes_but_effect_waits_for_commit_proof() {
        let target = key("app", 1);
        let (reconciler, entered, source, watch_tx) = harness(Vec::new(), 1);
        let mut fresh = source
            .fresh
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        fresh.insert(target.clone(), resource(target.clone(), 4));
        drop(fresh);
        let runner = run_in_thread(Arc::clone(&reconciler), Arc::clone(&source));
        watch_tx
            .send(Ok(WatchEvent::Hint(Box::new(WatchHint::new(
                target,
                ZoneRevision::new(4),
                TriggerSet::new([TriggerReason::ExpeditedMutation]),
                PriorityLane::Expedited,
                OperationContext::new("expedite", "expedite", "expedite", None).unwrap(),
            )))))
            .unwrap();

        wait_for(&reconciler.plan_count, 1);
        assert!(
            entered.recv_timeout(Duration::from_millis(100)).is_err(),
            "effect started before durable commit proof"
        );
        assert_eq!(source.effect_acceptances.load(Ordering::SeqCst), 0);
        assert_eq!(source.expedited_completions.load(Ordering::SeqCst), 0);
        source.release_commit_gate();
        entered.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(source.effect_acceptances.load(Ordering::SeqCst), 1);
        reconciler.release(1);
        watch_tx.send(Ok(WatchEvent::Closed)).unwrap();

        let report = runner.join().unwrap().unwrap();
        assert_eq!(report.dispatched, 1);
        assert_eq!(source.commits.load(Ordering::SeqCst), 1);
        assert_eq!(source.expedited_completions.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn expedited_abort_produces_no_effect_or_status_commit() {
        let target = key("app", 1);
        let (reconciler, entered, source, watch_tx) = harness(Vec::new(), 1);
        source
            .fresh
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(target.clone(), resource(target.clone(), 4));
        source.abort_expedited.store(true, Ordering::SeqCst);
        let runner = run_in_thread(Arc::clone(&reconciler), Arc::clone(&source));
        watch_tx
            .send(Ok(WatchEvent::Hint(Box::new(WatchHint::new(
                target,
                ZoneRevision::new(4),
                TriggerSet::new([TriggerReason::ExpeditedMutation]),
                PriorityLane::Expedited,
                OperationContext::new("abort", "abort", "abort", None).unwrap(),
            )))))
            .unwrap();
        wait_for(&reconciler.plan_count, 1);
        source.release_commit_gate();
        watch_tx.send(Ok(WatchEvent::Closed)).unwrap();

        let report = runner.join().unwrap().unwrap();
        assert!(entered.try_recv().is_err());
        assert_eq!(reconciler.reconcile_count.load(Ordering::SeqCst), 0);
        assert_eq!(source.effect_acceptances.load(Ordering::SeqCst), 0);
        assert_eq!(source.commits.load(Ordering::SeqCst), 0);
        assert_eq!(source.starting.load(Ordering::SeqCst), 0);
        assert_eq!(report.checkpointed, 0);
    }

    #[test]
    fn expedited_commit_failure_produces_no_effect() {
        let target = key("app", 1);
        let (reconciler, entered, source, watch_tx) = harness(Vec::new(), 1);
        source
            .fresh
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(target.clone(), resource(target.clone(), 4));
        source.expedited_gate_error.store(true, Ordering::SeqCst);
        let runner = run_in_thread(Arc::clone(&reconciler), Arc::clone(&source));
        watch_tx
            .send(Ok(WatchEvent::Hint(Box::new(WatchHint::new(
                target,
                ZoneRevision::new(4),
                TriggerSet::new([TriggerReason::ExpeditedMutation]),
                PriorityLane::Expedited,
                OperationContext::new("failed", "failed", "failed", None).unwrap(),
            )))))
            .unwrap();
        wait_for(&reconciler.plan_count, 1);
        source.release_commit_gate();

        let failure = runner.join().unwrap().unwrap_err();
        assert_eq!(
            failure.error(),
            RunnerError::Source(SourceError::Unavailable)
        );
        assert_eq!(failure.report().dispatched, 1);
        assert_eq!(failure.report().checkpointed, 0);
        assert_eq!(failure.report().committed_status_pending, 0);
        assert!(entered.try_recv().is_err());
        assert_eq!(reconciler.reconcile_count.load(Ordering::SeqCst), 0);
        assert_eq!(source.expedited_completions.load(Ordering::SeqCst), 0);
        drop(watch_tx);
    }

    #[test]
    fn invalid_spec_finishes_terminally_without_planning_or_effects() {
        let (reconciler, _entered, source, watch_tx) = harness(vec![key("app", 1)], 1);
        reconciler.validation_valid.store(false, Ordering::SeqCst);
        let runner = run_in_thread(Arc::clone(&reconciler), Arc::clone(&source));
        watch_tx.send(Ok(WatchEvent::Closed)).unwrap();

        let report = runner.join().unwrap().unwrap();
        assert_eq!(report.checkpointed, 1);
        assert_eq!(reconciler.plan_count.load(Ordering::SeqCst), 0);
        assert_eq!(reconciler.reconcile_count.load(Ordering::SeqCst), 0);
        assert_eq!(source.commits.load(Ordering::SeqCst), 0);
        assert_eq!(source.starting.load(Ordering::SeqCst), 0);
        let outcomes = source
            .persisted_outcomes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(outcomes[0].reason_code(), "invalid-spec");
        assert_eq!(
            outcomes[0].remediation(),
            "correct the declared specification and retry reconciliation"
        );
    }

    #[test]
    fn terminal_failure_retains_the_full_accumulated_report() {
        let target = key("report", 1);
        let (reconciler, _entered, source, watch_tx) = harness(vec![target], 1);
        reconciler.block_handlers.store(false, Ordering::SeqCst);
        let runner = run_in_thread(reconciler, Arc::clone(&source));

        wait_for(&source.checkpoints, 1);
        watch_tx.send(Err(WatchFailure::Fatal)).unwrap();

        let failure = runner.join().unwrap().unwrap_err();
        assert_eq!(failure.error(), RunnerError::Source(SourceError::Integrity));
        assert_eq!(failure.report().dispatched, 1);
        assert_eq!(failure.report().checkpointed, 1);
        assert_eq!(failure.report().committed_status_pending, 1);
    }

    #[test]
    fn expedited_invalid_spec_returns_a_failed_projection_after_proof() {
        let target = key("app", 1);
        let (reconciler, _entered, source, watch_tx) = harness(Vec::new(), 1);
        reconciler.validation_valid.store(false, Ordering::SeqCst);
        source
            .fresh
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(target.clone(), resource(target.clone(), 2));
        let runner = run_in_thread(Arc::clone(&reconciler), Arc::clone(&source));
        watch_tx
            .send(Ok(WatchEvent::Hint(Box::new(WatchHint::new(
                target,
                ZoneRevision::new(2),
                TriggerSet::new([TriggerReason::ExpeditedMutation]),
                PriorityLane::Expedited,
                OperationContext::new("invalid", "invalid", "invalid", None).unwrap(),
            )))))
            .unwrap();
        source.release_commit_gate();
        watch_tx.send(Ok(WatchEvent::Closed)).unwrap();

        runner.join().unwrap().unwrap();
        assert_eq!(reconciler.plan_count.load(Ordering::SeqCst), 0);
        assert_eq!(reconciler.reconcile_count.load(Ordering::SeqCst), 0);
        assert_eq!(source.expedited_completions.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn ordinary_reentry_after_expedited_effect_no_ops_without_duplicate() {
        let target = key("app", 1);
        let (reconciler, entered, source, watch_tx) = harness(Vec::new(), 1);
        reconciler.no_op_after_first.store(true, Ordering::SeqCst);
        source
            .fresh
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(target.clone(), resource(target.clone(), 4));
        let runner = run_in_thread(Arc::clone(&reconciler), Arc::clone(&source));
        watch_tx
            .send(Ok(WatchEvent::Hint(Box::new(WatchHint::new(
                target.clone(),
                ZoneRevision::new(4),
                TriggerSet::new([TriggerReason::ExpeditedMutation]),
                PriorityLane::Expedited,
                OperationContext::new("expedited", "expedited", "expedited", None).unwrap(),
            )))))
            .unwrap();
        wait_for(&reconciler.plan_count, 1);
        watch_tx
            .send(Ok(WatchEvent::Hint(Box::new(WatchHint::new(
                target,
                ZoneRevision::new(4),
                TriggerSet::new([TriggerReason::ManualReconcile]),
                PriorityLane::Ordinary,
                OperationContext::new("ordinary", "ordinary", "ordinary", None).unwrap(),
            )))))
            .unwrap();
        source.release_commit_gate();
        entered.recv_timeout(Duration::from_secs(2)).unwrap();
        reconciler.release(1);
        wait_for(&reconciler.plan_count, 2);
        assert!(
            entered.recv_timeout(Duration::from_millis(100)).is_err(),
            "ordinary reentry duplicated the effect"
        );
        watch_tx.send(Ok(WatchEvent::Closed)).unwrap();

        let report = runner.join().unwrap().unwrap();
        assert_eq!(report.dispatched, 2);
        assert_eq!(reconciler.reconcile_count.load(Ordering::SeqCst), 1);
        assert_eq!(source.effect_acceptances.load(Ordering::SeqCst), 1);
        assert_eq!(source.commits.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn stale_commit_reloads_and_retries_without_checkpointing_stale_output() {
        let target = key("app", 1);
        let (reconciler, entered, source, watch_tx) = harness(vec![target], 1);
        source.conflicts_remaining.store(1, Ordering::SeqCst);
        let runner = run_in_thread(Arc::clone(&reconciler), Arc::clone(&source));

        entered.recv_timeout(Duration::from_secs(2)).unwrap();
        reconciler.release(1);
        entered.recv_timeout(Duration::from_secs(2)).unwrap();
        reconciler.release(1);
        watch_tx.send(Ok(WatchEvent::Closed)).unwrap();

        let report = runner.join().unwrap().unwrap();
        assert_eq!(report.conflicts_retried, 1);
        assert_eq!(source.commits.load(Ordering::SeqCst), 2);
        assert_eq!(source.checkpoints.load(Ordering::SeqCst), 1);
        assert_eq!(source.starting.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn committed_mutation_defers_projection_until_fresh_reentry() {
        let target = key("app", 1);
        let (_reconciler, _entered, source, _watch_tx) = harness(Vec::new(), 1);
        let (target_snapshot, dependencies) = match resource(target.clone(), 4) {
            FreshSnapshot::Present {
                target,
                dependencies,
            } => (target, dependencies),
            FreshSnapshot::Deleted { .. } => unreachable!(),
        };
        let context = ReconcileContext::ordinary(
            identity(),
            &target_snapshot,
            &dependencies,
            TriggerSet::new([TriggerReason::ManualReconcile]),
            target_snapshot.revision(),
            OperationContext::new("mutation", "mutation", "mutation", None).unwrap(),
            1,
            0,
            30_000,
            Cancellation::default(),
            1,
            2,
            ConfigurationGeneration::new(3).unwrap(),
        )
        .unwrap();
        let mutation = MutationIntent::new(
            target_snapshot.key().resource_ref().clone(),
            Some(target_snapshot.key().uid().clone()),
            Some(target_snapshot.revision()),
            MutationIntentKind::UpdateSpec,
            Some(b"{}".to_vec()),
        )
        .unwrap();
        let projection = ReconcileProjection::new(
            target_snapshot.key().clone(),
            target_snapshot.revision(),
            ResourcePhase::Ready,
            ProjectionDisposition::Converged,
            ReconcileReason::ReconcilePass,
            false,
        );
        let result = ReconcileResult::new(
            target_snapshot.revision(),
            target_snapshot.generation(),
            Some(ResourceMutationBatch::new(vec![mutation]).unwrap()),
            Some(b"{}".to_vec()),
            ReconcileDisposition::Converged,
            None,
            Some(projection),
            StatusPersistence::Pending,
        )
        .unwrap();

        let outcome = block_on(persist_result(source.as_ref(), &context, result));
        assert!(matches!(
            outcome,
            WorkerOutcome::Done {
                checkpointed: true,
                status_pending: true,
                requeue_at: None,
            }
        ));
        assert_eq!(source.commits.load(Ordering::SeqCst), 1);
        assert_eq!(source.persisted_outcomes.lock().unwrap().len(), 0);
        assert_eq!(source.checkpoints.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn conflict_reentry_reuses_observed_effect_and_does_not_duplicate() {
        let target = key("app", 1);
        let (reconciler, entered, source, watch_tx) = harness(vec![target], 1);
        source.conflicts_remaining.store(1, Ordering::SeqCst);
        reconciler.no_op_after_first.store(true, Ordering::SeqCst);
        let runner = run_in_thread(Arc::clone(&reconciler), Arc::clone(&source));

        entered.recv_timeout(Duration::from_secs(2)).unwrap();
        reconciler.release(1);
        wait_for(&reconciler.plan_count, 2);
        assert!(
            entered.recv_timeout(Duration::from_millis(100)).is_err(),
            "retry duplicated an already-started effect"
        );
        watch_tx.send(Ok(WatchEvent::Closed)).unwrap();

        let report = runner.join().unwrap().unwrap();
        assert_eq!(report.conflicts_retried, 1);
        assert_eq!(reconciler.reconcile_count.load(Ordering::SeqCst), 1);
        assert_eq!(source.commits.load(Ordering::SeqCst), 1);
        assert_eq!(source.checkpoints.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn repeated_conflicts_stop_at_the_attempt_bound() {
        let target = key("app", 1);
        let (reconciler, _entered, source, watch_tx) = harness(vec![target], 1);
        reconciler.block_handlers.store(false, Ordering::SeqCst);
        source.conflicts_remaining.store(8, Ordering::SeqCst);
        let runner = run_in_thread(reconciler, Arc::clone(&source));
        watch_tx.send(Ok(WatchEvent::Closed)).unwrap();

        let report = runner.join().unwrap().unwrap();
        assert_eq!(report.conflicts_retried, 2);
        assert_eq!(report.handler_failures, 1);
        assert_eq!(source.commits.load(Ordering::SeqCst), 3);
        assert_eq!(source.checkpoints.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn exhausted_conflicts_persist_failure_before_open_watch_releases_single_flight() {
        let target = key("app", 1);
        let (reconciler, _entered, source, watch_tx) = harness(vec![target], 1);
        reconciler.block_handlers.store(false, Ordering::SeqCst);
        source.conflicts_remaining.store(8, Ordering::SeqCst);
        let runner = run_in_thread(reconciler, Arc::clone(&source));

        wait_for_outcomes(&source, 1);
        assert!(
            !runner.is_finished(),
            "open watch was lost after exhaustion"
        );
        let outcomes = source
            .persisted_outcomes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(outcomes[0].reason(), ReconcileReason::ConflictExhausted);
        drop(outcomes);
        watch_tx.send(Ok(WatchEvent::Closed)).unwrap();
        assert_eq!(runner.join().unwrap().unwrap().handler_failures, 1);
    }

    #[test]
    fn exhausted_handler_retries_persist_failure_while_watch_remains_open() {
        let (reconciler, _entered, source, watch_tx) = harness(vec![key("app", 1)], 1);
        reconciler.block_handlers.store(false, Ordering::SeqCst);
        reconciler
            .handler_failures_remaining
            .store(8, Ordering::SeqCst);
        let runner = run_in_thread(reconciler, Arc::clone(&source));

        wait_for_outcomes(&source, 1);
        assert!(
            !runner.is_finished(),
            "open watch was lost after exhaustion"
        );
        let outcomes = source
            .persisted_outcomes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(outcomes[0].reason(), ReconcileReason::HandlerExhausted);
        drop(outcomes);
        watch_tx.send(Ok(WatchEvent::Closed)).unwrap();
        assert_eq!(runner.join().unwrap().unwrap().handler_failures, 1);
    }

    #[test]
    fn terminal_handler_failure_persists_without_retrying() {
        let (reconciler, _entered, source, watch_tx) = harness(vec![key("app", 1)], 1);
        reconciler.block_handlers.store(false, Ordering::SeqCst);
        reconciler
            .handler_failures_remaining
            .store(1, Ordering::SeqCst);
        reconciler
            .handler_failure_terminal
            .store(true, Ordering::SeqCst);
        let runner = run_in_thread(reconciler, Arc::clone(&source));

        wait_for_outcomes(&source, 1);
        let outcomes = source
            .persisted_outcomes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(outcomes[0].reason(), ReconcileReason::HandlerTerminal);
        drop(outcomes);
        watch_tx.send(Ok(WatchEvent::Closed)).unwrap();
        let report = runner.join().unwrap().unwrap();
        assert_eq!(report.dispatched, 1);
        assert_eq!(report.handler_retries, 0);
        assert_eq!(report.handler_failures, 1);
    }

    #[test]
    fn blocked_handler_is_cancelled_at_deadline_and_persists_failure() {
        let (reconciler, entered, source, watch_tx) = harness(vec![key("app", 1)], 1);
        let mut deadline_config = config();
        deadline_config.deadline_tick = 25;
        let runner = run_with_config_in_thread(
            Arc::clone(&reconciler),
            Arc::clone(&source),
            deadline_config,
        );

        entered.recv_timeout(Duration::from_secs(2)).unwrap();
        wait_for_outcomes(&source, 1);
        assert_eq!(reconciler.active.load(Ordering::SeqCst), 0);
        assert!(!runner.is_finished(), "deadline closed the watch");
        let outcomes = source
            .persisted_outcomes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(outcomes[0].reason(), ReconcileReason::DeadlineExceeded);
        drop(outcomes);
        watch_tx.send(Ok(WatchEvent::Closed)).unwrap();
        assert_eq!(runner.join().unwrap().unwrap().handler_failures, 1);
    }

    #[test]
    fn transient_handler_failure_retries_from_a_fresh_read() {
        let (reconciler, entered, source, watch_tx) = harness(vec![key("app", 1)], 1);
        reconciler
            .handler_failures_remaining
            .store(1, Ordering::SeqCst);
        reconciler.block_handlers.store(false, Ordering::SeqCst);
        let runner = run_in_thread(Arc::clone(&reconciler), source);

        entered.recv_timeout(Duration::from_secs(2)).unwrap();
        watch_tx.send(Ok(WatchEvent::Closed)).unwrap();

        let report = runner.join().unwrap().unwrap();
        assert_eq!(report.dispatched, 2);
        assert_eq!(report.handler_retries, 1);
        assert_eq!(report.handler_failures, 0);
        assert_eq!(reconciler.plan_count.load(Ordering::SeqCst), 1);
        assert_eq!(reconciler.reconcile_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn requeue_at_uses_runner_scheduler_and_terminal_checkpoint() {
        let target = key("app", 1);
        let (reconciler, _entered, source, watch_tx) = harness(vec![target], 1);
        reconciler.block_handlers.store(false, Ordering::SeqCst);
        *reconciler
            .requeue_at
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(42);
        let runner = run_in_thread(reconciler, Arc::clone(&source));
        watch_tx.send(Ok(WatchEvent::Closed)).unwrap();

        let report = runner.join().unwrap().unwrap();
        assert_eq!(source.requeues.load(Ordering::SeqCst), 0);
        assert_eq!(source.checkpoints.load(Ordering::SeqCst), 2);
        assert_eq!(report.checkpointed, 2);
        assert_eq!(report.dispatched, 2);
    }

    #[test]
    fn reconcile_and_upgrade_for_one_resource_are_serialized() {
        let target = key("app", 1);
        let (reconciler, entered, source, watch_tx) = harness(vec![target.clone()], 2);
        let runner = run_in_thread(Arc::clone(&reconciler), Arc::clone(&source));

        let (_, action) = entered.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(action, "reconcile");
        watch_tx
            .send(Ok(WatchEvent::Hint(Box::new(WatchHint::new(
                target,
                ZoneRevision::new(2),
                TriggerSet::new([TriggerReason::UpgradeRequested]),
                PriorityLane::Ordinary,
                OperationContext::new("upgrade", "upgrade", "upgrade", None).unwrap(),
            )))))
            .unwrap();
        assert!(
            entered.recv_timeout(Duration::from_millis(100)).is_err(),
            "upgrade overlapped reconcile"
        );
        reconciler.release(1);
        let (_, action) = entered.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(action, "upgrade");
        reconciler.release(1);
        watch_tx.send(Ok(WatchEvent::Closed)).unwrap();

        runner.join().unwrap().unwrap();
        assert_eq!(reconciler.upgrade_count.load(Ordering::SeqCst), 1);
        assert_eq!(reconciler.max_active.load(Ordering::SeqCst), 1);
        assert_eq!(source.effect_acceptances.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn deletion_event_without_body_executes_event_only_finalizer_projection() {
        let target = key("gone", 1);
        let (reconciler, _entered, source, watch_tx) = harness(Vec::new(), 1);
        source
            .fresh
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                target.clone(),
                FreshSnapshot::Deleted {
                    key: target.clone(),
                    revision: ZoneRevision::new(7),
                    generation: ResourceGeneration::new(2).unwrap(),
                },
            );
        let runner = run_in_thread(Arc::clone(&reconciler), Arc::clone(&source));
        watch_tx
            .send(Ok(WatchEvent::Hint(Box::new(WatchHint::new(
                target,
                ZoneRevision::new(7),
                TriggerSet::new([TriggerReason::DeletionRequested]),
                PriorityLane::Ordinary,
                OperationContext::new("delete", "delete", "delete", None).unwrap(),
            )))))
            .unwrap();
        watch_tx.send(Ok(WatchEvent::Closed)).unwrap();

        runner.join().unwrap().unwrap();
        assert_eq!(reconciler.finalizer_count.load(Ordering::SeqCst), 1);
        assert_eq!(source.starting.load(Ordering::SeqCst), 0);
        assert_eq!(source.checkpoints.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn expedited_delete_event_cannot_finalize_before_commit_proof() {
        let target = key("gone", 1);
        let (reconciler, _entered, source, watch_tx) = harness(Vec::new(), 1);
        source
            .fresh
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                target.clone(),
                FreshSnapshot::Deleted {
                    key: target.clone(),
                    revision: ZoneRevision::new(7),
                    generation: ResourceGeneration::new(2).unwrap(),
                },
            );
        let runner = run_in_thread(Arc::clone(&reconciler), Arc::clone(&source));
        watch_tx
            .send(Ok(WatchEvent::Hint(Box::new(WatchHint::new(
                target,
                ZoneRevision::new(7),
                TriggerSet::new([
                    TriggerReason::DeletionRequested,
                    TriggerReason::ExpeditedMutation,
                ]),
                PriorityLane::Expedited,
                OperationContext::new("delete", "delete", "delete", None).unwrap(),
            )))))
            .unwrap();
        thread::sleep(Duration::from_millis(100));
        assert_eq!(reconciler.finalizer_count.load(Ordering::SeqCst), 0);
        source.release_commit_gate();
        wait_for(&reconciler.finalizer_count, 1);
        watch_tx.send(Ok(WatchEvent::Closed)).unwrap();

        runner.join().unwrap().unwrap();
        assert_eq!(source.starting.load(Ordering::SeqCst), 0);
        assert_eq!(source.checkpoints.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn expedited_committed_but_pending_status_keeps_ordinary_reentry() {
        let target = key("app", 1);
        let (reconciler, entered, source, watch_tx) = harness(Vec::new(), 1);
        source
            .fresh
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(target.clone(), resource(target.clone(), 2));
        source.commit_status_pending.store(true, Ordering::SeqCst);
        reconciler.no_op_after_first.store(true, Ordering::SeqCst);
        let runner = run_in_thread(Arc::clone(&reconciler), Arc::clone(&source));
        watch_tx
            .send(Ok(WatchEvent::Hint(Box::new(WatchHint::new(
                target.clone(),
                ZoneRevision::new(2),
                TriggerSet::new([TriggerReason::ExpeditedMutation]),
                PriorityLane::Expedited,
                OperationContext::new("fast", "fast", "fast", None).unwrap(),
            )))))
            .unwrap();
        wait_for(&reconciler.plan_count, 1);
        watch_tx
            .send(Ok(WatchEvent::Hint(Box::new(WatchHint::new(
                target,
                ZoneRevision::new(2),
                TriggerSet::new([TriggerReason::ExecutionStatusChanged]),
                PriorityLane::Ordinary,
                OperationContext::new("rejoin", "rejoin", "rejoin", None).unwrap(),
            )))))
            .unwrap();
        source.release_commit_gate();
        entered.recv_timeout(Duration::from_secs(2)).unwrap();
        reconciler.release(1);
        watch_tx.send(Ok(WatchEvent::Closed)).unwrap();

        let report = runner.join().unwrap().unwrap();
        assert_eq!(report.committed_status_pending, 1);
        assert_eq!(report.checkpointed, 2);
        assert_eq!(reconciler.reconcile_count.load(Ordering::SeqCst), 1);
        assert_eq!(source.expedited_completions.load(Ordering::SeqCst), 1);
        assert_eq!(source.pending_completions.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn non_disruptive_assessment_continues_through_ordinary_reconcile() {
        let target = key("app", 1);
        let (reconciler, entered, source, watch_tx) = harness(Vec::new(), 1);
        *reconciler
            .assessment_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            UpdateAssessmentState::NonDisruptive;
        source
            .fresh
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(target.clone(), resource(target.clone(), 2));
        reconciler.block_handlers.store(false, Ordering::SeqCst);
        let runner = run_in_thread(Arc::clone(&reconciler), source);
        watch_tx
            .send(Ok(WatchEvent::Hint(Box::new(WatchHint::new(
                target,
                ZoneRevision::new(2),
                TriggerSet::new([TriggerReason::ArtifactOrImageChanged]),
                PriorityLane::Ordinary,
                OperationContext::new("assess", "assess", "assess", None).unwrap(),
            )))))
            .unwrap();
        watch_tx.send(Ok(WatchEvent::Closed)).unwrap();

        let (_, action) = entered.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(action, "reconcile");
        runner.join().unwrap().unwrap();
        assert_eq!(reconciler.assess_count.load(Ordering::SeqCst), 1);
        assert_eq!(reconciler.reconcile_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn scheduled_observe_executes_observer_without_reconcile() {
        let target = key("app", 1);
        let (reconciler, entered, source, watch_tx) = harness(Vec::new(), 1);
        reconciler.block_handlers.store(false, Ordering::SeqCst);
        source
            .fresh
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(target.clone(), resource(target.clone(), 2));
        let runner = run_in_thread(Arc::clone(&reconciler), source);
        watch_tx
            .send(Ok(WatchEvent::Hint(Box::new(WatchHint::new(
                target,
                ZoneRevision::new(2),
                TriggerSet::new([TriggerReason::ScheduledObserve]),
                PriorityLane::Ordinary,
                OperationContext::new("observe", "observe", "observe", None).unwrap(),
            )))))
            .unwrap();
        watch_tx.send(Ok(WatchEvent::Closed)).unwrap();

        let (_, action) = entered.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(action, "observe");
        runner.join().unwrap().unwrap();
        assert_eq!(reconciler.observe_count.load(Ordering::SeqCst), 1);
        assert_eq!(reconciler.reconcile_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn upgrade_required_assessment_never_applies_change_in_place() {
        let target = key("app", 1);
        let (reconciler, entered, source, watch_tx) = harness(Vec::new(), 1);
        *reconciler
            .assessment_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            UpdateAssessmentState::UpgradeRequired;
        source
            .fresh
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(target.clone(), resource(target.clone(), 2));
        let runner = run_in_thread(Arc::clone(&reconciler), Arc::clone(&source));
        watch_tx
            .send(Ok(WatchEvent::Hint(Box::new(WatchHint::new(
                target,
                ZoneRevision::new(2),
                TriggerSet::new([TriggerReason::AssessUpdateDue]),
                PriorityLane::Ordinary,
                OperationContext::new("assess", "assess", "assess", None).unwrap(),
            )))))
            .unwrap();
        wait_for(&reconciler.assess_count, 1);
        watch_tx.send(Ok(WatchEvent::Closed)).unwrap();

        runner.join().unwrap().unwrap();
        assert!(entered.try_recv().is_err());
        assert_eq!(reconciler.reconcile_count.load(Ordering::SeqCst), 0);
        assert_eq!(reconciler.upgrade_count.load(Ordering::SeqCst), 0);
        assert_eq!(source.checkpoints.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn every_currency_trigger_executes_assessment_in_the_runner() {
        let triggers = [
            TriggerReason::SpecGenerationChanged,
            TriggerReason::ControllerGenerationChanged,
            TriggerReason::ProviderGenerationChanged,
            TriggerReason::SecurityPolicyChanged,
            TriggerReason::ArtifactOrImageChanged,
            TriggerReason::DependencyChanged,
            TriggerReason::AssessUpdateDue,
        ];
        let (reconciler, _entered, source, watch_tx) = harness(Vec::new(), 4);
        reconciler.block_handlers.store(false, Ordering::SeqCst);
        for (index, trigger) in triggers.into_iter().enumerate() {
            let target = key(&format!("assess-{index}"), u8::try_from(index + 1).unwrap());
            source
                .fresh
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(target.clone(), resource(target.clone(), 3));
            watch_tx
                .send(Ok(WatchEvent::Hint(Box::new(WatchHint::new(
                    target,
                    ZoneRevision::new(3),
                    TriggerSet::new([trigger]),
                    PriorityLane::Ordinary,
                    OperationContext::new(
                        format!("assess-{index}"),
                        format!("assess-{index}"),
                        format!("assess-{index}"),
                        None,
                    )
                    .unwrap(),
                )))))
                .unwrap();
        }
        let runner = run_in_thread(Arc::clone(&reconciler), source);
        watch_tx.send(Ok(WatchEvent::Closed)).unwrap();

        let report = runner.join().unwrap().unwrap();
        assert_eq!(report.dispatched, triggers.len());
        assert_eq!(
            reconciler.assess_count.load(Ordering::SeqCst),
            triggers.len()
        );
    }

    #[test]
    fn watch_revision_expiry_relists_and_reopens_after_new_snapshot() {
        let target = key("app", 1);
        let fresh = BTreeMap::from([(target.clone(), resource(target.clone(), 2))]);
        let (source, watch_tx) = FakeSource::new(
            vec![
                initial(&[]),
                InitialList {
                    resources: vec![InitialResource::new(target, ZoneRevision::new(2))],
                    snapshot_revision: ZoneRevision::new(2),
                },
            ],
            fresh,
        );
        let (entered_tx, entered) = mpsc::channel();
        let reconciler = Arc::new(FakeReconciler {
            descriptor: descriptor(
                identity(),
                vec![ResourceTypeName::parse("Process").unwrap()],
                1,
                4,
                1,
                4,
            )
            .unwrap(),
            entered_tx,
            release: Arc::new(Semaphore::new(1)),
            active: AtomicUsize::new(0),
            max_active: AtomicUsize::new(0),
            plan_count: AtomicUsize::new(0),
            assess_count: AtomicUsize::new(0),
            reconcile_count: AtomicUsize::new(0),
            observe_count: AtomicUsize::new(0),
            upgrade_count: AtomicUsize::new(0),
            finalizer_count: AtomicUsize::new(0),
            validation_valid: AtomicBool::new(true),
            handler_failures_remaining: AtomicUsize::new(0),
            handler_failure_terminal: AtomicBool::new(false),
            block_handlers: AtomicBool::new(false),
            no_op_after_first: AtomicBool::new(false),
            mutation_only: AtomicBool::new(false),
            assessment_state: Mutex::new(UpdateAssessmentState::Current),
            requeue_at: Mutex::new(None),
        });
        let runner = run_in_thread(reconciler, Arc::clone(&source));
        watch_tx.send(Err(WatchFailure::RevisionExpired)).unwrap();
        entered.recv_timeout(Duration::from_secs(2)).unwrap();
        watch_tx.send(Ok(WatchEvent::Closed)).unwrap();

        let report = runner.join().unwrap().unwrap();
        assert_eq!(report.relists, 1);
        assert_eq!(source.watch_opens.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn every_currency_trigger_reaches_update_assessment() {
        let triggers = [
            TriggerReason::SpecGenerationChanged,
            TriggerReason::ControllerGenerationChanged,
            TriggerReason::ProviderGenerationChanged,
            TriggerReason::SecurityPolicyChanged,
            TriggerReason::ArtifactOrImageChanged,
            TriggerReason::DependencyChanged,
            TriggerReason::AssessUpdateDue,
        ];
        for trigger in triggers {
            assert!(trigger.requires_update_assessment(), "{trigger:?}");
        }
        assert!(!TriggerReason::ManualReconcile.requires_update_assessment());
    }

    #[test]
    fn custom_block_on_executes_a_pending_future_after_wake() {
        struct WakeOnce {
            polled: bool,
        }
        impl Future for WakeOnce {
            type Output = usize;

            fn poll(
                mut self: std::pin::Pin<&mut Self>,
                context: &mut Context<'_>,
            ) -> Poll<Self::Output> {
                if self.polled {
                    Poll::Ready(1)
                } else {
                    self.polled = true;
                    context.waker().wake_by_ref();
                    Poll::Pending
                }
            }
        }

        assert_eq!(block_on(WakeOnce { polled: false }), 1);
    }

    #[test]
    fn health_and_drain_async_contracts_execute() {
        let (reconciler, _entered, _source, _watch_tx) = harness(Vec::new(), 1);
        assert_eq!(
            block_on(reconciler.health()).unwrap(),
            ControllerHealth::Healthy
        );
        assert_eq!(
            block_on(reconciler.drain(100)).unwrap(),
            DrainResult::Drained
        );
    }

    #[test]
    fn descriptor_rejects_unbounded_or_empty_execution_shapes() {
        assert_eq!(
            descriptor(identity(), Vec::new(), 1, 1, 1, 1).unwrap_err(),
            DescriptorError::InvalidRegistration
        );
        assert_eq!(
            descriptor(
                identity(),
                vec![ResourceTypeName::parse("Process").unwrap()],
                2,
                1,
                1,
                1,
            )
            .unwrap_err(),
            DescriptorError::InvalidExecution
        );
        let duplicate = ResourceTypeName::parse("Process").unwrap();
        assert_eq!(
            descriptor(identity(), vec![duplicate.clone(), duplicate], 1, 2, 1, 1).unwrap_err(),
            DescriptorError::InvalidRegistration
        );
    }

    #[test]
    fn complete_descriptor_carries_execution_and_registration_shape() {
        let descriptor = descriptor(
            identity(),
            vec![ResourceTypeName::parse("Process").unwrap()],
            4,
            4_096,
            2,
            8,
        )
        .unwrap();

        assert_eq!(descriptor.reconcile_concurrency(), 4);
        assert_eq!(descriptor.execution().observe_concurrency(), 4);
        assert_eq!(descriptor.watch_selectors().len(), 1);
        assert_eq!(descriptor.dependency_selectors().len(), 1);
        assert_eq!(descriptor.provider_capabilities(), &["resource-api"]);
        assert_eq!(descriptor.process_domains(), &["host"]);
        assert_eq!(
            descriptor.verbs(),
            &[ControllerVerb::ReadSpec, ControllerVerb::WriteStatus]
        );
        assert!(descriptor.consumes_owner_triggers());
        assert_eq!(descriptor.finalizers(), &["d2b.io/controller"]);
        assert_eq!(descriptor.resources()[0].versions(), &[1]);
        assert_eq!(descriptor.resources()[0].deadline_ticks(), 30_000);
        assert_eq!(descriptor.resources()[0].max_attempts(), 3);
        assert_eq!(
            descriptor.execution().resync().observe_interval_ticks(),
            Some(10_000)
        );
        assert_eq!(descriptor.service_fingerprints(), &["service.v1"]);
        assert_eq!(descriptor.schema_fingerprints(), &["schema.v1"]);
    }

    #[test]
    fn commit_decision_debug_redacts_accessor_visible_operation_identity() {
        const OPERATION: &str = "commit-operation-debug-sentinel";
        const ZONE: &str = "commit-zone-debug-sentinel";
        const UID: &str = "deadbeef-dead-4bad-8bad-deadbeef0009";
        let decision = CommitDecision::Committed(CommittedRevisionProof::issue(
            ZoneId::parse(ZONE).unwrap(),
            ResourceUid::parse(UID).unwrap(),
            ResourceGeneration::new(2).unwrap(),
            ZoneRevision::new(3),
            OPERATION.to_owned(),
        ));
        assert_eq!(decision.operation_id(), Some(OPERATION));
        assert_eq!(decision.zone().unwrap().as_str(), ZONE);

        let debug = format!("{decision:?}");
        for sentinel in [OPERATION, ZONE, UID] {
            assert!(!debug.contains(sentinel), "{debug}");
        }
        assert!(debug.contains("has_operation_id: true"), "{debug}");
    }
}
