//! Core-to-toolkit source and reconciler adapters.

use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use d2b_contracts_resource::v3::{ResourceTypeName, ZoneRevision};
use d2b_controller_toolkit::{
    CommitOutcome, ControllerDescriptor, ControllerExecutionPolicy, ControllerHealth,
    ControllerIdentity, ControllerSelector, ControllerSource, ControllerVerb, DependencySnapshot,
    DescriptorError, DisruptionClass, DrainResult, FinalizeResult, FreshSnapshot, HandlerFailure,
    InitialList, ObservationResult, OperationContext, ReconcileContext, ReconcilePlan,
    ReconcileDisposition, ReconcileProjection, ReconcileReason, ReconcileResult, ResourceKey,
    ResourceRegistration, ResourceReconciler, ResourceSnapshot, ResyncPolicy, SelectorField,
    SourceError, StatusPersistence, UpdateAssessment, UpdateAssessmentState, UpgradePlan,
    ValidationResult, WatchEvent, WatchFailure, MutationIntent, MutationIntentKind,
    ResourceMutationBatch,
};

use crate::{
    ChangeRecord, ControllerHint, ControllerLeaseKey, CoreResourceControllerRegistration,
    FairAdmission, HintAdmissionError, HintAdmissionOutcome, SuppressionDecision,
    WatchPlan, CORE_RESOURCE_CONTROLLER_REGISTRATIONS,
};

/// Core adapter construction or hint dispatch failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreSourceError {
    Hint(HintAdmissionError),
    WatchClosed,
}

impl core::fmt::Display for CoreSourceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Hint(_) => "core hint is invalid",
            Self::WatchClosed => "controller watch is closed",
        })
    }
}

impl std::error::Error for CoreSourceError {}

/// Closed result of dispatching a store-watch change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreDispatchOutcome {
    Suppressed(SuppressionDecision),
    Admitted,
    Coalesced,
}

/// Cardinality-safe Core admission counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CoreAdmissionCounts {
    pub admitted: usize,
    pub coalesced: usize,
    pub backpressure: usize,
}

fn validate_watch_plan(descriptor: &ControllerDescriptor) -> bool {
    WatchPlan::new(
        descriptor.resource_types().cloned().collect(),
        descriptor.watch_selectors().to_vec(),
        descriptor.consumes_owner_triggers(),
    )
    .is_ok()
}

/// Registered resource/store-watch operations available to one controller.
///
/// Implementations are trusted adapters over the production resource plane.
/// Outcome and checkpoint writes must be durable and revision-idempotent.
pub trait RegisteredControllerApi: Send + Sync + 'static {
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

    /// Stop a live adapter watch without dropping an admitted Core hint.
    fn stop_watch(&self) {}

    /// Whether `receive_watch_change` is backed by a live store stream.
    ///
    /// Test-only adapters can leave this disabled and inject changes through
    /// [`CoreControllerSource::dispatch_change`].
    fn has_watch_stream(&self) -> bool {
        false
    }

    /// Receive one raw store change for Core-owned validation and admission.
    ///
    /// The Core source applies suppression, lease, coalescing, and fair queue
    /// policy. `None` is a clean stream close; recoverable stream failures are
    /// returned as the toolkit's typed watch failure.
    fn receive_watch_change(
        &self,
    ) -> impl Future<Output = Result<Option<(ChangeRecord, OperationContext)>, WatchFailure>> + Send
    {
        std::future::ready(Err(WatchFailure::Fatal))
    }

    fn read_fresh(
        &self,
        key: &ResourceKey,
    ) -> impl Future<Output = Result<FreshSnapshot, SourceError>> + Send;

    fn write_starting(
        &self,
        context: &ReconcileContext,
    ) -> impl Future<Output = Result<(), SourceError>> + Send;

    fn accept_effect(
        &self,
        _context: &ReconcileContext,
        _plan: &ReconcilePlan,
    ) -> impl Future<Output = Result<(), SourceError>> + Send {
        std::future::ready(Ok(()))
    }

    fn complete_effect(
        &self,
        _context: &ReconcileContext,
        _result: &ReconcileResult,
    ) -> impl Future<Output = Result<(), SourceError>> + Send {
        std::future::ready(Ok(()))
    }

    fn verify_expedited_commit(
        &self,
        _context: &ReconcileContext,
    ) -> impl Future<Output = Result<bool, SourceError>> + Send {
        std::future::ready(Ok(false))
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

    fn persist_outcome_with_operation(
        &self,
        projection: &ReconcileProjection,
        _operation: &OperationContext,
    ) -> impl Future<Output = Result<(), SourceError>> + Send {
        self.persist_outcome(projection)
    }

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

struct WatchState {
    admission: FairAdmission,
    operations: BTreeMap<(ControllerLeaseKey, ResourceKey), (ZoneRevision, OperationContext)>,
    closed: bool,
}

/// Core adapter over a registered resource API and bounded store-watch queue.
pub struct CoreControllerSource<A> {
    descriptor: ControllerDescriptor,
    controller: ControllerLeaseKey,
    api: Arc<A>,
    watch: Mutex<WatchState>,
    watch_signal_tx: tokio::sync::mpsc::Sender<()>,
    watch_signal_rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<()>>,
    watch_stream_enabled: AtomicBool,
    admitted: AtomicUsize,
    coalesced: AtomicUsize,
    backpressure: AtomicUsize,
}

impl<A> CoreControllerSource<A>
where
    A: RegisteredControllerApi,
{
    /// Bind one complete descriptor to its registered resource API.
    pub fn new(descriptor: ControllerDescriptor, api: Arc<A>) -> Arc<Self> {
        let controller = ControllerLeaseKey::new(
            descriptor.identity().zone().clone(),
            descriptor.identity().controller_ref().clone(),
        )
        .expect("validated descriptor has a valid controller lease key");
        let pending_bound = descriptor.max_pending_resources();
        let (watch_signal_tx, watch_signal_rx) = tokio::sync::mpsc::channel(1);
        Arc::new(Self {
            descriptor,
            controller,
            api,
            watch: Mutex::new(WatchState {
                admission: FairAdmission::new(pending_bound, pending_bound),
                operations: BTreeMap::new(),
                closed: false,
            }),
            watch_signal_tx,
            watch_signal_rx: tokio::sync::Mutex::new(watch_signal_rx),
            watch_stream_enabled: AtomicBool::new(false),
            admitted: AtomicUsize::new(0),
            coalesced: AtomicUsize::new(0),
            backpressure: AtomicUsize::new(0),
        })
    }

    /// Apply suppression and admit one canonical toolkit hint.
    pub fn dispatch_change(
        &self,
        controller: ControllerLeaseKey,
        change: ChangeRecord,
        operation: OperationContext,
    ) -> Result<CoreDispatchOutcome, CoreSourceError> {
        let decision = change.suppression();
        if decision != SuppressionDecision::Dispatch {
            return Ok(CoreDispatchOutcome::Suppressed(decision));
        }
        if controller != self.controller {
            return Err(CoreSourceError::Hint(HintAdmissionError::InvalidHint));
        }
        if !self
            .descriptor
            .resource_types()
            .any(|resource_type| resource_type == change.target.resource_ref().resource_type())
        {
            return Err(CoreSourceError::Hint(HintAdmissionError::InvalidHint));
        }
        let target = change.target.clone();
        let revision = change.revision;
        let hint = ControllerHint::new(controller, change.target, change.revision, change.reasons)
            .map_err(CoreSourceError::Hint)?;
        self.admit_hint(hint, target, revision, operation)
    }

    /// Wake one exact resource for a declared liveness observation.
    ///
    /// This path is not a store mutation and therefore bypasses convergence
    /// suppression while still using the same bounded Core admission queue.
    pub fn dispatch_observation(
        &self,
        target: ResourceKey,
        revision: ZoneRevision,
    ) -> Result<CoreDispatchOutcome, CoreSourceError> {
        if revision.get() == 0
            || target.zone() != self.controller.zone()
            || !self
                .descriptor
                .resource_types()
                .any(|resource_type| resource_type == target.resource_ref().resource_type())
        {
            return Err(CoreSourceError::Hint(HintAdmissionError::InvalidHint));
        }
        let operation_suffix = format!(
            "{}:{}:{}",
            target.zone().as_str(),
            target.resource_ref().to_canonical_string(),
            target.uid().as_str(),
        );
        let operation = OperationContext::new(
            format!("process-observe:{operation_suffix}"),
            format!("process-observe:{operation_suffix}"),
            format!("process-observe:{operation_suffix}"),
            None,
        )
        .map_err(|_| CoreSourceError::Hint(HintAdmissionError::InvalidHint))?;
        let hint = ControllerHint::new(
            self.controller.clone(),
            target.clone(),
            revision,
            BTreeSet::from([d2b_controller_toolkit::TriggerReason::ScheduledObserve]),
        )
        .map_err(CoreSourceError::Hint)?;
        self.admit_hint(hint, target, revision, operation)
    }

    fn admit_hint(
        &self,
        hint: ControllerHint,
        target: ResourceKey,
        revision: ZoneRevision,
        operation: OperationContext,
    ) -> Result<CoreDispatchOutcome, CoreSourceError> {
        let key = (self.controller.clone(), target);
        let outcome = {
            let mut watch = self
                .watch
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if watch.closed {
                return Err(CoreSourceError::WatchClosed);
            }
            match watch.admission.push(hint) {
                Ok(HintAdmissionOutcome::Admitted) => {
                    watch.operations.insert(key, (revision, operation));
                    HintAdmissionOutcome::Admitted
                }
                Ok(HintAdmissionOutcome::Coalesced) => {
                    let entry = watch
                        .operations
                        .get_mut(&key)
                        .expect("coalesced hint has matching operation state");
                    if revision >= entry.0 {
                        *entry = (revision, operation);
                    }
                    HintAdmissionOutcome::Coalesced
                }
                Err(error) => {
                    if error == HintAdmissionError::Backpressure {
                        self.backpressure.fetch_add(1, Ordering::Relaxed);
                    }
                    return Err(CoreSourceError::Hint(error));
                }
            }
        };
        let dispatch = match outcome {
            HintAdmissionOutcome::Admitted => {
                self.admitted.fetch_add(1, Ordering::Relaxed);
                CoreDispatchOutcome::Admitted
            }
            HintAdmissionOutcome::Coalesced => {
                self.coalesced.fetch_add(1, Ordering::Relaxed);
                CoreDispatchOutcome::Coalesced
            }
        };
        match self.watch_signal_tx.try_send(()) {
            Ok(()) | Err(tokio::sync::mpsc::error::TrySendError::Full(())) => Ok(dispatch),
            Err(tokio::sync::mpsc::error::TrySendError::Closed(())) => {
                Err(CoreSourceError::WatchClosed)
            }
        }
    }

    /// Close the watch after all bounded admitted changes drain.
    pub fn close_watch(&self) -> Result<(), CoreSourceError> {
        self.api.stop_watch();
        self.watch
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .closed = true;
        self.watch_stream_enabled.store(false, Ordering::Release);
        match self.watch_signal_tx.try_send(()) {
            Ok(()) | Err(tokio::sync::mpsc::error::TrySendError::Full(())) => Ok(()),
            Err(tokio::sync::mpsc::error::TrySendError::Closed(())) => {
                Err(CoreSourceError::WatchClosed)
            }
        }
    }

    /// Snapshot admission, coalescing, and backpressure counters.
    pub fn admission_counts(&self) -> CoreAdmissionCounts {
        CoreAdmissionCounts {
            admitted: self.admitted.load(Ordering::Relaxed),
            coalesced: self.coalesced.load(Ordering::Relaxed),
            backpressure: self.backpressure.load(Ordering::Relaxed),
        }
    }
}

impl<A> ControllerSource for CoreControllerSource<A>
where
    A: RegisteredControllerApi,
{
    fn register(
        &self,
        descriptor: &ControllerDescriptor,
    ) -> impl Future<Output = Result<(), SourceError>> + Send {
        let valid = descriptor == &self.descriptor && validate_watch_plan(descriptor);
        async move {
            if !valid {
                return Err(SourceError::Integrity);
            }
            self.api.register(descriptor).await
        }
    }

    fn list_initial(
        &self,
        descriptor: &ControllerDescriptor,
    ) -> impl Future<Output = Result<InitialList, SourceError>> + Send {
        let valid = descriptor == &self.descriptor && validate_watch_plan(descriptor);
        let future = self.api.list_initial(descriptor);
        async move {
            if !valid {
                return Err(SourceError::Integrity);
            }
            future.await
        }
    }

    fn open_watch(
        &self,
        descriptor: &ControllerDescriptor,
        after_revision: ZoneRevision,
    ) -> impl Future<Output = Result<(), SourceError>> + Send {
        let valid = descriptor == &self.descriptor && validate_watch_plan(descriptor);
        let future = self.api.open_watch(descriptor, after_revision);
        async move {
            if !valid {
                return Err(SourceError::Integrity);
            }
            let result = future.await;
            if result.is_ok() && self.api.has_watch_stream() {
                self.watch_stream_enabled.store(true, Ordering::Release);
            }
            result
        }
    }

    async fn receive_watch(&self) -> Result<WatchEvent, WatchFailure> {
        loop {
            let event = {
                let mut watch = self
                    .watch
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if let Some(hint) = watch.admission.pop() {
                    let key = (hint.controller().clone(), hint.target().clone());
                    let Some((_, operation)) = watch.operations.remove(&key) else {
                        return Err(WatchFailure::Fatal);
                    };
                    Some(WatchEvent::Hint(Box::new(hint.into_watch_hint(operation))))
                } else if watch.closed {
                    Some(WatchEvent::Closed)
                } else {
                    None
                }
            };
            if let Some(event) = event {
                return Ok(event);
            }
            if self.watch_stream_enabled.load(Ordering::Acquire) {
                let mut signal_rx = self.watch_signal_rx.lock().await;
                tokio::select! {
                    change = self.api.receive_watch_change() => {
                        match change? {
                            Some((change, operation)) => {
                                match self.dispatch_change(self.controller.clone(), change, operation) {
                                    Ok(CoreDispatchOutcome::Suppressed(_))
                                    | Ok(CoreDispatchOutcome::Admitted)
                                    | Ok(CoreDispatchOutcome::Coalesced) => continue,
                                    Err(CoreSourceError::WatchClosed) => return Ok(WatchEvent::Closed),
                                    Err(_) => return Err(WatchFailure::Fatal),
                                }
                            }
                            None => {
                                self.watch_stream_enabled.store(false, Ordering::Release);
                                self.watch
                                    .lock()
                                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                                    .closed = true;
                                continue;
                            }
                        }
                    }
                    signal = signal_rx.recv() => {
                        if signal.is_none() {
                            return Ok(WatchEvent::Closed);
                        }
                        continue;
                    }
                }
            }
            if self.watch_signal_rx.lock().await.recv().await.is_none() {
                return Ok(WatchEvent::Closed);
            }
        }
    }

    fn read_fresh(
        &self,
        key: &ResourceKey,
    ) -> impl Future<Output = Result<FreshSnapshot, SourceError>> + Send {
        self.api.read_fresh(key)
    }

    fn write_starting(
        &self,
        context: &ReconcileContext,
    ) -> impl Future<Output = Result<(), SourceError>> + Send {
        self.api.write_starting(context)
    }

    fn accept_effect(
        &self,
        context: &ReconcileContext,
        plan: &ReconcilePlan,
    ) -> impl Future<Output = Result<(), SourceError>> + Send {
        self.api.accept_effect(context, plan)
    }

    fn complete_effect(
        &self,
        context: &ReconcileContext,
        result: &ReconcileResult,
    ) -> impl Future<Output = Result<(), SourceError>> + Send {
        self.api.complete_effect(context, result)
    }

    fn verify_expedited_commit(
        &self,
        context: &ReconcileContext,
    ) -> impl Future<Output = Result<bool, SourceError>> + Send {
        self.api.verify_expedited_commit(context)
    }

    fn commit_result(
        &self,
        context: &ReconcileContext,
        result: &ReconcileResult,
    ) -> impl Future<Output = Result<CommitOutcome, SourceError>> + Send {
        self.api.commit_result(context, result)
    }

    fn complete_expedited(
        &self,
        context: &ReconcileContext,
        projection: &ReconcileProjection,
        status_persistence: StatusPersistence,
    ) -> impl Future<Output = Result<(), SourceError>> + Send {
        self.api
            .complete_expedited(context, projection, status_persistence)
    }

    fn persist_outcome(
        &self,
        projection: &ReconcileProjection,
    ) -> impl Future<Output = Result<(), SourceError>> + Send {
        self.api.persist_outcome(projection)
    }

    fn persist_outcome_with_operation(
        &self,
        projection: &ReconcileProjection,
        operation: &OperationContext,
    ) -> impl Future<Output = Result<(), SourceError>> + Send {
        self.api
            .persist_outcome_with_operation(projection, operation)
    }

    fn checkpoint(
        &self,
        context: &ReconcileContext,
        revision: ZoneRevision,
    ) -> impl Future<Output = Result<(), SourceError>> + Send {
        self.api.checkpoint(context, revision)
    }

    fn schedule_requeue(
        &self,
        key: &ResourceKey,
        at_tick: u64,
    ) -> impl Future<Output = Result<(), SourceError>> + Send {
        self.api.schedule_requeue(key, at_tick)
    }
}

/// Failure while constructing the fixed Core controller descriptors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreControllerDescriptorError {
    /// A fixed Core ResourceType could not be parsed.
    InvalidResourceType,
    /// The shared descriptor contract rejected a fixed Core descriptor.
    Descriptor(DescriptorError),
}

impl core::fmt::Display for CoreControllerDescriptorError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidResourceType => formatter.write_str("core-resource-type-invalid"),
            Self::Descriptor(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for CoreControllerDescriptorError {}

impl From<DescriptorError> for CoreControllerDescriptorError {
    fn from(error: DescriptorError) -> Self {
        Self::Descriptor(error)
    }
}

/// Build the fixed Core ResourceType descriptors from one authenticated
/// controller identity.
pub fn core_controller_descriptors(
    identity: ControllerIdentity,
) -> Result<
    Vec<(CoreResourceControllerRegistration, ControllerDescriptor)>,
    CoreControllerDescriptorError,
> {
    CORE_RESOURCE_CONTROLLER_REGISTRATIONS
        .into_iter()
        .map(|registration| {
            let resource_type = ResourceTypeName::parse(registration.resource_type())
                .map_err(|_| CoreControllerDescriptorError::InvalidResourceType)?;
            let resource = ResourceRegistration::new(resource_type.clone(), vec![1], 5_000, 3)?;
            let selectors = [
                SelectorField::Spec,
                SelectorField::Status,
                SelectorField::Metadata,
                SelectorField::Finalizers,
                SelectorField::Deletion,
            ]
            .into_iter()
            .map(|field| ControllerSelector::new(resource_type.clone(), field, None))
            .collect::<Result<Vec<_>, _>>()?;
            let finalizers = registration
                .finalizer()
                .into_iter()
                .map(str::to_owned)
                .collect();
            let descriptor = ControllerDescriptor::new(
                identity.clone(),
                vec![resource],
                vec!["resource-api".to_owned()],
                vec!["system".to_owned()],
                vec![
                    ControllerVerb::ReadSpec,
                    ControllerVerb::ReadStatus,
                    ControllerVerb::WriteStatus,
                    ControllerVerb::AddFinalizer,
                    ControllerVerb::RemoveFinalizer,
                ],
                selectors,
                Vec::new(),
                registration.consumes_owner_triggers(),
                finalizers,
                vec!["d2b.resource.v3".to_owned()],
                vec!["resources.d2bus.org/v3".to_owned()],
                ControllerExecutionPolicy::new(
                    8,
                    4,
                    256,
                    8,
                    256,
                    ResyncPolicy::new(None, 5_000)?,
                )?,
            )?;
            Ok((registration, descriptor))
        })
        .collect()
}

/// Core reconcile adapter error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreReconcileError;

impl core::fmt::Display for CoreReconcileError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("core reconcile contract failed")
    }
}

impl std::error::Error for CoreReconcileError {}

fn resource_has_finalizer(
    resource: &ResourceSnapshot,
    expected: &str,
) -> Result<bool, CoreReconcileError> {
    let value = serde_json::from_slice::<serde_json::Value>(resource.canonical_json())
        .map_err(|_| CoreReconcileError)?;
    Ok(value
        .pointer("/metadata/finalizers")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|finalizers| {
            finalizers
                .iter()
                .any(|value| value.as_str() == Some(expected))
        }))
}

fn status_candidate(resource: &ResourceSnapshot) -> Result<Vec<u8>, CoreReconcileError> {
    let value = serde_json::from_slice::<serde_json::Value>(resource.canonical_json())
        .map_err(|_| CoreReconcileError)?;
    let status = value.get("status").cloned().ok_or(CoreReconcileError)?;
    if !status.is_object() {
        return Err(CoreReconcileError);
    }
    serde_json::to_vec(&status).map_err(|_| CoreReconcileError)
}

/// Core's baseline reconciler for metadata-only convergence.
pub struct CoreResourceReconciler {
    descriptor: ControllerDescriptor,
    handler: crate::CoreHandlerKind,
    ensure_finalizer: bool,
}

impl CoreResourceReconciler {
    /// Bind the reconciler to its complete signed descriptor.
    pub fn new(descriptor: ControllerDescriptor) -> Arc<Self> {
        Arc::new(Self {
            descriptor,
            handler: crate::CoreHandlerKind::Store,
            ensure_finalizer: false,
        })
    }

    /// Bind the reconciler to one fixed Core ResourceType handler.
    pub fn for_handler(
        descriptor: ControllerDescriptor,
        handler: crate::CoreHandlerKind,
    ) -> Arc<Self> {
        Arc::new(Self {
            descriptor,
            handler,
            ensure_finalizer: true,
        })
    }

    /// Return the fixed Core handler represented by this reconciler.
    pub const fn handler(&self) -> crate::CoreHandlerKind {
        self.handler
    }
}

impl ResourceReconciler for CoreResourceReconciler {
    type Error = CoreReconcileError;

    fn classify_error(&self, _error: &Self::Error) -> HandlerFailure {
        HandlerFailure::terminal()
    }

    fn describe(&self) -> impl Future<Output = Result<ControllerDescriptor, Self::Error>> + Send {
        std::future::ready(Ok(self.descriptor.clone()))
    }

    fn validate_spec(
        &self,
        _context: &ReconcileContext,
        resource: &ResourceSnapshot,
    ) -> impl Future<Output = Result<ValidationResult, Self::Error>> + Send {
        std::future::ready(Ok(if resource.canonical_json().is_empty() {
            ValidationResult::Invalid {
                reason: ReconcileReason::InvalidSpec,
            }
        } else {
            ValidationResult::Valid
        }))
    }

    async fn plan(
        &self,
        _context: &ReconcileContext,
        _resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
    ) -> Result<ReconcilePlan, Self::Error> {
        tokio::task::yield_now().await;
        ReconcilePlan::new(Vec::new(), !self.ensure_finalizer).map_err(|_| CoreReconcileError)
    }

    fn reconcile(
        &self,
        context: &ReconcileContext,
        resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
        _plan: &ReconcilePlan,
    ) -> impl Future<Output = Result<ReconcileResult, Self::Error>> + Send {
        std::future::ready((|| {
            context
                .authorize_effect()
                .map_err(|_| CoreReconcileError)?;
            if !self.ensure_finalizer {
                return Ok(ReconcileResult::converged(
                    resource.revision(),
                    resource.generation(),
                ));
            }
            let mut finalizer_missing = false;
            for finalizer in self.descriptor.finalizers() {
                if !resource_has_finalizer(resource, finalizer)? {
                    finalizer_missing = true;
                    break;
                }
            }
            if !finalizer_missing {
                return Ok(ReconcileResult::converged(
                    resource.revision(),
                    resource.generation(),
                ));
            }
            let status = status_candidate(resource)?;
            ReconcileResult::new(
                resource.revision(),
                resource.generation(),
                None,
                Some(status),
                d2b_controller_toolkit::ReconcileDisposition::Pending,
                None,
                None,
                StatusPersistence::Pending,
            )
            .map_err(|_| CoreReconcileError)
        })())
    }

    fn observe(
        &self,
        _context: &ReconcileContext,
        resource: &ResourceSnapshot,
    ) -> impl Future<Output = Result<ObservationResult, Self::Error>> + Send {
        std::future::ready(Ok(ObservationResult::new(ReconcileResult::converged(
            resource.revision(),
            resource.generation(),
        ))))
    }

    fn finalize(
        &self,
        _context: &ReconcileContext,
        resource: &ResourceSnapshot,
    ) -> impl Future<Output = Result<FinalizeResult, Self::Error>> + Send {
        std::future::ready(Ok(FinalizeResult::new(ReconcileResult::converged(
            resource.revision(),
            resource.generation(),
        ))))
    }

    fn prepare_finalize(
        &self,
        context: &ReconcileContext,
        deleting_resource: &ResourceSnapshot,
    ) -> impl Future<Output = Result<ReconcileResult, Self::Error>> + Send {
        let result = (|| {
            context
                .authorize_effect()
                .map_err(|_| CoreReconcileError)?;
            let Some(finalizer) = self.descriptor.finalizers().first() else {
                return Ok(ReconcileResult::converged(
                    deleting_resource.revision(),
                    deleting_resource.generation(),
                ));
            };
            if !resource_has_finalizer(deleting_resource, finalizer)? {
                return Ok(ReconcileResult::converged(
                    deleting_resource.revision(),
                    deleting_resource.generation(),
                ));
            };
            let mutation = MutationIntent::new(
                deleting_resource.key().resource_ref().clone(),
                Some(deleting_resource.key().uid().clone()),
                Some(deleting_resource.revision()),
                MutationIntentKind::UpdateFinalizers,
                None,
            )
            .map_err(|_| CoreReconcileError)?;
            let batch =
                ResourceMutationBatch::new(vec![mutation]).map_err(|_| CoreReconcileError)?;
            ReconcileResult::new(
                deleting_resource.revision(),
                deleting_resource.generation(),
                Some(batch),
                None,
                ReconcileDisposition::Pending,
                None,
                None,
                StatusPersistence::NotRequested,
            )
            .map_err(|_| CoreReconcileError)
        })();
        std::future::ready(result)
    }

    fn execute_finalize(
        &self,
        _context: &ReconcileContext,
        deleting_resource: &ResourceSnapshot,
    ) -> impl Future<Output = Result<ReconcileResult, Self::Error>> + Send {
        std::future::ready(Ok(ReconcileResult::converged(
            deleting_resource.revision(),
            deleting_resource.generation(),
        )))
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
        std::future::ready(
            UpdateAssessment::new(UpdateAssessmentState::Current, Vec::new(), true)
                .map_err(|_| CoreReconcileError),
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
                DisruptionClass::Restart,
                true,
                vec![d2b_controller_toolkit::UpgradeStage::Restart(
                    resource.key().resource_ref().clone(),
                )],
            )
            .map_err(|_| CoreReconcileError),
        )
    }

    fn execute_upgrade(
        &self,
        context: &ReconcileContext,
        resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
        _plan: &UpgradePlan,
    ) -> impl Future<Output = Result<ReconcileResult, Self::Error>> + Send {
        std::future::ready(
            context
                .authorize_effect()
                .map_err(|_| CoreReconcileError)
                .map(|_| ReconcileResult::converged(resource.revision(), resource.generation())),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet, VecDeque};

    use d2b_contracts_resource::v3::{
        ConfigurationGeneration, ControllerGeneration, ObservedGeneration, ResourceGeneration,
        ResourcePhase, ResourceRef, ResourceTypeName, ResourceUid, ZoneId,
    };
    use d2b_controller_toolkit::{
        ControllerExecutionPolicy, ControllerIdentity, ControllerSelector, ControllerVerb,
        InitialResource, ProjectionDisposition, ResourceRegistration, ResyncPolicy, Runner,
        RunnerConfig, SelectorField, TriggerReason,
    };

    use super::*;
    use crate::{ChangeField, CoreTriggerReason};

    const OUTCOME_RETENTION: usize = 2;

    struct TestRegisteredApi {
        initial: InitialList,
        snapshots: Mutex<BTreeMap<ResourceKey, FreshSnapshot>>,
        starting: Mutex<BTreeSet<(ResourceKey, ZoneRevision)>>,
        commits: Mutex<BTreeSet<(ResourceKey, ZoneRevision)>>,
        committed_results: Mutex<Vec<ReconcileResult>>,
        checkpoints: Mutex<BTreeSet<(ResourceKey, ZoneRevision)>>,
        checkpoint_calls: AtomicUsize,
        checkpoint_notify: tokio::sync::Notify,
        outcomes: Mutex<VecDeque<(ResourceKey, ZoneRevision, ReconcileReason)>>,
    }

    impl TestRegisteredApi {
        fn new(initial: InitialList, snapshots: BTreeMap<ResourceKey, FreshSnapshot>) -> Arc<Self> {
            Arc::new(Self {
                initial,
                snapshots: Mutex::new(snapshots),
                starting: Mutex::new(BTreeSet::new()),
                commits: Mutex::new(BTreeSet::new()),
                committed_results: Mutex::new(Vec::new()),
                checkpoints: Mutex::new(BTreeSet::new()),
                checkpoint_calls: AtomicUsize::new(0),
                checkpoint_notify: tokio::sync::Notify::new(),
                outcomes: Mutex::new(VecDeque::new()),
            })
        }

        fn starting_count(&self) -> usize {
            self.starting
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len()
        }

        fn commit_count(&self) -> usize {
            self.commits
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len()
        }

        fn committed_results(&self) -> Vec<ReconcileResult> {
            self.committed_results
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }

        fn checkpoint_count(&self) -> usize {
            self.checkpoints
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len()
        }

        async fn wait_for_checkpoint_calls(&self, expected: usize) {
            loop {
                let notified = self.checkpoint_notify.notified();
                if self.checkpoint_calls.load(Ordering::Acquire) >= expected {
                    return;
                }
                notified.await;
            }
        }

        fn record_outcome(&self, projection: &ReconcileProjection) {
            let mut outcomes = self
                .outcomes
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let key = (projection.target().clone(), projection.revision());
            if outcomes
                .iter()
                .any(|(target, revision, _)| (target, *revision) == (&key.0, key.1))
            {
                return;
            }
            if outcomes.len() == OUTCOME_RETENTION {
                outcomes.pop_front();
            }
            outcomes.push_back((key.0, key.1, projection.reason()));
        }
    }

    impl RegisteredControllerApi for TestRegisteredApi {
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
            std::future::ready(Ok(self.initial.clone()))
        }

        fn open_watch(
            &self,
            _descriptor: &ControllerDescriptor,
            _after_revision: ZoneRevision,
        ) -> impl Future<Output = Result<(), SourceError>> + Send {
            std::future::ready(Ok(()))
        }

        fn read_fresh(
            &self,
            key: &ResourceKey,
        ) -> impl Future<Output = Result<FreshSnapshot, SourceError>> + Send {
            std::future::ready(
                self.snapshots
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .get(key)
                    .cloned()
                    .ok_or(SourceError::Unavailable),
            )
        }

        fn write_starting(
            &self,
            context: &ReconcileContext,
        ) -> impl Future<Output = Result<(), SourceError>> + Send {
            self.starting
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert((context.target().clone(), context.revision()));
            std::future::ready(Ok(()))
        }

        fn commit_result(
            &self,
            context: &ReconcileContext,
            result: &ReconcileResult,
        ) -> impl Future<Output = Result<CommitOutcome, SourceError>> + Send {
            self.commits
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert((context.target().clone(), context.revision()));
            self.committed_results
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(result.clone());
            std::future::ready(Ok(CommitOutcome::Committed(context.revision())))
        }

        fn complete_expedited(
            &self,
            _context: &ReconcileContext,
            projection: &ReconcileProjection,
            _status_persistence: StatusPersistence,
        ) -> impl Future<Output = Result<(), SourceError>> + Send {
            self.record_outcome(projection);
            std::future::ready(Ok(()))
        }

        fn persist_outcome(
            &self,
            projection: &ReconcileProjection,
        ) -> impl Future<Output = Result<(), SourceError>> + Send {
            self.record_outcome(projection);
            std::future::ready(Ok(()))
        }

        fn checkpoint(
            &self,
            context: &ReconcileContext,
            revision: ZoneRevision,
        ) -> impl Future<Output = Result<(), SourceError>> + Send {
            self.checkpoints
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert((context.target().clone(), revision));
            self.checkpoint_calls.fetch_add(1, Ordering::Release);
            self.checkpoint_notify.notify_waiters();
            std::future::ready(Ok(()))
        }

        fn schedule_requeue(
            &self,
            _key: &ResourceKey,
            _at_tick: u64,
        ) -> impl Future<Output = Result<(), SourceError>> + Send {
            std::future::ready(Ok(()))
        }
    }

    fn key(name: &str, suffix: u16) -> ResourceKey {
        ResourceKey::new(
            ZoneId::parse("work").unwrap(),
            ResourceRef::parse(&format!("Process/{name}")).unwrap(),
            ResourceUid::parse(format!("123e4567-e89b-42d3-a456-{suffix:012}")).unwrap(),
        )
    }

    fn controller_key() -> ControllerLeaseKey {
        ControllerLeaseKey::new(
            ZoneId::parse("work").unwrap(),
            ResourceRef::parse("Process/controller").unwrap(),
        )
        .unwrap()
    }

    fn descriptor(max_pending: usize) -> ControllerDescriptor {
        let resource_type = ResourceTypeName::parse("Process").unwrap();
        ControllerDescriptor::new(
            ControllerIdentity::new(
                ZoneId::parse("work").unwrap(),
                ResourceRef::parse("Process/controller").unwrap(),
                ControllerGeneration::new(1).unwrap(),
                ResourceRef::parse("Provider/core").unwrap(),
                ResourceGeneration::new(1).unwrap(),
                ResourceRef::parse("Process/controller").unwrap(),
                ResourceRef::parse("Host/system").unwrap(),
                None,
            )
            .unwrap(),
            vec![ResourceRegistration::new(resource_type.clone(), vec![1], 5_000, 3).unwrap()],
            vec!["resource-api".to_owned()],
            vec!["host".to_owned()],
            vec![ControllerVerb::ReadSpec, ControllerVerb::WriteStatus],
            vec![ControllerSelector::new(resource_type, SelectorField::Spec, None).unwrap()],
            Vec::new(),
            true,
            Vec::new(),
            vec!["service.v1".to_owned()],
            vec!["schema.v1".to_owned()],
            ControllerExecutionPolicy::new(
                1,
                1,
                max_pending,
                1,
                4,
                ResyncPolicy::new(Some(100), 5_000).unwrap(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn snapshot(target: ResourceKey, revision: u64) -> ResourceSnapshot {
        ResourceSnapshot::new(
            target,
            ZoneRevision::new(revision),
            ResourceGeneration::new(revision).unwrap(),
            b"{}".to_vec(),
            false,
        )
    }

    fn change(
        target: ResourceKey,
        revision: u64,
        reasons: BTreeSet<CoreTriggerReason>,
    ) -> ChangeRecord {
        ChangeRecord {
            target,
            revision: ZoneRevision::new(revision),
            generation: ResourceGeneration::new(revision).unwrap(),
            observed_generation: ObservedGeneration::new(revision.saturating_sub(1)),
            fields: BTreeSet::from([ChangeField::Spec]),
            reasons,
            type_is_bound: true,
            relevant_field_changed: true,
            own_status_only: false,
            owner_consumer_exists: false,
            dependency_consumer_exists: false,
            controller_generation_current: true,
            conditions_require_work: false,
            unknown_requires_observation: false,
        }
    }

    fn operation(id: &str) -> OperationContext {
        OperationContext::new(id, format!("idem-{id}"), format!("corr-{id}"), None).unwrap()
    }

    fn source_with_snapshot(
        descriptor: &ControllerDescriptor,
        target: &ResourceKey,
        revision: u64,
    ) -> (
        Arc<TestRegisteredApi>,
        Arc<CoreControllerSource<TestRegisteredApi>>,
    ) {
        let target_snapshot = snapshot(target.clone(), revision);
        let api = TestRegisteredApi::new(
            InitialList {
                resources: Vec::new(),
                snapshot_revision: ZoneRevision::new(1),
            },
            BTreeMap::from([(
                target.clone(),
                FreshSnapshot::Present {
                    target: target_snapshot,
                    dependencies: Vec::new(),
                },
            )]),
        );
        let source = CoreControllerSource::new(descriptor.clone(), Arc::clone(&api));
        (api, source)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn durable_core_change_wakes_toolkit_queue_and_reconciles() {
        let target = key("app", 1);
        let descriptor = descriptor(8);
        let (api, source) = source_with_snapshot(&descriptor, &target, 2);
        let reconciler = CoreResourceReconciler::new(descriptor);
        let runner = tokio::spawn(
            Runner::new(
                reconciler,
                Arc::clone(&source),
                RunnerConfig {
                    policy_revision: 1,
                    api_revision: 1,
                    configuration_revision: ConfigurationGeneration::new(1).unwrap(),
                    deadline_tick: 5_000,
                    max_attempts: 3,
                },
            )
            .run(),
        );

        tokio::task::yield_now().await;
        assert_eq!(
            source
                .dispatch_change(
                    controller_key(),
                    change(
                        target,
                        2,
                        BTreeSet::from([CoreTriggerReason::SpecGenerationChanged]),
                    ),
                    operation("op"),
                )
                .unwrap(),
            CoreDispatchOutcome::Admitted
        );
        api.wait_for_checkpoint_calls(1).await;
        assert_eq!(api.checkpoint_count(), 1);
        source.close_watch().unwrap();
        let report = runner.await.unwrap().unwrap();
        assert_eq!(report.dispatched, 1);
        assert_eq!(report.checkpointed, 1);
        assert_eq!(
            source.admission_counts(),
            CoreAdmissionCounts {
                admitted: 1,
                coalesced: 0,
                backpressure: 0,
            }
        );
    }

    #[tokio::test]
    async fn declared_observation_wakeup_bypasses_convergence_suppression() {
        let target = key("observed", 9);
        let descriptor = descriptor(2);
        let (_api, source) = source_with_snapshot(&descriptor, &target, 2);

        assert_eq!(
            source
                .dispatch_observation(target, ZoneRevision::new(2))
                .unwrap(),
            CoreDispatchOutcome::Admitted
        );
        let WatchEvent::Hint(hint) = source.receive_watch().await.unwrap() else {
            panic!("observation wakeup returned an unexpected event");
        };
        assert!(hint.reasons().contains(TriggerReason::ScheduledObserve));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn production_core_source_cannot_authorize_expedited_effects() {
        let target = key("expedited", 2);
        let descriptor = descriptor(8);
        let (api, source) = source_with_snapshot(&descriptor, &target, 2);
        let runner = Runner::new(
            CoreResourceReconciler::new(descriptor),
            Arc::clone(&source),
            RunnerConfig {
                policy_revision: 1,
                api_revision: 1,
                configuration_revision: ConfigurationGeneration::new(1).unwrap(),
                deadline_tick: 5_000,
                max_attempts: 3,
            },
        )
        .run();

        assert_eq!(
            source
                .dispatch_change(
                    controller_key(),
                    change(
                        target,
                        2,
                        BTreeSet::from([CoreTriggerReason::ExpeditedMutation]),
                    ),
                    operation("expedited"),
                )
                .unwrap(),
            CoreDispatchOutcome::Admitted
        );
        source.close_watch().unwrap();

        let report = runner.await.unwrap();
        assert_eq!(report.dispatched, 1);
        assert_eq!(report.checkpointed, 0);
        assert_eq!(api.starting_count(), 0);
        assert_eq!(api.commit_count(), 0);
        assert!(
            api.outcomes
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_empty()
        );
    }

    #[tokio::test]
    async fn core_watch_admission_is_bounded_coalesced_and_counted() {
        let descriptor = descriptor(1);
        let first = key("first", 4);
        let api = TestRegisteredApi::new(
            InitialList {
                resources: Vec::new(),
                snapshot_revision: ZoneRevision::new(1),
            },
            BTreeMap::new(),
        );
        let source = CoreControllerSource::new(descriptor, api);

        assert_eq!(
            source
                .dispatch_change(
                    controller_key(),
                    change(
                        first.clone(),
                        2,
                        BTreeSet::from([CoreTriggerReason::SpecGenerationChanged]),
                    ),
                    operation("first"),
                )
                .unwrap(),
            CoreDispatchOutcome::Admitted
        );
        assert_eq!(
            source
                .dispatch_change(
                    controller_key(),
                    change(
                        first,
                        3,
                        BTreeSet::from([CoreTriggerReason::DeletionRequested]),
                    ),
                    operation("coalesced"),
                )
                .unwrap(),
            CoreDispatchOutcome::Coalesced
        );
        assert_eq!(
            source
                .dispatch_change(
                    controller_key(),
                    change(
                        key("second", 5),
                        2,
                        BTreeSet::from([CoreTriggerReason::SpecGenerationChanged]),
                    ),
                    operation("rejected"),
                )
                .unwrap_err(),
            CoreSourceError::Hint(HintAdmissionError::Backpressure)
        );
        assert_eq!(
            source.admission_counts(),
            CoreAdmissionCounts {
                admitted: 1,
                coalesced: 1,
                backpressure: 1,
            }
        );

        let WatchEvent::Hint(hint) = source.receive_watch().await.unwrap() else {
            panic!("bounded watch returned an unexpected event");
        };
        assert_eq!(hint.revision(), ZoneRevision::new(3));
        assert!(
            hint.reasons()
                .contains(TriggerReason::SpecGenerationChanged)
        );
        assert!(hint.reasons().contains(TriggerReason::DeletionRequested));
    }

    #[tokio::test]
    async fn test_persistence_is_revision_idempotent_and_retention_bounded() {
        let api = TestRegisteredApi::new(
            InitialList {
                resources: Vec::new(),
                snapshot_revision: ZoneRevision::new(1),
            },
            BTreeMap::new(),
        );
        let target = key("outcome", 6);
        for revision in [2, 2, 3, 4] {
            api.persist_outcome(&ReconcileProjection::new(
                target.clone(),
                ZoneRevision::new(revision),
                ResourcePhase::Failed,
                ProjectionDisposition::Failed,
                ReconcileReason::HandlerTerminal,
                false,
            ))
            .await
            .unwrap();
        }
        let outcomes = api
            .outcomes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(outcomes.len(), OUTCOME_RETENTION);
        assert_eq!(outcomes[0].1, ZoneRevision::new(3));
        assert_eq!(outcomes[1].1, ZoneRevision::new(4));
    }

    #[test]
    fn core_controller_catalog_covers_every_fixed_resource_owner() {
        let identity = descriptor(8).identity().clone();
        let registrations =
            core_controller_descriptors(identity).expect("fixed Core descriptors are valid");
        let resource_types = registrations
            .iter()
            .map(|(_, descriptor)| {
                descriptor
                    .resource_types()
                    .next()
                    .expect("each Core descriptor owns one ResourceType")
                    .as_str()
                    .to_owned()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            resource_types,
            vec![
                "Zone",
                "ZoneLink",
                "Provider",
                "Role",
                "RoleBinding",
                "Quota",
                "EmergencyPolicy",
                "ResourceExport",
                "ResourceImport",
            ]
        );
        assert!(
            registrations
                .iter()
                .all(|(_, descriptor)| descriptor.watch_selectors().len() == 5)
        );
        let mut finalizers = registrations
            .iter()
            .filter_map(|(_, descriptor)| descriptor.finalizers().first())
            .map(String::as_str)
            .collect::<Vec<_>>();
        finalizers.sort_unstable();
        assert_eq!(
            finalizers,
            vec![
                "core.emergency-drain",
                "core.provider-api-binding",
                "core.quota-drain",
                "core.resource-export-drain",
                "core.resource-import-drain",
                "core.role-binding-drain",
                "core.zone-link-drain",
            ]
        );
    }

    #[tokio::test]
    async fn core_finalize_removes_one_exact_finalizer_for_every_owner() {
        let identity = descriptor(8).identity().clone();
        let descriptors =
            core_controller_descriptors(identity).expect("fixed Core descriptors are valid");
        let mut finalizer_count = 0;
        for (index, (registration, descriptor)) in descriptors.into_iter().enumerate() {
            let Some(finalizer) = registration.finalizer() else {
                continue;
            };
            finalizer_count += 1;
            assert_eq!(descriptor.finalizers(), &[finalizer.to_owned()]);
            let key = ResourceKey::new(
                ZoneId::parse("work").unwrap(),
                ResourceRef::parse(&format!("{}/deleting-{index}", registration.resource_type()))
                    .unwrap(),
                ResourceUid::parse(format!(
                    "123e4567-e89b-42d3-a456-{index:012}"
                ))
                .unwrap(),
            );
            let resource = ResourceSnapshot::new(
                key.clone(),
                ZoneRevision::new(4),
                ResourceGeneration::new(2).unwrap(),
                serde_json::to_vec(&serde_json::json!({
                    "metadata": {
                        "finalizers": [finalizer, "foreign.finalizer"]
                    },
                    "status": {}
                }))
                .unwrap(),
                true,
            );
            let api = TestRegisteredApi::new(
                InitialList {
                    resources: vec![InitialResource::new(key.clone(), resource.revision())],
                    snapshot_revision: resource.revision(),
                },
                BTreeMap::from([(
                    key,
                    FreshSnapshot::Present {
                        target: resource,
                        dependencies: Vec::new(),
                    },
                )]),
            );
            let source = CoreControllerSource::new(descriptor.clone(), Arc::clone(&api));
            let task = tokio::spawn(
                Runner::new(
                    CoreResourceReconciler::for_handler(descriptor, registration.handler()),
                    Arc::clone(&source),
                    RunnerConfig {
                        policy_revision: 1,
                        api_revision: 1,
                        configuration_revision: ConfigurationGeneration::new(1).unwrap(),
                        deadline_tick: 5_000,
                        max_attempts: 1,
                    },
                )
                .run(),
            );
            api.wait_for_checkpoint_calls(1).await;
            source.close_watch().unwrap();
            let report = task.await.unwrap().unwrap();
            assert_eq!(report.checkpointed, 1);
            let result = api
                .committed_results()
                .into_iter()
                .next()
                .expect("finalizer removal was committed");
            let mutation = result
                .mutation_batch()
                .expect("present Core finalizer requires one mutation")
                .mutations()
                .first()
                .expect("finalizer mutation is present");
            assert_eq!(mutation.kind(), MutationIntentKind::UpdateFinalizers);
            assert!(
                mutation.canonical_resource().is_none(),
                "finalizer removal must use the typed delta path"
            );
        }
        assert_eq!(finalizer_count, 7);
    }

    #[tokio::test]
    async fn absent_or_empty_core_finalizer_is_already_cleared() {
        let identity = descriptor(8).identity().clone();
        let (registration, descriptor) = core_controller_descriptors(identity)
            .unwrap()
            .into_iter()
            .find(|(registration, _)| registration.finalizer().is_some())
            .unwrap();
        for (index, finalizers) in [Vec::<&str>::new(), vec!["foreign.finalizer"]]
            .into_iter()
            .enumerate()
        {
            let key = ResourceKey::new(
                ZoneId::parse("work").unwrap(),
                ResourceRef::parse(&format!(
                    "{}/already-cleared-{index}",
                    registration.resource_type()
                ))
                .unwrap(),
                ResourceUid::parse(format!(
                    "123e4567-e89b-42d3-a456-{:012}",
                    index + 100
                ))
                .unwrap(),
            );
            let resource = ResourceSnapshot::new(
                key.clone(),
                ZoneRevision::new(4),
                ResourceGeneration::new(2).unwrap(),
                serde_json::to_vec(&serde_json::json!({
                    "metadata": {"finalizers": finalizers},
                    "status": {}
                }))
                .unwrap(),
                true,
            );
            let api = TestRegisteredApi::new(
                InitialList {
                    resources: vec![InitialResource::new(key.clone(), resource.revision())],
                    snapshot_revision: resource.revision(),
                },
                BTreeMap::from([(
                    key,
                    FreshSnapshot::Present {
                        target: resource,
                        dependencies: Vec::new(),
                    },
                )]),
            );
            let source = CoreControllerSource::new(descriptor.clone(), api);
            let task = tokio::spawn(
                Runner::new(
                    CoreResourceReconciler::for_handler(descriptor.clone(), registration.handler()),
                    Arc::clone(&source),
                    RunnerConfig {
                        policy_revision: 1,
                        api_revision: 1,
                        configuration_revision: ConfigurationGeneration::new(1).unwrap(),
                        deadline_tick: 5_000,
                        max_attempts: 1,
                    },
                )
                .run(),
            );
            source.close_watch().unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
    }

}
