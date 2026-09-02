//! Bounded async adapter for the blocking process effect owner.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{
    Receiver, RecvTimeoutError, Sender, SyncSender, TrySendError, channel, sync_channel,
};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, Waker};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::broker::{BrokerLaunchResolver, BrokerProcessBackend};
use d2b_contracts_resource::v3::ResourceUid;
use d2b_process::{
    AdoptionCandidate, BackendObservation, LaunchTicket, LaunchedProcess, PidfdEvidence,
    ProcessConformanceError, ProcessEffectBackend, ProcessEffectError, ProcessIdentityDigest,
    ProcessLaunchEffectPort, ProcessLaunchRequest, ProcessRequest, ProcessStopClass, StopClass,
};
/// Default upper bound for concurrent blocking process effects.
pub const DEFAULT_BLOCKING_LIMIT: usize = 16;

type Job = Box<dyn FnOnce() + Send + 'static>;

struct BlockingPool {
    sender: Option<SyncSender<Job>>,
    workers: Vec<JoinHandle<()>>,
    deadline_sender: Option<Sender<Deadline>>,
    deadline_worker: Option<JoinHandle<()>>,
}

struct Deadline {
    at: Instant,
    state: Weak<dyn DeadlineState>,
}

trait DeadlineState: Send + Sync {
    fn is_completed(&self) -> bool;
    fn wake_deadline(&self);
}

impl BlockingPool {
    fn new(limit: usize) -> Self {
        let (sender, receiver) = sync_channel::<Job>(limit);
        let receiver = Arc::new(Mutex::new(receiver));
        let workers = (0..limit)
            .map(|_| {
                let receiver = Arc::clone(&receiver);
                std::thread::Builder::new()
                    .name("d2b-process-effect".to_owned())
                    .spawn(move || worker(receiver))
                    .expect("create bounded process effect worker")
            })
            .collect();
        let (deadline_sender, deadline_receiver) = channel();
        let deadline_worker = std::thread::Builder::new()
            .name("d2b-process-deadlines".to_owned())
            .spawn(move || deadline_worker(deadline_receiver))
            .expect("create process effect deadline worker");
        Self {
            sender: Some(sender),
            workers,
            deadline_sender: Some(deadline_sender),
            deadline_worker: Some(deadline_worker),
        }
    }

    fn submit<T, F>(&self, timeout: Duration, operation: F) -> JobFuture<T>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T, ProcessEffectError> + Send + 'static,
    {
        self.submit_with_deadline(timeout, move |_| operation())
    }

    fn submit_with_deadline<T, F>(&self, timeout: Duration, operation: F) -> JobFuture<T>
    where
        T: Send + 'static,
        F: FnOnce(Instant) -> Result<T, ProcessEffectError> + Send + 'static,
    {
        let deadline = Instant::now() + timeout;
        let state = Arc::new(JobState::default());
        let worker_state = Arc::clone(&state);
        let job = Box::new(move || worker_state.complete(operation(deadline)));
        let deadline_state: Arc<dyn DeadlineState> = state.clone();
        if self
            .deadline_sender
            .as_ref()
            .expect("deadline sender present")
            .send(Deadline {
                at: deadline,
                state: Arc::downgrade(&deadline_state),
            })
            .is_err()
        {
            state.complete(Err(ProcessEffectError::LaunchFailed));
            return JobFuture { state, deadline };
        }
        let submit_error = match self
            .sender
            .as_ref()
            .expect("pool sender present")
            .try_send(job)
        {
            Ok(()) => None,
            Err(TrySendError::Full(_)) => Some(ProcessEffectError::Busy),
            Err(TrySendError::Disconnected(_)) => Some(ProcessEffectError::LaunchFailed),
        };
        if let Some(error) = submit_error {
            state.complete(Err(error));
        }
        JobFuture { state, deadline }
    }
}

impl Drop for BlockingPool {
    fn drop(&mut self) {
        self.sender.take();
        self.workers.clear();
        self.deadline_sender.take();
        if let Some(worker) = self.deadline_worker.take() {
            let _ = worker.join();
        }
    }
}

fn worker(receiver: Arc<Mutex<Receiver<Job>>>) {
    loop {
        let job = {
            let Ok(receiver) = receiver.lock() else {
                return;
            };
            receiver.recv()
        };
        match job {
            Ok(job) => job(),
            Err(_) => return,
        }
    }
}

struct JobState<T> {
    result: Mutex<Option<Result<T, ProcessEffectError>>>,
    waker: Mutex<Option<Waker>>,
    completed: AtomicBool,
}

impl<T> Default for JobState<T> {
    fn default() -> Self {
        Self {
            result: Mutex::new(None),
            waker: Mutex::new(None),
            completed: AtomicBool::new(false),
        }
    }
}

impl<T> JobState<T> {
    fn complete(&self, result: Result<T, ProcessEffectError>) {
        if self.completed.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Ok(mut slot) = self.result.lock() {
            *slot = Some(result);
        }
        self.wake();
    }

    fn wake(&self) {
        if let Ok(mut waker) = self.waker.lock()
            && let Some(waker) = waker.take()
        {
            waker.wake();
        }
    }
}

impl<T: Send> DeadlineState for JobState<T> {
    fn is_completed(&self) -> bool {
        self.completed.load(Ordering::Acquire)
    }

    fn wake_deadline(&self) {
        self.wake();
    }
}

fn deadline_worker(receiver: Receiver<Deadline>) {
    let mut deadlines = Vec::<Deadline>::new();
    loop {
        deadlines.retain(|deadline| {
            deadline
                .state
                .upgrade()
                .is_some_and(|state| !state.is_completed())
        });
        deadlines.sort_by_key(|deadline| std::cmp::Reverse(deadline.at));
        let next_wait = deadlines
            .last()
            .map(|deadline| deadline.at.saturating_duration_since(Instant::now()));
        let received = match next_wait {
            Some(wait) => receiver.recv_timeout(wait),
            None => receiver.recv().map_err(|_| RecvTimeoutError::Disconnected),
        };
        match received {
            Ok(deadline) => deadlines.push(deadline),
            Err(RecvTimeoutError::Timeout) => {
                let now = Instant::now();
                while deadlines.last().is_some_and(|deadline| deadline.at <= now) {
                    if let Some(deadline) = deadlines.pop()
                        && let Some(state) = deadline.state.upgrade()
                        && !state.is_completed()
                    {
                        state.wake_deadline();
                    }
                }
            }
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

struct JobFuture<T> {
    state: Arc<JobState<T>>,
    deadline: Instant,
}

impl<T> Future for JobFuture<T> {
    type Output = Result<T, ProcessEffectError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if let Ok(mut result) = self.state.result.lock()
            && let Some(result) = result.take()
        {
            return Poll::Ready(result);
        }
        if Instant::now() >= self.deadline {
            return Poll::Ready(Err(ProcessEffectError::DeadlineExceeded));
        }
        if let Ok(mut waker) = self.state.waker.lock() {
            *waker = Some(context.waker().clone());
        }
        if let Ok(mut result) = self.state.result.lock()
            && let Some(result) = result.take()
        {
            return Poll::Ready(result);
        }
        Poll::Pending
    }
}

enum LaunchOutcome {
    OnTime(BackendObservation),
    TimedOut,
}

struct LaunchReconciliation {
    process_uid: ResourceUid,
    identity: Option<ProcessIdentityDigest>,
    quarantined: bool,
}

struct RuntimeState<H> {
    handles: BTreeMap<ProcessIdentityDigest, Arc<H>>,
    launches: BTreeMap<ResourceUid, LaunchReconciliation>,
    quarantined_processes: BTreeSet<ResourceUid>,
    quarantined_identities: BTreeSet<ProcessIdentityDigest>,
}

impl<H> Default for RuntimeState<H> {
    fn default() -> Self {
        Self {
            handles: BTreeMap::new(),
            launches: BTreeMap::new(),
            quarantined_processes: BTreeSet::new(),
            quarantined_identities: BTreeSet::new(),
        }
    }
}

/// The fixed core-owned implementation of [`ProcessLaunchEffectPort`].
///
/// The adapter admits at most `blocking_limit` blocking calls at once and runs
/// each admitted call on a dedicated bounded worker pool. Handles remain private in an
/// identity-keyed table; Providers receive only opaque evidence.
pub struct ProviderSupervisor<B: ProcessEffectBackend> {
    inner: Arc<Inner<B>>,
}

struct Inner<B: ProcessEffectBackend> {
    backend: Arc<B>,
    pool: BlockingPool,
    state: Arc<Mutex<RuntimeState<B::Handle>>>,
    default_timeout: Duration,
}

impl<B: ProcessEffectBackend> Clone for ProviderSupervisor<B> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<B: ProcessEffectBackend> std::fmt::Debug for ProviderSupervisor<B> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProviderSupervisor(<redacted>)")
    }
}

impl<B: ProcessEffectBackend> ProviderSupervisor<B> {
    /// Build an adapter with the default blocking concurrency bound.
    pub fn new(backend: B) -> Self {
        Self::with_limits(backend, DEFAULT_BLOCKING_LIMIT, Duration::from_secs(30))
    }

    /// Build an adapter with explicit blocking concurrency and fallback timeout.
    ///
    /// A zero blocking limit is rejected because it would deadlock every call.
    pub fn with_limits(backend: B, blocking_limit: usize, default_timeout: Duration) -> Self {
        assert!(blocking_limit > 0, "blocking limit must be nonzero");
        assert!(!default_timeout.is_zero(), "timeout must be nonzero");
        Self {
            inner: Arc::new(Inner {
                backend: Arc::new(backend),
                pool: BlockingPool::new(blocking_limit),
                state: Arc::new(Mutex::new(RuntimeState::default())),
                default_timeout,
            }),
        }
    }

    async fn blocking<T, F>(&self, timeout: Duration, operation: F) -> Result<T, ProcessEffectError>
    where
        T: Send + 'static,
        F: FnOnce(Arc<B>) -> Result<T, ProcessEffectError> + Send + 'static,
    {
        let backend = Arc::clone(&self.inner.backend);
        self.inner
            .pool
            .submit(timeout, move || operation(backend))
            .await
    }

    /// Finalize one exact process identity after observation says it exited.
    ///
    /// The local handle remains private to the supervisor while the backend
    /// removes its broker or service-manager registration. Only after that
    /// effect succeeds is the identity forgotten from the supervisor table.
    pub async fn finalize_identity(
        &self,
        identity: &ProcessIdentityDigest,
    ) -> Result<(), ProcessConformanceError> {
        let handle = self.handle(identity).map_err(map_error)?;
        let finalize_handle = Arc::clone(&handle);
        let finalize_identity = *identity;
        let state = Arc::clone(&self.inner.state);
        let result = self
            .blocking(self.inner.default_timeout, move |backend| {
                let result = backend.finalize(finalize_handle.as_ref());
                if result.is_ok() || result == Err(ProcessEffectError::Vanished) {
                    let mut state = state.lock().map_err(|_| ProcessEffectError::StopFailed)?;
                    if state
                        .handles
                        .get(&finalize_identity)
                        .is_some_and(|retained| Arc::ptr_eq(retained, &finalize_handle))
                    {
                        state.handles.remove(&finalize_identity);
                        state.quarantined_identities.remove(&finalize_identity);
                    }
                }
                result
            })
            .await;
        match result {
            Ok(()) | Err(ProcessEffectError::Vanished) => Ok(()),
            Err(error) => Err(map_error(error)),
        }
    }

    /// Take the Provider-controller bootstrap endpoint retained with one handle.
    pub async fn take_controller_bootstrap(
        &self,
        identity: &ProcessIdentityDigest,
    ) -> Result<Option<std::os::fd::OwnedFd>, ProcessConformanceError> {
        let handle = self.handle(identity).map_err(map_error)?;
        self.blocking(self.inner.default_timeout, move |backend| {
            backend.take_controller_bootstrap(handle.as_ref())
        })
        .await
        .map_err(map_error)
    }

    fn remember(
        &self,
        identity: ProcessIdentityDigest,
        handle: B::Handle,
    ) -> Result<(), ProcessEffectError> {
        self.inner
            .state
            .lock()
            .map_err(|_| ProcessEffectError::LaunchFailed)?
            .handles
            .insert(identity, Arc::new(handle));
        Ok(())
    }

    fn begin_launch(&self, ticket: &LaunchTicket) -> Result<ResourceUid, ProcessEffectError> {
        let operation_uid = ticket.operation().operation_uid().clone();
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| ProcessEffectError::LaunchFailed)?;
        if state.launches.contains_key(&operation_uid) {
            return Err(ProcessEffectError::Busy);
        }
        state.launches.insert(
            operation_uid.clone(),
            LaunchReconciliation {
                process_uid: ticket.process_uid().clone(),
                identity: None,
                quarantined: false,
            },
        );
        Ok(operation_uid)
    }

    fn quarantine_launch(&self, operation_uid: &ResourceUid) -> Result<bool, ProcessEffectError> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| ProcessEffectError::LaunchFailed)?;
        let Some(launch) = state.launches.get_mut(operation_uid) else {
            return Ok(false);
        };
        launch.quarantined = true;
        let process_uid = launch.process_uid.clone();
        let identity = launch.identity;
        state.quarantined_processes.insert(process_uid);
        if let Some(identity) = identity {
            state.quarantined_identities.insert(identity);
        }
        Ok(true)
    }

    fn finish_launch_success(&self, operation_uid: &ResourceUid) -> Result<(), ProcessEffectError> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| ProcessEffectError::LaunchFailed)?;
        if let Some(launch) = state.launches.remove(operation_uid)
            && launch.quarantined
        {
            state.quarantined_processes.remove(&launch.process_uid);
            if let Some(identity) = launch.identity {
                state.quarantined_identities.remove(&identity);
            }
        }
        Ok(())
    }

    fn handle(
        &self,
        identity: &ProcessIdentityDigest,
    ) -> Result<Arc<B::Handle>, ProcessEffectError> {
        self.inner
            .state
            .lock()
            .map_err(|_| ProcessEffectError::StopFailed)?
            .handles
            .get(identity)
            .cloned()
            .ok_or(ProcessEffectError::Vanished)
    }

    fn quarantine_handle(
        &self,
        identity: ProcessIdentityDigest,
        handle: &Arc<B::Handle>,
    ) -> Result<bool, ProcessEffectError> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| ProcessEffectError::StopFailed)?;
        if !state
            .handles
            .get(&identity)
            .is_some_and(|retained| Arc::ptr_eq(retained, handle))
        {
            return Ok(false);
        }
        state.quarantined_identities.insert(identity);
        Ok(true)
    }

    async fn launch_with_timeout(
        &self,
        ticket: &LaunchTicket,
        request: ProcessLaunchRequest,
        timeout: Duration,
    ) -> Result<LaunchedProcess, ProcessConformanceError> {
        let operation_uid = self.begin_launch(ticket).map_err(map_error)?;
        let backend = Arc::clone(&self.inner.backend);
        let state = Arc::clone(&self.inner.state);
        let worker_operation_uid = operation_uid.clone();
        let outcome = self
            .inner
            .pool
            .submit_with_deadline(timeout, move |deadline| {
                let launch = backend.launch_with_inherited_fds(request);
                let late = Instant::now() >= deadline;
                match (launch, late) {
                    (Err(error), late) => {
                        let mut state =
                            state.lock().map_err(|_| ProcessEffectError::LaunchFailed)?;
                        if let Some(launch) = state.launches.remove(&worker_operation_uid)
                            && launch.quarantined
                        {
                            state.quarantined_processes.remove(&launch.process_uid);
                            if let Some(identity) = launch.identity {
                                state.quarantined_identities.remove(&identity);
                            }
                        }
                        if late {
                            Err(ProcessEffectError::DeadlineExceeded)
                        } else {
                            Err(error)
                        }
                    }
                    (Ok(launch), false) => {
                        let (observation, handle) = launch.into_parts();
                        let identity = observation.identity();
                        let mut state =
                            state.lock().map_err(|_| ProcessEffectError::LaunchFailed)?;
                        state.handles.insert(identity, Arc::new(handle));
                        if let Some(launch) = state.launches.get_mut(&worker_operation_uid) {
                            launch.identity = Some(identity);
                        }
                        Ok(LaunchOutcome::OnTime(observation))
                    }
                    (Ok(launch), true) => {
                        let (observation, handle) = launch.into_parts();
                        let identity = observation.identity();
                        let handle = Arc::new(handle);
                        {
                            let mut state =
                                state.lock().map_err(|_| ProcessEffectError::LaunchFailed)?;
                            state.handles.insert(identity, Arc::clone(&handle));
                            state.quarantined_identities.insert(identity);
                            let process_uid = if let Some(launch) =
                                state.launches.get_mut(&worker_operation_uid)
                            {
                                launch.identity = Some(identity);
                                launch.quarantined = true;
                                Some(launch.process_uid.clone())
                            } else {
                                None
                            };
                            if let Some(process_uid) = process_uid {
                                state.quarantined_processes.insert(process_uid);
                            }
                        }
                        match backend.stop(handle.as_ref(), ProcessStopClass::Terminate) {
                            Ok(()) | Err(ProcessEffectError::Vanished) => {
                                let mut state =
                                    state.lock().map_err(|_| ProcessEffectError::StopFailed)?;
                                if state
                                    .handles
                                    .get(&identity)
                                    .is_some_and(|retained| Arc::ptr_eq(retained, &handle))
                                {
                                    state.handles.remove(&identity);
                                    state.quarantined_identities.remove(&identity);
                                }
                                if let Some(launch) = state.launches.remove(&worker_operation_uid) {
                                    state.quarantined_processes.remove(&launch.process_uid);
                                }
                                Ok(LaunchOutcome::TimedOut)
                            }
                            Err(_) => Err(ProcessEffectError::FateUnknown),
                        }
                    }
                }
            })
            .await;
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(ProcessEffectError::DeadlineExceeded) => {
                return if self.quarantine_launch(&operation_uid).map_err(map_error)? {
                    Err(ProcessConformanceError::AdoptionAmbiguous)
                } else {
                    Err(ProcessConformanceError::DeadlineExceeded)
                };
            }
            Err(error) => return Err(map_error(error)),
        };
        let observation = match outcome {
            LaunchOutcome::TimedOut => return Err(ProcessConformanceError::DeadlineExceeded),
            LaunchOutcome::OnTime(observation) => observation,
        };
        self.finish_launch_success(&operation_uid)
            .map_err(map_error)?;
        let identity = observation.identity();
        Ok(LaunchedProcess {
            identity,
            observed: observation.observed().clone(),
            pidfd: PidfdEvidence::held(),
            wait_reap_owner: observation.wait_reap_owner(),
        })
    }
}

impl<B: ProcessEffectBackend> ProcessLaunchEffectPort for ProviderSupervisor<B> {
    async fn launch(
        &self,
        ticket: &LaunchTicket,
    ) -> Result<LaunchedProcess, ProcessConformanceError> {
        self.launch_with_inherited_fds(ticket, Vec::new()).await
    }

    async fn launch_with_inherited_fds(
        &self,
        ticket: &LaunchTicket,
        inherited_fds: Vec<std::os::fd::OwnedFd>,
    ) -> Result<LaunchedProcess, ProcessConformanceError> {
        let timeout = Duration::from_millis(u64::from(ticket.operation().deadline_ms()));
        let request = ProcessLaunchRequest::new(ProcessRequest::new(ticket.clone()), inherited_fds)
            .map_err(|_| ProcessConformanceError::InvalidTicket)?;
        self.launch_with_timeout(ticket, request, timeout).await
    }

    async fn observe(
        &self,
        ticket: &LaunchTicket,
    ) -> Result<Option<AdoptionCandidate>, ProcessConformanceError> {
        let request = ProcessRequest::new(ticket.clone());
        let timeout = Duration::from_millis(u64::from(ticket.operation().deadline_ms()));
        let observation = self
            .blocking(timeout, move |backend| backend.observe(request))
            .await
            .map_err(map_error)?;
        Ok(observation.map(|observation| AdoptionCandidate {
            identity: observation.identity(),
            observed: observation.observed().clone(),
            wait_reap_owner: observation.wait_reap_owner(),
        }))
    }

    async fn probe(
        &self,
        ticket: &LaunchTicket,
    ) -> Result<Option<AdoptionCandidate>, ProcessConformanceError> {
        let request = ProcessRequest::new(ticket.clone());
        let timeout = Duration::from_millis(u64::from(ticket.operation().deadline_ms()));
        let observation = self
            .blocking(timeout, move |backend| backend.probe(request))
            .await
            .map_err(map_error)?;
        Ok(observation.map(|observation| AdoptionCandidate {
            identity: observation.identity(),
            observed: observation.observed().clone(),
            wait_reap_owner: observation.wait_reap_owner(),
        }))
    }

    async fn open_pidfd(
        &self,
        candidate: &AdoptionCandidate,
    ) -> Result<PidfdEvidence, ProcessConformanceError> {
        let observation = BackendObservation::new(
            candidate.identity,
            candidate.observed.clone(),
            candidate.wait_reap_owner,
        );
        let handle = self
            .blocking(self.inner.default_timeout, move |backend| {
                backend.open_pidfd(observation)
            })
            .await
            .map_err(map_error)?;
        self.remember(candidate.identity, handle)
            .map_err(map_error)?;
        Ok(PidfdEvidence::held())
    }

    async fn stop(
        &self,
        identity: &ProcessIdentityDigest,
        class: StopClass,
    ) -> Result<(), ProcessConformanceError> {
        let handle = self.handle(identity).map_err(map_error)?;
        let backend_class = match class {
            StopClass::Drain => ProcessStopClass::Drain,
            StopClass::Terminate => ProcessStopClass::Terminate,
        };
        let stop_handle = Arc::clone(&handle);
        if class == StopClass::Terminate {
            let backend = Arc::clone(&self.inner.backend);
            let state = Arc::clone(&self.inner.state);
            let stop_identity = *identity;
            let result = self
                .inner
                .pool
                .submit_with_deadline(self.inner.default_timeout, move |deadline| {
                    let result = backend.stop(stop_handle.as_ref(), backend_class);
                    let late = Instant::now() >= deadline;
                    if matches!(result, Ok(()) | Err(ProcessEffectError::Vanished)) {
                        let mut state = state.lock().map_err(|_| ProcessEffectError::StopFailed)?;
                        if state
                            .handles
                            .get(&stop_identity)
                            .is_some_and(|retained| Arc::ptr_eq(retained, &stop_handle))
                        {
                            state.handles.remove(&stop_identity);
                            state.quarantined_identities.remove(&stop_identity);
                        }
                        return if late {
                            Err(ProcessEffectError::DeadlineExceeded)
                        } else {
                            Ok(())
                        };
                    }
                    if late {
                        state
                            .lock()
                            .map_err(|_| ProcessEffectError::StopFailed)?
                            .quarantined_identities
                            .insert(stop_identity);
                        return Err(ProcessEffectError::FateUnknown);
                    }
                    result
                })
                .await;
            if matches!(result, Err(ProcessEffectError::DeadlineExceeded))
                && self
                    .quarantine_handle(*identity, &handle)
                    .map_err(map_error)?
            {
                return Err(ProcessConformanceError::AdoptionAmbiguous);
            }
            return result.map_err(map_error);
        }
        self.blocking(self.inner.default_timeout, move |backend| {
            backend.stop(stop_handle.as_ref(), backend_class)
        })
        .await
        .map_err(map_error)
    }
}

impl<R: BrokerLaunchResolver> ProviderSupervisor<BrokerProcessBackend<R>> {
    /// Verify that a peer PID still names the exact process represented by a
    /// retained broker pidfd and opaque process identity.
    pub fn matches_peer_process(
        &self,
        identity: &ProcessIdentityDigest,
        peer_pid: i32,
    ) -> Result<bool, ProcessConformanceError> {
        let handle = self.handle(identity).map_err(map_error)?;
        self.inner
            .backend
            .matches_peer_process(handle.as_ref(), peer_pid)
            .map_err(map_error)
    }
}

fn map_error(error: ProcessEffectError) -> ProcessConformanceError {
    match error {
        ProcessEffectError::WaitOwnerMismatch => ProcessConformanceError::WaitOwnerMismatch,
        ProcessEffectError::IdentityChanged | ProcessEffectError::FateUnknown => {
            ProcessConformanceError::AdoptionAmbiguous
        }
        ProcessEffectError::PidfdUnavailable | ProcessEffectError::Vanished => {
            ProcessConformanceError::PidfdUnavailable
        }
        ProcessEffectError::DeadlineExceeded | ProcessEffectError::Busy => {
            ProcessConformanceError::DeadlineExceeded
        }
        ProcessEffectError::UnsupportedProvider
        | ProcessEffectError::ResolutionFailed
        | ProcessEffectError::LaunchFailed
        | ProcessEffectError::ObserveFailed
        | ProcessEffectError::StopFailed => ProcessConformanceError::LaunchFailed,
        _ => ProcessConformanceError::LaunchFailed,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicU8};
    use std::sync::mpsc::{Receiver, Sender, channel};

    use d2b_process::{IdentityBinding, ObservedIdentity, WaitReapOwner};
    use d2b_process_conformance::testing::{block_on, fixtures};

    use super::*;

    struct ControlledBackend {
        started: Mutex<Option<Sender<()>>>,
        release: Mutex<Receiver<()>>,
        live: Arc<AtomicBool>,
        stop_fails: bool,
        next_identity: AtomicU8,
    }

    impl ControlledBackend {
        fn observation(&self) -> BackendObservation {
            let seed = self.next_identity.fetch_add(1, Ordering::Relaxed);
            BackendObservation::new(
                ProcessIdentityDigest::from_bytes([seed; 32]),
                ObservedIdentity::from_verified([IdentityBinding::Cgroup]),
                WaitReapOwner::Local,
            )
        }
    }

    impl ProcessEffectBackend for ControlledBackend {
        type Handle = ();

        fn launch(
            &self,
            _request: ProcessRequest,
        ) -> Result<d2b_process::BackendLaunch<Self::Handle>, ProcessEffectError> {
            self.live.store(true, Ordering::Release);
            if let Some(started) = self.started.lock().unwrap().take() {
                started.send(()).unwrap();
                self.release.lock().unwrap().recv().unwrap();
            }
            Ok(d2b_process::BackendLaunch::new(self.observation(), ()))
        }

        fn observe(
            &self,
            _request: ProcessRequest,
        ) -> Result<Option<BackendObservation>, ProcessEffectError> {
            Ok(None)
        }

        fn open_pidfd(
            &self,
            _observation: BackendObservation,
        ) -> Result<Self::Handle, ProcessEffectError> {
            Ok(())
        }

        fn stop(
            &self,
            _handle: &Self::Handle,
            _class: ProcessStopClass,
        ) -> Result<(), ProcessEffectError> {
            if self.stop_fails {
                return Err(ProcessEffectError::StopFailed);
            }
            self.live.store(false, Ordering::Release);
            Ok(())
        }
    }

    fn controlled_backend(
        stop_fails: bool,
    ) -> (ControlledBackend, Receiver<()>, Sender<()>, Arc<AtomicBool>) {
        let (started_sender, started_receiver) = channel();
        let (release_sender, release_receiver) = channel();
        let live = Arc::new(AtomicBool::new(false));
        (
            ControlledBackend {
                started: Mutex::new(Some(started_sender)),
                release: Mutex::new(release_receiver),
                live: Arc::clone(&live),
                stop_fails,
                next_identity: AtomicU8::new(1),
            },
            started_receiver,
            release_sender,
            live,
        )
    }

    fn wait_until(timeout: Duration, predicate: impl Fn() -> bool) {
        let deadline = Instant::now() + timeout;
        while !predicate() {
            assert!(Instant::now() < deadline, "condition did not become true");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn timed_out_launch_is_quarantined_until_late_cleanup_succeeds() {
        let (backend, started, release, live) = controlled_backend(false);
        let supervisor = ProviderSupervisor::new(backend);
        let worker_supervisor = supervisor.clone();
        let (result_sender, result_receiver) = channel();
        let thread = std::thread::spawn(move || {
            let ticket = fixtures::ticket_builder().build().unwrap();
            let request = ProcessLaunchRequest::empty(ProcessRequest::new(ticket.clone())).unwrap();
            result_sender
                .send(block_on(worker_supervisor.launch_with_timeout(
                    &ticket,
                    request,
                    Duration::from_millis(10),
                )))
                .unwrap();
        });

        started.recv().unwrap();
        assert!(live.load(Ordering::Acquire));
        assert_eq!(
            result_receiver
                .recv_timeout(Duration::from_millis(250))
                .unwrap()
                .unwrap_err(),
            ProcessConformanceError::AdoptionAmbiguous
        );
        thread.join().unwrap();
        {
            let state = supervisor.inner.state.lock().unwrap();
            assert_eq!(state.launches.len(), 1);
            assert_eq!(state.quarantined_processes.len(), 1);
        }
        release.send(()).unwrap();
        wait_until(Duration::from_millis(250), || !live.load(Ordering::Acquire));
        let state = supervisor.inner.state.lock().unwrap();
        assert!(state.launches.is_empty());
        assert!(state.quarantined_processes.is_empty());
        assert!(state.handles.is_empty());
        assert!(state.quarantined_identities.is_empty());
    }

    #[test]
    fn a_late_launch_cleanup_failure_stays_quarantined_and_tracked() {
        let (backend, started, release, live) = controlled_backend(true);
        let supervisor = ProviderSupervisor::new(backend);
        let worker_supervisor = supervisor.clone();
        let (result_sender, result_receiver) = channel();
        let thread = std::thread::spawn(move || {
            let ticket = fixtures::ticket_builder().build().unwrap();
            let request = ProcessLaunchRequest::empty(ProcessRequest::new(ticket.clone())).unwrap();
            result_sender
                .send(block_on(worker_supervisor.launch_with_timeout(
                    &ticket,
                    request,
                    Duration::from_millis(10),
                )))
                .unwrap();
        });

        started.recv().unwrap();
        assert_eq!(
            result_receiver
                .recv_timeout(Duration::from_millis(250))
                .unwrap()
                .unwrap_err(),
            ProcessConformanceError::AdoptionAmbiguous
        );
        thread.join().unwrap();
        assert!(live.load(Ordering::Acquire));
        release.send(()).unwrap();
        wait_until(Duration::from_millis(250), || {
            !supervisor.inner.state.lock().unwrap().handles.is_empty()
        });
        let state = supervisor.inner.state.lock().unwrap();
        assert_eq!(state.launches.len(), 1);
        assert_eq!(state.quarantined_processes.len(), 1);
        assert_eq!(state.handles.len(), 1);
        assert_eq!(state.quarantined_identities.len(), 1);
    }

    struct HungStopBackend {
        stop_started: Mutex<Option<Sender<()>>>,
        launch_delay: Duration,
        live: Arc<AtomicBool>,
    }

    impl ProcessEffectBackend for HungStopBackend {
        type Handle = ();

        fn launch(
            &self,
            _request: ProcessRequest,
        ) -> Result<d2b_process::BackendLaunch<Self::Handle>, ProcessEffectError> {
            if !self.launch_delay.is_zero() {
                std::thread::sleep(self.launch_delay);
            }
            self.live.store(true, Ordering::Release);
            Ok(d2b_process::BackendLaunch::new(
                BackendObservation::new(
                    ProcessIdentityDigest::from_bytes([9; 32]),
                    ObservedIdentity::from_verified([IdentityBinding::Cgroup]),
                    WaitReapOwner::Local,
                ),
                (),
            ))
        }

        fn observe(
            &self,
            _request: ProcessRequest,
        ) -> Result<Option<BackendObservation>, ProcessEffectError> {
            Ok(None)
        }

        fn open_pidfd(
            &self,
            _observation: BackendObservation,
        ) -> Result<Self::Handle, ProcessEffectError> {
            Ok(())
        }

        fn stop(
            &self,
            _handle: &Self::Handle,
            _class: ProcessStopClass,
        ) -> Result<(), ProcessEffectError> {
            if let Some(started) = self.stop_started.lock().unwrap().take() {
                started.send(()).unwrap();
            }
            loop {
                std::thread::park();
            }
        }
    }

    #[test]
    fn hung_late_launch_cleanup_is_bounded_and_quarantined() {
        let (stop_started_sender, stop_started_receiver) = channel();
        let live = Arc::new(AtomicBool::new(false));
        let supervisor = ProviderSupervisor::with_limits(
            HungStopBackend {
                stop_started: Mutex::new(Some(stop_started_sender)),
                launch_delay: Duration::from_millis(20),
                live: Arc::clone(&live),
            },
            1,
            Duration::from_millis(10),
        );
        let ticket = fixtures::ticket_builder().build().unwrap();
        let worker_supervisor = supervisor.clone();
        let (result_sender, result_receiver) = channel();
        std::thread::spawn(move || {
            result_sender
                .send(block_on(worker_supervisor.launch_with_timeout(
                    &ticket,
                    ProcessLaunchRequest::empty(ProcessRequest::new(ticket.clone())).unwrap(),
                    Duration::from_millis(10),
                )))
                .unwrap();
        });

        assert_eq!(
            result_receiver
                .recv_timeout(Duration::from_millis(250))
                .unwrap()
                .unwrap_err(),
            ProcessConformanceError::AdoptionAmbiguous
        );
        stop_started_receiver
            .recv_timeout(Duration::from_millis(250))
            .unwrap();
        assert!(live.load(Ordering::Acquire));
        let state = supervisor.inner.state.lock().unwrap();
        assert_eq!(state.launches.len(), 1);
        assert_eq!(state.quarantined_processes.len(), 1);
        assert_eq!(state.handles.len(), 1);
        assert_eq!(state.quarantined_identities.len(), 1);
    }

    #[test]
    fn hung_terminate_is_bounded_and_quarantined() {
        let (stop_started_sender, stop_started_receiver) = channel();
        let supervisor = ProviderSupervisor::with_limits(
            HungStopBackend {
                stop_started: Mutex::new(Some(stop_started_sender)),
                launch_delay: Duration::ZERO,
                live: Arc::new(AtomicBool::new(false)),
            },
            1,
            Duration::from_millis(10),
        );
        let ticket = fixtures::ticket_builder().build().unwrap();
        let launched = block_on(supervisor.launch(&ticket)).unwrap();
        let worker_supervisor = supervisor.clone();
        let identity = launched.identity;
        let (result_sender, result_receiver) = channel();
        std::thread::spawn(move || {
            result_sender
                .send(block_on(
                    worker_supervisor.stop(&identity, StopClass::Terminate),
                ))
                .unwrap();
        });

        assert_eq!(
            result_receiver
                .recv_timeout(Duration::from_millis(250))
                .unwrap()
                .unwrap_err(),
            ProcessConformanceError::AdoptionAmbiguous
        );
        stop_started_receiver
            .recv_timeout(Duration::from_millis(250))
            .unwrap();
        let state = supervisor.inner.state.lock().unwrap();
        assert!(state.handles.contains_key(&launched.identity));
        assert!(state.quarantined_identities.contains(&launched.identity));
    }

    #[test]
    fn terminal_stops_retire_retained_handles() {
        let (_unused_sender, release_receiver) = channel();
        let supervisor = ProviderSupervisor::new(ControlledBackend {
            started: Mutex::new(None),
            release: Mutex::new(release_receiver),
            live: Arc::new(AtomicBool::new(false)),
            stop_fails: false,
            next_identity: AtomicU8::new(1),
        });
        let ticket = fixtures::ticket_builder().build().unwrap();

        for _ in 0..64 {
            let launched = block_on(supervisor.launch(&ticket)).unwrap();
            block_on(supervisor.stop(&launched.identity, StopClass::Terminate)).unwrap();
            assert!(supervisor.inner.state.lock().unwrap().handles.is_empty());
        }
    }

    #[test]
    fn terminal_finalization_retires_a_naturally_exited_handle() {
        let (_unused_sender, release_receiver) = channel();
        let supervisor = ProviderSupervisor::new(ControlledBackend {
            started: Mutex::new(None),
            release: Mutex::new(release_receiver),
            live: Arc::new(AtomicBool::new(false)),
            stop_fails: false,
            next_identity: AtomicU8::new(1),
        });
        let ticket = fixtures::ticket_builder().build().unwrap();
        let launched = block_on(supervisor.launch(&ticket)).unwrap();
        block_on(supervisor.finalize_identity(&launched.identity)).unwrap();
        assert!(supervisor.inner.state.lock().unwrap().handles.is_empty());
    }

    struct ProbeOnlyBackend {
        observe_calls: Arc<AtomicU8>,
        probe_calls: Arc<AtomicU8>,
    }

    impl ProcessEffectBackend for ProbeOnlyBackend {
        type Handle = ();

        fn launch(
            &self,
            _request: ProcessRequest,
        ) -> Result<d2b_process::BackendLaunch<Self::Handle>, ProcessEffectError> {
            unreachable!("probe-only backend is not used for launch")
        }

        fn observe(
            &self,
            _request: ProcessRequest,
        ) -> Result<Option<BackendObservation>, ProcessEffectError> {
            self.observe_calls.fetch_add(1, Ordering::Relaxed);
            Ok(None)
        }

        fn probe(
            &self,
            _request: ProcessRequest,
        ) -> Result<Option<BackendObservation>, ProcessEffectError> {
            self.probe_calls.fetch_add(1, Ordering::Relaxed);
            Ok(None)
        }

        fn open_pidfd(
            &self,
            _observation: BackendObservation,
        ) -> Result<Self::Handle, ProcessEffectError> {
            unreachable!("probe-only backend is not used for pidfd opens")
        }

        fn stop(
            &self,
            _handle: &Self::Handle,
            _class: ProcessStopClass,
        ) -> Result<(), ProcessEffectError> {
            unreachable!("probe-only backend is not used for stops")
        }
    }

    #[test]
    fn probe_uses_the_non_mutating_backend_seam() {
        let observe_calls = Arc::new(AtomicU8::new(0));
        let probe_calls = Arc::new(AtomicU8::new(0));
        let supervisor = ProviderSupervisor::new(ProbeOnlyBackend {
            observe_calls: Arc::clone(&observe_calls),
            probe_calls: Arc::clone(&probe_calls),
        });
        let ticket = fixtures::ticket_builder().build().unwrap();

        assert_eq!(block_on(supervisor.probe(&ticket)).unwrap(), None);
        assert_eq!(probe_calls.load(Ordering::Relaxed), 1);
        assert_eq!(observe_calls.load(Ordering::Relaxed), 0);
    }
}
