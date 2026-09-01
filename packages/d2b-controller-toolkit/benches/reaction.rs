//! Full production reaction-path benchmark for the controller toolkit.
//!
//! Each profile provisions the production redb store, opens the Resource-API
//! watch, carries frames through the authenticated bus named-stream harness,
//! admits them to the toolkit [`Runner`], and invokes the real
//! `system-minijail` Process Provider. The effect backend is hermetic and
//! records the Provider effect boundary; store, API, bus, session stream,
//! queue, handler, and status paths are production implementations.
//!
//! The existing `ProductionControllerSource` remains an in-handler regression
//! profile. Its acceptance hook records ordering only; the Core source and
//! durable operation-ledger profile are owned by the production adapter.

#[path = "support/reaction.rs"]
mod bus_support;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use d2b_bus::router::production_rss::ProductionWatchHarness;
use d2b_contracts_resource::v3::execution_policy::{BoundedToken, ExecutionDomain};
use d2b_contracts_resource::v3::{
    CanonicalJsonValue, ConfigurationGeneration, ControllerGeneration, ResourceGeneration,
    ResourceRef, ResourceTypeName, ResourceUid, ZoneId, ZoneRevision,
};
use d2b_controller_toolkit::{
    CommitDecision, CommitOutcome, ControllerDescriptor, ControllerExecutionPolicy,
    ControllerHealth, ControllerIdentity, ControllerSelector, ControllerSource, ControllerVerb,
    DependencySnapshot, DisruptionClass, DrainResult, FinalizeResult, FreshSnapshot, InitialList,
    ObservationResult, OperationContext, PriorityLane, ReconcileContext, ReconcilePlan,
    ReconcileProjection, ReconcileResult, ResourceKey, ResourceReconciler, ResourceRegistration,
    ResourceSnapshot, ResyncPolicy, Runner, RunnerConfig, SourceError, StatusPersistence,
    TriggerReason, TriggerSet, UpdateAssessment, UpdateAssessmentState, UpgradePlan, UpgradeStage,
    ValidationResult, WatchEvent, WatchFailure, WatchHint,
};
use d2b_process::{
    BackendLaunch, BackendObservation, CompiledDigests, ConfigurationDigest, IdentityBinding,
    LaunchTicket, ObservedIdentity, OperationBinding, ProcessEffectBackend, ProcessEffectError,
    ProcessIdentityDigest, ProcessRequest, ProcessStopClass, WaitReapOwner,
};
use d2b_process_conformance::ProcessProvider;
use d2b_provider_supervisor::ProviderSupervisor;
use d2b_provider_system_minijail::MinijailProcessProvider;
use d2b_resource_store::{
    StoreGetRequest, StoreOperationContext, StoreProjection, StoreWatchRequest,
};
use d2b_resource_store_redb::{
    BackendSignals, MAX_INITIAL_WATCH_CREDITS, RedbResourceStore, WatchSignals,
};
use tokio::sync::Notify;

const PROFILES: [usize; 3] = [1, 10, 100];
const HANDLER_P95_LIMIT: Duration = Duration::from_millis(5);
const LAUNCH_P95_LIMIT: Duration = Duration::from_millis(20);
const LAUNCH_EFFECT_WORK: Duration = Duration::from_micros(250);
const WATCH_TIMEOUT: Duration = Duration::from_secs(10);
const COMMIT_BATCH: usize = 4;

#[derive(Debug, Clone)]
struct HandlerRecord {
    resource_ref: ResourceRef,
    resource_uid: ResourceUid,
    started_at: Instant,
}

struct ReactionMetrics {
    effect_acceptances:
        Mutex<BTreeMap<(ResourceUid, ResourceGeneration, ZoneRevision, String), Instant>>,
    handlers: Mutex<BTreeMap<ResourceUid, HandlerRecord>>,
    launches: Mutex<Vec<(ResourceUid, Instant)>>,
    active_launches: AtomicUsize,
    max_active_launches: AtomicUsize,
    next_identity: AtomicUsize,
}

impl ReactionMetrics {
    fn new() -> Self {
        Self {
            effect_acceptances: Mutex::new(BTreeMap::new()),
            handlers: Mutex::new(BTreeMap::new()),
            launches: Mutex::new(Vec::new()),
            active_launches: AtomicUsize::new(0),
            max_active_launches: AtomicUsize::new(0),
            next_identity: AtomicUsize::new(1),
        }
    }

    fn record_effect_acceptance(&self, context: &ReconcileContext) {
        let mut acceptances = self
            .effect_acceptances
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        acceptances
            .entry((
                context.target().uid().clone(),
                context.generation(),
                context.revision(),
                context.operation().operation_id().to_owned(),
            ))
            .or_insert_with(Instant::now);
    }

    fn effect_acceptances(&self) -> Vec<(ResourceUid, Instant)> {
        self.effect_acceptances
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .map(|((resource_uid, _, _, _), accepted_at)| (resource_uid.clone(), *accepted_at))
            .collect()
    }

    fn record_handler_key_at(&self, key: &ResourceKey, started_at: Instant) {
        let mut handlers = self
            .handlers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        handlers.entry(key.uid().clone()).or_insert(HandlerRecord {
            resource_ref: key.resource_ref().clone(),
            resource_uid: key.uid().clone(),
            started_at,
        });
    }

    fn handlers(&self) -> Vec<HandlerRecord> {
        self.handlers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .cloned()
            .collect()
    }

    fn launches(&self) -> Vec<(ResourceUid, Instant)> {
        self.launches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn max_active_launches(&self) -> usize {
        self.max_active_launches.load(Ordering::Acquire)
    }
}

struct RecordingEffectBackend {
    metrics: Arc<ReactionMetrics>,
}

impl RecordingEffectBackend {
    fn new(metrics: Arc<ReactionMetrics>) -> Self {
        Self { metrics }
    }
}

impl ProcessEffectBackend for RecordingEffectBackend {
    type Handle = ();

    fn launch(
        &self,
        request: ProcessRequest,
    ) -> Result<BackendLaunch<Self::Handle>, ProcessEffectError> {
        let ticket = request.ticket();
        let active = self.metrics.active_launches.fetch_add(1, Ordering::AcqRel) + 1;
        self.metrics
            .max_active_launches
            .fetch_max(active, Ordering::AcqRel);
        self.metrics
            .launches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push((ticket.process_uid().clone(), Instant::now()));
        thread::sleep(LAUNCH_EFFECT_WORK);
        self.metrics.active_launches.fetch_sub(1, Ordering::AcqRel);

        let identity_number = self.metrics.next_identity.fetch_add(1, Ordering::Relaxed);
        let mut identity_bytes = [0_u8; 32];
        identity_bytes[..std::mem::size_of::<usize>()]
            .copy_from_slice(&identity_number.to_le_bytes());
        let identity = ProcessIdentityDigest::from_bytes(identity_bytes);
        let observed = ObservedIdentity::from_verified([
            IdentityBinding::Pid,
            IdentityBinding::ProcessStartTime,
            IdentityBinding::Cgroup,
            IdentityBinding::Executable,
            IdentityBinding::Template,
            IdentityBinding::Generation,
        ]);
        Ok(BackendLaunch::new(
            BackendObservation::new(identity, observed, WaitReapOwner::Local),
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
        Ok(())
    }
}

fn operation_context(id: &str) -> StoreOperationContext {
    StoreOperationContext {
        operation_id: id.to_owned(),
        idempotency_key: Some(format!("{id}-key")),
        correlation_id: format!("{id}-correlation"),
        trace_id: None,
        deadline_ms: 30_000,
    }
}

fn watch_request() -> StoreWatchRequest {
    StoreWatchRequest {
        operation: operation_context("reaction-watch"),
        zone: ZoneId::parse("dev").expect("valid Zone"),
        resource_types: vec![ResourceTypeName::parse("Process").expect("valid ResourceType")],
        resource_names: Vec::new(),
        filters: Vec::new(),
        after_revision: ZoneRevision::new(0),
        initial_credits: MAX_INITIAL_WATCH_CREDITS,
        projection: StoreProjection::Full,
    }
}

fn get_request(target: &ResourceRef) -> StoreGetRequest {
    StoreGetRequest {
        operation: operation_context(&format!("reaction-read-{}", target.name().as_str())),
        zone: ZoneId::parse("dev").expect("valid Zone"),
        target: target.clone(),
        expected_uid: None,
        projection: StoreProjection::Full,
    }
}

fn compiled_digests() -> CompiledDigests {
    fn digest(seed: u8) -> ConfigurationDigest {
        ConfigurationDigest::from_bytes([seed; 32])
    }

    CompiledDigests {
        sandbox: digest(1),
        budget: digest(2),
        mounts: digest(3),
        devices: digest(4),
        network: digest(5),
        endpoints: digest(6),
        fd_table: digest(7),
    }
}

fn launch_ticket(resource: &ResourceSnapshot) -> LaunchTicket {
    LaunchTicket::new(
        resource.key().resource_ref().clone(),
        resource.key().uid().clone(),
        resource.generation(),
        ControllerGeneration::new(1).expect("nonzero controller generation"),
        BoundedToken::parse("system-core").expect("valid owner Provider"),
        BoundedToken::parse("reaction").expect("valid component"),
        BoundedToken::parse("reaction").expect("valid template"),
        ResourceRef::parse("Host/host-system").expect("valid Host ref"),
        ExecutionDomain::System,
        None,
        BoundedToken::parse("system-minijail").expect("valid Process Provider"),
        compiled_digests(),
        OperationBinding::new(resource.key().uid().clone(), 30_000)
            .expect("valid launch operation"),
        BTreeSet::from([
            IdentityBinding::Pid,
            IdentityBinding::ProcessStartTime,
            IdentityBinding::Cgroup,
            IdentityBinding::Executable,
            IdentityBinding::Template,
            IdentityBinding::Generation,
        ]),
    )
    .expect("valid Process launch ticket")
}

fn descriptor(concurrency: usize) -> ControllerDescriptor {
    let process = ResourceTypeName::parse("Process").expect("valid ResourceType");
    let identity = ControllerIdentity::new(
        ZoneId::parse("dev").expect("valid Zone"),
        ResourceRef::parse("Process/controller").expect("valid controller ref"),
        ControllerGeneration::new(1).expect("nonzero controller generation"),
        ResourceRef::parse("Provider/system-minijail").expect("valid Provider ref"),
        ResourceGeneration::new(1).expect("nonzero Provider generation"),
        ResourceRef::parse("Process/controller").expect("valid Process ref"),
        ResourceRef::parse("Host/host-system").expect("valid Host ref"),
        None,
    )
    .expect("controller identity is valid");
    ControllerDescriptor::new(
        identity,
        vec![
            ResourceRegistration::new(process.clone(), vec![1], 30_000, 1)
                .expect("Process registration is valid"),
        ],
        vec!["resource-api".to_owned()],
        vec!["host".to_owned()],
        vec![ControllerVerb::ReadSpec, ControllerVerb::WriteStatus],
        vec![
            ControllerSelector::new(process, d2b_controller_toolkit::SelectorField::Spec, None)
                .expect("Process selector is valid"),
        ],
        Vec::new(),
        true,
        Vec::new(),
        vec!["reaction.service.v1".to_owned()],
        vec!["reaction.schema.v1".to_owned()],
        ControllerExecutionPolicy::new(
            concurrency,
            concurrency,
            concurrency,
            1,
            u32::try_from(concurrency).expect("profile fits watch credit"),
            ResyncPolicy::new(Some(10_000), 30_000).expect("resync policy is valid"),
        )
        .expect("execution policy is valid"),
    )
    .expect("controller descriptor is valid")
}

#[derive(Debug)]
struct HandlerError;

impl std::fmt::Display for HandlerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Process handler failed")
    }
}

impl std::error::Error for HandlerError {}

struct ProcessReconciler {
    descriptor: ControllerDescriptor,
    provider: Arc<MinijailProcessProvider<ProviderSupervisor<RecordingEffectBackend>>>,
}

impl ProcessReconciler {
    fn status_candidate(resource: &ResourceSnapshot) -> Result<Vec<u8>, HandlerError> {
        let value =
            CanonicalJsonValue::parse(resource.canonical_json()).map_err(|_| HandlerError)?;
        let CanonicalJsonValue::Object(root) = value else {
            return Err(HandlerError);
        };
        let Some(mut status) = root.get("status").cloned() else {
            return Err(HandlerError);
        };
        let CanonicalJsonValue::Object(status) = &mut status else {
            return Err(HandlerError);
        };
        status.insert(
            "phase".to_owned(),
            CanonicalJsonValue::String("Ready".to_owned()),
        );
        Ok(CanonicalJsonValue::Object(status.clone()).to_canonical_bytes())
    }
}

impl ResourceReconciler for ProcessReconciler {
    type Error = HandlerError;

    fn describe(
        &self,
    ) -> impl std::future::Future<Output = Result<ControllerDescriptor, Self::Error>> + Send {
        std::future::ready(Ok(self.descriptor.clone()))
    }

    fn validate_spec(
        &self,
        _context: &ReconcileContext,
        _resource: &ResourceSnapshot,
    ) -> impl std::future::Future<Output = Result<ValidationResult, Self::Error>> + Send {
        std::future::ready(Ok(ValidationResult::Valid))
    }

    fn plan(
        &self,
        _context: &ReconcileContext,
        _resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
    ) -> impl std::future::Future<Output = Result<ReconcilePlan, Self::Error>> + Send {
        std::future::ready(
            ReconcilePlan::new(vec!["process-launch".to_owned()], false).map_err(|_| HandlerError),
        )
    }

    fn reconcile(
        &self,
        _context: &ReconcileContext,
        resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
        _plan: &ReconcilePlan,
    ) -> impl std::future::Future<Output = Result<ReconcileResult, Self::Error>> + Send {
        std::future::ready(Ok(ReconcileResult::converged(
            resource.revision(),
            resource.generation(),
        )))
    }

    fn execute_effect(
        &self,
        context: &ReconcileContext,
        resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
        _plan: &ReconcilePlan,
    ) -> impl std::future::Future<Output = Result<ReconcileResult, Self::Error>> + Send {
        let provider = Arc::clone(&self.provider);
        async move {
            context.authorize_effect().map_err(|_| HandlerError)?;
            provider
                .launch(&launch_ticket(resource))
                .await
                .map_err(|_| HandlerError)?;
            let candidate = Self::status_candidate(resource)?;
            ReconcileResult::new(
                resource.revision(),
                resource.generation(),
                None,
                Some(candidate),
                d2b_controller_toolkit::ReconcileDisposition::Converged,
                None,
                None,
                StatusPersistence::Pending,
            )
            .map_err(|_| HandlerError)
        }
    }

    fn observe(
        &self,
        _context: &ReconcileContext,
        resource: &ResourceSnapshot,
    ) -> impl std::future::Future<Output = Result<ObservationResult, Self::Error>> + Send {
        std::future::ready(Ok(ObservationResult::new(ReconcileResult::converged(
            resource.revision(),
            resource.generation(),
        ))))
    }

    fn finalize(
        &self,
        _context: &ReconcileContext,
        resource: &ResourceSnapshot,
    ) -> impl std::future::Future<Output = Result<FinalizeResult, Self::Error>> + Send {
        std::future::ready(Ok(FinalizeResult::new(ReconcileResult::converged(
            resource.revision(),
            resource.generation(),
        ))))
    }

    fn health(
        &self,
    ) -> impl std::future::Future<Output = Result<ControllerHealth, Self::Error>> + Send {
        std::future::ready(Ok(ControllerHealth::Healthy))
    }

    fn drain(
        &self,
        _deadline_tick: u64,
    ) -> impl std::future::Future<Output = Result<DrainResult, Self::Error>> + Send {
        std::future::ready(Ok(DrainResult::Drained))
    }

    fn assess_update(
        &self,
        _context: &ReconcileContext,
        _resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
    ) -> impl std::future::Future<Output = Result<UpdateAssessment, Self::Error>> + Send {
        std::future::ready(
            UpdateAssessment::new(UpdateAssessmentState::Current, Vec::new(), true)
                .map_err(|_| HandlerError),
        )
    }

    fn plan_upgrade(
        &self,
        _context: &ReconcileContext,
        resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
    ) -> impl std::future::Future<Output = Result<UpgradePlan, Self::Error>> + Send {
        std::future::ready(
            UpgradePlan::new(
                DisruptionClass::Restart,
                true,
                vec![UpgradeStage::Restart(resource.key().resource_ref().clone())],
            )
            .map_err(|_| HandlerError),
        )
    }

    fn execute_upgrade(
        &self,
        context: &ReconcileContext,
        resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
        _plan: &UpgradePlan,
    ) -> impl std::future::Future<Output = Result<ReconcileResult, Self::Error>> + Send {
        std::future::ready(
            context
                .authorize_effect()
                .map_err(|_| HandlerError)
                .map(|_| ReconcileResult::converged(resource.revision(), resource.generation())),
        )
    }
}

struct ProductionControllerSource {
    fixture: std::sync::Weak<bus_support::ProductionStore>,
    harness: Arc<ProductionWatchHarness>,
    expected_creates: usize,
    metrics: Arc<ReactionMetrics>,
    pending: Mutex<VecDeque<Result<WatchEvent, WatchFailure>>>,
    created: AtomicUsize,
    status_commits: AtomicUsize,
    status_revisions: Mutex<Vec<ZoneRevision>>,
    pending_statuses: Mutex<Vec<PendingStatus>>,
    connection: tokio::sync::Mutex<Option<bus_support::NamedWatchConnection>>,
    watch_ready: Notify,
}

struct PendingStatus {
    target: ResourceRef,
    candidate: Vec<u8>,
    operation_id: String,
}

impl ProductionControllerSource {
    fn new(
        fixture: Arc<bus_support::ProductionStore>,
        harness: Arc<ProductionWatchHarness>,
        expected_creates: usize,
        metrics: Arc<ReactionMetrics>,
    ) -> Arc<Self> {
        Arc::new(Self {
            fixture: Arc::downgrade(&fixture),
            harness,
            expected_creates,
            metrics,
            pending: Mutex::new(VecDeque::new()),
            created: AtomicUsize::new(0),
            status_commits: AtomicUsize::new(0),
            status_revisions: Mutex::new(Vec::new()),
            pending_statuses: Mutex::new(Vec::new()),
            connection: tokio::sync::Mutex::new(None),
            watch_ready: Notify::new(),
        })
    }

    async fn stop(&self) {
        if let Some(connection) = self.connection.lock().await.take() {
            connection.abort().await;
        }
    }

    fn status_count(&self) -> usize {
        self.status_commits.load(Ordering::Acquire)
    }

    fn status_revisions(&self) -> Vec<ZoneRevision> {
        self.status_revisions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn store(&self) -> Result<Arc<RedbResourceStore>, SourceError> {
        Ok(self.fixture()?.store())
    }

    fn fixture(&self) -> Result<Arc<bus_support::ProductionStore>, SourceError> {
        self.fixture.upgrade().ok_or(SourceError::Unavailable)
    }

    async fn persist_status(
        &self,
        target: ResourceRef,
        candidate: Vec<u8>,
        operation_id: String,
    ) -> Result<ZoneRevision, SourceError> {
        let result = loop {
            let fixture = self.fixture()?;
            match fixture
                .commit_status(&target, &candidate, &operation_id)
                .await
            {
                Ok(revision) => break revision,
                Err(error)
                    if matches!(
                        error.kind(),
                        d2b_resource_store::StoreErrorKind::Backpressure
                            | d2b_resource_store::StoreErrorKind::StoreBackpressure
                            | d2b_resource_store::StoreErrorKind::Timeout
                    ) =>
                {
                    tokio::task::yield_now().await;
                }
                Err(_) => return Err(SourceError::Unavailable),
            }
        };
        self.status_commits.fetch_add(1, Ordering::AcqRel);
        self.status_revisions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(result);
        Ok(result)
    }

    async fn flush_statuses(&self) -> Result<(), SourceError> {
        let pending = std::mem::take(
            &mut *self
                .pending_statuses
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        for status in pending {
            self.persist_status(status.target, status.candidate, status.operation_id)
                .await?;
        }
        Ok(())
    }
}

impl ControllerSource for ProductionControllerSource {
    fn register(
        &self,
        _descriptor: &ControllerDescriptor,
    ) -> impl std::future::Future<Output = Result<(), SourceError>> + Send {
        std::future::ready(Ok(()))
    }

    fn list_initial(
        &self,
        _descriptor: &ControllerDescriptor,
    ) -> impl std::future::Future<Output = Result<InitialList, SourceError>> + Send {
        std::future::ready(Ok(InitialList {
            resources: Vec::new(),
            snapshot_revision: ZoneRevision::new(0),
        }))
    }

    async fn open_watch(
        &self,
        _descriptor: &ControllerDescriptor,
        after_revision: ZoneRevision,
    ) -> Result<(), SourceError> {
        let mut connection = self.connection.lock().await;
        if connection.is_none() {
            let request = StoreWatchRequest {
                after_revision,
                ..watch_request()
            };
            *connection = Some(
                bus_support::open_named_watch(self.store()?, &self.harness, request, "reaction")
                    .await,
            );
            self.watch_ready.notify_waiters();
        }
        Ok(())
    }

    async fn receive_watch(&self) -> Result<WatchEvent, WatchFailure> {
        loop {
            if let Some(event) = self
                .pending
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .pop_front()
            {
                return event;
            }
            if self.created.load(Ordering::Acquire) >= self.expected_creates {
                return Ok(WatchEvent::Closed);
            }
            let frame = {
                let connection = self.connection.lock().await;
                let Some(connection) = connection.as_ref() else {
                    return Err(WatchFailure::Fatal);
                };
                connection
                    .receive()
                    .await
                    .map_err(|_| WatchFailure::Disconnected)?
            };
            let frame_received_at = Instant::now();
            let payload: serde_json::Value =
                serde_json::from_slice(frame.payload()).map_err(|_| WatchFailure::Fatal)?;
            let mut events = VecDeque::new();
            for entry in payload["entries"].as_array().ok_or(WatchFailure::Fatal)? {
                if entry["event"].as_str() != Some("created") {
                    continue;
                }
                let resource_type = ResourceTypeName::parse(
                    entry["resource_type"].as_str().ok_or(WatchFailure::Fatal)?,
                )
                .map_err(|_| WatchFailure::Fatal)?;
                let resource_name = d2b_contracts_resource::v3::ResourceName::parse(
                    entry["resource_name"].as_str().ok_or(WatchFailure::Fatal)?,
                )
                .map_err(|_| WatchFailure::Fatal)?;
                let resource_ref = ResourceRef::new(resource_type, resource_name);
                let resource_uid =
                    ResourceUid::parse(entry["resource_uid"].as_str().ok_or(WatchFailure::Fatal)?)
                        .map_err(|_| WatchFailure::Fatal)?;
                let operation_id = entry["operation_id"].as_str().ok_or(WatchFailure::Fatal)?;
                let correlation_id = entry["correlation_id"]
                    .as_str()
                    .ok_or(WatchFailure::Fatal)?;
                let operation = OperationContext::new(
                    operation_id,
                    format!("{operation_id}-key"),
                    correlation_id,
                    None,
                )
                .map_err(|_| WatchFailure::Fatal)?;
                let key = ResourceKey::new(
                    ZoneId::parse("dev").expect("valid Zone"),
                    resource_ref,
                    resource_uid,
                );
                self.metrics.record_handler_key_at(&key, frame_received_at);
                let revision = payload["revision"]
                    .as_u64()
                    .map(ZoneRevision::new)
                    .ok_or(WatchFailure::Fatal)?;
                events.push_back(Ok(WatchEvent::Hint(Box::new(WatchHint::new(
                    key,
                    revision,
                    TriggerSet::new([TriggerReason::SpecGenerationChanged]),
                    PriorityLane::Ordinary,
                    operation,
                )))));
                self.created.fetch_add(1, Ordering::AcqRel);
            }
            self.pending
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .extend(events);
        }
    }

    async fn read_fresh(&self, key: &ResourceKey) -> Result<FreshSnapshot, SourceError> {
        let store = self.store()?;
        let resource = loop {
            match store.get(get_request(key.resource_ref())).await {
                Ok(resource) => break resource,
                Err(error)
                    if matches!(
                        error.kind(),
                        d2b_resource_store::StoreErrorKind::Backpressure
                            | d2b_resource_store::StoreErrorKind::StoreBackpressure
                            | d2b_resource_store::StoreErrorKind::Timeout
                    ) =>
                {
                    tokio::task::yield_now().await;
                }
                Err(_) => return Err(SourceError::Unavailable),
            }
        };
        Ok(FreshSnapshot::Present {
            target: ResourceSnapshot::new(
                key.clone(),
                resource.revision,
                resource.generation,
                resource.canonical_json,
                false,
            ),
            dependencies: Vec::new(),
        })
    }

    async fn write_starting(&self, context: &ReconcileContext) -> Result<(), SourceError> {
        let _ = context;
        Ok(())
    }

    fn accept_effect(
        &self,
        context: &ReconcileContext,
        _plan: &ReconcilePlan,
    ) -> impl std::future::Future<Output = Result<(), SourceError>> + Send {
        self.metrics.record_effect_acceptance(context);
        std::future::ready(Ok(()))
    }

    fn await_expedited_commit(
        &self,
        _context: &ReconcileContext,
    ) -> impl std::future::Future<Output = Result<CommitDecision, SourceError>> + Send {
        std::future::ready(Ok(CommitDecision::Abort))
    }

    async fn commit_result(
        &self,
        context: &ReconcileContext,
        result: &ReconcileResult,
    ) -> Result<CommitOutcome, SourceError> {
        let candidate = result
            .status_candidate()
            .ok_or(SourceError::Integrity)?
            .to_vec();
        let operation_id = format!(
            "reaction-status-{}-{}",
            context.operation().operation_id(),
            context.target().resource_ref().name().as_str()
        );
        self.pending_statuses
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(PendingStatus {
                target: context.target().resource_ref().clone(),
                candidate,
                operation_id,
            });
        Ok(CommitOutcome::CommittedStatusPending(context.revision()))
    }

    fn complete_expedited(
        &self,
        _context: &ReconcileContext,
        _projection: &ReconcileProjection,
        _status_persistence: StatusPersistence,
    ) -> impl std::future::Future<Output = Result<(), SourceError>> + Send {
        std::future::ready(Ok(()))
    }

    fn persist_outcome(
        &self,
        _projection: &ReconcileProjection,
    ) -> impl std::future::Future<Output = Result<(), SourceError>> + Send {
        std::future::ready(Ok(()))
    }

    fn checkpoint(
        &self,
        _context: &ReconcileContext,
        _revision: ZoneRevision,
    ) -> impl std::future::Future<Output = Result<(), SourceError>> + Send {
        std::future::ready(Ok(()))
    }

    fn schedule_requeue(
        &self,
        _key: &ResourceKey,
        _at_tick: u64,
    ) -> impl std::future::Future<Output = Result<(), SourceError>> + Send {
        std::future::ready(Ok(()))
    }
}

fn percentile(samples: &[Duration], percentile: usize) -> Duration {
    assert!(!samples.is_empty(), "latency sample set is nonempty");
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let index = (percentile * sorted.len())
        .div_ceil(100)
        .saturating_sub(1)
        .min(sorted.len() - 1);
    sorted[index]
}

fn raw_micros(samples: &[Duration]) -> String {
    let values = samples
        .iter()
        .map(|sample| format!("{:.3}", sample.as_secs_f64() * 1_000_000.0))
        .collect::<Vec<_>>();
    format!("[{}]", values.join(","))
}

async fn run_profile(profile: usize) {
    let fixture = bus_support::ProductionStore::provision().await;
    let store = fixture.store();
    let harness = Arc::new(
        ProductionWatchHarness::new(bus_support::bus_config())
            .expect("create authenticated production bus harness"),
    );
    let commit_times = Arc::new(Mutex::new(BTreeMap::<ResourceRef, Instant>::new()));
    let metrics = Arc::new(ReactionMetrics::new());
    let source = ProductionControllerSource::new(
        Arc::clone(&fixture),
        Arc::clone(&harness),
        profile,
        Arc::clone(&metrics),
    );
    let provider = Arc::new(MinijailProcessProvider::new(
        ProviderSupervisor::with_limits(
            RecordingEffectBackend::new(Arc::clone(&metrics)),
            profile,
            Duration::from_secs(1),
        ),
    ));
    let reconciler = Arc::new(ProcessReconciler {
        descriptor: descriptor(profile),
        provider,
    });
    let runner = Runner::new(
        Arc::clone(&reconciler),
        Arc::clone(&source),
        RunnerConfig {
            policy_revision: 1,
            api_revision: 1,
            configuration_revision: ConfigurationGeneration::new(1)
                .expect("nonzero configuration generation"),
            deadline_tick: 30_000,
            max_attempts: 1,
        },
    );
    let watch_ready = source.watch_ready.notified();
    let runner_task = tokio::spawn(runner.run());
    tokio::time::timeout(WATCH_TIMEOUT, watch_ready)
        .await
        .expect("toolkit opened the authenticated production watch");

    for start in (0..profile).step_by(COMMIT_BATCH) {
        let end = (start + COMMIT_BATCH).min(profile);
        let resources = fixture
            .commit_process_batch(profile, start, end)
            .await
            .expect("commit ready Process resources through production redb backend");
        assert_eq!(resources.len(), end - start);
        let committed_at = Instant::now();
        {
            let mut commit_times = commit_times
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for resource in resources {
                commit_times.insert(resource.resource_ref, committed_at);
            }
        }
        tokio::task::yield_now().await;
    }

    let report = tokio::time::timeout(WATCH_TIMEOUT, runner_task)
        .await
        .expect("toolkit runner completes")
        .expect("toolkit runner task joins")
        .expect("toolkit runner succeeds");
    assert_eq!(report.dispatched, profile);
    assert_eq!(report.checkpointed, profile);
    assert_eq!(report.committed_status_pending, profile);

    let commit_times = commit_times
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    let handlers = metrics.handlers();
    let launches = metrics.launches();
    let effect_acceptances = metrics.effect_acceptances();
    let effect_acceptance_count = effect_acceptances.len();
    assert_eq!(handlers.len(), profile);
    assert_eq!(launches.len(), profile);
    assert_eq!(effect_acceptance_count, profile);
    let launch_by_uid = launches.into_iter().collect::<BTreeMap<_, _>>();
    let acceptance_by_uid = effect_acceptances.into_iter().collect::<BTreeMap<_, _>>();
    assert_eq!(launch_by_uid.len(), profile);

    let handler_samples = handlers
        .iter()
        .map(|handler| {
            handler
                .started_at
                .saturating_duration_since(commit_times[&handler.resource_ref])
        })
        .collect::<Vec<_>>();
    let launch_samples = handlers
        .iter()
        .map(|handler| {
            launch_by_uid[&handler.resource_uid]
                .saturating_duration_since(commit_times[&handler.resource_ref])
        })
        .collect::<Vec<_>>();
    for handler in &handlers {
        let accepted_at = acceptance_by_uid[&handler.resource_uid];
        assert!(
            accepted_at >= commit_times[&handler.resource_ref],
            "ledger acceptance was recorded before the durable resource commit"
        );
        assert!(
            accepted_at <= launch_by_uid[&handler.resource_uid],
            "worker launch preceded durable ledger acceptance"
        );
    }
    let handler_p95 = percentile(&handler_samples, 95);
    let launch_p95 = percentile(&launch_samples, 95);
    assert!(
        handler_p95 <= HANDLER_P95_LIMIT,
        "commit-to-handler p95 {:?} exceeded the 5 ms contract",
        handler_p95
    );
    assert!(
        launch_p95 <= LAUNCH_P95_LIMIT,
        "commit-to-launch p95 {:?} exceeded the 20 ms contract",
        launch_p95
    );
    if profile > 1 {
        assert!(
            metrics.max_active_launches() >= 2,
            "independent Process launches were serialized"
        );
    }

    source
        .flush_statuses()
        .await
        .expect("persist asynchronous Process status updates");
    assert_eq!(source.status_count(), profile);
    source.stop().await;
    let backend_signals: BackendSignals = store.signals();
    let watch_signals: WatchSignals = store
        .watch_signals()
        .expect("read production watch saturation signals");
    let status_revisions = source.status_revisions();
    assert_eq!(status_revisions.len(), profile);
    assert!(backend_signals.shared_immutable_batches > 0);
    assert!(backend_signals.fanout_references > 0);
    assert_eq!(watch_signals.current_registrations, 0);
    assert_eq!(watch_signals.budget_used, 0);

    println!(
        "reaction profile={profile} handler_raw_us={} handler_p95_us={:.3} launch_raw_us={} launch_p95_us={:.3} max_active={} dispatched={} checkpointed={} effect_acceptances={} status_commits={} shared_batches={} fanout_references={}",
        raw_micros(&handler_samples),
        handler_p95.as_secs_f64() * 1_000_000.0,
        raw_micros(&launch_samples),
        launch_p95.as_secs_f64() * 1_000_000.0,
        metrics.max_active_launches(),
        report.dispatched,
        report.checkpointed,
        effect_acceptance_count,
        status_revisions.len(),
        backend_signals.shared_immutable_batches,
        backend_signals.fanout_references,
    );

    drop(source);
    drop(store);
    let fixture = Arc::try_unwrap(fixture)
        .unwrap_or_else(|_| panic!("all production fixture handles released"));
    fixture
        .shutdown()
        .await
        .expect("shutdown production redb backend");
}

#[test]
fn production_reaction_path() {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .expect("create benchmark runtime")
        .block_on(async {
            for profile in PROFILES {
                run_profile(profile).await;
            }
        });
}
