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
use std::future::Future;
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
    ValidationResult, WatchEvent, WatchFailure, WatchHint, MutationIntent,
};
use d2b_core_controller::CoreControllerSource;
use d2b_process::{
    BackendLaunch, BackendObservation, CompiledDigests, ConfigurationDigest, IdentityBinding,
    LaunchTicket, ObservedIdentity, OperationBinding, ProcessEffectBackend, ProcessEffectError,
    ProcessIdentityDigest, ProcessRequest, ProcessStopClass, WaitReapOwner,
};
use d2b_process_conformance::ProcessProvider;
use d2b_provider_supervisor::ProviderSupervisor;
use d2b_provider_system_minijail::MinijailProcessProvider;
use d2b_resource_store::{
    StoreGetRequest, StoreOperationContext, StoreProjection, StoreWatchRequest, StoredResource,
};
use d2b_resource_store_redb::{
    AuthorityOperationState, BackendSignals, MAX_INITIAL_WATCH_CREDITS, RedbResourceStore,
    WatchSignals,
};
use tokio::sync::Notify;

const PROFILES: [usize; 3] = [1, 10, 100];
const HANDLER_P95_LIMIT: Duration = Duration::from_millis(5);
const LAUNCH_P95_LIMIT: Duration = Duration::from_millis(20);
const LAUNCH_EFFECT_WORK: Duration = Duration::from_micros(250);
const WATCH_TIMEOUT: Duration = Duration::from_secs(10);
const SETUP_TIMEOUT: Duration = Duration::from_secs(30);
const SEED_TIMEOUT: Duration = Duration::from_secs(90);
const COMMIT_BATCH: usize = 32;
const SEED_BATCH_MUTATIONS: usize = 8;

#[derive(Debug, Clone)]
struct HandlerRecord {
    resource_ref: ResourceRef,
    resource_uid: ResourceUid,
    started_at: Instant,
}

struct ReactionMetrics {
    effect_acceptances: Mutex<BTreeMap<ResourceUid, Instant>>,
    handlers: Mutex<BTreeMap<ResourceUid, HandlerRecord>>,
    launches: Mutex<Vec<(ResourceUid, Instant)>>,
    startup: Mutex<BTreeSet<ResourceUid>>,
    checkpoints: AtomicUsize,
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
            startup: Mutex::new(BTreeSet::new()),
            checkpoints: AtomicUsize::new(0),
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
            .entry(context.target().uid().clone())
            .or_insert_with(Instant::now);
    }

    fn record_durable_effect_acceptance(&self, uid: &ResourceUid) {
        self.effect_acceptances
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(uid.clone())
            .or_insert_with(Instant::now);
    }

    fn effect_acceptances(&self) -> Vec<(ResourceUid, Instant)> {
        self.effect_acceptances
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .map(|(resource_uid, accepted_at)| (resource_uid.clone(), *accepted_at))
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

    fn record_handler_start(&self, key: &ResourceKey) {
        self.handlers
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .entry(key.uid().clone())
        .and_modify(|record| record.started_at = Instant::now())
        .or_insert_with(|| HandlerRecord {
            resource_ref: key.resource_ref().clone(),
            resource_uid: key.uid().clone(),
            started_at: Instant::now(),
        });
    }

    fn record_startup(&self, key: &ResourceKey) {
        self.startup
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(key.uid().clone());
    }

    fn startup_count(&self) -> usize {
        self.startup
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
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

    fn record_checkpoint(&self) {
        self.checkpoints.fetch_add(1, Ordering::AcqRel);
    }

    fn checkpoint_count(&self) -> usize {
        self.checkpoints.load(Ordering::Acquire)
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

fn launch_ticket(
    resource: &ResourceSnapshot,
    controller_generation: ControllerGeneration,
) -> LaunchTicket {
    LaunchTicket::new(
        resource.key().resource_ref().clone(),
        resource.key().uid().clone(),
        resource.generation(),
        controller_generation,
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
    descriptor_for_generations(
        concurrency,
        ControllerGeneration::new(1).expect("nonzero controller generation"),
        ResourceGeneration::new(1).expect("nonzero Provider generation"),
    )
}

fn descriptor_for_generations(
    concurrency: usize,
    controller_generation: ControllerGeneration,
    provider_generation: ResourceGeneration,
) -> ControllerDescriptor {
    descriptor_for_generations_with_pending(
        concurrency,
        concurrency,
        controller_generation,
        provider_generation,
    )
}

fn descriptor_for_generations_with_pending(
    concurrency: usize,
    max_pending_resources: usize,
    controller_generation: ControllerGeneration,
    provider_generation: ResourceGeneration,
) -> ControllerDescriptor {
    let process = ResourceTypeName::parse("Process").expect("valid ResourceType");
    let identity = ControllerIdentity::new(
        ZoneId::parse("dev").expect("valid Zone"),
        ResourceRef::parse("Process/controller").expect("valid controller ref"),
        controller_generation,
        ResourceRef::parse("Provider/system-minijail").expect("valid Provider ref"),
        provider_generation,
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
            ControllerSelector::new(process.clone(), d2b_controller_toolkit::SelectorField::Spec, None)
                .expect("Process selector is valid"),
        ],
        Vec::new(),
        false,
        Vec::new(),
        vec!["reaction.service.v1".to_owned()],
        vec!["reaction.schema.v1".to_owned()],
        ControllerExecutionPolicy::new(
            concurrency,
            concurrency,
            max_pending_resources,
            1,
            u32::try_from(max_pending_resources).expect("profile fits watch credit"),
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
    metrics: Arc<ReactionMetrics>,
    measure_handler_start: bool,
    effect_id: &'static str,
    status_only: bool,
    seed_batches: Option<Arc<Mutex<Vec<Vec<MutationIntent>>>>>,
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

    fn status_resource(resource: &ResourceSnapshot) -> Result<Vec<u8>, HandlerError> {
        let mut value =
            CanonicalJsonValue::parse(resource.canonical_json()).map_err(|_| HandlerError)?;
        let CanonicalJsonValue::Object(root) = &mut value else {
            return Err(HandlerError);
        };
        let status = Self::status_candidate(resource)?;
        root.insert(
            "status".to_owned(),
            CanonicalJsonValue::parse(&status).map_err(|_| HandlerError)?,
        );
        Ok(value.to_canonical_bytes())
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
        context: &ReconcileContext,
        resource: &ResourceSnapshot,
    ) -> impl std::future::Future<Output = Result<ValidationResult, Self::Error>> + Send {
        if context.reasons().contains(TriggerReason::StartupRelist) {
            self.metrics.record_startup(resource.key());
        }
        if self.measure_handler_start
            && (!context.reasons().contains(TriggerReason::StartupRelist)
                || context
                    .reasons()
                    .contains(TriggerReason::SpecGenerationChanged))
        {
            self.metrics.record_handler_start(resource.key());
        }
        std::future::ready(Ok(ValidationResult::Valid))
    }

    fn plan(
        &self,
        context: &ReconcileContext,
        _resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
    ) -> impl std::future::Future<Output = Result<ReconcilePlan, Self::Error>> + Send {
        if self.status_only {
            return std::future::ready(
                ReconcilePlan::new(Vec::new(), false).map_err(|_| HandlerError),
            );
        }
        if context.reasons().contains(TriggerReason::StartupRelist)
            && !context
                .reasons()
                .contains(TriggerReason::SpecGenerationChanged)
        {
            return std::future::ready(
                ReconcilePlan::new(Vec::new(), false).map_err(|_| HandlerError),
            );
        }
        let effect_id = self.effect_id.to_owned();
        std::future::ready(
            ReconcilePlan::new(vec![effect_id], false).map_err(|_| HandlerError),
        )
    }

    fn reconcile(
        &self,
        _context: &ReconcileContext,
        resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
        _plan: &ReconcilePlan,
    ) -> impl std::future::Future<Output = Result<ReconcileResult, Self::Error>> + Send {
        if self.status_only {
            let mutations = self
                .seed_batches
                .as_ref()
                .and_then(|batches| {
                    batches
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .pop()
                });
            let result = (|| {
                if let Some(mutations) = mutations {
                    ReconcileResult::converged(resource.revision(), resource.generation())
                        .with_mutation_batch(
                            d2b_controller_toolkit::ResourceMutationBatch::new(mutations)
                                .map_err(|_| HandlerError)?,
                        )
                        .map_err(|_| HandlerError)
                } else {
                    Ok(ReconcileResult::converged(
                        resource.revision(),
                        resource.generation(),
                    ))
                }
            })();
            return std::future::ready(result);
        }
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
        let controller_generation = self.descriptor.identity().controller_generation();
        async move {
            context.authorize_effect().map_err(|_| HandlerError)?;
            provider
                .launch(&launch_ticket(
                    resource,
                    controller_generation,
                ))
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

fn reaction_test_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
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
        metrics: Arc::clone(&metrics),
        measure_handler_start: false,
        effect_id: "process-launch",
        status_only: false,
        seed_batches: None,
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
    drop(runner);
    tokio::time::timeout(WATCH_TIMEOUT, watch_ready)
        .await
        .expect("toolkit opened the authenticated production watch");

    for start in (0..profile).step_by(COMMIT_BATCH) {
        let end = (start + COMMIT_BATCH).min(profile);
        let (resources, committed_at) = fixture
            .commit_process_batch(profile, start, end)
            .await
            .expect("commit ready Process resources through production redb backend");
        assert_eq!(resources.len(), end - start);
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
            accepted_at <= launch_by_uid[&handler.resource_uid],
            "worker launch preceded durable ledger acceptance"
        );
    }
    let handler_p95 = percentile(&handler_samples, 95);
    let launch_p95 = percentile(&launch_samples, 95);
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

async fn seed_durable_assignments(
    fixture: &Arc<bus_support::ProductionStore>,
    resources: &[StoredResource],
    descriptor: &ControllerDescriptor,
) {
    let assignments = resources
        .iter()
        .map(|resource| {
            (
                resource.resource_ref.clone(),
                fixture.authoritative_assignment(resource),
            )
        })
        .collect();
    let seed_batches = resources
        .chunks(SEED_BATCH_MUTATIONS)
        .map(|chunk| {
            chunk
                .iter()
                .map(|resource| {
                    let snapshot = ResourceSnapshot::new(
                        ResourceKey::new(
                            resource.zone.clone(),
                            resource.resource_ref.clone(),
                            resource.uid.clone(),
                        ),
                        resource.revision,
                        resource.generation,
                        resource.canonical_json.clone(),
                        false,
                    );
                    MutationIntent::new(
                        resource.resource_ref.clone(),
                        Some(resource.uid.clone()),
                        Some(resource.revision),
                        d2b_controller_toolkit::MutationIntentKind::UpdateStatus,
                        Some(ProcessReconciler::status_resource(&snapshot).unwrap()),
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let seed_batch_count = seed_batches.len();
    let metrics = Arc::new(ReactionMetrics::new());
    let checkpoint_metrics = Arc::clone(&metrics);
    let api = fixture
        .core_registered_api_with_assignments(assignments)
        .with_checkpoint_observer(Arc::new(move |_| {
            checkpoint_metrics.record_checkpoint();
        }));
    let source = CoreControllerSource::new(descriptor.clone(), Arc::new(api));
    let provider = Arc::new(MinijailProcessProvider::new(
        ProviderSupervisor::with_limits(
            RecordingEffectBackend::new(Arc::clone(&metrics)),
            resources.len(),
            Duration::from_secs(1),
        ),
    ));
    let reconciler = Arc::new(ProcessReconciler {
        descriptor: descriptor.clone(),
        provider,
        metrics: Arc::clone(&metrics),
        measure_handler_start: false,
        effect_id: "assignment-seed",
        status_only: true,
        seed_batches: Some(Arc::new(Mutex::new(seed_batches))),
    });
    let runner = Runner::new(
        reconciler,
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
    let runner_task = tokio::spawn(runner.run());
    drop(runner);
    tokio::time::timeout(SEED_TIMEOUT, async {
        loop {
            if metrics.checkpoint_count() >= seed_batch_count {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("assignment seeding reaches every Process worker");
    source.close_watch().unwrap();
    let report = tokio::time::timeout(SEED_TIMEOUT, runner_task)
        .await
        .expect("assignment seeding runner completes")
        .expect("assignment seeding runner joins")
        .expect("assignment seeding runner succeeds");
    assert!(report.dispatched >= seed_batch_count);
    assert!(report.checkpointed >= seed_batch_count);
    for resource in resources {
        match fixture.assignment_fence(&resource.resource_ref).await {
            Ok(Some(fence)) if fence.resource_uid == resource.uid => {}
            Ok(Some(_)) => panic!("assignment seed returned a mismatched UID"),
            Ok(None) => panic!("assignment seed did not persist a fence"),
            Err(error) => panic!("assignment seed fence read failed: {error:?}"),
        }
        tokio::time::timeout(
            SEED_TIMEOUT,
            fixture.wait_for_newer_revision(&resource.resource_ref, resource.revision),
        )
        .await
        .expect("assignment seeding reaches the production store")
        .expect("assignment seeding status remains durable");
    }
}

async fn assert_durable_assignment_mismatches(
    fixture: &Arc<bus_support::ProductionStore>,
    resource: &StoredResource,
) {
    let resolver = fixture.durable_core_assignment_resolver();
    assert!(
        resolver(
            resource.resource_ref.clone(),
            resource.uid.clone(),
            resource.revision,
        )
        .await
        .is_ok()
    );
    let wrong_uid =
        ResourceUid::parse("123e4567-e89b-42d3-a456-999999999999").expect("valid mismatch UID");
    assert!(matches!(
        resolver(
            resource.resource_ref.clone(),
            wrong_uid,
            resource.revision,
        )
        .await,
        Err(SourceError::Integrity)
    ));
    assert!(matches!(
        resolver(
            resource.resource_ref.clone(),
            resource.uid.clone(),
            ZoneRevision::new(resource.revision.get() + 1),
        )
        .await,
        Err(SourceError::Integrity)
    ));
    let current_epoch = fixture.authoritative_assignment(resource).epoch;
    fixture.set_core_authority_epoch(current_epoch + 1);
    assert!(matches!(
        resolver(
            resource.resource_ref.clone(),
            resource.uid.clone(),
            resource.revision,
        )
        .await,
        Err(SourceError::Integrity)
    ));
    fixture.set_core_authority_epoch(current_epoch);
    assert!(matches!(
        resolver(
            ResourceRef::parse("Host/host-system").expect("valid mismatch target"),
            resource.uid.clone(),
            resource.revision,
        )
        .await,
        Err(SourceError::Integrity)
    ));
    assert!(matches!(
        resolver(
            ResourceRef::parse("Process/not-assigned").expect("valid missing target"),
            resource.uid.clone(),
            resource.revision,
        )
        .await,
        Err(SourceError::Integrity)
    ));
}

async fn run_core_profile(profile: usize) {
    let fixture = bus_support::ProductionStore::provision().await;
    let store = fixture.store();
    let descriptor = descriptor_for_generations_with_pending(
        profile.min(16),
        profile,
        ControllerGeneration::new(3).expect("nonzero controller generation"),
        ResourceGeneration::new(1).expect("nonzero Provider generation"),
    );
    let seed_descriptor = descriptor_for_generations_with_pending(
        1,
        profile,
        ControllerGeneration::new(3).expect("nonzero controller generation"),
        ResourceGeneration::new(1).expect("nonzero Provider generation"),
    );
    let mut resources = Vec::with_capacity(profile);
    for start in (0..profile).step_by(COMMIT_BATCH) {
        let end = (start + COMMIT_BATCH).min(profile);
        let (batch, _) = fixture
            .commit_process_batch(profile, start, end)
            .await
            .expect("commit ready Process resources through production ResourceService");
        resources.extend(batch);
    }
    assert_eq!(resources.len(), profile);
    seed_durable_assignments(&fixture, &resources, &seed_descriptor).await;
    let mut current_resources = Vec::with_capacity(resources.len());
    for resource in &resources {
        current_resources.push(
            fixture
                .get_resource(&resource.resource_ref)
                .await
                .expect("read seeded Process resource"),
        );
    }
    if profile == 1 {
        assert_durable_assignment_mismatches(&fixture, &current_resources[0]).await;
    }

    let metrics = Arc::new(ReactionMetrics::new());
    let observer_metrics = Arc::clone(&metrics);
    let checkpoint_metrics = Arc::clone(&metrics);
    let api = fixture
        .core_registered_api()
        .with_assignment_fence_resolver(fixture.durable_core_assignment_resolver())
        .with_effect_acceptance_observer(Arc::new(move |uid| {
            observer_metrics.record_durable_effect_acceptance(uid);
        }))
        .with_checkpoint_observer(Arc::new(move |_| {
            checkpoint_metrics.record_checkpoint();
        }));
    let source = CoreControllerSource::new(descriptor.clone(), Arc::new(api));
    source
        .register(&descriptor)
        .await
        .expect("register the durable Core source before read warmup");
    for resource in &current_resources {
        let key = ResourceKey::new(
            resource.zone.clone(),
            resource.resource_ref.clone(),
            resource.uid.clone(),
        );
        for _ in 0..4 {
            source
                .read_fresh(&key)
                .await
                .expect("read the durable assignment before the measured pass");
        }
    }
    let provider = Arc::new(MinijailProcessProvider::new(
        ProviderSupervisor::with_limits(
            RecordingEffectBackend::new(Arc::clone(&metrics)),
            1,
            Duration::from_secs(1),
        ),
    ));
    let reconciler = Arc::new(ProcessReconciler {
        descriptor: descriptor.clone(),
        provider,
        metrics: Arc::clone(&metrics),
        measure_handler_start: true,
        effect_id: "process-launch",
        status_only: false,
        seed_batches: None,
    });
    let runner = Runner::new(
        reconciler,
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
    let runner_task = tokio::spawn(runner.run());
    drop(runner);
    tokio::time::timeout(SETUP_TIMEOUT, async {
        loop {
            if metrics.startup_count() >= 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("CoreControllerSource opens the production watch");

    let commit_times = Arc::new(Mutex::new(BTreeMap::<ResourceRef, Instant>::new()));
    let mut updated_resources = Vec::with_capacity(profile);
    for (index, resource) in current_resources.iter().enumerate() {
        let operation_id = format!("reaction-trigger-{profile}-{index}");
        let (updated, committed_at) = fixture
            .commit_process_spec_update(std::slice::from_ref(resource), &operation_id)
            .await
            .expect("commit ready Process trigger through production ResourceService");
        assert_eq!(updated.len(), 1);
        let updated = updated
            .into_iter()
            .next()
            .expect("Process trigger response is present");
        commit_times
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(updated.resource_ref.clone(), committed_at);
        let completed = index + 1;
        tokio::time::timeout(WATCH_TIMEOUT, async {
            loop {
                if metrics.handlers().len() >= completed
                    && metrics.launches().len() >= completed
                    && metrics.checkpoint_count() >= completed
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("CoreControllerSource completes every production launch attempt");
        tokio::time::timeout(
            SETUP_TIMEOUT,
            fixture.wait_for_newer_revision(&updated.resource_ref, updated.revision),
        )
        .await
        .expect("measured status reaches the production store")
        .expect("measured status remains durable");
        updated_resources.push(updated);
    }
    source.close_watch().unwrap();
    let report = tokio::time::timeout(WATCH_TIMEOUT, runner_task)
        .await
        .expect("CoreControllerSource runner completes")
        .expect("CoreControllerSource runner task joins")
        .expect("CoreControllerSource runner succeeds");
    assert_eq!(report.dispatched, profile * 2);
    assert!(report.checkpointed >= profile);

    let handlers = metrics.handlers();
    let launches = metrics.launches();
    let effect_acceptances = metrics.effect_acceptances();
    assert_eq!(handlers.len(), profile);
    assert_eq!(
        launches.len(),
        profile,
        "unexpected launch records: {:?}",
        launches
            .iter()
            .map(|(uid, _)| uid.as_str())
            .collect::<Vec<_>>()
    );
    assert_eq!(effect_acceptances.len(), profile);
    let effect_acceptance_count = effect_acceptances.len();
    let launch_by_uid = launches.into_iter().collect::<BTreeMap<_, _>>();
    let acceptance_by_uid = effect_acceptances.into_iter().collect::<BTreeMap<_, _>>();
    let commit_times = commit_times
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
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
    let acceptance_samples = handlers
        .iter()
        .map(|handler| {
            acceptance_by_uid[&handler.resource_uid]
                .saturating_duration_since(commit_times[&handler.resource_ref])
        })
        .collect::<Vec<_>>();
    for handler in &handlers {
        let accepted_at = acceptance_by_uid[&handler.resource_uid];
        assert!(
            accepted_at <= launch_by_uid[&handler.resource_uid],
            "worker launch preceded durable ledger acceptance"
        );
    }
    let handler_p95 = percentile(&handler_samples, 95);
    let launch_p95 = percentile(&launch_samples, 95);
    println!(
        "core measurements profile={profile} handler_raw_us={} handler_p95_us={:.3} acceptance_raw_us={} launch_raw_us={} launch_p95_us={:.3}",
        raw_micros(&handler_samples),
        handler_p95.as_secs_f64() * 1_000_000.0,
        raw_micros(&acceptance_samples),
        raw_micros(&launch_samples),
        launch_p95.as_secs_f64() * 1_000_000.0,
    );
    assert!(
        handler_p95 <= HANDLER_P95_LIMIT,
        "CoreControllerSource commit-to-handler p95 {:?} exceeded 5 ms",
        handler_p95
    );
    assert!(
        launch_p95 <= LAUNCH_P95_LIMIT,
        "CoreControllerSource commit-to-launch p95 {:?} exceeded 20 ms",
        launch_p95
    );
    drop(source);
    let operations = tokio::time::timeout(SETUP_TIMEOUT, async {
        for _ in 0..8 {
            match store.authority_operations().await {
                Ok(operations) => return operations,
                Err(error)
                    if matches!(
                        error.kind(),
                        d2b_resource_store::StoreErrorKind::Timeout
                            | d2b_resource_store::StoreErrorKind::Backpressure
                            | d2b_resource_store::StoreErrorKind::StoreBackpressure
                    ) =>
                {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => panic!("read durable effect ledger: {error:?}"),
            }
        }
        panic!("read durable effect ledger retries exhausted")
    })
    .await
    .expect("durable effect ledger read stays bounded");
    let measured_identities = updated_resources
        .iter()
        .map(|resource| (resource.uid.clone(), resource.generation.get()))
        .collect::<BTreeSet<_>>();
    let measured_operations = operations
        .iter()
        .filter(|operation| {
            serde_json::from_slice::<serde_json::Value>(&operation.payload)
                .ok()
                .is_some_and(|payload| {
                    payload["effectIds"]
                        .as_array()
                        .is_some_and(|ids| ids.iter().any(|id| id.as_str() == Some("process-launch")))
                        && payload["resourceUid"]
                            .as_str()
                            .and_then(|uid| ResourceUid::parse(uid).ok())
                            .zip(payload["generation"].as_u64())
                            .is_some_and(|(uid, generation)| {
                                measured_identities.contains(&(uid, generation))
                            })
                })
        })
        .collect::<Vec<_>>();
    assert_eq!(measured_operations.len(), profile);
    assert!(
        measured_operations
            .iter()
            .all(|operation| operation.state == AuthorityOperationState::EffectConfirmed)
    );
    println!(
        "core reaction profile={profile} handler_raw_us={} handler_p95_us={:.3} launch_raw_us={} launch_p95_us={:.3} dispatched={} checkpointed={} ledger_acceptances={} ledger_confirmed={}",
        raw_micros(&handler_samples),
        handler_p95.as_secs_f64() * 1_000_000.0,
        raw_micros(&launch_samples),
        launch_p95.as_secs_f64() * 1_000_000.0,
        report.dispatched,
        report.checkpointed,
        effect_acceptance_count,
        measured_operations.len(),
    );

    drop(store);
    let fixture = Arc::try_unwrap(fixture)
        .unwrap_or_else(|_| panic!("all CoreControllerSource fixture handles released"));
    fixture
        .shutdown()
        .await
        .expect("shutdown CoreControllerSource production store");
}

fn provider_descriptor(provider: &str, index: usize) -> ControllerDescriptor {
    let resource_type = ResourceTypeName::parse("Provider").expect("valid Provider ResourceType");
    let controller_ref = ResourceRef::parse(&format!("Process/provider-controller-{index}"))
        .expect("valid Provider controller ref");
    let identity = ControllerIdentity::new(
        ZoneId::parse("dev").expect("valid Zone"),
        controller_ref.clone(),
        ControllerGeneration::new(3).expect("nonzero controller generation"),
        ResourceRef::parse(&format!("Provider/{provider}")).expect("valid Provider ref"),
        ResourceGeneration::new(1).expect("nonzero Provider generation"),
        controller_ref,
        ResourceRef::parse("Host/host-system").expect("valid execution target"),
        None,
    )
    .expect("Provider controller identity is valid");
    ControllerDescriptor::new(
        identity,
        vec![
            ResourceRegistration::new(resource_type.clone(), vec![1], 5_000, 1)
                .expect("Provider registration is valid"),
        ],
        vec!["resource-api".to_owned()],
        vec!["system".to_owned()],
        vec![ControllerVerb::ReadSpec],
        vec![
            ControllerSelector::new(
                resource_type,
                d2b_controller_toolkit::SelectorField::Spec,
                None,
            )
            .expect("Provider selector is valid"),
        ],
        Vec::new(),
        false,
        Vec::new(),
        vec!["d2b.resource.v3".to_owned()],
        vec!["resources.d2bus.org/v3".to_owned()],
        ControllerExecutionPolicy::new(
            1,
            1,
            1,
            1,
            1,
            ResyncPolicy::new(None, 5_000).expect("Provider resync policy is valid"),
        )
        .expect("Provider execution policy is valid"),
    )
    .expect("Provider descriptor is valid")
}

async fn run_all_provider_composition() {
    let fixture = bus_support::ProductionStore::provision().await;
    fixture.commit_provider_catalog().await;
    let expected = bus_support::PROVIDER_IDS
        .iter()
        .map(|provider| (*provider).to_owned())
        .collect::<BTreeSet<_>>();
    let mut sources = Vec::with_capacity(expected.len());
    let mut registrations = tokio::task::JoinSet::new();
    for (index, provider) in bus_support::PROVIDER_IDS.iter().enumerate() {
        let fixture = Arc::clone(&fixture);
        let provider = (*provider).to_owned();
        registrations.spawn(async move {
            let descriptor = provider_descriptor(&provider, index);
            let api = fixture.provider_registered_api(&provider, Vec::new());
            let source = CoreControllerSource::new(descriptor.clone(), Arc::new(api));
            retry_provider_setup(|| source.register(&descriptor)).await?;
            let listed = retry_provider_setup(|| source.list_initial(&descriptor)).await?;
            retry_provider_setup(|| source.open_watch(&descriptor, listed.snapshot_revision))
                .await?;
            Ok::<_, SourceError>((provider, source, listed.resources.len()))
        });
    }
    while let Some(result) = registrations.join_next().await {
        let (provider, source, listed) = result.unwrap().unwrap();
        assert_eq!(listed, expected.len());
        sources.push((provider, source));
    }
    assert_eq!(sources.len(), expected.len());

    let cancelled_provider = sources
        .first()
        .map(|(provider, _)| provider.clone())
        .expect("Provider composition is nonempty");
    sources
        .first()
        .expect("Provider composition is nonempty")
        .1
        .close_watch()
        .unwrap();
    fixture.commit_provider_catalog_update().await;

    let mut observed = BTreeSet::new();
    let mut closed = BTreeSet::new();
    let mut deliveries = tokio::task::JoinSet::new();
    for (provider, source) in sources {
        deliveries.spawn(async move {
            let event = tokio::time::timeout(WATCH_TIMEOUT, source.receive_watch())
                .await
                .expect("all Provider watches remain bounded");
            (provider, event)
        });
    }
    while let Some(delivery) = deliveries.join_next().await {
        let (provider, event) = delivery.unwrap();
        match event.expect("Provider watch remains healthy") {
            WatchEvent::Hint(hint) => {
                assert_eq!(
                    hint.key().resource_ref().resource_type().as_str(),
                    "Provider"
                );
                observed.insert(provider);
            }
            WatchEvent::Closed => {
                closed.insert(provider);
            }
        }
    }
    let mut expected_hints = expected.clone();
    expected_hints.remove(&cancelled_provider);
    assert_eq!(observed, expected_hints);
    assert_eq!(closed, BTreeSet::from([cancelled_provider]));
    assert_provider_failure_isolation(&fixture).await;

    let fixture = Arc::try_unwrap(fixture)
        .unwrap_or_else(|_| panic!("all Provider composition fixture handles released"));
    fixture
        .shutdown()
        .await
        .expect("shutdown Provider composition store");
}

async fn assert_provider_failure_isolation(fixture: &Arc<bus_support::ProductionStore>) {
    for failure in ["panic", "cancel", "unavailable", "retry-exhausted"] {
        let mut workers = tokio::task::JoinSet::new();
        for (index, provider) in bus_support::PROVIDER_IDS.iter().enumerate() {
            let fixture = Arc::clone(fixture);
            let provider = (*provider).to_owned();
            workers.spawn(async move {
                let descriptor = provider_descriptor(&provider, index);
                let api = fixture.provider_registered_api(&provider, Vec::new());
                let source = CoreControllerSource::new(descriptor.clone(), Arc::new(api));
                retry_provider_setup(|| source.register(&descriptor)).await?;
                let listed = retry_provider_setup(|| source.list_initial(&descriptor)).await?;
                assert_eq!(listed.resources.len(), bus_support::PROVIDER_IDS.len());
                retry_provider_setup(|| source.open_watch(&descriptor, listed.snapshot_revision))
                    .await?;
                if index == 0 {
                    match failure {
                        "panic" => panic!("isolated Provider failure"),
                        "cancel" => {
                            source.close_watch().unwrap();
                            Err(SourceError::Cancelled)
                        }
                        "unavailable" => Err(SourceError::Unavailable),
                        "retry-exhausted" => {
                            retry_provider_setup(|| async {
                                Err::<(), SourceError>(SourceError::Backpressure)
                            })
                            .await
                        }
                        _ => unreachable!(),
                    }
                } else {
                    source.close_watch().unwrap();
                    Ok(())
                }
            });
        }
        let mut successes = 0;
        let mut failures = 0;
        while let Some(result) = workers.join_next().await {
            match result {
                Ok(Ok(())) => {
                    successes += 1;
                }
                Ok(Err(_)) | Err(_) => failures += 1,
            }
        }

        assert_eq!(successes, bus_support::PROVIDER_IDS.len() - 1);
        assert_eq!(failures, 1);
    }
}

async fn retry_provider_setup<T, F, Fut>(mut operation: F) -> Result<T, SourceError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, SourceError>>,
{
    tokio::time::timeout(Duration::from_secs(5), async {
        for attempt in 0..256 {
            match operation().await {
                Ok(value) => return Ok(value),
                Err(SourceError::Backpressure) if attempt + 1 < 256 => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                Err(error) => return Err(error),
            }
        }
        Err(SourceError::Backpressure)
    })
    .await
    .unwrap_or(Err(SourceError::Timeout))
}

#[test]
fn production_reaction_path() {
    let _guard = reaction_test_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
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

#[test]
fn production_core_source_reaction_path() {
    let _guard = reaction_test_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("create benchmark runtime")
        .block_on(async {
            for profile in PROFILES {
                run_core_profile(profile).await;
            }
        });
}

#[test]
fn production_provider_composition() {
    let _guard = reaction_test_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .expect("create benchmark runtime")
        .block_on(run_all_provider_composition());
}
