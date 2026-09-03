//! Display controller lifecycle and finalizer state.

use crate::{
    FINALIZER, PROVIDER_REF, WaylandSpecError,
    policy::{FilterInput, WaylandPolicy},
    principal::{PrincipalLease, PrincipalPool},
    process::{
        LaunchTicket, ProcessObservation, VolumeState, WorkerAction, WorkerRestartEvidence,
        WorkerState, WorkerSupervisor,
    },
    spec::WaylandSessionSpec,
};
use d2b_contracts_resource::v3::{ResourceRef, ZoneId};
use d2b_provider_toolkit::{AuthenticatedComponentSession, AuthenticatedSessionRouteBinding};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Default shared-Runner repair interval for display resources.
pub const DISPLAY_REPAIR_INTERVAL_SECS: u64 = 30;
/// Maximum shared-Runner repair interval for display resources.
pub const DISPLAY_MAX_REPAIR_INTERVAL_SECS: u64 = 60;

/// The cutover contract for display-wayland resource ownership.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisplayRunnerContract {
    session_resource_type: &'static str,
    policy_resource_type: &'static str,
    finalizer: &'static str,
    repair_interval_secs: u64,
    legacy_scheduler_disabled: bool,
    watched_configuration_is_dependency: bool,
}

impl DisplayRunnerContract {
    /// Return the WaylandSession ResourceType.
    pub const fn session_resource_type(self) -> &'static str {
        self.session_resource_type
    }

    /// Return the WaylandPolicy ResourceType.
    pub const fn policy_resource_type(self) -> &'static str {
        self.policy_resource_type
    }

    /// Return the exact WaylandSession finalizer.
    pub const fn finalizer(self) -> &'static str {
        self.finalizer
    }

    /// Return the bounded repair interval.
    pub const fn repair_interval_secs(self) -> u64 {
        self.repair_interval_secs
    }

    /// Return the maximum permitted repair interval.
    pub const fn max_repair_interval_secs(self) -> u64 {
        DISPLAY_MAX_REPAIR_INTERVAL_SECS
    }

    /// Whether the legacy display scheduler is disabled.
    pub const fn legacy_scheduler_disabled(self) -> bool {
        self.legacy_scheduler_disabled
    }

    /// Whether watched configuration is dependency-only.
    pub const fn watched_configuration_is_dependency(self) -> bool {
        self.watched_configuration_is_dependency
    }
}

/// Return the shared-Runner contract for display-wayland.
pub const fn display_runner_contract() -> DisplayRunnerContract {
    DisplayRunnerContract {
        session_resource_type: "display-wayland.d2bus.org.WaylandSession",
        policy_resource_type: "display-wayland.d2bus.org.WaylandPolicy",
        finalizer: FINALIZER,
        repair_interval_secs: DISPLAY_REPAIR_INTERVAL_SECS,
        legacy_scheduler_disabled: true,
        watched_configuration_is_dependency: true,
    }
}

/// Closed display-session lifecycle phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Dependencies or workers are not Ready.
    Pending,
    /// Both display workers are Ready.
    Ready,
    /// The session is usable only with a dependency warning.
    Degraded,
    /// Bounded retries are exhausted or admission failed.
    Failed,
    /// Finalization is in progress.
    Terminating,
}

/// Session condition projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SessionCondition {
    /// The GPU cross-domain endpoint is available.
    GpuEndpointAvailable,
    /// The user portal can issue a compositor grant.
    UserPortalReady,
    /// The compiled policy is current.
    PolicyApplied,
    /// The explicit cross-domain opt-in is present.
    CrossDomainTrusted,
    /// The host proxy is Ready.
    ProxyReady,
    /// The guest frontend is Ready.
    GuestFrontendReady,
    /// The finalizer is blocked by ambiguous process state.
    FinalizerAmbiguous,
    /// The GPU lacks the optional virgl video capability.
    VirglVideoUnsupported,
    /// All pre-provisioned dynamic principals are occupied.
    NoPrincipalAvailable,
}

/// Typed readiness evidence supplied by Core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyReadiness {
    /// The dependency has not completed its authenticated handshake.
    Pending,
    /// The dependency completed its authenticated handshake.
    Ready,
    /// The dependency failed its bounded startup attempt.
    Failed,
}

/// Typed optional capability evidence supplied by Core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityReadiness {
    /// The optional capability is unavailable.
    Unsupported,
    /// The optional capability is available.
    Supported,
}

/// Dependency observations supplied by Core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyState {
    gpu: DependencyReadiness,
    portal: DependencyReadiness,
    clipboard: DependencyReadiness,
    virgl_video: CapabilityReadiness,
    zone: Option<ZoneId>,
}

impl DependencyState {
    /// Construct all required dependencies as Ready.
    pub const fn ready() -> Self {
        Self {
            gpu: DependencyReadiness::Ready,
            portal: DependencyReadiness::Ready,
            clipboard: DependencyReadiness::Ready,
            virgl_video: CapabilityReadiness::Supported,
            zone: None,
        }
    }

    /// Construct the dependency evidence admitted by the daemon's
    /// authenticated display route.
    ///
    /// The route is the retained projection of a sealed ComponentSession.
    /// This adapter deliberately does not accept caller-supplied readiness
    /// flags; the daemon may only promote the fixed dependency set after the
    /// Provider, Guest subject, generation, and Zone have all been admitted.
    pub fn from_authenticated_route(
        route: &AuthenticatedSessionRouteBinding,
    ) -> Result<Self, WaylandSpecError> {
        if route
            .provider_ref()
            .is_none_or(|provider| provider.to_canonical_string() != PROVIDER_REF)
            || route.service().as_str() != crate::SERVICE_PACKAGE
            || route.subject_ref().resource_type().as_str() != "Guest"
            || route.provider_generation().is_none()
        {
            return Err(WaylandSpecError::InvalidReference);
        }
        Ok(Self::ready().with_zone(route.zone().clone()))
    }

    /// Return the GPU endpoint readiness.
    pub const fn gpu(&self) -> DependencyReadiness {
        self.gpu
    }

    /// Return the user portal readiness.
    pub const fn portal(&self) -> DependencyReadiness {
        self.portal
    }

    /// Return the optional clipboard bridge readiness.
    pub const fn clipboard(&self) -> DependencyReadiness {
        self.clipboard
    }

    /// Return optional virgl video capability evidence.
    pub const fn virgl_video(&self) -> CapabilityReadiness {
        self.virgl_video
    }

    /// Borrow the observed dependency Zone.
    pub const fn zone(&self) -> Option<&ZoneId> {
        self.zone.as_ref()
    }

    /// Bind the Core-observed dependency Zone.
    pub fn with_zone(mut self, zone: ZoneId) -> Self {
        self.zone = Some(zone);
        self
    }

    /// Construct a typed pending observation.
    pub const fn pending() -> Self {
        Self {
            gpu: DependencyReadiness::Pending,
            portal: DependencyReadiness::Pending,
            clipboard: DependencyReadiness::Pending,
            virgl_video: CapabilityReadiness::Unsupported,
            zone: None,
        }
    }
}

impl Default for DependencyState {
    fn default() -> Self {
        Self::pending()
    }
}

/// Bounded status written to the owning resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaylandSessionStatus {
    /// Current lifecycle phase.
    pub phase: Phase,
    /// Closed conditions currently true.
    pub conditions: Vec<SessionCondition>,
    /// Compiled policy digest.
    pub policy_digest: String,
    /// Authenticated Core policy generation.
    pub policy_generation: u64,
    /// Opaque principal account name, when allocated.
    pub principal: Option<String>,
    /// Fixed finalizer identifier.
    pub finalizer: &'static str,
    /// Durable child and policy projection.
    pub resource: WaylandSessionResourceStatus,
}

/// Bounded `WaylandSession.status.resource` projection.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WaylandSessionResourceStatus {
    /// Stable Host proxy Process reference.
    pub proxy_process_ref: Option<ResourceRef>,
    /// Stable Guest frontend Process reference.
    pub guest_frontend_process_ref: Option<ResourceRef>,
    /// Stable cross-domain Wayland Endpoint reference.
    pub wayland_endpoint_ref: Option<ResourceRef>,
    /// Observed Endpoint generation.
    pub wayland_endpoint_generation: Option<u64>,
    /// Compiled policy digest.
    pub policy_digest: String,
}

/// Result of one reconcile pass.
#[derive(Debug, PartialEq, Eq)]
pub struct ReconcileResult {
    /// Projected status.
    pub status: WaylandSessionStatus,
    /// Role-bound LaunchTickets when workers need to be started.
    pub launch_tickets: Vec<LaunchTicket>,
    /// Independent worker actions for the Core-owned supervisor.
    pub worker_actions: Vec<WorkerAction>,
}

/// Core-authenticated evidence that the display endpoint is Ready.
#[derive(PartialEq, Eq)]
pub struct DisplayDependencyProof {
    provider_ref: ResourceRef,
    zone: ZoneId,
    guest_ref: ResourceRef,
    host_ref: ResourceRef,
    user_ref: ResourceRef,
    provider_generation: u64,
    policy_generation: u64,
    reconnect_generation: u64,
    controller_generation: u64,
    teardown_generation: u64,
    session_digest: [u8; 32],
}

impl DisplayDependencyProof {
    /// Borrow the authenticated Provider reference.
    pub const fn provider_ref(&self) -> &ResourceRef {
        &self.provider_ref
    }

    /// Borrow the authenticated Zone.
    pub const fn zone(&self) -> &ZoneId {
        &self.zone
    }

    /// Borrow the authenticated Guest reference.
    pub const fn guest_ref(&self) -> &ResourceRef {
        &self.guest_ref
    }

    /// Borrow the authenticated Host reference.
    pub const fn host_ref(&self) -> &ResourceRef {
        &self.host_ref
    }

    /// Borrow the authenticated User reference.
    pub const fn user_ref(&self) -> &ResourceRef {
        &self.user_ref
    }

    /// Return the Ready Provider generation.
    pub const fn generation(&self) -> u64 {
        self.provider_generation
    }

    /// Return the Core policy-resource generation applied by the workers.
    pub const fn policy_generation(&self) -> u64 {
        self.policy_generation
    }

    /// Return the authenticated Guest reconnect generation.
    pub const fn reconnect_generation(&self) -> u64 {
        self.reconnect_generation
    }

    /// Return the Core controller generation that fenced readiness.
    pub const fn controller_generation(&self) -> u64 {
        self.controller_generation
    }

    /// Return the supervisor teardown generation that fenced readiness.
    pub const fn teardown_generation(&self) -> u64 {
        self.teardown_generation
    }

    /// Return the opaque digest binding all display session identities.
    pub const fn session_digest(&self) -> [u8; 32] {
        self.session_digest
    }
}

impl core::fmt::Debug for DisplayDependencyProof {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DisplayDependencyProof(REDACTED)")
    }
}

/// Authenticated display-controller session routing evidence.
#[derive(Debug, PartialEq, Eq)]
pub struct AuthenticatedDisplaySession {
    guest_ref: ResourceRef,
    host_ref: ResourceRef,
    zone: ZoneId,
    reconnect_generation: u64,
    controller_generation: u64,
}

impl AuthenticatedDisplaySession {
    #[cfg(test)]
    pub(crate) fn from_test(
        guest_ref: ResourceRef,
        host_ref: ResourceRef,
        zone: ZoneId,
        reconnect_generation: u64,
        controller_generation: u64,
    ) -> Self {
        Self {
            guest_ref,
            host_ref,
            zone,
            reconnect_generation,
            controller_generation,
        }
    }

    /// Project the caller identity from an admitted ComponentSession.
    pub fn from_component_session<C>(
        session: &AuthenticatedComponentSession<C>,
    ) -> Result<Self, WaylandSpecError> {
        Self::from_authenticated_route(session.route_binding())
    }

    /// Project display identity from a route that was authenticated and
    /// registered by the daemon's Zone bus.
    pub fn from_authenticated_route(
        route: AuthenticatedSessionRouteBinding,
    ) -> Result<Self, WaylandSpecError> {
        if route
            .provider_ref()
            .is_none_or(|provider| provider.to_canonical_string() != PROVIDER_REF)
            || route.service().as_str() != crate::SERVICE_PACKAGE
            || route.subject_ref().resource_type().as_str() != "Guest"
            || route.provider_generation().is_none()
            || route.reconnect_generation().get() == 0
        {
            return Err(WaylandSpecError::InvalidReference);
        }
        let Some(host_ref) = route.context().execution_ref() else {
            return Err(WaylandSpecError::InvalidReference);
        };
        if host_ref.resource_type().as_str() != "Host" {
            return Err(WaylandSpecError::InvalidReference);
        }
        let Some(controller_generation) = route.controller_generation() else {
            return Err(WaylandSpecError::InvalidReference);
        };
        Ok(Self {
            guest_ref: route.subject_ref().clone(),
            host_ref: host_ref.clone(),
            zone: route.zone().clone(),
            reconnect_generation: route.reconnect_generation().get(),
            controller_generation: controller_generation.get(),
        })
    }

    /// Borrow the authenticated Guest reference.
    pub const fn guest_ref(&self) -> &ResourceRef {
        &self.guest_ref
    }

    /// Borrow the authenticated Host execution reference.
    pub const fn host_ref(&self) -> &ResourceRef {
        &self.host_ref
    }

    /// Borrow the authenticated Zone.
    pub const fn zone(&self) -> &ZoneId {
        &self.zone
    }

    /// Return the authenticated reconnect generation.
    pub const fn reconnect_generation(&self) -> u64 {
        self.reconnect_generation
    }

    /// Return the authenticated Core controller generation.
    pub const fn controller_generation(&self) -> u64 {
        self.controller_generation
    }
}

/// Finalization observations supplied by the Process controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalizationInput {
    stop_requested: StopRequest,
    proxy: WorkerState,
    frontend: WorkerState,
    volume: VolumeState,
    authority: CleanupState,
    principal: CleanupState,
    portal: CleanupState,
    grace: GraceState,
}

impl FinalizationInput {
    /// Construct finalization evidence at the Core/Supervisor boundary.
    #[expect(
        clippy::too_many_arguments,
        reason = "finalization evidence keeps every owned authority explicit"
    )]
    #[allow(dead_code)]
    pub(crate) const fn from_supervisor(
        stop_requested: StopRequest,
        proxy: WorkerState,
        frontend: WorkerState,
        volume: VolumeState,
        authority: CleanupState,
        principal: CleanupState,
        portal: CleanupState,
        grace: GraceState,
    ) -> Self {
        Self {
            stop_requested,
            proxy,
            frontend,
            volume,
            authority,
            principal,
            portal,
            grace,
        }
    }

    #[cfg(test)]
    #[expect(
        clippy::too_many_arguments,
        reason = "the test constructor mirrors the Core finalizer boundary"
    )]
    const fn new(
        stop_requested: StopRequest,
        proxy: WorkerState,
        frontend: WorkerState,
        volume: VolumeState,
        authority: CleanupState,
        principal: CleanupState,
        portal: CleanupState,
        grace: GraceState,
    ) -> Self {
        Self::from_supervisor(
            stop_requested,
            proxy,
            frontend,
            volume,
            authority,
            principal,
            portal,
            grace,
        )
    }
}

/// Whether the owning controller requested graceful stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopRequest {
    /// The worker is still serving.
    Active,
    /// Graceful stop has been requested.
    Requested,
}

/// Cleanup evidence for one Core-owned authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupState {
    /// Cleanup remains outstanding.
    Pending,
    /// Cleanup completion was observed.
    Complete,
}

/// Whether the bounded finalization grace period has elapsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraceState {
    /// The bounded grace period is still active.
    Active,
    /// The bounded grace period elapsed.
    Expired,
}

/// Finalizer action decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalizationDecision {
    /// Whether to issue a graceful Process stop.
    pub stop_proxy: bool,
    /// Whether to issue a graceful Process stop for the Guest frontend.
    pub stop_frontend: bool,
    /// Whether the runtime Volume may now be deleted.
    pub delete_runtime_volume: bool,
    /// Whether the finalizer may be removed.
    pub remove_finalizer: bool,
    /// Projected lifecycle phase.
    pub phase: Phase,
    /// Whether the finalizer must retain ownership due to ambiguity.
    pub ambiguous: bool,
}

/// A Core-resolved WaylandPolicy snapshot.
///
/// Policy filters and the generation are carried together so reconciliation
/// cannot silently compile a default policy after the referenced resource
/// changes.  Construction is private to the Core adapter; callers receive
/// this value only after authenticated resource resolution.
#[derive(Clone, PartialEq, Eq)]
pub struct WaylandPolicySnapshot {
    policy_ref: ResourceRef,
    zone: ZoneId,
    generation: u64,
    defaults: FilterInput,
    zone_policy: FilterInput,
}

impl WaylandPolicySnapshot {
    /// Resolve a policy snapshot for one authenticated Guest session.
    ///
    /// The route binding supplies the Zone and Provider identity; callers may
    /// not substitute a different Zone or service boundary while compiling
    /// the policy.
    pub fn from_authenticated_session<C>(
        session: &AuthenticatedComponentSession<C>,
        policy_ref: ResourceRef,
        generation: u64,
        defaults: FilterInput,
        zone_policy: FilterInput,
    ) -> Result<Self, WaylandSpecError> {
        let route = session.route_binding();
        Self::from_authenticated_route(&route, policy_ref, generation, defaults, zone_policy)
    }

    /// Resolve a policy snapshot from the daemon-retained authenticated route.
    ///
    /// This is the production adapter used after the Zone registrar consumed
    /// the sealed session authority.  The route is authenticated metadata only:
    /// it supplies the Zone, service, subject kind, and Provider generation;
    /// the daemon-supplied policy reference and filters remain explicit Core
    /// evidence and are validated before a snapshot is constructed.
    pub fn from_authenticated_route(
        route: &AuthenticatedSessionRouteBinding,
        policy_ref: ResourceRef,
        generation: u64,
        defaults: FilterInput,
        zone_policy: FilterInput,
    ) -> Result<Self, WaylandSpecError> {
        if route
            .provider_ref()
            .is_none_or(|provider| provider.to_canonical_string() != PROVIDER_REF)
            || route.service().as_str() != crate::SERVICE_PACKAGE
            || route.subject_ref().resource_type().as_str() != "Guest"
            || route.provider_generation().is_none()
            || generation == 0
        {
            return Err(WaylandSpecError::InvalidReference);
        }
        Self::from_core(
            policy_ref,
            route.zone().clone(),
            generation,
            defaults,
            zone_policy,
        )
    }

    /// Construct a snapshot resolved by the Core policy adapter.
    ///
    /// The generation is mandatory and must be non-zero; reconciliation
    /// rejects snapshots whose resource reference or Zone does not match the
    /// authenticated session.
    pub(crate) fn from_core(
        policy_ref: ResourceRef,
        zone: ZoneId,
        generation: u64,
        defaults: FilterInput,
        zone_policy: FilterInput,
    ) -> Result<Self, WaylandSpecError> {
        if generation == 0 {
            return Err(WaylandSpecError::InvalidReference);
        }
        Ok(Self {
            policy_ref,
            zone,
            generation,
            defaults,
            zone_policy,
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    /// Construct a policy snapshot for hermetic model tests.
    pub fn from_test_core(
        policy_ref: ResourceRef,
        zone: ZoneId,
        generation: u64,
        defaults: FilterInput,
        zone_policy: FilterInput,
    ) -> Result<Self, WaylandSpecError> {
        Self::from_core(policy_ref, zone, generation, defaults, zone_policy)
    }

    /// Borrow the referenced policy resource.
    pub const fn policy_ref(&self) -> &ResourceRef {
        &self.policy_ref
    }

    /// Borrow the authenticated policy Zone.
    pub const fn zone(&self) -> &ZoneId {
        &self.zone
    }

    /// Return the monotonic policy generation.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    fn compile(
        &self,
        spec: &WaylandSessionSpec,
    ) -> Result<crate::policy::CompiledWaylandPolicy, WaylandSpecError> {
        if self.policy_ref != *spec.policy_ref() {
            return Err(WaylandSpecError::InvalidReference);
        }
        WaylandPolicy::compile(&self.defaults, &self.zone_policy, spec.filter()).map_err(|error| {
            match error {
                crate::policy::PolicyCompileError::UnknownInterface(_) => {
                    WaylandSpecError::UnknownInterface
                }
                crate::policy::PolicyCompileError::BoundsExceeded => {
                    WaylandSpecError::InvalidReference
                }
            }
        })
    }
}

impl core::fmt::Debug for WaylandPolicySnapshot {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("WaylandPolicySnapshot(REDACTED)")
    }
}

/// Provider-issued principal release receipt.
pub struct PrincipalReleaseReceipt {
    session_key: String,
}

impl core::fmt::Debug for PrincipalReleaseReceipt {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PrincipalReleaseReceipt(REDACTED)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PolicyBinding {
    digest: String,
    generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReadySession {
    policy_generation: u64,
    proxy_generation: u64,
    frontend_generation: u64,
    teardown_generation: u64,
    controller_generation: u64,
}

/// Zone-local display controller.
pub struct DisplayController {
    principal_pool: PrincipalPool,
    principals: BTreeMap<String, PrincipalLease>,
    active_policies: BTreeMap<String, PolicyBinding>,
    ready_sessions: BTreeMap<String, ReadySession>,
    worker_supervisor: WorkerSupervisor,
}

impl DisplayController {
    /// Construct a controller with a bounded dynamic principal pool.
    pub fn new(pool_size: usize) -> Self {
        Self {
            principal_pool: PrincipalPool::new(std::iter::empty::<String>(), pool_size)
                .expect("display principal pool size is validated by the signed descriptor"),
            principals: BTreeMap::new(),
            active_policies: BTreeMap::new(),
            ready_sessions: BTreeMap::new(),
            worker_supervisor: WorkerSupervisor::new(WorkerSupervisor::DEFAULT_MAX_ATTEMPTS)
                .expect("default worker retry bound is non-zero"),
        }
    }

    /// Reconcile only after binding the desired state to an authenticated
    /// Guest ComponentSession.
    #[expect(
        clippy::too_many_arguments,
        reason = "the authenticated controller fence keeps every authority input explicit"
    )]
    pub fn reconcile_authenticated_session<C>(
        &mut self,
        session: &AuthenticatedComponentSession<C>,
        spec: &WaylandSessionSpec,
        dependencies: DependencyState,
        observation: ProcessObservation,
        supervision: WorkerRestartEvidence,
        grants: Option<crate::process::LaunchGrants>,
        policy: &WaylandPolicySnapshot,
    ) -> Result<ReconcileResult, WaylandSpecError> {
        let authenticated = AuthenticatedDisplaySession::from_component_session(session)?;
        if authenticated.guest_ref() != spec.guest_ref()
            || authenticated.host_ref() != spec.host_ref()
            || authenticated.reconnect_generation() != spec.reconnect_generation()
            || authenticated.zone() != policy.zone()
            || dependencies
                .zone()
                .is_some_and(|zone| zone != policy.zone())
        {
            return Err(WaylandSpecError::InvalidReference);
        }
        self.reconcile_with_policy_and_evidence_for_controller(
            spec,
            dependencies,
            observation,
            supervision,
            grants,
            policy,
            authenticated.controller_generation(),
        )
    }

    /// Reconcile using route metadata retained after daemon registration.
    #[expect(
        clippy::too_many_arguments,
        reason = "route, policy, and restart evidence remain explicit at the provider boundary"
    )]
    pub fn reconcile_authenticated_route(
        &mut self,
        route: &AuthenticatedSessionRouteBinding,
        spec: &WaylandSessionSpec,
        dependencies: DependencyState,
        observation: ProcessObservation,
        supervision: WorkerRestartEvidence,
        grants: Option<crate::process::LaunchGrants>,
        policy: &WaylandPolicySnapshot,
    ) -> Result<ReconcileResult, WaylandSpecError> {
        let authenticated = AuthenticatedDisplaySession::from_authenticated_route(route.clone())?;
        if authenticated.guest_ref() != spec.guest_ref()
            || authenticated.host_ref() != spec.host_ref()
            || authenticated.reconnect_generation() != spec.reconnect_generation()
            || authenticated.zone() != policy.zone()
            || dependencies
                .zone()
                .is_some_and(|zone| zone != policy.zone())
        {
            return Err(WaylandSpecError::InvalidReference);
        }
        self.reconcile_with_policy_and_evidence_for_controller(
            spec,
            dependencies,
            observation,
            supervision,
            grants,
            policy,
            authenticated.controller_generation(),
        )
    }

    /// Reconcile using the authenticated Core-resolved WaylandPolicy.
    #[cfg(any(test, feature = "test-support"))]
    pub fn reconcile_with_policy(
        &mut self,
        spec: &WaylandSessionSpec,
        dependencies: DependencyState,
        observation: ProcessObservation,
        grants: Option<crate::process::LaunchGrants>,
        policy: &WaylandPolicySnapshot,
    ) -> Result<ReconcileResult, WaylandSpecError> {
        self.reconcile_with_policy_and_evidence_for_controller(
            spec,
            dependencies,
            observation,
            WorkerRestartEvidence::from_supervisor(0, None, None, 1),
            grants,
            policy,
            0,
        )
    }

    /// Reconcile with Core-observed retry timing and teardown fencing.
    #[cfg(any(test, feature = "test-support"))]
    pub fn reconcile_with_policy_and_evidence(
        &mut self,
        spec: &WaylandSessionSpec,
        dependencies: DependencyState,
        observation: ProcessObservation,
        supervision: WorkerRestartEvidence,
        grants: Option<crate::process::LaunchGrants>,
        policy: &WaylandPolicySnapshot,
    ) -> Result<ReconcileResult, WaylandSpecError> {
        self.reconcile_with_policy_and_evidence_for_controller(
            spec,
            dependencies,
            observation,
            supervision,
            grants,
            policy,
            0,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the controller fence keeps every authenticated input explicit"
    )]
    fn reconcile_with_policy_and_evidence_for_controller(
        &mut self,
        spec: &WaylandSessionSpec,
        dependencies: DependencyState,
        observation: ProcessObservation,
        supervision: WorkerRestartEvidence,
        grants: Option<crate::process::LaunchGrants>,
        policy: &WaylandPolicySnapshot,
        controller_generation: u64,
    ) -> Result<ReconcileResult, WaylandSpecError> {
        if supervision.teardown_generation == 0 {
            return Err(WaylandSpecError::InvalidReference);
        }
        if !spec.cross_domain_trusted() {
            return Err(WaylandSpecError::CrossDomainUntrusted);
        }

        let compiled = policy.compile(spec)?;
        if let Some(zone) = dependencies.zone()
            && zone != policy.zone()
        {
            return Err(WaylandSpecError::InvalidReference);
        }
        let session_key = session_key(spec, controller_generation);
        let session_digest = session_digest(spec, controller_generation);
        let policy_binding = PolicyBinding {
            digest: compiled.digest().to_owned(),
            generation: policy.generation(),
        };
        if let Some(active) = self.active_policies.get(&session_key)
            && policy_binding.generation < active.generation
        {
            return Err(WaylandSpecError::InvalidReference);
        }
        let policy_changed = self
            .active_policies
            .get(&session_key)
            .is_some_and(|active| active != &policy_binding);
        let workers_ready_for_current_fence = observation.workers_ready_for(
            policy.generation(),
            supervision.teardown_generation,
            session_digest,
        );
        let worker_actions = match self.worker_supervisor.plan_with_evidence(
            observation,
            policy_changed || !workers_ready_for_current_fence,
            supervision,
        ) {
            Ok(actions) => actions,
            Err(_) => {
                self.active_policies.remove(&session_key);
                self.ready_sessions.remove(&session_key);
                return Ok(ReconcileResult {
                    status: self.status(
                        Phase::Failed,
                        compiled.digest().to_owned(),
                        policy.generation(),
                        String::new(),
                        Vec::new(),
                    ),
                    launch_tickets: Vec::new(),
                    worker_actions: Vec::new(),
                });
            }
        };
        if spec.virgl_video()
            && !matches!(dependencies.virgl_video(), CapabilityReadiness::Supported)
        {
            self.ready_sessions.remove(&session_key);
            return Ok(ReconcileResult {
                status: self.status(
                    Phase::Degraded,
                    compiled.digest().to_owned(),
                    policy.generation(),
                    String::new(),
                    vec![SessionCondition::VirglVideoUnsupported],
                ),
                launch_tickets: Vec::new(),
                worker_actions: Vec::new(),
            });
        }
        let conditions = [
            (
                matches!(dependencies.gpu(), DependencyReadiness::Ready),
                SessionCondition::GpuEndpointAvailable,
            ),
            (
                matches!(dependencies.portal(), DependencyReadiness::Ready),
                SessionCondition::UserPortalReady,
            ),
            (
                spec.cross_domain_trusted(),
                SessionCondition::CrossDomainTrusted,
            ),
            (
                observation.proxy.is_ready()
                    && observation.policy_generation == policy.generation()
                    && observation.teardown_generation == supervision.teardown_generation,
                SessionCondition::ProxyReady,
            ),
            (
                observation.frontend.is_ready()
                    && observation.policy_generation == policy.generation()
                    && observation.teardown_generation == supervision.teardown_generation,
                SessionCondition::GuestFrontendReady,
            ),
        ];
        if !matches!(dependencies.gpu(), DependencyReadiness::Ready)
            || !matches!(dependencies.portal(), DependencyReadiness::Ready)
        {
            self.ready_sessions.remove(&session_key);
            return Ok(ReconcileResult {
                status: self.status(
                    Phase::Pending,
                    compiled.digest().to_owned(),
                    policy.generation(),
                    String::new(),
                    conditions
                        .iter()
                        .filter_map(|(present, condition)| present.then_some(*condition))
                        .collect::<Vec<_>>(),
                ),
                launch_tickets: Vec::new(),
                worker_actions: worker_actions.clone(),
            });
        }
        let needs_worker_launch = !worker_actions.is_empty();
        if needs_worker_launch && grants.is_none() {
            self.ready_sessions.remove(&session_key);
            return Ok(ReconcileResult {
                status: self.status(
                    Phase::Pending,
                    compiled.digest().to_owned(),
                    policy.generation(),
                    String::new(),
                    conditions
                        .iter()
                        .filter_map(|(present, condition)| present.then_some(*condition))
                        .collect::<Vec<_>>(),
                ),
                launch_tickets: Vec::new(),
                worker_actions: worker_actions.clone(),
            });
        }
        let launch_tickets = if needs_worker_launch {
            let grants = grants.expect("launch grants checked before principal allocation");
            let expected_controller_generation = controller_generation.max(1);
            let Some(tickets) = grants.into_worker_tickets_with_fence_and_controller(
                session_digest,
                spec.reconnect_generation(),
                expected_controller_generation,
                supervision.teardown_generation,
                compiled.digest(),
                policy.generation(),
                spec.identity().label(),
                &worker_actions,
            ) else {
                self.ready_sessions.remove(&session_key);
                return Ok(ReconcileResult {
                    status: self.status(
                        Phase::Pending,
                        compiled.digest().to_owned(),
                        policy.generation(),
                        String::new(),
                        conditions
                            .iter()
                            .filter_map(|(present, condition)| present.then_some(*condition))
                            .collect::<Vec<_>>(),
                    ),
                    launch_tickets: Vec::new(),
                    worker_actions: worker_actions.clone(),
                });
            };
            tickets
        } else {
            Vec::new()
        };
        let principal = if let Some(lease) = self.principals.get(&session_key) {
            lease.principal().to_owned()
        } else {
            let lease = match self.principal_pool.acquire_dynamic() {
                Ok(lease) => lease,
                Err(crate::principal::PrincipalPoolError::NoPrincipalAvailable) => {
                    self.ready_sessions.remove(&session_key);
                    return Ok(ReconcileResult {
                        status: self.status(
                            Phase::Failed,
                            compiled.digest().to_owned(),
                            policy.generation(),
                            String::new(),
                            vec![SessionCondition::NoPrincipalAvailable],
                        ),
                        launch_tickets: Vec::new(),
                        worker_actions: Vec::new(),
                    });
                }
                Err(_) => return Err(WaylandSpecError::InvalidReference),
            };
            let principal = lease.principal().to_owned();
            self.principals.insert(session_key.clone(), lease);
            principal
        };
        if (!needs_worker_launch && workers_ready_for_current_fence) || !launch_tickets.is_empty() {
            self.active_policies
                .insert(session_key.clone(), policy_binding);
        }
        let phase = if !launch_tickets.is_empty() {
            Phase::Pending
        } else if workers_ready_for_current_fence {
            let (Some(proxy_generation), Some(frontend_generation)) = (
                observation.proxy.generation(),
                observation.frontend.generation(),
            ) else {
                self.ready_sessions.remove(&session_key);
                return Ok(ReconcileResult {
                    status: self.status(
                        Phase::Pending,
                        compiled.digest().to_owned(),
                        policy.generation(),
                        principal,
                        Vec::new(),
                    ),
                    launch_tickets,
                    worker_actions,
                });
            };
            self.ready_sessions.insert(
                session_key.clone(),
                ReadySession {
                    policy_generation: policy.generation(),
                    proxy_generation,
                    frontend_generation,
                    teardown_generation: supervision.teardown_generation,
                    controller_generation,
                },
            );
            Phase::Ready
        } else {
            self.ready_sessions.remove(&session_key);
            Phase::Pending
        };
        Ok(ReconcileResult {
            status: self.status(
                phase,
                compiled.digest().to_owned(),
                policy.generation(),
                principal,
                conditions
                    .iter()
                    .filter_map(|(present, condition)| present.then_some(*condition))
                    .chain(
                        (!needs_worker_launch && workers_ready_for_current_fence)
                            .then_some(SessionCondition::PolicyApplied),
                    )
                    .collect(),
            ),
            launch_tickets,
            worker_actions,
        })
    }

    /// Mint typed dependency evidence only after a Ready reconciliation and
    /// an authenticated Guest session binding.
    pub fn dependency_proof<C>(
        &self,
        session: &AuthenticatedComponentSession<C>,
        spec: &WaylandSessionSpec,
        result: &ReconcileResult,
        policy: &WaylandPolicySnapshot,
        observation: ProcessObservation,
    ) -> Result<DisplayDependencyProof, WaylandSpecError> {
        self.dependency_proof_from_route(
            &session.route_binding(),
            spec,
            result,
            policy,
            observation,
        )
    }

    /// Mint dependency evidence from route metadata retained after daemon
    /// registration.
    pub fn dependency_proof_from_route(
        &self,
        route: &AuthenticatedSessionRouteBinding,
        spec: &WaylandSessionSpec,
        result: &ReconcileResult,
        policy: &WaylandPolicySnapshot,
        observation: ProcessObservation,
    ) -> Result<DisplayDependencyProof, WaylandSpecError> {
        let authenticated = AuthenticatedDisplaySession::from_authenticated_route(route.clone())?;
        if authenticated.guest_ref() != spec.guest_ref()
            || authenticated.host_ref() != spec.host_ref()
            || authenticated.reconnect_generation() != spec.reconnect_generation()
            || authenticated.zone() != policy.zone()
        {
            return Err(WaylandSpecError::InvalidReference);
        }
        let controller_generation = authenticated.controller_generation();
        let session_key = session_key(spec, controller_generation);
        let session_digest = session_digest(spec, controller_generation);
        let Some(ready_session) = self.ready_sessions.get(&session_key) else {
            return Err(WaylandSpecError::InvalidReference);
        };
        let Some(active_policy) = self.active_policies.get(&session_key) else {
            return Err(WaylandSpecError::InvalidReference);
        };
        let principal_matches = result
            .status
            .principal
            .as_deref()
            .zip(self.principals.get(&session_key))
            .is_some_and(|(reported, lease)| reported == lease.principal());
        if result.status.phase != Phase::Ready
            || result.status.policy_generation != policy.generation()
            || ready_session.policy_generation != policy.generation()
            || ready_session.proxy_generation
                != observation
                    .proxy
                    .generation()
                    .ok_or(WaylandSpecError::InvalidReference)?
            || ready_session.frontend_generation
                != observation
                    .frontend
                    .generation()
                    .ok_or(WaylandSpecError::InvalidReference)?
            || observation.policy_generation != policy.generation()
            || observation.teardown_generation != ready_session.teardown_generation
            || ready_session.teardown_generation == 0
            || ready_session.controller_generation != controller_generation
            || !observation.proxy.is_ready()
            || !observation.frontend.is_ready()
            || observation.session_digest != session_digest
            || active_policy.generation != policy.generation()
            || active_policy.digest != result.status.policy_digest
            || policy.policy_ref() != spec.policy_ref()
            || !principal_matches
        {
            return Err(WaylandSpecError::InvalidReference);
        }
        Ok(DisplayDependencyProof {
            provider_ref: ResourceRef::parse(PROVIDER_REF)
                .map_err(|_| WaylandSpecError::InvalidReference)?,
            zone: policy.zone().clone(),
            guest_ref: spec.guest_ref().clone(),
            host_ref: spec.host_ref().clone(),
            user_ref: spec.user_ref().clone(),
            provider_generation: route
                .provider_generation()
                .ok_or(WaylandSpecError::InvalidReference)?
                .get(),
            policy_generation: policy.generation(),
            reconnect_generation: spec.reconnect_generation(),
            controller_generation,
            teardown_generation: ready_session.teardown_generation,
            session_digest,
        })
    }

    /// Decide the safe finalizer action for one session.
    pub const fn finalize(input: FinalizationInput) -> FinalizationDecision {
        if matches!(input.grace, GraceState::Expired)
            && !(input.proxy.is_terminal()
                && input.proxy.is_deleted()
                && input.frontend.is_terminal()
                && input.frontend.is_deleted())
        {
            return FinalizationDecision {
                stop_proxy: false,
                stop_frontend: false,
                delete_runtime_volume: false,
                remove_finalizer: false,
                phase: Phase::Degraded,
                ambiguous: true,
            };
        }
        if matches!(input.stop_requested, StopRequest::Active) {
            return FinalizationDecision {
                stop_proxy: true,
                stop_frontend: true,
                delete_runtime_volume: false,
                remove_finalizer: false,
                phase: Phase::Terminating,
                ambiguous: false,
            };
        }
        if !input.proxy.is_terminal()
            || !input.proxy.is_deleted()
            || !input.frontend.is_terminal()
            || !input.frontend.is_deleted()
        {
            return FinalizationDecision {
                stop_proxy: !(input.proxy.is_terminal() && input.proxy.is_deleted()),
                stop_frontend: !(input.frontend.is_terminal() && input.frontend.is_deleted()),
                delete_runtime_volume: false,
                remove_finalizer: false,
                phase: Phase::Terminating,
                ambiguous: false,
            };
        }
        if !input.volume.is_deleted() {
            return FinalizationDecision {
                stop_proxy: false,
                stop_frontend: false,
                delete_runtime_volume: true,
                remove_finalizer: false,
                phase: Phase::Terminating,
                ambiguous: false,
            };
        }
        if !matches!(input.authority, CleanupState::Complete)
            || !matches!(input.principal, CleanupState::Complete)
            || !matches!(input.portal, CleanupState::Complete)
        {
            return FinalizationDecision {
                stop_proxy: false,
                stop_frontend: false,
                delete_runtime_volume: false,
                remove_finalizer: false,
                phase: Phase::Terminating,
                ambiguous: true,
            };
        }
        FinalizationDecision {
            stop_proxy: false,
            stop_frontend: false,
            delete_runtime_volume: false,
            remove_finalizer: true,
            phase: Phase::Terminating,
            ambiguous: false,
        }
    }

    /// Return the fixed finalizer name.
    pub const fn finalizer() -> &'static str {
        FINALIZER
    }

    /// Display never declares a Provider-owned state Volume.
    pub const fn provider_state_set_empty() -> bool {
        true
    }

    /// Release a session's dynamic principal after verified Process cleanup.
    pub fn release_session_principal(
        &mut self,
        receipt: PrincipalReleaseReceipt,
    ) -> Result<(), crate::principal::PrincipalPoolError> {
        let Some(lease) = self.principals.get(&receipt.session_key) else {
            return Err(crate::principal::PrincipalPoolError::UnknownLease);
        };
        if !self.principal_pool.owns(lease) {
            return Err(crate::principal::PrincipalPoolError::UnknownLease);
        }
        let lease = self
            .principals
            .remove(&receipt.session_key)
            .ok_or(crate::principal::PrincipalPoolError::UnknownLease)?;
        self.active_policies.remove(&receipt.session_key);
        self.ready_sessions.remove(&receipt.session_key);
        self.principal_pool.release(lease)
    }

    #[allow(dead_code)]
    pub(crate) fn principal_release_receipt(
        &mut self,
        session_key: &str,
    ) -> Result<PrincipalReleaseReceipt, crate::principal::PrincipalPoolError> {
        if !self.principals.contains_key(session_key) {
            return Err(crate::principal::PrincipalPoolError::UnknownLease);
        }
        Ok(PrincipalReleaseReceipt {
            session_key: session_key.to_owned(),
        })
    }

    fn status(
        &self,
        phase: Phase,
        policy_digest: String,
        policy_generation: u64,
        principal: String,
        conditions: Vec<SessionCondition>,
    ) -> WaylandSessionStatus {
        WaylandSessionStatus {
            phase,
            conditions,
            policy_digest: policy_digest.clone(),
            policy_generation,
            principal: (!principal.is_empty()).then_some(principal),
            finalizer: FINALIZER,
            resource: WaylandSessionResourceStatus {
                policy_digest: policy_digest.clone(),
                ..WaylandSessionResourceStatus::default()
            },
        }
    }
}

impl core::fmt::Debug for DisplayController {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DisplayController")
            .field("principal_count", &self.principals.len())
            .field("available_principals", &self.principal_pool.available())
            .finish()
    }
}

fn session_key(spec: &WaylandSessionSpec, controller_generation: u64) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        spec.guest_ref().to_canonical_string(),
        spec.host_ref().to_canonical_string(),
        spec.user_ref().to_canonical_string(),
        spec.reconnect_generation(),
        controller_generation,
    )
}

pub(crate) fn session_digest(spec: &WaylandSessionSpec, controller_generation: u64) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(spec.guest_ref().to_canonical_string().as_bytes());
    digest.update([0]);
    digest.update(spec.host_ref().to_canonical_string().as_bytes());
    digest.update([0]);
    digest.update(spec.user_ref().to_canonical_string().as_bytes());
    digest.update([0]);
    digest.update(spec.reconnect_generation().to_be_bytes());
    digest.update([0]);
    digest.update(controller_generation.to_be_bytes());
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        policy::FilterInput,
        process::{AttachmentGrantHandle, LaunchGrants, ProcessObservation},
        spec::DisplayIdentity,
    };

    fn session_spec() -> WaylandSessionSpec {
        WaylandSessionSpec::new(
            ResourceRef::parse("Guest/demo").unwrap(),
            ResourceRef::parse("Host/demo").unwrap(),
            ResourceRef::parse("User/alice").unwrap(),
            ResourceRef::parse("display-wayland.d2bus.org.WaylandPolicy/demo").unwrap(),
            DisplayIdentity::new("demo", "#112233", "#223344", "#334455").unwrap(),
            true,
        )
        .unwrap()
    }

    fn ready(spec: &WaylandSessionSpec, policy: &WaylandPolicySnapshot) -> ProcessObservation {
        ProcessObservation::ready_for_session(spec, policy.generation(), 1)
    }

    #[test]
    fn core_policy_snapshot_and_principal_receipt_are_consumed_by_controller() {
        let spec = session_spec();
        let policy = WaylandPolicySnapshot::from_core(
            spec.policy_ref().clone(),
            ZoneId::parse("local").unwrap(),
            7,
            FilterInput::default(),
            FilterInput::default(),
        )
        .unwrap();
        assert_eq!(policy.generation(), 7);

        let mut controller = DisplayController::new(1);
        let result = controller
            .reconcile_with_policy(
                &spec,
                DependencyState::ready(),
                ready(&spec, &policy),
                None,
                &policy,
            )
            .unwrap();
        assert_eq!(result.status.phase, Phase::Ready);

        let receipt = controller
            .principal_release_receipt("Guest/demo|Host/demo|User/alice|1|0")
            .unwrap();
        controller.release_session_principal(receipt).unwrap();
    }

    #[test]
    fn policy_generation_change_requires_a_new_supervisor_launch() {
        let spec = session_spec();
        let first_policy = WaylandPolicySnapshot::from_core(
            spec.policy_ref().clone(),
            ZoneId::parse("local").unwrap(),
            7,
            FilterInput::default(),
            FilterInput::default(),
        )
        .unwrap();
        let second_policy = WaylandPolicySnapshot::from_core(
            spec.policy_ref().clone(),
            ZoneId::parse("local").unwrap(),
            8,
            FilterInput::default(),
            FilterInput::default(),
        )
        .unwrap();
        let mut controller = DisplayController::new(1);
        controller
            .reconcile_with_policy(
                &spec,
                DependencyState::ready(),
                ready(&spec, &first_policy),
                None,
                &first_policy,
            )
            .unwrap();

        let pending = controller
            .reconcile_with_policy(
                &spec,
                DependencyState::ready(),
                ready(&spec, &first_policy),
                None,
                &second_policy,
            )
            .unwrap();
        assert_eq!(pending.status.phase, Phase::Pending);
        assert!(
            !pending
                .status
                .conditions
                .contains(&SessionCondition::PolicyApplied)
        );

        let launched = controller
            .reconcile_with_policy(
                &spec,
                DependencyState::ready(),
                ready(&spec, &first_policy),
                Some(LaunchGrants::from_supervisor_for_session_with_frontend(
                    AttachmentGrantHandle::from_supervisor([9; 32]),
                    AttachmentGrantHandle::from_supervisor([10; 32]),
                    AttachmentGrantHandle::from_supervisor([11; 32]),
                    session_digest(&spec, 0),
                    spec.reconnect_generation(),
                    1,
                )),
                &second_policy,
            )
            .unwrap();
        assert_eq!(launched.launch_tickets.len(), 2);
        assert_eq!(launched.status.phase, Phase::Pending);

        let ready = controller
            .reconcile_with_policy(
                &spec,
                DependencyState::ready(),
                ready(&spec, &second_policy),
                None,
                &second_policy,
            )
            .unwrap();
        assert_eq!(ready.status.phase, Phase::Ready);
        assert!(
            ready
                .status
                .conditions
                .contains(&SessionCondition::PolicyApplied)
        );
    }

    #[test]
    fn finalizer_retains_ownership_for_ambiguous_process_cleanup() {
        let decision = DisplayController::finalize(FinalizationInput::new(
            StopRequest::Requested,
            WorkerState::Starting,
            WorkerState::Starting,
            VolumeState::Present,
            CleanupState::Pending,
            CleanupState::Pending,
            CleanupState::Pending,
            GraceState::Expired,
        ));
        assert_eq!(decision.phase, Phase::Degraded);
        assert!(decision.ambiguous);
        assert!(!decision.remove_finalizer);
    }

    #[test]
    fn finalizer_removes_ownership_only_after_all_cleanup_evidence() {
        let decision = DisplayController::finalize(FinalizationInput::new(
            StopRequest::Requested,
            WorkerState::Terminal { deleted: true },
            WorkerState::Terminal { deleted: true },
            VolumeState::Deleted,
            CleanupState::Complete,
            CleanupState::Complete,
            CleanupState::Complete,
            GraceState::Active,
        ));
        assert_eq!(decision.phase, Phase::Terminating);
        assert!(decision.remove_finalizer);
    }

    #[test]
    fn finalizer_retains_ownership_until_supervisor_authority_is_released() {
        let decision = DisplayController::finalize(FinalizationInput::new(
            StopRequest::Requested,
            WorkerState::Terminal { deleted: true },
            WorkerState::Terminal { deleted: true },
            VolumeState::Deleted,
            CleanupState::Pending,
            CleanupState::Complete,
            CleanupState::Complete,
            GraceState::Active,
        ));
        assert!(decision.ambiguous);
        assert!(!decision.remove_finalizer);
    }

    #[test]
    fn finalizer_tracks_frontend_deletion_independently() {
        let decision = DisplayController::finalize(FinalizationInput::new(
            StopRequest::Requested,
            WorkerState::Terminal { deleted: true },
            WorkerState::Terminal { deleted: false },
            VolumeState::Present,
            CleanupState::Complete,
            CleanupState::Complete,
            CleanupState::Complete,
            GraceState::Active,
        ));
        assert!(decision.stop_frontend);
        assert!(!decision.remove_finalizer);
    }
}
