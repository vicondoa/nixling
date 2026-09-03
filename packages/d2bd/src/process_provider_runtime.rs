//! Daemon-owned composition of the fixed process Providers.
//!
//! The Provider crates remain pure controllers: they receive only the
//! core-owned effect ports. This module is the one production seam that
//! constructs those ports from the authenticated broker transport and the
//! trusted bundle. No Provider receives a broker socket or a bundle resolver.

use std::{
    collections::{BTreeMap, BTreeSet},
    os::fd::{AsFd, OwnedFd},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use d2b_contracts_broker::broker_wire::BrokerCallerRole;
use d2b_contracts_resource::v3::execution_policy::{BoundedToken, ExecutionDomain};
use d2b_contracts_resource::v3::{
    ControllerGeneration, ResourceGeneration, ResourceRef, ResourceUid, SchemaFingerprint, ZoneId,
    ZoneRevision,
    process::ReadinessClass,
    process::{EphemeralProcessSpec, ProcessClass, ProcessSpec},
};
use d2b_core::{
    bundle_resolver::BundleResolver,
    processes::{ProcessNode, ProcessRole},
};
use d2b_core_controller::ResourceKey;
use d2b_process_conformance::{
    AdoptionCandidate, AdoptionOutcome, CompiledDigests, ConfigurationDigest,
    GuestExecutionBinding, IdentityBinding, LaunchTicket, OperationBinding,
    ProcessConformanceError, ProcessIdentityDigest, ProcessLaunchEffectPort, ProcessProvider,
    ProcessStatusReport, ReadinessExpectation, SandboxCompiler, StopClass, execution_commitment,
    runtime_scope_commitment,
};
use d2b_provider_supervisor::{
    BrokerProcessBackend, BrokerSystemdEffectOwner, BundleBackedLaunchResolver, ProviderSupervisor,
    SystemdProcessBackend,
};
use d2b_provider_system_minijail::{MinijailProcessProvider, launch::PlatformGate};
use d2b_provider_system_systemd::SystemdProcessProvider;
use d2b_provider_toolkit::CredentialDeliveryKeyHandoff;
use d2b_session::AuthenticatedSessionRouteBinding;
use d2b_session_unix::{PeerCredentials, prearmed_seqpacket_pair};
use d2bd_runtime::target_runtime::{ControllerProcessResource, DaemonMode};
use d2bd_runtime::vm_start_support::{
    is_durable_wayland_process_node, is_guest_owned_process_node,
};
use sha2::{Digest, Sha256};

use crate::provider_effects::FixedEffectAdapter;

/// The fixed process Provider names wired by the daemon.
pub const FIXED_PROCESS_PROVIDER_NAMES: [&str; 2] = ["system-minijail", "system-systemd"];
pub(crate) const GUEST_EXECUTION_UNAVAILABLE: &str = "provider-ticket:guest-execution-unavailable";

type BrokerProcessSupervisor = ProviderSupervisor<BrokerProcessBackend<BundleBackedLaunchResolver>>;
type BrokerSystemdSupervisor = ProviderSupervisor<SystemdProcessBackend<BrokerSystemdEffectOwner>>;
const RESOURCE_WAITER_POLL: Duration = Duration::from_millis(250);

/// Probe the host posture needed by the daemon-owned minijail Provider.
///
/// The Provider receives this bounded snapshot through its constructor; it
/// never reads host paths or cgroup state itself.
pub(crate) fn detect_minijail_platform_gate() -> PlatformGate {
    let (kernel_major, kernel_minor) = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .and_then(|release| {
            let mut components = release.split('.');
            let major = components.next()?.parse().ok()?;
            let minor = components
                .next()
                .and_then(|component| {
                    component
                        .split(|character: char| !character.is_ascii_digit())
                        .next()
                })
                .filter(|component| !component.is_empty())?
                .parse()
                .ok()?;
            Some((major, minor))
        })
        .unwrap_or((0, 0));
    let cgroup_kill_available = std::fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|cgroup| {
            let relative = cgroup
                .lines()
                .find_map(|line| line.strip_prefix("0::"))?
                .trim()
                .trim_start_matches('/')
                .to_owned();
            let path = std::path::Path::new("/sys/fs/cgroup")
                .join(relative)
                .join("cgroup.kill");
            Some(path)
        })
        .is_some_and(|path| path.is_file());
    PlatformGate::from_observed(kernel_major, kernel_minor, cgroup_kill_available)
}

fn retryable_stop_error(error: &str) -> bool {
    matches!(
        error,
        "stop-failed"
            | "observe-failed"
            | "launch-failed"
            | "effect-adapter-busy"
            | "deadline-exceeded"
            | "process-fate-unknown"
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagedProvider {
    Minijail,
    Systemd,
}

enum Waiter {
    Minijail(BrokerProcessSupervisor),
    Systemd(BrokerSystemdSupervisor),
}

impl Waiter {
    async fn wait(
        self,
        identity: ProcessIdentityDigest,
    ) -> Result<(), ProcessConformanceError> {
        loop {
            let done = match &self {
                Self::Minijail(supervisor) => {
                    supervisor.wait_identity(&identity, RESOURCE_WAITER_POLL).await?
                }
                Self::Systemd(supervisor) => {
                    supervisor.wait_identity(&identity, RESOURCE_WAITER_POLL).await?
                }
            };
            if done {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ManagedProcess {
    provider: ManagedProvider,
    identity: ProcessIdentityDigest,
}

#[derive(Clone)]
struct ManagedResource {
    zone: ZoneId,
    zone_uid: Option<ResourceUid>,
    resource_ref: ResourceRef,
    provider: ManagedProvider,
    provider_ref: ResourceRef,
    provider_uid: Option<ResourceUid>,
    provider_generation: Option<ResourceGeneration>,
    owner_ref: Option<ResourceRef>,
    owner_uid: Option<ResourceUid>,
    template: BoundedToken,
    identity: ProcessIdentityDigest,
    uid: ResourceUid,
    generation: ResourceGeneration,
    controller_generation: ControllerGeneration,
    execution_ref: ResourceRef,
    target_ref: Option<ResourceRef>,
    runtime_scope: Option<ConfigurationDigest>,
}

impl core::fmt::Debug for ManagedResource {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ManagedResource(<redacted>)")
    }
}

type ManagedResourceKey = (ZoneId, Option<ResourceUid>, ResourceRef);
type ResourceWaiterKey = (ManagedResourceKey, ProcessIdentityDigest);

fn resource_identity_matches(
    managed: &ManagedResource,
    context: &ProcessResourceContext<'_>,
) -> bool {
    resource_identity_mismatches(managed, context).is_empty()
}

fn resource_identity_mismatches(
    managed: &ManagedResource,
    context: &ProcessResourceContext<'_>,
) -> Vec<String> {
    let mut mismatches = Vec::new();
    let mut compare = |field: &str, managed: String, requested: String| {
        if managed != requested {
            mismatches.push(format!("{field}(managed={managed},requested={requested})"));
        }
    };
    compare(
        "zone",
        managed.zone.to_canonical_string(),
        context.zone.to_canonical_string(),
    );
    compare(
        "zone_uid",
        managed
            .zone_uid
            .as_ref()
            .map(ResourceUid::to_canonical_string)
            .unwrap_or_else(|| "none".to_owned()),
        context
            .zone_uid
            .as_ref()
            .map(ResourceUid::to_canonical_string)
            .unwrap_or_else(|| "none".to_owned()),
    );
    compare(
        "resource_ref",
        managed.resource_ref.to_canonical_string(),
        context.resource_ref.to_canonical_string(),
    );
    compare(
        "provider_ref",
        managed.provider_ref.to_canonical_string(),
        context.provider_ref.to_canonical_string(),
    );
    compare(
        "provider_uid",
        managed
            .provider_uid
            .as_ref()
            .map(ResourceUid::to_canonical_string)
            .unwrap_or_else(|| "none".to_owned()),
        context
            .provider_uid
            .as_ref()
            .map(ResourceUid::to_canonical_string)
            .unwrap_or_else(|| "none".to_owned()),
    );
    compare(
        "provider_generation",
        managed
            .provider_generation
            .map(|generation| generation.get().to_string())
            .unwrap_or_else(|| "none".to_owned()),
        context
            .provider_generation
            .map(|generation| generation.get().to_string())
            .unwrap_or_else(|| "none".to_owned()),
    );
    compare(
        "owner_ref",
        managed
            .owner_ref
            .as_ref()
            .map(ResourceRef::to_canonical_string)
            .unwrap_or_else(|| "none".to_owned()),
        context
            .owner_ref
            .as_ref()
            .map(ResourceRef::to_canonical_string)
            .unwrap_or_else(|| "none".to_owned()),
    );
    compare(
        "owner_uid",
        managed
            .owner_uid
            .as_ref()
            .map(ResourceUid::to_canonical_string)
            .unwrap_or_else(|| "none".to_owned()),
        context
            .owner_uid
            .as_ref()
            .map(ResourceUid::to_canonical_string)
            .unwrap_or_else(|| "none".to_owned()),
    );
    compare(
        "resource_uid",
        managed.uid.to_canonical_string(),
        context.resource_uid.to_canonical_string(),
    );
    compare(
        "resource_generation",
        managed.generation.get().to_string(),
        context.resource_generation.get().to_string(),
    );
    compare(
        "controller_generation",
        managed.controller_generation.get().to_string(),
        context.controller_generation.get().to_string(),
    );
    compare(
        "target_ref",
        managed
            .target_ref
            .as_ref()
            .map(ResourceRef::to_canonical_string)
            .unwrap_or_else(|| "none".to_owned()),
        context
            .target_ref
            .as_ref()
            .map(ResourceRef::to_canonical_string)
            .unwrap_or_else(|| "none".to_owned()),
    );
    mismatches
}

fn identity_changed_error(mismatches: Vec<String>) -> String {
    tracing::warn!(
        mismatches = %mismatches.join(","),
        "Process provider identity mismatch",
    );
    format!("provider-process-identity-changed:{}", mismatches.join(","))
}

#[derive(Debug, Clone)]
pub(crate) struct ProcessResourceContext<'a> {
    pub(crate) zone: ZoneId,
    pub(crate) resource_ref: &'a ResourceRef,
    pub(crate) resource_uid: &'a ResourceUid,
    pub(crate) resource_generation: ResourceGeneration,
    pub(crate) resource_revision: ZoneRevision,
    pub(crate) provider_ref: &'a ResourceRef,
    pub(crate) provider_uid: Option<ResourceUid>,
    pub(crate) provider_generation: Option<ResourceGeneration>,
    pub(crate) controller_generation: ControllerGeneration,
    pub(crate) guest_execution: Option<GuestExecutionBinding>,
    pub(crate) zone_uid: Option<ResourceUid>,
    pub(crate) policy_revision: Option<u64>,
    pub(crate) provider_assignment_generation: Option<ResourceGeneration>,
    /// Semantic owner used to bind static Provider controller templates.
    pub(crate) owner_ref: Option<ResourceRef>,
    /// Immutable identity of the semantic owner.
    pub(crate) owner_uid: Option<ResourceUid>,
    /// Provider that owns the supervised controller route.
    pub(crate) controller_provider_ref: Option<ResourceRef>,
    /// Optional Guest selector for a shared Host execution reference.
    pub(crate) target_ref: Option<ResourceRef>,
    /// Exact execution reference from the Process spec.
    pub(crate) execution_ref: Option<ResourceRef>,
    /// Exact User scope from the Process execution spec.
    pub(crate) user_ref: Option<ResourceRef>,
    /// Catalog-bound private Guest setup descriptor digest.
    pub(crate) guest_descriptor_digest: Option<SchemaFingerprint>,
}

impl<'a> ProcessResourceContext<'a> {
    pub(crate) const fn new(
        zone: ZoneId,
        resource_ref: &'a ResourceRef,
        resource_uid: &'a ResourceUid,
        resource_generation: ResourceGeneration,
        resource_revision: ZoneRevision,
        provider_ref: &'a ResourceRef,
        controller_generation: ControllerGeneration,
        target_ref: Option<ResourceRef>,
    ) -> Self {
        Self {
            zone,
            resource_ref,
            resource_uid,
            resource_generation,
            resource_revision,
            provider_ref,
            provider_uid: None,
            provider_generation: None,
            controller_generation,
            guest_execution: None,
            zone_uid: None,
            policy_revision: None,
            provider_assignment_generation: None,
            owner_ref: None,
            owner_uid: None,
            controller_provider_ref: None,
            target_ref,
            execution_ref: None,
            user_ref: None,
            guest_descriptor_digest: None,
        }
    }

    pub(crate) fn with_guest_execution(mut self, binding: Option<&GuestExecutionBinding>) -> Self {
        self.guest_execution = binding.cloned();
        self
    }

    pub(crate) fn with_lifecycle_identity(
        mut self,
        zone_uid: Option<ResourceUid>,
        policy_revision: Option<u64>,
        provider_assignment_generation: Option<ResourceGeneration>,
    ) -> Self {
        self.zone_uid = zone_uid;
        self.policy_revision = policy_revision;
        self.provider_assignment_generation = provider_assignment_generation;
        self
    }

    pub(crate) fn with_owner_ref(mut self, owner_ref: Option<ResourceRef>) -> Self {
        self.owner_ref = owner_ref;
        self
    }

    pub(crate) fn with_owner_uid(mut self, owner_uid: Option<ResourceUid>) -> Self {
        self.owner_uid = owner_uid;
        self
    }

    pub(crate) fn with_controller_provider_ref(
        mut self,
        provider_ref: Option<ResourceRef>,
    ) -> Self {
        self.controller_provider_ref = provider_ref;
        self
    }

    pub(crate) fn with_provider_identity(
        mut self,
        provider_uid: Option<&ResourceUid>,
        provider_generation: Option<ResourceGeneration>,
    ) -> Self {
        self.provider_uid = provider_uid.cloned();
        self.provider_generation = provider_generation;
        self
    }

    pub(crate) fn with_guest_descriptor_digest(
        mut self,
        descriptor_digest: Option<&SchemaFingerprint>,
    ) -> Self {
        self.guest_descriptor_digest = descriptor_digest.cloned();
        self
    }

    pub(crate) fn with_execution_ref(mut self, execution_ref: &ResourceRef) -> Self {
        self.execution_ref = Some(execution_ref.clone());
        self
    }

    pub(crate) fn with_user_ref(mut self, user_ref: Option<&ResourceRef>) -> Self {
        self.user_ref = user_ref.cloned();
        self
    }
}

/// Result of a Provider-backed launch, carrying only opaque process identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderLaunch {
    /// Opaque identity established by the effect adapter.
    pub identity: ProcessIdentityDigest,
}

/// Result of a Provider-backed adoption attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderAdoption {
    /// No process matching the trusted ticket is running.
    Absent,
    /// The exact process was adopted.
    Adopted(ProcessStatusReport),
    /// A static Provider controller was found without its exact bootstrap
    /// endpoint retained by this daemon.
    ControllerBootstrapMissing,
    /// A uniquely identified stale process is available for exact replacement.
    Stale {
        /// Opaque effect-owner evidence for the exact stale process.
        candidate: AdoptionCandidate,
    },
    /// A candidate was present but identity was ambiguous and quarantined.
    Quarantined(ProcessStatusReport),
}

const MAX_CONTROLLER_BOOTSTRAP_ENDPOINTS: usize = 256;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ControllerBootstrapContext {
    zone: ZoneId,
    zone_uid: Option<ResourceUid>,
    process_ref: ResourceRef,
    process_uid: ResourceUid,
    generation: ResourceGeneration,
    process_identity: ProcessIdentityDigest,
    process_provider_ref: ResourceRef,
    provider_owner_ref: ResourceRef,
    provider_uid: ResourceUid,
    provider_generation: ResourceGeneration,
    execution_ref: ResourceRef,
    user_ref: Option<ResourceRef>,
    controller_generation: ControllerGeneration,
}

impl std::fmt::Debug for ControllerBootstrapContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ControllerBootstrapContext(<redacted>)")
    }
}

impl ControllerBootstrapContext {
    fn from_resource_context(
        context: &ProcessResourceContext<'_>,
        execution_ref: &ResourceRef,
        process_identity: ProcessIdentityDigest,
    ) -> Result<Self, String> {
        let provider_owner_ref = context
            .controller_provider_ref
            .clone()
            .or_else(|| {
                context
                    .owner_ref
                    .as_ref()
                    .filter(|owner| owner.resource_type().as_str() == "Provider")
                    .cloned()
            })
            .filter(|owner| owner.resource_type().as_str() == "Provider")
            .ok_or_else(|| "provider-controller-owner-missing".to_owned())?;
        let provider_uid = context
            .provider_uid
            .clone()
            .ok_or_else(|| "provider-controller-provider-identity-missing".to_owned())?;
        let provider_generation = context
            .provider_generation
            .ok_or_else(|| "provider-controller-provider-identity-missing".to_owned())?;
        if context
            .user_ref
            .as_ref()
            .is_some_and(|user| user.resource_type().as_str() != "User")
        {
            return Err("provider-controller-user-identity-invalid".to_owned());
        }
        Ok(Self {
            zone: context.zone.clone(),
            zone_uid: context.zone_uid.clone(),
            process_ref: context.resource_ref.clone(),
            process_uid: context.resource_uid.clone(),
            generation: context.resource_generation,
            process_identity,
            process_provider_ref: context.provider_ref.clone(),
            provider_owner_ref,
            provider_uid,
            provider_generation,
            execution_ref: execution_ref.clone(),
            user_ref: context.user_ref.clone(),
            controller_generation: context.controller_generation,
        })
    }

    pub(crate) fn process_ref(&self) -> &ResourceRef {
        &self.process_ref
    }

    pub(crate) fn zone(&self) -> &ZoneId {
        &self.zone
    }

    pub(crate) fn process_uid(&self) -> &ResourceUid {
        &self.process_uid
    }

    pub(crate) const fn generation(&self) -> ResourceGeneration {
        self.generation
    }

    pub(crate) const fn process_identity(&self) -> ProcessIdentityDigest {
        self.process_identity
    }

    pub(crate) fn process_provider_ref(&self) -> &ResourceRef {
        &self.process_provider_ref
    }

    pub(crate) fn provider_owner_ref(&self) -> &ResourceRef {
        &self.provider_owner_ref
    }

    pub(crate) fn provider_uid(&self) -> &ResourceUid {
        &self.provider_uid
    }

    pub(crate) const fn provider_generation(&self) -> ResourceGeneration {
        self.provider_generation
    }

    pub(crate) fn execution_ref(&self) -> &ResourceRef {
        &self.execution_ref
    }

    pub(crate) fn user_ref(&self) -> Option<&ResourceRef> {
        self.user_ref.as_ref()
    }

    pub(crate) const fn controller_generation(&self) -> ControllerGeneration {
        self.controller_generation
    }
}

/// Lifetime handle returned by the Guest-local Credential backend supervisor.
pub(crate) trait GuestCredentialBackendLease: Send + Sync {
    /// Bind the responder to the exact authenticated Provider route.
    fn bind_route(
        &self,
        route: &AuthenticatedSessionRouteBinding,
        user_ref: Option<&ResourceRef>,
        peer: Option<PeerCredentials>,
    ) -> Result<(), String>;

    /// Stop the responder and revoke its session-bound backend authority.
    fn cancel(&self);
}

/// One backend endpoint prepared by the Guest-local supervisor.
pub(crate) struct GuestCredentialBackendPreparation {
    pub(crate) child_endpoint: OwnedFd,
    pub(crate) delivery_key_handoff: CredentialDeliveryKeyHandoff,
    pub(crate) lease: Arc<dyn GuestCredentialBackendLease>,
}

/// Guest-local owner of Credential backend responders.
pub(crate) trait GuestCredentialBackendSupervisor: Send + Sync {
    fn prepare(
        &self,
        context: &ProcessResourceContext<'_>,
    ) -> Result<GuestCredentialBackendPreparation, String>;
}

pub(crate) struct ControllerBootstrapEndpoint {
    daemon_endpoint: OwnedFd,
    delivery_key_handoff: Option<CredentialDeliveryKeyHandoff>,
    backend_lease: Option<Arc<dyn GuestCredentialBackendLease>>,
    context: ControllerBootstrapContext,
}

impl ControllerBootstrapEndpoint {
    pub(crate) fn into_parts(
        self,
    ) -> (
        OwnedFd,
        Option<CredentialDeliveryKeyHandoff>,
        Option<Arc<dyn GuestCredentialBackendLease>>,
        ControllerBootstrapContext,
    ) {
        (
            self.daemon_endpoint,
            self.delivery_key_handoff,
            self.backend_lease,
            self.context,
        )
    }

    pub(crate) fn context(&self) -> &ControllerBootstrapContext {
        &self.context
    }
}

enum ControllerBootstrapMarker {
    Pending(ControllerBootstrapEndpoint),
    Establishing(ControllerBootstrapContext),
    Active(ControllerBootstrapContext),
}

impl ControllerBootstrapMarker {
    fn context(&self) -> &ControllerBootstrapContext {
        match self {
            Self::Pending(endpoint) => &endpoint.context,
            Self::Establishing(context) | Self::Active(context) => context,
        }
    }
}

/// Provider-backed liveness result used by the daemon readiness loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderLiveness {
    /// The exact process is still present.
    Alive,
    /// The exact process is absent.
    Exited,
    /// Identity could not be established safely.
    Unknown,
}

/// Readiness-loop adapter for one Provider-managed process node.
pub struct ProviderLivenessProbe {
    providers: Arc<ProductionProcessProviders>,
    vm: String,
    node: ProcessNode,
}

impl ProviderLivenessProbe {
    /// Bind a Provider composition to one immutable process-DAG node.
    pub fn new(
        providers: Arc<ProductionProcessProviders>,
        vm: impl Into<String>,
        node: &ProcessNode,
    ) -> Self {
        Self {
            providers,
            vm: vm.into(),
            node: node.clone(),
        }
    }
}

impl d2bd_runtime::supervisor::readiness_liveness::LivenessProbe for ProviderLivenessProbe {
    fn probe(&self) -> d2bd_runtime::supervisor::readiness_liveness::RunnerLiveness {
        match crate::block_on_future(self.providers.probe_node(&self.vm, &self.node)) {
            Ok(ProviderLiveness::Alive) => {
                d2bd_runtime::supervisor::readiness_liveness::RunnerLiveness::Alive
            }
            Ok(ProviderLiveness::Exited) => {
                d2bd_runtime::supervisor::readiness_liveness::RunnerLiveness::Exited(None)
            }
            Ok(ProviderLiveness::Unknown) | Err(_) => {
                d2bd_runtime::supervisor::readiness_liveness::RunnerLiveness::Unknown
            }
        }
    }
}

/// Production process Provider controllers.
///
/// The concrete supervisors are retained by the daemon for its whole
/// lifetime. Their internal handles and broker effect owners never cross the
/// Provider boundary; Provider code sees only the
/// `ProcessLaunchEffectPort` implemented by `ProviderSupervisor`.
pub struct ProductionProcessProviders {
    minijail: MinijailProcessProvider<BrokerProcessSupervisor>,
    systemd: SystemdProcessProvider<BrokerSystemdSupervisor>,
    bundle: BundleResolver,
    mode: DaemonMode,
    fixed_effect: FixedEffectAdapter,
    guest_backend_supervisor: Option<Arc<dyn GuestCredentialBackendSupervisor>>,
    managed: Mutex<BTreeMap<(String, String), ManagedProcess>>,
    managed_resources: Mutex<BTreeMap<ManagedResourceKey, ManagedResource>>,
    resource_waiters: Arc<Mutex<BTreeSet<ResourceWaiterKey>>>,
    controller_bootstrap: Mutex<BTreeMap<(ZoneId, ResourceRef), ControllerBootstrapMarker>>,
}

impl std::fmt::Debug for ProductionProcessProviders {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductionProcessProviders")
            .field("providers", &FIXED_PROCESS_PROVIDER_NAMES)
            .finish()
    }
}

impl ProductionProcessProviders {
    /// Construct both fixed process Providers over the authenticated broker.
    pub fn new(
        bundle: BundleResolver,
        broker_socket: impl Into<PathBuf>,
        caller_role: BrokerCallerRole,
    ) -> Self {
        Self::new_for_mode(bundle, broker_socket, caller_role, DaemonMode::Host)
    }

    /// Construct both fixed process Providers over a mode-bound broker.
    ///
    /// The mode is selected once at construction. It is passed to both
    /// concrete broker adapters and cannot be widened by a Process ticket.
    pub fn new_for_mode(
        bundle: BundleResolver,
        broker_socket: impl Into<PathBuf>,
        caller_role: BrokerCallerRole,
        mode: DaemonMode,
    ) -> Self {
        let broker_socket = broker_socket.into();
        let fixed_socket = broker_socket.clone();
        let daemon_uid = caller_uid(&caller_role);
        let resolver = BundleBackedLaunchResolver::new(bundle.clone()).with_observation_socket(
            broker_socket.clone(),
            Duration::from_secs(10),
            caller_role.clone(),
        );
        let minijail_backend = BrokerProcessBackend::with_socket_profile_and_role(
            resolver.clone(),
            broker_socket.clone(),
            Duration::from_secs(10),
            mode.broker_profile(),
            caller_role.clone(),
        );
        let systemd_owner = BrokerSystemdEffectOwner::with_socket_profile_and_role(
            resolver,
            broker_socket,
            Duration::from_secs(10),
            mode.broker_profile(),
            caller_role,
        );
        let fixed_effect = FixedEffectAdapter::for_mode(mode, fixed_socket, daemon_uid);
        let platform_gate = detect_minijail_platform_gate();
        Self {
            minijail: MinijailProcessProvider::with_platform_gate(
                ProviderSupervisor::new(minijail_backend),
                platform_gate,
            ),
            systemd: SystemdProcessProvider::new(ProviderSupervisor::new(
                SystemdProcessBackend::new(systemd_owner),
            )),
            bundle,
            mode,
            fixed_effect,
            guest_backend_supervisor: None,
            managed: Mutex::new(BTreeMap::new()),
            managed_resources: Mutex::new(BTreeMap::new()),
            resource_waiters: Arc::new(Mutex::new(BTreeSet::new())),
            controller_bootstrap: Mutex::new(BTreeMap::new()),
        }
    }

    /// Bind the Guest-local Credential backend responder supervisor.
    pub(crate) fn with_guest_backend_supervisor(
        mut self,
        supervisor: Arc<dyn GuestCredentialBackendSupervisor>,
    ) -> Self {
        self.guest_backend_supervisor = Some(supervisor);
        self
    }

    /// Return the fixed daemon mode bound to these Process Providers.
    pub const fn mode(&self) -> DaemonMode {
        self.mode
    }

    /// Return the broker profile sealed into both concrete Process adapters.
    pub const fn broker_profile(&self) -> d2b_contracts_broker::broker_wire::BrokerProfile {
        self.mode.broker_profile()
    }

    /// Borrow the daemon-owned minijail Provider.
    pub const fn minijail(&self) -> &MinijailProcessProvider<BrokerProcessSupervisor> {
        &self.minijail
    }

    /// Borrow the daemon-owned systemd Provider.
    pub const fn systemd(&self) -> &SystemdProcessProvider<BrokerSystemdSupervisor> {
        &self.systemd
    }

    /// Return the fixed Provider names in contract order.
    pub const fn provider_names() -> &'static [&'static str; 2] {
        &FIXED_PROCESS_PROVIDER_NAMES
    }

    /// Borrow the fixed mode-bound effect adapter used by controller
    /// launches.
    pub const fn fixed_effect(&self) -> &FixedEffectAdapter {
        &self.fixed_effect
    }

    fn validate_execution_target(&self, target: &ResourceRef) -> Result<(), String> {
        let expected = match self.mode {
            DaemonMode::Host => "Host",
            DaemonMode::Guest => "Guest",
        };
        if target.resource_type().as_str() == expected {
            Ok(())
        } else {
            Err("process-execution-target-not-owned-by-daemon".to_owned())
        }
    }

    /// Return whether this node is a daemon-owned Provider process.
    pub fn supports_node(node: &ProcessNode) -> bool {
        !is_guest_owned_process_node(node)
            && !is_durable_wayland_process_node(node)
            && matches!(
                node.role,
                ProcessRole::SwtpmPreStartFlush
                    | ProcessRole::Swtpm
                    | ProcessRole::Virtiofsd
                    | ProcessRole::QemuMediaRunner
                    | ProcessRole::ActivationNixosRunner
                    | ProcessRole::Gpu
                    | ProcessRole::GpuRenderNode
                    | ProcessRole::Audio
                    | ProcessRole::Video
                    | ProcessRole::VsockRelay
                    | ProcessRole::OtelHostBridge
                    | ProcessRole::Usbip
                    | ProcessRole::WaylandProxy
            )
    }

    /// Return whether this node remains supervised after its start step.
    pub fn is_long_lived(node: &ProcessNode) -> bool {
        !matches!(
            node.role,
            ProcessRole::SwtpmPreStartFlush | ProcessRole::ActivationNixosRunner
        ) && Self::supports_node(node)
    }

    /// Return the stable role key used by the broker and daemon stop paths.
    pub fn tracked_role_id(node: &ProcessNode) -> String {
        if matches!(node.role, ProcessRole::CloudHypervisorRunner) {
            "ch-runner".to_owned()
        } else {
            node.id.0.clone()
        }
    }

    /// Return all Provider-managed long-lived roles declared for one VM.
    pub fn managed_role_ids(&self, vm: &str) -> Vec<String> {
        let Some(dag) = self.bundle.find_process_vm(vm) else {
            return Vec::new();
        };
        dag.nodes
            .iter()
            .filter(|node| Self::is_long_lived(node))
            .map(Self::tracked_role_id)
            .collect()
    }

    /// Return a cloned trusted process node for a tracked role key.
    pub fn node_for_role(&self, vm: &str, role_id: &str) -> Option<ProcessNode> {
        self.bundle
            .find_process_vm(vm)?
            .nodes
            .iter()
            .find(|node| Self::tracked_role_id(node) == role_id)
            .cloned()
    }

    /// Return every VM that has a process DAG in the trusted bundle.
    pub fn vm_ids(&self) -> Vec<String> {
        self.bundle
            .processes
            .vms
            .iter()
            .map(|dag| dag.vm.clone())
            .collect()
    }

    /// Return whether a Provider-managed identity is currently retained.
    pub fn has_active_role(&self, vm: &str, role_id: &str) -> bool {
        self.managed
            .lock()
            .map(|managed| managed.contains_key(&(vm.to_owned(), role_id.to_owned())))
            .unwrap_or(false)
    }

    /// Return whether any Provider-managed long-lived role is retained.
    pub fn has_active_vm(&self, vm: &str) -> bool {
        self.managed
            .lock()
            .map(|managed| managed.keys().any(|(managed_vm, _)| managed_vm == vm))
            .unwrap_or(false)
    }

    /// Return Provider role keys with retained exact local authority.
    pub fn active_role_ids(&self, vm: &str) -> Vec<String> {
        self.managed
            .lock()
            .map(|managed| {
                managed
                    .keys()
                    .filter(|(managed_vm, _)| managed_vm == vm)
                    .map(|(_, role)| role.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Launch one trusted process node through its selected fixed Provider.
    pub async fn launch_node(
        &self,
        vm: &str,
        node: &ProcessNode,
        timeout: Duration,
    ) -> Result<ProviderLaunch, String> {
        if !Self::supports_node(node) {
            return Err("provider-node-unsupported".to_owned());
        }
        let target = node
            .execution_ref
            .clone()
            .unwrap_or_else(|| d2b_core::bundle_resolver::default_execution_ref(vm, &node.role));
        self.validate_execution_target(
            &ResourceRef::parse(&target)
                .map_err(|_| "process-execution-target-invalid".to_owned())?,
        )?;
        let ticket = self.ticket_with_timeout(vm, node, timeout)?;
        let provider = self.provider_for(node);
        let report = match provider {
            ManagedProvider::Minijail => self
                .minijail
                .launch(&ticket)
                .await
                .map_err(provider_error)?,
            ManagedProvider::Systemd => {
                self.systemd.launch(&ticket).await.map_err(provider_error)?
            }
        };
        self.remember(vm, node, report.identity)?;
        Ok(ProviderLaunch {
            identity: report.identity,
        })
    }

    /// Launch one durable Process resource with the controller generation
    /// rehydrated from the owning Zone store.
    pub(crate) async fn launch_resource(
        &self,
        context: ProcessResourceContext<'_>,
        spec: &ProcessSpec,
        timeout: Duration,
    ) -> Result<ProviderLaunch, String> {
        let context = context
            .with_execution_ref(spec.execution().execution_ref())
            .with_user_ref(spec.execution().user_ref());
        self.validate_execution_target(spec.execution().execution_ref())?;
        let provider = managed_provider_from_ref(context.provider_ref)?;
        validate_resource_execution_target(self.mode, &context, spec.execution())?;
        let ticket = resource_ticket(
            &self.bundle,
            &context,
            spec.execution(),
            None,
            &serde_json::to_vec(spec).map_err(|_| "provider-ticket:serialization".to_owned())?,
            provider,
            self.mode,
            timeout,
            Some(spec.readiness().class()),
        )?;
        self.retire_resource_if_identity_changed(
            &context,
            provider,
            ticket.template(),
            spec.execution().execution_ref(),
            ticket.runtime_scope(),
        )
        .await?;
        let controller_bootstrap = ticket.inherited_fd_table().count() != 0;
        if controller_bootstrap && provider != ManagedProvider::Minijail {
            return Err("provider-controller-bootstrap-unsupported".to_owned());
        }
        if controller_bootstrap {
            self.forget_controller_bootstrap_for_resource_context(&context);
        }
        let controller_endpoints = if controller_bootstrap {
            let (daemon_endpoint, child_endpoint) = prearmed_seqpacket_pair()
                .map_err(|_| "provider-controller-bootstrap-create".to_owned())?;
            let (child_fds, delivery_key_handoff, backend_lease) =
                if ticket.inherited_fd_table().count() == 2 {
                    let supervisor = self.guest_backend_supervisor.as_ref().ok_or_else(|| {
                        "provider-credential-backend-supervisor-unavailable".to_owned()
                    })?;
                    let preparation = supervisor.prepare(&context)?;
                    (
                        vec![child_endpoint, preparation.child_endpoint],
                        Some(preparation.delivery_key_handoff),
                        Some(preparation.lease),
                    )
                } else {
                    (vec![child_endpoint], None, None)
                };
            Some((
                daemon_endpoint,
                child_fds,
                delivery_key_handoff,
                backend_lease,
            ))
        } else {
            None
        };
        let mut delivery_key_handoff = None;
        let mut backend_lease = None;
        let report = match provider {
            ManagedProvider::Minijail => match controller_endpoints {
                Some((daemon_endpoint, child_fds, key_handoff, lease)) => {
                    delivery_key_handoff = key_handoff;
                    backend_lease = lease;
                    let mut inherited_fds = child_fds;
                    inherited_fds.push(daemon_endpoint);
                    self.minijail
                        .launch_with_inherited_fds(&ticket, inherited_fds)
                        .await
                        .map_err(provider_error)
                }
                None => self.minijail.launch(&ticket).await.map_err(provider_error),
            },
            ManagedProvider::Systemd => self.systemd.launch(&ticket).await.map_err(provider_error),
        };
        let report = match report {
            Ok(report) => report,
            Err(error) => {
                if controller_bootstrap {
                    self.forget_controller_bootstrap_for_resource_context(&context);
                }
                return Err(error);
            }
        };
        self.remember_resource(
            context.zone.clone(),
            context.zone_uid.clone(),
            context.resource_ref,
            context.resource_uid,
            context.resource_generation,
            context.controller_generation,
            provider,
            context.provider_ref.clone(),
            context.provider_uid.clone(),
            context.provider_generation,
            context.owner_ref.clone(),
            context.owner_uid.clone(),
            ticket.template().clone(),
            report.identity,
            spec.execution().execution_ref(),
            context.target_ref.clone(),
            ticket.runtime_scope(),
        )?;
        if controller_bootstrap {
            let daemon_endpoint = self
                .minijail
                .port()
                .take_controller_bootstrap(&report.identity)
                .await
                .map_err(provider_error)?
                .ok_or_else(|| "provider-controller-bootstrap-missing".to_owned())?;
            let controller_context = match ControllerBootstrapContext::from_resource_context(
                &context,
                spec.execution().execution_ref(),
                report.identity,
            ) {
                Ok(controller_context) => controller_context,
                Err(error) => {
                    let _ = self
                        .stop_provider_identity(provider, &report.identity, StopClass::Terminate)
                        .await;
                    let _ = match provider {
                        ManagedProvider::Minijail => {
                            self.minijail
                                .port()
                                .finalize_identity(&report.identity)
                                .await
                        }
                        ManagedProvider::Systemd => {
                            self.systemd
                                .port()
                                .finalize_identity(&report.identity)
                                .await
                        }
                    };
                    self.forget_resource_for_context(&context, spec.execution().execution_ref());
                    return Err(error);
                }
            };
            if let Err(error) = self.remember_controller_bootstrap(ControllerBootstrapEndpoint {
                daemon_endpoint,
                delivery_key_handoff,
                backend_lease,
                context: controller_context,
            }) {
                let _ = self
                    .stop_provider_identity(provider, &report.identity, StopClass::Terminate)
                    .await;
                let _ = match provider {
                    ManagedProvider::Minijail => {
                        self.minijail
                            .port()
                            .finalize_identity(&report.identity)
                            .await
                    }
                    ManagedProvider::Systemd => {
                        self.systemd
                            .port()
                            .finalize_identity(&report.identity)
                            .await
                    }
                };
                self.forget_resource_for_context(&context, spec.execution().execution_ref());
                return Err(error);
            }
        }
        Ok(ProviderLaunch {
            identity: report.identity,
        })
    }

    /// Launch one ephemeral Process resource with the controller generation
    /// rehydrated from the owning Zone store.
    pub(crate) async fn launch_ephemeral_resource(
        &self,
        context: ProcessResourceContext<'_>,
        spec: &EphemeralProcessSpec,
        timeout: Duration,
    ) -> Result<ProviderLaunch, String> {
        self.validate_execution_target(spec.execution().execution_ref())?;
        let provider = managed_provider_from_ref(context.provider_ref)?;
        validate_resource_execution_target(self.mode, &context, spec.execution())?;
        let ticket = resource_ticket(
            &self.bundle,
            &context,
            spec.execution(),
            spec.activation_input(),
            &serde_json::to_vec(spec).map_err(|_| "provider-ticket:serialization".to_owned())?,
            provider,
            self.mode,
            timeout,
            None,
        )?;
        self.retire_resource_if_identity_changed(
            &context,
            provider,
            ticket.template(),
            spec.execution().execution_ref(),
            ticket.runtime_scope(),
        )
        .await?;
        let report = match provider {
            ManagedProvider::Minijail => self
                .minijail
                .launch(&ticket)
                .await
                .map_err(provider_error)?,
            ManagedProvider::Systemd => {
                self.systemd.launch(&ticket).await.map_err(provider_error)?
            }
        };
        self.remember_resource(
            context.zone.clone(),
            context.zone_uid.clone(),
            context.resource_ref,
            context.resource_uid,
            context.resource_generation,
            context.controller_generation,
            provider,
            context.provider_ref.clone(),
            context.provider_uid.clone(),
            context.provider_generation,
            context.owner_ref.clone(),
            context.owner_uid.clone(),
            ticket.template().clone(),
            report.identity,
            spec.execution().execution_ref(),
            context.target_ref.clone(),
            ticket.runtime_scope(),
        )?;
        Ok(ProviderLaunch {
            identity: report.identity,
        })
    }

    /// Launch a signed target-local controller Process.
    ///
    /// The controller is represented by a normal Process ticket. The fixed
    /// adapter validates the target mode first, then the selected Process
    /// Provider delivers the ticket through its mode-bound broker backend.
    pub(crate) async fn launch_controller(
        &self,
        resource: &ControllerProcessResource,
        target_readiness_digest: ConfigurationDigest,
        timeout: Duration,
    ) -> Result<ProviderLaunch, String> {
        self.validate_controller_target(resource)?;
        let provider = managed_provider_from_ref(resource.process_provider_ref())?;
        let zone_uid = self
            .bundle
            .zone_uid(resource.zone())
            .ok_or_else(|| "provider-ticket:zone-identity-missing".to_owned())?;
        let ticket = controller_launch_ticket(
            self.bundle.audit_bundle_hash(),
            resource,
            zone_uid,
            provider,
            target_readiness_digest,
            timeout,
        )?;
        self.fixed_effect
            .validate_controller_ticket(&ticket)
            .map_err(|error| error.to_string())?;
        let report = match provider {
            ManagedProvider::Minijail => self
                .minijail
                .launch(&ticket)
                .await
                .map_err(provider_error)?,
            ManagedProvider::Systemd => {
                self.systemd.launch(&ticket).await.map_err(provider_error)?
            }
        };
        self.remember_resource(
            resource.zone().clone(),
            None,
            resource.process_ref(),
            resource.uid(),
            resource.resource_generation(),
            resource.controller_generation(),
            provider,
            resource.process_provider_ref().clone(),
            None,
            Some(resource.provider_generation()),
            Some(resource.provider_ref().clone()),
            None,
            ticket.template().clone(),
            report.identity,
            resource.target(),
            Some(resource.target().clone()),
            ticket.runtime_scope(),
        )?;
        Ok(ProviderLaunch {
            identity: report.identity,
        })
    }

    /// Adopt a signed target-local controller Process after daemon restart.
    pub(crate) async fn adopt_controller(
        &self,
        resource: &ControllerProcessResource,
        target_readiness_digest: ConfigurationDigest,
    ) -> Result<ProviderAdoption, String> {
        self.validate_controller_target(resource)?;
        let provider = managed_provider_from_ref(resource.process_provider_ref())?;
        let zone_uid = self
            .bundle
            .zone_uid(resource.zone())
            .ok_or_else(|| "provider-ticket:zone-identity-missing".to_owned())?;
        let ticket = controller_launch_ticket(
            self.bundle.audit_bundle_hash(),
            resource,
            zone_uid,
            provider,
            target_readiness_digest,
            Duration::from_secs(30),
        )?;
        self.fixed_effect
            .validate_controller_ticket(&ticket)
            .map_err(|error| error.to_string())?;
        let outcome = match provider {
            ManagedProvider::Minijail => {
                self.minijail.adopt(&ticket).await.map_err(provider_error)?
            }
            ManagedProvider::Systemd => {
                self.systemd.adopt(&ticket).await.map_err(provider_error)?
            }
        };
        match outcome {
            AdoptionOutcome::Absent => Ok(ProviderAdoption::Absent),
            AdoptionOutcome::Adopted(report) => {
                self.remember_resource(
                    resource.zone().clone(),
                    None,
                    resource.process_ref(),
                    resource.uid(),
                    resource.resource_generation(),
                    resource.controller_generation(),
                    provider,
                    resource.process_provider_ref().clone(),
                    None,
                    Some(resource.provider_generation()),
                    Some(resource.provider_ref().clone()),
                    None,
                    ticket.template().clone(),
                    report.identity,
                    resource.target(),
                    Some(resource.target().clone()),
                    ticket.runtime_scope(),
                )?;
                Ok(ProviderAdoption::Adopted(report))
            }
            AdoptionOutcome::Stale { candidate } => {
                self.forget_resource_in_zone(resource.zone(), None, resource.process_ref());
                Ok(ProviderAdoption::Stale { candidate })
            }
            AdoptionOutcome::Quarantined(report) => {
                self.forget_resource_in_zone(resource.zone(), None, resource.process_ref());
                Ok(ProviderAdoption::Quarantined(report))
            }
        }
    }

    fn validate_controller_target(
        &self,
        resource: &ControllerProcessResource,
    ) -> Result<(), String> {
        let expected = match self.mode {
            DaemonMode::Host => "Host",
            DaemonMode::Guest => "Guest",
        };
        if resource.target().resource_type().as_str() != expected {
            return Err("provider-controller-target-denied".to_owned());
        }
        if !resource
            .required_effect_classes()
            .contains(&d2b_contracts_provider::v3::EffectPortClass::Process)
        {
            return Err("provider-controller-effect-class-denied".to_owned());
        }
        Ok(())
    }

    /// Adopt one durable Process resource with the controller generation
    /// rehydrated from the owning Zone store.
    pub(crate) async fn adopt_resource(
        &self,
        context: ProcessResourceContext<'_>,
        spec: &ProcessSpec,
    ) -> Result<ProviderAdoption, String> {
        self.adopt_resource_with_execution(
            context,
            spec.execution(),
            None,
            &serde_json::to_vec(spec).map_err(|_| "provider-ticket:serialization".to_owned())?,
            Some(spec.readiness().class()),
        )
        .await
    }

    async fn stop_resource_identity_with_retry(
        &self,
        managed: &ManagedResource,
        class: StopClass,
        deadline: Instant,
    ) -> Result<(), String> {
        loop {
            match self.stop_resource_identity(managed, class).await {
                Ok(()) => return Ok(()),
                Err(error) if error == "pidfd-unavailable" || error == "process-vanished" => {
                    return Err(error);
                }
                Err(error) if retryable_stop_error(&error) && Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Adopt one ephemeral Process resource with the controller generation
    /// rehydrated from the owning Zone store.
    pub(crate) async fn adopt_ephemeral_resource(
        &self,
        context: ProcessResourceContext<'_>,
        spec: &EphemeralProcessSpec,
    ) -> Result<ProviderAdoption, String> {
        self.adopt_resource_with_execution(
            context,
            spec.execution(),
            spec.activation_input(),
            &serde_json::to_vec(spec).map_err(|_| "provider-ticket:serialization".to_owned())?,
            None,
        )
        .await
    }

    /// Probe one durable Process resource with the controller generation
    /// rehydrated from the owning Zone store.
    pub(crate) async fn probe_resource(
        &self,
        context: ProcessResourceContext<'_>,
        spec: &ProcessSpec,
    ) -> Result<ProviderLiveness, String> {
        let liveness = self
            .probe_resource_with_execution(
                &context,
                spec.execution(),
                None,
                &serde_json::to_vec(spec)
                    .map_err(|_| "provider-ticket:serialization".to_owned())?,
                Some(spec.readiness().class()),
            )
        .await?;
        if liveness == ProviderLiveness::Exited {
                self.finalize_resource(context.clone()).await?;
        }
        Ok(liveness)
    }

    /// Probe one ephemeral Process resource with the controller generation
    /// rehydrated from the owning Zone store.
    pub(crate) async fn probe_ephemeral_resource(
        &self,
        context: ProcessResourceContext<'_>,
        spec: &EphemeralProcessSpec,
    ) -> Result<ProviderLiveness, String> {
        let liveness = self
            .probe_resource_with_execution(
                &context,
                spec.execution(),
                spec.activation_input(),
                &serde_json::to_vec(spec)
                    .map_err(|_| "provider-ticket:serialization".to_owned())?,
                None,
            )
        .await?;
        if liveness == ProviderLiveness::Exited {
                self.finalize_resource(context.clone()).await?;
        }
        Ok(liveness)
    }

    /// Stop one exact generic Process identity with the controller
    /// generation rehydrated from the owning Zone store.
    pub(crate) async fn stop_resource(
        &self,
        context: ProcessResourceContext<'_>,
        spec: &ProcessSpec,
        term_timeout: Duration,
        kill_timeout: Duration,
    ) -> Result<bool, String> {
        self.stop_resource_with_execution(
            context,
            spec.execution(),
            None,
            &serde_json::to_vec(spec).map_err(|_| "provider-ticket:serialization".to_owned())?,
            Some(spec.readiness().class()),
            term_timeout,
            kill_timeout,
        )
        .await
    }

    /// Stop one exact generic EphemeralProcess identity with the controller
    /// generation rehydrated from the owning Zone store.
    pub(crate) async fn stop_ephemeral_resource(
        &self,
        context: ProcessResourceContext<'_>,
        spec: &EphemeralProcessSpec,
        term_timeout: Duration,
        kill_timeout: Duration,
    ) -> Result<bool, String> {
        self.stop_resource_with_execution(
            context,
            spec.execution(),
            spec.activation_input(),
            &serde_json::to_vec(spec).map_err(|_| "provider-ticket:serialization".to_owned())?,
            None,
            term_timeout,
            kill_timeout,
        )
        .await
    }

    /// Finalize one terminal generic Process identity.
    pub(crate) async fn finalize_resource(
        &self,
        context: ProcessResourceContext<'_>,
    ) -> Result<(), String> {
        let Some(managed) = self
            .managed_resources
            .lock()
            .map_err(|_| "provider-managed-state-poisoned".to_owned())?
            .get(&(
                context.zone.clone(),
                context.zone_uid.clone(),
                context.resource_ref.clone(),
            ))
            .cloned()
        else {
            self.forget_controller_bootstrap_for_resource_context(&context);
            return Ok(());
        };
        let mismatches = resource_identity_mismatches(&managed, &context);
        if !mismatches.is_empty() {
            return Err(identity_changed_error(mismatches));
        }
        if !execution_target_allowed(self.mode, &managed.execution_ref) {
            return Err(GUEST_EXECUTION_UNAVAILABLE.to_owned());
        }
        self.forget_controller_bootstrap_for_context(
            &context,
            &managed.execution_ref,
            managed.identity,
        );
        let result = match managed.provider {
            ManagedProvider::Minijail => self
                .minijail
                .port()
                .finalize_identity(&managed.identity)
                .await
                .map_err(provider_error),
            ManagedProvider::Systemd => self
                .systemd
                .port()
                .finalize_identity(&managed.identity)
                .await
                .map_err(provider_error),
        };
        match result {
            Ok(()) => {
                self.forget_resource_for_context(&context, &managed.execution_ref);
                Ok(())
            }
            Err(error) if error == "process-vanished" => {
                self.forget_resource_for_context(&context, &managed.execution_ref);
                Ok(())
            }
            Err(error) if error == "pidfd-unavailable" => Err(error),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn spawn_resource_waiter(
        &self,
        context: &ProcessResourceContext<'_>,
        identity: ProcessIdentityDigest,
        waker: Arc<dyn Fn(ResourceKey, ZoneRevision) + Send + Sync>,
    ) -> Result<(), String> {
        let managed = self
            .managed_resources
            .lock()
            .map_err(|_| "provider-managed-state-poisoned".to_owned())?
            .get(&(
                context.zone.clone(),
                context.zone_uid.clone(),
                context.resource_ref.clone(),
            ))
            .cloned()
            .ok_or_else(|| "provider-process-not-found".to_owned())?;
        let mismatches = resource_identity_mismatches(&managed, context);
        if !mismatches.is_empty() {
            return Err(identity_changed_error(mismatches));
        }
        if managed.identity != identity {
            return Err(identity_changed_error(vec![
                "process_identity".to_owned(),
            ]));
        }
        let waiter_key = (
            (
                context.zone.clone(),
                context.zone_uid.clone(),
                context.resource_ref.clone(),
            ),
            identity,
        );
        {
            let mut waiters = self
                .resource_waiters
                .lock()
                .map_err(|_| "provider-managed-state-poisoned".to_owned())?;
            if !waiters.insert(waiter_key.clone()) {
                return Ok(());
            }
        }
        let waiter = match managed.provider {
            ManagedProvider::Minijail => Waiter::Minijail(self.minijail.port().clone()),
            ManagedProvider::Systemd => Waiter::Systemd(self.systemd.port().clone()),
        };
        let resource_waiters = Arc::clone(&self.resource_waiters);
        let key = ResourceKey::new(
            context.zone.clone(),
            context.resource_ref.clone(),
            context.resource_uid.clone(),
        );
        let revision = context.resource_revision;
        tokio::spawn(async move {
            if let Err(error) = waiter.wait(identity).await {
                tracing::debug!(error = %error, "Process identity waiter ended before exit wake");
            }
            if let Ok(mut waiters) = resource_waiters.lock() {
                waiters.remove(&waiter_key);
            }
            waker(key, revision);
        });
        Ok(())
    }

    /// Return whether a generic resource retains a verified identity.
    pub fn has_active_resource(&self, resource_ref: &ResourceRef) -> bool {
        self.managed_resources
            .lock()
            .map(|managed| managed.keys().any(|(_, _, key)| key == resource_ref))
            .unwrap_or(false)
    }

    /// Return whether a specific Zone retains a verified resource identity.
    pub fn has_active_resource_in_zone(
        &self,
        zone: &ZoneId,
        zone_uid: Option<&ResourceUid>,
        resource_ref: &ResourceRef,
    ) -> bool {
        self.managed_resources
            .lock()
            .map(|managed| {
                managed.contains_key(&(zone.clone(), zone_uid.cloned(), resource_ref.clone()))
            })
            .unwrap_or(false)
    }

    pub(crate) fn has_controller_bootstrap(
        &self,
        resource_ref: &ResourceRef,
        context: &ControllerBootstrapContext,
    ) -> bool {
        let key = (context.zone.clone(), resource_ref.clone());
        self.controller_bootstrap
            .lock()
            .ok()
            .and_then(|markers| markers.get(&key).map(|marker| marker.context() == context))
            .unwrap_or(false)
    }

    fn forget_controller_bootstrap_for_context(
        &self,
        context: &ProcessResourceContext<'_>,
        execution_ref: &ResourceRef,
        process_identity: ProcessIdentityDigest,
    ) {
        let Some(owner_ref) = context.owner_ref.as_ref() else {
            return;
        };
        let key = (context.zone.clone(), context.resource_ref.clone());
        if let Ok(mut markers) = self.controller_bootstrap.lock()
            && markers.get(&key).is_some_and(|marker| {
                let marker_context = marker.context();
                marker_context.zone == context.zone
                    && marker_context.zone_uid.as_ref() == context.zone_uid.as_ref()
                    && marker_context.process_ref == *context.resource_ref
                    && marker_context.process_uid == *context.resource_uid
                    && marker_context.generation == context.resource_generation
                    && marker_context.process_identity == process_identity
                    && marker_context.process_provider_ref == *context.provider_ref
                    && marker_context.provider_owner_ref == *owner_ref
                    && context
                        .provider_uid
                        .as_ref()
                        .is_some_and(|uid| marker_context.provider_uid == *uid)
                    && context
                        .provider_generation
                        .is_some_and(|generation| marker_context.provider_generation == generation)
                    && marker_context.execution_ref == *execution_ref
                    && marker_context.user_ref.as_ref() == context.user_ref.as_ref()
                    && marker_context.controller_generation == context.controller_generation
            })
        {
            markers.remove(&key);
        }
    }

    pub(crate) fn forget_controller_bootstrap_for_resource_context(
        &self,
        context: &ProcessResourceContext<'_>,
    ) {
        let Some(owner_ref) = context.owner_ref.as_ref() else {
            return;
        };
        let key = (context.zone.clone(), context.resource_ref.clone());
        if let Ok(mut markers) = self.controller_bootstrap.lock()
            && markers.get(&key).is_some_and(|marker| {
                let marker_context = marker.context();
                marker_context.process_ref == *context.resource_ref
                    && marker_context.zone_uid.as_ref() == context.zone_uid.as_ref()
                    && marker_context.process_uid == *context.resource_uid
                    && marker_context.generation == context.resource_generation
                    && marker_context.process_provider_ref == *context.provider_ref
                    && marker_context.provider_owner_ref == *owner_ref
                    && context
                        .provider_uid
                        .as_ref()
                        .is_none_or(|uid| marker_context.provider_uid == *uid)
                    && context
                        .provider_generation
                        .is_none_or(|generation| marker_context.provider_generation == generation)
                    && context.user_ref.as_ref() == marker_context.user_ref.as_ref()
                    && marker_context.controller_generation == context.controller_generation
            })
        {
            markers.remove(&key);
        }
    }

    fn remember_controller_bootstrap(
        &self,
        endpoint: ControllerBootstrapEndpoint,
    ) -> Result<(), String> {
        let process_ref = endpoint.context.process_ref.clone();
        let key = (endpoint.context.zone.clone(), process_ref);
        let mut markers = self
            .controller_bootstrap
            .lock()
            .map_err(|_| "provider-managed-state-poisoned".to_owned())?;
        if markers.len() >= MAX_CONTROLLER_BOOTSTRAP_ENDPOINTS && !markers.contains_key(&key) {
            return Err("provider-controller-bootstrap-capacity".to_owned());
        }
        if markers
            .get(&key)
            .is_some_and(|current| current.context().zone_uid != endpoint.context.zone_uid)
        {
            return Err("provider-controller-bootstrap-zone-identity-conflict".to_owned());
        }
        if markers
            .get(&key)
            .is_some_and(|current| current.context().generation() > endpoint.context.generation())
        {
            return Err("provider-controller-bootstrap-stale-generation".to_owned());
        }
        markers.insert(key, ControllerBootstrapMarker::Pending(endpoint));
        Ok(())
    }

    pub(crate) fn controller_bootstrap_refs(&self, zone: &ZoneId) -> Vec<ResourceRef> {
        self.controller_bootstrap
            .lock()
            .map(|markers| {
                markers
                    .keys()
                    .filter(|(marker_zone, _)| marker_zone == zone)
                    .map(|(_, process_ref)| process_ref.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub(crate) fn controller_bootstrap_present(
        &self,
        zone: &ZoneId,
        process_ref: &ResourceRef,
    ) -> bool {
        self.controller_bootstrap
            .lock()
            .map(|markers| markers.contains_key(&(zone.clone(), process_ref.clone())))
            .unwrap_or(false)
    }

    pub(crate) fn controller_bootstrap_ready(
        &self,
        zone: &ZoneId,
        process_ref: &ResourceRef,
    ) -> bool {
        let Ok(markers) = self.controller_bootstrap.lock() else {
            return false;
        };
        let Some(ControllerBootstrapMarker::Pending(endpoint)) =
            markers.get(&(zone.clone(), process_ref.clone()))
        else {
            return false;
        };
        use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
        let interests = PollFlags::POLLIN | PollFlags::POLLERR | PollFlags::POLLHUP;
        let mut descriptors = [PollFd::new(
            endpoint.daemon_endpoint.as_fd(),
            interests,
        )];
        matches!(poll(&mut descriptors, PollTimeout::ZERO), Ok(count) if count > 0)
            && descriptors[0]
                .revents()
                .is_some_and(|events| events.intersects(interests))
    }

    pub(crate) fn controller_bootstrap_contexts(
        &self,
        zone: &ZoneId,
    ) -> Vec<ControllerBootstrapContext> {
        self.controller_bootstrap
            .lock()
            .map(|markers| {
                markers
                    .iter()
                    .filter(|((marker_zone, _), _)| marker_zone == zone)
                    .map(|(_, marker)| marker.context().clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub(crate) fn controller_bootstrap_establishing_contexts(
        &self,
        zone: &ZoneId,
    ) -> Vec<ControllerBootstrapContext> {
        self.controller_bootstrap
            .lock()
            .map(|markers| {
                markers
                    .values()
                    .filter_map(|marker| match marker {
                        ControllerBootstrapMarker::Establishing(context)
                            if context.zone() == zone =>
                        {
                            Some(context.clone())
                        }
                        ControllerBootstrapMarker::Pending(_)
                        | ControllerBootstrapMarker::Establishing(_)
                        | ControllerBootstrapMarker::Active(_) => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub(crate) fn controller_peer_matches(
        &self,
        context: &ControllerBootstrapContext,
        peer_pid: i32,
    ) -> Result<bool, String> {
        if context.process_provider_ref().name().as_str() != "system-minijail" {
            return Ok(false);
        }
        self.minijail
            .port()
            .matches_peer_process(&context.process_identity(), peer_pid)
            .map_err(|error| error.to_string())
    }

    pub(crate) fn begin_controller_bootstrap(
        &self,
        zone: &ZoneId,
        process_ref: &ResourceRef,
    ) -> Option<ControllerBootstrapEndpoint> {
        let mut markers = self.controller_bootstrap.lock().ok()?;
        let key = (zone.clone(), process_ref.clone());
        let marker = markers.remove(&key)?;
        match marker {
            ControllerBootstrapMarker::Pending(endpoint) => {
                let context = endpoint.context.clone();
                markers.insert(key, ControllerBootstrapMarker::Establishing(context));
                Some(endpoint)
            }
            ControllerBootstrapMarker::Establishing(context) => {
                markers.insert(key, ControllerBootstrapMarker::Establishing(context));
                None
            }
            ControllerBootstrapMarker::Active(context) => {
                markers.insert(key, ControllerBootstrapMarker::Active(context));
                None
            }
        }
    }

    pub(crate) fn activate_controller_bootstrap(
        &self,
        context: &ControllerBootstrapContext,
    ) -> bool {
        let Ok(mut markers) = self.controller_bootstrap.lock() else {
            return false;
        };
        if !matches!(
            markers.get(&(context.zone.clone(), context.process_ref().clone())),
            Some(ControllerBootstrapMarker::Establishing(current)) if *current == *context
        ) {
            return false;
        }
        markers.insert(
            (context.zone.clone(), context.process_ref().clone()),
            ControllerBootstrapMarker::Active(context.clone()),
        );
        true
    }

    pub(crate) fn fail_controller_bootstrap(&self, context: &ControllerBootstrapContext) -> bool {
        let Ok(mut markers) = self.controller_bootstrap.lock() else {
            return false;
        };
        if markers
            .get(&(context.zone.clone(), context.process_ref().clone()))
            .is_some_and(|marker| marker.context() == context)
        {
            markers.remove(&(context.zone.clone(), context.process_ref().clone()));
            true
        } else {
            false
        }
    }

    fn forget_resource_for_context(
        &self,
        context: &ProcessResourceContext<'_>,
        execution_ref: &ResourceRef,
    ) {
        let process_identity = self
            .managed_resources
            .lock()
            .ok()
            .and_then(|managed| {
                managed
                    .get(&(
                        context.zone.clone(),
                        context.zone_uid.clone(),
                        context.resource_ref.clone(),
                    ))
                    .cloned()
            })
            .filter(|managed| {
                resource_identity_matches(managed, context)
                    && managed.execution_ref == *execution_ref
            })
            .map(|managed| managed.identity);
        if let Some(process_identity) = process_identity {
            self.forget_controller_bootstrap_for_context(context, execution_ref, process_identity);
        } else {
            self.forget_controller_bootstrap_for_resource_context(context);
        }
        if let Ok(mut managed) = self.managed_resources.lock()
            && managed
                .get(&(
                    context.zone.clone(),
                    context.zone_uid.clone(),
                    context.resource_ref.clone(),
                ))
                .is_some_and(|resource| {
                    resource_identity_matches(resource, context)
                        && resource.execution_ref == *execution_ref
                })
        {
            managed.remove(&(
                context.zone.clone(),
                context.zone_uid.clone(),
                context.resource_ref.clone(),
            ));
        }
    }

    async fn adopt_resource_with_execution(
        &self,
        context: ProcessResourceContext<'_>,
        execution: &d2b_contracts_resource::v3::process::ExecutionSpec,
        activation_input: Option<&d2b_contracts_resource::v3::ActivationRunnerInput>,
        spec_bytes: &[u8],
        readiness: Option<ReadinessClass>,
    ) -> Result<ProviderAdoption, String> {
        self.validate_execution_target(execution.execution_ref())?;
        let provider = managed_provider_from_ref(context.provider_ref)?;
        validate_resource_execution_target(self.mode, &context, execution)?;
        let ticket = resource_ticket(
            &self.bundle,
            &context,
            execution,
            activation_input,
            spec_bytes,
            provider,
            self.mode,
            Duration::from_secs(30),
            readiness,
        )?;
        self.retire_resource_if_identity_changed(
            &context,
            provider,
            ticket.template(),
            execution.execution_ref(),
            ticket.runtime_scope(),
        )
        .await?;
        let outcome = match provider {
            ManagedProvider::Minijail => {
                self.minijail.adopt(&ticket).await.map_err(provider_error)?
            }
            ManagedProvider::Systemd => {
                self.systemd.adopt(&ticket).await.map_err(provider_error)?
            }
        };
        let controller_bootstrap = ticket.inherited_fd_table().count() != 0;
        match outcome {
            AdoptionOutcome::Absent => {
                self.finalize_resource(context.clone()).await?;
                Ok(ProviderAdoption::Absent)
            }
            AdoptionOutcome::Adopted(report) => {
                self.remember_resource(
                    context.zone.clone(),
                    context.zone_uid.clone(),
                    context.resource_ref,
                    context.resource_uid,
                    context.resource_generation,
                    context.controller_generation,
                    provider,
                    context.provider_ref.clone(),
                    context.provider_uid.clone(),
                    context.provider_generation,
                    context.owner_ref.clone(),
                    context.owner_uid.clone(),
                    ticket.template().clone(),
                    report.identity,
                    execution.execution_ref(),
                    context.target_ref.clone(),
                    ticket.runtime_scope(),
                )?;
                if controller_bootstrap {
                    let controller_context = ControllerBootstrapContext::from_resource_context(
                        &context,
                        execution.execution_ref(),
                        report.identity,
                    )?;
                    let Some(daemon_endpoint) = self
                        .minijail
                        .port()
                        .take_controller_bootstrap(&report.identity)
                        .await
                        .map_err(provider_error)?
                    else {
                        return Ok(ProviderAdoption::ControllerBootstrapMissing);
                    };
                    if ticket.inherited_fd_table().count() == 2 {
                        return Ok(ProviderAdoption::ControllerBootstrapMissing);
                    }
                    self.remember_controller_bootstrap(ControllerBootstrapEndpoint {
                        daemon_endpoint,
                        delivery_key_handoff: None,
                        backend_lease: None,
                        context: controller_context,
                    })?;
                }
                Ok(ProviderAdoption::Adopted(report))
            }
            AdoptionOutcome::Stale { candidate } => {
                self.forget_resource_in_zone(
                    &context.zone,
                    context.zone_uid.as_ref(),
                    context.resource_ref,
                );
                Ok(ProviderAdoption::Stale { candidate })
            }
            AdoptionOutcome::Quarantined(report) => {
                self.forget_resource_in_zone(
                    &context.zone,
                    context.zone_uid.as_ref(),
                    context.resource_ref,
                );
                Ok(ProviderAdoption::Quarantined(report))
            }
        }
    }

    async fn probe_resource_with_execution(
        &self,
        context: &ProcessResourceContext<'_>,
        execution: &d2b_contracts_resource::v3::process::ExecutionSpec,
        activation_input: Option<&d2b_contracts_resource::v3::ActivationRunnerInput>,
        spec_bytes: &[u8],
        readiness: Option<ReadinessClass>,
    ) -> Result<ProviderLiveness, String> {
        self.validate_execution_target(execution.execution_ref())?;
        let provider = managed_provider_from_ref(context.provider_ref)?;
        validate_resource_execution_target(self.mode, &context, execution)?;
        let ticket = resource_ticket(
            &self.bundle,
            &context,
            execution,
            activation_input,
            spec_bytes,
            provider,
            self.mode,
            Duration::from_secs(30),
            readiness,
        )?;
        let candidate = match provider {
            ManagedProvider::Minijail => self
                .minijail
                .port()
                .probe(&ticket)
                .await
                .map_err(provider_error)?,
            ManagedProvider::Systemd => self
                .systemd
                .port()
                .probe(&ticket)
                .await
                .map_err(provider_error)?,
        };
        let Some(candidate) = candidate else {
            return Ok(ProviderLiveness::Exited);
        };
        let (expected_owner, required) = match provider {
            ManagedProvider::Minijail => (
                self.minijail.profile().wait_reap_owner(),
                self.minijail.profile().required_identity_bindings(),
            ),
            ManagedProvider::Systemd => (
                self.systemd.profile().wait_reap_owner(),
                self.systemd.profile().required_identity_bindings(),
            ),
        };
        if candidate.wait_reap_owner != expected_owner || candidate.validate(required).is_err() {
            Ok(ProviderLiveness::Unknown)
        } else {
            Ok(ProviderLiveness::Alive)
        }
    }

    async fn stop_resource_with_execution(
        &self,
        context: ProcessResourceContext<'_>,
        execution: &d2b_contracts_resource::v3::process::ExecutionSpec,
        activation_input: Option<&d2b_contracts_resource::v3::ActivationRunnerInput>,
        spec_bytes: &[u8],
        readiness: Option<ReadinessClass>,
        term_timeout: Duration,
        kill_timeout: Duration,
    ) -> Result<bool, String> {
        validate_resource_execution_target(self.mode, &context, execution)?;
        let provider = managed_provider_from_ref(context.provider_ref)?;
        let ticket = resource_ticket(
            &self.bundle,
            &context,
            execution,
            activation_input,
            spec_bytes,
            provider,
            self.mode,
            Duration::from_secs(30),
            readiness,
        )?;
        let managed = self
            .managed_resources
            .lock()
            .map_err(|_| "provider-managed-state-poisoned".to_owned())?
            .get(&(
                context.zone.clone(),
                context.zone_uid.clone(),
                context.resource_ref.clone(),
            ))
            .cloned()
            .ok_or_else(|| "provider-process-not-found".to_owned())?;
        let mut mismatches = resource_identity_mismatches(&managed, &context);
        if managed.provider != provider {
            mismatches.push(format!(
                "provider(managed={:?},requested={provider:?})",
                managed.provider
            ));
        }
        if managed.template != *ticket.template() {
            mismatches.push(format!(
                "template(managed={:?},requested={:?})",
                managed.template,
                ticket.template()
            ));
        }
        if managed.execution_ref != *execution.execution_ref() {
            mismatches.push(format!(
                "execution_ref(managed={:?},requested={:?})",
                managed.execution_ref,
                execution.execution_ref()
            ));
        }
        if managed.runtime_scope != ticket.runtime_scope() {
            mismatches.push(format!(
                "runtime_scope(managed={:?},requested={:?})",
                managed.runtime_scope,
                ticket.runtime_scope()
            ));
        }
        if !mismatches.is_empty() {
            return Err(identity_changed_error(mismatches));
        }
        match self
            .stop_resource_identity_with_retry(
                &managed,
                StopClass::Drain,
                Instant::now() + term_timeout,
            )
            .await
        {
            Ok(()) => {}
            Err(error) if error == "process-vanished" => {}
            Err(error) if error == "pidfd-unavailable" => return Err(error),
            Err(error) => return Err(error),
        }
        let deadline = Instant::now() + term_timeout;
        loop {
            match self
                .probe_resource_with_execution(
                    &context,
                    execution,
                    activation_input,
                    spec_bytes,
                    readiness,
                )
                .await?
            {
                ProviderLiveness::Exited => {
                    self.finalize_resource(context.clone()).await?;
                    return Ok(false);
                }
                ProviderLiveness::Alive => {}
                ProviderLiveness::Unknown if Instant::now() >= deadline => break,
                ProviderLiveness::Unknown => {}
            }
            if Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        match self
            .stop_resource_identity_with_retry(
                &managed,
                StopClass::Terminate,
                Instant::now() + kill_timeout,
            )
            .await
        {
            Ok(()) => {}
            Err(error) if error == "process-vanished" => {}
            Err(error) if error == "pidfd-unavailable" => return Err(error),
            Err(error) => return Err(error),
        }
        let kill_deadline = Instant::now() + kill_timeout;
        loop {
            match self
                .probe_resource_with_execution(
                    &context,
                    execution,
                    activation_input,
                    spec_bytes,
                    readiness,
                )
                .await?
            {
                ProviderLiveness::Exited => {
                    self.finalize_resource(context.clone()).await?;
                    return Ok(true);
                }
                ProviderLiveness::Alive | ProviderLiveness::Unknown => {}
            }
            if Instant::now() >= kill_deadline {
                return Err("provider-process-kill-timeout".to_owned());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// Adopt one trusted process node after a daemon restart.
    pub async fn adopt_node(
        &self,
        vm: &str,
        node: &ProcessNode,
    ) -> Result<ProviderAdoption, String> {
        if !Self::supports_node(node) {
            return Err("provider-node-unsupported".to_owned());
        }
        let ticket = self.ticket(vm, node)?;
        let outcome = match self.provider_for(node) {
            ManagedProvider::Minijail => {
                self.minijail.adopt(&ticket).await.map_err(provider_error)?
            }
            ManagedProvider::Systemd => {
                self.systemd.adopt(&ticket).await.map_err(provider_error)?
            }
        };
        match outcome {
            AdoptionOutcome::Absent => Ok(ProviderAdoption::Absent),
            AdoptionOutcome::Adopted(report) => {
                self.remember(vm, node, report.identity)?;
                Ok(ProviderAdoption::Adopted(report))
            }
            AdoptionOutcome::Stale { candidate } => {
                self.forget(vm, node);
                Ok(ProviderAdoption::Stale { candidate })
            }
            AdoptionOutcome::Quarantined(report) => {
                self.forget(vm, node);
                Ok(ProviderAdoption::Quarantined(report))
            }
        }
    }

    /// Probe one node through the Provider's authenticated read-only path.
    ///
    /// Unlike adoption, a liveness probe does not open a pidfd, retain a
    /// handle, or stage an observation for a later adoption call.
    pub async fn probe_node(
        &self,
        vm: &str,
        node: &ProcessNode,
    ) -> Result<ProviderLiveness, String> {
        if !Self::supports_node(node) {
            return Ok(ProviderLiveness::Unknown);
        }
        let ticket = self.ticket(vm, node)?;
        let candidate = match self.provider_for(node) {
            ManagedProvider::Minijail => self
                .minijail
                .port()
                .probe(&ticket)
                .await
                .map_err(provider_error)?,
            ManagedProvider::Systemd => self
                .systemd
                .port()
                .probe(&ticket)
                .await
                .map_err(provider_error)?,
        };
        let Some(candidate) = candidate else {
            return Ok(ProviderLiveness::Exited);
        };
        let expected_owner = match self.provider_for(node) {
            ManagedProvider::Minijail => self.minijail.profile().wait_reap_owner(),
            ManagedProvider::Systemd => self.systemd.profile().wait_reap_owner(),
        };
        let required = match self.provider_for(node) {
            ManagedProvider::Minijail => self.minijail.profile().required_identity_bindings(),
            ManagedProvider::Systemd => self.systemd.profile().required_identity_bindings(),
        };
        if candidate.wait_reap_owner != expected_owner || candidate.validate(required).is_err() {
            Ok(ProviderLiveness::Unknown)
        } else {
            Ok(ProviderLiveness::Alive)
        }
    }

    /// Observe a Provider-owned OneShot until it exits, then release its
    /// exact pidfd or service-manager identity.
    pub async fn wait_node(
        &self,
        vm: &str,
        node: &ProcessNode,
        timeout: Duration,
    ) -> Result<(), String> {
        if !Self::supports_node(node) {
            return Err("provider-node-unsupported".to_owned());
        }
        let deadline = Instant::now() + timeout;
        loop {
            match self.probe_node(vm, node).await? {
                ProviderLiveness::Exited => {
                    self.finalize_node(vm, node).await?;
                    return Ok(());
                }
                ProviderLiveness::Alive => {}
                ProviderLiveness::Unknown => {
                    return Err("provider-process-identity-ambiguous".to_owned());
                }
            }
            if Instant::now() >= deadline {
                return Err("provider-process-exit-timeout".to_owned());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// Stop one exact Provider identity, escalating after the drain budget.
    pub async fn stop_node(
        &self,
        vm: &str,
        node: &ProcessNode,
        term_timeout: Duration,
        kill_timeout: Duration,
    ) -> Result<bool, String> {
        if !Self::supports_node(node) {
            return Err("provider-node-unsupported".to_owned());
        }
        let key = (vm.to_owned(), Self::tracked_role_id(node));
        let managed = self
            .managed
            .lock()
            .map_err(|_| "provider-managed-state-poisoned".to_owned())?
            .get(&key)
            .copied()
            .ok_or_else(|| "provider-process-not-found".to_owned())?;
        match self.stop_identity(managed, StopClass::Drain).await {
            Ok(()) => {}
            Err(error) if error == "process-vanished" => {}
            Err(error) if error == "pidfd-unavailable" => return Err(error),
            Err(error) => return Err(error),
        }
        let deadline = Instant::now() + term_timeout;
        loop {
            match self.probe_node(vm, node).await? {
                ProviderLiveness::Exited => {
                    self.finalize_node(vm, node).await?;
                    return Ok(false);
                }
                ProviderLiveness::Alive => {}
                ProviderLiveness::Unknown => {
                    if Instant::now() >= deadline {
                        break;
                    }
                }
            }
            if Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        match self.stop_identity(managed, StopClass::Terminate).await {
            Ok(()) => {}
            Err(error) if error == "process-vanished" => {}
            Err(error) if error == "pidfd-unavailable" => return Err(error),
            Err(error) => return Err(error),
        }
        let kill_deadline = Instant::now() + kill_timeout;
        loop {
            match self.probe_node(vm, node).await? {
                ProviderLiveness::Exited => {
                    self.finalize_node(vm, node).await?;
                    return Ok(true);
                }
                ProviderLiveness::Alive | ProviderLiveness::Unknown => {}
            }
            if Instant::now() >= kill_deadline {
                return Err("provider-process-kill-timeout".to_owned());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// Finalize a terminal Provider process and remove its local authority.
    pub async fn finalize_node(&self, vm: &str, node: &ProcessNode) -> Result<(), String> {
        if !Self::supports_node(node) {
            return Err("provider-node-unsupported".to_owned());
        }
        let key = (vm.to_owned(), Self::tracked_role_id(node));
        let Some(managed) = self
            .managed
            .lock()
            .map_err(|_| "provider-managed-state-poisoned".to_owned())?
            .get(&key)
            .copied()
        else {
            return Ok(());
        };
        let result = match managed.provider {
            ManagedProvider::Minijail => self
                .minijail
                .port()
                .finalize_identity(&managed.identity)
                .await
                .map_err(provider_error),
            ManagedProvider::Systemd => self
                .systemd
                .port()
                .finalize_identity(&managed.identity)
                .await
                .map_err(provider_error),
        };
        match result {
            Ok(()) => {
                self.forget(vm, node);
                Ok(())
            }
            Err(error) if error == "process-vanished" => {
                self.forget(vm, node);
                Ok(())
            }
            Err(error) if error == "pidfd-unavailable" => Err(error),
            Err(error) => Err(error),
        }
    }

    /// Adopt only the long-lived process roles authorized by durable
    /// lifecycle snapshots for one VM.
    pub async fn adopt_vm(
        &self,
        vm: &str,
        eligible_roles: &BTreeSet<String>,
    ) -> Result<(), String> {
        let Some(dag) = self.bundle.find_process_vm(vm) else {
            return Ok(());
        };
        for node in dag
            .nodes
            .iter()
            .filter(|node| Self::is_long_lived(node))
            .filter(|node| eligible_roles.contains(&Self::tracked_role_id(node)))
        {
            match self.adopt_node(vm, node).await? {
                ProviderAdoption::Absent => {
                    self.forget(vm, node);
                }
                ProviderAdoption::Adopted(_) => {}
                ProviderAdoption::ControllerBootstrapMissing => {
                    tracing::warn!(
                        vm = %vm,
                        role = %Self::tracked_role_id(node),
                        "Provider startup adoption found a controller without bootstrap"
                    );
                }
                ProviderAdoption::Stale { .. } => {
                    tracing::warn!(
                        vm = %vm,
                        role = %Self::tracked_role_id(node),
                        "Provider startup adoption found a stale process"
                    );
                }
                ProviderAdoption::Quarantined(_) => {
                    tracing::warn!(
                        vm = %vm,
                        role = %Self::tracked_role_id(node),
                        "Provider startup adoption quarantined an ambiguous process"
                    );
                }
            }
        }
        Ok(())
    }

    fn provider_for(&self, node: &ProcessNode) -> ManagedProvider {
        if node.unit.is_some() {
            ManagedProvider::Systemd
        } else {
            ManagedProvider::Minijail
        }
    }

    fn remember(
        &self,
        vm: &str,
        node: &ProcessNode,
        identity: ProcessIdentityDigest,
    ) -> Result<(), String> {
        self.managed
            .lock()
            .map_err(|_| "provider-managed-state-poisoned".to_owned())?
            .insert(
                (vm.to_owned(), Self::tracked_role_id(node)),
                ManagedProcess {
                    provider: self.provider_for(node),
                    identity,
                },
            );
        Ok(())
    }

    fn remember_resource(
        &self,
        zone: ZoneId,
        zone_uid: Option<ResourceUid>,
        resource_ref: &ResourceRef,
        uid: &ResourceUid,
        generation: ResourceGeneration,
        controller_generation: ControllerGeneration,
        provider: ManagedProvider,
        provider_ref: ResourceRef,
        provider_uid: Option<ResourceUid>,
        provider_generation: Option<ResourceGeneration>,
        owner_ref: Option<ResourceRef>,
        owner_uid: Option<ResourceUid>,
        template: BoundedToken,
        identity: ProcessIdentityDigest,
        execution_ref: &ResourceRef,
        target_ref: Option<ResourceRef>,
        runtime_scope: Option<ConfigurationDigest>,
    ) -> Result<(), String> {
        self.managed_resources
            .lock()
            .map_err(|_| "provider-managed-state-poisoned".to_owned())?
            .insert(
                (zone.clone(), zone_uid.clone(), resource_ref.clone()),
                ManagedResource {
                    zone,
                    zone_uid,
                    resource_ref: resource_ref.clone(),
                    provider,
                    provider_ref,
                    provider_uid,
                    provider_generation,
                    owner_ref,
                    owner_uid,
                    template,
                    identity,
                    uid: uid.clone(),
                    generation,
                    controller_generation,
                    execution_ref: execution_ref.clone(),
                    target_ref,
                    runtime_scope,
                },
            );
        Ok(())
    }

    fn forget(&self, vm: &str, node: &ProcessNode) {
        if let Ok(mut managed) = self.managed.lock() {
            managed.remove(&(vm.to_owned(), Self::tracked_role_id(node)));
        }
    }

    fn forget_resource_in_zone(
        &self,
        zone: &ZoneId,
        zone_uid: Option<&ResourceUid>,
        resource_ref: &ResourceRef,
    ) {
        if let Ok(mut markers) = self.controller_bootstrap.lock() {
            markers.retain(|(marker_zone, marker_ref), marker| {
                marker_zone != zone
                    || marker_ref != resource_ref
                    || marker.context().zone_uid.as_ref() != zone_uid
            });
        }
        if let Ok(mut managed) = self.managed_resources.lock() {
            managed.remove(&(zone.clone(), zone_uid.cloned(), resource_ref.clone()));
        }
    }

    async fn stop_provider_identity(
        &self,
        provider: ManagedProvider,
        identity: &ProcessIdentityDigest,
        class: StopClass,
    ) -> Result<(), String> {
        match provider {
            ManagedProvider::Minijail => self
                .minijail
                .stop(identity, class)
                .await
                .map_err(provider_error),
            ManagedProvider::Systemd => self
                .systemd
                .stop(identity, class)
                .await
                .map_err(provider_error),
        }
    }

    pub(crate) async fn stop_stale_resource(
        &self,
        provider_ref: &ResourceRef,
        candidate: &AdoptionCandidate,
    ) -> Result<(), String> {
        let provider = managed_provider_from_ref(provider_ref)?;
        match provider {
            ManagedProvider::Minijail => self
                .minijail
                .stop_stale(candidate)
                .await
                .map_err(provider_error)?,
            ManagedProvider::Systemd => self
                .systemd
                .stop_stale(candidate)
                .await
                .map_err(provider_error)?,
        }
        let finalized = match provider {
            ManagedProvider::Minijail => self
                .minijail
                .port()
                .finalize_identity(&candidate.identity)
                .await
                .map_err(provider_error),
            ManagedProvider::Systemd => self
                .systemd
                .port()
                .finalize_identity(&candidate.identity)
                .await
                .map_err(provider_error),
        };
        match finalized {
            Ok(()) => Ok(()),
            Err(error) if error == "process-vanished" => Ok(()),
            Err(error) if error == "pidfd-unavailable" => Err(error),
            Err(error) => Err(error),
        }
    }

    async fn stop_identity(&self, managed: ManagedProcess, class: StopClass) -> Result<(), String> {
        self.stop_provider_identity(managed.provider, &managed.identity, class)
            .await
    }

    async fn stop_resource_identity(
        &self,
        managed: &ManagedResource,
        class: StopClass,
    ) -> Result<(), String> {
        self.stop_provider_identity(managed.provider, &managed.identity, class)
            .await
    }

    async fn retire_managed_resource(&self, managed: &ManagedResource) -> Result<(), String> {
        match self
            .stop_resource_identity_with_retry(
                managed,
                StopClass::Drain,
                Instant::now() + Duration::from_secs(30),
            )
            .await
        {
            Ok(()) => {}
            Err(error) if error == "process-vanished" => {}
            Err(error) if error == "pidfd-unavailable" => return Err(error),
            Err(error) if retryable_stop_error(&error) => {
                self.stop_resource_identity_with_retry(
                    managed,
                    StopClass::Terminate,
                    Instant::now() + Duration::from_secs(30),
                )
                .await
                .or_else(|error| {
                    if error == "process-vanished" {
                        Ok(())
                    } else {
                        Err(error)
                    }
                })?;
            }
            Err(error) => return Err(error),
        }
        let finalized = match managed.provider {
            ManagedProvider::Minijail => self
                .minijail
                .port()
                .finalize_identity(&managed.identity)
                .await
                .map_err(provider_error),
            ManagedProvider::Systemd => self
                .systemd
                .port()
                .finalize_identity(&managed.identity)
                .await
                .map_err(provider_error),
        };
        match finalized {
            Ok(()) => Ok(()),
            Err(error) if error == "process-vanished" => Ok(()),
            Err(error) if error == "pidfd-unavailable" => Err(error),
            Err(error) => Err(error),
        }
    }

    async fn retire_resource_if_identity_changed(
        &self,
        context: &ProcessResourceContext<'_>,
        provider: ManagedProvider,
        template: &BoundedToken,
        execution_ref: &ResourceRef,
        runtime_scope: Option<ConfigurationDigest>,
    ) -> Result<(), String> {
        let managed = self
            .managed_resources
            .lock()
            .map_err(|_| "provider-managed-state-poisoned".to_owned())?
            .values()
            .filter(|managed| {
                managed.zone == context.zone && managed.resource_ref == *context.resource_ref
            })
            .cloned()
            .collect::<Vec<_>>();
        for managed in managed {
            let mut mismatches = resource_identity_mismatches(&managed, context);
            if managed.provider != provider {
                mismatches.push(format!(
                    "provider(managed={:?},requested={provider:?})",
                    managed.provider
                ));
            }
            if managed.template != *template {
                mismatches.push(format!(
                    "template(managed={:?},requested={template:?})",
                    managed.template
                ));
            }
            if managed.execution_ref != *execution_ref {
                mismatches.push(format!(
                    "execution_ref(managed={:?},requested={execution_ref:?})",
                    managed.execution_ref
                ));
            }
            if managed.runtime_scope != runtime_scope {
                mismatches.push(format!(
                    "runtime_scope(managed={:?},requested={runtime_scope:?})",
                    managed.runtime_scope
                ));
            }
            if mismatches.is_empty() {
                continue;
            }
            self.retire_managed_resource(&managed).await?;
            self.forget_resource_in_zone(
                &managed.zone,
                managed.zone_uid.as_ref(),
                &managed.resource_ref,
            );
        }
        Ok(())
    }

    fn ticket(&self, vm: &str, node: &ProcessNode) -> Result<LaunchTicket, String> {
        self.ticket_with_timeout(vm, node, Duration::from_secs(30))
    }

    fn ticket_with_timeout(
        &self,
        vm: &str,
        node: &ProcessNode,
        timeout: Duration,
    ) -> Result<LaunchTicket, String> {
        build_ticket(&self.bundle, vm, node, self.provider_for(node), timeout)
            .map_err(|error| format!("provider-ticket:{}", error.code()))
    }
}

fn provider_error(error: ProcessConformanceError) -> String {
    error.code().to_owned()
}

fn caller_uid(caller: &BrokerCallerRole) -> u32 {
    match caller {
        BrokerCallerRole::AdminUid { uid }
        | BrokerCallerRole::LauncherUid { uid }
        | BrokerCallerRole::RootUid { uid }
        | BrokerCallerRole::HostShutdownUid { uid } => *uid,
        BrokerCallerRole::NotAuthorized => 0,
    }
}

fn managed_provider_from_ref(provider_ref: &ResourceRef) -> Result<ManagedProvider, String> {
    match provider_ref.name().as_str() {
        "system-minijail" => Ok(ManagedProvider::Minijail),
        "system-systemd" => Ok(ManagedProvider::Systemd),
        _ => Err("provider-ticket:unsupported-provider".to_owned()),
    }
}

fn is_credential_provider_ref(provider_ref: &ResourceRef) -> bool {
    provider_ref.resource_type().as_str() == "Provider"
        && matches!(
            provider_ref.name().as_str(),
            "credential-secret-service"
                | "credential-entra"
                | "credential-managed-identity"
        )
}

fn is_managed_identity_agent_context(
    context: &ProcessResourceContext<'_>,
    execution: &d2b_contracts_resource::v3::process::ExecutionSpec,
) -> bool {
    context.provider_ref.name().as_str() == "system-minijail"
        && context
            .owner_ref
            .as_ref()
            .is_some_and(|owner| owner.resource_type().as_str() == "Credential")
        && context.resource_ref.resource_type().as_str() == "Process"
        && context.resource_ref.name().as_str().starts_with("mi-agent-")
        && execution.template().as_str() == "d2b-managed-identity-agent"
        && context.controller_provider_ref.as_ref().is_some_and(|provider| {
            provider.to_canonical_string() == "Provider/credential-managed-identity"
        })
}

fn controller_launch_ticket(
    bundle_content_identity: &str,
    resource: &ControllerProcessResource,
    zone_uid: ResourceUid,
    provider: ManagedProvider,
    target_readiness_digest: ConfigurationDigest,
    timeout: Duration,
) -> Result<LaunchTicket, String> {
    let owner_provider = BoundedToken::parse(resource.provider_ref().name().as_str())
        .map_err(|_| "provider-ticket:invalid-owner-provider")?;
    let selected_provider = BoundedToken::parse(resource.process_provider_ref().name().as_str())
        .map_err(|_| "provider-ticket:invalid-process-provider")?;
    let component = resource.component_id().clone();
    let operation_scope = format!(
        "{}:{}:{}:{}",
        component.as_str(),
        resource.provider_generation().get(),
        resource.controller_generation().get(),
        resource.target_session_generation().get(),
    );
    let operation_uid = stable_uid(
        "controller-launch",
        &resource.process_ref().to_canonical_string(),
        &operation_scope,
        resource.resource_generation().get(),
    );
    let deadline_ms = timeout.as_millis().clamp(1, 900_000) as u32;
    let operation = OperationBinding::new(operation_uid, deadline_ms)
        .map_err(|_| "provider-ticket:invalid-operation")?;
    let ticket = LaunchTicket::new(
        resource.process_ref().clone(),
        resource.uid().clone(),
        resource.resource_generation(),
        resource.controller_generation(),
        owner_provider,
        component.clone(),
        component,
        resource.target().clone(),
        ExecutionDomain::System,
        None,
        selected_provider,
        compiled_controller_digests(resource, provider, &target_readiness_digest),
        operation,
        required_identity(provider),
    )
    .map_err(|error| format!("provider-ticket:{}", error.code()))?;
    let mut ticket = ticket
        .with_owner_ref(resource.provider_ref().clone())
        .map_err(|error| format!("provider-ticket:{}", error.code()))?;
    let sandbox = SandboxCompiler
        .compile_plan(
            resource.process_spec().execution().sandbox(),
            ExecutionDomain::System,
            false,
        )
        .map_err(|error| format!("provider-ticket:{}", error.code()))?;
    let signed_descriptor_digest = configuration_digest(
        "signed-descriptor",
        resource.signed_descriptor_digest().as_str(),
    );
    let commitment = execution_commitment(
        bundle_content_identity,
        ticket.execution_ref(),
        ticket.target_ref(),
        ticket.domain(),
        ticket.user_ref(),
        ticket.template(),
        ticket.selected_provider(),
    );
    let runtime_scope = runtime_scope_commitment(
        &zone_uid,
        None,
        resource.process_ref(),
        resource.uid(),
        resource.process_ref().name().as_str(),
        resource.resource_generation().get(),
    );
    ticket = ticket
        .with_resource_revision(resource.resource_revision())
        .map_err(|error| format!("provider-ticket:{}", error.code()))?
        .with_controller_launch_binding(
            resource.provider_generation(),
            resource.target_session_generation(),
            signed_descriptor_digest,
            target_readiness_digest,
        )
        .map_err(|error| format!("provider-ticket:{}", error.code()))?
        .with_execution_commitment(commitment)
        .map_err(|error| format!("provider-ticket:{}", error.code()))?
        .with_runtime_identity(
            zone_uid,
            Some(resource.provider_ref().clone()),
            runtime_scope,
        )
        .map_err(|error| format!("provider-ticket:{}", error.code()))?
        .with_sandbox_plan(sandbox)
        .with_readiness(ReadinessExpectation::None);
    Ok(ticket)
}

fn compiled_controller_digests(
    resource: &ControllerProcessResource,
    provider: ManagedProvider,
    readiness: &ConfigurationDigest,
) -> CompiledDigests {
    fn digest(label: &str, bytes: &[u8]) -> ConfigurationDigest {
        let mut hasher = Sha256::new();
        hasher.update(b"d2bd-provider-controller-ticket-v1");
        hasher.update(label.as_bytes());
        hasher.update([0]);
        hasher.update(bytes);
        ConfigurationDigest::from_bytes(hasher.finalize().into())
    }
    let context = format!(
        "{}:{}:{}:{}",
        resource.process_ref().to_canonical_string(),
        resource.signed_descriptor_digest().as_str(),
        resource.artifact_digest().as_str(),
        match provider {
            ManagedProvider::Minijail => "system-minijail",
            ManagedProvider::Systemd => "system-systemd",
        },
    );
    let bytes = format!("{context}:{}", readiness.to_hex()).into_bytes();
    CompiledDigests {
        sandbox: digest("sandbox", &bytes),
        budget: digest("budget", &bytes),
        mounts: digest("mounts", &bytes),
        devices: digest("devices", &bytes),
        network: digest("network", &bytes),
        endpoints: digest("endpoints", &bytes),
        fd_table: digest("fd-table", &bytes),
    }
}

fn configuration_digest(label: &str, value: &str) -> ConfigurationDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"d2bd-provider-configuration-digest-v1");
    hasher.update(label.as_bytes());
    hasher.update([0]);
    hasher.update(value.as_bytes());
    ConfigurationDigest::from_bytes(hasher.finalize().into())
}

pub(crate) fn execution_target_allowed(mode: DaemonMode, execution_ref: &ResourceRef) -> bool {
    match mode {
        DaemonMode::Host => execution_ref.resource_type().as_str() == "Host",
        DaemonMode::Guest => execution_ref.resource_type().as_str() == "Guest",
    }
}

fn validate_resource_execution_target(
    mode: DaemonMode,
    context: &ProcessResourceContext<'_>,
    execution: &d2b_contracts_resource::v3::process::ExecutionSpec,
) -> Result<(), String> {
    // A Host daemon has no authenticated cross-target Process session yet.
    // Reject Guest refs before ticket construction so they cannot fall
    // through to the Host broker's local systemd/minijail adapters.
    let execution_ref = execution.execution_ref();
    if !matches!(execution_ref.resource_type().as_str(), "Host" | "Guest") {
        return Err("provider-ticket:invalid-execution-ref".to_owned());
    }
    if !execution_target_allowed(mode, execution_ref) {
        return Err(match mode {
            DaemonMode::Host => GUEST_EXECUTION_UNAVAILABLE,
            DaemonMode::Guest => "provider-ticket:host-execution-denied",
        }
        .to_owned());
    }
    if execution_ref.resource_type().as_str() == "Host"
        && let Some(target) = context.target_ref.as_ref()
        && target.resource_type().as_str() != "Guest"
    {
        return Err("provider-ticket:invalid-target".to_owned());
    }
    Ok(())
}

fn resource_ticket(
    bundle: &BundleResolver,
    context: &ProcessResourceContext<'_>,
    execution: &d2b_contracts_resource::v3::process::ExecutionSpec,
    activation_input: Option<&d2b_contracts_resource::v3::ActivationRunnerInput>,
    spec_bytes: &[u8],
    provider: ManagedProvider,
    mode: DaemonMode,
    timeout: Duration,
    readiness: Option<ReadinessClass>,
) -> Result<LaunchTicket, String> {
    validate_resource_execution_target(mode, context, execution)?;
    let execution_domain = match execution.domain().unwrap_or(ExecutionDomain::System) {
        ExecutionDomain::System => d2b_core::processes::ProcessExecutionDomain::System,
        ExecutionDomain::User => d2b_core::processes::ProcessExecutionDomain::User,
    };
    let user_ref = execution.user_ref().map(ResourceRef::to_canonical_string);
    let target_vm_name = match execution.execution_ref().resource_type().as_str() {
        "Guest" => Some(execution.execution_ref().name().as_str()),
        "Host" => match context.target_ref.as_ref() {
            Some(target) if target.resource_type().as_str() == "Guest" => {
                Some(target.name().as_str())
            }
            None => context
                .owner_ref
                .as_ref()
                .filter(|owner| owner.resource_type().as_str() == "Guest")
                .map(|owner| owner.name().as_str()),
            Some(_) => return Err("provider-ticket:invalid-target".to_owned()),
        },
        _ => return Err("provider-ticket:invalid-execution-ref".to_owned()),
    };
    let execution_ref = execution.execution_ref().to_canonical_string();
    let owner_ref = context
        .owner_ref
        .as_ref()
        .map(ResourceRef::to_canonical_string);
    let exact_static_controller = execution.process_class() == ProcessClass::Controller
        && context
            .owner_ref
            .as_ref()
            .is_some_and(|owner| owner.resource_type().as_str() == "Provider");
    let managed_identity_agent = is_managed_identity_agent_context(context, execution);
    if exact_static_controller
        && context
            .owner_ref
            .as_ref()
            .is_some_and(is_credential_provider_ref)
        && execution.execution_ref().resource_type().as_str() != "Guest"
    {
        return Err("provider-ticket:credential-provider-guest-required".to_owned());
    }
    if execution.process_class() == ProcessClass::Controller && !exact_static_controller {
        return Err("provider-ticket:controller-owner-invalid".to_owned());
    }
    if managed_identity_agent && execution.execution_ref().resource_type().as_str() != "Guest" {
        return Err("provider-ticket:credential-agent-guest-required".to_owned());
    }
    let static_intent = exact_static_controller.then(|| {
        bundle.find_provider_controller_intent(
            context.resource_ref,
            &execution_ref,
            execution_domain,
            user_ref.as_deref(),
            execution.template().as_str(),
            owner_ref.as_deref(),
        )
    });
    let generic_intent = if exact_static_controller {
        None
    } else if managed_identity_agent {
        bundle.find_provider_component_intent_for_template(
            &execution_ref,
            execution_domain,
            user_ref.as_deref(),
            execution.template().as_str(),
            Some("Provider/credential-managed-identity"),
        )
    } else if let Some(owner) = context
        .owner_ref
        .as_ref()
        .filter(|owner| owner.resource_type().as_str() == "Guest")
    {
        if context.resource_ref.resource_type().as_str() != "Process"
            || context.resource_ref.name().as_str() != format!("{}-vmm", owner.name().as_str())
        {
            return Err("provider-ticket:guest-process-not-vmm".to_owned());
        }
        let Some(descriptor_digest) = context.guest_descriptor_digest.as_ref() else {
            return Err("provider-ticket:guest-descriptor-unbound".to_owned());
        };
        bundle.find_guest_vmm_intent(
            context.zone.as_str(),
            owner,
            descriptor_digest,
            &execution_ref,
            execution_domain,
            execution.template().as_str(),
        )
    } else {
        bundle.find_runner_intent_for_process_in_vm(
            target_vm_name,
            &execution_ref,
            execution_domain,
            user_ref.as_deref(),
            execution.template().as_str(),
        )
    };
    if static_intent.flatten().is_none() && generic_intent.is_none() {
        return Err("provider-ticket:template-not-found".to_owned());
    }
    let trusted_intent = static_intent
        .flatten()
        .or(generic_intent)
        .ok_or_else(|| "provider-ticket:template-not-found".to_owned())?;
    let ticket_template = if exact_static_controller || managed_identity_agent {
        execution.template().clone()
    } else {
        BoundedToken::parse(trusted_intent.role_id.clone())
            .map_err(|_| "provider-ticket:invalid-template".to_owned())?
    };
    let provider_name = context.provider_ref.name().as_str();
    let owner_provider =
        BoundedToken::parse(provider_name).map_err(|_| "provider-ticket:invalid-provider")?;
    let component = BoundedToken::parse("process-controller")
        .map_err(|_| "provider-ticket:invalid-component")?;
    let generation = context.resource_generation.get();
    let lifecycle_scope = format!(
        "{}:{}:{}",
        context
            .zone_uid
            .as_ref()
            .map(ResourceUid::as_str)
            .unwrap_or("unbound"),
        context
            .policy_revision
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unbound".to_owned()),
        context
            .provider_assignment_generation
            .map(|value| value.get().to_string())
            .unwrap_or_else(|| "unbound".to_owned()),
    );
    let operation_uid = stable_uid(
        "operation",
        &context.resource_ref.to_canonical_string(),
        &format!("{}:{lifecycle_scope}", context.resource_uid.as_str()),
        generation,
    );
    let deadline_ms = timeout.as_millis().clamp(1, 900_000) as u32;
    let mut ticket = LaunchTicket::new(
        context.resource_ref.clone(),
        context.resource_uid.clone(),
        context.resource_generation,
        context.controller_generation,
        owner_provider.clone(),
        component,
        ticket_template,
        execution.execution_ref().clone(),
        execution.domain().unwrap_or(ExecutionDomain::System),
        execution.user_ref().cloned(),
        owner_provider,
        compiled_resource_digests(bundle, context.resource_ref, provider, spec_bytes),
        OperationBinding::new(operation_uid, deadline_ms)
            .map_err(|_| "provider-ticket:invalid-operation")?,
        required_identity(provider),
    )
    .map_err(|error| format!("provider-ticket:{}", error.code()))?;
    ticket = ticket
        .with_inherited_fd_count(if exact_static_controller || managed_identity_agent {
            if managed_identity_agent
                || context
                .owner_ref
                .as_ref()
                .is_some_and(|owner| is_credential_provider_ref(&owner))
            {
                2
            } else {
                1
            }
        } else {
            0
        })
        .map_err(|error| format!("provider-ticket:{}", error.code()))?;
    if execution.execution_ref().resource_type().as_str() == "Host"
        && let Some(target_ref) = context.target_ref.as_ref()
    {
        ticket = ticket
            .with_target_ref(target_ref.clone())
            .map_err(|error| format!("provider-ticket:{}", error.code()))?;
    }
    let ticket = match context.guest_execution.as_ref() {
        Some(binding) if execution.execution_ref().resource_type().as_str() == "Guest" => ticket
            .with_guest_execution_binding(binding.clone())
            .map_err(|error| format!("provider-ticket:{}", error.code()))?,
        Some(_) => {
            return Err("provider-ticket:guest-binding-for-host".to_owned());
        }
        None if execution.execution_ref().resource_type().as_str() == "Guest" => {
            return Err("provider-ticket:guest-binding-missing".to_owned());
        }
        None => ticket,
    };
    let zone_uid = context
        .zone_uid
        .clone()
        .ok_or_else(|| "provider-ticket:zone-identity-missing".to_owned())?;
    let runtime_scope = runtime_scope_commitment(
        &zone_uid,
        context
            .guest_execution
            .as_ref()
            .map(GuestExecutionBinding::target_uid),
        context.resource_ref,
        context.resource_uid,
        trusted_intent.role_id.as_str(),
        context.resource_generation.get(),
    );
    let ticket = ticket
        .with_runtime_identity(zone_uid, context.owner_ref.clone(), runtime_scope)
        .map_err(|error| format!("provider-ticket:{}", error.code()))?;
    let ticket = match context.owner_uid.clone() {
        Some(owner_uid) => ticket
            .with_owner_uid(owner_uid)
            .map_err(|error| format!("provider-ticket:{}", error.code()))?,
        None => ticket,
    };
    let ticket = match activation_input {
        Some(input) => ticket
            .with_activation_input(input.clone())
            .map_err(|error| format!("provider-ticket:{}", error.code()))?,
        None => ticket,
    };
    let commitment = execution_commitment(
        bundle.audit_bundle_hash(),
        ticket.execution_ref(),
        ticket.target_ref(),
        ticket.domain(),
        ticket.user_ref(),
        ticket.template(),
        ticket.selected_provider(),
    );
    let domain = execution.domain().unwrap_or(ExecutionDomain::System);
    let sandbox = if provider == ManagedProvider::Systemd {
        let spec = execution.sandbox();
        if !spec.namespace_classes().is_empty()
            || !spec.capability_classes().is_empty()
            || spec.seccomp_class().as_str() != "strict"
            || !spec.no_new_privileges()
            || spec.start_root()
            || !matches!(
                spec.environment_class(),
                d2b_contracts_resource::v3::process::EnvironmentClass::Minimal
            )
            || !spec.read_only_root()
            || spec.user_namespace().is_some()
        {
            return Err("provider-ticket:systemd-sandbox-unsupported".to_owned());
        }
        SandboxCompiler
            .compile_plan(spec, domain, false)
            .map_err(|error| format!("provider-ticket:{}", error.code()))?
    } else {
        SandboxCompiler
            .compile_plan(execution.sandbox(), domain, false)
            .map_err(|error| format!("provider-ticket:{}", error.code()))?
    };
    let readiness = resource_readiness_expectation(readiness, timeout)?;
    Ok(ticket
        .with_resource_revision(context.resource_revision)
        .map_err(|error| format!("provider-ticket:{}", error.code()))?
        .with_execution_commitment(commitment)
        .map_err(|error| format!("provider-ticket:{}", error.code()))?
        .with_sandbox_plan(sandbox)
        .with_readiness(readiness))
}

fn resource_readiness_expectation(
    readiness: Option<ReadinessClass>,
    timeout: Duration,
) -> Result<ReadinessExpectation, String> {
    match readiness {
        Some(ReadinessClass::ReadyCondition) => {
            let timeout_ms = timeout.as_millis().clamp(1, 900_000) as u32;
            ReadinessExpectation::condition(timeout_ms)
                .map_err(|_| "provider-ticket:invalid-readiness".to_owned())
        }
        Some(ReadinessClass::ProviderDefined) | None => Ok(ReadinessExpectation::None),
    }
}

fn compiled_resource_digests(
    bundle: &BundleResolver,
    resource_ref: &ResourceRef,
    provider: ManagedProvider,
    spec_bytes: &[u8],
) -> CompiledDigests {
    fn digest(label: &str, bytes: &[u8]) -> ConfigurationDigest {
        let mut hasher = Sha256::new();
        hasher.update(b"d2bd-provider-resource-ticket-v1");
        hasher.update(label.as_bytes());
        hasher.update([0]);
        hasher.update(bytes);
        ConfigurationDigest::from_bytes(hasher.finalize().into())
    }
    let context = format!(
        "{}:{}:{}",
        resource_ref.to_canonical_string(),
        match provider {
            ManagedProvider::Minijail => "system-minijail",
            ManagedProvider::Systemd => "system-systemd",
        },
        bundle.bundle.bundle_hash.as_deref().unwrap_or("bundle"),
    );
    CompiledDigests {
        sandbox: digest(&format!("{context}:sandbox"), spec_bytes),
        budget: digest(&format!("{context}:budget"), spec_bytes),
        mounts: digest(&format!("{context}:mounts"), spec_bytes),
        devices: digest(&format!("{context}:devices"), spec_bytes),
        network: digest(&format!("{context}:network"), spec_bytes),
        endpoints: digest(&format!("{context}:endpoints"), spec_bytes),
        fd_table: digest(&format!("{context}:fd-table"), spec_bytes),
    }
}

fn build_ticket(
    bundle: &BundleResolver,
    vm: &str,
    node: &ProcessNode,
    provider: ManagedProvider,
    timeout: Duration,
) -> Result<LaunchTicket, ProcessConformanceError> {
    let provider_name = match provider {
        ManagedProvider::Minijail => "system-minijail",
        ManagedProvider::Systemd => "system-systemd",
    };
    let process_type = if ProductionProcessProviders::is_long_lived(node) {
        "Process"
    } else {
        "EphemeralProcess"
    };
    let process_name = stable_token(&node.id.0);
    let process_ref = ResourceRef::parse(&format!("{process_type}/{process_name}"))
        .map_err(|_| ProcessConformanceError::InvalidTicket)?;
    let execution_ref = ResourceRef::parse(
        &node
            .execution_ref
            .clone()
            .unwrap_or_else(|| d2b_core::bundle_resolver::default_execution_ref(vm, &node.role)),
    )
    .map_err(|_| ProcessConformanceError::InvalidTicket)?;
    let owner_provider =
        BoundedToken::parse(provider_name).map_err(|_| ProcessConformanceError::InvalidTicket)?;
    let component =
        BoundedToken::parse("vm-process").map_err(|_| ProcessConformanceError::InvalidTicket)?;
    let template = BoundedToken::parse(stable_token(&node.id.0))
        .map_err(|_| ProcessConformanceError::InvalidTicket)?;
    let selected_provider = owner_provider.clone();
    let commitment = execution_commitment(
        bundle.audit_bundle_hash(),
        &execution_ref,
        None,
        ExecutionDomain::System,
        None,
        &template,
        &selected_provider,
    );
    let generation = stable_generation(bundle);
    let digests = compiled_digests(bundle, vm, node, provider);
    let operation_uid = stable_uid("operation", vm, &node.id.0, generation);
    let deadline_ms = timeout.as_millis().clamp(1, 900_000) as u32;
    let ticket = LaunchTicket::new(
        process_ref,
        stable_uid("process", vm, &node.id.0, generation),
        ResourceGeneration::new(generation).map_err(|_| ProcessConformanceError::InvalidTicket)?,
        ControllerGeneration::new(1).map_err(|_| ProcessConformanceError::InvalidTicket)?,
        owner_provider,
        component,
        template,
        execution_ref,
        ExecutionDomain::System,
        None,
        selected_provider,
        digests,
        OperationBinding::new(operation_uid, deadline_ms)?,
        required_identity(provider),
    )?;
    Ok(ticket
        .with_execution_commitment(commitment)
        .map_err(|_| ProcessConformanceError::InvalidTicket)?
        .with_readiness(ReadinessExpectation::None))
}

fn required_identity(provider: ManagedProvider) -> std::collections::BTreeSet<IdentityBinding> {
    match provider {
        ManagedProvider::Minijail => std::collections::BTreeSet::from([
            IdentityBinding::Pid,
            IdentityBinding::ProcessStartTime,
            IdentityBinding::Cgroup,
            IdentityBinding::Executable,
            IdentityBinding::Template,
            IdentityBinding::Generation,
        ]),
        ManagedProvider::Systemd => std::collections::BTreeSet::from([
            IdentityBinding::UnitInvocationId,
            IdentityBinding::Cgroup,
            IdentityBinding::UnitMainPid,
            IdentityBinding::ProcessStartTime,
            IdentityBinding::Template,
            IdentityBinding::Generation,
        ]),
    }
}

fn compiled_digests(
    bundle: &BundleResolver,
    vm: &str,
    node: &ProcessNode,
    provider: ManagedProvider,
) -> CompiledDigests {
    fn digest(label: &str, bytes: &[u8]) -> ConfigurationDigest {
        let mut hasher = Sha256::new();
        hasher.update(b"d2bd-provider-ticket-v1");
        hasher.update(label.as_bytes());
        hasher.update([0]);
        hasher.update(bytes);
        ConfigurationDigest::from_bytes(hasher.finalize().into())
    }
    let node_bytes = serde_json::to_vec(node).unwrap_or_default();
    let context = format!(
        "{vm}:{}:{}:{}",
        node.id.0,
        match provider {
            ManagedProvider::Minijail => "system-minijail",
            ManagedProvider::Systemd => "system-systemd",
        },
        bundle.bundle.bundle_hash.as_deref().unwrap_or("bundle")
    );
    CompiledDigests {
        sandbox: digest(&format!("{context}:sandbox"), &node_bytes),
        budget: digest(&format!("{context}:budget"), &node_bytes),
        mounts: digest(&format!("{context}:mounts"), &node_bytes),
        devices: digest(&format!("{context}:devices"), &node_bytes),
        network: digest(&format!("{context}:network"), &node_bytes),
        endpoints: digest(&format!("{context}:endpoints"), &node_bytes),
        fd_table: digest(&format!("{context}:fd-table"), &node_bytes),
    }
}

fn stable_generation(bundle: &BundleResolver) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(
        bundle
            .bundle
            .bundle_hash
            .as_deref()
            .unwrap_or(bundle.bundle.generation.generator.as_str()),
    );
    let bytes: [u8; 32] = hasher.finalize().into();
    let generation = u64::from_le_bytes(bytes[..8].try_into().expect("digest prefix"));
    if generation == 0 { 1 } else { generation }
}

fn stable_uid(label: &str, vm: &str, role: &str, generation: u64) -> ResourceUid {
    let mut hasher = Sha256::new();
    hasher.update(b"d2bd-provider-resource-v1");
    hasher.update(label.as_bytes());
    hasher.update([0]);
    hasher.update(vm.as_bytes());
    hasher.update([0]);
    hasher.update(role.as_bytes());
    hasher.update(generation.to_le_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let rendered = format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    );
    ResourceUid::parse(rendered).expect("stable provider uid")
}

fn stable_token(value: &str) -> String {
    let valid = !value.is_empty()
        && value.len() <= 63
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if !valid {
        let digest = Sha256::digest(value.as_bytes());
        return format!(
            "process-{:02x}{:02x}{:02x}{:02x}",
            digest[0], digest[1], digest[2], digest[3]
        );
    }
    value.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use d2b_contracts_provider::v3::{
        ArtifactDigest, BinaryRef, ComponentDescriptor, ComponentExecution,
        ComponentTargetCapability, ComponentType, ControllerInstanceScope, ControllerTargetKind,
        EffectPortClass,
    };
    use d2b_contracts_resource::v3::{
        CanonicalJsonObject, ControllerGeneration, ResourceGeneration, ResourceName, ResourceRef,
        ResourceTypeName, Timestamp, ZoneId, ZoneRevision,
        execution_policy::{BoundedToken, ExecutionDomain},
        identity::ReconnectGeneration,
    };
    use d2b_contracts_zone_session::v3::resource_bundle::{
        BundleResource, BundleResourceMetadata, ResourceBundle,
    };
    use d2b_core::{
        bundle::{Bundle, BundleGeneration},
        processes::ProcessesJson,
    };
    use d2bd_runtime::target_runtime::ProviderDeployment;

    fn controller_resource() -> ControllerProcessResource {
        let digest = ArtifactDigest::parse(format!("sha256:{}", "a".repeat(64))).unwrap();
        let descriptor = ComponentDescriptor::new(
            BoundedToken::parse("process-controller").unwrap(),
            ComponentType::Controller,
            [ResourceTypeName::parse("Process").unwrap()],
            [BoundedToken::parse("reconcile").unwrap()],
            [ExecutionDomain::System],
            8,
            digest.clone(),
            [],
            false,
        )
        .unwrap()
        .with_execution(ComponentExecution::Launchable {
            binary_ref: BinaryRef::parse("process-controller").unwrap(),
        })
        .with_controller_placement(
            ControllerInstanceScope::PerResourceTarget,
            [ControllerTargetKind::Guest],
        )
        .unwrap()
        .with_target_capabilities([ComponentTargetCapability::new(
            ControllerTargetKind::Guest,
            digest,
            [EffectPortClass::Process],
        )
        .unwrap()])
        .unwrap();
        ProviderDeployment::new(
            DaemonMode::Guest,
            d2bd_runtime::target_runtime::AdmissionLimits::guest_default(),
        )
        .unwrap()
        .create_controller_process(
            ZoneId::parse("work").unwrap(),
            ResourceRef::parse("Provider/runtime").unwrap(),
            &descriptor,
            ResourceGeneration::new(1).unwrap(),
            ResourceGeneration::new(2).unwrap(),
            ControllerGeneration::new(3).unwrap(),
            ReconnectGeneration::new(4).unwrap(),
            ZoneRevision::new(5),
            ResourceRef::parse("Guest/workload").unwrap(),
            ResourceRef::parse("Provider/system-systemd").unwrap(),
            true,
        )
        .unwrap()
    }

    #[test]
    fn stable_uids_are_uuid_v4_shaped_and_repeatable() {
        let first = stable_uid("process", "corp-vm", "ch-runner", 7);
        let second = stable_uid("process", "corp-vm", "ch-runner", 7);
        let other = stable_uid("process", "corp-vm", "audio", 7);
        assert_eq!(first, second);
        assert_ne!(first, other);
    }

    #[test]
    fn stable_tokens_close_invalid_bundle_names_without_paths() {
        assert_eq!(stable_token("audio-sidecar"), "audio-sidecar");
        assert!(stable_token("/var/lib/d2b/audio").starts_with("process-"));
        assert!(stable_token("UpperCase").starts_with("process-"));
    }

    #[test]
    fn durable_process_readiness_is_not_reduced_to_liveness() {
        assert_eq!(
            resource_readiness_expectation(
                Some(ReadinessClass::ReadyCondition),
                Duration::from_secs(7),
            )
            .expect("bounded readiness"),
            ReadinessExpectation::Condition { timeout_ms: 7_000 }
        );
        assert_eq!(
            resource_readiness_expectation(None, Duration::from_secs(7))
                .expect("ephemeral readiness"),
            ReadinessExpectation::None
        );
    }

    #[test]
    fn host_process_providers_reject_guest_execution_before_ticket_creation() {
        let resource_ref = ResourceRef::parse("Process/guest-worker").expect("resource ref");
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").expect("uid");
        let provider_ref = ResourceRef::parse("Provider/system-systemd").expect("provider ref");
        let context = ProcessResourceContext::new(
            ZoneId::parse("work").expect("zone"),
            &resource_ref,
            &uid,
            ResourceGeneration::new(1).expect("generation"),
            ZoneRevision::new(1),
            &provider_ref,
            ControllerGeneration::new(1).expect("controller generation"),
            None,
        );
        let execution = d2b_contracts_resource::v3::process::ExecutionSpec::minimal(
            ResourceRef::parse("Guest/workload").expect("guest ref"),
            d2b_contracts_resource::v3::process::ProcessClass::Worker,
            BoundedToken::parse("guest-worker").expect("template"),
        )
        .expect("execution");

        assert_eq!(
            validate_resource_execution_target(DaemonMode::Host, &context, &execution),
            Err(GUEST_EXECUTION_UNAVAILABLE.to_owned())
        );
    }

    #[test]
    fn guest_process_providers_reject_host_execution() {
        let resource_ref = ResourceRef::parse("Process/host-worker").expect("resource ref");
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").expect("uid");
        let provider_ref = ResourceRef::parse("Provider/system-systemd").expect("provider ref");
        let context = ProcessResourceContext::new(
            ZoneId::parse("work").expect("zone"),
            &resource_ref,
            &uid,
            ResourceGeneration::new(1).expect("generation"),
            ZoneRevision::new(1),
            &provider_ref,
            ControllerGeneration::new(1).expect("controller generation"),
            None,
        );
        let execution = d2b_contracts_resource::v3::process::ExecutionSpec::minimal(
            ResourceRef::parse("Host/host-system").expect("host ref"),
            d2b_contracts_resource::v3::process::ProcessClass::Worker,
            BoundedToken::parse("host-worker").expect("template"),
        )
        .expect("execution");

        assert_eq!(
            validate_resource_execution_target(DaemonMode::Guest, &context, &execution),
            Err("provider-ticket:host-execution-denied".to_owned())
        );
    }

    #[test]
    fn production_composition_registers_only_fixed_process_providers() {
        assert_eq!(
            ProductionProcessProviders::provider_names(),
            &["system-minijail", "system-systemd"]
        );
    }

    #[test]
    fn managed_resource_finalization_requires_the_current_resource_identity() {
        let resource_ref = ResourceRef::parse("Process/worker").expect("resource ref");
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").expect("uid");
        let zone_uid =
            ResourceUid::parse("223e4567-e89b-42d3-a456-426614174001").expect("zone uid");
        let provider_ref = ResourceRef::parse("Provider/system-minijail").expect("provider ref");
        let managed = ManagedResource {
            zone: ZoneId::parse("work").expect("zone"),
            zone_uid: Some(zone_uid.clone()),
            resource_ref: resource_ref.clone(),
            provider: ManagedProvider::Minijail,
            provider_ref: provider_ref.clone(),
            provider_uid: None,
            provider_generation: None,
            owner_ref: None,
            owner_uid: None,
            template: BoundedToken::parse("reaction").expect("template"),
            identity: ProcessIdentityDigest::from_bytes([7; 32]),
            uid: uid.clone(),
            generation: ResourceGeneration::new(4).expect("generation"),
            controller_generation: ControllerGeneration::new(1).expect("controller generation"),
            execution_ref: ResourceRef::parse("Host/host-system").expect("execution ref"),
            target_ref: None,
            runtime_scope: None,
        };
        let context = ProcessResourceContext::new(
            ZoneId::parse("work").expect("zone"),
            &resource_ref,
            &uid,
            ResourceGeneration::new(4).expect("generation"),
            ZoneRevision::new(4),
            &provider_ref,
            ControllerGeneration::new(1).expect("controller generation"),
            None,
        )
        .with_lifecycle_identity(Some(zone_uid.clone()), Some(1), None);
        assert!(resource_identity_matches(&managed, &context));
        let stale_context = ProcessResourceContext::new(
            ZoneId::parse("work").expect("zone"),
            &resource_ref,
            &uid,
            ResourceGeneration::new(3).expect("generation"),
            ZoneRevision::new(3),
            &provider_ref,
            ControllerGeneration::new(1).expect("controller generation"),
            None,
        )
        .with_lifecycle_identity(Some(zone_uid.clone()), Some(1), None);
        assert!(!resource_identity_matches(&managed, &stale_context));
        assert_eq!(
            resource_identity_mismatches(&managed, &stale_context),
            ["resource_generation(managed=4,requested=3)"]
        );
        let newer_revision = ProcessResourceContext::new(
            ZoneId::parse("work").expect("zone"),
            &resource_ref,
            &uid,
            ResourceGeneration::new(4).expect("generation"),
            ZoneRevision::new(5),
            &provider_ref,
            ControllerGeneration::new(1).expect("controller generation"),
            None,
        )
        .with_lifecycle_identity(Some(zone_uid.clone()), Some(1), None);
        assert!(resource_identity_matches(&managed, &newer_revision));
        let stale_controller = ProcessResourceContext::new(
            ZoneId::parse("work").expect("zone"),
            &resource_ref,
            &uid,
            ResourceGeneration::new(4).expect("generation"),
            ZoneRevision::new(4),
            &provider_ref,
            ControllerGeneration::new(2).expect("controller generation"),
            None,
        )
        .with_lifecycle_identity(Some(zone_uid.clone()), Some(1), None);
        assert!(!resource_identity_matches(&managed, &stale_controller));
        assert_eq!(
            resource_identity_mismatches(&managed, &stale_controller),
            ["controller_generation(managed=1,requested=2)"]
        );
        let different_zone = ProcessResourceContext::new(
            ZoneId::parse("work").expect("zone"),
            &resource_ref,
            &uid,
            ResourceGeneration::new(4).expect("generation"),
            ZoneRevision::new(4),
            &provider_ref,
            ControllerGeneration::new(1).expect("controller generation"),
            None,
        )
        .with_lifecycle_identity(
            Some(ResourceUid::parse("323e4567-e89b-42d3-a456-426614174002").expect("zone uid")),
            Some(1),
            None,
        );
        assert!(!resource_identity_matches(&managed, &different_zone));
        assert_eq!(
            resource_identity_mismatches(&managed, &different_zone),
            [format!(
                "zone_uid(managed={},requested={})",
                zone_uid.to_canonical_string(),
                "323e4567-e89b-42d3-a456-426614174002"
            )]
        );
    }

    #[test]
    fn drain_retry_policy_distinguishes_transient_and_permanent_failures() {
        assert!(retryable_stop_error("stop-failed"));
        assert!(retryable_stop_error("process-fate-unknown"));
        assert!(!retryable_stop_error("identity-mismatch"));
        assert!(!retryable_stop_error("permission-denied"));
    }

    #[test]
    fn controller_launch_ticket_binds_target_descriptor_and_session_without_assignment() {
        let resource = controller_resource();
        let readiness = ConfigurationDigest::from_bytes([7; 32]);
        let ticket = controller_launch_ticket(
            "test-bundle",
            &resource,
            ResourceUid::parse("223e4567-e89b-42d3-a456-426614174001").unwrap(),
            ManagedProvider::Systemd,
            readiness,
            Duration::from_secs(5),
        )
        .expect("controller ticket");
        assert!(ticket.validate_controller_launch().is_ok());
        assert_eq!(ticket.process_ref(), resource.process_ref());
        assert_eq!(ticket.execution_ref(), resource.target());
        assert_eq!(
            ticket.provider_generation(),
            Some(resource.provider_generation())
        );
        assert_eq!(
            ticket.target_session_generation(),
            Some(resource.target_session_generation())
        );
        assert_eq!(
            ticket.resource_revision(),
            Some(resource.resource_revision())
        );
        assert!(ticket.signed_descriptor_digest().is_some());
        assert!(!ticket.has_assignment_binding());
        assert!(ticket.resource_client_binding().is_none());
        assert!(ticket.execution_commitment().is_some());
        assert!(ticket.runtime_scope().is_some());
    }

    #[test]
    fn static_controller_resource_ticket_resolves_private_intent_and_one_fd() {
        let zone = ZoneId::parse("dev").expect("zone");
        let owner = ResourceRef::parse("Provider/runtime-cloud-hypervisor").expect("owner");
        let provider = ResourceRef::parse("Provider/system-minijail").expect("provider");
        let target = ResourceRef::parse("Host/dev-host").expect("target");
        let process_ref = ResourceRef::parse("Process/controller-test").expect("process ref");
        let template = BoundedToken::parse("controller-test").expect("template");
        let execution = d2b_contracts_resource::v3::process::ExecutionSpec::new(
            target.clone(),
            Some(ExecutionDomain::System),
            None,
            ProcessClass::Controller,
            template.clone(),
            None,
            Vec::new(),
            Vec::new(),
            d2b_contracts_resource::v3::process::SandboxSpec::default(),
            d2b_contracts_resource::v3::execution_policy::BudgetSpec::default(),
            None,
            Vec::new(),
            d2b_contracts_resource::v3::process::TelemetrySpec::default(),
        )
        .expect("execution");
        let process = BundleResource::new(
            ResourceTypeName::parse("Process").expect("process type"),
            BundleResourceMetadata::new(
                ResourceName::parse("controller-test").expect("process name"),
                zone.clone(),
                Some(owner.clone()),
                BTreeMap::new(),
                BTreeMap::new(),
            ),
            CanonicalJsonObject::parse(
                br#"{"domain":"system","executionRef":"Host/dev-host","processClass":"controller","providerRef":"Provider/system-minijail","template":"controller-test"}"#,
            )
            .expect("process spec"),
        )
        .expect("process resource");
        let provider_resource = BundleResource::new(
            ResourceTypeName::parse("Provider").expect("provider type"),
            BundleResourceMetadata::new(
                ResourceName::parse("runtime-cloud-hypervisor").expect("provider name"),
                zone.clone(),
                None,
                BTreeMap::new(),
                BTreeMap::new(),
            ),
            CanonicalJsonObject::parse(
                br#"{"artifactId":"runtime-cloud-hypervisor","config":{"controllerExecutionRef":"Host/dev-host"}}"#,
            )
            .expect("provider spec"),
        )
        .expect("provider resource");
        let resource_bundle = ResourceBundle::new(
            zone.clone(),
            vec![process, provider_resource],
            format!("sha256:{}", "b".repeat(64)),
            BTreeMap::new(),
            BTreeMap::new(),
            Timestamp::parse("1970-01-01T00:00:00.000Z").expect("timestamp"),
        )
        .expect("resource bundle")
        .with_process_templates(vec![
            d2b_contracts_zone_session::v3::resource_bundle::ProcessTemplateBinding::new(
                process_ref.clone(),
                owner.clone(),
                target.clone(),
                template.clone(),
                d2b_contracts_resource::v3::ArtifactId::parse("runtime-cloud-hypervisor")
                    .expect("artifact"),
                d2b_contracts_provider::v3::BinaryRef::parse("d2b-cloud-hypervisor-controller")
                    .expect("binary"),
                d2b_contracts_provider::v3::ArtifactDigest::parse(format!(
                    "sha256:{}",
                    "a".repeat(64)
                ))
                .expect("digest"),
                "/nix/store/runtime-cloud-hypervisor/bin/d2b-cloud-hypervisor-controller",
            )
            .expect("template binding"),
        ])
        .expect("process templates");
        let host = serde_json::from_str::<d2b_core::host::HostJson>(include_str!(
            "../../../tests/fixtures/deny-unknown/host-valid.json"
        ))
        .expect("host fixture");
        let manifest = d2b_core::manifest_v04::ManifestV04::from_slice(
            include_str!("../../../tests/golden/manifest_v04/baseline-vms.json").as_bytes(),
        )
        .expect("manifest fixture");
        let resolver = BundleResolver::from_artifacts_with_zone_resource_bundles(
            Bundle {
                bundle_version: 11,
                schema_version: "v2".to_owned(),
                public_manifest_path: "vms.json".to_owned(),
                host_path: "host.json".to_owned(),
                processes_path: "processes.json".to_owned(),
                privileges_path: "privileges.json".to_owned(),
                storage_path: None,
                sync_path: None,
                allocator_path: None,
                realm_controllers_path: None,
                realm_identity_path: None,
                realm_workloads_launcher_v2_path: None,
                unsafe_local_workloads_path: None,
                closures: Vec::new(),
                minijail_profiles: Vec::new(),
                managed_keys: Default::default(),
                generation: BundleGeneration {
                    generator: "test".to_owned(),
                    source_revision: None,
                    generated_at: None,
                },
                bundle_hash: Some("sha256:bundle".to_owned()),
                artifact_hashes: None,
            },
            host,
            ProcessesJson {
                schema_version: "v2".to_owned(),
                vms: Vec::new(),
            },
            manifest,
            BTreeMap::from([(
                "dev".to_owned(),
                serde_json::to_vec(&resource_bundle).expect("resource bundle bytes"),
            )]),
        );
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").expect("uid");
        let context = ProcessResourceContext::new(
            zone,
            &process_ref,
            &uid,
            ResourceGeneration::new(1).expect("generation"),
            ZoneRevision::new(1),
            &provider,
            ControllerGeneration::new(1).expect("controller generation"),
            None,
        )
        .with_owner_ref(Some(owner.clone()))
        .with_lifecycle_identity(
            Some(ResourceUid::parse("223e4567-e89b-42d3-a456-426614174001").expect("zone uid")),
            Some(1),
            None,
        );
        let ticket = resource_ticket(
            &resolver,
            &context,
            &execution,
            None,
            b"process-spec",
            ManagedProvider::Minijail,
            DaemonMode::Host,
            Duration::from_secs(5),
            Some(ReadinessClass::ReadyCondition),
        )
        .expect("static controller ticket");
        assert_eq!(ticket.inherited_fd_table().count(), 1);
        assert_eq!(ticket.process_ref(), &process_ref);
        assert_eq!(ticket.template(), &template);
        assert!(ticket.zone_uid().is_some());
        assert_eq!(ticket.owner_ref(), Some(&owner));
        assert!(ticket.runtime_scope().is_some());
        let wrong_owner = ResourceRef::parse("Provider/wrong-owner").expect("wrong owner");
        let wrong_owner_context = context.clone().with_owner_ref(Some(wrong_owner));
        assert_eq!(
            resource_ticket(
                &resolver,
                &wrong_owner_context,
                &execution,
                None,
                b"process-spec",
                ManagedProvider::Minijail,
                DaemonMode::Host,
                Duration::from_secs(5),
                Some(ReadinessClass::ReadyCondition),
            ),
            Err("provider-ticket:template-not-found".to_owned())
        );
    }
}
