//! Privileged-broker process backend using the production broker wire.

use std::collections::BTreeMap;
use std::fs;
use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use d2b_contracts::types::{BundleOpId, RoleId, VmId};
use d2b_contracts_broker::broker_wire::{
    AuditJoinContext, BrokerCallerRole, BrokerProfile, BrokerRequest, BrokerRequestEnvelope,
    BrokerResponse, CanonicalAuditDigest, DeregisterRunnerPidfdRequest,
    GuestExecutionBinding as BrokerGuestExecutionBinding, ObserveRunnerRequest, OpenPidfdRequest,
    RunnerRole, RunnerSignal, SandboxLaunchPlan, SignalRunnerRequest, SpawnRunnerRequest,
};
use d2b_contracts_resource::v3::{ActivationRunnerInput, execution_policy::ExecutionDomain};
use d2b_contracts_resource::v3::{ResourceRef, ResourceUid};
use d2b_core::bundle_resolver::{BundleResolver, intent_id_legacy_runner};
use d2b_core::processes::ProcessRole;
use d2b_process::{
    BackendLaunch, BackendObservation, IdentityBinding, ObservedIdentity, ProcessEffectBackend,
    ProcessEffectError, ProcessIdentityDigest, ProcessLaunchRequest, ProcessRequest,
    ProcessStopClass, WaitReapOwner,
};
use d2b_process_conformance::runtime_scope_commitment;
use rustix::event::{PollFd, PollFlags, poll};
use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, SocketFlags, SocketType, recvmsg, send, sendmsg, socket_with,
};
use sha2::{Digest, Sha256};
use socket2::Socket;

const MAX_PENDING_OBSERVATIONS: usize = 1024;

/// Trusted-bundle launch intent resolved for one generic Process ticket.
#[derive(Clone, PartialEq, Eq)]
pub struct BrokerLaunchIntent {
    /// Broker VM scope.
    pub vm_id: VmId,
    /// Immutable Zone identity for a typed Process resource.
    pub zone_uid: Option<ResourceUid>,
    /// Exact semantic owner of a typed Process resource, when present.
    pub owner_ref: Option<ResourceRef>,
    /// Immutable UID of the semantic owner.
    pub owner_uid: Option<ResourceUid>,
    /// Selected Process Provider reference.
    pub provider_ref: ResourceRef,
    /// Private host-runtime scope commitment.
    pub runtime_scope: Option<[u8; 32]>,
    /// Whether this request is the generic Resource-backed Process path.
    pub typed_identity: bool,
    /// Canonical Host or Guest execution target.
    pub execution_ref: ResourceRef,
    /// Canonical execution domain.
    pub domain: ExecutionDomain,
    /// Canonical User identity for a user-domain launch.
    pub user_ref: Option<ResourceRef>,
    /// Broker role scope.
    pub role_id: RoleId,
    /// Existing closed broker runner role selecting its trusted argv compiler.
    pub role: RunnerRole,
    /// Opaque runner-intent row in the trusted broker bundle.
    pub bundle_runner_intent_ref: BundleOpId,
    /// Digest of the owning Provider identity resolved from trusted config.
    pub provider_identity: [u8; 32],
    /// Digest of the owning component template resolved from trusted config.
    pub template_identity: [u8; 32],
    /// Nonzero Process resource generation bound to this launch.
    pub generation: u64,
    /// Exact generic Process identity carried through broker lifecycle calls.
    pub resource_ref: ResourceRef,
    /// Immutable resource UID used to separate same-name generations.
    pub resource_uid: d2b_contracts_resource::v3::ResourceUid,
    /// Content identity of the trusted bundle snapshot.
    pub bundle_content_identity: String,
    /// Complete semantic sandbox plan for generic Process launches.
    pub sandbox_plan: Option<SandboxLaunchPlan>,
    /// Typed stdin input for the activation-nixos runner, when applicable.
    pub activation_input: Option<ActivationRunnerInput>,
    /// Exact authenticated binding for a Guest-local Process.
    pub guest_execution: Option<BrokerGuestExecutionBinding>,
}

impl std::fmt::Debug for BrokerLaunchIntent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BrokerLaunchIntent(<redacted>)")
    }
}

impl BrokerLaunchIntent {
    fn wire_resource_ref(&self) -> Option<ResourceRef> {
        self.typed_identity.then(|| self.resource_ref.clone())
    }

    fn wire_resource_uid(&self) -> Option<ResourceUid> {
        self.typed_identity.then(|| self.resource_uid.clone())
    }

    fn wire_zone_uid(&self) -> Option<ResourceUid> {
        self.typed_identity.then(|| self.zone_uid.clone()).flatten()
    }

    fn wire_owner_ref(&self) -> Option<ResourceRef> {
        self.typed_identity
            .then(|| self.owner_ref.clone())
            .flatten()
    }

    fn wire_provider_ref(&self) -> Option<ResourceRef> {
        self.typed_identity.then(|| self.provider_ref.clone())
    }

    fn wire_provider_identity(&self) -> Option<[u8; 32]> {
        self.typed_identity.then_some(self.provider_identity)
    }

    fn wire_template_identity(&self) -> Option<[u8; 32]> {
        self.typed_identity.then_some(self.template_identity)
    }

    fn wire_generation(&self) -> Option<u64> {
        self.typed_identity.then_some(self.generation)
    }

    fn wire_runtime_scope(&self) -> Option<[u8; 32]> {
        self.typed_identity.then(|| self.runtime_scope).flatten()
    }
}

/// Candidate discovered independently of the adapter's in-memory handle table.
#[derive(Clone, PartialEq, Eq)]
pub struct BrokerObservedProcess {
    /// Trusted launch intent identifying the broker-managed runner.
    pub intent: BrokerLaunchIntent,
    /// Observed process identifier used only inside the broker boundary.
    pub pid: i32,
    /// Observed process-start-time ticks used to reject identifier reuse.
    pub start_time_ticks: u64,
    /// Whether trusted observation also verified the declared cgroup leaf.
    pub cgroup_verified: bool,
    /// Whether trusted observation verified the executable behind the runner.
    pub executable_verified: bool,
}

impl std::fmt::Debug for BrokerObservedProcess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BrokerObservedProcess(<redacted>)")
    }
}

impl BrokerObservedProcess {
    fn validate(&self) -> Result<(), ProcessEffectError> {
        let mut provider_digest = Sha256::new();
        provider_digest.update(b"d2b-process-provider-v1");
        provider_digest.update(self.intent.provider_ref.name().as_str().as_bytes());
        let provider_identity: [u8; 32] = provider_digest.finalize().into();
        if self.pid <= 0
            || self.start_time_ticks == 0
            || self.intent.provider_identity == [0; 32]
            || self.intent.template_identity == [0; 32]
            || self.intent.generation == 0
            || self.intent.zone_uid.is_some() != self.intent.runtime_scope.is_some()
            || self
                .intent
                .runtime_scope
                .is_some_and(|scope| scope == [0; 32])
            || (self.intent.typed_identity
                && (self.intent.zone_uid.is_none() || self.intent.runtime_scope.is_none()))
            || self.intent.provider_ref.resource_type().as_str() != "Provider"
            || !matches!(
                self.intent.provider_ref.name().as_str(),
                "system-minijail" | "system-systemd"
            )
            || (self.intent.typed_identity && self.intent.provider_identity != provider_identity)
            || self
                .intent
                .guest_execution
                .as_ref()
                .is_some_and(|binding| !binding.is_valid())
        {
            return Err(ProcessEffectError::IdentityChanged);
        }
        Ok(())
    }

    fn validate_launch(&self) -> Result<(), ProcessEffectError> {
        self.validate()?;
        if !self.cgroup_verified || !self.executable_verified {
            return Err(ProcessEffectError::IdentityChanged);
        }
        Ok(())
    }

    fn digest(&self) -> ProcessIdentityDigest {
        let mut digest = Sha256::new();
        digest.update(b"d2b-broker-process-identity-v1");
        digest.update(self.intent.vm_id.as_str().as_bytes());
        digest.update([0]);
        if let Some(zone_uid) = &self.intent.zone_uid {
            digest.update(zone_uid.as_str().as_bytes());
        }
        digest.update([0]);
        if let Some(owner_ref) = &self.intent.owner_ref {
            digest.update(owner_ref.to_canonical_string().as_bytes());
        }
        digest.update([0]);
        digest.update(self.intent.provider_ref.to_canonical_string().as_bytes());
        digest.update([0]);
        digest.update(self.intent.resource_ref.to_canonical_string().as_bytes());
        digest.update([0]);
        digest.update(self.intent.resource_uid.as_str().as_bytes());
        digest.update([0]);
        digest.update(self.intent.role_id.as_str().as_bytes());
        digest.update([0]);
        digest.update(self.intent.role.as_str().as_bytes());
        digest.update(self.intent.provider_identity);
        digest.update(self.intent.template_identity);
        digest.update(self.intent.generation.to_le_bytes());
        if let Some(runtime_scope) = self.intent.runtime_scope {
            digest.update(runtime_scope);
        }
        digest.update([0]);
        if let Some(binding) = &self.intent.guest_execution {
            digest.update(binding.target_uid.as_str().as_bytes());
            digest.update(binding.boot_identity_digest);
            digest.update(binding.session_generation.to_le_bytes());
            digest.update(binding.assignment_epoch.to_le_bytes());
            digest.update(binding.provider_generation.to_le_bytes());
            digest.update(binding.controller_generation.to_le_bytes());
        }
        digest.update(self.pid.to_le_bytes());
        digest.update(self.start_time_ticks.to_le_bytes());
        ProcessIdentityDigest::from_bytes(digest.finalize().into())
    }

    fn observation(&self) -> BackendObservation {
        let mut verified = vec![
            IdentityBinding::Pid,
            IdentityBinding::ProcessStartTime,
            IdentityBinding::Template,
            IdentityBinding::Generation,
        ];
        if self.cgroup_verified {
            verified.push(IdentityBinding::Cgroup);
        }
        if self.executable_verified {
            verified.push(IdentityBinding::Executable);
        }
        BackendObservation::new(
            self.digest(),
            ObservedIdentity::from_verified(verified),
            WaitReapOwner::Local,
        )
    }
}

/// Trusted resolver for broker launch and independent adoption observation.
///
/// Generic v3 Process tickets do not carry a legacy [`RunnerRole`]. The
/// resolver must map a ticket to an existing trusted bundle row and may return
/// `UnsupportedProvider` when no exact role disposition exists yet.
pub trait BrokerLaunchResolver: Send + Sync + 'static {
    /// Resolve a validated ticket to one trusted broker runner intent.
    fn resolve(&self, request: &ProcessRequest) -> Result<BrokerLaunchIntent, ProcessEffectError>;

    /// Discover a running candidate and verify non-pid stable bindings.
    fn observe(
        &self,
        request: &ProcessRequest,
    ) -> Result<Option<BrokerObservedProcess>, ProcessEffectError>;

    /// Probe a running candidate without staging it for pidfd adoption.
    fn probe(
        &self,
        request: &ProcessRequest,
    ) -> Result<Option<BrokerObservedProcess>, ProcessEffectError> {
        self.observe(request)
    }

    /// Record one broker-verified launch so a later reconciliation in the
    /// same daemon lifetime can adopt it through the normal observe/open-pidfd
    /// path. Implementations that have an independent discovery source may
    /// ignore this callback.
    fn record_launched(&self, _request: &ProcessRequest, _observed: &BrokerObservedProcess) {}

    /// Forget one stopped process from an in-memory discovery source.
    fn record_stopped(&self, _observed: &BrokerObservedProcess) {}
}

/// Bundle-backed resolver for generic Process tickets.
///
/// The ticket carries only canonical resource references and bounded
/// configuration identities. This resolver turns the Guest resource name and
/// Process resource name into the closed broker runner role and then looks up
/// the complete launch intent in the trusted bundle. No caller-controlled
/// executable, argv, uid, cgroup, or legacy role is accepted.
#[derive(Clone)]
pub struct BundleBackedLaunchResolver {
    bundle: BundleResolver,
    observation: Option<BrokerObservationConfig>,
}

#[derive(Clone)]
struct BrokerObservationConfig {
    socket_path: PathBuf,
    io_timeout: Duration,
    caller_role: BrokerCallerRole,
}

impl BundleBackedLaunchResolver {
    /// Build a resolver from the broker's trusted bundle copy.
    pub fn new(bundle: BundleResolver) -> Self {
        Self {
            bundle,
            observation: None,
        }
    }

    /// Enable authenticated broker-backed runner observation for adoption.
    pub fn with_observation_socket(
        mut self,
        socket_path: impl Into<PathBuf>,
        io_timeout: Duration,
        caller_role: BrokerCallerRole,
    ) -> Self {
        self.observation = Some(BrokerObservationConfig {
            socket_path: socket_path.into(),
            io_timeout,
            caller_role,
        });
        self
    }

    fn identity_digest(value: &str, domain: &[u8]) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(domain);
        digest.update(value.as_bytes());
        digest.finalize().into()
    }
}

impl std::fmt::Debug for BundleBackedLaunchResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BundleBackedLaunchResolver(<redacted>)")
    }
}

impl BrokerLaunchResolver for BundleBackedLaunchResolver {
    fn resolve(&self, request: &ProcessRequest) -> Result<BrokerLaunchIntent, ProcessEffectError> {
        self.resolve_intent(request)
    }

    fn observe(
        &self,
        request: &ProcessRequest,
    ) -> Result<Option<BrokerObservedProcess>, ProcessEffectError> {
        let Some(observation) = self.observation.as_ref() else {
            return Ok(None);
        };
        let intent = self.resolve_intent(request)?;
        let frame = broker_round_trip(
            &observation.socket_path,
            observation.io_timeout,
            BrokerRequest::ObserveRunner(ObserveRunnerRequest {
                vm_id: intent.vm_id.clone(),
                role_id: intent.role_id.clone(),
                role: intent.role,
                bundle_runner_intent_ref: intent.bundle_runner_intent_ref.clone(),
                resource_ref: intent.wire_resource_ref(),
                resource_uid: intent.wire_resource_uid(),
                zone_uid: intent.wire_zone_uid(),
                owner_ref: intent.wire_owner_ref(),
                provider_ref: intent.wire_provider_ref(),
                provider_identity: intent.wire_provider_identity(),
                template_identity: intent.wire_template_identity(),
                generation: intent.wire_generation(),
                runtime_scope: intent.wire_runtime_scope(),
                guest_execution: intent.guest_execution.clone(),
                tracing_span_id: None,
            }),
            observation.caller_role.clone(),
        )?;
        let BrokerResponse::ObserveRunner(response) = frame.response else {
            return Err(ProcessEffectError::ObserveFailed);
        };
        if response.vm_id != intent.vm_id || response.role_id != intent.role_id {
            return Err(ProcessEffectError::IdentityChanged);
        }
        if !response.present {
            return Ok(None);
        }
        Ok(Some(BrokerObservedProcess {
            intent,
            pid: response.pid,
            start_time_ticks: response.start_time_ticks,
            cgroup_verified: response.cgroup_verified,
            executable_verified: response.executable_verified,
        }))
    }
}

impl BundleBackedLaunchResolver {
    fn resolve_intent(
        &self,
        request: &ProcessRequest,
    ) -> Result<BrokerLaunchIntent, ProcessEffectError> {
        let ticket = request.ticket();
        if !matches!(
            ticket.execution_ref().resource_type().as_str(),
            "Host" | "Guest"
        ) {
            return Err(ProcessEffectError::UnsupportedProvider);
        }
        let vm_name = match (
            ticket.execution_ref().resource_type().as_str(),
            ticket.target_ref(),
        ) {
            ("Guest", None) => ticket.execution_ref().name().as_str(),
            ("Host", None) => ticket.execution_ref().name().as_str(),
            ("Host", Some(target)) if target.resource_type().as_str() == "Guest" => {
                target.name().as_str()
            }
            _ => return Err(ProcessEffectError::IdentityChanged),
        };
        let process_role_id = ticket.process_ref().name().as_str();
        let intent_id = intent_id_legacy_runner(vm_name, process_role_id);
        let expected_execution_ref = ticket.execution_ref().to_canonical_string();
        let expected_execution_domain = match ticket.domain() {
            ExecutionDomain::System => d2b_core::processes::ProcessExecutionDomain::System,
            ExecutionDomain::User => d2b_core::processes::ProcessExecutionDomain::User,
        };
        let expected_user_ref = ticket.user_ref().map(ResourceRef::to_canonical_string);
        let legacy_intent = self.bundle.find_runner_intent(&intent_id);
        let static_controller_intent = self.bundle.find_provider_controller_intent(
            ticket.process_ref(),
            &expected_execution_ref,
            expected_execution_domain,
            expected_user_ref.as_deref(),
            ticket.template().as_str(),
            None,
        );
        let generic_intent = if let Some(owner) = ticket
            .owner_ref()
            .filter(|owner| owner.resource_type().as_str() == "Guest")
            .filter(|owner| {
                ticket.process_ref().name().as_str() == format!("{}-vmm", owner.name().as_str())
            }) {
            let Some(zone_uid) = ticket.zone_uid() else {
                return Err(ProcessEffectError::IdentityChanged);
            };
            self.bundle.find_guest_vmm_intent_for_zone_uid(
                zone_uid,
                owner.name().as_str(),
                &expected_execution_ref,
                expected_execution_domain,
                ticket.template().as_str(),
            )
        } else {
            self.bundle.find_runner_intent_for_process_in_vm(
                Some(vm_name),
                &expected_execution_ref,
                expected_execution_domain,
                expected_user_ref.as_deref(),
                ticket.template().as_str(),
            )
        };
        let (intent, legacy_identity) = match ticket.component().as_str() {
            "vm-process" => (
                legacy_intent.ok_or(ProcessEffectError::UnsupportedProvider)?,
                true,
            ),
            "process-controller" => (
                static_controller_intent
                    .or(generic_intent)
                    .ok_or(ProcessEffectError::UnsupportedProvider)?,
                false,
            ),
            _ => return Err(ProcessEffectError::UnsupportedProvider),
        };
        let role = runner_role_for_process_role(&intent.role)
            .ok_or(ProcessEffectError::UnsupportedProvider)?;
        let role_id = match &intent.role {
            ProcessRole::CloudHypervisorRunner => "ch-runner",
            _ => intent.role_id.as_str(),
        };
        if intent.vm_name != vm_name || (legacy_identity && intent.role_id != process_role_id) {
            return Err(ProcessEffectError::IdentityChanged);
        }
        let typed_identity = !legacy_identity && !ticket.has_controller_launch_binding();
        if typed_identity {
            let Some(zone_uid) = ticket.zone_uid() else {
                return Err(ProcessEffectError::IdentityChanged);
            };
            let Some(runtime_scope) = ticket.runtime_scope() else {
                return Err(ProcessEffectError::IdentityChanged);
            };
            let expected_scope = runtime_scope_commitment(
                zone_uid,
                ticket
                    .guest_execution_binding()
                    .map(|binding| binding.target_uid()),
                ticket.process_ref(),
                ticket.process_uid(),
                intent.role_id.as_str(),
                ticket.resource_generation().get(),
            )
            .as_bytes();
            if runtime_scope.as_bytes() != expected_scope {
                return Err(ProcessEffectError::IdentityChanged);
            }
        }
        let inherited_fd_count = ticket.inherited_fd_table().count();
        if (role == RunnerRole::ProviderController) != (inherited_fd_count == 1) {
            return Err(ProcessEffectError::IdentityChanged);
        }
        if intent.execution_ref != expected_execution_ref {
            return Err(ProcessEffectError::IdentityChanged);
        }
        let expected_domain = match intent.execution_domain {
            d2b_core::processes::ProcessExecutionDomain::System => ExecutionDomain::System,
            d2b_core::processes::ProcessExecutionDomain::User => ExecutionDomain::User,
        };
        if ticket.domain() != expected_domain {
            return Err(ProcessEffectError::IdentityChanged);
        }
        let expected_user_ref = intent
            .user_ref
            .as_deref()
            .map(ResourceRef::parse)
            .transpose()
            .map_err(|_| ProcessEffectError::IdentityChanged)?;
        if ticket.user_ref() != expected_user_ref.as_ref() {
            return Err(ProcessEffectError::IdentityChanged);
        }
        if ticket.execution_ref().resource_type().as_str() == "Guest"
            && ticket.guest_execution_binding().is_none()
        {
            return Err(ProcessEffectError::IdentityChanged);
        }
        if ticket.execution_ref().resource_type().as_str() == "Host"
            && ticket.guest_execution_binding().is_some()
        {
            return Err(ProcessEffectError::IdentityChanged);
        }
        let guest_execution =
            ticket
                .guest_execution_binding()
                .map(|binding| BrokerGuestExecutionBinding {
                    target_uid: binding.target_uid().clone(),
                    boot_identity_digest: binding.boot_identity_digest().as_bytes(),
                    session_generation: binding.session_generation().get(),
                    assignment_epoch: binding.assignment_epoch(),
                    provider_generation: binding.provider_generation().get(),
                    controller_generation: binding.controller_generation().get(),
                });
        Ok(BrokerLaunchIntent {
            vm_id: VmId::new(vm_name),
            zone_uid: ticket.zone_uid().cloned(),
            owner_ref: ticket.owner_ref().cloned(),
            owner_uid: ticket.owner_uid().cloned(),
            provider_ref: ticket.provider_ref().clone(),
            runtime_scope: ticket.runtime_scope().map(|scope| scope.as_bytes()),
            typed_identity,
            execution_ref: ticket.execution_ref().clone(),
            domain: ticket.domain(),
            user_ref: ticket.user_ref().cloned(),
            role_id: RoleId::new(role_id),
            role,
            bundle_runner_intent_ref: BundleOpId::new(intent.intent_id.clone()),
            provider_identity: Self::identity_digest(
                ticket.owner_provider().as_str(),
                b"d2b-process-provider-v1",
            ),
            template_identity: Self::identity_digest(
                ticket.template().as_str(),
                b"d2b-process-template-v1",
            ),
            generation: ticket.resource_generation().get(),
            resource_ref: ticket.process_ref().clone(),
            resource_uid: ticket.process_uid().clone(),
            bundle_content_identity: self
                .bundle
                .bundle
                .bundle_hash
                .clone()
                .ok_or(ProcessEffectError::IdentityChanged)?,
            activation_input: ticket.activation_input().cloned(),
            guest_execution,
            sandbox_plan: ticket.sandbox_plan().map(|plan| {
                let spec = plan.spec();
                SandboxLaunchPlan {
                    digest: plan.compiled().digest().to_hex(),
                    domain: ticket.domain(),
                    namespace_classes: spec.namespace_classes().to_vec(),
                    capability_classes: spec.capability_classes().to_vec(),
                    seccomp_class: spec.seccomp_class().clone(),
                    no_new_privileges: spec.no_new_privileges(),
                    start_root: spec.start_root(),
                    environment_class: spec.environment_class(),
                    read_only_root: spec.read_only_root(),
                    umask: spec.umask().map(str::to_owned),
                    oom_score_adj: spec.oom_score_adj(),
                    user_namespace: spec.user_namespace().copied(),
                }
            }),
        })
    }
}

/// Map the open Process role vocabulary to the broker's closed runner role.
pub fn runner_role_for_process_role(role: &ProcessRole) -> Option<RunnerRole> {
    match role {
        ProcessRole::ProviderController => Some(RunnerRole::ProviderController),
        ProcessRole::CloudHypervisorRunner => Some(RunnerRole::CloudHypervisor),
        ProcessRole::QemuMediaRunner => Some(RunnerRole::QemuMedia),
        ProcessRole::Virtiofsd => Some(RunnerRole::Virtiofsd),
        ProcessRole::Swtpm => Some(RunnerRole::Swtpm),
        ProcessRole::SwtpmPreStartFlush => Some(RunnerRole::SwtpmFlush),
        ProcessRole::Gpu | ProcessRole::GpuRenderNode => Some(RunnerRole::Gpu),
        ProcessRole::Audio => Some(RunnerRole::Audio),
        ProcessRole::Video => Some(RunnerRole::Video),
        ProcessRole::VsockRelay => Some(RunnerRole::VsockRelay),
        ProcessRole::Usbip => Some(RunnerRole::Usbip),
        ProcessRole::OtelHostBridge => Some(RunnerRole::OtelHostBridge),
        ProcessRole::WaylandProxy => Some(RunnerRole::WaylandProxy),
        ProcessRole::ActivationNixosRunner => Some(RunnerRole::ActivationNixos),
        ProcessRole::HostReconcile
        | ProcessRole::StoreVirtiofsPreflight
        | ProcessRole::ComponentSessionHealth
        | ProcessRole::SecurityKeyFrontend => None,
    }
}

/// Core-local pidfd plus the identity tuple the broker verified.
pub struct BrokerPidfdHandle {
    pidfd: OwnedFd,
    observed: BrokerObservedProcess,
    controller_bootstrap: Mutex<Option<OwnedFd>>,
}

impl std::fmt::Debug for BrokerPidfdHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BrokerPidfdHandle(<redacted>)")
    }
}

/// Production process backend for existing broker-managed runner roles.
///
/// It sends the repository's production `SpawnRunner`, `OpenPidfd`, and
/// `SignalRunner` wire requests. The broker performs trusted bundle resolution,
/// user-namespace pre-establishment, final cgroup placement, and audited spawn.
/// The pidfd returned via `SCM_RIGHTS` is retained inside this backend.
pub struct BrokerProcessBackend<R: BrokerLaunchResolver> {
    resolver: R,
    socket_path: PathBuf,
    io_timeout: Duration,
    profile: BrokerProfile,
    caller_role: BrokerCallerRole,
    observations: Mutex<BTreeMap<ProcessIdentityDigest, BrokerObservedProcess>>,
}

impl<R: BrokerLaunchResolver> BrokerProcessBackend<R> {
    /// Build a backend using the production broker socket path.
    pub fn new(resolver: R) -> Self {
        Self::with_socket_profile_and_role(
            resolver,
            d2b_contracts::BROKER_SOCKET_PATH,
            Duration::from_secs(10),
            BrokerProfile::Host,
            BrokerCallerRole::NotAuthorized,
        )
    }

    /// Build a backend with an explicit socket path and I/O timeout.
    pub fn with_socket(resolver: R, socket_path: impl Into<PathBuf>, io_timeout: Duration) -> Self {
        Self::with_socket_profile_and_role(
            resolver,
            socket_path,
            io_timeout,
            BrokerProfile::Host,
            BrokerCallerRole::NotAuthorized,
        )
    }

    /// Build a backend bound to one fixed broker profile and caller identity.
    pub fn with_socket_profile_and_role(
        resolver: R,
        socket_path: impl Into<PathBuf>,
        io_timeout: Duration,
        profile: BrokerProfile,
        caller_role: BrokerCallerRole,
    ) -> Self {
        Self {
            resolver,
            socket_path: socket_path.into(),
            io_timeout,
            profile,
            caller_role,
            observations: Mutex::new(BTreeMap::new()),
        }
    }

    /// Build a backend with an authenticated broker caller role.
    pub fn with_socket_and_role(
        resolver: R,
        socket_path: impl Into<PathBuf>,
        io_timeout: Duration,
        caller_role: BrokerCallerRole,
    ) -> Self {
        Self::with_socket_profile_and_role(
            resolver,
            socket_path,
            io_timeout,
            BrokerProfile::Host,
            caller_role,
        )
    }

    fn request(&self, request: BrokerRequest) -> Result<BrokerFrame, ProcessEffectError> {
        self.request_with_fds(request, &[])
    }

    fn request_with_fds(
        &self,
        request: BrokerRequest,
        inherited_fds: &[OwnedFd],
    ) -> Result<BrokerFrame, ProcessEffectError> {
        if matches!(self.caller_role, BrokerCallerRole::NotAuthorized)
            || !request.allowed_by_profile(self.profile)
        {
            return Err(ProcessEffectError::LaunchFailed);
        }
        broker_round_trip_with_fds(
            &self.socket_path,
            self.io_timeout,
            request,
            self.caller_role.clone(),
            inherited_fds,
        )
    }

    fn record(&self, observed: BrokerObservedProcess) -> Result<(), ProcessEffectError> {
        let mut observations = self
            .observations
            .lock()
            .map_err(|_| ProcessEffectError::ObserveFailed)?;
        let identity = observed.digest();
        if observations.len() >= MAX_PENDING_OBSERVATIONS
            && !observations.contains_key(&identity)
            && let Some(candidate) = observations.keys().next().copied()
        {
            observations.remove(&candidate);
        }
        observations.insert(identity, observed);
        Ok(())
    }

    fn take_observation(
        &self,
        identity: &ProcessIdentityDigest,
    ) -> Result<BrokerObservedProcess, ProcessEffectError> {
        self.observations
            .lock()
            .map_err(|_| ProcessEffectError::ObserveFailed)?
            .remove(identity)
            .ok_or(ProcessEffectError::IdentityChanged)
    }

    pub(crate) fn matches_peer_process(
        &self,
        handle: &BrokerPidfdHandle,
        peer_pid: i32,
    ) -> Result<bool, ProcessEffectError> {
        if peer_pid <= 0 || handle.observed.pid != peer_pid {
            return Ok(false);
        }
        if read_pidfd_process_id(&handle.pidfd)? != Some(peer_pid) {
            return Ok(false);
        }
        Ok(read_proc_start_time(peer_pid)? == Some(handle.observed.start_time_ticks))
    }
}

impl<R: BrokerLaunchResolver> std::fmt::Debug for BrokerProcessBackend<R> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BrokerProcessBackend(<redacted>)")
    }
}

impl<R: BrokerLaunchResolver> ProcessEffectBackend for BrokerProcessBackend<R> {
    type Handle = BrokerPidfdHandle;

    fn launch(
        &self,
        request: ProcessRequest,
    ) -> Result<BackendLaunch<Self::Handle>, ProcessEffectError> {
        let request =
            ProcessLaunchRequest::empty(request).map_err(|_| ProcessEffectError::LaunchFailed)?;
        self.launch_with_inherited_fds(request)
    }

    fn launch_with_inherited_fds(
        &self,
        request: ProcessLaunchRequest,
    ) -> Result<BackendLaunch<Self::Handle>, ProcessEffectError> {
        let (request, inherited_fds) = request.into_parts();
        let intent = self.resolver.resolve(&request)?;
        let inherited_fd_count = request.ticket().inherited_fd_table().count();
        let frame = self.request_with_fds(
            BrokerRequest::SpawnRunner(SpawnRunnerRequest {
                execution_ref: Some(intent.execution_ref.clone()),
                execution_domain: Some(intent.domain),
                user_ref: intent.user_ref.clone(),
                vm_id: intent.vm_id.clone(),
                role_id: intent.role_id.clone(),
                zone_uid: intent.wire_zone_uid(),
                owner_ref: intent.wire_owner_ref(),
                owner_uid: intent.owner_uid.clone(),
                provider_ref: intent.wire_provider_ref(),
                resource_ref: intent.wire_resource_ref(),
                resource_uid: intent.wire_resource_uid(),
                bundle_content_identity: Some(intent.bundle_content_identity.clone()),
                provider_identity: intent.wire_provider_identity(),
                template_identity: intent.wire_template_identity(),
                generation: intent.wire_generation(),
                runtime_scope: intent.wire_runtime_scope(),
                guest_execution: intent.guest_execution.clone(),
                sandbox_plan: intent.sandbox_plan.clone(),
                activation_input: intent.activation_input.clone(),
                role: intent.role,
                bundle_runner_intent_ref: intent.bundle_runner_intent_ref.clone(),
                runtime_allocations: Vec::new(),
                tracing_span_id: None,
                workload_identity: None,
                inherited_fd_count,
                network_tap_context: None,
            }),
            &inherited_fds,
        )?;
        let BrokerResponse::SpawnRunner(ref response) = frame.response else {
            return Err(response_error(&frame.response, BrokerOperation::Other));
        };
        if response.vm_id != intent.vm_id
            || response.role_id != intent.role_id
            || response.role != intent.role
            || response.resource_ref != intent.wire_resource_ref()
            || response.resource_uid != intent.wire_resource_uid()
            || response.zone_uid != intent.wire_zone_uid()
            || response.owner_ref != intent.wire_owner_ref()
            || response.runtime_scope != intent.wire_runtime_scope()
            || response.pid <= 0
            || response.start_time_ticks == 0
            || response.execution_ref.as_ref() != Some(&intent.execution_ref)
            || response.execution_domain != Some(intent.domain)
            || response.user_ref.as_ref() != intent.user_ref.as_ref()
            || response.provider_identity != intent.wire_provider_identity()
            || response.template_identity != intent.wire_template_identity()
            || response.generation != intent.wire_generation()
            || response.guest_execution != intent.guest_execution
            || response.bundle_content_identity.as_deref()
                != Some(intent.bundle_content_identity.as_str())
        {
            return Err(ProcessEffectError::IdentityChanged);
        }
        let pidfd = frame.take_fd(response.pidfd_index)?;
        let controller_bootstrap = response
            .controller_bootstrap_fd_index
            .map(|index| frame.take_fd(index))
            .transpose()?;
        if read_proc_start_time(response.pid)? != Some(response.start_time_ticks) {
            return Err(ProcessEffectError::IdentityChanged);
        }
        let observed = BrokerObservedProcess {
            intent,
            pid: response.pid,
            start_time_ticks: response.start_time_ticks,
            cgroup_verified: true,
            executable_verified: true,
        };
        observed.validate_launch()?;
        self.resolver.record_launched(&request, &observed);
        let observation = observed.observation();
        Ok(BackendLaunch::new(
            observation,
            BrokerPidfdHandle {
                pidfd,
                observed,
                controller_bootstrap: Mutex::new(controller_bootstrap),
            },
        ))
    }

    fn observe(
        &self,
        request: ProcessRequest,
    ) -> Result<Option<BackendObservation>, ProcessEffectError> {
        let Some(observed) = self.resolver.observe(&request)? else {
            return Ok(None);
        };
        observed.validate()?;
        let observation = observed.observation();
        if observed.cgroup_verified {
            self.record(observed)?;
        }
        Ok(Some(observation))
    }

    fn probe(
        &self,
        request: ProcessRequest,
    ) -> Result<Option<BackendObservation>, ProcessEffectError> {
        let Some(observed) = self.resolver.probe(&request)? else {
            return Ok(None);
        };
        observed.validate()?;
        Ok(Some(observed.observation()))
    }

    fn open_pidfd(
        &self,
        observation: BackendObservation,
    ) -> Result<Self::Handle, ProcessEffectError> {
        let observed = self.take_observation(&observation.identity())?;
        let frame = self.request(BrokerRequest::OpenPidfd(OpenPidfdRequest {
            vm_id: observed.intent.vm_id.clone(),
            role_id: observed.intent.role_id.clone(),
            bundle_runner_intent_ref: Some(observed.intent.bundle_runner_intent_ref.clone()),
            resource_ref: observed.intent.wire_resource_ref(),
            resource_uid: observed.intent.wire_resource_uid(),
            zone_uid: observed.intent.wire_zone_uid(),
            owner_ref: observed.intent.wire_owner_ref(),
            provider_ref: observed.intent.wire_provider_ref(),
            provider_identity: observed.intent.wire_provider_identity(),
            template_identity: observed.intent.wire_template_identity(),
            generation: observed.intent.wire_generation(),
            runtime_scope: observed.intent.wire_runtime_scope(),
            guest_execution: observed.intent.guest_execution.clone(),
            pid: observed.pid,
            expected_start_time_ticks: observed.start_time_ticks,
            tracing_span_id: None,
        }))?;
        let BrokerResponse::OpenPidfd(ref response) = frame.response else {
            return Err(response_error(
                &frame.response,
                BrokerOperation::OpenPidfd(&observed),
            ));
        };
        if response.vm_id != observed.intent.vm_id
            || response.role_id != observed.intent.role_id
            || response.pid != observed.pid
            || response.verified_start_time_ticks != observed.start_time_ticks
        {
            return Err(ProcessEffectError::IdentityChanged);
        }
        let pidfd = frame.take_fd(response.pidfd_index)?;
        let controller_bootstrap = response
            .controller_bootstrap_fd_index
            .map(|index| frame.take_fd(index))
            .transpose()?;
        if read_proc_start_time(response.pid)? != Some(response.verified_start_time_ticks) {
            return Err(ProcessEffectError::IdentityChanged);
        }
        Ok(BrokerPidfdHandle {
            pidfd,
            observed,
            controller_bootstrap: Mutex::new(controller_bootstrap),
        })
    }

    fn wait(
        &self,
        handle: &Self::Handle,
        timeout: Duration,
    ) -> Result<(), ProcessEffectError> {
        wait_pidfd_exit(&handle.pidfd, timeout)
    }

    fn take_controller_bootstrap(
        &self,
        handle: &Self::Handle,
    ) -> Result<Option<OwnedFd>, ProcessEffectError> {
        handle
            .controller_bootstrap
            .lock()
            .map_err(|_| ProcessEffectError::PidfdUnavailable)
            .map(|mut endpoint| endpoint.take())
    }

    fn stop(
        &self,
        handle: &Self::Handle,
        class: ProcessStopClass,
    ) -> Result<(), ProcessEffectError> {
        let signal = match class {
            ProcessStopClass::Drain => RunnerSignal::Term,
            ProcessStopClass::Terminate => RunnerSignal::Kill,
        };
        let frame = self.request(BrokerRequest::SignalRunner(SignalRunnerRequest {
            vm_id: handle.observed.intent.vm_id.clone(),
            role_id: handle.observed.intent.role_id.clone(),
            resource_ref: handle.observed.intent.wire_resource_ref(),
            resource_uid: handle.observed.intent.wire_resource_uid(),
            zone_uid: handle.observed.intent.wire_zone_uid(),
            owner_ref: handle.observed.intent.wire_owner_ref(),
            provider_ref: handle.observed.intent.wire_provider_ref(),
            provider_identity: handle.observed.intent.wire_provider_identity(),
            template_identity: handle.observed.intent.wire_template_identity(),
            generation: handle.observed.intent.wire_generation(),
            runtime_scope: handle.observed.intent.wire_runtime_scope(),
            guest_execution: handle.observed.intent.guest_execution.clone(),
            signal,
            pid: Some(handle.observed.pid),
            expected_start_time_ticks: Some(handle.observed.start_time_ticks),
            tracing_span_id: None,
        }))?;
        match frame.response {
            BrokerResponse::SignalRunner(response)
                if response.signaled
                    && response.vm_id == handle.observed.intent.vm_id
                    && response.role_id == handle.observed.intent.role_id =>
            {
                let _ = handle.pidfd.as_fd();
            }
            _ => return Err(ProcessEffectError::StopFailed),
        }
        if class == ProcessStopClass::Terminate {
            wait_pidfd_exit(&handle.pidfd, self.io_timeout)?;
            let frame = self.request(BrokerRequest::DeregisterRunnerPidfd(
                DeregisterRunnerPidfdRequest {
                    vm_id: handle.observed.intent.vm_id.clone(),
                    role_id: handle.observed.intent.role_id.clone(),
                    pid: Some(handle.observed.pid),
                    expected_start_time_ticks: Some(handle.observed.start_time_ticks),
                    resource_ref: handle.observed.intent.wire_resource_ref(),
                    resource_uid: handle.observed.intent.wire_resource_uid(),
                    zone_uid: handle.observed.intent.wire_zone_uid(),
                    owner_ref: handle.observed.intent.wire_owner_ref(),
                    provider_ref: handle.observed.intent.wire_provider_ref(),
                    provider_identity: handle.observed.intent.wire_provider_identity(),
                    template_identity: handle.observed.intent.wire_template_identity(),
                    generation: handle.observed.intent.wire_generation(),
                    runtime_scope: handle.observed.intent.wire_runtime_scope(),
                    guest_execution: handle.observed.intent.guest_execution.clone(),
                    tracing_span_id: None,
                },
            ))?;
            match frame.response {
                BrokerResponse::DeregisterRunnerPidfd(response)
                    if response.vm_id == handle.observed.intent.vm_id
                        && response.role_id == handle.observed.intent.role_id => {}
                _ => return Err(ProcessEffectError::StopFailed),
            }
            self.resolver.record_stopped(&handle.observed);
        }
        Ok(())
    }

    fn finalize(&self, handle: &Self::Handle) -> Result<(), ProcessEffectError> {
        let frame = self.request(BrokerRequest::DeregisterRunnerPidfd(
            DeregisterRunnerPidfdRequest {
                vm_id: handle.observed.intent.vm_id.clone(),
                role_id: handle.observed.intent.role_id.clone(),
                pid: Some(handle.observed.pid),
                expected_start_time_ticks: Some(handle.observed.start_time_ticks),
                resource_ref: handle.observed.intent.wire_resource_ref(),
                resource_uid: handle.observed.intent.wire_resource_uid(),
                zone_uid: handle.observed.intent.wire_zone_uid(),
                owner_ref: handle.observed.intent.wire_owner_ref(),
                provider_ref: handle.observed.intent.wire_provider_ref(),
                provider_identity: handle.observed.intent.wire_provider_identity(),
                template_identity: handle.observed.intent.wire_template_identity(),
                generation: handle.observed.intent.wire_generation(),
                runtime_scope: handle.observed.intent.wire_runtime_scope(),
                guest_execution: handle.observed.intent.guest_execution.clone(),
                tracing_span_id: None,
            },
        ))?;
        match frame.response {
            BrokerResponse::DeregisterRunnerPidfd(response)
                if response.vm_id == handle.observed.intent.vm_id
                    && response.role_id == handle.observed.intent.role_id =>
            {
                Ok(())
            }
            _ => Err(ProcessEffectError::StopFailed),
        }
    }
}

pub(crate) fn wait_pidfd_exit(
    pidfd: &OwnedFd,
    timeout: Duration,
) -> Result<(), ProcessEffectError> {
    let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    let mut fds = [PollFd::new(
        pidfd,
        PollFlags::IN | PollFlags::ERR | PollFlags::HUP,
    )];
    match poll(&mut fds, timeout_ms) {
        Ok(0) | Err(_) => Err(ProcessEffectError::StopFailed),
        Ok(_) if fds[0].revents().intersects(PollFlags::IN | PollFlags::HUP) => Ok(()),
        Ok(_) => Err(ProcessEffectError::StopFailed),
    }
}

pub(crate) struct BrokerFrame {
    pub(crate) response: BrokerResponse,
    fds: Mutex<Vec<Option<OwnedFd>>>,
}

impl BrokerFrame {
    pub(crate) fn take_fd(&self, index: u32) -> Result<OwnedFd, ProcessEffectError> {
        self.fds
            .lock()
            .map_err(|_| ProcessEffectError::PidfdUnavailable)?
            .get_mut(usize::try_from(index).map_err(|_| ProcessEffectError::PidfdUnavailable)?)
            .and_then(Option::take)
            .ok_or(ProcessEffectError::PidfdUnavailable)
    }
}

#[derive(Clone, Copy)]
enum BrokerOperation<'a> {
    OpenPidfd(&'a BrokerObservedProcess),
    Other,
}

fn response_error(response: &BrokerResponse, operation: BrokerOperation<'_>) -> ProcessEffectError {
    match response {
        BrokerResponse::Error(error)
            if error.kind == "Broker.LiveHandlerFailed"
                && matches!(operation, BrokerOperation::OpenPidfd(_)) =>
        {
            let BrokerOperation::OpenPidfd(observed) = operation else {
                unreachable!("guard requires OpenPidfd")
            };
            match read_proc_start_time(observed.pid) {
                Ok(Some(start_time)) if start_time != observed.start_time_ticks => {
                    ProcessEffectError::IdentityChanged
                }
                Ok(Some(_)) => ProcessEffectError::PidfdUnavailable,
                Ok(None) => ProcessEffectError::Vanished,
                Err(error) => error,
            }
        }
        BrokerResponse::Error(error) => {
            eprintln!(
                "process-broker-response-error kind={} reason={}",
                error.kind, error.message
            );
            ProcessEffectError::LaunchFailed
        }
        _ => ProcessEffectError::LaunchFailed,
    }
}

#[cfg(test)]
// Keep focused broker tests beside the response mapping they exercise.
#[allow(clippy::items_after_test_module)]
mod tests {
    use d2b_contracts_broker::broker_wire::BrokerErrorResponse;
    use d2b_core::processes::ProcessRole;

    use super::*;

    struct Resolver;

    impl BrokerLaunchResolver for Resolver {
        fn resolve(
            &self,
            _request: &ProcessRequest,
        ) -> Result<BrokerLaunchIntent, ProcessEffectError> {
            Err(ProcessEffectError::ResolutionFailed)
        }

        fn observe(
            &self,
            _request: &ProcessRequest,
        ) -> Result<Option<BrokerObservedProcess>, ProcessEffectError> {
            Ok(None)
        }
    }

    struct ObservingResolver {
        observed: BrokerObservedProcess,
    }

    impl BrokerLaunchResolver for ObservingResolver {
        fn resolve(
            &self,
            _request: &ProcessRequest,
        ) -> Result<BrokerLaunchIntent, ProcessEffectError> {
            Ok(self.observed.intent.clone())
        }

        fn observe(
            &self,
            _request: &ProcessRequest,
        ) -> Result<Option<BrokerObservedProcess>, ProcessEffectError> {
            Ok(Some(self.observed.clone()))
        }
    }

    fn observed(seed: u16) -> BrokerObservedProcess {
        let mut provider_digest = Sha256::new();
        provider_digest.update(b"d2b-process-provider-v1");
        provider_digest.update(b"system-minijail");
        let provider_identity: [u8; 32] = provider_digest.finalize().into();
        BrokerObservedProcess {
            intent: BrokerLaunchIntent {
                vm_id: VmId::new("corp-vm"),
                zone_uid: None,
                owner_ref: None,
                owner_uid: None,
                runtime_scope: None,
                typed_identity: false,
                provider_ref: ResourceRef::parse("Provider/system-minijail").unwrap(),
                execution_ref: ResourceRef::parse("Host/local").unwrap(),
                domain: ExecutionDomain::System,
                user_ref: None,
                role_id: RoleId::new("worker"),
                role: RunnerRole::Virtiofsd,
                bundle_runner_intent_ref: BundleOpId::new("runner:vm:corp-vm:role:worker"),
                provider_identity,
                template_identity: [2; 32],
                generation: 1,
                resource_ref: ResourceRef::parse("Process/worker").unwrap(),
                resource_uid: d2b_contracts_resource::v3::ResourceUid::parse(
                    "00000000-0000-4000-8000-000000000001",
                )
                .unwrap(),
                bundle_content_identity: "bundle".to_owned(),
                sandbox_plan: None,
                activation_input: None,
                guest_execution: None,
            },
            pid: i32::from(seed) + 1,
            start_time_ticks: u64::from(seed) + 1,
            cgroup_verified: true,
            executable_verified: true,
        }
    }

    fn observed_process(pid: i32, start_time_ticks: u64) -> BrokerObservedProcess {
        BrokerObservedProcess {
            pid,
            start_time_ticks,
            ..observed(1)
        }
    }

    fn producer_live_handler_error_kind() -> &'static str {
        const SOURCE: &str = include_str!("../../d2b-broker/src/runtime.rs");
        const ARM: &str = "Self::LiveHandler(message) => error_response(";
        let arm = SOURCE
            .split_once(ARM)
            .expect("broker LiveHandler response arm")
            .1;
        arm.split('"')
            .nth(1)
            .expect("broker LiveHandler error kind")
    }

    fn live_handler_response() -> BrokerResponse {
        BrokerResponse::Error(BrokerErrorResponse {
            kind: producer_live_handler_error_kind().to_owned(),
            operation: "LiveHandler".to_owned(),
            target_wave: None,
            message: "privileged host operation failed".to_owned(),
            action: "inspect private audit".to_owned(),
        })
    }

    #[test]
    fn pending_broker_observations_are_bounded_and_consumed() {
        let backend =
            BrokerProcessBackend::with_socket(Resolver, "/unused", Duration::from_millis(1));
        for seed in 0..=MAX_PENDING_OBSERVATIONS {
            backend
                .record(observed(u16::try_from(seed).unwrap()))
                .unwrap();
        }
        assert_eq!(
            backend.observations.lock().unwrap().len(),
            MAX_PENDING_OBSERVATIONS
        );
        let identity = observed(u16::try_from(MAX_PENDING_OBSERVATIONS).unwrap()).digest();
        backend.take_observation(&identity).unwrap();
        assert_eq!(
            backend.observations.lock().unwrap().len(),
            MAX_PENDING_OBSERVATIONS - 1
        );
    }

    #[test]
    fn executable_mismatch_remains_observable_as_incomplete_identity() {
        let mut process = observed(1);
        process.executable_verified = false;
        let backend = BrokerProcessBackend::with_socket(
            ObservingResolver {
                observed: process.clone(),
            },
            "/unused",
            Duration::from_millis(1),
        );
        let request = ProcessRequest::new(
            d2b_process_conformance::testing::fixtures::ticket_builder()
                .build()
                .expect("conformant ticket"),
        );
        let observation = backend
            .observe(request)
            .expect("mismatch observation")
            .expect("candidate remains present");
        assert!(
            !observation
                .observed()
                .verified()
                .contains(&IdentityBinding::Executable)
        );
        assert!(
            observation
                .observed()
                .verified()
                .contains(&IdentityBinding::Cgroup)
        );
        assert!(backend.take_observation(&observation.identity()).is_ok());
    }

    #[test]
    fn open_pidfd_live_handler_failure_is_ambiguous_only_after_identity_drift() {
        const LIVE_HANDLER_SOURCE: &str = include_str!("../../d2b-broker/src/live_handlers.rs");
        for producer_error in ["PidfdRace", "PidfdOpenFailed", "ProcStatReadFailed"] {
            assert!(LIVE_HANDLER_SOURCE.contains(producer_error));
        }

        let response = live_handler_response();
        let pid = i32::try_from(std::process::id()).unwrap();
        let current_start_time = read_proc_start_time(pid).unwrap().unwrap();
        let drifted = observed_process(pid, current_start_time.saturating_add(1));
        assert_eq!(
            response_error(&response, BrokerOperation::OpenPidfd(&drifted)),
            ProcessEffectError::IdentityChanged
        );

        let unchanged = observed_process(pid, current_start_time);
        assert_eq!(
            response_error(&response, BrokerOperation::OpenPidfd(&unchanged)),
            ProcessEffectError::PidfdUnavailable
        );

        let vanished = observed_process(-1, current_start_time);
        assert_eq!(
            response_error(&response, BrokerOperation::OpenPidfd(&vanished)),
            ProcessEffectError::Vanished
        );
        assert_eq!(
            response_error(&response, BrokerOperation::Other),
            ProcessEffectError::LaunchFailed
        );
    }

    #[test]
    fn generic_process_roles_map_only_to_closed_broker_roles() {
        assert_eq!(
            runner_role_for_process_role(&ProcessRole::CloudHypervisorRunner),
            Some(RunnerRole::CloudHypervisor)
        );
        assert_eq!(
            runner_role_for_process_role(&ProcessRole::GpuRenderNode),
            Some(RunnerRole::Gpu)
        );
        assert_eq!(
            runner_role_for_process_role(&ProcessRole::ComponentSessionHealth),
            None
        );
        assert_eq!(
            runner_role_for_process_role(&ProcessRole::SecurityKeyFrontend),
            None
        );
    }

    #[test]
    fn broker_diagnostics_redact_process_identity_values() {
        let process = observed(41);
        assert_eq!(format!("{process:?}"), "BrokerObservedProcess(<redacted>)");
        assert_eq!(
            format!("{:?}", process.intent),
            "BrokerLaunchIntent(<redacted>)"
        );
    }

    #[test]
    fn broker_process_identity_digest_binds_resource_incarnation() {
        let first = observed(41);
        let mut recreated = first.clone();
        recreated.intent.resource_uid =
            d2b_contracts_resource::v3::ResourceUid::parse("00000000-0000-4000-8000-000000000002")
                .unwrap();
        assert_ne!(first.digest(), recreated.digest());
    }
}

fn read_pidfd_process_id(pidfd: &OwnedFd) -> Result<Option<i32>, ProcessEffectError> {
    let contents = match fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd())) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(ProcessEffectError::ObserveFailed),
    };
    let mut observed = None;
    for line in contents.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name != "Pid" {
            continue;
        }
        if observed
            .replace(
                value
                    .trim()
                    .parse::<i32>()
                    .map_err(|_| ProcessEffectError::ObserveFailed)?,
            )
            .is_some()
        {
            return Err(ProcessEffectError::ObserveFailed);
        }
    }
    Ok(observed)
}

fn read_proc_start_time(pid: i32) -> Result<Option<u64>, ProcessEffectError> {
    let content = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(ProcessEffectError::ObserveFailed),
    };
    let close = content
        .trim_end_matches('\n')
        .rfind(')')
        .ok_or(ProcessEffectError::ObserveFailed)?;
    let mut fields = content[close + 1..].split_whitespace();
    let state = fields.next().ok_or(ProcessEffectError::ObserveFailed)?;
    if matches!(state, "Z" | "X") {
        return Ok(None);
    }
    fields
        .nth(18)
        .ok_or(ProcessEffectError::ObserveFailed)?
        .parse::<u64>()
        .map(Some)
        .map_err(|_| ProcessEffectError::ObserveFailed)
}

pub(crate) fn broker_round_trip(
    socket_path: &Path,
    io_timeout: Duration,
    request: BrokerRequest,
    caller_role: BrokerCallerRole,
) -> Result<BrokerFrame, ProcessEffectError> {
    broker_round_trip_with_fds(socket_path, io_timeout, request, caller_role, &[])
}

pub(crate) fn broker_round_trip_with_fds(
    socket_path: &Path,
    io_timeout: Duration,
    request: BrokerRequest,
    caller_role: BrokerCallerRole,
    inherited_fds: &[OwnedFd],
) -> Result<BrokerFrame, ProcessEffectError> {
    let fd = socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|_| ProcessEffectError::LaunchFailed)?;
    let socket = Socket::from(fd);
    let address =
        socket2::SockAddr::unix(socket_path).map_err(|_| ProcessEffectError::LaunchFailed)?;
    socket
        .connect_timeout(&address, io_timeout)
        .map_err(|_| ProcessEffectError::LaunchFailed)?;
    socket
        .set_read_timeout(Some(io_timeout))
        .map_err(|_| ProcessEffectError::LaunchFailed)?;
    socket
        .set_write_timeout(Some(io_timeout))
        .map_err(|_| ProcessEffectError::LaunchFailed)?;
    let (zone_id, operation_identity) = request
        .authoritative_audit_join()
        .ok_or(ProcessEffectError::LaunchFailed)?;
    let audit_join = AuditJoinContext {
        zone_id: CanonicalAuditDigest::parse(zone_id)
            .map_err(|_| ProcessEffectError::LaunchFailed)?,
        operation_identity: CanonicalAuditDigest::parse(operation_identity)
            .map_err(|_| ProcessEffectError::LaunchFailed)?,
    };
    let envelope = BrokerRequestEnvelope {
        request,
        caller_role,
        test_peer_uid: None,
        audit_join: Some(audit_join),
    };
    let frame =
        d2b_contracts::encode_frame(&envelope).map_err(|_| ProcessEffectError::LaunchFailed)?;
    let written = if inherited_fds.is_empty() {
        send(&socket, &frame, SendFlags::empty()).map_err(|_| ProcessEffectError::LaunchFailed)?
    } else {
        let descriptors = inherited_fds
            .iter()
            .map(std::os::fd::AsFd::as_fd)
            .collect::<Vec<_>>();
        let mut control_bytes = vec![0_u8; rustix::cmsg_space!(ScmRights(256))];
        let mut control = SendAncillaryBuffer::new(&mut control_bytes);
        if !control.push(SendAncillaryMessage::ScmRights(&descriptors)) {
            return Err(ProcessEffectError::LaunchFailed);
        }
        let iov = [IoSlice::new(&frame)];
        sendmsg(&socket, &iov, &mut control, SendFlags::empty())
            .map_err(|_| ProcessEffectError::LaunchFailed)?
    };
    if written != frame.len() {
        return Err(ProcessEffectError::LaunchFailed);
    }

    let mut payload = vec![0_u8; d2b_contracts::MAX_FRAME_SIZE + 4];
    let mut iov = [IoSliceMut::new(&mut payload)];
    let mut control_bytes = vec![0_u8; rustix::cmsg_space!(ScmRights(256))];
    let mut control = RecvAncillaryBuffer::new(&mut control_bytes);
    let message = recvmsg(&socket, &mut iov, &mut control, RecvFlags::CMSG_CLOEXEC)
        .map_err(|_| ProcessEffectError::LaunchFailed)?;
    let bytes = message.bytes;
    let mut fds = Vec::new();
    for message in control.drain() {
        if let RecvAncillaryMessage::ScmRights(received) = message {
            for owned in received {
                fds.push(Some(owned));
            }
        }
    }
    let response = d2b_contracts::decode_frame("BrokerResponse", &payload[..bytes])
        .map_err(|_| ProcessEffectError::LaunchFailed)?;
    Ok(BrokerFrame {
        response,
        fds: Mutex::new(fds),
    })
}
