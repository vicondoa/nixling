//! Service-manager effect owner adapter and atomic unit identity.

use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::os::fd::OwnedFd;
use std::sync::Mutex;

use d2b_contracts_broker::broker_wire::{
    BrokerCallerRole, BrokerProfile, BrokerRequest, BrokerResponse, GuestExecutionBinding,
    OpenSystemdUnitPidfdRequest, StopSystemdUnitRequest, SystemdStopClass, SystemdUnitDomain,
    SystemdUnitIdentity, SystemdUnitRequest,
};
use d2b_contracts_resource::v3::execution_policy::ExecutionDomain;
use d2b_process::{
    BackendLaunch, BackendObservation, IdentityBinding, ObservedIdentity, ProcessEffectBackend,
    ProcessEffectError, ProcessIdentityDigest, ProcessRequest, ProcessStopClass, WaitReapOwner,
};
use sha2::{Digest, Sha256};

use crate::broker::{
    BrokerFrame, BrokerLaunchIntent, BrokerLaunchResolver, BundleBackedLaunchResolver,
    broker_round_trip, wait_pidfd_exit,
};

const MAX_PENDING_OBSERVATIONS: usize = 1024;

/// Atomic identity read from one active non-forking transient unit or scope.
///
/// The effect owner must obtain the invocation identifier, cgroup identity,
/// main process, and process start time from one coherent active-state query.
/// The template and generation digests bind that runtime tuple to trusted
/// launch configuration. Diagnostics reveal none of those values.
#[derive(Clone, PartialEq, Eq)]
pub struct SystemdInvocationIdentity {
    invocation_id: [u8; 16],
    cgroup_identity: [u8; 32],
    main_pid: NonZeroU32,
    start_time_ticks: u64,
    provider_identity: [u8; 32],
    template_identity: [u8; 32],
    generation: u64,
    bundle_content_identity: String,
    guest_execution: Option<GuestExecutionBinding>,
}

/// Immutable bundle binding carried by a systemd runtime identity.
#[derive(Clone, PartialEq, Eq)]
pub struct SystemdIdentityContext {
    generation: u64,
    bundle_content_identity: String,
}

impl SystemdIdentityContext {
    /// Construct the bundle-bound portion of a systemd identity.
    pub fn new(
        generation: u64,
        bundle_content_identity: impl Into<String>,
    ) -> Result<Self, ProcessEffectError> {
        let bundle_content_identity = bundle_content_identity.into();
        if generation == 0 || bundle_content_identity.is_empty() {
            return Err(ProcessEffectError::IdentityChanged);
        }
        Ok(Self {
            generation,
            bundle_content_identity,
        })
    }
}

impl SystemdInvocationIdentity {
    /// Construct a complete service-manager identity tuple.
    pub fn new(
        invocation_id: [u8; 16],
        cgroup_identity: [u8; 32],
        main_pid: NonZeroU32,
        start_time_ticks: u64,
        provider_identity: [u8; 32],
        template_identity: [u8; 32],
        context: SystemdIdentityContext,
    ) -> Result<Self, ProcessEffectError> {
        if invocation_id == [0; 16]
            || cgroup_identity == [0; 32]
            || start_time_ticks == 0
            || provider_identity == [0; 32]
            || template_identity == [0; 32]
        {
            return Err(ProcessEffectError::IdentityChanged);
        }
        Ok(Self {
            invocation_id,
            cgroup_identity,
            main_pid,
            start_time_ticks,
            provider_identity,
            template_identity,
            generation: context.generation,
            bundle_content_identity: context.bundle_content_identity,
            guest_execution: None,
        })
    }

    fn digest(&self) -> ProcessIdentityDigest {
        let mut digest = Sha256::new();
        digest.update(b"d2b-systemd-process-identity-v1");
        digest.update(self.invocation_id);
        digest.update(self.cgroup_identity);
        digest.update(self.main_pid.get().to_le_bytes());
        digest.update(self.start_time_ticks.to_le_bytes());
        digest.update(self.provider_identity);
        digest.update(self.template_identity);
        digest.update(self.generation.to_le_bytes());
        digest.update(self.bundle_content_identity.as_bytes());
        if let Some(binding) = &self.guest_execution {
            digest.update(binding.target_uid.as_str().as_bytes());
            digest.update(binding.boot_identity_digest);
            digest.update(binding.session_generation.to_le_bytes());
            digest.update(binding.assignment_epoch.to_le_bytes());
            digest.update(binding.provider_generation.to_le_bytes());
            digest.update(binding.controller_generation.to_le_bytes());
        }
        ProcessIdentityDigest::from_bytes(digest.finalize().into())
    }

    fn observation(&self) -> BackendObservation {
        BackendObservation::new(
            self.digest(),
            ObservedIdentity::from_verified([
                IdentityBinding::UnitInvocationId,
                IdentityBinding::Cgroup,
                IdentityBinding::UnitMainPid,
                IdentityBinding::ProcessStartTime,
                IdentityBinding::Template,
                IdentityBinding::Generation,
            ]),
            WaitReapOwner::ServiceManager,
        )
    }

    pub(crate) fn wire_identity(&self) -> SystemdUnitIdentity {
        SystemdUnitIdentity {
            invocation_id: self.invocation_id,
            cgroup_identity: self.cgroup_identity,
            main_pid: self.main_pid.get(),
            start_time_ticks: self.start_time_ticks,
            provider_identity: self.provider_identity,
            template_identity: self.template_identity,
            generation: self.generation,
            bundle_content_identity: self.bundle_content_identity.clone(),
            guest_execution: self.guest_execution.clone(),
        }
    }

    pub(crate) fn from_wire(identity: &SystemdUnitIdentity) -> Result<Self, ProcessEffectError> {
        let mut value = Self::new(
            identity.invocation_id,
            identity.cgroup_identity,
            NonZeroU32::new(identity.main_pid).ok_or(ProcessEffectError::IdentityChanged)?,
            identity.start_time_ticks,
            identity.provider_identity,
            identity.template_identity,
            SystemdIdentityContext::new(
                identity.generation,
                identity.bundle_content_identity.clone(),
            )?,
        )?;
        value.guest_execution = identity.guest_execution.clone();
        Ok(value)
    }
}

impl std::fmt::Debug for SystemdInvocationIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SystemdInvocationIdentity(<redacted>)")
    }
}

/// Result of a service-manager launch or descriptor re-open.
pub struct SystemdEffectLaunch<H> {
    identity: SystemdInvocationIdentity,
    handle: H,
}

impl<H> SystemdEffectLaunch<H> {
    /// Bind the atomically observed unit identity to its local descriptor.
    pub fn new(identity: SystemdInvocationIdentity, handle: H) -> Self {
        Self { identity, handle }
    }

    fn into_parts(self) -> (SystemdInvocationIdentity, H) {
        (self.identity, self.handle)
    }
}

impl<H> std::fmt::Debug for SystemdEffectLaunch<H> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SystemdEffectLaunch(<redacted>)")
    }
}

/// Blocking core-owned access to system and verified user managers.
///
/// Implementations resolve the ticket from trusted configuration, create only
/// non-forking transient units or scopes, and return an atomic identity tuple.
/// `reopen` must query the tuple again after opening the descriptor so a unit
/// replacement or main-process reuse cannot be adopted.
pub trait SystemdEffectOwner: Send + Sync + 'static {
    /// Core-local pidfd or equivalent exact-main authority.
    type Handle: Send + Sync + 'static;

    /// Launch one transient unit or verified user scope.
    fn launch(
        &self,
        request: ProcessRequest,
    ) -> Result<SystemdEffectLaunch<Self::Handle>, ProcessEffectError>;

    /// Observe a transient unit without opening local process authority.
    fn observe(
        &self,
        request: ProcessRequest,
    ) -> Result<Option<SystemdInvocationIdentity>, ProcessEffectError>;

    /// Probe a transient unit without retaining adoption state.
    fn probe(
        &self,
        request: ProcessRequest,
    ) -> Result<Option<SystemdInvocationIdentity>, ProcessEffectError> {
        self.observe(request)
    }

    /// Open local authority and atomically re-query the unit identity.
    fn reopen(
        &self,
        expected: &SystemdInvocationIdentity,
    ) -> Result<SystemdEffectLaunch<Self::Handle>, ProcessEffectError>;

    /// Wait for the exact local authority to become readable.
    fn wait(
        &self,
        _handle: &Self::Handle,
        _timeout: std::time::Duration,
    ) -> Result<(), ProcessEffectError> {
        Err(ProcessEffectError::PidfdUnavailable)
    }

    /// Stop only the unit represented by the verified local handle.
    ///
    /// A successful [`ProcessStopClass::Terminate`] result certifies that the
    /// unit's represented process no longer survives.
    fn stop(
        &self,
        handle: &Self::Handle,
        class: ProcessStopClass,
    ) -> Result<(), ProcessEffectError>;

    /// Check the trusted per-user systemd manager without retaining a
    /// connection or process handle.
    fn check_user_manager(&self, _request: ProcessRequest) -> Result<bool, ProcessEffectError> {
        Err(ProcessEffectError::UnsupportedProvider)
    }

    /// Forget a terminal unit identity after the unit is no longer active.
    fn finalize(&self, _handle: &Self::Handle) -> Result<(), ProcessEffectError> {
        Ok(())
    }
}

/// [`ProcessEffectBackend`] over a real service-manager effect owner.
pub struct SystemdProcessBackend<O: SystemdEffectOwner> {
    owner: O,
    observations: Mutex<BTreeMap<ProcessIdentityDigest, SystemdInvocationIdentity>>,
}

impl<O: SystemdEffectOwner> SystemdProcessBackend<O> {
    /// Wrap a core-owned service-manager effect owner.
    pub fn new(owner: O) -> Self {
        Self {
            owner,
            observations: Mutex::new(BTreeMap::new()),
        }
    }

    fn record(&self, identity: SystemdInvocationIdentity) -> Result<(), ProcessEffectError> {
        let mut observations = self
            .observations
            .lock()
            .map_err(|_| ProcessEffectError::ObserveFailed)?;
        let digest = identity.digest();
        if observations.len() >= MAX_PENDING_OBSERVATIONS
            && !observations.contains_key(&digest)
            && let Some(oldest) = observations.keys().next().copied()
        {
            observations.remove(&oldest);
        }
        observations.insert(digest, identity);
        Ok(())
    }

    fn take_observation(
        &self,
        identity: &ProcessIdentityDigest,
    ) -> Result<SystemdInvocationIdentity, ProcessEffectError> {
        self.observations
            .lock()
            .map_err(|_| ProcessEffectError::ObserveFailed)?
            .remove(identity)
            .ok_or(ProcessEffectError::IdentityChanged)
    }
}

#[cfg(test)]
// Keep focused observation tests beside the state helpers they exercise.
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    struct Owner;

    impl SystemdEffectOwner for Owner {
        type Handle = ();

        fn launch(
            &self,
            _request: ProcessRequest,
        ) -> Result<SystemdEffectLaunch<Self::Handle>, ProcessEffectError> {
            Err(ProcessEffectError::LaunchFailed)
        }

        fn observe(
            &self,
            _request: ProcessRequest,
        ) -> Result<Option<SystemdInvocationIdentity>, ProcessEffectError> {
            Ok(None)
        }

        fn reopen(
            &self,
            _expected: &SystemdInvocationIdentity,
        ) -> Result<SystemdEffectLaunch<Self::Handle>, ProcessEffectError> {
            Err(ProcessEffectError::PidfdUnavailable)
        }

        fn stop(
            &self,
            _handle: &Self::Handle,
            _class: ProcessStopClass,
        ) -> Result<(), ProcessEffectError> {
            Ok(())
        }
    }

    fn identity(seed: u32) -> SystemdInvocationIdentity {
        let mut invocation_id = [0; 16];
        invocation_id[..4].copy_from_slice(&(seed + 1).to_le_bytes());
        SystemdInvocationIdentity::new(
            invocation_id,
            [1; 32],
            NonZeroU32::new(seed + 1).unwrap(),
            u64::from(seed) + 1,
            [2; 32],
            [3; 32],
            SystemdIdentityContext::new(1, "bundle").unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn pending_systemd_observations_are_bounded_and_consumed() {
        let backend = SystemdProcessBackend::new(Owner);
        for seed in 0..=u32::try_from(MAX_PENDING_OBSERVATIONS).unwrap() {
            backend.record(identity(seed)).unwrap();
        }
        assert_eq!(
            backend.observations.lock().unwrap().len(),
            MAX_PENDING_OBSERVATIONS
        );
        let digest = identity(u32::try_from(MAX_PENDING_OBSERVATIONS).unwrap()).digest();
        backend.take_observation(&digest).unwrap();
        assert_eq!(
            backend.observations.lock().unwrap().len(),
            MAX_PENDING_OBSERVATIONS - 1
        );
    }

    #[test]
    fn systemd_identity_diagnostics_are_redacted() {
        assert_eq!(
            format!("{:?}", identity(41)),
            "SystemdInvocationIdentity(<redacted>)"
        );
    }

    #[test]
    fn systemd_adoption_identity_binds_bundle_content_identity() {
        let mut first = identity(41);
        let mut second = identity(41);
        first.bundle_content_identity = "bundle-a".to_owned();
        second.bundle_content_identity = "bundle-b".to_owned();
        assert_ne!(first.digest(), second.digest());
    }
}

impl<O: SystemdEffectOwner> std::fmt::Debug for SystemdProcessBackend<O> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SystemdProcessBackend(<redacted>)")
    }
}

impl<O: SystemdEffectOwner> ProcessEffectBackend for SystemdProcessBackend<O> {
    type Handle = O::Handle;

    fn launch(
        &self,
        request: ProcessRequest,
    ) -> Result<BackendLaunch<Self::Handle>, ProcessEffectError> {
        let launch = self.owner.launch(request)?;
        let (identity, handle) = launch.into_parts();
        let observation = identity.observation();
        Ok(BackendLaunch::new(observation, handle))
    }

    fn observe(
        &self,
        request: ProcessRequest,
    ) -> Result<Option<BackendObservation>, ProcessEffectError> {
        let Some(identity) = self.owner.observe(request)? else {
            return Ok(None);
        };
        let observation = identity.observation();
        self.record(identity)?;
        Ok(Some(observation))
    }

    fn probe(
        &self,
        request: ProcessRequest,
    ) -> Result<Option<BackendObservation>, ProcessEffectError> {
        let Some(identity) = self.owner.probe(request)? else {
            return Ok(None);
        };
        Ok(Some(identity.observation()))
    }

    fn open_pidfd(
        &self,
        observation: BackendObservation,
    ) -> Result<Self::Handle, ProcessEffectError> {
        let expected = self.take_observation(&observation.identity())?;
        let reopened = self.owner.reopen(&expected)?;
        let (actual, handle) = reopened.into_parts();
        if actual != expected || actual.digest() != observation.identity() {
            return Err(ProcessEffectError::IdentityChanged);
        }
        Ok(handle)
    }

    fn wait(
        &self,
        handle: &Self::Handle,
        timeout: std::time::Duration,
    ) -> Result<(), ProcessEffectError> {
        self.owner.wait(handle, timeout)
    }

    fn stop(
        &self,
        handle: &Self::Handle,
        class: ProcessStopClass,
    ) -> Result<(), ProcessEffectError> {
        self.owner.stop(handle, class)
    }

    fn finalize(&self, handle: &Self::Handle) -> Result<(), ProcessEffectError> {
        self.owner.finalize(handle)
    }
}

impl<O: SystemdEffectOwner> SystemdProcessBackend<O> {
    /// Check the trusted per-user manager through the broker-owned effect
    /// owner.
    pub fn check_user_manager(&self, request: ProcessRequest) -> Result<bool, ProcessEffectError> {
        self.owner.check_user_manager(request)
    }
}

/// Broker-backed systemd effect owner used by the daemon's fixed supervisor.
///
/// The owner translates only typed systemd lifecycle requests to the broker.
/// Unit names, manager connections, cgroup paths, and process descriptors
/// remain on the broker side; the returned handle is retained here solely for
/// exact stop authority.
pub struct BrokerSystemdEffectOwner {
    resolver: BundleBackedLaunchResolver,
    socket_path: std::path::PathBuf,
    io_timeout: std::time::Duration,
    profile: BrokerProfile,
    caller_role: BrokerCallerRole,
    requests: Mutex<BTreeMap<ProcessIdentityDigest, SystemdUnitRequest>>,
}

impl BrokerSystemdEffectOwner {
    /// Build a broker-backed owner from the trusted bundle resolver.
    pub fn new(resolver: BundleBackedLaunchResolver) -> Self {
        Self::with_socket(
            resolver,
            d2b_contracts::BROKER_SOCKET_PATH,
            std::time::Duration::from_secs(10),
            BrokerCallerRole::NotAuthorized,
        )
    }

    /// Build an owner with explicit broker transport settings.
    pub fn with_socket(
        resolver: BundleBackedLaunchResolver,
        socket_path: impl Into<std::path::PathBuf>,
        io_timeout: std::time::Duration,
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

    /// Build an owner bound to one fixed broker profile and caller identity.
    pub fn with_socket_profile_and_role(
        resolver: BundleBackedLaunchResolver,
        socket_path: impl Into<std::path::PathBuf>,
        io_timeout: std::time::Duration,
        profile: BrokerProfile,
        caller_role: BrokerCallerRole,
    ) -> Self {
        Self {
            resolver,
            socket_path: socket_path.into(),
            io_timeout,
            profile,
            caller_role,
            requests: Mutex::new(BTreeMap::new()),
        }
    }

    fn request(&self, request: BrokerRequest) -> Result<BrokerFrame, ProcessEffectError> {
        if matches!(self.caller_role, BrokerCallerRole::NotAuthorized)
            || !request.allowed_by_profile(self.profile)
        {
            return Err(ProcessEffectError::LaunchFailed);
        }
        broker_round_trip(
            &self.socket_path,
            self.io_timeout,
            request,
            self.caller_role.clone(),
        )
    }

    fn intent(
        &self,
        request: &ProcessRequest,
    ) -> Result<(BrokerLaunchIntent, SystemdUnitRequest), ProcessEffectError> {
        let intent = self.resolver.resolve(request)?;
        let domain = match request.ticket().domain() {
            ExecutionDomain::System => SystemdUnitDomain::System,
            ExecutionDomain::User => SystemdUnitDomain::User,
        };
        let unit = SystemdUnitRequest {
            execution_ref: Some(intent.execution_ref.clone()),
            user_ref: intent.user_ref.clone(),
            vm_id: intent.vm_id.clone(),
            role_id: intent.role_id.clone(),
            resource_ref: Some(intent.resource_ref.clone()),
            resource_uid: Some(intent.resource_uid.clone()),
            role: intent.role,
            bundle_runner_intent_ref: intent.bundle_runner_intent_ref.clone(),
            bundle_content_identity: intent.bundle_content_identity.clone(),
            provider_identity: intent.provider_identity,
            template_identity: intent.template_identity,
            generation: intent.generation,
            domain,
            guest_execution: intent.guest_execution.clone(),
            sandbox_plan: intent.sandbox_plan.clone(),
            tracing_span_id: None,
        };
        Ok((intent, unit))
    }

    fn remember(
        &self,
        identity: &SystemdInvocationIdentity,
        request: SystemdUnitRequest,
    ) -> Result<(), ProcessEffectError> {
        self.requests
            .lock()
            .map_err(|_| ProcessEffectError::ObserveFailed)?
            .insert(identity.digest(), request);
        Ok(())
    }

    fn request_for(
        &self,
        identity: &SystemdInvocationIdentity,
    ) -> Result<SystemdUnitRequest, ProcessEffectError> {
        self.requests
            .lock()
            .map_err(|_| ProcessEffectError::ObserveFailed)?
            .get(&identity.digest())
            .cloned()
            .ok_or(ProcessEffectError::IdentityChanged)
    }

    fn take_request(
        &self,
        identity: &SystemdInvocationIdentity,
    ) -> Result<SystemdUnitRequest, ProcessEffectError> {
        self.requests
            .lock()
            .map_err(|_| ProcessEffectError::StopFailed)?
            .remove(&identity.digest())
            .ok_or(ProcessEffectError::IdentityChanged)
    }

    fn identity(
        &self,
        wire: &SystemdUnitIdentity,
        intent: &BrokerLaunchIntent,
    ) -> Result<SystemdInvocationIdentity, ProcessEffectError> {
        if wire.provider_identity != intent.provider_identity
            || wire.template_identity != intent.template_identity
            || wire.generation != intent.generation
            || wire.bundle_content_identity != intent.bundle_content_identity
            || wire.guest_execution != intent.guest_execution
            || wire.main_pid == 0
        {
            return Err(ProcessEffectError::IdentityChanged);
        }
        SystemdInvocationIdentity::from_wire(wire)
    }
}

impl std::fmt::Debug for BrokerSystemdEffectOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BrokerSystemdEffectOwner(<redacted>)")
    }
}

/// Core-local systemd pidfd handle.
pub struct BrokerSystemdPidfdHandle {
    pidfd: OwnedFd,
    request: SystemdUnitRequest,
    identity: SystemdInvocationIdentity,
}

impl std::fmt::Debug for BrokerSystemdPidfdHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BrokerSystemdPidfdHandle(<redacted>)")
    }
}

impl SystemdEffectOwner for BrokerSystemdEffectOwner {
    type Handle = BrokerSystemdPidfdHandle;

    fn launch(
        &self,
        request: ProcessRequest,
    ) -> Result<SystemdEffectLaunch<Self::Handle>, ProcessEffectError> {
        let (intent, unit) = self.intent(&request)?;
        let frame = self.request(BrokerRequest::StartSystemdUnit(unit.clone()))?;
        let BrokerResponse::StartSystemdUnit(ref response) = frame.response else {
            return Err(response_error(&frame.response));
        };
        if response.vm_id != unit.vm_id || response.role_id != unit.role_id {
            return Err(ProcessEffectError::IdentityChanged);
        }
        let identity = self.identity(&response.identity, &intent)?;
        let pidfd = frame.take_fd(response.pidfd_index)?;
        self.remember(&identity, unit.clone())?;
        Ok(SystemdEffectLaunch::new(
            identity.clone(),
            BrokerSystemdPidfdHandle {
                pidfd,
                request: unit,
                identity,
            },
        ))
    }

    fn observe(
        &self,
        request: ProcessRequest,
    ) -> Result<Option<SystemdInvocationIdentity>, ProcessEffectError> {
        let (intent, unit) = self.intent(&request)?;
        let frame = self.request(BrokerRequest::ObserveSystemdUnit(unit.clone()))?;
        let BrokerResponse::ObserveSystemdUnit(response) = frame.response else {
            return Err(response_error(&frame.response));
        };
        if response.vm_id != unit.vm_id || response.role_id != unit.role_id {
            return Err(ProcessEffectError::IdentityChanged);
        }
        let Some(wire) = response.identity else {
            return Ok(None);
        };
        let identity = self.identity(&wire, &intent)?;
        self.remember(&identity, unit)?;
        Ok(Some(identity))
    }

    fn probe(
        &self,
        request: ProcessRequest,
    ) -> Result<Option<SystemdInvocationIdentity>, ProcessEffectError> {
        let (intent, unit) = self.intent(&request)?;
        let frame = self.request(BrokerRequest::ObserveSystemdUnit(unit.clone()))?;
        let BrokerResponse::ObserveSystemdUnit(response) = frame.response else {
            return Err(response_error(&frame.response));
        };
        if response.vm_id != unit.vm_id || response.role_id != unit.role_id {
            return Err(ProcessEffectError::IdentityChanged);
        }
        let Some(wire) = response.identity else {
            return Ok(None);
        };
        self.identity(&wire, &intent).map(Some)
    }

    fn reopen(
        &self,
        expected: &SystemdInvocationIdentity,
    ) -> Result<SystemdEffectLaunch<Self::Handle>, ProcessEffectError> {
        let unit = self.request_for(expected)?;
        let frame = self.request(BrokerRequest::OpenSystemdUnitPidfd(
            OpenSystemdUnitPidfdRequest {
                unit: unit.clone(),
                expected: expected.wire_identity(),
            },
        ))?;
        let BrokerResponse::OpenSystemdUnitPidfd(ref response) = frame.response else {
            return Err(response_error(&frame.response));
        };
        let actual = SystemdInvocationIdentity::from_wire(&response.identity)?;
        if actual != *expected || response.vm_id != unit.vm_id || response.role_id != unit.role_id {
            return Err(ProcessEffectError::IdentityChanged);
        }
        let pidfd = frame.take_fd(response.pidfd_index)?;
        Ok(SystemdEffectLaunch::new(
            actual.clone(),
            BrokerSystemdPidfdHandle {
                pidfd,
                request: unit,
                identity: actual,
            },
        ))
    }

    fn wait(
        &self,
        handle: &Self::Handle,
        timeout: std::time::Duration,
    ) -> Result<(), ProcessEffectError> {
        wait_pidfd_exit(&handle.pidfd, timeout)
    }

    fn stop(
        &self,
        handle: &Self::Handle,
        class: ProcessStopClass,
    ) -> Result<(), ProcessEffectError> {
        let frame = self.request(BrokerRequest::StopSystemdUnit(StopSystemdUnitRequest {
            unit: handle.request.clone(),
            expected: handle.identity.wire_identity(),
            class: match class {
                ProcessStopClass::Drain => SystemdStopClass::Drain,
                ProcessStopClass::Terminate => SystemdStopClass::Terminate,
            },
        }))?;
        let BrokerResponse::StopSystemdUnit(response) = frame.response else {
            return Err(response_error(&frame.response));
        };
        if !response.stopped {
            return Err(ProcessEffectError::StopFailed);
        }
        let _ = &handle.pidfd;
        if class == ProcessStopClass::Terminate {
            let _ = self.take_request(&handle.identity)?;
        }
        Ok(())
    }

    fn check_user_manager(&self, request: ProcessRequest) -> Result<bool, ProcessEffectError> {
        let (intent, mut unit) = self.intent(&request)?;
        if unit.domain != SystemdUnitDomain::User {
            return Err(ProcessEffectError::UnsupportedProvider);
        }
        unit.tracing_span_id = None;
        let frame = self.request(BrokerRequest::CheckSystemdUserManager(unit.clone()))?;
        let BrokerResponse::CheckSystemdUserManager(response) = frame.response else {
            return Err(response_error(&frame.response));
        };
        if response.vm_id != intent.vm_id || response.role_id != intent.role_id {
            return Err(ProcessEffectError::IdentityChanged);
        }
        Ok(response.available)
    }

    fn finalize(&self, handle: &Self::Handle) -> Result<(), ProcessEffectError> {
        let _ = self.take_request(&handle.identity)?;
        Ok(())
    }
}

fn response_error(response: &BrokerResponse) -> ProcessEffectError {
    match response {
        BrokerResponse::Error(_) => ProcessEffectError::LaunchFailed,
        _ => ProcessEffectError::ObserveFailed,
    }
}
