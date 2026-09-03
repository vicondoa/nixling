//! Core-owned process effect backend contract.

use std::fmt;
use std::os::fd::OwnedFd;
use std::time::Duration;

use d2b_process_conformance::{
    LaunchTicket, MAX_INHERITED_FDS, ObservedIdentity, ProcessConformanceError,
    ProcessIdentityDigest, WaitReapOwner,
};

/// One owned request passed from the async adapter to a blocking effect owner.
///
/// The request deliberately wraps the validated ticket instead of expanding it
/// into host values. A broker or service-manager resolver must derive every
/// operating-system detail from trusted configuration.
#[derive(Clone)]
pub struct ProcessRequest {
    ticket: LaunchTicket,
}

impl ProcessRequest {
    /// Build a backend request from a validated launch ticket.
    pub fn new(ticket: LaunchTicket) -> Self {
        Self { ticket }
    }

    /// Borrow the validated launch ticket.
    pub const fn ticket(&self) -> &LaunchTicket {
        &self.ticket
    }
}

/// Launch-only request carrying the ticket and owned descriptors to inherit.
///
/// The descriptor vector never crosses the Provider boundary as metadata. It
/// is consumed by the effect backend and is intentionally absent from the
/// clonable [`ProcessRequest`], ticket, diagnostics, and status types.
pub struct ProcessLaunchRequest {
    request: ProcessRequest,
    inherited_fds: Vec<OwnedFd>,
}

impl ProcessLaunchRequest {
    /// Build a launch request whose owned descriptors exactly match the
    /// ticket's private inherited-fd table.
    pub fn new(
        request: ProcessRequest,
        inherited_fds: Vec<OwnedFd>,
    ) -> Result<Self, ProcessConformanceError> {
        let count = u16::try_from(inherited_fds.len())
            .map_err(|_| ProcessConformanceError::InvalidTicket)?;
        let expected = request.ticket().inherited_fd_table().count();
        let broker_escrowed_controller = expected > 0 && count == expected + 1;
        if count > MAX_INHERITED_FDS || (count != expected && !broker_escrowed_controller) {
            return Err(ProcessConformanceError::InvalidTicket);
        }
        Ok(Self {
            request,
            inherited_fds,
        })
    }

    /// Build an ordinary descriptor-free launch request.
    pub fn empty(request: ProcessRequest) -> Result<Self, ProcessConformanceError> {
        Ok(Self {
            request,
            inherited_fds: Vec::new(),
        })
    }

    /// Consume this launch-only request into its ordinary request and owned
    /// descriptor vector.
    pub fn into_parts(self) -> (ProcessRequest, Vec<OwnedFd>) {
        (self.request, self.inherited_fds)
    }
}

impl fmt::Debug for ProcessLaunchRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProcessLaunchRequest(<redacted>)")
    }
}

impl fmt::Debug for ProcessRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProcessRequest(<redacted>)")
    }
}

/// A stable process observation produced before a local handle is opened.
///
/// Sensitive identity material remains inside the effect owner. The Process
/// Provider sees only the digest, the closed verified-binding set, and the
/// closed wait/reap owner.
#[derive(Clone, PartialEq, Eq)]
pub struct BackendObservation {
    identity: ProcessIdentityDigest,
    observed: ObservedIdentity,
    wait_reap_owner: WaitReapOwner,
}

impl BackendObservation {
    /// Record a stable observation after the effect owner verified it.
    pub fn new(
        identity: ProcessIdentityDigest,
        observed: ObservedIdentity,
        wait_reap_owner: WaitReapOwner,
    ) -> Self {
        Self {
            identity,
            observed,
            wait_reap_owner,
        }
    }

    /// Return the opaque stable process identity.
    pub const fn identity(&self) -> ProcessIdentityDigest {
        self.identity
    }

    /// Borrow the exact set of verified identity bindings.
    pub const fn observed(&self) -> &ObservedIdentity {
        &self.observed
    }

    /// Return the effect owner responsible for wait and reap.
    pub const fn wait_reap_owner(&self) -> WaitReapOwner {
        self.wait_reap_owner
    }
}

impl fmt::Debug for BackendObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BackendObservation(<redacted>)")
    }
}

/// A successful backend launch with its locally held process handle.
///
/// For a broker launch the handle owns the descriptor received through
/// `SCM_RIGHTS`. For a service-manager launch it owns the locally verified
/// descriptor associated with the atomic unit observation.
pub struct BackendLaunch<H> {
    observation: BackendObservation,
    handle: H,
}

impl<H> BackendLaunch<H> {
    /// Bind a verified launch observation to its local handle.
    pub fn new(observation: BackendObservation, handle: H) -> Self {
        Self {
            observation,
            handle,
        }
    }

    /// Borrow the verified launch observation.
    pub const fn observation(&self) -> &BackendObservation {
        &self.observation
    }

    /// Split the launch into its observation and local handle.
    pub fn into_parts(self) -> (BackendObservation, H) {
        (self.observation, self.handle)
    }
}

impl<H> fmt::Debug for BackendLaunch<H> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BackendLaunch(<redacted>)")
    }
}

/// Stop class understood by a blocking process effect owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessStopClass {
    /// Request bounded graceful drain.
    Drain,
    /// Terminate the exact verified identity.
    Terminate,
}

/// Closed failures from a core process effect owner.
///
/// Variants carry no caller or host value, making both `Debug` and `Display`
/// safe for errors, audit summaries, and bounded telemetry labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProcessEffectError {
    /// The selected Process Provider has no production effect owner.
    UnsupportedProvider,
    /// Trusted launch configuration could not be resolved.
    ResolutionFailed,
    /// The broker or service manager refused or failed the launch.
    LaunchFailed,
    /// The process could not be observed safely.
    ObserveFailed,
    /// Stable identity changed or could not be verified.
    IdentityChanged,
    /// A verified local descriptor could not be obtained.
    PidfdUnavailable,
    /// The expected process or transient unit no longer exists.
    Vanished,
    /// Wait/reap ownership disagreed with the selected Provider.
    WaitOwnerMismatch,
    /// The bounded blocking adapter had no admission capacity.
    Busy,
    /// The effect did not complete inside the ticket deadline.
    DeadlineExceeded,
    /// The operation deadline passed while the process fate remained unknown.
    FateUnknown,
    /// The exact verified process could not be stopped.
    StopFailed,
}

impl ProcessEffectError {
    /// Return the stable lower-kebab error code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedProvider => "unsupported-provider",
            Self::ResolutionFailed => "resolution-failed",
            Self::LaunchFailed => "launch-failed",
            Self::ObserveFailed => "observe-failed",
            Self::IdentityChanged => "identity-changed",
            Self::PidfdUnavailable => "pidfd-unavailable",
            Self::Vanished => "process-vanished",
            Self::WaitOwnerMismatch => "wait-owner-mismatch",
            Self::Busy => "effect-adapter-busy",
            Self::DeadlineExceeded => "deadline-exceeded",
            Self::FateUnknown => "process-fate-unknown",
            Self::StopFailed => "stop-failed",
        }
    }
}

impl fmt::Display for ProcessEffectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ProcessEffectError {}

/// Blocking core-owned process effect operations.
///
/// Implementations may perform broker socket, service-manager, kernel, and
/// filesystem I/O. [`d2b_provider_supervisor`](https://docs.rs/d2b-provider-supervisor)
/// always invokes these methods on its bounded blocking adapter, never on the
/// Process controller's async executor thread.
pub trait ProcessEffectBackend: Send + Sync + 'static {
    /// Local process authority retained by the core adapter.
    type Handle: Send + Sync + 'static;

    /// Resolve and launch one ticket, returning mandatory local authority.
    fn launch(
        &self,
        request: ProcessRequest,
    ) -> Result<BackendLaunch<Self::Handle>, ProcessEffectError>;

    /// Launch with owned descriptors that must be inherited by the child.
    ///
    /// Existing effect owners remain descriptor-free by default. A concrete
    /// owner must opt in explicitly before it can receive a non-empty
    /// launch-only descriptor vector.
    fn launch_with_inherited_fds(
        &self,
        request: ProcessLaunchRequest,
    ) -> Result<BackendLaunch<Self::Handle>, ProcessEffectError> {
        let (request, inherited_fds) = request.into_parts();
        if !inherited_fds.is_empty() {
            return Err(ProcessEffectError::LaunchFailed);
        }
        self.launch(request)
    }

    /// Observe a candidate without opening a new local descriptor.
    fn observe(
        &self,
        request: ProcessRequest,
    ) -> Result<Option<BackendObservation>, ProcessEffectError>;

    /// Probe a candidate without retaining an adoption observation.
    ///
    /// Production effect owners override this when their ordinary
    /// [`Self::observe`] path stages an observation for a later pidfd open.
    /// Readiness and liveness callers must use this non-mutating seam.
    fn probe(
        &self,
        request: ProcessRequest,
    ) -> Result<Option<BackendObservation>, ProcessEffectError> {
        self.observe(request)
    }

    /// Re-verify an observation and open fresh local authority.
    fn open_pidfd(
        &self,
        observation: BackendObservation,
    ) -> Result<Self::Handle, ProcessEffectError>;

    /// Wait for the exact local authority to become readable.
    ///
    /// This observes process termination without exposing the descriptor to
    /// Provider code. Service-manager owners may use the same readiness
    /// signal without taking ownership of reap.
    fn wait(
        &self,
        _handle: &Self::Handle,
        _timeout: Duration,
    ) -> Result<(), ProcessEffectError> {
        Err(ProcessEffectError::PidfdUnavailable)
    }

    /// Take a broker-retained Provider-controller bootstrap endpoint.
    fn take_controller_bootstrap(
        &self,
        _handle: &Self::Handle,
    ) -> Result<Option<OwnedFd>, ProcessEffectError> {
        Ok(None)
    }

    /// Stop only the exact process represented by `handle`.
    ///
    /// A successful [`ProcessStopClass::Terminate`] result certifies that the
    /// represented process no longer survives. Accepting a signal or stop
    /// request without confirming exit is not success.
    fn stop(
        &self,
        handle: &Self::Handle,
        class: ProcessStopClass,
    ) -> Result<(), ProcessEffectError>;

    /// Release broker or service-manager registration after terminal exit.
    ///
    /// This is deliberately separate from [`Self::stop`]: a process can exit
    /// naturally without a stop request, but the core-owned effect owner must
    /// still remove its exact registration before the identity is forgotten.
    fn finalize(&self, _handle: &Self::Handle) -> Result<(), ProcessEffectError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use d2b_process_conformance::testing::fixtures;

    #[test]
    fn launch_request_rejects_inherited_fd_count_mismatch() {
        let ticket = fixtures::ticket_builder().build().expect("ticket");
        let read_fd: OwnedFd = std::fs::File::open("/dev/null")
            .expect("open test descriptor")
            .into();
        let error = ProcessLaunchRequest::new(ProcessRequest::new(ticket), vec![read_fd])
            .expect_err("descriptor count must match the ticket");
        assert_eq!(error, ProcessConformanceError::InvalidTicket);
    }

    #[test]
    fn launch_request_debug_redacts_owned_descriptors() {
        let ticket = fixtures::ticket_builder().build().expect("ticket");
        let request = ProcessLaunchRequest::empty(ProcessRequest::new(ticket)).expect("request");
        assert_eq!(format!("{request:?}"), "ProcessLaunchRequest(<redacted>)");
    }

    #[test]
    fn diagnostics_are_value_free() {
        let request = ProcessRequest::new(fixtures::ticket_builder().build().unwrap());
        let observation = BackendObservation::new(
            ProcessIdentityDigest::from_bytes([7; 32]),
            ObservedIdentity::default(),
            WaitReapOwner::Local,
        );
        assert_eq!(format!("{request:?}"), "ProcessRequest(<redacted>)");
        assert_eq!(format!("{observation:?}"), "BackendObservation(<redacted>)");
        assert_eq!(
            format!("{:?}", BackendLaunch::new(observation, ())),
            "BackendLaunch(<redacted>)"
        );
        for error in [
            ProcessEffectError::ResolutionFailed,
            ProcessEffectError::LaunchFailed,
            ProcessEffectError::IdentityChanged,
            ProcessEffectError::PidfdUnavailable,
            ProcessEffectError::Vanished,
            ProcessEffectError::WaitOwnerMismatch,
            ProcessEffectError::Busy,
            ProcessEffectError::DeadlineExceeded,
            ProcessEffectError::FateUnknown,
            ProcessEffectError::StopFailed,
        ] {
            assert_eq!(error.to_string(), error.code());
        }
    }
}
