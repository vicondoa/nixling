//! Minijail launch admission and mandatory platform gate.

use d2b_process_conformance::{
    AdoptionOutcome, LaunchTicket, ProcessConformanceError, ProcessIdentityDigest, ProcessProvider,
    ProcessStatusReport, StopClass,
};

use crate::PROVIDER_NAME;

/// Linux placement requirements that cannot be downgraded by config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformGate {
    /// Kernel major.
    pub kernel_major: u16,
    /// Kernel minor.
    pub kernel_minor: u16,
    /// Whether the runtime cgroup exposes cgroup.kill.
    pub cgroup_kill_available: bool,
}

impl PlatformGate {
    /// Construct a gate from daemon-owned host observations.
    pub const fn from_observed(
        kernel_major: u16,
        kernel_minor: u16,
        cgroup_kill_available: bool,
    ) -> Self {
        Self {
            kernel_major,
            kernel_minor,
            cgroup_kill_available,
        }
    }

    /// Construct a platform snapshot for hermetic conformance tests.
    pub const fn new_for_test(
        kernel_major: u16,
        kernel_minor: u16,
        cgroup_kill_available: bool,
    ) -> Self {
        Self::from_observed(kernel_major, kernel_minor, cgroup_kill_available)
    }

    /// Check Linux 5.14 and cgroup.kill.
    pub const fn validate(self) -> Result<(), ProcessConformanceError> {
        if self.kernel_major < 5
            || (self.kernel_major == 5 && self.kernel_minor < 14)
            || !self.cgroup_kill_available
        {
            Err(ProcessConformanceError::PlatformGateRejected)
        } else {
            Ok(())
        }
    }
}

/// Validate provider identity and platform evidence before spawn dispatch.
pub fn validate_launch_ticket(
    ticket: &LaunchTicket,
    gate: PlatformGate,
) -> Result<(), ProcessConformanceError> {
    if ticket.selected_provider().as_str() != PROVIDER_NAME
        || ticket.provider_ref().to_canonical_string() != "Provider/system-minijail"
    {
        return Err(ProcessConformanceError::ProviderMismatch);
    }
    gate.validate()
}

/// One typed action accepted by the minijail Process handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MinijailReconcileAction<'a> {
    /// Launch a new Process or EphemeralProcess.
    Start(&'a LaunchTicket),
    /// Adopt a matching running process after restart.
    Adopt(&'a LaunchTicket),
    /// Stop one exact process identity.
    Stop(&'a ProcessIdentityDigest, StopClass),
}

/// Result of one minijail handler action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MinijailReconcileResult {
    /// The effect owner launched a process.
    Started(ProcessStatusReport),
    /// Adoption was evaluated.
    Adoption(AdoptionOutcome),
    /// The exact process stop was accepted.
    Stopped,
}

/// Dispatch one typed action without exposing the broker or a raw process
/// handle to the Provider.
pub async fn reconcile<P: d2b_process_conformance::ProcessLaunchEffectPort>(
    provider: &crate::MinijailProcessProvider<P>,
    action: MinijailReconcileAction<'_>,
) -> Result<MinijailReconcileResult, ProcessConformanceError> {
    match action {
        MinijailReconcileAction::Start(ticket) => provider
            .launch(ticket)
            .await
            .map(MinijailReconcileResult::Started),
        MinijailReconcileAction::Adopt(ticket) => provider
            .adopt(ticket)
            .await
            .map(MinijailReconcileResult::Adoption),
        MinijailReconcileAction::Stop(identity, class) => provider
            .stop(identity, class)
            .await
            .map(|_| MinijailReconcileResult::Stopped),
    }
}
