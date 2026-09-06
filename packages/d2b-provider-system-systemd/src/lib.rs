//! The `system-systemd` Process Provider controller.
//!
//! A process is a **non-forking transient system unit or scope**. Identity is
//! the unit InvocationID bound together
//! with the cgroup, the unit main process, that process's start time, and
//! the Provider, template, and generation triple. A unit name alone is
//! never identity, so it is neither an identity binding nor public status.
//! systemd owns `wait` and reap; this Provider holds only a locally
//! verified pidfd.
//!
//! Adapted from the earlier non-forking `systemd-run` transient-unit launch
//! contract.
//!
//! This crate performs no privileged mutation: it opens no D-Bus or systemd
//! socket, spawns no process, and resolves no unit name or path. It
//! validates the ticket and calls the injected
//! [`ProcessLaunchEffectPort`], which the fixed core process effect adapter
//! implements.

#![deny(missing_docs)]

pub mod adoption;
pub mod audit;
pub mod controller;
pub mod drain;
pub mod effect_port;
pub mod error;
pub mod guest_exec;
pub mod launch;
pub mod lifecycle;
pub mod manifest;
pub mod metrics;
pub mod sandbox;

pub use guest_exec::{
    AttachRequest, ComponentSessionAttachment, GuestExecError, GuestExecPort, GuestExecRequest,
    NamedAttachmentStream, TtySize,
};
pub use lifecycle::{
    EphemeralProcessController, RestartPolicy, SystemdConfigError, SystemdProviderConfig,
};
pub use manifest::SystemdManifest;

use std::collections::BTreeSet;

use d2b_contracts_resource::v3::execution_policy::{BoundedToken, ExecutionDomain};
use d2b_process_conformance::{
    AdoptionCandidate, AdoptionCondition, AdoptionOutcome, CancellationBinding, IdentityBinding,
    LaunchTicket, LaunchedProcess, ProcessConformanceError, ProcessIdentityDigest,
    ProcessLaunchEffectPort, ProcessPhaseClass, ProcessProvider, ProcessProviderProfile,
    ProcessStatusReport, ReadinessExpectation, StopClass, WaitReapOwner,
};

/// The Provider name this controller implements.
pub const PROVIDER_NAME: &str = "system-systemd";

/// The `system-systemd` Process Provider controller.
#[derive(Debug)]
pub struct SystemdProcessProvider<P: ProcessLaunchEffectPort> {
    port: P,
    profile: ProcessProviderProfile,
}

impl<P: ProcessLaunchEffectPort> SystemdProcessProvider<P> {
    /// Build the controller over an injected process effect port.
    ///
    /// The broker verifies both system and authenticated user-manager
    /// transient-unit paths before the effect reaches systemd.
    pub fn new(port: P) -> Self {
        let profile = ProcessProviderProfile::new(
            BoundedToken::parse(PROVIDER_NAME).expect("the frozen provider name is a valid token"),
            WaitReapOwner::ServiceManager,
            BTreeSet::from([ExecutionDomain::System, ExecutionDomain::User]),
            BTreeSet::from([
                IdentityBinding::UnitInvocationId,
                IdentityBinding::Cgroup,
                IdentityBinding::UnitMainPid,
                IdentityBinding::ProcessStartTime,
                IdentityBinding::Template,
                IdentityBinding::Generation,
            ]),
        )
        .expect("the frozen system-systemd profile is well formed");
        Self { port, profile }
    }

    /// Borrow the injected effect port.
    pub const fn port(&self) -> &P {
        &self.port
    }

    fn validate(&self, ticket: &LaunchTicket) -> Result<(), ProcessConformanceError> {
        ticket.validate()?;
        if ticket.has_controller_launch_binding() {
            ticket.validate_controller_launch()?;
        }
        if ticket.has_assignment_binding() {
            ticket.validate_assignment()?;
        }
        if ticket.selected_provider().as_str() != PROVIDER_NAME {
            return Err(ProcessConformanceError::ProviderMismatch);
        }
        if !self.profile.supported_domains().contains(&ticket.domain()) {
            return Err(ProcessConformanceError::DomainNotSupported);
        }
        if ticket.operation().cancellation() == CancellationBinding::Cancelled {
            return Err(ProcessConformanceError::Cancelled);
        }
        if ticket.domain() == ExecutionDomain::User && ticket.user_ref().is_none() {
            return Err(ProcessConformanceError::UserRefRequired);
        }
        Ok(())
    }

    async fn cleanup_failed_launch(
        &self,
        launched: &LaunchedProcess,
        error: ProcessConformanceError,
    ) -> ProcessConformanceError {
        if launched.identity.is_zero() {
            return error;
        }
        match self
            .port
            .stop(&launched.identity, StopClass::Terminate)
            .await
        {
            Ok(()) => error,
            Err(_) => ProcessConformanceError::StopUnavailable,
        }
    }

    async fn readiness_phase(
        &self,
        ticket: &LaunchTicket,
        identity: ProcessIdentityDigest,
    ) -> Result<ProcessPhaseClass, ProcessConformanceError> {
        match ticket.readiness() {
            ReadinessExpectation::None => Ok(ProcessPhaseClass::Running),
            ReadinessExpectation::Condition { .. } => {
                // The fixed adapter's probe is the readiness observation;
                // it does not open or retain another pidfd.
                let Some(candidate) = self.port.probe(ticket).await? else {
                    return Err(ProcessConformanceError::DeadlineExceeded);
                };
                if !self.candidate_matches(ticket, &candidate, identity) {
                    return Err(ProcessConformanceError::AdoptionAmbiguous);
                }
                Ok(ProcessPhaseClass::Ready)
            }
        }
    }

    fn candidate_matches(
        &self,
        ticket: &LaunchTicket,
        candidate: &AdoptionCandidate,
        identity: ProcessIdentityDigest,
    ) -> bool {
        candidate.identity == identity
            && candidate.wait_reap_owner == WaitReapOwner::ServiceManager
            && candidate
                .validate(self.profile.required_identity_bindings())
                .is_ok()
            && ticket
                .validate_process_identity(&candidate.identity)
                .is_ok()
    }

    fn report(
        &self,
        ticket: &LaunchTicket,
        identity: d2b_process_conformance::ProcessIdentityDigest,
        phase: ProcessPhaseClass,
        adoption: AdoptionCondition,
    ) -> ProcessStatusReport {
        ProcessStatusReport {
            provider: self.profile.provider().clone(),
            identity,
            wait_reap_owner: self.profile.wait_reap_owner(),
            execution_ref: ticket.execution_ref().clone(),
            domain: ticket.domain(),
            user_ref: ticket.user_ref().cloned(),
            digests: *ticket.digests(),
            phase,
            last_exit: None,
            adoption,
        }
    }
}

impl<P: ProcessLaunchEffectPort> ProcessProvider for SystemdProcessProvider<P> {
    fn profile(&self) -> &ProcessProviderProfile {
        &self.profile
    }

    async fn launch(
        &self,
        ticket: &LaunchTicket,
    ) -> Result<ProcessStatusReport, ProcessConformanceError> {
        self.validate(ticket)?;
        let launched = self.port.launch(ticket).await?;
        if launched.wait_reap_owner != WaitReapOwner::ServiceManager {
            return Err(ProcessConformanceError::WaitOwnerMismatch);
        }
        launched.validate(self.profile.required_identity_bindings())?;
        ticket.validate_process_identity(&launched.identity)?;
        match self.readiness_phase(ticket, launched.identity).await {
            Ok(phase) => Ok(self.report(
                ticket,
                launched.identity,
                phase,
                AdoptionCondition::NotApplicable,
            )),
            Err(error) => Err(self.cleanup_failed_launch(&launched, error).await),
        }
    }

    async fn adopt(
        &self,
        ticket: &LaunchTicket,
    ) -> Result<AdoptionOutcome, ProcessConformanceError> {
        self.validate(ticket)?;
        let Some(candidate) = self.port.observe(ticket).await? else {
            return Ok(AdoptionOutcome::Absent);
        };
        // Revalidate every stable identity property before the pidfd is
        // opened. Ambiguity quarantines; it never broadly kills or reuses.
        let identity_ok = candidate.wait_reap_owner == WaitReapOwner::ServiceManager
            && candidate
                .validate(self.profile.required_identity_bindings())
                .is_ok()
            && ticket
                .validate_process_identity(&candidate.identity)
                .is_ok();
        if !identity_ok {
            return Ok(AdoptionOutcome::Quarantined(self.report(
                ticket,
                candidate.identity,
                ProcessPhaseClass::Unknown,
                AdoptionCondition::Quarantined,
            )));
        }
        let phase = match self.readiness_phase(ticket, candidate.identity).await {
            Ok(phase) => phase,
            Err(_) => {
                return Ok(AdoptionOutcome::Quarantined(self.report(
                    ticket,
                    candidate.identity,
                    ProcessPhaseClass::Unknown,
                    AdoptionCondition::Quarantined,
                )));
            }
        };
        let _pidfd = self.port.open_pidfd(&candidate).await?;
        Ok(AdoptionOutcome::Adopted(self.report(
            ticket,
            candidate.identity,
            phase,
            AdoptionCondition::Adopted,
        )))
    }

    async fn stop(
        &self,
        identity: &ProcessIdentityDigest,
        class: StopClass,
    ) -> Result<(), ProcessConformanceError> {
        if identity.is_zero() {
            return Err(ProcessConformanceError::IdentityUnverified);
        }
        self.port.stop(identity, class).await
    }

    async fn stop_stale(
        &self,
        candidate: &AdoptionCandidate,
    ) -> Result<(), ProcessConformanceError> {
        if candidate.identity.is_zero()
            || candidate.wait_reap_owner != WaitReapOwner::ServiceManager
        {
            return Err(ProcessConformanceError::IdentityUnverified);
        }
        self.port.open_pidfd(candidate).await?;
        self.port
            .stop(&candidate.identity, StopClass::Terminate)
            .await
    }
}
