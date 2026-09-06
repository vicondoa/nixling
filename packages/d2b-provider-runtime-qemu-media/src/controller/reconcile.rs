//! QEMU media Guest lifecycle controller.

use crate::{
    adoption::{AdoptionOutcome, ProcessIdentity, verify_identity},
    config::{ProviderConfig, ProviderConfigError},
    controller::process_builder::{PROCESS_TEMPLATE, validate_process_spec},
    controller::{
        DeviceAdmission, DeviceAdmissionError, DeviceObservation, LaunchTicket, ProcessSpec,
        ProcessSpecError,
    },
    qmp::QmpVmStatus,
    types::{GuestProviderSpecSettings, GuestSpecError},
};
use d2b_contracts_resource::v3::ResourceRef;
use std::marker::PhantomData;

/// QEMU media lifecycle phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QemuMediaPhase {
    /// Dependencies are pending.
    Pending,
    /// The QEMU Process is starting.
    Starting,
    /// Waiting for QMP greeting and capability negotiation.
    WaitingQmp,
    /// QEMU is paused after QMP readiness.
    PausedAtBoot,
    /// QEMU is running.
    Ready,
    /// A retryable observation or cleanup failed.
    Degraded,
    /// The current generation failed closed.
    Failed,
    /// Finalizer cleanup is in progress.
    Finalizing,
    /// Finalizer cleanup completed.
    Finalized,
}

/// Default descriptor repair interval.
pub const QEMU_MEDIA_REPAIR_INTERVAL_SECS: u64 = 30;

/// The shared-Runner contract for the qemu-media Guest owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QemuMediaRunnerContract {
    resource_type: &'static str,
    finalizer: &'static str,
    repair_interval_secs: u64,
    watched_configuration_is_dependency: bool,
}

impl QemuMediaRunnerContract {
    /// Return the owned ResourceType.
    pub const fn resource_type(self) -> &'static str {
        self.resource_type
    }

    /// Return the exact Guest finalizer.
    pub const fn finalizer(self) -> &'static str {
        self.finalizer
    }

    /// Return the bounded repair interval.
    pub const fn repair_interval_secs(self) -> u64 {
        self.repair_interval_secs
    }

    /// Whether watched configuration is treated as a dependency.
    pub const fn watched_configuration_is_dependency(self) -> bool {
        self.watched_configuration_is_dependency
    }
}

/// Return the shared-Runner contract for qemu-media Guests.
pub const fn qemu_media_runner_contract() -> QemuMediaRunnerContract {
    QemuMediaRunnerContract {
        resource_type: "Guest",
        finalizer: crate::FINALIZER,
        repair_interval_secs: QEMU_MEDIA_REPAIR_INTERVAL_SECS,
        watched_configuration_is_dependency: true,
    }
}

/// Reconcile result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QemuMediaReconcileOutcome {
    /// Process and device health converged.
    Ready,
    /// Dependencies or health require a retry.
    Retry {
        /// Suggested retry delay in milliseconds.
        after_ms: u32,
    },
    /// The current state was degraded but not terminal.
    Degraded,
}

/// Closed QEMU media controller failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QemuMediaError {
    /// Provider or Process configuration is invalid.
    InvalidConfiguration,
    /// A dependency is absent or not ready.
    DependencyNotReady,
    /// Device admission failed.
    Device(DeviceAdmissionError),
    /// Process identity was ambiguous.
    AdoptionAmbiguous,
    /// A typed effect failed.
    Effect,
    /// QMP health did not become ready.
    QmpNotReady,
    /// Finalization could not prove process closure.
    FinalizationIncomplete,
    /// The controller cannot accept a normal reconcile transition.
    InvalidState,
}

impl QemuMediaError {
    /// Return the stable Provider error code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidConfiguration => "runtime-qemu-media-invalid-configuration",
            Self::DependencyNotReady => "dependency-not-ready",
            Self::Device(error) => error.code(),
            Self::AdoptionAmbiguous => "process-adoption-ambiguous",
            Self::Effect => "runtime-qemu-media-effect-failed",
            Self::QmpNotReady => "qmp-greeting-timeout",
            Self::FinalizationIncomplete => "runtime-qemu-media-finalization-incomplete",
            Self::InvalidState => "runtime-qemu-media-invalid-state",
        }
    }
}

impl core::fmt::Display for QemuMediaError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for QemuMediaError {}

impl From<ProviderConfigError> for QemuMediaError {
    fn from(_: ProviderConfigError) -> Self {
        Self::InvalidConfiguration
    }
}

impl From<GuestSpecError> for QemuMediaError {
    fn from(_: GuestSpecError) -> Self {
        Self::InvalidConfiguration
    }
}

impl From<ProcessSpecError> for QemuMediaError {
    fn from(_: ProcessSpecError) -> Self {
        Self::InvalidConfiguration
    }
}

/// Dependency snapshot supplied by Core's authenticated watch path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QemuMediaDependencies {
    /// KVM Device observation.
    pub device: Option<DeviceObservation>,
    /// Network dependencies are all ready.
    pub network_ready: bool,
    /// Media Volume dependencies are all ready.
    pub media_ready: bool,
    /// Optional display dependency is ready.
    pub display_ready: bool,
    /// QMP Endpoint greeting and capability exchange completed.
    pub qmp_ready: bool,
    /// Current QMP VM state.
    pub qmp_status: Option<QmpVmStatus>,
    /// Authorized media Volume refs for the LaunchTicket.
    pub media_refs: Vec<ResourceRef>,
    /// Authorized display Endpoint ref for the LaunchTicket.
    pub display_ref: Option<ResourceRef>,
    /// Controller-created runtime Volume is Ready.
    pub runtime_volume_ready: bool,
    /// Elapsed seconds in the current initial QMP greeting wait.
    pub qmp_elapsed_seconds: u32,
}

impl Default for QemuMediaDependencies {
    fn default() -> Self {
        Self {
            device: None,
            network_ready: false,
            media_ready: false,
            display_ready: true,
            qmp_ready: false,
            qmp_status: None,
            media_refs: Vec::new(),
            display_ref: None,
            runtime_volume_ready: false,
            qmp_elapsed_seconds: 0,
        }
    }
}

impl QemuMediaDependencies {
    /// Construct a fully-ready dependency snapshot.
    pub fn ready(device: DeviceObservation) -> Self {
        Self {
            device: Some(device),
            network_ready: true,
            media_ready: true,
            display_ready: true,
            qmp_ready: true,
            qmp_status: Some(QmpVmStatus::Paused),
            media_refs: Vec::new(),
            display_ref: None,
            runtime_volume_ready: true,
            qmp_elapsed_seconds: 0,
        }
    }
}

/// Typed effect boundary owned by Core/ProviderSupervisor.
pub trait QemuMediaEffectPort {
    /// Launch the broker-spawned Process from an opaque LaunchTicket.
    fn launch(&mut self, ticket: &LaunchTicket) -> Result<ProcessIdentity, QemuMediaError>;
    /// Observe an existing candidate without opening a pidfd.
    fn observe(&mut self) -> Result<Option<ProcessIdentity>, QemuMediaError>;
    /// Open a pidfd after identity verification.
    fn open_pidfd(&mut self, identity: &ProcessIdentity) -> Result<(), QemuMediaError>;
    /// Reserve the Host-global Device authority before launch or adoption.
    fn reserve_device_authority(
        &mut self,
        authority_key: [u8; 32],
        owner_ref: &ResourceRef,
    ) -> Result<(), QemuMediaError>;
    /// Close all QMP/media effects before stopping the Process.
    fn close_media_effects(&mut self) -> Result<(), QemuMediaError>;
    /// Continue a paused Guest when pauseAtBoot is false.
    fn continue_guest(&mut self) -> Result<(), QemuMediaError>;
    /// Stop exactly one verified Process.
    fn stop(&mut self, identity: &ProcessIdentity) -> Result<(), QemuMediaError>;
    /// Release the retained Host-global Device authority.
    fn release_device_authority(&mut self) -> Result<(), QemuMediaError>;
    /// Delete the controller-created runtime Volume after Process exit.
    fn delete_runtime_volume(&mut self) -> Result<(), QemuMediaError>;
}

/// Durable non-secret recovery state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QemuMediaRecoveryState {
    /// Current phase.
    pub phase: QemuMediaPhase,
    /// Whether the finalizer remains installed.
    pub finalizer_installed: bool,
    /// Expected process identity, if a prior launch committed it.
    pub expected_identity: Option<ProcessIdentity>,
    /// Whether authority was reserved.
    pub authority_reserved: bool,
    /// Whether the pause-at-boot initial state was observed.
    pub initial_pause_observed: bool,
}

/// QEMU media lifecycle controller.
pub struct QemuMediaController<E> {
    config: crate::config::ControllerConfigProjection,
    settings: GuestProviderSpecSettings,
    process: ProcessSpec,
    guest_ref: ResourceRef,
    phase: QemuMediaPhase,
    expected_identity: Option<ProcessIdentity>,
    finalizer_installed: bool,
    authority_reserved: bool,
    initial_qmp_wait_pending: bool,
    initial_pause_observed: bool,
    pidfd_opened: bool,
    media_closed: bool,
    process_stopped: bool,
    authority_released: bool,
    runtime_volume_deleted: bool,
    marker: PhantomData<E>,
}

impl<E> QemuMediaController<E> {
    /// Construct a controller with explicit Provider and Process contracts.
    pub fn new(
        config: ProviderConfig,
        settings: GuestProviderSpecSettings,
        process: ProcessSpec,
        guest_ref: ResourceRef,
    ) -> Result<Self, QemuMediaError> {
        config.validate()?;
        let config = config.project_controller();
        settings.validate()?;
        validate_process_spec(&process)?;
        if guest_ref.resource_type().as_str() != "Guest" {
            return Err(QemuMediaError::InvalidConfiguration);
        }
        Ok(Self {
            config,
            settings,
            process,
            guest_ref,
            phase: QemuMediaPhase::Pending,
            expected_identity: None,
            finalizer_installed: true,
            authority_reserved: false,
            initial_qmp_wait_pending: false,
            initial_pause_observed: false,
            pidfd_opened: false,
            media_closed: false,
            process_stopped: false,
            authority_released: false,
            runtime_volume_deleted: false,
            marker: PhantomData,
        })
    }

    /// Return the current phase.
    pub const fn phase(&self) -> QemuMediaPhase {
        self.phase
    }

    /// Return whether the Guest finalizer remains installed.
    pub const fn finalizer_installed(&self) -> bool {
        self.finalizer_installed
    }

    /// Set the durable expected identity used for restart adoption.
    pub fn set_expected_identity(&mut self, identity: ProcessIdentity) {
        self.expected_identity = Some(identity);
    }

    /// Export non-secret restart state.
    pub fn recovery_state(&self) -> QemuMediaRecoveryState {
        QemuMediaRecoveryState {
            phase: self.phase,
            finalizer_installed: self.finalizer_installed,
            expected_identity: self.expected_identity.clone(),
            authority_reserved: self.authority_reserved,
            initial_pause_observed: self.initial_pause_observed,
        }
    }

    /// Restore non-secret restart state.
    pub fn restore_recovery_state(
        mut self,
        recovery: QemuMediaRecoveryState,
    ) -> Result<Self, QemuMediaError> {
        if !recovery.finalizer_installed && recovery.phase != QemuMediaPhase::Finalized {
            return Err(QemuMediaError::InvalidConfiguration);
        }
        self.phase = recovery.phase;
        self.finalizer_installed = recovery.finalizer_installed;
        self.expected_identity = recovery.expected_identity;
        self.authority_reserved =
            recovery.authority_reserved && recovery.phase != QemuMediaPhase::Finalized;
        self.initial_qmp_wait_pending = false;
        self.initial_pause_observed = recovery.initial_pause_observed;
        self.pidfd_opened = false;
        self.media_closed = false;
        self.process_stopped = recovery.phase == QemuMediaPhase::Finalized;
        self.authority_released = recovery.phase == QemuMediaPhase::Finalized;
        self.runtime_volume_deleted = recovery.phase == QemuMediaPhase::Finalized;
        Ok(self)
    }

    /// Test-only state setup used by hermetic finalizer tests.
    #[doc(hidden)]
    pub fn mark_ready_for_test(&mut self) {
        self.phase = QemuMediaPhase::Ready;
        self.finalizer_installed = true;
        self.authority_reserved = true;
        self.initial_pause_observed = self.settings.pause_at_boot;
    }
}

impl<E: QemuMediaEffectPort> QemuMediaController<E> {
    /// Reconcile dependencies, process identity, and QMP readiness.
    pub fn reconcile(
        &mut self,
        dependencies: &QemuMediaDependencies,
        effect: &mut E,
    ) -> Result<QemuMediaReconcileOutcome, QemuMediaError> {
        if !self.finalizer_installed
            || matches!(
                self.phase,
                QemuMediaPhase::Failed | QemuMediaPhase::Finalizing | QemuMediaPhase::Finalized
            )
        {
            return Err(QemuMediaError::InvalidState);
        }
        let Some(device) = dependencies.device.as_ref() else {
            self.phase = QemuMediaPhase::Pending;
            return Ok(QemuMediaReconcileOutcome::Retry { after_ms: 500 });
        };
        if !dependencies.network_ready
            || !dependencies.media_ready
            || !dependencies.runtime_volume_ready
            || (self.settings.display_window && !dependencies.display_ready)
        {
            self.phase = QemuMediaPhase::Pending;
            return Ok(QemuMediaReconcileOutcome::Retry { after_ms: 500 });
        }
        let expected_process = PROCESS_TEMPLATE;
        DeviceAdmission::validate(&self.guest_ref, device, expected_process, "qemu-media/v1")
            .map_err(QemuMediaError::Device)?;
        if !self.authority_reserved {
            effect.reserve_device_authority(device.authority_key, &self.guest_ref)?;
            self.authority_reserved = true;
        }

        let observed = effect.observe()?;
        let identity = match observed {
            Some(candidate) => {
                let Some(expected) = self.expected_identity.as_ref() else {
                    self.phase = QemuMediaPhase::Degraded;
                    return Err(QemuMediaError::AdoptionAmbiguous);
                };
                if verify_identity(expected, &candidate) != AdoptionOutcome::Adopted {
                    self.phase = QemuMediaPhase::Degraded;
                    return Err(QemuMediaError::AdoptionAmbiguous);
                }
                self.phase = QemuMediaPhase::Starting;
                if !self.pidfd_opened {
                    effect.open_pidfd(&candidate)?;
                    self.pidfd_opened = true;
                }
                candidate
            }
            None => {
                if self.expected_identity.is_some() {
                    self.phase = QemuMediaPhase::Failed;
                    return Err(QemuMediaError::AdoptionAmbiguous);
                }
                self.phase = QemuMediaPhase::Starting;
                let ticket = LaunchTicket::new(
                    self.process.clone(),
                    dependencies.media_refs.clone(),
                    dependencies.display_ref.clone(),
                )?;
                let candidate = effect.launch(&ticket)?;
                if !candidate.matches_process_token(expected_process) {
                    let _ = effect.stop(&candidate);
                    self.phase = QemuMediaPhase::Failed;
                    return Err(QemuMediaError::AdoptionAmbiguous);
                }
                if let Err(error) = effect.open_pidfd(&candidate) {
                    let _ = effect.stop(&candidate);
                    self.phase = QemuMediaPhase::Failed;
                    return Err(error);
                }
                self.pidfd_opened = true;
                self.expected_identity = Some(candidate.clone());
                self.initial_qmp_wait_pending = true;
                candidate
            }
        };

        if !dependencies.qmp_ready {
            if self.initial_qmp_wait_pending
                && dependencies.qmp_elapsed_seconds >= self.config.qmp_ready_timeout_seconds
            {
                self.initial_qmp_wait_pending = false;
                self.phase = QemuMediaPhase::Failed;
                if effect.stop(&identity).is_ok() && matches!(effect.observe(), Ok(None)) {
                    self.process_stopped = true;
                    if self.authority_reserved && !self.authority_released {
                        effect.release_device_authority()?;
                        self.authority_released = true;
                        self.authority_reserved = false;
                    }
                }
                return Err(QemuMediaError::QmpNotReady);
            }
            self.phase = if self.initial_qmp_wait_pending {
                QemuMediaPhase::WaitingQmp
            } else {
                QemuMediaPhase::Degraded
            };
            return Ok(QemuMediaReconcileOutcome::Retry { after_ms: 250 });
        }
        self.initial_qmp_wait_pending = false;
        let Some(qmp_status) = dependencies.qmp_status else {
            self.phase = QemuMediaPhase::WaitingQmp;
            return Ok(QemuMediaReconcileOutcome::Retry { after_ms: 250 });
        };
        match qmp_status {
            QmpVmStatus::Stopped => {
                self.phase = QemuMediaPhase::Failed;
                return Err(QemuMediaError::QmpNotReady);
            }
            QmpVmStatus::Paused if !self.settings.pause_at_boot => {
                effect.continue_guest()?;
            }
            QmpVmStatus::Paused => {
                self.initial_pause_observed = true;
            }
            QmpVmStatus::Running if self.settings.pause_at_boot && !self.initial_pause_observed => {
                self.phase = QemuMediaPhase::Degraded;
                return Err(QemuMediaError::QmpNotReady);
            }
            QmpVmStatus::Running => {}
        }
        self.expected_identity = Some(identity);
        self.phase = if self.settings.pause_at_boot && matches!(qmp_status, QmpVmStatus::Paused) {
            QemuMediaPhase::PausedAtBoot
        } else {
            QemuMediaPhase::Ready
        };
        Ok(QemuMediaReconcileOutcome::Ready)
    }

    /// Finalize QMP/media effects, then stop the Process and release authority.
    pub fn finalize(&mut self, effect: &mut E) -> Result<(), QemuMediaError> {
        if !self.finalizer_installed {
            return Ok(());
        }
        self.phase = QemuMediaPhase::Finalizing;
        if !self.media_closed {
            effect.close_media_effects()?;
            self.media_closed = true;
        }
        let observed = effect.observe()?;
        if self.expected_identity.is_none() && observed.is_some() {
            self.phase = QemuMediaPhase::Degraded;
            return Err(QemuMediaError::AdoptionAmbiguous);
        }
        if let Some(identity) = self.expected_identity.as_ref() {
            if let Some(candidate) = observed {
                if verify_identity(identity, &candidate) != AdoptionOutcome::Adopted {
                    self.phase = QemuMediaPhase::Degraded;
                    return Err(QemuMediaError::AdoptionAmbiguous);
                }
                if !self.pidfd_opened {
                    effect.open_pidfd(&candidate)?;
                    self.pidfd_opened = true;
                }
                if !self.process_stopped {
                    effect.stop(identity)?;
                    self.process_stopped = true;
                }
                if effect.observe()?.is_some() {
                    self.phase = QemuMediaPhase::Degraded;
                    return Err(QemuMediaError::FinalizationIncomplete);
                }
            } else {
                self.process_stopped = true;
            }
        }
        if self.authority_reserved && !self.authority_released {
            effect.release_device_authority()?;
            self.authority_released = true;
            self.authority_reserved = false;
        }
        if !self.runtime_volume_deleted {
            effect.delete_runtime_volume()?;
            self.runtime_volume_deleted = true;
        }
        self.finalizer_installed = false;
        self.phase = QemuMediaPhase::Finalized;
        Ok(())
    }

    /// Borrow the controller's Provider configuration projection.
    pub const fn config(&self) -> &crate::config::ControllerConfigProjection {
        &self.config
    }
}
