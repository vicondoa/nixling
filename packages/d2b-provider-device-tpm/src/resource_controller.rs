//! Device TPM child-resource lifecycle controller.

use d2b_contracts_resource::v3::{ResourceRef, ResourceUid};
use serde::Serialize;

use crate::resource_effect::{TpmResourceEffectError, TpmResourceEffectPort};
use crate::status::{TpmMarkerStatus, TpmStatusReport};

/// Default descriptor repair interval.
pub const TPM_REPAIR_INTERVAL_SECS: u64 = 30;
/// Maximum descriptor repair interval.
pub const TPM_MAX_REPAIR_INTERVAL_SECS: u64 = 60;
/// The cutover contract for the TPM Device owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TpmRunnerContract {
    resource_type: &'static str,
    finalizer: &'static str,
    repair_interval_secs: u64,
    legacy_scheduler_disabled: bool,
    watched_configuration_is_dependency: bool,
}

impl TpmRunnerContract {
    /// Return the owned ResourceType.
    pub const fn resource_type(self) -> &'static str {
        self.resource_type
    }

    /// Return the exact Device finalizer.
    pub const fn finalizer(self) -> &'static str {
        self.finalizer
    }

    /// Return the bounded repair interval.
    pub const fn repair_interval_secs(self) -> u64 {
        self.repair_interval_secs
    }

    /// Whether the legacy TPM scheduler is disabled.
    pub const fn legacy_scheduler_disabled(self) -> bool {
        self.legacy_scheduler_disabled
    }

    /// Whether watched configuration is treated as a dependency.
    pub const fn watched_configuration_is_dependency(self) -> bool {
        self.watched_configuration_is_dependency
    }
}

/// Return the one shared-Runner registration for the TPM Device owner.
pub const fn tpm_runner_contract() -> TpmRunnerContract {
    TpmRunnerContract {
        resource_type: "Device",
        finalizer: crate::DEVICE_TPM_FINALIZER,
        repair_interval_secs: TPM_REPAIR_INTERVAL_SECS,
        legacy_scheduler_disabled: true,
        watched_configuration_is_dependency: true,
    }
}

/// Lifecycle phase of the resource-backed TPM controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TpmResourcePhase {
    /// No child resources have been admitted.
    Pending,
    /// Child resources are being created or adopted.
    Reconciling,
    /// The endpoint is ready for Guest consumers.
    Ready,
    /// A retryable effect failed.
    Degraded,
    /// The state or schema failed closed.
    Failed,
    /// The finalizer has completed.
    Finalized,
}

/// Stable result of a resource-backed TPM reconcile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmResourceOutcome {
    /// The endpoint is ready.
    Ready,
    /// The Device must be retried.
    Retry,
    /// The state was refused without replacement.
    Failed,
    /// Finalization stopped workers and retained the Volume.
    VolumeRetained,
}

impl TpmResourceOutcome {
    /// Stable status code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Retry => "retry",
            Self::Failed => "failed",
            Self::VolumeRetained => "volume-retained",
        }
    }
}

/// Controller error with no path or broker detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmResourceControllerError {
    /// Core effect failed.
    Effect(TpmResourceEffectError),
    /// Finalization was requested before reconcile.
    InvalidState,
}

impl core::fmt::Display for TpmResourceControllerError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Effect(error) => error.fmt(formatter),
            Self::InvalidState => formatter.write_str("device-tpm-resource-invalid-state"),
        }
    }
}

impl std::error::Error for TpmResourceControllerError {}

/// Resource-backed Device TPM controller.
pub struct TpmResourceController {
    device_uid: ResourceUid,
    device_ref: ResourceRef,
    execution_ref: ResourceRef,
    phase: TpmResourcePhase,
    volume_ref: Option<ResourceRef>,
    process_ref: Option<ResourceRef>,
    flush_ref: Option<ResourceRef>,
    endpoint_ref: Option<ResourceRef>,
    marker_status: TpmMarkerStatus,
    last_error: Option<TpmResourceEffectError>,
    needs_state_verification: bool,
}

impl TpmResourceController {
    /// Construct a controller for one emulated Device.
    pub fn new(
        device_uid: ResourceUid,
        device_ref: ResourceRef,
        execution_ref: ResourceRef,
    ) -> Result<Self, TpmResourceControllerError> {
        if device_ref.resource_type().as_str() != "Device" {
            return Err(TpmResourceControllerError::Effect(
                TpmResourceEffectError::InvalidDevice,
            ));
        }
        if execution_ref.resource_type().as_str() != "Host" {
            return Err(TpmResourceControllerError::Effect(
                TpmResourceEffectError::InvalidExecutionRef,
            ));
        }
        Ok(Self {
            device_uid,
            device_ref,
            execution_ref,
            phase: TpmResourcePhase::Pending,
            volume_ref: None,
            process_ref: None,
            flush_ref: None,
            endpoint_ref: None,
            marker_status: TpmMarkerStatus::NeverProvisioned,
            last_error: None,
            needs_state_verification: true,
        })
    }

    /// Rehydrate a controller from its bounded persisted status evidence.
    pub fn from_status(
        device_uid: ResourceUid,
        device_ref: ResourceRef,
        execution_ref: ResourceRef,
        status: &TpmStatusReport,
    ) -> Result<Self, TpmResourceControllerError> {
        let mut controller = Self::new(device_uid, device_ref, execution_ref)?;
        if matches!(
            status.marker_status,
            TpmMarkerStatus::Missing
                | TpmMarkerStatus::Replaced
                | TpmMarkerStatus::Tampered
        ) {
            return Err(TpmResourceControllerError::Effect(
                TpmResourceEffectError::StateIntegrity,
            ));
        }
        if status.state_volume_ref.is_none()
            && (status.swtpm_process_ref.is_some()
                || status.last_flush_ref.is_some()
                || status.tpm_endpoint_ref.is_some())
        {
            return Err(TpmResourceControllerError::Effect(
                TpmResourceEffectError::StateIntegrity,
            ));
        }
        for (reference, expected_type) in [
            (status.state_volume_ref.as_ref(), "Volume"),
            (status.swtpm_process_ref.as_ref(), "Process"),
            (status.last_flush_ref.as_ref(), "EphemeralProcess"),
            (status.tpm_endpoint_ref.as_ref(), "Endpoint"),
        ] {
            if reference
                .is_some_and(|reference| reference.resource_type().as_str() != expected_type)
            {
                return Err(TpmResourceControllerError::Effect(
                    TpmResourceEffectError::StateIntegrity,
                ));
            }
        }
        controller.phase = status.phase;
        controller.volume_ref = status.state_volume_ref.clone();
        controller.process_ref = status.swtpm_process_ref.clone();
        controller.flush_ref = status.last_flush_ref.clone();
        controller.endpoint_ref = status.tpm_endpoint_ref.clone();
        controller.marker_status = status.marker_status;
        controller.last_error = if status.phase == TpmResourcePhase::Failed {
            Some(TpmResourceEffectError::EffectRejected)
        } else {
            None
        };
        Ok(controller)
    }

    /// Return the current lifecycle phase.
    pub const fn phase(&self) -> TpmResourcePhase {
        self.phase
    }

    /// Return whether the state-preserving finalizer remains installed.
    pub const fn finalizer_installed(&self) -> bool {
        !matches!(self.phase, TpmResourcePhase::Finalized)
    }

    /// Borrow the observed TPM Endpoint, when ready.
    pub const fn endpoint_ref(&self) -> Option<&ResourceRef> {
        self.endpoint_ref.as_ref()
    }

    /// Return the durable, redacted status projection retained for restart.
    pub fn status(&self) -> TpmStatusReport {
        TpmStatusReport {
            phase: self.phase,
            state_volume_ref: self.volume_ref.clone(),
            swtpm_process_ref: self.process_ref.clone(),
            last_flush_ref: self.flush_ref.clone(),
            tpm_endpoint_ref: self.endpoint_ref.clone(),
            marker_status: self.marker_status,
            condition: self.last_error.map(TpmResourceEffectError::code),
        }
    }

    /// Reconciliation creates the Volume, completes the mandatory pre-start
    /// flush, starts and observes the long-lived Process, and then exposes
    /// the Endpoint.
    pub async fn reconcile<P: TpmResourceEffectPort>(
        &mut self,
        port: &P,
    ) -> Result<TpmResourceOutcome, TpmResourceControllerError> {
        if self.phase == TpmResourcePhase::Finalized {
            return Err(TpmResourceControllerError::InvalidState);
        }
        if self.phase == TpmResourcePhase::Failed {
            return Err(TpmResourceControllerError::Effect(
                self.last_error
                    .unwrap_or(TpmResourceEffectError::StateIntegrity),
            ));
        }
        self.phase = TpmResourcePhase::Reconciling;
        let volume = if self.needs_state_verification || self.volume_ref.is_none() {
            let volume = match port
                .ensure_state_volume(&self.device_uid, &self.device_ref, &self.execution_ref)
                .await
            {
                Ok(value) => value,
                Err(error) => return self.effect_failed(error),
            };
            if self
                .volume_ref
                .as_ref()
                .is_some_and(|current| current != &volume)
            {
                return self.effect_failed(TpmResourceEffectError::StateIntegrity);
            }
            self.marker_status = TpmMarkerStatus::Verified;
            self.volume_ref = Some(volume.clone());
            self.needs_state_verification = false;
            volume
        } else {
            self.volume_ref
                .clone()
                .ok_or(TpmResourceControllerError::InvalidState)?
        };
        if self.flush_ref.is_none() {
            let flush = match port
                .request_flush_process(&self.device_uid, &self.execution_ref)
                .await
            {
                Ok(value) => value,
                Err(error) => return self.effect_failed(error),
            };
            self.flush_ref = Some(flush);
        }
        let process = if let Some(process) = self.process_ref.clone() {
            process
        } else {
            let process = match port
                .request_swtpm_process(&self.device_uid, &volume, &self.execution_ref)
                .await
            {
                Ok(value) => value,
                Err(error) => return self.effect_failed(error),
            };
            self.process_ref = Some(process.clone());
            process
        };
        let endpoint = match port.watch_tpm_endpoint(&process).await {
            Ok(value) => value,
            Err(error) => return self.effect_failed(error),
        };
        self.endpoint_ref = Some(endpoint);
        self.last_error = None;
        self.phase = TpmResourcePhase::Ready;
        Ok(TpmResourceOutcome::Ready)
    }

    /// Stop children and retain the Device-owned state Volume.
    pub async fn finalize<P: TpmResourceEffectPort>(
        &mut self,
        port: &P,
    ) -> Result<TpmResourceOutcome, TpmResourceControllerError> {
        if self.phase == TpmResourcePhase::Finalized {
            return Ok(TpmResourceOutcome::VolumeRetained);
        }
        if self.phase == TpmResourcePhase::Pending
            && self.volume_ref.is_none()
            && self.process_ref.is_none()
            && self.flush_ref.is_none()
        {
            return Err(TpmResourceControllerError::InvalidState);
        }
        if let Some(process) = self.process_ref.take()
            && let Err(error) = port.stop_swtpm_process(&process).await
        {
            self.process_ref = Some(process);
            self.phase = TpmResourcePhase::Degraded;
            return Err(TpmResourceControllerError::Effect(error));
        }
        if let Some(flush) = self.flush_ref.take()
            && let Err(error) = port.delete_flush_process(&flush).await
        {
            self.flush_ref = Some(flush);
            self.phase = TpmResourcePhase::Degraded;
            return Err(TpmResourceControllerError::Effect(error));
        }
        self.endpoint_ref = None;
        self.last_error = None;
        self.phase = TpmResourcePhase::Finalized;
        Ok(TpmResourceOutcome::VolumeRetained)
    }

    fn effect_failed<T>(
        &mut self,
        error: TpmResourceEffectError,
    ) -> Result<T, TpmResourceControllerError> {
        self.last_error = Some(error);
        if error == TpmResourceEffectError::StateIntegrity {
            self.marker_status = TpmMarkerStatus::Tampered;
        }
        self.phase = if error == TpmResourceEffectError::Transient {
            TpmResourcePhase::Degraded
        } else {
            TpmResourcePhase::Failed
        };
        Err(TpmResourceControllerError::Effect(error))
    }
}
