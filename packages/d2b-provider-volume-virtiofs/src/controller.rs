//! The volume-virtiofs Export controller.
//!
//! It reconciles `virtiofs.d2bus.org.Export` resources and never writes a
//! Volume row: it reads the referenced Volume only to resolve the named
//! view and the target Guest's vcpu count.

use d2b_contracts_resource::v3::execution_policy::BoundedToken;
use d2b_contracts_resource::v3::volume::{ViewSpec, VolumeSpec};

use crate::error::VirtiofsExportError;
use crate::export::{EXPORT_FINALIZER, EXPORT_RESOURCE_TYPE, ExportSpec};
use crate::port::{ExportPhase, ExportStatusReport, LaunchedWorker, VirtiofsExportEffectPort};
use crate::worker::{VirtiofsdWorkerPlan, WorkerSandbox};

/// The exact shared-Runner contract for `volume-virtiofs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtiofsRunnerContract {
    /// The qualified Export ResourceType owned by this Provider.
    pub resource_type: &'static str,
    /// The finalizer installed on Export resources.
    pub finalizer: &'static str,
    /// Bounded repair interval in seconds.
    pub repair_interval_secs: u64,
    /// Whether configuration is dependency-only.
    pub watched_configuration_is_dependency: bool,
}

/// Return the production volume-virtiofs Runner contract.
pub const fn virtiofs_runner_contract() -> VirtiofsRunnerContract {
    VirtiofsRunnerContract {
        resource_type: EXPORT_RESOURCE_TYPE,
        finalizer: EXPORT_FINALIZER,
        repair_interval_secs: 30,
        watched_configuration_is_dependency: true,
    }
}

/// Resolve the named view an Export selects, read-only.
pub fn resolve_view<'spec>(
    volume: &'spec VolumeSpec,
    export: &ExportSpec,
) -> Result<&'spec ViewSpec, VirtiofsExportError> {
    volume
        .views()
        .get(export.view().as_str())
        .ok_or(VirtiofsExportError::ViewNotFound)
}

/// The volume-virtiofs controller over its injected effect port.
#[derive(Debug)]
pub struct VirtiofsExportController<P> {
    provider: BoundedToken,
    port: P,
}

impl<P: VirtiofsExportEffectPort> VirtiofsExportController<P> {
    /// Build a controller over the injected port.
    pub fn new(port: P) -> Self {
        Self {
            provider: BoundedToken::parse("volume-virtiofs").expect("frozen provider name"),
            port,
        }
    }

    /// Borrow the Provider name.
    pub const fn provider(&self) -> &BoundedToken {
        &self.provider
    }

    /// The finalizer this controller adds, and only to an Export.
    pub const fn finalizer(&self) -> &'static str {
        EXPORT_FINALIZER
    }

    /// Reconcile one Export to a serving worker and report its status.
    pub async fn reconcile(
        &self,
        export: &ExportSpec,
        volume: &VolumeSpec,
        vcpu_count: u32,
        principal: BoundedToken,
    ) -> Result<ExportStatusReport, VirtiofsExportError> {
        let failed = |reason: VirtiofsExportError| ExportStatusReport {
            provider: self.provider.clone(),
            phase: ExportPhase::Failed,
            export_ready: false,
            guest_mount_ready: false,
            worker_process_ref: None,
            socket: None,
            reason: Some(reason),
        };

        if export.access() == d2b_contracts_resource::v3::volume::AttachmentAccess::SharedWrite {
            return Ok(failed(VirtiofsExportError::SharedWriteUnsupported));
        }
        WorkerSandbox::conformant().assert_conformant()?;
        let view = resolve_view(volume, export)?;
        let plan = match VirtiofsdWorkerPlan::for_export(export, view, vcpu_count, principal) {
            Ok(plan) => plan,
            Err(error) => return Ok(failed(error)),
        };
        if export.view().as_str() == "ro-store"
            && !self.port.observe_store_view_marker(export).await?
        {
            return Ok(ExportStatusReport {
                provider: self.provider.clone(),
                phase: ExportPhase::Pending,
                export_ready: false,
                guest_mount_ready: false,
                worker_process_ref: None,
                socket: None,
                reason: Some(VirtiofsExportError::StoreViewMarkerMissing),
            });
        }

        let worker = match self.port.launch_worker(export, &plan).await {
            Ok(worker) => worker,
            Err(error) => return Ok(failed(error)),
        };
        let export_ready = self.port.observe_socket(&worker).await?;
        let guest_mount_ready = if export_ready {
            self.port.observe_guest_mount(export).await?
        } else {
            false
        };

        let (phase, reason) = match (export_ready, guest_mount_ready) {
            (true, true) => (ExportPhase::Ready, None),
            (true, false) => (
                ExportPhase::Degraded,
                Some(VirtiofsExportError::GuestMountNotReady),
            ),
            (false, _) => (
                ExportPhase::Pending,
                Some(VirtiofsExportError::ExportNotReady),
            ),
        };
        Ok(ExportStatusReport {
            provider: self.provider.clone(),
            phase,
            export_ready,
            guest_mount_ready,
            worker_process_ref: Some(worker.process_ref),
            socket: Some(worker.socket),
            reason,
        })
    }

    /// Drain one Export before its finalizer is cleared.
    ///
    /// The owned worker and Endpoint are deleted first, then the guest
    /// mount is confirmed absent. A mount that is still present blocks
    /// the drain rather than being force-cleared.
    pub async fn drain(
        &self,
        export: &ExportSpec,
        worker: &LaunchedWorker,
    ) -> Result<(), VirtiofsExportError> {
        self.port.delete_worker(worker).await?;
        if self.port.observe_guest_mount(export).await? {
            return Err(VirtiofsExportError::DrainIncomplete);
        }
        Ok(())
    }
}
