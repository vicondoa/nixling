//! Combined GPU/video Device reconcile state machine.

use core::fmt;
use d2b_contracts_resource::v3::{ResourceRef, ResourceUid, device::DeviceArbitration};

use crate::{
    GpuAuthorityAdmission, GpuAuthorityError, GpuAuthorityLease, GpuClosureProof, GpuEffectError,
    GpuEffectPort, GpuEffectTokenSet, GpuLaunchTicket, GpuLifecycleEffectPort, GpuProcessIdentity,
    GpuProcessObservation, GpuProcessRole, GpuProcessSelectionError, GpuSettings, GpuWorkerSpec,
    VideoWorkerSpec, process::select_processes,
};

/// Default descriptor repair interval.
pub const GPU_REPAIR_INTERVAL_SECS: u64 = 30;
/// Maximum descriptor repair interval.
pub const GPU_MAX_REPAIR_INTERVAL_SECS: u64 = 60;

/// GPU controller lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuPhase {
    /// No worker effects have started.
    Pending,
    /// The GPU/render-node worker is starting.
    GpuStarting,
    /// The GPU/render-node worker is Ready.
    GpuReady,
    /// The video worker is starting after GPU readiness.
    VideoStarting,
    /// All requested workers are Ready.
    Ready,
    /// A worker can be retried.
    Degraded,
    /// The generation failed closed.
    Failed,
    /// Finalizer is stopping workers.
    Finalizing,
    /// Finalizer cleared.
    Finalized,
    /// Restart identity was ambiguous and is quarantined.
    Quarantined,
}

/// GPU controller failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuControllerError {
    /// Settings or process selection violated the Device contract.
    Selection(GpuProcessSelectionError),
    /// Core effect failed.
    Effect(GpuEffectError),
    /// A finalizer transition was invalid.
    InvalidState,
    /// Core authority admission failed before an effect.
    Authority(GpuAuthorityError),
    /// Restart observation was ambiguous.
    Quarantined,
    /// A dependency reference cannot be owned by the GPU controller.
    DependencyInvalid,
    /// A dependency is not ready for an upgrade.
    DependenciesNotReady,
    /// A dependency has not drained before replacement.
    DependenciesNotDrained,
}

impl fmt::Display for GpuControllerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Selection(error) => return error.fmt(formatter),
            Self::Effect(error) => return error.fmt(formatter),
            Self::InvalidState => "gpu-invalid-state",
            Self::Authority(error) => return error.fmt(formatter),
            Self::Quarantined => "gpu-authority-quarantined",
            Self::DependencyInvalid => "gpu-dependency-invalid",
            Self::DependenciesNotReady => "gpu-dependencies-not-ready",
            Self::DependenciesNotDrained => "gpu-dependencies-not-drained",
        })
    }
}

impl std::error::Error for GpuControllerError {}

/// Closed reconcile outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuReconcileOutcome {
    /// GPU and optional video workers converged.
    Converged,
    /// A transient effect should be retried.
    Retry,
}

/// A fresh dependency observation used by the GPU upgrade planner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuDependentResource {
    resource_ref: ResourceRef,
    ready: bool,
    drained: bool,
}

impl GpuDependentResource {
    /// Construct a dependency observation for a Guest, Process, or Endpoint.
    pub fn new(
        resource_ref: ResourceRef,
        ready: bool,
        drained: bool,
    ) -> Result<Self, GpuControllerError> {
        if !matches!(
            resource_ref.resource_type().as_str(),
            "Guest" | "Process" | "Endpoint"
        ) {
            return Err(GpuControllerError::DependencyInvalid);
        }
        Ok(Self {
            resource_ref,
            ready,
            drained,
        })
    }

    /// Borrow the dependent ResourceRef.
    pub const fn resource_ref(&self) -> &ResourceRef {
        &self.resource_ref
    }

    /// Whether the dependent is currently Ready.
    pub const fn ready(&self) -> bool {
        self.ready
    }

    /// Whether the dependent has stopped using the current GPU realization.
    pub const fn drained(&self) -> bool {
        self.drained
    }
}

/// Result of comparing the current and desired GPU settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuUpdateState {
    /// No disruptive change is required.
    Current,
    /// A dependency-aware recycle is required.
    UpgradeRequired,
}

/// Dependency-aware GPU replacement plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuUpgradePlan {
    desired_settings: GpuSettings,
    dependents: Vec<GpuDependentResource>,
}

impl GpuUpgradePlan {
    /// Borrow the settings to install after drain.
    pub const fn desired_settings(&self) -> &GpuSettings {
        &self.desired_settings
    }

    /// Borrow fresh dependent observations.
    pub fn dependents(&self) -> &[GpuDependentResource] {
        &self.dependents
    }
}

/// The cutover contract for the GPU Device owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GpuRunnerContract {
    resource_type: &'static str,
    finalizer: &'static str,
    repair_interval_secs: u64,
    legacy_scheduler_disabled: bool,
    watched_configuration_is_dependency: bool,
}

impl GpuRunnerContract {
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

    /// Whether legacy GPU scheduling is disabled.
    pub const fn legacy_scheduler_disabled(self) -> bool {
        self.legacy_scheduler_disabled
    }

    /// Whether watched configuration is treated as a dependency.
    pub const fn watched_configuration_is_dependency(self) -> bool {
        self.watched_configuration_is_dependency
    }
}

/// Return the one shared-Runner registration for the GPU Device owner.
pub const fn gpu_runner_contract() -> GpuRunnerContract {
    GpuRunnerContract {
        resource_type: "Device",
        finalizer: crate::DEVICE_GPU_FINALIZER,
        repair_interval_secs: GPU_REPAIR_INTERVAL_SECS,
        legacy_scheduler_disabled: true,
        watched_configuration_is_dependency: true,
    }
}

/// Combined GPU/video controller.
pub struct GpuController {
    device_uid: ResourceUid,
    arbitration: DeviceArbitration,
    settings: GpuSettings,
    tokens: GpuEffectTokenSet,
    phase: GpuPhase,
    finalizer: bool,
    gpu_role: Option<GpuProcessRole>,
    video_started: bool,
    admission: Option<GpuAuthorityAdmission>,
    authority_lease: Option<GpuAuthorityLease>,
    ticket: Option<GpuLaunchTicket>,
    gpu_identity: Option<GpuProcessIdentity>,
    video_identity: Option<GpuProcessIdentity>,
    gpu_closure: Option<GpuClosureProof>,
    video_closure: Option<GpuClosureProof>,
}

impl GpuController {
    /// Construct a controller with a Core-resolved token set.
    pub fn new(
        device_uid: ResourceUid,
        arbitration: DeviceArbitration,
        settings: GpuSettings,
        tokens: GpuEffectTokenSet,
    ) -> Result<Self, GpuControllerError> {
        select_processes(&device_uid, arbitration, &settings)
            .map_err(GpuControllerError::Selection)?;
        Ok(Self {
            device_uid,
            arbitration,
            settings,
            tokens,
            phase: GpuPhase::Pending,
            finalizer: true,
            gpu_role: None,
            video_started: false,
            admission: None,
            authority_lease: None,
            ticket: None,
            gpu_identity: None,
            video_identity: None,
            gpu_closure: None,
            video_closure: None,
        })
    }

    /// Construct an authority-bound controller from Core admission evidence.
    pub fn new_authorized(
        admission: GpuAuthorityAdmission,
        settings: GpuSettings,
        tokens: GpuEffectTokenSet,
    ) -> Result<Self, GpuControllerError> {
        let device_uid = admission.owner().device_uid().clone();
        let mut controller = Self::new(device_uid, admission.arbitration(), settings, tokens)?;
        controller.admission = Some(admission);
        Ok(controller)
    }

    /// Return the current controller phase.
    pub const fn phase(&self) -> GpuPhase {
        self.phase
    }

    /// Borrow the current desired settings.
    pub const fn settings(&self) -> &GpuSettings {
        &self.settings
    }

    /// Compare desired settings without starting an effect.
    pub fn assess_update(&self, desired: &GpuSettings) -> GpuUpdateState {
        if &self.settings == desired {
            GpuUpdateState::Current
        } else {
            GpuUpdateState::UpgradeRequired
        }
    }

    /// Build a replacement plan from fresh, dependency-owned observations.
    pub fn plan_upgrade(
        &self,
        desired_settings: GpuSettings,
        dependents: &[GpuDependentResource],
    ) -> Result<GpuUpgradePlan, GpuControllerError> {
        desired_settings
            .validate(self.arbitration)
            .map_err(|error| GpuControllerError::Selection(
                GpuProcessSelectionError::Settings(error),
            ))?;
        if dependents.iter().any(|dependent| !dependent.ready()) {
            return Err(GpuControllerError::DependenciesNotReady);
        }
        Ok(GpuUpgradePlan {
            desired_settings,
            dependents: dependents.to_vec(),
        })
    }

    /// Return whether the Provider finalizer remains installed.
    pub const fn finalizer_installed(&self) -> bool {
        self.finalizer
    }

    /// Whether this controller owns a Core admission.
    pub const fn authority_reserved(&self) -> bool {
        self.authority_lease.is_some()
    }

    /// Return the current GPU process identity, if started or adopted.
    pub const fn gpu_identity(&self) -> Option<&GpuProcessIdentity> {
        self.gpu_identity.as_ref()
    }

    /// Return the current video process identity, if started or adopted.
    pub const fn video_identity(&self) -> Option<&GpuProcessIdentity> {
        self.video_identity.as_ref()
    }

    /// Start the GPU worker and only then the optional video worker.
    pub fn reconcile<P: GpuEffectPort>(
        &mut self,
        port: &mut P,
    ) -> Result<GpuReconcileOutcome, GpuControllerError> {
        if self.admission.is_none() {
            return Err(GpuControllerError::Authority(
                GpuAuthorityError::StartupRehydrationRequired,
            ));
        }
        if !self.finalizer || matches!(self.phase, GpuPhase::Finalizing | GpuPhase::Finalized) {
            return Err(GpuControllerError::InvalidState);
        }
        if self.phase == GpuPhase::Ready {
            return Ok(GpuReconcileOutcome::Converged);
        }
        if self.ticket.is_none() {
            self.ticket = Some(match port.open_devices(&self.device_uid, &self.tokens) {
                Ok(ticket) => ticket,
                Err(error) => {
                    self.phase = phase_for_effect(error);
                    return Err(GpuControllerError::Effect(error));
                }
            });
        }
        let ticket = self
            .ticket
            .as_ref()
            .ok_or(GpuControllerError::InvalidState)?;
        let gpu_role = if self.settings.render_node_only {
            GpuProcessRole::RenderNode
        } else {
            GpuProcessRole::FullGpu
        };
        if self.gpu_role.is_none() {
            if let Err(error) = port.start(gpu_role, ticket) {
                self.phase = phase_for_effect(error);
                return Err(GpuControllerError::Effect(error));
            }
            self.gpu_role = Some(gpu_role);
        }
        self.phase = GpuPhase::GpuReady;
        if self.settings.video_sidecar && !self.video_started {
            if let Err(error) = port.start(GpuProcessRole::Video, ticket) {
                self.phase = phase_for_effect(error);
                return Err(GpuControllerError::Effect(error));
            }
            self.video_started = true;
        }
        self.phase = GpuPhase::Ready;
        Ok(GpuReconcileOutcome::Converged)
    }

    /// Stop video first and the GPU/render-node worker second.
    pub fn finalize<P: GpuEffectPort>(&mut self, port: &mut P) -> Result<(), GpuControllerError> {
        if !self.finalizer {
            return Ok(());
        }
        self.phase = GpuPhase::Finalizing;
        if self.video_started {
            if let Err(error) = port.stop(GpuProcessRole::Video) {
                self.phase = phase_for_effect(error);
                return Err(GpuControllerError::Effect(error));
            }
            self.video_started = false;
        }
        if let Some(role) = self.gpu_role.take() {
            if let Err(error) = port.stop(role) {
                self.gpu_role = Some(role);
                self.phase = GpuPhase::Degraded;
                return Err(GpuControllerError::Effect(error));
            }
        }
        self.ticket = None;
        self.finalizer = false;
        self.phase = GpuPhase::Finalized;
        Ok(())
    }

    /// Reconcile through the authority-aware production effect boundary.
    ///
    /// The Host-global reservation is acquired before the first open or
    /// spawn and remains retained until [`Self::finalize_lifecycle`] confirms
    /// every worker closure.
    pub fn reconcile_lifecycle<P: GpuLifecycleEffectPort>(
        &mut self,
        port: &mut P,
    ) -> Result<GpuReconcileOutcome, GpuControllerError> {
        if !self.finalizer
            || matches!(
                self.phase,
                GpuPhase::Failed
                    | GpuPhase::Finalizing
                    | GpuPhase::Finalized
                    | GpuPhase::Quarantined
            )
        {
            return Err(GpuControllerError::InvalidState);
        }
        let admission = self
            .admission
            .as_ref()
            .ok_or(GpuControllerError::InvalidState)?;
        if self.settings.video_sidecar && admission.video_principal().is_none() {
            return Err(GpuControllerError::Authority(
                GpuAuthorityError::PrincipalNotSeparated,
            ));
        }
        if self.authority_lease.is_none() {
            self.authority_lease = Some(
                port.reserve_authority(admission)
                    .map_err(GpuControllerError::Effect)?,
            );
        }
        if self.phase == GpuPhase::Ready {
            return Ok(GpuReconcileOutcome::Converged);
        }
        if self.ticket.is_none() {
            self.ticket = Some(
                port.open_authorized_devices(admission, &self.tokens)
                    .map_err(GpuControllerError::Effect)?,
            );
        }
        let ticket = self
            .ticket
            .as_ref()
            .ok_or(GpuControllerError::InvalidState)?;
        let generation = admission.owner().generation();
        if self.gpu_identity.is_none() {
            let spec = GpuWorkerSpec::gpu(&self.device_uid, &self.settings)
                .map_err(GpuControllerError::Selection)?;
            let identity = port
                .start_gpu_worker(
                    &spec,
                    ticket,
                    admission.gpu_principal(),
                    admission.platform(),
                    generation,
                )
                .map_err(GpuControllerError::Effect)?;
            self.gpu_role = Some(spec.process().role());
            self.gpu_identity = Some(identity.clone());
            if let Err(error) = validate_started_identity(
                &identity,
                spec.process().role(),
                admission.gpu_principal(),
                admission.platform(),
                generation,
            ) {
                self.phase = GpuPhase::Failed;
                return Err(GpuControllerError::Effect(error));
            }
        }
        self.phase = GpuPhase::GpuReady;
        if self.settings.video_sidecar && self.video_identity.is_none() {
            let principal = admission
                .video_principal()
                .ok_or(GpuControllerError::Authority(
                    GpuAuthorityError::PrincipalNotSeparated,
                ))?;
            let spec = VideoWorkerSpec::new(&self.device_uid, &self.settings)
                .map_err(GpuControllerError::Selection)?;
            let identity = port
                .start_video_worker(&spec, ticket, principal, admission.platform(), generation)
                .map_err(GpuControllerError::Effect)?;
            self.video_identity = Some(identity.clone());
            self.video_started = true;
            if let Err(error) = validate_started_identity(
                &identity,
                GpuProcessRole::Video,
                principal,
                admission.platform(),
                generation,
            ) {
                self.phase = GpuPhase::Failed;
                return Err(GpuControllerError::Effect(error));
            }
        }
        self.phase = GpuPhase::Ready;
        Ok(GpuReconcileOutcome::Converged)
    }

    /// Drain dependents, recycle the realization, and install new settings.
    pub fn execute_upgrade<P: GpuLifecycleEffectPort>(
        &mut self,
        plan: &GpuUpgradePlan,
        port: &mut P,
    ) -> Result<GpuReconcileOutcome, GpuControllerError> {
        if plan.dependents.iter().any(|dependent| !dependent.drained()) {
            return Err(GpuControllerError::DependenciesNotDrained);
        }
        if self.assess_update(&plan.desired_settings) == GpuUpdateState::Current {
            return Ok(GpuReconcileOutcome::Converged);
        }
        self.finalize_lifecycle(port)?;
        self.settings = plan.desired_settings.clone();
        self.finalizer = true;
        self.phase = GpuPhase::Pending;
        self.reconcile_lifecycle(port)
    }

    /// Adopt matching GPU/video workers after a daemon restart.
    pub fn adopt_lifecycle<P: GpuLifecycleEffectPort>(
        &mut self,
        lease: GpuAuthorityLease,
        expected: &[GpuProcessIdentity],
        port: &mut P,
    ) -> Result<GpuReconcileOutcome, GpuControllerError> {
        if !self.finalizer
            || matches!(
                self.phase,
                GpuPhase::Failed
                    | GpuPhase::Finalizing
                    | GpuPhase::Finalized
                    | GpuPhase::Quarantined
            )
        {
            return Err(GpuControllerError::InvalidState);
        }
        let admission = self
            .admission
            .as_ref()
            .ok_or(GpuControllerError::InvalidState)?;
        if self.settings.video_sidecar && admission.video_principal().is_none() {
            return Err(GpuControllerError::Authority(
                GpuAuthorityError::PrincipalNotSeparated,
            ));
        }
        self.authority_lease = Some(lease);
        let mut matched = Vec::new();
        let mut missing = false;
        for identity in expected {
            match port
                .observe_worker(identity)
                .map_err(GpuControllerError::Effect)?
            {
                GpuProcessObservation::Matching(observed) => {
                    if observed != *identity {
                        self.phase = GpuPhase::Quarantined;
                        return Err(GpuControllerError::Quarantined);
                    }
                    matched.push(observed);
                }
                GpuProcessObservation::Ambiguous => {
                    self.phase = GpuPhase::Quarantined;
                    return Err(GpuControllerError::Quarantined);
                }
                GpuProcessObservation::StaleIdentity => {
                    self.phase = GpuPhase::Failed;
                    return Err(GpuControllerError::Effect(
                        GpuEffectError::StaleDeviceIdentity,
                    ));
                }
                GpuProcessObservation::Missing => {
                    missing = true;
                }
            }
        }
        for identity in matched {
            let expected_role = if identity.role() == GpuProcessRole::Video {
                GpuProcessRole::Video
            } else if self.settings.render_node_only {
                GpuProcessRole::RenderNode
            } else {
                GpuProcessRole::FullGpu
            };
            let expected_principal = match identity.role() {
                GpuProcessRole::Video => admission.video_principal(),
                GpuProcessRole::FullGpu | GpuProcessRole::RenderNode => {
                    Some(admission.gpu_principal())
                }
            };
            let Some(expected_principal) = expected_principal else {
                self.phase = GpuPhase::Failed;
                return Err(GpuControllerError::Effect(GpuEffectError::WrongPrincipal));
            };
            if identity.role() != expected_role
                || identity.principal() != expected_principal
                || (identity.role() == GpuProcessRole::Video && !self.settings.video_sidecar)
            {
                self.phase = GpuPhase::Failed;
                return Err(GpuControllerError::Effect(GpuEffectError::WrongPrincipal));
            }
            if identity.platform() != admission.platform() {
                self.phase = GpuPhase::Failed;
                return Err(GpuControllerError::Effect(GpuEffectError::PlatformMismatch));
            }
            if identity.generation() != admission.owner().generation() {
                self.phase = GpuPhase::Failed;
                return Err(GpuControllerError::Effect(
                    GpuEffectError::StaleDeviceIdentity,
                ));
            }
            match identity.role() {
                GpuProcessRole::Video => {
                    if self.video_identity.is_some() {
                        self.phase = GpuPhase::Quarantined;
                        return Err(GpuControllerError::Quarantined);
                    }
                    self.video_started = true;
                    self.video_identity = Some(identity);
                }
                role => {
                    if self.gpu_identity.is_some() {
                        self.phase = GpuPhase::Quarantined;
                        return Err(GpuControllerError::Quarantined);
                    }
                    self.gpu_role = Some(role);
                    self.gpu_identity = Some(identity);
                }
            }
        }
        if missing
            || self.gpu_identity.is_none()
            || (self.settings.video_sidecar && self.video_identity.is_none())
        {
            self.phase = GpuPhase::Pending;
            return Ok(GpuReconcileOutcome::Retry);
        }
        self.phase = GpuPhase::Ready;
        Ok(GpuReconcileOutcome::Converged)
    }

    /// Close workers and release Host-global authority after exact proofs.
    pub fn finalize_lifecycle<P: GpuLifecycleEffectPort>(
        &mut self,
        port: &mut P,
    ) -> Result<(), GpuControllerError> {
        if !self.finalizer {
            return Ok(());
        }
        self.phase = GpuPhase::Finalizing;
        if self.video_closure.is_none()
            && let Some(identity) = self.video_identity.as_ref()
        {
            let closure = port
                .stop_worker(identity)
                .map_err(GpuControllerError::Effect)?;
            if closure.identity() != identity {
                self.phase = GpuPhase::Failed;
                return Err(GpuControllerError::Effect(GpuEffectError::CloseUnconfirmed));
            }
            self.video_closure = Some(closure);
        }
        if self.gpu_closure.is_none()
            && let Some(identity) = self.gpu_identity.as_ref()
        {
            let closure = port
                .stop_worker(identity)
                .map_err(GpuControllerError::Effect)?;
            if closure.identity() != identity {
                self.phase = GpuPhase::Failed;
                return Err(GpuControllerError::Effect(GpuEffectError::CloseUnconfirmed));
            }
            self.gpu_closure = Some(closure);
        }
        let closures = self
            .video_closure
            .iter()
            .chain(self.gpu_closure.iter())
            .cloned()
            .collect::<Vec<_>>();
        if let Some(lease) = self.authority_lease.take()
            && let Err(error) = port.release_authority(lease.clone(), &closures)
        {
            self.authority_lease = Some(lease);
            return Err(GpuControllerError::Effect(error));
        }
        self.video_identity = None;
        self.gpu_identity = None;
        self.ticket = None;
        self.gpu_role = None;
        self.video_started = false;
        self.gpu_closure = None;
        self.video_closure = None;
        self.finalizer = false;
        self.phase = GpuPhase::Finalized;
        Ok(())
    }
}

fn phase_for_effect(error: GpuEffectError) -> GpuPhase {
    if error == GpuEffectError::Transient {
        GpuPhase::Degraded
    } else {
        GpuPhase::Failed
    }
}

fn validate_started_identity(
    identity: &GpuProcessIdentity,
    expected_role: GpuProcessRole,
    expected_principal: &crate::GpuPrincipalToken,
    expected_platform: &crate::GpuPlatformToken,
    expected_generation: d2b_contracts_resource::v3::ResourceGeneration,
) -> Result<(), GpuEffectError> {
    if identity.role() != expected_role || identity.principal() != expected_principal {
        return Err(GpuEffectError::WrongPrincipal);
    }
    if identity.platform() != expected_platform {
        return Err(GpuEffectError::PlatformMismatch);
    }
    if identity.generation() != expected_generation {
        return Err(GpuEffectError::StaleDeviceIdentity);
    }
    Ok(())
}

impl fmt::Debug for GpuController {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GpuController")
            .field("device_uid", &"<redacted>")
            .field("arbitration", &self.arbitration)
            .field("phase", &self.phase)
            .field("finalizer", &self.finalizer)
            .field("gpu_role", &self.gpu_role)
            .field("video_started", &self.video_started)
            .field("has_authority", &self.authority_lease.is_some())
            .field("has_gpu_identity", &self.gpu_identity.is_some())
            .field("has_video_identity", &self.video_identity.is_some())
            .field("has_gpu_closure", &self.gpu_closure.is_some())
            .field("has_video_closure", &self.video_closure.is_some())
            .finish()
    }
}
