//! Azure VM lifecycle controller.

use std::{
    fmt,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    bootstrap::BootstrapPsk,
    bootstrap_svc::{BootstrapService, BootstrapServiceState},
    config::{AzureVmConfig, AzureVmGuestSettings, DataDiskSpec},
    effect::AzureCredentialPort,
    effect::{
        AzureAccessToken, AzureEffectPort, AzureVmHandle, AzureVmState, LroStatus,
        PskExtensionPayload, TagDigest,
    },
    error::AzureVmError,
    idempotency,
};

const MAX_PSK_DELIVERY_ATTEMPTS: u8 = 3;
const MAX_LRO_AGE_MS: u64 = 15 * 60 * 1_000;

/// Clock used for bootstrap admission and deadline checks.
pub trait AzureVmClock: Send + Sync {
    /// Return the current Unix time in milliseconds.
    fn now_unix_ms(&self) -> u64;
}

/// Production wall clock for Azure VM bootstrap deadlines.
#[derive(Debug, Default)]
pub struct SystemAzureVmClock;

impl AzureVmClock for SystemAzureVmClock {
    fn now_unix_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
            .unwrap_or(0)
    }
}

/// Azure VM Provider phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AzureVmPhase {
    /// No correlated VM exists.
    Absent,
    /// VM provisioning is in progress.
    Provisioning,
    /// PSK extension delivery is in progress.
    PskDelivering,
    /// The one-time PSK extension is being removed.
    PskCleaning,
    /// VM is awaiting the bootstrap session.
    Bootstrapping,
    /// VM and enrolled KK session are ready.
    Ready,
    /// VM is being reconfigured.
    Reconfiguring,
    /// VM is draining.
    Draining,
    /// VM deletion is in progress.
    Deleting,
    /// Provider-owned child resources are being removed.
    ChildCleaning,
    /// Provider failed closed.
    Failed,
    /// Finalizer completed.
    Finalized,
}

/// Default descriptor repair interval.
pub const AZURE_VM_REPAIR_INTERVAL_SECS: u64 = 30;
/// Exact Guest finalizer owned by the Azure VM runtime Provider.
pub const AZURE_VM_GUEST_FINALIZER: &str =
    "runtime-azure-virtual-machine.d2bus.org/guest-cleanup";

/// The shared-Runner contract for the Azure VM Guest owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AzureVirtualMachineRunnerContract {
    resource_type: &'static str,
    finalizer: &'static str,
    repair_interval_secs: u64,
    watched_configuration_is_dependency: bool,
}

impl AzureVirtualMachineRunnerContract {
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

/// Return the shared-Runner contract for Azure VM Guests.
pub const fn azure_virtual_machine_runner_contract() -> AzureVirtualMachineRunnerContract {
    AzureVirtualMachineRunnerContract {
        resource_type: "Guest",
        finalizer: AZURE_VM_GUEST_FINALIZER,
        repair_interval_secs: AZURE_VM_REPAIR_INTERVAL_SECS,
        watched_configuration_is_dependency: true,
    }
}

/// Non-blocking controller result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AzureVmReconcileOutcome {
    /// The VM is ready.
    Converged,
    /// Poll again after a bounded delay.
    Progressing {
        /// Delay in milliseconds.
        after_ms: u32,
    },
    /// Retry the same operation.
    Retry {
        /// Delay in milliseconds.
        after_ms: u32,
    },
}

/// A supported mutable Guest update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum AzureVmUpdate {
    /// Resize the VM to a new Azure size SKU.
    Resize {
        /// New size SKU.
        size: String,
    },
    /// Attach a provider-owned data disk.
    AttachDisk {
        /// Disk intent.
        disk: DataDiskSpec,
    },
    /// Detach a provider-owned data disk by LUN.
    DetachDisk {
        /// Azure LUN.
        lun: u8,
    },
    /// Replace operator-owned Azure tags.
    ReplaceTags {
        /// New tag set.
        tags: Vec<(String, String)>,
    },
}

/// Non-secret controller state required for restart recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureVmRecoveryState {
    /// Current lifecycle phase.
    pub phase: AzureVmPhase,
    /// Whether the finalizer remains installed.
    pub finalizer_installed: bool,
    /// Opaque in-flight ARM operation.
    pub operation: Option<crate::effect::AzureOperationHandle>,
    /// Deterministic delete operation id, when deletion is pending.
    pub pending_delete_operation_id: Option<String>,
    /// Bootstrap deadline start.
    pub bootstrap_started_at_unix_ms: Option<u64>,
    /// Number of extension delivery attempts.
    pub psk_delivery_attempts: u8,
    /// Controller-local LRO start time.
    pub operation_started_at_unix_ms: Option<u64>,
    /// Pending typed update.
    pub pending_update: Option<AzureVmUpdate>,
    /// Bootstrap service enrollment state.
    pub bootstrap_service_state: BootstrapServiceState,
    /// Whether the one-time bootstrap extension may still contain PSK data.
    #[serde(default)]
    pub bootstrap_extension_present: bool,
    /// Whether the VM deletion has been externally confirmed.
    #[serde(default)]
    pub vm_delete_confirmed: bool,
    /// Whether provider-owned child-resource cleanup has completed.
    #[serde(default)]
    pub child_cleanup_complete: bool,
    /// Whether bootstrap expiry caused the current cleanup operation.
    #[serde(default)]
    pub bootstrap_deadline_failed: bool,
}

impl AzureVmUpdate {
    fn operation_class(&self) -> &'static str {
        match self {
            Self::Resize { .. } => "resize",
            Self::AttachDisk { .. } => "disk-attach",
            Self::DetachDisk { .. } => "disk-detach",
            Self::ReplaceTags { .. } => "tags",
        }
    }
}

/// Redacted Guest status projection.
#[derive(Clone, PartialEq, Eq)]
pub struct AzureVmStatus {
    phase: AzureVmPhase,
    identity_digest: Option<[u8; 32]>,
    operation_digest: Option<[u8; 32]>,
}

impl AzureVmStatus {
    /// Return the current phase.
    pub const fn phase(&self) -> AzureVmPhase {
        self.phase
    }

    /// Return the enrolled identity digest.
    pub const fn identity_digest(&self) -> Option<[u8; 32]> {
        self.identity_digest
    }

    /// Return the opaque operation digest.
    pub const fn operation_digest(&self) -> Option<[u8; 32]> {
        self.operation_digest
    }
}

impl fmt::Debug for AzureVmStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzureVmStatus")
            .field("phase", &self.phase)
            .field(
                "identity_digest",
                &self.identity_digest.map(|_| "<redacted>"),
            )
            .field(
                "operation_digest",
                &self.operation_digest.map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Azure VM controller.
pub struct AzureVmController<E> {
    provider_config: AzureVmConfig,
    settings: AzureVmGuestSettings,
    effect: Arc<E>,
    credentials: Arc<dyn AzureCredentialPort>,
    phase: AzureVmPhase,
    finalizer: bool,
    operation: Option<crate::effect::AzureOperationHandle>,
    vm_handle: Option<AzureVmHandle>,
    tag_digest: Option<TagDigest>,
    expected_tag_digest: TagDigest,
    identity_digest: Option<[u8; 32]>,
    bootstrap_psk: Option<BootstrapPsk>,
    bootstrap_service: BootstrapService,
    pending_delete_operation_id: Option<String>,
    bootstrap_started_at_unix_ms: Option<u64>,
    psk_delivery_attempts: u8,
    operation_started_at_unix_ms: Option<u64>,
    pending_update: Option<AzureVmUpdate>,
    clock: Arc<dyn AzureVmClock>,
    bootstrap_extension_present: bool,
    vm_delete_confirmed: bool,
    child_cleanup_complete: bool,
    bootstrap_deadline_failed: bool,
}

impl<E> AzureVmController<E>
where
    E: AzureEffectPort + 'static,
{
    /// Construct a controller after validating the two config layers.
    pub fn new(
        provider_config: AzureVmConfig,
        settings: AzureVmGuestSettings,
        effect: Arc<E>,
        credentials: Arc<dyn AzureCredentialPort>,
        bootstrap_psk: Option<BootstrapPsk>,
    ) -> Result<Self, AzureVmError> {
        provider_config.validate()?;
        settings.validate()?;
        let expected_tag_digest = TagDigest::from_tags(&settings.azure_tags);
        Ok(Self {
            provider_config,
            settings,
            effect,
            credentials,
            phase: AzureVmPhase::Absent,
            finalizer: true,
            operation: None,
            vm_handle: None,
            tag_digest: None,
            expected_tag_digest,
            identity_digest: None,
            bootstrap_psk,
            bootstrap_service: BootstrapService::default(),
            pending_delete_operation_id: None,
            bootstrap_started_at_unix_ms: None,
            psk_delivery_attempts: 0,
            operation_started_at_unix_ms: None,
            pending_update: None,
            clock: Arc::new(SystemAzureVmClock),
            bootstrap_extension_present: false,
            vm_delete_confirmed: false,
            child_cleanup_complete: false,
            bootstrap_deadline_failed: false,
        })
    }

    /// Inject the durable bootstrap service state recovered by the gateway.
    pub fn with_bootstrap_service(mut self, bootstrap_service: BootstrapService) -> Self {
        self.bootstrap_service = bootstrap_service;
        self
    }

    /// Replace the wall clock used for bootstrap deadlines.
    pub fn with_clock(mut self, clock: Arc<dyn AzureVmClock>) -> Self {
        self.clock = clock;
        self
    }

    /// Export non-secret state for the core-owned sealed recovery record.
    pub fn recovery_state(&self) -> AzureVmRecoveryState {
        AzureVmRecoveryState {
            phase: self.phase,
            finalizer_installed: self.finalizer,
            operation: self.operation.clone(),
            pending_delete_operation_id: self.pending_delete_operation_id.clone(),
            bootstrap_started_at_unix_ms: self.bootstrap_started_at_unix_ms,
            psk_delivery_attempts: self.psk_delivery_attempts,
            operation_started_at_unix_ms: self.operation_started_at_unix_ms,
            pending_update: self.pending_update.clone(),
            bootstrap_service_state: self.bootstrap_service.state(),
            bootstrap_extension_present: self.bootstrap_extension_present,
            vm_delete_confirmed: self.vm_delete_confirmed,
            child_cleanup_complete: self.child_cleanup_complete,
            bootstrap_deadline_failed: self.bootstrap_deadline_failed,
        }
    }

    /// Restore non-secret state after the controller has been reconstructed.
    pub fn restore_recovery_state(
        mut self,
        recovery: AzureVmRecoveryState,
    ) -> Result<Self, AzureVmError> {
        if recovery.operation.is_some() != recovery.operation_started_at_unix_ms.is_some()
            || (recovery.phase == AzureVmPhase::Reconfiguring
                && (recovery.operation.is_none() || recovery.pending_update.is_none()))
            || (recovery.pending_update.is_some() && recovery.phase != AzureVmPhase::Reconfiguring)
            || (matches!(
                recovery.phase,
                AzureVmPhase::PskCleaning | AzureVmPhase::ChildCleaning
            ) && recovery.operation.is_none())
            || (!recovery.finalizer_installed && recovery.phase != AzureVmPhase::Finalized)
            || recovery.psk_delivery_attempts > MAX_PSK_DELIVERY_ATTEMPTS
            || recovery
                .pending_delete_operation_id
                .as_ref()
                .is_some_and(|id| {
                    id.is_empty()
                        || id.len() > 128
                        || !id.bytes().all(|byte| byte.is_ascii_graphic())
                })
        {
            return Err(AzureVmError::InvalidConfiguration);
        }
        self.phase = recovery.phase;
        self.finalizer = recovery.finalizer_installed;
        self.operation = recovery.operation;
        self.pending_delete_operation_id = recovery.pending_delete_operation_id;
        self.bootstrap_started_at_unix_ms = recovery.bootstrap_started_at_unix_ms;
        self.psk_delivery_attempts = recovery.psk_delivery_attempts;
        self.operation_started_at_unix_ms = recovery.operation_started_at_unix_ms;
        self.pending_update = recovery.pending_update;
        self.bootstrap_service = BootstrapService::from_state(recovery.bootstrap_service_state);
        self.bootstrap_extension_present = recovery.bootstrap_extension_present;
        self.vm_delete_confirmed = recovery.vm_delete_confirmed;
        self.child_cleanup_complete = recovery.child_cleanup_complete;
        self.bootstrap_deadline_failed = recovery.bootstrap_deadline_failed;
        Ok(self)
    }

    /// Return the current phase.
    pub const fn phase(&self) -> AzureVmPhase {
        self.phase
    }

    /// Return whether the finalizer remains installed.
    pub const fn finalizer_installed(&self) -> bool {
        self.finalizer
    }

    /// Return the redacted status.
    pub fn status(&self) -> AzureVmStatus {
        AzureVmStatus {
            phase: self.phase,
            identity_digest: self.identity_digest,
            operation_digest: self.operation.as_ref().map(|operation| operation.digest()),
        }
    }

    /// Reconcile without blocking on ARM polling.
    pub async fn reconcile(
        &mut self,
        zone_uid: &str,
        guest_uid: &str,
        generation: u64,
    ) -> Result<AzureVmReconcileOutcome, AzureVmError> {
        if !self.finalizer {
            return Err(AzureVmError::InvalidConfiguration);
        }
        if let Some(operation) = self.operation.clone() {
            return self.poll_operation(operation).await;
        }
        if self.bootstrap_deadline_failed && self.pending_delete_operation_id.is_none() {
            self.phase = AzureVmPhase::Failed;
            if self.bootstrap_extension_present {
                return self.start_extension_cleanup().await;
            }
            return Err(AzureVmError::BootstrapFailed);
        }
        if self.pending_delete_operation_id.is_some() {
            self.phase = AzureVmPhase::Deleting;
            return self.start_pending_delete().await;
        }
        let token = self.arm_token().await?;
        let (state, handle, tags) = self.effect.get_vm_state(&self.settings, &token).await?;
        match state {
            AzureVmState::Absent => {
                let operation_id =
                    idempotency::operation_id(zone_uid, guest_uid, generation, "provision");
                let token = self.arm_token().await?;
                let operation = self
                    .effect
                    .start_vm_provision(&self.settings, &operation_id, &token)
                    .await?;
                self.set_operation(operation);
                self.phase = AzureVmPhase::Provisioning;
                Ok(AzureVmReconcileOutcome::Progressing { after_ms: 1_000 })
            }
            AzureVmState::Running => {
                let Some(handle) = handle else {
                    return Err(AzureVmError::Ambiguous);
                };
                let Some(tags) = tags else {
                    self.phase = AzureVmPhase::Failed;
                    return Err(AzureVmError::ArmResourceConflict);
                };
                if tags != self.expected_tag_digest {
                    self.phase = AzureVmPhase::Failed;
                    return Err(AzureVmError::ArmResourceConflict);
                }
                self.vm_handle = Some(handle);
                self.tag_digest = Some(tags);
                if self.bootstrap_psk.is_some()
                    && self.bootstrap_service.state() != BootstrapServiceState::Enrolled
                {
                    self.start_psk_delivery().await
                } else {
                    self.ready_if_enrolled(tags).await
                }
            }
            AzureVmState::Provisioning => {
                self.phase = AzureVmPhase::Provisioning;
                Ok(AzureVmReconcileOutcome::Progressing { after_ms: 1_000 })
            }
            AzureVmState::Stopped => {
                self.phase = AzureVmPhase::Draining;
                Ok(AzureVmReconcileOutcome::Retry { after_ms: 1_000 })
            }
            AzureVmState::Failed | AzureVmState::Unknown => {
                self.phase = AzureVmPhase::Failed;
                Err(AzureVmError::ArmProvisioningFailed)
            }
        }
    }

    /// Adopt a running VM only when its d2b tag digest matches.
    pub async fn adopt(&mut self) -> Result<AzureVmReconcileOutcome, AzureVmError> {
        if !self.finalizer {
            return Err(AzureVmError::InvalidConfiguration);
        }
        let token = self.arm_token().await?;
        let (state, handle, tags) = self.effect.get_vm_state(&self.settings, &token).await?;
        if state != AzureVmState::Running {
            return Err(AzureVmError::Transient);
        }
        let Some(handle) = handle else {
            return Err(AzureVmError::Ambiguous);
        };
        let Some(tags) = tags else {
            self.phase = AzureVmPhase::Failed;
            return Err(AzureVmError::ArmResourceConflict);
        };
        if tags != self.expected_tag_digest {
            self.phase = AzureVmPhase::Failed;
            return Err(AzureVmError::ArmResourceConflict);
        }
        self.vm_handle = Some(handle);
        self.tag_digest = Some(tags);
        self.ready_if_enrolled(tags).await
    }

    /// Advance the current opaque long-running operation.
    pub async fn poll_operation(
        &mut self,
        operation: crate::effect::AzureOperationHandle,
    ) -> Result<AzureVmReconcileOutcome, AzureVmError> {
        if self.operation.as_ref() != Some(&operation) {
            return Err(AzureVmError::InvalidOperationHandle);
        }
        if self.operation_expired() {
            self.clear_operation();
            self.pending_update = None;
            if self.pending_delete_operation_id.is_some() {
                self.phase = AzureVmPhase::Deleting;
                return self.start_pending_delete().await;
            }
            self.phase = AzureVmPhase::Failed;
            return Err(AzureVmError::ArmProvisioningFailed);
        }
        let token = self.arm_token().await?;
        match self.effect.poll_lro(&operation, &token).await? {
            LroStatus::InProgress { after_ms } => Ok(AzureVmReconcileOutcome::Progressing {
                after_ms: after_ms.max(1),
            }),
            LroStatus::Failed => {
                if self.phase == AzureVmPhase::PskCleaning {
                    self.clear_operation();
                    self.phase = AzureVmPhase::Failed;
                    return Err(AzureVmError::BootstrapFailed);
                }
                if self.phase == AzureVmPhase::ChildCleaning {
                    self.clear_operation();
                    self.phase = AzureVmPhase::Failed;
                    return Err(AzureVmError::Ambiguous);
                }
                self.clear_operation();
                self.pending_update = None;
                if self.pending_delete_operation_id.is_some() {
                    self.phase = AzureVmPhase::Deleting;
                    return self.start_pending_delete().await;
                }
                if self.phase == AzureVmPhase::PskDelivering {
                    return self.start_psk_delivery().await;
                }
                self.phase = AzureVmPhase::Failed;
                Err(AzureVmError::ArmProvisioningFailed)
            }
            LroStatus::Succeeded => {
                self.clear_operation();
                match self.phase {
                    AzureVmPhase::Provisioning => {
                        if self.pending_delete_operation_id.is_some() {
                            self.phase = AzureVmPhase::Deleting;
                            return self.start_pending_delete().await;
                        }
                        let token = self.arm_token().await?;
                        let (state, handle, tags) =
                            self.effect.get_vm_state(&self.settings, &token).await?;
                        if state != AzureVmState::Running {
                            self.phase = AzureVmPhase::Failed;
                            return Err(AzureVmError::ArmProvisioningFailed);
                        }
                        let Some(handle) = handle else {
                            self.phase = AzureVmPhase::Failed;
                            return Err(AzureVmError::Ambiguous);
                        };
                        let Some(tags) = tags else {
                            self.phase = AzureVmPhase::Failed;
                            return Err(AzureVmError::ArmResourceConflict);
                        };
                        if tags != self.expected_tag_digest {
                            self.phase = AzureVmPhase::Failed;
                            return Err(AzureVmError::ArmResourceConflict);
                        }
                        self.vm_handle = Some(handle.clone());
                        self.tag_digest = Some(tags);
                        if self.bootstrap_psk.is_some() {
                            self.start_psk_delivery().await
                        } else {
                            self.phase = AzureVmPhase::Bootstrapping;
                            Ok(AzureVmReconcileOutcome::Progressing { after_ms: 1_000 })
                        }
                    }
                    AzureVmPhase::PskDelivering => {
                        self.bootstrap_psk = None;
                        self.phase = AzureVmPhase::Bootstrapping;
                        Ok(AzureVmReconcileOutcome::Progressing { after_ms: 1_000 })
                    }
                    AzureVmPhase::PskCleaning => {
                        self.bootstrap_extension_present = false;
                        self.bootstrap_psk = None;
                        if self.bootstrap_deadline_failed {
                            self.phase = AzureVmPhase::Failed;
                            return Err(AzureVmError::BootstrapFailed);
                        }
                        if self.pending_delete_operation_id.is_some() {
                            self.phase = AzureVmPhase::Deleting;
                            return self.start_pending_delete().await;
                        }
                        self.phase = AzureVmPhase::Ready;
                        Ok(AzureVmReconcileOutcome::Converged)
                    }
                    AzureVmPhase::Reconfiguring => {
                        let update = self.pending_update.take().ok_or(AzureVmError::Ambiguous)?;
                        self.apply_update(update)?;
                        self.phase = AzureVmPhase::Ready;
                        Ok(AzureVmReconcileOutcome::Converged)
                    }
                    AzureVmPhase::Deleting => self.start_pending_delete().await,
                    AzureVmPhase::ChildCleaning => {
                        self.child_cleanup_complete = true;
                        self.finalizer = false;
                        self.pending_delete_operation_id = None;
                        self.phase = AzureVmPhase::Finalized;
                        Ok(AzureVmReconcileOutcome::Converged)
                    }
                    _ => Ok(AzureVmReconcileOutcome::Converged),
                }
            }
        }
    }

    /// Start one typed mutable update without blocking on ARM.
    pub async fn update(
        &mut self,
        zone_uid: &str,
        guest_uid: &str,
        generation: u64,
        update: AzureVmUpdate,
    ) -> Result<AzureVmReconcileOutcome, AzureVmError> {
        if !matches!(self.phase, AzureVmPhase::Ready) {
            return Err(AzureVmError::Transient);
        }
        if self.operation.is_some() || self.pending_update.is_some() {
            return Ok(AzureVmReconcileOutcome::Progressing { after_ms: 250 });
        }
        self.validate_update(&update)?;
        let handle = self.vm_handle.clone().ok_or(AzureVmError::Ambiguous)?;
        let operation_id =
            idempotency::operation_id(zone_uid, guest_uid, generation, update.operation_class());
        let token = self.arm_token().await?;
        let operation = match &update {
            AzureVmUpdate::Resize { size } => {
                self.effect
                    .start_vm_resize(&handle, size, &operation_id, &token)
                    .await?
            }
            AzureVmUpdate::AttachDisk { disk } => {
                self.effect
                    .start_disk_attach(&handle, disk, &operation_id, &token)
                    .await?
            }
            AzureVmUpdate::DetachDisk { lun } => {
                self.effect
                    .start_disk_detach(&handle, *lun, &operation_id, &token)
                    .await?
            }
            AzureVmUpdate::ReplaceTags { tags } => {
                self.effect
                    .update_vm_tags(&handle, tags, &operation_id, &token)
                    .await?
            }
        };
        self.pending_update = Some(update);
        self.set_operation(operation);
        self.phase = AzureVmPhase::Reconfiguring;
        Ok(AzureVmReconcileOutcome::Progressing { after_ms: 250 })
    }

    /// Begin deletion. The finalizer is retained until the LRO succeeds.
    pub async fn finalize(
        &mut self,
        zone_uid: &str,
        guest_uid: &str,
        generation: u64,
    ) -> Result<AzureVmReconcileOutcome, AzureVmError> {
        if !self.finalizer {
            return Ok(AzureVmReconcileOutcome::Converged);
        }
        let delete_operation_id = self
            .pending_delete_operation_id
            .get_or_insert_with(|| {
                idempotency::operation_id(zone_uid, guest_uid, generation, "delete")
            })
            .clone();
        if self.operation.is_some() {
            self.pending_update = None;
            if !matches!(
                self.phase,
                AzureVmPhase::PskCleaning | AzureVmPhase::ChildCleaning
            ) {
                self.phase = AzureVmPhase::Deleting;
            }
            return Ok(AzureVmReconcileOutcome::Progressing { after_ms: 1_000 });
        }
        if self.bootstrap_extension_present {
            self.pending_delete_operation_id = Some(delete_operation_id);
            self.phase = AzureVmPhase::Deleting;
            return self.start_extension_cleanup().await;
        }
        let token = self.arm_token().await?;
        let (state, handle, tags) = self.effect.get_vm_state(&self.settings, &token).await?;
        let handle = match state {
            AzureVmState::Absent => {
                self.vm_delete_confirmed = true;
                return self.start_child_cleanup().await;
            }
            AzureVmState::Running | AzureVmState::Stopped => {
                let Some(handle) = handle else {
                    self.phase = AzureVmPhase::Failed;
                    return Err(AzureVmError::Ambiguous);
                };
                let Some(tags) = tags else {
                    self.phase = AzureVmPhase::Failed;
                    return Err(AzureVmError::ArmResourceConflict);
                };
                if tags != self.expected_tag_digest {
                    self.phase = AzureVmPhase::Failed;
                    return Err(AzureVmError::ArmResourceConflict);
                }
                self.vm_handle = Some(handle.clone());
                self.tag_digest = Some(tags);
                handle
            }
            AzureVmState::Provisioning => {
                self.phase = AzureVmPhase::Deleting;
                return Ok(AzureVmReconcileOutcome::Retry { after_ms: 1_000 });
            }
            AzureVmState::Failed | AzureVmState::Unknown => {
                self.phase = AzureVmPhase::Failed;
                return Err(AzureVmError::Transient);
            }
        };
        let token = self.arm_token().await?;
        let operation = self
            .effect
            .start_vm_delete(&handle, &delete_operation_id, &token)
            .await?;
        self.set_operation(operation);
        self.phase = AzureVmPhase::Deleting;
        Ok(AzureVmReconcileOutcome::Progressing { after_ms: 1_000 })
    }

    /// Return the configured gateway execution reference.
    pub fn controller_execution_ref(&self) -> &d2b_contracts::ResourceRef {
        &self.provider_config.controller_execution_ref
    }

    /// Complete one authenticated bootstrap enrollment.
    pub fn complete_enrollment(
        &mut self,
        admission: &mut crate::bootstrap::BootstrapAdmission,
        presented: &[u8],
        now_unix_ms: u64,
    ) -> Result<(), AzureVmError> {
        if self.bootstrap_started_at_unix_ms.is_some_and(|started| {
            now_unix_ms.saturating_sub(started) >= self.settings.bootstrap_deadline_ms
        }) {
            return Err(AzureVmError::BootstrapFailed);
        }
        self.bootstrap_service
            .complete_enrollment(admission, presented, now_unix_ms)
    }

    async fn start_psk_delivery(&mut self) -> Result<AzureVmReconcileOutcome, AzureVmError> {
        let handle = self.vm_handle.clone().ok_or(AzureVmError::Ambiguous)?;
        let started = *self
            .bootstrap_started_at_unix_ms
            .get_or_insert_with(|| self.clock.now_unix_ms());
        if self.clock.now_unix_ms().saturating_sub(started) >= self.settings.bootstrap_deadline_ms {
            self.phase = AzureVmPhase::Failed;
            return Err(AzureVmError::BootstrapFailed);
        }
        if self.psk_delivery_attempts >= MAX_PSK_DELIVERY_ATTEMPTS {
            self.phase = AzureVmPhase::Failed;
            return Err(AzureVmError::BootstrapFailed);
        }
        let psk = self
            .bootstrap_psk
            .as_ref()
            .ok_or(AzureVmError::BootstrapFailed)?;
        let payload = PskExtensionPayload::from_secret(psk.copy_for_delivery().to_vec())?;
        let token = self.arm_token().await?;
        let operation = self
            .effect
            .put_vm_extension(&handle, payload, &token)
            .await?;
        self.psk_delivery_attempts = self.psk_delivery_attempts.saturating_add(1);
        self.bootstrap_extension_present = true;
        self.set_operation(operation);
        self.phase = AzureVmPhase::PskDelivering;
        Ok(AzureVmReconcileOutcome::Progressing { after_ms: 250 })
    }

    async fn ready_if_enrolled(
        &mut self,
        tags: TagDigest,
    ) -> Result<AzureVmReconcileOutcome, AzureVmError> {
        if self.bootstrap_service.state() != BootstrapServiceState::Enrolled {
            let started = *self
                .bootstrap_started_at_unix_ms
                .get_or_insert_with(|| self.clock.now_unix_ms());
            if self.clock.now_unix_ms().saturating_sub(started)
                >= self.settings.bootstrap_deadline_ms
            {
                self.phase = AzureVmPhase::Failed;
                self.bootstrap_deadline_failed = true;
                if self.bootstrap_extension_present {
                    return self.start_extension_cleanup().await;
                }
                return Err(AzureVmError::BootstrapFailed);
            }
            self.identity_digest = None;
            self.phase = AzureVmPhase::Bootstrapping;
            return Ok(AzureVmReconcileOutcome::Retry { after_ms: 1_000 });
        }
        if self.bootstrap_extension_present {
            return self.start_extension_cleanup().await;
        }
        self.bootstrap_psk = None;
        self.phase = AzureVmPhase::Ready;
        self.identity_digest = Some(Sha256::digest(tags.as_bytes()).into());
        Ok(AzureVmReconcileOutcome::Converged)
    }

    async fn start_pending_delete(&mut self) -> Result<AzureVmReconcileOutcome, AzureVmError> {
        if self.bootstrap_extension_present {
            return self.start_extension_cleanup().await;
        }
        let token = self.arm_token().await?;
        let (state, handle, tags) = self.effect.get_vm_state(&self.settings, &token).await?;
        match state {
            AzureVmState::Absent => {
                self.vm_delete_confirmed = true;
                self.start_child_cleanup().await
            }
            AzureVmState::Running | AzureVmState::Stopped => {
                let Some(handle) = handle else {
                    return Err(AzureVmError::Ambiguous);
                };
                let Some(tags) = tags else {
                    return Err(AzureVmError::ArmResourceConflict);
                };
                if tags != self.expected_tag_digest {
                    return Err(AzureVmError::ArmResourceConflict);
                }
                let operation_id = self
                    .pending_delete_operation_id
                    .clone()
                    .ok_or(AzureVmError::Ambiguous)?;
                let token = self.arm_token().await?;
                let operation = self
                    .effect
                    .start_vm_delete(&handle, &operation_id, &token)
                    .await?;
                self.set_operation(operation);
                self.phase = AzureVmPhase::Deleting;
                Ok(AzureVmReconcileOutcome::Progressing { after_ms: 1_000 })
            }

            AzureVmState::Provisioning => {
                self.phase = AzureVmPhase::Deleting;
                Ok(AzureVmReconcileOutcome::Retry { after_ms: 1_000 })
            }
            AzureVmState::Failed | AzureVmState::Unknown => {
                self.phase = AzureVmPhase::Failed;
                Err(AzureVmError::Transient)
            }
        }
    }

    async fn start_extension_cleanup(&mut self) -> Result<AzureVmReconcileOutcome, AzureVmError> {
        if self.operation.is_some() {
            return Ok(AzureVmReconcileOutcome::Progressing { after_ms: 250 });
        }
        let token = self.arm_token().await?;
        let operation = self
            .effect
            .delete_vm_extension(&self.settings, &token)
            .await?;
        self.set_operation(operation);
        self.phase = AzureVmPhase::PskCleaning;
        Ok(AzureVmReconcileOutcome::Progressing { after_ms: 250 })
    }

    async fn start_child_cleanup(&mut self) -> Result<AzureVmReconcileOutcome, AzureVmError> {
        if self.child_cleanup_complete {
            self.finalizer = false;
            self.pending_delete_operation_id = None;
            self.phase = AzureVmPhase::Finalized;
            return Ok(AzureVmReconcileOutcome::Converged);
        }
        if self.operation.is_some() {
            return Ok(AzureVmReconcileOutcome::Progressing { after_ms: 1_000 });
        }
        let operation_id = self
            .pending_delete_operation_id
            .as_deref()
            .ok_or(AzureVmError::Ambiguous)?;
        let token = self.arm_token().await?;
        let operation = self
            .effect
            .start_child_resource_cleanup(&self.settings, operation_id, &token)
            .await?;
        self.set_operation(operation);
        self.phase = AzureVmPhase::ChildCleaning;
        Ok(AzureVmReconcileOutcome::Progressing { after_ms: 1_000 })
    }

    fn set_operation(&mut self, operation: crate::effect::AzureOperationHandle) {
        self.operation = Some(operation);
        self.operation_started_at_unix_ms = Some(self.clock.now_unix_ms());
    }

    fn clear_operation(&mut self) {
        self.operation = None;
        self.operation_started_at_unix_ms = None;
    }

    fn operation_expired(&self) -> bool {
        self.operation_started_at_unix_ms.is_some_and(|started| {
            self.clock.now_unix_ms().saturating_sub(started) >= MAX_LRO_AGE_MS
        })
    }

    fn validate_update(&self, update: &AzureVmUpdate) -> Result<(), AzureVmError> {
        match update {
            AzureVmUpdate::Resize { size } => {
                d2b_contracts::OpaqueAzureRef::parse(size.clone())
                    .map_err(|_| AzureVmError::InvalidConfiguration)?;
            }
            AzureVmUpdate::AttachDisk { disk } => {
                let mut settings = self.settings.clone();
                settings.data_disks.push(disk.clone());
                settings.validate()?;
            }
            AzureVmUpdate::DetachDisk { lun } => {
                if !self.settings.data_disks.iter().any(|disk| disk.lun == *lun) {
                    return Err(AzureVmError::InvalidConfiguration);
                }
            }
            AzureVmUpdate::ReplaceTags { tags } => {
                let mut settings = self.settings.clone();
                settings.azure_tags = tags.clone();
                settings.validate()?;
            }
        }
        Ok(())
    }

    fn apply_update(&mut self, update: AzureVmUpdate) -> Result<(), AzureVmError> {
        match update {
            AzureVmUpdate::Resize { size } => {
                self.settings.vm_size = d2b_contracts::OpaqueAzureRef::parse(size)
                    .map_err(|_| AzureVmError::InvalidConfiguration)?;
            }
            AzureVmUpdate::AttachDisk { disk } => self.settings.data_disks.push(disk),
            AzureVmUpdate::DetachDisk { lun } => {
                self.settings.data_disks.retain(|disk| disk.lun != lun)
            }
            AzureVmUpdate::ReplaceTags { tags } => self.settings.azure_tags = tags,
        }
        self.settings.validate()?;
        self.expected_tag_digest = TagDigest::from_tags(&self.settings.azure_tags);
        Ok(())
    }

    async fn arm_token(&self) -> Result<AzureAccessToken, AzureVmError> {
        self.credentials
            .acquire_token("https://management.azure.com/", 30_000)
            .await
    }
}
