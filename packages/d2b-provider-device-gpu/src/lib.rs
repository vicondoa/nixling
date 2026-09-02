//! Combined GPU/video Device Provider contracts.
//!
//! Core resolves the opaque GPU effect-token set into broker `OpenDevice` and
//! `SpawnRunner` operations. This crate never receives a device path, socket,
//! capability, or ambient host permission.

#![deny(missing_docs)]

mod arbitration;
mod audit;
mod authority;
mod controller;
mod descriptor;
mod effects;
pub mod gpu_argv;
mod probe;
mod process;
mod production;
mod settings;
mod status;
mod telemetry;
pub mod video_argv;
mod wire;
mod worker_gpu;
mod worker_video;
mod workers;

pub use arbitration::{GpuArbitrator, GpuClaim, GpuClaimError};
pub use audit::{GpuAuditOperation, GpuAuditOutcome, GpuAuditRecord};
pub use authority::{
    GpuAdoption, GpuAuthorityAdmission, GpuAuthorityError, GpuAuthorityIndex, GpuAuthorityLease,
    GpuBackingToken, GpuClosureProof, GpuOwnerProof, GpuPlatformToken, GpuPrincipalToken,
    GpuProcessIdentity, GpuProcessObservation, GpuRecoveryRecord, GpuRecoverySnapshot,
};
pub use controller::{
    GPU_MAX_REPAIR_INTERVAL_SECS, GPU_REPAIR_INTERVAL_SECS, GpuController, GpuControllerError,
    GpuDependentResource, GpuPhase, GpuReconcileOutcome, GpuRunnerContract, GpuUpdateState,
    GpuUpgradePlan, gpu_runner_contract,
};
pub use descriptor::{GpuComponentDescriptor, GpuDescriptorError};
pub use effects::{
    GpuEffectError, GpuEffectPort, GpuEffectToken, GpuEffectTokenSet, GpuLaunchTicket,
    GpuLifecycleEffectPort,
};
pub use gpu_argv::{
    GpuArgvError, GpuArgvInput, GpuContextType, GpuDisplayConfig, GpuParams,
    exec_arg0 as gpu_exec_arg0, generate_gpu_argv,
};
pub use probe::{
    DEFAULT_OBSERVE_INTERVAL_SECS, GpuDeviceSelector, GpuProbeDisposition, GpuProbeError,
    GpuProbePort, GpuProbeResult, GpuProbeTracker, MAX_OBSERVE_INTERVAL_SECS,
    MIN_OBSERVE_INTERVAL_SECS,
};
pub use process::{
    GpuProcessDeclaration, GpuProcessRole, GpuProcessSelectionError, gpu_process_name,
};
pub use production::{GpuBrokerDispatcher, ProductionPort};
pub use settings::{ContextType, DisplayConfig, GpuSettings, GpuSettingsError};
pub use status::{
    GpuCondition, GpuConditionState, GpuConditionType, GpuStatus, GpuStatusError, GpuStatusPhase,
};
pub use telemetry::{GpuMetricLabels, GpuOperation, GpuOutcome};
pub use video_argv::{
    VideoArgvError, VideoArgvInput, VideoBackend, exec_arg0 as video_exec_arg0,
    generate_video_argv, wire_contract_snapshot as video_wire_contract_snapshot,
};
pub use wire::{
    VHOST_USER_MEDIA_NUM_QUEUES, VHOST_USER_MEDIA_PROTOCOL_FLAGS, VHOST_USER_MEDIA_QUEUE_SIZE,
    VHOST_USER_MEDIA_SHM_REGION_BYTES, VHOST_USER_MEDIA_VRING_BASE, VIRTIO_ID_MEDIA,
    wire_contract_snapshot,
};
pub use worker_gpu::build_gpu_worker;
pub use worker_video::build_video_worker;
pub use workers::{GpuDeviceNode, GpuWorkerSpec, VideoWorkerSpec};

/// Provider identity.
pub const PROVIDER_REF: &str = "Provider/device-gpu";
/// Device extension schema identifier.
pub const DEVICE_GPU_SCHEMA_ID: &str = "device-gpu.d2bus.org/Device/spec";
/// Device Provider finalizer.
pub const DEVICE_GPU_FINALIZER: &str = "device-gpu.d2bus.org/worker-stopped";
