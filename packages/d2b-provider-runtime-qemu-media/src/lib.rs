//! Canonical `Provider/runtime-qemu-media` implementation.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod adoption;
pub mod audit;
pub mod config;
pub mod controller;
pub mod descriptor;
pub mod qemu_argv;
pub mod qmp;
pub mod state;
pub mod telemetry;
pub mod types;

pub use adoption::{AdoptionOutcome, ProcessIdentity, verify_identity};
pub use audit::{AuditEventKind, AuditOutcome, AuditRecord};
pub use config::{
    ControllerConfigProjection, ProviderConfig, ProviderConfigError, WorkerConfigProjection,
};
pub use controller::{
    AttachmentKind, AttachmentSlot, AuthorityReservation, DeviceAdmission, DeviceAdmissionError,
    DeviceObservation, DevicePhase, DisplayAttachment, DisplayObservation, DisplaySessionError,
    DisplaySessionPhase, HostGlobalAuthorityIndex, HotplugController, HotplugOperation,
    HotplugResult, LaunchTicket, LayoutEntry, MediaObservationError, MediaReadiness, MediaWatch,
    NetworkLaunchError, NetworkLaunchEvent, PlatformClass, ProcessSpec, ProcessSpecError,
    QemuMediaController, QemuMediaDependencies, QemuMediaEffectPort, QemuMediaError,
    QemuMediaPhase, QemuMediaReconcileOutcome, QemuMediaRecoveryState, RuntimeVolumeSpec,
    RuntimeVolumeView, TapAttachment, TapLaunchRouter, VolumeAttachment, VolumeLayoutType,
    VolumeObservation, VolumePhase, VolumeQuota, WaylandSessionSpec, build_process_spec,
    validate_process_spec,
};
pub use descriptor::{DescriptorError, ProviderDescriptor, QemuMediaProviderDescriptor};
pub use qemu_argv::{QemuMediaArgvError, QemuMediaArgvInput, exec_arg0, generate_qemu_media_argv};
pub use qmp::{
    QmpCommand, QmpError, QmpGreeting, QmpHealth, QmpReply, QmpSession, QmpTransport, QmpVmStatus,
    ScriptedQmpTransport,
};
pub use state::{GuestObservation, RuntimeState, StateError};
pub use telemetry::{
    MetricOutcome, QmpOperation, SpanKind, TelemetryError, TelemetryField, TelemetryFrame,
    TelemetrySpan,
};
pub use types::{
    Bios, ConditionStatus, CpuModel, DeviceAttachment, ExtraFeature, GuestCondition, GuestPhase,
    GuestProviderDetails, GuestProviderSpecSettings, GuestProviderStatus, GuestResourceSpecError,
    GuestRuntimeStatus, GuestSpec, GuestSpecError, GuestStatus, MachineType, NetworkAttachment,
    ProviderPhase, RemovableVolumeRef, RtcBase, build_guest_resource_spec,
};
pub use controller::reconcile::{
    QEMU_MEDIA_REPAIR_INTERVAL_SECS, qemu_media_runner_contract,
};

/// Stable Provider implementation identifier.
pub const QEMU_MEDIA_IMPLEMENTATION_ID: &str = "qemu-media";
/// Stable Provider resource reference.
pub const PROVIDER_REF: &str = "Provider/runtime-qemu-media";
/// Stable Guest finalizer.
pub const FINALIZER: &str = "runtime-qemu-media.d2bus.org/guest-cleanup";
