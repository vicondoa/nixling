//! Wayland display projection Provider.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod audit;
mod controller;
mod descriptor;
mod metrics;
mod policy;
mod portal;
mod principal;
mod process;
mod readiness;
mod runtime;
mod spec;
#[allow(missing_docs)]
pub mod wayland_proxy;
#[allow(missing_docs)]
pub mod wayland_proxy_argv;

pub use audit::{DisplayAuditKind, DisplayAuditOutcome, DisplayAuditRecord};
pub use controller::{
    AuthenticatedDisplaySession, CapabilityReadiness, CleanupState, DependencyReadiness,
    DependencyState, DisplayController, DisplayDependencyProof, DisplayRunnerContract,
    FinalizationDecision, FinalizationInput, GraceState, Phase, PrincipalReleaseReceipt,
    ReconcileResult, SessionCondition, StopRequest, WaylandPolicySnapshot,
    WaylandSessionResourceStatus, WaylandSessionStatus, display_runner_contract,
};
pub use descriptor::{DisplayDescriptorError, DisplayProviderDescriptor};
pub use metrics::{DisplayTelemetryField, DisplayTelemetryFrame, MetricOutcome};
pub use policy::{
    CompiledWaylandPolicy, FilterInput, KNOWN_GLOBALS, PolicyCompileError, PolicyWarning,
    WaylandPolicy,
};
pub use portal::{DisplayUserPortal, PortalError, PortalGrant, PortalSessionBinding};
pub use principal::{PrincipalLease, PrincipalPool, PrincipalPoolError};
pub use process::DisplayLaunchBinding;
pub use process::{
    AttachmentGrantHandle, DisplayProcessRole, LaunchGrants, LaunchTicket, ProcessObservation,
    ProxyProcessTemplate, ProxyReadinessFailure, ProxyReadinessStage, ProxyReadinessState,
    VolumeState, WorkerAction, WorkerRestartEvidence, WorkerState, WorkerSupervisor,
    WorkerSupervisorError,
};
pub use readiness::ProxyReadinessEvent;
pub use runtime::{
    DisplayProcessEffectPort, DisplayRuntime, DisplayRuntimeError, FinalizationReport,
    WorkerEffectError, WorkerLaunchReceipt,
};
pub use spec::{DisplayIdentity, DisplayLabelPosition, WaylandSessionSpec, WaylandSpecError};
pub use wayland_proxy_argv::{
    WaylandProxyArgvError, WaylandProxyArgvInput, WaylandProxyBorderConfig,
    WaylandProxyBorderLabelConfig, WaylandProxyBorderLabelPosition, generate_wayland_proxy_argv,
};

/// Canonical Provider reference.
pub const PROVIDER_REF: &str = "Provider/display-wayland";
/// Canonical display ComponentSession service package.
pub const SERVICE_PACKAGE: &str = "d2b.display.v3";
/// Canonical Provider artifact identifier.
pub const ARTIFACT_ID: &str = "display-wayland";
/// Canonical host proxy binary.
pub const HOST_PROXY_BINARY: &str = "d2b-display-wayland-host-proxy";
/// Canonical guest frontend binary.
pub const GUEST_FRONTEND_BINARY: &str = "wl-cross-domain-proxy";
/// Host clipboard service consumed by clipd-host.
pub const HOST_CLIPBOARD_SERVICE: &str = "d2b.display.host-clipboard.v3";
/// Internal bridge service consumed by the display proxy.
pub const CLIPBOARD_BRIDGE_SERVICE: &str = "d2b.clipboard.bridge.v3";
/// Display-session finalizer.
pub const FINALIZER: &str = "display-wayland.d2bus.org/proxy-stopped";
