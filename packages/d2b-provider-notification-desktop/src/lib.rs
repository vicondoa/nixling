//! Authenticated, transient desktop notification Provider.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod action_nonce;
mod admission;
mod audit;
mod controller;
mod descriptor;
mod error;
mod guest_source;
mod host_sink;
mod lifecycle;
mod metrics;
mod rbac;
mod redact;
mod runtime;
#[allow(missing_docs)]
pub mod security_key;
mod stream_admission;
mod types;

pub use action_nonce::{ActionNonce, ActionNonceError, ActionNonceStore};
pub use audit::{NotificationAuditKind, NotificationAuditRecord};
pub use controller::{
    DisplayDependencyEvidence, DisplayDependencyState, GuestSourceConfig, NotificationController,
    NotificationProviderConfig, NotificationRunnerContract, ProcessPlan,
    SourceProcessEffectPort, SourceProcessEffectReceipt, SourceReconcileResult,
    notification_runner_contract,
};
pub use descriptor::{NotificationDescriptorError, NotificationProviderDescriptor};
pub use error::ProviderError;
pub use guest_source::GuestSource;
pub use host_sink::{
    DesktopNotificationPort, NotificationProjection, NotificationResult, NotificationSink,
    SinkError,
};
pub use lifecycle::{
    NotificationHostSinkIdentity, NotificationLifecycleBackend, NotificationLifecycleObservation,
    NotificationLifecyclePlan, NotificationLifecycleReceipt, NotificationLifecycleSupervisor,
    NotificationSourceIdentity,
};
pub use metrics::{NotificationOutcome, NotificationTelemetryField, NotificationTelemetryFrame};
pub use rbac::{NotificationRbac, NotificationRole};
pub use redact::{SanitizedNotification, sanitize};
pub use runtime::{
    NotificationFinalizationReport, NotificationProcessEffectPort, NotificationRuntime,
    NotificationRuntimeError,
};
pub use stream_admission::{AdmissionError, AdmissionPurpose, SessionEvidence, TransportClass};
pub use types::{
    ActionSpec, Category, MAX_ACTIONS, MAX_BODY_CHARS, MAX_SUMMARY_CHARS, NotificationError,
    NotificationRequest, NotificationUrgency,
};

/// Canonical Provider reference.
pub const PROVIDER_REF: &str = "Provider/notification-desktop";
/// Canonical Provider artifact identifier.
pub const ARTIFACT_ID: &str = "notification-desktop";
/// Canonical service package.
pub const SERVICE_PACKAGE: &str = "d2b.notification.v3";
/// Guest-source to host-sink named stream.
pub const SINK_STREAM: &str = "DesktopNotificationSink";
/// Host-sink to observer named stream.
pub const OBSERVER_STREAM: &str = "DesktopNotificationObserver";
/// Maximum pending projection entries.
pub const DEFAULT_MAX_PENDING: usize = 64;
/// Canonical action nonce TTL in seconds.
pub const DEFAULT_NONCE_TTL_SECS: u64 = 120;
/// Canonical action nonce store capacity.
pub const DEFAULT_NONCE_STORE_SIZE: usize = 256;
/// Canonical observer acknowledgement timeout in seconds.
pub const DEFAULT_ACKNOWLEDGE_TIMEOUT_SECS: u64 = 3600;
