//! Optional, non-bootstrap observability Provider support.

#![forbid(unsafe_code)]

pub mod agent;
pub mod config;
pub mod controller;
pub mod emitter_socket;
pub mod ingress_policy;
pub mod metric_policy;
pub mod metrics;

pub const PROVIDER_NAME: &str = "observability-otel";
pub const PROVIDER_REF: &str = "Provider/observability-otel";
pub const PROVIDER_API_MAJOR: u16 = 1;

pub use agent::{
    ProviderAgentAuditEvent, ProviderAgentAuditOutcome, ProviderAgentError, ProviderAgentProcess,
};
pub use config::{
    AmbientCredentialError, ConfigError, ProviderConfig, reject_ambient_credential_chain,
    reject_process_environment_credential_chain,
};
pub use controller::{
    TelemetryBindingController, TelemetryBindingPhase, TelemetryBindingStatus,
    TelemetryComponentSession, TelemetryControllerError, TelemetryReconcileResult,
    TelemetryServiceController, TelemetryServiceError, TelemetryServicePhase, TelemetryServiceRole,
    TelemetryServiceStatus, TelemetryStreamAdmission, TelemetryStreamRequest,
    TelemetryStreamSignal,
};
pub use emitter_socket::{EmitterSocket, ReceiverReadiness};
pub use ingress_policy::{
    Ingress, IngressErrorClass, IngressOutcome, IngressPolicyGate, MetricFrame, MetricPoint,
};
pub use metric_policy::{
    IdentityCanaries, LabelDescriptor, MetricDescriptor, MetricPolicyError, ResourceAttributeError,
    allowed_values, canonical_descriptor, label, validate_data_point, validate_descriptor,
    validate_label_key, validate_resource_attributes,
};
