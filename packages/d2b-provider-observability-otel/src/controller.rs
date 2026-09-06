//! Telemetry Service and Binding reconciliation through typed child intents.

use d2b_contracts_provider::v3::semantic_services::{
    SemanticFamily,
    child_resources::{
        BindingChildKind, BindingChildPlacement, BindingChildRequest, BindingChildSet,
        explicit_binding_children,
    },
};
use d2b_contracts_resource::v3::{ExecutionDomain, ResourceRef};

use crate::{
    IdentityCanaries, Ingress, IngressErrorClass, IngressOutcome, IngressPolicyGate, MetricFrame,
};

const TELEMETRY_PROVIDER_REF: &str = "Provider/observability-otel";
/// Qualified semantic telemetry Service type.
pub const TELEMETRY_SERVICE_RESOURCE_TYPE: &str = "telemetry.d2bus.org.TelemetryService";
/// Qualified semantic telemetry Binding type.
pub const TELEMETRY_BINDING_RESOURCE_TYPE: &str = "telemetry.d2bus.org.TelemetryBinding";

/// Semantic role of a telemetry Service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryServiceRole {
    /// One Zone-local ingest authority.
    Authority,
    /// Core-owned projection of a remote authority.
    Projection,
}

/// Lifecycle phase of a telemetry Service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryServicePhase {
    /// The Service is waiting for an ingest route.
    Pending,
    /// The Service has a usable ingest route.
    Ready,
    /// The Service is ambiguous, revoked, or unavailable.
    Degraded,
    /// The Service was finalized.
    Deleted,
}

/// Bounded, provider-neutral telemetry Service status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TelemetryServiceStatus {
    /// Current Service lifecycle phase.
    pub phase: TelemetryServicePhase,
    /// Number of admitted ingest endpoints.
    pub endpoint_count: u8,
    /// Whether the authority index is unique.
    pub authority_unique: bool,
}

/// Stable Service-controller failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryServiceError {
    /// The Service or Provider reference used the wrong type.
    InvalidReference,
    /// An authority did not have the required bounded endpoint set.
    InvalidAuthority,
    /// A finalized Service cannot be reconciled.
    Finalized,
}

impl core::fmt::Display for TelemetryServiceError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidReference => "telemetry-service-reference-invalid",
            Self::InvalidAuthority => "telemetry-service-authority-invalid",
            Self::Finalized => "telemetry-service-finalized",
        })
    }
}

impl std::error::Error for TelemetryServiceError {}

/// Resource-backed telemetry Service controller.
#[derive(Debug, Default)]
pub struct TelemetryServiceController {
    phase: TelemetryServicePhase,
}

impl Default for TelemetryServicePhase {
    fn default() -> Self {
        Self::Pending
    }
}

impl TelemetryServiceController {
    /// Construct a Service controller in the pending phase.
    pub fn new() -> Self {
        Self {
            phase: TelemetryServicePhase::Pending,
        }
    }

    /// Return the current Service phase.
    pub const fn phase(&self) -> TelemetryServicePhase {
        self.phase
    }

    /// Reconcile one Service without opening or mutating a transport.
    pub fn reconcile(
        &mut self,
        service_ref: &ResourceRef,
        provider_ref: &ResourceRef,
        role: TelemetryServiceRole,
        ingest_endpoint_refs: &[ResourceRef],
        authority_unique: bool,
        ingest_ready: bool,
    ) -> Result<TelemetryServiceStatus, TelemetryServiceError> {
        if service_ref.resource_type().as_str() != TELEMETRY_SERVICE_RESOURCE_TYPE
            || provider_ref.to_canonical_string() != TELEMETRY_PROVIDER_REF
        {
            return Err(TelemetryServiceError::InvalidReference);
        }
        if self.phase == TelemetryServicePhase::Deleted {
            return Err(TelemetryServiceError::Finalized);
        }
        if matches!(role, TelemetryServiceRole::Authority)
            && !(1..=8).contains(&ingest_endpoint_refs.len())
        {
            self.phase = TelemetryServicePhase::Degraded;
            return Err(TelemetryServiceError::InvalidAuthority);
        }
        if ingest_endpoint_refs
            .iter()
            .any(|endpoint| endpoint.resource_type().as_str() != "Endpoint")
            || (matches!(role, TelemetryServiceRole::Projection)
                && !ingest_endpoint_refs.is_empty())
        {
            self.phase = TelemetryServicePhase::Degraded;
            return Err(TelemetryServiceError::InvalidAuthority);
        }
        let endpoint_count = u8::try_from(ingest_endpoint_refs.len()).unwrap_or(u8::MAX);
        self.phase = if !authority_unique {
            TelemetryServicePhase::Degraded
        } else if ingest_ready {
            TelemetryServicePhase::Ready
        } else {
            TelemetryServicePhase::Pending
        };
        Ok(TelemetryServiceStatus {
            phase: self.phase,
            endpoint_count,
            authority_unique,
        })
    }

    /// Finalize the Service without touching an independently owned backend.
    pub fn finalize(&mut self) {
        self.phase = TelemetryServicePhase::Deleted;
    }
}

/// Closed telemetry signal carried by a ComponentSession stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryStreamSignal {
    /// Metrics frames.
    Metrics,
    /// Trace frames.
    Traces,
    /// Log frames.
    Logs,
}

/// A typed stream request. It carries semantic identity, never a locator or
/// resource mutation payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryStreamRequest {
    /// Service capability selected by the producer.
    pub service_ref: ResourceRef,
    /// Binding that owns producer intent.
    pub binding_ref: ResourceRef,
    /// Signal carried by this stream.
    pub signal: TelemetryStreamSignal,
}

/// A stream-only ComponentSession admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryStreamAdmission {
    request: TelemetryStreamRequest,
}

impl TelemetryStreamAdmission {
    /// Borrow the admitted semantic stream request.
    pub const fn request(&self) -> &TelemetryStreamRequest {
        &self.request
    }
}

/// Stream-only ComponentSession adapter for telemetry producers.
#[derive(Debug, Default, Clone, Copy)]
pub struct TelemetryComponentSession;

impl TelemetryComponentSession {
    /// Admit one stream and reject all resource-service-shaped references.
    pub fn open_stream(
        &self,
        request: TelemetryStreamRequest,
    ) -> Result<TelemetryStreamAdmission, TelemetryControllerError> {
        if request.service_ref.resource_type().as_str() != TELEMETRY_SERVICE_RESOURCE_TYPE
            || request.binding_ref.resource_type().as_str() != TELEMETRY_BINDING_RESOURCE_TYPE
        {
            return Err(TelemetryControllerError::Admission);
        }
        Ok(TelemetryStreamAdmission { request })
    }

    /// Resource mutation is deliberately outside the ComponentSession seam.
    pub const fn resource_mutation_forbidden() -> TelemetryControllerError {
        TelemetryControllerError::StreamOnly
    }
}

const TELEMETRY_ZONE_BINDING_CHILD_REQUESTS: [BindingChildRequest; 2] = [
    BindingChildRequest::process(
        BindingChildKind::Process,
        BindingChildPlacement::Host,
        "collector",
        "Provider/system-minijail",
        "otel-collector",
        ExecutionDomain::System,
        "service",
    ),
    BindingChildRequest::endpoint(BindingChildPlacement::Host, "ingest-endpoint", "collector"),
];

const TELEMETRY_GUEST_BINDING_CHILD_REQUESTS: [BindingChildRequest; 4] = [
    BindingChildRequest::process(
        BindingChildKind::Process,
        BindingChildPlacement::Host,
        "collector",
        "Provider/system-minijail",
        "otel-collector",
        ExecutionDomain::System,
        "service",
    ),
    BindingChildRequest::endpoint(BindingChildPlacement::Host, "ingest-endpoint", "collector"),
    BindingChildRequest::process(
        BindingChildKind::Process,
        BindingChildPlacement::Host,
        "forwarder",
        "Provider/system-minijail",
        "otel-vsock-forwarder",
        ExecutionDomain::System,
        "worker",
    ),
    BindingChildRequest::endpoint(
        BindingChildPlacement::Host,
        "forwarder-endpoint",
        "forwarder",
    ),
];

/// Closed lifecycle phase for one telemetry Binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryBindingPhase {
    /// The Binding's collector children or route are not ready.
    Pending,
    /// The route accepted the most recent frame.
    Ready,
    /// The route rejected or quarantined a frame.
    Degraded,
    /// The Binding's children have been released.
    Deleted,
}

/// Status observed by the telemetry Binding controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TelemetryBindingStatus {
    /// Current route lifecycle phase.
    pub phase: TelemetryBindingPhase,
    /// Most recent ingress outcome.
    pub outcome: Option<IngressOutcome>,
    /// Most recent policy error, when one was reported.
    pub error_class: Option<IngressErrorClass>,
}

/// Reconcile result including explicit child-resource intents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryReconcileResult {
    /// Binding status after the route decision.
    pub status: TelemetryBindingStatus,
    /// UID-free collector Process and Endpoint intents.
    pub children: BindingChildSet,
}

/// Closed telemetry controller failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryControllerError {
    /// Binding, Service, target, or Provider admission failed.
    Admission,
    /// Reconciliation was attempted after finalization.
    Finalized,
    /// A resource mutation was attempted through a stream-only session.
    StreamOnly,
}

impl core::fmt::Display for TelemetryControllerError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Admission => "telemetry-controller-admission-failed",
            Self::Finalized => "telemetry-controller-finalized",
            Self::StreamOnly => "telemetry-session-resource-mutation-forbidden",
        })
    }
}

impl std::error::Error for TelemetryControllerError {}

/// Provider-owned telemetry Binding controller.
///
/// The controller owns only bounded ingress policy state and child intent
/// declarations. Process launch, Endpoint publication, and cleanup remain
/// Core-managed resource effects.
pub struct TelemetryBindingController {
    gate: IngressPolicyGate,
    phase: TelemetryBindingPhase,
}

impl core::fmt::Debug for TelemetryBindingController {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("TelemetryBindingController")
            .field("phase", &self.phase)
            .field("gate", &self.gate)
            .finish()
    }
}

impl Default for TelemetryBindingController {
    fn default() -> Self {
        Self::new()
    }
}

impl TelemetryBindingController {
    /// Construct an empty telemetry Binding controller.
    pub fn new() -> Self {
        Self {
            gate: IngressPolicyGate::default(),
            phase: TelemetryBindingPhase::Pending,
        }
    }

    /// Return the current Binding lifecycle phase.
    pub const fn phase(&self) -> TelemetryBindingPhase {
        self.phase
    }

    /// Build the explicit collector children for one authored Binding.
    ///
    /// The telemetry collector is host-placed even when its producer is a
    /// Guest or Zone. The `target_ref` is the producer target from the
    /// semantic Binding and is still required for Core admission.
    pub fn child_resources(
        binding_ref: &ResourceRef,
        service_ref: &ResourceRef,
        target_ref: &ResourceRef,
    ) -> Result<BindingChildSet, TelemetryControllerError> {
        if !matches!(target_ref.resource_type().as_str(), "Guest" | "Zone") {
            return Err(TelemetryControllerError::Admission);
        }
        let declarations = if target_ref.resource_type().as_str() == "Guest" {
            &TELEMETRY_GUEST_BINDING_CHILD_REQUESTS[..]
        } else {
            &TELEMETRY_ZONE_BINDING_CHILD_REQUESTS[..]
        };
        explicit_binding_children(
            SemanticFamily::Telemetry,
            binding_ref.clone(),
            service_ref.clone(),
            target_ref.clone(),
            ResourceRef::parse(TELEMETRY_PROVIDER_REF)
                .expect("telemetry Provider reference is canonical"),
            declarations,
        )
        .map_err(|_| TelemetryControllerError::Admission)
    }

    /// Reconcile one bounded ingress frame and return the children owned by
    /// the explicit Binding.
    pub fn reconcile(
        &mut self,
        binding_ref: &ResourceRef,
        service_ref: &ResourceRef,
        target_ref: &ResourceRef,
        ingress: Ingress,
        connection_id: u64,
        frame: &MetricFrame,
        canaries: &IdentityCanaries,
        capacity_available: bool,
    ) -> Result<TelemetryReconcileResult, TelemetryControllerError> {
        if self.phase == TelemetryBindingPhase::Deleted {
            return Err(TelemetryControllerError::Finalized);
        }
        if connection_id == 0 {
            return Err(TelemetryControllerError::Admission);
        }
        let children = Self::child_resources(binding_ref, service_ref, target_ref)?;
        let (outcome, error_class) = self.gate.admit_for_connection(
            ingress,
            connection_id,
            frame,
            canaries,
            capacity_available,
        );
        self.phase = match outcome {
            IngressOutcome::Accepted => TelemetryBindingPhase::Ready,
            IngressOutcome::Rejected | IngressOutcome::Quarantined => {
                TelemetryBindingPhase::Degraded
            }
        };
        Ok(TelemetryReconcileResult {
            status: TelemetryBindingStatus {
                phase: self.phase,
                outcome: Some(outcome),
                error_class: Some(error_class),
            },
            children,
        })
    }

    /// Release the Binding's child intents before its finalizer is removed.
    pub fn finalize(&mut self) -> Result<(), TelemetryControllerError> {
        if self.phase == TelemetryBindingPhase::Deleted {
            return Ok(());
        }
        self.phase = TelemetryBindingPhase::Deleted;
        Ok(())
    }
}
