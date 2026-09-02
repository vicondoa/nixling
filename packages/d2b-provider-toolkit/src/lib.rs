//! The Provider authoring toolkit.
//!
//! Every Provider in the frozen catalog is an independently buildable crate
//! that binds one or more ResourceTypes, runs as one or more Processes, and
//! reaches host state only through an injected effect port. This crate owns
//! the provider-neutral half of that: the Zone-allocator bootstrap check a
//! Provider agent process performs before it serves anything, the bounded
//! audit ring and bounded in-flight dispatch accounting every agent needs,
//! the Provider resource conformance kit, and the redaction and test-driver
//! helpers each Provider crate would otherwise re-derive.
//!
//! What this crate deliberately does not do, because
//! `ADR-046-provider-model-and-packaging` forbids it for a Provider and for
//! a common Provider library:
//!
//! - It registers no Provider identity of its own and composes no Provider.
//!   It is a common library, so it can never become a hidden multi-Provider
//!   binary.
//! - It performs no privileged mutation. It opens no broker, D-Bus, or
//!   systemd socket, resolves no host path, spawns no process, and offers no
//!   direct-effect escape. A Provider validates semantics and calls its own
//!   injected typed effect port, which the fixed core effect adapter alone
//!   implements; the broker stays the sole privileged executor and
//!   independent audit owner of every host mutation.
//! - It defines no type that carries authority. The identity a bootstrap
//!   check returns names who the agent is so it can label an audit event
//!   and refuse a Zone it was not placed in; it authorizes no call, route,
//!   or effect. Authorization stays with ComponentSession admission and the
//!   Zone RBAC binding.
//! - It imports no daemon, broker, Zone-store, Nix-emitter, or Provider
//!   implementation internals. It depends on the shared v3 contract catalog,
//!   the neutral Provider registry SDK, and the transport-agnostic
//!   ComponentSession driver.
//!
//! No file descriptor, numeric UID or GID, device node, store path, socket
//! path, or host path appears in any type here. A bootstrap binding names a
//! Zone path, a `Provider/<name>` reference, a session purpose, and an
//! opaque channel-binding digest, and nothing else.

#![deny(missing_docs)]

// The adapter module retains its transport-loop helper for compatibility;
// the lifecycle-owning generated server lives in `server`.
#[allow(dead_code)]
mod agent;
mod audit;
mod bootstrap;
mod credential;
mod dispatch;
mod error;
#[cfg(feature = "unix-transport")]
mod fd10;
mod fixture;
mod redaction;
mod registration;
mod runtime;
mod server;
mod session_runtime;
mod typed_boundary;
mod values;

pub mod conformance;
pub mod fakes;
pub mod manifest;
pub mod schema;
pub mod testing;

pub use agent::{
    ProviderAgentAdapter, ProviderAgentProcess, ProviderFrameCodec, ProviderRequest,
    ProviderService, validate_attachment_indexes,
};
pub use audit::{
    DEFAULT_AUDIT_CAPACITY, ProviderAgentAuditEvent, ProviderAgentAuditLog,
    ProviderAgentAuditOutcome,
};
pub use bootstrap::{
    AllocatorSessionBinding, PROVIDER_RESOURCE_TYPE, ProviderAgentBootstrap, ProviderAgentIdentity,
};
pub use credential::{
    CredentialAuthorizationSource, RouteCredentialAuthorization, credential_service,
    run_authenticated_credential_provider,
};
pub use d2b_session::{
    AuthenticatedComponentSession, AuthenticatedSessionRouteBinding, Cancellation,
    ComponentSessionDriver, StreamEvent, StreamId,
};
pub use dispatch::{DispatchLimiter, DispatchPermit, MAX_DISPATCH_IN_FLIGHT};
#[cfg(feature = "unix-transport")]
pub use fd10::{
    PROVIDER_BOOTSTRAP_STREAM_CREDIT, PROVIDER_BOOTSTRAP_STREAM_ID, PROVIDER_READY_MARKER,
    PROVIDER_READY_STREAM_CREDIT, PROVIDER_READY_STREAM_ID, ProviderFd10Spec,
    ProviderSessionMetadata, run_from_fd10,
};
pub use error::ProviderToolkitError;
pub use fixture::{
    DeterministicClock, FakeProvider, Fixture, SampleLeaseRequest, sample_lease_request,
};
pub use redaction::Redacted;
pub use registration::{
    ExactRegistration, ToolkitError, register_exact_instances, validate_manifest_registration,
};
pub use runtime::{
    AuthenticatedRoute, ProviderAdmission, ProviderEntrypoint, ProviderLifecycle,
    ProviderRuntimeError, ProviderSessionAdmission,
};
pub use server::{
    GeneratedProviderServiceServer, GeneratedServiceDescriptor, MAX_SERVER_IN_FLIGHT, ServerError,
    ServerRequestPermit,
};
pub use session_runtime::{
    AuthenticatedProviderFrameCodec, AuthenticatedProviderRequest, run_authenticated_provider,
    serve_authenticated_component_session, validate_provider_route,
};
pub use typed_boundary::{ComponentSessionService, TransportProvider};
pub use values::{
    ProviderHealth, ProviderHealthState, ProviderInspection, ProviderObservability, ProviderValues,
    ValuesError,
};

/// Audited Unix attachment types used by Provider-specific transport adapters.
#[cfg(feature = "unix-transport")]
pub mod unix {
    pub use d2b_session_unix::{
        AcceptedAttachment, CreditBundle, VerifiedPacket, credential_provider_endpoint_policy,
    };
}
