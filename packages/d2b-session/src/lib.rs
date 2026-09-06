//! Portable ComponentSession v3 runtime.
//!
//! Transport-specific socket and descriptor handling is intentionally outside
//! this crate. Callers provide an owned [`OwnedTransport`] implementation.

#![forbid(unsafe_code)]

mod admission;
mod attachment;
pub mod audit;
mod bootstrap;
mod cancellation;
mod client;
mod deadline;
mod driver;
mod engine;
mod error;
mod fragmentation;
mod handshake;
mod lifecycle;
mod metrics;
mod operation;
mod record;
mod scheduler;
mod server;
mod streams;
mod transport;
mod typed_stream;

pub use bootstrap::{AdmittedBootstrapPsk, BootstrapAdmission, BootstrapPsk, Secret32};
pub use cancellation::{Cancellation, RequestRegistry};
pub use client::SessionTtrpcClient;
pub use deadline::DeadlineBudget;
pub use driver::{ComponentSessionDriver, SessionDriverHandle};
pub use engine::{SessionEngine, SessionEvent};
pub use error::{Result, SessionError, SessionErrorClass};
pub use fragmentation::{Fragment, Fragmenter, Reassembler};
pub use handshake::{
    EstablishedHandshake, GENERATION_DISCOVERY_REQUEST_LEN, GENERATION_DISCOVERY_RESPONSE_LEN,
    HandshakeCredentials, HandshakeRole, NegotiatedOffer, NoiseHandshake,
    accept_generation_discovery_request, decode_generation_discovery_response,
    encode_generation_discovery_request, encode_generation_discovery_response, encode_offer,
    is_generation_discovery_request, negotiate_offer, x25519_public_key,
};
pub use lifecycle::{KeepaliveAction, SessionLifecycle, SessionPhase};
pub use metrics::{MetricEvent, MetricsSink, NoopMetrics};
pub use operation::{
    GENERATED_OPERATION_CATALOG, OperationCatalogEntry, OperationKind, OperationMember,
    SessionOperation, operation_catalog_entry, resource_operation,
};
pub use record::{ProtectedRecord, RecordProtector};
pub use scheduler::{FairScheduler, OutboundFrame, QueueClass};
pub use server::{
    SessionServerError, current_handler_cancellation, rewrite_ttrpc_stream_id,
    serve_ttrpc_services, ttrpc_is_request, ttrpc_is_response, ttrpc_request_id, ttrpc_stream_id,
};
pub use streams::{NamedStreamMux, StreamEvent, StreamId, StreamPhase};
pub use transport::{
    OwnedTransport, OwnedTransportHandle, TransportDescriptor, TransportError, TransportPacket,
    TransportReader, TransportWriter, serialized_transport_split,
};
pub use typed_stream::ComponentSessionStream;

pub use admission::{
    AuthenticatedComponentSession, AuthenticatedSessionDriver, AuthenticatedSessionRouteBinding,
    AuthenticatedTtrpcHandle, AuthorizedSessionOperation, SessionAcceptor,
    SessionAuthenticationBinding, SessionAuthorizationRequest, SessionCancellationHandle,
    SessionLiveness, SessionRegistrationCapability, TransportEvidence,
};
pub use attachment::{AttachmentPayload, AttachmentValidationError, OwnedAttachment};
pub use d2b_contracts_zone_session::v3::component_session as contract;
pub use d2b_resource_api::authz::SessionVerb;
