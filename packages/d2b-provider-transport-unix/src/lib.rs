//! Authenticated local Unix transport for Zone-local Provider requests.

#![deny(missing_docs)]

/// Socket admission rules for local transport requests.
pub mod admission;
/// Bounded audit records for transport lifecycle events.
pub mod audit;
/// Accepted-socket request binding.
pub mod identity;
/// Bounded transport telemetry.
pub mod metrics;
/// The local transport portal and its owned monitor table.
pub mod portal;
/// Service lifecycle façade for the local transport portal.
pub mod service;

pub use admission::{OpenTransportRequest, RouteClass, SocketKind, TransportAdmissionError};
pub use identity::{BrokerRole, ExpectedPeer, TransportRequestBinding};
pub use portal::{
    OpenedTransport, PortalError, TransportDescriptor, TransportHandle, TransportObservation,
    TransportPortal,
};
