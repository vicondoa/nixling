//! Provider-neutral typed ComponentSession boundaries.
//!
//! Resource-backed Providers use the ResourceService owned by the resource
//! API. Service-only and Transport Providers use the narrower typed traits in
//! this module; neither trait exposes a universal method switch or a host
//! mutation port.

use std::future::Future;

use d2b_session::{ComponentSessionStream, OwnedTransportHandle};

/// A service-only Provider component that owns one typed ComponentSession
/// named stream.
pub trait ComponentSessionService: Send + Sync + 'static {
    /// The component's closed stream failure type.
    type Error: Send + 'static;

    /// Serve the already-authenticated named stream.
    fn serve_stream(
        &self,
        stream: ComponentSessionStream,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// A typed Transport Provider boundary.
///
/// Implementations choose their own request and observation DTOs. The common
/// toolkit only carries the opaque, single-owner transport handle returned by
/// `open_transport`; it never interprets a Provider payload or performs host
/// mutation.
pub trait TransportProvider: Send + Sync + 'static {
    /// The Provider-owned open request DTO.
    type OpenRequest: Send + 'static;
    /// The Provider-owned transport observation DTO.
    type Observation: Send + 'static;
    /// The Provider-owned failure type.
    type Error: Send + 'static;

    /// Open one typed transport and return its opaque owned handle.
    fn open_transport(
        &self,
        request: Self::OpenRequest,
    ) -> impl Future<Output = Result<OwnedTransportHandle, Self::Error>> + Send;

    /// Close one previously opened opaque transport handle.
    fn close_transport(
        &self,
        handle: OwnedTransportHandle,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Observe one opened transport without exposing its implementation.
    fn observe_transport(
        &self,
        handle: &OwnedTransportHandle,
    ) -> impl Future<Output = Result<Self::Observation, Self::Error>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::ready;

    struct Service;

    impl ComponentSessionService for Service {
        type Error = ();

        fn serve_stream(
            &self,
            _stream: ComponentSessionStream,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send {
            ready(Ok(()))
        }
    }

    struct Transport;

    impl TransportProvider for Transport {
        type OpenRequest = ();
        type Observation = ();
        type Error = ();

        fn open_transport(
            &self,
            _request: Self::OpenRequest,
        ) -> impl Future<Output = Result<OwnedTransportHandle, Self::Error>> + Send {
            ready(Err(()))
        }

        fn close_transport(
            &self,
            _handle: OwnedTransportHandle,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send {
            ready(Err(()))
        }

        fn observe_transport(
            &self,
            _handle: &OwnedTransportHandle,
        ) -> impl Future<Output = Result<Self::Observation, Self::Error>> + Send {
            ready(Err(()))
        }
    }

    #[test]
    fn service_and_transport_boundaries_are_typed_without_a_rpc_catalogue() {
        fn assert_service<T: ComponentSessionService<Error = ()>>() {}
        fn assert_transport<
            T: TransportProvider<OpenRequest = (), Observation = (), Error = ()>,
        >() {
        }

        assert_service::<Service>();
        assert_transport::<Transport>();
    }
}
