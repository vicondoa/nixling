//! Bounded Provider-agent dispatch and service-server adapters.
//!
//! The adapter is intentionally transport-agnostic.  A ComponentSession
//! receive loop supplies a canonical request, while this module owns the
//! fixed 64-call admission ceiling, the 1024-entry diagnostic audit ring,
//! and the bounded shutdown state.

use std::sync::Mutex;

use d2b_contracts_resource::v3::{
    CanonicalJsonObject, ResourceRef, execution_policy::BoundedToken,
};
use d2b_contracts_zone_session::v3::{
    component_session::RequestId,
    zone_routing::{ZoneLabelId, ZonePath},
};
use d2b_session::{AuthenticatedSessionRouteBinding, Cancellation, ComponentSessionDriver};

use crate::runtime::same_controller_identity;
use crate::{
    DispatchLimiter, ProviderAgentAuditEvent, ProviderAgentAuditLog, ProviderAgentAuditOutcome,
    ProviderToolkitError,
};

/// Validate the strict attachment-index sequence carried by a Provider
/// adapter.  Descriptors are numbered from zero and may not repeat, reorder,
/// or skip an index; rejecting before dispatch prevents an adapter from
/// confusing a stale attachment with a current one.
pub fn validate_attachment_indexes(indexes: &[u32]) -> Result<(), ProviderToolkitError> {
    for (expected, observed) in indexes.iter().enumerate() {
        if *observed != expected as u32 {
            return Err(ProviderToolkitError::NonMonotoneAttachmentIndexes);
        }
    }
    Ok(())
}

/// Provider-specific service implementation behind the generic adapter.
pub trait ProviderService: Send + Sync {
    /// Dispatch one canonical method payload.
    fn dispatch(
        &self,
        method: &BoundedToken,
        payload: &CanonicalJsonObject,
    ) -> Result<CanonicalJsonObject, ProviderToolkitError>;
}

/// One decoded request carried by an authenticated ComponentSession.
pub struct ProviderRequest {
    request_id: RequestId,
    zone: ZonePath,
    provider_ref: ResourceRef,
    method: BoundedToken,
    payload: CanonicalJsonObject,
}

impl ProviderRequest {
    /// Build a decoded request after binding all routing identity locally.
    pub fn new(
        request_id: RequestId,
        zone: ZonePath,
        provider_ref: ResourceRef,
        method: BoundedToken,
        payload: CanonicalJsonObject,
    ) -> Self {
        Self {
            request_id,
            zone,
            provider_ref,
            method,
            payload,
        }
    }

    /// Borrow the authenticated request correlation.
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    /// Borrow the Zone routing identity.
    pub const fn zone(&self) -> &ZonePath {
        &self.zone
    }

    /// Borrow the Provider resource identity.
    pub const fn provider_ref(&self) -> &ResourceRef {
        &self.provider_ref
    }

    /// Borrow the method.
    pub const fn method(&self) -> &BoundedToken {
        &self.method
    }

    /// Borrow the canonical payload.
    pub const fn payload(&self) -> &CanonicalJsonObject {
        &self.payload
    }
}

impl std::fmt::Debug for ProviderRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProviderRequest(<redacted>)")
    }
}

/// Codec owned by generated v3 service bindings.
pub trait ProviderFrameCodec: Send + Sync {
    /// Decode one authenticated request frame.
    fn decode_request(&self, frame: &[u8]) -> Result<ProviderRequest, ProviderToolkitError>;

    /// Encode one response frame for the request correlation.
    fn encode_response(
        &self,
        request_id: &RequestId,
        payload: &CanonicalJsonObject,
    ) -> Result<Vec<u8>, ProviderToolkitError>;
}

/// Bounded Provider-agent adapter.
pub struct ProviderAgentAdapter<S> {
    service: S,
    dispatch: DispatchLimiter,
    audit: Mutex<ProviderAgentAuditLog>,
    authenticated_route: Mutex<Option<AuthenticatedSessionRouteBinding>>,
}

impl<S> ProviderAgentAdapter<S> {
    /// Construct an adapter with the frozen dispatch and audit bounds.
    pub fn new(service: S) -> Self {
        Self {
            service,
            dispatch: DispatchLimiter::new(),
            audit: Mutex::new(ProviderAgentAuditLog::new()),
            authenticated_route: Mutex::new(None),
        }
    }

    /// Borrow the service implementation.
    pub const fn service(&self) -> &S {
        &self.service
    }

    /// Borrow dispatch accounting.
    pub const fn dispatch_limiter(&self) -> &DispatchLimiter {
        &self.dispatch
    }

    /// Snapshot retained audit events.
    pub fn audit_len(&self) -> usize {
        self.audit
            .lock()
            .map(|audit| audit.len())
            .unwrap_or_default()
    }

    /// Bind the adapter to one authenticated controller route.
    ///
    /// A route is admission evidence only. It does not grant a ResourceClient
    /// or effect capability, and a second route cannot replace the first one
    /// while this adapter is alive.
    pub fn bind_authenticated_route(
        &self,
        route: AuthenticatedSessionRouteBinding,
    ) -> Result<(), ProviderToolkitError> {
        if route.provider_ref().is_none()
            || route.provider_generation().is_none()
            || route.controller_generation().is_none()
            || route.reconnect_generation().get() == 0
        {
            return Err(ProviderToolkitError::SessionUnauthenticated);
        }
        let mut bound = self
            .authenticated_route
            .lock()
            .map_err(|_| ProviderToolkitError::SessionUnauthenticated)?;
        match bound.as_ref() {
            None => {
                *bound = Some(route);
                Ok(())
            }
            Some(existing) if existing == &route => Ok(()),
            Some(existing)
                if same_controller_identity(existing, &route)
                    && route.reconnect_generation() > existing.reconnect_generation() =>
            {
                *bound = Some(route);
                Ok(())
            }
            Some(_) => Err(ProviderToolkitError::SessionUnauthenticated),
        }
    }

    /// Whether an authenticated controller route has been bound.
    pub fn has_authenticated_route(&self) -> bool {
        self.authenticated_route
            .lock()
            .ok()
            .is_some_and(|route| route.is_some())
    }
}

impl<S> ProviderAgentAdapter<S>
where
    S: ProviderService,
{
    /// Dispatch one request under bounded admission and record its outcome.
    pub fn dispatch(
        &self,
        zone: ZonePath,
        provider_ref: ResourceRef,
        method: BoundedToken,
        payload: CanonicalJsonObject,
    ) -> Result<CanonicalJsonObject, ProviderToolkitError> {
        let bound = self
            .authenticated_route
            .lock()
            .map_err(|_| ProviderToolkitError::SessionUnauthenticated)?;
        if let Some(route) = bound.as_ref() {
            Self::validate_bound_request(route, &zone, &provider_ref)?;
        }
        self.dispatch_inner(zone, provider_ref, method, payload)
    }

    fn dispatch_for_route(
        &self,
        route: &AuthenticatedSessionRouteBinding,
        zone: ZonePath,
        provider_ref: ResourceRef,
        method: BoundedToken,
        payload: CanonicalJsonObject,
    ) -> Result<CanonicalJsonObject, ProviderToolkitError> {
        let bound = self
            .authenticated_route
            .lock()
            .map_err(|_| ProviderToolkitError::SessionUnauthenticated)?;
        let current_route = bound
            .as_ref()
            .ok_or(ProviderToolkitError::SessionUnauthenticated)?;
        if current_route != route {
            return Err(ProviderToolkitError::SessionUnauthenticated);
        }
        Self::validate_bound_request(route, &zone, &provider_ref)?;
        self.dispatch_inner(zone, provider_ref, method, payload)
    }

    fn dispatch_inner(
        &self,
        zone: ZonePath,
        provider_ref: ResourceRef,
        method: BoundedToken,
        payload: CanonicalJsonObject,
    ) -> Result<CanonicalJsonObject, ProviderToolkitError> {
        let _permit = self.dispatch.acquire()?;
        let result = self.service.dispatch(&method, &payload);
        let outcome = if result.is_ok() {
            ProviderAgentAuditOutcome::Accepted
        } else {
            ProviderAgentAuditOutcome::Failed
        };
        if let Ok(mut audit) = self.audit.lock() {
            audit.record(ProviderAgentAuditEvent::new(
                zone,
                provider_ref,
                method,
                outcome,
            ));
        }
        result
    }

    /// Serve decoded Provider frames from one authenticated
    /// ComponentSession until cancellation or transport close.
    ///
    /// Callers must bind the authenticated route before entering this loop.
    /// Every decoded target is checked against that binding.
    ///
    /// Session authentication, generation binding, attachment policy, and
    /// stream fairness remain owned by `d2b-session`; this loop only bridges
    /// the generated frame codec to the bounded Provider service adapter.
    pub async fn serve_component_session<D, C>(
        &self,
        driver: &D,
        codec: &C,
        cancellation: Cancellation,
    ) -> Result<(), ProviderToolkitError>
    where
        D: ComponentSessionDriver,
        C: ProviderFrameCodec,
    {
        let route = self
            .authenticated_route
            .lock()
            .map_err(|_| ProviderToolkitError::SessionUnauthenticated)?
            .clone()
            .ok_or(ProviderToolkitError::SessionUnauthenticated)?;
        loop {
            if cancellation.is_cancelled() {
                return Ok(());
            }
            let current_route = self
                .authenticated_route
                .lock()
                .map_err(|_| ProviderToolkitError::SessionUnauthenticated)?
                .clone()
                .ok_or(ProviderToolkitError::SessionUnauthenticated)?;
            if current_route != route {
                return Err(ProviderToolkitError::SessionUnauthenticated);
            }
            let frame = driver
                .receive_ttrpc()
                .await
                .map_err(|_| ProviderToolkitError::SessionClosed)?;
            let request = codec
                .decode_request(&frame)
                .map_err(|_| ProviderToolkitError::WireInvalid)?;
            let response = self.dispatch_for_route(
                &route,
                request.zone().clone(),
                request.provider_ref().clone(),
                request.method().clone(),
                request.payload().clone(),
            )?;
            let encoded = codec
                .encode_response(request.request_id(), &response)
                .map_err(|_| ProviderToolkitError::WireInvalid)?;
            driver
                .send_ttrpc_cancellable(encoded, cancellation.clone())
                .await
                .map_err(|_| ProviderToolkitError::SessionClosed)?;
        }
    }

    fn validate_bound_request(
        route: &AuthenticatedSessionRouteBinding,
        zone: &ZonePath,
        provider_ref: &ResourceRef,
    ) -> Result<(), ProviderToolkitError> {
        let expected_zone = ZonePath::new(vec![
            ZoneLabelId::parse(route.zone().as_str())
                .map_err(|_| ProviderToolkitError::SessionUnauthenticated)?,
        ])
        .map_err(|_| ProviderToolkitError::SessionUnauthenticated)?;
        let expected_provider = route
            .provider_ref()
            .ok_or(ProviderToolkitError::SessionUnauthenticated)?;
        if zone != &expected_zone || provider_ref != expected_provider {
            return Err(ProviderToolkitError::SessionUnauthenticated);
        }
        Ok(())
    }
}

/// Generated-service registration facade over a Provider agent adapter.
pub struct GeneratedProviderServiceServer<S> {
    adapter: ProviderAgentAdapter<S>,
}

impl<S> GeneratedProviderServiceServer<S> {
    /// Construct the generated service facade.
    pub fn new(service: S) -> Self {
        Self {
            adapter: ProviderAgentAdapter::new(service),
        }
    }

    /// Borrow the bounded adapter.
    pub const fn adapter(&self) -> &ProviderAgentAdapter<S> {
        &self.adapter
    }

    /// Bind the generated server to one authenticated controller route.
    pub fn bind_authenticated_route(
        &self,
        route: AuthenticatedSessionRouteBinding,
    ) -> Result<(), ProviderToolkitError> {
        self.adapter.bind_authenticated_route(route)
    }
}

impl<S> GeneratedProviderServiceServer<S>
where
    S: ProviderService,
{
    /// Serve the generated service over an authenticated ComponentSession.
    pub async fn serve_component_session<D, C>(
        &self,
        driver: &D,
        codec: &C,
        cancellation: Cancellation,
    ) -> Result<(), ProviderToolkitError>
    where
        D: ComponentSessionDriver,
        C: ProviderFrameCodec,
    {
        self.adapter
            .serve_component_session(driver, codec, cancellation)
            .await
    }
}

/// Fixed Provider-agent shutdown state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderAgentProcess {
    shutdown_deadline_ms: u32,
    stopping: bool,
}

impl ProviderAgentProcess {
    /// Maximum shutdown deadline accepted by the toolkit.
    pub const MAX_SHUTDOWN_DEADLINE_MS: u32 = 5_000;

    /// Construct a running process state.
    pub fn new(shutdown_deadline_ms: u32) -> Result<Self, ProviderToolkitError> {
        if shutdown_deadline_ms == 0 || shutdown_deadline_ms > Self::MAX_SHUTDOWN_DEADLINE_MS {
            return Err(ProviderToolkitError::CapacityOutOfRange);
        }
        Ok(Self {
            shutdown_deadline_ms,
            stopping: false,
        })
    }

    /// Request bounded shutdown.
    pub fn stop(&mut self) {
        self.stopping = true;
    }

    /// Complete the bounded shutdown transition.
    ///
    /// The transport owner performs the actual session close; this state
    /// transition is deliberately synchronous and cannot outlive the fixed
    /// deadline advertised by the process.
    pub async fn shutdown(&mut self) -> Result<(), ProviderToolkitError> {
        self.stop();
        Ok(())
    }

    /// Whether shutdown has been requested.
    pub const fn stopping(&self) -> bool {
        self.stopping
    }

    /// Return the configured shutdown deadline.
    pub const fn shutdown_deadline_ms(&self) -> u32 {
        self.shutdown_deadline_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use d2b_contracts_resource::v3::{ResourceName, ResourceTypeName};
    use d2b_contracts_zone_session::v3::zone_routing::ZoneLabelId;
    struct Echo;

    impl ProviderService for Echo {
        fn dispatch(
            &self,
            _method: &BoundedToken,
            payload: &CanonicalJsonObject,
        ) -> Result<CanonicalJsonObject, ProviderToolkitError> {
            Ok(payload.clone())
        }
    }

    fn zone() -> ZonePath {
        ZonePath::new(vec![ZoneLabelId::parse("dev").unwrap()]).unwrap()
    }

    fn provider() -> ResourceRef {
        ResourceRef::new(
            ResourceTypeName::parse("Provider").unwrap(),
            ResourceName::parse("system-core").unwrap(),
        )
    }

    #[test]
    fn adapter_dispatches_and_records_only_bounded_metadata() {
        let adapter = ProviderAgentAdapter::new(Echo);
        let result = adapter
            .dispatch(
                zone(),
                provider(),
                BoundedToken::parse("inspect").unwrap(),
                CanonicalJsonObject::parse(br#"{"ok":true}"#).unwrap(),
            )
            .unwrap();
        assert_eq!(
            result,
            CanonicalJsonObject::parse(br#"{"ok":true}"#).unwrap()
        );
        assert_eq!(adapter.audit_len(), 1);
    }

    #[test]
    fn shutdown_deadline_is_bounded() {
        assert!(ProviderAgentProcess::new(5_001).is_err());
        let mut process = ProviderAgentProcess::new(5_000).unwrap();
        process.stop();
        assert!(process.stopping());
    }

    #[test]
    fn attachment_indexes_are_strictly_monotone() {
        assert!(validate_attachment_indexes(&[0, 1, 2]).is_ok());
        assert_eq!(
            validate_attachment_indexes(&[0, 2]),
            Err(ProviderToolkitError::NonMonotoneAttachmentIndexes)
        );
        assert_eq!(
            validate_attachment_indexes(&[1, 0]),
            Err(ProviderToolkitError::NonMonotoneAttachmentIndexes)
        );
    }

    #[test]
    fn component_session_serving_requires_controller_route_admission() {
        use crate::Fixture;
        use d2b_provider::ProviderClass;
        use d2b_session::AuthenticatedSessionRouteBinding;

        let fixture = Fixture::new(ProviderClass::Runtime, 0).expect("fixture");
        let adapter = ProviderAgentAdapter::new(Echo);
        let missing_generation = AuthenticatedSessionRouteBinding::for_test(
            Some(fixture.descriptor.provider_ref().clone()),
            "d2b.provider.v3",
            1,
            Some(1),
            None,
        );
        assert_eq!(
            adapter.bind_authenticated_route(missing_generation),
            Err(ProviderToolkitError::SessionUnauthenticated)
        );
        assert!(!adapter.has_authenticated_route());

        let route = AuthenticatedSessionRouteBinding::for_test(
            Some(fixture.descriptor.provider_ref().clone()),
            "d2b.provider.v3",
            1,
            Some(1),
            Some(1),
        );
        assert!(adapter.bind_authenticated_route(route.clone()).is_ok());
        assert!(adapter.has_authenticated_route());
        assert!(adapter.bind_authenticated_route(route).is_ok());
        let reconnect = AuthenticatedSessionRouteBinding::for_test(
            Some(fixture.descriptor.provider_ref().clone()),
            "d2b.provider.v3",
            2,
            Some(1),
            Some(1),
        );
        assert!(adapter.bind_authenticated_route(reconnect).is_ok());
        assert_eq!(
            adapter.dispatch(
                d2b_contracts_zone_session::v3::zone_routing::ZonePath::new(vec![
                    d2b_contracts_zone_session::v3::zone_routing::ZoneLabelId::parse("dev")
                        .unwrap(),
                ])
                .unwrap(),
                d2b_contracts_resource::v3::ResourceRef::parse("Provider/other").unwrap(),
                BoundedToken::parse("inspect").unwrap(),
                CanonicalJsonObject::empty(),
            ),
            Err(ProviderToolkitError::SessionUnauthenticated)
        );
    }
}
