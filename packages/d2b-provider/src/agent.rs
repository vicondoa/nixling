//! Async v3 Provider-agent dispatch.
//!
//! The agent is a bounded service loop over an already-authenticated
//! ComponentSession.  It does not resolve a route, authenticate a subject, or
//! perform a privileged effect.  Those decisions happen before a message
//! reaches this module.

use std::{
    collections::VecDeque,
    future::Future,
    sync::{Arc, Mutex},
};

use d2b_contracts_provider::v3::{SpecifiedProviderMethod, provider_registry::ProviderBindingAxis};
use d2b_contracts_resource::v3::identity::ServiceName;
use d2b_contracts_resource::v3::{CanonicalJsonObject, ZoneId};
use tokio::{
    sync::{Semaphore, mpsc},
    time::{Duration, timeout},
};

/// Maximum concurrent Provider-agent dispatches.
pub const MAX_AGENT_IN_FLIGHT: usize = 64;
/// Maximum retained diagnostic events.
pub const MAX_AGENT_AUDIT_EVENTS: usize = 1024;
/// Maximum supported request timeout.
pub const MAX_AGENT_TIMEOUT_MS: u64 = 900_000;

/// One request delivered by an authenticated Provider session.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderAgentRequest {
    service: ServiceName,
    method: SpecifiedProviderMethod,
    payload: CanonicalJsonObject,
    timeout_ms: u64,
}

impl ProviderAgentRequest {
    /// Construct a bounded request.
    pub fn new(
        service: ServiceName,
        method: SpecifiedProviderMethod,
        payload: CanonicalJsonObject,
        timeout_ms: u64,
    ) -> Result<Self, ProviderAgentError> {
        if timeout_ms == 0 || timeout_ms > MAX_AGENT_TIMEOUT_MS {
            return Err(ProviderAgentError::InvalidTimeout);
        }
        Ok(Self {
            service,
            method,
            payload,
            timeout_ms,
        })
    }

    /// Borrow the exact service package.
    pub const fn service(&self) -> &ServiceName {
        &self.service
    }

    /// Return the closed method.
    pub const fn method(&self) -> SpecifiedProviderMethod {
        self.method
    }

    /// Borrow the canonical payload.
    pub const fn payload(&self) -> &CanonicalJsonObject {
        &self.payload
    }

    /// Return the bounded timeout.
    pub const fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }
}

impl core::fmt::Debug for ProviderAgentRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProviderAgentRequest(<redacted>)")
    }
}

/// One agent response.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderAgentResponse {
    payload: CanonicalJsonObject,
}

impl ProviderAgentResponse {
    /// Construct a response.
    pub const fn new(payload: CanonicalJsonObject) -> Self {
        Self { payload }
    }

    /// Borrow the canonical response payload.
    pub const fn payload(&self) -> &CanonicalJsonObject {
        &self.payload
    }
}

impl core::fmt::Debug for ProviderAgentResponse {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProviderAgentResponse(<redacted>)")
    }
}

/// The closed dispatch outcome retained in the bounded audit ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderAgentOutcome {
    /// The handler accepted the request.
    Accepted,
    /// The request named a service this agent does not serve.
    UnsupportedService,
    /// The handler or timeout failed the request.
    Failed,
}

/// One identity-free diagnostic event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderAgentAuditEvent {
    outcome: ProviderAgentOutcome,
    method: SpecifiedProviderMethod,
    axis: ProviderBindingAxis,
}

impl ProviderAgentAuditEvent {
    /// Construct an event with only closed metadata.
    pub const fn new(
        outcome: ProviderAgentOutcome,
        method: SpecifiedProviderMethod,
        axis: ProviderBindingAxis,
    ) -> Self {
        Self {
            outcome,
            method,
            axis,
        }
    }

    /// Return the outcome.
    pub const fn outcome(self) -> ProviderAgentOutcome {
        self.outcome
    }

    /// Return the method.
    pub const fn method(self) -> SpecifiedProviderMethod {
        self.method
    }

    /// Return the binding axis.
    pub const fn axis(self) -> ProviderBindingAxis {
        self.axis
    }
}

/// Agent service implementation.
pub trait ProviderAgentService: Send + Sync + 'static {
    /// Dispatch one request after the session has authenticated and authorized
    /// it.
    fn dispatch(
        &self,
        request: ProviderAgentRequest,
    ) -> impl Future<Output = Result<ProviderAgentResponse, ProviderAgentError>> + Send;
}

/// Messages accepted by the serving loop.
pub enum ProviderAgentMessage {
    /// A typed request.
    Request(ProviderAgentRequest),
    /// The authenticated session has closed; the loop must terminate.
    SessionClosed,
}

/// Typed Provider-agent failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderAgentError {
    /// The request timeout was zero or over the protocol maximum.
    InvalidTimeout,
    /// The request named a service this agent does not serve.
    UnsupportedService,
    /// The authenticated session closed.
    SessionClosed,
    /// All dispatch permits were occupied.
    DispatchSaturated,
    /// The handler exceeded the request timeout.
    DispatchTimeout,
    /// The Provider handler returned a failure.
    HandlerFailed,
}

impl core::fmt::Display for ProviderAgentError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidTimeout => "provider-agent-timeout-invalid",
            Self::UnsupportedService => "provider-agent-service-unsupported",
            Self::SessionClosed => "provider-agent-session-closed",
            Self::DispatchSaturated => "provider-agent-dispatch-saturated",
            Self::DispatchTimeout => "provider-agent-dispatch-timeout",
            Self::HandlerFailed => "provider-agent-handler-failed",
        })
    }
}

impl std::error::Error for ProviderAgentError {}

/// Bounded agent process state.
pub struct ProviderAgent<S> {
    zone: ZoneId,
    provider_axis: ProviderBindingAxis,
    service: S,
    permits: Arc<Semaphore>,
    audit: Mutex<VecDeque<ProviderAgentAuditEvent>>,
}

impl<S> ProviderAgent<S> {
    /// Construct an agent with the frozen dispatch and audit bounds.
    pub fn new(
        zone: ZoneId,
        provider_axis: ProviderBindingAxis,
        service: S,
    ) -> Result<Self, ProviderAgentError> {
        if matches!(provider_axis, ProviderBindingAxis::Unknown) {
            return Err(ProviderAgentError::UnsupportedService);
        }
        Ok(Self {
            zone,
            provider_axis,
            service,
            permits: Arc::new(Semaphore::new(MAX_AGENT_IN_FLIGHT)),
            audit: Mutex::new(VecDeque::with_capacity(MAX_AGENT_AUDIT_EVENTS)),
        })
    }

    /// Borrow the configured Zone.
    pub const fn zone(&self) -> &ZoneId {
        &self.zone
    }

    /// Return currently available dispatch permits.
    pub fn available_dispatch(&self) -> usize {
        self.permits.available_permits()
    }

    /// Snapshot retained audit events.
    pub fn audit_events(&self) -> Vec<ProviderAgentAuditEvent> {
        self.audit
            .lock()
            .map(|events| events.iter().copied().collect())
            .unwrap_or_default()
    }

    fn record(&self, event: ProviderAgentAuditEvent) {
        if let Ok(mut audit) = self.audit.lock() {
            if audit.len() == MAX_AGENT_AUDIT_EVENTS {
                audit.pop_front();
            }
            audit.push_back(event);
        }
    }
}

impl<S> ProviderAgent<S>
where
    S: ProviderAgentService,
{
    /// Dispatch one request with a bounded timeout.
    pub async fn dispatch(
        &self,
        request: ProviderAgentRequest,
    ) -> Result<ProviderAgentResponse, ProviderAgentError> {
        if request.service.as_str() != "d2b.provider.v3" {
            self.record(ProviderAgentAuditEvent::new(
                ProviderAgentOutcome::UnsupportedService,
                request.method,
                self.provider_axis,
            ));
            return Err(ProviderAgentError::UnsupportedService);
        }
        let permit = self
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| ProviderAgentError::DispatchSaturated)?;
        let result = timeout(
            Duration::from_millis(request.timeout_ms),
            self.service.dispatch(request.clone()),
        )
        .await
        .map_err(|_| ProviderAgentError::DispatchTimeout)?
        .map_err(|_| ProviderAgentError::HandlerFailed);
        drop(permit);
        self.record(ProviderAgentAuditEvent::new(
            if result.is_ok() {
                ProviderAgentOutcome::Accepted
            } else {
                ProviderAgentOutcome::Failed
            },
            request.method,
            self.provider_axis,
        ));
        result
    }

    /// Serve requests until the authenticated session closes or its channel
    /// is dropped.  A session close is a clean termination, not a retry loop.
    pub async fn serve(
        &self,
        mut requests: mpsc::Receiver<ProviderAgentMessage>,
        responses: mpsc::Sender<Result<ProviderAgentResponse, ProviderAgentError>>,
    ) -> Result<(), ProviderAgentError> {
        while let Some(message) = requests.recv().await {
            let request = match message {
                ProviderAgentMessage::Request(request) => request,
                ProviderAgentMessage::SessionClosed => return Ok(()),
            };
            let result = self.dispatch(request).await;
            if responses.send(result).await.is_err() {
                return Err(ProviderAgentError::SessionClosed);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::ready;

    struct Echo;

    impl ProviderAgentService for Echo {
        fn dispatch(
            &self,
            request: ProviderAgentRequest,
        ) -> impl Future<Output = Result<ProviderAgentResponse, ProviderAgentError>> + Send
        {
            ready(Ok(ProviderAgentResponse::new(request.payload.clone())))
        }
    }

    fn request(service: &str) -> ProviderAgentRequest {
        ProviderAgentRequest::new(
            ServiceName::parse(service).unwrap(),
            SpecifiedProviderMethod::AssessUpdate,
            CanonicalJsonObject::parse(br#"{"ok":true}"#).unwrap(),
            1_000,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn unsupported_service_returns_typed_error() {
        let agent = ProviderAgent::new(
            ZoneId::parse("dev").unwrap(),
            ProviderBindingAxis::Provider,
            Echo,
        )
        .unwrap();
        assert_eq!(
            agent.dispatch(request("d2b.audit.v3")).await,
            Err(ProviderAgentError::UnsupportedService)
        );
    }

    #[tokio::test]
    async fn negative_timeout_is_rejected_before_dispatch() {
        assert_eq!(
            ProviderAgentRequest::new(
                ServiceName::parse("d2b.provider.v3").unwrap(),
                SpecifiedProviderMethod::AssessUpdate,
                CanonicalJsonObject::empty(),
                0,
            )
            .unwrap_err(),
            ProviderAgentError::InvalidTimeout
        );
    }

    #[tokio::test]
    async fn session_close_terminates_serve_loop() {
        let agent = ProviderAgent::new(
            ZoneId::parse("dev").unwrap(),
            ProviderBindingAxis::Provider,
            Echo,
        )
        .unwrap();
        let (request_tx, request_rx) = mpsc::channel(1);
        let (response_tx, mut response_rx) = mpsc::channel(1);
        request_tx
            .send(ProviderAgentMessage::SessionClosed)
            .await
            .unwrap();
        drop(request_tx);
        agent.serve(request_rx, response_tx).await.unwrap();
        assert!(response_rx.try_recv().is_err());
    }
}
