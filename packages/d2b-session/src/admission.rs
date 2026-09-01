use std::{
    fmt,
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use async_trait::async_trait;
use d2b_contracts_resource::v3::identity::{
    AuthenticatedSubjectContext, BindingDigest, EvidenceClass, Locality, ReconnectGeneration,
    ServiceName, SessionPurpose, TranscriptHash, TransportBinding as IdentityTransportBinding,
};
use d2b_contracts_resource::v3::{
    ControllerGeneration, ResourceGeneration, ResourceRef, ResourceUid, SchemaFingerprint, ZoneId,
};
use d2b_contracts_zone_session::v3::component_session::{
    AuthorizationLease, BootstrapIdentityBinding, ChannelClass, ComponentSessionBoundary,
    ComponentSessionDescriptor, EndpointPolicy, EndpointPurpose, EndpointRole, HandshakeOffer,
    HealthState, Locality as ComponentLocality, MetricLabels, MetricReason, MetricResult,
    NoiseProfile, OperationClass, PurposeClass, RequestId, ServicePackage, SessionErrorCode,
    TransportClass,
};
use d2b_resource_api::authz::SessionVerb;

use crate::{
    Cancellation, ComponentSessionDriver, ComponentSessionStream, MetricEvent, MetricsSink,
    NoopMetrics, OwnedAttachment, OwnedTransport, Result, SessionDriverHandle, SessionEngine,
    SessionError, SessionEvent, SessionOperation, StreamEvent, StreamId,
    handshake::EstablishedAuthentication, metrics::reason_for_error,
};

/// Redacted transport evidence presented to the trusted session authority.
///
/// This is evidence input, not an authenticated identity. The authority must
/// validate it against its private registry before returning a subject.
pub struct TransportEvidence {
    class: EvidenceClass,
    binding_digest: BindingDigest,
}

impl TransportEvidence {
    /// Construct evidence from a transport adapter's verified observation.
    pub fn new(class: EvidenceClass, binding_digest: BindingDigest) -> Self {
        Self {
            class,
            binding_digest,
        }
    }

    /// Return the evidence class.
    pub const fn class(&self) -> EvidenceClass {
        self.class
    }

    /// Borrow the redacted evidence binding.
    pub fn binding_digest(&self) -> &BindingDigest {
        &self.binding_digest
    }
}

impl fmt::Debug for TransportEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TransportEvidence(<redacted>)")
    }
}

/// Liveness marker shared by an authenticated session and its route metadata.
///
/// The marker has no public constructor or revocation method. It becomes
/// inactive when the owning authenticated session is dropped, so a retained
/// route snapshot cannot outlive that session's owner.
#[derive(Clone)]
pub struct SessionLiveness(Arc<AtomicBool>);

impl SessionLiveness {
    fn new() -> Self {
        Self(Arc::new(AtomicBool::new(true)))
    }

    /// Whether the authenticated session owner is still live.
    pub fn is_live(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    fn invalidate(&self) {
        self.0.store(false, Ordering::Release);
    }
}

impl fmt::Debug for SessionLiveness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionLiveness(<redacted>)")
    }
}

impl PartialEq for SessionLiveness {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for SessionLiveness {}

struct SessionLivenessOwner(SessionLiveness);

impl SessionLivenessOwner {
    fn new() -> Self {
        Self(SessionLiveness::new())
    }

    fn marker(&self) -> SessionLiveness {
        self.0.clone()
    }
}

impl Drop for SessionLivenessOwner {
    fn drop(&mut self) {
        self.0.invalidate();
    }
}

/// Immutable handshake values supplied to the trusted authority.
pub struct SessionAuthenticationBinding {
    evidence_class: EvidenceClass,
    purpose: SessionPurpose,
    purpose_class: PurposeClass,
    initiator_role: EndpointRole,
    responder_role: EndpointRole,
    endpoint_locality: ComponentLocality,
    service: ServiceName,
    schema_fingerprint: SchemaFingerprint,
    transport_class: TransportClass,
    transport_binding: IdentityTransportBinding,
    bootstrap_identity: Option<BootstrapIdentityBinding>,
    reconnect_generation: ReconnectGeneration,
    transcript_hash: TranscriptHash,
    remote_static_key: Option<[u8; 32]>,
}

impl SessionAuthenticationBinding {
    /// Return the required authenticated evidence class.
    pub const fn evidence_class(&self) -> EvidenceClass {
        self.evidence_class
    }

    /// Borrow the endpoint purpose.
    pub fn purpose(&self) -> &SessionPurpose {
        &self.purpose
    }

    /// Return the authenticated purpose class.
    pub const fn purpose_class(&self) -> PurposeClass {
        self.purpose_class
    }

    /// Return the authenticated initiator role.
    pub const fn initiator_role(&self) -> EndpointRole {
        self.initiator_role
    }

    /// Return the authenticated responder role.
    pub const fn responder_role(&self) -> EndpointRole {
        self.responder_role
    }

    /// Return the exact authenticated ComponentSession locality.
    pub const fn endpoint_locality(&self) -> ComponentLocality {
        self.endpoint_locality
    }

    /// Borrow the exact service name.
    pub fn service(&self) -> &ServiceName {
        &self.service
    }

    /// Borrow the exact schema fingerprint.
    pub fn schema_fingerprint(&self) -> &SchemaFingerprint {
        &self.schema_fingerprint
    }

    /// Return the exact transport class authenticated by the Noise prologue.
    pub const fn transport_class(&self) -> TransportClass {
        self.transport_class
    }

    /// Borrow the transport channel binding.
    pub fn transport_binding(&self) -> &IdentityTransportBinding {
        &self.transport_binding
    }

    /// Borrow the one-time identity consumed by an IKpsk2 handshake.
    pub fn bootstrap_identity(&self) -> Option<&BootstrapIdentityBinding> {
        self.bootstrap_identity.as_ref()
    }

    /// Return the reconnect generation.
    pub const fn reconnect_generation(&self) -> ReconnectGeneration {
        self.reconnect_generation
    }

    /// Borrow the Noise transcript hash.
    pub fn transcript_hash(&self) -> &TranscriptHash {
        &self.transcript_hash
    }

    /// Borrow the authenticated remote static key for enrolled or bootstrap profiles.
    pub fn remote_static_key(&self) -> Option<&[u8; 32]> {
        self.remote_static_key.as_ref()
    }
}

impl fmt::Debug for SessionAuthenticationBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionAuthenticationBinding(<redacted>)")
    }
}

/// Exact authorization attributes presented by the session to its authority.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionAuthorizationRequest {
    verb: SessionVerb,
    operation: SessionOperation,
    target_zone: ZoneId,
    target: Option<ResourceRef>,
    forwarded_target_verb: Option<SessionVerb>,
    next_hop_zone: Option<ZoneId>,
}

impl SessionAuthorizationRequest {
    /// Build an exact method or stream authorization request.
    pub fn new(
        verb: SessionVerb,
        service: ServiceName,
        operation: impl Into<String>,
        target_zone: ZoneId,
        target: Option<ResourceRef>,
    ) -> Result<Self> {
        Self::new_inner(verb, service, operation, target_zone, target, None, None)
    }

    /// Build a one-hop relay request with immutable target authorization.
    pub fn relay(
        service: ServiceName,
        operation: impl Into<String>,
        target_zone: ZoneId,
        target: Option<ResourceRef>,
        forwarded_target_verb: SessionVerb,
        next_hop_zone: ZoneId,
    ) -> Result<Self> {
        Self::new_inner(
            SessionVerb::Relay,
            service,
            operation,
            target_zone,
            target,
            Some(forwarded_target_verb),
            Some(next_hop_zone),
        )
    }

    fn new_inner(
        verb: SessionVerb,
        service: ServiceName,
        operation: impl Into<String>,
        target_zone: ZoneId,
        target: Option<ResourceRef>,
        forwarded_target_verb: Option<SessionVerb>,
        next_hop_zone: Option<ZoneId>,
    ) -> Result<Self> {
        let operation = operation.into();
        let stream = matches!(
            if verb == SessionVerb::Relay {
                forwarded_target_verb.unwrap_or(verb)
            } else {
                verb
            },
            SessionVerb::OpenStream | SessionVerb::Observe
        );
        let operation = if stream {
            SessionOperation::stream(service, operation)?
        } else {
            SessionOperation::method(service, operation)?
        };
        let relay_fields_valid = matches!(verb, SessionVerb::Relay)
            == (forwarded_target_verb.is_some() && next_hop_zone.is_some());
        let relay_target_valid = forwarded_target_verb.is_none_or(|target_verb| {
            matches!(
                target_verb,
                SessionVerb::Invoke
                    | SessionVerb::OpenStream
                    | SessionVerb::Cancel
                    | SessionVerb::Observe
            )
        });
        let diagnostic_binding_valid = match verb {
            SessionVerb::AuditExport => {
                operation.diagnostic_verb() == Some(SessionVerb::AuditExport)
            }
            SessionVerb::SupportBundle => {
                operation.diagnostic_verb() == Some(SessionVerb::SupportBundle)
            }
            _ => operation.diagnostic_verb().is_none(),
        };
        if !relay_fields_valid || !relay_target_valid || !diagnostic_binding_valid {
            return Err(SessionError::new(SessionErrorCode::PolicyDenied));
        }
        Ok(Self {
            verb,
            operation,
            target_zone,
            target,
            forwarded_target_verb,
            next_hop_zone,
        })
    }

    /// Return the closed session verb.
    pub const fn verb(&self) -> SessionVerb {
        self.verb
    }

    /// Borrow the exact service.
    pub fn service(&self) -> &ServiceName {
        self.operation.service()
    }

    /// Borrow the exact method or named-stream operation.
    pub fn operation(&self) -> &str {
        self.operation.member().as_str()
    }

    /// Borrow the typed exact service operation.
    pub const fn operation_contract(&self) -> &SessionOperation {
        &self.operation
    }

    /// Return whether this request is the bounded target-local Guest seed
    /// operation.
    pub fn is_guest_resource_commit_batch(&self) -> bool {
        self.verb == SessionVerb::Invoke && self.operation.is_guest_resource_commit_batch()
    }

    /// Borrow the immutable target Zone.
    pub fn target_zone(&self) -> &ZoneId {
        &self.target_zone
    }

    /// Borrow the optional exact resource target.
    pub fn target(&self) -> Option<&ResourceRef> {
        self.target.as_ref()
    }

    /// Return the immutable forwarded target verb for a relay.
    pub const fn forwarded_target_verb(&self) -> Option<SessionVerb> {
        self.forwarded_target_verb
    }

    /// Borrow the route-selected next hop for a relay.
    pub fn next_hop_zone(&self) -> Option<&ZoneId> {
        self.next_hop_zone.as_ref()
    }
}

impl fmt::Debug for SessionAuthorizationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionAuthorizationRequest")
            .field("verb", &self.verb)
            .field("service", &"<redacted>")
            .field("operation", &"<redacted>")
            .field("target", &"<redacted>")
            .finish()
    }
}

mod authority_seal {
    pub trait Sealed {}
}

/// Trusted evidence mapper and native authorization hook.
///
/// Implementations are confined to this crate. The acceptor consumes this
/// object and stores it beside the authenticated subject. Neither value can be
/// recovered or shared independently.
#[async_trait]
trait SessionAuthority: authority_seal::Sealed + Send {
    /// Authenticate evidence, map one subject, and authorize session connect.
    async fn authenticate_connect(
        &mut self,
        evidence: TransportEvidence,
        binding: &SessionAuthenticationBinding,
        expected_zone: &ZoneId,
        now_tick: u64,
    ) -> Result<(AuthenticatedSubjectContext, AuthorizationLease)>;

    /// Revalidate one exact method or stream under current native policy.
    async fn authorize(
        &mut self,
        subject: &AuthenticatedSubjectContext,
        request: &SessionAuthorizationRequest,
        previous_lease: AuthorizationLease,
        now_tick: u64,
    ) -> Result<AuthorizationLease>;
}

type AuthenticateSession = dyn FnOnce(
        TransportEvidence,
        &SessionAuthenticationBinding,
        &ZoneId,
        u64,
    ) -> Result<(AuthenticatedSubjectContext, AuthorizationLease)>
    + Send;
type AuthorizeSession = dyn FnMut(
        &AuthenticatedSubjectContext,
        &SessionAuthorizationRequest,
        AuthorizationLease,
        u64,
    ) -> Result<AuthorizationLease>
    + Send;

struct VerifiedAdapterAuthority {
    authenticate: Option<Box<AuthenticateSession>>,
    authorize: Box<AuthorizeSession>,
    authenticated_subject: Option<AuthenticatedSubjectContext>,
}

impl authority_seal::Sealed for VerifiedAdapterAuthority {}

#[async_trait]
impl SessionAuthority for VerifiedAdapterAuthority {
    async fn authenticate_connect(
        &mut self,
        evidence: TransportEvidence,
        binding: &SessionAuthenticationBinding,
        expected_zone: &ZoneId,
        now_tick: u64,
    ) -> Result<(AuthenticatedSubjectContext, AuthorizationLease)> {
        let authenticate = self
            .authenticate
            .take()
            .ok_or_else(|| SessionError::new(SessionErrorCode::PolicyDenied))?;
        let (subject, lease) = authenticate(evidence, binding, expected_zone, now_tick)?;
        self.authenticated_subject = Some(subject.clone());
        Ok((subject, lease))
    }

    async fn authorize(
        &mut self,
        subject: &AuthenticatedSubjectContext,
        request: &SessionAuthorizationRequest,
        previous_lease: AuthorizationLease,
        now_tick: u64,
    ) -> Result<AuthorizationLease> {
        if self.authenticated_subject.as_ref() != Some(subject) {
            return Err(SessionError::new(SessionErrorCode::PolicyDenied));
        }
        (self.authorize)(subject, request, previous_lease, now_tick)
    }
}

impl fmt::Debug for VerifiedAdapterAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedAdapterAuthority(<redacted>)")
    }
}

/// Single-use builder for an authenticated ComponentSession.
///
/// The authority implementation is private and sealed:
///
/// ```compile_fail
/// use d2b_session::SessionAuthority;
/// ```
///
/// The acceptor itself cannot be cloned, default-constructed, or created from
/// caller input:
///
/// ```compile_fail
/// use d2b_session::SessionAcceptor;
///
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<SessionAcceptor<()>>();
/// ```
///
/// ```compile_fail
/// use d2b_session::SessionAcceptor;
///
/// fn requires_default<T: Default>() {}
/// requires_default::<SessionAcceptor<()>>();
/// ```
///
/// ```compile_fail
/// use d2b_session::SessionAcceptor;
///
/// let _: SessionAcceptor<()> = <() as Into<SessionAcceptor<()>>>::into(());
/// ```
pub struct SessionAcceptor<C> {
    policy: EndpointPolicy,
    expected_zone: ZoneId,
    authority: Box<dyn SessionAuthority>,
    metrics: Arc<dyn MetricsSink>,
    registration_capability: C,
}

fn assert_session_acceptor_has_no_minting_traits<C>() {
    // Any guarded impl makes this assertion ambiguous. Remove the capability
    // trait impl instead of weakening this construction boundary.
    trait CapabilityMustNotImplementCloneCopyDefaultOrFrom<A, B> {
        fn some_item() {}
    }
    impl<T: ?Sized, B> CapabilityMustNotImplementCloneCopyDefaultOrFrom<(), B> for T {}
    impl<T: Clone, B> CapabilityMustNotImplementCloneCopyDefaultOrFrom<u8, B> for T {}
    impl<T: Copy, B> CapabilityMustNotImplementCloneCopyDefaultOrFrom<u16, B> for T {}
    impl<T: Default, B> CapabilityMustNotImplementCloneCopyDefaultOrFrom<u32, B> for T {}
    impl<T: From<B>, B> CapabilityMustNotImplementCloneCopyDefaultOrFrom<u64, B> for T {}
    let _ =
        <SessionAcceptor<C> as CapabilityMustNotImplementCloneCopyDefaultOrFrom<_, C>>::some_item;
}

const _: fn() = assert_session_acceptor_has_no_minting_traits::<()>;

const _: fn() = || {
    // Any guarded impl makes this assertion ambiguous. Remove the capability
    // trait impl instead of weakening this construction boundary.
    trait CapabilityMustNotImplementCloneCopyDefaultOrFrom<A> {
        fn some_item() {}
    }
    impl<T: ?Sized> CapabilityMustNotImplementCloneCopyDefaultOrFrom<()> for T {}
    impl<T: Clone> CapabilityMustNotImplementCloneCopyDefaultOrFrom<u8> for T {}
    impl<T: Copy> CapabilityMustNotImplementCloneCopyDefaultOrFrom<u16> for T {}
    impl<T: Default> CapabilityMustNotImplementCloneCopyDefaultOrFrom<u32> for T {}
    impl<T: From<()>> CapabilityMustNotImplementCloneCopyDefaultOrFrom<u64> for T {}
    let _ = <SessionAcceptor<()> as CapabilityMustNotImplementCloneCopyDefaultOrFrom<_>>::some_item;
};

#[cfg(any(
    d2b_capability_trait_mutation = "session-acceptor-clone",
    d2b_capability_trait_mutation = "session-acceptor-default"
))]
macro_rules! mutate_session_acceptor_trait {
    (clone) => {
        impl<C> Clone for SessionAcceptor<C> {
            fn clone(&self) -> Self {
                unreachable!()
            }
        }
    };
    (default) => {
        impl<C> Default for SessionAcceptor<C> {
            fn default() -> Self {
                unreachable!()
            }
        }
    };
}

#[cfg(d2b_capability_trait_mutation = "session-acceptor-clone")]
mutate_session_acceptor_trait!(clone);
#[cfg(d2b_capability_trait_mutation = "session-acceptor-default")]
mutate_session_acceptor_trait!(default);

impl<C> SessionAcceptor<C> {
    /// Consume adapter-verified identity binding, registrar-owned policy
    /// callbacks, and the instance-bound registration capability.
    pub fn from_verified_adapter<A, Z>(
        policy: EndpointPolicy,
        expected_zone: ZoneId,
        authenticate: A,
        authorize: Z,
        registration_capability: C,
    ) -> Result<Self>
    where
        A: FnOnce(
                TransportEvidence,
                &SessionAuthenticationBinding,
                &ZoneId,
                u64,
            ) -> Result<(AuthenticatedSubjectContext, AuthorizationLease)>
            + Send
            + 'static,
        Z: FnMut(
                &AuthenticatedSubjectContext,
                &SessionAuthorizationRequest,
                AuthorizationLease,
                u64,
            ) -> Result<AuthorizationLease>
            + Send
            + 'static,
    {
        HandshakeOffer::from(policy.clone())
            .validate()
            .map_err(SessionError::from)?;
        Ok(Self {
            policy,
            expected_zone,
            authority: Box::new(VerifiedAdapterAuthority {
                authenticate: Some(Box::new(authenticate)),
                authorize: Box::new(authorize),
                authenticated_subject: None,
            }),
            metrics: Arc::new(NoopMetrics),
            registration_capability,
        })
    }

    pub fn with_metrics(mut self, metrics: Arc<dyn MetricsSink>) -> Self {
        self.metrics = metrics;
        self
    }

    /// Consume a completed session engine and mint one authenticated candidate.
    pub async fn admit<T>(
        mut self,
        mut engine: SessionEngine<T>,
        evidence: TransportEvidence,
        now_tick: u64,
    ) -> Result<AuthenticatedComponentSession<C>>
    where
        T: OwnedTransport + 'static,
    {
        engine.set_metrics(Arc::clone(&self.metrics));
        macro_rules! admit_try {
            ($expression:expr) => {
                match $expression {
                    Ok(value) => value,
                    Err(error) => {
                        engine.record_failure(
                            MetricEvent::ConnectAttempt,
                            ChannelClass::SessionControl,
                            OperationClass::Connect,
                            error,
                        );
                        return Err(error);
                    }
                }
            };
        }
        let authentication = admit_try!(engine.take_authentication(&self.policy));
        let binding = admit_try!(authentication_binding(&self.policy, authentication));
        admit_try!(validate_transport_evidence(
            &self.policy,
            &binding,
            &evidence
        ));
        admit_try!(validate_bootstrap_zone(&binding, &self.expected_zone));
        let (subject, lease) = self
            .authority
            .authenticate_connect(evidence, &binding, &self.expected_zone, now_tick)
            .await
            .inspect_err(|error| {
                engine.record_failure(
                    MetricEvent::ConnectAttempt,
                    ChannelClass::SessionControl,
                    OperationClass::Connect,
                    *error,
                );
            })?;
        admit_try!(validate_subject(&subject, &self.expected_zone, &binding));
        if !lease.is_valid_at(now_tick) {
            let error = SessionError::new(SessionErrorCode::PolicyDenied);
            engine.record_failure(
                MetricEvent::ConnectAttempt,
                ChannelClass::SessionControl,
                OperationClass::Connect,
                error,
            );
            return Err(error);
        }
        engine.record_metric(
            MetricEvent::ConnectAttempt,
            ChannelClass::SessionControl,
            OperationClass::Connect,
            MetricResult::Accepted,
            MetricReason::None,
        );
        let cleanup_observer = SessionCleanupObserver::new(&self.policy, Arc::clone(&self.metrics));
        Ok(AuthenticatedComponentSession {
            registration_capability: self.registration_capability,
            expected_zone: self.expected_zone,
            subject,
            lease,
            purpose_class: binding.purpose_class,
            initiator_role: binding.initiator_role,
            responder_role: binding.responder_role,
            endpoint_locality: binding.endpoint_locality,
            transport_class: binding.transport_class,
            transport_binding: binding.transport_binding.clone(),
            liveness: SessionLivenessOwner::new(),
            authority: self.authority,
            driver: engine.into_driver(),
            cleanup_observer,
        })
    }
}

impl<C> fmt::Debug for SessionAcceptor<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionAcceptor(<redacted>)")
    }
}

/// Authenticated session candidate that has not passed bus registration.
///
/// This value is not a routing capability. A registrar must consume it and
/// run native authorization before installing any routes.
///
/// It cannot be cloned, default-constructed, or created from caller input:
///
/// ```compile_fail
/// use d2b_session::AuthenticatedComponentSession;
///
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<AuthenticatedComponentSession<()>>();
/// ```
///
/// ```compile_fail
/// use d2b_session::AuthenticatedComponentSession;
///
/// fn requires_default<T: Default>() {}
/// requires_default::<AuthenticatedComponentSession<()>>();
/// ```
///
/// ```compile_fail
/// use d2b_session::AuthenticatedComponentSession;
///
/// let _: AuthenticatedComponentSession<()> =
///     <() as Into<AuthenticatedComponentSession<()>>>::into(());
/// ```
pub struct AuthenticatedComponentSession<C> {
    registration_capability: C,
    expected_zone: ZoneId,
    subject: AuthenticatedSubjectContext,
    lease: AuthorizationLease,
    purpose_class: PurposeClass,
    initiator_role: EndpointRole,
    responder_role: EndpointRole,
    endpoint_locality: ComponentLocality,
    transport_class: TransportClass,
    transport_binding: IdentityTransportBinding,
    liveness: SessionLivenessOwner,
    authority: Box<dyn SessionAuthority>,
    driver: SessionDriverHandle,
    cleanup_observer: SessionCleanupObserver,
}

/// Non-cloneable ComponentSession driver that retains its authenticated
/// session owner for the lifetime of the transport lane.
///
/// The driver handle is only an internal transport implementation detail. The
/// owning session remains in this value so its liveness and single-owner
/// authority cannot be detached by extracting a cloneable handle.
pub struct AuthenticatedSessionDriver {
    _owner: std::sync::Mutex<AuthenticatedComponentSession<()>>,
    driver: SessionDriverHandle,
}

impl fmt::Debug for AuthenticatedSessionDriver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedSessionDriver(<redacted>)")
    }
}

#[async_trait]
impl ComponentSessionDriver for AuthenticatedSessionDriver {
    fn generation(&self) -> u64 {
        ComponentSessionDriver::generation(&self.driver)
    }

    async fn start_ttrpc(&self, request_id: RequestId, frame: Vec<u8>) -> Result<()> {
        self.driver.start_ttrpc(request_id, frame).await
    }

    async fn complete_ttrpc(&self, request_id: RequestId) -> Result<bool> {
        self.driver.complete_ttrpc(request_id).await
    }

    async fn cancel(&self, generation: u64, request_id: RequestId) -> Result<()> {
        ComponentSessionDriver::cancel(&self.driver, generation, request_id).await
    }

    async fn send_ttrpc(&self, frame: Vec<u8>) -> Result<()> {
        self.driver.send_ttrpc(frame).await
    }

    async fn send_ttrpc_cancellable(
        &self,
        frame: Vec<u8>,
        cancellation: Cancellation,
    ) -> Result<()> {
        self.driver
            .send_ttrpc_cancellable(frame, cancellation)
            .await
    }

    async fn receive_ttrpc(&self) -> Result<Vec<u8>> {
        self.driver.receive_ttrpc().await
    }

    async fn register_inbound_call(&self, request_id: RequestId) -> Result<Cancellation> {
        self.driver.register_inbound_call(request_id).await
    }

    async fn mark_inbound_dispatched(&self, request_id: RequestId) -> Result<()> {
        self.driver.mark_inbound_dispatched(request_id).await
    }

    async fn complete_inbound_call(&self, request_id: RequestId) -> Result<bool> {
        self.driver.complete_inbound_call(request_id).await
    }

    async fn remove_inbound_call(&self, request_id: RequestId) -> Result<bool> {
        self.driver.remove_inbound_call(request_id).await
    }

    async fn send_attachments(&self, attachments: Vec<OwnedAttachment>) -> Result<()> {
        self.driver.send_attachments(attachments).await
    }

    async fn receive_attachments(&self) -> Result<Vec<OwnedAttachment>> {
        self.driver.receive_attachments().await
    }

    async fn open_named_stream(
        &self,
        stream: StreamId,
        send_credit: u32,
        receive_credit: u32,
    ) -> Result<()> {
        self.driver
            .open_named_stream(stream, send_credit, receive_credit)
            .await
    }

    async fn send_named_stream(&self, stream: StreamId, bytes: Vec<u8>) -> Result<()> {
        self.driver.send_named_stream(stream, bytes).await
    }

    async fn receive_named_stream(&self) -> Result<StreamEvent> {
        self.driver.receive_named_stream().await
    }

    async fn grant_named_stream_credit(&self, stream: StreamId, bytes: u32) -> Result<()> {
        self.driver.grant_named_stream_credit(stream, bytes).await
    }

    async fn close_named_stream(&self, stream: StreamId) -> Result<()> {
        self.driver.close_named_stream(stream).await
    }

    async fn reset_named_stream(&self, stream: StreamId) -> Result<()> {
        self.driver.reset_named_stream(stream).await
    }

    async fn drive_keepalive(&self, now: std::time::Instant) -> Result<()> {
        self.driver.drive_keepalive(now).await
    }

    async fn receive_control(&self) -> Result<SessionEvent> {
        self.driver.receive_control().await
    }

    async fn close(
        &self,
        reason: d2b_contracts_zone_session::v3::component_session::CloseReason,
        remediation: d2b_contracts_zone_session::v3::component_session::Remediation,
    ) -> Result<()> {
        self.driver.close(reason, remediation).await
    }
}

const _: fn() = || {
    trait CapabilityMustNotImplementCloneCopyDefaultOrFrom<A> {
        fn some_item() {}
    }
    impl<T: ?Sized> CapabilityMustNotImplementCloneCopyDefaultOrFrom<()> for T {}
    impl<T: Clone> CapabilityMustNotImplementCloneCopyDefaultOrFrom<u8> for T {}
    impl<T: Copy> CapabilityMustNotImplementCloneCopyDefaultOrFrom<u16> for T {}
    impl<T: Default> CapabilityMustNotImplementCloneCopyDefaultOrFrom<u32> for T {}
    impl<T: From<()>> CapabilityMustNotImplementCloneCopyDefaultOrFrom<u64> for T {}
    let _ = <AuthenticatedSessionDriver as CapabilityMustNotImplementCloneCopyDefaultOrFrom<_>>::some_item;
};

fn assert_authenticated_session_has_no_minting_traits<C>() {
    // Any guarded impl makes this assertion ambiguous. Remove the capability
    // trait impl instead of weakening this construction boundary.
    trait CapabilityMustNotImplementCloneCopyDefaultOrFrom<A, B> {
        fn some_item() {}
    }
    impl<T: ?Sized, B> CapabilityMustNotImplementCloneCopyDefaultOrFrom<(), B> for T {}
    impl<T: Clone, B> CapabilityMustNotImplementCloneCopyDefaultOrFrom<u8, B> for T {}
    impl<T: Copy, B> CapabilityMustNotImplementCloneCopyDefaultOrFrom<u16, B> for T {}
    impl<T: Default, B> CapabilityMustNotImplementCloneCopyDefaultOrFrom<u32, B> for T {}
    impl<T: From<B>, B> CapabilityMustNotImplementCloneCopyDefaultOrFrom<u64, B> for T {}
    let _ =
        <AuthenticatedComponentSession<C> as CapabilityMustNotImplementCloneCopyDefaultOrFrom<
            _,
            C,
        >>::some_item;
}

const _: fn() = assert_authenticated_session_has_no_minting_traits::<()>;

const _: fn() = || {
    // Any guarded impl makes this assertion ambiguous. Remove the capability
    // trait impl instead of weakening this construction boundary.
    trait CapabilityMustNotImplementCloneCopyDefaultOrFrom<A> {
        fn some_item() {}
    }
    impl<T: ?Sized> CapabilityMustNotImplementCloneCopyDefaultOrFrom<()> for T {}
    impl<T: Clone> CapabilityMustNotImplementCloneCopyDefaultOrFrom<u8> for T {}
    impl<T: Copy> CapabilityMustNotImplementCloneCopyDefaultOrFrom<u16> for T {}
    impl<T: Default> CapabilityMustNotImplementCloneCopyDefaultOrFrom<u32> for T {}
    impl<T: From<()>> CapabilityMustNotImplementCloneCopyDefaultOrFrom<u64> for T {}
    let _ =
        <AuthenticatedComponentSession<()> as CapabilityMustNotImplementCloneCopyDefaultOrFrom<
            _,
        >>::some_item;
};

#[cfg(any(
    d2b_capability_trait_mutation = "authenticated-component-session-clone",
    d2b_capability_trait_mutation = "authenticated-component-session-default"
))]
macro_rules! mutate_authenticated_session_trait {
    (clone) => {
        impl<C> Clone for AuthenticatedComponentSession<C> {
            fn clone(&self) -> Self {
                unreachable!()
            }
        }
    };
    (default) => {
        impl<C> Default for AuthenticatedComponentSession<C> {
            fn default() -> Self {
                unreachable!()
            }
        }
    };
}

#[cfg(d2b_capability_trait_mutation = "authenticated-component-session-clone")]
mutate_authenticated_session_trait!(clone);
#[cfg(d2b_capability_trait_mutation = "authenticated-component-session-default")]
mutate_authenticated_session_trait!(default);

/// Cloneable correlated ttrpc data plane separated from mutable authorization.
#[derive(Clone)]
pub struct AuthenticatedTtrpcHandle {
    driver: SessionDriverHandle,
    cleanup_observer: SessionCleanupObserver,
}

fn validate_ttrpc_permit(permit: &AuthorizedSessionOperation, now_tick: u64) -> Result<()> {
    if !permit.lease.is_valid_at(now_tick)
        || !matches!(
            permit.request.verb,
            SessionVerb::Invoke | SessionVerb::AuditExport | SessionVerb::SupportBundle
        )
    {
        return Err(SessionError::new(SessionErrorCode::PolicyDenied));
    }
    Ok(())
}

impl AuthenticatedTtrpcHandle {
    /// Clone the driver for a named-stream owner that remains under the
    /// authenticated ComponentSession lifetime.
    ///
    /// The returned handle carries no subject or authorization lease. It is
    /// exposed only to daemon composition after the session has been
    /// registered, where the owning route and target are already fixed.
    pub fn component_session_driver(&self) -> SessionDriverHandle {
        self.driver.clone()
    }

    /// Mint an attempt guard that can synchronously fence an admitted write.
    pub fn attempt_guard(&self) -> crate::Cancellation {
        crate::Cancellation::new()
    }

    /// Start one request under a permit minted by the authenticated session.
    pub async fn start(
        &self,
        permit: AuthorizedSessionOperation,
        request_id: RequestId,
        frame: Vec<u8>,
        cancellation: crate::Cancellation,
        now_tick: u64,
    ) -> Result<()> {
        validate_ttrpc_permit(&permit, now_tick)?;
        self.driver
            .start_ttrpc_guarded(request_id, frame, cancellation)
            .await
    }

    /// Receive the next authenticated ttrpc frame.
    pub async fn receive(&self) -> Result<Vec<u8>> {
        self.driver.receive_ttrpc().await
    }

    /// Receive the next authenticated attachment batch.
    ///
    /// Attachment packets are kept on their own bounded driver queue because
    /// ComponentSession carries descriptor metadata separately from ttrpc
    /// frames. Callers must pair the batch with the operation/request ids in
    /// the authenticated descriptors before handing it to a Provider.
    pub async fn receive_attachments(&self) -> Result<Vec<crate::OwnedAttachment>> {
        self.driver.receive_attachments().await
    }

    /// Send one response frame for an authenticated inbound request.
    ///
    /// The Zone bus owns the request authorization and correlation fence
    /// before calling this transport operation.  Provider code never
    /// receives this handle.
    pub async fn send_response(&self, frame: Vec<u8>) -> Result<()> {
        self.driver.send_ttrpc(frame).await
    }

    /// Remove one terminal correlated request.
    pub async fn complete(&self, request_id: RequestId) -> Result<bool> {
        let result = ComponentSessionDriver::complete_ttrpc(&self.driver, request_id).await;
        if let Err(error) = result {
            self.cleanup_observer.record(OperationClass::Invoke, error);
        }
        result
    }

    /// Serve generated ttrpc services on this already authenticated session.
    ///
    /// The handle contains only the correlated transport plane; authorization
    /// and resource policy remain bound to the generated service adapter.
    pub async fn serve_ttrpc_services(
        self,
        services: std::collections::HashMap<String, ttrpc::r#async::Service>,
    ) -> std::result::Result<(), crate::SessionServerError> {
        crate::serve_ttrpc_services(Arc::new(self.driver), services).await
    }
}

impl fmt::Debug for AuthenticatedTtrpcHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedTtrpcHandle(<redacted>)")
    }
}

#[derive(Clone)]
struct SessionCleanupObserver {
    metrics: Arc<dyn MetricsSink>,
    labels: MetricLabels,
}

impl SessionCleanupObserver {
    fn new(policy: &EndpointPolicy, metrics: Arc<dyn MetricsSink>) -> Self {
        Self {
            metrics,
            labels: MetricLabels {
                transport: policy.transport_binding.transport,
                purpose: policy.purpose,
                service: policy.service,
                channel_class: ChannelClass::TtrpcControl,
                noise: policy.noise_profile,
                locality: policy.transport_binding.locality,
                operation_class: OperationClass::Invoke,
                attachment_class: None,
                health_state: HealthState::Degraded,
                result: MetricResult::Rejected,
                reason: MetricReason::InternalInvariant,
            },
        }
    }

    fn record(&self, operation_class: OperationClass, error: SessionError) {
        let mut labels = self.labels;
        labels.operation_class = operation_class;
        labels.reason = reason_for_error(error.code());
        self.metrics.record(MetricEvent::CleanupFailure, labels, 1);
    }
}

trait SessionCancellationDriver: Send + Sync {
    fn generation(&self) -> u64;
    fn cancel(
        &self,
        generation: u64,
        request_id: RequestId,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'static>>;
}

impl SessionCancellationDriver for SessionDriverHandle {
    fn generation(&self) -> u64 {
        ComponentSessionDriver::generation(self)
    }

    fn cancel(
        &self,
        generation: u64,
        request_id: RequestId,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'static>> {
        let completion = self.queue_cancellation(generation, request_id);
        Box::pin(async move {
            completion?
                .await
                .map_err(|_| SessionError::new(SessionErrorCode::SessionDisconnected))?
        })
    }
}

/// Restricted concurrent cancellation surface for one authenticated session.
#[derive(Clone)]
pub struct SessionCancellationHandle {
    driver: Arc<dyn SessionCancellationDriver>,
    writer_fence: crate::Cancellation,
}

impl SessionCancellationHandle {
    #[doc(hidden)]
    pub fn revoke_generation_writes(&self) -> impl Future<Output = ()> + Send + 'static {
        let fence = self.writer_fence.cancel_and_wait();
        async move {
            fence.await;
        }
    }

    /// Signal cancellation for one exact request in the current generation.
    pub fn cancel(
        &self,
        request_id: RequestId,
    ) -> impl Future<Output = Result<()>> + Send + 'static {
        self.driver.cancel(self.driver.generation(), request_id)
    }
}

impl fmt::Debug for SessionCancellationHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionCancellationHandle(<redacted>)")
    }
}

/// Redacted routing metadata derived only from an authenticated candidate.
///
/// This value carries no driver, authority, lease, transport binding, or
/// transcript and cannot be converted back into an admitted session.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthenticatedSessionRouteBinding {
    context: AuthenticatedSubjectContext,
    zone: ZoneId,
    subject_ref: ResourceRef,
    subject_uid: ResourceUid,
    evidence_class: EvidenceClass,
    locality: Locality,
    endpoint_locality: ComponentLocality,
    purpose_class: PurposeClass,
    initiator_role: EndpointRole,
    responder_role: EndpointRole,
    transport_class: TransportClass,
    transport_binding: IdentityTransportBinding,
    liveness: SessionLiveness,
    service: ServiceName,
    schema: SchemaFingerprint,
    reconnect_generation: ReconnectGeneration,
    provider_ref: Option<ResourceRef>,
    provider_generation: Option<ResourceGeneration>,
    controller_generation: Option<ControllerGeneration>,
}

impl AuthenticatedSessionRouteBinding {
    /// Borrow the authenticated context for registrar-owned authorization.
    pub fn context(&self) -> &AuthenticatedSubjectContext {
        &self.context
    }

    pub fn zone(&self) -> &ZoneId {
        &self.zone
    }

    pub fn subject_ref(&self) -> &ResourceRef {
        &self.subject_ref
    }

    pub fn subject_uid(&self) -> &ResourceUid {
        &self.subject_uid
    }

    pub const fn evidence_class(&self) -> EvidenceClass {
        self.evidence_class
    }

    pub const fn locality(&self) -> Locality {
        self.locality
    }

    /// Return the exact authenticated ComponentSession locality.
    pub const fn endpoint_locality(&self) -> ComponentLocality {
        self.endpoint_locality
    }

    /// Return the authenticated endpoint purpose class.
    pub const fn purpose_class(&self) -> PurposeClass {
        self.purpose_class
    }

    /// Return the authenticated endpoint initiator role.
    pub const fn initiator_role(&self) -> EndpointRole {
        self.initiator_role
    }

    /// Return the authenticated endpoint responder role.
    pub const fn responder_role(&self) -> EndpointRole {
        self.responder_role
    }

    /// Return the exact authenticated transport class.
    pub const fn transport_class(&self) -> TransportClass {
        self.transport_class
    }

    /// Borrow the exact authenticated transport binding.
    pub fn transport_binding(&self) -> &IdentityTransportBinding {
        &self.transport_binding
    }

    /// Borrow a shared liveness marker for a trusted route owner.
    pub fn liveness(&self) -> SessionLiveness {
        self.liveness.clone()
    }

    pub fn service(&self) -> &ServiceName {
        &self.service
    }

    pub fn schema(&self) -> &SchemaFingerprint {
        &self.schema
    }

    pub const fn reconnect_generation(&self) -> ReconnectGeneration {
        self.reconnect_generation
    }

    pub fn provider_ref(&self) -> Option<&ResourceRef> {
        self.provider_ref.as_ref()
    }

    pub const fn provider_generation(&self) -> Option<ResourceGeneration> {
        self.provider_generation
    }

    pub const fn controller_generation(&self) -> Option<ControllerGeneration> {
        self.controller_generation
    }

    /// Derive an exact typed ComponentSession descriptor for this route.
    ///
    /// The caller chooses the already-decided boundary; the route supplies
    /// the authenticated service, schema, and reconnect generation.
    pub fn component_descriptor(
        &self,
        boundary: ComponentSessionBoundary,
    ) -> Result<ComponentSessionDescriptor> {
        let service = ServicePackage::ALL
            .iter()
            .copied()
            .find(|service| service.as_str() == self.service.as_str())
            .ok_or_else(|| SessionError::new(SessionErrorCode::ServiceMismatch))?;
        ComponentSessionDescriptor::new(
            boundary,
            service,
            schema_fingerprint_bytes(&self.schema)?,
            self.reconnect_generation.get(),
        )
        .map_err(SessionError::from)
    }

    /// Build redacted route metadata for toolkit unit tests.
    #[cfg(feature = "test-support")]
    pub fn for_test(
        provider_ref: Option<ResourceRef>,
        service: &str,
        reconnect_generation: u64,
        provider_generation: Option<u64>,
        controller_generation: Option<u64>,
    ) -> Self {
        let zone = ZoneId::parse("dev").expect("test Zone is valid");
        let subject_ref = ResourceRef::parse("Guest/test").expect("test subject is valid");
        let subject_uid =
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").expect("test UID is valid");
        let service_name = ServiceName::parse(service).expect("test service is valid");
        let session = d2b_contracts_resource::v3::identity::SessionBinding::new(
            SchemaFingerprint::parse(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            )
            .expect("test schema is valid"),
            IdentityTransportBinding::new(
                Locality::Local,
                BindingDigest::parse(
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                )
                .expect("test binding is valid"),
            ),
            ReconnectGeneration::new(reconnect_generation).expect("test reconnect is valid"),
            TranscriptHash::from_bytes([0; 32]),
        );
        let mut context = AuthenticatedSubjectContext::new(
            subject_ref.clone(),
            subject_uid.clone(),
            ResourceRef::parse("Zone/dev").expect("test Zone ref is valid"),
            EvidenceClass::UnixPeer,
            SessionPurpose::parse("provider-invoke").expect("test purpose is valid"),
            service_name.clone(),
            session,
        )
        .with_execution_ref(ResourceRef::parse("Host/test").expect("test Host is valid"));
        if let Some(provider_ref) = provider_ref.clone() {
            context = context.with_provider_ref(provider_ref);
        }
        if let Some(generation) = provider_generation {
            context = context.with_provider_generation(
                ResourceGeneration::new(generation).expect("test Provider generation is valid"),
            );
        }
        if let Some(generation) = controller_generation {
            context = context.with_controller_generation(
                ControllerGeneration::new(generation).expect("test controller generation is valid"),
            );
        }
        let schema = context.schema_fingerprint().clone();
        let transport_binding = context.transport_binding().clone();
        Self {
            context,
            zone,
            subject_ref,
            subject_uid,
            evidence_class: EvidenceClass::UnixPeer,
            locality: Locality::Local,
            endpoint_locality: ComponentLocality::HostLocal,
            service: service_name,
            schema,
            reconnect_generation: ReconnectGeneration::new(reconnect_generation)
                .expect("test reconnect is valid"),
            purpose_class: PurposeClass::Local,
            initiator_role: EndpointRole::ZoneController,
            responder_role: EndpointRole::Component,
            transport_class: TransportClass::UnixSeqpacket,
            transport_binding,
            liveness: SessionLiveness::new(),
            provider_ref,
            provider_generation: provider_generation
                .map(|generation| ResourceGeneration::new(generation).expect("test generation")),
            controller_generation: controller_generation
                .map(|generation| ControllerGeneration::new(generation).expect("test generation")),
        }
    }
}

impl fmt::Debug for AuthenticatedSessionRouteBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedSessionRouteBinding(<redacted>)")
    }
}

/// A registration capability consumes itself against one concrete registrar.
///
/// The capability implementation owns validation. The session never exposes
/// the value to a caller or to a caller-supplied closure.
pub trait SessionRegistrationCapability<R> {
    type Error;

    fn consume(self, registrar: &R) -> std::result::Result<(), Self::Error>;
}

impl<C> AuthenticatedComponentSession<C> {
    fn ttrpc_handle(&self) -> AuthenticatedTtrpcHandle {
        AuthenticatedTtrpcHandle {
            driver: self.driver.clone(),
            cleanup_observer: self.cleanup_observer.clone(),
        }
    }

    /// Consume the instance-bound capability and split out the correlated data
    /// plane for the registrar-owned response dispatcher.
    pub fn consume_registration<R>(
        self,
        registrar: &R,
    ) -> std::result::Result<(AuthenticatedComponentSession<()>, AuthenticatedTtrpcHandle), C::Error>
    where
        C: SessionRegistrationCapability<R>,
    {
        let Self {
            registration_capability,
            expected_zone,
            subject,
            lease,
            purpose_class,
            initiator_role,
            responder_role,
            endpoint_locality,
            transport_class,
            transport_binding,
            liveness,
            authority,
            driver,
            cleanup_observer,
        } = self;
        registration_capability.consume(registrar)?;
        let ttrpc = AuthenticatedTtrpcHandle {
            driver: driver.clone(),
            cleanup_observer: cleanup_observer.clone(),
        };
        Ok((
            AuthenticatedComponentSession {
                registration_capability: (),
                expected_zone,
                subject,
                lease,
                purpose_class,
                initiator_role,
                responder_role,
                endpoint_locality,
                transport_class,
                transport_binding,
                liveness,
                authority,
                driver,
                cleanup_observer,
            },
            ttrpc,
        ))
    }

    /// Clone a cancellation-only handle that carries no claims or send access.
    pub fn cancellation_handle(&self) -> SessionCancellationHandle {
        SessionCancellationHandle {
            driver: Arc::new(self.driver.clone()),
            writer_fence: self.driver.writer_fence(),
        }
    }

    /// Return the active authorization revision.
    pub const fn authorization_revision(&self) -> u64 {
        self.lease.policy_revision()
    }

    /// Snapshot non-authority routing metadata without exposing session claims.
    pub fn route_binding(&self) -> AuthenticatedSessionRouteBinding {
        AuthenticatedSessionRouteBinding {
            context: self.subject.clone(),
            zone: self.expected_zone.clone(),
            subject_ref: self.subject.subject_ref().clone(),
            subject_uid: self.subject.subject_uid().clone(),
            evidence_class: self.subject.evidence_class(),
            locality: self.subject.transport_binding().locality(),
            endpoint_locality: self.endpoint_locality,
            purpose_class: self.purpose_class,
            initiator_role: self.initiator_role,
            responder_role: self.responder_role,
            transport_class: self.transport_class,
            transport_binding: self.transport_binding.clone(),
            liveness: self.liveness.marker(),
            service: self.subject.service().clone(),
            schema: self.subject.schema_fingerprint().clone(),
            reconnect_generation: self.subject.reconnect_generation(),
            provider_ref: self.subject.provider_ref().cloned(),
            provider_generation: self.subject.provider_generation(),
            controller_generation: self.subject.controller_generation(),
        }
    }

    /// Authorize one exact operation and mint a non-cloneable permit.
    pub async fn authorize(
        &mut self,
        request: SessionAuthorizationRequest,
        now_tick: u64,
    ) -> Result<AuthorizedSessionOperation> {
        validate_zone(&self.subject, &self.expected_zone)?;
        let zone_scope_valid = if request.verb == SessionVerb::Relay {
            let next_hop = request.next_hop_zone.as_ref();
            let forwarded = self.subject.transport_binding().locality() == Locality::AdjacentZone
                && request.target_zone == self.expected_zone
                && next_hop == Some(&self.expected_zone);
            let outbound = request.target_zone != self.expected_zone
                && next_hop.is_some_and(|next_hop| next_hop != &self.expected_zone);
            forwarded || outbound
        } else {
            request.target_zone == self.expected_zone
        };
        if !zone_scope_valid || !self.lease.is_valid_at(now_tick) {
            return Err(SessionError::new(SessionErrorCode::PolicyDenied));
        }

        let lease = self
            .authority
            .authorize(&self.subject, &request, self.lease, now_tick)
            .await?;
        validate_zone(&self.subject, &self.expected_zone)?;
        if !lease.is_valid_at(now_tick) {
            return Err(SessionError::new(SessionErrorCode::PolicyDenied));
        }
        self.lease = lease;
        Ok(AuthorizedSessionOperation { request, lease })
    }

    /// Receive one authenticated ttrpc frame for authorization and dispatch.
    pub async fn receive_ttrpc(&mut self) -> Result<Vec<u8>> {
        self.driver.receive_ttrpc().await
    }

    /// Send one ttrpc frame under a consumed exact-operation permit.
    pub async fn send_authorized_ttrpc(
        &mut self,
        permit: AuthorizedSessionOperation,
        frame: Vec<u8>,
        now_tick: u64,
    ) -> Result<()> {
        if !permit.lease.is_valid_at(now_tick)
            || !matches!(
                permit.request.verb,
                SessionVerb::Invoke | SessionVerb::AuditExport | SessionVerb::SupportBundle
            )
        {
            return Err(SessionError::new(SessionErrorCode::PolicyDenied));
        }
        self.driver.send_ttrpc(frame).await
    }

    /// Start one correlated ttrpc request under a consumed operation permit.
    pub async fn start_authorized_ttrpc(
        &mut self,
        permit: AuthorizedSessionOperation,
        request_id: RequestId,
        frame: Vec<u8>,
        now_tick: u64,
    ) -> Result<()> {
        let handle = self.ttrpc_handle();
        let cancellation = handle.attempt_guard();
        handle
            .start(permit, request_id, frame, cancellation, now_tick)
            .await
    }

    /// Open one named stream under a consumed exact stream authorization.
    ///
    /// The returned handle exposes only bounded stream operations and remains
    /// fenced to the reconnect generation that opened it.
    pub async fn open_authorized_named_stream(
        &mut self,
        permit: AuthorizedSessionOperation,
        stream: StreamId,
        send_credit: u32,
        receive_credit: u32,
        now_tick: u64,
    ) -> Result<ComponentSessionStream> {
        if !permit.lease.is_valid_at(now_tick)
            || permit.request.verb != SessionVerb::OpenStream
            || !permit.request.operation.member().is_stream()
        {
            return Err(SessionError::new(SessionErrorCode::PolicyDenied));
        }
        ComponentSessionStream::open(self.driver.clone(), stream, send_credit, receive_credit).await
    }

    /// Remove one terminal correlated request.
    pub async fn complete_ttrpc(&mut self, request_id: RequestId) -> Result<bool> {
        let result = ComponentSessionDriver::complete_ttrpc(&self.driver, request_id).await;
        if let Err(error) = result {
            self.cleanup_observer.record(OperationClass::Invoke, error);
        }
        result
    }
}

impl AuthenticatedComponentSession<()> {
    /// Consume this registered authenticated session into a non-cloneable
    /// driver owner.
    ///
    /// The returned driver retains the session, including its liveness and
    /// single-owner authority, while exposing only the transport operations
    /// required by a bound lane.
    pub fn into_authenticated_driver(self) -> AuthenticatedSessionDriver {
        let driver = self.driver.clone();
        AuthenticatedSessionDriver {
            _owner: std::sync::Mutex::new(self),
            driver,
        }
    }

    /// Split the transport plane after a session admitted without a
    /// registration capability, such as a Guest target's parent session.
    pub fn into_ttrpc_handle(self) -> AuthenticatedTtrpcHandle {
        self.ttrpc_handle()
    }
}

impl<C> fmt::Debug for AuthenticatedComponentSession<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedComponentSession")
            .field("subject", &"<redacted>")
            .field("authorization", &"<redacted>")
            .field("driver", &"<redacted>")
            .finish()
    }
}

/// Non-cloneable proof that one exact operation passed session policy.
pub struct AuthorizedSessionOperation {
    request: SessionAuthorizationRequest,
    lease: AuthorizationLease,
}

impl AuthorizedSessionOperation {
    /// Borrow the exact authorized request.
    pub fn request(&self) -> &SessionAuthorizationRequest {
        &self.request
    }

    /// Return the policy revision that minted this permit.
    pub const fn policy_revision(&self) -> u64 {
        self.lease.policy_revision()
    }

    /// Return the monotonic expiry captured when this work was admitted.
    pub const fn expires_at_tick(&self) -> u64 {
        self.lease.expires_at_tick()
    }
}

impl fmt::Debug for AuthorizedSessionOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedSessionOperation")
            .field("request", &"<redacted>")
            .field("lease", &"<redacted>")
            .finish()
    }
}

fn authentication_binding(
    policy: &EndpointPolicy,
    authentication: EstablishedAuthentication,
) -> Result<SessionAuthenticationBinding> {
    if authentication.generation != policy.reconnect_generation {
        return Err(SessionError::new(SessionErrorCode::GenerationMismatch));
    }
    let schema_fingerprint =
        SchemaFingerprint::parse(format!("sha256:{}", hex(&policy.schema_fingerprint)))
            .map_err(|_| SessionError::new(SessionErrorCode::SchemaMismatch))?;
    let binding_digest = binding_digest(policy.transport_binding.channel_binding)?;
    let locality = match (policy.purpose, policy.transport_binding.locality) {
        (EndpointPurpose::ZoneLink, ComponentLocality::Remote) => Locality::AdjacentZone,
        (
            _,
            ComponentLocality::ProcessLocal
            | ComponentLocality::HostLocal
            | ComponentLocality::GuestLocal,
        ) => Locality::Local,
        (_, ComponentLocality::Remote) => Locality::Remote,
    };
    Ok(SessionAuthenticationBinding {
        evidence_class: evidence_class(policy.noise_profile),
        purpose: SessionPurpose::parse(policy.purpose.as_str())
            .map_err(|_| SessionError::new(SessionErrorCode::PurposeMismatch))?,
        purpose_class: policy.purpose_class,
        initiator_role: policy.initiator_role,
        responder_role: policy.responder_role,
        endpoint_locality: policy.transport_binding.locality,
        service: ServiceName::parse(policy.service.as_str())
            .map_err(|_| SessionError::new(SessionErrorCode::ServiceMismatch))?,
        schema_fingerprint,
        transport_class: policy.transport_binding.transport,
        transport_binding: IdentityTransportBinding::new(locality, binding_digest),
        bootstrap_identity: authentication.bootstrap_identity,
        reconnect_generation: ReconnectGeneration::new(authentication.generation)
            .map_err(|_| SessionError::new(SessionErrorCode::GenerationMismatch))?,
        transcript_hash: TranscriptHash::from_bytes(authentication.transcript_hash),
        remote_static_key: authentication.remote_static_key,
    })
}

fn validate_transport_evidence(
    policy: &EndpointPolicy,
    binding: &SessionAuthenticationBinding,
    evidence: &TransportEvidence,
) -> Result<()> {
    if evidence.class != binding.evidence_class {
        return Err(SessionError::new(
            SessionErrorCode::IdentityEvidenceMismatch,
        ));
    }
    let remote_static_expected = binding.evidence_class != EvidenceClass::UnixPeer;
    if remote_static_expected != binding.remote_static_key.is_some() {
        return Err(SessionError::new(
            SessionErrorCode::IdentityEvidenceMismatch,
        ));
    }
    if &evidence.binding_digest != binding.transport_binding.binding_digest() {
        return Err(SessionError::new(SessionErrorCode::ChannelBindingMismatch));
    }
    let transport_valid = match policy.noise_profile {
        NoiseProfile::Nn25519ChaChaPolySha256 => matches!(
            policy.transport_binding.transport,
            TransportClass::UnixStream
                | TransportClass::UnixSeqpacket
                | TransportClass::InheritedSocketpair
        ),
        NoiseProfile::Kk25519ChaChaPolySha256 => true,
        NoiseProfile::Ikpsk2_25519ChaChaPolySha256 => true,
    };
    if !transport_valid {
        return Err(SessionError::new(SessionErrorCode::TransportMismatch));
    }
    Ok(())
}

fn validate_subject(
    subject: &AuthenticatedSubjectContext,
    expected_zone: &ZoneId,
    binding: &SessionAuthenticationBinding,
) -> Result<()> {
    validate_zone(subject, expected_zone)?;
    if subject.evidence_class() != binding.evidence_class
        || subject.session_purpose() != &binding.purpose
        || subject.service() != &binding.service
        || subject.schema_fingerprint() != &binding.schema_fingerprint
        || subject.transport_binding() != &binding.transport_binding
        || subject.reconnect_generation() != binding.reconnect_generation
        || subject.transcript_hash() != &binding.transcript_hash
    {
        return Err(SessionError::new(SessionErrorCode::SubjectMismatch));
    }
    if let Some(expected) = &binding.bootstrap_identity
        && (subject.subject_ref() != &expected.subject_ref
            || subject.subject_uid() != &expected.subject_uid
            || subject.zone_ref().name().as_str() != expected.zone.as_str()
            || subject.session_purpose() != &expected.purpose)
    {
        return Err(SessionError::new(SessionErrorCode::SubjectMismatch));
    }

    Ok(())
}

fn validate_bootstrap_zone(
    binding: &SessionAuthenticationBinding,
    expected_zone: &ZoneId,
) -> Result<()> {
    let bootstrap_expected = binding.evidence_class == EvidenceClass::BootstrapIkpsk2;
    if bootstrap_expected != binding.bootstrap_identity.is_some()
        || binding
            .bootstrap_identity
            .as_ref()
            .is_some_and(|identity| &identity.zone != expected_zone)
    {
        return Err(SessionError::new(SessionErrorCode::SubjectMismatch));
    }
    Ok(())
}

const fn evidence_class(profile: NoiseProfile) -> EvidenceClass {
    match profile {
        NoiseProfile::Nn25519ChaChaPolySha256 => EvidenceClass::UnixPeer,
        NoiseProfile::Kk25519ChaChaPolySha256 => EvidenceClass::EnrolledKk,
        NoiseProfile::Ikpsk2_25519ChaChaPolySha256 => EvidenceClass::BootstrapIkpsk2,
    }
}

fn validate_zone(subject: &AuthenticatedSubjectContext, expected_zone: &ZoneId) -> Result<()> {
    if subject.zone_ref().resource_type().as_str() != "Zone"
        || subject.zone_ref().name().as_str() != expected_zone.as_str()
    {
        return Err(SessionError::new(SessionErrorCode::SubjectMismatch));
    }
    Ok(())
}

fn binding_digest(bytes: [u8; 32]) -> Result<BindingDigest> {
    BindingDigest::parse(format!("sha256:{}", hex(&bytes)))
        .map_err(|_| SessionError::new(SessionErrorCode::ChannelBindingMismatch))
}

fn schema_fingerprint_bytes(value: &SchemaFingerprint) -> Result<[u8; 32]> {
    let raw = value
        .as_str()
        .strip_prefix("sha256:")
        .ok_or_else(|| SessionError::new(SessionErrorCode::SchemaMismatch))?;
    if raw.len() != 64 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SessionError::new(SessionErrorCode::SchemaMismatch));
    }
    let mut bytes = [0_u8; 32];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&raw[index * 2..index * 2 + 2], 16)
            .map_err(|_| SessionError::new(SessionErrorCode::SchemaMismatch))?;
    }
    Ok(bytes)
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct MockCancellationDriver {
        cancel_error: Option<SessionError>,
        local_complete_calls: AtomicUsize,
    }

    impl SessionCancellationDriver for MockCancellationDriver {
        fn generation(&self) -> u64 {
            7
        }

        fn cancel(
            &self,
            _generation: u64,
            _request_id: RequestId,
        ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'static>> {
            self.local_complete_calls.fetch_add(1, Ordering::AcqRel);
            let result = self.cancel_error.map_or(Ok(()), Err);
            Box::pin(async move { result })
        }
    }

    fn request_id() -> RequestId {
        RequestId::new(vec![9; 16]).unwrap()
    }

    #[tokio::test]
    async fn cancellation_schedules_local_completion_before_delivery() {
        let driver = Arc::new(MockCancellationDriver {
            cancel_error: None,
            local_complete_calls: AtomicUsize::new(0),
        });
        let handle = SessionCancellationHandle {
            driver: driver.clone(),
            writer_fence: crate::Cancellation::new(),
        };

        handle.cancel(request_id()).await.unwrap();
        assert_eq!(driver.local_complete_calls.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn cancellation_propagates_delivery_failure_after_local_cleanup() {
        let driver = Arc::new(MockCancellationDriver {
            cancel_error: Some(SessionError::new(SessionErrorCode::SessionDisconnected)),
            local_complete_calls: AtomicUsize::new(0),
        });
        let handle = SessionCancellationHandle {
            driver: driver.clone(),
            writer_fence: crate::Cancellation::new(),
        };

        let error = handle.cancel(request_id()).await.unwrap_err();
        assert_eq!(error.code(), SessionErrorCode::SessionDisconnected);
        assert_eq!(driver.local_complete_calls.load(Ordering::Acquire), 1);
    }
}
