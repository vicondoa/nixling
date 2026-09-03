//! Supervised Provider binary bootstrap over the inherited fd 10 handoff.

use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};

use d2b_contracts_provider::v3::credential::CredentialProvider;
use d2b_contracts_resource::v3::{
    ControllerGeneration, ResourceGeneration, ResourceRef, ResourceUid, SchemaFingerprint, ZoneId,
    identity::{
        AuthenticatedSubjectContext, EvidenceClass, ServiceName, SessionBinding, SessionPurpose,
        TranscriptHash, TransportBinding as IdentityTransportBinding,
    },
};
use d2b_contracts_zone_session::v3::{
    component_session::{
        EndpointPolicy, EndpointRole as ComponentEndpointRole,
        Locality as ComponentLocality, PurposeClass, TransportClass,
    },
    zone_routing::{ZoneLabelId, ZonePath},
};
use d2b_session::{
    AuthenticatedSessionRouteBinding, ComponentSessionDriver, HandshakeCredentials,
    Secret32, SessionDriverHandle, SessionEngine, SessionTtrpcClient, StreamEvent, StreamId,
    x25519_public_key,
};
use d2b_session_unix::{
    AncillaryCapacity, CONTROLLER_BOOTSTRAP_TIMEOUT, DescriptorPolicyResolver, PeerIdentityPolicy,
    SeqpacketSocket, UnixSeqpacketTransport, UnixSessionError,
    controller_bootstrap_attachment_policy, controller_credit_scopes,
    credential_delivery_endpoint_policy, credential_provider_endpoint_policy,
    prearmed_seqpacket_pair,
};
use serde::{Deserialize, Serialize};

use crate::{
    AllocatorSessionBinding, ProviderAgentBootstrap, ProviderEntrypoint, ProviderRuntimeError,
    ProviderSessionAdmission, credential_service,
};

const PROVIDER_BOOTSTRAP_FD: i32 = 10;
/// Named stream carrying the authenticated Provider route bootstrap.
pub const PROVIDER_BOOTSTRAP_STREAM_ID: u16 = 0x0102;
/// Initial bounded credit for the Provider route bootstrap stream.
pub const PROVIDER_BOOTSTRAP_STREAM_CREDIT: u32 = 64 * 1024;
/// Named stream carrying the post-admission Provider readiness receipt.
pub const PROVIDER_READY_STREAM_ID: u16 = 0x0103;
/// Initial bounded credit for the Provider readiness stream.
pub const PROVIDER_READY_STREAM_CREDIT: u32 = 256;
/// Protected readiness receipt sent only after the typed service is live.
pub const PROVIDER_READY_MARKER: &[u8] = b"d2b-provider-ready-v1";
/// Named stream carrying one allocator-issued Credential delivery key handoff.
pub const PROVIDER_DELIVERY_KEY_STREAM_ID: u16 = 0x0104;
/// Initial bounded credit for the Credential delivery key handoff stream.
pub const PROVIDER_DELIVERY_KEY_STREAM_CREDIT: u32 = 1024;
const PROVIDER_BOOTSTRAP_MAX_BYTES: usize = 64 * 1024;
const PROVIDER_BOOTSTRAP_PROTOCOL: &str = "d2b-provider-session-bootstrap-v1";
const GUEST_CREDENTIAL_BACKEND_MAX_BYTES: usize = 64 * 1024;
/// Protocol marker for the Guest-local typed credential backend.
pub const GUEST_CREDENTIAL_BACKEND_PROTOCOL: &str = "d2b-guest-credential-backend-v1";
/// Ttrpc service name for the Guest-local typed credential backend.
pub const GUEST_CREDENTIAL_BACKEND_SERVICE: &str = "d2b.guest.credential.v1.GuestCredentialBackend";

/// Fixed inherited descriptor for the Guest-local credential backend port.
pub const GUEST_CREDENTIAL_BACKEND_FD: i32 = 11;

/// Exact static configuration compiled into one Provider binary.
pub struct ProviderFd10Spec {
    name: &'static str,
    provider_ref: ResourceRef,
    service: &'static str,
    accepted_purpose: SessionPurpose,
}

impl ProviderFd10Spec {
    /// Bind one binary to its immutable Provider service identity.
    pub fn new(
        name: &'static str,
        provider_ref: ResourceRef,
        service: &'static str,
        accepted_purpose: SessionPurpose,
    ) -> Self {
        Self {
            name,
            provider_ref,
            service,
            accepted_purpose,
        }
    }
}

/// Non-secret route metadata sent by d2bd after it authenticates the child
/// ComponentSession. The protected session remains the source of authority.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProviderSessionMetadata {
    protocol: String,
    zone: ZoneId,
    provider_ref: ResourceRef,
    subject_ref: ResourceRef,
    subject_uid: ResourceUid,
    zone_ref: ResourceRef,
    evidence_class: EvidenceClass,
    execution_ref: Option<ResourceRef>,
    #[serde(default)]
    user_ref: Option<ResourceRef>,
    process_ref: Option<ResourceRef>,
    provider_generation: Option<ResourceGeneration>,
    controller_generation: Option<ControllerGeneration>,
    session_purpose: SessionPurpose,
    service: ServiceName,
    schema_fingerprint: SchemaFingerprint,
    transport_binding: IdentityTransportBinding,
    reconnect_generation: d2b_contracts_resource::v3::identity::ReconnectGeneration,
    transcript_hash: TranscriptHash,
    endpoint_locality: ComponentLocality,
    purpose_class: PurposeClass,
    initiator_role: ComponentEndpointRole,
    responder_role: ComponentEndpointRole,
    transport_class: TransportClass,
}

impl ProviderSessionMetadata {
    /// Snapshot an authenticated route into bounded, non-secret wire metadata.
    pub fn from_route(
        route: &AuthenticatedSessionRouteBinding,
    ) -> Result<Self, ProviderRuntimeError> {
        Self::from_route_with_user(route, None)
    }

    /// Snapshot an authenticated route and an exact User scope claim.
    ///
    /// The claim is supplied by the trusted Process/Resource placement
    /// binding; it never changes the authenticated Provider subject.
    pub fn from_route_with_user(
        route: &AuthenticatedSessionRouteBinding,
        user_ref: Option<&ResourceRef>,
    ) -> Result<Self, ProviderRuntimeError> {
        let provider_ref = route
            .provider_ref()
            .cloned()
            .ok_or(ProviderRuntimeError::SessionUnauthenticated)?;
        if route.subject_ref().resource_type().as_str() != "Provider"
            || route.subject_ref() != &provider_ref
        {
            return Err(ProviderRuntimeError::SessionUnauthenticated);
        }
        if user_ref
            .as_ref()
            .is_some_and(|reference| reference.resource_type().as_str() != "User")
        {
            return Err(ProviderRuntimeError::SessionUnauthenticated);
        }
        Ok(Self {
            protocol: PROVIDER_BOOTSTRAP_PROTOCOL.to_owned(),
            zone: route.zone().clone(),
            provider_ref,
            subject_ref: route.subject_ref().clone(),
            subject_uid: route.subject_uid().clone(),
            zone_ref: route.context().zone_ref().clone(),
            evidence_class: route.evidence_class(),
            execution_ref: route.context().execution_ref().cloned(),
            user_ref: user_ref.cloned(),
            process_ref: route.context().process_ref().cloned(),
            provider_generation: route.provider_generation(),
            controller_generation: route.controller_generation(),
            session_purpose: route.context().session_purpose().clone(),
            service: route.service().clone(),
            schema_fingerprint: route.schema().clone(),
            transport_binding: route.transport_binding().clone(),
            reconnect_generation: route.reconnect_generation(),
            transcript_hash: route.context().transcript_hash().clone(),
            endpoint_locality: route.endpoint_locality(),
            purpose_class: route.purpose_class(),
            initiator_role: route.initiator_role(),
            responder_role: route.responder_role(),
            transport_class: route.transport_class(),
        })
    }

    /// Encode the bounded route bootstrap.
    pub fn encode(&self) -> Result<Vec<u8>, ProviderRuntimeError> {
        let bytes =
            serde_json::to_vec(self).map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
        if bytes.len() > PROVIDER_BOOTSTRAP_MAX_BYTES {
            return Err(ProviderRuntimeError::SessionUnauthenticated);
        }
        Ok(bytes)
    }

    /// Decode and validate the bounded route bootstrap envelope.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProviderRuntimeError> {
        if bytes.len() > PROVIDER_BOOTSTRAP_MAX_BYTES {
            return Err(ProviderRuntimeError::SessionUnauthenticated);
        }
        let metadata: Self = serde_json::from_slice(bytes)
            .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
        if metadata.protocol != PROVIDER_BOOTSTRAP_PROTOCOL {
            return Err(ProviderRuntimeError::SessionUnauthenticated);
        }
        if metadata
            .user_ref
            .as_ref()
            .is_some_and(|reference| reference.resource_type().as_str() != "User")
        {
            return Err(ProviderRuntimeError::SessionUnauthenticated);
        }
        Ok(metadata)
    }

    /// Borrow the optional authenticated User placement claim.
    pub fn user_ref(&self) -> Option<&ResourceRef> {
        self.user_ref.as_ref()
    }

    fn allocator_binding(&self) -> Result<AllocatorSessionBinding, ProviderRuntimeError> {
        let zone = ZonePath::new(vec![
            ZoneLabelId::parse(self.zone.as_str())
                .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?,
        ])
        .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
        Ok(AllocatorSessionBinding::new(
            zone,
            self.provider_ref.clone(),
            self.session_purpose.clone(),
            self.transport_binding.clone(),
        ))
    }

    fn route(&self) -> Result<AuthenticatedSessionRouteBinding, ProviderRuntimeError> {
        if self.provider_ref.resource_type().as_str() != "Provider"
            || self.zone_ref.resource_type().as_str() != "Zone"
            || self.zone_ref.name().as_str() != self.zone.as_str()
            || self.provider_generation.is_none()
            || self.controller_generation.is_none()
            || self.reconnect_generation.get() == 0
            || self.transport_binding.locality()
                != d2b_contracts_resource::v3::identity::Locality::Local
        {
            return Err(ProviderRuntimeError::SessionUnauthenticated);
        }
        let session = SessionBinding::new(
            self.schema_fingerprint.clone(),
            self.transport_binding.clone(),
            self.reconnect_generation,
            self.transcript_hash.clone(),
        );
        let mut context = AuthenticatedSubjectContext::new(
            self.subject_ref.clone(),
            self.subject_uid.clone(),
            self.zone_ref.clone(),
            self.evidence_class,
            self.session_purpose.clone(),
            self.service.clone(),
            session,
        )
        .with_provider_ref(self.provider_ref.clone());
        if let Some(execution_ref) = self.execution_ref.clone() {
            context = context.with_execution_ref(execution_ref);
        }
        if let Some(process_ref) = self.process_ref.clone() {
            context = context.with_process_ref(process_ref);
        }
        if let Some(provider_generation) = self.provider_generation {
            context = context.with_provider_generation(provider_generation);
        }
        if let Some(controller_generation) = self.controller_generation {
            context = context.with_controller_generation(controller_generation);
        }
        AuthenticatedSessionRouteBinding::from_authenticated_peer(
            context,
            self.endpoint_locality,
            self.purpose_class,
            self.initiator_role,
            self.responder_role,
            self.transport_class,
        )
        .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)
    }
}

impl std::fmt::Debug for ProviderSessionMetadata {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProviderSessionMetadata(<redacted>)")
    }
}

const PROVIDER_DELIVERY_KEY_PROTOCOL: &str = "d2b-provider-delivery-key-v1";

/// One allocator-issued Provider-side Credential delivery key handoff.
///
/// The private key is held only in a zeroizing owner until the Provider
/// consumes this value to establish its delivery session.
pub struct CredentialDeliveryKeyHandoff {
    provider_private: zeroize::Zeroizing<[u8; 32]>,
    provider_public: [u8; 32],
    backend_public: [u8; 32],
}

impl CredentialDeliveryKeyHandoff {
    /// Construct a handoff from already-issued key material.
    pub fn new(
        provider_private: [u8; 32],
        backend_public: [u8; 32],
    ) -> Result<Self, ProviderRuntimeError> {
        if provider_private == [0; 32] || backend_public == [0; 32] {
            return Err(ProviderRuntimeError::SessionUnauthenticated);
        }
        let provider_public = x25519_public_key(&provider_private)
            .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
        Ok(Self {
            provider_private: zeroize::Zeroizing::new(provider_private),
            provider_public,
            backend_public,
        })
    }

    /// Encode the handoff for one exact authenticated Provider route.
    pub fn encode_for_route(
        &self,
        route: &AuthenticatedSessionRouteBinding,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, ProviderRuntimeError> {
        let provider_ref = route
            .provider_ref()
            .ok_or(ProviderRuntimeError::SessionUnauthenticated)?;
        let process_ref = route
            .context()
            .process_ref()
            .ok_or(ProviderRuntimeError::SessionUnauthenticated)?;
        let execution_ref = route
            .context()
            .execution_ref()
            .ok_or(ProviderRuntimeError::SessionUnauthenticated)?;
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Wire<'a> {
            protocol: &'static str,
            zone: &'a str,
            provider_ref: String,
            process_ref: String,
            execution_ref: String,
            provider_generation: u64,
            controller_generation: u64,
            session_generation: u64,
            provider_private: &'a [u8; 32],
            provider_public: &'a [u8; 32],
            backend_public: &'a [u8; 32],
        }
        let payload = Wire {
            protocol: PROVIDER_DELIVERY_KEY_PROTOCOL,
            zone: route.zone().as_str(),
            provider_ref: provider_ref.to_canonical_string(),
            process_ref: process_ref.to_canonical_string(),
            execution_ref: execution_ref.to_canonical_string(),
            provider_generation: route
                .provider_generation()
                .ok_or(ProviderRuntimeError::SessionUnauthenticated)?
                .get(),
            controller_generation: route
                .controller_generation()
                .ok_or(ProviderRuntimeError::SessionUnauthenticated)?
                .get(),
            session_generation: route.reconnect_generation().get(),
            provider_private: &self.provider_private,
            provider_public: &self.provider_public,
            backend_public: &self.backend_public,
        };
        serde_json::to_vec(&payload)
            .map(zeroize::Zeroizing::new)
            .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)
    }

    /// Consume the handoff for the Provider side of the delivery session.
    pub fn into_material(self) -> CredentialDeliveryKeyMaterial {
        CredentialDeliveryKeyMaterial {
            local_private: self.provider_private,
            remote_public: self.backend_public,
        }
    }

    /// Borrow the Provider public key for Guest-supervisor enrollment.
    pub const fn provider_public(&self) -> &[u8; 32] {
        &self.provider_public
    }

    /// Borrow the enrolled Guest backend public key.
    pub const fn backend_public(&self) -> &[u8; 32] {
        &self.backend_public
    }
}

impl std::fmt::Debug for CredentialDeliveryKeyHandoff {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CredentialDeliveryKeyHandoff(<redacted>)")
    }
}

/// Zeroizing Provider-side key material for one sensitive Credential session.
pub struct CredentialDeliveryKeyMaterial {
    local_private: zeroize::Zeroizing<[u8; 32]>,
    remote_public: [u8; 32],
}

impl CredentialDeliveryKeyMaterial {
    /// Construct explicit enrolled key material.
    pub fn new(
        local_private: [u8; 32],
        remote_public: [u8; 32],
    ) -> Result<Self, ProviderRuntimeError> {
        if local_private == [0; 32] || remote_public == [0; 32] {
            return Err(ProviderRuntimeError::SessionUnauthenticated);
        }
        Ok(Self {
            local_private: zeroize::Zeroizing::new(local_private),
            remote_public,
        })
    }

    /// Convert the material into the session handshake credentials.
    pub fn into_handshake(self) -> Result<HandshakeCredentials, ProviderRuntimeError> {
        Ok(HandshakeCredentials::Kk {
            local_private: Secret32::new(*self.local_private)
                .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?,
            remote_public: self.remote_public,
        })
    }
}

impl std::fmt::Debug for CredentialDeliveryKeyMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CredentialDeliveryKeyMaterial(<redacted>)")
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CredentialDeliveryKeyWire {
    protocol: String,
    zone: String,
    provider_ref: ResourceRef,
    process_ref: ResourceRef,
    execution_ref: ResourceRef,
    provider_generation: u64,
    controller_generation: u64,
    session_generation: u64,
    provider_private: Vec<u8>,
    provider_public: Vec<u8>,
    backend_public: Vec<u8>,
}

impl Drop for CredentialDeliveryKeyWire {
    fn drop(&mut self) {
        self.provider_private.fill(0);
        self.provider_public.fill(0);
        self.backend_public.fill(0);
    }
}

fn decode_delivery_key_handoff(
    bytes: &[u8],
    route: &AuthenticatedSessionRouteBinding,
) -> Result<CredentialDeliveryKeyMaterial, ProviderRuntimeError> {
    let wire: CredentialDeliveryKeyWire =
        serde_json::from_slice(bytes).map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    let provider_ref = route
        .provider_ref()
        .ok_or(ProviderRuntimeError::SessionUnauthenticated)?;
    let process_ref = route
        .context()
        .process_ref()
        .ok_or(ProviderRuntimeError::SessionUnauthenticated)?;
    let execution_ref = route
        .context()
        .execution_ref()
        .ok_or(ProviderRuntimeError::SessionUnauthenticated)?;
    if wire.protocol != PROVIDER_DELIVERY_KEY_PROTOCOL
        || wire.zone != route.zone().as_str()
        || wire.provider_ref != *provider_ref
        || wire.process_ref != *process_ref
        || wire.execution_ref != *execution_ref
        || wire.provider_generation
            != route
                .provider_generation()
                .ok_or(ProviderRuntimeError::SessionUnauthenticated)?
                .get()
        || wire.controller_generation
            != route
                .controller_generation()
                .ok_or(ProviderRuntimeError::SessionUnauthenticated)?
                .get()
        || wire.session_generation != route.reconnect_generation().get()
    {
        return Err(ProviderRuntimeError::SessionUnauthenticated);
    }
    let provider_private = wire
        .provider_private
        .as_slice()
        .try_into()
        .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    let backend_public = wire
        .backend_public
        .as_slice()
        .try_into()
        .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    let provider_public: [u8; 32] = wire
        .provider_public
        .as_slice()
        .try_into()
        .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    if provider_public
        != x25519_public_key(&provider_private)
            .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?
    {
        return Err(ProviderRuntimeError::SessionUnauthenticated);
    }
    CredentialDeliveryKeyMaterial::new(provider_private, backend_public)
}

/// Closed failures from the Guest-local credential backend port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestCredentialBackendError {
    /// The endpoint could not be reached or did not answer in time.
    Unavailable,
    /// The endpoint returned a malformed response.
    Malformed,
    /// A request or response exceeded the bounded wire size.
    Oversize,
}

impl std::fmt::Display for GuestCredentialBackendError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "guest-credential-backend-unavailable",
            Self::Malformed => "guest-credential-backend-malformed",
            Self::Oversize => "guest-credential-backend-oversize",
        })
    }
}

impl std::error::Error for GuestCredentialBackendError {}

/// Non-secret metadata returned by one Guest-local provider operation.
pub struct GuestCredentialBackendResponse {
    state: Option<String>,
    lease_handle: Option<String>,
    source_version: Option<String>,
    rotation_generation: Option<u64>,
    expires_at_unix_ms: Option<u64>,
    outcome: Option<String>,
    bytes: Option<zeroize::Zeroizing<Vec<u8>>>,
}

impl GuestCredentialBackendResponse {
    /// Borrow the optional backend state.
    pub fn state(&self) -> Option<&str> {
        self.state.as_deref()
    }

    /// Borrow the optional opaque lease handle.
    pub fn lease_handle(&self) -> Option<&str> {
        self.lease_handle.as_deref()
    }

    /// Borrow the optional opaque source version.
    pub fn source_version(&self) -> Option<&str> {
        self.source_version.as_deref()
    }

    /// Return the optional rotation generation.
    pub const fn rotation_generation(&self) -> Option<u64> {
        self.rotation_generation
    }

    /// Return the optional absolute expiry.
    pub const fn expires_at_unix_ms(&self) -> Option<u64> {
        self.expires_at_unix_ms
    }

    /// Borrow the optional closed outcome label.
    pub fn outcome(&self) -> Option<&str> {
        self.outcome.as_deref()
    }

    /// Consume the response and return sensitive bytes in a zeroizing owner.
    pub fn into_bytes(self) -> Option<zeroize::Zeroizing<Vec<u8>>> {
        self.bytes
    }

    /// Explicitly erase and discard any sensitive response bytes.
    pub fn clear_bytes(&mut self) {
        self.bytes.take();
    }
}

impl std::fmt::Debug for GuestCredentialBackendResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("GuestCredentialBackendResponse(<redacted>)")
    }
}

/// A non-secret or zeroizing response returned by one Guest backend operation.
pub struct GuestCredentialBackendReply {
    state: Option<String>,
    lease_handle: Option<String>,
    source_version: Option<String>,
    rotation_generation: Option<u64>,
    expires_at_unix_ms: Option<u64>,
    outcome: Option<String>,
    bytes: Option<zeroize::Zeroizing<Vec<u8>>>,
}

impl GuestCredentialBackendReply {
    /// Construct a typed backend reply. Sensitive bytes remain zeroizing.
    pub fn new(
        state: Option<String>,
        lease_handle: Option<String>,
        source_version: Option<String>,
        rotation_generation: Option<u64>,
        expires_at_unix_ms: Option<u64>,
        outcome: Option<String>,
        bytes: Option<zeroize::Zeroizing<Vec<u8>>>,
    ) -> Self {
        Self {
            state,
            lease_handle,
            source_version,
            rotation_generation,
            expires_at_unix_ms,
            outcome,
            bytes,
        }
    }

    fn encode(self) -> Result<zeroize::Zeroizing<Vec<u8>>, GuestCredentialBackendHandlerError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Wire<'a> {
            protocol: &'static str,
            #[serde(skip_serializing_if = "Option::is_none")]
            state: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            lease_handle: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            source_version: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            rotation_generation: Option<u64>,
            #[serde(skip_serializing_if = "Option::is_none")]
            expires_at_unix_ms: Option<u64>,
            #[serde(skip_serializing_if = "Option::is_none")]
            outcome: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            bytes: Option<&'a [u8]>,
        }
        let bytes = self.bytes.as_ref().map(|bytes| bytes.as_slice());
        serde_json::to_vec(&Wire {
            protocol: GUEST_CREDENTIAL_BACKEND_PROTOCOL,
            state: self.state,
            lease_handle: self.lease_handle,
            source_version: self.source_version,
            rotation_generation: self.rotation_generation,
            expires_at_unix_ms: self.expires_at_unix_ms,
            outcome: self.outcome,
            bytes,
        })
        .map(zeroize::Zeroizing::new)
        .map_err(|_| GuestCredentialBackendHandlerError::Malformed)
    }
}

impl std::fmt::Debug for GuestCredentialBackendReply {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("GuestCredentialBackendReply(<redacted>)")
    }
}

/// Closed failures from a Guest backend responder handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestCredentialBackendHandlerError {
    /// The request is not valid for the exact backend route.
    Denied,
    /// The request or response is malformed.
    Malformed,
    /// The Guest-local provider backend could not answer.
    Unavailable,
}

/// Boxed future returned by a Guest backend responder handler.
pub type GuestCredentialBackendHandlerFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<GuestCredentialBackendReply, GuestCredentialBackendHandlerError>>
            + Send
            + 'a,
    >,
>;

/// Typed operation handler owned by the Guest credential execution context.
pub trait GuestCredentialBackendHandler: Send + Sync + 'static {
    /// Execute one already authenticated, route-bound operation.
    fn handle(
        &self,
        route: &AuthenticatedSessionRouteBinding,
        user_ref: Option<&ResourceRef>,
        operation: &str,
        fields: serde_json::Value,
    ) -> GuestCredentialBackendHandlerFuture<'_>;
}

#[derive(Clone)]
struct GuestCredentialBackendBinding {
    route: AuthenticatedSessionRouteBinding,
    user_ref: Option<ResourceRef>,
    expected_peer: d2b_session_unix::PeerCredentials,
}

/// Cancellable Guest-local backend responder lease.
pub struct GuestCredentialBackendResponderLease {
    route: tokio::sync::watch::Sender<Option<GuestCredentialBackendBinding>>,
    cancel: tokio::sync::watch::Sender<bool>,
    bound: std::sync::Mutex<bool>,
    initial_peer: d2b_session_unix::PeerCredentials,
}

impl std::fmt::Debug for GuestCredentialBackendResponderLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("GuestCredentialBackendResponderLease(<redacted>)")
    }
}

impl GuestCredentialBackendResponderLease {
    /// Bind the responder to one exact Provider ComponentSession route.
    pub fn bind_route(
        &self,
        route: AuthenticatedSessionRouteBinding,
    ) -> Result<(), ProviderRuntimeError> {
        self.bind_route_with_user(route, None)
    }

    /// Bind the responder to one exact Provider route and User scope claim.
    pub fn bind_route_with_user(
        &self,
        route: AuthenticatedSessionRouteBinding,
        user_ref: Option<ResourceRef>,
    ) -> Result<(), ProviderRuntimeError> {
        self.bind_route_with_user_and_peer(route, user_ref, self.initial_peer)
    }

    /// Bind the responder with the peer credentials observed on the
    /// authenticated fd10 bootstrap.
    pub fn bind_route_with_user_and_peer(
        &self,
        route: AuthenticatedSessionRouteBinding,
        user_ref: Option<ResourceRef>,
        expected_peer: d2b_session_unix::PeerCredentials,
    ) -> Result<(), ProviderRuntimeError> {
        if !validate_guest_backend_route(&route).is_ok() {
            return Err(ProviderRuntimeError::SessionUnauthenticated);
        }
        if user_ref
            .as_ref()
            .is_some_and(|reference| reference.resource_type().as_str() != "User")
        {
            return Err(ProviderRuntimeError::SessionUnauthenticated);
        }
        let mut bound = self
            .bound
            .lock()
            .map_err(|_| ProviderRuntimeError::SessionLoopFailed)?;
        if *bound {
            return Err(ProviderRuntimeError::SessionUnauthenticated);
        }
        *bound = true;
        self.route
            .send(Some(GuestCredentialBackendBinding {
                route,
                user_ref,
                expected_peer,
            }))
            .map_err(|_| ProviderRuntimeError::SessionLoopFailed)
    }

    /// Cancel the responder and close its sensitive session.
    pub fn cancel(&self) {
        let _ = self.cancel.send(true);
    }
}

impl Drop for GuestCredentialBackendResponderLease {
    fn drop(&mut self) {
        let _ = self.cancel.send(true);
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GuestCredentialBackendResponseWire {
    protocol: String,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    lease_handle: Option<String>,
    #[serde(default)]
    source_version: Option<String>,
    #[serde(default)]
    rotation_generation: Option<u64>,
    #[serde(default)]
    expires_at_unix_ms: Option<u64>,
    #[serde(default)]
    outcome: Option<String>,
    #[serde(default)]
    bytes: Option<Vec<u8>>,
}

/// Guest-local typed provider backend connection.
///
/// The endpoint is an inherited, prearmed descriptor. Requests contain only
/// opaque operation metadata; any sensitive response bytes are immediately
/// placed in a zeroizing buffer and never appear in a debug or status type.
#[derive(Clone)]
pub struct GuestCredentialBackend {
    state: Arc<tokio::sync::Mutex<GuestCredentialBackendState>>,
    route: Option<AuthenticatedSessionRouteBinding>,
}

impl std::fmt::Debug for GuestCredentialBackend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("GuestCredentialBackend(<redacted>)")
    }
}

impl GuestCredentialBackend {
    /// Adopt the broker-inherited Guest-local backend descriptor.
    pub fn from_inherited_fd(
        raw_fd: i32,
        route: &AuthenticatedSessionRouteBinding,
        delivery_keys: CredentialDeliveryKeyMaterial,
    ) -> Result<Arc<Self>, ProviderRuntimeError> {
        validate_guest_backend_route(route)?;
        let socket = SeqpacketSocket::from_inherited_fd(raw_fd)
            .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
        socket
            .acceptor_peer_credentials()
            .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
        Ok(Arc::new(Self {
            state: Arc::new(tokio::sync::Mutex::new(GuestCredentialBackendState {
                socket: Some(socket),
                connection: None,
                delivery_keys: Some(delivery_keys),
            })),
            route: Some(route.clone()),
        }))
    }

    /// Bind a prearmed backend socket for Layer-1 transport tests.
    pub fn from_socket_for_test(socket: SeqpacketSocket) -> Arc<Self> {
        Arc::new(Self {
            state: Arc::new(tokio::sync::Mutex::new(GuestCredentialBackendState {
                socket: Some(socket),
                connection: None,
                delivery_keys: None,
            })),
            route: None,
        })
    }

    /// Bind a prearmed backend socket to an authenticated route for transport
    /// and session-fencing tests.
    pub fn from_socket_for_test_with_route(
        socket: SeqpacketSocket,
        route: AuthenticatedSessionRouteBinding,
        delivery_keys: CredentialDeliveryKeyMaterial,
    ) -> Result<Arc<Self>, ProviderRuntimeError> {
        validate_guest_backend_route(&route)?;
        Ok(Arc::new(Self {
            state: Arc::new(tokio::sync::Mutex::new(GuestCredentialBackendState {
                socket: Some(socket),
                connection: None,
                delivery_keys: Some(delivery_keys),
            })),
            route: Some(route),
        }))
    }

    /// Attempt one typed operation against the Guest-local endpoint.
    pub async fn request(
        &self,
        operation: &str,
        fields: serde_json::Value,
    ) -> Result<GuestCredentialBackendResponse, GuestCredentialBackendError> {
        if operation.is_empty()
            || operation.len() > 128
            || !operation.is_ascii()
            || !matches!(
                operation,
                "secret-service.state"
                    | "secret-service.issue-lease"
                    | "secret-service.inspect-lease"
                    | "secret-service.refresh-lease"
                    | "secret-service.revoke-lease"
                    | "entra.state"
                    | "entra.issue-lease"
                    | "entra.inspect-lease"
                    | "entra.refresh-lease"
                    | "entra.revoke-lease"
                    | "managed-identity.state"
                    | "managed-identity.issue-lease"
                    | "managed-identity.inspect-lease"
                    | "managed-identity.refresh-lease"
                    | "managed-identity.revoke-lease"
            )
            || !fields.is_object()
        {
            return Err(GuestCredentialBackendError::Malformed);
        }
        let mut request = fields
            .as_object()
            .cloned()
            .ok_or(GuestCredentialBackendError::Malformed)?;
        request.insert(
            "protocol".to_owned(),
            serde_json::Value::String(GUEST_CREDENTIAL_BACKEND_PROTOCOL.to_owned()),
        );
        request.insert(
            "operation".to_owned(),
            serde_json::Value::String(operation.to_owned()),
        );
        let payload =
            serde_json::to_vec(&request).map_err(|_| GuestCredentialBackendError::Malformed)?;
        if payload.len() > GUEST_CREDENTIAL_BACKEND_MAX_BYTES {
            return Err(GuestCredentialBackendError::Oversize);
        }
        if let Some(route) = self.route.as_ref() {
            return self
                .request_over_authenticated_session(route, request)
                .await;
        }
        let policy = guest_backend_attachment_policy();
        let capacity = AncillaryCapacity::from_policy(policy)
            .map_err(|_| GuestCredentialBackendError::Malformed)?;
        let scopes =
            controller_credit_scopes().map_err(|_| GuestCredentialBackendError::Unavailable)?;
        let packet = d2b_session_unix::OutboundPacket::new(
            payload,
            Vec::new(),
            None,
            d2b_contracts_zone_session::v3::component_session::LimitProfile::local_default(),
            capacity,
            &scopes,
        )
        .map_err(|_| GuestCredentialBackendError::Oversize)?;
        let mut queue = VecDeque::from([packet]);
        let state = self.state.lock().await;
        let socket = state
            .socket
            .as_ref()
            .ok_or(GuestCredentialBackendError::Unavailable)?;
        let sent = tokio::time::timeout(
            Duration::from_millis(250),
            socket.send_burst(&mut queue, capacity, 1),
        )
        .await
        .map_err(|_| GuestCredentialBackendError::Unavailable)?
        .map_err(|_| GuestCredentialBackendError::Unavailable)?;
        if sent.sent.len() != 1 || !queue.is_empty() {
            return Err(GuestCredentialBackendError::Unavailable);
        }
        for packet in sent.sent {
            packet.acknowledge();
        }
        let burst = tokio::time::timeout(
            Duration::from_millis(250),
            socket.recv_burst(
                d2b_contracts_zone_session::v3::component_session::LimitProfile::local_default(),
                capacity,
                &scopes,
                1,
            ),
        )
        .await
        .map_err(|_| GuestCredentialBackendError::Unavailable)?
        .map_err(|_| GuestCredentialBackendError::Unavailable)?;
        if burst.packets.len() != 1 {
            return Err(GuestCredentialBackendError::Unavailable);
        }
        let packet = burst
            .packets
            .into_iter()
            .next()
            .ok_or(GuestCredentialBackendError::Unavailable)?;
        if packet.control_count() != 0 {
            return Err(GuestCredentialBackendError::Malformed);
        }
        let payload = packet.into_payload_zeroizing();
        let response: GuestCredentialBackendResponseWire =
            serde_json::from_slice(&payload).map_err(|_| GuestCredentialBackendError::Malformed)?;
        if response.protocol != GUEST_CREDENTIAL_BACKEND_PROTOCOL {
            return Err(GuestCredentialBackendError::Malformed);
        }
        Ok(GuestCredentialBackendResponse {
            state: response.state,
            lease_handle: response.lease_handle,
            source_version: response.source_version,
            rotation_generation: response.rotation_generation,
            expires_at_unix_ms: response.expires_at_unix_ms,
            outcome: response.outcome,
            bytes: response.bytes.map(zeroize::Zeroizing::new),
        })
    }

    /// Establish the authenticated Guest-local backend session before the
    /// synchronous Provider service begins dispatching operations.
    pub async fn preconnect(&self) -> Result<(), GuestCredentialBackendError> {
        let route = self
            .route
            .clone()
            .ok_or(GuestCredentialBackendError::Unavailable)?;
        let mut state = self.state.lock().await;
        ensure_backend_connection(&mut state, &route).await
    }

    async fn request_over_authenticated_session(
        &self,
        route: &AuthenticatedSessionRouteBinding,
        fields: serde_json::Map<String, serde_json::Value>,
    ) -> Result<GuestCredentialBackendResponse, GuestCredentialBackendError> {
        let mut state = self.state.lock().await;
        ensure_backend_connection(&mut state, route).await?;
        let connection = state
            .connection
            .as_ref()
            .ok_or(GuestCredentialBackendError::Unavailable)?;
        let mut metadata = Vec::with_capacity(8);
        metadata.push(ttrpc::proto::KeyValue {
            key: "d2b.credential.zone".to_owned(),
            value: route.zone().as_str().to_owned(),
            ..Default::default()
        });
        metadata.push(ttrpc::proto::KeyValue {
            key: "d2b.credential.provider".to_owned(),
            value: route
                .provider_ref()
                .ok_or(GuestCredentialBackendError::Unavailable)?
                .to_canonical_string(),
            ..Default::default()
        });
        metadata.push(ttrpc::proto::KeyValue {
            key: "d2b.credential.session-generation".to_owned(),
            value: route.reconnect_generation().get().to_string(),
            ..Default::default()
        });
        if let Some(execution_ref) = route.context().execution_ref() {
            metadata.push(ttrpc::proto::KeyValue {
                key: "d2b.credential.execution-ref".to_owned(),
                value: execution_ref.to_canonical_string(),
                ..Default::default()
            });
        }
        if let Some(process_ref) = route.context().process_ref() {
            metadata.push(ttrpc::proto::KeyValue {
                key: "d2b.credential.process-ref".to_owned(),
                value: process_ref.to_canonical_string(),
                ..Default::default()
            });
        }
        if let Some(provider_generation) = route.provider_generation() {
            metadata.push(ttrpc::proto::KeyValue {
                key: "d2b.credential.provider-generation".to_owned(),
                value: provider_generation.get().to_string(),
                ..Default::default()
            });
        }
        if let Some(controller_generation) = route.controller_generation() {
            metadata.push(ttrpc::proto::KeyValue {
                key: "d2b.credential.controller-generation".to_owned(),
                value: controller_generation.get().to_string(),
                ..Default::default()
            });
        }
        let mut request = ttrpc::proto::Request::new();
        request.set_service(GUEST_CREDENTIAL_BACKEND_SERVICE.to_owned());
        request.set_method("Request".to_owned());
        request.metadata = metadata;
        request.payload =
            serde_json::to_vec(&fields).map_err(|_| GuestCredentialBackendError::Malformed)?;
        let response = tokio::time::timeout(
            Duration::from_millis(250),
            connection.client.client().request(request),
        )
        .await
        .map_err(|_| GuestCredentialBackendError::Unavailable)?
        .map_err(|_| GuestCredentialBackendError::Unavailable)?;
        let payload = zeroize::Zeroizing::new(response.payload);
        let response: GuestCredentialBackendResponseWire =
            serde_json::from_slice(&payload).map_err(|_| GuestCredentialBackendError::Malformed)?;
        if response.protocol != GUEST_CREDENTIAL_BACKEND_PROTOCOL {
            return Err(GuestCredentialBackendError::Malformed);
        }
        Ok(GuestCredentialBackendResponse {
            state: response.state,
            lease_handle: response.lease_handle,
            source_version: response.source_version,
            rotation_generation: response.rotation_generation,
            expires_at_unix_ms: response.expires_at_unix_ms,
            outcome: response.outcome,
            bytes: response.bytes.map(zeroize::Zeroizing::new),
        })
    }
}

async fn ensure_backend_connection(
    state: &mut GuestCredentialBackendState,
    route: &AuthenticatedSessionRouteBinding,
) -> Result<(), GuestCredentialBackendError> {
    if state.connection.is_some() {
        return Ok(());
    }
    let socket = state
        .socket
        .take()
        .ok_or(GuestCredentialBackendError::Unavailable)?;
    let expected_peer = socket
        .acceptor_peer_credentials()
        .map_err(|_| GuestCredentialBackendError::Unavailable)?;
    let policy = credential_delivery_endpoint_policy(route.reconnect_generation().get());
    let transport = guest_backend_transport(socket, &policy, expected_peer)
        .map_err(|_| GuestCredentialBackendError::Unavailable)?;
    let credentials = state
        .delivery_keys
        .take()
        .ok_or(GuestCredentialBackendError::Unavailable)?
        .into_handshake()
        .map_err(|_| GuestCredentialBackendError::Unavailable)?;
    let engine = SessionEngine::establish_initiator(
        transport,
        policy,
        credentials,
        Instant::now(),
    )
    .await
    .map_err(|_| GuestCredentialBackendError::Unavailable)?;
    let driver: Arc<dyn ComponentSessionDriver> = Arc::new(engine.into_driver());
    let client = Arc::new(SessionTtrpcClient::new(Arc::clone(&driver)));
    state.connection = Some(GuestCredentialBackendConnection {
        _driver: driver,
        client,
    });
    Ok(())
}

struct GuestCredentialBackendState {
    socket: Option<SeqpacketSocket>,
    connection: Option<GuestCredentialBackendConnection>,
    delivery_keys: Option<CredentialDeliveryKeyMaterial>,
}

struct GuestCredentialBackendConnection {
    _driver: Arc<dyn ComponentSessionDriver>,
    client: Arc<SessionTtrpcClient>,
}

fn validate_guest_backend_route(
    route: &AuthenticatedSessionRouteBinding,
) -> Result<(), ProviderRuntimeError> {
    if !route.liveness().is_live()
        || route.service().as_str() != "d2b.credential.v3"
        || route
            .context()
            .execution_ref()
            .is_none_or(|reference| reference.resource_type().as_str() != "Guest")
        || route.provider_ref().is_none()
        || route.provider_generation().is_none()
        || route.controller_generation().is_none()
    {
        return Err(ProviderRuntimeError::SessionUnauthenticated);
    }
    Ok(())
}

fn guest_backend_attachment_policy()
-> d2b_contracts_zone_session::v3::component_session::AttachmentPolicy {
    use d2b_contracts_zone_session::v3::component_session::{
        AttachmentPolicy, AttachmentPolicyKind,
    };
    AttachmentPolicy {
        kind: AttachmentPolicyKind::PacketAtomic,
        max_per_packet: 1,
        max_per_request: 1,
        max_per_operation: 1,
        max_per_session: 1,
        credentials_allowed: false,
    }
}

fn guest_backend_transport(
    socket: SeqpacketSocket,
    policy: &EndpointPolicy,
    expected_peer: d2b_session_unix::PeerCredentials,
) -> Result<UnixSeqpacketTransport, ProviderRuntimeError> {
    let resolver: DescriptorPolicyResolver =
        Arc::new(|_| Err(UnixSessionError::DescriptorMismatch));
    UnixSeqpacketTransport::new(
        socket,
        policy.transport_binding.locality,
        policy.limits,
        policy.attachment_policy,
        controller_credit_scopes().map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?,
        resolver,
        PeerIdentityPolicy::inherited_socketpair(expected_peer),
    )
    .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)
}

/// Start the Guest-local credential backend responder for one prearmed peer.
///
/// The responder remains dormant until its owning Guest supervisor binds the
/// exact authenticated Provider route. This prevents a child from using a
/// socket or enrolled key pair after a Process or session replacement.
pub fn spawn_guest_credential_backend_responder(
    socket: SeqpacketSocket,
    delivery_keys: CredentialDeliveryKeyMaterial,
    handler: Arc<dyn GuestCredentialBackendHandler>,
) -> Result<Arc<GuestCredentialBackendResponderLease>, ProviderRuntimeError> {
    let initial_peer = socket
        .acceptor_peer_credentials()
        .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    let (route_tx, route_rx) = tokio::sync::watch::channel(None);
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    tokio::runtime::Handle::try_current().map_err(|_| ProviderRuntimeError::SessionLoopFailed)?;
    tokio::spawn(run_guest_credential_backend_responder(
        socket,
        delivery_keys,
        handler,
        route_rx,
        cancel_rx,
    ));
    Ok(Arc::new(GuestCredentialBackendResponderLease {
        route: route_tx,
        cancel: cancel_tx,
        bound: std::sync::Mutex::new(false),
        initial_peer,
    }))
}

async fn run_guest_credential_backend_responder(
    socket: SeqpacketSocket,
    delivery_keys: CredentialDeliveryKeyMaterial,
    handler: Arc<dyn GuestCredentialBackendHandler>,
    mut route_rx: tokio::sync::watch::Receiver<Option<GuestCredentialBackendBinding>>,
    mut cancel_rx: tokio::sync::watch::Receiver<bool>,
) {
    let route = loop {
        if *cancel_rx.borrow() {
            return;
        }
        if let Some(binding) = route_rx.borrow().clone() {
            break binding;
        }
        tokio::select! {
            result = route_rx.changed() => {
                if result.is_err() {
                    return;
                }
            }
            result = cancel_rx.changed() => {
                if result.is_err() || *cancel_rx.borrow() {
                    return;
                }
            }
        }
    };
    if !validate_guest_backend_route(&route.route).is_ok() {
        return;
    }
    let policy = credential_delivery_endpoint_policy(route.route.reconnect_generation().get());
    let Ok(transport) = guest_backend_transport(socket, &policy, route.expected_peer) else {
        return;
    };
    let Ok(credentials) = delivery_keys.into_handshake() else {
        return;
    };
    let responder =
        match SessionEngine::establish_responder(transport, policy, credentials, Instant::now())
            .await
        {
            Ok(responder) => responder,
            Err(_) => return,
        };
    let driver: Arc<dyn ComponentSessionDriver> = Arc::new(responder.into_driver());
    let service = ttrpc::r#async::Service {
        methods: HashMap::from([(
            "Request".to_owned(),
            Box::new(GuestCredentialBackendMethod {
                route: route.route,
                user_ref: route.user_ref,
                handler,
            })
            as Box<dyn ttrpc::r#async::MethodHandler + Send + Sync>,
        )]),
        streams: HashMap::new(),
    };
    tokio::select! {
        _ = d2b_session::serve_ttrpc_services(
            driver,
            HashMap::from([(GUEST_CREDENTIAL_BACKEND_SERVICE.to_owned(), service)]),
        ) => {}
        result = cancel_rx.changed() => {
            let _ = result;
        }
    }
}

struct GuestCredentialBackendMethod {
    route: AuthenticatedSessionRouteBinding,
    user_ref: Option<ResourceRef>,
    handler: Arc<dyn GuestCredentialBackendHandler>,
}

impl GuestCredentialBackendMethod {
    async fn invoke(
        &self,
        request: ttrpc::Request,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, GuestCredentialBackendHandlerError> {
        if request.service != GUEST_CREDENTIAL_BACKEND_SERVICE
            || request.method != "Request"
            || !self.route.liveness().is_live()
            || metadata_value(&request, "d2b.credential.zone") != Some(self.route.zone().as_str())
            || metadata_value(&request, "d2b.credential.provider")
                != self
                    .route
                    .provider_ref()
                    .map(|value| value.to_canonical_string())
                    .as_deref()
            || metadata_value(&request, "d2b.credential.session-generation")
                .and_then(|value| value.parse::<u64>().ok())
                != Some(self.route.reconnect_generation().get())
            || metadata_value(&request, "d2b.credential.execution-ref")
                != self
                    .route
                    .context()
                    .execution_ref()
                    .map(|value| value.to_canonical_string())
                    .as_deref()
            || metadata_value(&request, "d2b.credential.process-ref")
                != self
                    .route
                    .context()
                    .process_ref()
                    .map(|value| value.to_canonical_string())
                    .as_deref()
            || metadata_value(&request, "d2b.credential.provider-generation")
                .and_then(|value| value.parse::<u64>().ok())
                != self.route.provider_generation().map(|value| value.get())
            || metadata_value(&request, "d2b.credential.controller-generation")
                .and_then(|value| value.parse::<u64>().ok())
                != self.route.controller_generation().map(|value| value.get())
        {
            return Err(GuestCredentialBackendHandlerError::Denied);
        }
        let mut payload = zeroize::Zeroizing::new(request.payload);
        let mut value: serde_json::Value = serde_json::from_slice(&payload)
            .map_err(|_| GuestCredentialBackendHandlerError::Malformed)?;
        let object = value
            .as_object_mut()
            .ok_or(GuestCredentialBackendHandlerError::Malformed)?;
        if object.remove("protocol")
            != Some(serde_json::Value::String(
                GUEST_CREDENTIAL_BACKEND_PROTOCOL.to_owned(),
            ))
        {
            return Err(GuestCredentialBackendHandlerError::Denied);
        }
        let operation = object
            .remove("operation")
            .and_then(|value| value.as_str().map(str::to_owned))
            .ok_or(GuestCredentialBackendHandlerError::Malformed)?;
        if !valid_guest_backend_operation(&operation) {
            return Err(GuestCredentialBackendHandlerError::Denied);
        }
        let fields = serde_json::Value::Object(std::mem::take(object));
        let reply = self
            .handler
            .handle(&self.route, self.user_ref.as_ref(), &operation, fields)
            .await?;
        payload.fill(0);
        reply.encode()
    }
}

#[async_trait::async_trait]
impl ttrpc::r#async::MethodHandler for GuestCredentialBackendMethod {
    async fn handler(
        &self,
        _context: ttrpc::r#async::TtrpcContext,
        request: ttrpc::Request,
    ) -> ttrpc::Result<ttrpc::Response> {
        let payload = self.invoke(request).await.map_err(backend_rpc_error)?;
        let mut response = ttrpc::Response::new();
        response.set_status(ttrpc::get_status(ttrpc::Code::OK, ""));
        response.payload = payload.to_vec();
        Ok(response)
    }
}

fn backend_rpc_error(error: GuestCredentialBackendHandlerError) -> ttrpc::Error {
    let code = match error {
        GuestCredentialBackendHandlerError::Denied => ttrpc::Code::PERMISSION_DENIED,
        GuestCredentialBackendHandlerError::Malformed => ttrpc::Code::INVALID_ARGUMENT,
        GuestCredentialBackendHandlerError::Unavailable => ttrpc::Code::UNAVAILABLE,
    };
    ttrpc::Error::RpcStatus(ttrpc::get_status(code, "guest-credential-backend"))
}

fn metadata_value<'a>(request: &'a ttrpc::Request, key: &str) -> Option<&'a str> {
    request
        .metadata
        .iter()
        .find(|value| value.key == key)
        .map(|value| value.value.as_str())
}

fn valid_guest_backend_operation(operation: &str) -> bool {
    matches!(
        operation,
        "secret-service.state"
            | "secret-service.issue-lease"
            | "secret-service.inspect-lease"
            | "secret-service.refresh-lease"
            | "secret-service.revoke-lease"
            | "entra.state"
            | "entra.issue-lease"
            | "entra.inspect-lease"
            | "entra.refresh-lease"
            | "entra.revoke-lease"
            | "managed-identity.state"
            | "managed-identity.issue-lease"
            | "managed-identity.inspect-lease"
            | "managed-identity.refresh-lease"
            | "managed-identity.revoke-lease"
    )
}

/// Run one Provider's real supervised fd10 lifecycle.
pub fn run_from_fd10<P, A, F>(spec: ProviderFd10Spec, factory: F) -> i32
where
    P: CredentialProvider + 'static,
    A: crate::CredentialAuthorizationSource,
    F: FnOnce(
            &AuthenticatedSessionRouteBinding,
            &ProviderSessionMetadata,
            Arc<GuestCredentialBackend>,
        ) -> Result<(Arc<P>, Arc<A>), ProviderRuntimeError>
        + Send
        + 'static,
{
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => return 1,
    };
    match runtime.block_on(run_from_fd10_async(spec, factory)) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

async fn run_from_fd10_async<P, A, F>(
    spec: ProviderFd10Spec,
    factory: F,
) -> Result<(), ProviderRuntimeError>
where
    P: CredentialProvider + 'static,
    A: crate::CredentialAuthorizationSource,
    F: FnOnce(
            &AuthenticatedSessionRouteBinding,
            &ProviderSessionMetadata,
            Arc<GuestCredentialBackend>,
        ) -> Result<(Arc<P>, Arc<A>), ProviderRuntimeError>
        + Send
        + 'static,
{
    let bootstrap = SeqpacketSocket::from_inherited_fd(PROVIDER_BOOTSTRAP_FD)
        .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    let expected_peer = bootstrap
        .acceptor_peer_credentials()
        .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    let (daemon_endpoint, controller_endpoint) =
        prearmed_seqpacket_pair().map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    let controller_socket = SeqpacketSocket::from_parent_prearmed(controller_endpoint)
        .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    send_controller_bootstrap(&bootstrap, daemon_endpoint).await?;
    let policy = credential_provider_endpoint_policy();
    let transport = provider_transport(controller_socket, &policy, expected_peer)?;
    let engine = SessionEngine::establish_initiator(
        transport,
        policy,
        HandshakeCredentials::Nn,
        Instant::now(),
    )
    .await
    .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    let driver = engine.into_driver();
    let bootstrap_stream = StreamId::new(PROVIDER_BOOTSTRAP_STREAM_ID)
        .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    driver
        .open_named_stream(
            bootstrap_stream,
            PROVIDER_BOOTSTRAP_STREAM_CREDIT,
            PROVIDER_BOOTSTRAP_STREAM_CREDIT,
        )
        .await
        .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    let metadata = ProviderSessionMetadata::decode(&receive_route_metadata(&driver).await?)?;
    if metadata.provider_ref != spec.provider_ref
        || metadata.service.as_str() != spec.service
        || metadata.session_purpose != spec.accepted_purpose
        || metadata.reconnect_generation.get() != driver.generation()
    {
        return Err(ProviderRuntimeError::SessionUnauthenticated);
    }
    let route = metadata.route()?;
    let delivery_keys = receive_delivery_key_handoff(&driver, &route).await?;
    let backend = GuestCredentialBackend::from_inherited_fd(
        GUEST_CREDENTIAL_BACKEND_FD,
        &route,
        delivery_keys,
    )?;
    backend
        .preconnect()
        .await
        .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    let bootstrap_identity = ProviderAgentBootstrap::new(
        spec.provider_ref.clone(),
        ZonePath::new(vec![
            ZoneLabelId::parse(metadata.zone.as_str())
                .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?,
        ])
        .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?,
        spec.accepted_purpose.clone(),
    );
    bootstrap_identity
        .admit(metadata.allocator_binding()?)
        .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;

    let mut entrypoint =
        ProviderEntrypoint::with_provider(spec.name, spec.provider_ref, spec.service)?;
    if let Some(execution_ref) = route.context().execution_ref().cloned() {
        entrypoint = entrypoint.with_execution_target(execution_ref)?;
    }
    if let Some(process_ref) = route.context().process_ref().cloned() {
        entrypoint = entrypoint.with_controller_process(process_ref)?;
    }
    if let (Some(provider_generation), Some(controller_generation)) =
        (route.provider_generation(), route.controller_generation())
    {
        entrypoint = entrypoint.with_generations(provider_generation, controller_generation)?;
    }
    let registration = entrypoint.admit()?;
    let session_admission = entrypoint.admit_authenticated(&route)?;
    let (provider, authorizer) = factory(&route, &metadata, backend)?;
    serve_provider_route(
        entrypoint,
        registration,
        session_admission,
        Arc::new(driver),
        route,
        provider,
        authorizer,
    )
    .await
}

async fn send_controller_bootstrap(
    bootstrap: &SeqpacketSocket,
    daemon_endpoint: std::os::fd::OwnedFd,
) -> Result<(), ProviderRuntimeError> {
    let policy = controller_bootstrap_attachment_policy();
    let capacity = AncillaryCapacity::from_policy(policy)
        .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    let scopes =
        controller_credit_scopes().map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    let packet = d2b_session_unix::OutboundPacket::with_current_credentials(
        d2b_session_unix::CONTROLLER_BOOTSTRAP_PROTOCOL_MARKER.to_vec(),
        vec![Arc::new(daemon_endpoint)],
        d2b_contracts_zone_session::v3::component_session::LimitProfile::local_default(),
        capacity,
        &scopes,
    )
    .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    let mut queue = VecDeque::from([packet]);
    let sent = tokio::time::timeout(
        CONTROLLER_BOOTSTRAP_TIMEOUT,
        bootstrap.send_burst(&mut queue, capacity, 1),
    )
    .await
    .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?
    .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    if sent.sent.len() != 1 || !queue.is_empty() {
        return Err(ProviderRuntimeError::SessionUnauthenticated);
    }
    for packet in sent.sent {
        packet.acknowledge();
    }
    Ok(())
}

fn provider_transport(
    socket: SeqpacketSocket,
    policy: &EndpointPolicy,
    expected_peer: d2b_session_unix::PeerCredentials,
) -> Result<UnixSeqpacketTransport, ProviderRuntimeError> {
    let resolver: DescriptorPolicyResolver =
        Arc::new(|_| Err(UnixSessionError::DescriptorMismatch));
    UnixSeqpacketTransport::new(
        socket,
        policy.transport_binding.locality,
        policy.limits,
        policy.attachment_policy,
        controller_credit_scopes().map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?,
        resolver,
        PeerIdentityPolicy::inherited_socketpair(expected_peer),
    )
    .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)
}

async fn receive_route_metadata(
    driver: &SessionDriverHandle,
) -> Result<Vec<u8>, ProviderRuntimeError> {
    let stream = StreamId::new(PROVIDER_BOOTSTRAP_STREAM_ID)
        .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    let mut bytes = Vec::new();
    loop {
        match driver
            .receive_named_stream_for(stream)
            .await
            .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?
        {
            StreamEvent::Data {
                stream: received,
                bytes: chunk,
            } if received == stream => {
                bytes.extend_from_slice(&chunk);
                if bytes.len() > PROVIDER_BOOTSTRAP_MAX_BYTES {
                    return Err(ProviderRuntimeError::SessionUnauthenticated);
                }
                driver
                    .grant_named_stream_credit(
                        stream,
                        u32::try_from(chunk.len())
                            .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?,
                    )
                    .await
                    .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
            }
            StreamEvent::RemoteClosed { stream: closed } if closed == stream => return Ok(bytes),
            StreamEvent::Reset { .. } => {
                return Err(ProviderRuntimeError::SessionUnauthenticated);
            }
            _ => return Err(ProviderRuntimeError::SessionUnauthenticated),
        }
    }
}

async fn serve_provider_route<P, A>(
    entrypoint: ProviderEntrypoint,
    registration: crate::ProviderAdmission,
    session_admission: ProviderSessionAdmission,
    driver: Arc<dyn ComponentSessionDriver>,
    route: AuthenticatedSessionRouteBinding,
    provider: Arc<P>,
    authorizer: Arc<A>,
) -> Result<(), ProviderRuntimeError>
where
    P: CredentialProvider + 'static,
    A: crate::CredentialAuthorizationSource,
{
    let services = credential_service(provider, authorizer, route.clone());
    let serving = tokio::spawn(d2b_session::serve_ttrpc_services(
        Arc::clone(&driver),
        services,
    ));
    tokio::task::yield_now().await;
    if serving.is_finished() {
        let _ = serving.await;
        return Err(ProviderRuntimeError::SessionLoopFailed);
    }
    if entrypoint
        .publish_authenticated_ready(&registration, session_admission, &route)
        .is_err()
    {
        serving.abort();
        let _ = serving.await;
        return Err(ProviderRuntimeError::SessionLoopFailed);
    }
    let ready_result = async {
        let stream = StreamId::new(PROVIDER_READY_STREAM_ID)
            .map_err(|_| ProviderRuntimeError::SessionLoopFailed)?;
        driver
            .open_named_stream(
                stream,
                PROVIDER_READY_STREAM_CREDIT,
                PROVIDER_READY_STREAM_CREDIT,
            )
            .await
            .map_err(|_| ProviderRuntimeError::SessionLoopFailed)?;
        driver
            .send_named_stream(stream, PROVIDER_READY_MARKER.to_vec())
            .await
            .map_err(|_| ProviderRuntimeError::SessionLoopFailed)?;
        driver
            .close_named_stream(stream)
            .await
            .map_err(|_| ProviderRuntimeError::SessionLoopFailed)
    }
    .await;
    if let Err(error) = ready_result {
        serving.abort();
        let _ = serving.await;
        return Err(error);
    }
    let result = serving
        .await
        .map_err(|_| ProviderRuntimeError::SessionLoopFailed)?
        .map_err(|_| ProviderRuntimeError::SessionLoopFailed);
    let _ = driver
        .close(
            d2b_contracts_zone_session::v3::component_session::CloseReason::Normal,
            d2b_contracts_zone_session::v3::component_session::Remediation::None,
        )
        .await;
    drop(registration);
    if !entrypoint.drain(Duration::from_secs(5)) {
        return Err(ProviderRuntimeError::SessionLoopFailed);
    }
    result
}

async fn receive_delivery_key_handoff(
    driver: &SessionDriverHandle,
    route: &AuthenticatedSessionRouteBinding,
) -> Result<CredentialDeliveryKeyMaterial, ProviderRuntimeError> {
    let stream = StreamId::new(PROVIDER_DELIVERY_KEY_STREAM_ID)
        .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    driver
        .open_named_stream(
            stream,
            PROVIDER_DELIVERY_KEY_STREAM_CREDIT,
            PROVIDER_DELIVERY_KEY_STREAM_CREDIT,
        )
        .await
        .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    loop {
        match driver
            .receive_named_stream_for(stream)
            .await
            .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?
        {
            StreamEvent::Data {
                stream: received,
                bytes: chunk,
            } if received == stream => {
                bytes.extend_from_slice(&chunk);
                if bytes.len() > 4 * 1024 {
                    return Err(ProviderRuntimeError::SessionUnauthenticated);
                }
                driver
                    .grant_named_stream_credit(
                        stream,
                        u32::try_from(chunk.len())
                            .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?,
                    )
                    .await
                    .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
            }
            StreamEvent::RemoteClosed { stream: closed } if closed == stream => {
                return decode_delivery_key_handoff(&bytes, route);
            }
            StreamEvent::Reset { .. } => {
                return Err(ProviderRuntimeError::SessionUnauthenticated);
            }
            _ => return Err(ProviderRuntimeError::SessionUnauthenticated),
        }
    }
}
