//! Supervised Provider binary bootstrap over the inherited fd 10 handoff.

use std::{
    collections::VecDeque,
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
use sha2::{Digest, Sha256};

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
const PROVIDER_BOOTSTRAP_MAX_BYTES: usize = 64 * 1024;
const PROVIDER_BOOTSTRAP_PROTOCOL: &str = "d2b-provider-session-bootstrap-v1";
const GUEST_CREDENTIAL_BACKEND_MAX_BYTES: usize = 64 * 1024;
const GUEST_CREDENTIAL_BACKEND_PROTOCOL: &str = "d2b-guest-credential-backend-v1";

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
        let provider_ref = route
            .provider_ref()
            .cloned()
            .ok_or(ProviderRuntimeError::SessionUnauthenticated)?;
        Ok(Self {
            protocol: PROVIDER_BOOTSTRAP_PROTOCOL.to_owned(),
            zone: route.zone().clone(),
            provider_ref,
            subject_ref: route.subject_ref().clone(),
            subject_uid: route.subject_uid().clone(),
            zone_ref: route.context().zone_ref().clone(),
            evidence_class: route.evidence_class(),
            execution_ref: route.context().execution_ref().cloned(),
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
        Ok(metadata)
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
            })),
            route: None,
        })
    }

    /// Bind a prearmed backend socket to an authenticated route for transport
    /// and session-fencing tests.
    pub fn from_socket_for_test_with_route(
        socket: SeqpacketSocket,
        route: AuthenticatedSessionRouteBinding,
    ) -> Result<Arc<Self>, ProviderRuntimeError> {
        validate_guest_backend_route(&route)?;
        Ok(Arc::new(Self {
            state: Arc::new(tokio::sync::Mutex::new(GuestCredentialBackendState {
                socket: Some(socket),
                connection: None,
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

    async fn request_over_authenticated_session(
        &self,
        route: &AuthenticatedSessionRouteBinding,
        fields: serde_json::Map<String, serde_json::Value>,
    ) -> Result<GuestCredentialBackendResponse, GuestCredentialBackendError> {
        let mut state = self.state.lock().await;
        if state.connection.is_none() {
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
            let credentials = credential_delivery_credentials(route, true)
                .map_err(|_| GuestCredentialBackendError::Unavailable)?;
            let engine = match SessionEngine::establish_initiator(
                transport,
                policy,
                credentials,
                Instant::now(),
            )
            .await
            {
                Ok(engine) => engine,
                Err(_error) => {
                    return Err(GuestCredentialBackendError::Unavailable);
                }
            };
            let driver: Arc<dyn ComponentSessionDriver> = Arc::new(engine.into_driver());
            let client = Arc::new(SessionTtrpcClient::new(Arc::clone(&driver)));
            state.connection = Some(GuestCredentialBackendConnection {
                _driver: driver,
                client,
            });
        }
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
        request.set_service("d2b.guest.credential.v1.GuestCredentialBackend".to_owned());
        request.set_method("Request".to_owned());
        request.metadata = metadata;
        request.payload = serde_json::to_vec(&fields)
            .map_err(|_| GuestCredentialBackendError::Malformed)?;
        let response = tokio::time::timeout(
            Duration::from_millis(250),
            connection.client.client().request(request),
        )
        .await
        .map_err(|_| GuestCredentialBackendError::Unavailable)?
        .map_err(|_| GuestCredentialBackendError::Unavailable)?;
        let payload = zeroize::Zeroizing::new(response.payload);
        let response: GuestCredentialBackendResponseWire = serde_json::from_slice(&payload)
            .map_err(|_| GuestCredentialBackendError::Malformed)?;
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

struct GuestCredentialBackendState {
    socket: Option<SeqpacketSocket>,
    connection: Option<GuestCredentialBackendConnection>,
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

/// Derive the session-bound enrolled Noise_KK credentials used by a
/// Guest-local Credential backend route.
///
/// The seed is bound to the already authenticated Provider route and is
/// intentionally never serialized into status, audit, or request metadata.
pub fn credential_delivery_credentials(
    route: &AuthenticatedSessionRouteBinding,
    initiator: bool,
) -> Result<HandshakeCredentials, ProviderRuntimeError> {
    let local_label = if initiator {
        b"provider".as_slice()
    } else {
        b"guest".as_slice()
    };
    let remote_label = if initiator {
        b"guest".as_slice()
    } else {
        b"provider".as_slice()
    };
    let local = credential_delivery_seed(route, local_label);
    let remote = credential_delivery_seed(route, remote_label);
    Ok(HandshakeCredentials::Kk {
        local_private: Secret32::new(local)
            .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?,
        remote_public: x25519_public_key(&remote)
            .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?,
    })
}

fn credential_delivery_seed(route: &AuthenticatedSessionRouteBinding, label: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"d2b:v3:credential-delivery:enrolled-kk");
    digest.update([0]);
    digest.update(label);
    digest.update([0]);
    digest.update(route.zone().as_str().as_bytes());
    digest.update([0]);
    if let Some(provider) = route.provider_ref() {
        digest.update(provider.to_canonical_string().as_bytes());
    }
    digest.update([0]);
    digest.update(route.reconnect_generation().get().to_be_bytes());
    if let Some(provider_generation) = route.provider_generation() {
        digest.update(provider_generation.get().to_be_bytes());
    }
    digest.update([0]);
    if let Some(controller_generation) = route.controller_generation() {
        digest.update(controller_generation.get().to_be_bytes());
    }
    digest.finalize().into()
}

/// Run one Provider's real supervised fd10 lifecycle.
pub fn run_from_fd10<P, A, F>(spec: ProviderFd10Spec, factory: F) -> i32
where
    P: CredentialProvider + 'static,
    A: crate::CredentialAuthorizationSource,
    F: FnOnce(
            &AuthenticatedSessionRouteBinding,
            Arc<GuestCredentialBackend>,
        ) -> Result<(Arc<P>, Arc<A>), ProviderRuntimeError>
        + Send
        + 'static,
{
    let runtime = match tokio::runtime::Builder::new_current_thread()
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
    let backend = GuestCredentialBackend::from_inherited_fd(GUEST_CREDENTIAL_BACKEND_FD, &route)?;
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
    let (provider, authorizer) = factory(&route, backend)?;
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
