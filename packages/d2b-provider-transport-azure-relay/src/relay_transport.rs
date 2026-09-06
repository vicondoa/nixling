//! Azure Relay byte-stream Provider.

use std::{
    collections::HashMap,
    fmt,
    sync::{
        Arc, Mutex as StdMutex, MutexGuard as StdMutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use d2b_contracts::ResourceRef;
use d2b_session::{
    OwnedTransport, TransportDescriptor, TransportError, TransportPacket, TransportReader,
    TransportWriter,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::time::{Instant, sleep, timeout_at};
use zeroize::Zeroizing;

use crate::{
    backpressure::{BackpressureError, CreditWindow, MAX_RELAY_FRAME_BYTES},
    credential_client::{
        RelayCredentialBinding, RelayCredentialLease, RelayCredentialRole, RelaySecret,
        ScopedCredentialClient, ScopedCredentialRequest,
    },
    reconnect::{ReconnectBackoff, ReconnectDecision},
    transport_settings::RelayTransportSettings,
};

type HmacSha256 = Hmac<Sha256>;

/// Maximum number of retained ZoneLink/session generation fences.
pub const MAX_RELAY_GENERATION_FENCES: usize = 1_024;
/// Maximum Guest-local CA bundle accepted by the connector.
pub const MAX_RELAY_CA_BYTES: usize = 256 * 1024;
/// Maximum WebSocket write buffer for one Relay connection.
pub const MAX_RELAY_WS_WRITE_BUFFER_BYTES: usize = 2 * MAX_RELAY_FRAME_BYTES;
const MAX_COMPLETED_RELAY_TRANSPORTS: usize = MAX_RELAY_GENERATION_FENCES;

/// Relay endpoint role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayRole {
    /// Gateway listener.
    Listener,
    /// Gateway sender.
    Sender,
}

/// Non-secret Relay endpoint settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayEndpoint {
    /// Validated transport settings.
    pub settings: RelayTransportSettings,
}

/// Provider root configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct RelayTransportConfig {
    /// Gateway Guest execution boundary.
    pub execution_ref: ResourceRef,
    /// Gateway egress Network.
    pub network_ref: ResourceRef,
    /// Session cap.
    pub max_concurrent_sessions: u32,
    /// Connect timeout.
    pub connect_timeout_seconds: u32,
}

impl RelayTransportConfig {
    /// Validate placement and bounds.
    pub fn validate(&self) -> Result<(), RelayTransportError> {
        if self.execution_ref.resource_type().as_str() != "Guest"
            || self.network_ref.resource_type().as_str() != "Network"
            || !(1..=256).contains(&self.max_concurrent_sessions)
            || !(5..=300).contains(&self.connect_timeout_seconds)
        {
            return Err(RelayTransportError::InvalidConfiguration);
        }
        Ok(())
    }
}

impl fmt::Debug for RelayTransportConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayTransportConfig")
            .field("execution_ref", &"<redacted>")
            .field("network_ref", &"<redacted>")
            .field("max_concurrent_sessions", &self.max_concurrent_sessions)
            .field("connect_timeout_seconds", &self.connect_timeout_seconds)
            .finish()
    }
}

/// Relay application frame.
pub struct RelayFrame(Zeroizing<Vec<u8>>);

impl RelayFrame {
    /// Construct a bounded frame.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, RelayTransportError> {
        let bytes = bytes.into();
        if bytes.len() > MAX_RELAY_FRAME_BYTES {
            return Err(RelayTransportError::FrameTooLarge);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    /// Borrow bytes at the socket effect boundary.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl fmt::Debug for RelayFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RelayFrame(<redacted>)")
    }
}

/// Relay socket seam. The production adapter can back this with a
/// WebSocket; tests use a real duplex byte stream.
#[async_trait]
pub trait RelaySocket: Send + Sync {
    /// Write one bounded frame.
    async fn send(&self, frame: RelayFrame) -> Result<(), RelayTransportError>;
    /// Read one bounded frame.
    async fn receive(&self) -> Result<Option<RelayFrame>, RelayTransportError>;
    /// Close the socket.
    async fn close(&self) -> Result<(), RelayTransportError>;
}

/// Connector seam that owns endpoint and WebSocket details.
#[async_trait]
pub trait RelaySocketConnector: Send + Sync {
    /// Connect one role using gateway-local credential material.
    async fn connect(
        &self,
        endpoint: &RelayEndpoint,
        role: RelayRole,
        lease: &RelayCredentialLease,
    ) -> Result<Arc<dyn RelaySocket>, RelayTransportError>;
}

type RelayWebSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

struct RelayWebSocketSocket {
    sink: Mutex<
        futures_util::stream::SplitSink<RelayWebSocket, tokio_tungstenite::tungstenite::Message>,
    >,
    stream: Mutex<futures_util::stream::SplitStream<RelayWebSocket>>,
}

#[async_trait]
impl RelaySocket for RelayWebSocketSocket {
    async fn send(&self, frame: RelayFrame) -> Result<(), RelayTransportError> {
        use futures_util::SinkExt;
        self.sink
            .lock()
            .await
            .send(tokio_tungstenite::tungstenite::Message::Binary(
                frame.as_bytes().to_vec(),
            ))
            .await
            .map_err(|_| RelayTransportError::Unavailable)
    }

    async fn receive(&self) -> Result<Option<RelayFrame>, RelayTransportError> {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;

        loop {
            let message = self.stream.lock().await.next().await;
            match message {
                Some(Ok(Message::Binary(bytes))) => {
                    return RelayFrame::new(bytes).map(Some);
                }
                Some(Ok(Message::Ping(bytes))) => {
                    self.sink
                        .lock()
                        .await
                        .send(Message::Pong(bytes))
                        .await
                        .map_err(|_| RelayTransportError::Unavailable)?;
                }
                Some(Ok(Message::Pong(_)) | Ok(Message::Text(_)) | Ok(Message::Frame(_))) => {}
                Some(Ok(Message::Close(_))) | None => return Ok(None),
                Some(Err(_)) => return Err(RelayTransportError::Unavailable),
            }
        }
    }

    async fn close(&self) -> Result<(), RelayTransportError> {
        use futures_util::SinkExt;
        self.sink
            .lock()
            .await
            .close()
            .await
            .map_err(|_| RelayTransportError::Unavailable)
    }
}

/// Guest-local Azure Relay WebSocket connector.
///
/// The connector is intentionally an effect adapter: it receives a lease only
/// for the duration of the WebSocket authentication call. The caller revokes
/// the lease before exposing the resulting socket to the rest of the
/// transport, and the connector never stores credential bytes.
pub struct AzureRelaySocketConnector {
    ca_pem: Option<Vec<u8>>,
    sas_ttl_secs: u64,
    connect_timeout: Duration,
}

impl AzureRelaySocketConnector {
    /// Construct a connector using public web PKI roots.
    pub const fn new() -> Self {
        Self {
            ca_pem: None,
            sas_ttl_secs: crate::auth::DEFAULT_SAS_TTL_SECS,
            connect_timeout: Duration::from_secs(30),
        }
    }

    /// Add a Guest-local PEM CA bundle for an egress proxy.
    pub fn with_ca_pem(mut self, ca_pem: Option<Vec<u8>>) -> Self {
        self.ca_pem = ca_pem;
        self
    }

    /// Set the bounded TTL used when a SAS rule key mints a bearer.
    pub fn with_sas_ttl_secs(mut self, sas_ttl_secs: u64) -> Self {
        self.sas_ttl_secs = sas_ttl_secs;
        self
    }

    /// Bound one WebSocket/TLS handshake.
    pub fn with_connect_timeout(mut self, connect_timeout: Duration) -> Self {
        self.connect_timeout = connect_timeout;
        self
    }
}

impl Default for AzureRelaySocketConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for AzureRelaySocketConnector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzureRelaySocketConnector")
            .field("ca_pem", &self.ca_pem.as_ref().map(|_| "<configured>"))
            .field("sas_ttl_secs", &self.sas_ttl_secs)
            .field("connect_timeout", &self.connect_timeout)
            .finish()
    }
}

#[async_trait]
impl RelaySocketConnector for AzureRelaySocketConnector {
    async fn connect(
        &self,
        endpoint: &RelayEndpoint,
        role: RelayRole,
        lease: &RelayCredentialLease,
    ) -> Result<Arc<dyn RelaySocket>, RelayTransportError> {
        use futures_util::StreamExt;
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue};
        use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

        install_rustls_provider();
        let credential = lease
            .auth_credential()
            .map_err(|_| RelayTransportError::CredentialInvalid)?;
        let auth_endpoint = crate::auth::RelayEndpoint {
            namespace: format!(
                "{}.servicebus.windows.net",
                endpoint.settings.relay_namespace_id
            ),
            entity: endpoint.settings.relay_entity_id.clone(),
        };
        let auth_role = match role {
            RelayRole::Listener => crate::auth::RelayRole::Listener,
            RelayRole::Sender => crate::auth::RelayRole::Sender,
        };
        let sas_ttl_secs = if matches!(credential, crate::auth::RelayCredential::Sas { .. }) {
            let now_unix_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| RelayTransportError::CredentialExpired)?
                .as_millis() as u64;
            let lease_ttl_secs = lease.expires_at_unix_ms().saturating_sub(now_unix_ms) / 1_000;
            self.sas_ttl_secs.min(lease_ttl_secs.max(1))
        } else {
            self.sas_ttl_secs
        };
        let connect =
            crate::auth::build_connect(&auth_endpoint, auth_role, &credential, sas_ttl_secs)
                .map_err(|_| RelayTransportError::CredentialInvalid)?;
        let (url, auth_header) = connect.into_parts();
        let mut request = url
            .into_client_request()
            .map_err(|_| RelayTransportError::InvalidConfiguration)?;
        if let Some(value) = auth_header.as_deref() {
            request.headers_mut().insert(
                HeaderName::from_static("servicebusauthorization"),
                HeaderValue::from_str(value).map_err(|_| RelayTransportError::CredentialInvalid)?,
            );
        }
        if self
            .ca_pem
            .as_ref()
            .is_some_and(|ca_pem| ca_pem.len() > MAX_RELAY_CA_BYTES)
        {
            return Err(RelayTransportError::InvalidConfiguration);
        }
        let connector = tls_connector(self.ca_pem.as_deref())?;
        let websocket_config = WebSocketConfig {
            write_buffer_size: MAX_RELAY_FRAME_BYTES,
            max_write_buffer_size: MAX_RELAY_WS_WRITE_BUFFER_BYTES,
            max_message_size: Some(MAX_RELAY_FRAME_BYTES),
            max_frame_size: Some(MAX_RELAY_FRAME_BYTES),
            ..WebSocketConfig::default()
        };
        let result = tokio::time::timeout(
            self.connect_timeout,
            tokio_tungstenite::connect_async_tls_with_config(
                request,
                Some(websocket_config),
                false,
                Some(connector),
            ),
        )
        .await
        .map_err(|_| RelayTransportError::DeadlineExpired)?;
        let (socket, _) = result.map_err(map_websocket_error)?;
        let (sink, stream) = socket.split();
        Ok(Arc::new(RelayWebSocketSocket {
            sink: Mutex::new(sink),
            stream: Mutex::new(stream),
        }))
    }
}

fn install_rustls_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn tls_connector(
    ca_pem: Option<&[u8]>,
) -> Result<tokio_tungstenite::Connector, RelayTransportError> {
    use rustls_pki_types::{CertificateDer, pem::PemObject};

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(pem) = ca_pem {
        for cert in CertificateDer::pem_slice_iter(pem) {
            roots
                .add(cert.map_err(|_| RelayTransportError::InvalidConfiguration)?)
                .map_err(|_| RelayTransportError::InvalidConfiguration)?;
        }
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(tokio_tungstenite::Connector::Rustls(Arc::new(config)))
}

fn map_websocket_error(error: tokio_tungstenite::tungstenite::Error) -> RelayTransportError {
    match error {
        tokio_tungstenite::tungstenite::Error::Http(response)
            if matches!(response.status().as_u16(), 401 | 403) =>
        {
            RelayTransportError::AuthenticationFailed
        }
        _ => RelayTransportError::Unavailable,
    }
}

/// Session phase, including the bootstrap-to-enrolled transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelaySessionPhase {
    /// One-time IKpsk2 bootstrap is not yet committed.
    Bootstrap,
    /// Core persisted enrollment before opening KK.
    EnrollmentCommitted,
    /// Enrolled KK session is active.
    EnrolledKk,
    /// Session closed.
    Closed,
}

/// Evidence produced by an authenticated enrollment handshake.
#[derive(PartialEq, Eq)]
pub struct RelayEnrollmentProof {
    transcript_digest: [u8; 32],
    challenge: [u8; 32],
}

impl fmt::Debug for RelayEnrollmentProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RelayEnrollmentProof(<redacted>)")
    }
}

/// Verifies the authenticated enrollment transcript.
pub trait RelayEnrollmentVerifier: Send + Sync {
    /// Verify the transcript and bind it to this connection challenge.
    fn verify_enrollment(&self, transcript: &[u8], challenge: &RelayEnrollmentChallenge) -> bool;
}

impl RelayEnrollmentProof {
    /// Verify an enrollment transcript and mint a proof bound to one
    /// connection challenge.
    pub fn authenticate<V: RelayEnrollmentVerifier>(
        verifier: &V,
        transcript: &[u8],
        challenge: &RelayEnrollmentChallenge,
    ) -> Result<Self, RelayTransportError> {
        if transcript.is_empty() || !verifier.verify_enrollment(transcript, challenge) {
            return Err(RelayTransportError::AuthenticationFailed);
        }
        Ok(Self {
            transcript_digest: Sha256::digest(transcript).into(),
            challenge: challenge.0,
        })
    }
}

/// Per-connection challenge used to bind one authenticated enrollment proof.
#[derive(Clone, PartialEq, Eq)]
pub struct RelayEnrollmentChallenge([u8; 32]);

impl fmt::Debug for RelayEnrollmentChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RelayEnrollmentChallenge(<redacted>)")
    }
}

impl RelayEnrollmentChallenge {
    /// Construct a challenge at an effect boundary.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the challenge for transcript binding at the authentication
    /// boundary.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

static NEXT_CONNECTION_CHALLENGE: AtomicU64 = AtomicU64::new(1);

fn next_connection_challenge() -> RelayEnrollmentChallenge {
    let counter = NEXT_CONNECTION_CHALLENGE.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let mut digest = Sha256::new();
    digest.update(counter.to_be_bytes());
    digest.update(now.to_be_bytes());
    RelayEnrollmentChallenge(digest.finalize().into())
}

impl RelaySessionPhase {
    /// Accept the one-time enrollment transition using authenticated proof.
    pub fn establish_enrolled_kk(
        self,
        proof: RelayEnrollmentProof,
        offered_bootstrap_continuation: bool,
    ) -> Result<Self, RelayTransportError> {
        let _ = proof.transcript_digest;
        match self {
            Self::Bootstrap => Err(RelayTransportError::InvalidSessionTransition),
            Self::EnrollmentCommitted if offered_bootstrap_continuation => {
                Err(RelayTransportError::InvalidSessionTransition)
            }
            Self::EnrollmentCommitted => Ok(Self::EnrolledKk),
            Self::EnrolledKk => Err(RelayTransportError::InvalidSessionTransition),
            Self::Closed => Err(RelayTransportError::InvalidSessionTransition),
        }
    }
}

/// A relay-authenticated peer carries no local d2b authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayAuthenticatedPeer;

impl RelayAuthenticatedPeer {
    /// Relay evidence never grants local Admin.
    pub const fn local_admin(self) -> bool {
        false
    }
}

#[derive(Default)]
struct RelayGenerationFence {
    states: StdMutex<HashMap<(String, String, String), RelayGenerationState>>,
}

#[derive(Default)]
struct RelayGenerationState {
    committed: Option<u64>,
    in_flight: HashMap<u64, usize>,
    active: HashMap<u64, usize>,
}

type RelayGenerationStates = HashMap<(String, String, String), RelayGenerationState>;

struct RelayGenerationAttempt {
    fence: Arc<RelayGenerationFence>,
    key: (String, String, String),
    generation: u64,
    live: bool,
}

struct RelayGenerationLease {
    fence: Arc<RelayGenerationFence>,
    key: (String, String, String),
    generation: u64,
    live: bool,
}

impl RelayGenerationFence {
    fn lock_states(&self) -> StdMutexGuard<'_, RelayGenerationStates> {
        match self.states.lock() {
            Ok(states) => states,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn begin(
        self: &Arc<Self>,
        binding: &RelayCredentialBinding,
    ) -> Result<RelayGenerationAttempt, RelayTransportError> {
        let key = generation_key(binding);
        let generation = binding.reconnect_generation();
        let mut states = self.lock_states();
        let state = match states.get_mut(&key) {
            Some(state) => state,
            None => {
                if states.len() >= MAX_RELAY_GENERATION_FENCES {
                    return Err(RelayTransportError::Unavailable);
                }
                states.insert(key.clone(), RelayGenerationState::default());
                states.get_mut(&key).expect("inserted generation state")
            }
        };
        if state.committed.is_some_and(|current| current > generation) {
            return Err(RelayTransportError::StaleGeneration);
        }
        if state
            .in_flight
            .get(&generation)
            .is_some_and(|count| *count > 0)
            || state
                .active
                .get(&generation)
                .is_some_and(|count| *count > 0)
        {
            return Err(RelayTransportError::DuplicateTransport);
        }
        *state.in_flight.entry(generation).or_default() += 1;
        Ok(RelayGenerationAttempt {
            fence: Arc::clone(self),
            key,
            generation,
            live: true,
        })
    }

    fn commit(
        &self,
        key: &(String, String, String),
        generation: u64,
    ) -> Result<(), RelayTransportError> {
        let mut states = self.lock_states();
        let Some(state) = states.get_mut(key) else {
            return Err(RelayTransportError::StaleGeneration);
        };
        decrement_count(&mut state.in_flight, generation);
        if state.committed.is_some_and(|current| current > generation) {
            remove_empty_state(&mut states, key);
            return Err(RelayTransportError::StaleGeneration);
        }
        state.committed = Some(state.committed.unwrap_or(0).max(generation));
        *state.active.entry(generation).or_default() += 1;
        Ok(())
    }

    fn abort(&self, key: &(String, String, String), generation: u64) {
        let mut states = self.lock_states();
        if let Some(state) = states.get_mut(key) {
            decrement_count(&mut state.in_flight, generation);
        }
        remove_empty_state(&mut states, key);
    }

    fn release(&self, key: &(String, String, String), generation: u64) {
        let mut states = self.lock_states();
        if let Some(state) = states.get_mut(key) {
            decrement_count(&mut state.active, generation);
        }
        remove_empty_state(&mut states, key);
    }

    fn is_current(&self, binding: &RelayCredentialBinding) -> bool {
        let key = generation_key(binding);
        let states = self.lock_states();
        let Some(state) = states.get(&key) else {
            return false;
        };
        state.committed == Some(binding.reconnect_generation())
            && state
                .active
                .get(&binding.reconnect_generation())
                .is_some_and(|count| *count > 0)
    }

    fn is_attempt_eligible(&self, key: &(String, String, String), generation: u64) -> bool {
        let states = self.lock_states();
        let Some(state) = states.get(key) else {
            return false;
        };
        !state.committed.is_some_and(|current| current > generation)
            && state
                .in_flight
                .get(&generation)
                .is_some_and(|count| *count > 0)
    }
}

impl RelayGenerationAttempt {
    fn eligible(&self) -> bool {
        self.live && self.fence.is_attempt_eligible(&self.key, self.generation)
    }

    fn commit(mut self) -> Result<RelayGenerationLease, RelayTransportError> {
        let result = self.fence.commit(&self.key, self.generation);
        self.live = false;
        result?;
        Ok(RelayGenerationLease {
            fence: Arc::clone(&self.fence),
            key: self.key.clone(),
            generation: self.generation,
            live: true,
        })
    }
}

impl Drop for RelayGenerationAttempt {
    fn drop(&mut self) {
        if self.live {
            self.fence.abort(&self.key, self.generation);
            self.live = false;
        }
    }
}

impl RelayGenerationLease {
    fn release(&mut self) {
        if self.live {
            self.fence.release(&self.key, self.generation);
            self.live = false;
        }
    }
}

impl Drop for RelayGenerationLease {
    fn drop(&mut self) {
        self.release();
    }
}

fn decrement_count(counts: &mut HashMap<u64, usize>, generation: u64) {
    if let Some(count) = counts.get_mut(&generation) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            counts.remove(&generation);
        }
    }
}

fn generation_key(binding: &RelayCredentialBinding) -> (String, String, String) {
    (
        binding
            .zone()
            .map_or_else(|| "<unscoped>".to_owned(), |zone| zone.as_str().to_owned()),
        binding.zone_link_uid().to_owned(),
        binding.session_id().to_owned(),
    )
}

fn remove_empty_state(
    states: &mut HashMap<(String, String, String), RelayGenerationState>,
    key: &(String, String, String),
) {
    let remove = states
        .get(key)
        .is_some_and(|state| state.in_flight.is_empty() && state.active.is_empty());
    if remove {
        states.remove(key);
    }
}

/// One open relay connection with bounded named-stream credits.
pub struct RelayConnection {
    socket: Arc<dyn RelaySocket>,
    credits: Mutex<CreditWindow>,
    write_lock: Mutex<()>,
    phase: Mutex<RelaySessionPhase>,
    challenge: RelayEnrollmentChallenge,
    binding: RelayCredentialBinding,
    generation_fence: Arc<RelayGenerationFence>,
    generation_lease: StdMutex<Option<RelayGenerationLease>>,
    session_permit: Mutex<Option<OwnedSemaphorePermit>>,
}

impl RelayConnection {
    /// Construct a connection whose enrollment was durably committed by Core.
    fn from_committed_socket(
        socket: Arc<dyn RelaySocket>,
        credit_bytes: usize,
        session_permit: OwnedSemaphorePermit,
        binding: RelayCredentialBinding,
        generation_fence: Arc<RelayGenerationFence>,
        generation_lease: RelayGenerationLease,
    ) -> Result<Self, RelayTransportError> {
        let credits =
            CreditWindow::new(credit_bytes).map_err(|_| RelayTransportError::CreditExhausted)?;
        Ok(Self {
            socket,
            credits: Mutex::new(credits),
            write_lock: Mutex::new(()),
            phase: Mutex::new(RelaySessionPhase::EnrollmentCommitted),
            challenge: next_connection_challenge(),
            binding,
            generation_fence,
            generation_lease: StdMutex::new(Some(generation_lease)),
            session_permit: Mutex::new(Some(session_permit)),
        })
    }

    fn release_generation_lease(&self) {
        let lease = match self.generation_lease.lock() {
            Ok(mut lease) => lease.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        drop(lease);
    }

    async fn reject_stale_generation(&self) -> RelayTransportError {
        *self.phase.lock().await = RelaySessionPhase::Closed;
        self.session_permit.lock().await.take();
        self.release_generation_lease();
        let _ = self.socket.close().await;
        RelayTransportError::StaleGeneration
    }

    async fn ensure_current_generation(&self) -> Result<(), RelayTransportError> {
        if self.generation_fence.is_current(&self.binding) {
            Ok(())
        } else {
            Err(self.reject_stale_generation().await)
        }
    }

    /// Return the challenge that must be included in the authenticated proof.
    pub fn enrollment_challenge(&self) -> RelayEnrollmentChallenge {
        self.challenge.clone()
    }

    /// Return the exact ZoneLink/session/generation binding.
    pub const fn binding(&self) -> &RelayCredentialBinding {
        &self.binding
    }

    /// Return the reconnect generation for this connection.
    pub const fn reconnect_generation(&self) -> u64 {
        self.binding.reconnect_generation()
    }

    /// Commit authenticated enrollment before any application frame is sent.
    pub async fn enroll(&self, proof: RelayEnrollmentProof) -> Result<(), RelayTransportError> {
        self.ensure_current_generation().await?;
        let mut phase = self.phase.lock().await;
        if proof.challenge != self.challenge.0 {
            return Err(RelayTransportError::AuthenticationFailed);
        }
        *phase = (*phase).establish_enrolled_kk(proof, false)?;
        Ok(())
    }

    /// Send one frame only when credits are available.
    pub async fn send(&self, frame: RelayFrame) -> Result<(), RelayTransportError> {
        self.ensure_current_generation().await?;
        if self.phase().await != RelaySessionPhase::EnrolledKk {
            return Err(RelayTransportError::InvalidSessionTransition);
        }
        let _write_guard = self.write_lock.lock().await;
        self.ensure_current_generation().await?;
        if self.phase().await != RelaySessionPhase::EnrolledKk {
            return Err(RelayTransportError::InvalidSessionTransition);
        }
        let size = frame.as_bytes().len();
        {
            let mut credits = self.credits.lock().await;
            credits.reserve(size).map_err(|error| match error {
                BackpressureError::FrameTooLarge => RelayTransportError::FrameTooLarge,
                BackpressureError::CreditExhausted => RelayTransportError::CreditExhausted,
            })?;
        }
        let result = self.socket.send(frame).await;
        if result.is_err() {
            self.credits.lock().await.rollback(size);
            *self.phase.lock().await = RelaySessionPhase::Closed;
            self.session_permit.lock().await.take();
            self.release_generation_lease();
            let _ = self.socket.close().await;
        }
        result
    }

    /// Receive one frame.
    pub async fn receive(&self) -> Result<Option<RelayFrame>, RelayTransportError> {
        self.ensure_current_generation().await?;
        if self.phase().await != RelaySessionPhase::EnrolledKk {
            return Err(RelayTransportError::InvalidSessionTransition);
        }
        let result = self.socket.receive().await;
        if result.as_ref().is_ok_and(Option::is_none) || result.is_err() {
            *self.phase.lock().await = RelaySessionPhase::Closed;
            self.session_permit.lock().await.take();
            self.release_generation_lease();
            let _ = self.socket.close().await;
        }
        result
    }

    /// Grant credits from the remote named stream.
    pub async fn grant(&self, bytes: usize) {
        self.credits.lock().await.grant(bytes);
    }

    /// Release send credits after a remote acknowledgement.
    pub async fn acknowledge(&self, bytes: usize) {
        self.credits.lock().await.acknowledge(bytes);
    }

    /// Return available and in-flight send credits.
    pub async fn credit_state(&self) -> (usize, usize) {
        let credits = self.credits.lock().await;
        (credits.available(), credits.in_flight())
    }

    /// Close the exact connection.
    pub async fn close(&self) -> Result<(), RelayTransportError> {
        *self.phase.lock().await = RelaySessionPhase::Closed;
        self.session_permit.lock().await.take();
        self.release_generation_lease();
        self.socket.close().await
    }

    /// Return current session phase.
    pub async fn phase(&self) -> RelaySessionPhase {
        *self.phase.lock().await
    }
}

/// An authenticated Relay connection presented as a ComponentSession
/// `OwnedTransport`.
///
/// The Relay Provider carries only protected ComponentSession packets. It
/// never interprets their contents and never permits attachments on the
/// remote carriage.
pub struct RelayComponentSessionTransport {
    connection: Arc<RelayConnection>,
}

impl RelayComponentSessionTransport {
    /// Wrap one connection after its transport-level enrollment has completed.
    pub fn from_connection(connection: RelayConnection) -> Self {
        Self {
            connection: Arc::new(connection),
        }
    }
}

impl fmt::Debug for RelayComponentSessionTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RelayComponentSessionTransport(<redacted>)")
    }
}

struct RelayComponentSessionReader {
    connection: Arc<RelayConnection>,
}

struct RelayComponentSessionWriter {
    connection: Arc<RelayConnection>,
}

fn map_transport_error(error: RelayTransportError) -> TransportError {
    match error {
        RelayTransportError::FrameTooLarge | RelayTransportError::CreditExhausted => {
            TransportError::LimitExceeded
        }
        RelayTransportError::Unavailable
        | RelayTransportError::AuthenticationFailed
        | RelayTransportError::CredentialUnavailable
        | RelayTransportError::CredentialRoleMismatch
        | RelayTransportError::CredentialExpired
        | RelayTransportError::CredentialBindingMismatch
        | RelayTransportError::CredentialInvalid
        | RelayTransportError::Protocol
        | RelayTransportError::InvalidSessionTransition
        | RelayTransportError::DeadlineExpired
        | RelayTransportError::StaleGeneration
        | RelayTransportError::UnknownTransportHandle
        | RelayTransportError::DuplicateTransport => TransportError::Disconnected,
        RelayTransportError::InvalidConfiguration => TransportError::Other,
    }
}

#[async_trait]
impl TransportReader for RelayComponentSessionReader {
    async fn receive(
        &mut self,
        _protected_limit: usize,
    ) -> Result<TransportPacket, TransportError> {
        match self.connection.receive().await {
            Ok(Some(frame)) => Ok(TransportPacket::new(frame.into_bytes())),
            Ok(None) => Err(TransportError::Disconnected),
            Err(error) => Err(map_transport_error(error)),
        }
    }
}

#[async_trait]
impl TransportWriter for RelayComponentSessionWriter {
    async fn send(&mut self, packet: TransportPacket) -> Result<(), TransportError> {
        let (bytes, attachments) = packet.into_parts();
        if !attachments.is_empty() {
            for attachment in attachments {
                attachment.close();
            }
            return Err(TransportError::InvalidAttachment);
        }
        let frame = RelayFrame::new(bytes).map_err(map_transport_error)?;
        self.connection
            .send(frame)
            .await
            .map_err(map_transport_error)
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        self.connection.close().await.map_err(map_transport_error)
    }
}

#[async_trait]
impl OwnedTransport for RelayComponentSessionTransport {
    fn descriptor(&self) -> TransportDescriptor {
        TransportDescriptor {
            class:
                d2b_contracts_zone_session::v3::component_session::TransportClass::ProviderStream,
            locality: d2b_contracts_zone_session::v3::component_session::Locality::Remote,
            packet_atomic: false,
            supports_attachments: false,
        }
    }

    fn into_split(self: Box<Self>) -> (Box<dyn TransportReader>, Box<dyn TransportWriter>) {
        (
            Box::new(RelayComponentSessionReader {
                connection: Arc::clone(&self.connection),
            }),
            Box::new(RelayComponentSessionWriter {
                connection: Arc::clone(&self.connection),
            }),
        )
    }

    async fn receive(
        &mut self,
        _protected_limit: usize,
    ) -> Result<TransportPacket, TransportError> {
        match self.connection.receive().await {
            Ok(Some(frame)) => Ok(TransportPacket::new(frame.into_bytes())),
            Ok(None) => Err(TransportError::Disconnected),
            Err(error) => Err(map_transport_error(error)),
        }
    }

    async fn send(&mut self, packet: TransportPacket) -> Result<(), TransportError> {
        let (bytes, attachments) = packet.into_parts();
        if !attachments.is_empty() {
            for attachment in attachments {
                attachment.close();
            }
            return Err(TransportError::InvalidAttachment);
        }
        self.connection
            .send(RelayFrame::new(bytes).map_err(map_transport_error)?)
            .await
            .map_err(map_transport_error)
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        self.connection.close().await.map_err(map_transport_error)
    }
}

/// Stable transport errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayTransportError {
    /// Provider config or settings were invalid.
    InvalidConfiguration,
    /// Credentials were unavailable.
    CredentialUnavailable,
    /// The credential lease was issued for the wrong relay role.
    CredentialRoleMismatch,
    /// The credential lease was already expired.
    CredentialExpired,
    /// The lease was not bound to this exact ZoneLink/session/generation.
    CredentialBindingMismatch,
    /// Credential material or metadata was invalid.
    CredentialInvalid,
    /// Authentication failed.
    AuthenticationFailed,
    /// Endpoint was not ready.
    Unavailable,
    /// A frame exceeded the fixed bound.
    FrameTooLarge,
    /// Credits were exhausted.
    CreditExhausted,
    /// The wire protocol was malformed.
    Protocol,
    /// The session transition was invalid.
    InvalidSessionTransition,
    /// The operation deadline elapsed.
    DeadlineExpired,
    /// A newer reconnect generation superseded this connection.
    StaleGeneration,
    /// A transport handle was not owned by this service.
    UnknownTransportHandle,
    /// A carriage already exists for the exact binding.
    DuplicateTransport,
}

impl fmt::Display for RelayTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "relay-invalid-configuration",
            Self::CredentialUnavailable => "relay-credential-unavailable",
            Self::CredentialRoleMismatch => "relay-credential-role-mismatch",
            Self::CredentialExpired => "relay-credential-expired",
            Self::CredentialBindingMismatch => "relay-credential-binding-mismatch",
            Self::CredentialInvalid => "relay-credential-invalid",
            Self::AuthenticationFailed => "relay-authentication-failed",
            Self::Unavailable => "relay-unavailable",
            Self::FrameTooLarge => "relay-frame-too-large",
            Self::CreditExhausted => "relay-credit-exhausted",
            Self::Protocol => "relay-protocol",
            Self::InvalidSessionTransition => "relay-invalid-session-transition",
            Self::DeadlineExpired => "relay-deadline-expired",
            Self::StaleGeneration => "relay-stale-generation",
            Self::UnknownTransportHandle => "relay-unknown-transport-handle",
            Self::DuplicateTransport => "relay-duplicate-transport",
        })
    }
}

impl std::error::Error for RelayTransportError {}

fn map_credential_error(error: crate::RelayCredentialError) -> RelayTransportError {
    match error {
        crate::RelayCredentialError::Unavailable => RelayTransportError::CredentialUnavailable,
        crate::RelayCredentialError::Expired => RelayTransportError::CredentialExpired,
        crate::RelayCredentialError::RoleMismatch => RelayTransportError::CredentialRoleMismatch,
        crate::RelayCredentialError::InvalidBinding
        | crate::RelayCredentialError::BindingRequired
        | crate::RelayCredentialError::AlreadyBound
        | crate::RelayCredentialError::BindingMismatch
        | crate::RelayCredentialError::InvalidScope => {
            RelayTransportError::CredentialBindingMismatch
        }
        crate::RelayCredentialError::InvalidSecret | crate::RelayCredentialError::UnknownLease => {
            RelayTransportError::CredentialInvalid
        }
    }
}

enum RetryResult {
    Retry(Duration),
    Return(RelayTransportError),
}

const CREDENTIAL_REVOKE_CLEANUP_TIMEOUT: Duration = Duration::from_millis(250);

struct CredentialLeaseGuard<C: ScopedCredentialClient + 'static> {
    credentials: Arc<C>,
    lease: Option<RelayCredentialLease>,
}

impl<C> CredentialLeaseGuard<C>
where
    C: ScopedCredentialClient + 'static,
{
    fn new(credentials: Arc<C>, lease: RelayCredentialLease) -> Self {
        Self {
            credentials,
            lease: Some(lease),
        }
    }

    fn lease(&self) -> &RelayCredentialLease {
        self.lease
            .as_ref()
            .expect("credential lease guard must own a lease")
    }

    async fn revoke(&mut self, deadline: Instant) -> Result<(), RelayTransportError> {
        let Some(lease) = self.lease.take() else {
            return Ok(());
        };
        let Some(task) = spawn_bounded_revoke(Arc::clone(&self.credentials), lease) else {
            return Err(RelayTransportError::CredentialUnavailable);
        };
        match timeout_at(deadline, task).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(_))) | Ok(Err(_)) => Err(RelayTransportError::CredentialUnavailable),
            Err(_) => Err(RelayTransportError::DeadlineExpired),
        }
    }
}

impl<C> Drop for CredentialLeaseGuard<C>
where
    C: ScopedCredentialClient + 'static,
{
    fn drop(&mut self) {
        if let Some(lease) = self.lease.take() {
            let _ = spawn_bounded_revoke(Arc::clone(&self.credentials), lease);
        }
    }
}

fn spawn_bounded_revoke<C>(
    credentials: Arc<C>,
    lease: RelayCredentialLease,
) -> Option<tokio::task::JoinHandle<Result<(), crate::RelayCredentialError>>>
where
    C: ScopedCredentialClient + 'static,
{
    let handle = tokio::runtime::Handle::try_current().ok()?;
    Some(handle.spawn(async move {
        match tokio::time::timeout(
            CREDENTIAL_REVOKE_CLEANUP_TIMEOUT,
            credentials.revoke_credential(lease),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(crate::RelayCredentialError::Unavailable),
        }
    }))
}

fn retry_or_close(
    backoff: &mut ReconnectBackoff,
    remaining: Duration,
    error: RelayTransportError,
) -> RetryResult {
    match backoff.failed() {
        ReconnectDecision::RetryAfter(delay)
            if Duration::from_millis(u64::from(delay)) <= remaining =>
        {
            RetryResult::Retry(Duration::from_millis(u64::from(delay)))
        }
        ReconnectDecision::RetryAfter(_) | ReconnectDecision::Closed => RetryResult::Return(error),
        ReconnectDecision::OpenNow => RetryResult::Retry(Duration::ZERO),
    }
}

fn revoke_or(
    original: RelayTransportError,
    revoke: Result<(), RelayTransportError>,
) -> RelayTransportError {
    revoke.err().unwrap_or(original)
}

/// Canonical Azure Relay Provider.
pub struct AzureRelayTransportProvider<C, K> {
    config: RelayTransportConfig,
    endpoint: RelayEndpoint,
    credentials: Arc<C>,
    connector: Arc<K>,
    session_slots: Arc<Semaphore>,
    generation_fence: Arc<RelayGenerationFence>,
}

impl<C, K> AzureRelayTransportProvider<C, K>
where
    C: ScopedCredentialClient + 'static,
    K: RelaySocketConnector + 'static,
{
    /// Construct a Provider with gateway-local effect ports.
    pub fn new(
        config: RelayTransportConfig,
        endpoint: RelayEndpoint,
        credentials: Arc<C>,
        connector: Arc<K>,
    ) -> Result<Self, RelayTransportError> {
        config.validate()?;
        endpoint
            .settings
            .validate()
            .map_err(|_| RelayTransportError::InvalidConfiguration)?;
        let max_concurrent_sessions = config.max_concurrent_sessions as usize;
        Ok(Self {
            config,
            endpoint,
            credentials,
            connector,
            session_slots: Arc::new(Semaphore::new(max_concurrent_sessions)),
            generation_fence: Arc::new(RelayGenerationFence::default()),
        })
    }

    /// Open a connection through the narrow same-Zone Credential boundary.
    ///
    /// The request is the only place where the transport sees a Credential
    /// reference. U10 supplies the scoped ResourceClient/session gate without
    /// changing transport ownership or scheduling.
    pub async fn open_scoped(
        &self,
        request: ScopedCredentialRequest,
    ) -> Result<RelayConnection, RelayTransportError> {
        self.open_scoped_with_backoff(request, ReconnectBackoff::with_limits(0, 0, 0, 0))
            .await
    }

    /// Open a scoped connection with bounded carriage-attempt retries.
    pub async fn open_scoped_with_backoff(
        &self,
        request: ScopedCredentialRequest,
        backoff: ReconnectBackoff,
    ) -> Result<RelayConnection, RelayTransportError> {
        self.open_inner(request, backoff).await
    }

    async fn open_inner(
        &self,
        request: ScopedCredentialRequest,
        mut backoff: ReconnectBackoff,
    ) -> Result<RelayConnection, RelayTransportError> {
        let role = relay_role(request.role());
        let binding = request.binding().clone();
        let deadline_ms = request.deadline_ms();
        if deadline_ms == 0 {
            return Err(RelayTransportError::DeadlineExpired);
        }
        if request.execution_ref() != &self.config.execution_ref {
            return Err(RelayTransportError::CredentialBindingMismatch);
        }
        let generation_attempt = self.generation_fence.begin(&binding)?;
        let deadline = Instant::now() + Duration::from_millis(u64::from(deadline_ms));
        let session_permit = timeout_at(deadline, self.session_slots.clone().acquire_owned())
            .await
            .map_err(|_| RelayTransportError::DeadlineExpired)?
            .map_err(|_| RelayTransportError::Unavailable)?;
        let credential_role = credential_role(role);
        loop {
            if !generation_attempt.eligible() {
                return Err(RelayTransportError::StaleGeneration);
            }
            let remaining_ms = deadline
                .saturating_duration_since(Instant::now())
                .as_millis()
                .min(u128::from(u32::MAX)) as u32;
            if remaining_ms == 0 {
                return Err(RelayTransportError::DeadlineExpired);
            }
            let request = request
                .with_deadline(remaining_ms)
                .map_err(map_credential_error)?;
            let lease = match timeout_at(deadline, self.credentials.read_credential(&request)).await
            {
                Err(_) => return Err(RelayTransportError::DeadlineExpired),
                Ok(Ok(lease)) => lease,
                Ok(Err(error)) => {
                    let mapped = map_credential_error(error);
                    if !matches!(mapped, RelayTransportError::CredentialUnavailable) {
                        return Err(mapped);
                    }
                    match retry_or_close(
                        &mut backoff,
                        deadline.saturating_duration_since(Instant::now()),
                        mapped,
                    ) {
                        RetryResult::Retry(delay) => {
                            timeout_at(deadline, sleep(delay))
                                .await
                                .map_err(|_| RelayTransportError::DeadlineExpired)?;
                            continue;
                        }
                        RetryResult::Return(error) => return Err(error),
                    }
                }
            };
            let mut lease_guard = CredentialLeaseGuard::new(Arc::clone(&self.credentials), lease);
            let now_unix_ms = match SystemTime::now().duration_since(UNIX_EPOCH) {
                Ok(duration) => duration.as_millis() as u64,
                Err(_) => {
                    return Err(revoke_or(
                        RelayTransportError::CredentialExpired,
                        lease_guard.revoke(deadline).await,
                    ));
                }
            };
            let required_binding = lease_guard.lease().binding() == Some(&binding);
            let role_matches = lease_guard.lease().role() == credential_role;
            let lifetime_satisfies_deadline = lease_guard.lease().expires_at_unix_ms()
                > now_unix_ms.saturating_add(u64::from(remaining_ms));
            if !required_binding || !role_matches || !lifetime_satisfies_deadline {
                let reason = if !required_binding {
                    RelayTransportError::CredentialBindingMismatch
                } else if !role_matches {
                    RelayTransportError::CredentialRoleMismatch
                } else {
                    RelayTransportError::CredentialExpired
                };
                return Err(revoke_or(reason, lease_guard.revoke(deadline).await));
            }

            let connect_deadline = std::cmp::min(
                deadline,
                Instant::now()
                    + Duration::from_secs(u64::from(self.config.connect_timeout_seconds)),
            );
            let socket_result = match timeout_at(
                connect_deadline,
                self.connector
                    .connect(&self.endpoint, role, lease_guard.lease()),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => Err(RelayTransportError::DeadlineExpired),
            };
            let revoke_result = lease_guard.revoke(deadline).await;
            let socket = match socket_result {
                Ok(socket) => socket,
                Err(error) => {
                    revoke_result?;
                    if !matches!(error, RelayTransportError::Unavailable) {
                        return Err(error);
                    }
                    match retry_or_close(
                        &mut backoff,
                        deadline.saturating_duration_since(Instant::now()),
                        RelayTransportError::Unavailable,
                    ) {
                        RetryResult::Retry(delay) => {
                            timeout_at(deadline, sleep(delay))
                                .await
                                .map_err(|_| RelayTransportError::DeadlineExpired)?;
                            continue;
                        }
                        RetryResult::Return(error) => return Err(error),
                    }
                }
            };
            if let Err(error) = revoke_result {
                let _ = socket.close().await;
                return Err(error);
            }
            let generation_lease = match generation_attempt.commit() {
                Ok(lease) => lease,
                Err(error) => {
                    let _ = socket.close().await;
                    return Err(error);
                }
            };
            return RelayConnection::from_committed_socket(
                socket,
                256 * 1024,
                session_permit,
                binding,
                Arc::clone(&self.generation_fence),
                generation_lease,
            );
        }
    }

    /// Return the gateway execution boundary.
    pub const fn config(&self) -> &RelayTransportConfig {
        &self.config
    }
}

fn credential_role(role: RelayRole) -> RelayCredentialRole {
    match role {
        RelayRole::Listener => RelayCredentialRole::Listen,
        RelayRole::Sender => RelayCredentialRole::Send,
    }
}

fn relay_role(role: RelayCredentialRole) -> RelayRole {
    match role {
        RelayCredentialRole::Listen => RelayRole::Listener,
        RelayCredentialRole::Send => RelayRole::Sender,
    }
}

/// Opaque handle for one relay carriage owned by a transport service.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RelayTransportHandle(u64);

impl RelayTransportHandle {
    /// Construct a handle at the trusted Core boundary.
    pub const fn from_core(value: u64) -> Self {
        Self(value)
    }
}

impl fmt::Debug for RelayTransportHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RelayTransportHandle(<redacted>)")
    }
}

/// Typed response for one relay carriage open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayOpenTransportResponse {
    /// Opaque handle used by close and observe.
    pub transport_handle: RelayTransportHandle,
    /// Remote carriage descriptor.
    pub descriptor: TransportDescriptor,
}

/// Typed observation for one relay carriage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayTransportObservation {
    /// Current Core-selected session phase.
    pub phase: RelaySessionPhase,
    /// Current available send credit.
    pub available_credits: usize,
    /// Current in-flight send credit.
    pub in_flight_credits: usize,
    /// Core-owned reconnect generation.
    pub reconnect_generation: u64,
}

fn relay_transport_descriptor() -> TransportDescriptor {
    TransportDescriptor {
        class: d2b_contracts_zone_session::v3::component_session::TransportClass::ProviderStream,
        locality: d2b_contracts_zone_session::v3::component_session::Locality::Remote,
        packet_atomic: false,
        supports_attachments: false,
    }
}

impl RelayConnection {
    /// Return the bounded, identity-free carriage observation.
    pub async fn observe_transport(&self) -> RelayTransportObservation {
        let (available_credits, in_flight_credits) = self.credit_state().await;
        RelayTransportObservation {
            phase: self.phase().await,
            available_credits,
            in_flight_credits,
            reconnect_generation: self.reconnect_generation(),
        }
    }
}

/// Typed transport-only service façade.
///
/// The service owns only high-churn carriage handles. It does not watch or
/// reconcile ZoneLink resources; Core supplies the scoped request and decides
/// reconnect timing.
pub struct RelayTransportService<C, K> {
    provider: AzureRelayTransportProvider<C, K>,
    active: Mutex<HashMap<RelayTransportHandle, RelayConnection>>,
    completed: Mutex<HashMap<RelayTransportHandle, RelayTransportObservation>>,
    open_lock: Mutex<()>,
    next_handle: AtomicU64,
}

impl<C, K> RelayTransportService<C, K>
where
    C: ScopedCredentialClient + 'static,
    K: RelaySocketConnector + 'static,
{
    /// Construct one service over one transport Provider instance.
    pub fn new(provider: AzureRelayTransportProvider<C, K>) -> Self {
        Self {
            provider,
            active: Mutex::new(HashMap::new()),
            completed: Mutex::new(HashMap::new()),
            open_lock: Mutex::new(()),
            next_handle: AtomicU64::new(1),
        }
    }

    /// Open one scoped carriage supplied by Core.
    pub async fn open_transport(
        &self,
        request: ScopedCredentialRequest,
        backoff: ReconnectBackoff,
    ) -> Result<RelayOpenTransportResponse, RelayTransportError> {
        let _open_guard = self.open_lock.lock().await;
        if self
            .active
            .lock()
            .await
            .values()
            .any(|connection| connection.binding() == request.binding())
        {
            return Err(RelayTransportError::DuplicateTransport);
        }
        let connection = self
            .provider
            .open_scoped_with_backoff(request, backoff)
            .await?;
        let handle =
            RelayTransportHandle::from_core(self.next_handle.fetch_add(1, Ordering::Relaxed));
        self.active.lock().await.insert(handle, connection);
        Ok(RelayOpenTransportResponse {
            transport_handle: handle,
            descriptor: relay_transport_descriptor(),
        })
    }

    /// Close one carriage. Repeating a successful close is idempotent.
    pub async fn close_transport(
        &self,
        handle: RelayTransportHandle,
    ) -> Result<(), RelayTransportError> {
        let connection = self.active.lock().await.remove(&handle);
        let Some(connection) = connection else {
            return if self.completed.lock().await.contains_key(&handle) {
                Ok(())
            } else {
                Err(RelayTransportError::UnknownTransportHandle)
            };
        };
        let result = connection.close().await;
        let observation = connection.observe_transport().await;
        let mut completed = self.completed.lock().await;
        if completed.len() >= MAX_COMPLETED_RELAY_TRANSPORTS {
            if let Some(evicted) = completed.keys().next().copied() {
                completed.remove(&evicted);
            }
        }
        completed.insert(handle, observation);
        result
    }

    /// Observe one active or completed carriage.
    pub async fn observe_transport(
        &self,
        handle: RelayTransportHandle,
    ) -> Result<RelayTransportObservation, RelayTransportError> {
        if let Some(connection) = self.active.lock().await.get(&handle) {
            return Ok(connection.observe_transport().await);
        }
        self.completed
            .lock()
            .await
            .get(&handle)
            .copied()
            .ok_or(RelayTransportError::UnknownTransportHandle)
    }

    /// Close every carriage owned by this service.
    pub async fn finalize(&self) -> Result<(), RelayTransportError> {
        let handles = self.active.lock().await.keys().copied().collect::<Vec<_>>();
        let mut first_error = None;
        for handle in handles {
            if let Err(error) = self.close_transport(handle).await {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

/// Mint a short-lived SAS token inside the gateway Guest.
pub fn mint_sas(
    resource_uri: &str,
    key_name: &str,
    key: &RelaySecret,
    ttl_secs: u64,
    now_unix_secs: u64,
) -> Result<RelaySecret, RelayTransportError> {
    if ttl_secs == 0 || ttl_secs > 15 * 60 || resource_uri.is_empty() || key_name.is_empty() {
        return Err(RelayTransportError::InvalidConfiguration);
    }
    let expiry = now_unix_secs.saturating_add(ttl_secs);
    let encoded_uri = urlencoding::encode(resource_uri);
    let string_to_sign = format!("{encoded_uri}\n{expiry}");
    let mut mac = HmacSha256::new_from_slice(key.as_bytes())
        .map_err(|_| RelayTransportError::AuthenticationFailed)?;
    mac.update(string_to_sign.as_bytes());
    let signature = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        mac.finalize().into_bytes(),
    );
    RelaySecret::new(format!(
        "SharedAccessSignature sr={encoded_uri}&sig={}&se={expiry}&skn={key_name}",
        urlencoding::encode(&signature)
    ))
    .map_err(|_| RelayTransportError::AuthenticationFailed)
}
