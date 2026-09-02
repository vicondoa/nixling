use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use d2b_contracts::ResourceRef;
use d2b_contracts_resource::v3::ZoneId;
use d2b_provider_transport_azure_relay::{
    AzureRelayTransportProvider, CreditWindow, MAX_RELAY_GENERATION_FENCES, ReconnectBackoff,
    RelayAuthenticatedPeer, RelayComponentSessionTransport, RelayConnection,
    RelayCredentialBinding, RelayCredentialError, RelayCredentialLease, RelayCredentialMaterial,
    RelayCredentialPort, RelayCredentialRole, RelayEndpoint, RelayEnrollmentProof,
    RelayEnrollmentVerifier, RelayFrame, RelayRole, RelaySecret, RelaySocket, RelaySocketConnector,
    RelayTransportConfig, RelayTransportError, RelayTransportService, RelayTransportSettings,
    ScopedCredentialClient, ScopedCredentialRequest,
};
use d2b_session::{OwnedTransport, TransportPacket};
use tokio::sync::Notify;

#[derive(Default)]
struct FakeSocket {
    frames: Mutex<VecDeque<RelayFrame>>,
}

#[async_trait]
impl RelaySocket for FakeSocket {
    async fn send(&self, frame: RelayFrame) -> Result<(), RelayTransportError> {
        self.frames.lock().unwrap().push_back(frame);
        Ok(())
    }

    async fn receive(&self) -> Result<Option<RelayFrame>, RelayTransportError> {
        Ok(self.frames.lock().unwrap().pop_front())
    }

    async fn close(&self) -> Result<(), RelayTransportError> {
        Ok(())
    }
}

struct FakeConnector {
    socket: Arc<FakeSocket>,
}

#[async_trait]
impl RelaySocketConnector for FakeConnector {
    async fn connect(
        &self,
        _: &RelayEndpoint,
        _: RelayRole,
        _: &RelayCredentialLease,
    ) -> Result<Arc<dyn RelaySocket>, RelayTransportError> {
        Ok(Arc::clone(&self.socket) as Arc<dyn RelaySocket>)
    }
}

struct FakeCredentials;

fn valid_expiry() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
        + 60_000
}

struct FakeEnrollment;

impl RelayEnrollmentVerifier for FakeEnrollment {
    fn verify_enrollment(
        &self,
        transcript: &[u8],
        _: &d2b_provider_transport_azure_relay::RelayEnrollmentChallenge,
    ) -> bool {
        transcript == b"authenticated-enrollment"
    }
}

#[async_trait]
impl RelayCredentialPort for FakeCredentials {
    async fn acquire(
        &self,
        role: RelayCredentialRole,
        _: u32,
    ) -> Result<RelayCredentialLease, RelayCredentialError> {
        Ok(RelayCredentialLease::new(
            RelayCredentialMaterial::SasToken(RelaySecret::new(b"token".to_vec()).unwrap()),
            role,
            valid_expiry(),
        ))
    }

    async fn acquire_bound(
        &self,
        role: RelayCredentialRole,
        binding: &RelayCredentialBinding,
        _: u32,
    ) -> Result<RelayCredentialLease, RelayCredentialError> {
        Ok(RelayCredentialLease::new_bound(
            RelayCredentialMaterial::SasToken(RelaySecret::new(b"token".to_vec()).unwrap()),
            role,
            valid_expiry(),
            binding.clone(),
        )
        .unwrap())
    }

    async fn revoke(&self, _: RelayCredentialLease) -> Result<(), RelayCredentialError> {
        Ok(())
    }
}

macro_rules! legacy_scoped_adapter {
    ($credential_type:ty) => {
        #[async_trait]
        impl ScopedCredentialClient for $credential_type {
            async fn read_credential(
                &self,
                request: &ScopedCredentialRequest,
            ) -> Result<RelayCredentialLease, RelayCredentialError> {
                RelayCredentialPort::acquire_bound(
                    self,
                    request.role(),
                    request.binding(),
                    request.deadline_ms(),
                )
                .await
            }

            async fn revoke_credential(
                &self,
                lease: RelayCredentialLease,
            ) -> Result<(), RelayCredentialError> {
                RelayCredentialPort::revoke(self, lease).await
            }
        }
    };
}

legacy_scoped_adapter!(FakeCredentials);

struct ScopedOnlyCredentials {
    calls: Arc<Mutex<usize>>,
}

#[async_trait]
impl RelayCredentialPort for ScopedOnlyCredentials {
    async fn acquire(
        &self,
        _: RelayCredentialRole,
        _: u32,
    ) -> Result<RelayCredentialLease, RelayCredentialError> {
        panic!("transport must not use an unscoped credential read");
    }

    async fn acquire_bound(
        &self,
        _: RelayCredentialRole,
        _: &RelayCredentialBinding,
        _: u32,
    ) -> Result<RelayCredentialLease, RelayCredentialError> {
        panic!("transport must use the scoped ResourceClient boundary");
    }

    async fn revoke(&self, _: RelayCredentialLease) -> Result<(), RelayCredentialError> {
        Ok(())
    }
}

#[async_trait]
impl ScopedCredentialClient for ScopedOnlyCredentials {
    async fn read_credential(
        &self,
        request: &ScopedCredentialRequest,
    ) -> Result<RelayCredentialLease, RelayCredentialError> {
        *self.calls.lock().unwrap() += 1;
        assert_eq!(request.zone(), &ZoneId::parse("work").unwrap());
        assert_eq!(
            request.credential_ref(),
            &ResourceRef::parse("Credential/relay-send").unwrap()
        );
        assert_eq!(
            request.execution_ref(),
            &ResourceRef::parse("Guest/gateway").unwrap()
        );
        Ok(RelayCredentialLease::new_bound(
            RelayCredentialMaterial::SasToken(RelaySecret::new(b"scoped-token").unwrap()),
            request.role(),
            valid_expiry(),
            request.binding().clone(),
        )
        .unwrap())
    }

    async fn revoke_credential(&self, _: RelayCredentialLease) -> Result<(), RelayCredentialError> {
        Ok(())
    }
}

struct RetryConnector {
    attempts: Arc<Mutex<usize>>,
    failures: usize,
    socket: Arc<FakeSocket>,
}

#[async_trait]
impl RelaySocketConnector for RetryConnector {
    async fn connect(
        &self,
        _: &RelayEndpoint,
        _: RelayRole,
        _: &RelayCredentialLease,
    ) -> Result<Arc<dyn RelaySocket>, RelayTransportError> {
        let mut attempts = self.attempts.lock().unwrap();
        *attempts += 1;
        if *attempts <= self.failures {
            return Err(RelayTransportError::Unavailable);
        }
        Ok(Arc::clone(&self.socket) as Arc<dyn RelaySocket>)
    }
}

struct FailGenerationConnector {
    fail_generation: u64,
    socket: Arc<FakeSocket>,
}

#[async_trait]
impl RelaySocketConnector for FailGenerationConnector {
    async fn connect(
        &self,
        _: &RelayEndpoint,
        _: RelayRole,
        lease: &RelayCredentialLease,
    ) -> Result<Arc<dyn RelaySocket>, RelayTransportError> {
        if lease.reconnect_generation() == self.fail_generation {
            return Err(RelayTransportError::Unavailable);
        }
        Ok(Arc::clone(&self.socket) as Arc<dyn RelaySocket>)
    }
}

struct RevokeFails;

#[async_trait]
impl RelayCredentialPort for RevokeFails {
    async fn acquire(
        &self,
        role: RelayCredentialRole,
        _: u32,
    ) -> Result<RelayCredentialLease, RelayCredentialError> {
        Ok(RelayCredentialLease::new(
            RelayCredentialMaterial::SasToken(RelaySecret::new(b"token".to_vec()).unwrap()),
            role,
            valid_expiry(),
        ))
    }

    async fn acquire_bound(
        &self,
        role: RelayCredentialRole,
        binding: &RelayCredentialBinding,
        _: u32,
    ) -> Result<RelayCredentialLease, RelayCredentialError> {
        Ok(RelayCredentialLease::new_bound(
            RelayCredentialMaterial::SasToken(RelaySecret::new(b"token".to_vec()).unwrap()),
            role,
            valid_expiry(),
            binding.clone(),
        )
        .unwrap())
    }

    async fn revoke(&self, _: RelayCredentialLease) -> Result<(), RelayCredentialError> {
        Err(RelayCredentialError::Unavailable)
    }
}

legacy_scoped_adapter!(RevokeFails);

struct TrackingSocket {
    closed: Arc<Mutex<bool>>,
}

#[async_trait]
impl RelaySocket for TrackingSocket {
    async fn send(&self, _: RelayFrame) -> Result<(), RelayTransportError> {
        Ok(())
    }

    async fn receive(&self) -> Result<Option<RelayFrame>, RelayTransportError> {
        Ok(None)
    }

    async fn close(&self) -> Result<(), RelayTransportError> {
        *self.closed.lock().unwrap() = true;
        Ok(())
    }
}

fn provider() -> AzureRelayTransportProvider<FakeCredentials, FakeConnector> {
    AzureRelayTransportProvider::new(
        RelayTransportConfig {
            execution_ref: ResourceRef::parse("Guest/gateway").unwrap(),
            network_ref: ResourceRef::parse("Network/relay").unwrap(),
            max_concurrent_sessions: 4,
            connect_timeout_seconds: 30,
        },
        RelayEndpoint {
            settings: RelayTransportSettings::new("relns-d2b-prod", "hc-d2b-k2").unwrap(),
        },
        Arc::new(FakeCredentials),
        Arc::new(FakeConnector {
            socket: Arc::new(FakeSocket::default()),
        }),
    )
    .unwrap()
}

fn config() -> RelayTransportConfig {
    RelayTransportConfig {
        execution_ref: ResourceRef::parse("Guest/gateway").unwrap(),
        network_ref: ResourceRef::parse("Network/relay").unwrap(),
        max_concurrent_sessions: 4,
        connect_timeout_seconds: 30,
    }
}

fn test_binding() -> RelayCredentialBinding {
    RelayCredentialBinding::new("link-test", "session-test", 1).unwrap()
}

fn scoped_binding(binding: &RelayCredentialBinding) -> RelayCredentialBinding {
    RelayCredentialBinding::new_scoped(
        binding
            .zone()
            .cloned()
            .unwrap_or_else(|| ZoneId::parse("work").unwrap()),
        binding.zone_link_uid(),
        binding.session_id(),
        binding.reconnect_generation(),
    )
    .unwrap()
}

fn scoped_request_for(
    role: RelayRole,
    binding: &RelayCredentialBinding,
    deadline_ms: u32,
) -> ScopedCredentialRequest {
    let credential_role = match role {
        RelayRole::Listener => RelayCredentialRole::Listen,
        RelayRole::Sender => RelayCredentialRole::Send,
    };
    let credential_name = match credential_role {
        RelayCredentialRole::Listen => "relay-listen",
        RelayCredentialRole::Send => "relay-send",
    };
    let zone = binding
        .zone()
        .cloned()
        .unwrap_or_else(|| ZoneId::parse("work").unwrap());
    ScopedCredentialRequest::new(
        zone.clone(),
        ResourceRef::parse(&format!("Credential/{credential_name}")).unwrap(),
        ResourceRef::parse("Guest/gateway").unwrap(),
        credential_role,
        scoped_binding(binding),
        deadline_ms,
    )
    .unwrap()
}

async fn open_for<C, K>(
    provider: &AzureRelayTransportProvider<C, K>,
    role: RelayRole,
    binding: &RelayCredentialBinding,
    deadline_ms: u32,
) -> Result<RelayConnection, RelayTransportError>
where
    C: ScopedCredentialClient + 'static,
    K: RelaySocketConnector + 'static,
{
    provider
        .open_scoped(scoped_request_for(role, binding, deadline_ms))
        .await
}

fn scoped_request(generation: u64) -> ScopedCredentialRequest {
    let zone = ZoneId::parse("work").unwrap();
    ScopedCredentialRequest::new(
        zone.clone(),
        ResourceRef::parse("Credential/relay-send").unwrap(),
        ResourceRef::parse("Guest/gateway").unwrap(),
        RelayCredentialRole::Send,
        RelayCredentialBinding::new_scoped(zone, "link-test", "session-test", generation).unwrap(),
        1_000,
    )
    .unwrap()
}

fn endpoint() -> RelayEndpoint {
    RelayEndpoint {
        settings: RelayTransportSettings::new("relns-d2b-prod", "hc-d2b-k2").unwrap(),
    }
}

#[tokio::test]
async fn scoped_open_uses_only_the_same_zone_guest_credential_boundary() {
    let provider = provider();
    let connection = provider.open_scoped(scoped_request(1)).await.unwrap();
    assert_eq!(
        connection.binding().zone(),
        Some(&ZoneId::parse("work").unwrap())
    );
    assert_eq!(connection.reconnect_generation(), 1);
    connection.close().await.unwrap();
}

#[tokio::test]
async fn scoped_open_dispatches_only_the_scoped_resource_client_method() {
    let calls = Arc::new(Mutex::new(0));
    let provider = AzureRelayTransportProvider::new(
        config(),
        endpoint(),
        Arc::new(ScopedOnlyCredentials {
            calls: Arc::clone(&calls),
        }),
        Arc::new(FakeConnector {
            socket: Arc::new(FakeSocket::default()),
        }),
    )
    .unwrap();
    let connection = provider.open_scoped(scoped_request(1)).await.unwrap();
    assert_eq!(*calls.lock().unwrap(), 1);
    connection.close().await.unwrap();
}

#[test]
fn scoped_credential_requests_reject_host_and_cross_zone_bindings() {
    let zone = ZoneId::parse("work").unwrap();
    let binding =
        RelayCredentialBinding::new_scoped(zone.clone(), "link-test", "session-test", 1).unwrap();
    assert_eq!(
        ScopedCredentialRequest::new(
            zone.clone(),
            ResourceRef::parse("Credential/relay-send").unwrap(),
            ResourceRef::parse("Host/host").unwrap(),
            RelayCredentialRole::Send,
            binding.clone(),
            1_000,
        )
        .unwrap_err(),
        RelayCredentialError::InvalidScope
    );
    assert_eq!(
        ScopedCredentialRequest::new(
            ZoneId::parse("other").unwrap(),
            ResourceRef::parse("Credential/relay-send").unwrap(),
            ResourceRef::parse("Guest/gateway").unwrap(),
            RelayCredentialRole::Send,
            binding,
            1_000,
        )
        .unwrap_err(),
        RelayCredentialError::InvalidScope
    );
}

#[test]
fn relay_provider_configuration_rejects_host_execution_or_non_network_egress() {
    let mut host_config = config();
    host_config.execution_ref = ResourceRef::parse("Host/host").unwrap();
    assert_eq!(
        host_config.validate().unwrap_err(),
        RelayTransportError::InvalidConfiguration
    );

    let mut host_network = config();
    host_network.network_ref = ResourceRef::parse("Host/host").unwrap();
    assert_eq!(
        host_network.validate().unwrap_err(),
        RelayTransportError::InvalidConfiguration
    );
}

#[tokio::test]
async fn typed_relay_handles_reject_duplicate_carriage_and_expose_only_observation() {
    let service = RelayTransportService::new(provider());
    let request = scoped_request(1);
    let opened = service
        .open_transport(request.clone(), ReconnectBackoff::with_limits(0, 0, 0, 0))
        .await
        .unwrap();
    assert_eq!(
        service
            .observe_transport(opened.transport_handle)
            .await
            .unwrap()
            .phase,
        d2b_provider_transport_azure_relay::RelaySessionPhase::EnrollmentCommitted
    );
    assert_eq!(
        service
            .open_transport(request, ReconnectBackoff::with_limits(0, 0, 0, 0))
            .await
            .unwrap_err(),
        RelayTransportError::DuplicateTransport
    );
    service
        .close_transport(opened.transport_handle)
        .await
        .unwrap();
    service
        .close_transport(opened.transport_handle)
        .await
        .unwrap();
    assert_eq!(
        service
            .observe_transport(opened.transport_handle)
            .await
            .unwrap()
            .phase,
        d2b_provider_transport_azure_relay::RelaySessionPhase::Closed
    );
    assert_eq!(
        service
            .observe_transport(
                d2b_provider_transport_azure_relay::RelayTransportHandle::from_core(999),
            )
            .await
            .unwrap_err(),
        RelayTransportError::UnknownTransportHandle
    );
}

#[tokio::test]
async fn relay_reconnect_reopens_only_carriage_for_a_new_generation() {
    let service = RelayTransportService::new(provider());
    let first = service
        .open_transport(scoped_request(1), ReconnectBackoff::with_limits(0, 0, 0, 0))
        .await
        .unwrap();
    service
        .close_transport(first.transport_handle)
        .await
        .unwrap();
    let second = service
        .open_transport(scoped_request(2), ReconnectBackoff::with_limits(0, 0, 0, 0))
        .await
        .unwrap();
    assert_ne!(first.transport_handle, second.transport_handle);
    assert_eq!(
        service
            .observe_transport(second.transport_handle)
            .await
            .unwrap()
            .reconnect_generation,
        2
    );
    service
        .close_transport(second.transport_handle)
        .await
        .unwrap();
}

#[tokio::test]
async fn sender_roundtrip_is_bounded_and_relay_has_no_local_admin() {
    let provider = provider();
    let connection = open_for(&provider, RelayRole::Sender, &test_binding(), 1_000)
        .await
        .unwrap();
    assert_eq!(
        connection.phase().await,
        d2b_provider_transport_azure_relay::RelaySessionPhase::EnrollmentCommitted
    );
    let challenge = connection.enrollment_challenge();
    let proof = RelayEnrollmentProof::authenticate(
        &FakeEnrollment,
        b"authenticated-enrollment",
        &challenge,
    )
    .unwrap();
    connection.enroll(proof).await.unwrap();
    connection
        .send(RelayFrame::new(b"hello".to_vec()).unwrap())
        .await
        .unwrap();
    assert_eq!(connection.credit_state().await, (256 * 1024 - 5, 5));
    assert!(connection.receive().await.unwrap().is_some());
    connection.acknowledge(5).await;
    assert_eq!(connection.credit_state().await, (256 * 1024, 0));
    let peer = RelayAuthenticatedPeer;
    assert!(!peer.local_admin());
}

#[tokio::test]
async fn enrolled_relay_connection_is_a_component_session_transport() {
    let provider = provider();
    let connection = open_for(&provider, RelayRole::Sender, &test_binding(), 1_000)
        .await
        .unwrap();
    let challenge = connection.enrollment_challenge();
    let proof = RelayEnrollmentProof::authenticate(
        &FakeEnrollment,
        b"authenticated-enrollment",
        &challenge,
    )
    .unwrap();
    connection.enroll(proof).await.unwrap();

    let mut transport = RelayComponentSessionTransport::from_connection(connection);
    let descriptor = transport.descriptor();
    assert_eq!(
        descriptor.class,
        d2b_contracts_zone_session::v3::component_session::TransportClass::ProviderStream
    );
    assert_eq!(
        descriptor.locality,
        d2b_contracts_zone_session::v3::component_session::Locality::Remote
    );
    assert!(!descriptor.supports_attachments);

    transport
        .send(TransportPacket::new(b"encrypted-session-record".to_vec()))
        .await
        .unwrap();
    let packet = transport.receive(1024).await.unwrap();
    assert_eq!(packet.as_bytes(), b"encrypted-session-record");
}

#[tokio::test]
async fn unauthenticated_connection_cannot_send() {
    let connection = open_for(&provider(), RelayRole::Sender, &test_binding(), 1_000)
        .await
        .unwrap();
    assert_eq!(
        connection
            .send(RelayFrame::new(b"blocked".to_vec()).unwrap())
            .await,
        Err(RelayTransportError::InvalidSessionTransition)
    );
}

#[tokio::test]
async fn unauthenticated_connection_cannot_receive() {
    let provider = provider();
    let connection = open_for(&provider, RelayRole::Sender, &test_binding(), 1_000)
        .await
        .unwrap();
    assert!(matches!(
        connection.receive().await,
        Err(RelayTransportError::InvalidSessionTransition)
    ));
}

#[tokio::test]
async fn reconnect_policy_is_used_by_provider_open() {
    let attempts = Arc::new(Mutex::new(0));
    let provider = AzureRelayTransportProvider::new(
        RelayTransportConfig {
            max_concurrent_sessions: 1,
            ..config()
        },
        endpoint(),
        Arc::new(FakeCredentials),
        Arc::new(RetryConnector {
            attempts: Arc::clone(&attempts),
            failures: 2,
            socket: Arc::new(FakeSocket::default()),
        }),
    )
    .unwrap();
    provider
        .open_scoped_with_backoff(
            scoped_request_for(RelayRole::Sender, &test_binding(), 1_000),
            ReconnectBackoff::with_limits(0, 1, 3, 1),
        )
        .await
        .unwrap();
    assert_eq!(*attempts.lock().unwrap(), 3);
}

#[tokio::test]
async fn failed_credential_revoke_closes_connected_socket() {
    let closed = Arc::new(Mutex::new(false));
    let socket = Arc::new(TrackingSocket {
        closed: Arc::clone(&closed),
    });

    struct TrackingConnector {
        socket: Arc<TrackingSocket>,
    }

    #[async_trait]
    impl RelaySocketConnector for TrackingConnector {
        async fn connect(
            &self,
            _: &RelayEndpoint,
            _: RelayRole,
            _: &RelayCredentialLease,
        ) -> Result<Arc<dyn RelaySocket>, RelayTransportError> {
            Ok(Arc::clone(&self.socket) as Arc<dyn RelaySocket>)
        }
    }

    let provider = AzureRelayTransportProvider::new(
        config(),
        endpoint(),
        Arc::new(RevokeFails),
        Arc::new(TrackingConnector { socket }),
    )
    .unwrap();
    assert!(matches!(
        open_for(&provider, RelayRole::Sender, &test_binding(), 1_000).await,
        Err(RelayTransportError::CredentialUnavailable)
    ));
    assert!(*closed.lock().unwrap());
}

#[tokio::test]
async fn session_slot_wait_is_bounded_by_open_deadline() {
    let provider = AzureRelayTransportProvider::new(
        RelayTransportConfig {
            max_concurrent_sessions: 1,
            ..config()
        },
        endpoint(),
        Arc::new(FakeCredentials),
        Arc::new(FakeConnector {
            socket: Arc::new(FakeSocket::default()),
        }),
    )
    .unwrap();
    let held_binding = RelayCredentialBinding::new("link-1", "session-held", 1).unwrap();
    let held = open_for(&provider, RelayRole::Sender, &held_binding, 1_000)
        .await
        .unwrap();
    let waiting_binding = RelayCredentialBinding::new("link-1", "session-waiting", 1).unwrap();
    assert!(matches!(
        open_for(&provider, RelayRole::Sender, &waiting_binding, 20).await,
        Err(RelayTransportError::DeadlineExpired)
    ));
    held.close().await.unwrap();
}

struct TrackingCredentials {
    acquired: Arc<Mutex<usize>>,
    revoked: Arc<Mutex<usize>>,
    binding: Arc<Mutex<Option<RelayCredentialBinding>>>,
}

#[async_trait]
impl RelayCredentialPort for TrackingCredentials {
    async fn acquire(
        &self,
        _: RelayCredentialRole,
        _: u32,
    ) -> Result<RelayCredentialLease, RelayCredentialError> {
        panic!("the transport must use the binding-aware acquisition path");
    }

    async fn acquire_bound(
        &self,
        role: RelayCredentialRole,
        binding: &RelayCredentialBinding,
        _: u32,
    ) -> Result<RelayCredentialLease, RelayCredentialError> {
        *self.acquired.lock().unwrap() += 1;
        *self.binding.lock().unwrap() = Some(binding.clone());
        Ok(RelayCredentialLease::new_bound(
            RelayCredentialMaterial::SasToken(
                RelaySecret::new(b"connection-token".to_vec()).unwrap(),
            ),
            role,
            valid_expiry(),
            binding.clone(),
        )
        .unwrap())
    }

    async fn revoke(&self, _: RelayCredentialLease) -> Result<(), RelayCredentialError> {
        *self.revoked.lock().unwrap() += 1;
        Ok(())
    }
}

legacy_scoped_adapter!(TrackingCredentials);

#[tokio::test]
async fn bound_open_acquires_and_revokes_one_lease_per_connection() {
    let acquired = Arc::new(Mutex::new(0));
    let revoked = Arc::new(Mutex::new(0));
    let seen_binding = Arc::new(Mutex::new(None));
    let provider = AzureRelayTransportProvider::new(
        config(),
        endpoint(),
        Arc::new(TrackingCredentials {
            acquired: Arc::clone(&acquired),
            revoked: Arc::clone(&revoked),
            binding: Arc::clone(&seen_binding),
        }),
        Arc::new(FakeConnector {
            socket: Arc::new(FakeSocket::default()),
        }),
    )
    .unwrap();
    let binding = RelayCredentialBinding::new("link-1", "session-1", 3).unwrap();
    let connection = open_for(&provider, RelayRole::Sender, &binding, 1_000)
        .await
        .unwrap();
    assert_eq!(*acquired.lock().unwrap(), 1);
    assert_eq!(*revoked.lock().unwrap(), 1);
    assert_eq!(
        seen_binding.lock().unwrap().as_ref().map(|value| {
            (
                value.zone_link_uid().to_owned(),
                value.session_id().to_owned(),
                value.reconnect_generation(),
            )
        }),
        Some(("link-1".to_owned(), "session-1".to_owned(), 3))
    );
    assert_eq!(
        connection.binding().zone(),
        Some(&ZoneId::parse("work").unwrap())
    );
    connection.close().await.unwrap();
}

#[tokio::test]
async fn failed_new_generation_leaves_the_live_current_connection_usable() {
    let socket = Arc::new(FakeSocket::default());
    let provider = AzureRelayTransportProvider::new(
        config(),
        endpoint(),
        Arc::new(FakeCredentials),
        Arc::new(FailGenerationConnector {
            fail_generation: 2,
            socket: Arc::clone(&socket),
        }),
    )
    .unwrap();
    let first_binding = RelayCredentialBinding::new("link-1", "session-1", 1).unwrap();
    let first = open_for(&provider, RelayRole::Sender, &first_binding, 1_000)
        .await
        .unwrap();
    let challenge = first.enrollment_challenge();
    let proof = RelayEnrollmentProof::authenticate(
        &FakeEnrollment,
        b"authenticated-enrollment",
        &challenge,
    )
    .unwrap();
    first.enroll(proof).await.unwrap();

    let second_binding = RelayCredentialBinding::new("link-1", "session-1", 2).unwrap();
    assert!(matches!(
        open_for(&provider, RelayRole::Sender, &second_binding, 50).await,
        Err(RelayTransportError::Unavailable)
    ));
    assert_eq!(
        first
            .send(RelayFrame::new(b"still-current".to_vec()).unwrap())
            .await,
        Ok(())
    );
    first.close().await.unwrap();
}

#[tokio::test]
async fn cancelled_connect_releases_the_active_lease_row() {
    let active = Arc::new(AtomicUsize::new(0));
    let provider = Arc::new(
        AzureRelayTransportProvider::new(
            config(),
            endpoint(),
            Arc::new(CleanupCredentials {
                active: Arc::clone(&active),
                pending_revoke: true,
            }),
            Arc::new(PendingConnector),
        )
        .unwrap(),
    );
    let binding = RelayCredentialBinding::new("link-1", "cancelled", 1).unwrap();
    let task_provider = Arc::clone(&provider);
    let task =
        tokio::spawn(
            async move { open_for(&task_provider, RelayRole::Sender, &binding, 10_000).await },
        );
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while active.load(Ordering::SeqCst) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    task.abort();
    let join = task.await;
    assert!(matches!(join, Err(error) if error.is_cancelled()));
    wait_for_zero(&active).await;
}

#[tokio::test]
async fn timed_out_connect_releases_the_active_lease_row() {
    let active = Arc::new(AtomicUsize::new(0));
    let provider = AzureRelayTransportProvider::new(
        config(),
        endpoint(),
        Arc::new(CleanupCredentials {
            active: Arc::clone(&active),
            pending_revoke: true,
        }),
        Arc::new(PendingConnector),
    )
    .unwrap();
    let binding = RelayCredentialBinding::new("link-1", "timed-out", 1).unwrap();
    assert!(matches!(
        open_for(&provider, RelayRole::Sender, &binding, 20).await,
        Err(RelayTransportError::DeadlineExpired)
    ));
    wait_for_zero(&active).await;
}

#[tokio::test]
async fn connector_error_releases_the_active_lease_row() {
    let active = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(Mutex::new(0));
    let provider = AzureRelayTransportProvider::new(
        config(),
        endpoint(),
        Arc::new(CleanupCredentials {
            active: Arc::clone(&active),
            pending_revoke: false,
        }),
        Arc::new(CountingConnector {
            calls: Arc::clone(&calls),
        }),
    )
    .unwrap();
    let binding = RelayCredentialBinding::new("link-1", "connector-error", 1).unwrap();
    assert!(matches!(
        open_for(&provider, RelayRole::Sender, &binding, 1_000).await,
        Err(RelayTransportError::Unavailable)
    ));
    assert_eq!(*calls.lock().unwrap(), 1);
    wait_for_zero(&active).await;
}

#[tokio::test]
async fn timed_out_revoke_releases_the_active_lease_row() {
    let active = Arc::new(AtomicUsize::new(0));
    let provider = AzureRelayTransportProvider::new(
        config(),
        endpoint(),
        Arc::new(CleanupCredentials {
            active: Arc::clone(&active),
            pending_revoke: true,
        }),
        Arc::new(FakeConnector {
            socket: Arc::new(FakeSocket::default()),
        }),
    )
    .unwrap();
    let binding = RelayCredentialBinding::new("link-1", "revoke-timeout", 1).unwrap();
    assert!(matches!(
        open_for(&provider, RelayRole::Sender, &binding, 20).await,
        Err(RelayTransportError::DeadlineExpired)
    ));
    wait_for_zero(&active).await;
}

#[tokio::test]
async fn convenience_opens_release_generation_capacity() {
    let provider = provider();
    for _ in 0..=MAX_RELAY_GENERATION_FENCES {
        open_for(&provider, RelayRole::Sender, &test_binding(), 1_000)
            .await
            .unwrap()
            .close()
            .await
            .unwrap();
    }
    let final_binding = RelayCredentialBinding::new("link-final", "session-final", 1).unwrap();
    open_for(&provider, RelayRole::Sender, &final_binding, 1_000)
        .await
        .unwrap()
        .close()
        .await
        .unwrap();
}

struct WrongBindingCredentials {
    wrong_binding: RelayCredentialBinding,
    revoked: Arc<Mutex<usize>>,
}

#[async_trait]
impl RelayCredentialPort for WrongBindingCredentials {
    async fn acquire(
        &self,
        role: RelayCredentialRole,
        _: u32,
    ) -> Result<RelayCredentialLease, RelayCredentialError> {
        Ok(RelayCredentialLease::new(
            RelayCredentialMaterial::SasToken(
                RelaySecret::new(b"wrong-binding-token".to_vec()).unwrap(),
            ),
            role,
            valid_expiry(),
        ))
    }

    async fn acquire_bound(
        &self,
        role: RelayCredentialRole,
        _: &RelayCredentialBinding,
        _: u32,
    ) -> Result<RelayCredentialLease, RelayCredentialError> {
        Ok(RelayCredentialLease::new_bound(
            RelayCredentialMaterial::SasToken(
                RelaySecret::new(b"wrong-binding-token".to_vec()).unwrap(),
            ),
            role,
            valid_expiry(),
            self.wrong_binding.clone(),
        )
        .unwrap())
    }

    async fn revoke(&self, _: RelayCredentialLease) -> Result<(), RelayCredentialError> {
        *self.revoked.lock().unwrap() += 1;
        Ok(())
    }
}

legacy_scoped_adapter!(WrongBindingCredentials);

struct CountingConnector {
    calls: Arc<Mutex<usize>>,
}

#[async_trait]
impl RelaySocketConnector for CountingConnector {
    async fn connect(
        &self,
        _: &RelayEndpoint,
        _: RelayRole,
        _: &RelayCredentialLease,
    ) -> Result<Arc<dyn RelaySocket>, RelayTransportError> {
        *self.calls.lock().unwrap() += 1;
        Err(RelayTransportError::Unavailable)
    }
}

#[tokio::test]
async fn mismatched_bound_lease_is_revoked_before_connector_dispatch() {
    let revoked = Arc::new(Mutex::new(0));
    let calls = Arc::new(Mutex::new(0));
    let provider = AzureRelayTransportProvider::new(
        config(),
        endpoint(),
        Arc::new(WrongBindingCredentials {
            wrong_binding: RelayCredentialBinding::new_scoped(
                ZoneId::parse("work").unwrap(),
                "link-2",
                "session-2",
                1,
            )
            .unwrap(),
            revoked: Arc::clone(&revoked),
        }),
        Arc::new(CountingConnector {
            calls: Arc::clone(&calls),
        }),
    )
    .unwrap();
    let binding = RelayCredentialBinding::new("link-1", "session-1", 1).unwrap();
    assert!(matches!(
        open_for(&provider, RelayRole::Sender, &binding, 1_000).await,
        Err(RelayTransportError::CredentialBindingMismatch)
    ));
    assert_eq!(*revoked.lock().unwrap(), 1);
    assert_eq!(*calls.lock().unwrap(), 0);
}

#[tokio::test]
async fn stale_reconnect_generation_closes_the_old_connection_before_io() {
    let provider = provider();
    let first_binding = RelayCredentialBinding::new("link-1", "session-1", 1).unwrap();
    let first = open_for(&provider, RelayRole::Sender, &first_binding, 1_000)
        .await
        .unwrap();
    let challenge = first.enrollment_challenge();
    let proof = RelayEnrollmentProof::authenticate(
        &FakeEnrollment,
        b"authenticated-enrollment",
        &challenge,
    )
    .unwrap();
    first.enroll(proof).await.unwrap();

    let second_binding = RelayCredentialBinding::new("link-1", "session-1", 2).unwrap();
    let second = open_for(&provider, RelayRole::Sender, &second_binding, 1_000)
        .await
        .unwrap();
    assert_eq!(
        first
            .send(RelayFrame::new(b"stale".to_vec()).unwrap())
            .await,
        Err(RelayTransportError::StaleGeneration)
    );
    assert_eq!(
        first.phase().await,
        d2b_provider_transport_azure_relay::RelaySessionPhase::Closed
    );
    second.close().await.unwrap();
}

#[tokio::test]
async fn newer_success_remains_authoritative_after_older_cleanup() {
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let provider = Arc::new(
        AzureRelayTransportProvider::new(
            config(),
            endpoint(),
            Arc::new(FakeCredentials),
            Arc::new(BlockingGenerationConnector {
                started: Arc::clone(&started),
                release: Arc::clone(&release),
                socket: Arc::new(FakeSocket::default()),
            }),
        )
        .unwrap(),
    );
    let first_binding = RelayCredentialBinding::new("link-1", "session-1", 1).unwrap();
    let old_provider = Arc::clone(&provider);
    let old_open = tokio::spawn(async move {
        open_for(&old_provider, RelayRole::Sender, &first_binding, 10_000).await
    });
    tokio::time::timeout(std::time::Duration::from_secs(1), started.notified())
        .await
        .unwrap();

    let second_binding = RelayCredentialBinding::new("link-1", "session-1", 2).unwrap();
    let second = open_for(&provider, RelayRole::Sender, &second_binding, 1_000)
        .await
        .unwrap();
    release.notify_one();
    assert!(matches!(
        old_open.await.unwrap(),
        Err(RelayTransportError::StaleGeneration)
    ));

    let challenge = second.enrollment_challenge();
    let proof = RelayEnrollmentProof::authenticate(
        &FakeEnrollment,
        b"authenticated-enrollment",
        &challenge,
    )
    .unwrap();
    second.enroll(proof).await.unwrap();
    second
        .send(RelayFrame::new(b"new-current".to_vec()).unwrap())
        .await
        .unwrap();
    second.close().await.unwrap();
}

struct UnavailableCredentials {
    attempts: Arc<Mutex<usize>>,
}

#[async_trait]
impl RelayCredentialPort for UnavailableCredentials {
    async fn acquire(
        &self,
        _: RelayCredentialRole,
        _: u32,
    ) -> Result<RelayCredentialLease, RelayCredentialError> {
        *self.attempts.lock().unwrap() += 1;
        Err(RelayCredentialError::Unavailable)
    }

    async fn acquire_bound(
        &self,
        _: RelayCredentialRole,
        _: &RelayCredentialBinding,
        _: u32,
    ) -> Result<RelayCredentialLease, RelayCredentialError> {
        *self.attempts.lock().unwrap() += 1;
        Err(RelayCredentialError::Unavailable)
    }

    async fn revoke(&self, _: RelayCredentialLease) -> Result<(), RelayCredentialError> {
        Ok(())
    }
}

legacy_scoped_adapter!(UnavailableCredentials);

#[tokio::test]
async fn unavailable_credential_provider_uses_bounded_retries() {
    let attempts = Arc::new(Mutex::new(0));
    let provider = AzureRelayTransportProvider::new(
        config(),
        endpoint(),
        Arc::new(UnavailableCredentials {
            attempts: Arc::clone(&attempts),
        }),
        Arc::new(FakeConnector {
            socket: Arc::new(FakeSocket::default()),
        }),
    )
    .unwrap();
    let binding = RelayCredentialBinding::new("link-1", "session-1", 1).unwrap();
    assert!(matches!(
        provider
            .open_scoped_with_backoff(
                scoped_request_for(RelayRole::Sender, &binding, 100),
                ReconnectBackoff::with_limits(1, 0, 2, 50),
            )
            .await,
        Err(RelayTransportError::CredentialUnavailable)
    ));
    assert!(*attempts.lock().unwrap() <= 3);
}

struct CleanupCredentials {
    active: Arc<AtomicUsize>,
    pending_revoke: bool,
}

#[async_trait]
impl RelayCredentialPort for CleanupCredentials {
    async fn acquire(
        &self,
        _: RelayCredentialRole,
        _: u32,
    ) -> Result<RelayCredentialLease, RelayCredentialError> {
        Err(RelayCredentialError::BindingRequired)
    }

    async fn acquire_bound(
        &self,
        role: RelayCredentialRole,
        binding: &RelayCredentialBinding,
        _: u32,
    ) -> Result<RelayCredentialLease, RelayCredentialError> {
        self.active.fetch_add(1, Ordering::SeqCst);
        let active = Arc::clone(&self.active);
        let mut lease = RelayCredentialLease::new_bound(
            RelayCredentialMaterial::SasToken(RelaySecret::new(b"cleanup-token".to_vec()).unwrap()),
            role,
            valid_expiry(),
            binding.clone(),
        )
        .unwrap();
        lease.set_drop_hook(Arc::new(move |_| {
            active.fetch_sub(1, Ordering::SeqCst);
        }));
        Ok(lease)
    }

    async fn revoke(&self, _: RelayCredentialLease) -> Result<(), RelayCredentialError> {
        if self.pending_revoke {
            std::future::pending::<()>().await;
        }
        Ok(())
    }
}

legacy_scoped_adapter!(CleanupCredentials);

struct PendingConnector;

#[async_trait]
impl RelaySocketConnector for PendingConnector {
    async fn connect(
        &self,
        _: &RelayEndpoint,
        _: RelayRole,
        _: &RelayCredentialLease,
    ) -> Result<Arc<dyn RelaySocket>, RelayTransportError> {
        std::future::pending::<Result<Arc<dyn RelaySocket>, RelayTransportError>>().await
    }
}

struct BlockingGenerationConnector {
    started: Arc<Notify>,
    release: Arc<Notify>,
    socket: Arc<FakeSocket>,
}

#[async_trait]
impl RelaySocketConnector for BlockingGenerationConnector {
    async fn connect(
        &self,
        _: &RelayEndpoint,
        _: RelayRole,
        lease: &RelayCredentialLease,
    ) -> Result<Arc<dyn RelaySocket>, RelayTransportError> {
        if lease.reconnect_generation() == 1 {
            self.started.notify_one();
            self.release.notified().await;
        }
        Ok(Arc::clone(&self.socket) as Arc<dyn RelaySocket>)
    }
}

async fn wait_for_zero(active: &AtomicUsize) {
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if active.load(Ordering::SeqCst) == 0 {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

struct RoleAndExpiryCredentials {
    role: RelayCredentialRole,
    expiry: u64,
    revoked: Arc<Mutex<usize>>,
}

#[async_trait]
impl RelayCredentialPort for RoleAndExpiryCredentials {
    async fn acquire(
        &self,
        _: RelayCredentialRole,
        _: u32,
    ) -> Result<RelayCredentialLease, RelayCredentialError> {
        Ok(RelayCredentialLease::new(
            RelayCredentialMaterial::SasToken(RelaySecret::new(b"token".to_vec()).unwrap()),
            self.role,
            self.expiry,
        ))
    }

    async fn acquire_bound(
        &self,
        _: RelayCredentialRole,
        binding: &RelayCredentialBinding,
        _: u32,
    ) -> Result<RelayCredentialLease, RelayCredentialError> {
        Ok(RelayCredentialLease::new_bound(
            RelayCredentialMaterial::SasToken(RelaySecret::new(b"token".to_vec()).unwrap()),
            self.role,
            self.expiry,
            binding.clone(),
        )
        .unwrap())
    }

    async fn revoke(&self, _: RelayCredentialLease) -> Result<(), RelayCredentialError> {
        *self.revoked.lock().unwrap() += 1;
        Ok(())
    }
}

legacy_scoped_adapter!(RoleAndExpiryCredentials);

#[tokio::test]
async fn invalid_lease_role_and_expiry_never_reach_connector() {
    let revoked = Arc::new(Mutex::new(0));
    let provider = AzureRelayTransportProvider::new(
        config(),
        endpoint(),
        Arc::new(RoleAndExpiryCredentials {
            role: RelayCredentialRole::Listen,
            expiry: valid_expiry(),
            revoked: Arc::clone(&revoked),
        }),
        Arc::new(FakeConnector {
            socket: Arc::new(FakeSocket::default()),
        }),
    )
    .unwrap();
    assert!(matches!(
        open_for(&provider, RelayRole::Sender, &test_binding(), 1_000).await,
        Err(RelayTransportError::CredentialRoleMismatch)
    ));
    assert_eq!(*revoked.lock().unwrap(), 1);

    let revoked = Arc::new(Mutex::new(0));
    let provider = AzureRelayTransportProvider::new(
        config(),
        endpoint(),
        Arc::new(RoleAndExpiryCredentials {
            role: RelayCredentialRole::Send,
            expiry: 1,
            revoked: Arc::clone(&revoked),
        }),
        Arc::new(FakeConnector {
            socket: Arc::new(FakeSocket::default()),
        }),
    )
    .unwrap();
    assert!(matches!(
        open_for(&provider, RelayRole::Sender, &test_binding(), 1_000).await,
        Err(RelayTransportError::CredentialExpired)
    ));
    assert_eq!(*revoked.lock().unwrap(), 1);
}

struct FailingSocket {
    closed: Arc<Mutex<bool>>,
}

#[async_trait]
impl RelaySocket for FailingSocket {
    async fn send(&self, _: RelayFrame) -> Result<(), RelayTransportError> {
        Err(RelayTransportError::Unavailable)
    }

    async fn receive(&self) -> Result<Option<RelayFrame>, RelayTransportError> {
        Err(RelayTransportError::Unavailable)
    }

    async fn close(&self) -> Result<(), RelayTransportError> {
        *self.closed.lock().unwrap() = true;
        Ok(())
    }
}

struct FailingConnector {
    socket: Arc<FailingSocket>,
}

#[async_trait]
impl RelaySocketConnector for FailingConnector {
    async fn connect(
        &self,
        _: &RelayEndpoint,
        _: RelayRole,
        _: &RelayCredentialLease,
    ) -> Result<Arc<dyn RelaySocket>, RelayTransportError> {
        Ok(Arc::clone(&self.socket) as Arc<dyn RelaySocket>)
    }
}

struct EofSocket {
    closed: Arc<Mutex<bool>>,
}

#[async_trait]
impl RelaySocket for EofSocket {
    async fn send(&self, _: RelayFrame) -> Result<(), RelayTransportError> {
        Ok(())
    }

    async fn receive(&self) -> Result<Option<RelayFrame>, RelayTransportError> {
        Ok(None)
    }

    async fn close(&self) -> Result<(), RelayTransportError> {
        *self.closed.lock().unwrap() = true;
        Ok(())
    }
}

struct EofConnector {
    socket: Arc<EofSocket>,
}

#[async_trait]
impl RelaySocketConnector for EofConnector {
    async fn connect(
        &self,
        _: &RelayEndpoint,
        _: RelayRole,
        _: &RelayCredentialLease,
    ) -> Result<Arc<dyn RelaySocket>, RelayTransportError> {
        Ok(Arc::clone(&self.socket) as Arc<dyn RelaySocket>)
    }
}

#[tokio::test]
async fn failed_send_closes_the_session() {
    let closed = Arc::new(Mutex::new(false));
    let socket = Arc::new(FailingSocket {
        closed: Arc::clone(&closed),
    });
    let provider = AzureRelayTransportProvider::new(
        config(),
        endpoint(),
        Arc::new(FakeCredentials),
        Arc::new(FailingConnector {
            socket: Arc::clone(&socket),
        }),
    )
    .unwrap();
    let connection = open_for(&provider, RelayRole::Sender, &test_binding(), 1_000)
        .await
        .unwrap();
    let challenge = connection.enrollment_challenge();
    let proof = RelayEnrollmentProof::authenticate(
        &FakeEnrollment,
        b"authenticated-enrollment",
        &challenge,
    )
    .unwrap();
    connection.enroll(proof).await.unwrap();
    assert_eq!(
        connection
            .send(RelayFrame::new(b"x".to_vec()).unwrap())
            .await,
        Err(RelayTransportError::Unavailable)
    );
    assert_eq!(
        connection.phase().await,
        d2b_provider_transport_azure_relay::RelaySessionPhase::Closed
    );
    assert!(*closed.lock().unwrap());
    let connection = open_for(&provider, RelayRole::Sender, &test_binding(), 1_000)
        .await
        .unwrap();
    connection.close().await.unwrap();
}

#[tokio::test]
async fn eof_closes_the_session_and_releases_the_slot() {
    let closed = Arc::new(Mutex::new(false));
    let socket = Arc::new(EofSocket {
        closed: Arc::clone(&closed),
    });
    let provider = AzureRelayTransportProvider::new(
        RelayTransportConfig {
            max_concurrent_sessions: 1,
            ..config()
        },
        endpoint(),
        Arc::new(FakeCredentials),
        Arc::new(EofConnector {
            socket: Arc::clone(&socket),
        }),
    )
    .unwrap();
    let connection = open_for(&provider, RelayRole::Sender, &test_binding(), 1_000)
        .await
        .unwrap();
    let challenge = connection.enrollment_challenge();
    let proof = RelayEnrollmentProof::authenticate(
        &FakeEnrollment,
        b"authenticated-enrollment",
        &challenge,
    )
    .unwrap();
    connection.enroll(proof).await.unwrap();
    assert!(connection.receive().await.unwrap().is_none());
    assert_eq!(
        connection.phase().await,
        d2b_provider_transport_azure_relay::RelaySessionPhase::Closed
    );
    assert!(*closed.lock().unwrap());
    open_for(&provider, RelayRole::Sender, &test_binding(), 1_000)
        .await
        .unwrap()
        .close()
        .await
        .unwrap();
}

#[test]
fn helper_surface_does_not_reintroduce_unbounded_window() {
    assert!(CreditWindow::new(256 * 1024).is_ok());
}
