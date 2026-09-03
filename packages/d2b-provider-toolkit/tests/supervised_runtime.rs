use std::{
    io::{BufRead, BufReader, Read},
    process::{Command, Stdio},
    sync::mpsc,
    time::Duration,
};

use d2b_contracts_resource::v3::{
    ControllerGeneration, ResourceGeneration, ResourceRef, ResourceUid, SchemaFingerprint,
    identity::{
        AuthenticatedSubjectContext, BindingDigest, EvidenceClass, Locality, ServiceName,
        SessionBinding, SessionPurpose, TranscriptHash, TransportBinding,
    },
};
use d2b_contracts_zone_session::v3::component_session::{
    EndpointRole, EndpointRole as ComponentEndpointRole, Locality as ComponentLocality,
    PurposeClass, TransportClass,
};
use d2b_provider_toolkit::{
    CredentialDeliveryKeyHandoff, CredentialDeliveryKeyMaterial, GUEST_CREDENTIAL_BACKEND_FD,
    GuestCredentialBackend, GuestCredentialBackendHandler, GuestCredentialBackendHandlerError,
    GuestCredentialBackendHandlerFuture, GuestCredentialBackendReply,
    PROVIDER_BOOTSTRAP_STREAM_CREDIT, PROVIDER_BOOTSTRAP_STREAM_ID,
    PROVIDER_DELIVERY_KEY_STREAM_CREDIT, PROVIDER_DELIVERY_KEY_STREAM_ID, PROVIDER_READY_MARKER,
    PROVIDER_READY_STREAM_CREDIT, PROVIDER_READY_STREAM_ID, ProviderSessionMetadata,
    spawn_guest_credential_backend_responder,
};
use d2b_session::{
    ComponentSessionDriver, HandshakeCredentials, SessionEngine, StreamEvent, StreamId,
    x25519_public_key,
};
use d2b_session_unix::{
    AncillaryCapacity, CreditPool, CreditScopeSet, DescriptorPolicyResolver, PeerIdentityPolicy,
    SeqpacketSocket, UnixSeqpacketTransport, UnixSessionError,
    controller_bootstrap_attachment_policy, controller_credit_scopes,
    credential_delivery_endpoint_policy, credential_provider_endpoint_policy,
    duplicate_to_inherited_fd, prearmed_seqpacket_pair,
};

fn route(provider: &str) -> d2b_session::AuthenticatedSessionRouteBinding {
    route_with_execution(provider, "Guest/test")
}

fn route_with_execution(
    provider: &str,
    execution: &str,
) -> d2b_session::AuthenticatedSessionRouteBinding {
    let provider_ref = ResourceRef::parse(provider).expect("Provider reference");
    let digest = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
    let context = AuthenticatedSubjectContext::new(
        provider_ref.clone(),
        ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").expect("UID"),
        ResourceRef::parse("Zone/dev").expect("Zone reference"),
        EvidenceClass::UnixPeer,
        SessionPurpose::parse("provider-control").expect("purpose"),
        ServiceName::parse("d2b.credential.v3").expect("service"),
        SessionBinding::new(
            SchemaFingerprint::parse(digest).expect("schema"),
            TransportBinding::new(
                Locality::Local,
                BindingDigest::parse(
                    "sha256:3434343434343434343434343434343434343434343434343434343434343434",
                )
                .expect("binding"),
            ),
            d2b_contracts_resource::v3::identity::ReconnectGeneration::new(1)
                .expect("session generation"),
            TranscriptHash::from_bytes([0x5a; 32]),
        ),
    )
    .with_execution_ref(ResourceRef::parse(execution).expect("execution reference"))
    .with_provider_ref(provider_ref)
    .with_process_ref(ResourceRef::parse("Process/credential-controller").expect("Process"))
    .with_provider_generation(ResourceGeneration::new(1).expect("Provider generation"))
    .with_controller_generation(ControllerGeneration::new(1).expect("Controller generation"));
    d2b_session::AuthenticatedSessionRouteBinding::from_authenticated_peer(
        context,
        ComponentLocality::HostLocal,
        PurposeClass::Local,
        ComponentEndpointRole::Provider,
        EndpointRole::ZoneController,
        TransportClass::InheritedSocketpair,
    )
    .expect("route")
}

#[test]
fn guest_backend_rejects_a_host_execution_route() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");
    runtime.block_on(async {
        let (client_fd, _server_fd) = prearmed_seqpacket_pair().expect("backend pair");
        let client_socket =
            SeqpacketSocket::from_parent_prearmed(client_fd).expect("backend socket");
        assert!(
            GuestCredentialBackend::from_socket_for_test_with_route(
                client_socket,
                route_with_execution(
                    "Provider/credential-managed-identity",
                    "Host/test",
                ),
                CredentialDeliveryKeyMaterial::new([1; 32], [2; 32])
                    .expect("test key material"),
            )
            .is_err()
        );
    });
}

async fn receive_bootstrap(
    socket: &SeqpacketSocket,
) -> Result<(SeqpacketSocket, d2b_session_unix::PeerCredentials), UnixSessionError> {
    let policy = controller_bootstrap_attachment_policy();
    let capacity = AncillaryCapacity::from_policy(policy).expect("bootstrap capacity");
    let scopes = CreditScopeSet::new(
        CreditPool::new(8).expect("credit"),
        CreditPool::new(8).expect("credit"),
        CreditPool::new(8).expect("credit"),
        CreditPool::new(8).expect("credit"),
        CreditPool::new(8).expect("credit"),
        CreditPool::new(8).expect("credit"),
    );
    let mut burst = socket
        .recv_burst(
            d2b_contracts_zone_session::v3::component_session::LimitProfile::local_default(),
            capacity,
            &scopes,
            2,
        )
        .await?;
    let packet = burst.packets.pop().expect("bootstrap packet");
    assert!(burst.packets.is_empty());
    assert_eq!(
        packet.payload(),
        d2b_session_unix::CONTROLLER_BOOTSTRAP_PROTOCOL_MARKER
    );
    let (fd, credentials) = packet.into_single_file_and_credentials()?;
    let socket = SeqpacketSocket::from_parent_prearmed(fd)?;
    assert_eq!(socket.acceptor_peer_credentials()?, credentials);
    Ok((socket, credentials))
}

fn provider_transport(
    socket: SeqpacketSocket,
    credentials: d2b_session_unix::PeerCredentials,
) -> UnixSeqpacketTransport {
    let policy = credential_provider_endpoint_policy();
    let resolver: DescriptorPolicyResolver =
        std::sync::Arc::new(|_| Err(UnixSessionError::DescriptorMismatch));
    UnixSeqpacketTransport::new(
        socket,
        policy.transport_binding.locality,
        policy.limits,
        policy.attachment_policy,
        controller_credit_scopes().expect("credit scopes"),
        resolver,
        PeerIdentityPolicy::inherited_socketpair(credentials),
    )
    .expect("provider transport")
}

fn delivery_transport(
    socket: SeqpacketSocket,
    credentials: d2b_session_unix::PeerCredentials,
) -> UnixSeqpacketTransport {
    let policy = credential_delivery_endpoint_policy(1);
    let resolver: DescriptorPolicyResolver =
        std::sync::Arc::new(|_| Err(UnixSessionError::DescriptorMismatch));
    UnixSeqpacketTransport::new(
        socket,
        policy.transport_binding.locality,
        policy.limits,
        policy.attachment_policy,
        controller_credit_scopes().expect("credit scopes"),
        resolver,
        PeerIdentityPolicy::inherited_socketpair(credentials),
    )
    .expect("delivery transport")
}

fn run_supervised_binary(path: &str, provider: &str) {
    let (bootstrap_fd, child_fd) = prearmed_seqpacket_pair().expect("bootstrap pair");
    let inherited = duplicate_to_inherited_fd(&child_fd, 200).expect("inherited fd");
    let (backend_peer, backend_child) = prearmed_seqpacket_pair().expect("backend pair");
    let backend_inherited =
        duplicate_to_inherited_fd(&backend_child, 201).expect("backend inherited fd");
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "exec 10<&200; exec {}<&201; exec \"$1\"",
            GUEST_CREDENTIAL_BACKEND_FD
        ))
        .arg("d2b-provider-supervised-test")
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("provider binary");
    drop(inherited);
    drop(backend_inherited);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");
    let driver = runtime.block_on(async {
        let bootstrap = SeqpacketSocket::from_parent_prearmed(bootstrap_fd).expect("bootstrap");
        let (resource_socket, credentials) = tokio::time::timeout(
            Duration::from_secs(3),
            receive_bootstrap(&bootstrap),
        )
        .await
        .expect("bootstrap receive timeout")
        .expect("bootstrap receive");
        let policy = credential_provider_endpoint_policy();
        let responder = SessionEngine::establish_responder(
            provider_transport(resource_socket, credentials),
            policy,
            HandshakeCredentials::Nn,
            std::time::Instant::now(),
        )
        .await
        .expect("provider handshake");
        let driver = responder.into_driver();
        let route = route(provider);
        let user_ref = provider
            .ends_with("credential-secret-service")
            .then(|| ResourceRef::parse("User/provider-scope").expect("User reference"));
        let metadata = ProviderSessionMetadata::from_route_with_user(&route, user_ref.as_ref())
            .expect("route metadata")
            .encode()
            .expect("metadata encoding");
        let stream = StreamId::new(PROVIDER_BOOTSTRAP_STREAM_ID).expect("bootstrap stream");
        driver
            .open_named_stream(
                stream,
                PROVIDER_BOOTSTRAP_STREAM_CREDIT,
                PROVIDER_BOOTSTRAP_STREAM_CREDIT,
            )
            .await
            .expect("open bootstrap stream");
        driver
            .send_named_stream(stream, metadata)
            .await
            .expect("send route metadata");
        driver
            .close_named_stream(stream)
            .await
            .expect("close bootstrap stream");
        let provider_private = [7_u8; 32];
        let backend_private = [9_u8; 32];
        let backend_public = x25519_public_key(&backend_private).expect("backend public key");
        let provider_public = x25519_public_key(&provider_private).expect("provider public key");
        let backend_responder = spawn_guest_credential_backend_responder(
            SeqpacketSocket::from_parent_prearmed(backend_peer)
                .expect("backend responder socket"),
            CredentialDeliveryKeyMaterial::new(backend_private, provider_public)
                .expect("backend key material"),
            std::sync::Arc::new(ScriptedGuestCredentialBackend),
        )
        .expect("backend responder");
        backend_responder
            .bind_route_with_user(route.clone(), user_ref.clone())
            .expect("bind backend responder route");
        let key_handoff = CredentialDeliveryKeyHandoff::new(provider_private, backend_public)
            .expect("delivery key handoff");
        let key_stream =
            StreamId::new(PROVIDER_DELIVERY_KEY_STREAM_ID).expect("delivery key stream");
        driver
            .open_named_stream(
                key_stream,
                PROVIDER_DELIVERY_KEY_STREAM_CREDIT,
                PROVIDER_DELIVERY_KEY_STREAM_CREDIT,
            )
            .await
            .expect("open delivery key stream");
        driver
            .send_named_stream(key_stream, {
                let bytes = key_handoff
                    .encode_for_route(&route)
                    .expect("delivery key encoding")
                    .to_vec();
                bytes
            })
            .await
            .expect("send delivery key handoff");
        driver
            .close_named_stream(key_stream)
            .await
            .expect("close delivery key stream");
        let ready_stream = StreamId::new(PROVIDER_READY_STREAM_ID).expect("ready stream");
        driver
            .open_named_stream(
                ready_stream,
                PROVIDER_READY_STREAM_CREDIT,
                PROVIDER_READY_STREAM_CREDIT,
            )
            .await
            .expect("open ready stream");
        let mut ready = Vec::new();
        loop {
            match tokio::time::timeout(
                Duration::from_secs(5),
                driver.receive_named_stream_for(ready_stream),
            )
                .await
            .expect("receive readiness timeout")
                .expect("receive readiness")
            {
                StreamEvent::Data { bytes, .. } => {
                    ready.extend_from_slice(&bytes);
                    driver
                        .grant_named_stream_credit(
                            ready_stream,
                            u32::try_from(bytes.len()).expect("readiness size"),
                        )
                        .await
                        .expect("grant readiness credit");
                }
                StreamEvent::RemoteClosed { .. } => break,
                StreamEvent::Reset { .. } => panic!("provider reset readiness stream"),
            }
        }
        assert_eq!(ready, PROVIDER_READY_MARKER);
        tokio::task::yield_now().await;
        driver
    });

    let stderr = child.stderr.take().expect("provider stderr");
    let stdout = child.stdout.take().expect("provider stdout");
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout).read_line(&mut line);
        let _ = sender.send((result, line));
    });
    let (read, line) = receiver
        .recv_timeout(Duration::from_secs(5))
        .expect("provider readiness");
    let read = read.expect("readiness read");
    if read == 0 {
        let mut error = String::new();
        BufReader::new(stderr)
            .read_to_string(&mut error)
            .expect("provider stderr");
        let status = child.wait().expect("reap failed provider");
        panic!("provider exited before readiness ({status}): {error}");
    }
    assert!(line.starts_with("D2B_PROVIDER_READY "));
    child.kill().expect("stop provider");
    child.wait().expect("reap provider");
    drop(driver);
}

#[test]
fn provider_binaries_complete_the_supervised_fd10_session_lifecycle() {
    let binaries = [
        (
            option_env!("CARGO_BIN_EXE_d2b-provider-credential-secret-service"),
            "Provider/credential-secret-service",
        ),
        (
            option_env!("CARGO_BIN_EXE_d2b-provider-credential-entra"),
            "Provider/credential-entra",
        ),
        (
            option_env!("CARGO_BIN_EXE_d2b-managed-identity-controller"),
            "Provider/credential-managed-identity",
        ),
        (
            option_env!("CARGO_BIN_EXE_d2b-managed-identity-agent"),
            "Provider/credential-managed-identity",
        ),
    ];
    for (path, provider) in binaries {
        let path = path.expect("binary path supplied by Bazel");
        eprintln!("starting {provider}");
        run_supervised_binary(path, provider);
        eprintln!("finished {provider}");
    }
}

#[test]
fn guest_backend_round_trip_keeps_response_bytes_zeroizing() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");
    runtime.block_on(async {
        let (client_fd, server_fd) = prearmed_seqpacket_pair().expect("backend pair");
        let client_socket =
            SeqpacketSocket::from_parent_prearmed(client_fd).expect("backend client socket");
        let server_socket =
            SeqpacketSocket::from_parent_prearmed(server_fd).expect("backend server socket");
        let route = route("Provider/credential-managed-identity");
        let provider_private = [7_u8; 32];
        let backend_private = [9_u8; 32];
        let backend_public = x25519_public_key(&backend_private).expect("backend public key");
        let provider_public = x25519_public_key(&provider_private).expect("provider public key");
        let backend = GuestCredentialBackend::from_socket_for_test_with_route(
            client_socket,
            route.clone(),
            CredentialDeliveryKeyMaterial::new(provider_private, backend_public)
                .expect("provider key material"),
        )
        .expect("Guest route");
        let credentials = server_socket
            .acceptor_peer_credentials()
            .expect("backend peer credentials");
        assert_eq!(
            credentials,
            server_socket
                .acceptor_peer_credentials()
                .expect("backend peer credentials")
        );
        let responder = spawn_guest_credential_backend_responder(
            server_socket,
            CredentialDeliveryKeyMaterial::new(backend_private, provider_public)
                .expect("backend key material"),
            std::sync::Arc::new(ScriptedGuestCredentialBackend),
        )
        .expect("backend responder");
        responder
            .bind_route(route.clone())
            .expect("bind backend responder route");
        let response = backend
            .request(
                "managed-identity.issue-lease",
                serde_json::json!({"credentialRef": "Credential/test"}),
            )
            .await
            .expect("backend response");
        assert_eq!(response.state(), Some("ready"));
        assert!(!format!("{response:?}").contains("1, 2, 3, 4"));
        assert_eq!(
            response.into_bytes().expect("response bytes").as_slice(),
            [1, 2, 3, 4]
        );
        let response = backend
            .request(
                "managed-identity.inspect-lease",
                serde_json::json!({"credentialRef": "Credential/test"}),
            )
            .await
            .expect("inspection response");
        assert_eq!(response.state(), Some("active"));
        assert!(response.into_bytes().is_none());
        let response = backend
            .request(
                "managed-identity.refresh-lease",
                serde_json::json!({
                    "credentialRef": "Credential/test",
                    "leaseHandle": "backend-lease",
                }),
            )
            .await
            .expect("refresh response");
        assert_eq!(response.state(), Some("ready"));
        assert!(response.into_bytes().is_some());
        let response = backend
            .request(
                "managed-identity.revoke-lease",
                serde_json::json!({"credentialRef": "Credential/test"}),
            )
            .await
            .expect("revocation response");
        assert_eq!(response.outcome(), Some("revoked"));
        assert!(response.into_bytes().is_none());
        responder.cancel();
    });
}

#[test]
fn guest_backend_rejects_an_unenrolled_peer_key() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");
    runtime.block_on(async {
        let (client_fd, server_fd) = prearmed_seqpacket_pair().expect("backend pair");
        let client_socket =
            SeqpacketSocket::from_parent_prearmed(client_fd).expect("backend client socket");
        let server_socket =
            SeqpacketSocket::from_parent_prearmed(server_fd).expect("backend server socket");
        let route = route("Provider/credential-managed-identity");
        let provider_private = [7_u8; 32];
        let backend_private = [9_u8; 32];
        let wrong_backend_private = [11_u8; 32];
        let provider_public = x25519_public_key(&provider_private).expect("provider public key");
        let wrong_backend_public =
            x25519_public_key(&wrong_backend_private).expect("wrong backend public key");
        let backend = GuestCredentialBackend::from_socket_for_test_with_route(
            client_socket,
            route.clone(),
            CredentialDeliveryKeyMaterial::new(provider_private, wrong_backend_public)
                .expect("provider key material"),
        )
        .expect("Guest route");
        let credentials = server_socket
            .acceptor_peer_credentials()
            .expect("backend peer credentials");
        let policy = credential_delivery_endpoint_policy(route.reconnect_generation().get());
        let responder = tokio::spawn(async move {
            SessionEngine::establish_responder(
                delivery_transport(server_socket, credentials),
                policy,
                CredentialDeliveryKeyMaterial::new(backend_private, provider_public)
                    .expect("backend key material")
                    .into_handshake()
                    .expect("backend handshake credentials"),
                std::time::Instant::now(),
            )
            .await
        });
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            backend.request(
                "managed-identity.inspect-lease",
                serde_json::json!({"credentialRef": "Credential/test"}),
            ),
        )
        .await
        .expect("wrong-key timeout");
        assert!(result.is_err());
        responder.abort();
        let _ = responder.await;
    });
}

#[test]
fn delivery_key_handoff_serializes_only_explicit_key_material() {
    let first = route("Provider/credential-managed-identity");
    let second = route_with_execution("Provider/credential-managed-identity", "Guest/other");
    let handoff = CredentialDeliveryKeyHandoff::new(
        [7_u8; 32],
        x25519_public_key(&[9_u8; 32]).expect("backend public key"),
    )
    .expect("handoff");
    let first: serde_json::Value = serde_json::from_slice(
        &handoff
            .encode_for_route(&first)
            .expect("first handoff")
            .to_vec(),
    )
    .expect("first handoff JSON");
    let second: serde_json::Value = serde_json::from_slice(
        &handoff
            .encode_for_route(&second)
            .expect("second handoff")
            .to_vec(),
    )
    .expect("second handoff JSON");
    assert_eq!(first["providerPrivate"], second["providerPrivate"]);
    assert_ne!(first["executionRef"], second["executionRef"]);
}

struct ScriptedGuestCredentialBackend;

impl GuestCredentialBackendHandler for ScriptedGuestCredentialBackend {
    fn handle(
        &self,
        _route: &d2b_session::AuthenticatedSessionRouteBinding,
        _user_ref: Option<&ResourceRef>,
        operation: &str,
        _fields: serde_json::Value,
    ) -> GuestCredentialBackendHandlerFuture<'_> {
        let operation = operation.to_owned();
        Box::pin(async move {
            let response = match operation.as_str() {
                "managed-identity.issue-lease" => GuestCredentialBackendReply::new(
                    Some("ready".to_owned()),
                    Some("backend-lease".to_owned()),
                    Some("backend-source".to_owned()),
                    Some(1),
                    Some(2_000),
                    None,
                    Some(zeroize::Zeroizing::new(vec![1, 2, 3, 4])),
                ),
                "managed-identity.inspect-lease" => GuestCredentialBackendReply::new(
                    Some("active".to_owned()),
                    Some("backend-lease".to_owned()),
                    Some("backend-source".to_owned()),
                    Some(1),
                    Some(2_000),
                    None,
                    None,
                ),
                "managed-identity.refresh-lease" => GuestCredentialBackendReply::new(
                    Some("ready".to_owned()),
                    Some("backend-lease".to_owned()),
                    Some("backend-source".to_owned()),
                    Some(2),
                    Some(3_000),
                    None,
                    Some(zeroize::Zeroizing::new(vec![5, 6, 7])),
                ),
                "managed-identity.revoke-lease" => GuestCredentialBackendReply::new(
                    Some("revoked".to_owned()),
                    Some("backend-lease".to_owned()),
                    Some("backend-source".to_owned()),
                    Some(1),
                    Some(2_000),
                    Some("revoked".to_owned()),
                    None,
                ),
                _ => return Err(GuestCredentialBackendHandlerError::Denied),
            };
        Ok(response)
        })
    }
}
