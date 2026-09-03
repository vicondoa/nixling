use std::{
    collections::HashMap,
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
    GUEST_CREDENTIAL_BACKEND_FD, GuestCredentialBackend, PROVIDER_BOOTSTRAP_STREAM_CREDIT,
    PROVIDER_BOOTSTRAP_STREAM_ID, PROVIDER_READY_MARKER, PROVIDER_READY_STREAM_CREDIT,
    PROVIDER_READY_STREAM_ID, ProviderSessionMetadata, credential_delivery_credentials,
};
use d2b_session::{
    ComponentSessionDriver, HandshakeCredentials, SessionEngine, StreamEvent, StreamId,
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
    let subject_ref = if provider.ends_with("secret-service") {
        ResourceRef::parse("User/provider-controller").expect("User reference")
    } else {
        provider_ref.clone()
    };
    let digest = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
    let context = AuthenticatedSubjectContext::new(
        subject_ref,
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
    let (_backend_peer, backend_child) = prearmed_seqpacket_pair().expect("backend pair");
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
        let (resource_socket, credentials) = receive_bootstrap(&bootstrap)
            .await
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
        let metadata = ProviderSessionMetadata::from_route(&route(provider))
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
            match driver
                .receive_named_stream_for(ready_stream)
                .await
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
        run_supervised_binary(path, provider);
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
        let backend =
            GuestCredentialBackend::from_socket_for_test_with_route(client_socket, route.clone())
                .expect("Guest route");
        let credentials = server_socket
            .acceptor_peer_credentials()
            .expect("backend peer credentials");
        let policy = credential_delivery_endpoint_policy(route.reconnect_generation().get());
        let serving = tokio::spawn(async move {
            let responder = SessionEngine::establish_responder(
                delivery_transport(server_socket, credentials),
                policy,
                credential_delivery_credentials(&route, false).expect("delivery credentials"),
                std::time::Instant::now(),
            )
            .await
            .expect("delivery handshake");
            let driver = std::sync::Arc::new(responder.into_driver());
            let handler = BackendHandler;
            let service = ttrpc::r#async::Service {
                methods: HashMap::from([(
                    "Request".to_owned(),
                    Box::new(handler)
                        as Box<dyn ttrpc::r#async::MethodHandler + Send + Sync>,
                )]),
                streams: HashMap::new(),
            };
            d2b_session::serve_ttrpc_services(
                driver,
                HashMap::from([(
                    "d2b.guest.credential.v1.GuestCredentialBackend".to_owned(),
                    service,
                )]),
            )
            .await
        });
        let response = backend
            .request(
                "managed-identity.issue-lease",
                serde_json::json!({"credentialRef": "Credential/test"}),
            )
            .await
            .expect("backend response");
        assert_eq!(response.state(), Some("ready"));
        assert!(!format!("{response:?}").contains("1, 2, 3, 4"));
        assert_eq!(response.into_bytes().expect("response bytes").as_slice(), [1, 2, 3, 4]);
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
                "managed-identity.revoke-lease",
                serde_json::json!({"credentialRef": "Credential/test"}),
            )
            .await
            .expect("revocation response");
        assert_eq!(response.outcome(), Some("revoked"));
        assert!(response.into_bytes().is_none());
        serving.abort();
        let _ = serving.await;
    });
}

struct BackendHandler;

#[async_trait::async_trait]
impl ttrpc::r#async::MethodHandler for BackendHandler {
    async fn handler(
        &self,
        _context: ttrpc::r#async::TtrpcContext,
        request: ttrpc::Request,
    ) -> ttrpc::Result<ttrpc::Response> {
        let request: serde_json::Value =
            serde_json::from_slice(&request.payload).expect("backend request");
        let operation = request
            .get("operation")
            .and_then(serde_json::Value::as_str)
            .expect("operation");
        let mut response = serde_json::json!({
            "protocol": "d2b-guest-credential-backend-v1",
            "state": "ready",
            "leaseHandle": "backend-lease",
            "sourceVersion": "backend-source",
            "rotationGeneration": 1,
            "expiresAtUnixMs": 2_000,
        });
        match operation {
            "managed-identity.issue-lease" => {
                response["bytes"] = serde_json::json!([1, 2, 3, 4]);
            }
            "managed-identity.inspect-lease" => {
                response["state"] = serde_json::json!("active");
            }
            "managed-identity.revoke-lease" => {
                response["outcome"] = serde_json::json!("revoked");
            }
            other => panic!("unexpected operation {other}"),
        }
        let payload = serde_json::to_vec(&response).expect("backend response");
        let mut response = ttrpc::Response::new();
        response.set_status(ttrpc::get_status(ttrpc::Code::OK, ""));
        response.payload = payload;
        Ok(response)
    }
}
