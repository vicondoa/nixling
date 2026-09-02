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
    EndpointRole, EndpointRole as ComponentEndpointRole,
    Locality as ComponentLocality, PurposeClass, TransportClass,
};
use d2b_provider_toolkit::{
    PROVIDER_BOOTSTRAP_STREAM_CREDIT, PROVIDER_BOOTSTRAP_STREAM_ID, ProviderSessionMetadata,
};
use d2b_session::{
    ComponentSessionDriver, HandshakeCredentials, SessionEngine, StreamId,
};
use d2b_session_unix::{
    AncillaryCapacity, CreditPool, CreditScopeSet, DescriptorPolicyResolver,
    PeerIdentityPolicy, SeqpacketSocket, UnixSeqpacketTransport, UnixSessionError,
    controller_bootstrap_attachment_policy, controller_credit_scopes,
    credential_provider_endpoint_policy, duplicate_to_inherited_fd, prearmed_seqpacket_pair,
};

fn route(provider: &str) -> d2b_session::AuthenticatedSessionRouteBinding {
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
    .with_execution_ref(ResourceRef::parse("Host/test").expect("Host reference"))
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

fn run_supervised_binary(path: &str, provider: &str) {
    let (bootstrap_fd, child_fd) = prearmed_seqpacket_pair().expect("bootstrap pair");
    let inherited = duplicate_to_inherited_fd(&child_fd, 200).expect("inherited fd");
    let mut child = Command::new("sh")
        .arg("-c")
        .arg("exec 10<&200; exec \"$1\"")
        .arg("d2b-provider-supervised-test")
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("provider binary");
    drop(inherited);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");
    let driver = runtime.block_on(async {
        let bootstrap = SeqpacketSocket::from_parent_prearmed(bootstrap_fd).expect("bootstrap");
        let (resource_socket, credentials) =
            receive_bootstrap(&bootstrap).await.expect("bootstrap receive");
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
