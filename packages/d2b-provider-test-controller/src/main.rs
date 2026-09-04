//! Minimal authenticated controller used by the host acceptance fixture.

#![forbid(unsafe_code)]

use std::{
    collections::VecDeque,
    os::fd::OwnedFd,
    sync::Arc,
    time::{Duration, Instant},
};

use d2b_core_controller::{CONTROLLER_ASSIGNMENT_STREAM_CREDIT, CONTROLLER_ASSIGNMENT_STREAM_ID};
use d2b_session::{HandshakeCredentials, SessionEngine, SessionEvent, StreamEvent, StreamId};
use d2b_session_unix::{
    AncillaryCapacity, CONTROLLER_BOOTSTRAP_TIMEOUT, DescriptorPolicyResolver, PeerIdentityPolicy,
    SeqpacketSocket, UnixSeqpacketTransport, UnixSessionError,
    controller_bootstrap_attachment_policy, controller_credit_scopes,
    controller_resource_endpoint_policy, prearmed_seqpacket_pair,
};

const CONTROLLER_BOOTSTRAP_FD: i32 = 10;
const RUNTIME_FAILURE_EXIT: i32 = 78;

fn main() {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => std::process::exit(RUNTIME_FAILURE_EXIT),
    };
    if runtime.block_on(run()).is_err() {
        std::process::exit(RUNTIME_FAILURE_EXIT);
    }
}

async fn run() -> Result<(), ()> {
    let bootstrap = SeqpacketSocket::from_inherited_fd(CONTROLLER_BOOTSTRAP_FD).map_err(|_| ())?;
    let expected_peer = bootstrap.acceptor_peer_credentials().map_err(|_| ())?;
    let policy = controller_resource_endpoint_policy();
    let poll_interval = Duration::from_millis(u64::from(
        policy
            .limits
            .keepalive_interval_ms
            .min(policy.limits.keepalive_timeout_ms),
    ));
    let (daemon_endpoint, controller_endpoint) = prearmed_seqpacket_pair().map_err(|_| ())?;
    let controller_socket =
        SeqpacketSocket::from_parent_prearmed(controller_endpoint).map_err(|_| ())?;
    send_bootstrap(&bootstrap, daemon_endpoint).await?;
    let transport = controller_transport(controller_socket, &policy, expected_peer)?;
    let mut session = SessionEngine::establish_initiator(
        transport,
        policy,
        HandshakeCredentials::Nn,
        Instant::now(),
    )
    .await
    .map_err(|_| ())?;
    let assignment_stream = StreamId::new(CONTROLLER_ASSIGNMENT_STREAM_ID).map_err(|_| ())?;
    session
        .open_named_stream(
            assignment_stream,
            CONTROLLER_ASSIGNMENT_STREAM_CREDIT,
            CONTROLLER_ASSIGNMENT_STREAM_CREDIT,
        )
        .map_err(|_| ())?;

    loop {
        match tokio::time::timeout(poll_interval, session.receive()).await {
            Ok(Ok(SessionEvent::Close(_))) => return Ok(()),
            Ok(Ok(SessionEvent::NamedStream(StreamEvent::Data { stream, bytes })))
                if stream == assignment_stream =>
            {
                let byte_count = u32::try_from(bytes.len()).map_err(|_| ())?;
                session
                    .grant_named_stream_credit(assignment_stream, byte_count)
                    .await
                    .map_err(|_| ())?;
            }
            Ok(Ok(SessionEvent::NamedStream(StreamEvent::Reset { stream })))
                if stream == assignment_stream =>
            {
                session
                    .open_named_stream(
                        assignment_stream,
                        CONTROLLER_ASSIGNMENT_STREAM_CREDIT,
                        CONTROLLER_ASSIGNMENT_STREAM_CREDIT,
                    )
                    .map_err(|_| ())?;
            }
            Ok(Ok(SessionEvent::NamedStream(_))) => return Err(()),
            Ok(Ok(_)) | Err(_) => {}
            Ok(Err(_)) => return Ok(()),
        }
        session
            .drive_keepalive(Instant::now())
            .await
            .map_err(|_| ())?;
    }
}

async fn send_bootstrap(bootstrap: &SeqpacketSocket, daemon_endpoint: OwnedFd) -> Result<(), ()> {
    let policy = controller_bootstrap_attachment_policy();
    let capacity = AncillaryCapacity::from_policy(policy).map_err(|_| ())?;
    let scopes = controller_credit_scopes().map_err(|_| ())?;
    let packet = d2b_session_unix::OutboundPacket::with_current_credentials(
        d2b_session_unix::CONTROLLER_BOOTSTRAP_PROTOCOL_MARKER.to_vec(),
        vec![Arc::new(daemon_endpoint)],
        d2b_contracts_zone_session::v3::component_session::LimitProfile::local_default(),
        capacity,
        &scopes,
    )
    .map_err(|_| ())?;
    let mut queue = VecDeque::from([packet]);
    let sent = tokio::time::timeout(
        CONTROLLER_BOOTSTRAP_TIMEOUT,
        bootstrap.send_burst(&mut queue, capacity, 1),
    )
    .await
    .map_err(|_| ())?
    .map_err(|_| ())?;
    if sent.sent.len() != 1 || !queue.is_empty() {
        return Err(());
    }
    for packet in sent.sent {
        packet.acknowledge();
    }
    Ok(())
}

fn controller_transport(
    socket: SeqpacketSocket,
    policy: &d2b_contracts_zone_session::v3::component_session::EndpointPolicy,
    expected_peer: d2b_session_unix::PeerCredentials,
) -> Result<UnixSeqpacketTransport, ()> {
    let resolver: DescriptorPolicyResolver =
        Arc::new(|_| Err(UnixSessionError::DescriptorMismatch));
    UnixSeqpacketTransport::new(
        socket,
        policy.transport_binding.locality,
        policy.limits,
        policy.attachment_policy,
        controller_credit_scopes().map_err(|_| ())?,
        resolver,
        PeerIdentityPolicy::inherited_socketpair(expected_peer),
    )
    .map_err(|_| ())
}
