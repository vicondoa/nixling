//! Minimal authenticated controller used by the host acceptance fixture.

#![forbid(unsafe_code)]

use std::{
    collections::VecDeque,
    os::fd::OwnedFd,
    sync::Arc,
    time::{Duration, Instant},
};

use d2b_contracts_zone_session::v3::component_session::CloseReason;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionDisposition {
    Reconnect,
    Shutdown,
}

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
    loop {
        match run_session(&bootstrap, expected_peer).await? {
            SessionDisposition::Reconnect => tokio::time::sleep(Duration::from_millis(100)).await,
            SessionDisposition::Shutdown => return Ok(()),
        }
    }
}

async fn run_session(
    bootstrap: &SeqpacketSocket,
    expected_peer: d2b_session_unix::PeerCredentials,
) -> Result<SessionDisposition, ()> {
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
    let mut session = match SessionEngine::establish_initiator(
        transport,
        policy,
        HandshakeCredentials::Nn,
        Instant::now(),
    )
    .await
    {
        Ok(session) => session,
        Err(_) => return Err(()),
    };
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
            Ok(Ok(SessionEvent::Close(close))) => {
                return Ok(if should_reconnect(close.reason) {
                    SessionDisposition::Reconnect
                } else {
                    SessionDisposition::Shutdown
                });
            }
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
            Ok(Ok(SessionEvent::NamedStream(_))) => {
                return Ok(SessionDisposition::Reconnect);
            }
            Ok(Ok(_)) | Err(_) => {}
            Ok(Err(_)) => return Ok(SessionDisposition::Reconnect),
        }
        if session.drive_keepalive(Instant::now()).await.is_err() {
            return Ok(SessionDisposition::Reconnect);
        }
    }
}

fn should_reconnect(reason: CloseReason) -> bool {
    !matches!(reason, CloseReason::Normal | CloseReason::PeerRequested)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_loss_reconnects_but_peer_shutdown_is_graceful() {
        assert!(should_reconnect(CloseReason::RoleMismatch));
        assert!(should_reconnect(CloseReason::SessionLost));
        assert!(!should_reconnect(CloseReason::Normal));
        assert!(!should_reconnect(CloseReason::PeerRequested));
    }

    #[test]
    fn initial_handshake_failure_sends_one_bootstrap_then_is_terminal() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        runtime.block_on(async {
            let (bootstrap_fd, receiver_fd) =
                prearmed_seqpacket_pair().expect("bootstrap socketpair");
            let bootstrap =
                SeqpacketSocket::from_parent_prearmed(bootstrap_fd).expect("bootstrap sender");
            let receiver =
                SeqpacketSocket::from_parent_prearmed(receiver_fd).expect("bootstrap receiver");
            let expected_peer = bootstrap
                .acceptor_peer_credentials()
                .expect("bootstrap peer credentials");
            let policy = controller_bootstrap_attachment_policy();
            let capacity = AncillaryCapacity::from_policy(policy).expect("bootstrap capacity");
            let scopes = controller_credit_scopes().expect("bootstrap credit scopes");
            let mut session = Box::pin(run_session(&bootstrap, expected_peer));
            let mut receive = Box::pin(receiver.recv_burst(
                d2b_contracts_zone_session::v3::component_session::LimitProfile::local_default(),
                capacity,
                &scopes,
                2,
            ));
            let burst = tokio::select! {
                result = &mut session => panic!("handshake must wait for bootstrap delivery: {result:?}"),
                burst = &mut receive => burst.expect("bootstrap packet"),
            };
            assert_eq!(burst.packets.len(), 1);
            drop(burst);

            assert!(
                tokio::time::timeout(Duration::from_secs(1), &mut session)
                    .await
                    .expect("initial handshake must fail promptly")
                    .is_err(),
                "an initial handshake failure must be terminal"
            );
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(100),
                    receiver.recv_burst(
                        d2b_contracts_zone_session::v3::component_session::LimitProfile::local_default(),
                        capacity,
                        &scopes,
                        2,
                    ),
                )
                .await
                .is_err(),
                "a failed initial handshake must not send a second bootstrap"
            );
        });
    }
}
