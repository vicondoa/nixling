use d2b_contracts_resource::v3::{ResourceRef, ZoneId};
use d2b_provider_transport_unix::{
    BrokerRole, ExpectedPeer, OpenTransportRequest, PortalError, RouteClass, SocketKind,
    TransportPortal, TransportRequestBinding,
};
use rustix::{
    fd::AsFd,
    fs::fcntl_getfd,
    io::FdFlags,
    net::{
        AddressFamily, SocketFlags, SocketType, socketpair,
        sockopt::{get_socket_passcred, get_socket_type},
    },
    process::{getgid, getuid},
};

fn binding() -> TransportRequestBinding {
    TransportRequestBinding::new(
        ZoneId::parse("local-root").expect("zone"),
        ResourceRef::parse("Provider/system-core").expect("subject"),
        BrokerRole::ZoneController,
    )
}

fn pair(kind: SocketType) -> (rustix::fd::OwnedFd, rustix::fd::OwnedFd) {
    socketpair(
        AddressFamily::UNIX,
        kind,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .expect("socketpair")
}

#[test]
fn accepted_fd_peer_and_request_context_are_bound_once() {
    let (accepted, _peer) = pair(SocketType::SEQPACKET);
    let portal = TransportPortal::new();
    let opened = portal
        .open(
            binding(),
            OpenTransportRequest::new(SocketKind::Seqpacket, RouteClass::LocalPortal, true),
            accepted,
        )
        .expect("accepted request");

    assert_eq!(opened.descriptor().socket_kind(), SocketKind::Seqpacket);
    assert!(opened.descriptor().attachments_enabled());
    assert_eq!(
        get_socket_type(opened.transport_fd()).expect("socket type"),
        SocketType::SEQPACKET
    );
    assert!(
        get_socket_passcred(opened.transport_fd()).expect("passcred"),
        "seqpacket transport must accept only kernel credentials"
    );
    assert!(
        fcntl_getfd(opened.transport_fd())
            .expect("fd flags")
            .contains(FdFlags::CLOEXEC),
        "transport fd must not survive exec"
    );
    assert!(portal.close(opened.handle()).is_ok());
    assert!(portal.close(opened.handle()).is_ok(), "close is idempotent");
}

#[test]
fn peer_credentials_are_kernel_bound_and_wrong_peers_are_rejected() {
    let portal = TransportPortal::new();
    let expected = ExpectedPeer::new(getuid().as_raw(), getgid().as_raw());
    let (accepted, _peer) = pair(SocketType::SEQPACKET);
    let opened = portal
        .open(
            binding().with_expected_peer(expected),
            OpenTransportRequest::new(SocketKind::Seqpacket, RouteClass::LocalPortal, false),
            accepted,
        )
        .expect("current process peer credentials");
    portal.close(opened.handle()).expect("close accepted peer");

    let (wrong_peer, _peer) = pair(SocketType::SEQPACKET);
    let wrong = ExpectedPeer::new(expected.uid().saturating_add(1), expected.gid());
    assert_eq!(
        portal
            .open(
                binding().with_expected_peer(wrong),
                OpenTransportRequest::new(SocketKind::Seqpacket, RouteClass::LocalPortal, false),
                wrong_peer,
            )
            .expect_err("mismatched kernel peer must fail closed"),
        PortalError::PeerCredentials
    );
}

#[test]
fn route_class_and_socket_kind_refuse_fd_substitution() {
    let portal = TransportPortal::new();
    let (stream, _peer) = pair(SocketType::STREAM);
    assert_eq!(
        portal
            .open(
                binding(),
                OpenTransportRequest::new(SocketKind::Seqpacket, RouteClass::LocalPortal, false),
                stream,
            )
            .expect_err("stream cannot satisfy seqpacket request"),
        PortalError::SocketKindMismatch
    );

    let (seqpacket, _peer) = pair(SocketType::SEQPACKET);
    assert_eq!(
        portal
            .open(
                binding(),
                OpenTransportRequest::new(SocketKind::Seqpacket, RouteClass::ZoneLink, true),
                seqpacket,
            )
            .expect_err("ZoneLink fd grants are forbidden"),
        PortalError::AttachmentPolicyConflict
    );

    let (stream, _peer) = pair(SocketType::STREAM);
    assert_eq!(
        portal
            .open(
                binding(),
                OpenTransportRequest::new(SocketKind::Stream, RouteClass::LocalPortal, true),
                stream,
            )
            .expect_err("stream cannot carry SCM_RIGHTS"),
        PortalError::AttachmentPolicyConflict
    );
}

#[test]
fn finalization_retires_only_portal_owned_monitor_fds() {
    let portal = TransportPortal::new();
    let (accepted, peer) = pair(SocketType::SEQPACKET);
    let opened = portal
        .open(
            binding(),
            OpenTransportRequest::new(SocketKind::Seqpacket, RouteClass::LocalPortal, false),
            accepted,
        )
        .expect("open transport");
    let handle = opened.handle();
    drop(opened);

    portal.finalize();
    assert_eq!(portal.observe(handle), Err(PortalError::UnknownHandle));
    assert_eq!(
        get_socket_type(peer.as_fd()).expect("peer remains caller-owned"),
        SocketType::SEQPACKET
    );
}

#[test]
fn portal_refuses_foreign_or_stale_handles_and_observes_disconnects() {
    let portal = TransportPortal::new();
    let foreign_portal = TransportPortal::new();
    let (accepted, peer) = pair(SocketType::SEQPACKET);
    let opened = portal
        .open(
            binding(),
            OpenTransportRequest::new(SocketKind::Seqpacket, RouteClass::LocalPortal, false),
            accepted,
        )
        .expect("open transport");
    let handle = opened.handle();

    assert_eq!(
        foreign_portal.close(handle),
        Err(PortalError::UnknownHandle),
        "a handle cannot authorize another portal"
    );
    drop(peer);
    assert_eq!(
        portal.observe(handle),
        Ok(d2b_provider_transport_unix::TransportObservation::PeerDisconnected)
    );
    portal.close(handle).expect("owner closes handle");
    assert_eq!(
        portal.observe(handle),
        Err(PortalError::UnknownHandle),
        "a finalized handle cannot be replayed"
    );
}

#[test]
fn open_refuses_a_full_handle_table_then_recovers_after_close() {
    let portal = TransportPortal::new();
    let mut opened = Vec::new();
    for _ in 0..256 {
        let (accepted, _peer) = pair(SocketType::SEQPACKET);
        opened.push(
            portal
                .open(
                    binding(),
                    OpenTransportRequest::new(
                        SocketKind::Seqpacket,
                        RouteClass::LocalPortal,
                        false,
                    ),
                    accepted,
                )
                .expect("open within table bound"),
        );
    }

    let (overflow, peer) = pair(SocketType::SEQPACKET);
    assert_eq!(
        portal
            .open(
                binding(),
                OpenTransportRequest::new(SocketKind::Seqpacket, RouteClass::LocalPortal, false),
                overflow,
            )
            .expect_err("full table must refuse"),
        PortalError::HandleTableFull
    );
    drop(peer);

    let released = opened.pop().expect("occupied table");
    portal.close(released.handle()).expect("release one handle");

    let (accepted, _peer) = pair(SocketType::SEQPACKET);
    let recovered = portal
        .open(
            binding(),
            OpenTransportRequest::new(SocketKind::Seqpacket, RouteClass::LocalPortal, false),
            accepted,
        )
        .expect("close must free a table slot");
    assert!(portal.close(recovered.handle()).is_ok());
}
