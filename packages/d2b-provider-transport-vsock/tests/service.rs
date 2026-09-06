use async_trait::async_trait;
use d2b_contracts_resource::v3::{ResourceRef, ZoneId};
use d2b_provider_transport_vsock::{
    CLOSE_GRACE_MS, CloseTransportRequest, GuestIdentity, MAX_ACTIVE_TRANSPORTS, NamedStreamError,
    NamedStreamId, NamedStreamPort, OpaqueBindingId, OpaqueEndpointId, OpenTransportRequest,
    PeerCid, ReadySession, ServiceError, SessionAuthority, SessionKey, SessionProof,
    TransportPhase, TransportRole, VsockEffectError, VsockEffectPort, VsockTransportService,
};
use ring::rand::{SystemRandom, generate};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

fn nonce() -> [u8; 32] {
    generate::<[u8; 32]>(&SystemRandom::new()).unwrap().expose()
}

#[derive(Clone)]
struct FakeEffect {
    peers: Arc<Mutex<Vec<DuplexStream>>>,
    closes: Arc<Mutex<usize>>,
    open_delay: Option<Duration>,
    close_delay: Option<Duration>,
    hang_close: bool,
    fail_close: Arc<Mutex<bool>>,
}

#[async_trait]
impl VsockEffectPort for FakeEffect {
    type Stream = DuplexStream;

    async fn open(
        &self,
        _: &OpaqueEndpointId,
        _: &OpaqueBindingId,
        _: TransportRole,
        _: Instant,
    ) -> Result<Self::Stream, VsockEffectError> {
        if let Some(delay) = self.open_delay {
            tokio::time::sleep(delay).await;
        }
        let (local, peer) = duplex(1024);
        self.peers.lock().unwrap().push(peer);
        Ok(local)
    }

    async fn close(&self, _: Self::Stream) -> Result<(), VsockEffectError> {
        *self.closes.lock().unwrap() += 1;
        if self.hang_close {
            std::future::pending::<()>().await;
        }
        if let Some(delay) = self.close_delay {
            tokio::time::sleep(delay).await;
        }
        if *self.fail_close.lock().unwrap() {
            Err(VsockEffectError::Transient)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone)]
struct FakeStreams {
    next: Arc<Mutex<u64>>,
    closes: Arc<Mutex<usize>>,
    peers: Arc<Mutex<Vec<DuplexStream>>>,
    open_delay: Option<Duration>,
    close_delay: Option<Duration>,
    hang_close: bool,
}

#[async_trait]
impl NamedStreamPort for FakeStreams {
    type Stream = DuplexStream;

    async fn open_named_stream(&self) -> Result<(NamedStreamId, Self::Stream), NamedStreamError> {
        if let Some(delay) = self.open_delay {
            tokio::time::sleep(delay).await;
        }
        let mut next = self.next.lock().unwrap();
        *next += 1;
        let (local, peer) = duplex(1024);
        self.peers.lock().unwrap().push(peer);
        Ok((NamedStreamId::from_core(*next), local))
    }

    async fn close_named_stream(&self, _: NamedStreamId) -> Result<(), NamedStreamError> {
        *self.closes.lock().unwrap() += 1;
        if self.hang_close {
            std::future::pending::<()>().await;
        }
        if let Some(delay) = self.close_delay {
            tokio::time::sleep(delay).await;
        }
        Ok(())
    }
}

fn identity() -> GuestIdentity {
    GuestIdentity::new(
        ResourceRef::parse("Guest/guest-a").unwrap(),
        ZoneId::parse("work").unwrap(),
        PeerCid::from_core(42).unwrap(),
        "boot-a",
    )
    .unwrap()
}

fn session() -> ReadySession {
    session_at_generation(1)
}

fn session_at_generation(generation: u64) -> ReadySession {
    let identity = identity();
    let key = SessionKey::from_core([1; 32]);
    let mut authority = SessionAuthority::new(identity.clone(), key.clone(), generation);
    authority
        .authenticate(
            PeerCid::from_core(42).unwrap(),
            SessionProof::sign(&key, &identity, nonce(), generation),
        )
        .unwrap()
}

fn request() -> OpenTransportRequest {
    OpenTransportRequest::new(
        OpaqueEndpointId::parse("endpoint-a").unwrap(),
        OpaqueBindingId::parse("binding-a").unwrap(),
        TransportRole::Initiator,
        1_000,
    )
    .with_session_generation(1)
}

#[test]
fn ready_session_retains_the_core_generation_fence() {
    assert_eq!(session_at_generation(7).generation(), 7);
}

#[test]
fn open_rejects_a_mismatched_core_generation() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        let effect = FakeEffect {
            peers: Arc::new(Mutex::new(Vec::new())),
            closes: Arc::new(Mutex::new(0)),
            open_delay: None,
            close_delay: None,
            hang_close: false,
            fail_close: Arc::new(Mutex::new(false)),
        };
        let service = VsockTransportService::new(
            effect,
            FakeStreams {
                next: Arc::new(Mutex::new(0)),
                closes: Arc::new(Mutex::new(0)),
                peers: Arc::new(Mutex::new(Vec::new())),
                open_delay: None,
                close_delay: None,
                hang_close: false,
            },
            identity(),
        );
        assert_eq!(
            service
                .open_transport(
                    &session_at_generation(2),
                    request().with_session_generation(1)
                )
                .await
                .unwrap_err(),
            ServiceError::SessionGenerationMismatch
        );
        assert_eq!(
            service
                .open_transport(
                    &session_at_generation(2),
                    request().with_session_generation(0)
                )
                .await
                .unwrap_err(),
            ServiceError::InvalidSessionGeneration
        );
    });
}

#[test]
fn reconnect_reopens_only_carriage_for_the_new_core_generation() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        let effect = FakeEffect {
            peers: Arc::new(Mutex::new(Vec::new())),
            closes: Arc::new(Mutex::new(0)),
            open_delay: None,
            close_delay: None,
            hang_close: false,
            fail_close: Arc::new(Mutex::new(false)),
        };
        let effect_peers = Arc::clone(&effect.peers);
        let effect_closes = Arc::clone(&effect.closes);
        let service = VsockTransportService::new(
            effect,
            FakeStreams {
                next: Arc::new(Mutex::new(0)),
                closes: Arc::new(Mutex::new(0)),
                peers: Arc::new(Mutex::new(Vec::new())),
                open_delay: None,
                close_delay: None,
                hang_close: false,
            },
            identity(),
        );
        let first = service
            .open_transport(
                &session_at_generation(1),
                request().with_session_generation(1),
            )
            .await
            .unwrap();
        service
            .close_transport(CloseTransportRequest {
                transport_handle: first.transport_handle,
            })
            .await
            .unwrap();

        let second = service
            .open_transport(
                &session_at_generation(2),
                request().with_session_generation(2),
            )
            .await
            .unwrap();
        assert_ne!(first.transport_handle, second.transport_handle);
        assert_eq!(effect_peers.lock().unwrap().len(), 2);
        assert_eq!(*effect_closes.lock().unwrap(), 1);
        service
            .close_transport(CloseTransportRequest {
                transport_handle: second.transport_handle,
            })
            .await
            .unwrap();
        assert_eq!(*effect_closes.lock().unwrap(), 2);
    });
}

#[test]
fn open_observe_and_close_release_the_bridge() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        let effect = FakeEffect {
            peers: Arc::new(Mutex::new(Vec::new())),
            closes: Arc::new(Mutex::new(0)),
            open_delay: None,
            close_delay: None,
            hang_close: false,
            fail_close: Arc::new(Mutex::new(false)),
        };
        let effect_closes = Arc::clone(&effect.closes);
        let effect_peers = Arc::clone(&effect.peers);
        let streams = FakeStreams {
            next: Arc::new(Mutex::new(0)),
            closes: Arc::new(Mutex::new(0)),
            peers: Arc::new(Mutex::new(Vec::new())),
            open_delay: None,
            close_delay: None,
            hang_close: false,
        };
        let stream_closes = Arc::clone(&streams.closes);
        let stream_peers = Arc::clone(&streams.peers);
        let service = VsockTransportService::new(effect, streams, identity());
        let opened = service.open_transport(&session(), request()).await.unwrap();
        let mut effect_peer = effect_peers.lock().unwrap().pop().unwrap();
        let mut stream_peer = stream_peers.lock().unwrap().pop().unwrap();
        effect_peer.write_all(b"guest-to-core").await.unwrap();
        let mut received = [0_u8; 13];
        stream_peer.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"guest-to-core");
        stream_peer.write_all(b"core-to-guest").await.unwrap();
        let mut received = [0_u8; 13];
        effect_peer.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"core-to-guest");
        let observed = service
            .observe_snapshot(d2b_provider_transport_vsock::ObserveTransportRequest {
                transport_handle: opened.transport_handle,
                include_bytes: true,
            })
            .await
            .unwrap();
        assert_eq!(observed.phase, TransportPhase::Acquired);
        let mut events = service
            .observe_transport(d2b_provider_transport_vsock::ObserveTransportRequest {
                transport_handle: opened.transport_handle,
                include_bytes: true,
            })
            .await
            .unwrap();
        assert_eq!(
            events.recv().await,
            Some(d2b_provider_transport_vsock::TransportEvent::Acquired)
        );
        service
            .close_transport(d2b_provider_transport_vsock::CloseTransportRequest {
                transport_handle: opened.transport_handle,
            })
            .await
            .unwrap();
        loop {
            match events.recv().await {
                Some(d2b_provider_transport_vsock::TransportEvent::BytesTransferred {
                    rx_bytes,
                    tx_bytes,
                }) => {
                    assert_eq!((rx_bytes, tx_bytes), (13, 13));
                }
                Some(d2b_provider_transport_vsock::TransportEvent::Released) => break,
                Some(_) => {}
                None => panic!("event stream ended before release"),
            }
        }
        assert_eq!(*effect_closes.lock().unwrap(), 1);
        assert_eq!(*stream_closes.lock().unwrap(), 1);
        assert_eq!(
            service.phase().await,
            d2b_provider_transport_vsock::ServicePhase::Ready
        );
        assert_eq!(
            service
                .observe_snapshot(d2b_provider_transport_vsock::ObserveTransportRequest {
                    transport_handle: opened.transport_handle,
                    include_bytes: false,
                })
                .await
                .unwrap()
                .phase,
            TransportPhase::Released
        );
        assert_eq!(
            service
                .observe_snapshot(d2b_provider_transport_vsock::ObserveTransportRequest {
                    transport_handle: d2b_provider_transport_vsock::TransportHandle::from_core(999),
                    include_bytes: false,
                })
                .await
                .unwrap_err(),
            ServiceError::UnknownTransportHandle
        );
    });
}

#[test]
fn open_effect_is_bounded_by_the_request_deadline() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        let effect = FakeEffect {
            peers: Arc::new(Mutex::new(Vec::new())),
            closes: Arc::new(Mutex::new(0)),
            open_delay: Some(Duration::from_millis(1_100)),
            close_delay: None,
            hang_close: false,
            fail_close: Arc::new(Mutex::new(false)),
        };
        let service = VsockTransportService::new(
            effect,
            FakeStreams {
                next: Arc::new(Mutex::new(0)),
                closes: Arc::new(Mutex::new(0)),
                peers: Arc::new(Mutex::new(Vec::new())),
                open_delay: None,
                close_delay: None,
                hang_close: false,
            },
            identity(),
        );
        assert_eq!(
            service
                .open_transport(&session(), request())
                .await
                .unwrap_err(),
            ServiceError::Effect(VsockEffectError::DeadlineExceeded)
        );
    });
}

#[test]
fn named_stream_open_uses_remaining_end_to_end_deadline() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        let effect = FakeEffect {
            peers: Arc::new(Mutex::new(Vec::new())),
            closes: Arc::new(Mutex::new(0)),
            open_delay: Some(Duration::from_millis(850)),
            close_delay: None,
            hang_close: false,
            fail_close: Arc::new(Mutex::new(false)),
        };
        let service = VsockTransportService::new(
            effect,
            FakeStreams {
                next: Arc::new(Mutex::new(0)),
                closes: Arc::new(Mutex::new(0)),
                peers: Arc::new(Mutex::new(Vec::new())),
                open_delay: Some(Duration::from_millis(200)),
                close_delay: None,
                hang_close: false,
            },
            identity(),
        );

        assert_eq!(
            service
                .open_transport(&session(), request())
                .await
                .unwrap_err(),
            ServiceError::Effect(VsockEffectError::DeadlineExceeded)
        );
    });
}

#[test]
fn failed_endpoint_close_is_reported_as_degraded() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        let effect = FakeEffect {
            peers: Arc::new(Mutex::new(Vec::new())),
            closes: Arc::new(Mutex::new(0)),
            open_delay: None,
            close_delay: None,
            hang_close: false,
            fail_close: Arc::new(Mutex::new(true)),
        };
        let service = VsockTransportService::new(
            effect,
            FakeStreams {
                next: Arc::new(Mutex::new(0)),
                closes: Arc::new(Mutex::new(0)),
                peers: Arc::new(Mutex::new(Vec::new())),
                open_delay: None,
                close_delay: None,
                hang_close: false,
            },
            identity(),
        );
        let opened = service.open_transport(&session(), request()).await.unwrap();
        assert_eq!(
            service
                .close_transport(d2b_provider_transport_vsock::CloseTransportRequest {
                    transport_handle: opened.transport_handle,
                })
                .await
                .unwrap_err(),
            ServiceError::CloseUnconfirmed
        );
        assert_eq!(
            service
                .observe_snapshot(d2b_provider_transport_vsock::ObserveTransportRequest {
                    transport_handle: opened.transport_handle,
                    include_bytes: false,
                })
                .await
                .unwrap()
                .phase,
            TransportPhase::Degraded
        );
        assert_eq!(
            service.phase().await,
            d2b_provider_transport_vsock::ServicePhase::Degraded
        );
        assert_eq!(
            service
                .close_transport(d2b_provider_transport_vsock::CloseTransportRequest {
                    transport_handle: opened.transport_handle,
                })
                .await
                .unwrap_err(),
            ServiceError::CloseUnconfirmed
        );
        let mut events = service
            .observe_transport(d2b_provider_transport_vsock::ObserveTransportRequest {
                transport_handle: opened.transport_handle,
                include_bytes: false,
            })
            .await
            .unwrap();
        assert_eq!(
            events.recv().await,
            Some(d2b_provider_transport_vsock::TransportEvent::Error {
                kind: "close-unconfirmed",
                recoverable: true,
            })
        );
    });
}

#[test]
fn close_waits_for_both_endpoint_grace_periods() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        let effect = FakeEffect {
            peers: Arc::new(Mutex::new(Vec::new())),
            closes: Arc::new(Mutex::new(0)),
            open_delay: None,
            close_delay: Some(Duration::from_millis(CLOSE_GRACE_MS / 2 + 25)),
            hang_close: false,
            fail_close: Arc::new(Mutex::new(false)),
        };
        let streams = FakeStreams {
            next: Arc::new(Mutex::new(0)),
            closes: Arc::new(Mutex::new(0)),
            peers: Arc::new(Mutex::new(Vec::new())),
            open_delay: None,
            close_delay: Some(Duration::from_millis(CLOSE_GRACE_MS / 2 + 25)),
            hang_close: false,
        };
        let service = VsockTransportService::new(effect, streams, identity());
        let opened = service.open_transport(&session(), request()).await.unwrap();

        service
            .close_transport(d2b_provider_transport_vsock::CloseTransportRequest {
                transport_handle: opened.transport_handle,
            })
            .await
            .unwrap();
        assert_eq!(
            service
                .observe_snapshot(d2b_provider_transport_vsock::ObserveTransportRequest {
                    transport_handle: opened.transport_handle,
                    include_bytes: false,
                })
                .await
                .unwrap()
                .phase,
            TransportPhase::Released
        );
    });
}

#[test]
fn hung_endpoint_close_remains_degraded() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        let effect = FakeEffect {
            peers: Arc::new(Mutex::new(Vec::new())),
            closes: Arc::new(Mutex::new(0)),
            open_delay: None,
            close_delay: None,
            hang_close: true,
            fail_close: Arc::new(Mutex::new(false)),
        };
        let streams = FakeStreams {
            next: Arc::new(Mutex::new(0)),
            closes: Arc::new(Mutex::new(0)),
            peers: Arc::new(Mutex::new(Vec::new())),
            open_delay: None,
            close_delay: None,
            hang_close: false,
        };
        let service = VsockTransportService::new(effect, streams, identity());
        let opened = service.open_transport(&session(), request()).await.unwrap();

        assert_eq!(
            service
                .close_transport(d2b_provider_transport_vsock::CloseTransportRequest {
                    transport_handle: opened.transport_handle,
                })
                .await
                .unwrap_err(),
            ServiceError::CloseUnconfirmed
        );
        assert_eq!(
            service
                .observe_snapshot(d2b_provider_transport_vsock::ObserveTransportRequest {
                    transport_handle: opened.transport_handle,
                    include_bytes: false,
                })
                .await
                .unwrap()
                .phase,
            TransportPhase::Degraded
        );
    });
}

#[test]
fn degraded_close_survives_completed_observation_eviction() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        let effect = FakeEffect {
            peers: Arc::new(Mutex::new(Vec::new())),
            closes: Arc::new(Mutex::new(0)),
            open_delay: None,
            close_delay: None,
            hang_close: false,
            fail_close: Arc::new(Mutex::new(true)),
        };
        let fail_close = Arc::clone(&effect.fail_close);
        let service = VsockTransportService::new(
            effect,
            FakeStreams {
                next: Arc::new(Mutex::new(0)),
                closes: Arc::new(Mutex::new(0)),
                peers: Arc::new(Mutex::new(Vec::new())),
                open_delay: None,
                close_delay: None,
                hang_close: false,
            },
            identity(),
        );
        let degraded = service.open_transport(&session(), request()).await.unwrap();
        assert_eq!(
            service
                .close_transport(d2b_provider_transport_vsock::CloseTransportRequest {
                    transport_handle: degraded.transport_handle,
                })
                .await
                .unwrap_err(),
            ServiceError::CloseUnconfirmed
        );

        *fail_close.lock().unwrap() = false;
        for _ in 0..=MAX_ACTIVE_TRANSPORTS {
            let opened = service.open_transport(&session(), request()).await.unwrap();
            service
                .close_transport(d2b_provider_transport_vsock::CloseTransportRequest {
                    transport_handle: opened.transport_handle,
                })
                .await
                .unwrap();
        }

        assert_eq!(
            service
                .observe_snapshot(d2b_provider_transport_vsock::ObserveTransportRequest {
                    transport_handle: degraded.transport_handle,
                    include_bytes: false,
                })
                .await
                .unwrap()
                .phase,
            TransportPhase::Degraded
        );
        assert_eq!(
            service
                .close_transport(d2b_provider_transport_vsock::CloseTransportRequest {
                    transport_handle: degraded.transport_handle,
                })
                .await
                .unwrap_err(),
            ServiceError::CloseUnconfirmed
        );
    });
}
