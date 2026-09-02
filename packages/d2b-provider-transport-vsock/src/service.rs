//! Authenticated vsock transport service lifecycle.

use crate::{
    ReadySession,
    bridge::{
        BridgeControl, BridgeExit, BridgeStats, NamedStreamError, NamedStreamId, NamedStreamPort,
        TransportHandle, run_bridge,
    },
    effect_port::{OpaqueBindingId, OpaqueEndpointId, TransportRole, VsockEffectPort},
    errors::{ServiceError, VsockEffectError},
    framing::VsockTransportDescriptor,
    limits::{CLOSE_GRACE_MS, MAX_ACTIVE_TRANSPORTS, MAX_OPEN_DEADLINE_MS, MIN_OPEN_DEADLINE_MS},
};
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc},
    time::timeout,
};

const PROVIDER_REF: &str = "Provider/transport-vsock";
const CLOSE_COMPLETION_BUDGET_MS: u64 = CLOSE_GRACE_MS * 2;

/// Request to open one ZoneLink byte transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenTransportRequest {
    /// Core-issued endpoint resolution identity.
    pub endpoint_id: OpaqueEndpointId,
    /// Core-issued binding identity.
    pub binding_id: OpaqueBindingId,
    /// Initiator or responder role.
    pub role: TransportRole,
    /// Bounded connect/accept deadline.
    pub deadline_ms: u32,
    /// Optional Core-owned reconnect generation fence.
    pub session_generation: Option<u64>,
}

impl OpenTransportRequest {
    /// Construct an open request.
    pub const fn new(
        endpoint_id: OpaqueEndpointId,
        binding_id: OpaqueBindingId,
        role: TransportRole,
        deadline_ms: u32,
    ) -> Self {
        Self {
            endpoint_id,
            binding_id,
            role,
            deadline_ms,
            session_generation: None,
        }
    }

    /// Bind this request to the Core-owned reconnect generation.
    #[must_use]
    pub const fn with_session_generation(mut self, generation: u64) -> Self {
        self.session_generation = Some(generation);
        self
    }

    /// Parse a wire-shaped request at the service boundary.
    pub fn from_raw(
        endpoint_id: impl Into<String>,
        binding_id: impl Into<String>,
        role: TransportRole,
        deadline_ms: u32,
    ) -> Result<Self, ServiceError> {
        let endpoint_id =
            OpaqueEndpointId::parse(endpoint_id).map_err(|_| ServiceError::InvalidEndpointId)?;
        let binding_id =
            OpaqueBindingId::parse(binding_id).map_err(|_| ServiceError::InvalidBindingId)?;
        Ok(Self::new(endpoint_id, binding_id, role, deadline_ms))
    }

    fn validate(&self) -> Result<(), ServiceError> {
        if !(MIN_OPEN_DEADLINE_MS..=MAX_OPEN_DEADLINE_MS).contains(&self.deadline_ms) {
            return Err(ServiceError::InvalidDeadline);
        }
        if self.session_generation == Some(0) {
            return Err(ServiceError::InvalidSessionGeneration);
        }
        Ok(())
    }
}

/// Result of opening one transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenTransportResponse {
    /// Opaque handle used by CloseTransport and ObserveTransport.
    pub transport_handle: TransportHandle,
    /// ComponentSession named stream carrying the bridge bytes.
    pub stream_id: NamedStreamId,
    /// Native-vsock transport descriptor.
    pub descriptor: VsockTransportDescriptor,
}

/// Request to close one transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseTransportRequest {
    /// Handle returned by OpenTransport.
    pub transport_handle: TransportHandle,
}

/// Request to observe one transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObserveTransportRequest {
    /// Handle returned by OpenTransport.
    pub transport_handle: TransportHandle,
    /// Include bounded byte counters in the response.
    pub include_bytes: bool,
}

/// Bounded lifecycle event emitted by ObserveTransport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportEvent {
    /// The effect stream and named stream were acquired.
    Acquired,
    /// Bounded byte counters for one observation interval.
    BytesTransferred {
        /// Bytes received from the vsock side.
        rx_bytes: u64,
        /// Bytes sent to the vsock side.
        tx_bytes: u64,
    },
    /// A bridge error occurred.
    Error {
        /// Closed error class.
        kind: &'static str,
        /// Whether the owner may reopen the transport.
        recoverable: bool,
    },
    /// The bridge and both endpoints were released.
    Released,
}

/// Provider lifecycle phase for one transport handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportPhase {
    /// The effect and named stream were acquired.
    Acquired,
    /// The owner requested closure.
    Closing,
    /// The bridge and both endpoints are closed.
    Released,
    /// Closure could not be confirmed within the bound.
    Degraded,
}

/// Bounded observation returned by ObserveTransport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportObservation {
    /// Current lifecycle phase.
    pub phase: TransportPhase,
    /// Fixed provider descriptor.
    pub descriptor: VsockTransportDescriptor,
    /// Bytes received from the vsock side when requested.
    pub bytes_rx: Option<u64>,
    /// Bytes sent to the vsock side when requested.
    pub bytes_tx: Option<u64>,
    /// Last bridge termination reason.
    pub last_exit: Option<BridgeExit>,
}

/// Provider service readiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServicePhase {
    /// The service has no active transport.
    Ready,
    /// At least one transport is active.
    Serving,
    /// One transport failed bounded closure.
    Degraded,
}

type EventSubscriber = (bool, mpsc::Sender<TransportEvent>);
type EventSubscribers = Arc<Mutex<Vec<EventSubscriber>>>;

/// The single transport-vsock service component for one Zone.
pub struct VsockTransportService<P, N>
where
    P: VsockEffectPort,
    N: NamedStreamPort,
{
    effect: Arc<P>,
    streams: Arc<N>,
    expected_identity: crate::GuestIdentity,
    active: Arc<Mutex<HashMap<TransportHandle, TransportEntry>>>,
    completed: Arc<Mutex<HashMap<TransportHandle, TransportObservation>>>,
    slots: Arc<Semaphore>,
    next_handle: AtomicU64,
}

struct TransportEntry {
    control: BridgeControl,
    abort: tokio::task::AbortHandle,
    subscribers: EventSubscribers,
    history: Arc<Mutex<Vec<TransportEvent>>>,
    phase: Arc<Mutex<TransportPhase>>,
    exit: Arc<Mutex<Option<BridgeExit>>>,
    stats: Arc<BridgeStats>,
    _permit: OwnedSemaphorePermit,
}

impl<P, N> VsockTransportService<P, N>
where
    P: VsockEffectPort,
    N: NamedStreamPort,
{
    /// Construct a service over the child-core effect and stream ports.
    pub fn new(effect: P, streams: N, expected_identity: crate::GuestIdentity) -> Self {
        Self {
            effect: Arc::new(effect),
            streams: Arc::new(streams),
            expected_identity,
            active: Arc::new(Mutex::new(HashMap::new())),
            completed: Arc::new(Mutex::new(HashMap::new())),
            slots: Arc::new(Semaphore::new(MAX_ACTIVE_TRANSPORTS)),
            next_handle: AtomicU64::new(1),
        }
    }

    /// Return the stable Provider reference.
    pub const fn provider_ref(&self) -> &'static str {
        PROVIDER_REF
    }

    /// Return the current service phase.
    pub async fn phase(&self) -> ServicePhase {
        let active_degraded = self
            .active
            .lock()
            .await
            .values()
            .any(futures_phase_is_degraded);
        if active_degraded {
            ServicePhase::Degraded
        } else {
            let completed_degraded = {
                let completed = self.completed.lock().await;
                completed
                    .values()
                    .any(|observation| observation.phase == TransportPhase::Degraded)
            };
            if completed_degraded {
                ServicePhase::Degraded
            } else {
                let active_empty = self.active.lock().await.is_empty();
                if active_empty {
                    ServicePhase::Ready
                } else {
                    ServicePhase::Serving
                }
            }
        }
    }

    /// Open one authenticated transport and its named stream bridge.
    pub async fn open_transport(
        &self,
        session: &ReadySession,
        request: OpenTransportRequest,
    ) -> Result<OpenTransportResponse, ServiceError> {
        self.reap_released().await;
        if session.state() != crate::SessionState::Ready {
            return Err(ServiceError::SessionNotReady);
        }
        if !session.matches(&self.expected_identity) {
            return Err(ServiceError::SessionIdentityMismatch);
        }
        request.validate()?;
        if request
            .session_generation
            .is_some_and(|generation| generation != session.generation())
        {
            return Err(ServiceError::SessionGenerationMismatch);
        }
        let permit = Arc::clone(&self.slots)
            .try_acquire_owned()
            .map_err(|_| ServiceError::ProviderOverloaded)?;
        let deadline = Instant::now() + Duration::from_millis(u64::from(request.deadline_ms));
        let effect_stream = timeout(
            remaining_until(deadline),
            self.effect.open(
                &request.endpoint_id,
                &request.binding_id,
                request.role,
                deadline,
            ),
        )
        .await
        .map_err(|_| ServiceError::Effect(VsockEffectError::DeadlineExceeded))?
        .map_err(ServiceError::Effect)?;
        let (stream_id, named_stream) =
            match timeout(remaining_until(deadline), self.streams.open_named_stream()).await {
                Ok(Ok(value)) => value,
                Ok(Err(_)) => {
                    let closed =
                        timeout(remaining_until(deadline), self.effect.close(effect_stream))
                            .await
                            .is_ok_and(|result| result.is_ok());
                    return Err(if closed {
                        ServiceError::StreamUnavailable
                    } else {
                        ServiceError::CloseUnconfirmed
                    });
                }
                Err(_) => {
                    let closed =
                        timeout(remaining_until(deadline), self.effect.close(effect_stream))
                            .await
                            .is_ok_and(|result| result.is_ok());
                    return Err(if closed {
                        ServiceError::Effect(VsockEffectError::DeadlineExceeded)
                    } else {
                        ServiceError::CloseUnconfirmed
                    });
                }
            };
        let handle = TransportHandle::from_core(self.next_handle.fetch_add(1, Ordering::Relaxed));
        let (control, stop) = BridgeControl::new();
        let task_control = control.clone();
        let phase = Arc::new(Mutex::new(TransportPhase::Acquired));
        let exit = Arc::new(Mutex::new(None));
        let stats = Arc::new(BridgeStats::default());
        let subscribers = Arc::new(Mutex::new(Vec::new()));
        let history = Arc::new(Mutex::new(vec![TransportEvent::Acquired]));
        let task_effect = Arc::clone(&self.effect);
        let task_streams = Arc::clone(&self.streams);
        let task_phase = Arc::clone(&phase);
        let task_exit = Arc::clone(&exit);
        let task_stats = Arc::clone(&stats);
        let task_subscribers = Arc::clone(&subscribers);
        let task_history = Arc::clone(&history);
        let task = tokio::spawn(async move {
            let (effect_stream, _named_stream, reason) =
                run_bridge(effect_stream, named_stream, stop, Arc::clone(&task_stats)).await;
            let effect_result = timeout(
                Duration::from_millis(CLOSE_GRACE_MS),
                task_effect.close(effect_stream),
            )
            .await
            .is_ok_and(|result| result.is_ok());
            let stream_result = timeout(
                Duration::from_millis(CLOSE_GRACE_MS),
                task_streams.close_named_stream(stream_id),
            )
            .await
            .is_ok_and(|result| result.is_ok());
            *task_exit.lock().await = Some(reason);
            if reason == BridgeExit::IoError {
                emit_event(
                    &task_subscribers,
                    &task_history,
                    TransportEvent::Error {
                        kind: "bridge-io",
                        recoverable: false,
                    },
                )
                .await;
            } else {
                let rx_bytes = task_stats.bytes_from_vsock();
                let tx_bytes = task_stats.bytes_to_vsock();
                if rx_bytes != 0 || tx_bytes != 0 {
                    emit_event(
                        &task_subscribers,
                        &task_history,
                        TransportEvent::BytesTransferred { rx_bytes, tx_bytes },
                    )
                    .await;
                }
            }
            let released = effect_result && stream_result;
            *task_phase.lock().await = if released {
                TransportPhase::Released
            } else {
                TransportPhase::Degraded
            };
            if released {
                emit_event(&task_subscribers, &task_history, TransportEvent::Released).await;
            } else {
                emit_event(
                    &task_subscribers,
                    &task_history,
                    TransportEvent::Error {
                        kind: "close-unconfirmed",
                        recoverable: true,
                    },
                )
                .await;
            }
            task_control.mark_completed();
        });
        let abort = task.abort_handle();
        self.active.lock().await.insert(
            handle,
            TransportEntry {
                control,
                abort,
                subscribers,
                history,
                phase,
                exit,
                stats,
                _permit: permit,
            },
        );
        Ok(OpenTransportResponse {
            transport_handle: handle,
            stream_id,
            descriptor: VsockTransportDescriptor::default(),
        })
    }

    /// Close one transport. The bridge closes before the effect is released.
    pub async fn close_transport(
        &self,
        request: CloseTransportRequest,
    ) -> Result<(), ServiceError> {
        let entry = {
            let active = self.active.lock().await;
            active
                .get(&request.transport_handle)
                .map(|entry| (entry.control.clone(), Arc::clone(&entry.phase)))
        };
        if let Some(observation) = self
            .completed
            .lock()
            .await
            .get(&request.transport_handle)
            .copied()
        {
            if observation.phase == TransportPhase::Degraded {
                return Err(ServiceError::CloseUnconfirmed);
            }
            return Ok(());
        }
        let Some((completion, phase)) = entry else {
            return Err(ServiceError::UnknownTransportHandle);
        };
        if *phase.lock().await == TransportPhase::Released {
            if let Some(entry) = self.active.lock().await.remove(&request.transport_handle) {
                self.remember_completed(request.transport_handle, entry)
                    .await;
            }
            return Ok(());
        }
        let entry_to_stop = {
            let active = self.active.lock().await;
            active
                .get(&request.transport_handle)
                .map(|entry| (entry.control.clone(), Arc::clone(&entry.phase)))
        };
        if let Some((control, phase)) = entry_to_stop {
            let mut entry_phase = phase.lock().await;
            if *entry_phase != TransportPhase::Degraded {
                control.stop();
                *entry_phase = TransportPhase::Closing;
            }
        }
        if timeout(
            Duration::from_millis(CLOSE_COMPLETION_BUDGET_MS),
            completion.wait(),
        )
        .await
        .is_err()
        {
            let entry = self.active.lock().await.remove(&request.transport_handle);
            if let Some(entry) = entry {
                entry.abort.abort();
                *entry.phase.lock().await = TransportPhase::Degraded;
                self.remember_completed(request.transport_handle, entry)
                    .await;
            }
            return Err(ServiceError::CloseUnconfirmed);
        }
        let degraded = *phase.lock().await == TransportPhase::Degraded;
        if let Some(entry) = self.active.lock().await.remove(&request.transport_handle) {
            self.remember_completed(request.transport_handle, entry)
                .await;
        }
        if degraded {
            Err(ServiceError::CloseUnconfirmed)
        } else {
            Ok(())
        }
    }

    /// Observe one transport snapshot without exposing identity, path, CID, or port.
    pub async fn observe_snapshot(
        &self,
        request: ObserveTransportRequest,
    ) -> Result<TransportObservation, ServiceError> {
        let active = self.active.lock().await;
        let Some(entry) = active.get(&request.transport_handle) else {
            drop(active);
            let observation = self
                .completed
                .lock()
                .await
                .get(&request.transport_handle)
                .copied()
                .ok_or(ServiceError::UnknownTransportHandle)?;
            return Ok(if request.include_bytes {
                observation
            } else {
                TransportObservation {
                    bytes_rx: None,
                    bytes_tx: None,
                    ..observation
                }
            });
        };
        let phase = *entry.phase.lock().await;
        let stats = if request.include_bytes {
            Some((entry.stats.bytes_from_vsock(), entry.stats.bytes_to_vsock()))
        } else {
            None
        };
        Ok(TransportObservation {
            phase,
            descriptor: VsockTransportDescriptor::default(),
            bytes_rx: stats.map(|(rx, _)| rx),
            bytes_tx: stats.map(|(_, tx)| tx),
            last_exit: *entry.exit.lock().await,
        })
    }

    /// Subscribe to one transport's bounded lifecycle event stream.
    pub async fn observe_transport(
        &self,
        request: ObserveTransportRequest,
    ) -> Result<mpsc::Receiver<TransportEvent>, ServiceError> {
        let active = self.active.lock().await;
        if let Some(entry) = active.get(&request.transport_handle) {
            let (sender, receiver) = mpsc::channel(16);
            for event in entry.history.lock().await.iter().copied() {
                if request.include_bytes
                    || !matches!(event, TransportEvent::BytesTransferred { .. })
                {
                    let _ = sender.try_send(event);
                }
            }
            entry
                .subscribers
                .lock()
                .await
                .push((request.include_bytes, sender));
            return Ok(receiver);
        }
        drop(active);
        let completed_phase = self
            .completed
            .lock()
            .await
            .get(&request.transport_handle)
            .map(|observation| observation.phase);
        if completed_phase.is_some() {
            let (sender, receiver) = mpsc::channel(2);
            let event = if completed_phase == Some(TransportPhase::Degraded) {
                TransportEvent::Error {
                    kind: "close-unconfirmed",
                    recoverable: true,
                }
            } else {
                TransportEvent::Released
            };
            let _ = sender.try_send(event);
            return Ok(receiver);
        }
        Err(ServiceError::UnknownTransportHandle)
    }

    /// Finalize all handles owned by this service.
    pub async fn finalize(&self) -> Result<(), ServiceError> {
        let handles = self.active.lock().await.keys().copied().collect::<Vec<_>>();
        let mut first_error = None;
        for handle in handles {
            if let Err(error) = self
                .close_transport(CloseTransportRequest {
                    transport_handle: handle,
                })
                .await
            {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    async fn reap_released(&self) {
        let handles = {
            let active = self.active.lock().await;
            active
                .iter()
                .filter_map(|(handle, entry)| {
                    entry
                        .phase
                        .try_lock()
                        .ok()
                        .filter(|phase| **phase == TransportPhase::Released)
                        .map(|_| *handle)
                })
                .collect::<Vec<_>>()
        };
        for handle in handles {
            if let Some(entry) = self.active.lock().await.remove(&handle) {
                self.remember_completed(handle, entry).await;
            }
        }
    }

    async fn remember_completed(&self, handle: TransportHandle, entry: TransportEntry) {
        let observation = TransportObservation {
            phase: *entry.phase.lock().await,
            descriptor: VsockTransportDescriptor::default(),
            bytes_rx: Some(entry.stats.bytes_from_vsock()),
            bytes_tx: Some(entry.stats.bytes_to_vsock()),
            last_exit: *entry.exit.lock().await,
        };
        let mut completed = self.completed.lock().await;
        if completed.len() >= MAX_ACTIVE_TRANSPORTS {
            let released = completed.iter().find_map(|(handle, observation)| {
                (observation.phase == TransportPhase::Released).then_some(*handle)
            });
            if let Some(released) = released {
                completed.remove(&released);
            }
        }
        completed.insert(handle, observation);
    }
}

fn remaining_until(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

async fn emit_event(
    subscribers: &EventSubscribers,
    history: &Arc<Mutex<Vec<TransportEvent>>>,
    event: TransportEvent,
) {
    history.lock().await.push(event);
    let mut active = subscribers.lock().await;
    active.retain(|(include_bytes, sender)| {
        if !*include_bytes && matches!(event, TransportEvent::BytesTransferred { .. }) {
            true
        } else {
            sender.try_send(event).is_ok()
        }
    });
}

fn futures_phase_is_degraded(entry: &TransportEntry) -> bool {
    entry
        .phase
        .try_lock()
        .is_ok_and(|phase| *phase == TransportPhase::Degraded)
}

impl From<NamedStreamError> for ServiceError {
    fn from(_: NamedStreamError) -> Self {
        ServiceError::StreamUnavailable
    }
}
