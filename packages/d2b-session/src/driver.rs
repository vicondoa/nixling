use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use d2b_contracts_zone_session::v3::component_session::{
    ChannelClass, CloseReason, OperationClass, Remediation, RequestId, SessionErrorCode,
};
use tokio::sync::{mpsc, oneshot};

use crate::{
    Cancellation, Fragment, MetricEvent, OwnedAttachment, OwnedTransport, Result, SessionEngine,
    SessionError, SessionEvent, StreamEvent, StreamId, TransportDescriptor, TransportError,
    TransportPacket, TransportReader, TransportWriter,
};

const DRIVER_COMMAND_CAPACITY: usize = 128;
const DRIVER_EVENT_CAPACITY: usize = 128;
const DRIVER_WRITE_CAPACITY: usize = 128;

/// Object-safe, clonable control surface for one established ComponentSession.
///
/// Ttrpc frames stay opaque: generated ttrpc code owns framing and correlation,
/// while ComponentSession owns protection, fragmentation, cancellation,
/// attachments, and named-stream multiplexing.
#[async_trait]
pub trait ComponentSessionDriver: Send + Sync {
    fn generation(&self) -> u64;

    /// Registers and sends one outbound ttrpc request. Response correlation
    /// remains with the ttrpc adapter through `receive_ttrpc`.
    async fn start_ttrpc(&self, request_id: RequestId, frame: Vec<u8>) -> Result<()>;

    /// Removes a completed outbound request after the ttrpc adapter has paired
    /// the response frame with its local stream.
    async fn complete_ttrpc(&self, request_id: RequestId) -> Result<bool>;

    async fn cancel(&self, generation: u64, request_id: RequestId) -> Result<()>;

    async fn send_ttrpc(&self, frame: Vec<u8>) -> Result<()>;

    async fn send_ttrpc_cancellable(
        &self,
        frame: Vec<u8>,
        cancellation: Cancellation,
    ) -> Result<()> {
        if cancellation.is_cancelled() {
            Err(SessionError::new(SessionErrorCode::Cancelled))
        } else {
            self.send_ttrpc(frame).await
        }
    }

    async fn receive_ttrpc(&self) -> Result<Vec<u8>>;

    /// Registers an authenticated inbound request before handler dispatch.
    async fn register_inbound_call(&self, request_id: RequestId) -> Result<Cancellation>;

    /// Mark an inbound request as dispatched to its generated handler.
    async fn mark_inbound_dispatched(&self, request_id: RequestId) -> Result<()>;

    /// Removes a normally completed inbound request.
    async fn complete_inbound_call(&self, request_id: RequestId) -> Result<bool>;

    /// Cancels and removes an aborted inbound request.
    async fn remove_inbound_call(&self, request_id: RequestId) -> Result<bool>;

    async fn send_attachments(&self, attachments: Vec<OwnedAttachment>) -> Result<()>;

    async fn receive_attachments(&self) -> Result<Vec<OwnedAttachment>>;

    async fn open_named_stream(
        &self,
        stream: StreamId,
        send_credit: u32,
        receive_credit: u32,
    ) -> Result<()>;

    /// Sends one logical message, fragmenting internally as stream credit
    /// becomes available.
    async fn send_named_stream(&self, stream: StreamId, bytes: Vec<u8>) -> Result<()>;

    async fn receive_named_stream(&self) -> Result<StreamEvent>;

    /// Reports application consumption in logical plaintext bytes.
    async fn grant_named_stream_credit(&self, stream: StreamId, bytes: u32) -> Result<()>;

    async fn close_named_stream(&self, stream: StreamId) -> Result<()>;

    async fn reset_named_stream(&self, stream: StreamId) -> Result<()>;

    async fn drive_keepalive(&self, now: Instant) -> Result<()>;

    async fn receive_control(&self) -> Result<SessionEvent>;

    async fn close(&self, reason: CloseReason, remediation: Remediation) -> Result<()>;
}

#[derive(Clone)]
pub struct SessionDriverHandle {
    commands: mpsc::Sender<DriverCommand>,
    mandatory_commands: mpsc::UnboundedSender<DriverCommand>,
    generation: Arc<AtomicU64>,
    writer_fence: Cancellation,
}

impl fmt::Debug for SessionDriverHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionDriverHandle")
            .field("generation", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl SessionDriverHandle {
    pub(crate) fn writer_fence(&self) -> Cancellation {
        self.writer_fence.clone()
    }

    async fn request<R>(
        &self,
        make_command: impl FnOnce(oneshot::Sender<Result<R>>) -> DriverCommand,
    ) -> Result<R> {
        let (reply, receive) = oneshot::channel();
        self.commands
            .send(make_command(reply))
            .await
            .map_err(|_| disconnected())?;
        receive.await.map_err(|_| disconnected())?
    }

    pub(crate) async fn start_ttrpc_guarded(
        &self,
        request_id: RequestId,
        frame: Vec<u8>,
        cancellation: Cancellation,
    ) -> Result<()> {
        self.request(|reply| DriverCommand::StartTtrpc {
            request_id,
            frame,
            cancellation,
            reply,
        })
        .await
    }

    pub(crate) fn queue_cancellation(
        &self,
        generation: u64,
        request_id: RequestId,
    ) -> Result<oneshot::Receiver<Result<()>>> {
        let (reply, receive) = oneshot::channel();
        self.mandatory_commands
            .send(DriverCommand::Cancel {
                generation,
                request_id,
                reply,
            })
            .map_err(|_| disconnected())?;
        Ok(receive)
    }

    /// Receive the next event for one exact named stream.
    ///
    /// The driver demultiplexes events without removing events owned by any
    /// other stream.
    pub async fn receive_named_stream_for(&self, stream: StreamId) -> Result<StreamEvent> {
        self.request(|reply| DriverCommand::ReceiveNamedStreamFor { stream, reply })
            .await
    }
}

#[async_trait]
impl ComponentSessionDriver for SessionDriverHandle {
    fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    async fn start_ttrpc(&self, request_id: RequestId, frame: Vec<u8>) -> Result<()> {
        self.start_ttrpc_guarded(request_id, frame, Cancellation::new())
            .await
    }

    async fn complete_ttrpc(&self, request_id: RequestId) -> Result<bool> {
        self.request(|reply| DriverCommand::CompleteTtrpc { request_id, reply })
            .await
    }

    async fn cancel(&self, generation: u64, request_id: RequestId) -> Result<()> {
        self.request(|reply| DriverCommand::Cancel {
            generation,
            request_id,
            reply,
        })
        .await
    }

    async fn send_ttrpc(&self, frame: Vec<u8>) -> Result<()> {
        self.request(|reply| DriverCommand::SendTtrpc {
            frame,
            cancellation: None,
            reply,
        })
        .await
    }

    async fn send_ttrpc_cancellable(
        &self,
        frame: Vec<u8>,
        cancellation: Cancellation,
    ) -> Result<()> {
        self.request(|reply| DriverCommand::SendTtrpc {
            frame,
            cancellation: Some(cancellation),
            reply,
        })
        .await
    }

    async fn receive_ttrpc(&self) -> Result<Vec<u8>> {
        self.request(DriverCommand::ReceiveTtrpc).await
    }

    async fn register_inbound_call(&self, request_id: RequestId) -> Result<Cancellation> {
        self.request(|reply| DriverCommand::RegisterInboundCall { request_id, reply })
            .await
    }

    async fn mark_inbound_dispatched(&self, request_id: RequestId) -> Result<()> {
        self.request(|reply| DriverCommand::MarkInboundDispatched { request_id, reply })
            .await
    }

    async fn complete_inbound_call(&self, request_id: RequestId) -> Result<bool> {
        self.request(|reply| DriverCommand::CompleteInboundCall { request_id, reply })
            .await
    }

    async fn remove_inbound_call(&self, request_id: RequestId) -> Result<bool> {
        self.request(|reply| DriverCommand::RemoveInboundCall { request_id, reply })
            .await
    }

    async fn send_attachments(&self, attachments: Vec<OwnedAttachment>) -> Result<()> {
        self.request(|reply| DriverCommand::SendAttachments { attachments, reply })
            .await
    }

    async fn receive_attachments(&self) -> Result<Vec<OwnedAttachment>> {
        self.request(DriverCommand::ReceiveAttachments).await
    }

    async fn open_named_stream(
        &self,
        stream: StreamId,
        send_credit: u32,
        receive_credit: u32,
    ) -> Result<()> {
        self.request(|reply| DriverCommand::OpenNamedStream {
            stream,
            send_credit,
            receive_credit,
            reply,
        })
        .await
    }

    async fn send_named_stream(&self, stream: StreamId, bytes: Vec<u8>) -> Result<()> {
        self.request(|reply| DriverCommand::SendNamedStream {
            stream,
            bytes,
            reply,
        })
        .await
    }

    async fn receive_named_stream(&self) -> Result<StreamEvent> {
        self.request(DriverCommand::ReceiveNamedStream).await
    }

    async fn grant_named_stream_credit(&self, stream: StreamId, bytes: u32) -> Result<()> {
        self.request(|reply| DriverCommand::GrantNamedStreamCredit {
            stream,
            bytes,
            reply,
        })
        .await
    }

    async fn close_named_stream(&self, stream: StreamId) -> Result<()> {
        self.request(|reply| DriverCommand::CloseNamedStream { stream, reply })
            .await
    }

    async fn reset_named_stream(&self, stream: StreamId) -> Result<()> {
        self.request(|reply| DriverCommand::ResetNamedStream { stream, reply })
            .await
    }

    async fn drive_keepalive(&self, now: Instant) -> Result<()> {
        self.request(|reply| DriverCommand::DriveKeepalive { now, reply })
            .await
    }

    async fn receive_control(&self) -> Result<SessionEvent> {
        self.request(DriverCommand::ReceiveControl).await
    }

    async fn close(&self, reason: CloseReason, remediation: Remediation) -> Result<()> {
        self.request(|reply| DriverCommand::Close {
            reason,
            remediation,
            reply,
        })
        .await
    }
}

impl<T: OwnedTransport + 'static> SessionEngine<T> {
    pub fn into_driver(mut self) -> SessionDriverHandle {
        let generation = Arc::new(AtomicU64::new(self.generation()));
        let writer_fence = Cancellation::new();
        let (commands, receiver) = mpsc::channel(DRIVER_COMMAND_CAPACITY);
        let (mandatory_commands, mandatory_receiver) = mpsc::unbounded_channel();
        let descriptor = self.transport_descriptor();
        let timeout = Duration::from_millis(u64::from(self.keepalive_timeout_ms()));
        let (write_sender, write_receiver) = mpsc::channel(DRIVER_WRITE_CAPACITY);
        let (priority_sender, priority_receiver) = mpsc::unbounded_channel();
        let placeholder = Box::new(DriverTransport::placeholder(descriptor));
        let (reader, writer) = self.split_transport(placeholder);
        self.install_driver_transport(Box::new(DriverTransport {
            descriptor,
            reader,
            writes: write_sender.clone(),
            priority: priority_sender.clone(),
            write_cancellation: None,
            writer_fence: writer_fence.clone(),
            batch: None,
        }));
        let (writer_failures, writer_failure_receiver) = mpsc::channel(1);
        tokio::spawn(run_writer(
            writer,
            write_receiver,
            priority_receiver,
            writer_failures,
            timeout,
        ));
        tokio::spawn(run_driver(
            self,
            receiver,
            mandatory_receiver,
            writer_failure_receiver,
            write_sender,
            priority_sender,
            writer_fence.clone(),
        ));
        SessionDriverHandle {
            commands,
            mandatory_commands,
            generation,
            writer_fence,
        }
    }
}

enum WriterCommand {
    Batch {
        packets: Vec<TransportPacket>,
        cancellation: Option<Cancellation>,
        writer_fence: Cancellation,
        completion: Option<Reply<()>>,
        close_after: bool,
    },
    Close,
    Abort {
        error: SessionError,
        closed: Option<oneshot::Sender<()>>,
    },
}

struct PendingWriteBatch {
    packets: Vec<TransportPacket>,
    cancellation: Option<Cancellation>,
    close_after: bool,
}

type PreparedWriteBatch = (Vec<TransportPacket>, Option<Cancellation>, bool);

trait PreparedWriteSource {
    fn take_prepared_write(&mut self) -> Option<PreparedWriteBatch>;
}

impl<T: OwnedTransport> PreparedWriteSource for SessionEngine<T> {
    fn take_prepared_write(&mut self) -> Option<PreparedWriteBatch> {
        self.take_write_batch()
    }
}

struct DriverTransport {
    descriptor: TransportDescriptor,
    reader: Box<dyn TransportReader>,
    writes: mpsc::Sender<WriterCommand>,
    priority: mpsc::UnboundedSender<WriterCommand>,
    write_cancellation: Option<Cancellation>,
    writer_fence: Cancellation,
    batch: Option<PendingWriteBatch>,
}

impl DriverTransport {
    fn placeholder(descriptor: TransportDescriptor) -> Self {
        let (writes, _receiver) = mpsc::channel(1);
        Self {
            descriptor,
            reader: Box::new(DisconnectedReader),
            writes,
            priority: mpsc::unbounded_channel().0,
            write_cancellation: None,
            writer_fence: Cancellation::new(),
            batch: None,
        }
    }
}

struct DisconnectedReader;

#[async_trait]
impl TransportReader for DisconnectedReader {
    async fn receive(
        &mut self,
        _protected_limit: usize,
    ) -> std::result::Result<TransportPacket, TransportError> {
        Err(TransportError::Disconnected)
    }
}

#[async_trait]
impl OwnedTransport for DriverTransport {
    fn descriptor(&self) -> TransportDescriptor {
        self.descriptor
    }

    fn into_split(self: Box<Self>) -> (Box<dyn TransportReader>, Box<dyn TransportWriter>) {
        crate::serialized_transport_split(self)
    }

    fn set_write_cancellation(&mut self, cancellation: Option<Cancellation>) {
        if let Some(batch) = self.batch.as_mut()
            && cancellation.is_some()
        {
            batch.cancellation.clone_from(&cancellation);
        }
        self.write_cancellation = cancellation;
    }

    fn begin_write_batch(&mut self, cancellation: Option<Cancellation>) {
        self.write_cancellation.clone_from(&cancellation);
        self.batch = Some(PendingWriteBatch {
            packets: Vec::new(),
            cancellation,
            close_after: false,
        });
    }

    fn take_write_batch(&mut self) -> Option<(Vec<TransportPacket>, Option<Cancellation>, bool)> {
        let batch = self.batch.take()?;
        self.write_cancellation = None;
        Some((batch.packets, batch.cancellation, batch.close_after))
    }

    async fn receive(
        &mut self,
        protected_limit: usize,
    ) -> std::result::Result<TransportPacket, TransportError> {
        self.reader.receive(protected_limit).await
    }

    async fn send(&mut self, packet: TransportPacket) -> std::result::Result<(), TransportError> {
        if let Some(batch) = self.batch.as_mut() {
            batch.packets.push(packet);
            return Ok(());
        }
        if self.writes.capacity() <= 1 {
            return Err(TransportError::WouldBlock);
        }
        self.writes
            .try_send(WriterCommand::Batch {
                packets: vec![packet],
                cancellation: self.write_cancellation.clone(),
                writer_fence: self.writer_fence.clone(),
                completion: None,
                close_after: false,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => TransportError::WouldBlock,
                mpsc::error::TrySendError::Closed(_) => TransportError::Disconnected,
            })
    }

    async fn close(&mut self) -> std::result::Result<(), TransportError> {
        if let Some(batch) = self.batch.as_mut() {
            batch.close_after = true;
            return Ok(());
        }
        self.priority
            .send(WriterCommand::Close)
            .map_err(|_| TransportError::Disconnected)
    }
}

async fn run_writer(
    mut writer: Box<dyn TransportWriter>,
    mut writes: mpsc::Receiver<WriterCommand>,
    mut priority: mpsc::UnboundedReceiver<WriterCommand>,
    failures: mpsc::Sender<SessionError>,
    timeout: Duration,
) {
    let mut normal_open = true;
    let mut priority_open = true;
    loop {
        enum WriterInput {
            Normal(Option<WriterCommand>),
            Priority(Option<WriterCommand>),
        }
        let input = match (normal_open, priority_open) {
            (true, true) => tokio::select! {
                biased;
                command = priority.recv() => WriterInput::Priority(command),
                command = writes.recv() => WriterInput::Normal(command),
            },
            (true, false) => WriterInput::Normal(writes.recv().await),
            (false, true) => WriterInput::Priority(priority.recv().await),
            (false, false) => {
                let _ = writer.close().await;
                return;
            }
        };
        let command = match input {
            WriterInput::Normal(Some(command)) | WriterInput::Priority(Some(command)) => command,
            WriterInput::Normal(None) => {
                normal_open = false;
                continue;
            }
            WriterInput::Priority(None) => {
                priority_open = false;
                continue;
            }
        };
        match command {
            WriterCommand::Batch {
                packets,
                cancellation,
                writer_fence,
                completion,
                close_after,
            } => {
                let writer_admission = match writer_fence.admit_write() {
                    Some(admission) => admission,
                    None => {
                        if let Some(completion) = completion {
                            let _ = completion
                                .send(Err(SessionError::new(SessionErrorCode::Cancelled)));
                        }
                        let error = SessionError::new(SessionErrorCode::Cancelled);
                        let _ = writer.close().await;
                        let _ = failures.try_send(error);
                        return;
                    }
                };
                let admission = match cancellation.as_ref() {
                    Some(cancellation) => match cancellation.admit_write() {
                        Some(admission) => Some(admission),
                        None => {
                            if let Some(completion) = completion {
                                let _ = completion
                                    .send(Err(SessionError::new(SessionErrorCode::Cancelled)));
                            }
                            let error = SessionError::new(SessionErrorCode::Cancelled);
                            let _ = writer.close().await;
                            let _ = failures.try_send(error);
                            return;
                        }
                    },
                    None => None,
                };
                for packet in packets {
                    enum SendOutcome {
                        Completed(
                            std::result::Result<
                                std::result::Result<(), TransportError>,
                                tokio::time::error::Elapsed,
                            >,
                        ),
                        Cancelled,
                    }
                    let result = {
                        let send = tokio::time::timeout(timeout, writer.send(packet));
                        tokio::pin!(send);
                        let outcome = tokio::select! {
                            result = send.as_mut() => SendOutcome::Completed(result),
                            () = writer_fence.cancelled() => {
                                if writer_fence.preserves_admitted_write() {
                                    SendOutcome::Completed(send.as_mut().await)
                                } else {
                                    SendOutcome::Cancelled
                                }
                            }
                            () = async {
                                if let Some(cancellation) = cancellation.as_ref() {
                                    cancellation.cancelled().await;
                                } else {
                                    std::future::pending::<()>().await;
                                }
                            } => {
                                if cancellation
                                    .as_ref()
                                    .is_some_and(Cancellation::preserves_admitted_write)
                                {
                                    SendOutcome::Completed(send.as_mut().await)
                                } else {
                                    SendOutcome::Cancelled
                                }
                            }
                        };
                        match outcome {
                            SendOutcome::Completed(Ok(result)) => {
                                result.map_err(SessionError::from)
                            }
                            SendOutcome::Completed(Err(_)) => {
                                Err(SessionError::new(SessionErrorCode::KeepaliveTimeout))
                            }
                            SendOutcome::Cancelled => {
                                Err(SessionError::new(SessionErrorCode::Cancelled))
                            }
                        }
                    };
                    if let Err(error) = result {
                        if let Some(completion) = completion {
                            let _ = completion.send(Err(error));
                        }
                        let _ = writer.close().await;
                        let _ = failures.try_send(error);
                        return;
                    }
                }
                drop(admission);
                drop(writer_admission);
                if close_after {
                    let result = writer.close().await.map_err(SessionError::from);
                    if let Some(completion) = completion {
                        let _ = completion.send(result);
                    }
                    if let Err(error) = result {
                        let _ = failures.try_send(error);
                    }
                    return;
                }
                if let Some(completion) = completion {
                    let _ = completion.send(Ok(()));
                }
            }
            WriterCommand::Close => {
                if let Err(error) = writer.close().await.map_err(SessionError::from) {
                    let _ = failures.try_send(error);
                }
                return;
            }
            WriterCommand::Abort { error, closed } => {
                let _ = writer.close().await;
                if let Some(closed) = closed {
                    let _ = closed.send(());
                }
                let _ = failures.try_send(error);
                return;
            }
        }
        tokio::task::yield_now().await;
    }
}

enum DriverCommand {
    StartTtrpc {
        request_id: RequestId,
        frame: Vec<u8>,
        cancellation: Cancellation,
        reply: Reply<()>,
    },
    CompleteTtrpc {
        request_id: RequestId,
        reply: Reply<bool>,
    },
    Cancel {
        generation: u64,
        request_id: RequestId,
        reply: Reply<()>,
    },
    SendTtrpc {
        frame: Vec<u8>,
        cancellation: Option<Cancellation>,
        reply: Reply<()>,
    },
    ReceiveTtrpc(Reply<Vec<u8>>),
    RegisterInboundCall {
        request_id: RequestId,
        reply: Reply<Cancellation>,
    },
    MarkInboundDispatched {
        request_id: RequestId,
        reply: Reply<()>,
    },
    CompleteInboundCall {
        request_id: RequestId,
        reply: Reply<bool>,
    },
    RemoveInboundCall {
        request_id: RequestId,
        reply: Reply<bool>,
    },
    SendAttachments {
        attachments: Vec<OwnedAttachment>,
        reply: Reply<()>,
    },
    ReceiveAttachments(Reply<Vec<OwnedAttachment>>),
    OpenNamedStream {
        stream: StreamId,
        send_credit: u32,
        receive_credit: u32,
        reply: Reply<()>,
    },
    SendNamedStream {
        stream: StreamId,
        bytes: Vec<u8>,
        reply: Reply<()>,
    },
    ReceiveNamedStream(Reply<StreamEvent>),
    ReceiveNamedStreamFor {
        stream: StreamId,
        reply: Reply<StreamEvent>,
    },
    GrantNamedStreamCredit {
        stream: StreamId,
        bytes: u32,
        reply: Reply<()>,
    },
    CloseNamedStream {
        stream: StreamId,
        reply: Reply<()>,
    },
    ResetNamedStream {
        stream: StreamId,
        reply: Reply<()>,
    },
    DriveKeepalive {
        now: Instant,
        reply: Reply<()>,
    },
    ReceiveControl(Reply<SessionEvent>),
    Close {
        reason: CloseReason,
        remediation: Remediation,
        reply: Reply<()>,
    },
}

type Reply<T> = oneshot::Sender<Result<T>>;

struct PendingNamedSend {
    stream: StreamId,
    fragments: VecDeque<Fragment>,
    remaining: usize,
    reply: Reply<()>,
}

struct DriverQueues {
    named_sends: VecDeque<PendingNamedSend>,
    named_send_bytes: usize,
    ttrpc: EventQueue<Vec<u8>>,
    attachments: EventQueue<Vec<OwnedAttachment>>,
    streams: NamedStreamEventQueue,
    control: EventQueue<SessionEvent>,
}

impl DriverQueues {
    fn new<T: OwnedTransport>(engine: &SessionEngine<T>) -> Self {
        Self {
            named_sends: VecDeque::new(),
            named_send_bytes: 0,
            ttrpc: EventQueue::new(engine.ttrpc_event_queue_limit()),
            attachments: EventQueue::new(engine.control_event_queue_limit()),
            streams: NamedStreamEventQueue::new(engine.stream_event_queue_limit()),
            control: EventQueue::new(engine.control_event_queue_limit()),
        }
    }

    fn can_enqueue_named_send(
        &self,
        stream: StreamId,
        bytes: usize,
        aggregate_limit: usize,
    ) -> Result<()> {
        let aggregate = self
            .named_send_bytes
            .checked_add(bytes)
            .ok_or_else(|| SessionError::new(SessionErrorCode::ArithmeticOverflow))?;
        if bytes == 0
            || aggregate > aggregate_limit
            || self
                .named_sends
                .iter()
                .any(|pending| pending.stream == stream)
        {
            return Err(backpressure());
        }
        Ok(())
    }

    fn enqueue_named_send(&mut self, pending: PendingNamedSend) {
        self.named_send_bytes += pending.remaining;
        self.named_sends.push_back(pending);
    }

    fn has_sendable_named<T: OwnedTransport>(&self, engine: &SessionEngine<T>) -> bool {
        self.named_sends.iter().any(|pending| {
            pending.fragments.front().is_some_and(|fragment| {
                u32::try_from(fragment.as_bytes().len()).is_ok_and(|fragment_credit| {
                    engine
                        .named_stream_send_credit(pending.stream)
                        .is_some_and(|credit| credit >= fragment_credit)
                })
            })
        })
    }

    fn cancel_named_send(&mut self, stream: StreamId, error: SessionError) {
        let mut retained = VecDeque::with_capacity(self.named_sends.len());
        while let Some(pending) = self.named_sends.pop_front() {
            if pending.stream == stream {
                self.named_send_bytes = self.named_send_bytes.saturating_sub(pending.remaining);
                let _ = pending.reply.send(Err(error));
            } else {
                retained.push_back(pending);
            }
        }
        self.named_sends = retained;
    }

    fn fail(self, error: SessionError) {
        for pending in self.named_sends {
            let _ = pending.reply.send(Err(error));
        }
        self.ttrpc.fail(error);
        self.attachments.fail(error);
        self.streams.fail(error);
        self.control.fail(error);
    }
}

trait EventBytes {
    fn event_bytes(&self) -> usize;
}

impl EventBytes for Vec<u8> {
    fn event_bytes(&self) -> usize {
        self.len().max(1)
    }
}

impl EventBytes for Vec<OwnedAttachment> {
    fn event_bytes(&self) -> usize {
        self.len().max(1)
    }
}

impl EventBytes for StreamEvent {
    fn event_bytes(&self) -> usize {
        match self {
            StreamEvent::Data { bytes, .. } => bytes.len().max(1),
            StreamEvent::RemoteClosed { .. } | StreamEvent::Reset { .. } => 1,
        }
    }
}

impl EventBytes for SessionEvent {
    fn event_bytes(&self) -> usize {
        match self {
            SessionEvent::Ttrpc(bytes) => bytes.len().max(1),
            SessionEvent::NamedStream(event) => event.event_bytes(),
            SessionEvent::Attachments(attachments) => attachments.len().max(1),
            SessionEvent::CancelRequest(_)
            | SessionEvent::CancelAck(_)
            | SessionEvent::AttachmentAcknowledged { .. }
            | SessionEvent::Close(_)
            | SessionEvent::ControlProcessed => 1,
        }
    }
}

#[cfg(test)]
impl EventBytes for u8 {
    fn event_bytes(&self) -> usize {
        1
    }
}

struct EventQueue<T> {
    events: VecDeque<T>,
    waiters: VecDeque<Reply<T>>,
    queued_bytes: usize,
    max_bytes: usize,
}

impl<T: EventBytes> EventQueue<T> {
    fn new(max_bytes: usize) -> Self {
        Self {
            events: VecDeque::new(),
            waiters: VecDeque::new(),
            queued_bytes: 0,
            max_bytes,
        }
    }

    fn receive(&mut self, waiter: Reply<T>) -> Result<()> {
        if let Some(event) = self.events.pop_front() {
            self.queued_bytes = self.queued_bytes.saturating_sub(event.event_bytes());
            match waiter.send(Ok(event)) {
                Ok(()) => {}
                Err(Ok(returned)) => {
                    self.queued_bytes += returned.event_bytes();
                    self.events.push_front(returned);
                }
                Err(Err(_)) => {
                    return Err(SessionError::new(SessionErrorCode::InternalInvariant));
                }
            }
        } else {
            self.waiters.retain(|waiter| !waiter.is_closed());
            if self.waiters.len() >= DRIVER_COMMAND_CAPACITY {
                return Err(backpressure());
            }
            self.waiters.push_back(waiter);
        }
        Ok(())
    }

    fn deliver(&mut self, mut event: T) -> Result<()> {
        while let Some(waiter) = self.waiters.pop_front() {
            match waiter.send(Ok(event)) {
                Ok(()) => return Ok(()),
                Err(Ok(returned)) => event = returned,
                Err(Err(_)) => {
                    return Err(SessionError::new(SessionErrorCode::InternalInvariant));
                }
            }
        }
        let event_bytes = event.event_bytes();
        if event_bytes > self.max_bytes
            || self.queued_bytes.saturating_add(event_bytes) > self.max_bytes
            || self.events.len() >= DRIVER_EVENT_CAPACITY
        {
            return Err(backpressure());
        }
        self.queued_bytes += event_bytes;
        self.events.push_back(event);
        Ok(())
    }

    fn fail(self, error: SessionError) {
        for waiter in self.waiters {
            let _ = waiter.send(Err(error));
        }
    }
}

struct NamedStreamEventQueue {
    events: EventQueue<StreamEvent>,
    waiters: BTreeMap<StreamId, VecDeque<Reply<StreamEvent>>>,
    waiter_count: usize,
}

impl NamedStreamEventQueue {
    fn new(max_bytes: usize) -> Self {
        Self {
            events: EventQueue::new(max_bytes),
            waiters: BTreeMap::new(),
            waiter_count: 0,
        }
    }

    fn receive(&mut self, waiter: Reply<StreamEvent>) -> Result<()> {
        self.events.receive(waiter)
    }

    fn receive_for(&mut self, stream: StreamId, waiter: Reply<StreamEvent>) -> Result<()> {
        if let Some(index) = self
            .events
            .events
            .iter()
            .position(|event| event.stream() == stream)
        {
            let event = self
                .events
                .events
                .remove(index)
                .ok_or_else(|| SessionError::new(SessionErrorCode::InternalInvariant))?;
            self.events.queued_bytes = self.events.queued_bytes.saturating_sub(event.event_bytes());
            match waiter.send(Ok(event)) {
                Ok(()) => {}
                Err(Ok(returned)) => {
                    self.events.queued_bytes += returned.event_bytes();
                    self.events.events.insert(index, returned);
                }
                Err(Err(_)) => {
                    return Err(SessionError::new(SessionErrorCode::InternalInvariant));
                }
            }
            return Ok(());
        }

        let waiters = self.waiters.entry(stream).or_default();
        let before = waiters.len();
        waiters.retain(|waiter| !waiter.is_closed());
        self.waiter_count = self
            .waiter_count
            .saturating_sub(before.saturating_sub(waiters.len()));
        if self.waiter_count >= DRIVER_COMMAND_CAPACITY {
            if waiters.is_empty() {
                self.waiters.remove(&stream);
            }
            return Err(backpressure());
        }
        waiters.push_back(waiter);
        self.waiter_count += 1;
        Ok(())
    }

    fn deliver(&mut self, mut event: StreamEvent) -> Result<()> {
        let stream = event.stream();
        let mut waiters = self.waiters.remove(&stream).unwrap_or_default();
        self.waiter_count = self.waiter_count.saturating_sub(waiters.len());
        while let Some(waiter) = waiters.pop_front() {
            match waiter.send(Ok(event)) {
                Ok(()) => {
                    if !waiters.is_empty() {
                        self.waiter_count += waiters.len();
                        self.waiters.insert(stream, waiters);
                    }
                    return Ok(());
                }
                Err(Ok(returned)) => event = returned,
                Err(Err(_)) => {
                    return Err(SessionError::new(SessionErrorCode::InternalInvariant));
                }
            }
        }
        self.events.deliver(event)
    }

    fn fail(self, error: SessionError) {
        self.events.fail(error);
        for waiters in self.waiters.into_values() {
            for waiter in waiters {
                let _ = waiter.send(Err(error));
            }
        }
    }
}

async fn run_driver<T: OwnedTransport>(
    mut engine: SessionEngine<T>,
    mut commands: mpsc::Receiver<DriverCommand>,
    mut mandatory_commands: mpsc::UnboundedReceiver<DriverCommand>,
    mut writer_failures: mpsc::Receiver<SessionError>,
    write_commands: mpsc::Sender<WriterCommand>,
    priority_writes: mpsc::UnboundedSender<WriterCommand>,
    writer_fence: Cancellation,
) {
    let mut queues = DriverQueues::new(&engine);
    let mut fairness_turn = 0_u8;
    let result = loop {
        enum Work {
            Command(Option<DriverCommand>),
            MandatoryCommand(Option<DriverCommand>),
            Inbound(Result<SessionEvent>),
            NamedStream,
            WriterFailure(Option<SessionError>),
        }
        let named_ready = queues.has_sendable_named(&engine);
        let named_work = async {
            if !named_ready {
                std::future::pending::<()>().await;
            }
        };
        let work = match fairness_turn {
            0 => tokio::select! {
                biased;
                command = mandatory_commands.recv() => Work::MandatoryCommand(command),
                error = writer_failures.recv() => Work::WriterFailure(error),
                command = commands.recv() => Work::Command(command),
                event = engine.receive() => Work::Inbound(event),
                () = named_work => Work::NamedStream,
            },
            1 => tokio::select! {
                biased;
                command = mandatory_commands.recv() => Work::MandatoryCommand(command),
                error = writer_failures.recv() => Work::WriterFailure(error),
                event = engine.receive() => Work::Inbound(event),
                () = named_work => Work::NamedStream,
                command = commands.recv() => Work::Command(command),
            },
            _ => tokio::select! {
                biased;
                command = mandatory_commands.recv() => Work::MandatoryCommand(command),
                error = writer_failures.recv() => Work::WriterFailure(error),
                () = named_work => Work::NamedStream,
                command = commands.recv() => Work::Command(command),
                event = engine.receive() => Work::Inbound(event),
            },
        };
        fairness_turn = (fairness_turn + 1) % 3;
        match work {
            Work::Command(command) | Work::MandatoryCommand(command) => {
                let Some(command) = command else {
                    break Err(disconnected());
                };
                match handle_command(
                    &mut engine,
                    &mut queues,
                    &write_commands,
                    &priority_writes,
                    &writer_fence,
                    command,
                )
                .await
                {
                    Ok(DriverAction::Continue) => {}
                    Ok(DriverAction::Close) => break Ok(()),
                    Err(error) => break Err(error),
                }
            }
            Work::Inbound(event) => match event.and_then(|event| route_event(&mut queues, event)) {
                Ok(()) => {}
                Err(error) => {
                    engine.record_failure(
                        MetricEvent::QueueDepth,
                        ChannelClass::SessionControl,
                        OperationClass::Observe,
                        error,
                    );
                    break Err(error);
                }
            },
            Work::NamedStream => {
                match pump_named_stream(
                    &mut engine,
                    &mut queues,
                    &write_commands,
                    &priority_writes,
                    &writer_fence,
                )
                .await
                {
                    Ok(_) => {}
                    Err(error) => {
                        engine.record_failure(
                            MetricEvent::RejectedRecord,
                            ChannelClass::NamedStream,
                            OperationClass::OpenStream,
                            error,
                        );
                        break Err(error);
                    }
                }
            }
            Work::WriterFailure(error) => {
                let error = error.unwrap_or_else(disconnected);
                record_writer_failure(&engine, error);
                break Err(error);
            }
        }
    };

    let error = result.err().unwrap_or_else(disconnected);
    queues.fail(error);
}

trait WriterFailureRecorder {
    fn record_writer_failure(
        &self,
        event: MetricEvent,
        channel_class: ChannelClass,
        operation_class: OperationClass,
        error: SessionError,
    );
}

impl<T: OwnedTransport> WriterFailureRecorder for SessionEngine<T> {
    fn record_writer_failure(
        &self,
        event: MetricEvent,
        channel_class: ChannelClass,
        operation_class: OperationClass,
        error: SessionError,
    ) {
        self.record_failure(event, channel_class, operation_class, error);
    }
}

fn record_writer_failure(recorder: &impl WriterFailureRecorder, error: SessionError) {
    recorder.record_writer_failure(
        MetricEvent::RejectedRecord,
        ChannelClass::SessionControl,
        OperationClass::Cancel,
        error,
    );
}

enum DriverAction {
    Continue,
    Close,
}

async fn handle_command<T: OwnedTransport>(
    engine: &mut SessionEngine<T>,
    queues: &mut DriverQueues,
    write_commands: &mpsc::Sender<WriterCommand>,
    priority_writes: &mpsc::UnboundedSender<WriterCommand>,
    writer_fence: &Cancellation,
    command: DriverCommand,
) -> Result<DriverAction> {
    match command {
        DriverCommand::StartTtrpc {
            request_id,
            frame,
            cancellation,
            reply,
        } => {
            if reply.is_closed() || cancellation.is_cancelled() {
                let _ = reply.send(Err(SessionError::new(SessionErrorCode::Cancelled)));
                return Ok(DriverAction::Continue);
            }
            let batch = match reserve_write_batch(write_commands, priority_writes) {
                Ok(batch) => batch,
                Err(error) => {
                    let _ = reply.send(Err(error));
                    return Err(error);
                }
            };
            engine.begin_write_batch(Some(cancellation.clone()));
            let result = engine
                .call_guarded(request_id, frame, cancellation)
                .await
                .map(|_| ());
            complete_after_write(engine, batch, priority_writes, writer_fence, reply, result).await;
        }
        DriverCommand::CompleteTtrpc { request_id, reply } => {
            let _ = reply.send(Ok(engine.complete_call(&request_id)));
        }
        DriverCommand::Cancel {
            generation,
            request_id,
            reply,
        } => {
            engine.cancel_and_complete_call(&request_id);
            let batch = match reserve_cancellation_write(write_commands, priority_writes) {
                Ok(batch) => batch,
                Err(error) => {
                    let _ = reply.send(Err(error));
                    return Err(error);
                }
            };
            engine.begin_write_batch(None);
            let result = if generation == engine.generation() {
                engine.cancel_call(&request_id).await
            } else {
                Err(SessionError::new(SessionErrorCode::GenerationMismatch))
            };
            complete_after_write(engine, batch, priority_writes, writer_fence, reply, result).await;
        }
        DriverCommand::SendTtrpc {
            frame,
            cancellation,
            reply,
        } => {
            let batch = match reserve_write_batch(write_commands, priority_writes) {
                Ok(batch) => batch,
                Err(error) => {
                    let _ = reply.send(Err(error));
                    return Err(error);
                }
            };
            let result = if reply.is_closed()
                || cancellation
                    .as_ref()
                    .is_some_and(Cancellation::is_cancelled)
            {
                Err(SessionError::new(SessionErrorCode::Cancelled))
            } else {
                engine.begin_write_batch(cancellation);
                engine.send_ttrpc(frame).await
            };
            complete_after_write(engine, batch, priority_writes, writer_fence, reply, result).await;
        }
        DriverCommand::ReceiveTtrpc(reply) => queues.ttrpc.receive(reply)?,
        DriverCommand::RegisterInboundCall { request_id, reply } => {
            let _ = reply.send(engine.register_inbound_call(request_id));
        }
        DriverCommand::MarkInboundDispatched { request_id, reply } => {
            let _ = reply.send(engine.mark_inbound_dispatched(&request_id));
        }
        DriverCommand::CompleteInboundCall { request_id, reply } => {
            let _ = reply.send(Ok(engine.complete_inbound_call(&request_id)));
        }
        DriverCommand::RemoveInboundCall { request_id, reply } => {
            let _ = reply.send(Ok(engine.remove_inbound_call(&request_id)));
        }
        DriverCommand::SendAttachments { attachments, reply } => {
            let batch = match reserve_write_batch(write_commands, priority_writes) {
                Ok(batch) => batch,
                Err(error) => {
                    let _ = reply.send(Err(error));
                    return Err(error);
                }
            };
            engine.begin_write_batch(None);
            let result = engine.send_attachments(attachments).await;
            complete_after_write(engine, batch, priority_writes, writer_fence, reply, result).await;
        }
        DriverCommand::ReceiveAttachments(reply) => queues.attachments.receive(reply)?,
        DriverCommand::OpenNamedStream {
            stream,
            send_credit,
            receive_credit,
            reply,
        } => {
            let _ = reply.send(engine.open_named_stream(stream, send_credit, receive_credit));
        }
        DriverCommand::SendNamedStream {
            stream,
            bytes,
            reply,
        } => {
            let len = bytes.len();
            if let Err(error) =
                queues.can_enqueue_named_send(stream, len, engine.aggregate_named_stream_limit())
            {
                engine.record_failure(
                    MetricEvent::QueueDepth,
                    ChannelClass::NamedStream,
                    OperationClass::OpenStream,
                    error,
                );
                let _ = reply.send(Err(error));
            } else {
                match engine.fragment_named_stream(stream, bytes) {
                    Ok(fragments) => queues.enqueue_named_send(PendingNamedSend {
                        stream,
                        fragments,
                        remaining: len,
                        reply,
                    }),
                    Err(error) => {
                        engine.record_failure(
                            MetricEvent::RejectedRecord,
                            ChannelClass::NamedStream,
                            OperationClass::OpenStream,
                            error,
                        );
                        let _ = reply.send(Err(error));
                    }
                }
            }
        }
        DriverCommand::ReceiveNamedStream(reply) => queues.streams.receive(reply)?,
        DriverCommand::ReceiveNamedStreamFor { stream, reply } => {
            queues.streams.receive_for(stream, reply)?
        }
        DriverCommand::GrantNamedStreamCredit {
            stream,
            bytes,
            reply,
        } => {
            let batch = match reserve_write_batch(write_commands, priority_writes) {
                Ok(batch) => batch,
                Err(error) => {
                    let _ = reply.send(Err(error));
                    return Err(error);
                }
            };
            engine.begin_write_batch(None);
            let result = engine.grant_named_stream_credit(stream, bytes).await;
            complete_after_write(engine, batch, priority_writes, writer_fence, reply, result).await;
        }
        DriverCommand::CloseNamedStream { stream, reply } => {
            queues.cancel_named_send(stream, SessionError::new(SessionErrorCode::Cancelled));
            let batch = match reserve_write_batch(write_commands, priority_writes) {
                Ok(batch) => batch,
                Err(error) => {
                    let _ = reply.send(Err(error));
                    return Err(error);
                }
            };
            engine.begin_write_batch(None);
            let result = engine.close_named_stream(stream).await;
            complete_after_write(engine, batch, priority_writes, writer_fence, reply, result).await;
        }
        DriverCommand::ResetNamedStream { stream, reply } => {
            queues.cancel_named_send(stream, SessionError::new(SessionErrorCode::Cancelled));
            let batch = match reserve_write_batch(write_commands, priority_writes) {
                Ok(batch) => batch,
                Err(error) => {
                    let _ = reply.send(Err(error));
                    return Err(error);
                }
            };
            engine.begin_write_batch(None);
            let result = engine.reset_named_stream(stream).await;
            complete_after_write(engine, batch, priority_writes, writer_fence, reply, result).await;
        }
        DriverCommand::DriveKeepalive { now, reply } => {
            let batch = match reserve_write_batch(write_commands, priority_writes) {
                Ok(batch) => batch,
                Err(error) => {
                    let _ = reply.send(Err(error));
                    return Err(error);
                }
            };
            engine.begin_write_batch(None);
            let result = engine.drive_keepalive(now).await;
            complete_after_write(engine, batch, priority_writes, writer_fence, reply, result).await;
        }
        DriverCommand::ReceiveControl(reply) => queues.control.receive(reply)?,
        DriverCommand::Close {
            reason,
            remediation,
            reply,
        } => {
            let batch = match reserve_cancellation_write(write_commands, priority_writes) {
                Ok(batch) => batch,
                Err(error) => {
                    let _ = reply.send(Err(error));
                    return Err(error);
                }
            };
            engine.begin_write_batch(None);
            let result = engine.close(reason, remediation).await;
            let closed = result.is_ok();
            complete_after_write(engine, batch, priority_writes, writer_fence, reply, result).await;
            if closed {
                return Ok(DriverAction::Close);
            }
        }
    }
    Ok(DriverAction::Continue)
}

fn reserve_write_batch<'a>(
    write_commands: &'a mpsc::Sender<WriterCommand>,
    priority_writes: &mpsc::UnboundedSender<WriterCommand>,
) -> Result<mpsc::Permit<'a, WriterCommand>> {
    if write_commands.capacity() <= 1 {
        let error = SessionError::new(SessionErrorCode::QueueBackpressure);
        let _ = priority_writes.send(WriterCommand::Abort {
            error,
            closed: None,
        });
        return Err(error);
    }
    write_commands.try_reserve().map_err(|error| match error {
        mpsc::error::TrySendError::Full(()) => {
            let error = SessionError::new(SessionErrorCode::QueueBackpressure);
            let _ = priority_writes.send(WriterCommand::Abort {
                error,
                closed: None,
            });
            error
        }
        mpsc::error::TrySendError::Closed(()) => {
            SessionError::new(SessionErrorCode::SessionDisconnected)
        }
    })
}

async fn complete_after_write(
    engine: &mut impl PreparedWriteSource,
    batch: mpsc::Permit<'_, WriterCommand>,
    priority_writes: &mpsc::UnboundedSender<WriterCommand>,
    writer_fence: &Cancellation,
    reply: Reply<()>,
    result: Result<()>,
) {
    let prepared = engine.take_prepared_write();
    if let Err(error) = result {
        if prepared
            .as_ref()
            .is_some_and(|(packets, _, _)| !packets.is_empty())
        {
            abort_writer_and_wait(priority_writes, error).await;
        }
        let _ = reply.send(Err(error));
        return;
    }
    let Some((packets, cancellation, close_after)) = prepared else {
        let _ = reply.send(Err(SessionError::new(SessionErrorCode::InternalInvariant)));
        return;
    };
    batch.send(WriterCommand::Batch {
        packets,
        cancellation,
        writer_fence: writer_fence.clone(),
        completion: Some(reply),
        close_after,
    });
}

fn reserve_cancellation_write<'a>(
    write_commands: &'a mpsc::Sender<WriterCommand>,
    priority_writes: &mpsc::UnboundedSender<WriterCommand>,
) -> Result<mpsc::Permit<'a, WriterCommand>> {
    if write_commands.capacity() == 0 {
        let error = backpressure();
        let _ = priority_writes.send(WriterCommand::Abort {
            error,
            closed: None,
        });
        return Err(error);
    }
    write_commands.try_reserve().map_err(|error| {
        let error = match error {
            mpsc::error::TrySendError::Full(()) => {
                SessionError::new(SessionErrorCode::QueueBackpressure)
            }
            mpsc::error::TrySendError::Closed(()) => disconnected(),
        };
        let _ = priority_writes.send(WriterCommand::Abort {
            error,
            closed: None,
        });
        error
    })
}

async fn abort_writer_and_wait(
    priority_writes: &mpsc::UnboundedSender<WriterCommand>,
    error: SessionError,
) {
    let (closed, wait_closed) = oneshot::channel();
    if priority_writes
        .send(WriterCommand::Abort {
            error,
            closed: Some(closed),
        })
        .is_ok()
    {
        let _ = wait_closed.await;
    }
}

async fn complete_unobserved_write(
    engine: &mut SessionEngine<impl OwnedTransport>,
    batch: mpsc::Permit<'_, WriterCommand>,
    priority_writes: &mpsc::UnboundedSender<WriterCommand>,
    writer_fence: &Cancellation,
    result: Result<()>,
) -> Result<()> {
    let prepared = engine.take_write_batch();
    if let Err(error) = result {
        if prepared
            .as_ref()
            .is_some_and(|(packets, _, _)| !packets.is_empty())
        {
            abort_writer_and_wait(priority_writes, error).await;
        }
        return Err(error);
    }
    let Some((packets, cancellation, close_after)) = prepared else {
        return Err(SessionError::new(SessionErrorCode::InternalInvariant));
    };
    batch.send(WriterCommand::Batch {
        packets,
        cancellation,
        writer_fence: writer_fence.clone(),
        completion: None,
        close_after,
    });
    Ok(())
}

async fn pump_named_stream<T: OwnedTransport>(
    engine: &mut SessionEngine<T>,
    queues: &mut DriverQueues,
    write_commands: &mpsc::Sender<WriterCommand>,
    priority_writes: &mpsc::UnboundedSender<WriterCommand>,
    writer_fence: &Cancellation,
) -> Result<bool> {
    let attempts = queues.named_sends.len();
    for _ in 0..attempts {
        let Some(mut pending) = queues.named_sends.pop_front() else {
            return Ok(false);
        };
        let Some(fragment) = pending.fragments.front() else {
            let _ = pending.reply.send(Ok(()));
            continue;
        };
        let fragment_len = fragment.as_bytes().len();
        let fragment_credit = u32::try_from(fragment_len)
            .map_err(|_| SessionError::new(SessionErrorCode::ArithmeticOverflow))?;
        if engine
            .named_stream_send_credit(pending.stream)
            .is_none_or(|credit| credit < fragment_credit)
        {
            queues.named_sends.push_back(pending);
            continue;
        }

        let fragment = pending
            .fragments
            .pop_front()
            .ok_or_else(|| SessionError::new(SessionErrorCode::InternalInvariant))?;
        let batch = reserve_write_batch(write_commands, priority_writes)?;
        engine.begin_write_batch(None);
        let result = engine
            .send_named_stream_fragment(pending.stream, fragment)
            .await;
        complete_unobserved_write(engine, batch, priority_writes, writer_fence, result).await?;
        pending.remaining = pending
            .remaining
            .checked_sub(fragment_len)
            .ok_or_else(|| SessionError::new(SessionErrorCode::InternalInvariant))?;
        queues.named_send_bytes = queues
            .named_send_bytes
            .checked_sub(fragment_len)
            .ok_or_else(|| SessionError::new(SessionErrorCode::InternalInvariant))?;
        if pending.fragments.is_empty() {
            let _ = pending.reply.send(Ok(()));
        } else {
            queues.named_sends.push_back(pending);
        }
        return Ok(true);
    }
    Ok(false)
}

fn route_event(queues: &mut DriverQueues, event: SessionEvent) -> Result<()> {
    match event {
        SessionEvent::Ttrpc(frame) => {
            queues.ttrpc.deliver(frame)?;
        }
        SessionEvent::Attachments(attachments) => queues.attachments.deliver(attachments)?,
        SessionEvent::NamedStream(event) => {
            if let StreamEvent::Reset { stream } = &event {
                queues.cancel_named_send(*stream, SessionError::new(SessionErrorCode::Cancelled));
            }
            queues.streams.deliver(event)?;
        }
        event => queues.control.deliver(event)?,
    }
    Ok(())
}

fn disconnected() -> SessionError {
    SessionError::new(SessionErrorCode::SessionDisconnected)
}

fn backpressure() -> SessionError {
    SessionError::new(SessionErrorCode::QueueBackpressure)
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, atomic::AtomicBool};

    use tokio::sync::Notify;

    use super::*;

    struct FailingWriter {
        closed: Arc<AtomicBool>,
    }

    #[async_trait]
    impl TransportWriter for FailingWriter {
        async fn send(
            &mut self,
            _packet: TransportPacket,
        ) -> std::result::Result<(), TransportError> {
            Err(TransportError::Other)
        }

        async fn close(&mut self) -> std::result::Result<(), TransportError> {
            self.closed.store(true, Ordering::Release);
            Ok(())
        }
    }

    struct PausedWriter {
        entered: Arc<Notify>,
        release: Arc<Notify>,
        sent: Arc<AtomicBool>,
        closed: Arc<AtomicBool>,
    }

    struct RecordingPausedWriter {
        entered: Arc<Notify>,
        release: Arc<Notify>,
        packets: Arc<Mutex<Vec<Vec<u8>>>>,
        closed: Arc<AtomicBool>,
    }

    struct BlockingCloseWriter {
        entered: Arc<Notify>,
        release: Arc<Notify>,
        closed: Arc<AtomicBool>,
    }

    #[async_trait]
    impl TransportWriter for BlockingCloseWriter {
        async fn send(
            &mut self,
            _packet: TransportPacket,
        ) -> std::result::Result<(), TransportError> {
            Ok(())
        }

        async fn close(&mut self) -> std::result::Result<(), TransportError> {
            self.entered.notify_one();
            self.release.notified().await;
            self.closed.store(true, Ordering::Release);
            Ok(())
        }
    }

    #[async_trait]
    impl TransportWriter for RecordingPausedWriter {
        async fn send(
            &mut self,
            packet: TransportPacket,
        ) -> std::result::Result<(), TransportError> {
            if self
                .packets
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_empty()
            {
                self.entered.notify_one();
                self.release.notified().await;
            }
            self.packets
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(packet.as_bytes().to_vec());
            Ok(())
        }

        async fn close(&mut self) -> std::result::Result<(), TransportError> {
            self.closed.store(true, Ordering::Release);
            Ok(())
        }
    }

    #[async_trait]
    impl TransportWriter for PausedWriter {
        async fn send(
            &mut self,
            _packet: TransportPacket,
        ) -> std::result::Result<(), TransportError> {
            self.entered.notify_one();
            self.release.notified().await;
            self.sent.store(true, Ordering::Release);
            Ok(())
        }

        async fn close(&mut self) -> std::result::Result<(), TransportError> {
            self.closed.store(true, Ordering::Release);
            Ok(())
        }
    }

    struct PreparedWriteFixture(Option<PreparedWriteBatch>);

    #[derive(Default)]
    struct CapturingWriterFailure(
        Mutex<
            Vec<(
                MetricEvent,
                ChannelClass,
                OperationClass,
                d2b_contracts_zone_session::v3::component_session::MetricReason,
            )>,
        >,
    );

    impl WriterFailureRecorder for CapturingWriterFailure {
        fn record_writer_failure(
            &self,
            event: MetricEvent,
            channel_class: ChannelClass,
            operation_class: OperationClass,
            error: SessionError,
        ) {
            self.0.lock().unwrap().push((
                event,
                channel_class,
                operation_class,
                crate::metrics::reason_for_error(error.code()),
            ));
        }
    }

    impl PreparedWriteSource for PreparedWriteFixture {
        fn take_prepared_write(&mut self) -> Option<PreparedWriteBatch> {
            self.0.take()
        }
    }

    #[tokio::test]
    async fn writer_closes_transport_before_reporting_packet_failure() {
        let closed = Arc::new(AtomicBool::new(false));
        let (writes, receiver) = mpsc::channel(1);
        let (_priority, priority_receiver) = mpsc::unbounded_channel();
        let (failures, mut failure_receiver) = mpsc::channel(1);
        let task = tokio::spawn(run_writer(
            Box::new(FailingWriter {
                closed: Arc::clone(&closed),
            }),
            receiver,
            priority_receiver,
            failures,
            Duration::from_secs(1),
        ));
        writes
            .send(WriterCommand::Batch {
                packets: vec![TransportPacket::new(vec![1])],
                cancellation: None,
                writer_fence: Cancellation::new(),
                completion: None,
                close_after: false,
            })
            .await
            .unwrap();

        let error = failure_receiver.recv().await.unwrap();
        assert_eq!(error.code(), SessionErrorCode::InternalInvariant);
        assert!(closed.load(Ordering::Acquire));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn revocation_waits_for_writer_admission_before_returning() {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let sent = Arc::new(AtomicBool::new(false));
        let closed = Arc::new(AtomicBool::new(false));
        let (writes, receiver) = mpsc::channel(1);
        let (priority, priority_receiver) = mpsc::unbounded_channel();
        let (failures, _failure_receiver) = mpsc::channel(1);
        let task = tokio::spawn(run_writer(
            Box::new(PausedWriter {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
                sent: Arc::clone(&sent),
                closed: Arc::clone(&closed),
            }),
            receiver,
            priority_receiver,
            failures,
            Duration::from_secs(1),
        ));
        let cancellation = Cancellation::new();
        let writer_fence = Cancellation::new();
        writes
            .send(WriterCommand::Batch {
                packets: vec![TransportPacket::new(vec![1])],
                cancellation: Some(cancellation.clone()),
                writer_fence,
                completion: None,
                close_after: false,
            })
            .await
            .unwrap();
        entered.notified().await;

        let mut revocation = Box::pin(cancellation.cancel_and_wait());
        tokio::select! {
            result = &mut revocation => {
                panic!("revocation returned before the admitted writer acknowledged: {result}")
            }
            () = tokio::task::yield_now() => {}
        }
        release.notify_one();
        assert!(revocation.await);
        assert!(sent.load(Ordering::Acquire));

        drop(writes);
        drop(priority);
        task.await.unwrap();
        assert!(closed.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn generation_revocation_rejects_queued_control_after_admitted_request() {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let packets = Arc::new(Mutex::new(Vec::new()));
        let closed = Arc::new(AtomicBool::new(false));
        let (writes, receiver) = mpsc::channel(2);
        let (priority, priority_receiver) = mpsc::unbounded_channel();
        let (failures, mut failure_receiver) = mpsc::channel(1);
        let task = tokio::spawn(run_writer(
            Box::new(RecordingPausedWriter {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
                packets: Arc::clone(&packets),
                closed: Arc::clone(&closed),
            }),
            receiver,
            priority_receiver,
            failures,
            Duration::from_secs(1),
        ));
        let writer_fence = Cancellation::new();
        writes
            .send(WriterCommand::Batch {
                packets: vec![TransportPacket::new(vec![1])],
                cancellation: Some(Cancellation::new()),
                writer_fence: writer_fence.clone(),
                completion: None,
                close_after: false,
            })
            .await
            .unwrap();
        writes
            .send(WriterCommand::Batch {
                packets: vec![TransportPacket::new(vec![2])],
                cancellation: None,
                writer_fence: writer_fence.clone(),
                completion: None,
                close_after: false,
            })
            .await
            .unwrap();
        entered.notified().await;

        let mut revocation = Box::pin(writer_fence.cancel_and_wait());
        tokio::select! {
            result = &mut revocation => {
                panic!("revocation returned before the admitted request completed: {result}")
            }
            () = tokio::task::yield_now() => {}
        }
        release.notify_one();
        assert!(revocation.await);
        assert_eq!(
            {
                let error = failure_receiver.recv().await.unwrap();
                let metrics = CapturingWriterFailure::default();
                record_writer_failure(&metrics, error);
                assert_eq!(
                    *metrics.0.lock().unwrap(),
                    vec![(
                        MetricEvent::RejectedRecord,
                        ChannelClass::SessionControl,
                        OperationClass::Cancel,
                        d2b_contracts_zone_session::v3::component_session::MetricReason::Cancellation,
                    )]
                );
                error.code()
            },
            SessionErrorCode::Cancelled,
        );
        task.await.unwrap();
        assert_eq!(
            *packets
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            vec![vec![1]]
        );
        assert!(closed.load(Ordering::Acquire));
        drop(writes);
        drop(priority);
    }

    #[tokio::test]
    async fn post_protection_error_closes_writer_before_reply() {
        let close_entered = Arc::new(Notify::new());
        let release_close = Arc::new(Notify::new());
        let closed = Arc::new(AtomicBool::new(false));
        let (writes, receiver) = mpsc::channel(1);
        let (priority, priority_receiver) = mpsc::unbounded_channel();
        let (failures, _failure_receiver) = mpsc::channel(1);
        let task = tokio::spawn(run_writer(
            Box::new(BlockingCloseWriter {
                entered: Arc::clone(&close_entered),
                release: Arc::clone(&release_close),
                closed: Arc::clone(&closed),
            }),
            receiver,
            priority_receiver,
            failures,
            Duration::from_secs(1),
        ));
        let writes_for_completion = writes.clone();
        let priority_for_completion = priority.clone();
        let (reply, mut result) = oneshot::channel();
        let completion = tokio::spawn(async move {
            let permit = writes_for_completion.reserve().await.unwrap();
            let mut prepared =
                PreparedWriteFixture(Some((vec![TransportPacket::new(vec![1])], None, false)));
            complete_after_write(
                &mut prepared,
                permit,
                &priority_for_completion,
                &Cancellation::new(),
                reply,
                Err(SessionError::new(SessionErrorCode::Cancelled)),
            )
            .await;
        });

        close_entered.notified().await;
        assert_eq!(result.try_recv(), Err(oneshot::error::TryRecvError::Empty));
        assert!(!closed.load(Ordering::Acquire));
        release_close.notify_one();
        completion.await.unwrap();
        assert_eq!(
            result.await.unwrap().unwrap_err().code(),
            SessionErrorCode::Cancelled
        );
        assert!(closed.load(Ordering::Acquire));
        drop(writes);
        drop(priority);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn unbatched_writes_preserve_the_cancellation_slot() {
        let descriptor = TransportDescriptor {
            class: d2b_contracts_zone_session::v3::component_session::TransportClass::UnixSeqpacket,
            locality: d2b_contracts_zone_session::v3::component_session::Locality::HostLocal,
            packet_atomic: true,
            supports_attachments: false,
        };
        let (writes, mut receiver) = mpsc::channel(2);
        let (priority, _priority_receiver) = mpsc::unbounded_channel();
        let mut transport = DriverTransport {
            descriptor,
            reader: Box::new(DisconnectedReader),
            writes: writes.clone(),
            priority: priority.clone(),
            write_cancellation: None,
            writer_fence: Cancellation::new(),
            batch: None,
        };
        transport.send(TransportPacket::new(vec![1])).await.unwrap();
        assert_eq!(
            transport
                .send(TransportPacket::new(vec![9]))
                .await
                .unwrap_err(),
            TransportError::WouldBlock
        );

        reserve_cancellation_write(&writes, &priority)
            .unwrap()
            .send(WriterCommand::Batch {
                packets: vec![TransportPacket::new(vec![2])],
                cancellation: None,
                writer_fence: Cancellation::new(),
                completion: None,
                close_after: false,
            });
        let WriterCommand::Batch { packets, .. } = receiver.recv().await.unwrap() else {
            panic!("ordinary write was not queued");
        };
        assert_eq!(packets[0].as_bytes(), &[1]);
        let WriterCommand::Batch { packets, .. } = receiver.recv().await.unwrap() else {
            panic!("cancellation write was not queued");
        };
        assert_eq!(packets[0].as_bytes(), &[2]);
    }

    #[tokio::test]
    async fn driver_transport_enqueues_a_logical_packet_batch_atomically() {
        let descriptor = TransportDescriptor {
            class: d2b_contracts_zone_session::v3::component_session::TransportClass::UnixSeqpacket,
            locality: d2b_contracts_zone_session::v3::component_session::Locality::HostLocal,
            packet_atomic: true,
            supports_attachments: false,
        };
        let (writes, mut receiver) = mpsc::channel(1);
        let (priority, _priority_receiver) = mpsc::unbounded_channel();
        let mut transport = DriverTransport {
            descriptor,
            reader: Box::new(DisconnectedReader),
            writes: writes.clone(),
            priority,
            write_cancellation: None,
            writer_fence: Cancellation::new(),
            batch: None,
        };
        transport.begin_write_batch(None);
        transport.send(TransportPacket::new(vec![1])).await.unwrap();
        transport.send(TransportPacket::new(vec![2])).await.unwrap();
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        let (packets, cancellation, close_after) = transport.take_write_batch().unwrap();
        writes
            .try_send(WriterCommand::Batch {
                packets,
                cancellation,
                writer_fence: transport.writer_fence.clone(),
                completion: None,
                close_after,
            })
            .unwrap();
        let WriterCommand::Batch { packets, .. } = receiver.recv().await.unwrap() else {
            panic!("logical write was not queued as one batch");
        };
        assert_eq!(packets.len(), 2);
    }

    #[test]
    fn queue_exhaustion_aborts_the_writer_through_priority_control() {
        let (writes, _receiver) = mpsc::channel(1);
        writes.try_send(WriterCommand::Close).unwrap();
        let (priority, mut priority_receiver) = mpsc::unbounded_channel();

        let error = match reserve_write_batch(&writes, &priority) {
            Ok(_) => panic!("full logical queue unexpectedly admitted a batch"),
            Err(error) => error,
        };
        assert_eq!(error.code(), SessionErrorCode::QueueBackpressure);
        assert!(matches!(
            priority_receiver.try_recv(),
            Ok(WriterCommand::Abort { error, .. })
                if error.code() == SessionErrorCode::QueueBackpressure
        ));
    }

    #[test]
    fn cancelled_immediate_receiver_restores_queued_event() {
        let mut queue = EventQueue::new(1);
        queue.deliver(7_u8).unwrap();
        let (waiter, receiver) = oneshot::channel();
        drop(receiver);
        queue.receive(waiter).unwrap();

        let (waiter, mut receiver) = oneshot::channel();
        queue.receive(waiter).unwrap();
        assert_eq!(receiver.try_recv().unwrap().unwrap(), 7);
    }

    #[test]
    fn event_queue_capacity_is_measured_in_bytes() {
        let mut queue = EventQueue::new(4);
        queue.deliver(vec![1_u8; 4]).unwrap();
        assert_eq!(
            queue.deliver(vec![2_u8]).unwrap_err().code(),
            SessionErrorCode::QueueBackpressure
        );
        let (waiter, mut receiver) = oneshot::channel();
        queue.receive(waiter).unwrap();
        assert_eq!(receiver.try_recv().unwrap().unwrap(), vec![1_u8; 4]);
        queue.deliver(vec![2_u8]).unwrap();
    }

    #[test]
    fn cancelled_receives_do_not_consume_waiter_capacity() {
        let mut queue = EventQueue::new(1);
        for _ in 0..(DRIVER_COMMAND_CAPACITY * 2) {
            let (waiter, receiver) = oneshot::channel();
            queue.receive(waiter).unwrap();
            drop(receiver);
        }

        let (waiter, mut receiver) = oneshot::channel();
        queue.receive(waiter).unwrap();
        queue.deliver(7_u8).unwrap();
        assert_eq!(receiver.try_recv().unwrap().unwrap(), 7);
    }

    #[tokio::test]
    async fn named_stream_waiters_are_delivered_only_their_stream_events() {
        let first = StreamId::new(0x0100).unwrap();
        let second = StreamId::new(0x0101).unwrap();
        let mut queue = NamedStreamEventQueue::new(8);
        let (first_waiter, first_events) = oneshot::channel();
        let (second_waiter, second_events) = oneshot::channel();

        queue.receive_for(first, first_waiter).unwrap();
        queue.receive_for(second, second_waiter).unwrap();
        queue
            .deliver(StreamEvent::Data {
                stream: second,
                bytes: b"second".to_vec(),
            })
            .unwrap();
        queue.deliver(StreamEvent::Reset { stream: first }).unwrap();

        assert!(matches!(
            first_events.await.unwrap().unwrap(),
            StreamEvent::Reset { stream } if stream == first
        ));
        assert!(matches!(
            second_events.await.unwrap().unwrap(),
            StreamEvent::Data { stream, bytes }
                if stream == second && bytes == b"second"
        ));
    }
}
