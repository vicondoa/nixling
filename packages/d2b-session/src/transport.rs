use std::{error::Error, fmt};

use async_trait::async_trait;
use d2b_contracts_zone_session::v3::component_session::{Locality, TransportClass};
use tokio::sync::Mutex;

use crate::{Cancellation, OwnedAttachment};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportDescriptor {
    pub class: TransportClass,
    pub locality: Locality,
    pub packet_atomic: bool,
    pub supports_attachments: bool,
}

pub struct TransportPacket {
    bytes: Vec<u8>,
    attachments: Vec<OwnedAttachment>,
}

impl TransportPacket {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            attachments: Vec::new(),
        }
    }

    pub fn with_attachments(bytes: Vec<u8>, attachments: Vec<OwnedAttachment>) -> Self {
        Self { bytes, attachments }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn attachments(&self) -> &[OwnedAttachment] {
        &self.attachments
    }

    pub fn into_parts(self) -> (Vec<u8>, Vec<OwnedAttachment>) {
        (self.bytes, self.attachments)
    }
}

impl fmt::Debug for TransportPacket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransportPacket")
            .field("bytes", &"<redacted>")
            .field("len", &self.bytes.len())
            .field("attachments", &self.attachments.len())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    Disconnected,
    WouldBlock,
    Truncated,
    LimitExceeded,
    InvalidAttachment,
    Other,
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Disconnected => "transport-disconnected",
            Self::WouldBlock => "transport-would-block",
            Self::Truncated => "transport-truncated",
            Self::LimitExceeded => "transport-limit-exceeded",
            Self::InvalidAttachment => "transport-invalid-attachment",
            Self::Other => "transport-error",
        })
    }
}

impl Error for TransportError {}

#[async_trait]
pub trait TransportReader: Send {
    async fn receive(
        &mut self,
        protected_limit: usize,
    ) -> std::result::Result<TransportPacket, TransportError>;
}

#[async_trait]
pub trait TransportWriter: Send {
    async fn send(&mut self, packet: TransportPacket) -> std::result::Result<(), TransportError>;

    async fn close(&mut self) -> std::result::Result<(), TransportError>;
}

#[async_trait]
pub trait OwnedTransport: Send + 'static {
    fn descriptor(&self) -> TransportDescriptor;

    /// Separates established-session reads from writes.
    ///
    /// Implementations used by the async session driver must return halves
    /// that can make progress concurrently. This ownership split happens only
    /// after the authenticated handshake has completed.
    fn into_split(self: Box<Self>) -> (Box<dyn TransportReader>, Box<dyn TransportWriter>);

    /// Applies a cancellation guard to packets enqueued by the next logical
    /// write. Direct transports complete writes inline and need no guard.
    fn set_write_cancellation(&mut self, _cancellation: Option<Cancellation>) {}

    /// Begins driver-owned atomic collection for one logical write.
    #[doc(hidden)]
    fn begin_write_batch(&mut self, cancellation: Option<Cancellation>) {
        self.set_write_cancellation(cancellation);
    }

    /// Takes one driver-owned logical write and its close disposition.
    #[doc(hidden)]
    fn take_write_batch(&mut self) -> Option<(Vec<TransportPacket>, Option<Cancellation>, bool)> {
        None
    }

    /// Receives protected bytes and opaque transport-owned payloads.
    ///
    /// A transport must construct received attachments with
    /// [`OwnedAttachment::unbound`]. Their descriptors remain encrypted until
    /// ComponentSession authenticates and binds them.
    async fn receive(
        &mut self,
        protected_limit: usize,
    ) -> std::result::Result<TransportPacket, TransportError>;

    /// Sends one owned packet.
    ///
    /// The transport may borrow attachment payloads for its atomic send. On
    /// success the peer owns any kernel-created duplicates; local payloads are
    /// closed when this consumed packet is dropped. On failure they are also
    /// dropped and closed. A transport that must retain ownership may use
    /// [`OwnedAttachment::into_payload`] and assumes sole close responsibility.
    async fn send(&mut self, packet: TransportPacket) -> std::result::Result<(), TransportError>;

    async fn close(&mut self) -> std::result::Result<(), TransportError>;
}

/// An opaque, single-owner transport handle returned by a typed Transport
/// Provider operation.
///
/// The handle exposes only the transport descriptor and the ability to
/// consume or close the owned carriage. It carries no ZoneLink state,
/// authorization claims, or raw locator.
pub struct OwnedTransportHandle(Option<Box<dyn OwnedTransport>>);

impl OwnedTransportHandle {
    /// Wrap one owned transport without exposing its implementation type.
    pub fn new<T>(transport: T) -> Self
    where
        T: OwnedTransport,
    {
        Self(Some(Box::new(transport)))
    }

    /// Wrap an already erased owned transport.
    pub fn from_box(transport: Box<dyn OwnedTransport>) -> Self {
        Self(Some(transport))
    }

    /// Borrow the immutable carriage descriptor.
    pub fn descriptor(&self) -> TransportDescriptor {
        self.0
            .as_ref()
            .expect("an owned transport handle is consumed only once")
            .descriptor()
    }

    /// Consume the handle and return the session-owned transport.
    pub fn into_owned_transport(mut self) -> Box<dyn OwnedTransport> {
        self.0
            .take()
            .expect("an owned transport handle is consumed only once")
    }

    /// Close the owned carriage and consume the handle.
    pub async fn close(mut self) -> std::result::Result<(), TransportError> {
        self.0
            .take()
            .expect("an owned transport handle is consumed only once")
            .close()
            .await
    }
}

impl fmt::Debug for OwnedTransportHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OwnedTransportHandle(<redacted>)")
    }
}

struct SerializedReader {
    transport: std::sync::Arc<Mutex<Box<dyn OwnedTransport>>>,
}

struct SerializedWriter {
    transport: std::sync::Arc<Mutex<Box<dyn OwnedTransport>>>,
}

/// Compatibility split for transports that are never driven concurrently.
///
/// Production transports and driver tests must provide independent halves;
/// this helper exists for direct engine-only test transports.
pub fn serialized_transport_split(
    transport: Box<dyn OwnedTransport>,
) -> (Box<dyn TransportReader>, Box<dyn TransportWriter>) {
    let transport = std::sync::Arc::new(Mutex::new(transport));
    (
        Box::new(SerializedReader {
            transport: std::sync::Arc::clone(&transport),
        }),
        Box::new(SerializedWriter { transport }),
    )
}

#[async_trait]
impl TransportReader for SerializedReader {
    async fn receive(
        &mut self,
        protected_limit: usize,
    ) -> std::result::Result<TransportPacket, TransportError> {
        self.transport.lock().await.receive(protected_limit).await
    }
}

#[async_trait]
impl TransportWriter for SerializedWriter {
    async fn send(&mut self, packet: TransportPacket) -> std::result::Result<(), TransportError> {
        self.transport.lock().await.send(packet).await
    }

    async fn close(&mut self) -> std::result::Result<(), TransportError> {
        self.transport.lock().await.close().await
    }
}
