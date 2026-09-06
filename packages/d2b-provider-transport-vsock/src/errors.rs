//! Stable, identity-free Provider errors.

use std::{error::Error, fmt};

/// Errors reported by the framed byte transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    /// The transport has already been closed.
    Closed,
    /// The peer disconnected before a complete record arrived.
    Disconnected,
    /// The peer disconnected after a record had started.
    Truncated,
    /// A frame exceeded the configured bound.
    FrameTooLarge,
    /// A frame was empty or malformed.
    InvalidFrame,
    /// Attachments are not supported by vsock.
    AttachmentsNotSupported,
    /// The underlying stream returned an I/O failure.
    Io,
}

impl TransportError {
    /// Return the stable error code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Closed => "transport-closed",
            Self::Disconnected => "transport-disconnected",
            Self::Truncated => "transport-truncated",
            Self::FrameTooLarge => "transport-frame-too-large",
            Self::InvalidFrame => "transport-invalid-frame",
            Self::AttachmentsNotSupported => "transport-attachments-not-supported",
            Self::Io => "transport-io",
        }
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for TransportError {}

/// Fail-closed failures from the injected native vsock effect port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VsockEffectError {
    /// The deadline expired before the endpoint was acquired.
    DeadlineExceeded,
    /// The endpoint refused the connection.
    ConnectRefused,
    /// The endpoint could not be reached.
    CidUnreachable,
    /// The selected binding is already occupied.
    PortConflict,
    /// The effect was rejected by the core adapter.
    EffectRejected,
    /// The endpoint or binding was not found.
    EndpointUnavailable,
    /// The effect can be retried.
    Transient,
}

impl VsockEffectError {
    /// Return the stable error code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::DeadlineExceeded => "deadline-exceeded",
            Self::ConnectRefused => "connect-refused",
            Self::CidUnreachable => "cid-unreachable",
            Self::PortConflict => "port-conflict",
            Self::EffectRejected => "effect-rejected",
            Self::EndpointUnavailable => "endpoint-unavailable",
            Self::Transient => "transient",
        }
    }
}

impl fmt::Display for VsockEffectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for VsockEffectError {}

/// Service lifecycle failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceError {
    /// The supplied session is not Ready for transport use.
    SessionNotReady,
    /// The supplied session is not bound to this Provider's Guest/Zone.
    SessionIdentityMismatch,
    /// The request carried a zero reconnect generation.
    InvalidSessionGeneration,
    /// The request generation does not match the authenticated session.
    SessionGenerationMismatch,
    /// The request's endpoint ID is malformed.
    InvalidEndpointId,
    /// The request's binding ID is malformed.
    InvalidBindingId,
    /// The open deadline is outside the closed range.
    InvalidDeadline,
    /// The service has reached its active transport limit.
    ProviderOverloaded,
    /// The effect port refused the open.
    Effect(VsockEffectError),
    /// The named stream could not be created.
    StreamUnavailable,
    /// The requested handle is not owned by this service.
    UnknownTransportHandle,
    /// The bridge did not close within its bounded grace period.
    CloseUnconfirmed,
}

impl ServiceError {
    /// Return the stable error code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::SessionNotReady => "session-not-ready",
            Self::SessionIdentityMismatch => "session-identity-mismatch",
            Self::InvalidSessionGeneration => "invalid-session-generation",
            Self::SessionGenerationMismatch => "session-generation-mismatch",
            Self::InvalidEndpointId => "invalid-endpoint-id",
            Self::InvalidBindingId => "invalid-binding-id",
            Self::InvalidDeadline => "invalid-deadline",
            Self::ProviderOverloaded => "provider-overloaded",
            Self::Effect(error) => error.code(),
            Self::StreamUnavailable => "stream-unavailable",
            Self::UnknownTransportHandle => "unknown-transport-handle",
            Self::CloseUnconfirmed => "close-unconfirmed",
        }
    }
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for ServiceError {}

impl From<VsockEffectError> for ServiceError {
    fn from(value: VsockEffectError) -> Self {
        Self::Effect(value)
    }
}
