//! Bounded local transport-handle ownership and socket observation.

use crate::{
    admission::{OpenTransportRequest, SocketKind, TransportAdmissionError, validate_and_prepare},
    identity::{AcceptedTransport, TransportRequestBinding},
};
use getrandom::fill;
use rustix::{
    event::{PollFd, PollFlags, poll},
    fd::{AsFd, OwnedFd},
    io::fcntl_dupfd_cloexec,
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    error::Error,
    fmt,
    sync::Mutex,
};

const MAX_OPEN_TRANSPORTS: usize = 256;

/// Opaque, redacted transport handle.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransportHandle([u8; 16]);

impl fmt::Debug for TransportHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TransportHandle(REDACTED)")
    }
}

/// Stable, non-sensitive properties returned for an accepted transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportDescriptor {
    socket_kind: SocketKind,
    attachments_enabled: bool,
}

impl TransportDescriptor {
    /// Return the verified socket kind.
    pub const fn socket_kind(self) -> SocketKind {
        self.socket_kind
    }

    /// Return whether the route can carry descriptor attachments.
    pub const fn attachments_enabled(self) -> bool {
        self.attachments_enabled
    }
}

/// Socket-level observation without payload or identity data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportObservation {
    /// The socket has no terminal event.
    Pending,
    /// The remote peer disconnected.
    PeerDisconnected,
    /// The socket reports a non-disconnect error.
    Error,
}

/// Result of opening a transport.
pub struct OpenedTransport {
    handle: TransportHandle,
    descriptor: TransportDescriptor,
    transport_fd: OwnedFd,
}

impl OpenedTransport {
    /// Return the opaque monitoring handle.
    pub const fn handle(&self) -> TransportHandle {
        self.handle
    }

    /// Return verified transport properties.
    pub const fn descriptor(&self) -> TransportDescriptor {
        self.descriptor
    }

    /// Borrow the caller-owned transport descriptor.
    pub fn transport_fd(&self) -> rustix::fd::BorrowedFd<'_> {
        self.transport_fd.as_fd()
    }

    /// Transfer the validated transport descriptor to ComponentSession.
    pub fn into_transport_fd(self) -> OwnedFd {
        self.transport_fd
    }
}

impl fmt::Debug for OpenedTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenedTransport")
            .field("handle", &self.handle)
            .field("descriptor", &self.descriptor)
            .finish_non_exhaustive()
    }
}

/// Fail-closed portal operation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortalError {
    /// The requested attachment policy is not valid for this route.
    AttachmentPolicyConflict,
    /// The accepted descriptor does not match the requested socket kind.
    SocketKindMismatch,
    /// The descriptor cannot be protected with close-on-exec.
    Cloexec,
    /// The accepted descriptor does not expose kernel peer credentials.
    PeerCredentials,
    /// The per-service monitor table is full.
    HandleTableFull,
    /// The supplied handle is not owned by this portal instance.
    UnknownHandle,
    /// The portal monitor table is unavailable after an internal failure.
    MonitorUnavailable,
}

impl From<TransportAdmissionError> for PortalError {
    fn from(value: TransportAdmissionError) -> Self {
        match value {
            TransportAdmissionError::AttachmentPolicyConflict => Self::AttachmentPolicyConflict,
            TransportAdmissionError::SocketKindMismatch => Self::SocketKindMismatch,
            TransportAdmissionError::Cloexec => Self::Cloexec,
            TransportAdmissionError::PeerCredentials => Self::PeerCredentials,
        }
    }
}

impl fmt::Display for PortalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AttachmentPolicyConflict => "attachment-policy-conflict",
            Self::SocketKindMismatch => "socket-kind-mismatch",
            Self::Cloexec => "cloexec-set-failed",
            Self::PeerCredentials => "peer-credentials-unavailable",
            Self::HandleTableFull => "handle-table-full",
            Self::UnknownHandle => "unknown-handle",
            Self::MonitorUnavailable => "transport-monitor-unavailable",
        })
    }
}

impl Error for PortalError {}

struct MonitorEntry {
    _binding: TransportRequestBinding,
    _peer: rustix::net::UCred,
    monitor_fd: OwnedFd,
}

/// One service-local, bounded transport portal.
pub struct TransportPortal {
    state: Mutex<PortalState>,
}

struct PortalState {
    entries: HashMap<TransportHandle, MonitorEntry>,
    finalized: HashSet<TransportHandle>,
    finalized_order: VecDeque<TransportHandle>,
}

impl PortalState {
    fn mark_finalized(&mut self, handle: TransportHandle) {
        if self.finalized.insert(handle) {
            self.finalized_order.push_back(handle);
        }
        if self.finalized_order.len() > MAX_OPEN_TRANSPORTS {
            let evicted = self
                .finalized_order
                .pop_front()
                .expect("finalized order is populated");
            self.finalized.remove(&evicted);
        }
    }
}

impl Default for TransportPortal {
    fn default() -> Self {
        Self::new()
    }
}

impl TransportPortal {
    /// Create an empty bounded portal.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(PortalState {
                entries: HashMap::new(),
                finalized: HashSet::new(),
                finalized_order: VecDeque::new(),
            }),
        }
    }

    /// Validate one accepted descriptor and transfer it to the caller.
    ///
    /// The portal retains request binding, peer evidence, and a close-on-exec
    /// duplicate for observation. The original accepted descriptor has exactly
    /// one transfer destination.
    pub fn open(
        &self,
        binding: TransportRequestBinding,
        request: OpenTransportRequest,
        fd: OwnedFd,
    ) -> Result<OpenedTransport, PortalError> {
        validate_and_prepare(&fd, request)?;
        let accepted =
            AcceptedTransport::bind(binding, fd).map_err(|_| PortalError::PeerCredentials)?;
        let (binding, peer, fd) = accepted.into_parts();
        let descriptor = TransportDescriptor {
            socket_kind: request.socket_kind(),
            attachments_enabled: request.attachments_enabled(),
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| PortalError::MonitorUnavailable)?;
        if state.entries.len() == MAX_OPEN_TRANSPORTS {
            return Err(PortalError::HandleTableFull);
        }
        let monitor_fd = fcntl_dupfd_cloexec(fd.as_fd(), 3).map_err(|_| PortalError::Cloexec)?;
        let handle = next_handle(&state)?;
        state.entries.insert(
            handle,
            MonitorEntry {
                _binding: binding,
                _peer: peer,
                monitor_fd,
            },
        );
        Ok(OpenedTransport {
            handle,
            descriptor,
            transport_fd: fd,
        })
    }

    /// Close a monitored transport, refusing handles owned by another portal.
    pub fn close(&self, handle: TransportHandle) -> Result<(), PortalError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| PortalError::MonitorUnavailable)?;
        if state.entries.remove(&handle).is_some() {
            state.mark_finalized(handle);
            Ok(())
        } else if state.finalized.contains(&handle) {
            Ok(())
        } else {
            Err(PortalError::UnknownHandle)
        }
    }

    /// Return the current socket-level monitor state for one portal-owned fd.
    pub fn observe(&self, handle: TransportHandle) -> Result<TransportObservation, PortalError> {
        let state = self
            .state
            .lock()
            .map_err(|_| PortalError::MonitorUnavailable)?;
        let entry = state
            .entries
            .get(&handle)
            .ok_or(PortalError::UnknownHandle)?;
        let mut fds = [PollFd::new(
            &entry.monitor_fd,
            PollFlags::ERR | PollFlags::HUP | PollFlags::RDHUP,
        )];
        poll(&mut fds, 0).map_err(|_| PortalError::MonitorUnavailable)?;
        let observed = fds[0].revents();
        if observed.intersects(PollFlags::HUP | PollFlags::RDHUP) {
            Ok(TransportObservation::PeerDisconnected)
        } else if observed.contains(PollFlags::ERR) {
            Ok(TransportObservation::Error)
        } else {
            Ok(TransportObservation::Pending)
        }
    }

    /// Retire every portal-owned monitor descriptor during service finalization.
    pub fn finalize(&self) {
        if let Ok(mut state) = self.state.lock() {
            let handles = state
                .entries
                .drain()
                .map(|(handle, _)| handle)
                .collect::<Vec<_>>();
            for handle in handles {
                state.mark_finalized(handle);
            }
        }
    }
}

impl Drop for TransportPortal {
    fn drop(&mut self) {
        self.finalize();
    }
}

impl fmt::Debug for TransportPortal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TransportPortal(REDACTED)")
    }
}

fn next_handle(state: &PortalState) -> Result<TransportHandle, PortalError> {
    for _ in 0..8 {
        let mut bytes = [0_u8; 16];
        fill(&mut bytes).map_err(|_| PortalError::MonitorUnavailable)?;
        let handle = TransportHandle(bytes);
        if handle_is_available(state, handle) {
            return Ok(handle);
        }
    }
    Err(PortalError::MonitorUnavailable)
}

fn handle_is_available(state: &PortalState, handle: TransportHandle) -> bool {
    !state.entries.contains_key(&handle) && !state.finalized.contains(&handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finalized_handles_cannot_be_reissued() {
        let handle = TransportHandle([42; 16]);
        let mut state = PortalState {
            entries: HashMap::new(),
            finalized: HashSet::new(),
            finalized_order: VecDeque::new(),
        };

        state.mark_finalized(handle);

        assert!(!handle_is_available(&state, handle));
    }
}
