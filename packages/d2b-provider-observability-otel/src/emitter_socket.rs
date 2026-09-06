//! Per-Zone Unix datagram receiver for bounded telemetry frames.

use crate::ingress_policy::{Ingress, IngressOutcome, IngressPolicyGate};
use d2b_contracts_provider::v3::{redact_parsed_frame, validate_raw_frame};
use rustix::fs::{Mode, fchmod, fstat};
use std::{
    collections::VecDeque,
    fs, io,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    os::unix::net::UnixDatagram,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use zeroize::Zeroize;

/// Maximum compact frame accepted from a core-process emitter.
pub const MAX_COMPACT_FRAME_BYTES: usize = 64 * 1024;
/// Maximum datagrams consumed by one nonblocking drain call.
pub const MAX_DATAGRAMS_PER_DRAIN: usize = 256;
/// Maximum retained frame count.
pub const MAX_RETAINED_FRAMES: usize = 1024;
/// Maximum retained frame age.
pub const MAX_RETAINED_AGE: Duration = Duration::from_secs(30);

/// Receiver state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverReadiness {
    /// The socket exists and at least one drain cycle completed.
    Ready,
    /// The socket is not yet available.
    Pending,
    /// The socket exists but a drain failed.
    Failed,
}

/// A bounded datagram receiver.
pub struct EmitterSocket {
    path: PathBuf,
    socket: UnixDatagram,
    frames: VecDeque<QueuedFrame>,
    capacity_bytes: usize,
    queued_bytes: usize,
    dropped: u64,
    readiness: ReceiverReadiness,
    identity: (u64, u64, u32, u32),
    policy_gate: IngressPolicyGate,
}

#[derive(Debug)]
struct QueuedFrame {
    bytes: Vec<u8>,
    enqueued_at: Instant,
}

impl Drop for QueuedFrame {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl core::fmt::Debug for EmitterSocket {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("EmitterSocket")
            .field("ready", &self.readiness)
            .field("queued_frames", &self.frames.len())
            .field("dropped", &self.dropped)
            .finish()
    }
}

impl EmitterSocket {
    /// Bind a per-Zone socket without replacing an existing pathname.
    pub fn bind(path: impl AsRef<Path>, capacity_bytes: usize) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        validate_socket_parent(&path)?;
        let socket = UnixDatagram::bind(&path)?;
        if let Err(error) = fchmod(&socket, Mode::from_raw_mode(0o660)) {
            drop(socket);
            let _ = fs::remove_file(&path);
            return Err(error.into());
        }
        if let Err(error) = fs::set_permissions(&path, fs::Permissions::from_mode(0o660)) {
            drop(socket);
            let _ = fs::remove_file(&path);
            return Err(error);
        }
        let metadata = fs::symlink_metadata(&path)?;
        let stat = fstat(&socket)?;
        if !metadata.file_type().is_socket()
            || metadata.permissions().mode() & 0o777 != 0o660
            || metadata.uid() != stat.st_uid
            || metadata.gid() != stat.st_gid
            || stat.st_mode & 0o777 != 0o660
        {
            drop(socket);
            let _ = fs::remove_file(&path);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "telemetry-socket-identity-invalid",
            ));
        }
        socket.set_nonblocking(true)?;
        Ok(Self {
            path,
            socket,
            frames: VecDeque::new(),
            capacity_bytes: capacity_bytes.max(1),
            queued_bytes: 0,
            dropped: 0,
            readiness: ReceiverReadiness::Pending,
            identity: (
                metadata.dev(),
                metadata.ino(),
                metadata.uid(),
                metadata.gid(),
            ),
            policy_gate: IngressPolicyGate::default(),
        })
    }

    /// Drain available datagrams into the bounded FIFO.
    pub fn drain_once(&mut self) -> io::Result<usize> {
        self.prune_expired();
        self.validate_bound_identity()?;
        let mut drained = 0;
        while drained < MAX_DATAGRAMS_PER_DRAIN {
            // One extra byte lets the receiver distinguish a full-size frame
            // from a datagram truncated by the bounded receive buffer.
            let mut bytes = vec![0_u8; MAX_COMPACT_FRAME_BYTES + 1];
            match self.socket.recv(&mut bytes) {
                Ok(size) => {
                    if size > MAX_COMPACT_FRAME_BYTES {
                        self.dropped = self.dropped.saturating_add(1);
                        drained += 1;
                        continue;
                    }
                    bytes.truncate(size);
                    let frame = match validate_raw_frame(&bytes) {
                        Ok(frame) => frame,
                        Err(_) => {
                            self.dropped = self.dropped.saturating_add(1);
                            drained += 1;
                            continue;
                        }
                    };
                    // Unix datagrams do not carry a stable per-sender
                    // connection identity. The shared socket scope is
                    // intentionally accounted as connection id zero.
                    if !matches!(
                        self.policy_gate
                            .admit_parsed(Ingress::EmitterUnix, 0, &frame, bytes.len())
                            .0,
                        IngressOutcome::Accepted
                    ) {
                        self.dropped = self.dropped.saturating_add(1);
                        drained += 1;
                        continue;
                    }
                    let Some(bytes) = redact_parsed_frame(frame).ok() else {
                        self.dropped = self.dropped.saturating_add(1);
                        drained += 1;
                        continue;
                    };
                    if bytes.len() > self.capacity_bytes {
                        self.dropped = self.dropped.saturating_add(1);
                        drained += 1;
                        continue;
                    }
                    while self.queued_bytes.saturating_add(bytes.len()) > self.capacity_bytes {
                        let Some(oldest) = self.frames.pop_front() else {
                            break;
                        };
                        self.queued_bytes = self.queued_bytes.saturating_sub(oldest.bytes.len());
                        self.dropped = self.dropped.saturating_add(1);
                    }
                    while self.frames.len() >= MAX_RETAINED_FRAMES {
                        let Some(oldest) = self.frames.pop_front() else {
                            break;
                        };
                        self.queued_bytes = self.queued_bytes.saturating_sub(oldest.bytes.len());
                        self.dropped = self.dropped.saturating_add(1);
                    }
                    self.queued_bytes += bytes.len();
                    self.frames.push_back(QueuedFrame {
                        bytes,
                        enqueued_at: Instant::now(),
                    });
                    drained += 1;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => {
                    self.readiness = ReceiverReadiness::Failed;
                    return Err(error);
                }
            }
        }
        self.readiness = ReceiverReadiness::Ready;
        Ok(drained)
    }

    /// Pop the oldest received frame.
    pub fn pop(&mut self) -> Option<Vec<u8>> {
        self.prune_expired();
        let mut frame = self.frames.pop_front()?;
        self.queued_bytes = self.queued_bytes.saturating_sub(frame.bytes.len());
        Some(std::mem::take(&mut frame.bytes))
    }

    /// Current receiver readiness.
    pub const fn readiness(&self) -> ReceiverReadiness {
        self.readiness
    }

    /// Number of frames dropped due to bounded storage.
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Number of queued frames.
    pub fn queued(&self) -> usize {
        self.frames.len()
    }

    /// Number of queued bytes.
    pub const fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    /// Maximum retained frame age.
    pub const fn max_age(&self) -> Duration {
        MAX_RETAINED_AGE
    }

    /// Borrow the owned socket path for activation diagnostics.
    pub fn socket_path(&self) -> &Path {
        &self.path
    }

    fn validate_bound_identity(&mut self) -> io::Result<()> {
        let metadata = fs::symlink_metadata(&self.path)?;
        let stat = fstat(&self.socket)?;
        let identity = (
            metadata.dev(),
            metadata.ino(),
            metadata.uid(),
            metadata.gid(),
        );
        if !metadata.file_type().is_socket()
            || metadata.permissions().mode() & 0o777 != 0o660
            || identity != self.identity
            || stat.st_mode & 0o777 != 0o660
            || stat.st_uid != self.identity.2
            || stat.st_gid != self.identity.3
        {
            self.readiness = ReceiverReadiness::Failed;
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "telemetry-socket-identity-invalid",
            ))
        } else {
            Ok(())
        }
    }

    fn prune_expired(&mut self) {
        while self
            .frames
            .front()
            .is_some_and(|frame| frame.enqueued_at.elapsed() >= MAX_RETAINED_AGE)
        {
            let frame = self.frames.pop_front().expect("front was present");
            self.queued_bytes = self.queued_bytes.saturating_sub(frame.bytes.len());
            self.dropped = self.dropped.saturating_add(1);
        }
    }
}

impl Drop for EmitterSocket {
    fn drop(&mut self) {
        if let Ok(metadata) = fs::symlink_metadata(&self.path)
            && metadata.file_type().is_socket()
            && (
                metadata.dev(),
                metadata.ino(),
                metadata.uid(),
                metadata.gid(),
            ) == self.identity
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn validate_socket_parent(path: &Path) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "telemetry-socket-path-not-absolute",
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "telemetry-socket-parent-invalid",
        )
    })?;
    let metadata = fs::symlink_metadata(parent).map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "telemetry-socket-parent-invalid",
        )
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o022 != 0
        || fs::canonicalize(parent).ok().as_deref() != Some(parent)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "telemetry-socket-parent-symlink",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::net::UnixDatagram,
        sync::atomic::{AtomicUsize, Ordering},
    };

    static SOCKET_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    fn test_socket_path(prefix: &str) -> PathBuf {
        let sequence = SOCKET_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let directory =
            std::env::temp_dir().join(format!("d2b-o-{:x}-{sequence:x}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join(format!("{prefix}.sock"));
        assert!(
            path.as_os_str().len() <= 100,
            "AF_UNIX test path must leave sockaddr headroom"
        );
        path
    }

    fn cleanup_socket(path: PathBuf) {
        let parent = path.parent().map(Path::to_path_buf);
        let _ = fs::remove_file(path);
        if let Some(parent) = parent {
            let _ = fs::remove_dir(parent);
        }
    }

    #[test]
    fn receiver_drains_datagrams_and_reports_ready() {
        let path = test_socket_path("e");
        let mut receiver = EmitterSocket::bind(&path, 512).unwrap();
        let sender = UnixDatagram::unbound().unwrap();
        sender
            .send_to(
                br#"{"signal":"metric","value":{"name":"d2b_otel_ingress_policy_total","labels":{"ingress":"emitter_unix","outcome":"accepted","error_class":"none"},"value":1}}"#,
                &path,
            )
            .unwrap();
        assert_eq!(receiver.drain_once().unwrap(), 1);
        assert_eq!(receiver.readiness(), ReceiverReadiness::Ready);
        assert_eq!(
            receiver
                .pop()
                .and_then(|frame| String::from_utf8(frame).ok())
                .as_deref(),
            Some(
                r#"{"signal":"metric","value":{"labels":{"error_class":"none","ingress":"emitter_unix","outcome":"accepted"},"name":"d2b_otel_ingress_policy_total","value":1}}"#,
            )
        );
        drop(receiver);
        cleanup_socket(path);
    }

    #[test]
    fn receiver_uses_closed_descriptor_accounting_before_queue_insertion() {
        let path = test_socket_path("registry");
        let mut receiver = EmitterSocket::bind(&path, 512).unwrap();
        let sender = UnixDatagram::unbound().unwrap();
        sender
            .send_to(
                br#"{"signal":"metric","value":{"name":"d2b_unregistered_total","labels":{"outcome":"ok"},"value":1}}"#,
                &path,
            )
            .unwrap();
        sender
            .send_to(
                br#"{"signal":"metric","value":{"name":"d2b_otel_ingress_policy_total","labels":{"ingress":"emitter_unix","outcome":"accepted","error_class":"none"},"value":1}}"#,
                &path,
            )
            .unwrap();

        assert_eq!(receiver.drain_once().unwrap(), 2);
        assert_eq!(receiver.queued(), 1);
        assert!(
            String::from_utf8(receiver.pop().unwrap())
                .unwrap()
                .contains("d2b_otel_ingress_policy_total")
        );
        assert_eq!(receiver.dropped(), 1);
        drop(receiver);
        cleanup_socket(path);
    }

    #[test]
    fn receiver_redacts_or_drops_forbidden_frames_within_bounds() {
        let path = test_socket_path("er");
        let mut receiver = EmitterSocket::bind(&path, 512).unwrap();
        let sender = UnixDatagram::unbound().unwrap();
        sender
            .send_to(
                br#"{"signal":"trace","value":{"path":"/private/canary","d2b.zone":"identity-canary"}}"#,
                &path,
            )
            .unwrap();
        sender.send_to(b"attacker-text", &path).unwrap();
        assert_eq!(receiver.drain_once().unwrap(), 2);
        let frame = receiver.pop().unwrap();
        let rendered = String::from_utf8(frame).unwrap();
        assert!(!rendered.contains("/private/canary"));
        assert!(!rendered.contains("identity-canary"));
        assert_eq!(receiver.queued(), 0);
        assert_eq!(receiver.dropped(), 1);
        drop(receiver);
        cleanup_socket(path);
    }

    #[test]
    fn inode_checked_drop_does_not_remove_replacement_socket() {
        let path = test_socket_path("race");
        let receiver = EmitterSocket::bind(&path, 512).unwrap();
        fs::remove_file(&path).unwrap();
        let replacement = UnixDatagram::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).unwrap();
        drop(receiver);
        assert!(path.exists());
        drop(replacement);
        cleanup_socket(path);
    }
}
