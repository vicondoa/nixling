use crate::{
    credit::{CreditBundle, CreditScopeSet},
    descriptor::{PeerCredentials, ReceivedControl, ReceivedPacket},
    error::{UnixSessionError, io_error},
};
use d2b_contracts_zone_session::v3::component_session::{
    AttachmentPolicy, AttachmentPolicyKind, LimitProfile, MAX_PACKET_ATTACHMENTS,
};
use rustix::{
    fd::{AsFd, BorrowedFd, OwnedFd},
    fs::{OFlags, fcntl_getfl},
    io::{FdFlags, IoSlice, IoSliceMut, fcntl_getfd, read},
    net::{
        AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
        SendAncillaryMessage, SendFlags, Shutdown, SocketFlags, SocketType, UCred, recvmsg, send,
        sendmsg, shutdown, socketpair,
        sockopt::{
            get_socket_domain, get_socket_passcred, get_socket_peercred, get_socket_type,
            set_socket_passcred,
        },
    },
    process::{getgid, getpid, getuid},
};
use std::{
    collections::VecDeque,
    fmt, io,
    mem::size_of,
    os::fd::RawFd,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
#[cfg(feature = "test-support")]
use std::os::fd::AsRawFd;
use tokio::io::unix::AsyncFd;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AncillaryCapacity {
    bytes: usize,
    max_files: usize,
    credentials_allowed: bool,
}

impl AncillaryCapacity {
    pub fn from_policy(policy: AttachmentPolicy) -> Result<Self, UnixSessionError> {
        if policy.kind != AttachmentPolicyKind::PacketAtomic
            || (policy.max_per_packet == 0 && !policy.credentials_allowed)
            || policy.max_per_packet > MAX_PACKET_ATTACHMENTS
        {
            return Err(UnixSessionError::AncillaryCapacity);
        }
        let max_files = usize::from(policy.max_per_packet);
        let each_right = rustix::cmsg_space!(ScmRights(1));
        let rights = each_right
            .checked_mul(max_files)
            .ok_or(UnixSessionError::AncillaryCapacity)?;
        let credentials = if policy.credentials_allowed {
            rustix::cmsg_aligned_space!(ScmCredentials(1))
        } else {
            0
        };
        let bytes = rights
            .checked_add(credentials)
            .ok_or(UnixSessionError::AncillaryCapacity)?;
        Ok(Self {
            bytes,
            max_files,
            credentials_allowed: policy.credentials_allowed,
        })
    }

    pub fn bytes(self) -> usize {
        self.bytes
    }

    pub fn max_files(self) -> usize {
        self.max_files
    }

    pub fn credentials_allowed(self) -> bool {
        self.credentials_allowed
    }
}

pub struct OutboundPacket {
    payload: zeroize::Zeroizing<Vec<u8>>,
    files: Vec<Arc<OwnedFd>>,
    credentials: Option<PeerCredentials>,
    credits: CreditBundle,
}

impl fmt::Debug for OutboundPacket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboundPacket")
            .field("payload_bytes", &self.payload.len())
            .field("file_count", &self.files.len())
            .field("has_credentials", &self.credentials.is_some())
            .finish()
    }
}

impl OutboundPacket {
    pub fn new(
        payload: Vec<u8>,
        files: Vec<Arc<OwnedFd>>,
        credentials: Option<PeerCredentials>,
        limits: LimitProfile,
        capacity: AncillaryCapacity,
        credit_scopes: &CreditScopeSet,
    ) -> Result<Self, UnixSessionError> {
        if payload.is_empty() {
            return Err(UnixSessionError::EmptyPacket);
        }
        let file_count = files.len();
        if payload.len()
            > usize::try_from(limits.protected_ciphertext_bytes)
                .map_err(|_| UnixSessionError::PayloadLimit)?
            || file_count > capacity.max_files
            || (credentials.is_some() && !capacity.credentials_allowed)
        {
            return Err(UnixSessionError::PayloadLimit);
        }
        let credits = credit_scopes
            .reserve(file_count)
            .map_err(|_| UnixSessionError::CreditExceeded)?;
        Ok(Self {
            payload: zeroize::Zeroizing::new(payload),
            files,
            credentials,
            credits,
        })
    }

    pub fn with_current_credentials(
        payload: Vec<u8>,
        files: Vec<Arc<OwnedFd>>,
        limits: LimitProfile,
        capacity: AncillaryCapacity,
        credit_scopes: &CreditScopeSet,
    ) -> Result<Self, UnixSessionError> {
        Self::new(
            payload,
            files,
            Some(PeerCredentials::from_ucred(UCred {
                pid: getpid(),
                uid: getuid(),
                gid: getgid(),
            })),
            limits,
            capacity,
            credit_scopes,
        )
    }
}

#[derive(Debug)]
pub struct PacketBurst {
    pub packets: Vec<ReceivedPacket>,
    pub drained_to_would_block: bool,
}

pub struct SentPacket {
    _files: Vec<Arc<OwnedFd>>,
    credits: CreditBundle,
}

impl fmt::Debug for SentPacket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SentPacket(REDACTED)")
    }
}

impl SentPacket {
    pub fn acknowledge(self) {}

    pub fn credits_mut(&mut self) -> &mut CreditBundle {
        &mut self.credits
    }
}

#[derive(Debug)]
pub struct SendBurst {
    pub sent: Vec<SentPacket>,
    pub queue_empty: bool,
    pub drained_to_would_block: bool,
}

pub struct SeqpacketSocket {
    io: AsyncFd<OwnedFd>,
    received_any: AtomicBool,
}

impl fmt::Debug for SeqpacketSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SeqpacketSocket(REDACTED)")
    }
}

impl SeqpacketSocket {
    pub fn from_owned(fd: OwnedFd) -> Result<Self, UnixSessionError> {
        validate_socket(&fd, SocketType::SEQPACKET)?;
        Ok(Self {
            io: AsyncFd::new(fd).map_err(io_error)?,
            received_any: AtomicBool::new(false),
        })
    }

    pub fn from_parent_prearmed(fd: OwnedFd) -> Result<Self, UnixSessionError> {
        verify_parent_prearmed(&fd)?;
        Self::from_owned(fd)
    }

    /// Adopt a broker-inherited descriptor, restoring close-on-exec before
    /// validating the prearmed Unix seqpacket contract.
    ///
    /// The broker deliberately clears close-on-exec while arranging fd 10 so
    /// the controller can receive it across `execve`. This function validates
    /// that well-known descriptor without closing it, rearms close-on-exec,
    /// and then takes ownership before any session use.
    pub fn from_inherited_fd(raw_fd: RawFd) -> Result<Self, UnixSessionError> {
        let fd = duplicate_inherited_fd(raw_fd)?;
        let socket = Self::from_parent_prearmed(fd)?;
        nix::unistd::close(raw_fd).map_err(nix_io_error)?;
        Ok(socket)
    }

    pub fn acceptor_peer_credentials(&self) -> Result<PeerCredentials, UnixSessionError> {
        get_socket_peercred(self.io.get_ref())
            .map(PeerCredentials::from_ucred)
            .map_err(io_error)
    }

    pub fn verify_parent_prearmed(&self) -> Result<(), UnixSessionError> {
        verify_parent_prearmed(self.io.get_ref())
    }

    pub fn close(&self) -> Result<(), UnixSessionError> {
        shutdown(self.io.get_ref(), Shutdown::ReadWrite).map_err(io_error)
    }

    pub async fn recv_burst(
        &self,
        limits: LimitProfile,
        capacity: AncillaryCapacity,
        ingress_credit_scopes: &CreditScopeSet,
        fairness_budget: usize,
    ) -> Result<PacketBurst, UnixSessionError> {
        if fairness_budget == 0 {
            return Err(UnixSessionError::FairnessBudget);
        }
        let payload_capacity = usize::try_from(limits.protected_ciphertext_bytes)
            .map_err(|_| UnixSessionError::PayloadLimit)?;
        let mut ready = self.io.readable().await.map_err(io_error)?;
        let mut packets = Vec::new();
        while packets.len() < fairness_budget {
            match ready.try_io(|inner| recv_one(inner.get_ref(), payload_capacity, capacity.bytes))
            {
                Ok(Ok((payload, controls, unknown_control))) => {
                    let first_on_socket = !self.received_any.swap(true, Ordering::AcqRel);
                    let file_count = controls
                        .iter()
                        .filter(|control| matches!(control, ReceivedControl::File(_)))
                        .count();
                    let credits = ingress_credit_scopes
                        .reserve_ingress(file_count)
                        .map_err(|_| UnixSessionError::CreditExceeded)?;
                    packets.push(ReceivedPacket {
                        payload,
                        controls,
                        unknown_control,
                        first_on_socket,
                        credits,
                    });
                }
                Ok(Err(error)) => {
                    self.received_any.store(true, Ordering::Release);
                    return Err(classify_io(error));
                }
                Err(_) => {
                    return Ok(PacketBurst {
                        packets,
                        drained_to_would_block: true,
                    });
                }
            }
        }
        Ok(PacketBurst {
            packets,
            drained_to_would_block: false,
        })
    }

    pub async fn send_burst(
        &self,
        queue: &mut VecDeque<OutboundPacket>,
        capacity: AncillaryCapacity,
        fairness_budget: usize,
    ) -> Result<SendBurst, UnixSessionError> {
        if fairness_budget == 0 {
            return Err(UnixSessionError::FairnessBudget);
        }
        let mut ready = self.io.writable().await.map_err(io_error)?;
        let mut sent = 0;
        let mut sent_packets = Vec::new();
        while sent < fairness_budget {
            let Some(packet) = queue.front() else {
                return Ok(SendBurst {
                    sent: sent_packets,
                    queue_empty: true,
                    drained_to_would_block: false,
                });
            };
            match ready.try_io(|inner| send_one(inner.get_ref(), packet, capacity.bytes)) {
                Ok(Ok(bytes)) => {
                    if bytes != packet.payload.len() {
                        return Err(UnixSessionError::PacketNotAtomic);
                    }
                    let Some(packet) = queue.pop_front() else {
                        return Err(UnixSessionError::Io { errno: None });
                    };
                    sent_packets.push(SentPacket {
                        _files: packet.files,
                        credits: packet.credits,
                    });
                    sent += 1;
                }
                Ok(Err(error)) => return Err(classify_io(error)),
                Err(_) => {
                    return Ok(SendBurst {
                        sent: sent_packets,
                        queue_empty: false,
                        drained_to_would_block: true,
                    });
                }
            }
        }
        Ok(SendBurst {
            sent: sent_packets,
            queue_empty: queue.is_empty(),
            drained_to_would_block: false,
        })
    }
}

pub fn prearmed_seqpacket_pair() -> Result<(OwnedFd, OwnedFd), UnixSessionError> {
    let (left, right) = socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
        None,
    )
    .map_err(io_error)?;
    set_socket_passcred(&left, true).map_err(io_error)?;
    set_socket_passcred(&right, true).map_err(io_error)?;
    verify_parent_prearmed(&left)?;
    verify_parent_prearmed(&right)?;
    Ok((left, right))
}

/// Duplicate one descriptor to the fixed inherited fd used by subprocess
/// tests. The returned owner keeps the descriptor open until the child has
/// been spawned.
#[cfg(feature = "test-support")]
pub fn duplicate_to_inherited_fd(
    source: impl AsFd,
    target: RawFd,
) -> Result<OwnedFd, UnixSessionError> {
    if target < 0 || source.as_fd().as_raw_fd() == target {
        return Err(UnixSessionError::InvalidSocket);
    }
    let _ = nix::unistd::close(target);
    let mut fillers = Vec::new();
    loop {
        let file = std::fs::File::open("/dev/null").map_err(io_error)?;
        if file.as_raw_fd() > target {
            return Err(UnixSessionError::InvalidSocket);
        }
        if file.as_raw_fd() == target {
            let duplicated: OwnedFd = file.into();
            nix::unistd::dup2(source.as_fd().as_raw_fd(), duplicated.as_raw_fd()).map_err(|error| {
                UnixSessionError::Io {
                    errno: Some(error as i32),
                }
            })?;
            rustix::io::fcntl_setfd(&duplicated, FdFlags::empty()).map_err(io_error)?;
            return Ok(duplicated);
        }
        fillers.push(file);
    }
}

fn verify_parent_prearmed(fd: impl AsFd) -> Result<(), UnixSessionError> {
    match get_socket_passcred(fd).map_err(io_error)? {
        true => Ok(()),
        false => Err(UnixSessionError::PasscredNotPrearmed),
    }
}

fn duplicate_inherited_fd(raw_fd: RawFd) -> Result<OwnedFd, UnixSessionError> {
    if raw_fd < 0 {
        return Err(UnixSessionError::InvalidSocket);
    }

    uapi::fcntl_dupfd_cloexec(raw_fd, 3)
        .map(Into::into)
        .map_err(|error| io_error(io::Error::from(error)))
}

fn nix_io_error(error: nix::errno::Errno) -> UnixSessionError {
    io_error(io::Error::from_raw_os_error(error as i32))
}

fn recv_one(
    fd: &OwnedFd,
    payload_capacity: usize,
    control_capacity: usize,
) -> io::Result<(Vec<u8>, Vec<ReceivedControl>, bool)> {
    let mut payload = vec![0_u8; payload_capacity];
    let mut control_bytes = vec![0_u8; control_capacity];
    let mut control = RecvAncillaryBuffer::new(&mut control_bytes);
    let result = {
        let mut iov = [IoSliceMut::new(&mut payload)];
        loop {
            match recvmsg(
                fd,
                &mut iov,
                &mut control,
                RecvFlags::DONTWAIT | RecvFlags::CMSG_CLOEXEC,
            ) {
                Err(rustix::io::Errno::INTR) => continue,
                result => break result.map_err(errno_to_io)?,
            }
        }
    };

    let mut controls = Vec::new();
    let mut unknown_control = false;
    let mut received_files = 0_usize;
    let mut received_credentials = 0_usize;
    for message in control.drain() {
        match message {
            RecvAncillaryMessage::ScmRights(files) => {
                for file in files {
                    received_files += 1;
                    controls.push(ReceivedControl::File(file));
                }
            }
            RecvAncillaryMessage::ScmCredentials(credentials) => {
                received_credentials += 1;
                controls.push(ReceivedControl::Credentials(PeerCredentials::from_ucred(
                    credentials,
                )));
            }
            _ => unknown_control = true,
        }
    }
    drop(control);
    match scan_control_layout(&control_bytes) {
        Ok(layout)
            if layout.files == received_files && layout.credentials == received_credentials => {}
        Ok(_) | Err(()) => unknown_control = true,
    }

    if result.bytes == 0 {
        drop(controls);
        return Err(semantic_io(UnixSessionError::Closed));
    }
    if result.flags.contains(RecvFlags::TRUNC) {
        drop(controls);
        return Err(semantic_io(UnixSessionError::MessageTruncated));
    }
    const CMSG_TRUNC: RecvFlags = RecvFlags::from_bits_retain(0x08);
    if result.flags.contains(CMSG_TRUNC) {
        drop(controls);
        return Err(semantic_io(UnixSessionError::ControlTruncated));
    }
    if unknown_control {
        drop(controls);
        return Err(semantic_io(UnixSessionError::UnknownControl));
    }
    payload.truncate(result.bytes);
    Ok((payload, controls, unknown_control))
}

fn send_one(fd: &OwnedFd, packet: &OutboundPacket, control_capacity: usize) -> io::Result<usize> {
    let borrowed: Vec<BorrowedFd<'_>> = packet.files.iter().map(|file| file.as_fd()).collect();
    let mut control_bytes = vec![0_u8; control_capacity];
    let mut control = SendAncillaryBuffer::new(&mut control_bytes);
    if !borrowed.is_empty() && !control.push(SendAncillaryMessage::ScmRights(&borrowed)) {
        return Err(semantic_io(UnixSessionError::AncillaryCapacity));
    }
    if let Some(credentials) = packet.credentials
        && !control.push(SendAncillaryMessage::ScmCredentials(credentials.as_ucred()))
    {
        return Err(semantic_io(UnixSessionError::AncillaryCapacity));
    }
    loop {
        match sendmsg(
            fd,
            &[IoSlice::new(&packet.payload)],
            &mut control,
            SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
        ) {
            Err(rustix::io::Errno::INTR) => continue,
            result => break result.map_err(errno_to_io),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamRead {
    pub bytes: usize,
    pub eof: bool,
    pub drained_to_would_block: bool,
}

pub struct StreamSocket {
    io: AsyncFd<OwnedFd>,
}

impl fmt::Debug for StreamSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StreamSocket(REDACTED)")
    }
}

impl StreamSocket {
    pub fn from_owned(fd: OwnedFd) -> Result<Self, UnixSessionError> {
        validate_socket(&fd, SocketType::STREAM)?;
        Ok(Self {
            io: AsyncFd::new(fd).map_err(io_error)?,
        })
    }

    pub fn acceptor_peer_credentials(&self) -> Result<PeerCredentials, UnixSessionError> {
        get_socket_peercred(self.io.get_ref())
            .map(PeerCredentials::from_ucred)
            .map_err(io_error)
    }

    pub fn close(&self) -> Result<(), UnixSessionError> {
        shutdown(self.io.get_ref(), Shutdown::ReadWrite).map_err(io_error)
    }

    pub async fn read_available(
        &self,
        output: &mut Vec<u8>,
        chunk_bytes: usize,
        fairness_budget: usize,
    ) -> Result<StreamRead, UnixSessionError> {
        if chunk_bytes == 0 || fairness_budget == 0 {
            return Err(UnixSessionError::FairnessBudget);
        }
        let initial = output.len();
        let mut ready = self.io.readable().await.map_err(io_error)?;
        for _ in 0..fairness_budget {
            let mut chunk = vec![0_u8; chunk_bytes];
            match ready.try_io(|inner| {
                loop {
                    match read(inner.get_ref(), &mut chunk) {
                        Err(rustix::io::Errno::INTR) => continue,
                        result => break result.map_err(errno_to_io),
                    }
                }
            }) {
                Ok(Ok(0)) => {
                    return Ok(StreamRead {
                        bytes: output.len() - initial,
                        eof: true,
                        drained_to_would_block: false,
                    });
                }
                Ok(Ok(count)) => output.extend_from_slice(&chunk[..count]),
                Ok(Err(error)) => return Err(classify_io(error)),
                Err(_) => {
                    return Ok(StreamRead {
                        bytes: output.len() - initial,
                        eof: false,
                        drained_to_would_block: true,
                    });
                }
            }
        }
        Ok(StreamRead {
            bytes: output.len() - initial,
            eof: false,
            drained_to_would_block: false,
        })
    }

    pub async fn write_all(&self, bytes: &[u8]) -> Result<(), UnixSessionError> {
        let mut offset = 0;
        self.write_all_from(bytes, &mut offset).await
    }

    pub async fn write_all_from(
        &self,
        bytes: &[u8],
        offset: &mut usize,
    ) -> Result<(), UnixSessionError> {
        while *offset < bytes.len() {
            let mut ready = self.io.writable().await.map_err(io_error)?;
            loop {
                match ready.try_io(|inner| {
                    loop {
                        match send(
                            inner.get_ref(),
                            &bytes[*offset..],
                            SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
                        ) {
                            Err(rustix::io::Errno::INTR) => continue,
                            result => break result.map_err(errno_to_io),
                        }
                    }
                }) {
                    Ok(Ok(0)) => return Err(UnixSessionError::Closed),
                    Ok(Ok(count)) => {
                        *offset += count;
                        if *offset == bytes.len() {
                            return Ok(());
                        }
                    }
                    Ok(Err(error)) => return Err(io_error(error)),
                    Err(_) => break,
                }
            }
        }
        Ok(())
    }
}

fn validate_socket(fd: impl AsFd, expected: SocketType) -> Result<(), UnixSessionError> {
    let fd = fd.as_fd();
    if get_socket_domain(fd).map_err(io_error)? != AddressFamily::UNIX
        || get_socket_type(fd).map_err(io_error)? != expected
    {
        return Err(UnixSessionError::InvalidSocket);
    }
    if !fcntl_getfl(fd)
        .map_err(io_error)?
        .contains(OFlags::NONBLOCK)
    {
        return Err(UnixSessionError::BlockingSocket);
    }
    if !fcntl_getfd(fd)
        .map_err(io_error)?
        .contains(FdFlags::CLOEXEC)
    {
        return Err(UnixSessionError::MissingCloexec);
    }
    Ok(())
}

fn errno_to_io(error: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}

fn semantic_io(error: UnixSessionError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn classify_io(error: io::Error) -> UnixSessionError {
    if let Some(semantic) = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<UnixSessionError>())
        .copied()
    {
        semantic
    } else if matches!(
        error.raw_os_error(),
        Some(libc::EPIPE) | Some(libc::ECONNRESET) | Some(libc::ENOTCONN)
    ) {
        UnixSessionError::Closed
    } else {
        UnixSessionError::Io {
            errno: error.raw_os_error(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ControlLayout {
    files: usize,
    credentials: usize,
}

fn scan_control_layout(bytes: &[u8]) -> Result<ControlLayout, ()> {
    const SOL_SOCKET: i32 = 1;
    const SCM_RIGHTS: i32 = 1;
    const SCM_CREDENTIALS: i32 = 2;
    const RAW_FD_BYTES: usize = size_of::<i32>();
    const UCRED_BYTES: usize = size_of::<i32>() + size_of::<u32>() + size_of::<u32>();

    let word = size_of::<usize>();
    let header = word.checked_add(2 * size_of::<i32>()).ok_or(())?;
    let mut offset = 0_usize;
    let mut layout = ControlLayout {
        files: 0,
        credentials: 0,
    };
    while offset.checked_add(header).ok_or(())? <= bytes.len() {
        let length = read_native_usize(&bytes[offset..offset + word])?;
        if length == 0 {
            if bytes[offset..].iter().any(|byte| *byte != 0) {
                return Err(());
            }
            return Ok(layout);
        }
        if length < header || offset.checked_add(length).ok_or(())? > bytes.len() {
            return Err(());
        }
        let level_offset = offset + word;
        let kind_offset = level_offset + size_of::<i32>();
        let level = i32::from_ne_bytes(
            bytes[level_offset..kind_offset]
                .try_into()
                .map_err(|_| ())?,
        );
        let kind = i32::from_ne_bytes(
            bytes[kind_offset..kind_offset + size_of::<i32>()]
                .try_into()
                .map_err(|_| ())?,
        );
        let payload = length - header;
        match (level, kind) {
            (SOL_SOCKET, SCM_RIGHTS) if payload != 0 && payload % RAW_FD_BYTES == 0 => {
                layout.files = layout.files.checked_add(payload / RAW_FD_BYTES).ok_or(())?;
            }
            (SOL_SOCKET, SCM_CREDENTIALS) if payload == UCRED_BYTES => {
                layout.credentials = layout.credentials.checked_add(1).ok_or(())?;
            }
            _ => return Err(()),
        }
        offset = offset
            .checked_add(align_up(length, word).ok_or(())?)
            .ok_or(())?;
    }
    if bytes[offset..].iter().all(|byte| *byte == 0) {
        Ok(layout)
    } else {
        Err(())
    }
}

fn read_native_usize(bytes: &[u8]) -> Result<usize, ()> {
    match size_of::<usize>() {
        8 => Ok(u64::from_ne_bytes(bytes.try_into().map_err(|_| ())?) as usize),
        4 => Ok(u32::from_ne_bytes(bytes.try_into().map_err(|_| ())?) as usize),
        _ => Err(()),
    }
}

fn align_up(value: usize, alignment: usize) -> Option<usize> {
    value
        .checked_add(alignment.checked_sub(1)?)
        .map(|sum| sum & !(alignment - 1))
}

#[cfg(test)]
mod tests {
    use super::{ControlLayout, SeqpacketSocket, scan_control_layout};
    use crate::prearmed_seqpacket_pair;
    use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};
    use std::{mem::size_of, os::fd::IntoRawFd};

    #[tokio::test(flavor = "current_thread")]
    async fn inherited_fd_is_rearmed_before_session_use() {
        let (fd, _peer) = prearmed_seqpacket_pair().unwrap();
        fcntl_setfd(&fd, FdFlags::empty()).unwrap();
        let socket = SeqpacketSocket::from_inherited_fd(fd.into_raw_fd()).unwrap();
        assert!(
            fcntl_getfd(socket.io.get_ref())
                .unwrap()
                .contains(FdFlags::CLOEXEC)
        );
    }

    #[test]
    fn raw_control_scanner_rejects_unknown_and_partial_headers() {
        let word = size_of::<usize>();
        let header = word + 2 * size_of::<i32>();
        let mut unknown = vec![0_u8; header + 8];
        unknown[..word].copy_from_slice(&(header + 4).to_ne_bytes()[..word]);
        unknown[word..word + 4].copy_from_slice(&1_i32.to_ne_bytes());
        unknown[word + 4..word + 8].copy_from_slice(&99_i32.to_ne_bytes());
        assert_eq!(scan_control_layout(&unknown), Err(()));

        let mut partial = vec![0_u8; header];
        partial[..word].copy_from_slice(&(header + 1).to_ne_bytes()[..word]);
        assert_eq!(scan_control_layout(&partial), Err(()));
    }

    #[test]
    fn raw_control_scanner_accepts_exact_rights_shape() {
        let word = size_of::<usize>();
        let header = word + 2 * size_of::<i32>();
        let length = header + 2 * size_of::<i32>();
        let aligned = (length + word - 1) & !(word - 1);
        let mut rights = vec![0_u8; aligned];
        rights[..word].copy_from_slice(&length.to_ne_bytes()[..word]);
        rights[word..word + 4].copy_from_slice(&1_i32.to_ne_bytes());
        rights[word + 4..word + 8].copy_from_slice(&1_i32.to_ne_bytes());
        assert_eq!(
            scan_control_layout(&rights),
            Ok(ControlLayout {
                files: 2,
                credentials: 0,
            })
        );
    }
}
