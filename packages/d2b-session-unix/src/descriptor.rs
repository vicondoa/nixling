use crate::{
    credit::{CreditBundle, CreditScope, CreditScopeSet},
    error::{UnixSessionError, io_error},
    pidfd::{PidfdEvidence, PidfdIdentityVerifier, verify_pidfd},
};
use d2b_contracts_zone_session::v3::component_session::{
    AttachmentAccess, AttachmentKind, AttachmentPacket, AttachmentPolicy, KernelObjectType,
};
use d2b_session::OwnedAttachment;
use rustix::{
    fd::{AsFd, OwnedFd},
    fs::{FileType, OFlags, fcntl_get_seals, fcntl_getfl, fstat},
    io::{FdFlags, fcntl_getfd},
    net::{
        AddressFamily, SocketType, UCred,
        sockopt::{get_socket_domain, get_socket_type},
    },
    process::{Gid, Pid, Uid},
};
use std::{fmt, sync::Arc};

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials(UCred);

impl PeerCredentials {
    pub(crate) fn from_ucred(credentials: UCred) -> Self {
        Self(credentials)
    }

    pub fn pid(self) -> Pid {
        self.0.pid
    }

    pub fn uid(self) -> Uid {
        self.0.uid
    }

    pub fn gid(self) -> Gid {
        self.0.gid
    }

    pub(crate) fn as_ucred(self) -> UCred {
        self.0
    }
}

impl fmt::Debug for PeerCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PeerCredentials(REDACTED)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FirstPacketCredentials(PeerCredentials);

impl FirstPacketCredentials {
    pub fn pid(self) -> Pid {
        self.0.pid()
    }
}

impl fmt::Debug for FirstPacketCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FirstPacketCredentials(REDACTED)")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ObjectIdentity {
    device: u64,
    inode: u64,
    file_type: FileType,
    object_type: KernelObjectType,
    access: AttachmentAccess,
    special_device: u64,
    socket: Option<(AddressFamily, SocketType)>,
    seals: Option<u32>,
}

impl fmt::Debug for ObjectIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ObjectIdentity(REDACTED)")
    }
}

impl ObjectIdentity {
    pub fn from_trusted(
        fd: impl AsFd,
        object_type: KernelObjectType,
        access: AttachmentAccess,
    ) -> Result<Self, UnixSessionError> {
        inspect_identity(fd, object_type, access, false)
    }

    pub(crate) fn same_kernel_object(&self, other: &Self) -> bool {
        self.device == other.device
            && self.inode == other.inode
            && self.file_type == other.file_type
            && self.special_device == other.special_device
            && self.socket == other.socket
    }
}

#[derive(Clone)]
pub struct PidfdIdentityPolicy {
    expected: ObjectIdentity,
    evidence: PidfdEvidence,
    verifier: Arc<dyn PidfdIdentityVerifier>,
}

impl fmt::Debug for PidfdIdentityPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PidfdIdentityPolicy(REDACTED)")
    }
}

impl PidfdIdentityPolicy {
    pub fn new(
        trusted_pidfd: impl AsFd,
        access: AttachmentAccess,
        evidence: PidfdEvidence,
        verifier: Arc<dyn PidfdIdentityVerifier>,
    ) -> Result<Self, UnixSessionError> {
        verify_pidfd(trusted_pidfd.as_fd(), &evidence, verifier.as_ref())?;
        let expected = inspect_identity(trusted_pidfd, KernelObjectType::Pidfd, access, true)?;
        Ok(Self {
            expected,
            evidence,
            verifier,
        })
    }

    fn validate(
        &self,
        pidfd: impl AsFd,
        access: AttachmentAccess,
    ) -> Result<ObjectIdentity, UnixSessionError> {
        verify_pidfd(pidfd.as_fd(), &self.evidence, self.verifier.as_ref())?;
        let actual = inspect_identity(pidfd, KernelObjectType::Pidfd, access, true)?;
        if actual == self.expected {
            Ok(actual)
        } else {
            Err(UnixSessionError::PidfdIdentityMismatch)
        }
    }
}

#[derive(Clone)]
pub enum DescriptorPolicy {
    File(ObjectIdentity),
    /// The transport has authenticated the descriptor envelope and checked
    /// its declared kernel type/access. The Provider performs the final
    /// operation-specific safety admission.
    ProviderValidatedFile,
    SealedReadOnlyMemfd,
    Pidfd(PidfdIdentityPolicy),
    Credentials(PeerCredentials),
}

impl fmt::Debug for DescriptorPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::File(_) => "DescriptorPolicy::File(REDACTED)",
            Self::ProviderValidatedFile => "DescriptorPolicy::ProviderValidatedFile",
            Self::SealedReadOnlyMemfd => "DescriptorPolicy::SealedReadOnlyMemfd",
            Self::Pidfd(_) => "DescriptorPolicy::Pidfd(REDACTED)",
            Self::Credentials(_) => "DescriptorPolicy::Credentials(REDACTED)",
        })
    }
}

pub enum AcceptedAttachment {
    File(OwnedFd),
    Credentials(PeerCredentials),
}

impl fmt::Debug for AcceptedAttachment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::File(_) => "AcceptedAttachment::File(REDACTED)",
            Self::Credentials(_) => "AcceptedAttachment::Credentials(REDACTED)",
        })
    }
}

pub struct VerifiedPacket {
    payload: Vec<u8>,
    attachments: Vec<AcceptedAttachment>,
    credits: CreditBundle,
}

impl fmt::Debug for VerifiedPacket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedPacket")
            .field("payload_bytes", &self.payload.len())
            .field("attachment_count", &self.attachments.len())
            .finish_non_exhaustive()
    }
}

impl VerifiedPacket {
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn attachments(&self) -> &[AcceptedAttachment] {
        &self.attachments
    }

    pub fn release_credit(&mut self, scope: CreditScope) {
        self.credits.release(scope);
    }

    pub fn into_parts(self) -> (Vec<u8>, Vec<AcceptedAttachment>, CreditBundle) {
        (self.payload, self.attachments, self.credits)
    }

    /// Convert attachments that have already passed ComponentSession
    /// descriptor binding into the Provider-facing verified representation.
    ///
    /// The transport credit reservation remains owned by the attachment
    /// payload and is released when the payload is consumed or dropped. The
    /// empty bundle is intentional: this conversion is only for the
    /// post-session dispatch path, not raw transport admission.
    pub fn from_bound_attachments(
        attachments: Vec<OwnedAttachment>,
    ) -> Result<Self, UnixSessionError> {
        let mut accepted = Vec::with_capacity(attachments.len());
        for attachment in attachments {
            let descriptor = attachment
                .descriptor()
                .ok_or(UnixSessionError::DescriptorMismatch)?;
            if descriptor.kind != AttachmentKind::FileDescriptor {
                return Err(UnixSessionError::DescriptorMismatch);
            }
            let payload = attachment
                .into_any()
                .ok_or(UnixSessionError::DescriptorMismatch)?
                .downcast::<crate::UnixAttachmentPayload>()
                .map_err(|_| UnixSessionError::DescriptorMismatch)?;
            accepted.push(AcceptedAttachment::File(payload.into_owned_file()));
        }
        Ok(Self {
            payload: Vec::new(),
            attachments: accepted,
            credits: CreditBundle::empty(),
        })
    }
}

pub(crate) enum ReceivedControl {
    File(OwnedFd),
    Credentials(PeerCredentials),
}

pub struct ReceivedPacket {
    pub(crate) payload: Vec<u8>,
    pub(crate) controls: Vec<ReceivedControl>,
    pub(crate) unknown_control: bool,
    pub(crate) first_on_socket: bool,
    pub(crate) credits: CreditBundle,
}

impl fmt::Debug for ReceivedPacket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReceivedPacket")
            .field("payload_bytes", &self.payload.len())
            .field("control_count", &self.controls.len())
            .finish_non_exhaustive()
    }
}

impl ReceivedPacket {
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Consume the packet payload in a zeroizing owner.
    pub fn into_payload_zeroizing(self) -> zeroize::Zeroizing<Vec<u8>> {
        zeroize::Zeroizing::new(self.payload)
    }

    pub fn control_count(&self) -> usize {
        self.controls.len()
    }

    /// Consume the first bootstrap packet that carries exactly one file
    /// descriptor and one SCM credential record.
    ///
    /// The caller must validate the bounded payload marker separately. Any
    /// missing, duplicate, or unexpected control is rejected before the
    /// descriptor can be used.
    pub fn into_single_file_and_credentials(
        self,
    ) -> Result<(OwnedFd, PeerCredentials), UnixSessionError> {
        if !self.first_on_socket {
            return Err(UnixSessionError::ControlMismatch);
        }
        if self.unknown_control {
            return Err(UnixSessionError::UnknownControl);
        }
        let mut file = None;
        let mut credentials = None;
        for control in self.controls {
            match control {
                ReceivedControl::File(fd) if file.is_none() => file = Some(fd),
                ReceivedControl::Credentials(value) if credentials.is_none() => {
                    credentials = Some(value);
                }
                ReceivedControl::File(_) | ReceivedControl::Credentials(_) => {
                    return Err(UnixSessionError::ControlMismatch);
                }
            }
        }
        match (file, credentials) {
            (Some(file), Some(credentials)) => Ok((file, credentials)),
            _ => Err(UnixSessionError::ControlMismatch),
        }
    }

    pub fn verify_first_packet_credentials(
        &self,
        expected: PeerCredentials,
    ) -> Result<FirstPacketCredentials, UnixSessionError> {
        if !self.first_on_socket {
            return Err(UnixSessionError::CredentialMismatch);
        }
        match self.controls.as_slice() {
            [ReceivedControl::Credentials(actual)] if *actual == expected => {
                Ok(FirstPacketCredentials(*actual))
            }
            [ReceivedControl::Credentials(_)] => Err(UnixSessionError::CredentialMismatch),
            _ => Err(UnixSessionError::ControlMismatch),
        }
    }

    pub fn verify(
        self,
        packet: &AttachmentPacket,
        attachment_policy: AttachmentPolicy,
        policies: &[DescriptorPolicy],
        credit_scopes: &CreditScopeSet,
    ) -> Result<VerifiedPacket, UnixSessionError> {
        packet
            .validate(
                attachment_policy,
                self.controls.len(),
                false,
                false,
                self.unknown_control,
            )
            .map_err(|_| {
                if self.unknown_control {
                    UnixSessionError::UnknownControl
                } else {
                    UnixSessionError::ControlMismatch
                }
            })?;
        if policies.len() != self.controls.len() {
            return Err(UnixSessionError::ControlMismatch);
        }

        let mut credits = self.credits;
        credits
            .acquire_dispatch(credit_scopes, self.controls.len())
            .map_err(|_| UnixSessionError::CreditExceeded)?;
        let mut accepted = Vec::with_capacity(self.controls.len());
        let mut identities: Vec<(ObjectIdentity, bool)> = Vec::new();

        for ((control, descriptor), policy) in self
            .controls
            .into_iter()
            .zip(packet.descriptors.iter())
            .zip(policies)
        {
            match (control, descriptor.kind, policy) {
                (
                    ReceivedControl::Credentials(actual),
                    AttachmentKind::Credentials,
                    DescriptorPolicy::Credentials(expected),
                ) if actual == *expected => {
                    accepted.push(AcceptedAttachment::Credentials(actual));
                }
                (
                    ReceivedControl::File(fd),
                    AttachmentKind::FileDescriptor,
                    DescriptorPolicy::ProviderValidatedFile,
                ) => {
                    let actual =
                        inspect_identity(&fd, descriptor.object_type, descriptor.access, false)?;
                    if identities.iter().any(|(prior, prior_allows)| {
                        prior.same_kernel_object(&actual)
                            && (!descriptor.duplicate_object_allowed || !prior_allows)
                    }) {
                        return Err(UnixSessionError::DuplicateObject);
                    }
                    identities.push((actual, descriptor.duplicate_object_allowed));
                    accepted.push(AcceptedAttachment::File(fd));
                }
                (
                    ReceivedControl::File(fd),
                    AttachmentKind::FileDescriptor,
                    DescriptorPolicy::File(expected),
                ) if descriptor.object_type != KernelObjectType::Pidfd => {
                    let actual =
                        inspect_identity(&fd, descriptor.object_type, descriptor.access, false)?;
                    if actual != *expected {
                        return Err(UnixSessionError::DescriptorMismatch);
                    }
                    if identities.iter().any(|(prior, prior_allows)| {
                        prior.same_kernel_object(&actual)
                            && (!descriptor.duplicate_object_allowed || !prior_allows)
                    }) {
                        return Err(UnixSessionError::DuplicateObject);
                    }
                    identities.push((actual, descriptor.duplicate_object_allowed));
                    accepted.push(AcceptedAttachment::File(fd));
                }
                (
                    ReceivedControl::File(fd),
                    AttachmentKind::FileDescriptor,
                    DescriptorPolicy::SealedReadOnlyMemfd,
                ) if descriptor.object_type == KernelObjectType::Memfd
                    && descriptor.access == AttachmentAccess::ReadOnly =>
                {
                    let actual = inspect_identity(
                        &fd,
                        KernelObjectType::Memfd,
                        AttachmentAccess::ReadOnly,
                        false,
                    )?;
                    require_fully_sealed(&actual)?;
                    if identities.iter().any(|(prior, prior_allows)| {
                        prior.same_kernel_object(&actual)
                            && (!descriptor.duplicate_object_allowed || !prior_allows)
                    }) {
                        return Err(UnixSessionError::DuplicateObject);
                    }
                    identities.push((actual, descriptor.duplicate_object_allowed));
                    accepted.push(AcceptedAttachment::File(fd));
                }
                (
                    ReceivedControl::File(fd),
                    AttachmentKind::FileDescriptor,
                    DescriptorPolicy::Pidfd(policy),
                ) if descriptor.object_type == KernelObjectType::Pidfd => {
                    let actual = policy.validate(&fd, descriptor.access)?;
                    if identities.iter().any(|(prior, prior_allows)| {
                        prior.same_kernel_object(&actual)
                            && (!descriptor.duplicate_object_allowed || !prior_allows)
                    }) {
                        return Err(UnixSessionError::DuplicateObject);
                    }
                    identities.push((actual, descriptor.duplicate_object_allowed));
                    accepted.push(AcceptedAttachment::File(fd));
                }
                (ReceivedControl::Credentials(_), _, _) | (ReceivedControl::File(_), _, _) => {
                    return Err(UnixSessionError::DescriptorMismatch);
                }
            }
        }

        Ok(VerifiedPacket {
            payload: self.payload,
            attachments: accepted,
            credits,
        })
    }
}

fn inspect_identity(
    fd: impl AsFd,
    object_type: KernelObjectType,
    access: AttachmentAccess,
    pidfd_verified: bool,
) -> Result<ObjectIdentity, UnixSessionError> {
    let fd = fd.as_fd();
    if !fcntl_getfd(fd)
        .map_err(io_error)?
        .contains(FdFlags::CLOEXEC)
    {
        return Err(UnixSessionError::MissingCloexec);
    }
    let stat = fstat(fd).map_err(io_error)?;
    let file_type = FileType::from_raw_mode(stat.st_mode);
    let flags = fcntl_getfl(fd).map_err(io_error)?;
    if access_mode(flags) != access {
        return Err(UnixSessionError::DescriptorMismatch);
    }

    let socket = match object_type {
        KernelObjectType::UnixStreamSocket | KernelObjectType::WaylandSocket => {
            require_type(file_type, FileType::Socket)?;
            let domain = get_socket_domain(fd).map_err(io_error)?;
            let kind = get_socket_type(fd).map_err(io_error)?;
            if domain != AddressFamily::UNIX || kind != SocketType::STREAM {
                return Err(UnixSessionError::DescriptorMismatch);
            }
            Some((domain, kind))
        }
        KernelObjectType::UnixSeqpacketSocket => {
            require_type(file_type, FileType::Socket)?;
            let domain = get_socket_domain(fd).map_err(io_error)?;
            let kind = get_socket_type(fd).map_err(io_error)?;
            if domain != AddressFamily::UNIX || kind != SocketType::SEQPACKET {
                return Err(UnixSessionError::DescriptorMismatch);
            }
            Some((domain, kind))
        }
        KernelObjectType::PipeRead | KernelObjectType::PipeWrite => {
            require_type(file_type, FileType::Fifo)?;
            None
        }
        KernelObjectType::Memfd => {
            require_type(file_type, FileType::RegularFile)?;
            None
        }
        KernelObjectType::RegularFile => {
            require_type(file_type, FileType::RegularFile)?;
            None
        }
        KernelObjectType::Directory => {
            require_type(file_type, FileType::Directory)?;
            None
        }
        KernelObjectType::Device
        | KernelObjectType::Tap
        | KernelObjectType::Kvm
        | KernelObjectType::Vhost
        | KernelObjectType::Fuse
        | KernelObjectType::Hidraw
        | KernelObjectType::PtyMaster
        | KernelObjectType::PtySlave => {
            require_type(file_type, FileType::CharacterDevice)?;
            None
        }
        KernelObjectType::Pidfd => {
            if !pidfd_verified {
                return Err(UnixSessionError::PidfdEvidenceUnavailable);
            }
            None
        }

        KernelObjectType::ProcessCredentials => {
            return Err(UnixSessionError::DescriptorMismatch);
        }
    };

    let seals = if object_type == KernelObjectType::Memfd {
        Some(fcntl_get_seals(fd).map_err(io_error)?.bits())
    } else {
        None
    };

    Ok(ObjectIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
        file_type,
        object_type,
        access,
        special_device: stat.st_rdev,
        socket,
        seals,
    })
}

pub(crate) fn validate_owned_file(
    fd: impl AsFd,
    descriptor: &d2b_contracts_zone_session::v3::component_session::AttachmentDescriptor,
    policy: &DescriptorPolicy,
) -> Result<(), UnixSessionError> {
    validate_owned_file_identity(fd, descriptor, policy).map(|_| ())
}

pub(crate) fn validate_owned_file_identity(
    fd: impl AsFd,
    descriptor: &d2b_contracts_zone_session::v3::component_session::AttachmentDescriptor,
    policy: &DescriptorPolicy,
) -> Result<ObjectIdentity, UnixSessionError> {
    if descriptor.kind != AttachmentKind::FileDescriptor {
        return Err(UnixSessionError::DescriptorMismatch);
    }
    match policy {
        DescriptorPolicy::File(expected) if descriptor.object_type != KernelObjectType::Pidfd => {
            let actual = inspect_identity(fd, descriptor.object_type, descriptor.access, false)?;
            if actual == *expected {
                Ok(actual)
            } else {
                Err(UnixSessionError::DescriptorMismatch)
            }
        }
        DescriptorPolicy::Pidfd(policy) if descriptor.object_type == KernelObjectType::Pidfd => {
            policy.validate(fd, descriptor.access)
        }
        DescriptorPolicy::SealedReadOnlyMemfd
            if descriptor.object_type == KernelObjectType::Memfd
                && descriptor.access == AttachmentAccess::ReadOnly =>
        {
            let actual = inspect_identity(
                fd,
                KernelObjectType::Memfd,
                AttachmentAccess::ReadOnly,
                false,
            )?;
            require_fully_sealed(&actual)?;
            Ok(actual)
        }
        DescriptorPolicy::ProviderValidatedFile => {
            if descriptor.kind != AttachmentKind::FileDescriptor {
                return Err(UnixSessionError::DescriptorMismatch);
            }
            inspect_identity(fd, descriptor.object_type, descriptor.access, false)
        }
        DescriptorPolicy::File(_)
        | DescriptorPolicy::SealedReadOnlyMemfd
        | DescriptorPolicy::Pidfd(_)
        | DescriptorPolicy::Credentials(_) => Err(UnixSessionError::DescriptorMismatch),
    }
}

fn require_fully_sealed(identity: &ObjectIdentity) -> Result<(), UnixSessionError> {
    let required =
        (libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL) as u32;
    if identity.object_type == KernelObjectType::Memfd
        && identity.access == AttachmentAccess::ReadOnly
        && identity
            .seals
            .is_some_and(|seals| seals & required == required)
    {
        Ok(())
    } else {
        Err(UnixSessionError::DescriptorMismatch)
    }
}

fn require_type(actual: FileType, expected: FileType) -> Result<(), UnixSessionError> {
    if actual == expected {
        Ok(())
    } else {
        Err(UnixSessionError::DescriptorMismatch)
    }
}

fn access_mode(flags: OFlags) -> AttachmentAccess {
    match flags & OFlags::ACCMODE {
        OFlags::WRONLY => AttachmentAccess::WriteOnly,
        OFlags::RDWR => AttachmentAccess::ReadWrite,
        _ => AttachmentAccess::ReadOnly,
    }
}

#[cfg(test)]
mod tests {
    use super::{PeerCredentials, ReceivedControl, ReceivedPacket};
    use crate::credit::CreditBundle;
    use rustix::{
        net::UCred,
        process::{getgid, getpid, getuid},
    };

    #[test]
    fn first_packet_credentials_require_exact_pid_uid_and_gid() {
        let expected = PeerCredentials::from_ucred(UCred {
            pid: getpid(),
            uid: getuid(),
            gid: getgid(),
        });
        let actual = PeerCredentials::from_ucred(UCred {
            pid: rustix::process::Pid::from_raw(getpid().as_raw_nonzero().get().saturating_add(1))
                .unwrap(),
            uid: getuid(),
            gid: getgid(),
        });
        let packet = ReceivedPacket {
            payload: b"preface".to_vec(),
            controls: vec![ReceivedControl::Credentials(actual)],
            unknown_control: false,
            first_on_socket: true,
            credits: CreditBundle::empty(),
        };

        assert_eq!(
            packet.verify_first_packet_credentials(expected),
            Err(crate::UnixSessionError::CredentialMismatch)
        );
    }
}
