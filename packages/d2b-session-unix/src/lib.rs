//! Audited Unix transport substrate for ComponentSession.
//!
//! The default feature set exercises both Linux host sockets and native vsock.

#[cfg(all(feature = "host-socket", not(target_os = "linux")))]
compile_error!("the host-socket feature requires Linux");
#[cfg(all(feature = "native-vsock", not(target_os = "linux")))]
compile_error!("the native-vsock feature requires Linux");

#[cfg(feature = "host-socket")]
mod adapter;
#[cfg(feature = "host-socket")]
mod credit;
#[cfg(feature = "host-socket")]
mod descriptor;
#[cfg(feature = "host-socket")]
mod error;
#[cfg(feature = "host-socket")]
mod pidfd;
#[cfg(feature = "host-socket")]
mod socket;
#[cfg(feature = "host-socket")]
mod subject;
#[cfg(feature = "host-socket")]
mod systemd;
#[cfg(feature = "native-vsock")]
mod vsock;
#[cfg(feature = "host-socket")]
mod zone_admission;

/// Fixed bounded marker for the one-shot Provider controller bootstrap
/// handoff. The packet carries no caller-authored identity.
#[cfg(feature = "host-socket")]
pub const CONTROLLER_BOOTSTRAP_PROTOCOL_MARKER: &[u8] = b"d2b-resource-v3-controller-bootstrap-v1";

/// Deadline for the one-shot Provider controller bootstrap handoff.
#[cfg(feature = "host-socket")]
pub const CONTROLLER_BOOTSTRAP_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(250);

/// Raw attachment policy for the one-shot controller bootstrap packet.
#[cfg(feature = "host-socket")]
pub fn controller_bootstrap_attachment_policy()
-> d2b_contracts_zone_session::v3::component_session::AttachmentPolicy {
    use d2b_contracts_zone_session::v3::component_session::{
        AttachmentPolicy, AttachmentPolicyKind,
    };
    AttachmentPolicy {
        kind: AttachmentPolicyKind::PacketAtomic,
        max_per_packet: 1,
        max_per_request: 1,
        max_per_operation: 1,
        max_per_session: 1,
        credentials_allowed: true,
    }
}

/// Bounded credit scopes shared by both sides of a Provider controller
/// bootstrap and ResourceV3 session.
#[cfg(feature = "host-socket")]
pub fn controller_credit_scopes() -> Result<CreditScopeSet, CreditError> {
    let pool = || CreditPool::new(64);
    Ok(CreditScopeSet::new(
        pool()?,
        pool()?,
        pool()?,
        pool()?,
        pool()?,
        pool()?,
    ))
}

/// Exact local inherited-socket ResourceV3 ComponentSession policy.
#[cfg(feature = "host-socket")]
pub fn inherited_resource_v3_endpoint_policy(
    initiator_role: d2b_contracts_zone_session::v3::component_session::EndpointRole,
    responder_role: d2b_contracts_zone_session::v3::component_session::EndpointRole,
) -> d2b_contracts_zone_session::v3::component_session::EndpointPolicy {
    use d2b_contracts_zone_session::v3::component_session::{
        AttachmentPolicy, AttachmentPolicyKind, EndpointPolicy, EndpointPurpose,
        IdentityEvidenceRequirement, LimitProfile, Locality, NoiseProfile, PurposeClass,
        ServicePackage, TransportBinding, TransportClass,
    };
    EndpointPolicy {
        purpose: EndpointPurpose::ResourceService,
        purpose_class: PurposeClass::Local,
        initiator_role,
        responder_role,
        service: ServicePackage::ResourceV3,
        schema_fingerprint: [0x11; 32],
        noise_profile: NoiseProfile::Nn25519ChaChaPolySha256,
        limits: LimitProfile::local_default(),
        transport_binding: TransportBinding {
            transport: TransportClass::InheritedSocketpair,
            locality: Locality::HostLocal,
            channel_binding: [0x22; 32],
            identity_evidence: IdentityEvidenceRequirement::DirectionalUnix,
        },
        reconnect_generation: 1,
        attachment_policy: AttachmentPolicy {
            kind: AttachmentPolicyKind::PacketAtomic,
            max_per_packet: 1,
            max_per_request: 1,
            max_per_operation: 1,
            max_per_session: 1,
            credentials_allowed: false,
        },
    }
}

/// Exact local ResourceV3 ComponentSession policy used by an external
/// Provider controller and its daemon responder.
#[cfg(feature = "host-socket")]
pub fn controller_resource_endpoint_policy()
-> d2b_contracts_zone_session::v3::component_session::EndpointPolicy {
    use d2b_contracts_zone_session::v3::component_session::EndpointRole;
    inherited_resource_v3_endpoint_policy(EndpointRole::Provider, EndpointRole::ZoneController)
}

/// Exact local ComponentSession policy used by a typed Credential Provider
/// service. Sensitive token delivery remains a separate Noise_KK session
/// owned by the Provider; this control session carries only bounded metadata.
#[cfg(feature = "host-socket")]
pub fn credential_provider_endpoint_policy()
-> d2b_contracts_zone_session::v3::component_session::EndpointPolicy {
    use d2b_contracts_zone_session::v3::component_session::{
        AttachmentPolicy, AttachmentPolicyKind, EndpointPolicy, EndpointPurpose, EndpointRole,
        IdentityEvidenceRequirement, LimitProfile, Locality, NoiseProfile, PurposeClass,
        ServicePackage, TransportBinding, TransportClass,
    };
    EndpointPolicy {
        purpose: EndpointPurpose::ProviderControl,
        purpose_class: PurposeClass::Local,
        initiator_role: EndpointRole::Provider,
        responder_role: EndpointRole::ZoneController,
        service: ServicePackage::CredentialV3,
        schema_fingerprint: [0x33; 32],
        noise_profile: NoiseProfile::Nn25519ChaChaPolySha256,
        limits: LimitProfile::local_default(),
        transport_binding: TransportBinding {
            transport: TransportClass::InheritedSocketpair,
            locality: Locality::HostLocal,
            channel_binding: [0x34; 32],
            identity_evidence: IdentityEvidenceRequirement::DirectionalUnix,
        },
        reconnect_generation: 1,
        attachment_policy: AttachmentPolicy {
            kind: AttachmentPolicyKind::PacketAtomic,
            max_per_packet: 1,
            max_per_request: 1,
            max_per_operation: 1,
            max_per_session: 1,
            credentials_allowed: false,
        },
    }
}

/// Exact enrolled ComponentSession policy for Guest-local sensitive
/// Credential delivery.
#[cfg(feature = "host-socket")]
pub fn credential_delivery_endpoint_policy(
    reconnect_generation: u64,
) -> d2b_contracts_zone_session::v3::component_session::EndpointPolicy {
    use d2b_contracts_zone_session::v3::component_session::{
        AttachmentPolicy, EndpointPolicy, EndpointPurpose, EndpointRole,
        IdentityEvidenceRequirement, LimitProfile, Locality, NoiseProfile, PurposeClass,
        ServicePackage, TransportBinding, TransportClass,
    };
    EndpointPolicy {
        purpose: EndpointPurpose::SensitiveCredential,
        purpose_class: PurposeClass::Enrolled,
        initiator_role: EndpointRole::Provider,
        responder_role: EndpointRole::GuestAgent,
        service: ServicePackage::CredentialV3,
        schema_fingerprint: [0x55; 32],
        noise_profile: NoiseProfile::Kk25519ChaChaPolySha256,
        limits: LimitProfile::local_default(),
        transport_binding: TransportBinding {
            transport: TransportClass::InheritedSocketpair,
            locality: Locality::GuestLocal,
            channel_binding: [0x56; 32],
            identity_evidence: IdentityEvidenceRequirement::EnrolledStaticKeys,
        },
        reconnect_generation,
        attachment_policy: AttachmentPolicy {
            kind: d2b_contracts_zone_session::v3::component_session::AttachmentPolicyKind::PacketAtomic,
            max_per_packet: 1,
            max_per_request: 1,
            max_per_operation: 1,
            max_per_session: 1,
            credentials_allowed: false,
        },
    }
}

#[cfg(feature = "host-socket")]
pub use adapter::{
    DescriptorPolicyResolver, NoopUnixTransportObserver, OwnedUnixAttachment, PathnamePeerVerifier,
    PeerIdentityPolicy, UnixAttachmentPayload, UnixSeqpacketTransport, UnixStreamTransport,
    UnixTransportEvent, UnixTransportFailure, UnixTransportObserver,
};
#[cfg(feature = "host-socket")]
pub use credit::{
    CreditBundle, CreditError, CreditPool, CreditScope, CreditScopeSet, ProcessCreditLimit,
};
#[cfg(feature = "host-socket")]
pub use descriptor::ReceivedPacket;
#[cfg(feature = "host-socket")]
pub use descriptor::{
    AcceptedAttachment, DescriptorPolicy, FirstPacketCredentials, ObjectIdentity, PeerCredentials,
    PidfdIdentityPolicy, VerifiedPacket,
};
#[cfg(feature = "host-socket")]
pub use error::UnixSessionError;
#[cfg(feature = "host-socket")]
pub use pidfd::{
    DigestEvidenceCallback, PidfdEvidence, PidfdIdentityVerifier, PidfdInfoSource,
    ProcPidfdIdentityVerifier, ProcSelfFdInfoSource, parse_pidfd_fdinfo,
};
#[cfg(feature = "host-socket")]
pub use socket::{
    AncillaryCapacity, OutboundPacket, PacketBurst, SendBurst, SentPacket, SeqpacketSocket,
    StreamRead, StreamSocket, prearmed_seqpacket_pair,
};
#[cfg(feature = "test-support")]
pub use socket::duplicate_to_inherited_fd;
#[cfg(feature = "host-socket")]
pub use subject::VerifiedUnixPeer;
#[cfg(feature = "host-socket")]
pub use systemd::{
    ActivatedSeqpacketListener, ActivatedSeqpacketListeners, SystemdActivationError,
};
#[cfg(feature = "native-vsock")]
pub use vsock::{
    FramedVsockTransport, NativeVsockListener, NativeVsockTransport,
    guest_control_transport_descriptor, is_guest_control_transport,
};
#[cfg(feature = "host-socket")]
pub use zone_admission::{BootstrapProvider, ZoneAdmissionError, ZoneBootstrapIdentity};
