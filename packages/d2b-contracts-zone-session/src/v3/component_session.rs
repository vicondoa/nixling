//! Canonical serialized and binary contracts for ComponentSession v3.
//!
//! This module defines wire values and their fail-closed validation. Transport,
//! Noise execution, scheduling, descriptor ownership, and I/O belong to the
//! ComponentSession implementation layer.

use schemars::{
    JsonSchema,
    schema::{
        ArrayValidation, InstanceType, NumberValidation, Schema, SchemaObject, SingleOrVec,
        SubschemaValidation,
    },
};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{SeqAccess, Visitor},
};
use std::{
    error::Error,
    fmt,
    ops::{Deref, DerefMut},
};

use d2b_contracts_resource::v3::identity::SessionPurpose;
use d2b_contracts_resource::v3::{ResourceRef, ResourceUid, ZoneId};

pub const PREFACE_LEN: usize = 16;
pub const PREFACE_MAGIC: [u8; 8] = *b"D2BCS3\r\n";
pub const COMPONENT_SESSION_MAJOR: u16 = 3;
pub const COMPONENT_SESSION_MINOR: u16 = 0;
pub const MAX_HANDSHAKE_OFFER_BYTES: usize = 16 * 1024;
pub const HANDSHAKE_OFFER_CANONICAL_LEN: usize = 148;
pub const ENDPOINT_POLICY_IDENTITY_CANONICAL_LEN: usize = HANDSHAKE_OFFER_CANONICAL_LEN - 8;
pub const MAX_PROTECTED_CIPHERTEXT_BYTES: u32 = u16::MAX as u32;
pub const NOISE_TAG_BYTES: u32 = 16;
pub const RECORD_LENGTH_BYTES: u32 = 2;
pub const MAX_PROTECTED_PLAINTEXT_BYTES: u32 = MAX_PROTECTED_CIPHERTEXT_BYTES - NOISE_TAG_BYTES;
pub const MAX_LOGICAL_MESSAGE_BYTES: u32 = 1024 * 1024;
pub const MAX_ACTIVE_NAMED_STREAMS: u16 = 128;
pub const MAX_PACKET_ATTACHMENTS: u16 = 32;
pub const MAX_REQUEST_ATTACHMENTS: u16 = 64;
pub const MAX_OPERATION_ATTACHMENTS: u16 = 128;
pub const MAX_SESSION_ATTACHMENTS: u16 = 256;
pub const MAX_PROCESS_ATTACHMENT_CREDITS: u16 = 2_048;
pub const MAX_HOST_ATTACHMENT_CREDITS: u16 = 8_192;
pub const RESERVED_CONTROL_FDS: u16 = 64;
pub const MAX_NAMED_STREAM_QUEUE_BYTES: u32 = 256 * 1024;
pub const MAX_AGGREGATE_NAMED_STREAM_QUEUE_BYTES: u32 = 4 * 1024 * 1024;
pub const MAX_TTRPC_CONTROL_QUEUE_BYTES: u32 = 2 * 1024 * 1024;
pub const MAX_SESSION_CONTROL_QUEUE_BYTES: u32 = 64 * 1024;
pub const MAX_CLOCK_SKEW_MS: u64 = 30_000;
pub const MAX_REQUEST_LIFETIME_MS: u64 = 15 * 60 * 1_000;
pub const LOCAL_HANDSHAKE_DEADLINE_MS: u32 = 5_000;
pub const REMOTE_HANDSHAKE_DEADLINE_MS: u32 = 15_000;
pub const LOCAL_RECONNECT_DEADLINE_MS: u32 = 5_000;
pub const REMOTE_RECONNECT_DEADLINE_MS: u32 = 30_000;
pub const MAX_RECONNECT_ATTEMPTS: u16 = 10;
pub const MAX_RECONNECT_WINDOW_MS: u32 = 5 * 60 * 1_000;
pub const MAX_KEEPALIVE_INTERVAL_MS: u32 = 60_000;
pub const MAX_KEEPALIVE_TIMEOUT_MS: u32 = 30_000;
pub const MAX_ID_BYTES: usize = 64;
pub const RECORD_HEADER_LEN: usize = 24;
pub const FRAGMENT_HEADER_LEN: usize = 24;
const HANDSHAKE_BINARY_VERSION: u8 = 1;
const NAMED_STREAM_CHANNEL_MIN: u16 = 0x0100;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct BoundedVec<T, const MIN: usize, const MAX: usize>(Vec<T>);

impl<T, const MIN: usize, const MAX: usize> BoundedVec<T, MIN, MAX> {
    pub fn new(values: Vec<T>) -> Result<Self, ContractError> {
        if values.len() < MIN || values.len() > MAX {
            Err(ContractError::LimitExceeded)
        } else {
            Ok(Self(values))
        }
    }

    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<T, const MIN: usize, const MAX: usize> Deref for BoundedVec<T, MIN, MAX> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<T, const MIN: usize, const MAX: usize> DerefMut for BoundedVec<T, MIN, MAX> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'de, T, const MIN: usize, const MAX: usize> Deserialize<'de> for BoundedVec<T, MIN, MAX>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BoundedVisitor<T, const MIN: usize, const MAX: usize>(std::marker::PhantomData<T>);

        impl<'de, T, const MIN: usize, const MAX: usize> Visitor<'de> for BoundedVisitor<T, MIN, MAX>
        where
            T: Deserialize<'de>,
        {
            type Value = BoundedVec<T, MIN, MAX>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "a sequence containing {MIN}..={MAX} items")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let capacity = sequence.size_hint().unwrap_or(0).min(MAX);
                let mut values = Vec::with_capacity(capacity);
                while let Some(value) = sequence.next_element()? {
                    if values.len() == MAX {
                        return Err(serde::de::Error::invalid_length(
                            MAX.saturating_add(1),
                            &self,
                        ));
                    }
                    values.push(value);
                }
                if values.len() < MIN {
                    return Err(serde::de::Error::invalid_length(values.len(), &self));
                }
                Ok(BoundedVec(values))
            }
        }

        deserializer.deserialize_seq(BoundedVisitor::<T, MIN, MAX>(std::marker::PhantomData))
    }
}

impl<T, const MIN: usize, const MAX: usize> JsonSchema for BoundedVec<T, MIN, MAX>
where
    T: JsonSchema,
{
    fn schema_name() -> String {
        format!("BoundedVec_{}_{}_{}", MIN, MAX, T::schema_name())
    }

    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> Schema {
        let mut schema = <Vec<T>>::json_schema(generator);
        if let Schema::Object(object) = &mut schema {
            let array = object
                .array
                .get_or_insert_with(Box::<ArrayValidation>::default);
            array.min_items = Some(MIN as u32);
            array.max_items = Some(MAX as u32);
        }
        schema
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefaceError {
    Truncated,
    InvalidLength,
    InvalidMagic,
    UnsupportedMajor,
    UnsupportedMinor,
    EmptyOffer,
    OfferTooLarge,
}

impl fmt::Display for PrefaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "component-session-preface-truncated",
            Self::InvalidLength => "component-session-preface-invalid-length",
            Self::InvalidMagic => "component-session-preface-invalid-magic",
            Self::UnsupportedMajor => "component-session-preface-unsupported-major",
            Self::UnsupportedMinor => "component-session-preface-unsupported-minor",
            Self::EmptyOffer => "component-session-preface-empty-offer",
            Self::OfferTooLarge => "component-session-preface-offer-too-large",
        })
    }
}

impl Error for PrefaceError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComponentSessionPreface {
    pub offer_len: u32,
}

impl ComponentSessionPreface {
    pub fn new(offer_len: usize) -> Result<Self, PrefaceError> {
        if offer_len == 0 {
            return Err(PrefaceError::EmptyOffer);
        }
        if offer_len > MAX_HANDSHAKE_OFFER_BYTES {
            return Err(PrefaceError::OfferTooLarge);
        }
        Ok(Self {
            offer_len: offer_len as u32,
        })
    }

    pub fn encode(self) -> [u8; PREFACE_LEN] {
        let mut bytes = [0_u8; PREFACE_LEN];
        bytes[..8].copy_from_slice(&PREFACE_MAGIC);
        bytes[8..10].copy_from_slice(&COMPONENT_SESSION_MAJOR.to_be_bytes());
        bytes[10..12].copy_from_slice(&COMPONENT_SESSION_MINOR.to_be_bytes());
        bytes[12..16].copy_from_slice(&self.offer_len.to_be_bytes());
        bytes
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, PrefaceError> {
        if bytes.len() < PREFACE_LEN {
            return Err(PrefaceError::Truncated);
        }
        if bytes.len() > PREFACE_LEN {
            return Err(PrefaceError::InvalidLength);
        }
        if bytes[..8] != PREFACE_MAGIC {
            return Err(PrefaceError::InvalidMagic);
        }
        if u16::from_be_bytes([bytes[8], bytes[9]]) != COMPONENT_SESSION_MAJOR {
            return Err(PrefaceError::UnsupportedMajor);
        }
        if u16::from_be_bytes([bytes[10], bytes[11]]) != COMPONENT_SESSION_MINOR {
            return Err(PrefaceError::UnsupportedMinor);
        }
        let offer_len = u32::from_be_bytes(bytes[12..16].try_into().expect("fixed slice"));
        Self::new(offer_len as usize)
    }
}

macro_rules! closed_enum {
    ($name:ident { $($variant:ident = $tag:literal => $wire:literal),+ $(,)? }) => {
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash,
            Serialize, Deserialize, JsonSchema,
        )]
        pub enum $name {
            $(
                #[serde(rename = $wire)]
                #[schemars(rename = $wire)]
                $variant
            ),+
        }

        impl $name {
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            pub const fn tag(self) -> u8 {
                match self {
                    $(Self::$variant => $tag),+
                }
            }

            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $wire),+
                }
            }

            pub fn from_tag(tag: u8) -> Result<Self, BinaryError> {
                match tag {
                    $($tag => Ok(Self::$variant),)+
                    _ => Err(BinaryError::UnknownEnumTag),
                }
            }
        }
    };
}

macro_rules! wire_enum_values {
    ($name:ident { $($variant:ident => $wire:literal),+ $(,)? }) => {
        impl $name {
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $wire),+
                }
            }
        }
    };
}

closed_enum!(EndpointPurpose {
    LocalLifecycle = 1 => "local-lifecycle",
    ResourceService = 2 => "resource-service",
    ZoneLink = 3 => "zone-link",
    Bootstrap = 4 => "bootstrap",
    ComponentSession = 5 => "component-session",
    ResourceTransfer = 6 => "resource-transfer",
    ProviderControl = 7 => "provider-control",
    SensitiveCredential = 8 => "sensitive-credential",
    UserControl = 9 => "user-control",
    ControllerWatch = 10 => "controller-watch",
    NamedStream = 11 => "named-stream",
    AuditExport = 12 => "audit-export",
    SupportBundle = 13 => "support-bundle"
});

closed_enum!(PurposeClass {
    Local = 1 => "local",
    Enrolled = 2 => "enrolled",
    Bootstrap = 3 => "bootstrap"
});

closed_enum!(EndpointRole {
    Component = 1 => "component",
    ZoneController = 2 => "zone-controller",
    HostAgent = 3 => "host-agent",
    GuestAgent = 4 => "guest-agent",
    Provider = 5 => "provider",
    UserAgent = 6 => "user-agent",
    Relay = 7 => "relay",
    Bootstrapper = 8 => "bootstrapper"
});

closed_enum!(ServicePackage {
    ResourceV3 = 1 => "d2b.resource.v3",
    ControllerV3 = 2 => "d2b.controller.v3",
    ProviderV3 = 3 => "d2b.provider.v3",
    AuditV3 = 4 => "d2b.audit.v3",
    SupportV3 = 5 => "d2b.support.v3",
    CredentialV3 = 6 => "d2b.credential.v3",
    DisplayV3 = 9 => "d2b.display.v3",
    ClipboardV3 = 10 => "d2b.clipboard.v3",
    ClipboardBridgeV3 = 11 => "d2b.clipboard.bridge.v3",
    ClipboardPickerCoordV3 = 12 => "d2b.clipboard.picker-coord.v3",
    NotificationV3 = 13 => "d2b.notification.v3",
    ConfigNixosV3 = 14 => "d2b.config-nixos.v3"
});

/// The typed authority boundary carried by a ComponentSession descriptor.
///
/// Resource API traffic remains a ResourceService boundary. Service-only
/// streams and Transport Provider carriage remain ComponentSession
/// boundaries, so neither can be represented as a generic RPC surface.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum ComponentSessionBoundary {
    /// The authenticated ResourceService client boundary.
    ResourceService,
    /// A service-only named stream boundary.
    ServiceStream,
    /// The typed Transport Provider carriage boundary.
    Transport,
}

/// Exact typed identity for one ComponentSession service boundary.
///
/// This descriptor carries only the immutable service, schema, and reconnect
/// generation. It does not enumerate methods or carry a transport handle.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ComponentSessionDescriptor {
    boundary: ComponentSessionBoundary,
    service: ServicePackage,
    schema_fingerprint: [u8; 32],
    reconnect_generation: u64,
}

impl ComponentSessionDescriptor {
    /// Construct and validate one exact typed boundary.
    pub fn new(
        boundary: ComponentSessionBoundary,
        service: ServicePackage,
        schema_fingerprint: [u8; 32],
        reconnect_generation: u64,
    ) -> Result<Self, ContractError> {
        if reconnect_generation == 0 {
            return Err(ContractError::InvalidGeneration);
        }
        if schema_fingerprint == [0; 32] {
            return Err(ContractError::InvalidBinding);
        }
        let service_matches = match boundary {
            ComponentSessionBoundary::ResourceService => service == ServicePackage::ResourceV3,
            ComponentSessionBoundary::ServiceStream => service != ServicePackage::ResourceV3,
            ComponentSessionBoundary::Transport => service == ServicePackage::ProviderV3,
        };
        if !service_matches {
            return Err(ContractError::IdentityEvidenceMismatch);
        }
        Ok(Self {
            boundary,
            service,
            schema_fingerprint,
            reconnect_generation,
        })
    }

    /// Construct the authenticated ResourceService boundary.
    pub fn resource(
        schema_fingerprint: [u8; 32],
        reconnect_generation: u64,
    ) -> Result<Self, ContractError> {
        Self::new(
            ComponentSessionBoundary::ResourceService,
            ServicePackage::ResourceV3,
            schema_fingerprint,
            reconnect_generation,
        )
    }

    /// Construct a service-only named-stream boundary.
    pub fn service_stream(
        service: ServicePackage,
        schema_fingerprint: [u8; 32],
        reconnect_generation: u64,
    ) -> Result<Self, ContractError> {
        Self::new(
            ComponentSessionBoundary::ServiceStream,
            service,
            schema_fingerprint,
            reconnect_generation,
        )
    }

    /// Construct the typed Transport Provider boundary.
    pub fn transport(
        schema_fingerprint: [u8; 32],
        reconnect_generation: u64,
    ) -> Result<Self, ContractError> {
        Self::new(
            ComponentSessionBoundary::Transport,
            ServicePackage::ProviderV3,
            schema_fingerprint,
            reconnect_generation,
        )
    }

    /// Derive a typed descriptor from an already validated endpoint policy.
    pub fn from_endpoint_policy(
        policy: &EndpointPolicy,
        boundary: ComponentSessionBoundary,
    ) -> Result<Self, ContractError> {
        HandshakeOffer::from(policy.clone()).validate()?;
        Self::new(
            boundary,
            policy.service,
            policy.schema_fingerprint,
            policy.reconnect_generation,
        )
    }

    /// Require exact service, schema, and generation agreement with a policy.
    pub fn matches_endpoint_policy(&self, policy: &EndpointPolicy) -> Result<(), ContractError> {
        if self.service != policy.service
            || self.schema_fingerprint != policy.schema_fingerprint
            || self.reconnect_generation != policy.reconnect_generation
        {
            return Err(ContractError::IdentityEvidenceMismatch);
        }
        HandshakeOffer::from(policy.clone()).validate()?;
        Ok(())
    }

    /// Return the typed boundary.
    pub const fn boundary(&self) -> ComponentSessionBoundary {
        self.boundary
    }

    /// Return the exact service package.
    pub const fn service(&self) -> ServicePackage {
        self.service
    }

    /// Borrow the exact schema fingerprint.
    pub const fn schema_fingerprint(&self) -> &[u8; 32] {
        &self.schema_fingerprint
    }

    /// Return the exact reconnect generation.
    pub const fn reconnect_generation(&self) -> u64 {
        self.reconnect_generation
    }

    /// Whether this is the ResourceService boundary.
    pub const fn is_resource_service(&self) -> bool {
        matches!(self.boundary, ComponentSessionBoundary::ResourceService)
    }

    /// Whether this is a service-only stream boundary.
    pub const fn is_service_stream(&self) -> bool {
        matches!(self.boundary, ComponentSessionBoundary::ServiceStream)
    }

    /// Whether this is the Transport Provider boundary.
    pub const fn is_transport(&self) -> bool {
        matches!(self.boundary, ComponentSessionBoundary::Transport)
    }
}

impl fmt::Debug for ComponentSessionDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ComponentSessionDescriptor")
            .field("boundary", &self.boundary)
            .field("service", &self.service)
            .field("schema_fingerprint", &"<redacted>")
            .field("reconnect_generation", &self.reconnect_generation)
            .finish()
    }
}

closed_enum!(NoiseProfile {
    Nn25519ChaChaPolySha256 = 1 => "Noise_NN_25519_ChaChaPoly_SHA256",
    Kk25519ChaChaPolySha256 = 2 => "Noise_KK_25519_ChaChaPoly_SHA256",
    Ikpsk2_25519ChaChaPolySha256 = 3 => "Noise_IKpsk2_25519_ChaChaPoly_SHA256"
});

closed_enum!(IdentityEvidenceRequirement {
    DirectionalUnix = 1 => "directional-unix",
    EnrolledStaticKeys = 2 => "enrolled-static-keys",
    ParentStaticAndSingleUsePsk = 3 => "parent-static-and-single-use-psk"
});

impl NoiseProfile {
    pub const fn identity_evidence(self) -> IdentityEvidenceRequirement {
        match self {
            Self::Nn25519ChaChaPolySha256 => IdentityEvidenceRequirement::DirectionalUnix,
            Self::Kk25519ChaChaPolySha256 => IdentityEvidenceRequirement::EnrolledStaticKeys,
            Self::Ikpsk2_25519ChaChaPolySha256 => {
                IdentityEvidenceRequirement::ParentStaticAndSingleUsePsk
            }
        }
    }

    pub const fn valid_for(self, purpose_class: PurposeClass) -> bool {
        matches!(
            (self, purpose_class),
            (Self::Nn25519ChaChaPolySha256, PurposeClass::Local)
                | (Self::Kk25519ChaChaPolySha256, PurposeClass::Enrolled)
                | (Self::Ikpsk2_25519ChaChaPolySha256, PurposeClass::Bootstrap)
        )
    }
}

closed_enum!(Locality {
    ProcessLocal = 1 => "process-local",
    HostLocal = 2 => "host-local",
    GuestLocal = 3 => "guest-local",
    Remote = 4 => "remote"
});

closed_enum!(TransportClass {
    UnixStream = 1 => "unix-stream",
    UnixSeqpacket = 2 => "unix-seqpacket",
    InheritedSocketpair = 3 => "inherited-socketpair",
    NativeVsock = 4 => "native-vsock",
    CloudHypervisorVsock = 5 => "cloud-hypervisor-vsock",
    ProviderStream = 6 => "provider-stream",
    DirectConfigured = 7 => "direct-configured"
});

closed_enum!(AttachmentPolicyKind {
    Disabled = 0 => "disabled",
    PacketAtomic = 1 => "packet-atomic"
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AttachmentPolicy {
    pub kind: AttachmentPolicyKind,
    pub max_per_packet: u16,
    pub max_per_request: u16,
    pub max_per_operation: u16,
    pub max_per_session: u16,
    pub credentials_allowed: bool,
}

impl AttachmentPolicy {
    pub const fn disabled() -> Self {
        Self {
            kind: AttachmentPolicyKind::Disabled,
            max_per_packet: 0,
            max_per_request: 0,
            max_per_operation: 0,
            max_per_session: 0,
            credentials_allowed: false,
        }
    }

    pub fn validate(self, transport: TransportClass) -> Result<(), ContractError> {
        match self.kind {
            AttachmentPolicyKind::Disabled => {
                if self != Self::disabled() {
                    return Err(ContractError::InvalidAttachmentPolicy);
                }
            }
            AttachmentPolicyKind::PacketAtomic => {
                if !matches!(
                    transport,
                    TransportClass::UnixSeqpacket | TransportClass::InheritedSocketpair
                ) || self.max_per_packet == 0
                    || self.max_per_packet > MAX_PACKET_ATTACHMENTS
                    || self.max_per_request < self.max_per_packet
                    || self.max_per_request > MAX_REQUEST_ATTACHMENTS
                    || self.max_per_operation < self.max_per_request
                    || self.max_per_operation > MAX_OPERATION_ATTACHMENTS
                    || self.max_per_session < self.max_per_operation
                    || self.max_per_session > MAX_SESSION_ATTACHMENTS
                {
                    return Err(ContractError::InvalidAttachmentPolicy);
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LimitProfile {
    pub handshake_offer_bytes: u32,
    pub protected_ciphertext_bytes: u32,
    pub logical_ttrpc_bytes: u32,
    pub logical_named_stream_bytes: u32,
    pub active_named_streams: u16,
    pub named_stream_queue_bytes: u32,
    pub aggregate_named_stream_queue_bytes: u32,
    pub ttrpc_control_queue_bytes: u32,
    pub session_control_queue_bytes: u32,
    pub keepalive_interval_ms: u32,
    pub keepalive_timeout_ms: u32,
    pub handshake_deadline_ms: u32,
    pub reconnect_deadline_ms: u32,
    pub reconnect_attempts: u16,
    pub reconnect_window_ms: u32,
}

impl LimitProfile {
    pub const fn local_default() -> Self {
        Self {
            handshake_offer_bytes: MAX_HANDSHAKE_OFFER_BYTES as u32,
            protected_ciphertext_bytes: MAX_PROTECTED_CIPHERTEXT_BYTES,
            logical_ttrpc_bytes: MAX_LOGICAL_MESSAGE_BYTES,
            logical_named_stream_bytes: MAX_NAMED_STREAM_QUEUE_BYTES,
            active_named_streams: MAX_ACTIVE_NAMED_STREAMS,
            named_stream_queue_bytes: MAX_NAMED_STREAM_QUEUE_BYTES,
            aggregate_named_stream_queue_bytes: MAX_AGGREGATE_NAMED_STREAM_QUEUE_BYTES,
            ttrpc_control_queue_bytes: MAX_TTRPC_CONTROL_QUEUE_BYTES,
            session_control_queue_bytes: MAX_SESSION_CONTROL_QUEUE_BYTES,
            keepalive_interval_ms: 30_000,
            keepalive_timeout_ms: 10_000,
            handshake_deadline_ms: LOCAL_HANDSHAKE_DEADLINE_MS,
            reconnect_deadline_ms: LOCAL_RECONNECT_DEADLINE_MS,
            reconnect_attempts: MAX_RECONNECT_ATTEMPTS,
            reconnect_window_ms: MAX_RECONNECT_WINDOW_MS,
        }
    }

    pub const fn remote_default() -> Self {
        Self {
            handshake_deadline_ms: REMOTE_HANDSHAKE_DEADLINE_MS,
            reconnect_deadline_ms: REMOTE_RECONNECT_DEADLINE_MS,
            ..Self::local_default()
        }
    }

    pub fn validate(self) -> Result<(), ContractError> {
        let nonzero = self.handshake_offer_bytes >= HANDSHAKE_OFFER_CANONICAL_LEN as u32
            && self.protected_ciphertext_bytes > NOISE_TAG_BYTES
            && self.logical_ttrpc_bytes != 0
            && self.logical_named_stream_bytes != 0
            && self.active_named_streams != 0
            && self.named_stream_queue_bytes != 0
            && self.aggregate_named_stream_queue_bytes != 0
            && self.ttrpc_control_queue_bytes != 0
            && self.session_control_queue_bytes != 0
            && self.keepalive_interval_ms != 0
            && self.keepalive_timeout_ms != 0
            && self.handshake_deadline_ms != 0
            && self.reconnect_deadline_ms != 0
            && self.reconnect_attempts != 0
            && self.reconnect_window_ms != 0;
        let bounded = self.handshake_offer_bytes <= MAX_HANDSHAKE_OFFER_BYTES as u32
            && self.protected_ciphertext_bytes <= MAX_PROTECTED_CIPHERTEXT_BYTES
            && self.logical_ttrpc_bytes <= MAX_LOGICAL_MESSAGE_BYTES
            && self.logical_named_stream_bytes <= MAX_LOGICAL_MESSAGE_BYTES
            && self.active_named_streams <= MAX_ACTIVE_NAMED_STREAMS
            && self.named_stream_queue_bytes <= MAX_NAMED_STREAM_QUEUE_BYTES
            && self.aggregate_named_stream_queue_bytes <= MAX_AGGREGATE_NAMED_STREAM_QUEUE_BYTES
            && self.ttrpc_control_queue_bytes <= MAX_TTRPC_CONTROL_QUEUE_BYTES
            && self.session_control_queue_bytes <= MAX_SESSION_CONTROL_QUEUE_BYTES
            && self.keepalive_interval_ms <= MAX_KEEPALIVE_INTERVAL_MS
            && self.keepalive_timeout_ms <= MAX_KEEPALIVE_TIMEOUT_MS
            && self.handshake_deadline_ms <= REMOTE_HANDSHAKE_DEADLINE_MS
            && self.reconnect_deadline_ms <= REMOTE_RECONNECT_DEADLINE_MS
            && self.reconnect_attempts <= MAX_RECONNECT_ATTEMPTS
            && self.reconnect_window_ms <= MAX_RECONNECT_WINDOW_MS;
        let ordered = self.keepalive_timeout_ms < self.keepalive_interval_ms
            && self.aggregate_named_stream_queue_bytes >= self.named_stream_queue_bytes
            && self.logical_named_stream_bytes <= self.named_stream_queue_bytes;
        if nonzero && bounded && ordered {
            Ok(())
        } else {
            Err(ContractError::LimitExceeded)
        }
    }

    pub fn protected_plaintext_bytes(self) -> Result<u32, ContractError> {
        self.protected_ciphertext_bytes
            .checked_sub(NOISE_TAG_BYTES)
            .ok_or(ContractError::ArithmeticOverflow)
    }

    pub fn checked_ciphertext_allocation(
        self,
        plaintext_bytes: u32,
        component_header_bytes: u32,
    ) -> Result<u32, ContractError> {
        let plaintext = plaintext_bytes
            .checked_add(component_header_bytes)
            .ok_or(ContractError::ArithmeticOverflow)?;
        let ciphertext = plaintext
            .checked_add(NOISE_TAG_BYTES)
            .ok_or(ContractError::ArithmeticOverflow)?;
        let wire = ciphertext
            .checked_add(RECORD_LENGTH_BYTES)
            .ok_or(ContractError::ArithmeticOverflow)?;
        if ciphertext > self.protected_ciphertext_bytes {
            return Err(ContractError::LimitExceeded);
        }
        Ok(wire)
    }

    pub fn checked_handshake_allocation(
        self,
        fixed_fields_bytes: u32,
        payload_bytes: u32,
        handshake_aead_tags: u32,
    ) -> Result<u32, ContractError> {
        let tags = handshake_aead_tags
            .checked_mul(NOISE_TAG_BYTES)
            .ok_or(ContractError::ArithmeticOverflow)?;
        let message = fixed_fields_bytes
            .checked_add(payload_bytes)
            .and_then(|value| value.checked_add(tags))
            .ok_or(ContractError::ArithmeticOverflow)?;
        let wire = message
            .checked_add(RECORD_LENGTH_BYTES)
            .ok_or(ContractError::ArithmeticOverflow)?;
        if message > self.protected_ciphertext_bytes {
            return Err(ContractError::LimitExceeded);
        }
        Ok(wire)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TransportBinding {
    pub transport: TransportClass,
    pub locality: Locality,
    pub channel_binding: [u8; 32],
    pub identity_evidence: IdentityEvidenceRequirement,
}

impl fmt::Debug for TransportBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransportBinding")
            .field("transport", &self.transport)
            .field("locality", &self.locality)
            .field("channel_binding", &"<redacted>")
            .field("identity_evidence", &self.identity_evidence)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HandshakeOffer {
    pub purpose: EndpointPurpose,
    pub purpose_class: PurposeClass,
    pub initiator_role: EndpointRole,
    pub responder_role: EndpointRole,
    pub service: ServicePackage,
    pub schema_fingerprint: [u8; 32],
    pub noise_profile: NoiseProfile,
    pub limits: LimitProfile,
    pub transport_binding: TransportBinding,
    pub reconnect_generation: u64,
    pub attachment_policy: AttachmentPolicy,
}

impl fmt::Debug for HandshakeOffer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HandshakeOffer")
            .field("purpose", &self.purpose)
            .field("purpose_class", &self.purpose_class)
            .field("initiator_role", &self.initiator_role)
            .field("responder_role", &self.responder_role)
            .field("service", &self.service)
            .field("schema_fingerprint", &"<redacted>")
            .field("noise_profile", &self.noise_profile)
            .field("limits", &self.limits)
            .field("transport_binding", &self.transport_binding)
            .field("reconnect_generation", &self.reconnect_generation)
            .field("attachment_policy", &self.attachment_policy)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EndpointPolicy {
    pub purpose: EndpointPurpose,
    pub purpose_class: PurposeClass,
    pub initiator_role: EndpointRole,
    pub responder_role: EndpointRole,
    pub service: ServicePackage,
    pub schema_fingerprint: [u8; 32],
    pub noise_profile: NoiseProfile,
    pub limits: LimitProfile,
    pub transport_binding: TransportBinding,
    pub reconnect_generation: u64,
    pub attachment_policy: AttachmentPolicy,
}

impl fmt::Debug for EndpointPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EndpointPolicy(<redacted>)")
    }
}

/// Exact endpoint policy fields that are stable before a local daemon restart
/// generation is known. This is not an authenticated session policy and cannot
/// validate a request until a nonzero generation has been negotiated.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EndpointPolicyIdentity {
    pub purpose: EndpointPurpose,
    pub purpose_class: PurposeClass,
    pub initiator_role: EndpointRole,
    pub responder_role: EndpointRole,
    pub service: ServicePackage,
    pub schema_fingerprint: [u8; 32],
    pub noise_profile: NoiseProfile,
    pub limits: LimitProfile,
    pub transport_binding: TransportBinding,
    pub attachment_policy: AttachmentPolicy,
}

impl fmt::Debug for EndpointPolicyIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EndpointPolicyIdentity(<redacted>)")
    }
}

fn validate_profile_policy(
    purpose: EndpointPurpose,
    purpose_class: PurposeClass,
    profile: NoiseProfile,
    transport: TransportBinding,
) -> Result<(), ContractError> {
    let bootstrap_exact =
        (purpose == EndpointPurpose::Bootstrap) == (purpose_class == PurposeClass::Bootstrap);
    let profile_transport_valid = match profile {
        NoiseProfile::Nn25519ChaChaPolySha256 => {
            transport.locality != Locality::Remote
                && matches!(
                    transport.transport,
                    TransportClass::UnixStream
                        | TransportClass::UnixSeqpacket
                        | TransportClass::InheritedSocketpair
                )
        }
        NoiseProfile::Kk25519ChaChaPolySha256 => true,
        NoiseProfile::Ikpsk2_25519ChaChaPolySha256 => purpose == EndpointPurpose::Bootstrap,
    };
    let credential_profile_valid = purpose != EndpointPurpose::SensitiveCredential
        || profile == NoiseProfile::Kk25519ChaChaPolySha256;
    if bootstrap_exact && profile_transport_valid && credential_profile_valid {
        Ok(())
    } else {
        Err(ContractError::IdentityEvidenceMismatch)
    }
}

impl From<&EndpointPolicy> for EndpointPolicyIdentity {
    fn from(value: &EndpointPolicy) -> Self {
        Self {
            purpose: value.purpose,
            purpose_class: value.purpose_class,
            initiator_role: value.initiator_role,
            responder_role: value.responder_role,
            service: value.service,
            schema_fingerprint: value.schema_fingerprint,
            noise_profile: value.noise_profile,
            limits: value.limits,
            transport_binding: value.transport_binding,
            attachment_policy: value.attachment_policy,
        }
    }
}

impl EndpointPolicyIdentity {
    pub fn validate(&self) -> Result<(), ContractError> {
        self.limits.validate()?;
        self.attachment_policy
            .validate(self.transport_binding.transport)?;
        if !self.noise_profile.valid_for(self.purpose_class)
            || self.noise_profile.identity_evidence() != self.transport_binding.identity_evidence
        {
            return Err(ContractError::IdentityEvidenceMismatch);
        }
        validate_profile_policy(
            self.purpose,
            self.purpose_class,
            self.noise_profile,
            self.transport_binding,
        )?;
        if self.schema_fingerprint == [0; 32] || self.transport_binding.channel_binding == [0; 32] {
            return Err(ContractError::InvalidBinding);
        }
        Ok(())
    }

    pub fn validate_local_generation_discovery(&self) -> Result<(), ContractError> {
        self.validate()?;
        if self.purpose_class != PurposeClass::Local
            || self.noise_profile != NoiseProfile::Nn25519ChaChaPolySha256
            || self.transport_binding.identity_evidence
                != IdentityEvidenceRequirement::DirectionalUnix
            || !matches!(
                self.transport_binding.transport,
                TransportClass::UnixStream | TransportClass::UnixSeqpacket
            )
        {
            return Err(ContractError::IdentityEvidenceMismatch);
        }
        Ok(())
    }

    /// Validate an identity permitted to request reconnect generation
    /// discovery. Discovery does not authenticate static keys; the subsequent
    /// handshake remains responsible for exact policy and key authentication.
    pub fn validate_generation_discovery(&self) -> Result<(), ContractError> {
        self.validate()?;
        let local = self.purpose_class == PurposeClass::Local
            && self.noise_profile == NoiseProfile::Nn25519ChaChaPolySha256
            && self.transport_binding.identity_evidence
                == IdentityEvidenceRequirement::DirectionalUnix
            && matches!(
                self.transport_binding.transport,
                TransportClass::UnixStream | TransportClass::UnixSeqpacket
            );
        let enrolled_guest = self.purpose == EndpointPurpose::ZoneLink
            && self.purpose_class == PurposeClass::Enrolled
            && self.initiator_role == EndpointRole::ZoneController
            && self.responder_role == EndpointRole::GuestAgent
            && self.service == ServicePackage::ResourceV3
            && self.noise_profile == NoiseProfile::Kk25519ChaChaPolySha256
            && self.transport_binding.transport == TransportClass::NativeVsock
            && self.transport_binding.locality == Locality::GuestLocal
            && self.transport_binding.identity_evidence
                == IdentityEvidenceRequirement::EnrolledStaticKeys
            && self.attachment_policy == AttachmentPolicy::disabled();
        if local || enrolled_guest {
            Ok(())
        } else {
            Err(ContractError::IdentityEvidenceMismatch)
        }
    }

    pub fn with_generation(
        &self,
        reconnect_generation: u64,
    ) -> Result<EndpointPolicy, ContractError> {
        let policy = EndpointPolicy {
            purpose: self.purpose,
            purpose_class: self.purpose_class,
            initiator_role: self.initiator_role,
            responder_role: self.responder_role,
            service: self.service,
            schema_fingerprint: self.schema_fingerprint,
            noise_profile: self.noise_profile,
            limits: self.limits,
            transport_binding: self.transport_binding,
            reconnect_generation,
            attachment_policy: self.attachment_policy,
        };
        HandshakeOffer::from(policy.clone()).validate()?;
        Ok(policy)
    }

    pub fn validate_exact(&self, policy: &EndpointPolicy) -> Result<(), HandshakeRejectReason> {
        let expected = Self::from(policy);
        if self.purpose != expected.purpose {
            return Err(HandshakeRejectReason::PurposeMismatch);
        }
        if self.purpose_class != expected.purpose_class {
            return Err(HandshakeRejectReason::PurposeClassMismatch);
        }
        if self.initiator_role != expected.initiator_role
            || self.responder_role != expected.responder_role
        {
            return Err(HandshakeRejectReason::RoleMismatch);
        }
        if self.service != expected.service {
            return Err(HandshakeRejectReason::ServiceMismatch);
        }
        if self.schema_fingerprint != expected.schema_fingerprint {
            return Err(HandshakeRejectReason::SchemaMismatch);
        }
        if self.noise_profile != expected.noise_profile {
            return Err(HandshakeRejectReason::NoiseProfileMismatch);
        }
        if self.limits != expected.limits {
            return Err(HandshakeRejectReason::LimitProfileMismatch);
        }
        if self.transport_binding != expected.transport_binding {
            return Err(HandshakeRejectReason::ChannelBindingMismatch);
        }
        if self.attachment_policy != expected.attachment_policy {
            return Err(HandshakeRejectReason::AttachmentPolicyMismatch);
        }
        self.validate()
            .map_err(|_| HandshakeRejectReason::MalformedOffer)
    }

    pub fn encode_canonical(&self) -> Result<Vec<u8>, BinaryError> {
        self.validate().map_err(BinaryError::InvalidContract)?;
        let mut writer = BinaryWriter::with_capacity(ENDPOINT_POLICY_IDENTITY_CANONICAL_LEN);
        writer.u8(HANDSHAKE_BINARY_VERSION);
        writer.u8(self.purpose.tag());
        writer.u8(self.purpose_class.tag());
        writer.u8(self.initiator_role.tag());
        writer.u8(self.responder_role.tag());
        writer.u8(self.service.tag());
        writer.bytes(&self.schema_fingerprint);
        writer.u8(self.noise_profile.tag());
        encode_limits(&mut writer, self.limits);
        writer.u8(self.transport_binding.transport.tag());
        writer.u8(self.transport_binding.locality.tag());
        writer.bytes(&self.transport_binding.channel_binding);
        writer.u8(self.transport_binding.identity_evidence.tag());
        encode_attachment_policy(&mut writer, self.attachment_policy);
        if writer.len() != ENDPOINT_POLICY_IDENTITY_CANONICAL_LEN {
            return Err(BinaryError::NonCanonical);
        }
        Ok(writer.finish())
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, BinaryError> {
        if bytes.len() != ENDPOINT_POLICY_IDENTITY_CANONICAL_LEN {
            return Err(BinaryError::LengthExceeded);
        }
        let mut reader = BinaryReader::new(bytes);
        if reader.u8()? != HANDSHAKE_BINARY_VERSION {
            return Err(BinaryError::UnsupportedVersion);
        }
        let identity = Self {
            purpose: EndpointPurpose::from_tag(reader.u8()?)?,
            purpose_class: PurposeClass::from_tag(reader.u8()?)?,
            initiator_role: EndpointRole::from_tag(reader.u8()?)?,
            responder_role: EndpointRole::from_tag(reader.u8()?)?,
            service: ServicePackage::from_tag(reader.u8()?)?,
            schema_fingerprint: reader.array()?,
            noise_profile: NoiseProfile::from_tag(reader.u8()?)?,
            limits: decode_limits(&mut reader)?,
            transport_binding: TransportBinding {
                transport: TransportClass::from_tag(reader.u8()?)?,
                locality: Locality::from_tag(reader.u8()?)?,
                channel_binding: reader.array()?,
                identity_evidence: IdentityEvidenceRequirement::from_tag(reader.u8()?)?,
            },
            attachment_policy: decode_attachment_policy(&mut reader)?,
        };
        reader.finish()?;
        identity.validate().map_err(BinaryError::InvalidContract)?;
        if identity.encode_canonical()?.as_slice() != bytes {
            return Err(BinaryError::NonCanonical);
        }
        Ok(identity)
    }
}

impl EndpointPolicy {
    /// Validate the exact endpoint profile allowed for ZoneLink traffic.
    ///
    /// ZoneLink traffic is an enrolled, attachment-free `Noise_KK` session.
    /// The two active carriage profiles are a remote Provider stream between
    /// Zone controllers and a Guest-local vsock session terminating at a
    /// GuestAgent. The authenticated session carries these same fields in its
    /// transcript-bound policy; this method only validates the profile and
    /// returns no authority-bearing value.
    pub fn validate_zone_link(&self) -> Result<(), ContractError> {
        EndpointPolicyIdentity::from(self).validate()?;
        if self.reconnect_generation == 0
            || self.purpose != EndpointPurpose::ZoneLink
            || self.purpose_class != PurposeClass::Enrolled
            || self.initiator_role != EndpointRole::ZoneController
            || self.service != ServicePackage::ResourceV3
            || self.noise_profile != NoiseProfile::Kk25519ChaChaPolySha256
            || self.transport_binding.identity_evidence
                != IdentityEvidenceRequirement::EnrolledStaticKeys
            || self.attachment_policy != AttachmentPolicy::disabled()
            || !matches!(
                (
                    self.responder_role,
                    self.transport_binding.transport,
                    self.transport_binding.locality,
                ),
                (
                    EndpointRole::ZoneController,
                    TransportClass::ProviderStream,
                    Locality::Remote,
                ) | (
                    EndpointRole::GuestAgent,
                    TransportClass::NativeVsock,
                    Locality::GuestLocal,
                )
            )
        {
            return Err(ContractError::InvalidBinding);
        }
        Ok(())
    }
}

impl From<EndpointPolicy> for HandshakeOffer {
    fn from(value: EndpointPolicy) -> Self {
        Self {
            purpose: value.purpose,
            purpose_class: value.purpose_class,
            initiator_role: value.initiator_role,
            responder_role: value.responder_role,
            service: value.service,
            schema_fingerprint: value.schema_fingerprint,
            noise_profile: value.noise_profile,
            limits: value.limits,
            transport_binding: value.transport_binding,
            reconnect_generation: value.reconnect_generation,
            attachment_policy: value.attachment_policy,
        }
    }
}

impl HandshakeOffer {
    pub fn validate(&self) -> Result<(), ContractError> {
        self.limits.validate()?;
        self.attachment_policy
            .validate(self.transport_binding.transport)?;
        if self.reconnect_generation == 0 {
            return Err(ContractError::InvalidGeneration);
        }
        if !self.noise_profile.valid_for(self.purpose_class)
            || self.noise_profile.identity_evidence() != self.transport_binding.identity_evidence
        {
            return Err(ContractError::IdentityEvidenceMismatch);
        }
        validate_profile_policy(
            self.purpose,
            self.purpose_class,
            self.noise_profile,
            self.transport_binding,
        )?;
        if self.schema_fingerprint == [0; 32] || self.transport_binding.channel_binding == [0; 32] {
            return Err(ContractError::InvalidBinding);
        }
        Ok(())
    }

    pub fn validate_exact(&self, policy: &EndpointPolicy) -> Result<(), HandshakeRejectReason> {
        if self.purpose != policy.purpose {
            return Err(HandshakeRejectReason::PurposeMismatch);
        }
        if self.purpose_class != policy.purpose_class {
            return Err(HandshakeRejectReason::PurposeClassMismatch);
        }
        if self.initiator_role != policy.initiator_role
            || self.responder_role != policy.responder_role
        {
            return Err(HandshakeRejectReason::RoleMismatch);
        }
        if self.service != policy.service {
            return Err(HandshakeRejectReason::ServiceMismatch);
        }
        if self.schema_fingerprint != policy.schema_fingerprint {
            return Err(HandshakeRejectReason::SchemaMismatch);
        }
        if self.noise_profile != policy.noise_profile {
            return Err(HandshakeRejectReason::NoiseProfileMismatch);
        }
        if self.limits != policy.limits {
            return Err(HandshakeRejectReason::LimitProfileMismatch);
        }
        if self.transport_binding != policy.transport_binding {
            return Err(HandshakeRejectReason::ChannelBindingMismatch);
        }
        if self.reconnect_generation != policy.reconnect_generation {
            return Err(HandshakeRejectReason::GenerationMismatch);
        }
        if self.attachment_policy != policy.attachment_policy {
            return Err(HandshakeRejectReason::AttachmentPolicyMismatch);
        }
        self.validate()
            .map_err(|_| HandshakeRejectReason::MalformedOffer)
    }

    pub fn encode_canonical(&self) -> Result<Vec<u8>, BinaryError> {
        self.validate().map_err(BinaryError::InvalidContract)?;
        let mut writer = BinaryWriter::with_capacity(192);
        writer.u8(HANDSHAKE_BINARY_VERSION);
        writer.u8(self.purpose.tag());
        writer.u8(self.purpose_class.tag());
        writer.u8(self.initiator_role.tag());
        writer.u8(self.responder_role.tag());
        writer.u8(self.service.tag());
        writer.bytes(&self.schema_fingerprint);
        writer.u8(self.noise_profile.tag());
        encode_limits(&mut writer, self.limits);
        writer.u8(self.transport_binding.transport.tag());
        writer.u8(self.transport_binding.locality.tag());
        writer.bytes(&self.transport_binding.channel_binding);
        writer.u8(self.transport_binding.identity_evidence.tag());
        writer.u64(self.reconnect_generation);
        encode_attachment_policy(&mut writer, self.attachment_policy);
        if writer.len() != HANDSHAKE_OFFER_CANONICAL_LEN {
            return Err(BinaryError::NonCanonical);
        }
        if writer.len() > MAX_HANDSHAKE_OFFER_BYTES
            || writer.len() > self.limits.handshake_offer_bytes as usize
        {
            return Err(BinaryError::LengthExceeded);
        }
        Ok(writer.finish())
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, BinaryError> {
        if bytes.is_empty() || bytes.len() > MAX_HANDSHAKE_OFFER_BYTES {
            return Err(BinaryError::LengthExceeded);
        }
        let mut reader = BinaryReader::new(bytes);
        if reader.u8()? != HANDSHAKE_BINARY_VERSION {
            return Err(BinaryError::UnsupportedVersion);
        }
        let offer = Self {
            purpose: EndpointPurpose::from_tag(reader.u8()?)?,
            purpose_class: PurposeClass::from_tag(reader.u8()?)?,
            initiator_role: EndpointRole::from_tag(reader.u8()?)?,
            responder_role: EndpointRole::from_tag(reader.u8()?)?,
            service: ServicePackage::from_tag(reader.u8()?)?,
            schema_fingerprint: reader.array()?,
            noise_profile: NoiseProfile::from_tag(reader.u8()?)?,
            limits: decode_limits(&mut reader)?,
            transport_binding: TransportBinding {
                transport: TransportClass::from_tag(reader.u8()?)?,
                locality: Locality::from_tag(reader.u8()?)?,
                channel_binding: reader.array()?,
                identity_evidence: IdentityEvidenceRequirement::from_tag(reader.u8()?)?,
            },
            reconnect_generation: reader.u64()?,
            attachment_policy: decode_attachment_policy(&mut reader)?,
        };
        reader.finish()?;
        if bytes.len() > offer.limits.handshake_offer_bytes as usize {
            return Err(BinaryError::LengthExceeded);
        }
        offer.validate().map_err(BinaryError::InvalidContract)?;
        if offer.encode_canonical()?.as_slice() != bytes {
            return Err(BinaryError::NonCanonical);
        }
        Ok(offer)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HandshakeAccept {
    pub offer: HandshakeOffer,
    pub transcript_binding: [u8; 32],
}

impl fmt::Debug for HandshakeAccept {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HandshakeAccept")
            .field("offer", &self.offer)
            .field("transcript_binding", &"<redacted>")
            .finish()
    }
}

impl HandshakeAccept {
    pub fn encode_canonical(&self) -> Result<Vec<u8>, BinaryError> {
        if self.transcript_binding == [0; 32] {
            return Err(BinaryError::InvalidContract(ContractError::InvalidBinding));
        }
        let offer = self.offer.encode_canonical()?;
        let offer_len = u16::try_from(offer.len()).map_err(|_| BinaryError::LengthExceeded)?;
        let mut writer = BinaryWriter::with_capacity(offer.len() + 36);
        writer.u8(HANDSHAKE_BINARY_VERSION);
        writer.u16(offer_len);
        writer.bytes(&offer);
        writer.bytes(&self.transcript_binding);
        Ok(writer.finish())
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, BinaryError> {
        let mut reader = BinaryReader::new(bytes);
        if reader.u8()? != HANDSHAKE_BINARY_VERSION {
            return Err(BinaryError::UnsupportedVersion);
        }
        let offer_len = reader.u16()? as usize;
        let offer = HandshakeOffer::decode_canonical(reader.take(offer_len)?)?;
        let transcript_binding = reader.array()?;
        reader.finish()?;
        let accept = Self {
            offer,
            transcript_binding,
        };
        if accept.transcript_binding == [0; 32] {
            return Err(BinaryError::InvalidContract(ContractError::InvalidBinding));
        }
        Ok(accept)
    }
}

closed_enum!(HandshakeRejectReason {
    MalformedPreface = 1 => "malformed-preface",
    UnsupportedVersion = 2 => "unsupported-version",
    OfferTooLarge = 3 => "offer-too-large",
    MalformedOffer = 4 => "malformed-offer",
    PurposeMismatch = 5 => "purpose-mismatch",
    PurposeClassMismatch = 6 => "purpose-class-mismatch",
    RoleMismatch = 7 => "role-mismatch",
    ServiceMismatch = 8 => "service-mismatch",
    SchemaMismatch = 9 => "schema-mismatch",
    NoiseProfileMismatch = 10 => "noise-profile-mismatch",
    LimitProfileMismatch = 11 => "limit-profile-mismatch",
    ChannelBindingMismatch = 12 => "channel-binding-mismatch",
    GenerationMismatch = 13 => "generation-mismatch",
    AttachmentPolicyMismatch = 14 => "attachment-policy-mismatch",
    IdentityEvidenceMismatch = 15 => "identity-evidence-mismatch",
    AuthenticationFailed = 16 => "authentication-failed",
    HandshakeTimeout = 17 => "handshake-timeout",
    BootstrapExpired = 18 => "bootstrap-expired",
    BootstrapReplayed = 19 => "bootstrap-replayed",
    BootstrapOperationMismatch = 20 => "bootstrap-operation-mismatch",
    ResourceExhausted = 21 => "resource-exhausted"
});

closed_enum!(Remediation {
    None = 0 => "none",
    RetryBounded = 1 => "retry-bounded",
    InspectProvider = 2 => "inspect-provider",
    RestartAgent = 3 => "restart-agent",
    ReplaceGeneration = 4 => "replace-generation",
    ReEnrollPeer = 5 => "re-enroll-peer",
    RepairConfiguration = 6 => "repair-configuration",
    ReduceLoad = 7 => "reduce-load"
});

closed_enum!(SessionErrorCode {
    MalformedPreface = 1 => "malformed-preface",
    UnsupportedVersion = 2 => "unsupported-version",
    MalformedHandshake = 3 => "malformed-handshake",
    AuthenticationFailed = 4 => "authentication-failed",
    TranscriptMismatch = 5 => "transcript-mismatch",
    PurposeMismatch = 6 => "purpose-mismatch",
    PurposeClassMismatch = 7 => "purpose-class-mismatch",
    RoleMismatch = 8 => "role-mismatch",
    ServiceMismatch = 9 => "service-mismatch",
    SchemaMismatch = 10 => "schema-mismatch",
    LimitMismatch = 11 => "limit-mismatch",
    ChannelBindingMismatch = 12 => "channel-binding-mismatch",
    GenerationMismatch = 13 => "generation-mismatch",
    IdentityEvidenceMismatch = 14 => "identity-evidence-mismatch",
    AttachmentPolicyMismatch = 15 => "attachment-policy-mismatch",
    HandshakeTimeout = 16 => "handshake-timeout",
    RecordTruncated = 17 => "record-truncated",
    RecordMalformed = 18 => "record-malformed",
    RecordReplay = 19 => "record-replay",
    RecordOutOfOrder = 20 => "record-out-of-order",
    NonceExhausted = 21 => "nonce-exhausted",
    FragmentTruncated = 22 => "fragment-truncated",
    FragmentDuplicate = 23 => "fragment-duplicate",
    FragmentReordered = 24 => "fragment-reordered",
    FragmentOverlap = 25 => "fragment-overlap",
    ReassemblyLimitExceeded = 26 => "reassembly-limit-exceeded",
    InvalidChannel = 27 => "invalid-channel",
    UnknownControl = 28 => "unknown-control",
    DeadlineInvalid = 29 => "deadline-invalid",
    DeadlineExpired = 30 => "deadline-expired",
    Cancelled = 31 => "cancelled",
    RequestIdDuplicate = 32 => "request-id-duplicate",
    AttachmentTruncated = 33 => "attachment-truncated",
    AttachmentControlTruncated = 34 => "attachment-control-truncated",
    AttachmentCountMismatch = 35 => "attachment-count-mismatch",
    AttachmentDescriptorMismatch = 36 => "attachment-descriptor-mismatch",
    AttachmentObjectMismatch = 37 => "attachment-object-mismatch",
    AttachmentAccessMismatch = 38 => "attachment-access-mismatch",
    AttachmentMissingCloexec = 39 => "attachment-missing-cloexec",
    AttachmentCreditExceeded = 40 => "attachment-credit-exceeded",
    QueueBackpressure = 41 => "queue-backpressure",
    ControlResourceExhausted = 42 => "control-resource-exhausted",
    SchedulerStalled = 43 => "scheduler-stalled",
    KeepaliveTimeout = 44 => "keepalive-timeout",
    SessionDisconnected = 45 => "session-disconnected",
    BootstrapExpired = 46 => "bootstrap-expired",
    BootstrapReplayed = 47 => "bootstrap-replayed",
    BootstrapOperationMismatch = 48 => "bootstrap-operation-mismatch",
    ArithmeticOverflow = 49 => "arithmetic-overflow",
    InternalInvariant = 50 => "internal-invariant",
    PolicyDenied = 51 => "policy-denied",
    SubjectMismatch = 52 => "subject-mismatch",
    TransportMismatch = 53 => "transport-mismatch",
    SubjectConfigurationMismatch = 54 => "subject-configuration-mismatch"
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HandshakeReject {
    pub reason: HandshakeRejectReason,
    pub remediation: Remediation,
}

impl HandshakeReject {
    pub fn encode_canonical(self) -> [u8; 3] {
        [
            HANDSHAKE_BINARY_VERSION,
            self.reason.tag(),
            self.remediation.tag(),
        ]
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, BinaryError> {
        if bytes.len() != 3 {
            return Err(BinaryError::Truncated);
        }
        if bytes[0] != HANDSHAKE_BINARY_VERSION {
            return Err(BinaryError::UnsupportedVersion);
        }
        Ok(Self {
            reason: HandshakeRejectReason::from_tag(bytes[1])?,
            remediation: Remediation::from_tag(bytes[2])?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractError {
    ArithmeticOverflow,
    LimitExceeded,
    InvalidAttachmentPolicy,
    IdentityEvidenceMismatch,
    InvalidBinding,
    InvalidGeneration,
    InvalidChannel,
    InvalidFragment,
    InvalidDeadline,
    InvalidId,
    InvalidAttachment,
    CreditExceeded,
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ArithmeticOverflow => "checked-arithmetic-overflow",
            Self::LimitExceeded => "contract-limit-exceeded",
            Self::InvalidAttachmentPolicy => "invalid-attachment-policy",
            Self::IdentityEvidenceMismatch => "identity-evidence-mismatch",
            Self::InvalidBinding => "invalid-binding",
            Self::InvalidGeneration => "invalid-session-generation",
            Self::InvalidChannel => "invalid-channel",
            Self::InvalidFragment => "invalid-fragment",
            Self::InvalidDeadline => "invalid-request-deadline",
            Self::InvalidId => "invalid-bounded-id",
            Self::InvalidAttachment => "invalid-attachment",
            Self::CreditExceeded => "attachment-credit-exceeded",
        })
    }
}

impl Error for ContractError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryError {
    Truncated,
    TrailingBytes,
    LengthExceeded,
    UnknownEnumTag,
    UnsupportedVersion,
    NonCanonical,
    InvalidContract(ContractError),
}

impl fmt::Display for BinaryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidContract(error) => write!(f, "invalid-component-session-contract:{error}"),
            Self::Truncated => f.write_str("component-session-binary-truncated"),
            Self::TrailingBytes => f.write_str("component-session-binary-trailing-bytes"),
            Self::LengthExceeded => f.write_str("component-session-binary-length-exceeded"),
            Self::UnknownEnumTag => f.write_str("component-session-binary-unknown-enum-tag"),
            Self::UnsupportedVersion => f.write_str("component-session-binary-unsupported-version"),
            Self::NonCanonical => f.write_str("component-session-binary-non-canonical"),
        }
    }
}

impl Error for BinaryError {}

impl From<ContractError> for BinaryError {
    fn from(value: ContractError) -> Self {
        Self::InvalidContract(value)
    }
}

closed_enum!(RecordKind {
    SessionControl = 1 => "session-control",
    Ttrpc = 2 => "ttrpc",
    NamedStream = 3 => "named-stream",
    Attachment = 4 => "attachment",
    KeepalivePing = 5 => "keepalive-ping",
    KeepalivePong = 6 => "keepalive-pong",
    Close = 7 => "close",
    CancelRequest = 8 => "cancel-request",
    CancelAck = 9 => "cancel-ack"
});

closed_enum!(ChannelClass {
    SessionControl = 1 => "session-control",
    TtrpcControl = 2 => "ttrpc-control",
    AttachmentControl = 3 => "attachment-control",
    NamedStream = 4 => "named-stream"
});

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ChannelId(u16);

impl ChannelId {
    pub const SESSION_CONTROL: Self = Self(0);
    pub const TTRPC_CONTROL: Self = Self(1);
    pub const ATTACHMENT_CONTROL: Self = Self(2);

    pub fn named(value: u16) -> Result<Self, ContractError> {
        if value < NAMED_STREAM_CHANNEL_MIN {
            Err(ContractError::InvalidChannel)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn value(self) -> u16 {
        self.0
    }

    pub const fn class(self) -> ChannelClass {
        match self.0 {
            0 => ChannelClass::SessionControl,
            1 => ChannelClass::TtrpcControl,
            2 => ChannelClass::AttachmentControl,
            _ => ChannelClass::NamedStream,
        }
    }

    pub fn validate(self) -> Result<(), ContractError> {
        if self.0 == 3 || (self.0 > 3 && self.0 < NAMED_STREAM_CHANNEL_MIN) {
            Err(ContractError::InvalidChannel)
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for ChannelId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ChannelId(<redacted>)")
    }
}

impl<'de> Deserialize<'de> for ChannelId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u16::deserialize(deserializer)?;
        let channel = Self(value);
        channel.validate().map_err(serde::de::Error::custom)?;
        Ok(channel)
    }
}

impl JsonSchema for ChannelId {
    fn schema_name() -> String {
        "ChannelId".to_owned()
    }

    fn json_schema(_generator: &mut schemars::r#gen::SchemaGenerator) -> Schema {
        fn integer_range(minimum: u16, maximum: u16) -> Schema {
            Schema::Object(SchemaObject {
                instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::Integer))),
                number: Some(Box::new(NumberValidation {
                    minimum: Some(f64::from(minimum)),
                    maximum: Some(f64::from(maximum)),
                    ..NumberValidation::default()
                })),
                ..SchemaObject::default()
            })
        }

        Schema::Object(SchemaObject {
            subschemas: Some(Box::new(SubschemaValidation {
                any_of: Some(vec![
                    integer_range(0, 0),
                    integer_range(1, 1),
                    integer_range(2, 2),
                    integer_range(NAMED_STREAM_CHANNEL_MIN, u16::MAX),
                ]),
                ..SubschemaValidation::default()
            })),
            ..SchemaObject::default()
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RecordHeader {
    pub kind: RecordKind,
    pub flags: u8,
    pub channel: ChannelId,
    pub sequence: u64,
    pub reconnect_generation: u64,
    pub payload_len: u32,
}

impl RecordHeader {
    pub fn validate(self, limits: LimitProfile) -> Result<(), ContractError> {
        self.channel.validate()?;
        if self.reconnect_generation == 0
            || self.payload_len > limits.protected_plaintext_bytes()?
        {
            return Err(ContractError::LimitExceeded);
        }
        let expected_class = match self.kind {
            RecordKind::SessionControl
            | RecordKind::KeepalivePing
            | RecordKind::KeepalivePong
            | RecordKind::Close
            | RecordKind::CancelRequest
            | RecordKind::CancelAck => ChannelClass::SessionControl,
            RecordKind::Ttrpc => ChannelClass::TtrpcControl,
            RecordKind::Attachment => ChannelClass::AttachmentControl,
            RecordKind::NamedStream => ChannelClass::NamedStream,
        };
        if self.channel.class() != expected_class {
            return Err(ContractError::InvalidChannel);
        }
        Ok(())
    }

    pub fn encode(self, limits: LimitProfile) -> Result<[u8; RECORD_HEADER_LEN], ContractError> {
        self.validate(limits)?;
        let mut bytes = [0_u8; RECORD_HEADER_LEN];
        bytes[0] = self.kind.tag();
        bytes[1] = self.flags;
        bytes[2..4].copy_from_slice(&self.channel.value().to_be_bytes());
        bytes[4..12].copy_from_slice(&self.sequence.to_be_bytes());
        bytes[12..20].copy_from_slice(&self.reconnect_generation.to_be_bytes());
        bytes[20..24].copy_from_slice(&self.payload_len.to_be_bytes());
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8], limits: LimitProfile) -> Result<Self, BinaryError> {
        if bytes.len() != RECORD_HEADER_LEN {
            return Err(BinaryError::Truncated);
        }
        let header = Self {
            kind: RecordKind::from_tag(bytes[0])?,
            flags: bytes[1],
            channel: ChannelId(u16::from_be_bytes([bytes[2], bytes[3]])),
            sequence: u64::from_be_bytes(bytes[4..12].try_into().expect("fixed slice")),
            reconnect_generation: u64::from_be_bytes(
                bytes[12..20].try_into().expect("fixed slice"),
            ),
            payload_len: u32::from_be_bytes(bytes[20..24].try_into().expect("fixed slice")),
        };
        header
            .validate(limits)
            .map_err(BinaryError::InvalidContract)?;
        Ok(header)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FragmentHeader {
    pub message_id: u64,
    pub index: u32,
    pub count: u32,
    pub total_plaintext_len: u32,
    pub offset: u32,
}

impl FragmentHeader {
    pub fn validate(self, fragment_len: u32, logical_limit: u32) -> Result<(), ContractError> {
        let end = self
            .offset
            .checked_add(fragment_len)
            .ok_or(ContractError::ArithmeticOverflow)?;
        if self.message_id == 0
            || self.count == 0
            || self.index >= self.count
            || self.total_plaintext_len == 0
            || self.total_plaintext_len > logical_limit
            || self.offset >= self.total_plaintext_len
            || end > self.total_plaintext_len
            || (self.index + 1 == self.count && end != self.total_plaintext_len)
        {
            return Err(ContractError::InvalidFragment);
        }

        Ok(())
    }

    pub fn encode(
        self,
        fragment_len: u32,
        logical_limit: u32,
    ) -> Result<[u8; FRAGMENT_HEADER_LEN], ContractError> {
        self.validate(fragment_len, logical_limit)?;
        let mut bytes = [0_u8; FRAGMENT_HEADER_LEN];
        bytes[0..8].copy_from_slice(&self.message_id.to_be_bytes());
        bytes[8..12].copy_from_slice(&self.index.to_be_bytes());
        bytes[12..16].copy_from_slice(&self.count.to_be_bytes());
        bytes[16..20].copy_from_slice(&self.total_plaintext_len.to_be_bytes());
        bytes[20..24].copy_from_slice(&self.offset.to_be_bytes());
        Ok(bytes)
    }

    pub fn decode(
        bytes: &[u8],
        fragment_len: u32,
        logical_limit: u32,
    ) -> Result<Self, BinaryError> {
        if bytes.len() != FRAGMENT_HEADER_LEN {
            return Err(BinaryError::Truncated);
        }
        let header = Self {
            message_id: u64::from_be_bytes(bytes[0..8].try_into().expect("fixed slice")),
            index: u32::from_be_bytes(bytes[8..12].try_into().expect("fixed slice")),
            count: u32::from_be_bytes(bytes[12..16].try_into().expect("fixed slice")),
            total_plaintext_len: u32::from_be_bytes(bytes[16..20].try_into().expect("fixed slice")),
            offset: u32::from_be_bytes(bytes[20..24].try_into().expect("fixed slice")),
        };
        header
            .validate(fragment_len, logical_limit)
            .map_err(BinaryError::InvalidContract)?;
        Ok(header)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragmentSequenceError {
    DifferentMessage,
    Duplicate,
    Reordered,
    Overlap,
    Invalid,
    Complete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentSequence {
    message_id: u64,
    count: u32,
    total_plaintext_len: u32,
    next_index: u32,
    next_offset: u32,
}

impl FragmentSequence {
    pub fn begin(
        first: FragmentHeader,
        fragment_len: u32,
        logical_limit: u32,
    ) -> Result<Self, FragmentSequenceError> {
        first
            .validate(fragment_len, logical_limit)
            .map_err(|_| FragmentSequenceError::Invalid)?;
        if first.index != 0 || first.offset != 0 {
            return Err(FragmentSequenceError::Reordered);
        }
        Ok(Self {
            message_id: first.message_id,
            count: first.count,
            total_plaintext_len: first.total_plaintext_len,
            next_index: 1,
            next_offset: fragment_len,
        })
    }

    pub fn accept(
        &mut self,
        fragment: FragmentHeader,
        fragment_len: u32,
        logical_limit: u32,
    ) -> Result<bool, FragmentSequenceError> {
        if self.next_index >= self.count {
            return Err(FragmentSequenceError::Complete);
        }
        if fragment.message_id != self.message_id
            || fragment.count != self.count
            || fragment.total_plaintext_len != self.total_plaintext_len
        {
            return Err(FragmentSequenceError::DifferentMessage);
        }
        if fragment.index < self.next_index {
            return Err(FragmentSequenceError::Duplicate);
        }
        if fragment.index > self.next_index {
            return Err(FragmentSequenceError::Reordered);
        }
        if fragment.offset < self.next_offset {
            return Err(FragmentSequenceError::Overlap);
        }
        if fragment.offset > self.next_offset {
            return Err(FragmentSequenceError::Reordered);
        }
        fragment
            .validate(fragment_len, logical_limit)
            .map_err(|_| FragmentSequenceError::Invalid)?;
        self.next_offset = self
            .next_offset
            .checked_add(fragment_len)
            .ok_or(FragmentSequenceError::Invalid)?;
        self.next_index += 1;
        Ok(self.next_index == self.count && self.next_offset == self.total_plaintext_len)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequenceError {
    Replay,
    OutOfOrder,
    NonceExhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiveSequence {
    expected: u64,
    exhausted: bool,
}

impl ReceiveSequence {
    pub const fn new() -> Self {
        Self {
            expected: 0,
            exhausted: false,
        }
    }

    pub const fn from_expected(expected: u64) -> Self {
        Self {
            expected,
            exhausted: expected == u64::MAX,
        }
    }

    pub fn accept(&mut self, sequence: u64) -> Result<(), SequenceError> {
        if self.exhausted || sequence == u64::MAX {
            return Err(SequenceError::NonceExhausted);
        }
        if sequence < self.expected {
            return Err(SequenceError::Replay);
        }
        if sequence > self.expected {
            return Err(SequenceError::OutOfOrder);
        }
        if sequence == u64::MAX - 1 {
            self.exhausted = true;
        } else {
            self.expected += 1;
        }
        Ok(())
    }
}

impl Default for ReceiveSequence {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendSequence {
    next: u64,
    exhausted: bool,
}

impl SendSequence {
    pub const fn new() -> Self {
        Self {
            next: 0,
            exhausted: false,
        }
    }

    pub const fn from_next(next: u64) -> Self {
        Self {
            next,
            exhausted: next == u64::MAX,
        }
    }

    pub fn take(&mut self) -> Result<u64, SequenceError> {
        if self.exhausted || self.next == u64::MAX {
            return Err(SequenceError::NonceExhausted);
        }
        let sequence = self.next;
        if sequence == u64::MAX - 1 {
            self.exhausted = true;
        } else {
            self.next += 1;
        }
        Ok(sequence)
    }
}

impl Default for SendSequence {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
pub enum CloseReason {
    #[serde(rename = "normal")]
    #[schemars(rename = "normal")]
    Normal,
    #[serde(rename = "peer-requested")]
    #[schemars(rename = "peer-requested")]
    PeerRequested,
    #[serde(rename = "authentication-failed")]
    #[schemars(rename = "authentication-failed")]
    AuthenticationFailed,
    #[serde(rename = "purpose-mismatch")]
    #[schemars(rename = "purpose-mismatch")]
    PurposeMismatch,
    #[serde(rename = "role-mismatch")]
    #[schemars(rename = "role-mismatch")]
    RoleMismatch,
    #[serde(rename = "schema-mismatch")]
    #[schemars(rename = "schema-mismatch")]
    SchemaMismatch,
    #[serde(rename = "limit-mismatch")]
    #[schemars(rename = "limit-mismatch")]
    LimitMismatch,
    #[serde(rename = "channel-binding-mismatch")]
    #[schemars(rename = "channel-binding-mismatch")]
    ChannelBindingMismatch,
    #[serde(rename = "replay")]
    #[schemars(rename = "replay")]
    Replay,
    #[serde(rename = "record-truncated")]
    #[schemars(rename = "record-truncated")]
    RecordTruncated,
    #[serde(rename = "fragment-invalid")]
    #[schemars(rename = "fragment-invalid")]
    FragmentInvalid,
    #[serde(rename = "nonce-exhausted")]
    #[schemars(rename = "nonce-exhausted")]
    NonceExhausted,
    #[serde(rename = "deadline-expired")]
    #[schemars(rename = "deadline-expired")]
    DeadlineExpired,
    #[serde(rename = "cancelled")]
    #[schemars(rename = "cancelled")]
    Cancelled,
    #[serde(rename = "attachment-invalid")]
    #[schemars(rename = "attachment-invalid")]
    AttachmentInvalid,
    #[serde(rename = "attachment-truncated")]
    #[schemars(rename = "attachment-truncated")]
    AttachmentTruncated,
    #[serde(rename = "unknown-control")]
    #[schemars(rename = "unknown-control")]
    UnknownControl,
    #[serde(rename = "credit-exhausted")]
    #[schemars(rename = "credit-exhausted")]
    CreditExhausted,
    #[serde(rename = "control-resource-exhausted")]
    #[schemars(rename = "control-resource-exhausted")]
    ControlResourceExhausted,
    #[serde(rename = "scheduler-stalled")]
    #[schemars(rename = "scheduler-stalled")]
    SchedulerStalled,
    #[serde(rename = "keepalive-timeout")]
    #[schemars(rename = "keepalive-timeout")]
    KeepaliveTimeout,
    #[serde(rename = "session-lost")]
    #[schemars(rename = "session-lost")]
    SessionLost,
    #[serde(rename = "internal-invariant")]
    #[schemars(rename = "internal-invariant")]
    InternalInvariant,
}

wire_enum_values!(CloseReason {
    Normal => "normal",
    PeerRequested => "peer-requested",
    AuthenticationFailed => "authentication-failed",
    PurposeMismatch => "purpose-mismatch",
    RoleMismatch => "role-mismatch",
    SchemaMismatch => "schema-mismatch",
    LimitMismatch => "limit-mismatch",
    ChannelBindingMismatch => "channel-binding-mismatch",
    Replay => "replay",
    RecordTruncated => "record-truncated",
    FragmentInvalid => "fragment-invalid",
    NonceExhausted => "nonce-exhausted",
    DeadlineExpired => "deadline-expired",
    Cancelled => "cancelled",
    AttachmentInvalid => "attachment-invalid",
    AttachmentTruncated => "attachment-truncated",
    UnknownControl => "unknown-control",
    CreditExhausted => "credit-exhausted",
    ControlResourceExhausted => "control-resource-exhausted",
    SchedulerStalled => "scheduler-stalled",
    KeepaliveTimeout => "keepalive-timeout",
    SessionLost => "session-lost",
    InternalInvariant => "internal-invariant"
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct KeepaliveRecord {
    pub reconnect_generation: u64,
    pub nonce: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CloseRecord {
    pub reconnect_generation: u64,
    pub reason: CloseReason,
    pub remediation: Remediation,
}

macro_rules! bounded_bytes {
    ($name:ident, $min:expr, $max:expr) => {
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
        #[serde(transparent)]
        pub struct $name(BoundedVec<u8, $min, $max>);

        impl $name {
            pub fn new(value: impl Into<Vec<u8>>) -> Result<Self, ContractError> {
                BoundedVec::new(value.into())
                    .map(Self)
                    .map_err(|_| ContractError::InvalidId)
            }

            pub fn as_bytes(&self) -> &[u8] {
                self.0.as_slice()
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = BoundedVec::<u8, $min, $max>::deserialize(deserializer)?;
                Ok(Self(value))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}

bounded_bytes!(RequestId, 16, 16);
bounded_bytes!(CorrelationId, 1, 64);
bounded_bytes!(TraceId, 16, 16);
bounded_bytes!(IdempotencyKey, 1, 64);
bounded_bytes!(OperationId, 16, 16);

#[cfg(test)]
mod bounded_identifier_tests {
    use super::*;

    #[test]
    fn identifier_debug_shapes_are_exact_and_redacted() {
        let sentinel = b"0123456789secret".to_vec();
        let request = RequestId::new(sentinel.clone()).unwrap();
        let correlation = CorrelationId::new(sentinel.clone()).unwrap();
        let trace = TraceId::new(sentinel.clone()).unwrap();
        let idempotency = IdempotencyKey::new(sentinel.clone()).unwrap();
        let operation = OperationId::new(sentinel.clone()).unwrap();

        for retained in [
            request.as_bytes(),
            correlation.as_bytes(),
            trace.as_bytes(),
            idempotency.as_bytes(),
            operation.as_bytes(),
        ] {
            assert_eq!(retained, sentinel);
        }
        assert_eq!(format!("{request:?}"), "RequestId(<redacted>)");
        assert_eq!(format!("{correlation:?}"), "CorrelationId(<redacted>)");
        assert_eq!(format!("{trace:?}"), "TraceId(<redacted>)");
        assert_eq!(format!("{idempotency:?}"), "IdempotencyKey(<redacted>)");
        assert_eq!(format!("{operation:?}"), "OperationId(<redacted>)");
    }

    #[test]
    fn channel_debug_redacts_named_stream_identifiers() {
        let channel = ChannelId::named(43_981).unwrap();
        assert_eq!(channel.value(), 43_981);
        assert_eq!(format!("{channel:?}"), "ChannelId(<redacted>)");

        let header = RecordHeader {
            kind: RecordKind::NamedStream,
            flags: 0,
            channel,
            sequence: 7,
            reconnect_generation: 9,
            payload_len: 11,
        };
        let rendered = format!("{header:?}");
        assert!(!rendered.contains("43981"), "{rendered}");
        assert!(rendered.contains("ChannelId(<redacted>)"), "{rendered}");
    }

    #[test]
    fn named_stream_contract_never_advertises_more_than_one_queue_can_retain() {
        let limits = LimitProfile::local_default();
        assert_eq!(
            limits.logical_named_stream_bytes,
            limits.named_stream_queue_bytes
        );
        let mut invalid = limits;
        invalid.logical_named_stream_bytes += 1;
        assert_eq!(invalid.validate(), Err(ContractError::LimitExceeded));
    }

    #[test]
    fn handshake_debug_redacts_bindings_after_accessor_preconditions() {
        let offer = HandshakeOffer {
            purpose: EndpointPurpose::LocalLifecycle,
            purpose_class: PurposeClass::Local,
            initiator_role: EndpointRole::ZoneController,
            responder_role: EndpointRole::Component,
            service: ServicePackage::ResourceV3,
            schema_fingerprint: [0x51; 32],
            noise_profile: NoiseProfile::Nn25519ChaChaPolySha256,
            limits: LimitProfile::local_default(),
            transport_binding: TransportBinding {
                transport: TransportClass::UnixStream,
                locality: Locality::HostLocal,
                channel_binding: [0x52; 32],
                identity_evidence: IdentityEvidenceRequirement::DirectionalUnix,
            },
            reconnect_generation: 1,
            attachment_policy: AttachmentPolicy::disabled(),
        };
        let accept = HandshakeAccept {
            offer: offer.clone(),
            transcript_binding: [0x53; 32],
        };
        assert_eq!(offer.schema_fingerprint, [0x51; 32]);
        assert_eq!(offer.transport_binding.channel_binding, [0x52; 32]);
        assert_eq!(accept.transcript_binding, [0x53; 32]);
        let raw_bindings = [
            format!("{:?}", offer.schema_fingerprint),
            format!("{:?}", offer.transport_binding.channel_binding),
            format!("{:?}", accept.transcript_binding),
        ];
        let rendered = format!("{accept:?}");
        for raw_binding in raw_bindings {
            assert!(!rendered.contains(&raw_binding), "{rendered}");
        }
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }
}

#[cfg(test)]
mod zone_link_profile_tests {
    use super::*;

    fn enrolled_policy() -> EndpointPolicy {
        EndpointPolicy {
            purpose: EndpointPurpose::ZoneLink,
            purpose_class: PurposeClass::Enrolled,
            initiator_role: EndpointRole::ZoneController,
            responder_role: EndpointRole::ZoneController,
            service: ServicePackage::ResourceV3,
            schema_fingerprint: [0x11; 32],
            noise_profile: NoiseProfile::Kk25519ChaChaPolySha256,
            limits: LimitProfile::local_default(),
            transport_binding: TransportBinding {
                transport: TransportClass::ProviderStream,
                locality: Locality::Remote,
                channel_binding: [0x22; 32],
                identity_evidence: IdentityEvidenceRequirement::EnrolledStaticKeys,
            },
            reconnect_generation: 7,
            attachment_policy: AttachmentPolicy::disabled(),
        }
    }

    fn guest_policy() -> EndpointPolicy {
        EndpointPolicy {
            purpose: EndpointPurpose::ZoneLink,
            purpose_class: PurposeClass::Enrolled,
            initiator_role: EndpointRole::ZoneController,
            responder_role: EndpointRole::GuestAgent,
            service: ServicePackage::ResourceV3,
            schema_fingerprint: [0x11; 32],
            noise_profile: NoiseProfile::Kk25519ChaChaPolySha256,
            limits: LimitProfile::remote_default(),
            transport_binding: TransportBinding {
                transport: TransportClass::NativeVsock,
                locality: Locality::GuestLocal,
                channel_binding: [0x22; 32],
                identity_evidence: IdentityEvidenceRequirement::EnrolledStaticKeys,
            },
            reconnect_generation: 7,
            attachment_policy: AttachmentPolicy::disabled(),
        }
    }

    #[test]
    fn only_the_enrolled_zone_link_profiles_validate() {
        assert!(enrolled_policy().validate_zone_link().is_ok());
        assert!(guest_policy().validate_zone_link().is_ok());

        for mutate in [
            |policy: &mut EndpointPolicy| policy.purpose = EndpointPurpose::ResourceService,
            |policy: &mut EndpointPolicy| policy.purpose_class = PurposeClass::Local,
            |policy: &mut EndpointPolicy| policy.initiator_role = EndpointRole::Provider,
            |policy: &mut EndpointPolicy| policy.responder_role = EndpointRole::Provider,
            |policy: &mut EndpointPolicy| policy.service = ServicePackage::ControllerV3,
            |policy: &mut EndpointPolicy| {
                policy.noise_profile = NoiseProfile::Nn25519ChaChaPolySha256
            },
            |policy: &mut EndpointPolicy| {
                policy.transport_binding.transport = TransportClass::NativeVsock
            },
            |policy: &mut EndpointPolicy| policy.transport_binding.locality = Locality::GuestLocal,
            |policy: &mut EndpointPolicy| {
                policy.transport_binding.identity_evidence =
                    IdentityEvidenceRequirement::DirectionalUnix
            },
            |policy: &mut EndpointPolicy| {
                policy.attachment_policy = AttachmentPolicy {
                    kind: AttachmentPolicyKind::PacketAtomic,
                    max_per_packet: 1,
                    max_per_request: 1,
                    max_per_operation: 1,
                    max_per_session: 1,
                    credentials_allowed: false,
                }
            },
        ] {
            let mut policy = enrolled_policy();
            mutate(&mut policy);
            assert!(policy.validate_zone_link().is_err());
        }
    }

    #[test]
    fn a_zero_reconnect_generation_cannot_bind_a_zone_link_session() {
        let mut policy = enrolled_policy();
        policy.reconnect_generation = 0;
        assert_eq!(
            policy.validate_zone_link(),
            Err(ContractError::InvalidBinding)
        );
    }
}

#[derive(PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BootstrapIdentityBinding {
    pub subject_ref: ResourceRef,
    pub subject_uid: ResourceUid,
    pub zone: ZoneId,
    pub purpose: SessionPurpose,
}

impl BootstrapIdentityBinding {
    pub fn validate(&self) -> Result<(), ContractError> {
        if !matches!(
            self.subject_ref.resource_type().as_str(),
            "Host" | "Guest" | "Provider" | "Zone" | "Process"
        ) {
            return Err(ContractError::InvalidBinding);
        }
        Ok(())
    }
}

impl fmt::Debug for BootstrapIdentityBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BootstrapIdentityBinding(<redacted>)")
    }
}

#[derive(PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BootstrapPskBinding {
    pub operation_id: OperationId,
    pub replay_nonce: [u8; 32],
    pub identity: BootstrapIdentityBinding,
    pub expires_at_unix_ms: u64,
}

impl BootstrapPskBinding {
    pub fn validate(&self) -> Result<(), ContractError> {
        self.identity.validate()?;
        if self.replay_nonce == [0; 32] {
            return Err(ContractError::InvalidBinding);
        }
        if self.expires_at_unix_ms == 0 {
            return Err(ContractError::InvalidDeadline);
        }
        Ok(())
    }
}

impl fmt::Debug for BootstrapPskBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BootstrapPskBinding(<redacted>)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RequestEnvelope {
    pub request_id: RequestId,
    pub correlation_id: Option<CorrelationId>,
    pub trace_id: Option<TraceId>,
    pub idempotency_key: Option<IdempotencyKey>,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmittedDeadline {
    pub absolute_expiry_unix_ms: u64,
    pub remaining_nanos: u64,
}

/// Short-lived authorization state held by one authenticated session owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuthorizationLease {
    policy_revision: u64,
    expires_at_tick: u64,
}

impl AuthorizationLease {
    /// Construct a nonempty policy lease.
    pub fn new(policy_revision: u64, expires_at_tick: u64) -> Result<Self, ContractError> {
        if policy_revision == 0 || expires_at_tick == 0 {
            return Err(ContractError::InvalidDeadline);
        }
        Ok(Self {
            policy_revision,
            expires_at_tick,
        })
    }

    /// Return the policy revision captured by this lease.
    pub const fn policy_revision(self) -> u64 {
        self.policy_revision
    }

    /// Return the monotonic expiry tick.
    pub const fn expires_at_tick(self) -> u64 {
        self.expires_at_tick
    }

    /// Check whether the lease remains valid at a monotonic tick.
    pub const fn is_valid_at(self, now_tick: u64) -> bool {
        now_tick < self.expires_at_tick
    }
}

impl RequestEnvelope {
    pub fn admit(
        &self,
        local_wall_clock_ms: u64,
        service_max_lifetime_ms: u64,
        monotonic_remaining_nanos: Option<u64>,
        peer_ttrpc_timeout_nanos: Option<u64>,
    ) -> Result<AdmittedDeadline, ContractError> {
        if self.expires_at_unix_ms < self.issued_at_unix_ms
            || service_max_lifetime_ms == 0
            || service_max_lifetime_ms > MAX_REQUEST_LIFETIME_MS
        {
            return Err(ContractError::InvalidDeadline);
        }
        let lifetime = self
            .expires_at_unix_ms
            .checked_sub(self.issued_at_unix_ms)
            .ok_or(ContractError::InvalidDeadline)?;
        let newest_acceptable_issue = local_wall_clock_ms
            .checked_add(MAX_CLOCK_SKEW_MS)
            .ok_or(ContractError::ArithmeticOverflow)?;
        if lifetime > MAX_REQUEST_LIFETIME_MS
            || lifetime > service_max_lifetime_ms
            || self.issued_at_unix_ms > newest_acceptable_issue
            || self.expires_at_unix_ms <= local_wall_clock_ms
        {
            return Err(ContractError::InvalidDeadline);
        }
        let wall_remaining_ms = self.expires_at_unix_ms - local_wall_clock_ms;
        let capped_ms = wall_remaining_ms.min(service_max_lifetime_ms);
        let mut remaining_nanos = capped_ms
            .checked_mul(1_000_000)
            .ok_or(ContractError::ArithmeticOverflow)?;
        if let Some(monotonic) = monotonic_remaining_nanos {
            remaining_nanos = remaining_nanos.min(monotonic);
        }
        if let Some(peer_timeout) = peer_ttrpc_timeout_nanos {
            remaining_nanos = remaining_nanos.min(peer_timeout);
        }
        if remaining_nanos == 0 {
            return Err(ContractError::InvalidDeadline);
        }
        Ok(AdmittedDeadline {
            absolute_expiry_unix_ms: self.expires_at_unix_ms,
            remaining_nanos,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CancelRequest {
    pub reconnect_generation: u64,
    pub request_id: RequestId,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
pub enum CancelResult {
    #[serde(rename = "cancelled-before-dispatch")]
    #[schemars(rename = "cancelled-before-dispatch")]
    CancelledBeforeDispatch,
    #[serde(rename = "cancellation-signalled")]
    #[schemars(rename = "cancellation-signalled")]
    CancellationSignalled,
    #[serde(rename = "already-terminal")]
    #[schemars(rename = "already-terminal")]
    AlreadyTerminal,
    #[serde(rename = "unknown-request")]
    #[schemars(rename = "unknown-request")]
    UnknownRequest,
    #[serde(rename = "generation-mismatch")]
    #[schemars(rename = "generation-mismatch")]
    GenerationMismatch,
}

wire_enum_values!(CancelResult {
    CancelledBeforeDispatch => "cancelled-before-dispatch",
    CancellationSignalled => "cancellation-signalled",
    AlreadyTerminal => "already-terminal",
    UnknownRequest => "unknown-request",
    GenerationMismatch => "generation-mismatch"
});

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CancelAck {
    pub reconnect_generation: u64,
    pub request_id: RequestId,
    pub result: CancelResult,
}

impl CancelRequest {
    pub fn acknowledge(self, active_generation: u64, result: CancelResult) -> CancelAck {
        let result = if self.reconnect_generation == active_generation {
            result
        } else {
            CancelResult::GenerationMismatch
        };
        CancelAck {
            reconnect_generation: self.reconnect_generation,
            request_id: self.request_id,
            result,
        }
    }
}

closed_enum!(AttachmentKind {
    FileDescriptor = 1 => "file-descriptor",
    Credentials = 2 => "credentials"
});

closed_enum!(KernelObjectType {
    Pidfd = 1 => "pidfd",
    UnixStreamSocket = 2 => "unix-stream-socket",
    UnixSeqpacketSocket = 3 => "unix-seqpacket-socket",
    PipeRead = 4 => "pipe-read",
    PipeWrite = 5 => "pipe-write",
    Memfd = 6 => "memfd",
    RegularFile = 7 => "regular-file",
    Directory = 8 => "directory",
    Device = 9 => "device",
    Tap = 10 => "tap",
    Kvm = 11 => "kvm",
    Vhost = 12 => "vhost",
    Fuse = 13 => "fuse",
    Hidraw = 14 => "hidraw",
    PtyMaster = 15 => "pty-master",
    PtySlave = 16 => "pty-slave",
    WaylandSocket = 17 => "wayland-socket",
    ProcessCredentials = 18 => "process-credentials"
});

closed_enum!(AttachmentAccess {
    ReadOnly = 1 => "read-only",
    WriteOnly = 2 => "write-only",
    ReadWrite = 3 => "read-write",
    IoctlRestricted = 4 => "ioctl-restricted"
});

closed_enum!(AttachmentPurpose {
    RequestInput = 1 => "request-input",
    ResponseOutput = 2 => "response-output",
    Terminal = 3 => "terminal",
    Wayland = 4 => "wayland",
    ClipboardTransfer = 5 => "clipboard-transfer",
    Listener = 6 => "listener",
    ProcessIdentity = 7 => "process-identity",
    DeviceLease = 8 => "device-lease",
    RuntimeHandle = 9 => "runtime-handle"
});

closed_enum!(AttachmentCreditClass {
    Packet = 1 => "packet",
    Request = 2 => "request",
    Operation = 3 => "operation",
    Session = 4 => "session",
    Process = 5 => "process",
    Host = 6 => "host"
});

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AttachmentDescriptor {
    pub index: u16,
    pub kind: AttachmentKind,
    pub object_type: KernelObjectType,
    pub access: AttachmentAccess,
    pub purpose: AttachmentPurpose,
    pub service: ServicePackage,
    pub method_id: u32,
    pub request_id: RequestId,
    pub operation_id: Option<OperationId>,
    pub packet_sequence: u64,
    pub reconnect_generation: u64,
    pub duplicate_object_allowed: bool,
    pub cloexec_required: bool,
    pub credit_classes: BoundedVec<AttachmentCreditClass, 6, 6>,
}

impl AttachmentDescriptor {
    pub fn validate(&self, expected_index: u16) -> Result<(), ContractError> {
        if self.index != expected_index
            || self.reconnect_generation == 0
            || self.credit_classes.as_slice()
                != [
                    AttachmentCreditClass::Packet,
                    AttachmentCreditClass::Request,
                    AttachmentCreditClass::Operation,
                    AttachmentCreditClass::Session,
                    AttachmentCreditClass::Process,
                    AttachmentCreditClass::Host,
                ]
            || match self.kind {
                AttachmentKind::FileDescriptor => {
                    !self.cloexec_required
                        || self.object_type == KernelObjectType::ProcessCredentials
                }
                AttachmentKind::Credentials => {
                    self.cloexec_required
                        || self.object_type != KernelObjectType::ProcessCredentials
                        || self.access != AttachmentAccess::ReadOnly
                        || self.purpose != AttachmentPurpose::ProcessIdentity
                        || self.duplicate_object_allowed
                }
            }
        {
            return Err(ContractError::InvalidAttachment);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AttachmentPacket {
    pub declared_count: u16,
    pub descriptors: BoundedVec<AttachmentDescriptor, 0, 32>,
}

impl AttachmentPacket {
    pub fn validate(
        &self,
        policy: AttachmentPolicy,
        actual_descriptor_count: usize,
        message_truncated: bool,
        control_truncated: bool,
        unknown_control: bool,
    ) -> Result<(), AttachmentReceiveError> {
        if message_truncated {
            return Err(AttachmentReceiveError::MessageTruncated);
        }
        if control_truncated {
            return Err(AttachmentReceiveError::ControlTruncated);
        }
        if unknown_control {
            return Err(AttachmentReceiveError::UnknownControl);
        }
        if policy.kind != AttachmentPolicyKind::PacketAtomic {
            return Err(AttachmentReceiveError::PolicyDenied);
        }
        let declared = usize::from(self.declared_count);
        if declared != self.descriptors.len() || declared != actual_descriptor_count {
            return Err(AttachmentReceiveError::CountMismatch);
        }
        if self.declared_count > policy.max_per_packet {
            return Err(AttachmentReceiveError::CreditExceeded);
        }
        if !policy.credentials_allowed
            && self
                .descriptors
                .iter()
                .any(|descriptor| descriptor.kind == AttachmentKind::Credentials)
        {
            return Err(AttachmentReceiveError::PolicyDenied);
        }
        for (index, descriptor) in self.descriptors.iter().enumerate() {
            descriptor
                .validate(index as u16)
                .map_err(|_| AttachmentReceiveError::DescriptorMismatch)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentReceiveError {
    MessageTruncated,
    ControlTruncated,
    UnknownControl,
    CountMismatch,
    DescriptorMismatch,
    CreditExceeded,
    PolicyDenied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttachmentCredits {
    pub packet: u16,
    pub request: u16,
    pub operation: u16,
    pub session: u16,
    pub process: u16,
    pub host: u16,
}

impl AttachmentCredits {
    pub fn reserve(self, count: u16, policy: AttachmentPolicy) -> Result<Self, ContractError> {
        let next = Self {
            packet: self
                .packet
                .checked_add(count)
                .ok_or(ContractError::ArithmeticOverflow)?,
            request: self
                .request
                .checked_add(count)
                .ok_or(ContractError::ArithmeticOverflow)?,
            operation: self
                .operation
                .checked_add(count)
                .ok_or(ContractError::ArithmeticOverflow)?,
            session: self
                .session
                .checked_add(count)
                .ok_or(ContractError::ArithmeticOverflow)?,
            process: self
                .process
                .checked_add(count)
                .ok_or(ContractError::ArithmeticOverflow)?,
            host: self
                .host
                .checked_add(count)
                .ok_or(ContractError::ArithmeticOverflow)?,
        };
        if next.packet > policy.max_per_packet
            || next.request > policy.max_per_request
            || next.operation > policy.max_per_operation
            || next.session > policy.max_per_session
            || next.process > MAX_PROCESS_ATTACHMENT_CREDITS
            || next.host > MAX_HOST_ATTACHMENT_CREDITS
        {
            return Err(ContractError::CreditExceeded);
        }
        Ok(next)
    }

    pub fn process_pool(
        rlimit_nofile_soft: u64,
        observed_nontransferable_open_fds: u64,
    ) -> Result<u16, ContractError> {
        let available = rlimit_nofile_soft
            .checked_sub(observed_nontransferable_open_fds)
            .and_then(|value| value.checked_sub(u64::from(RESERVED_CONTROL_FDS)))
            .ok_or(ContractError::CreditExceeded)?;
        Ok(available
            .min(u64::from(MAX_PROCESS_ATTACHMENT_CREDITS))
            .try_into()
            .expect("bounded by u16 constant"))
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
pub enum MetricResult {
    #[serde(rename = "accepted")]
    #[schemars(rename = "accepted")]
    Accepted,
    #[serde(rename = "rejected")]
    #[schemars(rename = "rejected")]
    Rejected,
    #[serde(rename = "cancelled")]
    #[schemars(rename = "cancelled")]
    Cancelled,
    #[serde(rename = "expired")]
    #[schemars(rename = "expired")]
    Expired,
    #[serde(rename = "closed")]
    #[schemars(rename = "closed")]
    Closed,
    #[serde(rename = "retrying")]
    #[schemars(rename = "retrying")]
    Retrying,
    #[serde(rename = "exhausted")]
    #[schemars(rename = "exhausted")]
    Exhausted,
}

wire_enum_values!(MetricResult {
    Accepted => "accepted",
    Rejected => "rejected",
    Cancelled => "cancelled",
    Expired => "expired",
    Closed => "closed",
    Retrying => "retrying",
    Exhausted => "exhausted"
});

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
pub enum MetricReason {
    #[serde(rename = "none")]
    #[schemars(rename = "none")]
    None,
    #[serde(rename = "policy-denied")]
    #[schemars(rename = "policy-denied")]
    PolicyDenied,
    #[serde(rename = "authentication")]
    #[schemars(rename = "authentication")]
    Authentication,
    #[serde(rename = "transcript-mismatch")]
    #[schemars(rename = "transcript-mismatch")]
    TranscriptMismatch,
    #[serde(rename = "purpose-mismatch")]
    #[schemars(rename = "purpose-mismatch")]
    PurposeMismatch,
    #[serde(rename = "role-mismatch")]
    #[schemars(rename = "role-mismatch")]
    RoleMismatch,
    #[serde(rename = "schema-mismatch")]
    #[schemars(rename = "schema-mismatch")]
    SchemaMismatch,
    #[serde(rename = "limit-mismatch")]
    #[schemars(rename = "limit-mismatch")]
    LimitMismatch,
    #[serde(rename = "channel-binding-mismatch")]
    #[schemars(rename = "channel-binding-mismatch")]
    ChannelBindingMismatch,
    #[serde(rename = "replay")]
    #[schemars(rename = "replay")]
    Replay,
    #[serde(rename = "truncation")]
    #[schemars(rename = "truncation")]
    Truncation,
    #[serde(rename = "malformed")]
    #[schemars(rename = "malformed")]
    Malformed,
    #[serde(rename = "deadline")]
    #[schemars(rename = "deadline")]
    Deadline,
    #[serde(rename = "cancellation")]
    #[schemars(rename = "cancellation")]
    Cancellation,
    #[serde(rename = "backpressure")]
    #[schemars(rename = "backpressure")]
    Backpressure,
    #[serde(rename = "credit-exhausted")]
    #[schemars(rename = "credit-exhausted")]
    CreditExhausted,
    #[serde(rename = "keepalive-timeout")]
    #[schemars(rename = "keepalive-timeout")]
    KeepaliveTimeout,
    #[serde(rename = "transport")]
    #[schemars(rename = "transport")]
    Transport,
    #[serde(rename = "unsupported-version")]
    #[schemars(rename = "unsupported-version")]
    UnsupportedVersion,
    #[serde(rename = "generation-mismatch")]
    #[schemars(rename = "generation-mismatch")]
    GenerationMismatch,
    #[serde(rename = "identity-evidence-mismatch")]
    #[schemars(rename = "identity-evidence-mismatch")]
    IdentityEvidenceMismatch,
    #[serde(rename = "transport-mismatch")]
    #[schemars(rename = "transport-mismatch")]
    TransportMismatch,
    #[serde(rename = "internal-invariant")]
    #[schemars(rename = "internal-invariant")]
    InternalInvariant,
}

wire_enum_values!(MetricReason {
    None => "none",
    PolicyDenied => "policy-denied",
    Authentication => "authentication",
    TranscriptMismatch => "transcript-mismatch",
    PurposeMismatch => "purpose-mismatch",
    RoleMismatch => "role-mismatch",
    SchemaMismatch => "schema-mismatch",
    LimitMismatch => "limit-mismatch",
    ChannelBindingMismatch => "channel-binding-mismatch",
    Replay => "replay",
    Truncation => "truncation",
    Malformed => "malformed",
    Deadline => "deadline",
    Cancellation => "cancellation",
    Backpressure => "backpressure",
    CreditExhausted => "credit-exhausted",
    KeepaliveTimeout => "keepalive-timeout",
    Transport => "transport",
    UnsupportedVersion => "unsupported-version",
    GenerationMismatch => "generation-mismatch",
    IdentityEvidenceMismatch => "identity-evidence-mismatch",
    TransportMismatch => "transport-mismatch",
    InternalInvariant => "internal-invariant"
});

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
pub enum HealthState {
    #[serde(rename = "starting")]
    #[schemars(rename = "starting")]
    Starting,
    #[serde(rename = "healthy")]
    #[schemars(rename = "healthy")]
    Healthy,
    #[serde(rename = "degraded")]
    #[schemars(rename = "degraded")]
    Degraded,
    #[serde(rename = "unavailable")]
    #[schemars(rename = "unavailable")]
    Unavailable,
    #[serde(rename = "failed")]
    #[schemars(rename = "failed")]
    Failed,
}

wire_enum_values!(HealthState {
    Starting => "starting",
    Healthy => "healthy",
    Degraded => "degraded",
    Unavailable => "unavailable",
    Failed => "failed"
});

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
pub enum OperationClass {
    #[serde(rename = "connect")]
    #[schemars(rename = "connect")]
    Connect,
    #[serde(rename = "invoke")]
    #[schemars(rename = "invoke")]
    Invoke,
    #[serde(rename = "open-stream")]
    #[schemars(rename = "open-stream")]
    OpenStream,
    #[serde(rename = "relay")]
    #[schemars(rename = "relay")]
    Relay,
    #[serde(rename = "attach")]
    #[schemars(rename = "attach")]
    Attach,
    #[serde(rename = "cancel")]
    #[schemars(rename = "cancel")]
    Cancel,
    #[serde(rename = "observe")]
    #[schemars(rename = "observe")]
    Observe,
    #[serde(rename = "audit-export")]
    #[schemars(rename = "audit-export")]
    AuditExport,
    #[serde(rename = "support-bundle")]
    #[schemars(rename = "support-bundle")]
    SupportBundle,
}

wire_enum_values!(OperationClass {
    Connect => "connect",
    Invoke => "invoke",
    OpenStream => "open-stream",
    Relay => "relay",
    Attach => "attach",
    Cancel => "cancel",
    Observe => "observe",
    AuditExport => "audit-export",
    SupportBundle => "support-bundle"
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MetricLabels {
    pub transport: TransportClass,
    pub purpose: EndpointPurpose,
    pub service: ServicePackage,
    pub channel_class: ChannelClass,
    pub noise: NoiseProfile,
    pub locality: Locality,
    pub operation_class: OperationClass,
    pub attachment_class: Option<AttachmentKind>,
    pub health_state: HealthState,
    pub result: MetricResult,
    pub reason: MetricReason,
}

fn encode_limits(writer: &mut BinaryWriter, value: LimitProfile) {
    writer.u32(value.handshake_offer_bytes);
    writer.u32(value.protected_ciphertext_bytes);
    writer.u32(value.logical_ttrpc_bytes);
    writer.u32(value.logical_named_stream_bytes);
    writer.u16(value.active_named_streams);
    writer.u32(value.named_stream_queue_bytes);
    writer.u32(value.aggregate_named_stream_queue_bytes);
    writer.u32(value.ttrpc_control_queue_bytes);
    writer.u32(value.session_control_queue_bytes);
    writer.u32(value.keepalive_interval_ms);
    writer.u32(value.keepalive_timeout_ms);
    writer.u32(value.handshake_deadline_ms);
    writer.u32(value.reconnect_deadline_ms);
    writer.u16(value.reconnect_attempts);
    writer.u32(value.reconnect_window_ms);
}

fn decode_limits(reader: &mut BinaryReader<'_>) -> Result<LimitProfile, BinaryError> {
    Ok(LimitProfile {
        handshake_offer_bytes: reader.u32()?,
        protected_ciphertext_bytes: reader.u32()?,
        logical_ttrpc_bytes: reader.u32()?,
        logical_named_stream_bytes: reader.u32()?,
        active_named_streams: reader.u16()?,
        named_stream_queue_bytes: reader.u32()?,
        aggregate_named_stream_queue_bytes: reader.u32()?,
        ttrpc_control_queue_bytes: reader.u32()?,
        session_control_queue_bytes: reader.u32()?,
        keepalive_interval_ms: reader.u32()?,
        keepalive_timeout_ms: reader.u32()?,
        handshake_deadline_ms: reader.u32()?,
        reconnect_deadline_ms: reader.u32()?,
        reconnect_attempts: reader.u16()?,
        reconnect_window_ms: reader.u32()?,
    })
}

fn encode_attachment_policy(writer: &mut BinaryWriter, value: AttachmentPolicy) {
    writer.u8(value.kind.tag());
    writer.u16(value.max_per_packet);
    writer.u16(value.max_per_request);
    writer.u16(value.max_per_operation);
    writer.u16(value.max_per_session);
    writer.u8(u8::from(value.credentials_allowed));
}

fn decode_attachment_policy(
    reader: &mut BinaryReader<'_>,
) -> Result<AttachmentPolicy, BinaryError> {
    Ok(AttachmentPolicy {
        kind: AttachmentPolicyKind::from_tag(reader.u8()?)?,
        max_per_packet: reader.u16()?,
        max_per_request: reader.u16()?,
        max_per_operation: reader.u16()?,
        max_per_session: reader.u16()?,
        credentials_allowed: match reader.u8()? {
            0 => false,
            1 => true,
            _ => return Err(BinaryError::NonCanonical),
        },
    })
}

struct BinaryWriter {
    bytes: Vec<u8>,
}

impl BinaryWriter {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn bytes(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

struct BinaryReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> BinaryReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], BinaryError> {
        let end = self
            .cursor
            .checked_add(len)
            .ok_or(BinaryError::LengthExceeded)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(BinaryError::Truncated)?;
        self.cursor = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, BinaryError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, BinaryError> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("fixed slice"),
        ))
    }

    fn u32(&mut self) -> Result<u32, BinaryError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("fixed slice"),
        ))
    }

    fn u64(&mut self) -> Result<u64, BinaryError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("fixed slice"),
        ))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], BinaryError> {
        Ok(self.take(N)?.try_into().expect("fixed slice"))
    }

    fn finish(self) -> Result<(), BinaryError> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(BinaryError::TrailingBytes)
        }
    }
}
