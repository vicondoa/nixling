//! Opaque USBIP firewall and relay effect boundary.

use d2b_contracts_resource::v3::{ResourceGeneration, ResourceUid};

/// Closed direction of one ownership-scoped firewall projection mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallProjectionAction {
    /// Install or converge the resolved projection.
    Apply,
    /// Remove only the resolved projection.
    Remove,
}

impl FirewallProjectionAction {
    /// Parse the exact semantic action spelling.
    pub fn parse(value: &str) -> Result<Self, UsbipEffectError> {
        match value {
            "Apply" => Ok(Self::Apply),
            "Remove" => Ok(Self::Remove),
            _ => Err(UsbipEffectError::UnknownProjectionAction),
        }
    }

    /// Return the exact semantic action spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Apply => "Apply",
            Self::Remove => "Remove",
        }
    }
}

/// Expected resource generations for one projection mutation.
#[derive(Clone, PartialEq, Eq)]
pub struct FirewallGenerationFence {
    network_generation: ResourceGeneration,
    service_generation: ResourceGeneration,
}

impl FirewallGenerationFence {
    /// Bind an effect to the exact Network and USB Service generations read by
    /// the controller.
    pub const fn new(
        network_generation: ResourceGeneration,
        service_generation: ResourceGeneration,
    ) -> Self {
        Self {
            network_generation,
            service_generation,
        }
    }

    /// Return the expected Network generation.
    pub const fn network_generation(&self) -> ResourceGeneration {
        self.network_generation
    }

    /// Return the expected USB Service generation.
    pub const fn service_generation(&self) -> ResourceGeneration {
        self.service_generation
    }
}

impl core::fmt::Debug for FirewallGenerationFence {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FirewallGenerationFence(<redacted>)")
    }
}

/// Opaque exact per-Network/per-device projection mutation.
///
/// Core resolves these resource identities through its trusted private bundle.
/// No rule text, ownership marker, interface, address, port, or bus id crosses
/// this boundary.
#[derive(Clone, PartialEq, Eq)]
pub struct FirewallProjectionIntent {
    device_uid: ResourceUid,
    network_uid: ResourceUid,
    action: FirewallProjectionAction,
    expected: FirewallGenerationFence,
}

impl FirewallProjectionIntent {
    /// Construct one exact opaque projection mutation.
    pub const fn new(
        device_uid: ResourceUid,
        network_uid: ResourceUid,
        action: FirewallProjectionAction,
        expected: FirewallGenerationFence,
    ) -> Self {
        Self {
            device_uid,
            network_uid,
            action,
            expected,
        }
    }

    /// Borrow the opaque Device identity for the Core adapter.
    pub const fn device_uid(&self) -> &ResourceUid {
        &self.device_uid
    }

    /// Borrow the opaque Network identity for the Core adapter.
    pub const fn network_uid(&self) -> &ResourceUid {
        &self.network_uid
    }

    /// Return the requested closed action.
    pub const fn action(&self) -> FirewallProjectionAction {
        self.action
    }

    /// Borrow the resource-generation fence.
    pub const fn expected(&self) -> &FirewallGenerationFence {
        &self.expected
    }
}

impl core::fmt::Debug for FirewallProjectionIntent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FirewallProjectionIntent")
            .field("action", &self.action)
            .field("expected", &self.expected)
            .finish()
    }
}

/// Opaque adapter-issued token proving ownership of one applied projection.
#[derive(Clone, PartialEq, Eq)]
pub struct FirewallToken([u8; 16]);

impl FirewallToken {
    /// Construct a token at the trusted effect adapter boundary.
    pub const fn from_adapter(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

impl core::fmt::Debug for FirewallToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FirewallToken(<redacted>)")
    }
}

/// Opaque ownership-scoped digest returned by the effect adapter.
#[derive(Clone, PartialEq, Eq)]
pub struct FirewallDigest([u8; 32]);

impl FirewallDigest {
    /// Construct a digest at the trusted effect adapter boundary.
    pub const fn from_adapter(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl core::fmt::Debug for FirewallDigest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FirewallDigest(<redacted>)")
    }
}

/// Closed successful effect result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallConfirmationKind {
    /// The projection was installed or already matched desired state.
    Applied,
    /// The owned projection was removed.
    Removed,
    /// Ownership was validated and the projection was already absent.
    ValidatedAbsent,
}

/// Successful, ownership-scoped firewall confirmation.
#[derive(Clone, PartialEq, Eq)]
pub struct FirewallConfirmation {
    kind: FirewallConfirmationKind,
    token: Option<FirewallToken>,
    digest: Option<FirewallDigest>,
}

impl FirewallConfirmation {
    /// Confirm an applied projection and return the retained token and digest.
    pub const fn applied(token: FirewallToken, digest: FirewallDigest) -> Self {
        Self {
            kind: FirewallConfirmationKind::Applied,
            token: Some(token),
            digest: Some(digest),
        }
    }

    /// Confirm removal of the exact owned projection.
    pub const fn removed() -> Self {
        Self {
            kind: FirewallConfirmationKind::Removed,
            token: None,
            digest: None,
        }
    }

    /// Confirm idempotent, ownership-validated absence.
    pub const fn validated_absent() -> Self {
        Self {
            kind: FirewallConfirmationKind::ValidatedAbsent,
            token: None,
            digest: None,
        }
    }

    /// Return the closed result kind.
    pub const fn kind(&self) -> FirewallConfirmationKind {
        self.kind
    }

    /// Consume the confirmation into an applied token and digest.
    pub fn into_applied(self) -> Option<(FirewallToken, FirewallDigest)> {
        match (self.kind, self.token, self.digest) {
            (FirewallConfirmationKind::Applied, Some(token), Some(digest)) => Some((token, digest)),
            _ => None,
        }
    }
}

impl core::fmt::Debug for FirewallConfirmation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FirewallConfirmation")
            .field("kind", &self.kind)
            .field("has_token", &self.token.is_some())
            .field("has_digest", &self.digest.is_some())
            .finish()
    }
}

/// Ownership-scoped firewall observation.
#[derive(Clone, PartialEq, Eq)]
pub struct FirewallObservation {
    matches_expected: bool,
    digest: FirewallDigest,
}

impl FirewallObservation {
    /// Construct one projection-only observation.
    pub const fn new(matches_expected: bool, digest: FirewallDigest) -> Self {
        Self {
            matches_expected,
            digest,
        }
    }

    /// Whether the exact USBIP ownership projection matches desired state.
    pub const fn matches_expected(&self) -> bool {
        self.matches_expected
    }

    /// Borrow the opaque projection digest.
    pub const fn digest(&self) -> &FirewallDigest {
        &self.digest
    }
}

impl core::fmt::Debug for FirewallObservation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FirewallObservation")
            .field("matches_expected", &self.matches_expected)
            .field("digest", &self.digest)
            .finish()
    }
}

/// Opaque lease on the Core-derived per-Network relay Endpoint authority.
#[derive(Clone, PartialEq, Eq)]
pub struct RelayAuthorityLease([u8; 16]);

impl RelayAuthorityLease {
    /// Construct a lease at the trusted Core authority adapter boundary.
    pub const fn from_adapter(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

impl core::fmt::Debug for RelayAuthorityLease {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RelayAuthorityLease(<redacted>)")
    }
}

/// Closed effect failures with no caller-controlled payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbipEffectError {
    /// Device and Network do not belong to one Zone.
    WrongZone,
    /// The dependency was not Ready.
    NetworkNotReady,
    /// The dependency assignment no longer matches this controller.
    StaleAssignment,
    /// A second owner attempted to create the Network relay authority.
    RelayAuthorityConflict,
    /// Effect may be retried with all authority retained.
    Transient,
    /// The installed generation differs; dependencies must be refreshed.
    FirewallGenerationMismatch,
    /// A foreign ownership marker blocked safe mutation.
    FirewallForeignConflict,
    /// The effect adapter rejected the request terminally.
    EffectRejected,
    /// A caller attempted a value outside the closed action set.
    UnknownProjectionAction,
}

impl UsbipEffectError {
    /// Return the stable closed error code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::WrongZone => "wrong-zone",
            Self::NetworkNotReady => "network-not-ready",
            Self::StaleAssignment => "usbip-assignment-stale",
            Self::RelayAuthorityConflict => "usbip-network-relay-authority-conflict",
            Self::Transient => "transient",
            Self::FirewallGenerationMismatch => "firewall-generation-mismatch",
            Self::FirewallForeignConflict => "firewall-foreign-conflict",
            Self::EffectRejected => "effect-rejected",
            Self::UnknownProjectionAction => "unknown-projection-action",
        }
    }
}

impl core::fmt::Display for UsbipEffectError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for UsbipEffectError {}

/// Injected semantic boundary implemented by Core.
///
/// Implementations privately resolve the shared projection request, installed
/// generation, ownership marker, host module, listener, and firewall intent.
/// The Provider receives no broker DTO or host identity.
pub trait UsbipEffectPort {
    /// Acquire or share the one multiplexed relay Endpoint authority for a
    /// Network. A second owner fails before listener or firewall effects.
    fn acquire_relay(
        &mut self,
        network_uid: &ResourceUid,
    ) -> Result<RelayAuthorityLease, UsbipEffectError>;

    /// Apply or remove the exact resolved ownership projection.
    fn mutate_firewall(
        &mut self,
        intent: &FirewallProjectionIntent,
        retained_token: Option<&FirewallToken>,
    ) -> Result<FirewallConfirmation, UsbipEffectError>;

    /// Observe only the exact USBIP projection represented by the token.
    fn observe_firewall(
        &mut self,
        intent: &FirewallProjectionIntent,
        token: &FirewallToken,
    ) -> Result<FirewallObservation, UsbipEffectError>;

    /// Release a relay authority after the last projection removal is confirmed.
    fn release_relay(&mut self, lease: RelayAuthorityLease) -> Result<(), UsbipEffectError>;
}
