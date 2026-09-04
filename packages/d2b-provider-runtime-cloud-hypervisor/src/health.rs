//! Authenticated component-session health contract.

use std::fmt;

use async_trait::async_trait;
use d2b_contracts_resource::v3::identity::ReconnectGeneration;
use d2b_contracts_resource::v3::{
    ControllerGeneration, ResourceGeneration, ResourceRef, ResourceUid, SchemaFingerprint,
};

/// Health result for the authenticated component-session session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestSessionHealth {
    /// Process and authenticated probe are ready.
    Ready,
    /// The transport/session is temporarily unavailable.
    Degraded,
    /// Authentication or protocol failed closed.
    Failed,
}

/// Exact non-secret identity and generation commitments for one Guest session.
///
/// Endpoint and seed generations are retained separately so readiness can be
/// checked against the exact controller observation that produced the
/// evidence. The values are bounded identity primitives; no transport
/// locator, credential, or host path is representable.
#[derive(Clone, PartialEq, Eq)]
pub struct GuestSessionEvidenceBinding {
    guest_uid: ResourceUid,
    descriptor_digest: SchemaFingerprint,
    schema_digest: SchemaFingerprint,
    provider_generation: ResourceGeneration,
    controller_generation: ControllerGeneration,
    session_generation: ReconnectGeneration,
    reconnect_generation: ReconnectGeneration,
    endpoint_generation: ResourceGeneration,
    seed_generation: ResourceGeneration,
}

impl GuestSessionEvidenceBinding {
    /// Validate and construct one exact Guest-session evidence binding.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        guest_uid: impl Into<String>,
        descriptor_digest: impl Into<String>,
        schema_digest: impl Into<String>,
        provider_generation: u64,
        controller_generation: u64,
        session_generation: u64,
        reconnect_generation: u64,
        endpoint_generation: u64,
        seed_generation: u64,
    ) -> Result<Self, GuestSessionError> {
        let guest_uid = ResourceUid::parse(guest_uid).map_err(|_| GuestSessionError::Protocol)?;
        let descriptor_digest =
            SchemaFingerprint::parse(descriptor_digest).map_err(|_| GuestSessionError::Protocol)?;
        let schema_digest =
            SchemaFingerprint::parse(schema_digest).map_err(|_| GuestSessionError::Protocol)?;
        let provider_generation = ResourceGeneration::new(provider_generation)
            .map_err(|_| GuestSessionError::Protocol)?;
        let controller_generation = ControllerGeneration::new(controller_generation)
            .map_err(|_| GuestSessionError::Protocol)?;
        let session_generation = ReconnectGeneration::new(session_generation)
            .map_err(|_| GuestSessionError::Protocol)?;
        let reconnect_generation = ReconnectGeneration::new(reconnect_generation)
            .map_err(|_| GuestSessionError::Protocol)?;
        let endpoint_generation = ResourceGeneration::new(endpoint_generation)
            .map_err(|_| GuestSessionError::Protocol)?;
        let seed_generation =
            ResourceGeneration::new(seed_generation).map_err(|_| GuestSessionError::Protocol)?;
        Ok(Self {
            guest_uid,
            descriptor_digest,
            schema_digest,
            provider_generation,
            controller_generation,
            session_generation,
            reconnect_generation,
            endpoint_generation,
            seed_generation,
        })
    }

    /// Borrow the exact store-assigned Guest UID.
    pub const fn guest_uid(&self) -> &ResourceUid {
        &self.guest_uid
    }

    /// Borrow the signed setup descriptor digest.
    pub const fn descriptor_digest(&self) -> &SchemaFingerprint {
        &self.descriptor_digest
    }

    /// Borrow the target-local seed schema digest.
    pub const fn schema_digest(&self) -> &SchemaFingerprint {
        &self.schema_digest
    }

    /// Return the Provider generation.
    pub const fn provider_generation(&self) -> u64 {
        self.provider_generation.get()
    }

    /// Return the controller generation.
    pub const fn controller_generation(&self) -> u64 {
        self.controller_generation.get()
    }

    /// Return the authenticated session generation.
    pub const fn session_generation(&self) -> u64 {
        self.session_generation.get()
    }

    /// Return the authenticated reconnect generation.
    pub const fn reconnect_generation(&self) -> u64 {
        self.reconnect_generation.get()
    }

    /// Return the Endpoint readiness generation.
    pub const fn endpoint_generation(&self) -> u64 {
        self.endpoint_generation.get()
    }

    /// Return the guest seed readiness generation.
    pub const fn seed_generation(&self) -> u64 {
        self.seed_generation.get()
    }

    /// Validate exact identity and generation equality against an expectation.
    ///
    /// A lower session or reconnect generation is stale and cannot be
    /// accepted as a current session. All other commitments must match
    /// exactly, including Endpoint and seed generations.
    pub fn validate_against(
        &self,
        expected: &GuestSessionEvidenceBinding,
    ) -> Result<(), GuestSessionError> {
        if self.session_generation < expected.session_generation
            || self.reconnect_generation < expected.reconnect_generation
        {
            return Err(GuestSessionError::Disconnected);
        }
        if self.guest_uid != expected.guest_uid
            || self.descriptor_digest != expected.descriptor_digest
            || self.schema_digest != expected.schema_digest
            || self.provider_generation != expected.provider_generation
            || self.controller_generation != expected.controller_generation
            || self.session_generation != expected.session_generation
            || self.reconnect_generation != expected.reconnect_generation
            || self.endpoint_generation != expected.endpoint_generation
            || self.seed_generation != expected.seed_generation
        {
            return Err(GuestSessionError::WrongIdentity);
        }
        Ok(())
    }
}

impl fmt::Debug for GuestSessionEvidenceBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GuestSessionEvidenceBinding")
            .field("guest_uid", &"<redacted>")
            .field("descriptor_digest", &"<redacted>")
            .field("schema_digest", &"<redacted>")
            .field("provider_generation", &self.provider_generation())
            .field("controller_generation", &self.controller_generation())
            .field("session_generation", &self.session_generation())
            .field("reconnect_generation", &self.reconnect_generation())
            .field("endpoint_generation", &self.endpoint_generation())
            .field("seed_generation", &self.seed_generation())
            .finish()
    }
}

/// Redacted evidence produced by an authenticated Guest ComponentSession.
///
/// The evidence binds the Guest, boot identity, descriptor and schema
/// commitments, generations, capabilities, and readiness together.
#[derive(Clone, PartialEq, Eq)]
pub struct GuestSessionEvidence {
    guest_ref: Option<ResourceRef>,
    boot_identity_digest: Option<String>,
    reconnect_generation: Option<u64>,
    capabilities: Vec<String>,
    controller_ready: bool,
    endpoint_ready: bool,
    seed_ready: bool,
    binding: Option<GuestSessionEvidenceBinding>,
    health: GuestSessionHealth,
}

impl GuestSessionEvidence {
    /// Construct current evidence from an authenticated ComponentSession.
    pub fn current(
        guest_ref: ResourceRef,
        boot_identity_digest: impl Into<String>,
        reconnect_generation: u64,
        capabilities: impl IntoIterator<Item = String>,
        controller_ready: bool,
        endpoint_ready: bool,
    ) -> Result<Self, GuestSessionError> {
        let boot_identity_digest = boot_identity_digest.into();
        if guest_ref.resource_type().as_str() != "Guest"
            || guest_ref.name().as_str().is_empty()
            || reconnect_generation == 0
            || !valid_digest(&boot_identity_digest)
        {
            return Err(GuestSessionError::AuthenticationFailed);
        }
        let capabilities = validate_capabilities(capabilities)?;
        let health = if controller_ready && endpoint_ready {
            GuestSessionHealth::Ready
        } else {
            GuestSessionHealth::Degraded
        };
        Ok(Self {
            guest_ref: Some(guest_ref),
            boot_identity_digest: Some(boot_identity_digest),
            reconnect_generation: Some(reconnect_generation),
            capabilities,
            controller_ready,
            endpoint_ready,
            seed_ready: false,
            binding: None,
            health,
        })
    }

    /// Construct current evidence with exact Guest, descriptor, generation,
    /// Endpoint, and seed commitments.
    pub fn current_bound(
        guest_ref: ResourceRef,
        boot_identity_digest: impl Into<String>,
        capabilities: impl IntoIterator<Item = String>,
        controller_ready: bool,
        endpoint_ready: bool,
        seed_ready: bool,
        binding: GuestSessionEvidenceBinding,
    ) -> Result<Self, GuestSessionError> {
        let reconnect_generation = binding.reconnect_generation();
        let mut evidence = Self::current(
            guest_ref,
            boot_identity_digest,
            reconnect_generation,
            capabilities,
            controller_ready,
            endpoint_ready,
        )?;
        evidence.seed_ready = seed_ready;
        evidence.binding = Some(binding);
        evidence.health = if controller_ready && endpoint_ready && seed_ready {
            GuestSessionHealth::Ready
        } else {
            GuestSessionHealth::Degraded
        };
        Ok(evidence)
    }

    /// Construct a stale evidence snapshot after a disconnected session.
    pub fn stale(
        guest_ref: ResourceRef,
        reconnect_generation: u64,
    ) -> Result<Self, GuestSessionError> {
        let mut evidence = Self::current(
            guest_ref,
            "sha256:".to_owned() + &"0".repeat(64),
            reconnect_generation,
            [],
            false,
            false,
        )?;
        evidence.health = GuestSessionHealth::Degraded;
        Ok(evidence)
    }

    /// Return the current health projection.
    pub const fn health(&self) -> GuestSessionHealth {
        self.health
    }

    /// Return the bound Guest identity, when available.
    pub fn guest_ref(&self) -> Option<&ResourceRef> {
        self.guest_ref.as_ref()
    }

    /// Return the redacted boot-identity commitment, when available.
    pub fn boot_identity_digest(&self) -> Option<&str> {
        self.boot_identity_digest.as_deref()
    }

    /// Return the authenticated reconnect generation, when available.
    pub const fn reconnect_generation(&self) -> Option<u64> {
        self.reconnect_generation
    }

    /// Return the bounded capability names.
    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    /// Return whether the target-local controller reported readiness.
    pub const fn controller_ready(&self) -> bool {
        self.controller_ready
    }

    /// Return whether the authenticated Endpoint reported readiness.
    pub const fn endpoint_ready(&self) -> bool {
        self.endpoint_ready
    }

    /// Return whether the target-local seed set reported readiness.
    pub const fn seed_ready(&self) -> bool {
        self.seed_ready
    }

    /// Borrow the exact non-secret evidence binding, when available.
    pub fn binding(&self) -> Option<&GuestSessionEvidenceBinding> {
        self.binding.as_ref()
    }

    /// Borrow the exact Guest UID, when available.
    pub fn guest_uid(&self) -> Option<&ResourceUid> {
        self.binding
            .as_ref()
            .map(GuestSessionEvidenceBinding::guest_uid)
    }

    /// Borrow the exact setup descriptor digest, when available.
    pub fn descriptor_digest(&self) -> Option<&SchemaFingerprint> {
        self.binding
            .as_ref()
            .map(GuestSessionEvidenceBinding::descriptor_digest)
    }

    /// Borrow the exact target-local schema digest, when available.
    pub fn schema_digest(&self) -> Option<&SchemaFingerprint> {
        self.binding
            .as_ref()
            .map(GuestSessionEvidenceBinding::schema_digest)
    }

    /// Return the Provider generation, when available.
    pub fn provider_generation(&self) -> Option<u64> {
        self.binding
            .as_ref()
            .map(GuestSessionEvidenceBinding::provider_generation)
    }

    /// Return the controller generation, when available.
    pub fn controller_generation(&self) -> Option<u64> {
        self.binding
            .as_ref()
            .map(GuestSessionEvidenceBinding::controller_generation)
    }

    /// Return the session generation, when available.
    pub fn session_generation(&self) -> Option<u64> {
        self.binding
            .as_ref()
            .map(GuestSessionEvidenceBinding::session_generation)
    }

    /// Return the Endpoint readiness generation, when available.
    pub fn endpoint_generation(&self) -> Option<u64> {
        self.binding
            .as_ref()
            .map(GuestSessionEvidenceBinding::endpoint_generation)
    }

    /// Return the guest seed readiness generation, when available.
    pub fn seed_generation(&self) -> Option<u64> {
        self.binding
            .as_ref()
            .map(GuestSessionEvidenceBinding::seed_generation)
    }

    /// Validate this evidence against one exact expected binding.
    pub fn validate_against(
        &self,
        expected: &GuestSessionEvidenceBinding,
    ) -> Result<(), GuestSessionError> {
        let binding = self
            .binding
            .as_ref()
            .ok_or(GuestSessionError::WrongIdentity)?;
        binding.validate_against(expected)?;
        if self.health != GuestSessionHealth::Ready {
            return Err(GuestSessionError::Disconnected);
        }
        Ok(())
    }

    /// Return whether this evidence is Ready for one exact expected binding.
    pub fn ready_for(&self, expected: &GuestSessionEvidenceBinding) -> bool {
        self.validate_against(expected).is_ok()
    }

    pub(crate) fn failed() -> Self {
        Self {
            guest_ref: None,
            boot_identity_digest: None,
            reconnect_generation: None,
            capabilities: Vec::new(),
            controller_ready: false,
            endpoint_ready: false,
            seed_ready: false,
            binding: None,
            health: GuestSessionHealth::Failed,
        }
    }
}

impl fmt::Debug for GuestSessionEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GuestSessionEvidence")
            .field("guest_ref", &"<redacted>")
            .field("boot_identity_digest", &"<redacted>")
            .field("reconnect_generation", &self.reconnect_generation)
            .field("capabilities", &self.capabilities.len())
            .field("controller_ready", &self.controller_ready)
            .field("endpoint_ready", &self.endpoint_ready)
            .field("seed_ready", &self.seed_ready)
            .field("binding", &self.binding)
            .field("health", &self.health)
            .finish()
    }
}

fn valid_digest(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_capabilities(
    capabilities: impl IntoIterator<Item = String>,
) -> Result<Vec<String>, GuestSessionError> {
    let capabilities = capabilities.into_iter().collect::<Vec<_>>();
    if capabilities.len() > 64
        || capabilities.iter().any(|capability| {
            capability.is_empty()
                || capability.len() > 128
                || !capability.is_ascii()
                || capability.chars().any(char::is_whitespace)
        })
    {
        return Err(GuestSessionError::Protocol);
    }
    Ok(capabilities)
}

/// Stable component-session health failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestSessionError {
    /// Wrong component-session identity or CID.
    WrongIdentity,
    /// Signature or replay verification failed.
    AuthenticationFailed,
    /// Probe exceeded its deadline.
    Timeout,
    /// The wire protocol was malformed.
    Protocol,
    /// The endpoint disconnected.
    Disconnected,
}

impl GuestSessionError {
    /// Return the stable error code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::WrongIdentity => "component-session-wrong-identity",
            Self::AuthenticationFailed => "component-session-authentication-failed",
            Self::Timeout => "component-session-timeout",
            Self::Protocol => "component-session-protocol",
            Self::Disconnected => "component-session-disconnected",
        }
    }
}

/// Authenticated Guest ComponentSession evidence probe.
#[async_trait]
pub trait GuestSessionEvidenceProbe: Send + Sync {
    /// Observe the current authenticated Guest session and its capabilities.
    async fn observe(
        &self,
        expected_cid: u32,
        deadline_ms: u32,
    ) -> Result<GuestSessionEvidence, GuestSessionError>;

    /// Close the authenticated Guest session before VMM teardown.
    async fn close(&self, expected_cid: u32) -> Result<(), GuestSessionError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use d2b_contracts_resource::v3::ResourceUid;

    const GUEST_UID: &str = "123e4567-e89b-42d3-a456-426614174000";
    const BOOT_DIGEST: &str =
        "sha256:0000000000000000000000000000000000000000000000000000000000000001";
    const DESCRIPTOR_DIGEST: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const SCHEMA_DIGEST: &str =
        "sha256:2222222222222222222222222222222222222222222222222222222222222222";

    fn guest_ref() -> ResourceRef {
        ResourceRef::parse("Guest/test").expect("Guest ref")
    }

    fn binding(generation: u64) -> GuestSessionEvidenceBinding {
        GuestSessionEvidenceBinding::new(
            GUEST_UID,
            DESCRIPTOR_DIGEST,
            SCHEMA_DIGEST,
            7,
            generation,
            generation,
            generation,
            generation,
            generation,
        )
        .expect("valid evidence binding")
    }

    fn bound_evidence(generation: u64, seed_ready: bool) -> GuestSessionEvidence {
        GuestSessionEvidence::current_bound(
            guest_ref(),
            BOOT_DIGEST,
            vec!["resource-read".to_owned()],
            true,
            true,
            seed_ready,
            binding(generation),
        )
        .expect("valid bound evidence")
    }

    #[test]
    fn bound_evidence_requires_endpoint_and_seed_readiness_for_ready() {
        assert_eq!(bound_evidence(3, true).health(), GuestSessionHealth::Ready);
        let pending = bound_evidence(3, false);
        assert_eq!(pending.health(), GuestSessionHealth::Degraded);
        assert!(!pending.ready_for(&binding(3)));
        let spawned_only = GuestSessionEvidence::current_bound(
            guest_ref(),
            BOOT_DIGEST,
            vec!["resource-read".to_owned()],
            false,
            true,
            true,
            binding(3),
        )
        .expect("spawned process without VMM readiness is representable");
        assert_eq!(spawned_only.health(), GuestSessionHealth::Degraded);
        assert!(!spawned_only.ready_for(&binding(3)));
    }

    #[test]
    fn bound_evidence_exposes_only_exact_bounded_commitments() {
        let evidence = bound_evidence(3, true);
        assert_eq!(
            evidence.guest_uid().map(ResourceUid::as_str),
            Some(GUEST_UID)
        );
        assert_eq!(
            evidence.descriptor_digest().map(SchemaFingerprint::as_str),
            Some(DESCRIPTOR_DIGEST)
        );
        assert_eq!(
            evidence.schema_digest().map(SchemaFingerprint::as_str),
            Some(SCHEMA_DIGEST)
        );
        assert_eq!(evidence.provider_generation(), Some(7));
        assert_eq!(evidence.controller_generation(), Some(3));
        assert_eq!(evidence.session_generation(), Some(3));
        assert_eq!(evidence.reconnect_generation(), Some(3));
        assert_eq!(evidence.endpoint_generation(), Some(3));
        assert_eq!(evidence.seed_generation(), Some(3));
        assert!(evidence.seed_ready());
    }

    #[test]
    fn binding_rejects_zero_and_malformed_generations() {
        assert_eq!(
            GuestSessionEvidenceBinding::new(
                GUEST_UID,
                DESCRIPTOR_DIGEST,
                SCHEMA_DIGEST,
                0,
                3,
                3,
                3,
                3,
                3,
            ),
            Err(GuestSessionError::Protocol)
        );
        assert_eq!(
            GuestSessionEvidenceBinding::new(
                "malformed",
                DESCRIPTOR_DIGEST,
                SCHEMA_DIGEST,
                7,
                3,
                3,
                3,
                3,
                3,
            ),
            Err(GuestSessionError::Protocol)
        );
        assert_eq!(
            GuestSessionEvidenceBinding::new(
                GUEST_UID,
                "malformed",
                SCHEMA_DIGEST,
                7,
                3,
                3,
                3,
                3,
                3,
            ),
            Err(GuestSessionError::Protocol)
        );
        assert_eq!(
            GuestSessionEvidenceBinding::new(
                GUEST_UID,
                DESCRIPTOR_DIGEST,
                "malformed",
                7,
                3,
                3,
                3,
                3,
                3,
            ),
            Err(GuestSessionError::Protocol)
        );
        let expected = binding(3);
        let mismatched = GuestSessionEvidenceBinding::new(
            GUEST_UID,
            DESCRIPTOR_DIGEST,
            SCHEMA_DIGEST,
            7,
            4,
            3,
            3,
            3,
            3,
        )
        .expect("well-formed mismatched binding");
        assert_eq!(
            mismatched.validate_against(&expected),
            Err(GuestSessionError::WrongIdentity)
        );
    }

    #[test]
    fn stale_or_mismatched_evidence_fails_closed_against_expected_binding() {
        let expected = binding(4);
        let stale = bound_evidence(3, true);
        assert_eq!(
            stale.validate_against(&expected),
            Err(GuestSessionError::Disconnected)
        );
        assert!(!stale.ready_for(&expected));

        let mismatched = GuestSessionEvidenceBinding::new(
            GUEST_UID,
            DESCRIPTOR_DIGEST,
            "sha256:3333333333333333333333333333333333333333333333333333333333333333",
            7,
            4,
            4,
            4,
            4,
            4,
        )
        .expect("mismatched schema binding");
        let evidence = GuestSessionEvidence::current_bound(
            guest_ref(),
            BOOT_DIGEST,
            [],
            true,
            true,
            true,
            mismatched,
        )
        .expect("well-formed mismatched evidence");
        assert_eq!(
            evidence.validate_against(&expected),
            Err(GuestSessionError::WrongIdentity)
        );
        assert!(!evidence.ready_for(&expected));

        let mismatched_guest = GuestSessionEvidenceBinding::new(
            "223e4567-e89b-42d3-a456-426614174001",
            DESCRIPTOR_DIGEST,
            SCHEMA_DIGEST,
            7,
            4,
            4,
            4,
            4,
            4,
        )
        .expect("mismatched Guest binding");
        let evidence = GuestSessionEvidence::current_bound(
            guest_ref(),
            BOOT_DIGEST,
            [],
            true,
            true,
            true,
            mismatched_guest,
        )
        .expect("well-formed mismatched Guest evidence");
        assert_eq!(
            evidence.validate_against(&expected),
            Err(GuestSessionError::WrongIdentity)
        );
    }

    #[test]
    fn capabilities_remain_bounded_and_legacy_constructors_stay_compatible() {
        let too_many = (0..=64).map(|index| format!("capability-{index}"));
        assert_eq!(
            GuestSessionEvidence::current(guest_ref(), BOOT_DIGEST, 1, too_many, true, true,),
            Err(GuestSessionError::Protocol)
        );
        assert_eq!(
            GuestSessionEvidence::current(
                guest_ref(),
                BOOT_DIGEST,
                1,
                [format!("capability-{}", "x".repeat(129))],
                true,
                true,
            ),
            Err(GuestSessionError::Protocol)
        );
        assert_eq!(
            GuestSessionEvidence::current(guest_ref(), BOOT_DIGEST, 1, [], true, true)
                .expect("legacy evidence")
                .health(),
            GuestSessionHealth::Ready
        );
        assert_eq!(
            GuestSessionEvidence::stale(guest_ref(), 1)
                .expect("legacy stale evidence")
                .health(),
            GuestSessionHealth::Degraded
        );
    }

    #[test]
    fn debug_output_redacts_all_identity_payloads() {
        let evidence = bound_evidence(3, true);
        let debug = format!("{evidence:?}");
        assert!(!debug.contains(GUEST_UID));
        assert!(!debug.contains(BOOT_DIGEST));
        assert!(!debug.contains(DESCRIPTOR_DIGEST));
        assert!(!debug.contains(SCHEMA_DIGEST));
        assert!(!debug.contains("/run/d2b"));
        assert!(!debug.contains("credential"));
    }
}
