//! Guest-bound proof-of-possession and replay-safe ComponentSession admission.

use crate::limits::MAX_REPLAY_ENTRIES;
use d2b_contracts_resource::v3::{ResourceRef, ZoneId};
use ring::hmac;
use std::{collections::HashSet, fmt};

const TAG_BYTES: usize = 32;

/// Opaque kernel-observed peer CID.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerCid(u32);

impl PeerCid {
    /// Construct a peer CID at the trusted Core adapter boundary.
    pub const fn from_core(value: u32) -> Option<Self> {
        if value == 0 { None } else { Some(Self(value)) }
    }

    pub(crate) fn matches(self, other: Self) -> bool {
        self == other
    }
}

impl fmt::Debug for PeerCid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PeerCid(<redacted>)")
    }
}

/// ComponentSession signing key held by the trusted Core adapter.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionKey([u8; 32]);

impl SessionKey {
    /// Construct a key at the trusted Core adapter boundary.
    pub const fn from_core(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl fmt::Debug for SessionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionKey(<redacted>)")
    }
}

/// Exact Guest and Zone identity bound to one transport session.
#[derive(Clone, PartialEq, Eq)]
pub struct GuestIdentity {
    guest: ResourceRef,
    zone: ZoneId,
    cid: PeerCid,
    boot_id: String,
}

impl GuestIdentity {
    /// Construct one exact Guest identity.
    pub fn new(
        guest: ResourceRef,
        zone: ZoneId,
        cid: PeerCid,
        boot_id: impl Into<String>,
    ) -> Result<Self, SessionRejectReason> {
        if guest.resource_type().as_str() != "Guest" {
            return Err(SessionRejectReason::GuestMismatch);
        }
        let boot_id = boot_id.into();
        if boot_id.is_empty() || boot_id.len() > 128 {
            return Err(SessionRejectReason::MalformedProof);
        }
        Ok(Self {
            guest,
            zone,
            cid,
            boot_id,
        })
    }

    /// Borrow the exact Guest reference.
    pub const fn guest(&self) -> &ResourceRef {
        &self.guest
    }

    /// Borrow the exact Zone identity.
    pub const fn zone(&self) -> &ZoneId {
        &self.zone
    }
}

impl fmt::Debug for GuestIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GuestIdentity(<redacted>)")
    }
}

/// Proof presented by a Guest ComponentSession peer.
#[derive(Clone)]
pub struct SessionProof {
    identity: GuestIdentity,
    nonce: [u8; 32],
    generation: u64,
    tag: [u8; TAG_BYTES],
}

impl SessionProof {
    /// Sign one exact Guest, Zone, CID, boot, nonce, and generation tuple.
    pub fn sign(
        key: &SessionKey,
        identity: &GuestIdentity,
        nonce: [u8; 32],
        generation: u64,
    ) -> Self {
        let tag = sign_tag(key, identity, &nonce, generation);
        Self {
            identity: identity.clone(),
            nonce,
            generation,
            tag,
        }
    }

    fn tag(&self) -> &[u8; TAG_BYTES] {
        &self.tag
    }
}

impl fmt::Debug for SessionProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionProof(<redacted>)")
    }
}

/// Stable proof rejection reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRejectReason {
    /// The peer CID is not the one bound to this Guest.
    CidMismatch,
    /// The proof names another Guest.
    GuestMismatch,
    /// The proof names another Zone.
    ZoneMismatch,
    /// The proof's boot or generation is stale.
    StaleSignature,
    /// The nonce was already admitted.
    Replay,
    /// The proof shape is invalid.
    MalformedProof,
    /// The signature did not verify.
    SignatureInvalid,
    /// The authority has no remaining admission capacity.
    AuthorityUnavailable,
}

impl SessionRejectReason {
    /// Return the stable error code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::CidMismatch => "cid-mismatch",
            Self::GuestMismatch => "guest-mismatch",
            Self::ZoneMismatch => "zone-mismatch",
            Self::StaleSignature => "stale-signature",
            Self::Replay => "replay",
            Self::MalformedProof => "malformed-proof",
            Self::SignatureInvalid => "signature-invalid",
            Self::AuthorityUnavailable => "session-authority-unavailable",
        }
    }
}

impl fmt::Display for SessionRejectReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for SessionRejectReason {}

/// State of one admitted transport session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// The authenticated session is ready for transport operations.
    Ready,
    /// The peer has disconnected and the session is no longer usable.
    Disconnected,
}

/// Single-use authenticated session authority.
pub struct ReadySession {
    identity: GuestIdentity,
    generation: u64,
    state: SessionState,
}

impl ReadySession {
    /// Return the current session state.
    pub const fn state(&self) -> SessionState {
        self.state
    }

    /// Return the Core-owned reconnect generation for this session.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Check that a request remains bound to this Guest and Zone.
    pub fn matches(&self, identity: &GuestIdentity) -> bool {
        self.state == SessionState::Ready
            && self.identity.guest == identity.guest
            && self.identity.zone == identity.zone
            && self.identity.cid.matches(identity.cid)
            && self.identity.boot_id == identity.boot_id
    }

    /// Borrow the exact session Guest identity.
    pub const fn identity(&self) -> &GuestIdentity {
        &self.identity
    }

    /// Consume the authority on disconnect.
    pub fn disconnect(mut self) -> SessionState {
        self.state = SessionState::Disconnected;
        self.state
    }
}

impl fmt::Debug for ReadySession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReadySession")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// Replay-safe authority for one exact Guest and Zone.
pub struct SessionAuthority {
    expected: GuestIdentity,
    key: SessionKey,
    generation: u64,
    replayed: HashSet<[u8; 32]>,
}

impl SessionAuthority {
    /// Construct an authority with one current boot/generation binding.
    pub fn new(expected: GuestIdentity, key: SessionKey, generation: u64) -> Self {
        Self {
            expected,
            key,
            generation,
            replayed: HashSet::new(),
        }
    }

    /// Authenticate one proof and consume its nonce.
    pub fn authenticate(
        &mut self,
        observed_cid: PeerCid,
        proof: SessionProof,
    ) -> Result<ReadySession, SessionRejectReason> {
        if !self.expected.cid.matches(observed_cid) || !observed_cid.matches(proof.identity.cid) {
            return Err(SessionRejectReason::CidMismatch);
        }
        if self.expected.guest != proof.identity.guest {
            return Err(SessionRejectReason::GuestMismatch);
        }
        if self.expected.zone != proof.identity.zone {
            return Err(SessionRejectReason::ZoneMismatch);
        }
        if self.generation == 0
            || proof.generation == 0
            || self.expected.boot_id != proof.identity.boot_id
            || proof.generation != self.generation
        {
            return Err(SessionRejectReason::StaleSignature);
        }
        if self.replayed.contains(&proof.nonce) {
            return Err(SessionRejectReason::Replay);
        }
        if self.replayed.len() >= MAX_REPLAY_ENTRIES {
            return Err(SessionRejectReason::AuthorityUnavailable);
        }
        let expected_tag = sign_tag(&self.key, &proof.identity, &proof.nonce, proof.generation);
        if !constant_time_equal(&expected_tag, proof.tag()) {
            return Err(SessionRejectReason::SignatureInvalid);
        }
        self.replayed.insert(proof.nonce);
        Ok(ReadySession {
            identity: self.expected.clone(),
            generation: proof.generation,
            state: SessionState::Ready,
        })
    }
}

impl fmt::Debug for SessionAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionAuthority")
            .field("replay_count", &self.replayed.len())
            .finish()
    }
}

fn sign_tag(
    key: &SessionKey,
    identity: &GuestIdentity,
    nonce: &[u8; 32],
    generation: u64,
) -> [u8; TAG_BYTES] {
    let mut transcript = Vec::with_capacity(160);
    transcript.extend_from_slice(b"d2b-component-session-auth-v1\0");
    append_field(
        &mut transcript,
        identity.guest.to_canonical_string().as_bytes(),
    );
    append_field(&mut transcript, identity.zone.as_str().as_bytes());
    append_field(&mut transcript, &identity.cid.0.to_be_bytes());
    append_field(&mut transcript, identity.boot_id.as_bytes());
    append_field(&mut transcript, &generation.to_be_bytes());
    append_field(&mut transcript, nonce);
    let signing_key = hmac::Key::new(hmac::HMAC_SHA256, &key.0);
    let tag = hmac::sign(&signing_key, &transcript);
    let mut output = [0_u8; TAG_BYTES];
    output.copy_from_slice(tag.as_ref());
    output
}

fn append_field(transcript: &mut Vec<u8>, value: &[u8]) {
    transcript.extend_from_slice(&(value.len() as u32).to_be_bytes());
    transcript.extend_from_slice(value);
}

fn constant_time_equal(left: &[u8; TAG_BYTES], right: &[u8; TAG_BYTES]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}
