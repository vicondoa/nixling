//! Host-global GPU authority and restart-adoption contracts.
//!
//! Core creates the opaque values in this module after resolving the trusted
//! device inventory. The Provider can compare those values and retain the
//! resulting lease, but it cannot derive one from a path, selector, or
//! process identifier.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use d2b_contracts_resource::v3::{
    ResourceGeneration, ResourceRef, ResourceUid, device::DeviceArbitration,
};

use crate::process::GpuProcessRole;

/// Core-derived identity for one physical GPU or render node backing.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GpuBackingToken([u8; 32]);

impl GpuBackingToken {
    /// Construct a backing token at the trusted Core boundary.
    pub const fn from_core(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Whether the token is the forbidden all-zero identity.
    pub fn is_zero(&self) -> bool {
        self.0 == [0; 32]
    }

    /// Borrow the token for another trusted adapter comparison.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for GpuBackingToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GpuBackingToken(<redacted>)")
    }
}

/// Core-derived platform identity for one GPU effect.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GpuPlatformToken([u8; 32]);

impl GpuPlatformToken {
    /// Construct a platform token at the trusted Core boundary.
    pub const fn from_core(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Whether the token is the forbidden all-zero identity.
    pub fn is_zero(&self) -> bool {
        self.0 == [0; 32]
    }
}

impl fmt::Debug for GpuPlatformToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GpuPlatformToken(<redacted>)")
    }
}

/// Core-assigned worker principal.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GpuPrincipalToken([u8; 32]);

impl GpuPrincipalToken {
    /// Construct a principal token at the trusted Core boundary.
    pub const fn from_core(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Whether the token is the forbidden all-zero identity.
    pub fn is_zero(&self) -> bool {
        self.0 == [0; 32]
    }
}

impl fmt::Debug for GpuPrincipalToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GpuPrincipalToken(<redacted>)")
    }
}

/// Opaque proof that a Device owner is authorized to hold GPU authority.
#[derive(Clone, PartialEq, Eq)]
pub struct GpuOwnerProof {
    zone_ref: ResourceRef,
    holder_ref: ResourceRef,
    device_uid: ResourceUid,
    host_uid: ResourceUid,
    generation: ResourceGeneration,
}

impl GpuOwnerProof {
    /// Bind a proof to an exact Zone, holder, Device, Host, and generation.
    pub fn new(
        zone_ref: ResourceRef,
        holder_ref: ResourceRef,
        device_uid: ResourceUid,
        host_uid: ResourceUid,
        generation: ResourceGeneration,
    ) -> Result<Self, GpuAuthorityError> {
        if zone_ref.resource_type().as_str() != "Zone"
            || !matches!(holder_ref.resource_type().as_str(), "Guest" | "Host")
        {
            return Err(GpuAuthorityError::WrongPrincipal);
        }
        Ok(Self {
            zone_ref,
            holder_ref,
            device_uid,
            host_uid,
            generation,
        })
    }

    /// Borrow the exact Zone reference.
    pub const fn zone_ref(&self) -> &ResourceRef {
        &self.zone_ref
    }

    /// Borrow the exact holder reference.
    pub const fn holder_ref(&self) -> &ResourceRef {
        &self.holder_ref
    }

    /// Borrow the Device UID.
    pub const fn device_uid(&self) -> &ResourceUid {
        &self.device_uid
    }

    /// Borrow the Host UID.
    pub const fn host_uid(&self) -> &ResourceUid {
        &self.host_uid
    }

    /// Return the admitted resource generation.
    pub const fn generation(&self) -> ResourceGeneration {
        self.generation
    }
}

impl fmt::Debug for GpuOwnerProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GpuOwnerProof(<redacted>)")
    }
}

/// Core-issued GPU authority admission.
#[derive(Clone, PartialEq, Eq)]
pub struct GpuAuthorityAdmission {
    owner: GpuOwnerProof,
    backing: GpuBackingToken,
    platform: GpuPlatformToken,
    arbitration: DeviceArbitration,
    max_holders: u32,
    render_node_only: bool,
    gpu_principal: GpuPrincipalToken,
    video_principal: Option<GpuPrincipalToken>,
}

impl GpuAuthorityAdmission {
    /// Construct an admission before any device or process effect.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner: GpuOwnerProof,
        backing: GpuBackingToken,
        platform: GpuPlatformToken,
        arbitration: DeviceArbitration,
        max_holders: u32,
        render_node_only: bool,
        gpu_principal: GpuPrincipalToken,
    ) -> Result<Self, GpuAuthorityError> {
        if backing.is_zero() || platform.is_zero() || gpu_principal.is_zero() {
            return Err(GpuAuthorityError::StaleDeviceIdentity);
        }
        if !(1..=16).contains(&max_holders)
            || (arbitration == DeviceArbitration::Exclusive && max_holders != 1)
            || (arbitration == DeviceArbitration::Shared && !render_node_only)
            || (arbitration == DeviceArbitration::Exclusive && render_node_only && max_holders != 1)
        {
            return Err(GpuAuthorityError::ArbitrationViolation);
        }
        Ok(Self {
            owner,
            backing,
            platform,
            arbitration,
            max_holders,
            render_node_only,
            gpu_principal,
            video_principal: None,
        })
    }

    /// Attach the distinct Core-assigned video principal.
    pub fn with_video_principal(
        mut self,
        video_principal: GpuPrincipalToken,
    ) -> Result<Self, GpuAuthorityError> {
        if video_principal.is_zero() || video_principal == self.gpu_principal {
            return Err(GpuAuthorityError::PrincipalNotSeparated);
        }
        self.video_principal = Some(video_principal);
        Ok(self)
    }

    /// Borrow the exact owner proof.
    pub const fn owner(&self) -> &GpuOwnerProof {
        &self.owner
    }

    /// Borrow the opaque backing identity.
    pub const fn backing(&self) -> &GpuBackingToken {
        &self.backing
    }

    /// Borrow the opaque platform identity.
    pub const fn platform(&self) -> &GpuPlatformToken {
        &self.platform
    }

    /// Return the requested arbitration.
    pub const fn arbitration(&self) -> DeviceArbitration {
        self.arbitration
    }

    /// Return the signed holder ceiling.
    pub const fn max_holders(&self) -> u32 {
        self.max_holders
    }

    /// Whether this is render-node-only authority.
    pub const fn render_node_only(&self) -> bool {
        self.render_node_only
    }

    /// Borrow the GPU worker principal.
    pub const fn gpu_principal(&self) -> &GpuPrincipalToken {
        &self.gpu_principal
    }

    /// Borrow the distinct video worker principal, when configured.
    pub const fn video_principal(&self) -> Option<&GpuPrincipalToken> {
        self.video_principal.as_ref()
    }
}

impl fmt::Debug for GpuAuthorityAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GpuAuthorityAdmission")
            .field("arbitration", &self.arbitration)
            .field("max_holders", &self.max_holders)
            .field("render_node_only", &self.render_node_only)
            .field("has_video_principal", &self.video_principal.is_some())
            .finish()
    }
}

/// Opaque Host-global GPU lease.
#[derive(Clone, PartialEq, Eq)]
pub struct GpuAuthorityLease([u8; 16]);

impl GpuAuthorityLease {
    /// Construct a lease at the trusted authority adapter boundary.
    pub const fn from_core(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Borrow the opaque lease token at the daemon adapter boundary.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for GpuAuthorityLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GpuAuthorityLease(<redacted>)")
    }
}

/// Opaque identity of one broker-supervised GPU worker.
#[derive(Clone, PartialEq, Eq)]
pub struct GpuProcessIdentity {
    process_token: [u8; 16],
    role: GpuProcessRole,
    principal: GpuPrincipalToken,
    platform: GpuPlatformToken,
    generation: ResourceGeneration,
}

impl GpuProcessIdentity {
    /// Construct a verified process identity at the broker boundary.
    pub const fn from_core(
        process_token: [u8; 16],
        role: GpuProcessRole,
        principal: GpuPrincipalToken,
        platform: GpuPlatformToken,
        generation: ResourceGeneration,
    ) -> Self {
        Self {
            process_token,
            role,
            principal,
            platform,
            generation,
        }
    }

    /// Return the worker role.
    pub const fn role(&self) -> GpuProcessRole {
        self.role
    }

    /// Borrow the worker principal.
    pub const fn principal(&self) -> &GpuPrincipalToken {
        &self.principal
    }

    /// Borrow the platform identity.
    pub const fn platform(&self) -> &GpuPlatformToken {
        &self.platform
    }

    /// Return the resource generation bound to this worker.
    pub const fn generation(&self) -> ResourceGeneration {
        self.generation
    }
}

impl fmt::Debug for GpuProcessIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GpuProcessIdentity")
            .field("role", &self.role)
            .field("generation", &self.generation)
            .finish()
    }
}

/// Broker proof that one exact worker process has closed.
#[derive(Clone, PartialEq, Eq)]
pub struct GpuClosureProof {
    identity: GpuProcessIdentity,
}

impl GpuClosureProof {
    /// Construct a closure proof at the broker boundary.
    pub fn from_core(identity: GpuProcessIdentity) -> Self {
        Self { identity }
    }

    /// Borrow the closed process identity for exact lease matching.
    pub const fn identity(&self) -> &GpuProcessIdentity {
        &self.identity
    }
}

impl fmt::Debug for GpuClosureProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GpuClosureProof(<redacted>)")
    }
}

/// Observation used by restart adoption.
#[derive(Clone, PartialEq, Eq)]
pub enum GpuProcessObservation {
    /// Exactly one process matched the expected identity.
    Matching(GpuProcessIdentity),
    /// No process with the expected identity was found.
    Missing,
    /// The identity was reused or could not be verified.
    StaleIdentity,
    /// More than one process matched the expected identity.
    Ambiguous,
}

impl fmt::Debug for GpuProcessObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Matching(_) => "GpuProcessObservation::Matching",
            Self::Missing => "GpuProcessObservation::Missing",
            Self::StaleIdentity => "GpuProcessObservation::StaleIdentity",
            Self::Ambiguous => "GpuProcessObservation::Ambiguous",
        })
    }
}

/// Persisted, non-authorizing worker record used during restart recovery.
#[derive(Clone, PartialEq, Eq)]
pub struct GpuRecoveryRecord {
    /// The Core admission that owned the worker.
    pub admission: GpuAuthorityAdmission,
    /// Worker identities observed before restart.
    pub processes: Vec<GpuProcessIdentity>,
    /// The opaque lease proof persisted by the Core adapter.
    pub lease: GpuAuthorityLease,
}

impl GpuRecoveryRecord {
    /// Construct a recovery record for one GPU worker.
    pub fn from_core(
        admission: GpuAuthorityAdmission,
        process: GpuProcessIdentity,
        lease: GpuAuthorityLease,
    ) -> Self {
        Self {
            admission,
            processes: vec![process],
            lease,
        }
    }

    /// Add another same-Device worker, such as the video sidecar.
    pub fn with_process(mut self, process: GpuProcessIdentity) -> Self {
        self.processes.push(process);
        self
    }
}

impl fmt::Debug for GpuRecoveryRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GpuRecoveryRecord(<redacted>)")
    }
}

/// Durable records loaded before new GPU claims may be admitted.
#[derive(Default)]
pub struct GpuRecoverySnapshot {
    records: Vec<GpuRecoveryRecord>,
}

impl GpuRecoverySnapshot {
    /// Construct a recovery snapshot from trusted storage.
    pub fn from_core(records: Vec<GpuRecoveryRecord>) -> Self {
        Self { records }
    }

    /// Borrow the loaded records.
    pub fn records(&self) -> &[GpuRecoveryRecord] {
        &self.records
    }
}

/// Restart adoption result.
pub enum GpuAdoption {
    /// One exact worker was adopted.
    Adopted(GpuAuthorityLease),
    /// No matching worker was found.
    Missing,
    /// Ambiguous matching workers remain quarantined.
    Quarantined,
    /// The observed worker identity was stale.
    StaleIdentity,
}

impl fmt::Debug for GpuAdoption {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Adopted(_) => "GpuAdoption::Adopted",
            Self::Missing => "GpuAdoption::Missing",
            Self::Quarantined => "GpuAdoption::Quarantined",
            Self::StaleIdentity => "GpuAdoption::StaleIdentity",
        })
    }
}

/// Stable GPU authority errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuAuthorityError {
    /// A claim used a wrong holder or Zone reference.
    WrongPrincipal,
    /// GPU and video workers attempted to share one principal.
    PrincipalNotSeparated,
    /// A physical identity was zero or no longer current.
    StaleDeviceIdentity,
    /// The arbitration and render-node settings disagree.
    ArbitrationViolation,
    /// A full-device or render-node claim conflicts with an owner.
    ClaimConflict,
    /// The signed shared-holder ceiling was reached.
    MaxClaimsExceeded,
    /// The authority index has not completed restart rehydration.
    StartupRehydrationRequired,
    /// The same owner already holds the authority.
    DuplicateActiveReservation,
    /// A process observation used the wrong principal.
    ProcessPrincipalMismatch,
    /// A process observation used the wrong platform identity.
    PlatformMismatch,
    /// A process observation used an old resource generation.
    GenerationMismatch,
    /// The exact owner proof did not match the retained lease.
    OwnerProofMismatch,
    /// A close proof was missing or named another process.
    CloseUnconfirmed,
    /// A quarantined key cannot admit a new effect.
    Quarantined,
}

impl GpuAuthorityError {
    /// Return the stable, identity-free error code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::WrongPrincipal => "gpu-authority-principal-denied",
            Self::PrincipalNotSeparated => "gpu-principal-not-separated",
            Self::StaleDeviceIdentity => "gpu-device-identity-stale",
            Self::ArbitrationViolation => "gpu-arbitration-violation",
            Self::ClaimConflict => "device-claim-conflict",
            Self::MaxClaimsExceeded => "device-claim-max-exceeded",
            Self::StartupRehydrationRequired => "authority-startup-rehydration-required",
            Self::DuplicateActiveReservation => "authority-duplicate-active-reservation",
            Self::ProcessPrincipalMismatch => "gpu-process-principal-mismatch",
            Self::PlatformMismatch => "gpu-platform-mismatch",
            Self::GenerationMismatch => "gpu-device-generation-stale",
            Self::OwnerProofMismatch => "gpu-authority-owner-proof-mismatch",
            Self::CloseUnconfirmed => "gpu-worker-close-unconfirmed",
            Self::Quarantined => "gpu-authority-quarantined",
        }
    }
}

impl fmt::Display for GpuAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for GpuAuthorityError {}

struct AuthorityOwner {
    admission: GpuAuthorityAdmission,
    lease: GpuAuthorityLease,
    processes: Vec<GpuProcessIdentity>,
}

struct AuthorityEntry {
    arbitration: DeviceArbitration,
    max_holders: u32,
    platform: GpuPlatformToken,
    lease_seq: u64,
    owners: Vec<AuthorityOwner>,
}

fn validate_process_identity(
    admission: &GpuAuthorityAdmission,
    process: &GpuProcessIdentity,
) -> Result<(), GpuAuthorityError> {
    let expected_principal = match process.role {
        GpuProcessRole::Video => admission
            .video_principal
            .as_ref()
            .ok_or(GpuAuthorityError::ProcessPrincipalMismatch)?,
        GpuProcessRole::FullGpu | GpuProcessRole::RenderNode => &admission.gpu_principal,
    };
    if process.principal != *expected_principal {
        return Err(GpuAuthorityError::ProcessPrincipalMismatch);
    }
    if process.platform != admission.platform {
        return Err(GpuAuthorityError::PlatformMismatch);
    }
    if process.generation != admission.owner.generation {
        return Err(GpuAuthorityError::GenerationMismatch);
    }
    Ok(())
}

/// Host-global GPU authority index.
///
/// The index is deliberately small and in-memory. Core's durable operation
/// owner supplies the recovery snapshot and the opaque lease values before the
/// index becomes ready for new admission.
pub struct GpuAuthorityIndex {
    entries: BTreeMap<GpuBackingToken, AuthorityEntry>,
    quarantined: BTreeSet<GpuBackingToken>,
    rehydrated: bool,
}

impl GpuAuthorityIndex {
    /// Construct the production startup barrier.
    pub fn new_unrehydrated() -> Self {
        Self {
            entries: BTreeMap::new(),
            quarantined: BTreeSet::new(),
            rehydrated: false,
        }
    }

    /// Construct an explicitly ready in-memory index for hermetic tests.
    pub fn new_for_tests_ready() -> Self {
        Self {
            rehydrated: true,
            ..Self::new_unrehydrated()
        }
    }

    /// Rehydrate all durable owners before admitting new claims.
    pub fn rehydrate(snapshot: GpuRecoverySnapshot) -> Result<Self, GpuAuthorityError> {
        let mut index = Self::new_unrehydrated();
        for record in snapshot.records {
            for process in &record.processes {
                validate_process_identity(&record.admission, process)?;
            }
            let key = record.admission.backing.clone();
            if index.quarantined.contains(&key) {
                continue;
            }
            let duplicate_lease = index.entries.iter().find_map(|(existing_key, entry)| {
                entry.owners.iter().find_map(|owner| {
                    (owner.lease == record.lease
                        && !(existing_key == &key && owner.admission == record.admission))
                        .then(|| existing_key.clone())
                })
            });
            if let Some(existing_key) = duplicate_lease {
                index.quarantined.insert(existing_key.clone());
                index.quarantined.insert(key.clone());
                if let Some(entry) = index.entries.get_mut(&existing_key) {
                    entry.owners.clear();
                }
                if let Some(entry) = index.entries.get_mut(&key) {
                    entry.owners.clear();
                }
                continue;
            }
            let entry = index
                .entries
                .entry(key.clone())
                .or_insert_with(|| AuthorityEntry {
                    arbitration: record.admission.arbitration,
                    max_holders: record.admission.max_holders,
                    platform: record.admission.platform.clone(),
                    lease_seq: 0,
                    owners: Vec::new(),
                });
            if entry.arbitration != record.admission.arbitration
                || entry.max_holders != record.admission.max_holders
                || entry.platform != record.admission.platform
            {
                entry.owners.clear();
                index.quarantined.insert(key);
                continue;
            }
            if let Some(owner) = entry
                .owners
                .iter_mut()
                .find(|owner| owner.admission.owner == record.admission.owner)
            {
                if owner.lease != record.lease || owner.admission != record.admission {
                    entry.owners.clear();
                    index.quarantined.insert(key);
                    continue;
                }
                for process in record.processes {
                    if !owner.processes.contains(&process) {
                        owner.processes.push(process);
                    }
                }
            } else {
                entry.lease_seq = entry.lease_seq.saturating_add(1);
                entry.owners.push(AuthorityOwner {
                    admission: record.admission,
                    lease: record.lease,
                    processes: record.processes,
                });
            }
        }
        index.rehydrated = true;
        Ok(index)
    }

    /// Whether durable startup recovery has completed.
    pub const fn is_rehydrated(&self) -> bool {
        self.rehydrated
    }

    /// Whether one backing key is quarantined.
    pub fn is_quarantined(&self, backing: &GpuBackingToken) -> bool {
        self.quarantined.contains(backing)
    }

    /// Reserve the Host-global key before opening or spawning anything.
    pub fn reserve(
        &mut self,
        admission: GpuAuthorityAdmission,
    ) -> Result<GpuAuthorityLease, GpuAuthorityError> {
        if !self.rehydrated {
            return Err(GpuAuthorityError::StartupRehydrationRequired);
        }
        if self.quarantined.contains(&admission.backing) {
            return Err(GpuAuthorityError::Quarantined);
        }
        let next_ordinal = {
            let entry = self
                .entries
                .entry(admission.backing.clone())
                .or_insert_with(|| AuthorityEntry {
                    arbitration: admission.arbitration,
                    max_holders: admission.max_holders,
                    platform: admission.platform.clone(),
                    lease_seq: 0,
                    owners: Vec::new(),
                });
            if entry.arbitration != admission.arbitration
                || entry.max_holders != admission.max_holders
            {
                return Err(GpuAuthorityError::ArbitrationViolation);
            }
            if entry.platform != admission.platform {
                return Err(GpuAuthorityError::StaleDeviceIdentity);
            }
            if entry
                .owners
                .iter()
                .any(|owner| owner.admission.owner == admission.owner)
            {
                return Err(GpuAuthorityError::DuplicateActiveReservation);
            }
            if admission.arbitration == DeviceArbitration::Exclusive && !entry.owners.is_empty() {
                return Err(GpuAuthorityError::ClaimConflict);
            }
            if entry.owners.len() >= admission.max_holders as usize {
                return Err(GpuAuthorityError::MaxClaimsExceeded);
            }
            entry.lease_seq.saturating_add(1).max(1)
        };
        let backing = admission.backing.clone();
        let (ordinal, lease) = self.allocate_lease(&backing, next_ordinal)?;
        let entry = self
            .entries
            .get_mut(&backing)
            .expect("authority entry exists after validation");
        entry.lease_seq = ordinal;
        entry.owners.push(AuthorityOwner {
            admission,
            lease: lease.clone(),
            processes: Vec::new(),
        });
        Ok(lease)
    }

    /// Bind the broker-issued process identity to a retained lease.
    pub fn bind_process(
        &mut self,
        lease: &GpuAuthorityLease,
        process: GpuProcessIdentity,
    ) -> Result<(), GpuAuthorityError> {
        let owner = self.find_owner_mut(lease)?;
        validate_process_identity(&owner.admission, &process)?;
        if !owner.processes.iter().any(|known| known == &process) {
            owner.processes.push(process);
        }
        Ok(())
    }

    /// Adopt one matching process after restart.
    pub fn adopt(
        &mut self,
        admission: &GpuAuthorityAdmission,
        observations: &[GpuProcessObservation],
    ) -> Result<GpuAdoption, GpuAuthorityError> {
        if self.quarantined.contains(&admission.backing) {
            return Ok(GpuAdoption::Quarantined);
        }
        let Some(entry) = self.entries.get(&admission.backing) else {
            return Ok(GpuAdoption::Missing);
        };
        let owner = entry
            .owners
            .iter()
            .find(|owner| owner.admission.owner == admission.owner);
        let Some(owner) = owner else {
            return Ok(GpuAdoption::Missing);
        };
        if owner.admission != *admission {
            return Err(GpuAuthorityError::OwnerProofMismatch);
        }
        let owner_lease = owner.lease.clone();
        let owner_processes = owner.processes.clone();
        if observations
            .iter()
            .any(|observation| matches!(observation, GpuProcessObservation::Ambiguous))
        {
            self.quarantined.insert(admission.backing.clone());
            return Ok(GpuAdoption::Quarantined);
        }
        for observation in observations {
            if let GpuProcessObservation::Matching(identity) = observation {
                validate_process_identity(admission, identity)?;
            }
        }
        let mut matched_roles = BTreeSet::new();
        let mut matched_count = 0;
        for observation in observations {
            let GpuProcessObservation::Matching(identity) = observation else {
                continue;
            };
            if owner_processes.iter().any(|known| known == identity) {
                if !matched_roles.insert(identity.role()) {
                    self.quarantined.insert(admission.backing.clone());
                    return Ok(GpuAdoption::Quarantined);
                }
                matched_count += 1;
            }
        }
        if matched_count > 0 {
            Ok(GpuAdoption::Adopted(owner_lease))
        } else if observations
            .iter()
            .any(|observation| matches!(observation, GpuProcessObservation::StaleIdentity))
        {
            Ok(GpuAdoption::StaleIdentity)
        } else {
            Ok(GpuAdoption::Missing)
        }
    }

    /// Release only after the exact owned process has closed.
    pub fn release_after_close(
        &mut self,
        lease: &GpuAuthorityLease,
        closure: &GpuClosureProof,
    ) -> Result<(), GpuAuthorityError> {
        self.release_after_all_closed(lease, std::slice::from_ref(closure))
    }

    /// Release only after every process bound to the exact lease has closed.
    pub fn release_after_all_closed(
        &mut self,
        lease: &GpuAuthorityLease,
        closures: &[GpuClosureProof],
    ) -> Result<(), GpuAuthorityError> {
        let key = self
            .entries
            .iter()
            .find_map(|(key, entry)| {
                entry
                    .owners
                    .iter()
                    .any(|owner| &owner.lease == lease)
                    .then(|| key.clone())
            })
            .ok_or(GpuAuthorityError::OwnerProofMismatch)?;
        let entry = self.entries.get_mut(&key).expect("authority entry exists");
        let position = entry
            .owners
            .iter()
            .position(|owner| {
                &owner.lease == lease && {
                    (owner.processes.is_empty() && closures.is_empty())
                        || owner.processes.iter().all(|process| {
                            closures.iter().any(|closure| closure.identity() == process)
                        })
                }
            })
            .ok_or(GpuAuthorityError::CloseUnconfirmed)?;
        entry.owners.remove(position);
        if entry.owners.is_empty() {
            self.entries.remove(&key);
            self.quarantined.remove(&key);
        }
        Ok(())
    }

    /// Return the current holder count for one backing.
    pub fn holder_count(&self, backing: &GpuBackingToken) -> usize {
        self.entries
            .get(backing)
            .map_or(0, |entry| entry.owners.len())
    }

    fn find_owner_mut(
        &mut self,
        lease: &GpuAuthorityLease,
    ) -> Result<&mut AuthorityOwner, GpuAuthorityError> {
        self.entries
            .values_mut()
            .find_map(|entry| entry.owners.iter_mut().find(|owner| &owner.lease == lease))
            .ok_or(GpuAuthorityError::OwnerProofMismatch)
    }

    fn allocate_lease(
        &self,
        backing: &GpuBackingToken,
        start_ordinal: u64,
    ) -> Result<(u64, GpuAuthorityLease), GpuAuthorityError> {
        let mut ordinal = start_ordinal.max(1);
        loop {
            let lease = GpuAuthorityLease::from_core(lease_bytes(backing, ordinal));
            if !self.lease_in_use(&lease) {
                return Ok((ordinal, lease));
            }
            ordinal = ordinal
                .checked_add(1)
                .ok_or(GpuAuthorityError::MaxClaimsExceeded)?;
        }
    }

    fn lease_in_use(&self, lease: &GpuAuthorityLease) -> bool {
        self.entries
            .values()
            .flat_map(|entry| entry.owners.iter())
            .any(|owner| &owner.lease == lease)
    }
}

fn lease_bytes(backing: &GpuBackingToken, ordinal: u64) -> [u8; 16] {
    let mut bytes = [0; 16];
    for (index, value) in backing.0.iter().enumerate() {
        bytes[index % 16] ^= *value;
    }
    for (index, value) in ordinal.to_be_bytes().iter().enumerate() {
        bytes[index] ^= *value;
    }
    bytes
}
