//! Typed, bounded content projections for Volume-owned files.
//!
//! A content projection is a complete declaration, not a collection of
//! filename/value pairs. Every file carries its anchored name, typed owner
//! and group, exact mode, bytes, and digest; the projection also carries the
//! resource provenance and the Volume ownership marker. The effect adapter
//! may publish evidence only after it has read back every declared file.

use std::collections::BTreeSet;
use std::fmt;

use d2b_contracts_resource::v3::{
    ResourceGeneration, ResourceRef, ResourceUid,
    identity::ReconnectGeneration,
    network::{NetworkProvenance, derive_network_ownership_marker},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::VolumeLocalError;

/// Schema identity for Volume provider content settings.
pub const VOLUME_CONTENT_SCHEMA_ID: &str = "volume-local.d2bus.org/Volume/spec";
/// Schema version for the generic Volume content boundary.
pub const VOLUME_CONTENT_SCHEMA_VERSION: &str = "1.0";
/// Schema identity for the generic content projection boundary.
pub const GENERIC_CONTENT_SCHEMA_ID: &str = "volume-local.d2bus.org/ContentProjection";
/// Maximum number of files in one content projection.
pub const MAX_CONTENT_FILES: usize = 64;
/// Maximum aggregate payload accepted by one content projection.
pub const MAX_CONTENT_BYTES: usize = 4 * 1024 * 1024;
/// Maximum aggregate payload accepted by the Network projection.
pub const MAX_NETWORK_CONFIG_CONTENT_BYTES: usize = MAX_CONTENT_BYTES;
/// Maximum bytes in one anchored content filename.
pub const MAX_CONTENT_PATH_BYTES: usize = 255;

/// Exact identity and fence provenance for a content projection.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContentProvenance {
    owner_ref: ResourceRef,
    owner_uid: ResourceUid,
    owner_generation: ResourceGeneration,
    assignment_key: String,
    session_generation: Option<ReconnectGeneration>,
}

impl ContentProvenance {
    /// Construct a bounded content provenance tuple.
    pub fn new(
        owner_ref: ResourceRef,
        owner_uid: ResourceUid,
        owner_generation: ResourceGeneration,
        assignment_key: impl Into<String>,
        session_generation: Option<ReconnectGeneration>,
    ) -> Result<Self, VolumeLocalError> {
        let assignment_key = assignment_key.into();
        if assignment_key.is_empty()
            || assignment_key.len() > 128
            || !assignment_key.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(VolumeLocalError::InvalidSpec);
        }
        Ok(Self {
            owner_ref,
            owner_uid,
            owner_generation,
            assignment_key,
            session_generation,
        })
    }

    /// Borrow the resource that authored the content.
    pub const fn owner_ref(&self) -> &ResourceRef {
        &self.owner_ref
    }

    /// Borrow the immutable author UID.
    pub const fn owner_uid(&self) -> &ResourceUid {
        &self.owner_uid
    }

    /// Return the author generation.
    pub const fn owner_generation(&self) -> ResourceGeneration {
        self.owner_generation
    }

    /// Borrow the exact assignment fence.
    pub fn assignment_key(&self) -> &str {
        &self.assignment_key
    }

    /// Return the session/reconnect fence, when the owner is session-bound.
    pub const fn session_generation(&self) -> Option<ReconnectGeneration> {
        self.session_generation
    }
}

impl fmt::Debug for ContentProvenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ContentProvenance(<redacted>)")
    }
}

/// One complete declared file in a content projection.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContentFile {
    path: String,
    owner: ResourceRef,
    group: ResourceRef,
    mode: String,
    bytes: Vec<u8>,
    digest: String,
}

impl ContentFile {
    /// Construct a file and derive its canonical SHA-256 digest.
    pub fn new(
        path: impl Into<String>,
        owner: ResourceRef,
        group: ResourceRef,
        mode: impl Into<String>,
        bytes: Vec<u8>,
    ) -> Result<Self, VolumeLocalError> {
        let bytes_digest = digest_bytes(&bytes);
        Self::with_digest(path, owner, group, mode, bytes, bytes_digest)
    }

    /// Construct a file with a caller-supplied digest that is validated.
    pub fn with_digest(
        path: impl Into<String>,
        owner: ResourceRef,
        group: ResourceRef,
        mode: impl Into<String>,
        bytes: Vec<u8>,
        digest: impl Into<String>,
    ) -> Result<Self, VolumeLocalError> {
        let file = Self {
            path: path.into(),
            owner,
            group,
            mode: mode.into(),
            bytes,
            digest: digest.into(),
        };
        file.validate()?;
        Ok(file)
    }

    /// Validate the anchored name, typed ownership, mode, size, and digest.
    pub fn validate(&self) -> Result<(), VolumeLocalError> {
        validate_content_path(&self.path)?;
        if self.owner.resource_type().as_str() != "User"
            || self.group.resource_type().as_str() != "User"
            || !valid_mode(&self.mode)
            || !is_digest(&self.digest)
            || digest_bytes(&self.bytes) != self.digest
        {
            return Err(VolumeLocalError::InvalidSpec);
        }
        Ok(())
    }

    /// Borrow the validated anchored relative path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Borrow the typed owner.
    pub const fn owner(&self) -> &ResourceRef {
        &self.owner
    }

    /// Borrow the typed group.
    pub const fn group(&self) -> &ResourceRef {
        &self.group
    }

    /// Borrow the exact four-digit mode.
    pub fn mode(&self) -> &str {
        &self.mode
    }

    /// Borrow the exact file bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Borrow the canonical content digest.
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

impl fmt::Debug for ContentFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ContentFile(<redacted>)")
    }
}

/// A complete, typed Volume content declaration.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContentProjection {
    volume_uid: ResourceUid,
    provenance: ContentProvenance,
    ownership_marker: String,
    files: Vec<ContentFile>,
    content_digest: String,
}

impl ContentProjection {
    /// Construct and validate a complete content declaration.
    pub fn new(
        volume_uid: ResourceUid,
        provenance: ContentProvenance,
        ownership_marker: impl Into<String>,
        files: impl IntoIterator<Item = ContentFile>,
    ) -> Result<Self, VolumeLocalError> {
        let projection = Self {
            volume_uid,
            provenance,
            ownership_marker: ownership_marker.into(),
            files: files.into_iter().collect(),
            content_digest: String::new(),
        };
        let content_digest = digest_projection(&projection)?;
        let projection = Self {
            content_digest,
            ..projection
        };
        projection.validate()?;
        Ok(projection)
    }

    /// Parse and validate a serialized content projection.
    pub fn from_value(value: &serde_json::Value) -> Result<Self, VolumeLocalError> {
        let projection: Self =
            serde_json::from_value(value.clone()).map_err(|_| VolumeLocalError::InvalidSpec)?;
        projection.validate()?;
        Ok(projection)
    }

    /// Validate every identity, fence, filename, ownership field, and digest.
    pub fn validate(&self) -> Result<(), VolumeLocalError> {
        if self.ownership_marker.is_empty()
            || self.ownership_marker.len() > 256
            || !self
                .ownership_marker
                .bytes()
                .all(|byte| byte.is_ascii_graphic())
            || self.files.is_empty()
            || self.files.len() > MAX_CONTENT_FILES
            || self.files.iter().any(|file| file.validate().is_err())
            || self
                .files
                .iter()
                .map(|file| file.path())
                .collect::<BTreeSet<_>>()
                .len()
                != self.files.len()
            || self
                .files
                .iter()
                .map(|file| file.bytes().len())
                .sum::<usize>()
                > MAX_CONTENT_BYTES
            || !is_digest(&self.content_digest)
            || digest_projection(self)? != self.content_digest
        {
            return Err(VolumeLocalError::InvalidSpec);
        }
        Ok(())
    }

    /// Borrow the Volume UID this projection targets.
    pub const fn volume_uid(&self) -> &ResourceUid {
        &self.volume_uid
    }

    /// Borrow the complete author provenance.
    pub const fn provenance(&self) -> &ContentProvenance {
        &self.provenance
    }

    /// Borrow the expected Volume ownership marker.
    pub fn ownership_marker(&self) -> &str {
        &self.ownership_marker
    }

    /// Borrow all declared files in deterministic order.
    pub fn files(&self) -> &[ContentFile] {
        &self.files
    }

    /// Borrow the aggregate projection digest.
    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }
}

impl fmt::Debug for ContentProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ContentProjection(<redacted>)")
    }
}

/// One readback observation supplied by a trusted effect adapter.
#[derive(Clone, PartialEq, Eq)]
pub struct ObservedContentFile {
    path: String,
    owner: ResourceRef,
    group: ResourceRef,
    mode: String,
    bytes: Vec<u8>,
}

impl ObservedContentFile {
    /// Construct a readback observation.
    pub fn new(
        path: impl Into<String>,
        owner: ResourceRef,
        group: ResourceRef,
        mode: impl Into<String>,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            path: path.into(),
            owner,
            group,
            mode: mode.into(),
            bytes,
        }
    }

    /// Borrow the observed anchored path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Borrow the observed owner.
    pub const fn owner(&self) -> &ResourceRef {
        &self.owner
    }

    /// Borrow the observed group.
    pub const fn group(&self) -> &ResourceRef {
        &self.group
    }

    /// Borrow the observed mode.
    pub fn mode(&self) -> &str {
        &self.mode
    }

    /// Borrow the observed bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Durable evidence that every projected file was materialized and read back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContentMaterializationEvidence {
    volume_uid: ResourceUid,
    provenance: ContentProvenance,
    ownership_marker: String,
    files: Vec<ContentFileEvidence>,
    content_digest: String,
    materialized: bool,
}

/// Readback evidence for one projected file without retaining its bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContentFileEvidence {
    path: String,
    owner: ResourceRef,
    group: ResourceRef,
    mode: String,
    digest: String,
}

impl ContentMaterializationEvidence {
    /// Build evidence only after all files match the projection exactly.
    pub fn from_readback(
        projection: &ContentProjection,
        observed: &[ObservedContentFile],
    ) -> Result<Self, VolumeLocalError> {
        projection.validate()?;
        if observed.len() != projection.files.len()
            || observed
                .iter()
                .zip(&projection.files)
                .any(|(actual, expected)| {
                    actual.path != expected.path
                        || actual.owner != expected.owner
                        || actual.group != expected.group
                        || actual.mode != expected.mode
                        || digest_bytes(&actual.bytes) != expected.digest
                })
        {
            return Err(VolumeLocalError::EffectFailed);
        }
        let files = observed
            .iter()
            .map(|file| ContentFileEvidence {
                path: file.path.clone(),
                owner: file.owner.clone(),
                group: file.group.clone(),
                mode: file.mode.clone(),
                digest: digest_bytes(&file.bytes),
            })
            .collect();
        Ok(Self {
            volume_uid: projection.volume_uid.clone(),
            provenance: projection.provenance.clone(),
            ownership_marker: projection.ownership_marker.clone(),
            files,
            content_digest: projection.content_digest.clone(),
            materialized: true,
        })
    }

    /// Whether this evidence is a complete match for the supplied projection.
    pub fn matches(&self, projection: &ContentProjection) -> bool {
        self.materialized
            && self.volume_uid == projection.volume_uid
            && self.provenance == projection.provenance
            && self.ownership_marker == projection.ownership_marker
            && self.content_digest == projection.content_digest
            && self.files.len() == projection.files.len()
            && self
                .files
                .iter()
                .zip(&projection.files)
                .all(|(actual, expected)| {
                    actual.path == expected.path
                        && actual.owner == expected.owner
                        && actual.group == expected.group
                        && actual.mode == expected.mode
                        && actual.digest == expected.digest
                })
    }

    /// Borrow the aggregate projection digest.
    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }
}

fn validate_content_path(path: &str) -> Result<(), VolumeLocalError> {
    if path.is_empty()
        || path.len() > MAX_CONTENT_PATH_BYTES
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains('\0')
        || path.contains(':')
        || path.contains('\u{FF0F}')
        || path.contains('\u{FF3C}')
        || path.contains('\u{FF0E}')
    {
        return Err(VolumeLocalError::InvalidSpec);
    }
    let mut components = path.split('/');
    if components.any(|component| {
        component.is_empty()
            || component == "."
            || component == ".."
            || !component
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    }) {
        return Err(VolumeLocalError::InvalidSpec);
    }
    Ok(())
}

fn valid_mode(mode: &str) -> bool {
    mode.len() == 4
        && mode.starts_with('0')
        && mode[1..].bytes().all(|byte| (b'0'..=b'7').contains(&byte))
}

fn is_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn digest_bytes(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    format!(
        "sha256:{}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn digest_projection(projection: &ContentProjection) -> Result<String, VolumeLocalError> {
    let mut input = Vec::new();
    input.extend_from_slice(projection.volume_uid.as_str().as_bytes());
    input.push(0);
    input.extend_from_slice(
        &serde_json::to_vec(&projection.provenance).map_err(|_| VolumeLocalError::InvalidSpec)?,
    );
    input.push(0);
    input.extend_from_slice(projection.ownership_marker.as_bytes());
    for file in &projection.files {
        input.extend_from_slice(&(file.path.len() as u64).to_be_bytes());
        input.extend_from_slice(file.path.as_bytes());
        input.extend_from_slice(file.owner.to_canonical_string().as_bytes());
        input.push(0);
        input.extend_from_slice(file.group.to_canonical_string().as_bytes());
        input.push(0);
        input.extend_from_slice(file.mode.as_bytes());
        input.push(0);
        input.extend_from_slice(file.digest.as_bytes());
        input.push(0);
    }
    Ok(digest_bytes(&input))
}

/// Fixed content kind used by the Network Provider's Volume projection.
pub const NETWORK_CONFIG_CONTENT_KIND: &str = "network-config";
/// Declared owner of Network configuration files.
pub const NETWORK_CONFIG_FILE_OWNER: &str = "User/net-local-controller";
/// Declared mode of Network configuration files.
pub const NETWORK_CONFIG_FILE_MODE: &str = "0640";

/// Four exact Network configuration files submitted to `volume-local`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkConfigContentProjection {
    volume_uid: ResourceUid,
    network_ref: ResourceRef,
    provenance: NetworkProvenance,
    ownership_marker: String,
    file_owner: ResourceRef,
    file_group: ResourceRef,
    file_mode: String,
    dnsmasq: Vec<u8>,
    nftables: Vec<u8>,
    routing: Vec<u8>,
    attachments: Vec<u8>,
    content_digest: String,
}

impl NetworkConfigContentProjection {
    /// Construct and validate a Network configuration projection.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        volume_uid: ResourceUid,
        network_ref: ResourceRef,
        provenance: NetworkProvenance,
        ownership_marker: impl Into<String>,
        file_owner: ResourceRef,
        file_group: ResourceRef,
        file_mode: impl Into<String>,
        dnsmasq: Vec<u8>,
        nftables: Vec<u8>,
        routing: Vec<u8>,
        attachments: Vec<u8>,
        digest: [u8; 32],
    ) -> Result<Self, VolumeLocalError> {
        let projection = Self {
            volume_uid,
            network_ref,
            provenance,
            ownership_marker: ownership_marker.into(),
            file_owner,
            file_group,
            file_mode: file_mode.into(),
            dnsmasq,
            nftables,
            routing,
            attachments,
            content_digest: format_digest(&digest),
        };
        projection.validate()?;
        Ok(projection)
    }

    /// Parse and validate a provider `settings.content` object.
    pub fn from_settings(settings: &serde_json::Value) -> Result<Self, VolumeLocalError> {
        let projection: Self =
            serde_json::from_value(settings.clone()).map_err(|_| VolumeLocalError::InvalidSpec)?;
        projection.validate()?;
        Ok(projection)
    }

    /// Validate identity, payload, marker, and digest bounds.
    pub fn validate(&self) -> Result<(), VolumeLocalError> {
        if self.network_ref.resource_type().as_str() != "Network"
            || self.file_owner.resource_type().as_str() != "User"
            || self.file_group.resource_type().as_str() != "User"
            || self.file_mode != NETWORK_CONFIG_FILE_MODE
            || self.ownership_marker
                != derive_network_ownership_marker(&self.provenance, "network-config")
        {
            return Err(VolumeLocalError::InvalidSpec);
        }
        let total = self
            .dnsmasq
            .len()
            .saturating_add(self.nftables.len())
            .saturating_add(self.routing.len())
            .saturating_add(self.attachments.len());
        if total == 0 || total > MAX_CONTENT_BYTES {
            return Err(VolumeLocalError::InvalidSpec);
        }
        if network_digest_for(self) != self.content_digest {
            return Err(VolumeLocalError::InvalidSpec);
        }
        Ok(())
    }

    /// Borrow the Volume identity this projection targets.
    pub const fn volume_uid(&self) -> &ResourceUid {
        &self.volume_uid
    }

    /// Borrow the owning Network reference.
    pub const fn network_ref(&self) -> &ResourceRef {
        &self.network_ref
    }

    /// Borrow the complete Network provenance fence.
    pub const fn provenance(&self) -> &NetworkProvenance {
        &self.provenance
    }

    /// Borrow the expected Volume ownership marker.
    pub fn ownership_marker(&self) -> &str {
        &self.ownership_marker
    }

    /// Borrow the declared file owner.
    pub const fn file_owner(&self) -> &ResourceRef {
        &self.file_owner
    }

    /// Borrow the declared file group.
    pub const fn file_group(&self) -> &ResourceRef {
        &self.file_group
    }

    /// Borrow the declared file mode.
    pub fn file_mode(&self) -> &str {
        &self.file_mode
    }

    /// Borrow dnsmasq bytes.
    pub fn dnsmasq(&self) -> &[u8] {
        &self.dnsmasq
    }

    /// Borrow nftables bytes.
    pub fn nftables(&self) -> &[u8] {
        &self.nftables
    }

    /// Borrow routing bytes.
    pub fn routing(&self) -> &[u8] {
        &self.routing
    }

    /// Borrow attachment-table bytes.
    pub fn attachments(&self) -> &[u8] {
        &self.attachments
    }

    /// Borrow the expected content digest.
    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }
}

impl fmt::Debug for NetworkConfigContentProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NetworkConfigContentProjection(<redacted>)")
    }
}

/// Status evidence returned after the Network projection is read back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkConfigMaterializationEvidence {
    volume_uid: ResourceUid,
    network_ref: ResourceRef,
    provenance: NetworkProvenance,
    ownership_marker: String,
    file_owner: ResourceRef,
    file_group: ResourceRef,
    file_mode: String,
    content_digest: String,
    materialized: bool,
}

impl NetworkConfigMaterializationEvidence {
    /// Construct evidence only after all exact files have been read back.
    pub fn from_observed_files(
        projection: &NetworkConfigContentProjection,
        dnsmasq: &[u8],
        nftables: &[u8],
        routing: &[u8],
        attachments: &[u8],
    ) -> Result<Self, VolumeLocalError> {
        projection.validate()?;
        if dnsmasq != projection.dnsmasq()
            || nftables != projection.nftables()
            || routing != projection.routing()
            || attachments != projection.attachments()
        {
            return Err(VolumeLocalError::EffectFailed);
        }
        Ok(Self {
            volume_uid: projection.volume_uid.clone(),
            network_ref: projection.network_ref.clone(),
            provenance: projection.provenance.clone(),
            ownership_marker: projection.ownership_marker.clone(),
            file_owner: projection.file_owner.clone(),
            file_group: projection.file_group.clone(),
            file_mode: projection.file_mode.clone(),
            content_digest: projection.content_digest.clone(),
            materialized: true,
        })
    }

    /// Whether this evidence exactly matches the projection.
    pub fn matches(&self, projection: &NetworkConfigContentProjection) -> bool {
        self.materialized
            && self.volume_uid == projection.volume_uid
            && self.network_ref == projection.network_ref
            && self.provenance == projection.provenance
            && self.ownership_marker == projection.ownership_marker
            && self.file_owner == projection.file_owner
            && self.file_group == projection.file_group
            && self.file_mode == projection.file_mode
            && self.content_digest == projection.content_digest
    }

    /// Borrow the materialized content digest.
    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }
}

fn network_digest_for(projection: &NetworkConfigContentProjection) -> String {
    let mut input = Vec::new();
    for bytes in [
        &projection.dnsmasq,
        &projection.nftables,
        &projection.routing,
        &projection.attachments,
    ] {
        input.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        input.extend_from_slice(bytes);
    }
    input.extend_from_slice(&(projection.ownership_marker.len() as u64).to_be_bytes());
    input.extend_from_slice(projection.ownership_marker.as_bytes());
    format_digest(&Sha256::digest(input).into())
}

fn format_digest(digest: &[u8; 32]) -> String {
    let mut rendered = String::with_capacity(71);
    rendered.push_str("sha256:");
    for byte in digest {
        rendered.push_str(&format!("{byte:02x}"));
    }
    rendered
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provenance() -> ContentProvenance {
        ContentProvenance::new(
            ResourceRef::parse("Network/work").unwrap(),
            ResourceUid::parse("7f9619ff-8b86-4d01-b42d-00cf4fc964ff").unwrap(),
            ResourceGeneration::new(3).unwrap(),
            "assignment-7",
            None,
        )
        .unwrap()
    }

    fn projection() -> ContentProjection {
        ContentProjection::new(
            ResourceUid::parse("6f9619ff-8b86-4d01-b42d-00cf4fc964ff").unwrap(),
            provenance(),
            "network:config:owned",
            [ContentFile::new(
                "dnsmasq.conf",
                ResourceRef::parse("User/net-local-controller").unwrap(),
                ResourceRef::parse("User/net-local-controller").unwrap(),
                "0640",
                b"lan=192.0.2.0/24\n".to_vec(),
            )
            .unwrap()],
        )
        .unwrap()
    }

    #[test]
    fn readback_evidence_requires_exact_bytes_and_metadata() {
        let projection = projection();
        let file = &projection.files()[0];
        let observed = [ObservedContentFile::new(
            file.path(),
            file.owner().clone(),
            file.group().clone(),
            file.mode(),
            file.bytes().to_vec(),
        )];
        let evidence = ContentMaterializationEvidence::from_readback(&projection, &observed)
            .expect("exact readback");
        assert!(evidence.matches(&projection));

        let mut tampered = observed;
        tampered[0].bytes.push(b'x');
        assert_eq!(
            ContentMaterializationEvidence::from_readback(&projection, &tampered),
            Err(VolumeLocalError::EffectFailed)
        );
    }

    #[test]
    fn unsafe_names_and_metadata_fail_before_materialization() {
        let owner = ResourceRef::parse("User/net-local-controller").unwrap();
        let invalid = ["../escape", "/absolute", "a//b", "a/\u{FF0F}b", "a:b"];
        for path in invalid {
            assert!(ContentFile::new(path, owner.clone(), owner.clone(), "0640", vec![1]).is_err());
        }
        assert!(ContentFile::new("good", owner.clone(), owner, "06666", vec![1]).is_err());
    }
}
