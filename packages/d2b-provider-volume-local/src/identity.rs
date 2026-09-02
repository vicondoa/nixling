//! Opaque layout identity, root-handle evidence, and owner proof.
//!
//! No host path, source policy ID, anchored entry path, numeric UID or
//! GID, or ACL value is public here. An entry is named in public status
//! only by its digest.

use std::{
    fmt,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
};

use serde::Serialize;
use sha2::{Digest, Sha256};

use d2b_contracts_resource::v3::ResourceUid;

use crate::marker::{MarkerBinding, VolumeRootIdentity};

/// The opaque public identity of one layout entry.
///
/// It is derived from the Volume UID and the anchored relative entry
/// path, so it is stable across reconciles while never disclosing the
/// path itself.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntryDigest([u8; 32]);

impl EntryDigest {
    /// Derive the digest of one entry of one Volume.
    pub fn derive(volume_uid: &ResourceUid, anchored_path: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"d2b/volume-local/entry/v1");
        hasher.update(volume_uid.as_str().as_bytes());
        hasher.update([0u8]);
        hasher.update(anchored_path.as_bytes());
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hasher.finalize());
        Self(bytes)
    }

    /// Render the digest as lowercase hex.
    pub fn to_hex(self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
            out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
        }
        out
    }
}

impl fmt::Debug for EntryDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EntryDigest(<redacted>)")
    }
}

impl Serialize for EntryDigest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

/// Proof that the effect adapter resolved the Volume source policy ID
/// against its private allowlist and holds the resulting root directory
/// descriptor.
///
/// The descriptor and the resolved path never reach controller code.
/// This value is deliberately not `Clone`, not `Copy`, not `Default`, not
/// `Serialize`, and carries no accessor: it is never persisted, never
/// public status, and never crosses a Zone boundary. It is dropped and
/// re-derived after a controller restart.
pub struct VolumeRootHandle {
    pub(crate) fd: Option<OwnedFd>,
    pub(crate) marker_root_fd: Option<OwnedFd>,
    pub(crate) volume_uid: Option<ResourceUid>,
    pub(crate) marker_name: Option<String>,
    pub(crate) lock_name: Option<String>,
    pub(crate) identity: Option<VolumeRootIdentity>,
    pub(crate) marker_binding: Option<MarkerBinding>,
    pub(crate) marker_owner_uid: Option<u32>,
    pub(crate) marker_group_gid: Option<u32>,
}

/// Borrowed descriptor view exposed only to the trusted core effect adapter.
///
/// The view contains no path and cannot outlive the held root. Provider
/// controllers never receive it; they pass the opaque handle to an injected
/// effect port.
pub struct VolumeRootHandleView<'a> {
    /// The anchored Volume-root directory descriptor.
    pub fd: BorrowedFd<'a>,
    /// The broker-owned marker-root descriptor, when the marker is external.
    pub marker_root_fd: Option<BorrowedFd<'a>>,
    /// The Volume UID bound to the root.
    pub volume_uid: &'a ResourceUid,
    /// The marker filename relative to `marker_root_fd` or `fd`.
    pub marker_name: &'a str,
    /// The lock filename relative to `fd`.
    pub lock_name: &'a str,
    /// The root filesystem identity captured at resolution.
    pub identity: VolumeRootIdentity,
    /// The marker binding validated by the trusted resolver.
    pub marker_binding: &'a MarkerBinding,
    /// Expected marker owner UID.
    pub marker_owner_uid: u32,
    /// Expected marker group GID.
    pub marker_group_gid: u32,
}

impl VolumeRootHandle {
    /// Record that a validated Volume root descriptor is held.
    ///
    /// Only an effect adapter calls this, immediately after it resolved
    /// the opaque source policy ID against the private allowlist policy.
    pub const fn held() -> Self {
        Self {
            fd: None,
            marker_root_fd: None,
            volume_uid: None,
            marker_name: None,
            lock_name: None,
            identity: None,
            marker_binding: None,
            marker_owner_uid: None,
            marker_group_gid: None,
        }
    }

    /// Borrow the trusted adapter-only descriptor view.
    pub fn view(&self) -> Option<VolumeRootHandleView<'_>> {
        Some(VolumeRootHandleView {
            fd: self.fd.as_ref()?.as_fd(),
            marker_root_fd: self.marker_root_fd.as_ref().map(AsFd::as_fd),
            volume_uid: self.volume_uid.as_ref()?,
            marker_name: self.marker_name.as_deref()?,
            lock_name: self.lock_name.as_deref()?,
            identity: self.identity?,
            marker_binding: self.marker_binding.as_ref()?,
            marker_owner_uid: self.marker_owner_uid?,
            marker_group_gid: self.marker_group_gid?,
        })
    }

    /// Construct a handle from a broker-resolved anchored root.
    ///
    /// This is a trusted adapter boundary. The returned handle remains opaque
    /// to the Provider controller and is never serializable.
    pub fn from_anchored(
        fd: OwnedFd,
        marker_root_fd: Option<OwnedFd>,
        volume_uid: ResourceUid,
        marker_name: String,
        lock_name: String,
        identity: VolumeRootIdentity,
        marker_binding: MarkerBinding,
        marker_owner_uid: u32,
        marker_group_gid: u32,
    ) -> Self {
        Self {
            fd: Some(fd),
            marker_root_fd,
            volume_uid: Some(volume_uid),
            marker_name: Some(marker_name),
            lock_name: Some(lock_name),
            identity: Some(identity),
            marker_binding: Some(marker_binding),
            marker_owner_uid: Some(marker_owner_uid),
            marker_group_gid: Some(marker_group_gid),
        }
    }

    /// Borrow the broker-resolved Volume-root descriptor.
    pub fn anchored_fd(&self) -> Option<&OwnedFd> {
        self.fd.as_ref()
    }

    /// Borrow the external marker-root descriptor, when configured.
    pub fn marker_root_fd(&self) -> Option<&OwnedFd> {
        self.marker_root_fd.as_ref()
    }

    /// Borrow the Volume UID bound to this handle.
    pub fn volume_uid(&self) -> Option<&ResourceUid> {
        self.volume_uid.as_ref()
    }

    /// Borrow the marker filename relative to the marker root.
    pub fn marker_name(&self) -> Option<&str> {
        self.marker_name.as_deref()
    }

    /// Borrow the OFD lock filename relative to the Volume root.
    pub fn lock_name(&self) -> Option<&str> {
        self.lock_name.as_deref()
    }

    /// Return the root filesystem identity captured at resolution.
    pub fn root_identity(&self) -> Option<VolumeRootIdentity> {
        self.identity
    }

    /// Borrow the marker binding captured at resolution.
    pub fn marker_binding(&self) -> Option<&MarkerBinding> {
        self.marker_binding.as_ref()
    }

    /// Return the expected marker owner UID.
    pub fn marker_owner_uid(&self) -> Option<u32> {
        self.marker_owner_uid
    }

    /// Return the expected marker group GID.
    pub fn marker_group_gid(&self) -> Option<u32> {
        self.marker_group_gid
    }
}

impl fmt::Debug for VolumeRootHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VolumeRootHandle(<redacted>)")
    }
}

/// What the effect adapter could prove about the live owner of an
/// existing entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OwnerProof {
    /// The entry declares no lease, so no owner proof is required.
    NotApplicable,
    /// A live lease was verified for the declared lease class.
    Live,
    /// The lease class was verified and the owner is gone.
    Dead,
    /// The owner could not be determined. Ambiguity quarantines.
    Unknown,
}

/// Whether a `create-if-never-provisioned` marker exists for the Volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MarkerState {
    /// No prior provision was ever recorded.
    NeverProvisioned,
    /// A prior provision marker exists and matches the trusted record.
    Provisioned,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uid() -> ResourceUid {
        ResourceUid::parse("6f9619ff-8b86-4d01-b42d-00cf4fc964ff").expect("valid fixture uid")
    }

    #[test]
    fn entry_digests_are_stable_distinct_and_redacted() {
        let root = EntryDigest::derive(&uid(), "");
        let live = EntryDigest::derive(&uid(), "live");
        assert_eq!(root, EntryDigest::derive(&uid(), ""));
        assert_ne!(root, live);
        assert_eq!(root.to_hex().len(), 64);
        assert!(root.to_hex().bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(format!("{root:?}"), "EntryDigest(<redacted>)");
        assert!(!serde_json::to_string(&live).unwrap().contains("live"));
    }

    #[test]
    fn the_root_handle_is_opaque_in_diagnostics() {
        assert_eq!(
            format!("{:?}", VolumeRootHandle::held()),
            "VolumeRootHandle(<redacted>)"
        );
    }
}
