//! The volume-local effect-port seam.
//!
//! The controller validates semantics and calls these injected typed
//! ports. It never imports the broker crate, receives a broker socket or
//! DTO, resolves or opens a host path, or issues a filesystem syscall.
//! ProviderSupervisor alone maps each call onto the broker, and the
//! broker stays the sole privileged executor and independent audit owner
//! of the mutation.

use std::collections::BTreeSet;
use std::future::Future;

use serde::Serialize;

use d2b_contracts_resource::v3::execution_policy::BoundedToken;
use d2b_contracts_resource::v3::volume::SourceKind;

use crate::content::{
    ContentMaterializationEvidence, ContentProjection, NetworkConfigContentProjection,
    NetworkConfigMaterializationEvidence,
};
use crate::error::VolumeLocalError;
use crate::identity::{MarkerState, OwnerProof, VolumeRootHandle};
use crate::layout::EntryRequest;

/// One observed difference between an existing entry and its declared
/// state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum DriftClass {
    /// The owning or group principal does not match the declared one.
    Owner,
    /// The POSIX mode does not match the declared one.
    Mode,
    /// An applied ACL does not match the declared grants.
    Acl,
    /// The on-disk entry class does not match the declared entry type.
    EntryType,
    /// The entry does not share a filesystem with the Volume root.
    SameFilesystem,
}

/// What the effect adapter observed for one declared entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedEntry {
    /// Whether an entry exists at the declared anchored path.
    pub present: bool,
    /// Every observed difference from the declared state.
    pub drift: BTreeSet<DriftClass>,
    /// A symlink was met while walking to the entry.
    pub symlink_encountered: bool,
    /// Children carry ACL entries the declared ACL does not cover.
    pub foreign_children: bool,
    /// What the adapter could prove about the entry's live owner.
    pub owner_proof: OwnerProof,
}

impl ObservedEntry {
    /// A conformant, drift-free observation of an existing entry.
    pub fn conformant(owner_proof: OwnerProof) -> Self {
        Self {
            present: true,
            drift: BTreeSet::new(),
            symlink_encountered: false,
            foreign_children: false,
            owner_proof,
        }
    }

    /// An observation of an entry that does not exist.
    pub fn absent() -> Self {
        Self {
            present: false,
            drift: BTreeSet::new(),
            symlink_encountered: false,
            foreign_children: false,
            owner_proof: OwnerProof::NotApplicable,
        }
    }
}

/// Whether the backing filesystem can enforce byte and inode limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum QuotaCapability {
    /// The filesystem enforces both declared ceilings.
    Enforceable,
    /// The filesystem cannot enforce the declared ceilings.
    Unenforceable,
}

/// Resolution of the Volume's opaque source policy ID.
///
/// The controller never sees the resolved path; it receives only the
/// non-clonable root handle plus the quota capability the adapter
/// observed for that root.
pub trait VolumeSourceEffectPort: Send + Sync {
    /// Resolve the opaque source policy ID against the private allowlist
    /// policy, or resolve the selected system artifact for a Nix closure, and
    /// return proof that the root descriptor is held.
    fn resolve_root(
        &self,
        source_policy_id: Option<&BoundedToken>,
        system_artifact_id: Option<&BoundedToken>,
        kind: SourceKind,
    ) -> impl Future<Output = Result<VolumeRootHandle, VolumeLocalError>> + Send;

    /// Resolve a root while binding it to the exact Volume identity.
    ///
    /// Existing source adapters may keep using [`Self::resolve_root`]; the
    /// production adapter overrides this method so marker evidence cannot be
    /// reused across Volume UIDs.
    fn resolve_root_for(
        &self,
        _volume_uid: &d2b_contracts_resource::v3::ResourceUid,
        source_policy_id: Option<&BoundedToken>,
        system_artifact_id: Option<&BoundedToken>,
        kind: SourceKind,
    ) -> impl Future<Output = Result<VolumeRootHandle, VolumeLocalError>> + Send {
        self.resolve_root(source_policy_id, system_artifact_id, kind)
    }

    /// Report whether the resolved root can enforce hard quotas.
    fn quota_capability(
        &self,
        root: &VolumeRootHandle,
    ) -> impl Future<Output = Result<QuotaCapability, VolumeLocalError>> + Send;
}

/// The typed async layout effect port.
///
/// Implemented only by the fixed core volume effect adapter and by test
/// doubles. Every method acts on exactly one declared entry of one
/// Volume; there is no broad sweep and no recursive mutation that the
/// entry did not declare.
pub trait VolumeLayoutEffectPort: Send + Sync {
    /// Observe one declared entry without mutating it.
    fn observe(
        &self,
        root: &VolumeRootHandle,
        entry: &EntryRequest,
    ) -> impl Future<Output = Result<ObservedEntry, VolumeLocalError>> + Send;

    /// Create one declared entry.
    fn provision(
        &self,
        root: &VolumeRootHandle,
        entry: &EntryRequest,
    ) -> impl Future<Output = Result<(), VolumeLocalError>> + Send;

    /// Reconcile exactly the observed drift classes of one entry.
    fn repair(
        &self,
        root: &VolumeRootHandle,
        entry: &EntryRequest,
        drift: &BTreeSet<DriftClass>,
    ) -> impl Future<Output = Result<(), VolumeLocalError>> + Send;

    /// Re-apply the declared access and default ACLs of one entry.
    fn apply_acl(
        &self,
        root: &VolumeRootHandle,
        entry: &EntryRequest,
    ) -> impl Future<Output = Result<(), VolumeLocalError>> + Send;

    /// Remove one declared entry.
    fn cleanup(
        &self,
        root: &VolumeRootHandle,
        entry: &EntryRequest,
    ) -> impl Future<Output = Result<(), VolumeLocalError>> + Send;

    /// Read the Volume's provisioning marker.
    fn marker_state(
        &self,
        root: &VolumeRootHandle,
    ) -> impl Future<Output = Result<MarkerState, VolumeLocalError>> + Send;

    /// Publish the first-provision marker after all declared entries are
    /// durable and have been read back successfully.
    fn publish_marker(
        &self,
        _root: &VolumeRootHandle,
    ) -> impl Future<Output = Result<(), VolumeLocalError>> + Send {
        async { Ok(()) }
    }

    /// Materialize a complete typed content projection through the same
    /// anchored, locked, and atomic adapter as layout effects.
    fn materialize_content(
        &self,
        _root: &VolumeRootHandle,
        _projection: &ContentProjection,
    ) -> impl Future<Output = Result<ContentMaterializationEvidence, VolumeLocalError>> + Send {
        async { Err(VolumeLocalError::EffectFailed) }
    }

    /// Materialize the qualified Network content projection.
    fn materialize_network_config(
        &self,
        _root: &VolumeRootHandle,
        _projection: &NetworkConfigContentProjection,
    ) -> impl Future<Output = Result<NetworkConfigMaterializationEvidence, VolumeLocalError>> + Send
    {
        async { Err(VolumeLocalError::EffectFailed) }
    }
}
