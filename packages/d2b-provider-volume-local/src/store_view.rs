//! Store-view mode: the per-Guest closure-only hardlink farm.
//!
//! The canonical layout follows the shipped hardlink farm rather than the
//! older path-row emitter: `gcroots/` and `state/` sit at the store-view
//! root, not under `meta/`. The guest is served the farm at `live/`; it
//! is never served the host store.

use d2b_contracts_resource::v3::ResourceUid;
use d2b_contracts_resource::v3::execution_policy::BoundedToken;
use d2b_contracts_resource::v3::volume::{
    AttachmentAccess, CleanupPolicy, EntryType, LayoutEntry, VolumeSpec,
};

use crate::error::VolumeLocalError;
use crate::layout::EntryRequest;
use crate::views::resolve_view;

/// The hardlink farm root that virtiofsd serves to the guest.
pub const LIVE_DIR: &str = "live";
/// The generation metadata tree.
pub const META_DIR: &str = "meta";
/// The per-generation metadata directory.
pub const GENERATIONS_DIR: &str = "meta/generations";
/// The symlink naming the current generation.
pub const CURRENT_LINK: &str = "meta/current";
/// The host-only per-generation state tree; never served to the guest.
pub const STATE_DIR: &str = "state";
/// The GC root tree, at the store-view root and never under `meta/`.
pub const GCROOTS_DIR: &str = "gcroots";
/// The store-sync advisory lock file, which is never unlinked.
pub const SYNC_LOCK: &str = "sync.lock";
/// The store-view path that is never a valid layout entry, because the
/// GC roots live at the store-view root.
pub const REJECTED_GCROOTS_DIR: &str = "meta/gcroots";

/// The readiness marker path for one Guest's farm.
pub fn marker_path(guest: &BoundedToken) -> String {
    format!("{LIVE_DIR}/.d2b-marker-{}", guest.as_str())
}

fn entry<'spec>(spec: &'spec VolumeSpec, path: &str) -> Option<&'spec LayoutEntry> {
    spec.layout().iter().find(|entry| entry.path() == path)
}

fn require<'spec>(
    spec: &'spec VolumeSpec,
    path: &str,
    expected: EntryType,
) -> Result<&'spec LayoutEntry, VolumeLocalError> {
    let found = entry(spec, path).ok_or(VolumeLocalError::InvariantViolated)?;
    if found.entry_type() == expected {
        Ok(found)
    } else {
        Err(VolumeLocalError::InvariantViolated)
    }
}

/// Check that a Volume declares the canonical store-view layout.
///
/// This is a fail-closed shape check, not a repair: a store-view Volume
/// whose layout drifts from the farm contract is rejected before any
/// effect is requested.
pub fn assert_store_view_layout(
    volume_uid: &ResourceUid,
    spec: &VolumeSpec,
    guest: &BoundedToken,
) -> Result<(), VolumeLocalError> {
    require(spec, "", EntryType::Directory)?;
    require(spec, LIVE_DIR, EntryType::Directory)?;
    require(spec, META_DIR, EntryType::Directory)?;
    require(spec, GENERATIONS_DIR, EntryType::Directory)?;
    require(spec, STATE_DIR, EntryType::Directory)?;
    require(spec, GCROOTS_DIR, EntryType::Directory)?;
    require(spec, &marker_path(guest), EntryType::File)?;

    if entry(spec, REJECTED_GCROOTS_DIR).is_some() {
        return Err(VolumeLocalError::InvariantViolated);
    }

    let current = require(spec, CURRENT_LINK, EntryType::Symlink)?;
    let target = current
        .target()
        .ok_or(VolumeLocalError::InvariantViolated)?;
    if target != "generations" && !target.starts_with("generations/") {
        return Err(VolumeLocalError::InvariantViolated);
    }

    let lock = require(spec, SYNC_LOCK, EntryType::File)?;
    let lock = EntryRequest::resolve(volume_uid, lock)?;
    if lock.cleanup_policy() != CleanupPolicy::Never {
        return Err(VolumeLocalError::InvariantViolated);
    }
    Ok(())
}

/// Check that every store-view attachment serves the farm read-only.
///
/// The guest receives `live/` and nothing above it, so the host store can
/// never be exported through a store-view Volume.
pub fn assert_ro_store_attachment(spec: &VolumeSpec) -> Result<(), VolumeLocalError> {
    for attachment in spec.attachments() {
        let view = resolve_view(spec, attachment.view())?;
        if view.path() != LIVE_DIR {
            return Err(VolumeLocalError::InvariantViolated);
        }
        if attachment.access() != AttachmentAccess::ReadOnly {
            return Err(VolumeLocalError::InvariantViolated);
        }
    }
    Ok(())
}

/// Read-only evidence for the store-view launch marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreViewMarkerEvidence {
    /// The marker file exists.
    pub present: bool,
    /// The marker file has zero length.
    pub zero_length: bool,
}

/// Read-only observations needed before a store-view sync or Export launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreViewObservation {
    /// `/nix/store` and the Volume root have equal device identity.
    pub same_filesystem: bool,
    /// The live readiness marker exists and has zero length.
    pub marker_zero_length: bool,
    /// The OFD lock file exists and has not been replaced.
    pub sync_lock_preserved: bool,
    /// `gcroots/` is at the store-view root.
    pub gcroots_at_root: bool,
    /// `state/` is at the store-view root.
    pub state_at_root: bool,
}

/// Validate the runtime store-view posture before serving it.
pub fn validate_store_view_observation(
    observation: StoreViewObservation,
) -> Result<(), VolumeLocalError> {
    if !observation.same_filesystem {
        return Err(VolumeLocalError::InvariantViolated);
    }
    if !observation.marker_zero_length {
        return Err(VolumeLocalError::StoreViewMarkerMissing);
    }
    if !observation.sync_lock_preserved
        || !observation.gcroots_at_root
        || !observation.state_at_root
    {
        return Err(VolumeLocalError::InvariantViolated);
    }
    Ok(())
}

/// The bounded decision made before a store-view worker launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreViewAction {
    /// The marker is not ready; the caller should requeue.
    WaitForMarker,
    /// The farm may be synchronized and served.
    Serve,
    /// A hard invariant failed.
    Fail,
}

/// Classify a store-view observation without exposing any path.
pub fn classify_store_view(
    observation: StoreViewObservation,
) -> Result<StoreViewAction, VolumeLocalError> {
    if !observation.marker_zero_length {
        return Ok(StoreViewAction::WaitForMarker);
    }
    validate_store_view_observation(observation)?;
    Ok(StoreViewAction::Serve)
}
