//! Public Volume status projection.
//!
//! No host path, source policy ID, anchored entry path, ACL value,
//! numeric identity, export socket path, or raw adapter diagnostic is
//! public status. An entry appears only as its digest, and every reason
//! is one member of the closed error set.

use serde::Serialize;

use d2b_contracts_resource::v3::ResourceRef;
use d2b_contracts_resource::v3::execution_policy::BoundedToken;
use d2b_contracts_resource::v3::volume::{AttachmentAccess, VolumeKind};

use crate::content::NetworkConfigMaterializationEvidence;
use crate::layout::EntryCondition;

/// Coarse layout phase of a Volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LayoutPhase {
    /// Reconcile requested, no entry evaluated yet.
    Pending,
    /// Every declared entry matches its declared state.
    Ready,
    /// Recoverable drift or a quarantined entry was observed.
    Degraded,
    /// A fail-closed invariant does not hold.
    Failed,
}

impl LayoutPhase {
    /// Fold two phases, keeping the more severe one.
    pub fn worse(self, other: Self) -> Self {
        if self as u8 >= other as u8 {
            self
        } else {
            other
        }
    }
}

/// Lifecycle state of one attachment, aggregated from its Export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttachmentState {
    /// The Export has been requested but is not serving yet.
    Pending,
    /// The Export is serving and the guest mount is observed ready.
    Attached,
    /// The Export is draining before the attachment is removed.
    Detaching,
}

/// The aggregated public status of one attachment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentStatus {
    /// The Host or Guest the Volume is exported to.
    pub execution_ref: ResourceRef,
    /// The selected named view.
    pub view: BoundedToken,
    /// The admitted access level.
    pub access: AttachmentAccess,
    /// The attachment lifecycle state.
    pub state: AttachmentState,
    /// Whether the owning Export reports itself serving.
    pub export_ready: bool,
    /// Whether the guest reports the mount present.
    pub guest_mount_ready: bool,
}

/// The volume-local written Volume status projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VolumeStatusReport {
    /// The Volume Provider implementation that owns this Volume.
    pub provider: BoundedToken,
    /// The declared persistence class.
    pub kind: VolumeKind,
    /// The coarse layout phase.
    pub layout_phase: LayoutPhase,
    /// Every condition raised this pass, in declaration order.
    pub layout_conditions: Vec<EntryCondition>,
    /// One entry per declared virtiofs attachment.
    pub attachment_statuses: Vec<AttachmentStatus>,
    /// Durable evidence for a qualified content projection, when requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<NetworkConfigMaterializationEvidence>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_folding_keeps_the_more_severe_phase() {
        assert_eq!(
            LayoutPhase::Ready.worse(LayoutPhase::Degraded),
            LayoutPhase::Degraded
        );
        assert_eq!(
            LayoutPhase::Failed.worse(LayoutPhase::Degraded),
            LayoutPhase::Failed
        );
        assert_eq!(
            LayoutPhase::Ready.worse(LayoutPhase::Ready),
            LayoutPhase::Ready
        );
    }
}
