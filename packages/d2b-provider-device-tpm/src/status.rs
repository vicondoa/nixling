//! Redacted Device TPM status projection.

use d2b_contracts_resource::v3::{ResourceRef, ResourceUid};
use serde::Serialize;

use crate::resource_controller::TpmResourcePhase;

/// Marker posture visible to the Device status builder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TpmMarkerStatus {
    /// Core has not observed a prior provision.
    NeverProvisioned,
    /// The broker marker matches the retained state Volume.
    Verified,
    /// A previously provisioned marker is absent.
    Missing,
    /// The retained state identity changed.
    Replaced,
    /// The marker payload failed validation.
    Tampered,
}

/// Public Device TPM status. No path, PID, socket, marker bytes, or UID/GID
/// appears in this projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpmStatusReport {
    /// Universal Provider phase.
    pub phase: TpmResourcePhase,
    /// The retained Device-owned state Volume.
    pub state_volume_ref: Option<ResourceRef>,
    /// The Device-owned swtpm Process.
    pub swtpm_process_ref: Option<ResourceRef>,
    /// The most recent pre-start flush Process.
    pub last_flush_ref: Option<ResourceRef>,
    /// The Device-owned TPM Endpoint.
    pub tpm_endpoint_ref: Option<ResourceRef>,
    /// Marker posture.
    pub marker_status: TpmMarkerStatus,
    /// Stable condition code, when degraded or failed.
    pub condition: Option<&'static str>,
}

impl TpmStatusReport {
    /// Construct a pending status with no endpoint.
    pub fn pending(_device_ref: ResourceUid) -> Self {
        Self {
            phase: TpmResourcePhase::Pending,
            state_volume_ref: None,
            swtpm_process_ref: None,
            last_flush_ref: None,
            tpm_endpoint_ref: None,
            marker_status: TpmMarkerStatus::NeverProvisioned,
            condition: None,
        }
    }
}
