//! The volume-virtiofs effect-port seam and public Export status.
//!
//! The controller validates semantics and calls this injected typed
//! port. It never imports the broker crate, spawns a process, binds a
//! socket, or resolves a host path. ProviderSupervisor alone maps a call
//! onto the broker, and the broker stays the sole privileged executor
//! and audit owner.

use std::future::Future;

use serde::Serialize;

use d2b_contracts_resource::v3::ResourceRef;
use d2b_contracts_resource::v3::execution_policy::BoundedToken;

use crate::error::VirtiofsExportError;
use crate::export::{ExportSpec, SocketIdentity};
use crate::worker::VirtiofsdWorkerPlan;

/// The worker the effect adapter launched for one Export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchedWorker {
    /// The Export-owned virtiofsd Process resource.
    pub process_ref: ResourceRef,
    /// The opaque identity of the private listening socket.
    pub socket: SocketIdentity,
}

/// The typed async effect port for the virtiofs Export domain.
pub trait VirtiofsExportEffectPort: Send + Sync {
    /// Launch the Export-owned virtiofsd worker.
    fn launch_worker(
        &self,
        export: &ExportSpec,
        plan: &VirtiofsdWorkerPlan,
    ) -> impl Future<Output = Result<LaunchedWorker, VirtiofsExportError>> + Send;

    /// Report whether the worker's private socket is listening.
    fn observe_socket(
        &self,
        worker: &LaunchedWorker,
    ) -> impl Future<Output = Result<bool, VirtiofsExportError>> + Send;

    /// Report whether the guest observes the mount present.
    fn observe_guest_mount(
        &self,
        export: &ExportSpec,
    ) -> impl Future<Output = Result<bool, VirtiofsExportError>> + Send;

    /// Check the zero-length store-view marker before a ro-store launch.
    ///
    /// Adapters must explicitly prove the marker. A missing implementation
    /// fails closed instead of permitting a store-view worker launch.
    fn observe_store_view_marker(
        &self,
        _export: &ExportSpec,
    ) -> impl Future<Output = Result<bool, VirtiofsExportError>> + Send {
        async { Ok(false) }
    }

    /// Delete the Export-owned worker and its Endpoint.
    fn delete_worker(
        &self,
        worker: &LaunchedWorker,
    ) -> impl Future<Output = Result<(), VirtiofsExportError>> + Send;
}

/// Coarse lifecycle phase of one Export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExportPhase {
    /// The worker exists but the share is not serving yet.
    Pending,
    /// The socket is listening and the guest mount is present.
    Ready,
    /// The socket is listening but the guest mount is not observed.
    Degraded,
    /// A frozen invariant does not hold; nothing was launched.
    Failed,
}

/// The volume-virtiofs written Export status projection.
///
/// It carries the opaque socket identity, never the socket path, and no
/// shared directory, argv, unit name, or numeric identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportStatusReport {
    /// The Provider implementation that owns this Export.
    pub provider: BoundedToken,
    /// The coarse lifecycle phase.
    pub phase: ExportPhase,
    /// Whether the worker reports itself serving.
    pub export_ready: bool,
    /// Whether the guest reports the mount present.
    pub guest_mount_ready: bool,
    /// The Export-owned worker Process, when one exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_process_ref: Option<ResourceRef>,
    /// The opaque identity of the private listening socket.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socket: Option<SocketIdentity>,
    /// The condition code when the Export is not Ready.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "serialize_reason")]
    pub reason: Option<VirtiofsExportError>,
}

fn serialize_reason<S: serde::Serializer>(
    reason: &Option<VirtiofsExportError>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match reason {
        Some(reason) => serializer.serialize_str(reason.code()),
        None => serializer.serialize_none(),
    }
}
