//! The volume-virtiofs attachment Provider.
//!
//! `Provider/volume-virtiofs` reconciles `virtiofs.d2bus.org.Export`
//! resources, not Volume resources. For each Export it ensures exactly
//! one Export-owned virtiofsd worker Process and one stable Endpoint,
//! observes their readiness, and writes Export status. volume-local
//! alone reads that status and writes the aggregated Volume attachment
//! status.
//!
//! What this crate deliberately does not do, because
//! `ADR-046-resources-volume` forbids it: it never writes a Volume row,
//! never performs a privileged mutation, never spawns a process, never
//! binds a socket, and never resolves a host path. It calls the injected
//! [`VirtiofsExportEffectPort`]; ProviderSupervisor alone maps that call
//! onto the broker.
//!
//! The virtiofsd sandbox posture is frozen by ADR 0021 and is asserted
//! before any launch: zero host capabilities, no start as root, a chroot
//! sandbox, a read-only root, and `--inode-file-handles=never`. There is
//! no free-form virtiofsd argument channel.
//!
//! The export socket path is a generated private implementation detail.
//! Only its opaque identity is public; the path never appears in a spec,
//! a status field, an audit record, or CLI output.

#![deny(missing_docs)]

mod controller;
mod error;
mod export;
mod port;
mod readiness;
mod socket_path;
mod user_ns;
mod virtiofsd_argv;
mod worker;

pub mod testing;

pub use controller::{
    VirtiofsExportController, VirtiofsRunnerContract, resolve_view, virtiofs_runner_contract,
};
pub use error::VirtiofsExportError;
pub use export::{EXPORT_FINALIZER, EXPORT_RESOURCE_TYPE, ExportSpec, SocketIdentity};
pub use port::{ExportPhase, ExportStatusReport, LaunchedWorker, VirtiofsExportEffectPort};
pub use readiness::{
    GuestMountObservation, SocketObservation, StoreViewMarkerObservation, classify_readiness,
    require_store_view_marker,
};
pub use socket_path::{MAX_SOCKET_PATH_BYTES, PrivateSocketPath, SocketPathError};
pub use user_ns::{
    CLONE_NEWNS_FLAG, CLONE_NEWUSER_FLAG, MappingStep, UserNamespaceError, UserNamespaceTemplate,
    validate_clone3_flags, validate_mapping_order,
};
pub use virtiofsd_argv::{
    SocketGroup, VirtiofsdArgvError, VirtiofsdArgvInput, VirtiofsdCacheMode,
    generate_virtiofsd_argv,
};
pub use worker::{
    INODE_FILE_HANDLES, SANDBOX_MODE, USER_NAMESPACE_MAPPING_CLASS, VirtiofsdWorkerPlan,
    WORKER_TEMPLATE, WorkerSandbox,
};
