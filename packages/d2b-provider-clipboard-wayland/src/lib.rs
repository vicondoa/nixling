//! Zone-scoped clipboard mediation behind the display Provider boundary.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod audit;
mod controller;
mod descriptor;
mod fd;
mod history;
mod picker;
mod policy;
mod rbac;
mod runtime;
mod service;

pub use audit::{
    ClipboardAuditEvent, ClipboardAuditQueue, ClipboardAuditSink, ClipboardEventType,
    ClipboardReason, SizeBucket,
};
pub use controller::{
    ClipboardController, ClipboardRunnerContract, DependencyStatus, DisplayDependencyEvidence,
    ProcessPlan, clipboard_runner_contract,
};
pub use descriptor::{ClipboardDescriptorError, ClipboardProviderDescriptor};
pub use fd::{
    AcceptedTransferFdKind, AttachmentClass, FdAccessMode, FdCapModel, FdMetadata, FdObjectKind,
    FdPermitPool, FdReadError, FdSafetyError, FdStatModel, FileSystemKind, ReceivedFdBatch,
    classify_fd_model, inspect_fd, read_bounded, read_owned_fd_bounded, validate_fd_cap,
    validate_fd_metadata, validate_received_fd, validate_recvmsg_control,
};
pub use history::{ClipboardEntry, ClipboardHistory, HistoryError};
pub use picker::{PickerAuthority, PickerError, PickerReceipt, PickerRequest, PickerResult};
pub use policy::{ALLOWED_MIME_TYPES, ClipboardPolicyError, Policy, SECRET_HINT_MIME_TYPES};
pub use rbac::{ClipboardRbac, ClipboardRole, ClipboardRoleBinding};
pub use runtime::{
    ClipboardFinalizationReport, ClipboardProcessEffectPort, ClipboardRuntime,
    ClipboardRuntimeError,
};
pub use service::{
    AuthenticatedClipboardSession, AuthenticatedPasteRoute, ClipboardBridgePort, ClipboardConfig,
    ClipboardServiceError, ClipboardServiceRole, ClipdHost, DisplayDependency, GuestSelectionEvent,
    VerifiedClipboardAttachments,
};

/// Canonical Provider reference.
pub const PROVIDER_REF: &str = "Provider/clipboard-wayland";
/// Canonical display Provider dependency reference.
pub(crate) const DISPLAY_PROVIDER_REF: &str = "Provider/display-wayland";
/// Canonical Provider artifact identifier.
pub const ARTIFACT_ID: &str = "clipboard-wayland";
/// Canonical clipboard bridge service package.
pub const BRIDGE_SERVICE: &str = "d2b.clipboard.bridge.v3";
/// Canonical picker coordination service package.
pub const PICKER_SERVICE: &str = "d2b.clipboard.picker-coord.v3";
/// Fixed clipboard management service package.
pub const MANAGEMENT_SERVICE: &str = "d2b.clipboard.v3";
/// Attachment class for Guest clipboard transfer.
pub const CLIPBOARD_TRANSFER_FD: &str = "clipboard-transfer-fd";
/// Attachment class for host selection reads.
pub const HOST_SELECTION_TRANSFER_FD: &str = "host-selection-transfer-fd";
/// Attachment class for host selection writes.
pub const HOST_SELECTION_SUPPLY_FD: &str = "host-selection-supply-fd";
