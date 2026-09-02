//! The volume-local Volume Provider.
//!
//! `Provider/volume-local` is the sole writer of the `Volume`
//! ResourceType: it owns the layout engine, named views, attachment
//! admission, store-view mode, and TPM state mode. It reconciles the
//! declared layout through an injected effect port and never performs the
//! mutation itself.
//!
//! What this crate deliberately does not do, because
//! `ADR-046-resources-volume` forbids it for a Provider: it performs no
//! privileged mutation, opens no broker socket, resolves no host path,
//! issues no filesystem syscall, and never learns what a
//! `sourcePolicyId` resolves to. The controller passes the opaque ID to
//! the injected [`VolumeSourceEffectPort`]; ProviderSupervisor alone
//! validates it against the private allowlist policy and hands back a
//! non-clonable root handle, and the broker remains the sole privileged
//! executor and audit owner of every layout mutation.
//!
//! No host path, source policy ID, numeric UID or GID, device node,
//! store path, or socket path appears in any type here. A layout entry
//! travels through public status only as an opaque digest.

#![deny(missing_docs)]

mod acl;
mod content;
mod controller;
mod error;
mod exports;
mod finalization;
mod identity;
mod layout;
mod port;
mod quota;
mod source;
mod status;
mod store_view;
mod swtpm_volume;
mod views;

pub mod atomic;
pub mod audit;
pub mod diagnostics;
pub mod effect_port;
pub mod lock;
pub mod marker;
pub mod migration;
pub mod otel;
pub mod path;
pub mod relocation;
pub mod sealing;
pub mod snapshot;
pub mod testing;

pub use acl::{
    AclAction, AclBinding, AclGrantSummary, AclObservation, plan_acl_reconciliation,
    user_revision_changed,
};
pub use content::{
    ContentFile, ContentFileEvidence, ContentMaterializationEvidence, ContentProjection,
    ContentProvenance, GENERIC_CONTENT_SCHEMA_ID, MAX_CONTENT_BYTES, MAX_CONTENT_FILES,
    MAX_CONTENT_PATH_BYTES, MAX_NETWORK_CONFIG_CONTENT_BYTES, NETWORK_CONFIG_CONTENT_KIND,
    NETWORK_CONFIG_FILE_MODE, NETWORK_CONFIG_FILE_OWNER, NetworkConfigContentProjection,
    NetworkConfigMaterializationEvidence, ObservedContentFile, VOLUME_CONTENT_SCHEMA_ID,
    VOLUME_CONTENT_SCHEMA_VERSION,
};
pub use controller::{
    VOLUME_FINALIZER, VolumeLocalController, VolumeLocalProfile, VolumeRunnerContract,
    volume_runner_contract,
};
pub use error::VolumeLocalError;
pub use exports::{EXPORT_RESOURCE_TYPE, ExportIntent, desired_export_intents};
pub use finalization::{
    FinalizationAction, FinalizationObservation, FinalizationResult, finalization_plan,
};
pub use identity::{EntryDigest, MarkerState, OwnerProof, VolumeRootHandle, VolumeRootHandleView};
pub use layout::{
    ConditionSeverity, EntryCondition, EntryPlan, EntryRequest, plan_cleanup, plan_entry,
};
pub use port::{
    DriftClass, ObservedEntry, QuotaCapability, VolumeLayoutEffectPort, VolumeSourceEffectPort,
};
pub use quota::{QuotaUsage, QuotaUsageDecision, admit_quota, check_usage, usage_error};
pub use source::{
    BlockImagePlan, SourcePolicy, SourcePolicyCatalog, TmpfsMountOptions, validate_source_spec,
};
pub use status::{AttachmentState, AttachmentStatus, LayoutPhase, VolumeStatusReport};
pub use store_view::{
    CURRENT_LINK, GCROOTS_DIR, GENERATIONS_DIR, LIVE_DIR, META_DIR, REJECTED_GCROOTS_DIR,
    STATE_DIR, SYNC_LOCK, StoreViewAction, StoreViewMarkerEvidence, StoreViewObservation,
    assert_ro_store_attachment, assert_store_view_layout, classify_store_view, marker_path,
    validate_store_view_observation,
};
pub use swtpm_volume::{SwtpmDisposition, assert_swtpm_volume, evaluate_swtpm_state};
pub use views::{AttachmentPlan, admit_access, admit_attachments, is_read_only, resolve_view};
