//! Security-key Device Provider contracts.
//!
//! This crate owns the catalog-derived semantic Service/Binding descriptor,
//! the unprivileged relay/frontend Process declarations, and the bounded
//! lease/session protocol. Core alone resolves the physical hidraw effect and
//! places the returned fd in the relay LaunchTicket.

#![deny(missing_docs)]

mod authority;
mod cid;
mod controller;
mod descriptor;
pub mod effect_port;
mod lease;
mod process;
pub mod relay;
mod session_ring;

pub use authority::{
    PhysicalAuthorityLease, PhysicalUsbBackingClaim, PhysicalUsbBackingToken, RelayLaunchTicket,
    SecurityKeyAdmission, SecurityKeyEffectError, SecurityKeyEffectPort, SecurityKeyOpenIntent,
};
pub use cid::{CidTranslationError, GuestCid, RelayCid, SecurityKeyCidTranslator};
pub use controller::{
    SECURITY_KEY_BINDING_FINALIZER, SECURITY_KEY_MAX_REPAIR_INTERVAL_SECS,
    SECURITY_KEY_REPAIR_INTERVAL_SECS, SECURITY_KEY_SERVICE_FINALIZER, SecurityKeyBindingAdmission,
    SecurityKeyController, SecurityKeyControllerError, SecurityKeyPhase,
    SecurityKeyReconcileOutcome, SecurityKeyReconcileResultWithChildren, SecurityKeyRunnerContract,
    security_key_runner_contract,
};
pub use descriptor::{
    SECURITY_KEY_BINDING_RESOURCE_TYPE, SECURITY_KEY_PROJECTION_PROTOCOL_VERSION,
    SECURITY_KEY_SERVICE_RESOURCE_TYPE, SecurityKeySemanticDescriptor,
    security_key_factory_fingerprint, security_key_projection_factory,
    security_key_projection_schema_fingerprint, security_key_semantic_descriptor,
};
pub use effect_port::{
    DeviceId, InventoryEffectError, InventoryObservation, ObservationPolicyId,
    SecurityKeyInventoryEffectPort,
};
pub use lease::{LeaseState, SecurityKeyLease, SecurityKeyLeaseError, SecurityKeySessionId};
pub use process::{
    FrontendProcessDeclaration, ProcessDeclarationError, RelayProcessDeclaration,
    SecurityKeyProcessRole, security_key_process_name,
};
pub use relay::{
    CEREMONY_TIMEOUT, CTAPHID_BROADCAST_CID, CTAPHID_CANCEL, CTAPHID_CBOR,
    CTAPHID_ERR_CHANNEL_BUSY, CTAPHID_ERR_INVALID_CMD, CTAPHID_ERROR, CTAPHID_INIT,
    CTAPHID_INIT_PKT_BIT, CTAPHID_KEEPALIVE, CTAPHID_MSG, CTAPHID_PING, CTAPHID_REPORT_SIZE,
    CTAPHID_WINK, CidTranslator, CtaphidContPacket, CtaphidInitPacket, CtaphidPacket,
    CtaphidReport, LeaseId, QUEUE_WAIT_TIMEOUT, SecurityKeyState, build_cancel_packet,
    build_error_report, build_init_packet, parse_ctaphid_report, recv_report, send_report,
};
pub use session_ring::{SessionRecord, SessionResult, SessionRing, SessionRingError};

/// Provider identity.
pub const PROVIDER_REF: &str = "Provider/device-security-key";
/// Device extension schema identifier.
pub const DEVICE_SECURITY_KEY_SCHEMA_ID: &str = "device-security-key.d2bus.org/Device/spec";
/// Device Provider finalizer.
pub const DEVICE_SECURITY_KEY_FINALIZER: &str = "device-security-key.d2bus.org/lease-released";
/// Stable default Host↔Guest vsock port.
pub const DEFAULT_VSOCK_PORT: u16 = 14_320;
/// Minimum bounded recent-session ring.
pub const MIN_SESSION_RING_SIZE: usize = 8;
/// Maximum bounded recent-session ring.
pub const MAX_SESSION_RING_SIZE: usize = 256;
/// Default bounded recent-session ring.
pub const DEFAULT_SESSION_RING_SIZE: usize = 32;
/// Minimum lease timeout in seconds.
pub const MIN_LEASE_TIMEOUT_SECS: u64 = 30;
/// Maximum lease timeout in seconds.
pub const MAX_LEASE_TIMEOUT_SECS: u64 = 3_600;
/// Default lease timeout in seconds.
pub const DEFAULT_LEASE_TIMEOUT_SECS: u64 = 300;
