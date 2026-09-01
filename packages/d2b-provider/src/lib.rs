//! The v3 Provider model surface: descriptors, registry, session identity,
//! and forwarding admission.
//!
//! This crate is the Zone-side Provider registry. It holds one registry
//! generation per Zone, admits authenticated calls against it, drains and
//! retires a generation, and republishes a replacement live. It is adapted
//! from the ADR45 `d2b-provider` registry: the lifecycle, in-flight
//! accounting, RAII permit, drain-waiter notify race, and live-swap manager
//! are carried over, while the identity is now the Zone's
//! [`ZonePath`](d2b_contracts_zone_session::v3::zone_routing::ZonePath) plus an
//! authenticated Zone principal rather than a realm and a peer role.
//!
//! What this crate deliberately does not do. It performs no host mutation and
//! opens no socket: a Provider never mutates host state directly, and every
//! privileged effect belongs to a typed, audited broker op reached through an
//! injected effect port in a Provider implementation crate. No public type
//! here carries a numeric UID or GID, a device node, a store path, a socket
//! path, or any host path; a Provider is named only by its Zone path and its
//! `Provider/<name>` reference. No type here carries authority: an
//! [`InFlightPermit`] is a concurrency slot, and forwarding admissions are
//! runtime-issued route evidence, not transferable capabilities.
//!
//! It also does not name the Provider trait-object catalog. Rather than
//! inventing a universal RPC or proxy surface, [`ProviderRegistry`] is
//! generic over the Zone runtime's own instance handle, and [`ProviderClass`]
//! preserves the eleven frozen Provider families as a discriminant.

#![deny(missing_docs)]

pub mod agent;
mod context;
mod descriptor;
mod error;
mod forwarding;
mod identity;
mod installation;
mod operation_ledger;
mod registry;
mod session;
pub mod share_adapter;

pub mod instance;

pub use agent::{
    MAX_AGENT_AUDIT_EVENTS, MAX_AGENT_IN_FLIGHT, MAX_AGENT_TIMEOUT_MS, ProviderAgent,
    ProviderAgentAuditEvent, ProviderAgentError, ProviderAgentMessage, ProviderAgentOutcome,
    ProviderAgentRequest, ProviderAgentResponse, ProviderAgentService,
};
pub use context::{CancellationToken, OwnedOperationContext};
pub use descriptor::{
    DEFAULT_REPAIR_INTERVAL_MS, MAX_AUDIO_NOTIFICATION_REPAIR_WINDOW_MS,
    MAX_DEVICE_REPAIR_WINDOW_MS, MAX_REPAIR_WINDOW_MS, ProviderDescriptor, RepairPolicy,
};
pub use error::{ProviderRuntimeError, RegistryBuildError};
pub use forwarding::{
    ForwardTarget, ForwardedCall, ProviderForwardRequest, ZoneRouteFailClosedReason,
    admit_provider_forward,
};
pub use identity::{
    MAX_PROVIDER_CAPABILITIES, MAX_PROVIDER_REGISTRY_ENTRIES, PROVIDER_RESOURCE_TYPE,
    PROVIDER_SCHEMA_VERSION, ProviderCapabilitySet, ProviderClass, ProviderImplementationId,
    ProviderMethodName,
};
pub use installation::{
    InstalledProvider, ProviderReadiness, RequiredProviderApi, TargetInstallProfile,
    admit_installation, admit_installation_for_target,
};
pub use operation_ledger::{
    MAX_OPERATION_LEDGER_ROWS, OperationLedger, OperationLedgerAdmission, OperationLedgerError,
    OperationLedgerRow, OperationLedgerState,
};
pub use registry::{
    AdmissionOptions, AdmittedProvider, InFlightPermit, MAX_REGISTRY_DRAIN_MS, ProviderRegistry,
    ProviderRegistryBuilder, ProviderRegistryManager, ProviderRegistrySnapshot,
    RegistryDrainPolicy, RegistryLifecycle, RegistryLimits, RegistryShutdownReport,
};
pub use session::SessionIdentity;
pub use share_adapter::{
    ExportAdapter, ImportAdapter, ShareAdapter, ShareAdapterError, admit_binding_target,
    admit_export, admit_factory_pair, admit_import, projection_protocol_version, service_type,
};
