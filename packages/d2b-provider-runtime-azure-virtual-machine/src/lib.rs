//! Canonical `Provider/runtime-azure-virtual-machine` implementation.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod audit;
pub mod bootstrap;
pub mod bootstrap_svc;
pub mod config;
pub mod controller;
pub mod effect;
pub mod error;
pub mod idempotency;
pub mod telemetry;

pub use bootstrap::{BootstrapAdmission, BootstrapAdmissionState, BootstrapPsk};
pub use bootstrap_svc::{BootstrapService, BootstrapServiceState};
pub use config::{
    AzureVmConfig, AzureVmGuestSettings, BootstrapPskDelivery, DataDiskSpec, DiskSku,
};
pub use controller::{
    AzureVmClock, AzureVmController, AzureVmPhase, AzureVmReconcileOutcome, AzureVmRecoveryState,
    AzureVmStatus, AzureVmUpdate, AzureVirtualMachineRunnerContract, SystemAzureVmClock,
    AZURE_VM_GUEST_FINALIZER, AZURE_VM_REPAIR_INTERVAL_SECS,
    azure_virtual_machine_runner_contract,
};
pub use effect::{
    AzureAccessToken, AzureCredentialPort, AzureEffectPort, AzureOperationHandle, AzureVmHandle,
    AzureVmState, LroStatus, PskExtensionPayload, TagDigest,
};
pub use error::AzureVmError;

/// Stable Provider implementation identifier.
pub const AZURE_VM_IMPLEMENTATION_ID: &str = "azure-vm";
/// Stable Provider resource reference.
pub const PROVIDER_REF: &str = "Provider/runtime-azure-virtual-machine";
/// Stable Guest finalizer.
pub const FINALIZER: &str = AZURE_VM_GUEST_FINALIZER;
