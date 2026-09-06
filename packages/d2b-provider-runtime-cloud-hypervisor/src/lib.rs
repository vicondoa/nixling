//! Canonical `Provider/runtime-cloud-hypervisor` implementation.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

use d2b_contracts_resource::v3::ResourceRef;

pub mod adoption;
pub mod audit;
pub mod bootstrap_graph;
pub mod config;
pub mod controller;
mod controller_session;
pub mod descriptor;
pub mod guest_local;
pub mod health;
pub mod identity;
pub mod metrics;
pub mod shutdown;
pub mod state;

pub use adoption::{
    AdoptionObservationError, AdoptionOutcome, ProcessAdoptionStatus, ProcessIdentity,
    ProcessObservation,
};
pub use bootstrap_graph::{
    BootstrapGraph, DependencyReadiness, GuestChildGraphPlan, VmmLifecycleEligibility,
};
pub use config::{CloudHypervisorConfig, CloudHypervisorGuestSettings, ConsoleType};
pub use controller::{
    CLOUD_HYPERVISOR_REPAIR_INTERVAL_SECS, CloudHypervisorRunnerContract,
    GUEST_CONTROLLER_FINALIZER, cloud_hypervisor_runner_contract,
};
pub use controller::{
    AuthenticatedResourceApiAdapter, AuthenticatedResourceSession, ChildSpecUpdate,
    CloudHypervisorController, CloudHypervisorControllerRegistration, CloudHypervisorError,
    CloudHypervisorReconcileOutcome, CloudHypervisorResourceApi, CloudHypervisorResourceApiError,
    CloudHypervisorResourceRequest, CloudHypervisorResourceResponse, GuestChildCommitResponse,
    GuestChildCreateBatch, GuestCondition, GuestDependencySnapshot, GuestSnapshot,
    GuestStatusProjection, OwnedChildSnapshot,
};
pub use descriptor::{
    BootstrapHandoff, DescriptorSignature, GuestSeedContract, GuestSetupDescriptor,
    GuestSetupDescriptorError, GuestSetupDescriptorVerifier, OpaqueDescriptorSignature,
    SignatureAlgorithm, VerifiedGuestSetupDescriptor,
};
pub use guest_local::{
    GUEST_SEED_RESOURCE_TYPES, GuestControlEndpoint, GuestControlEndpointResolver,
    GuestControlSessionConnector, GuestLocalController, GuestLocalError,
    GuestLocalReconcileOutcome, GuestLocalResourceStatus, GuestLocalSeedBatch,
    GuestLocalSeedResource, GuestLocalSeedResourceError, GuestLocalSeedResult, GuestLocalSession,
    GuestLocalSessionBinding, GuestLocalSessionExpectation, GuestLocalStatus, GuestLocalWatch,
};
pub use health::{
    GuestSessionError, GuestSessionEvidence, GuestSessionEvidenceBinding,
    GuestSessionEvidenceProbe, GuestSessionHealth,
};
pub use identity::{
    ChildCreateBody, ChildIdentityError, ChildMutation, ChildRole, ChildRoleSet,
    CommitResponseError, CommittedChild, CommittedChildren, CreatePrecondition, EndpointCreateBody,
    GuestChildBatch, ProcessCreateBody, VolumeCreateBody, deterministic_child_name,
    deterministic_child_ref, map_commit_response, map_wire_commit_response,
};
pub use shutdown::{
    FencedChild, FinalizationBlockReason, FinalizationDisposition, FinalizationStep,
    GuestFinalizationInput, GuestFinalizationPlan, GuestUpgradePlan, LifecyclePlanError,
    ProcessState, SessionState, UpgradeReason, child_role_for_ref, plan_finalization, plan_upgrade,
    session_generation_is_fresh,
};
pub use state::{
    GuestGenerationSet, GuestRuntimeStatus, GuestStatusObservation, GuestStatusPhase,
    finalization_eligible, reduce_status,
};

/// Stable Provider implementation identifier.
pub const CLOUD_HYPERVISOR_IMPLEMENTATION_ID: &str = "cloud-hypervisor";
/// Stable Provider resource reference.
pub const PROVIDER_REF: &str = "Provider/runtime-cloud-hypervisor";
/// Controller Process role declared by the Provider contract.
pub const CONTROLLER_ROLE_REF: &str = "Process/cloud-hypervisor-controller";
/// Controller binary declared by the Provider manifest.
pub const CONTROLLER_BINARY: &str = "d2b-cloud-hypervisor-controller";
/// Exit status used when authenticated controller-session wiring fails.
pub const RUNTIME_UNAVAILABLE_EXIT: i32 = 78;

/// Return whether a ResourceRef names this Provider implementation.
pub fn is_provider_ref(reference: &ResourceRef) -> bool {
    reference.resource_type().as_str() == "Provider"
        && reference.name().as_str() == "runtime-cloud-hypervisor"
}

/// Parse the canonical Provider manifest packaged with this Provider.
pub fn provider_manifest() -> Result<d2b_contracts_provider::v3::ProviderManifest, serde_json::Error>
{
    serde_json::from_slice(include_bytes!("../provider-manifest.json"))
}

/// Enter the controller role.
pub fn controller_binary_entrypoint() -> i32 {
    controller_session::run_from_fd10()
}
