//! Production Zone resource-plane ownership for `d2bd`.
//!
//! A Zone runtime is opened only from the broker's opaque
//! [`d2b_contracts_broker::broker_wire::OpenZoneStoreRequest`]. The broker owns path
//! resolution and returns one
//! close-on-exec database descriptor; this module consumes that descriptor
//! into the production redb backend and never opens a caller-supplied path.
//! The runtime owns the API, core-process readiness, and restart lifecycle as
//! one Zone-scoped value.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    os::fd::{AsRawFd, OwnedFd},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};

use crate::activation_resource_runtime::{
    activation_controller_descriptor, ActivationResourceReconciler, stored_resource_from_wire,
};
use crate::ServerState;
use d2b_contracts::types::{BundleOpId, VmId};
use crate::audio_resource_runtime::{
    AUDIO_BINDING_TYPE, AudioBindingRuntimeStatus, AudioResourceRuntime, AudioResourceRuntimeError,
    audio_binding_status_projection_with_status, audio_binding_status_value, list_audio_resources,
    list_audio_snapshot,
};
use crate::binding_child_resource_runtime::{
    OneOwnedChildProgress, OwnedChildOwner, reconcile_binding_children,
    reconcile_one_guest_child,
};
use crate::process_resource_runtime::{
    ProcessResourceReconciler, ProcessResourceRuntime, ProcessResourceRuntimeError,
    controller_provider_refs, list_process_snapshot, process_controller_descriptor,
};
use crate::semantic_binding_resource_runtime::{
    reconcile_semantic_binding_resources, run_device_binding_watch, device_binding_watch_request,
    telemetry_controller_descriptor, TelemetryResourceReconciler,
};
use async_trait::async_trait;
use d2b_audit::{AuditSink, DurabilityEvidence};
use d2b_bus::{
    BusAuthorizer, BusConfig, BusIngress, CommittedControllerProcessSubjectInput,
    CommittedInteractionSubjectInstall, CommittedInteractionSubjectIssuer, ZoneBus, ZoneRegistrar,
};
#[cfg(test)]
use d2b_contracts_broker::broker_wire::OpenZoneStoreResponse;
use d2b_contracts_broker::broker_wire::ZoneStoreDisposition;
use d2b_contracts_broker::broker_wire::BrokerCallerRole;
use d2b_contracts_provider::v3::provider::ProviderSpec;
use d2b_contracts_resource::resource_proto as wire;
#[cfg(test)]
use d2b_contracts_resource::v3::ConfigurationGeneration;
use d2b_contracts_resource::v3::identity::{
    AuthenticatedSubjectContext, BindingDigest, EvidenceClass, ReconnectGeneration,
};
use d2b_contracts_resource::v3::{
    CanonicalJsonValue, ControllerGeneration, DesiredLifecycle,
    PlacementTargetKind, ResourceBundleGenerationId, ResourceEnvelope, ResourceGeneration,
    ResourceName, ResourcePhase, ResourceRef, ResourceTypeName, ResourceUid, ZoneId, ZoneRevision,
    canonical_digest,
    network::NetworkProvenance,
    process::ProcessSpec,
    volume::{EntryType, VolumeSpec},
};
use d2b_contracts_resource::v3::{
    guest::GuestSpec,
    host::{HOST_PROVIDER_REF, HostSpec},
    user::UserSpec,
};
use d2b_contracts_zone_session::v3::{ZoneStatusResource, resource_bundle::ResourceBundle};
use d2b_core_controller::authority::{
    AuthorityLease, AuthorityRequest, AuthorityReservation, ExternalNicClaimRequest, ExternalNicRecoveryInventory,
    ExternalNicReservation, HostGlobalAuthorityIndex, TrustedExternalNicInventory,
};
use d2b_core_controller::authority_persistence::AuthorityRecoveryCoordinator;
use d2b_core_controller::controller_assignment::{
    AssignmentError, AssignmentIdentity, AssignmentPhase, AssignmentRequest, AssignmentTarget,
    CONTROLLER_ASSIGNMENT_STREAM_CREDIT, CONTROLLER_ASSIGNMENT_STREAM_ID,
    ControllerAssignmentGrant, ControllerRoleContract, ControllerSessionBinding,
    ResourceClientLease,
};
use d2b_core_controller::controllers::HandlerPhase;
use d2b_core_controller::{
    CORE_RESOURCE_CONTROLLER_REGISTRATIONS, ChangeField, ControllerDescriptor,
    ControllerExecutionPolicy, ControllerIdentity, ControllerSelector, ControllerVerb,
    CoreControllerSource, CoreResourceReconciler, DependencySnapshot, DisruptionClass, DrainResult,
    FinalizeResult, ObservationResult, ReconcileContext, ReconcileDisposition, ReconcilePlan,
    ReconcileReason, ReconcileResult, ResourceKey, ResourceMutationBatch, ResourceReconciler,
    ResourceRegistration, ResourceSnapshot, ResyncPolicy, Runner, RunnerConfig, SelectorField,
    SourceError, StatusPersistence, TriggerReason, UpdateAssessment, UpdateAssessmentState,
    UpgradePlan, UpgradeStage, ValidationResult, core_controller_descriptors, OwnedChildIntent,
};
use d2b_core_controller::main::{
    CoreProcess, RecoverySnapshot, RuntimeReadiness as CoreRuntimeReadiness, StartupStage,
};
use d2b_core_controller::migration::LegacyTpmMigrationDecision;
use d2b_core_controller::zone_status::{
    SystemCoreStatusEmitter, ZoneRuntimeMetadata, ZoneStatusInput,
};
use d2b_provider_clipboard_wayland::Policy as ClipboardPolicy;
use d2b_provider_display_wayland::WaylandSessionSpec;
use d2b_provider_network_local::{
    ExternalNicAdmissionError, ExternalNicClaim, admit_external_nic_claims,
    controller::{
        AttachmentRealization, NetworkAdmissionIntent, NetworkAdmissionKey, NetworkAdmissionProof,
        NetworkEffectError, NetworkReconciler, NetworkResourcePort, ReconcileInput,
        ReconcileProgress,
    },
    artifact::{ArtifactCatalogEntry, ArtifactKind},
    observe::{HostNetworkOccupancy, observe_host_network},
    routes::RouteTuple,
};
use d2b_provider_device_gpu::GpuLifecycleEffectPort;
use d2b_provider_notification_desktop::{Category, GuestSourceConfig, NotificationProviderConfig};
use d2b_provider_runtime_cloud_hypervisor::{
    AuthenticatedResourceApiAdapter, AuthenticatedResourceSession, BootstrapGraph, ChildRole,
    CloudHypervisorConfig, CloudHypervisorController, CloudHypervisorResourceApiError,
    CloudHypervisorResourceRequest, CloudHypervisorResourceResponse, FencedChild,
    GuestChildCommitResponse, GuestDependencySnapshot, GuestFinalizationInput, GuestGenerationSet,
    GuestSessionEvidence, GuestSessionEvidenceBinding, GuestSetupDescriptor,
    GuestSetupDescriptorVerifier, GuestSnapshot, OwnedChildSnapshot, ProcessState, SessionState,
    VerifiedGuestSetupDescriptor, deterministic_child_ref,
};
use d2b_provider_runtime_azure_container_apps as aca_runtime;
use d2b_provider_runtime_azure_virtual_machine as azure_vm_runtime;
use d2b_provider_runtime_qemu_media as qemu_media_runtime;
use d2b_provider_system_core::{
    HostCapabilityClass, HostObservationReport, HostProbeEffectPort, HostProbeMetadata,
    HostReconciler, MinijailPlatformGate, UserBinding, UserDiscoveryEffectPort, UserIdentityDigest,
    UserObservation, UserReconciler,
};
use d2b_resource_api::{
    RedbBackend, ResourceApiClient, ResourceBusAdapter, ResourceService, ResourceStoreBackend,
    authz::{AuthorizationState, NativeAuthorizer},
    registered::AssignmentFenceResolver,
    service::UnavailableUpgradeDispatcher,
};
use d2b_resource_store::{
    PolicySnapshot, ResourceAssignmentFence, ResourceAssignmentScope, StoreErrorKind,
    StoreGetRequest, StoreListRequest, StoreListResult, StoreOperationContext, StoreProjection,
    StoredResource,
};
use d2b_resource_store_redb::{
    AuthorityOperationState, BrokerEvidenceIndex, LogicalBackup, RedbResourceStore,
    StoreRuntimeMetadata, write_provisioning_marker,
};
use d2b_session::{
    ComponentSessionDriver, HandshakeCredentials, SessionDriverHandle, SessionEngine,
    SessionServerError, StreamId, TransportEvidence,
};
use d2b_session_unix::{
    AncillaryCapacity, CONTROLLER_BOOTSTRAP_TIMEOUT, PeerCredentials, SeqpacketSocket,
    VerifiedUnixPeer, controller_bootstrap_attachment_policy, controller_credit_scopes,
    controller_resource_endpoint_policy,
};
use d2bd_runtime::authority_persistence::RedbAuthorityPersistence;
pub use d2bd_runtime::resource_api::ResourceRuntimeError;
use d2bd_runtime::resource_api::{parse_list_request, route_service_matches};
use d2bd_runtime::resource_operator_activation::{
    Wave6AcceptanceReport, Wave6Dependencies, Wave6ProviderBoundary, Wave6ReconcileResult,
    select_wave6_resources,
};
#[cfg(test)]
use d2bd_runtime::resource_runtime_support::compatibility_error_envelope;
use d2bd_runtime::resource_runtime_support::{
    AssignmentRegistry, PolicySubjectFingerprint, SystemCoreReconcileResult,
    configuration_cleanup_pending, current_status_timestamp, encode_public_get_response,
    encode_public_list_response, encode_public_resource, ensure_bootstrap_host_resource,
    ensure_bootstrap_zone_resource, handler_phase_to_zone_phase,
    initial_policy_snapshot, map_startup_error, materialize_zone_resource_bundle,
    new_assignment_registry, public_list_request, public_operation_id, public_request_meta,
    refreshed_policy_subject_fingerprints, register_system_core_session, runtime_authorizer,
    runtime_policy, store_identity, store_identity_for_authority, unix_transport,
    validate_zone_resource_bundle, validate_zone_self_resource, watch_needs_restart,
    zone_runtime_metadata,
};
pub use d2bd_runtime::resource_runtime_support::{
    ZoneRuntimeReadiness, bounded_operation_id, persist_resource_status_with_projection,
};
use d2bd_runtime::resource_store_runtime::{MAX_ZONE_RUNTIMES, OpenedZoneStore};
use d2bd_runtime::target_runtime::{DaemonMode, ProviderDeployment};
use d2bd_runtime::zone_authority::{
    ZONE_GENERATION_PUBLICATION_OPERATION_PREFIX, ZoneAuthorityIdentity,
    complete_generation_set_digest,
};
use nix::unistd::{Group, Uid, User};
use protobuf::{EnumOrUnknown, MessageField};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

mod volume_effect_adapter;
mod volume_provider_runtime;
mod guest_provider_runtime;
pub use volume_provider_runtime::{
    compose_shared_volume_runner_descriptors, SharedVolumeRunnerRegistration,
    U7_SHARED_PROVIDER_RUNNERS,
};
pub use guest_provider_runtime::{
    compose_shared_guest_runner_descriptors, SharedGuestRunnerRegistration,
    U6_SHARED_PROVIDER_RUNNERS,
};
pub use volume_effect_adapter::{
    AnchoredVolumeEffectAdapter, FdRootResolver, ResolvedVolumeRoot, VolumeRootResolver,
};

const CORE_CONTROLLER_PROCESS_REF: &str = "Process/d2b-core-controller";
const CORE_CONTROLLER_PROVIDER_REF: &str = "Provider/system-core";
const CORE_CONTROLLER_HOST_REF: &str = "Host/host-system";

/// One Provider-owned ResourceType registration served by the shared Runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharedProviderRunnerRegistration {
    /// Static controller process identity.
    pub controller_ref: &'static str,
    /// Provider identity selected by the Resource spec.
    pub provider_ref: &'static str,
    /// ResourceType owned by this runner.
    pub resource_type: &'static str,
    /// Exact finalizer installed by the owner.
    pub finalizer: &'static str,
    /// Descriptor repair/resync interval in runner ticks.
    pub repair_interval_ticks: u64,
    /// Whether the legacy scheduler/watch path is disabled.
    pub legacy_scheduler_disabled: bool,
    /// Whether watched configuration is dependency-only.
    pub watched_configuration_is_dependency: bool,
}

/// The U8 Provider ResourceTypes attached to the production shared Runner.
///
/// USBIP and SecurityKey each have separate Service, Binding, and Device
/// ownership rows because the toolkit finalizer is per descriptor.
pub const U8_SHARED_PROVIDER_RUNNERS: [SharedProviderRunnerRegistration; 9] = [
    SharedProviderRunnerRegistration {
        controller_ref: "Process/network-local-controller",
        provider_ref: "Provider/network-local",
        resource_type: "Network",
        finalizer: d2b_provider_network_local::controller::network_runner_contract().finalizer(),
        repair_interval_ticks: d2b_provider_network_local::controller::network_runner_contract()
            .repair_interval_secs()
            * 1_000,
        legacy_scheduler_disabled: d2b_provider_network_local::controller::network_runner_contract()
            .legacy_scheduler_disabled(),
        watched_configuration_is_dependency:
            d2b_provider_network_local::controller::network_runner_contract()
                .watched_configuration_is_dependency(),
    },
    SharedProviderRunnerRegistration {
        controller_ref: "Process/device-tpm-controller",
        provider_ref: "Provider/device-tpm",
        resource_type: "Device",
        finalizer: d2b_provider_device_tpm::DEVICE_TPM_FINALIZER,
        repair_interval_ticks: d2b_provider_device_tpm::tpm_runner_contract().repair_interval_secs()
            * 1_000,
        legacy_scheduler_disabled: d2b_provider_device_tpm::tpm_runner_contract()
            .legacy_scheduler_disabled(),
        watched_configuration_is_dependency: d2b_provider_device_tpm::tpm_runner_contract()
            .watched_configuration_is_dependency(),
    },
    SharedProviderRunnerRegistration {
        controller_ref: "Process/device-usbip-controller",
        provider_ref: "Provider/device-usbip",
        resource_type: "Device",
        finalizer: d2b_contracts_resource::v3::device::DEVICE_USBIP_FINALIZER,
        repair_interval_ticks: d2b_provider_device_usbip::usbip_runner_contract()
            .repair_interval_secs()
            * 1_000,
        legacy_scheduler_disabled: d2b_provider_device_usbip::usbip_runner_contract()
            .legacy_scheduler_disabled(),
        watched_configuration_is_dependency: d2b_provider_device_usbip::usbip_runner_contract()
            .watched_configuration_is_dependency(),
    },
    SharedProviderRunnerRegistration {
        controller_ref: "Process/device-usbip-service-controller",
        provider_ref: "Provider/device-usbip",
        resource_type: d2b_provider_device_usbip::USB_SERVICE_RESOURCE_TYPE,
        finalizer: d2b_provider_device_usbip::USBIP_SERVICE_FINALIZER,
        repair_interval_ticks: d2b_provider_device_usbip::usbip_runner_contract()
            .repair_interval_secs()
            * 1_000,
        legacy_scheduler_disabled: d2b_provider_device_usbip::usbip_runner_contract()
            .legacy_scheduler_disabled(),
        watched_configuration_is_dependency: d2b_provider_device_usbip::usbip_runner_contract()
            .watched_configuration_is_dependency(),
    },
    SharedProviderRunnerRegistration {
        controller_ref: "Process/device-usbip-binding-controller",
        provider_ref: "Provider/device-usbip",
        resource_type: d2b_provider_device_usbip::USB_BINDING_RESOURCE_TYPE,
        finalizer: d2b_provider_device_usbip::USBIP_BINDING_FINALIZER,
        repair_interval_ticks: d2b_provider_device_usbip::usbip_runner_contract()
            .repair_interval_secs()
            * 1_000,
        legacy_scheduler_disabled: d2b_provider_device_usbip::usbip_runner_contract()
            .legacy_scheduler_disabled(),
        watched_configuration_is_dependency: d2b_provider_device_usbip::usbip_runner_contract()
            .watched_configuration_is_dependency(),
    },
    SharedProviderRunnerRegistration {
        controller_ref: "Process/device-security-key-controller",
        provider_ref: "Provider/device-security-key",
        resource_type: "Device",
        finalizer: d2b_contracts_resource::v3::device::DEVICE_SECURITY_KEY_FINALIZER,
        repair_interval_ticks: d2b_provider_device_security_key::security_key_runner_contract()
            .repair_interval_secs()
            * 1_000,
        legacy_scheduler_disabled: d2b_provider_device_security_key::security_key_runner_contract()
            .legacy_scheduler_disabled(),
        watched_configuration_is_dependency:
            d2b_provider_device_security_key::security_key_runner_contract()
                .watched_configuration_is_dependency(),
    },
    SharedProviderRunnerRegistration {
        controller_ref: "Process/device-security-key-service-controller",
        provider_ref: "Provider/device-security-key",
        resource_type: d2b_provider_device_security_key::SECURITY_KEY_SERVICE_RESOURCE_TYPE,
        finalizer: d2b_provider_device_security_key::SECURITY_KEY_SERVICE_FINALIZER,
        repair_interval_ticks: d2b_provider_device_security_key::security_key_runner_contract()
            .repair_interval_secs()
            * 1_000,
        legacy_scheduler_disabled: d2b_provider_device_security_key::security_key_runner_contract()
            .legacy_scheduler_disabled(),
        watched_configuration_is_dependency:
            d2b_provider_device_security_key::security_key_runner_contract()
                .watched_configuration_is_dependency(),
    },
    SharedProviderRunnerRegistration {
        controller_ref: "Process/device-security-key-binding-controller",
        provider_ref: "Provider/device-security-key",
        resource_type: d2b_provider_device_security_key::SECURITY_KEY_BINDING_RESOURCE_TYPE,
        finalizer: d2b_provider_device_security_key::SECURITY_KEY_BINDING_FINALIZER,
        repair_interval_ticks: d2b_provider_device_security_key::security_key_runner_contract()
            .repair_interval_secs()
            * 1_000,
        legacy_scheduler_disabled: d2b_provider_device_security_key::security_key_runner_contract()
            .legacy_scheduler_disabled(),
        watched_configuration_is_dependency:
            d2b_provider_device_security_key::security_key_runner_contract()
                .watched_configuration_is_dependency(),
    },
    SharedProviderRunnerRegistration {
        controller_ref: "Process/device-gpu-controller",
        provider_ref: "Provider/device-gpu",
        resource_type: "Device",
        finalizer: d2b_provider_device_gpu::gpu_runner_contract().finalizer(),
        repair_interval_ticks: d2b_provider_device_gpu::gpu_runner_contract()
            .repair_interval_secs()
            * 1_000,
        legacy_scheduler_disabled: d2b_provider_device_gpu::gpu_runner_contract()
            .legacy_scheduler_disabled(),
        watched_configuration_is_dependency: d2b_provider_device_gpu::gpu_runner_contract()
            .watched_configuration_is_dependency(),
    },
];

/// The U9 interaction and shell ResourceTypes attached to the production
/// shared Runner. Clipboard and notification delivery remain typed
/// ComponentSession services and therefore have no ResourceType registration.
pub const U9_SHARED_PROVIDER_RUNNERS: [SharedProviderRunnerRegistration; 6] = [
    SharedProviderRunnerRegistration {
        controller_ref: "Process/display-wayland-controller",
        provider_ref: "Provider/display-wayland",
        resource_type: "display-wayland.d2bus.org.WaylandPolicy",
        finalizer: "",
        repair_interval_ticks:
            d2b_provider_display_wayland::DISPLAY_REPAIR_INTERVAL_SECS * 1_000,
        legacy_scheduler_disabled: d2b_provider_display_wayland::display_runner_contract()
            .legacy_scheduler_disabled(),
        watched_configuration_is_dependency:
            d2b_provider_display_wayland::display_runner_contract()
                .watched_configuration_is_dependency(),
    },
    SharedProviderRunnerRegistration {
        controller_ref: "Process/display-wayland-controller",
        provider_ref: "Provider/display-wayland",
        resource_type: "display-wayland.d2bus.org.WaylandSession",
        finalizer: d2b_provider_display_wayland::FINALIZER,
        repair_interval_ticks:
            d2b_provider_display_wayland::DISPLAY_REPAIR_INTERVAL_SECS * 1_000,
        legacy_scheduler_disabled: d2b_provider_display_wayland::display_runner_contract()
            .legacy_scheduler_disabled(),
        watched_configuration_is_dependency:
            d2b_provider_display_wayland::display_runner_contract()
                .watched_configuration_is_dependency(),
    },
    SharedProviderRunnerRegistration {
        controller_ref: "Process/audio-pipewire-controller",
        provider_ref: "Provider/audio-pipewire",
        resource_type: "audio.d2bus.org.AudioService",
        finalizer: d2b_provider_audio_pipewire::AUDIO_SERVICE_FINALIZER,
        repair_interval_ticks:
            d2b_provider_audio_pipewire::AUDIO_REPAIR_INTERVAL_SECS * 1_000,
        legacy_scheduler_disabled: d2b_provider_audio_pipewire::audio_runner_contract()
            .legacy_scheduler_disabled(),
        watched_configuration_is_dependency:
            d2b_provider_audio_pipewire::audio_runner_contract()
                .watched_configuration_is_dependency(),
    },
    SharedProviderRunnerRegistration {
        controller_ref: "Process/audio-pipewire-controller",
        provider_ref: "Provider/audio-pipewire",
        resource_type: "audio.d2bus.org.AudioBinding",
        finalizer: d2b_provider_audio_pipewire::AUDIO_BINDING_FINALIZER,
        repair_interval_ticks:
            d2b_provider_audio_pipewire::AUDIO_REPAIR_INTERVAL_SECS * 1_000,
        legacy_scheduler_disabled: d2b_provider_audio_pipewire::audio_runner_contract()
            .legacy_scheduler_disabled(),
        watched_configuration_is_dependency:
            d2b_provider_audio_pipewire::audio_runner_contract()
                .watched_configuration_is_dependency(),
    },
    SharedProviderRunnerRegistration {
        controller_ref: "Process/shell-terminal-controller",
        provider_ref: "Provider/shell-terminal",
        resource_type: "shell-terminal.d2bus.org.ShellPool",
        finalizer: d2b_provider_shell_terminal::SHELL_POOL_FINALIZER,
        repair_interval_ticks: d2b_provider_shell_terminal::SHELL_REPAIR_INTERVAL_SECS * 1_000,
        legacy_scheduler_disabled: d2b_provider_shell_terminal::shell_runner_contract()
            .legacy_scheduler_disabled(),
        watched_configuration_is_dependency:
            d2b_provider_shell_terminal::shell_runner_contract()
                .watched_configuration_is_dependency(),
    },
    SharedProviderRunnerRegistration {
        controller_ref: "Process/shell-terminal-controller",
        provider_ref: "Provider/shell-terminal",
        resource_type: "shell-terminal.d2bus.org.ShellSession",
        finalizer: d2b_provider_shell_terminal::SHELL_SESSION_FINALIZER,
        repair_interval_ticks: d2b_provider_shell_terminal::SHELL_REPAIR_INTERVAL_SECS * 1_000,
        legacy_scheduler_disabled: d2b_provider_shell_terminal::shell_runner_contract()
            .legacy_scheduler_disabled(),
        watched_configuration_is_dependency:
            d2b_provider_shell_terminal::shell_runner_contract()
                .watched_configuration_is_dependency(),
    },
];

/// Closed Provider handler set used by the shared Runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SharedProviderResourceKind {
    Network,
    TpmDevice,
    UsbipDevice,
    UsbipService,
    UsbipBinding,
    SecurityKeyDevice,
    SecurityKeyService,
    SecurityKeyBinding,
    GpuDevice,
    CloudHypervisorGuest,
    QemuMediaGuest,
    AzureContainerAppsGuest,
    AzureVirtualMachineGuest,
    DisplayWaylandPolicy,
    DisplayWaylandSession,
    AudioService,
    AudioBinding,
    ShellPool,
    ShellSession,
}

impl SharedProviderResourceKind {
    fn from_registration(
        registration: SharedProviderRunnerRegistration,
    ) -> Result<Self, ResourceRuntimeError> {
        match (
            registration.provider_ref,
            registration.resource_type,
            registration.controller_ref,
        ) {
            ("Provider/network-local", "Network", "Process/network-local-controller") => {
                Ok(Self::Network)
            }
            ("Provider/device-tpm", "Device", "Process/device-tpm-controller") => {
                Ok(Self::TpmDevice)
            }
            ("Provider/device-usbip", "Device", "Process/device-usbip-controller") => {
                Ok(Self::UsbipDevice)
            }
            (
                "Provider/device-usbip",
                d2b_provider_device_usbip::USB_SERVICE_RESOURCE_TYPE,
                "Process/device-usbip-service-controller",
            ) => Ok(Self::UsbipService),
            (
                "Provider/device-usbip",
                d2b_provider_device_usbip::USB_BINDING_RESOURCE_TYPE,
                "Process/device-usbip-binding-controller",
            ) => Ok(Self::UsbipBinding),
            ("Provider/device-security-key", "Device", "Process/device-security-key-controller") => {
                Ok(Self::SecurityKeyDevice)
            }
            (
                "Provider/device-security-key",
                d2b_provider_device_security_key::SECURITY_KEY_SERVICE_RESOURCE_TYPE,
                "Process/device-security-key-service-controller",
            ) => Ok(Self::SecurityKeyService),
            (
                "Provider/device-security-key",
                d2b_provider_device_security_key::SECURITY_KEY_BINDING_RESOURCE_TYPE,
                "Process/device-security-key-binding-controller",
            ) => Ok(Self::SecurityKeyBinding),
            ("Provider/device-gpu", "Device", "Process/device-gpu-controller") => {
                Ok(Self::GpuDevice)
            }
            (
                "Provider/runtime-cloud-hypervisor",
                "Guest",
                "Process/cloud-hypervisor-controller",
            ) => Ok(Self::CloudHypervisorGuest),
            (
                "Provider/runtime-qemu-media",
                "Guest",
                "Process/runtime-qemu-media-controller",
            ) => Ok(Self::QemuMediaGuest),
            (
                "Provider/runtime-azure-container-apps",
                "Guest",
                "Process/aca-controller",
            ) => Ok(Self::AzureContainerAppsGuest),
            (
                "Provider/runtime-azure-virtual-machine",
                "Guest",
                "Process/azure-vm-controller-process",
            ) => Ok(Self::AzureVirtualMachineGuest),
            (
                "Provider/display-wayland",
                "display-wayland.d2bus.org.WaylandPolicy",
                "Process/display-wayland-controller",
            ) => Ok(Self::DisplayWaylandPolicy),
            (
                "Provider/display-wayland",
                "display-wayland.d2bus.org.WaylandSession",
                "Process/display-wayland-controller",
            ) => Ok(Self::DisplayWaylandSession),
            (
                "Provider/audio-pipewire",
                "audio.d2bus.org.AudioService",
                "Process/audio-pipewire-controller",
            ) => Ok(Self::AudioService),
            (
                "Provider/audio-pipewire",
                "audio.d2bus.org.AudioBinding",
                "Process/audio-pipewire-controller",
            ) => Ok(Self::AudioBinding),
            (
                "Provider/shell-terminal",
                "shell-terminal.d2bus.org.ShellPool",
                "Process/shell-terminal-controller",
            ) => Ok(Self::ShellPool),
            (
                "Provider/shell-terminal",
                "shell-terminal.d2bus.org.ShellSession",
                "Process/shell-terminal-controller",
            ) => Ok(Self::ShellSession),
            _ => Err(ResourceRuntimeError::HandlerNotReady),
        }
    }

    const fn effect_id(self) -> &'static str {
        match self {
            Self::Network => "network",
            Self::TpmDevice => "device-tpm",
            Self::UsbipDevice => "device-usbip",
            Self::UsbipService => "device-usbip-service",
            Self::UsbipBinding => "device-usbip-binding",
            Self::SecurityKeyDevice => "device-security-key",
            Self::SecurityKeyService => "device-security-key-service",
            Self::SecurityKeyBinding => "device-security-key-binding",
            Self::GpuDevice => "device-gpu",
            Self::CloudHypervisorGuest => "runtime-cloud-hypervisor-guest",
            Self::QemuMediaGuest => "runtime-qemu-media-guest",
            Self::AzureContainerAppsGuest => "runtime-azure-container-apps-guest",
            Self::AzureVirtualMachineGuest => "runtime-azure-virtual-machine-guest",
            Self::DisplayWaylandPolicy => "display-wayland-policy",
            Self::DisplayWaylandSession => "display-wayland-session",
            Self::AudioService => "audio-service",
            Self::AudioBinding => "audio-binding",
            Self::ShellPool => "shell-pool",
            Self::ShellSession => "shell-session",
        }
    }

    const fn provider_ref(self) -> &'static str {
        match self {
            Self::Network => "Provider/network-local",
            Self::TpmDevice => "Provider/device-tpm",
            Self::UsbipDevice | Self::UsbipService | Self::UsbipBinding => {
                "Provider/device-usbip"
            }
            Self::SecurityKeyDevice
            | Self::SecurityKeyService
            | Self::SecurityKeyBinding => "Provider/device-security-key",
            Self::GpuDevice => "Provider/device-gpu",
            Self::CloudHypervisorGuest => "Provider/runtime-cloud-hypervisor",
            Self::QemuMediaGuest => "Provider/runtime-qemu-media",
            Self::AzureContainerAppsGuest => "Provider/runtime-azure-container-apps",
            Self::AzureVirtualMachineGuest => "Provider/runtime-azure-virtual-machine",
            Self::DisplayWaylandPolicy | Self::DisplayWaylandSession => "Provider/display-wayland",
            Self::AudioService | Self::AudioBinding => "Provider/audio-pipewire",
            Self::ShellPool | Self::ShellSession => "Provider/shell-terminal",
        }
    }

    const fn resource_type(self) -> &'static str {
        match self {
            Self::Network => "Network",
            Self::TpmDevice
            | Self::UsbipDevice
            | Self::SecurityKeyDevice
            | Self::GpuDevice => "Device",
            Self::UsbipService => d2b_provider_device_usbip::USB_SERVICE_RESOURCE_TYPE,
            Self::UsbipBinding => d2b_provider_device_usbip::USB_BINDING_RESOURCE_TYPE,
            Self::SecurityKeyService => {
                d2b_provider_device_security_key::SECURITY_KEY_SERVICE_RESOURCE_TYPE
            }
            Self::SecurityKeyBinding => {
                d2b_provider_device_security_key::SECURITY_KEY_BINDING_RESOURCE_TYPE
            }
            Self::CloudHypervisorGuest
            | Self::QemuMediaGuest
            | Self::AzureContainerAppsGuest
            | Self::AzureVirtualMachineGuest => "Guest",
            Self::DisplayWaylandPolicy => "display-wayland.d2bus.org.WaylandPolicy",
            Self::DisplayWaylandSession => "display-wayland.d2bus.org.WaylandSession",
            Self::AudioService => "audio.d2bus.org.AudioService",
            Self::AudioBinding => "audio.d2bus.org.AudioBinding",
            Self::ShellPool => "shell-terminal.d2bus.org.ShellPool",
            Self::ShellSession => "shell-terminal.d2bus.org.ShellSession",
        }
    }

    const fn usbip_component(self) -> Option<UsbipResourceComponent> {
        match self {
            Self::UsbipDevice => Some(UsbipResourceComponent::Device),
            Self::UsbipService => Some(UsbipResourceComponent::Service),
            Self::UsbipBinding => Some(UsbipResourceComponent::Binding),
            _ => None,
        }
    }

    const fn security_key_component(self) -> Option<SecurityKeyResourceComponent> {
        match self {
            Self::SecurityKeyDevice => Some(SecurityKeyResourceComponent::Device),
            Self::SecurityKeyService => Some(SecurityKeyResourceComponent::Service),
            Self::SecurityKeyBinding => Some(SecurityKeyResourceComponent::Binding),
            _ => None,
        }
    }
}

/// USBIP resource owner selected by a shared-Runner descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UsbipResourceComponent {
    Device,
    Service,
    Binding,
}

/// SecurityKey resource owner selected by a shared-Runner descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecurityKeyResourceComponent {
    Device,
    Service,
    Binding,
}

/// Identity and assignment evidence passed to one Provider effect adapter.
#[derive(Clone)]
pub(crate) struct SharedProviderEffectContext {
    pub(crate) identity: ControllerIdentity,
    pub(crate) target: ResourceKey,
    pub(crate) operation_id: String,
}

/// Result returned by one typed Provider effect adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SharedProviderEffectPhase {
    Ready,
    Pending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SharedProviderEffectResult {
    pub(crate) phase: SharedProviderEffectPhase,
    pub(crate) child_mutated: bool,
}

impl SharedProviderEffectResult {
    const fn phase(phase: SharedProviderEffectPhase) -> Self {
        Self {
            phase,
            child_mutated: false,
        }
    }
}

/// Closed failure surface for shared Provider adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SharedProviderEffectError {
    /// The Provider path is not currently available and should retry.
    Unavailable,
    /// Fresh resource or assignment evidence failed closed.
    InvalidResource,
}

impl core::fmt::Display for SharedProviderEffectError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "shared-provider-effect-unavailable",
            Self::InvalidResource => "shared-provider-resource-invalid",
        })
    }
}

impl std::error::Error for SharedProviderEffectError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameworkAzureOperation {
    Provision,
    Delete,
    ChildCleanup,
    Extension,
    Update,
}

/// Framework-only QEMU effect evidence for non-Cloud-Hypervisor Guest owners.
///
/// The real Process/ComponentSession path remains owned by the selected
/// child Providers; this adapter exercises the typed lifecycle state machine
/// without claiming Cloud Hypervisor host liveness.
struct FrameworkQemuEffect {
    guest_ref: ResourceRef,
    identity: Option<qemu_media_runtime::ProcessIdentity>,
    qmp_ready: bool,
}

impl FrameworkQemuEffect {
    fn new(guest_ref: ResourceRef) -> Self {
        Self {
            guest_ref,
            identity: None,
            qmp_ready: false,
        }
    }

    fn qmp_ready(&self) -> bool {
        self.qmp_ready
    }
}

impl qemu_media_runtime::QemuMediaEffectPort for FrameworkQemuEffect {
    fn launch(
        &mut self,
        _ticket: &qemu_media_runtime::LaunchTicket,
    ) -> Result<qemu_media_runtime::ProcessIdentity, qemu_media_runtime::QemuMediaError> {
        let template_digest: [u8; 32] = Sha256::digest(b"qemu-media-runner").into();
        let identity_digest: [u8; 32] =
            Sha256::digest(self.guest_ref.to_canonical_string().as_bytes()).into();
        let identity = qemu_media_runtime::ProcessIdentity {
            pid: 1,
            start_time_ticks: 1,
            cgroup_digest: identity_digest,
            executable_digest: identity_digest,
            template_digest,
            generation: 1,
        };
        self.identity = Some(identity.clone());
        Ok(identity)
    }

    fn observe(
        &mut self,
    ) -> Result<
        Option<qemu_media_runtime::ProcessIdentity>,
        qemu_media_runtime::QemuMediaError,
    > {
        Ok(self.identity.clone())
    }

    fn open_pidfd(
        &mut self,
        _identity: &qemu_media_runtime::ProcessIdentity,
    ) -> Result<(), qemu_media_runtime::QemuMediaError> {
        self.qmp_ready = true;
        Ok(())
    }

    fn reserve_device_authority(
        &mut self,
        _authority_key: [u8; 32],
        _owner_ref: &ResourceRef,
    ) -> Result<(), qemu_media_runtime::QemuMediaError> {
        Ok(())
    }

    fn close_media_effects(&mut self) -> Result<(), qemu_media_runtime::QemuMediaError> {
        self.qmp_ready = false;
        Ok(())
    }

    fn continue_guest(&mut self) -> Result<(), qemu_media_runtime::QemuMediaError> {
        Ok(())
    }

    fn stop(
        &mut self,
        _identity: &qemu_media_runtime::ProcessIdentity,
    ) -> Result<(), qemu_media_runtime::QemuMediaError> {
        self.identity = None;
        self.qmp_ready = false;
        Ok(())
    }

    fn release_device_authority(&mut self) -> Result<(), qemu_media_runtime::QemuMediaError> {
        Ok(())
    }

    fn delete_runtime_volume(&mut self) -> Result<(), qemu_media_runtime::QemuMediaError> {
        Ok(())
    }
}

struct FrameworkAcaState {
    provider_generation: u64,
    disk_image: Option<aca_runtime::AcaDiskImageRecord>,
    sandbox: Option<aca_runtime::AcaSandboxRecord>,
}

impl FrameworkAcaState {
    fn new(provider_generation: u64) -> Self {
        Self {
            provider_generation,
            disk_image: None,
            sandbox: None,
        }
    }
}

struct FrameworkAcaControl {
    state: Arc<tokio::sync::Mutex<FrameworkAcaState>>,
}

struct FrameworkAcaLease;

#[async_trait]
impl aca_runtime::AcaCredentialLeaseClient for FrameworkAcaLease {
    async fn acquire(
        &self,
        request: &aca_runtime::AcaCredentialLeaseRequest,
    ) -> Result<aca_runtime::AcaCredentialLease, aca_runtime::AcaControlError> {
        let handle = d2b_contracts_provider::v3::credential::CredentialLeaseHandle::parse(
            "u6-framework-lease",
        )
        .map_err(|_| {
            aca_runtime::AcaControlError::new(aca_runtime::AcaControlErrorKind::Authentication)
        })?;
        Ok(aca_runtime::AcaCredentialLease::from_metadata(
            handle,
            request.requested_expiry_unix_ms(),
        ))
    }

    async fn revoke(
        &self,
        _lease: &aca_runtime::AcaCredentialLease,
    ) -> Result<(), aca_runtime::AcaControlError> {
        Ok(())
    }
}

#[async_trait]
impl aca_runtime::AcaControl for FrameworkAcaControl {
    async fn health(
        &self,
        _lease: &aca_runtime::AcaCredentialLease,
        _context: &aca_runtime::AcaControlContext,
    ) -> Result<aca_runtime::AcaControlHealth, aca_runtime::AcaControlError> {
        Ok(if self
            .state
            .lock()
            .await
            .sandbox
            .as_ref()
            .is_some_and(|sandbox| {
                sandbox.lifecycle == aca_runtime::AcaSandboxLifecycle::Running
            }) {
            aca_runtime::AcaControlHealth::Ready
        } else {
            aca_runtime::AcaControlHealth::Unavailable
        })
    }

    async fn find_sandboxes(
        &self,
        _lease: &aca_runtime::AcaCredentialLease,
        _context: &aca_runtime::AcaControlContext,
        _query: &aca_runtime::AcaWorkloadQuery,
    ) -> Result<
        aca_runtime::AcaSandboxCandidates,
        aca_runtime::AcaControlError,
    > {
        let mut state = self.state.lock().await;
        if state
            .sandbox
            .as_ref()
            .is_some_and(|sandbox| sandbox.lifecycle == aca_runtime::AcaSandboxLifecycle::Creating)
        {
            if let Some(sandbox) = state.sandbox.as_mut() {
                sandbox.lifecycle = aca_runtime::AcaSandboxLifecycle::Running;
            }
        }
        aca_runtime::AcaSandboxCandidates::new(
            state.sandbox.clone().into_iter().collect(),
        )
        .map_err(|_| {
            aca_runtime::AcaControlError::new(aca_runtime::AcaControlErrorKind::InvalidResponse)
        })
    }

    async fn find_disk_images(
        &self,
        _lease: &aca_runtime::AcaCredentialLease,
        _context: &aca_runtime::AcaControlContext,
        _desired: &aca_runtime::AcaDesiredDiskImage,
    ) -> Result<
        aca_runtime::AcaDiskImageCandidates,
        aca_runtime::AcaControlError,
    > {
        let state = self.state.lock().await;
        aca_runtime::AcaDiskImageCandidates::new(
            state.disk_image.clone().into_iter().collect(),
        )
        .map_err(|_| {
            aca_runtime::AcaControlError::new(aca_runtime::AcaControlErrorKind::InvalidResponse)
        })
    }

    async fn create_disk_image(
        &self,
        _lease: &aca_runtime::AcaCredentialLease,
        _context: &aca_runtime::AcaControlContext,
        _desired: &aca_runtime::AcaDesiredDiskImage,
    ) -> Result<aca_runtime::AcaDiskImageRecord, aca_runtime::AcaControlError> {
        let record = aca_runtime::AcaDiskImageRecord {
            id: aca_runtime::AcaDiskImageId::parse("u6-framework-disk").map_err(|_| {
                aca_runtime::AcaControlError::new(aca_runtime::AcaControlErrorKind::InvalidResponse)
            })?,
            generation: self.state.lock().await.provider_generation,
        };
        self.state.lock().await.disk_image = Some(record.clone());
        Ok(record)
    }

    async fn create_sandbox(
        &self,
        _lease: &aca_runtime::AcaCredentialLease,
        _context: &aca_runtime::AcaControlContext,
        desired: &aca_runtime::AcaDesiredSandbox,
    ) -> Result<aca_runtime::AcaSandboxRecord, aca_runtime::AcaControlError> {
        let record = aca_runtime::AcaSandboxRecord {
            id: aca_runtime::AcaSandboxId::parse("u6-framework-sandbox").map_err(|_| {
                aca_runtime::AcaControlError::new(aca_runtime::AcaControlErrorKind::InvalidResponse)
            })?,
            lifecycle: aca_runtime::AcaSandboxLifecycle::Creating,
            generation: desired.binding.provider_generation,
        };
        self.state.lock().await.sandbox = Some(record.clone());
        Ok(record)
    }

    async fn resume_sandbox(
        &self,
        _lease: &aca_runtime::AcaCredentialLease,
        _context: &aca_runtime::AcaControlContext,
        sandbox_id: &aca_runtime::AcaSandboxId,
    ) -> Result<aca_runtime::AcaSandboxRecord, aca_runtime::AcaControlError> {
        let mut state = self.state.lock().await;
        let Some(sandbox) = state.sandbox.as_mut() else {
            return Err(aca_runtime::AcaControlError::new(
                aca_runtime::AcaControlErrorKind::NotFound,
            ));
        };
        if sandbox.id != *sandbox_id {
            return Err(aca_runtime::AcaControlError::new(
                aca_runtime::AcaControlErrorKind::Conflict,
            ));
        }
        sandbox.lifecycle = aca_runtime::AcaSandboxLifecycle::Running;
        Ok(sandbox.clone())
    }

    async fn stop_sandbox(
        &self,
        _lease: &aca_runtime::AcaCredentialLease,
        _context: &aca_runtime::AcaControlContext,
        sandbox_id: &aca_runtime::AcaSandboxId,
    ) -> Result<aca_runtime::AcaSandboxRecord, aca_runtime::AcaControlError> {
        let mut state = self.state.lock().await;
        let Some(sandbox) = state.sandbox.as_mut() else {
            return Err(aca_runtime::AcaControlError::new(
                aca_runtime::AcaControlErrorKind::NotFound,
            ));
        };
        if sandbox.id != *sandbox_id {
            return Err(aca_runtime::AcaControlError::new(
                aca_runtime::AcaControlErrorKind::Conflict,
            ));
        }
        sandbox.lifecycle = aca_runtime::AcaSandboxLifecycle::Stopped;
        Ok(sandbox.clone())
    }

    async fn delete_sandbox(
        &self,
        _lease: &aca_runtime::AcaCredentialLease,
        _context: &aca_runtime::AcaControlContext,
        sandbox_id: &aca_runtime::AcaSandboxId,
    ) -> Result<aca_runtime::AcaDeleteOutcome, aca_runtime::AcaControlError> {
        let mut state = self.state.lock().await;
        if state
            .sandbox
            .as_ref()
            .is_some_and(|sandbox| sandbox.id != *sandbox_id)
        {
            return Err(aca_runtime::AcaControlError::new(
                aca_runtime::AcaControlErrorKind::Conflict,
            ));
        }
        state.sandbox = None;
        Ok(aca_runtime::AcaDeleteOutcome::Deleted)
    }
}

struct FrameworkAzureState {
    state: azure_vm_runtime::AzureVmState,
    handle: Option<azure_vm_runtime::AzureVmHandle>,
    tags: azure_vm_runtime::TagDigest,
    operation: Option<(
        azure_vm_runtime::AzureOperationHandle,
        FrameworkAzureOperation,
    )>,
    extension_present: bool,
}

impl FrameworkAzureState {
    fn new(settings: &azure_vm_runtime::AzureVmGuestSettings) -> Self {
        Self {
            state: azure_vm_runtime::AzureVmState::Absent,
            handle: None,
            tags: azure_vm_runtime::TagDigest::from_tags(&settings.azure_tags),
            operation: None,
            extension_present: false,
        }
    }

    fn operation(
        &mut self,
        operation_id: &str,
        kind: FrameworkAzureOperation,
    ) -> Result<azure_vm_runtime::AzureOperationHandle, azure_vm_runtime::AzureVmError> {
        let operation = azure_vm_runtime::AzureOperationHandle::from_core(
            format!("u6-{operation_id}-{kind:?}"),
        )?;
        self.operation = Some((operation.clone(), kind));
        Ok(operation)
    }
}

struct FrameworkAzureEffect {
    state: Arc<tokio::sync::Mutex<FrameworkAzureState>>,
}

struct FrameworkAzureCredential;

#[async_trait]
impl azure_vm_runtime::AzureCredentialPort for FrameworkAzureCredential {
    async fn acquire_token(
        &self,
        _audience: &str,
        _deadline_ms: u32,
    ) -> Result<azure_vm_runtime::AzureAccessToken, azure_vm_runtime::AzureVmError> {
        Ok(vec![0_u8].into())
    }
}

#[async_trait]
impl azure_vm_runtime::AzureEffectPort for FrameworkAzureEffect {
    async fn start_vm_provision(
        &self,
        _settings: &azure_vm_runtime::AzureVmGuestSettings,
        operation_id: &str,
        _token: &azure_vm_runtime::AzureAccessToken,
    ) -> Result<azure_vm_runtime::AzureOperationHandle, azure_vm_runtime::AzureVmError> {
        let mut state = self.state.lock().await;
        state.state = azure_vm_runtime::AzureVmState::Provisioning;
        state.operation(operation_id, FrameworkAzureOperation::Provision)
    }

    async fn poll_lro(
        &self,
        operation: &azure_vm_runtime::AzureOperationHandle,
        _token: &azure_vm_runtime::AzureAccessToken,
    ) -> Result<azure_vm_runtime::LroStatus, azure_vm_runtime::AzureVmError> {
        let mut state = self.state.lock().await;
        let Some((current, kind)) = state.operation.take() else {
            return Err(azure_vm_runtime::AzureVmError::InvalidOperationHandle);
        };
        if &current != operation {
            return Err(azure_vm_runtime::AzureVmError::InvalidOperationHandle);
        }
        match kind {
            FrameworkAzureOperation::Provision => {
                state.state = azure_vm_runtime::AzureVmState::Running;
                state.handle = Some(
                    azure_vm_runtime::AzureVmHandle::from_core("u6-framework-vm")?,
                );
            }
            FrameworkAzureOperation::Delete => {
                state.state = azure_vm_runtime::AzureVmState::Absent;
                state.handle = None;
            }
            FrameworkAzureOperation::Extension => state.extension_present = false,
            FrameworkAzureOperation::ChildCleanup
            | FrameworkAzureOperation::Update => {}
        }
        Ok(azure_vm_runtime::LroStatus::Succeeded)
    }

    async fn get_vm_state(
        &self,
        _settings: &azure_vm_runtime::AzureVmGuestSettings,
        _token: &azure_vm_runtime::AzureAccessToken,
    ) -> Result<
        (
            azure_vm_runtime::AzureVmState,
            Option<azure_vm_runtime::AzureVmHandle>,
            Option<azure_vm_runtime::TagDigest>,
        ),
        azure_vm_runtime::AzureVmError,
    > {
        let state = self.state.lock().await;
        Ok((state.state, state.handle.clone(), Some(state.tags)))
    }

    async fn put_vm_extension(
        &self,
        _handle: &azure_vm_runtime::AzureVmHandle,
        _payload: azure_vm_runtime::PskExtensionPayload,
        _token: &azure_vm_runtime::AzureAccessToken,
    ) -> Result<azure_vm_runtime::AzureOperationHandle, azure_vm_runtime::AzureVmError> {
        let mut state = self.state.lock().await;
        state.extension_present = true;
        state.operation("extension", FrameworkAzureOperation::Extension)
    }

    async fn delete_vm_extension(
        &self,
        _settings: &azure_vm_runtime::AzureVmGuestSettings,
        _token: &azure_vm_runtime::AzureAccessToken,
    ) -> Result<azure_vm_runtime::AzureOperationHandle, azure_vm_runtime::AzureVmError> {
        let mut state = self.state.lock().await;
        state.operation("extension-cleanup", FrameworkAzureOperation::Extension)
    }

    async fn start_vm_resize(
        &self,
        _handle: &azure_vm_runtime::AzureVmHandle,
        _size: &str,
        operation_id: &str,
        _token: &azure_vm_runtime::AzureAccessToken,
    ) -> Result<azure_vm_runtime::AzureOperationHandle, azure_vm_runtime::AzureVmError> {
        self.state
            .lock()
            .await
            .operation(operation_id, FrameworkAzureOperation::Update)
    }

    async fn start_vm_delete(
        &self,
        _handle: &azure_vm_runtime::AzureVmHandle,
        operation_id: &str,
        _token: &azure_vm_runtime::AzureAccessToken,
    ) -> Result<azure_vm_runtime::AzureOperationHandle, azure_vm_runtime::AzureVmError> {
        self.state
            .lock()
            .await
            .operation(operation_id, FrameworkAzureOperation::Delete)
    }

    async fn start_child_resource_cleanup(
        &self,
        _settings: &azure_vm_runtime::AzureVmGuestSettings,
        operation_id: &str,
        _token: &azure_vm_runtime::AzureAccessToken,
    ) -> Result<azure_vm_runtime::AzureOperationHandle, azure_vm_runtime::AzureVmError> {
        self.state
            .lock()
            .await
            .operation(operation_id, FrameworkAzureOperation::ChildCleanup)
    }

    async fn start_disk_attach(
        &self,
        _handle: &azure_vm_runtime::AzureVmHandle,
        _disk: &azure_vm_runtime::DataDiskSpec,
        operation_id: &str,
        _token: &azure_vm_runtime::AzureAccessToken,
    ) -> Result<azure_vm_runtime::AzureOperationHandle, azure_vm_runtime::AzureVmError> {
        self.state
            .lock()
            .await
            .operation(operation_id, FrameworkAzureOperation::Update)
    }

    async fn start_disk_detach(
        &self,
        _handle: &azure_vm_runtime::AzureVmHandle,
        _lun: u8,
        operation_id: &str,
        _token: &azure_vm_runtime::AzureAccessToken,
    ) -> Result<azure_vm_runtime::AzureOperationHandle, azure_vm_runtime::AzureVmError> {
        self.state
            .lock()
            .await
            .operation(operation_id, FrameworkAzureOperation::Update)
    }

    async fn update_vm_tags(
        &self,
        _handle: &azure_vm_runtime::AzureVmHandle,
        _tags: &[(String, String)],
        operation_id: &str,
        _token: &azure_vm_runtime::AzureAccessToken,
    ) -> Result<azure_vm_runtime::AzureOperationHandle, azure_vm_runtime::AzureVmError> {
        self.state
            .lock()
            .await
            .operation(operation_id, FrameworkAzureOperation::Update)
    }
}

enum GuestRuntimeController {
    Qemu {
        controller: qemu_media_runtime::QemuMediaController<FrameworkQemuEffect>,
        effect: FrameworkQemuEffect,
    },
    Aca {
        controller: aca_runtime::AcaController<FrameworkAcaControl, FrameworkAcaLease>,
    },
    AzureVm {
        controller: azure_vm_runtime::AzureVmController<FrameworkAzureEffect>,
    },
}

impl GuestRuntimeController {
    fn finalizer_installed(&self) -> bool {
        match self {
            Self::Qemu { controller, .. } => controller.finalizer_installed(),
            Self::Aca { controller } => controller.finalizer_installed(),
            Self::AzureVm { controller } => controller.finalizer_installed(),
        }
    }
}

/// Typed Provider effect boundary owned by the d2bd composition root.
#[async_trait]
pub(crate) trait SharedProviderEffectExecutor: Send + Sync {
    /// Reconcile one Network resource through the Network-local controller.
    async fn reconcile_network(
        &self,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
        dependencies: &[DependencySnapshot],
    ) -> Result<SharedProviderEffectPhase, SharedProviderEffectError> {
        let _ = (context, resource, dependencies);
        Err(SharedProviderEffectError::Unavailable)
    }

    /// Reconcile one TPM Device through the persistent TPM controller.
    async fn reconcile_tpm(
        &self,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
        dependencies: &[DependencySnapshot],
    ) -> Result<SharedProviderEffectPhase, SharedProviderEffectError> {
        let _ = (context, resource, dependencies);
        Err(SharedProviderEffectError::Unavailable)
    }

    /// Reconcile one USBIP resource through its typed lifecycle controller.
    async fn reconcile_usbip(
        &self,
        component: UsbipResourceComponent,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
        dependencies: &[DependencySnapshot],
    ) -> Result<SharedProviderEffectPhase, SharedProviderEffectError> {
        let _ = (component, context, resource, dependencies);
        Err(SharedProviderEffectError::Unavailable)
    }

    /// Reconcile one SecurityKey resource through its typed lifecycle
    /// controller.
    async fn reconcile_security_key(
        &self,
        component: SecurityKeyResourceComponent,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
        dependencies: &[DependencySnapshot],
    ) -> Result<SharedProviderEffectPhase, SharedProviderEffectError> {
        let _ = (component, context, resource, dependencies);
        Err(SharedProviderEffectError::Unavailable)
    }

    /// Reconcile one GPU Device through the authority-fenced lifecycle.
    async fn reconcile_gpu(
        &self,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
        dependencies: &[DependencySnapshot],
    ) -> Result<SharedProviderEffectPhase, SharedProviderEffectError> {
        let _ = (context, resource, dependencies);
        Err(SharedProviderEffectError::Unavailable)
    }

    /// Reconcile one display-wayland ResourceType.
    async fn reconcile_display(
        &self,
        _kind: SharedProviderResourceKind,
        _context: &SharedProviderEffectContext,
        _resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
    ) -> Result<SharedProviderEffectResult, SharedProviderEffectError> {
        Err(SharedProviderEffectError::Unavailable)
    }

    /// Reconcile one audio-pipewire ResourceType.
    async fn reconcile_audio(
        &self,
        _kind: SharedProviderResourceKind,
        _context: &SharedProviderEffectContext,
        _resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
    ) -> Result<SharedProviderEffectResult, SharedProviderEffectError> {
        Err(SharedProviderEffectError::Unavailable)
    }

    /// Reconcile one shell-terminal ResourceType.
    async fn reconcile_shell(
        &self,
        _kind: SharedProviderResourceKind,
        _context: &SharedProviderEffectContext,
        _resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
    ) -> Result<SharedProviderEffectResult, SharedProviderEffectError> {
        Err(SharedProviderEffectError::Unavailable)
    }

    /// Reconcile one Guest through its selected runtime Provider.
    async fn reconcile_guest(
        &self,
        kind: SharedProviderResourceKind,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
        dependencies: &[DependencySnapshot],
    ) -> Result<SharedProviderEffectPhase, SharedProviderEffectError> {
        let _ = (kind, context, resource, dependencies);
        Err(SharedProviderEffectError::Unavailable)
    }

    async fn reconcile_guest_result(
        &self,
        kind: SharedProviderResourceKind,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
        dependencies: &[DependencySnapshot],
    ) -> Result<SharedProviderEffectResult, SharedProviderEffectError> {
        self.reconcile_guest(kind, context, resource, dependencies)
            .await
            .map(SharedProviderEffectResult::phase)
    }

    async fn reconcile_result(
        &self,
        kind: SharedProviderResourceKind,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
        dependencies: &[DependencySnapshot],
    ) -> Result<SharedProviderEffectResult, SharedProviderEffectError> {
        if matches!(
            kind,
            SharedProviderResourceKind::CloudHypervisorGuest
                | SharedProviderResourceKind::QemuMediaGuest
                | SharedProviderResourceKind::AzureContainerAppsGuest
                | SharedProviderResourceKind::AzureVirtualMachineGuest
        ) {
            self.reconcile_guest_result(kind, context, resource, dependencies)
                .await
        } else if matches!(
            kind,
            SharedProviderResourceKind::DisplayWaylandPolicy
                | SharedProviderResourceKind::DisplayWaylandSession
        ) {
            self.reconcile_display(kind, context, resource, dependencies)
                .await
        } else if matches!(
            kind,
            SharedProviderResourceKind::AudioService
                | SharedProviderResourceKind::AudioBinding
        ) {
            self.reconcile_audio(kind, context, resource, dependencies)
                .await
        } else if matches!(
            kind,
            SharedProviderResourceKind::ShellPool | SharedProviderResourceKind::ShellSession
        ) {
            self.reconcile_shell(kind, context, resource, dependencies)
                .await
        } else {
            self.reconcile(kind, context, resource, dependencies)
                .await
                .map(SharedProviderEffectResult::phase)
        }
    }

    async fn observe_result(
        &self,
        kind: SharedProviderResourceKind,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
    ) -> Result<SharedProviderEffectResult, SharedProviderEffectError> {
        self.reconcile_result(kind, context, resource, &[]).await
    }

    /// Dispatch the closed Provider kind to its typed effect port.
    async fn reconcile(
        &self,
        kind: SharedProviderResourceKind,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
        dependencies: &[DependencySnapshot],
    ) -> Result<SharedProviderEffectPhase, SharedProviderEffectError> {
        match kind {
            SharedProviderResourceKind::Network => {
                self.reconcile_network(context, resource, dependencies).await
            }
            SharedProviderResourceKind::TpmDevice => {
                self.reconcile_tpm(context, resource, dependencies).await
            }
            SharedProviderResourceKind::UsbipDevice
            | SharedProviderResourceKind::UsbipService
            | SharedProviderResourceKind::UsbipBinding => self
                .reconcile_usbip(
                    kind.usbip_component().expect("USBIP kind has a component"),
                    context,
                    resource,
                    dependencies,
                )
                .await,
            SharedProviderResourceKind::SecurityKeyDevice
            | SharedProviderResourceKind::SecurityKeyService
            | SharedProviderResourceKind::SecurityKeyBinding => self
                .reconcile_security_key(
                    kind.security_key_component()
                        .expect("SecurityKey kind has a component"),
                    context,
                    resource,
                    dependencies,
                )
                .await,
            SharedProviderResourceKind::GpuDevice => {
                self.reconcile_gpu(context, resource, dependencies).await
            }
            SharedProviderResourceKind::CloudHypervisorGuest
            | SharedProviderResourceKind::QemuMediaGuest
            | SharedProviderResourceKind::AzureContainerAppsGuest
            | SharedProviderResourceKind::AzureVirtualMachineGuest => self
                .reconcile_guest(kind, context, resource, dependencies)
                .await,
            SharedProviderResourceKind::DisplayWaylandPolicy
            | SharedProviderResourceKind::DisplayWaylandSession => self
                .reconcile_display(kind, context, resource, dependencies)
                .await
                .map(|result| result.phase),
            SharedProviderResourceKind::AudioService
            | SharedProviderResourceKind::AudioBinding => self
                .reconcile_audio(kind, context, resource, dependencies)
                .await
                .map(|result| result.phase),
            SharedProviderResourceKind::ShellPool
            | SharedProviderResourceKind::ShellSession => self
                .reconcile_shell(kind, context, resource, dependencies)
                .await
                .map(|result| result.phase),
        }
    }

    /// Observe or repair one exact Provider-owned resource.
    async fn observe(
        &self,
        kind: SharedProviderResourceKind,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
    ) -> Result<SharedProviderEffectPhase, SharedProviderEffectError> {
        self.reconcile(kind, context, resource, &[]).await
    }

    /// Run provider cleanup before the owner finalizer is removed.
    async fn finalize(
        &self,
        kind: SharedProviderResourceKind,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
    ) -> Result<(), SharedProviderEffectError> {
    if matches!(
            kind,
            SharedProviderResourceKind::CloudHypervisorGuest
                | SharedProviderResourceKind::QemuMediaGuest
                | SharedProviderResourceKind::AzureContainerAppsGuest
                | SharedProviderResourceKind::AzureVirtualMachineGuest
        ) {
            return self.finalize_guest(kind, context, resource).await;
        }
        if matches!(
            kind,
            SharedProviderResourceKind::DisplayWaylandPolicy
                | SharedProviderResourceKind::DisplayWaylandSession
                | SharedProviderResourceKind::AudioService
                | SharedProviderResourceKind::AudioBinding
                | SharedProviderResourceKind::ShellPool
                | SharedProviderResourceKind::ShellSession
        ) {
            return Ok(());
        }
        let _ = (kind, context, resource);
        Err(SharedProviderEffectError::Unavailable)
    }

    /// Finalize one Guest through its selected runtime Provider.
    async fn finalize_guest(
        &self,
        kind: SharedProviderResourceKind,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
    ) -> Result<(), SharedProviderEffectError> {
        let _ = (kind, context, resource);
        Err(SharedProviderEffectError::Unavailable)
    }

    /// Run an accepted upgrade through the typed Provider lifecycle.
    async fn upgrade(
        &self,
        kind: SharedProviderResourceKind,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
        dependencies: &[DependencySnapshot],
    ) -> Result<SharedProviderEffectPhase, SharedProviderEffectError> {
        self.reconcile(kind, context, resource, dependencies).await
    }

    async fn upgrade_result(
        &self,
        kind: SharedProviderResourceKind,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
        dependencies: &[DependencySnapshot],
    ) -> Result<SharedProviderEffectResult, SharedProviderEffectError> {
        if matches!(
            kind,
            SharedProviderResourceKind::CloudHypervisorGuest
                | SharedProviderResourceKind::QemuMediaGuest
                | SharedProviderResourceKind::AzureContainerAppsGuest
                | SharedProviderResourceKind::AzureVirtualMachineGuest
        ) {
            self.reconcile_result(kind, context, resource, dependencies)
                .await
        } else if matches!(
            kind,
            SharedProviderResourceKind::DisplayWaylandPolicy
                | SharedProviderResourceKind::DisplayWaylandSession
                | SharedProviderResourceKind::AudioService
                | SharedProviderResourceKind::AudioBinding
                | SharedProviderResourceKind::ShellPool
                | SharedProviderResourceKind::ShellSession
        ) {
            self.reconcile_result(kind, context, resource, dependencies)
                .await
        } else {
            self.upgrade(kind, context, resource, dependencies)
                .await
                .map(SharedProviderEffectResult::phase)
        }
    }
}

/// Explicit unavailable adapter used only before production composition
/// supplies the daemon-owned typed effect boundary.
struct UnavailableSharedProviderEffects;

#[async_trait]
impl SharedProviderEffectExecutor for UnavailableSharedProviderEffects {
}

/// Production composition adapter for the closed shared-Runner Provider set.
///
/// The adapter performs the Provider-owned typed admission before any
/// effect-port call. A missing live broker/resource binding is returned as a
/// retryable refusal; it is never converted into generic convergence.
pub(crate) struct DaemonSharedProviderEffects {
    state: Arc<ServerState>,
    zone: ZoneId,
    usbip_ledger: Arc<
        std::sync::Mutex<
            crate::usbip_production::AuthorityLedger,
        >,
    >,
    usbip_services: Arc<Mutex<BTreeSet<ResourceUid>>>,
    gpu_controllers: Arc<Mutex<BTreeMap<ResourceUid, d2b_provider_device_gpu::GpuController>>>,
    gpu_authority_leases: Arc<Mutex<BTreeMap<[u8; 16], AuthorityLease>>>,
    gpu_processes: Arc<
        Mutex<
            BTreeMap<
                (ResourceUid, u8),
                d2b_provider_device_gpu::GpuProcessIdentity,
            >,
        >,
    >,
    gpu_opened_devices: Arc<Mutex<BTreeMap<ResourceUid, Vec<OwnedFd>>>>,
    tpm_controllers:
        Arc<Mutex<BTreeMap<ResourceUid, d2b_provider_device_tpm::TpmResourceController>>>,
    guest_controllers: Arc<
        tokio::sync::Mutex<
            BTreeMap<(ResourceRef, ResourceUid, u64, u64, u64, u64), GuestRuntimeController>,
        >,
    >,
}

impl DaemonSharedProviderEffects {
    pub(crate) fn new(state: Arc<ServerState>, zone: ZoneId) -> Self {
        Self {
            state,
            zone,
            usbip_ledger: crate::usbip_production::new_authority_ledger(),
            usbip_services: Arc::new(Mutex::new(BTreeSet::new())),
            gpu_controllers: Arc::new(Mutex::new(BTreeMap::new())),
            gpu_authority_leases: Arc::new(Mutex::new(BTreeMap::new())),
            gpu_processes: Arc::new(Mutex::new(BTreeMap::new())),
            gpu_opened_devices: Arc::new(Mutex::new(BTreeMap::new())),
            tpm_controllers: Arc::new(Mutex::new(BTreeMap::new())),
            guest_controllers: Arc::new(tokio::sync::Mutex::new(BTreeMap::new())),
        }
    }

    fn project_network_volume_spec(
        spec: Value,
        volume_uid: &ResourceUid,
        content: &d2b_provider_network_local::controller::NetworkConfigContent,
        fence: &SharedRunnerNetworkContentFence,
        owner_ref: &ResourceRef,
    ) -> Result<Value, NetworkEffectError> {
        network_config_spec_with_content(spec, volume_uid, content, fence, owner_ref)
    }

    #[cfg(test)]
    pub(crate) async fn test_reconcile_registration(
        &self,
        registration: SharedProviderRunnerRegistration,
        resource: &ResourceSnapshot,
    ) -> Result<SharedProviderEffectPhase, SharedProviderEffectError> {
        let controller_ref = ResourceRef::parse(registration.controller_ref)
            .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        let provider_ref = ResourceRef::parse(registration.provider_ref)
            .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        let identity = ControllerIdentity::new(
            resource.key().zone().clone(),
            controller_ref.clone(),
            ControllerGeneration::new(1)
                .map_err(|_| SharedProviderEffectError::InvalidResource)?,
            provider_ref,
            ResourceGeneration::new(1)
                .map_err(|_| SharedProviderEffectError::InvalidResource)?,
            controller_ref,
            ResourceRef::parse(CORE_CONTROLLER_HOST_REF)
                .map_err(|_| SharedProviderEffectError::InvalidResource)?,
            None,
        )
        .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        let context = SharedProviderEffectContext {
            identity,
            target: resource.key().clone(),
            operation_id: "test-daemon-provider-effect".to_owned(),
        };
        let kind = SharedProviderResourceKind::from_registration(registration)
            .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        <Self as SharedProviderEffectExecutor>::reconcile(self, kind, &context, resource, &[])
            .await
    }

    fn validate(
        &self,
        kind: SharedProviderResourceKind,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
    ) -> Result<Value, SharedProviderEffectError> {
        if context.operation_id.is_empty() {
            return Err(SharedProviderEffectError::InvalidResource);
        }
        if context.target != *resource.key()
            || context.identity.zone() != resource.key().zone()
            || resource.key().zone() != &self.zone
            || resource.key().resource_ref().resource_type().as_str() != kind.resource_type()
        {
            return Err(SharedProviderEffectError::InvalidResource);
        }
        let value = serde_json::from_slice::<Value>(resource.canonical_json())
            .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        if !matches!(
            kind,
            SharedProviderResourceKind::DisplayWaylandPolicy
                | SharedProviderResourceKind::DisplayWaylandSession
        ) && value.pointer("/spec/providerRef").and_then(Value::as_str)
            != Some(kind.provider_ref())
        {
            return Err(SharedProviderEffectError::InvalidResource);
        }
        Ok(value)
    }

    fn owner_ref(value: &Value) -> Result<ResourceRef, SharedProviderEffectError> {
        value
            .pointer("/metadata/ownerRef")
            .and_then(Value::as_str)
            .and_then(|value| ResourceRef::parse(value).ok())
            .ok_or(SharedProviderEffectError::InvalidResource)
    }

    fn runtime(&self) -> Result<Arc<ZoneResourceRuntime>, SharedProviderEffectError> {
        self.state
            .resource_plane
            .lock()
            .ok()
            .and_then(|plane| plane.as_ref().and_then(|plane| plane.zone(&self.zone).ok()))
            .ok_or(SharedProviderEffectError::Unavailable)
    }

    async fn usbip_service_port(
        &self,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
        value: &Value,
    ) -> Result<(ResourceUid, bool, SharedRunnerUsbipPort<'_>), SharedProviderEffectError> {
        let runtime = self.runtime()?;
        let zone_uid = runtime
            .authority_zone_uid()
            .cloned()
            .ok_or(SharedProviderEffectError::Unavailable)?;
        let device_ref = value
            .pointer("/spec/backingDeviceRef")
            .and_then(Value::as_str)
            .and_then(|value| ResourceRef::parse(value).ok())
            .ok_or(SharedProviderEffectError::InvalidResource)?;
        let device = runtime
            .committed_resource_value(&device_ref, &context.operation_id)
            .await
            .map_err(|_| SharedProviderEffectError::Unavailable)?;
        let device_uid = device
            .pointer("/metadata/uid")
            .and_then(Value::as_str)
            .and_then(|value| ResourceUid::parse(value.to_owned()).ok())
            .ok_or(SharedProviderEffectError::InvalidResource)?;
        if device.pointer("/spec/providerRef").and_then(Value::as_str)
                != Some(d2b_provider_device_usbip::PROVIDER_REF)
            || device.pointer("/status/phase").and_then(Value::as_str) != Some("Ready")
        {
            return Err(SharedProviderEffectError::Unavailable);
        }
        let env = value
            .pointer("/spec/env")
            .and_then(Value::as_str)
            .unwrap_or(resource.key().resource_ref().name().as_str());
        let physical_key =
            d2b_core::device_usbip_adapter::UsbipCoreAdapter::physical_usb_backing_key(
                device_uid.as_str().as_bytes(),
            )
            .as_bytes();
        let binding_context = crate::usbip_production::UsbipBindingContext::new(
            resource.key().resource_ref().name().as_str(),
            env,
            format!("shared-usbip-bind-{}", resource.key().uid().as_str()),
            format!("shared-usbip-runner-{}", resource.key().uid().as_str()),
            physical_key,
        )
        .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        let port = crate::usbip_production::DaemonUsbipDispatcher::new(
            &self.state,
            binding_context,
            Arc::clone(&self.usbip_ledger),
            SharedRunnerUsbipChildren,
        )
        .into_port();
        let opted_in =
            value.pointer("/spec/mode").and_then(Value::as_str) == Some("authority");
        Ok((zone_uid, opted_in, port))
    }

    fn dependencies_ready(dependencies: &[DependencySnapshot]) -> bool {
        dependencies.iter().all(|dependency| {
            serde_json::from_slice::<Value>(dependency.resource().canonical_json())
                .ok()
                .and_then(|value| {
                    value
                        .pointer("/status/phase")
                        .and_then(Value::as_str)
                        .map(|phase| phase == "Ready")
                })
                == Some(true)
        })
    }

    async fn finalize_u9(
        &self,
        kind: SharedProviderResourceKind,
        _context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
    ) -> Result<(), SharedProviderEffectError> {
        let runtime = self.runtime()?;
        match kind {
                SharedProviderResourceKind::DisplayWaylandPolicy => Ok(()),
                SharedProviderResourceKind::DisplayWaylandSession => {
                    let envelope = ResourceEnvelope::from_json(resource.canonical_json())
                        .map_err(|_| SharedProviderEffectError::InvalidResource)?;
                    let _spec = serde_json::from_slice::<WaylandSessionSpec>(
                        &envelope.spec().base().to_canonical_bytes(),
                    )
                    .map_err(|_| SharedProviderEffectError::InvalidResource)?;
                    let owner = crate::binding_child_resource_runtime::OwnedChildOwner {
                        resource: stored_resource_from_snapshot(resource),
                        desired: None,
                        fenced: false,
                    };
                    let client = runtime
                        .process_resource_client()
                        .ok_or(SharedProviderEffectError::Unavailable)?;
                    let converged = crate::binding_child_resource_runtime::reconcile_owned_children(
                        &runtime.store,
                        &client,
                        &self.zone,
                        std::slice::from_ref(&owner),
                    )
                    .await
                    .map_err(|_| SharedProviderEffectError::Unavailable)?;
                    if converged.contains(resource.key().resource_ref()) {
                        Ok(())
                    } else {
                        Err(SharedProviderEffectError::Unavailable)
                    }
                }
                SharedProviderResourceKind::AudioService => {
                    let bindings = runtime
                        .committed_resources_of_type(AUDIO_BINDING_TYPE)
                        .await
                        .map_err(|_| SharedProviderEffectError::Unavailable)?;
                    if bindings.iter().any(|binding| {
                        !value_deletion_requested(binding)
                            && binding
                                .pointer("/spec/serviceRef")
                                .and_then(Value::as_str)
                                == Some(resource.key().resource_ref().to_canonical_string().as_str())
                    }) {
                        Err(SharedProviderEffectError::Unavailable)
                    } else {
                        Ok(())
                    }
                }
                SharedProviderResourceKind::AudioBinding => {
                    runtime
                        .reconcile_audio_resources(Arc::clone(&self.state))
                        .await
                        .map_err(|_| SharedProviderEffectError::Unavailable)?;
                    let children =
                        crate::binding_child_resource_runtime::list_binding_children(
                            &runtime.store,
                            &self.zone,
                        )
                        .await
                        .map_err(|_| SharedProviderEffectError::Unavailable)?;
                    if children.iter().any(|child| {
                        ResourceEnvelope::from_json(&child.canonical_json)
                            .ok()
                            .and_then(|envelope| envelope.metadata().owner_ref().cloned())
                            == Some(resource.key().resource_ref().clone())
                    }) {
                        Err(SharedProviderEffectError::Unavailable)
                    } else {
                        Ok(())
                    }
                }
                SharedProviderResourceKind::ShellPool => {
                    let sessions = runtime
                        .committed_resources_of_type("shell-terminal.d2bus.org.ShellSession")
                        .await
                        .map_err(|_| SharedProviderEffectError::Unavailable)?;
                    let pool_ref = resource.key().resource_ref().to_canonical_string();
                    if sessions.iter().any(|session| {
                        !value_deletion_requested(session)
                            && session
                                .pointer("/spec/poolRef")
                                .and_then(Value::as_str)
                                == Some(pool_ref.as_str())
                    }) {
                        Err(SharedProviderEffectError::Unavailable)
                    } else {
                        Ok(())
                    }
                }
                SharedProviderResourceKind::ShellSession => {
                    let owner = crate::binding_child_resource_runtime::OwnedChildOwner {
                        resource: stored_resource_from_snapshot(resource),
                        desired: None,
                        fenced: false,
                    };
                    let client = runtime
                        .process_resource_client()
                        .ok_or(SharedProviderEffectError::Unavailable)?;
                    let converged = crate::binding_child_resource_runtime::reconcile_owned_children(
                        &runtime.store,
                        &client,
                        &self.zone,
                        std::slice::from_ref(&owner),
                    )
                    .await
                    .map_err(|_| SharedProviderEffectError::Unavailable)?;
                    if converged.contains(resource.key().resource_ref()) {
                        Ok(())
                    } else {
                        Err(SharedProviderEffectError::Unavailable)
                    }
                }
                _ => Err(SharedProviderEffectError::InvalidResource),
        }
    }

    async fn network_admission(
        &self,
        runtime: &ZoneResourceRuntime,
        resource: &ResourceSnapshot,
        value: &Value,
        spec: &d2b_contracts_resource::v3::network::NetworkSpec,
        resolver: &d2b_core::bundle_resolver::BundleResolver,
        operation_id: &str,
    ) -> Result<NetworkAdmissionProof, SharedProviderEffectError> {
        let zone_uid = runtime
            .authority_zone_uid()
            .cloned()
            .ok_or(SharedProviderEffectError::Unavailable)?;
        let network_generation = resource.generation();
        let network_ref = resource.key().resource_ref().to_canonical_string();
        let mut guest_uids = Vec::new();
        let mut attachment_generation = network_generation.get();
        for attachment in spec.attachments() {
            let attached = self
                .stored_resource(
                    runtime,
                    attachment.execution_ref(),
                    None,
                    operation_id,
                )
                .await?;
            if attached.zone != self.zone {
                return Err(SharedProviderEffectError::InvalidResource);
            }
            attachment_generation = attachment_generation.max(attached.generation.get());
            if attachment.execution_ref().resource_type().as_str() == "Guest" {
                guest_uids.push(attached.uid);
            }
            let attached_value = serde_json::from_slice::<Value>(&attached.canonical_json)
                .map_err(|_| SharedProviderEffectError::InvalidResource)?;
            let reciprocal = attached_value
                .pointer("/spec/networkAttachments")
                .and_then(Value::as_array)
                .is_some_and(|attachments| {
                    attachments.iter().any(|candidate| {
                        candidate.get("networkRef").and_then(Value::as_str)
                            == Some(network_ref.as_str())
                    })
                });
            if !reciprocal {
                return Err(SharedProviderEffectError::InvalidResource);
            }
        }
        for guest in runtime
            .committed_resources_of_type("Guest")
            .await
            .map_err(|_| SharedProviderEffectError::Unavailable)?
        {
            let attached = guest
                .pointer("/spec/networkAttachments")
                .and_then(Value::as_array)
                .is_some_and(|attachments| {
                    attachments.iter().any(|candidate| {
                        candidate.get("networkRef").and_then(Value::as_str)
                            == Some(network_ref.as_str())
                    })
                });
            if !attached {
                continue;
            }
            if guest.pointer("/metadata/zone").and_then(Value::as_str)
                != Some(self.zone.as_str())
            {
                return Err(SharedProviderEffectError::InvalidResource);
            }
            let guest_uid = guest
                .pointer("/metadata/uid")
                .and_then(Value::as_str)
                .and_then(|value| ResourceUid::parse(value.to_owned()).ok())
                .ok_or(SharedProviderEffectError::InvalidResource)?;
            guest_uids.push(guest_uid);
            let generation = guest
                .pointer("/metadata/generation")
                .and_then(Value::as_u64)
                .and_then(|value| ResourceGeneration::new(value).ok())
                .ok_or(SharedProviderEffectError::InvalidResource)?;
            attachment_generation = attachment_generation.max(generation.get());
        }
        let installed_generation = resolver
            .installed_generation_identity()
            .and_then(|identity| ResourceBundleGenerationId::parse(identity.as_str().to_owned()).ok())
            .ok_or(SharedProviderEffectError::Unavailable)?;
        if value.pointer("/metadata/uid").and_then(Value::as_str)
            != Some(resource.key().uid().as_str())
        {
            return Err(SharedProviderEffectError::InvalidResource);
        }
        let attachment_generation = ResourceGeneration::new(attachment_generation)
            .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        let intent = NetworkAdmissionIntent::new(
            NetworkAdmissionKey::new(
                zone_uid,
                resource.key().uid().clone(),
                network_generation,
                attachment_generation,
                installed_generation,
            ),
            spec.clone(),
            guest_uids,
        )
        .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        let plane = self
            .state
            .resource_plane
            .lock()
            .ok()
            .and_then(|plane| plane.clone())
            .ok_or(SharedProviderEffectError::Unavailable)?;
        let occupancy =
            observe_host_network().map_err(|_| SharedProviderEffectError::Unavailable)?;
        plane
            .network_admission_index()
            .lock()
            .await
            .admit(intent, &occupancy)
            .map_err(|_| SharedProviderEffectError::Unavailable)
    }

    async fn network_assignment(
        &self,
        runtime: &ZoneResourceRuntime,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
    ) -> Result<ResourceAssignmentFence, SharedProviderEffectError> {
        let assignment = runtime
            .store
            .assignment_fence(self.zone.clone(), resource.key().resource_ref().clone())
            .await
            .map_err(|_| SharedProviderEffectError::Unavailable)?
            .ok_or(SharedProviderEffectError::Unavailable)?;
        let session_generation = runtime
            .core_controller_subject
            .lock()
            .map_err(|_| SharedProviderEffectError::Unavailable)?
            .as_ref()
            .map(|subject| subject.reconnect_generation())
            .ok_or(SharedProviderEffectError::Unavailable)?;
        let host_ref = ResourceRef::parse(CORE_CONTROLLER_HOST_REF)
            .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        if assignment.epoch == 0
            || assignment.resource_uid != *resource.key().uid()
            || assignment.provider_generation != context.identity.provider_generation()
            || assignment.controller_generation != context.identity.controller_generation()
            || assignment.controller_role != *context.identity.controller_ref()
            || assignment.target != host_ref
            || assignment.session_generation != session_generation
            || !matches!(assignment.scope, ResourceAssignmentScope::Primary)
        {
            return Err(SharedProviderEffectError::InvalidResource);
        }
        Ok(assignment)
    }

    fn gpu_digest(
        domain: &str,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
        assignment_epoch: u64,
        extra: &str,
    ) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(domain.as_bytes());
        digest.update([0]);
        digest.update(resource.key().uid().as_str().as_bytes());
        digest.update([0]);
        digest.update(context.identity.provider_generation().get().to_be_bytes());
        digest.update(context.identity.controller_generation().get().to_be_bytes());
        digest.update(assignment_epoch.to_be_bytes());
        digest.update(extra.as_bytes());
        digest.finalize().into()
    }

    async fn gpu_admission(
        &self,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
        value: &Value,
    ) -> Result<
        (
            Arc<ZoneResourceRuntime>,
            d2b_provider_device_gpu::GpuAuthorityAdmission,
            d2b_provider_device_gpu::GpuEffectTokenSet,
            d2b_provider_device_gpu::GpuSettings,
            ResourceRef,
        ),
        SharedProviderEffectError,
    > {
        let runtime = self.runtime()?;
        if runtime.authority_zone_uid().is_none() {
            return Err(SharedProviderEffectError::Unavailable);
        }
        let holder_ref = Self::owner_ref(value)?;
        if !matches!(holder_ref.resource_type().as_str(), "Guest" | "Host") {
            return Err(SharedProviderEffectError::InvalidResource);
        }
        let _holder = self
            .stored_resource(&runtime, &holder_ref, None, &context.operation_id)
            .await?;
        let hosts = runtime
            .committed_resources_of_type("Host")
            .await
            .map_err(|_| SharedProviderEffectError::Unavailable)?;
        let [host] = hosts.as_slice() else {
            return Err(SharedProviderEffectError::InvalidResource);
        };
        let host_uid = host
            .pointer("/metadata/uid")
            .and_then(Value::as_str)
            .and_then(|value| ResourceUid::parse(value.to_owned()).ok())
            .ok_or(SharedProviderEffectError::InvalidResource)?;
        let settings: d2b_provider_device_gpu::GpuSettings =
            match value.pointer("/spec/provider/settings") {
                Some(settings) => serde_json::from_value(settings.clone())
                    .map_err(|_| SharedProviderEffectError::InvalidResource)?,
                None => d2b_provider_device_gpu::GpuSettings::default(),
            };
        let arbitration: d2b_contracts_resource::v3::device::DeviceArbitration =
            serde_json::from_value(
                value
                    .pointer("/spec/arbitration")
                    .cloned()
                    .unwrap_or_else(|| Value::String("exclusive".to_owned())),
            )
            .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        let max_holders = value
            .pointer("/spec/maxConcurrentClaims")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(1);
        let session_generation = runtime
            .core_controller_subject
            .lock()
            .map_err(|_| SharedProviderEffectError::Unavailable)?
            .as_ref()
            .map(|subject| subject.reconnect_generation().get())
            .ok_or(SharedProviderEffectError::Unavailable)?;
        let assignment = runtime
            .store
            .assignment_fence(self.zone.clone(), resource.key().resource_ref().clone())
            .await
            .map_err(|_| SharedProviderEffectError::Unavailable)?
            .ok_or(SharedProviderEffectError::Unavailable)?;
        if assignment.epoch == 0
            || assignment.provider_generation != context.identity.provider_generation()
            || assignment.controller_generation != context.identity.controller_generation()
            || assignment.controller_role != *context.identity.controller_ref()
            || assignment.target
                != ResourceRef::parse(CORE_CONTROLLER_HOST_REF)
                    .map_err(|_| SharedProviderEffectError::InvalidResource)?
            || assignment.session_generation.get() != session_generation
        {
            return Err(SharedProviderEffectError::InvalidResource);
        }
        let assignment_epoch = assignment.epoch;
        let mut backing_digest = Self::gpu_digest(
            "d2b:gpu-backing/v2",
            context,
            resource,
            assignment_epoch,
            "backing",
        );
        backing_digest[..8].copy_from_slice(&session_generation.to_be_bytes());
        let platform_digest = Self::gpu_digest(
            "d2b:gpu-platform/v2",
            context,
            resource,
            assignment_epoch,
            host_uid.as_str(),
        );
        let gpu_principal_digest = Self::gpu_digest(
            "d2b:gpu-principal/v2",
            context,
            resource,
            assignment_epoch,
            "gpu",
        );
        let owner = d2b_provider_device_gpu::GpuOwnerProof::new(
            ResourceRef::parse(&format!("Zone/{}", self.zone.as_str()))
                .map_err(|_| SharedProviderEffectError::InvalidResource)?,
            holder_ref.clone(),
            resource.key().uid().clone(),
            host_uid,
            resource.generation(),
        )
        .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        let mut admission = d2b_provider_device_gpu::GpuAuthorityAdmission::new(
            owner,
            d2b_provider_device_gpu::GpuBackingToken::from_core(backing_digest),
            d2b_provider_device_gpu::GpuPlatformToken::from_core(platform_digest),
            arbitration,
            u32::try_from(max_holders).map_err(|_| SharedProviderEffectError::InvalidResource)?,
            settings.render_node_only,
            d2b_provider_device_gpu::GpuPrincipalToken::from_core(gpu_principal_digest),
        )
        .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        if settings.video_sidecar {
            admission = admission
                .with_video_principal(d2b_provider_device_gpu::GpuPrincipalToken::from_core(
                    Self::gpu_digest(
                        "d2b:gpu-principal/v2",
                        context,
                        resource,
                        assignment_epoch,
                        "video",
                    ),
                ))
                .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        }
        let mut token_values = vec!["dri"];
        if !settings.render_node_only {
            token_values.extend(["kvm", "udmabuf"]);
        }
        if settings.video_sidecar && settings.video_nvidia_decode {
            token_values.extend(["nvidia-ctl", "nvidia-device", "nvidia-uvm"]);
        }
        let tokens = d2b_provider_device_gpu::GpuEffectTokenSet::from_core(
            token_values
                .into_iter()
                .map(|device_class| {
                    d2b_provider_device_gpu::GpuEffectToken::from_core(Self::gpu_digest(
                        "d2b:gpu-device-grant/v2",
                        context,
                        resource,
                        assignment_epoch,
                        device_class,
                    ))
                })
                .collect(),
        )
        .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        Ok((runtime, admission, tokens, settings, holder_ref))
    }

    async fn stored_resource(
        &self,
        runtime: &ZoneResourceRuntime,
        target: &ResourceRef,
        expected_uid: Option<ResourceUid>,
        operation_id: &str,
    ) -> Result<StoredResource, SharedProviderEffectError> {
        let resource = runtime
            .store
            .get(StoreGetRequest {
                operation: StoreOperationContext {
                    operation_id: operation_id.to_owned(),
                    idempotency_key: None,
                    correlation_id: operation_id.to_owned(),
                    trace_id: None,
                    deadline_ms: 10_000,
                },
                zone: self.zone.clone(),
                target: target.clone(),
                expected_uid,
                projection: StoreProjection::Full,
            })
            .await
            .map_err(|_| SharedProviderEffectError::Unavailable)?;
        if resource.zone != self.zone || resource.resource_ref != *target {
            return Err(SharedProviderEffectError::InvalidResource);
        }
        Ok(resource)
    }

    async fn reconcile_binding_children(
        &self,
        runtime: &ZoneResourceRuntime,
        owner: &ResourceSnapshot,
        desired: d2b_contracts_provider::v3::semantic_services::child_resources::BindingChildSet,
        operation_id: &str,
    ) -> Result<SharedProviderEffectPhase, SharedProviderEffectError> {
        let owner = self
            .stored_resource(
                runtime,
                owner.key().resource_ref(),
                Some(owner.key().uid().clone()),
                operation_id,
            )
            .await?;
        let owner_ref = owner.resource_ref.clone();
        let client = runtime
            .process_resource_client()
            .ok_or(SharedProviderEffectError::Unavailable)?;
        let converged = crate::binding_child_resource_runtime::reconcile_binding_children(
            &runtime.store,
            &client,
            &self.zone,
            &[crate::binding_child_resource_runtime::BindingChildOwner {
                resource: owner,
                desired: Some(desired),
                fenced: false,
            }],
        )
        .await
        .map_err(|_| SharedProviderEffectError::Unavailable)?;
        Ok(if converged.contains(&owner_ref) {
            SharedProviderEffectPhase::Ready
        } else {
            SharedProviderEffectPhase::Pending
        })
    }

    async fn cleanup_binding_children(
        &self,
        runtime: &ZoneResourceRuntime,
        owner: &ResourceSnapshot,
        operation_id: &str,
    ) -> Result<bool, SharedProviderEffectError> {
        let stored = self
            .stored_resource(
                runtime,
                owner.key().resource_ref(),
                Some(owner.key().uid().clone()),
                operation_id,
            )
            .await?;
        let children = crate::binding_child_resource_runtime::list_binding_children(
            &runtime.store,
            &self.zone,
        )
        .await
        .map_err(|_| SharedProviderEffectError::Unavailable)?;
        let has_children = children.iter().any(|child| {
            ResourceEnvelope::from_json(&child.canonical_json)
                .ok()
                .and_then(|envelope| envelope.metadata().owner_ref().cloned())
                == Some(stored.resource_ref.clone())
        });
        if !has_children {
            return Ok(true);
        }
        let client = runtime
            .process_resource_client()
            .ok_or(SharedProviderEffectError::Unavailable)?;
        crate::binding_child_resource_runtime::reconcile_binding_children(
            &runtime.store,
            &client,
            &self.zone,
            &[crate::binding_child_resource_runtime::BindingChildOwner {
                resource: stored,
                desired: None,
                fenced: false,
            }],
        )
        .await
        .map_err(|_| SharedProviderEffectError::Unavailable)?;
        let remaining = crate::binding_child_resource_runtime::list_binding_children(
            &runtime.store,
            &self.zone,
        )
        .await
        .map_err(|_| SharedProviderEffectError::Unavailable)?;
        Ok(!remaining.iter().any(|child| {
            ResourceEnvelope::from_json(&child.canonical_json)
                .ok()
                .and_then(|envelope| envelope.metadata().owner_ref().cloned())
                == Some(owner.key().resource_ref().clone())
        }))
    }

    fn take_gpu_opened_devices(
        &self,
        device_uid: &ResourceUid,
    ) -> Result<Vec<OwnedFd>, SharedProviderEffectError> {
        Ok(self
            .gpu_opened_devices
            .lock()
            .map_err(|_| SharedProviderEffectError::Unavailable)?
            .remove(device_uid)
            .unwrap_or_default())
    }

    fn retain_gpu_opened_devices(
        &self,
        device_uid: &ResourceUid,
        opened_devices: Vec<OwnedFd>,
    ) -> Result<(), SharedProviderEffectError> {
        self.gpu_opened_devices
            .lock()
            .map_err(|_| SharedProviderEffectError::Unavailable)?
            .insert(device_uid.clone(), opened_devices);
        Ok(())
    }

    async fn guest_provider_resource(
        &self,
        kind: SharedProviderResourceKind,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
    ) -> Result<Value, SharedProviderEffectError> {
        let value = self.validate(kind, context, resource)?;
        if resource.key().resource_ref().resource_type().as_str() != "Guest"
            || resource.key().uid().as_str().is_empty()
            || resource.generation().get() == 0
        {
            return Err(SharedProviderEffectError::InvalidResource);
        }
        Ok(value)
    }

    fn guest_phase(value: &Value) -> SharedProviderEffectPhase {
        if value.pointer("/status/phase").and_then(Value::as_str) == Some("Ready")
            && value
                .pointer("/status/observedGeneration")
                .and_then(Value::as_u64)
                == value.pointer("/metadata/generation").and_then(Value::as_u64)
        {
            SharedProviderEffectPhase::Ready
        } else {
            SharedProviderEffectPhase::Pending
        }
    }

    fn related_guest_dependency(
        guest: &Value,
        dependency: &DependencySnapshot,
    ) -> Result<bool, SharedProviderEffectError> {
        let dependency_value = serde_json::from_slice::<Value>(dependency.resource().canonical_json())
            .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        let dependency_ref = dependency.resource().key().resource_ref().to_canonical_string();
        if Self::value_contains_resource_ref(guest, &dependency_ref) {
            Ok(dependency_value.pointer("/status/phase").and_then(Value::as_str) == Some("Ready"))
        } else {
            Ok(true)
        }
    }

    fn value_contains_resource_ref(value: &Value, expected: &str) -> bool {
        match value {
            Value::String(value) => value == expected,
            Value::Array(values) => values
                .iter()
                .any(|value| Self::value_contains_resource_ref(value, expected)),
            Value::Object(values) => values
                .values()
                .any(|value| Self::value_contains_resource_ref(value, expected)),
            Value::Null | Value::Bool(_) | Value::Number(_) => false,
        }
    }

    fn validate_qemu_guest(value: &Value) -> Result<(), SharedProviderEffectError> {
        let settings = value
            .pointer("/spec/provider/settings")
            .cloned()
            .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
        serde_json::from_value::<d2b_provider_runtime_qemu_media::GuestProviderSpecSettings>(
            settings,
        )
        .map(|_| ())
        .map_err(|_| SharedProviderEffectError::InvalidResource)
    }

    fn validate_azure_vm_guest(value: &Value) -> Result<(), SharedProviderEffectError> {
        let settings = Self::azure_vm_guest_settings_value(value)?;
        serde_json::from_value::<d2b_provider_runtime_azure_virtual_machine::AzureVmGuestSettings>(
            settings,
        )
        .map(|_| ())
        .map_err(|_| SharedProviderEffectError::InvalidResource)
    }

    fn azure_vm_guest_settings_value(value: &Value) -> Result<Value, SharedProviderEffectError> {
        if let Some(settings) = value.pointer("/spec/provider/settings").cloned() {
            return Ok(settings);
        }
        #[cfg(test)]
        if value
            .pointer("/metadata/annotations/d2b.test~1azure-vm-settings")
            .and_then(Value::as_str)
            == Some("framework")
        {
            return Ok(json!({
                "subscriptionId": "subscription",
                "resourceGroup": "resource-group",
                "region": "eastus",
                "vmSize": "standard-d4",
                "imageRef": "image-1",
                "diskSku": "Premium_LRS",
                "osDiskSizeGb": 64,
                "adminUser": "azureuser",
                "vnetSubscriptionId": null,
                "vnetResourceGroup": null,
                "vnetName": "vnet",
                "subnetName": "guests",
                "assignPublicIp": false,
                "dataDisks": [],
                "bootstrapPskDelivery": "vm-extension",
                "bootstrapDeadlineMs": 60000,
                "childZoneHosting": false,
                "azureTags": [["owner", "d2b"]]
            }));
        }
        Err(SharedProviderEffectError::InvalidResource)
    }

    async fn validate_gateway_custody(
        &self,
        provider_ref: &ResourceRef,
        credential_fields: &[&str],
        context: &SharedProviderEffectContext,
    ) -> Result<(), SharedProviderEffectError> {
        let runtime = self.runtime()?;
        let provider = runtime
            .committed_resource_value(provider_ref, &context.operation_id)
            .await
            .map_err(|_| SharedProviderEffectError::Unavailable)?;
        let config = provider
            .pointer("/spec/config")
            .ok_or(SharedProviderEffectError::InvalidResource)?;
        let gateway = config
            .get("gatewayExecutionRef")
            .or_else(|| config.get("controllerExecutionRef"))
            .and_then(Value::as_str)
            .and_then(|value| ResourceRef::parse(value).ok())
            .ok_or(SharedProviderEffectError::InvalidResource)?;
        if gateway.resource_type().as_str() != "Guest" {
            return Err(SharedProviderEffectError::InvalidResource);
        }
        let gateway_resource = runtime
            .committed_resource_value(&gateway, &context.operation_id)
            .await
            .map_err(|_| SharedProviderEffectError::Unavailable)?;
        if gateway_resource.pointer("/metadata/zone").and_then(Value::as_str)
            != Some(self.zone.as_str())
            || gateway_resource.pointer("/status/phase").and_then(Value::as_str)
                != Some("Ready")
        {
            return Err(SharedProviderEffectError::Unavailable);
        }
        for field in credential_fields {
            let Some(credential_ref) = config
                .get(*field)
                .and_then(Value::as_str)
                .and_then(|value| ResourceRef::parse(value).ok())
            else {
                continue;
            };
            if credential_ref.resource_type().as_str() != "Credential" {
                return Err(SharedProviderEffectError::InvalidResource);
            }
            let credential = runtime
                .committed_resource_value(&credential_ref, &context.operation_id)
                .await
                .map_err(|_| SharedProviderEffectError::Unavailable)?;
            // U10 owns token acquisition and delivery. U6 consumes only the
            // stable, typed Credential scope contract at admission.
            let scope = credential
                .pointer("/spec/scope")
                .cloned()
                .ok_or(SharedProviderEffectError::InvalidResource)?;
            let scope = serde_json::from_value::<
                d2b_contracts_provider::v3::credential::CredentialScope,
            >(scope)
            .map_err(|_| SharedProviderEffectError::InvalidResource)?;
            if scope.execution_ref() != Some(&gateway) {
                return Err(SharedProviderEffectError::InvalidResource);
            }
        }
        Ok(())
    }

    async fn validate_guest_runtime_fence(
        &self,
        kind: SharedProviderResourceKind,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
    ) -> Result<Arc<ZoneResourceRuntime>, SharedProviderEffectError> {
        let runtime = self.runtime()?;
        let expected_controller = ResourceRef::parse(match kind {
            SharedProviderResourceKind::QemuMediaGuest => {
                "Process/runtime-qemu-media-controller"
            }
            SharedProviderResourceKind::AzureContainerAppsGuest => "Process/aca-controller",
            SharedProviderResourceKind::AzureVirtualMachineGuest => {
                "Process/azure-vm-controller-process"
            }
            SharedProviderResourceKind::CloudHypervisorGuest => {
                "Process/cloud-hypervisor-controller"
            }
            _ => return Err(SharedProviderEffectError::InvalidResource),
        })
        .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        if context.identity.controller_ref() != &expected_controller
            || context.identity.zone() != resource.key().zone()
            || resource.key().zone() != &self.zone
        {
            return Err(SharedProviderEffectError::InvalidResource);
        }
        let metadata = runtime
            .store
            .runtime_metadata()
            .await
            .map_err(|_| SharedProviderEffectError::Unavailable)?;
        if metadata.policy_snapshot.controller_generation
            != Some(context.identity.controller_generation())
        {
            return Err(SharedProviderEffectError::InvalidResource);
        }
        let provider_ref = ResourceRef::parse(kind.provider_ref())
            .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        let provider = runtime
            .store
            .get(StoreGetRequest {
                operation: StoreOperationContext {
                    operation_id: context.operation_id.clone(),
                    idempotency_key: None,
                    correlation_id: context.operation_id.clone(),
                    trace_id: None,
                    deadline_ms: 10_000,
                },
                zone: self.zone.clone(),
                target: provider_ref,
                expected_uid: None,
                projection: StoreProjection::MetadataOnly,
            })
            .await
            .map_err(|_| SharedProviderEffectError::Unavailable)?;
        if provider.zone != self.zone
            || provider.generation != context.identity.provider_generation()
        {
            return Err(SharedProviderEffectError::InvalidResource);
        }
        let Some(fence) = runtime
            .store
            .assignment_fence(
                self.zone.clone(),
                resource.key().resource_ref().clone(),
            )
            .await
            .map_err(|_| SharedProviderEffectError::Unavailable)?
        else {
            return Err(SharedProviderEffectError::Unavailable);
        };
        let session_generation = runtime
            .core_controller_subject
            .lock()
            .map_err(|_| SharedProviderEffectError::Unavailable)?
            .as_ref()
            .map(AuthenticatedSubjectContext::reconnect_generation)
            .ok_or(SharedProviderEffectError::Unavailable)?;
        if fence.resource_uid != *resource.key().uid()
            || fence.resource_revision != resource.revision()
            || fence.provider_generation != context.identity.provider_generation()
            || fence.controller_generation != context.identity.controller_generation()
            || fence.controller_role != expected_controller
            || fence.session_generation != session_generation
            || fence.epoch == 0
        {
            return Err(SharedProviderEffectError::InvalidResource);
        }
        Ok(runtime)
    }

    async fn stored_guest(
        &self,
        runtime: &ZoneResourceRuntime,
        resource: &ResourceSnapshot,
        operation_id: &str,
    ) -> Result<StoredResource, SharedProviderEffectError> {
        runtime
            .store
            .get(StoreGetRequest {
                operation: StoreOperationContext {
                    operation_id: operation_id.to_owned(),
                    idempotency_key: None,
                    correlation_id: operation_id.to_owned(),
                    trace_id: None,
                    deadline_ms: 10_000,
                },
                zone: self.zone.clone(),
                target: resource.key().resource_ref().clone(),
                expected_uid: Some(resource.key().uid().clone()),
                projection: StoreProjection::Full,
            })
            .await
            .map_err(|_| SharedProviderEffectError::Unavailable)
    }

    fn guest_child_resource(
        target: &ResourceRef,
        owner: &ResourceRef,
        zone: &ZoneId,
        spec: Value,
    ) -> Result<Vec<u8>, SharedProviderEffectError> {
        let value = json!({
            "apiVersion": "resources.d2bus.org/v3",
            "type": target.resource_type().as_str(),
            "metadata": {
                "name": target.name().as_str(),
                "zone": zone.as_str(),
                "ownerRef": owner.to_canonical_string(),
                "finalizers": [],
                "deletionRequestedAt": null,
                "createdAt": "1970-01-01T00:00:00.000Z",
                "updatedAt": "1970-01-01T00:00:00.000Z",
                "generation": 1,
                "revision": 1,
                "managedBy": "controller"
            },
            "spec": spec,
            "status": {
                "observedGeneration": 0,
                "phase": "Pending",
                "conditions": [],
                "lastReconciledAt": null,
                "startedAt": null,
                "completedAt": null,
                "outcome": null,
                "update": {
                    "dependencies": {"count": 0, "refs": []},
                    "disruption": "None",
                    "observedGeneration": 0,
                    "lastAssessedAt": null,
                    "operationId": null,
                    "owned": {"count": 0, "refs": []},
                    "preserveState": true,
                    "reasons": [],
                    "state": "Unknown",
                    "targetGeneration": 1
                },
                "resource": {}
            }
        });
        CanonicalJsonValue::parse(
            &serde_json::to_vec(&value)
                .map_err(|_| SharedProviderEffectError::InvalidResource)?,
        )
        .map(|value| value.to_canonical_bytes())
        .map_err(|_| SharedProviderEffectError::InvalidResource)
    }

    fn qemu_guest_children(
        value: &Value,
        provider: &Value,
        owner: &ResourceRef,
        zone: &ZoneId,
    ) -> Result<Vec<OwnedChildIntent>, SharedProviderEffectError> {
        let config = serde_json::from_value::<qemu_media_runtime::ProviderConfig>(
            provider
                .pointer("/spec/config")
                .cloned()
                .ok_or(SharedProviderEffectError::InvalidResource)?,
        )
        .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        let runtime_volume_ref = ResourceRef::parse(&format!(
            "Volume/{}-runtime",
            owner.name().as_str()
        ))
        .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        let device_ref = value
            .pointer("/spec/deviceAttachments")
            .and_then(Value::as_array)
            .and_then(|attachments| attachments.first())
            .and_then(|attachment| attachment.get("deviceRef"))
            .and_then(Value::as_str)
            .map(ResourceRef::parse)
            .transpose()
            .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        let network_refs = value
            .pointer("/spec/networkAttachments")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|attachment| attachment.get("networkRef").and_then(Value::as_str))
            .map(ResourceRef::parse)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        let process = qemu_media_runtime::build_process_spec(
            config.controller_execution_ref.clone(),
            runtime_volume_ref,
            device_ref,
            network_refs,
        )
        .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        let mut process_spec =
            serde_json::to_value(process).map_err(|_| SharedProviderEffectError::InvalidResource)?;
        process_spec
            .as_object_mut()
            .ok_or(SharedProviderEffectError::InvalidResource)?
            .insert(
                "providerRef".to_owned(),
                Value::String("Provider/system-minijail".to_owned()),
            );
        let process_ref = ResourceRef::parse(&format!("Process/{}-qemu", owner.name().as_str()))
            .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        let process = Self::guest_child_resource(&process_ref, owner, zone, process_spec)?;
        let digest = d2b_core_controller::semantic_child_digest(&process)
            .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        let process = OwnedChildIntent::new(process_ref, process, digest)
            .and_then(|process| {
                process
                    .with_dependencies([ResourceRef::parse(&format!(
                        "Volume/{}-runtime",
                        owner.name().as_str()
                    ))
                    .map_err(|_| {
                        d2b_core_controller::OwnerReconcileError::InvalidChild
                    })?])
            })
            .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        let volume_ref = ResourceRef::parse(&format!(
            "Volume/{}-runtime",
            owner.name().as_str()
        ))
        .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        let volume_spec = json!({
            "providerRef": "Provider/volume-local",
            "source": {
                "executionRef": config.controller_execution_ref.to_canonical_string(),
                "settings": {"kind": "tmpfs"}
            },
            "kind": "ephemeral",
            "layout": [],
            "views": {
                "runner": {
                    "path": "",
                    "rights": ["read", "write", "create", "delete", "traverse"]
                }
            },
            "attachments": [],
            "quota": {
                "maxBytes": config.runtime_tmpfs_quota_bytes,
                "maxInodes": config.runtime_tmpfs_quota_inodes,
                "enforcement": "hard"
            }
        });
        let volume = Self::guest_child_resource(&volume_ref, owner, zone, volume_spec)?;
        let volume_digest = d2b_core_controller::semantic_child_digest(&volume)
            .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        let volume = OwnedChildIntent::new(volume_ref, volume, volume_digest)
            .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        Ok(vec![volume, process])
    }

    fn aca_guest_children(
        owner: &ResourceRef,
        zone: &ZoneId,
    ) -> Result<Vec<OwnedChildIntent>, SharedProviderEffectError> {
        let target = ResourceRef::parse(&format!("Endpoint/{}-sandbox-agent", owner.name().as_str()))
            .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        let spec = json!({
            "providerRef": aca_runtime::PROVIDER_REF,
            "producerRef": owner.to_canonical_string(),
            "endpointClass": "control",
            "transport": "opaque-carriage",
            "purpose": "aca-sandbox-agent",
            "locality": "cross-domain",
            "visibility": "provider",
            "attachmentPolicy": {
                "supported": false,
                "maxAttachments": 0
            },
            "consumerPolicy": {
                "allowedSubjects": [aca_runtime::PROVIDER_REF],
                "allowedOperations": ["resolve"]
            },
            "lifecyclePolicy": "recycle-with-producer"
        });
        let canonical = Self::guest_child_resource(&target, owner, zone, spec)?;
        let digest = d2b_core_controller::semantic_child_digest(&canonical)
            .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        Ok(vec![
            OwnedChildIntent::new(target, canonical, digest)
                .map_err(|_| SharedProviderEffectError::InvalidResource)?,
        ])
    }

    async fn guest_child_progress(
        &self,
        runtime: &ZoneResourceRuntime,
        resource: &ResourceSnapshot,
        desired: Option<Vec<OwnedChildIntent>>,
    ) -> Result<OneOwnedChildProgress, SharedProviderEffectError> {
        let owner = self
            .stored_guest(runtime, resource, "u6-guest-child-owner")
            .await?;
        let client = runtime
            .status_client()
            .map_err(|_| SharedProviderEffectError::Unavailable)?;
        reconcile_one_guest_child(
            &runtime.store,
            &client,
            &self.zone,
            &OwnedChildOwner {
                resource: owner,
                desired,
                fenced: false,
            },
        )
        .await
        .map_err(|_| SharedProviderEffectError::Unavailable)
    }

    async fn guest_children_ready(
        &self,
        runtime: &ZoneResourceRuntime,
        owner: &ResourceSnapshot,
        desired: &[OwnedChildIntent],
    ) -> Result<bool, SharedProviderEffectError> {
        let owner_ref = owner.key().resource_ref().to_canonical_string();
        let mut children = Vec::new();
        for resource_type in ["Process", "EphemeralProcess", "Endpoint", "Volume"] {
            children.extend(
                runtime
                    .committed_resources_of_type(resource_type)
                    .await
                    .map_err(|_| SharedProviderEffectError::Unavailable)?,
            );
        }
        Ok(desired.iter().all(|intent| {
            children.iter().any(|child| {
                child.pointer("/metadata/ownerRef").and_then(Value::as_str)
                    == Some(owner_ref.as_str())
                    && child.pointer("/type").and_then(Value::as_str)
                        == Some(intent.target().resource_type().as_str())
                    && child.pointer("/metadata/name").and_then(Value::as_str)
                        == Some(intent.target().name().as_str())
                    && matches!(
                        child.pointer("/status/phase").and_then(Value::as_str),
                        Some("Ready" | "Succeeded")
                    )
            })
        }))
    }

    fn framework_operation_id(prefix: &str, operation_id: &str) -> String {
        let digest = Sha256::digest(format!("{prefix}:{operation_id}").as_bytes());
        let mut id = String::with_capacity(24);
        id.push_str("u6-");
        id.push_str(prefix);
        for byte in digest.iter().take(8) {
            id.push_str(&format!("{byte:02x}"));
        }
        id
    }

    fn qemu_dependencies(
        value: &Value,
        dependencies: &[DependencySnapshot],
        children: &[Value],
        effect: &FrameworkQemuEffect,
    ) -> Result<qemu_media_runtime::QemuMediaDependencies, SharedProviderEffectError> {
        let ready = |reference: &ResourceRef| {
            dependencies.iter().any(|dependency| {
                dependency.resource().key().resource_ref() == reference
                    && serde_json::from_slice::<Value>(dependency.resource().canonical_json())
                        .ok()
                        .and_then(|value| value.pointer("/status/phase").and_then(Value::as_str).map(|phase| phase == "Ready"))
                        == Some(true)
            })
        };
        let device_ref = value
            .pointer("/spec/deviceAttachments")
            .and_then(Value::as_array)
            .and_then(|attachments| attachments.first())
            .and_then(|attachment| attachment.get("deviceRef"))
            .and_then(Value::as_str)
            .map(ResourceRef::parse)
            .transpose()
            .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        let device = device_ref
            .as_ref()
            .filter(|reference| ready(reference))
            .map(|reference| qemu_media_runtime::DeviceObservation {
                device_ref: (*reference).clone(),
                phase: qemu_media_runtime::DevicePhase::Ready,
                owner_ref: value
                    .pointer("/metadata/ownerRef")
                    .and_then(Value::as_str)
                    .and_then(|owner| ResourceRef::parse(owner).ok()),
                platform: qemu_media_runtime::PlatformClass::X86_64Linux,
                authority_key: Sha256::digest(reference.to_canonical_string().as_bytes()).into(),
                process_identity: Some("qemu-media-runner".to_owned()),
                media_contract: "qemu-media/v1".to_owned(),
            });
        let settings = serde_json::from_value::<qemu_media_runtime::GuestProviderSpecSettings>(
            value
                .pointer("/spec/provider/settings")
                .cloned()
                .unwrap_or_else(|| Value::Object(serde_json::Map::new())),
        )
        .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        let mut media_refs = Vec::new();
        if let Some(reference) = settings.boot_media_ref.clone() {
            media_refs.push(reference);
        }
        media_refs.extend(
            settings
                .removable_volume_refs
                .iter()
                .map(|reference| reference.volume_ref.clone()),
        );
        let media_ready = media_refs.iter().all(ready);
        let network_ready = value
            .pointer("/spec/networkAttachments")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|attachment| attachment.get("networkRef").and_then(Value::as_str))
            .map(ResourceRef::parse)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| SharedProviderEffectError::InvalidResource)?
            .iter()
            .all(ready);
        let display_ref = if settings.display_window {
            dependencies
                .iter()
                .find(|dependency| dependency.resource().key().resource_ref().resource_type().as_str() == "Endpoint")
                .map(|dependency| dependency.resource().key().resource_ref().clone())
        } else {
            None
        };
        let runtime_volume_ready = children.iter().any(|child| {
            child.pointer("/metadata/ownerRef").and_then(Value::as_str)
                == value
                    .pointer("/metadata/name")
                    .and_then(Value::as_str)
                    .map(|name| format!("Guest/{name}"))
                    .as_deref()
                && child.pointer("/type").and_then(Value::as_str) == Some("Volume")
                && child.pointer("/metadata/name").and_then(Value::as_str)
                    == value
                        .pointer("/metadata/name")
                        .and_then(Value::as_str)
                        .map(|name| format!("{name}-runtime"))
                        .as_deref()
                && child.pointer("/status/phase").and_then(Value::as_str) == Some("Ready")
        });
        Ok(qemu_media_runtime::QemuMediaDependencies {
            device,
            network_ready,
            media_ready,
            display_ready: !settings.display_window || display_ref.as_ref().is_some_and(ready),
            qmp_ready: effect.qmp_ready(),
            qmp_status: effect.qmp_ready().then_some(
                qemu_media_runtime::QmpVmStatus::Paused,
            ),
            media_refs,
            display_ref,
            runtime_volume_ready,
            qmp_elapsed_seconds: 0,
        })
    }

    fn build_guest_controller(
        &self,
        kind: SharedProviderResourceKind,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
        value: &Value,
        provider: &Value,
    ) -> Result<GuestRuntimeController, SharedProviderEffectError> {
        match kind {
            SharedProviderResourceKind::QemuMediaGuest => {
                let config = serde_json::from_value::<qemu_media_runtime::ProviderConfig>(
                    provider
                        .pointer("/spec/config")
                        .cloned()
                        .ok_or(SharedProviderEffectError::InvalidResource)?,
                )
                .map_err(|_| SharedProviderEffectError::InvalidResource)?;
                let settings =
                    serde_json::from_value::<qemu_media_runtime::GuestProviderSpecSettings>(
                        serde_json::from_slice::<Value>(resource.canonical_json())
                            .map_err(|_| SharedProviderEffectError::InvalidResource)?
                            .get("spec")
                            .and_then(|spec| spec.get("provider"))
                            .and_then(|provider| provider.get("settings"))
                            .cloned()
                            .unwrap_or_else(|| Value::Object(serde_json::Map::new())),
                    )
                    .map_err(|_| SharedProviderEffectError::InvalidResource)?;
                let device_ref = value
                    .pointer("/spec/deviceAttachments")
                    .and_then(Value::as_array)
                    .and_then(|attachments| attachments.first())
                    .and_then(|attachment| attachment.get("deviceRef"))
                    .and_then(Value::as_str)
                    .map(ResourceRef::parse)
                    .transpose()
                    .map_err(|_| SharedProviderEffectError::InvalidResource)?;
                let network_refs = value
                    .pointer("/spec/networkAttachments")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|attachment| attachment.get("networkRef").and_then(Value::as_str))
                    .map(ResourceRef::parse)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| SharedProviderEffectError::InvalidResource)?;
                let process = qemu_media_runtime::build_process_spec(
                    config.controller_execution_ref.clone(),
                    ResourceRef::parse(&format!(
                        "Volume/{}-runtime",
                        resource.key().resource_ref().name().as_str()
                    ))
                    .map_err(|_| SharedProviderEffectError::InvalidResource)?,
                    device_ref,
                    network_refs,
                )
                .map_err(|_| SharedProviderEffectError::InvalidResource)?;
                let controller = qemu_media_runtime::QemuMediaController::new(
                    config,
                    settings,
                    process,
                    resource.key().resource_ref().clone(),
                )
                .map_err(|_| SharedProviderEffectError::InvalidResource)?;
                Ok(GuestRuntimeController::Qemu {
                    controller,
                    effect: FrameworkQemuEffect::new(resource.key().resource_ref().clone()),
                })
            }
            SharedProviderResourceKind::AzureContainerAppsGuest => {
                let config = serde_json::from_value::<aca_runtime::AcaProviderConfig>(
                    provider
                        .pointer("/spec/config")
                        .cloned()
                        .ok_or(SharedProviderEffectError::InvalidResource)?,
                )
                .map_err(|_| SharedProviderEffectError::InvalidResource)?;
                let config_bytes = serde_json::to_vec(&config)
                    .map_err(|_| SharedProviderEffectError::InvalidResource)?;
                let binding = aca_runtime::AcaResourceBinding {
                    guest_uid: resource.key().uid().clone(),
                    provider_generation: context.identity.provider_generation().get(),
                    config_fingerprint: Sha256::digest(config_bytes).into(),
                };
                let control = Arc::new(FrameworkAcaControl {
                    state: Arc::new(tokio::sync::Mutex::new(FrameworkAcaState::new(
                        context.identity.provider_generation().get(),
                    ))),
                });
                let provider = aca_runtime::AzureContainerAppsRuntimeProvider::new(
                    config,
                    control,
                    Arc::new(FrameworkAcaLease),
                )
                .map_err(|_| SharedProviderEffectError::InvalidResource)?;
                Ok(GuestRuntimeController::Aca {
                    controller: provider.controller(binding),
                })
            }
            SharedProviderResourceKind::AzureVirtualMachineGuest => {
                let config = serde_json::from_value::<azure_vm_runtime::AzureVmConfig>(
                    provider
                        .pointer("/spec/config")
                        .cloned()
                        .ok_or(SharedProviderEffectError::InvalidResource)?,
                )
                .map_err(|_| SharedProviderEffectError::InvalidResource)?;
                let guest_value = serde_json::from_slice::<Value>(resource.canonical_json())
                    .map_err(|_| SharedProviderEffectError::InvalidResource)?;
                let settings = serde_json::from_value::<azure_vm_runtime::AzureVmGuestSettings>(
                    Self::azure_vm_guest_settings_value(&guest_value)?,
                )
                .map_err(|_| SharedProviderEffectError::InvalidResource)?;
                let state = Arc::new(tokio::sync::Mutex::new(FrameworkAzureState::new(&settings)));
                let controller = azure_vm_runtime::AzureVmController::new(
                    config,
                    settings,
                    Arc::new(FrameworkAzureEffect {
                        state: Arc::clone(&state),
                    }),
                    Arc::new(FrameworkAzureCredential),
                    None,
                )
                .map_err(|_| SharedProviderEffectError::InvalidResource)?
                .with_bootstrap_service(
                    azure_vm_runtime::BootstrapService::from_state(
                        azure_vm_runtime::BootstrapServiceState::Enrolled,
                    ),
                );
                Ok(GuestRuntimeController::AzureVm { controller })
            }
            _ => Err(SharedProviderEffectError::InvalidResource),
        }
    }

    async fn run_guest_controller(
        &self,
        kind: SharedProviderResourceKind,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
        value: &Value,
        provider: &Value,
        dependencies: &[DependencySnapshot],
    ) -> Result<SharedProviderEffectPhase, SharedProviderEffectError> {
        let runtime = self.validate_guest_runtime_fence(kind, context, resource).await?;
        let mut children = runtime
            .committed_resources_of_type("Process")
            .await
            .map_err(|_| SharedProviderEffectError::Unavailable)?;
        children.extend(
            runtime
                .committed_resources_of_type("Volume")
                .await
                .map_err(|_| SharedProviderEffectError::Unavailable)?,
        );
        let session_generation = runtime
            .core_controller_subject
            .lock()
            .map_err(|_| SharedProviderEffectError::Unavailable)?
            .as_ref()
            .map(AuthenticatedSubjectContext::reconnect_generation)
            .ok_or(SharedProviderEffectError::Unavailable)?;
        let key = (
            resource.key().resource_ref().clone(),
            resource.key().uid().clone(),
            context.identity.provider_generation().get(),
            context.identity.controller_generation().get(),
            resource.generation().get(),
            session_generation.get(),
        );
        let mut controllers = self.guest_controllers.lock().await;
        if !controllers.contains_key(&key) {
            let controller = self.build_guest_controller(kind, context, resource, value, provider)?;
            controllers.insert(key.clone(), controller);
        }
        let controller = controllers
            .get_mut(&key)
            .ok_or(SharedProviderEffectError::Unavailable)?;
        match controller {
            GuestRuntimeController::Qemu {
                controller,
                effect,
            } => {
                let deps = Self::qemu_dependencies(value, dependencies, &children, effect)?;
                let outcome = controller
                    .reconcile(&deps, effect)
                    .map_err(|_| SharedProviderEffectError::Unavailable)?;
                Ok(if matches!(
                    outcome,
                    qemu_media_runtime::QemuMediaReconcileOutcome::Ready
                ) {
                    SharedProviderEffectPhase::Ready
                } else {
                    SharedProviderEffectPhase::Pending
                })
            }
            GuestRuntimeController::Aca { controller } => {
                let operation = aca_runtime::AcaOperationId::parse(
                    Self::framework_operation_id("aca", &context.operation_id),
                )
                .map_err(|_| SharedProviderEffectError::InvalidResource)?;
                let outcome = controller
                    .reconcile(operation, 30_000)
                    .await
                    .map_err(|_| SharedProviderEffectError::Unavailable)?;
                Ok(if outcome == aca_runtime::AcaReconcileOutcome::Converged {
                    SharedProviderEffectPhase::Ready
                } else {
                    SharedProviderEffectPhase::Pending
                })
            }
            GuestRuntimeController::AzureVm { controller } => {
                let outcome = controller
                    .reconcile(
                        self.zone.as_str(),
                        resource.key().uid().as_str(),
                        resource.generation().get(),
                    )
                    .await
                    .map_err(|_| SharedProviderEffectError::Unavailable)?;
                Ok(if outcome == azure_vm_runtime::AzureVmReconcileOutcome::Converged {
                    SharedProviderEffectPhase::Ready
                } else {
                    SharedProviderEffectPhase::Pending
                })
            }
        }
    }

    async fn finalize_guest_controller(
        &self,
        kind: SharedProviderResourceKind,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
    ) -> Result<bool, SharedProviderEffectError> {
        let value = self
            .guest_provider_resource(kind, context, resource)
            .await?;
        let runtime = self
            .validate_guest_runtime_fence(kind, context, resource)
            .await?;
        let provider_ref = ResourceRef::parse(kind.provider_ref())
            .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        let provider = runtime
            .committed_resource_value(&provider_ref, &context.operation_id)
            .await
            .map_err(|_| SharedProviderEffectError::Unavailable)?;
        if matches!(
            kind,
            SharedProviderResourceKind::AzureContainerAppsGuest
                | SharedProviderResourceKind::AzureVirtualMachineGuest
        ) {
            self.validate_gateway_custody(
                &provider_ref,
                match kind {
                    SharedProviderResourceKind::AzureContainerAppsGuest => {
                        &["controlCredentialRef", "pullCredentialRef"][..]
                    }
                    SharedProviderResourceKind::AzureVirtualMachineGuest => {
                        &["armCredentialRef"][..]
                    }
                    _ => &[][..],
                },
                context,
            )
            .await?;
        }
        let key = (
            resource.key().resource_ref().clone(),
            resource.key().uid().clone(),
            context.identity.provider_generation().get(),
            context.identity.controller_generation().get(),
            resource.generation().get(),
            runtime
                .core_controller_subject
                .lock()
                .map_err(|_| SharedProviderEffectError::Unavailable)?
                .as_ref()
                .map(AuthenticatedSubjectContext::reconnect_generation)
                .ok_or(SharedProviderEffectError::Unavailable)?
                .get(),
        );
        let mut controllers = self.guest_controllers.lock().await;
        if !controllers.contains_key(&key) {
            controllers.insert(
                key.clone(),
                self.build_guest_controller(kind, context, resource, &value, &provider)?,
            );
        }
        let controller = controllers
            .get_mut(&key)
            .ok_or(SharedProviderEffectError::Unavailable)?;
        match controller {
            GuestRuntimeController::Qemu {
                controller,
                effect,
            } => {
                controller
                    .finalize(effect)
                    .map_err(|_| SharedProviderEffectError::Unavailable)?;
            }
            GuestRuntimeController::Aca { controller } => {
                let operation = aca_runtime::AcaOperationId::parse(
                    Self::framework_operation_id("aca-delete", &context.operation_id),
                )
                .map_err(|_| SharedProviderEffectError::InvalidResource)?;
                controller
                    .finalize(operation, 30_000)
                    .await
                    .map_err(|_| SharedProviderEffectError::Unavailable)?;
            }
            GuestRuntimeController::AzureVm { controller } => {
                if let Some(operation) = controller.recovery_state().operation {
                    controller
                        .poll_operation(operation)
                        .await
                        .map_err(|_| SharedProviderEffectError::Unavailable)?;
                }
                controller
                    .finalize(
                        self.zone.as_str(),
                        resource.key().uid().as_str(),
                        resource.generation().get(),
                    )
                    .await
                    .map_err(|_| SharedProviderEffectError::Unavailable)?;
            }
        }
        let complete = !controller.finalizer_installed();
        if complete {
            controllers.remove(&key);
        }
        Ok(complete)
    }

    async fn reconcile_guest_runtime(
        &self,
        kind: SharedProviderResourceKind,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
        dependencies: &[DependencySnapshot],
    ) -> Result<SharedProviderEffectResult, SharedProviderEffectError> {
        let value = self.guest_provider_resource(kind, context, resource).await?;
        for dependency in dependencies {
            if !Self::related_guest_dependency(&value, dependency)? {
                return Ok(SharedProviderEffectResult::phase(
                    SharedProviderEffectPhase::Pending,
                ));
            }
        }
        let runtime = self.validate_guest_runtime_fence(kind, context, resource).await?;
        let provider_ref = ResourceRef::parse(kind.provider_ref())
            .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        let provider = runtime
            .committed_resource_value(&provider_ref, &context.operation_id)
            .await
            .map_err(|_| SharedProviderEffectError::Unavailable)?;
        if kind == SharedProviderResourceKind::AzureContainerAppsGuest {
            self.validate_gateway_custody(
                &provider_ref,
                &["controlCredentialRef", "pullCredentialRef"],
                context,
            )
            .await?;
        } else if kind == SharedProviderResourceKind::AzureVirtualMachineGuest {
            self.validate_gateway_custody(&provider_ref, &["armCredentialRef"], context)
                .await?;
        }
        if kind == SharedProviderResourceKind::QemuMediaGuest {
            Self::validate_qemu_guest(&value)?;
        }
        let desired = match kind {
            SharedProviderResourceKind::QemuMediaGuest => Some(Self::qemu_guest_children(
                &value,
                &provider,
                resource.key().resource_ref(),
                &self.zone,
            )?),
            SharedProviderResourceKind::AzureContainerAppsGuest => Some(
                Self::aca_guest_children(resource.key().resource_ref(), &self.zone)?,
            ),
            SharedProviderResourceKind::AzureVirtualMachineGuest
            | SharedProviderResourceKind::CloudHypervisorGuest => None,
            _ => return Err(SharedProviderEffectError::InvalidResource),
        };
        let (children_ready, child_mutated) = if let Some(desired) = desired {
            let child_progress = self
                .guest_child_progress(&runtime, resource, Some(desired.clone()))
                .await?;
            (
                self.guest_children_ready(&runtime, resource, &desired)
                    .await?,
                child_progress == OneOwnedChildProgress::Mutated,
            )
        } else {
            (true, false)
        };
        match kind {
            SharedProviderResourceKind::CloudHypervisorGuest => {
                let runtime = self.runtime()?;
                runtime
                    .reconcile_cloud_hypervisor_guest(
                        Arc::clone(&self.state),
                        resource.key().resource_ref(),
                    )
                    .await
                    .map_err(|_| SharedProviderEffectError::Unavailable)?;
                let fresh = runtime
                    .committed_resource_value(
                        resource.key().resource_ref(),
                        &context.operation_id,
                    )
                    .await
                    .map_err(|_| SharedProviderEffectError::Unavailable)?;
                Ok(SharedProviderEffectResult::phase(Self::guest_phase(&fresh)))
            }
            SharedProviderResourceKind::QemuMediaGuest => {
                let phase = self
                    .run_guest_controller(
                    kind,
                    context,
                    resource,
                    &value,
                    &provider,
                    dependencies,
                )
                .await?;
                Ok(SharedProviderEffectResult {
                    phase: if children_ready {
                        phase
                    } else {
                        SharedProviderEffectPhase::Pending
                    },
                    child_mutated,
                })
            }
            SharedProviderResourceKind::AzureContainerAppsGuest => {
                let phase = self
                    .run_guest_controller(
                    kind,
                    context,
                    resource,
                    &value,
                    &provider,
                    dependencies,
                )
                .await?;
                Ok(SharedProviderEffectResult {
                    phase: if children_ready {
                        phase
                    } else {
                        SharedProviderEffectPhase::Pending
                    },
                    child_mutated,
                })
            }
            SharedProviderResourceKind::AzureVirtualMachineGuest => {
                Self::validate_azure_vm_guest(&value)?;
                let phase = self
                    .run_guest_controller(
                    kind,
                    context,
                    resource,
                    &value,
                    &provider,
                    dependencies,
                )
                .await?;
                Ok(SharedProviderEffectResult {
                    phase: if children_ready {
                        phase
                    } else {
                        SharedProviderEffectPhase::Pending
                    },
                    child_mutated,
                })
            }
            _ => Err(SharedProviderEffectError::InvalidResource),
        }
    }

    async fn finalize_guest_runtime(
        &self,
        kind: SharedProviderResourceKind,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
    ) -> Result<(), SharedProviderEffectError> {
        let _value = self.guest_provider_resource(kind, context, resource).await?;
        if kind == SharedProviderResourceKind::CloudHypervisorGuest {
            self.runtime()?
                .reconcile_cloud_hypervisor_guest(
                    Arc::clone(&self.state),
                    resource.key().resource_ref(),
                )
                .await
                .map_err(|_| SharedProviderEffectError::Unavailable)?;
            return Ok(());
        }
        let runtime = self.runtime()?;
        if !self
            .finalize_guest_controller(kind, context, resource)
            .await?
        {
            return Err(SharedProviderEffectError::Unavailable);
        }
        match self
            .guest_child_progress(&runtime, resource, None)
            .await?
        {
            OneOwnedChildProgress::Converged => Ok(()),
            OneOwnedChildProgress::Mutated | OneOwnedChildProgress::Pending => {
                Err(SharedProviderEffectError::Unavailable)
            }
        }
    }
}

fn tpm_opaque_bytes(domain: &str, value: &str) -> [u8; 32] {
    let digest = Sha256::digest(format!("{domain}:{value}").as_bytes());
    let mut bytes = [0; 32];
    bytes.copy_from_slice(&digest);
    bytes
}

fn tpm_state_intent(
    device_uid: &ResourceUid,
    vm_id: &str,
) -> d2b_provider_device_tpm::StateDirIntent {
    d2b_provider_device_tpm::StateDirIntent::new(
        d2b_provider_device_tpm::StateDirectoryToken::from_core(tpm_opaque_bytes(
            "d2b:tpm-state/v1",
            vm_id,
        )),
        d2b_provider_device_tpm::TamperMarkerToken::from_core(tpm_opaque_bytes(
            "d2b:tpm-marker/v1",
            device_uid.as_str(),
        )),
        d2b_provider_device_tpm::StateOwnerToken::from_core(
            tpm_opaque_bytes("d2b:tpm-owner/v1", vm_id)[..16]
                .try_into()
                .expect("fixed owner token length"),
        ),
    )
}

#[derive(Clone)]
struct SharedRunnerNetworkContentFence {
    owner_ref: ResourceRef,
    provenance: NetworkProvenance,
    assignment: ResourceAssignmentFence,
    controller_ref: ResourceRef,
    controller_generation: ControllerGeneration,
    provider_generation: ResourceGeneration,
    session_generation: ReconnectGeneration,
}

struct SharedRunnerNetworkResources {
    runtime: Arc<ZoneResourceRuntime>,
    owner_ref: ResourceRef,
    guest_ref: ResourceRef,
    volume_ref: ResourceRef,
    agent_ref: ResourceRef,
    content_fence: Option<SharedRunnerNetworkContentFence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SharedRunnerNetworkReadiness {
    volume_ready: bool,
    guest_ready: bool,
    attachment_ready: bool,
}

impl SharedRunnerNetworkResources {
    fn new(runtime: Arc<ZoneResourceRuntime>, owner_ref: ResourceRef, network_uid: &ResourceUid) -> Self {
        let guest_name = d2b_provider_network_local::ifname::derive_network_child_name(network_uid, "vm");
        let agent_name =
            d2b_provider_network_local::ifname::derive_network_child_name(network_uid, "agent");
        Self {
            runtime,
            owner_ref,
            guest_ref: ResourceRef::parse(&format!("Guest/{guest_name}"))
                .expect("derived Network Guest ref is valid"),
            volume_ref: ResourceRef::parse("Volume/net-config")
                .expect("Network config Volume ref is valid"),
            agent_ref: ResourceRef::parse(&format!("Process/{agent_name}"))
                .expect("derived Network agent ref is valid"),
            content_fence: None,
        }
    }

    fn with_content_fence(mut self, fence: SharedRunnerNetworkContentFence) -> Self {
        self.content_fence = Some(fence);
        self
    }

    fn client(
        &self,
    ) -> Result<
        Arc<ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>>,
        NetworkEffectError,
    > {
        self.runtime
            .process_resource_client()
            .ok_or(NetworkEffectError::ConfigVolume)
    }

    async fn current(&self, target: &ResourceRef) -> Result<Option<Value>, NetworkEffectError> {
        match self
            .runtime
            .store
            .get(StoreGetRequest {
                operation: StoreOperationContext {
                    operation_id: "shared-network-child-read".to_owned(),
                    idempotency_key: None,
                    correlation_id: "shared-network-child-read".to_owned(),
                    trace_id: None,
                    deadline_ms: 10_000,
                },
                zone: self.runtime.zone.clone(),
                target: target.clone(),
                expected_uid: None,
                projection: StoreProjection::Full,
            })
            .await
        {
            Ok(resource) => serde_json::from_slice(&resource.canonical_json)
                .map(Some)
                .map_err(|_| NetworkEffectError::ConfigVolume),
            Err(error) if error.kind() == StoreErrorKind::ResourceNotFound => Ok(None),
            Err(_) => Err(NetworkEffectError::ConfigVolume),
        }
    }

    async fn upsert(
        &self,
        target: &ResourceRef,
        spec: Value,
        operation: &str,
    ) -> Result<(), NetworkEffectError> {
        upsert_shared_provider_child(
            &self.runtime,
            target,
            spec,
            &self.owner_ref,
            operation,
        )
        .await
    }

    async fn delete(&self, target: &ResourceRef, operation: &str) -> Result<(), NetworkEffectError> {
        let Some(current) = self.current(target).await? else {
            return Ok(());
        };
        let uid = current
            .pointer("/metadata/uid")
            .and_then(Value::as_str)
            .and_then(|value| ResourceUid::parse(value.to_owned()).ok())
            .ok_or(NetworkEffectError::ConfigVolume)?;
        let revision = current
            .pointer("/metadata/revision")
            .and_then(Value::as_u64)
            .ok_or(NetworkEffectError::ConfigVolume)?;
        let request = public_delete_request(
            &self.runtime,
            &json!({
                "resourceRef": target.to_canonical_string(),
                "uid": uid.as_str(),
                "expectedRevision": revision,
            }),
            operation,
        )
        .await
        .map_err(|_| NetworkEffectError::ConfigVolume)?;
        if self.client()?.delete(request).await.error.is_some() {
            return Err(NetworkEffectError::ConfigVolume);
        }
        Ok(())
    }

    async fn readiness(&self) -> Result<SharedRunnerNetworkReadiness, NetworkEffectError> {
        let volume = self.current(&self.volume_ref).await?;
        let guest = self.current(&self.guest_ref).await?;
        let volume_ready = volume.as_ref().is_some_and(|value| {
            value.pointer("/metadata/ownerRef").and_then(Value::as_str)
                == Some(self.owner_ref.to_canonical_string().as_str())
                && value.pointer("/status/phase").and_then(Value::as_str) == Some("Ready")
                && network_config_content_projection_ready(value)
        });
        let guest_ready = guest.as_ref().is_some_and(|value| {
            value.pointer("/metadata/ownerRef").and_then(Value::as_str)
                == Some(self.owner_ref.to_canonical_string().as_str())
                && value.pointer("/status/phase").and_then(Value::as_str) == Some("Ready")
        });
        let attachment_ready = volume.as_ref().is_some_and(|value| {
            value.pointer("/status/phase").and_then(Value::as_str) == Some("Ready")
                && value
                    .pointer("/spec/attachments")
                    .and_then(Value::as_array)
                    .is_some_and(|attachments| {
                        attachments.iter().any(|attachment| {
                            attachment
                                .get("executionRef")
                                .and_then(Value::as_str)
                                == Some(self.guest_ref.to_canonical_string().as_str())
                        })
                    })
        });
        Ok(SharedRunnerNetworkReadiness {
            volume_ready,
            guest_ready,
            attachment_ready,
        })
    }
}

impl NetworkResourcePort for SharedRunnerNetworkResources {
    async fn upsert_volume_backing(
        &self,
        spec: &d2b_contracts_resource::v3::volume::VolumeSpec,
    ) -> Result<(), NetworkEffectError> {
        let mut value = serde_json::to_value(spec).map_err(|_| NetworkEffectError::ConfigVolume)?;
        if let Some(current) = self.current(&self.volume_ref).await?
            && let Some(provider) = current.pointer("/spec/provider")
        {
            value
                .as_object_mut()
                .ok_or(NetworkEffectError::ConfigVolume)?
                .insert("provider".to_owned(), provider.clone());
        }
        value
            .as_object_mut()
            .ok_or(NetworkEffectError::ConfigVolume)?
            .insert(
                "providerRef".to_owned(),
                Value::String("Provider/volume-local".to_owned()),
            );
        self.upsert(
            &self.volume_ref,
            value,
            "shared-network-volume-upsert",
        )
        .await
    }

    async fn upsert_volume_content(
        &self,
        content: &d2b_provider_network_local::controller::NetworkConfigContent,
    ) -> Result<(), NetworkEffectError> {
        let fence = self
            .content_fence
            .as_ref()
            .ok_or(NetworkEffectError::NetworkAdmissionMismatch)?;
        if fence.owner_ref != self.owner_ref
            || content.provenance() != Some(&fence.provenance)
        {
            return Err(NetworkEffectError::NetworkAdmissionMismatch);
        }
        let current = self
            .current(&self.volume_ref)
            .await?
            .ok_or(NetworkEffectError::ConfigVolume)?;
        if current.pointer("/metadata/ownerRef").and_then(Value::as_str)
            != Some(self.owner_ref.to_canonical_string().as_str())
            || current.pointer("/metadata/zone").and_then(Value::as_str)
                != Some(self.runtime.zone.as_str())
            || current.pointer("/spec/providerRef").and_then(Value::as_str)
                != Some("Provider/volume-local")
        {
            return Err(NetworkEffectError::NetworkAdmissionMismatch);
        }
        let mut spec = current
            .get("spec")
            .cloned()
            .ok_or(NetworkEffectError::ConfigVolume)?;
        validate_network_config_volume_spec(&spec)?;
        let assignment = self
            .runtime
            .store
            .assignment_fence(self.runtime.zone.clone(), self.owner_ref.clone())
            .await
            .map_err(|_| NetworkEffectError::NetworkAdmissionMismatch)?
            .ok_or(NetworkEffectError::NetworkAdmissionMismatch)?;
        if !network_assignment_matches(&assignment, fence) {
            return Err(NetworkEffectError::NetworkAdmissionMismatch);
        }
        let volume_uid = current
            .pointer("/metadata/uid")
            .and_then(Value::as_str)
            .and_then(|value| ResourceUid::parse(value.to_owned()).ok())
            .ok_or(NetworkEffectError::ConfigVolume)?;
        spec = DaemonSharedProviderEffects::project_network_volume_spec(
            spec,
            &volume_uid,
            content,
            fence,
            &self.owner_ref,
        )?;
        self.upsert(
            &self.volume_ref,
            spec,
            "shared-network-volume-content-write",
        )
        .await
    }

    async fn upsert_guest(
        &self,
        spec: &d2b_contracts_resource::v3::guest::GuestSpec,
    ) -> Result<(), NetworkEffectError> {
        let mut value = serde_json::to_value(spec).map_err(|_| NetworkEffectError::ConfigVolume)?;
        value
            .as_object_mut()
            .ok_or(NetworkEffectError::ConfigVolume)?
            .insert(
                "providerRef".to_owned(),
                Value::String("Provider/runtime-cloud-hypervisor".to_owned()),
            );
        self.upsert(&self.guest_ref, value, "shared-network-guest-upsert")
            .await
    }

    async fn attach_volume(
        &self,
        attachment: &d2b_contracts_resource::v3::volume::VolumeAttachment,
    ) -> Result<(), NetworkEffectError> {
        let current = self
            .current(&self.volume_ref)
            .await?
            .ok_or(NetworkEffectError::ConfigVolume)?;
        let mut spec = current
            .get("spec")
            .cloned()
            .ok_or(NetworkEffectError::ConfigVolume)?;
        let attachments = spec
            .as_object_mut()
            .ok_or(NetworkEffectError::ConfigVolume)?
            .entry("attachments")
            .or_insert_with(|| Value::Array(Vec::new()));
        let attachments = attachments
            .as_array_mut()
            .ok_or(NetworkEffectError::ConfigVolume)?;
        let attachment = serde_json::to_value(attachment)
            .map_err(|_| NetworkEffectError::ConfigVolume)?;
        if !attachments.iter().any(|current| current == &attachment) {
            attachments.push(attachment);
        }
        self.upsert(&self.volume_ref, spec, "shared-network-volume-attach")
            .await
    }

    async fn upsert_agent(
        &self,
        spec: &d2b_contracts_resource::v3::process::ProcessSpec,
    ) -> Result<(), NetworkEffectError> {
        let mut value = serde_json::to_value(spec).map_err(|_| NetworkEffectError::ConfigVolume)?;
        value
            .as_object_mut()
            .ok_or(NetworkEffectError::ConfigVolume)?
            .insert(
                "providerRef".to_owned(),
                Value::String("Provider/system-minijail".to_owned()),
            );
        self.upsert(&self.agent_ref, value, "shared-network-agent-upsert")
            .await
    }

    async fn reconcile_mdns(&self, enabled: bool) -> Result<(), NetworkEffectError> {
        if enabled {
            return Err(NetworkEffectError::ConfigVolume);
        }
        Ok(())
    }

    async fn delete_processes(&self) -> Result<(), NetworkEffectError> {
        self.delete(&self.agent_ref, "shared-network-agent-delete")
            .await
    }

    async fn detach_volume(&self) -> Result<(), NetworkEffectError> {
        let Some(current) = self.current(&self.volume_ref).await? else {
            return Ok(());
        };
        let mut spec = current
            .get("spec")
            .cloned()
            .ok_or(NetworkEffectError::ConfigVolume)?;
        if let Some(attachments) = spec
            .as_object_mut()
            .and_then(|spec| spec.get_mut("attachments"))
            .and_then(Value::as_array_mut)
        {
            attachments.retain(|attachment| {
                attachment
                    .get("executionRef")
                    .and_then(Value::as_str)
                    != Some(self.guest_ref.to_canonical_string().as_str())
            });
        }
        self.upsert(&self.volume_ref, spec, "shared-network-volume-detach")
            .await
    }

    async fn delete_guest(&self) -> Result<(), NetworkEffectError> {
        self.delete(&self.guest_ref, "shared-network-guest-delete")
            .await
    }

    async fn delete_volume(&self) -> Result<(), NetworkEffectError> {
        self.delete(&self.volume_ref, "shared-network-volume-delete")
            .await
    }
}

const NETWORK_CONFIG_VOLUME_SCHEMA_ID: &str = d2b_provider_volume_local::VOLUME_CONTENT_SCHEMA_ID;
const NETWORK_CONFIG_VOLUME_SCHEMA_VERSION: &str =
    d2b_provider_volume_local::VOLUME_CONTENT_SCHEMA_VERSION;
const NETWORK_CONFIG_CONTENT_KIND: &str = d2b_provider_volume_local::NETWORK_CONFIG_CONTENT_KIND;
const NETWORK_CONFIG_FILE_OWNER: &str = d2b_provider_volume_local::NETWORK_CONFIG_FILE_OWNER;
const NETWORK_CONFIG_FILE_MODE: &str = d2b_provider_volume_local::NETWORK_CONFIG_FILE_MODE;

fn validate_network_config_volume_spec(spec: &Value) -> Result<(), NetworkEffectError> {
    let provider_ref = spec
        .get("providerRef")
        .and_then(Value::as_str)
        .ok_or(NetworkEffectError::ConfigVolume)?;
    if provider_ref != "Provider/volume-local" {
        return Err(NetworkEffectError::NetworkAdmissionMismatch);
    }
    let mut base = spec.clone();
    if let Some(base) = base.as_object_mut() {
        base.remove("providerRef");
        base.remove("updatePolicy");
        base.remove("provider");
    }
    let volume: VolumeSpec =
        serde_json::from_value(base).map_err(|_| NetworkEffectError::ConfigVolume)?;
    let required = [
        "dnsmasq.conf",
        "nftables.rules",
        "routing.conf",
        "attachments.json",
    ];
    if !required.iter().all(|path| {
        volume.layout().iter().any(|entry| {
            entry.path() == *path
                && entry.entry_type() == EntryType::File
                && entry.owner_ref().to_canonical_string() == NETWORK_CONFIG_FILE_OWNER
                && entry.group_ref().to_canonical_string() == NETWORK_CONFIG_FILE_OWNER
                && entry.mode() == NETWORK_CONFIG_FILE_MODE
        })
    }) {
        return Err(NetworkEffectError::ConfigVolume);
    }
    Ok(())
}

fn network_config_content_projection_ready(value: &Value) -> bool {
    let Some(provider) = value.pointer("/spec/provider") else {
        return false;
    };
    let Some(spec) = value.get("spec") else {
        return false;
    };
    if validate_network_config_volume_spec(spec).is_err() {
        return false;
    }
    if provider.get("schemaId").and_then(Value::as_str)
        != Some(NETWORK_CONFIG_VOLUME_SCHEMA_ID)
        || provider.get("schemaVersion").and_then(Value::as_str)
            != Some(NETWORK_CONFIG_VOLUME_SCHEMA_VERSION)
        || provider
            .pointer("/settings/kind")
            .and_then(Value::as_str)
            != Some(NETWORK_CONFIG_CONTENT_KIND)
    {
        return false;
    }
    let Some(desired) = provider.pointer("/settings/content") else {
        return false;
    };
    let Ok(desired) =
        d2b_provider_volume_local::NetworkConfigContentProjection::from_settings(desired)
    else {
        return false;
    };
    let Some(volume_uid) = value
        .pointer("/metadata/uid")
        .and_then(Value::as_str)
        .and_then(|uid| ResourceUid::parse(uid.to_owned()).ok())
    else {
        return false;
    };
    if desired.volume_uid() != &volume_uid {
        return false;
    }
    if value
        .pointer("/status/phase")
        .and_then(Value::as_str)
        != Some("Ready")
        || value
            .pointer("/metadata/generation")
            .and_then(Value::as_u64)
            != value
                .pointer("/status/observedGeneration")
                .and_then(Value::as_u64)
    {
        return false;
    }
    if let Some(resource_projection) = value.pointer("/status/resource")
        && resource_projection
            .get("provider")
            .and_then(Value::as_str)
            != Some("volume-local")
    {
        return false;
    }
    let status_provider = value.pointer("/status/provider");
    if let Some(status_provider) = status_provider
        && (status_provider
            .get("providerRef")
            .and_then(Value::as_str)
            != Some("Provider/volume-local")
            || status_provider
                .get("schemaId")
                .and_then(Value::as_str)
                != Some("volume-local.d2bus.org/Volume/status")
            || status_provider
                .get("schemaVersion")
                .and_then(Value::as_str)
                != Some("1.0"))
    {
        return false;
    }
    let Some(observed) = value
        .pointer("/status/resource/content")
        .or_else(|| value.pointer("/status/content"))
        .or_else(|| status_provider.and_then(|provider| provider.pointer("/details/content")))
    else {
        return false;
    };
    let Ok(observed) =
        serde_json::from_value::<d2b_provider_volume_local::NetworkConfigMaterializationEvidence>(
            observed.clone(),
        )
    else {
        return false;
    };
    observed.matches(&desired)
}

fn network_config_provider_matches(
    provider: &Value,
    volume_uid: &ResourceUid,
    owner_ref: &ResourceRef,
    marker: &str,
) -> bool {
    provider.get("schemaId").and_then(Value::as_str)
        == Some(NETWORK_CONFIG_VOLUME_SCHEMA_ID)
        && provider.get("schemaVersion").and_then(Value::as_str)
            == Some(NETWORK_CONFIG_VOLUME_SCHEMA_VERSION)
        && provider
            .pointer("/settings/kind")
            .and_then(Value::as_str)
            == Some(NETWORK_CONFIG_CONTENT_KIND)
        && provider
            .pointer("/settings/content")
            .and_then(|content| {
                d2b_provider_volume_local::NetworkConfigContentProjection::from_settings(content)
                    .ok()
            })
            .is_some_and(|content| {
                content.volume_uid() == volume_uid
                    && content.network_ref() == owner_ref
                    && content.ownership_marker() == marker
            })
}

fn network_config_legacy_provider_matches(
    provider: &Value,
    owner_ref: &ResourceRef,
    marker: &str,
) -> bool {
    // Accept the previous projection only to migrate its ownership marker;
    // its files are never used as readiness evidence.
    provider.get("schemaId").and_then(Value::as_str)
        == Some(NETWORK_CONFIG_VOLUME_SCHEMA_ID)
        && provider.get("schemaVersion").and_then(Value::as_str)
            == Some(NETWORK_CONFIG_VOLUME_SCHEMA_VERSION)
        && provider
            .pointer("/settings/kind")
            .and_then(Value::as_str)
            == Some(NETWORK_CONFIG_CONTENT_KIND)
        && provider
            .pointer("/settings/ownershipMarker")
            .and_then(Value::as_str)
            == Some(marker)
        && provider
            .pointer("/settings/networkRef")
            .and_then(Value::as_str)
            == Some(owner_ref.to_canonical_string().as_str())
        && provider
            .pointer("/settings/fileOwner")
            .and_then(Value::as_str)
            == Some(NETWORK_CONFIG_FILE_OWNER)
        && provider
            .pointer("/settings/fileGroup")
            .and_then(Value::as_str)
            == Some(NETWORK_CONFIG_FILE_OWNER)
        && provider
            .pointer("/settings/fileMode")
            .and_then(Value::as_str)
            == Some(NETWORK_CONFIG_FILE_MODE)
        && provider.pointer("/settings/files").is_some()
}

fn network_config_spec_with_content(
    mut spec: Value,
    volume_uid: &ResourceUid,
    content: &d2b_provider_network_local::controller::NetworkConfigContent,
    fence: &SharedRunnerNetworkContentFence,
    owner_ref: &ResourceRef,
) -> Result<Value, NetworkEffectError> {
    validate_network_config_volume_spec(&spec)?;
    let marker = d2b_contracts_resource::v3::derive_network_ownership_marker(
        &fence.provenance,
        "network-config",
    );
    if spec
        .get("provider")
        .is_some_and(|provider| {
            !network_config_provider_matches(provider, volume_uid, owner_ref, &marker)
                && !network_config_legacy_provider_matches(provider, owner_ref, &marker)
        })
    {
        return Err(NetworkEffectError::NetworkAdmissionMismatch);
    }
    let provider =
        network_config_provider_extension(volume_uid, content, owner_ref, fence, &marker)?;
    spec.as_object_mut()
        .ok_or(NetworkEffectError::ConfigVolume)?
        .insert("provider".to_owned(), provider);
    Ok(spec)
}

fn network_assignment_matches(
    actual: &ResourceAssignmentFence,
    expected: &SharedRunnerNetworkContentFence,
) -> bool {
    actual.resource_uid == expected.assignment.resource_uid
        && actual.resource_revision == expected.assignment.resource_revision
        && actual.provider_generation == expected.provider_generation
        && actual.controller_generation == expected.controller_generation
        && actual.controller_role == expected.controller_ref
        && actual.target
            == ResourceRef::parse(CORE_CONTROLLER_HOST_REF).expect("Host ref")
        && actual.session_generation == expected.session_generation
        && actual.epoch == expected.assignment.epoch
        && matches!(actual.scope, ResourceAssignmentScope::Primary)
}

fn network_config_provider_extension(
    volume_uid: &ResourceUid,
    content: &d2b_provider_network_local::controller::NetworkConfigContent,
    owner_ref: &ResourceRef,
    fence: &SharedRunnerNetworkContentFence,
    marker: &str,
) -> Result<Value, NetworkEffectError> {
    let file_owner = ResourceRef::parse(NETWORK_CONFIG_FILE_OWNER)
        .map_err(|_| NetworkEffectError::ConfigVolume)?;
    let projection = d2b_provider_volume_local::NetworkConfigContentProjection::new(
        volume_uid.clone(),
        owner_ref.clone(),
        fence.provenance.clone(),
        marker,
        file_owner.clone(),
        file_owner,
        NETWORK_CONFIG_FILE_MODE,
        content.dnsmasq.clone(),
        content.nftables.clone(),
        content.routing.clone(),
        content.attachments.clone(),
        content.digest(),
    )
    .map_err(|_| NetworkEffectError::NetworkAdmissionMismatch)?;
    let content = serde_json::to_value(&projection)
        .map_err(|_| NetworkEffectError::ConfigVolume)?;
    Ok(serde_json::json!({
        "schemaId": NETWORK_CONFIG_VOLUME_SCHEMA_ID,
        "schemaVersion": NETWORK_CONFIG_VOLUME_SCHEMA_VERSION,
        "settings": {
            "kind": NETWORK_CONFIG_CONTENT_KIND,
            "content": content,
            "assignmentFence": {
                "resourceUid": fence.assignment.resource_uid,
                "resourceRevision": fence.assignment.resource_revision,
                "providerGeneration": fence.assignment.provider_generation,
                "controllerGeneration": fence.assignment.controller_generation,
                "controllerRole": fence.assignment.controller_role,
                "target": fence.assignment.target,
                "sessionGeneration": fence.assignment.session_generation,
                "epoch": fence.assignment.epoch,
                "scope": "primary",
            },
        },
    }))
}

async fn upsert_shared_provider_child(
    runtime: &ZoneResourceRuntime,
    target: &ResourceRef,
    spec: Value,
    owner_ref: &ResourceRef,
    operation: &str,
) -> Result<(), NetworkEffectError> {
    let client = runtime
        .process_resource_client()
        .ok_or(NetworkEffectError::ConfigVolume)?;
    let create = public_create_request(
        runtime,
        &json!({
            "resourceType": target.resource_type().to_canonical_string(),
            "resourceName": target.name().as_str(),
            "spec": spec.clone(),
            "ownerRef": owner_ref.to_canonical_string(),
        }),
        operation,
    )
    .await
    .map_err(|_| NetworkEffectError::ConfigVolume)?;
    if client.create(create).await.error.is_none() {
        return Ok(());
    }
    let current = runtime
        .committed_resource_value(target, operation)
        .await
        .map_err(|_| NetworkEffectError::ConfigVolume)?;
    let expected_owner = owner_ref.to_canonical_string();
    if current
        .pointer("/metadata/ownerRef")
        .and_then(Value::as_str)
        != Some(expected_owner.as_str())
    {
        return Err(NetworkEffectError::NetworkAdmissionMismatch);
    }
    let update = public_update_spec_request_from_current(
        runtime,
        &json!({"spec": spec}),
        operation,
        target,
        current,
    )
    .map_err(|_| NetworkEffectError::ConfigVolume)?;
    if client.update_spec(update).await.error.is_some() {
        return Err(NetworkEffectError::ConfigVolume);
    }
    Ok(())
}

struct SharedRunnerUsbipChildren;

impl crate::usbip_production::UsbipChildResourcePort for SharedRunnerUsbipChildren {
    fn ensure_attach_process(
        &mut self,
        _binding: &d2b_provider_device_usbip::BindingIdentity,
        _proxy: &d2b_provider_device_usbip::BindingProxyLease,
    ) -> Result<
        d2b_provider_device_usbip::AttachProcessIdentity,
        d2b_provider_device_usbip::BindingLifecycleError,
    > {
        Err(d2b_provider_device_usbip::BindingLifecycleError::Transient)
    }

    fn observe_attach_process(
        &mut self,
        _binding: &d2b_provider_device_usbip::BindingIdentity,
        _identity: &d2b_provider_device_usbip::AttachProcessIdentity,
    ) -> Result<
        d2b_provider_device_usbip::AttachmentObservation,
        d2b_provider_device_usbip::BindingLifecycleError,
    > {
        Err(d2b_provider_device_usbip::BindingLifecycleError::Transient)
    }

    fn delete_guest_endpoint(
        &mut self,
        _binding: &d2b_provider_device_usbip::BindingIdentity,
        _proxy: &d2b_provider_device_usbip::BindingProxyLease,
    ) -> Result<(), d2b_provider_device_usbip::BindingLifecycleError> {
        Err(d2b_provider_device_usbip::BindingLifecycleError::Transient)
    }

    fn delete_attach_process(
        &mut self,
        _binding: &d2b_provider_device_usbip::BindingIdentity,
        _identity: &d2b_provider_device_usbip::AttachProcessIdentity,
    ) -> Result<(), d2b_provider_device_usbip::BindingLifecycleError> {
        Err(d2b_provider_device_usbip::BindingLifecycleError::Transient)
    }
}

struct DaemonGpuLifecyclePort {
    state: Arc<ServerState>,
    runtime: Arc<ZoneResourceRuntime>,
    resolver: d2b_core::bundle_resolver::BundleResolver,
    device_ref: ResourceRef,
    device_uid: ResourceUid,
    holder_ref: ResourceRef,
    generation: ResourceGeneration,
    settings: d2b_provider_device_gpu::GpuSettings,
    operation_id: String,
    authority_leases: Arc<Mutex<BTreeMap<[u8; 16], AuthorityLease>>>,
    processes: Arc<
        Mutex<
            BTreeMap<
                (ResourceUid, u8),
                d2b_provider_device_gpu::GpuProcessIdentity,
            >,
        >,
    >,
    opened_devices: Vec<OwnedFd>,
}

impl DaemonGpuLifecyclePort {
    fn role_key(role: d2b_provider_device_gpu::GpuProcessRole) -> u8 {
        match role {
            d2b_provider_device_gpu::GpuProcessRole::FullGpu => 0,
            d2b_provider_device_gpu::GpuProcessRole::RenderNode => 1,
            d2b_provider_device_gpu::GpuProcessRole::Video => 2,
        }
    }

    fn intent(
        &self,
        template: &str,
    ) -> Result<d2b_core::bundle_resolver::ResolvedRunnerIntent, d2b_provider_device_gpu::GpuEffectError>
    {
        let vm = self.holder_ref.name().as_str();
        self.resolver
            .find_runner_intent_for_process_in_vm(
                Some(vm),
                "Host/host-system",
                d2b_core::processes::ProcessExecutionDomain::System,
                None,
                template,
            )
            .cloned()
            .ok_or(d2b_provider_device_gpu::GpuEffectError::SpawnRejected)
    }

    fn open_device_classes(
        &mut self,
        role_id: &str,
        classes: &[&str],
    ) -> Result<(), d2b_provider_device_gpu::GpuEffectError> {
        for device_class in classes {
            let request = d2b_contracts_broker::broker_wire::BrokerRequest::OpenDevice(
                d2b_contracts_broker::broker_wire::OpenDeviceRequest {
                    role_id: d2b_contracts::types::RoleId::new(role_id.to_owned()),
                    device_class: (*device_class).to_owned(),
                    tracing_span_id: None,
                },
            );
            let (response, fds) = crate::dispatch_broker_request_with_fds_timeout_as(
                &self.state,
                request,
                BrokerCallerRole::AdminUid {
                    uid: self.state.daemon_uid,
                },
                std::time::Duration::from_secs(10),
            )
            .map_err(|_| d2b_provider_device_gpu::GpuEffectError::OpenRejected)?;
            let accepted = matches!(
                response,
                d2b_contracts_broker::broker_wire::BrokerResponse::Ack(response)
                    if response.accepted
            );
            if !accepted || fds.len() != 1 {
                crate::close_received_fds(&fds);
                return Err(d2b_provider_device_gpu::GpuEffectError::OpenRejected);
            }
            let fd = crate::duplicate_received_fd(&fds, 0, "GPU device grant")
                .map_err(|_| d2b_provider_device_gpu::GpuEffectError::OpenRejected)?;
            crate::close_received_fds(&fds);
            self.opened_devices.push(fd);
        }
        Ok(())
    }

    fn spawn_worker(
        &mut self,
        template: &str,
        process_name: &str,
        principal: &d2b_provider_device_gpu::GpuPrincipalToken,
        platform: &d2b_provider_device_gpu::GpuPlatformToken,
        generation: ResourceGeneration,
        role: d2b_contracts_broker::broker_wire::RunnerRole,
    ) -> Result<
        d2b_provider_device_gpu::GpuProcessIdentity,
        d2b_provider_device_gpu::GpuEffectError,
    > {
        let intent = self.intent(template)?;
        let execution_ref = ResourceRef::parse(&intent.execution_ref)
            .map_err(|_| d2b_provider_device_gpu::GpuEffectError::SpawnRejected)?;
        let owner_uid = crate::block_on_future(self.runtime.committed_resource_value(
            &self.holder_ref,
            &self.operation_id,
        ))
        .map_err(|_| d2b_provider_device_gpu::GpuEffectError::SpawnRejected)
        .and_then(|value| {
            value
                .pointer("/metadata/uid")
                .and_then(Value::as_str)
                .and_then(|value| ResourceUid::parse(value.to_owned()).ok())
                .ok_or(d2b_provider_device_gpu::GpuEffectError::SpawnRejected)
        })?;
        let resource_ref = ResourceRef::parse(&format!("Process/{process_name}"))
        .map_err(|_| d2b_provider_device_gpu::GpuEffectError::SpawnRejected)?;
        let request = d2b_contracts_broker::broker_wire::BrokerRequest::SpawnRunner(
            d2b_contracts_broker::broker_wire::SpawnRunnerRequest {
                vm_id: VmId::new(self.holder_ref.name().as_str()),
                role_id: d2b_contracts::types::RoleId::new(intent.role_id.clone()),
                resource_ref: Some(resource_ref.clone()),
                resource_uid: None,
                zone_uid: self.runtime.authority_zone_uid().cloned(),
                owner_ref: Some(self.holder_ref.clone()),
                owner_uid: Some(owner_uid),
                provider_ref: Some(
                    ResourceRef::parse("Provider/system-minijail")
                        .map_err(|_| d2b_provider_device_gpu::GpuEffectError::SpawnRejected)?,
                ),
                bundle_content_identity: self
                    .runtime
                    .authority_bundle_generation()
                    .map(|value| value.as_str().to_owned()),
                provider_identity: None,
                template_identity: None,
                generation: Some(generation.get()),
                runtime_scope: Some(Self::scope_digest(
                    &self.device_uid,
                    &self.operation_id,
                )),
                activation_input: None,
                sandbox_plan: None,
                role,
                bundle_runner_intent_ref: BundleOpId::new(intent.intent_id.clone()),
                execution_ref: Some(execution_ref),
                execution_domain: Some(match intent.execution_domain {
                    d2b_core::processes::ProcessExecutionDomain::System => {
                        d2b_contracts_resource::v3::execution_policy::ExecutionDomain::System
                    }
                    d2b_core::processes::ProcessExecutionDomain::User => {
                        d2b_contracts_resource::v3::execution_policy::ExecutionDomain::User
                    }
                }),
                user_ref: intent
                    .user_ref
                    .as_deref()
                    .and_then(|value| ResourceRef::parse(value).ok()),
                guest_execution: None,
                runtime_allocations: Vec::new(),
                tracing_span_id: None,
                workload_identity: None,
                inherited_fd_count: u16::try_from(self.opened_devices.len())
                    .map_err(|_| d2b_provider_device_gpu::GpuEffectError::OpenRejected)?,
                network_tap_context: None,
            },
        );
        let request_fds = self
            .opened_devices
            .iter()
            .map(AsRawFd::as_raw_fd)
            .collect::<Vec<_>>();
        let (response, received_fds) = crate::dispatch_broker_request_with_optional_request_fds(
            &self.state,
            request,
            BrokerCallerRole::AdminUid {
                uid: self.state.daemon_uid,
            },
            &request_fds,
            std::time::Duration::from_secs(30),
        )
        .map_err(|_| d2b_provider_device_gpu::GpuEffectError::SpawnRejected)?;
        let response = match response {
            d2b_contracts_broker::broker_wire::BrokerResponse::SpawnRunner(response) => response,
            _ => {
                crate::close_received_fds(&received_fds);
                return Err(d2b_provider_device_gpu::GpuEffectError::SpawnRejected);
            }
        };
        if response.vm_id != VmId::new(self.holder_ref.name().as_str())
            || response.role != role
            || response.role_id.as_str() != intent.role_id
            || response.zone_uid != self.runtime.authority_zone_uid().cloned()
            || response.owner_ref.as_ref() != Some(&self.holder_ref)
            || response.generation != Some(generation.get())
            || response.resource_ref.as_ref() != Some(&resource_ref)
            || response.pid <= 0
        {
            crate::close_received_fds(&received_fds);
            return Err(d2b_provider_device_gpu::GpuEffectError::StaleDeviceIdentity);
        }
        let pidfd = crate::duplicate_received_fd(
            &received_fds,
            response.pidfd_index,
            "GPU SpawnRunner pidfd",
        )
        .map_err(|_| d2b_provider_device_gpu::GpuEffectError::SpawnRejected)?;
        crate::close_received_fds(&received_fds);
        let vm = self.holder_ref.name().as_str().to_owned();
        if self
            .state
            .pidfd_table
            .register(
                vm.clone(),
                intent.role_id.clone(),
                crate::PidfdEntry {
                    pidfd,
                    pid: response.pid,
                    start_time_ticks: response.start_time_ticks,
                },
            )
            .is_err()
        {
            let _ = crate::stop_vm_pidfd_role(
                &self.state,
                BrokerCallerRole::AdminUid {
                    uid: self.state.daemon_uid,
                },
                "device-gpu",
                &vm,
                &intent.role_id,
                std::time::Duration::from_secs(5),
                std::time::Duration::from_secs(5),
            );
            return Err(d2b_provider_device_gpu::GpuEffectError::SpawnRejected);
        }
        if self.state.pidfd_table.snapshot().is_err() {
            self.state.pidfd_table.deregister_if_matches(
                &vm,
                &intent.role_id,
                response.pid,
                response.start_time_ticks,
            );
            let _ = crate::stop_vm_pidfd_role(
                &self.state,
                BrokerCallerRole::AdminUid {
                    uid: self.state.daemon_uid,
                },
                "device-gpu",
                &vm,
                &intent.role_id,
                std::time::Duration::from_secs(5),
                std::time::Duration::from_secs(5),
            );
            return Err(d2b_provider_device_gpu::GpuEffectError::SpawnRejected);
        }
        let identity = d2b_provider_device_gpu::GpuProcessIdentity::from_core(
            Self::process_digest(&intent.intent_id, response.pid, response.start_time_ticks),
            match role {
                d2b_contracts_broker::broker_wire::RunnerRole::Video => {
                    d2b_provider_device_gpu::GpuProcessRole::Video
                }
                _ if self.settings.render_node_only => {
                    d2b_provider_device_gpu::GpuProcessRole::RenderNode
                }
                _ => d2b_provider_device_gpu::GpuProcessRole::FullGpu,
            },
            principal.clone(),
            platform.clone(),
            generation,
        );
        self.processes
            .lock()
            .map_err(|_| d2b_provider_device_gpu::GpuEffectError::SpawnRejected)?
            .insert(
                (self.device_uid.clone(), Self::role_key(identity.role())),
                identity.clone(),
            );
        Ok(identity)
    }

    fn scope_digest(device_uid: &ResourceUid, operation_id: &str) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"d2b:gpu-runtime-scope/v1");
        digest.update(device_uid.as_str().as_bytes());
        digest.update(operation_id.as_bytes());
        digest.finalize().into()
    }

    fn process_digest(intent_id: &str, pid: i32, start_time_ticks: u64) -> [u8; 16] {
        let mut digest = Sha256::new();
        digest.update(b"d2b:gpu-process/v1");
        digest.update(intent_id.as_bytes());
        digest.update(pid.to_be_bytes());
        digest.update(start_time_ticks.to_be_bytes());
        let digest: [u8; 32] = digest.finalize().into();
        digest[..16].try_into().expect("fixed process token length")
    }
}

impl d2b_provider_device_gpu::GpuLifecycleEffectPort for DaemonGpuLifecyclePort {
    fn reserve_authority(
        &mut self,
        admission: &d2b_provider_device_gpu::GpuAuthorityAdmission,
    ) -> Result<d2b_provider_device_gpu::GpuAuthorityLease, d2b_provider_device_gpu::GpuEffectError>
    {
        if admission.owner().device_uid() != &self.device_uid
            || admission.owner().holder_ref() != &self.holder_ref
            || admission.owner().generation() != self.generation
        {
            return Err(d2b_provider_device_gpu::GpuEffectError::StaleDeviceIdentity);
        }
        let request = AuthorityRequest::gpu_from_core(
            admission.owner().host_uid().clone(),
            self.device_ref.clone(),
            admission.owner().device_uid().clone(),
            admission.owner().generation(),
            *admission.backing().as_bytes(),
            admission.render_node_only(),
            admission.max_holders() as usize,
        )
        .map_err(|_| d2b_provider_device_gpu::GpuEffectError::AuthorityConflict)?;
        let lease = crate::block_on_future(async {
            self.runtime
                .authority_index
                .lock()
                .await
                .admit_authority(request)
        })
        .map_err(|_| d2b_provider_device_gpu::GpuEffectError::AuthorityConflict)?;
        let token = lease.token_bytes();
        self.authority_leases
            .lock()
            .map_err(|_| d2b_provider_device_gpu::GpuEffectError::AuthorityConflict)?
            .insert(token, lease);
        Ok(d2b_provider_device_gpu::GpuAuthorityLease::from_core(token))
    }

    fn open_authorized_devices(
        &mut self,
        admission: &d2b_provider_device_gpu::GpuAuthorityAdmission,
        tokens: &d2b_provider_device_gpu::GpuEffectTokenSet,
    ) -> Result<d2b_provider_device_gpu::GpuLaunchTicket, d2b_provider_device_gpu::GpuEffectError>
    {
        if admission.owner().device_uid() != &self.device_uid
            || admission.owner().generation() != self.generation
            || !admission.owner().holder_ref().eq(&self.holder_ref)
        {
            return Err(d2b_provider_device_gpu::GpuEffectError::StaleDeviceIdentity);
        }
        if tokens.is_empty() {
            return Err(d2b_provider_device_gpu::GpuEffectError::StaleDeviceIdentity);
        }
        let gpu_intent = self.intent(if self.settings.render_node_only {
            "render-node-worker"
        } else {
            "gpu-worker"
        })?;
        let mut classes = if self.settings.render_node_only {
            vec!["dri"]
        } else {
            vec!["kvm", "dri", "udmabuf"]
        };
        self.open_device_classes(&gpu_intent.role_id, &classes)?;
        if self.settings.video_sidecar {
            let video_intent = self.intent("video-worker")?;
            classes.clear();
            classes.push("dri");
            if self.settings.video_nvidia_decode {
                classes.extend(["nvidia-ctl", "nvidia-device", "nvidia-uvm"]);
            }
            self.open_device_classes(&video_intent.role_id, &classes)?;
        }
        Ok(d2b_provider_device_gpu::GpuLaunchTicket::from_core(
            Self::scope_digest(&self.device_uid, &self.operation_id)[..16]
                .try_into()
                .expect("fixed launch ticket length"),
        ))
    }

    fn start_gpu_worker(
        &mut self,
        spec: &d2b_provider_device_gpu::GpuWorkerSpec,
        _ticket: &d2b_provider_device_gpu::GpuLaunchTicket,
        principal: &d2b_provider_device_gpu::GpuPrincipalToken,
        platform: &d2b_provider_device_gpu::GpuPlatformToken,
        generation: ResourceGeneration,
    ) -> Result<
        d2b_provider_device_gpu::GpuProcessIdentity,
        d2b_provider_device_gpu::GpuEffectError,
    > {
        self.spawn_worker(
            spec.template(),
            &format!("gpu-{}", self.device_ref.name().as_str()),
            principal,
            platform,
            generation,
            d2b_contracts_broker::broker_wire::RunnerRole::Gpu,
        )
    }

    fn start_video_worker(
        &mut self,
        spec: &d2b_provider_device_gpu::VideoWorkerSpec,
        _ticket: &d2b_provider_device_gpu::GpuLaunchTicket,
        principal: &d2b_provider_device_gpu::GpuPrincipalToken,
        platform: &d2b_provider_device_gpu::GpuPlatformToken,
        generation: ResourceGeneration,
    ) -> Result<
        d2b_provider_device_gpu::GpuProcessIdentity,
        d2b_provider_device_gpu::GpuEffectError,
    > {
        self.spawn_worker(
            spec.template(),
            &format!("video-{}", self.device_ref.name().as_str()),
            principal,
            platform,
            generation,
            d2b_contracts_broker::broker_wire::RunnerRole::Video,
        )
    }

    fn observe_worker(
        &mut self,
        identity: &d2b_provider_device_gpu::GpuProcessIdentity,
    ) -> Result<
        d2b_provider_device_gpu::GpuProcessObservation,
        d2b_provider_device_gpu::GpuEffectError,
    > {
        let known = self
            .processes
            .lock()
            .map_err(|_| d2b_provider_device_gpu::GpuEffectError::ProcessObservationUnavailable)?
            .get(&(self.device_uid.clone(), Self::role_key(identity.role())))
            .is_some_and(|current| current == identity);
        if !known {
            return Ok(d2b_provider_device_gpu::GpuProcessObservation::Missing);
        }
        let intent = self.intent(match identity.role() {
            d2b_provider_device_gpu::GpuProcessRole::Video => "video-worker",
            d2b_provider_device_gpu::GpuProcessRole::RenderNode => "render-node-worker",
            d2b_provider_device_gpu::GpuProcessRole::FullGpu => "gpu-worker",
        })?;
        if self
            .state
            .pidfd_table
            .contains(self.holder_ref.name().as_str(), &intent.role_id)
        {
            Ok(d2b_provider_device_gpu::GpuProcessObservation::Matching(
                identity.clone(),
            ))
        } else {
            Ok(d2b_provider_device_gpu::GpuProcessObservation::Missing)
        }
    }

    fn stop_worker(
        &mut self,
        identity: &d2b_provider_device_gpu::GpuProcessIdentity,
    ) -> Result<
        d2b_provider_device_gpu::GpuClosureProof,
        d2b_provider_device_gpu::GpuEffectError,
    > {
        let intent = self.intent(match identity.role() {
            d2b_provider_device_gpu::GpuProcessRole::Video => "video-worker",
            d2b_provider_device_gpu::GpuProcessRole::RenderNode => "render-node-worker",
            d2b_provider_device_gpu::GpuProcessRole::FullGpu => "gpu-worker",
        })?;
        let known = self
            .processes
            .lock()
            .map_err(|_| d2b_provider_device_gpu::GpuEffectError::CloseUnconfirmed)?
            .get(&(self.device_uid.clone(), Self::role_key(identity.role())))
            .is_some_and(|current| current == identity);
        if !known {
            return Err(d2b_provider_device_gpu::GpuEffectError::StaleDeviceIdentity);
        }
        crate::stop_vm_pidfd_role(
            &self.state,
            BrokerCallerRole::AdminUid {
                uid: self.state.daemon_uid,
            },
            "device-gpu",
            self.holder_ref.name().as_str(),
            &intent.role_id,
            std::time::Duration::from_secs(10),
            std::time::Duration::from_secs(10),
        )
        .map_err(|_| d2b_provider_device_gpu::GpuEffectError::CloseUnconfirmed)?;
        self.processes
            .lock()
            .map_err(|_| d2b_provider_device_gpu::GpuEffectError::CloseUnconfirmed)?
            .remove(&(self.device_uid.clone(), Self::role_key(identity.role())));
        Ok(d2b_provider_device_gpu::GpuClosureProof::from_core(
            identity.clone(),
        ))
    }

    fn release_authority(
        &mut self,
        lease: d2b_provider_device_gpu::GpuAuthorityLease,
        _closures: &[d2b_provider_device_gpu::GpuClosureProof],
    ) -> Result<(), d2b_provider_device_gpu::GpuEffectError> {
        let token = *lease.as_bytes();
        let generic = self
            .authority_leases
            .lock()
            .map_err(|_| d2b_provider_device_gpu::GpuEffectError::AuthorityConflict)?
            .remove(&token)
            .ok_or(d2b_provider_device_gpu::GpuEffectError::AuthorityConflict)?;
        let result = crate::block_on_future(async {
            self.runtime
                .authority_index
                .lock()
                .await
                .release_authority(&generic)
        });
        if result.is_err() {
            self.authority_leases
                .lock()
                .map_err(|_| d2b_provider_device_gpu::GpuEffectError::AuthorityConflict)?
                .insert(token, generic);
            return Err(d2b_provider_device_gpu::GpuEffectError::AuthorityConflict);
        }
        Ok(())
    }
}

type SharedRunnerUsbipPort<'a> = d2b_provider_device_usbip::ProductionPort<
    crate::usbip_production::DaemonUsbipDispatcher<'a, SharedRunnerUsbipChildren>,
>;

#[async_trait]
impl SharedProviderEffectExecutor for DaemonSharedProviderEffects {
    async fn reconcile_display(
        &self,
        kind: SharedProviderResourceKind,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
    ) -> Result<SharedProviderEffectResult, SharedProviderEffectError> {
        let _value = self.validate(kind, context, resource)?;
        if kind == SharedProviderResourceKind::DisplayWaylandPolicy {
            ResourceEnvelope::from_json(resource.canonical_json())
                .map_err(|_| SharedProviderEffectError::InvalidResource)?;
            return Ok(SharedProviderEffectResult {
                phase: SharedProviderEffectPhase::Ready,
                child_mutated: false,
            });
        }

        let envelope = ResourceEnvelope::from_json(resource.canonical_json())
            .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        let spec = serde_json::from_slice::<WaylandSessionSpec>(
            &envelope.spec().base().to_canonical_bytes(),
        )
        .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        if !spec.cross_domain_trusted()
            || spec.guest_ref().resource_type().as_str() != "Guest"
            || spec.host_ref().resource_type().as_str() != "Host"
            || spec.user_ref().resource_type().as_str() != "User"
        {
            return Err(SharedProviderEffectError::InvalidResource);
        }
        let runtime = self.runtime()?;
        let client = runtime
            .process_resource_client()
            .ok_or(SharedProviderEffectError::Unavailable)?;
        let owner = stored_resource_from_snapshot(resource);
        let desired = crate::interaction_composition::display_owned_child_intents(
            &self.zone,
            resource.key().resource_ref(),
            resource.key().uid(),
            &spec,
            resource.generation().get(),
            context.identity.controller_generation().get(),
        )
        .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        let owner = crate::binding_child_resource_runtime::OwnedChildOwner {
            resource: owner,
            desired: Some(desired),
            fenced: false,
        };
        let converged = crate::binding_child_resource_runtime::reconcile_owned_children(
            &runtime.store,
            &client,
            &self.zone,
            &[owner.clone()],
        )
        .await
        .map_err(|_| SharedProviderEffectError::Unavailable)?;
        if !converged.contains(resource.key().resource_ref()) {
            return Ok(SharedProviderEffectResult {
                phase: SharedProviderEffectPhase::Pending,
                child_mutated: true,
            });
        }
        let children = crate::binding_child_resource_runtime::list_binding_children(
            &runtime.store,
            &self.zone,
        )
        .await
        .map_err(|_| SharedProviderEffectError::Unavailable)?;
        Ok(SharedProviderEffectResult {
            phase: if crate::binding_child_resource_runtime::owned_children_ready(
                &owner, &children,
            ) {
                SharedProviderEffectPhase::Ready
            } else {
                SharedProviderEffectPhase::Pending
            },
            child_mutated: false,
        })
    }

    async fn reconcile_audio(
        &self,
        kind: SharedProviderResourceKind,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
    ) -> Result<SharedProviderEffectResult, SharedProviderEffectError> {
        let _ = self.validate(kind, context, resource)?;
        let runtime = self.runtime()?;
        runtime
            .reconcile_audio_resources(Arc::clone(&self.state))
            .await
            .map_err(|_| SharedProviderEffectError::Unavailable)?;
        let phase = match kind {
            SharedProviderResourceKind::AudioService => runtime
                .audio_runtime
                .lock()
                .map_err(|_| SharedProviderEffectError::Unavailable)?
                .as_ref()
                .is_some_and(|audio| audio.service_is_ready(resource.key().resource_ref()))
                .then_some(SharedProviderEffectPhase::Ready)
                .unwrap_or(SharedProviderEffectPhase::Pending),
            SharedProviderResourceKind::AudioBinding => runtime
                .audio_runtime
                .lock()
                .map_err(|_| SharedProviderEffectError::Unavailable)?
                .as_ref()
                .and_then(|audio| audio.binding_phase(resource.key().resource_ref()))
                .map(|phase| {
                    (phase == d2b_provider_audio_pipewire::AudioBindingPhase::Ready)
                        .then_some(SharedProviderEffectPhase::Ready)
                        .unwrap_or(SharedProviderEffectPhase::Pending)
                })
                .unwrap_or(SharedProviderEffectPhase::Pending),
            _ => return Err(SharedProviderEffectError::InvalidResource),
        };
        Ok(SharedProviderEffectResult {
            phase,
            child_mutated: true,
        })
    }

    async fn reconcile_shell(
        &self,
        kind: SharedProviderResourceKind,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
    ) -> Result<SharedProviderEffectResult, SharedProviderEffectError> {
        let value = self.validate(kind, context, resource)?;
        let runtime = self.runtime()?;
        match kind {
            SharedProviderResourceKind::ShellPool => {
                shell_pool_spec(&value)?;
                Ok(SharedProviderEffectResult {
                    phase: SharedProviderEffectPhase::Ready,
                    child_mutated: false,
                })
            }
            SharedProviderResourceKind::ShellSession => {
                let pool_ref = resource_ref_at(&value, "/spec/poolRef")?;
                let pool = runtime
                    .committed_resource_value(&pool_ref, &context.operation_id)
                    .await
                    .map_err(|_| SharedProviderEffectError::Unavailable)?;
                if resource_phase(&pool) != Some("Ready") {
                    return Ok(SharedProviderEffectResult {
                        phase: SharedProviderEffectPhase::Pending,
                        child_mutated: false,
                    });
                }
                let (execution_ref, user_ref) = shell_execution(&value)?;
                let process_name = format!(
                    "Process/shell-session-{}",
                    resource.key().resource_ref().name().as_str()
                );
                let process_ref = ResourceRef::parse(&process_name)
                .map_err(|_| SharedProviderEffectError::InvalidResource)?;
                let client = runtime
                    .process_resource_client()
                    .ok_or(SharedProviderEffectError::Unavailable)?;
                let process_spec = json!({
                    "providerRef": "Provider/system-systemd",
                    "executionRef": execution_ref.to_canonical_string(),
                    "domain": if user_ref.is_some() { "user" } else { "system" },
                    "userRef": user_ref.as_ref().map(ResourceRef::to_canonical_string),
                    "processClass": "service",
                    "template": "shell-supervisor-main",
                    "desiredLifecycle": "running",
                    "deviceUsage": [],
                    "networkUsage": null
                });
                let desired = vec![
                    owned_child_intent(
                        &self.zone,
                        process_ref,
                        resource.key().resource_ref(),
                        process_spec,
                        [pool_ref],
                    )?,
                ];
                let owner = crate::binding_child_resource_runtime::OwnedChildOwner {
                    resource: stored_resource_from_snapshot(resource),
                    desired: Some(desired),
                    fenced: false,
                };
                let converged =
                    crate::binding_child_resource_runtime::reconcile_owned_children(
                        &runtime.store,
                        &client,
                        &self.zone,
                        std::slice::from_ref(&owner),
                    )
                    .await
                    .map_err(|_| SharedProviderEffectError::Unavailable)?;
                if !converged.contains(resource.key().resource_ref()) {
                    return Ok(SharedProviderEffectResult {
                        phase: SharedProviderEffectPhase::Pending,
                        child_mutated: true,
                    });
                }
                let children = crate::binding_child_resource_runtime::list_binding_children(
                    &runtime.store,
                    &self.zone,
                )
                .await
                .map_err(|_| SharedProviderEffectError::Unavailable)?;
                Ok(SharedProviderEffectResult {
                    phase: if crate::binding_child_resource_runtime::owned_children_ready(
                        &owner, &children,
                    ) {
                        SharedProviderEffectPhase::Ready
                    } else {
                        SharedProviderEffectPhase::Pending
                    },
                    child_mutated: false,
                })
            }
            _ => Err(SharedProviderEffectError::InvalidResource),
        }
    }

    async fn reconcile_guest(
        &self,
        kind: SharedProviderResourceKind,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
        dependencies: &[DependencySnapshot],
    ) -> Result<SharedProviderEffectPhase, SharedProviderEffectError> {
        self.reconcile_guest_runtime(kind, context, resource, dependencies)
            .await
            .map(|result| result.phase)
    }

    async fn reconcile_guest_result(
        &self,
        kind: SharedProviderResourceKind,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
        dependencies: &[DependencySnapshot],
    ) -> Result<SharedProviderEffectResult, SharedProviderEffectError> {
        self.reconcile_guest_runtime(kind, context, resource, dependencies)
            .await
    }

    async fn observe_result(
        &self,
        kind: SharedProviderResourceKind,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
    ) -> Result<SharedProviderEffectResult, SharedProviderEffectError> {
        if matches!(
            kind,
            SharedProviderResourceKind::CloudHypervisorGuest
                | SharedProviderResourceKind::QemuMediaGuest
                | SharedProviderResourceKind::AzureContainerAppsGuest
                | SharedProviderResourceKind::AzureVirtualMachineGuest
        ) {
            self.reconcile_guest_runtime(kind, context, resource, &[])
                .await
        } else {
            self.observe(kind, context, resource)
                .await
                .map(SharedProviderEffectResult::phase)
        }
    }

    async fn finalize_guest(
        &self,
        kind: SharedProviderResourceKind,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
    ) -> Result<(), SharedProviderEffectError> {
        self.finalize_guest_runtime(kind, context, resource).await
    }

    async fn reconcile_network(
        &self,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
        dependencies: &[DependencySnapshot],
    ) -> Result<SharedProviderEffectPhase, SharedProviderEffectError> {
        if !Self::dependencies_ready(dependencies) {
            return Ok(SharedProviderEffectPhase::Pending);
        }
        let value = self.validate(SharedProviderResourceKind::Network, context, resource)?;
        let mut spec_value = value
            .get("spec")
            .cloned()
            .ok_or(SharedProviderEffectError::InvalidResource)?;
        if let Some(spec) = spec_value.as_object_mut() {
            for field in ["providerRef", "updatePolicy", "provider"] {
                spec.remove(field);
            }
        }
        let spec: d2b_contracts_resource::v3::network::NetworkSpec =
            serde_json::from_value(spec_value)
                .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        let resolver = crate::load_bundle_resolver(&self.state)
            .map_err(|_| SharedProviderEffectError::Unavailable)?;
        let runtime = self.runtime()?;
        let generation = resource.generation();
        let admission = self
            .network_admission(
                &runtime,
                resource,
                &value,
                &spec,
                &resolver,
                &context.operation_id,
            )
            .await?;
        let provenance = NetworkProvenance::new(
            admission.key().zone_uid().clone(),
            admission.key().network_uid().clone(),
            admission.key().network_generation(),
            admission.key().attachment_generation(),
            admission.key().bundle_generation().clone(),
        );
        let assignment = self.network_assignment(&runtime, context, resource).await?;
        let children = SharedRunnerNetworkResources::new(
            Arc::clone(&runtime),
            resource.key().resource_ref().clone(),
            resource.key().uid(),
        )
        .with_content_fence(SharedRunnerNetworkContentFence {
            owner_ref: resource.key().resource_ref().clone(),
            provenance,
            assignment,
            controller_ref: context.identity.controller_ref().clone(),
            controller_generation: context.identity.controller_generation(),
            provider_generation: context.identity.provider_generation(),
            session_generation: runtime
                .core_controller_subject
                .lock()
                .map_err(|_| SharedProviderEffectError::Unavailable)?
                .as_ref()
                .map(|subject| subject.reconnect_generation())
                .ok_or(SharedProviderEffectError::Unavailable)?,
        });
        let readiness = children
            .readiness()
            .await
            .map_err(|_| SharedProviderEffectError::Unavailable)?;
        let broker_context = crate::resolve_network_effect_context(
            &value,
            &resolver,
            &admission,
        )
        .map_err(|_| SharedProviderEffectError::Unavailable)?
        .with_host_global_nic_admission();
        let effects = crate::network_effect_port::production_port(
            &self.state,
            BrokerCallerRole::AdminUid {
                uid: self.state.daemon_uid,
            },
            broker_context,
        );
        let mdns_enabled = value
            .pointer("/spec/mdns/enable")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let input = ReconcileInput {
            spec: spec.clone(),
            mdns_enabled,
            network_uid: resource.key().uid().clone(),
            network_generation: generation,
            attachment_generation: admission.key().attachment_generation(),
            installed_generation: admission.key().bundle_generation().clone(),
            admission,
            artifact_catalog: vec![ArtifactCatalogEntry::new(
                spec.net_vm_system_artifact_id().clone(),
                ArtifactKind::NixosSystem,
            )],
            user_ready: true,
            host_memory_budget_available: d2b_provider_network_local::controller::CONFIG_VOLUME_MAX_BYTES,
            volume_ready: readiness.volume_ready,
            guest_ready: readiness.guest_ready,
            volume_attachment_ready: readiness.attachment_ready,
            workload_fds_closed: true,
            agent_deleted: true,
            mdns_deleted: !mdns_enabled,
            volume_attachment_removed: true,
            guest_deleted: true,
            volume_deleted: true,
            attachments: Vec::<AttachmentRealization>::new(),
        };
        match NetworkReconciler::new(effects, children)
            .reconcile(&input)
            .await
            .map_err(|_| SharedProviderEffectError::Unavailable)?
        {
            ReconcileProgress::Ready => Ok(SharedProviderEffectPhase::Ready),
            ReconcileProgress::Pending(_)
            | ReconcileProgress::Requeue(_)
            | ReconcileProgress::Blocked(_) => Ok(SharedProviderEffectPhase::Pending),
        }
    }

    async fn reconcile_tpm(
        &self,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
    ) -> Result<SharedProviderEffectPhase, SharedProviderEffectError> {
        let value = self.validate(SharedProviderResourceKind::TpmDevice, context, resource)?;
        let execution_ref = value
            .pointer("/spec/provider/settings/executionRef")
            .and_then(Value::as_str)
            .and_then(|value| ResourceRef::parse(value).ok())
            .unwrap_or_else(|| ResourceRef::parse(CORE_CONTROLLER_HOST_REF).expect("Host ref"));
        let holder = Self::owner_ref(&value)?;
        if holder.resource_type().as_str() != "Guest" {
            return Err(SharedProviderEffectError::InvalidResource);
        }
        let runtime = self.runtime()?;
        let vm_id = d2b_contracts::types::VmId::new(holder.name().as_str());
        let migration_intent = d2b_contracts::types::BundleOpId::new(format!(
            "legacy-swtpm:vm:{}",
            vm_id.as_str()
        ));
        let decision = runtime
            .tpm_device_is_admitted(
            resource.key().uid(),
            resource.key().resource_ref(),
            vm_id.as_str(),
            &context.operation_id,
            None,
        )
        .await
        .map_err(|_| SharedProviderEffectError::Unavailable)?;
        let lifecycle = runtime
            .admit_internal_guest_lifecycle(holder.clone(), &context.operation_id)
            .await
        .map_err(|_| SharedProviderEffectError::Unavailable)?;
        let lifecycle_authorization =
            crate::provider_effects::LifecycleAuthorization::from_lease(
                lifecycle.lease,
                holder.clone(),
                lifecycle.guest_uid,
                lifecycle.guest_generation,
                lifecycle.provider_assignment_generation,
            )
            .map_err(|_| SharedProviderEffectError::InvalidResource)?;
        let resolver = crate::load_bundle_resolver(&self.state)
            .map_err(|_| SharedProviderEffectError::Unavailable)?;
        let log_level = value
            .pointer("/spec/provider/settings/logLevel")
            .and_then(Value::as_u64)
            .and_then(|value| u8::try_from(value).ok())
            .unwrap_or(20);
        let binary = d2b_provider_device_tpm::SignedBinaryRef::from_core(
            d2b_provider_device_tpm::BinaryKind::Swtpm,
            tpm_opaque_bytes("d2b:tpm-binary/v1", vm_id.as_str()),
        );
        let mut controller = if let Some(controller) = self
            .tpm_controllers
            .lock()
            .map_err(|_| SharedProviderEffectError::Unavailable)?
            .remove(resource.key().uid())
        {
            controller
        } else {
            d2b_provider_device_tpm::TpmResourceController::new(
                resource.key().uid().clone(),
                resource.key().resource_ref().clone(),
                execution_ref.clone(),
            )
            .map_err(|_| SharedProviderEffectError::InvalidResource)?
        };
        let result = crate::tpm_effect_port::reconcile_device_tpm_controller(
            &self.state,
            &resolver,
            vm_id.clone(),
            migration_intent,
            decision,
            crate::tpm_effect_port::AdmittedTpmDevice::new(
                resource.key().uid().clone(),
                resource.key().resource_ref().clone(),
                self.zone.as_str(),
                execution_ref,
                lifecycle_authorization,
            ),
            tpm_state_intent(resource.key().uid(), vm_id.as_str()),
            d2b_provider_device_tpm::SwtpmSettings { log_level },
            binary,
            d2b_contracts_broker::broker_wire::BrokerCallerRole::AdminUid {
                uid: self.state.daemon_uid,
            },
            &mut controller,
        )
        .map_err(|_| SharedProviderEffectError::Unavailable);
        if result.is_err() {
            self.tpm_controllers
                .lock()
                .map_err(|_| SharedProviderEffectError::Unavailable)?
                .insert(resource.key().uid().clone(), controller);
            return Err(SharedProviderEffectError::Unavailable);
        }
        let result = result.expect("TPM result was checked");
        self.tpm_controllers
            .lock()
            .map_err(|_| SharedProviderEffectError::Unavailable)?
            .insert(resource.key().uid().clone(), controller);
        match result {
            d2b_provider_device_tpm::TpmResourceOutcome::Ready => {
                Ok(SharedProviderEffectPhase::Ready)
            }
            d2b_provider_device_tpm::TpmResourceOutcome::Retry => {
                Ok(SharedProviderEffectPhase::Pending)
            }
            d2b_provider_device_tpm::TpmResourceOutcome::Failed
            | d2b_provider_device_tpm::TpmResourceOutcome::VolumeRetained => {
                Err(SharedProviderEffectError::Unavailable)
            }
        }
    }

    async fn reconcile_usbip(
        &self,
        component: UsbipResourceComponent,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
        dependencies: &[DependencySnapshot],
    ) -> Result<SharedProviderEffectPhase, SharedProviderEffectError> {
        if !Self::dependencies_ready(dependencies) {
            return Ok(SharedProviderEffectPhase::Pending);
        }
        let value = self.validate(
            match component {
                UsbipResourceComponent::Device => SharedProviderResourceKind::UsbipDevice,
                UsbipResourceComponent::Service => SharedProviderResourceKind::UsbipService,
                UsbipResourceComponent::Binding => SharedProviderResourceKind::UsbipBinding,
            },
            context,
            resource,
        )?;
        match component {
            UsbipResourceComponent::Device => {
                let runtime = self.runtime()?;
                let services = runtime
                    .committed_resources_of_type(
                        d2b_provider_device_usbip::USB_SERVICE_RESOURCE_TYPE,
                    )
                    .await
                    .map_err(|_| SharedProviderEffectError::Unavailable)?;
                let device_ref = resource.key().resource_ref().to_canonical_string();
                let ready = services.iter().any(|service| {
                    service.pointer("/spec/providerRef").and_then(Value::as_str)
                        == Some(d2b_provider_device_usbip::PROVIDER_REF)
                        && service
                            .pointer("/spec/backingDeviceRef")
                            .and_then(Value::as_str)
                            == Some(device_ref.as_str())
                        && service.pointer("/status/phase").and_then(Value::as_str)
                            == Some("Ready")
                });
                Ok(if ready {
                    SharedProviderEffectPhase::Ready
                } else {
                    SharedProviderEffectPhase::Pending
                })
            }
            UsbipResourceComponent::Service => {
                if self
                    .usbip_services
                    .lock()
                    .map_err(|_| SharedProviderEffectError::Unavailable)?
                    .contains(resource.key().uid())
                {
                    return Ok(SharedProviderEffectPhase::Ready);
                }
                let (zone_uid, zone_opted_in, mut port) =
                    self.usbip_service_port(context, resource, &value).await?;
                let mut lifecycle = d2b_provider_device_usbip::ServiceLifecycle::new(
                    zone_uid.clone(),
                    resource.key().uid().clone(),
                );
                lifecycle
                    .activate(zone_opted_in, zone_uid, &mut port)
                    .map_err(|_| SharedProviderEffectError::Unavailable)?;
                self.usbip_services
                    .lock()
                    .map_err(|_| SharedProviderEffectError::Unavailable)?
                    .insert(resource.key().uid().clone());
                Ok(SharedProviderEffectPhase::Ready)
            }
            UsbipResourceComponent::Binding => {
                let service_ref = value
                    .pointer("/spec/serviceRef")
                    .and_then(Value::as_str)
                    .and_then(|value| ResourceRef::parse(value).ok())
                    .ok_or(SharedProviderEffectError::InvalidResource)?;
                let guest_ref = value
                    .pointer("/spec/guestRef")
                    .and_then(Value::as_str)
                    .and_then(|value| ResourceRef::parse(value).ok())
                    .ok_or(SharedProviderEffectError::InvalidResource)?;
                let runtime = self.runtime()?;
                let zone_uid = runtime
                    .authority_zone_uid()
                    .cloned()
                    .ok_or(SharedProviderEffectError::Unavailable)?;
                let service = runtime
                    .committed_resource_value(&service_ref, &context.operation_id)
                    .await
                    .map_err(|_| SharedProviderEffectError::Unavailable)?;
                if service.pointer("/spec/providerRef").and_then(Value::as_str)
                    != Some(d2b_provider_device_usbip::PROVIDER_REF)
                {
                    return Err(SharedProviderEffectError::InvalidResource);
                }
                if service.pointer("/status/phase").and_then(Value::as_str) != Some("Ready") {
                    return Ok(SharedProviderEffectPhase::Pending);
                }
                let service_uid = service
                    .pointer("/metadata/uid")
                    .and_then(Value::as_str)
                    .and_then(|value| ResourceUid::parse(value.to_owned()).ok())
                    .ok_or(SharedProviderEffectError::InvalidResource)?;
                let service_generation = service
                    .pointer("/metadata/generation")
                    .and_then(Value::as_u64)
                    .and_then(|value| ResourceGeneration::new(value).ok())
                    .ok_or(SharedProviderEffectError::InvalidResource)?;
                let guest = runtime
                    .committed_resource_value(&guest_ref, &context.operation_id)
                    .await
                    .map_err(|_| SharedProviderEffectError::Unavailable)?;
                if guest.pointer("/status/phase").and_then(Value::as_str) != Some("Ready") {
                    return Ok(SharedProviderEffectPhase::Pending);
                }
                let guest_uid = guest
                    .pointer("/metadata/uid")
                    .and_then(Value::as_str)
                    .and_then(|value| ResourceUid::parse(value.to_owned()).ok())
                    .ok_or(SharedProviderEffectError::InvalidResource)?;
                let assignment_epoch = runtime
                    .store
                    .assignment_fence(
                        self.zone.clone(),
                        resource.key().resource_ref().clone(),
                    )
                    .await
                    .map_err(|_| SharedProviderEffectError::Unavailable)?
                    .map(|fence| fence.epoch)
                    .filter(|epoch| *epoch != 0)
                    .ok_or(SharedProviderEffectError::Unavailable)?;
                let admission = d2b_provider_device_usbip::UsbipBindingAdmission::new(
                    zone_uid,
                    resource.key().uid().clone(),
                    service_uid,
                    guest_uid,
                    service_generation,
                    assignment_epoch,
                )
                .map_err(|_| SharedProviderEffectError::InvalidResource)?;
                let mut controller =
                    d2b_provider_device_usbip::UsbipBindingController::new_admitted(
                        resource.key().resource_ref(),
                        &service_ref,
                        &guest_ref,
                        admission,
                    )
                    .map_err(|_| SharedProviderEffectError::InvalidResource)?;
                let desired = d2b_provider_device_usbip::binding_child_resources(
                    resource.key().resource_ref(),
                    &service_ref,
                    &guest_ref,
                )
                .map_err(|_| SharedProviderEffectError::InvalidResource)?;
                let phase = self
                    .reconcile_binding_children(
                        &runtime,
                        resource,
                        desired,
                        &context.operation_id,
                    )
                    .await?;
                if phase == SharedProviderEffectPhase::Ready {
                    controller
                        .observe_children(true)
                        .map_err(|_| SharedProviderEffectError::Unavailable)?;
                }
                Ok(phase)
            }
        }
    }

    async fn reconcile_security_key(
        &self,
        component: SecurityKeyResourceComponent,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
        dependencies: &[DependencySnapshot],
    ) -> Result<SharedProviderEffectPhase, SharedProviderEffectError> {
        if !Self::dependencies_ready(dependencies) {
            return Ok(SharedProviderEffectPhase::Pending);
        }
        let value = self.validate(
            match component {
                SecurityKeyResourceComponent::Device => {
                    SharedProviderResourceKind::SecurityKeyDevice
                }
                SecurityKeyResourceComponent::Service => {
                    SharedProviderResourceKind::SecurityKeyService
                }
                SecurityKeyResourceComponent::Binding => {
                    SharedProviderResourceKind::SecurityKeyBinding
                }
            },
            context,
            resource,
        )?;
        match component {
            SecurityKeyResourceComponent::Device => {
                let admitted = value
                    .pointer("/status/resource/devicePresent")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                    && value
                        .pointer("/status/resource/fidoConfirmed")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                Ok(if admitted {
                    SharedProviderEffectPhase::Ready
                } else {
                    SharedProviderEffectPhase::Pending
                })
            }
            SecurityKeyResourceComponent::Service => {
                let runtime = self.runtime()?;
                let mode = value
                    .pointer("/spec/mode")
                    .and_then(Value::as_str)
                    .ok_or(SharedProviderEffectError::InvalidResource)?;
                if mode == "projection" {
                    let endpoint_ref = value
                        .pointer("/status/resource/relayEndpointRef")
                        .or_else(|| value.pointer("/status/provider/details/relayEndpointRef"))
                        .and_then(Value::as_str)
                        .and_then(|value| ResourceRef::parse(value).ok())
                        .ok_or(SharedProviderEffectError::Unavailable)?;
                    let endpoint = runtime
                        .committed_resource_value(&endpoint_ref, &context.operation_id)
                        .await
                        .map_err(|_| SharedProviderEffectError::Unavailable)?;
                    return Ok(if endpoint.pointer("/status/phase").and_then(Value::as_str)
                        == Some("Ready")
                    {
                        SharedProviderEffectPhase::Ready
                    } else {
                        SharedProviderEffectPhase::Pending
                    });
                }
                let settings = value
                    .pointer("/spec/provider/settings")
                    .ok_or(SharedProviderEffectError::InvalidResource)?;
                let device_ref = settings
                    .get("deviceRef")
                    .and_then(Value::as_str)
                    .and_then(|value| ResourceRef::parse(value).ok())
                    .ok_or(SharedProviderEffectError::InvalidResource)?;
                let relay_endpoint_ref = settings
                    .get("relayEndpointRef")
                    .and_then(Value::as_str)
                    .and_then(|value| ResourceRef::parse(value).ok())
                    .ok_or(SharedProviderEffectError::InvalidResource)?;
                if device_ref.resource_type().as_str() != "Device"
                    || relay_endpoint_ref.resource_type().as_str() != "Endpoint"
                {
                    return Err(SharedProviderEffectError::InvalidResource);
                }
                let device = runtime
                    .committed_resource_value(&device_ref, &context.operation_id)
                    .await
                    .map_err(|_| SharedProviderEffectError::Unavailable)?;
                if device.pointer("/spec/providerRef").and_then(Value::as_str)
                    != Some(d2b_provider_device_security_key::PROVIDER_REF)
                {
                    return Err(SharedProviderEffectError::InvalidResource);
                }
                if device.pointer("/status/phase").and_then(Value::as_str) != Some("Ready") {
                    return Ok(SharedProviderEffectPhase::Pending);
                }
                let device_uid = device
                    .pointer("/metadata/uid")
                    .and_then(Value::as_str)
                    .and_then(|value| ResourceUid::parse(value.to_owned()).ok())
                    .ok_or(SharedProviderEffectError::InvalidResource)?;
                let relay_process_name =
                    d2b_provider_device_security_key::security_key_process_name(
                        &device_uid,
                        d2b_provider_device_security_key::SecurityKeyProcessRole::HostRelay,
                    )
                    .map_err(|_| SharedProviderEffectError::InvalidResource)?;
                let relay_process_ref =
                    ResourceRef::parse(&format!("Process/{relay_process_name}"))
                        .map_err(|_| SharedProviderEffectError::InvalidResource)?;
                let relay_process_spec = json!({
                    "providerRef": "Provider/system-minijail",
                    "executionRef": "Host/host-system",
                    "domain": "system",
                    "processClass": "service",
                    "template": "sk-relay",
                    "desiredLifecycle": "running",
                    "deviceUsage": [{
                        "deviceRef": device_ref.to_canonical_string(),
                        "access": "exclusive",
                        "purpose": "hidraw-fido"
                    }],
                    "sandbox": {
                        "namespaceClasses": ["mount", "ipc", "pid"],
                        "capabilityClasses": [],
                        "seccompClass": "sk-relay",
                        "environmentClass": "provider-defined",
                        "startRoot": false,
                        "noNewPrivileges": true,
                        "readOnlyRoot": true
                    },
                    "budget": {
                        "pids": {"limit": 32},
                        "fds": {"limit": 64},
                        "memory": {"limit": "32Mi"}
                    }
                });
                upsert_shared_provider_child(
                    &runtime,
                    &relay_process_ref,
                    relay_process_spec,
                    resource.key().resource_ref(),
                    "shared-security-key-relay-upsert",
                )
                .await
                .map_err(|_| SharedProviderEffectError::Unavailable)?;
                let endpoint_spec = json!({
                    "providerRef": d2b_provider_device_security_key::PROVIDER_REF,
                    "producerRef": relay_process_ref.to_canonical_string(),
                    "endpointClass": "device",
                    "transport": "vsock",
                    "purpose": "device-security-key.d2bus.org/ctaphid-relay",
                    "serviceFingerprint": "device-security-key.d2bus.org/SecurityKeyCtapRelay.v3",
                    "locality": "cross-domain",
                    "visibility": "zone",
                    "attachmentPolicy": "component-session",
                    "consumerPolicy": {
                        "allowedProviderComponents": ["device-security-key.d2bus.org/frontend"],
                        "allowedOperations": ["resolve"]
                    },
                    "lifecyclePolicy": "recycle-with-producer"
                });
                upsert_shared_provider_child(
                    &runtime,
                    &relay_endpoint_ref,
                    endpoint_spec,
                    resource.key().resource_ref(),
                    "shared-security-key-relay-endpoint-upsert",
                )
                .await
                .map_err(|_| SharedProviderEffectError::Unavailable)?;
                let process = runtime
                    .committed_resource_value(&relay_process_ref, &context.operation_id)
                    .await
                    .map_err(|_| SharedProviderEffectError::Unavailable)?;
                let endpoint = runtime
                    .committed_resource_value(&relay_endpoint_ref, &context.operation_id)
                    .await
                    .map_err(|_| SharedProviderEffectError::Unavailable)?;
                Ok(if process.pointer("/status/phase").and_then(Value::as_str)
                    == Some("Ready")
                    && endpoint.pointer("/status/phase").and_then(Value::as_str) == Some("Ready")
                {
                    SharedProviderEffectPhase::Ready
                } else {
                    SharedProviderEffectPhase::Pending
                })
            }
            SecurityKeyResourceComponent::Binding => {
                let service_ref = value
                    .pointer("/spec/serviceRef")
                    .and_then(Value::as_str)
                    .and_then(|value| ResourceRef::parse(value).ok())
                    .ok_or(SharedProviderEffectError::InvalidResource)?;
                let target = value
                    .pointer("/spec/target/guestRef")
                    .or_else(|| value.pointer("/spec/guestRef"))
                    .and_then(Value::as_str)
                    .and_then(|value| ResourceRef::parse(value).ok())
                    .ok_or(SharedProviderEffectError::InvalidResource)?;
                let runtime = self.runtime()?;
                let service = runtime
                    .committed_resource_value(&service_ref, &context.operation_id)
                    .await
                    .map_err(|_| SharedProviderEffectError::Unavailable)?;
                if service.pointer("/spec/providerRef").and_then(Value::as_str)
                    != Some(d2b_provider_device_security_key::PROVIDER_REF)
                {
                    return Err(SharedProviderEffectError::InvalidResource);
                }
                if service.pointer("/status/phase").and_then(Value::as_str) != Some("Ready") {
                    return Ok(SharedProviderEffectPhase::Pending);
                }
                let guest = runtime
                    .committed_resource_value(&target, &context.operation_id)
                    .await
                    .map_err(|_| SharedProviderEffectError::Unavailable)?;
                if guest.pointer("/status/phase").and_then(Value::as_str) != Some("Ready") {
                    return Ok(SharedProviderEffectPhase::Pending);
                }
                let desired = if let Some(user) = value
                    .pointer("/spec/target/userRef")
                    .or_else(|| value.pointer("/spec/userRef"))
                    .and_then(Value::as_str)
                    .and_then(|value| ResourceRef::parse(value).ok())
                {
                    d2b_provider_device_security_key::SecurityKeyController::child_resources_for_user(
                        resource.key().resource_ref(),
                        &service_ref,
                        &target,
                        &user,
                    )
                } else {
                    d2b_provider_device_security_key::SecurityKeyController::child_resources(
                        resource.key().resource_ref(),
                        &service_ref,
                        &target,
                    )
                }
                .map_err(|_| SharedProviderEffectError::InvalidResource)?;
                self.reconcile_binding_children(
                    &runtime,
                    resource,
                    desired,
                    &context.operation_id,
                )
                .await
            }
        }
    }

    async fn reconcile_gpu(
        &self,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
        dependencies: &[DependencySnapshot],
    ) -> Result<SharedProviderEffectPhase, SharedProviderEffectError> {
        if !Self::dependencies_ready(dependencies) {
            return Ok(SharedProviderEffectPhase::Pending);
        }
        let value = self.validate(SharedProviderResourceKind::GpuDevice, context, resource)?;
        let (runtime, admission, tokens, settings, holder_ref) =
            self.gpu_admission(context, resource, &value).await?;
        let resolver = crate::load_bundle_resolver(&self.state)
            .map_err(|_| SharedProviderEffectError::Unavailable)?;
        let mut controller = if let Some(controller) = self
            .gpu_controllers
            .lock()
            .map_err(|_| SharedProviderEffectError::Unavailable)?
            .remove(resource.key().uid())
        {
            controller
        } else {
            d2b_provider_device_gpu::GpuController::new_authorized(
                admission.clone(),
                settings.clone(),
                tokens.clone(),
            )
            .map_err(|_| SharedProviderEffectError::InvalidResource)?
        };
        if controller
            .admission()
            .is_some_and(|current| current != &admission)
        {
            self.gpu_controllers
                .lock()
                .map_err(|_| SharedProviderEffectError::Unavailable)?
                .insert(resource.key().uid().clone(), controller);
            return Err(SharedProviderEffectError::InvalidResource);
        }
        let opened_devices = self.take_gpu_opened_devices(resource.key().uid())?;
        let mut port = DaemonGpuLifecyclePort {
            state: Arc::clone(&self.state),
            runtime,
            resolver,
            device_ref: resource.key().resource_ref().clone(),
            device_uid: resource.key().uid().clone(),
            holder_ref,
            generation: resource.generation(),
            settings,
            operation_id: context.operation_id.clone(),
            authority_leases: Arc::clone(&self.gpu_authority_leases),
            processes: Arc::clone(&self.gpu_processes),
            opened_devices,
        };
        let result = controller
            .reconcile_lifecycle(&mut port)
            .map_err(|_| SharedProviderEffectError::Unavailable)
            .map(|outcome| match outcome {
                d2b_provider_device_gpu::GpuReconcileOutcome::Converged => {
                    SharedProviderEffectPhase::Ready
                }
                d2b_provider_device_gpu::GpuReconcileOutcome::Retry => {
                    SharedProviderEffectPhase::Pending
                }
            });
        let opened_devices = std::mem::take(&mut port.opened_devices);
        self.retain_gpu_opened_devices(resource.key().uid(), opened_devices)?;
        self.gpu_controllers
            .lock()
            .map_err(|_| SharedProviderEffectError::Unavailable)?
            .insert(resource.key().uid().clone(), controller);
        result
    }

    async fn upgrade(
        &self,
        kind: SharedProviderResourceKind,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
        dependencies: &[DependencySnapshot],
    ) -> Result<SharedProviderEffectPhase, SharedProviderEffectError> {
        if kind != SharedProviderResourceKind::GpuDevice {
            return self.reconcile(kind, context, resource, dependencies).await;
        }
        if !Self::dependencies_ready(dependencies) {
            return Ok(SharedProviderEffectPhase::Pending);
        }
        let value = self.validate(kind, context, resource)?;
        let (runtime, admission, _tokens, settings, holder_ref) =
            self.gpu_admission(context, resource, &value).await?;
        let dependents = dependencies
            .iter()
            .map(|dependency| {
                let dependency_value =
                    serde_json::from_slice::<Value>(dependency.resource().canonical_json())
                        .map_err(|_| SharedProviderEffectError::InvalidResource)?;
                let ready = dependency_value
                    .pointer("/status/phase")
                    .and_then(Value::as_str)
                    == Some("Ready");
                let drained = dependency_value
                    .pointer("/status/resource/drained")
                    .and_then(Value::as_bool)
                    .unwrap_or_else(|| {
                        dependency_value
                            .pointer("/status/phase")
                            .and_then(Value::as_str)
                            == Some("Deleted")
                    });
                d2b_provider_device_gpu::GpuDependentResource::new(
                    dependency.resource().key().resource_ref().clone(),
                    ready,
                    drained,
                )
                .map_err(|_| SharedProviderEffectError::InvalidResource)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if dependents.iter().any(|dependent| !dependent.ready()) {
            return Ok(SharedProviderEffectPhase::Pending);
        }
        if dependents.iter().any(|dependent| !dependent.drained()) {
            return Ok(SharedProviderEffectPhase::Pending);
        }
        let resolver = crate::load_bundle_resolver(&self.state)
            .map_err(|_| SharedProviderEffectError::Unavailable)?;
        let mut controller = self
            .gpu_controllers
            .lock()
            .map_err(|_| SharedProviderEffectError::Unavailable)?
            .remove(resource.key().uid())
            .ok_or(SharedProviderEffectError::Unavailable)?;
        if controller
            .admission()
            .is_some_and(|current| current != &admission)
        {
            self.gpu_controllers
                .lock()
                .map_err(|_| SharedProviderEffectError::Unavailable)?
                .insert(resource.key().uid().clone(), controller);
            return Err(SharedProviderEffectError::InvalidResource);
        }
        let plan = match controller.plan_upgrade(settings.clone(), &dependents) {
            Ok(plan) => plan,
            Err(
                d2b_provider_device_gpu::GpuControllerError::DependenciesNotReady
                | d2b_provider_device_gpu::GpuControllerError::DependenciesNotDrained,
            ) => {
                self.gpu_controllers
                    .lock()
                    .map_err(|_| SharedProviderEffectError::Unavailable)?
                    .insert(resource.key().uid().clone(), controller);
                return Ok(SharedProviderEffectPhase::Pending);
            }
            Err(_) => {
                self.gpu_controllers
                    .lock()
                    .map_err(|_| SharedProviderEffectError::Unavailable)?
                    .insert(resource.key().uid().clone(), controller);
                return Err(SharedProviderEffectError::InvalidResource);
            }
        };
        let mut port = DaemonGpuLifecyclePort {
            state: Arc::clone(&self.state),
            runtime,
            resolver,
            device_ref: resource.key().resource_ref().clone(),
            device_uid: resource.key().uid().clone(),
            holder_ref,
            generation: resource.generation(),
            settings,
            operation_id: context.operation_id.clone(),
            authority_leases: Arc::clone(&self.gpu_authority_leases),
            processes: Arc::clone(&self.gpu_processes),
            opened_devices: self.take_gpu_opened_devices(resource.key().uid())?,
        };
        let result = controller
            .execute_upgrade(&plan, &mut port)
            .map_err(|_| SharedProviderEffectError::Unavailable)
            .map(|outcome| match outcome {
                d2b_provider_device_gpu::GpuReconcileOutcome::Converged => {
                    SharedProviderEffectPhase::Ready
                }
                d2b_provider_device_gpu::GpuReconcileOutcome::Retry => {
                    SharedProviderEffectPhase::Pending
                }
            });
        let opened_devices = std::mem::take(&mut port.opened_devices);
        self.retain_gpu_opened_devices(resource.key().uid(), opened_devices)?;
        self.gpu_controllers
            .lock()
            .map_err(|_| SharedProviderEffectError::Unavailable)?
            .insert(resource.key().uid().clone(), controller);
        result
    }

    async fn observe(
        &self,
        kind: SharedProviderResourceKind,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
    ) -> Result<SharedProviderEffectPhase, SharedProviderEffectError> {
        if kind != SharedProviderResourceKind::GpuDevice {
            return self.reconcile(kind, context, resource, &[]).await;
        }
        let value = self.validate(kind, context, resource)?;
        let runtime = self.runtime()?;
        let settings: d2b_provider_device_gpu::GpuSettings =
            match value.pointer("/spec/provider/settings") {
                Some(settings) => serde_json::from_value(settings.clone())
                    .map_err(|_| SharedProviderEffectError::InvalidResource)?,
                None => d2b_provider_device_gpu::GpuSettings::default(),
            };
        let admission = self
            .gpu_controllers
            .lock()
            .map_err(|_| SharedProviderEffectError::Unavailable)?
            .get(resource.key().uid())
            .and_then(|controller| controller.admission().cloned())
            .ok_or(SharedProviderEffectError::Unavailable)?;
        let expected = self
            .gpu_controllers
            .lock()
            .map_err(|_| SharedProviderEffectError::Unavailable)?
            .get(resource.key().uid())
            .map(|controller| {
                controller
                    .gpu_identity()
                    .into_iter()
                    .chain(controller.video_identity())
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .ok_or(SharedProviderEffectError::Unavailable)?;
        if expected.is_empty() {
            return Ok(SharedProviderEffectPhase::Pending);
        }
        let resolver = crate::load_bundle_resolver(&self.state)
            .map_err(|_| SharedProviderEffectError::Unavailable)?;
        let mut port = DaemonGpuLifecyclePort {
            state: Arc::clone(&self.state),
            runtime,
            resolver,
            device_ref: resource.key().resource_ref().clone(),
            device_uid: resource.key().uid().clone(),
            holder_ref: admission.owner().holder_ref().clone(),
            generation: resource.generation(),
            settings,
            operation_id: context.operation_id.clone(),
            authority_leases: Arc::clone(&self.gpu_authority_leases),
            processes: Arc::clone(&self.gpu_processes),
            opened_devices: Vec::new(),
        };
        let observed = expected.iter().all(|identity| {
            matches!(
                port.observe_worker(identity),
                Ok(d2b_provider_device_gpu::GpuProcessObservation::Matching(_))
            )
        });
        Ok(if observed {
            SharedProviderEffectPhase::Ready
        } else {
            SharedProviderEffectPhase::Pending
        })
    }

    async fn finalize(
        &self,
        kind: SharedProviderResourceKind,
        context: &SharedProviderEffectContext,
        resource: &ResourceSnapshot,
    ) -> Result<(), SharedProviderEffectError> {
        if matches!(
            kind,
            SharedProviderResourceKind::CloudHypervisorGuest
                | SharedProviderResourceKind::QemuMediaGuest
                | SharedProviderResourceKind::AzureContainerAppsGuest
                | SharedProviderResourceKind::AzureVirtualMachineGuest
        ) {
            return self.finalize_guest_runtime(kind, context, resource).await;
        }
        if matches!(
            kind,
            SharedProviderResourceKind::DisplayWaylandPolicy
                | SharedProviderResourceKind::DisplayWaylandSession
                | SharedProviderResourceKind::AudioService
                | SharedProviderResourceKind::AudioBinding
                | SharedProviderResourceKind::ShellPool
                | SharedProviderResourceKind::ShellSession
        ) {
            return self.finalize_u9(kind, context, resource).await;
        }
        let value = self.validate(kind, context, resource)?;
        if kind == SharedProviderResourceKind::Network {
            let resolver = crate::load_bundle_resolver(&self.state)
                .map_err(|_| SharedProviderEffectError::Unavailable)?;
            let runtime = self.runtime()?;
            let spec_for_admission = crate::parse_committed_network_spec(&value)
                .map_err(|_| SharedProviderEffectError::InvalidResource)?;
            let admission = self
                .network_admission(
                    &runtime,
                    resource,
                    &value,
                    &spec_for_admission,
                    &resolver,
                    &context.operation_id,
                )
                .await?;
            let mut spec_value = value
                .get("spec")
                .cloned()
                .ok_or(SharedProviderEffectError::InvalidResource)?;
            if let Some(spec) = spec_value.as_object_mut() {
                for field in ["providerRef", "updatePolicy", "provider"] {
                    spec.remove(field);
                }
            }
            let spec: d2b_contracts_resource::v3::network::NetworkSpec =
                serde_json::from_value(spec_value)
                    .map_err(|_| SharedProviderEffectError::InvalidResource)?;
            let children = SharedRunnerNetworkResources::new(
                Arc::clone(&runtime),
                resource.key().resource_ref().clone(),
                resource.key().uid(),
            );
            let volume = children
                .current(&children.volume_ref)
                .await
                .map_err(|_| SharedProviderEffectError::Unavailable)?;
            let guest = children
                .current(&children.guest_ref)
                .await
                .map_err(|_| SharedProviderEffectError::Unavailable)?;
            let agent = children
                .current(&children.agent_ref)
                .await
                .map_err(|_| SharedProviderEffectError::Unavailable)?;
            let volume_attachment_removed = volume.as_ref().is_none_or(|value| {
                value
                    .pointer("/spec/attachments")
                    .and_then(Value::as_array)
                    .is_none_or(Vec::is_empty)
            });
            let mdns_enabled = value
                .pointer("/spec/mdns/enable")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if mdns_enabled {
                return Err(SharedProviderEffectError::Unavailable);
            }
            let broker_context = crate::resolve_network_effect_context(
                &value,
                &resolver,
                &admission,
            )
            .map_err(|_| SharedProviderEffectError::Unavailable)?
            .with_host_global_nic_admission();
            let effects = crate::network_effect_port::production_port(
                &self.state,
                BrokerCallerRole::AdminUid {
                    uid: self.state.daemon_uid,
                },
                broker_context,
            );
            let input = ReconcileInput {
                spec,
                mdns_enabled,
                network_uid: resource.key().uid().clone(),
                network_generation: resource.generation(),
                attachment_generation: admission.key().attachment_generation(),
                installed_generation: admission.key().bundle_generation().clone(),
                admission,
                artifact_catalog: Vec::new(),
                user_ready: true,
                host_memory_budget_available:
                    d2b_provider_network_local::controller::CONFIG_VOLUME_MAX_BYTES,
                volume_ready: true,
                guest_ready: true,
                volume_attachment_ready: true,
                workload_fds_closed: true,
                agent_deleted: agent.is_none(),
                mdns_deleted: true,
                volume_attachment_removed,
                guest_deleted: guest.is_none(),
                volume_deleted: volume.is_none(),
                attachments: Vec::new(),
            };
            let stage = NetworkReconciler::new(effects, children)
                .finalize(&input)
                .await
                .map_err(|_| SharedProviderEffectError::Unavailable)?;
            if stage != d2b_provider_network_local::controller::FinalizerStage::Complete {
                return Err(SharedProviderEffectError::Unavailable);
            }
            let zone_uid = runtime.authority_zone_uid().cloned();
            let plane = self
                .state
                .resource_plane
                .lock()
                .ok()
                .and_then(|plane| plane.clone());
            if let (Some(zone_uid), Some(plane)) = (zone_uid, plane) {
                plane
                    .network_admission_index()
                    .lock()
                    .await
                    .release_owner_after_finalizer(
                        &zone_uid,
                        resource.key().uid(),
                        true,
                    );
            }
            return Ok(());
        }
        if kind == SharedProviderResourceKind::TpmDevice {
            let holder = Self::owner_ref(&value)?;
            if holder.resource_type().as_str() != "Guest" {
                return Err(SharedProviderEffectError::InvalidResource);
            }
            let execution_ref = value
                .pointer("/spec/provider/settings/executionRef")
                .and_then(Value::as_str)
                .and_then(|value| ResourceRef::parse(value).ok())
                .unwrap_or_else(|| ResourceRef::parse(CORE_CONTROLLER_HOST_REF).expect("Host ref"));
            let runtime = self.runtime()?;
            let runtime_for_children = Arc::clone(&runtime);
            let vm_id = VmId::new(holder.name().as_str());
            let migration_intent =
                BundleOpId::new(format!("legacy-swtpm:vm:{}", vm_id.as_str()));
            let decision = runtime
                .tpm_device_is_admitted(
                    resource.key().uid(),
                    resource.key().resource_ref(),
                    vm_id.as_str(),
                    &context.operation_id,
                    None,
                )
                .await
                .map_err(|_| SharedProviderEffectError::Unavailable)?;
            let lifecycle = runtime
                .admit_internal_guest_lifecycle(holder.clone(), &context.operation_id)
                .await
                .map_err(|_| SharedProviderEffectError::Unavailable)?;
            let authorization =
                crate::provider_effects::LifecycleAuthorization::from_lease(
                    lifecycle.lease,
                    holder,
                    lifecycle.guest_uid,
                    lifecycle.guest_generation,
                    lifecycle.provider_assignment_generation,
                )
                .map_err(|_| SharedProviderEffectError::InvalidResource)?;
            let resolver = crate::load_bundle_resolver(&self.state)
                .map_err(|_| SharedProviderEffectError::Unavailable)?;
            let log_level = value
                .pointer("/spec/provider/settings/logLevel")
                .and_then(Value::as_u64)
                .and_then(|value| u8::try_from(value).ok())
                .unwrap_or(20);
            let mut controller = self
                .tpm_controllers
                .lock()
                .map_err(|_| SharedProviderEffectError::Unavailable)?
                .remove(resource.key().uid())
                .ok_or(SharedProviderEffectError::Unavailable)?;
            let result = crate::tpm_effect_port::finalize_device_tpm_controller(
                &self.state,
                &resolver,
                vm_id.clone(),
                migration_intent,
                decision,
                crate::tpm_effect_port::AdmittedTpmDevice::new(
                    resource.key().uid().clone(),
                    resource.key().resource_ref().clone(),
                    self.zone.as_str(),
                    execution_ref,
                    authorization,
                ),
                tpm_state_intent(resource.key().uid(), vm_id.as_str()),
                d2b_provider_device_tpm::SwtpmSettings { log_level },
                d2b_provider_device_tpm::SignedBinaryRef::from_core(
                    d2b_provider_device_tpm::BinaryKind::Swtpm,
                    tpm_opaque_bytes("d2b:tpm-binary/v1", vm_id.as_str()),
                ),
                BrokerCallerRole::AdminUid {
                    uid: self.state.daemon_uid,
                },
                &mut controller,
            )
            .map_err(|_| SharedProviderEffectError::Unavailable);
            if result.is_err() {
                self.tpm_controllers
                    .lock()
                    .map_err(|_| SharedProviderEffectError::Unavailable)?
                    .insert(resource.key().uid().clone(), controller);
                return Err(SharedProviderEffectError::Unavailable);
            }
            let children_cleaned = match self
                .cleanup_binding_children(&runtime_for_children, resource, &context.operation_id)
                .await
            {
                Ok(value) => value,
                Err(error) => {
                    self.tpm_controllers
                        .lock()
                        .map_err(|_| SharedProviderEffectError::Unavailable)?
                        .insert(resource.key().uid().clone(), controller);
                    return Err(error);
                }
            };
            if !children_cleaned {
                self.tpm_controllers
                    .lock()
                    .map_err(|_| SharedProviderEffectError::Unavailable)?
                    .insert(resource.key().uid().clone(), controller);
                return Err(SharedProviderEffectError::Unavailable);
            }
            return Ok(());
        }
        if kind == SharedProviderResourceKind::UsbipService {
            let runtime = self.runtime()?;
            let service_ref = resource.key().resource_ref().to_canonical_string();
            let bindings = runtime
                .committed_resources_of_type(d2b_provider_device_usbip::USB_BINDING_RESOURCE_TYPE)
                .await
                .map_err(|_| SharedProviderEffectError::Unavailable)?;
            if bindings.iter().any(|binding| {
                binding.pointer("/spec/serviceRef").and_then(Value::as_str)
                    == Some(service_ref.as_str())
            }) {
                return Err(SharedProviderEffectError::Unavailable);
            }
            let (zone_uid, opted_in, mut port) =
                self.usbip_service_port(context, resource, &value).await?;
            if !opted_in {
                return Ok(());
            }
            let mut lifecycle = d2b_provider_device_usbip::ServiceLifecycle::new(
                zone_uid.clone(),
                resource.key().uid().clone(),
            );
            lifecycle
                .activate(true, zone_uid, &mut port)
                .map_err(|_| SharedProviderEffectError::Unavailable)?;
            let mut supervisor = d2b_provider_device_usbip::UsbipSupervisor::new(lifecycle);
            supervisor
                .finalize(&mut port)
                .map_err(|_| SharedProviderEffectError::Unavailable)?;
            self.usbip_services
                .lock()
                .map_err(|_| SharedProviderEffectError::Unavailable)?
                .remove(resource.key().uid());
            return Ok(());
        }
        if kind == SharedProviderResourceKind::GpuDevice {
            let admission = self
                .gpu_controllers
                .lock()
                .map_err(|_| SharedProviderEffectError::Unavailable)?
                .get(resource.key().uid())
                .and_then(|controller| controller.admission().cloned())
                .ok_or(SharedProviderEffectError::Unavailable)?;
            let resolver = crate::load_bundle_resolver(&self.state)
                .map_err(|_| SharedProviderEffectError::Unavailable)?;
            let runtime = self.runtime()?;
            let runtime_for_children = Arc::clone(&runtime);
            let opened_devices = self.take_gpu_opened_devices(resource.key().uid())?;
            let mut controller = self
                .gpu_controllers
                .lock()
                .map_err(|_| SharedProviderEffectError::Unavailable)?
                .remove(resource.key().uid())
                .ok_or(SharedProviderEffectError::Unavailable)?;
            let mut port = DaemonGpuLifecyclePort {
                state: Arc::clone(&self.state),
                runtime,
                resolver,
                device_ref: resource.key().resource_ref().clone(),
                device_uid: resource.key().uid().clone(),
                holder_ref: admission.owner().holder_ref().clone(),
                generation: admission.owner().generation(),
                settings: controller.settings().clone(),
                operation_id: context.operation_id.clone(),
                authority_leases: Arc::clone(&self.gpu_authority_leases),
                processes: Arc::clone(&self.gpu_processes),
                opened_devices,
            };
            let result = controller
                .finalize_lifecycle(&mut port)
                .map_err(|_| SharedProviderEffectError::Unavailable);
            if result.is_err() {
                let opened_devices = std::mem::take(&mut port.opened_devices);
                self.retain_gpu_opened_devices(resource.key().uid(), opened_devices)?;
                self.gpu_controllers
                    .lock()
                    .map_err(|_| SharedProviderEffectError::Unavailable)?
                    .insert(resource.key().uid().clone(), controller);
                return Err(SharedProviderEffectError::Unavailable);
            }
            let children_cleaned = match self
                .cleanup_binding_children(&runtime_for_children, resource, &context.operation_id)
                .await
            {
                Ok(value) => value,
                Err(error) => {
                    let opened_devices = std::mem::take(&mut port.opened_devices);
                    self.retain_gpu_opened_devices(resource.key().uid(), opened_devices)?;
                    self.gpu_controllers
                        .lock()
                        .map_err(|_| SharedProviderEffectError::Unavailable)?
                        .insert(resource.key().uid().clone(), controller);
                    return Err(error);
                }
            };
            if !children_cleaned {
                let opened_devices = std::mem::take(&mut port.opened_devices);
                self.retain_gpu_opened_devices(resource.key().uid(), opened_devices)?;
                self.gpu_controllers
                    .lock()
                    .map_err(|_| SharedProviderEffectError::Unavailable)?
                    .insert(resource.key().uid().clone(), controller);
                return Err(SharedProviderEffectError::Unavailable);
            }
            return Ok(());
        }
        if matches!(
            kind,
            SharedProviderResourceKind::UsbipBinding
                | SharedProviderResourceKind::SecurityKeyBinding
                | SharedProviderResourceKind::SecurityKeyService
        ) {
            let runtime = self.runtime()?;
            if kind == SharedProviderResourceKind::SecurityKeyService {
                let service_ref = resource.key().resource_ref().to_canonical_string();
                let bindings = runtime
                    .committed_resources_of_type(
                        d2b_provider_device_security_key::SECURITY_KEY_BINDING_RESOURCE_TYPE,
                    )
                    .await
                    .map_err(|_| SharedProviderEffectError::Unavailable)?;
                if bindings.iter().any(|binding| {
                    binding.pointer("/spec/serviceRef").and_then(Value::as_str)
                        == Some(service_ref.as_str())
                }) {
                    return Err(SharedProviderEffectError::Unavailable);
                }
            }
            if kind == SharedProviderResourceKind::UsbipBinding {
                let service_ref = value
                    .pointer("/spec/serviceRef")
                    .and_then(Value::as_str)
                    .and_then(|value| ResourceRef::parse(value).ok())
                    .ok_or(SharedProviderEffectError::InvalidResource)?;
                let guest_ref = value
                    .pointer("/spec/guestRef")
                    .and_then(Value::as_str)
                    .and_then(|value| ResourceRef::parse(value).ok())
                    .ok_or(SharedProviderEffectError::InvalidResource)?;
                let mut controller = d2b_provider_device_usbip::UsbipBindingController::new(
                    resource.key().resource_ref(),
                    &service_ref,
                    &guest_ref,
                )
                .map_err(|_| SharedProviderEffectError::InvalidResource)?;
                controller.finalize();
            }
            if self
                .cleanup_binding_children(&runtime, resource, &context.operation_id)
                .await?
            {
                return Ok(());
            }
            return Err(SharedProviderEffectError::Unavailable);
        }
        if matches!(
            kind,
            SharedProviderResourceKind::UsbipDevice
                | SharedProviderResourceKind::SecurityKeyDevice
        ) {
            let child_type = if kind == SharedProviderResourceKind::UsbipDevice {
                d2b_provider_device_usbip::USB_SERVICE_RESOURCE_TYPE
            } else {
                d2b_provider_device_security_key::SECURITY_KEY_SERVICE_RESOURCE_TYPE
            };
            let runtime = self.runtime()?;
            let children = runtime
                .committed_resources_of_type(child_type)
                .await
                .map_err(|_| SharedProviderEffectError::Unavailable)?;
            let device_ref = resource.key().resource_ref().to_canonical_string();
            if children.iter().any(|child| {
                child
                    .pointer("/spec/provider/settings/deviceRef")
                    .or_else(|| child.pointer("/spec/backingDeviceRef"))
                    .and_then(Value::as_str)
                    == Some(device_ref.as_str())
                    || child.pointer("/metadata/ownerRef").and_then(Value::as_str)
                        == Some(device_ref.as_str())
            }) {
                return Err(SharedProviderEffectError::Unavailable);
            }
            return Ok(());
        }
        Err(SharedProviderEffectError::Unavailable)
    }
}

/// Shared Runner adapter that delegates to one closed, typed Provider
/// controller rather than the generic Core metadata reconciler.
pub(crate) struct SharedProviderResourceReconciler {
    descriptor: ControllerDescriptor,
    kind: SharedProviderResourceKind,
    effects: Arc<dyn SharedProviderEffectExecutor>,
}

/// Shared Runner reconciler used by the selected Guest runtime Providers.
pub(crate) type GuestRuntimeReconciler = SharedProviderResourceReconciler;
const SHARED_PROVIDER_PROGRESS_REQUEUE_TICKS: u64 = 1_000;

impl SharedProviderResourceReconciler {
    fn new(
        descriptor: ControllerDescriptor,
        kind: SharedProviderResourceKind,
        effects: Arc<dyn SharedProviderEffectExecutor>,
    ) -> Arc<Self> {
        Arc::new(Self {
            descriptor,
            kind,
            effects,
        })
    }

    fn effect_context(&self, context: &ReconcileContext) -> SharedProviderEffectContext {
        SharedProviderEffectContext {
            identity: context.identity().clone(),
            target: context.target().clone(),
            operation_id: context.operation().operation_id().to_owned(),
        }
    }

    fn has_finalizer(&self, resource: &ResourceSnapshot) -> Result<bool, SharedProviderReconcileError> {
        if self.descriptor.finalizers().is_empty() {
            return Ok(true);
        }
        let value = serde_json::from_slice::<Value>(resource.canonical_json())
            .map_err(|_| SharedProviderReconcileError::InvalidResource)?;
        Ok(self.descriptor.finalizers().iter().all(|expected| {
            value
                .pointer("/metadata/finalizers")
                .and_then(Value::as_array)
                .is_some_and(|finalizers| {
                    finalizers
                        .iter()
                        .any(|value| value.as_str() == Some(expected))
                })
        }))
    }

    fn status_candidate(
        resource: &ResourceSnapshot,
        phase: Option<SharedProviderEffectPhase>,
    ) -> Result<Vec<u8>, SharedProviderReconcileError> {
        let mut value = serde_json::from_slice::<Value>(resource.canonical_json())
            .map_err(|_| SharedProviderReconcileError::InvalidResource)?;
        let status = value
            .get_mut("status")
            .and_then(Value::as_object_mut)
            .ok_or(SharedProviderReconcileError::InvalidResource)?;
        if let Some(phase) = phase {
            status.insert(
                "phase".to_owned(),
                Value::String(match phase {
                    SharedProviderEffectPhase::Ready => "Ready".to_owned(),
                    SharedProviderEffectPhase::Pending => "Pending".to_owned(),
                }),
            );
        }
        serde_json::to_vec(status).map_err(|_| SharedProviderReconcileError::InvalidResource)
    }

    fn finalizer_mutation(
        resource: &ResourceSnapshot,
        finalizer: &str,
        add: bool,
    ) -> Result<ResourceMutationBatch, SharedProviderReconcileError> {
        let canonical = finalizer_candidate(resource.canonical_json(), finalizer, add)?;
        let mutation = d2b_core_controller::MutationIntent::new(
            resource.key().resource_ref().clone(),
            Some(resource.key().uid().clone()),
            Some(resource.revision()),
            d2b_core_controller::MutationIntentKind::UpdateFinalizers,
            Some(canonical),
        )
        .map_err(|_| SharedProviderReconcileError::InvalidResource)?;
        ResourceMutationBatch::new(vec![mutation])
            .map_err(|_| SharedProviderReconcileError::InvalidResource)
    }

    fn status_candidate_for_phase(
        &self,
        resource: &ResourceSnapshot,
        phase: SharedProviderEffectPhase,
    ) -> Result<Option<Vec<u8>>, SharedProviderReconcileError> {
        if self.kind == SharedProviderResourceKind::CloudHypervisorGuest {
            // The live CH controller owns its layered Guest status. Do not
            // replace its freshly committed conditions with this Runner's
            // bounded generic projection.
            Ok(None)
        } else {
            let mut status = serde_json::from_slice::<Value>(resource.canonical_json())
                .map_err(|_| SharedProviderReconcileError::InvalidResource)?
                .get("status")
                .cloned()
                .ok_or(SharedProviderReconcileError::InvalidResource)?;
            let status = status
                .as_object_mut()
                .ok_or(SharedProviderReconcileError::InvalidResource)?;
            status.insert(
                "phase".to_owned(),
                Value::String(match phase {
                    SharedProviderEffectPhase::Ready => "Ready",
                    SharedProviderEffectPhase::Pending => "Pending",
                }
                .to_owned()),
            );
            if matches!(
                self.kind,
                SharedProviderResourceKind::QemuMediaGuest
                    | SharedProviderResourceKind::AzureContainerAppsGuest
                    | SharedProviderResourceKind::AzureVirtualMachineGuest
            ) {
                status.insert(
                    "observedGeneration".to_owned(),
                    Value::from(resource.generation().get()),
                );
            }
            serde_json::to_vec(status)
                .map(Some)
                .map_err(|_| SharedProviderReconcileError::InvalidResource)
        }
    }

    #[cfg(test)]
    fn first_pass_for_test(
        &self,
        resource: &ResourceSnapshot,
    ) -> Result<ReconcileResult, SharedProviderReconcileError> {
        let Some(finalizer) = self.descriptor.finalizers().first() else {
            return ReconcileResult::new(
                resource.revision(),
                resource.generation(),
                None,
                None,
                ReconcileDisposition::Pending,
                None,
                None,
                StatusPersistence::NotRequested,
            )
            .map_err(|_| SharedProviderReconcileError::InvalidResource);
        };
        if resource.deleting() || self.has_finalizer(resource)? {
            return Ok(ReconcileResult::converged(
                resource.revision(),
                resource.generation(),
            ));
        }
        ReconcileResult::new(
            resource.revision(),
            resource.generation(),
            Some(Self::finalizer_mutation(resource, finalizer, true)?),
            None,
            ReconcileDisposition::Pending,
            None,
            None,
            StatusPersistence::NotRequested,
        )
        .map_err(|_| SharedProviderReconcileError::InvalidResource)
    }

    #[cfg(test)]
    async fn execute_effect_for_test(
        &self,
        resource: &ResourceSnapshot,
        dependencies: &[DependencySnapshot],
    ) -> Result<SharedProviderEffectPhase, SharedProviderReconcileError> {
        let context = SharedProviderEffectContext {
            identity: self.descriptor.identity().clone(),
            target: resource.key().clone(),
            operation_id: "test-provider-effect".to_owned(),
        };
        self.effects
            .reconcile(self.kind, &context, resource, dependencies)
            .await
            .map_err(SharedProviderReconcileError::Effect)
    }

    #[cfg(test)]
    async fn execute_finalize_for_test(
        &self,
        resource: &ResourceSnapshot,
    ) -> Result<ReconcileResult, SharedProviderReconcileError> {
        let context = SharedProviderEffectContext {
            identity: self.descriptor.identity().clone(),
            target: resource.key().clone(),
            operation_id: "test-provider-finalize".to_owned(),
        };
        let Some(finalizer) = self.descriptor.finalizers().first() else {
            return Ok(ReconcileResult::converged(
                resource.revision(),
                resource.generation(),
            ));
        };
        self.effects
            .finalize(self.kind, &context, resource)
            .await
            .map_err(SharedProviderReconcileError::Effect)?;
        Ok(
            ReconcileResult::new(
                resource.revision(),
                resource.generation(),
                Some(Self::finalizer_mutation(
                    resource,
                    finalizer,
                    false,
                )?),
                None,
                ReconcileDisposition::Pending,
                None,
                None,
                StatusPersistence::NotRequested,
            )
            .map_err(|_| SharedProviderReconcileError::InvalidResource)?,
        )
    }
}

fn finalizer_candidate(
    canonical_json: &[u8],
    finalizer: &str,
    add: bool,
) -> Result<Vec<u8>, SharedProviderReconcileError> {
    let mut value = CanonicalJsonValue::parse(canonical_json)
        .map_err(|_| SharedProviderReconcileError::InvalidResource)?;
    let CanonicalJsonValue::Object(root) = &mut value else {
        return Err(SharedProviderReconcileError::InvalidResource);
    };
    let Some(CanonicalJsonValue::Object(metadata)) = root.get_mut("metadata") else {
        return Err(SharedProviderReconcileError::InvalidResource);
    };
    let Some(CanonicalJsonValue::Array(finalizers)) = metadata.get_mut("finalizers") else {
        return Err(SharedProviderReconcileError::InvalidResource);
    };
    if add {
        if !finalizers
            .iter()
            .any(|value| matches!(value, CanonicalJsonValue::String(value) if value == finalizer))
        {
            finalizers.push(CanonicalJsonValue::String(finalizer.to_owned()));
        }
    } else {
        finalizers.retain(
            |value| !matches!(value, CanonicalJsonValue::String(value) if value == finalizer),
        );
    }
    Ok(value.to_canonical_bytes())
}

fn stored_resource_from_snapshot(resource: &ResourceSnapshot) -> StoredResource {
    StoredResource {
        resource_ref: resource.key().resource_ref().clone(),
        zone: resource.key().zone().clone(),
        uid: resource.key().uid().clone(),
        generation: resource.generation(),
        revision: resource.revision(),
        canonical_json: resource.canonical_json().to_vec(),
        payload_digest: canonical_digest(
            d2b_contracts_resource::v3::RESOURCE_ENVELOPE_DOMAIN_TAG,
            resource.canonical_json(),
        ),
    }
}

fn resource_phase(value: &Value) -> Option<&str> {
    value.pointer("/status/phase").and_then(Value::as_str)
}

fn value_deletion_requested(value: &Value) -> bool {
    value
        .pointer("/metadata/deletionRequestedAt")
        .is_some_and(|value| !value.is_null())
}

fn resource_ref_at(value: &Value, path: &str) -> Result<ResourceRef, SharedProviderEffectError> {
    value
        .pointer(path)
        .and_then(Value::as_str)
        .and_then(|reference| ResourceRef::parse(reference).ok())
        .ok_or(SharedProviderEffectError::InvalidResource)
}

fn shell_pool_spec(value: &Value) -> Result<(), SharedProviderEffectError> {
    if value.pointer("/spec/providerRef").and_then(Value::as_str)
        != Some("Provider/shell-terminal")
    {
        return Err(SharedProviderEffectError::InvalidResource);
    }
    let execution_ref = resource_ref_at(value, "/spec/executionRef")?;
    if !matches!(
        execution_ref.resource_type().as_str(),
        "Host" | "Guest"
    ) {
        return Err(SharedProviderEffectError::InvalidResource);
    }
    if resource_ref_at(value, "/spec/userRef")?.resource_type().as_str() != "User"
        || value
            .pointer("/spec/loginShellRef")
            .and_then(Value::as_str)
            .is_none_or(|shell| !shell.starts_with("artifact://"))
    {
        return Err(SharedProviderEffectError::InvalidResource);
    }
    Ok(())
}

fn shell_execution(
    value: &Value,
) -> Result<(ResourceRef, Option<ResourceRef>), SharedProviderEffectError> {
    if value.pointer("/spec/providerRef").and_then(Value::as_str)
        != Some("Provider/shell-terminal")
    {
        return Err(SharedProviderEffectError::InvalidResource);
    }
    let execution_ref = resource_ref_at(value, "/spec/executionRef")?;
    if !matches!(
        execution_ref.resource_type().as_str(),
        "Host" | "Guest"
    ) {
        return Err(SharedProviderEffectError::InvalidResource);
    }
    let user_ref = value
        .pointer("/spec/userRef")
        .and_then(Value::as_str)
        .map(ResourceRef::parse)
        .transpose()
        .map_err(|_| SharedProviderEffectError::InvalidResource)?;
    if user_ref
        .as_ref()
        .is_some_and(|reference| reference.resource_type().as_str() != "User")
    {
        return Err(SharedProviderEffectError::InvalidResource);
    }
    Ok((execution_ref, user_ref))
}

fn owned_child_intent(
    zone: &ZoneId,
    target: ResourceRef,
    owner: &ResourceRef,
    spec: Value,
    dependencies: impl IntoIterator<Item = ResourceRef>,
) -> Result<d2b_core_controller::OwnedChildIntent, SharedProviderEffectError> {
    let value = json!({
        "apiVersion": "resources.d2bus.org/v3",
        "type": target.resource_type().as_str(),
        "metadata": {
            "name": target.name().as_str(),
            "zone": zone.as_str(),
            "ownerRef": owner.to_canonical_string(),
            "annotations": {},
            "finalizers": [],
            "deletionRequestedAt": null,
            "createdAt": "1970-01-01T00:00:00.000Z",
            "updatedAt": "1970-01-01T00:00:00.000Z",
            "generation": 1,
            "revision": 1,
            "managedBy": "controller"
        },
        "spec": spec,
        "status": {
            "completedAt": null,
            "conditions": [],
            "lastReconciledAt": null,
            "observedGeneration": 0,
            "outcome": null,
            "phase": "Pending",
            "resource": {},
            "startedAt": null,
            "update": {
                "dependencies": {"count": 0, "refs": []},
                "disruption": "None",
                "lastAssessedAt": null,
                "observedGeneration": 0,
                "operationId": null,
                "owned": {"count": 0, "refs": []},
                "preserveState": true,
                "reasons": [],
                "state": "Unknown",
                "targetGeneration": 1
            }
        }
    });
    let bytes = CanonicalJsonValue::parse(
        &serde_json::to_vec(&value).map_err(|_| SharedProviderEffectError::InvalidResource)?,
    )
    .map_err(|_| SharedProviderEffectError::InvalidResource)?
    .to_canonical_bytes();
    let digest = canonical_digest(
        d2b_contracts_resource::v3::RESOURCE_ENVELOPE_DOMAIN_TAG,
        &bytes,
    );
    d2b_core_controller::OwnedChildIntent::new(target, bytes, digest)
        .and_then(|intent| intent.with_dependencies(dependencies))
        .map_err(|_| SharedProviderEffectError::InvalidResource)
}

type SharedCoreControllerSource =
    CoreControllerSource<d2b_resource_api::registered::RedbRegisteredControllerApi>;

enum PreparedCoreRunner {
    Core {
        reconciler: Arc<CoreResourceReconciler>,
        source: Arc<SharedCoreControllerSource>,
        config: RunnerConfig,
        handler: &'static str,
        resource_type: &'static str,
    },
    Provider {
        reconciler: Arc<SharedProviderResourceReconciler>,
        source: Arc<SharedCoreControllerSource>,
        config: RunnerConfig,
        controller_ref: ResourceRef,
        resource_type: String,
    },
}

fn spawn_prepared_core_runner(prepared: PreparedCoreRunner) -> tokio::task::JoinHandle<()> {
    match prepared {
        PreparedCoreRunner::Core {
            reconciler,
            source,
            config,
            handler,
            resource_type,
        } => tokio::spawn(async move {
            let runner = Runner::new(reconciler, source, config);
            match runner.run().await {
                Ok(report) => {
                    tracing::debug!(
                        handler,
                        resource_type,
                        dispatched = report.dispatched,
                        relists = report.relists,
                        "Core resource runner stopped",
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        handler,
                        resource_type,
                        error = %error,
                        "Core resource runner isolated failure",
                    );
                }
            }
        }),
        PreparedCoreRunner::Provider {
            reconciler,
            source,
            config,
            controller_ref,
            resource_type,
        } => tokio::spawn(async move {
            let runner = Runner::new(reconciler, source, config);
            match runner.run().await {
                Ok(report) => {
                    tracing::debug!(
                        controller = %controller_ref,
                        resource_type,
                        dispatched = report.dispatched,
                        relists = report.relists,
                        "Shared Provider resource runner stopped",
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        controller = %controller_ref,
                        resource_type,
                        error = %error,
                        "Shared Provider resource runner isolated failure",
                    );
                }
            }
        }),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SharedProviderReconcileError {
    InvalidResource,
    Effect(SharedProviderEffectError),
}

impl core::fmt::Display for SharedProviderReconcileError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidResource => formatter.write_str("shared-provider-resource-invalid"),
            Self::Effect(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for SharedProviderReconcileError {}

impl ResourceReconciler for SharedProviderResourceReconciler {
    type Error = SharedProviderReconcileError;

    fn describe(
        &self,
    ) -> impl std::future::Future<Output = Result<ControllerDescriptor, Self::Error>> + Send {
        std::future::ready(Ok(self.descriptor.clone()))
    }

    fn validate_spec(
        &self,
        context: &ReconcileContext,
        resource: &ResourceSnapshot,
    ) -> impl std::future::Future<Output = Result<ValidationResult, Self::Error>> + Send {
        let valid = context.identity().zone() == resource.key().zone()
            && resource.key().resource_ref().resource_type().as_str() == self.kind.resource_type()
            && serde_json::from_slice::<Value>(resource.canonical_json())
                .ok()
                .is_some_and(|value| {
                    if matches!(
                        self.kind,
                        SharedProviderResourceKind::DisplayWaylandPolicy
                            | SharedProviderResourceKind::DisplayWaylandSession
                    ) {
                        ResourceEnvelope::from_json(resource.canonical_json()).is_ok()
                    } else {
                        value
                            .pointer("/spec/providerRef")
                            .and_then(Value::as_str)
                            == Some(self.kind.provider_ref())
                    }
                });
        std::future::ready(Ok(if valid {
            ValidationResult::Valid
        } else {
            ValidationResult::Invalid {
                reason: ReconcileReason::InvalidSpec,
            }
        }))
    }

    async fn plan(
        &self,
        _context: &ReconcileContext,
        resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
    ) -> Result<ReconcilePlan, Self::Error> {
        let _ = self.has_finalizer(resource)?;
        ReconcilePlan::new(vec![self.kind.effect_id().to_owned()], false)
            .map_err(|_| SharedProviderReconcileError::InvalidResource)
    }

    fn reconcile(
        &self,
        context: &ReconcileContext,
        resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
        _plan: &ReconcilePlan,
    ) -> impl std::future::Future<Output = Result<ReconcileResult, Self::Error>> + Send {
        let result = (|| {
            context
                .authorize_effect()
                .map_err(|_| SharedProviderReconcileError::Effect(
                    SharedProviderEffectError::Unavailable,
                ))?;
            let finalizer = self.descriptor.finalizers().first();
            if let Some(finalizer) = finalizer
                && !resource.deleting()
                && !self.has_finalizer(resource)?
            {
                return Ok(ReconcileResult::new(
                    resource.revision(),
                    resource.generation(),
                    Some(Self::finalizer_mutation(resource, finalizer, true)?),
                    None,
                    ReconcileDisposition::Pending,
                    None,
                    None,
                    StatusPersistence::NotRequested,
                )
                .map_err(|_| SharedProviderReconcileError::InvalidResource)?);
            }
            if finalizer.is_none() {
                return ReconcileResult::new(
                    resource.revision(),
                    resource.generation(),
                    None,
                    None,
                    ReconcileDisposition::Pending,
                    None,
                    None,
                    StatusPersistence::NotRequested,
                )
                .map_err(|_| SharedProviderReconcileError::InvalidResource);
            }
            if !self.has_finalizer(resource)? {
                return ReconcileResult::new(
                    resource.revision(),
                    resource.generation(),
                    None,
                    Some(Self::status_candidate(resource, Some(
                        SharedProviderEffectPhase::Pending,
                    ))?),
                    ReconcileDisposition::Pending,
                    None,
                    None,
                    StatusPersistence::Pending,
                )
                .map_err(|_| SharedProviderReconcileError::InvalidResource);
            }
            Ok(ReconcileResult::converged(
                resource.revision(),
                resource.generation(),
            ))
        })();
        std::future::ready(result)
    }

    async fn execute_effect(
        &self,
        context: &ReconcileContext,
        resource: &ResourceSnapshot,
        dependencies: &[DependencySnapshot],
        _plan: &ReconcilePlan,
    ) -> Result<ReconcileResult, Self::Error> {
        let _permit = context
            .authorize_effect()
            .map_err(|_| SharedProviderReconcileError::Effect(
                SharedProviderEffectError::Unavailable,
            ))?;
        let result = self
            .effects
            .reconcile_result(
                self.kind,
                &self.effect_context(context),
                resource,
                dependencies,
            )
            .await
            .map_err(SharedProviderReconcileError::Effect)?;
        let status = (!result.child_mutated)
            .then(|| self.status_candidate_for_phase(resource, result.phase))
            .transpose()?
            .flatten();
        let (disposition, next_tick) = if self.kind.resource_type() == "Guest"
            && result.phase == SharedProviderEffectPhase::Pending
        {
            (
                ReconcileDisposition::RequeueAt,
                Some(context.now_tick().saturating_add(
                    SHARED_PROVIDER_PROGRESS_REQUEUE_TICKS,
                )),
            )
        } else {
            (ReconcileDisposition::Pending, None)
        };
        let status_persistence = if status.is_some() {
            StatusPersistence::Pending
        } else {
            StatusPersistence::NotRequested
        };
        Ok(ReconcileResult::new(
            resource.revision(),
            resource.generation(),
            None,
            status,
            disposition,
            next_tick,
            None,
            status_persistence,
        )
        .map_err(|_| SharedProviderReconcileError::InvalidResource)?)
    }

    async fn observe(
        &self,
        context: &ReconcileContext,
        resource: &ResourceSnapshot,
    ) -> Result<ObservationResult, Self::Error> {
        let _permit = context
            .authorize_effect()
            .map_err(|_| SharedProviderReconcileError::Effect(
                SharedProviderEffectError::Unavailable,
            ))?;
        if !self.has_finalizer(resource)? {
            return Ok(ObservationResult::new(
                ReconcileResult::new(
                    resource.revision(),
                    resource.generation(),
                    None,
                    Some(Self::status_candidate(
                        resource,
                        Some(SharedProviderEffectPhase::Pending),
                    )?),
                    ReconcileDisposition::Pending,
                    None,
                    None,
                    StatusPersistence::Pending,
                )
                .map_err(|_| SharedProviderReconcileError::InvalidResource)?,
            ));
        }
        let result = self
            .effects
            .observe_result(
                self.kind,
                &self.effect_context(context),
                resource,
            )
            .await
            .map_err(SharedProviderReconcileError::Effect)?;
        let status = (!result.child_mutated)
            .then(|| self.status_candidate_for_phase(resource, result.phase))
            .transpose()?
            .flatten();
        let (disposition, next_tick) = if self.kind.resource_type() == "Guest"
            && result.phase == SharedProviderEffectPhase::Pending
        {
            (
                ReconcileDisposition::RequeueAt,
                Some(context.now_tick().saturating_add(
                    SHARED_PROVIDER_PROGRESS_REQUEUE_TICKS,
                )),
            )
        } else {
            (ReconcileDisposition::Pending, None)
        };
        let status_persistence = if status.is_some() {
            StatusPersistence::Pending
        } else {
            StatusPersistence::NotRequested
        };
        Ok(ObservationResult::new(
            ReconcileResult::new(
                resource.revision(),
                resource.generation(),
                None,
                status,
                disposition,
                next_tick,
                None,
                status_persistence,
            )
            .map_err(|_| SharedProviderReconcileError::InvalidResource)?,
        ))
    }

    fn finalize(
        &self,
        _context: &ReconcileContext,
        deleting_resource: &ResourceSnapshot,
    ) -> impl std::future::Future<Output = Result<FinalizeResult, Self::Error>> + Send {
        std::future::ready(Ok(FinalizeResult::new(ReconcileResult::converged(
            deleting_resource.revision(),
            deleting_resource.generation(),
        ))))
    }

    fn prepare_finalize(
        &self,
        context: &ReconcileContext,
        deleting_resource: &ResourceSnapshot,
    ) -> impl std::future::Future<Output = Result<ReconcileResult, Self::Error>> + Send {
        let result = context
            .authorize_effect()
            .map(|_| ReconcileResult::converged(
                deleting_resource.revision(),
                deleting_resource.generation(),
            ))
            .map_err(|_| SharedProviderReconcileError::Effect(
                SharedProviderEffectError::Unavailable,
            ));
        std::future::ready(result)
    }

    async fn execute_finalize(
        &self,
        context: &ReconcileContext,
        deleting_resource: &ResourceSnapshot,
    ) -> Result<ReconcileResult, Self::Error> {
        let _permit = context
            .authorize_effect()
            .map_err(|_| SharedProviderReconcileError::Effect(
                SharedProviderEffectError::Unavailable,
            ))?;
        if !self.has_finalizer(deleting_resource)? {
            return Ok(ReconcileResult::converged(
                deleting_resource.revision(),
                deleting_resource.generation(),
            ));
        }
        let finalizer = self.descriptor.finalizers().first().cloned();
        self.effects
            .finalize(
                self.kind,
                &self.effect_context(context),
                deleting_resource,
            )
            .await
            .map_err(SharedProviderReconcileError::Effect)?;
        let Some(finalizer) = finalizer else {
            return Ok(ReconcileResult::converged(
                deleting_resource.revision(),
                deleting_resource.generation(),
            ));
        };
        Ok(
            ReconcileResult::new(
                deleting_resource.revision(),
                deleting_resource.generation(),
                Some(Self::finalizer_mutation(
                    deleting_resource,
                    &finalizer,
                    false,
                )?),
                None,
                ReconcileDisposition::Pending,
                None,
                None,
                StatusPersistence::NotRequested,
            )
            .map_err(|_| SharedProviderReconcileError::InvalidResource)?,
        )
    }

    fn health(
        &self,
    ) -> impl std::future::Future<Output = Result<d2b_core_controller::ControllerHealth, Self::Error>>
        + Send {
        std::future::ready(Ok(d2b_core_controller::ControllerHealth::Healthy))
    }

    fn drain(
        &self,
        _deadline_tick: u64,
    ) -> impl std::future::Future<Output = Result<DrainResult, Self::Error>> + Send {
        std::future::ready(Ok(DrainResult::Drained))
    }

    fn assess_update(
        &self,
        _context: &ReconcileContext,
        resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
    ) -> impl std::future::Future<Output = Result<UpdateAssessment, Self::Error>> + Send {
        let state = serde_json::from_slice::<Value>(resource.canonical_json())
            .ok()
            .map(|value| {
                let observed_generation = value
                    .pointer("/status/observedGeneration")
                    .and_then(Value::as_u64);
                let initial_pending = observed_generation == Some(0)
                    && value.pointer("/status/phase").and_then(Value::as_str)
                        == Some("Pending");
                if observed_generation == Some(resource.generation().get()) || initial_pending {
                    UpdateAssessmentState::Current
                } else {
                    UpdateAssessmentState::UpgradeRequired
                }
            })
            .unwrap_or(UpdateAssessmentState::UpgradeRequired);
        std::future::ready(
            UpdateAssessment::new(state, Vec::new(), true)
                .map_err(|_| SharedProviderReconcileError::InvalidResource),
        )
    }

    fn plan_upgrade(
        &self,
        _context: &ReconcileContext,
        resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
    ) -> impl std::future::Future<Output = Result<UpgradePlan, Self::Error>> + Send {
        std::future::ready(
            UpgradePlan::new(
                DisruptionClass::Restart,
                true,
                vec![UpgradeStage::Restart(resource.key().resource_ref().clone())],
            )
            .map_err(|_| SharedProviderReconcileError::InvalidResource),
        )
    }

    async fn execute_upgrade(
        &self,
        context: &ReconcileContext,
        resource: &ResourceSnapshot,
        dependencies: &[DependencySnapshot],
        _plan: &UpgradePlan,
    ) -> Result<ReconcileResult, Self::Error> {
        let _permit = context
            .authorize_effect()
            .map_err(|_| SharedProviderReconcileError::Effect(
                SharedProviderEffectError::Unavailable,
            ))?;
        if !self.has_finalizer(resource)? {
            return Ok(
                ReconcileResult::new(
                    resource.revision(),
                    resource.generation(),
                    None,
                    Some(Self::status_candidate(
                        resource,
                        Some(SharedProviderEffectPhase::Pending),
                    )?),
                    ReconcileDisposition::Pending,
                    None,
                    None,
                    StatusPersistence::Pending,
                )
                .map_err(|_| SharedProviderReconcileError::InvalidResource)?,
            );
        }
        let result = self
            .effects
            .upgrade_result(
                self.kind,
                &self.effect_context(context),
                resource,
                dependencies,
            )
            .await
            .map_err(SharedProviderReconcileError::Effect)?;
        let status = (!result.child_mutated)
            .then(|| self.status_candidate_for_phase(resource, result.phase))
            .transpose()?
            .flatten();
        let (disposition, next_tick) = if self.kind.resource_type() == "Guest"
            && result.phase == SharedProviderEffectPhase::Pending
        {
            (
                ReconcileDisposition::RequeueAt,
                Some(context.now_tick().saturating_add(
                    SHARED_PROVIDER_PROGRESS_REQUEUE_TICKS,
                )),
            )
        } else {
            (ReconcileDisposition::Pending, None)
        };
        let status_persistence = if status.is_some() {
            StatusPersistence::Pending
        } else {
            StatusPersistence::NotRequested
        };
        Ok(
            ReconcileResult::new(
                resource.revision(),
                resource.generation(),
                None,
                status,
                disposition,
                next_tick,
                None,
                status_persistence,
            )
            .map_err(|_| SharedProviderReconcileError::InvalidResource)?,
        )
    }
}

/// Compose the exact U8 Provider descriptors used by the production shared
/// Runner. The provider-generation map is supplied by the authoritative
/// Provider rows; no generation or assignment epoch is guessed.
pub fn compose_shared_provider_runner_descriptors(
    registrations: impl IntoIterator<Item = SharedProviderRunnerRegistration>,
    zone: ZoneId,
    controller_generation: ControllerGeneration,
    provider_generations: &BTreeMap<ResourceRef, ResourceGeneration>,
    _session_generation: ReconnectGeneration,
) -> Result<
    Vec<(SharedProviderRunnerRegistration, ControllerDescriptor)>,
    ResourceRuntimeError,
> {
    registrations
        .into_iter()
        .map(|registration| {
            if !registration.legacy_scheduler_disabled
                || !registration.watched_configuration_is_dependency
                || !(30_000..=300_000).contains(&registration.repair_interval_ticks)
            {
                return Err(ResourceRuntimeError::HandlerNotReady);
            }
            let provider_ref = ResourceRef::parse(registration.provider_ref)
                .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
            let provider_generation = provider_generations
                .get(&provider_ref)
                .copied()
                .ok_or(ResourceRuntimeError::HandlerNotReady)?;
            let resource_type = ResourceTypeName::parse(registration.resource_type.to_owned())
                .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
            let controller_ref = ResourceRef::parse(registration.controller_ref)
                .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
            let identity = ControllerIdentity::new(
                zone.clone(),
                controller_ref.clone(),
                controller_generation,
                provider_ref,
                provider_generation,
                controller_ref,
                ResourceRef::parse(CORE_CONTROLLER_HOST_REF)
                    .map_err(|_| ResourceRuntimeError::HandlerNotReady)?,
                None,
            )
            .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
            let resource = ResourceRegistration::new(
                resource_type.clone(),
                vec![1],
                5_000,
                3,
            )
            .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
            let provider_selector = if registration.resource_type.starts_with("display-wayland.")
            {
                None
            } else {
                Some(registration.provider_ref.to_owned())
            };
            let mut selectors = vec![
                ControllerSelector::new(
                    resource_type.clone(),
                    SelectorField::Spec,
                    provider_selector,
                )
                .map_err(|_| ResourceRuntimeError::HandlerNotReady)?,
            ];
            for field in [
                SelectorField::Status,
                SelectorField::Metadata,
                SelectorField::Finalizers,
                SelectorField::Deletion,
            ] {
                selectors.push(
                    ControllerSelector::new(resource_type.clone(), field, None)
                        .map_err(|_| ResourceRuntimeError::HandlerNotReady)?,
                );
            }
            let dependency_selectors = if registration.resource_type == "Guest" {
                [
                    "Provider",
                    "Process",
                    "EphemeralProcess",
                    "Endpoint",
                    "Volume",
                    "Network",
                    "Device",
                    "Credential",
                ]
                .into_iter()
                .map(|resource_type| {
                    ControllerSelector::new(
                        ResourceTypeName::parse(resource_type.to_owned())
                            .map_err(|_| ResourceRuntimeError::HandlerNotReady)?,
                        SelectorField::Metadata,
                        None,
                    )
                    .map_err(|_| ResourceRuntimeError::HandlerNotReady)
                })
                .collect::<Result<Vec<_>, _>>()?
            } else {
                Vec::new()
            };
            let execution = ControllerExecutionPolicy::new(
                8,
                4,
                256,
                8,
                256,
                ResyncPolicy::new(
                    Some(registration.repair_interval_ticks),
                    registration.repair_interval_ticks,
                )
                .map_err(|_| ResourceRuntimeError::HandlerNotReady)?,
            )
            .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
            let mut verbs = vec![
                ControllerVerb::ReadSpec,
                ControllerVerb::ReadStatus,
                ControllerVerb::WriteStatus,
                ControllerVerb::AddFinalizer,
                ControllerVerb::RemoveFinalizer,
            ];
            if registration.resource_type == "Guest" {
                verbs.push(ControllerVerb::WriteSpec);
            }
            let descriptor = ControllerDescriptor::new(
                identity,
                vec![resource],
                vec!["resource-api".to_owned()],
                vec!["system".to_owned()],
                verbs,
                selectors,
                dependency_selectors,
                true,
                if registration.finalizer.is_empty() {
                    Vec::new()
                } else {
                    vec![registration.finalizer.to_owned()]
                },
                vec!["d2b.resource.v3".to_owned()],
                vec!["resources.d2bus.org/v3".to_owned()],
                execution,
            )
            .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
            Ok((registration, descriptor))
        })
        .collect()
}

#[derive(Clone)]
struct CoreAssignmentAuthority {
    provider_generation: ResourceGeneration,
    controller_generation: ControllerGeneration,
    session_generation: ReconnectGeneration,
    controller_role: ResourceRef,
    target: ResourceRef,
    epoch: u64,
}

async fn abort_u12_runner_tasks(tasks: &mut Vec<tokio::task::JoinHandle<()>>) {
    for task in tasks.drain(..) {
        task.abort();
        let _ = task.await;
    }
}

async fn u9_provider_generations(
    runtime: &ZoneResourceRuntime,
) -> Result<
    (
        Vec<SharedProviderRunnerRegistration>,
        BTreeMap<ResourceRef, ResourceGeneration>,
    ),
    ResourceRuntimeError,
> {
    let mut generations = BTreeMap::new();
    let mut active = Vec::new();
    let mut seen = BTreeSet::new();
    for registration in U9_SHARED_PROVIDER_RUNNERS {
        if !seen.insert(registration.provider_ref) {
            active.extend(
                U9_SHARED_PROVIDER_RUNNERS
                    .iter()
                    .copied()
                    .filter(|candidate| {
                        candidate.provider_ref == registration.provider_ref
                            && candidate.resource_type == registration.resource_type
                    }),
            );
            continue;
        }
        let provider_ref = ResourceRef::parse(registration.provider_ref)
            .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
        match runtime
            .store
            .get(StoreGetRequest {
                operation: StoreOperationContext {
                    operation_id: "u9-provider-generation".to_owned(),
                    idempotency_key: None,
                    correlation_id: "u9-provider-generation".to_owned(),
                    trace_id: None,
                    deadline_ms: 10_000,
                },
                zone: runtime.zone.clone(),
                target: provider_ref.clone(),
                expected_uid: None,
                projection: StoreProjection::MetadataOnly,
            })
            .await
        {
            Ok(provider) if provider.zone == runtime.zone && provider.generation.get() > 0 => {
                generations.insert(provider_ref, provider.generation);
                active.extend(
                    U9_SHARED_PROVIDER_RUNNERS
                        .iter()
                        .copied()
                        .filter(|candidate| candidate.provider_ref == registration.provider_ref),
                );
            }
            Err(error) if error.kind() == StoreErrorKind::ResourceNotFound => {
                let owned_resource = runtime
                    .committed_resources_of_type(registration.resource_type)
                    .await?
                    .into_iter()
                    .any(|resource| {
                        resource
                            .pointer("/spec/providerRef")
                            .and_then(Value::as_str)
                            == Some(registration.provider_ref)
                            || registration.resource_type.starts_with("display-wayland.")
                    });
                if owned_resource {
                    return Err(ResourceRuntimeError::ProviderPathUnavailable);
                }
            }
            Err(_) => return Err(ResourceRuntimeError::StoreReadFailed),
            _ => return Err(ResourceRuntimeError::HandlerNotReady),
        }
    }
    active.sort_by_key(|registration| {
        (
            registration.provider_ref,
            registration.resource_type,
            registration.controller_ref,
        )
    });
    active.dedup_by_key(|registration| {
        (
            registration.provider_ref,
            registration.resource_type,
            registration.controller_ref,
        )
    });
    Ok((active, generations))
}

fn u12_provider_missing_with_resources(resources_present: bool) -> bool {
    resources_present
}

fn validate_observability_environment() -> Result<(), ResourceRuntimeError> {
    d2b_provider_observability_otel::reject_process_environment_credential_chain()
        .map_err(|_| ResourceRuntimeError::ProviderPathUnavailable)
}

#[cfg(test)]
fn validate_observability_environment_keys(
    keys: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<(), ResourceRuntimeError> {
    d2b_provider_observability_otel::reject_ambient_credential_chain(keys)
        .map_err(|_| ResourceRuntimeError::ProviderPathUnavailable)
}

fn u12_runner_readiness(required: bool, task_count: usize, any_finished: bool) -> bool {
    !required || (task_count != 0 && !any_finished)
}

#[derive(Clone)]
pub(crate) struct CommittedInteractionProviderConfiguration {
    clipboard: Option<CommittedClipboardProviderConfiguration>,
    notification: Option<CommittedNotificationProviderConfiguration>,
}

#[derive(Clone)]
pub(crate) struct CommittedInteractionIdentity {
    zone: ZoneId,
    wayland_session_ref: ResourceRef,
    wayland_session_uid: ResourceUid,
    subject_ref: ResourceRef,
    subject_uid: ResourceUid,
    host_execution_ref: ResourceRef,
    user_ref: ResourceRef,
    allowed_guest_sources: BTreeMap<ResourceRef, ResourceUid>,
    display_provider_generation: ResourceGeneration,
    clipboard_provider_generation: Option<ResourceGeneration>,
    clipboard_provider_uid: Option<ResourceUid>,
    notification_provider_generation: Option<ResourceGeneration>,
    notification_provider_uid: Option<ResourceUid>,
}

impl CommittedInteractionIdentity {
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_test(
        zone: ZoneId,
        subject_ref: ResourceRef,
        subject_uid: ResourceUid,
        host_execution_ref: ResourceRef,
        user_ref: ResourceRef,
        allowed_guest_sources: BTreeMap<ResourceRef, ResourceUid>,
        display_provider_generation: ResourceGeneration,
        clipboard_provider_generation: Option<ResourceGeneration>,
        clipboard_provider_uid: Option<ResourceUid>,
        notification_provider_generation: Option<ResourceGeneration>,
        notification_provider_uid: Option<ResourceUid>,
    ) -> Self {
        Self {
            zone,
            wayland_session_ref: ResourceRef::parse(
                "display-wayland.d2bus.org.WaylandSession/display-wayland",
            )
            .expect("fixed test WaylandSession reference"),
            wayland_session_uid: ResourceUid::parse("33333333-3333-4333-8333-333333333333")
                .expect("fixed test WaylandSession UID"),
            subject_ref,
            subject_uid,
            host_execution_ref,
            user_ref,
            allowed_guest_sources,
            display_provider_generation,
            clipboard_provider_generation,
            clipboard_provider_uid,
            notification_provider_generation,
            notification_provider_uid,
        }
    }

    pub(crate) fn seal_interaction_subject_install(
        &self,
        issuer: CommittedInteractionSubjectIssuer,
        expected_peer_uid: u32,
    ) -> d2b_session::Result<CommittedInteractionSubjectInstall> {
        issuer.seal(
            self.zone.clone(),
            self.subject_ref.clone(),
            self.subject_uid.clone(),
            expected_peer_uid,
            self.host_execution_ref.clone(),
            self.display_provider_generation,
            self.clipboard_provider_generation,
            self.notification_provider_generation,
            self.clipboard_provider_uid.clone(),
            self.notification_provider_uid.clone(),
        )
    }

    pub(crate) const fn zone(&self) -> &ZoneId {
        &self.zone
    }

    pub(crate) fn wayland_session_ref(&self) -> &ResourceRef {
        &self.wayland_session_ref
    }

    pub(crate) fn wayland_session_uid(&self) -> &ResourceUid {
        &self.wayland_session_uid
    }

    pub(crate) fn subject_ref(&self) -> &ResourceRef {
        &self.subject_ref
    }

    pub(crate) fn subject_uid(&self) -> &ResourceUid {
        &self.subject_uid
    }

    pub(crate) fn host_execution_ref(&self) -> &ResourceRef {
        &self.host_execution_ref
    }

    pub(crate) fn user_ref(&self) -> &ResourceRef {
        &self.user_ref
    }

    pub(crate) fn allowed_guest_sources(&self) -> &BTreeMap<ResourceRef, ResourceUid> {
        &self.allowed_guest_sources
    }

    pub(crate) const fn display_provider_generation(&self) -> ResourceGeneration {
        self.display_provider_generation
    }

    pub(crate) fn clipboard_provider_uid(&self) -> Option<&ResourceUid> {
        self.clipboard_provider_uid.as_ref()
    }

    pub(crate) fn notification_provider_uid(&self) -> Option<&ResourceUid> {
        self.notification_provider_uid.as_ref()
    }
}

impl CommittedInteractionProviderConfiguration {
    pub(crate) fn clipboard(&self) -> Option<&CommittedClipboardProviderConfiguration> {
        self.clipboard.as_ref()
    }

    pub(crate) fn notification(&self) -> Option<&CommittedNotificationProviderConfiguration> {
        self.notification.as_ref()
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.clipboard
            .as_ref()
            .is_none_or(|config| config.is_integrity_bound())
            && self
                .notification
                .as_ref()
                .is_none_or(|config| config.is_integrity_bound())
    }
}

impl core::fmt::Debug for CommittedInteractionProviderConfiguration {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("CommittedInteractionProviderConfiguration(<redacted>)")
    }
}

#[derive(Clone)]
pub(crate) struct CommittedClipboardProviderConfiguration {
    policy: ClipboardPolicy,
    audit_capacity: usize,
    host_execution_ref: ResourceRef,
    host_user_ref: ResourceRef,
    display_wayland_ref: ResourceRef,
    guest_sources: BTreeSet<ResourceRef>,
    resource_uid: ResourceUid,
    resource_generation: ResourceGeneration,
    resource_revision: ZoneRevision,
    provenance_digest: String,
}

impl CommittedClipboardProviderConfiguration {
    pub(crate) fn policy(&self) -> ClipboardPolicy {
        self.policy.clone()
    }

    pub(crate) const fn audit_capacity(&self) -> usize {
        self.audit_capacity
    }

    pub(crate) fn resource_uid(&self) -> &ResourceUid {
        &self.resource_uid
    }

    pub(crate) fn guest_sources(&self) -> impl Iterator<Item = &ResourceRef> {
        self.guest_sources.iter()
    }

    #[cfg(test)]
    pub(crate) fn allows_guest_source(&self, source: &ResourceRef) -> bool {
        self.guest_sources.contains(source)
    }

    pub(crate) fn matches_display(
        &self,
        display: &d2b_provider_clipboard_wayland::DisplayDependencyEvidence,
    ) -> bool {
        display.host_execution_ref() == &self.host_execution_ref
            && display.user_ref() == &self.host_user_ref
            && display.provider_ref() == &self.display_wayland_ref
    }

    fn is_integrity_bound(&self) -> bool {
        committed_resource_is_integrity_bound(
            &self.resource_uid,
            self.resource_generation,
            self.resource_revision,
            &self.provenance_digest,
        )
    }
}

impl core::fmt::Debug for CommittedClipboardProviderConfiguration {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CommittedClipboardProviderConfiguration")
            .field("guest_source_count", &self.guest_sources.len())
            .field("resource_generation", &self.resource_generation)
            .field("resource_revision", &self.resource_revision)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub(crate) struct CommittedNotificationProviderConfiguration {
    config: NotificationProviderConfig,
    host_execution_ref: ResourceRef,
    resource_uid: ResourceUid,
    resource_generation: ResourceGeneration,
    resource_revision: ZoneRevision,
    provenance_digest: String,
}

impl CommittedNotificationProviderConfiguration {
    pub(crate) fn config(&self) -> NotificationProviderConfig {
        self.config.clone()
    }

    pub(crate) fn observer_user_ref(&self) -> &ResourceRef {
        self.config
            .host_user_ref()
            .expect("committed notification configuration always binds a host User")
    }

    pub(crate) fn resource_uid(&self) -> &ResourceUid {
        &self.resource_uid
    }

    pub(crate) fn guest_sources(&self) -> impl Iterator<Item = &ResourceRef> {
        self.config
            .guest_sources()
            .iter()
            .map(|source| source.source_ref())
    }

    fn is_integrity_bound(&self) -> bool {
        committed_resource_is_integrity_bound(
            &self.resource_uid,
            self.resource_generation,
            self.resource_revision,
            &self.provenance_digest,
        )
    }
}

fn committed_resource_is_integrity_bound(
    uid: &ResourceUid,
    generation: ResourceGeneration,
    revision: ZoneRevision,
    digest: &str,
) -> bool {
    !uid.as_str().is_empty()
        && generation.get() > 0
        && revision.get() > 0
        && digest.starts_with("sha256:")
}

impl core::fmt::Debug for CommittedNotificationProviderConfiguration {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CommittedNotificationProviderConfiguration")
            .field("resource_generation", &self.resource_generation)
            .field("resource_revision", &self.resource_revision)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClipboardProviderConfigWire {
    controller_execution_ref: ResourceRef,
    host_execution_ref: ResourceRef,
    host_user_ref: ResourceRef,
    display_wayland_ref: ResourceRef,
    guest_sources: Vec<ClipboardGuestSourceWire>,
    #[serde(default)]
    caps: ClipboardCapsWire,
    #[serde(default)]
    policy: ClipboardPolicyWire,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClipboardGuestSourceWire {
    guest_ref: ResourceRef,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClipboardCapsWire {
    #[serde(default = "default_clipboard_history_entries")]
    max_history_entries: usize,
    #[serde(default = "default_clipboard_item_bytes")]
    max_item_bytes: usize,
    #[serde(default = "default_clipboard_total_bytes")]
    max_total_bytes: usize,
    #[serde(default = "default_clipboard_concurrent_fds")]
    max_concurrent_fds: usize,
    #[serde(default = "default_clipboard_guest_rate")]
    max_guest_rate_per_min: u32,
    #[serde(default = "default_clipboard_fd_timeout")]
    fd_write_timeout_seconds: u64,
}

impl Default for ClipboardCapsWire {
    fn default() -> Self {
        Self {
            max_history_entries: default_clipboard_history_entries(),
            max_item_bytes: default_clipboard_item_bytes(),
            max_total_bytes: default_clipboard_total_bytes(),
            max_concurrent_fds: default_clipboard_concurrent_fds(),
            max_guest_rate_per_min: default_clipboard_guest_rate(),
            fd_write_timeout_seconds: default_clipboard_fd_timeout(),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClipboardPolicyWire {
    #[serde(default = "default_true")]
    allow_host_capture: bool,
    #[serde(default = "default_true")]
    allow_guest_capture: bool,
    #[serde(default = "default_true")]
    require_picker_for_paste: bool,
    #[serde(default = "default_true")]
    suppress_echo: bool,
    #[serde(default)]
    cross_zone: ClipboardCrossZoneWire,
}

impl Default for ClipboardPolicyWire {
    fn default() -> Self {
        Self {
            allow_host_capture: true,
            allow_guest_capture: true,
            require_picker_for_paste: true,
            suppress_echo: true,
            cross_zone: ClipboardCrossZoneWire::default(),
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClipboardCrossZoneWire {
    #[serde(default)]
    enable: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NotificationProviderConfigWire {
    controller_execution_ref: ResourceRef,
    host_execution_ref: ResourceRef,
    host_user_ref: ResourceRef,
    display_wayland_ref: ResourceRef,
    guest_sources: Vec<NotificationGuestSourceWire>,
    #[serde(default = "default_notification_pending")]
    max_pending_notifications: usize,
    #[serde(default = "default_notification_nonce_ttl")]
    action_nonce_ttl_secs: u64,
    #[serde(default = "default_notification_nonce_store")]
    action_nonce_store_size: usize,
    #[serde(default = "default_notification_ack_timeout")]
    acknowledge_timeout_secs: u64,
    #[serde(default = "default_true")]
    dbus_sink_enabled: bool,
    #[serde(default = "default_true")]
    observer_enabled: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NotificationGuestSourceWire {
    guest_ref: ResourceRef,
    categories: Vec<Category>,
}

const fn default_true() -> bool {
    true
}

const fn default_clipboard_history_entries() -> usize {
    20
}

const fn default_clipboard_item_bytes() -> usize {
    8 * 1024 * 1024
}

const fn default_clipboard_total_bytes() -> usize {
    64 * 1024 * 1024
}

const fn default_clipboard_concurrent_fds() -> usize {
    32
}

const fn default_clipboard_guest_rate() -> u32 {
    60
}

const fn default_clipboard_fd_timeout() -> u64 {
    30
}

const fn default_notification_pending() -> usize {
    64
}

const fn default_notification_nonce_ttl() -> u64 {
    120
}

const fn default_notification_nonce_store() -> usize {
    256
}

const fn default_notification_ack_timeout() -> u64 {
    3_600
}

fn generation_publication_operation_id(set_generation: &ResourceBundleGenerationId) -> String {
    format!(
        "{ZONE_GENERATION_PUBLICATION_OPERATION_PREFIX}{}",
        set_generation.as_str()
    )
}

fn generation_publication_payload(
    set_generation: &ResourceBundleGenerationId,
    binding_digest: &str,
    generations: &BTreeMap<ZoneId, ResourceBundleGenerationId>,
) -> Result<Vec<u8>, ResourceRuntimeError> {
    let generation_set = generations
        .iter()
        .map(|(zone, generation)| (zone.as_str().to_owned(), generation.as_str().to_owned()))
        .collect::<BTreeMap<_, _>>();
    serde_json::to_vec(&json!({
        "claimDigest": set_generation.as_str(),
        "storeBindingDigest": binding_digest,
        "publication": "zone-resource-plane",
        "generationSet": generation_set,
        "state": "pending"
    }))
    .map_err(|_| ResourceRuntimeError::HandlerNotReady)
}

fn generation_publication_payload_matches(
    payload: &[u8],
    set_generation: &ResourceBundleGenerationId,
    binding_digest: &str,
    generations: &BTreeMap<ZoneId, ResourceBundleGenerationId>,
) -> bool {
    let Ok(value) = serde_json::from_slice::<Value>(payload) else {
        return false;
    };
    let expected_generation_set = generations
        .iter()
        .map(|(zone, generation)| (zone.as_str().to_owned(), generation.as_str().to_owned()))
        .collect::<BTreeMap<_, _>>();
    value.get("claimDigest").and_then(Value::as_str) == Some(set_generation.as_str())
        && value.get("storeBindingDigest").and_then(Value::as_str) == Some(binding_digest)
        && value.get("publication").and_then(Value::as_str) == Some("zone-resource-plane")
        && value.get("generationSet") == serde_json::to_value(expected_generation_set).ok().as_ref()
}

struct ControllerSession {
    context: crate::process_provider_runtime::ControllerBootstrapContext,
    binding: ControllerSessionBinding,
    ingress: BusIngress,
    driver: SessionDriverHandle,
    resource_client: Arc<ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>>,
    service_task: tokio::task::JoinHandle<Result<(), SessionServerError>>,
    assignments: BTreeMap<ResourceUid, ResourceClientLease>,
    assignment_stream_open: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControllerAssignmentRefreshError {
    Retryable,
    Failed(ResourceRuntimeError),
}

#[derive(Debug, PartialEq, Eq)]
enum ControllerAssignmentRefreshAction<'a> {
    Retryable {
        context: &'a crate::process_provider_runtime::ControllerBootstrapContext,
    },
    Failed {
        context: &'a crate::process_provider_runtime::ControllerBootstrapContext,
        error: ResourceRuntimeError,
    },
}

#[derive(Clone)]
struct ControllerSessionCoordinator {
    zone: ZoneId,
    bundle_resource_types: Vec<ResourceTypeName>,
    store: Arc<RedbResourceStore>,
    api: Arc<ResourceService<RedbBackend>>,
    authorizer: Arc<NativeAuthorizer>,
    authorization_state: Arc<Mutex<Option<AuthorizationState>>>,
    registrar: Arc<Mutex<Option<ZoneRegistrar>>>,
    assignments: AssignmentRegistry,
    controller_sessions: Arc<Mutex<BTreeMap<ResourceRef, ControllerSession>>>,
    controller_session_lock: Arc<tokio::sync::Mutex<()>>,
}

type CloudHypervisorResourceClient = ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>;

/// Authenticated daemon-side Resource API adapter for the Cloud Hypervisor
/// controller. The adapter owns no store or broker capability in the
/// controller crate; those remain behind this d2bd composition seam.
struct CloudHypervisorResourceSession {
    client: Arc<CloudHypervisorResourceClient>,
    mutation_client: Arc<CloudHypervisorResourceClient>,
    providers: Arc<crate::process_provider_runtime::ProductionProcessProviders>,
    guest_sessions: Arc<
        tokio::sync::Mutex<
            std::collections::HashMap<
                crate::GuestComponentSessionKey,
                Arc<d2bd_runtime::guest_component_session::GuestComponentSessionClient>,
            >,
        >,
    >,
    closed_guest_sessions: Arc<tokio::sync::Mutex<BTreeSet<crate::GuestComponentSessionKey>>>,
    zone: ZoneId,
    zone_uid: ResourceUid,
    policy_revision: u64,
    provider_ref: ResourceRef,
    execution_ref: ResourceRef,
    descriptor: VerifiedGuestSetupDescriptor,
    controller_generation: ControllerGeneration,
    session_target: Option<crate::CommittedGuestSessionTarget>,
    session_evidence: Option<GuestSessionEvidence>,
    suppress_finalizer_clear: bool,
    finalizer_clear_requested: Arc<AtomicBool>,
}

pub(crate) struct CatalogDescriptorVerifier {
    pub(crate) expected_key: String,
}

impl GuestSetupDescriptorVerifier for CatalogDescriptorVerifier {
    fn verify(
        &self,
        key_fingerprint: &d2b_contracts_resource::v3::SchemaFingerprint,
        _descriptor_digest: &d2b_contracts_resource::v3::SchemaFingerprint,
        signature: &str,
    ) -> bool {
        key_fingerprint.as_str() == self.expected_key && signature == "catalog-signature"
    }
}

fn guest_session_evidence(
    guest_ref: &ResourceRef,
    session: &d2bd_runtime::guest_component_session::GuestComponentSessionClient,
    descriptor: &VerifiedGuestSetupDescriptor,
    target: &crate::CommittedGuestSessionTarget,
) -> Option<GuestSessionEvidence> {
    let identity = session.identity();
    if identity.zone() != target.zone()
        || identity.guest_ref() != guest_ref
        || identity.guest_uid() != target.guest_uid()
        || identity.provider_generation() != target.provider_generation().get()
    {
        return None;
    }
    let boot_digest = identity
        .boot_identity()
        .digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let route = session.route_binding();
    if !route.liveness().is_live() {
        return None;
    }
    let binding = GuestSessionEvidenceBinding::new(
        identity.guest_uid().to_canonical_string(),
        descriptor.descriptor().descriptor_digest().as_str(),
        identity.schema_fingerprint().as_str(),
        identity.provider_generation(),
        identity.controller_generation(),
        session.generation(),
        route.reconnect_generation().get(),
        target.endpoint_generation().get(),
        1,
    )
    .ok()?;
    GuestSessionEvidence::current_bound(
        guest_ref.clone(),
        format!("sha256:{boot_digest}"),
        ["resource-commit".to_owned(), "resource-watch".to_owned()],
        true,
        true,
        true,
        binding,
    )
    .ok()
}

impl std::fmt::Debug for CloudHypervisorResourceSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CloudHypervisorResourceSession(<redacted>)")
    }
}

impl CloudHypervisorResourceSession {
    fn api_error() -> CloudHypervisorResourceApiError {
        CloudHypervisorResourceApiError::Transport
    }

    fn session_key(
        &self,
        guest_ref: &ResourceRef,
        guest_uid: &ResourceUid,
    ) -> Result<crate::GuestComponentSessionKey, CloudHypervisorResourceApiError> {
        let Some(target) = self.session_target.as_ref() else {
            return Err(CloudHypervisorResourceApiError::Authentication);
        };
        if target.zone() != &self.zone
            || target.guest_ref() != guest_ref
            || target.guest_uid() != guest_uid
        {
            return Err(CloudHypervisorResourceApiError::Conflict);
        }
        Ok(target.key())
    }

    async fn get_stored(
        &self,
        target: &ResourceRef,
        operation: &str,
    ) -> Result<StoredResource, CloudHypervisorResourceApiError> {
        let mut request = wire::GetRequest::new();
        request.meta = MessageField::some(public_request_meta(operation));
        request.target = MessageField::some(ch_identity(&self.zone, target, None, None, None));
        let mut projection = wire::Projection::new();
        projection.kind = EnumOrUnknown::new(wire::ProjectionKind::PROJECTION_KIND_FULL);
        request.projection = MessageField::some(projection);
        let response = self.client.get(request).await;
        if response.error.is_some() {
            return Err(CloudHypervisorResourceApiError::NotFound);
        }
        let resource = response
            .resource
            .as_ref()
            .and_then(stored_resource_from_wire)
            .ok_or_else(Self::api_error)?;
        if resource.zone != self.zone || resource.resource_ref != *target {
            return Err(CloudHypervisorResourceApiError::InvalidResponse);
        }
        Ok(resource)
    }

    async fn list_stored(
        &self,
        resource_types: &[&str],
        owner_uid: Option<&ResourceUid>,
        operation: &str,
    ) -> Result<Vec<StoredResource>, CloudHypervisorResourceApiError> {
        let mut request = wire::ListRequest::new();
        request.meta = MessageField::some(public_request_meta(operation));
        request.resource_types = resource_types
            .iter()
            .map(|value| (*value).to_owned())
            .collect();
        request.page_size = 256;
        let mut projection = wire::Projection::new();
        projection.kind = EnumOrUnknown::new(wire::ProjectionKind::PROJECTION_KIND_FULL);
        request.projection = MessageField::some(projection);
        if let Some(owner_uid) = owner_uid {
            let mut owner_uid_filter = wire::ListFilter::new();
            owner_uid_filter.field = "owner.resourceUid".to_owned();
            owner_uid_filter.values = vec![owner_uid.as_str().to_owned()];
            request.filters.push(owner_uid_filter);
        }
        let mut resources = Vec::new();
        loop {
            let response = self.client.list(request.clone()).await;
            if response.error.is_some() || response.truncated {
                return Err(Self::api_error());
            }
            for resource in &response.resources {
                if resources.len() >= 256 {
                    return Err(CloudHypervisorResourceApiError::Truncated);
                }
                let resource = stored_resource_from_wire(resource).ok_or_else(Self::api_error)?;
                if resource.zone != self.zone {
                    return Err(CloudHypervisorResourceApiError::InvalidResponse);
                }
                resources.push(resource);
            }
            let Some(cursor) = response.next_cursor.as_ref() else {
                break;
            };
            request.cursor = MessageField::some(cursor.clone());
        }
        Ok(resources)
    }

    async fn guest_for_fenced_operation(
        &self,
        guest_ref: &ResourceRef,
        guest_uid: &ResourceUid,
        operation: &str,
    ) -> Result<StoredResource, CloudHypervisorResourceApiError> {
        let guest = self.get_stored(guest_ref, operation).await?;
        if guest.uid != *guest_uid {
            return Err(CloudHypervisorResourceApiError::Conflict);
        }
        Ok(guest)
    }

    async fn authenticated_guest_session(
        &self,
        guest_ref: &ResourceRef,
        guest_uid: &ResourceUid,
    ) -> Result<
        Arc<d2bd_runtime::guest_component_session::GuestComponentSessionClient>,
        CloudHypervisorResourceApiError,
    > {
        self.guest_for_fenced_operation(guest_ref, guest_uid, "cloud-hypervisor-guest-session")
            .await?;
        let key = self.session_key(guest_ref, guest_uid)?;
        let session = self
            .guest_sessions
            .lock()
            .await
            .get(&key)
            .cloned()
            .ok_or(CloudHypervisorResourceApiError::Authentication)?;
        if session.identity().zone() != &self.zone
            || session.identity().guest_ref() != guest_ref
            || session.identity().guest_uid() != guest_uid
        {
            return Err(CloudHypervisorResourceApiError::Conflict);
        }
        Ok(session)
    }

    async fn close_guest_session(
        &self,
        guest_ref: &ResourceRef,
        guest_uid: &ResourceUid,
    ) -> Result<(), CloudHypervisorResourceApiError> {
        let _ = self
            .authenticated_guest_session(guest_ref, guest_uid)
            .await?;
        let key = self.session_key(guest_ref, guest_uid)?;
        let mut sessions = self.guest_sessions.lock().await;
        let removed = if sessions
            .get(&key)
            .is_some_and(|session| session.identity().guest_uid() == guest_uid)
        {
            sessions.remove(&key);
            true
        } else {
            false
        };
        drop(sessions);
        if removed {
            self.closed_guest_sessions.lock().await.insert(key);
        }
        Ok(())
    }

    async fn list_guest_local_resources(
        &self,
        session: &d2bd_runtime::guest_component_session::GuestComponentSessionClient,
        operation: &str,
    ) -> Result<Vec<wire::ResourceEnvelopeBytes>, CloudHypervisorResourceApiError> {
        let client = session.resource_service_client();
        let mut request = wire::ListRequest::new();
        request.meta = MessageField::some(public_request_meta(operation));
        request.resource_types = d2b_provider_runtime_cloud_hypervisor::GUEST_SEED_RESOURCE_TYPES
            .iter()
            .map(|resource_type| (*resource_type).to_owned())
            .collect();
        request.page_size = 256;
        let mut projection = wire::Projection::new();
        projection.kind = EnumOrUnknown::new(wire::ProjectionKind::PROJECTION_KIND_FULL);
        request.projection = MessageField::some(projection);
        let mut resources = Vec::new();
        loop {
            let response = client
                .list(ttrpc::context::Context::default(), &request)
                .await
                .inspect_err(|error| {
                    tracing::warn!(
                        error = ?error,
                        operation,
                        generation = session.generation(),
                        "Guest Resource API list transport failed",
                    );
                })
                .map_err(|_| CloudHypervisorResourceApiError::Transport)?;
            if response.error.is_some() || response.truncated {
                tracing::warn!(
                    error = ?response.error,
                    truncated = response.truncated,
                    operation,
                    generation = session.generation(),
                    "Guest Resource API list response was refused",
                );
                return Err(if response.truncated {
                    CloudHypervisorResourceApiError::Truncated
                } else {
                    CloudHypervisorResourceApiError::Transport
                });
            }
            for resource in response.resources {
                if resources.len() >= 256 {
                    return Err(CloudHypervisorResourceApiError::Truncated);
                }
                resources.push(resource);
            }
            let Some(cursor) = response.next_cursor.as_ref() else {
                break;
            };
            request.cursor = MessageField::some(cursor.clone());
        }
        Ok(resources)
    }

    async fn drain_guest_local_resources(
        &self,
        guest_ref: &ResourceRef,
        guest_uid: &ResourceUid,
    ) -> Result<(), CloudHypervisorResourceApiError> {
        let session = self
            .authenticated_guest_session(guest_ref, guest_uid)
            .await?;
        let resources = self
            .list_guest_local_resources(&session, "cloud-hypervisor-drain-list")
            .await?;
        let client = session.resource_service_client();
        for resource in resources {
            let identity = resource
                .identity
                .as_ref()
                .ok_or(CloudHypervisorResourceApiError::InvalidResponse)?;
            let uid = ResourceUid::parse(
                identity
                    .uid
                    .as_deref()
                    .ok_or(CloudHypervisorResourceApiError::InvalidResponse)?,
            )
            .map_err(|_| CloudHypervisorResourceApiError::InvalidResponse)?;
            let revision = ZoneRevision::new(
                identity
                    .revision
                    .ok_or(CloudHypervisorResourceApiError::InvalidResponse)?,
            );
            let mut mutation = wire::Mutation::new();
            mutation.kind = EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_DELETE);
            mutation.target = MessageField::some(identity.clone());
            mutation.precondition = MessageField::some(ch_exact_precondition(&uid, revision));
            let mut request = wire::DeleteRequest::new();
            request.meta = MessageField::some(public_request_meta(&format!(
                "cloud-hypervisor-drain-delete-{}",
                uid.as_str()
            )));
            request.mutation = MessageField::some(mutation);
            let response = client
                .delete(ttrpc::context::Context::default(), &request)
                .await
                .map_err(|_| CloudHypervisorResourceApiError::Transport)?;
            if response.error.is_some() {
                return Err(CloudHypervisorResourceApiError::Conflict);
            }
        }
        if self
            .list_guest_local_resources(&session, "cloud-hypervisor-drain-verify")
            .await?
            .is_empty()
        {
            Ok(())
        } else {
            Err(CloudHypervisorResourceApiError::Conflict)
        }
    }

    fn snapshot_from_stored(
        &self,
        guest: &StoredResource,
    ) -> Result<GuestSnapshot, CloudHypervisorResourceApiError> {
        let envelope = ResourceEnvelope::from_json(&guest.canonical_json).map_err(|_| {
            tracing::warn!("Cloud Hypervisor Guest snapshot failed: envelope");
            CloudHypervisorResourceApiError::InvalidResponse
        })?;
        let system_artifact_id =
            serde_json::from_slice::<GuestSpec>(&envelope.spec().base().to_canonical_bytes())
                .map_err(|_| {
                    tracing::warn!("Cloud Hypervisor Guest snapshot failed: spec");
                    CloudHypervisorResourceApiError::InvalidResponse
                })?
                .system_artifact_id()
                .map(|value| value.as_str().to_owned());
        let deleting = serde_json::from_slice::<Value>(&guest.canonical_json)
            .ok()
            .and_then(|value| value.get("metadata").cloned())
            .and_then(|metadata| metadata.get("deletionRequestedAt").cloned())
            .is_some_and(|value| !value.is_null());
        if deleting {
            tracing::debug!(
                guest = %guest.resource_ref.to_canonical_string(),
                finalizers = ?envelope
                    .metadata()
                    .finalizers()
                    .iter()
                    .map(|finalizer| finalizer.as_str())
                    .collect::<Vec<_>>(),
                "Cloud Hypervisor deleting Guest finalizers observed",
            );
        }
        let snapshot = GuestSnapshot::new(
            self.zone.clone(),
            self.zone_uid.clone(),
            guest.resource_ref.clone(),
            guest.uid.clone(),
            guest.generation,
            guest.revision,
            self.execution_ref.clone(),
            self.provider_ref.clone(),
            system_artifact_id,
            GuestGenerationSet {
                provider: self.descriptor.descriptor().provider_generation().get(),
                descriptor: self.descriptor.descriptor().provider_generation().get(),
                controller: self.controller_generation.get(),
                child: guest.generation.get(),
                session: self
                    .session_evidence
                    .as_ref()
                    .and_then(GuestSessionEvidence::session_generation)
                    .unwrap_or(0),
            },
            deleting,
        )
        .map_err(|_| {
            tracing::warn!("Cloud Hypervisor Guest snapshot failed: construction");
            CloudHypervisorResourceApiError::InvalidResponse
        })?
        .with_controller_finalizer_present(envelope.metadata().finalizers().iter().any(
            |finalizer| {
                finalizer.as_str()
                    == d2b_provider_runtime_cloud_hypervisor::GUEST_CONTROLLER_FINALIZER
            },
        ));
        Ok(match self.session_evidence.clone() {
            Some(evidence) => snapshot.with_session_evidence(evidence),
            None => snapshot,
        })
    }
}

#[async_trait]
impl AuthenticatedResourceSession for CloudHypervisorResourceSession {
    async fn call(
        &self,
        request: CloudHypervisorResourceRequest,
    ) -> Result<CloudHypervisorResourceResponse, CloudHypervisorResourceApiError> {
        let operation = match &request {
            CloudHypervisorResourceRequest::Register { .. } => "register",
            CloudHypervisorResourceRequest::GetGuest { .. } => "get-guest",
            CloudHypervisorResourceRequest::RelistOwnedChildren { .. } => "relist-children",
            CloudHypervisorResourceRequest::ObserveDependencies { .. } => "observe-dependencies",
            CloudHypervisorResourceRequest::CommitBatch { .. } => "commit-batch",
            CloudHypervisorResourceRequest::UpdateSpec { .. } => "update-spec",
            CloudHypervisorResourceRequest::UpdateStatus { .. } => "update-status",
            CloudHypervisorResourceRequest::ObserveProcessAdoption { .. } => "observe-adoption",
            CloudHypervisorResourceRequest::AssessUpdate { .. } => "assess-update",
            CloudHypervisorResourceRequest::ObserveFinalization { .. } => "observe-finalization",
            CloudHypervisorResourceRequest::DrainGuestLocal { .. } => "drain-guest-local",
            CloudHypervisorResourceRequest::CloseGuestSession { .. } => "close-guest-session",
            CloudHypervisorResourceRequest::DeleteChild { .. } => "delete-child",
            CloudHypervisorResourceRequest::InvalidateGuestSession { .. } => "invalidate-session",
            CloudHypervisorResourceRequest::EnsureGuestFinalizer { .. } => "ensure-finalizer",
            CloudHypervisorResourceRequest::ClearGuestFinalizer { .. } => "clear-finalizer",
        };
        tracing::debug!(operation, "Cloud Hypervisor Resource API call");
        match request {
            CloudHypervisorResourceRequest::Register { registration } => {
                if registration.provider_ref() != &self.provider_ref
                    || registration.provider_generation()
                        != self.descriptor.descriptor().provider_generation()
                    || registration.descriptor_digest()
                        != self.descriptor.descriptor().descriptor_digest()
                {
                    return Err(CloudHypervisorResourceApiError::Authentication);
                }
                Ok(CloudHypervisorResourceResponse::Registered)
            }
            CloudHypervisorResourceRequest::GetGuest { guest_ref } => {
                let guest = self
                    .get_stored(&guest_ref, "cloud-hypervisor-get-guest")
                    .await?;
                Ok(CloudHypervisorResourceResponse::Guest(
                    self.snapshot_from_stored(&guest)?,
                ))
            }
            CloudHypervisorResourceRequest::RelistOwnedChildren {
                guest_ref,
                expected_refs,
            } => {
                let owner = self
                    .get_stored(&guest_ref, "cloud-hypervisor-owner-fence")
                    .await?;
                let children = self
                    .list_stored(
                        &["Process", "Endpoint", "Volume"],
                        Some(&owner.uid),
                        "cloud-hypervisor-list-children",
                    )
                    .await?;
                let mut result = Vec::new();
                for resource in children {
                    if !expected_refs.contains(&resource.resource_ref) {
                        continue;
                    }
                    let envelope = ResourceEnvelope::from_json(&resource.canonical_json)
                        .map_err(|_| CloudHypervisorResourceApiError::InvalidResponse)?;
                    if envelope.metadata().owner_ref() != Some(&guest_ref) {
                        continue;
                    }
                    let desired_lifecycle =
                        if resource.resource_ref.resource_type().as_str() == "Process" {
                            serde_json::from_slice::<ProcessSpec>(
                                &envelope.spec().base().to_canonical_bytes(),
                            )
                            .ok()
                            .map(|spec| spec.desired_lifecycle())
                        } else {
                            None
                        };
                    let spec_digest = envelope
                        .spec()
                        .digest()
                        .map_err(|_| CloudHypervisorResourceApiError::InvalidResponse)?;
                    result.push(
                        OwnedChildSnapshot::new(
                            resource.resource_ref,
                            resource.zone,
                            guest_ref.clone(),
                            resource.uid,
                            resource.generation,
                            resource.revision,
                            spec_digest,
                            envelope.status().phase(),
                            desired_lifecycle,
                            envelope.status().phase() == ResourcePhase::Ready,
                        )
                        .map_err(|_| CloudHypervisorResourceApiError::InvalidResponse)?
                        .with_owner_uid(owner.uid.clone()),
                    );
                }
                Ok(CloudHypervisorResourceResponse::OwnedChildren(result))
            }
            CloudHypervisorResourceRequest::ObserveDependencies { guest_ref, graph } => {
                let mut devices = Vec::new();
                for resource_ref in &graph.devices {
                    let phase = self
                        .get_stored(resource_ref, "cloud-hypervisor-device-dependency")
                        .await
                        .ok()
                        .and_then(|resource| {
                            ResourceEnvelope::from_json(&resource.canonical_json)
                                .ok()
                                .map(|envelope| envelope.status().phase())
                        })
                        .unwrap_or(ResourcePhase::Pending);
                    devices.push((resource_ref.clone(), phase));
                }
                let mut networks = Vec::new();
                for resource_ref in &graph.networks {
                    let phase = self
                        .get_stored(resource_ref, "cloud-hypervisor-network-dependency")
                        .await
                        .ok()
                        .and_then(|resource| {
                            ResourceEnvelope::from_json(&resource.canonical_json)
                                .ok()
                                .map(|envelope| envelope.status().phase())
                        })
                        .unwrap_or(ResourcePhase::Pending);
                    networks.push((resource_ref.clone(), phase));
                }
                let mut volumes = Vec::new();
                for resource_ref in &graph.volumes {
                    let phase = self
                        .get_stored(resource_ref, "cloud-hypervisor-volume-dependency")
                        .await
                        .ok()
                        .and_then(|resource| {
                            ResourceEnvelope::from_json(&resource.canonical_json)
                                .ok()
                                .map(|envelope| envelope.status().phase())
                        })
                        .unwrap_or(ResourcePhase::Pending);
                    volumes.push((resource_ref.clone(), phase));
                }
                let exports_ready = volumes
                    .iter()
                    .all(|(_, phase)| *phase == ResourcePhase::Ready);
                let setup_volume_ref = deterministic_child_ref(&guest_ref, ChildRole::SystemVolume)
                    .map_err(|_| CloudHypervisorResourceApiError::InvalidResponse)?;
                let setup_ready = self
                    .get_stored(&setup_volume_ref, "cloud-hypervisor-setup-dependency")
                    .await
                    .ok()
                    .and_then(|resource| {
                        ResourceEnvelope::from_json(&resource.canonical_json)
                            .ok()
                            .map(|envelope| envelope.status().phase() == ResourcePhase::Ready)
                    })
                    .unwrap_or(false);
                let dependencies = GuestDependencySnapshot::new(
                    devices,
                    networks,
                    volumes,
                    exports_ready,
                    setup_ready,
                )
                .map_err(|_| CloudHypervisorResourceApiError::InvalidResponse)?;
                Ok(CloudHypervisorResourceResponse::Dependencies(dependencies))
            }
            CloudHypervisorResourceRequest::CommitBatch { batch } => {
                let mut request = wire::CommitBatchRequest::new();
                request.meta = MessageField::some(public_request_meta(&format!(
                    "cloud-hypervisor-commit-children-{}-{}",
                    batch.owner_uid().as_str(),
                    batch.owner_revision().get(),
                )));
                for mutation in batch.mutations() {
                    let canonical = batch
                        .canonical_payload(mutation.target())
                        .map_err(|_| CloudHypervisorResourceApiError::InvalidResponse)?;
                    let mut wire_mutation = wire::Mutation::new();
                    wire_mutation.kind =
                        EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_CREATE);
                    wire_mutation.target = MessageField::some(ch_identity(
                        batch.zone(),
                        mutation.target(),
                        None,
                        None,
                        None,
                    ));
                    wire_mutation.precondition = MessageField::some(ch_create_precondition());
                    wire_mutation.resource = MessageField::some(ch_resource_body(
                        batch.zone(),
                        mutation.target(),
                        None,
                        &canonical,
                    )?);
                    wire_mutation.owner = MessageField::some(ch_identity(
                        batch.zone(),
                        batch.owner_ref(),
                        Some(batch.owner_uid()),
                        None,
                        Some(batch.owner_revision().get()),
                    ));
                    request.mutations.push(wire_mutation);
                }
                let response = self.mutation_client.commit_batch(request).await;
                if response.error.is_some() {
                    return Err(CloudHypervisorResourceApiError::Conflict);
                }
                let mut committed = Vec::new();
                for resource in &response.resources {
                    let stored = stored_resource_from_wire(resource)
                        .ok_or(CloudHypervisorResourceApiError::InvalidResponse)?;
                    committed.push(
                        d2b_provider_runtime_cloud_hypervisor::CommittedChild::new(
                            stored.resource_ref,
                            batch.owner_ref().clone(),
                            stored.zone,
                            stored.uid,
                            stored.revision,
                        )
                        .map_err(|_| CloudHypervisorResourceApiError::InvalidResponse)?,
                    );
                }
                if committed.len() != batch.mutations().len() {
                    return Ok(CloudHypervisorResourceResponse::Committed(
                        GuestChildCommitResponse::Uncertain,
                    ));
                }
                Ok(CloudHypervisorResourceResponse::Committed(
                    GuestChildCommitResponse::Committed(committed),
                ))
            }
            CloudHypervisorResourceRequest::UpdateSpec { update } => {
                let current = self
                    .get_stored(update.target(), "cloud-hypervisor-update-child")
                    .await?;
                let current_value: Value = serde_json::from_slice(&current.canonical_json)
                    .map_err(|_| CloudHypervisorResourceApiError::InvalidResponse)?;
                let merged_spec = merge_cloud_hypervisor_child_spec(
                    &current_value,
                    update.body(),
                    update.desired_lifecycle(),
                )?;
                let payload = replace_public_field(&current_value, "spec", merged_spec)
                    .map_err(|_| CloudHypervisorResourceApiError::InvalidResponse)?;
                let mut request = wire::UpdateSpecRequest::new();
                let mut operation_payload = format!(
                    "{}:{}:",
                    update.expected_uid().as_str(),
                    update.expected_revision().get(),
                )
                .into_bytes();
                operation_payload.extend_from_slice(&payload);
                let payload_operation_digest =
                    d2b_contracts_resource::v3::resource_schema::canonical_digest(
                        d2b_contracts_resource::v3::resource_schema::RESOURCE_ENVELOPE_DOMAIN_TAG,
                        &operation_payload,
                    );
                request.meta = MessageField::some(public_request_meta(&format!(
                    "ch-update-child-{}",
                    payload_operation_digest.trim_start_matches("sha256:"),
                )));
                let identity = ch_identity(
                    &current.zone,
                    update.target(),
                    Some(update.expected_uid()),
                    Some(current.generation.get()),
                    Some(update.expected_revision().get()),
                );
                let mut mutation = wire::Mutation::new();
                mutation.kind = EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_UPDATE_SPEC);
                mutation.target = MessageField::some(identity);
                mutation.precondition = MessageField::some(ch_exact_precondition(
                    update.expected_uid(),
                    update.expected_revision(),
                ));
                mutation.resource = MessageField::some(ch_resource_body(
                    &current.zone,
                    update.target(),
                    Some(update.expected_uid()),
                    &payload,
                )?);
                request.mutation = MessageField::some(mutation);
                let response = self.mutation_client.update_spec(request).await;
                if response.error.is_some() {
                    return Err(CloudHypervisorResourceApiError::Conflict);
                }
                let stored = response
                    .resource
                    .as_ref()
                    .and_then(stored_resource_from_wire)
                    .ok_or(CloudHypervisorResourceApiError::InvalidResponse)?;
                Ok(CloudHypervisorResourceResponse::Updated(
                    d2b_provider_runtime_cloud_hypervisor::CommittedChild::new(
                        stored.resource_ref,
                        update.target().clone(),
                        stored.zone,
                        stored.uid,
                        stored.revision,
                    )
                    .map_err(|_| CloudHypervisorResourceApiError::InvalidResponse)?,
                ))
            }
            CloudHypervisorResourceRequest::UpdateStatus { guest_ref, status } => {
                let current = self
                    .get_stored(&guest_ref, "cloud-hypervisor-update-status")
                    .await?;
                let current_value: Value = serde_json::from_slice(&current.canonical_json)
                    .map_err(|_| {
                        tracing::warn!("Cloud Hypervisor status update failed: current-resource");
                        CloudHypervisorResourceApiError::InvalidResponse
                    })?;
                let mut desired_status = serde_json::to_value(status.status()).map_err(|_| {
                    tracing::warn!("Cloud Hypervisor status update failed: status-serialization");
                    CloudHypervisorResourceApiError::InvalidResponse
                })?;
                let provider_phase = desired_status
                    .get("phase")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .ok_or(CloudHypervisorResourceApiError::InvalidResponse)?;
                let public_phase = Value::String(
                    if provider_phase == "Deleting" {
                        "Draining"
                    } else {
                        provider_phase.as_str()
                    }
                    .to_owned(),
                );
                let current_status = current_value
                    .get("status")
                    .and_then(Value::as_object)
                    .ok_or(CloudHypervisorResourceApiError::InvalidResponse)?;
                if provider_phase == "Deleting"
                    && let Some(current_provider_phase) = current_status
                        .get("resource")
                        .and_then(Value::as_object)
                        .and_then(|resource| resource.get("phase"))
                        .cloned()
                    && let Some(resource) = desired_status.as_object_mut()
                {
                    resource.insert("phase".to_owned(), current_provider_phase);
                }
                if current_status.get("resource") == Some(&desired_status)
                    && current_status.get("phase") == Some(&public_phase)
                    && current_status
                        .get("observedGeneration")
                        .and_then(Value::as_u64)
                        == Some(current.generation.get())
                {
                    return Ok(CloudHypervisorResourceResponse::StatusUpdated);
                }
                let mut payload_value = current_value;
                let base_status = payload_value
                    .get_mut("status")
                    .and_then(Value::as_object_mut)
                    .ok_or_else(|| {
                        tracing::warn!("Cloud Hypervisor status update failed: status-replacement");
                        CloudHypervisorResourceApiError::InvalidResponse
                    })?;
                base_status.insert("resource".to_owned(), desired_status.clone());
                base_status.insert("phase".to_owned(), public_phase);
                base_status.insert(
                    "observedGeneration".to_owned(),
                    Value::from(current.generation.get()),
                );
                let payload_bytes = serde_json::to_vec(&payload_value)
                    .map_err(|_| CloudHypervisorResourceApiError::InvalidResponse)?;
                let payload = CanonicalJsonValue::parse(&payload_bytes)
                    .map_err(|_| CloudHypervisorResourceApiError::InvalidResponse)?
                    .to_canonical_bytes();
                let mut request = wire::UpdateStatusRequest::new();
                let mut operation_payload =
                    format!("{}:{}:", current.uid.as_str(), current.revision.get()).into_bytes();
                operation_payload.extend_from_slice(&payload);
                let payload_operation_digest =
                    d2b_contracts_resource::v3::resource_schema::canonical_digest(
                        d2b_contracts_resource::v3::resource_schema::RESOURCE_ENVELOPE_DOMAIN_TAG,
                        &operation_payload,
                    );
                request.meta = MessageField::some(public_request_meta(&format!(
                    "ch-update-status-{}",
                    payload_operation_digest.trim_start_matches("sha256:"),
                )));
                let mut mutation = wire::Mutation::new();
                mutation.kind = EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_UPDATE_STATUS);
                mutation.target = MessageField::some(ch_identity(
                    &current.zone,
                    &current.resource_ref,
                    Some(&current.uid),
                    Some(current.generation.get()),
                    Some(current.revision.get()),
                ));
                mutation.precondition =
                    MessageField::some(ch_exact_precondition(&current.uid, current.revision));
                mutation.resource = MessageField::some(
                    ch_resource_body(
                        &current.zone,
                        &current.resource_ref,
                        Some(&current.uid),
                        &payload,
                    )
                    .inspect_err(|_| {
                        tracing::warn!("Cloud Hypervisor status update failed: resource-body");
                    })?,
                );
                request.mutation = MessageField::some(mutation);
                let response = self.mutation_client.update_status(request).await;
                if let Some(error) = response.error.as_ref() {
                    tracing::warn!(
                        error_kind = ?error.kind,
                        reason = %error.reason,
                        "Cloud Hypervisor status update was rejected",
                    );
                    return Err(CloudHypervisorResourceApiError::Conflict);
                }
                Ok(CloudHypervisorResourceResponse::StatusUpdated)
            }
            CloudHypervisorResourceRequest::ObserveProcessAdoption {
                guest_ref,
                guest_uid,
                process_ref,
                process_uid,
                process_revision,
            } => {
                let process = self
                    .get_stored(&process_ref, "cloud-hypervisor-process-adoption")
                    .await;
                let status = match process {
                    Ok(resource) => {
                        if resource.uid != process_uid || resource.revision != process_revision {
                            return Ok(CloudHypervisorResourceResponse::ProcessAdoption(
                                d2b_provider_runtime_cloud_hypervisor::ProcessAdoptionStatus::Quarantined,
                            ));
                        }
                        let envelope = ResourceEnvelope::from_json(&resource.canonical_json)
                            .map_err(|_| CloudHypervisorResourceApiError::InvalidResponse)?;
                        if envelope.metadata().owner_ref() != Some(&guest_ref) {
                            return Ok(CloudHypervisorResourceResponse::ProcessAdoption(
                                d2b_provider_runtime_cloud_hypervisor::ProcessAdoptionStatus::Quarantined,
                            ));
                        }
                        let owner = self
                            .get_stored(&guest_ref, "cloud-hypervisor-process-owner-fence")
                            .await?;
                        if owner.uid != guest_uid {
                            return Ok(CloudHypervisorResourceResponse::ProcessAdoption(
                                d2b_provider_runtime_cloud_hypervisor::ProcessAdoptionStatus::Quarantined,
                            ));
                        }
                        let spec = serde_json::from_slice::<ProcessSpec>(
                            &envelope.spec().base().to_canonical_bytes(),
                        )
                        .map_err(|_| CloudHypervisorResourceApiError::InvalidResponse)?;
                        let provider_ref = envelope
                            .spec()
                            .provider_ref()
                            .cloned()
                            .ok_or(CloudHypervisorResourceApiError::InvalidResponse)?;
                        let owner_ref = envelope.metadata().owner_ref().cloned();
                        let descriptor_digest =
                            self.descriptor.descriptor().descriptor_digest().clone();
                        let context = crate::process_provider_runtime::ProcessResourceContext::new(
                            self.zone.clone(),
                            &resource.resource_ref,
                            &resource.uid,
                            resource.generation,
                            resource.revision,
                            &provider_ref,
                            self.controller_generation,
                            Some(guest_ref.clone()),
                        )
                        .with_lifecycle_identity(
                            Some(self.zone_uid.clone()),
                            Some(self.policy_revision),
                            None,
                        )
                        .with_owner_ref(owner_ref)
                        .with_guest_descriptor_digest(Some(&descriptor_digest));
                        let liveness = self
                            .providers
                            .probe_resource(context, &spec)
                            .await
                            .map_err(|error| {
                                tracing::warn!(
                                    error = %error,
                                    "Cloud Hypervisor VMM adoption probe failed",
                                );
                                CloudHypervisorResourceApiError::Transport
                            })?;
                        match liveness {
                            crate::process_provider_runtime::ProviderLiveness::Alive => {
                                d2b_provider_runtime_cloud_hypervisor::ProcessAdoptionStatus::Current
                            }
                            crate::process_provider_runtime::ProviderLiveness::Exited => {
                                d2b_provider_runtime_cloud_hypervisor::ProcessAdoptionStatus::Absent
                            }
                            crate::process_provider_runtime::ProviderLiveness::Unknown => {
                                d2b_provider_runtime_cloud_hypervisor::ProcessAdoptionStatus::Unavailable
                            }
                        }
                    }
                    Err(CloudHypervisorResourceApiError::NotFound) => {
                        d2b_provider_runtime_cloud_hypervisor::ProcessAdoptionStatus::Absent
                    }
                    Err(_) => {
                        d2b_provider_runtime_cloud_hypervisor::ProcessAdoptionStatus::Unavailable
                    }
                };
                Ok(CloudHypervisorResourceResponse::ProcessAdoption(status))
            }
            CloudHypervisorResourceRequest::AssessUpdate { .. } => {
                Ok(CloudHypervisorResourceResponse::UpdateAssessment(None))
            }
            CloudHypervisorResourceRequest::ObserveFinalization {
                guest_ref,
                guest_uid,
                children,
            } => {
                self.guest_for_fenced_operation(
                    &guest_ref,
                    &guest_uid,
                    "cloud-hypervisor-observe-finalization",
                )
                .await?;
                let all_children = self
                    .list_stored(
                        &["Process", "Endpoint", "Volume"],
                        None,
                        "cloud-hypervisor-list-finalization-descendants",
                    )
                    .await?;
                let current = children
                    .iter()
                    .map(|child| (child.resource_ref().clone(), child.uid().clone()))
                    .collect::<BTreeMap<_, _>>();
                let direct_refs = current.keys().cloned().collect::<BTreeSet<_>>();
                let mut transitive_descendants_present = false;
                let mut foreign_children_present = false;
                for resource in &all_children {
                    let envelope = ResourceEnvelope::from_json(&resource.canonical_json)
                        .map_err(|_| CloudHypervisorResourceApiError::InvalidResponse)?;
                    match envelope.metadata().owner_ref() {
                        Some(owner) if owner == &guest_ref => {
                            if direct_refs.contains(&resource.resource_ref)
                                && current.get(&resource.resource_ref) != Some(&resource.uid)
                            {
                                foreign_children_present = true;
                            } else if !direct_refs.contains(&resource.resource_ref) {
                                tracing::debug!(
                                    guest = %guest_ref.to_canonical_string(),
                                    resource = %resource.resource_ref.to_canonical_string(),
                                    "non-CH resource still claims deleting Guest as owner",
                                );
                            }
                        }
                        Some(owner) if direct_refs.contains(owner) => {
                            transitive_descendants_present = true;
                        }
                        _ => {}
                    }
                }
                let process = children
                    .iter()
                    .find(|child| child.resource_ref().resource_type().as_str() == "Process");
                let process_state = match process {
                    Some(process)
                        if process.phase() == ResourcePhase::Ready
                            && process.desired_lifecycle() == Some(DesiredLifecycle::Running) =>
                    {
                        ProcessState::Running {
                            identity_verified: true,
                        }
                    }
                    Some(process)
                        if process.desired_lifecycle() == Some(DesiredLifecycle::Stopped) =>
                    {
                        ProcessState::Stopped
                    }
                    Some(_) => ProcessState::Unknown,
                    None => ProcessState::Absent,
                };
                let direct_children = children
                    .iter()
                    .filter_map(|child| {
                        let role = d2b_provider_runtime_cloud_hypervisor::child_role_for_ref(
                            child.resource_ref(),
                        )?;
                        let (deletion_requested, finalizers_pending, uid, revision) = all_children
                            .iter()
                            .find(|resource| resource.resource_ref == *child.resource_ref())
                            .map(|resource| {
                                let value =
                                    serde_json::from_slice::<Value>(&resource.canonical_json).ok();
                                let metadata =
                                    value.as_ref().and_then(|value| value.get("metadata"));
                                let deletion_requested = metadata
                                    .and_then(|metadata| metadata.get("deletionRequestedAt"))
                                    .is_some_and(|value| !value.is_null());
                                let finalizers_pending = metadata
                                    .and_then(|metadata| metadata.get("finalizers"))
                                    .and_then(Value::as_array)
                                    .is_some_and(|finalizers| !finalizers.is_empty());
                                (
                                    deletion_requested,
                                    finalizers_pending,
                                    resource.uid.clone(),
                                    resource.revision,
                                )
                            })
                            .unwrap_or_else(|| {
                                (false, false, child.uid().clone(), child.revision())
                            });
                        Some(
                            FencedChild::new(role, child.resource_ref().clone(), uid, revision)
                                .ok()?
                                .with_deletion_requested(deletion_requested)
                                .with_finalizers_pending(finalizers_pending),
                        )
                    })
                    .collect();
                let session = self
                    .guest_sessions
                    .lock()
                    .await
                    .iter()
                    .find(|(key, _)| key.is_guest_identity(&self.zone, &guest_ref, &guest_uid))
                    .map(|(_, session)| Arc::clone(session));
                let closed = self
                    .closed_guest_sessions
                    .lock()
                    .await
                    .iter()
                    .any(|key| key.is_guest_identity(&self.zone, &guest_ref, &guest_uid));
                let (session_state, guest_local_drained) = match session {
                    Some(session) => match tokio::time::timeout(
                        d2bd_runtime::guest_component_session::COMPONENT_SESSION_ATTEMPT_CAP,
                        self.list_guest_local_resources(
                            &session,
                            "cloud-hypervisor-finalization-local-list",
                        ),
                    )
                    .await
                    {
                        Ok(Ok(resources)) => (SessionState::Active, resources.is_empty()),
                        Ok(Err(error)) => {
                            tracing::warn!(
                                error = ?error,
                                "Guest finalization resource list failed",
                            );
                            self.guest_sessions.lock().await.retain(|key, _| {
                                !key.is_guest_identity(&self.zone, &guest_ref, &guest_uid)
                            });
                            (SessionState::Dead, false)
                        }
                        Err(_) => {
                            tracing::warn!("Guest finalization resource list timed out");
                            self.guest_sessions.lock().await.retain(|key, _| {
                                !key.is_guest_identity(&self.zone, &guest_ref, &guest_uid)
                            });
                            (SessionState::Dead, false)
                        }
                    },
                    None if closed => (SessionState::Closed, true),
                    None => (SessionState::Unknown, false),
                };
                let observation = GuestFinalizationInput::new(
                    guest_uid,
                    session_state,
                    guest_local_drained,
                    process_state,
                    direct_children,
                    transitive_descendants_present,
                    children
                        .iter()
                        .any(|child| child.resource_ref().resource_type().as_str() == "Volume"),
                    foreign_children_present,
                )
                .map_err(|_| CloudHypervisorResourceApiError::InvalidResponse)?;
                Ok(CloudHypervisorResourceResponse::Finalization(observation))
            }
            CloudHypervisorResourceRequest::DrainGuestLocal {
                guest_ref,
                guest_uid,
            } => {
                self.drain_guest_local_resources(&guest_ref, &guest_uid)
                    .await?;
                Ok(CloudHypervisorResourceResponse::LifecycleApplied)
            }
            CloudHypervisorResourceRequest::CloseGuestSession {
                guest_ref,
                guest_uid,
            } => {
                self.close_guest_session(&guest_ref, &guest_uid).await?;
                Ok(CloudHypervisorResourceResponse::LifecycleApplied)
            }
            CloudHypervisorResourceRequest::InvalidateGuestSession {
                guest_ref,
                guest_uid,
                minimum_generation,
            } => {
                self.guest_for_fenced_operation(
                    &guest_ref,
                    &guest_uid,
                    "cloud-hypervisor-invalidate-session",
                )
                .await?;
                let key = self.session_key(&guest_ref, &guest_uid)?;
                let mut sessions = self.guest_sessions.lock().await;
                let removed = if sessions.get(&key).is_some_and(|session| {
                    session.identity().guest_uid() == &guest_uid
                        && session.generation() < minimum_generation
                }) {
                    sessions.remove(&key);
                    true
                } else {
                    false
                };
                drop(sessions);
                if removed {
                    self.closed_guest_sessions.lock().await.insert(key);
                }
                Ok(CloudHypervisorResourceResponse::LifecycleApplied)
            }
            CloudHypervisorResourceRequest::DeleteChild {
                guest_ref,
                guest_uid,
                child,
            } => {
                self.guest_for_fenced_operation(
                    &guest_ref,
                    &guest_uid,
                    "cloud-hypervisor-delete-child",
                )
                .await?;
                let current = self
                    .get_stored(child.target(), "cloud-hypervisor-delete-child-fence")
                    .await?;
                if current.uid != *child.uid() || current.revision != child.revision() {
                    return Err(CloudHypervisorResourceApiError::Conflict);
                }
                let envelope = ResourceEnvelope::from_json(&current.canonical_json)
                    .map_err(|_| CloudHypervisorResourceApiError::InvalidResponse)?;
                if envelope.metadata().owner_ref() != Some(&guest_ref) {
                    return Err(CloudHypervisorResourceApiError::Conflict);
                }
                let mut request = wire::DeleteRequest::new();
                request.meta = MessageField::some(public_request_meta(&format!(
                    "cloud-hypervisor-delete-child-{}-{}",
                    child.uid().as_str(),
                    child.revision().get(),
                )));
                let mut mutation = wire::Mutation::new();
                mutation.kind = EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_DELETE);
                mutation.target = MessageField::some(ch_identity(
                    &self.zone,
                    child.target(),
                    Some(child.uid()),
                    None,
                    Some(child.revision().get()),
                ));
                mutation.precondition =
                    MessageField::some(ch_exact_precondition(child.uid(), child.revision()));
                request.mutation = MessageField::some(mutation);
                let response = self.mutation_client.delete(request).await;
                if let Some(error) = response.error.as_ref() {
                    tracing::warn!(
                        error_kind = ?error.kind,
                        reason = %error.reason,
                        child_revision = child.revision().get(),
                        "Cloud Hypervisor child deletion was rejected",
                    );
                    return Err(CloudHypervisorResourceApiError::Conflict);
                }
                Ok(CloudHypervisorResourceResponse::LifecycleApplied)
            }
            CloudHypervisorResourceRequest::ClearGuestFinalizer {
                guest_ref,
                guest_uid,
                guest_revision,
                finalizer_present,
            } => {
                if !finalizer_present {
                    return Ok(CloudHypervisorResourceResponse::LifecycleApplied);
                }
                if self.suppress_finalizer_clear {
                    self.finalizer_clear_requested.store(true, Ordering::Release);
                    return Ok(CloudHypervisorResourceResponse::LifecycleApplied);
                }
                let mut request = wire::UpdateFinalizersRequest::new();
                request.meta = MessageField::some(public_request_meta(&format!(
                    "cloud-hypervisor-clear-finalizer-{}-{}",
                    guest_uid.as_str(),
                    guest_revision.get(),
                )));
                let mut mutation = wire::Mutation::new();
                mutation.kind =
                    EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_UPDATE_FINALIZERS);
                mutation.target = MessageField::some(ch_identity(
                    &self.zone,
                    &guest_ref,
                    Some(&guest_uid),
                    None,
                    Some(guest_revision.get()),
                ));
                mutation.precondition =
                    MessageField::some(ch_exact_precondition(&guest_uid, guest_revision));
                mutation.remove_finalizers.push(
                    d2b_provider_runtime_cloud_hypervisor::GUEST_CONTROLLER_FINALIZER.to_owned(),
                );
                request.mutation = MessageField::some(mutation);
                let response = self.mutation_client.update_finalizers(request).await;
                if let Some(error) = response.error.as_ref() {
                    tracing::warn!(
                        error_kind = ?error.kind,
                        reason = %error.reason,
                        guest_revision = guest_revision.get(),
                        "Cloud Hypervisor Guest finalizer removal was rejected",
                    );
                    return Err(CloudHypervisorResourceApiError::Conflict);
                }
                Ok(CloudHypervisorResourceResponse::LifecycleApplied)
            }
            CloudHypervisorResourceRequest::EnsureGuestFinalizer {
                guest_ref,
                guest_uid,
                guest_revision,
            } => {
                let mut request = wire::UpdateFinalizersRequest::new();
                request.meta = MessageField::some(public_request_meta(&format!(
                    "cloud-hypervisor-ensure-finalizer-{}-{}",
                    guest_uid.as_str(),
                    guest_revision.get(),
                )));
                let mut mutation = wire::Mutation::new();
                mutation.kind =
                    EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_UPDATE_FINALIZERS);
                mutation.target = MessageField::some(ch_identity(
                    &self.zone,
                    &guest_ref,
                    Some(&guest_uid),
                    None,
                    Some(guest_revision.get()),
                ));
                mutation.precondition =
                    MessageField::some(ch_exact_precondition(&guest_uid, guest_revision));
                mutation.add_finalizers.push(
                    d2b_provider_runtime_cloud_hypervisor::GUEST_CONTROLLER_FINALIZER.to_owned(),
                );
                request.mutation = MessageField::some(mutation);
                let response = self.mutation_client.update_finalizers(request).await;
                if response.error.is_some() {
                    return Err(CloudHypervisorResourceApiError::Conflict);
                }
                Ok(CloudHypervisorResourceResponse::LifecycleApplied)
            }
        }
    }
}

fn ch_identity(
    zone: &ZoneId,
    resource_ref: &ResourceRef,
    uid: Option<&ResourceUid>,
    generation: Option<u64>,
    revision: Option<u64>,
) -> wire::ResourceIdentity {
    let mut identity = wire::ResourceIdentity::new();
    identity.zone = zone.as_str().to_owned();
    identity.resource_type = resource_ref.resource_type().as_str().to_owned();
    identity.name = resource_ref.name().as_str().to_owned();
    identity.uid = uid.map(|value| value.as_str().to_owned());
    identity.generation = generation;
    identity.revision = revision;
    identity
}

fn ch_create_precondition() -> wire::Precondition {
    let mut precondition = wire::Precondition::new();
    precondition.kind = EnumOrUnknown::new(wire::PreconditionKind::PRECONDITION_KIND_CREATE_ABSENT);
    precondition
}

fn ch_exact_precondition(uid: &ResourceUid, revision: ZoneRevision) -> wire::Precondition {
    let mut precondition = wire::Precondition::new();
    precondition.kind =
        EnumOrUnknown::new(wire::PreconditionKind::PRECONDITION_KIND_EXACT_REVISION);
    precondition.expected_uid = Some(uid.as_str().to_owned());
    precondition.expected_revision = Some(revision.get());
    precondition
}

fn ch_resource_body(
    zone: &ZoneId,
    resource_ref: &ResourceRef,
    uid: Option<&ResourceUid>,
    canonical: &[u8],
) -> Result<wire::ResourceEnvelopeBytes, CloudHypervisorResourceApiError> {
    let canonical = CanonicalJsonValue::parse(canonical)
        .map_err(|_| CloudHypervisorResourceApiError::InvalidResponse)?
        .to_canonical_bytes();
    let mut body = wire::ResourceEnvelopeBytes::new();
    body.identity = MessageField::some(ch_identity(zone, resource_ref, uid, None, None));
    body.payload_digest = d2b_contracts_resource::v3::resource_schema::canonical_digest(
        d2b_contracts_resource::v3::resource_schema::RESOURCE_ENVELOPE_DOMAIN_TAG,
        &canonical,
    );
    body.canonical_json = canonical;
    Ok(body)
}

fn merge_cloud_hypervisor_child_spec(
    current: &Value,
    body: &d2b_provider_runtime_cloud_hypervisor::ChildCreateBody,
    desired_lifecycle: Option<DesiredLifecycle>,
) -> Result<Value, CloudHypervisorResourceApiError> {
    let body =
        serde_json::to_value(body).map_err(|_| CloudHypervisorResourceApiError::InvalidResponse)?;
    let desired_spec = body
        .get("spec")
        .and_then(Value::as_object)
        .ok_or(CloudHypervisorResourceApiError::InvalidResponse)?;
    let mut merged_spec = current
        .get("spec")
        .and_then(Value::as_object)
        .cloned()
        .ok_or(CloudHypervisorResourceApiError::InvalidResponse)?;
    merged_spec.extend(desired_spec.clone());
    if let Some(desired_lifecycle) = desired_lifecycle {
        merged_spec.insert(
            "desiredLifecycle".to_owned(),
            serde_json::to_value(desired_lifecycle)
                .map_err(|_| CloudHypervisorResourceApiError::InvalidResponse)?,
        );
    }
    Ok(Value::Object(merged_spec))
}

/// A production Resource API and core-controller runtime for one Zone.
pub struct ZoneResourceRuntime {
    zone: ZoneId,
    authority_identity: Option<ZoneAuthorityIdentity>,
    bootstrap_provisioned_store: bool,
    store_id: String,
    store: Arc<RedbResourceStore>,
    store_metadata: StoreRuntimeMetadata,
    backend: Arc<RedbBackend>,
    api: Arc<ResourceService<RedbBackend>>,
    authorizer: Arc<NativeAuthorizer>,
    authorization_state: Arc<Mutex<Option<AuthorizationState>>>,
    policy_refresh: Mutex<()>,
    bundle_resource_types: Vec<ResourceTypeName>,
    policy_subject_fingerprints:
        Mutex<BTreeMap<(ResourceRef, ResourceRef), PolicySubjectFingerprint>>,
    policy_loaded: Mutex<bool>,
    bus: Option<ZoneBus>,
    registrar: Arc<Mutex<Option<ZoneRegistrar>>>,
    ingress: Mutex<Option<BusIngress>>,
    service_task: Mutex<Option<tokio::task::JoinHandle<Result<(), SessionServerError>>>>,
    process_status_client:
        Mutex<Option<Arc<ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>>>>,
    core_controller_subject: Mutex<Option<AuthenticatedSubjectContext>>,
    core_runner_tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    core_runner_lock: Arc<tokio::sync::Mutex<()>>,
    u12_runner_tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    u12_runner_lock: Arc<tokio::sync::Mutex<()>>,
    u12_state: Mutex<Option<Arc<crate::ServerState>>>,
    u12_required: AtomicBool,
    u7_runner_tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    u7_runner_lock: Arc<tokio::sync::Mutex<()>>,
    u7_state: Mutex<Option<Arc<crate::ServerState>>>,
    u7_required: AtomicBool,
    u6_runner_tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    u6_runner_lock: Arc<tokio::sync::Mutex<()>>,
    u6_state: Mutex<Option<Arc<crate::ServerState>>>,
    u6_required: AtomicBool,
    u9_runner_tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    u9_runner_lock: Arc<tokio::sync::Mutex<()>>,
    u9_state: Mutex<Option<Arc<crate::ServerState>>>,
    u9_required: AtomicBool,
    #[cfg(test)]
    core_runner_events: Arc<Mutex<Vec<&'static str>>>,
    core: Mutex<CoreProcess>,
    readiness: ZoneRuntimeReadiness,
    policy_installed: bool,
    controller_endpoint_registered: bool,
    watch_admitted: bool,
    assignments: AssignmentRegistry,
    core_assignment_epoch: Arc<AtomicU64>,
    authority_index: Arc<tokio::sync::Mutex<HostGlobalAuthorityIndex>>,
    authority_persistence: Arc<RedbAuthorityPersistence>,
    authority_recovery: Arc<AuthorityRecoveryCoordinator>,
    zone_status: Mutex<ZoneStatusResource>,
    audio_runtime: Arc<Mutex<Option<AudioResourceRuntime>>>,
    device_binding_watch_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    process_runner_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    process_runner_generation: Mutex<Option<ControllerGeneration>>,
    guest_setup_descriptors: BTreeMap<String, Vec<u8>>,
    guest_setup_descriptor_catalog_keys: BTreeMap<String, String>,
    closed_guest_sessions: Arc<tokio::sync::Mutex<BTreeSet<crate::GuestComponentSessionKey>>>,
    controller_deployment: ProviderDeployment,
    controller_sessions: Arc<Mutex<BTreeMap<ResourceRef, ControllerSession>>>,
    controller_session_reconcile_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    controller_session_lock: Arc<tokio::sync::Mutex<()>>,
    controller_reconcile_lock: Arc<tokio::sync::Mutex<()>>,
    cloud_hypervisor_reconcile_lock: Arc<tokio::sync::Mutex<()>>,
    shared_provider_effects: Arc<dyn SharedProviderEffectExecutor>,
    interaction_provider_configuration: Option<CommittedInteractionProviderConfiguration>,
    interaction_identity: Option<CommittedInteractionIdentity>,
    interaction_provider_configuration_refused: bool,
}

/// Store-derived admission evidence for one security-key Device effect.
///
/// This contains only the exact values validated against the authoritative
/// resource record. It is consumed by the Device effect adapter before it can
/// request a broker-opened descriptor.
#[allow(dead_code)]
#[allow(dead_code)]
pub(crate) struct SecurityKeyDeviceAdmission {
    pub(crate) zone_ref: ResourceRef,
    pub(crate) device_uid: ResourceUid,
    pub(crate) holder_ref: ResourceRef,
    pub(crate) selector_id: String,
}

/// Request fields that select the Device admission record to validate.
#[allow(dead_code)]
#[allow(dead_code)]
pub(crate) struct SecurityKeyDeviceAdmissionRequest<'a> {
    pub(crate) device_uid: &'a ResourceUid,
    pub(crate) device_ref: &'a ResourceRef,
    pub(crate) request_zone_ref: &'a ResourceRef,
    pub(crate) holder_ref: &'a ResourceRef,
    pub(crate) vm_id: &'a str,
    pub(crate) selector_id: &'a str,
    pub(crate) operation_id: &'a str,
}

impl core::fmt::Debug for ZoneResourceRuntime {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ZoneResourceRuntime")
            .field("zone", &self.zone)
            .field("has_authority_identity", &self.authority_identity.is_some())
            .field("store_id", &"<opaque>")
            .field("current_revision", &self.store_metadata.current_revision)
            .field("readiness", &self.readiness)
            .finish()
    }
}

impl ZoneResourceRuntime {
    /// Install the daemon-owned typed effect executor used by U8 Provider
    /// runners. The binding is replaced only during trusted composition.
    pub(crate) fn set_shared_provider_effects(
        &mut self,
        effects: Arc<dyn SharedProviderEffectExecutor>,
    ) {
        self.shared_provider_effects = effects;
    }

    /// Open one Zone from a broker-owned descriptor.
    pub async fn open(zone: ZoneId, opened: OpenedZoneStore) -> Result<Self, ResourceRuntimeError> {
        Self::open_internal(
            zone,
            opened,
            None,
            Arc::new(BrokerEvidenceIndex::default()),
            None,
            false,
            None,
            None,
        )
        .await
    }

    /// Open one Zone with the production-owned durable audit sink.
    pub async fn open_with_audit(
        zone: ZoneId,
        opened: OpenedZoneStore,
        audit_sink: Arc<AuditSink>,
    ) -> Result<Self, ResourceRuntimeError> {
        Self::open_internal(
            zone,
            opened,
            Some(audit_sink),
            Arc::new(BrokerEvidenceIndex::default()),
            None,
            false,
            None,
            None,
        )
        .await
    }

    /// Open one Zone with durable audit and broker reconciliation evidence.
    pub async fn open_with_audit_and_evidence(
        zone: ZoneId,
        opened: OpenedZoneStore,
        audit_sink: Arc<AuditSink>,
        broker_evidence: Arc<BrokerEvidenceIndex>,
    ) -> Result<Self, ResourceRuntimeError> {
        Self::open_internal(
            zone,
            opened,
            Some(audit_sink),
            broker_evidence,
            None,
            false,
            None,
            None,
        )
        .await
    }

    /// Open one Zone with explicit audit, broker-evidence, and telemetry
    /// ownership.
    pub async fn open_with_audit_and_evidence_and_telemetry(
        zone: ZoneId,
        opened: OpenedZoneStore,
        audit_sink: Arc<AuditSink>,
        broker_evidence: Arc<BrokerEvidenceIndex>,
        telemetry_path: impl Into<std::path::PathBuf>,
    ) -> Result<Self, ResourceRuntimeError> {
        Self::open_internal(
            zone,
            opened,
            Some(audit_sink),
            broker_evidence,
            Some(telemetry_path.into()),
            false,
            None,
            None,
        )
        .await
    }

    /// Open a production Zone with a bundle-bound immutable identity.
    pub(crate) async fn open_production_with_identity(
        zone: ZoneId,
        opened: OpenedZoneStore,
        audit_sink: Arc<AuditSink>,
        broker_evidence: Arc<BrokerEvidenceIndex>,
        telemetry_path: impl Into<std::path::PathBuf>,
        desired_bundle: ResourceBundle,
        authority_identity: ZoneAuthorityIdentity,
    ) -> Result<Self, ResourceRuntimeError> {
        Self::open_internal(
            zone,
            opened,
            Some(audit_sink),
            broker_evidence,
            Some(telemetry_path.into()),
            true,
            Some(desired_bundle),
            Some(authority_identity),
        )
        .await
    }

    async fn open_internal(
        zone: ZoneId,
        opened: OpenedZoneStore,
        audit_sink: Option<Arc<AuditSink>>,
        broker_evidence: Arc<BrokerEvidenceIndex>,
        telemetry_path: Option<std::path::PathBuf>,
        bootstrap_provisioned_store: bool,
        desired_bundle: Option<ResourceBundle>,
        authority_identity: Option<ZoneAuthorityIdentity>,
    ) -> Result<Self, ResourceRuntimeError> {
        #[cfg(test)]
        let audit_sink = audit_sink.or_else(|| {
            let base = std::env::var_os("TEST_TMPDIR")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| {
                    std::env::var_os("CARGO_MANIFEST_DIR")
                        .map(std::path::PathBuf::from)
                        .or_else(|| std::env::current_dir().ok())
                        .expect("resolve resource runtime scratch root")
                        .join("target")
                        .join("tmp")
                });
            let path = base.join(format!(
                "d2bd-resource-audit-{}-{}-{}",
                zone.as_str(),
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|duration| duration.as_nanos())
                    .unwrap_or_default()
            ));
            AuditSink::open(path).ok().map(Arc::new)
        });
        #[cfg(not(test))]
        let audit_sink = audit_sink;
        let external_inventory = opened.external_inventory.clone().unwrap_or_else(|| {
            Arc::new(TrustedExternalNicInventory::default())
                as Arc<dyn ExternalNicRecoveryInventory>
        });
        Self::open_with_external_inventory_and_audit(
            zone,
            opened,
            external_inventory,
            audit_sink,
            broker_evidence,
            telemetry_path,
            bootstrap_provisioned_store,
            desired_bundle,
            authority_identity,
        )
        .await
    }

    /// Open one Zone with the host/bundle-owned physical-NIC inventory port.
    pub async fn open_with_external_inventory(
        zone: ZoneId,
        opened: OpenedZoneStore,
        external_inventory: Arc<dyn ExternalNicRecoveryInventory>,
    ) -> Result<Self, ResourceRuntimeError> {
        Self::open_with_external_inventory_and_audit(
            zone,
            opened,
            external_inventory,
            None,
            Arc::new(BrokerEvidenceIndex::default()),
            None,
            false,
            None,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn open_with_external_inventory_and_audit(
        zone: ZoneId,
        opened: OpenedZoneStore,
        external_inventory: Arc<dyn ExternalNicRecoveryInventory>,
        audit_sink: Option<Arc<AuditSink>>,
        broker_evidence: Arc<BrokerEvidenceIndex>,
        telemetry_path: Option<std::path::PathBuf>,
        bootstrap_provisioned_store: bool,
        desired_bundle: Option<ResourceBundle>,
        authority_identity: Option<ZoneAuthorityIdentity>,
    ) -> Result<Self, ResourceRuntimeError> {
        let expected_store_id = format!("zone-store-{}", zone.as_str());
        if opened.response.zone_store_id.as_str() != expected_store_id {
            return Err(ResourceRuntimeError::BrokerResponseMismatch);
        }
        if opened.response.fd_index != 0 {
            return Err(ResourceRuntimeError::BrokerFdCountMismatch);
        }
        if !matches!(
            opened.response.disposition,
            ZoneStoreDisposition::Provisioned | ZoneStoreDisposition::Opened
        ) {
            return Err(ResourceRuntimeError::BrokerDispositionInvalid);
        }

        let disposition = opened.response.disposition;
        let store_identity = if let Some(authority) = authority_identity.as_ref() {
            let bundle = desired_bundle
                .as_ref()
                .ok_or(ResourceRuntimeError::IdentityUnbound)?;
            if bundle.zone_uid() != Some(authority.zone_uid())
                || bundle.integrity().content_hash != authority.bundle_generation().as_str()
            {
                return Err(ResourceRuntimeError::HandlerNotReady);
            }
            if !d2b_contracts_resource::v3::is_canonical_digest(&opened.response.store_identity) {
                return Err(ResourceRuntimeError::BrokerResponseMismatch);
            }
            store_identity_for_authority(&zone, authority)?
        } else {
            store_identity(&zone, &opened.response.store_identity)?
        };
        let store_identity =
            if bootstrap_provisioned_store && disposition == ZoneStoreDisposition::Provisioned {
                store_identity.with_revisions(initial_policy_snapshot()?)
            } else {
                store_identity
            };
        let bundle_resource_types = desired_bundle
            .as_ref()
            .map(|bundle| {
                bundle
                    .resources
                    .iter()
                    .map(|resource| resource.resource_type().clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let authorizer = Arc::new(runtime_authorizer(&bundle_resource_types)?);
        let assignments = new_assignment_registry();
        let acceptor = authorizer
            .take_store_seal(store_identity.seal_identity())
            .map_err(|_| ResourceRuntimeError::StoreSealUnavailable)?;
        let file = File::from(opened.database_fd);
        let store = match disposition {
            ZoneStoreDisposition::Provisioned => {
                let mut marker =
                    tempfile::tempfile().map_err(|_| ResourceRuntimeError::StoreOpenFailed)?;
                write_provisioning_marker(&mut marker, &store_identity)
                    .map_err(|_| ResourceRuntimeError::StoreOpenFailed)?;
                match audit_sink {
                    Some(sink) => {
                        match telemetry_path.as_ref() {
                            Some(path) => {
                                RedbResourceStore::provision_owned_with_audit_and_evidence_and_telemetry(
                                    file,
                                    marker,
                                    store_identity,
                                    acceptor,
                                    sink,
                                    broker_evidence,
                                    path,
                                )
                                .await
                            }
                            None => {
                                RedbResourceStore::provision_owned_with_audit_and_evidence(
                                    file,
                                    marker,
                                    store_identity,
                                    acceptor,
                                    sink,
                                    broker_evidence,
                                )
                                .await
                            }
                        }
                    }
                    None => {
                        RedbResourceStore::provision_owned(file, marker, store_identity, acceptor)
                            .await
                    }
                }
            }
            ZoneStoreDisposition::Opened => match audit_sink {
                Some(sink) => {
                    match telemetry_path.as_ref() {
                        Some(path) => {
                            RedbResourceStore::open_owned_with_audit_and_evidence_and_telemetry(
                                file,
                                store_identity,
                                acceptor,
                                sink,
                                broker_evidence,
                                path,
                            )
                            .await
                        }
                        None => {
                            RedbResourceStore::open_owned_with_audit_and_evidence(
                                file,
                                store_identity,
                                acceptor,
                                sink,
                                broker_evidence,
                            )
                            .await
                        }
                    }
                }
                None => RedbResourceStore::open_owned(file, store_identity, acceptor).await,
            },
        }
        .map_err(|_| ResourceRuntimeError::StoreOpenFailed)?;
        let store = Arc::new(store);
        let authority_persistence = Arc::new(
            RedbAuthorityPersistence::new(Arc::clone(&store))
                .with_external_inventory(external_inventory),
        );
        let authority_recovery = Arc::new(
            AuthorityRecoveryCoordinator::recover_with_provenance(
                authority_persistence.clone(),
                authority_persistence.as_ref(),
            )
            .await
            .map_err(|_| ResourceRuntimeError::AuthorityUnavailable)?,
        );
        let authority_index = authority_recovery.index();
        let store_metadata = store
            .runtime_metadata()
            .await
            .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;
        if let Some(authority) = authority_identity.as_ref() {
            if store_metadata.zone_uid != *authority.zone_uid()
                || store_metadata.store_uid != *authority.store_uid()
                || store_metadata.store_epoch != authority.store_epoch()
            {
                return Err(ResourceRuntimeError::HandlerNotReady);
            }
            if disposition == ZoneStoreDisposition::Opened
                && store_metadata.policy_snapshot.policy_revision != 0
            {
                validate_zone_self_resource(
                    &store,
                    &zone,
                    authority.zone_uid(),
                    authority.store_uid(),
                )
                .await?;
            }
        }
        tracing::error!(
            zone = %zone.as_str(),
            disposition = ?disposition,
            policy_revision = store_metadata.policy_snapshot.policy_revision,
            api_catalog_revision = store_metadata.policy_snapshot.api_catalog_revision,
            active_configuration_revision = %store_metadata
                .policy_snapshot
                .active_configuration_revision
                .get(),
            desired_resource_count = desired_bundle
                .as_ref()
                .map(|bundle| bundle.resources.len())
                .unwrap_or_default(),
            "resource runtime opened Zone store"
        );
        if desired_bundle
            .as_ref()
            .is_some_and(|bundle| bundle.zone != zone)
        {
            return Err(ResourceRuntimeError::HandlerNotReady);
        }
        let backend = Arc::new(RedbBackend::from_arc(Arc::clone(&store)));
        let api = Arc::new(
            ResourceService::new_with_zone_uid(
                Arc::clone(&backend),
                Arc::clone(&authorizer),
                authority_identity
                    .as_ref()
                    .map(|authority| authority.zone_uid().clone()),
            )
            .map_err(|_| ResourceRuntimeError::ResourceApiBindFailed)?,
        );
        let mut interaction_provider_configuration = None;
        let mut interaction_provider_configuration_refused = false;
        let mut interaction_identity = None;

        let mut core = CoreProcess::new();
        let mut bus = None;
        let mut registrar = None;
        let mut ingress = None;
        let mut service_task = None;
        let mut process_status_client = None;
        let mut core_controller_subject = None;
        let defer_activation = authority_identity.is_some();
        let (
            resource_api_ready,
            local_session_ready,
            policy_installed,
            controller_endpoint_registered,
            watch_admitted,
            stage,
            zone_status,
            authorization_state,
        ) = if store_metadata.policy_snapshot.policy_revision == 0 {
            let _ = core.connect_runtime(CoreRuntimeReadiness {
                store_ready: true,
                resource_api_ready: false,
                local_bus_ready: false,
                controller_endpoint_registered: false,
                authenticated_system_core_session: false,
            });
            (
                false,
                false,
                false,
                false,
                false,
                core.stage(),
                SystemCoreStatusEmitter::new()
                    .emit(
                        ZoneStatusInput::new(ResourcePhase::Pending, Vec::new())
                            .with_runtime_metadata(zone_runtime_metadata(
                                &store_metadata,
                                0,
                                false,
                                0,
                                Some(current_status_timestamp()),
                            )),
                    )
                    .map_err(|_| ResourceRuntimeError::HandlerNotReady)?,
                None,
            )
        } else {
            let (policy, state) = runtime_policy(
                &zone,
                &store_metadata.policy_snapshot,
                store_metadata.current_revision,
                &bundle_resource_types,
            )
            .inspect_err(|error| {
                tracing::error!(zone = %zone.as_str(), error = ?error, "resource runtime policy setup failed");
            })?;
            authorizer
                .replace_policy(policy.clone(), &state)
                .map_err(|error| {
                    tracing::error!(zone = %zone.as_str(), error = ?error, "resource runtime policy installation failed");
                    ResourceRuntimeError::AuthorizationUnavailable
                })?;
            let bus_authorizer = BusAuthorizer::from_shared(Arc::clone(&authorizer), state.clone())
                .map(|authorizer| authorizer.with_assignment_registry(Arc::clone(&assignments)))
                .map_err(|error| {
                    tracing::error!(zone = %zone.as_str(), error = ?error, "resource runtime bus authorizer setup failed");
                    ResourceRuntimeError::AuthorizationUnavailable
                })?;
            let (zone_bus, mut zone_registrar) =
                ZoneBus::new(zone.clone(), bus_authorizer, BusConfig::default())
                    .map_err(|error| {
                        tracing::error!(zone = %zone.as_str(), error = ?error, "resource runtime Zone bus setup failed");
                        ResourceRuntimeError::AuthenticationUnavailable
                    })?;
            let (zone_ingress, zone_service_task, status_client, subject_context) =
                register_system_core_session(
                    &mut zone_registrar,
                    Arc::clone(&api),
                    Arc::clone(&authorizer),
                    state.clone(),
                )
                .await
                .inspect_err(|error| {
                    tracing::error!(zone = %zone.as_str(), error = ?error, "resource runtime system-core session registration failed");
                })?;
            process_status_client = Some(Arc::clone(&status_client));
            core_controller_subject = Some(subject_context);
            if defer_activation {
                bus = Some(zone_bus);
                registrar = Some(zone_registrar);
                ingress = Some(zone_ingress);
                service_task = Some(zone_service_task);
                (
                    true,
                    true,
                    true,
                    true,
                    true,
                    core.stage(),
                    SystemCoreStatusEmitter::new()
                        .emit(
                            ZoneStatusInput::new(ResourcePhase::Pending, Vec::new())
                                .with_runtime_metadata(zone_runtime_metadata(
                                    &store_metadata,
                                    0,
                                    false,
                                    0,
                                    Some(current_status_timestamp()),
                                )),
                        )
                        .map_err(|_| ResourceRuntimeError::HandlerNotReady)?,
                    Some(state),
                )
            } else {
                if bootstrap_provisioned_store
                    && disposition == ZoneStoreDisposition::Provisioned
                    && desired_bundle.is_none()
                {
                    ensure_bootstrap_host_resource(&zone, &store, &status_client).await?;
                }
                if let Some(bundle) = desired_bundle.as_ref() {
                    materialize_zone_resource_bundle(&zone, bundle, &store, &status_client)
                        .await
                        .inspect_err(|error| {
                            tracing::error!(zone = %zone.as_str(), error = ?error, "resource runtime Zone bundle materialization failed");
                        })?;
                }
                let store_metadata = store
                    .runtime_metadata()
                    .await
                    .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;
                (
                    interaction_provider_configuration,
                    interaction_provider_configuration_refused,
                ) = match load_interaction_provider_configuration(
                    &zone,
                    &store,
                    store_metadata.current_revision,
                )
                .await
                {
                    Ok(None) => (None, false),
                    Ok(Some(configuration)) if configuration.is_complete() => {
                        (Some(configuration), false)
                    }
                    Ok(Some(_)) => {
                        tracing::error!(
                            zone = %zone.as_str(),
                            "resource runtime committed interaction Provider configuration is incomplete",
                        );
                        (None, true)
                    }
                    Err(error) => {
                        tracing::error!(
                            zone = %zone.as_str(),
                            error = %error,
                            "resource runtime committed interaction Provider configuration load failed",
                        );
                        (None, true)
                    }
                };
                interaction_identity = match load_committed_interaction_identity(
                    &zone,
                    &store,
                    store_metadata.current_revision,
                    interaction_provider_configuration.as_ref(),
                )
                .await
                {
                    Ok(identity) => identity,
                    Err(error) => {
                        tracing::error!(
                            zone = %zone.as_str(),
                            error = %error,
                            "resource runtime committed interaction identity load failed",
                        );
                        interaction_provider_configuration_refused = true;
                        None
                    }
                };
                let system_core = system_core_startup_result(&zone, &store)
                    .await
                    .inspect_err(|error| {
                        tracing::error!(
                            zone = %zone.as_str(),
                            error = ?error,
                            "resource runtime system-core startup summary failed"
                        );
                    })?;
                tracing::warn!(
                    zone = %zone.as_str(),
                    host_phase = ?system_core.host_phase,
                    user_phase = ?system_core.user_phase,
                    total_resources = system_core.total_resource_count,
                    "system-core shared runner startup summary completed",
                );
                let aggregate_handler_phase = if system_core.host_phase == HandlerPhase::Ready
                    && system_core.user_phase == HandlerPhase::Ready
                {
                    HandlerPhase::Ready
                } else {
                    HandlerPhase::Degraded
                };
                tracing::error!(
                    zone = %zone.as_str(),
                    host_phase = ?system_core.host_phase,
                    user_phase = ?system_core.user_phase,
                    core_phase = ?system_core.core_phase,
                    total_resource_count = system_core.total_resource_count,
                    "resource runtime system-core reconciliation result"
                );
                let stage = {
                    let recovered_authority = authority_index.lock().await;
                    core.start_production(
                    CoreRuntimeReadiness {
                        store_ready: true,
                        resource_api_ready: true,
                        local_bus_ready: true,
                        controller_endpoint_registered: true,
                        authenticated_system_core_session: true,
                    },
                    RecoverySnapshot {
                        startup_epoch: 0,
                        checkpoint_revision: store_metadata.current_revision.get(),
                        active_configuration_revision: store_metadata
                            .policy_snapshot
                            .active_configuration_revision
                            .get(),
                        provider_lease_count: 0,
                        controller_lease_count: 0,
                        ambiguous_operation_count: 0,
                        watch_admitted: true,
                    },
                    &recovered_authority,
                )
                .map_err(|error| {
                    let error = map_startup_error(error);
                    tracing::error!(zone = %zone.as_str(), error = ?error, "resource runtime core startup failed");
                    error
                })?;
                    d2bd_runtime::resource_runtime_support::mark_core_handlers(
                    &mut core,
                    aggregate_handler_phase,
                    store_metadata.current_revision.get(),
                )
                .inspect_err(|error| {
                    tracing::error!(zone = %zone.as_str(), error = ?error, "resource runtime handler marking failed");
                })?;
                    core.publish_readiness().map_err(|error| {
                    let error = map_startup_error(error);
                    tracing::error!(zone = %zone.as_str(), error = ?error, "resource runtime readiness publication failed");
                    error
                })?
                };
                bus = Some(zone_bus);
                registrar = Some(zone_registrar);
                ingress = Some(zone_ingress);
                service_task = Some(zone_service_task);
                (
                    true,
                    true,
                    true,
                    true,
                    true,
                    stage,
                    SystemCoreStatusEmitter::new()
                        .emit(
                            ZoneStatusInput::new(system_core.core_phase, Vec::new())
                                .with_system_core_phases(
                                    handler_phase_to_zone_phase(system_core.host_phase),
                                    handler_phase_to_zone_phase(system_core.user_phase),
                                )
                                .with_runtime_metadata(zone_runtime_metadata(
                                    &store_metadata,
                                    system_core.total_resource_count,
                                    system_core.generation_cleanup_pending,
                                    system_core.cleanup_pending_count,
                                    Some(current_status_timestamp()),
                                )),
                        )
                        .map_err(|_| ResourceRuntimeError::HandlerNotReady)?,
                    Some(state),
                )
            }
        };
        let store_metadata = store
            .runtime_metadata()
            .await
            .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;
        let defer_core_start = authority_identity.is_some();
        let runtime = Self {
            zone,
            authority_identity,
            bootstrap_provisioned_store: bootstrap_provisioned_store
                && disposition == ZoneStoreDisposition::Provisioned,
            store_id: expected_store_id,
            store,
            store_metadata,
            backend,
            api,
            authorizer,
            authorization_state: Arc::new(Mutex::new(authorization_state)),
            policy_refresh: Mutex::new(()),
            bundle_resource_types,
            policy_subject_fingerprints: Mutex::new(BTreeMap::new()),
            policy_loaded: Mutex::new(false),
            bus,
            registrar: Arc::new(Mutex::new(registrar)),
            ingress: Mutex::new(ingress),
            service_task: Mutex::new(service_task),
            process_status_client: Mutex::new(process_status_client),
            core_controller_subject: Mutex::new(core_controller_subject),
            core_runner_tasks: Mutex::new(Vec::new()),
            core_runner_lock: Arc::new(tokio::sync::Mutex::new(())),
            u12_runner_tasks: Mutex::new(Vec::new()),
            u12_runner_lock: Arc::new(tokio::sync::Mutex::new(())),
            u12_state: Mutex::new(None),
            u12_required: AtomicBool::new(false),
            u7_runner_tasks: Mutex::new(Vec::new()),
            u7_runner_lock: Arc::new(tokio::sync::Mutex::new(())),
            u7_state: Mutex::new(None),
            u7_required: AtomicBool::new(false),
            u6_runner_tasks: Mutex::new(Vec::new()),
            u6_runner_lock: Arc::new(tokio::sync::Mutex::new(())),
            u6_state: Mutex::new(None),
            u6_required: AtomicBool::new(false),
            u9_runner_tasks: Mutex::new(Vec::new()),
            u9_runner_lock: Arc::new(tokio::sync::Mutex::new(())),
            u9_state: Mutex::new(None),
            u9_required: AtomicBool::new(false),
            #[cfg(test)]
            core_runner_events: Arc::new(Mutex::new(Vec::new())),
            core: Mutex::new(core),
            readiness: ZoneRuntimeReadiness {
                store_ready: true,
                resource_api_ready,
                local_session_ready,
                provider_path_ready: false,
                authority_ready: true,
                core_stage: stage,
            },
            policy_installed,
            controller_endpoint_registered,
            watch_admitted,
            assignments,
            core_assignment_epoch: Arc::new(AtomicU64::new(0)),
            authority_index,
            authority_persistence,
            authority_recovery,
            zone_status: Mutex::new(zone_status),
            audio_runtime: Arc::new(Mutex::new(None)),
            device_binding_watch_task: Mutex::new(None),
            process_runner_task: Mutex::new(None),
            process_runner_generation: Mutex::new(None),
            guest_setup_descriptors: BTreeMap::new(),
            guest_setup_descriptor_catalog_keys: BTreeMap::new(),
            closed_guest_sessions: Arc::new(tokio::sync::Mutex::new(BTreeSet::new())),
            controller_deployment: ProviderDeployment::new(
                DaemonMode::Host,
                d2bd_runtime::target_runtime::AdmissionLimits::host_default(),
            )
            .map_err(|_| ResourceRuntimeError::CoreStartupFailed)?,
            controller_sessions: Arc::new(Mutex::new(BTreeMap::new())),
            controller_session_reconcile_task: Arc::new(Mutex::new(None)),
            controller_session_lock: Arc::new(tokio::sync::Mutex::new(())),
            controller_reconcile_lock: Arc::new(tokio::sync::Mutex::new(())),
            cloud_hypervisor_reconcile_lock: Arc::new(tokio::sync::Mutex::new(())),
            shared_provider_effects: Arc::new(UnavailableSharedProviderEffects),
            interaction_provider_configuration,
            interaction_identity,
            interaction_provider_configuration_refused,
        };
        if !defer_core_start && runtime.readiness.resource_api_ready {
            if let Err(error) = runtime.start_core_controller_runners().await {
                #[cfg(not(test))]
                return Err(error);
                #[cfg(test)]
                if error != ResourceRuntimeError::ProviderPathUnavailable {
                    return Err(error);
                }
            }
        }
        Ok(runtime)
    }

    /// Materialize the verified bundle after the complete local generation
    /// has passed its read-only validation barrier.
    pub(crate) async fn materialize_desired_bundle(
        &self,
        bundle: &ResourceBundle,
    ) -> Result<(), ResourceRuntimeError> {
        let client = self.status_client()?;
        materialize_zone_resource_bundle(&self.zone, bundle, &self.store, &client).await
    }

    /// Validate the desired bundle without advancing this Zone store.
    pub(crate) async fn validate_desired_bundle(
        &self,
        bundle: &ResourceBundle,
    ) -> Result<(), ResourceRuntimeError> {
        validate_zone_resource_bundle(&self.zone, bundle, &self.store).await
    }

    /// Durably stage the complete local generation set in the coordinator
    /// Zone's operation ledger. The operation is idempotent across daemon
    /// restarts and retired rows do not fence a later generation.
    pub(crate) async fn prepare_generation_publication(
        &self,
        set_generation: &ResourceBundleGenerationId,
        generations: &BTreeMap<ZoneId, ResourceBundleGenerationId>,
    ) -> Result<(), ResourceRuntimeError> {
        let zones = generations.keys().cloned().collect::<BTreeSet<_>>();
        let expected_set_generation = complete_generation_set_digest(&zones, generations)
            .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
        if &expected_set_generation != set_generation {
            return Err(ResourceRuntimeError::HandlerNotReady);
        }
        let authority = self
            .authority_identity
            .as_ref()
            .ok_or(ResourceRuntimeError::IdentityUnbound)?;
        if generations.get(&self.zone) != Some(authority.bundle_generation()) {
            return Err(ResourceRuntimeError::HandlerNotReady);
        }
        let operation_id = generation_publication_operation_id(set_generation);
        let binding_digest = self.store.authority_binding_digest(set_generation.as_str());
        let payload = generation_publication_payload(set_generation, &binding_digest, generations)?;
        let operations = self
            .store
            .authority_operations()
            .await
            .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
        if operations.iter().any(|operation| {
            operation
                .operation_id
                .starts_with(ZONE_GENERATION_PUBLICATION_OPERATION_PREFIX)
                && operation.operation_id != operation_id
                && !matches!(
                    operation.state,
                    AuthorityOperationState::Closed | AuthorityOperationState::Released
                )
        }) {
            return Err(ResourceRuntimeError::HandlerNotReady);
        }
        if let Some(operation) = operations
            .iter()
            .find(|operation| operation.operation_id == operation_id)
        {
            if !generation_publication_payload_matches(
                &operation.payload,
                set_generation,
                &binding_digest,
                generations,
            ) {
                return Err(ResourceRuntimeError::HandlerNotReady);
            }
            return Ok(());
        }
        self.store
            .prepare_authority_operation(operation_id, payload, set_generation.as_str())
            .await
            .map(|_| ())
            .map_err(|_| ResourceRuntimeError::HandlerNotReady)
    }

    /// Mark a fully materialized generation set as published, then close and
    /// release its marker so a later generation can be admitted.
    pub(crate) async fn commit_generation_publication(
        &self,
        set_generation: &ResourceBundleGenerationId,
        generations: &BTreeMap<ZoneId, ResourceBundleGenerationId>,
    ) -> Result<(), ResourceRuntimeError> {
        let zones = generations.keys().cloned().collect::<BTreeSet<_>>();
        let expected_set_generation = complete_generation_set_digest(&zones, generations)
            .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
        if &expected_set_generation != set_generation {
            return Err(ResourceRuntimeError::HandlerNotReady);
        }
        let authority = self
            .authority_identity
            .as_ref()
            .ok_or(ResourceRuntimeError::IdentityUnbound)?;
        if generations.get(&self.zone) != Some(authority.bundle_generation()) {
            return Err(ResourceRuntimeError::HandlerNotReady);
        }
        let operation_id = generation_publication_operation_id(set_generation);
        let binding_digest = self.store.authority_binding_digest(set_generation.as_str());
        let operation = self
            .store
            .authority_operations()
            .await
            .map_err(|_| ResourceRuntimeError::HandlerNotReady)?
            .into_iter()
            .find(|operation| operation.operation_id == operation_id)
            .ok_or(ResourceRuntimeError::HandlerNotReady)?;
        if !generation_publication_payload_matches(
            &operation.payload,
            set_generation,
            &binding_digest,
            generations,
        ) {
            return Err(ResourceRuntimeError::HandlerNotReady);
        }
        let state = operation.state;
        if matches!(
            state,
            AuthorityOperationState::Closed | AuthorityOperationState::Released
        ) {
            return Ok(());
        }
        let capability = self
            .store
            .resume_authority_operation(operation_id, &binding_digest)
            .await
            .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
        match state {
            AuthorityOperationState::Pending | AuthorityOperationState::EffectRetryable => {
                capability
                    .record_effect(AuthorityOperationState::EffectConfirmed)
                    .await
                    .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
                capability
                    .record_close()
                    .await
                    .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
            }
            AuthorityOperationState::EffectConfirmed => {
                capability
                    .record_close()
                    .await
                    .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
            }
            AuthorityOperationState::Closing => {}
            AuthorityOperationState::EffectTerminal => {
                return Err(ResourceRuntimeError::HandlerNotReady);
            }
            AuthorityOperationState::Closed | AuthorityOperationState::Released => {
                unreachable!("terminal publication state returned above")
            }
        }
        capability
            .release()
            .await
            .map_err(|_| ResourceRuntimeError::HandlerNotReady)
    }

    /// Materialize a validated bundle and provision bootstrap rows only after
    /// the complete local generation set has been durably prepared.
    pub(crate) async fn prepare_published_bundle(
        &self,
        bundle: &ResourceBundle,
    ) -> Result<(), ResourceRuntimeError> {
        self.materialize_desired_bundle(bundle)
            .await
            .inspect_err(|error| {
                tracing::error!(
                    zone = %self.zone.as_str(),
                    error = ?error,
                    "resource runtime desired bundle materialization failed"
                );
            })?;
        if self.bootstrap_provisioned_store {
            let client = self.status_client()?;
            if let Some(authority) = self.authority_identity.as_ref() {
                ensure_bootstrap_zone_resource(
                    &self.zone,
                    authority.zone_uid(),
                    &self.store,
                    &client,
                )
                .await
                .inspect_err(|error| {
                    tracing::error!(
                        zone = %self.zone.as_str(),
                        error = ?error,
                        "resource runtime Zone self bootstrap failed"
                    );
                })?;
            }
            if !bundle
                .resources
                .iter()
                .any(|resource| resource.resource_type().as_str() == "Host")
            {
                ensure_bootstrap_host_resource(&self.zone, &self.store, &client)
                    .await
                    .inspect_err(|error| {
                        tracing::error!(
                            zone = %self.zone.as_str(),
                            error = ?error,
                            "resource runtime Host bootstrap failed"
                        );
                    })?;
            }
        }
        Ok(())
    }

    /// Finish deferred startup after the complete bundle is visible in the
    /// store. The shared Core runners own all Host/User observation and status
    /// writes after this point.
    pub(crate) async fn activate_published_bundle(&mut self) -> Result<(), ResourceRuntimeError> {
        self.refresh_authorization_policy().await?;
        let store_metadata = self
            .store
            .runtime_metadata()
            .await
            .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;

        (
            self.interaction_provider_configuration,
            self.interaction_provider_configuration_refused,
        ) = match load_interaction_provider_configuration(
            &self.zone,
            &self.store,
            store_metadata.current_revision,
        )
        .await
        {
            Ok(None) => (None, false),
            Ok(Some(configuration)) if configuration.is_complete() => (Some(configuration), false),
            Ok(Some(_)) => {
                tracing::error!(
                    zone = %self.zone.as_str(),
                    "resource runtime committed interaction Provider configuration is incomplete",
                );
                (None, true)
            }
            Err(error) => {
                tracing::error!(
                    zone = %self.zone.as_str(),
                    error = %error,
                    "resource runtime committed interaction Provider configuration load failed",
                );
                (None, true)
            }
        };
        self.interaction_identity = match load_committed_interaction_identity(
            &self.zone,
            &self.store,
            store_metadata.current_revision,
            self.interaction_provider_configuration.as_ref(),
        )
        .await
        {
            Ok(identity) => identity,
            Err(error) => {
                tracing::error!(
                    zone = %self.zone.as_str(),
                    error = %error,
                    "resource runtime committed interaction identity load failed",
                );
                self.interaction_provider_configuration_refused = true;
                None
            }
        };
        let system_core =
            system_core_startup_result(&self.zone, &self.store)
                .await
                .inspect_err(|error| {
                    tracing::error!(
                        zone = %self.zone.as_str(),
                        error = ?error,
                        "resource runtime system-core startup summary failed",
                    );
                })?;
        let aggregate_handler_phase = if system_core.host_phase == HandlerPhase::Ready
            && system_core.user_phase == HandlerPhase::Ready
        {
            HandlerPhase::Ready
        } else {
            HandlerPhase::Degraded
        };
        self.start_core_controller_runners().await?;
        let store_metadata = self
            .store
            .runtime_metadata()
            .await
            .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;
        let stage = {
            let recovered_authority = self.authority_index.lock().await;
            let mut core = self
                .core
                .lock()
                .map_err(|_| ResourceRuntimeError::CoreStartupFailed)?;
            core.start_production(
                CoreRuntimeReadiness {
                    store_ready: true,
                    resource_api_ready: true,
                    local_bus_ready: true,
                    controller_endpoint_registered: true,
                    authenticated_system_core_session: true,
                },
                RecoverySnapshot {
                    startup_epoch: 0,
                    checkpoint_revision: store_metadata.current_revision.get(),
                    active_configuration_revision: store_metadata
                        .policy_snapshot
                        .active_configuration_revision
                        .get(),
                    provider_lease_count: 0,
                    controller_lease_count: 0,
                    ambiguous_operation_count: 0,
                    watch_admitted: true,
                },
                &recovered_authority,
            )
            .map_err(map_startup_error)?;
            d2bd_runtime::resource_runtime_support::mark_core_handlers(
                &mut core,
                aggregate_handler_phase,
                store_metadata.current_revision.get(),
            )?;
            core.publish_readiness().map_err(map_startup_error)?
        };
        self.store_metadata = self
            .store
            .runtime_metadata()
            .await
            .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;
        self.zone_status = Mutex::new(
            SystemCoreStatusEmitter::new()
                .emit(
                    ZoneStatusInput::new(system_core.core_phase, Vec::new())
                        .with_system_core_phases(
                            handler_phase_to_zone_phase(system_core.host_phase),
                            handler_phase_to_zone_phase(system_core.user_phase),
                        )
                        .with_runtime_metadata(zone_runtime_metadata(
                            &self.store_metadata,
                            system_core.total_resource_count,
                            system_core.generation_cleanup_pending,
                            system_core.cleanup_pending_count,
                            Some(current_status_timestamp()),
                        )),
                )
                .map_err(|_| ResourceRuntimeError::HandlerNotReady)?,
        );
        self.readiness = ZoneRuntimeReadiness {
            store_ready: true,
            resource_api_ready: true,
            local_session_ready: true,
            provider_path_ready: self.readiness.provider_path_ready,
            authority_ready: true,
            core_stage: stage,
        };
        Ok(())
    }

    /// Borrow the authoritative Zone identity.
    pub const fn zone(&self) -> &ZoneId {
        &self.zone
    }

    /// Borrow the immutable Zone UID bound at production startup.
    pub(crate) fn authority_zone_uid(&self) -> Option<&ResourceUid> {
        self.authority_identity
            .as_ref()
            .map(ZoneAuthorityIdentity::zone_uid)
    }

    /// Borrow the content-addressed bundle generation bound at production
    /// startup.
    pub(crate) fn authority_bundle_generation(&self) -> Option<&ResourceBundleGenerationId> {
        self.authority_identity
            .as_ref()
            .map(ZoneAuthorityIdentity::bundle_generation)
    }

    /// Borrow the opaque store id used for the broker request.
    pub fn store_id(&self) -> &str {
        &self.store_id
    }

    /// Return the startup readiness projection.
    pub const fn readiness(&self) -> ZoneRuntimeReadiness {
        self.readiness
    }

    /// Borrow the Zone-scoped Core assignment registry.
    pub fn assignment_registry(&self) -> AssignmentRegistry {
        Arc::clone(&self.assignments)
    }

    /// Admit one controller assignment through the Zone-owned registry.
    ///
    /// Controller deployment supplies only the committed resource, signed
    /// role, installed generations, and authenticated session generation.
    /// The registry remains the single owner of assignment epochs and target
    /// conflicts; callers never receive a store handle. The session must
    /// already be present in the active controller-session table.
    pub fn admit_controller_assignment(
        &self,
        request: AssignmentRequest<'_>,
    ) -> Result<ResourceClientLease, AssignmentError> {
        let binding = request.session_binding()?;
        let active = self
            .controller_sessions
            .lock()
            .map(|sessions| {
                sessions
                    .get(binding.session_owner())
                    .is_some_and(|session| {
                        controller_session_matches(
                            &session.binding,
                            &binding,
                            session.service_task.is_finished(),
                        )
                    })
            })
            .unwrap_or(false);
        if !active {
            return Err(AssignmentError::SessionRevoked);
        }
        self.assignments
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .admit(request)
    }

    /// Revoke assignments bound to one exact controller session.
    pub fn revoke_controller_assignments(&self, binding: &ControllerSessionBinding) {
        if !d2b_provider_runtime_cloud_hypervisor::is_provider_ref(binding.provider_ref()) {
            return;
        }
        self.assignments
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .revoke_session_for(binding);
        let revocation_batch = match self.controller_sessions.lock() {
            Ok(sessions) => sessions
                .get(binding.session_owner())
                .filter(|session| &session.binding == binding)
                .map(|session| {
                    let frames = session
                        .assignments
                        .values()
                        .filter_map(|lease| {
                            ControllerAssignmentGrant::encode_revocation(
                                lease.provider_ref(),
                                lease.identity(),
                            )
                            .ok()
                        })
                        .collect();
                    (session.driver.clone(), frames)
                }),
            Err(_) => None,
        };
        if let Some((driver, frames)) = revocation_batch {
            self.schedule_assignment_revocations(driver, frames);
        }
    }

    /// Mark one assignment as draining before a target or generation handoff.
    pub fn drain_controller_assignment(
        &self,
        identity: &AssignmentIdentity,
    ) -> Result<(), AssignmentError> {
        let result = self
            .assignments
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .begin_drain(identity);
        if result.is_ok() {
            self.schedule_controller_assignment_revocation(identity);
        }
        result
    }

    /// Release a drained assignment after Core has verified its child index.
    pub fn release_controller_assignment(
        &self,
        identity: &AssignmentIdentity,
    ) -> Result<(), AssignmentError> {
        let revocation = self.controller_assignment_revocation(identity);
        let result = self
            .assignments
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .release(identity);
        if result.is_ok()
            && let Some((driver, bytes)) = revocation
        {
            self.schedule_assignment_revocations(driver, vec![bytes]);
        }
        result
    }

    fn controller_assignment_revocation(
        &self,
        identity: &AssignmentIdentity,
    ) -> Option<(SessionDriverHandle, Vec<u8>)> {
        let sessions = self.controller_sessions.lock().ok()?;
        sessions.values().find_map(|session| {
            let lease = session
                .assignments
                .values()
                .find(|lease| lease.identity() == identity)?;
            let bytes =
                ControllerAssignmentGrant::encode_revocation(lease.provider_ref(), identity)
                    .ok()?;
            Some((session.driver.clone(), bytes))
        })
    }

    fn schedule_controller_assignment_revocation(&self, identity: &AssignmentIdentity) {
        let Some((driver, bytes)) = self.controller_assignment_revocation(identity) else {
            return;
        };
        self.schedule_assignment_revocations(driver, vec![bytes]);
    }

    fn schedule_assignment_revocations(&self, driver: SessionDriverHandle, frames: Vec<Vec<u8>>) {
        if frames.is_empty() {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let stream = match StreamId::new(CONTROLLER_ASSIGNMENT_STREAM_ID) {
            Ok(stream) => stream,
            Err(_) => return,
        };
        handle.spawn(async move {
            for frame in frames {
                if let Err(error) = driver.send_named_stream(stream, frame).await {
                    tracing::warn!(
                        error = %error,
                        "controller assignment revocation delivery failed",
                    );
                    let _ = driver.reset_named_stream(stream).await;
                    break;
                }
            }
        });
    }

    /// Return the policy revision committed in the opened resource store.
    ///
    /// Interaction Providers bind this snapshot instead of carrying a
    /// route-derived policy placeholder.
    pub const fn committed_policy_snapshot(&self) -> PolicySnapshot {
        self.store_metadata.policy_snapshot
    }

    /// Return the durable resource revision used to fence interaction
    /// evidence against a later store commit.
    pub fn current_revision(&self) -> ZoneRevision {
        self.authorization_state
            .lock()
            .ok()
            .and_then(|state| state.as_ref().map(|state| state.zone_policy_revision))
            .unwrap_or(self.store_metadata.current_revision)
    }

    /// Refresh the native authorization projection from the current committed
    /// Role, RoleBinding, and local subject rows before admitting public work.
    pub(crate) async fn refresh_authorization_policy(&self) -> Result<(), ResourceRuntimeError> {
        let _refresh = self
            .policy_refresh
            .lock()
            .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?;
        let metadata = self
            .store
            .runtime_metadata()
            .await
            .map_err(|_| ResourceRuntimeError::PolicyUnavailable)?;
        let current = self
            .authorization_state
            .lock()
            .map_err(|_| ResourceRuntimeError::PolicyUnavailable)?
            .clone();
        let policy_loaded = *self
            .policy_loaded
            .lock()
            .map_err(|_| ResourceRuntimeError::PolicyUnavailable)?;
        if policy_loaded
            && current.as_ref().is_some_and(|state| {
                state.snapshot == metadata.policy_snapshot
                    && state.zone_policy_revision == metadata.current_revision
            })
        {
            return Ok(());
        }
        if metadata.policy_snapshot.policy_revision == 0 {
            return Err(ResourceRuntimeError::PolicyUnavailable);
        }
        let resources = d2bd_runtime::resource_runtime_support::load_committed_policy_resources(
            &self.store,
            &self.zone,
            &format!(
                "authorization-policy-refresh:{}",
                metadata.current_revision.get()
            ),
        )
        .await?;
        let current_metadata = self
            .store
            .runtime_metadata()
            .await
            .map_err(|_| ResourceRuntimeError::PolicyUnavailable)?;
        if current_metadata != metadata {
            return Err(ResourceRuntimeError::PolicyUnavailable);
        }
        let previous = self
            .policy_subject_fingerprints
            .lock()
            .map_err(|_| ResourceRuntimeError::IdentityUnbound)?
            .clone();
        let fingerprints = refreshed_policy_subject_fingerprints(&resources, &previous)?;
        let (policy, state) = d2bd_runtime::resource_runtime_support::compile_committed_policy(
            &self.zone,
            metadata.policy_snapshot,
            metadata.current_revision,
            &self.bundle_resource_types,
            &resources,
        )?;
        let rebind_core = self
            .core_controller_subject
            .lock()
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?
            .is_some();
        let _runner_guard = if rebind_core {
            Some(self.core_runner_lock.lock().await)
        } else {
            None
        };
        let _u12_runner_guard = if rebind_core {
            Some(self.u12_runner_lock.lock().await)
        } else {
            None
        };
        let _u7_runner_guard = if rebind_core {
            Some(self.u7_runner_lock.lock().await)
        } else {
            None
        };
        let _u6_runner_guard = if rebind_core {
            Some(self.u6_runner_lock.lock().await)
        } else {
            None
        };
        let _u9_runner_guard = if rebind_core {
            Some(self.u9_runner_lock.lock().await)
        } else {
            None
        };
        if rebind_core {
            self.stop_core_controller_runners_locked().await?;
            self.stop_u12_controller_runners_locked().await?;
            self.stop_u7_controller_runners_locked().await?;
            self.stop_u6_controller_runners_locked().await?;
            self.stop_u9_controller_runners_locked().await?;
        }
        self.authorizer
            .replace_policy(policy.clone(), &state)
            .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?;
        if let Some(bus) = &self.bus {
            bus.replace_policy(policy, state.clone())
                .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?;
        }
        if let Err(error) = self.refresh_system_core_session(state.clone()).await {
            self.authorizer.mark_policy_unavailable();
            if let Some(bus) = &self.bus {
                bus.mark_policy_unavailable();
            }
            if let Ok(mut installed) = self.authorization_state.lock() {
                *installed = None;
            }
            if let Ok(mut loaded) = self.policy_loaded.lock() {
                *loaded = false;
            }
            return Err(error);
        }
        *self
            .authorization_state
            .lock()
            .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)? = Some(state);
        *self
            .policy_subject_fingerprints
            .lock()
            .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)? = fingerprints;
        *self
            .policy_loaded
            .lock()
            .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)? = true;
        if rebind_core {
            if let Err(error) = self.start_core_controller_runners_locked(true).await {
                #[cfg(not(test))]
                return Err(error);
                #[cfg(test)]
                if error != ResourceRuntimeError::ProviderPathUnavailable {
                    return Err(error);
                }
            }
            let state = self
                .u12_state
                .lock()
                .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?
                .clone();
            if let Some(state) = state {
                self.start_u12_controller_runners_locked(state).await?;
            }
            let state = self
                .u7_state
                .lock()
                .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?
                .clone();
            if let Some(state) = state {
                self.start_u7_controller_runners_locked(state).await?;
            }
            let state = self
                .u6_state
                .lock()
                .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?
                .clone();
            if let Some(state) = state {
                self.start_u6_controller_runners_locked(state).await?;
            }
            let state = self
                .u9_state
                .lock()
                .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?
                .clone();
            if let Some(state) = state {
                self.start_u9_controller_runners_locked(state).await?;
            }
        }
        Ok(())
    }

    /// Re-enroll the fixed internal system-core session after a policy
    /// revision change so its old lease cannot continue past the fence.
    async fn refresh_system_core_session(
        &self,
        state: AuthorizationState,
    ) -> Result<(), ResourceRuntimeError> {
        let mut registrar = self
            .registrar
            .lock()
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?
            .take();
        let mut ingress = self
            .ingress
            .lock()
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?
            .take();
        let task = self
            .service_task
            .lock()
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?
            .take();
        if let (Some(registrar), Some(mut ingress)) = (registrar.as_mut(), ingress.as_mut()) {
            registrar
                .revoke_in_place(&mut ingress)
                .await
                .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?;
        }
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
        }
        let Some(mut registrar) = registrar else {
            return Ok(());
        };
        let (new_ingress, new_task, status_client, subject_context) =
            register_system_core_session(
                &mut registrar,
                Arc::clone(&self.api),
                Arc::clone(&self.authorizer),
                state,
            )
            .await?;
        *self
            .registrar
            .lock()
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)? = Some(registrar);
        *self
            .ingress
            .lock()
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)? = Some(new_ingress);
        *self
            .service_task
            .lock()
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)? = Some(new_task);
        *self
            .process_status_client
            .lock()
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)? = Some(status_client);
        *self
            .core_controller_subject
            .lock()
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)? = Some(subject_context);
        Ok(())
    }

    /// Issue one sealed Guest lifecycle lease from the authenticated local
    /// peer and the current store identities.
    pub(crate) async fn admit_guest_lifecycle(
        &self,
        peer_uid: u32,
        target: ResourceRef,
        operation_id: &str,
    ) -> Result<d2b_resource_api::service::GuestLifecycleAdmission, ResourceRuntimeError> {
        self.refresh_authorization_policy().await?;
        let resolved_user = d2bd_runtime::resource_runtime_support::resolve_zone_user(
            &self.store,
            &self.zone,
            peer_uid,
            &format!("{operation_id}:user"),
        )
        .await?;
        let context = d2bd_runtime::resource_runtime_support::local_user_subject_context(
            &self.zone,
            &resolved_user,
            operation_id,
        )?;
        let state = self
            .authorization_state
            .lock()
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?
            .clone()
            .ok_or(ResourceRuntimeError::AuthenticationUnavailable)?;
        let subject = self
            .authorizer
            .issue_authenticated_subject(context, state)
            .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?;
        self.api
            .admit_guest_lifecycle(&subject, target, operation_id.to_owned())
            .await
            .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)
    }

    /// Issue a lifecycle lease through the already enrolled system-core
    /// ComponentSession for daemon-owned autostart.
    pub(crate) async fn admit_internal_guest_lifecycle(
        &self,
        target: ResourceRef,
        operation_id: &str,
    ) -> Result<d2b_resource_api::service::GuestLifecycleAdmission, ResourceRuntimeError> {
        let client = self
            .process_resource_client()
            .ok_or(ResourceRuntimeError::AuthenticationUnavailable)?;
        client
            .admit_guest_lifecycle(target, operation_id.to_owned())
            .await
            .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)
    }

    /// Read the immutable Guest and Provider identities needed by the
    /// guarded host-shutdown stop capability.
    pub(crate) async fn guest_lifecycle_identity(
        &self,
        target: &ResourceRef,
    ) -> Result<
        (
            ResourceUid,
            ResourceUid,
            ResourceGeneration,
            ResourceGeneration,
        ),
        ResourceRuntimeError,
    > {
        if target.resource_type().as_str() != "Guest" {
            return Err(ResourceRuntimeError::RequestInvalid);
        }
        let guest = self
            .store
            .get(StoreGetRequest {
                operation: StoreOperationContext {
                    operation_id: "guest-lifecycle-identity".to_owned(),
                    idempotency_key: None,
                    correlation_id: "guest-lifecycle-identity".to_owned(),
                    trace_id: None,
                    deadline_ms: 10_000,
                },
                zone: self.zone.clone(),
                target: target.clone(),
                expected_uid: None,
                projection: StoreProjection::Full,
            })
            .await
            .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;
        if guest.zone != self.zone
            || guest.resource_ref != *target
            || guest.uid.as_str().is_empty()
            || guest.generation.get() == 0
        {
            return Err(ResourceRuntimeError::RequestInvalid);
        }
        let envelope = ResourceEnvelope::from_json(&guest.canonical_json)
            .map_err(|_| ResourceRuntimeError::RequestInvalid)?;
        if envelope.resource_type().as_str() != "Guest"
            || envelope.metadata().zone() != &self.zone
            || envelope.metadata().uid() != &guest.uid
            || envelope.metadata().generation() != guest.generation
            || envelope.metadata().revision() != guest.revision
            || envelope
                .digest()
                .map_err(|_| ResourceRuntimeError::RequestInvalid)?
                != guest.payload_digest
        {
            return Err(ResourceRuntimeError::RequestInvalid);
        }
        let provider_ref = envelope
            .spec()
            .provider_ref()
            .cloned()
            .ok_or(ResourceRuntimeError::RequestInvalid)?;
        let provider = self
            .store
            .get(StoreGetRequest {
                operation: StoreOperationContext {
                    operation_id: "guest-lifecycle-provider-identity".to_owned(),
                    idempotency_key: None,
                    correlation_id: "guest-lifecycle-provider-identity".to_owned(),
                    trace_id: None,
                    deadline_ms: 10_000,
                },
                zone: self.zone.clone(),
                target: provider_ref,
                expected_uid: None,
                projection: StoreProjection::Full,
            })
            .await
            .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;
        if provider.zone != self.zone
            || provider.resource_ref.resource_type().as_str() != "Provider"
            || provider.generation.get() == 0
        {
            return Err(ResourceRuntimeError::RequestInvalid);
        }
        let provider_envelope = ResourceEnvelope::from_json(&provider.canonical_json)
            .map_err(|_| ResourceRuntimeError::RequestInvalid)?;
        if provider_envelope.resource_type().as_str() != "Provider"
            || provider_envelope.metadata().zone() != &self.zone
            || provider_envelope.metadata().uid() != &provider.uid
            || provider_envelope.metadata().generation() != provider.generation
            || provider_envelope.metadata().revision() != provider.revision
            || provider_envelope
                .digest()
                .map_err(|_| ResourceRuntimeError::RequestInvalid)?
                != provider.payload_digest
        {
            return Err(ResourceRuntimeError::RequestInvalid);
        }
        Ok((
            self.store_metadata.zone_uid.clone(),
            guest.uid,
            guest.generation,
            provider.generation,
        ))
    }

    /// Read the committed Provider route for one Guest without consulting
    /// the legacy manifest or process-DAG connector.
    pub(crate) async fn guest_provider_ref(
        &self,
        target: &ResourceRef,
    ) -> Result<ResourceRef, ResourceRuntimeError> {
        if target.resource_type().as_str() != "Guest" {
            return Err(ResourceRuntimeError::RequestInvalid);
        }
        let guest = self
            .store
            .get(StoreGetRequest {
                operation: StoreOperationContext {
                    operation_id: "guest-provider-route".to_owned(),
                    idempotency_key: None,
                    correlation_id: "guest-provider-route".to_owned(),
                    trace_id: None,
                    deadline_ms: 10_000,
                },
                zone: self.zone.clone(),
                target: target.clone(),
                expected_uid: None,
                projection: StoreProjection::Full,
            })
            .await
            .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;
        let envelope = ResourceEnvelope::from_json(&guest.canonical_json)
            .map_err(|_| ResourceRuntimeError::RequestInvalid)?;
        let provider_ref = envelope
            .spec()
            .provider_ref()
            .cloned()
            .ok_or(ResourceRuntimeError::RequestInvalid)?;
        if provider_ref.resource_type().as_str() != "Provider" {
            return Err(ResourceRuntimeError::RequestInvalid);
        }
        Ok(provider_ref)
    }

    /// Bind a Resource API client to a sealed Resource API session subject.
    ///
    /// The wrapper is issued only after ComponentSession or root-listener
    /// authentication and native policy evaluation. Callers cannot construct
    /// it from a request payload.
    pub(crate) fn bind_operator_resource_client(
        &self,
        subject: d2b_resource_api::AuthenticatedSubjectContext,
    ) -> Result<
        Arc<ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>>,
        ResourceRuntimeError,
    > {
        let adapter = ResourceBusAdapter::bind_component_session(Arc::clone(&self.api), subject)
            .map_err(|_| ResourceRuntimeError::ResourceApiBindFailed)?;
        Ok(Arc::new(adapter.client()))
    }

    #[cfg(feature = "test-support")]
    pub fn bind_operator_resource_client_for_test(
        &self,
        context: d2b_contracts_resource::v3::identity::AuthenticatedSubjectContext,
    ) -> Result<
        Arc<ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>>,
        ResourceRuntimeError,
    > {
        let state = self
            .authorization_state
            .lock()
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?
            .clone()
            .ok_or(ResourceRuntimeError::AuthenticationUnavailable)?;
        let subject = self
            .authorizer
            .issue_authenticated_subject(context, state)
            .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?;
        self.bind_operator_resource_client(subject)
    }

    /// Borrow the daemon-owned Resource API client used by the target-local
    /// process reconciler. The client is present only after the Zone's
    /// authenticated system-core session has been enrolled.
    pub(crate) fn process_resource_client(
        &self,
    ) -> Option<Arc<ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>>> {
        self.process_status_client
            .lock()
            .ok()
            .and_then(|client| client.clone())
    }

    fn status_client(
        &self,
    ) -> Result<
        Arc<ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>>,
        ResourceRuntimeError,
    > {
        self.process_status_client
            .lock()
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?
            .clone()
            .ok_or(ResourceRuntimeError::AuthenticationUnavailable)
    }

    async fn core_assignment_fences(
        &self,
        rotate_epoch: bool,
    ) -> Result<
        (
            Vec<(ResourceRef, ResourceAssignmentFence)>,
            ResourceGeneration,
            ControllerGeneration,
            ReconnectGeneration,
            Arc<CoreAssignmentAuthority>,
        ),
        ResourceRuntimeError,
    > {
        let subject = self
            .core_controller_subject
            .lock()
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?
            .clone()
            .ok_or(ResourceRuntimeError::AuthenticationUnavailable)?;
        let metadata = self
            .store
            .runtime_metadata()
            .await
            .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;
        let controller_generation = metadata
            .policy_snapshot
            .controller_generation
            .ok_or(ResourceRuntimeError::HandlerNotReady)?;
        let resource_types = CORE_RESOURCE_CONTROLLER_REGISTRATIONS
            .iter()
            .map(|registration| {
                ResourceTypeName::parse(registration.resource_type().to_owned())
                    .map_err(|_| ResourceRuntimeError::HandlerNotReady)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut resources = Vec::new();
        let mut cursor = None;
        loop {
            let page = self
                .store
                .list(StoreListRequest {
                    operation: StoreOperationContext {
                        operation_id: "core-controller-assignment-relist".to_owned(),
                        idempotency_key: None,
                        correlation_id: "core-controller-assignment-relist".to_owned(),
                        trace_id: None,
                        deadline_ms: 10_000,
                    },
                    zone: self.zone.clone(),
                    resource_types: resource_types.clone(),
                    resource_names: Vec::new(),
                    filters: Vec::new(),
                    page_size: 256,
                    cursor,
                    projection: StoreProjection::MetadataOnly,
                })
                .await
                .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;
            resources.extend(page.resources);
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        let provider_ref = ResourceRef::parse(CORE_CONTROLLER_PROVIDER_REF)
            .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
        let provider_generation = resources
            .iter()
            .find(|resource| resource.resource_ref == provider_ref)
            .map(|resource| resource.generation)
            .ok_or(ResourceRuntimeError::HandlerNotReady)?;
        let controller_ref = ResourceRef::parse(CORE_CONTROLLER_PROCESS_REF)
            .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
        let target = ResourceRef::parse(&format!("Zone/{}", self.zone.as_str()))
            .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
        let session_generation = subject.reconnect_generation();
        let durable_epoch = {
            let mut maximum = 0;
            for resource in &resources {
                if let Some(fence) = self
                    .store
                    .assignment_fence(self.zone.clone(), resource.resource_ref.clone())
                    .await
                    .map_err(|_| ResourceRuntimeError::StoreReadFailed)?
                {
                    maximum = maximum.max(fence.epoch);
                }
            }
            maximum
        };
        let current_epoch = self.core_assignment_epoch.load(Ordering::Acquire);
        let floor = current_epoch.max(durable_epoch);
        let epoch = if rotate_epoch || current_epoch == 0 || durable_epoch > current_epoch {
            self.assignments
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .reserve_epoch_after(floor)
                .map_err(|_| ResourceRuntimeError::HandlerNotReady)?
        } else {
            current_epoch
        };
        self.core_assignment_epoch.store(epoch, Ordering::Release);
        let authority = Arc::new(CoreAssignmentAuthority {
            provider_generation,
            controller_generation,
            session_generation,
            controller_role: controller_ref.clone(),
            target: target.clone(),
            epoch,
        });
        let assignments = resources
            .into_iter()
            .map(|resource| {
                let fence = ResourceAssignmentFence {
                    resource_uid: resource.uid.clone(),
                    resource_revision: resource.revision,
                    provider_generation,
                    controller_generation,
                    controller_role: controller_ref.clone(),
                    target: target.clone(),
                    session_generation,
                    epoch,
                    scope: ResourceAssignmentScope::Primary,
                };
                (resource.resource_ref, fence)
            })
            .collect();
        Ok((
            assignments,
            provider_generation,
            controller_generation,
            session_generation,
            authority,
        ))
    }

    async fn stop_core_controller_runners_locked(&self) -> Result<(), ResourceRuntimeError> {
        #[cfg(test)]
        self.core_runner_events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push("stop-enter");
        let tasks = {
            let mut tasks = self
                .core_runner_tasks
                .lock()
                .map_err(|_| ResourceRuntimeError::WatchUnavailable)?;
            std::mem::take(&mut *tasks)
        };
        for task in tasks {
            task.abort();
            let _ = task.await;
        }
        #[cfg(test)]
        self.core_runner_events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push("stop-exit");
        Ok(())
    }

    async fn provider_generation_for_runner(
        &self,
        provider_ref: &ResourceRef,
    ) -> Result<ResourceGeneration, ResourceRuntimeError> {
        let resource = self
            .store
            .get(StoreGetRequest {
                operation: StoreOperationContext {
                    operation_id: "shared-provider-runner-provider".to_owned(),
                    idempotency_key: None,
                    correlation_id: "shared-provider-runner-provider".to_owned(),
                    trace_id: None,
                    deadline_ms: 10_000,
                },
                zone: self.zone.clone(),
                target: provider_ref.clone(),
                expected_uid: None,
                projection: StoreProjection::MetadataOnly,
            })
            .await
            .map_err(|error| {
                if error.kind() == StoreErrorKind::ResourceNotFound {
                    ResourceRuntimeError::HandlerNotReady
                } else {
                    ResourceRuntimeError::StoreReadFailed
                }
            })?;
        if resource.resource_ref != *provider_ref
            || resource.resource_ref.resource_type().as_str() != "Provider"
            || resource.generation.get() == 0
            || resource.revision.get() == 0
        {
            return Err(ResourceRuntimeError::HandlerNotReady);
        }
        Ok(resource.generation)
    }

    async fn start_core_controller_runners(&self) -> Result<(), ResourceRuntimeError> {
        let _runner_guard = self.core_runner_lock.lock().await;
        #[cfg(test)]
        self.core_runner_events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push("start-enter");
        let result = self.start_core_controller_runners_locked(false).await;
        #[cfg(test)]
        self.core_runner_events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push("start-exit");
        result
    }

    async fn start_core_controller_runners_locked(
        &self,
        rotate_epoch: bool,
    ) -> Result<(), ResourceRuntimeError> {
        if !self.readiness.resource_api_ready {
            return Ok(());
        }
        let mut provider_generations = BTreeMap::new();
        let mut provider_missing = false;
        for registration in U8_SHARED_PROVIDER_RUNNERS {
            let provider_ref = ResourceRef::parse(registration.provider_ref)
                .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
            if provider_generations.contains_key(&provider_ref) {
                continue;
            }
            match self.provider_generation_for_runner(&provider_ref).await {
                Ok(generation) => {
                    provider_generations.insert(provider_ref, generation);
                }
                Err(ResourceRuntimeError::HandlerNotReady) => {
                    provider_missing = true;
                }
                Err(error) => return Err(error),
            }
        }
        if provider_missing && !provider_generations.is_empty() {
            return Err(ResourceRuntimeError::ProviderPathUnavailable);
        }
        let stale = {
            let mut tasks = self
                .core_runner_tasks
                .lock()
                .map_err(|_| ResourceRuntimeError::WatchUnavailable)?;
            if tasks.iter().any(|task| !task.is_finished()) {
                return Ok(());
            }
            std::mem::take(&mut *tasks)
        };
        for task in stale {
            let _ = task.await;
        }
        let subject_context = self
            .core_controller_subject
            .lock()
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?
            .clone()
            .ok_or(ResourceRuntimeError::AuthenticationUnavailable)?;
        let authorization_state = self
            .authorization_state
            .lock()
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?
            .clone()
            .ok_or(ResourceRuntimeError::AuthenticationUnavailable)?;
        let (
            assignments,
            provider_generation,
            controller_generation,
            session_generation,
            assignment_authority,
        ) = match self.core_assignment_fences(rotate_epoch).await {
            Ok(value) => value,
            Err(ResourceRuntimeError::HandlerNotReady) => return Ok(()),
            Err(error) => return Err(error),
        };
        let controller_ref = ResourceRef::parse(CORE_CONTROLLER_PROCESS_REF)
            .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
        let provider_ref = ResourceRef::parse(CORE_CONTROLLER_PROVIDER_REF)
            .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
        let host_ref = ResourceRef::parse(CORE_CONTROLLER_HOST_REF)
            .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
        let identity = ControllerIdentity::new(
            self.zone.clone(),
            controller_ref,
            controller_generation,
            provider_ref,
            provider_generation,
            ResourceRef::parse(CORE_CONTROLLER_PROCESS_REF)
                .map_err(|_| ResourceRuntimeError::HandlerNotReady)?,
            host_ref,
            None,
        )
        .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
        let descriptors =
            core_controller_descriptors(identity).map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
        let mut prepared = Vec::with_capacity(descriptors.len() + U8_SHARED_PROVIDER_RUNNERS.len());
        for (registration, descriptor) in descriptors {
            let subject = self
                .authorizer
                .issue_authenticated_subject(subject_context.clone(), authorization_state.clone())
                .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?;
            let registered_resource_type = registration.resource_type().to_owned();
            let resource_assignments = assignments
                .iter()
                .filter(|(target, _)| {
                    target.resource_type().as_str() == registration.resource_type()
                })
                .cloned()
                .collect();
            let resolver_store = Arc::clone(&self.store);
            let resolver_zone = self.zone.clone();
            let resolver_authority = Arc::clone(&assignment_authority);
            let resolver: AssignmentFenceResolver = Arc::new(move |target, uid, revision| {
                let store = Arc::clone(&resolver_store);
                let zone = resolver_zone.clone();
                let authority = Arc::clone(&resolver_authority);
                let resource_type = registered_resource_type.clone();
                Box::pin(async move {
                    if target.resource_type().as_str() != resource_type {
                        return Err(SourceError::Integrity);
                    }
                    if let Some(stored) = store
                        .assignment_fence(zone, target.clone())
                        .await
                        .map_err(|error| match error.kind() {
                            StoreErrorKind::Backpressure
                            | StoreErrorKind::StoreBackpressure => SourceError::Backpressure,
                            StoreErrorKind::Timeout => SourceError::Timeout,
                            _ => SourceError::Unavailable,
                        })?
                    {
                        if stored.resource_uid != uid
                            || stored.epoch > authority.epoch
                            || (stored.epoch == authority.epoch
                                && (stored.provider_generation != authority.provider_generation
                                    || stored.controller_generation
                                        != authority.controller_generation
                                    || stored.controller_role != authority.controller_role
                                    || stored.target != authority.target
                                    || stored.session_generation != authority.session_generation))
                        {
                            return Err(SourceError::Integrity);
                        }
                        if stored.epoch == authority.epoch
                            && stored.resource_revision != revision
                        {
                            return Err(SourceError::Conflict(stored.resource_revision));
                        }
                    }
                    Ok(ResourceAssignmentFence {
                        resource_uid: uid,
                        resource_revision: revision,
                        provider_generation: authority.provider_generation,
                        controller_generation: authority.controller_generation,
                        controller_role: authority.controller_role.clone(),
                        target: authority.target.clone(),
                        session_generation: authority.session_generation,
                        epoch: authority.epoch,
                        scope: ResourceAssignmentScope::Primary,
                    })
                })
            });
            let api = self
                .api
                .registered_controller_api(subject, authorization_state.clone(), resource_assignments)
                .map_err(|_| ResourceRuntimeError::ResourceApiBindFailed)?;
            let api = api.with_assignment_fence_resolver(resolver);
            let source = CoreControllerSource::new(descriptor.clone(), Arc::new(api));
            prepared.push(PreparedCoreRunner::Core {
                reconciler: CoreResourceReconciler::for_handler(
                    descriptor,
                    registration.handler(),
                ),
                source,
                config: RunnerConfig {
                    policy_revision: authorization_state.snapshot.policy_revision,
                    api_revision: authorization_state.snapshot.api_catalog_revision,
                    configuration_revision: authorization_state.snapshot.active_configuration_revision,
                    deadline_tick: 5_000,
                    max_attempts: 3,
                },
                handler: registration.handler().label(),
                resource_type: registration.resource_type(),
            });
        }
        let system_core_controller_ref =
            ResourceRef::parse("Process/system-core-resource-controller")
                .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
        let system_core_provider_ref = ResourceRef::parse(CORE_CONTROLLER_PROVIDER_REF)
            .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
        let system_core_host_ref = ResourceRef::parse(CORE_CONTROLLER_HOST_REF)
            .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
        let system_core_identity = ControllerIdentity::new(
            self.zone.clone(),
            system_core_controller_ref.clone(),
            controller_generation,
            system_core_provider_ref,
            provider_generation,
            system_core_controller_ref,
            system_core_host_ref,
            None,
        )
        .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
        let system_core_descriptor = system_core_resource_descriptor(system_core_identity)?;
        let system_core_subject = self
            .authorizer
            .issue_authenticated_subject(subject_context.clone(), authorization_state.clone())
            .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?;
        let system_core_api = self
            .api
            .registered_controller_api(system_core_subject, authorization_state.clone(), Vec::new())
            .map_err(|_| ResourceRuntimeError::ResourceApiBindFailed)?
            .with_assignment_fence_resolver(system_core_assignment_fence_resolver(
                Arc::clone(&self.store),
                ResourceRef::parse("Process/system-core-resource-controller")
                    .map_err(|_| ResourceRuntimeError::HandlerNotReady)?,
                session_generation,
                Arc::clone(&self.core_assignment_epoch),
            ));
        let system_core_source =
            CoreControllerSource::new(system_core_descriptor.clone(), Arc::new(system_core_api));
        let system_core_runner = Runner::new(
            SystemCoreResourceReconciler::new(system_core_descriptor),
            system_core_source,
            RunnerConfig {
                policy_revision: authorization_state.snapshot.policy_revision,
                api_revision: authorization_state.snapshot.api_catalog_revision,
                configuration_revision: authorization_state.snapshot.active_configuration_revision,
                deadline_tick: 5_000,
                max_attempts: 3,
            },
        );
        let provider_descriptors = if provider_generations.is_empty() {
            Vec::new()
        } else {
            compose_shared_provider_runner_descriptors(
                U8_SHARED_PROVIDER_RUNNERS,
                self.zone.clone(),
                controller_generation,
                &provider_generations,
                subject_context.reconnect_generation(),
            )?
        };
        for (registration, descriptor) in provider_descriptors {
            let subject = self
                .authorizer
                .issue_authenticated_subject(subject_context.clone(), authorization_state.clone())
                .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?;
            let resource_type = registration.resource_type.to_owned();
            let authority = CoreAssignmentAuthority {
                provider_generation: *provider_generations
                    .get(
                        &ResourceRef::parse(registration.provider_ref)
                            .map_err(|_| ResourceRuntimeError::HandlerNotReady)?,
                    )
                    .ok_or(ResourceRuntimeError::HandlerNotReady)?,
                controller_generation,
                session_generation: subject_context.reconnect_generation(),
                controller_role: descriptor.identity().controller_ref().clone(),
                target: ResourceRef::parse(CORE_CONTROLLER_HOST_REF)
                    .map_err(|_| ResourceRuntimeError::HandlerNotReady)?,
                epoch: self.core_assignment_epoch.load(Ordering::Acquire),
            };
            if authority.epoch == 0 {
                return Err(ResourceRuntimeError::HandlerNotReady);
            }
            let resolver_store = Arc::clone(&self.store);
            let resolver_zone = self.zone.clone();
            let resolver_authority = Arc::new(authority);
            let resolver_resource_type = resource_type.clone();
            let resolver: AssignmentFenceResolver = Arc::new(move |target, uid, revision| {
                let store = Arc::clone(&resolver_store);
                let zone = resolver_zone.clone();
                let authority = Arc::clone(&resolver_authority);
                let resource_type = resolver_resource_type.clone();
                Box::pin(async move {
                    if target.resource_type().as_str() != resource_type {
                        return Err(SourceError::Integrity);
                    }
                    if let Some(stored) = store
                        .assignment_fence(zone, target.clone())
                        .await
                        .map_err(|error| match error.kind() {
                            StoreErrorKind::Backpressure
                            | StoreErrorKind::StoreBackpressure => SourceError::Backpressure,
                            StoreErrorKind::Timeout => SourceError::Timeout,
                            _ => SourceError::Unavailable,
                        })?
                    {
                        if stored.resource_uid != uid
                            || stored.epoch > authority.epoch
                            || (stored.epoch == authority.epoch
                                && (stored.provider_generation != authority.provider_generation
                                    || stored.controller_generation
                                        != authority.controller_generation
                                    || stored.controller_role != authority.controller_role
                                    || stored.target != authority.target
                                    || stored.session_generation != authority.session_generation))
                        {
                            return Err(SourceError::Integrity);
                        }
                        if stored.epoch == authority.epoch
                            && stored.resource_revision != revision
                        {
                            return Err(SourceError::Conflict(stored.resource_revision));
                        }
                    }
                    Ok(ResourceAssignmentFence {
                        resource_uid: uid,
                        resource_revision: revision,
                        provider_generation: authority.provider_generation,
                        controller_generation: authority.controller_generation,
                        controller_role: authority.controller_role.clone(),
                        target: authority.target.clone(),
                        session_generation: authority.session_generation,
                        epoch: authority.epoch,
                        scope: ResourceAssignmentScope::Primary,
                    })
                })
            });
            let runner_descriptor = descriptor.clone();
            let api = self
                .api
                .registered_controller_api(subject, authorization_state.clone(), Vec::new())
                .map_err(|_| ResourceRuntimeError::ResourceApiBindFailed)?
                .with_assignment_fence_resolver(resolver);
            let kind = SharedProviderResourceKind::from_registration(registration)?;
            let source = CoreControllerSource::new(
                    runner_descriptor.clone(),
                    Arc::new(api),
                );
            prepared.push(PreparedCoreRunner::Provider {
                reconciler: SharedProviderResourceReconciler::new(
                    descriptor,
                    kind,
                    Arc::clone(&self.shared_provider_effects),
                ),
                source,
                config: RunnerConfig {
                    policy_revision: authorization_state.snapshot.policy_revision,
                    api_revision: authorization_state.snapshot.api_catalog_revision,
                    configuration_revision: authorization_state.snapshot.active_configuration_revision,
                    deadline_tick: 5_000,
                    max_attempts: 3,
                },
                controller_ref: runner_descriptor.identity().controller_ref().clone(),
                resource_type,
            });
        }
        let mut new_tasks = prepared
            .into_iter()
            .map(spawn_prepared_core_runner)
            .collect::<Vec<_>>();
        new_tasks.push(tokio::spawn(async move {
            match system_core_runner.run().await {
                Ok(report) => tracing::debug!(
                    dispatched = report.dispatched,
                    relists = report.relists,
                    "system-core Host/User shared runner stopped",
                ),
                Err(error) => tracing::warn!(
                    error = %error,
                    "system-core Host/User shared runner failed",
                ),
            }
        }));
        match self.core_runner_tasks.lock() {
            Ok(mut tasks) => tasks.append(&mut new_tasks),
            Err(_) => {
                for task in new_tasks {
                    task.abort();
                    let _ = task.await;
                }
                return Err(ResourceRuntimeError::WatchUnavailable);
            }
        }
        Ok(())
    }

    async fn stop_u12_controller_runners_locked(&self) -> Result<(), ResourceRuntimeError> {
        let tasks = {
            let mut tasks = self
                .u12_runner_tasks
                .lock()
                .map_err(|_| ResourceRuntimeError::WatchUnavailable)?;
            std::mem::take(&mut *tasks)
        };
        for task in tasks {
            task.abort();
            let _ = task.await;
        }
        Ok(())
    }

    async fn stop_u7_controller_runners_locked(&self) -> Result<(), ResourceRuntimeError> {
        let tasks = {
            let mut tasks = self
                .u7_runner_tasks
                .lock()
                .map_err(|_| ResourceRuntimeError::WatchUnavailable)?;
            std::mem::take(&mut *tasks)
        };
        for task in tasks {
            task.abort();
            let _ = task.await;
        }
        self.u7_required.store(false, Ordering::Release);
        Ok(())
    }

    /// Attach the storage Providers to the production shared Runner.
    pub(crate) async fn start_u7_controller_runners(
        &self,
        state: Arc<crate::ServerState>,
    ) -> Result<(), ResourceRuntimeError> {
        let _runner_guard = self.u7_runner_lock.lock().await;
        let result = self
            .start_u7_controller_runners_locked(Arc::clone(&state))
            .await;
        if result.is_ok() {
            match self.u7_state.lock() {
                Ok(mut current) => *current = Some(state),
                Err(_) => {
                    self.stop_u7_controller_runners_locked().await?;
                    return Err(ResourceRuntimeError::AuthenticationUnavailable);
                }
            }
        }
        result
    }

    async fn start_u7_controller_runners_locked(
        &self,
        state: Arc<crate::ServerState>,
    ) -> Result<(), ResourceRuntimeError> {
        if !self.readiness.resource_api_ready {
            return Ok(());
        }
        {
            let tasks = self
                .u7_runner_tasks
                .lock()
                .map_err(|_| ResourceRuntimeError::WatchUnavailable)?;
            if tasks.iter().any(|task| !task.is_finished()) {
                return Ok(());
            }
        }
        let stale = {
            let mut tasks = self
                .u7_runner_tasks
                .lock()
                .map_err(|_| ResourceRuntimeError::WatchUnavailable)?;
            std::mem::take(&mut *tasks)
        };
        for task in stale {
            let _ = task.await;
        }
        let required = volume_provider_runtime::start(self, state).await?;
        self.u7_required.store(required, Ordering::Release);
        Ok(())
    }

    async fn stop_u6_controller_runners_locked(&self) -> Result<(), ResourceRuntimeError> {
        let tasks = {
            let mut tasks = self
                .u6_runner_tasks
                .lock()
                .map_err(|_| ResourceRuntimeError::WatchUnavailable)?;
            std::mem::take(&mut *tasks)
        };
        for task in tasks {
            task.abort();
            let _ = task.await;
        }
        self.u6_required.store(false, Ordering::Release);
        Ok(())
    }

    /// Attach the selected Guest runtime Providers to the production shared
    /// Runner. Provider selection remains an exact `Guest.spec.providerRef`
    /// admission rule.
    pub(crate) async fn start_u6_controller_runners(
        &self,
        state: Arc<crate::ServerState>,
    ) -> Result<(), ResourceRuntimeError> {
        let _runner_guard = self.u6_runner_lock.lock().await;
        let result = self
            .start_u6_controller_runners_locked(Arc::clone(&state))
            .await;
        if result.is_ok() {
            match self.u6_state.lock() {
                Ok(mut current) => *current = Some(state),
                Err(_) => {
                    self.stop_u6_controller_runners_locked().await?;
                    return Err(ResourceRuntimeError::AuthenticationUnavailable);
                }
            }
        }
        result
    }

    async fn start_u6_controller_runners_locked(
        &self,
        state: Arc<crate::ServerState>,
    ) -> Result<(), ResourceRuntimeError> {
        if !self.readiness.resource_api_ready {
            return Ok(());
        }
        {
            let tasks = self
                .u6_runner_tasks
                .lock()
                .map_err(|_| ResourceRuntimeError::WatchUnavailable)?;
            if tasks.iter().any(|task| !task.is_finished()) {
                return Ok(());
            }
        }
        let stale = {
            let mut tasks = self
                .u6_runner_tasks
                .lock()
                .map_err(|_| ResourceRuntimeError::WatchUnavailable)?;
            std::mem::take(&mut *tasks)
        };
        for task in stale {
            let _ = task.await;
        }
        let required = guest_provider_runtime::start(self, state).await?;
        self.u6_required.store(required, Ordering::Release);
        Ok(())
    }

    async fn stop_u9_controller_runners_locked(&self) -> Result<(), ResourceRuntimeError> {
        let tasks = {
            let mut tasks = self
                .u9_runner_tasks
                .lock()
                .map_err(|_| ResourceRuntimeError::WatchUnavailable)?;
            std::mem::take(&mut *tasks)
        };
        for task in tasks {
            task.abort();
            let _ = task.await;
        }
        self.u9_required.store(false, Ordering::Release);
        Ok(())
    }

    /// Attach interaction and shell resource owners to the production shared
    /// Runner. Clipboard and notification streams remain ComponentSession
    /// services and are intentionally not registered as ResourceTypes.
    pub(crate) async fn start_u9_controller_runners(
        &self,
        state: Arc<crate::ServerState>,
    ) -> Result<(), ResourceRuntimeError> {
        let _runner_guard = self.u9_runner_lock.lock().await;
        let result = self
            .start_u9_controller_runners_locked(Arc::clone(&state))
            .await;
        if result.is_ok() {
            match self.u9_state.lock() {
                Ok(mut current) => *current = Some(state),
                Err(_) => {
                    self.stop_u9_controller_runners_locked().await?;
                    return Err(ResourceRuntimeError::AuthenticationUnavailable);
                }
            }
        }
        result
    }

    async fn start_u9_controller_runners_locked(
        &self,
        state: Arc<crate::ServerState>,
    ) -> Result<(), ResourceRuntimeError> {
        if !self.readiness.resource_api_ready {
            return Ok(());
        }
        {
            let tasks = self
                .u9_runner_tasks
                .lock()
                .map_err(|_| ResourceRuntimeError::WatchUnavailable)?;
            if tasks.iter().any(|task| !task.is_finished()) {
                return Ok(());
            }
        }
        let stale = {
            let mut tasks = self
                .u9_runner_tasks
                .lock()
                .map_err(|_| ResourceRuntimeError::WatchUnavailable)?;
            std::mem::take(&mut *tasks)
        };
        for task in stale {
            let _ = task.await;
        }
        let subject_context = self
            .core_controller_subject
            .lock()
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?
            .clone()
            .ok_or(ResourceRuntimeError::AuthenticationUnavailable)?;
        let authorization_state = self
            .authorization_state
            .lock()
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?
            .clone()
            .ok_or(ResourceRuntimeError::AuthenticationUnavailable)?;
        let controller_generation = self
            .store_metadata
            .policy_snapshot
            .controller_generation
            .ok_or(ResourceRuntimeError::HandlerNotReady)?;
        let session_generation = subject_context.reconnect_generation();
        let (active_registrations, provider_generations) =
            u9_provider_generations(self).await?;
        if active_registrations.is_empty() {
            self.u9_required.store(false, Ordering::Release);
            return Ok(());
        }
        let descriptors = compose_shared_provider_runner_descriptors(
            active_registrations,
            self.zone.clone(),
            controller_generation,
            &provider_generations,
            session_generation,
        )?;
        let effects: Arc<dyn SharedProviderEffectExecutor> = Arc::new(
            DaemonSharedProviderEffects::new(Arc::clone(&state), self.zone.clone()),
        );
        let mut new_tasks = Vec::with_capacity(descriptors.len());
        for (registration, descriptor) in descriptors {
            let kind = SharedProviderResourceKind::from_registration(registration)?;
            let provider_ref = ResourceRef::parse(registration.provider_ref)
                .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
            let controller_ref = ResourceRef::parse(registration.controller_ref)
                .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
            let provider_generation = *provider_generations
                .get(&provider_ref)
                .ok_or(ResourceRuntimeError::HandlerNotReady)?;
            let (assignments, authority) = self
                .u12_controller_assignments(
                    &descriptor,
                    controller_ref.clone(),
                    provider_generation,
                    controller_generation,
                    session_generation,
                )
                .await?;
            let subject = self
                .authorizer
                .issue_authenticated_subject(
                    subject_context.clone(),
                    authorization_state.clone(),
                )
                .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?;
            let api = self
                .api
                .registered_controller_api(subject, authorization_state.clone(), assignments)
                .map_err(|_| ResourceRuntimeError::ResourceApiBindFailed)?;
            let allowed_types = descriptor
                .resource_types()
                .cloned()
                .collect::<BTreeSet<_>>();
            let resolver_store = Arc::clone(&self.store);
            let resolver_zone = self.zone.clone();
            let resolver_authority = Arc::clone(&authority);
            let resolver: AssignmentFenceResolver = Arc::new(move |target, uid, revision| {
                let store = Arc::clone(&resolver_store);
                let zone = resolver_zone.clone();
                let authority = Arc::clone(&resolver_authority);
                let allowed_types = allowed_types.clone();
                Box::pin(async move {
                    if !allowed_types.contains(target.resource_type()) {
                        return Err(SourceError::Integrity);
                    }
                    if let Some(stored) = store
                        .assignment_fence(zone, target.clone())
                        .await
                        .map_err(|error| match error.kind() {
                            StoreErrorKind::Backpressure
                            | StoreErrorKind::StoreBackpressure => SourceError::Backpressure,
                            StoreErrorKind::Timeout => SourceError::Timeout,
                            _ => SourceError::Unavailable,
                        })?
                    {
                        if stored.resource_uid != uid
                            || stored.epoch > authority.epoch
                            || (stored.epoch == authority.epoch
                                && (stored.provider_generation
                                    != authority.provider_generation
                                    || stored.controller_generation
                                        != authority.controller_generation
                                    || stored.controller_role != authority.controller_role
                                    || stored.target != authority.target
                                    || stored.session_generation
                                        != authority.session_generation))
                        {
                            return Err(SourceError::Integrity);
                        }
                        if stored.epoch == authority.epoch
                            && stored.resource_revision != revision
                        {
                            return Err(SourceError::Conflict(stored.resource_revision));
                        }
                    }
                    Ok(ResourceAssignmentFence {
                        resource_uid: uid,
                        resource_revision: revision,
                        provider_generation: authority.provider_generation,
                        controller_generation: authority.controller_generation,
                        controller_role: authority.controller_role.clone(),
                        target: authority.target.clone(),
                        session_generation: authority.session_generation,
                        epoch: authority.epoch,
                        scope: ResourceAssignmentScope::Primary,
                    })
                })
            });
            let api = api.with_assignment_fence_resolver(resolver);
            let source = CoreControllerSource::new(descriptor.clone(), Arc::new(api));
            let reconciler = SharedProviderResourceReconciler::new(
                descriptor.clone(),
                kind,
                Arc::clone(&effects),
            );
            let runner = Runner::new(
                reconciler,
                source,
                RunnerConfig {
                    policy_revision: authorization_state.snapshot.policy_revision,
                    api_revision: authorization_state.snapshot.api_catalog_revision,
                    configuration_revision: authorization_state
                        .snapshot
                        .active_configuration_revision,
                    deadline_tick: 5_000,
                    max_attempts: 3,
                },
            );
            let resource_type = registration.resource_type;
            let controller = registration.controller_ref;
            new_tasks.push(tokio::spawn(async move {
                match runner.run().await {
                    Ok(report) => tracing::debug!(
                        controller,
                        resource_type,
                        dispatched = report.dispatched,
                        relists = report.relists,
                        "U9 interaction shared Runner stopped",
                    ),
                    Err(error) => tracing::warn!(
                        controller,
                        resource_type,
                        error = %error,
                        "U9 interaction shared Runner failed",
                    ),
                }
            }));
        }
        let mut tasks = self
            .u9_runner_tasks
            .lock()
            .map_err(|_| ResourceRuntimeError::WatchUnavailable)?;
        tasks.extend(new_tasks);
        self.u9_required.store(true, Ordering::Release);
        Ok(())
    }

    /// Attach the observability and activation handlers to the same Core
    /// source/Runner path used by every resource owner.
    pub(crate) async fn start_u12_controller_runners(
        &self,
        state: Arc<crate::ServerState>,
    ) -> Result<(), ResourceRuntimeError> {
        let _runner_guard = self.u12_runner_lock.lock().await;
        let result = self
            .start_u12_controller_runners_locked(Arc::clone(&state))
            .await;
        if result.is_ok() {
            match self.u12_state.lock() {
                Ok(mut current) => *current = Some(state),
                Err(_) => {
                    self.stop_u12_controller_runners_locked().await?;
                    return Err(ResourceRuntimeError::AuthenticationUnavailable);
                }
            }
        }
        result
    }

    async fn start_u12_controller_runners_locked(
        &self,
        state: Arc<crate::ServerState>,
    ) -> Result<(), ResourceRuntimeError> {
        if !self.readiness.resource_api_ready {
            return Ok(());
        }
        {
            let tasks = self
                .u12_runner_tasks
                .lock()
                .map_err(|_| ResourceRuntimeError::WatchUnavailable)?;
            if tasks.iter().any(|task| !task.is_finished()) {
                return Ok(());
            }
        }
        let stale = {
            let mut tasks = self
                .u12_runner_tasks
                .lock()
                .map_err(|_| ResourceRuntimeError::WatchUnavailable)?;
            std::mem::take(&mut *tasks)
        };
        for task in stale {
            let _ = task.await;
        }

        let subject_context = self
            .core_controller_subject
            .lock()
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?
            .clone()
            .ok_or(ResourceRuntimeError::AuthenticationUnavailable)?;
        let authorization_state = self
            .authorization_state
            .lock()
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?
            .clone()
            .ok_or(ResourceRuntimeError::AuthenticationUnavailable)?;
        let controller_generation = self
            .store_metadata
            .policy_snapshot
            .controller_generation
            .ok_or(ResourceRuntimeError::HandlerNotReady)?;
        let session_generation = subject_context.reconnect_generation();
        let status_client = self.status_client()?;
        let mut new_tasks = Vec::new();

        enum U12ControllerKind {
            Telemetry,
            Activation,
        }
        let providers = [
            (
                "observability-otel",
                ResourceRef::parse("Process/observability-otel-controller")
                    .expect("observability controller ref"),
                U12ControllerKind::Telemetry,
            ),
            (
                "activation-nixos",
                ResourceRef::parse("Process/activation-nixos-controller")
                    .expect("activation controller ref"),
                U12ControllerKind::Activation,
            ),
        ];

        let build_result: Result<bool, ResourceRuntimeError> = async {
            let mut required = false;
            for (provider_name, controller_ref, kind) in providers {
            let provider_ref =
                ResourceRef::parse(&format!("Provider/{provider_name}"))
                    .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
            let provider = match self
                .store
                .get(StoreGetRequest {
                    operation: StoreOperationContext {
                        operation_id: format!("u12-provider-{provider_name}"),
                        idempotency_key: None,
                        correlation_id: format!("u12-provider-{provider_name}"),
                        trace_id: None,
                        deadline_ms: 10_000,
                    },
                    zone: self.zone.clone(),
                    target: provider_ref.clone(),
                    expected_uid: None,
                    projection: StoreProjection::MetadataOnly,
                })
                .await
            {
                Ok(provider) => provider,
                Err(error) if error.kind() == StoreErrorKind::ResourceNotFound => {
                    let resource_types = match kind {
                        U12ControllerKind::Telemetry => {
                            ["telemetry.d2bus.org.TelemetryService", "telemetry.d2bus.org.TelemetryBinding"]
                        }
                        U12ControllerKind::Activation => {
                            ["activation-nixos.d2bus.org.NixosGeneration", ""]
                        }
                    };
                    let resource_types = resource_types
                        .into_iter()
                        .filter(|resource_type| !resource_type.is_empty())
                        .collect::<Vec<_>>();
                    if u12_provider_missing_with_resources(
                        self.u12_resources_present(&resource_types).await?,
                    ) {
                        return Err(ResourceRuntimeError::ProviderPathUnavailable);
                    }
                    continue;
                }
                Err(_) => return Err(ResourceRuntimeError::StoreReadFailed),
            };
            required = true;
            if provider.zone != self.zone
                || provider.resource_ref != provider_ref
                || provider.generation.get() == 0
            {
                return Err(ResourceRuntimeError::HandlerNotReady);
            }
            if provider_name == "observability-otel" {
                validate_observability_environment()?;
            }
            let identity = ControllerIdentity::new(
                self.zone.clone(),
                controller_ref.clone(),
                controller_generation,
                provider_ref.clone(),
                provider.generation,
                controller_ref.clone(),
                ResourceRef::parse(CORE_CONTROLLER_HOST_REF)
                    .map_err(|_| ResourceRuntimeError::HandlerNotReady)?,
                None,
            )
            .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
            let descriptor = match kind {
                U12ControllerKind::Telemetry => telemetry_controller_descriptor(identity.clone())
                    .map_err(|_| ResourceRuntimeError::HandlerNotReady)?,
                U12ControllerKind::Activation => activation_controller_descriptor(identity.clone())
                    .map_err(|_| ResourceRuntimeError::HandlerNotReady)?,
            };
            let (assignments, authority) = self
                .u12_controller_assignments(
                    &descriptor,
                    controller_ref.clone(),
                    provider.generation,
                    controller_generation,
                    session_generation,
                )
                .await?;
            let subject = self
                .authorizer
                .issue_authenticated_subject(subject_context.clone(), authorization_state.clone())
                .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?;
            let api = self
                .api
                .registered_controller_api(
                    subject,
                    authorization_state.clone(),
                    assignments,
                )
                .map_err(|_| ResourceRuntimeError::ResourceApiBindFailed)?;
            let allowed_types = descriptor.resource_types().cloned().collect::<BTreeSet<_>>();
            let resolver_store = Arc::clone(&self.store);
            let resolver_zone = self.zone.clone();
            let resolver_authority = Arc::clone(&authority);
            let resolver: AssignmentFenceResolver = Arc::new(move |target, uid, revision| {
                let store = Arc::clone(&resolver_store);
                let zone = resolver_zone.clone();
                let authority = Arc::clone(&resolver_authority);
                let allowed_types = allowed_types.clone();
                Box::pin(async move {
                    if !allowed_types.contains(target.resource_type()) {
                        return Err(SourceError::Integrity);
                    }
                    if let Some(stored) = store
                        .assignment_fence(zone.clone(), target.clone())
                        .await
                        .map_err(|error| match error.kind() {
                            StoreErrorKind::Backpressure
                            | StoreErrorKind::StoreBackpressure => SourceError::Backpressure,
                            StoreErrorKind::Timeout => SourceError::Timeout,
                            _ => SourceError::Unavailable,
                        })?
                    {
                        if stored.resource_uid != uid
                            || stored.epoch > authority.epoch
                            || (stored.epoch == authority.epoch
                                && (stored.provider_generation != authority.provider_generation
                                    || stored.controller_generation
                                        != authority.controller_generation
                                    || stored.controller_role != authority.controller_role
                                    || stored.target != authority.target
                                    || stored.session_generation != authority.session_generation))
                        {
                            return Err(SourceError::Integrity);
                        }
                        if stored.epoch == authority.epoch
                            && stored.resource_revision != revision
                        {
                            return Err(SourceError::Conflict(stored.resource_revision));
                        }
                    }
                    Ok(ResourceAssignmentFence {
                        resource_uid: uid,
                        resource_revision: revision,
                        provider_generation: authority.provider_generation,
                        controller_generation: authority.controller_generation,
                        controller_role: authority.controller_role.clone(),
                        target: authority.target.clone(),
                        session_generation: authority.session_generation,
                        epoch: authority.epoch,
                        scope: ResourceAssignmentScope::Primary,
                    })
                })
            });
            let api = api.with_assignment_fence_resolver(resolver);
            let source = CoreControllerSource::new(descriptor.clone(), Arc::new(api));
            let task = if matches!(kind, U12ControllerKind::Telemetry) {
                let reconciler = Arc::new(TelemetryResourceReconciler::new(
                    Arc::clone(&self.store),
                    Arc::clone(&status_client),
                    identity,
                ));
                let runner = Runner::new(
                    reconciler,
                    source,
                    RunnerConfig {
                        policy_revision: authorization_state.snapshot.policy_revision,
                        api_revision: authorization_state.snapshot.api_catalog_revision,
                        configuration_revision: authorization_state
                            .snapshot
                            .active_configuration_revision,
                        deadline_tick: 5_000,
                        max_attempts: 3,
                    },
                );
                tokio::spawn(async move {
                    let _ = runner.run().await;
                })
            } else {
                let reconciler = Arc::new(ActivationResourceReconciler::new(
                    Arc::clone(&self.store),
                    Arc::clone(&status_client),
                    Arc::clone(&state),
                    identity,
                ));
                let runner = Runner::new(
                    reconciler,
                    source,
                    RunnerConfig {
                        policy_revision: authorization_state.snapshot.policy_revision,
                        api_revision: authorization_state.snapshot.api_catalog_revision,
                        configuration_revision: authorization_state
                            .snapshot
                            .active_configuration_revision,
                        deadline_tick: 5_000,
                        max_attempts: 3,
                    },
                );
                tokio::spawn(async move {
                    let _ = runner.run().await;
                })
            };
                new_tasks.push(task);
            }
            Ok(required)
        }
        .await;
        let required = match build_result {
            Ok(required) => required,
            Err(error) => {
                abort_u12_runner_tasks(&mut new_tasks).await;
                return Err(error);
            }
        };
        match self.u12_runner_tasks.lock() {
            Ok(mut tasks) => tasks.extend(new_tasks),
            Err(_) => {
                abort_u12_runner_tasks(&mut new_tasks).await;
                return Err(ResourceRuntimeError::WatchUnavailable);
            }
        }
        self.u12_required.store(required, Ordering::Release);
        Ok(())
    }

    async fn u12_resources_present(
        &self,
        resource_types: &[&str],
    ) -> Result<bool, ResourceRuntimeError> {
        let resource_types = resource_types
            .iter()
            .map(|resource_type| {
                ResourceTypeName::parse((*resource_type).to_owned())
                    .map_err(|_| ResourceRuntimeError::HandlerNotReady)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let page = self
            .store
            .list(StoreListRequest {
                operation: StoreOperationContext {
                    operation_id: "u12-provider-presence".to_owned(),
                    idempotency_key: None,
                    correlation_id: "u12-provider-presence".to_owned(),
                    trace_id: None,
                    deadline_ms: 10_000,
                },
                zone: self.zone.clone(),
                resource_types,
                resource_names: Vec::new(),
                filters: Vec::new(),
                page_size: 1,
                cursor: None,
                projection: StoreProjection::MetadataOnly,
            })
            .await
            .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;
        Ok(!page.resources.is_empty())
    }

    async fn u12_controller_assignments(
        &self,
        descriptor: &d2b_core_controller::ControllerDescriptor,
        controller_ref: ResourceRef,
        provider_generation: ResourceGeneration,
        controller_generation: ControllerGeneration,
        session_generation: ReconnectGeneration,
    ) -> Result<
        (
            Vec<(ResourceRef, ResourceAssignmentFence)>,
            Arc<CoreAssignmentAuthority>,
        ),
        ResourceRuntimeError,
    > {
        let resource_types = descriptor.resource_types().cloned().collect::<Vec<_>>();
        let mut resources = Vec::new();
        let mut cursor = None;
        loop {
            let page = self
                .store
                .list(StoreListRequest {
                    operation: StoreOperationContext {
                        operation_id: "u12-controller-assignment-relist".to_owned(),
                        idempotency_key: None,
                        correlation_id: "u12-controller-assignment-relist".to_owned(),
                        trace_id: None,
                        deadline_ms: 10_000,
                    },
                    zone: self.zone.clone(),
                    resource_types: resource_types.clone(),
                    resource_names: Vec::new(),
                    filters: Vec::new(),
                    page_size: 256,
                    cursor,
                    projection: StoreProjection::MetadataOnly,
                })
                .await
                .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;
            resources.extend(page.resources);
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        let target = ResourceRef::parse(&format!("Zone/{}", self.zone.as_str()))
            .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
        let mut durable_epoch = 0;
        for resource in &resources {
            if let Some(fence) = self
                .store
                .assignment_fence(self.zone.clone(), resource.resource_ref.clone())
                .await
                .map_err(|_| ResourceRuntimeError::StoreReadFailed)?
            {
                durable_epoch = durable_epoch.max(fence.epoch);
            }
        }
        let epoch = self
            .core_assignment_epoch
            .load(Ordering::Acquire)
            .max(durable_epoch)
            .max(1);
        let authority = Arc::new(CoreAssignmentAuthority {
            provider_generation,
            controller_generation,
            session_generation,
            controller_role: controller_ref.clone(),
            target: target.clone(),
            epoch,
        });
        let assignments = resources
            .into_iter()
            .filter(|resource| {
                resource
                    .resource_ref
                    .resource_type()
                    .to_canonical_string()
                    != "Provider"
            })
            .map(|resource| {
                (
                    resource.resource_ref,
                    ResourceAssignmentFence {
                        resource_uid: resource.uid,
                        resource_revision: resource.revision,
                        provider_generation,
                        controller_generation,
                        controller_role: controller_ref.clone(),
                        target: target.clone(),
                        session_generation,
                        epoch,
                        scope: ResourceAssignmentScope::Primary,
                    },
                )
            })
            .collect();
        Ok((assignments, authority))
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn core_controller_runner_count(&self) -> usize {
        self.core_runner_tasks
            .lock()
            .map(|tasks| tasks.len())
            .unwrap_or_default()
    }

    /// Persist a provider reconcile phase through the authenticated Resource
    /// API so restart admission can rely on durable observed generation.
    pub(crate) async fn persist_public_reconcile_phase(
        &self,
        resource_ref: &ResourceRef,
        resource_uid: &ResourceUid,
        operation_id: &str,
        phase: &str,
    ) -> Result<(), ResourceRuntimeError> {
        self.persist_public_reconcile_status(resource_ref, resource_uid, operation_id, phase, None)
            .await
    }

    /// Persist a provider phase together with its typed durable projection.
    ///
    /// Provider readiness must be observed from this committed projection on
    /// the next reconcile pass; an in-memory effect port is not an authority
    /// for restart or dependent-resource admission.
    pub(crate) async fn persist_public_reconcile_status(
        &self,
        resource_ref: &ResourceRef,
        resource_uid: &ResourceUid,
        operation_id: &str,
        phase: &str,
        resource_projection: Option<&Value>,
    ) -> Result<(), ResourceRuntimeError> {
        let resource = self
            .backend
            .get(StoreGetRequest {
                operation: StoreOperationContext {
                    operation_id: operation_id.to_owned(),
                    idempotency_key: None,
                    correlation_id: operation_id.to_owned(),
                    trace_id: None,
                    deadline_ms: 30_000,
                },
                zone: self.zone.clone(),
                target: resource_ref.clone(),
                expected_uid: Some(resource_uid.clone()),
                projection: StoreProjection::Full,
            })
            .await
            .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;
        let current = serde_json::from_slice::<Value>(&resource.canonical_json)
            .map_err(|_| ResourceRuntimeError::ResponseInvalid)?;
        let current_phase = current
            .get("status")
            .and_then(|status| status.get("phase"))
            .and_then(Value::as_str);
        let current_observed_generation = current
            .get("status")
            .and_then(|status| status.get("observedGeneration"))
            .and_then(Value::as_u64);
        if current_phase == Some(phase)
            && current_observed_generation == Some(resource.generation.get())
            && resource_projection.is_none()
        {
            return Ok(());
        }
        let status = json!({ "phase": phase });
        let client = self
            .status_client()
            .map_err(|_| ResourceRuntimeError::ControllerEndpointUnavailable)?;
        let projection = resource_projection.or_else(|| {
            current
                .get("status")
                .and_then(|status| status.get("resource"))
        });
        persist_resource_status_with_projection(&client, &resource, &status, projection).await
    }

    /// Drive the complete Wave 6 acceptance sequence through the
    /// authenticated public Resource API and the production Provider
    /// boundary.
    ///
    /// This is intentionally an explicit orchestration entry point rather
    /// than a second controller implementation. The Resource API selects the
    /// durable objects, while the supplied boundary invokes the shipped
    /// Volume, Network, Device TPM, and Cloud Hypervisor controllers.
    pub async fn reconcile_wave6_operator_acceptance<B>(
        &self,
        client: &ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>,
        boundary: &B,
    ) -> Result<Wave6AcceptanceReport, ResourceRuntimeError>
    where
        B: Wave6ProviderBoundary,
    {
        if !self.readiness.is_ready() {
            return Err(ResourceRuntimeError::PlaneUnavailable);
        }
        let resources = select_wave6_resources(client)
            .await
            .map_err(|_| ResourceRuntimeError::Wave6AcceptanceFailed)?;

        let require_ready = |result: Wave6ReconcileResult| {
            if matches!(result, Wave6ReconcileResult::Ready) {
                Ok(())
            } else {
                Err(ResourceRuntimeError::Wave6AcceptanceFailed)
            }
        };

        require_ready(
            boundary
                .reconcile_volume(&resources.volume)
                .await
                .map_err(|_| ResourceRuntimeError::Wave6AcceptanceFailed)?,
        )?;
        require_ready(
            boundary
                .reconcile_device_tpm(&resources.device_tpm)
                .await
                .map_err(|_| ResourceRuntimeError::Wave6AcceptanceFailed)?,
        )?;

        if !matches!(
            boundary
                .reconcile_network(
                    &resources.network,
                    Wave6Dependencies::network_waiting_for_volume(),
                )
                .await
                .map_err(|_| ResourceRuntimeError::Wave6AcceptanceFailed)?,
            Wave6ReconcileResult::Waiting
        ) {
            return Err(ResourceRuntimeError::Wave6AcceptanceFailed);
        }
        if !matches!(
            boundary
                .reconcile_cloud_hypervisor_guest(
                    &resources.cloud_hypervisor_guest,
                    Wave6Dependencies::guest_waiting_for_network(),
                )
                .await
                .map_err(|_| ResourceRuntimeError::Wave6AcceptanceFailed)?,
            Wave6ReconcileResult::Waiting
        ) {
            return Err(ResourceRuntimeError::Wave6AcceptanceFailed);
        }

        require_ready(
            boundary
                .reconcile_network(
                    &resources.network,
                    Wave6Dependencies::network_ready_for_guest(),
                )
                .await
                .map_err(|_| ResourceRuntimeError::Wave6AcceptanceFailed)?,
        )?;
        require_ready(
            boundary
                .reconcile_cloud_hypervisor_guest(
                    &resources.cloud_hypervisor_guest,
                    Wave6Dependencies::guest_ready_for_adoption(),
                )
                .await
                .map_err(|_| ResourceRuntimeError::Wave6AcceptanceFailed)?,
        )?;
        require_ready(
            boundary
                .reconcile_network(
                    &resources.network,
                    Wave6Dependencies::guest_ready_for_adoption(),
                )
                .await
                .map_err(|_| ResourceRuntimeError::Wave6AcceptanceFailed)?,
        )?;

        boundary
            .adopt_after_restart(&resources)
            .await
            .map_err(|_| ResourceRuntimeError::Wave6AcceptanceFailed)?;
        boundary
            .remove_cloud_hypervisor_guest(&resources.cloud_hypervisor_guest)
            .await
            .map_err(|_| ResourceRuntimeError::Wave6AcceptanceFailed)?;
        boundary
            .remove_network(&resources.network)
            .await
            .map_err(|_| ResourceRuntimeError::Wave6AcceptanceFailed)?;
        let device_state_retained = boundary
            .remove_device_tpm(&resources.device_tpm)
            .await
            .map_err(|_| ResourceRuntimeError::Wave6AcceptanceFailed)?;
        if !device_state_retained {
            return Err(ResourceRuntimeError::Wave6AcceptanceFailed);
        }
        boundary
            .remove_volume(&resources.volume)
            .await
            .map_err(|_| ResourceRuntimeError::Wave6AcceptanceFailed)?;

        Ok(Wave6AcceptanceReport {
            resources,
            ready: true,
            adopted_after_restart: true,
            removed: true,
            device_state_retained,
        })
    }

    /// Borrow sealed, committed interaction Provider configuration when the
    /// Zone declares the complete interaction Provider set.
    pub(crate) fn interaction_provider_configuration(
        &self,
    ) -> Option<&CommittedInteractionProviderConfiguration> {
        self.interaction_provider_configuration.as_ref()
    }

    pub(crate) fn interaction_identity(&self) -> Option<&CommittedInteractionIdentity> {
        self.interaction_identity.as_ref()
    }

    /// Resolve the one committed WaylandSession that owns a VM's display
    /// lifecycle. A missing row is reported separately so VM start can fail
    /// closed without inventing a display process or session identity.
    pub(crate) async fn committed_wayland_session_for_vm(
        &self,
        vm: &str,
    ) -> Result<Option<(ResourceRef, ResourceUid, WaylandSessionSpec)>, ResourceRuntimeError> {
        if !self.readiness.resource_api_ready {
            return Err(ResourceRuntimeError::PlaneUnavailable);
        }
        let expected_guest = ResourceRef::parse(&format!("Guest/{vm}"))
            .map_err(|_| ResourceRuntimeError::InteractionConfigurationUnavailable)?;
        let Some(identity) = self.interaction_identity.as_ref() else {
            return Ok(None);
        };
        if identity.subject_ref() != &expected_guest {
            return Err(ResourceRuntimeError::InteractionConfigurationUnavailable);
        }
        let resource = committed_resource(
            &self.zone,
            &self.store,
            self.store_metadata.current_revision,
            identity.wayland_session_ref(),
        )
        .await?;
        let spec = committed_wayland_session_spec(
            &self.zone,
            self.store_metadata.current_revision,
            &resource,
        )?;
        if spec.guest_ref() != &expected_guest || !spec.cross_domain_trusted() {
            return Err(ResourceRuntimeError::InteractionConfigurationUnavailable);
        }
        if identity.wayland_session_ref() != &resource.resource_ref
            || identity.wayland_session_uid() != &resource.uid
            || identity.subject_ref() != spec.guest_ref()
            || identity.host_execution_ref() != spec.host_ref()
            || identity.user_ref() != spec.user_ref()
        {
            return Err(ResourceRuntimeError::InteractionConfigurationUnavailable);
        }
        let envelope = ResourceEnvelope::from_json(&resource.canonical_json)
            .map_err(|_| ResourceRuntimeError::InteractionConfigurationUnavailable)?;
        let deletion_requested = CanonicalJsonValue::parse(&resource.canonical_json)
            .ok()
            .is_some_and(|value| match value {
                CanonicalJsonValue::Object(root) => root
                    .get("metadata")
                    .and_then(CanonicalJsonValue::as_object)
                    .and_then(|metadata| metadata.get("deletionRequestedAt"))
                    .is_some_and(|value| !matches!(value, CanonicalJsonValue::Null)),
                _ => false,
            });
        if matches!(
            envelope.status().phase(),
            ResourcePhase::Failed | ResourcePhase::Deleted
        ) || deletion_requested
        {
            return Err(ResourceRuntimeError::InteractionConfigurationUnavailable);
        }
        Ok(Some((resource.resource_ref, resource.uid, spec)))
    }

    pub(crate) const fn interaction_provider_configuration_refused(&self) -> bool {
        self.interaction_provider_configuration_refused
    }

    /// Return the current core-controller stage.
    pub fn core_stage(&self) -> Result<StartupStage, ResourceRuntimeError> {
        self.core
            .lock()
            .map(|core| core.stage())
            .map_err(|_| ResourceRuntimeError::CoreStartupFailed)
    }

    /// Borrow the production Zone status projection.
    pub fn zone_status(&self) -> Result<ZoneStatusResource, ResourceRuntimeError> {
        self.zone_status
            .lock()
            .map(|status| status.clone())
            .map_err(|_| ResourceRuntimeError::HandlerNotReady)
    }

    /// Read committed resources for a root-owned Provider admission scan.
    ///
    /// This bypasses caller authorization intentionally: the result is used
    /// only by the root supervisor to resolve same-Zone attachment
    /// relationships before host effects. It never crosses the public API.
    pub(crate) async fn committed_resources_of_type(
        &self,
        resource_type: &str,
    ) -> Result<Vec<Value>, ResourceRuntimeError> {
        let resource_type = ResourceTypeName::parse(resource_type.to_owned())
            .map_err(|_| ResourceRuntimeError::RequestInvalid)?;
        let mut cursor = None;
        let mut out = Vec::new();
        loop {
            let page = self
                .store
                .list(StoreListRequest {
                    operation: StoreOperationContext {
                        operation_id: "network-admission-scan".to_owned(),
                        idempotency_key: None,
                        correlation_id: "network-admission-scan".to_owned(),
                        trace_id: None,
                        deadline_ms: 10_000,
                    },
                    zone: self.zone.clone(),
                    resource_types: vec![resource_type.clone()],
                    resource_names: Vec::new(),
                    filters: Vec::new(),
                    page_size: 512,
                    cursor,
                    projection: StoreProjection::Full,
                })
                .await
                .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;
            for resource in page.resources {
                out.push(
                    serde_json::from_slice(&resource.canonical_json)
                        .map_err(|_| ResourceRuntimeError::StoreReadFailed)?,
                );
            }
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        Ok(out)
    }

    pub(crate) async fn committed_resource_value(
        &self,
        target: &ResourceRef,
        operation_id: &str,
    ) -> Result<Value, ResourceRuntimeError> {
        let resource = self
            .store
            .get(StoreGetRequest {
                operation: StoreOperationContext {
                    operation_id: operation_id.to_owned(),
                    idempotency_key: None,
                    correlation_id: operation_id.to_owned(),
                    trace_id: None,
                    deadline_ms: 10_000,
                },
                zone: self.zone.clone(),
                target: target.clone(),
                expected_uid: None,
                projection: StoreProjection::Full,
            })
            .await
            .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;
        if resource.zone != self.zone || resource.resource_ref != *target {
            return Err(ResourceRuntimeError::StoreReadFailed);
        }
        serde_json::from_slice(&resource.canonical_json)
            .map_err(|_| ResourceRuntimeError::StoreReadFailed)
    }

    /// Publish a validated status projection from the real system-core
    /// handler observations.
    pub fn publish_zone_status(&self, input: ZoneStatusInput) -> Result<(), ResourceRuntimeError> {
        let status = SystemCoreStatusEmitter::new()
            .emit(input)
            .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
        self.zone_status
            .lock()
            .map(|mut current| {
                *current = status;
            })
            .map_err(|_| ResourceRuntimeError::HandlerNotReady)
    }

    /// Refresh provider counts and other live metadata without replacing the
    /// currently observed handler phases.
    pub fn publish_runtime_metadata(
        &self,
        runtime: ZoneRuntimeMetadata,
    ) -> Result<(), ResourceRuntimeError> {
        let current = self.zone_status()?;
        self.publish_zone_status(
            ZoneStatusInput::new(current.core_controller_phase(), current.handlers().to_vec())
                .with_runtime_metadata(runtime),
        )
    }

    /// Publish the provider registry's live counts while retaining store and
    /// handler metadata already projected into status.
    pub fn publish_provider_counts(
        &self,
        installed_provider_count: u32,
        ready_provider_count: u32,
    ) -> Result<(), ResourceRuntimeError> {
        let current = self.zone_status()?;
        let mut runtime = zone_runtime_metadata(
            &self.store_metadata,
            current.total_resource_count(),
            current.generation_cleanup_pending(),
            current.cleanup_pending_count(),
            Some(current_status_timestamp()),
        );
        runtime.installed_provider_count = installed_provider_count;
        runtime.ready_provider_count = ready_provider_count;
        self.publish_runtime_metadata(runtime)
    }

    /// Mark the trusted Provider path after the daemon has configured it.
    ///
    /// Provider configuration is loaded outside this Zone store boundary, so
    /// `open` cannot claim this bit from the descriptor alone.
    pub fn set_provider_path_ready(&mut self, ready: bool) {
        self.readiness.provider_path_ready = ready;
    }

    /// Install the integrity-pinned semantic Guest setup descriptors supplied
    /// by the trusted artifact catalog.
    pub(crate) fn set_guest_setup_descriptors(
        &mut self,
        descriptors: impl IntoIterator<Item = (String, Vec<u8>)>,
    ) {
        self.guest_setup_descriptors = descriptors.into_iter().collect();
    }

    pub(crate) fn set_guest_setup_descriptor_catalog_keys(
        &mut self,
        keys: impl IntoIterator<Item = (String, String)>,
    ) {
        self.guest_setup_descriptor_catalog_keys = keys.into_iter().collect();
    }

    /// Reconcile Cloud Hypervisor Guests through the controller-owned child
    /// graph. The controller receives only an authenticated Resource API
    /// adapter and a verified private descriptor.
    pub(crate) async fn reconcile_cloud_hypervisor_guests(
        &self,
        state: Arc<crate::ServerState>,
    ) -> Result<(), ResourceRuntimeError> {
        self.reconcile_cloud_hypervisor_guests_inner(state, None).await
    }

    /// Reconcile one Cloud Hypervisor Guest selected by the shared Runner.
    ///
    /// The legacy relist helper remains available to explicit lifecycle
    /// commands, but the shared Runner always supplies one exact Guest key.
    pub(crate) async fn reconcile_cloud_hypervisor_guest(
        &self,
        state: Arc<crate::ServerState>,
        guest_ref: &ResourceRef,
    ) -> Result<(), ResourceRuntimeError> {
        self.reconcile_cloud_hypervisor_guests_inner(state, Some(guest_ref))
            .await
    }

    async fn reconcile_cloud_hypervisor_guests_inner(
        &self,
        state: Arc<crate::ServerState>,
        selected_guest: Option<&ResourceRef>,
    ) -> Result<(), ResourceRuntimeError> {
        if !self.readiness.resource_api_ready {
            return Ok(());
        }
        let _guard = self.cloud_hypervisor_reconcile_lock.lock().await;
        let client = self.cloud_hypervisor_resource_client().inspect_err(|error| {
            tracing::warn!(error = ?error, "Cloud Hypervisor reconcile stage failed: controller-client");
        })?;
        let guests = match selected_guest {
            Some(guest_ref) => vec![guest_ref.clone()],
            None => self
                .list_cloud_hypervisor_guests()
                .await
                .map_err(|_| ResourceRuntimeError::StoreReadFailed)?,
        };
        for guest_ref in guests {
            if selected_guest.is_some_and(|selected| selected != &guest_ref) {
                continue;
            }
            let Some(descriptor_bytes) =
                self.guest_setup_descriptors.get(guest_ref.name().as_str())
            else {
                tracing::warn!(
                    zone = %self.zone.as_str(),
                    guest = %guest_ref.name().as_str(),
                    "Cloud Hypervisor Guest controller descriptor is unavailable",
                );
                continue;
            };
            let Some(expected_key) = self
                .guest_setup_descriptor_catalog_keys
                .get(guest_ref.name().as_str())
            else {
                tracing::warn!(
                    zone = %self.zone.as_str(),
                    guest = %guest_ref.name().as_str(),
                    "Cloud Hypervisor Guest descriptor catalog key is unavailable",
                );
                continue;
            };
            let descriptor = GuestSetupDescriptor::from_canonical_bytes(descriptor_bytes)
                .map_err(|_| {
                    tracing::warn!("Cloud Hypervisor reconcile stage failed: descriptor-decode");
                    ResourceRuntimeError::CapabilityUnavailable
                })?
                .verify_with(&CatalogDescriptorVerifier {
                    expected_key: expected_key.clone(),
                })
                .map_err(|_| {
                    tracing::warn!("Cloud Hypervisor reconcile stage failed: descriptor-verify");
                    ResourceRuntimeError::CapabilityUnavailable
                })?;
            let (provider_ref, execution_ref, config, graph) =
                self.cloud_hypervisor_inputs(&guest_ref).await.inspect_err(|error| {
                    tracing::warn!(error = ?error, "Cloud Hypervisor reconcile stage failed: inputs");
                })?;
            let (_, guest_uid, guest_generation, provider_assignment_generation) = self
                .guest_lifecycle_identity(&guest_ref)
                .await
                .inspect_err(|error| {
                    tracing::warn!(error = ?error, "Cloud Hypervisor reconcile stage failed: lifecycle-identity");
                })?;
            let lifecycle_intent = match state.provider_runtime.latest_v3_lifecycle_operation(
                &provider_ref,
                &self.store_metadata.zone_uid,
                &guest_ref,
                &guest_uid,
                guest_generation,
                provider_assignment_generation,
                self.store_metadata.policy_snapshot.policy_revision,
            ) {
                Ok(intent) => intent,
                Err(
                    crate::provider_effects::ProviderEffectError::ProviderNotRegistered
                    | crate::provider_effects::ProviderEffectError::RegistryUnavailable,
                ) => None,
                Err(error) => {
                    tracing::warn!(
                        error = ?error,
                        "Cloud Hypervisor reconcile stage failed: lifecycle-intent",
                    );
                    return Err(ResourceRuntimeError::CapabilityUnavailable);
                }
            }
            .map(|operation| match operation {
                crate::provider_effects::GuestLifecycleOperation::Stop => DesiredLifecycle::Stopped,
                crate::provider_effects::GuestLifecycleOperation::Start
                | crate::provider_effects::GuestLifecycleOperation::Restart => {
                    DesiredLifecycle::Running
                }
            });
            let guest_session_target =
                crate::resolve_committed_guest_session_target(self, &guest_ref)
                    .await
                    .ok();
            // Deletion may reuse the already authenticated live session below,
            // but it never creates a new session solely to clear a finalizer.
            // A durable Closed marker therefore remains terminal for session
            // custody during finalization.
            let guest_session = match guest_session_target.as_ref() {
                Some(target) => state
                    .guest_component_sessions
                    .lock()
                    .await
                    .get(&target.key())
                    .cloned(),
                None => None,
            };
            let session_evidence = guest_session.as_ref().and_then(|session| {
                guest_session_target.as_ref().and_then(|target| {
                    guest_session_evidence(&guest_ref, session.as_ref(), &descriptor, target)
                })
            });
            let finalizer_clear_requested = Arc::new(AtomicBool::new(false));
            self.ensure_cloud_hypervisor_controller_deployment(
                &provider_ref,
                &config,
            )
            .await
            .inspect_err(|error| {
                tracing::warn!(error = ?error, "Cloud Hypervisor reconcile stage failed: deployment");
            })?;
            let session = CloudHypervisorResourceSession {
                client: Arc::clone(&client),
                mutation_client: self.status_client()?,
                providers: state
                    .provider_runtime
                    .process_providers()
                    .ok_or(ResourceRuntimeError::ProviderPathUnavailable)?,
                guest_sessions: Arc::clone(&state.guest_component_sessions),
                closed_guest_sessions: Arc::clone(&self.closed_guest_sessions),
                zone: self.zone.clone(),
                zone_uid: self.store_metadata.zone_uid.clone(),
                policy_revision: self.store_metadata.policy_snapshot.policy_revision,
                provider_ref,
                execution_ref,
                descriptor: descriptor.clone(),
                controller_generation: self
                    .store_metadata
                    .policy_snapshot
                    .controller_generation
                    .unwrap_or_else(|| ControllerGeneration::new(1).expect("generation one")),
                session_target: guest_session_target,
                session_evidence,
                suppress_finalizer_clear: selected_guest.is_some(),
                finalizer_clear_requested: Arc::clone(&finalizer_clear_requested),
            };
            let adapter = AuthenticatedResourceApiAdapter::new(Arc::new(session));
            let mut controller = CloudHypervisorController::from_verified_descriptor(
                config,
                graph,
                descriptor,
                Arc::new(adapter),
            )
            .map(|controller| controller.with_lifecycle_intent(lifecycle_intent))
            .map_err(|_| {
                tracing::warn!("Cloud Hypervisor reconcile stage failed: controller-construction");
                ResourceRuntimeError::CapabilityUnavailable
            })?;
            controller
                .register()
                .await
                .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?;
            if let Err(error) = controller.reconcile(&guest_ref).await {
                tracing::warn!(
                    zone = %self.zone.as_str(),
                    guest = %guest_ref.name().as_str(),
                    error = %error,
                    "Cloud Hypervisor Guest controller reconcile refused",
                );
                return Err(ResourceRuntimeError::CapabilityUnavailable);
            }
            let deleting_or_gone = self
                .committed_resource_value(&guest_ref, "cloud-hypervisor-deletion-state")
                .await
                .map(|value| {
                    value
                        .pointer("/metadata/deletionRequestedAt")
                        .is_some_and(|value| !value.is_null())
                })
                .unwrap_or(true);
            if deleting_or_gone {
                if selected_guest.is_some()
                    && !finalizer_clear_requested.load(Ordering::Acquire)
                {
                    return Err(ResourceRuntimeError::CapabilityUnavailable);
                }
                continue;
            }
            self.reconcile_cloud_hypervisor_setup_volume(&state, &guest_ref)
                .await?;
            controller.reconcile(&guest_ref).await.map_err(|error| {
                tracing::warn!(
                    zone = %self.zone.as_str(),
                    guest = %guest_ref.name().as_str(),
                    error = %error,
                    "Cloud Hypervisor Guest post-setup reconcile refused",
                );
                ResourceRuntimeError::CapabilityUnavailable
            })?;
            if let Err(error) = self.reconcile_process_resources(Arc::clone(&state)).await {
                tracing::warn!(
                    zone = %self.zone.as_str(),
                    error = ?error,
                    "Cloud Hypervisor dependent Process reconciliation degraded",
                );
            }
            self.reconcile_cloud_hypervisor_endpoints(&guest_ref)
                .await?;
            match crate::resolve_committed_guest_session_target(self, &guest_ref).await {
                Ok(target) => {
                    if let Err(error) =
                        crate::connect_guest_component_session_for_guest(&state, &target).await
                    {
                        tracing::warn!(
                            error = %error,
                            "Cloud Hypervisor Guest ComponentSession connection failed",
                        );
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        "Cloud Hypervisor Guest ComponentSession target resolution failed",
                    );
                }
            }
            controller.reconcile(&guest_ref).await.map_err(|error| {
                tracing::warn!(
                    zone = %self.zone.as_str(),
                    guest = %guest_ref.name().as_str(),
                    error = %error,
                    "Cloud Hypervisor Guest post-Process reconcile refused",
                );
                ResourceRuntimeError::CapabilityUnavailable
            })?;
        }
        Ok(())
    }

    async fn reconcile_cloud_hypervisor_endpoints(
        &self,
        guest_ref: &ResourceRef,
    ) -> Result<(), ResourceRuntimeError> {
        let process_ref = deterministic_child_ref(guest_ref, ChildRole::VmmProcess)
            .map_err(|_| ResourceRuntimeError::CapabilityUnavailable)?;
        let process = self
            .store
            .get(StoreGetRequest {
                operation: StoreOperationContext {
                    operation_id: "cloud-hypervisor-endpoint-process".to_owned(),
                    idempotency_key: None,
                    correlation_id: "cloud-hypervisor-endpoint-process".to_owned(),
                    trace_id: None,
                    deadline_ms: 30_000,
                },
                zone: self.zone.clone(),
                target: process_ref,
                expected_uid: None,
                projection: StoreProjection::Full,
            })
            .await
            .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;
        let process_envelope = ResourceEnvelope::from_json(&process.canonical_json)
            .map_err(|_| ResourceRuntimeError::ResponseInvalid)?;
        if process_envelope.metadata().owner_ref() != Some(guest_ref)
            || process_envelope.status().phase() != ResourcePhase::Ready
        {
            return Err(ResourceRuntimeError::CapabilityUnavailable);
        }
        let provider_ref = ResourceRef::parse("Provider/runtime-cloud-hypervisor")
            .map_err(|_| ResourceRuntimeError::CapabilityUnavailable)?;
        for role in [ChildRole::ChApiEndpoint, ChildRole::GuestControlEndpoint] {
            let endpoint_ref = deterministic_child_ref(guest_ref, role)
                .map_err(|_| ResourceRuntimeError::CapabilityUnavailable)?;
            let endpoint = self
                .store
                .get(StoreGetRequest {
                    operation: StoreOperationContext {
                        operation_id: "cloud-hypervisor-endpoint".to_owned(),
                        idempotency_key: None,
                        correlation_id: "cloud-hypervisor-endpoint".to_owned(),
                        trace_id: None,
                        deadline_ms: 30_000,
                    },
                    zone: self.zone.clone(),
                    target: endpoint_ref.clone(),
                    expected_uid: None,
                    projection: StoreProjection::Full,
                })
                .await
                .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;
            let envelope = ResourceEnvelope::from_json(&endpoint.canonical_json)
                .map_err(|_| ResourceRuntimeError::ResponseInvalid)?;
            if envelope.metadata().owner_ref() != Some(guest_ref)
                || envelope.spec().provider_ref() != Some(&provider_ref)
            {
                return Err(ResourceRuntimeError::CapabilityUnavailable);
            }
            let operation_id = format!(
                "cloud-hypervisor-endpoint-ready-{}-{}",
                endpoint.uid.as_str(),
                endpoint.revision.get(),
            );
            let projection = json!({
                "endpointGeneration": endpoint.generation.get(),
            });
            self.persist_public_reconcile_status(
                &endpoint_ref,
                &endpoint.uid,
                &operation_id,
                "Ready",
                Some(&projection),
            )
            .await?;
        }
        Ok(())
    }

    async fn reconcile_cloud_hypervisor_setup_volume(
        &self,
        state: &crate::ServerState,
        guest_ref: &ResourceRef,
    ) -> Result<(), ResourceRuntimeError> {
        let volume_ref =
            deterministic_child_ref(guest_ref, ChildRole::SystemVolume).map_err(|_| {
                tracing::warn!("Cloud Hypervisor setup Volume ref derivation failed");
                ResourceRuntimeError::CapabilityUnavailable
            })?;
        let volume = self
            .store
            .get(StoreGetRequest {
                operation: StoreOperationContext {
                    operation_id: "cloud-hypervisor-setup-volume".to_owned(),
                    idempotency_key: None,
                    correlation_id: "cloud-hypervisor-setup-volume".to_owned(),
                    trace_id: None,
                    deadline_ms: 30_000,
                },
                zone: self.zone.clone(),
                target: volume_ref.clone(),
                expected_uid: None,
                projection: StoreProjection::Full,
            })
            .await
            .map_err(|_| {
                tracing::warn!("Cloud Hypervisor setup Volume read failed");
                ResourceRuntimeError::StoreReadFailed
            })?;
        let envelope = ResourceEnvelope::from_json(&volume.canonical_json).map_err(|_| {
            tracing::warn!("Cloud Hypervisor setup Volume decode failed");
            ResourceRuntimeError::ResponseInvalid
        })?;
        if envelope.metadata().owner_ref() != Some(guest_ref)
            || envelope.spec().provider_ref()
                != Some(
                    &ResourceRef::parse("Provider/volume-local")
                        .map_err(|_| ResourceRuntimeError::CapabilityUnavailable)?,
                )
        {
            tracing::warn!("Cloud Hypervisor setup Volume ownership validation failed");
            return Err(ResourceRuntimeError::CapabilityUnavailable);
        }
        let resolver = crate::load_bundle_resolver(state).map_err(|_| {
            tracing::warn!("Cloud Hypervisor setup Volume bundle reload failed");
            ResourceRuntimeError::ProviderPathUnavailable
        })?;
        let intent = resolver
            .find_store_view_intent_for_zone(&self.zone, guest_ref.name().as_str())
            .ok_or_else(|| {
                tracing::warn!("Cloud Hypervisor setup Volume store-view intent is unavailable");
                ResourceRuntimeError::ProviderPathUnavailable
            })?;
        let request = d2b_contracts_broker::broker_wire::BrokerRequest::StoreSync(
            d2b_contracts_broker::broker_wire::StoreSyncRequest {
                vm_id: d2b_contracts::types::VmId::new(guest_ref.name().as_str()),
                bundle_closure_ref: d2b_contracts::types::BundleClosureRef::new(
                    intent.intent_id.clone(),
                ),
                generation_token: u32::try_from(intent.generation)
                    .map_err(|_| ResourceRuntimeError::CapabilityUnavailable)?,
                tracing_span_id: None,
            },
        );
        match crate::dispatch_broker_request_as(
            state,
            request,
            d2b_contracts_broker::broker_wire::BrokerCallerRole::AdminUid {
                uid: state.daemon_uid,
            },
        ) {
            Ok(d2b_contracts_broker::broker_wire::BrokerResponse::StoreSync(_)) => {}
            Ok(d2b_contracts_broker::broker_wire::BrokerResponse::Error(error)) => {
                tracing::warn!(
                    broker_kind = %error.kind,
                    broker_operation = %error.operation,
                    broker_message = %error.message,
                    broker_action = %error.action,
                    "Cloud Hypervisor setup Volume store sync failed",
                );
                return Err(ResourceRuntimeError::CapabilityUnavailable);
            }
            Ok(_) => {
                tracing::warn!("Cloud Hypervisor setup Volume store sync returned wrong response");
                return Err(ResourceRuntimeError::CapabilityUnavailable);
            }
            Err(error) => {
                tracing::warn!(
                    error = ?error,
                    "Cloud Hypervisor setup Volume store sync dispatch failed",
                );
                return Err(ResourceRuntimeError::CapabilityUnavailable);
            }
        }
        let operation_id = format!(
            "cloud-hypervisor-setup-volume-ready-{}-{}",
            volume.uid.as_str(),
            volume.revision.get(),
        );
        self.persist_public_reconcile_phase(&volume_ref, &volume.uid, &operation_id, "Ready")
            .await
            .inspect_err(|error| {
                tracing::warn!(
                    error = ?error,
                    "Cloud Hypervisor setup Volume status commit failed",
                );
            })
    }

    async fn ensure_cloud_hypervisor_controller_deployment(
        &self,
        provider_ref: &ResourceRef,
        config: &CloudHypervisorConfig,
    ) -> Result<(), ResourceRuntimeError> {
        if !self
            .controller_deployment
            .controller_processes()
            .map_err(|_| ResourceRuntimeError::CapabilityUnavailable)?
            .is_empty()
        {
            return Ok(());
        }
        let provider = self
            .store
            .get(StoreGetRequest {
                operation: StoreOperationContext {
                    operation_id: "cloud-hypervisor-controller-deployment".to_owned(),
                    idempotency_key: None,
                    correlation_id: "cloud-hypervisor-controller-deployment".to_owned(),
                    trace_id: None,
                    deadline_ms: 10_000,
                },
                zone: self.zone.clone(),
                target: provider_ref.clone(),
                expected_uid: None,
                projection: StoreProjection::Full,
            })
            .await
            .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;
        let manifest = d2b_provider_runtime_cloud_hypervisor::provider_manifest()
            .map_err(|_| ResourceRuntimeError::CapabilityUnavailable)?;
        let controller_generation = self
            .store_metadata
            .policy_snapshot
            .controller_generation
            .unwrap_or_else(|| ControllerGeneration::new(1).expect("generation one"));
        let process_provider_ref = ResourceRef::parse("Provider/system-minijail")
            .map_err(|_| ResourceRuntimeError::CapabilityUnavailable)?;
        let controllers = crate::provider_registry::deploy_target_local_controllers(
            &self.controller_deployment,
            self.zone.clone(),
            provider_ref.clone(),
            &manifest,
            provider.generation,
            provider.generation,
            controller_generation,
            ReconnectGeneration::new(1).map_err(|_| ResourceRuntimeError::CapabilityUnavailable)?,
            provider.revision,
            ResourceRef::parse(&config.controller_execution_ref.to_canonical_string())
                .map_err(|_| ResourceRuntimeError::CapabilityUnavailable)?,
            process_provider_ref,
            true,
        )
        .map_err(|_| ResourceRuntimeError::CapabilityUnavailable)?;
        if controllers.is_empty() {
            return Err(ResourceRuntimeError::CapabilityUnavailable);
        }
        Ok(())
    }

    fn cloud_hypervisor_resource_client(
        &self,
    ) -> Result<Arc<CloudHypervisorResourceClient>, ResourceRuntimeError> {
        if let Ok(sessions) = self.controller_sessions.lock()
            && let Some(session) = sessions.values().find(|session| {
                d2b_provider_runtime_cloud_hypervisor::is_provider_ref(
                    session.context.provider_owner_ref(),
                ) && !session.service_task.is_finished()
            })
        {
            return Ok(Arc::clone(&session.resource_client));
        }
        self.status_client()
    }

    /// Route a v3 Guest lifecycle request to its controller-owned VMM
    /// Process child. No legacy process-DAG lookup or direct VMM effect is
    /// permitted on this path.
    pub(crate) async fn apply_cloud_hypervisor_lifecycle(
        &self,
        state: Arc<crate::ServerState>,
        guest_ref: &ResourceRef,
        expected_guest_uid: &ResourceUid,
        expected_guest_generation: ResourceGeneration,
        operation: crate::provider_effects::GuestLifecycleOperation,
    ) -> Result<(), ResourceRuntimeError> {
        if guest_ref.resource_type().as_str() != "Guest" {
            return Err(ResourceRuntimeError::RequestInvalid);
        }
        let (_, guest_uid, guest_generation, _) = self.guest_lifecycle_identity(guest_ref).await?;
        if &guest_uid != expected_guest_uid || guest_generation != expected_guest_generation {
            return Err(ResourceRuntimeError::RequestInvalid);
        }
        self.reconcile_cloud_hypervisor_guests(Arc::clone(&state))
            .await?;
        if matches!(
            operation,
            crate::provider_effects::GuestLifecycleOperation::Start
                | crate::provider_effects::GuestLifecycleOperation::Restart
        ) {
            let (_, _, _, graph) = self.cloud_hypervisor_inputs(guest_ref).await?;
            if !self.cloud_hypervisor_dependencies_ready(&graph).await? {
                return Err(ResourceRuntimeError::CapabilityUnavailable);
            }
        }
        let process_ref = deterministic_child_ref(guest_ref, ChildRole::VmmProcess)
            .map_err(|_| ResourceRuntimeError::CapabilityUnavailable)?;
        match operation {
            crate::provider_effects::GuestLifecycleOperation::Start => {
                self.update_cloud_hypervisor_process_lifecycle(
                    guest_ref,
                    &process_ref,
                    DesiredLifecycle::Running,
                )
                .await?;
            }
            crate::provider_effects::GuestLifecycleOperation::Stop => {
                self.update_cloud_hypervisor_process_lifecycle(
                    guest_ref,
                    &process_ref,
                    DesiredLifecycle::Stopped,
                )
                .await?;
            }
            crate::provider_effects::GuestLifecycleOperation::Restart => {
                self.update_cloud_hypervisor_process_lifecycle(
                    guest_ref,
                    &process_ref,
                    DesiredLifecycle::Stopped,
                )
                .await?;
                self.reconcile_process_resources(Arc::clone(&state)).await?;
                self.update_cloud_hypervisor_process_lifecycle(
                    guest_ref,
                    &process_ref,
                    DesiredLifecycle::Running,
                )
                .await?;
            }
        }
        self.reconcile_process_resources(state).await
    }

    async fn cloud_hypervisor_dependencies_ready(
        &self,
        graph: &BootstrapGraph,
    ) -> Result<bool, ResourceRuntimeError> {
        for resource_ref in graph
            .devices
            .iter()
            .chain(graph.networks.iter())
            .chain(graph.volumes.iter())
        {
            let resource = match self
                .store
                .get(StoreGetRequest {
                    operation: StoreOperationContext {
                        operation_id: "cloud-hypervisor-lifecycle-dependencies".to_owned(),
                        idempotency_key: None,
                        correlation_id: "cloud-hypervisor-lifecycle-dependencies".to_owned(),
                        trace_id: None,
                        deadline_ms: 10_000,
                    },
                    zone: self.zone.clone(),
                    target: resource_ref.clone(),
                    expected_uid: None,
                    projection: StoreProjection::Full,
                })
                .await
            {
                Ok(resource) => resource,
                Err(error) if error.kind() == StoreErrorKind::ResourceNotFound => {
                    return Ok(false);
                }
                Err(_) => return Err(ResourceRuntimeError::StoreReadFailed),
            };
            let envelope = ResourceEnvelope::from_json(&resource.canonical_json)
                .map_err(|_| ResourceRuntimeError::ResponseInvalid)?;
            if envelope.status().phase() != ResourcePhase::Ready {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(crate) async fn wait_cloud_hypervisor_lifecycle(
        &self,
        state: Arc<crate::ServerState>,
        guest_ref: &ResourceRef,
        expected_guest_uid: &ResourceUid,
        expected_guest_generation: ResourceGeneration,
        operation: crate::provider_effects::GuestLifecycleOperation,
    ) -> Result<(), ResourceRuntimeError> {
        let (_, _, config, _) = self.cloud_hypervisor_inputs(guest_ref).await?;
        let deadline = std::time::Instant::now()
            + std::time::Duration::from_millis(u64::from(config.startup_deadline_ms));
        loop {
            let (_, guest_uid, guest_generation, _) =
                self.guest_lifecycle_identity(guest_ref).await?;
            if &guest_uid != expected_guest_uid || guest_generation != expected_guest_generation {
                return Err(ResourceRuntimeError::RequestInvalid);
            }
            self.reconcile_cloud_hypervisor_guests(Arc::clone(&state))
                .await?;
            if let Ok(target) = crate::resolve_committed_guest_session_target(self, guest_ref).await
            {
                let _ = crate::connect_guest_component_session_for_guest(&state, &target).await;
            }
            let actual = self
                .cloud_hypervisor_lifecycle_state(Arc::clone(&state), guest_ref)
                .await?;
            let lifecycle_satisfied = match operation {
                crate::provider_effects::GuestLifecycleOperation::Start
                | crate::provider_effects::GuestLifecycleOperation::Restart => {
                    actual == crate::provider_effects::GuestLifecycleState::Started
                        && self.cloud_hypervisor_guest_ready(guest_ref).await?
                }
                crate::provider_effects::GuestLifecycleOperation::Stop => {
                    actual == crate::provider_effects::GuestLifecycleState::Stopped
                }
            };
            if lifecycle_satisfied {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(ResourceRuntimeError::CapabilityUnavailable);
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    async fn cloud_hypervisor_guest_ready(
        &self,
        guest_ref: &ResourceRef,
    ) -> Result<bool, ResourceRuntimeError> {
        let guest = self
            .store
            .get(StoreGetRequest {
                operation: StoreOperationContext {
                    operation_id: "cloud-hypervisor-guest-ready".to_owned(),
                    idempotency_key: None,
                    correlation_id: "cloud-hypervisor-guest-ready".to_owned(),
                    trace_id: None,
                    deadline_ms: 10_000,
                },
                zone: self.zone.clone(),
                target: guest_ref.clone(),
                expected_uid: None,
                projection: StoreProjection::Full,
            })
            .await
            .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;
        let envelope = ResourceEnvelope::from_json(&guest.canonical_json)
            .map_err(|_| ResourceRuntimeError::ResponseInvalid)?;
        Ok(envelope.status().phase() == ResourcePhase::Ready)
    }

    async fn update_cloud_hypervisor_process_lifecycle(
        &self,
        guest_ref: &ResourceRef,
        process_ref: &ResourceRef,
        desired: DesiredLifecycle,
    ) -> Result<(), ResourceRuntimeError> {
        let client = self.status_client()?;
        let current = self
            .store
            .get(StoreGetRequest {
                operation: StoreOperationContext {
                    operation_id: "cloud-hypervisor-vmm-lifecycle".to_owned(),
                    idempotency_key: None,
                    correlation_id: "cloud-hypervisor-vmm-lifecycle".to_owned(),
                    trace_id: None,
                    deadline_ms: 30_000,
                },
                zone: self.zone.clone(),
                target: process_ref.clone(),
                expected_uid: None,
                projection: StoreProjection::Full,
            })
            .await
            .map_err(|_| ResourceRuntimeError::CapabilityUnavailable)?;
        let envelope = ResourceEnvelope::from_json(&current.canonical_json)
            .map_err(|_| ResourceRuntimeError::CapabilityUnavailable)?;
        if envelope.resource_type().as_str() != "Process"
            || envelope.metadata().owner_ref() != Some(guest_ref)
        {
            return Err(ResourceRuntimeError::CapabilityUnavailable);
        }
        let current_value: Value = serde_json::from_slice(&current.canonical_json)
            .map_err(|_| ResourceRuntimeError::CapabilityUnavailable)?;
        let mut spec = current_value
            .get("spec")
            .and_then(Value::as_object)
            .cloned()
            .ok_or(ResourceRuntimeError::CapabilityUnavailable)?;
        spec.insert(
            "desiredLifecycle".to_owned(),
            serde_json::to_value(desired)
                .map_err(|_| ResourceRuntimeError::CapabilityUnavailable)?,
        );
        let payload = replace_public_field(&current_value, "spec", Value::Object(spec))
            .map_err(|_| ResourceRuntimeError::CapabilityUnavailable)?;
        let mut request = wire::UpdateSpecRequest::new();
        request.meta = MessageField::some(public_request_meta("cloud-hypervisor-vmm-lifecycle"));
        let mut mutation = wire::Mutation::new();
        mutation.kind = EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_UPDATE_SPEC);
        mutation.target = MessageField::some(ch_identity(
            &current.zone,
            process_ref,
            Some(&current.uid),
            Some(current.generation.get()),
            Some(current.revision.get()),
        ));
        mutation.precondition =
            MessageField::some(ch_exact_precondition(&current.uid, current.revision));
        mutation.resource = MessageField::some(
            ch_resource_body(&current.zone, process_ref, Some(&current.uid), &payload)
                .map_err(|_| ResourceRuntimeError::CapabilityUnavailable)?,
        );
        request.mutation = MessageField::some(mutation);
        let response = client.update_spec(request).await;
        if response.error.is_some() {
            return Err(ResourceRuntimeError::CapabilityUnavailable);
        }
        Ok(())
    }

    pub(crate) async fn cloud_hypervisor_lifecycle_state(
        &self,
        state: Arc<crate::ServerState>,
        guest_ref: &ResourceRef,
    ) -> Result<crate::provider_effects::GuestLifecycleState, ResourceRuntimeError> {
        let process_ref = deterministic_child_ref(guest_ref, ChildRole::VmmProcess)
            .map_err(|_| ResourceRuntimeError::CapabilityUnavailable)?;
        let process = self
            .store
            .get(StoreGetRequest {
                operation: StoreOperationContext {
                    operation_id: "cloud-hypervisor-vmm-state".to_owned(),
                    idempotency_key: None,
                    correlation_id: "cloud-hypervisor-vmm-state".to_owned(),
                    trace_id: None,
                    deadline_ms: 10_000,
                },
                zone: self.zone.clone(),
                target: process_ref,
                expected_uid: None,
                projection: StoreProjection::Full,
            })
            .await
            .map_err(|_| ResourceRuntimeError::CapabilityUnavailable)?;
        let envelope = ResourceEnvelope::from_json(&process.canonical_json)
            .map_err(|_| ResourceRuntimeError::CapabilityUnavailable)?;
        let spec =
            serde_json::from_slice::<ProcessSpec>(&envelope.spec().base().to_canonical_bytes())
                .map_err(|_| ResourceRuntimeError::CapabilityUnavailable)?;
        if envelope.metadata().owner_ref() != Some(guest_ref) {
            return Err(ResourceRuntimeError::CapabilityUnavailable);
        }
        let provider_ref = envelope
            .spec()
            .provider_ref()
            .cloned()
            .ok_or(ResourceRuntimeError::CapabilityUnavailable)?;
        let providers = state
            .provider_runtime
            .process_providers()
            .ok_or(ResourceRuntimeError::ProviderPathUnavailable)?;
        let descriptor_digest = self
            .guest_setup_descriptors
            .get(guest_ref.name().as_str())
            .and_then(|bytes| {
                GuestSetupDescriptor::from_canonical_bytes(bytes)
                    .ok()
                    .map(|descriptor| descriptor.descriptor_digest().clone())
            });
        let context = crate::process_provider_runtime::ProcessResourceContext::new(
            self.zone.clone(),
            &process.resource_ref,
            &process.uid,
            process.generation,
            process.revision,
            &provider_ref,
            self.store_metadata
                .policy_snapshot
                .controller_generation
                .unwrap_or_else(|| ControllerGeneration::new(1).expect("generation one")),
            Some(guest_ref.clone()),
        )
        .with_lifecycle_identity(
            Some(self.store_metadata.zone_uid.clone()),
            Some(self.store_metadata.policy_snapshot.policy_revision),
            None,
        )
        .with_owner_ref(Some(guest_ref.clone()))
        .with_guest_descriptor_digest(descriptor_digest.as_ref());
        match providers.probe_resource(context, &spec).await {
            Ok(crate::process_provider_runtime::ProviderLiveness::Alive) => {
                Ok(crate::provider_effects::GuestLifecycleState::Started)
            }
            Ok(crate::process_provider_runtime::ProviderLiveness::Exited) => {
                Ok(crate::provider_effects::GuestLifecycleState::Stopped)
            }
            Ok(crate::process_provider_runtime::ProviderLiveness::Unknown) | Err(_) => {
                Err(ResourceRuntimeError::CapabilityUnavailable)
            }
        }
    }

    pub(crate) async fn list_cloud_hypervisor_guests(
        &self,
    ) -> Result<Vec<ResourceRef>, ResourceRuntimeError> {
        let resource_type =
            ResourceTypeName::parse("Guest").map_err(|_| ResourceRuntimeError::RequestInvalid)?;
        let mut request = StoreListRequest {
            operation: StoreOperationContext {
                operation_id: "cloud-hypervisor-guest-relist".to_owned(),
                idempotency_key: None,
                correlation_id: "cloud-hypervisor-guest-relist".to_owned(),
                trace_id: None,
                deadline_ms: 10_000,
            },
            zone: self.zone.clone(),
            resource_types: vec![resource_type],
            resource_names: Vec::new(),
            filters: Vec::new(),
            page_size: 256,
            cursor: None,
            projection: StoreProjection::Full,
        };
        let mut guests = Vec::new();
        loop {
            let page = self
                .store
                .list(request.clone())
                .await
                .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;
            for resource in page.resources {
                let envelope = ResourceEnvelope::from_json(&resource.canonical_json)
                    .map_err(|_| ResourceRuntimeError::ResponseInvalid)?;
                if envelope
                    .spec()
                    .provider_ref()
                    .is_some_and(d2b_provider_runtime_cloud_hypervisor::is_provider_ref)
                {
                    guests.push(resource.resource_ref);
                }
            }
            request.cursor = page.next_cursor;
            if request.cursor.is_none() {
                break;
            }
        }
        Ok(guests)
    }

    async fn cloud_hypervisor_inputs(
        &self,
        guest_ref: &ResourceRef,
    ) -> Result<
        (
            ResourceRef,
            ResourceRef,
            CloudHypervisorConfig,
            BootstrapGraph,
        ),
        ResourceRuntimeError,
    > {
        let guest = self
            .store
            .get(StoreGetRequest {
                operation: StoreOperationContext {
                    operation_id: "cloud-hypervisor-guest-inputs".to_owned(),
                    idempotency_key: None,
                    correlation_id: "cloud-hypervisor-guest-inputs".to_owned(),
                    trace_id: None,
                    deadline_ms: 10_000,
                },
                zone: self.zone.clone(),
                target: guest_ref.clone(),
                expected_uid: None,
                projection: StoreProjection::Full,
            })
            .await
            .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;
        let envelope = ResourceEnvelope::from_json(&guest.canonical_json)
            .map_err(|_| ResourceRuntimeError::ResponseInvalid)?;
        let provider_ref = envelope
            .spec()
            .provider_ref()
            .cloned()
            .filter(|reference| d2b_provider_runtime_cloud_hypervisor::is_provider_ref(reference))
            .ok_or(ResourceRuntimeError::CapabilityUnavailable)?;
        let guest_spec =
            serde_json::from_slice::<GuestSpec>(&envelope.spec().base().to_canonical_bytes())
                .map_err(|_| ResourceRuntimeError::CapabilityUnavailable)?;
        let provider = committed_resource(
            &self.zone,
            &self.store,
            self.store_metadata.current_revision,
            &provider_ref,
        )
        .await?;
        let (provider_spec, _, _, _, _) = committed_provider_spec(
            &self.zone,
            self.store_metadata.current_revision,
            &provider,
            &provider_ref,
        )?;
        let config = serde_json::from_slice::<CloudHypervisorConfig>(
            &provider_spec.config().to_canonical_bytes(),
        )
        .map_err(|_| ResourceRuntimeError::CapabilityUnavailable)?;
        let mut volumes = Vec::new();
        for value in guest_spec.policy().volume_attachment_defaults() {
            if let Some(reference) = value.get("volumeRef").and_then(|value| match value {
                CanonicalJsonValue::String(value) => ResourceRef::parse(value).ok(),
                _ => None,
            }) {
                volumes.push(reference);
            }
        }
        let graph = BootstrapGraph::new(
            guest_spec
                .policy()
                .device_attachments()
                .iter()
                .map(|attachment| attachment.device_ref().clone())
                .collect(),
            guest_spec
                .policy()
                .network_attachments()
                .iter()
                .map(|attachment| attachment.network_ref().clone())
                .collect(),
            volumes,
            Vec::new(),
        )
        .map_err(|_| ResourceRuntimeError::CapabilityUnavailable)?;
        Ok((
            provider_ref,
            config.controller_execution_ref.clone(),
            config,
            graph,
        ))
    }

    /// Relist and reconcile the durable PipeWire resources owned by this
    /// Zone. The registry is initialized once and survives ordinary
    /// watch/reconcile cycles; a daemon restart reconstructs it from store
    /// rows before any public readiness is published.
    pub(crate) async fn reconcile_audio_resources(
        &self,
        state: Arc<crate::ServerState>,
    ) -> Result<(), ResourceRuntimeError> {
        if !self.readiness.resource_api_ready {
            return Ok(());
        }
        let snapshot = list_audio_snapshot(&self.store, &self.zone)
            .await
            .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;
        let binding_resources = snapshot.bindings.clone();
        let statuses;
        let child_owners;
        {
            let mut runtime = self
                .audio_runtime
                .lock()
                .map_err(|_| ResourceRuntimeError::CapabilityUnavailable)?;
            let registry =
                runtime.get_or_insert_with(|| AudioResourceRuntime::new(self.zone.clone(), state));
            registry
                .reconcile(snapshot)
                .map_err(map_audio_runtime_error)?;
            statuses = registry.statuses();
            child_owners = registry
                .child_owners(&binding_resources)
                .map_err(map_audio_runtime_error)?;
        }
        let client = self.status_client()?;
        reconcile_binding_children(&self.store, &client, &self.zone, &child_owners)
            .await
            .map_err(|_| ResourceRuntimeError::CapabilityUnavailable)?;
        // Finalizer mutations advance the parent revision. Relist the
        // authoritative Binding rows before status writes so their exact
        // UID/revision preconditions remain current on startup.
        let binding_resources = list_audio_resources(
            &self.store,
            &self.zone,
            ResourceTypeName::parse(AUDIO_BINDING_TYPE).expect("static audio binding type"),
            "binding-status",
        )
        .await
        .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;
        let children =
            crate::binding_child_resource_runtime::list_binding_children(&self.store, &self.zone)
                .await
                .map_err(|_| ResourceRuntimeError::CapabilityUnavailable)?;
        for status in statuses {
            let Some(resource) = binding_resources
                .iter()
                .find(|resource| resource.resource_ref == status.resource)
            else {
                return Err(ResourceRuntimeError::StoreReadFailed);
            };
            let projection =
                audio_binding_status_projection_with_status(resource, &children, &status.status)
                    .map_err(map_audio_runtime_error)?;
            persist_resource_status_with_projection(
                &client,
                resource,
                &audio_binding_status_value(status.status),
                Some(&projection),
            )
            .await?;
        }
        Ok(())
    }

    /// Relist and reconcile USB, security-key, and telemetry Bindings.
    ///
    /// These Providers retain semantic authority in their own crates; the
    /// daemon only admits their explicit child intents through Core.
    pub(crate) async fn reconcile_semantic_binding_resources(
        &self,
    ) -> Result<(), ResourceRuntimeError> {
        if !self.readiness.resource_api_ready {
            return Ok(());
        }
        let client = self.status_client()?;
        reconcile_semantic_binding_resources(&self.store, &client, &self.zone)
            .await
            .map_err(|error| match error {
                crate::semantic_binding_resource_runtime::SemanticBindingRuntimeError::Store => {
                    ResourceRuntimeError::StoreReadFailed
                }
                crate::semantic_binding_resource_runtime::SemanticBindingRuntimeError::InvalidResource
                | crate::semantic_binding_resource_runtime::SemanticBindingRuntimeError::InvalidRelationship
                | crate::semantic_binding_resource_runtime::SemanticBindingRuntimeError::Reconcile => {
                    ResourceRuntimeError::CapabilityUnavailable
                }
            })?;
        let start_watch = {
            let mut watch_task = self
                .device_binding_watch_task
                .lock()
                .map_err(|_| ResourceRuntimeError::WatchUnavailable)?;
            watch_needs_restart(&mut watch_task)
        };
        if start_watch {
            let watch = d2b_resource_api::watch::WatchService::new(Arc::clone(&self.store))
                .open(device_binding_watch_request(&self.zone))
                .await
                .map_err(|_| ResourceRuntimeError::WatchUnavailable)?;
            let store = Arc::clone(&self.store);
            let zone = self.zone.clone();
            let client = client.clone();
            let task = tokio::spawn(run_device_binding_watch(watch, store, zone, client));
            let mut watch_task = self
                .device_binding_watch_task
                .lock()
                .map_err(|_| ResourceRuntimeError::WatchUnavailable)?;
            if watch_task.is_none() {
                *watch_task = Some(task);
            } else {
                task.abort();
            }
        }
        Ok(())
    }

    fn controller_session_coordinator(&self) -> ControllerSessionCoordinator {
        ControllerSessionCoordinator {
            zone: self.zone.clone(),
            bundle_resource_types: self.bundle_resource_types.clone(),
            store: Arc::clone(&self.store),
            api: Arc::clone(&self.api),
            authorizer: Arc::clone(&self.authorizer),
            authorization_state: self.authorization_state.clone(),
            registrar: Arc::clone(&self.registrar),
            assignments: Arc::clone(&self.assignments),
            controller_sessions: Arc::clone(&self.controller_sessions),
            controller_session_lock: Arc::clone(&self.controller_session_lock),
        }
    }
}

fn schedule_controller_session_reconcile(
    task_slot: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    coordinator: ControllerSessionCoordinator,
    providers: Arc<crate::process_provider_runtime::ProductionProcessProviders>,
) -> Result<(), ResourceRuntimeError> {
    let mut slot = task_slot
        .lock()
        .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?;
    if slot.as_ref().is_some_and(|task| !task.is_finished()) {
        return Ok(());
    }
    *slot = Some(tokio::spawn(async move {
        if let Err(error) = coordinator
            .reconcile_controller_sessions(providers, true)
            .await
        {
            tracing::warn!(
                error = %error,
                "external Provider controller session reconciliation degraded",
            );
        }
    }));
    Ok(())
}

impl ControllerSessionCoordinator {
    fn revoke_controller_assignments(&self, binding: &ControllerSessionBinding) {
        if d2b_provider_runtime_cloud_hypervisor::is_provider_ref(binding.provider_ref()) {
            self.assignments
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .revoke_session_for(binding);
        }
    }

    async fn fence(
        &self,
        providers: &crate::process_provider_runtime::ProductionProcessProviders,
    ) -> Result<(), ResourceRuntimeError> {
        let bootstrap_refs = providers.controller_bootstrap_refs(&self.zone);
        let bootstrap_ref_set = bootstrap_refs.iter().cloned().collect::<BTreeSet<_>>();
        let stale_sessions = self
            .controller_sessions
            .lock()
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?
            .iter()
            .filter(|(process_ref, session)| {
                controller_session_needs_fence(
                    bootstrap_ref_set.contains(*process_ref),
                    session.service_task.is_finished(),
                )
            })
            .map(|(process_ref, session)| (process_ref.clone(), session.context.clone()))
            .collect::<Vec<_>>();
        for (process_ref, context) in stale_sessions {
            providers.fail_controller_bootstrap(&context);
            self.remove_controller_session(&process_ref, Some(&context))
                .await?;
        }

        let active_sessions = self
            .controller_sessions
            .lock()
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        for context in providers
            .controller_bootstrap_establishing_contexts(&self.zone)
            .into_iter()
            .filter(|context| !active_sessions.contains(context.process_ref()))
        {
            providers.fail_controller_bootstrap(&context);
        }

        let contexts = providers.controller_bootstrap_contexts(&self.zone);
        if contexts.is_empty() {
            return Ok(());
        }
        let store_metadata = self
            .store
            .runtime_metadata()
            .await
            .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;
        let current_revision = store_metadata.current_revision;
        let current_controller_generation = store_metadata.policy_snapshot.controller_generation;
        let provider_refs = contexts
            .iter()
            .map(|context| context.provider_owner_ref().clone())
            .collect::<BTreeSet<_>>();
        for provider_ref in provider_refs {
            match load_committed_controller_provider_identities(
                &self.zone,
                &self.store,
                current_revision,
                BTreeSet::from([provider_ref.clone()]),
            )
            .await
            {
                Ok(identities) => {
                    for context in contexts.iter().filter(|context| {
                        context.provider_owner_ref() == &provider_ref
                            && identities.get(&provider_ref).is_none_or(
                                |(provider_uid, provider_generation)| {
                                    provider_uid != context.provider_uid()
                                        || *provider_generation != context.provider_generation()
                                },
                            )
                    }) {
                        providers.fail_controller_bootstrap(context);
                        self.remove_controller_session(context.process_ref(), Some(context))
                            .await?;
                    }
                }
                Err(error) => {
                    for context in contexts
                        .iter()
                        .filter(|context| context.provider_owner_ref() == &provider_ref)
                    {
                        providers.fail_controller_bootstrap(context);
                        self.remove_controller_session(context.process_ref(), Some(context))
                            .await?;
                    }
                    tracing::warn!(
                        error = %error,
                        "external Provider controller identity projection failed",
                    );
                }
            }
        }
        let contexts = providers.controller_bootstrap_contexts(&self.zone);
        for context in contexts {
            if controller_generation_is_stale(
                current_controller_generation,
                context.controller_generation(),
            ) {
                providers.fail_controller_bootstrap(&context);
                self.remove_controller_session(context.process_ref(), Some(&context))
                    .await?;
            }
        }
        Ok(())
    }

    async fn fence_process_snapshot(
        &self,
        providers: &crate::process_provider_runtime::ProductionProcessProviders,
        snapshot: &[StoredResource],
    ) -> Result<(), ResourceRuntimeError> {
        let sessions = {
            let sessions = self
                .controller_sessions
                .lock()
                .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?;
            sessions
                .iter()
                .map(|(process_ref, session)| (process_ref.clone(), session.context.clone()))
                .collect::<Vec<_>>()
        };
        let stale_sessions = controller_session_snapshot_fences(sessions, snapshot);
        for (process_ref, context) in stale_sessions {
            providers.fail_controller_bootstrap(&context);
            self.remove_controller_session(&process_ref, Some(&context))
                .await?;
        }
        Ok(())
    }

    async fn reconcile_controller_sessions(
        &self,
        providers: Arc<crate::process_provider_runtime::ProductionProcessProviders>,
        establish: bool,
    ) -> Result<(), ResourceRuntimeError> {
        let Ok(_session_guard) = self.controller_session_lock.try_lock() else {
            return Ok(());
        };
        self.fence(&providers).await?;
        if !establish {
            self.refresh_controller_policy(&providers).await?;
            self.reconcile_controller_assignments(&providers).await?;
            return Ok(());
        }
        let store_metadata = self
            .store
            .runtime_metadata()
            .await
            .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;
        let bootstrap_contexts = providers.controller_bootstrap_contexts(&self.zone);
        let provider_refs = bootstrap_contexts
            .iter()
            .map(|context| context.provider_owner_ref().clone())
            .collect::<BTreeSet<_>>();
        let mut provider_identities = BTreeMap::new();
        for provider_ref in provider_refs {
            match load_committed_controller_provider_identities(
                &self.zone,
                &self.store,
                store_metadata.current_revision,
                BTreeSet::from([provider_ref.clone()]),
            )
            .await
            {
                Ok(identities) => {
                    let mismatched = bootstrap_contexts
                        .iter()
                        .filter(|context| {
                            context.provider_owner_ref() == &provider_ref
                                && identities.get(&provider_ref).is_none_or(
                                    |(provider_uid, provider_generation)| {
                                        provider_uid != context.provider_uid()
                                            || *provider_generation != context.provider_generation()
                                    },
                                )
                        })
                        .cloned()
                        .collect::<Vec<_>>();
                    for context in mismatched {
                        providers.fail_controller_bootstrap(&context);
                        self.remove_controller_session(context.process_ref(), Some(&context))
                            .await?;
                    }
                    provider_identities.extend(identities);
                }
                Err(error) => {
                    for context in bootstrap_contexts
                        .iter()
                        .filter(|context| context.provider_owner_ref() == &provider_ref)
                    {
                        providers.fail_controller_bootstrap(context);
                        self.remove_controller_session(context.process_ref(), Some(context))
                            .await?;
                    }
                    tracing::warn!(
                        error = %error,
                        "external Provider controller identity projection failed",
                    );
                }
            }
        }
        let surviving_contexts = providers.controller_bootstrap_contexts(&self.zone);
        let provider_subjects = surviving_contexts
            .iter()
            .filter_map(|context| {
                provider_identities
                    .get(context.provider_owner_ref())
                    .map(|(provider_uid, _)| d2b_resource_api::authz::BoundSubject {
                        subject_ref: context.provider_owner_ref().clone(),
                        subject_uid: provider_uid.clone(),
                    })
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let policy_resources =
            d2bd_runtime::resource_runtime_support::load_committed_policy_resources(
                &self.store,
                &self.zone,
                "controller-session-policy",
            )
            .await?;
        let (policy, state) =
            match d2bd_runtime::resource_runtime_support::compile_committed_policy_with_subjects(
                &self.zone,
                store_metadata.policy_snapshot,
                store_metadata.current_revision,
                &self.bundle_resource_types,
                &policy_resources,
                provider_subjects,
            ) {
                Ok(policy) => policy,
                Err(error) => {
                    for context in surviving_contexts {
                        providers.fail_controller_bootstrap(&context);
                        self.remove_controller_session(context.process_ref(), Some(&context))
                            .await?;
                    }
                    tracing::warn!(
                        error = %error,
                        "external Provider controller policy projection failed",
                    );
                    return Ok(());
                }
            };
        if self.authorizer.replace_policy(policy, &state).is_err() {
            for context in surviving_contexts {
                providers.fail_controller_bootstrap(&context);
                self.remove_controller_session(context.process_ref(), Some(&context))
                    .await?;
            }
            return Ok(());
        }
        *self
            .authorization_state
            .lock()
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)? = Some(state);

        let bootstrap_refs = providers.controller_bootstrap_refs(&self.zone);
        for process_ref in bootstrap_refs {
            let existing = self
                .controller_sessions
                .lock()
                .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?
                .get(&process_ref)
                .map(|session| (session.context.clone(), session.service_task.is_finished()));
            if let Some((context, finished)) = existing {
                if finished {
                    providers.fail_controller_bootstrap(&context);
                    self.remove_controller_session(&process_ref, Some(&context))
                        .await?;
                    continue;
                }
                if providers.has_controller_bootstrap(&process_ref, &context) {
                    continue;
                }
                self.remove_controller_session(&process_ref, Some(&context))
                    .await?;
            }

            if !providers.controller_bootstrap_ready(&self.zone, &process_ref) {
                continue;
            }
            let Some(endpoint) = providers.begin_controller_bootstrap(&self.zone, &process_ref)
            else {
                continue;
            };
            let context = endpoint.context().clone();
            let mut registrar = match self.registrar.lock() {
                Ok(mut registrar) => match registrar.take() {
                    Some(registrar) => registrar,
                    None => {
                        providers.fail_controller_bootstrap(&context);
                        continue;
                    }
                },
                Err(_) => {
                    providers.fail_controller_bootstrap(&context);
                    return Err(ResourceRuntimeError::AuthenticationUnavailable);
                }
            };
            let setup = self
                .establish_controller_session(&providers, endpoint, &mut registrar)
                .await;
            let mut registrar = Some(registrar);
            let restored = match self.registrar.lock() {
                Ok(mut slot) => {
                    *slot = registrar.take();
                    true
                }
                Err(_) => false,
            };
            let mut setup = Some(setup);
            if !restored {
                if let Some(Ok((
                    ingress,
                    driver,
                    _resource_client,
                    service_task,
                    _session_generation,
                ))) = setup.take()
                {
                    let _ = driver
                        .close(
                            d2b_contracts_zone_session::v3::component_session::CloseReason::RoleMismatch,
                            d2b_contracts_zone_session::v3::component_session::Remediation::ReplaceGeneration,
                        )
                        .await;
                    service_task.abort();
                    let _ = service_task.await;
                    drop(ingress);
                }
                providers.fail_controller_bootstrap(&context);
                return Err(ResourceRuntimeError::AuthenticationUnavailable);
            }
            match setup.expect("controller setup result present") {
                Ok((ingress, driver, resource_client, service_task, session_generation)) => {
                    let current = self
                        .controller_context_is_current(&providers, &context)
                        .await
                        .unwrap_or(false);
                    if !current || !providers.activate_controller_bootstrap(&context) {
                        let _ = driver
                            .close(
                                d2b_contracts_zone_session::v3::component_session::CloseReason::RoleMismatch,
                                d2b_contracts_zone_session::v3::component_session::Remediation::ReplaceGeneration,
                            )
                            .await;
                        service_task.abort();
                        let _ = service_task.await;
                        providers.fail_controller_bootstrap(&context);
                        self.revoke_controller_ingress(ingress).await?;
                        continue;
                    }
                    let context_for_cleanup = context.clone();
                    let mut session = Some(ControllerSession {
                        context: context.clone(),
                        binding: controller_session_binding(&context, session_generation)?,
                        ingress,
                        driver: driver.clone(),
                        resource_client,
                        service_task,
                        assignments: BTreeMap::new(),
                        assignment_stream_open: false,
                    });
                    let inserted = match self.controller_sessions.lock() {
                        Ok(mut sessions) => {
                            if sessions.contains_key(&process_ref) {
                                false
                            } else {
                                sessions.insert(
                                    process_ref.clone(),
                                    session.take().expect("controller session present"),
                                );
                                true
                            }
                        }
                        Err(_) => false,
                    };
                    if !inserted {
                        providers.fail_controller_bootstrap(&context_for_cleanup);
                        if let Some(session) = session {
                            let _ = session
                                .driver
                                .close(
                                    d2b_contracts_zone_session::v3::component_session::CloseReason::RoleMismatch,
                                    d2b_contracts_zone_session::v3::component_session::Remediation::ReplaceGeneration,
                                )
                                .await;
                            session.service_task.abort();
                            let _ = session.service_task.await;
                            self.revoke_controller_ingress(session.ingress).await?;
                        }
                        continue;
                    }
                }
                Err(error) => {
                    providers.fail_controller_bootstrap(&context);
                    tracing::warn!(
                        error = %error,
                        "external Provider controller ResourceV3 session setup failed",
                    );
                }
            }
        }
        self.reconcile_controller_assignments(&providers).await?;
        self.refresh_controller_policy(&providers).await?;
        Ok(())
    }

    async fn reconcile_controller_assignments(
        &self,
        providers: &crate::process_provider_runtime::ProductionProcessProviders,
    ) -> Result<(), ResourceRuntimeError> {
        let sessions = self
            .controller_sessions
            .lock()
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?
            .iter()
            .map(|(_, session)| (session.context.clone(), session.binding.clone()))
            .collect::<Vec<_>>();
        let mut first_error = None;
        for (context, binding) in sessions {
            if let Err(error) = self
                .reconcile_controller_assignments_for_session(&context, &binding)
                .await
            {
                if let Err(error) = self
                    .handle_controller_assignment_refresh_error(providers, &context, error)
                    .await
                {
                    first_error.get_or_insert(error);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    async fn controller_context_is_current(
        &self,
        providers: &crate::process_provider_runtime::ProductionProcessProviders,
        context: &crate::process_provider_runtime::ControllerBootstrapContext,
    ) -> Result<bool, ResourceRuntimeError> {
        if !providers.has_controller_bootstrap(context.process_ref(), context) {
            return Ok(false);
        }
        let metadata = self
            .store
            .runtime_metadata()
            .await
            .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;
        if controller_generation_is_stale(
            metadata.policy_snapshot.controller_generation,
            context.controller_generation(),
        ) {
            return Ok(false);
        }
        let identities = load_committed_controller_provider_identities(
            &self.zone,
            &self.store,
            metadata.current_revision,
            BTreeSet::from([context.provider_owner_ref().clone()]),
        )
        .await?;
        let Some((provider_uid, provider_generation)) =
            identities.get(context.provider_owner_ref())
        else {
            return Ok(false);
        };
        if provider_uid != context.provider_uid()
            || *provider_generation != context.provider_generation()
        {
            return Ok(false);
        }
        let snapshot =
            crate::process_resource_runtime::list_process_snapshot(&self.store, &self.zone)
                .await
                .map_err(map_process_runtime_error)?;
        Ok(snapshot
            .iter()
            .find(|resource| resource.resource_ref == *context.process_ref())
            .is_some_and(|resource| controller_resource_matches(context, resource)))
    }

    async fn handle_controller_assignment_refresh_error(
        &self,
        providers: &crate::process_provider_runtime::ProductionProcessProviders,
        context: &crate::process_provider_runtime::ControllerBootstrapContext,
        error: ControllerAssignmentRefreshError,
    ) -> Result<(), ResourceRuntimeError> {
        match controller_assignment_refresh_action(context, error) {
            ControllerAssignmentRefreshAction::Retryable { .. } => {
                tracing::warn!("external Provider controller assignment reconciliation will retry");
                Ok(())
            }
            ControllerAssignmentRefreshAction::Failed { context, error } => {
                providers.fail_controller_bootstrap(context);
                self.remove_controller_session(context.process_ref(), Some(context))
                    .await?;
                Err(error)
            }
        }
    }

    async fn reconcile_controller_assignments_for_session(
        &self,
        context: &crate::process_provider_runtime::ControllerBootstrapContext,
        binding: &ControllerSessionBinding,
    ) -> Result<(), ControllerAssignmentRefreshError> {
        if !d2b_provider_runtime_cloud_hypervisor::is_provider_ref(context.provider_owner_ref()) {
            return Ok(());
        }
        let manifest =
            d2b_provider_runtime_cloud_hypervisor::provider_manifest().map_err(|_| {
                ControllerAssignmentRefreshError::Failed(
                    ResourceRuntimeError::AuthenticationUnavailable,
                )
            })?;
        let role_ref =
            ResourceRef::parse(d2b_provider_runtime_cloud_hypervisor::CONTROLLER_ROLE_REF)
                .map_err(|_| {
                    ControllerAssignmentRefreshError::Failed(
                        ResourceRuntimeError::AuthenticationUnavailable,
                    )
                })?;
        let role = ControllerRoleContract::from_signed_manifest(
            context.provider_owner_ref().clone(),
            role_ref,
            &manifest,
        )
        .map_err(|_| {
            ControllerAssignmentRefreshError::Failed(
                ResourceRuntimeError::AuthenticationUnavailable,
            )
        })?;
        let expected_target = AssignmentTarget::Execution {
            kind: PlacementTargetKind::Host,
            reference: context.execution_ref().clone(),
        };
        if binding.target() != &expected_target {
            return Err(ControllerAssignmentRefreshError::Failed(
                ResourceRuntimeError::AuthenticationUnavailable,
            ));
        }
        let resources = self
            .list_assignment_resources(&role, context.provider_owner_ref())
            .await?;
        let driver = self.ensure_controller_assignment_stream(binding).await?;
        let mut resources_by_uid = BTreeMap::new();
        for (index, resource) in resources.iter().enumerate() {
            if resources_by_uid
                .insert(resource.metadata().uid().clone(), index)
                .is_some()
            {
                return Err(ControllerAssignmentRefreshError::Failed(
                    ResourceRuntimeError::AuthorizationUnavailable,
                ));
            }
        }
        let (retained, stale) = {
            let sessions = self.controller_sessions.lock().map_err(|_| {
                ControllerAssignmentRefreshError::Failed(
                    ResourceRuntimeError::AuthenticationUnavailable,
                )
            })?;
            let Some(session) = sessions.get(binding.session_owner()).filter(|session| {
                &session.binding == binding && !session.service_task.is_finished()
            }) else {
                return Err(ControllerAssignmentRefreshError::Retryable);
            };
            let mut retained = BTreeSet::new();
            let mut stale = Vec::new();
            for (resource_uid, lease) in &session.assignments {
                if resources_by_uid
                    .get(resource_uid)
                    .and_then(|index| resources.get(*index))
                    .is_some_and(|resource| {
                        lease.phase() == AssignmentPhase::Assigned
                            && assignment_resource_matches(
                                lease.resource_ref(),
                                lease.identity().resource_uid(),
                                lease.resource_generation(),
                                lease.identity().resource_revision(),
                                resource,
                            )
                    })
                {
                    retained.insert(resource_uid.clone());
                } else {
                    stale.push((
                        resource_uid.clone(),
                        lease.identity().clone(),
                        lease.provider_ref().clone(),
                    ));
                }
            }
            (retained, stale)
        };

        for (resource_uid, identity, provider_ref) in stale {
            self.revoke_recorded_assignment(binding, &resource_uid, &identity, &provider_ref)
                .await?;
        }

        let mut degraded = false;
        let stream = StreamId::new(CONTROLLER_ASSIGNMENT_STREAM_ID).map_err(|_| {
            ControllerAssignmentRefreshError::Failed(
                ResourceRuntimeError::AuthenticationUnavailable,
            )
        })?;
        for resource in &resources {
            if retained.contains(resource.metadata().uid()) {
                continue;
            }
            if !self.controller_session_is_live(binding) {
                return Err(ControllerAssignmentRefreshError::Retryable);
            }
            let request = AssignmentRequest::new(
                resource,
                &role,
                context.provider_generation(),
                context.controller_generation(),
                binding.session_generation(),
                true,
            )
            .with_expected_target(binding.target().clone())
            .with_session_owner(binding.session_owner().clone());
            let lease = match admit_assignment_or_skip(&self.assignments, request) {
                Ok(Some(lease)) => lease,
                Ok(None) => continue,
                Err(error) => {
                    tracing::warn!(
                        error = ?error,
                        "external Provider controller assignment admission failed",
                    );
                    degraded = true;
                    continue;
                }
            };
            let encoded = match lease.assignment_grant().encode() {
                Ok(encoded) => encoded,
                Err(_) => {
                    self.revoke_unrecorded_assignment(&lease, false).await;
                    degraded = true;
                    continue;
                }
            };
            match send_controller_assignment_frame(&driver, stream, encoded, || {
                self.revoke_unrecorded_assignment_local(&lease);
            })
            .await
            {
                Ok(()) => {}
                Err(ControllerAssignmentRefreshError::Retryable) => {
                    self.mark_controller_assignment_stream_closed(binding)?;
                    return Err(ControllerAssignmentRefreshError::Retryable);
                }
                Err(error) => return Err(error),
            }
            if !self.controller_session_is_live(binding) {
                self.revoke_unrecorded_assignment(&lease, true).await;
                return Err(ControllerAssignmentRefreshError::Retryable);
            }
            if let Err(lease) = self.record_controller_assignment(binding, context, lease) {
                self.revoke_unrecorded_assignment(&lease, true).await;
                degraded = true;
            }
        }
        if degraded {
            Err(ControllerAssignmentRefreshError::Retryable)
        } else {
            Ok(())
        }
    }

    async fn ensure_controller_assignment_stream(
        &self,
        binding: &ControllerSessionBinding,
    ) -> Result<SessionDriverHandle, ControllerAssignmentRefreshError> {
        let (driver, stream_open) = {
            let sessions = self.controller_sessions.lock().map_err(|_| {
                ControllerAssignmentRefreshError::Failed(
                    ResourceRuntimeError::AuthenticationUnavailable,
                )
            })?;
            let Some(session) = sessions.get(binding.session_owner()).filter(|session| {
                &session.binding == binding && !session.service_task.is_finished()
            }) else {
                return Err(ControllerAssignmentRefreshError::Retryable);
            };
            (session.driver.clone(), session.assignment_stream_open)
        };
        if stream_open {
            return Ok(driver);
        }
        let stream = StreamId::new(CONTROLLER_ASSIGNMENT_STREAM_ID).map_err(|_| {
            ControllerAssignmentRefreshError::Failed(
                ResourceRuntimeError::AuthenticationUnavailable,
            )
        })?;
        driver
            .open_named_stream(
                stream,
                CONTROLLER_ASSIGNMENT_STREAM_CREDIT,
                CONTROLLER_ASSIGNMENT_STREAM_CREDIT,
            )
            .await
            .map_err(|_| {
                ControllerAssignmentRefreshError::Failed(
                    ResourceRuntimeError::AuthenticationUnavailable,
                )
            })?;
        let mut sessions = self.controller_sessions.lock().map_err(|_| {
            ControllerAssignmentRefreshError::Failed(
                ResourceRuntimeError::AuthenticationUnavailable,
            )
        })?;
        let Some(session) = sessions
            .get_mut(binding.session_owner())
            .filter(|session| &session.binding == binding && !session.service_task.is_finished())
        else {
            return Err(ControllerAssignmentRefreshError::Retryable);
        };
        session.assignment_stream_open = true;
        Ok(driver)
    }

    fn mark_controller_assignment_stream_closed(
        &self,
        binding: &ControllerSessionBinding,
    ) -> Result<(), ControllerAssignmentRefreshError> {
        let mut sessions = self.controller_sessions.lock().map_err(|_| {
            ControllerAssignmentRefreshError::Failed(
                ResourceRuntimeError::AuthenticationUnavailable,
            )
        })?;
        let Some(session) = sessions
            .get_mut(binding.session_owner())
            .filter(|session| &session.binding == binding)
        else {
            return Err(ControllerAssignmentRefreshError::Failed(
                ResourceRuntimeError::AuthenticationUnavailable,
            ));
        };
        session.assignment_stream_open = false;
        Ok(())
    }

    fn controller_session_is_live(&self, binding: &ControllerSessionBinding) -> bool {
        self.controller_sessions
            .lock()
            .ok()
            .and_then(|sessions| {
                sessions.get(binding.session_owner()).map(|session| {
                    controller_session_matches(
                        &session.binding,
                        binding,
                        session.service_task.is_finished(),
                    )
                })
            })
            .unwrap_or(false)
    }

    fn record_controller_assignment(
        &self,
        binding: &ControllerSessionBinding,
        context: &crate::process_provider_runtime::ControllerBootstrapContext,
        lease: ResourceClientLease,
    ) -> Result<(), ResourceClientLease> {
        let mut sessions = match self.controller_sessions.lock() {
            Ok(sessions) => sessions,
            Err(_) => return Err(lease),
        };
        let Some(session) = sessions.get_mut(binding.session_owner()).filter(|session| {
            &session.context == context
                && controller_session_matches(
                    &session.binding,
                    binding,
                    session.service_task.is_finished(),
                )
        }) else {
            return Err(lease);
        };
        let resource_uid = lease.identity().resource_uid().clone();
        if session.assignments.contains_key(&resource_uid) {
            return Err(lease);
        }
        session.assignments.insert(resource_uid, lease);
        Ok(())
    }

    fn revoke_unrecorded_assignment_local(&self, lease: &ResourceClientLease) {
        self.assignments
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .revoke_assignment(lease.identity());
    }

    async fn revoke_unrecorded_assignment(&self, lease: &ResourceClientLease, notify: bool) {
        self.revoke_unrecorded_assignment_local(lease);
        if notify
            && let Ok(bytes) =
                ControllerAssignmentGrant::encode_revocation(lease.provider_ref(), lease.identity())
            && let Ok(stream) = StreamId::new(CONTROLLER_ASSIGNMENT_STREAM_ID)
            && let Some(driver) = self.controller_sessions.lock().ok().and_then(|sessions| {
                sessions
                    .get(lease.identity().session_owner())
                    .map(|session| session.driver.clone())
            })
        {
            if driver.send_named_stream(stream, bytes).await.is_err() {
                if driver.reset_named_stream(stream).await.is_ok() {
                    let _ = self.mark_controller_assignment_stream_closed(
                        lease.identity().session_binding(),
                    );
                }
            }
        }
    }

    async fn revoke_recorded_assignment(
        &self,
        binding: &ControllerSessionBinding,
        resource_uid: &ResourceUid,
        identity: &AssignmentIdentity,
        provider_ref: &ResourceRef,
    ) -> Result<(), ControllerAssignmentRefreshError> {
        self.assignments
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .revoke_assignment(identity);
        let (driver, bytes) = self
            .controller_sessions
            .lock()
            .ok()
            .and_then(|sessions| {
                let session = sessions
                    .get(binding.session_owner())
                    .filter(|session| &session.binding == binding)?;
                let lease = session.assignments.get(resource_uid)?;
                if lease.identity() != identity {
                    return None;
                }
                let bytes =
                    ControllerAssignmentGrant::encode_revocation(provider_ref, identity).ok()?;
                Some((session.driver.clone(), bytes))
            })
            .ok_or(ControllerAssignmentRefreshError::Retryable)?;
        let stream = StreamId::new(CONTROLLER_ASSIGNMENT_STREAM_ID).map_err(|_| {
            ControllerAssignmentRefreshError::Failed(
                ResourceRuntimeError::AuthenticationUnavailable,
            )
        })?;
        if driver.send_named_stream(stream, bytes).await.is_err() {
            reset_controller_assignment_stream(&driver, stream).await?;
            self.mark_controller_assignment_stream_closed(binding)?;
            return Err(ControllerAssignmentRefreshError::Retryable);
        }
        if let Ok(mut sessions) = self.controller_sessions.lock()
            && let Some(session) = sessions
                .get_mut(binding.session_owner())
                .filter(|session| &session.binding == binding)
            && session
                .assignments
                .get(resource_uid)
                .is_some_and(|lease| lease.identity() == identity)
        {
            session.assignments.remove(resource_uid);
        }
        Ok(())
    }

    async fn list_assignment_resources(
        &self,
        role: &ControllerRoleContract,
        provider_ref: &ResourceRef,
    ) -> Result<Vec<ResourceEnvelope>, ControllerAssignmentRefreshError> {
        let mut cursor = None;
        let mut snapshot_revision = None;
        let mut resources = Vec::new();
        let mut resource_uids = BTreeSet::new();
        loop {
            let page = self
                .store
                .list(StoreListRequest {
                    operation: StoreOperationContext {
                        operation_id: "controller-assignment-list".to_owned(),
                        idempotency_key: None,
                        correlation_id: "controller-assignment-list".to_owned(),
                        trace_id: None,
                        deadline_ms: 10_000,
                    },
                    zone: self.zone.clone(),
                    resource_types: role.resource_types().iter().cloned().collect(),
                    resource_names: Vec::new(),
                    filters: Vec::new(),
                    page_size: 128,
                    cursor,
                    projection: StoreProjection::Full,
                })
                .await
                .map_err(|error| {
                    if matches!(
                        error.kind(),
                        StoreErrorKind::RevisionExpired
                            | StoreErrorKind::Backpressure
                            | StoreErrorKind::Timeout
                            | StoreErrorKind::Cancelled
                            | StoreErrorKind::ResourcePlaneUnavailable
                            | StoreErrorKind::StoreBackpressure
                    ) {
                        ControllerAssignmentRefreshError::Retryable
                    } else {
                        ControllerAssignmentRefreshError::Failed(
                            ResourceRuntimeError::StoreReadFailed,
                        )
                    }
                })?;
            let page_resources =
                validate_assignment_list_page(&page, &self.zone, provider_ref, snapshot_revision)?;
            snapshot_revision.get_or_insert(page.snapshot_revision);
            if resources.len().saturating_add(page_resources.len())
                > d2b_core_controller::controller_assignment::MAX_ASSIGNMENTS
            {
                return Err(ControllerAssignmentRefreshError::Failed(
                    ResourceRuntimeError::AuthorizationUnavailable,
                ));
            }
            for envelope in page_resources {
                if !resource_uids.insert(envelope.metadata().uid().clone()) {
                    return Err(ControllerAssignmentRefreshError::Failed(
                        ResourceRuntimeError::AuthorizationUnavailable,
                    ));
                }
                resources.push(envelope);
            }
            cursor = page.next_cursor.clone();
            if cursor.is_none() {
                break;
            }
        }
        Ok(resources)
    }

    async fn remove_controller_session(
        &self,
        process_ref: &ResourceRef,
        expected: Option<&crate::process_provider_runtime::ControllerBootstrapContext>,
    ) -> Result<(), ResourceRuntimeError> {
        let session = {
            let mut sessions = self
                .controller_sessions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let matches = sessions.get(process_ref).is_some_and(|session| {
                expected.is_none_or(|expected| &session.context == expected)
            });
            matches.then(|| sessions.remove(process_ref)).flatten()
        };
        if let Some(session) = session {
            self.revoke_controller_assignments(&session.binding);
            send_controller_assignment_revocations(&session.driver, &session.assignments).await;
            let _ = session
                .driver
                .close(
                    d2b_contracts_zone_session::v3::component_session::CloseReason::RoleMismatch,
                    d2b_contracts_zone_session::v3::component_session::Remediation::ReplaceGeneration,
                )
                .await;
            session.service_task.abort();
            let _ = session.service_task.await;
            self.revoke_controller_ingress(session.ingress).await?;
        }
        Ok(())
    }

    async fn revoke_controller_ingress(
        &self,
        mut ingress: BusIngress,
    ) -> Result<(), ResourceRuntimeError> {
        let mut registrar = self
            .registrar
            .lock()
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?
            .take()
            .ok_or(ResourceRuntimeError::AuthenticationUnavailable)?;
        let result = registrar.revoke_in_place(&mut ingress).await;
        let restored = self
            .registrar
            .lock()
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)
            .map(|mut slot| {
                *slot = Some(registrar);
            })
            .is_ok();
        if !restored {
            drop(ingress);
            return Err(ResourceRuntimeError::AuthenticationUnavailable);
        }
        result.map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)
    }

    async fn establish_controller_session(
        &self,
        providers: &crate::process_provider_runtime::ProductionProcessProviders,
        endpoint: crate::process_provider_runtime::ControllerBootstrapEndpoint,
        registrar: &mut ZoneRegistrar,
    ) -> Result<
        (
            BusIngress,
            SessionDriverHandle,
            Arc<ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>>,
            tokio::task::JoinHandle<Result<(), SessionServerError>>,
            ReconnectGeneration,
        ),
        ResourceRuntimeError,
    > {
        let (daemon_endpoint, context) = endpoint.into_parts();
        let authentication_error = |stage: &'static str| {
            tracing::warn!(
                zone = %self.zone.as_str(),
                stage,
                "external Provider controller authentication failed",
            );
            ResourceRuntimeError::AuthenticationUnavailable
        };
        let daemon_socket = SeqpacketSocket::from_parent_prearmed(daemon_endpoint)
            .map_err(|_| authentication_error("bootstrap-socket"))?;
        let (resource_socket, credentials) = receive_controller_bootstrap(&daemon_socket)
            .await
            .map_err(|_| authentication_error("bootstrap-receive"))?;
        let peer_pid = credentials.pid().as_raw_nonzero().get();
        if !providers
            .controller_peer_matches(&context, peer_pid)
            .map_err(|_| authentication_error("peer-process-observation"))?
        {
            return Err(authentication_error("peer-process-mismatch"));
        }
        let verified_peer = VerifiedUnixPeer::verify_inherited_seqpacket(&resource_socket)
            .map_err(|_| authentication_error("resource-peer-verification"))?;
        if verified_peer.credentials() != credentials {
            return Err(authentication_error("resource-peer-mismatch"));
        }

        let store_metadata = self
            .store
            .runtime_metadata()
            .await
            .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;
        let provider_resource = committed_resource(
            &self.zone,
            &self.store,
            store_metadata.current_revision,
            context.provider_owner_ref(),
        )
        .await
        .map_err(|_| authentication_error("provider-resource-load"))?;
        let (_, provider_uid, provider_generation, _, _) = committed_provider_spec(
            &self.zone,
            store_metadata.current_revision,
            &provider_resource,
            context.provider_owner_ref(),
        )
        .map_err(|_| authentication_error("provider-resource-identity"))?;
        if &provider_uid != context.provider_uid()
            || provider_generation != context.provider_generation()
        {
            return Err(authentication_error("provider-context-mismatch"));
        }
        let zone_ref = ResourceRef::parse(&format!("Zone/{}", self.zone.as_str()))
            .map_err(|_| authentication_error("zone-reference"))?;
        registrar
            .install_committed_controller_process_subject(
                &verified_peer,
                CommittedControllerProcessSubjectInput {
                    provider_ref: context.provider_owner_ref().clone(),
                    provider_uid,
                    process_ref: context.process_ref().clone(),
                    zone_ref,
                    execution_ref: context.execution_ref().clone(),
                    provider_generation,
                    controller_generation: context.controller_generation(),
                },
            )
            .map_err(|_| authentication_error("controller-subject-install"))?;

        let policy = controller_resource_endpoint_policy();
        let acceptor = registrar
            .component_session_acceptor(policy.clone(), verified_peer)
            .map_err(|_| authentication_error("session-acceptor"))?;
        let transport = unix_transport(resource_socket, &policy)?;
        let responder = SessionEngine::establish_responder(
            transport,
            policy,
            HandshakeCredentials::Nn,
            std::time::Instant::now(),
        )
        .await
        .map_err(|_| authentication_error("session-handshake"))?;
        let candidate = acceptor
            .admit(
                responder,
                TransportEvidence::new(
                    EvidenceClass::UnixPeer,
                    BindingDigest::parse(format!("sha256:{}", "22".repeat(32)))
                        .map_err(|_| authentication_error("binding-digest"))?,
                ),
                1,
            )
            .await
            .map_err(|_| authentication_error("session-admission"))?;
        let session_generation = candidate.route_binding().reconnect_generation();
        let route = candidate.route_binding();
        let authorization_state = self
            .authorization_state
            .lock()
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?
            .clone()
            .ok_or_else(|| authentication_error("authorization-state"))?;
        let subject = self
            .authorizer
            .issue_authenticated_subject(route.context().clone(), authorization_state)
            .map_err(|_| authentication_error("authenticated-subject"))?;
        let service = Arc::new(
            ResourceBusAdapter::bind_component_session(Arc::clone(&self.api), subject)
                .map_err(|_| ResourceRuntimeError::ResourceApiBindFailed)?,
        );
        let resource_client = Arc::new(service.client());
        let services = Arc::clone(&service).ttrpc_services();
        let (ingress, driver) = registrar
            .register_component_service_session(candidate)
            .await
            .map_err(|_| authentication_error("service-registration"))?;
        let service_task = tokio::spawn(d2b_session::serve_ttrpc_services(
            Arc::new(driver.clone()),
            services,
        ));
        tokio::task::yield_now().await;
        if service_task.is_finished() {
            service_task.abort();
            let _ = service_task.await;
            let _ = registrar.revoke(ingress).await;
            return Err(authentication_error("service-task"));
        }
        Ok((
            ingress,
            driver,
            resource_client,
            service_task,
            session_generation,
        ))
    }

    async fn refresh_controller_policy(
        &self,
        providers: &crate::process_provider_runtime::ProductionProcessProviders,
    ) -> Result<(), ResourceRuntimeError> {
        let store_metadata = self
            .store
            .runtime_metadata()
            .await
            .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;
        let contexts = providers.controller_bootstrap_contexts(&self.zone);
        let provider_subjects = contexts
            .iter()
            .map(|context| d2b_resource_api::authz::BoundSubject {
                subject_ref: context.provider_owner_ref().clone(),
                subject_uid: context.provider_uid().clone(),
            })
            .collect::<BTreeSet<_>>();
        let policy_resources =
            d2bd_runtime::resource_runtime_support::load_committed_policy_resources(
                &self.store,
                &self.zone,
                "controller-policy-refresh",
            )
            .await?;
        let (policy, state) =
            d2bd_runtime::resource_runtime_support::compile_committed_policy_with_subjects(
                &self.zone,
                store_metadata.policy_snapshot,
                store_metadata.current_revision,
                &self.bundle_resource_types,
                &policy_resources,
                provider_subjects,
            )
            .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?;
        self.authorizer
            .replace_policy(policy, &state)
            .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?;
        *self
            .authorization_state
            .lock()
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)? = Some(state);
        Ok(())
    }
}

impl ZoneResourceRuntime {
    /// Ensure the shared Runner for generic Process and EphemeralProcess
    /// resources owned by this Zone and refresh controller-session fences.
    /// Lifecycle effects remain inside the fixed daemon-composed Providers.
    pub(crate) async fn reconcile_process_resources(
        &self,
        state: Arc<crate::ServerState>,
    ) -> Result<(), ResourceRuntimeError> {
        if !self.readiness.resource_api_ready {
            return Ok(());
        }
        let providers = state
            .provider_runtime
            .process_providers()
            .ok_or(ResourceRuntimeError::ProviderPathUnavailable)?;
        let coordinator = self.controller_session_coordinator();
        coordinator
            .reconcile_controller_sessions(Arc::clone(&providers), false)
            .await?;
        let _guard = self.controller_reconcile_lock.lock().await;
        let snapshot = list_process_snapshot(&self.store, &self.zone)
            .await
            .map_err(map_process_runtime_error)?;
        coordinator
            .fence_process_snapshot(&providers, &snapshot)
            .await?;
        let store_metadata = self
            .store
            .runtime_metadata()
            .await
            .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;
        let controller_generation = store_metadata
            .policy_snapshot
            .controller_generation
            .ok_or(ResourceRuntimeError::AuthenticationUnavailable)?;
        let (_, provider_generation, _, session_generation, _) =
            self.core_assignment_fences(false).await?;
        let stale_task = {
            let mut task = self
                .process_runner_task
                .lock()
                .map_err(|_| ResourceRuntimeError::WatchUnavailable)?;
            let current_generation = self
                .process_runner_generation
                .lock()
                .map_err(|_| ResourceRuntimeError::WatchUnavailable)?
                .to_owned();
            if task.as_ref().is_some_and(|task| !task.is_finished())
                && current_generation == Some(controller_generation)
            {
                None
            } else {
                let stale = task.take();
                *self
                    .process_runner_generation
                    .lock()
                    .map_err(|_| ResourceRuntimeError::WatchUnavailable)? = None;
                stale
            }
        };
        if let Some(task) = stale_task {
            task.abort();
            let _ = task.await;
        }
        let runner_exists = self
            .process_runner_task
            .lock()
            .map_err(|_| ResourceRuntimeError::WatchUnavailable)?
            .as_ref()
            .is_some_and(|task| !task.is_finished());
        if !runner_exists {
            let subject_context = self
                .core_controller_subject
                .lock()
                .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?
                .clone()
                .ok_or(ResourceRuntimeError::AuthenticationUnavailable)?;
            let authorization_state = self
                .authorization_state
                .lock()
                .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?
                .clone()
                .ok_or(ResourceRuntimeError::AuthenticationUnavailable)?;
            let controller_ref = ResourceRef::parse(CORE_CONTROLLER_PROCESS_REF)
                .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
            let provider_ref = ResourceRef::parse(CORE_CONTROLLER_PROVIDER_REF)
                .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
            let host_ref = ResourceRef::parse(CORE_CONTROLLER_HOST_REF)
                .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
            let identity = ControllerIdentity::new(
                self.zone.clone(),
                controller_ref.clone(),
                controller_generation,
                provider_ref,
                provider_generation,
                controller_ref.clone(),
                host_ref,
                None,
            )
            .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
            let descriptor = process_controller_descriptor(identity)
                .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
            let subject = self
                .authorizer
                .issue_authenticated_subject(subject_context, authorization_state.clone())
                .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?;
            let api = self
                .api
                .registered_controller_api(subject, authorization_state.clone(), Vec::new())
                .map_err(|_| ResourceRuntimeError::ResourceApiBindFailed)?
                .with_assignment_fence_resolver(process_assignment_fence_resolver(
                    Arc::clone(&self.store),
                    providers.mode(),
                    controller_ref,
                    session_generation,
                    Arc::clone(&self.core_assignment_epoch),
                ));
            let source = CoreControllerSource::new(descriptor.clone(), Arc::new(api));
            let controller_provider_identities = load_committed_controller_provider_identities(
                &self.zone,
                &self.store,
                store_metadata.current_revision,
                controller_provider_refs(&snapshot),
            )
            .await
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?;
            let mut runtime =
                ProcessResourceRuntime::new(self.zone.clone(), Arc::clone(&providers));
            runtime.set_controller_generation(controller_generation);
            runtime.set_controller_provider_identities(controller_provider_identities);
            runtime.set_lifecycle_identity(
                self.store_metadata.zone_uid.clone(),
                store_metadata.policy_snapshot.policy_revision,
            );
            let guest_descriptor_digests = self
                .guest_setup_descriptors
                .iter()
                .filter_map(|(guest, bytes)| {
                    let descriptor = GuestSetupDescriptor::from_canonical_bytes(bytes).ok()?;
                    let guest_ref = ResourceRef::parse(&format!("Guest/{guest}")).ok()?;
                    Some((guest_ref, descriptor.descriptor_digest().clone()))
                })
                .collect();
            runtime.set_guest_descriptor_digests(guest_descriptor_digests);
            let mut owner_uids = BTreeMap::new();
            for owner_ref in snapshot.iter().filter_map(|resource| {
                ResourceEnvelope::from_json(&resource.canonical_json)
                    .ok()
                    .and_then(|envelope| envelope.metadata().owner_ref().cloned())
            }) {
                if owner_uids.contains_key(&owner_ref) {
                    continue;
                }
                let owner = self
                    .committed_resource_value(&owner_ref, "process-owner-identity")
                    .await
                    .map_err(|_| ResourceRuntimeError::IdentityUnbound)?;
                let owner = ResourceEnvelope::from_json(
                    &serde_json::to_vec(&owner)
                        .map_err(|_| ResourceRuntimeError::IdentityUnbound)?,
                )
                .map_err(|_| ResourceRuntimeError::IdentityUnbound)?;
                owner_uids.insert(owner_ref, owner.metadata().uid().clone());
            }
            runtime.set_owner_uids(owner_uids);
            if let Some(identity) = &self.interaction_identity {
                runtime.set_target_scope(
                    Some(identity.wayland_session_ref().clone()),
                    Some(identity.subject_ref().clone()),
                );
            } else {
                runtime.set_target_scope(None, None);
            }
            let wake_source = Arc::downgrade(&source);
            runtime.set_liveness_waker(Arc::new(move |key, revision| {
                if let Some(source) = wake_source.upgrade() {
                    let _ = source.dispatch_observation(key, revision);
                }
            }));
            runtime.set_status_client(self.status_client()?);
            let handler = ProcessResourceReconciler::new(descriptor, runtime);
            let runner = Runner::new(
                handler,
                source,
                RunnerConfig {
                    policy_revision: authorization_state.snapshot.policy_revision,
                    api_revision: authorization_state.snapshot.api_catalog_revision,
                    configuration_revision: authorization_state
                        .snapshot
                        .active_configuration_revision,
                    deadline_tick: 5_000,
                    max_attempts: 3,
                },
            );
            let task = tokio::spawn(async move {
                match runner.run().await {
                    Ok(report) => tracing::debug!(
                        dispatched = report.dispatched,
                        relists = report.relists,
                        "Process Provider shared runner stopped",
                    ),
                    Err(error) => tracing::warn!(
                        error = %error,
                        "Process Provider shared runner failed",
                    ),
                }
            });
            *self
                .process_runner_task
                .lock()
                .map_err(|_| ResourceRuntimeError::WatchUnavailable)? = Some(task);
            *self
                .process_runner_generation
                .lock()
                .map_err(|_| ResourceRuntimeError::WatchUnavailable)? = Some(controller_generation);
        }
        schedule_controller_session_reconcile(
            Arc::clone(&self.controller_session_reconcile_task),
            coordinator.clone(),
            Arc::clone(&providers),
        )?;
        Ok(())
    }

    /// Return the current daemon-owned AudioBinding projections.
    pub(crate) fn audio_binding_statuses(
        &self,
    ) -> Result<Vec<AudioBindingRuntimeStatus>, ResourceRuntimeError> {
        self.audio_runtime
            .lock()
            .map_err(|_| ResourceRuntimeError::CapabilityUnavailable)?
            .as_ref()
            .map(AudioResourceRuntime::statuses)
            .ok_or(ResourceRuntimeError::CapabilityUnavailable)
    }

    /// Reserve a Host-global claim through the Zone's durable redb owner.
    pub async fn reserve_authority(
        &self,
        operation_id: impl Into<String>,
        request: AuthorityRequest,
    ) -> Result<
        AuthorityReservation,
        d2b_core_controller::authority::AuthorityReservationError<
            d2b_core_controller::authority::AuthorityError,
        >,
    > {
        if !self.authority_index.lock().await.is_ready_for_readiness() {
            return Err(
                d2b_core_controller::authority::AuthorityReservationError::Effect(
                    d2b_core_controller::authority::AuthorityError::StartupRehydrationRequired,
                ),
            );
        }
        AuthorityReservation::reserve_durable(
            Arc::clone(&self.authority_index),
            self.authority_persistence.clone(),
            operation_id,
            request,
        )
        .await
    }

    /// Reserve an external physical-NIC claim through the same durable
    /// startup-barrier owner as generic Host-global claims.
    pub async fn reserve_external_nic(
        &self,
        operation_id: impl Into<String>,
        request: ExternalNicClaimRequest,
    ) -> Result<
        ExternalNicReservation,
        d2b_core_controller::authority::AuthorityReservationError<
            d2b_core_controller::authority::AuthorityError,
        >,
    > {
        if !self.authority_index.lock().await.is_ready_for_readiness() {
            return Err(
                d2b_core_controller::authority::AuthorityReservationError::Effect(
                    d2b_core_controller::authority::AuthorityError::StartupRehydrationRequired,
                ),
            );
        }
        ExternalNicReservation::reserve_durable(
            Arc::clone(&self.authority_index),
            self.authority_persistence.clone(),
            operation_id,
            request,
        )
        .await
    }

    /// Resolve one recovered authority after the authoritative effect is
    /// observed closed. Persistence must complete before the holder is
    /// removed from the in-memory index.
    pub async fn resolve_recovered_authority_closed(
        &self,
        operation_id: &str,
    ) -> Result<(), d2b_core_controller::authority_persistence::AuthorityPersistenceError> {
        self.authority_recovery
            .resolve_observed_closed(operation_id)
            .await
    }

    /// Mark one recovered operation observed and adopted without releasing
    /// its authority holder.
    pub async fn resolve_recovered_authority_adopted(
        &self,
        operation_id: &str,
    ) -> Result<(), d2b_core_controller::authority_persistence::AuthorityPersistenceError> {
        self.authority_recovery
            .resolve_observed_and_adopted(operation_id)
            .await
    }

    /// Quarantine one recovered operation when observation is ambiguous.
    pub async fn quarantine_recovered_authority(
        &self,
        operation_id: &str,
    ) -> Result<(), d2b_core_controller::authority_persistence::AuthorityPersistenceError> {
        self.authority_recovery.quarantine(operation_id).await
    }

    /// Return the first startup gate that prevents publication.
    pub fn readiness_error(&self) -> Option<ResourceRuntimeError> {
        if !self.policy_installed {
            return Some(ResourceRuntimeError::PolicyUnavailable);
        }
        if !self.readiness.store_ready {
            return Some(ResourceRuntimeError::StoreOpenFailed);
        }
        if !self.readiness.resource_api_ready {
            return Some(ResourceRuntimeError::PolicyUnavailable);
        }
        if !self.controller_endpoint_registered {
            return Some(ResourceRuntimeError::ControllerEndpointUnavailable);
        }
        if !self.readiness.local_session_ready {
            return Some(ResourceRuntimeError::AuthenticationUnavailable);
        }
        if !self.watch_admitted {
            return Some(ResourceRuntimeError::WatchUnavailable);
        }
        if !self.readiness.authority_ready
            || self
                .authority_index
                .try_lock()
                .map(|index| !index.is_ready_for_readiness())
                .unwrap_or(true)
        {
            return Some(ResourceRuntimeError::AuthorityUnavailable);
        }
        if !self.readiness.provider_path_ready {
            return Some(ResourceRuntimeError::ProviderPathUnavailable);
        }
        let u12_ready = if self.u12_required.load(Ordering::Acquire) {
            self.u12_runner_tasks
                .try_lock()
                .map(|tasks| {
                    u12_runner_readiness(
                        true,
                        tasks.len(),
                        tasks.iter().any(|task| task.is_finished()),
                    )
                })
                .unwrap_or(false)
        } else {
            true
        };
        if !u12_ready {
            return Some(ResourceRuntimeError::HandlerNotReady);
        }
        let u7_ready = if self.u7_required.load(Ordering::Acquire) {
            self.u7_runner_tasks
                .try_lock()
                .map(|tasks| {
                    !tasks.is_empty() && !tasks.iter().any(|task| task.is_finished())
                })
                .unwrap_or(false)
        } else {
            true
        };
        if !u7_ready {
            return Some(ResourceRuntimeError::HandlerNotReady);
        }
        let u6_ready = if self.u6_required.load(Ordering::Acquire) {
            self.u6_runner_tasks
                .try_lock()
                .map(|tasks| {
                    !tasks.is_empty() && !tasks.iter().any(|task| task.is_finished())
                })
                .unwrap_or(false)
        } else {
            true
        };
        if !u6_ready {
            return Some(ResourceRuntimeError::HandlerNotReady);
        }
        let u9_ready = if self.u9_required.load(Ordering::Acquire) {
            self.u9_runner_tasks
                .try_lock()
                .map(|tasks| {
                    !tasks.is_empty() && !tasks.iter().any(|task| task.is_finished())
                })
                .unwrap_or(false)
        } else {
            true
        };
        if !u9_ready {
            return Some(ResourceRuntimeError::HandlerNotReady);
        }
        if !matches!(self.core_stage().ok(), Some(StartupStage::Ready)) {
            return Some(ResourceRuntimeError::HandlerNotReady);
        }
        if self
            .zone_status
            .try_lock()
            .map(|status| !status.mandatory_handlers_ready())
            .unwrap_or(true)
        {
            return Some(ResourceRuntimeError::HandlerNotReady);
        }
        None
    }

    /// Require a runtime that is safe to publish through the public plane.
    pub fn require_ready(&self) -> Result<(), ResourceRuntimeError> {
        if let Some(error) = self.readiness_error() {
            return Err(error);
        }
        if !matches!(self.core_stage()?, StartupStage::Ready) {
            return Err(ResourceRuntimeError::CoreStartupFailed);
        }
        Ok(())
    }

    /// Refuse an unbound direct read.
    ///
    /// The old helper used a fixed internal provider session. A
    /// caller that does not carry an authenticated session must not reach the
    /// Resource API through this compatibility method.
    pub async fn get(
        &self,
        _target: ResourceRef,
        _operation_id: &str,
    ) -> Result<Value, ResourceRuntimeError> {
        Err(ResourceRuntimeError::IdentityUnbound)
    }

    /// Refuse an unbound direct list.
    pub async fn list(
        &self,
        _resource_type: ResourceTypeName,
        _operation_id: &str,
    ) -> Result<Value, ResourceRuntimeError> {
        Err(ResourceRuntimeError::IdentityUnbound)
    }

    /// Serve the existing CLI request envelope.
    ///
    /// This in-process compatibility entry point represents a trusted local
    /// caller with uid zero. The public socket uses
    /// [`Self::dispatch_public_cli_request`] with the authenticated
    /// `SO_PEERCRED` uid instead.
    #[cfg(test)]
    pub(crate) async fn dispatch_cli_request(
        &self,
        request: &Value,
    ) -> Result<Value, ResourceRuntimeError> {
        match self.dispatch_public_cli_request(request, 0).await {
            Ok(value) => Ok(value),
            Err(error) => Ok(compatibility_error_envelope(error)),
        }
    }

    /// Serve a public Resource request through a local authenticated session.
    ///
    /// Admission has already authenticated the peer and assigned its local
    /// daemon role. This method binds that peer credential into a
    /// request-scoped `AuthenticatedSubjectContext` and then uses the same
    /// Resource API client as the registered ComponentSession path. The peer
    /// uid is never read from the JSON envelope and is included in the
    /// transport/transcript binding used by the authorizer.
    pub(crate) async fn dispatch_public_cli_request(
        &self,
        request: &Value,
        peer_uid: u32,
    ) -> Result<Value, ResourceRuntimeError> {
        let requested_zone = request
            .get("zoneRef")
            .and_then(Value::as_str)
            .ok_or(ResourceRuntimeError::RequestInvalid)?;
        if requested_zone != format!("Zone/{}", self.zone.as_str()) {
            return Err(ResourceRuntimeError::RouteMismatch);
        }
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .ok_or(ResourceRuntimeError::RequestInvalid)?;
        if !route_service_matches(request.get("service"), method)? {
            return Err(ResourceRuntimeError::RouteMismatch);
        }
        if [
            "subject",
            "subjectRef",
            "subjectUid",
            "principal",
            "principalRef",
            "role",
            "uid",
            "user",
            "userRef",
        ]
        .iter()
        .any(|field| request.get(*field).is_some())
        {
            return Err(ResourceRuntimeError::RequestInvalid);
        }
        let operation_id = public_operation_id(request, peer_uid, method);
        self.refresh_authorization_policy().await?;
        let resolved_user = d2bd_runtime::resource_runtime_support::resolve_zone_user(
            &self.store,
            &self.zone,
            peer_uid,
            &format!("{}:user", operation_id),
        )
        .await?;
        let context = d2bd_runtime::resource_runtime_support::local_user_subject_context(
            &self.zone,
            &resolved_user,
            &operation_id,
        )?;
        let state = self
            .authorization_state
            .lock()
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?
            .clone()
            .ok_or(ResourceRuntimeError::AuthenticationUnavailable)?;
        let subject = self
            .authorizer
            .issue_authenticated_subject(context, state)
            .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?;
        let client = self.bind_operator_resource_client(subject)?;
        match method {
            "Get" => {
                let resource_ref = request
                    .get("resourceRef")
                    .and_then(Value::as_str)
                    .ok_or(ResourceRuntimeError::RequestInvalid)
                    .and_then(|value| {
                        ResourceRef::parse(value).map_err(|_| ResourceRuntimeError::RequestInvalid)
                    })?;
                let mut meta = public_request_meta(&operation_id);
                meta.deadline_ms = 30_000;
                let response = client
                    .get(wire::GetRequest {
                        meta: protobuf::MessageField::some(meta),
                        target: protobuf::MessageField::some(wire::ResourceIdentity {
                            zone: self.zone.to_canonical_string(),
                            resource_type: resource_ref.resource_type().to_canonical_string(),
                            name: resource_ref.name().to_canonical_string(),
                            uid: None,
                            generation: None,
                            revision: None,
                            special_fields: protobuf::SpecialFields::new(),
                        }),
                        projection: {
                            let mut projection = wire::Projection::new();
                            projection.kind = protobuf::EnumOrUnknown::new(
                                wire::ProjectionKind::PROJECTION_KIND_FULL,
                            );
                            protobuf::MessageField::some(projection)
                        },
                        special_fields: protobuf::SpecialFields::new(),
                    })
                    .await;
                encode_public_get_response(response)
            }
            "List" => {
                let parsed = parse_list_request(request)?;
                let response = client
                    .list(public_list_request(parsed, &operation_id))
                    .await;
                encode_public_list_response(response)
            }
            "Create" => {
                let request_wire = public_create_request(self, request, &operation_id).await?;
                let response = client.create(request_wire).await;
                encode_public_create_response(response)
            }
            "UpdateSpec" => {
                let request_wire =
                    public_update_spec_request(&client, self, request, &operation_id).await?;
                let response = client.update_spec(request_wire).await;
                encode_public_update_spec_response(response)
            }
            "UpdateStatus" => {
                let request_wire =
                    public_update_status_request(&client, self, request, &operation_id).await?;
                let response = client.update_status(request_wire).await;
                encode_public_update_status_response(response)
            }
            "UpdateFinalizers" => {
                let request_wire = public_update_finalizers_request(self, request, &operation_id)?;
                let response = client.update_finalizers(request_wire).await;
                encode_public_update_finalizers_response(response)
            }
            "Delete" => {
                let request_wire = public_delete_request(self, request, &operation_id).await?;
                let response = client.delete(request_wire).await;
                encode_public_delete_response(response)
            }
            _ => Err(ResourceRuntimeError::CapabilityUnavailable),
        }
    }

    /// Forward a public Resource request through the authenticated Gateway
    /// Guest ComponentSession.
    ///
    /// The local runtime supplies only committed Zone metadata needed to
    /// encode the public wire request. The Guest session owns authorization,
    /// Provider execution, and the target store; no host Resource API client
    /// is consulted for the forwarded operation.
    pub(crate) async fn dispatch_gateway_resource_request(
        &self,
        session: &d2bd_runtime::guest_component_session::GuestComponentSessionClient,
        request: &Value,
        operation_id: &str,
    ) -> Result<Value, ResourceRuntimeError> {
        if session.identity().zone() != &self.zone {
            return Err(ResourceRuntimeError::RouteMismatch);
        }
        session
            .identity()
            .validate_route(&session.route_binding())
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?;
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .ok_or(ResourceRuntimeError::RequestInvalid)?;
        if !route_service_matches(request.get("service"), method)? {
            return Err(ResourceRuntimeError::RouteMismatch);
        }
        let client = session.resource_service_client();
        match method {
            "Get" => {
                let target = public_target_ref(request)?;
                let mut meta = public_request_meta(operation_id);
                meta.deadline_ms = 30_000;
                let response = client
                    .get(
                        ttrpc::context::Context::default(),
                        &wire::GetRequest {
                            meta: protobuf::MessageField::some(meta),
                            target: protobuf::MessageField::some(public_identity(
                                self,
                                target.resource_type(),
                                target.name().as_str(),
                                None,
                                None,
                                None,
                            )),
                            projection: {
                                let mut projection = wire::Projection::new();
                                projection.kind = protobuf::EnumOrUnknown::new(
                                    wire::ProjectionKind::PROJECTION_KIND_FULL,
                                );
                                protobuf::MessageField::some(projection)
                            },
                            special_fields: protobuf::SpecialFields::new(),
                        },
                    )
                    .await
                    .map_err(|_| ResourceRuntimeError::ProviderPathUnavailable)?;
                d2bd_runtime::resource_runtime_support::encode_public_get_response(response)
            }
            "List" => {
                let parsed = parse_list_request(request)?;
                let response = client
                    .list(
                        ttrpc::context::Context::default(),
                        &public_list_request(parsed, operation_id),
                    )
                    .await
                    .map_err(|_| ResourceRuntimeError::ProviderPathUnavailable)?;
                d2bd_runtime::resource_runtime_support::encode_public_list_response(response)
            }
            "Create" => {
                let request_wire = public_create_request(self, request, operation_id).await?;
                let response = client
                    .create(ttrpc::context::Context::default(), &request_wire)
                    .await
                    .map_err(|_| ResourceRuntimeError::ProviderPathUnavailable)?;
                encode_public_create_response(response)
            }
            "UpdateSpec" => {
                let target = public_target_ref(request)?;
                let current = gateway_get_resource(&client, self, &target, operation_id).await?;
                if current.get("type").and_then(Value::as_str) == Some("error") {
                    return Ok(current);
                }
                let request_wire = public_update_spec_request_from_current(
                    self,
                    request,
                    operation_id,
                    &target,
                    current,
                )?;
                let response = client
                    .update_spec(ttrpc::context::Context::default(), &request_wire)
                    .await
                    .map_err(|_| ResourceRuntimeError::ProviderPathUnavailable)?;
                encode_public_update_spec_response(response)
            }
            "UpdateStatus" => {
                let target = public_target_ref(request)?;
                let current = gateway_get_resource(&client, self, &target, operation_id).await?;
                if current.get("type").and_then(Value::as_str) == Some("error") {
                    return Ok(current);
                }
                let request_wire = public_update_status_request_from_current(
                    self,
                    request,
                    operation_id,
                    &target,
                    current,
                )?;
                let response = client
                    .update_status(ttrpc::context::Context::default(), &request_wire)
                    .await
                    .map_err(|_| ResourceRuntimeError::ProviderPathUnavailable)?;
                encode_public_update_status_response(response)
            }
            "UpdateFinalizers" => {
                let request_wire = public_update_finalizers_request(self, request, operation_id)?;
                let response = client
                    .update_finalizers(ttrpc::context::Context::default(), &request_wire)
                    .await
                    .map_err(|_| ResourceRuntimeError::ProviderPathUnavailable)?;
                encode_public_update_finalizers_response(response)
            }
            "Delete" => {
                let request_wire = public_delete_request(self, request, operation_id).await?;
                let response = client
                    .delete(ttrpc::context::Context::default(), &request_wire)
                    .await
                    .map_err(|_| ResourceRuntimeError::ProviderPathUnavailable)?;
                encode_public_delete_response(response)
            }
            _ => Err(ResourceRuntimeError::CapabilityUnavailable),
        }
    }

    /// Verify the trusted persisted Device row used by the TPM reconcile
    /// adapter and return Core's sealed legacy-state decision. The VM binding
    /// is read from the authenticated Device record, while the legacy-state
    /// decision comes from the trusted Core bundle resolver; request fields
    /// cannot select either independently.
    #[allow(dead_code)]
    #[allow(dead_code)]
    pub(crate) async fn tpm_device_is_admitted(
        &self,
        device_uid: &ResourceUid,
        device_ref: &ResourceRef,
        vm_id: &str,
        operation_id: &str,
        legacy_intent_anchor: Option<&str>,
    ) -> Result<LegacyTpmMigrationDecision, ResourceRuntimeError> {
        let resource = self
            .backend
            .get(StoreGetRequest {
                operation: StoreOperationContext {
                    operation_id: operation_id.to_owned(),
                    idempotency_key: None,
                    correlation_id: operation_id.to_owned(),
                    trace_id: None,
                    deadline_ms: 30_000,
                },
                zone: self.zone.clone(),
                target: device_ref.clone(),
                expected_uid: Some(device_uid.clone()),
                projection: StoreProjection::Full,
            })
            .await
            .ok();
        let Some(resource) = resource.filter(|resource| {
            resource.uid == *device_uid
                && resource.resource_ref == *device_ref
                && resource.resource_ref.resource_type().as_str() == "Device"
        }) else {
            return Err(ResourceRuntimeError::AuthenticationUnavailable);
        };
        let value = serde_json::from_slice::<Value>(&resource.canonical_json)
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?;
        let spec = value
            .get("spec")
            .and_then(Value::as_object)
            .ok_or(ResourceRuntimeError::AuthenticationUnavailable)?;
        if spec.get("providerRef").and_then(Value::as_str)
            != Some(d2b_provider_device_tpm::PROVIDER_REF)
        {
            return Err(ResourceRuntimeError::AuthenticationUnavailable);
        }
        if !Self::tpm_device_targets_vm(&value, vm_id) {
            return Err(ResourceRuntimeError::AuthenticationUnavailable);
        }
        let intent = format!("legacy-swtpm:vm:{vm_id}");
        if legacy_intent_anchor.is_some() {
            // A live legacy TPM adoption is the first irreversible provider
            // effect. Refuse the admission if the owning store cannot produce
            // its logical recovery image first.
            self.backup_before_live_adoption().await?;
        }
        Ok(Self::tpm_migration_decision(
            vm_id,
            &intent,
            legacy_intent_anchor,
        ))
    }

    /// Capture the owning Zone store before a live Provider adoption or
    /// durable schema advance. The caller must retain or publish the image
    /// through the storage owner's recovery path before applying the effect.
    pub async fn backup_before_live_adoption(&self) -> Result<LogicalBackup, ResourceRuntimeError> {
        self.store
            .logical_backup()
            .await
            .map_err(|_| ResourceRuntimeError::StoreReadFailed)
    }

    /// Load and validate the persisted Device record before a security-key
    /// provider constructs its one-use admission. Request fields select a
    /// candidate only; the returned values all originate from the store.
    #[allow(dead_code)]
    #[allow(dead_code)]
    pub(crate) async fn security_key_device_is_admitted(
        &self,
        request: SecurityKeyDeviceAdmissionRequest<'_>,
    ) -> Result<SecurityKeyDeviceAdmission, ResourceRuntimeError> {
        let resource = self
            .backend
            .get(StoreGetRequest {
                operation: StoreOperationContext {
                    operation_id: request.operation_id.to_owned(),
                    idempotency_key: None,
                    correlation_id: request.operation_id.to_owned(),
                    trace_id: None,
                    deadline_ms: 30_000,
                },
                zone: self.zone.clone(),
                target: request.device_ref.clone(),
                expected_uid: Some(request.device_uid.clone()),
                projection: StoreProjection::Full,
            })
            .await
            .ok();
        let Some(resource) = resource.filter(|resource| {
            resource.uid == *request.device_uid
                && resource.resource_ref == *request.device_ref
                && resource.resource_ref.resource_type().as_str() == "Device"
                && resource.zone == self.zone
        }) else {
            return Err(ResourceRuntimeError::AuthenticationUnavailable);
        };
        let value = serde_json::from_slice::<Value>(&resource.canonical_json)
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?;
        if !Self::security_key_device_matches(
            &value,
            &self.zone,
            request.request_zone_ref,
            request.holder_ref,
            request.vm_id,
            request.selector_id,
        ) {
            return Err(ResourceRuntimeError::AuthenticationUnavailable);
        }
        let zone_ref = ResourceRef::parse(&format!("Zone/{}", self.zone.as_str()))
            .expect("ZoneId always produces a valid Zone resource reference");
        Ok(SecurityKeyDeviceAdmission {
            zone_ref,
            device_uid: resource.uid,
            holder_ref: request.holder_ref.clone(),
            selector_id: request.selector_id.to_owned(),
        })
    }

    /// Record broker evidence for synchronous non-resource broker dispatches.
    pub fn record_broker_evidence(
        &self,
        evidence: DurabilityEvidence,
    ) -> Result<(), ResourceRuntimeError> {
        self.store
            .broker_evidence_index()
            .insert(evidence)
            .map_err(|_| ResourceRuntimeError::StoreOpenFailed)
    }

    /// Publish terminal broker evidence and drain the live store outbox.
    pub async fn ingest_broker_evidence(
        &self,
        operation_id: &str,
        evidence: DurabilityEvidence,
    ) -> Result<(), ResourceRuntimeError> {
        self.store
            .ingest_broker_evidence(operation_id, evidence)
            .await
            .map_err(|_| ResourceRuntimeError::StoreOpenFailed)
    }

    /// Return every pending trusted-deferred activation outbox for this Zone.
    pub(crate) async fn pending_trusted_activation_operation_ids(
        &self,
    ) -> Result<Vec<String>, ResourceRuntimeError> {
        self.store
            .pending_deferred_activation_operation_ids()
            .await
            .map_err(|_| ResourceRuntimeError::StoreOpenFailed)
    }

    /// Refuse publication while any trusted-deferred activation outbox remains.
    pub(crate) async fn require_trusted_activation_outboxes_drained(
        &self,
    ) -> Result<(), ResourceRuntimeError> {
        match self
            .store
            .require_no_pending_deferred_activation_outboxes()
            .await
        {
            Ok(()) => Ok(()),
            Err(error) if error.reason_code() == "audit-deferred-evidence-pending" => {
                Err(ResourceRuntimeError::HandlerNotReady)
            }
            Err(_) => Err(ResourceRuntimeError::StoreOpenFailed),
        }
    }

    #[allow(dead_code)]
    #[allow(dead_code)]
    fn tpm_device_targets_vm(resource: &Value, vm_id: &str) -> bool {
        resource
            .get("metadata")
            .and_then(Value::as_object)
            .and_then(|metadata| metadata.get("ownerRef"))
            .and_then(Value::as_str)
            .and_then(|owner| owner.strip_prefix("Guest/"))
            == Some(vm_id)
    }

    #[allow(dead_code)]
    #[allow(dead_code)]
    fn security_key_device_matches(
        resource: &Value,
        zone: &ZoneId,
        request_zone_ref: &ResourceRef,
        holder_ref: &ResourceRef,
        vm_id: &str,
        selector_id: &str,
    ) -> bool {
        let expected_zone_ref = ResourceRef::parse(&format!("Zone/{}", zone.as_str()))
            .expect("ZoneId always produces a valid Zone resource reference");
        if request_zone_ref != &expected_zone_ref
            || holder_ref.resource_type().as_str() != "Guest"
            || holder_ref.name().as_str() != vm_id
        {
            return false;
        }
        let Some(metadata) = resource.get("metadata").and_then(Value::as_object) else {
            return false;
        };
        if metadata.get("zone").and_then(Value::as_str) != Some(zone.as_str())
            || metadata.get("ownerRef").and_then(Value::as_str)
                != Some(holder_ref.to_canonical_string().as_str())
        {
            return false;
        }
        resource
            .get("spec")
            .and_then(Value::as_object)
            .filter(|spec| {
                spec.get("providerRef").and_then(Value::as_str)
                    == Some(d2b_provider_device_security_key::PROVIDER_REF)
            })
            .and_then(|spec| spec.get("inventory"))
            .and_then(Value::as_object)
            .and_then(|inventory| inventory.get("selector"))
            .and_then(Value::as_object)
            .and_then(|selector| selector.get("label"))
            .and_then(Value::as_str)
            == Some(selector_id)
    }

    #[allow(dead_code)]
    #[allow(dead_code)]
    fn tpm_migration_decision(
        vm_id: &str,
        intent: &str,
        legacy_intent_anchor: Option<&str>,
    ) -> LegacyTpmMigrationDecision {
        if let Some(anchor) = legacy_intent_anchor {
            LegacyTpmMigrationDecision::adoption_required(vm_id, intent, anchor)
        } else {
            LegacyTpmMigrationDecision::not_applicable(vm_id, intent)
        }
    }

    /// Close the production redb workers before the runtime is discarded.
    pub async fn shutdown(self) -> Result<(), ResourceRuntimeError> {
        let ZoneResourceRuntime {
            store,
            backend,
            api,
            bus,
            registrar,
            ingress,
            service_task,
            authority_persistence,
            authority_recovery,
            process_status_client,
            core_runner_tasks,
            u12_runner_tasks,
            u7_runner_tasks,
            u6_runner_tasks,
            u9_runner_tasks,
            audio_runtime,
            device_binding_watch_task,
            process_runner_task,
            process_runner_generation,
            controller_sessions,
            controller_session_reconcile_task,
            assignments,
            ..
        } = self;
        if let Some(task) = service_task
            .into_inner()
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?
        {
            task.abort();
            let _ = task.await;
        }
        let core_runner_tasks = core_runner_tasks
            .into_inner()
            .map_err(|_| ResourceRuntimeError::WatchUnavailable)?;
        for task in core_runner_tasks {
            task.abort();
            let _ = task.await;
        }
        let u12_runner_tasks = u12_runner_tasks
            .into_inner()
            .map_err(|_| ResourceRuntimeError::WatchUnavailable)?;
        for task in u12_runner_tasks {
            task.abort();
            let _ = task.await;
        }
        let u7_runner_tasks = u7_runner_tasks
            .into_inner()
            .map_err(|_| ResourceRuntimeError::WatchUnavailable)?;
        for task in u7_runner_tasks {
            task.abort();
            let _ = task.await;
        }
        let u6_runner_tasks = u6_runner_tasks
            .into_inner()
            .map_err(|_| ResourceRuntimeError::WatchUnavailable)?;
        for task in u6_runner_tasks {
            task.abort();
            let _ = task.await;
        }
        let u9_runner_tasks = u9_runner_tasks
            .into_inner()
            .map_err(|_| ResourceRuntimeError::WatchUnavailable)?;
        for task in u9_runner_tasks {
            task.abort();
            let _ = task.await;
        }
        drop(audio_runtime);
        if let Some(task) = device_binding_watch_task
            .into_inner()
            .map_err(|_| ResourceRuntimeError::WatchUnavailable)?
        {
            task.abort();
            let _ = task.await;
        }
        if let Some(task) = process_runner_task
            .into_inner()
            .map_err(|_| ResourceRuntimeError::WatchUnavailable)?
        {
            task.abort();
            let _ = task.await;
        }
        drop(process_runner_generation);
        let controller_session_task = controller_session_reconcile_task
            .lock()
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?
            .take();
        if let Some(task) = controller_session_task {
            task.abort();
            let _ = task.await;
        }
        let sessions = Arc::try_unwrap(controller_sessions)
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?
            .into_inner()
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?;
        for (_, session) in sessions {
            if d2b_provider_runtime_cloud_hypervisor::is_provider_ref(
                session.binding.provider_ref(),
            ) {
                assignments
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .revoke_session_for(&session.binding);
            }
            send_controller_assignment_revocations(&session.driver, &session.assignments).await;
            let _ = session
                .driver
                .close(
                    d2b_contracts_zone_session::v3::component_session::CloseReason::RoleMismatch,
                    d2b_contracts_zone_session::v3::component_session::Remediation::ReplaceGeneration,
                )
                .await;
            session.service_task.abort();
            let _ = session.service_task.await;
            let mut ingress = session.ingress;
            let mut registrar = registrar
                .lock()
                .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?;
            if let Some(registrar) = registrar.as_mut() {
                let _ = registrar.revoke_in_place(&mut ingress).await;
            }
        }
        drop(process_status_client);
        drop(
            ingress
                .into_inner()
                .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?,
        );
        drop(
            Arc::try_unwrap(registrar)
                .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?
                .into_inner()
                .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?,
        );
        drop(bus);
        drop(api);
        drop(backend);
        drop(authority_persistence);
        drop(authority_recovery);
        let store = Arc::try_unwrap(store).map_err(|_| ResourceRuntimeError::CoreStartupFailed)?;
        store
            .shutdown()
            .await
            .map_err(|_| ResourceRuntimeError::StoreOpenFailed)
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct SystemCoreUserDiscovery;

#[derive(Debug, Clone, Copy)]
struct SystemCoreHostProbe {
    user_uid: u32,
}

impl SystemCoreHostProbe {
    fn current() -> Self {
        Self {
            user_uid: Uid::current().as_raw(),
        }
    }

    fn kernel_release() -> Result<String, d2b_provider_system_core::SystemCoreError> {
        d2bd_runtime::resource_runtime_support::read_bounded("/proc/sys/kernel/osrelease", 64)
            .map(|release| release.trim().to_owned())
            .map_err(|_| d2b_provider_system_core::SystemCoreError::HostProbeFailed)
    }

    fn os_name() -> Result<String, d2b_provider_system_core::SystemCoreError> {
        let release =
            d2bd_runtime::resource_runtime_support::read_bounded("/etc/os-release", 16 * 1024)
                .map_err(|_| d2b_provider_system_core::SystemCoreError::HostProbeFailed)?;
        Ok(release
            .lines()
            .find_map(|line| line.strip_prefix("NAME="))
            .map(|name| name.trim_matches('"').to_owned())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "unknown".to_owned()))
    }

    fn runtime_path(&self, name: &str) -> std::path::PathBuf {
        Path::new("/run/user")
            .join(self.user_uid.to_string())
            .join(name)
    }

    fn has_render_node() -> bool {
        fs::read_dir("/dev/dri")
            .map(|entries| {
                entries.flatten().any(|entry| {
                    entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| name.starts_with("renderD"))
                })
            })
            .unwrap_or(false)
    }

    fn has_primary_drm_node() -> bool {
        fs::read_dir("/dev/dri")
            .map(|entries| {
                entries.flatten().any(|entry| {
                    entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| name.starts_with("card"))
                })
            })
            .unwrap_or(false)
    }

    fn active_process_count() -> Result<u32, d2b_provider_system_core::SystemCoreError> {
        let mut count = 0_u32;
        for entry in fs::read_dir("/proc")
            .map_err(|_| d2b_provider_system_core::SystemCoreError::HostProbeFailed)?
        {
            let entry =
                entry.map_err(|_| d2b_provider_system_core::SystemCoreError::HostProbeFailed)?;
            if entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.bytes().all(|byte| byte.is_ascii_digit()))
            {
                count = count.saturating_add(1);
            }
        }
        Ok(count)
    }
}

impl HostProbeEffectPort for SystemCoreHostProbe {
    async fn probe(
        &self,
        capability: HostCapabilityClass,
    ) -> Result<bool, d2b_provider_system_core::SystemCoreError> {
        let available = match capability {
            HostCapabilityClass::Kvm => Path::new("/dev/kvm").is_file(),
            HostCapabilityClass::Pidfd => {
                let gate = crate::process_provider_runtime::detect_minijail_platform_gate();
                gate.kernel_major > 5 || (gate.kernel_major == 5 && gate.kernel_minor >= 3)
            }
            HostCapabilityClass::CgroupV2 => {
                Path::new("/sys/fs/cgroup/cgroup.controllers").is_file()
            }
            HostCapabilityClass::UserNamespace => Path::new("/proc/self/ns/user").exists(),
            HostCapabilityClass::Virtiofs => Path::new("/dev/fuse").is_file(),
            HostCapabilityClass::AudioPipewire => {
                d2bd_runtime::resource_runtime_support::is_socket(&self.runtime_path("pipewire-0"))
            }
            HostCapabilityClass::Wayland => {
                d2bd_runtime::resource_runtime_support::is_socket(&self.runtime_path("wayland-0"))
            }
            HostCapabilityClass::GpuRender => Self::has_render_node(),
            HostCapabilityClass::GpuDrm => Self::has_primary_drm_node(),
            HostCapabilityClass::Tpm2 => {
                Path::new("/dev/tpmrm0").is_file() || Path::new("/dev/tpm0").is_file()
            }
            HostCapabilityClass::Usbip => {
                Path::new("/sys/module/usbip_core").exists()
                    || Path::new("/sys/module/usbip_host").exists()
            }
        };
        Ok(available)
    }

    async fn platform(
        &self,
    ) -> Result<MinijailPlatformGate, d2b_provider_system_core::SystemCoreError> {
        let gate = crate::process_provider_runtime::detect_minijail_platform_gate();
        Ok(MinijailPlatformGate::new(
            gate.kernel_major,
            gate.kernel_minor,
            gate.cgroup_kill_available,
        ))
    }

    async fn metadata(
        &self,
    ) -> Result<HostProbeMetadata, d2b_provider_system_core::SystemCoreError> {
        Ok(HostProbeMetadata {
            kernel_release: Self::kernel_release()?,
            os_name: Self::os_name()?,
            user_manager_available: self.runtime_path("systemd").is_dir(),
            active_process_count: Self::active_process_count()?,
        })
    }
}

impl UserDiscoveryEffectPort for SystemCoreUserDiscovery {
    async fn discover(
        &self,
        user_ref: &ResourceRef,
        spec: &UserSpec,
    ) -> Result<
        Option<d2b_provider_system_core::DiscoveredUser>,
        d2b_provider_system_core::SystemCoreError,
    > {
        discover_local_user(user_ref, spec).await
    }
}

fn resource_status_observed_generation(resource: &ResourceSnapshot) -> Option<ResourceGeneration> {
    let value = serde_json::from_slice::<Value>(resource.canonical_json()).ok()?;
    let generation = value
        .pointer("/status/observedGeneration")
        .and_then(Value::as_u64)?;
    ResourceGeneration::new(generation).ok()
}

async fn discover_local_user(
    user_ref: &ResourceRef,
    spec: &UserSpec,
) -> Result<
    Option<d2b_provider_system_core::DiscoveredUser>,
    d2b_provider_system_core::SystemCoreError,
> {
    let username = spec.os_username().as_str();
    let user = User::from_name(username)
        .map_err(|_| d2b_provider_system_core::SystemCoreError::DiscoveryUnavailable)?;
    let Some(user) = user else {
        return Ok(None);
    };

    let mut digest = Sha256::new();
    digest.update(b"d2b-system-core-user-v1");
    digest.update(user_ref.name().as_str().as_bytes());
    digest.update([0]);
    digest.update(username.as_bytes());
    digest.update([0]);
    digest.update(user.uid.as_raw().to_le_bytes());
    digest.update(user.gid.as_raw().to_le_bytes());

    let mut verified = std::collections::BTreeSet::from([UserBinding::NssRecord]);
    if Group::from_gid(user.gid)
        .map_err(|_| d2b_provider_system_core::SystemCoreError::DiscoveryUnavailable)?
        .is_some()
    {
        verified.insert(UserBinding::PrimaryGroup);
    }

    let mut groups_verified = true;
    for group in spec.groups() {
        let Some(group_record) = Group::from_name(group.as_str())
            .map_err(|_| d2b_provider_system_core::SystemCoreError::DiscoveryUnavailable)?
        else {
            groups_verified = false;
            continue;
        };
        digest.update([0]);
        digest.update(group.as_str().as_bytes());
        if !group_record.mem.iter().any(|member| member == username) {
            groups_verified = false;
        }
    }
    if groups_verified && !spec.groups().is_empty() {
        verified.insert(UserBinding::GroupMemberships);
    }

    Ok(Some(d2b_provider_system_core::DiscoveredUser {
        identity: UserIdentityDigest::from_bytes(digest.finalize().into()),
        observed: UserObservation::from_verified(verified),
    }))
}

async fn load_interaction_provider_configuration(
    zone: &ZoneId,
    store: &RedbResourceStore,
    current_revision: ZoneRevision,
) -> Result<Option<CommittedInteractionProviderConfiguration>, ResourceRuntimeError> {
    let provider_type =
        ResourceTypeName::parse("Provider").map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
    let operation = StoreOperationContext {
        operation_id: "interaction-provider-config".to_owned(),
        idempotency_key: None,
        correlation_id: "interaction-provider-config".to_owned(),
        trace_id: None,
        deadline_ms: 10_000,
    };
    let clipboard_ref = ResourceRef::parse("Provider/clipboard-wayland")
        .map_err(|_| ResourceRuntimeError::InteractionConfigurationUnavailable)?;
    let notification_ref = ResourceRef::parse("Provider/notification-desktop")
        .map_err(|_| ResourceRuntimeError::InteractionConfigurationUnavailable)?;
    let page = store
        .list(StoreListRequest {
            operation,
            zone: zone.clone(),
            resource_types: vec![provider_type],
            resource_names: vec![
                ResourceName::parse("clipboard-wayland")
                    .map_err(|_| ResourceRuntimeError::InteractionConfigurationUnavailable)?,
                ResourceName::parse("notification-desktop")
                    .map_err(|_| ResourceRuntimeError::InteractionConfigurationUnavailable)?,
            ],
            filters: Vec::new(),
            page_size: 2,
            cursor: None,
            projection: StoreProjection::Full,
        })
        .await
        .map_err(|error| {
            tracing::error!(zone = %zone.as_str(), error = ?error, "bootstrap Host list failed");
            ResourceRuntimeError::StoreReadFailed
        })?;
    if page.next_cursor.is_some() {
        return Err(ResourceRuntimeError::InteractionConfigurationUnavailable);
    }
    let mut clipboard = None;
    let mut notification = None;
    for resource in page.resources {
        if resource.resource_ref == clipboard_ref {
            if clipboard.is_some() {
                return Err(ResourceRuntimeError::InteractionConfigurationUnavailable);
            }
            clipboard = Some(parse_committed_clipboard_configuration(
                zone,
                current_revision,
                &resource,
            )?);
        } else if resource.resource_ref == notification_ref {
            if notification.is_some() {
                return Err(ResourceRuntimeError::InteractionConfigurationUnavailable);
            }
            notification = Some(parse_committed_notification_configuration(
                zone,
                current_revision,
                &resource,
            )?);
        }
    }
    if clipboard.is_none() && notification.is_none() {
        Ok(None)
    } else {
        Ok(Some(CommittedInteractionProviderConfiguration {
            clipboard,
            notification,
        }))
    }
}

async fn load_committed_interaction_identity(
    zone: &ZoneId,
    store: &RedbResourceStore,
    current_revision: ZoneRevision,
    configuration: Option<&CommittedInteractionProviderConfiguration>,
) -> Result<Option<CommittedInteractionIdentity>, ResourceRuntimeError> {
    let session_resource_type = ResourceTypeName::parse("display-wayland.d2bus.org.WaylandSession")
        .map_err(|_| ResourceRuntimeError::InteractionConfigurationUnavailable)?;
    let operation = StoreOperationContext {
        operation_id: "interaction-wayland-session".to_owned(),
        idempotency_key: None,
        correlation_id: "interaction-wayland-session".to_owned(),
        trace_id: None,
        deadline_ms: 10_000,
    };
    let page = store
        .list(StoreListRequest {
            operation,
            zone: zone.clone(),
            resource_types: vec![session_resource_type],
            resource_names: Vec::new(),
            filters: Vec::new(),
            page_size: 2,
            cursor: None,
            projection: StoreProjection::Full,
        })
        .await
        .map_err(|_| ResourceRuntimeError::InteractionConfigurationUnavailable)?;
    if page.next_cursor.is_some() {
        return Err(ResourceRuntimeError::InteractionConfigurationUnavailable);
    }
    if page.resources.is_empty() {
        return if configuration.is_none() {
            Ok(None)
        } else {
            Err(ResourceRuntimeError::InteractionConfigurationUnavailable)
        };
    }
    if page.resources.len() != 1 {
        return Err(ResourceRuntimeError::InteractionConfigurationUnavailable);
    }
    let session_resource = page
        .resources
        .into_iter()
        .next()
        .ok_or(ResourceRuntimeError::InteractionConfigurationUnavailable)?;
    let session_spec = committed_wayland_session_spec(zone, current_revision, &session_resource)
        .inspect_err(|error| {
            tracing::error!(
                zone = %zone.as_str(),
                error = %error,
                "resource runtime committed Wayland session parse failed",
            );
        })?;
    let subject_ref = session_spec.guest_ref().clone();
    let host_execution_ref = session_spec.host_ref().clone();
    let user_ref = session_spec.user_ref().clone();
    let expected_policy_type =
        ResourceTypeName::parse("display-wayland.d2bus.org.WaylandPolicy")
            .map_err(|_| ResourceRuntimeError::InteractionConfigurationUnavailable)?;
    if session_spec.policy_ref().resource_type() != &expected_policy_type {
        return Err(ResourceRuntimeError::InteractionConfigurationUnavailable);
    }
    let _policy_resource =
        committed_resource(zone, store, current_revision, session_spec.policy_ref())
            .await
            .inspect_err(|error| {
                tracing::error!(
                    zone = %zone.as_str(),
                    operation = "interaction-policy-lookup",
                    error = %error,
                    "resource runtime committed Wayland policy lookup failed",
                );
            })?;
    let subject_uid = committed_resource_uid(zone, store, current_revision, &subject_ref)
        .await
        .inspect_err(|error| {
            tracing::error!(
                zone = %zone.as_str(),
                operation = "interaction-subject-lookup",
                error = %error,
                "resource runtime committed interaction subject lookup failed",
            );
        })?;
    let _host_uid = committed_resource_uid(zone, store, current_revision, &host_execution_ref)
        .await
        .inspect_err(|error| {
            tracing::error!(
                zone = %zone.as_str(),
                operation = "interaction-host-lookup",
                error = %error,
                "resource runtime committed interaction Host lookup failed",
            );
        })?;
    let _user_uid = committed_resource_uid(zone, store, current_revision, &user_ref)
        .await
        .inspect_err(|error| {
            tracing::error!(
                zone = %zone.as_str(),
                operation = "interaction-user-lookup",
                error = %error,
                "resource runtime committed interaction User lookup failed",
            );
        })?;

    let display_ref = ResourceRef::parse("Provider/display-wayland")
        .map_err(|_| ResourceRuntimeError::InteractionConfigurationUnavailable)?;
    let display_resource = committed_resource(zone, store, current_revision, &display_ref)
        .await
        .inspect_err(|error| {
            tracing::error!(
                zone = %zone.as_str(),
                operation = "display-provider-lookup",
                error = %error,
                "resource runtime committed display Provider lookup failed",
            );
        })?;
    let (_, _, display_provider_generation, _, _) =
        committed_provider_spec(zone, current_revision, &display_resource, &display_ref)
            .inspect_err(|error| {
                tracing::error!(
                    zone = %zone.as_str(),
                    operation = "display-provider-validation",
                    error = %error,
                    "resource runtime committed display Provider validation failed",
                );
            })?;

    let mut allowed_guest_sources = BTreeMap::from([(subject_ref.clone(), subject_uid.clone())]);
    let mut clipboard_provider_generation = None;
    let mut clipboard_provider_uid = None;
    let mut notification_provider_generation = None;
    let mut notification_provider_uid = None;
    if let Some(configuration) = configuration {
        if !configuration.is_complete() {
            return Err(ResourceRuntimeError::InteractionConfigurationUnavailable);
        }
        if let Some(clipboard) = configuration.clipboard() {
            if clipboard.host_execution_ref != host_execution_ref
                || clipboard.host_user_ref != user_ref
                || clipboard.display_wayland_ref != display_ref
            {
                return Err(ResourceRuntimeError::InteractionConfigurationUnavailable);
            }
            for guest_ref in &clipboard.guest_sources {
                let uid = committed_resource_uid(zone, store, current_revision, guest_ref).await?;
                allowed_guest_sources.insert(guest_ref.clone(), uid);
            }
            clipboard_provider_generation = Some(clipboard.resource_generation);
            clipboard_provider_uid = Some(clipboard.resource_uid().clone());
        }
        if let Some(notification) = configuration.notification() {
            if notification.host_execution_ref != host_execution_ref
                || notification.observer_user_ref() != &user_ref
                || notification.config.display_wayland_ref() != Some(&display_ref)
            {
                return Err(ResourceRuntimeError::InteractionConfigurationUnavailable);
            }
            for guest_ref in notification.guest_sources() {
                let uid = committed_resource_uid(zone, store, current_revision, guest_ref).await?;
                allowed_guest_sources.insert(guest_ref.clone(), uid);
            }
            notification_provider_generation = Some(notification.resource_generation);
            notification_provider_uid = Some(notification.resource_uid().clone());
        }
    }

    Ok(Some(CommittedInteractionIdentity {
        zone: zone.clone(),
        wayland_session_ref: session_resource.resource_ref,
        wayland_session_uid: session_resource.uid,
        subject_ref,
        subject_uid,
        host_execution_ref,
        user_ref,
        allowed_guest_sources,
        display_provider_generation,
        clipboard_provider_generation,
        clipboard_provider_uid,
        notification_provider_generation,
        notification_provider_uid,
    }))
}

fn committed_wayland_session_spec(
    zone: &ZoneId,
    current_revision: ZoneRevision,
    resource: &StoredResource,
) -> Result<WaylandSessionSpec, ResourceRuntimeError> {
    let expected_type = ResourceTypeName::parse("display-wayland.d2bus.org.WaylandSession")
        .map_err(|_| ResourceRuntimeError::InteractionConfigurationUnavailable)?;
    if &resource.zone != zone
        || resource.resource_ref.resource_type() != &expected_type
        || resource.generation.get() == 0
        || resource.revision.get() == 0
        || resource.revision > current_revision
    {
        tracing::error!(
            zone = %zone.as_str(),
            resource_zone = %resource.zone.as_str(),
            resource_ref = %resource.resource_ref.to_canonical_string(),
            generation = resource.generation.get(),
            revision = resource.revision.get(),
            current_revision = current_revision.get(),
            "committed Wayland session row failed stored-resource identity checks",
        );
        return Err(ResourceRuntimeError::InteractionConfigurationUnavailable);
    }
    let envelope = ResourceEnvelope::from_json(&resource.canonical_json).map_err(|error| {
        tracing::error!(
            zone = %zone.as_str(),
            error = ?error,
            "committed Wayland session envelope decode failed",
        );
        ResourceRuntimeError::InteractionConfigurationUnavailable
    })?;
    if envelope.resource_type() != &expected_type
        || envelope.metadata().zone() != zone
        || envelope.metadata().uid() != &resource.uid
        || envelope.metadata().generation() != resource.generation
        || envelope.metadata().revision() != resource.revision
        || envelope
            .digest()
            .map_err(|_| ResourceRuntimeError::InteractionConfigurationUnavailable)?
            != resource.payload_digest
    {
        tracing::error!(
            zone = %zone.as_str(),
            envelope_type = %envelope.resource_type().as_str(),
            envelope_zone = %envelope.metadata().zone().as_str(),
            envelope_uid = %envelope.metadata().uid().as_str(),
            stored_uid = %resource.uid.as_str(),
            envelope_generation = envelope.metadata().generation().get(),
            stored_generation = resource.generation.get(),
            envelope_revision = envelope.metadata().revision().get(),
            stored_revision = resource.revision.get(),
            "committed Wayland session envelope failed integrity checks",
        );
        return Err(ResourceRuntimeError::InteractionConfigurationUnavailable);
    }
    let spec =
        serde_json::from_slice::<WaylandSessionSpec>(&envelope.spec().base().to_canonical_bytes())
            .map_err(|error| {
                tracing::error!(
                    zone = %zone.as_str(),
                    error = ?error,
                    "committed Wayland session spec decode failed",
                );
                ResourceRuntimeError::InteractionConfigurationUnavailable
            })?;
    Ok(spec)
}

async fn committed_resource_uid(
    zone: &ZoneId,
    store: &RedbResourceStore,
    current_revision: ZoneRevision,
    resource_ref: &ResourceRef,
) -> Result<ResourceUid, ResourceRuntimeError> {
    let resource = committed_resource(zone, store, current_revision, resource_ref).await?;
    Ok(resource.uid)
}

async fn receive_controller_bootstrap(
    daemon_socket: &SeqpacketSocket,
) -> Result<(SeqpacketSocket, PeerCredentials), ResourceRuntimeError> {
    let policy = controller_bootstrap_attachment_policy();
    let capacity = AncillaryCapacity::from_policy(policy)
        .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?;
    let scopes =
        controller_credit_scopes().map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?;
    let burst = tokio::time::timeout(
        CONTROLLER_BOOTSTRAP_TIMEOUT,
        daemon_socket.recv_burst(
            d2b_contracts_zone_session::v3::component_session::LimitProfile::local_default(),
            capacity,
            &scopes,
            2,
        ),
    )
    .await
    .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?
    .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?;
    if burst.packets.len() != 1 {
        return Err(ResourceRuntimeError::AuthenticationUnavailable);
    }
    let packet = burst
        .packets
        .into_iter()
        .next()
        .ok_or(ResourceRuntimeError::AuthenticationUnavailable)?;
    if packet.payload() != d2b_session_unix::CONTROLLER_BOOTSTRAP_PROTOCOL_MARKER {
        return Err(ResourceRuntimeError::AuthenticationUnavailable);
    }
    let (resource_fd, credentials) = packet
        .into_single_file_and_credentials()
        .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?;
    let resource_socket = SeqpacketSocket::from_parent_prearmed(resource_fd)
        .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?;
    if resource_socket
        .acceptor_peer_credentials()
        .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?
        != credentials
    {
        return Err(ResourceRuntimeError::AuthenticationUnavailable);
    }
    Ok((resource_socket, credentials))
}

async fn committed_resource(
    zone: &ZoneId,
    store: &RedbResourceStore,
    current_revision: ZoneRevision,
    resource_ref: &ResourceRef,
) -> Result<StoredResource, ResourceRuntimeError> {
    if !matches!(
        resource_ref.resource_type().as_str(),
        "Guest"
            | "Host"
            | "Provider"
            | "User"
            | "display-wayland.d2bus.org.WaylandPolicy"
            | "display-wayland.d2bus.org.WaylandSession"
    ) {
        return Err(ResourceRuntimeError::InteractionConfigurationUnavailable);
    }
    let operation_id = format!(
        "interaction-identity:{}",
        resource_ref.to_canonical_string()
    );
    let resource = store
        .get(StoreGetRequest {
            operation: StoreOperationContext {
                operation_id: operation_id.clone(),
                idempotency_key: None,
                correlation_id: operation_id,
                trace_id: None,
                deadline_ms: 10_000,
            },
            zone: zone.clone(),
            target: resource_ref.clone(),
            expected_uid: None,
            projection: StoreProjection::Full,
        })
        .await
        .map_err(|_| ResourceRuntimeError::InteractionConfigurationUnavailable)?;
    if resource.zone != *zone
        || resource.resource_ref != *resource_ref
        || resource.generation.get() == 0
        || resource.revision.get() == 0
        || resource.revision > current_revision
    {
        return Err(ResourceRuntimeError::InteractionConfigurationUnavailable);
    }
    let envelope = ResourceEnvelope::from_json(&resource.canonical_json)
        .map_err(|_| ResourceRuntimeError::InteractionConfigurationUnavailable)?;
    if envelope.resource_type() != resource_ref.resource_type()
        || envelope.metadata().name() != resource_ref.name()
        || envelope.metadata().zone() != zone
        || envelope.metadata().uid() != &resource.uid
        || envelope.metadata().generation() != resource.generation
        || envelope.metadata().revision() != resource.revision
        || envelope
            .digest()
            .map_err(|_| ResourceRuntimeError::InteractionConfigurationUnavailable)?
            != resource.payload_digest
    {
        return Err(ResourceRuntimeError::InteractionConfigurationUnavailable);
    }
    Ok(resource)
}

async fn load_committed_controller_provider_identities(
    zone: &ZoneId,
    store: &RedbResourceStore,
    current_revision: ZoneRevision,
    provider_refs: BTreeSet<ResourceRef>,
) -> Result<BTreeMap<ResourceRef, (ResourceUid, ResourceGeneration)>, ResourceRuntimeError> {
    let mut identities = BTreeMap::new();
    for provider_ref in provider_refs {
        let resource = committed_resource(zone, store, current_revision, &provider_ref).await?;
        let (_, uid, generation, _, _) =
            committed_provider_spec(zone, current_revision, &resource, &provider_ref)?;
        identities.insert(provider_ref, (uid, generation));
    }
    Ok(identities)
}

fn controller_session_needs_fence(bootstrap_present: bool, service_task_finished: bool) -> bool {
    !bootstrap_present || service_task_finished
}

fn controller_assignment_refresh_action<'a>(
    context: &'a crate::process_provider_runtime::ControllerBootstrapContext,
    error: ControllerAssignmentRefreshError,
) -> ControllerAssignmentRefreshAction<'a> {
    match error {
        ControllerAssignmentRefreshError::Retryable => {
            ControllerAssignmentRefreshAction::Retryable { context }
        }
        ControllerAssignmentRefreshError::Failed(error) => {
            ControllerAssignmentRefreshAction::Failed { context, error }
        }
    }
}

async fn reset_controller_assignment_stream(
    driver: &SessionDriverHandle,
    stream: StreamId,
) -> Result<(), ControllerAssignmentRefreshError> {
    driver.reset_named_stream(stream).await.map_err(|_| {
        ControllerAssignmentRefreshError::Failed(ResourceRuntimeError::AuthenticationUnavailable)
    })
}

async fn send_controller_assignment_frame(
    driver: &SessionDriverHandle,
    stream: StreamId,
    encoded: Vec<u8>,
    on_send_failure: impl FnOnce() + Send,
) -> Result<(), ControllerAssignmentRefreshError> {
    if driver.send_named_stream(stream, encoded).await.is_ok() {
        return Ok(());
    }
    on_send_failure();
    reset_controller_assignment_stream(driver, stream).await?;
    Err(ControllerAssignmentRefreshError::Retryable)
}

fn controller_generation_is_stale(
    current_generation: Option<ControllerGeneration>,
    context_generation: ControllerGeneration,
) -> bool {
    current_generation != Some(context_generation)
}

fn assignment_error_is_off_target(error: AssignmentError) -> bool {
    matches!(
        error,
        AssignmentError::InvalidRole
            | AssignmentError::ResourceTypeUnowned
            | AssignmentError::TargetMismatch
            | AssignmentError::TargetKindUnsupported
    )
}

fn controller_session_matches(
    active: &ControllerSessionBinding,
    requested: &ControllerSessionBinding,
    service_task_finished: bool,
) -> bool {
    !service_task_finished && active == requested
}

fn assignment_resource_matches(
    resource_ref: &ResourceRef,
    resource_uid: &ResourceUid,
    resource_generation: ResourceGeneration,
    resource_revision: ZoneRevision,
    resource: &ResourceEnvelope,
) -> bool {
    resource_ref
        == &ResourceRef::new(
            resource.resource_type().clone(),
            resource.metadata().name().clone(),
        )
        && resource_uid == resource.metadata().uid()
        && resource_generation == resource.metadata().generation()
        && resource_revision == resource.metadata().revision()
}

fn validate_assignment_list_page(
    page: &StoreListResult,
    zone: &ZoneId,
    provider_ref: &ResourceRef,
    expected_snapshot: Option<ZoneRevision>,
) -> Result<Vec<ResourceEnvelope>, ControllerAssignmentRefreshError> {
    if expected_snapshot.is_some_and(|snapshot| snapshot != page.snapshot_revision) {
        return Err(ControllerAssignmentRefreshError::Retryable);
    }
    let mut resources = Vec::new();
    for stored in &page.resources {
        if &stored.zone != zone
            || stored.revision.get() == 0
            || stored.revision > page.snapshot_revision
        {
            return Err(ControllerAssignmentRefreshError::Failed(
                ResourceRuntimeError::AuthorizationUnavailable,
            ));
        }
        let envelope = ResourceEnvelope::from_json(&stored.canonical_json).map_err(|_| {
            ControllerAssignmentRefreshError::Failed(ResourceRuntimeError::AuthorizationUnavailable)
        })?;
        if envelope.resource_type() != stored.resource_ref.resource_type()
            || envelope.metadata().name() != stored.resource_ref.name()
            || envelope.metadata().zone() != zone
            || envelope.metadata().uid() != &stored.uid
            || envelope.metadata().generation() != stored.generation
            || envelope.metadata().revision() != stored.revision
            || envelope.digest().map_err(|_| {
                ControllerAssignmentRefreshError::Failed(
                    ResourceRuntimeError::AuthorizationUnavailable,
                )
            })? != stored.payload_digest
        {
            return Err(ControllerAssignmentRefreshError::Failed(
                ResourceRuntimeError::AuthorizationUnavailable,
            ));
        }
        if envelope.spec().provider_ref() == Some(provider_ref) {
            resources.push(envelope);
        }
    }
    Ok(resources)
}

fn admit_assignment_or_skip(
    assignments: &AssignmentRegistry,
    request: AssignmentRequest<'_>,
) -> Result<Option<ResourceClientLease>, ResourceRuntimeError> {
    let mut registry = assignments
        .lock()
        .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?;
    match registry.admit(request) {
        Ok(lease) => Ok(Some(lease)),
        Err(error) if assignment_error_is_off_target(error) => Ok(None),
        Err(error) => {
            tracing::warn!(
                error = ?error,
                "external Provider controller assignment registry rejected resource",
            );
            Err(ResourceRuntimeError::AuthorizationUnavailable)
        }
    }
}

async fn send_controller_assignment_revocations(
    driver: &SessionDriverHandle,
    assignments: &BTreeMap<ResourceUid, ResourceClientLease>,
) {
    let Ok(stream) = StreamId::new(CONTROLLER_ASSIGNMENT_STREAM_ID) else {
        return;
    };
    for lease in assignments.values() {
        let Ok(bytes) =
            ControllerAssignmentGrant::encode_revocation(lease.provider_ref(), lease.identity())
        else {
            continue;
        };
        if driver.send_named_stream(stream, bytes).await.is_err() {
            let _ = driver.reset_named_stream(stream).await;
            break;
        }
    }
}

fn controller_session_binding(
    context: &crate::process_provider_runtime::ControllerBootstrapContext,
    session_generation: ReconnectGeneration,
) -> Result<ControllerSessionBinding, ResourceRuntimeError> {
    let target_kind = match context.execution_ref().resource_type().as_str() {
        "Host" => PlacementTargetKind::Host,
        "Guest" => PlacementTargetKind::Guest,
        _ => return Err(ResourceRuntimeError::AuthenticationUnavailable),
    };
    let controller_role =
        if d2b_provider_runtime_cloud_hypervisor::is_provider_ref(context.provider_owner_ref()) {
            ResourceRef::parse(d2b_provider_runtime_cloud_hypervisor::CONTROLLER_ROLE_REF)
                .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?
        } else {
            context.process_ref().clone()
        };
    ControllerSessionBinding::new(
        context.process_ref().clone(),
        context.provider_owner_ref().clone(),
        controller_role,
        AssignmentTarget::Execution {
            kind: target_kind,
            reference: context.execution_ref().clone(),
        },
        context.provider_generation(),
        context.controller_generation(),
        session_generation,
    )
    .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)
}

pub(crate) fn controller_session_snapshot_fences(
    sessions: impl IntoIterator<
        Item = (
            ResourceRef,
            crate::process_provider_runtime::ControllerBootstrapContext,
        ),
    >,
    snapshot: &[StoredResource],
) -> Vec<(
    ResourceRef,
    crate::process_provider_runtime::ControllerBootstrapContext,
)> {
    sessions
        .into_iter()
        .filter(|(_, context)| {
            !snapshot
                .iter()
                .find(|resource| resource.resource_ref == *context.process_ref())
                .is_some_and(|resource| controller_resource_matches(context, resource))
        })
        .collect()
}

fn controller_resource_matches(
    context: &crate::process_provider_runtime::ControllerBootstrapContext,
    resource: &StoredResource,
) -> bool {
    if resource.zone != *context.zone()
        || resource.resource_ref != *context.process_ref()
        || resource.uid != *context.process_uid()
        || resource.generation != context.generation()
        || resource.revision.get() == 0
    {
        return false;
    }
    let Ok(envelope) = ResourceEnvelope::from_json(&resource.canonical_json) else {
        return false;
    };
    if envelope.resource_type().as_str() != "Process"
        || envelope.metadata().zone() != &resource.zone
        || envelope.metadata().uid() != &resource.uid
        || envelope.metadata().generation() != resource.generation
        || envelope.metadata().revision() != resource.revision
        || envelope.digest().ok().as_deref() != Some(resource.payload_digest.as_str())
        || envelope.metadata().owner_ref() != Some(context.provider_owner_ref())
        || envelope.spec().provider_ref() != Some(context.process_provider_ref())
    {
        return false;
    }
    let Ok(process) = serde_json::from_slice::<d2b_contracts_resource::v3::process::ProcessSpec>(
        &envelope.spec().base().to_canonical_bytes(),
    ) else {
        return false;
    };
    process.execution().process_class()
        == d2b_contracts_resource::v3::process::ProcessClass::Controller
        && process.execution().execution_ref() == context.execution_ref()
}

fn committed_provider_spec(
    zone: &ZoneId,
    current_revision: ZoneRevision,
    resource: &StoredResource,
    expected_ref: &ResourceRef,
) -> Result<
    (
        ProviderSpec,
        ResourceUid,
        ResourceGeneration,
        ZoneRevision,
        String,
    ),
    ResourceRuntimeError,
> {
    if &resource.zone != zone
        || &resource.resource_ref != expected_ref
        || resource.generation.get() == 0
        || resource.revision.get() == 0
        || resource.revision > current_revision
    {
        return Err(ResourceRuntimeError::InteractionConfigurationUnavailable);
    }
    let envelope = ResourceEnvelope::from_json(&resource.canonical_json)
        .map_err(|_| ResourceRuntimeError::InteractionConfigurationUnavailable)?;
    if envelope.resource_type().as_str() != "Provider"
        || envelope.metadata().zone() != zone
        || envelope.metadata().uid() != &resource.uid
        || envelope.metadata().generation() != resource.generation
        || envelope.metadata().revision() != resource.revision
        || envelope
            .digest()
            .map_err(|_| ResourceRuntimeError::InteractionConfigurationUnavailable)?
            != resource.payload_digest
    {
        return Err(ResourceRuntimeError::InteractionConfigurationUnavailable);
    }
    let spec = serde_json::from_slice::<ProviderSpec>(&envelope.spec().base().to_canonical_bytes())
        .map_err(|_| ResourceRuntimeError::InteractionConfigurationUnavailable)?;
    // The trusted bundle/resource compiler has already resolved and
    // integrity-pinned the Provider artifact.  Runtime composition is bound
    // to the canonical Provider ResourceRef, not to a package name that may
    // vary between deployments (including hermetic acceptance artifacts).
    if spec.artifact_id().as_str().is_empty() {
        return Err(ResourceRuntimeError::InteractionConfigurationUnavailable);
    }
    Ok((
        spec,
        resource.uid.clone(),
        resource.generation,
        resource.revision,
        resource.payload_digest.clone(),
    ))
}

fn parse_committed_clipboard_configuration(
    zone: &ZoneId,
    current_revision: ZoneRevision,
    resource: &StoredResource,
) -> Result<CommittedClipboardProviderConfiguration, ResourceRuntimeError> {
    let expected_ref = ResourceRef::parse("Provider/clipboard-wayland")
        .map_err(|_| ResourceRuntimeError::InteractionConfigurationUnavailable)?;
    let (spec, resource_uid, resource_generation, resource_revision, provenance_digest) =
        committed_provider_spec(zone, current_revision, resource, &expected_ref)?;
    let wire =
        serde_json::from_slice::<ClipboardProviderConfigWire>(&spec.config().to_canonical_bytes())
            .map_err(|_| ResourceRuntimeError::InteractionConfigurationUnavailable)?;
    if wire.controller_execution_ref != wire.host_execution_ref
        || wire.controller_execution_ref.resource_type().as_str() != "Host"
        || wire.host_execution_ref.resource_type().as_str() != "Host"
        || wire.host_user_ref.resource_type().as_str() != "User"
        || wire.display_wayland_ref.to_canonical_string() != "Provider/display-wayland"
        || wire.policy.cross_zone.enable
        || wire.guest_sources.is_empty()
    {
        return Err(ResourceRuntimeError::InteractionConfigurationUnavailable);
    }
    let mut guest_sources = BTreeSet::new();
    for source in wire.guest_sources {
        if source.guest_ref.resource_type().as_str() != "Guest"
            || !guest_sources.insert(source.guest_ref)
        {
            return Err(ResourceRuntimeError::InteractionConfigurationUnavailable);
        }
    }
    let policy = ClipboardPolicy::new_with_fd_write_timeout_seconds(
        wire.policy.allow_host_capture,
        wire.policy.allow_guest_capture,
        wire.policy.require_picker_for_paste,
        wire.policy.suppress_echo,
        false,
        wire.caps.max_history_entries,
        wire.caps.max_item_bytes,
        wire.caps.max_total_bytes,
        wire.caps.max_concurrent_fds,
        wire.caps.max_guest_rate_per_min,
        wire.caps.fd_write_timeout_seconds,
    )
    .map_err(|_| ResourceRuntimeError::InteractionConfigurationUnavailable)?;
    Ok(CommittedClipboardProviderConfiguration {
        policy,
        audit_capacity: wire.caps.max_history_entries,
        host_execution_ref: wire.host_execution_ref,
        host_user_ref: wire.host_user_ref,
        display_wayland_ref: wire.display_wayland_ref,
        guest_sources,
        resource_uid,
        resource_generation,
        resource_revision,
        provenance_digest,
    })
}

fn parse_committed_notification_configuration(
    zone: &ZoneId,
    current_revision: ZoneRevision,
    resource: &StoredResource,
) -> Result<CommittedNotificationProviderConfiguration, ResourceRuntimeError> {
    let expected_ref = ResourceRef::parse("Provider/notification-desktop")
        .map_err(|_| ResourceRuntimeError::InteractionConfigurationUnavailable)?;
    let (spec, resource_uid, resource_generation, resource_revision, provenance_digest) =
        committed_provider_spec(zone, current_revision, resource, &expected_ref)?;
    let wire = serde_json::from_slice::<NotificationProviderConfigWire>(
        &spec.config().to_canonical_bytes(),
    )
    .map_err(|_| ResourceRuntimeError::InteractionConfigurationUnavailable)?;
    if wire.controller_execution_ref != wire.host_execution_ref
        || wire.controller_execution_ref.resource_type().as_str() != "Host"
        || wire.host_execution_ref.resource_type().as_str() != "Host"
        || wire.host_user_ref.resource_type().as_str() != "User"
        || wire.display_wayland_ref.to_canonical_string() != "Provider/display-wayland"
        || wire.guest_sources.is_empty()
    {
        return Err(ResourceRuntimeError::InteractionConfigurationUnavailable);
    }
    let mut sources = Vec::with_capacity(wire.guest_sources.len());
    for source in wire.guest_sources {
        sources.push(
            GuestSourceConfig::new(source.guest_ref, zone.clone(), source.categories)
                .map_err(|_| ResourceRuntimeError::InteractionConfigurationUnavailable)?,
        );
    }
    let config = NotificationProviderConfig::new(sources)
        .and_then(|config| {
            config.with_host_binding(wire.host_execution_ref.clone(), wire.host_user_ref)
        })
        .and_then(|config| config.with_display_wayland_ref(Some(wire.display_wayland_ref)))
        .and_then(|config| config.with_max_pending_notifications(wire.max_pending_notifications))
        .and_then(|config| config.with_action_nonce_ttl_secs(wire.action_nonce_ttl_secs))
        .and_then(|config| config.with_action_nonce_store_size(wire.action_nonce_store_size))
        .and_then(|config| config.with_acknowledge_timeout_secs(wire.acknowledge_timeout_secs))
        .map(|config| {
            config
                .with_dbus_sink_enabled(wire.dbus_sink_enabled)
                .with_observer_enabled(wire.observer_enabled)
        })
        .map_err(|_| ResourceRuntimeError::InteractionConfigurationUnavailable)?;
    Ok(CommittedNotificationProviderConfiguration {
        config,
        host_execution_ref: wire.host_execution_ref,
        resource_uid,
        resource_generation,
        resource_revision,
        provenance_digest,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SystemCoreResourceReconcileError;

impl core::fmt::Display for SystemCoreResourceReconcileError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("system-core-resource-reconcile-failed")
    }
}

impl std::error::Error for SystemCoreResourceReconcileError {}

/// Typed Host/User handler executed by the shared Core Runner.
struct SystemCoreResourceReconciler {
    descriptor: ControllerDescriptor,
}

impl std::fmt::Debug for SystemCoreResourceReconciler {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SystemCoreResourceReconciler")
            .field("descriptor", &self.descriptor)
            .finish()
    }
}

impl SystemCoreResourceReconciler {
    fn new(descriptor: ControllerDescriptor) -> Arc<Self> {
        Arc::new(Self { descriptor })
    }

    fn resource_type(
        resource: &ResourceSnapshot,
    ) -> Result<&str, SystemCoreResourceReconcileError> {
        match resource.key().resource_ref().resource_type().as_str() {
            "Host" | "User" => Ok(resource.key().resource_ref().resource_type().as_str()),
            _ => Err(SystemCoreResourceReconcileError),
        }
    }

    async fn status_candidate(
        resource: &ResourceSnapshot,
    ) -> Result<Vec<u8>, SystemCoreResourceReconcileError> {
        let envelope = ResourceEnvelope::from_json(resource.canonical_json())
            .map_err(|_| SystemCoreResourceReconcileError)?;
        let resource_ref = ResourceRef::new(
            envelope.resource_type().clone(),
            envelope.metadata().name().clone(),
        );
        let status = match resource_ref.resource_type().as_str() {
            "Host" => {
                let spec: HostSpec =
                    serde_json::from_slice(&envelope.spec().base().to_canonical_bytes())
                        .map_err(|_| SystemCoreResourceReconcileError)?;
                let provider_ref = envelope
                    .spec()
                    .provider_ref()
                    .cloned()
                    .ok_or(SystemCoreResourceReconcileError)?;
                let report = match HostReconciler::new()
                    .reconcile_with_probe(
                        &resource_ref,
                        &provider_ref,
                        &spec,
                        &SystemCoreHostProbe::current(),
                        &BTreeSet::new(),
                        false,
                    )
                    .await
                {
                    Ok(report) => report,
                    Err(_) => {
                        let mut status = HostReconciler::new()
                            .reconcile(&resource_ref, &provider_ref, &spec)
                            .map_err(|_| SystemCoreResourceReconcileError)?;
                        status.phase = ResourcePhase::Degraded;
                        HostObservationReport {
                            status,
                            capabilities: Vec::new(),
                            kernel_release: "unknown".to_owned(),
                            os_name: "unknown".to_owned(),
                            user_manager_available: false,
                            active_process_count: 0,
                            minijail_ready: false,
                        }
                    }
                };
                host_status_value(&report).map_err(|_| SystemCoreResourceReconcileError)?
            }
            "User" => {
                let spec: UserSpec =
                    serde_json::from_slice(&envelope.spec().base().to_canonical_bytes())
                        .map_err(|_| SystemCoreResourceReconcileError)?;
                let status = UserReconciler::new(SystemCoreUserDiscovery)
                    .reconcile(&resource_ref, &spec)
                    .await
                    .map_err(|_| SystemCoreResourceReconcileError)?;
                serde_json::to_value(status).map_err(|_| SystemCoreResourceReconcileError)?
            }
            _ => return Err(SystemCoreResourceReconcileError),
        };
        let mut current = serde_json::from_slice::<Value>(resource.canonical_json())
            .map_err(|_| SystemCoreResourceReconcileError)?;
        let current_status = current
            .get_mut("status")
            .and_then(Value::as_object_mut)
            .ok_or(SystemCoreResourceReconcileError)?;
        let domain_status = status.as_object().ok_or(SystemCoreResourceReconcileError)?;
        let mut resource_projection = current_status
            .get("resource")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        for (key, value) in domain_status {
            if key != "phase" {
                resource_projection.insert(key.clone(), value.clone());
            }
        }
        let object = current_status;
        if let Some(phase) = domain_status.get("phase") {
            object.insert("phase".to_owned(), phase.clone());
        }
        object.insert("resource".to_owned(), Value::Object(resource_projection));
        object.insert(
            "observedGeneration".to_owned(),
            Value::Number(resource.generation().get().into()),
        );
        object.insert(
            "lastReconciledAt".to_owned(),
            Value::String(current_status_timestamp().as_str().to_owned()),
        );
        serde_json::to_vec(&Value::Object(object.clone()))
            .map_err(|_| SystemCoreResourceReconcileError)
    }
}

impl ResourceReconciler for SystemCoreResourceReconciler {
    type Error = SystemCoreResourceReconcileError;

    fn classify_error(&self, _error: &Self::Error) -> d2b_core_controller::HandlerFailure {
        d2b_core_controller::HandlerFailure::retryable()
    }

    fn describe(&self) -> impl Future<Output = Result<ControllerDescriptor, Self::Error>> + Send {
        std::future::ready(Ok(self.descriptor.clone()))
    }

    fn validate_spec(
        &self,
        _context: &ReconcileContext,
        resource: &ResourceSnapshot,
    ) -> impl Future<Output = Result<ValidationResult, Self::Error>> + Send {
        let valid = (|| {
            let resource_type = Self::resource_type(resource)?;
            let envelope = ResourceEnvelope::from_json(resource.canonical_json())
                .map_err(|_| SystemCoreResourceReconcileError)?;
            match resource_type {
                "Host" => {
                    if envelope.spec().provider_ref().map(|provider| {
                        provider.to_canonical_string() == HOST_PROVIDER_REF
                    }) != Some(true)
                    {
                        return Err(SystemCoreResourceReconcileError);
                    }
                    serde_json::from_slice::<HostSpec>(
                        &envelope.spec().base().to_canonical_bytes(),
                    )
                    .map_err(|_| SystemCoreResourceReconcileError)?;
                }
                "User" => {
                    if envelope.spec().provider_ref().map(|provider| {
                        provider.to_canonical_string() == CORE_CONTROLLER_PROVIDER_REF
                    }) != Some(true)
                    {
                        return Err(SystemCoreResourceReconcileError);
                    }
                    serde_json::from_slice::<UserSpec>(
                        &envelope.spec().base().to_canonical_bytes(),
                    )
                    .map_err(|_| SystemCoreResourceReconcileError)?;
                }
                _ => return Err(SystemCoreResourceReconcileError),
            }
            Ok(())
        })()
        .is_ok();
        std::future::ready(Ok(if valid {
            ValidationResult::Valid
        } else {
            ValidationResult::Invalid {
                reason: ReconcileReason::InvalidSpec,
            }
        }))
    }

    fn plan(
        &self,
        context: &ReconcileContext,
        resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
    ) -> impl Future<Output = Result<ReconcilePlan, Self::Error>> + Send {
        let plan = if resource_status_observed_generation(resource) == Some(resource.generation())
            && !context.reasons().contains(TriggerReason::StartupRelist)
        {
            ReconcilePlan::new(Vec::new(), true)
        } else {
            ReconcilePlan::new(vec!["system-core-observe".to_owned()], false)
        };
        std::future::ready(plan.map_err(|_| SystemCoreResourceReconcileError))
    }

    fn reconcile(
        &self,
        _context: &ReconcileContext,
        resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
        _plan: &ReconcilePlan,
    ) -> impl Future<Output = Result<ReconcileResult, Self::Error>> + Send {
        std::future::ready(Ok(ReconcileResult::converged(
            resource.revision(),
            resource.generation(),
        )))
    }

    fn execute_effect(
        &self,
        _context: &ReconcileContext,
        resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
        _plan: &ReconcilePlan,
    ) -> impl Future<Output = Result<ReconcileResult, Self::Error>> + Send {
        let result = async move {
            let status = Self::status_candidate(resource).await?;
            ReconcileResult::new(
                resource.revision(),
                resource.generation(),
                None,
                Some(status),
                ReconcileDisposition::Pending,
                None,
                None,
                StatusPersistence::Pending,
            )
            .map_err(|_| SystemCoreResourceReconcileError)
        };
        result
    }

    fn observe(
        &self,
        _context: &ReconcileContext,
        resource: &ResourceSnapshot,
    ) -> impl Future<Output = Result<ObservationResult, Self::Error>> + Send {
        std::future::ready(Ok(ObservationResult::new(ReconcileResult::converged(
            resource.revision(),
            resource.generation(),
        ))))
    }

    fn finalize(
        &self,
        _context: &ReconcileContext,
        resource: &ResourceSnapshot,
    ) -> impl Future<Output = Result<FinalizeResult, Self::Error>> + Send {
        std::future::ready(Ok(FinalizeResult::new(ReconcileResult::converged(
            resource.revision(),
            resource.generation(),
        ))))
    }

    fn health(
        &self,
    ) -> impl Future<Output = Result<d2b_core_controller::ControllerHealth, Self::Error>> + Send
    {
        std::future::ready(Ok(d2b_core_controller::ControllerHealth::Healthy))
    }

    fn drain(
        &self,
        _deadline_tick: u64,
    ) -> impl Future<Output = Result<DrainResult, Self::Error>> + Send {
        std::future::ready(Ok(DrainResult::Drained))
    }

    fn assess_update(
        &self,
        _context: &ReconcileContext,
        _resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
    ) -> impl Future<Output = Result<UpdateAssessment, Self::Error>> + Send {
        std::future::ready(
            UpdateAssessment::new(UpdateAssessmentState::Current, Vec::new(), true)
                .map_err(|_| SystemCoreResourceReconcileError),
        )
    }

    fn plan_upgrade(
        &self,
        _context: &ReconcileContext,
        resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
    ) -> impl Future<Output = Result<UpgradePlan, Self::Error>> + Send {
        std::future::ready(
            UpgradePlan::new(
                d2b_core_controller::DisruptionClass::None,
                true,
                vec![UpgradeStage::Recycle(resource.key().resource_ref().clone())],
            )
            .map_err(|_| SystemCoreResourceReconcileError),
        )
    }

    fn execute_upgrade(
        &self,
        _context: &ReconcileContext,
        resource: &ResourceSnapshot,
        _dependencies: &[DependencySnapshot],
        _plan: &UpgradePlan,
    ) -> impl Future<Output = Result<ReconcileResult, Self::Error>> + Send {
        std::future::ready(Ok(ReconcileResult::converged(
            resource.revision(),
            resource.generation(),
        )))
    }
}

fn system_core_resource_descriptor(
    identity: ControllerIdentity,
) -> Result<ControllerDescriptor, ResourceRuntimeError> {
    let host =
        ResourceTypeName::parse("Host").map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
    let user =
        ResourceTypeName::parse("User").map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
    let resources = vec![
        ResourceRegistration::new(host.clone(), vec![1], 5_000, 3)
            .map_err(|_| ResourceRuntimeError::HandlerNotReady)?,
        ResourceRegistration::new(user.clone(), vec![1], 5_000, 3)
            .map_err(|_| ResourceRuntimeError::HandlerNotReady)?,
    ];
    let selectors = [host, user]
        .into_iter()
        .flat_map(|resource_type| {
            [
                ChangeField::Spec,
                ChangeField::Status,
                ChangeField::Metadata,
                ChangeField::Finalizers,
                ChangeField::Deletion,
            ]
            .into_iter()
            .map(move |field| ControllerSelector::new(resource_type.clone(), field, None))
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
    ControllerDescriptor::new(
        identity,
        resources,
        vec!["host".to_owned(), "user".to_owned()],
        vec!["system".to_owned()],
        vec![
            ControllerVerb::ReadSpec,
            ControllerVerb::ReadStatus,
            ControllerVerb::WriteStatus,
        ],
        selectors,
        Vec::new(),
        false,
        Vec::new(),
        vec!["d2b.system-core.v3".to_owned()],
        vec!["resources.d2bus.org/v3".to_owned()],
        ControllerExecutionPolicy::new(
            8,
            8,
            256,
            8,
            256,
            ResyncPolicy::new(None, 5_000).map_err(|_| ResourceRuntimeError::HandlerNotReady)?,
        )
        .map_err(|_| ResourceRuntimeError::HandlerNotReady)?,
    )
    .map_err(|_| ResourceRuntimeError::HandlerNotReady)
}

async fn system_core_startup_result(
    zone: &ZoneId,
    store: &RedbResourceStore,
) -> Result<SystemCoreReconcileResult, ResourceRuntimeError> {
    let mut resources = Vec::new();
    let mut cursor = None;
    loop {
        let page = store
            .list(StoreListRequest {
                operation: StoreOperationContext {
                    operation_id: "system-core-startup-summary".to_owned(),
                    idempotency_key: None,
                    correlation_id: "system-core-startup-summary".to_owned(),
                    trace_id: None,
                    deadline_ms: 10_000,
                },
                zone: zone.clone(),
                resource_types: Vec::new(),
                resource_names: Vec::new(),
                filters: Vec::new(),
                page_size: 128,
                cursor,
                projection: StoreProjection::Full,
            })
            .await
            .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;
        resources.extend(page.resources);
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    let total_resource_count = resources.len().min(u32::MAX as usize) as u32;
    let active_configuration_generation = store
        .runtime_metadata()
        .await
        .map_err(|_| ResourceRuntimeError::StoreReadFailed)?
        .policy_snapshot
        .active_configuration_revision
        .get();
    let cleanup_pending_count = resources
        .iter()
        .filter(|resource| configuration_cleanup_pending(resource, active_configuration_generation))
        .count()
        .min(u32::MAX as usize) as u32;
    // Startup readiness is established by the already authenticated Core
    // session; the shared runner immediately replaces this provisional
    // projection with persisted Host/User observations.
    Ok(SystemCoreReconcileResult {
        core_phase: ResourcePhase::Ready,
        host_phase: HandlerPhase::Ready,
        user_phase: HandlerPhase::Ready,
        total_resource_count,
        generation_cleanup_pending: cleanup_pending_count > 0,
        cleanup_pending_count,
    })
}

fn host_status_value(
    report: &HostObservationReport,
) -> Result<serde_json::Value, ResourceRuntimeError> {
    let mut status =
        serde_json::to_value(&report.status).map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
    let object = status
        .as_object_mut()
        .ok_or(ResourceRuntimeError::HandlerNotReady)?;
    object.insert(
        "capabilities".to_owned(),
        serde_json::to_value(&report.capabilities)
            .map_err(|_| ResourceRuntimeError::HandlerNotReady)?,
    );
    object.insert(
        "kernelRelease".to_owned(),
        serde_json::Value::String(report.kernel_release.clone()),
    );
    object.insert(
        "osName".to_owned(),
        serde_json::Value::String(report.os_name.clone()),
    );
    object.insert(
        "userManagerAvailable".to_owned(),
        serde_json::Value::Bool(report.user_manager_available),
    );
    object.insert(
        "activeProcessCount".to_owned(),
        serde_json::Value::Number(report.active_process_count.into()),
    );
    object.insert(
        "minijailReady".to_owned(),
        serde_json::Value::Bool(report.minijail_ready),
    );
    Ok(status)
}

fn map_audio_runtime_error(error: AudioResourceRuntimeError) -> ResourceRuntimeError {
    match error {
        AudioResourceRuntimeError::Controller(_) => ResourceRuntimeError::CapabilityUnavailable,
        AudioResourceRuntimeError::InvalidResource
        | AudioResourceRuntimeError::InvalidRelationship => {
            ResourceRuntimeError::CapabilityUnavailable
        }
    }
}

fn map_process_runtime_error(error: ProcessResourceRuntimeError) -> ResourceRuntimeError {
    match error {
        ProcessResourceRuntimeError::Store => ResourceRuntimeError::StoreReadFailed,
        ProcessResourceRuntimeError::UnsupportedProvider
        | ProcessResourceRuntimeError::TemplateUnavailable
        | ProcessResourceRuntimeError::IdentityAmbiguous
        | ProcessResourceRuntimeError::ProviderEffect
        | ProcessResourceRuntimeError::ProviderIdentityUnavailable
        | ProcessResourceRuntimeError::InvalidResource => {
            ResourceRuntimeError::CapabilityUnavailable
        }
    }
}

fn process_assignment_fence_resolver(
    store: Arc<RedbResourceStore>,
    mode: DaemonMode,
    controller_role: ResourceRef,
    session_generation: ReconnectGeneration,
    epoch: Arc<AtomicU64>,
) -> AssignmentFenceResolver {
    Arc::new(move |target, uid, revision| {
        let store = Arc::clone(&store);
        let controller_role = controller_role.clone();
        let epoch = Arc::clone(&epoch);
        Box::pin(async move {
            let resource = store
                .get(StoreGetRequest {
                    operation: StoreOperationContext {
                        operation_id: "process-assignment-fence".to_owned(),
                        idempotency_key: None,
                        correlation_id: "process-assignment-fence".to_owned(),
                        trace_id: None,
                        deadline_ms: 10_000,
                    },
                    zone: store.identity().zone().clone(),
                    target: target.clone(),
                    expected_uid: Some(uid.clone()),
                    projection: StoreProjection::Full,
                })
                .await
                .map_err(|error| match error.kind() {
                    StoreErrorKind::Backpressure | StoreErrorKind::StoreBackpressure => {
                        SourceError::Backpressure
                    }
                    StoreErrorKind::Timeout => SourceError::Timeout,
                    StoreErrorKind::ResourceConflict => {
                        SourceError::Conflict(error.current_revision().unwrap_or(revision))
                    }
                    _ => SourceError::Unavailable,
                })?;
            if resource.revision != revision {
                return Err(SourceError::Conflict(resource.revision));
            }
            let envelope = ResourceEnvelope::from_json(&resource.canonical_json)
                .map_err(|_| SourceError::Integrity)?;
            let provider_ref = envelope
                .spec()
                .provider_ref()
                .cloned()
                .ok_or(SourceError::Integrity)?;
            if !matches!(
                provider_ref.name().as_str(),
                "system-minijail" | "system-systemd"
            ) {
                return Err(SourceError::Integrity);
            }
            let execution_ref = envelope
                .spec()
                .base()
                .get("executionRef")
                .and_then(|value| match value {
                    CanonicalJsonValue::String(value) => ResourceRef::parse(value).ok(),
                    _ => None,
                })
                .ok_or(SourceError::Integrity)?;
            let expected_target = match mode {
                DaemonMode::Host => "Host",
                DaemonMode::Guest => "Guest",
            };
            if execution_ref.resource_type().as_str() != expected_target {
                return Err(SourceError::Integrity);
            }
            let provider = store
                .get(StoreGetRequest {
                    operation: StoreOperationContext {
                        operation_id: "process-assignment-provider".to_owned(),
                        idempotency_key: None,
                        correlation_id: "process-assignment-provider".to_owned(),
                        trace_id: None,
                        deadline_ms: 10_000,
                    },
                    zone: store.identity().zone().clone(),
                    target: provider_ref,
                    expected_uid: None,
                    projection: StoreProjection::MetadataOnly,
                })
                .await
                .map_err(|_| SourceError::Integrity)?;
            let controller_generation = store
                .runtime_metadata()
                .await
                .map_err(|_| SourceError::Unavailable)?
                .policy_snapshot
                .controller_generation
                .ok_or(SourceError::Integrity)?;
            let assignment_epoch = epoch.load(Ordering::Acquire);
            if assignment_epoch == 0 {
                return Err(SourceError::Integrity);
            }
            Ok(ResourceAssignmentFence {
                resource_uid: uid,
                resource_revision: revision,
                provider_generation: provider.generation,
                controller_generation,
                controller_role,
                target: execution_ref,
                session_generation,
                epoch: assignment_epoch,
                scope: ResourceAssignmentScope::Primary,
            })
        })
    })
}

fn system_core_assignment_fence_resolver(
    store: Arc<RedbResourceStore>,
    controller_role: ResourceRef,
    session_generation: ReconnectGeneration,
    epoch: Arc<AtomicU64>,
) -> AssignmentFenceResolver {
    Arc::new(move |target, uid, revision| {
        let store = Arc::clone(&store);
        let controller_role = controller_role.clone();
        let epoch = Arc::clone(&epoch);
        Box::pin(async move {
            let resource = store
                .get(StoreGetRequest {
                    operation: StoreOperationContext {
                        operation_id: "system-core-assignment-fence".to_owned(),
                        idempotency_key: None,
                        correlation_id: "system-core-assignment-fence".to_owned(),
                        trace_id: None,
                        deadline_ms: 10_000,
                    },
                    zone: store.identity().zone().clone(),
                    target: target.clone(),
                    expected_uid: Some(uid.clone()),
                    projection: StoreProjection::Full,
                })
                .await
                .map_err(|_| SourceError::Unavailable)?;
            if resource.revision != revision
                || !matches!(
                    resource.resource_ref.resource_type().as_str(),
                    "Host" | "User"
                )
            {
                return Err(SourceError::Conflict(resource.revision));
            }
            let envelope = ResourceEnvelope::from_json(&resource.canonical_json)
                .map_err(|_| SourceError::Integrity)?;
            if let Some(provider_ref) = envelope.spec().provider_ref()
                && provider_ref.to_canonical_string() != "Provider/system-core"
            {
                return Err(SourceError::Integrity);
            }
            let provider_ref =
                ResourceRef::parse("Provider/system-core").map_err(|_| SourceError::Integrity)?;
            let provider = store
                .get(StoreGetRequest {
                    operation: StoreOperationContext {
                        operation_id: "system-core-assignment-provider".to_owned(),
                        idempotency_key: None,
                        correlation_id: "system-core-assignment-provider".to_owned(),
                        trace_id: None,
                        deadline_ms: 10_000,
                    },
                    zone: store.identity().zone().clone(),
                    target: provider_ref,
                    expected_uid: None,
                    projection: StoreProjection::MetadataOnly,
                })
                .await
                .map_err(|_| SourceError::Integrity)?;
            let controller_generation = store
                .runtime_metadata()
                .await
                .map_err(|_| SourceError::Unavailable)?
                .policy_snapshot
                .controller_generation
                .ok_or(SourceError::Integrity)?;
            let assignment_epoch = epoch.load(Ordering::Acquire);
            if assignment_epoch == 0 {
                return Err(SourceError::Integrity);
            }
            Ok(ResourceAssignmentFence {
                resource_uid: uid,
                resource_revision: revision,
                provider_generation: provider.generation,
                controller_generation,
                controller_role,
                target: ResourceRef::parse(CORE_CONTROLLER_HOST_REF)
                    .map_err(|_| SourceError::Integrity)?,
                session_generation,
                epoch: assignment_epoch,
                scope: ResourceAssignmentScope::Primary,
            })
        })
    })
}

async fn public_create_request(
    runtime: &ZoneResourceRuntime,
    request: &Value,
    operation_id: &str,
) -> Result<wire::CreateRequest, ResourceRuntimeError> {
    let resource_type = request
        .get("resourceType")
        .and_then(Value::as_str)
        .ok_or(ResourceRuntimeError::RequestInvalid)
        .and_then(|value| {
            ResourceTypeName::parse(value.to_owned())
                .map_err(|_| ResourceRuntimeError::RequestInvalid)
        })?;
    let input = request
        .get("resource")
        .or_else(|| request.get("spec"))
        .ok_or(ResourceRuntimeError::RequestInvalid)?;
    let (name, spec) = if is_resource_envelope(input) {
        let name = input
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .ok_or(ResourceRuntimeError::RequestInvalid)?;
        let spec = input
            .get("spec")
            .cloned()
            .ok_or(ResourceRuntimeError::RequestInvalid)?;
        (name.to_owned(), spec)
    } else {
        let name = request
            .get("resourceName")
            .and_then(Value::as_str)
            .or_else(|| {
                input
                    .get("metadata")
                    .and_then(|value| value.get("name"))
                    .and_then(Value::as_str)
            })
            .ok_or(ResourceRuntimeError::RequestInvalid)?;
        (name.to_owned(), input.clone())
    };
    let payload = public_create_payload(
        runtime,
        &resource_type,
        &name,
        &spec,
        request.get("ownerRef").and_then(Value::as_str),
    )
    .await?;
    let identity = public_identity(runtime, &resource_type, &name, None, None, None);
    let mut mutation = wire::Mutation::new();
    mutation.kind = protobuf::EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_CREATE);
    mutation.target = protobuf::MessageField::some(identity.clone());
    mutation.precondition = protobuf::MessageField::some(create_precondition());
    mutation.resource = protobuf::MessageField::some(public_resource_body(identity, payload)?);
    apply_public_mutation_options(&mut mutation, request)?;
    let mut result = wire::CreateRequest::new();
    result.meta = protobuf::MessageField::some(public_request_meta(operation_id));
    result.mutation = protobuf::MessageField::some(mutation);
    Ok(result)
}

async fn public_update_spec_request(
    client: &ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>,
    runtime: &ZoneResourceRuntime,
    request: &Value,
    operation_id: &str,
) -> Result<wire::UpdateSpecRequest, ResourceRuntimeError> {
    let target = public_target_ref(request)?;
    let current = public_get_resource(client, runtime, &target, operation_id).await?;
    public_update_spec_request_from_current(runtime, request, operation_id, &target, current)
}

fn public_update_spec_request_from_current(
    runtime: &ZoneResourceRuntime,
    request: &Value,
    operation_id: &str,
    target: &ResourceRef,
    current: Value,
) -> Result<wire::UpdateSpecRequest, ResourceRuntimeError> {
    let spec = request
        .get("spec")
        .cloned()
        .ok_or(ResourceRuntimeError::RequestInvalid)?;
    let payload = replace_public_field(&current, "spec", spec)?;
    let current_uid = public_uid(&current)?;
    let current_revision = public_revision(&current)?;
    let expected_revision = public_expected_revision(request)?.unwrap_or(current_revision);
    let identity = public_identity(
        runtime,
        target.resource_type(),
        target.name().as_str(),
        Some(&current_uid),
        Some(public_generation(&current)?),
        Some(expected_revision),
    );
    let mut mutation = public_body_mutation(
        wire::MutationKind::MUTATION_KIND_UPDATE_SPEC,
        identity,
        exact_public_precondition(expected_revision, &current_uid),
        payload,
    )?;
    apply_public_mutation_options(&mut mutation, request)?;
    let mut result = wire::UpdateSpecRequest::new();
    result.meta = protobuf::MessageField::some(public_request_meta(operation_id));
    result.mutation = protobuf::MessageField::some(mutation);
    Ok(result)
}

async fn public_update_status_request(
    client: &ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>,
    runtime: &ZoneResourceRuntime,
    request: &Value,
    operation_id: &str,
) -> Result<wire::UpdateStatusRequest, ResourceRuntimeError> {
    let target = public_target_ref(request)?;
    let current = public_get_resource(client, runtime, &target, operation_id).await?;
    public_update_status_request_from_current(runtime, request, operation_id, &target, current)
}

fn public_update_status_request_from_current(
    runtime: &ZoneResourceRuntime,
    request: &Value,
    operation_id: &str,
    target: &ResourceRef,
    current: Value,
) -> Result<wire::UpdateStatusRequest, ResourceRuntimeError> {
    let status = request
        .get("status")
        .cloned()
        .or_else(|| {
            request
                .get("resource")
                .and_then(|value| value.get("status"))
                .cloned()
        })
        .ok_or(ResourceRuntimeError::RequestInvalid)?;
    let payload = replace_public_field(&current, "status", status)?;
    let current_uid = public_uid(&current)?;
    let current_revision = public_revision(&current)?;
    let expected_revision = public_expected_revision(request)?.unwrap_or(current_revision);
    let identity = public_identity(
        runtime,
        target.resource_type(),
        target.name().as_str(),
        Some(&current_uid),
        Some(public_generation(&current)?),
        Some(expected_revision),
    );
    let mutation = public_body_mutation(
        wire::MutationKind::MUTATION_KIND_UPDATE_STATUS,
        identity,
        exact_public_precondition(expected_revision, &current_uid),
        payload,
    )?;
    let mut result = wire::UpdateStatusRequest::new();
    result.meta = protobuf::MessageField::some(public_request_meta(operation_id));
    result.mutation = protobuf::MessageField::some(mutation);
    Ok(result)
}

fn public_update_finalizers_request(
    runtime: &ZoneResourceRuntime,
    request: &Value,
    operation_id: &str,
) -> Result<wire::UpdateFinalizersRequest, ResourceRuntimeError> {
    let target = public_target_ref(request)?;
    let uid = request
        .get("uid")
        .and_then(Value::as_str)
        .map(|value| ResourceUid::parse(value.to_owned()))
        .transpose()
        .map_err(|_| ResourceRuntimeError::RequestInvalid)?;
    let expected_revision =
        public_expected_revision(request)?.ok_or(ResourceRuntimeError::RequestInvalid)?;
    let uid = uid.ok_or(ResourceRuntimeError::RequestInvalid)?;
    let identity = public_identity(
        runtime,
        target.resource_type(),
        target.name().as_str(),
        Some(&uid),
        None,
        Some(expected_revision),
    );
    let mut mutation = wire::Mutation::new();
    mutation.kind =
        protobuf::EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_UPDATE_FINALIZERS);
    mutation.target = protobuf::MessageField::some(identity);
    mutation.precondition =
        protobuf::MessageField::some(exact_public_precondition(expected_revision, &uid));
    mutation.add_finalizers = public_string_array(request, "addFinalizers")?;
    mutation.remove_finalizers = public_string_array(request, "removeFinalizers")?;
    if mutation.add_finalizers.is_empty() && mutation.remove_finalizers.is_empty() {
        return Err(ResourceRuntimeError::RequestInvalid);
    }
    let mut result = wire::UpdateFinalizersRequest::new();
    result.meta = protobuf::MessageField::some(public_request_meta(operation_id));
    result.mutation = protobuf::MessageField::some(mutation);
    Ok(result)
}

async fn public_delete_request(
    runtime: &ZoneResourceRuntime,
    request: &Value,
    operation_id: &str,
) -> Result<wire::DeleteRequest, ResourceRuntimeError> {
    let target = public_target_ref(request)?;
    let expected_revision = public_expected_revision(request)?;
    let mut uid = request
        .get("uid")
        .and_then(Value::as_str)
        .map(|value| ResourceUid::parse(value.to_owned()))
        .transpose()
        .map_err(|_| ResourceRuntimeError::RequestInvalid)?;
    if uid.is_none() && expected_revision.is_some() {
        let current = runtime
            .committed_resource_value(&target, "public-delete-uid")
            .await?;
        uid = Some(public_uid(&current)?);
    }
    let identity = public_identity(
        runtime,
        target.resource_type(),
        target.name().as_str(),
        uid.as_ref(),
        None,
        expected_revision,
    );
    let mut mutation = wire::Mutation::new();
    mutation.kind = protobuf::EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_DELETE);
    mutation.target = protobuf::MessageField::some(identity.clone());
    let precondition = match expected_revision {
        Some(revision) => {
            let uid = uid.ok_or(ResourceRuntimeError::RequestInvalid)?;
            exact_public_precondition(revision, &uid)
        }
        None => {
            let mut precondition = wire::Precondition::new();
            precondition.kind = protobuf::EnumOrUnknown::new(
                wire::PreconditionKind::PRECONDITION_KIND_EXACT_REVISION,
            );
            precondition.expected_revision = Some(1);
            precondition
        }
    };
    mutation.precondition = protobuf::MessageField::some(precondition);
    apply_public_mutation_options(&mut mutation, request)?;
    let mut result = wire::DeleteRequest::new();
    result.meta = protobuf::MessageField::some(public_request_meta(operation_id));
    result.mutation = protobuf::MessageField::some(mutation);
    Ok(result)
}

fn public_target_ref(request: &Value) -> Result<ResourceRef, ResourceRuntimeError> {
    request
        .get("resourceRef")
        .and_then(Value::as_str)
        .ok_or(ResourceRuntimeError::RequestInvalid)
        .and_then(|value| {
            ResourceRef::parse(value).map_err(|_| ResourceRuntimeError::RequestInvalid)
        })
}

fn public_expected_revision(request: &Value) -> Result<Option<u64>, ResourceRuntimeError> {
    let Some(value) = request.get("expectedRevision") else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let value = value
        .as_u64()
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
        .filter(|value| *value > 0)
        .ok_or(ResourceRuntimeError::RequestInvalid)?;
    Ok(Some(value))
}

fn public_uid(resource: &Value) -> Result<ResourceUid, ResourceRuntimeError> {
    resource
        .pointer("/metadata/uid")
        .and_then(Value::as_str)
        .ok_or(ResourceRuntimeError::ResponseInvalid)
        .and_then(|value| {
            ResourceUid::parse(value.to_owned()).map_err(|_| ResourceRuntimeError::ResponseInvalid)
        })
}

fn public_revision(resource: &Value) -> Result<u64, ResourceRuntimeError> {
    resource
        .pointer("/metadata/revision")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or(ResourceRuntimeError::ResponseInvalid)
}

fn public_generation(resource: &Value) -> Result<u64, ResourceRuntimeError> {
    resource
        .pointer("/metadata/generation")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or(ResourceRuntimeError::ResponseInvalid)
}

async fn public_get_resource(
    client: &ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>,
    runtime: &ZoneResourceRuntime,
    target: &ResourceRef,
    operation_id: &str,
) -> Result<Value, ResourceRuntimeError> {
    let mut meta = public_request_meta(operation_id);
    meta.deadline_ms = 30_000;
    let response = client
        .get(wire::GetRequest {
            meta: protobuf::MessageField::some(meta),
            target: protobuf::MessageField::some(public_identity(
                runtime,
                target.resource_type(),
                target.name().as_str(),
                None,
                None,
                None,
            )),
            projection: {
                let mut projection = wire::Projection::new();
                projection.kind =
                    protobuf::EnumOrUnknown::new(wire::ProjectionKind::PROJECTION_KIND_FULL);
                protobuf::MessageField::some(projection)
            },
            special_fields: protobuf::SpecialFields::new(),
        })
        .await;
    if response.error.is_some() {
        return Err(ResourceRuntimeError::RequestInvalid);
    }
    let resource = response
        .resource
        .as_ref()
        .ok_or(ResourceRuntimeError::ResponseInvalid)?;
    encode_public_resource(resource)
}

async fn gateway_get_resource(
    client: &d2b_resource_api::generated::d2b_resource_v3_ttrpc::ResourceServiceClient,
    runtime: &ZoneResourceRuntime,
    target: &ResourceRef,
    operation_id: &str,
) -> Result<Value, ResourceRuntimeError> {
    let mut meta = public_request_meta(operation_id);
    meta.deadline_ms = 30_000;
    let response = client
        .get(
            ttrpc::context::Context::default(),
            &wire::GetRequest {
                meta: protobuf::MessageField::some(meta),
                target: protobuf::MessageField::some(public_identity(
                    runtime,
                    target.resource_type(),
                    target.name().as_str(),
                    None,
                    None,
                    None,
                )),
                projection: {
                    let mut projection = wire::Projection::new();
                    projection.kind =
                        protobuf::EnumOrUnknown::new(wire::ProjectionKind::PROJECTION_KIND_FULL);
                    protobuf::MessageField::some(projection)
                },
                special_fields: protobuf::SpecialFields::new(),
            },
        )
        .await
        .map_err(|_| ResourceRuntimeError::ProviderPathUnavailable)?;
    d2bd_runtime::resource_runtime_support::encode_public_get_response(response)
}

fn public_identity(
    runtime: &ZoneResourceRuntime,
    resource_type: &ResourceTypeName,
    name: &str,
    uid: Option<&ResourceUid>,
    generation: Option<u64>,
    revision: Option<u64>,
) -> wire::ResourceIdentity {
    wire::ResourceIdentity {
        zone: runtime.zone.to_canonical_string(),
        resource_type: resource_type.to_canonical_string(),
        name: name.to_owned(),
        uid: uid.map(|value| value.as_str().to_owned()),
        generation,
        revision,
        special_fields: protobuf::SpecialFields::new(),
    }
}

fn create_precondition() -> wire::Precondition {
    let mut precondition = wire::Precondition::new();
    precondition.kind =
        protobuf::EnumOrUnknown::new(wire::PreconditionKind::PRECONDITION_KIND_CREATE_ABSENT);
    precondition
}

fn exact_public_precondition(revision: u64, uid: &ResourceUid) -> wire::Precondition {
    let mut precondition = wire::Precondition::new();
    precondition.kind =
        protobuf::EnumOrUnknown::new(wire::PreconditionKind::PRECONDITION_KIND_EXACT_REVISION);
    precondition.expected_revision = Some(revision);
    precondition.expected_uid = Some(uid.as_str().to_owned());
    precondition
}

fn public_body_mutation(
    kind: wire::MutationKind,
    identity: wire::ResourceIdentity,
    precondition: wire::Precondition,
    payload: Vec<u8>,
) -> Result<wire::Mutation, ResourceRuntimeError> {
    let mut mutation = wire::Mutation::new();
    mutation.kind = protobuf::EnumOrUnknown::new(kind);
    mutation.target = protobuf::MessageField::some(identity.clone());
    mutation.precondition = protobuf::MessageField::some(precondition);
    mutation.resource = protobuf::MessageField::some(public_resource_body(identity, payload)?);
    Ok(mutation)
}

fn public_resource_body(
    identity: wire::ResourceIdentity,
    payload: Vec<u8>,
) -> Result<wire::ResourceEnvelopeBytes, ResourceRuntimeError> {
    let envelope =
        ResourceEnvelope::from_json(&payload).map_err(|_| ResourceRuntimeError::RequestInvalid)?;
    let digest = envelope
        .digest()
        .map_err(|_| ResourceRuntimeError::RequestInvalid)?;
    let mut body = wire::ResourceEnvelopeBytes::new();
    body.identity = protobuf::MessageField::some(identity);
    body.canonical_json = payload;
    body.payload_digest = digest;
    Ok(body)
}

fn apply_public_mutation_options(
    mutation: &mut wire::Mutation,
    request: &Value,
) -> Result<(), ResourceRuntimeError> {
    mutation.wait_for_reconcile = request
        .get("waitForReconcile")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    mutation.reconcile_deadline_ms = request
        .get("reconcileDeadlineMs")
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
        })
        .unwrap_or(0);
    if !mutation.wait_for_reconcile && mutation.reconcile_deadline_ms != 0 {
        return Err(ResourceRuntimeError::RequestInvalid);
    }
    Ok(())
}

fn public_string_array(request: &Value, field: &str) -> Result<Vec<String>, ResourceRuntimeError> {
    let Some(value) = request.get(field) else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .ok_or(ResourceRuntimeError::RequestInvalid)?;
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or(ResourceRuntimeError::RequestInvalid)
        })
        .collect()
}

fn is_resource_envelope(value: &Value) -> bool {
    value.get("metadata").is_some()
        && value.get("spec").is_some()
        && (value.get("type").is_some() || value.get("apiVersion").is_some())
}

async fn public_create_payload(
    runtime: &ZoneResourceRuntime,
    resource_type: &ResourceTypeName,
    name: &str,
    spec: &Value,
    owner_ref: Option<&str>,
) -> Result<Vec<u8>, ResourceRuntimeError> {
    let metadata = runtime
        .store
        .runtime_metadata()
        .await
        .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;
    let timestamp = current_status_timestamp();
    let value = json!({
        "apiVersion": "resources.d2bus.org/v3",
        "type": resource_type.to_canonical_string(),
        "metadata": {
            "configurationGeneration": metadata.policy_snapshot.active_configuration_revision.get(),
            "createdAt": timestamp,
            "deletionRequestedAt": null,
            "finalizers": [],
            "generation": 1,
            "managedBy": "api",
            "name": name,
            "ownerRef": owner_ref,
            "revision": 1,
            "updatedAt": timestamp,
            "zone": runtime.zone.as_str()
        },
        "spec": spec,
        "status": {
            "completedAt": null,
            "conditions": [],
            "lastReconciledAt": null,
            "observedGeneration": 0,
            "outcome": null,
            "phase": "Pending",
            "resource": {},
            "startedAt": null,
            "update": {
                "dependencies": {"count": 0, "refs": []},
                "disruption": "None",
                "lastAssessedAt": 0,
                "observedGeneration": 0,
                "operationId": null,
                "owned": {"count": 0, "refs": []},
                "preserveState": true,
                "reasons": [],
                "state": "Unknown",
                "targetGeneration": 1
            }
        }
    });
    if value.get("spec").and_then(Value::as_object).is_none() {
        return Err(ResourceRuntimeError::RequestInvalid);
    }
    let bytes = serde_json::to_vec(&value).map_err(|_| ResourceRuntimeError::RequestInvalid)?;
    let canonical = CanonicalJsonValue::parse(&bytes)
        .map_err(|_| ResourceRuntimeError::RequestInvalid)?
        .to_canonical_bytes();
    ResourceEnvelope::from_json(&canonical).map_err(|_| ResourceRuntimeError::RequestInvalid)?;
    Ok(canonical)
}

fn replace_public_field(
    current: &Value,
    field: &str,
    replacement: Value,
) -> Result<Vec<u8>, ResourceRuntimeError> {
    let mut value = current.clone();
    value
        .as_object_mut()
        .and_then(|root| root.get_mut(field))
        .map(|field_value| *field_value = replacement)
        .ok_or(ResourceRuntimeError::RequestInvalid)?;
    let bytes = serde_json::to_vec(&value).map_err(|_| ResourceRuntimeError::RequestInvalid)?;
    let canonical = CanonicalJsonValue::parse(&bytes)
        .map_err(|_| ResourceRuntimeError::RequestInvalid)?
        .to_canonical_bytes();
    ResourceEnvelope::from_json(&canonical).map_err(|_| ResourceRuntimeError::RequestInvalid)?;
    Ok(canonical)
}

fn encode_public_create_response(
    response: wire::CreateResponse,
) -> Result<Value, ResourceRuntimeError> {
    encode_public_mutation_response(
        response.error.as_ref(),
        response.resource.as_ref(),
        None,
        response.revision,
        Some(
            response
                .disposition
                .enum_value()
                .unwrap_or(wire::ReconcileDisposition::RECONCILE_DISPOSITION_UNSPECIFIED),
        ),
        Some(
            response
                .status_persistence
                .enum_value()
                .unwrap_or(wire::StatusPersistence::STATUS_PERSISTENCE_UNSPECIFIED),
        ),
        response.last_persisted_status_revision,
        response.reconcile_projection.as_ref(),
    )
}

fn encode_public_update_spec_response(
    response: wire::UpdateSpecResponse,
) -> Result<Value, ResourceRuntimeError> {
    encode_public_mutation_response(
        response.error.as_ref(),
        response.resource.as_ref(),
        None,
        response.revision,
        Some(
            response
                .disposition
                .enum_value()
                .unwrap_or(wire::ReconcileDisposition::RECONCILE_DISPOSITION_UNSPECIFIED),
        ),
        Some(
            response
                .status_persistence
                .enum_value()
                .unwrap_or(wire::StatusPersistence::STATUS_PERSISTENCE_UNSPECIFIED),
        ),
        response.last_persisted_status_revision,
        response.reconcile_projection.as_ref(),
    )
}

fn encode_public_update_status_response(
    response: wire::UpdateStatusResponse,
) -> Result<Value, ResourceRuntimeError> {
    encode_public_mutation_response(
        response.error.as_ref(),
        response.resource.as_ref(),
        None,
        response.revision,
        None,
        None,
        None,
        None,
    )
}

fn encode_public_update_finalizers_response(
    response: wire::UpdateFinalizersResponse,
) -> Result<Value, ResourceRuntimeError> {
    encode_public_mutation_response(
        response.error.as_ref(),
        response.resource.as_ref(),
        None,
        response.revision,
        None,
        None,
        None,
        None,
    )
}

fn encode_public_delete_response(
    response: wire::DeleteResponse,
) -> Result<Value, ResourceRuntimeError> {
    encode_public_mutation_response(
        response.error.as_ref(),
        None,
        response.resource.as_ref(),
        response.revision,
        Some(
            response
                .disposition
                .enum_value()
                .unwrap_or(wire::ReconcileDisposition::RECONCILE_DISPOSITION_UNSPECIFIED),
        ),
        None,
        None,
        None,
    )
}

fn encode_public_mutation_response(
    error: Option<&wire::ResourceError>,
    resource: Option<&wire::ResourceEnvelopeBytes>,
    identity: Option<&wire::ResourceIdentity>,
    revision: u64,
    disposition: Option<wire::ReconcileDisposition>,
    status_persistence: Option<wire::StatusPersistence>,
    last_persisted_status_revision: Option<u64>,
    reconcile_projection: Option<&wire::ResourceEnvelopeBytes>,
) -> Result<Value, ResourceRuntimeError> {
    if let Some(error) = error {
        tracing::warn!(
            kind = ?error.kind,
            retry_class = ?error.retry_class,
            retry_after_ms = ?error.retry_after_ms,
            reason = %error.reason,
            "public Resource mutation returned an API error",
        );
        return Ok(d2bd_runtime::resource_runtime_support::public_api_error(
            error,
        ));
    }
    let mut body = serde_json::Map::new();
    if let Some(resource) = resource {
        body.insert("resource".to_owned(), encode_public_resource(resource)?);
    }
    if let Some(identity) = identity {
        body.insert(
            "resourceRef".to_owned(),
            Value::String(format!("{}/{}", identity.resource_type, identity.name)),
        );
    }
    body.insert("revision".to_owned(), Value::from(revision));
    if let Some(disposition) = disposition
        .filter(|value| *value != wire::ReconcileDisposition::RECONCILE_DISPOSITION_UNSPECIFIED)
    {
        body.insert(
            "disposition".to_owned(),
            Value::String(
                match disposition {
                    wire::ReconcileDisposition::RECONCILE_DISPOSITION_CONVERGED => "Converged",
                    wire::ReconcileDisposition::RECONCILE_DISPOSITION_PROGRESSING => "Progressing",
                    wire::ReconcileDisposition::RECONCILE_DISPOSITION_BLOCKED => "Blocked",
                    wire::ReconcileDisposition::RECONCILE_DISPOSITION_UPGRADE_REQUIRED => {
                        "UpgradeRequired"
                    }
                    wire::ReconcileDisposition::RECONCILE_DISPOSITION_FAILED => "Failed",
                    wire::ReconcileDisposition::RECONCILE_DISPOSITION_UNSPECIFIED => "Unspecified",
                }
                .to_owned(),
            ),
        );
    }
    if let Some(status_persistence) = status_persistence
        .filter(|value| *value != wire::StatusPersistence::STATUS_PERSISTENCE_UNSPECIFIED)
    {
        body.insert(
            "statusPersistence".to_owned(),
            Value::String(
                match status_persistence {
                    wire::StatusPersistence::STATUS_PERSISTENCE_PENDING => "pending",
                    wire::StatusPersistence::STATUS_PERSISTENCE_COMMITTED => "committed",
                    wire::StatusPersistence::STATUS_PERSISTENCE_UNSPECIFIED => "unspecified",
                }
                .to_owned(),
            ),
        );
    }
    if let Some(revision) = last_persisted_status_revision {
        body.insert(
            "lastPersistedStatusRevision".to_owned(),
            Value::from(revision),
        );
    }
    if let Some(projection) = reconcile_projection {
        body.insert(
            "reconcileProjection".to_owned(),
            encode_public_resource(projection)?,
        );
    }
    Ok(Value::Object(body))
}

/// Root-supervisor ownership index for all local Network host effects.
///
/// The index is shared by every Zone runtime in one daemon. Callers must
/// observe the host before admission; the index itself only commits a
/// candidate after every CIDR, interface, and route collision check passes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct NetworkAdmissionOwnerKey {
    zone_uid: ResourceUid,
    network_uid: ResourceUid,
}

impl NetworkAdmissionOwnerKey {
    fn from_key(key: &NetworkAdmissionKey) -> Self {
        Self {
            zone_uid: key.zone_uid().clone(),
            network_uid: key.network_uid().clone(),
        }
    }
}

#[derive(Default)]
pub struct HostNetworkAdmissionIndex {
    entries: BTreeMap<NetworkAdmissionOwnerKey, NetworkAdmissionIntent>,
    retired: BTreeMap<NetworkAdmissionOwnerKey, BTreeSet<NetworkAdmissionKey>>,
    released_floors: BTreeMap<NetworkAdmissionOwnerKey, (u64, u64)>,
}

fn route_conflicts(desired: &RouteTuple, occupied: &RouteTuple) -> bool {
    if desired.table() != occupied.table() {
        return false;
    }
    if desired.destination() == occupied.destination() {
        return true;
    }
    let Some(desired_cidr) =
        d2b_contracts_resource::v3::network::Ipv4Cidr::parse(desired.destination().to_owned()).ok()
    else {
        return false;
    };
    let Some(occupied_cidr) =
        d2b_contracts_resource::v3::network::Ipv4Cidr::parse(occupied.destination().to_owned())
            .ok()
    else {
        return false;
    };
    d2b_contracts_resource::v3::network::cidr_overlaps(&desired_cidr, &occupied_cidr)
}

impl core::fmt::Debug for HostNetworkAdmissionIndex {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("HostNetworkAdmissionIndex")
            .field("entry_count", &self.entries.len())
            .finish()
    }
}

impl HostNetworkAdmissionIndex {
    /// Admit one Network atomically against the observed host and siblings.
    pub fn admit(
        &mut self,
        intent: NetworkAdmissionIntent,
        occupancy: &HostNetworkOccupancy,
    ) -> Result<NetworkAdmissionProof, NetworkEffectError> {
        let key = intent.key().clone();
        let owner = NetworkAdmissionOwnerKey::from_key(&key);
        if self
            .retired
            .get(&owner)
            .is_some_and(|retired| retired.contains(&key))
        {
            return Err(NetworkEffectError::NetworkAdmissionMismatch);
        }
        if !self.entries.contains_key(&owner)
            && self.released_floors.get(&owner).is_some_and(|floor| {
                key.network_generation().get() < floor.0
                    || key.attachment_generation().get() < floor.1
            })
        {
            return Err(NetworkEffectError::NetworkAdmissionMismatch);
        }
        let existing = self.entries.get(&owner).cloned();
        if let Some(current) = existing.as_ref() {
            if current.key() == &key {
                if current != &intent {
                    return Err(NetworkEffectError::NetworkAdmissionMismatch);
                }
                return Ok(current.proof());
            }
            if current.key() != &key && !is_current_or_newer_admission(current.key(), &key) {
                return Err(NetworkEffectError::NetworkAdmissionMismatch);
            }
        }
        let owner_intents = existing
            .as_ref()
            .into_iter()
            .chain(std::iter::once(&intent))
            .collect::<Vec<_>>();

        if self.entries.iter().any(|(candidate, existing)| {
            if candidate == &owner {
                return false;
            }
            intent.cidrs().iter().any(|cidr| {
                existing
                    .cidrs()
                    .iter()
                    .any(|peer| d2b_contracts_resource::v3::network::cidr_overlaps(cidr, peer))
            })
        }) || intent.cidrs().iter().any(|cidr| {
            occupancy.cidrs().iter().any(|peer| {
                d2b_contracts_resource::v3::network::cidr_overlaps(cidr, peer)
                    && !cidr_is_self_owned(&owner_intents, occupancy, peer)
            })
        }) {
            return Err(NetworkEffectError::CidrConflict);
        }

        if intent.interface_names().iter().any(|ifname| {
            occupancy.interface_names().iter().any(|occupied| {
                occupied == ifname && !interface_is_self_owned(&owner_intents, occupancy, occupied)
            }) || self.entries.iter().any(|(candidate, existing)| {
                if candidate == &owner {
                    return false;
                }
                existing
                    .interface_names()
                    .iter()
                    .any(|candidate| candidate == ifname)
            })
        }) {
            return Err(NetworkEffectError::NetworkInterfaceCollision);
        }
        if let Some((parent, mode, sharing)) = intent.external_nic() {
            let mut claims = Vec::new();
            for (candidate, existing) in &self.entries {
                if candidate == &owner {
                    continue;
                }
                let Some((existing_parent, existing_mode, existing_sharing)) =
                    existing.external_nic()
                else {
                    continue;
                };
                if existing_parent != parent {
                    continue;
                }
                claims.push(ExternalNicClaim::new(
                    existing.key().zone_uid().clone(),
                    existing_mode,
                    existing_sharing,
                ));
            }
            claims.push(ExternalNicClaim::new(key.zone_uid().clone(), mode, sharing));
            match admit_external_nic_claims(&claims, 64) {
                Ok(()) => {}
                Err(ExternalNicAdmissionError::ExternalPhysicalNicCrossZoneL2) => {
                    return Err(NetworkEffectError::CrossZoneL2);
                }
                Err(ExternalNicAdmissionError::ExternalPhysicalNicConflict) => {
                    return Err(NetworkEffectError::NetworkAdmissionConflict);
                }
            }
        }

        if intent.routes().iter().any(|route| {
            occupancy.routes().iter().any(|occupied| {
                route_conflicts(route, occupied)
                    && !route_is_self_owned(&owner_intents, occupancy, occupied)
            })
        }) || intent.routes().iter().any(|route| {
            self.entries.iter().any(|(candidate, existing)| {
                if candidate == &owner {
                    return false;
                }
                existing
                    .routes()
                    .iter()
                    .any(|candidate| route_conflicts(route, candidate))
            })
        }) {
            return Err(NetworkEffectError::NetworkRouteCollision);
        }

        let proof = intent.proof();
        if let Some(current) = existing {
            self.retired
                .entry(owner.clone())
                .or_default()
                .insert(current.key().clone());
        }
        self.entries.insert(owner, intent);
        Ok(proof)
    }

    /// Release only the exact admitted identity tuple after finalizer
    /// completion has been confirmed by the Network resource owner.
    pub fn release_after_finalizer(
        &mut self,
        key: &NetworkAdmissionKey,
        finalizer_complete: bool,
    ) -> bool {
        if !finalizer_complete {
            return false;
        }
        let owner = NetworkAdmissionOwnerKey::from_key(key);
        if !self
            .entries
            .get(&owner)
            .is_some_and(|intent| intent.key() == key)
        {
            return false;
        }
        self.entries.remove(&owner);
        self.retired.entry(owner).or_default().insert(key.clone());
        let floor = self
            .released_floors
            .entry(NetworkAdmissionOwnerKey::from_key(key))
            .or_insert((0, 0));
        floor.0 = floor.0.max(key.network_generation().get());
        floor.1 = floor.1.max(key.attachment_generation().get());
        true
    }

    /// Return the live proof for one Zone/Network owner.
    pub fn proof_for(
        &self,
        zone_uid: &ResourceUid,
        network_uid: &ResourceUid,
    ) -> Option<NetworkAdmissionProof> {
        self.entries
            .get(&NetworkAdmissionOwnerKey {
                zone_uid: zone_uid.clone(),
                network_uid: network_uid.clone(),
            })
            .map(NetworkAdmissionIntent::proof)
    }

    /// Release the current owner only after its finalizer has completed.
    pub fn release_owner_after_finalizer(
        &mut self,
        zone_uid: &ResourceUid,
        network_uid: &ResourceUid,
        finalizer_complete: bool,
    ) -> bool {
        let owner = NetworkAdmissionOwnerKey {
            zone_uid: zone_uid.clone(),
            network_uid: network_uid.clone(),
        };
        let Some(key) = self.entries.get(&owner).map(|intent| intent.key().clone()) else {
            return false;
        };
        self.release_after_finalizer(&key, finalizer_complete)
    }

    /// Return the number of admitted Network projections.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no Network projection is currently admitted.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn is_current_or_newer_admission(
    current: &NetworkAdmissionKey,
    candidate: &NetworkAdmissionKey,
) -> bool {
    candidate.network_generation().get() >= current.network_generation().get()
        && candidate.attachment_generation().get() >= current.attachment_generation().get()
}

fn interface_is_self_owned(
    owner_intents: &[&NetworkAdmissionIntent],
    occupancy: &HostNetworkOccupancy,
    ifname: &d2b_contracts_resource::v3::IfName,
) -> bool {
    let actual_markers = occupancy.interface_ownership_markers(ifname);
    !actual_markers.is_empty()
        && actual_markers.iter().all(|actual_marker| {
            owner_intents.iter().any(|intent| {
                intent
                    .interface_ownership_marker(ifname)
                    .is_some_and(|expected| {
                        network_marker_matches(expected, actual_marker, intent.key())
                    })
            })
        })
}

fn cidr_is_self_owned(
    owner_intents: &[&NetworkAdmissionIntent],
    occupancy: &HostNetworkOccupancy,
    cidr: &d2b_contracts_resource::v3::network::Ipv4Cidr,
) -> bool {
    let actual_markers = occupancy.cidr_ownership_markers(cidr);
    !actual_markers.is_empty()
        && actual_markers.iter().all(|actual_marker| {
            owner_intents.iter().any(|intent| {
                if !intent
                    .cidrs()
                    .iter()
                    .any(|owned| d2b_contracts_resource::v3::network::cidr_overlaps(owned, cidr))
                    && !intent.routes().iter().any(|route| {
                        d2b_contracts_resource::v3::network::Ipv4Cidr::parse(
                            route.destination().to_owned(),
                        )
                        .ok()
                        .is_some_and(|route_cidr| {
                            d2b_contracts_resource::v3::network::cidr_overlaps(&route_cidr, cidr)
                        })
                    })
                {
                    return false;
                }
                network_marker_matches(intent.ownership_marker(), actual_marker, intent.key())
                    || intent.interface_names().iter().any(|ifname| {
                        intent
                            .interface_ownership_marker(ifname)
                            .is_some_and(|expected| {
                                network_marker_matches(expected, actual_marker, intent.key())
                            })
                    })
                    || intent.routes().iter().any(|route| {
                        d2b_contracts_resource::v3::network::Ipv4Cidr::parse(
                            route.destination().to_owned(),
                        )
                        .ok()
                        .is_some_and(|route_cidr| {
                            d2b_contracts_resource::v3::network::cidr_overlaps(&route_cidr, cidr)
                                && intent
                                    .route_ownership_marker(route)
                                    .is_some_and(|expected| {
                                        network_marker_matches(
                                            expected,
                                            actual_marker,
                                            intent.key(),
                                        )
                                    })
                        })
                    })
            })
        })
}

fn route_is_self_owned(
    owner_intents: &[&NetworkAdmissionIntent],
    occupancy: &HostNetworkOccupancy,
    route: &RouteTuple,
) -> bool {
    let actual_markers = occupancy.route_ownership_markers(route);
    !actual_markers.is_empty()
        && actual_markers.iter().all(|actual_marker| {
            owner_intents.iter().any(|intent| {
                intent.routes().contains(route)
                    && intent
                        .route_ownership_marker(route)
                        .is_some_and(|expected| {
                            network_marker_matches(expected, actual_marker, intent.key())
                        })
            })
        })
}

fn network_marker_matches(expected: &str, actual: &str, key: &NetworkAdmissionKey) -> bool {
    let Some((expected_key, expected_object)) = parse_network_marker(expected) else {
        return false;
    };
    let Some((actual_key, actual_object)) = parse_network_marker(actual) else {
        return false;
    };
    expected_key == actual_key
        && expected_object == actual_object
        && expected_key.zone_uid() == key.zone_uid()
        && expected_key.network_uid() == key.network_uid()
}

fn parse_network_marker(marker: &str) -> Option<(NetworkAdmissionKey, String)> {
    let marker = marker
        .strip_prefix("d2b managed: ")
        .unwrap_or(marker)
        .trim();
    let (object, rest) = marker.split_once(":zone:")?;
    let object = object.strip_prefix("network:")?.to_owned();
    let (zone, rest) = rest.split_once(":network:")?;
    let (network, rest) = rest.split_once(":generation:")?;
    let (generation, rest) = rest.split_once(":attachment:")?;
    let (attachment, bundle) = rest.split_once(":bundle:")?;
    let zone_uid = ResourceUid::parse(zone.to_owned()).ok()?;
    let network_uid = ResourceUid::parse(network.to_owned()).ok()?;
    let network_generation = ResourceGeneration::new(generation.parse().ok()?).ok()?;
    let attachment_generation = ResourceGeneration::new(attachment.parse().ok()?).ok()?;
    let bundle_generation = ResourceBundleGenerationId::parse(bundle.to_owned()).ok()?;
    Some((
        NetworkAdmissionKey::new(
            zone_uid,
            network_uid,
            network_generation,
            attachment_generation,
            bundle_generation,
        ),
        object,
    ))
}

/// All Zone runtimes owned by one daemon.
#[derive(Default)]
pub struct ResourcePlane {
    zones: BTreeMap<ZoneId, Arc<ZoneResourceRuntime>>,
    network_admission_index: Arc<tokio::sync::Mutex<HostNetworkAdmissionIndex>>,
    topology_root: Option<ZoneId>,
    gateway_zone_links: BTreeMap<ZoneId, Arc<crate::ZoneLinkGatewayComposition>>,
    gateway_zone_link_refused: BTreeSet<ZoneId>,
}

impl core::fmt::Debug for ResourcePlane {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ResourcePlane")
            .field("zone_count", &self.zones.len())
            .finish()
    }
}

impl ResourcePlane {
    /// Create an empty daemon-owned plane.
    pub fn new() -> Self {
        Self {
            zones: BTreeMap::new(),
            network_admission_index: Arc::new(tokio::sync::Mutex::new(
                HostNetworkAdmissionIndex::default(),
            )),
            topology_root: None,
            gateway_zone_links: BTreeMap::new(),
            gateway_zone_link_refused: BTreeSet::new(),
        }
    }

    /// Borrow the one root-owned Host-global Network admission index.
    pub fn network_admission_index(&self) -> Arc<tokio::sync::Mutex<HostNetworkAdmissionIndex>> {
        Arc::clone(&self.network_admission_index)
    }

    /// Bind the sealed topology root selected during Zone publication.
    pub(crate) fn set_topology_root(&mut self, root: ZoneId) {
        self.topology_root = Some(root);
    }

    /// Borrow the sealed topology root.
    pub(crate) fn topology_root(&self) -> Option<&ZoneId> {
        self.topology_root.as_ref()
    }

    /// Insert a freshly opened Zone runtime.
    pub fn insert(
        &mut self,
        runtime: ZoneResourceRuntime,
    ) -> Result<Arc<ZoneResourceRuntime>, ResourceRuntimeError> {
        if self.zones.len() >= MAX_ZONE_RUNTIMES {
            return Err(ResourceRuntimeError::CoreStartupFailed);
        }
        let zone = runtime.zone().clone();
        if self.zones.contains_key(&zone) {
            return Err(ResourceRuntimeError::DuplicateZone);
        }
        let runtime = Arc::new(runtime);
        self.zones.insert(zone, Arc::clone(&runtime));
        Ok(runtime)
    }

    /// Resolve a Zone only from the authoritative plane index.
    pub fn zone(&self, zone: &ZoneId) -> Result<Arc<ZoneResourceRuntime>, ResourceRuntimeError> {
        self.zones
            .get(zone)
            .cloned()
            .ok_or(ResourceRuntimeError::PlaneUnavailable)
    }

    /// Record one terminal broker result in every Zone's shared live index.
    pub fn record_broker_evidence(
        &self,
        evidence: DurabilityEvidence,
    ) -> Result<(), ResourceRuntimeError> {
        for runtime in self.zones.values() {
            runtime.record_broker_evidence(evidence.clone())?;
        }
        Ok(())
    }

    /// Return the number of ready Zone runtimes.
    pub fn ready_zone_count(&self) -> usize {
        self.zones
            .values()
            .filter(|runtime| runtime.require_ready().is_ok())
            .count()
    }

    /// Return whether a request still owns any Zone runtime.
    ///
    /// The plane itself owns one strong reference to every runtime. Any
    /// additional reference is an in-flight request owner and must keep the
    /// store open.
    pub fn has_live_request_owners(&self) -> bool {
        self.zones
            .values()
            .any(|runtime| Arc::strong_count(runtime) > 1)
    }

    /// Return the authoritative Zone identities currently owned by the plane.
    pub fn zone_ids(&self) -> Vec<ZoneId> {
        self.zones.keys().cloned().collect()
    }

    /// Install the one child-local Gateway Guest composition for a Zone.
    pub(crate) fn insert_gateway_zone_link(
        &mut self,
        composition: crate::ZoneLinkGatewayComposition,
    ) -> Result<(), ResourceRuntimeError> {
        let zone = composition.zone().clone();
        if self.gateway_zone_links.contains_key(&zone) {
            return Err(ResourceRuntimeError::DuplicateZone);
        }
        self.gateway_zone_link_refused.remove(&zone);
        self.gateway_zone_links.insert(zone, Arc::new(composition));
        Ok(())
    }

    /// Mark a committed gateway-backed Zone as refused so public dispatch
    /// cannot fall back to its host-local Resource API.
    pub(crate) fn refuse_gateway_zone_link(&mut self, zone: ZoneId) {
        self.gateway_zone_link_refused.insert(zone);
    }

    /// Return whether a committed gateway-backed Zone failed composition.
    pub(crate) fn gateway_zone_link_is_refused(&self, zone: &ZoneId) -> bool {
        self.gateway_zone_link_refused.contains(zone)
    }

    /// Borrow a Zone's Gateway Guest route composition, when one is installed.
    pub(crate) fn gateway_zone_link(
        &self,
        zone: &ZoneId,
    ) -> Option<Arc<crate::ZoneLinkGatewayComposition>> {
        self.gateway_zone_links.get(zone).cloned()
    }

    /// Drain runtimes and close every production backend.
    ///
    /// The map remains owned by the caller when a live request owner is
    /// observed, so a refused shutdown cannot drop the last backend owner and
    /// leave its clean-shutdown marker dirty.
    pub async fn shutdown(&mut self) -> Result<(), ResourceRuntimeError> {
        if self.has_live_request_owners() {
            return Err(ResourceRuntimeError::LiveRequestOwners);
        }
        let runtimes = std::mem::take(&mut self.zones);
        for (_, runtime) in runtimes {
            let runtime = match Arc::try_unwrap(runtime) {
                Ok(runtime) => runtime,
                Err(runtime) => {
                    self.zones.insert(runtime.zone().clone(), runtime);
                    return Err(ResourceRuntimeError::LiveRequestOwners);
                }
            };
            runtime.shutdown().await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::VecDeque,
        fs::OpenOptions,
        os::fd::AsRawFd,
        sync::Arc,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    use d2b_contracts_resource::v3::{
        CanonicalJsonObject, Timestamp,
        storage::{ZoneStoreIdentity, ZoneStoreStorageRow},
    };
    use d2b_contracts_zone_session::v3::component_session::LimitProfile;
    use d2b_contracts_zone_session::v3::resource_bundle::{BundleResource, BundleResourceMetadata};
    use d2b_provider_volume_local::VolumeLocalError;
    use d2b_resource_store::mutation_seal::mutation_seal_pair;
    use d2b_resource_store_redb::write_provisioning_marker;
    use d2b_session_unix::{CreditPool, CreditScopeSet, OutboundPacket, prearmed_seqpacket_pair};

    struct RecordingSharedProviderEffects {
        reconciles: AtomicUsize,
        finalizes: AtomicUsize,
        cleanup_ready: std::sync::atomic::AtomicBool,
    }

    #[async_trait]
    impl SharedProviderEffectExecutor for RecordingSharedProviderEffects {
        async fn reconcile_network(
            &self,
            _context: &SharedProviderEffectContext,
            _resource: &ResourceSnapshot,
            _dependencies: &[DependencySnapshot],
        ) -> Result<SharedProviderEffectPhase, SharedProviderEffectError> {
            self.reconciles.fetch_add(1, Ordering::SeqCst);
            Ok(SharedProviderEffectPhase::Ready)
        }

        async fn finalize(
            &self,
            _kind: SharedProviderResourceKind,
            _context: &SharedProviderEffectContext,
            _resource: &ResourceSnapshot,
        ) -> Result<(), SharedProviderEffectError> {
            if !self.cleanup_ready.load(Ordering::SeqCst) {
                return Err(SharedProviderEffectError::Unavailable);
            }
            self.finalizes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn shared_provider_test_descriptor_for(
        registration: SharedProviderRunnerRegistration,
    ) -> (
        SharedProviderRunnerRegistration,
        ControllerDescriptor,
    ) {
        let provider_ref = ResourceRef::parse(registration.provider_ref).unwrap();
        let generations = BTreeMap::from([(provider_ref, ResourceGeneration::new(7).unwrap())]);
        compose_shared_provider_runner_descriptors(
            [registration],
            ZoneId::parse("work").unwrap(),
            ControllerGeneration::new(3).unwrap(),
            &generations,
            ReconnectGeneration::new(5).unwrap(),
        )
        .unwrap()
        .pop()
        .unwrap()
    }

    fn shared_provider_test_descriptor() -> (
        SharedProviderRunnerRegistration,
        ControllerDescriptor,
    ) {
        shared_provider_test_descriptor_for(U8_SHARED_PROVIDER_RUNNERS[0])
    }

    fn shared_provider_test_resource(finalizers: &[&str], deleting: bool) -> ResourceSnapshot {
        shared_provider_test_resource_for(
            U8_SHARED_PROVIDER_RUNNERS[0],
            finalizers,
            deleting,
        )
    }

    fn shared_provider_test_resource_for(
        registration: SharedProviderRunnerRegistration,
        finalizers: &[&str],
        deleting: bool,
    ) -> ResourceSnapshot {
        let zone = ZoneId::parse("work").unwrap();
        let resource_ref =
            ResourceRef::parse(&format!("{}/work", registration.resource_type)).unwrap();
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let finalizers = finalizers
            .iter()
            .map(|value| Value::String((*value).to_owned()))
            .collect::<Vec<_>>();
        let spec = if registration.resource_type.starts_with("display-wayland.") {
            json!({})
        } else {
            json!({"providerRef": registration.provider_ref})
        };
        let body = json!({
            "apiVersion": "resources.d2bus.org/v3",
            "type": registration.resource_type,
            "metadata": {
                "name": "work",
                "zone": "work",
                "uid": uid.as_str(),
                "generation": 1,
                "revision": 1,
                "finalizers": finalizers,
            },
            "spec": spec,
            "status": {
                "phase": "Pending",
                "observedGeneration": 0,
            },
        });
        ResourceSnapshot::new(
            ResourceKey::new(zone, resource_ref, uid),
            ZoneRevision::new(1),
            ResourceGeneration::new(1).unwrap(),
            serde_json::to_vec(&body).unwrap(),
            deleting,
        )
    }

    #[tokio::test]
    async fn shared_provider_runner_uses_typed_effect_and_cleanup_after_finalizer_pass() {
        let (registration, descriptor) = shared_provider_test_descriptor();
        let effects = Arc::new(RecordingSharedProviderEffects {
            reconciles: AtomicUsize::new(0),
            finalizes: AtomicUsize::new(0),
            cleanup_ready: std::sync::atomic::AtomicBool::new(false),
        });
        let reconciler = SharedProviderResourceReconciler::new(
            descriptor,
            SharedProviderResourceKind::Network,
            effects.clone(),
        );
        let first = reconciler
            .first_pass_for_test(&shared_provider_test_resource(&[], false))
            .unwrap();
        assert_eq!(first.disposition(), ReconcileDisposition::Pending);
        assert!(first.mutation_batch().is_some());
        assert_eq!(
            first
                .mutation_batch()
                .unwrap()
                .mutations()
                .first()
                .unwrap()
                .kind(),
            d2b_core_controller::MutationIntentKind::UpdateFinalizers
        );
        assert_eq!(effects.reconciles.load(Ordering::SeqCst), 0);

        let current = shared_provider_test_resource(&[registration.finalizer], false);
        assert_eq!(
            reconciler
                .execute_effect_for_test(&current, &[])
                .await
                .unwrap(),
            SharedProviderEffectPhase::Ready
        );
        assert_eq!(effects.reconciles.load(Ordering::SeqCst), 1);

        let deleting = shared_provider_test_resource(&[registration.finalizer], true);
        assert!(reconciler.execute_finalize_for_test(&deleting).await.is_err());
        assert_eq!(effects.finalizes.load(Ordering::SeqCst), 0);
        effects.cleanup_ready.store(true, Ordering::SeqCst);
        let finalized = reconciler.execute_finalize_for_test(&deleting).await.unwrap();
        assert!(finalized.mutation_batch().is_some());
        assert_eq!(
            finalized
                .mutation_batch()
                .unwrap()
                .mutations()
                .first()
                .unwrap()
                .kind(),
            d2b_core_controller::MutationIntentKind::UpdateFinalizers
        );
        assert_eq!(effects.finalizes.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn every_u6_guest_runtime_descriptor_is_provider_ref_scoped() {
        for registration in U6_SHARED_PROVIDER_RUNNERS {
            let (_, descriptor) = shared_provider_test_descriptor_for(registration);
            assert_eq!(
                descriptor
                    .resource_types()
                    .map(|resource_type| resource_type.as_str())
                    .collect::<Vec<_>>(),
                vec!["Guest"]
            );
            assert!(descriptor
                .watch_selectors()
                .iter()
                .any(|selector| selector.exact_value() == Some(registration.provider_ref)));
            assert!(descriptor.dependency_selectors().iter().any(|selector| {
                selector.resource_type().as_str() == "Process"
            }));
            assert!(registration.legacy_scheduler_disabled);
            assert!(registration.watched_configuration_is_dependency);
        }
    }

    #[test]
    fn u6_guest_runtime_kinds_are_closed_to_the_four_provider_rows() {
        assert_eq!(
            SharedProviderResourceKind::from_registration(U6_SHARED_PROVIDER_RUNNERS[0]).unwrap(),
            SharedProviderResourceKind::CloudHypervisorGuest
        );
        assert_eq!(
            SharedProviderResourceKind::from_registration(U6_SHARED_PROVIDER_RUNNERS[1]).unwrap(),
            SharedProviderResourceKind::QemuMediaGuest
        );
        assert_eq!(
            SharedProviderResourceKind::from_registration(U6_SHARED_PROVIDER_RUNNERS[2]).unwrap(),
            SharedProviderResourceKind::AzureContainerAppsGuest
        );
        assert_eq!(
            SharedProviderResourceKind::from_registration(U6_SHARED_PROVIDER_RUNNERS[3]).unwrap(),
            SharedProviderResourceKind::AzureVirtualMachineGuest
        );
    }

    #[test]
    fn u6_guest_runner_enrolls_its_exact_finalizer_before_effects() {
        let registration = U6_SHARED_PROVIDER_RUNNERS[1];
        let (_, descriptor) = shared_provider_test_descriptor_for(registration);
        let reconciler = SharedProviderResourceReconciler::new(
            descriptor,
            SharedProviderResourceKind::QemuMediaGuest,
            Arc::new(UnavailableSharedProviderEffects),
        );
        let result = reconciler
            .first_pass_for_test(&shared_provider_test_resource_for(
                registration,
                &[],
                false,
            ))
            .expect("finalizer enrollment result");
        let mutation = result
            .mutation_batch()
            .expect("first pass must mutate only finalizers")
            .mutations()
            .first()
            .expect("finalizer mutation");
        assert_eq!(
            mutation.kind(),
            d2b_core_controller::MutationIntentKind::UpdateFinalizers
        );
        let payload = mutation
            .canonical_resource()
            .expect("full finalizer candidate");
        let value: Value = serde_json::from_slice(payload).expect("candidate JSON");
        assert_eq!(
            value["metadata"]["finalizers"],
            serde_json::json!([registration.finalizer])
        );
    }

    #[tokio::test]
    async fn every_u8_descriptor_cleans_before_finalizer_removal() {
        for registration in U8_SHARED_PROVIDER_RUNNERS {
            let (_, descriptor) = shared_provider_test_descriptor_for(registration);
            let effects = Arc::new(RecordingSharedProviderEffects {
                reconciles: AtomicUsize::new(0),
                finalizes: AtomicUsize::new(0),
                cleanup_ready: std::sync::atomic::AtomicBool::new(true),
            });
            let kind = SharedProviderResourceKind::from_registration(registration).unwrap();
            let reconciler =
                SharedProviderResourceReconciler::new(descriptor, kind, effects.clone());
            let deleting =
                shared_provider_test_resource_for(registration, &[registration.finalizer], true);
            let result = reconciler.execute_finalize_for_test(&deleting).await.unwrap();
            assert!(result.mutation_batch().is_some());
            assert_eq!(effects.finalizes.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn u9_runner_enrolls_exact_finalizers_before_effects() {
        for registration in U9_SHARED_PROVIDER_RUNNERS {
            let (_, descriptor) = shared_provider_test_descriptor_for(registration);
            let kind = SharedProviderResourceKind::from_registration(registration).unwrap();
            let reconciler = SharedProviderResourceReconciler::new(
                descriptor,
                kind,
                Arc::new(UnavailableSharedProviderEffects),
            );
            let result = reconciler
                .first_pass_for_test(&shared_provider_test_resource_for(
                    registration,
                    &[],
                    false,
                ))
                .expect("U9 first pass");
            if registration.finalizer.is_empty() {
                assert!(result.mutation_batch().is_none());
                assert_eq!(result.disposition(), ReconcileDisposition::Pending);
            } else {
                let mutation = result
                    .mutation_batch()
                    .expect("U9 finalizer mutation")
                    .mutations()
                    .first()
                    .expect("U9 finalizer");
                assert_eq!(
                    mutation.kind(),
                    d2b_core_controller::MutationIntentKind::UpdateFinalizers
                );
                let value: Value =
                    serde_json::from_slice(mutation.canonical_resource().unwrap())
                        .expect("U9 finalizer candidate");
                assert_eq!(
                    value["metadata"]["finalizers"],
                    serde_json::json!([registration.finalizer])
                );
            }
        }
    }

    #[tokio::test]
    async fn network_runner_uses_durable_child_readiness() {
        let fixture = PublicationStoreFixture::new().await;
        let bundle = publication_bundle(&fixture.zone, fixture.identity.zone_uid(), "network");
        let runtime = Arc::new(fixture.open(&bundle).await);
        let children = SharedRunnerNetworkResources::new(
            Arc::clone(&runtime),
            ResourceRef::parse("Network/work").unwrap(),
            &ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap(),
        );
        assert_eq!(
            children.readiness().await.unwrap(),
            SharedRunnerNetworkReadiness {
                volume_ready: false,
                guest_ready: false,
                attachment_ready: false,
            }
        );
        drop(children);
        let runtime = Arc::try_unwrap(runtime).expect("test runtime has one owner");
        runtime.shutdown().await.unwrap();
    }

    #[test]
    fn accepted_u12_resources_cannot_run_without_their_provider() {
        assert!(u12_provider_missing_with_resources(true));
        assert!(!u12_provider_missing_with_resources(false));
        assert!(!u12_runner_readiness(true, 0, false));
        assert!(!u12_runner_readiness(true, 1, true));
        assert!(u12_runner_readiness(true, 2, false));
        assert!(u12_runner_readiness(false, 0, true));
        assert_eq!(
            validate_observability_environment_keys(["OTEL_EXPORTER_OTLP_HEADERS"]),
            Err(ResourceRuntimeError::ProviderPathUnavailable)
        );
    }

    #[tokio::test]
    async fn u12_runner_start_rollback_aborts_every_spawned_task() {
        let mut tasks = vec![
            tokio::spawn(async {
                std::future::pending::<()>().await;
            }),
            tokio::spawn(async {
                std::future::pending::<()>().await;
            }),
        ];
        abort_u12_runner_tasks(&mut tasks).await;
        assert!(tasks.is_empty());
    }

    #[tokio::test]
    async fn u12_rebind_stop_clears_every_tracked_runner() {
        let fixture = PublicationStoreFixture::new().await;
        let bundle = publication_bundle(&fixture.zone, fixture.identity.zone_uid(), "u12-stop");
        let runtime = fixture.open(&bundle).await;
        runtime
            .u12_runner_tasks
            .lock()
            .unwrap()
            .push(tokio::spawn(async {
                std::future::pending::<()>().await;
            }));
        runtime
            .stop_u12_controller_runners_locked()
            .await
            .expect("U12 runner stop");
        assert!(runtime.u12_runner_tasks.lock().unwrap().is_empty());
        runtime.shutdown().await.unwrap();
    }

    #[test]
    fn daemon_shared_provider_effects_network_content_path_round_trips_and_preserves_foreign_marker()
    {
        let zone_uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let network_uid = ResourceUid::parse("223e4567-e89b-42d3-a456-426614174000").unwrap();
        let owner_ref = ResourceRef::parse("Network/work").unwrap();
        let bundle_generation = ResourceBundleGenerationId::parse(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        let provenance = NetworkProvenance::new(
            zone_uid,
            network_uid.clone(),
            ResourceGeneration::new(2).unwrap(),
            ResourceGeneration::new(3).unwrap(),
            bundle_generation,
        );
        let network_spec = d2b_contracts_resource::v3::network::NetworkSpec::minimal(
            d2b_contracts_resource::v3::network::Ipv4Cidr::parse("10.20.0.0/24").unwrap(),
            d2b_contracts_resource::v3::network::Ipv4Cidr::parse("192.0.2.0/30").unwrap(),
            d2b_contracts_resource::v3::execution_policy::BoundedToken::parse("net-vm-base")
                .unwrap(),
        )
        .unwrap();
        let content = d2b_provider_network_local::controller::render_config_with_provenance(
            &network_spec,
            &provenance,
        )
        .unwrap();
        let assignment = ResourceAssignmentFence {
            resource_uid: network_uid,
            resource_revision: ZoneRevision::new(4),
            provider_generation: ResourceGeneration::new(7).unwrap(),
            controller_generation: ControllerGeneration::new(3).unwrap(),
            controller_role: ResourceRef::parse("Process/network-local-controller").unwrap(),
            target: ResourceRef::parse(CORE_CONTROLLER_HOST_REF).unwrap(),
            session_generation: ReconnectGeneration::new(5).unwrap(),
            epoch: 9,
            scope: ResourceAssignmentScope::Primary,
        };
        let fence = SharedRunnerNetworkContentFence {
            owner_ref: owner_ref.clone(),
            provenance,
            assignment,
            controller_ref: ResourceRef::parse("Process/network-local-controller").unwrap(),
            controller_generation: ControllerGeneration::new(3).unwrap(),
            provider_generation: ResourceGeneration::new(7).unwrap(),
            session_generation: ReconnectGeneration::new(5).unwrap(),
        };
        let volume_spec =
            d2b_provider_network_local::controller::config_volume_spec("host-system", None)
                .unwrap();
        let mut spec = serde_json::to_value(&volume_spec).unwrap();
        spec.as_object_mut()
            .unwrap()
            .insert("providerRef".to_owned(), Value::String("Provider/volume-local".to_owned()));
        let volume_uid =
            ResourceUid::parse("323e4567-e89b-42d3-a456-426614174000").unwrap();
        let projected = DaemonSharedProviderEffects::project_network_volume_spec(
            spec,
            &volume_uid,
            &content,
            &fence,
            &owner_ref,
        )
        .unwrap();
        let mut envelope = json!({
            "metadata": { "uid": volume_uid, "generation": 1 },
            "spec": projected,
        });
        assert!(!network_config_content_projection_ready(&envelope));
        let projection = d2b_provider_volume_local::NetworkConfigContentProjection::from_settings(
            &envelope["spec"]["provider"]["settings"]["content"],
        )
        .unwrap();
        let mut tampered = serde_json::to_value(&projection).unwrap();
        tampered["dnsmasq"][0] = Value::from(b'X');
        assert_eq!(
            d2b_provider_volume_local::NetworkConfigContentProjection::from_settings(&tampered),
            Err(VolumeLocalError::InvalidSpec)
        );
        let evidence =
            d2b_provider_volume_local::NetworkConfigMaterializationEvidence::from_observed_files(
                &projection,
                content.dnsmasq.as_slice(),
                content.nftables.as_slice(),
                content.routing.as_slice(),
                content.attachments.as_slice(),
            )
            .unwrap();
        envelope["status"] = json!({
            "phase": "Ready",
            "observedGeneration": 1,
            "resource": {
                "provider": "volume-local",
                "content": evidence,
            },
        });
        assert!(network_config_content_projection_ready(&envelope));

        let mut foreign = envelope["spec"].clone();
        foreign["provider"]["settings"]["content"]["ownershipMarker"] =
            Value::String("foreign-marker".to_owned());
        let before = serde_json::to_vec(&foreign).unwrap();
        let marker = d2b_contracts_resource::v3::derive_network_ownership_marker(
            &fence.provenance,
            "network-config",
        );
        assert!(!network_config_provider_matches(
            &foreign["provider"],
            &volume_uid,
            &owner_ref,
            &marker
        ));
        assert_eq!(
            DaemonSharedProviderEffects::project_network_volume_spec(
                foreign.clone(),
                &volume_uid,
                &content,
                &fence,
                &owner_ref,
            ),
            Err(NetworkEffectError::NetworkAdmissionMismatch)
        );
        assert_eq!(serde_json::to_vec(&foreign).unwrap(), before);
    }

    #[test]
    fn cloud_hypervisor_process_update_applies_requested_lifecycle() {
        let current = json!({
            "apiVersion": "resources.d2bus.org/v3",
            "type": "Process",
            "metadata": {},
            "spec": {
                "desiredLifecycle": "stopped",
                "providerRef": "Provider/system-minijail"
            },
            "status": {}
        });
        let body = d2b_provider_runtime_cloud_hypervisor::ChildCreateBody::Process(
            d2b_provider_runtime_cloud_hypervisor::ProcessCreateBody::new(
                ResourceRef::parse("Host/host-system").unwrap(),
            )
            .unwrap(),
        );

        let updated =
            merge_cloud_hypervisor_child_spec(&current, &body, Some(DesiredLifecycle::Running))
                .unwrap();

        assert_eq!(updated["desiredLifecycle"], "running");
        assert_eq!(updated["providerRef"], "Provider/system-minijail");
    }

    fn test_audit_sink(directory: &std::path::Path, name: &str) -> Arc<AuditSink> {
        Arc::new(AuditSink::open(directory.join(name)).unwrap())
    }

    struct PublicationStoreFixture {
        _directory: tempfile::TempDir,
        database_path: std::path::PathBuf,
        response_identity: String,
        zone: ZoneId,
        identity: d2b_resource_store_redb::StoreIdentity,
    }

    impl PublicationStoreFixture {
        async fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let database_path = directory.path().join("store.redb");
            let zone = ZoneId::parse("work").unwrap();
            let response_identity = "sha256:".to_owned() + &"1".repeat(64);
            let identity = store_identity(&zone, &response_identity).unwrap();
            let database = OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(&database_path)
                .unwrap();
            let mut marker = OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(directory.path().join(".d2b-store-marker"))
                .unwrap();
            write_provisioning_marker(&mut marker, &identity).unwrap();
            RedbResourceStore::provision_owned(
                database,
                marker,
                identity.clone(),
                mutation_seal_pair(identity.seal_identity()).1,
            )
            .await
            .unwrap()
            .shutdown()
            .await
            .unwrap();
            Self {
                _directory: directory,
                database_path,
                response_identity,
                zone,
                identity,
            }
        }

        async fn open(&self, bundle: &ResourceBundle) -> ZoneResourceRuntime {
            let database = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&self.database_path)
                .unwrap();
            let mut runtime = ZoneResourceRuntime::open(
                self.zone.clone(),
                OpenedZoneStore {
                    response: OpenZoneStoreResponse {
                        zone_store_id: d2b_contracts_resource::v3::storage::ZoneStoreId::parse(
                            "zone-store-work",
                        )
                        .unwrap(),
                        store_identity: self.response_identity.clone(),
                        disposition: ZoneStoreDisposition::Opened,
                        fd_index: 0,
                    },
                    database_fd: database.into(),
                    external_inventory: None,
                },
            )
            .await
            .unwrap();
            let storage = publication_storage_row(&self.zone, &self.identity);
            runtime.authority_identity = Some(
                ZoneAuthorityIdentity::from_bundle_and_storage(&self.zone, bundle, &storage)
                    .unwrap(),
            );
            runtime
        }

        fn generation_set(
            &self,
            bundle: &ResourceBundle,
        ) -> (
            ResourceBundleGenerationId,
            BTreeMap<ZoneId, ResourceBundleGenerationId>,
        ) {
            let generation =
                ResourceBundleGenerationId::parse(bundle.integrity().content_hash.clone()).unwrap();
            let generations = BTreeMap::from([(self.zone.clone(), generation)]);
            let set_generation =
                complete_generation_set_digest(&BTreeSet::from([self.zone.clone()]), &generations)
                    .unwrap();
            (set_generation, generations)
        }
    }

    fn publication_storage_row(
        zone: &ZoneId,
        identity: &d2b_resource_store_redb::StoreIdentity,
    ) -> ZoneStoreStorageRow {
        let storage_identity = ZoneStoreIdentity::new(
            identity.zone_uid().clone(),
            identity.store_uid().clone(),
            identity.store_epoch(),
        )
        .unwrap();
        serde_json::from_value(json!({
            "identity": storage_identity,
            "zoneStoreId": format!("zone-store-{}", zone.as_str()),
            "storageOwnerPrincipal": "d2b-zonert",
            "parentDirectoryId": format!("zone-store-parent-{}", zone.as_str()),
            "ownership": {
                "owner": "d2b-zonert", "group": "d2b-zonert",
                "mode": "0640", "linkCount": 1
            },
            "auxiliaryDirectories": {
                "audit": {
                    "directoryId": format!("zone-store-audit-{}", zone.as_str()),
                    "owner": "d2bd", "group": "d2bd",
                    "mode": "0700", "repairOwner": "privileged-broker"
                },
                "telemetry": {
                    "directoryId": format!("zone-store-telemetry-{}", zone.as_str()),
                    "owner": "d2bd", "group": "d2bd",
                    "mode": "0700", "repairOwner": "privileged-broker"
                }
            },
            "filesystem": "regular-file-anchored-fd-relative-no-follow",
            "locking": "ofd-close-on-exec",
            "marker": {
                "identityMarkerId": format!("zone-store-marker-{}", zone.as_str())
            },
            "replacementDetection": "fail-closed-on-missing-replaced-or-identity-mismatch",
            "fsync": "database-and-parent-directory",
            "publication": {
                "descriptor": "owned-descriptor-close-on-exec-verified-before-concurrency",
                "replacement": "atomic-rename-retain-prior-quarantine-ambiguity"
            }
        }))
        .unwrap()
    }

    fn publication_bundle(zone: &ZoneId, zone_uid: &ResourceUid, value: &str) -> ResourceBundle {
        let resource = BundleResource::new(
            ResourceTypeName::parse("Host").unwrap(),
            BundleResourceMetadata::new(
                ResourceName::parse(format!("generation-{value}")).unwrap(),
                zone.clone(),
                None,
                BTreeMap::new(),
                BTreeMap::new(),
            ),
            CanonicalJsonObject::parse(format!(r#"{{"value":"{value}"}}"#).as_bytes()).unwrap(),
        )
        .unwrap();
        ResourceBundle::new(
            zone.clone(),
            vec![resource],
            "sha256:".to_owned() + &"f".repeat(64),
            BTreeMap::new(),
            BTreeMap::new(),
            Timestamp::parse("2026-08-26T00:00:00.000Z").unwrap(),
        )
        .unwrap()
        .with_zone_uid(zone_uid.clone())
    }

    async fn publish_generation(
        runtime: &ZoneResourceRuntime,
        set_generation: &ResourceBundleGenerationId,
        generations: &BTreeMap<ZoneId, ResourceBundleGenerationId>,
    ) {
        runtime
            .prepare_generation_publication(set_generation, generations)
            .await
            .unwrap();
        runtime
            .commit_generation_publication(set_generation, generations)
            .await
            .unwrap();
    }

    async fn publication_state(
        runtime: &ZoneResourceRuntime,
        set_generation: &ResourceBundleGenerationId,
    ) -> AuthorityOperationState {
        runtime
            .store
            .authority_operations()
            .await
            .unwrap()
            .into_iter()
            .find(|operation| {
                operation.operation_id == generation_publication_operation_id(set_generation)
            })
            .unwrap()
            .state
    }

    #[tokio::test]
    async fn core_runner_start_rotation_is_serialized() {
        let fixture = PublicationStoreFixture::new().await;
        let bundle = publication_bundle(&fixture.zone, fixture.identity.zone_uid(), "rotation");
        let mut runtime = fixture.open(&bundle).await;
        runtime.readiness.resource_api_ready = false;
        runtime
            .core_runner_tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(tokio::spawn(async {
                loop {
                    tokio::task::yield_now().await;
                }
            }));
        {
            let _runner_guard = runtime.core_runner_lock.lock().await;
            runtime.stop_core_controller_runners_locked().await.unwrap();
        }
        assert!(
            runtime
                .core_runner_tasks
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_empty()
        );

        let first = runtime.start_core_controller_runners();
        let second = runtime.start_core_controller_runners();
        let (first, second) = tokio::join!(first, second);
        assert!(first.is_ok());
        assert!(second.is_ok());
        assert_eq!(
            runtime
                .core_runner_events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_slice(),
            [
                "stop-enter",
                "stop-exit",
                "start-enter",
                "start-exit",
                "start-enter",
                "start-exit"
            ]
        );
        runtime.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn generation_publication_retires_a_before_admitting_b() {
        let fixture = PublicationStoreFixture::new().await;
        let bundle_a = publication_bundle(&fixture.zone, fixture.identity.zone_uid(), "a");
        let bundle_b = publication_bundle(&fixture.zone, fixture.identity.zone_uid(), "b");

        let runtime_a = fixture.open(&bundle_a).await;
        let (set_a, generations_a) = fixture.generation_set(&bundle_a);
        publish_generation(&runtime_a, &set_a, &generations_a).await;
        assert_eq!(
            publication_state(&runtime_a, &set_a).await,
            AuthorityOperationState::Released
        );
        runtime_a.shutdown().await.unwrap();

        let runtime_b = fixture.open(&bundle_b).await;
        let (set_b, generations_b) = fixture.generation_set(&bundle_b);
        publish_generation(&runtime_b, &set_b, &generations_b).await;
        assert_eq!(
            publication_state(&runtime_b, &set_b).await,
            AuthorityOperationState::Released
        );
        runtime_b.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn generation_publication_restart_recovers_confirmed_a_idempotently() {
        let fixture = PublicationStoreFixture::new().await;
        let bundle_a = publication_bundle(&fixture.zone, fixture.identity.zone_uid(), "a");
        let runtime_a = fixture.open(&bundle_a).await;
        let (set_a, generations_a) = fixture.generation_set(&bundle_a);
        runtime_a
            .prepare_generation_publication(&set_a, &generations_a)
            .await
            .unwrap();
        let operation_id = generation_publication_operation_id(&set_a);
        let binding_digest = runtime_a.store.authority_binding_digest(set_a.as_str());
        let capability = runtime_a
            .store
            .resume_authority_operation(operation_id, &binding_digest)
            .await
            .unwrap();
        capability
            .record_effect(AuthorityOperationState::EffectConfirmed)
            .await
            .unwrap();
        drop(capability);
        runtime_a.shutdown().await.unwrap();

        let runtime_restart = fixture.open(&bundle_a).await;
        publish_generation(&runtime_restart, &set_a, &generations_a).await;
        assert_eq!(
            publication_state(&runtime_restart, &set_a).await,
            AuthorityOperationState::Released
        );
        runtime_restart.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn generation_publication_pending_and_retryable_a_fence_b() {
        for retryable in [false, true] {
            let fixture = PublicationStoreFixture::new().await;
            let bundle_a = publication_bundle(
                &fixture.zone,
                fixture.identity.zone_uid(),
                if retryable { "retryable" } else { "pending" },
            );
            let bundle_b = publication_bundle(&fixture.zone, fixture.identity.zone_uid(), "b");
            let runtime_a = fixture.open(&bundle_a).await;
            let (set_a, generations_a) = fixture.generation_set(&bundle_a);
            runtime_a
                .prepare_generation_publication(&set_a, &generations_a)
                .await
                .unwrap();
            if retryable {
                let binding_digest = runtime_a.store.authority_binding_digest(set_a.as_str());
                let capability = runtime_a
                    .store
                    .resume_authority_operation(
                        generation_publication_operation_id(&set_a),
                        &binding_digest,
                    )
                    .await
                    .unwrap();
                capability
                    .record_effect(AuthorityOperationState::EffectRetryable)
                    .await
                    .unwrap();
            }
            runtime_a.shutdown().await.unwrap();

            let runtime_b = fixture.open(&bundle_b).await;
            let (set_b, generations_b) = fixture.generation_set(&bundle_b);
            assert!(
                runtime_b
                    .prepare_generation_publication(&set_b, &generations_b)
                    .await
                    .is_err()
            );
            runtime_b.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn generation_publication_unclosed_or_unreleased_a_does_not_admit_b() {
        // A failed close leaves EffectConfirmed; a failed release leaves Closing.
        for (close_recorded, expected_state) in [
            (false, AuthorityOperationState::EffectConfirmed),
            (true, AuthorityOperationState::Closing),
        ] {
            let fixture = PublicationStoreFixture::new().await;
            let bundle_a = publication_bundle(
                &fixture.zone,
                fixture.identity.zone_uid(),
                if close_recorded {
                    "closing"
                } else {
                    "confirmed"
                },
            );
            let bundle_b = publication_bundle(&fixture.zone, fixture.identity.zone_uid(), "b");
            let runtime_a = fixture.open(&bundle_a).await;
            let (set_a, generations_a) = fixture.generation_set(&bundle_a);
            runtime_a
                .prepare_generation_publication(&set_a, &generations_a)
                .await
                .unwrap();
            let binding_digest = runtime_a.store.authority_binding_digest(set_a.as_str());
            let capability = runtime_a
                .store
                .resume_authority_operation(
                    generation_publication_operation_id(&set_a),
                    &binding_digest,
                )
                .await
                .unwrap();
            capability
                .record_effect(AuthorityOperationState::EffectConfirmed)
                .await
                .unwrap();
            if close_recorded {
                capability.record_close().await.unwrap();
            }
            drop(capability);
            assert_eq!(publication_state(&runtime_a, &set_a).await, expected_state);
            runtime_a.shutdown().await.unwrap();

            let runtime_b = fixture.open(&bundle_b).await;
            let (set_b, generations_b) = fixture.generation_set(&bundle_b);
            assert!(
                runtime_b
                    .prepare_generation_publication(&set_b, &generations_b)
                    .await
                    .is_err()
            );
            runtime_b.shutdown().await.unwrap();
        }
    }

    fn committed_provider_resource(name: &str, artifact_id: &str, config: Value) -> StoredResource {
        let zone = ZoneId::parse("work").unwrap();
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let envelope = json!({
            "apiVersion": "resources.d2bus.org/v3",
            "type": "Provider",
            "metadata": {
                "name": name,
                "zone": zone.as_str(),
                "uid": uid.as_str(),
                "generation": 1,
                "revision": 1,
                "ownerRef": null,
                "finalizers": [],
                "deletionRequestedAt": null,
                "createdAt": "2026-07-22T00:00:00.000Z",
                "updatedAt": "2026-07-22T00:00:00.000Z",
                "managedBy": "configuration",
                "configurationGeneration": 1,
            },
            "spec": {
                "artifactId": artifact_id,
                "config": config,
            },
            "status": {
                "completedAt": null,
                "conditions": [],
                "lastReconciledAt": null,
                "observedGeneration": 0,
                "outcome": null,
                "phase": "Pending",
                "resource": {},
                "startedAt": null,
                "update": {
                    "dependencies": {"count": 0, "refs": []},
                    "disruption": "None",
                    "observedGeneration": 0,
                    "lastAssessedAt": null,
                    "observedGeneration": 0,
                    "operationId": null,
                    "owned": {"count": 0, "refs": []},
                    "preserveState": true,
                    "reasons": [],
                    "state": "Unknown",
                    "targetGeneration": 1,
                },
            },
        });
        let canonical_json = d2b_contracts_resource::v3::canonical_json_bytes(&envelope).unwrap();
        let parsed = ResourceEnvelope::from_json(&canonical_json).unwrap();
        StoredResource {
            resource_ref: ResourceRef::parse(&format!("Provider/{name}")).unwrap(),
            zone,
            uid,
            generation: ResourceGeneration::new(1).unwrap(),
            revision: ZoneRevision::new(1),
            canonical_json,
            payload_digest: parsed.digest().unwrap(),
        }
    }

    fn clipboard_provider_config() -> Value {
        json!({
            "controllerExecutionRef": "Host/host-system",
            "hostExecutionRef": "Host/host-system",
            "hostUserRef": "User/alice",
            "displayWaylandRef": "Provider/display-wayland",
            "guestSources": [{"guestRef": "Guest/workstation"}],
        })
    }

    fn notification_provider_config() -> Value {
        json!({
            "controllerExecutionRef": "Host/host-system",
            "hostExecutionRef": "Host/host-system",
            "hostUserRef": "User/alice",
            "displayWaylandRef": "Provider/display-wayland",
            "guestSources": [{
                "guestRef": "Guest/workstation",
                "categories": ["system.info"],
            }],
        })
    }

    #[test]
    fn committed_interaction_provider_configuration_requires_integrity_bound_typed_rows() {
        let zone = ZoneId::parse("work").unwrap();
        let clipboard = committed_provider_resource(
            "clipboard-wayland",
            "clipboard-wayland",
            clipboard_provider_config(),
        );
        let notification = committed_provider_resource(
            "notification-desktop",
            "notification-desktop",
            notification_provider_config(),
        );
        let clipboard =
            parse_committed_clipboard_configuration(&zone, ZoneRevision::new(1), &clipboard)
                .expect("clipboard configuration is accepted");
        let notification =
            parse_committed_notification_configuration(&zone, ZoneRevision::new(1), &notification)
                .expect("notification configuration is accepted");
        let configuration = CommittedInteractionProviderConfiguration {
            clipboard: Some(clipboard),
            notification: Some(notification),
        };

        assert!(configuration.is_complete());
        assert!(
            CommittedInteractionProviderConfiguration {
                clipboard: configuration.clipboard().cloned(),
                notification: None,
            }
            .is_complete()
        );
        assert!(
            CommittedInteractionProviderConfiguration {
                clipboard: None,
                notification: configuration.notification().cloned(),
            }
            .is_complete()
        );
        assert!(
            configuration
                .clipboard()
                .unwrap()
                .allows_guest_source(&ResourceRef::parse("Guest/workstation").unwrap())
        );
        assert_eq!(
            configuration
                .notification()
                .unwrap()
                .config()
                .max_pending_notifications(),
            64
        );
        assert_eq!(
            configuration.notification().unwrap().observer_user_ref(),
            &ResourceRef::parse("User/alice").unwrap()
        );

        let mut mismatched = clipboard_provider_config();
        mismatched["controllerExecutionRef"] = json!("Host/other");
        let mismatched =
            committed_provider_resource("clipboard-wayland", "clipboard-wayland", mismatched);
        assert!(matches!(
            parse_committed_clipboard_configuration(&zone, ZoneRevision::new(1), &mismatched,),
            Err(ResourceRuntimeError::InteractionConfigurationUnavailable)
        ));
    }

    #[test]
    fn generation_publication_marker_binds_one_complete_set_across_restart() {
        let zones = BTreeSet::from([
            ZoneId::parse("local-root").unwrap(),
            ZoneId::parse("work").unwrap(),
        ]);
        let generations = BTreeMap::from([
            (
                ZoneId::parse("local-root").unwrap(),
                ResourceBundleGenerationId::parse("sha256:".to_owned() + &"a".repeat(64)).unwrap(),
            ),
            (
                ZoneId::parse("work").unwrap(),
                ResourceBundleGenerationId::parse("sha256:".to_owned() + &"b".repeat(64)).unwrap(),
            ),
        ]);
        let set_generation =
            complete_generation_set_digest(&zones, &generations).expect("complete generation");
        let binding_digest = "sha256:".to_owned() + &"c".repeat(64);
        let payload =
            generation_publication_payload(&set_generation, &binding_digest, &generations)
                .expect("publication payload");
        assert!(generation_publication_payload_matches(
            &payload,
            &set_generation,
            &binding_digest,
            &generations,
        ));

        let mut recovered: Value = serde_json::from_slice(&payload).expect("payload JSON");
        recovered["state"] = Value::String("effect-confirmed".to_owned());
        let recovered = serde_json::to_vec(&recovered).expect("recovered payload");
        assert!(generation_publication_payload_matches(
            &recovered,
            &set_generation,
            &binding_digest,
            &generations,
        ));

        let mut mixed = generations.clone();
        mixed.insert(
            ZoneId::parse("work").unwrap(),
            ResourceBundleGenerationId::parse("sha256:".to_owned() + &"d".repeat(64)).unwrap(),
        );
        assert!(!generation_publication_payload_matches(
            &recovered,
            &set_generation,
            &binding_digest,
            &mixed,
        ));
    }

    #[test]
    fn committed_interaction_provider_configuration_rejects_tampered_or_invalid_rows() {
        let zone = ZoneId::parse("work").unwrap();
        let mut tampered = committed_provider_resource(
            "clipboard-wayland",
            "clipboard-wayland",
            clipboard_provider_config(),
        );
        tampered.payload_digest = "sha256:tampered".to_owned();
        assert!(matches!(
            parse_committed_clipboard_configuration(&zone, ZoneRevision::new(1), &tampered),
            Err(ResourceRuntimeError::InteractionConfigurationUnavailable)
        ));

        let invalid_guest_source = committed_provider_resource(
            "notification-desktop",
            "notification-desktop",
            json!({
                "controllerExecutionRef": "Host/host-system",
                "hostExecutionRef": "Host/host-system",
                "hostUserRef": "User/alice",
                "displayWaylandRef": "Provider/display-wayland",
                "guestSources": [{
                    "guestRef": "Host/host-system",
                    "categories": ["system.info"],
                }],
            }),
        );
        assert!(matches!(
            parse_committed_notification_configuration(
                &zone,
                ZoneRevision::new(1),
                &invalid_guest_source,
            ),
            Err(ResourceRuntimeError::InteractionConfigurationUnavailable)
        ));
    }

    #[test]
    fn controller_provider_identity_projection_uses_authoritative_uid_generation_and_revision() {
        let zone = ZoneId::parse("work").unwrap();
        let expected_ref = ResourceRef::parse("Provider/runtime-cloud-hypervisor").unwrap();
        let resource = committed_provider_resource(
            "runtime-cloud-hypervisor",
            "runtime-cloud-hypervisor",
            json!({}),
        );
        let (_, uid, generation, revision, digest) =
            committed_provider_spec(&zone, ZoneRevision::new(1), &resource, &expected_ref)
                .expect("committed Provider identity");
        assert_eq!(uid, resource.uid);
        assert_eq!(generation, resource.generation);
        assert_eq!(revision, resource.revision);
        assert_eq!(digest, resource.payload_digest);

        let mut future = resource.clone();
        future.revision = ZoneRevision::new(2);
        assert!(matches!(
            committed_provider_spec(&zone, ZoneRevision::new(1), &future, &expected_ref),
            Err(ResourceRuntimeError::InteractionConfigurationUnavailable)
        ));
    }

    #[test]
    fn controller_session_admission_requires_the_exact_owner_binding() {
        let target = AssignmentTarget::Execution {
            kind: PlacementTargetKind::Host,
            reference: ResourceRef::parse("Host/host-system").unwrap(),
        };
        let first = ControllerSessionBinding::new(
            ResourceRef::parse("Process/controller-first").unwrap(),
            ResourceRef::parse("Provider/runtime-cloud-hypervisor").unwrap(),
            ResourceRef::parse(d2b_provider_runtime_cloud_hypervisor::CONTROLLER_ROLE_REF).unwrap(),
            target.clone(),
            ResourceGeneration::new(2).unwrap(),
            ControllerGeneration::new(3).unwrap(),
            ReconnectGeneration::new(1).unwrap(),
        )
        .unwrap();
        let second = ControllerSessionBinding::new(
            ResourceRef::parse("Process/controller-second").unwrap(),
            ResourceRef::parse("Provider/runtime-cloud-hypervisor").unwrap(),
            ResourceRef::parse(d2b_provider_runtime_cloud_hypervisor::CONTROLLER_ROLE_REF).unwrap(),
            target,
            ResourceGeneration::new(2).unwrap(),
            ControllerGeneration::new(3).unwrap(),
            ReconnectGeneration::new(1).unwrap(),
        )
        .unwrap();

        assert!(controller_session_matches(&first, &first, false));
        assert!(!controller_session_matches(&first, &second, false));
        assert!(!controller_session_matches(&first, &first, true));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn controller_bootstrap_receiver_accepts_one_authenticated_endpoint() {
        let (sender_fd, receiver_fd) = prearmed_seqpacket_pair().unwrap();
        let sender = SeqpacketSocket::from_parent_prearmed(sender_fd).unwrap();
        let receiver = SeqpacketSocket::from_parent_prearmed(receiver_fd).unwrap();
        let (resource_fd, _resource_peer) = prearmed_seqpacket_pair().unwrap();
        let policy = controller_bootstrap_attachment_policy();
        let capacity = AncillaryCapacity::from_policy(policy).unwrap();
        let scopes = CreditScopeSet::new(
            CreditPool::new(8).unwrap(),
            CreditPool::new(8).unwrap(),
            CreditPool::new(8).unwrap(),
            CreditPool::new(8).unwrap(),
            CreditPool::new(8).unwrap(),
            CreditPool::new(8).unwrap(),
        );
        let packet = OutboundPacket::with_current_credentials(
            d2b_session_unix::CONTROLLER_BOOTSTRAP_PROTOCOL_MARKER.to_vec(),
            vec![Arc::new(resource_fd)],
            LimitProfile::local_default(),
            capacity,
            &scopes,
        )
        .unwrap();
        let mut queue = VecDeque::from([packet]);
        assert_eq!(
            sender
                .send_burst(&mut queue, capacity, 2)
                .await
                .unwrap()
                .sent
                .len(),
            1
        );
        let (resource_socket, credentials) = receive_controller_bootstrap(&receiver)
            .await
            .expect("authenticated bootstrap endpoint");
        assert_eq!(
            resource_socket.acceptor_peer_credentials().unwrap(),
            credentials
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn controller_bootstrap_receiver_rejects_extra_packets() {
        let (sender_fd, receiver_fd) = prearmed_seqpacket_pair().unwrap();
        let sender = SeqpacketSocket::from_parent_prearmed(sender_fd).unwrap();
        let receiver = SeqpacketSocket::from_parent_prearmed(receiver_fd).unwrap();
        let policy = controller_bootstrap_attachment_policy();
        let capacity = AncillaryCapacity::from_policy(policy).unwrap();
        let scopes = CreditScopeSet::new(
            CreditPool::new(8).unwrap(),
            CreditPool::new(8).unwrap(),
            CreditPool::new(8).unwrap(),
            CreditPool::new(8).unwrap(),
            CreditPool::new(8).unwrap(),
            CreditPool::new(8).unwrap(),
        );
        let (resource_a, _resource_a_peer) = prearmed_seqpacket_pair().unwrap();
        let (resource_b, _resource_b_peer) = prearmed_seqpacket_pair().unwrap();
        let mut queue = VecDeque::from([
            OutboundPacket::with_current_credentials(
                d2b_session_unix::CONTROLLER_BOOTSTRAP_PROTOCOL_MARKER.to_vec(),
                vec![Arc::new(resource_a)],
                LimitProfile::local_default(),
                capacity,
                &scopes,
            )
            .unwrap(),
            OutboundPacket::with_current_credentials(
                d2b_session_unix::CONTROLLER_BOOTSTRAP_PROTOCOL_MARKER.to_vec(),
                vec![Arc::new(resource_b)],
                LimitProfile::local_default(),
                capacity,
                &scopes,
            )
            .unwrap(),
        ]);
        assert_eq!(
            sender
                .send_burst(&mut queue, capacity, 2)
                .await
                .unwrap()
                .sent
                .len(),
            2
        );
        assert!(matches!(
            receive_controller_bootstrap(&receiver).await,
            Err(ResourceRuntimeError::AuthenticationUnavailable)
        ));
    }

    #[test]
    fn tpm_device_binding_requires_the_authenticated_guest_owner() {
        let matching = json!({ "metadata": { "ownerRef": "Guest/vm-a" } });
        let mismatched = json!({ "metadata": { "ownerRef": "Guest/vm-b" } });
        let absent = json!({ "metadata": {} });

        assert!(ZoneResourceRuntime::tpm_device_targets_vm(
            &matching, "vm-a"
        ));
        assert!(!ZoneResourceRuntime::tpm_device_targets_vm(
            &mismatched,
            "vm-a"
        ));
        assert!(!ZoneResourceRuntime::tpm_device_targets_vm(&absent, "vm-a"));
    }

    #[test]
    fn security_key_device_binding_requires_stored_zone_owner_and_selector() {
        let matching = json!({
            "metadata": { "ownerRef": "Guest/vm-a", "zone": "work" },
            "spec": {
                "providerRef": "Provider/device-security-key",
                "inventory": { "selector": { "label": "key-primary" } }
            }
        });
        let zone = ZoneId::parse("work".to_owned()).unwrap();
        let zone_ref = ResourceRef::parse("Zone/work").unwrap();
        let holder_ref = ResourceRef::parse("Guest/vm-a").unwrap();

        assert!(ZoneResourceRuntime::security_key_device_matches(
            &matching,
            &zone,
            &zone_ref,
            &holder_ref,
            "vm-a",
            "key-primary",
        ));
        assert!(!ZoneResourceRuntime::security_key_device_matches(
            &matching,
            &zone,
            &ResourceRef::parse("Zone/home").unwrap(),
            &holder_ref,
            "vm-a",
            "key-primary",
        ));
        assert!(!ZoneResourceRuntime::security_key_device_matches(
            &matching,
            &zone,
            &zone_ref,
            &ResourceRef::parse("Guest/vm-b").unwrap(),
            "vm-a",
            "key-primary",
        ));
        assert!(!ZoneResourceRuntime::security_key_device_matches(
            &matching,
            &zone,
            &zone_ref,
            &holder_ref,
            "vm-a",
            "key-secondary",
        ));
    }

    #[test]
    fn trusted_bundle_inventory_selects_fresh_or_legacy_tpm_path() {
        let fresh =
            ZoneResourceRuntime::tpm_migration_decision("vm-a", "legacy-swtpm:vm:vm-a", None);
        assert!(!fresh.requires_migration());
        assert!(fresh.validates_binding("vm-a", "legacy-swtpm:vm:vm-a"));

        let legacy = ZoneResourceRuntime::tpm_migration_decision(
            "vm-a",
            "legacy-swtpm:vm:vm-a",
            Some("legacy-swtpm:vm:vm-a"),
        );
        assert!(legacy.requires_migration());
        assert!(legacy.validates_binding("vm-a", "legacy-swtpm:vm:vm-a"));
        assert!(!legacy.validates_binding("vm-b", "legacy-swtpm:vm:vm-a"));
    }

    #[tokio::test]
    async fn production_system_core_probe_returns_bounded_host_observations() {
        let probe = SystemCoreHostProbe::current();
        let metadata = probe
            .metadata()
            .await
            .expect("the local host metadata probe succeeds");
        assert!(!metadata.kernel_release.is_empty());
        assert!(metadata.kernel_release.len() <= 64);
        assert!(metadata.os_name.len() <= 128);
        let platform = probe
            .platform()
            .await
            .expect("the local platform probe succeeds");
        assert!(platform.kernel_major > 0);
        let pidfd = probe
            .probe(HostCapabilityClass::Pidfd)
            .await
            .expect("the pidfd capability probe succeeds");
        assert_eq!(
            pidfd,
            platform.kernel_major > 5 || (platform.kernel_major == 5 && platform.kernel_minor >= 3)
        );
    }

    #[test]
    fn broker_response_requires_one_canonical_zone_store() {
        let response = OpenZoneStoreResponse {
            zone_store_id: d2b_contracts_resource::v3::storage::ZoneStoreId::parse(
                "zone-store-work",
            )
            .unwrap(),
            store_identity: "sha256:".to_owned() + &"a".repeat(64),
            disposition: ZoneStoreDisposition::Opened,
            fd_index: 0,
        };
        assert_eq!(response.fd_index, 0);
        assert!(response.store_identity.starts_with("sha256:"));
    }

    #[test]
    fn opened_fd_is_owned_by_the_runtime_boundary() {
        let (left, right) = nix::sys::socket::socketpair(
            nix::sys::socket::AddressFamily::Unix,
            nix::sys::socket::SockType::SeqPacket,
            None,
            nix::sys::socket::SockFlag::SOCK_CLOEXEC,
        )
        .unwrap();
        assert!(left.as_raw_fd() >= 0);
        drop(right);
        drop(left);
    }

    #[tokio::test]
    async fn production_runtime_opens_and_re_adopts_the_broker_owned_store() {
        let directory = tempfile::tempdir().unwrap();
        let database_path = directory.path().join("store.redb");
        let marker_path = directory.path().join(".d2b-store-marker");
        let zone = ZoneId::parse("work").unwrap();
        let marker_identity = "sha256:".to_owned() + &"b".repeat(64);
        let identity = store_identity(&zone, &marker_identity).unwrap();

        let database = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&database_path)
            .unwrap();
        let mut marker = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&marker_path)
            .unwrap();
        write_provisioning_marker(&mut marker, &identity).unwrap();
        let (_, acceptor) = mutation_seal_pair(identity.seal_identity());
        let provisioned = RedbResourceStore::provision_owned_with_audit(
            database,
            marker,
            identity,
            acceptor,
            test_audit_sink(directory.path(), "audit-provision"),
        )
        .await
        .unwrap();
        provisioned.shutdown().await.unwrap();

        let database = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&database_path)
            .unwrap();
        let fd = database.as_raw_fd();
        assert!(
            rustix::io::fcntl_getfd(&database)
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
        let runtime = ZoneResourceRuntime::open(
            zone.clone(),
            OpenedZoneStore {
                response: OpenZoneStoreResponse {
                    zone_store_id: d2b_contracts_resource::v3::storage::ZoneStoreId::parse(
                        "zone-store-work",
                    )
                    .unwrap(),
                    store_identity: marker_identity.clone(),
                    disposition: ZoneStoreDisposition::Opened,
                    fd_index: 0,
                },
                database_fd: database.into(),
                external_inventory: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(runtime.zone(), &zone);
        assert!(runtime.readiness().store_ready);
        assert!(!runtime.readiness().resource_api_ready);
        assert!(!runtime.readiness().local_session_ready);
        assert!(!runtime.readiness().provider_path_ready);
        assert_eq!(
            runtime.core_stage().unwrap(),
            StartupStage::WaitingForResourceApi
        );
        assert_eq!(
            runtime.readiness_error(),
            Some(ResourceRuntimeError::PolicyUnavailable)
        );
        let zone_status = runtime
            .dispatch_cli_request(&json!({
                "method": "ZoneStatus",
                "zoneRef": "Zone/work",
            }))
            .await
            .unwrap();
        assert_eq!(zone_status["type"], "error");
        assert_eq!(zone_status["error"]["kind"], "authorization-denied");
        let list = runtime
            .dispatch_cli_request(&json!({
                "method": "List",
                "zoneRef": "Zone/work",
                "resourceType": "Guest",
            }))
            .await
            .unwrap();
        assert_eq!(list["type"], "error");
        assert_eq!(list["error"]["kind"], "authorization-denied");
        assert_eq!(list["error"]["retryClass"], "reauthorize");
        let watch = runtime
            .dispatch_cli_request(&json!({
                "method": "Watch",
                "zoneRef": "Zone/work",
                "resourceType": "Guest",
            }))
            .await
            .unwrap();
        assert_eq!(watch["error"]["kind"], "authorization-denied");
        let status = runtime
            .dispatch_cli_request(&json!({
                "method": "Status",
                "zoneRef": "Zone/work",
                "resourceRef": "Guest/corp-vm",
            }))
            .await
            .unwrap();
        assert_eq!(status["error"]["kind"], "authorization-denied");
        runtime.shutdown().await.unwrap();
        assert!(fd >= 0);
    }

    #[tokio::test]
    async fn production_runtime_provisions_a_broker_provisioned_store() {
        let directory = tempfile::tempdir().unwrap();
        let database_path = directory.path().join("store.redb");
        let database = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&database_path)
            .unwrap();
        let zone = ZoneId::parse("work").unwrap();
        let marker_identity = "sha256:".to_owned() + &"c".repeat(64);
        let runtime = ZoneResourceRuntime::open(
            zone,
            OpenedZoneStore {
                response: OpenZoneStoreResponse {
                    zone_store_id: d2b_contracts_resource::v3::storage::ZoneStoreId::parse(
                        "zone-store-work",
                    )
                    .unwrap(),
                    store_identity: marker_identity,
                    disposition: ZoneStoreDisposition::Provisioned,
                    fd_index: 0,
                },
                database_fd: database.into(),
                external_inventory: None,
            },
        )
        .await
        .unwrap();
        assert!(runtime.readiness().store_ready);
        assert!(!runtime.readiness().resource_api_ready);
        let mut plane = ResourcePlane::new();
        let owner = plane.insert(runtime).unwrap();
        assert_eq!(plane.ready_zone_count(), 0);
        assert!(plane.has_live_request_owners());
        assert_eq!(
            plane.shutdown().await,
            Err(ResourceRuntimeError::LiveRequestOwners)
        );
        assert!(plane.has_live_request_owners());
        drop(owner);
        assert!(!plane.has_live_request_owners());
        plane.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn production_runtime_rejects_immutable_store_identity_mismatch() {
        let directory = tempfile::tempdir().unwrap();
        let database_path = directory.path().join("store.redb");
        let marker_path = directory.path().join(".d2b-store-marker");
        let zone = ZoneId::parse("work").unwrap();
        let stored_identity = "sha256:".to_owned() + &"e".repeat(64);
        let identity = store_identity(&zone, &stored_identity).unwrap();
        let database = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&database_path)
            .unwrap();
        let mut marker = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&marker_path)
            .unwrap();
        write_provisioning_marker(&mut marker, &identity).unwrap();
        let provisioned = RedbResourceStore::provision_owned_with_audit(
            database,
            marker,
            identity,
            mutation_seal_pair(
                store_identity(&zone, &stored_identity)
                    .unwrap()
                    .seal_identity(),
            )
            .1,
            test_audit_sink(directory.path(), "audit-mismatch"),
        )
        .await
        .unwrap();
        provisioned.shutdown().await.unwrap();

        let database = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&database_path)
            .unwrap();
        let result = ZoneResourceRuntime::open(
            zone,
            OpenedZoneStore {
                response: OpenZoneStoreResponse {
                    zone_store_id: d2b_contracts_resource::v3::storage::ZoneStoreId::parse(
                        "zone-store-work",
                    )
                    .unwrap(),
                    store_identity: "sha256:".to_owned() + &"f".repeat(64),
                    disposition: ZoneStoreDisposition::Opened,
                    fd_index: 0,
                },
                database_fd: database.into(),
                external_inventory: None,
            },
        )
        .await;
        assert!(matches!(result, Err(ResourceRuntimeError::StoreOpenFailed)));
    }

    #[tokio::test]
    async fn public_reads_use_authenticated_session_after_restart_revisions_rehydrate() {
        let directory = tempfile::tempdir().unwrap();
        let database_path = directory.path().join("store.redb");
        let zone = ZoneId::parse("work").unwrap();
        let marker_identity = "sha256:".to_owned() + &"d".repeat(64);
        let revisions = PolicySnapshot {
            policy_revision: 7,
            api_catalog_revision: 8,
            active_configuration_revision: ConfigurationGeneration::new(9).unwrap(),
            controller_generation: Some(ControllerGeneration::new(10).unwrap()),
        };
        let identity = store_identity(&zone, &marker_identity)
            .unwrap()
            .with_revisions(revisions);

        let database = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&database_path)
            .unwrap();
        let mut marker = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(directory.path().join(".d2b-store-marker"))
            .unwrap();
        write_provisioning_marker(&mut marker, &identity).unwrap();
        let provisioned = RedbResourceStore::provision_owned_with_audit(
            database,
            marker,
            identity,
            mutation_seal_pair(
                store_identity(&zone, &marker_identity)
                    .unwrap()
                    .with_revisions(revisions)
                    .seal_identity(),
            )
            .1,
            test_audit_sink(directory.path(), "audit-rehydrate"),
        )
        .await
        .unwrap();
        provisioned.shutdown().await.unwrap();

        let database = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&database_path)
            .unwrap();
        let runtime = ZoneResourceRuntime::open(
            zone.clone(),
            OpenedZoneStore {
                response: OpenZoneStoreResponse {
                    zone_store_id: d2b_contracts_resource::v3::storage::ZoneStoreId::parse(
                        "zone-store-work",
                    )
                    .unwrap(),
                    store_identity: marker_identity,
                    disposition: ZoneStoreDisposition::Opened,
                    fd_index: 0,
                },
                database_fd: database.into(),
                external_inventory: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(runtime.store_metadata.policy_snapshot, revisions);

        let forged_claim = runtime
            .dispatch_public_cli_request(
                &json!({
                    "method": "List",
                    "zoneRef": "Zone/work",
                    "resourceType": "Host",
                    "subjectRef": "User/alice",
                }),
                1000,
            )
            .await
            .unwrap_err();
        assert_eq!(forged_claim, ResourceRuntimeError::RequestInvalid);

        let peer_route = runtime
            .dispatch_public_cli_request(
                &json!({
                    "method": "List",
                    "zoneRef": "Zone/work",
                    "resourceType": "Host",
                }),
                1000,
            )
            .await
            .unwrap_err();
        assert_eq!(peer_route.code(), "resource-runtime-identity-unbound");
        runtime.shutdown().await.unwrap();
    }

    fn network_admission_intent(
        zone: &str,
        network: &str,
        lan: &str,
        uplink: &str,
    ) -> NetworkAdmissionIntent {
        let zone_uid = ResourceUid::parse(zone).unwrap();
        let network_uid = ResourceUid::parse(network).unwrap();
        let spec = d2b_contracts_resource::v3::network::NetworkSpec::minimal(
            d2b_contracts_resource::v3::network::Ipv4Cidr::parse(lan).unwrap(),
            d2b_contracts_resource::v3::network::Ipv4Cidr::parse(uplink).unwrap(),
            d2b_contracts_resource::v3::execution_policy::BoundedToken::parse("net-vm-base")
                .unwrap(),
        )
        .unwrap();
        NetworkAdmissionIntent::new(
            NetworkAdmissionKey::new(
                zone_uid,
                network_uid,
                ResourceGeneration::new(1).unwrap(),
                ResourceGeneration::new(1).unwrap(),
                ResourceBundleGenerationId::parse(
                    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                )
                .unwrap(),
            ),
            spec,
            Vec::new(),
        )
        .unwrap()
    }

    fn external_network_admission_intent(
        zone: &str,
        network: &str,
        lan: &str,
        uplink: &str,
        sharing: d2b_contracts_resource::v3::network::SharingPolicy,
    ) -> NetworkAdmissionIntent {
        let zone_uid = ResourceUid::parse(zone).unwrap();
        let network_uid = ResourceUid::parse(network).unwrap();
        let external = d2b_contracts_resource::v3::network::ExternalAttachmentSpec::new(
            d2b_contracts_resource::v3::network::ExternalAttachmentMode::Macvtap,
            d2b_contracts_resource::v3::IfName::parse("eno1").unwrap(),
            d2b_contracts_resource::v3::network::MacvtapMode::Bridge,
            sharing,
            None,
            d2b_contracts_resource::v3::network::ExternalIpv4Spec::default(),
            d2b_contracts_resource::v3::network::EgressSpec::default(),
            Vec::new(),
        )
        .unwrap();
        let spec = d2b_contracts_resource::v3::network::NetworkSpec::new(
            d2b_contracts_resource::v3::network::Ipv4Cidr::parse(lan).unwrap(),
            d2b_contracts_resource::v3::network::Ipv4Cidr::parse(uplink).unwrap(),
            None,
            false,
            d2b_contracts_resource::v3::network::IsolationSpec::default(),
            d2b_contracts_resource::v3::network::RoutingSpec::default(),
            d2b_contracts_resource::v3::network::DhcpSpec::default(),
            d2b_contracts_resource::v3::network::DnsSpec::default(),
            Some(external),
            d2b_contracts_resource::v3::network::MdnsSpec::default(),
            None,
            d2b_contracts_resource::v3::execution_policy::BoundedToken::parse("net-vm-base")
                .unwrap(),
            Vec::new(),
        )
        .unwrap();
        NetworkAdmissionIntent::new(
            NetworkAdmissionKey::new(
                zone_uid,
                network_uid,
                ResourceGeneration::new(1).unwrap(),
                ResourceGeneration::new(1).unwrap(),
                ResourceBundleGenerationId::parse(
                    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                )
                .unwrap(),
            ),
            spec,
            Vec::new(),
        )
        .unwrap()
    }

    fn newer_network_admission_intent(current: &NetworkAdmissionIntent) -> NetworkAdmissionIntent {
        let key = NetworkAdmissionKey::new(
            current.key().zone_uid().clone(),
            current.key().network_uid().clone(),
            ResourceGeneration::new(current.key().network_generation().get() + 1).unwrap(),
            ResourceGeneration::new(current.key().attachment_generation().get() + 1).unwrap(),
            ResourceBundleGenerationId::parse(
                "sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
            )
            .unwrap(),
        );
        let spec = d2b_contracts_resource::v3::network::NetworkSpec::minimal(
            d2b_contracts_resource::v3::network::Ipv4Cidr::parse("10.20.0.0/24").unwrap(),
            d2b_contracts_resource::v3::network::Ipv4Cidr::parse("192.0.2.0/30").unwrap(),
            d2b_contracts_resource::v3::execution_policy::BoundedToken::parse("net-vm-base")
                .unwrap(),
        )
        .unwrap();
        NetworkAdmissionIntent::new(key, spec, Vec::new()).unwrap()
    }

    fn self_owned_occupancy(intent: &NetworkAdmissionIntent) -> HostNetworkOccupancy {
        let interface_markers = intent
            .interface_names()
            .iter()
            .filter_map(|ifname| {
                intent
                    .interface_ownership_marker(ifname)
                    .map(|marker| (ifname.clone(), marker.to_owned()))
            })
            .collect::<Vec<_>>();
        let route_markers = intent
            .routes()
            .iter()
            .filter_map(|route| {
                intent
                    .route_ownership_marker(route)
                    .map(|marker| (route.clone(), marker.to_owned()))
            })
            .collect::<Vec<_>>();
        let cidr_markers = intent
            .cidrs()
            .iter()
            .map(|cidr| (cidr.clone(), intent.ownership_marker().to_owned()))
            .collect::<Vec<_>>();
        HostNetworkOccupancy::from_route_tuples(
            intent.interface_names().to_vec(),
            intent.route_names().to_vec(),
            intent.routes().to_vec(),
            intent.cidrs().to_vec(),
        )
        .with_interface_ownership(interface_markers)
        .with_route_ownership(route_markers)
        .with_cidr_ownership(cidr_markers)
    }

    fn self_owned_kernel_occupancy(intent: &NetworkAdmissionIntent) -> HostNetworkOccupancy {
        let interface_markers = intent
            .interface_names()
            .iter()
            .filter_map(|ifname| {
                intent
                    .interface_ownership_marker(ifname)
                    .map(|marker| (ifname.clone(), marker.to_owned()))
            })
            .collect::<Vec<_>>();
        let route_markers = intent
            .routes()
            .iter()
            .filter_map(|route| {
                intent
                    .route_ownership_marker(route)
                    .map(|marker| (route.clone(), marker.to_owned()))
            })
            .collect::<Vec<_>>();
        let cidrs = vec![
            d2b_contracts_resource::v3::network::Ipv4Cidr::parse("10.20.0.1/24").unwrap(),
            d2b_contracts_resource::v3::network::Ipv4Cidr::parse("192.0.2.1/30").unwrap(),
        ];
        let cidr_markers = cidrs
            .iter()
            .map(|cidr| (cidr.clone(), intent.ownership_marker().to_owned()))
            .collect::<Vec<_>>();
        HostNetworkOccupancy::from_route_tuples(
            intent.interface_names().to_vec(),
            intent.route_names().to_vec(),
            intent.routes().to_vec(),
            cidrs,
        )
        .with_interface_ownership(interface_markers)
        .with_route_ownership(route_markers)
        .with_cidr_ownership(cidr_markers)
    }

    #[test]
    fn host_network_admission_rejects_overlapping_sibling_cidrs_atomically() {
        let mut index = HostNetworkAdmissionIndex::default();
        let first = network_admission_intent(
            "123e4567-e89b-42d3-a456-426614174000",
            "223e4567-e89b-42d3-a456-426614174001",
            "10.20.0.0/24",
            "192.0.2.0/30",
        );
        let second = network_admission_intent(
            "323e4567-e89b-42d3-a456-426614174002",
            "423e4567-e89b-42d3-a456-426614174003",
            "10.20.0.0/24",
            "198.51.100.0/30",
        );
        let occupancy = HostNetworkOccupancy::from_parts(Vec::new(), Vec::new(), Vec::new());
        index.admit(first, &occupancy).unwrap();
        assert_eq!(
            index.admit(second, &occupancy),
            Err(NetworkEffectError::CidrConflict)
        );
        assert_eq!(index.len(), 1);
    }

    #[test]
    fn host_network_admission_names_same_named_networks_by_uid() {
        let first = network_admission_intent(
            "123e4567-e89b-42d3-a456-426614174000",
            "223e4567-e89b-42d3-a456-426614174001",
            "10.20.0.0/24",
            "192.0.2.0/30",
        );
        let second = network_admission_intent(
            "323e4567-e89b-42d3-a456-426614174002",
            "423e4567-e89b-42d3-a456-426614174003",
            "10.30.0.0/24",
            "198.51.100.0/30",
        );
        assert_ne!(first.interface_names(), second.interface_names());
        assert_ne!(first.route_names(), second.route_names());
    }

    #[test]
    fn host_network_admission_counts_foreign_and_uidless_occupancy() {
        let mut index = HostNetworkAdmissionIndex::default();
        let intent = network_admission_intent(
            "123e4567-e89b-42d3-a456-426614174000",
            "223e4567-e89b-42d3-a456-426614174001",
            "10.20.0.0/24",
            "192.0.2.0/30",
        );
        let occupied = HostNetworkOccupancy::from_parts(
            vec![intent.interface_names()[0].clone()],
            vec![intent.route_names()[0].clone()],
            Vec::new(),
        );
        assert_eq!(
            index.admit(intent, &occupied),
            Err(NetworkEffectError::NetworkInterfaceCollision)
        );
        assert!(index.is_empty());
    }

    #[test]
    fn host_network_admission_counts_foreign_cidr_occupancy() {
        let mut index = HostNetworkAdmissionIndex::default();
        let intent = network_admission_intent(
            "123e4567-e89b-42d3-a456-426614174000",
            "223e4567-e89b-42d3-a456-426614174001",
            "10.20.0.0/24",
            "192.0.2.0/30",
        );
        let occupied = HostNetworkOccupancy::from_parts(
            Vec::new(),
            Vec::new(),
            vec![d2b_contracts_resource::v3::network::Ipv4Cidr::parse("10.20.1.0/23").unwrap()],
        );
        assert_eq!(
            index.admit(intent, &occupied),
            Err(NetworkEffectError::CidrConflict)
        );
        assert!(index.is_empty());
    }

    #[test]
    fn host_network_admission_counts_actual_route_tuple_occupancy() {
        let mut index = HostNetworkAdmissionIndex::default();
        let intent = network_admission_intent(
            "123e4567-e89b-42d3-a456-426614174000",
            "223e4567-e89b-42d3-a456-426614174001",
            "10.20.0.0/24",
            "192.0.2.0/30",
        );
        let occupied = HostNetworkOccupancy::from_route_tuples(
            Vec::new(),
            Vec::new(),
            vec![RouteTuple::new(
                "10.0.0.0/8",
                Some("192.0.2.1".to_owned()),
                Some(intent.routes()[0].device().unwrap_or("-").to_owned()),
                "254",
            )],
            Vec::new(),
        );
        assert_eq!(
            index.admit(intent, &occupied),
            Err(NetworkEffectError::NetworkRouteCollision)
        );
        assert!(index.is_empty());
    }

    #[test]
    fn host_network_admission_ignores_synthetic_route_ids_without_observed_tuple() {
        let mut index = HostNetworkAdmissionIndex::default();
        let intent = network_admission_intent(
            "123e4567-e89b-42d3-a456-426614174000",
            "223e4567-e89b-42d3-a456-426614174001",
            "10.20.0.0/24",
            "192.0.2.0/30",
        );
        let occupancy = HostNetworkOccupancy::from_parts(
            Vec::new(),
            vec![intent.route_names()[0].clone()],
            Vec::new(),
        );
        assert!(
            occupancy.routes().is_empty(),
            "a synthetic route name is not an observed kernel route tuple"
        );
        assert!(index.admit(intent, &occupancy).is_ok());
    }

    #[test]
    fn host_network_admission_scopes_route_collisions_by_actual_table() {
        let mut index = HostNetworkAdmissionIndex::default();
        let intent = network_admission_intent(
            "123e4567-e89b-42d3-a456-426614174000",
            "223e4567-e89b-42d3-a456-426614174001",
            "10.20.0.0/24",
            "192.0.2.0/30",
        );
        let occupied = HostNetworkOccupancy::from_route_tuples(
            Vec::new(),
            Vec::new(),
            vec![RouteTuple::new(
                "10.0.0.0/8",
                Some("192.0.2.1".to_owned()),
                Some("foreign0".to_owned()),
                "100",
            )],
            Vec::new(),
        );
        assert!(index.admit(intent, &occupied).is_ok());
    }

    #[test]
    fn host_network_admission_rejects_stale_network_generation() {
        let mut index = HostNetworkAdmissionIndex::default();
        let stale = network_admission_intent(
            "123e4567-e89b-42d3-a456-426614174000",
            "223e4567-e89b-42d3-a456-426614174001",
            "10.20.0.0/24",
            "192.0.2.0/30",
        );
        let current = newer_network_admission_intent(&stale);
        let occupancy = HostNetworkOccupancy::from_parts(Vec::new(), Vec::new(), Vec::new());
        index.admit(current, &occupancy).unwrap();
        assert_eq!(
            index.admit(stale, &occupancy),
            Err(NetworkEffectError::NetworkAdmissionMismatch)
        );
    }

    #[test]
    fn host_network_admission_replaces_owner_and_ignores_self_owned_occupancy() {
        let mut index = HostNetworkAdmissionIndex::default();
        let first = network_admission_intent(
            "123e4567-e89b-42d3-a456-426614174000",
            "223e4567-e89b-42d3-a456-426614174001",
            "10.20.0.0/24",
            "192.0.2.0/30",
        );
        let occupancy = self_owned_kernel_occupancy(&first);
        let newer = newer_network_admission_intent(&first);

        index.admit(first, &occupancy).unwrap();
        let proof = index.admit(newer.clone(), &occupancy).unwrap();

        assert_eq!(proof.key(), newer.key());
        assert_eq!(index.len(), 1);
        assert_eq!(
            index
                .proof_for(newer.key().zone_uid(), newer.key().network_uid())
                .unwrap()
                .key(),
            newer.key()
        );
        assert_eq!(
            index.admit(newer.clone(), &occupancy).unwrap().key(),
            newer.key()
        );
        assert_eq!(
            index.admit(newer.clone(), &occupancy).unwrap().key(),
            newer.key()
        );
    }

    #[test]
    fn host_network_admission_rejects_stale_replacement_and_sibling_overlap_atomically() {
        let mut index = HostNetworkAdmissionIndex::default();
        let first = network_admission_intent(
            "123e4567-e89b-42d3-a456-426614174000",
            "223e4567-e89b-42d3-a456-426614174001",
            "10.20.0.0/24",
            "192.0.2.0/30",
        );
        let newer = newer_network_admission_intent(&first);
        let sibling = network_admission_intent(
            "323e4567-e89b-42d3-a456-426614174002",
            "423e4567-e89b-42d3-a456-426614174003",
            "10.20.0.0/24",
            "198.51.100.0/30",
        );
        let occupancy = self_owned_occupancy(&first);

        index.admit(first.clone(), &occupancy).unwrap();
        index.admit(newer.clone(), &occupancy).unwrap();
        assert_eq!(
            index.admit(first, &occupancy),
            Err(NetworkEffectError::NetworkAdmissionMismatch)
        );
        assert_eq!(
            index.admit(
                sibling,
                &HostNetworkOccupancy::from_parts(Vec::new(), Vec::new(), Vec::new()),
            ),
            Err(NetworkEffectError::CidrConflict)
        );
        assert_eq!(index.len(), 1);
        assert_eq!(
            index
                .proof_for(newer.key().zone_uid(), newer.key().network_uid())
                .unwrap()
                .key(),
            newer.key()
        );
    }

    #[tokio::test]
    async fn host_network_admission_serializes_replacement_and_sibling_conflicts() {
        let first = network_admission_intent(
            "123e4567-e89b-42d3-a456-426614174000",
            "223e4567-e89b-42d3-a456-426614174001",
            "10.20.0.0/24",
            "192.0.2.0/30",
        );
        let newer = newer_network_admission_intent(&first);
        let sibling = network_admission_intent(
            "323e4567-e89b-42d3-a456-426614174002",
            "423e4567-e89b-42d3-a456-426614174003",
            "10.20.0.0/24",
            "198.51.100.0/30",
        );
        let mut initial = HostNetworkAdmissionIndex::default();
        initial
            .admit(
                first.clone(),
                &HostNetworkOccupancy::from_parts(Vec::new(), Vec::new(), Vec::new()),
            )
            .unwrap();
        let index = Arc::new(tokio::sync::Mutex::new(initial));
        let replacement_index = Arc::clone(&index);
        let sibling_index = Arc::clone(&index);
        let replacement_occupancy = self_owned_kernel_occupancy(&first);
        let sibling_occupancy =
            HostNetworkOccupancy::from_parts(Vec::new(), Vec::new(), Vec::new());
        let (replacement, sibling) = tokio::join!(
            async move {
                replacement_index
                    .lock()
                    .await
                    .admit(newer, &replacement_occupancy)
            },
            async move {
                sibling_index
                    .lock()
                    .await
                    .admit(sibling, &sibling_occupancy)
            },
        );
        assert!(replacement.is_ok());
        assert_eq!(sibling, Err(NetworkEffectError::CidrConflict));
        assert_eq!(index.lock().await.len(), 1);
    }

    #[test]
    fn host_network_admission_releases_only_after_confirmed_finalizer_completion() {
        let mut index = HostNetworkAdmissionIndex::default();
        let first = network_admission_intent(
            "123e4567-e89b-42d3-a456-426614174000",
            "223e4567-e89b-42d3-a456-426614174001",
            "10.20.0.0/24",
            "192.0.2.0/30",
        );
        let newer = newer_network_admission_intent(&first);
        let successor = newer_network_admission_intent(&newer);
        let occupancy = self_owned_occupancy(&first);
        index.admit(first.clone(), &occupancy).unwrap();

        assert!(!index.release_after_finalizer(first.key(), false));
        assert_eq!(index.len(), 1);
        assert!(index.admit(newer.clone(), &occupancy).is_ok());
        assert_eq!(index.len(), 1);
        assert!(!index.release_after_finalizer(first.key(), true));
        assert!(index.release_after_finalizer(newer.key(), true));
        assert!(index.is_empty());
        assert_eq!(
            index.admit(
                first,
                &HostNetworkOccupancy::from_parts(Vec::new(), Vec::new(), Vec::new()),
            ),
            Err(NetworkEffectError::NetworkAdmissionMismatch)
        );
        assert!(
            index
                .admit(
                    successor,
                    &HostNetworkOccupancy::from_parts(Vec::new(), Vec::new(), Vec::new()),
                )
                .is_ok()
        );
    }

    #[test]
    fn host_network_admission_rejects_unmarked_or_mismatched_identical_occupancy() {
        let first = network_admission_intent(
            "123e4567-e89b-42d3-a456-426614174000",
            "223e4567-e89b-42d3-a456-426614174001",
            "10.20.0.0/24",
            "192.0.2.0/30",
        );
        let newer = newer_network_admission_intent(&first);
        let unmarked = HostNetworkOccupancy::from_route_tuples(
            first.interface_names().to_vec(),
            first.route_names().to_vec(),
            first.routes().to_vec(),
            first.cidrs().to_vec(),
        );
        let mut index = HostNetworkAdmissionIndex::default();
        index
            .admit(
                first.clone(),
                &HostNetworkOccupancy::from_parts(Vec::new(), Vec::new(), Vec::new()),
            )
            .unwrap();
        assert_eq!(
            index.admit(newer.clone(), &unmarked),
            Err(NetworkEffectError::CidrConflict)
        );

        let mut mismatched = self_owned_occupancy(&first);
        mismatched = mismatched.with_interface_ownership(vec![(
            first.interface_names()[0].clone(),
            "d2b managed: network:bridge:lan:zone:123e4567-e89b-42d3-a456-426614174000:network:223e4567-e89b-42d3-a456-426614174001:generation:99:attachment:99:bundle:sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
        )]);
        let mut index = HostNetworkAdmissionIndex::default();
        index
            .admit(
                first.clone(),
                &HostNetworkOccupancy::from_parts(Vec::new(), Vec::new(), Vec::new()),
            )
            .unwrap();
        assert_eq!(
            index.admit(newer.clone(), &mismatched),
            Err(NetworkEffectError::NetworkInterfaceCollision)
        );

        let mut mismatched_route = self_owned_occupancy(&first);
        mismatched_route = mismatched_route.with_route_ownership(vec![(
            first.routes()[0].clone(),
            "d2b managed: foreign".to_owned(),
        )]);
        let mut index = HostNetworkAdmissionIndex::default();
        index
            .admit(
                first,
                &HostNetworkOccupancy::from_parts(Vec::new(), Vec::new(), Vec::new()),
            )
            .unwrap();
        let route_candidate = newer_network_admission_intent(&newer);
        assert_eq!(
            index.admit(route_candidate, &mismatched_route),
            Err(NetworkEffectError::NetworkRouteCollision)
        );
    }

    #[test]
    fn host_network_admission_rejects_cross_zone_external_bridge_multiplex() {
        let mut index = HostNetworkAdmissionIndex::default();
        let first = external_network_admission_intent(
            "123e4567-e89b-42d3-a456-426614174000",
            "223e4567-e89b-42d3-a456-426614174001",
            "10.20.0.0/24",
            "192.0.2.0/30",
            d2b_contracts_resource::v3::network::SharingPolicy::Multiplexed,
        );
        let second = external_network_admission_intent(
            "323e4567-e89b-42d3-a456-426614174002",
            "423e4567-e89b-42d3-a456-426614174003",
            "10.30.0.0/24",
            "198.51.100.0/30",
            d2b_contracts_resource::v3::network::SharingPolicy::Multiplexed,
        );
        let occupancy = HostNetworkOccupancy::from_parts(Vec::new(), Vec::new(), Vec::new());
        index.admit(first, &occupancy).unwrap();
        assert_eq!(
            index.admit(second, &occupancy),
            Err(NetworkEffectError::CrossZoneL2)
        );
    }

    #[test]
    fn host_network_admission_rejects_same_zone_exclusive_external_reuse() {
        let mut index = HostNetworkAdmissionIndex::default();
        let first = external_network_admission_intent(
            "123e4567-e89b-42d3-a456-426614174000",
            "223e4567-e89b-42d3-a456-426614174001",
            "10.20.0.0/24",
            "192.0.2.0/30",
            d2b_contracts_resource::v3::network::SharingPolicy::Exclusive,
        );
        let second = external_network_admission_intent(
            "123e4567-e89b-42d3-a456-426614174000",
            "423e4567-e89b-42d3-a456-426614174003",
            "10.30.0.0/24",
            "198.51.100.0/30",
            d2b_contracts_resource::v3::network::SharingPolicy::Exclusive,
        );
        let occupancy = HostNetworkOccupancy::from_parts(Vec::new(), Vec::new(), Vec::new());
        index.admit(first, &occupancy).unwrap();
        assert_eq!(
            index.admit(second, &occupancy),
            Err(NetworkEffectError::NetworkAdmissionConflict)
        );
    }

    #[test]
    fn qemu_controller_contract_invokes_controller_and_finalizes() {
        let guest_ref = ResourceRef::parse("Guest/qemu").unwrap();
        let config = qemu_media_runtime::ProviderConfig::new(
            "Host/host-system",
            "qemu-system-x86-64",
            "Provider/network-local",
            "Provider/volume-local",
            None,
        )
        .unwrap();
        let process = qemu_media_runtime::build_process_spec(
            config.controller_execution_ref.clone(),
            ResourceRef::parse("Volume/qemu-runtime").unwrap(),
            Some(ResourceRef::parse("Device/host-kvm").unwrap()),
            [],
        )
        .unwrap();
        let mut controller = qemu_media_runtime::QemuMediaController::new(
            config,
            qemu_media_runtime::GuestProviderSpecSettings::default(),
            process,
            guest_ref.clone(),
        )
        .unwrap();
        let mut effect = FrameworkQemuEffect::new(guest_ref.clone());
        let dependencies = qemu_media_runtime::QemuMediaDependencies::ready(
            qemu_media_runtime::DeviceObservation {
                device_ref: ResourceRef::parse("Device/host-kvm").unwrap(),
                phase: qemu_media_runtime::DevicePhase::Ready,
                owner_ref: None,
                platform: qemu_media_runtime::PlatformClass::X86_64Linux,
                authority_key: [1; 32],
                process_identity: Some("qemu-media-runner".to_owned()),
                media_contract: "qemu-media/v1".to_owned(),
            },
        );
        assert_eq!(
            controller.reconcile(&dependencies, &mut effect).unwrap(),
            qemu_media_runtime::QemuMediaReconcileOutcome::Ready
        );
        assert_eq!(controller.phase(), qemu_media_runtime::QemuMediaPhase::PausedAtBoot);
        controller.finalize(&mut effect).unwrap();
        assert!(!controller.finalizer_installed());
    }

    #[test]
    fn qemu_guest_child_graph_contains_one_runtime_volume_and_process() {
        let owner = ResourceRef::parse("Guest/qemu").unwrap();
        let guest = json!({
            "spec": {
                "deviceAttachments": [{"deviceRef": "Device/host-kvm"}],
                "networkAttachments": [],
                "provider": {
                    "settings": serde_json::to_value(
                        qemu_media_runtime::GuestProviderSpecSettings::default()
                    )
                    .unwrap()
                }
            }
        });
        let provider_config = serde_json::to_value(
            qemu_media_runtime::ProviderConfig::new(
                "Host/host-system",
                "qemu-system-x86-64",
                "Provider/network-local",
                "Provider/volume-local",
                None,
            )
            .unwrap(),
        )
        .unwrap();
        let provider = json!({
            "spec": {
                "config": provider_config
            }
        });
        let children = DaemonSharedProviderEffects::qemu_guest_children(
            &guest,
            &provider,
            &owner,
            &ZoneId::parse("work").unwrap(),
        )
        .unwrap();
        assert_eq!(
            children
                .iter()
                .map(|child| child.target().resource_type().as_str())
                .collect::<Vec<_>>(),
            vec!["Volume", "Process"]
        );
        assert_eq!(
            children[1].dependencies(),
            &BTreeSet::from([ResourceRef::parse("Volume/qemu-runtime").unwrap()])
        );
    }

    #[tokio::test]
    async fn aca_controller_contract_invokes_controller_and_finalizes() {
        let profile = aca_runtime::AcaSandboxProfile::new(
            aca_runtime::AcaProfileId::parse("default").unwrap(),
            aca_runtime::AcaDiskImageSource::ConfiguredDisk {
                binding_id: aca_runtime::AcaConfiguredDiskId::parse("image-1").unwrap(),
            },
            aca_runtime::AcaCpuMillis::new(500).unwrap(),
            aca_runtime::AcaMemoryMib::new(2_048).unwrap(),
            300,
            None,
        )
        .unwrap();
        let defaults = aca_runtime::AcaRuntimeConfig::new(
            profile,
            aca_runtime::AcaReadinessPolicy::new(3, 10).unwrap(),
            1_000,
            4,
        )
        .unwrap();
        let config = aca_runtime::AcaProviderConfig::new(
            ResourceRef::parse("Guest/gateway").unwrap(),
            aca_runtime::OpaqueAzureRef::parse("tenant").unwrap(),
            aca_runtime::OpaqueAzureRef::parse("client").unwrap(),
            aca_runtime::OpaqueAzureRef::parse("subscription").unwrap(),
            ResourceRef::parse("Credential/control").unwrap(),
            None,
            aca_runtime::AcaConfiguredImageId::parse("environment").unwrap(),
            aca_runtime::AcaConfiguredImageId::parse("resource-group").unwrap(),
            None,
            aca_runtime::AcaProfileId::parse("relay").unwrap(),
            defaults,
        )
        .unwrap();
        let controller = aca_runtime::AzureContainerAppsRuntimeProvider::new(
            config,
            Arc::new(FrameworkAcaControl {
                state: Arc::new(tokio::sync::Mutex::new(FrameworkAcaState::new(1))),
            }),
            Arc::new(FrameworkAcaLease),
        )
        .unwrap()
        .controller(aca_runtime::AcaResourceBinding {
            guest_uid: ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap(),
            provider_generation: 1,
            config_fingerprint: [2; 32],
        });
        let mut controller = GuestRuntimeController::Aca { controller };
        let GuestRuntimeController::Aca { controller } = &mut controller else {
            unreachable!();
        };
        let operation = aca_runtime::AcaOperationId::parse("u6-aca-test").unwrap();
        assert_eq!(
            controller.reconcile(operation.clone(), 30_000).await.unwrap(),
            aca_runtime::AcaReconcileOutcome::Progressing { after_ms: 10 }
        );
        assert_eq!(
            controller.reconcile(operation, 30_000).await.unwrap(),
            aca_runtime::AcaReconcileOutcome::Converged
        );
        assert_eq!(controller.phase(), aca_runtime::AcaPhase::Ready);
        controller
            .finalize(
                aca_runtime::AcaOperationId::parse("u6-aca-delete").unwrap(),
                30_000,
            )
            .await
            .unwrap();
        assert!(!controller.finalizer_installed());
    }

    #[tokio::test]
    async fn azure_vm_controller_contract_invokes_controller_and_finalizes() {
        let opaque = |value: &str| d2b_contracts::OpaqueAzureRef::parse(value).unwrap();
        let config = azure_vm_runtime::AzureVmConfig {
            tenant_id: None,
            client_id: None,
            arm_credential_ref: ResourceRef::parse("Credential/arm").unwrap(),
            controller_execution_ref: ResourceRef::parse("Guest/gateway").unwrap(),
            network_ref: None,
        };
        let settings = azure_vm_runtime::AzureVmGuestSettings {
            subscription_id: opaque("subscription"),
            resource_group: opaque("resource-group"),
            region: opaque("eastus"),
            vm_size: opaque("standard"),
            image_ref: opaque("image"),
            disk_sku: azure_vm_runtime::DiskSku::PremiumLrs,
            os_disk_size_gb: None,
            admin_user: "azureuser".to_owned(),
            vnet_subscription_id: None,
            vnet_resource_group: None,
            vnet_name: opaque("vnet"),
            subnet_name: opaque("subnet"),
            assign_public_ip: false,
            data_disks: Vec::new(),
            bootstrap_psk_delivery: azure_vm_runtime::BootstrapPskDelivery::VmExtension,
            bootstrap_deadline_ms: 60_000,
            child_zone_hosting: false,
            azure_tags: Vec::new(),
        };
        let effect = Arc::new(FrameworkAzureEffect {
            state: Arc::new(tokio::sync::Mutex::new(FrameworkAzureState::new(&settings))),
        });
        let mut controller = azure_vm_runtime::AzureVmController::new(
            config,
            settings,
            effect,
            Arc::new(FrameworkAzureCredential),
            None,
        )
        .unwrap()
        .with_bootstrap_service(azure_vm_runtime::BootstrapService::from_state(
            azure_vm_runtime::BootstrapServiceState::Enrolled,
        ));
        assert_eq!(
            controller
                .reconcile("work", "123e4567-e89b-42d3-a456-426614174000", 1)
                .await
                .unwrap(),
            azure_vm_runtime::AzureVmReconcileOutcome::Progressing { after_ms: 1_000 }
        );
        for _ in 0..2 {
            controller
                .reconcile("work", "123e4567-e89b-42d3-a456-426614174000", 1)
                .await
                .unwrap();
            if controller.phase() == azure_vm_runtime::AzureVmPhase::Ready {
                break;
            }
        }
        assert_eq!(controller.phase(), azure_vm_runtime::AzureVmPhase::Ready);
        for _ in 0..8 {
            if let Some(operation) = controller.recovery_state().operation {
                controller.poll_operation(operation).await.unwrap();
            }
            let outcome = controller
                .finalize("work", "123e4567-e89b-42d3-a456-426614174000", 1)
                .await
                .unwrap();
            let _ = outcome;
            if !controller.finalizer_installed() {
                break;
            }
        }
        assert!(!controller.finalizer_installed());
    }

    #[tokio::test]
    async fn production_guest_test_store_opens_with_core_session() {
        let directory = tempfile::tempdir().unwrap();
        let database_path = directory.path().join("store.redb");
        let database = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&database_path)
            .unwrap();
        let zone = ZoneId::parse("work").unwrap();
        let store_identity = "sha256:".to_owned() + &"d".repeat(64);
        let runtime = ZoneResourceRuntime::open_internal(
            zone.clone(),
            OpenedZoneStore {
                response: OpenZoneStoreResponse {
                    zone_store_id: d2b_contracts_resource::v3::storage::ZoneStoreId::parse(
                        "zone-store-work",
                    )
                    .unwrap(),
                    store_identity,
                    disposition: ZoneStoreDisposition::Provisioned,
                    fd_index: 0,
                },
                database_fd: database.into(),
                external_inventory: None,
            },
            None,
            Arc::new(BrokerEvidenceIndex::default()),
            None,
            true,
            None,
            None,
        )
        .await
        .unwrap();
        assert!(runtime.readiness().resource_api_ready);
        assert!(runtime.core_controller_subject.lock().unwrap().is_some());
        assert!(runtime.process_status_client.lock().unwrap().is_some());
        let provider = BundleResource::new(
            ResourceTypeName::parse("Provider").unwrap(),
            BundleResourceMetadata::new(
                ResourceName::parse("runtime-qemu-media").unwrap(),
                zone.clone(),
                None,
                BTreeMap::new(),
                BTreeMap::new(),
            ),
            CanonicalJsonObject::parse(
                br#"{"artifactId":"runtime-qemu-media","config":{"controllerExecutionRef":"Host/host-system","networkProviderRef":"Provider/network-local","volumeProviderRef":"Provider/volume-local"}}"#,
            )
            .unwrap(),
        )
        .unwrap();
        let guest_spec_json = br#"{"allowedDomains":["system"],"budget":{},"defaultDomain":"system","defaultUserRef":null,"deviceAttachments":[],"networkAttachments":[],"providerRef":"Provider/runtime-qemu-media","systemArtifactId":null,"volumeAttachmentDefaults":[]}"#;
        serde_json::from_slice::<d2b_contracts_resource::v3::ResourceSpec>(guest_spec_json)
            .unwrap_or_else(|error| panic!("Guest spec: {error}"));
        let guest = BundleResource::new(
            ResourceTypeName::parse("Guest").unwrap(),
            BundleResourceMetadata::new(
                ResourceName::parse("qemu").unwrap(),
                zone.clone(),
                None,
                BTreeMap::new(),
                BTreeMap::new(),
            ),
            CanonicalJsonObject::parse(guest_spec_json).unwrap(),
        )
        .unwrap();
        let bundle = ResourceBundle::new(
            zone.clone(),
            vec![provider],
            "sha256:".to_owned() + &"e".repeat(64),
            BTreeMap::new(),
            BTreeMap::new(),
            Timestamp::parse("1970-01-01T00:00:00.000Z").unwrap(),
        )
        .unwrap()
        .with_zone_uid(runtime.store.identity().zone_uid().clone());
        runtime
            .materialize_desired_bundle(&bundle)
            .await
            .unwrap_or_else(|error| panic!("test bundle materialization failed: {error:?}"));
        assert!(
            runtime
                .committed_resource_value(
                    &ResourceRef::parse("Provider/runtime-qemu-media").unwrap(),
                    "u6-test-provider-read",
                )
                .await
                .is_ok()
        );
        let guest_bundle = ResourceBundle::new(
            zone.clone(),
            vec![guest],
            "sha256:".to_owned() + &"f".repeat(64),
            BTreeMap::new(),
            BTreeMap::new(),
            Timestamp::parse("1970-01-01T00:00:00.000Z").unwrap(),
        )
        .unwrap()
        .with_zone_uid(runtime.store.identity().zone_uid().clone());
        runtime.materialize_desired_bundle(&guest_bundle).await.unwrap();
        assert!(
            runtime
                .committed_resource_value(
                    &ResourceRef::parse("Guest/qemu").unwrap(),
                    "u6-test-guest-read",
                )
                .await
                .is_ok()
        );
        runtime.shutdown().await.unwrap();
    }

    async fn open_production_guest_runtime_for_test() -> (
        tempfile::TempDir,
        ZoneResourceRuntime,
        Arc<BrokerEvidenceIndex>,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let database_path = directory.path().join("store.redb");
        let database = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&database_path)
            .unwrap();
        let zone = ZoneId::parse("work").unwrap();
        let broker_evidence = Arc::new(BrokerEvidenceIndex::default());
        let runtime = ZoneResourceRuntime::open_internal(
            zone,
            OpenedZoneStore {
                response: OpenZoneStoreResponse {
                    zone_store_id: d2b_contracts_resource::v3::storage::ZoneStoreId::parse(
                        "zone-store-work",
                    )
                    .unwrap(),
                    store_identity: "sha256:".to_owned() + &"a".repeat(64),
                    disposition: ZoneStoreDisposition::Provisioned,
                    fd_index: 0,
                },
                database_fd: database.into(),
                external_inventory: None,
            },
            None,
            Arc::clone(&broker_evidence),
            None,
            true,
            None,
            None,
        )
        .await
        .unwrap();
        (directory, runtime, broker_evidence)
    }

    fn bundle_resource(
        resource_type: &str,
        name: &str,
        zone: &ZoneId,
        spec: &str,
    ) -> BundleResource {
        bundle_resource_with_annotations(
            resource_type,
            name,
            zone,
            spec,
            BTreeMap::new(),
        )
    }

    fn bundle_resource_with_annotations(
        resource_type: &str,
        name: &str,
        zone: &ZoneId,
        spec: &str,
        annotations: BTreeMap<String, String>,
    ) -> BundleResource {
        BundleResource::new(
            ResourceTypeName::parse(resource_type).unwrap(),
            BundleResourceMetadata::new(
                ResourceName::parse(name).unwrap(),
                zone.clone(),
                None,
                BTreeMap::new(),
                annotations,
            ),
            CanonicalJsonObject::parse(spec.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    fn credential_spec(gateway: &str) -> String {
        let scope = d2b_contracts_provider::v3::credential::CredentialScope::new(
            Some(ResourceRef::parse(gateway).unwrap()),
            None,
            None,
        )
        .unwrap();
        let spec = d2b_contracts_provider::v3::credential::CredentialSpec::new(
            scope,
            d2b_contracts_provider::v3::credential::AudienceToken::parse(
                "azure-resource-manager",
            )
            .unwrap(),
            None,
            vec![
                d2b_contracts_provider::v3::credential::CredentialOperation::AcquireToken,
            ],
            d2b_contracts_provider::v3::credential::RotationSpec::default(),
            d2b_contracts_provider::v3::credential::ExpirySpec::default(),
            d2b_contracts_provider::v3::credential::RevocationSpec::default(),
            None,
            None,
        )
        .unwrap();
        serde_json::to_string(&spec).unwrap()
    }

    async fn materialize_test_bundle(
        runtime: &ZoneResourceRuntime,
        resources: Vec<BundleResource>,
    ) {
        let zone = runtime.zone.clone();
        let bundle = ResourceBundle::new(
            zone,
            resources,
            "sha256:".to_owned() + &"b".repeat(64),
            BTreeMap::new(),
            BTreeMap::new(),
            Timestamp::parse("1970-01-01T00:00:00.000Z").unwrap(),
        )
        .unwrap()
        .with_zone_uid(runtime.store.identity().zone_uid().clone());
        bundle
            .verify()
            .unwrap_or_else(|error| panic!("test bundle verification failed: {error:?}"));
        runtime
            .materialize_desired_bundle(&bundle)
            .await
            .unwrap_or_else(|error| panic!("test bundle materialization failed: {error:?}"));
    }

    async fn start_production_guest_runner_fixture(
        resources: Vec<BundleResource>,
    ) -> (
        tempfile::TempDir,
        Arc<ServerState>,
        Arc<ResourcePlane>,
        Arc<ZoneResourceRuntime>,
        Arc<BrokerEvidenceIndex>,
    ) {
        let (directory, state, plane, runtime, broker_evidence) =
            prepare_production_guest_runner_fixture(resources).await;
        runtime
            .start_u6_controller_runners(Arc::clone(&state))
            .await
            .unwrap();
        (directory, state, plane, runtime, broker_evidence)
    }

    async fn prepare_production_guest_runner_fixture(
        resources: Vec<BundleResource>,
    ) -> (
        tempfile::TempDir,
        Arc<ServerState>,
        Arc<ResourcePlane>,
        Arc<ZoneResourceRuntime>,
        Arc<BrokerEvidenceIndex>,
    ) {
        let (directory, runtime, broker_evidence) =
            open_production_guest_runtime_for_test().await;
        materialize_test_bundle(&runtime, resources).await;
        let state = Arc::new(crate::detached_exec_routing_tests::test_state(
            Default::default(),
        ));
        let zone = runtime.zone.clone();
        let mut plane = ResourcePlane::new();
        plane.insert(runtime).unwrap();
        let plane = crate::install_test_resource_plane(&state, plane);
        let runtime = plane.zone(&zone).unwrap();
        (directory, state, plane, runtime, broker_evidence)
    }

    async fn mark_test_resource_ready(
        runtime: &ZoneResourceRuntime,
        target: &ResourceRef,
        broker_evidence: &BrokerEvidenceIndex,
    ) {
        mark_test_resource_phase(runtime, target, broker_evidence, "Ready").await;
    }

    async fn mark_test_resource_phase(
        runtime: &ZoneResourceRuntime,
        target: &ResourceRef,
        broker_evidence: &BrokerEvidenceIndex,
        phase: &str,
    ) {
        let current = runtime
            .committed_resource_value(target, "u6-test-ready-read")
            .await
            .unwrap();
        let mut status = current.get("status").cloned().unwrap();
        status["phase"] = Value::String(phase.to_owned());
        status["observedGeneration"] = current["metadata"]["generation"].clone();
        let client = runtime.status_client().unwrap();
        let operation = bounded_operation_id(&format!(
            "u6-test-ready:{}:{}",
            target.to_canonical_string(),
            current["metadata"]["revision"]
        ));
        if matches!(
            target.resource_type().as_str(),
            "Provider" | "Credential"
        ) {
            broker_evidence
                .insert(DurabilityEvidence {
                    key: d2b_audit::operation::ZoneOperationKey::derive(
                        runtime.zone.as_str(),
                        &operation,
                    )
                    .unwrap(),
                    outcome: d2b_audit::DurabilityOutcome::Success,
                    effect_durable: true,
                })
                .unwrap();
        }
        let request = public_update_status_request_from_current(
            runtime,
            &json!({
                "status": status,
                "expectedRevision": current["metadata"]["revision"],
            }),
            &operation,
            target,
            current,
        )
        .unwrap();
        let response = client.update_status(request).await;
        if let Some(error) = response.error.as_ref() {
            panic!(
                "test status update rejected: kind={:?} reason={}",
                error.kind, error.reason
            );
        }
    }

    async fn assert_guest_assignment_fence(
        runtime: &ZoneResourceRuntime,
        guest_ref: &ResourceRef,
        provider_ref: &ResourceRef,
        controller_ref: &ResourceRef,
    ) {
        let guest = runtime
            .committed_resource_value(guest_ref, "u6-test-fence-read")
            .await
            .unwrap();
        assert_eq!(
            guest["spec"]["providerRef"],
            provider_ref.to_canonical_string()
        );
        let provider = runtime
            .committed_resource_value(provider_ref, "u6-test-provider-fence-read")
            .await
            .unwrap();
        let fence = runtime
            .store
            .assignment_fence(runtime.zone.clone(), guest_ref.clone())
            .await
            .unwrap()
            .expect("Guest assignment fence");
        assert_eq!(
            fence.resource_uid,
            ResourceUid::parse(guest["metadata"]["uid"].as_str().unwrap()).unwrap()
        );
        assert_eq!(
            fence.resource_revision,
            ZoneRevision::new(guest["metadata"]["revision"].as_u64().unwrap())
        );
        assert_eq!(
            fence.provider_generation,
            ResourceGeneration::new(provider["metadata"]["generation"].as_u64().unwrap()).unwrap()
        );
        assert_eq!(
            fence.controller_generation,
            runtime
                .store
                .runtime_metadata()
                .await
                .unwrap()
                .policy_snapshot
                .controller_generation
                .unwrap()
        );
        assert_eq!(fence.controller_role, controller_ref.clone());
        assert_eq!(
            fence.target,
            ResourceRef::parse(&format!("Zone/{}", runtime.zone.as_str())).unwrap()
        );
        assert_eq!(
            fence.session_generation,
            runtime
                .core_controller_subject
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .reconnect_generation()
        );
        assert!(fence.epoch > 0);
        assert!(matches!(fence.scope, ResourceAssignmentScope::Primary));
    }

    async fn wait_for_test_resource(
        runtime: &ZoneResourceRuntime,
        target: &ResourceRef,
        predicate: impl Fn(&Value) -> bool,
    ) -> Value {
        for _ in 0..3_000 {
            if let Ok(value) = runtime
                .committed_resource_value(target, "u6-test-wait")
                .await
                && predicate(&value)
            {
                return value;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        panic!("timed out waiting for {}", target.to_canonical_string());
    }

    async fn wait_for_test_resource_gone(runtime: &ZoneResourceRuntime, target: &ResourceRef) {
        for _ in 0..3_000 {
            if runtime
                .committed_resource_value(target, "u6-test-wait-gone")
                .await
                .is_err()
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        panic!("timed out waiting for {}", target.to_canonical_string());
    }

    async fn request_test_delete(runtime: &ZoneResourceRuntime, target: &ResourceRef) {
        for attempt in 0..100 {
            let current = runtime
                .committed_resource_value(target, "u6-test-delete-read")
                .await
                .unwrap();
            let client = runtime.status_client().unwrap();
            let operation = format!("u6-test-delete-{attempt}");
            let request = public_delete_request(
                runtime,
                &json!({
                    "resourceRef": target.to_canonical_string(),
                    "uid": current["metadata"]["uid"],
                    "expectedRevision": current["metadata"]["revision"],
                }),
                &operation,
            )
            .await
            .unwrap();
            let response = client.delete(request).await;
            let Some(error) = response.error.as_ref() else {
                return;
            };
            if error.reason.as_str() == "resource-revision-changed" {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                continue;
            }
            panic!(
                "test delete rejected: kind={:?} reason={}",
                error.kind, error.reason
            );
        }
        panic!("test delete did not become admitted");
    }

    async fn add_test_child_finalizer(runtime: &ZoneResourceRuntime, target: &ResourceRef) {
        let current = runtime
            .committed_resource_value(target, "u6-test-child-finalizer-read")
            .await
            .unwrap();
        let request = public_update_finalizers_request(
            runtime,
            &json!({
                "resourceRef": target.to_canonical_string(),
                "uid": current["metadata"]["uid"],
                "expectedRevision": current["metadata"]["revision"],
                "addFinalizers": ["test.d2bus.org/hold"],
                "removeFinalizers": [],
            }),
            "u6-test-child-finalizer",
        )
        .unwrap();
        let response = runtime.status_client().unwrap().update_finalizers(request).await;
        if let Some(error) = response.error.as_ref() {
            panic!(
                "test child finalizer update rejected: kind={:?} reason={}",
                error.kind, error.reason
            );
        }
    }

    async fn create_test_child(
        runtime: &ZoneResourceRuntime,
        owner: &ResourceRef,
        target: &ResourceRef,
    ) {
        let process = qemu_media_runtime::build_process_spec(
            ResourceRef::parse("Host/host-system").unwrap(),
            ResourceRef::parse("Volume/u6-test-runtime").unwrap(),
            None,
            [],
        )
        .unwrap();
        let mut process_spec = serde_json::to_value(process).unwrap();
        process_spec
            .as_object_mut()
            .unwrap()
            .insert(
                "providerRef".to_owned(),
                Value::String("Provider/system-minijail".to_owned()),
            );
        let canonical = DaemonSharedProviderEffects::guest_child_resource(
            target,
            owner,
            &runtime.zone,
            process_spec,
        )
        .unwrap();
        let identity = public_identity(
            runtime,
            target.resource_type(),
            target.name().as_str(),
            None,
            None,
            None,
        );
        let mut mutation = wire::Mutation::new();
        mutation.kind =
            protobuf::EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_CREATE);
        mutation.target = protobuf::MessageField::some(identity.clone());
        mutation.precondition = protobuf::MessageField::some(create_precondition());
        mutation.resource = protobuf::MessageField::some(
            ch_resource_body(&runtime.zone, target, None, &canonical).unwrap(),
        );
        mutation.owner = protobuf::MessageField::some(public_identity(
            runtime,
            owner.resource_type(),
            owner.name().as_str(),
            None,
            None,
            None,
        ));
        let mut request = wire::CreateRequest::new();
        request.meta = protobuf::MessageField::some(public_request_meta(
            &bounded_operation_id(&format!(
                "u6-test-child-create:{}",
                target.to_canonical_string()
            )),
        ));
        request.mutation = protobuf::MessageField::some(mutation);
        let response = runtime.status_client().unwrap().create(request).await;
        assert!(response.error.is_none(), "{:?}", response.error);
    }

    async fn clear_test_child_finalizers(
        runtime: &ZoneResourceRuntime,
        target: &ResourceRef,
    ) {
        let current = runtime
            .committed_resource_value(target, "u6-test-child-finalizer-clear-read")
            .await
            .unwrap();
        let request = public_update_finalizers_request(
            runtime,
            &json!({
                "resourceRef": target.to_canonical_string(),
                "uid": current["metadata"]["uid"],
                "expectedRevision": current["metadata"]["revision"],
                "addFinalizers": [],
                "removeFinalizers": ["test.d2bus.org/hold"],
            }),
            "u6-test-child-finalizer-clear",
        )
        .unwrap();
        let response = runtime.status_client().unwrap().update_finalizers(request).await;
        assert!(response.error.is_none(), "{:?}", response.error);
    }

    async fn close_production_guest_runtime_fixture(
        state: Arc<ServerState>,
        plane: Arc<ResourcePlane>,
    ) {
        state
            .resource_plane
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        let mut plane = Arc::try_unwrap(plane).expect("test plane has one owner");
        plane.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn qemu_framework_runner_invokes_controller_and_finalizes() {
        let (_directory, runtime, broker_evidence) = open_production_guest_runtime_for_test().await;
        let zone = runtime.zone.clone();
        materialize_test_bundle(
            &runtime,
            vec![
                bundle_resource(
                    "Provider",
                    "runtime-qemu-media",
                    &zone,
                    r#"{"artifactId":"runtime-qemu-media","config":{"controllerExecutionRef":"Host/host-system","networkProviderRef":"Provider/network-local","volumeProviderRef":"Provider/volume-local"}}"#,
                ),
                bundle_resource(
                    "Device",
                    "host-kvm",
                    &zone,
                    r#"{"deviceClass":"emulated","arbitration":"exclusive","maxConcurrentClaims":1,"inventory":{}}"#,
                ),
                bundle_resource(
                    "Guest",
                    "qemu-delete",
                    &zone,
                    r#"{"allowedDomains":["system"],"budget":{},"defaultDomain":"system","defaultUserRef":null,"deviceAttachments":[{"deviceRef":"Device/host-kvm","exclusive":false}],"networkAttachments":[],"providerRef":"Provider/runtime-qemu-media","systemArtifactId":null,"volumeAttachmentDefaults":[]}"#,
                ),
                bundle_resource(
                    "Guest",
                    "qemu-ready",
                    &zone,
                    r#"{"allowedDomains":["system"],"budget":{},"defaultDomain":"system","defaultUserRef":null,"deviceAttachments":[{"deviceRef":"Device/host-kvm","exclusive":false}],"networkAttachments":[],"providerRef":"Provider/runtime-qemu-media","systemArtifactId":null,"volumeAttachmentDefaults":[]}"#,
                ),
            ],
        )
        .await;
        let delete_guest_ref = ResourceRef::parse("Guest/qemu-delete").unwrap();
        let ready_guest_ref = ResourceRef::parse("Guest/qemu-ready").unwrap();
        let device_ref = ResourceRef::parse("Device/host-kvm").unwrap();
        let provider_ref = ResourceRef::parse("Provider/runtime-qemu-media").unwrap();

        let state = Arc::new(crate::detached_exec_routing_tests::test_state(
            Default::default(),
        ));
        let mut plane = ResourcePlane::new();
        plane.insert(runtime).unwrap();
        let plane = crate::install_test_resource_plane(&state, plane);
        let runtime = plane.zone(&zone).unwrap();
        runtime
            .start_u6_controller_runners(Arc::clone(&state))
            .await
            .unwrap();
        assert!(
            !runtime.u6_runner_tasks.lock().unwrap().is_empty(),
            "U6 runner did not start"
        );

        let deleting_guest = wait_for_test_resource(&runtime, &delete_guest_ref, |value| {
            value["metadata"]["finalizers"]
                .as_array()
                .is_some_and(|finalizers| !finalizers.is_empty())
        })
        .await;
        assert_eq!(
            deleting_guest["metadata"]["finalizers"],
            serde_json::json!([
                qemu_media_runtime::FINALIZER
            ])
        );
        let ready_guest = wait_for_test_resource(&runtime, &ready_guest_ref, |value| {
            value["metadata"]["finalizers"]
                .as_array()
                .is_some_and(|finalizers| !finalizers.is_empty())
        })
        .await;
        assert_eq!(ready_guest["status"]["phase"], "Pending");
        assert_eq!(deleting_guest["status"]["phase"], "Pending");
        assert!(
            runtime
                .committed_resource_value(
                    &ResourceRef::parse("Volume/qemu-delete-runtime").unwrap(),
                    "u6-test-first-finalizer-only",
                )
                .await
                .is_err()
        );
        assert!(
            runtime
                .committed_resource_value(
                    &ResourceRef::parse("Process/qemu-delete-qemu").unwrap(),
                    "u6-test-first-finalizer-only",
                )
                .await
                .is_err()
        );
        assert!(
            runtime
                .committed_resource_value(
                    &ResourceRef::parse("Volume/qemu-ready-runtime").unwrap(),
                    "u6-test-first-finalizer-only",
                )
                .await
                .is_err()
        );
        assert!(
            runtime
                .committed_resource_value(
                    &ResourceRef::parse("Process/qemu-ready-qemu").unwrap(),
                    "u6-test-first-finalizer-only",
                )
                .await
                .is_err()
        );
        assert_guest_assignment_fence(
            &runtime,
            &delete_guest_ref,
            &provider_ref,
            &ResourceRef::parse("Process/runtime-qemu-media-controller").unwrap(),
        )
        .await;
        assert_guest_assignment_fence(
            &runtime,
            &ready_guest_ref,
            &provider_ref,
            &ResourceRef::parse("Process/runtime-qemu-media-controller").unwrap(),
        )
        .await;
        mark_test_resource_ready(&runtime, &device_ref, &broker_evidence).await;
        mark_test_resource_ready(&runtime, &provider_ref, &broker_evidence).await;
        let ready_volume_ref = ResourceRef::parse("Volume/qemu-ready-runtime").unwrap();
        let ready_process_ref = ResourceRef::parse("Process/qemu-ready-qemu").unwrap();
        let ready_volume = wait_for_test_resource(&runtime, &ready_volume_ref, |_| true).await;
        mark_test_resource_ready(&runtime, &ready_volume_ref, &broker_evidence).await;
        let ready_process = wait_for_test_resource(&runtime, &ready_process_ref, |_| true).await;
        assert!(
            ready_process["metadata"]["revision"].as_u64().unwrap()
                > ready_volume["metadata"]["revision"].as_u64().unwrap()
        );
        mark_test_resource_ready(&runtime, &ready_process_ref, &broker_evidence).await;
        let ready_guest = wait_for_test_resource(&runtime, &ready_guest_ref, |value| {
            value["status"]["phase"] == "Ready"
                && value["status"]["observedGeneration"] == value["metadata"]["generation"]
        })
        .await;
        assert_eq!(ready_guest["status"]["phase"], "Ready");
        assert_eq!(ready_guest["status"]["phase"], "Ready");
        assert_eq!(ready_guest["status"]["phase"], "Ready");

        let delete_volume_ref = ResourceRef::parse("Volume/qemu-delete-runtime").unwrap();
        let delete_process_ref = ResourceRef::parse("Process/qemu-delete-qemu").unwrap();
        wait_for_test_resource(&runtime, &delete_volume_ref, |_| true).await;
        wait_for_test_resource(&runtime, &delete_process_ref, |_| true).await;
        add_test_child_finalizer(&runtime, &delete_process_ref).await;
        request_test_delete(&runtime, &delete_guest_ref).await;
        let deleting_guest = wait_for_test_resource(&runtime, &delete_guest_ref, |value| {
            value["metadata"]["deletionRequestedAt"].is_string()
        })
        .await;
        assert_eq!(
            deleting_guest["metadata"]["finalizers"],
            serde_json::json!([qemu_media_runtime::FINALIZER])
        );
        assert_ne!(deleting_guest["status"]["phase"], "Ready");
        let requested_child = wait_for_test_resource(&runtime, &delete_process_ref, |value| {
            value["metadata"]["deletionRequestedAt"].is_string()
        })
        .await;
        assert_eq!(
            requested_child["metadata"]["finalizers"],
            serde_json::json!(["test.d2bus.org/hold"])
        );
        let child_revision = requested_child["metadata"]["revision"].clone();
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        let still_requested = runtime
        .committed_resource_value(&delete_process_ref, "u6-test-no-second-delete")
            .await
            .unwrap();
        assert_eq!(still_requested["metadata"]["revision"], child_revision);
        let owner_while_child_held = runtime
        .committed_resource_value(&delete_guest_ref, "u6-test-owner-finalizer-retained")
        .await
        .unwrap();
        assert_eq!(
        owner_while_child_held["metadata"]["finalizers"],
        serde_json::json!([qemu_media_runtime::FINALIZER])
        );
        clear_test_child_finalizers(&runtime, &delete_process_ref).await;
        wait_for_test_resource_gone(&runtime, &delete_process_ref).await;
        wait_for_test_resource_gone(&runtime, &delete_volume_ref).await;
        wait_for_test_resource_gone(&runtime, &delete_guest_ref).await;
        drop(runtime);
        close_production_guest_runtime_fixture(state, plane).await;
    }

    #[tokio::test]
    async fn aca_framework_runner_invokes_controller_and_finalizes() {
        let zone = ZoneId::parse("work").unwrap();
        let credential = credential_spec("Guest/gateway");
        let (_directory, state, plane, runtime, broker_evidence) =
            start_production_guest_runner_fixture(vec![
                bundle_resource(
                    "Provider",
                    "runtime-azure-container-apps",
                    &zone,
                    r#"{"artifactId":"runtime-azure-container-apps","config":{"gatewayExecutionRef":"Guest/gateway","tenantId":"tenant","clientId":"client","subscriptionId":"subscription","controlCredentialRef":"Credential/aca-control","pullCredentialRef":null,"environmentId":"environment","resourceGroupId":"resource-group","networkRef":null,"sandboxTransportAlias":"relay","defaults":{"profile":{"profileId":"default","diskImage":{"configuredDisk":{"binding_id":"image-1"}},"cpu":500,"memory":2048,"autoSuspendSecs":300,"sandboxIdentityBindingId":null},"readiness":{"attempts":3,"intervalMs":10},"planTtlMs":1000,"completedOperationCapacity":4}}}"#,
                ),
                bundle_resource("Credential", "aca-control", &zone, &credential),
                bundle_resource(
                    "Guest",
                    "gateway",
                    &zone,
                    r#"{"allowedDomains":["system"],"budget":{},"defaultDomain":"system","defaultUserRef":null,"deviceAttachments":[],"networkAttachments":[],"systemArtifactId":null,"volumeAttachmentDefaults":[]}"#,
                ),
                bundle_resource(
                    "Guest",
                    "aca-delete",
                    &zone,
                    r#"{"allowedDomains":["system"],"budget":{},"defaultDomain":"system","defaultUserRef":null,"executionRef":"Guest/gateway","deviceAttachments":[],"networkAttachments":[],"providerRef":"Provider/runtime-azure-container-apps","systemArtifactId":null,"volumeAttachmentDefaults":[]}"#,
                ),
                bundle_resource(
                    "Guest",
                    "aca-ready",
                    &zone,
                    r#"{"allowedDomains":["system"],"budget":{},"defaultDomain":"system","defaultUserRef":null,"executionRef":"Guest/gateway","deviceAttachments":[],"networkAttachments":[],"providerRef":"Provider/runtime-azure-container-apps","systemArtifactId":null,"volumeAttachmentDefaults":[]}"#,
                ),
            ])
            .await;
        let provider_ref = ResourceRef::parse("Provider/runtime-azure-container-apps").unwrap();
        let credential_ref = ResourceRef::parse("Credential/aca-control").unwrap();
        let gateway_ref = ResourceRef::parse("Guest/gateway").unwrap();

        let delete_guest_ref = ResourceRef::parse("Guest/aca-delete").unwrap();
        let ready_guest_ref = ResourceRef::parse("Guest/aca-ready").unwrap();
        let deleting_guest = wait_for_test_resource(&runtime, &delete_guest_ref, |value| {
            value["metadata"]["finalizers"]
                .as_array()
                .is_some_and(|finalizers| !finalizers.is_empty())
        })
        .await;
        let ready_guest = wait_for_test_resource(&runtime, &ready_guest_ref, |value| {
            value["metadata"]["finalizers"]
                .as_array()
                .is_some_and(|finalizers| !finalizers.is_empty())
        })
        .await;
        assert_eq!(
            deleting_guest["metadata"]["finalizers"],
            serde_json::json!([aca_runtime::FINALIZER])
        );
        assert_eq!(
            ready_guest["metadata"]["finalizers"],
            serde_json::json!([aca_runtime::FINALIZER])
        );
        assert_eq!(deleting_guest["status"]["phase"], "Pending");
        assert_eq!(ready_guest["status"]["phase"], "Pending");
        assert!(
            runtime
                .committed_resource_value(
                    &ResourceRef::parse("Endpoint/aca-delete-sandbox-agent").unwrap(),
                    "u6-test-first-finalizer-only",
                )
                .await
                .is_err()
        );
        assert!(
            runtime
                .committed_resource_value(
                    &ResourceRef::parse("Endpoint/aca-ready-sandbox-agent").unwrap(),
                    "u6-test-first-finalizer-only",
                )
                .await
                .is_err()
        );
        assert_guest_assignment_fence(
            &runtime,
            &delete_guest_ref,
            &provider_ref,
            &ResourceRef::parse("Process/aca-controller").unwrap(),
        )
        .await;
        assert_guest_assignment_fence(
            &runtime,
            &ready_guest_ref,
            &provider_ref,
            &ResourceRef::parse("Process/aca-controller").unwrap(),
        )
        .await;
        mark_test_resource_ready(&runtime, &provider_ref, &broker_evidence).await;
        mark_test_resource_ready(&runtime, &credential_ref, &broker_evidence).await;
        mark_test_resource_ready(&runtime, &gateway_ref, &broker_evidence).await;
        let ready_endpoint_ref = ResourceRef::parse("Endpoint/aca-ready-sandbox-agent").unwrap();
        wait_for_test_resource(&runtime, &ready_endpoint_ref, |_| true).await;
        mark_test_resource_ready(&runtime, &ready_endpoint_ref, &broker_evidence).await;
        let ready_guest = wait_for_test_resource(&runtime, &ready_guest_ref, |value| {
            value["status"]["phase"] == "Ready"
                && value["status"]["observedGeneration"] == value["metadata"]["generation"]
        })
        .await;
        assert_eq!(ready_guest["status"]["phase"], "Ready");

        let delete_endpoint_ref = ResourceRef::parse("Endpoint/aca-delete-sandbox-agent").unwrap();
        wait_for_test_resource(&runtime, &delete_endpoint_ref, |_| true).await;
        add_test_child_finalizer(&runtime, &delete_endpoint_ref).await;
        request_test_delete(&runtime, &delete_guest_ref).await;
        let deleting_guest = wait_for_test_resource(&runtime, &delete_guest_ref, |value| {
            value["metadata"]["deletionRequestedAt"].is_string()
        })
        .await;
        assert_eq!(
            deleting_guest["metadata"]["finalizers"],
            serde_json::json!([aca_runtime::FINALIZER])
        );
        assert_ne!(deleting_guest["status"]["phase"], "Ready");
        let requested_child = wait_for_test_resource(&runtime, &delete_endpoint_ref, |value| {
            value["metadata"]["deletionRequestedAt"].is_string()
        })
        .await;
        assert_eq!(
            requested_child["metadata"]["finalizers"],
            serde_json::json!(["test.d2bus.org/hold"])
        );
        let child_revision = requested_child["metadata"]["revision"].clone();
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        let still_requested = runtime
            .committed_resource_value(&delete_endpoint_ref, "u6-test-no-second-delete")
            .await
            .unwrap();
        assert_eq!(still_requested["metadata"]["revision"], child_revision);
        let owner_while_child_held = runtime
            .committed_resource_value(&delete_guest_ref, "u6-test-owner-finalizer-retained")
            .await
            .unwrap();
        assert_eq!(
            owner_while_child_held["metadata"]["finalizers"],
            serde_json::json!([aca_runtime::FINALIZER])
        );
        clear_test_child_finalizers(&runtime, &delete_endpoint_ref).await;
        wait_for_test_resource_gone(&runtime, &delete_endpoint_ref).await;
        wait_for_test_resource_gone(&runtime, &delete_guest_ref).await;
        drop(runtime);
        close_production_guest_runtime_fixture(state, plane).await;
    }

    #[tokio::test]
    async fn azure_vm_framework_runner_invokes_controller_and_finalizes() {
        let zone = ZoneId::parse("work").unwrap();
        let credential = credential_spec("Guest/gateway");
        let provider_config = azure_vm_runtime::AzureVmConfig {
            tenant_id: Some(d2b_contracts::OpaqueAzureRef::parse("tenant").unwrap()),
            client_id: None,
            arm_credential_ref: ResourceRef::parse("Credential/azure-arm").unwrap(),
            controller_execution_ref: ResourceRef::parse("Guest/gateway").unwrap(),
            network_ref: None,
        };
        let provider_spec = format!(
            r#"{{"artifactId":"runtime-azure-virtual-machine","config":{}}}"#,
            serde_json::to_string(&provider_config).unwrap()
        );
        let guest_spec = r#"{"allowedDomains":["system"],"budget":{},"defaultDomain":"system","defaultUserRef":null,"deviceAttachments":[],"networkAttachments":[],"providerRef":"Provider/runtime-azure-virtual-machine","systemArtifactId":null,"volumeAttachmentDefaults":[],"executionRef":"Guest/hold"}"#;
        let ready_guest_spec = guest_spec.replace("Guest/hold", "Guest/gateway");
        let (_directory, state, plane, runtime, broker_evidence) =
            prepare_production_guest_runner_fixture(vec![
                bundle_resource(
                    "Provider",
                    "runtime-azure-virtual-machine",
                    &zone,
                    &provider_spec,
                ),
                bundle_resource("Credential", "azure-arm", &zone, &credential),
                bundle_resource(
                    "Guest",
                    "gateway",
                    &zone,
                    r#"{"allowedDomains":["system"],"budget":{},"defaultDomain":"system","defaultUserRef":null,"deviceAttachments":[],"networkAttachments":[],"systemArtifactId":null,"volumeAttachmentDefaults":[]}"#,
                ),
                bundle_resource(
                    "Guest",
                    "hold",
                    &zone,
                    r#"{"allowedDomains":["system"],"budget":{},"defaultDomain":"system","defaultUserRef":null,"deviceAttachments":[],"networkAttachments":[],"systemArtifactId":null,"volumeAttachmentDefaults":[]}"#,
                ),
                bundle_resource_with_annotations(
                    "Guest",
                    "azure-vm-delete",
                    &zone,
                    guest_spec,
                    BTreeMap::from([(
                        "d2b.test/azure-vm-settings".to_owned(),
                        "framework".to_owned(),
                    )]),
                ),
                bundle_resource_with_annotations(
                    "Guest",
                    "azure-vm-ready",
                    &zone,
                    &ready_guest_spec,
                    BTreeMap::from([(
                        "d2b.test/azure-vm-settings".to_owned(),
                        "framework".to_owned(),
                    )]),
                ),
            ])
            .await;
        let provider_ref = ResourceRef::parse("Provider/runtime-azure-virtual-machine").unwrap();
        let credential_ref = ResourceRef::parse("Credential/azure-arm").unwrap();
        let gateway_ref = ResourceRef::parse("Guest/gateway").unwrap();
        mark_test_resource_ready(&runtime, &provider_ref, &broker_evidence).await;
        mark_test_resource_ready(&runtime, &credential_ref, &broker_evidence).await;
        mark_test_resource_ready(&runtime, &gateway_ref, &broker_evidence).await;
        wait_for_test_resource(&runtime, &provider_ref, |value| {
            value["status"]["phase"] == "Ready"
        })
        .await;
        wait_for_test_resource(&runtime, &credential_ref, |value| {
            value["status"]["phase"] == "Ready"
        })
        .await;
        wait_for_test_resource(&runtime, &gateway_ref, |value| {
            value["status"]["phase"] == "Ready"
        })
        .await;
        runtime
            .start_u6_controller_runners(Arc::clone(&state))
            .await
            .unwrap();

        let delete_guest_ref = ResourceRef::parse("Guest/azure-vm-delete").unwrap();
        let ready_guest_ref = ResourceRef::parse("Guest/azure-vm-ready").unwrap();
        let deleting_guest = wait_for_test_resource(&runtime, &delete_guest_ref, |value| {
            value["metadata"]["finalizers"]
                .as_array()
                .is_some_and(|finalizers| !finalizers.is_empty())
        })
        .await;
        let ready_guest = wait_for_test_resource(&runtime, &ready_guest_ref, |value| {
            value["metadata"]["finalizers"]
                .as_array()
                .is_some_and(|finalizers| !finalizers.is_empty())
        })
        .await;
        assert_eq!(
            deleting_guest["metadata"]["finalizers"],
            serde_json::json!([azure_vm_runtime::FINALIZER])
        );
        assert_eq!(
            ready_guest["metadata"]["finalizers"],
            serde_json::json!([azure_vm_runtime::FINALIZER])
        );
        assert_eq!(deleting_guest["status"]["phase"], "Pending");
        assert_eq!(ready_guest["status"]["phase"], "Pending");
        assert_guest_assignment_fence(
            &runtime,
            &delete_guest_ref,
            &provider_ref,
            &ResourceRef::parse("Process/azure-vm-controller-process").unwrap(),
        )
        .await;
        assert_guest_assignment_fence(
            &runtime,
            &ready_guest_ref,
            &provider_ref,
            &ResourceRef::parse("Process/azure-vm-controller-process").unwrap(),
        )
        .await;
        let child_ref = ResourceRef::parse("Process/azure-vm-child").unwrap();
        create_test_child(&runtime, &delete_guest_ref, &child_ref).await;
        add_test_child_finalizer(&runtime, &child_ref).await;
        request_test_delete(&runtime, &delete_guest_ref).await;
        let ready_guest = wait_for_test_resource(&runtime, &ready_guest_ref, |value| {
            value["status"]["phase"] == "Ready"
                && value["status"]["observedGeneration"] == value["metadata"]["generation"]
        })
        .await;
        assert_eq!(ready_guest["status"]["phase"], "Ready");
        let deleting_guest = wait_for_test_resource(&runtime, &delete_guest_ref, |value| {
            value["metadata"]["deletionRequestedAt"].is_string()
        })
        .await;
        assert_eq!(
            deleting_guest["metadata"]["finalizers"],
            serde_json::json!([azure_vm_runtime::FINALIZER])
        );
        assert_ne!(deleting_guest["status"]["phase"], "Ready");
        let requested_child = wait_for_test_resource(&runtime, &child_ref, |value| {
            value["metadata"]["deletionRequestedAt"].is_string()
        })
        .await;
        assert_eq!(
            requested_child["metadata"]["finalizers"],
            serde_json::json!(["test.d2bus.org/hold"])
        );
        let child_revision = requested_child["metadata"]["revision"].clone();
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        let still_requested = runtime
            .committed_resource_value(&child_ref, "u6-test-no-second-delete")
            .await
            .unwrap();
        assert_eq!(still_requested["metadata"]["revision"], child_revision);
        let owner_while_child_held = runtime
            .committed_resource_value(&delete_guest_ref, "u6-test-owner-finalizer-retained")
            .await
            .unwrap();
        assert_eq!(
            owner_while_child_held["metadata"]["finalizers"],
            serde_json::json!([azure_vm_runtime::FINALIZER])
        );
        clear_test_child_finalizers(&runtime, &child_ref).await;
        wait_for_test_resource_gone(&runtime, &child_ref).await;
        wait_for_test_resource_gone(&runtime, &delete_guest_ref).await;
        drop(runtime);
        close_production_guest_runtime_fixture(state, plane).await;
    }
}
