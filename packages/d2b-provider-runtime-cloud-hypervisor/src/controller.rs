//! Resource-first Cloud Hypervisor Guest reconciliation.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::Arc,
};

use async_trait::async_trait;
use d2b_contracts_resource::v3::{
    CanonicalJsonValue, DesiredLifecycle, ResourceGeneration, ResourcePhase, ResourceRef,
    ResourceTypeName, ResourceUid, SchemaFingerprint, ZoneId, ZoneRevision,
};
use d2b_core_controller::{HintTarget, ObservedChild, OwnerIndex, OwnerLimits};

use crate::{
    adoption::ProcessAdoptionStatus,
    bootstrap_graph::{BootstrapGraph, DependencyReadiness, GuestChildGraphPlan},
    descriptor::{
        GuestSetupDescriptor, GuestSetupDescriptorError, GuestSetupDescriptorVerifier,
        VerifiedGuestSetupDescriptor,
    },
    health::{GuestSessionEvidence, GuestSessionHealth},
    identity::{
        ChildCreateBody, ChildMutation, ChildRole, ChildRoleSet, CommittedChild, GuestChildBatch,
        PrivateRuntimeScope, derive_private_runtime_scope,
    },
    shutdown::{
        FencedChild, FinalizationDisposition, FinalizationStep, GuestFinalizationInput,
        GuestUpgradePlan, LifecyclePlanError, UpgradeReason, plan_finalization, plan_upgrade,
    },
    state::{
        GuestGenerationSet, GuestRuntimeStatus, GuestStatusObservation, GuestStatusPhase,
        reduce_status,
    },
};

/// The finalizer owned by the Cloud Hypervisor Guest controller.
pub const GUEST_CONTROLLER_FINALIZER: &str = "runtime-cloud-hypervisor.d2bus.org/guest";
/// Default descriptor repair interval.
pub const CLOUD_HYPERVISOR_REPAIR_INTERVAL_SECS: u64 = 30;

/// The shared-Runner contract for the Cloud Hypervisor Guest owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloudHypervisorRunnerContract {
    resource_type: &'static str,
    finalizer: &'static str,
    repair_interval_secs: u64,
    watched_configuration_is_dependency: bool,
}

impl CloudHypervisorRunnerContract {
    /// Return the owned ResourceType.
    pub const fn resource_type(self) -> &'static str {
        self.resource_type
    }

    /// Return the exact Guest finalizer.
    pub const fn finalizer(self) -> &'static str {
        self.finalizer
    }

    /// Return the bounded repair interval.
    pub const fn repair_interval_secs(self) -> u64 {
        self.repair_interval_secs
    }

    /// Whether watched configuration is treated as a dependency.
    pub const fn watched_configuration_is_dependency(self) -> bool {
        self.watched_configuration_is_dependency
    }
}

/// Return the shared-Runner contract for Cloud Hypervisor Guests.
pub const fn cloud_hypervisor_runner_contract() -> CloudHypervisorRunnerContract {
    CloudHypervisorRunnerContract {
        resource_type: "Guest",
        finalizer: GUEST_CONTROLLER_FINALIZER,
        repair_interval_secs: CLOUD_HYPERVISOR_REPAIR_INTERVAL_SECS,
        watched_configuration_is_dependency: true,
    }
}

/// Errors returned by the authenticated Resource API seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudHypervisorResourceApiError {
    /// The authenticated session was unavailable.
    Authentication,
    /// The Resource API transport failed.
    Transport,
    /// The target did not exist.
    NotFound,
    /// A UID or revision precondition conflicted.
    Conflict,
    /// The response could not be trusted as complete.
    Uncertain,
    /// A bounded response was truncated.
    Truncated,
    /// The response type did not match the request.
    InvalidResponse,
    /// The lifecycle operation is not implemented by this API adapter.
    Unsupported,
}

impl CloudHypervisorResourceApiError {
    /// Return the stable identity-free error code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Authentication => "cloud-hypervisor-resource-authentication",
            Self::Transport => "cloud-hypervisor-resource-transport",
            Self::NotFound => "cloud-hypervisor-resource-not-found",
            Self::Conflict => "cloud-hypervisor-resource-conflict",
            Self::Uncertain => "cloud-hypervisor-resource-uncertain",
            Self::Truncated => "cloud-hypervisor-resource-truncated",
            Self::InvalidResponse => "cloud-hypervisor-resource-invalid-response",
            Self::Unsupported => "cloud-hypervisor-resource-unsupported",
        }
    }
}

impl fmt::Display for CloudHypervisorResourceApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for CloudHypervisorResourceApiError {}

/// Cloud Hypervisor controller failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudHypervisorError {
    /// The controller configuration was invalid.
    InvalidConfiguration,
    /// The private descriptor did not verify.
    Descriptor(GuestSetupDescriptorError),
    /// The controller has not been registered with an authenticated API.
    NotRegistered,
    /// The Guest snapshot did not match the verified Provider contract.
    InvalidGuest,
    /// A child had a foreign or stale owner identity.
    ChildConflict,
    /// The child batch response was incomplete or malformed.
    BatchResponseInvalid,
    /// The authenticated Resource API failed.
    ResourceApi(CloudHypervisorResourceApiError),
    /// A bounded lifecycle plan could not be constructed.
    LifecyclePlan(LifecyclePlanError),
}

impl fmt::Display for CloudHypervisorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration => {
                formatter.write_str("cloud-hypervisor-invalid-configuration")
            }
            Self::Descriptor(error) => error.fmt(formatter),
            Self::NotRegistered => {
                formatter.write_str("cloud-hypervisor-controller-not-registered")
            }
            Self::InvalidGuest => formatter.write_str("cloud-hypervisor-guest-invalid"),
            Self::ChildConflict => formatter.write_str("cloud-hypervisor-child-conflict"),
            Self::BatchResponseInvalid => {
                formatter.write_str("cloud-hypervisor-batch-response-invalid")
            }
            Self::ResourceApi(error) => error.fmt(formatter),
            Self::LifecyclePlan(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for CloudHypervisorError {}

impl From<GuestSetupDescriptorError> for CloudHypervisorError {
    fn from(error: GuestSetupDescriptorError) -> Self {
        Self::Descriptor(error)
    }
}

impl From<CloudHypervisorResourceApiError> for CloudHypervisorError {
    fn from(error: CloudHypervisorResourceApiError) -> Self {
        Self::ResourceApi(error)
    }
}

impl From<LifecyclePlanError> for CloudHypervisorError {
    fn from(error: LifecyclePlanError) -> Self {
        Self::LifecyclePlan(error)
    }
}

/// The verified controller registration and its bounded watch set.
#[derive(Clone, PartialEq, Eq)]
pub struct CloudHypervisorControllerRegistration {
    provider_ref: ResourceRef,
    provider_generation: ResourceGeneration,
    descriptor_digest: SchemaFingerprint,
    child_roles: ChildRoleSet,
    watched_types: Vec<ResourceTypeName>,
    dependency_types: Vec<ResourceTypeName>,
    finalizer: String,
}

impl CloudHypervisorControllerRegistration {
    /// Build the registration from a verified private descriptor.
    pub fn from_verified_descriptor(
        descriptor: &VerifiedGuestSetupDescriptor,
    ) -> Result<Self, CloudHypervisorError> {
        let provider_ref = ResourceRef::parse(crate::PROVIDER_REF)
            .map_err(|_| CloudHypervisorError::InvalidConfiguration)?;
        if descriptor.descriptor().provider_ref() != &provider_ref
            || !descriptor.descriptor().child_roles().is_fixed()
        {
            return Err(CloudHypervisorError::InvalidConfiguration);
        }
        let watched_types = ["Guest", "Process", "Endpoint", "Volume"]
            .into_iter()
            .map(|value| {
                ResourceTypeName::parse(value)
                    .map_err(|_| CloudHypervisorError::InvalidConfiguration)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let dependency_types = ["Device", "Network"]
            .into_iter()
            .map(|value| {
                ResourceTypeName::parse(value)
                    .map_err(|_| CloudHypervisorError::InvalidConfiguration)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            provider_ref,
            provider_generation: descriptor.descriptor().provider_generation(),
            descriptor_digest: descriptor.descriptor().descriptor_digest().clone(),
            child_roles: descriptor.descriptor().child_roles().clone(),
            watched_types,
            dependency_types,
            finalizer: GUEST_CONTROLLER_FINALIZER.to_owned(),
        })
    }

    /// Borrow the Provider identity.
    pub const fn provider_ref(&self) -> &ResourceRef {
        &self.provider_ref
    }

    /// Return the Provider generation bound into registration.
    pub const fn provider_generation(&self) -> ResourceGeneration {
        self.provider_generation
    }

    /// Borrow the verified descriptor digest bound into registration.
    pub const fn descriptor_digest(&self) -> &SchemaFingerprint {
        &self.descriptor_digest
    }

    /// Borrow the direct child role set.
    pub const fn child_roles(&self) -> &ChildRoleSet {
        &self.child_roles
    }

    /// Borrow the ResourceTypes watched by this controller.
    pub fn watched_types(&self) -> &[ResourceTypeName] {
        &self.watched_types
    }

    /// Borrow the dependency ResourceTypes watched by this controller.
    pub fn dependency_types(&self) -> &[ResourceTypeName] {
        &self.dependency_types
    }

    /// Borrow the controller finalizer ID.
    pub fn finalizer(&self) -> &str {
        &self.finalizer
    }
}

impl fmt::Debug for CloudHypervisorControllerRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudHypervisorControllerRegistration")
            .field("provider_ref", &self.provider_ref)
            .field("provider_generation", &self.provider_generation)
            .field("child_role_count", &self.child_roles.iter().count())
            .field("watched_type_count", &self.watched_types.len())
            .field("dependency_type_count", &self.dependency_types.len())
            .field("has_finalizer", &true)
            .finish()
    }
}

/// A fresh Guest snapshot read through the authenticated Resource API.
#[derive(Clone, PartialEq, Eq)]
pub struct GuestSnapshot {
    zone: ZoneId,
    zone_uid: ResourceUid,
    resource_ref: ResourceRef,
    uid: ResourceUid,
    generation: ResourceGeneration,
    revision: ZoneRevision,
    execution_ref: ResourceRef,
    provider_ref: ResourceRef,
    system_artifact_id: Option<String>,
    generations: GuestGenerationSet,
    session_evidence: Option<GuestSessionEvidence>,
    deleting: bool,
    controller_finalizer_present: bool,
}

impl GuestSnapshot {
    /// Construct a validated Guest snapshot.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        zone: ZoneId,
        zone_uid: ResourceUid,
        resource_ref: ResourceRef,
        uid: ResourceUid,
        generation: ResourceGeneration,
        revision: ZoneRevision,
        execution_ref: ResourceRef,
        provider_ref: ResourceRef,
        system_artifact_id: Option<String>,
        generations: GuestGenerationSet,
        deleting: bool,
    ) -> Result<Self, CloudHypervisorError> {
        if resource_ref.resource_type().as_str() != "Guest"
            || execution_ref.resource_type().as_str() != "Host"
            || provider_ref.resource_type().as_str() != "Provider"
            || generation.get() == 0
            || revision.get() == 0
            || system_artifact_id
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > 63)
        {
            return Err(CloudHypervisorError::InvalidGuest);
        }
        Ok(Self {
            zone,
            zone_uid,
            resource_ref,
            uid,
            generation,
            revision,
            execution_ref,
            provider_ref,
            system_artifact_id,
            generations,
            session_evidence: None,
            deleting,
            controller_finalizer_present: true,
        })
    }

    /// Attach the latest bounded authenticated session evidence.
    pub fn with_session_evidence(mut self, evidence: GuestSessionEvidence) -> Self {
        self.session_evidence = Some(evidence);
        self
    }

    /// Attach whether this controller's exact Guest finalizer remains.
    pub const fn with_controller_finalizer_present(mut self, present: bool) -> Self {
        self.controller_finalizer_present = present;
        self
    }

    /// Borrow the Guest Zone.
    pub const fn zone(&self) -> &ZoneId {
        &self.zone
    }

    /// Borrow the immutable Zone UID used only for private runtime fencing.
    pub const fn zone_uid(&self) -> &ResourceUid {
        &self.zone_uid
    }

    /// Borrow the Guest ResourceRef.
    pub const fn resource_ref(&self) -> &ResourceRef {
        &self.resource_ref
    }

    /// Borrow the store-assigned Guest UID.
    pub const fn uid(&self) -> &ResourceUid {
        &self.uid
    }

    /// Return the Guest desired-state generation.
    pub const fn generation(&self) -> ResourceGeneration {
        self.generation
    }

    /// Return the Guest revision used for update fencing.
    pub const fn revision(&self) -> ZoneRevision {
        self.revision
    }

    /// Borrow the semantic execution target.
    pub const fn execution_ref(&self) -> &ResourceRef {
        &self.execution_ref
    }

    /// Borrow the selected Provider.
    pub const fn provider_ref(&self) -> &ResourceRef {
        &self.provider_ref
    }

    /// Borrow the selected public system artifact ID.
    pub fn system_artifact_id(&self) -> Option<&str> {
        self.system_artifact_id.as_deref()
    }

    /// Borrow the generation observation consumed by the pure status reducer.
    pub const fn generations(&self) -> GuestGenerationSet {
        self.generations
    }

    /// Borrow the latest authenticated session evidence.
    pub fn session_evidence(&self) -> Option<&GuestSessionEvidence> {
        self.session_evidence.as_ref()
    }

    /// Whether deletion has been requested.
    pub const fn deleting(&self) -> bool {
        self.deleting
    }

    /// Whether this controller's exact Guest finalizer remains.
    pub const fn controller_finalizer_present(&self) -> bool {
        self.controller_finalizer_present
    }
}

impl fmt::Debug for GuestSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GuestSnapshot")
            .field("resource_type", &self.resource_ref.resource_type())
            .field("has_zone", &true)
            .field("has_uid", &true)
            .field("generation", &self.generation)
            .field("revision", &self.revision)
            .field("has_execution_ref", &true)
            .field("has_provider_ref", &true)
            .field("has_system_artifact_id", &self.system_artifact_id.is_some())
            .field("deleting", &self.deleting)
            .finish()
    }
}

/// A complete owner-index row for one direct child.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnedChildSnapshot {
    resource_ref: ResourceRef,
    zone: ZoneId,
    owner_ref: ResourceRef,
    owner_uid: Option<ResourceUid>,
    uid: ResourceUid,
    generation: ResourceGeneration,
    revision: ZoneRevision,
    spec_digest: String,
    phase: ResourcePhase,
    desired_lifecycle: Option<DesiredLifecycle>,
    healthy: bool,
}

impl OwnedChildSnapshot {
    /// Construct one observed child row.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        resource_ref: ResourceRef,
        zone: ZoneId,
        owner_ref: ResourceRef,
        uid: ResourceUid,
        generation: ResourceGeneration,
        revision: ZoneRevision,
        spec_digest: impl Into<String>,
        phase: ResourcePhase,
        desired_lifecycle: Option<DesiredLifecycle>,
        healthy: bool,
    ) -> Result<Self, CloudHypervisorError> {
        let spec_digest = spec_digest.into();
        if !matches!(
            resource_ref.resource_type().as_str(),
            "Process" | "Endpoint" | "Volume"
        ) || owner_ref.resource_type().as_str() != "Guest"
            || generation.get() == 0
            || revision.get() == 0
            || spec_digest.is_empty()
            || resource_ref.resource_type().as_str() != "Process" && desired_lifecycle.is_some()
        {
            return Err(CloudHypervisorError::ChildConflict);
        }
        if spec_digest.len() > 128 {
            return Err(CloudHypervisorError::ChildConflict);
        }
        Ok(Self {
            resource_ref,
            zone,
            owner_ref,
            owner_uid: None,
            uid,
            generation,
            revision,
            spec_digest,
            phase,
            desired_lifecycle,
            healthy,
        })
    }

    /// Attach the exact Guest owner UID from the Resource envelope.
    pub fn with_owner_uid(mut self, owner_uid: ResourceUid) -> Self {
        self.owner_uid = Some(owner_uid);
        self
    }

    /// Override the observed Process desired lifecycle after a successful
    /// optimistic update.
    pub fn with_desired_lifecycle(mut self, desired: DesiredLifecycle) -> Self {
        self.desired_lifecycle = Some(desired);
        self
    }

    /// Borrow the child ResourceRef.
    pub const fn resource_ref(&self) -> &ResourceRef {
        &self.resource_ref
    }

    /// Borrow the child Zone.
    pub const fn zone(&self) -> &ZoneId {
        &self.zone
    }

    /// Borrow the singular owner ResourceRef.
    pub const fn owner_ref(&self) -> &ResourceRef {
        &self.owner_ref
    }

    /// Borrow the exact owner UID, when supplied by the Resource API.
    pub fn owner_uid(&self) -> Option<&ResourceUid> {
        self.owner_uid.as_ref()
    }

    /// Borrow the child UID.
    pub const fn uid(&self) -> &ResourceUid {
        &self.uid
    }

    /// Return the child generation.
    pub const fn generation(&self) -> ResourceGeneration {
        self.generation
    }

    /// Return the child revision.
    pub const fn revision(&self) -> ZoneRevision {
        self.revision
    }

    /// Borrow the semantic desired-state digest.
    pub fn spec_digest(&self) -> &str {
        &self.spec_digest
    }

    /// Return the universal lifecycle phase.
    pub const fn phase(&self) -> ResourcePhase {
        self.phase
    }

    /// Return the Process desired lifecycle, when this is a Process.
    pub const fn desired_lifecycle(&self) -> Option<DesiredLifecycle> {
        self.desired_lifecycle
    }

    /// Whether the child status is healthy.
    pub const fn healthy(&self) -> bool {
        self.healthy
    }
}

impl fmt::Debug for OwnedChildSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnedChildSnapshot")
            .field("resource_type", &self.resource_ref.resource_type())
            .field("has_zone", &true)
            .field("has_owner", &true)
            .field("has_owner_uid", &self.owner_uid.is_some())
            .field("has_uid", &true)
            .field("generation", &self.generation)
            .field("revision", &self.revision)
            .field("phase", &self.phase)
            .field("has_spec_digest", &true)
            .finish()
    }
}

/// Bounded Device, Network, and Volume dependency status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestDependencySnapshot {
    devices: Vec<(ResourceRef, ResourcePhase)>,
    networks: Vec<(ResourceRef, ResourcePhase)>,
    volumes: Vec<(ResourceRef, ResourcePhase)>,
    exports_ready: bool,
    setup_ready: bool,
}

impl GuestDependencySnapshot {
    /// Construct and validate dependency status rows.
    pub fn new(
        devices: Vec<(ResourceRef, ResourcePhase)>,
        networks: Vec<(ResourceRef, ResourcePhase)>,
        volumes: Vec<(ResourceRef, ResourcePhase)>,
        exports_ready: bool,
        setup_ready: bool,
    ) -> Result<Self, CloudHypervisorError> {
        validate_dependency_family(&devices, "Device")?;
        validate_dependency_family(&networks, "Network")?;
        validate_dependency_family(&volumes, "Volume")?;
        let mut refs = BTreeSet::new();
        for (reference, _) in devices.iter().chain(&networks).chain(&volumes) {
            if !refs.insert(reference.clone()) {
                return Err(CloudHypervisorError::InvalidGuest);
            }
        }
        Ok(Self {
            devices,
            networks,
            volumes,
            exports_ready,
            setup_ready,
        })
    }

    /// Construct all-ready dependency evidence for a graph.
    pub fn ready(graph: BootstrapGraph) -> Self {
        Self {
            devices: graph
                .devices
                .into_iter()
                .map(|reference| (reference, ResourcePhase::Ready))
                .collect(),
            networks: graph
                .networks
                .into_iter()
                .map(|reference| (reference, ResourcePhase::Ready))
                .collect(),
            volumes: graph
                .volumes
                .into_iter()
                .map(|reference| (reference, ResourcePhase::Ready))
                .collect(),
            exports_ready: true,
            setup_ready: true,
        }
    }

    /// Return the Device dependency readiness.
    pub fn devices_ready(&self, graph: &BootstrapGraph) -> bool {
        all_family_ready(&graph.devices, &self.devices)
    }

    /// Return the Network dependency readiness.
    pub fn networks_ready(&self, graph: &BootstrapGraph) -> bool {
        all_family_ready(&graph.networks, &self.networks)
    }

    /// Return the backing Volume dependency readiness.
    pub fn volumes_ready(&self, graph: &BootstrapGraph) -> bool {
        all_family_ready(&graph.volumes, &self.volumes)
    }

    /// Return whether all required Volume Exports are Ready.
    pub const fn exports_ready(&self) -> bool {
        self.exports_ready
    }

    /// Return whether all descriptor-declared setup Volumes are Ready.
    pub const fn setup_ready(&self) -> bool {
        self.setup_ready
    }

    fn readiness(&self, graph: &BootstrapGraph) -> (DependencyReadiness, Vec<GuestCondition>) {
        let devices_ready = self.devices_ready(graph);
        let networks_ready = self.networks_ready(graph);
        let volumes_ready = self.volumes_ready(graph);
        let eligibility = graph.vmm_lifecycle(
            devices_ready,
            networks_ready,
            volumes_ready,
            self.exports_ready,
            self.setup_ready,
        );
        let mut conditions = Vec::new();
        if !devices_ready {
            conditions.push(GuestCondition::DeviceDependencyNotReady);
        }
        if !networks_ready {
            conditions.push(GuestCondition::NetworkDependencyNotReady);
        }
        if !volumes_ready {
            conditions.push(GuestCondition::VolumeDependencyNotReady);
        }
        if !self.exports_ready {
            conditions.push(GuestCondition::ExportDependencyNotReady);
        }
        if !self.setup_ready {
            conditions.push(GuestCondition::SetupVolumeNotReady);
        }
        (
            if eligibility.is_running() {
                DependencyReadiness::Ready
            } else {
                DependencyReadiness::Pending
            },
            conditions,
        )
    }
}

fn validate_dependency_family(
    rows: &[(ResourceRef, ResourcePhase)],
    expected_type: &str,
) -> Result<(), CloudHypervisorError> {
    let mut refs = BTreeSet::new();
    if rows.iter().any(|(reference, _)| {
        reference.resource_type().as_str() != expected_type || !refs.insert(reference.clone())
    }) {
        return Err(CloudHypervisorError::InvalidGuest);
    }
    Ok(())
}

fn all_family_ready(expected: &[ResourceRef], observed: &[(ResourceRef, ResourcePhase)]) -> bool {
    expected.iter().all(|reference| {
        observed
            .iter()
            .find(|(observed_ref, _)| observed_ref == reference)
            .is_some_and(|(_, phase)| *phase == ResourcePhase::Ready)
    })
}

/// One bounded UID-free child CommitBatch request.
#[derive(Clone, PartialEq, Eq)]
pub struct GuestChildCreateBatch {
    zone: ZoneId,
    owner_ref: ResourceRef,
    owner_uid: ResourceUid,
    owner_revision: ZoneRevision,
    source: GuestChildBatch,
    mutations: Vec<ChildMutation>,
}

impl GuestChildCreateBatch {
    /// Select missing deterministic children from the complete pure plan.
    pub fn new(
        guest: &GuestSnapshot,
        source: &GuestChildBatch,
        missing: impl IntoIterator<Item = ResourceRef>,
    ) -> Result<Self, CloudHypervisorError> {
        if source.zone() != guest.zone() || source.owner_ref() != guest.resource_ref() {
            return Err(CloudHypervisorError::ChildConflict);
        }
        let expected = source
            .mutations()
            .iter()
            .map(|mutation| mutation.target().clone())
            .collect::<BTreeSet<_>>();
        let missing = missing.into_iter().collect::<BTreeSet<_>>();
        if missing.is_empty()
            || missing.len() > 128
            || missing.iter().any(|target| !expected.contains(target))
        {
            return Err(CloudHypervisorError::BatchResponseInvalid);
        }
        let mutations = source
            .mutations()
            .iter()
            .filter(|mutation| missing.contains(mutation.target()))
            .cloned()
            .collect::<Vec<_>>();
        if mutations.len() != missing.len() {
            return Err(CloudHypervisorError::BatchResponseInvalid);
        }
        Ok(Self {
            zone: guest.zone.clone(),
            owner_ref: guest.resource_ref.clone(),
            owner_uid: guest.uid.clone(),
            owner_revision: guest.revision,
            source: source.clone(),
            mutations,
        })
    }

    /// Borrow the batch Zone.
    pub const fn zone(&self) -> &ZoneId {
        &self.zone
    }

    /// Borrow the Guest owner ResourceRef.
    pub const fn owner_ref(&self) -> &ResourceRef {
        &self.owner_ref
    }

    /// Borrow the exact Guest UID fence.
    pub const fn owner_uid(&self) -> &ResourceUid {
        &self.owner_uid
    }

    /// Return the exact Guest revision fence.
    pub const fn owner_revision(&self) -> ZoneRevision {
        self.owner_revision
    }

    /// Borrow the complete pure child batch used as the source.
    pub const fn source(&self) -> &GuestChildBatch {
        &self.source
    }

    /// Borrow only the missing UID-free mutations submitted to the API.
    pub fn mutations(&self) -> &[ChildMutation] {
        &self.mutations
    }

    /// Return the canonical desired digest for one child.
    pub fn desired_digest(&self, target: &ResourceRef) -> Result<String, CloudHypervisorError> {
        let mutation = self
            .source
            .mutations()
            .iter()
            .find(|mutation| mutation.target() == target)
            .ok_or(CloudHypervisorError::BatchResponseInvalid)?;
        let payload = materialize_child_payload(mutation)?;
        d2b_core_controller::semantic_child_digest(&payload)
            .map_err(|_| CloudHypervisorError::BatchResponseInvalid)
    }

    /// Return the canonical UID-free Resource payload for one child.
    pub fn canonical_payload(&self, target: &ResourceRef) -> Result<Vec<u8>, CloudHypervisorError> {
        let mutation = self
            .mutations
            .iter()
            .find(|mutation| mutation.target() == target)
            .ok_or(CloudHypervisorError::BatchResponseInvalid)?;
        materialize_child_payload(mutation)
    }
}

impl fmt::Debug for GuestChildCreateBatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GuestChildCreateBatch")
            .field("child_count", &self.mutations.len())
            .field("has_owner_uid", &true)
            .field("has_owner_revision", &true)
            .finish()
    }
}

/// One exact UID/revision-fenced UpdateSpec request.
#[derive(Clone, PartialEq, Eq)]
pub struct ChildSpecUpdate {
    target: ResourceRef,
    expected_uid: ResourceUid,
    expected_revision: ZoneRevision,
    body: ChildCreateBody,
    desired_lifecycle: Option<DesiredLifecycle>,
}

impl ChildSpecUpdate {
    /// Construct one exact child spec update.
    pub fn new(
        target: ResourceRef,
        expected_uid: ResourceUid,
        expected_revision: ZoneRevision,
        body: ChildCreateBody,
        desired_lifecycle: Option<DesiredLifecycle>,
    ) -> Result<Self, CloudHypervisorError> {
        if expected_revision.get() == 0
            || target.resource_type().as_str()
                != match body {
                    ChildCreateBody::Process(_) => "Process",
                    ChildCreateBody::Endpoint(_) => "Endpoint",
                    ChildCreateBody::Volume(_) => "Volume",
                }
            || target.resource_type().as_str() != "Process" && desired_lifecycle.is_some()
        {
            return Err(CloudHypervisorError::ChildConflict);
        }
        Ok(Self {
            target,
            expected_uid,
            expected_revision,
            body,
            desired_lifecycle,
        })
    }

    /// Borrow the updated child ResourceRef.
    pub const fn target(&self) -> &ResourceRef {
        &self.target
    }

    /// Borrow the exact UID precondition.
    pub const fn expected_uid(&self) -> &ResourceUid {
        &self.expected_uid
    }

    /// Return the exact revision precondition.
    pub const fn expected_revision(&self) -> ZoneRevision {
        self.expected_revision
    }

    /// Borrow the semantic replacement body.
    pub const fn body(&self) -> &ChildCreateBody {
        &self.body
    }

    /// Return the requested Process lifecycle, when present.
    pub const fn desired_lifecycle(&self) -> Option<DesiredLifecycle> {
        self.desired_lifecycle
    }
}

impl fmt::Debug for ChildSpecUpdate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChildSpecUpdate")
            .field("resource_type", &self.target.resource_type())
            .field("has_expected_uid", &true)
            .field("expected_revision", &self.expected_revision)
            .field("has_desired_lifecycle", &self.desired_lifecycle.is_some())
            .finish()
    }
}

/// Bounded Guest status conditions aggregated from base children and
/// dependency states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GuestCondition {
    /// A deterministic direct child is absent.
    ChildMissing(ChildRole),
    /// A deterministic direct child is not Ready.
    ChildNotReady(ChildRole),
    /// A deterministic direct child reported unhealthy.
    ChildUnhealthy(ChildRole),
    /// The Device dependency family is not Ready.
    DeviceDependencyNotReady,
    /// The Network dependency family is not Ready.
    NetworkDependencyNotReady,
    /// The backing Volume dependency family is not Ready.
    VolumeDependencyNotReady,
    /// A required Volume Export is not Ready.
    ExportDependencyNotReady,
    /// A descriptor-declared setup Volume is not Ready.
    SetupVolumeNotReady,
    /// The VMM desired lifecycle is still stopped.
    ProcessStopped,
    /// The authenticated Guest session is not Ready.
    SessionNotReady,
    /// The authenticated Guest session is degraded.
    SessionDegraded,
    /// Process identity could not be adopted exactly after restart.
    AdoptionAmbiguous,
    /// The VMM Process exited or reported a terminal failure.
    VmmProcessExited,
    /// A disruptive D091 update requires a recycle.
    UpgradeRequired,
    /// Finalization is blocked by an unresolved lifecycle condition.
    FinalizationBlocked,
}

/// Public Guest status plus only bounded base conditions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestStatusProjection {
    status: GuestRuntimeStatus,
    conditions: Vec<GuestCondition>,
}

impl GuestStatusProjection {
    /// Construct a bounded status projection.
    fn new(status: GuestRuntimeStatus, mut conditions: Vec<GuestCondition>) -> Self {
        conditions.sort();
        conditions.dedup();
        conditions.truncate(32);
        Self { status, conditions }
    }

    /// Borrow the pure public Guest status.
    pub const fn status(&self) -> &GuestRuntimeStatus {
        &self.status
    }

    /// Borrow bounded status conditions.
    pub fn conditions(&self) -> &[GuestCondition] {
        &self.conditions
    }

    /// Return whether this status contains one bounded condition.
    pub fn has_condition(&self, condition: GuestCondition) -> bool {
        self.conditions.contains(&condition)
    }
}

/// Resource API requests emitted by the authenticated adapter.
#[derive(Clone, PartialEq, Eq)]
pub enum CloudHypervisorResourceRequest {
    /// Register the verified controller descriptor.
    Register {
        /// Controller registration.
        registration: CloudHypervisorControllerRegistration,
    },
    /// Read a fresh Guest snapshot.
    GetGuest {
        /// Guest ResourceRef.
        guest_ref: ResourceRef,
    },
    /// Relist the complete owner-index view.
    RelistOwnedChildren {
        /// Guest owner.
        guest_ref: ResourceRef,
        /// Expected direct child addresses.
        expected_refs: Vec<ResourceRef>,
    },
    /// Read Device, Network, and Volume dependency status.
    ObserveDependencies {
        /// Guest owner.
        guest_ref: ResourceRef,
        /// Pure dependency graph.
        graph: BootstrapGraph,
    },
    /// Create missing direct children atomically.
    CommitBatch {
        /// UID-free bounded batch.
        batch: GuestChildCreateBatch,
    },
    /// Update one child spec under exact identity preconditions.
    UpdateSpec {
        /// Fenced update.
        update: ChildSpecUpdate,
    },
    /// Persist the bounded Guest status projection.
    UpdateStatus {
        /// Guest owner.
        guest_ref: ResourceRef,
        /// Status candidate.
        status: GuestStatusProjection,
    },
    /// Observe Process Provider adoption outcome without exposing identity.
    ObserveProcessAdoption {
        /// Guest owner.
        guest_ref: ResourceRef,
        /// Exact Guest UID fence.
        guest_uid: ResourceUid,
        /// VMM Process child.
        process_ref: ResourceRef,
        /// Exact Process UID fence.
        process_uid: ResourceUid,
        /// Exact Process revision fence.
        process_revision: ZoneRevision,
    },
    /// Assess whether a disruptive D091 upgrade is required.
    AssessUpdate {
        /// Guest owner.
        guest_ref: ResourceRef,
    },
    /// Observe finalization state and owned descendants.
    ObserveFinalization {
        /// Guest owner.
        guest_ref: ResourceRef,
        /// Exact Guest UID fence.
        guest_uid: ResourceUid,
        /// Current direct children.
        children: Vec<OwnedChildSnapshot>,
    },
    /// Drain target-local Guest Resources.
    DrainGuestLocal {
        /// Guest owner.
        guest_ref: ResourceRef,
        /// Exact Guest UID fence.
        guest_uid: ResourceUid,
    },
    /// Close the authenticated Guest-control session.
    CloseGuestSession {
        /// Guest owner.
        guest_ref: ResourceRef,
        /// Exact Guest UID fence.
        guest_uid: ResourceUid,
    },
    /// Delete one direct child under exact identity fencing.
    DeleteChild {
        /// Guest owner.
        guest_ref: ResourceRef,
        /// Exact Guest UID fence.
        guest_uid: ResourceUid,
        /// Exact child fence.
        child: FencedChild,
    },
    /// Invalidate prior session generations.
    InvalidateGuestSession {
        /// Guest owner.
        guest_ref: ResourceRef,
        /// Exact Guest UID fence.
        guest_uid: ResourceUid,
        /// Minimum accepted replacement generation.
        minimum_generation: u64,
    },
    /// Ensure the controller-owned Guest finalizer.
    EnsureGuestFinalizer {
        /// Guest owner.
        guest_ref: ResourceRef,
        /// Exact Guest UID fence.
        guest_uid: ResourceUid,
        /// Exact Guest revision fence.
        guest_revision: ZoneRevision,
    },
    /// Clear the controller-owned Guest finalizer.
    ClearGuestFinalizer {
        /// Guest owner.
        guest_ref: ResourceRef,
        /// Exact Guest UID fence.
        guest_uid: ResourceUid,
        /// Exact Guest revision fence.
        guest_revision: ZoneRevision,
        /// Whether the controller finalizer remains on this snapshot.
        finalizer_present: bool,
    },
}

impl fmt::Debug for CloudHypervisorResourceRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Register { .. } => "CloudHypervisorResourceRequest::Register",
            Self::GetGuest { .. } => "CloudHypervisorResourceRequest::GetGuest",
            Self::RelistOwnedChildren { .. } => {
                "CloudHypervisorResourceRequest::RelistOwnedChildren"
            }
            Self::ObserveDependencies { .. } => {
                "CloudHypervisorResourceRequest::ObserveDependencies"
            }
            Self::CommitBatch { .. } => "CloudHypervisorResourceRequest::CommitBatch",
            Self::UpdateSpec { .. } => "CloudHypervisorResourceRequest::UpdateSpec",
            Self::UpdateStatus { .. } => "CloudHypervisorResourceRequest::UpdateStatus",
            Self::ObserveProcessAdoption { .. } => {
                "CloudHypervisorResourceRequest::ObserveProcessAdoption"
            }
            Self::AssessUpdate { .. } => "CloudHypervisorResourceRequest::AssessUpdate",
            Self::ObserveFinalization { .. } => {
                "CloudHypervisorResourceRequest::ObserveFinalization"
            }
            Self::DrainGuestLocal { .. } => "CloudHypervisorResourceRequest::DrainGuestLocal",
            Self::CloseGuestSession { .. } => "CloudHypervisorResourceRequest::CloseGuestSession",
            Self::DeleteChild { .. } => "CloudHypervisorResourceRequest::DeleteChild",
            Self::InvalidateGuestSession { .. } => {
                "CloudHypervisorResourceRequest::InvalidateGuestSession"
            }
            Self::EnsureGuestFinalizer { .. } => {
                "CloudHypervisorResourceRequest::EnsureGuestFinalizer"
            }
            Self::ClearGuestFinalizer { .. } => {
                "CloudHypervisorResourceRequest::ClearGuestFinalizer"
            }
        })
    }
}

/// Resource API responses returned by an authenticated session.
#[derive(Clone, PartialEq, Eq)]
pub enum CloudHypervisorResourceResponse {
    /// Registration succeeded.
    Registered,
    /// A fresh Guest snapshot.
    Guest(GuestSnapshot),
    /// Complete owner-index rows.
    OwnedChildren(Vec<OwnedChildSnapshot>),
    /// Dependency status.
    Dependencies(GuestDependencySnapshot),
    /// CommitBatch result.
    Committed(GuestChildCommitResponse),
    /// UpdateSpec result.
    Updated(CommittedChild),
    /// UpdateStatus succeeded.
    StatusUpdated,
    /// Process adoption outcome.
    ProcessAdoption(ProcessAdoptionStatus),
    /// D091 update assessment.
    UpdateAssessment(Option<UpgradeReason>),
    /// Finalization observation.
    Finalization(GuestFinalizationInput),
    /// A lifecycle mutation was accepted.
    LifecycleApplied,
}

impl fmt::Debug for CloudHypervisorResourceResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Registered => "CloudHypervisorResourceResponse::Registered",
            Self::Guest(_) => "CloudHypervisorResourceResponse::Guest",
            Self::OwnedChildren(_) => "CloudHypervisorResourceResponse::OwnedChildren",
            Self::Dependencies(_) => "CloudHypervisorResourceResponse::Dependencies",
            Self::Committed(_) => "CloudHypervisorResourceResponse::Committed",
            Self::Updated(_) => "CloudHypervisorResourceResponse::Updated",
            Self::StatusUpdated => "CloudHypervisorResourceResponse::StatusUpdated",
            Self::ProcessAdoption(_) => "CloudHypervisorResourceResponse::ProcessAdoption",
            Self::UpdateAssessment(_) => "CloudHypervisorResourceResponse::UpdateAssessment",
            Self::Finalization(_) => "CloudHypervisorResourceResponse::Finalization",
            Self::LifecycleApplied => "CloudHypervisorResourceResponse::LifecycleApplied",
        })
    }
}

/// A session that is already authenticated and route-pinned by its owner.
#[async_trait]
pub trait AuthenticatedResourceSession: Send + Sync {
    /// Send one bounded Resource API request.
    async fn call(
        &self,
        request: CloudHypervisorResourceRequest,
    ) -> Result<CloudHypervisorResourceResponse, CloudHypervisorResourceApiError>;
}

/// Adapter from an authenticated session to the typed Guest controller API.
pub struct AuthenticatedResourceApiAdapter<S> {
    session: Arc<S>,
}

impl<S> AuthenticatedResourceApiAdapter<S> {
    /// Bind the adapter to an already authenticated session.
    pub const fn new(session: Arc<S>) -> Self {
        Self { session }
    }
}

#[async_trait]
impl<S> CloudHypervisorResourceApi for AuthenticatedResourceApiAdapter<S>
where
    S: AuthenticatedResourceSession + 'static,
{
    async fn register(
        &self,
        registration: &CloudHypervisorControllerRegistration,
    ) -> Result<(), CloudHypervisorResourceApiError> {
        match self
            .session
            .call(CloudHypervisorResourceRequest::Register {
                registration: registration.clone(),
            })
            .await?
        {
            CloudHypervisorResourceResponse::Registered => Ok(()),
            _ => Err(CloudHypervisorResourceApiError::InvalidResponse),
        }
    }

    async fn get_guest(
        &self,
        guest_ref: &ResourceRef,
    ) -> Result<GuestSnapshot, CloudHypervisorResourceApiError> {
        match self
            .session
            .call(CloudHypervisorResourceRequest::GetGuest {
                guest_ref: guest_ref.clone(),
            })
            .await?
        {
            CloudHypervisorResourceResponse::Guest(guest) => Ok(guest),
            _ => Err(CloudHypervisorResourceApiError::InvalidResponse),
        }
    }

    async fn relist_owned_children(
        &self,
        guest: &GuestSnapshot,
        expected_refs: &[ResourceRef],
    ) -> Result<Vec<OwnedChildSnapshot>, CloudHypervisorResourceApiError> {
        match self
            .session
            .call(CloudHypervisorResourceRequest::RelistOwnedChildren {
                guest_ref: guest.resource_ref.clone(),
                expected_refs: expected_refs.to_vec(),
            })
            .await?
        {
            CloudHypervisorResourceResponse::OwnedChildren(children) => Ok(children),
            _ => Err(CloudHypervisorResourceApiError::InvalidResponse),
        }
    }

    async fn observe_dependencies(
        &self,
        guest: &GuestSnapshot,
        graph: &BootstrapGraph,
    ) -> Result<GuestDependencySnapshot, CloudHypervisorResourceApiError> {
        match self
            .session
            .call(CloudHypervisorResourceRequest::ObserveDependencies {
                guest_ref: guest.resource_ref.clone(),
                graph: graph.clone(),
            })
            .await?
        {
            CloudHypervisorResourceResponse::Dependencies(dependencies) => Ok(dependencies),
            _ => Err(CloudHypervisorResourceApiError::InvalidResponse),
        }
    }

    async fn commit_batch(
        &self,
        batch: GuestChildCreateBatch,
    ) -> Result<GuestChildCommitResponse, CloudHypervisorResourceApiError> {
        match self
            .session
            .call(CloudHypervisorResourceRequest::CommitBatch { batch })
            .await?
        {
            CloudHypervisorResourceResponse::Committed(result) => Ok(result),
            _ => Err(CloudHypervisorResourceApiError::InvalidResponse),
        }
    }

    async fn update_spec(
        &self,
        update: ChildSpecUpdate,
    ) -> Result<CommittedChild, CloudHypervisorResourceApiError> {
        match self
            .session
            .call(CloudHypervisorResourceRequest::UpdateSpec { update })
            .await?
        {
            CloudHypervisorResourceResponse::Updated(child) => Ok(child),
            _ => Err(CloudHypervisorResourceApiError::InvalidResponse),
        }
    }

    async fn update_status(
        &self,
        guest: &GuestSnapshot,
        status: GuestStatusProjection,
    ) -> Result<(), CloudHypervisorResourceApiError> {
        match self
            .session
            .call(CloudHypervisorResourceRequest::UpdateStatus {
                guest_ref: guest.resource_ref.clone(),
                status,
            })
            .await?
        {
            CloudHypervisorResourceResponse::StatusUpdated => Ok(()),
            _ => Err(CloudHypervisorResourceApiError::InvalidResponse),
        }
    }

    async fn observe_process_adoption(
        &self,
        guest: &GuestSnapshot,
        process: &OwnedChildSnapshot,
    ) -> Result<ProcessAdoptionStatus, CloudHypervisorResourceApiError> {
        match self
            .session
            .call(CloudHypervisorResourceRequest::ObserveProcessAdoption {
                guest_ref: guest.resource_ref.clone(),
                guest_uid: guest.uid.clone(),
                process_ref: process.resource_ref.clone(),
                process_uid: process.uid.clone(),
                process_revision: process.revision,
            })
            .await?
        {
            CloudHypervisorResourceResponse::ProcessAdoption(status) => Ok(status),
            _ => Err(CloudHypervisorResourceApiError::InvalidResponse),
        }
    }

    async fn assess_update(
        &self,
        guest: &GuestSnapshot,
        children: &[OwnedChildSnapshot],
    ) -> Result<Option<UpgradeReason>, CloudHypervisorResourceApiError> {
        let _ = children;
        match self
            .session
            .call(CloudHypervisorResourceRequest::AssessUpdate {
                guest_ref: guest.resource_ref.clone(),
            })
            .await?
        {
            CloudHypervisorResourceResponse::UpdateAssessment(reason) => Ok(reason),
            _ => Err(CloudHypervisorResourceApiError::InvalidResponse),
        }
    }

    async fn observe_finalization(
        &self,
        guest: &GuestSnapshot,
        children: &[OwnedChildSnapshot],
    ) -> Result<GuestFinalizationInput, CloudHypervisorResourceApiError> {
        match self
            .session
            .call(CloudHypervisorResourceRequest::ObserveFinalization {
                guest_ref: guest.resource_ref.clone(),
                guest_uid: guest.uid.clone(),
                children: children.to_vec(),
            })
            .await?
        {
            CloudHypervisorResourceResponse::Finalization(observation) => Ok(observation),
            _ => Err(CloudHypervisorResourceApiError::InvalidResponse),
        }
    }

    async fn drain_guest_local(
        &self,
        guest: &GuestSnapshot,
    ) -> Result<(), CloudHypervisorResourceApiError> {
        match self
            .session
            .call(CloudHypervisorResourceRequest::DrainGuestLocal {
                guest_ref: guest.resource_ref.clone(),
                guest_uid: guest.uid.clone(),
            })
            .await?
        {
            CloudHypervisorResourceResponse::LifecycleApplied => Ok(()),
            _ => Err(CloudHypervisorResourceApiError::InvalidResponse),
        }
    }

    async fn close_guest_session(
        &self,
        guest: &GuestSnapshot,
    ) -> Result<(), CloudHypervisorResourceApiError> {
        match self
            .session
            .call(CloudHypervisorResourceRequest::CloseGuestSession {
                guest_ref: guest.resource_ref.clone(),
                guest_uid: guest.uid.clone(),
            })
            .await?
        {
            CloudHypervisorResourceResponse::LifecycleApplied => Ok(()),
            _ => Err(CloudHypervisorResourceApiError::InvalidResponse),
        }
    }

    async fn delete_child(
        &self,
        guest: &GuestSnapshot,
        child: FencedChild,
    ) -> Result<(), CloudHypervisorResourceApiError> {
        match self
            .session
            .call(CloudHypervisorResourceRequest::DeleteChild {
                guest_ref: guest.resource_ref.clone(),
                guest_uid: guest.uid.clone(),
                child,
            })
            .await?
        {
            CloudHypervisorResourceResponse::LifecycleApplied => Ok(()),
            _ => Err(CloudHypervisorResourceApiError::InvalidResponse),
        }
    }

    async fn invalidate_guest_session(
        &self,
        guest: &GuestSnapshot,
        minimum_generation: u64,
    ) -> Result<(), CloudHypervisorResourceApiError> {
        match self
            .session
            .call(CloudHypervisorResourceRequest::InvalidateGuestSession {
                guest_ref: guest.resource_ref.clone(),
                guest_uid: guest.uid.clone(),
                minimum_generation,
            })
            .await?
        {
            CloudHypervisorResourceResponse::LifecycleApplied => Ok(()),
            _ => Err(CloudHypervisorResourceApiError::InvalidResponse),
        }
    }

    async fn clear_guest_finalizer(
        &self,
        guest: &GuestSnapshot,
    ) -> Result<(), CloudHypervisorResourceApiError> {
        match self
            .session
            .call(CloudHypervisorResourceRequest::ClearGuestFinalizer {
                guest_ref: guest.resource_ref.clone(),
                guest_uid: guest.uid.clone(),
                guest_revision: guest.revision,
                finalizer_present: guest.controller_finalizer_present,
            })
            .await?
        {
            CloudHypervisorResourceResponse::LifecycleApplied => Ok(()),
            _ => Err(CloudHypervisorResourceApiError::InvalidResponse),
        }
    }

    async fn ensure_guest_finalizer(
        &self,
        guest: &GuestSnapshot,
    ) -> Result<(), CloudHypervisorResourceApiError> {
        match self
            .session
            .call(CloudHypervisorResourceRequest::EnsureGuestFinalizer {
                guest_ref: guest.resource_ref.clone(),
                guest_uid: guest.uid.clone(),
                guest_revision: guest.revision,
            })
            .await?
        {
            CloudHypervisorResourceResponse::LifecycleApplied => Ok(()),
            _ => Err(CloudHypervisorResourceApiError::InvalidResponse),
        }
    }
}

/// Typed authenticated Resource API operations required by the Guest
/// controller.
#[async_trait]
pub trait CloudHypervisorResourceApi: Send + Sync {
    /// Register the controller descriptor.
    async fn register(
        &self,
        registration: &CloudHypervisorControllerRegistration,
    ) -> Result<(), CloudHypervisorResourceApiError>;

    /// Read a fresh Guest snapshot.
    async fn get_guest(
        &self,
        guest_ref: &ResourceRef,
    ) -> Result<GuestSnapshot, CloudHypervisorResourceApiError>;

    /// Replace the complete owner-index relist.
    async fn relist_owned_children(
        &self,
        guest: &GuestSnapshot,
        expected_refs: &[ResourceRef],
    ) -> Result<Vec<OwnedChildSnapshot>, CloudHypervisorResourceApiError>;

    /// Observe all dependency status needed by the pure bootstrap graph.
    async fn observe_dependencies(
        &self,
        guest: &GuestSnapshot,
        graph: &BootstrapGraph,
    ) -> Result<GuestDependencySnapshot, CloudHypervisorResourceApiError>;

    /// Commit missing direct children atomically.
    async fn commit_batch(
        &self,
        batch: GuestChildCreateBatch,
    ) -> Result<GuestChildCommitResponse, CloudHypervisorResourceApiError>;

    /// Update one child spec under exact UID/revision fencing.
    async fn update_spec(
        &self,
        update: ChildSpecUpdate,
    ) -> Result<CommittedChild, CloudHypervisorResourceApiError>;

    /// Persist the bounded Guest status projection.
    async fn update_status(
        &self,
        guest: &GuestSnapshot,
        status: GuestStatusProjection,
    ) -> Result<(), CloudHypervisorResourceApiError>;

    /// Observe Process Provider identity candidates without opening a pidfd.
    ///
    /// The default reports that no restart adoption decision is required.
    /// Production adapters must obtain this outcome from the Process Provider,
    /// never infer identity from a Resource name or status alone.
    async fn observe_process_adoption(
        &self,
        _guest: &GuestSnapshot,
        _process: &OwnedChildSnapshot,
    ) -> Result<ProcessAdoptionStatus, CloudHypervisorResourceApiError> {
        Ok(ProcessAdoptionStatus::Current)
    }

    /// Assess whether a disruptive D091 upgrade is required.
    async fn assess_update(
        &self,
        _guest: &GuestSnapshot,
        _children: &[OwnedChildSnapshot],
    ) -> Result<Option<UpgradeReason>, CloudHypervisorResourceApiError> {
        Ok(None)
    }

    /// Observe the exact state needed for finalizer-safe Guest deletion.
    async fn observe_finalization(
        &self,
        _guest: &GuestSnapshot,
        _children: &[OwnedChildSnapshot],
    ) -> Result<GuestFinalizationInput, CloudHypervisorResourceApiError> {
        Err(CloudHypervisorResourceApiError::Unsupported)
    }

    /// Drain target-local Guest Resources through the authenticated session.
    async fn drain_guest_local(
        &self,
        _guest: &GuestSnapshot,
    ) -> Result<(), CloudHypervisorResourceApiError> {
        Err(CloudHypervisorResourceApiError::Unsupported)
    }

    /// Close the authenticated Guest-control session.
    async fn close_guest_session(
        &self,
        _guest: &GuestSnapshot,
    ) -> Result<(), CloudHypervisorResourceApiError> {
        Err(CloudHypervisorResourceApiError::Unsupported)
    }

    /// Request deletion of one direct child under its exact UID/revision.
    async fn delete_child(
        &self,
        _guest: &GuestSnapshot,
        _child: FencedChild,
    ) -> Result<(), CloudHypervisorResourceApiError> {
        Err(CloudHypervisorResourceApiError::Unsupported)
    }

    /// Invalidate the prior session generation before a replacement session.
    async fn invalidate_guest_session(
        &self,
        _guest: &GuestSnapshot,
        _minimum_generation: u64,
    ) -> Result<(), CloudHypervisorResourceApiError> {
        Err(CloudHypervisorResourceApiError::Unsupported)
    }

    /// Clear the Guest controller finalizer after complete drain.
    async fn clear_guest_finalizer(
        &self,
        _guest: &GuestSnapshot,
    ) -> Result<(), CloudHypervisorResourceApiError> {
        Err(CloudHypervisorResourceApiError::Unsupported)
    }

    /// Ensure the Guest controller finalizer before managing children.
    async fn ensure_guest_finalizer(
        &self,
        _guest: &GuestSnapshot,
    ) -> Result<(), CloudHypervisorResourceApiError> {
        Err(CloudHypervisorResourceApiError::Unsupported)
    }
}

/// Result of one direct-child CommitBatch call.
#[derive(Clone, PartialEq, Eq)]
pub enum GuestChildCommitResponse {
    /// Complete identities returned by the Resource API.
    Committed(Vec<CommittedChild>),
    /// The transport outcome is unknown and requires relisting.
    Uncertain,
    /// The response was bounded but truncated.
    Truncated,
}

impl fmt::Debug for GuestChildCommitResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Committed(_) => "GuestChildCommitResponse::Committed",
            Self::Uncertain => "GuestChildCommitResponse::Uncertain",
            Self::Truncated => "GuestChildCommitResponse::Truncated",
        })
    }
}

/// Result of one Resource API reconcile pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudHypervisorReconcileOutcome {
    /// The bounded status remains pending and should be retried.
    Pending(GuestStatusProjection),
    /// The child batch response requires an authoritative relist.
    RelistRequired(GuestStatusProjection),
    /// The Guest status is ready.
    Ready(GuestStatusProjection),
    /// The Guest status is degraded after prior readiness.
    Degraded(GuestStatusProjection),
}

impl CloudHypervisorReconcileOutcome {
    /// Whether the pass leaves the Guest pending.
    pub const fn is_pending(&self) -> bool {
        matches!(self, Self::Pending(_) | Self::RelistRequired(_))
    }

    /// Borrow the bounded status projection.
    pub const fn status(&self) -> &GuestStatusProjection {
        match self {
            Self::Pending(status)
            | Self::RelistRequired(status)
            | Self::Ready(status)
            | Self::Degraded(status) => status,
        }
    }

    fn from_status(status: GuestStatusProjection, relist_required: bool) -> Self {
        if relist_required {
            return Self::RelistRequired(status);
        }
        match status.status.phase {
            GuestStatusPhase::Ready => Self::Ready(status),
            GuestStatusPhase::Degraded => Self::Degraded(status),
            GuestStatusPhase::Pending | GuestStatusPhase::Draining => Self::Pending(status),
        }
    }
}

/// Cloud Hypervisor Guest controller.
pub struct CloudHypervisorController<A> {
    _config: crate::CloudHypervisorConfig,
    graph: BootstrapGraph,
    descriptor: VerifiedGuestSetupDescriptor,
    registration: CloudHypervisorControllerRegistration,
    api: Arc<A>,
    registered: bool,
    known_child_uids: BTreeMap<(ZoneId, ResourceRef), ResourceUid>,
    pending_retired_child_uids: BTreeSet<(ZoneId, ResourceRef, ResourceUid)>,
    retired_child_uids: BTreeSet<(ZoneId, ResourceRef, ResourceUid)>,
    upgrade_progress: BTreeMap<ResourceUid, (UpgradeReason, usize)>,
    observed_process_status: Option<ProcessAdoptionStatus>,
    lifecycle_intent: Option<DesiredLifecycle>,
}

impl<A> CloudHypervisorController<A>
where
    A: CloudHypervisorResourceApi + 'static,
{
    /// Construct a controller from a verified descriptor without performing a
    /// Resource API call.
    pub fn from_verified_descriptor(
        config: crate::CloudHypervisorConfig,
        graph: BootstrapGraph,
        descriptor: VerifiedGuestSetupDescriptor,
        api: Arc<A>,
    ) -> Result<Self, CloudHypervisorError> {
        config
            .validate()
            .map_err(|_| CloudHypervisorError::InvalidConfiguration)?;
        let registration =
            CloudHypervisorControllerRegistration::from_verified_descriptor(&descriptor)?;
        Ok(Self {
            _config: config,
            graph,
            descriptor,
            registration,
            api,
            registered: false,
            known_child_uids: BTreeMap::new(),
            pending_retired_child_uids: BTreeSet::new(),
            retired_child_uids: BTreeSet::new(),
            upgrade_progress: BTreeMap::new(),
            observed_process_status: None,
            lifecycle_intent: None,
        })
    }

    /// Verify a raw descriptor before binding any authenticated API.
    pub fn from_descriptor(
        config: crate::CloudHypervisorConfig,
        graph: BootstrapGraph,
        descriptor: GuestSetupDescriptor,
        verifier: &impl GuestSetupDescriptorVerifier,
        api: Arc<A>,
    ) -> Result<Self, CloudHypervisorError> {
        let descriptor = descriptor.verify_with(verifier)?;
        Self::from_verified_descriptor(config, graph, descriptor, api)
    }

    /// Borrow the verified controller registration.
    pub const fn registration(&self) -> &CloudHypervisorControllerRegistration {
        &self.registration
    }

    /// Borrow the verified setup descriptor.
    pub const fn descriptor(&self) -> &VerifiedGuestSetupDescriptor {
        &self.descriptor
    }

    /// Set the durable lifecycle intent admitted by the daemon dispatcher.
    pub fn with_lifecycle_intent(mut self, intent: Option<DesiredLifecycle>) -> Self {
        self.lifecycle_intent = intent;
        self
    }

    /// Register the controller on its authenticated Resource API session.
    pub async fn register(&mut self) -> Result<(), CloudHypervisorError> {
        if self.registered {
            return Ok(());
        }
        self.api.register(&self.registration).await?;
        self.registered = true;
        Ok(())
    }

    /// Derive a private UID-based runtime scope without exposing it to the
    /// Resource API.
    pub fn private_runtime_scope(
        &self,
        guest: &GuestSnapshot,
        role: &str,
    ) -> Result<PrivateRuntimeScope, CloudHypervisorError> {
        derive_private_runtime_scope(
            guest.zone_uid(),
            guest.uid(),
            role,
            self.descriptor.descriptor().provider_generation(),
        )
        .map_err(|_| CloudHypervisorError::InvalidGuest)
    }

    /// Reconcile one Guest from a fresh snapshot and complete owner relist.
    pub async fn reconcile(
        &mut self,
        guest_ref: &ResourceRef,
    ) -> Result<CloudHypervisorReconcileOutcome, CloudHypervisorError> {
        if !self.registered {
            return Err(CloudHypervisorError::NotRegistered);
        }
        let guest = self.api.get_guest(guest_ref).await.map_err(|error| {
            eprintln!("cloud-hypervisor-controller-stage=get-guest error={error}");
            error
        })?;
        self.validate_guest(&guest, guest_ref)?;
        if !guest.controller_finalizer_present() {
            self.api.ensure_guest_finalizer(&guest).await?;
            return Ok(CloudHypervisorReconcileOutcome::Pending(
                GuestStatusProjection::new(
                    GuestRuntimeStatus {
                        phase: GuestStatusPhase::Pending,
                        runtime_ready: false,
                        bootstrap_ready: false,
                        active_process_count: 0,
                    },
                    Vec::new(),
                ),
            ));
        }
        self.observed_process_status = None;
        let child_plan = BootstrapGraph::plan_children(
            guest.zone.clone(),
            guest.resource_ref.clone(),
            guest.execution_ref.clone(),
            &self.descriptor,
        )
        .map_err(|_| CloudHypervisorError::InvalidConfiguration)?;
        let expected_refs = child_plan
            .child_batch()
            .mutations()
            .iter()
            .map(|mutation| mutation.target().clone())
            .collect::<Vec<_>>();
        let observed = self
            .api
            .relist_owned_children(&guest, &expected_refs)
            .await
            .map_err(|error| {
                eprintln!("cloud-hypervisor-controller-stage=relist-children error={error}");
                error
            })?;
        let children = self.validate_owner_relist(&guest, &expected_refs, observed)?;
        self.validate_child_incarnations(&guest, &children)?;
        let dependencies = self
            .api
            .observe_dependencies(&guest, &self.graph)
            .await
            .map_err(|error| {
                eprintln!("cloud-hypervisor-controller-stage=observe-dependencies error={error}");
                error
            })?;
        let (dependency_readiness, dependency_conditions) = dependencies.readiness(&self.graph);

        if guest.deleting() {
            return self
                .reconcile_deletion(
                    &guest,
                    &child_plan,
                    &children,
                    dependency_readiness,
                    dependency_conditions,
                )
                .await;
        }

        let upgrade_required = self
            .api
            .assess_update(&guest, &children.values().cloned().collect::<Vec<_>>())
            .await
            .map_err(|error| {
                eprintln!("cloud-hypervisor-controller-stage=assess-update error={error}");
                error
            })?
            .is_some();
        if upgrade_required {
            let status = self.project_status(
                &guest,
                &child_plan,
                &children,
                dependency_readiness,
                dependency_conditions,
                &[GuestCondition::UpgradeRequired],
                true,
            );
            self.api.update_status(&guest, status.clone()).await?;
            return Ok(CloudHypervisorReconcileOutcome::from_status(status, false));
        }
        let mut lifecycle_conditions = Vec::new();
        let mut force_degraded = false;
        if let Some(process) = child_plan
            .child_batch()
            .child_ref(ChildRole::VmmProcess)
            .and_then(|target| children.get(target))
        {
            let mut adoption_blocked = false;
            let adoption = if process.phase() == ResourcePhase::Ready
                && process.owner_ref() == guest.resource_ref()
                && process.owner_uid() == Some(guest.uid())
            {
                ProcessAdoptionStatus::Current
            } else {
                self.api.observe_process_adoption(&guest, process).await?
            };
            match adoption {
                ProcessAdoptionStatus::Unavailable | ProcessAdoptionStatus::Quarantined => {
                    lifecycle_conditions.push(GuestCondition::AdoptionAmbiguous);
                    force_degraded = true;
                    adoption_blocked = true;
                }
                ProcessAdoptionStatus::Absent => {
                    lifecycle_conditions.push(GuestCondition::VmmProcessExited);
                    force_degraded = true;
                    self.observed_process_status = Some(ProcessAdoptionStatus::Absent);
                }
                ProcessAdoptionStatus::Current | ProcessAdoptionStatus::Adopted => {
                    self.observed_process_status = Some(ProcessAdoptionStatus::Current);
                }
            }
            if adoption_blocked {
                let status = self.project_status(
                    &guest,
                    &child_plan,
                    &children,
                    dependency_readiness,
                    dependency_conditions,
                    &lifecycle_conditions,
                    true,
                );
                self.api.update_status(&guest, status.clone()).await?;
                return Ok(CloudHypervisorReconcileOutcome::from_status(status, false));
            }
        }
        if self.observed_process_status.is_none() {
            self.observed_process_status = Some(ProcessAdoptionStatus::Absent);
        }

        let missing = expected_refs
            .iter()
            .filter(|target| !children.contains_key(*target))
            .cloned()
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            let batch = GuestChildCreateBatch::new(&guest, child_plan.child_batch(), missing)?;
            let response = match self.api.commit_batch(batch.clone()).await.map_err(|error| {
                eprintln!("cloud-hypervisor-controller-stage=commit-batch error={error}");
                error
            }) {
                Ok(response) => response,
                Err(error)
                    if matches!(
                        error,
                        CloudHypervisorResourceApiError::Conflict
                            | CloudHypervisorResourceApiError::Uncertain
                            | CloudHypervisorResourceApiError::Truncated
                    ) =>
                {
                    return self
                        .pending_after_batch(
                            &guest,
                            &child_plan,
                            &children,
                            dependency_readiness,
                            dependency_conditions,
                            true,
                            lifecycle_conditions,
                            force_degraded,
                        )
                        .await;
                }
                Err(error) => return Err(error.into()),
            };
            match response {
                GuestChildCommitResponse::Committed(returned) => {
                    match validate_commit_response(&batch, returned) {
                        Ok(_) => {
                            return self
                                .pending_after_batch(
                                    &guest,
                                    &child_plan,
                                    &children,
                                    dependency_readiness,
                                    dependency_conditions,
                                    true,
                                    lifecycle_conditions,
                                    force_degraded,
                                )
                                .await;
                        }
                        Err(CloudHypervisorError::BatchResponseInvalid) => {
                            return self
                                .pending_after_batch(
                                    &guest,
                                    &child_plan,
                                    &children,
                                    dependency_readiness,
                                    dependency_conditions,
                                    true,
                                    lifecycle_conditions,
                                    force_degraded,
                                )
                                .await;
                        }
                        Err(error) => return Err(error),
                    }
                }
                GuestChildCommitResponse::Uncertain | GuestChildCommitResponse::Truncated => {
                    return self
                        .pending_after_batch(
                            &guest,
                            &child_plan,
                            &children,
                            dependency_readiness,
                            dependency_conditions,
                            true,
                            lifecycle_conditions,
                            force_degraded,
                        )
                        .await;
                }
            }
        }
        let committed = BTreeMap::new();

        let desired_lifecycle = if dependency_readiness != DependencyReadiness::Ready {
            DesiredLifecycle::Stopped
        } else {
            self.lifecycle_intent.unwrap_or(DesiredLifecycle::Running)
        };
        match self
            .repair_children(
                child_plan.child_batch(),
                &children,
                &committed,
                desired_lifecycle,
            )
            .await
        {
            Ok(true) => {
                let status = self.project_status(
                    &guest,
                    &child_plan,
                    &children,
                    dependency_readiness,
                    dependency_conditions,
                    &lifecycle_conditions,
                    force_degraded,
                );
                return Ok(CloudHypervisorReconcileOutcome::from_status(status, false));
            }
            Ok(false) => {}
            Err(error)
                if error
                    == CloudHypervisorError::ResourceApi(
                        CloudHypervisorResourceApiError::Conflict,
                    ) =>
            {
                let status = self.project_status(
                    &guest,
                    &child_plan,
                    &children,
                    dependency_readiness,
                    dependency_conditions,
                    &lifecycle_conditions,
                    force_degraded,
                );
                return Ok(CloudHypervisorReconcileOutcome::from_status(status, false));
            }
            Err(error) => return Err(error),
        }

        let status = self.project_status(
            &guest,
            &child_plan,
            &children,
            dependency_readiness,
            dependency_conditions,
            &lifecycle_conditions,
            force_degraded,
        );
        self.api.update_status(&guest, status.clone()).await?;
        Ok(CloudHypervisorReconcileOutcome::from_status(status, false))
    }

    fn validate_guest(
        &self,
        guest: &GuestSnapshot,
        requested_ref: &ResourceRef,
    ) -> Result<(), CloudHypervisorError> {
        if guest.resource_ref() != requested_ref
            || guest.provider_ref() != self.registration.provider_ref()
            || guest.system_artifact_id()
                != Some(self.descriptor.descriptor().system_artifact_id().as_str())
        {
            return Err(CloudHypervisorError::InvalidGuest);
        }
        Ok(())
    }

    fn validate_child_incarnations(
        &mut self,
        guest: &GuestSnapshot,
        children: &BTreeMap<ResourceRef, OwnedChildSnapshot>,
    ) -> Result<(), CloudHypervisorError> {
        let observed = children.keys().cloned().collect::<BTreeSet<_>>();
        let pending = self
            .pending_retired_child_uids
            .iter()
            .filter(|(zone, target, _)| zone == guest.zone() && !observed.contains(target))
            .cloned()
            .collect::<Vec<_>>();
        for retired in pending {
            self.promote_retired_child(retired);
        }
        for child in children.values() {
            let key = (guest.zone().clone(), child.resource_ref().clone());
            if self.retired_child_uids.contains(&(
                guest.zone().clone(),
                child.resource_ref().clone(),
                child.uid().clone(),
            )) {
                return Err(CloudHypervisorError::ChildConflict);
            }
            if self
                .known_child_uids
                .get(&key)
                .is_some_and(|known| known != child.uid())
            {
                return Err(CloudHypervisorError::ChildConflict);
            }
            self.known_child_uids.insert(key, child.uid().clone());
        }
        Ok(())
    }

    fn retire_child(&mut self, guest: &GuestSnapshot, child: &FencedChild) {
        const MAX_PENDING_RETIRED_CHILD_UIDS: usize = 1024;
        if self.pending_retired_child_uids.len() >= MAX_PENDING_RETIRED_CHILD_UIDS {
            if let Some(oldest) = self.pending_retired_child_uids.iter().next().cloned() {
                self.pending_retired_child_uids.remove(&oldest);
            }
        }
        self.pending_retired_child_uids.insert((
            guest.zone().clone(),
            child.target().clone(),
            child.uid().clone(),
        ));
    }

    fn promote_retired_child(&mut self, retired: (ZoneId, ResourceRef, ResourceUid)) {
        self.pending_retired_child_uids.remove(&retired);
        self.known_child_uids
            .remove(&(retired.0.clone(), retired.1.clone()));
        const MAX_RETIRED_CHILD_UIDS: usize = 1024;
        if self.retired_child_uids.len() >= MAX_RETIRED_CHILD_UIDS {
            if let Some(oldest) = self.retired_child_uids.iter().next().cloned() {
                self.retired_child_uids.remove(&oldest);
            }
        }
        self.retired_child_uids.insert(retired);
    }

    fn promote_pending_for_ref(&mut self, guest: &GuestSnapshot, target: &ResourceRef) {
        let pending = self
            .pending_retired_child_uids
            .iter()
            .filter(|(zone, child_ref, _)| zone == guest.zone() && child_ref == target)
            .cloned()
            .collect::<Vec<_>>();
        for retired in pending {
            self.promote_retired_child(retired);
        }
    }

    /// Build a D091 plan from the current exact direct-child observations.
    pub fn plan_upgrade(
        &self,
        guest: &GuestSnapshot,
        children: &BTreeMap<ResourceRef, OwnedChildSnapshot>,
        reason: UpgradeReason,
    ) -> Result<GuestUpgradePlan, CloudHypervisorError> {
        let fenced = children
            .values()
            .map(|child| {
                let role = crate::shutdown::child_role_for_ref(child.resource_ref())
                    .ok_or(CloudHypervisorError::ChildConflict)?;
                FencedChild::new(
                    role,
                    child.resource_ref().clone(),
                    child.uid().clone(),
                    child.revision(),
                )
                .map_err(CloudHypervisorError::LifecyclePlan)
            })
            .collect::<Result<Vec<_>, _>>()?;
        plan_upgrade(
            guest.resource_ref().clone(),
            guest.uid().clone(),
            fenced,
            guest
                .session_evidence()
                .and_then(GuestSessionEvidence::session_generation),
            reason,
        )
        .map_err(CloudHypervisorError::LifecyclePlan)
    }

    /// Execute a D091 recycle through exact Resource API operations.
    pub async fn execute_upgrade(
        &mut self,
        guest: &GuestSnapshot,
        child_plan: &GuestChildGraphPlan,
        upgrade: &GuestUpgradePlan,
    ) -> Result<(), CloudHypervisorError> {
        if upgrade.guest_ref() != guest.resource_ref() || upgrade.guest_uid() != guest.uid() {
            return Err(CloudHypervisorError::ChildConflict);
        }
        let (stored_reason, stored_cursor) = self
            .upgrade_progress
            .get(guest.uid())
            .copied()
            .unwrap_or((upgrade.reason(), 0));
        let mut cursor = if stored_reason == upgrade.reason() {
            stored_cursor
        } else {
            0
        };
        while cursor < upgrade.steps().len() {
            let step = &upgrade.steps()[cursor];
            match step {
                FinalizationStep::DrainGuestLocal => {
                    self.api.drain_guest_local(guest).await?;
                    cursor += 1;
                }
                FinalizationStep::CloseSession => {
                    self.api.close_guest_session(guest).await?;
                    cursor += 1;
                }
                FinalizationStep::RecycleVmm { child } => {
                    let observation = self.observe_upgrade_state(guest, child_plan).await?;
                    if observation.guest_uid() != guest.uid() {
                        return Err(CloudHypervisorError::ChildConflict);
                    }
                    let fresh_process = observation
                        .direct_children()
                        .iter()
                        .find(|current| current.target() == child.target())
                        .cloned();
                    if let Some(fresh) = fresh_process.as_ref()
                        && fresh.uid() != child.uid()
                    {
                        return Err(CloudHypervisorError::ChildConflict);
                    }
                    if observation.process().is_stopped_or_absent() {
                        cursor += 1;
                        self.upgrade_progress
                            .insert(guest.uid().clone(), (upgrade.reason(), cursor));
                        return Ok(());
                    }
                    let process = fresh_process.ok_or(CloudHypervisorError::ChildConflict)?;
                    let mutation = child_plan
                        .child_batch()
                        .mutations()
                        .iter()
                        .find(|mutation| mutation.target() == child.target())
                        .ok_or(CloudHypervisorError::ChildConflict)?;
                    let update = ChildSpecUpdate::new(
                        process.target().clone(),
                        process.uid().clone(),
                        process.revision(),
                        mutation.body().clone(),
                        Some(DesiredLifecycle::Stopped),
                    )?;
                    self.api.update_spec(update).await?;
                    cursor += 1;
                    self.upgrade_progress
                        .insert(guest.uid().clone(), (upgrade.reason(), cursor));
                    return Ok(());
                }
                FinalizationStep::DeleteChild(child) => {
                    if child.deletion_requested() {
                        cursor += 1;
                        self.upgrade_progress
                            .insert(guest.uid().clone(), (upgrade.reason(), cursor));
                        continue;
                    }
                    let observation = self.observe_upgrade_state(guest, child_plan).await?;
                    if observation.guest_uid() != guest.uid() {
                        return Err(CloudHypervisorError::ChildConflict);
                    }
                    if !observation.process().is_stopped_or_absent() {
                        self.upgrade_progress
                            .insert(guest.uid().clone(), (upgrade.reason(), cursor));
                        return Ok(());
                    }
                    let fresh = observation
                        .direct_children()
                        .iter()
                        .find(|current| current.target() == child.target())
                        .cloned();
                    let Some(fresh) = fresh else {
                        self.retire_child(guest, child);
                        self.promote_pending_for_ref(guest, child.target());
                        cursor += 1;
                        self.upgrade_progress
                            .insert(guest.uid().clone(), (upgrade.reason(), cursor));
                        return Ok(());
                    };
                    if fresh.uid() != child.uid() {
                        return Err(CloudHypervisorError::ChildConflict);
                    }
                    if fresh.deletion_requested() || fresh.finalizers_pending() {
                        self.upgrade_progress
                            .insert(guest.uid().clone(), (upgrade.reason(), cursor));
                        return Ok(());
                    }
                    let pending = self.pending_retired_child_uids.contains(&(
                        guest.zone().clone(),
                        child.target().clone(),
                        child.uid().clone(),
                    ));
                    if !pending {
                        self.api.delete_child(guest, fresh.clone()).await?;
                        self.retire_child(guest, &fresh);
                    }
                    self.upgrade_progress
                        .insert(guest.uid().clone(), (upgrade.reason(), cursor));
                    return Ok(());
                }
                FinalizationStep::InvalidateSession {
                    next_generation, ..
                } => {
                    self.api
                        .invalidate_guest_session(guest, *next_generation)
                        .await?;
                    cursor += 1;
                }
                FinalizationStep::StopVmm { .. }
                | FinalizationStep::WaitForDescendants
                | FinalizationStep::ClearGuestFinalizer => {
                    cursor += 1;
                }
            }
            self.upgrade_progress
                .insert(guest.uid().clone(), (upgrade.reason(), cursor));
        }
        self.upgrade_progress.remove(guest.uid());
        Ok(())
    }

    async fn observe_upgrade_state(
        &self,
        guest: &GuestSnapshot,
        child_plan: &GuestChildGraphPlan,
    ) -> Result<GuestFinalizationInput, CloudHypervisorError> {
        let expected_refs = child_plan
            .child_batch()
            .mutations()
            .iter()
            .map(|mutation| mutation.target().clone())
            .collect::<Vec<_>>();
        let children = self
            .api
            .relist_owned_children(guest, &expected_refs)
            .await?;
        self.api
            .observe_finalization(guest, &children)
            .await
            .map_err(CloudHypervisorError::ResourceApi)
    }

    async fn reconcile_deletion(
        &mut self,
        guest: &GuestSnapshot,
        plan: &GuestChildGraphPlan,
        children: &BTreeMap<ResourceRef, OwnedChildSnapshot>,
        dependency_readiness: DependencyReadiness,
        dependency_conditions: Vec<GuestCondition>,
    ) -> Result<CloudHypervisorReconcileOutcome, CloudHypervisorError> {
        let observation = self
            .api
            .observe_finalization(guest, &children.values().cloned().collect::<Vec<_>>())
            .await?;
        let finalization = plan_finalization(observation)?;
        let blocked = matches!(
            finalization.disposition(),
            FinalizationDisposition::Blocked(_)
        );
        for step in finalization.steps() {
            match step {
                FinalizationStep::DrainGuestLocal => {
                    self.api.drain_guest_local(guest).await?;
                }
                FinalizationStep::CloseSession => {
                    self.api.close_guest_session(guest).await?;
                }
                FinalizationStep::StopVmm { child, .. } => {
                    let mutation = plan
                        .child_batch()
                        .mutations()
                        .iter()
                        .find(|mutation| mutation.target() == child.target())
                        .ok_or(CloudHypervisorError::ChildConflict)?;
                    let update = ChildSpecUpdate::new(
                        child.target().clone(),
                        child.uid().clone(),
                        child.revision(),
                        mutation.body().clone(),
                        Some(DesiredLifecycle::Stopped),
                    )?;
                    self.api.update_spec(update).await?;
                }
                FinalizationStep::DeleteChild(child) => {
                    if child.deletion_requested() {
                        continue;
                    }
                    self.api.delete_child(guest, child.clone()).await?;
                    self.retire_child(guest, child);
                }
                FinalizationStep::ClearGuestFinalizer => {
                    let status = self.project_status(
                        guest,
                        plan,
                        children,
                        dependency_readiness,
                        dependency_conditions.clone(),
                        &[],
                        false,
                    );
                    self.api.clear_guest_finalizer(guest).await?;
                    let expected = plan
                        .child_batch()
                        .mutations()
                        .iter()
                        .map(|mutation| mutation.target().clone())
                        .collect::<BTreeSet<_>>();
                    self.known_child_uids.retain(|(zone, target), _| {
                        zone != guest.zone() || !expected.contains(target)
                    });
                    return Ok(CloudHypervisorReconcileOutcome::from_status(status, false));
                }
                FinalizationStep::RecycleVmm { .. }
                | FinalizationStep::WaitForDescendants
                | FinalizationStep::InvalidateSession { .. } => {}
            }
        }
        let extra = if blocked {
            [GuestCondition::FinalizationBlocked].as_slice()
        } else {
            &[]
        };
        let status = self.project_status(
            guest,
            plan,
            children,
            dependency_readiness,
            dependency_conditions,
            extra,
            false,
        );
        Ok(CloudHypervisorReconcileOutcome::from_status(status, false))
    }

    async fn pending_after_batch(
        &self,
        guest: &GuestSnapshot,
        plan: &GuestChildGraphPlan,
        children: &BTreeMap<ResourceRef, OwnedChildSnapshot>,
        dependency_readiness: DependencyReadiness,
        conditions: Vec<GuestCondition>,
        relist_required: bool,
        extra_conditions: Vec<GuestCondition>,
        force_degraded: bool,
    ) -> Result<CloudHypervisorReconcileOutcome, CloudHypervisorError> {
        let status = self.project_status(
            guest,
            plan,
            children,
            dependency_readiness,
            conditions,
            &extra_conditions,
            force_degraded,
        );
        Ok(CloudHypervisorReconcileOutcome::from_status(
            status,
            relist_required,
        ))
    }

    fn validate_owner_relist(
        &self,
        guest: &GuestSnapshot,
        expected_refs: &[ResourceRef],
        observed: Vec<OwnedChildSnapshot>,
    ) -> Result<BTreeMap<ResourceRef, OwnedChildSnapshot>, CloudHypervisorError> {
        let expected = expected_refs.iter().collect::<BTreeSet<_>>();
        let mut children = BTreeMap::new();
        for child in observed {
            if child.zone() != guest.zone()
                || child.owner_ref() != guest.resource_ref()
                || child.owner_uid() != Some(guest.uid())
            {
                return Err(CloudHypervisorError::ChildConflict);
            }
            if !expected.contains(child.resource_ref()) {
                return Err(CloudHypervisorError::ChildConflict);
            }
            if children
                .insert(child.resource_ref().clone(), child)
                .is_some()
            {
                return Err(CloudHypervisorError::ChildConflict);
            }
        }
        let owner = HintTarget::new(
            guest.zone.clone(),
            guest.resource_ref.clone(),
            guest.uid.clone(),
        );
        let indexed = children
            .values()
            .map(|child| {
                let target = HintTarget::new(
                    child.zone.clone(),
                    child.resource_ref.clone(),
                    child.uid.clone(),
                );
                ObservedChild::with_owner_identity(
                    target,
                    guest.resource_ref.clone(),
                    guest.uid.clone(),
                    guest.generation,
                    child.revision,
                    child.spec_digest.clone(),
                    false,
                    false,
                    std::iter::empty(),
                )
                .map(|observed| observed.with_generation(child.generation))
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| CloudHypervisorError::ChildConflict)?;
        let mut owner_index =
            OwnerIndex::new(OwnerLimits::new(8, 128).expect("fixed owner limits"));
        owner_index
            .relist_with_owner_generation(owner, guest.generation, indexed)
            .map_err(|_| CloudHypervisorError::ChildConflict)?;
        Ok(children)
    }

    async fn repair_children(
        &self,
        batch: &GuestChildBatch,
        observed: &BTreeMap<ResourceRef, OwnedChildSnapshot>,
        committed: &BTreeMap<ResourceRef, CommittedChild>,
        desired_lifecycle: DesiredLifecycle,
    ) -> Result<bool, CloudHypervisorError> {
        for mutation in batch.mutations() {
            let target = mutation.target();
            let Some(child) = observed.get(target) else {
                if target.resource_type().as_str() == "Process"
                    && desired_lifecycle == DesiredLifecycle::Running
                    && let Some(identity) = committed.get(target)
                {
                    let update = ChildSpecUpdate::new(
                        target.clone(),
                        identity.uid().clone(),
                        identity.revision(),
                        mutation.body().clone(),
                        Some(desired_lifecycle),
                    )?;
                    self.api.update_spec(update).await?;
                    return Ok(true);
                }
                continue;
            };
            let lifecycle_drift = target.resource_type().as_str() == "Process"
                && child.desired_lifecycle() != Some(desired_lifecycle);
            let process_failed = target.resource_type().as_str() == "Process"
                && matches!(
                    child.phase(),
                    ResourcePhase::Degraded | ResourcePhase::Failed | ResourcePhase::Unknown
                )
                && desired_lifecycle == DesiredLifecycle::Running;
            if lifecycle_drift || process_failed {
                let update = ChildSpecUpdate::new(
                    target.clone(),
                    child.uid().clone(),
                    child.revision(),
                    mutation.body().clone(),
                    (target.resource_type().as_str() == "Process").then_some(desired_lifecycle),
                )?;
                self.api.update_spec(update).await?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn project_status(
        &self,
        guest: &GuestSnapshot,
        plan: &GuestChildGraphPlan,
        children: &BTreeMap<ResourceRef, OwnedChildSnapshot>,
        dependency_readiness: DependencyReadiness,
        mut conditions: Vec<GuestCondition>,
        extra_conditions: &[GuestCondition],
        force_degraded: bool,
    ) -> GuestStatusProjection {
        conditions.extend_from_slice(extra_conditions);
        for mutation in plan.child_batch().mutations() {
            let target = mutation.target();
            let role = [
                ChildRole::VmmProcess,
                ChildRole::ChApiEndpoint,
                ChildRole::GuestControlEndpoint,
                ChildRole::SystemVolume,
            ]
            .into_iter()
            .find(|role| plan.child_batch().child_ref(*role) == Some(target))
            .expect("fixed child plan role");
            match children.get(target) {
                None => conditions.push(GuestCondition::ChildMissing(role)),
                Some(child) => {
                    if role == ChildRole::VmmProcess
                        && matches!(
                            child.phase(),
                            ResourcePhase::Degraded
                                | ResourcePhase::Failed
                                | ResourcePhase::Unknown
                        )
                    {
                        conditions.push(GuestCondition::VmmProcessExited);
                    }
                    if child.phase() != ResourcePhase::Ready
                        || child.generation() != guest.generation()
                    {
                        conditions.push(GuestCondition::ChildNotReady(role));
                    }
                    if !child.healthy() {
                        conditions.push(GuestCondition::ChildUnhealthy(role));
                    }
                }
            }
        }
        let process = plan
            .child_batch()
            .child_ref(ChildRole::VmmProcess)
            .and_then(|target| children.get(target));
        if process.is_none_or(|child| child.desired_lifecycle() != Some(DesiredLifecycle::Running))
        {
            conditions.push(GuestCondition::ProcessStopped);
        }
        let endpoint_ready = [ChildRole::ChApiEndpoint, ChildRole::GuestControlEndpoint]
            .into_iter()
            .all(|role| {
                plan.child_batch()
                    .child_ref(role)
                    .and_then(|target| children.get(target))
                    .is_some_and(|child| child.phase() == ResourcePhase::Ready)
            });
        let process_ready = process.is_some_and(|child| {
            child.phase() == ResourcePhase::Ready
                && child.owner_ref() == guest.resource_ref()
                && child.owner_uid() == Some(guest.uid())
                && child.desired_lifecycle() == Some(DesiredLifecycle::Running)
        });
        let session_observed = guest.session_evidence().is_some();
        let session_evidence = guest
            .session_evidence()
            .cloned()
            .unwrap_or_else(GuestSessionEvidence::failed);
        let session_ready =
            session_observed && session_evidence.health() == GuestSessionHealth::Ready;
        let session_healthy =
            session_observed && session_evidence.health() == GuestSessionHealth::Ready;
        match guest.session_evidence().map(GuestSessionEvidence::health) {
            None => conditions.push(GuestCondition::SessionNotReady),
            Some(GuestSessionHealth::Ready) => {}
            Some(_) => conditions.push(GuestCondition::SessionDegraded),
        }
        let child_healthy = plan.child_batch().mutations().iter().all(|mutation| {
            children.get(mutation.target()).is_some_and(|child| {
                child.healthy()
                    && child.owner_ref() == guest.resource_ref()
                    && child.owner_uid() == Some(guest.uid())
            })
        });
        let observation = GuestStatusObservation {
            generations: guest.generations(),
            dependencies_ready: dependency_readiness == DependencyReadiness::Ready,
            process_ready,
            endpoint_ready,
            session_ready,
            seed_ready: session_observed && session_evidence.seed_ready(),
            session_healthy,
            required_children_healthy: child_healthy,
            deletion_requested: guest.deleting(),
            session_active: session_observed,
            descendants_present: !children.is_empty(),
            process_stopped: !process_ready,
        };
        let mut status = reduce_status(&observation);
        if force_degraded && !guest.deleting() {
            status.phase = GuestStatusPhase::Degraded;
        }
        GuestStatusProjection::new(status, conditions)
    }
}

impl<A> fmt::Debug for CloudHypervisorController<A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudHypervisorController")
            .field("registration", &self.registration)
            .field("registered", &self.registered)
            .finish()
    }
}

fn validate_commit_response(
    batch: &GuestChildCreateBatch,
    returned: Vec<CommittedChild>,
) -> Result<BTreeMap<ResourceRef, CommittedChild>, CloudHypervisorError> {
    let expected = batch
        .mutations()
        .iter()
        .map(|mutation| mutation.target().clone())
        .collect::<BTreeSet<_>>();
    if returned.len() != expected.len() {
        return Err(CloudHypervisorError::BatchResponseInvalid);
    }
    let mut seen_refs = BTreeSet::new();
    let mut seen_uids = BTreeSet::new();
    let mut mapped = BTreeMap::new();
    for child in returned {
        if !expected.contains(child.resource_ref())
            || child.zone() != batch.zone()
            || child.owner_ref() != batch.owner_ref()
            || !seen_refs.insert(child.resource_ref().clone())
            || !seen_uids.insert(child.uid().clone())
        {
            return Err(CloudHypervisorError::BatchResponseInvalid);
        }
        mapped.insert(child.resource_ref().clone(), child);
    }
    Ok(mapped)
}

fn materialize_child_payload(mutation: &ChildMutation) -> Result<Vec<u8>, CloudHypervisorError> {
    let body = serde_json::to_value(mutation.body())
        .map_err(|_| CloudHypervisorError::BatchResponseInvalid)?;
    let mut spec = body
        .get("spec")
        .cloned()
        .ok_or(CloudHypervisorError::BatchResponseInvalid)?;
    let spec_object = spec
        .as_object_mut()
        .ok_or(CloudHypervisorError::BatchResponseInvalid)?;
    match mutation.target().resource_type().as_str() {
        "Process" => {
            spec_object
                .entry("processClass".to_owned())
                .or_insert_with(|| serde_json::Value::String("worker".to_owned()));
            spec_object.entry("sandbox".to_owned()).or_insert_with(|| {
                serde_json::json!({
                    "namespaceClasses": ["mount", "ipc"],
                    "capabilityClasses": [],
                    "seccompClass": "strict",
                    "noNewPrivileges": true,
                    "startRoot": false,
                    "environmentClass": "minimal",
                    "readOnlyRoot": true,
                    "umask": "0022",
                    "oomScoreAdj": 0,
                    "userNamespace": null
                })
            });
        }
        "Endpoint" => {
            let producer_guest = spec_object
                .get("producerRef")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value| value.starts_with("Guest/"));
            spec_object
                .entry("endpointClass".to_owned())
                .or_insert_with(|| serde_json::Value::String("control".to_owned()));
            spec_object
                .entry("transport".to_owned())
                .or_insert_with(|| serde_json::Value::String("opaque-carriage".to_owned()));
            spec_object.entry("locality".to_owned()).or_insert_with(|| {
                serde_json::Value::String(
                    if producer_guest {
                        "cross-domain"
                    } else {
                        "host-local"
                    }
                    .to_owned(),
                )
            });
            spec_object
                .entry("visibility".to_owned())
                .or_insert_with(|| serde_json::Value::String("provider".to_owned()));
            spec_object
                .entry("attachmentPolicy".to_owned())
                .or_insert_with(|| {
                    serde_json::json!({
                        "supported": true,
                        "maxAttachments": 1
                    })
                });
            spec_object
                .entry("consumerPolicy".to_owned())
                .or_insert_with(|| {
                    serde_json::json!({
                        "allowedOperations": ["resolve", "attach", "observe"]
                    })
                });
            spec_object
                .entry("lifecyclePolicy".to_owned())
                .or_insert_with(|| serde_json::Value::String("recycle-with-producer".to_owned()));
        }
        "Volume" => {
            let provider_ref = spec_object
                .get("providerRef")
                .cloned()
                .ok_or(CloudHypervisorError::BatchResponseInvalid)?;
            let execution_ref = spec_object
                .get("executionRef")
                .cloned()
                .ok_or(CloudHypervisorError::BatchResponseInvalid)?;
            let system_artifact_id = spec_object
                .get("systemArtifactId")
                .cloned()
                .ok_or(CloudHypervisorError::BatchResponseInvalid)?;
            let view = spec_object
                .get("view")
                .cloned()
                .ok_or(CloudHypervisorError::BatchResponseInvalid)?;
            let view_name = view.as_str().unwrap_or("system").to_owned();
            spec_object.clear();
            spec_object.insert("providerRef".to_owned(), provider_ref);
            spec_object.insert(
                "source".to_owned(),
                serde_json::json!({
                    "executionRef": execution_ref,
                    "settings": {
                        "kind": "nix-closure",
                        "systemArtifactId": system_artifact_id
                    }
                }),
            );
            spec_object.insert(
                "kind".to_owned(),
                serde_json::Value::String("state".to_owned()),
            );
            spec_object.insert("layout".to_owned(), serde_json::json!([]));
            spec_object.insert(
                "views".to_owned(),
                serde_json::json!({
                    view_name: {
                        "path": "system",
                        "rights": ["read", "write", "create", "delete", "traverse"]
                    }
                }),
            );
            spec_object.insert("attachments".to_owned(), serde_json::json!([]));
            spec_object.insert("quota".to_owned(), serde_json::Value::Null);
        }
        _ => return Err(CloudHypervisorError::BatchResponseInvalid),
    }
    let value = serde_json::json!({
        "apiVersion": "resources.d2bus.org/v3",
        "type": mutation.target().resource_type().as_str(),
        "metadata": {
            "name": mutation.target().name().as_str(),
            "zone": mutation.zone().as_str(),
            "ownerRef": mutation.owner_ref().to_canonical_string(),
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
                "lastAssessedAt": null,
                "observedGeneration": 0,
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
    let bytes =
        serde_json::to_vec(&value).map_err(|_| CloudHypervisorError::BatchResponseInvalid)?;
    let canonical = CanonicalJsonValue::parse(&bytes)
        .map_err(|_| CloudHypervisorError::BatchResponseInvalid)?
        .to_canonical_bytes();
    Ok(canonical)
}
