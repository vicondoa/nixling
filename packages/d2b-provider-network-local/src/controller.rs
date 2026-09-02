//! Async Network controller state machine and typed child-resource projection.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;

use d2b_contracts_resource::v3::{
    IfName, NetworkProvenance, ResourceBundleGenerationId, ResourceGeneration, ResourceRef,
    ResourceUid,
    execution_policy::{BoundedToken, BudgetSpec, ExecutionPolicy},
    guest::GuestSpec,
    network::{
        AttachmentGenerationFence, AttachmentHandle, Ipv4Cidr, MacvtapMode, NetworkSpec,
        SharingPolicy, cidr_overlaps,
    },
    process::{
        CapabilityClass, EnvironmentClass, ExecutionSpec, MountAccess, MountSpec, ProcessClass,
        ProcessSpec, SandboxSpec, TelemetrySpec,
    },
    volume::{
        AttachmentAccess, AttachmentSettings, AttachmentTransport, CleanupPolicy, CreatePolicy,
        EntryAdoptionPolicy, EntryRestartPolicy, EntryType, ForeignChildPolicy, Invariant,
        LayoutEntry, LeaseClass, QuotaEnforcement, QuotaSpec, RepairPolicy, SensitivityClass,
        SourceKind, SourceSettings, ViewRight, ViewSpec, VolumeAttachment, VolumeKind,
        VolumeSource, VolumeSpec,
    },
};

use crate::artifact::{
    ArtifactCatalogEntry, ArtifactResolutionError, resolve_net_vm_system_artifact,
};
use crate::ifname::{
    NetworkIfRole, derive_network_child_name, derive_network_ifname, derive_network_route_name_for,
};
use crate::observe::{NetworkObservation, ObserveDecision, evaluate_observation};
use crate::plan::{ActualState, NetworkReconcilePlan, compute_plan};
use crate::routes::RouteTuple;

/// Config Volume byte ceiling charged to the Host memory budget.
pub const CONFIG_VOLUME_MAX_BYTES: u64 = 4 * 1024 * 1024;
/// Config Volume inode ceiling.
pub const CONFIG_VOLUME_MAX_INODES: u64 = 128;
/// Guest mount path for the read-only config view.
pub const CONFIG_MOUNT_PATH: &str = "/run/d2b/net-config";
/// Network-local's exact Resource finalizer.
pub const NETWORK_FINALIZER: &str = "network.d2bus.org/fabric-cleanup";
/// Default descriptor repair interval.
pub const NETWORK_REPAIR_INTERVAL_SECS: u64 = 30;
/// Maximum descriptor repair interval.
pub const NETWORK_MAX_REPAIR_INTERVAL_SECS: u64 = 60;

/// The cutover contract for the Network resource owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkRunnerContract {
    resource_type: &'static str,
    finalizer: &'static str,
    repair_interval_secs: u64,
    legacy_scheduler_disabled: bool,
    watched_configuration_is_dependency: bool,
}

impl NetworkRunnerContract {
    /// Return the owned ResourceType.
    pub const fn resource_type(self) -> &'static str {
        self.resource_type
    }

    /// Return the exact Network finalizer.
    pub const fn finalizer(self) -> &'static str {
        self.finalizer
    }

    /// Return the bounded repair interval.
    pub const fn repair_interval_secs(self) -> u64 {
        self.repair_interval_secs
    }

    /// Whether the legacy Network scheduler is disabled.
    pub const fn legacy_scheduler_disabled(self) -> bool {
        self.legacy_scheduler_disabled
    }

    /// Whether watched configuration is treated as a dependency.
    pub const fn watched_configuration_is_dependency(self) -> bool {
        self.watched_configuration_is_dependency
    }
}

/// Return the one shared-Runner registration for Network-local.
pub const fn network_runner_contract() -> NetworkRunnerContract {
    NetworkRunnerContract {
        resource_type: "Network",
        finalizer: NETWORK_FINALIZER,
        repair_interval_secs: NETWORK_REPAIR_INTERVAL_SECS,
        legacy_scheduler_disabled: true,
        watched_configuration_is_dependency: true,
    }
}

/// Closed condition reason emitted by the state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkConditionReason {
    /// A bridge effect failed.
    BridgeCreateError,
    /// Config Volume creation failed terminally.
    ConfigVolumeError,
    /// The reserved User dependency is not Ready.
    UserNotReady,
    /// The backing Volume is not Ready.
    VolumeNotReady,
    /// The Guest is not Ready.
    GuestNotReady,
    /// The Guest Volume attachment is not Ready.
    AttachmentNotReady,
    /// A generation fence was stale and must be refreshed.
    StaleGeneration,
    /// A foreign ownership marker blocked mutation.
    ForeignOwnership,
}

impl NetworkConditionReason {
    /// Return the stable redacted reason code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::BridgeCreateError => "bridge-create-error",
            Self::ConfigVolumeError => "config-volume-error",
            Self::UserNotReady => "user-not-ready",
            Self::VolumeNotReady => "volume-not-ready",
            Self::GuestNotReady => "guest-not-ready",
            Self::AttachmentNotReady => "attachment-not-ready",
            Self::StaleGeneration => "stale-projection-generation",
            Self::ForeignOwnership => "foreign-nft-rule-preserved",
        }
    }
}

/// Closed effect failures. No variant carries a caller or kernel value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkEffectError {
    /// Retryable effect failure.
    Transient,
    /// Bridge creation failed.
    BridgeCreate,
    /// Config Volume creation failed.
    ConfigVolume,
    /// Host memory budget rejected the tmpfs charge.
    HostMemoryBudgetExceeded,
    /// Immutable installed configuration generation changed.
    StaleConfigurationGeneration,
    /// Attachment generation changed.
    StaleAttachmentGeneration,
    /// A foreign ownership marker occupies a trusted slot.
    ForeignOwnership,
    /// CIDRs overlap.
    CidrConflict,
    /// Cross-Zone physical-NIC bridge multiplex was refused.
    CrossZoneL2,
    /// A runtime artifact ID could not be resolved.
    Artifact,
    /// The controller reached an invalid state.
    InvalidState,
    /// East-west forwarding was requested without the site-level opt-in.
    EastWestHostOptInRequired,
    /// An external physical-NIC claim was requested without Host-global
    /// authority admission.
    ExternalNicAuthorityRequired,
    /// A Network reconcile did not carry Host-global admission evidence.
    NetworkAdmissionRequired,
    /// Admission evidence did not match the current Network identity.
    NetworkAdmissionMismatch,
    /// A Network admission conflicts with an existing host or Network owner.
    NetworkAdmissionConflict,
    /// A derived interface name collides with an occupied host name.
    NetworkInterfaceCollision,
    /// A derived route name collides with an occupied host route.
    NetworkRouteCollision,
    /// Current host network occupancy could not be observed safely.
    HostNetworkObservationFailed,
    /// A committed attachment reference points outside the enclosing Zone.
    CrossZoneReference,
    /// A committed attachment reference does not reciprocate the Network.
    AttachmentReferenceMismatch,
}

impl NetworkEffectError {
    /// Return the stable redacted error code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Transient => "network-effect-transient",
            Self::BridgeCreate => "bridge-create-error",
            Self::ConfigVolume => "config-volume-error",
            Self::HostMemoryBudgetExceeded => "host-memory-budget-exceeded",
            Self::StaleConfigurationGeneration => "stale-projection-generation",
            Self::StaleAttachmentGeneration => "attachment-generation-mismatch",
            Self::ForeignOwnership => "foreign-nft-rule-preserved",
            Self::CidrConflict => "cidr-conflict",
            Self::CrossZoneL2 => "external-physical-nic-cross-zone-l2",
            Self::Artifact => "net-vm-artifact-resolution",
            Self::InvalidState => "network-controller-invalid-state",
            Self::EastWestHostOptInRequired => "east-west-host-opt-in-required",
            Self::ExternalNicAuthorityRequired => "external-nic-authority-required",
            Self::NetworkAdmissionRequired => "network-admission-required",
            Self::NetworkAdmissionMismatch => "network-admission-mismatch",
            Self::NetworkAdmissionConflict => "network-admission-conflict",
            Self::NetworkInterfaceCollision => "network-interface-collision",
            Self::NetworkRouteCollision => "network-route-collision",
            Self::HostNetworkObservationFailed => "host-network-observation-failed",
            Self::CrossZoneReference => "network-cross-zone-reference",
            Self::AttachmentReferenceMismatch => "network-attachment-mismatch",
        }
    }
}

impl core::fmt::Display for NetworkEffectError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for NetworkEffectError {}

impl From<ArtifactResolutionError> for NetworkEffectError {
    fn from(_: ArtifactResolutionError) -> Self {
        Self::Artifact
    }
}

/// Immutable identity tuple that authorizes one Network host projection.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NetworkAdmissionKey {
    zone_uid: ResourceUid,
    network_uid: ResourceUid,
    network_generation: ResourceGeneration,
    attachment_generation: ResourceGeneration,
    bundle_generation: ResourceBundleGenerationId,
}

impl NetworkAdmissionKey {
    /// Construct an exact host-admission identity tuple.
    pub const fn new(
        zone_uid: ResourceUid,
        network_uid: ResourceUid,
        network_generation: ResourceGeneration,
        attachment_generation: ResourceGeneration,
        bundle_generation: ResourceBundleGenerationId,
    ) -> Self {
        Self {
            zone_uid,
            network_uid,
            network_generation,
            attachment_generation,
            bundle_generation,
        }
    }

    /// Borrow the enclosing Zone identity.
    pub const fn zone_uid(&self) -> &ResourceUid {
        &self.zone_uid
    }

    /// Borrow the Network identity.
    pub const fn network_uid(&self) -> &ResourceUid {
        &self.network_uid
    }

    /// Return the committed Network generation.
    pub const fn network_generation(&self) -> ResourceGeneration {
        self.network_generation
    }

    /// Return the committed attachment generation.
    pub const fn attachment_generation(&self) -> ResourceGeneration {
        self.attachment_generation
    }

    /// Borrow the installed bundle generation.
    pub const fn bundle_generation(&self) -> &ResourceBundleGenerationId {
        &self.bundle_generation
    }
}

fn network_cidrs(spec: &NetworkSpec) -> Vec<Ipv4Cidr> {
    let mut cidrs = vec![spec.lan_cidr().clone(), spec.uplink_cidr().clone()];
    if let Some(external) = spec.external_attachment()
        && let Some(address) = external.ipv4().address()
    {
        cidrs.push(address.clone());
    }
    cidrs
}

fn network_cidr_host_address(cidr: &str, host: u8) -> Option<String> {
    let address = cidr.split_once('/')?.0;
    let mut octets = address
        .split('.')
        .map(|octet| octet.parse::<u8>().ok())
        .collect::<Option<Vec<_>>>()?;
    if octets.len() != 4 {
        return None;
    }
    let last = octets.last_mut()?;
    *last = last.checked_add(host)?;
    Some(
        octets
            .into_iter()
            .map(|octet| octet.to_string())
            .collect::<Vec<_>>()
            .join("."),
    )
}

/// Host-fabric names and CIDRs admitted for one immutable Network identity.
#[derive(Clone, PartialEq, Eq)]
pub struct NetworkAdmissionIntent {
    key: NetworkAdmissionKey,
    cidrs: Vec<Ipv4Cidr>,
    interface_names: Vec<IfName>,
    interface_markers: BTreeMap<IfName, String>,
    route_names: Vec<String>,
    routes: Vec<RouteTuple>,
    route_markers: BTreeMap<RouteTuple, String>,
    ownership_marker: String,
    external_nic: Option<(IfName, MacvtapMode, SharingPolicy)>,
}

impl NetworkAdmissionIntent {
    /// Derive all private host locators from committed Network identity.
    pub fn new(
        key: NetworkAdmissionKey,
        spec: NetworkSpec,
        guest_uids: Vec<ResourceUid>,
    ) -> Result<Self, NetworkEffectError> {
        let mut interface_names = Vec::new();
        let mut interface_markers = BTreeMap::new();
        let provenance = NetworkProvenance::new(
            key.zone_uid().clone(),
            key.network_uid().clone(),
            key.network_generation(),
            key.attachment_generation(),
            key.bundle_generation().clone(),
        );
        for (role, object) in [
            (NetworkIfRole::LanBridge, "bridge:lan"),
            (NetworkIfRole::UplinkBridge, "bridge:uplink"),
            (NetworkIfRole::NetVmLanTap, "tap:net-vm-lan"),
            (NetworkIfRole::NetVmUplinkTap, "tap:net-vm-uplink"),
        ] {
            let ifname = derive_network_ifname(key.zone_uid(), key.network_uid(), role, None)
                .map_err(|_| NetworkEffectError::NetworkInterfaceCollision)?;
            interface_markers.insert(
                ifname.clone(),
                d2b_contracts_resource::v3::derive_network_ownership_marker(&provenance, object),
            );
            interface_names.push(ifname);
        }
        let mut sorted_guest_uids = guest_uids;
        sorted_guest_uids.sort();
        sorted_guest_uids.dedup();
        for guest_uid in &sorted_guest_uids {
            let ifname = derive_network_ifname(
                key.zone_uid(),
                key.network_uid(),
                NetworkIfRole::WorkloadGuestTap,
                Some(guest_uid),
            )
            .map_err(|_| NetworkEffectError::NetworkInterfaceCollision)?;
            interface_markers.insert(
                ifname.clone(),
                d2b_contracts_resource::v3::derive_network_ownership_marker(
                    &provenance,
                    &format!("tap:{}", guest_uid.as_str()),
                ),
            );
            interface_names.push(ifname);
        }
        let external_nic = spec.external_attachment().map(|external| {
            (
                external.parent_interface().clone(),
                external.macvtap_mode(),
                external.sharing_policy(),
            )
        });
        if external_nic.is_some() {
            let ifname = derive_network_ifname(
                key.zone_uid(),
                key.network_uid(),
                NetworkIfRole::ExternalMacvtap,
                None,
            )
            .map_err(|_| NetworkEffectError::NetworkInterfaceCollision)?;
            interface_markers.insert(
                ifname.clone(),
                d2b_contracts_resource::v3::derive_network_ownership_marker(&provenance, "macvtap"),
            );
            interface_names.push(ifname);
        }
        let mut unique_interfaces = BTreeSet::new();
        if interface_names
            .iter()
            .any(|ifname| !unique_interfaces.insert(ifname.as_str().to_owned()))
        {
            return Err(NetworkEffectError::NetworkInterfaceCollision);
        }
        let route_count = spec.routing().host_blocklist().len().max(1);
        let uplink_gateway = network_cidr_host_address(spec.uplink_cidr().as_str(), 2);
        let route_names = (0..route_count)
            .map(|index| derive_network_route_name_for(key.zone_uid(), key.network_uid(), index))
            .collect::<Vec<_>>();
        let route_destinations = if spec.routing().host_blocklist().is_empty() {
            vec![spec.lan_cidr().clone()]
        } else {
            spec.routing().host_blocklist().to_vec()
        };
        let route_device = derive_network_ifname(
            key.zone_uid(),
            key.network_uid(),
            NetworkIfRole::UplinkBridge,
            None,
        )
        .map_err(|_| NetworkEffectError::NetworkInterfaceCollision)?;
        let routes = route_destinations
            .into_iter()
            .map(|destination| {
                Ok(RouteTuple::new(
                    destination.as_str(),
                    uplink_gateway.clone(),
                    Some(route_device.as_str().to_owned()),
                    "main",
                ))
            })
            .collect::<Result<Vec<_>, NetworkEffectError>>()?;
        let route_markers = route_names
            .iter()
            .zip(&routes)
            .map(|(route_name, route)| {
                (
                    route.clone(),
                    d2b_contracts_resource::v3::derive_network_ownership_marker(
                        &provenance,
                        &format!("route:{route_name}"),
                    ),
                )
            })
            .collect();
        let mut unique_routes = BTreeSet::new();
        if route_names.iter().any(|name| !unique_routes.insert(name)) {
            return Err(NetworkEffectError::NetworkRouteCollision);
        }
        let ownership_marker =
            d2b_contracts_resource::v3::derive_network_ownership_marker(&provenance, "network");
        Ok(Self {
            key,
            cidrs: network_cidrs(&spec),
            interface_names,
            interface_markers,
            route_names,
            routes,
            route_markers,
            ownership_marker,
            external_nic,
        })
    }

    /// Borrow the exact identity tuple.
    pub const fn key(&self) -> &NetworkAdmissionKey {
        &self.key
    }

    /// Borrow the Network CIDRs reserved by this intent.
    pub fn cidrs(&self) -> &[Ipv4Cidr] {
        &self.cidrs
    }

    /// Borrow the derived interface names.
    pub fn interface_names(&self) -> &[IfName] {
        &self.interface_names
    }

    /// Borrow the expected ownership marker for one derived interface.
    pub fn interface_ownership_marker(&self, ifname: &IfName) -> Option<&str> {
        self.interface_markers.get(ifname).map(String::as_str)
    }

    /// Borrow the derived route identities.
    pub fn route_names(&self) -> &[String] {
        &self.route_names
    }

    /// Borrow the desired observable route tuples.
    pub fn routes(&self) -> &[RouteTuple] {
        &self.routes
    }

    /// Borrow the expected ownership marker for one derived route tuple.
    pub fn route_ownership_marker(&self, route: &RouteTuple) -> Option<&str> {
        self.route_markers.get(route).map(String::as_str)
    }

    /// Borrow the exact ownership marker expected by host effects.
    pub fn ownership_marker(&self) -> &str {
        &self.ownership_marker
    }

    /// Borrow the optional Host-global physical-NIC claim.
    pub fn external_nic(&self) -> Option<(&IfName, MacvtapMode, SharingPolicy)> {
        self.external_nic
            .as_ref()
            .map(|(parent, mode, sharing)| (parent, *mode, *sharing))
    }

    /// Seal this intent for consumption by the Zone-local reconciler.
    pub fn proof(&self) -> NetworkAdmissionProof {
        NetworkAdmissionProof {
            intent: self.clone(),
        }
    }
}

impl core::fmt::Debug for NetworkAdmissionIntent {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("NetworkAdmissionIntent(<redacted>)")
    }
}

/// Non-serializable proof returned by the root host-admission owner.
#[derive(Clone, PartialEq, Eq)]
pub struct NetworkAdmissionProof {
    intent: NetworkAdmissionIntent,
}

impl NetworkAdmissionProof {
    /// Borrow the admitted identity tuple.
    pub const fn key(&self) -> &NetworkAdmissionKey {
        self.intent.key()
    }

    /// Borrow the admitted host intent.
    pub const fn intent(&self) -> &NetworkAdmissionIntent {
        &self.intent
    }

    /// Verify that the proof is still for the supplied Network generation.
    pub fn matches(
        &self,
        network_uid: &ResourceUid,
        network_generation: ResourceGeneration,
        installed_generation: &ResourceBundleGenerationId,
        spec: &NetworkSpec,
    ) -> bool {
        self.key().network_uid() == network_uid
            && self.key().network_generation() == network_generation
            && self.key().bundle_generation() == installed_generation
            && self.cidrs_match(spec)
    }

    fn cidrs_match(&self, spec: &NetworkSpec) -> bool {
        self.intent.cidrs() == network_cidrs(spec)
    }
}

impl core::fmt::Debug for NetworkAdmissionProof {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("NetworkAdmissionProof(<redacted>)")
    }
}

/// Readiness input from child resources and private realization state.
#[derive(Clone, PartialEq, Eq)]
pub struct ReconcileInput {
    /// Current desired Network spec.
    pub spec: NetworkSpec,
    /// Authored mDNS toggle carried beside the validated Network spec.
    pub mdns_enabled: bool,
    /// Current immutable Network identity.
    pub network_uid: ResourceUid,
    /// Current Network resource generation.
    pub network_generation: ResourceGeneration,
    /// Current aggregate Guest-attachment generation.
    pub attachment_generation: ResourceGeneration,
    /// Immutable installed configuration generation used as the firewall fence.
    pub installed_generation: ResourceBundleGenerationId,
    /// Root-owned Host-global admission proof for this Network.
    pub admission: NetworkAdmissionProof,
    /// Declared private artifact catalog.
    pub artifact_catalog: Vec<ArtifactCatalogEntry>,
    /// Reserved User resource is Ready.
    pub user_ready: bool,
    /// Host memory budget can admit the config tmpfs charge.
    pub host_memory_budget_available: u64,
    /// Volume backing readiness.
    pub volume_ready: bool,
    /// Net-VM Guest readiness.
    pub guest_ready: bool,
    /// Volume attachment readiness.
    pub volume_attachment_ready: bool,
    /// Workload VMM owners have closed all attachment FDs.
    pub workload_fds_closed: bool,
    /// Owned child deletion observations.
    pub agent_deleted: bool,
    /// Owned mDNS child deletion observations.
    pub mdns_deleted: bool,
    /// The Volume attachment removal was confirmed.
    pub volume_attachment_removed: bool,
    /// The net-VM Guest deletion was confirmed.
    pub guest_deleted: bool,
    /// The config Volume deletion was confirmed.
    pub volume_deleted: bool,
    /// Retained attachment realizations.
    pub attachments: Vec<AttachmentRealization>,
}

impl core::fmt::Debug for ReconcileInput {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ReconcileInput(<redacted>)")
    }
}

/// Private retained attachment realization.
#[derive(Clone, PartialEq, Eq)]
pub struct AttachmentRealization {
    /// Opaque handle and exact generation fence.
    pub handle: AttachmentHandle,
    /// Whether its owning VMM has closed the FD.
    pub vmm_fd_closed: bool,
}

impl core::fmt::Debug for AttachmentRealization {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AttachmentRealization(<redacted>)")
    }
}

/// Opaque firewall effect intent.
#[derive(Clone, PartialEq, Eq)]
pub struct FirewallIntent {
    network_uid: ResourceUid,
    zone_uid: Option<ResourceUid>,
    network_generation: Option<ResourceGeneration>,
    attachment_generation: Option<ResourceGeneration>,
    expected_generation_id: ResourceBundleGenerationId,
}

impl FirewallIntent {
    /// Construct a projection-scoped immutable-generation intent.
    pub const fn new(
        network_uid: ResourceUid,
        expected_generation_id: ResourceBundleGenerationId,
    ) -> Self {
        Self {
            network_uid,
            zone_uid: None,
            network_generation: None,
            attachment_generation: None,
            expected_generation_id,
        }
    }

    /// Construct a firewall intent bound to the complete Network admission
    /// tuple.
    pub fn from_admission(
        admission: &NetworkAdmissionProof,
        expected_generation_id: ResourceBundleGenerationId,
    ) -> Self {
        let key = admission.key();
        Self {
            network_uid: key.network_uid().clone(),
            zone_uid: Some(key.zone_uid().clone()),
            network_generation: Some(key.network_generation()),
            attachment_generation: Some(key.attachment_generation()),
            expected_generation_id,
        }
    }

    /// Borrow the expected immutable installed generation.
    pub const fn expected_generation_id(&self) -> &ResourceBundleGenerationId {
        &self.expected_generation_id
    }

    /// Borrow the opaque Network identity for the Core effect adapter.
    pub const fn network_uid(&self) -> &ResourceUid {
        &self.network_uid
    }

    /// Borrow the bound Zone identity, when this is an admitted intent.
    pub const fn zone_uid(&self) -> Option<&ResourceUid> {
        self.zone_uid.as_ref()
    }

    /// Return the bound Network generation, when present.
    pub const fn network_generation(&self) -> Option<ResourceGeneration> {
        self.network_generation
    }

    /// Return the bound attachment generation, when present.
    pub const fn attachment_generation(&self) -> Option<ResourceGeneration> {
        self.attachment_generation
    }
}

impl core::fmt::Debug for FirewallIntent {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("FirewallIntent(<redacted>)")
    }
}

/// Opaque projection digest returned by the effect adapter.
#[derive(Clone, PartialEq, Eq)]
pub struct FirewallDigest([u8; 32]);

impl FirewallDigest {
    /// Construct from trusted digest bytes.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl core::fmt::Debug for FirewallDigest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("FirewallDigest(<redacted>)")
    }
}

/// All host effects injected into the controller.
pub trait NetworkEffectPort: Send + Sync {
    /// Validate policy that is resolved outside the Network resource.
    ///
    /// The default implementation keeps hermetic Providers independent of
    /// host policy. The production Core adapter overrides it to require
    /// site-level east-west opt-in and Host-global physical-NIC admission
    /// before any host effect is dispatched.
    fn validate_policy(
        &self,
        _spec: &NetworkSpec,
    ) -> impl Future<Output = Result<(), NetworkEffectError>> + Send {
        core::future::ready(Ok(()))
    }

    /// Ensure both Network bridges.
    fn create_bridges(
        &self,
        network_uid: &ResourceUid,
    ) -> impl Future<Output = Result<(), NetworkEffectError>> + Send;
    /// Re-apply IPv6 suppression.
    fn apply_sysctls(
        &self,
        network_uid: &ResourceUid,
    ) -> impl Future<Output = Result<(), NetworkEffectError>> + Send;
    /// Apply only this Network's firewall projection.
    fn apply_host_firewall(
        &self,
        intent: &FirewallIntent,
    ) -> impl Future<Output = Result<FirewallDigest, NetworkEffectError>> + Send;
    /// Remove only this Network's firewall projection.
    fn remove_host_firewall(
        &self,
        intent: &FirewallIntent,
    ) -> impl Future<Output = Result<(), NetworkEffectError>> + Send;
    /// Remove this Network's owned host routes.
    fn remove_routes(
        &self,
        _network_uid: &ResourceUid,
    ) -> impl Future<Output = Result<(), NetworkEffectError>> + Send {
        core::future::ready(Ok(()))
    }
    /// Reconcile NetworkManager unmanaged state.
    fn apply_nm_unmanaged(&self) -> impl Future<Output = Result<(), NetworkEffectError>> + Send;
    /// Reconcile host routes.
    fn apply_routes(
        &self,
        network_uid: &ResourceUid,
    ) -> impl Future<Output = Result<(), NetworkEffectError>> + Send;
    /// Reconcile the owned hosts block.
    fn update_hosts(
        &self,
        network_uid: &ResourceUid,
    ) -> impl Future<Output = Result<(), NetworkEffectError>> + Send;
    /// Seed new DHCP reservations.
    fn seed_dhcp(
        &self,
        network_uid: &ResourceUid,
    ) -> impl Future<Output = Result<(), NetworkEffectError>> + Send;
    /// Delete one opaque attachment realization.
    fn delete_persistent_tap(
        &self,
        handle: &AttachmentHandle,
        fence: &AttachmentGenerationFence,
    ) -> impl Future<Output = Result<(), NetworkEffectError>> + Send;
    /// Delete both bridges after every tap confirmation.
    fn delete_bridges(
        &self,
        network_uid: &ResourceUid,
    ) -> impl Future<Output = Result<(), NetworkEffectError>> + Send;
}

/// Child-resource mutation port. It accepts typed specs, never raw host paths.
pub trait NetworkResourcePort: Send + Sync {
    /// Create or update backing-only Volume state and charge its tmpfs quota.
    fn upsert_volume_backing(
        &self,
        spec: &VolumeSpec,
    ) -> impl Future<Output = Result<(), NetworkEffectError>> + Send;
    /// Write all four bounded config payloads through the Volume service.
    fn write_volume_content(
        &self,
        content: &NetworkConfigContent,
    ) -> impl Future<Output = Result<(), NetworkEffectError>> + Send;
    /// Create or update the net-VM Guest.
    fn upsert_guest(
        &self,
        spec: &GuestSpec,
    ) -> impl Future<Output = Result<(), NetworkEffectError>> + Send;
    /// Add the typed read-only Guest attachment.
    fn attach_volume(
        &self,
        attachment: &VolumeAttachment,
    ) -> impl Future<Output = Result<(), NetworkEffectError>> + Send;
    /// Create or update the guest-agent Process.
    fn upsert_agent(
        &self,
        spec: &ProcessSpec,
    ) -> impl Future<Output = Result<(), NetworkEffectError>> + Send;
    /// Reconcile mDNS Process resources from the authored toggle.
    fn reconcile_mdns(
        &self,
        enabled: bool,
    ) -> impl Future<Output = Result<(), NetworkEffectError>> + Send;
    /// Delete agent and mDNS Processes.
    fn delete_processes(&self) -> impl Future<Output = Result<(), NetworkEffectError>> + Send;
    /// Remove the Guest attachment from the Volume.
    fn detach_volume(&self) -> impl Future<Output = Result<(), NetworkEffectError>> + Send;
    /// Delete the net-VM Guest.
    fn delete_guest(&self) -> impl Future<Output = Result<(), NetworkEffectError>> + Send;
    /// Delete the config Volume.
    fn delete_volume(&self) -> impl Future<Output = Result<(), NetworkEffectError>> + Send;
}

/// Four bounded files written through the Volume service.
#[derive(Clone, PartialEq, Eq)]
pub struct NetworkConfigContent {
    /// dnsmasq configuration bytes.
    pub dnsmasq: Vec<u8>,
    /// net-VM nftables configuration bytes.
    pub nftables: Vec<u8>,
    /// routing configuration bytes.
    pub routing: Vec<u8>,
    /// attachment table bytes.
    pub attachments: Vec<u8>,
    /// Complete Network identity that authorized these bytes, when the
    /// content was rendered for the production reconcile path.
    pub provenance: Option<NetworkProvenance>,
    digest: [u8; 32],
}

impl NetworkConfigContent {
    /// Return the digest used to request an agent reload.
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Borrow the provenance bound to the rendered content.
    pub const fn provenance(&self) -> Option<&NetworkProvenance> {
        self.provenance.as_ref()
    }
}

impl core::fmt::Debug for NetworkConfigContent {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("NetworkConfigContent(<redacted>)")
    }
}

/// Ordered reconciliation progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileProgress {
    /// All desired state converged.
    Ready,
    /// Waiting for a dependency watch event.
    Pending(NetworkConditionReason),
    /// Refresh desired state before retrying a stale effect.
    Requeue(NetworkConditionReason),
    /// Cleanup or reconcile is blocked fail closed.
    Blocked(NetworkConditionReason),
}

/// Strict finalizer stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalizerStage {
    /// Stop workload VMM owners and wait for FD closure.
    WorkloadFdClosure,
    /// Delete retained persistent taps.
    PersistentTaps,
    /// Delete owned agent and mDNS Processes.
    Processes,
    /// Remove the Guest attachment from the Volume.
    VolumeAttachment,
    /// Delete the net-VM Guest.
    Guest,
    /// Delete the config Volume.
    Volume,
    /// Remove host effects and bridges.
    HostFabric,
    /// Finalizer can be cleared.
    Complete,
}

/// Bounded metric label sets. Keys and values are closed enums.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkMetricLabels {
    /// Semantic operation.
    pub operation: &'static str,
    /// Closed outcome.
    pub outcome: &'static str,
    /// Closed error class.
    pub error: &'static str,
}

impl NetworkMetricLabels {
    /// Build labels from closed semantic values only.
    pub const fn new(
        operation: NetworkMetricOperation,
        outcome: NetworkMetricOutcome,
        error: Option<NetworkEffectError>,
    ) -> Self {
        Self {
            operation: operation.label(),
            outcome: outcome.label(),
            error: match error {
                Some(value) => value.code(),
                None => "none",
            },
        }
    }
}

/// Closed metric operation values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMetricOperation {
    /// Reconcile pass.
    Reconcile,
    /// Observe pass.
    Observe,
    /// Finalizer pass.
    Finalize,
    /// Config Volume sync.
    VolumeSync,
    /// Agent reload.
    AgentReload,
}

impl NetworkMetricOperation {
    const fn label(self) -> &'static str {
        match self {
            Self::Reconcile => "reconcile",
            Self::Observe => "observe",
            Self::Finalize => "finalize",
            Self::VolumeSync => "volume-sync",
            Self::AgentReload => "agent-reload",
        }
    }
}

/// Closed metric outcome values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMetricOutcome {
    /// Operation converged.
    Success,
    /// Operation will retry.
    Retry,
    /// Operation is blocked.
    Blocked,
}

impl NetworkMetricOutcome {
    const fn label(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Retry => "retry",
            Self::Blocked => "blocked",
        }
    }
}

/// Stateless async Network reconciler.
pub struct NetworkReconciler<E, R> {
    effects: E,
    resources: R,
}

impl<E, R> NetworkReconciler<E, R>
where
    E: NetworkEffectPort,
    R: NetworkResourcePort,
{
    /// Construct with injected effect and resource ports.
    pub const fn new(effects: E, resources: R) -> Self {
        Self { effects, resources }
    }

    /// Compute the effect-free desired-versus-actual plan.
    pub fn plan(&self, input: &ReconcileInput, actual: ActualState) -> NetworkReconcilePlan {
        compute_plan(&input.spec, input.mdns_enabled, actual)
    }

    /// Evaluate projection, sysctl, bridge-port, CIDR, authority, and agent
    /// observations without performing an effect.
    pub fn observe(
        &self,
        observation: NetworkObservation,
    ) -> Result<ObserveDecision, NetworkEffectError> {
        evaluate_observation(observation)
    }

    /// Refuse adoption without root-owned Network admission evidence.
    pub fn adopt(
        &self,
        _observation: NetworkObservation,
    ) -> Result<ObserveDecision, NetworkEffectError> {
        Err(NetworkEffectError::NetworkAdmissionRequired)
    }

    /// Adopt an already-converged projection only with root-owned admission.
    pub fn adopt_with_admission(
        &self,
        proof: &NetworkAdmissionProof,
        observation: NetworkObservation,
    ) -> Result<ObserveDecision, NetworkEffectError> {
        if proof.intent().ownership_marker().is_empty() {
            return Err(NetworkEffectError::NetworkAdmissionMismatch);
        }
        self.observe(observation)
    }

    /// Run ordered reconcile while enforcing every child-readiness barrier.
    pub async fn reconcile(
        &self,
        input: &ReconcileInput,
    ) -> Result<ReconcileProgress, NetworkEffectError> {
        validate_input(input)?;
        if !input.user_ready {
            return Ok(ReconcileProgress::Pending(
                NetworkConditionReason::UserNotReady,
            ));
        }
        if input.host_memory_budget_available < CONFIG_VOLUME_MAX_BYTES {
            return Err(NetworkEffectError::HostMemoryBudgetExceeded);
        }
        self.effects.validate_policy(&input.spec).await?;
        if !input.admission.matches(
            &input.network_uid,
            input.network_generation,
            &input.installed_generation,
            &input.spec,
        ) {
            return Err(NetworkEffectError::NetworkAdmissionMismatch);
        }

        self.effects
            .create_bridges(&input.network_uid)
            .await
            .map_err(|_| NetworkEffectError::BridgeCreate)?;
        self.effects.apply_sysctls(&input.network_uid).await?;
        let firewall =
            FirewallIntent::from_admission(&input.admission, input.installed_generation.clone());
        match self.effects.apply_host_firewall(&firewall).await {
            Err(NetworkEffectError::StaleConfigurationGeneration) => {
                return Ok(ReconcileProgress::Requeue(
                    NetworkConditionReason::StaleGeneration,
                ));
            }
            Err(NetworkEffectError::ForeignOwnership) => {
                return Ok(ReconcileProgress::Blocked(
                    NetworkConditionReason::ForeignOwnership,
                ));
            }
            result => {
                result?;
            }
        }
        self.effects.apply_nm_unmanaged().await?;
        self.effects.apply_routes(&input.network_uid).await?;
        self.effects.update_hosts(&input.network_uid).await?;
        self.effects.seed_dhcp(&input.network_uid).await?;

        let net_vm_name = derive_network_child_name(&input.network_uid, "vm");
        let volume = config_volume_spec("host-system", Some(&net_vm_name))?;
        self.resources
            .upsert_volume_backing(&volume)
            .await
            .map_err(|_| NetworkEffectError::ConfigVolume)?;
        let provenance = NetworkProvenance::new(
            input.admission.key().zone_uid().clone(),
            input.admission.key().network_uid().clone(),
            input.admission.key().network_generation(),
            input.admission.key().attachment_generation(),
            input.admission.key().bundle_generation().clone(),
        );
        let content = render_config_with_provenance(&input.spec, &provenance)?;
        if content.provenance() != Some(&provenance) {
            return Err(NetworkEffectError::NetworkAdmissionMismatch);
        }
        self.resources.write_volume_content(&content).await?;
        if !input.volume_ready {
            return Ok(ReconcileProgress::Pending(
                NetworkConditionReason::VolumeNotReady,
            ));
        }

        let artifact = resolve_net_vm_system_artifact(&input.spec, &input.artifact_catalog)?;
        self.resources
            .upsert_guest(&GuestSpec::new(
                ExecutionPolicy::system_default(),
                Some(artifact),
            ))
            .await?;
        if !input.guest_ready {
            return Ok(ReconcileProgress::Pending(
                NetworkConditionReason::GuestNotReady,
            ));
        }

        let attachment = config_volume_attachment(&net_vm_name)?;
        self.resources.attach_volume(&attachment).await?;
        if !input.volume_attachment_ready {
            return Ok(ReconcileProgress::Pending(
                NetworkConditionReason::AttachmentNotReady,
            ));
        }

        self.resources
            .upsert_agent(&guest_agent_process_spec(&net_vm_name)?)
            .await?;
        self.resources.reconcile_mdns(input.mdns_enabled).await?;
        for attachment in &input.attachments {
            if attachment.vmm_fd_closed {
                match self
                    .effects
                    .delete_persistent_tap(&attachment.handle, attachment.handle.generation_fence())
                    .await
                {
                    Err(NetworkEffectError::StaleAttachmentGeneration) => {
                        return Ok(ReconcileProgress::Requeue(
                            NetworkConditionReason::StaleGeneration,
                        ));
                    }
                    Err(NetworkEffectError::ForeignOwnership) => {
                        return Ok(ReconcileProgress::Blocked(
                            NetworkConditionReason::ForeignOwnership,
                        ));
                    }
                    result => result?,
                }
            }
        }
        Ok(ReconcileProgress::Ready)
    }

    /// Advance exactly one strict finalizer stage.
    pub async fn finalize(
        &self,
        input: &ReconcileInput,
    ) -> Result<FinalizerStage, NetworkEffectError> {
        validate_input(input)?;
        if !input.workload_fds_closed || input.attachments.iter().any(|item| !item.vmm_fd_closed) {
            return Ok(FinalizerStage::WorkloadFdClosure);
        }
        for attachment in &input.attachments {
            match self
                .effects
                .delete_persistent_tap(&attachment.handle, attachment.handle.generation_fence())
                .await
            {
                Err(NetworkEffectError::Transient) => return Ok(FinalizerStage::PersistentTaps),
                Err(NetworkEffectError::StaleAttachmentGeneration) => {
                    return Ok(FinalizerStage::PersistentTaps);
                }
                result => result?,
            }
        }
        if !input.agent_deleted || !input.mdns_deleted {
            self.resources.delete_processes().await?;
            return Ok(FinalizerStage::Processes);
        }
        if !input.volume_attachment_removed {
            self.resources.detach_volume().await?;
            return Ok(FinalizerStage::VolumeAttachment);
        }
        if !input.guest_deleted {
            self.resources.delete_guest().await?;
            return Ok(FinalizerStage::Guest);
        }
        if !input.volume_deleted {
            self.resources.delete_volume().await?;
            return Ok(FinalizerStage::Volume);
        }
        let firewall =
            FirewallIntent::from_admission(&input.admission, input.installed_generation.clone());
        self.effects.remove_host_firewall(&firewall).await?;
        self.effects.remove_routes(&input.network_uid).await?;
        self.effects.delete_bridges(&input.network_uid).await?;
        Ok(FinalizerStage::Complete)
    }
}

impl<E, R> core::fmt::Debug for NetworkReconciler<E, R> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("NetworkReconciler(<redacted>)")
    }
}

fn validate_input(input: &ReconcileInput) -> Result<(), NetworkEffectError> {
    if input.network_uid != *input.admission.key().network_uid() {
        return Err(NetworkEffectError::NetworkAdmissionMismatch);
    }
    if input.network_generation != input.admission.key().network_generation() {
        return Err(NetworkEffectError::NetworkAdmissionMismatch);
    }
    if input.attachment_generation != input.admission.key().attachment_generation() {
        return Err(NetworkEffectError::NetworkAdmissionMismatch);
    }
    if input.attachments.iter().any(|attachment| {
        let fence = attachment.handle.generation_fence();
        fence.network_uid() != &input.network_uid
            || fence.network_generation() != input.network_generation
            || fence.attachment_generation() != input.admission.key().attachment_generation()
    }) {
        return Err(NetworkEffectError::NetworkAdmissionMismatch);
    }
    if cidr_overlaps(input.spec.lan_cidr(), input.spec.uplink_cidr()) {
        return Err(NetworkEffectError::CidrConflict);
    }
    Ok(())
}

/// Construct the exact backing-only config Volume schema.
pub fn config_volume_spec(
    host_name: &str,
    guest_name: Option<&str>,
) -> Result<VolumeSpec, NetworkEffectError> {
    let owner = ResourceRef::parse("User/net-local-controller")
        .map_err(|_| NetworkEffectError::InvalidState)?;
    let source = VolumeSource::new(
        ResourceRef::parse(&format!("Host/{host_name}"))
            .map_err(|_| NetworkEffectError::InvalidState)?,
        SourceSettings::new(SourceKind::Tmpfs, None)
            .map_err(|_| NetworkEffectError::InvalidState)?,
    )
    .map_err(|_| NetworkEffectError::InvalidState)?;
    let mut layout = vec![
        LayoutEntry::new(
            "",
            EntryType::Directory,
            owner.clone(),
            owner.clone(),
            "0750",
            None,
            Vec::new(),
            Vec::new(),
            ForeignChildPolicy::Preserve,
            true,
            false,
            SensitivityClass::Private,
            CreatePolicy::CreateIfAbsent,
            RepairPolicy::ExactOwner,
            CleanupPolicy::Never,
            EntryAdoptionPolicy::AdoptWithLiveOwnerProof,
            EntryRestartPolicy::RecreateOnControllerRestart,
            LeaseClass::None,
            vec![Invariant::NoSymlink],
        )
        .map_err(|_| NetworkEffectError::InvalidState)?,
    ];
    for path in [
        "dnsmasq.conf",
        "nftables.rules",
        "routing.conf",
        "attachments.json",
    ] {
        layout.push(
            LayoutEntry::new(
                path,
                EntryType::File,
                owner.clone(),
                owner.clone(),
                "0640",
                None,
                Vec::new(),
                Vec::new(),
                ForeignChildPolicy::Fail,
                true,
                false,
                SensitivityClass::Private,
                CreatePolicy::CreateIfAbsent,
                RepairPolicy::ExactOwner,
                CleanupPolicy::OwnerControlled,
                EntryAdoptionPolicy::AdoptWithLiveOwnerProof,
                EntryRestartPolicy::RecreateOnControllerRestart,
                LeaseClass::None,
                vec![Invariant::NoSymlink, Invariant::BrokerOpaqueIdOnly],
            )
            .map_err(|_| NetworkEffectError::InvalidState)?,
        );
    }
    let mut views = BTreeMap::new();
    views.insert(
        "guest-readonly".to_owned(),
        ViewSpec::new("", vec![ViewRight::Read, ViewRight::Traverse])
            .map_err(|_| NetworkEffectError::InvalidState)?,
    );
    let attachments = guest_name
        .map(config_volume_attachment)
        .transpose()?
        .into_iter()
        .collect();
    VolumeSpec::new(
        source,
        VolumeKind::Ephemeral,
        layout,
        views,
        attachments,
        Some(
            QuotaSpec::new(
                Some(CONFIG_VOLUME_MAX_BYTES),
                Some(CONFIG_VOLUME_MAX_INODES),
                QuotaEnforcement::Hard,
            )
            .map_err(|_| NetworkEffectError::InvalidState)?,
        ),
    )
    .map_err(|_| NetworkEffectError::InvalidState)
}

/// Construct the exact read-only virtiofs attachment.
pub fn config_volume_attachment(guest_name: &str) -> Result<VolumeAttachment, NetworkEffectError> {
    VolumeAttachment::new(
        ResourceRef::parse(&format!("Guest/{guest_name}"))
            .map_err(|_| NetworkEffectError::InvalidState)?,
        AttachmentTransport::Virtiofs,
        BoundedToken::parse("guest-readonly").map_err(|_| NetworkEffectError::InvalidState)?,
        AttachmentAccess::ReadOnly,
        CONFIG_MOUNT_PATH,
        AttachmentSettings::default(),
    )
    .map_err(|_| NetworkEffectError::InvalidState)
}

/// Construct the guest-network-namespace agent Process spec.
pub fn guest_agent_process_spec(guest_name: &str) -> Result<ProcessSpec, NetworkEffectError> {
    let sandbox = SandboxSpec::new(
        Vec::new(),
        vec![
            CapabilityClass::NetworkAdmin,
            CapabilityClass::NetworkBind,
            CapabilityClass::NetworkRaw,
        ],
        BoundedToken::parse("strict").map_err(|_| NetworkEffectError::InvalidState)?,
        true,
        false,
        EnvironmentClass::Minimal,
        true,
        Some("0022".to_owned()),
        0,
        None,
    )
    .map_err(|_| NetworkEffectError::InvalidState)?;
    let mount = MountSpec::new(
        ResourceRef::parse("Volume/net-config").map_err(|_| NetworkEffectError::InvalidState)?,
        BoundedToken::parse("guest-readonly").map_err(|_| NetworkEffectError::InvalidState)?,
        CONFIG_MOUNT_PATH,
        MountAccess::ReadOnly,
        true,
    )
    .map_err(|_| NetworkEffectError::InvalidState)?;
    let execution = ExecutionSpec::new(
        ResourceRef::parse(&format!("Guest/{guest_name}"))
            .map_err(|_| NetworkEffectError::InvalidState)?,
        None,
        None,
        ProcessClass::Worker,
        BoundedToken::parse("network-agent").map_err(|_| NetworkEffectError::InvalidState)?,
        None,
        Vec::new(),
        vec![mount],
        sandbox,
        BudgetSpec::default(),
        None,
        Vec::new(),
        TelemetrySpec::default(),
    )
    .map_err(|_| NetworkEffectError::InvalidState)?;
    Ok(ProcessSpec::minimal(execution))
}

/// Render per-Network data into the four config files only.
pub fn render_config(spec: &NetworkSpec) -> Result<NetworkConfigContent, NetworkEffectError> {
    render_config_inner(spec, None)
}

/// Render per-Network data with the immutable identity that authorized it.
pub fn render_config_with_provenance(
    spec: &NetworkSpec,
    provenance: &NetworkProvenance,
) -> Result<NetworkConfigContent, NetworkEffectError> {
    render_config_inner(spec, Some(provenance))
}

fn render_config_inner(
    spec: &NetworkSpec,
    provenance: Option<&NetworkProvenance>,
) -> Result<NetworkConfigContent, NetworkEffectError> {
    let dnsmasq = format!("lan={}\n", spec.lan_cidr().as_str()).into_bytes();
    let nftables = format!(
        "lan={}\nuplink={}\nblocklist={}\n",
        spec.lan_cidr().as_str(),
        spec.uplink_cidr().as_str(),
        d2b_contracts_resource::v3::network::DEFAULT_HOST_BLOCKLIST.join(",")
    )
    .into_bytes();
    let uplink_gateway = cidr_host_address(spec.uplink_cidr(), 2)?;
    let external_gateway = spec
        .external_attachment()
        .and_then(|external| external.ipv4().gateway())
        .map(|gateway| gateway.as_str().to_owned())
        .unwrap_or_default();
    let routing = format!(
        "uplink={}\ngateway={uplink_gateway}\nexternalGateway={external_gateway}\n",
        spec.uplink_cidr().as_str()
    )
    .into_bytes();
    let attachments = format!(
        "[{}]",
        spec.attachments()
            .iter()
            .map(|attachment| attachment.index().to_string())
            .collect::<Vec<_>>()
            .join(",")
    )
    .into_bytes();
    let mut digest_input = Vec::new();
    for bytes in [&dnsmasq, &nftables, &routing, &attachments] {
        digest_input.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        digest_input.extend_from_slice(bytes);
    }
    if let Some(provenance) = provenance {
        let marker = d2b_contracts_resource::v3::derive_network_ownership_marker(
            provenance,
            "network-config",
        );
        digest_input.extend_from_slice(&(marker.len() as u64).to_be_bytes());
        digest_input.extend_from_slice(marker.as_bytes());
    }
    Ok(NetworkConfigContent {
        dnsmasq,
        nftables,
        routing,
        attachments,
        provenance: provenance.cloned(),
        digest: crate::nftables::digest_bytes(&digest_input),
    })
}

fn cidr_host_address(cidr: &Ipv4Cidr, host: u8) -> Result<String, NetworkEffectError> {
    let address = cidr
        .as_str()
        .split_once('/')
        .map(|(address, _)| address)
        .ok_or(NetworkEffectError::InvalidState)?;
    let mut octets = address
        .split('.')
        .map(|octet| {
            octet
                .parse::<u8>()
                .map_err(|_| NetworkEffectError::InvalidState)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if octets.len() != 4 {
        return Err(NetworkEffectError::InvalidState);
    }
    let last = octets.last_mut().ok_or(NetworkEffectError::InvalidState)?;
    *last = last
        .checked_add(host)
        .ok_or(NetworkEffectError::InvalidState)?;
    Ok(octets
        .into_iter()
        .map(|octet| octet.to_string())
        .collect::<Vec<_>>()
        .join("."))
}
