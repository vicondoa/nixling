//! Bundle resolver: map `BundleOpId` opaque references to concrete
//! intent rows the broker live_handlers can execute.
//!
//! # Motivation
//!
//! Per the security contract in
//! `packages/d2b-contracts/src/types.rs::BundleOpId`, mutating broker
//! requests carry opaque IDs that the broker resolves against its own
//! trusted copy of the bundle - the daemon never names raw paths, raw
//! uids/gids, raw argv, raw nft rule text, raw routes, or raw sysctl
//! values.
//!
//! Earlier clean-break broker dispatch arms for `ApplyNftables` /
//! `ApplyRoute` / `ApplySysctl` / `UpdateHostsFile` / `OpenPidfd` /
//! `SpawnRunner` returned an unimplemented target until there was an
//! in-tree code path that turned `bundle_*_intent_ref: BundleOpId` into
//! the concrete `script_body` / `RouteIntent` / `SysctlIntent` /
//! hosts-file bytes / runner argv the live_handlers needed.
//!
//! [`BundleResolver`] closes that gap.
//!
//! # Design
//!
//! `BundleResolver` loads the trusted bundle artifacts from disk
//! (`bundle.json` plus its private compatibility artifacts and the
//! Zone resource/artifact-catalog documents) and builds a deterministic
//! intent table keyed by a documented `BundleOpId` encoding:
//!
//! | Intent          | `BundleOpId` format                                       | Source data                                                       |
//! | --------------- | --------------------------------------------------------- | ----------------------------------------------------------------- |
//! | nft             | `nft:host`                                                | [`crate::host::HostJson::nftables`] (whole-host table)            |
//! | Network projection | `network-bridge:<zone-uid>:<network-uid>:<name-token>:<role>` | committed Zone Network resource and derived bridge policy      |
//! | Network firewall  | `network-firewall:<zone-uid>:<network-uid>:<name-token>` | committed Network projection + ownership-marker row              |
//! | Network route     | `network-route:<zone-uid>:<network-uid>:<name-token>:<idx>` | committed Network routing policy and derived gateway          |
//! | Network sysctl    | `network-sysctl:<zone-uid>:<network-uid>:<name-token>:<if-role>:<key>` | committed Network bridge hardening policy                 |
//! | Network hosts     | `network-hosts:<zone-uid>:<network-uid>:<name-token>` | committed Network resource projection                           |
//! | Network TAP       | `network-tap:<sha256>`                                      | complete Zone/Network/attachment/generation TAP identity      |
//! | NM unmanaged    | `nm-unmanaged:host`                                       | [`crate::host::NetworkManagerUnmanaged`]                          |
//! | USBIP firewall  | `usbip-fw:env:<env>:bus:<bus_id>`                         | [`crate::host::UsbipBusidLock`] + nft chain template              |
//! | USBIP bind      | `usbip-bind:env:<env>:vm:<vm>:bus:<bus_id>`               | [`crate::host::UsbipBusidLock`]                                   |
//! | runner          | `runner:zone:<zone>:vm:<vm>:role:<role_id>`               | descriptor-bound private artifact-catalog intent |
//! | Guest VMM       | `runner:zone:<zone>:vm:<guest>:role:cloud-hypervisor`    | descriptor-bound private artifact-catalog intent |
//! | legacy runner   | `runner:vm:<vm>:role:<role_id>`                           | compatibility [`crate::processes::ProcessNode`] intent |
//! | role socket     | `socket:vm:<vm>:role:<role_id>`                           | [`crate::processes::ProcessNode`] (derived `/run/d2b/vms/...`)|
//!
//! The encoding is **deterministic**: callers (the daemon, integrators
//! preparing test fixtures, and the broker itself) build a
//! `BundleOpId` by formatting these well-known strings, and the
//! resolver looks them up. There is no out-of-band ID allocation /
//! UUIDs - every intent_id is reconstructable from the bundle data
//! alone, so the security property "the broker never trusts a
//! caller-supplied authority-bearing payload" is preserved: the
//! daemon's `bundle_*_intent_ref` value is a *lookup key*, not the
//! authority it points at.
//!
//! # What the resolver deliberately does **not** do
//!
//! - **Broker wiring**: the broker `dispatch_request` may still surface
//!   `Unimplemented` for real-wire arms until they are wired to this
//!   resolver (with `fd_passing::send_with_fd` for `OpenPidfd` /
//!   `SpawnRunner`).
//! - **Legacy runner compatibility**: non-Guest callers may still load
//!   `processes.json`, but the current Guest VMM path requires the complete
//!   descriptor-bound private intent emitted by the artifact catalog.

use crate::allocator_config::{AllocatorJson, AllocatorZoneTopology};
use crate::bundle::{Bundle, BundleGeneration};
use crate::closures::ClosureMetadata;
use crate::error::Error;
use crate::host::{
    ChNetHandoffMode, HostJson, HostsFileOwnership, ModuleRequirement, NetEnv,
    NetworkManagerUnmanaged, NftablesModel, OwnershipRule, QemuMediaSourceIntent, SitePolicy,
    TapRole, UsbipBusidLock, VendorProductPair,
};
use crate::host_w3::{ModuleRequirementW3, TapRoleW3};
use crate::manifest_v04::{ManifestV04, VmEntry};
use crate::minijail_profile::{CgroupPlacement, MountPolicy, NamespaceSet, WritablePath};
use crate::processes::{
    ProcessExecutionDomain, ProcessMacvtapMode, ProcessNetworkInterfaceType, ProcessNode,
    ProcessRole, ProcessesJson, RoleProfile, VmProcessDag,
};
use crate::storage::StorageJson;
use crate::sync::SyncJson;
use crate::unsafe_local_workloads::{UnsafeLocalWorkload, UnsafeLocalWorkloadsJson};
use d2b_contracts::{
    RealmIdentityConfigJson, controller_config::RealmControllersJson,
    launcher::RealmWorkloadsLauncherV2Json,
};
use d2b_contracts_resource::v3::{
    IfName, NetworkIfRole, NetworkProvenance, ResourceRef, ResourceUid, ZoneId,
    derive_network_ifname, derive_network_route_name,
    network::NetworkSpec,
    resource_schema::{CanonicalJsonValue, framed_canonical_digest},
    storage::ZoneStoreStorageRow,
};
use d2b_contracts_zone_session::v3::resource_bundle::{
    ARTIFACT_CATALOG_DOMAIN_TAG, ProcessTemplateBinding, ResourceBundle,
};
use serde::Deserialize;
use sha2::Digest as _;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Read as _;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// Trusted-bundle intent lookup tables loaded from the broker-configured
/// `bundle_path`. See the module docs for the `BundleOpId` encoding
/// contract.
#[derive(Clone)]
pub struct BundleResolver {
    pub bundle: Bundle,
    pub allocator: Option<AllocatorJson>,
    zone_topology: Option<AllocatorZoneTopology>,
    pub host: HostJson,
    pub processes: ProcessesJson,
    zone_resource_bundles: BTreeMap<String, Vec<u8>>,
    guest_setup_descriptors: BTreeMap<(String, String), Vec<u8>>,
    guest_setup_descriptor_catalog_keys: BTreeMap<(String, String), String>,
    guest_vmm_intents: BTreeMap<(String, String), ResolvedRunnerIntent>,
    guest_vmm_zone_uids: BTreeMap<(String, String), ResourceUid>,
    zone_storage_rows: BTreeMap<String, ZoneStoreStorageRow>,
    pub storage: Option<StorageJson>,
    pub sync: Option<SyncJson>,
    pub realm_controllers: Option<RealmControllersJson>,
    pub realm_identity: Option<RealmIdentityConfigJson>,
    pub realm_workloads_launcher_v2: Option<RealmWorkloadsLauncherV2Json>,
    pub unsafe_local_workloads: Option<UnsafeLocalWorkloadsJson>,
    pub manifest: ManifestV04,
    audit_bundle_version: String,
    audit_bundle_hash: String,
    installed_generation_identity: Option<ResolvedInstalledGenerationIdentity>,
    nft_intents: BTreeMap<String, ResolvedNftIntent>,
    nft_projection_intents: BTreeMap<String, ResolvedNftablesProjectionIntent>,
    ownership_marker_intents: BTreeMap<String, ResolvedOwnershipMarkerIntent>,
    bridge_intents: BTreeMap<String, ResolvedBridgeIntent>,
    route_intents: BTreeMap<String, ResolvedRouteIntent>,
    sysctl_intents: BTreeMap<String, ResolvedSysctlIntent>,
    hosts_intents: BTreeMap<String, ResolvedHostsIntent>,
    nm_unmanaged_intents: BTreeMap<String, ResolvedNmUnmanagedIntent>,
    usbip_firewall_intents: BTreeMap<String, ResolvedUsbipFirewallIntent>,
    usbip_bind_intents: BTreeMap<String, ResolvedUsbipBindIntent>,
    runner_intents: BTreeMap<String, ResolvedRunnerIntent>,
    socket_intents: BTreeMap<String, ResolvedSocketIntent>,
    installer_intents: BTreeMap<String, ResolvedInstallerIntent>,
    migrate_intents: BTreeMap<String, ResolvedMigrateIntent>,
    activation_intents: BTreeMap<String, ResolvedActivationIntent>,
    store_view_intents: BTreeMap<String, ResolvedStoreViewIntent>,
    gc_intents: BTreeMap<String, ResolvedGcIntent>,
    closure_toplevels: BTreeMap<String, String>,
    keys_rotate_intents: BTreeMap<String, ResolvedKeysRotateIntent>,
    host_key_trust_intents: BTreeMap<String, ResolvedHostKeyTrustIntent>,
    rotate_known_host_intents: BTreeMap<String, ResolvedRotateKnownHostIntent>,
}

impl fmt::Debug for BundleResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BundleResolver")
            .field("bundle_version", &self.bundle.bundle_version)
            .field("zone_count", &self.zone_resource_bundles.len())
            .field(
                "guest_descriptor_count",
                &self.guest_setup_descriptors.len(),
            )
            .field("guest_vmm_count", &self.guest_vmm_intents.len())
            .field("runner_intent_count", &self.runner_intents.len())
            .finish()
    }
}

struct ParsedBundleArtifacts {
    allocator: Option<AllocatorJson>,
    host: HostJson,
    processes: ProcessesJson,
    zone_resource_bundles: BTreeMap<String, Vec<u8>>,
    guest_setup_descriptors: BTreeMap<(String, String), Vec<u8>>,
    guest_setup_descriptor_catalog_keys: BTreeMap<(String, String), String>,
    guest_vmm_intents: BTreeMap<(String, String), ResolvedRunnerIntent>,
    guest_vmm_zone_uids: BTreeMap<(String, String), ResourceUid>,
    guest_store_view_intents: BTreeMap<String, ResolvedStoreViewIntent>,
    provider_controller_templates: Vec<ProcessTemplateBinding>,
    zone_storage_rows: BTreeMap<String, ZoneStoreStorageRow>,
    storage: Option<StorageJson>,
    sync: Option<SyncJson>,
    realm_controllers: Option<RealmControllersJson>,
    realm_identity: Option<RealmIdentityConfigJson>,
    realm_workloads_launcher_v2: Option<RealmWorkloadsLauncherV2Json>,
    unsafe_local_workloads: Option<UnsafeLocalWorkloadsJson>,
    manifest: ManifestV04,
    closures: Vec<ClosureMetadata>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ZoneNativeBundleIndex {
    artifact_hashes: BTreeMap<String, String>,
    bundle_hash: String,
    bundle_version: u32,
    schema_version: String,
    privileges_path: String,
    #[serde(default)]
    realm_workloads_launcher_v2_path: Option<String>,
    zones: Vec<ZoneNativeBundleRef>,
    generation: BundleGeneration,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ZoneNativeBundleRef {
    zone: String,
    path: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ZoneNativeIndexDocument {
    zones: BTreeMap<String, serde_json::Value>,
    topology: ZoneNativeTopology,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ZoneNativeTopology {
    sealed: bool,
    parent_map: BTreeMap<String, Option<String>>,
    parent_map_digest: String,
    generation_by_zone: BTreeMap<String, String>,
}

/// Resolved nft script ready for `live_apply_nftables`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedNftIntent {
    pub intent_id: String,
    /// Scope label for audit (`host` or `env:<env>`).
    pub scope_label: String,
    /// The full `nft -f -` script body.
    pub script_body: String,
    /// Stable digest of `script_body` for drift detection. The
    /// daemon's optional `desired_hash` field on the wire can be
    /// compared against this to assert pre-apply agreement.
    pub desired_hash: String,
    /// Comment marker installed on every emitted rule.
    pub ownership_id: String,
}

/// Trusted bridge configuration resolved from the private host bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedBridgeIntent {
    pub intent_id: String,
    pub scope_label: String,
    pub bridge_ifname: IfName,
    pub mtu: u16,
    pub stp_disabled: bool,
    pub multicast_snooping_disabled: bool,
    pub ipv6_suppressed: bool,
    pub provenance: Option<NetworkProvenance>,
    pub ownership_marker: Option<String>,
}

/// Trusted ownership marker resolved separately from a projection request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedOwnershipMarkerIntent {
    pub intent_id: String,
    pub marker: String,
    /// Network identity that authorized this marker, when applicable.
    pub provenance: Option<NetworkProvenance>,
}

/// Trusted rule set for one ownership-scoped nftables projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedNftablesProjectionIntent {
    pub intent_id: String,
    pub scope_label: String,
    pub script_body: String,
    pub desired_hash: String,
    pub ownership_marker_intent_ref: String,
    pub provenance: Option<NetworkProvenance>,
}

/// Immutable identity of the installed private configuration bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedInstalledGenerationIdentity {
    generation_id: String,
}

impl ResolvedInstalledGenerationIdentity {
    /// Borrow the validated immutable bundle generation identity.
    pub fn as_str(&self) -> &str {
        &self.generation_id
    }
}

/// Resolved ip-route command ready for `live_apply_route`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRouteIntent {
    pub intent_id: String,
    /// `ip route` command body - the part after `ip route add` (or
    /// del / replace). The broker live_handler chooses the verb.
    pub route_spec: String,
    pub destination: String,
    pub via: Option<String>,
    pub device: Option<String>,
    pub table: Option<String>,
    /// Legacy projection metadata; live route ownership is proven by the
    /// durable UID-bound marker record, never by this flag.
    pub owned: bool,
    pub route_name: Option<String>,
    pub provenance: Option<NetworkProvenance>,
    pub ownership_marker: Option<String>,
}

/// Resolved per-link sysctl pair ready for `live_apply_sysctl`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSysctlIntent {
    pub intent_id: String,
    pub key: String,
    pub value: String,
    pub provenance: Option<NetworkProvenance>,
    pub ownership_marker: Option<String>,
}

/// Resolved /etc/hosts managed block ready for `live_update_hosts_file`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedHostsIntent {
    pub intent_id: String,
    pub path: PathBuf,
    pub managed_block: String,
    pub start_marker: String,
    pub end_marker: String,
    pub mode: u32,
    pub provenance: Option<NetworkProvenance>,
    pub ownership_marker: Option<String>,
}

/// Resolved NetworkManager unmanaged drop-in file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedNmUnmanagedIntent {
    pub intent_id: String,
    pub file_path: PathBuf,
    pub contents: String,
    pub mode: u32,
    pub owner: String,
    pub group: String,
    pub reload_behavior: String,
}

/// Resolved per-busid USBIP firewall rule body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedUsbipFirewallIntent {
    pub intent_id: String,
    pub bus_id: String,
    pub env: String,
    pub nft_rule_body: String,
    pub desired_hash: String,
}

/// Resolved USBIP bind plan - per-busid lock + owner VM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedUsbipBindIntent {
    pub intent_id: String,
    pub bus_id: String,
    pub vm_name: String,
    pub env: String,
    pub lock_path: PathBuf,
    pub vendor_product_allowlist: Vec<VendorProductPair>,
    pub dynamic_bus_id: bool,
}

/// Resolved executable startup action for a process-DAG node that would
/// otherwise be treated as readiness-only by the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedVmStartAction {
    PrepareRuntimeDir(ResolvedPrepareDirIntent),
    PrepareStateDir(ResolvedPrepareDirIntent),
    PrepareStoreView(ResolvedStoreViewIntent),
}

/// Resolved startup plan for a process-DAG node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedVmStartIntent {
    pub intent_id: String,
    pub vm_name: String,
    pub role_id: String,
    pub role: ProcessRole,
    pub actions: Vec<ResolvedVmStartAction>,
}

impl ResolvedVmStartIntent {
    pub fn is_readiness_only(&self) -> bool {
        self.actions.is_empty()
    }
}

/// Returned by [`BundleResolver::resolve_disk_init_ops`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedDiskInitOp {
    /// Absolute target path; validated by the broker as under
    /// `/var/lib/d2b/vms/`.
    pub target_path: std::path::PathBuf,
    /// Pre-allocated file size in bytes.
    pub size_bytes: u64,
    /// Unix permission bits (e.g. `0o600`).
    pub mode: u32,
    /// Owner UID - typically the per-VM runner UID.
    pub owner_uid: u32,
    /// Owner GID.
    pub owner_gid: u32,
    /// When `true`, skip creation if file already exists (idempotent).
    pub if_absent: bool,
}

/// Resolved runner spawn plan - input to `live_spawn_runner`'s
/// `SpawnRunnerPlanInput`.
///
/// Resolved runner execve plan. `processes.json` now carries the
/// per-role binary path plus the full argv vector, so the resolver
/// simply round-trips the trusted bundle data for spawnable roles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRunnerIntent {
    pub intent_id: String,
    pub vm_name: String,
    /// Canonical Host or Guest execution target bound by the private bundle.
    pub execution_ref: String,
    /// Optional semantic owner for a static Provider controller Process.
    pub owner_ref: Option<String>,
    /// Canonical execution domain bound by the private bundle.
    pub execution_domain: ProcessExecutionDomain,
    /// Canonical User resource for a user-domain launch.
    pub user_ref: Option<String>,
    pub role_id: String,
    pub role: ProcessRole,
    pub binary_path: PathBuf,
    pub argv: Vec<String>,
    pub env: Vec<String>,
    pub uid: u32,
    pub gid: u32,
    pub supplementary_groups: Vec<u32>,
    pub capabilities: Vec<String>,
    pub namespaces: NamespaceSet,
    pub seccomp_policy_ref: Option<String>,
    pub mount_policy: MountPolicy,
    pub cgroup_placement: CgroupPlacement,
    pub root_carve_out: bool,
    /// Profile id (matches `RoleProfile::profile_id` so the broker
    /// can look up the per-role minijail profile JSON).
    pub profile_id: String,
    /// When `Some`, the broker pre-establishes a single-entry user
    /// namespace for this runner; the child is fake-root inside the NS
    /// and the host-side `capabilities` set should be empty. Set by
    /// virtiofsd (v1.1.2, ADR 0021) and swtpm (v1.2) roles for
    /// least-privilege operation without host caps.
    pub user_namespace: Option<UserNamespaceSpec>,
    /// Umask the broker installs in the spawned child before execve.
    /// None = inherit broker umask.
    pub umask: Option<u32>,
}

/// Single-entry user-NS mapping. See [`ResolvedRunnerIntent::user_namespace`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserNamespaceSpec {
    pub host_uid_for_zero: u32,
    pub host_gid_for_zero: u32,
}

impl ResolvedRunnerIntent {
    /// Convert one trusted process-DAG node into the broker runner intent shape.
    ///
    /// Non-runner/readiness-only roles and runner roles without a safe current or
    /// legacy spawn specification return `None`.
    pub fn from_process_node(vm_name: &str, node: &ProcessNode) -> Option<Self> {
        let role_name = runner_role_name(&node.role)?;
        let execution_ref = node
            .execution_ref
            .clone()
            .unwrap_or_else(|| default_execution_ref(vm_name, &node.role));
        let valid_execution_ref = execution_ref
            .split_once('/')
            .is_some_and(|(kind, name)| matches!(kind, "Host" | "Guest") && !name.is_empty());
        if !valid_execution_ref {
            return None;
        }
        let execution_domain = node
            .execution_domain
            .unwrap_or(ProcessExecutionDomain::System);
        if execution_domain == ProcessExecutionDomain::User
            && node.user_ref.as_deref().is_none_or(|value| {
                value
                    .split_once('/')
                    .is_none_or(|(kind, name)| kind != "User" || name.is_empty())
            })
        {
            return None;
        }
        if execution_domain == ProcessExecutionDomain::System && node.user_ref.is_some() {
            return None;
        }
        let (binary_path, argv) = match node.binary_path.as_deref() {
            Some(binary_path)
                if binary_path.starts_with('/')
                    && !node.argv.is_empty()
                    && !node.argv[0].is_empty()
                    && !is_placeholder_runner_spec(binary_path, &node.argv, role_name) =>
            {
                (binary_path.to_owned(), node.argv.clone())
            }
            _ => legacy_runner_spec(vm_name, &node.role)?,
        };
        // v1.1.1fu11 (Option B): start with the baseline D2B_VM
        // env var, then append any node-specific env entries from the
        // bundle (used by audio/gpu/video sidecars to thread
        // PIPEWIRE_RUNTIME_DIR / XDG_RUNTIME_DIR / WAYLAND_DISPLAY).
        let mut env = vec![format!("D2B_VM={vm_name}")];
        env.extend(node.env.iter().cloned());
        let RoleProfile {
            profile_id,
            uid,
            gid,
            adr_carve_out,
            caps,
            namespaces,
            seccomp_policy_ref,
            mount_policy,
            cgroup_placement,
            user_namespace,
            umask,
        } = &node.profile;
        Some(Self {
            intent_id: intent_id_legacy_runner(vm_name, &node.id.0),
            vm_name: vm_name.to_owned(),
            execution_ref,
            owner_ref: None,
            execution_domain,
            user_ref: node.user_ref.clone(),
            role_id: node.id.0.clone(),
            role: node.role.clone(),
            binary_path: PathBuf::from(binary_path),
            argv,
            env,
            uid: *uid,
            gid: *gid,
            supplementary_groups: Vec::new(),
            capabilities: caps.clone(),
            namespaces: namespaces.clone(),
            seccomp_policy_ref: seccomp_policy_ref.clone(),
            mount_policy: mount_policy.clone(),
            cgroup_placement: cgroup_placement.clone(),
            root_carve_out: adr_carve_out.is_some(),
            profile_id: profile_id.clone(),
            user_namespace: user_namespace.map(UserNamespaceSpec::from),
            umask: *umask,
        })
    }
}

/// Resolve the legacy placement default for one trusted VM-DAG role.
///
/// Host-side infrastructure roles execute in the singleton Host target.
/// The activation runner is the only legacy role whose default placement is
/// the owning Guest. New resource-backed Process rows must carry an explicit
/// `executionRef`.
pub fn default_execution_ref(vm_name: &str, role: &ProcessRole) -> String {
    if matches!(role, ProcessRole::ActivationNixosRunner) {
        format!("Guest/{vm_name}")
    } else {
        "Host/host-system".to_owned()
    }
}

// Convenience From impls across the wire (`UserNamespaceProfile`) and
// intent (`UserNamespaceSpec`) types so layer boundaries can `.into()`
// instead of hand-copying fields.
impl From<crate::minijail_profile::UserNamespaceProfile> for UserNamespaceSpec {
    fn from(p: crate::minijail_profile::UserNamespaceProfile) -> Self {
        Self {
            host_uid_for_zero: p.host_uid_for_zero,
            host_gid_for_zero: p.host_gid_for_zero,
        }
    }
}

impl From<UserNamespaceSpec> for crate::minijail_profile::UserNamespaceProfile {
    fn from(s: UserNamespaceSpec) -> Self {
        Self {
            host_uid_for_zero: s.host_uid_for_zero,
            host_gid_for_zero: s.host_gid_for_zero,
        }
    }
}

impl From<crate::processes::RoleUserNamespace> for UserNamespaceSpec {
    fn from(rn: crate::processes::RoleUserNamespace) -> Self {
        Self {
            host_uid_for_zero: rn.host_uid_for_zero,
            host_gid_for_zero: rn.host_gid_for_zero,
        }
    }
}

impl From<UserNamespaceSpec> for crate::processes::RoleUserNamespace {
    fn from(s: UserNamespaceSpec) -> Self {
        Self {
            host_uid_for_zero: s.host_uid_for_zero,
            host_gid_for_zero: s.host_gid_for_zero,
        }
    }
}

/// Resolved per-role Unix socket plan - input to broker
/// `BindUnixSocket` / `SetSocketAcl`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSocketIntent {
    pub intent_id: String,
    pub vm_name: String,
    pub role_id: String,
    pub socket_path: PathBuf,
    pub mode: u32,
    pub owner_uid: u32,
    pub group_gid: u32,
}

/// Resolved host-install plan.
///
/// Synthesized from the bundle's static installer policy: the
/// systemd unit file path the daemon ships at + the service name
/// + the `daemon-config.json` path the unit reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedInstallerIntent {
    pub intent_id: String,
    pub unit_path: PathBuf,
    pub service_name: String,
    pub daemon_config_path: PathBuf,
    pub bundle_path: PathBuf,
    /// Today the installer plan is a small set of fixed targets the
    /// broker writes. Future versions can extend
    /// this with per-host customization.
    pub artifacts: Vec<InstallerArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallerArtifact {
    pub path: PathBuf,
    pub mode: u32,
    pub purpose: String,
}

/// Resolved migration plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedMigrateIntent {
    pub intent_id: String,
    /// VMs that will be migrated from systemd-owned to daemon-owned.
    /// The bundle's `processes.json` is the source of truth here,
    /// excluding synthetic per-env runner scopes such as
    /// `sys-<env>-usbipd`.
    pub vms: Vec<String>,
    /// Notes the broker echoes back so the operator can see what
    /// the writer plans to do without inspecting the bundle.
    pub notes: Vec<String>,
}

/// Resolved activation intent for per-VM switch / boot / test / rollback
/// broker dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedActivationIntent {
    pub intent_id: String,
    pub vm: String,
    pub target_generation_path: PathBuf,
    pub generation_number: Option<u64>,
}

/// Resolved per-VM store-view plan used by the broker's native activation
/// path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedStoreViewIntent {
    pub intent_id: String,
    pub vm: String,
    pub generation: u64,
    pub hardlink_farm_path: PathBuf,
    pub target_view_path: PathBuf,
    pub closure_paths: Vec<PathBuf>,
    pub db_dump_path: PathBuf,
}

impl ResolvedStoreViewIntent {
    /// Stable per-closure identity for this store-view generation,
    /// derived from the toplevel store-path basename (whose Nix-base32
    /// hash component captures the full closure content). Written into
    /// the hardlink-farm generation marker's `closure_hash` so that a
    /// u32 generation-number collision between two *distinct* closures
    /// of the same VM is detected fail-closed instead of silently
    /// unioning two closures into one store view (which would corrupt
    /// rollback). Falls back to the vm+generation tuple only when the
    /// target view path has no basename (should never happen for a
    /// resolved intent).
    pub fn closure_identity(&self) -> String {
        self.target_view_path
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| format!("toplevel:{name}"))
            .unwrap_or_else(|| format!("store-view:{}:{}", self.vm, self.generation))
    }
}

/// Resolved host-GC intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedGcIntent {
    pub intent_id: String,
    pub retained_store_paths: Vec<PathBuf>,
}

/// Resolved framework-managed SSH key rotation intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedKeysRotateIntent {
    pub intent_id: String,
    pub vm: String,
    pub key_path: PathBuf,
}

/// Resolved known_hosts trust intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedHostKeyTrustIntent {
    pub intent_id: String,
    pub vm: String,
    pub static_ip: String,
    pub known_hosts_path: PathBuf,
    pub host_public_key_path: PathBuf,
}

/// Resolved known_hosts entry removal intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRotateKnownHostIntent {
    pub intent_id: String,
    pub vm: String,
    pub static_ip: String,
    pub known_hosts_path: PathBuf,
}

/// Bundle-resolved TAP / bridge plan for one VM role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTapIntent {
    pub intent_id: String,
    pub vm_name: String,
    pub role_id: String,
    pub bridge_ifname: IfName,
    pub tap_ifname: IfName,
    pub tap_role: TapRoleW3,
    pub net_handoff_mode: ChNetHandoffMode,
    pub owner_uid: u32,
    pub owner_gid: u32,
    pub provenance: NetworkProvenance,
    pub ownership_marker: String,
}

/// Normalize the stable TAP role key shared by host-prep and runner paths.
pub fn canonical_tap_role_id(role_id: &str) -> &str {
    match role_id {
        "ch-runner" => "ch",
        other => other,
    }
}

/// Bundle-resolved macvtap interface for a VMM runner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedMacvtapIntent {
    pub vm_name: String,
    pub role_id: String,
    pub ifname: IfName,
    pub parent_ifname: IfName,
    pub mode: ProcessMacvtapMode,
    pub mac: String,
    pub fd: i32,
}

/// Bundle-resolved per-VM directory create plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPrepareDirIntent {
    pub vm_name: String,
    pub base_dir: PathBuf,
    pub owner_uid: u32,
    pub owner_gid: u32,
    pub mode: u32,
}

/// Trusted legacy swtpm adoption paths derived from the private bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedLegacySwtpmIntent {
    pub intent_id: String,
    pub vm: String,
    pub source: PathBuf,
    pub destination: PathBuf,
    pub journal: PathBuf,
    pub marker: PathBuf,
    pub owner_uid: u32,
    pub owner_gid: u32,
}

/// Bundle-resolved kernel-module allowlist row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedKernelModuleIntent {
    pub module_name: String,
    pub matrix_entry_id: String,
    pub feature: String,
    pub requirement: ModuleRequirementW3,
    pub fail_if_modules_disabled: bool,
    pub load_allowed: bool,
}

/// Bundle-resolved role-to-device claim matrix row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRoleDeviceClaim {
    pub role_id: String,
    pub role: ProcessRole,
    pub allowed_device_classes: Vec<String>,
}

/// Host-runtime.json record for the unified ifname source of truth.
///
/// The Nix `derivedIfName` and the Rust
/// `d2b_host::ifname::derive_from_env_vm` produce ifnames that
/// match the same *format* (length, role tag prefix, alphabet subset)
/// but use different hash algorithms (SHA-256 first-8 vs FNV-1a +
/// Crockford base32). The broker emits the canonical ifname set into
/// `/var/lib/d2b/runtime/host-runtime.json` at install time, and
/// downstream consumers (status reporter, nft chain emitter) read from
/// it instead of recomputing.
///
/// `HostRuntime` is the resolver-side type; the broker's live host-
/// install path writes the
/// [`crate::bundle_resolver::HostRuntimeArtifact`] to disk.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostRuntime {
    pub schema_version: String,
    pub bundle_version: u32,
    pub generated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nft_applied_hash: Option<String>,
    pub ifnames: Vec<HostRuntimeIfName>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostRuntimeIfName {
    pub env: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vm: Option<String>,
    pub user_visible_name: String,
    pub derived_ifname: String,
    pub role_tag: String,
}

/// Artifact that the broker writes during host-install.
/// `path` defaults to `/var/lib/d2b/runtime/host-runtime.json`;
/// the installer plan can override via the artifact list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRuntimeArtifact {
    pub path: PathBuf,
    pub runtime: HostRuntime,
}

impl HostRuntimeArtifact {
    pub fn new(runtime: HostRuntime) -> Self {
        Self {
            path: PathBuf::from("/var/lib/d2b/runtime/host-runtime.json"),
            runtime,
        }
    }

    pub fn render_json(&self) -> Result<String, Error> {
        serde_json::to_string_pretty(&self.runtime)
            .map(|mut s| {
                s.push('\n');
                s
            })
            .map_err(|_| Error::internal_io("host-runtime-serialize"))
    }
}

// ---------------------------------------------------------------
// Bundle-artifact tamper-resistance verification.
// ---------------------------------------------------------------

/// Policy applied by [`BundleResolver::load_with_policy`] when
/// opening bundle artifacts from disk.
///
/// Production code uses [`BundleVerifyPolicy::production`].
/// Tests supply a policy whose `required_uid`/`required_gid` match the
/// current process so that tamper-free test files pass verification.
#[derive(Debug, Clone)]
pub struct BundleVerifyPolicy {
    /// Expected file owner UID.  Production = 0 (root).
    pub required_uid: u32,
    /// Expected file owner GID.  `None` means skip the GID check.
    pub required_gid: Option<u32>,
    /// Expected permission bits (low 9 bits of st_mode).
    pub required_mode: u32,
}

impl BundleVerifyPolicy {
    /// Production policy: owned by `root:d2bd`, mode 0640.
    ///
    /// Looks up the `d2bd` group by parsing `/etc/group`.
    /// If the group does not exist the GID check is skipped.
    pub fn production() -> Self {
        Self {
            required_uid: 0,
            required_gid: lookup_group_gid("d2bd"),
            required_mode: 0o640,
        }
    }

    /// Test policy: accepts the invoking process's uid/gid + the same
    /// 0640 mode. Used by unit tests that materialise bundles in a
    /// per-test temp directory (cargo test runs as the invoking user,
    /// not root, so the production owner/mode check would reject every
    /// such bundle). Outside of `#[cfg(test)]` paths, callers must use
    /// [`Self::production`].
    #[doc(hidden)]
    pub fn for_tests() -> Self {
        // rustix is the workspace's libc replacement; getuid()/getgid()
        // are infallible and async-signal-safe.
        let uid = rustix::process::getuid().as_raw();
        let gid = rustix::process::getgid().as_raw();
        Self {
            required_uid: uid,
            required_gid: Some(gid),
            required_mode: 0o640,
        }
    }
}

/// Look up a UNIX group GID by name via `/etc/group` (no unsafe).
fn lookup_group_gid(name: &str) -> Option<u32> {
    let contents = std::fs::read_to_string("/etc/group").ok()?;
    for line in contents.lines() {
        let mut parts = line.splitn(4, ':');
        let group_name = parts.next()?;
        if group_name != name {
            continue;
        }
        parts.next()?; // password
        let gid_str = parts.next()?;
        return gid_str.parse().ok();
    }
    None
}

/// Open `path` with `O_NOFOLLOW | O_RDONLY`, verify ownership/mode,
/// return the file's raw bytes.
///
/// Returns [`Error::Bundle`] wrapping
/// [`crate::error::BundleError::Tampered`] with a short `reason` slug
/// on any security check failure:
/// - `"symlink"` - `open` returned `ELOOP` (path is a symlink).
/// - `"not-regular-file"` - `fstat` shows it is not a regular file.
/// - `"owner"` - `st_uid` ≠ `policy.required_uid` or
///   `st_gid` ≠ `policy.required_gid` (when Some).
/// - `"mode"` - low 9 bits of `st_mode` ≠ `policy.required_mode`.
fn secure_open_and_read(path: &Path, policy: &BundleVerifyPolicy) -> Result<Vec<u8>, Error> {
    use rustix::fs::{FileType, OFlags, fstat, open};

    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let fd = open(path, flags, rustix::fs::Mode::empty()).map_err(|e| {
        if e == rustix::io::Errno::LOOP {
            Error::bundle_tampered(path.to_path_buf(), "symlink")
        } else {
            Error::internal_io(format!("bundle-open:{}", path.display()))
        }
    })?;

    let stat =
        fstat(&fd).map_err(|_| Error::internal_io(format!("bundle-fstat:{}", path.display())))?;

    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(Error::bundle_tampered(
            path.to_path_buf(),
            "not-regular-file",
        ));
    }

    if stat.st_uid != policy.required_uid {
        return Err(Error::bundle_tampered(path.to_path_buf(), "owner"));
    }

    if let Some(gid) = policy.required_gid
        && stat.st_gid != gid
    {
        return Err(Error::bundle_tampered(path.to_path_buf(), "owner"));
    }

    let mode = (stat.st_mode as u32) & 0o777;
    if mode != policy.required_mode {
        return Err(Error::bundle_tampered(path.to_path_buf(), "mode"));
    }

    let mut file = std::fs::File::from(fd);
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| Error::internal_io(format!("bundle-read:{}", path.display())))?;
    Ok(bytes)
}

/// Compute `"sha256:<64-char hex>"` over `data`.
fn sha256_hex(data: &[u8]) -> String {
    let digest: [u8; 32] = sha2::Sha256::digest(data).into();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{hex}")
}

/// Verify the SHA-256 of `bytes` against `artifact_hashes[key]`.
///
/// - When `artifact_hashes` is `None` verification is skipped (backwards
///   compatibility with bundles that pre-date this field).
/// - When `key` is absent from the map the artifact was loaded without being
///   declared, which is a hard failure:
///   `BundleTampered { reason: "unhashed" }`.
/// - On hash mismatch: `BundleTampered { reason: "hash" }`.
fn verify_artifact_hash(
    path: &Path,
    bytes: &[u8],
    artifact_hashes: Option<&std::collections::BTreeMap<String, String>>,
    key: &str,
) -> Result<(), Error> {
    let hashes = match artifact_hashes {
        None => return Ok(()),
        Some(h) => h,
    };
    let expected = match hashes.get(key) {
        None => return Err(Error::bundle_tampered(path.to_path_buf(), "unhashed")),
        Some(h) => h,
    };
    let actual = sha256_hex(bytes);
    if &actual != expected {
        return Err(Error::bundle_tampered(path.to_path_buf(), "hash"));
    }
    Ok(())
}

/// Verify the `bundleHash` self-field in an already-parsed `Bundle`.
///
/// The hash is computed over the canonical JSON of the bundle with
/// `bundleHash` removed and `artifactHashes` set to null - matching what
/// `nixos-modules/bundle.nix` emits via `builtins.toJSON dataWithoutHash`
/// where `dataWithoutHash` has `artifactHashes = null`.
///
/// For `schemaVersion "v2"` bundles a missing `bundleHash` is a hard
/// failure (`BundleTampered { reason: "missing-bundle-hash" }`).
/// For older schema versions a missing field logs a warning and returns
/// `Ok` for backwards compatibility.
fn verify_bundle_hash(path: &Path, raw_bytes: &[u8]) -> Result<(), Error> {
    // Parse as a generic JSON value so we can extract and drop bundleHash
    // without going through the typed Bundle struct (which would normalise
    // the representation).
    let mut value: serde_json::Value = match serde_json::from_slice(raw_bytes) {
        Ok(v) => v,
        Err(_) => {
            // Unparseable bytes mean the file has been corrupted/truncated.
            return Err(Error::bundle_tampered(path.to_path_buf(), "hash"));
        }
    };

    // Check schemaVersion before removing bundleHash so we know whether a
    // missing hash is a hard failure or a compat warning. P0fu3 H1 (security):
    // require bundleHash for any schemaVersion >= 2 (was exact "v2" before;
    // a future "v3" would have silently downgraded to warning-only).
    let schema_str = value
        .as_object()
        .and_then(|o| o.get("schemaVersion"))
        .and_then(|v| v.as_str());
    let require_hash = match schema_str {
        // Numeric suffix v<N>: require bundleHash for N >= 2. Unknown shapes
        // are treated as future schemas and MUST carry bundleHash (fail closed).
        Some(s) => {
            if let Some(n) = s.strip_prefix('v').and_then(|t| t.parse::<u32>().ok()) {
                n >= 2
            } else {
                true
            }
        }
        // No schemaVersion at all is a v1 / legacy bundle - warning only.
        None => false,
    };

    let expected = match value.as_object_mut().and_then(|o| o.remove("bundleHash")) {
        None => {
            if require_hash {
                // schemaVersion >= 2 (and unknown future schemas) MUST carry
                // bundleHash.
                return Err(Error::bundle_tampered(
                    path.to_path_buf(),
                    "missing-bundle-hash",
                ));
            }
            eprintln!(
                "d2b: warning: bundle artifact {} has no bundleHash field; \
                 skipping self-hash check (re-run nixos-rebuild to add it)",
                path.display()
            );
            return Ok(());
        }
        Some(serde_json::Value::String(s)) => s,
        Some(other) => {
            return Err(Error::bundle_tampered(
                path.to_path_buf(),
                format!("bundleHash is not a string: {other}"),
            ));
        }
    };

    // Nullify artifactHashes so the hash input matches what the Nix emitter
    // used: bundleHash = sha256(bundle with artifactHashes:null, no bundleHash).
    // Old bundles that never had this field are left unchanged.
    if let Some(obj) = value.as_object_mut()
        && obj.contains_key("artifactHashes")
    {
        obj.insert("artifactHashes".to_owned(), serde_json::Value::Null);
    }

    // serde_json without `preserve_order` feature serialises objects with
    // BTreeMap (sorted keys) - the same lexicographic ordering that
    // builtins.toJSON uses on the Nix side.
    let canonical =
        serde_json::to_vec(&value).map_err(|_| Error::internal_io("bundle-hash-canonical"))?;
    let actual = sha256_hex(&canonical);

    if actual != expected {
        return Err(Error::bundle_tampered(path.to_path_buf(), "hash"));
    }
    Ok(())
}

fn normalize_zone_native_ref(bundle_root: &Path, value: &str) -> Result<String, Error> {
    let path = Path::new(value);
    let relative = if path.is_absolute() {
        path.strip_prefix(bundle_root).ok()
    } else {
        Some(path)
    };
    relative
        .filter(|relative| {
            !relative.as_os_str().is_empty()
                && relative
                    .components()
                    .all(|component| matches!(component, std::path::Component::Normal(_)))
        })
        .and_then(Path::to_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            Error::manifest_parse_error("bundle.json", "artifact path escapes bundle root")
        })
}

fn normalize_zone_native_artifact_hashes(
    bundle_root: &Path,
    artifact_hashes: BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, Error> {
    artifact_hashes
        .into_iter()
        .map(|(path, hash)| Ok((normalize_zone_native_ref(bundle_root, &path)?, hash)))
        .collect()
}

fn empty_zone_native_host() -> HostJson {
    HostJson {
        schema_version: "v3".to_owned(),
        site: SitePolicy {
            allow_unsafe_east_west: false,
        },
        environments: Vec::new(),
        nftables: NftablesModel {
            family: "inet".to_owned(),
            table: "d2b".to_owned(),
            chains: Vec::new(),
            table_hash_after_apply: None,
            ownership_id: String::new(),
        },
        network_manager: NetworkManagerUnmanaged {
            file_path: String::new(),
            match_criteria: Vec::new(),
            reload_behavior: String::new(),
            ownership: OwnershipRule {
                owner: String::new(),
                group: String::new(),
                mode: String::new(),
                drift_policy: String::new(),
            },
        },
        hosts_file: HostsFileOwnership {
            start_marker: "# d2b-managed begin".to_owned(),
            end_marker: "# d2b-managed end".to_owned(),
            rule: String::new(),
        },
        kernel_modules: Vec::new(),
        fd_ownership: Vec::new(),
        runtime_providers: Vec::new(),
        vm_runtimes: Vec::new(),
        qemu_media: None,
        security_key_selectors: Vec::new(),
        cloud_hypervisor_capabilities: Vec::new(),
        if_name_mappings: Vec::new(),
        ch: None,
        firewall_coexistence_policy: None,
    }
}

impl BundleResolver {
    /// Load the bundle.json at `bundle_path`, verify ownership, mode,
    /// and SHA-256 self-hash, then parse sibling artifacts.
    ///
    /// Uses [`BundleVerifyPolicy::production`]: owned by `root:d2bd`,
    /// mode 0640, opened with `O_NOFOLLOW`.
    pub fn load(bundle_path: &Path) -> Result<Self, Error> {
        Self::load_with_policy(bundle_path, &BundleVerifyPolicy::production())
    }

    /// Like [`Self::load`] but accepts an explicit [`BundleVerifyPolicy`].
    ///
    /// Tests supply a policy whose `required_uid`/`required_gid`/
    /// `required_mode` match the temp-dir files they create.
    pub fn load_with_policy(
        bundle_path: &Path,
        policy: &BundleVerifyPolicy,
    ) -> Result<Self, Error> {
        let bundle_bytes = secure_open_and_read(bundle_path, policy)?;
        verify_bundle_hash(bundle_path, &bundle_bytes)?;
        if serde_json::from_slice::<serde_json::Value>(&bundle_bytes)
            .ok()
            .and_then(|value| {
                value
                    .get("schemaVersion")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
            .as_deref()
            == Some("v3")
        {
            return Self::load_zone_native_bundle(bundle_path, &bundle_bytes, policy);
        }
        let bundle: Bundle = serde_json::from_slice(&bundle_bytes).map_err(|e| {
            Error::manifest_parse_error("bundle.json", manifest_parse_reason(&e.to_string()))
        })?;
        let bundle_hash = stable_digest_bytes(&bundle_bytes);
        let bundle_root = bundle_path.parent().unwrap_or_else(|| Path::new("/"));
        let host_path = resolve_bundle_ref(bundle_root, &bundle.host_path);
        let processes_path = resolve_bundle_ref(bundle_root, &bundle.processes_path);
        let manifest_path = resolve_bundle_ref(bundle_root, &bundle.public_manifest_path);
        Self::load_with_paths(
            bundle,
            bundle_hash,
            &host_path,
            &processes_path,
            &manifest_path,
            bundle_root,
            policy,
        )
    }

    fn load_zone_native_bundle(
        bundle_path: &Path,
        bundle_bytes: &[u8],
        policy: &BundleVerifyPolicy,
    ) -> Result<Self, Error> {
        let index: ZoneNativeBundleIndex =
            serde_json::from_slice(bundle_bytes).map_err(|error| {
                Error::manifest_parse_error(
                    "bundle.json",
                    manifest_parse_reason(&error.to_string()),
                )
            })?;
        if index.bundle_version != 1 {
            return Err(Error::manifest_version_mismatch(
                "bundle.json",
                "manifest-version-mismatch",
            ));
        }
        let bundle_root = bundle_path.parent().unwrap_or_else(|| Path::new("/"));
        let artifact_hashes =
            normalize_zone_native_artifact_hashes(bundle_root, index.artifact_hashes)?;
        for zone in &index.zones {
            let expected = format!("zones/{}/resource-bundle.json", zone.zone);
            if zone.path != expected || !artifact_hashes.contains_key(&zone.path) {
                return Err(Error::manifest_parse_error(
                    "bundle.json",
                    "Zone resource bundle reference is invalid",
                ));
            }
        }
        let bundle = Bundle {
            bundle_version: index.bundle_version,
            schema_version: index.schema_version,
            public_manifest_path: bundle_root.join("vms.json").to_string_lossy().into_owned(),
            host_path: bundle_root.join("host.json").to_string_lossy().into_owned(),
            processes_path: bundle_root
                .join("processes.json")
                .to_string_lossy()
                .into_owned(),
            privileges_path: normalize_zone_native_ref(bundle_root, &index.privileges_path)?,
            storage_path: None,
            sync_path: None,
            allocator_path: None,
            realm_controllers_path: None,
            realm_identity_path: None,
            realm_workloads_launcher_v2_path: index
                .realm_workloads_launcher_v2_path
                .as_deref()
                .map(|path| normalize_zone_native_ref(bundle_root, path))
                .transpose()?,
            unsafe_local_workloads_path: None,
            closures: Vec::new(),
            minijail_profiles: Vec::new(),
            managed_keys: Default::default(),
            generation: index.generation,
            bundle_hash: Some(index.bundle_hash),
            artifact_hashes: Some(artifact_hashes),
        };
        let bundle_hash = stable_digest_bytes(bundle_bytes);
        let (zone_resource_bundles, provider_controller_templates) =
            load_zone_resource_bundles(&bundle, bundle_root, policy)?;
        let (
            guest_setup_descriptors,
            guest_setup_descriptor_catalog_keys,
            guest_vmm_intents,
            guest_vmm_zone_uids,
            guest_store_view_intents,
        ) = load_guest_setup_descriptors(&zone_resource_bundles, bundle_root, policy)?;
        let zone_storage_rows = load_zone_storage_rows(&bundle, bundle_root, policy)?;
        let zone_topology =
            load_zone_native_topology(&bundle, &zone_resource_bundles, bundle_root, policy)?;
        let realm_workloads_launcher_v2 =
            load_optional_realm_workloads_launcher_v2_artifact(&bundle, bundle_root, policy)?;
        let host = empty_zone_native_host();
        let processes = ProcessesJson {
            schema_version: "v3".to_owned(),
            vms: Vec::new(),
        };
        let manifest = ManifestV04::from_slice(
            br#"{"_manifest":{"manifestVersion":7},"_observability":{"enabled":false,"obsVsockCid":0,"obsVsockHostSocket":"","signozOtlpGrpcPort":4317,"signozOtlpHttpPort":4318,"signozUrl":"","vmName":""}}"#,
        )?;
        let mut resolver = Self::from_parsed_artifacts(
            bundle,
            bundle_hash,
            ParsedBundleArtifacts {
                allocator: None,
                host,
                processes,
                zone_resource_bundles,
                guest_setup_descriptors,
                guest_setup_descriptor_catalog_keys,
                guest_vmm_intents,
                guest_vmm_zone_uids,
                guest_store_view_intents,
                provider_controller_templates,
                zone_storage_rows,
                storage: None,
                sync: None,
                realm_controllers: None,
                realm_identity: None,
                realm_workloads_launcher_v2,
                unsafe_local_workloads: None,
                manifest,
                closures: Vec::new(),
            },
            false,
        );
        resolver.zone_topology = zone_topology;
        Ok(resolver)
    }

    /// Construct a resolver from already-parsed artifacts; used by
    /// unit tests + by the broker when it has already validated
    /// the artifacts.
    pub fn from_artifacts(
        bundle: Bundle,
        host: HostJson,
        processes: ProcessesJson,
        manifest: ManifestV04,
    ) -> Self {
        let bundle_hash = stable_digest_bytes(
            serde_json::to_vec(&bundle)
                .expect("bundle serialization for audit hashing must succeed")
                .as_slice(),
        );
        Self::from_artifacts_with_closures(
            bundle,
            bundle_hash,
            host,
            processes,
            manifest,
            Vec::new(),
        )
    }

    /// Variant for test fixtures that also accepts parsed
    /// `closures/<vm>.json` artifacts.
    pub fn from_artifacts_with_closures(
        bundle: Bundle,
        bundle_hash: String,
        host: HostJson,
        processes: ProcessesJson,
        manifest: ManifestV04,
        closures: Vec<ClosureMetadata>,
    ) -> Self {
        Self::from_parsed_artifacts(
            bundle,
            bundle_hash,
            ParsedBundleArtifacts {
                allocator: None,
                host,
                processes,
                zone_resource_bundles: BTreeMap::new(),
                guest_setup_descriptors: BTreeMap::new(),
                guest_setup_descriptor_catalog_keys: BTreeMap::new(),
                guest_vmm_intents: BTreeMap::new(),
                guest_vmm_zone_uids: BTreeMap::new(),
                guest_store_view_intents: BTreeMap::new(),
                provider_controller_templates: Vec::new(),
                zone_storage_rows: BTreeMap::new(),
                storage: None,
                sync: None,
                realm_controllers: None,
                realm_identity: None,
                realm_workloads_launcher_v2: None,
                unsafe_local_workloads: None,
                manifest,
                closures,
            },
            true,
        )
    }

    /// Variant for tests and embedded callers that already hold verified
    /// per-Zone resource-bundle bytes.
    pub fn from_artifacts_with_zone_resource_bundles(
        bundle: Bundle,
        host: HostJson,
        processes: ProcessesJson,
        manifest: ManifestV04,
        zone_resource_bundles: BTreeMap<String, Vec<u8>>,
    ) -> Self {
        let bundle_hash = stable_digest_bytes(
            serde_json::to_vec(&bundle)
                .expect("bundle serialization for audit hashing must succeed")
                .as_slice(),
        );
        let provider_controller_templates = zone_resource_bundles
            .values()
            .flat_map(|bytes| {
                ResourceBundle::from_json(bytes)
                    .expect("zone resource bundle bytes must be verified")
                    .process_templates
            })
            .collect();
        Self::from_parsed_artifacts(
            bundle,
            bundle_hash,
            ParsedBundleArtifacts {
                allocator: None,
                host,
                processes,
                zone_resource_bundles,
                guest_setup_descriptors: BTreeMap::new(),
                guest_setup_descriptor_catalog_keys: BTreeMap::new(),
                guest_vmm_intents: BTreeMap::new(),
                guest_vmm_zone_uids: BTreeMap::new(),
                guest_store_view_intents: BTreeMap::new(),
                provider_controller_templates,
                zone_storage_rows: BTreeMap::new(),
                storage: None,
                sync: None,
                realm_controllers: None,
                realm_identity: None,
                realm_workloads_launcher_v2: None,
                unsafe_local_workloads: None,
                manifest,
                closures: Vec::new(),
            },
            true,
        )
    }

    fn from_parsed_artifacts(
        bundle: Bundle,
        bundle_hash: String,
        artifacts: ParsedBundleArtifacts,
        include_fixture_network_intents: bool,
    ) -> Self {
        let ParsedBundleArtifacts {
            allocator,
            host,
            processes,
            zone_resource_bundles,
            guest_setup_descriptors,
            guest_setup_descriptor_catalog_keys,
            guest_vmm_intents,
            guest_vmm_zone_uids,
            guest_store_view_intents,
            provider_controller_templates,
            zone_storage_rows,
            storage,
            sync,
            realm_controllers,
            realm_identity,
            realm_workloads_launcher_v2,
            unsafe_local_workloads,
            manifest,
            closures,
        } = artifacts;
        let zone_topology = allocator
            .as_ref()
            .and_then(|allocator| allocator.zone_topology.clone());
        let installed_generation_identity = build_installed_generation_identity(&bundle);
        let nft_intents = if include_fixture_network_intents {
            build_nft_intents(&host)
        } else {
            build_host_nft_intents(&host)
        };
        let nft_projection_intents = if include_fixture_network_intents {
            build_nft_projection_intents(&host)
        } else {
            BTreeMap::new()
        };
        let ownership_marker_intents = if include_fixture_network_intents {
            build_ownership_marker_intents(&host)
        } else {
            BTreeMap::new()
        };
        let bridge_intents = if include_fixture_network_intents {
            build_bridge_intents(&host)
        } else {
            BTreeMap::new()
        };
        let route_intents = if include_fixture_network_intents {
            build_route_intents(&host)
        } else {
            BTreeMap::new()
        };
        let sysctl_intents = if include_fixture_network_intents {
            build_sysctl_intents(&host)
        } else {
            BTreeMap::new()
        };
        let hosts_intents = if include_fixture_network_intents {
            build_hosts_intents(&host)
        } else {
            BTreeMap::new()
        };
        let (
            resource_nft_projection_intents,
            resource_ownership_marker_intents,
            resource_bridge_intents,
            resource_route_intents,
            resource_sysctl_intents,
            resource_hosts_intents,
        ) = build_resource_network_intents(&zone_resource_bundles, include_fixture_network_intents);
        let mut nft_projection_intents = nft_projection_intents;
        nft_projection_intents.extend(resource_nft_projection_intents);
        let mut ownership_marker_intents = ownership_marker_intents;
        ownership_marker_intents.extend(resource_ownership_marker_intents);
        let mut bridge_intents = bridge_intents;
        bridge_intents.extend(resource_bridge_intents);
        let mut route_intents = route_intents;
        route_intents.extend(resource_route_intents);
        let mut sysctl_intents = sysctl_intents;
        sysctl_intents.extend(resource_sysctl_intents);
        let mut hosts_intents = hosts_intents;
        hosts_intents.extend(resource_hosts_intents);
        let nm_unmanaged_intents = build_nm_unmanaged_intents(&host);
        let usbip_firewall_intents = build_usbip_firewall_intents(&host);
        let usbip_bind_intents = build_usbip_bind_intents(&host);
        let mut runner_intents = build_runner_intents(&processes);
        runner_intents.extend(build_provider_controller_intents(
            &provider_controller_templates,
        ));
        runner_intents.extend(
            guest_vmm_intents
                .values()
                .cloned()
                .map(|intent| (intent.intent_id.clone(), intent)),
        );
        let socket_intents = build_socket_intents(&processes);
        let installer_intents = build_installer_intents(&bundle);
        let migrate_intents = build_migrate_intents(&processes);
        let activation_intents = build_activation_intents(&closures, &manifest);
        let mut store_view_intents = build_store_view_intents(&closures, &manifest);
        store_view_intents.extend(guest_store_view_intents);
        let gc_intents = build_gc_intents(&closures);
        let closure_toplevels = closures
            .iter()
            .map(|closure| (closure.vm.clone(), closure.toplevel.clone()))
            .collect();
        let keys_rotate_intents = build_keys_rotate_intents(&bundle, &manifest);
        let host_key_trust_intents = build_host_key_trust_intents(&bundle, &manifest);
        let rotate_known_host_intents = build_rotate_known_host_intents(&bundle, &manifest);
        Self {
            audit_bundle_version: format!("v{}", bundle.bundle_version),
            audit_bundle_hash: bundle_hash,
            installed_generation_identity,
            bundle,
            allocator,
            zone_topology,
            host,
            processes,
            zone_resource_bundles,
            guest_setup_descriptors,
            guest_setup_descriptor_catalog_keys,
            guest_vmm_intents,
            guest_vmm_zone_uids,
            zone_storage_rows,
            storage,
            sync,
            realm_controllers,
            realm_identity,
            realm_workloads_launcher_v2,
            unsafe_local_workloads,
            manifest,
            nft_intents,
            nft_projection_intents,
            ownership_marker_intents,
            bridge_intents,
            route_intents,
            sysctl_intents,
            hosts_intents,
            nm_unmanaged_intents,
            usbip_firewall_intents,
            usbip_bind_intents,
            runner_intents,
            socket_intents,
            installer_intents,
            migrate_intents,
            activation_intents,
            store_view_intents,
            gc_intents,
            closure_toplevels,
            keys_rotate_intents,
            host_key_trust_intents,
            rotate_known_host_intents,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_artifacts_with_optional_contracts(
        bundle: Bundle,
        host: HostJson,
        processes: ProcessesJson,
        storage: Option<StorageJson>,
        sync: Option<SyncJson>,
        realm_controllers: Option<RealmControllersJson>,
        realm_identity: Option<RealmIdentityConfigJson>,
        manifest: ManifestV04,
    ) -> Self {
        let bundle_hash = stable_digest_bytes(
            serde_json::to_vec(&bundle)
                .expect("bundle serialization for audit hashing must succeed")
                .as_slice(),
        );
        Self::from_parsed_artifacts(
            bundle,
            bundle_hash,
            ParsedBundleArtifacts {
                allocator: None,
                host,
                processes,
                zone_resource_bundles: BTreeMap::new(),
                guest_setup_descriptors: BTreeMap::new(),
                guest_setup_descriptor_catalog_keys: BTreeMap::new(),
                guest_vmm_intents: BTreeMap::new(),
                guest_vmm_zone_uids: BTreeMap::new(),
                guest_store_view_intents: BTreeMap::new(),
                provider_controller_templates: Vec::new(),
                zone_storage_rows: BTreeMap::new(),
                storage,
                sync,
                realm_controllers,
                realm_identity,
                realm_workloads_launcher_v2: None,
                unsafe_local_workloads: None,
                manifest,
                closures: Vec::new(),
            },
            true,
        )
    }

    fn load_with_paths(
        bundle: Bundle,
        bundle_hash: String,
        host_path: &Path,
        processes_path: &Path,
        manifest_path: &Path,
        bundle_root: &Path,
        policy: &BundleVerifyPolicy,
    ) -> Result<Self, Error> {
        let host_bytes = secure_open_and_read(host_path, policy)?;
        verify_artifact_hash(
            host_path,
            &host_bytes,
            bundle.artifact_hashes.as_ref(),
            &bundle.host_path,
        )?;
        let host: HostJson = serde_json::from_slice(&host_bytes).map_err(|e| {
            Error::manifest_parse_error("host.json", manifest_parse_reason(&e.to_string()))
        })?;
        let processes_bytes = secure_open_and_read(processes_path, policy)?;
        verify_artifact_hash(
            processes_path,
            &processes_bytes,
            bundle.artifact_hashes.as_ref(),
            &bundle.processes_path,
        )?;
        let processes: ProcessesJson = serde_json::from_slice(&processes_bytes).map_err(|e| {
            Error::manifest_parse_error("processes.json", manifest_parse_reason(&e.to_string()))
        })?;
        let (zone_resource_bundles, provider_controller_templates) =
            load_zone_resource_bundles(&bundle, bundle_root, policy)?;
        let (
            guest_setup_descriptors,
            guest_setup_descriptor_catalog_keys,
            guest_vmm_intents,
            guest_vmm_zone_uids,
            guest_store_view_intents,
        ) = load_guest_setup_descriptors(&zone_resource_bundles, bundle_root, policy)?;
        let zone_storage_rows = load_zone_storage_rows(&bundle, bundle_root, policy)?;
        let allocator = load_optional_allocator_artifact(&bundle, bundle_root, policy)?;
        let storage = load_optional_storage_artifact(&bundle, bundle_root, policy)?;
        let sync = load_optional_sync_artifact(&bundle, bundle_root, policy)?;
        let realm_controllers =
            load_optional_realm_controllers_artifact(&bundle, bundle_root, policy)?;
        let realm_identity = load_optional_realm_identity_artifact(&bundle, bundle_root, policy)?;
        let realm_workloads_launcher_v2 =
            load_optional_realm_workloads_launcher_v2_artifact(&bundle, bundle_root, policy)?;
        let unsafe_local_workloads =
            load_optional_unsafe_local_workloads_artifact(&bundle, bundle_root, policy)?;
        // The public manifest (vms.json) lives under /run/current-system/…
        // which is root-owned 0444; skip the private-artifact policy for it.
        let manifest = ManifestV04::from_path(manifest_path)?;
        let closures = load_closure_metadata_verified(&bundle, bundle_root, policy)?;
        Ok(Self::from_parsed_artifacts(
            bundle,
            bundle_hash,
            ParsedBundleArtifacts {
                allocator,
                host,
                processes,
                zone_resource_bundles,
                guest_setup_descriptors,
                guest_setup_descriptor_catalog_keys,
                guest_vmm_intents,
                guest_vmm_zone_uids,
                guest_store_view_intents,
                provider_controller_templates,
                zone_storage_rows,
                storage,
                sync,
                realm_controllers,
                realm_identity,
                realm_workloads_launcher_v2,
                unsafe_local_workloads,
                manifest,
                closures,
            },
            false,
        ))
    }

    pub fn audit_bundle_version(&self) -> &str {
        &self.audit_bundle_version
    }

    /// Return the sealed Zone topology, when the allocator artifact carries it.
    pub fn zone_topology(&self) -> Option<&AllocatorZoneTopology> {
        self.zone_topology.as_ref()
    }

    /// Return the verified Nix-authored resource bundle bytes for one Zone.
    ///
    /// The bytes were loaded through the same ownership, no-follow, and
    /// artifact-hash checks as every other private bundle artifact. Parsing
    /// remains in `d2bd`, which owns the Resource API activation boundary.
    pub fn zone_resource_bundle_bytes(&self, zone: &str) -> Option<&[u8]> {
        self.zone_resource_bundles.get(zone).map(Vec::as_slice)
    }

    /// Return the canonical private Guest setup descriptor for one Zone-local
    /// Guest, when the installed artifact catalog supplies one.
    ///
    /// The returned bytes are semantic descriptor data only. Store paths,
    /// credentials, executable arguments, and broker operations are not part
    /// of this projection.
    pub fn guest_setup_descriptor_bytes(&self, zone: &str, guest: &str) -> Option<&[u8]> {
        self.guest_setup_descriptors
            .get(&(zone.to_owned(), guest.to_owned()))
            .map(Vec::as_slice)
    }

    /// Return the provider-contract fingerprint published beside one private
    /// Guest setup descriptor in the verified artifact catalog.
    pub fn guest_setup_descriptor_catalog_key(&self, zone: &str, guest: &str) -> Option<&str> {
        self.guest_setup_descriptor_catalog_keys
            .get(&(zone.to_owned(), guest.to_owned()))
            .map(String::as_str)
    }

    /// Return the Zone identities that have a verified resource bundle.
    pub fn zone_resource_bundle_zones(
        &self,
    ) -> Result<BTreeSet<d2b_contracts_resource::v3::ZoneId>, &'static str> {
        self.zone_resource_bundles
            .keys()
            .map(|zone| {
                d2b_contracts_resource::v3::ZoneId::parse(zone.clone())
                    .map_err(|_| "bundle Zone resource bundle index invalid")
            })
            .collect()
    }

    /// Check that a supplied Zone UID is present in a verified private bundle.
    pub fn has_zone_uid(&self, zone_uid: &d2b_contracts_resource::v3::ResourceUid) -> bool {
        self.zone_resource_bundles.values().any(|bytes| {
            ResourceBundle::from_json(bytes)
                .ok()
                .and_then(|bundle| bundle.zone_uid)
                .as_ref()
                == Some(zone_uid)
        })
    }

    /// Return the immutable UID bound into one verified Zone resource bundle.
    pub fn zone_uid(&self, zone: &ZoneId) -> Option<ResourceUid> {
        self.zone_resource_bundles
            .get(zone.as_str())
            .and_then(|bytes| ResourceBundle::from_json(bytes).ok())
            .and_then(|bundle| bundle.zone_uid)
    }

    /// Return the verified broker-owned storage row for one Zone.
    pub fn zone_storage_row(&self, zone: &str) -> Option<&ZoneStoreStorageRow> {
        self.zone_storage_rows.get(zone)
    }

    pub fn audit_bundle_hash(&self) -> &str {
        &self.audit_bundle_hash
    }

    pub fn find_unsafe_local_workload(&self, target: &str) -> Option<&UnsafeLocalWorkload> {
        self.unsafe_local_workloads
            .as_ref()?
            .workloads
            .iter()
            .find(|workload| workload.identity.canonical_target.to_canonical() == target)
    }

    pub fn find_nft_intent(&self, id: &str) -> Option<&ResolvedNftIntent> {
        self.nft_intents.get(id)
    }

    pub fn find_nft_projection_intent(
        &self,
        id: &str,
    ) -> Option<&ResolvedNftablesProjectionIntent> {
        self.nft_projection_intents.get(id)
    }

    pub fn find_ownership_marker_intent(&self, id: &str) -> Option<&ResolvedOwnershipMarkerIntent> {
        self.ownership_marker_intents.get(id)
    }

    pub fn find_bridge_intent(&self, id: &str) -> Option<&ResolvedBridgeIntent> {
        self.bridge_intents.get(id)
    }

    pub fn installed_generation_identity(&self) -> Option<&ResolvedInstalledGenerationIdentity> {
        self.installed_generation_identity.as_ref()
    }

    pub fn find_route_intent(&self, id: &str) -> Option<&ResolvedRouteIntent> {
        self.route_intents.get(id)
    }

    pub fn find_sysctl_intent(&self, id: &str) -> Option<&ResolvedSysctlIntent> {
        self.sysctl_intents.get(id)
    }

    pub fn find_hosts_intent(&self, id: &str) -> Option<&ResolvedHostsIntent> {
        self.hosts_intents.get(id)
    }

    /// Resolve a Network bridge row from an admitted UID-bound reference.
    pub fn resolve_network_bridge_intent(
        &self,
        id: &str,
        provenance: &NetworkProvenance,
    ) -> Option<ResolvedBridgeIntent> {
        let parts = parse_network_intent_ref(id)?;
        if parts.kind != NetworkIntentKind::Bridge
            || parts.zone_uid != *provenance.zone_uid()
            || parts.network_uid != *provenance.network_uid()
        {
            return None;
        }
        let spec = self.find_network_spec(&parts)?;
        let role = match parts.variant.as_deref() {
            Some("uplink") => NetworkIfRole::UplinkBridge,
            Some("lan") => NetworkIfRole::LanBridge,
            _ => return None,
        };
        let bridge_ifname =
            derive_network_ifname(provenance.zone_uid(), provenance.network_uid(), role, None)
                .ok()?;
        let variant = parts.variant.as_deref()?;
        let ownership_marker = format!(
            "d2b managed: {}",
            d2b_contracts_resource::v3::derive_network_ownership_marker(
                provenance,
                &format!("bridge:{variant}"),
            )
        );
        Some(ResolvedBridgeIntent {
            intent_id: id.to_owned(),
            scope_label: network_scope(provenance),
            bridge_ifname,
            mtu: spec.mtu().unwrap_or(1500) as u16,
            stp_disabled: true,
            multicast_snooping_disabled: true,
            ipv6_suppressed: true,
            provenance: Some(provenance.clone()),
            ownership_marker: Some(ownership_marker),
        })
    }

    /// Resolve a Network ownership marker row from an admitted reference.
    pub fn resolve_network_marker_intent(
        &self,
        id: &str,
        provenance: &NetworkProvenance,
    ) -> Option<ResolvedOwnershipMarkerIntent> {
        let parts = parse_network_intent_ref(id)?;
        if parts.kind != NetworkIntentKind::Marker
            || parts.zone_uid != *provenance.zone_uid()
            || parts.network_uid != *provenance.network_uid()
        {
            return None;
        }
        self.find_network_spec(&parts)?;
        let marker =
            d2b_contracts_resource::v3::derive_network_ownership_marker(provenance, "firewall");
        Some(ResolvedOwnershipMarkerIntent {
            intent_id: id.to_owned(),
            marker,
            provenance: Some(provenance.clone()),
        })
    }

    /// Resolve a Network firewall projection from an admitted reference.
    pub fn resolve_network_projection_intent(
        &self,
        id: &str,
        provenance: &NetworkProvenance,
    ) -> Option<ResolvedNftablesProjectionIntent> {
        let parts = parse_network_intent_ref(id)?;
        if parts.kind != NetworkIntentKind::Firewall
            || parts.zone_uid != *provenance.zone_uid()
            || parts.network_uid != *provenance.network_uid()
        {
            return None;
        }
        let spec = self.find_network_spec(&parts)?;
        let uplink = derive_network_ifname(
            provenance.zone_uid(),
            provenance.network_uid(),
            NetworkIfRole::UplinkBridge,
            None,
        )
        .ok()?;
        let marker_id = format!(
            "network-marker:{}:{}:{}",
            provenance.zone_uid().as_str(),
            provenance.network_uid().as_str(),
            parts.network_name
        );
        let marker =
            d2b_contracts_resource::v3::derive_network_ownership_marker(provenance, "firewall");
        let chain = network_firewall_chain_name(provenance.network_uid());
        let script_body = format!(
            "table inet d2b {{\n  chain \"{chain}\" {{ comment \"d2b managed: {marker}\";\n    ct state established,related accept comment \"d2b managed: {marker}\";\n    iifname \"{}\" ct state new accept comment \"d2b managed: {marker}\";\n  }}\n}}\n",
            uplink.as_str()
        );
        let _ = spec;
        Some(ResolvedNftablesProjectionIntent {
            intent_id: id.to_owned(),
            scope_label: network_scope(provenance),
            desired_hash: stable_digest(&script_body),
            script_body,
            ownership_marker_intent_ref: marker_id,
            provenance: Some(provenance.clone()),
        })
    }

    /// Resolve a Network route row from an admitted UID-bound reference.
    pub fn resolve_network_route_intent(
        &self,
        id: &str,
        provenance: &NetworkProvenance,
    ) -> Option<ResolvedRouteIntent> {
        let parts = parse_network_intent_ref(id)?;
        if parts.kind != NetworkIntentKind::Route
            || parts.zone_uid != *provenance.zone_uid()
            || parts.network_uid != *provenance.network_uid()
        {
            return None;
        }
        let spec = self.find_network_spec(&parts)?;
        let index = parts.index?;
        let destinations = if spec.routing().host_blocklist().is_empty() {
            vec![spec.lan_cidr().as_str().to_owned()]
        } else {
            spec.routing()
                .host_blocklist()
                .iter()
                .map(|cidr| cidr.as_str().to_owned())
                .collect::<Vec<_>>()
        };
        let destination = destinations.get(index)?.clone();
        let bridge = derive_network_ifname(
            provenance.zone_uid(),
            provenance.network_uid(),
            NetworkIfRole::UplinkBridge,
            None,
        )
        .ok()?;
        let via = network_cidr_host_address(spec.uplink_cidr().as_str(), 2);
        let route_spec = format!(
            "{destination}{} dev {} table main",
            via.as_deref()
                .map(|gateway| format!(" via {gateway}"))
                .unwrap_or_default(),
            bridge.as_str()
        );
        let route_name =
            derive_network_route_name(provenance.zone_uid(), provenance.network_uid(), index);
        let marker = format!(
            "d2b managed: {}",
            d2b_contracts_resource::v3::derive_network_ownership_marker(
                provenance,
                &format!("route:{route_name}"),
            )
        );
        Some(ResolvedRouteIntent {
            intent_id: id.to_owned(),
            route_spec,
            destination,
            via,
            device: Some(bridge.as_str().to_owned()),
            table: Some("main".to_owned()),
            owned: true,
            route_name: Some(route_name),
            provenance: Some(provenance.clone()),
            ownership_marker: Some(marker),
        })
    }

    /// Resolve a Network sysctl row from an admitted UID-bound reference.
    pub fn resolve_network_sysctl_intent(
        &self,
        id: &str,
        provenance: &NetworkProvenance,
    ) -> Option<ResolvedSysctlIntent> {
        let parts = parse_network_intent_ref(id)?;
        if parts.kind != NetworkIntentKind::Sysctl
            || parts.zone_uid != *provenance.zone_uid()
            || parts.network_uid != *provenance.network_uid()
        {
            return None;
        }
        let spec = self.find_network_spec(&parts)?;
        let role = match parts.variant.as_deref() {
            Some("lan") => NetworkIfRole::LanBridge,
            Some("uplink") => NetworkIfRole::UplinkBridge,
            _ => return None,
        };
        let ifname =
            derive_network_ifname(provenance.zone_uid(), provenance.network_uid(), role, None)
                .ok()?;
        let key = parts.key.as_deref()?;
        let value = match key {
            "disable-ipv6" => "1",
            "accept-ra" | "autoconf" => "0",
            _ => return None,
        };
        let marker = d2b_contracts_resource::v3::derive_network_ownership_marker(
            provenance,
            &format!("sysctl:{key}"),
        );
        let _ = spec;
        Some(ResolvedSysctlIntent {
            intent_id: id.to_owned(),
            key: format!(
                "net.ipv6.conf.{}.{}",
                ifname.as_str(),
                key.replace('-', "_")
            ),
            value: value.to_owned(),
            provenance: Some(provenance.clone()),
            ownership_marker: Some(marker),
        })
    }

    /// Resolve a Network hosts projection from an admitted reference.
    pub fn resolve_network_hosts_intent(
        &self,
        id: &str,
        provenance: &NetworkProvenance,
    ) -> Option<ResolvedHostsIntent> {
        let parts = parse_network_intent_ref(id)?;
        if parts.kind != NetworkIntentKind::Hosts
            || parts.zone_uid != *provenance.zone_uid()
            || parts.network_uid != *provenance.network_uid()
        {
            return None;
        }
        let spec = self.find_network_spec(&parts)?;
        let marker =
            d2b_contracts_resource::v3::derive_network_ownership_marker(provenance, "hosts");
        let managed_block = format!(
            "# d2b-managed begin\n# d2b managed: {marker}\n# network {} lan {} uplink {}\n# d2b-managed end\n",
            parts.network_name,
            spec.lan_cidr().as_str(),
            spec.uplink_cidr().as_str()
        );
        Some(ResolvedHostsIntent {
            intent_id: id.to_owned(),
            path: PathBuf::from("/etc/hosts"),
            managed_block,
            start_marker: "# d2b-managed begin".to_owned(),
            end_marker: "# d2b-managed end".to_owned(),
            mode: 0o644,
            provenance: Some(provenance.clone()),
            ownership_marker: Some(marker),
        })
    }

    fn find_network_spec(&self, parts: &ParsedNetworkIntentRef) -> Option<NetworkSpec> {
        self.zone_resource_bundles.values().find_map(|bytes| {
            let bundle = ResourceBundle::from_json(bytes).ok()?;
            if bundle.zone_uid.as_ref() != Some(&parts.zone_uid) {
                return None;
            }
            let resource = bundle.resources.iter().find(|resource| {
                resource.resource_type().as_str() == "Network"
                    && network_name_token(resource.metadata().name().as_str()) == parts.network_name
                    && resource
                        .metadata()
                        .annotations()
                        .get("networkUid")
                        .is_none_or(|value| {
                            d2b_contracts_resource::v3::ResourceUid::parse(value.clone()).ok()
                                == Some(parts.network_uid.clone())
                        })
            })?;
            let mut value = serde_json::to_value(resource.spec()).ok()?;
            let object = value.as_object_mut()?;
            for field in ["providerRef", "updatePolicy", "provider"] {
                object.remove(field);
            }
            serde_json::from_value(value).ok()
        })
    }

    pub fn find_nm_unmanaged_intent(&self, id: &str) -> Option<&ResolvedNmUnmanagedIntent> {
        self.nm_unmanaged_intents.get(id)
    }

    pub fn find_usbip_firewall_intent(&self, id: &str) -> Option<&ResolvedUsbipFirewallIntent> {
        self.usbip_firewall_intents.get(id)
    }

    pub fn find_usbip_bind_intent(&self, id: &str) -> Option<&ResolvedUsbipBindIntent> {
        self.usbip_bind_intents.get(id)
    }

    pub fn find_runner_intent(&self, id: &str) -> Option<&ResolvedRunnerIntent> {
        self.runner_intents.get(id)
    }

    /// Find the unique trusted runner intent for a Process template and
    /// execution binding.
    ///
    /// Generic v3 Process resources carry a plain Provider template name
    /// rather than a legacy process-DAG role id.  The private runner artifact
    /// remains the only source of executable and sandbox data, so this lookup
    /// deliberately matches only trusted intent metadata and refuses
    /// ambiguity.
    pub fn find_runner_intent_for_process(
        &self,
        execution_ref: &str,
        execution_domain: ProcessExecutionDomain,
        user_ref: Option<&str>,
        template: &str,
    ) -> Option<&ResolvedRunnerIntent> {
        self.find_runner_intent_for_process_in_vm(
            None,
            execution_ref,
            execution_domain,
            user_ref,
            template,
        )
    }

    /// Find the unique trusted Process runner intent, optionally restricted
    /// to one VM when a shared Host execution reference is used.
    pub fn find_runner_intent_for_process_in_vm(
        &self,
        vm_name: Option<&str>,
        execution_ref: &str,
        execution_domain: ProcessExecutionDomain,
        user_ref: Option<&str>,
        template: &str,
    ) -> Option<&ResolvedRunnerIntent> {
        let mut matches = self.runner_intents.values().filter(|intent| {
            intent.role != ProcessRole::ProviderController
                && vm_name.is_none_or(|vm| intent.vm_name == vm)
                && intent.execution_ref == execution_ref
                && intent.execution_domain == execution_domain
                && intent.user_ref.as_deref() == user_ref
                && (intent.role_id == template
                    || intent.profile_id == template
                    || runner_template_name(&intent.role) == Some(template)
                    || process_template_name_matches(intent, template))
        });
        let first = matches.next()?;
        matches.next().is_none().then_some(first)
    }

    /// Find the private Cloud Hypervisor VMM intent for a controller-owned
    /// Guest Process. The caller must present the exact Zone-local Guest
    /// reference and catalog-bound descriptor digest; a matching Guest name
    /// alone is never sufficient.
    pub fn find_guest_vmm_intent(
        &self,
        zone: &str,
        guest_ref: &ResourceRef,
        descriptor_digest: &d2b_contracts_resource::v3::SchemaFingerprint,
        execution_ref: &str,
        execution_domain: ProcessExecutionDomain,
        template: &str,
    ) -> Option<&ResolvedRunnerIntent> {
        if guest_ref.resource_type().as_str() != "Guest" {
            return None;
        }
        let descriptor = self
            .guest_setup_descriptors
            .get(&(zone.to_owned(), guest_ref.name().as_str().to_owned()))?;
        let catalog_key =
            self.guest_setup_descriptor_catalog_key(zone, guest_ref.name().as_str())?;
        let descriptor_value = serde_json::from_slice::<serde_json::Value>(descriptor).ok()?;
        if descriptor_value
            .get("descriptorDigest")
            .and_then(serde_json::Value::as_str)
            != Some(descriptor_digest.as_str())
            || descriptor_value
                .get("signature")
                .and_then(|signature| signature.get("keyFingerprint"))
                .and_then(serde_json::Value::as_str)
                != Some(catalog_key)
        {
            return None;
        }
        let vm_name = guest_ref.name().as_str();
        let intent = self
            .guest_vmm_intents
            .get(&(zone.to_owned(), vm_name.to_owned()))?;
        (intent.role == ProcessRole::CloudHypervisorRunner
            && intent.vm_name == vm_name
            && intent.execution_ref == execution_ref
            && intent.execution_domain == execution_domain
            && intent.user_ref.is_none()
            && guest_vmm_template_matches(intent, template))
        .then_some(intent)
    }

    /// Find the private Guest VMM intent using the immutable Zone UID carried
    /// by a Process launch ticket. This prevents two Zones with the same
    /// Guest name from sharing a global runner lookup.
    pub fn find_guest_vmm_intent_for_zone_uid(
        &self,
        zone_uid: &ResourceUid,
        guest: &str,
        execution_ref: &str,
        execution_domain: ProcessExecutionDomain,
        template: &str,
    ) -> Option<&ResolvedRunnerIntent> {
        let key = self
            .guest_vmm_zone_uids
            .iter()
            .find_map(|(key, value)| (value == zone_uid && key.1 == guest).then_some(key))?;
        let intent = self.guest_vmm_intents.get(key)?;
        (intent.role == ProcessRole::CloudHypervisorRunner
            && intent.vm_name == guest
            && intent.execution_ref == execution_ref
            && intent.execution_domain == execution_domain
            && intent.user_ref.is_none()
            && guest_vmm_template_matches(intent, template))
        .then_some(intent)
    }

    /// Find the static Provider controller intent for one exact Process
    /// resource. The Process identity disambiguates multiple installations of
    /// the same Provider artifact on one execution target.
    pub fn find_provider_controller_intent(
        &self,
        process_ref: &ResourceRef,
        execution_ref: &str,
        execution_domain: ProcessExecutionDomain,
        user_ref: Option<&str>,
        template: &str,
        owner_ref: Option<&str>,
    ) -> Option<&ResolvedRunnerIntent> {
        if process_ref.resource_type().as_str() != "Process" {
            return None;
        }
        let mut matches = self.runner_intents.values().filter(|intent| {
            intent.role == ProcessRole::ProviderController
                && intent.role_id == process_ref.name().as_str()
                && intent.execution_ref == execution_ref
                && intent.execution_domain == execution_domain
                && intent.user_ref.as_deref() == user_ref
                && owner_ref.is_none_or(|owner| intent.owner_ref.as_deref() == Some(owner))
                && intent.profile_id == template
        });
        let first = matches.next()?;
        matches.next().is_none().then_some(first)
    }

    /// Find the unique dynamic Provider component template for one execution
    /// target. The controller-created Process name is intentionally not part
    /// of this lookup.
    pub fn find_provider_component_intent_for_template(
        &self,
        execution_ref: &str,
        execution_domain: ProcessExecutionDomain,
        user_ref: Option<&str>,
        template: &str,
        owner_ref: Option<&str>,
    ) -> Option<&ResolvedRunnerIntent> {
        let mut matches = self.runner_intents.values().filter(|intent| {
            intent.role == ProcessRole::ProviderController
                && intent.execution_ref == execution_ref
                && intent.execution_domain == execution_domain
                && intent.user_ref.as_deref() == user_ref
                && owner_ref.is_none_or(|owner| intent.owner_ref.as_deref() == Some(owner))
                && intent.profile_id == template
        });
        let first = matches.next()?;
        matches.next().is_none().then_some(first)
    }

    pub fn find_socket_intent(&self, id: &str) -> Option<&ResolvedSocketIntent> {
        self.socket_intents.get(id)
    }

    pub fn find_installer_intent(&self, id: &str) -> Option<&ResolvedInstallerIntent> {
        self.installer_intents.get(id)
    }

    pub fn find_migrate_intent(&self, id: &str) -> Option<&ResolvedMigrateIntent> {
        self.migrate_intents.get(id)
    }

    pub fn find_activation_intent(&self, id: &str) -> Option<&ResolvedActivationIntent> {
        self.activation_intents.get(id)
    }

    /// Find a store-view intent by its exact opaque bundle key.
    ///
    /// Zone-native callers must pass the Zone-qualified
    /// [`intent_id_store_view`] result; the legacy VM-only key is accepted
    /// only through [`Self::find_legacy_store_view_intent`].
    pub fn find_store_view_intent(&self, intent_id: &str) -> Option<&ResolvedStoreViewIntent> {
        self.store_view_intents.get(intent_id)
    }

    pub fn find_store_view_intent_for_zone(
        &self,
        zone: &ZoneId,
        vm: &str,
    ) -> Option<&ResolvedStoreViewIntent> {
        self.find_store_view_intent(&intent_id_store_view(zone, vm))
    }

    pub fn find_legacy_store_view_intent(&self, vm: &str) -> Option<&ResolvedStoreViewIntent> {
        self.find_store_view_intent(&intent_id_legacy_store_view(vm))
    }

    pub fn find_guest_closure_out_path(&self, vm: &str) -> Option<&str> {
        self.closure_toplevels.get(vm).map(String::as_str)
    }

    pub fn find_gc_intent(&self, id: &str) -> Option<&ResolvedGcIntent> {
        self.gc_intents.get(id)
    }

    pub fn find_keys_rotate_intent(&self, id: &str) -> Option<&ResolvedKeysRotateIntent> {
        self.keys_rotate_intents.get(id)
    }

    pub fn find_host_key_trust_intent(&self, id: &str) -> Option<&ResolvedHostKeyTrustIntent> {
        self.host_key_trust_intents.get(id)
    }

    pub fn find_rotate_known_host_intent(
        &self,
        id: &str,
    ) -> Option<&ResolvedRotateKnownHostIntent> {
        self.rotate_known_host_intents.get(id)
    }

    /// Resolve a QEMU media source by VM + opaque ref.
    ///
    /// Raw physical identity is deliberately absent from the bundle; callers
    /// use the returned policy row to decide whether enrollment/open must be
    /// read-only or writable, then the broker reads the root-only runtime
    /// registry for the actual device identity.
    pub fn find_qemu_media_source(
        &self,
        vm: &str,
        media_ref: &str,
    ) -> Option<&QemuMediaSourceIntent> {
        self.host
            .qemu_media
            .as_ref()?
            .sources
            .iter()
            .find(|source| source.vm == vm && source.media_ref == media_ref)
    }

    pub fn find_storage_path_spec(&self, id: &str) -> Option<&crate::storage::StoragePathSpec> {
        self.storage
            .as_ref()?
            .paths
            .iter()
            .find(|spec| spec.id.as_str() == id)
    }

    pub fn find_sync_lock_spec(&self, id: &str) -> Option<&crate::sync::LockSpec> {
        self.sync
            .as_ref()?
            .locks
            .iter()
            .find(|spec| spec.id.as_str() == id)
    }

    pub fn find_manifest_vm(&self, vm_id: &str) -> Option<&VmEntry> {
        self.manifest.vms.get(vm_id)
    }

    pub fn find_process_vm(&self, vm_id: &str) -> Option<&VmProcessDag> {
        self.processes.vms.iter().find(|vm| vm.vm == vm_id)
    }

    pub fn find_process_node(&self, vm_id: &str, role_id: &str) -> Option<&ProcessNode> {
        self.find_process_vm(vm_id)
            .and_then(|vm| vm.nodes.iter().find(|node| node.id.0 == role_id))
    }

    /// v1.2 collect every `DiskInit` plan-op declared on any node in
    /// the VM's process DAG.
    ///
    /// The broker calls this before issuing `SpawnRunner` for a VM
    /// so it can create the backing disk images declared in the
    /// trusted bundle. The caller (daemon) only supplies the opaque
    /// `vm_id`; all paths and permissions come from the bundle.
    pub fn resolve_disk_init_ops(&self, vm_id: &str) -> Vec<ResolvedDiskInitOp> {
        use crate::processes::SpawnRunnerPlanOp;
        let Some(vm) = self.find_process_vm(vm_id) else {
            return Vec::new();
        };
        let mut ops = Vec::new();
        for node in &vm.nodes {
            for plan_op in &node.plan_ops {
                match plan_op {
                    SpawnRunnerPlanOp::DiskInit {
                        target_path,
                        size_bytes,
                        mode,
                        owner_uid,
                        owner_gid,
                        if_absent,
                    } => {
                        ops.push(ResolvedDiskInitOp {
                            target_path: target_path.clone(),
                            size_bytes: *size_bytes,
                            mode: *mode,
                            owner_uid: *owner_uid,
                            owner_gid: *owner_gid,
                            if_absent: *if_absent,
                        });
                    }
                }
            }
        }
        ops
    }

    pub fn resolve_vm_start_intent(
        &self,
        vm_id: &str,
        role_id: &str,
    ) -> Option<ResolvedVmStartIntent> {
        let node = self.find_process_node(vm_id, role_id)?;
        let mut actions = Vec::new();
        match node.role {
            ProcessRole::HostReconcile => {
                if let Some(intent) = self.resolve_prepare_dir_intent(vm_id, true) {
                    actions.push(ResolvedVmStartAction::PrepareRuntimeDir(intent));
                }
                if let Some(intent) = self.resolve_prepare_dir_intent(vm_id, false) {
                    actions.push(ResolvedVmStartAction::PrepareStateDir(intent));
                }
            }
            ProcessRole::StoreVirtiofsPreflight => {
                if let Some(intent) = self.find_legacy_store_view_intent(vm_id).cloned() {
                    actions.push(ResolvedVmStartAction::PrepareStoreView(intent));
                }
            }
            _ => {}
        }
        Some(ResolvedVmStartIntent {
            intent_id: intent_id_vm_start(vm_id, role_id),
            vm_name: vm_id.to_owned(),
            role_id: role_id.to_owned(),
            role: node.role.clone(),
            actions,
        })
    }

    pub fn resolve_vm_start_prerequisites(
        &self,
        vm_id: &str,
        role_id: &str,
    ) -> Vec<ResolvedVmStartIntent> {
        let Some(vm) = self.find_process_vm(vm_id) else {
            return Vec::new();
        };
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        self.collect_vm_start_predecessors(vm, role_id, &mut seen, &mut out);
        out
    }

    pub fn find_host_env(&self, env: &str) -> Option<&NetEnv> {
        self.host
            .environments
            .iter()
            .find(|candidate| candidate.env == env)
    }

    pub fn find_if_name_mapping_for_vm(&self, vm_id: &str) -> Option<&crate::host::IfNameMapping> {
        self.host
            .if_name_mappings
            .iter()
            .find(|mapping| mapping.vm.as_deref() == Some(vm_id))
    }

    pub fn resolve_tap_intent(
        &self,
        vm_id: &str,
        role_id: &str,
        provenance: NetworkProvenance,
        attachment_id: ResourceUid,
    ) -> Option<ResolvedTapIntent> {
        let node = self.find_process_node(vm_id, role_id).or_else(|| {
            if matches!(role_id, "ch" | "ch-runner") {
                self.find_process_vm(vm_id).and_then(|vm| {
                    vm.nodes
                        .iter()
                        .find(|node| matches!(node.role, ProcessRole::CloudHypervisorRunner))
                })
            } else {
                None
            }
        })?;
        let canonical_role_id = canonical_tap_role_id(role_id);
        let is_net_vm = vm_id
            == d2b_contracts_resource::v3::derive_network_child_name(
                provenance.network_uid(),
                "vm",
            );
        if is_net_vm && canonical_role_id != "ch" {
            return None;
        }
        let (bridge_role, tap_role, tap_class) = if is_net_vm {
            (
                NetworkIfRole::LanBridge,
                NetworkIfRole::NetVmLanTap,
                TapRoleW3::NetVmLan,
            )
        } else {
            match canonical_role_id {
                "net-vm-lan" => (
                    NetworkIfRole::LanBridge,
                    NetworkIfRole::NetVmLanTap,
                    TapRoleW3::NetVmLan,
                ),
                "uplink" => (
                    NetworkIfRole::UplinkBridge,
                    NetworkIfRole::NetVmUplinkTap,
                    TapRoleW3::UplinkP2P,
                ),
                "ch" | "qemu-media" | "workload-lan" | "network-attachment" | "runner-lan" => (
                    NetworkIfRole::LanBridge,
                    NetworkIfRole::WorkloadGuestTap,
                    TapRoleW3::WorkloadLanIsolated,
                ),
                _ => return None,
            }
        };
        let bridge_ifname = derive_network_ifname(
            provenance.zone_uid(),
            provenance.network_uid(),
            bridge_role,
            None,
        )
        .ok()?;
        let tap_ifname = derive_network_ifname(
            provenance.zone_uid(),
            provenance.network_uid(),
            tap_role,
            match tap_role {
                NetworkIfRole::NetVmLanTap | NetworkIfRole::NetVmUplinkTap => None,
                NetworkIfRole::WorkloadGuestTap | NetworkIfRole::ExternalMacvtap => {
                    Some(&attachment_id)
                }
                NetworkIfRole::LanBridge | NetworkIfRole::UplinkBridge => None,
            },
        )
        .ok()?;
        let ownership_marker = d2b_contracts_resource::v3::derive_network_ownership_marker(
            &provenance,
            &format!("tap:{}", attachment_id.as_str()),
        );
        Some(ResolvedTapIntent {
            intent_id: intent_id_network_tap(
                provenance.zone_uid(),
                provenance.network_uid(),
                &attachment_id,
                provenance.network_generation(),
                provenance.attachment_generation(),
                provenance.bundle_generation(),
                canonical_role_id,
                vm_id,
            ),
            vm_name: vm_id.to_owned(),
            role_id: canonical_role_id.to_owned(),
            bridge_ifname,
            tap_ifname,
            tap_role: tap_class,
            net_handoff_mode: self
                .host
                .ch
                .as_ref()
                .map(|ch| ch.net_handoff_mode)
                .unwrap_or(ChNetHandoffMode::PersistentTap),
            owner_uid: node.profile.uid,
            owner_gid: node.profile.gid,
            provenance,
            ownership_marker,
        })
    }

    pub fn resolve_macvtap_intents(
        &self,
        vm_id: &str,
        role_id: &str,
    ) -> Result<Vec<ResolvedMacvtapIntent>, String> {
        let node = self
            .find_process_node(vm_id, role_id)
            .ok_or_else(|| format!("missing process node vm={vm_id} role={role_id}"))?;
        let mut next_fd = 10;
        let mut out = Vec::new();
        for iface in &node.network_interfaces {
            if iface.type_ != ProcessNetworkInterfaceType::Macvtap {
                continue;
            }
            let macvtap = iface.macvtap.as_ref().ok_or_else(|| {
                format!(
                    "macvtap interface {} for vm={vm_id} role={role_id} is missing macvtap metadata",
                    iface.id
                )
            })?;
            out.push(ResolvedMacvtapIntent {
                vm_name: vm_id.to_owned(),
                role_id: role_id.to_owned(),
                ifname: IfName::new(iface.id.clone())
                    .map_err(|err| format!("invalid macvtap ifname {}: {err}", iface.id))?,
                parent_ifname: IfName::new(macvtap.link.clone()).map_err(|err| {
                    format!("invalid macvtap parent ifname {}: {err}", macvtap.link)
                })?,
                mode: macvtap.mode,
                mac: iface.mac.clone(),
                fd: next_fd,
            });
            next_fd += 1;
        }
        Ok(out)
    }

    pub fn resolve_prepare_dir_intent(
        &self,
        vm_id: &str,
        runtime_dir: bool,
    ) -> Option<ResolvedPrepareDirIntent> {
        let vm = self.find_manifest_vm(vm_id)?;
        let base_dir = if runtime_dir {
            PathBuf::from(format!("/run/d2b/vms/{vm_id}"))
        } else {
            PathBuf::from(&vm.state_dir)
        };
        let (owner_uid, owner_gid) = self.resolve_path_owner(vm_id, &base_dir)?;
        Some(ResolvedPrepareDirIntent {
            vm_name: vm_id.to_owned(),
            base_dir,
            owner_uid,
            owner_gid,
            mode: if runtime_dir { 0o755 } else { 0o750 },
        })
    }

    /// Resolve the one migration-required legacy swtpm row for a VM.
    pub fn resolve_legacy_swtpm_intent(&self, vm_id: &str) -> Option<ResolvedLegacySwtpmIntent> {
        let vm = self.find_manifest_vm(vm_id)?;
        if !vm.tpm {
            return None;
        }
        let state_dir = PathBuf::from(&vm.state_dir);
        let destination = state_dir.join("swtpm");
        let (owner_uid, owner_gid) = self.resolve_path_owner(vm_id, &destination)?;
        let marker_root = state_dir.parent()?.parent()?.join("swtpm-markers");
        Some(ResolvedLegacySwtpmIntent {
            intent_id: intent_id_legacy_swtpm(vm_id),
            vm: vm_id.to_owned(),
            source: state_dir.join("swtpm-legacy"),
            destination,
            journal: state_dir.join(".d2b-legacy-swtpm.journal"),
            marker: marker_root.join(vm_id),
            owner_uid,
            owner_gid,
        })
    }

    fn collect_vm_start_predecessors(
        &self,
        vm: &VmProcessDag,
        role_id: &str,
        seen: &mut BTreeSet<String>,
        out: &mut Vec<ResolvedVmStartIntent>,
    ) {
        for predecessor in vm
            .edges
            .iter()
            .filter(|edge| edge.to.0 == role_id)
            .map(|edge| edge.from.0.as_str())
        {
            if !seen.insert(predecessor.to_owned()) {
                continue;
            }
            let Some(intent) = self.resolve_vm_start_intent(&vm.vm, predecessor) else {
                continue;
            };
            if intent.is_readiness_only() {
                continue;
            }
            self.collect_vm_start_predecessors(vm, predecessor, seen, out);
            out.push(intent);
        }
    }

    pub fn resolve_kernel_module_intent(
        &self,
        module_name: &str,
    ) -> Option<ResolvedKernelModuleIntent> {
        let row = self
            .host
            .kernel_modules
            .iter()
            .find(|row| row.module == module_name)?;
        Some(ResolvedKernelModuleIntent {
            module_name: row.module.clone(),
            matrix_entry_id: format!("kernel-module:{}", row.module),
            feature: row.feature.clone(),
            requirement: module_requirement_w3(&row.requirement),
            fail_if_modules_disabled: module_fail_if_disabled(&row.requirement),
            load_allowed: module_allows_modprobe(&row.requirement),
        })
    }

    pub fn resolve_role_device_claim(&self, role_id: &str) -> Option<ResolvedRoleDeviceClaim> {
        let node = self
            .processes
            .vms
            .iter()
            .flat_map(|vm| vm.nodes.iter())
            .find(|node| node.id.0 == role_id)?;
        Some(ResolvedRoleDeviceClaim {
            role_id: role_id.to_owned(),
            role: node.role.clone(),
            allowed_device_classes: role_device_classes(
                &node.role,
                self.host
                    .ch
                    .as_ref()
                    .map(|ch| ch.net_handoff_mode)
                    .unwrap_or(ChNetHandoffMode::PersistentTap),
            )
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        })
    }

    fn resolve_path_owner(&self, vm_id: &str, path: &Path) -> Option<(u32, u32)> {
        let dag = self.find_process_vm(vm_id)?;
        let path_str = path.to_string_lossy();
        dag.nodes
            .iter()
            .filter_map(|node| {
                node.profile
                    .mount_policy
                    .writable_paths
                    .iter()
                    .filter_map(|writable| {
                        let exact = writable.path == path_str;
                        let prefix = path_str == writable.path
                            || path_str
                                .starts_with(&format!("{}/", writable.path.trim_end_matches('/')));
                        if exact || prefix {
                            Some((
                                (node.profile.uid, node.profile.gid),
                                score_writable_path(node, exact),
                            ))
                        } else {
                            None
                        }
                    })
                    .max_by_key(|(_, score)| *score)
            })
            .max_by_key(|(_, score)| *score)
            .map(|(owner, _)| owner)
    }

    /// Build the canonical `host-runtime.json` record from the bundle's
    /// `host.if_name_mappings` rows. The broker writes this during
    /// `RunHostInstall` so downstream consumers read ifnames from a
    /// single source of truth instead of recomputing via the
    /// SHA-256-vs-FNV-1a dual-algorithm dance.
    pub fn host_runtime(&self) -> HostRuntime {
        let ifnames = self
            .host
            .if_name_mappings
            .iter()
            .map(|m| HostRuntimeIfName {
                env: m.env.clone(),
                vm: m.vm.clone(),
                user_visible_name: m.user_visible_name.clone(),
                derived_ifname: m.derived_ifname.as_str().to_owned(),
                role_tag: role_tag_for(&m.role),
            })
            .collect();
        HostRuntime {
            schema_version: self.bundle.schema_version.clone(),
            bundle_version: self.bundle.bundle_version,
            generated_at: self
                .bundle
                .generation
                .generated_at
                .clone()
                .unwrap_or_else(|| "runtime-emitted".to_owned()),
            nft_applied_hash: self.host.nftables.table_hash_after_apply.clone(),
            ifnames,
        }
    }

    /// All registered nft intent ids (sorted, deterministic).
    pub fn nft_intent_ids(&self) -> impl Iterator<Item = &str> {
        self.nft_intents.keys().map(String::as_str)
    }

    pub fn route_intent_ids(&self) -> impl Iterator<Item = &str> {
        self.route_intents.keys().map(String::as_str)
    }

    pub fn sysctl_intent_ids(&self) -> impl Iterator<Item = &str> {
        self.sysctl_intents.keys().map(String::as_str)
    }

    pub fn hosts_intent_ids(&self) -> impl Iterator<Item = &str> {
        self.hosts_intents.keys().map(String::as_str)
    }

    pub fn nm_unmanaged_intent_ids(&self) -> impl Iterator<Item = &str> {
        self.nm_unmanaged_intents.keys().map(String::as_str)
    }

    pub fn usbip_firewall_intent_ids(&self) -> impl Iterator<Item = &str> {
        self.usbip_firewall_intents.keys().map(String::as_str)
    }

    pub fn usbip_bind_intent_ids(&self) -> impl Iterator<Item = &str> {
        self.usbip_bind_intents.keys().map(String::as_str)
    }

    pub fn runner_intent_ids(&self) -> impl Iterator<Item = &str> {
        self.runner_intents.keys().map(String::as_str)
    }

    pub fn socket_intent_ids(&self) -> impl Iterator<Item = &str> {
        self.socket_intents.keys().map(String::as_str)
    }

    pub fn installer_intent_ids(&self) -> impl Iterator<Item = &str> {
        self.installer_intents.keys().map(String::as_str)
    }

    pub fn migrate_intent_ids(&self) -> impl Iterator<Item = &str> {
        self.migrate_intents.keys().map(String::as_str)
    }

    pub fn activation_intent_ids(&self) -> impl Iterator<Item = &str> {
        self.activation_intents.keys().map(String::as_str)
    }

    pub fn gc_intent_ids(&self) -> impl Iterator<Item = &str> {
        self.gc_intents.keys().map(String::as_str)
    }

    pub fn keys_rotate_intent_ids(&self) -> impl Iterator<Item = &str> {
        self.keys_rotate_intents.keys().map(String::as_str)
    }

    pub fn host_key_trust_intent_ids(&self) -> impl Iterator<Item = &str> {
        self.host_key_trust_intents.keys().map(String::as_str)
    }

    pub fn rotate_known_host_intent_ids(&self) -> impl Iterator<Item = &str> {
        self.rotate_known_host_intents.keys().map(String::as_str)
    }

    /// Per-role minijail profile validator. Walks every profile the
    /// bundle ships (via `processes.json` role profiles) and asserts
    /// the invariants:
    ///
    /// 1. uid and gid are non-zero unless a NON-EMPTY `adr_carve_out`
    ///    ref explicitly documents a root carve-out (an empty or
    ///    whitespace-only carve-out is treated as no carve-out);
    /// 2. mount_policy.nix_store_read_only is `true` for every
    ///    non-root role;
    /// 3. cgroup_placement.subtree starts with `d2b/` or `d2b.slice/`;
    /// 4. profile_id is non-empty.
    ///
    /// Returns the first violation as `Err`, or `Ok(profile_count)`
    /// when every profile passes. The integrator must add a
    /// corresponding fix to the Nix profile emitter for any reported
    /// violation.
    ///
    /// Migration note (supersedes tests/static-invariant-uid0.sh): the
    /// retired bash gate additionally coupled a uid-0 long-lived profile to
    /// `requiresStartRoot = true`. `requires_start_root` lives on the
    /// minijail-profile metadata, not on the `processes::RoleProfile` this
    /// validator walks, and per ADR 0021 virtiofsd now runs fake-root inside
    /// a broker-established user namespace with `requiresStartRoot = false` -
    /// so the carve-out reference, not `requiresStartRoot`, is the live
    /// security gate. The schema-shape part of the bash gate (root-capable
    /// shapes must declare an ADR carve-out field) is structurally
    /// guaranteed: `RoleProfile` carries `adr_carve_out` alongside `uid`/`gid`
    /// (so the negative unit tests would fail to compile if it were removed)
    /// and `bundle-drift` keeps the committed v2 schema in sync with the DTO.
    pub fn validate_minijail_profiles(&self) -> Result<usize, MinijailProfileViolation> {
        let mut count = 0usize;
        for dag in &self.processes.vms {
            for node in &dag.nodes {
                let p = &node.profile;
                if p.profile_id.is_empty() {
                    return Err(MinijailProfileViolation::EmptyProfileId {
                        vm: dag.vm.clone(),
                        node: node.id.0.clone(),
                    });
                }
                // An ADR carve-out justifies a uid/gid 0 or writable-store
                // profile, but only if it is a real reference - an empty or
                // whitespace-only `adr_carve_out` is treated as NO carve-out
                // (the bash static-invariant-uid0 gate required an ADR-like
                // reference; matching that here closes a fail-open where
                // `Some("")` would satisfy the gate).
                let root_carve_out = p
                    .adr_carve_out
                    .as_deref()
                    .is_some_and(|s| !s.trim().is_empty());
                if !root_carve_out && (p.uid == 0 || p.gid == 0) {
                    return Err(MinijailProfileViolation::RootWithoutCarveOut {
                        profile_id: p.profile_id.clone(),
                        vm: dag.vm.clone(),
                        uid: p.uid,
                        gid: p.gid,
                    });
                }
                if !root_carve_out && !p.mount_policy.nix_store_read_only {
                    return Err(MinijailProfileViolation::NixStoreNotReadOnly {
                        profile_id: p.profile_id.clone(),
                        vm: dag.vm.clone(),
                    });
                }
                if !p.cgroup_placement.subtree.starts_with("d2b/")
                    && !p.cgroup_placement.subtree.starts_with("d2b.slice/")
                    && !p.cgroup_placement.subtree.is_empty()
                {
                    return Err(MinijailProfileViolation::CgroupSubtreeOutsideD2b {
                        profile_id: p.profile_id.clone(),
                        subtree: p.cgroup_placement.subtree.clone(),
                    });
                }
                count += 1;
            }
        }
        Ok(count)
    }
}

/// Minijail profile validator violations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MinijailProfileViolation {
    EmptyProfileId {
        vm: String,
        node: String,
    },
    RootWithoutCarveOut {
        profile_id: String,
        vm: String,
        uid: u32,
        gid: u32,
    },
    NixStoreNotReadOnly {
        profile_id: String,
        vm: String,
    },
    CgroupSubtreeOutsideD2b {
        profile_id: String,
        subtree: String,
    },
}

impl std::fmt::Display for MinijailProfileViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyProfileId { vm, node } => {
                write!(
                    f,
                    "minijail profile for vm={vm} node={node} has empty profile_id"
                )
            }
            Self::RootWithoutCarveOut {
                profile_id,
                vm,
                uid,
                gid,
            } => write!(
                f,
                "minijail profile {profile_id} for vm={vm} runs as uid={uid} gid={gid} without adr_carve_out ref"
            ),
            Self::NixStoreNotReadOnly { profile_id, vm } => write!(
                f,
                "minijail profile {profile_id} for vm={vm} has nix_store_read_only=false without adr_carve_out"
            ),
            Self::CgroupSubtreeOutsideD2b {
                profile_id,
                subtree,
            } => write!(
                f,
                "minijail profile {profile_id} cgroup subtree {subtree} is outside the delegated d2b root"
            ),
        }
    }
}

impl std::error::Error for MinijailProfileViolation {}

fn module_requirement_w3(requirement: &ModuleRequirement) -> ModuleRequirementW3 {
    match requirement {
        ModuleRequirement::Required => ModuleRequirementW3::Required,
        ModuleRequirement::Alternatives => ModuleRequirementW3::Alternatives,
        ModuleRequirement::Optional => ModuleRequirementW3::Optional,
        ModuleRequirement::Deferred => ModuleRequirementW3::Deferred,
    }
}

fn module_fail_if_disabled(requirement: &ModuleRequirement) -> bool {
    matches!(
        requirement,
        ModuleRequirement::Required | ModuleRequirement::Alternatives
    )
}

fn module_allows_modprobe(requirement: &ModuleRequirement) -> bool {
    !matches!(requirement, ModuleRequirement::Deferred)
}

fn score_writable_path(node: &ProcessNode, exact: bool) -> u8 {
    match (&node.role, exact) {
        (ProcessRole::QemuMediaRunner, true) => 5,
        (ProcessRole::HostReconcile, true) => 4,
        (_, true) => 3,
        (ProcessRole::HostReconcile, false) => 2,
        _ => 1,
    }
}

fn role_device_classes(
    role: &ProcessRole,
    net_handoff_mode: ChNetHandoffMode,
) -> &'static [&'static str] {
    match role {
        ProcessRole::CloudHypervisorRunner => match net_handoff_mode {
            ChNetHandoffMode::TapFd => &["kvm", "net-tun", "vhost-net"],
            ChNetHandoffMode::PersistentTap => &["kvm"],
        },
        ProcessRole::Virtiofsd => &["fuse"],
        // Gpu device claim. Must EXACTLY match the per-role device
        // matrix in nixos-modules/minijail-profiles.nix and the row in
        // docs/reference/privileges.md:
        //   /dev/kvm, /dev/dri/renderD128, /dev/nvidiactl,
        //   /dev/nvidia0 (was nvidia-render → /dev/nvidia0),
        //   /dev/nvidia-uvm, /dev/udmabuf.
        // The previous claim included vfio (NOT in the GPU contract -
        // vfio is for SR-IOV passthrough scenarios that this role does
        // not cover) and omitted kvm + udmabuf.
        ProcessRole::Gpu | ProcessRole::GpuRenderNode => &[
            "kvm",
            "dri",
            "nvidia-ctl",
            "nvidia-uvm",
            "nvidia-render",
            "udmabuf",
        ],
        ProcessRole::Audio => &["pipewire-socket"],
        ProcessRole::Usbip => &["usbip-host"],
        ProcessRole::QemuMediaRunner => &["kvm"],
        ProcessRole::SwtpmPreStartFlush => &["tpm"],
        _ => &[],
    }
}

// ---------------------------------------------------------------
// Installer + migrate intent ID helpers.
// ---------------------------------------------------------------

pub fn intent_id_installer_host() -> String {
    "installer:host".to_owned()
}

pub fn intent_id_migrate_host() -> String {
    "migrate:host".to_owned()
}

pub fn intent_id_activation(vm: &str) -> String {
    format!("activation:vm:{vm}")
}

pub fn intent_id_store_view(zone: &ZoneId, vm: &str) -> String {
    format!("store-view:zone:{}:vm:{vm}", zone.as_str())
}

pub fn intent_id_legacy_store_view(vm: &str) -> String {
    format!("store-view:vm:{vm}")
}

pub fn intent_id_vm_start(vm: &str, role_id: &str) -> String {
    format!("vm-start:vm:{vm}:role:{role_id}")
}

pub fn intent_id_legacy_swtpm(vm: &str) -> String {
    format!("legacy-swtpm:vm:{vm}")
}

pub fn intent_id_gc_host() -> String {
    "gc:host".to_owned()
}

pub fn intent_id_keys_rotate(vm: &str) -> String {
    format!("keys-rotate:vm:{vm}")
}

pub fn intent_id_trust(vm: &str) -> String {
    format!("trust:vm:{vm}")
}

pub fn intent_id_rotate_known_host(vm: &str) -> String {
    format!("rotate-known-host:vm:{vm}")
}

// ---------------------------------------------------------------
// Intent ID format helpers (deterministic, public).
// ---------------------------------------------------------------

pub fn intent_id_nft_host() -> String {
    "nft:host".to_owned()
}

pub fn intent_id_nft_env(env: &str) -> String {
    format!("nft:env:{env}")
}

pub fn intent_id_nft_projection_env(env: &str) -> String {
    format!("nft-projection:env:{env}")
}

/// Build a UID-bound Network effect reference.
///
/// The resource name is retained only as a bundle lookup hint. Admission and
/// effect authorization use the Zone and Network UIDs encoded before it.
pub fn intent_id_network_bridge_uids(
    zone_uid: &d2b_contracts_resource::v3::ResourceUid,
    network_uid: &d2b_contracts_resource::v3::ResourceUid,
    network_name: &str,
    uplink: bool,
) -> String {
    format!(
        "network-bridge:{}:{}:{}:{}",
        zone_uid.as_str(),
        network_uid.as_str(),
        network_name_token(network_name),
        if uplink { "uplink" } else { "lan" }
    )
}

/// Build a UID-bound Network firewall projection reference.
pub fn intent_id_network_projection_uids(
    zone_uid: &d2b_contracts_resource::v3::ResourceUid,
    network_uid: &d2b_contracts_resource::v3::ResourceUid,
    network_name: &str,
) -> String {
    format!(
        "network-firewall:{}:{}:{}",
        zone_uid.as_str(),
        network_uid.as_str(),
        network_name_token(network_name)
    )
}

/// Build a UID-bound Network ownership-marker reference.
pub fn intent_id_network_ownership_marker_uids(
    zone_uid: &d2b_contracts_resource::v3::ResourceUid,
    network_uid: &d2b_contracts_resource::v3::ResourceUid,
    network_name: &str,
) -> String {
    format!(
        "network-marker:{}:{}:{}",
        zone_uid.as_str(),
        network_uid.as_str(),
        network_name_token(network_name)
    )
}

/// Build a UID-bound Network route reference.
pub fn intent_id_network_route_uids(
    zone_uid: &d2b_contracts_resource::v3::ResourceUid,
    network_uid: &d2b_contracts_resource::v3::ResourceUid,
    network_name: &str,
    idx: usize,
) -> String {
    format!(
        "network-route:{}:{}:{}:{}",
        zone_uid.as_str(),
        network_uid.as_str(),
        network_name_token(network_name),
        idx
    )
}

/// Build the exact opaque TAP intent reference for one admitted provenance.
pub fn intent_id_network_tap(
    zone_uid: &d2b_contracts_resource::v3::ResourceUid,
    network_uid: &d2b_contracts_resource::v3::ResourceUid,
    attachment_uid: &d2b_contracts_resource::v3::ResourceUid,
    network_generation: d2b_contracts_resource::v3::ResourceGeneration,
    attachment_generation: d2b_contracts_resource::v3::ResourceGeneration,
    bundle_generation: &d2b_contracts_resource::v3::ResourceBundleGenerationId,
    role_id: &str,
    vm_id: &str,
) -> String {
    format!(
        "network-tap:{}",
        tap_identity_digest(
            zone_uid,
            network_uid,
            attachment_uid,
            network_generation,
            attachment_generation,
            bundle_generation,
            role_id,
            vm_id,
        )
    )
}

fn tap_identity_digest(
    zone_uid: &d2b_contracts_resource::v3::ResourceUid,
    network_uid: &d2b_contracts_resource::v3::ResourceUid,
    attachment_uid: &d2b_contracts_resource::v3::ResourceUid,
    network_generation: d2b_contracts_resource::v3::ResourceGeneration,
    attachment_generation: d2b_contracts_resource::v3::ResourceGeneration,
    bundle_generation: &d2b_contracts_resource::v3::ResourceBundleGenerationId,
    role_id: &str,
    vm_id: &str,
) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"d2b:v3:network-tap-identity\0");
    for value in [
        zone_uid.as_str(),
        network_uid.as_str(),
        attachment_uid.as_str(),
        role_id,
        vm_id,
    ] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    for value in [network_generation.get(), attachment_generation.get()] {
        hasher.update(value.to_be_bytes());
    }
    let bundle = bundle_generation.as_str();
    hasher.update((bundle.len() as u64).to_be_bytes());
    hasher.update(bundle.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Build a UID-bound Network sysctl reference.
pub fn intent_id_network_sysctl_uids(
    zone_uid: &d2b_contracts_resource::v3::ResourceUid,
    network_uid: &d2b_contracts_resource::v3::ResourceUid,
    network_name: &str,
    if_role: &str,
    key: &str,
) -> String {
    format!(
        "network-sysctl:{}:{}:{}:{}:{}",
        zone_uid.as_str(),
        network_uid.as_str(),
        network_name_token(network_name),
        if_role,
        key
    )
}

/// Build a UID-bound Network hosts reference.
pub fn intent_id_network_hosts_uids(
    zone_uid: &d2b_contracts_resource::v3::ResourceUid,
    network_uid: &d2b_contracts_resource::v3::ResourceUid,
    network_name: &str,
) -> String {
    format!(
        "network-hosts:{}:{}:{}",
        zone_uid.as_str(),
        network_uid.as_str(),
        network_name_token(network_name)
    )
}

/// Bound the human-readable Network lookup hint inside an opaque id.
pub fn network_name_token(network_name: &str) -> String {
    stable_digest(network_name)
        .strip_prefix("fnv1a64:")
        .unwrap_or_default()
        .to_owned()
}

pub fn intent_id_ownership_marker_env(env: &str) -> String {
    format!("ownership-marker:env:{env}")
}

pub fn intent_id_bridge_env(env: &str) -> String {
    format!("bridge:env:{env}")
}

pub fn intent_id_route_env(env: &str, idx: usize) -> String {
    format!("route:env:{env}:{idx}")
}

pub fn intent_id_sysctl(env: &str, if_name: &str, key: &str) -> String {
    format!("sysctl:env:{env}:if:{if_name}:{key}")
}

pub fn intent_id_hosts_host() -> String {
    "hosts:host".to_owned()
}

pub fn intent_id_nm_unmanaged_host() -> String {
    "nm-unmanaged:host".to_owned()
}

pub fn intent_id_usbip_firewall(env: &str, bus_id: &str) -> String {
    format!("usbip-fw:env:{env}:bus:{bus_id}")
}

pub fn intent_id_usbip_bind(env: &str, vm: &str, bus_id: &str) -> String {
    format!("usbip-bind:env:{env}:vm:{vm}:bus:{bus_id}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetworkIntentKind {
    Bridge,
    Firewall,
    Marker,
    Route,
    Sysctl,
    Hosts,
}

struct ParsedNetworkIntentRef {
    kind: NetworkIntentKind,
    zone_uid: d2b_contracts_resource::v3::ResourceUid,
    network_uid: d2b_contracts_resource::v3::ResourceUid,
    network_name: String,
    variant: Option<String>,
    index: Option<usize>,
    key: Option<String>,
}

fn parse_network_intent_ref(id: &str) -> Option<ParsedNetworkIntentRef> {
    let fields = id.split(':').collect::<Vec<_>>();
    let (kind, required_len) = match fields.first().copied()? {
        "network-bridge" => (NetworkIntentKind::Bridge, 5),
        "network-firewall" => (NetworkIntentKind::Firewall, 4),
        "network-marker" => (NetworkIntentKind::Marker, 4),
        "network-route" => (NetworkIntentKind::Route, 5),
        "network-sysctl" => (NetworkIntentKind::Sysctl, 6),
        "network-hosts" => (NetworkIntentKind::Hosts, 4),
        _ => return None,
    };
    if fields.len() != required_len
        || fields[1].is_empty()
        || fields[2].is_empty()
        || fields[3].is_empty()
    {
        return None;
    }
    let zone_uid = d2b_contracts_resource::v3::ResourceUid::parse(fields[1].to_owned()).ok()?;
    let network_uid = d2b_contracts_resource::v3::ResourceUid::parse(fields[2].to_owned()).ok()?;
    let network_name = fields[3].to_owned();
    if !network_name
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return None;
    }
    let (variant, index, key) = match kind {
        NetworkIntentKind::Bridge => (Some(fields[4].to_owned()), None, None),
        NetworkIntentKind::Route => (None, Some(fields[4].parse().ok()?), None),
        NetworkIntentKind::Sysctl => (Some(fields[4].to_owned()), None, Some(fields[5].to_owned())),
        NetworkIntentKind::Firewall | NetworkIntentKind::Marker | NetworkIntentKind::Hosts => {
            (None, None, None)
        }
    };
    Some(ParsedNetworkIntentRef {
        kind,
        zone_uid,
        network_uid,
        network_name,
        variant,
        index,
        key,
    })
}

fn network_scope(provenance: &NetworkProvenance) -> String {
    format!(
        "network:{}:{}",
        provenance.zone_uid().as_str(),
        provenance.network_uid().as_str()
    )
}

fn network_firewall_chain_name(network_uid: &d2b_contracts_resource::v3::ResourceUid) -> String {
    let compact = network_uid.as_str().replace('-', "");
    format!("forward-{}", &compact[..8])
}

pub fn intent_id_runner(zone: &ZoneId, vm: &str, role_id: &str) -> String {
    format!("runner:zone:{}:vm:{vm}:role:{role_id}", zone.as_str())
}

pub fn intent_id_legacy_runner(vm: &str, role_id: &str) -> String {
    format!("runner:vm:{vm}:role:{role_id}")
}

pub fn intent_id_socket(vm: &str, role_id: &str) -> String {
    format!("socket:vm:{vm}:role:{role_id}")
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

fn build_resource_network_intents(
    bundles: &BTreeMap<String, Vec<u8>>,
    include_fixture_network_intents: bool,
) -> (
    BTreeMap<String, ResolvedNftablesProjectionIntent>,
    BTreeMap<String, ResolvedOwnershipMarkerIntent>,
    BTreeMap<String, ResolvedBridgeIntent>,
    BTreeMap<String, ResolvedRouteIntent>,
    BTreeMap<String, ResolvedSysctlIntent>,
    BTreeMap<String, ResolvedHostsIntent>,
) {
    // Live bundle loading resolves Network rows only after d2bd supplies the
    // committed resource UID and generation. Test-only parsed fixtures may
    // carry a `networkUid` annotation for exercising the row builder.
    if !include_fixture_network_intents {
        return (
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
    }
    let mut nft_projections = BTreeMap::new();
    let mut markers = BTreeMap::new();
    let mut bridges = BTreeMap::new();
    let mut routes = BTreeMap::new();
    let mut sysctls = BTreeMap::new();
    let mut hosts = BTreeMap::new();

    for bytes in bundles.values() {
        let Ok(bundle) = ResourceBundle::from_json(bytes) else {
            continue;
        };
        for resource in &bundle.resources {
            if resource.resource_type().as_str() != "Network" {
                continue;
            }
            let Some(zone_uid) = bundle.zone_uid.clone() else {
                continue;
            };
            let Some(network_uid) = resource
                .metadata()
                .annotations()
                .get("networkUid")
                .and_then(|value| {
                    d2b_contracts_resource::v3::ResourceUid::parse(value.clone()).ok()
                })
            else {
                continue;
            };
            let name = resource.metadata().name().as_str();
            let mut spec_value =
                serde_json::to_value(resource.spec()).unwrap_or_else(|_| serde_json::json!({}));
            let Some(spec_object) = spec_value.as_object_mut() else {
                continue;
            };
            for field in ["providerRef", "updatePolicy", "provider"] {
                spec_object.remove(field);
            }
            let Ok(spec) = serde_json::from_value::<NetworkSpec>(spec_value) else {
                continue;
            };
            let Some(lan_bridge) =
                derive_network_ifname(&zone_uid, &network_uid, NetworkIfRole::LanBridge, None).ok()
            else {
                continue;
            };
            let Some(uplink_bridge) =
                derive_network_ifname(&zone_uid, &network_uid, NetworkIfRole::UplinkBridge, None)
                    .ok()
            else {
                continue;
            };
            let scope = format!("network:{}:{}", zone_uid.as_str(), network_uid.as_str());
            let marker = format!(
                "network:bundle:zone:{}:network:{}",
                zone_uid.as_str(),
                network_uid.as_str()
            );
            let marker_id = intent_id_network_ownership_marker_uids(&zone_uid, &network_uid, name);
            markers.insert(
                marker_id.clone(),
                ResolvedOwnershipMarkerIntent {
                    intent_id: marker_id.clone(),
                    marker: marker.clone(),
                    provenance: None,
                },
            );

            let bridge_id = intent_id_network_bridge_uids(&zone_uid, &network_uid, name, false);
            bridges.insert(
                bridge_id.clone(),
                ResolvedBridgeIntent {
                    intent_id: bridge_id,
                    scope_label: scope.clone(),
                    bridge_ifname: lan_bridge.clone(),
                    mtu: spec.mtu().unwrap_or(1500) as u16,
                    stp_disabled: true,
                    multicast_snooping_disabled: true,
                    ipv6_suppressed: true,
                    provenance: None,
                    ownership_marker: None,
                },
            );
            let uplink_bridge_id =
                intent_id_network_bridge_uids(&zone_uid, &network_uid, name, true);
            bridges.insert(
                uplink_bridge_id.clone(),
                ResolvedBridgeIntent {
                    intent_id: uplink_bridge_id,
                    scope_label: scope.clone(),
                    bridge_ifname: uplink_bridge.clone(),
                    mtu: spec.mtu().unwrap_or(1500) as u16,
                    stp_disabled: true,
                    multicast_snooping_disabled: true,
                    ipv6_suppressed: true,
                    provenance: None,
                    ownership_marker: None,
                },
            );

            let projection_id = intent_id_network_projection_uids(&zone_uid, &network_uid, name);
            let chain = network_firewall_chain_name(&network_uid);
            let script_body = format!(
                "table inet d2b {{\n  chain \"{chain}\" {{ comment \"d2b managed: {marker}\";\n    ct state established,related accept comment \"d2b managed: {marker}\";\n    iifname \"{}\" ct state new accept comment \"d2b managed: {marker}\";\n  }}\n}}\n",
                uplink_bridge.as_str()
            );
            nft_projections.insert(
                projection_id.clone(),
                ResolvedNftablesProjectionIntent {
                    intent_id: projection_id,
                    scope_label: scope.clone(),
                    desired_hash: stable_digest(&script_body),
                    script_body,
                    ownership_marker_intent_ref: marker_id,
                    provenance: None,
                },
            );

            let mut route_index = 0usize;
            let uplink_gateway = network_cidr_host_address(spec.uplink_cidr().as_str(), 2);
            for destination in spec.routing().host_blocklist() {
                let route_id =
                    intent_id_network_route_uids(&zone_uid, &network_uid, name, route_index);
                let route_spec = format!(
                    "{}{} dev {} table main",
                    destination.as_str(),
                    uplink_gateway
                        .as_deref()
                        .map(|gateway| format!(" via {gateway}"))
                        .unwrap_or_default(),
                    uplink_bridge.as_str()
                );
                routes.insert(
                    route_id.clone(),
                    ResolvedRouteIntent {
                        intent_id: route_id,
                        route_spec,
                        destination: destination.as_str().to_owned(),
                        via: uplink_gateway.clone(),
                        device: Some(uplink_bridge.as_str().to_owned()),
                        table: Some("main".to_owned()),
                        owned: true,
                        route_name: Some(derive_network_route_name(
                            &zone_uid,
                            &network_uid,
                            route_index,
                        )),
                        provenance: None,
                        ownership_marker: Some(format!("route:{marker}:{route_index}")),
                    },
                );
                route_index += 1;
            }
            if route_index == 0 {
                let route_id = intent_id_network_route_uids(&zone_uid, &network_uid, name, 0);
                routes.insert(
                    route_id.clone(),
                    ResolvedRouteIntent {
                        intent_id: route_id,
                        route_spec: format!(
                            "{}{} dev {} table main",
                            spec.lan_cidr().as_str(),
                            uplink_gateway
                                .as_deref()
                                .map(|gateway| format!(" via {gateway}"))
                                .unwrap_or_default(),
                            uplink_bridge.as_str()
                        ),
                        destination: spec.lan_cidr().as_str().to_owned(),
                        via: uplink_gateway,
                        device: Some(uplink_bridge.as_str().to_owned()),
                        table: Some("main".to_owned()),
                        owned: true,
                        route_name: Some(derive_network_route_name(&zone_uid, &network_uid, 0)),
                        provenance: None,
                        ownership_marker: Some(format!("route:{marker}:0")),
                    },
                );
            }

            for (if_name, role) in [(&lan_bridge, "lan"), (&uplink_bridge, "uplink")] {
                let key = "disable-ipv6";
                let id = intent_id_network_sysctl_uids(&zone_uid, &network_uid, name, role, key);
                sysctls.insert(
                    id.clone(),
                    ResolvedSysctlIntent {
                        intent_id: id,
                        key: format!("net.ipv6.conf.{}.disable_ipv6", if_name.as_str()),
                        value: "1".to_owned(),
                        provenance: None,
                        ownership_marker: None,
                    },
                );
                let key = "accept-ra";
                let id = intent_id_network_sysctl_uids(&zone_uid, &network_uid, name, role, key);
                sysctls.insert(
                    id.clone(),
                    ResolvedSysctlIntent {
                        intent_id: id,
                        key: format!("net.ipv6.conf.{}.accept_ra", if_name.as_str()),
                        value: "0".to_owned(),
                        provenance: None,
                        ownership_marker: None,
                    },
                );
                let key = "autoconf";
                let id = intent_id_network_sysctl_uids(&zone_uid, &network_uid, name, role, key);
                sysctls.insert(
                    id.clone(),
                    ResolvedSysctlIntent {
                        intent_id: id,
                        key: format!("net.ipv6.conf.{}.autoconf", if_name.as_str()),
                        value: "0".to_owned(),
                        provenance: None,
                        ownership_marker: None,
                    },
                );
            }

            let hosts_id = intent_id_network_hosts_uids(&zone_uid, &network_uid, name);
            hosts.insert(
                hosts_id.clone(),
                ResolvedHostsIntent {
                    intent_id: hosts_id,
                    path: PathBuf::from("/etc/hosts"),
                    managed_block: format!(
                        "# d2b-managed begin\n# d2b managed: {marker}\n# network {name} lan {} uplink {}\n# d2b-managed end\n",
                        spec.lan_cidr().as_str(),
                        spec.uplink_cidr().as_str()
                    ),
                    start_marker: "# d2b-managed begin".to_owned(),
                    end_marker: "# d2b-managed end".to_owned(),
                    mode: 0o644,
                    provenance: None,
                    ownership_marker: None,
                },
            );
        }
    }

    (nft_projections, markers, bridges, routes, sysctls, hosts)
}

// ---------------------------------------------------------------
// Intent table builders.
// ---------------------------------------------------------------

fn build_nft_intents(host: &HostJson) -> BTreeMap<String, ResolvedNftIntent> {
    let mut out = BTreeMap::new();
    let host_script = render_host_nft_script(host);
    let host_hash = stable_digest(&host_script);
    out.insert(
        intent_id_nft_host(),
        ResolvedNftIntent {
            intent_id: intent_id_nft_host(),
            scope_label: "host".to_owned(),
            script_body: host_script,
            desired_hash: host_hash,
            ownership_id: host.nftables.ownership_id.clone(),
        },
    );
    for env in &host.environments {
        let script = render_env_nft_subset(host, env);
        let digest = stable_digest(&script);
        out.insert(
            intent_id_nft_env(&env.env),
            ResolvedNftIntent {
                intent_id: intent_id_nft_env(&env.env),
                scope_label: format!("env:{}", env.env),
                script_body: script,
                desired_hash: digest,
                ownership_id: host.nftables.ownership_id.clone(),
            },
        );
    }
    out
}

fn build_host_nft_intents(host: &HostJson) -> BTreeMap<String, ResolvedNftIntent> {
    let script = render_host_nft_script(host);
    let intent_id = intent_id_nft_host();
    BTreeMap::from([(
        intent_id.clone(),
        ResolvedNftIntent {
            intent_id,
            scope_label: "host".to_owned(),
            desired_hash: stable_digest(&script),
            ownership_id: host.nftables.ownership_id.clone(),
            script_body: script,
        },
    )])
}

fn build_bridge_intents(host: &HostJson) -> BTreeMap<String, ResolvedBridgeIntent> {
    host.environments
        .iter()
        .map(|env| {
            let intent_id = intent_id_bridge_env(&env.env);
            let bridge_ifname =
                resolved_ifname_for(host, &env.env, None, crate::host::TapRole::NetVmLan)
                    .and_then(|value| IfName::new(value).ok())
                    .unwrap_or_else(|| env.bridge.clone());
            (
                intent_id.clone(),
                ResolvedBridgeIntent {
                    intent_id,
                    scope_label: format!("env:{}", env.env),
                    bridge_ifname,
                    mtu: env.mtu,
                    stp_disabled: true,
                    multicast_snooping_disabled: true,
                    ipv6_suppressed: true,
                    provenance: None,
                    ownership_marker: None,
                },
            )
        })
        .collect()
}

fn build_ownership_marker_intents(
    host: &HostJson,
) -> BTreeMap<String, ResolvedOwnershipMarkerIntent> {
    host.environments
        .iter()
        .map(|env| {
            let intent_id = intent_id_ownership_marker_env(&env.env);
            (
                intent_id.clone(),
                ResolvedOwnershipMarkerIntent {
                    intent_id,
                    marker: format!("{}:env:{}", host.nftables.ownership_id, env.env),
                    provenance: None,
                },
            )
        })
        .collect()
}

fn build_nft_projection_intents(
    host: &HostJson,
) -> BTreeMap<String, ResolvedNftablesProjectionIntent> {
    host.environments
        .iter()
        .map(|env| {
            let intent_id = intent_id_nft_projection_env(&env.env);
            let script_body = render_env_nft_subset(host, env);
            (
                intent_id.clone(),
                ResolvedNftablesProjectionIntent {
                    intent_id,
                    scope_label: format!("env:{}", env.env),
                    desired_hash: stable_digest(&script_body),
                    script_body,
                    ownership_marker_intent_ref: intent_id_ownership_marker_env(&env.env),
                    provenance: None,
                },
            )
        })
        .collect()
}

fn build_installed_generation_identity(
    bundle: &Bundle,
) -> Option<ResolvedInstalledGenerationIdentity> {
    let generation_id = bundle.bundle_hash.as_deref()?;
    let valid = generation_id.len() == 71
        && generation_id.starts_with("sha256:")
        && generation_id[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
    valid.then(|| ResolvedInstalledGenerationIdentity {
        generation_id: generation_id.to_owned(),
    })
}

fn render_host_nft_script(host: &HostJson) -> String {
    let mut buf = String::new();
    let model = &host.nftables;
    let comment = if model.ownership_id.is_empty() {
        String::new()
    } else {
        format!(" comment \"d2b managed: {}\"", model.ownership_id)
    };
    buf.push_str(&format!(
        "table {} {} {{\n",
        model.family.to_lowercase(),
        model.table
    ));
    for chain in &model.chains {
        buf.push_str(&format!("  chain {} {{\n", chain.name));
        if let (Some(hook), Some(priority)) = (chain.hook.as_ref(), chain.priority) {
            buf.push_str(&format!(
                "    type filter hook {hook} priority {priority};\n"
            ));
        }
        if let Some(policy) = chain.policy.as_ref() {
            buf.push_str(&format!("    policy {policy};\n"));
        }
        if !chain.purpose.is_empty() {
            buf.push_str(&format!("    # purpose: {}\n", chain.purpose));
        }
        if !comment.is_empty() {
            buf.push_str(&format!(
                "    ct state established,related accept{comment};\n"
            ));
        }
        // Per-env forward acceptance: workload traffic exits each env
        // via its `br-<env>-up` bridge (the host-side end of the net-VM
        // uplink point-to-point). The forward chain default-drops, so
        // without an explicit accept the SYN never reaches eno1. The
        // existing nixos-filter-forward chain at priority 0 already
        // performs the same allow-by-iifname check; we mirror it here
        // so the d2b chain at priority -5 doesn't fail-closed
        // before the nixos chain runs.
        if chain.hook.as_deref() == Some("forward") {
            for env in &host.environments {
                buf.push_str(&format!(
                    "    iifname \"br-{}-up\" ct state new accept{comment};\n",
                    env.env
                ));
            }
        }
        if chain.hook.as_deref() == Some("input") {
            let usbip_backend_ports: Vec<u16> = host
                .environments
                .iter()
                .filter_map(|env| {
                    env.usbip_backend_port
                        .filter(|_| !env.usbip_busid_locks.is_empty())
                })
                .collect();
            if !usbip_backend_ports.is_empty() {
                let backend_ports = usbip_backend_ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                buf.push_str(&format!(
                    "    iifname != \"lo\" meta l4proto tcp tcp dport {{ {backend_ports} }} drop{comment};\n"
                ));
                buf.push_str(&format!(
                    "    iifname != \"lo\" meta l4proto tcp tcp dport 3240 drop{comment};\n"
                ));
            }
        }
        buf.push_str("  }\n");
    }
    buf.push_str("}\n");
    buf
}

fn render_env_nft_subset(host: &HostJson, env: &NetEnv) -> String {
    let marker = format!(
        "d2b managed: {}:env:{}",
        host.nftables.ownership_id, env.env
    );
    let chain = format!("forward-{}", env.env);
    let bridge_ifname = format!("br-{}-up", env.env);
    let mut buf = String::new();
    buf.push_str(&format!(
        "table inet d2b {{\n  chain \"{chain}\" {{ comment \"{marker}\";\n"
    ));
    buf.push_str(&format!(
        "    ct state established,related accept comment \"{marker}\";\n",
    ));
    buf.push_str(&format!(
        "    iifname \"{}\" ct state new accept comment \"{}\";\n",
        bridge_ifname, marker
    ));
    buf.push_str("  }\n}\n");
    buf
}

fn build_route_intents(host: &HostJson) -> BTreeMap<String, ResolvedRouteIntent> {
    let mut out = BTreeMap::new();
    for env in &host.environments {
        let bridge_ifname =
            user_visible_ifname_for(host, &env.env, None, crate::host::TapRole::Uplink)
                .unwrap_or_else(|| format!("br-{}-up", env.env));
        // Each env gets one synthetic default route per uplink in its
        // forward blocklist (placeholder until real route intents are
        // wired). The route_spec is `<dest> dev <bridge>` so the
        // broker's `ip route add` call is well-formed even without
        // the gateway.
        for (idx, blocked) in env.net_vm_forward_blocklist.iter().enumerate() {
            let intent_id = intent_id_route_env(&env.env, idx);
            let route_spec = format!("{blocked} dev {bridge_ifname}");
            out.insert(
                intent_id.clone(),
                ResolvedRouteIntent {
                    intent_id,
                    route_spec,
                    destination: blocked.clone(),
                    via: None,
                    device: Some(bridge_ifname.clone()),
                    table: None,
                    owned: true,
                    route_name: None,
                    provenance: None,
                    ownership_marker: None,
                },
            );
        }
    }
    out
}

fn build_sysctl_intents(host: &HostJson) -> BTreeMap<String, ResolvedSysctlIntent> {
    let mut out = BTreeMap::new();
    for env in &host.environments {
        for entry in &env.ipv6_sysctls {
            insert_sysctl_pair(
                &mut out,
                &env.env,
                &entry.if_name,
                "disable_ipv6",
                entry.disable_ipv6,
                Ipv6SysctlKey::DisableIpv6,
            );
            insert_sysctl_pair(
                &mut out,
                &env.env,
                &entry.if_name,
                "accept_ra",
                entry.accept_ra,
                Ipv6SysctlKey::AcceptRa,
            );
            insert_sysctl_pair(
                &mut out,
                &env.env,
                &entry.if_name,
                "autoconf",
                entry.autoconf,
                Ipv6SysctlKey::Autoconf,
            );
            insert_sysctl_pair(
                &mut out,
                &env.env,
                &entry.if_name,
                "addr_gen_mode",
                entry.addr_gen_mode,
                Ipv6SysctlKey::AddrGenMode,
            );
            insert_sysctl_pair(
                &mut out,
                &env.env,
                &entry.if_name,
                "arp_ignore",
                entry.arp_ignore,
                Ipv6SysctlKey::ArpIgnore,
            );
        }
        insert_sysctl_pair(
            &mut out,
            &env.env,
            &env.bridge,
            "bridge-nf-call-arptables",
            0,
            Ipv6SysctlKey::BridgeNfCallArptables,
        );
        insert_sysctl_pair(
            &mut out,
            &env.env,
            &env.bridge,
            "bridge-nf-call-iptables",
            0,
            Ipv6SysctlKey::BridgeNfCallIptables,
        );
        insert_sysctl_pair(
            &mut out,
            &env.env,
            &env.bridge,
            "bridge-nf-call-ip6tables",
            0,
            Ipv6SysctlKey::BridgeNfCallIp6tables,
        );
    }
    out
}

enum Ipv6SysctlKey {
    DisableIpv6,
    AcceptRa,
    Autoconf,
    AddrGenMode,
    ArpIgnore,
    BridgeNfCallArptables,
    BridgeNfCallIptables,
    BridgeNfCallIp6tables,
}

impl Ipv6SysctlKey {
    fn dotted_path(&self, if_name: &str) -> String {
        match self {
            Self::DisableIpv6 => format!("net.ipv6.conf.{if_name}.disable_ipv6"),
            Self::AcceptRa => format!("net.ipv6.conf.{if_name}.accept_ra"),
            Self::Autoconf => format!("net.ipv6.conf.{if_name}.autoconf"),
            Self::AddrGenMode => format!("net.ipv6.conf.{if_name}.addr_gen_mode"),
            Self::ArpIgnore => format!("net.ipv4.conf.{if_name}.arp_ignore"),
            Self::BridgeNfCallArptables => "net.bridge.bridge-nf-call-arptables".to_owned(),
            Self::BridgeNfCallIptables => "net.bridge.bridge-nf-call-iptables".to_owned(),
            Self::BridgeNfCallIp6tables => "net.bridge.bridge-nf-call-ip6tables".to_owned(),
        }
    }
}

fn insert_sysctl_pair(
    out: &mut BTreeMap<String, ResolvedSysctlIntent>,
    env: &str,
    if_name: &IfName,
    short_key: &str,
    value: u8,
    full_key: Ipv6SysctlKey,
) {
    let intent_id = intent_id_sysctl(env, if_name.as_str(), short_key);
    out.insert(
        intent_id.clone(),
        ResolvedSysctlIntent {
            intent_id,
            key: full_key.dotted_path(if_name.as_str()),
            value: value.to_string(),
            provenance: None,
            ownership_marker: None,
        },
    );
}

fn build_hosts_intents(host: &HostJson) -> BTreeMap<String, ResolvedHostsIntent> {
    let mut out = BTreeMap::new();
    let block = render_hosts_managed_block(host);
    out.insert(
        intent_id_hosts_host(),
        ResolvedHostsIntent {
            intent_id: intent_id_hosts_host(),
            path: PathBuf::from("/etc/hosts"),
            managed_block: block,
            start_marker: host.hosts_file.start_marker.clone(),
            end_marker: host.hosts_file.end_marker.clone(),
            mode: 0o644,
            provenance: None,
            ownership_marker: None,
        },
    );
    out
}

fn render_hosts_managed_block(host: &HostJson) -> String {
    let mut buf = String::new();
    buf.push_str(&host.hosts_file.start_marker);
    buf.push('\n');
    buf.push_str("# managed by d2b broker - do not edit by hand\n");
    for env in &host.environments {
        buf.push_str(&format!(
            "# env {} bridge {} mtu {}\n",
            env.env,
            env.bridge.as_str(),
            env.mtu
        ));
    }
    buf.push_str(&host.hosts_file.end_marker);
    buf.push('\n');
    buf
}

fn build_nm_unmanaged_intents(host: &HostJson) -> BTreeMap<String, ResolvedNmUnmanagedIntent> {
    let mut out = BTreeMap::new();
    let mut contents = String::from("# d2b-managed begin\n");
    contents.push_str("# Generated by d2b-broker; do not edit by hand.\n");
    contents.push_str("[keyfile]\n");
    contents.push_str("unmanaged-devices=");
    contents.push_str(&host.network_manager.match_criteria.join(";"));
    contents.push('\n');
    contents.push_str("# marker-id=nm-unmanaged:host\n");
    contents.push_str("# d2b-managed end\n");
    let mode = parse_octal_mode(&host.network_manager.ownership.mode).unwrap_or(0o644);
    out.insert(
        intent_id_nm_unmanaged_host(),
        ResolvedNmUnmanagedIntent {
            intent_id: intent_id_nm_unmanaged_host(),
            file_path: PathBuf::from(&host.network_manager.file_path),
            contents,
            mode,
            owner: host.network_manager.ownership.owner.clone(),
            group: host.network_manager.ownership.group.clone(),
            reload_behavior: host.network_manager.reload_behavior.clone(),
        },
    );
    out
}

fn parse_octal_mode(s: &str) -> Option<u32> {
    let trimmed = s.trim_start_matches('0');
    if trimmed.is_empty() {
        return Some(0);
    }
    u32::from_str_radix(trimmed, 8).ok()
}

fn build_usbip_firewall_intents(host: &HostJson) -> BTreeMap<String, ResolvedUsbipFirewallIntent> {
    let mut out = BTreeMap::new();
    for env in &host.environments {
        let bridge_ifname =
            user_visible_ifname_for(host, &env.env, None, crate::host::TapRole::Uplink)
                .unwrap_or_else(|| format!("br-{}-up", env.env));
        let Some(rule_body) = scoped_usbip_proxy_rule_body(env, &bridge_ifname) else {
            continue;
        };
        for lock in &env.usbip_busid_locks {
            for bus_id in synthesize_bus_ids(lock) {
                let intent_id = intent_id_usbip_firewall(&env.env, &bus_id);
                let desired_hash = stable_digest(&rule_body);
                out.insert(
                    intent_id.clone(),
                    ResolvedUsbipFirewallIntent {
                        intent_id,
                        bus_id,
                        env: env.env.clone(),
                        nft_rule_body: rule_body.clone(),
                        desired_hash,
                    },
                );
            }
        }
    }
    out
}

fn scoped_usbip_proxy_rule_body(env: &NetEnv, bridge_ifname: &str) -> Option<String> {
    let bridge_ifname = safe_ifname_literal(bridge_ifname)?;
    let host_uplink_ip = safe_ipv4_literal(env.host_uplink_ip.as_deref()?)?;
    let net_uplink_ip = safe_ipv4_literal(env.net_uplink_ip.as_deref()?)?;
    let uplink_flags = env
        .bridge_port_flags
        .iter()
        .find(|flags| flags.role == crate::host::TapRole::Uplink)?;
    if !uplink_flags.isolated
        || !uplink_flags.neigh_suppress
        || uplink_flags.resolved_learning()
        || uplink_flags.resolved_unicast_flood()
    {
        return None;
    }

    Some(format!(
        "iifname \"{bridge_ifname}\" ip saddr {net_uplink_ip} ip daddr {host_uplink_ip} ip protocol tcp tcp dport 3240 accept"
    ))
}

fn safe_ifname_literal(value: &str) -> Option<&str> {
    IfName::new(value).ok()?;
    Some(value)
}

fn safe_ipv4_literal(value: &str) -> Option<String> {
    match value.parse::<IpAddr>().ok()? {
        IpAddr::V4(addr)
            if !addr.is_unspecified() && !addr.is_loopback() && !addr.is_multicast() =>
        {
            Some(addr.to_string())
        }
        _ => None,
    }
}

fn build_usbip_bind_intents(host: &HostJson) -> BTreeMap<String, ResolvedUsbipBindIntent> {
    let mut out = BTreeMap::new();
    for env in &host.environments {
        for lock in &env.usbip_busid_locks {
            for bus_id in synthesize_bus_ids(lock) {
                let intent_id = intent_id_usbip_bind(&env.env, &lock.vm, &bus_id);
                let lock_path = PathBuf::from(format!("/run/d2b/locks/usbip/{bus_id}"));
                out.insert(
                    intent_id.clone(),
                    ResolvedUsbipBindIntent {
                        intent_id,
                        bus_id,
                        vm_name: lock.vm.clone(),
                        env: env.env.clone(),
                        lock_path,
                        vendor_product_allowlist: lock.vendor_product_allowlist.clone(),
                        dynamic_bus_id: false,
                    },
                );
            }
        }
    }
    out
}

/// Prefer the real busid list when the Nix emitter provides it.
/// Fall back to a single placeholder for older v0.4 host.json
/// fixtures that predate the additive `busIds` field.
fn synthesize_bus_ids(lock: &UsbipBusidLock) -> Vec<String> {
    if !lock.bus_ids.is_empty() {
        return lock.bus_ids.clone();
    }
    // Fallback for the bash-CLI v0.4 fixture path where the Nix
    // emitter hasn't been extended yet. The daemon dispatch
    // surface returns BundleIntentMissing if the operator asks
    // for a real bus_id that isn't in the bundle.
    vec!["pending".to_owned()]
}

fn build_runner_intents(processes: &ProcessesJson) -> BTreeMap<String, ResolvedRunnerIntent> {
    let mut out = BTreeMap::new();
    for dag in &processes.vms {
        for node in &dag.nodes {
            let Some(resolved) = ResolvedRunnerIntent::from_process_node(&dag.vm, node) else {
                continue;
            };
            out.insert(resolved.intent_id.clone(), resolved);
        }
    }
    out
}

fn build_provider_controller_intents(
    templates: &[ProcessTemplateBinding],
) -> BTreeMap<String, ResolvedRunnerIntent> {
    let mut out = BTreeMap::new();
    for binding in templates {
        let vm_name = binding.execution_ref().name().as_str().to_owned();
        let role_id = binding.process_ref().name().as_str().to_owned();
        let cgroup_subtree = format!("d2b.slice/{vm_name}/{role_id}");
        let profile_id = binding.template().as_str().to_owned();
        let principal = format!(
            "{}:{}:{}",
            binding.owner_ref().to_canonical_string(),
            binding.process_ref().to_canonical_string(),
            binding.execution_ref().to_canonical_string()
        );
        let profile_hash = sha2::Sha256::digest(principal.as_bytes());
        let principal_id = 50_000_u32.saturating_add(
            u32::from_be_bytes(
                profile_hash[..4]
                    .try_into()
                    .expect("SHA-256 always has four-byte prefixes"),
            ) & 0x00ff_ffff,
        );
        let intent = ResolvedRunnerIntent {
            intent_id: intent_id_legacy_runner(&vm_name, &role_id),
            vm_name,
            execution_ref: binding.execution_ref().to_canonical_string(),
            owner_ref: Some(binding.owner_ref().to_canonical_string()),
            execution_domain: ProcessExecutionDomain::System,
            user_ref: None,
            role_id,
            role: ProcessRole::ProviderController,
            binary_path: PathBuf::from(binding.binary_path()),
            argv: vec![binding.binary_ref().as_str().to_owned()],
            env: Vec::new(),
            uid: principal_id,
            gid: principal_id,
            supplementary_groups: Vec::new(),
            capabilities: Vec::new(),
            namespaces: NamespaceSet {
                mount: false,
                pid: false,
                net: false,
                ipc: false,
                uts: false,
                user: false,
            },
            seccomp_policy_ref: Some("w1-provider-controller".to_owned()),
            mount_policy: MountPolicy {
                read_only_paths: vec!["/nix/store".to_owned()],
                writable_paths: Vec::new(),
                nix_store_read_only: true,
                hide_device_nodes_by_default: true,
                device_binds: Vec::new(),
                bind_mounts: Vec::new(),
            },
            cgroup_placement: CgroupPlacement {
                subtree: cgroup_subtree,
                controllers: vec!["cpu".to_owned(), "memory".to_owned(), "pids".to_owned()],
                delegated: false,
            },
            root_carve_out: false,
            profile_id,
            user_namespace: None,
            umask: Some(0o022),
        };
        out.insert(intent.intent_id.clone(), intent);
    }
    out
}

fn runner_role_name(role: &ProcessRole) -> Option<&'static str> {
    // Provider controller intents are committed Provider metadata, not
    // processes.json runner entries.
    match role {
        ProcessRole::HostReconcile
        | ProcessRole::ProviderController
        | ProcessRole::StoreVirtiofsPreflight
        | ProcessRole::ComponentSessionHealth
        | ProcessRole::SecurityKeyFrontend => None,
        ProcessRole::SwtpmPreStartFlush => Some("swtpm-flush"),
        ProcessRole::Swtpm => Some("swtpm"),
        ProcessRole::Virtiofsd => Some("virtiofsd"),
        ProcessRole::Video => Some("video"),
        ProcessRole::Gpu => Some("gpu"),
        ProcessRole::GpuRenderNode => Some("gpu-render-node"),
        ProcessRole::Audio => Some("audio"),
        ProcessRole::CloudHypervisorRunner => Some("cloud-hypervisor"),
        ProcessRole::QemuMediaRunner => Some("qemu-media"),
        ProcessRole::ActivationNixosRunner => Some("activation-nixos-runner"),
        ProcessRole::VsockRelay => Some("vsock-relay"),
        ProcessRole::OtelHostBridge => Some("otel-host-bridge"),
        ProcessRole::Usbip => Some("usbip"),
        ProcessRole::WaylandProxy => Some("wayland-proxy"),
    }
}

fn runner_template_name(role: &ProcessRole) -> Option<&'static str> {
    runner_role_name(role)
}

fn process_template_name_matches(intent: &ResolvedRunnerIntent, template: &str) -> bool {
    if intent.role == ProcessRole::CloudHypervisorRunner {
        return template == "cloud-hypervisor-runner"
            && cloud_hypervisor_intent_is_complete(intent);
    }
    if intent.role == ProcessRole::WaylandProxy {
        return match template {
            "wayland-proxy-worker" => intent
                .execution_ref
                .split_once('/')
                .is_some_and(|(kind, _)| kind == "Host"),
            "wayland-frontend-worker" => intent
                .execution_ref
                .split_once('/')
                .is_some_and(|(kind, _)| kind == "Guest"),
            _ => false,
        };
    }
    false
}

fn guest_vmm_template_matches(intent: &ResolvedRunnerIntent, template: &str) -> bool {
    intent.role_id == template
        || intent.profile_id == template
        || process_template_name_matches(intent, template)
}

fn cloud_hypervisor_intent_is_complete(intent: &ResolvedRunnerIntent) -> bool {
    intent.role == ProcessRole::CloudHypervisorRunner
        && cloud_hypervisor_intent_is_complete_values(&intent.binary_path, &intent.argv)
}

fn is_placeholder_runner_spec(binary_path: &str, argv: &[String], role_name: &str) -> bool {
    binary_path == format!("/run/current-system/sw/bin/{role_name}")
        && argv.len() == 1
        && argv[0] == role_name
}

fn legacy_runner_spec(vm_name: &str, role: &ProcessRole) -> Option<(String, Vec<String>)> {
    let (binary_name, arg0) = match role {
        ProcessRole::SwtpmPreStartFlush => ("bash", format!("d2b-swtpm-flush@{vm_name}")),
        ProcessRole::Swtpm => ("swtpm", format!("microvm-swtpm@{vm_name}")),
        ProcessRole::Virtiofsd => ("virtiofsd", format!("microvm-virtiofsd@{vm_name}")),
        // Video must always carry the patched crosvm video-decoder binary
        // and closed argv from processes.json. Never fall back to stock crosvm.
        ProcessRole::Video => return None,
        ProcessRole::Gpu => ("crosvm", format!("d2b-{vm_name}-gpu")),
        ProcessRole::GpuRenderNode => ("crosvm", format!("d2b-{vm_name}-gpu-render-node")),
        ProcessRole::Audio => ("vhost-device-sound", format!("d2b-{vm_name}-snd")),
        ProcessRole::CloudHypervisorRunner => ("cloud-hypervisor", format!("microvm@{vm_name}")),
        // QEMU media runners must carry the closed scaffold argv from
        // processes.json. There is no Cloud Hypervisor-compatible legacy
        // fallback for this runtime kind.
        ProcessRole::QemuMediaRunner => return None,
        // Activation runners are Guest-local and have no host-side legacy
        // fallback. Their executable and argv must be present in the
        // trusted per-Guest process DAG.
        ProcessRole::ActivationNixosRunner => return None,
        ProcessRole::VsockRelay => ("socat", format!("d2b-otel-relay@{vm_name}")),
        // OtelHostBridge must always carry the closed argv from
        // processes.json; it has no legacy singleton fallback.
        ProcessRole::OtelHostBridge => return None,
        // USBIP proxy runners must bind their own listen socket in the
        // daemon-owned SpawnRunner path. The retired socket-activated
        // systemd-socket-proxyd shape is not a safe legacy fallback.
        ProcessRole::Usbip => return None,
        // WaylandProxy must always carry the d2b-wayland-proxy binary
        // and closed argv from processes.json. No legacy fallback.
        ProcessRole::WaylandProxy => return None,
        ProcessRole::ProviderController
        | ProcessRole::HostReconcile
        | ProcessRole::StoreVirtiofsPreflight
        | ProcessRole::ComponentSessionHealth
        | ProcessRole::SecurityKeyFrontend => return None,
    };
    Some((
        format!("/run/current-system/sw/bin/{binary_name}"),
        vec![arg0],
    ))
}

#[cfg(test)]
fn resolve_runner_node(dag: &VmProcessDag, node: &ProcessNode) -> Option<ResolvedRunnerIntent> {
    ResolvedRunnerIntent::from_process_node(&dag.vm, node)
}

fn role_tag_for(role: &crate::host::TapRole) -> String {
    match role {
        crate::host::TapRole::NetVmLan => "nvl".to_owned(),
        crate::host::TapRole::WorkloadLan => "wkl".to_owned(),
        crate::host::TapRole::Uplink => "upl".to_owned(),
    }
}

fn resolved_ifname_for(
    host: &HostJson,
    env: &str,
    vm: Option<&str>,
    role: crate::host::TapRole,
) -> Option<String> {
    host.if_name_mappings
        .iter()
        .find(|mapping| mapping.env == env && mapping.vm.as_deref() == vm && mapping.role == role)
        .map(|mapping| mapping.derived_ifname.as_str().to_owned())
}

fn user_visible_ifname_for(
    host: &HostJson,
    env: &str,
    vm: Option<&str>,
    role: crate::host::TapRole,
) -> Option<String> {
    host.if_name_mappings
        .iter()
        .find(|mapping| mapping.env == env && mapping.vm.as_deref() == vm && mapping.role == role)
        .map(|mapping| mapping.user_visible_name.clone())
}

fn build_socket_intents(processes: &ProcessesJson) -> BTreeMap<String, ResolvedSocketIntent> {
    let mut out = BTreeMap::new();
    for dag in &processes.vms {
        for node in &dag.nodes {
            let intent_id = intent_id_socket(&dag.vm, &node.id.0);
            let socket_path = PathBuf::from(format!("/run/d2b/vms/{}/{}.sock", dag.vm, node.id.0));
            out.insert(
                intent_id.clone(),
                ResolvedSocketIntent {
                    intent_id,
                    vm_name: dag.vm.clone(),
                    role_id: node.id.0.clone(),
                    socket_path,
                    mode: 0o660,
                    owner_uid: node.profile.uid,
                    group_gid: node.profile.gid,
                },
            );
        }
    }
    out
}

fn build_installer_intents(bundle: &Bundle) -> BTreeMap<String, ResolvedInstallerIntent> {
    let mut out = BTreeMap::new();
    let bundle_path = PathBuf::from("/var/lib/d2b/current-bundle/manifest.json");
    let artifacts = vec![
        InstallerArtifact {
            path: PathBuf::from("/etc/systemd/system/d2bd.service"),
            mode: 0o644,
            purpose: "d2bd systemd unit (non-NixOS host)".to_owned(),
        },
        InstallerArtifact {
            path: PathBuf::from("/etc/d2b/daemon-config.json"),
            mode: 0o640,
            purpose: "daemon configuration file consumed by d2bd".to_owned(),
        },
        InstallerArtifact {
            path: PathBuf::from(&bundle.public_manifest_path),
            mode: 0o644,
            purpose: "public vms.json manifest (bundle entry point)".to_owned(),
        },
    ];
    out.insert(
        intent_id_installer_host(),
        ResolvedInstallerIntent {
            intent_id: intent_id_installer_host(),
            unit_path: PathBuf::from("/etc/systemd/system/d2bd.service"),
            service_name: "d2bd.service".to_owned(),
            daemon_config_path: PathBuf::from("/etc/d2b/daemon-config.json"),
            bundle_path,
            artifacts,
        },
    );
    out
}

fn build_migrate_intents(processes: &ProcessesJson) -> BTreeMap<String, ResolvedMigrateIntent> {
    let mut out = BTreeMap::new();
    let vms: Vec<String> = processes
        .vms
        .iter()
        .filter(|dag| !is_per_env_usbipd_scope(&dag.vm))
        .map(|dag| dag.vm.clone())
        .collect();
    let notes = vec![
        "migrate plan synthesised from processes.json vm list".to_owned(),
        format!("{} VM(s) eligible for daemon-owned migration", vms.len()),
        "Per-VM systemd unit `microvm@<vm>` will be stopped and replaced by the daemon supervisor's pidfd table entry".to_owned(),
    ];
    out.insert(
        intent_id_migrate_host(),
        ResolvedMigrateIntent {
            intent_id: intent_id_migrate_host(),
            vms,
            notes,
        },
    );
    out
}

fn is_per_env_usbipd_scope(vm: &str) -> bool {
    vm.starts_with("sys-") && vm.ends_with("-usbipd")
}

fn build_activation_intents(
    closures: &[ClosureMetadata],
    manifest: &ManifestV04,
) -> BTreeMap<String, ResolvedActivationIntent> {
    let mut out = BTreeMap::new();
    for closure in closures {
        if !manifest.vms.contains_key(&closure.vm) {
            continue;
        }
        let intent_id = intent_id_activation(&closure.vm);
        out.insert(
            intent_id.clone(),
            ResolvedActivationIntent {
                intent_id,
                vm: closure.vm.clone(),
                target_generation_path: PathBuf::from(&closure.toplevel),
                generation_number: closure.generation.host_generation,
            },
        );
    }
    out
}

fn build_store_view_intents(
    closures: &[ClosureMetadata],
    manifest: &ManifestV04,
) -> BTreeMap<String, ResolvedStoreViewIntent> {
    let mut out = BTreeMap::new();
    for closure in closures {
        let Some(vm) = manifest.vms.get(&closure.vm) else {
            continue;
        };
        let Some(generation) = closure.generation.host_generation else {
            continue;
        };
        let Some(target_name) = Path::new(&closure.toplevel).file_name() else {
            continue;
        };
        let hardlink_farm_path = PathBuf::from(&vm.state_dir).join("store-view");
        let live_view_path = hardlink_farm_path.join("live");
        let target_view_path = live_view_path.join(target_name);
        let mut closure_paths: Vec<PathBuf> =
            closure.closure_paths.iter().map(PathBuf::from).collect();
        let toplevel_path = PathBuf::from(&closure.toplevel);
        if !closure_paths.iter().any(|path| path == &toplevel_path) {
            closure_paths.push(toplevel_path);
        }
        let intent_id = intent_id_legacy_store_view(&closure.vm);
        out.insert(
            intent_id.clone(),
            ResolvedStoreViewIntent {
                intent_id,
                vm: closure.vm.clone(),
                generation,
                hardlink_farm_path,
                target_view_path,
                closure_paths,
                db_dump_path: PathBuf::from(&closure.db_dump_path),
            },
        );
    }
    out
}

fn build_gc_intents(closures: &[ClosureMetadata]) -> BTreeMap<String, ResolvedGcIntent> {
    let mut retained = BTreeMap::<String, PathBuf>::new();
    for closure in closures {
        for store_path in &closure.closure_paths {
            retained
                .entry(store_path.clone())
                .or_insert_with(|| PathBuf::from(store_path));
        }
        retained
            .entry(closure.toplevel.clone())
            .or_insert_with(|| PathBuf::from(&closure.toplevel));
    }
    let mut out = BTreeMap::new();
    out.insert(
        intent_id_gc_host(),
        ResolvedGcIntent {
            intent_id: intent_id_gc_host(),
            retained_store_paths: retained.into_values().collect(),
        },
    );
    out
}

fn build_keys_rotate_intents(
    bundle: &Bundle,
    manifest: &ManifestV04,
) -> BTreeMap<String, ResolvedKeysRotateIntent> {
    let mut out = BTreeMap::new();
    for vm in manifest.vms.keys() {
        let intent_id = intent_id_keys_rotate(vm);
        out.insert(
            intent_id.clone(),
            ResolvedKeysRotateIntent {
                intent_id,
                vm: vm.clone(),
                key_path: bundle.managed_keys.effective_key_path(vm),
            },
        );
    }
    out
}

fn build_host_key_trust_intents(
    bundle: &Bundle,
    manifest: &ManifestV04,
) -> BTreeMap<String, ResolvedHostKeyTrustIntent> {
    let mut out = BTreeMap::new();
    for (vm, entry) in &manifest.vms {
        let Some(static_ip) = entry.static_ip.as_ref() else {
            continue;
        };
        let intent_id = intent_id_trust(vm);
        out.insert(
            intent_id.clone(),
            ResolvedHostKeyTrustIntent {
                intent_id,
                vm: vm.clone(),
                static_ip: static_ip.clone(),
                known_hosts_path: bundle.managed_keys.known_hosts_path_buf(),
                host_public_key_path: PathBuf::from(&entry.state_dir)
                    .join("sshd-host-keys")
                    .join("ssh_host_ed25519_key.pub"),
            },
        );
    }
    out
}

fn build_rotate_known_host_intents(
    bundle: &Bundle,
    manifest: &ManifestV04,
) -> BTreeMap<String, ResolvedRotateKnownHostIntent> {
    let mut out = BTreeMap::new();
    for (vm, entry) in &manifest.vms {
        let Some(static_ip) = entry.static_ip.as_ref() else {
            continue;
        };
        let intent_id = intent_id_rotate_known_host(vm);
        out.insert(
            intent_id.clone(),
            ResolvedRotateKnownHostIntent {
                intent_id,
                vm: vm.clone(),
                static_ip: static_ip.clone(),
                known_hosts_path: bundle.managed_keys.known_hosts_path_buf(),
            },
        );
    }
    out
}

fn resolve_bundle_ref(bundle_root: &Path, artifact_path: &str) -> PathBuf {
    let path = Path::new(artifact_path);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        bundle_root.join(path)
    }
}

/// Load closure metadata without tamper-resistance checks.
///
/// Used when artifacts have already been validated by the caller
/// (e.g. `from_artifacts_with_closures` test path) or when the
/// bundle root is known-trusted (Nix store).
#[allow(dead_code)]
fn load_closure_metadata(
    bundle: &Bundle,
    bundle_root: &Path,
) -> Result<Vec<ClosureMetadata>, Error> {
    let mut closures = Vec::new();
    for closure_ref in &bundle.closures {
        let closure_path = resolve_bundle_ref(bundle_root, &closure_ref.path);
        let closure_bytes =
            std::fs::read(&closure_path).map_err(|_| Error::internal_io("bundle-closure-read"))?;
        let closure: ClosureMetadata = serde_json::from_slice(&closure_bytes).map_err(|e| {
            Error::manifest_parse_error("closure.json", manifest_parse_reason(&e.to_string()))
        })?;
        closures.push(closure);
    }
    Ok(closures)
}

/// Like `load_closure_metadata` but applies the tamper-resistance policy to
/// every `closures/<vm>.json` artifact and verifies each
/// file's SHA-256 against `bundle.artifact_hashes`.
fn load_closure_metadata_verified(
    bundle: &Bundle,
    bundle_root: &Path,
    policy: &BundleVerifyPolicy,
) -> Result<Vec<ClosureMetadata>, Error> {
    let mut closures = Vec::new();
    for closure_ref in &bundle.closures {
        let closure_path = resolve_bundle_ref(bundle_root, &closure_ref.path);
        let closure_bytes = secure_open_and_read(&closure_path, policy)?;
        verify_artifact_hash(
            &closure_path,
            &closure_bytes,
            bundle.artifact_hashes.as_ref(),
            &closure_ref.path,
        )?;
        let closure: ClosureMetadata = serde_json::from_slice(&closure_bytes).map_err(|e| {
            Error::manifest_parse_error("closure.json", manifest_parse_reason(&e.to_string()))
        })?;
        closures.push(closure);
    }
    Ok(closures)
}

/// Load the integrity-pinned per-Zone Resource bundles emitted by Nix.
///
/// The bundle index is deliberately kept in `Bundle.artifact_hashes` rather
/// than added as another compatibility field to `bundle.json`: older
/// producers can still be parsed, while v3 producers get the same
/// no-follow/ownership/hash enforcement as every other private artifact.
fn load_zone_resource_bundles(
    bundle: &Bundle,
    bundle_root: &Path,
    policy: &BundleVerifyPolicy,
) -> Result<(BTreeMap<String, Vec<u8>>, Vec<ProcessTemplateBinding>), Error> {
    let mut bundles = BTreeMap::new();
    let mut process_templates = Vec::new();
    let Some(artifact_hashes) = bundle.artifact_hashes.as_ref() else {
        return Ok((bundles, process_templates));
    };
    for key in artifact_hashes.keys() {
        let Some(zone_path) = key.strip_prefix("zones/") else {
            continue;
        };
        let Some(zone_name) = zone_path.strip_suffix("/resource-bundle.json") else {
            continue;
        };
        if zone_name.is_empty() || zone_name.contains('/') || zone_name.contains('\\') {
            return Err(Error::manifest_parse_error(
                "resource-bundle.json",
                "Zone resource bundle path is invalid",
            ));
        }
        let zone_path = resolve_bundle_ref(bundle_root, key);
        let bytes = secure_open_and_read(&zone_path, policy)?;
        verify_artifact_hash(&zone_path, &bytes, bundle.artifact_hashes.as_ref(), key)?;
        let parsed = ResourceBundle::from_json(&bytes).map_err(|_| {
            Error::manifest_parse_error("resource-bundle.json", "resource bundle is invalid")
        })?;
        if bundles.insert(zone_name.to_owned(), bytes).is_some() {
            return Err(Error::manifest_parse_error(
                "resource-bundle.json",
                "duplicate Zone resource bundle",
            ));
        }
        process_templates.extend(parsed.process_templates);
    }
    Ok((bundles, process_templates))
}

/// Load the semantic Guest setup descriptors from the adjacent artifact
/// catalog. The catalog is bound to every Zone resource bundle by its
/// `artifactCatalogDigest`, so a descriptor cannot be selected from an
/// unrelated catalog.
fn load_guest_setup_descriptors(
    zone_resource_bundles: &BTreeMap<String, Vec<u8>>,
    bundle_root: &Path,
    policy: &BundleVerifyPolicy,
) -> Result<
    (
        BTreeMap<(String, String), Vec<u8>>,
        BTreeMap<(String, String), String>,
        BTreeMap<(String, String), ResolvedRunnerIntent>,
        BTreeMap<(String, String), ResourceUid>,
        BTreeMap<String, ResolvedStoreViewIntent>,
    ),
    Error,
> {
    let catalog_path = resolve_bundle_ref(bundle_root, "artifact-catalog.json");
    if !catalog_path.exists() {
        return Ok((
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        ));
    }
    let bytes = secure_open_and_read(&catalog_path, policy)?;
    let mut catalog: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
        Error::manifest_parse_error(
            "artifact-catalog.json",
            manifest_parse_reason(&error.to_string()),
        )
    })?;
    let catalog_digest = catalog
        .get("catalogDigest")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            Error::manifest_parse_error(
                "artifact-catalog.json",
                "artifact catalog digest is missing",
            )
        })?
        .to_owned();
    let Some(object) = catalog.as_object_mut() else {
        return Err(Error::manifest_parse_error(
            "artifact-catalog.json",
            "artifact catalog is not an object",
        ));
    };
    object.remove("catalogDigest");
    let preimage = serde_json::to_vec(&catalog).map_err(|_| {
        Error::manifest_parse_error("artifact-catalog.json", "artifact catalog is invalid")
    })?;
    let canonical = CanonicalJsonValue::parse(&preimage).map_err(|_| {
        Error::manifest_parse_error("artifact-catalog.json", "artifact catalog is not canonical")
    })?;
    let canonical = canonical.to_canonical_bytes();
    if framed_canonical_digest(ARTIFACT_CATALOG_DOMAIN_TAG, &canonical) != catalog_digest {
        return Err(Error::manifest_parse_error(
            "artifact-catalog.json",
            "artifact catalog digest does not match its content",
        ));
    }
    for bytes in zone_resource_bundles.values() {
        let bundle = ResourceBundle::from_json(bytes).map_err(|_| {
            Error::manifest_parse_error(
                "resource-bundle.json",
                "resource bundle is invalid while checking artifact catalog",
            )
        })?;
        if bundle.integrity().artifact_catalog_digest != catalog_digest {
            return Err(Error::manifest_parse_error(
                "resource-bundle.json",
                "resource bundle artifact catalog digest does not match",
            ));
        }
    }
    let descriptors = catalog
        .get("guestSetupDescriptors")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            Error::manifest_parse_error(
                "artifact-catalog.json",
                "Guest setup descriptor list is missing",
            )
        })?;
    let mut result = BTreeMap::new();
    let mut catalog_keys = BTreeMap::new();
    for row in descriptors {
        let zone = row
            .get("zone")
            .and_then(serde_json::Value::as_str)
            .filter(|zone| !zone.is_empty())
            .ok_or_else(|| {
                Error::manifest_parse_error(
                    "artifact-catalog.json",
                    "Guest setup descriptor Zone is invalid",
                )
            })?;
        let guest = row
            .get("guest")
            .and_then(serde_json::Value::as_str)
            .filter(|guest| !guest.is_empty())
            .ok_or_else(|| {
                Error::manifest_parse_error(
                    "artifact-catalog.json",
                    "Guest setup descriptor name is invalid",
                )
            })?;
        let descriptor = row.get("descriptor").ok_or_else(|| {
            Error::manifest_parse_error(
                "artifact-catalog.json",
                "Guest setup descriptor payload is missing",
            )
        })?;
        let provider_contract_digest = row
            .get("providerContractDigest")
            .and_then(serde_json::Value::as_str)
            .filter(|digest| {
                d2b_contracts_resource::v3::resource_schema::is_canonical_digest(digest)
            })
            .ok_or_else(|| {
                Error::manifest_parse_error(
                    "artifact-catalog.json",
                    "Guest setup descriptor Provider contract digest is invalid",
                )
            })?;
        let descriptor_bytes = serde_json::to_vec(descriptor).map_err(|_| {
            Error::manifest_parse_error(
                "artifact-catalog.json",
                "Guest setup descriptor payload is invalid",
            )
        })?;
        let descriptor_value = CanonicalJsonValue::parse(&descriptor_bytes).map_err(|_| {
            Error::manifest_parse_error(
                "artifact-catalog.json",
                "Guest setup descriptor payload is not canonical",
            )
        })?;
        let descriptor_bytes = descriptor_value.to_canonical_bytes();
        let key = (zone.to_owned(), guest.to_owned());
        if result.insert(key.clone(), descriptor_bytes).is_some()
            || catalog_keys
                .insert(key, provider_contract_digest.to_owned())
                .is_some()
        {
            return Err(Error::manifest_parse_error(
                "artifact-catalog.json",
                "duplicate Guest setup descriptor",
            ));
        }
    }
    let (guest_vmm_intents, guest_vmm_zone_uids) = load_guest_vmm_intents(&catalog, &result)?;
    let guest_store_view_intents = load_guest_store_view_intents(&catalog)?;
    Ok((
        result,
        catalog_keys,
        guest_vmm_intents,
        guest_vmm_zone_uids,
        guest_store_view_intents,
    ))
}

fn load_guest_store_view_intents(
    catalog: &serde_json::Value,
) -> Result<BTreeMap<String, ResolvedStoreViewIntent>, Error> {
    let Some(rows) = catalog
        .get("guestClosures")
        .and_then(serde_json::Value::as_array)
    else {
        return Ok(BTreeMap::new());
    };
    let mut intents = BTreeMap::new();
    for row in rows {
        let zone = row
            .get("zone")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .and_then(|value| ZoneId::parse(value.to_owned()).ok())
            .ok_or_else(|| {
                Error::manifest_parse_error(
                    "artifact-catalog.json",
                    "Guest closure Zone is invalid",
                )
            })?;
        let guest = row
            .get("guest")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                Error::manifest_parse_error(
                    "artifact-catalog.json",
                    "Guest closure name is invalid",
                )
            })?;
        let toplevel = row
            .get("toplevel")
            .and_then(serde_json::Value::as_str)
            .map(PathBuf::from)
            .filter(|value| value.is_absolute())
            .ok_or_else(|| {
                Error::manifest_parse_error(
                    "artifact-catalog.json",
                    "Guest closure toplevel is invalid",
                )
            })?;
        let closure_paths = row
            .get("closurePaths")
            .and_then(serde_json::Value::as_array)
            .filter(|values| !values.is_empty())
            .ok_or_else(|| {
                Error::manifest_parse_error(
                    "artifact-catalog.json",
                    "Guest closure paths are invalid",
                )
            })?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(PathBuf::from)
                    .filter(|path| path.is_absolute())
                    .ok_or_else(|| {
                        Error::manifest_parse_error(
                            "artifact-catalog.json",
                            "Guest closure path is invalid",
                        )
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let hardlink_farm_path = row
            .get("storeView")
            .and_then(|value| value.get("root"))
            .and_then(serde_json::Value::as_str)
            .map(PathBuf::from)
            .filter(|value| value.is_absolute())
            .ok_or_else(|| {
                Error::manifest_parse_error(
                    "artifact-catalog.json",
                    "Guest store-view root is invalid",
                )
            })?;
        let db_dump_path = row
            .get("dbDumpPath")
            .and_then(serde_json::Value::as_str)
            .map(PathBuf::from)
            .filter(|value| value.is_absolute())
            .ok_or_else(|| {
                Error::manifest_parse_error(
                    "artifact-catalog.json",
                    "Guest closure registration is invalid",
                )
            })?;
        let target_name = toplevel.file_name().ok_or_else(|| {
            Error::manifest_parse_error(
                "artifact-catalog.json",
                "Guest closure toplevel has no basename",
            )
        })?;
        let intent_id = intent_id_store_view(&zone, guest);
        let intent = ResolvedStoreViewIntent {
            intent_id: intent_id.clone(),
            vm: guest.to_owned(),
            generation: 1,
            target_view_path: hardlink_farm_path.join("live").join(target_name),
            hardlink_farm_path,
            closure_paths,
            db_dump_path,
        };
        if intents.insert(intent_id, intent).is_some() {
            return Err(Error::manifest_parse_error(
                "artifact-catalog.json",
                "duplicate Guest store-view intent",
            ));
        }
    }
    Ok(intents)
}

fn load_guest_vmm_intents(
    catalog: &serde_json::Value,
    descriptors: &BTreeMap<(String, String), Vec<u8>>,
) -> Result<
    (
        BTreeMap<(String, String), ResolvedRunnerIntent>,
        BTreeMap<(String, String), ResourceUid>,
    ),
    Error,
> {
    let Some(rows) = catalog
        .get("guestClosures")
        .and_then(serde_json::Value::as_array)
    else {
        return Ok((BTreeMap::new(), BTreeMap::new()));
    };
    let mut intents = BTreeMap::new();
    let mut zone_uids = BTreeMap::new();
    for row in rows {
        let zone = row
            .get("zone")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .and_then(|value| ZoneId::parse(value.to_owned()).ok())
            .ok_or_else(|| {
                Error::manifest_parse_error(
                    "artifact-catalog.json",
                    "Guest closure Zone is invalid",
                )
            })?;
        let guest = row
            .get("guest")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                Error::manifest_parse_error(
                    "artifact-catalog.json",
                    "Guest closure name is invalid",
                )
            })?;
        let zone_uid = row
            .get("vmm")
            .and_then(|vmm| vmm.get("zoneUid"))
            .and_then(serde_json::Value::as_str)
            .and_then(|value| ResourceUid::parse(value.to_owned()).ok())
            .ok_or_else(|| {
                Error::manifest_parse_error(
                    "artifact-catalog.json",
                    "Guest VMM Zone identity is invalid",
                )
            })?;
        let descriptor_digest = row
            .get("vmm")
            .and_then(|vmm| vmm.get("descriptorDigest"))
            .and_then(serde_json::Value::as_str)
            .filter(|value| d2b_contracts_resource::v3::resource_schema::is_canonical_digest(value))
            .ok_or_else(|| {
                Error::manifest_parse_error(
                    "artifact-catalog.json",
                    "Guest VMM descriptor binding is invalid",
                )
            })?;
        let descriptor = descriptors
            .get(&(zone.as_str().to_owned(), guest.to_owned()))
            .ok_or_else(|| {
                Error::manifest_parse_error(
                    "artifact-catalog.json",
                    "Guest VMM descriptor binding is missing",
                )
            })?;
        let descriptor_value: serde_json::Value =
            serde_json::from_slice(descriptor).map_err(|_| {
                Error::manifest_parse_error(
                    "artifact-catalog.json",
                    "Guest setup descriptor is invalid while binding VMM intent",
                )
            })?;
        if descriptor_value
            .get("descriptorDigest")
            .and_then(serde_json::Value::as_str)
            != Some(descriptor_digest)
        {
            return Err(Error::manifest_parse_error(
                "artifact-catalog.json",
                "Guest VMM descriptor digest does not match setup descriptor",
            ));
        }
        let artifact_id = row
            .get("artifactId")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                Error::manifest_parse_error(
                    "artifact-catalog.json",
                    "Guest closure artifact binding is invalid",
                )
            })?;
        if descriptor_value
            .get("systemArtifactId")
            .and_then(serde_json::Value::as_str)
            != Some(artifact_id)
        {
            return Err(Error::manifest_parse_error(
                "artifact-catalog.json",
                "Guest VMM artifact does not match setup descriptor",
            ));
        }
        let vmm = row.get("vmm").ok_or_else(|| {
            Error::manifest_parse_error("artifact-catalog.json", "Guest VMM intent is missing")
        })?;
        let execution_ref = vmm
            .get("executionRef")
            .and_then(serde_json::Value::as_str)
            .and_then(|value| ResourceRef::parse(value).ok())
            .filter(|value| value.resource_type().as_str() == "Host")
            .ok_or_else(|| {
                Error::manifest_parse_error(
                    "artifact-catalog.json",
                    "Guest VMM execution reference is invalid",
                )
            })?;
        let binary_path = vmm
            .get("binaryPath")
            .and_then(serde_json::Value::as_str)
            .filter(|value| {
                !value.is_empty()
                    && !value.contains('\0')
                    && value.starts_with("/nix/store/")
                    && !value
                        .split('/')
                        .any(|segment| matches!(segment, "." | ".."))
            })
            .map(PathBuf::from)
            .ok_or_else(|| {
                Error::manifest_parse_error(
                    "artifact-catalog.json",
                    "Guest VMM binary path is invalid",
                )
            })?;
        let argv = vmm
            .get("argv")
            .and_then(serde_json::Value::as_array)
            .filter(|values| {
                !values.is_empty()
                    && values.iter().all(|value| {
                        value.as_str().is_some_and(|argument| {
                            !argument.is_empty() && !argument.contains('\0')
                        })
                    })
            })
            .map(|values| {
                values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .ok_or_else(|| {
                Error::manifest_parse_error("artifact-catalog.json", "Guest VMM argv is invalid")
            })?;
        let uid = vmm
            .get("uid")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| {
                Error::manifest_parse_error("artifact-catalog.json", "Guest VMM uid is invalid")
            })?;
        let gid = vmm
            .get("gid")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| {
                Error::manifest_parse_error("artifact-catalog.json", "Guest VMM gid is invalid")
            })?;
        let state_dir = vmm
            .get("stateDir")
            .and_then(serde_json::Value::as_str)
            .filter(|value| {
                value.starts_with('/')
                    && !value.contains('\0')
                    && !value
                        .split('/')
                        .any(|segment| matches!(segment, "." | ".."))
            })
            .map(|value| value.to_owned())
            .ok_or_else(|| {
                Error::manifest_parse_error(
                    "artifact-catalog.json",
                    "Guest VMM state directory is invalid",
                )
            })?;
        let device_binds = vmm
            .get("deviceBinds")
            .and_then(serde_json::Value::as_array)
            .filter(|values| {
                values.iter().all(|value| {
                    value
                        .as_str()
                        .is_some_and(|path| path.starts_with('/') && !path.contains('\0'))
                })
            })
            .map(|values| {
                values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let profile_id = vmm
            .get("profileId")
            .and_then(serde_json::Value::as_str)
            .and_then(|value| {
                d2b_contracts_resource::v3::execution_policy::BoundedToken::parse(value.to_owned())
                    .ok()
            })
            .ok_or_else(|| {
                Error::manifest_parse_error(
                    "artifact-catalog.json",
                    "Guest VMM profile ID is invalid",
                )
            })?;
        let cgroup_subtree = vmm
            .get("cgroupSubtree")
            .and_then(serde_json::Value::as_str)
            .filter(|value| {
                !value.is_empty()
                    && !value.starts_with('/')
                    && !value.contains('\0')
                    && !value.split('/').any(|segment| segment == "..")
            })
            .ok_or_else(|| {
                Error::manifest_parse_error(
                    "artifact-catalog.json",
                    "Guest VMM cgroup placement is invalid",
                )
            })?;
        let cgroup_segments = cgroup_subtree.split('/').collect::<Vec<_>>();
        if cgroup_segments.len() != 4
            || cgroup_segments[0] != "d2b.slice"
            || cgroup_segments[1] != zone.as_str()
            || cgroup_segments[2] != guest
            || cgroup_segments[3] != "cloud-hypervisor"
            || cgroup_segments
                .iter()
                .any(|segment| segment.is_empty() || matches!(*segment, "." | ".."))
        {
            return Err(Error::manifest_parse_error(
                "artifact-catalog.json",
                "Guest VMM cgroup placement is not Guest-bound",
            ));
        }
        let env = vmm
            .get("env")
            .and_then(serde_json::Value::as_array)
            .filter(|values| {
                values.iter().all(|value| {
                    value.as_str().is_some_and(|entry| {
                        !entry.is_empty() && !entry.contains('\0') && entry.contains('=')
                    })
                })
            })
            .map(|values| {
                values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec![format!("D2B_VM={guest}")]);
        if !cloud_hypervisor_intent_is_complete_values(&binary_path, &argv) {
            return Err(Error::manifest_parse_error(
                "artifact-catalog.json",
                "Guest VMM intent does not carry a complete Cloud Hypervisor argv",
            ));
        }
        let key = (zone.as_str().to_owned(), guest.to_owned());
        if intents.contains_key(&key) {
            return Err(Error::manifest_parse_error(
                "artifact-catalog.json",
                "duplicate Guest VMM intent",
            ));
        }
        let intent = ResolvedRunnerIntent {
            intent_id: intent_id_runner(&zone, guest, "cloud-hypervisor"),
            vm_name: guest.to_owned(),
            execution_ref: execution_ref.to_canonical_string(),
            owner_ref: None,
            execution_domain: ProcessExecutionDomain::System,
            user_ref: None,
            role_id: "cloud-hypervisor".to_owned(),
            role: ProcessRole::CloudHypervisorRunner,
            binary_path,
            argv,
            env,
            uid,
            gid,
            supplementary_groups: Vec::new(),
            capabilities: Vec::new(),
            namespaces: NamespaceSet {
                mount: true,
                pid: false,
                net: false,
                ipc: true,
                uts: false,
                user: false,
            },
            seccomp_policy_ref: Some("w1-cloud-hypervisor-runner".to_owned()),
            mount_policy: MountPolicy {
                read_only_paths: vec!["/nix/store".to_owned()],
                writable_paths: vec![WritablePath {
                    path: state_dir,
                    purpose: "Guest VMM runtime state".to_owned(),
                }],
                nix_store_read_only: true,
                hide_device_nodes_by_default: true,
                device_binds,
                bind_mounts: Vec::new(),
            },
            cgroup_placement: CgroupPlacement {
                subtree: cgroup_subtree.to_owned(),
                controllers: vec!["cpu".to_owned(), "memory".to_owned(), "pids".to_owned()],
                delegated: false,
            },
            root_carve_out: false,
            profile_id: profile_id.as_str().to_owned(),
            user_namespace: None,
            umask: Some(0o022),
        };
        if intents.insert(key.clone(), intent).is_some()
            || zone_uids.insert(key, zone_uid).is_some()
        {
            return Err(Error::manifest_parse_error(
                "artifact-catalog.json",
                "duplicate Guest VMM Zone identity",
            ));
        }
    }
    Ok((intents, zone_uids))
}

fn cloud_hypervisor_intent_is_complete_values(binary_path: &Path, argv: &[String]) -> bool {
    let value_for = |flag: &str| {
        argv.iter()
            .position(|argument| argument == flag)
            .and_then(|index| argv.get(index + 1))
    };
    let kernel = value_for("--kernel");
    let initrd = value_for("--initramfs");
    let cmdline = value_for("--cmdline");
    let api_socket = value_for("--api-socket");
    binary_path.is_absolute()
        && binary_path.starts_with("/nix/store/")
        && binary_path
            .to_string_lossy()
            .ends_with("/bin/cloud-hypervisor")
        && !binary_path.starts_with("/run/current-system/sw/")
        && kernel.is_some_and(|value| value.starts_with("/nix/store/"))
        && initrd.is_some_and(|value| value.starts_with("/nix/store/"))
        && cmdline.is_some_and(|value| value.contains("init=/nix/store/"))
        && api_socket.is_some_and(|value| {
            value.starts_with('/')
                && !value.contains('\0')
                && !value
                    .split('/')
                    .any(|segment| matches!(segment, "." | ".."))
        })
}

/// Load the integrity-pinned per-Zone storage rows emitted by Nix.
fn load_zone_storage_rows(
    bundle: &Bundle,
    bundle_root: &Path,
    policy: &BundleVerifyPolicy,
) -> Result<BTreeMap<String, ZoneStoreStorageRow>, Error> {
    let mut rows = BTreeMap::new();
    let Some(artifact_hashes) = bundle.artifact_hashes.as_ref() else {
        return Ok(rows);
    };
    for key in artifact_hashes.keys() {
        let Some(zone_path) = key.strip_prefix("zones/") else {
            continue;
        };
        let Some(zone_name) = zone_path.strip_suffix("/storage.json") else {
            continue;
        };
        if zone_name.is_empty() || zone_name.contains('/') || zone_name.contains('\\') {
            return Err(Error::manifest_parse_error(
                "storage.json",
                "Zone storage row path is invalid",
            ));
        }
        let row_path = resolve_bundle_ref(bundle_root, key);
        let bytes = secure_open_and_read(&row_path, policy)?;
        verify_artifact_hash(&row_path, &bytes, bundle.artifact_hashes.as_ref(), key)?;
        let row: ZoneStoreStorageRow = serde_json::from_slice(&bytes).map_err(|error| {
            Error::manifest_parse_error("storage.json", manifest_parse_reason(&error.to_string()))
        })?;
        if rows.insert(zone_name.to_owned(), row).is_some() {
            return Err(Error::manifest_parse_error(
                "storage.json",
                "duplicate Zone storage row",
            ));
        }
    }
    Ok(rows)
}

fn load_zone_native_topology(
    bundle: &Bundle,
    zone_resource_bundles: &BTreeMap<String, Vec<u8>>,
    bundle_root: &Path,
    policy: &BundleVerifyPolicy,
) -> Result<Option<AllocatorZoneTopology>, Error> {
    if bundle.schema_version != "v3" {
        return Ok(None);
    }
    let Some(artifact_hashes) = bundle.artifact_hashes.as_ref() else {
        return Ok(None);
    };
    if !artifact_hashes.contains_key("index.json") {
        return if zone_resource_bundles.is_empty() {
            Ok(None)
        } else {
            Err(Error::manifest_parse_error(
                "index.json",
                "Zone topology index is missing",
            ))
        };
    }
    let index_path = resolve_bundle_ref(bundle_root, "index.json");
    let bytes = secure_open_and_read(&index_path, policy)?;
    verify_artifact_hash(
        &index_path,
        &bytes,
        bundle.artifact_hashes.as_ref(),
        "index.json",
    )?;
    let index: ZoneNativeIndexDocument = serde_json::from_slice(&bytes).map_err(|error| {
        Error::manifest_parse_error("index.json", manifest_parse_reason(&error.to_string()))
    })?;
    if !index.topology.sealed {
        return Err(Error::manifest_parse_error(
            "index.json",
            "Zone topology is not sealed",
        ));
    }
    let zone_names = zone_resource_bundles
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    if index.zones.keys().cloned().collect::<BTreeSet<_>>() != zone_names
        || index
            .topology
            .generation_by_zone
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
            != zone_names
        || index
            .topology
            .parent_map
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
            != zone_names
    {
        return Err(Error::manifest_parse_error(
            "index.json",
            "Zone topology does not cover the committed Zone set",
        ));
    }
    let parent_map_bytes = serde_json::to_vec(&index.topology.parent_map)
        .map_err(|_| Error::internal_io("zone-topology-canonical"))?;
    if framed_canonical_digest("d2b:v3:parent-topology", &parent_map_bytes)
        != index.topology.parent_map_digest
    {
        return Err(Error::manifest_parse_error(
            "index.json",
            "Zone topology digest does not match",
        ));
    }
    let mut parent_map = BTreeMap::new();
    let mut roots = Vec::new();
    for (zone, parent) in index.topology.parent_map {
        let zone = ZoneId::parse(zone).map_err(|_| {
            Error::manifest_parse_error("index.json", "Zone topology name is invalid")
        })?;
        let parent = parent
            .map(|parent| {
                ZoneId::parse(parent).map_err(|_| {
                    Error::manifest_parse_error("index.json", "Zone topology parent is invalid")
                })
            })
            .transpose()?;
        if parent.is_none() {
            roots.push(zone.clone());
        }
        parent_map.insert(zone, parent);
    }
    let [root] = roots.as_slice() else {
        return Err(Error::manifest_parse_error(
            "index.json",
            "Zone topology must have exactly one root",
        ));
    };
    Ok(Some(AllocatorZoneTopology {
        root: root.clone(),
        parent_map,
    }))
}

fn load_optional_allocator_artifact(
    bundle: &Bundle,
    bundle_root: &Path,
    policy: &BundleVerifyPolicy,
) -> Result<Option<AllocatorJson>, Error> {
    let Some(allocator_ref) = bundle.allocator_path.as_deref() else {
        return Ok(None);
    };
    let allocator_path = resolve_bundle_ref(bundle_root, allocator_ref);
    let bytes = secure_open_and_read(&allocator_path, policy)?;
    verify_artifact_hash(
        &allocator_path,
        &bytes,
        bundle.artifact_hashes.as_ref(),
        allocator_ref,
    )?;
    let allocator: AllocatorJson = serde_json::from_slice(&bytes).map_err(|error| {
        Error::manifest_parse_error("allocator.json", manifest_parse_reason(&error.to_string()))
    })?;
    Ok(Some(allocator))
}

fn load_optional_storage_artifact(
    bundle: &Bundle,
    bundle_root: &Path,
    policy: &BundleVerifyPolicy,
) -> Result<Option<StorageJson>, Error> {
    let Some(storage_ref) = bundle.storage_path.as_deref() else {
        return Ok(None);
    };
    let storage_path = resolve_bundle_ref(bundle_root, storage_ref);
    let bytes = secure_open_and_read(&storage_path, policy)?;
    verify_artifact_hash(
        &storage_path,
        &bytes,
        bundle.artifact_hashes.as_ref(),
        storage_ref,
    )?;
    let storage: StorageJson = serde_json::from_slice(&bytes).map_err(|e| {
        Error::manifest_parse_error("storage.json", manifest_parse_reason(&e.to_string()))
    })?;
    Ok(Some(storage))
}

fn load_optional_sync_artifact(
    bundle: &Bundle,
    bundle_root: &Path,
    policy: &BundleVerifyPolicy,
) -> Result<Option<SyncJson>, Error> {
    let Some(sync_ref) = bundle.sync_path.as_deref() else {
        return Ok(None);
    };
    let sync_path = resolve_bundle_ref(bundle_root, sync_ref);
    let bytes = secure_open_and_read(&sync_path, policy)?;
    verify_artifact_hash(
        &sync_path,
        &bytes,
        bundle.artifact_hashes.as_ref(),
        sync_ref,
    )?;
    let sync: SyncJson = serde_json::from_slice(&bytes).map_err(|e| {
        Error::manifest_parse_error("sync.json", manifest_parse_reason(&e.to_string()))
    })?;
    Ok(Some(sync))
}

fn load_optional_realm_controllers_artifact(
    bundle: &Bundle,
    bundle_root: &Path,
    policy: &BundleVerifyPolicy,
) -> Result<Option<RealmControllersJson>, Error> {
    let Some(realm_controllers_ref) = bundle.realm_controllers_path.as_deref() else {
        return Ok(None);
    };
    let realm_controllers_path = resolve_bundle_ref(bundle_root, realm_controllers_ref);
    let bytes = secure_open_and_read(&realm_controllers_path, policy)?;
    verify_artifact_hash(
        &realm_controllers_path,
        &bytes,
        bundle.artifact_hashes.as_ref(),
        realm_controllers_ref,
    )?;
    let realm_controllers: RealmControllersJson = serde_json::from_slice(&bytes).map_err(|e| {
        Error::manifest_parse_error(
            "realm-controllers.json",
            manifest_parse_reason(&e.to_string()),
        )
    })?;
    realm_controllers
        .validate_metadata_only()
        .map_err(|err| Error::manifest_parse_error("realm-controllers.json", err.to_string()))?;
    Ok(Some(realm_controllers))
}

fn load_optional_realm_identity_artifact(
    bundle: &Bundle,
    bundle_root: &Path,
    policy: &BundleVerifyPolicy,
) -> Result<Option<RealmIdentityConfigJson>, Error> {
    let Some(realm_identity_ref) = bundle.realm_identity_path.as_deref() else {
        return Ok(None);
    };
    let realm_identity_path = resolve_bundle_ref(bundle_root, realm_identity_ref);
    let bytes = secure_open_and_read(&realm_identity_path, policy)?;
    verify_artifact_hash(
        &realm_identity_path,
        &bytes,
        bundle.artifact_hashes.as_ref(),
        realm_identity_ref,
    )?;
    let realm_identity: RealmIdentityConfigJson = serde_json::from_slice(&bytes).map_err(|e| {
        Error::manifest_parse_error("realm-identity.json", manifest_parse_reason(&e.to_string()))
    })?;
    realm_identity
        .validate_metadata_only()
        .map_err(|err| Error::manifest_parse_error("realm-identity.json", err.to_string()))?;
    Ok(Some(realm_identity))
}

fn load_optional_unsafe_local_workloads_artifact(
    bundle: &Bundle,
    bundle_root: &Path,
    policy: &BundleVerifyPolicy,
) -> Result<Option<UnsafeLocalWorkloadsJson>, Error> {
    let Some(unsafe_local_workloads_ref) = bundle.unsafe_local_workloads_path.as_deref() else {
        return Ok(None);
    };
    let path = resolve_bundle_ref(bundle_root, unsafe_local_workloads_ref);
    let bytes = secure_open_and_read(&path, policy)?;
    verify_artifact_hash(
        &path,
        &bytes,
        bundle.artifact_hashes.as_ref(),
        unsafe_local_workloads_ref,
    )?;
    let artifact: UnsafeLocalWorkloadsJson = serde_json::from_slice(&bytes).map_err(|e| {
        Error::manifest_parse_error(
            "unsafe-local-workloads.json",
            manifest_parse_reason(&e.to_string()),
        )
    })?;
    artifact
        .validate()
        .map_err(|error| Error::manifest_parse_error("unsafe-local-workloads.json", error))?;
    Ok(Some(artifact))
}

fn load_optional_realm_workloads_launcher_v2_artifact(
    bundle: &Bundle,
    bundle_root: &Path,
    policy: &BundleVerifyPolicy,
) -> Result<Option<RealmWorkloadsLauncherV2Json>, Error> {
    let Some(launcher_ref) = bundle.realm_workloads_launcher_v2_path.as_deref() else {
        return Ok(None);
    };
    let path = resolve_bundle_ref(bundle_root, launcher_ref);
    let bytes = secure_open_and_read(&path, policy)?;
    verify_artifact_hash(&path, &bytes, bundle.artifact_hashes.as_ref(), launcher_ref)?;
    let artifact: RealmWorkloadsLauncherV2Json =
        serde_json::from_slice(&bytes).map_err(|error| {
            Error::manifest_parse_error(
                "realm-workloads-launcher-v2.json",
                manifest_parse_reason(&error.to_string()),
            )
        })?;
    artifact
        .validate()
        .map_err(|error| Error::manifest_parse_error("realm-workloads-launcher-v2.json", error))?;
    Ok(Some(artifact))
}

// ---------------------------------------------------------------
// Stable digest helper.
// ---------------------------------------------------------------

/// Stable, non-cryptographic content digest for drift detection.
///
/// Uses FNV-1a 64-bit over the UTF-8 bytes. Not a security boundary:
/// the broker resolves authority from the bundle, not from this
/// digest. The digest exists so the daemon's optional
/// `desired_hash` field can be compared against the resolver's
/// view of the same intent for pre-apply drift detection.
fn stable_digest(input: &str) -> String {
    stable_digest_bytes(input.as_bytes())
}

fn stable_digest_bytes(input: &[u8]) -> String {
    const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x00000100000001B3;
    let mut hash: u64 = FNV_OFFSET_BASIS;
    for byte in input {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    format!("fnv1a64:{hash:016x}")
}

// ---------------------------------------------------------------
// Minimal-touch helpers re-exported from types this module needs.
// ---------------------------------------------------------------

fn manifest_parse_reason(err: &str) -> &'static str {
    // Bridge to the existing manifest_v04 helper without exposing it.
    // We just need a stable category string for `Error::manifest_parse_error`.
    if err.contains("missing field") {
        "missing-required-field"
    } else if err.contains("unknown field") {
        "unknown-field"
    } else if err.contains("invalid type") {
        "invalid-type"
    } else {
        "parse-failed"
    }
}

// Silence the "TapRole imported but unused" warning - we only need
// it transitively to refer to BridgePortFlags in the render
// helpers, which already use the type via `flag.role`.
#[allow(dead_code)]
const _ASSERT_TAPROLE: Option<TapRole> = None;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{Bundle, BundleClosureRef, BundleGeneration};
    use crate::closures::{ClosureGeneration, ClosureMetadata};
    use crate::host::{
        BridgePortFlags, ChNetHandoffMode, HostChConfig, HostJson, HostsFileOwnership,
        IfNameMapping, LanPolicy, NetEnv, NetworkManagerUnmanaged, NftablesModel, OwnershipRule,
        SitePolicy, UsbipBusidLock, UsbipLockOwner, UsbipLockScope,
    };
    use crate::manifest_v04::{
        ManifestMeta, ManifestV04, ObservabilityMeta, VmEntry, VmLanPolicy, VmObservability,
    };
    use crate::minijail_profile::WritablePath;
    use crate::processes::{
        DagEdge, NodeId, ProcessMacvtapInterface, ProcessMacvtapMode, ProcessNetworkInterface,
        ProcessNetworkInterfaceType, ProcessNode, ProcessRole, ProcessesJson, RoleProfile,
        VmProcessDag, VmProcessInvariants,
    };
    use crate::runtime::RuntimeMetadata;
    use d2b_contracts_resource::v3::{
        CanonicalJsonObject, IfName, ResourceName, ResourceTypeName, ResourceUid, Timestamp,
        ZoneId,
        execution_policy::BoundedToken,
        network::{Ipv4Cidr, NetworkSpec},
    };
    use d2b_contracts_zone_session::v3::resource_bundle::{
        BundleResource, BundleResourceMetadata, ResourceBundle,
    };
    use serde::Serialize;
    use std::collections::BTreeMap;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    const HOST_JSON_FIXTURE: &str =
        include_str!("../../../tests/fixtures/deny-unknown/host-valid.json");

    #[test]
    fn build_sysctl_intents_emits_bridge_nf_triplet() {
        let host: HostJson = serde_json::from_str(HOST_JSON_FIXTURE).expect("host fixture parses");
        let intents = build_sysctl_intents(&host);
        let keys: Vec<_> = intents.values().map(|intent| intent.key.as_str()).collect();
        assert!(keys.contains(&"net.bridge.bridge-nf-call-arptables"));
        assert!(keys.contains(&"net.bridge.bridge-nf-call-iptables"));
        assert!(keys.contains(&"net.bridge.bridge-nf-call-ip6tables"));
    }

    #[test]
    fn host_runtime_carries_persisted_nft_hash() {
        let mut host: HostJson =
            serde_json::from_str(HOST_JSON_FIXTURE).expect("host fixture parses");
        host.nftables.table_hash_after_apply = Some("0123456789abcdef".to_owned());
        let manifest = crate::manifest_v04::ManifestV04::from_slice(
            include_str!("../../../tests/golden/manifest_v04/baseline-vms.json").as_bytes(),
        )
        .expect("manifest fixture parses");
        let resolver = BundleResolver::from_artifacts(
            Bundle {
                bundle_version: 4,
                schema_version: "v2".to_owned(),
                public_manifest_path: "vms.json".to_owned(),
                host_path: "host.json".to_owned(),
                processes_path: "processes.json".to_owned(),
                privileges_path: "privileges.json".to_owned(),
                storage_path: None,
                sync_path: None,
                allocator_path: None,
                realm_controllers_path: None,
                realm_identity_path: None,
                realm_workloads_launcher_v2_path: None,
                unsafe_local_workloads_path: None,
                closures: Vec::new(),
                minijail_profiles: Vec::new(),
                managed_keys: Default::default(),
                generation: BundleGeneration {
                    generator: "test".to_owned(),
                    source_revision: None,
                    generated_at: Some("2025-01-01T00:00:00Z".to_owned()),
                },
                bundle_hash: None,
                artifact_hashes: None,
            },
            host,
            crate::processes::ProcessesJson {
                schema_version: "v2".to_owned(),
                vms: Vec::new(),
            },
            manifest,
        );
        assert_eq!(
            resolver.host_runtime().nft_applied_hash.as_deref(),
            Some("0123456789abcdef")
        );
    }

    fn test_root(test_name: &str) -> PathBuf {
        let base = std::env::var_os("TEST_TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join("d2b-bundle-resolver-tests"));
        fs::create_dir_all(&base).expect("create bundle resolver test root");
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        base.join(format!("{test_name}-{}-{unique}", std::process::id()))
    }

    fn write_json<T: Serialize>(path: &Path, value: &T) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create json parent");
        }
        let mut body = serde_json::to_vec_pretty(value).expect("serialize test json");
        body.push(b'\n');
        fs::write(path, body).expect("write test json");
    }

    #[test]
    fn production_bundle_does_not_load_legacy_env_nft_projection() {
        let root = test_root("nft-projection");
        let resolver = build_personal_dev_bundle(&root);
        assert!(
            resolver
                .find_nft_projection_intent(&intent_id_nft_projection_env("personal"))
                .is_none()
        );
        assert!(
            resolver
                .find_bridge_intent(&intent_id_bridge_env("personal"))
                .is_none()
        );
        assert!(
            resolver
                .find_route_intent(&intent_id_route_env("personal", 0))
                .is_none()
        );
        assert!(
            resolver
                .find_sysctl_intent(&intent_id_sysctl("personal", "d2b-b", "disable_ipv6"))
                .is_none()
        );

        let _ = fs::remove_dir_all(root);
    }

    fn role_profile(uid: u32, gid: u32, writable_paths: &[&str], subtree: &str) -> RoleProfile {
        crate::test_support::RoleProfileBuilder::new()
            .with_profile_id(format!("profile-{uid}-{gid}"))
            .with_uid(uid)
            .with_gid(gid)
            .with_read_only_paths(vec!["/nix/store".to_owned()])
            .with_writable_paths(
                writable_paths
                    .iter()
                    .map(|path| WritablePath {
                        path: (*path).to_owned(),
                        purpose: "test writable path".to_owned(),
                    })
                    .collect(),
            )
            .with_cgroup_placement(CgroupPlacement {
                subtree: subtree.to_owned(),
                controllers: vec!["cpu".to_owned(), "memory".to_owned()],
                delegated: true,
            })
            .build()
    }

    #[test]
    fn qemu_media_runner_wins_exact_writable_path_owner_score() {
        let state_dir = "/var/lib/d2b/vms/media";
        let host = ProcessNode {
            execution_ref: None,
            execution_domain: None,
            user_ref: None,
            id: NodeId("host-reconcile".to_owned()),
            role: ProcessRole::HostReconcile,
            unit: None,
            binary_path: None,
            argv: Vec::new(),
            env: Vec::new(),
            profile: role_profile(1100, 1100, &[state_dir], "d2b.slice/media/host-reconcile"),
            readiness: Vec::new(),
            plan_ops: Vec::new(),
            network_interfaces: Vec::new(),
        };
        let qemu = ProcessNode {
            execution_ref: None,
            execution_domain: None,
            user_ref: None,
            id: NodeId("qemu-media".to_owned()),
            role: ProcessRole::QemuMediaRunner,
            unit: None,
            binary_path: None,
            argv: Vec::new(),
            env: Vec::new(),
            profile: role_profile(1200, 1200, &[state_dir], "d2b.slice/media/qemu-media"),
            readiness: Vec::new(),
            plan_ops: Vec::new(),
            network_interfaces: Vec::new(),
        };

        assert!(score_writable_path(&qemu, true) > score_writable_path(&host, true));
    }

    #[test]
    fn provider_controller_is_not_resolved_from_process_dag() {
        let node = ProcessNode {
            execution_ref: Some("Host/host-system".to_owned()),
            execution_domain: Some(ProcessExecutionDomain::System),
            user_ref: None,
            id: NodeId("cloud-hypervisor-controller".to_owned()),
            role: ProcessRole::ProviderController,
            unit: None,
            binary_path: Some("/bin/controller".to_owned()),
            argv: vec!["controller".to_owned()],
            env: Vec::new(),
            profile: role_profile(1200, 1200, &[], "d2b.slice/controller"),
            readiness: Vec::new(),
            plan_ops: Vec::new(),
            network_interfaces: Vec::new(),
        };

        assert!(ResolvedRunnerIntent::from_process_node("host-system", &node).is_none());
    }

    #[test]
    fn provider_controller_intent_uses_private_bundle_metadata_exactly() {
        let zone = ZoneId::parse("dev").expect("zone");
        let process_ref = ResourceRef::parse("Process/controller-test").expect("process ref");
        let owner_ref = ResourceRef::parse("Provider/runtime-cloud-hypervisor").expect("owner ref");
        let template = "controller-test";
        let process = BundleResource::new(
            ResourceTypeName::parse("Process").expect("process type"),
            BundleResourceMetadata::new(
                process_ref.name().clone(),
                zone.clone(),
                Some(owner_ref.clone()),
                BTreeMap::new(),
                BTreeMap::new(),
            ),
            CanonicalJsonObject::parse(
                br#"{"domain":"system","executionRef":"Host/dev-host","processClass":"controller","providerRef":"Provider/system-minijail","template":"controller-test"}"#,
            )
            .expect("process spec"),
        )
        .expect("process resource");
        let provider = BundleResource::new(
            ResourceTypeName::parse("Provider").expect("provider type"),
            BundleResourceMetadata::new(
                owner_ref.name().clone(),
                zone.clone(),
                None,
                BTreeMap::new(),
                BTreeMap::new(),
            ),
            CanonicalJsonObject::parse(
                br#"{"artifactId":"runtime-cloud-hypervisor","config":{"controllerExecutionRef":"Host/dev-host"}}"#,
            )
            .expect("provider spec"),
        )
        .expect("provider resource");
        let resource_bundle = ResourceBundle::new(
            zone,
            vec![process, provider],
            format!("sha256:{}", "b".repeat(64)),
            BTreeMap::new(),
            BTreeMap::new(),
            Timestamp::parse("1970-01-01T00:00:00.000Z").expect("timestamp"),
        )
        .expect("resource bundle");
        let mut resource_bundle_value =
            serde_json::to_value(&resource_bundle).expect("resource bundle value");
        resource_bundle_value["processTemplates"] = serde_json::json!([{
            "processRef": "Process/controller-test",
            "ownerRef": "Provider/runtime-cloud-hypervisor",
            "executionRef": "Host/dev-host",
            "template": "controller-test",
            "artifactId": "runtime-cloud-hypervisor",
            "binaryRef": "d2b-cloud-hypervisor-controller",
            "artifactDigest": format!("sha256:{}", "a".repeat(64)),
            "binaryPath": "/nix/store/runtime-cloud-hypervisor/bin/d2b-cloud-hypervisor-controller"
        }]);
        let resource_bundle_bytes =
            serde_json::to_vec(&resource_bundle_value).expect("resource bundle bytes");
        ResourceBundle::from_json(&resource_bundle_bytes).expect("process templates");
        let host = serde_json::from_str::<HostJson>(include_str!(
            "../../../tests/fixtures/deny-unknown/host-valid.json"
        ))
        .expect("host fixture");
        let manifest = ManifestV04::from_slice(
            include_str!("../../../tests/golden/manifest_v04/baseline-vms.json").as_bytes(),
        )
        .expect("manifest fixture");
        let processes = ProcessesJson {
            schema_version: "v2".to_owned(),
            vms: Vec::new(),
        };
        let resolver = BundleResolver::from_artifacts_with_zone_resource_bundles(
            Bundle {
                bundle_version: 11,
                schema_version: "v2".to_owned(),
                public_manifest_path: "vms.json".to_owned(),
                host_path: "host.json".to_owned(),
                processes_path: "processes.json".to_owned(),
                privileges_path: "privileges.json".to_owned(),
                storage_path: None,
                sync_path: None,
                allocator_path: None,
                realm_controllers_path: None,
                realm_identity_path: None,
                realm_workloads_launcher_v2_path: None,
                unsafe_local_workloads_path: None,
                closures: Vec::new(),
                minijail_profiles: Vec::new(),
                managed_keys: Default::default(),
                generation: BundleGeneration {
                    generator: "test".to_owned(),
                    source_revision: None,
                    generated_at: None,
                },
                bundle_hash: Some("sha256:bundle".to_owned()),
                artifact_hashes: None,
            },
            host,
            processes,
            manifest,
            BTreeMap::from([("dev".to_owned(), resource_bundle_bytes)]),
        );
        let resolved = resolver
            .find_provider_controller_intent(
                &process_ref,
                "Host/dev-host",
                ProcessExecutionDomain::System,
                None,
                template,
                Some("Provider/runtime-cloud-hypervisor"),
            )
            .expect("private controller intent");
        assert_eq!(resolved.role, ProcessRole::ProviderController);
        assert_eq!(
            resolved.cgroup_placement.subtree,
            "d2b.slice/dev-host/controller-test"
        );
        assert!(!resolved.namespaces.mount);
        assert!(!resolved.namespaces.pid);
        assert!(!resolved.namespaces.net);
        assert!(!resolved.namespaces.ipc);
        assert!(!resolved.namespaces.uts);
        assert!(!resolved.namespaces.user);
        assert_eq!(
            resolved.binary_path,
            PathBuf::from(
                "/nix/store/runtime-cloud-hypervisor/bin/d2b-cloud-hypervisor-controller"
            )
        );
        assert!(
            resolver
                .find_runner_intent_for_process_in_vm(
                    None,
                    "Host/dev-host",
                    ProcessExecutionDomain::System,
                    None,
                    template,
                )
                .is_none(),
            "ProviderController must remain excluded from processes.json intents"
        );
        assert!(
            resolver
                .find_provider_controller_intent(
                    &process_ref,
                    "Host/dev-host",
                    ProcessExecutionDomain::System,
                    None,
                    template,
                    Some("Provider/wrong-owner"),
                )
                .is_none()
        );
        assert!(
            resolver
                .find_provider_controller_intent(
                    &process_ref,
                    "Host/wrong-target",
                    ProcessExecutionDomain::System,
                    None,
                    template,
                    Some("Provider/runtime-cloud-hypervisor"),
                )
                .is_none()
        );
        assert!(
            resolver
                .find_provider_controller_intent(
                    &process_ref,
                    "Host/dev-host",
                    ProcessExecutionDomain::System,
                    None,
                    "controller-wrong",
                    Some("Provider/runtime-cloud-hypervisor"),
                )
                .is_none()
        );
        let wrong_kind = ResourceRef::parse("EphemeralProcess/controller-test").expect("ref");
        assert!(
            resolver
                .find_provider_controller_intent(
                    &wrong_kind,
                    "Host/dev-host",
                    ProcessExecutionDomain::System,
                    None,
                    template,
                    Some("Provider/runtime-cloud-hypervisor"),
                )
                .is_none()
        );
    }

    fn build_personal_dev_bundle(root: &Path) -> BundleResolver {
        let bundle_dir = root.join("bundle");
        let bundle_path = bundle_dir.join("bundle.json");
        let manifest_path = bundle_dir.join("vms.json");
        let host_path = bundle_dir.join("host.json");
        let processes_path = bundle_dir.join("processes.json");
        let closure_path = bundle_dir.join("closures/personal-dev.json");

        let host = HostJson {
            schema_version: "v2".to_owned(),
            site: SitePolicy {
                allow_unsafe_east_west: false,
            },
            environments: vec![NetEnv {
                env: "personal".to_owned(),
                bridge: IfName::new("nlpersbr0").expect("bridge ifname"),
                host_uplink_ip: Some("192.0.2.1".to_owned()),
                net_uplink_ip: Some("192.0.2.2".to_owned()),
                mtu: 1500,
                mss_clamp: Some(1460),
                lan: LanPolicy {
                    allow_east_west: false,
                    effective_east_west: false,
                },
                net_vm_forward_blocklist: Vec::new(),
                external_network: None,
                bridge_port_flags: vec![BridgePortFlags {
                    role: TapRole::Uplink,
                    isolated: true,
                    neigh_suppress: true,
                    learning: Some(false),
                    unicast_flood: Some(false),
                    rule: "uplink point-to-point anti-spoofing".to_owned(),
                }],
                ipv6_sysctls: Vec::new(),
                usbip_busid_locks: vec![UsbipBusidLock {
                    vm: "personal-dev".to_owned(),
                    lock_owner: UsbipLockOwner::Daemon,
                    scope: UsbipLockScope::PerBusid,
                    bus_ids: Vec::new(),
                    vendor_product_allowlist: Vec::new(),
                }],
                usbip_backend_port: Some(3241),
            }],
            nftables: NftablesModel {
                family: "inet".to_owned(),
                table: "d2b".to_owned(),
                chains: Vec::new(),
                table_hash_after_apply: None,
                ownership_id: "ownership-test".to_owned(),
            },
            network_manager: NetworkManagerUnmanaged {
                file_path: "/etc/NetworkManager/conf.d/00-d2b-unmanaged.conf".to_owned(),
                match_criteria: vec!["interface-name:d2b-*".to_owned()],
                reload_behavior: "atomic-reload".to_owned(),
                ownership: OwnershipRule {
                    owner: "root".to_owned(),
                    group: "root".to_owned(),
                    mode: "0644".to_owned(),
                    drift_policy: "replace".to_owned(),
                },
            },
            hosts_file: HostsFileOwnership {
                start_marker: "# d2b-managed begin".to_owned(),
                end_marker: "# d2b-managed end".to_owned(),
                rule: "replace-managed-block".to_owned(),
            },
            kernel_modules: Vec::new(),
            fd_ownership: Vec::new(),
            runtime_providers: Vec::new(),
            vm_runtimes: Vec::new(),
            security_key_selectors: Vec::new(),
            cloud_hypervisor_capabilities: Vec::new(),
            if_name_mappings: Vec::<IfNameMapping>::new(),
            qemu_media: None,
            ch: Some(HostChConfig {
                net_handoff_mode: ChNetHandoffMode::TapFd,
            }),
            firewall_coexistence_policy: None,
        };

        let state_dir = "/var/lib/d2b/vms/personal-dev";
        let runtime_dir = "/run/d2b/personal-dev";
        let processes = ProcessesJson {
            schema_version: "v2".to_owned(),
            vms: vec![VmProcessDag {
                workload_identity: None,
                vm: "personal-dev".to_owned(),
                nodes: vec![
                    ProcessNode {
                        execution_ref: None,
                        execution_domain: None,
                        user_ref: None,
                        id: NodeId("host-reconcile".to_owned()),
                        role: ProcessRole::HostReconcile,
                        unit: None,
                        binary_path: None,
                        argv: Vec::new(),
                        env: Vec::new(),
                        profile: role_profile(
                            1100,
                            1100,
                            &[state_dir, "/run/d2b"],
                            "d2b.slice/personal-dev/host-reconcile",
                        ),
                        readiness: Vec::new(),
                        plan_ops: Vec::new(),
                        network_interfaces: Vec::new(),
                    },
                    ProcessNode {
                        execution_ref: None,
                        execution_domain: None,
                        user_ref: None,
                        id: NodeId("store-virtiofs-preflight".to_owned()),
                        role: ProcessRole::StoreVirtiofsPreflight,
                        unit: None,
                        binary_path: None,
                        argv: Vec::new(),
                        env: Vec::new(),
                        profile: role_profile(
                            1100,
                            1100,
                            &[state_dir, runtime_dir],
                            "d2b.slice/personal-dev/store-virtiofs-preflight",
                        ),
                        readiness: Vec::new(),
                        plan_ops: Vec::new(),
                        network_interfaces: Vec::new(),
                    },
                    ProcessNode {
                        execution_ref: None,
                        execution_domain: None,
                        user_ref: None,
                        id: NodeId("virtiofsd-ro-store".to_owned()),
                        role: ProcessRole::Virtiofsd,
                        unit: None,
                        binary_path: Some("/run/current-system/sw/bin/virtiofsd".to_owned()),
                        argv: vec!["virtiofsd".to_owned()],
                        env: Vec::new(),
                        profile: role_profile(
                            1100,
                            1100,
                            &[state_dir, runtime_dir],
                            "d2b.slice/personal-dev/virtiofsd-ro-store",
                        ),
                        readiness: Vec::new(),
                        plan_ops: Vec::new(),
                        network_interfaces: Vec::new(),
                    },
                ],
                edges: vec![
                    DagEdge {
                        from: NodeId("host-reconcile".to_owned()),
                        to: NodeId("store-virtiofs-preflight".to_owned()),
                        reason: "host before store".to_owned(),
                    },
                    DagEdge {
                        from: NodeId("store-virtiofs-preflight".to_owned()),
                        to: NodeId("virtiofsd-ro-store".to_owned()),
                        reason: "store before virtiofs".to_owned(),
                    },
                ],
                invariants: VmProcessInvariants {
                    swtpm_pre_start_flush: true,
                    per_vm_audit_pipeline: true,
                    usbip_gating: true,
                    tpm_ownership_migration_without_running_vm_mutation: true,
                },
            }],
        };

        let manifest = ManifestV04 {
            manifest: ManifestMeta {
                manifest_version: crate::manifest_v04::MANIFEST_VERSION_CURRENT,
            },
            observability: ObservabilityMeta {
                enabled: false,
                obs_vsock_cid: 3,
                obs_vsock_host_socket: "/run/d2b/obs.sock".to_owned(),
                signoz_otlp_grpc_port: 4317,
                signoz_otlp_http_port: 4318,
                signoz_url: "http://127.0.0.1:8080".to_owned(),
                vm_name: "obs".to_owned(),
            },
            vms: BTreeMap::from([(
                "personal-dev".to_owned(),
                VmEntry {
                    api_socket: Some("/run/d2b/vms/personal-dev/api.sock".to_owned()),
                    audio: false,
                    audio_service: Some(String::new()),
                    audio_state_file: Some(String::new()),
                    bridge: Some("br-personal".to_owned()),
                    env: Some("personal".to_owned()),
                    mtu: Some(1500),
                    mss_clamp: Some(1460),
                    lan: Some(VmLanPolicy {
                        allow_east_west: false,
                        effective_east_west: false,
                    }),
                    gpu_socket: Some(String::new()),
                    graphics: false,
                    is_net_vm: false,
                    name: "personal-dev".to_owned(),
                    net_vm: Some("sys-personal-net".to_owned()),
                    observability: VmObservability {
                        agent_socket: Some("/run/d2b/vms/personal-dev/agent.sock".to_owned()),
                        enabled: false,
                        vsock_cid: Some(17),
                        vsock_host_socket: Some(
                            "/run/d2b/vms/personal-dev/agent-host.sock".to_owned(),
                        ),
                    },
                    runtime: RuntimeMetadata::local_nixos(),
                    autostart: true,
                    security_key: false,
                    lifecycle: Default::default(),
                    shell: None,
                    ssh_user: Some("alice".to_owned()),
                    state_dir: state_dir.to_owned(),
                    static_ip: Some("192.0.2.20".to_owned()),
                    tap: "tap-personal-dev".to_owned(),
                    tpm: false,
                    tpm_socket: Some(String::new()),
                    usbip_yubikey: false,
                    usbipd_host_ip: Some("192.0.2.1".to_owned()),
                },
            )]),
        };

        let closure = ClosureMetadata {
            schema_version: "v2".to_owned(),
            vm: "personal-dev".to_owned(),
            toplevel: "/nix/store/personal-dev-system".to_owned(),
            closure_paths: vec!["/nix/store/personal-dev-system".to_owned()],
            db_dump_path: "/nix/store/personal-dev-registration".to_owned(),
            declared_runner: "/run/current-system/sw/bin/cloud-hypervisor".to_owned(),
            runner_parity_path: "/run/current-system/sw/bin/cloud-hypervisor".to_owned(),
            runner_parity_ok: true,
            generation: ClosureGeneration {
                host_generation: Some(7),
                vm_generation: Some("7".to_owned()),
                source_revision: Some("deadbeef".to_owned()),
                generated_at: Some("2026-01-01T00:00:00Z".to_owned()),
            },
        };

        let bundle = Bundle {
            bundle_version: 3,
            schema_version: "v2".to_owned(),
            public_manifest_path: "vms.json".to_owned(),
            host_path: "host.json".to_owned(),
            processes_path: "processes.json".to_owned(),
            privileges_path: "privileges.json".to_owned(),
            storage_path: None,
            sync_path: None,
            allocator_path: None,
            realm_controllers_path: None,
            realm_identity_path: None,
            realm_workloads_launcher_v2_path: None,
            unsafe_local_workloads_path: None,
            closures: vec![BundleClosureRef {
                vm: "personal-dev".to_owned(),
                path: "closures/personal-dev.json".to_owned(),
            }],
            minijail_profiles: Vec::new(),
            managed_keys: Default::default(),
            generation: BundleGeneration {
                generator: "test".to_owned(),
                source_revision: Some("deadbeef".to_owned()),
                generated_at: Some("2026-01-01T00:00:00Z".to_owned()),
            },
            bundle_hash: None,
            artifact_hashes: None,
        };

        write_json(&manifest_path, &manifest);
        write_json(&host_path, &host);
        write_json(&processes_path, &processes);
        write_json(&closure_path, &closure);

        // schemaVersion v2 bundles MUST carry bundleHash. Replicate the
        // bundle_resolver verify path:
        // bundleHash = sha256( serde_json::to_vec( bundle as Value
        // with artifactHashes set to null and no bundleHash field ) ).
        // serde_json (no preserve_order) emits sorted keys, matching
        // builtins.toJSON on the Nix side.
        let mut as_value: serde_json::Value =
            serde_json::to_value(&bundle).expect("serialize bundle to value");
        if let serde_json::Value::Object(map) = &mut as_value {
            map.remove("bundleHash");
            map.insert("artifactHashes".to_owned(), serde_json::Value::Null);
        }
        let canonical =
            serde_json::to_vec(&as_value).expect("canonical-serialize bundle for hashing");
        let digest = {
            use sha2::Digest as _;
            let raw: [u8; 32] = sha2::Sha256::digest(&canonical).into();
            let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
            format!("sha256:{hex}")
        };
        if let serde_json::Value::Object(map) = &mut as_value {
            map.insert("bundleHash".to_owned(), serde_json::Value::String(digest));
        }
        let with_hash = serde_json::to_vec(&as_value).expect("re-serialize bundle");
        fs::write(&bundle_path, with_hash).expect("write bundle with hash");

        // Production policy requires root:d2bd owner + 0640 mode;
        // use a current-user policy so the test runs as
        // a non-root developer too (matches the pattern in
        // tests/bundle_resolver_tamper.rs current_user_policy()).
        // fs::write defaults to 0644 (minus umask); chmod the bundle
        // to 0640 to satisfy the verifier's mode check.
        use std::os::unix::fs::PermissionsExt as _;
        for p in [
            &bundle_path,
            &manifest_path,
            &host_path,
            &processes_path,
            &closure_path,
        ] {
            fs::set_permissions(p, fs::Permissions::from_mode(0o640))
                .expect("chmod test bundle artifact");
        }
        let test_policy = BundleVerifyPolicy {
            required_uid: rustix::process::getuid().as_raw(),
            required_gid: Some(rustix::process::getgid().as_raw()),
            required_mode: 0o640,
        };
        BundleResolver::load_with_policy(&bundle_path, &test_policy)
            .expect("load personal-dev test bundle")
    }

    fn write_hashed_test_bundle(bundle_path: &Path, mut as_value: serde_json::Value) {
        if let serde_json::Value::Object(map) = &mut as_value {
            map.remove("bundleHash");
            map.insert("artifactHashes".to_owned(), serde_json::Value::Null);
        }
        let canonical =
            serde_json::to_vec(&as_value).expect("canonical-serialize bundle for hashing");
        let digest = {
            use sha2::Digest as _;
            let raw: [u8; 32] = sha2::Sha256::digest(&canonical).into();
            let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
            format!("sha256:{hex}")
        };
        if let serde_json::Value::Object(map) = &mut as_value {
            map.insert("bundleHash".to_owned(), serde_json::Value::String(digest));
        }
        fs::write(
            bundle_path,
            serde_json::to_vec(&as_value).expect("serialize bundle with hash"),
        )
        .expect("write bundle with hash");
    }

    fn current_user_bundle_policy() -> BundleVerifyPolicy {
        BundleVerifyPolicy {
            required_uid: rustix::process::getuid().as_raw(),
            required_gid: Some(rustix::process::getgid().as_raw()),
            required_mode: 0o640,
        }
    }

    #[test]
    fn loads_zone_native_bundle_index_without_legacy_artifacts() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = test_root("zone-native-bundle-index");
        fs::create_dir_all(&root).expect("create bundle root");
        let bundle_path = root.join("bundle.json");
        let mut bundle = serde_json::json!({
            "artifactHashes": null,
            "bundleVersion": 1,
            "schemaVersion": "v3",
            "privilegesPath": "privileges.json",
            "zones": [],
            "generation": {
                "generator": "nixos-modules/bundle.nix",
                "sourceRevision": null,
                "generatedAt": null
            }
        });
        let hash =
            sha256_hex(&serde_json::to_vec(&bundle).expect("serialize bundle hash preimage"));
        bundle["artifactHashes"] = serde_json::json!({});
        bundle["bundleHash"] = serde_json::Value::String(hash);
        fs::write(
            &bundle_path,
            serde_json::to_vec(&bundle).expect("serialize bundle"),
        )
        .expect("write bundle");
        fs::set_permissions(&bundle_path, fs::Permissions::from_mode(0o640)).expect("chmod bundle");

        let resolver =
            BundleResolver::load_with_policy(&bundle_path, &current_user_bundle_policy())
                .expect("Zone-native bundle index loads");
        assert_eq!(resolver.bundle.bundle_version, 1);
        assert_eq!(resolver.bundle.schema_version, "v3");
        assert_eq!(
            Path::new(&resolver.bundle.host_path).parent(),
            Some(root.as_path())
        );
        assert!(resolver.zone_resource_bundles.is_empty());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn zone_native_bundle_index_rejects_artifact_paths_outside_bundle_root() {
        assert!(normalize_zone_native_ref(Path::new("/etc/d2b"), "../foreign").is_err());
        assert!(normalize_zone_native_ref(Path::new("/etc/d2b"), "/etc/foreign").is_err());
    }

    #[test]
    fn zone_native_index_supplies_sealed_runtime_topology() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = test_root("zone-native-topology");
        fs::create_dir_all(&root).expect("create bundle root");
        let parent_map = BTreeMap::from([
            ("local-root".to_owned(), None),
            ("work".to_owned(), Some("local-root".to_owned())),
        ]);
        let parent_map_bytes = serde_json::to_vec(&parent_map).expect("serialize parent map");
        let index = serde_json::json!({
            "schemaVersion": "v1",
            "zones": {
                "local-root": {},
                "work": {}
            },
            "topology": {
                "sealed": true,
                "parentMap": parent_map,
                "parentMapDigest": framed_canonical_digest(
                    "d2b:v3:parent-topology",
                    &parent_map_bytes,
                ),
                "generationByZone": {
                    "local-root": format!("sha256:{}", "a".repeat(64)),
                    "work": format!("sha256:{}", "b".repeat(64))
                }
            },
            "executionIndex": {},
            "networkIndex": {},
            "closureIndex": {}
        });
        let index_bytes = serde_json::to_vec(&index).expect("serialize index");
        let index_path = root.join("index.json");
        fs::write(&index_path, &index_bytes).expect("write index");
        fs::set_permissions(&index_path, fs::Permissions::from_mode(0o640)).expect("chmod index");
        let bundle = Bundle {
            bundle_version: 1,
            schema_version: "v3".to_owned(),
            public_manifest_path: "vms.json".to_owned(),
            host_path: "host.json".to_owned(),
            processes_path: "processes.json".to_owned(),
            privileges_path: "privileges.json".to_owned(),
            storage_path: None,
            sync_path: None,
            allocator_path: None,
            realm_controllers_path: None,
            realm_identity_path: None,
            realm_workloads_launcher_v2_path: None,
            unsafe_local_workloads_path: None,
            closures: Vec::new(),
            minijail_profiles: Vec::new(),
            managed_keys: Default::default(),
            generation: BundleGeneration {
                generator: "test".to_owned(),
                source_revision: None,
                generated_at: None,
            },
            bundle_hash: None,
            artifact_hashes: Some(BTreeMap::from([(
                "index.json".to_owned(),
                sha256_hex(&index_bytes),
            )])),
        };
        let zone_bundles = BTreeMap::from([
            ("local-root".to_owned(), Vec::new()),
            ("work".to_owned(), Vec::new()),
        ]);

        let topology =
            load_zone_native_topology(&bundle, &zone_bundles, &root, &current_user_bundle_policy())
                .expect("load topology")
                .expect("topology present");
        assert_eq!(topology.root.as_str(), "local-root");
        assert_eq!(
            topology
                .parent_map
                .get(&ZoneId::parse("work").unwrap())
                .and_then(Option::as_ref)
                .map(ZoneId::as_str),
            Some("local-root")
        );

        let _ = fs::remove_dir_all(root);
    }

    fn realm_controllers_artifact_value(no_systemd_units_materialized: bool) -> serde_json::Value {
        serde_json::json!({
            "schemaVersion": "v2",
            "runtimeState": "metadata-only",
            "controllers": [
                {
                    "realmName": "Home",
                    "realmId": "home",
                    "realmPath": "home",
                    "placement": "host-local",
                    "daemon": {
                        "user": "d2br-0123456789abcdef",
                        "group": "d2br-0123456789abcdef",
                        "publicSocketGroup": "d2bra-0123456789abcdef",
                        "serviceName": "d2b-realm-0123456789abcdef-daemon.service",
                        "configPath": "/etc/d2b/realms/home/daemon-config.json",
                        "stateLockPath": "/run/d2b/realms/home/daemon.lock",
                        "locksDir": "/run/d2b/realms/home/locks",
                        "socketActivated": false,
                        "materializedService": !no_systemd_units_materialized
                    },
                    "broker": {
                        "enabled": true,
                        "hostMutation": true,
                        "user": "root",
                        "group": "d2br-0123456789abcdef",
                        "socketPath": "/run/d2b/realms/home/broker.sock",
                        "socketUnitName": "d2b-realm-0123456789abcdef-priv-broker.socket",
                        "serviceUnitName": "d2b-realm-0123456789abcdef-priv-broker.service",
                        "auditDir": "/var/lib/d2b/realms/home/audit",
                        "materializedSocket": !no_systemd_units_materialized,
                        "materializedService": !no_systemd_units_materialized
                    },
                    "paths": {
                        "runDir": "/run/d2b/realms/home",
                        "stateDir": "/var/lib/d2b/realms/home",
                        "auditDir": "/var/lib/d2b/realms/home/audit"
                    },
                    "sockets": {
                        "publicSocketPath": "/run/d2b/realms/home/public.sock",
                        "brokerSocketPath": "/run/d2b/realms/home/broker.sock"
                    },
                    "allocator": {
                        "kind": "local-root-metadata",
                        "configPath": "/etc/d2b/allocator.json",
                        "rootSocket": "/run/d2b/allocator/local-root.sock",
                        "resourceRequestRefs": ["realm-home-state"]
                    },
                    "access": {
                        "allowedUsers": ["alice"],
                        "allowedGroups": ["realm-home"],
                        "inheritedAdminUsers": []
                    },
                    "providers": []
                }
            ],
            "invariants": {
                "metadataOnly": true,
                "noSystemdUnitsMaterialized": no_systemd_units_materialized,
                "preservesGlobalDaemonBehavior": true,
                "preservesDirectUnixSocketSemantics": true
            }
        })
    }

    fn realm_identity_artifact_value() -> serde_json::Value {
        serde_json::json!({
            "schemaVersion": "v2",
            "runtimeState": "metadata-only",
            "realms": [
                {
                    "realm": ["home"],
                    "realmIdentityRef": "idref-home",
                    "realmIdentityFingerprint": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    "controllerCredentialRef": "cgref-home",
                    "controllerCredentialFingerprint": "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
                    "trustBundleRef": "trust-home",
                    "enrollmentRef": "enroll-home",
                    "rotationPolicyRef": "rotate-home"
                }
            ],
            "invariants": {
                "metadataOnly": true,
                "noSecretMaterial": true,
                "preservesRuntimeBehavior": true
            }
        })
    }

    #[test]
    fn bundle_resolver_loads_realm_controller_artifact() {
        let root = test_root("realm-controller-artifact");
        let _baseline = build_personal_dev_bundle(&root);
        let bundle_dir = root.join("bundle");
        let bundle_path = bundle_dir.join("bundle.json");
        let realm_controllers_path = bundle_dir.join("realm-controllers.json");

        write_json(
            &realm_controllers_path,
            &realm_controllers_artifact_value(false),
        );

        let mut bundle_value: serde_json::Value =
            serde_json::from_slice(&fs::read(&bundle_path).expect("read bundle json"))
                .expect("bundle json parses");
        if let serde_json::Value::Object(map) = &mut bundle_value {
            map.insert(
                "realmControllersPath".to_owned(),
                serde_json::Value::String("realm-controllers.json".to_owned()),
            );
        }
        write_hashed_test_bundle(&bundle_path, bundle_value);

        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&bundle_path, fs::Permissions::from_mode(0o640)).expect("chmod bundle");
        fs::set_permissions(&realm_controllers_path, fs::Permissions::from_mode(0o640))
            .expect("chmod realm controllers");

        let resolver =
            BundleResolver::load_with_policy(&bundle_path, &current_user_bundle_policy())
                .expect("load bundle with realm controllers");
        let controllers = resolver
            .realm_controllers
            .as_ref()
            .expect("realm controller artifact loaded");
        assert_eq!(controllers.controllers.len(), 1);
        assert_eq!(controllers.controllers[0].realm_path.as_str(), "home");
        assert!(controllers.controllers[0].daemon.materialized_service);

        let mut invalid = realm_controllers_artifact_value(true);
        invalid["controllers"][0]["daemon"]["materializedService"] = serde_json::Value::Bool(true);
        write_json(&realm_controllers_path, &invalid);
        fs::set_permissions(&realm_controllers_path, fs::Permissions::from_mode(0o640))
            .expect("chmod invalid realm controllers");
        let err = BundleResolver::load_with_policy(&bundle_path, &current_user_bundle_policy())
            .expect_err("bundle resolver rejects invalid realm controller metadata");
        assert!(
            err.to_string().contains("realm-controllers.json"),
            "error names realm-controller artifact: {err}"
        );
    }

    #[test]
    fn bundle_resolver_loads_realm_identity_artifact() {
        let root = test_root("realm-identity-artifact");
        let _baseline = build_personal_dev_bundle(&root);
        let bundle_dir = root.join("bundle");
        let bundle_path = bundle_dir.join("bundle.json");
        let realm_identity_path = bundle_dir.join("realm-identity.json");

        write_json(&realm_identity_path, &realm_identity_artifact_value());

        let mut bundle_value: serde_json::Value =
            serde_json::from_slice(&fs::read(&bundle_path).expect("read bundle json"))
                .expect("bundle json parses");
        if let serde_json::Value::Object(map) = &mut bundle_value {
            map.insert(
                "realmIdentityPath".to_owned(),
                serde_json::Value::String("realm-identity.json".to_owned()),
            );
        }
        write_hashed_test_bundle(&bundle_path, bundle_value);

        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&bundle_path, fs::Permissions::from_mode(0o640)).expect("chmod bundle");
        fs::set_permissions(&realm_identity_path, fs::Permissions::from_mode(0o640))
            .expect("chmod realm identity");

        let resolver =
            BundleResolver::load_with_policy(&bundle_path, &current_user_bundle_policy())
                .expect("load bundle with realm identity");
        let identity = resolver
            .realm_identity
            .as_ref()
            .expect("realm identity artifact loaded");
        assert_eq!(identity.realms.len(), 1);
        assert_eq!(identity.realms[0].realm.target_form(), "home");
        assert!(identity.realms[0].realm_identity_ref.is_some());

        let mut invalid = realm_identity_artifact_value();
        invalid["invariants"]["noSecretMaterial"] = serde_json::Value::Bool(false);
        write_json(&realm_identity_path, &invalid);
        fs::set_permissions(&realm_identity_path, fs::Permissions::from_mode(0o640))
            .expect("chmod invalid realm identity");
        let err = BundleResolver::load_with_policy(&bundle_path, &current_user_bundle_policy())
            .expect_err("bundle resolver rejects invalid realm identity metadata");
        let err_text = err.to_string();
        assert!(
            err_text.contains("realm-identity.json"),
            "error names realm-identity artifact: {err}"
        );
        assert!(
            !err_text.contains(realm_identity_path.to_string_lossy().as_ref()),
            "realm identity parse errors must not expose host paths: {err_text}"
        );
    }

    #[test]
    fn bundle_resolver_defaults_absent_realm_identity_to_none() {
        let root = test_root("realm-identity-absent");
        let resolver = build_personal_dev_bundle(&root);

        assert!(resolver.bundle.realm_identity_path.is_none());
        assert!(resolver.realm_identity.is_none());
        assert!(
            !root.join("bundle/realm-identity.json").exists(),
            "baseline bundles without realmIdentityPath must not require a realm-identity file"
        );
    }

    #[test]
    fn closure_identity_uses_toplevel_basename() {
        let intent = ResolvedStoreViewIntent {
            intent_id: intent_id_legacy_store_view("corp-vm"),
            vm: "corp-vm".to_owned(),
            generation: 42,
            hardlink_farm_path: PathBuf::from("/var/lib/d2b/vms/corp-vm/store-view"),
            target_view_path: PathBuf::from(
                "/var/lib/d2b/vms/corp-vm/store-view/live/abc123-nixos-system-corp",
            ),
            closure_paths: Vec::new(),
            db_dump_path: PathBuf::from("/nix/store/corp-vm-registration"),
        };
        // Identity is the toplevel basename (carries the Nix input hash),
        // so two distinct closures of one VM never share an identity even
        // if their u32 generation numbers collide.
        assert_eq!(
            intent.closure_identity(),
            "toplevel:abc123-nixos-system-corp"
        );
    }

    #[test]
    fn host_reconcile_and_store_preflight_emit_executable_vm_start_intents() {
        let root = test_root("vm-start-intents");
        let resolver = build_personal_dev_bundle(&root);

        let host = resolver
            .resolve_vm_start_intent("personal-dev", "host-reconcile")
            .expect("host reconcile intent");
        assert!(!host.is_readiness_only());
        assert!(matches!(
            host.actions.as_slice(),
            [
                ResolvedVmStartAction::PrepareRuntimeDir(runtime),
                ResolvedVmStartAction::PrepareStateDir(state),
            ] if runtime.base_dir == Path::new("/run/d2b/vms/personal-dev")
                && state.base_dir == Path::new("/var/lib/d2b/vms/personal-dev")
        ));

        let store = resolver
            .resolve_vm_start_intent("personal-dev", "store-virtiofs-preflight")
            .expect("store preflight intent");
        assert!(!store.is_readiness_only());
        assert!(matches!(
            store.actions.as_slice(),
            [ResolvedVmStartAction::PrepareStoreView(intent)]
                if intent.hardlink_farm_path == Path::new("/var/lib/d2b/vms/personal-dev/store-view")
        ));

        let prerequisites =
            resolver.resolve_vm_start_prerequisites("personal-dev", "virtiofsd-ro-store");
        assert_eq!(
            prerequisites
                .iter()
                .map(|intent| intent.role_id.as_str())
                .collect::<Vec<_>>(),
            vec!["host-reconcile", "store-virtiofs-preflight"]
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn resolves_macvtap_intents_from_process_contract() {
        let root = test_root("macvtap-intents");
        let mut resolver = build_personal_dev_bundle(&root);
        resolver.processes.vms[0].nodes.push(ProcessNode {
            execution_ref: None,
            execution_domain: None,
            user_ref: None,
            id: NodeId("cloud-hypervisor".to_owned()),
            role: ProcessRole::CloudHypervisorRunner,
            unit: None,
            binary_path: Some("/nix/store/cloud-hypervisor/bin/cloud-hypervisor".to_owned()),
            argv: vec![
                "cloud-hypervisor".to_owned(),
                "--kernel".to_owned(),
                "/nix/store/guest-system/kernel".to_owned(),
                "--initramfs".to_owned(),
                "/nix/store/guest-system/initrd".to_owned(),
                "--cmdline".to_owned(),
                "init=/nix/store/guest-system/init".to_owned(),
                "--api-socket".to_owned(),
                "/var/lib/d2b/zones/personal/guests/personal-dev/personal-dev.sock".to_owned(),
                "--net".to_owned(),
                "tap=personal-u2,mac=02:00:00:00:00:01".to_owned(),
                "fd=10,mac=02:00:00:00:00:02".to_owned(),
            ],
            env: Vec::new(),
            profile: role_profile(
                1200,
                1200,
                &["/var/lib/d2b/vms/personal-dev"],
                "d2b.slice/personal-dev/cloud-hypervisor",
            ),
            readiness: Vec::new(),
            plan_ops: Vec::new(),
            network_interfaces: vec![
                ProcessNetworkInterface {
                    type_: ProcessNetworkInterfaceType::Tap,
                    id: "personal-u2".to_owned(),
                    mac: "02:00:00:00:00:01".to_owned(),
                    macvtap: None,
                },
                ProcessNetworkInterface {
                    type_: ProcessNetworkInterfaceType::Macvtap,
                    id: "personal-h0".to_owned(),
                    mac: "02:00:00:00:00:02".to_owned(),
                    macvtap: Some(ProcessMacvtapInterface {
                        link: "eno1".to_owned(),
                        mode: ProcessMacvtapMode::Bridge,
                    }),
                },
            ],
        });

        let intents = resolver
            .resolve_macvtap_intents("personal-dev", "cloud-hypervisor")
            .expect("macvtap intents resolve");
        assert_eq!(intents.len(), 1);
        assert_eq!(intents[0].ifname.as_str(), "personal-h0");
        assert_eq!(intents[0].parent_ifname.as_str(), "eno1");
        assert_eq!(intents[0].mode, ProcessMacvtapMode::Bridge);
        assert_eq!(intents[0].fd, 10);
        resolver.runner_intents = build_runner_intents(&resolver.processes);
        assert!(
            resolver
                .find_runner_intent_for_process_in_vm(
                    Some("personal-dev"),
                    "Host/host-system",
                    ProcessExecutionDomain::System,
                    None,
                    "cloud-hypervisor-runner",
                )
                .is_some(),
            "the controller-owned VMM child template resolves to the trusted runner intent"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn network_tap_intent_ref_binds_full_provenance_and_role() {
        let zone_uid =
            ResourceUid::parse("223e4567-e89b-42d3-a456-426614174001").expect("zone uid");
        let network_uid =
            ResourceUid::parse("323e4567-e89b-42d3-a456-426614174002").expect("network uid");
        let attachment_uid =
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").expect("attachment uid");
        let bundle_generation = d2b_contracts_resource::v3::ResourceBundleGenerationId::parse(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .expect("bundle generation");
        let intent = intent_id_network_tap(
            &zone_uid,
            &network_uid,
            &attachment_uid,
            d2b_contracts_resource::v3::ResourceGeneration::new(4).unwrap(),
            d2b_contracts_resource::v3::ResourceGeneration::new(7).unwrap(),
            &bundle_generation,
            "runner-lan",
            "corp-vm",
        );

        assert!(intent.starts_with("network-tap:"));
        assert!(intent.len() <= 192);
        assert_ne!(
            intent,
            intent_id_network_tap(
                &zone_uid,
                &network_uid,
                &attachment_uid,
                d2b_contracts_resource::v3::ResourceGeneration::new(5).unwrap(),
                d2b_contracts_resource::v3::ResourceGeneration::new(7).unwrap(),
                &bundle_generation,
                "runner-lan",
                "corp-vm",
            )
        );
        assert_ne!(
            intent,
            intent_id_network_tap(
                &zone_uid,
                &network_uid,
                &attachment_uid,
                d2b_contracts_resource::v3::ResourceGeneration::new(4).unwrap(),
                d2b_contracts_resource::v3::ResourceGeneration::new(7).unwrap(),
                &bundle_generation,
                "runner-uplink",
                "corp-vm",
            )
        );
        let bridge = derive_network_ifname(&zone_uid, &network_uid, NetworkIfRole::LanBridge, None)
            .expect("bridge name");
        let tap = derive_network_ifname(
            &zone_uid,
            &network_uid,
            NetworkIfRole::WorkloadGuestTap,
            Some(&attachment_uid),
        )
        .expect("tap name");
        assert_ne!(bridge, tap);
    }

    #[test]
    fn v3_tap_resolution_ignores_legacy_env_and_manifest_names() {
        let root = test_root("tap-resolution-uid-authority");
        let mut resolver = build_personal_dev_bundle(&root);
        resolver.processes.vms[0].nodes.push(ProcessNode {
            execution_ref: None,
            execution_domain: None,
            user_ref: None,
            id: NodeId("cloud-hypervisor".to_owned()),
            role: ProcessRole::CloudHypervisorRunner,
            unit: None,
            binary_path: Some("/run/current-system/sw/bin/cloud-hypervisor".to_owned()),
            argv: Vec::new(),
            env: vec!["D2B_NETWORK=attacker".to_owned()],
            profile: role_profile(
                1200,
                1200,
                &["/var/lib/d2b/vms/personal-dev"],
                "d2b.slice/personal-dev/cloud-hypervisor",
            ),
            readiness: Vec::new(),
            plan_ops: Vec::new(),
            network_interfaces: Vec::new(),
        });
        let zone_uid =
            ResourceUid::parse("223e4567-e89b-42d3-a456-426614174001").expect("zone uid");
        let network_uid =
            ResourceUid::parse("323e4567-e89b-42d3-a456-426614174002").expect("network uid");
        let attachment_uid =
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").expect("attachment uid");
        let provenance = NetworkProvenance::new(
            zone_uid.clone(),
            network_uid.clone(),
            d2b_contracts_resource::v3::ResourceGeneration::new(4).unwrap(),
            d2b_contracts_resource::v3::ResourceGeneration::new(7).unwrap(),
            d2b_contracts_resource::v3::ResourceBundleGenerationId::parse(
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )
            .unwrap(),
        );
        let first = resolver
            .resolve_tap_intent(
                "personal-dev",
                "ch",
                provenance.clone(),
                attachment_uid.clone(),
            )
            .expect("v3 TAP intent");
        resolver.host.environments[0].env = "attacker".to_owned();
        resolver.manifest.vms.get_mut("personal-dev").unwrap().env = Some("attacker".to_owned());
        let second = resolver
            .resolve_tap_intent("personal-dev", "ch", provenance, attachment_uid)
            .expect("v3 TAP intent after legacy mutation");
        assert_eq!(first, second);
        assert_eq!(
            first.bridge_ifname,
            derive_network_ifname(&zone_uid, &network_uid, NetworkIfRole::LanBridge, None).unwrap()
        );
        assert_eq!(
            first.tap_ifname,
            derive_network_ifname(
                &zone_uid,
                &network_uid,
                NetworkIfRole::WorkloadGuestTap,
                Some(&ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap()),
            )
            .unwrap()
        );
        let _ = fs::remove_dir_all(root);
    }

    fn network_resource_bundle_bytes(
        zone: &str,
        zone_uid: &ResourceUid,
        network_uid: &ResourceUid,
        network_name: &str,
        lan_cidr: &str,
        uplink_cidr: &str,
    ) -> Vec<u8> {
        let spec = NetworkSpec::minimal(
            Ipv4Cidr::parse(lan_cidr).unwrap(),
            Ipv4Cidr::parse(uplink_cidr).unwrap(),
            BoundedToken::parse("net-vm-base").unwrap(),
        )
        .unwrap();
        let mut annotations = BTreeMap::new();
        annotations.insert("networkUid".to_owned(), network_uid.as_str().to_owned());
        let resource = BundleResource::new(
            ResourceTypeName::parse("Network").unwrap(),
            BundleResourceMetadata::new(
                ResourceName::parse(network_name).unwrap(),
                ZoneId::parse(zone).unwrap(),
                None,
                BTreeMap::new(),
                annotations,
            ),
            CanonicalJsonObject::parse(&serde_json::to_vec(&spec).unwrap()).unwrap(),
        )
        .unwrap();
        let bundle = ResourceBundle::new(
            ZoneId::parse(zone).unwrap(),
            vec![resource],
            "sha256:".to_owned() + &"0".repeat(64),
            BTreeMap::new(),
            BTreeMap::new(),
            Timestamp::parse("2026-08-26T00:00:00.000Z").unwrap(),
        )
        .unwrap()
        .with_zone_uid(zone_uid.clone());
        d2b_contracts_resource::v3::canonical_json_bytes(&bundle).unwrap()
    }

    #[test]
    fn resource_network_intents_use_uid_derived_kernel_names() {
        let zone_a = ResourceUid::parse("323e4567-e89b-42d3-a456-426614174002").expect("zone uid");
        let zone_b = ResourceUid::parse("423e4567-e89b-42d3-a456-426614174003").expect("zone uid");
        let network_a =
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").expect("network uid");
        let network_b =
            ResourceUid::parse("223e4567-e89b-42d3-a456-426614174001").expect("network uid");
        let bundles = BTreeMap::from([
            (
                "work".to_owned(),
                network_resource_bundle_bytes(
                    "work",
                    &zone_a,
                    &network_a,
                    "same-name",
                    "10.20.0.0/24",
                    "192.0.2.0/30",
                ),
            ),
            (
                "personal".to_owned(),
                network_resource_bundle_bytes(
                    "personal",
                    &zone_b,
                    &network_b,
                    "same-name",
                    "10.30.0.0/24",
                    "198.51.100.0/30",
                ),
            ),
        ]);
        let (_, _, bridges, routes, _, _) = build_resource_network_intents(&bundles, true);
        let first_bridge_id =
            intent_id_network_bridge_uids(&zone_a, &network_a, "same-name", false);
        let second_bridge_id =
            intent_id_network_bridge_uids(&zone_b, &network_b, "same-name", false);
        let first_bridge = bridges.get(&first_bridge_id).expect("first bridge");
        let second_bridge = bridges.get(&second_bridge_id).expect("second bridge");
        assert_eq!(
            first_bridge.bridge_ifname,
            derive_network_ifname(&zone_a, &network_a, NetworkIfRole::LanBridge, None).unwrap()
        );
        assert_eq!(
            second_bridge.bridge_ifname,
            derive_network_ifname(&zone_b, &network_b, NetworkIfRole::LanBridge, None).unwrap()
        );
        assert_ne!(first_bridge.bridge_ifname, second_bridge.bridge_ifname);
        let first_route_id = intent_id_network_route_uids(&zone_a, &network_a, "same-name", 0);
        let second_route_id = intent_id_network_route_uids(&zone_b, &network_b, "same-name", 0);
        assert_eq!(
            routes
                .get(&first_route_id)
                .and_then(|intent| intent.route_name.as_deref()),
            Some(derive_network_route_name(&zone_a, &network_a, 0).as_str())
        );
        assert_eq!(
            routes
                .get(&second_route_id)
                .and_then(|intent| intent.route_name.as_deref()),
            Some(derive_network_route_name(&zone_b, &network_b, 0).as_str())
        );
        assert_ne!(
            routes
                .get(&first_route_id)
                .and_then(|intent| intent.route_name.as_deref()),
            routes
                .get(&second_route_id)
                .and_then(|intent| intent.route_name.as_deref())
        );
    }

    #[test]
    fn resolved_network_effects_bind_complete_provenance_and_markers() {
        let root = test_root("network-effect-provenance");
        let zone_uid =
            ResourceUid::parse("323e4567-e89b-42d3-a456-426614174002").expect("zone uid");
        let network_uid =
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").expect("network uid");
        let provenance = NetworkProvenance::new(
            zone_uid.clone(),
            network_uid.clone(),
            d2b_contracts_resource::v3::ResourceGeneration::new(4).unwrap(),
            d2b_contracts_resource::v3::ResourceGeneration::new(7).unwrap(),
            d2b_contracts_resource::v3::ResourceBundleGenerationId::parse(
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )
            .unwrap(),
        );
        let mut resolver = build_personal_dev_bundle(&root);
        resolver.zone_resource_bundles.insert(
            "work".to_owned(),
            network_resource_bundle_bytes(
                "work",
                &zone_uid,
                &network_uid,
                "work-net",
                "10.20.0.0/24",
                "192.0.2.0/30",
            ),
        );

        let bridge_id = intent_id_network_bridge_uids(&zone_uid, &network_uid, "work-net", false);
        let bridge = resolver
            .resolve_network_bridge_intent(&bridge_id, &provenance)
            .expect("resolved Network bridge");
        assert_eq!(bridge.provenance.as_ref(), Some(&provenance));
        assert_eq!(
            bridge.ownership_marker.as_deref(),
            Some(
                format!(
                    "d2b managed: {}",
                    d2b_contracts_resource::v3::derive_network_ownership_marker(
                        &provenance,
                        "bridge:lan",
                    )
                )
                .as_str()
            )
        );

        let route_id = intent_id_network_route_uids(&zone_uid, &network_uid, "work-net", 0);
        let route = resolver
            .resolve_network_route_intent(&route_id, &provenance)
            .expect("resolved Network route");
        assert_eq!(route.provenance.as_ref(), Some(&provenance));
        assert_eq!(
            route.ownership_marker.as_deref(),
            Some(
                format!(
                    "d2b managed: {}",
                    d2b_contracts_resource::v3::derive_network_ownership_marker(
                        &provenance,
                        &format!("route:{}", route.route_name.as_deref().expect("route name"),),
                    )
                )
                .as_str()
            )
        );

        let marker_id =
            intent_id_network_ownership_marker_uids(&zone_uid, &network_uid, "work-net");
        let marker = resolver
            .resolve_network_marker_intent(&marker_id, &provenance)
            .expect("resolved Network ownership marker");
        assert_eq!(marker.provenance.as_ref(), Some(&provenance));
        assert_eq!(
            marker.marker,
            d2b_contracts_resource::v3::derive_network_ownership_marker(&provenance, "firewall",)
        );
        let _ = fs::remove_dir_all(root);
    }

    // W3: negative-case coverage for BundleResolver::validate_minijail_profiles.
    // The static-invariant-uid0 / minijail-validator bash gates were the ONLY
    // coverage of these rejection paths; these unit tests bring the invariant
    // logic into Rust so those gates can retire to a Rust successor (plus the
    // positive contract test over the rendered fixture bundle in
    // owner-local rendered fixture contract). Each
    // mutates ONE invariant on the first node of the otherwise-valid
    // personal-dev bundle and asserts the matching violation (validate returns
    // on the first violation, and vms[0].nodes[0] is iterated first).
    #[test]
    fn validate_minijail_profiles_accepts_the_rendered_personal_dev_bundle() {
        let root = test_root("minijail-valid-baseline");
        let resolver = build_personal_dev_bundle(&root);
        assert!(
            resolver.validate_minijail_profiles().is_ok(),
            "the rendered personal-dev bundle must pass every minijail invariant"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn validate_minijail_profiles_rejects_empty_profile_id() {
        let root = test_root("minijail-empty-id");
        let mut resolver = build_personal_dev_bundle(&root);
        resolver.processes.vms[0].nodes[0].profile.profile_id = String::new();
        assert!(
            matches!(
                resolver.validate_minijail_profiles(),
                Err(MinijailProfileViolation::EmptyProfileId { .. })
            ),
            "an empty profile_id must be rejected"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn validate_minijail_profiles_rejects_root_uid_without_carve_out() {
        let root = test_root("minijail-root-no-carveout");
        let mut resolver = build_personal_dev_bundle(&root);
        {
            let p = &mut resolver.processes.vms[0].nodes[0].profile;
            p.uid = 0;
            p.adr_carve_out = None;
        }
        assert!(
            matches!(
                resolver.validate_minijail_profiles(),
                Err(MinijailProfileViolation::RootWithoutCarveOut { uid: 0, .. })
            ),
            "uid 0 without an ADR carve-out must be rejected"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn validate_minijail_profiles_rejects_writable_nix_store_without_carve_out() {
        let root = test_root("minijail-store-rw");
        let mut resolver = build_personal_dev_bundle(&root);
        {
            let p = &mut resolver.processes.vms[0].nodes[0].profile;
            p.adr_carve_out = None;
            p.mount_policy.nix_store_read_only = false;
        }
        assert!(
            matches!(
                resolver.validate_minijail_profiles(),
                Err(MinijailProfileViolation::NixStoreNotReadOnly { .. })
            ),
            "a writable /nix/store without an ADR carve-out must be rejected"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn validate_minijail_profiles_rejects_cgroup_subtree_outside_d2b() {
        let root = test_root("minijail-cgroup-foreign");
        let mut resolver = build_personal_dev_bundle(&root);
        resolver.processes.vms[0].nodes[0]
            .profile
            .cgroup_placement
            .subtree = "system.slice/evil".to_owned();
        assert!(
            matches!(
                resolver.validate_minijail_profiles(),
                Err(MinijailProfileViolation::CgroupSubtreeOutsideD2b { .. })
            ),
            "a cgroup subtree outside d2b/ must be rejected"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn validate_minijail_profiles_accepts_root_uid_with_carve_out() {
        let root = test_root("minijail-root-with-carveout");
        let mut resolver = build_personal_dev_bundle(&root);
        {
            let p = &mut resolver.processes.vms[0].nodes[0].profile;
            p.uid = 0;
            p.adr_carve_out =
                Some("ADR 0004 swtpm-flush requires uid 0 for /dev/tpm access".to_owned());
        }
        assert!(
            resolver.validate_minijail_profiles().is_ok(),
            "uid 0 WITH an ADR carve-out must be accepted (the swtpm-flush pattern)"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn validate_minijail_profiles_rejects_root_uid_with_empty_carve_out() {
        let root = test_root("minijail-root-empty-carveout");
        let mut resolver = build_personal_dev_bundle(&root);
        {
            let p = &mut resolver.processes.vms[0].nodes[0].profile;
            p.uid = 0;
            // An empty (or whitespace-only) carve-out is NOT a real ADR
            // reference and must not satisfy the uid0 gate.
            p.adr_carve_out = Some("   ".to_owned());
        }
        assert!(
            matches!(
                resolver.validate_minijail_profiles(),
                Err(MinijailProfileViolation::RootWithoutCarveOut { uid: 0, .. })
            ),
            "uid 0 with an empty/whitespace adr_carve_out must be rejected"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn validate_minijail_profiles_rejects_root_gid_without_carve_out() {
        let root = test_root("minijail-root-gid-no-carveout");
        let mut resolver = build_personal_dev_bundle(&root);
        {
            let p = &mut resolver.processes.vms[0].nodes[0].profile;
            // uid stays non-root (1100); gid 0 alone must also be rejected
            // (the validator gates on uid == 0 || gid == 0).
            p.gid = 0;
            p.adr_carve_out = None;
        }
        assert!(
            matches!(
                resolver.validate_minijail_profiles(),
                Err(MinijailProfileViolation::RootWithoutCarveOut { gid: 0, .. })
            ),
            "gid 0 without an ADR carve-out must be rejected"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn usbip_firewall_intent_targets_uplink_not_lan_bridge() {
        let root = test_root("usbip-firewall-uplink");
        let resolver = build_personal_dev_bundle(&root);

        let intent = resolver
            .find_usbip_firewall_intent(&intent_id_usbip_firewall("personal", "pending"))
            .expect("usbip firewall intent");
        assert!(
            intent.nft_rule_body.contains("iifname \"br-personal-up\""),
            "rule body should target uplink fallback: {}",
            intent.nft_rule_body
        );
        assert!(
            !intent.nft_rule_body.contains("nlpersbr0"),
            "rule body must not target LAN bridge: {}",
            intent.nft_rule_body
        );
        assert!(
            intent
                .nft_rule_body
                .contains("ip saddr 192.0.2.2 ip daddr 192.0.2.1"),
            "rule body must scope to the host-visible net-VM source identity: {}",
            intent.nft_rule_body
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn usbip_firewall_intent_uses_user_visible_uplink_ifname() {
        let mut host: HostJson =
            serde_json::from_str(HOST_JSON_FIXTURE).expect("host fixture parses");
        host.environments[0].host_uplink_ip = Some("192.0.2.1".to_owned());
        host.environments[0].net_uplink_ip = Some("192.0.2.2".to_owned());
        host.environments[0].bridge_port_flags = vec![BridgePortFlags {
            role: TapRole::Uplink,
            isolated: true,
            neigh_suppress: true,
            learning: Some(false),
            unicast_flood: Some(false),
            rule: "uplink point-to-point anti-spoofing".to_owned(),
        }];
        host.environments[0].usbip_busid_locks = vec![UsbipBusidLock {
            vm: "corp-vm".to_owned(),
            lock_owner: UsbipLockOwner::Daemon,
            scope: UsbipLockScope::PerBusid,
            bus_ids: vec!["1-2".to_owned()],
            vendor_product_allowlist: Vec::new(),
        }];
        host.environments[0].usbip_backend_port = Some(3241);
        host.if_name_mappings = vec![IfNameMapping {
            env: host.environments[0].env.clone(),
            vm: None,
            role: crate::host::TapRole::Uplink,
            user_visible_name: "br-visible-up".to_owned(),
            derived_ifname: IfName::new("d2b-derived0").expect("ifname"),
        }];

        let intents = build_usbip_firewall_intents(&host);
        let intent = intents
            .get(&intent_id_usbip_firewall(&host.environments[0].env, "1-2"))
            .expect("usbip firewall intent");
        assert!(
            intent.nft_rule_body.contains("iifname \"br-visible-up\""),
            "rule body: {}",
            intent.nft_rule_body
        );
        assert!(intent.nft_rule_body.contains("ip saddr 192.0.2.2"));
        assert!(!intent.nft_rule_body.contains("d2b-derived0"));
    }

    #[test]
    fn usbip_firewall_intent_fails_closed_without_uplink_source_validation() {
        let mut host: HostJson =
            serde_json::from_str(HOST_JSON_FIXTURE).expect("host fixture parses");
        host.environments[0].host_uplink_ip = Some("192.0.2.1".to_owned());
        host.environments[0].net_uplink_ip = Some("192.0.2.2".to_owned());
        host.environments[0].usbip_busid_locks = vec![UsbipBusidLock {
            vm: "corp-vm".to_owned(),
            lock_owner: UsbipLockOwner::Daemon,
            scope: UsbipLockScope::PerBusid,
            bus_ids: vec!["1-2".to_owned()],
            vendor_product_allowlist: Vec::new(),
        }];
        host.environments[0].bridge_port_flags = vec![BridgePortFlags {
            role: TapRole::Uplink,
            isolated: false,
            neigh_suppress: true,
            learning: Some(false),
            unicast_flood: Some(false),
            rule: "unsafe uplink".to_owned(),
        }];

        let intents = build_usbip_firewall_intents(&host);
        assert!(
            !intents.contains_key(&intent_id_usbip_firewall(&host.environments[0].env, "1-2",)),
            "unsafe or unvalidated uplink must not widen USBIP exposure"
        );
    }

    #[test]
    fn host_nft_script_drops_usbip_input_without_runtime_carveout() {
        let mut host: HostJson =
            serde_json::from_str(HOST_JSON_FIXTURE).expect("host fixture parses");
        host.environments[0].usbip_busid_locks = vec![UsbipBusidLock {
            vm: "corp-vm".to_owned(),
            lock_owner: UsbipLockOwner::Daemon,
            scope: UsbipLockScope::PerBusid,
            bus_ids: vec!["1-2".to_owned()],
            vendor_product_allowlist: Vec::new(),
        }];
        host.environments[0].usbip_backend_port = Some(3241);

        let script = render_host_nft_script(&host);
        assert!(
            script.contains("iifname != \"lo\" meta l4proto tcp tcp dport { 3241 } drop"),
            "backend port must be broker-dropped on non-loopback ingress:\n{script}"
        );
        assert!(
            script.contains("iifname != \"lo\" meta l4proto tcp tcp dport 3240 drop"),
            "proxy port must default-drop until UsbipBindFirewallRule inserts a carve-out:\n{script}"
        );
    }

    // ---------------------------------------------------------------
    // role_device_classes for Gpu MUST exactly match the per-role
    // device matrix in nixos-modules/minijail-profiles.nix and the
    // row in docs/reference/privileges.md. vfio is NOT in the GPU
    // contract; kvm + udmabuf ARE.
    // ---------------------------------------------------------------
    #[test]
    fn role_device_classes_gpu_matches_p1_matrix() {
        let claim =
            super::role_device_classes(&ProcessRole::Gpu, super::ChNetHandoffMode::PersistentTap);
        let actual: std::collections::BTreeSet<&str> = claim.iter().copied().collect();
        let expected: std::collections::BTreeSet<&str> = [
            "kvm",
            "dri",
            "nvidia-ctl",
            "nvidia-uvm",
            "nvidia-render",
            "udmabuf",
        ]
        .into_iter()
        .collect();
        assert_eq!(
            actual, expected,
            "GPU role_device_classes drifted from the P1 device matrix"
        );
        assert!(
            !claim.contains(&"vfio"),
            "vfio is NOT in the P1 GPU device contract (was incorrectly included pre-R2)"
        );
    }

    #[test]
    fn role_device_classes_audio_matches_p1_matrix() {
        let claim =
            super::role_device_classes(&ProcessRole::Audio, super::ChNetHandoffMode::PersistentTap);
        assert_eq!(claim, &["pipewire-socket"]);
    }

    #[test]
    fn role_device_classes_virtiofsd_matches_p1_matrix() {
        let claim = super::role_device_classes(
            &ProcessRole::Virtiofsd,
            super::ChNetHandoffMode::PersistentTap,
        );
        assert_eq!(claim, &["fuse"]);
    }

    #[test]
    fn role_device_classes_qemu_media_declares_kvm_only() {
        let claim = super::role_device_classes(
            &ProcessRole::QemuMediaRunner,
            super::ChNetHandoffMode::PersistentTap,
        );
        assert_eq!(claim, &["kvm"]);
        assert!(
            !claim.contains(&"vhost-net") && !claim.contains(&"net-tun"),
            "qemu-media fd-backed mode must not claim path-backed vhost-net or tun devices"
        );
    }

    #[test]
    fn video_runner_has_no_stock_crosvm_legacy_fallback() {
        use crate::minijail_profile::{CgroupPlacement, MountPolicy, NamespaceSet};
        use crate::processes::{
            NodeId, ProcessNode, ProcessRole, RoleProfile, VmProcessDag, VmProcessInvariants,
        };

        let profile = RoleProfile {
            profile_id: "vm-test-video".to_owned(),
            uid: 60_100,
            gid: 60_100,
            adr_carve_out: None,
            caps: Vec::new(),
            namespaces: NamespaceSet {
                mount: true,
                pid: false,
                net: false,
                ipc: false,
                uts: false,
                user: false,
            },
            seccomp_policy_ref: Some("w1-video".to_owned()),
            mount_policy: MountPolicy {
                read_only_paths: Vec::new(),
                writable_paths: vec![crate::minijail_profile::WritablePath {
                    path: "/run/d2b-video/test-vm".to_owned(),
                    purpose: "test video runtime dir".to_owned(),
                }],
                nix_store_read_only: true,
                hide_device_nodes_by_default: true,
                device_binds: vec!["/dev/dri/renderD128".to_owned()],
                bind_mounts: Vec::new(),
            },
            cgroup_placement: CgroupPlacement {
                subtree: "d2b.slice/test-vm/video".to_owned(),
                controllers: vec![],
                delegated: false,
            },
            user_namespace: None,
            umask: Some(7),
        };

        let dag = VmProcessDag {
            workload_identity: None,
            vm: "test-vm".to_owned(),
            nodes: vec![ProcessNode {
                execution_ref: None,
                execution_domain: None,
                user_ref: None,
                id: NodeId("video".to_owned()),
                role: ProcessRole::Video,
                unit: None,
                binary_path: None,
                argv: Vec::new(),
                env: Vec::new(),
                profile,
                readiness: Vec::new(),
                plan_ops: Vec::new(),
                network_interfaces: Vec::new(),
            }],
            edges: Vec::new(),
            invariants: VmProcessInvariants {
                swtpm_pre_start_flush: false,
                per_vm_audit_pipeline: false,
                usbip_gating: false,
                tpm_ownership_migration_without_running_vm_mutation: false,
            },
        };

        assert!(
            super::resolve_runner_node(&dag, &dag.nodes[0]).is_none(),
            "video must fail closed when processes.json omits the patched crosvm video binary/argv"
        );
    }

    #[test]
    fn cloud_hypervisor_requires_a_closed_runner_specification() {
        let incomplete = ProcessNode {
            execution_ref: Some("Host/host-system".to_owned()),
            execution_domain: Some(ProcessExecutionDomain::System),
            user_ref: None,
            id: NodeId("cloud-hypervisor".to_owned()),
            role: ProcessRole::CloudHypervisorRunner,
            unit: None,
            binary_path: None,
            argv: Vec::new(),
            env: Vec::new(),
            profile: role_profile(
                1200,
                1200,
                &["/var/lib/d2b/vms/test-vm"],
                "d2b.slice/test-vm/cloud-hypervisor",
            ),
            readiness: Vec::new(),
            plan_ops: Vec::new(),
            network_interfaces: Vec::new(),
        };
        let intent =
            ResolvedRunnerIntent::from_process_node("test-vm", &incomplete).expect("legacy intent");
        assert!(!cloud_hypervisor_intent_is_complete(&intent));

        let complete = ProcessNode {
            binary_path: Some("/nix/store/cloud-hypervisor/bin/cloud-hypervisor".to_owned()),
            argv: vec![
                "cloud-hypervisor".to_owned(),
                "--kernel".to_owned(),
                "/nix/store/guest-system/kernel".to_owned(),
                "--initramfs".to_owned(),
                "/nix/store/guest-system/initrd".to_owned(),
                "--cmdline".to_owned(),
                "init=/nix/store/guest-system/init".to_owned(),
                "--api-socket".to_owned(),
                "/var/lib/d2b/zones/work/guests/test-vm/test-vm.sock".to_owned(),
            ],
            ..incomplete
        };
        let intent =
            ResolvedRunnerIntent::from_process_node("test-vm", &complete).expect("closed intent");
        assert!(cloud_hypervisor_intent_is_complete(&intent));
    }

    #[test]
    fn catalog_guest_vmm_intent_is_zone_and_descriptor_bound() {
        let descriptor_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let descriptors = BTreeMap::from([(
            ("work".to_owned(), "guest".to_owned()),
            serde_json::to_vec(&serde_json::json!({
                "descriptorDigest": descriptor_digest,
                "systemArtifactId": "guest-system"
            }))
            .expect("descriptor"),
        )]);
        let catalog = serde_json::json!({
            "guestClosures": [{
                "zone": "work",
                "guest": "guest",
                "artifactId": "guest-system",
                "toplevel": "/nix/store/guest-system",
                "closurePaths": ["/nix/store/guest-system"],
                "dbDumpPath": "/nix/store/guest-registration",
                "storeView": {
                    "root": "/var/lib/d2b/zones/work/guests/guest/store-view"
                },
                "vmm": {
                    "zoneUid": "123e4567-e89b-42d3-a456-426614174000",
                    "descriptorDigest": descriptor_digest,
                    "executionRef": "Host/host-system",
                    "binaryPath": "/nix/store/cloud-hypervisor/bin/cloud-hypervisor",
                    "argv": [
                        "microvm@guest",
                        "--kernel", "/nix/store/guest-system/kernel",
                        "--initramfs", "/nix/store/guest-system/initrd",
                        "--cmdline", "init=/nix/store/guest-system/init",
                        "--api-socket", "/var/lib/d2b/zones/work/guests/guest/guest.sock"
                    ],
                    "uid": 50001,
                    "gid": 50001,
                    "stateDir": "/var/lib/d2b/zones/work/guests/guest",
                    "deviceBinds": ["/dev/kvm", "/dev/vhost-net"],
                    "profileId": "ch-guest",
                    "cgroupSubtree": "d2b.slice/work/guest/cloud-hypervisor"
                }
            }]
        });
        let (intents, zone_uids) =
            load_guest_vmm_intents(&catalog, &descriptors).expect("VMM intent");
        let intent = intents
            .get(&("work".to_owned(), "guest".to_owned()))
            .expect("zone-local intent");
        assert_eq!(intent.role, ProcessRole::CloudHypervisorRunner);
        assert_eq!(intent.vm_name, "guest");
        assert_eq!(intent.execution_ref, "Host/host-system");
        assert_eq!(
            zone_uids
                .get(&("work".to_owned(), "guest".to_owned()))
                .map(ResourceUid::as_str),
            Some("123e4567-e89b-42d3-a456-426614174000")
        );
        assert!(process_template_name_matches(
            intent,
            "cloud-hypervisor-runner"
        ));
        assert_eq!(intent.umask, Some(0o022));
        assert!(!process_template_name_matches(intent, "cloud-hypervisor"));
        let store_intents = load_guest_store_view_intents(&catalog).expect("store-view intent");
        let store_intent = store_intents
            .get(&intent_id_store_view(
                &ZoneId::parse("work").unwrap(),
                "guest",
            ))
            .expect("Guest store-view intent");
        assert_eq!(
            store_intent.hardlink_farm_path,
            PathBuf::from("/var/lib/d2b/zones/work/guests/guest/store-view")
        );
        assert_eq!(
            store_intent.target_view_path,
            PathBuf::from("/var/lib/d2b/zones/work/guests/guest/store-view/live/guest-system")
        );
    }

    #[test]
    fn catalog_same_named_guests_keep_store_views_runners_and_cgroups_distinct() {
        let descriptor_digest =
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let descriptors = BTreeMap::from([
            (
                ("work".to_owned(), "desktop".to_owned()),
                serde_json::to_vec(&serde_json::json!({
                    "descriptorDigest": descriptor_digest,
                    "systemArtifactId": "desktop-system"
                }))
                .expect("work descriptor"),
            ),
            (
                ("personal".to_owned(), "desktop".to_owned()),
                serde_json::to_vec(&serde_json::json!({
                    "descriptorDigest": descriptor_digest,
                    "systemArtifactId": "desktop-system"
                }))
                .expect("personal descriptor"),
            ),
        ]);
        let guest_closure = |zone: &str, zone_uid: &str| {
            serde_json::json!({
                "zone": zone,
                "guest": "desktop",
                "artifactId": "desktop-system",
                "toplevel": format!("/nix/store/{zone}-desktop-system"),
                "closurePaths": [format!("/nix/store/{zone}-desktop-system")],
                "dbDumpPath": format!("/nix/store/{zone}-desktop-registration"),
                "storeView": {
                    "root": format!("/var/lib/d2b/zones/{zone}/guests/desktop/store-view")
                },
                "vmm": {
                    "zoneUid": zone_uid,
                    "descriptorDigest": descriptor_digest,
                    "executionRef": "Host/host-system",
                    "binaryPath": "/nix/store/cloud-hypervisor/bin/cloud-hypervisor",
                    "argv": [
                        "microvm@desktop",
                        "--kernel", format!("/nix/store/{zone}-desktop-system/kernel"),
                        "--initramfs", format!("/nix/store/{zone}-desktop-system/initrd"),
                        "--cmdline", format!("init=/nix/store/{zone}-desktop-system/init"),
                        "--api-socket",
                        format!("/var/lib/d2b/zones/{zone}/guests/desktop/desktop.sock")
                    ],
                    "uid": 50001,
                    "gid": 50001,
                    "stateDir": format!("/var/lib/d2b/zones/{zone}/guests/desktop"),
                    "deviceBinds": ["/dev/kvm", "/dev/vhost-net"],
                    "profileId": format!("ch-{zone}-desktop"),
                    "cgroupSubtree": format!("d2b.slice/{zone}/desktop/cloud-hypervisor")
                }
            })
        };
        let catalog = serde_json::json!({
            "guestClosures": [
                guest_closure("work", "123e4567-e89b-42d3-a456-426614174000"),
                guest_closure("personal", "223e4567-e89b-42d3-a456-426614174001")
            ]
        });

        let store_intents =
            load_guest_store_view_intents(&catalog).expect("zone-qualified store-view intents");
        let work_zone = ZoneId::parse("work").expect("work Zone");
        let personal_zone = ZoneId::parse("personal").expect("personal Zone");
        let work_store = store_intents
            .get(&intent_id_store_view(&work_zone, "desktop"))
            .expect("work desktop store view");
        let personal_store = store_intents
            .get(&intent_id_store_view(&personal_zone, "desktop"))
            .expect("personal desktop store view");
        assert_ne!(work_store.intent_id, personal_store.intent_id);
        assert_ne!(
            work_store.hardlink_farm_path,
            personal_store.hardlink_farm_path
        );

        let (runner_intents, zone_uids) =
            load_guest_vmm_intents(&catalog, &descriptors).expect("zone-qualified VMM intents");
        let work_key = ("work".to_owned(), "desktop".to_owned());
        let personal_key = ("personal".to_owned(), "desktop".to_owned());
        let work_runner = runner_intents.get(&work_key).expect("work desktop runner");
        let personal_runner = runner_intents
            .get(&personal_key)
            .expect("personal desktop runner");
        assert_eq!(
            work_runner.intent_id,
            intent_id_runner(&work_zone, "desktop", "cloud-hypervisor")
        );
        assert_eq!(
            personal_runner.intent_id,
            intent_id_runner(&personal_zone, "desktop", "cloud-hypervisor")
        );
        assert_ne!(work_runner.intent_id, personal_runner.intent_id);
        assert_eq!(
            work_runner.cgroup_placement.subtree,
            "d2b.slice/work/desktop/cloud-hypervisor"
        );
        assert_eq!(
            personal_runner.cgroup_placement.subtree,
            "d2b.slice/personal/desktop/cloud-hypervisor"
        );
        assert_ne!(
            work_runner.cgroup_placement.subtree,
            personal_runner.cgroup_placement.subtree
        );
        assert_ne!(zone_uids.get(&work_key), zone_uids.get(&personal_key));
    }

    // v1.2 swtpm broker-pre-NS extension.
    //
    // When the swtpm RoleProfile declares userNamespace = Some(...),
    // resolve_runner_node must carry that spec through to
    // ResolvedRunnerIntent.user_namespace = Some(...).
    // This mirrors the virtiofsd user_namespace round-trip contract
    // (ADR 0021) and guards against silent drops in the resolver.
    #[test]
    fn swtpm_user_namespace_propagates_to_resolved_intent() {
        use crate::minijail_profile::{CgroupPlacement, MountPolicy, NamespaceSet};
        use crate::processes::{
            NodeId, ProcessNode, ProcessRole, RoleProfile, RoleUserNamespace, VmProcessDag,
            VmProcessInvariants,
        };

        const SWTPM_UID: u32 = 60_100;
        const SWTPM_GID: u32 = 60_100;

        let swtpm_profile = RoleProfile {
            profile_id: "w1-swtpm-test".to_owned(),
            uid: SWTPM_UID,
            gid: SWTPM_GID,
            adr_carve_out: None,
            caps: Vec::new(),
            namespaces: NamespaceSet {
                mount: false,
                pid: false,
                net: false,
                ipc: false,
                uts: false,
                user: true, // set by mkProfile when userNamespace != null
            },
            seccomp_policy_ref: Some("w1-swtpm".to_owned()),
            mount_policy: MountPolicy {
                read_only_paths: vec!["/nix/store".to_owned()],
                writable_paths: vec![],
                nix_store_read_only: true,
                hide_device_nodes_by_default: true,
                device_binds: Vec::new(),
                bind_mounts: Vec::new(),
            },
            cgroup_placement: CgroupPlacement {
                subtree: "d2b.slice/test-vm/swtpm".to_owned(),
                controllers: vec!["cpu".to_owned(), "memory".to_owned()],
                delegated: false,
            },
            // v1.2 swtpm declares userNamespace per ADR 0021 model.
            user_namespace: Some(RoleUserNamespace {
                host_uid_for_zero: SWTPM_UID,
                host_gid_for_zero: SWTPM_GID,
            }),
            umask: Some(7),
        };

        let dag = VmProcessDag {
            workload_identity: None,
            vm: "test-vm".to_owned(),
            nodes: vec![ProcessNode {
                execution_ref: None,
                execution_domain: None,
                user_ref: None,
                id: NodeId("swtpm".to_owned()),
                role: ProcessRole::Swtpm,
                unit: None,
                binary_path: Some("/run/current-system/sw/bin/swtpm".to_owned()),
                argv: vec!["swtpm".to_owned()],
                env: Vec::new(),
                profile: swtpm_profile,
                readiness: Vec::new(),
                plan_ops: Vec::new(),
                network_interfaces: Vec::new(),
            }],
            edges: Vec::new(),
            invariants: VmProcessInvariants {
                swtpm_pre_start_flush: false,
                per_vm_audit_pipeline: false,
                usbip_gating: false,
                tpm_ownership_migration_without_running_vm_mutation: false,
            },
        };

        let node = &dag.nodes[0];
        let intent = super::resolve_runner_node(&dag, node)
            .expect("swtpm node must produce a ResolvedRunnerIntent");

        assert_eq!(
            intent.user_namespace,
            Some(super::UserNamespaceSpec {
                host_uid_for_zero: SWTPM_UID,
                host_gid_for_zero: SWTPM_GID,
            }),
            "swtpm ResolvedRunnerIntent.user_namespace must carry the profile's \
             userNamespace spec (ADR 0021 broker-pre-NS, D5/P2.3)"
        );
        // Confirm host caps are empty - invariant required alongside user_namespace.
        assert!(
            intent.capabilities.is_empty(),
            "swtpm host capabilities must be empty when user_namespace is Some(_) \
             (zero-host-caps invariant, ADR 0021)"
        );
        // Confirm umask = 7 is preserved (fu36 socket-ACL requirement).
        assert_eq!(
            intent.umask,
            Some(7),
            "swtpm umask must remain 0o007 after D5/P2.3 (fu36 socket-ACL requirement)"
        );
    }

    // v1.2 gpu-render-node broker-pre-NS extension.
    //
    // When the gpu-render-node RoleProfile declares userNamespace = Some(...),
    // resolve_runner_node must carry that spec through to
    // ResolvedRunnerIntent.user_namespace = Some(...).
    // Also verifies that the role name resolves to "gpu-render-node" and
    // that the legacy arg0 is "d2b-{vm}-gpu-render-node".
    #[test]
    fn gpu_render_node_user_namespace_propagates_to_resolved_intent() {
        use crate::minijail_profile::{CgroupPlacement, MountPolicy, NamespaceSet};
        use crate::processes::{
            NodeId, ProcessNode, ProcessRole, RoleProfile, RoleUserNamespace, VmProcessDag,
            VmProcessInvariants,
        };

        const GPU_UID: u32 = 60_200;
        const GPU_GID: u32 = 60_200;

        let gpu_render_node_profile = RoleProfile {
            profile_id: "w1-gpu-render-node-test".to_owned(),
            uid: GPU_UID,
            gid: GPU_GID,
            adr_carve_out: None,
            caps: Vec::new(),
            namespaces: NamespaceSet {
                mount: false,
                pid: false,
                net: false,
                ipc: false,
                uts: false,
                user: true, // set by mkProfile when userNamespace != null
            },
            seccomp_policy_ref: Some("w1-gpu-render-node".to_owned()),
            mount_policy: MountPolicy {
                read_only_paths: vec!["/nix/store".to_owned()],
                writable_paths: vec![],
                nix_store_read_only: true,
                hide_device_nodes_by_default: true,
                // No deviceBinds: render node is pre-opened by broker and
                // passed via fd inheritance (RENDER_NODE_INHERITED_FD = 10).
                device_binds: Vec::new(),
                bind_mounts: Vec::new(),
            },
            cgroup_placement: CgroupPlacement {
                subtree: "d2b.slice/test-vm/gpu".to_owned(),
                controllers: vec!["cpu".to_owned(), "memory".to_owned()],
                delegated: false,
            },
            // v1.2 gpu-render-node declares userNamespace per ADR 0021 model.
            user_namespace: Some(RoleUserNamespace {
                host_uid_for_zero: GPU_UID,
                host_gid_for_zero: GPU_GID,
            }),
            umask: Some(7),
        };

        let dag = VmProcessDag {
            workload_identity: None,
            vm: "test-vm".to_owned(),
            nodes: vec![ProcessNode {
                execution_ref: None,
                execution_domain: None,
                user_ref: None,
                id: NodeId("gpu-render-node".to_owned()),
                role: ProcessRole::GpuRenderNode,
                unit: None,
                binary_path: Some("/run/current-system/sw/bin/crosvm".to_owned()),
                argv: vec!["d2b-test-vm-gpu-render-node".to_owned()],
                env: Vec::new(),
                profile: gpu_render_node_profile,
                readiness: Vec::new(),
                plan_ops: Vec::new(),
                network_interfaces: Vec::new(),
            }],
            edges: Vec::new(),
            invariants: VmProcessInvariants {
                swtpm_pre_start_flush: false,
                per_vm_audit_pipeline: false,
                usbip_gating: false,
                tpm_ownership_migration_without_running_vm_mutation: false,
            },
        };

        let node = &dag.nodes[0];
        let intent = super::resolve_runner_node(&dag, node)
            .expect("gpu-render-node node must produce a ResolvedRunnerIntent");

        assert_eq!(
            intent.user_namespace,
            Some(super::UserNamespaceSpec {
                host_uid_for_zero: GPU_UID,
                host_gid_for_zero: GPU_GID,
            }),
            "gpu-render-node ResolvedRunnerIntent.user_namespace must carry the profile's \
             userNamespace spec (ADR 0021 broker-pre-NS, D5/P2.3)"
        );
        // Confirm host caps are empty - invariant required alongside user_namespace.
        assert!(
            intent.capabilities.is_empty(),
            "gpu-render-node host capabilities must be empty when user_namespace is Some(_) \
             (zero-host-caps invariant, ADR 0021)"
        );
        // Confirm umask = 7 is preserved (fu36 socket-ACL requirement).
        assert_eq!(
            intent.umask,
            Some(7),
            "gpu-render-node umask must remain 0o007 (fu36 socket-ACL requirement)"
        );
        // Confirm seccomp_policy_ref for broker pre-open detection.
        assert_eq!(
            intent.seccomp_policy_ref.as_deref(),
            Some("w1-gpu-render-node"),
            "gpu-render-node seccomp_policy_ref must be w1-gpu-render-node so the broker \
             pre-open detection in live_spawn_runner fires"
        );
    }

    // v1.2 audio broker-pre-NS extension (Tier 2).
    //
    // When the audio RoleProfile declares userNamespace = Some(...) and
    // namespaces.net = true, resolve_runner_node must carry the user_namespace
    // spec through to ResolvedRunnerIntent.user_namespace = Some(...).
    //
    // Context: vhost-device-sound's libpipewire client opens
    // AF_NETLINK(NETLINK_KOBJECT_UEVENT) during pw_context_new() (spa-alsa-monitor).
    // In a user-NS-only spawn, ns_capable(net->user_ns, CAP_NET_RAW) fails because
    // the host net NS is owned by the initial user NS. Tier 2 resolves this by
    // combining clone3(CLONE_NEWUSER) with unshare(CLONE_NEWNET) inside the user NS:
    // the new net NS is owned by the new user NS; CAP_NET_RAW is effective there.
    // The audio block and review cover CAP_NET_RAW + AF_NETLINK.
    #[test]
    fn audio_user_namespace_propagates_to_resolved_intent() {
        use crate::minijail_profile::{CgroupPlacement, MountPolicy, NamespaceSet};
        use crate::processes::{
            NodeId, ProcessNode, ProcessRole, RoleProfile, RoleUserNamespace, VmProcessDag,
            VmProcessInvariants,
        };

        const AUDIO_UID: u32 = 60_300;
        const AUDIO_GID: u32 = 60_300;

        let audio_profile = RoleProfile {
            profile_id: "w1-audio-test".to_owned(),
            uid: AUDIO_UID,
            gid: AUDIO_GID,
            adr_carve_out: None,
            // Host caps must be empty - CAP_NET_RAW is effective inside
            // the user-NS-owned net NS, not on the host.
            caps: Vec::new(),
            namespaces: NamespaceSet {
                mount: false,
                pid: false,
                net: true, // CLONE_NEWNET in unshare inside user NS
                ipc: false,
                uts: false,
                user: true, // set by mkProfile when userNamespace != null
            },
            seccomp_policy_ref: Some("w1-audio".to_owned()),
            mount_policy: MountPolicy {
                read_only_paths: vec!["/nix/store".to_owned()],
                writable_paths: vec![],
                nix_store_read_only: true,
                hide_device_nodes_by_default: true,
                device_binds: Vec::new(),
                bind_mounts: Vec::new(),
            },
            cgroup_placement: CgroupPlacement {
                subtree: "d2b.slice/test-vm/audio".to_owned(),
                controllers: vec!["cpu".to_owned(), "memory".to_owned()],
                delegated: false,
            },
            // v1.2 audio declares userNamespace per ADR 0021 model.
            user_namespace: Some(RoleUserNamespace {
                host_uid_for_zero: AUDIO_UID,
                host_gid_for_zero: AUDIO_GID,
            }),
            umask: Some(7),
        };

        let dag = VmProcessDag {
            workload_identity: None,
            vm: "test-vm".to_owned(),
            nodes: vec![ProcessNode {
                execution_ref: None,
                execution_domain: None,
                user_ref: None,
                id: NodeId("audio".to_owned()),
                role: ProcessRole::Audio,
                unit: None,
                binary_path: Some("/run/current-system/sw/bin/vhost-device-sound".to_owned()),
                argv: vec!["d2b-test-vm-snd".to_owned()],
                env: Vec::new(),
                profile: audio_profile,
                readiness: Vec::new(),
                plan_ops: Vec::new(),
                network_interfaces: Vec::new(),
            }],
            edges: Vec::new(),
            invariants: VmProcessInvariants {
                swtpm_pre_start_flush: false,
                per_vm_audit_pipeline: false,
                usbip_gating: false,
                tpm_ownership_migration_without_running_vm_mutation: false,
            },
        };

        let node = &dag.nodes[0];
        let intent = super::resolve_runner_node(&dag, node)
            .expect("audio node must produce a ResolvedRunnerIntent");

        assert_eq!(
            intent.user_namespace,
            Some(super::UserNamespaceSpec {
                host_uid_for_zero: AUDIO_UID,
                host_gid_for_zero: AUDIO_GID,
            }),
            "audio ResolvedRunnerIntent.user_namespace must carry the profile's \
             userNamespace spec (ADR 0021 broker-pre-NS, D5/P2.3 Tier 2)"
        );
        // Zero host caps - CAP_NET_RAW is effective only inside the
        // user-NS-owned net NS, not on the host side.
        assert!(
            intent.capabilities.is_empty(),
            "audio host capabilities must be empty when user_namespace is Some(_) \
             (zero-host-caps invariant, ADR 0021; Tier 2 drops CAP_NET_RAW from host)"
        );
        // Confirm umask = 7 is preserved (fu36 socket-ACL requirement).
        assert_eq!(
            intent.umask,
            Some(7),
            "audio umask must remain 0o007 (fu36 socket-ACL requirement)"
        );
        // Confirm net = true propagates - required for the user-NS-owned net NS
        // that makes CAP_NET_RAW effective for AF_NETLINK.
        assert!(
            intent.namespaces.net,
            "audio namespaces.net must be true (D5/P2.3 Tier 2: unshare CLONE_NEWNET \
             inside user NS for AF_NETLINK support without host CAP_NET_RAW)"
        );
    }
}
