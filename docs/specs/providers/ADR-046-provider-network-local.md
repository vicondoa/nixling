# ADR 0046 Provider dossier - Provider/network-local

| Field | Value |
| --- | --- |
| Spec ID | `ADR-046-provider-network-local` |
| Parent | ADR 0046 |
| Status | Accepted |
| Version | 3 |
| Baseline | `b5ddbed67867d9244bf33390868101bd9b053e49` |
| Normative | Yes |
| Owners | `d2b-provider-network-local` crate, `d2b-host` IfName/nftables/bridge/routes modules |
| Depends on | `ADR-046-resources-network`, `ADR-046-resources-host-guest-process-user`, `ADR-046-resources-volume`, `ADR-046-provider-model-and-packaging`, `ADR-046-componentsession-and-bus`, `ADR-046-resource-reconciliation`, `ADR-046-nix-configuration`, `ADR-046-telemetry-audit-and-support`, `ADR-046-current-code-migration-map` |
| Supersedes | `nixos-modules/network.nix`, `nixos-modules/net.nix` |

---

## 1. Purpose and scope

This dossier is the exhaustive engineering specification for `Provider/network-local`.
It governs:

- the `Network` ResourceType: spec schema, status, IfName derivation, CIDR
  validation, attachment lifecycle, east-west isolation, DHCP/DNS, firewall,
  and mDNS;
- all child resources created per Network: one config Volume, one net-VM Guest,
  four Process resources (net-agent service, dnsmasq worker, mdns-reflector
  worker, mdns-dnsbridge worker), and one User resource;
- the `NetworkEffectPort` abstraction through which ALL host-kernel effects are
  driven - the provider crate has **no** broker dependency or socket;
- the controller's reconcile/observe/finalize loops, the ProviderStateSet, RBAC,
  d2b-bus, audit, OTEL, Nix configuration, and security invariants;
- migration from the v1 baseline, reuse of existing modules, work items, and
  the test structure required by policy.

The Provider baseline is pre-ADR 0045 (d2b 2.x) - no wave-N implementation crates
exist. Reuse is limited to `d2b-host` IfName/nftables/bridge/routes modules and
existing Nix module logic.

Sections reference `ADR-046-resources-network` (hereafter **NET**),
`ADR-046-resources-host-guest-process-user` (hereafter **PROC**), and
`ADR-046-resource-reconciliation` (hereafter **RECONCILE**) as normative sources.

---

## 2. Provider identity

| Field | Value |
| --- | --- |
| `providerRef` | `Provider/network-local` |
| Artifact ID | `provider-network-local` |
| Crate | `packages/d2b-provider-network-local/` |
| Controller binary | `d2b-provider-network-local-ctrl` |
| ResourceTypes implemented | `Network` |
| ResourceTypes consumed | `Host`, `Guest`, `Volume`, `Process`, `User`, `Zone` |
| Process Providers depended on | `Provider/system-minijail` |
| Data Providers depended on | `Provider/volume-local` |
| Broker dependency | **None** - all host-kernel effects via `NetworkEffectPort` |

**D089 spec extension contract:** `Provider/network-local` carries any
implementation-only Network desired configuration only in `spec.provider.settings`
under `network-local.d2bus.org/Network/spec`; that schema is registered/signed in
the manifest, deny-unknown, bounded, versioned, and validated against
`spec.providerRef` at Nix build and API admission. Base Network fields stay at
`spec.*`; shared semantics are promoted to the Network base and never placed in
`spec.provider`. The Provider implements the exact base spec/status schema
version/fingerprint, accepts the canonical minimal valid base Spec, and rejects
an unsupported optional base capability only through its signed capability matrix
plus provider-neutral `unsupported-capability`. `spec.provider` aligns with
`status.provider` for `Provider/network-local`.

The provider crate does **not** depend on `d2bd`, `d2b-priv-broker`, any broker
socket or wire type, or any Provider's implementation crate. All host-kernel effects
are driven through the injected `NetworkEffectPort` async trait, which is declared in
`d2b-contracts` (the neutral provider contract crate); the core adapter (not the
provider crate) implements that trait, maps it to closed broker wire operations, and
emits the corresponding audit records.

---

## 3. Crate layout

```
packages/d2b-provider-network-local/
  README.md              # covers all 7 required topics (identity → standalone-repo path)
  src/
    main.rs              # controller binary entry point; dependency injection
    controller.rs        # reconcile/observe/finalize handlers
    validate.rs          # spec validation (CIDR, attachment, IfName constraints)
    config_volume.rs     # Volume resource creation and content rendering
    guest.rs             # net-VM Guest resource management
    process_specs.rs     # canonical Process resource specs (agent, dnsmasq, mDNS)
    user.rs              # User resource precondition check
    ifname.rs            # re-exports d2b_host::ifname::derive_ifname
    status.rs            # status and condition helpers
    audit.rs             # audit redaction helpers
    error.rs             # typed ReconcileError
    #[cfg(test)] units inside each source file
  tests/
    schema_roundtrip.rs  # NetworkSpec JSON serialize/deserialize
    ifname_derive.rs     # IfName derivation determinism
    cidr_overlap.rs      # CIDR validation matrix
    controller_state.rs  # reconcile state-machine with deterministic clock
    conformance.rs       # provider-toolkit conformance suite
    fault_injection.rs   # NetworkEffectPort (from d2b-contracts) error injection
  integration/
    host_fabric.rs       # bridge/tap/nftables lifecycle (container-based)
    guest_lifecycle.rs   # net-VM Guest create/delete
    agent_reload.rs      # agent service reload path
    mdns_reflector.rs    # mDNS reflector Process lifecycle
    delete_sequence.rs   # full delete ordering
```

`src/`, `tests/`, and `integration/` each contain at least one tracked file.
The root `README.md` covers all required topics.  The workspace policy test
(`make test-policy` / `xtask workspace-policy`) enforces these four paths.
A nested `integration/README.md` is optional and not required by policy.

Crate dependencies:

| Crate | Role |
| --- | --- |
| `d2b-contracts` | `NetworkSpec`, `NetworkStatus`, IfName, Network-related DTOs; **`NetworkEffectPort` trait**; opaque `FabricHandle`/`AttachmentHandle` types |
| `d2b-controller-toolkit` | async reconcile loop, `ResourceClient`, `ResourceMutationBatch` |
| `d2b-host` | `derive_ifname`, `nftables`, bridge-port, route-preflight, sysctl modules |
| `d2b-provider-toolkit` | Provider registration, conformance kit, fake-core/store/bus/effect |

No broker crate appears in `[dependencies]` or `[dev-dependencies]`.

---

## 4. Provider resource spec

The `Provider/network-local` resource is declared in Nix:

```yaml
# Generated from d2b.zones.<zone>.providers.network-local (Nix option)
apiVersion: resources.d2bus.org/v3
type: Provider
metadata:
  name: network-local
  zone: dev
spec:
  artifactId: provider-network-local    # ^[a-z][a-z0-9-]*$; plain bounded ID
  config:
    controllerExecutionRef: Host/host-system
    # Root config validated against provider-network-local/Network.schema.json.
    # All config fields are Provider-specific; no raw broker parameters or
    # kernel interface names appear in config.
```

`artifactId` is a plain bounded ID matching `^[a-z][a-z0-9-]*$`.  It is **not** a
path, Nix store path, or ResourceRef.  The artifact catalog entry (§22) maps this ID
to the Nix derivation.

`config.controllerExecutionRef` is the `Host` ResourceRef on which the controller
Process runs.  The framework creates the controller Process resource from this config
field.

### 4.1 Controller Process resource

The framework creates the following Process resource when `Provider/network-local`
is installed:

```yaml
apiVersion: resources.d2bus.org/v3
type: Process
metadata:
  name: network-local-ctrl
  zone: dev
  ownerRef: Provider/network-local
spec:
  providerRef: Provider/system-minijail
  executionRef: Host/host-system            # from Provider.spec.config.controllerExecutionRef
  domain: system
  processClass: controller
  template: controller-main
  sandbox:
    namespaceClasses: []                    # no additional namespace isolation; inherits host
    capabilityClasses: []                   # no ambient capabilities; effects via NetworkEffectPort
    seccompClass: strict
    noNewPrivileges: true
    startRoot: false
    readOnlyRoot: true
    environmentClass: minimal
  budget:
    memory:
      request: "32Mi"
      limit: "128Mi"
    pids:
      limit: 64
    fds:
      limit: 512
  mounts: []                             # no Provider state Volume under D087
  desiredLifecycle: running
  restartPolicy:
    class: on-failure
    backoffBase: "2s"
    backoffMax: "120s"
    backoffMultiplierMilli: 2000
    maxRestarts: null
    resetAfter: "300s"
  readiness:
    initialDelay: "0s"
    timeout: "30s"
    failureThreshold: 3
    successThreshold: 1
    class: ready-condition
  healthCheck:
    enabled: true
    interval: "30s"
    timeout: "5s"
    failureThreshold: 3
    class: provider-defined
  adoptionPolicy: adopt-on-restart
  drainTimeout: "30s"
```

The controller process has **no ambient host capabilities**.  All host-kernel bridge,
tap, nftables, sysctl, route, NM-unmanaged, and hosts-file effects are driven through
the injected `NetworkEffectPort` (§5).  No `kvm`, `net-admin`, or other
`capabilityClass` appears in this spec.

The required Host capabilities for the controller's execution environment are:
`pidfd`, `cgroup-v2`.  The `kvm` and `user-namespace` capabilities are **not**
required for the network controller; `kvm` belongs to
`Provider/runtime-cloud-hypervisor`.

---

## 5. NetworkEffectPort - broker abstraction layer

### 5.1 Purpose

The reconcile context (RECONCILE §Reconcile context) contains no database handle,
direct broker socket, reusable credential, or raw route table.  The network-local
controller is generic over `P: NetworkEffectPort` and drives all host-kernel
mutations through the concrete implementation injected at startup.  The native
async trait is declared in `d2b-contracts` and uses no trait object or
`async-trait` dependency.  The core adapter (in `d2b-core`, not the provider
crate) implements this trait, maps opaque resource UIDs and semantic intent
structs to closed broker wire operations, and emits broker-level audit records.

The provider crate sees the declared `NetworkSpec` in full - including `lanCidr`,
`uplinkCidr`, and other operator-declared IP policy fields - because those are the
desired spec inputs that drive the controller's reconcile logic.  What the provider
crate **never** sees through the `NetworkEffectPort` interface are runtime-observed
or kernel-derived values: kernel interface names, observed host addresses, DHCP MAC
assignments, tap FDs, or route-table text.  Opaque handle types (`FabricHandle`,
`AttachmentHandle`) carry internal identity material that is never exposed as a
printable string; they implement custom redacted `Debug` and are not `Clone` or
`Copy`.

### 5.2 Trait definition (Rust pseudocode)

```rust
/// Injected port for all host-kernel fabric and firewall effects.
/// Declared in d2b-contracts; implemented by the core adapter.
/// All methods are async and must not hold a redb transaction across any await.
/// Blocking kernel effects use explicit bounded adapters inside the core impl.
/// EffectError is a closed typed enum; no String-payload error variant exists.
pub trait NetworkEffectPort: Send + Sync {
    // ── Fabric (bridges) ─────────────────────────────────────────────────────
    /// Create or ensure a host kernel bridge fabric for a Network.
    /// The core adapter derives IfName internally from the networkName in the
    /// FabricIntent; the provider never receives the raw IfName.
    async fn create_fabric(
        &self,
        network_uid: &Uid,
        intent: &FabricIntent,
    ) -> Result<FabricHandle, EffectError>;

    /// Delete the host kernel bridge for a Network.  Idempotent on absence.
    async fn delete_fabric(
        &self,
        handle: &FabricHandle,
    ) -> Result<(), EffectError>;

    // ── Attachment taps ───────────────────────────────────────────────────────
    /// Declare a tap attachment intent for a specific Guest on a Network.
    /// Returns an opaque AttachmentHandle; the core adapter creates or adopts
    /// the tap and bridge-port configuration.  The tap IfName is never exposed.
    async fn declare_attachment_tap(
        &self,
        network_uid: &Uid,
        attachment_uid: &Uid,
        intent: &TapIntent,
    ) -> Result<AttachmentHandle, EffectError>;

    /// Revoke a previously declared persistent tap attachment. The generation
    /// fence prevents a stale finalizer from deleting a replacement attachment.
    /// Absence is success only after ownership validation.
    async fn revoke_attachment_tap(
        &self,
        handle: &AttachmentHandle,
        expected: &AttachmentGenerationFence,
    ) -> Result<(), EffectError>;

    /// Set the isolation flag on a tap's bridge port.
    async fn set_attachment_isolation(
        &self,
        handle: &AttachmentHandle,
        isolated: bool,
    ) -> Result<(), EffectError>;

    // ── Firewall ──────────────────────────────────────────────────────────────
    /// Apply or replace only the inet-d2b rules carrying this Network UID's
    /// ownership marker (`comment "d2b managed: <network-uid>"`). The broker
    /// mutates exactly this ownership projection and byte-preserves every other
    /// marker in the table (sibling Networks and device-usbip); discovering a
    /// foreign marker where this Network's is expected fails closed with
    /// `foreign-nft-rule-preserved`. `fence` carries the expected projection
    /// generation; a stale fence mutates nothing and requeues after a refresh.
    /// Returns the SHA-256 digest of this Network UID's ownership projection
    /// (opaque; used for drift detection in status). USBIP-owned rules are
    /// excluded from the digest. No rule text is stored in status or audit.
    async fn apply_host_firewall(
        &self,
        network_uid: &Uid,
        intent: &FirewallIntent,
        fence: &FirewallGenerationFence,
    ) -> Result<FirewallDigest, EffectError>;

    /// Remove only the inet-d2b rules carrying this Network UID's ownership
    /// marker (deletion path). All sibling-Network and device-usbip markers are
    /// preserved; the whole `inet d2b` table is never deleted. A validated
    /// already-absent projection is idempotent success; a generation mismatch
    /// removes nothing and requeues after a fresh read.
    async fn remove_host_firewall(
        &self,
        network_uid: &Uid,
        fence: &FirewallGenerationFence,
    ) -> Result<(), EffectError>;

    // ── Routes ────────────────────────────────────────────────────────────────
    async fn apply_host_routes(
        &self,
        network_uid: &Uid,
        intent: &RouteIntent,
    ) -> Result<(), EffectError>;

    async fn remove_host_routes(
        &self,
        network_uid: &Uid,
    ) -> Result<(), EffectError>;

    // ── Sysctls ───────────────────────────────────────────────────────────────
    /// Re-apply per-bridge IPv6 suppression sysctls (defense-in-depth).
    async fn apply_host_sysctls(
        &self,
        network_uid: &Uid,
        intent: &SysctlIntent,
    ) -> Result<(), EffectError>;

    // ── NetworkManager ────────────────────────────────────────────────────────
    async fn apply_nm_unmanaged(
        &self,
        pattern: &NmUnmanagedPattern,
    ) -> Result<(), EffectError>;

    // ── /etc/hosts ────────────────────────────────────────────────────────────
    async fn update_hosts_file(
        &self,
        network_uid: &Uid,
        intent: &HostsIntent,
    ) -> Result<(), EffectError>;

    // ── DHCP pre-seed ─────────────────────────────────────────────────────────
    async fn seed_dhcp_reservations(
        &self,
        network_uid: &Uid,
        intent: &DhcpSeedIntent,
    ) -> Result<(), EffectError>;

    // ── Read-back (observe/drift detection) ───────────────────────────────────
    async fn read_firewall_digest(
        &self,
        network_uid: &Uid,
    ) -> Result<Option<FirewallDigest>, EffectError>;

    async fn read_sysctl_state(
        &self,
        network_uid: &Uid,
    ) -> Result<SysctlState, EffectError>;

    async fn read_attachment_isolation(
        &self,
        handle: &AttachmentHandle,
    ) -> Result<bool, EffectError>;
}
```

### 5.3 Opaque intent structs and handle types

Intent structs are declared in `d2b-contracts` and contain only semantic data.  They
never contain raw kernel interface names, IP strings derived at runtime, or MAC
address strings.  The core adapter resolves all opaque UIDs → kernel interface names
internally using the IfName derivation algorithm (§7).

Opaque handle types implement a custom redacted `Debug` that prints only a stable
type tag and no sensitive content.  They are not `Clone`, not `Copy`, and cannot be
serialized to JSON or transmitted over the resource API wire.

| Type | Semantic content | Constraints |
| --- | --- | --- |
| `FabricIntent` | `mtu`, `stp_disabled`, `multicast_snooping_disabled`, `ipv6_suppress` | All fields from declared spec |
| `TapIntent` | `attachment_index`, `neigh_suppress` | Index from declared spec |
| `AttachmentHandle` | opaque seal over internal `(network_uid, attachment_uid)` | Redacted Debug; not Clone/Copy/Serialize |
| `AttachmentGenerationFence` | `expected_network_generation`, `expected_attachment_generation` | Both are non-zero resource generations captured from the current realization; stale values fail closed |
| `FabricHandle` | opaque seal over internal `network_uid` | Redacted Debug; not Clone/Copy/Serialize |
| `FirewallIntent` | `rules: Vec<FirewallRule>` (rules reference attachment handles, not IfNames) | No raw IfNames and no USBIP/TCP-3240 rule |
| `FirewallGenerationFence` | `expected_generation_id` | The immutable installed configuration generation (bundle generationId/contentHash) the controller reconciled against; a value that differs from the currently-installed generation fails closed (`stale-projection-generation`) and mutates nothing |
| `FirewallDigest` | opaque `[u8; 32]` SHA-256 of the Network-UID ownership projection | Stored in status for Network-owned drift comparison only; excludes device-usbip |
| `RouteIntent` | `destinations: Vec<IpNet>`, `via: Option<RouteViaHint>` | CIDRs from declared spec |
| `SysctlIntent` | `ipv6_suppress: bool` | - |
| `NmUnmanagedPattern` | `prefix_pattern: &'static str` (the `"d2b-*"` glob) | Compile-time constant; no runtime string |
| `HostsIntent` | `entries: Vec<HostEntry>` with resource names only | No raw IPs or MACs |
| `DhcpSeedIntent` | `reservations: Vec<DhcpReservation>` with opaque attachment refs | No raw MACs in provider surface |
| `EffectError` | closed typed enum; no String-payload variant | `#[non_exhaustive]` internally; stable codes to provider |

### 5.4 Broker op mapping (core adapter, not provider)

The core adapter maps NetworkEffectPort calls to the following broker wire operations.
This table is informational for the core adapter authors; it does not appear in the
provider crate.

| NetworkEffectPort method | Broker wire op | Migration source |
| --- | --- | --- |
| `create_fabric` | `CreateBridge` (new v3 op) | none (v3 new) |
| `delete_fabric` | `DeleteBridge` (new v3 op) | none (v3 new) |
| `declare_attachment_tap` | `CreatePersistentTap` + `SetBridgePortFlags` | `d2b-priv-broker/src/runtime.rs` tap ops |
| `revoke_attachment_tap` | `DeletePersistentTap` (planned closed op paired with `CreatePersistentTap`) | new v3 op |
| `set_attachment_isolation` | `SetBridgePortFlags` | `d2b-host/src/bridge_port.rs` |
| `apply_host_firewall` | `ApplyNftablesProjection` (new v3 op, `action: Apply`) | none (v3 new; shipped `ApplyNftables` is whole-table, see D-NETWORK-004) |
| `remove_host_firewall` | `ApplyNftablesProjection` (new v3 op, `action: Remove`) | same |
| `apply_host_routes` | `ApplyRoute` | `d2b_contracts::broker_wire::ApplyRouteRequest` |
| `remove_host_routes` | `ApplyRoute` (empty) | same |
| `apply_host_sysctls` | `ApplySysctl` | `d2b_contracts::broker_wire::ApplySysctlRequest` |
| `apply_nm_unmanaged` | `ApplyNmUnmanaged` | `d2b_contracts::broker_wire::ApplyNmUnmanagedRequest` |
| `update_hosts_file` | `UpdateHostsFile` | `d2b_contracts::broker_wire::UpdateHostsFileRequest` |
| `seed_dhcp_reservations` | `SeedDnsmasqLease` | `d2b_contracts::broker_wire::SeedDnsmasqLeaseRequest` |
| `read_firewall_digest` | `ReadNftablesDigest` (new v3 op) | `d2b-host/src/nftables.rs:hash_inet_d2b_table` |
| `read_sysctl_state` | `ReadSysctlState` (new v3 op) | `d2b-host/src/netlink.rs` |
| `read_attachment_isolation` | `ReadBridgePortFlags` (new v3 op) | `d2b-host/src/bridge_port.rs` |

`DeletePersistentTapRequest` is a closed broker request containing only the
opaque attachment ID resolved from `AttachmentHandle`,
`expected_network_generation`, and `expected_attachment_generation`. It has no
IfName, path, or caller-supplied ownership-marker field. The broker resolves the
private realization record, validates both generations and the d2b ownership
marker, and then deletes only that persistent tap. An already-absent tap is
success when the trusted realization record and marker state prove that no
foreign object occupies the attachment; an ownership-marker conflict fails
closed. A generation mismatch never deletes anything and makes the controller
refresh status before retrying.

```rust
#[serde(deny_unknown_fields)]
pub struct DeletePersistentTapRequest {
    pub attachment_id: OpaqueAttachmentId,
    pub expected_network_generation: u64,
    pub expected_attachment_generation: u64,
}
```

The broker appends a post-effect, path-free audit record with
`op: DeletePersistentTap`, an opaque attachment digest, both expected
generations, `outcome`, `error_class`, and `correlation_id`. It never records an
IfName, path, marker body, or attachment-handle bytes. Retryable kernel failures
map to `AttachmentDeleteFailed`; stale fences map to
`AttachmentGenerationMismatch` and requeue after a fresh read; marker conflicts
map to terminal `AttachmentOwnershipConflict`. The finalizer retains the
attachment handle and does not advance until the broker confirms success,
including validated already-absent success.

`ApplyNftablesProjectionRequest` is a new closed broker request that mutates
exactly one validated firewall ownership projection inside the shared `inet d2b`
table. It exists because the shipped `ApplyNftables` op discards `ownership_id`
and atomically deletes and recreates the whole table
(`d2b-priv-broker/src/ops/nft.rs`), which cannot express independent per-Network
reconciles and would erase sibling Networks and device-usbip rules; see
D-NETWORK-004 in `ADR-046-resources-network.md` for the decision. The request
carries only an opaque reference to the validated projection in the
integrity-pinned private bundle plus a generation fence; it never carries inline
rule text, an IfName, or a caller-supplied ownership marker.

```rust
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum NftProjectionAction {
    Apply,
    Remove,
}

#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplyNftablesProjectionRequest {
    pub bundle_nft_projection_ref: BundleOpId,
    pub action: NftProjectionAction,
    pub expected_generation_id: GenerationId,
    pub tracing_span_id: Option<TracingSpanId>,
}
```

The broker resolves `bundle_nft_projection_ref` to the validated projection
(ownership marker + rule set) from the private bundle, compares
`expected_generation_id` against the currently-installed configuration
generation (the bundle `generationId`/`contentHash`, which the broker reloads
per request from the installed bundle and `generation.json`), then:

- for `Apply`, atomically replaces only the rules bearing that projection's
  ownership marker (`comment "d2b managed: <ownership-id>"`) within `inet d2b`,
  byte-preserving every other marker (sibling Networks and every device-usbip
  marker);
- for `Remove`, deletes only that marker's rules; a validated already-absent
  projection is idempotent success.

It never deletes the whole `inet d2b` table. Discovering a foreign marker where
the resolved projection's marker is expected fails closed with
`foreign-nft-rule-preserved`; a request whose `expected_generation_id` differs
from the currently-installed configuration generation mutates nothing and
requeues as `stale-projection-generation` after a fresh read. The op returns the
projection-scoped `FirewallDigest` (SHA-256 over only that marker's rules).
`expected_generation_id` is the immutable installed configuration generation, not
a live projection-generation counter, and there is no compare-and-advance:
serialization is provided by the ordered OFD lock on the `inet d2b` table (total
acquisition order per ADR 0034), so concurrent applies to *different* projections
commute and two concurrent same-generation applies to the *same* projection
converge because they carry identical desired state (see D125). The broker
appends a post-effect, path-free audit record with
`op: ApplyNftablesProjection`, an opaque projection digest, the expected
generationId, `action`, `outcome`, `error_class`, and `correlation_id`; it never
records rule text, an IfName, a marker body, or the projection bytes.

The same closed op serves every ownership projection in `inet d2b`: the
device-usbip Provider's `apply_firewall` / `release_firewall` path
(`ADR-046-provider-device-usbip.md`) mutates its own per-Network/per-busid
projection through this op, so the two Providers preserve each other's markers
by construction.

### 5.5 Runtime Provider attachment FD path

When `Provider/runtime-cloud-hypervisor` reconciles the net-VM Guest, it needs the
tap file descriptors to configure `--net fd=<fd>` arguments.  The runtime Provider
does **not** call the NetworkEffectPort directly.  The net-VM Guest has
`ownerRef: Network/work-net`; core uses the owner/dependency graph to find the
Network, reads the internally-stored `AttachmentHandle` records (never exposed in
any public spec or status field), and supplies the actual tap FDs to the runtime via
the LaunchTicket mechanism.

No attachment identity, tap FD, or kernel interface name flows through the Guest
spec, Guest status, or any other public resource surface.  The binding is purely
private to the core dependency resolver.

---

## 6. Network ResourceType spec

### 6.1 Full spec schema

```yaml
apiVersion: resources.d2bus.org/v3
type: Network
metadata:
  name: work-net                       # ^[a-z][a-z0-9-]*$; max 63; Zone-local
  zone: dev
spec:
  # ── Identity ────────────────────────────────────────────────────────────────
  networkName: work-net                # defaults to metadata.name; used for IfName derivation
  netVmNameOverride: null              # optional; overrides auto-derived net-VM Guest name
  netVmSystemArtifactId: net-vm-base   # REQUIRED; ^[a-z][a-z0-9-]*$; type must be nixos-system
                                       # in d2b.artifacts catalog; checked at build time

  # ── CIDR ────────────────────────────────────────────────────────────────────
  lanCidr: "10.20.0.0/24"             # exactly /24; base ends in .0; RFC1918 recommended
  uplinkCidr: "192.0.2.0/30"          # exactly /30; host .1; net-VM .2

  # ── MTU and MSS ─────────────────────────────────────────────────────────────
  mtu: 1500                            # 576..9000; applied to both bridges
  mssClamp: false                      # true adds TCP MSS clamp rule in net-VM

  # ── Attachments (workload Guests) ───────────────────────────────────────────
  attachments:
    - executionRef: Guest/corp-vm
      index: 10                        # 2..250 inclusive; unique within Network
    - executionRef: Guest/personal-vm
      index: 11

  # ── External physical attachment ────────────────────────────────────────────
  externalAttachment: null             # null or ExternalAttachmentSpec
  # ExternalAttachmentSpec:
  #   mode: macvtap                     # only initial attachment type
  #   parentInterface: eth0            # requested Host inventory selector
  #   macvtapMode: bridge              # bridge|private|vepa|passthru
  #   sharingPolicy: exclusive         # exclusive|multiplexed; explicit
  #                                    # multiplexing valid only for bridge
  #   mac: null                        # null → derived; static or null
  #   ipv4:
  #     method: dhcp                   # dhcp|static
  #     address: null                  # static address/prefix
  #     gateway: null                  # static gateway
  #   egress:
  #     enable: false
  #     allowedCidrs: []               # egress CIDRs for forward chain
  #     masquerade: true
  #   portForwards: []
  #   # PortForwardSpec: {protocol, listenPort, targetRef|targetIp, targetPort, sourceCidrs}

  # ── Isolation ────────────────────────────────────────────────────────────────
  isolation:
    allowEastWest: false               # default false; workload taps set to Isolated=true

  # ── DNS ──────────────────────────────────────────────────────────────────────
  dns:
    forwarders: []                     # upstream DNS IPs passed to dnsmasq
    domain: null                       # optional local search domain
    searchDomains: []

  # ── Routing ──────────────────────────────────────────────────────────────────
  routing:
    hostBlocklist: []                  # additive; controller unions RFC1918+LL defaults

  # ── mDNS ─────────────────────────────────────────────────────────────────────
  mdns:
    enable: false                      # create mDNS reflector Process when true
    dnsmasqLocal: false                # create local DNS bridge Process when true
```

### 6.2 Field validation (validateSpec)

| Field | Constraint | Error code |
| --- | --- | --- |
| `networkName` | `^[a-z][a-z0-9-]*$` | `network-name-invalid` |
| `netVmSystemArtifactId` | Required; `^[a-z][a-z0-9-]*$`; artifact must be type `nixos-system` | `net-vm-artifact-missing`, `net-vm-artifact-type-mismatch` |
| `lanCidr` | Exactly `/24`; base ends in `.0` | `network-cidr-invalid` |
| `uplinkCidr` | Exactly `/30` | `network-cidr-invalid` |
| `lanCidr` ↔ `uplinkCidr` | No overlap | `network-cidr-conflict` |
| `lanCidr`, `uplinkCidr` ↔ peers | No overlap with any other Network in Zone | `network-cidr-conflict` |
| `attachments[].index` | 2..250; unique within Network | `attachment-index-invalid`, `attachment-index-duplicate` |
| `netVmNameOverride` | If set: `^[a-z][a-z0-9-]*$`; not `launcher`; not `sys-*` | `net-vm-name-reserved` |
| `externalAttachment.mode` | `macvtap` | `external-attachment-mode-invalid` |
| `externalAttachment.parentInterface` | Linux IfName syntax; resolves through trusted Host inventory to one physical NIC | `external-parent-interface-invalid`, `external-parent-interface-not-found` |
| `externalAttachment.macvtapMode` | `bridge\|private\|vepa\|passthru` | `external-macvtap-mode-invalid` |
| `externalAttachment.sharingPolicy` | defaults `exclusive`; `multiplexed` must be explicitly authored, requires `macvtapMode=bridge`, requires every multiplexing holder to be in the same Zone, and is bounded by the signed Provider quota | `external-sharing-policy-invalid`, `external-physical-nic-conflict`, `external-physical-nic-cross-zone-l2` |
| `externalAttachment.egress.allowedCidrs` | No overlap with any Network CIDR | `network-cidr-conflict` |
| IfName collision | All derived IfNames unique across Hosts | `ifname-collision` |

IfName collision is terminal: the controller sets `ReconcileError{reason: ifname-collision}`
and halts reconciliation until the operator adjusts `networkName`.

Core resolves `parentInterface` to a non-reversible
`external-physical-nic/v1` identity and preflights the Host-global authority
index before any Provider or broker effect. A second same- or cross-Zone
exclusive claim, a mixed exclusive/multiplexed claim, or any multiplexed
non-bridge claim fails with `external-physical-nic-conflict` and no macvtap or
VMM spawn; a `bridge` multiplex whose holders span two Zones fails with
`external-physical-nic-cross-zone-l2` (INV-NET-011) with no host effect.

### 6.3 Network status schema

D088 status layering is normative: the controller populates the Network
ResourceType-common `status.resource` with network readiness, fabric readiness,
and attachment readiness in the same provider-neutral shape read by all generic
Network consumers. Local bridge/firewall/config observations, including bounded
firewall and config-volume digests, live only in `status.provider.details` with
`providerRef: Provider/network-local`, qualified `schemaId`
(`network-local.d2bus.org/Network/status`), `schemaVersion`, and
`observedProviderGeneration`. Controller status writes include all present layers
atomically in one status mutation; shared fields are never duplicated into
`status.provider`, and the strict, ≤32 KiB, redacted extension schema is
registered and signed in the Provider manifest.

```yaml
status:
  observedGeneration: 1
  phase: Ready          # Pending|Ready|Degraded|Failed|Deleted|Unknown
  conditions: []
  lastReconciledAt: "2026-07-22T00:00:00.000Z"
  resource:
    # Per-workload attachment phases - opaque phase only; no raw IfName or IP
    attachments:
      - executionRef: Guest/corp-vm
        phase: Ready                          # Pending|Ready|Degraded|Absent
    fabricReady: true                         # bridges created and Ready
    externalAttachment: null                  # or bounded phase + D097 authority state
  provider:
    providerRef: Provider/network-local
    schemaId: network-local.d2bus.org/Network/status
    schemaVersion: 1.0.0
    observedProviderGeneration: 1
    details:
      firewallDigest: "<hex-sha256>"          # Network-owned rules only; USBIP excluded
      configVolumeRevisionDigest: "<hex>"     # digest of last committed config Volume content
```

When configured, `status.resource.externalAttachment` contains only `phase`
and universal D097 authority observations:
`available`, `holderCount`, `queueDepth`, `arbitration`, and
`updateCurrency`. It contains no `parentInterface`, opaque key/digest,
owner proof, host/guest IfName, MAC, or address.

**No** raw `ifName`, `bridgeName`, `tapIfName`, `hostUplinkIp`, `netVmUplinkIp`,
`netVmLanIp`, MAC address, attachment handle, FD reference, or kernel path appears
in any public status field, audit record, metric label, or OTEL span attribute.
Attachment handles and FDs are private to the core dependency resolver; they are
never stored in or read from the public resource store.

### 6.4 Conditions

| Condition type | Ready=True when | Reason codes |
| --- | --- | --- |
| `ControllerReady` | Controller Process is Ready | `controller-unavailable` |
| `FabricReady` | Both host bridges exist and sysctls applied | `bridge-create-error`, `sysctl-error`, `ifname-collision` |
| `FirewallReady` | Host nftables `inet d2b` rules applied; digest matches | `nftables-error`, `nftables-drift` |
| `NmUnmanagedReady` | `00-d2b-unmanaged.conf` written | `nm-unmanaged-error` |
| `HostRoutesReady` | Host route to LAN CIDR via uplink bridge applied | `route-error` |
| `ConfigVolumeReady` | Config Volume backing Ready; content written | `config-volume-error`, `volume-backing-error`, `attachment-not-ready` |
| `NetVmReady` | net-VM Guest in Ready phase | `net-vm-pending`, `net-vm-failed`, `net-vm-degraded`, `agent-restart` |
| `DhcpReady` | Guest-agent reports `dnsmasq-bound` readiness predicate | `agent-not-ready`, `dnsmasq-not-bound` |
| `FirewallReady` (guest) | Guest-agent reports `nft-applied` readiness predicate | `nft-not-applied` |
| `DnsReady` | Guest-agent reports `routes-applied` and dnsmasq DNS socket bound | `dns-not-ready` |
| `CidrConflict` | No CIDR overlap detected | `network-cidr-conflict` |
| `ExternalNicAuthorityReady` | Core admitted/adopted the Host-global physical-NIC claim, or no external attachment is configured | `external-physical-nic-claimed`, `external-physical-nic-conflict`, `external-physical-nic-cross-zone-l2`, `external-nic-owner-ambiguous`, `not-required` |
| `ExternalAttachmentReady` | macvtap interface in net VM Ready (if externalAttachment≠null) | `macvtap-not-ready` |
| `MdnsReady` | mDNS Process(es) in Ready phase (if mdns.enable) | `mdns-process-not-ready` |

---

## 7. IfName derivation

IfNames are **internal** to the core adapter.  They are derived deterministically
from `(networkName, role, optional guestName)` using the algorithm in
`packages/d2b-host/src/ifname.rs:derive_ifname`:

- FNV-1a 64-bit hash of the input tuple;
- Crockford base32 encoding (no I/L/O/U);
- truncated to 8 characters;
- prefixed as:

| Role | Prefix | Total max length |
| --- | --- | --- |
| LAN bridge | `d2b-b` | 14 chars ≤ IFNAMSIZ-1 |
| Uplink bridge | `d2b-b` | 14 chars |
| Net-VM LAN tap | `d2b-t` | 14 chars |
| Net-VM uplink tap | `d2b-t` | 14 chars |
| Workload Guest tap | `d2b-t` | 14 chars |
| External macvtap | `d2b-t` | 14 chars |

The 15-byte IFNAMSIZ-1 constraint is guaranteed by construction.  Collision
detection (`detect_collisions`) re-runs at every reconcile cycle.  A collision is
terminal (§6.2).

IfNames **never** appear in:
- `Network.spec` fields (any kind);
- `Network.status` fields (any kind);
- `Guest.spec.provider.settings`;
- audit records;
- OTEL span attributes or metric labels;
- any user-facing diagnostic beyond the bounded diagnostic API.

---

## 8. Net-VM Guest resource

The Network controller creates and owns exactly one net-VM Guest per Network.

```yaml
apiVersion: resources.d2bus.org/v3
type: Guest
metadata:
  name: net-work-net                    # or spec.netVmNameOverride
  zone: dev
  ownerRef: Network/work-net            # owner relationship; core uses this to bind tap FDs
spec:
  providerRef: Provider/runtime-cloud-hypervisor
  defaultDomain: system
  allowedDomains: [system]
  budget:
    memory: { request: "256Mi", limit: "512Mi" }
    vcpus: 1
  systemArtifactId: net-vm-base         # from Network.spec.netVmSystemArtifactId
                                        # plain bounded ID ^[a-z][a-z0-9-]*$ - NOT a path
  # spec.provider.settings carries only runtime-cloud-hypervisor desired values.
  # Tap FDs are resolved privately by core from the Network→Guest owner relationship
  # and are supplied to the runtime via LaunchTicket.
  # No attachment identity, handle, IfName, IP, or MAC appears here.
  provider:
    schemaId: runtime-cloud-hypervisor.d2bus.org/Guest/spec
    schemaVersion: 1.0.0
    settings:
      vsockCid: 1024                  # assigned from the Network's CIDR allocation
  # When spec.externalAttachment is non-null, Core resolves its admitted
  # Host-global authority privately and supplies the macvtap FD through the
  # LaunchTicket. parentInterface and authority identity are not copied here.
```

`systemArtifactId` is a plain bounded ID (`^[a-z][a-z0-9-]*$`); it is **not** a
Nix store path or a `nixos-system/...` path.  The artifact catalog entry
(`d2b.artifacts.net-vm-base`) maps this ID to the nixos-system derivation.

The nixos-system artifact contains the **generic** net-VM OS: guest-agent binary,
kernel, base NixOS services, and systemd-networkd NIC bootstrap with the
`lib.mkForce` override on `10-eth-dhcp` (INV-NET-001).  It does NOT encode
per-Network DHCP reservations, nftables rules, or routing policy.  All
per-Network desired state flows through the config Volume (§9).

Mutations changing only DHCP/DNS, firewall, or attachment configuration update the
config Volume and trigger a guest-agent `Reload()` call; a Guest switch or restart
is NOT required.  NIC topology changes (attachment index add/remove, external
attachment) additionally require a Guest spec update.

---

## 9. Config Volume resource

The Network controller creates one config Volume per Network.  `Provider/volume-local`
is the sole reconciler of all Volume resources; the network-local controller creates
Volume resource objects (with `ownerRef: Network/<name>`) but does not implement or
reconcile the Volume ResourceType.

```yaml
apiVersion: resources.d2bus.org/v3
type: Volume
metadata:
  name: net-work-net-config             # net-<networkName>-config
  zone: dev
  ownerRef: Network/work-net
spec:
  providerRef: Provider/volume-local
  kind: ephemeral                       # tmpfs-backed; boot-scoped; no persistent backing
  source:
    executionRef: Host/host-system      # backing tmpfs on this Host
    settings:
      kind: tmpfs                       # memory-backed; charged to Host memory budget
  quota:
    maxBytes: 4194304                   # 4 MiB; tmpfs size= option; kernel-enforced
    maxInodes: 128                      # bounded; tmpfs nr_inodes= option
    enforcement: hard                   # required for tmpfs; kernel enforces
  layout:
    - path: ""                          # Volume root directory
      type: directory
      ownerRef: User/net-local-controller
      groupRef: User/net-local-controller
      mode: "0750"
      accessAcl: []
      defaultAcl: []
      noFollow: true
      createPolicy: create-if-absent
      repairPolicy: exact-owner
      cleanupPolicy: owner-controlled
    - path: "dnsmasq.conf"
      type: file
      ownerRef: User/net-local-controller
      groupRef: User/net-local-controller
      mode: "0640"
      accessAcl: []
      defaultAcl: []
      noFollow: true
      createPolicy: create-if-absent
      repairPolicy: exact-owner
      cleanupPolicy: owner-controlled
    - path: "nftables.rules"
      type: file
      ownerRef: User/net-local-controller
      groupRef: User/net-local-controller
      mode: "0640"
      accessAcl: []
      defaultAcl: []
      noFollow: true
      createPolicy: create-if-absent
      repairPolicy: exact-owner
      cleanupPolicy: owner-controlled
    - path: "routing.conf"
      type: file
      ownerRef: User/net-local-controller
      groupRef: User/net-local-controller
      mode: "0640"
      accessAcl: []
      defaultAcl: []
      noFollow: true
      createPolicy: create-if-absent
      repairPolicy: exact-owner
      cleanupPolicy: owner-controlled
    - path: "attachments.json"
      type: file
      ownerRef: User/net-local-controller
      groupRef: User/net-local-controller
      mode: "0640"
      accessAcl: []
      defaultAcl: []
      noFollow: true
      createPolicy: create-if-absent
      repairPolicy: exact-owner
      cleanupPolicy: owner-controlled
  views:
    guest-readonly:
      path: ""                          # root of the Volume subtree
      rights: [read, traverse]          # minimum for agent to read config files
  attachments: []                       # initially empty; Guest attachment added in Phase 2
```

### 9.1 Volume content

Content is **bounded structured network configuration** rendered from `Network.spec`.
No workload VM names, host paths, raw IfNames, raw IP addresses of individual
workload VMs, or other per-workload identifiers appear in paths or file entries.
Content that appears in files:

| File | Content |
| --- | --- |
| `dnsmasq.conf` | DHCP reservations (MAC→index mapping, no external hostnames), forwarders, domain, static pools; `bind-interfaces=true`; `dhcp-ignore-names=true`; dnsmasq system user; hardened confinement settings from `nixos-modules/net.nix` lines 363-441 |
| `nftables.rules` | Complete `inet` filter/nat/ip6 rulesets for the net VM; all semantics from `nixos-modules/net.nix` lines 168-296; no raw tap IfNames (interface indices used via `eth0`/`eth1` NIC naming inside guest) |
| `routing.conf` | Static routes for external attachment egress CIDRs; no raw IfNames |
| `attachments.json` | Attachment index → MAC mapping; no Guest resource names or workload IPs |

No raw kernel interface name, host bridge name, IP address, or hostname appears in
any Volume file in a form that constitutes a network configuration secret.

### 9.2 Writes through Volume service

The controller submits a typed `network-config` content projection through the
canonical `Volume` spec update path. `Provider/volume-local` consumes that
projection, resolves its own anchored root, verifies the Volume marker and
declared owner/mode, and materializes the four files through its content effect
port. Network-local never receives or manipulates the underlying filesystem
path. The Volume status provider details carry only the bounded materialization
evidence and content digest used by Network readiness; the desired projection
bytes are not readiness evidence.

### 9.3 Two-phase provisioning

**Phase 1 - backing ready**: create Volume with `attachments: []`.  Backing tmpfs
becomes Ready.  Controller writes initial config content via Volume service.

**Phase 2 - Guest attachment**: after net-VM Guest reaches Ready, update Volume to
add:
```yaml
attachments:
  - executionRef: Guest/net-work-net
    transport: virtiofs
    view: guest-readonly
    access: read-only
    mountPath: "/run/d2b/net-config"
    settings:
      posixAcl: false
      xattr: false
      cache: auto
      inodeFileHandles: never
      threadPoolSize: null
      socketGroup: null
```

Only after the attachment reaches Ready may the guest-agent Process be created.

---

## 10. User resource - net-local-controller

The `User/net-local-controller` resource is **declared in Nix** (§22) and
reconciled to Ready by `Provider/system-core` via NSS lookup.  The network-local
controller does **not** create this User resource dynamically; it waits for it to
be Ready as a reconcile precondition.

```yaml
apiVersion: resources.d2bus.org/v3
type: User
metadata:
  name: net-local-controller            # ^[a-z][a-z0-9-]*$
  zone: dev
  ownerRef: Provider/network-local      # owner is the Provider; set in Nix
spec:
  osUsername: net-local-controller      # OS username for NSS getpwnam
  # spec contains only: osUsername, displayName (optional), groups (optional)
  # NO managedBy field - that is metadata.managedBy set by core, not spec
```

`spec.managedBy` does **not** exist in the User spec.  The `ownerRef` is in
`metadata`, not `spec`.  The Nix module pre-provisions the OS account (fixed UID/GID)
in Host prerequisites and in the generic net-VM nixos-system artifact so virtiofs
ACLs are consistent on both sides.  `Provider/system-core` reconciles the User
resource to Ready via NSS `getpwnam(net-local-controller)`.

Numeric UID/GID never enter any ResourceSpec field, authz check, or audit record.
`User.status` MAY carry diagnostic `uid`/`gid` values from NSS lookup; those are
informational only and are never authorization inputs.

The controller waits for `User/net-local-controller.status.phase == Ready` before
creating any config Volume.  This is a reconcile precondition enforced by checking
the `DependenciesReady` condition.

---

## 11. Process resources

The network-local controller creates four Process resources per Network.  All four
are owned by `Network/<networkName>` and run on `Guest/<netVmName>`.

### 11.1 Net-agent service (Process/net-\<networkName\>-agent)

The net-agent is a **`service`** (not a `worker`).  It serves an internal
ComponentSession method `NetworkAgentService` over a Noise-KK vsock.  It applies
nftables rules and ip routes inside the net VM on startup and on `Reload()` calls.
It does **not** supervise or spawn dnsmasq; dnsmasq is a separate Process (§11.2).

```yaml
apiVersion: resources.d2bus.org/v3
type: Process
metadata:
  name: net-work-net-agent
  zone: dev
  ownerRef: Network/work-net
spec:
  providerRef: Provider/system-minijail
  executionRef: Guest/net-work-net      # runs INSIDE the net-VM Guest
  domain: system
  processClass: service                 # serves typed ComponentSession methods
  template: net-vm-agent
  sandbox:
    namespaceClasses: []                # empty: inherit all Guest namespaces (incl. netns)
    capabilityClasses: [network-admin, network-raw]
    # network-admin → CAP_NET_ADMIN: required for nft ruleset load and ip route
    # network-raw   → CAP_NET_RAW:   required for raw socket operations
    # Both are effective only within the inherited Guest network namespace; no
    # host capability is conferred (INV-NET-009).
    # network-bind is NOT required here; dnsmasq is a separate Process (§11.2).
    seccompClass: strict
    noNewPrivileges: true
    startRoot: false
    readOnlyRoot: true
    environmentClass: minimal
  budget:
    memory: { request: "8Mi", limit: "32Mi" }
    pids: { limit: 16 }
    fds: { limit: 64 }
  mounts:
    - volumeRef: Volume/net-work-net-config
      view: guest-readonly
      mountPath: "/run/d2b/net-config"
      access: read-only
      required: true
  networkUsage:
    networkRef: Network/work-net
    ports: []
    allowEgress: true
  desiredLifecycle: running
  restartPolicy:
    class: on-failure
    backoffBase: "1s"
    backoffMax: "60s"
    backoffMultiplierMilli: 2000
    maxRestarts: null
    resetAfter: "300s"
  readiness:
    initialDelay: "2s"
    timeout: "30s"
    failureThreshold: 3
    successThreshold: 1
    class: provider-defined
    # Provider-defined: agent reports typed readiness predicates via its
    # ComponentSession service interface (see §11.1.1)
  healthCheck:
    enabled: true
    interval: "30s"
    timeout: "5s"
    failureThreshold: 3
    class: provider-defined
  adoptionPolicy: adopt-on-restart
  drainTimeout: "10s"
```

The agent's stable service binding is represented as an owned `Endpoint`
resource:

```yaml
apiVersion: resources.d2bus.org/v3
type: Endpoint
metadata:
  name: net-work-net-agent-service
  zone: dev
  ownerRef: Process/net-work-net-agent
spec:
  providerRef: Provider/network-local
  producerRef: Process/net-work-net-agent
  endpointClass: service
  transport: vsock
  purpose: network-local.d2bus.org/agent
  serviceFingerprint: d2b.network.v3.agent/v1
  locality: cross-domain
  visibility: zone
  attachmentPolicy: none
  consumerPolicy:
    allowedProviderComponents: [provider-network-local.d2bus.org/controller]
    allowedOperations: [resolve]
  lifecyclePolicy: producer-owned
status:
  phase: Ready
  resource:
    readiness: Ready
    observedProducerGeneration: 1
    observedResourceGeneration: 1
    endpointGeneration: 1
    connectionAvailability: Available
    leaseAvailability: NotRequired
  conditions: []
  update:
    state: Current
    reasons: []
    observedGeneration: 1
    targetGeneration: 1
    disruption: None
    preserveState: true
    operationId: null
    lastAssessedAt: null
    owned: { count: 0, refs: [] }
    dependencies: { count: 0, refs: [] }
```

#### Endpoint resources (D092)

Stable network service bindings that are independently consumed are standard
`Endpoint` resources. The net-agent service Endpoint above is one example; a
future DHCP, DNS, or mDNS service binding that is consumed outside its owning
Process would likewise be an Endpoint child with `producerRef` pointing at the
service Process. Bridge/fabric realization, tap handles, route/nft state, and
config Volume contents remain Network/Process realization state, not Endpoints.
Consumers use `Endpoint/<name>`, raw addresses and ports never appear in
`Endpoint.spec` or `Endpoint.status`, authorized resolution goes through
EffectPort/LaunchTicket, unauthorized callers receive `endpoint-resolve-denied`,
and a producer restart bumps `endpointGeneration` so consumers observe
`dependency-changed`.

#### Retained opaque handles (D092)

Per-session named streams, `OwnedTransport` byte-stream handles, transport
connection handles, pidfds, FD indexes, NetworkEffectPort operation handles,
bridge/tap realization handles, and `operationId` values remain
controller-internal or high-churn opaque handles. They are not promoted to
`Endpoint` resources.

#### 11.1.1 NetworkAgentService ComponentSession interface

The agent serves one Noise-KK vsock ComponentSession service
`d2b.network.v3.agent/v1`:

```text
service NetworkAgentService {
  // Apply nftables rules and ip routes from the config Volume.
  // Called by the host controller after writing new config content.
  // config_digest: SHA-256 of the config Volume content at write time.
  // Returns: applied predicate set and any error codes.
  Reload(config_digest: ConfigDigest) -> ReloadResult

  // Return current readiness predicates.
  ReadinessQuery() -> AgentReadiness
}

message AgentReadiness {
  nft_applied: bool
  routes_applied: bool
}

message ReloadResult {
  applied_digest: ConfigDigest
  predicates: AgentReadiness
  errors: [AgentError]     # bounded typed error codes; no raw kernel output
}
```

The host controller calls `Reload()` after each successful config Volume write.
The agent does NOT watch the Volume directly or use any Volume watch interface.

The agent's sole responsibilities:
1. On startup: read `/run/d2b/net-config/nftables.rules` and apply via `nft -f`;
   read `/run/d2b/net-config/routing.conf` and apply via `ip route`;
   report `nft-applied` and `routes-applied` readiness predicates.
2. On `Reload(digest)`: atomically re-read and re-apply nftables and routes;
   return `ReloadResult`.

The agent does **not**: supervise dnsmasq; watch any Volume interface; fork or exec
any child process; expose any bus authority beyond the single vsock service endpoint;
or perform any Resource API calls.

### 11.2 Dnsmasq worker (Process/net-\<networkName\>-dnsmasq)

dnsmasq runs as a separate owned `worker` Process.  It reads its config from the
Volume mount at startup.  Workers have **no** bus authority, no dependency/resource
API, and no child-spawning.

```yaml
apiVersion: resources.d2bus.org/v3
type: Process
metadata:
  name: net-work-net-dnsmasq
  zone: dev
  ownerRef: Network/work-net
spec:
  providerRef: Provider/system-minijail
  executionRef: Guest/net-work-net
  domain: system
  processClass: worker                  # no bus, no resource API, no child spawning
  template: net-vm-dnsmasq
  sandbox:
    namespaceClasses: []                # inherit Guest namespaces
    capabilityClasses: [network-bind, network-raw]
    # network-bind → CAP_NET_BIND_SERVICE: bind to port 53 (DNS) and port 67 (DHCP)
    # network-raw  → CAP_NET_RAW:          DHCP raw socket operations
    seccompClass: strict
    noNewPrivileges: true
    startRoot: false
    readOnlyRoot: true
    environmentClass: minimal
  budget:
    memory: { request: "8Mi", limit: "32Mi" }
    pids: { limit: 8 }
    fds: { limit: 64 }
  mounts:
    - volumeRef: Volume/net-work-net-config
      view: guest-readonly
      mountPath: "/run/d2b/net-config"
      access: read-only
      required: true
  networkUsage:
    networkRef: Network/work-net
    ports:
      - port: 53
        protocol: udp
        purpose: dns
      - port: 53
        protocol: tcp
        purpose: dns
      - port: 67
        protocol: udp
        purpose: dhcp
    allowEgress: true
  desiredLifecycle: running
  restartPolicy:
    class: on-failure
    backoffBase: "1s"
    backoffMax: "60s"
    backoffMultiplierMilli: 2000
    maxRestarts: null
    resetAfter: "300s"
  readiness:
    initialDelay: "1s"
    timeout: "20s"
    failureThreshold: 3
    successThreshold: 1
    class: provider-defined
    # Provider-defined readiness: dnsmasq-bound socket detected by the Process Provider
  healthCheck:
    enabled: true
    interval: "30s"
    timeout: "5s"
    failureThreshold: 3
    class: provider-defined
  adoptionPolicy: adopt-on-restart
  drainTimeout: "5s"
```

**Config updates**: when the controller writes new config Volume content, it
forces a dnsmasq restart by setting `desiredLifecycle: stopped` followed by
`running` in a ResourceMutationBatch.  The controller waits for the dnsmasq
Process to reach Ready again before reporting `DhcpReady=True`.

dnsmasq invariants (preserved from `nixos-modules/net.nix` lines 302-441):
- `bind-interfaces=true` (binds only to `eth1`/LAN);
- `dhcp-ignore-names=true` (no hostname spoofing);
- static DHCP host reservations from `spec.attachments[]` (via config Volume);
- DHCP dynamic pool: `lanCidr.251`-`lanCidr.254`;
- DNS forwarders from `spec.dns.forwarders`;
- runs under the `net-local-controller` OS user with hardened minijail confinement.

### 11.3 mDNS reflector worker (Process/net-\<networkName\>-mdns-reflector)

Created only when `spec.mdns.enable = true`.

```yaml
apiVersion: resources.d2bus.org/v3
type: Process
metadata:
  name: net-work-net-mdns-reflector
  zone: dev
  ownerRef: Network/work-net
spec:
  providerRef: Provider/system-minijail
  executionRef: Guest/net-work-net
  domain: system
  processClass: worker                  # no bus, no resource API
  template: net-vm-mdns-reflector
  sandbox:
    namespaceClasses: []
    capabilityClasses: [network-raw]    # CAP_NET_RAW for multicast socket
    seccompClass: strict
    noNewPrivileges: true
    startRoot: false
    readOnlyRoot: true
    environmentClass: minimal
  budget:
    memory: { request: "4Mi", limit: "16Mi" }
    pids: { limit: 4 }
    fds: { limit: 32 }
  networkUsage:
    networkRef: Network/work-net
    ports:
      - port: 5353
        protocol: udp
        purpose: mdns
    allowEgress: true
  desiredLifecycle: running
  restartPolicy:
    class: on-failure
    backoffBase: "2s"
    backoffMax: "60s"
    backoffMultiplierMilli: 2000
    maxRestarts: null
    resetAfter: "300s"
  readiness:
    initialDelay: "1s"
    timeout: "15s"
    failureThreshold: 3
    successThreshold: 1
    class: provider-defined
  healthCheck:
    enabled: false
    interval: "30s"
    timeout: "5s"
    failureThreshold: 3
    class: provider-defined
  adoptionPolicy: adopt-on-restart
  drainTimeout: "5s"
```

### 11.4 mDNS local DNS bridge worker (Process/net-\<networkName\>-mdns-dnsbridge)

Created only when `spec.mdns.enable = true` and `spec.mdns.dnsmasqLocal = true`.

```yaml
apiVersion: resources.d2bus.org/v3
type: Process
metadata:
  name: net-work-net-mdns-dnsbridge
  zone: dev
  ownerRef: Network/work-net
spec:
  providerRef: Provider/system-minijail
  executionRef: Guest/net-work-net
  domain: system
  processClass: worker
  template: net-vm-mdns-dnsbridge
  sandbox:
    namespaceClasses: []
    capabilityClasses: [network-bind]   # CAP_NET_BIND_SERVICE for DNS port
    seccompClass: strict
    noNewPrivileges: true
    startRoot: false
    readOnlyRoot: true
    environmentClass: minimal
  budget:
    memory: { request: "4Mi", limit: "16Mi" }
    pids: { limit: 4 }
    fds: { limit: 32 }
  networkUsage:
    networkRef: Network/work-net
    ports:
      - port: 5353
        protocol: udp
        purpose: mdns
    allowEgress: true
  desiredLifecycle: running
  restartPolicy:
    class: on-failure
    backoffBase: "2s"
    backoffMax: "60s"
    backoffMultiplierMilli: 2000
    maxRestarts: null
    resetAfter: "300s"
  readiness:
    initialDelay: "1s"
    timeout: "15s"
    failureThreshold: 3
    successThreshold: 1
    class: provider-defined
  healthCheck:
    enabled: false
    interval: "30s"
    timeout: "5s"
    failureThreshold: 3
    class: provider-defined
  adoptionPolicy: adopt-on-restart
  drainTimeout: "5s"
```

---

## 12. Host fabric lifecycle

### 12.1 Bridge creation and deletion

Bridge creation and deletion are **dynamic operations** driven through
`NetworkEffectPort.create_fabric()` and `NetworkEffectPort.delete_fabric()`.
A NixOS generation switch is NOT required to create or remove a Network.

`create_fabric` (via core adapter `CreateBridge` broker op):
- creates the kernel bridge device with the internally-derived IfName;
- sets MTU from `spec.mtu`;
- disables STP and multicast snooping unconditionally;
- applies IPv6 suppression sysctls atomically
  (`disable_ipv6=1`, `accept_ra=0`, `autoconf=0`)
  before returning (closes race between creation and subsequent sysctl step).

`delete_fabric` (via core adapter `DeleteBridge` broker op):
- removes only the kernel bridge device after every persistent tap has been
  confirmed removed through `DeletePersistentTap`;
- never cascades deletion to an attached tap; a remaining owned tap is
  retryable and a foreign port/marker fails closed;
- idempotent (returns success if already absent).

### 12.2 IPv6 suppression (defense-in-depth)

IPv6 suppression is applied at two points:
1. Atomically inside `create_fabric` (per bridge, at creation time);
2. Via `apply_host_sysctls` at each reconcile cycle (handles `systemctl restart
   systemd-networkd` and any sysctl drift).

No Nix boot-time sysctl entry is required for specific bridge IfNames because
bridges are created dynamically.

### 12.3 Tap lifecycle

Persistent-tap creation is declared by the network-local controller through
`NetworkEffectPort`; Core maps that declaration to `CreatePersistentTap` and
supplies the resulting FD privately to
**`Provider/runtime-cloud-hypervisor`** through LaunchTicket. The
network-local controller:
1. Calls `NetworkEffectPort.declare_attachment_tap()` to record the attachment intent
   and receive an `AttachmentHandle`;
2. Stores the handle in `Network.status.resource.attachments[]`;
3. Calls `NetworkEffectPort.set_attachment_isolation()` to apply isolated/
   neigh-suppress bridge port flags when the tap is created.

Core resolves the handle privately when the runtime Provider needs the tap FD;
the runtime does not own persistent-tap deletion. On attachment removal or
Network finalization, the network-local controller waits until the Guest/VMM no
longer owns the FD, then calls `revoke_attachment_tap(handle,
AttachmentGenerationFence { expected_network_generation,
expected_attachment_generation })`. The core adapter maps that call only to
`DeletePersistentTap`; the handle/fence never becomes an IfName or path input
from the Provider.

### 12.4 NM unmanaged and /etc/hosts

- `NetworkEffectPort.apply_nm_unmanaged()` writes `00-d2b-unmanaged.conf`
  with the `d2b-*` prefix pattern, covering all dynamically-created d2b bridges
  and taps regardless of specific IfNames.
- `NetworkEffectPort.update_hosts_file()` maintains VM→IP entries in the
  `d2b-managed` block of `/etc/hosts`.  **No hostname, IP, or MAC is stored in
  any public spec/status/audit field** - /etc/hosts entries are write-only
  from the resource API's perspective.

### 12.5 DHCP pre-seed

`NetworkEffectPort.seed_dhcp_reservations()` pre-seeds dnsmasq DHCP lease
reservations for known attachment MACs via `SeedDnsmasqLease` broker op.  Entries
use opaque attachment refs; the DHCP MAC-to-IP mappings are not stored in any
public resource field.

---

## 13. DHCP/DNS and firewall lifecycle

### 13.1 DHCP/DNS (inside net VM)

The dnsmasq worker Process (§11.2) runs inside the net VM.  The network-local
controller writes `dnsmasq.conf` to the config Volume; dnsmasq reads it at startup
from the mounted read-only Volume view at `/run/d2b/net-config/dnsmasq.conf`.

Config update flow:
1. Controller detects `Network.spec` change affecting DHCP/DNS.
2. Controller writes new `dnsmasq.conf` to the config Volume via Volume service.
3. Controller calls `NetworkAgentService.Reload(new_digest)` on the agent to apply
   updated nftables/routes.
4. Controller restarts the dnsmasq Process (sets `desiredLifecycle: stopped` then
   `running` in a ResourceMutationBatch).
5. dnsmasq Process Provider stops dnsmasq, waits for Process Ready, then starts
   dnsmasq with the new config.
6. Once dnsmasq Process returns to Ready, controller sets `DhcpReady=True`.

### 13.2 Host-side firewall (inet d2b table)

The controller calls `NetworkEffectPort.apply_host_firewall()` with a
`FirewallIntent` and a `FirewallGenerationFence` at each reconcile cycle. The
core adapter dispatches the `ApplyNftablesProjection` broker op (`action:
Apply`), which mutates only this Network UID's ownership projection inside the
shared `inet d2b` table and byte-preserves every other marker (see §5.4). The
`inet d2b` table:
- blocks all traffic on LAN bridges (host has no IP there);
- installs per-rule `comment "d2b managed: <ownership-id>"` markers
  (ownership ID is the Network resource UID - opaque, not the IfName);
- coexists with other firewall managers per `FirewallCoexistencePolicy`
  (Coexist/Refuse/RequireUnmanaged matrix from `d2b-host/src/nftables.rs`).

Because the op is projection-scoped, independent Network reconciles never
overwrite one another and never delete the whole table: a mutation to one
Network's marker leaves every sibling Network and every device-usbip marker
byte-preserved. The ordered OFD lock on the `inet d2b` table serializes
concurrent mutations. The generation fence does not serialize and has no
compare-and-advance behavior; it only rejects and requeues an intent whose
`expected_generation_id` names a superseded installed configuration generation.
Same-generation mutations converge idempotently under the lock. Network-local
emits no USBIP rule and no TCP/3240 match. The returned `FirewallDigest` covers
only this Network UID's ownership projection and is stored in
`status.provider.details.firewallDigest` for drift detection.
Device-usbip-owned rules and markers are excluded. No rule text appears in
status, audit, or telemetry.

### 13.3 Net-VM-side firewall (via config Volume)

The controller writes the net VM's nftables ruleset to the `nftables.rules` config
Volume entry.  The **net-agent service** reads and applies it via `nft -f` at
startup and on each `Reload()` call.  The ruleset preserves all semantics from
`nixos-modules/net.nix` lines 168-296 (see §16 security invariants for the full
chain), except that it contains no USBIP/TCP-3240 carve-out. USBIP Binding
proxies receive an authorized connected relay stream through Endpoint
resolution and a LaunchTicket; they do not require a generic net-VM forward
allow.

### 13.4 Drift detection (observe)

On each observe cycle (`observeInterval: 60s`):
- `NetworkEffectPort.read_firewall_digest()` → compare against `status.provider.details.firewallDigest`;
  compare only Network-UID-owned rules; if drift, set
  `FirewallReady=False/nftables-drift` and queue reconcile. Ignore
  device-usbip-owned rules and marker churn.
- `NetworkEffectPort.read_sysctl_state()` → compare against expected IPv6 suppression;
  if drift, queue reconcile.
- `NetworkEffectPort.read_attachment_isolation()` per attachment → compare against
  expected isolation; if drift, queue reconcile.

Observation commits status-only updates without incrementing resource generation.

---

## 14. Attachment lifecycle

### 14.1 Workload Guest attachment

A workload Guest requests attachment by appearing in `Network.spec.attachments`.
The network-local controller:
1. Calls `NetworkEffectPort.declare_attachment_tap()` → receives `AttachmentHandle`.
2. Stores handle in `Network.status.resource.attachments[]` (opaque; no raw IfName).
3. Calls `NetworkEffectPort.set_attachment_isolation()` with `isolated: !spec.isolation.allowEastWest`.

The runtime-cloud-hypervisor Provider resolves the `AttachmentHandle` to an FD
via LaunchTicket when starting the workload Guest.  The runtime does not read
the `AttachmentHandle` directly; core supplies the FD implicitly.

### 14.2 East-west isolation

Default: `isolation.allowEastWest = false`:
- tap bridge port flags `Isolated=true`;
- no `eth1→eth1 new accept` rule in net-VM forward chain.

`allowEastWest = true`:
- `set_attachment_isolation(handle, isolated: false)` on all workload taps;
- adds east-west accept rule in net-VM forward chain.

### 14.3 External attachment (macvtap)

When `spec.externalAttachment` is non-null:
1. Core resolves the operator-declared `parentInterface` through trusted Host
   inventory, derives the private physical-NIC authority identity, and admits
   the Host-global claim. The controller receives only success/failure and
   bounded authority status; it does not receive the key/digest or owner proof.
2. Core resolves the Network→Guest owner relationship and supplies the admitted
   attachment through the private dependency resolver and LaunchTicket. The
   controller does not copy `parentInterface` or an authority key into Guest
   spec. `Provider/runtime-cloud-hypervisor` requests the opaque VMM launch
   through its injected ProcessEffectPort. The core effect adapter privately
   dispatches the broker's `SpawnRunner` operation, and the broker creates the
   macvtap FD internally (`live_create_macvtap_fd` in
   `d2b-priv-broker/src/runtime.rs`) before core supplies it in the LaunchTicket.
3. Port-forward DNAT rules are written to `nftables.rules` by the controller and
   applied by the net-agent inside the net VM.

The `ExternalAttachmentReady` condition reflects macvtap interface state via the
net VM's Guest readiness predicates. `ExternalNicAuthorityReady` independently
reflects authority admission/adoption.

### 14.4 External physical-NIC AuthorityDescriptor

The signed Provider descriptor classifies every non-null
`Network.externalAttachment` with this D097 contract:

```yaml
authorityScope: physical-device            # Host-global index scope
authorityKey: external-physical-nic/v1     # Core-derived opaque key class
cardinality: zero-or-one
arbitration: exclusive                     # multiplexed only for explicit same-Zone bridge policy
authorityRef: Network/work-net
duplicateConflict: external-physical-nic-conflict
ownerProof: network-resource-and-vmm-process-identity
updateStrategy: drain-release-reacquire
exportability: forbidden
quota:
  maxHolders: 1                            # exclusive; signed 2..16 for multiplexed
  fairness: fifo
```

The selector name is not the authority key. Core resolves it to trusted
physical-NIC identity, derives the opaque digest, and indexes
`(Host, external-physical-nic, opaqueKeyDigest)` across all Zones on that Host.
The authority binds an isolation domain equal to the claimant's Zone UID.
`passthru`, `private`, and `vepa` are always exclusive. `bridge` defaults
exclusive and may be multiplexed only when every holder explicitly declares
`sharingPolicy: multiplexed`, every holder belongs to the same Zone (the same
isolation domain), and the signed quota admits it. A `bridge` multiplex whose
holders span two Zones is categorically rejected fail closed with
`external-physical-nic-cross-zone-l2`, because those macvtap endpoints would
share one L2 broadcast domain and work and personal Zones never share an L2
bridge. Core retains one authority owner and treats additional admitted
same-Zone Networks as bounded holders; no holder opens the backing a second
time.

Changing `parentInterface`, `macvtapMode`, or `sharingPolicy` reports
`UpgradeRequired` with disruptive recycle. The planner drains dependent
attachments and the net VM, closes the old macvtap/VMM ownership, releases the
old claim, admits the new claim, and only then spawns the replacement. Delete
releases the claim last. Restart adopts only the exact resource/process
`ownerProof`; ambiguity sets
`ExternalNicAuthorityReady=False/external-nic-owner-ambiguous` and quarantines
the attachment. When the owner of a compatible multiplexed authority is
deleted, Core atomically transfers the owner proof to the oldest admitted
holder without reopening the NIC; failure to prove that transfer blocks
release.

---

## 15. USBIP proxy boundary

The USBIP backend and proxy processes are **not** owned by the network-local
controller.  They are owned by `Provider/device-usbip`.

USBIP-owned `ApplyNftablesProjection` requests stay with
`Provider/device-usbip`. The network-local controller does **not** install USBIP
firewall rules and does **not** dispatch that shared operation for a
device-usbip projection. The shipped whole-table `UsbipBindFirewallRule` op is
not the firewall path.

Network-local emits **no** USBIP or TCP/3240 rule on the host or in the net-VM
ruleset. `Network.spec` has no `usbipCarveOut` field and must not be mutated by
the device-usbip provider. Network `FirewallReady` and
`status.provider.details.firewallDigest` cover only Network-UID-owned rules and
ignore device-usbip ownership markers.

`Provider/device-usbip` consumes `Network/work-net` via a `networkRef`
dependency, watches only identity/readiness/generation, and owns exactly one
multiplexed relay `Endpoint` authority per Network. Its typed
`UsbipEffectPort` is the sole semantic path for all TCP/3240 and
per-Network/per-busid firewall effects. The Core adapter privately resolves the
Network UID and dispatches the shared closed `ApplyNftablesProjection` broker
operation for the device-usbip-owned projection; raw attachment handles,
IfNames, addresses, and rules never enter either Provider controller. USBIP
drift and status belong exclusively to the owning USB Service's strict provider
status.

---

## 16. Reconcile loop

The network-local controller implements the full reconciliation contract from
`ADR-046-resource-reconciliation`.

### 16.1 Async loop invariants

From RECONCILE §Async interface:
> No handler holds a redb transaction or blocking kernel/systemd/filesystem call
> across an await.  Blocking effects use explicit bounded adapters.

From RECONCILE §Async loop, step 7:
> Each resource has one running handler; independent resources run in parallel
> under semaphore/budget.

From RECONCILE §Reconcile context:
> It contains no database handle, direct broker socket, reusable credential, raw
> route table, or authority supplied by the resource payload.

All `NetworkEffectPort` calls are dispatched in background tasks through bounded
blocking adapters.  The reconcile handler releases any redb read transaction before
the first `await` on an effect call.  Each resource's reconcile/observe/finalize
handler runs independently; the watch receiver continues dispatching other ready
resources without waiting for any single handler.

**Currency and upgrade (D091).** The controller implements `assess_update`,
`plan_upgrade`, and `execute_upgrade` for Network fabric realization and writes
only the universal `status.update`, never `status.provider`, with
`state: Current|UpdateAvailable|UpgradeRequired|Upgrading|Blocked|Unknown`,
`reasons` from `CoreGenerationChanged`, `ProviderGenerationChanged`,
`ArtifactChanged`, `ImageOrSystemGenerationChanged`, `SpecChanged`,
`DependencyChanged`, or `SecurityPolicyChanged`, observed/target
generation/digest IDs, `disruption: None|Reload|Restart|Recycle|Replace`,
`preserveState`, optional `operationId`, `lastAssessedAt`, and
`owned`/`dependencies` refs. It honors base `spec.updatePolicy` (manual
disruptive default; auto non-disruptive), while the Core Operation ledger owns
upgrade operation, idempotency, and progress. A fabric/provider-generation
change returns `UpgradeRequired` with `disruption: Recycle` or
`disruption: Restart` instead of being applied in place; the dependency-aware
planner drains dependent attachments/Guests, recycles the fabric realization,
restarts dependents, and preserves Network identity. Non-disruptive changes
reconcile normally. A change to external `parentInterface`, `macvtapMode`, or
`sharingPolicy` is always disruptive: the planner closes the old VMM/macvtap,
releases the old Host-global authority claim, admits the replacement claim, and
only then restarts dependents.

**Expedited reconcile (D090).** For `Create`, `UpdateSpec`, or `Delete` with
`waitForReconcile`, the controller performs no external effect, finalizer
mutation, or status mutation until Core supplies
`CommittedRevisionProof {resourceUid,generation,revision,operationId}`. `Abort`
means no effect; a durable commit is never rolled back after a later reconcile
timeout. The response contains the committed object, one-pass projected layered
status, `disposition: Converged|Progressing|Blocked|UpgradeRequired|Failed`,
and `statusPersistence: pending|committed`; effect idempotency keys derive from
`(UID,generation,revision,operationId)` in the same per-resource single-flight
using a bounded priority lane.

### 16.2 Reconcile (Network resource)

```text
1. validateSpec
   └─ CIDR, attachment index, IfName collision, netVmSystemArtifactId format
   └─ external parent/mode/sharing policy + Host-global authority preflight
   └─ fail → ReconcileError{reason}; set condition; return failed-retryable

2. Check User/net-local-controller status.phase == Ready
   └─ not Ready → set DependenciesReady=False; return pending

3. [background task] create_fabric + apply_host_sysctls + apply_host_firewall +
                     apply_host_routes + apply_nm_unmanaged
   └─ each dispatched independently; handler does not block between calls
   └─ error → set FabricReady=False or FirewallReady=False; return failed-retryable

4. Create or update Volume/net-<networkName>-config (Phase 1)
   └─ error → ConfigVolumeReady=False; return failed-retryable

5. Write config content to Volume via Volume service (all 4 files)
   └─ no raw IfName or workload hostname in content

6. Create or update Guest/<netVmName>
   └─ systemArtifactId = Network.spec.netVmSystemArtifactId (plain bounded ID)
   └─ spec.provider.settings.vsockCid from Network CIDR allocation
   └─ when externalAttachment non-null: require ExternalNicAuthorityReady=True;
      Core supplies the admitted macvtap attachment privately via LaunchTicket

7. Wait for Guest Ready (via DependenciesReady hint)
   └─ pending → set NetVmReady=False; return pending

8. Update Volume to add Guest attachment (Phase 2)
   └─ wait for attachment Ready
   └─ pending → ConfigVolumeReady=False/attachment-not-ready; return pending

9. Create Process/net-<networkName>-agent (service)
   Create Process/net-<networkName>-dnsmasq (worker)
   Create Process/net-<networkName>-mdns-reflector (worker; if mdns.enable)
   Create Process/net-<networkName>-mdns-dnsbridge (worker; if mdns.dnsmasqLocal)
   └─ each create is independent; handler does not block between creates

10. Call NetworkAgentService.Reload(config_digest) on agent service
    └─ wait for ReloadResult.predicates.{nft_applied, routes_applied}
    └─ update_hosts_file via NetworkEffectPort (no raw IfName/IP in audit)
    └─ seed_dhcp_reservations via NetworkEffectPort

11. Set_attachment_isolation for each workload tap via NetworkEffectPort

12. For each attachment removed from the current spec, wait for its Guest/VMM FD
    ownership to close, then call revoke_attachment_tap with the retained opaque
    handle and current Network/attachment generation fence
    └─ DeletePersistentTap absent success is accepted only after ownership validation
    └─ generation mismatch refreshes status and requeues; marker conflict is terminal

13. Commit ResourceMutationBatch with all child resource mutations + status

14. Evaluate conditions; report phase
    └─ all conditions True → phase: Ready
    └─ any terminal error → phase: Failed
    └─ partial → phase: Degraded
```

### 16.3 Finalizer (delete sequence, strictly child-first)

```text
network.d2bus.org/fabric-cleanup finalizer

1. Set NetworkDraining condition

2. Set desiredLifecycle:stopped on all attached workload Guests (via ResourceMutation)

3. Wait for all attachment phases to become non-Ready (workload Guests stopped)

4. For each retained attachment handle, call revoke_attachment_tap with the
   current expected Network and attachment generations
   └─ core dispatches DeletePersistentTap; no IfName/path crosses the port
   └─ retain handle and retry transient failures before advancing
   └─ stale generation refreshes/requeues; foreign ownership marker blocks cleanup

5. Delete mDNS Process resources (if any); wait for each Deleted watch event
   └─ Deleted event: single atomic store transaction (row+index removed); no
      persistent phase=Deleted row; audit record separate from deletion tx

6. Delete Process/net-<networkName>-agent; wait for Deleted event

7. Delete Process/net-<networkName>-dnsmasq; wait for Deleted event

8. Update Volume attachments to [] (remove Guest attachment); wait for removal

9. Delete Guest/<netVmName>; wait for Deleted event
   └─ confirms the VMM and macvtap FD owner are gone

10. Delete Volume/net-<networkName>-config; wait for Deleted event

11. [background tasks, independent]:
    remove_host_firewall(network_uid, fence)
    remove_host_routes(network_uid)
    update_hosts_file(network_uid, empty)
    delete_fabric(lan_fabric_handle)
    delete_fabric(uplink_fabric_handle)
    apply_nm_unmanaged(empty pattern for this network)
    Each is idempotent; failure is retried before clearing finalizer

12. Release the Host-global external-NIC authority claim, if present
    └─ release is forbidden until Guest/VMM/macvtap ownership is closed
    └─ multiplexed owner transfer is an atomic Core authority-index operation

13. Clear finalizer
```

Each step is driven by `owned-resource-changed` hints rather than polling.
The handler does not block the watch receiver while waiting for child Deleted events.

### 16.4 Adopt (controller restart)

On controller restart (continuation event):
1. List all Network resources in Zone.
2. For each external attachment, ask Core to adopt its exact Host-global
   physical-NIC authority owner proof; ambiguity quarantines and sets
   `ExternalNicAuthorityReady=False`.
3. Read current host bridge state via `NetworkEffectPort.read_firewall_digest()`
   and `read_sysctl_state()`.
4. If the controller's internally-held fabric handles are consistent and digests
   match: mark adopted (no re-application).
5. If bridges absent: normal reconcile creates them.

Adoption never deletes or restarts unambiguous running state and never opens a
second physical NIC attachment.

---

## 17. ProviderStateSet

`ProviderStateSet(zone, "network-local")` is the **query-time grouping** of all
Volume resources in a Zone whose `metadata.ownerRef == "Provider/network-local"`.
It is not a ResourceType or a stored artifact; it is the logical set defined in
`ADR-046-provider-state`:

```text
ProviderStateSet(zone, "network-local") =
  { v : Volume | v.metadata.zone == zone
              && v.metadata.ownerRef == "Provider/network-local" }
```

The set itself is not a compartment type or a framework-managed object - it is a
query.  The Volumes in the set are ordinary Volume resources that happen to carry
`ownerRef: Provider/network-local`.

Under D087, `Provider/network-local` declares **no Provider state Volume**. Its
ProviderStateSet is therefore empty:

```text
ProviderStateSet(zone, "network-local") = {}
```

The controller's network operational state fails the storage-need test for a
durable Provider state Volume: bridge, route, nftables, DHCP, attachment, and
adoption observations are bounded, non-secret, and derivable from `Network.spec`,
`Network.status`, the core Operation ledger, broker operation results, and
external kernel/network observation after restart.

The controller Process therefore mounts no Provider state Volume, declares no
state namespace, has no dedicated state-layout `User/<name>` principal, and has
no identity marker, migration worker, Provider state reset path, or Provider
state destroy path. There is no bootstrap state-Volume mechanism; the previous
bootstrap exception (D086, superseded by D087) does not apply.

The per-Network config Volumes (§9) are preserved. They carry actual runtime
configuration content (`dnsmasq.conf`, `nftables.rules`, `routing.conf`,
`attachments.json`) on tmpfs with `ownerRef: Network/<networkName>`, so they are
runtime/config operational Volumes, not Provider state Volumes and not members of
the ProviderStateSet. Runtime network artifacts such as bridges, routes,
nftables rules, and mDNS/agent Processes are likewise unaffected and remain
broker/controller-managed operational state, not Provider state Volumes.

Status is observation only. It is revisioned, optimistic-status-writer
controlled, RBAC-readable, redacted, bounded to the global/provider-detail
limits, written only on material change, and re-verified against external
kernel/network reality after restart. It never contains secrets, authority
handles, private paths, argv/env, PIDs, unit names, raw command output, large
blobs, or unbounded collections; oversize status is rejected with
`status-oversize`.

The network-local controller does not add Volume to its exported `ResourceTypes
implemented`. `Provider/volume-local` remains the reconciler for per-Network
config Volume resources (§9); the controller creates those resource objects and
writes their bounded config content through the Volume service, but it does not
reconcile Volumes and does not create a Provider state Volume prerequisite.

---

## 18. RBAC

### 18.1 Roles

```yaml
# Operator roles
type: Role
metadata: { name: network-operator, zone: dev }
spec:
  rules:
    - resourceTypes: [Network]
      verbs: [get, list, watch, create, update-spec, delete]
      zones: [dev]
    - resourceTypes: [Zone]
      verbs: [get]
      zones: [dev]
---
type: Role
metadata: { name: network-reader, zone: dev }
spec:
  rules:
    - resourceTypes: [Network]
      verbs: [get, list, watch]
      zones: [dev]
---
# Controller role (bound to Provider/network-local)
type: Role
metadata: { name: network-local-controller, zone: dev }
spec:
  rules:
    - resourceTypes: [Network]
      verbs: [get, list, watch, update-status, update-finalizers]
      zones: [dev]
    - resourceTypes: [Guest]
      verbs: [get, list, watch, create, update-spec, delete]
      zones: [dev]
      # Scoped: only Guests with ownerRef resolving to a Network resource
    - resourceTypes: [Volume]
      verbs: [get, list, watch, create, update-spec, delete]
      zones: [dev]
      # Scoped: only Volumes with ownerRef resolving to a Network resource
    - resourceTypes: [Process]
      verbs: [get, list, watch, create, update-spec, delete]
      zones: [dev]
      # Scoped: only Processes with ownerRef resolving to a Network resource
    - resourceTypes: [User]
      verbs: [get, watch]               # read User/net-local-controller status
      zones: [dev]
    - resourceTypes: [Host]
      verbs: [get]
      zones: [dev]
    - resourceTypes: [Zone]
      verbs: [get]
      zones: [dev]
---
type: RoleBinding
metadata: { name: network-local-ctrl-binding, zone: dev }
spec:
  roleRef: Role/network-local-controller
  subjects:
    - Provider/network-local
  externalPrincipalSelector: null
  scopeNarrowing: null
```

The controller holds **no** broker role and **no** `network-admin` capability.
All host-kernel effects go through the injected `NetworkEffectPort`.

### 18.2 Resource/verb matrix

| Verb | Resource | Held by | Notes |
| --- | --- | --- | --- |
| `create` | `User/net-local-controller` | **Nix config publication** | NOT the network-local controller; declared in Nix |
| `update-status` | `User/net-local-controller` | `Provider/system-core` only | system-core reconciles via NSS |
| `get,watch` | `User/net-local-controller` | `Provider/network-local` | read-only precondition |
| `update-status` | `Network` | `Provider/network-local` | sole status owner |
| `create,update-spec` | `Guest` | `Provider/network-local` | scoped to ownerRef=Network |
| `create,update-spec` | `Volume` | `Provider/network-local` | creates per-Network config Volume resource objects only; volume-local reconciles; network-local does NOT implement Volume ResourceType |
| `update-spec` | `Volume` | `Provider/network-local` | declared config content changes use the canonical Volume spec/update path; there is no `write-content` verb |
| `create,update-spec` | `Process` | `Provider/network-local` | agent + dnsmasq + mDNS processes |

---

## 19. d2b-bus

The network-local controller authenticates to d2b-bus with a local Noise-NN
profile (no pre-shared key; Host/Zone scope).

### 19.1 Watch registrations

| ResourceType | Watch selector | Purpose |
| --- | --- | --- |
| `Network` | all in Zone | owns reconcile |
| `Guest` | `ownerRef: Network/*` | observe net-VM lifecycle |
| `Volume` | `ownerRef: Network/*` | observe config Volume lifecycle |
| `Process` | `ownerRef: Network/*` | observe agent/dnsmasq/mDNS lifecycle |
| `User` | `name: net-local-controller` | precondition check |
| `Host` | all in Zone | host network inventory for hostBlocklist |

No `Network` or `Host` resource is watch-subscribed by the agent or dnsmasq
processes.  Workers have no bus authority.  The agent service endpoint is the sole
bus-adjacent surface for guest-side interactions.

### 19.2 Service endpoint (agent)

The net-agent service process exposes `d2b.network.v3.agent/v1` through
`Endpoint/net-work-net-agent-service`, a Noise-KK vsock Endpoint resource. Only
the network-local controller is authorized to resolve and call this service
(bound via the Zone's internal ComponentSession RBAC).

---

## 20. Status, errors, and conditions

### 20.1 Error codes (stable; no raw kernel output)

| Code | Phase | Description |
| --- | --- | --- |
| `network-cidr-conflict` | Failed | CIDR overlap detected |
| `ifname-collision` | Failed | Derived IfName collision; terminal |
| `bridge-create-error` | Degraded | create_fabric failed |
| `bridge-delete-error` | Degraded | delete_fabric failed or an owned persistent tap remains; retry after tap cleanup |
| `sysctl-error` | Degraded | apply_host_sysctls failed |
| `nftables-error` | Degraded | apply_host_firewall failed |
| `nftables-drift` | Degraded | Firewall digest mismatch detected at observe |
| `nm-unmanaged-error` | Degraded | apply_nm_unmanaged failed |
| `route-error` | Degraded | apply_host_routes failed |
| `attachment-delete-failed` | Degraded | `DeletePersistentTap` failed transiently; retry with the same fence |
| `attachment-generation-mismatch` | Degraded | stale Network/attachment generation fence; refresh realization and requeue without deleting |
| `attachment-ownership-conflict` | Failed | persistent tap ownership marker does not match; fail closed without deleting |
| `config-volume-error` | Degraded | Volume create failed |
| `volume-backing-error` | Degraded | Volume backing not Ready |
| `attachment-not-ready` | Degraded | Volume Guest attachment not Ready |
| `net-vm-pending` | Pending | Guest not yet Ready |
| `net-vm-failed` | Failed | Guest in Failed phase |
| `net-vm-degraded` | Degraded | Guest in Degraded phase |
| `agent-restart` | Degraded | Agent process restarted unexpectedly |
| `agent-reload-failed` | Degraded | NetworkAgentService.Reload() returned error |
| `dnsmasq-not-bound` | Degraded | dnsmasq process not Ready; DNS/DHCP unavailable |
| `nft-not-applied` | Degraded | Agent reports nft_applied=false |
| `macvtap-not-ready` | Degraded | External attachment macvtap not ready |
| `external-attachment-mode-invalid` | Failed | External attachment type is not macvtap |
| `external-parent-interface-invalid` | Failed | Declared parentInterface fails IfName syntax |
| `external-parent-interface-not-found` | Failed | Trusted Host inventory cannot resolve parentInterface |
| `external-sharing-policy-invalid` | Failed | Multiplexing requested for a non-bridge mode or policy is incomplete |
| `external-physical-nic-conflict` | Failed | Same Host physical NIC has an incompatible same- or cross-Zone authority claim |
| `external-physical-nic-cross-zone-l2` | Failed | A `bridge`-mode macvtap multiplex of one physical NIC spans two Zones, which would share an L2 broadcast domain (INV-NET-011) |
| `external-nic-owner-ambiguous` | Degraded | Restart could not prove the prior physical-NIC authority owner |
| `mdns-process-not-ready` | Degraded | mDNS reflector or bridge not Ready |
| `net-vm-artifact-missing` | Failed | netVmSystemArtifactId absent from artifact catalog |
| `net-vm-artifact-type-mismatch` | Failed | Artifact type is not nixos-system |
| `user-not-ready` | Pending | User/net-local-controller not Ready |

Error messages are bounded and contain no raw kernel output, ifNames, IPs, MACs,
cgroup paths, or internal resource paths.

### 20.2 Latency guidelines

| Operation | P50 target | P99 target |
| --- | --- | --- |
| Bridge creation (create_fabric) | < 200 ms | < 500 ms |
| Host nftables apply | < 100 ms | < 300 ms |
| Config Volume write (4 files) | < 50 ms | < 150 ms |
| Agent Reload() round-trip | < 500 ms | < 2 s |
| dnsmasq restart | < 1 s | < 3 s |
| Full Network provisioning | < 10 s | < 30 s |
| Full Network deletion | < 15 s | < 45 s |

---

## 21. Audit, OTEL, and redaction

### 21.1 Audit records

One audit record per Resource API mutation; additional records per `NetworkEffectPort`
call (emitted by the core adapter, not the provider crate).

Network-specific audit payload:

| Field | Included | Rationale |
| --- | --- | --- |
| ResourceType and resource name | Yes | operational identity |
| verb / subresource | Yes | standard |
| `network.lanCidr` | Yes | address allocation decision |
| `network.uplinkCidr` | Yes | address allocation decision |
| `network.isolation.allowEastWest` | Yes | security-relevant policy change |
| `network.attachments[].executionRef` | Yes | Guest identity is operational |
| `firewallDigest` | Yes | drift evidence (opaque hex; no rule text) |
| Bridge/tap drift reason | Yes (stable code; no raw IfName) | diagnostic |
| `network.attachments[].attachmentHandle` | Yes (opaque; no IfName) | fabric identity |
| `DeletePersistentTap` expected generations and opaque attachment digest | Yes | deletion fence and effect correlation; no handle bytes |
| Workload hostname, IP, MAC | **No** | redacted from API-level audit |
| nftables rule text | **No** | redacted |
| DHCP lease data | **No** | never written to audit |
| dnsmasq config contents | **No** | not audit material |
| Raw IfNames | **No** | internal to core adapter |
| raw kernel interface names | **No** | redacted |
| `externalAttachment.portForwards[].targetIp` | **No** | workload-internal |
| Error message body | **No** (error code only) | no kernel output |

Broker operations emit their own audit records (path-free outcome codes) from within
the core adapter. `DeletePersistentTap` audit uses the exact op name and carries
only the opaque attachment digest, expected Network/attachment generations,
outcome, error class, and correlation ID; it never carries an IfName, path, or
ownership-marker body.

### 21.2 OTEL spans and metrics

Root span per reconcile attempt:

```
d2b.network.reconcile
  network.generation: <n>
  reconcile.trigger: <reason-set>
  reconcile.attempt: <n>
  outcome: converged|pending|degraded|failed-retryable|failed-terminal
```

Child spans (no raw IfName, IP, MAC, rule text, or lease data in any attribute):

```
d2b.network.effect.create_fabric
d2b.network.effect.delete_fabric
d2b.network.effect.delete_persistent_tap
d2b.network.effect.apply_firewall
d2b.network.effect.apply_routes
d2b.network.effect.apply_sysctls
d2b.network.effect.update_hosts
d2b.network.effect.seed_dhcp
d2b.network.volume.sync
d2b.network.guest.sync
d2b.network.agent.reload
d2b.network.dnsmasq.restart
d2b.network.observe.drift_check
```

Metric labels use closed semantic cardinality and carry no Zone or Network
identity. Zone identity remains in the `d2b.zone` OTEL resource attribute.
Network identity is likewise available only as a bounded OTEL resource
attribute and permitted audit field, never as a span attribute or metric label.

Metrics:

| Metric | Labels |
| --- | --- |
| `d2b_network_reconcile_total` | `outcome` |
| `d2b_network_phase` | `phase` |
| `d2b_network_attachment_count` | (none) |
| `d2b_nftables_apply_total` | `outcome` |
| `d2b_nftables_drift_total` | (none) |
| `d2b_bridge_create_total` | `outcome` |
| `d2b_bridge_delete_total` | `outcome` |
| `d2b_network_volume_sync_total` | `outcome` |
| `d2b_network_agent_reload_total` | `outcome` |
| `d2b_network_agent_restart_total` | `outcome` |
| `d2b_network_dnsmasq_restart_total` | `outcome` |
| `d2b_network_observe_drift_total` | `surface` |

---

## 22. Nix configuration

### 22.1 Artifact catalog entries

```nix
# In flake.nix / nixos-modules/bundle-artifacts.nix
d2b.artifacts.provider-network-local = {
  package = packages.${system}.d2b-provider-network-local;
  type    = "provider";
};

d2b.artifacts.net-vm-base = {
  package = pkgs.d2b-net-vm-nixos-system;
  type    = "nixos-system";
};
```

Artifact IDs match `^[a-z][a-z0-9-]*$`.  They are plain bounded IDs, not paths.
The resource spec/status/audit surface never exposes Nix store paths; only the
private artifact catalog retains the derivation reference.

### 22.2 Provider and User declaration

```nix
# In d2b.zones.dev.providers (or d2b.zones.dev.resources)
d2b.zones.dev.resources = {
  network-local = {
    type = "Provider";
    spec = {
      artifactId = "provider-network-local";
      config = {
        controllerExecutionRef = "Host/host-system";
      };
    };
  };

  # User resource declared here - NOT created dynamically by the controller
  net-local-controller = {
    type = "User";
    metadata.ownerRef = "Provider/network-local";
    spec = {
      osUsername = "net-local-controller";
      # displayName and groups are optional
    };
  };
};
```

The Nix module also provisions the OS account in the host NixOS system:
```nix
# nixos-modules/host-users.nix additions for network-local
users.users.net-local-controller = {
  uid         = <RESERVED_UID>;          # fixed private UID; never in ResourceSpec
  isSystemUser = true;
  group       = "net-local-controller";
  home        = "/var/empty";
  shell       = pkgs.shadow + "/bin/nologin";
};
users.groups.net-local-controller.gid = <RESERVED_GID>;
```

The same account (identical UID/GID) is baked into the generic `net-vm-base`
nixos-system artifact so virtiofs ACLs on config Volume layout entries are
consistent inside the net VM.

### 22.3 Network resource declaration

```nix
d2b.zones.dev.resources.work-net = {
  type = "Network";
  spec = {
    networkName         = "work-net";
    netVmSystemArtifactId = "net-vm-base";   # plain bounded ID
    lanCidr             = "10.20.0.0/24";
    uplinkCidr          = "192.0.2.0/30";
    attachments         = [
      { executionRef = "Guest/corp-vm";    index = 10; }
      { executionRef = "Guest/personal-vm"; index = 11; }
    ];
    isolation.allowEastWest = false;
    dns.forwarders      = [ "8.8.8.8" "8.8.4.4" ];
  };
};
```

### 22.4 Nix static prerequisites

Nix provisions the following **static** prerequisites (no runtime IfName
knowledge required):

| Artifact | Purpose |
| --- | --- |
| `networking.networkmanager.unmanaged` block for `d2b-*` prefix | Covers all dynamically-created d2b bridges/taps regardless of IfName |
| `net-local-controller` OS account (fixed UID/GID) | virtiofs ACL consistency on both Host and Guest |
| Schema validation artifacts | Checked at build time (`nix flake check`) |
| Controller binary deployment | Package in the host system closure |
| `net-vm-base` nixos-system derivation | Generic net-VM OS; no per-Network config encoded |

No per-Network or per-IfName Nix entries are required; all dynamic fabric state is
provisioned at runtime through `NetworkEffectPort`.

### 22.5 eval-time checks

| Check | What is verified |
| --- | --- |
| `netVmSystemArtifactId` present | Required field; fails if absent |
| `netVmSystemArtifactId` type is `nixos-system` | Artifact catalog type check |
| `lanCidr` / `uplinkCidr` format | Regex + prefix length at Nix eval time |
| CIDR overlaps between declared Networks | Cross-Network CIDR overlap check (where input is available at eval time) |
| `networkName` regex | `^[a-z][a-z0-9-]*$` |

Runtime checks in `validateSpec` cover the full set.

---

## 23. Security invariants

### INV-NET-001: lib.mkForce on 10-eth-dhcp

**Invariant**: the net VM's NixOS config MUST contain a `lib.mkForce` override
replacing the `10-eth-dhcp` catch-all networkd definition with a non-matching
bogus MAC (`00:00:00:00:00:00`).

**Rationale**: prevents the catch-all from being selected for any real NIC,
which would start DHCP on all interfaces.

**Validation**: `tests/net-vm-network-eval.sh` (Layer-1 eval gate).

### INV-NET-002: IPv6 suppression

**Invariant**: all host-side bridge interfaces created by the network-local
controller MUST have `net.ipv6.conf.<ifname>.disable_ipv6 = 1`,
`accept_ra = 0`, and `autoconf = 0` before the bridge becomes active.
Suppression is applied both atomically at `create_fabric` time and defensively
at each reconcile via `apply_host_sysctls`.

**Rationale**: d2b is IPv4-only; suppression prevents kernel autoconf and
inadvertent IPv6 router solicitation on tenant bridges.

### INV-NET-003: LAN bridge host isolation

**Invariant**: the host has no IP address on any LAN bridge; LAN bridge is not
a routable host interface.

**Rationale**: prevents the host from becoming a router to the tenant LAN.

### INV-NET-004: workload tap isolation (default)

**Invariant**: workload taps are created with `Isolated=true` on the LAN bridge
by default.  Only the net-VM tap is non-isolated.  East-west traffic between
workloads passes through the net VM and is subject to the `inet filter forward`
chain.

**Rationale**: workloads cannot communicate directly at L2 without traversing
the net-VM firewall.

### INV-NET-005: east-west default deny

**Invariant**: when `isolation.allowEastWest = false`, the net VM's forward
chain contains no `eth1→eth1 new accept` rule and workload taps carry
`Isolated=true`.

### INV-NET-006: CIDR non-overlap

**Invariant**: no two Networks in a Zone may have overlapping `lanCidr`,
`uplinkCidr`, or `externalAttachment.egress.allowedCidrs` entries.  Validated
at `validateSpec` time and re-checked at each reconcile cycle.

### INV-NET-007: hostBlocklist effectiveness

**Invariant**: the effective `hostBlocklist` in the net VM always includes the
default RFC1918+link-local set plus all other active Network CIDRs in the Zone
plus the Host resource's observed network inventory.  The hostBlocklist cannot
be entirely emptied; it is only additive.

**Rationale**: prevents workloads from routing to host LAN ranges or to other
tenant networks.

### INV-NET-008: Guest-network-admin isolation

**Invariant**: `CAP_NET_ADMIN`, `CAP_NET_RAW`, and `CAP_NET_BIND_SERVICE`
granted to the net-agent and dnsmasq Processes are effective only within the
inherited Guest VM network namespace (the `namespaceClasses: []` Process spec
field causes the Process Provider to inherit the Guest's netns).  No host
capability is conferred.

**Rationale**: the net VM's privileged processes cannot affect the host network
stack.

**Validation**: `tests/unit/nix/cases/process-sandbox-netns.nix` (Layer-1 eval
case).

### INV-NET-009: no raw IfName/IP/MAC on public surface

**Invariant**: except for the operator-declared
`Network.spec.externalAttachment.parentInterface` Host inventory selector, no
raw kernel interface name, host bridge name, tap interface name, workload IP
address, DHCP MAC address, or host uplink IP address appears in any of:
- `Network.status` fields;
- `Guest.spec.provider.settings`;
- OTEL span attributes;
- metric label values;
- audit record payload fields.

The declared selector may appear in spec-mutation audit but is never reused as
the authority key. Runtime IfNames, the Core-derived opaque NIC digest, and
owner proof are internal to Core adapters and never exposed through the
Provider crate's API boundary.

**Rationale**: prevents information-disclosure about the host kernel interface
topology through the resource API surface.

### INV-NET-010: no network-local USBIP firewall ownership

**Invariant**: network-local host and net-VM firewall intents contain no USBIP
rule and no TCP/3240 match. Its firewall digest and `FirewallReady` condition
cover only rules bearing that Network UID's ownership. Device-usbip rules are
created, observed, reported, and removed only through `UsbipEffectPort` and the
shared closed `ApplyNftablesProjection` broker operation.

**Rationale**: one semantic owner prevents a generic uplink opening from
outliving a USB claim or bypassing per-Network/per-busid authorization.

### INV-NET-011: Host-global external physical-NIC authority

**Invariant**: Core admits `(Host, external-physical-nic,
opaqueKeyDigest)` before any macvtap/VMM effect and binds an isolation domain
equal to the claimant's Zone UID. `passthru`, `private`, and `vepa` are
exclusive; `bridge` is exclusive unless all holders explicitly request
compatible multiplexing AND share one isolation domain (one Zone). The rule
spans Zones on a Host: a `bridge` multiplex whose holders span two Zones is
categorically rejected fail closed with `external-physical-nic-cross-zone-l2`,
independent of `sharingPolicy`. Update/delete closes the VMM/macvtap before
releasing the claim; restart requires exact owner proof.

**Rationale**: a Zone-local interface-name check cannot prevent two Zones from
opening the same physical NIC or silently weakening exclusive modes. macvtap
endpoints on one NIC in `bridge` mode share a single L2 broadcast domain, so
admitting a cross-Zone multiplex would place two Zones on one L2 segment; the
binding invariant that work and personal Zones never share an L2 bridge makes
that combination categorically inadmissible at authority admission time.

---

## 24. Provider lifecycle (install / upgrade / remove)

### 24.1 Install

1. Nix activation deploys `d2b-provider-network-local-ctrl` binary to the host
   system closure.
2. Nix activation provisions `net-local-controller` OS account and group.
3. Nix config publication creates `User/net-local-controller` resource and
   `Provider/network-local` resource.
4. Framework creates controller Process resource (`Process/network-local-ctrl`);
   system-minijail starts the controller.
5. Controller registers `Network` watch plan on d2b-bus.
6. Controller reconciles any already-declared Network resources.

### 24.2 Upgrade

On controller binary upgrade:
- `adopt-on-restart` policy on the controller Process causes system-minijail to
  adopt the new controller process transparently.
- Net-VM Guest processes are NOT restarted unless the `net-vm-base` artifact
  generation changes.
- Per-Network config Volumes are updated if the new controller detects spec drift.
- The `NetworkEffectPort` contract version is checked; mismatched versions fail
  the controller launch.

### 24.3 Remove

1. Operator deletes all Network resources; waits for each to complete its
   finalizer sequence (§16.3).
2. Operator deletes `Provider/network-local` resource.
3. Framework deletes controller Process resource; system-minijail stops controller.
4. Framework removes `User/net-local-controller` resource (blocked if any
   per-Network config Volume layout still references `User/net-local-controller` -
   must clear Networks first).
5. Nix activation removes the account (separate operator step, outside the
   resource lifecycle).

---

## 25. Migration from v1 baseline

### 25.1 Reused modules

| Module | Location | Reuse scope |
| --- | --- | --- |
| IfName derivation | `packages/d2b-host/src/ifname.rs:derive_ifname` | Full reuse; algorithm unchanged |
| nftables apply/hash | `packages/d2b-host/src/nftables.rs` | Full reuse; wrapped by core adapter |
| Bridge-port flags | `packages/d2b-host/src/bridge_port.rs` | Full reuse; wrapped by core adapter |
| Route preflight | `packages/d2b-host/src/routes.rs` | Full reuse; wrapped by core adapter |
| sysctl apply | `packages/d2b-host/src/netlink.rs` | Full reuse; wrapped by core adapter |
| CIDR validation | `nixos-modules/lib.nix:cidrOverlaps` (lines 429-462) | Ported to `validate.rs` |
| dnsmasq invariants | `nixos-modules/net.nix` lines 302-441 | Encoded in `dnsmasq.conf` rendering |
| nftables rules | `nixos-modules/net.nix` lines 168-296 | Encoded in `nftables.rules` rendering |
| lib.mkForce override | `nixos-modules/base.nix`:`10-eth-dhcp` | Preserved in net-vm-base artifact |

### 25.2 Breaking changes from v1 baseline

| Change | v1 behavior | v3 behavior |
| --- | --- | --- |
| IfName exposure | `br-<env>-lan` / `br-<env>-up` in NixOS module | IfNames are internal; never in resource API |
| Bridge creation | Declared in NixOS activation (static, per-env) | Dynamic broker effects via NetworkEffectPort |
| dnsmasq management | systemd unit declared in Nix per env | Separate worker Process resource per Network |
| mDNS | avahi static Nix config | Separate worker Process resources per Network |
| DHCP config | Static Nix config per env | Config Volume written by controller at runtime |
| Firewall | Static Nix config per env | Dynamic NetworkEffectPort.apply_host_firewall |
| Net-VM artifact ID | implicit path in microvm.nix | Explicit `netVmSystemArtifactId` field |

### 25.3 Migration work items

| ID | Category | Description |
| --- | --- | --- |

### ADR046-nl-001
| Field | Value |
| --- | --- |
| Dependency/owner | Core; owns `NetworkEffectPort` contract/versioning in `d2b-contracts` and adapter implementation in `d2b-core`. |
| Current source | None - net-new v3 work; no pre-ADR45 baseline equivalent for a provider-neutral `NetworkEffectPort` core adapter. |
| Reuse action | create |
| Destination | `d2b-contracts` trait plus `d2b-core` core adapter; maps to broker wire operations and audit emission. |
| Detailed design | Implement `NetworkEffectPort` core adapter in `d2b-core`; map to broker wire ops; emit audit records. `revoke_attachment_tap` accepts only an opaque `AttachmentHandle` plus `AttachmentGenerationFence { expected_network_generation, expected_attachment_generation }` and maps to `DeletePersistentTap`; no IfName/path or caller-authored marker crosses the trait. Versioning: minor releases may add methods with default impls; major releases require Provider upgrade. The trait lives in `d2b-contracts`; the adapter in `d2b-core`. |
| Integration | `Provider/network-local` reconcile calls injected `NetworkEffectPort`; the core adapter resolves opaque Network intents to closed broker wire ops and emits broker-level audit records. |
| Data migration | Full d2b 3.0 reset; no v2 state/config import. |
| Validation | `packages/d2b-provider-network-local/tests/fault_injection.rs` verifies fake `NetworkEffectPort` behavior, error mapping, no broker socket in provider context, and audit-safe adapter boundaries. |
| Removal proof | None - net-new; no prior owner to remove. |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-nl-002
| Field | Value |
| --- | --- |
| Dependency/owner | `ADR046-transport-unix-006`; Core; broker/core contract work consumed by ADR046-nl-001. The transport item is the dependency-ordered prior writer of the shared broker wire, privilege, audit, runtime, and dispatch surfaces; this item is their later Network-operation writer. |
| Current source | Existing broker wire has related ApplyNftables, ApplyRoute, ApplySysctl, ApplyNmUnmanaged, UpdateHostsFile, SeedDnsmasqLease, and `CreatePersistentTap` operations, but no paired `DeletePersistentTap`, `CreateBridge`, `DeleteBridge`, `ReadNftablesDigest`, `ReadSysctlState`, `ReadBridgePortFlags`, or `ApplyNftablesProjection` v3 ops. The shipped `ApplyNftables` op discards `ownership_id` and does a whole-table `delete table ...; table ...` replace (`packages/d2b-priv-broker/src/ops/nft.rs`), so it cannot express per-Network projection mutation; `ApplyNftablesProjection` is authored to replace that mapping for `apply_host_firewall`/`remove_host_firewall` (D-NETWORK-004 in `ADR-046-resources-network.md`). |
| Reuse action | adapt |
| Destination | Broker wire contract and broker/core adapter operation table for `DeletePersistentTap`, `CreateBridge`, `DeleteBridge`, `ReadNftablesDigest`, `ReadSysctlState`, `ReadBridgePortFlags`, and `ApplyNftablesProjection`. |
| Detailed design | Add canonical closed `DeletePersistentTap` paired with `CreatePersistentTap`, plus `CreateBridge`, `DeleteBridge`, `ReadNftablesDigest`, `ReadSysctlState`, `ReadBridgePortFlags`, and `ApplyNftablesProjection`. `DeletePersistentTapRequest` contains only an opaque attachment ID and expected Network/attachment generations. `ApplyNftablesProjectionRequest` contains only an opaque `bundle_nft_projection_ref`, a closed `NftProjectionAction { Apply, Remove }`, an `expected_generation_id` fence, and an optional `tracing_span_id`; the broker resolves the projection (ownership marker + rule set) from the private bundle, mutates only that marker's rules inside `inet d2b`, byte-preserves every other Network and device-usbip marker, never whole-table replaces, treats validated absence as success, rejects foreign markers without deletion, and emits a path-free post-effect audit with a projection-scoped digest. The broker resolves trusted realization state, validates generations and ownership marker, treats validated absence as success, rejects foreign markers without deletion, and emits path-free post-effect audit. No request accepts an IfName, path, inline rule text, or caller-authored marker. Primary reuse disposition: `adapt`. Preserved source-plan detail: extend broker wire with net-new operations and reuse existing closed broker-operation dispatch shape. |
| Integration | `NetworkEffectPort` core adapter invokes these broker ops for attachment/fabric/firewall lifecycle and observe/drift checks; `Provider/network-local` receives only typed results and opaque digests/handles. Attachment removal and Network finalization retain the handle until `DeletePersistentTap` confirms deletion or validated absence; firewall apply/remove retains the projection reference until `ApplyNftablesProjection` confirms the effect or validated absence. |
| Data migration | Full d2b 3.0 reset; no v2 state/config import. |
| Validation | Broker tests cover `DeletePersistentTap` success, validated already-absent idempotency, stale Network/attachment generations, foreign-marker fail-closed behavior, path-free audit, and rejection of any IfName/path field; `ApplyNftablesProjection` tests cover apply/remove of exactly one ownership marker, sibling-Network and device-usbip marker preservation, never-whole-table-replace, generation-fence rejection of stale same-projection mutation, validated-absence idempotency, foreign-marker fail-closed, projection-scoped digest, and path-free audit with no rule text/IfName/path; `integration/host_fabric.rs` covers persistent-tap deletion, bridge create/delete, nftables projection apply/remove/digest, IPv6 suppression, NetworkManager unmanaged handling, and real `NetworkEffectPort` implementation. |
| Removal proof | None - net-new broker ops; remove only if no Provider consumes them per the removal checklist. |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-nl-003
| Field | Value |
| --- | --- |
| Dependency/owner | Core; handle DTOs are owned by `d2b-contracts` and consumed by `d2b-core` plus `Provider/network-local`. |
| Current source | None - net-new v3 work; no public pre-ADR45 baseline equivalent for opaque `AttachmentHandle` or `FabricHandle`. |
| Reuse action | create |
| Destination | `d2b-contracts` opaque byte-array newtypes; core-held HMAC key and provider-facing redacted handle types. |
| Detailed design | Implement `AttachmentHandle` and `FabricHandle` as opaque byte-array newtypes (32 bytes of HMAC-SHA-256 over internal identity material; key held by core). Each attachment handle identifies one generation-fenced realization and is retained until explicit `DeletePersistentTap` confirmation during attachment removal or Network finalization. These types are declared in `d2b-contracts`, not in the provider crate. |
| Integration | Core creates handles from Network and attachment identity, stores them only in internal state/status-resource attachment realization, and supplies resolved tap FDs through LaunchTicket without exposing IfNames or MACs. |
| Data migration | Full d2b 3.0 reset; no v2 state/config import. |
| Validation | `tests/fault_injection.rs` and `tests/controller_state.rs` cover opaque-handle mismatch, generation-fenced `DeletePersistentTap`, retained handle until confirmation, and no raw IfName/IP/MAC/path public surface. |
| Removal proof | None - net-new; no prior owner to remove. |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-nl-004
| Field | Value |
| --- | --- |
| Dependency/owner | Core; depends on ADR046-nl-003 handles and runtime-cloud-hypervisor LaunchTicket consumption. |
| Current source | Existing v1 runtime tap handling is broker/runtime-specific; no v3 LaunchTicket owner-graph FD resolution surface exists. |
| Reuse action | create |
| Destination | Core LaunchTicket builder and dependency resolver that walks `Guest.ownerRef: Network/<name>` to resolved tap FDs. |
| Detailed design | Implement LaunchTicket FD resolution: when core builds the LaunchTicket for a Guest with `ownerRef: Network/<name>`, it walks the owner graph, locates the Network, reads its internally-held `AttachmentHandle` set, and includes the corresponding tap FDs in the ticket. No API surface for the provider or runtime is required beyond the existing LaunchTicket mechanism. Primary reuse disposition: `create`. Preserved source-plan detail: net-new LaunchTicket integration; reuse existing LaunchTicket mechanism without adding provider/runtime API surface. |
| Integration | Runtime-cloud-hypervisor starts Guests using tap FDs supplied in LaunchTickets; `Provider/network-local` declares attachments and core resolves handles privately. |
| Data migration | Full d2b 3.0 reset; no v2 state/config import. |
| Validation | `integration/guest_lifecycle.rs` validates net-VM/workload Guest lifecycle, opaque attachment handle resolution, and `systemArtifactId` binding. |
| Removal proof | None - net-new; no prior owner to remove. |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-nl-005
| Field | Value |
| --- | --- |
| Dependency/owner | Provider plus Core; provider validates through `d2b_host::ifname::derive_ifname`, while core adapter consumes host networking modules. |
| Current source | Reuse modules listed in §25.1: `packages/d2b-host/src/ifname.rs:derive_ifname`, `packages/d2b-host/src/nftables.rs`, `packages/d2b-host/src/bridge_port.rs`, `packages/d2b-host/src/routes.rs`, and `packages/d2b-host/src/netlink.rs`. |
| Reuse source | `d2b-host` IfName, nftables, bridge-port, route preflight, and sysctl/netlink modules. |
| Reuse action | adapt |
| Destination | Core adapter imports `d2b-host` modules; `packages/d2b-provider-network-local/src/ifname.rs` re-exports `d2b_host::ifname::derive_ifname` only. |
| Detailed design | The `d2b-host` IfName/nftables/bridge/route modules are consumed directly by the core adapter (not by the provider crate). The provider crate re-exports only `d2b_host::ifname::derive_ifname` for validation purposes. No additional extraction work is required beyond confirming the `d2b-host` API surface is stable. Primary reuse disposition: `adapt`. Preserved source-plan detail: reuse directly in core adapter; provider re-exports only `derive_ifname` for validation. |
| Integration | Provider validateSpec uses deterministic IfName derivation for collision checks; core adapter applies bridge, nftables, route, and sysctl effects through reused `d2b-host` helpers. |
| Data migration | Full d2b 3.0 reset; no v2 state/config import. |
| Validation | `tests/ifname_derive.rs`, `tests/fault_injection.rs`, and `integration/host_fabric.rs` prove derivation, adapter reuse, and real host-fabric behavior. |
| Removal proof | None - reused modules remain owned by `d2b-host`; no prior provider-local copy to remove. |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-nl-006
| Field | Value |
| --- | --- |
| Dependency/owner | Provider; depends on ADR046-nl-001 through ADR046-nl-005 and owns the Network reconcile/observe/finalize handlers. |
| Current source | None - net-new v3 provider controller; v1 behavior lived in `nixos-modules/network.nix` and `nixos-modules/net.nix` static NixOS module logic. |
| Reuse action | adapt |
| Destination | `packages/d2b-provider-network-local/src/{controller.rs,metrics.rs}`. |
| Detailed design | Implement `controller.rs` reconcile/observe/finalize handlers with `NetworkEffectPort` injection and the §21 metric descriptors with closed semantic labels. Attachment removal and finalization wait for Guest/VMM FD ownership to close, then call `revoke_attachment_tap` with the retained opaque handle and current Network/attachment generation fence; transient deletion retries retain the handle, stale generations refresh/requeue, and ownership conflict blocks finalizer clearing. No descriptor may carry `vm`, `zone`, `zone_id`, `zone_uid`, `network`, or another resource-name-derived key; Network/Zone identity stays only in OTEL resource attributes and permitted audit fields. Primary reuse disposition: `adapt`. Preserved source-plan detail: port semantics into provider reconcile state machine; do not reuse static per-env systemd/Nix ownership. |
| Integration | Controller watches Network, Guest, Volume, Process, User, Host, and Zone resources; creates child resources, writes status, invokes `NetworkEffectPort`, and drives finalizers. |
| Data migration | Full d2b 3.0 reset; no v2 state/config import. |
| Validation | `tests/controller_state.rs` covers normal reconcile, errors, finalizer ordering, adoption on restart, and observe/drift cycles with deterministic clock; `tests/metrics_labels.rs` structurally asserts exact identity-key absence and that a Network-name canary never enters metric label values. |
| Removal proof | Supersedes static per-env lifecycle in `nixos-modules/network.nix` and `nixos-modules/net.nix`; removal proof is successor controller coverage plus deletion of duplicate old gates when this provider lands. |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-nl-007
| Field | Value |
| --- | --- |
| Dependency/owner | Provider; owns net-agent ComponentSession service and depends on ComponentSession/bus and net-VM Process lifecycle. |
| Current source | None - net-new v3 NetworkAgentService; v1 net-VM behavior was encoded in NixOS services and scripts under `nixos-modules/net.nix`. |
| Reuse action | create |
| Destination | `packages/d2b-provider-network-local/src/process_specs.rs` agent template plus agent service implementation in the net-VM artifact. |
| Detailed design | Implement `NetworkAgentService` Noise-KK vsock ComponentSession (Reload + ReadinessQuery methods). Agent reconnect policy: if the controller cannot reach the agent vsock (Guest restart in progress), it retries with exponential backoff up to `drainTimeout` of the agent Process; after timeout it deletes and re-creates the agent Process resource. Primary reuse disposition: `create`. Preserved source-plan detail: net-new service; preserve semantic nftables/routes reload behavior from v1 net VM configuration. |
| Integration | Controller writes config Volume content, resolves `Endpoint/net-<networkName>-agent-service`, calls `Reload(config_digest)`, and uses readiness predicates to set Network conditions. |
| Data migration | Full d2b 3.0 reset; no v2 state/config import. |
| Validation | `integration/agent_reload.rs` validates Reload, `nft_applied` and `routes_applied` predicates, reconnect behavior, and config digest matching. |
| Removal proof | None - net-new ComponentSession service; no prior service endpoint to remove. |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-nl-008
| Field | Value |
| --- | --- |
| Dependency/owner | Provider; config rendering owned by `Provider/network-local`, storage reconciliation owned by `Provider/volume-local`. |
| Current source | Reuse semantics from `nixos-modules/net.nix` lines 168-296 for nftables and lines 302-441 for dnsmasq; runtime volume model is net-new. |
| Reuse source | `nixos-modules/net.nix` dnsmasq, nftables, routing, and attachment configuration semantics. |
| Reuse action | adapt |
| Destination | `packages/d2b-provider-network-local/src/config_volume.rs`. |
| Detailed design | Implement config Volume content rendering (dnsmasq.conf, nftables.rules, routing.conf, attachments.json). Primary reuse disposition: `adapt`. Preserved source-plan detail: port and render into bounded config Volume files. |
| Integration | Controller creates `Volume/net-<networkName>-config`, writes four files through the Volume service, attaches the read-only view to the net VM, and triggers agent reload plus dnsmasq restart. |
| Data migration | Full d2b 3.0 reset; config Volume is runtime tmpfs content regenerated from Network spec. |
| Validation | `tests/controller_state.rs`, `integration/agent_reload.rs`, and `integration/delete_sequence.rs` validate rendering, write flow, reload, and cleanup ordering. |
| Removal proof | Supersedes static per-env config generation in `nixos-modules/net.nix`; successor coverage retires duplicate old Nix/service assertions. |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-nl-009
| Field | Value |
| --- | --- |
| Dependency/owner | Provider; Process resource builders owned by `d2b-provider-network-local`. |
| Current source | v1 dnsmasq and mDNS process shape came from `nixos-modules/net.nix` and static NixOS services; no v3 Process builder exists. |
| Reuse action | adapt |
| Destination | `packages/d2b-provider-network-local/src/process_specs.rs`. |
| Detailed design | Implement canonical Process spec builders for agent, dnsmasq, mdns-reflector, mdns-dnsbridge. Primary reuse disposition: `adapt`. Preserved source-plan detail: port service semantics into canonical Process resource specs. |
| Integration | Controller creates agent service, dnsmasq worker, and optional mDNS workers as owned Process resources on the net VM; Process Provider reports readiness and lifecycle status. |
| Data migration | Full d2b 3.0 reset; no v2 state/config import. |
| Validation | `tests/controller_state.rs`, `integration/mdns_reflector.rs`, and eval case `process-sandbox-netns.nix` validate Process shape, optional mDNS, and guest-netns capability isolation. |
| Removal proof | Supersedes static per-env systemd services; old duplicate service tests are retired after successor Process coverage passes. |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-nl-010
| Field | Value |
| --- | --- |
| Dependency/owner | net-vm artifact; owns generic `net-vm-base` nixos-system artifact and shared net-local-controller UID/GID reservation. |
| Current source | Reuse lib.mkForce NIC bootstrap from `nixos-modules/base.nix` `10-eth-dhcp` override and account reservation documented in `nixos-modules/host-users.nix`; v1 per-Network config does not carry forward. |
| Reuse source | `nixos-modules/base.nix` `10-eth-dhcp` lib.mkForce override and host-users reservation table. |
| Reuse action | adapt |
| Destination | `net-vm-base` nixos-system artifact and artifact catalog entry `d2b.artifacts.net-vm-base`. |
| Detailed design | Build generic `net-vm-base` nixos-system artifact with net-agent binary, agent-service endpoint, guest-agent binary, standard NIC bootstrap, lib.mkForce override; bake `net-local-controller` account with the UID/GID allocated from the host-users reservation table (documented in `nixos-modules/host-users.nix`). Primary reuse disposition: `adapt`. Preserved source-plan detail: preserve generic boot/safety invariants; exclude per-Network static config. |
| Integration | Network resource `spec.netVmSystemArtifactId` points to `net-vm-base`; runtime-cloud-hypervisor consumes the artifact ID, and the config Volume provides all per-Network DHCP/firewall/routing content. |
| Data migration | Full d2b 3.0 reset; no per-Network v2 net-VM config import. |
| Validation | Eval cases `net-vm-artifact-id-eval.nix` and `network-spec-eval.nix`, plus `tests/net-vm-network-eval.sh` for the lib.mkForce invariant. |
| Removal proof | Supersedes implicit microvm/Nix path coupling; remove `net-vm-base` artifact catalog entry only after all Network resources and provider references are gone. |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-nl-011
| Field | Value |
| --- | --- |
| Dependency/owner | Nix; owns resource declaration, User declaration, host account provisioning, and artifact catalog wiring. |
| Current source | Existing NixOS modules `nixos-modules/network.nix`, `nixos-modules/net.nix`, and `nixos-modules/host-users.nix` provide v1 static declarations and user/account patterns. |
| Reuse action | adapt |
| Destination | Nix module resource emission for `Provider/network-local`, `User/net-local-controller`, host OS account, `provider-network-local`, and `net-vm-base` artifacts. |
| Detailed design | Nix module for `Provider/network-local` resource declaration; `User/net-local-controller` declaration; OS account provisioning; artifact catalog entries. Primary reuse disposition: `adapt`. Preserved source-plan detail: adapt Nix option/resource emission and account provisioning to v3 resources. |
| Integration | Nix compiler emits Provider/User/Network resources and host prerequisites; core ProviderDeployment starts controller Process; system-core reconciles the User resource. |
| Data migration | Full d2b 3.0 reset; no v2 state/config import. |
| Validation | Eval cases `network-spec-eval.nix`, `user-no-managed-by-eval.nix`, `net-vm-artifact-id-eval.nix`, and `make test-policy` for artifact/package paths. |
| Removal proof | Supersedes v1 NixOS module declarations; removal proof is deletion of old resource emission and account/artifact entries when provider is retired. |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-nl-012
| Field | Value |
| --- | --- |
| Dependency/owner | Nix; depends on Network resource schema and CIDR validation rules. |
| Current source | `nixos-modules/lib.nix:cidrOverlaps` lines 429-462 provides CIDR overlap logic in the v1 module layer. |
| Reuse source | `nixos-modules/lib.nix:cidrOverlaps`. |
| Reuse action | adapt |
| Destination | Nix flake/resource schema checks for declared Networks and provider `validate.rs` parity. |
| Detailed design | Build-time CIDR overlap check for declared Networks in flake check. Primary reuse disposition: `adapt`. Preserved source-plan detail: port/reuse overlap semantics in v3 eval checks and provider validation. |
| Integration | Nix compiler rejects overlapping declared Network CIDRs before resource publication; runtime `validateSpec` re-checks full overlap matrix. |
| Data migration | None - docs/tooling only; no runtime state. |
| Validation | Eval case `network-cidr-overlap-eval.nix` and `tests/cidr_overlap.rs` cover same-Network, cross-Network, external CIDR, and adjacency cases. |
| Removal proof | None - validation net-new in v3 resource compiler; no prior owner to remove. |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-nl-013
| Field | Value |
| --- | --- |
| Dependency/owner | Tests; owned by `d2b-provider-network-local` hermetic test suite. |
| Current source | Reusable semantic assertions come from §25.1 IfName/CIDR reuse inventory and Network schema defined in this spec. |
| Reuse action | adapt |
| Destination | `packages/d2b-provider-network-local/tests/schema_roundtrip.rs`, `tests/ifname_derive.rs`, and `tests/cidr_overlap.rs`. |
| Detailed design | Conformance suite: NetworkSpec round-trip, IfName derivation, CIDR validation matrix. Primary reuse disposition: `adapt`. Preserved source-plan detail: adapt existing IfName/CIDR assertions into provider conformance tests. |
| Integration | Test suite runs under `cargo test -p d2b-provider-network-local --lib --tests` and validates provider schema before integration gates. |
| Data migration | None - docs/tooling only; no runtime state. |
| Validation | The listed conformance tests themselves are the validation, with workspace policy ensuring `tests/` exists. |
| Removal proof | Retire replaced current-code tests only after successor hermetic tests cover the minimum reusable assertions and gate manifests/pins are updated. |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-nl-014
| Field | Value |
| --- | --- |
| Dependency/owner | Tests; depends on ADR046-nl-006 controller and fake `NetworkEffectPort` from `d2b-contracts`. |
| Current source | None - net-new v3 controller state-machine test; v1 shell/Nix gates are not a controller-reconcile equivalent. |
| Reuse action | create |
| Destination | `packages/d2b-provider-network-local/tests/controller_state.rs`. |
| Detailed design | Controller state-machine unit tests with fake `NetworkEffectPort` (from d2b-contracts mock) and deterministic clock, including attachment removal/finalizer calls to generation-fenced `DeletePersistentTap`. |
| Integration | Hermetic fake effect port drives reconcile, observe, finalizer, and adoption transitions without real broker, systemd, container, or network dependencies. |
| Data migration | None - docs/tooling only; no runtime state. |
| Validation | `tests/controller_state.rs` covers normal path, CIDR conflict, User not Ready, Volume error, Guest timeout, agent reload failure, finalizer sequence, `DeletePersistentTap` validated absence, transient retry with retained handle, stale-generation refresh, foreign-marker block, adoption, and drift. |
| Removal proof | None - net-new; no prior owner to remove. |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-nl-015
| Field | Value |
| --- | --- |
| Dependency/owner | Tests; integration coverage for the complete Network lifecycle. |
| Current source | Existing Layer-1 eval and shell gates cover fragments; no v3 provider lifecycle integration test exists. |
| Reuse action | adapt |
| Destination | `packages/d2b-provider-network-local/integration/host_fabric.rs`, `guest_lifecycle.rs`, `agent_reload.rs`, and `delete_sequence.rs`. |
| Detailed design | Integration tests: full Network lifecycle (create, config update, agent Reload, generation-fenced persistent-tap deletion, delete sequence) in container environment. Primary reuse disposition: `adapt`. Preserved source-plan detail: adapt reusable semantic assertions into v3 integration coverage. |
| Integration | Integration tests exercise resource publication, host fabric effects, config Volume updates, ComponentSession reload, Process lifecycle, and finalizer cleanup through the provider stack. |
| Data migration | None - docs/tooling only; no runtime state. |
| Validation | `make test-integration` for container tests and `make test-host-integration` where guest lifecycle requires host/KVM coverage. |
| Removal proof | Old duplicate tests, shell gates, fixtures, static artifacts, CI jobs, manifests, and pins are deleted once successor coverage and removal proof pass. |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-nl-016
| Field | Value |
| --- | --- |
| Dependency/owner | Security; depends on Process sandbox schema and `Provider/system-minijail` guest namespace inheritance. |
| Current source | The invariant is specified as INV-NET-008 and has eval coverage named `tests/unit/nix/cases/process-sandbox-netns.nix`. |
| Reuse action | adapt |
| Destination | Process templates for agent and dnsmasq plus sandbox/eval tests. |
| Detailed design | Verify INV-NET-008 (Guest-network-admin isolation): Process Provider correctly inherits Guest netns for agent/dnsmasq. Primary reuse disposition: `adapt`. Preserved source-plan detail: preserve and verify existing guest-netns isolation invariant in v3 Process specs. |
| Integration | `Provider/network-local` emits `namespaceClasses: []` and guest-only capability classes; Process Provider starts agent/dnsmasq inside the net VM network namespace only. |
| Data migration | None - docs/tooling only; no runtime state. |
| Validation | `tests/unit/nix/cases/process-sandbox-netns.nix` and provider Process-template tests assert no host capability or host network namespace grant. |
| Removal proof | None - security invariant preserved; no prior owner to remove. |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-nl-017
| Field | Value |
| --- | --- |
| Dependency/owner | Docs; owned by `d2b-provider-network-local` package documentation. |
| Current source | None - provider crate README is net-new for v3 packaging; this dossier supplies the required topics. |
| Reuse action | create |
| Destination | `packages/d2b-provider-network-local/README.md`. |
| Detailed design | `packages/d2b-provider-network-local/README.md` covering all 7 required topics. Primary reuse disposition: `create`. Preserved source-plan detail: net-new documentation. |
| Integration | Workspace policy requires the README alongside `src/`, `tests/`, and `integration/`; operators and contributors use it for provider identity, build, test, integration, state, RBAC, and standalone-repo path. |
| Data migration | None - docs/tooling only; no runtime state. |
| Validation | `make test-policy` / `xtask workspace-policy` verifies required provider crate paths and README presence. |
| Removal proof | None - net-new documentation; no prior owner to remove. |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-nl-018
| Field | Value |
| --- | --- |
| Dependency/owner | Broker plus device provider boundary; USBIP ownership projections applied through the shared `ApplyNftablesProjection` operation remain owned by `Provider/device-usbip`. |
| Current source | The shipped whole-table `UsbipBindFirewallRule` op currently owns per-busid `inet d2b` exposure, while legacy `network.nix` and `net.nix` add broader TCP/3240 allows; that shipped op is not the v3 firewall path. |
| Reuse action | adapt |
| Destination | Device-usbip EffectPort/adapter owns USBIP rules, drift, and strict provider status; network-local host/net-VM renderers and status cover only Network-owned policy. |
| Detailed design | `ApplyNftablesProjection { action: Apply \| Remove }` is the sole broker mutation path for exact per-Network/per-busid TCP/3240 exposure. Network-local emits no TCP/3240 match, excludes device-usbip ownership markers from its digest, and never reports USBIP drift. Primary reuse disposition: `adapt`. Preserved source-plan detail: reuse the shared projection-scoped broker op; remove both generic network-local USBIP allows and do not extend or dispatch the shipped whole-table `UsbipBindFirewallRule` op. |
| Integration | `Provider/device-usbip` watches only Network identity/readiness/generation; Core privately resolves the Network attachment for the one relay Endpoint authority and firewall op. Binding proxies receive authorized connected streams through LaunchTickets. |
| Data migration | Full d2b 3.0 reset; no v2 state/config import. |
| Validation | Network-local host and net-VM firewall intent tests assert no TCP/3240/USBIP rule; USBIP rule churn leaves Network digest/`FirewallReady` unchanged; device-usbip tests own exact scoping, drift, status, and release. |
| Removal proof | Legacy generic `network.nix` and `net.nix` USBIP allow fragments and any golden expectation for them are removed after device-usbip host integration passes. |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-nl-019
| Field | Value |
| --- | --- |
| Dependency/owner | Provider; depends on D087 ProviderStateSet and status-first storage rules. |
| Current source | None - net-new v3 ProviderStateSet/status contract; v1 network module did not expose Provider state Volumes. |
| Reuse action | create |
| Destination | Provider descriptor, controller-main deployment, `tests/state_schema_roundtrip.rs`, and eval case `provider-state-volume-eval.nix`. |
| Detailed design | Confirm `controller-main` declares no stateNamespace and core ProviderDeployment creates no Provider state Volume or state mount; validate ProviderStateSet query returns empty for `Provider/network-local`; validate bounded operational state is written to revisioned/redacted status and the core Operation ledger with `status-oversize` conformance; confirm per-Network config Volumes remain `ownerRef: Network/<name>` runtime/config operational Volumes outside the ProviderStateSet and `Volume` is not in `ResourceTypes implemented`. Primary reuse disposition: `create`. Preserved source-plan detail: net-new status-first provider-state conformance. |
| Integration | Core ProviderDeployment starts controller without `/state`; controller uses Network status and Operation ledger for bounded observations; ProviderStateSet query excludes per-Network config Volumes. |
| Data migration | Full d2b 3.0 reset; no v2 state/config import. |
| Validation | `tests/state_schema_roundtrip.rs` and `tests/unit/nix/cases/provider-state-volume-eval.nix` validate empty ProviderStateSet, status bounds/redaction, and config Volume exclusion. |
| Removal proof | None - net-new; no Provider state Volume or prior owner to remove. |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-nl-020
| Field | Value |
| --- | --- |
| Dependency/owner | D097 Core authority index, Network contracts, runtime-cloud-hypervisor private attachment path |
| Current source | Current macvtap spawn resolves a raw parent interface but has no Host-global duplicate admission, sharing policy, authority status, or owner-proof lifecycle. |
| Reuse action | adapt |
| Destination | Network schema/Provider descriptor, Core authority index, Network reconcile/update/finalizer, runtime LaunchTicket resolver, and authority tests |
| Detailed design | Register the external physical-NIC `AuthorityDescriptor`: Host-global `external-physical-nic/v1` Core-derived identity, `zero-or-one` authority, an isolation domain equal to the claimant's Zone UID, exclusive `passthru`/`private`/`vepa`, exclusive-by-default `bridge`, explicitly compatible bounded multiplexing only for `bridge` and only among holders in one Zone, categorical cross-Zone `bridge` multiplex rejection with `external-physical-nic-cross-zone-l2` (INV-NET-011), `external-physical-nic-conflict` for same-Zone incompatible claims, exact owner proof, drain-release-reacquire update, forbidden export, and bounded FIFO holder policy. Primary reuse disposition: `adapt`. Preserved source-plan detail: adapt the existing broker-internal macvtap-FD creation path behind mandatory Core authority admission. |
| Integration | Core preflight gates every runtime LaunchTicket/`SpawnRunner`; status reports bounded authority state and conditions; D091 update and finalizer close macvtap ownership before release. |
| Data migration | Full d2b 3.0 reset; no legacy authority import. |
| Validation | `external_nic_authority.rs` covers Core-derived identity, same-/cross-Zone conflicts, explicit same-Zone bridge multiplexing, categorical cross-Zone bridge multiplex rejection with `external-physical-nic-cross-zone-l2` and no host effect (INV-NET-011), incompatible policy, non-bridge multiplex denial, no-effect rejection, adoption ambiguity, owner transfer, disruptive update, release ordering, and redaction; Nix eval and host integration cover declared configuration and lifecycle. |
| Removal proof | The old direct macvtap spawn path is unreachable unless Core supplies an admitted authority claim in the LaunchTicket. |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

---

## 26. Tests

### 26.1 Workspace policy

The workspace policy (`make test-policy` / `xtask workspace-policy`) requires four
paths at the crate root:

| Required path | Satisfied by |
| --- | --- |
| `src/` | at least one tracked `.rs` source file |
| `tests/` | at least one tracked `.rs` test file |
| `integration/` | at least one tracked `.rs` integration scenario file |
| `README.md` | root README covering all 7 required topics |

A nested `integration/README.md` is **optional** and not required by policy.
The integration test invocation commands are documented in the root `README.md`.

### Fast hermetic execution and test placement (D094)

Per D094 and the repository's test-budget guidance, this Provider's `src/`
unit tests and `tests/*.rs` hermetic suite are fast, in-process, deterministic,
and parallel-safe: an individual normal test has an advisory wall-clock p95
diagnostic threshold of <=50 ms; gate enforcement is aggregate per-crate
process CPU only. There is no wall-clock
sleep, and `cargo test -p d2b-provider-network-local --lib --tests` completes in
≤3 s warm-cache execution time (compilation excluded). They use a deterministic
fake clock/RNG and the toolkit fakes/FakeEffectPort only - no process spawn,
container, network, DBus, systemd, broker daemon, Nix eval/build, KVM,
USB/GPU/TPM hardware, or live cloud, and no filesystem tree beyond tiny temp
fixtures. Any scenario needing those lives only in `integration/`, which keeps a
lane timeout/budget, parallel isolation, and fake external services by default;
such a need is re-placed into `integration/`, never given a sleep, larger
timeout, or `#[ignore]`. Bounded crypto/property tests are the only classified
exception, each named with a capped case count and a declared higher per-test
budget.

### 26.2 Unit tests (`tests/`)

| Test file | Coverage |
| --- | --- |
| `schema_roundtrip.rs` | `NetworkSpec` and `NetworkStatus` JSON serialize/deserialize; external `parentInterface`/mode/sharing policy; bounded authority status; all optional fields and enum variants |
| `state_schema_roundtrip.rs` | Provider descriptor has no stateNamespace for `controller-main`; no Provider state Volume, state mount, identity marker, migration worker, or state-layout principal is emitted; ProviderStateSet query returns empty; bounded operational observations live in status/core Operation ledger and pass redaction/size-bound checks; per-Network config Volumes are excluded from ProviderStateSet (ownerRef mismatch) |
| `ifname_derive.rs` | IfName derivation determinism; collision detection; 15-byte constraint; all role prefixes |
| `cidr_overlap.rs` | CIDR overlap matrix: same Network, cross-Network, external CIDR; all boundaries; no-false-positive at adjacent CIDRs |
| `controller_state.rs` | Full reconcile state machine: Normal path; CIDR conflict; User not Ready; Volume error; Guest timeout; agent reload failure; attachment removal and finalizer issue generation-fenced `DeletePersistentTap` only after Guest/VMM FD closure, retain handles across transient retry, refresh on stale generation, block on foreign marker, and accept validated absence; all remaining child ordering; external authority release after VMM/macvtap close; adoption on restart; Network-owned drift detection |
| `external_nic_authority.rs` | Core-derived Host-global identity; same-/cross-Zone exclusive collision; non-bridge multiplex denial; explicit same-Zone compatible bridge multiplex; categorical cross-Zone bridge multiplex rejection (`external-physical-nic-cross-zone-l2`, no effect); mixed-policy conflict; no effect before admission; owner-proof adoption/ambiguity; owner transfer; update/release ordering; no raw identity in status |
| `firewall_ownership.rs` | Host and net-VM intents contain no TCP/3240/USBIP rule; device-usbip marker/rule churn does not alter Network digest or `FirewallReady` |
| `conformance.rs` | Provider toolkit black-box conformance suite; descriptor validation; ResourceType schema fingerprint |
| `fault_injection.rs` | `NetworkEffectPort` returns each `EffectError` variant; `DeletePersistentTap` transient/generation/ownership errors have exact retry/terminal classification; each step fails independently; reconcile context has no broker socket; provider crate has no broker import |
| `metrics_labels.rs` | Every metric descriptor uses only closed semantic labels; exact absence of `vm`, `zone`, `zone_id`, `zone_uid`, `network`, and resource-name-derived keys; Network-name canary absent from emitted labels; `d2b.zone` retained as an OTEL resource attribute |

### 26.3 Integration tests (`integration/`)

| Test file | Coverage | Runner |
| --- | --- | --- |
| `host_fabric.rs` | Persistent tap create/delete pairing; opaque attachment ID and generation fences; validated absent success; foreign-marker fail-closed; no IfName/path request or audit; bridge create/delete; Network-owned nftables apply; no USBIP/TCP-3240 allow; IPv6 suppression; NM unmanaged; ownership-scoped drift detection; NetworkEffectPort real impl | `make test-integration` (container) |
| `guest_lifecycle.rs` | net-VM Guest create/delete; opaque attachment handle resolution; systemArtifactId binding | `make test-host-integration` |
| `agent_reload.rs` | Agent service Reload() call; nft-applied + routes-applied predicates; config digest match | `make test-host-integration` |
| `mdns_reflector.rs` | mDNS reflector Process lifecycle; create when mdns.enable; delete on Network delete | `make test-integration` (container) |
| `delete_sequence.rs` | Full finalizer ordering: workload Guest/VMM FD closure, generation-fenced `DeletePersistentTap` confirmation, Process Deleted events, Volume attachment removal, net-VM Guest Deleted, Volume Deleted, fabric cleanup; transient delete retry retains the handle | `make test-host-integration` |
| `external_nic_lifecycle.rs` | Fake physical NIC: Host-global claim before SpawnRunner; cross-Zone conflict has no effect; explicit same-Zone bridge multiplex; cross-Zone bridge multiplex rejected (`external-physical-nic-cross-zone-l2`) with no macvtap effect; update drain/reacquire; delete closes macvtap before claim release | `make test-host-integration` |

### 26.4 Eval tests (Layer-1, `tests/unit/nix/cases/`)

| Case file | Coverage |
| --- | --- |
| `network-spec-eval.nix` | `d2b.zones.dev.resources.work-net` Nix option round-trip; `netVmSystemArtifactId` required field; artifact type check |
| `network-cidr-overlap-eval.nix` | Dual-Network CIDR overlap eval-time assertion |
| `process-sandbox-netns.nix` | Agent and dnsmasq Process sandbox: `namespaceClasses: []` → inherits Guest netns; no capabilityClass on host |
| `net-vm-artifact-id-eval.nix` | `net-vm-base` artifact ID format; `nixos-system` type; no path separator |
| `user-no-managed-by-eval.nix` | `User/net-local-controller` spec contains no `managedBy`; `ownerRef` is in metadata |
| `provider-state-volume-eval.nix` | ProviderStateSet query-time membership returns empty for `Provider/network-local`; per-Network config Volumes (ownerRef: `Network/<name>`) are excluded and remain runtime/config operational Volumes |
| `network-external-nic-authority-eval.nix` | parent/mode/sharing schema; non-bridge multiplex rejection; declared same-/cross-Zone conflicts; explicit same-Zone compatible bridge multiplex policy; declared cross-Zone bridge multiplex rejected with `external-physical-nic-cross-zone-l2` |

### 26.5 Drift gates (Layer-1)

| Gate | What is guarded |
| --- | --- |
| `make test-drift` | `xtask gen-schemas` → `git diff --exit-code` on `docs/reference/schemas/v2/*.json`; Network schema drift |
| `make test-policy` | `xtask workspace-policy` → all four paths (`src/`, `tests/`, `integration/`, `README.md`) present |

---

## 27. Removal checklist

When `Provider/network-local` is retired (superseded or removed):

- [ ] All `Network` resources in all Zones must be deleted and finalizers cleared.
- [ ] Verify no Provider state Volume exists for `Provider/network-local` before
  marking Provider Deleted.
- [ ] `User/net-local-controller` resources must be deleted (after Network deletion
  releases all per-Network config Volume layout references).
- [ ] `Provider/network-local` resource must be deleted (after all Networks cleared).
- [ ] `net-local-controller` OS account must be removed from host NixOS config.
- [ ] `net-vm-base` artifact catalog entry must be removed from `d2b.artifacts`.
- [ ] `provider-network-local` artifact catalog entry must be removed.
- [ ] `d2b-provider-network-local` crate must be removed from workspace members and
  the members list must remain alphanumerically sorted.
- [ ] Broker ops `CreatePersistentTap` and `DeletePersistentTap` are retired as
  a pair only if no other Provider uses them and no retained attachment
  realization exists; `CreateBridge` and `DeleteBridge` may be retired if no
  other Provider uses them. Consult the broker op table in
  `docs/reference/privileges.md`.
- [ ] `NetworkEffectPort` trait declaration in `d2b-contracts` must be removed or
  marked `#[deprecated]` when no other Provider uses it; the core adapter
  implementation is removed alongside the Provider.
- [ ] All eval-time tests and drift gates referencing `network-local` or
  `net-vm-base` must be updated or removed.
- [ ] CHANGELOG.md entry required for the removal (as a `Removed` entry under the
  appropriate version section).

Per D094, each replaced current-code test is retired with an explicit
keep/adapt/move/delete disposition and a removal gate: the minimum reusable
semantic assertions migrate into this crate's hermetic `tests/`, and the old
duplicate tests, shell gates, fixtures, static artifacts, CI jobs, and manifest
entries are deleted once successor coverage and the removal proof pass -
updating the fixed Bazel suites, closed gate manifests, flake/Nix-unit pins,
generated ledgers, and CI jobs.
Old and new suites never run in parallel indefinitely.
