# ADR 0046 Volume resource

| Field | Value |
| --- | --- |
| Spec ID | `ADR-046-resources-volume` |
| Parent | ADR 0046 |
| Status | Accepted |
| Version | 1 |
| Baseline | `b5ddbed67867d9244bf33390868101bd9b053e49` |
| Normative | Yes |
| Owners | `d2b-provider-volume-local`, `d2b-provider-volume-virtiofs`, Zone resource API/store |
| Depends on | `ADR-046-resource-object-model`, `ADR-046-primitive-resource-composition`, `ADR-046-resource-reconciliation`, `ADR-046-provider-model-and-packaging`, `ADR-046-components-processes-and-sandbox` |
| Supersedes | `storage.json` v2, `sync.json` v1, per-VM hardlink-farm and store-view emitters in `nixos-modules/storage-json.nix`, `nixos-modules/store.nix` |

## Purpose

This spec exhaustively defines the Volume ResourceType: schema, entry types, ACL
contract, lifecycle policies, sensitivity, named views, Process mounts, same-Zone
Host/Guest attachments, the virtiofs transport and owned virtiofsd Process, both
Provider implementations, current `storage.json`/`sync.json`/store-view/TPM/runtime
path rows and their v3 successors, async reconciliation, owner triggers, RBAC,
Nix configuration examples, and implementation work items.

Volume replaces `storage.json`/`sync.json` path rows as the single authoritative
storage layout/lifecycle contract (D032). It does not replace Host/Guest/Process
configuration or broker wire operations.

## Terminology mapping (current baseline → v3 target)

All evidence citations in this spec use current baseline symbol names. This table
records the canonical rename so every citation can be traced forward to its v3
destination.

| Current baseline name | Current location | v3 target name | Notes |
| --- | --- | --- | --- |
| `Realm` / `RealmId` | `packages/d2b-realm-core/src/ids.rs` | Zone | `RealmId::parse(label)` validates lowercase label shape |
| `RealmPath` | `packages/d2b-realm-core/src/realm.rs` | Zone self resource path | Runtime directory root for the realm |
| `NodeId` | `d2b-realm-core/src/ids.rs` | Not yet a first-class v3 ResourceType | Retained in Zone runtime contracts |
| `WorkloadId` | `d2b-realm-core/src/ids.rs`, `src/workload.rs` | Guest (VM/sandbox/cloud/remote) or Host (local physical) | Classified by `WorkloadProviderKind` below |
| `WorkloadProviderKind::LocalVm` | `d2b-realm-core/src/workload.rs` | Guest with isolation: VirtualMachine under a Zone | Locally supervised NixOS microVM |
| `WorkloadProviderKind::QemuMedia` | same | Guest with isolation: VirtualMachine (QEMU media path) | Locally supervised external-media QEMU runtime |
| `WorkloadProviderKind::ProviderManaged` | same | Guest under a Zone-local Provider resource | Runtime owned by a provider adapter |
| `WorkloadProviderKind::UnsafeLocal` | same | User-only Host under Provider/system-core | No isolation boundary; `IsolationPosture::UnsafeLocal` |
| `ProviderId` | `d2b-realm-core/src/ids.rs` | Provider ResourceRef | Provider resource identity |
| `VmProcessDag` | `d2b-core/src/processes.rs` | Set of Process/EphemeralProcess resources under a Guest | Currently emitted as `processes.json` bundle artifact |
| `ProcessRole` | `d2b-core/src/processes.rs` | Process/EphemeralProcess ResourceType classification | enum variant → resource spec template name |
| `ProcessRole::Virtiofsd` | same | Process resource, template `virtiofsd-worker`, owned by `virtiofs.d2bus.org.Export` and reconciled by volume-virtiofs | Currently a dag node under Guest (WorkloadId) |
| `ProcessRole::Swtpm` | same | Process resource owned by a device-tpm Provider (not Volume) | TPM state belongs to Volume; swtpm lifecycle to device-tpm |
| `ProcessRole::CloudHypervisorRunner` | same | Process resource template `cloud-hypervisor-runner` under Guest | Core VM runner |
| `d2b.vms.<vm>` | `nixos-modules/options-vms.nix` | v3 target: flat `d2b.zones.<zone>.resources.<name>` with `type = "Guest"` | Current Nix option namespace for VM config |
| `d2b.realms.<realm>` | `nixos-modules/options-realms.nix` | v3 target: Zone configuration | Current Nix namespace for realm workload stateDir etc. |
| `storage.json` row `scope: "vm:<vm>"` | `nixos-modules/storage-json.nix` | `ownerRef: Guest/<name>` in Volume LayoutEntry | Opaque bundle ID in v2; typed ResourceRef in v3 |
| `storage.json` row `scope: "host"` | same | Zone-level path; ownerRef absent or `Host/<name>` | Host-global paths owned by Zone runtime |
| `d2b-priv-broker` (`d2b-priv-broker.service`) | `packages/d2b-priv-broker/` | Zone broker; child realm broker child process | Fixed local-root broker; realm brokers are separate child processes (ADR 0045) |
| `d2bd` (`d2bd.service`) | `packages/d2bd/` | Zone runtime controller | Fixed local-root controller; child realm controllers are separate child processes |

## Resolved decisions

All ten Volume design decisions are resolved in this revision.

| ID | Resolution |
| --- | --- |
| DRVOL-001 | `block-image` is a first-class volume-local SourceKind. volume-local manages the image file; the Guest Provider (cloud-hypervisor/QEMU) receives a stable FD and attaches it as `virtio-blk`. |
| DRVOL-002 | `quota.enforcement: hard` means the Volume is set to Failed at creation if the backing filesystem cannot enforce byte/inode quotas. `enforcement: none` is always permitted. For `tmpfs` SourceKind, enforcement is always effectively hard (kernel-enforced mount limits). |
| DRVOL-003 | Volume snapshot and storage-content migration operations are modeled as EphemeralProcess resources owned by the Volume and surfaced through the resource API; they are not CLI-only jobs. |
| DRVOL-004 | `access: read-write` permits at most one simultaneous writer; the controller enforces the single-writer constraint. `access: shared-write` is a distinct mode requiring the Provider to declare `supportsSharedWrite: true`; write-ordering semantics are the Provider's responsibility. |
| DRVOL-005 | `tmpfs` is a first-class SourceKind. `quota.maxBytes` and `quota.maxInodes` are required; usage is charged against the Host or Guest memory budget. `kind` must be `ephemeral` or `tmp`. |
| DRVOL-006 | Maximum per Volume: 1024 layout entries, 64 Views, 64 attachments. |
| DRVOL-007 | `file`, `directory`, and `symlink` are each first-class LayoutEntry types with independent `createPolicy`/`repairPolicy`/`cleanupPolicy`. A `symlink` entry carries a required `target` field; the target must be a path relative to the Volume root with no `..` components, no leading `/`, and no null bytes. Absolute targets and escape attempts are rejected at schema validation time. |
| DRVOL-008 | ACL `principal.ref` is a typed `User/<name>` ResourceRef in the same Zone. No numeric UID/GID migration path; d2b 3.0 is a clean reset. The controller resolves the stable UID from the User resource at reconciliation time and re-resolves on User resource revision changes. |
| DRVOL-009 | `accessAcl` and `defaultAcl` are continuously reconciled: the controller re-applies declared ACLs to all existing entries and children during every repair cycle. A `foreignChildPolicy` field on each directory entry governs children not covered by `defaultAcl`: `preserve` leaves foreign ACL entries unchanged; `fail` sets an `ForeignAclViolation` condition on the entry. |
| DRVOL-010 | The virtiofsd export socket path is a generated private implementation detail of volume-virtiofs. It is never exposed as a spec field, status field, or API surface. ADR046-volume-003 owns the safe path generation contract. |

## Volume ResourceSpec

### Three-layer spec shape (D089)

D089 freezes Volume spec as three layers. Layer 1 is the universal Resource
envelope and metadata. Layer 2 is the Volume base spec at top-level `spec.*`,
including `spec.providerRef`; source, kind, layout, views, attachments, quota,
and lifecycle fields documented here are base fields. Layer 3 is the optional
canonical selected-Provider extension
`spec.provider = { schemaId, schemaVersion, settings }`; it is the only
Provider-specific desired extension. It omits `providerRef` and
`observedProviderGeneration`: `spec.providerRef` is base, and spec is desired
rather than observed.

**D091 update policy.** The universal base spec carries `spec.updatePolicy` for
every Volume: disruptive changes default to manual, while automatic
non-disruptive upgrades are permitted by policy. A `spec.provider` extension MAY
add provider-specific knobs, but MUST NOT bypass or weaken base
`spec.updatePolicy`.

**D090 expedited reconcile.** Authorized Volume `Create`, `UpdateSpec`, and
`Delete` calls MAY set `waitForReconcile`. Under one mutation ticket,
`operationId`, and deadline, Core admission and the reserved-revision redb commit
run in parallel with controller preflight/plan, but the controller MUST NOT
perform external effects, finalizer release, or status mutation until Core
supplies `CommittedRevisionProof {resourceUid, generation, revision,
operationId}`; DB failure aborts with no effect. The API returns the committed
object plus one-pass projected layered status, `disposition`
(`Converged|Progressing|Blocked|UpgradeRequired|Failed`), `statusPersistence`
(`pending|committed`), and the last persisted status revision. The durable
commit is never rolled back on reconcile timeout or failure; effect idempotency
keys derive from `(UID,generation,revision,operationId)`, and the expedited pass
uses a bounded priority lane in the same per-resource single-flight.

Every Volume Provider `ResourceApiBinding` MUST implement the exact Volume base
spec schema version and fingerprint, accept the canonical minimal valid base
Spec, and pass base lifecycle/status/error/finalizer conformance. A Provider MAY
reject an optional base capability only through its signed standard capability
matrix and a typed provider-neutral `unsupported-capability` error; it MUST NOT
ignore, reinterpret, rename, duplicate, weaken, or require extension data for
base-required behavior. `spec.provider.settings` is strict deny-unknown,
bounded, schema-versioned and digested, validated against `spec.providerRef` at
Nix build and API admission, and fails with `spec-provider-schema-invalid` or
`spec-provider-shadow` when invalid or shadowing/restating/overriding/renaming/
duplicating a base field. Shared Volume semantics are promoted to the Volume
base spec and never live in `spec.provider`; generic CLI/controllers operate on
base spec plus base status. For the same Provider, the `spec.provider` and
`status.provider` schemas align.

`Volume.spec.source.settings` (including `kind` and `sourcePolicyId`) and the
per-attachment `settings` object (typed mount options) are Volume base
structures, not a Provider extension. Only genuinely
implementation-only desired settings use `spec.provider.settings`.
Provider resource dossiers in this file retain the D075 Provider
self-description shape (`spec.artifactId`, `spec.config`) because a Provider has
no non-circular `spec.providerRef`.

```yaml
apiVersion: resources.d2bus.org/v3
type: Volume
metadata:
  name: work-state
  zone: dev
  uid: <store-generated>
  generation: 1
  ownerRef: Guest/work-vm        # optional
  finalizers: []
spec:
  providerRef: Provider/volume-local
  source:
    executionRef: Host/host-system   # where the backing storage lives
    settings:
      kind: local-path               # see SourceKind below
      sourcePolicyId: <opaque ID bound to a volume-local allowlist policy entry>
  kind: state                        # volume semantic kind (see below)
  layout:
    - path: ""                       # root of the volume
      type: directory
      ownerRef: User/example-system
      groupRef: User/example-system
      mode: "0700"
      accessAcl: []
      defaultAcl: []
      noFollow: true
      recursive: false
      sensitivity: private
      createPolicy: create-if-never-provisioned
      repairPolicy: exact-owner
      cleanupPolicy: owner-controlled
      adoptionPolicy: adopt-with-live-owner-proof
      restartPolicy: preserve-across-controller-restart
      leaseClass: none
      invariants: [no-symlink, broker-opaque-id-only]
  views:
    controller:
      path: ""
      rights: [read, write, create, delete, traverse]
    reader:
      path: ""
      rights: [read, traverse]
  attachments:
    - executionRef: Guest/work-vm
      transport: virtiofs
      view: controller
      access: read-write
      mountPath: /state
      settings:
        posixAcl: false
        xattr: false
        cache: auto
        inodeFileHandles: never
        threadPoolSize: null         # null → vcpu count
  quota: null                        # null = no limit; see §Quota for enforcement options
status:
  observedGeneration: 0
  phase: Pending
  conditions: []
  lastReconciledAt: null
  startedAt: null
  completedAt: null
  outcome: null
  resource: {}                       # Layer 2 ResourceType-common; {} until reconciled (D107)
  update:                            # universal currency object; present on every resource (D091)
    state: Unknown
    reasons: []
    observedGeneration: 0
    targetGeneration: 1
    disruption: None
    preserveState: true
    operationId: null
    lastAssessedAt: null
    owned: { count: 0, refs: [] }
    dependencies: { count: 0, refs: [] }
```

### Spec field reference

| Field | Type | Required | Default | Constraints |
| --- | --- | --- | --- | --- |
| `providerRef` | ResourceRef | Yes | - | Must resolve to a Ready Provider in the same Zone implementing Volume |
| `source.executionRef` | ResourceRef | Yes | - | Must resolve to a Host or Guest in the same Zone |
| `source.settings` | object | Yes | - | Volume base source object; validated by the exact Volume base schema implemented by the selected Provider |
| `source.settings.kind` | SourceKind enum | Yes | - | `local-path`, `block-image`, `tmpfs` |
| `source.settings.sourcePolicyId` | string | conditional | - | Opaque bounded ID for `local-path`/`block-image`; references an entry in volume-local's private allowlisted root policy. Never a raw host path; never exposed in public status or audit. |
| `kind` | VolumeKind enum | Yes | - | `durable`, `ephemeral`, `state`, `tmp`, `cache` |
| `layout` | LayoutEntry[] | Yes | `[]` | Anchored relative paths; must be non-overlapping; max 1024 entries |
| `views` | map<ViewName, ViewSpec> | Yes | `{}` | ViewName matches `^[a-z][a-z0-9-]*$`; max 64 Views |
| `attachments` | Attachment[] | No | `[]` | Max 64 attachments; at most one `read-write` at any time; `shared-write` requires Provider `supportsSharedWrite: true` |
| `quota` | QuotaSpec or null | No | null | `enforcement: hard` fails Volume if backing FS cannot enforce; `enforcement: none` always permitted |

### VolumeKind semantics

| Kind | Persistence | Cleanup trigger | Typical backing |
| --- | --- | --- | --- |
| `durable` | Across reboots and controller restarts | Never (operator-controlled) | Local persistent directory |
| `state` | Across reboots and controller restarts; content is role-state | Never; fail-closed on missing-after-provision | Local persistent directory + provisioning marker |
| `cache` | Best-effort; may be rebuilt | On controller restart or explicit flush | Local persistent or tmpfs |
| `ephemeral` | Boot-scoped; content is transient | On Host/Guest restart or Zone reset | `tmpfs` or `local-path` (boot-scoped subdir under `/run/d2b`) |
| `tmp` | Process-scoped; cleaned on process exit | Process exit with proof | Local subdirectory with process-pidfd lease |

## Layout entries

A LayoutEntry declares one path relative to the Volume root. Relative path `""` is
the Volume root itself. All paths are anchored; no `..`, absolute path, symlink
traversal (when noFollow is true), or drive-letter form is accepted.

### LayoutEntry fields

| Field | Type | Required | Default | Constraints |
| --- | --- | --- | --- | --- |
| `path` | relative path string | Yes | - | Anchored; `""` = volume root; no leading `/`; no `..` |
| `type` | EntryType enum | Yes | - | `directory`, `file`, `symlink`, `unix-socket`; each is first-class with independent lifecycle policies |
| `ownerRef` | ResourceRef | Yes | - | Must resolve to a `User/<name>` ResourceRef in the same Zone; no numeric UID accepted |
| `groupRef` | ResourceRef | Yes | - | Must resolve to a `User/<name>` ResourceRef in the same Zone; no numeric GID accepted |
| `mode` | octal string | Yes | - | Four-octet string, e.g. `"0700"`, `"0640"`, `"0660"` |
| `target` | relative path string | conditional | - | Required for `symlink` type only; relative to Volume root; no `..`, no leading `/`, no null bytes; must resolve within Volume root |
| `accessAcl` | AclGrant[] | No | `[]` | Named access ACL; continuously reconciled during every repair cycle |
| `defaultAcl` | AclGrant[] | No | `[]` | Default ACL applied to all new children; continuously reconciled; `foreignChildPolicy` governs unlisted children |
| `foreignChildPolicy` | `preserve` or `fail` | No | `preserve` | For `directory` entries: `preserve` retains unexpected child ACL entries; `fail` sets `ForeignAclViolation` condition |
| `noFollow` | bool | No | `true` | Reject symlink traversal during layout operations; may be false only for `symlink`-type entries |
| `recursive` | bool | No | `false` | Apply owner/mode/ACL recursively during repair; dangerous for large trees |
| `sensitivity` | SensitivityClass enum | No | `private` | Governs audit redaction and log handling |
| `createPolicy` | CreatePolicy enum | No | `create-if-absent` | When to create the entry |
| `repairPolicy` | RepairPolicy enum | No | `exact-owner` | How to reconcile drift from the declared state |
| `cleanupPolicy` | CleanupPolicy enum | No | `never` | When the entry is removed |
| `adoptionPolicy` | AdoptionPolicy enum | No | `adopt-with-live-owner-proof` | How an existing entry is treated on first bind |
| `restartPolicy` | RestartPolicy enum | No | `preserve-across-controller-restart` | Behavior across Volume controller restart |
| `leaseClass` | LeaseClass enum | No | `none` | Type of live-ownership lease checked during adoption |
| `invariants` | Invariant[] | No | `[no-symlink]` | Additional fail-closed checks |

### EntryType

| Value | Current baseline analog | Notes |
| --- | --- | --- |
| `directory` | `StoragePathKind::Directory` | Default and most common |
| `file` | `StoragePathKind::RegularFile` | Regular file; must be declared with an ownerRef/mode |
| `symlink` | `StoragePathKind::Symlink` | First-class entry type with independent lifecycle policies; `noFollow: false` required; `target` field required (relative to Volume root, no `..`, no absolute); target is validated at schema time |
| `unix-socket` | `StoragePathKind::UnixSocket` | Mode `0660` default; process-scoped cleanup required |

`DeviceNode` and `ExternalGrantOnly` from the current `StoragePathKind` enum are not
exposed as Volume LayoutEntry types. Device nodes are a Device Provider concern;
`external-grant-only` becomes an observation-only entry with `repairPolicy: none`.

### AclGrant

```yaml
principal:
  ref: User/example-system    # typed User/<name> ResourceRef; always same Zone
permissions: rwx               # POSIX ACL permission string
```

ACL principals are always typed `User/<name>` ResourceRefs in the same Zone.
No numeric UID/GID form is accepted; d2b 3.0 is a clean reset with no numeric
migration path. The controller resolves the User's stable UID at reconciliation
time and re-resolves on any User resource revision change that affects the UID binding.

### CreatePolicy

| Value | Semantics | Baseline `StorageLifecycle` analog |
| --- | --- | --- |
| `create-if-absent` | Create the entry if it does not exist | `Config`, `Persistent` |
| `create-if-never-provisioned` | Create only if a prior-provision marker is absent; preserve existing content | - (swtpm/state hardening model) |
| `always-recreate` | Always remove and recreate; use only for process-scoped entries | `ProcessScoped` |
| `observe-only` | Do not create; observe and report phase but do not mutate | `ExternalObserveOnly` |

### RepairPolicy

| Value | Semantics | Baseline analog |
| --- | --- | --- |
| `none` | No repair; report drift as a condition | `RepairPolicy::None` |
| `nix-activation` | Repair is Nix activation system responsibility | `RepairPolicy::NixActivation` |
| `exact-owner` | Broker reconciles owner/group/mode to exact declared values; non-recursive by default | `RepairPolicy::BrokerReconcile` |
| `fail-closed` | Broker treats any drift as a fatal condition; sets Degraded/Failed; no repair | `RepairPolicy::BrokerFailClosed` |
| `operator-only` | No automated repair; operator must intervene | `RepairPolicy::OperatorOnly` |

### CleanupPolicy

| Value | Semantics | Baseline analog |
| --- | --- | --- |
| `never` | Entry is never removed by the Volume controller | `CleanupPolicy::Never` |
| `boot` | Removed on next host/Zone boot; entry is /run/-scoped | `CleanupPolicy::Boot` |
| `process-exit-with-proof` | Removed after the owning Process exits (verified by pidfd) | `CleanupPolicy::ProcessExitWithProof` |
| `vm-stop-with-proof` | Removed when the owning Guest stops (verified by controller) | `CleanupPolicy::VmStopWithProof` |
| `owner-controlled` | Lifecycle is owned by the controller that mounts/creates the Volume | `CleanupPolicy::External` |

### AdoptionPolicy

| Value | Semantics | Baseline analog |
| --- | --- | --- |
| `adopt-with-live-owner-proof` | Adopt existing entry if owner proof (pidfd/cgroup) is live | `StorageAdoptionPolicy::AdoptWithLiveOwnerProof` |
| `recreate-from-persistent` | Delete existing and recreate from persistent state | `StorageAdoptionPolicy::RecreateFromPersistent` |
| `quarantine-on-ambiguity` | Quarantine existing entry; set Degraded; do not destroy | `StorageAdoptionPolicy::QuarantineOnAmbiguity` |
| `delete-if-owner-dead` | Delete existing entry if the owner is no longer live | `StorageAdoptionPolicy::DeleteIfOwnerDead` |
| `not-adoptable` | Entry is not adoptable; always recreated on controller start | `StorageAdoptionPolicy::NotAdoptable` |

### RestartPolicy

| Value | Semantics | Baseline analog |
| --- | --- | --- |
| `preserve-across-controller-restart` | Entry is retained across Volume controller restart | `StorageRestartPolicy::PreserveAcrossDaemonRestart` |
| `recreate-after-owner-death` | Entry is recreated if the owning process exits | `StorageRestartPolicy::RecreateAfterOwnerDeath` |
| `cleanup-after-owner-death` | Entry is removed if the owning process exits | `StorageRestartPolicy::CleanupAfterOwnerDeath` |
| `manual-recovery` | Restart requires operator action; controller sets Degraded | `StorageRestartPolicy::ManualRecovery` |
| `not-applicable` | Entry has no process owner; restart policy is irrelevant | `StorageRestartPolicy::NotApplicable` |

### LeaseClass

| Value | Semantics | Baseline analog |
| --- | --- | --- |
| `none` | No live-ownership lease | `LeaseClass::None` |
| `process-pidfd` | Entry is leased to a process identified by pidfd | `LeaseClass::ProcessPidfd` |
| `cgroup-leaf` | Entry is leased to a cgroup leaf | `LeaseClass::CgroupLeaf` |
| `file-record` | Entry has an OFD file-record lock | `LeaseClass::FileRecord` |

### SensitivityClass

| Value | Semantics | Baseline analog |
| --- | --- | --- |
| `public` | Content may be mentioned in status/logs at bounded granularity | `SensitivityClass::Public` |
| `private` | Content path must not appear in public status/audit events | `SensitivityClass::Private` |
| `secret-adjacent` | Content path and size must not appear anywhere outside the broker audit trail | `SensitivityClass::SecretAdjacent` |
| `audit` | Entry is a tamper-evident audit segment; special repair/cleanup rules | `SensitivityClass::Audit` |
| `zone-scoped` | Sensitivity is bounded to the Zone boundary; Zone-link does not export metadata | `SensitivityClass::RealmScoped` |

### Invariants

| Value | Semantics | Baseline analog |
| --- | --- | --- |
| `no-symlink` | Broker rejects symlinks during path walk | `StorageInvariant::NoSymlink` |
| `no-magic-link` | Broker rejects magic links (`/proc/self/...`) | `StorageInvariant::NoMagicLink` |
| `no-recursive-mutation` | Broker does not recurse into children | `StorageInvariant::NoRecursiveMutation` |
| `same-filesystem` | Entry must share `st_dev` with the Volume root (hardlink farm constraint) | `StorageInvariant::SameFilesystem` |
| `hardlink-farm-no-recursion` | Entry is a hardlink farm node; broker does not recurse | `StorageInvariant::HardlinkFarmNoRecursion` |
| `broker-opaque-id-only` | Only broker-assigned identities may create children | `StorageInvariant::BrokerOpaqueIdOnly` |

## Named views and rights

A View maps a name to a subtree of the Volume and a bounded rights set.
Process mounts and attachments always select a named View; they do not
reference the raw Volume path.

```yaml
views:
  controller:
    path: ""          # subtree root relative to Volume root ("" = whole volume)
    rights: [read, write, create, delete, traverse, execute]
  reader:
    path: data
    rights: [read, traverse]
  config:
    path: config
    rights: [read]
```

### Rights

| Right | Meaning |
| --- | --- |
| `read` | Read file contents and directory entries |
| `write` | Modify file contents; create, delete, rename within the subtree |
| `create` | Create new files/directories directly in this subtree |
| `delete` | Remove files/directories directly in this subtree |
| `traverse` | Enter directories (needed to reach sub-paths) |
| `execute` | Execute files; implies `traverse` on parent directories |

A View grants only rights that the Volume LayoutEntry ACLs permit for the
Process/Guest principal. The controller validates right intersection at attach time.

ViewName must match `^[a-z][a-z0-9-]*$`. A Volume must have at least one View.
Views declared in a Process mount or attachment spec must exist in the Volume at
creation time.

## Quota

The `quota` field specifies storage limits for the Volume. `enforcement: hard`
requires the Provider to verify that the backing filesystem can enforce byte and
inode limits at Volume creation time; if it cannot, the Volume is set to Failed
immediately and no layout operations are performed. `enforcement: none` is always
accepted and records the limits for informational purposes only.

```yaml
quota:
  maxBytes: 10737418240   # 10 GiB; required when enforcement: hard
  maxInodes: 1000000       # required when enforcement: hard
  enforcement: none        # none | hard
                           # hard: Volume fails if FS cannot enforce limits
```

For `tmpfs` SourceKind Volumes, `quota.maxBytes` maps to the `size=` mount option
and `quota.maxInodes` to `nr_inodes=`; the kernel enforces these limits so
enforcement is always effectively `hard` for tmpfs. `quota.maxBytes` and
`quota.maxInodes` are required for `tmpfs` source Volumes.

## Process volume mounts

Process and EphemeralProcess spec inline their Volume mounts:

```yaml
mounts:
  - volumeRef: Volume/work-state
    view: controller
    mountPath: /state
    access: read-write   # read-only | read-write
    optional: false
```

| Field | Type | Required | Default | Constraints |
| --- | --- | --- | --- | --- |
| `volumeRef` | ResourceRef | Yes | - | Must resolve to a Ready Volume in the same Zone |
| `view` | ViewName | Yes | - | Must exist in the Volume spec |
| `mountPath` | absolute path string | Yes | - | Inside the Process sandbox; no overlap with other mounts |
| `access` | `read-only` or `read-write` | No | `read-only` | Must be compatible with View rights |
| `optional` | bool | No | `false` | If true, absent/Degraded Volume does not prevent Process start |

The Process Provider (system-systemd or system-minijail) never resolves the
Volume root itself. ProviderSupervisor resolves it via `VolumeSourceEffectPort`
at launch time and delivers a bound FD in the LaunchTicket. The raw host
path never appears in Process ResourceSpec, status, or audit.

## Volume source

### SourceKind

| Kind | Backing | Notes |
| --- | --- | --- |
| `local-path` | Host directory rooted at an allowlisted policy entry, referenced by opaque `sourcePolicyId` | Only accepted by volume-local with a policy-allowlisted root |
| `block-image` | Raw or qcow2 disk-image file under the allowlisted policy entry's root, referenced by opaque `sourcePolicyId` | volume-local manages the image file; Guest Provider attaches as `virtio-blk`; `kind: ephemeral` or `kind: durable`; `quota.maxBytes` required |
| `tmpfs` | Memory-backed tmpfs mount; no persistent backing | `quota.maxBytes` and `quota.maxInodes` required (charged to Host/Guest memory budget); `kind` must be `ephemeral` or `tmp`; cleanup unmounts the tmpfs |

`source.settings.sourcePolicyId` is a required field for `local-path` and
`block-image`. It is an opaque bounded string ID (never a raw path) that
references one entry in volume-local's own private `config.allowedHostPaths`
policy catalog - each catalog entry carries its own `id` plus the actual root
path. The Provider process and its controller see only the ID; path
resolution happens exclusively inside volume-local's private Nix/bundle/effect
authority, and the resolved path is handed to the caller only as an opaque FD
via `VolumeSourceEffectPort` at attach/launch time. It never appears in
public status, audit records, or CLI output. The allowlisted roots in the
v3.0 initial policy are:

- `id: state-root`, root `$stateDir` (default `/var/lib/d2b`) - durable and state Volumes
- `id: ephemeral-root`, root `/run/d2b` - ephemeral and tmp Volumes
- `id: cache-root`, root `/var/cache/d2b` - cache Volumes

Operator root config binds `stateDir` at Nix compile time.

## Same-Zone Host/Guest attachments

An Attachment declares that the Volume is exported to an execution context.

```yaml
attachments:
  - executionRef: Guest/work-vm
    transport: virtiofs
    view: controller
    access: read-write
    mountPath: /state
    settings:
      posixAcl: false
      xattr: false
      cache: auto             # auto | always | never
      inodeFileHandles: never # never | prefer | mandatory
      threadPoolSize: null    # null → vcpu count of the target Guest
      socketGroup: null       # null → broker-default (runner gid)
```

| Field | Type | Required | Default | Constraints |
| --- | --- | --- | --- | --- |
| `executionRef` | ResourceRef | Yes | - | Host or Guest in same Zone |
| `transport` | AttachmentTransport enum | Yes | - | `virtiofs` for filesystem shares; `virtio-blk` for `block-image` source Volumes |
| `view` | ViewName | Yes | - | Must exist in the Volume spec |
| `access` | `read-only`, `read-write`, or `shared-write` | No | `read-only` | `read-write`: single writer enforced by controller; `shared-write`: requires Provider `supportsSharedWrite: true`; must be compatible with View rights |
| `mountPath` | absolute path string | Yes | - | Guest-side mount path |
| `settings` | typed attachment-options object | No | `{}` | Volume base nested attachment (mount) options defined by the Volume base schema (`posixAcl`, `xattr`, `cache`, `threadPoolSize`, `inodeFileHandles`, `socketGroup`) and validated against it; a ResourceType-common structure, not a Provider extension. Genuinely implementation-only tuning uses `spec.provider.settings`, never this base object. |

The sole Volume controller, volume-local, translates each attachment with
`transport: virtiofs` into one owned `virtiofs.d2bus.org.Export`. Multiple
attachments with distinct `executionRef` values each get a separate Export.
volume-virtiofs reconciles those Exports and never writes a Volume row.

## virtiofs attachment controller (volume-virtiofs)

`Provider/volume-virtiofs` reconciles `virtiofs.d2bus.org.Export` resources,
not Volume resources. It is one Provider crate with one controller component
and one worker Process binary (virtiofsd itself).

### Responsibilities

1. volume-local translates each Volume virtiofs attachment into one Export
   owned by that Volume.
2. For each Export, volume-virtiofs ensures exactly one virtiofsd `Process` and
   one stable `Endpoint` exist, both owned by the Export.
3. On Export create/repair, it emits `Create` or `UpdateSpec` for those children.
4. On Export delete, it deletes the children, confirms guest-mount absence, and
   clears only its `volume-virtiofs.d2bus.org/export` finalizer.
5. volume-virtiofs writes Export status. volume-local alone reads those statuses
   and writes the aggregated Volume `attachmentStatuses`.

### Owned virtiofsd Process

The virtiofsd Process resource is owned by the Export (via `ownerRef`) and
managed by volume-virtiofs. Its spec follows the common Process spec with
Provider-specific fields:

```yaml
type: Process
metadata:
  name: vol-work-state-virtiofsd-work-vm
  ownerRef: virtiofs.d2bus.org.Export/vol-work-state-x-work-vm
spec:
  providerRef: Provider/system-minijail
  executionRef: Host/host-system
  domain: system
  processClass: worker
  template: virtiofsd-worker   # resolves through Provider/volume-virtiofs registered as the Export controller
  sandbox:
    namespaceClasses: [mount, user]
    capabilityClasses: []
    startRoot: false
    seccompClass: w1-virtiofsd
    readOnlyRoot: true
    userNamespace:
      mappingClass: process-principal-root   # maps in-NS UID/GID 0 to User/vol-work-state-vfd
  mounts: []
```

Every field above is one of the exact common Process/SandboxSpec fields (see
`ADR-046-resources-host-guest-process-user`); there is no Provider-private
`hostUidForZero`/`hostGidForZero`, `requiresStartRoot`, `seccompPolicyRef`,
`readOnlyPaths`/`writablePaths`, or `cgroupSubtree` field. `cgroupSubtree` is
never authored: cgroup placement is derived by ProviderSupervisor/the broker
from the declared Process, exactly as for any other Process.

The virtiofsd worker has:

- **Zero host capabilities** (`capabilityClasses: []`). All filesystem capabilities
  are scoped inside the user namespace (ADR 0021).
- **ProviderSupervisor-mediated, broker-pre-established user namespace**: the
  `system-minijail` Provider controller never calls the broker itself; it
  resolves `userNamespace.mappingClass: process-principal-root` through
  `ProcessLaunchEffectPort`, and ProviderSupervisor dispatches
  `clone3(CLONE_NEWUSER)` to the broker to write a single-entry UID/GID map
  (`in-NS 0 → stable principal UID`) before virtiofsd's first instruction
  runs. The mapping principal is `User/vol-<volume-name>-vfd` - a dedicated
  per-Volume User resource.
- **`--sandbox=chroot`**: permitted because `CAP_SYS_ADMIN` is available inside
  the user namespace.
- **`--inode-file-handles=never`**: `open_by_handle_at(2)` is not needed for
  read-only or per-VM share serving.
- **`--posix-acl --xattr`** only when the attachment `settings.posixAcl` or
  `settings.xattr` is true. These flags are omitted for the ro-store share
  because `/nix/store` has no ACLs and per-VM hardlink farms are d2b-managed.
- **`--readonly`** when `access: read-only` or when the backing Volume kind
  is `state/durable` and the View rights do not include `write`.
- **`--cache=<mode>`** from `settings.cache`, default `auto`.
- **`--thread-pool-size=<N>`** from resolved `settings.threadPoolSize` or
  the target Guest's vcpu count.
- The worker's own runtime/control state (export socket, control files) is a
  private runtime path under the Zone/Guest runtime root directory (not a
  Volume - see `path:vm-run:<vm>` in the current-code migration table),
  computed and handed to the worker only through its LaunchTicket. It is
  never an authored `mounts` entry and never a raw writable sandbox path.
- Read access to `/nix/store` for the virtiofsd binary's own execution is
  inherent to standard sandbox namespace inheritance; it is never an authored
  sandbox path list entry.

virtiofsd is NOT started as root (`startRoot: false`). It never holds
ambient host capabilities. Any change to the virtiofsd sandbox profile that
introduces host capabilities, `startRoot: true`, or `--sandbox=namespace`
violates ADR 0021. This invariant is tested by `tests/minijail-validator-virtiofsd.sh`
and enforced by the `tests/unit/nix/cases/broker-caps.nix` policy gate.

### Export status and Volume aggregation

volume-virtiofs writes status only on its Export:

```yaml
status:
  observedGeneration: 1
  phase: Ready
  resource:
    exportReady: true
    guestMountReady: true
    endpointRef: Endpoint/vol-work-state-virtiofsd-work-vm
  provider:
    providerRef: Provider/volume-virtiofs
    schemaId: volume-virtiofs.d2bus.org/Export/status
    schemaVersion: 1.0.0
    observedProviderGeneration: 1
    details:
      workerProcessRef: Process/vol-work-state-virtiofsd-work-vm
  conditions:
    - type: ExportReady
      status: "True"
      reason: socket-exists
      observedGeneration: 1
```

volume-local reads Export `status.resource` and alone writes the corresponding
Volume `status.resource.attachmentStatuses` entry. volume-virtiofs has read-only
access to the referenced Volume for view and Guest-vCPU resolution.

The virtiofsd export socket path is an internal implementation detail of
volume-virtiofs and is never exposed as a status field, spec field, or API surface.
Export readiness is detected by the Unix socket listener check (current:
`unix-socket-exists` readiness kind). Guest mount readiness is observed via the
guest-control health protocol.

## Store-view Volume

The per-VM closure-only Nix store hardlink farm is modeled as a Volume with
`Provider/volume-local`, `kind: durable`, and `source.settings.kind: local-path`
rooted at `$storeStateDir/<vm>/store-view`.

The store-view Volume is always owned by the Guest that uses it. Its attachment
has `transport: virtiofs`, `view: ro-store`, `access: read-only`, and
`mountPath: /nix/.ro-store` in the guest.

The Volume controller (or system-minijail broker, until volume-local is live)
enforces:

1. **Hardlink farm layout**: the `live/` subdirectory contains only hardlinks
   from the VM's Nix closure. It is never a direct bind of `/nix/store`.
   `share.source == "/nix/store"` is the eval-time sentinel that triggers
   store-view substitution; virtiofsd is pointed at `store-view/live`, not
   at `/nix/store`.
2. **Same-filesystem invariant**: hardlinks require `st_dev` equality between
   `/nix/store` and `$storeStateDir`. If they differ, the controller fails
   closed and reports `storage-drift` condition.
3. **Marker file**: `store-view/live/.d2b-marker-<vm>` is a zero-length file
   owned `d2bd:users 0444`, `invariants: [no-symlink, same-filesystem,
   hardlink-farm-no-recursion, broker-opaque-id-only]`. Its existence is
   checked by the virtiofsd readiness predicate before the virtiofsd worker
   is considered ready.
4. **Generation meta**: `store-view/meta/current` is a symlink (noFollow: false)
   pointing at `generations/<N>`. The current generation contains `system`,
   `store-paths`, `db.dump`, and `meta.json`. GC roots live in
   `store-view/gcroots/generation-<N>` (host-only, at store-view root; see
   spec correction below).
5. **State directory**: `store-view/state/` is a host-only directory that holds
   per-generation state entries (`state/generations/<id>/`). It is never served
   to the guest via virtiofsd.
5. **Sync lock**: `store-view/sync.lock` is a regular-file OFD advisory lock
   (`leaseClass: file-record`, owner `d2bd:users 0640`) used during store sync.
   It is never unlinked (preserves OFD semantics across controller restarts).
6. **Private mount namespace**: the broker performs the hardlink operation inside
   a private mount namespace where `/nix/store` is lazily detached from the
   bind-mount shadow, avoiding `EXDEV` from cross-vfsmount `link(2)`.
   A `EMLINK` fallback (saturated inode link count) copies the byte content.

### Store-view LayoutEntry rows

| Entry path (relative) | Type | Invariants | Notes |
| --- | --- | --- | --- |
| `` (root) | directory | no-symlink, scope-authorization-required | root: `d2bd:users 0755` |
| `live` | directory | no-symlink, broker-opaque-id-only | hardlink farm root; `never` cleanup |
| `live/.d2b-marker-<vm>` | file | no-symlink, same-filesystem, hardlink-farm-no-recursion, broker-opaque-id-only | zero-length readiness marker; `d2bd:users 0444` |
| `meta` | directory | no-symlink, same-filesystem, hardlink-farm-no-recursion, broker-opaque-id-only | generation meta tree; guest-served via virtiofsd |
| `meta/generations` | directory | no-symlink, same-filesystem, hardlink-farm-no-recursion, broker-opaque-id-only | never cleanup |
| `meta/current` | symlink | broker-opaque-id-only | noFollow: false; points at generations/<N> |
| `state` | directory | no-symlink, broker-opaque-id-only | host-only; NOT guest-served; `d2bd:users 0700`; holds `state/generations/<id>/` |
| `gcroots` | directory | no-symlink, same-filesystem, hardlink-farm-no-recursion, broker-opaque-id-only | host-only, at store-view root (NOT under `meta/`); never cleanup; `d2bd:users 0755` |
| `sync.lock` | file | no-symlink, broker-opaque-id-only | OFD lock; never unlink; leaseClass: none |

**Spec correction**: `nixos-modules/storage-json.nix` (baseline `b5ddbed6`) declares
`path:store-view-gcroots` at `store-view/meta/gcroots` and omits `store-view/state/`
entirely. `packages/d2b-host/src/hardlink_farm.rs::gcroots_dir()` places gcroots at
`store-view/gcroots` (store-view root), and `packages/d2b-priv-broker/src/ops/store_view_posture.rs`
confirms the broker posturas `state/`, `gcroots/`, `sync.lock` at root level. Code wins;
the v3 Volume LayoutEntry spec follows `hardlink_farm.rs`. `storage-json.nix` path drift
will be resolved when Volume resources replace the path rows.

## TPM Volume

The per-VM swtpm state directory is modeled as a Volume with `Provider/volume-local`,
`kind: state`, `source.settings.kind: local-path`, and root `$storeStateDir/<vm>/swtpm`.

Key invariants enforced by the volume-local controller (pre-v3: broker `swtpm_dir.rs`):

1. **Fail-closed owner**: any mismatch between declared ownerRef UID and `st_uid`
   fails closed with a typed, path-free error. The controller never silently
   chowns existing NVRAM.
2. **Provisioning marker**: `/var/lib/d2b/swtpm-markers/<vm>` is a root-owned
   regular file (`0600`, `invariants: [no-symlink, root-owned-parent,
   broker-opaque-id-only, scope-authorization-required]`). It records the trusted
   `st_dev`/`st_ino` plus first-provision stamp. If the swtpm directory is absent
   after the marker was written (`previously-provisioned-swtpm-state-missing`),
   the controller sets Failed and refuses to re-provision.
3. **Stale socket cleanup**: a stale `tpm.sock` under the runtime dir is unlinked
   before the swtpm Process is started. The socket path itself is not part of
   the TPM Volume layout; it belongs to the TPM Device Provider runtime.
4. **Sensitivity**: `sensitivity: secret-adjacent`. The swtpm state path must never
   appear in public status, audit, or log output.

TPM Volume layout entry:

```yaml
layout:
  - path: ""
    type: directory
    ownerRef: User/d2b-<vm>-swtpm    # stable UID mapped by User resource
    groupRef: User/d2b-<vm>-swtpm
    mode: "0700"
    createPolicy: create-if-never-provisioned
    repairPolicy: fail-closed
    cleanupPolicy: never
    adoptionPolicy: quarantine-on-ambiguity
    sensitivity: secret-adjacent
    invariants: [no-symlink, broker-opaque-id-only, scope-authorization-required]
```

## Volume status

### Three-layer status shape (D088)

D088 freezes `Volume` status as three layers. The universal `ResourceStatus`
base (Layer 1) lives at top-level `status` and owns `observedGeneration`,
`phase`, `conditions`, `lastReconciledAt`, `startedAt`, `completedAt`, and
bounded `outcome`. The `Volume`-specific status fields documented in this
section constitute the ResourceType-common `status.resource` (Layer 2) object
and never restate the universal base. Optional implementation-only observation
belongs in `status.provider` (Layer 3) with exactly `providerRef`, qualified
immutable `schemaId`, semver `MAJOR.MINOR` `schemaVersion`, numeric
`observedProviderGeneration`, and strict, bounded, redacted,
unknown-field-denied `details`. Generic API, CLI, and controllers MUST consume
only the base-only projection (`status` base plus `status.resource`).
Controllers MUST write all present layers atomically in one status mutation with
one expected revision. D087/D088 mapping is: shared observations go to
`status.resource`; implementation-specific bounded non-secret observations go to
`status.provider.details`; secret, large, or private observations go to an
optional Volume. D088 bounds apply: total status <= 64 KiB, `status.resource` <=
32 KiB, `status.provider.details` <= 32 KiB, 32 conditions, 64-entry lists/maps,
and 4 KiB strings; violations use `status-oversize`,
`status-provider-schema-invalid`, or `status-provider-overlap`.

Mapping convention: within this spec a reference to `status.<field>` denotes the ResourceType-common `status.resource.<field>` unless `<field>` is a universal base field (`observedGeneration`, `phase`, `conditions`, `lastReconciledAt`, `startedAt`, `completedAt`, `outcome`).

**D091 update currency.** Every Volume includes universal `status.update` with
`state` (`Current|UpdateAvailable|UpgradeRequired|Upgrading|Blocked|Unknown`),
`reasons`
(`CoreGenerationChanged|ProviderGenerationChanged|ArtifactChanged|ImageOrSystemGenerationChanged|SpecChanged|DependencyChanged|SecurityPolicyChanged`),
bounded non-secret observed/target generation and digest IDs, `disruption`
(`None|Reload|Restart|Recycle|Replace`), `preserveState`, optional
`operationId`, `lastAssessedAt`, and bounded/truncated `owned:{count,refs}` and
`dependencies:{count,refs}`. Volume-specific currency refinements live in
`status.resource` and never in `status.provider`; controllers set
`status.update` via `assess_update` on core/provider/artifact/spec/dependency/
security-policy triggers and MUST report `UpgradeRequired` for disruptive
changes rather than applying them in place. Durable/state Volumes report
`preserveState: true` across upgrades; disruption `Replace` is allowed only with
explicit state transfer.

`Provider/volume-local` is the single Volume implementation and status writer.
Attachment base status, layout phase/conditions, marker/invariant observations,
quota observations, and per-attachment readiness are frozen in
`status.resource`. volume-local aggregates per-attachment readiness from
provider-owned resources such as `virtiofs.d2bus.org.Export`; an attachment
Provider never writes the Volume row. Implementation-specific Export
observation belongs only in the Export's `status.provider.details`.

Common resource status plus:

| Field | Type | Notes |
| --- | --- | --- |
| `layoutPhase` | phase string | `Pending`, `Ready`, `Degraded`, `Failed` |
| `layoutConditions` | Condition[] | Per-entry condition types: `EntryMissing`, `EntryDrift`, `EntryQuarantined`, `InvariantViolated` |
| `attachmentStatuses` | AttachmentStatus[] | One per attachment; see per-attachment status above |

Condition message is bounded (512 bytes), UTF-8/control-character validated, and
must not contain host paths, secret content, process data, or terminal bytes.

Phase transitions:

```text
Pending → Ready
       → Degraded (recoverable drift or quarantine)
       → Failed   (fail-closed invariant, missing-after-provision)
       → Unknown  (controller/Host/link unreachable)
```

## Async reconciliation

Volume reconciliation follows the common reconciliation loop
(`ADR-046-resource-reconciliation`):

1. On Volume spec create/update, volume-local receives `spec-generation-changed`.
2. Controller reads current Volume spec and evaluates all layout entries.
3. For each entry, the controller resolves `ownerRef`/`groupRef` User UID/GID.
4. The controller calls `VolumeLayoutEffectPort` with the entry's declared
   policy; ProviderSupervisor dispatches the layout operation
   (create/repair/cleanup/adopt) to the broker via a bounded broker operation
   with a path-free audit record. The controller itself never imports or
   calls the broker.
5. Controller writes status batch with expected revision; conflict → re-read/retry.
6. volume-local translates every virtiofs attachment into one
   `virtiofs.d2bus.org.Export` owned by the Volume and diffs that Export set on
   attachment changes.
7. volume-virtiofs receives Export reconcile hints and emits or updates the
   Export-owned virtiofsd Process and Endpoint.
8. volume-virtiofs observes those children and writes Export status; volume-local
   reads Export status and writes aggregated Volume attachment status.
9. On Volume deletion, volume-local requests deletion of every owned Export.
   Each Export drains its volume-virtiofs finalizer and children before
   volume-local clears the Volume attachment finalizer and proceeds to layout
   cleanup.

Owner triggers: every Volume spec/status/finalizer mutation produces a
`owned-resource-changed` hint for the Volume's `ownerRef` (typically a Guest).
The Guest controller relist and re-asserts the full child graph.

External drift observation: volume-local declares a bounded observe interval
(default 60 s) for durable/state Volumes, querying entry owner/mode/invariants.
Ephemeral/tmp Volumes observe only on start.

## Volume ownership, sharing, and finalizers

### Ownership

A Volume may have `metadata.ownerRef` pointing to a Host, Guest, or another
Volume (nested). Owner deletion orders the Volume's finalization first.

A Volume without an ownerRef is standalone; it persists until explicitly deleted.

### Sharing

Multiple Processes may mount the same Volume (with potentially different Views).
Multiple Guests may receive the same Volume via multiple attachments. At most one
attachment may use `access: read-write` at any time; the controller enforces the
single-writer constraint and rejects a second `read-write` attachment while one is
active. Multiple simultaneous writers require `access: shared-write` on all
writer attachments; the Provider must declare `supportsSharedWrite: true` in its
capabilities and is responsible for write-ordering semantics.

A Volume may not be owned by two separate resources simultaneously (singular
ownerRef). Unrelated consumers use ordinary `volumeRef` without ownership.

### Finalizers

volume-local adds finalizer `volume-local.d2bus.org/layout` when any layout entry has
`cleanupPolicy != never`. It is cleared after cleanup completes or is skipped.

volume-local adds `volume-local/virtiofs-attachments` to the Volume while any
owned Export exists. volume-virtiofs adds `volume-virtiofs.d2bus.org/export` only to each
Export; it clears that finalizer after the Export-owned Process and Endpoint are
deleted and the guest mount is confirmed absent. Once every Export is deleted,
volume-local clears the Volume attachment finalizer.

### Snapshots and migrations

Volume snapshot and storage-content migration operations are modeled as
EphemeralProcess resources owned by the Volume and surfaced through the resource
API. They are not CLI-only jobs. The `volume-local` Provider exposes snapshot
and migration operations as EphemeralProcess templates in its Provider catalog.
Current baseline has no evidence for these operations; ADR046-volume-005 carries
the implementation work item.

## RBAC

Standard resource verbs apply. Typical Role rules:

```yaml
# Zone controller creating Volumes
rules:
  - resourceTypes: [Volume]
    verbs: [create, update-spec, update-status, update-finalizers, get, list, watch]
    zones: [dev]

# Guest Provider reading/mounting volumes
rules:
  - resourceTypes: [Volume]
    verbs: [get, list, watch]
    zones: [dev]
    executionRefs: [Guest/work-vm]

# Process mounting (read-only)
rules:
  - resourceTypes: [Volume]
    verbs: [get]
    zones: [dev]
```

No subject may write spec for a Volume they do not own. Status may be written only
by the current controller lease for the declared `providerRef`. The
`sourcePolicyId` field in `source.settings` is an opaque ID; resolving it to an
actual host path is rejected for any caller without the
`volume-local/source-policy-resolve` permission claim, which authorizes only a
`VolumeSourceEffectPort` call. This permission is granted only to
ProviderSupervisor acting on behalf of `Provider/volume-local`'s controller
process - never to the controller process performing the resolution itself.

## Security invariants

1. **No raw host path in public surface**: `source.settings` never carries a
   raw host path field; it carries only the opaque `sourcePolicyId`, which
   never appears in resource list/watch responses, status, audit records,
   error messages, CLI output, or telemetry. The controller reads the ID once
   from spec and calls `VolumeSourceEffectPort` to resolve it to a validated
   FD; subsequent broker operations use the FD, never a path.
2. **Anchored relative paths**: all layout entry paths are validated as
   relative, non-absolute, with no `..` component, no drive letter, and no null
   byte. The validator rejects Unicode homoglyphs of path separator characters.
3. **noFollow default true**: symlink traversal in layout operations is disabled
   by default. Only `symlink`-type entries with explicit `noFollow: false` may
   traverse.
4. **Broker-opaque-id-only**: entries with this invariant reject children created
   by non-broker actors. This prevents arbitrary file injection into controlled
   subtrees (swtpm state, store-view, lock files).
5. **No recursive mutation without explicit flag**: `recursive: false` is the
   default. Enabling recursion for large trees (store-view) is rejected unless
   the entry is explicitly declared with `recursive: true` and `repairPolicy`
   is `exact-owner` or `fail-closed`.
6. **ADR 0021 virtiofsd invariant**: every virtiofsd worker process must declare
   `capabilityClasses: []` and `startRoot: false`. A policy test rejects any
   virtiofsd Profile that includes a non-empty capability set or a true
   `startRoot`. `--sandbox=namespace` is never emitted.
7. **TPM never re-provisioned**: after the swtpm provisioning marker exists,
   a missing or replaced swtpm directory is a hard failure. The controller never
   silently creates a new empty TPM directory.
8. **Store isolation**: virtiofsd serving `access: read-only` for the ro-store
   attachment always uses `store-view/live` as `--shared-dir`, never the host's
   `/nix/store`. `share.source == "/nix/store"` is the compile-time sentinel only.

## Audit and redaction

Volume audit records include:

- subject/Zone
- `Volume/<name>` reference (never spec body)
- verb: `create`, `update-spec`, `update-status`, `delete`
- expected/current/result revision
- authorization outcome
- operation/correlation ID

Excluded from audit: `source.settings.sourcePolicyId`, entry paths, ACL grant
values, layout entry content, virtiofsd socket paths, secret-adjacent entry
paths, guest mount paths, process data, terminal bytes, credential material.

Broker path-free audit ops (current: `PrepareSwtpmDir`):

| Op | Fields logged |
| --- | --- |
| `ProvisionLayoutEntry` | Volume UID, entry type, owner UID digest (not path) |
| `RepairLayoutEntry` | Volume UID, entry type, repair action class |
| `CleanupLayoutEntry` | Volume UID, entry type, cleanup trigger |
| `PrepareSwtpmDir` | VM UID, result class (provisioned/reconciled/quarantined) |
| `VirtiofsdLaunch` | Volume UID, attachment executionRef digest |
| `StoreSyncComplete` | Volume UID, generation number |

## Provider dossiers

> **Workspace policy**: every `packages/d2b-provider-<base>-<implementation>/` crate must contain
> `src/`, `tests/`, `integration/`, and `README.md`. Missing any path fails the workspace/package
> policy gate. `src/` owns implementation binaries and colocated unit tests. `tests/` owns hermetic
> Cargo integration, ResourceType/controller/conformance, and fault tests. `integration/` owns
> heavier container/Host/Guest/cross-process/provider-system fixtures and scenarios invoked by
> existing test orchestration. `README.md` documents Provider identity, config schema, ResourceTypes,
> controllers/services/workers/binaries, placement, dependencies/RBAC, security/state/telemetry,
> build/test/integration commands, and future standalone-repo usage.

Neither `volume-local` nor `volume-virtiofs` declares a Provider state Volume:
their bounded non-secret operational state (reconcile stage, per-attachment
readiness, adoption observations, last-successful checkpoints) lives in the
owning resource's `status` subresource and the core Operation ledger (D087),
and per-Volume provisioning markers for `state`-kind Volumes are broker-
maintained outside any Volume tree. Their `ProviderStateSet` is therefore
empty. The "State" rows below describe the ResourceType-owned data each
Provider keeps - in resource status and the layout it manages for *other*
Providers' declared Volumes - not a state Volume of its own.
`ProviderStateSet` is an optional query-time grouping of a Provider's declared
Volumes, not a separate stored artifact, and it never duplicates the resource
store's own authority over layout/attachment status.

### Provider/volume-local

| Field | Value |
| --- | --- |
| Crate | `packages/d2b-provider-volume-local/` |
| ResourceTypes | Volume (layout + views; no attachment transport) |
| Source kinds | `local-path`, `block-image`, `tmpfs` |
| Controller component | `volume-local-controller`; Process under Host/system-core |
| Broker ops (dispatched via `VolumeLayoutEffectPort`/ProviderSupervisor, never called by the Provider process itself) | `ProvisionLayoutEntry`, `RepairLayoutEntry`, `CleanupLayoutEntry`, `StoreSyncComplete`, `PrepareSwtpmDir` |
| State | Volume's own layout root; per-Volume provisioning marker for `state` kind |
| Permissions | `volume-local/source-policy-resolve` (authorizes only a `VolumeSourceEffectPort` FD resolution call); never ambient path access; never a broker import in the Provider process |
| Finalizers | `volume-local.d2bus.org/layout` |
| Supported Host capabilities | Local NixOS Host; bare-metal; ACA if filesystem is accessible |
| Supported Guest capabilities | Not applicable (volume-local does not attach to Guests) |
| Required crate layout | `src/` (controller, broker op adapters, layout engine, store_view.rs, swtpm_volume.rs, colocated unit tests); `tests/` (hermetic: layout provision/repair/cleanup/adopt, store-view invariants, ACL reconciliation, swtpm fail-closed, quota enforcement, block-image lifecycle, tmpfs mount/unmount, symlink target validation, foreignChildPolicy preserve/fail); `integration/` (container fixtures: Host path access, store-view FS boundary enforcement, quota FS fixture, swtpm marker, block-image virtio-blk attachment); `README.md` (identity, allowedHostPaths config schema, owned ResourceTypes, broker op catalogue, placement, deps/RBAC, security invariants, state/telemetry, build/test/integration commands) |

volume-local is the sole reconciler of every other Provider's *declared*
optional state Volume, but it declares no state Volume of its own. Because the
first `volume-local-controller` instance on each execution target keeps its
bounded non-secret operational state in `status`/the core Operation ledger and
declares no state Volume, no component needs a Volume before that instance is
Ready - so there is no bootstrap state-Volume cycle, no per-execution-target
local bootstrap storage mechanism, and no bootstrap-storage exception (D086,
superseded by D087; see "No bootstrap state Volume" in
`ADR-046-components-processes-and-sandbox`). A Guest bootstraps its own
Guest-local `volume-local` instance without any parent-Host dirfd or resource
handle, and that instance reaches Ready from Guest-local primitives and its own
status alone. Every Provider's declared state Volume - on any target - is
provisioned only through the normal Core ProviderDeployment → volume-local
create/reconcile path.

volume-local controller reconcile flow:

1. Resolve `source.settings.sourcePolicyId` by calling `VolumeSourceEffectPort`;
   ProviderSupervisor validates it against the private allowlist policy and
   returns an `OwnedFd`. The controller never opens the host path itself and
   never sees the raw path.
2. For each layout entry (topological order, parent before child):
   a. Resolve `ownerRef`/`groupRef` → UID/GID from User resource.
   b. Call `VolumeLayoutEffectPort.provision`/`.repair`; ProviderSupervisor
      dispatches the corresponding broker `ProvisionLayoutEntry` or
      `RepairLayoutEntry` op based on `createPolicy`/`repairPolicy`.
   c. Apply and continuously reconcile ACLs if `accessAcl` or `defaultAcl` is non-empty; enforce `foreignChildPolicy` (`preserve` or `fail`) for directory children not covered by declared ACL entries.
3. Check store-view specific invariants (marker, sync.lock) if `kind: durable`
   and `source.settings.kind: local-path` with storeView mode.
4. Write status batch with layout conditions.

### Provider/volume-virtiofs

| Field | Value |
| --- | --- |
| Crate | `packages/d2b-provider-volume-virtiofs/` |
| ResourceTypes | `virtiofs.d2bus.org.Export`; read-only watch of Volume |
| Attachment transport | `virtiofs` |
| Controller component | `volume-virtiofs-controller`; Process under Host |
| Worker binary | `virtiofsd` (upstream Rust virtiofsd from `pkgs/virtiofsd/`) |
| Worker Process template | `virtiofsd-worker` |
| Owned Process naming | `vol-<volume-name>-virtiofsd-<guest-name>`; ownerRef is the Export |
| Broker ops (dispatched via `ProcessLaunchEffectPort`/`VolumeSourceEffectPort`/ProviderSupervisor, never called by the Provider process itself) | `SpawnRunner` (virtiofsd), `VirtiofsdLaunch`, `ProvideFdToWorker` |
| State | Per-attachment virtiofsd export socket (boot-scoped; path is a private implementation detail of volume-virtiofs; never exposed in spec/status/API) |
| Permissions | `volume-virtiofs/spawn-virtiofsd` (authorizes only a `ProcessLaunchEffectPort` call); receives source Volume FD from volume-local via ProviderSupervisor, never a direct cross-Provider or broker call |
| Finalizers | `volume-virtiofs.d2bus.org/export` on Export only |
| Required crate layout | `src/` (Export controller, virtiofsd argv generation, Export lifecycle, socket readiness, ADR 0021 semantic conformance validation, colocated unit tests); `tests/` (hermetic: argv golden/pinned vectors, ADR 0021 invariant rejection, Export create/ready/delete lifecycle, read-only flag per access mode, multi-Export isolation, socket path never-in-status invariant, no Volume mutation); `integration/` (container fixtures: virtiofsd launch, guest-mount readiness, Export finalizer drain under Guest restart); `README.md` (identity, virtiofsd argv options, owned ResourceTypes, ADR 0021 invariant summary, socket path privacy contract, placement, deps/RBAC, security invariants, state/telemetry, build/test/integration commands) |

virtiofsd argv shape (baseline: `packages/d2b-host/src/virtiofsd_argv.rs`):

```
virtiofsd
  --socket-path=<controller-generated private path under Zone runtime directory>
  --socket-group=<resolved gid>
  --shared-dir=<volume-root-fd-path>
  --thread-pool-size=<N>
  --sandbox=chroot
  --inode-file-handles=never
  --cache=<mode>
  [--posix-acl]   # only if settings.posixAcl
  [--xattr]       # only if settings.xattr
  [--readonly]    # only if access: read-only
  [<extra-args>]  # Provider root config only; empty by default
```

The virtiofsd worker is tested by:

- `packages/d2b-host/src/virtiofsd_argv.rs` (14 unit tests; golden/pinned/argv.txt)
- `tests/tools/gen-migration-ledger.sh` → `virtiofsd-argv-shape` gate
- `tests/tools/gen-migration-ledger.sh` → `minijail-validator-virtiofsd` gate
- `tests/unit/smoke/smoke-eval-tpm.nix` (swtpm ordering only)

## Current-code fit

| Item | Evidence class | Treatment |
| --- | --- | --- |
| `packages/d2b-core/src/storage.rs`: `StorageJson`, `StoragePathSpec`, all policy enums (`CleanupPolicy`, `RepairPolicy`, `StorageRestartPolicy`, `StorageAdoptionPolicy`, `LeaseClass`, `SensitivityClass`, `StorageInvariant`, `StoragePathKind`, `PrincipalRef`, `ActorRef`, `AclGrant`) | `generated-or-eval-contract` | Extract and adapt to Volume LayoutEntry; enum values preserved with renames where noted |
| `packages/d2b-core/src/sync.rs`: `SyncJson`, `LockSpec` | `generated-or-eval-contract` | OFD lock rows become Volume layout entries with `leaseClass: file-record`; per-process advisory lock semantics preserved |
| `packages/d2b-core/src/storage_lifecycle.rs`: `StorageLifecycleReport`, `StorageLifecycleIssue`, `StorageContractValidationReason`, `SyncContractValidationReason` | `implemented-and-reachable` | Daemon startup lifecycle report; migrated to Volume controller phase/condition reporting |
| `packages/d2b-core/src/processes.rs`: `VmProcessDag`, `ProcessRole::Virtiofsd`, `ProcessRole::Swtpm`, `ProcessRole::CloudHypervisorRunner` | `generated-or-eval-contract` | `ProcessRole::Virtiofsd` → v3 Process resource template `virtiofsd-worker` owned by an Export and reconciled by volume-virtiofs; `VmProcessDag` → per-Guest set of Process resources |
| `packages/d2b-realm-core/src/ids.rs`: `RealmId`, `WorkloadId`, `NodeId`, `ProviderId` (newtype label-validated types) | `implemented-and-reachable` | Current identifier layer; maps to Zone/Guest/Provider `<ResourceType>/<name>` ResourceRef in v3 |
| `packages/d2b-realm-core/src/workload.rs`: `WorkloadId`, `WorkloadProviderKind` (LocalVm/QemuMedia/ProviderManaged/UnsafeLocal), `IsolationPosture`, `WorkloadExecutionPosture` | `implemented-and-reachable` | Current VM/workload classification layer; LocalVm/QemuMedia → Guest (VirtualMachine isolation); ProviderManaged → Guest under Provider; UnsafeLocal → user-only Host under Provider/system-core |
| `nixos-modules/storage-json.nix` (1086 lines): all path rows with `scope:"vm:<vm>"`/`scope:"host"`, owner, mode, cleanup/repair/restart/adoption/lease/sensitivity/invariants | `generated-or-eval-contract` | Each path row maps to a Volume LayoutEntry or a non-Volume host path (see migration table below); `scope:"vm:<vm>"` → `ownerRef: Guest/<vm>` |
| `nixos-modules/store.nix`: per-VM hardlink farm activation, private-NS sync algorithm | `generated-or-eval-contract` | Extracted to volume-local store-view mode; sync algorithm and private-mount-NS invariant preserved |
| `packages/d2b-host/src/hardlink_farm.rs`: `build_store_view`, `build_farm`, `GenerationMarker`, `BuildStoreViewRequest`, `gcroots_dir`, `state_dir`, `meta_dir`, `live_dir`, `sync_lock_path`, `generation_id` | `implemented-and-reachable` | Canonical store-view layout implementation; confirms `gcroots/` and `state/` at store-view root (not under `meta/`); marker is zero-length; migrates to volume-local store-view mode |
| `packages/d2b-priv-broker/src/ops/storage_contract.rs`: `reconcile_storage_scope`, `validate_lock_spec`, `validate_storage_scope` | `implemented-and-reachable` | Live broker handler; accepts only opaque BundleOpId; resolves path/owner/mode from broker's trusted bundle; path-hash in errors (never raw path); migrates to volume-local broker ops |
| `packages/d2b-priv-broker/src/ops/store_sync.rs`: `run_store_sync`, `run_store_sync_repair`, `StoreSyncOutcome`, `cleanup_store_view`, `prune_gcroots` | `implemented-and-reachable` | Live StoreSync broker op; calls `d2b_host::hardlink_farm`; confirms gcroots at store-view root; migrates to volume-local `StoreSyncComplete` broker op |
| `packages/d2b-priv-broker/src/ops/store_sync_audit.rs`, `store_sync_export.rs`: audit fields and export wire | `implemented-and-reachable` | Co-located with `store_sync.rs`; migrate to volume-local audit/export ops |
| `packages/d2b-priv-broker/src/ops/store_view_posture.rs`: `posture_store_view_matrix_paths`, `plant_live_marker_with_matrix_posture` | `implemented-and-reachable` | No-recursion posture for `state/`, `gcroots/`, `sync.lock` at store-view root; hardlink-farm-no-recursion invariant enforced here; migrates to volume-local repair policy |
| `packages/d2b-priv-broker/src/ops/state_dir.rs`: `PrepareStateDir`, `PrepareRuntimeDir`, `PrepareDirRequest`, `DirKind` | `implemented-and-reachable` | Broker op that fchown/fchmod per-VM state/runtime dirs without ambient path traversal; migrates to volume-local `ProvisionLayoutEntry` op |
| `packages/d2b-priv-broker/src/ops/swtpm_dir.rs`: swtpm provisioning, fail-closed marker, reconcile-in-place, ancestor traverse ACL, `seccomp_policy_ref: "w1-swtpm"` | `implemented-and-reachable` | Migrated to volume-local `create-if-never-provisioned` + fail-closed repair for TPM Volume |
| `packages/d2b-host/src/virtiofsd_argv.rs`: `VirtiofsdArgvInput`, `generate_virtiofsd_argv` (14 unit tests, golden `argv.txt` lines 166-184) | `implemented-and-reachable` | Extracted to volume-virtiofs virtiofsd-worker template; all 14 existing tests migrated |
| `nixos-modules/minijail-profiles.nix`: `virtiofsdProfiles`; principal `d2b-<vm>-runner` (normal shares); principal `d2b-<vm>-gctlfs` (d2b-gctl share); exception `"ADR 0021 v1.1.1fu14 virtiofsd fake-root via broker pre-established user NS"` | `generated-or-eval-contract` | Becomes virtiofsd worker sandbox spec; ADR 0021 invariants preserved; principal names → `User/<name>` ResourceRef (typed ResourceRef only; no numeric form) |
| `nixos-modules/processes-json.nix`: `virtiofsdRunner` shape; `roStoreSharedDir` redirect sentinel `share.source == "/nix/store"` → `store-view/live` | `generated-or-eval-contract` | Replaced by an Export-owned Process resource reconciled by volume-virtiofs; store-view/live redirect preserved |
| `packages/d2bd/src/supervisor/dag.rs`: virtiofsd `VmProcessDag` node supervised as `ProcessRole::Virtiofsd` dag entry under a WorkloadId (current `d2b-realm-core::WorkloadId`-keyed dag) | `implemented-and-reachable` | Replaced by Process controller lifecycle in v3 |
| `packages/d2b-contract-tests/tests/storage_sync_contracts.rs`: `storage_and_sync_emitters_are_wired_into_private_bundle`, `broker_storage_and_sync_requests_stay_opaque_only`, `host_mutation_sources_are_registered_with_storage_or_sync_policy`, `tmpfiles_host_mutable_paths_are_covered_by_storage_contract_roots` | `implemented-and-reachable` | Live gate asserting storage.json/sync.json bundle wiring and opaque-id contract; adapted to Volume resource parity gate in v3 |
| `tests/unit/nix/cases/per-vm-state-ownership.nix` | `implemented-and-reachable` | Adapted to v3 Volume LayoutEntry matrix |
| `tests/unit/smoke/smoke-eval-tpm.nix` | `implemented-and-reachable` | Migrated to volume-local TPM Volume conformance test |

### Current storage.json path rows → Volume migration

| Current id prefix | Current path | v3 Volume | Notes |
| --- | --- | --- | --- |
| `path:etc-root` | `/etc/d2b` | Not a Volume (config root; Nix activation) | Remains in system-core Host activation |
| `path:state-root` | `$stateDir` | Not a Volume (host tree root) | system-core Host state root |
| `path:run-root` | `/run/d2b` | Not a Volume (host runtime root) | system-core Host runtime root |
| `path:daemon-state` | `$stateDir/daemon-state` | Not a Volume (daemon internal) | d2bd internal state; Zone store replaces |
| `path:run-locks` | `/run/d2b/locks` | Not a Volume | system-core bootstrap path |
| `path:run-locks-usbip` | `/run/d2b/locks/usbip` | Device Provider state | device-usbip Provider owns |
| `path:vm-state:<vm>` | `$storeStateDir/<vm>` | Volume root for per-Guest state | Guest owns as Volume with `kind: state` |
| `path:vm-run:<vm>` | `/run/d2b/vms/<vm>` | Zone/Guest runtime root directory; not a Volume | system-core Host runtime path; volume-virtiofs stores export sockets here as a private implementation detail |
| `path:store-view:<vm>` | `$storeStateDir/<vm>/store-view` | `Volume/store-view-<vm>` root | volume-local, kind: durable |
| `path:store-view-live:<vm>` | `.../store-view/live` | LayoutEntry `live` | never, broker-opaque-id-only |
| `path:store-view-marker:<vm>` | `.../store-view/live/.d2b-marker-<vm>` | LayoutEntry `live/.d2b-marker-<vm>` | zero-length file, hardlink-farm invariants |
| `path:store-view-meta:<vm>` | `.../store-view/meta` | LayoutEntry `meta` | same-filesystem, hardlink-farm; guest-served |
| `path:store-view-generations:<vm>` | `.../store-view/meta/generations` | LayoutEntry `meta/generations` | same |
| _(absent from storage-json.nix)_ | `.../store-view/state` | LayoutEntry `state` | host-only state dir; present in `hardlink_farm.rs::state_dir()`; see spec correction |
| `path:store-view-gcroots:<vm>` | `.../store-view/meta/gcroots` _(storage-json.nix)_ | LayoutEntry `gcroots` at store-view root | **Spec correction**: `hardlink_farm.rs::gcroots_dir()` places gcroots at `store-view/gcroots`, NOT `meta/gcroots`; code wins |
| `path:store-view-current:<vm>` | `.../store-view/meta/current` | LayoutEntry `meta/current` | symlink, noFollow: false |
| `path:store-sync-lock:<vm>` | `.../store-view/sync.lock` | LayoutEntry `sync.lock` | file, leaseClass: none (OFD) |
| `path:swtpm-state:<vm>` | `$storeStateDir/<vm>/swtpm` | `Volume/swtpm-<vm>` root | volume-local, kind: state, secret-adjacent |
| `path:swtpm-marker:<vm>` | `$stateDir/swtpm-markers/<vm>` | LayoutEntry in swtpm-markers host path | volume-local or system-core path |
| `path:vm-audio-state-dir:<vm>` | `$storeStateDir/<vm>/state` | LayoutEntry in Guest state Volume | audio-pipewire Provider mounts view |
| `path:vm-audio-state-file:<vm>` | `.../state/audio-state.json` | LayoutEntry file in Guest state Volume | same |
| `path:vm-audio-lock:<vm>` | `/run/d2b/locks/audio-<vm>.lock` | OFD lock file in Zone runtime; LayoutEntry with `leaseClass: file-record`; path not exposed in spec/status | audio-pipewire Provider owns |

sync.json lock rows migrate to Volume LayoutEntry `leaseClass: file-record` entries
or to controller-internal OFD locks not exposed as Volume resources.

## Nix configuration

> **Note**: The Nix option namespace `d2b.zones.<zone>` shown below is the
> **v3 ADR-only target API** - it does not exist in the current baseline
> (`b5ddbed6`). Current Nix API uses `d2b.vms.<vm>` (options-vms.nix) and
> `d2b.realms.<realm>` (options-realms.nix). The v3 resource compiler
> (ADR046-volume-004) emits Volume resource JSON from an evolved Nix surface.

### Resource shape

All resources - Volume, Provider, Credential, User, Guest, Host - use one
uniform Nix shape that mirrors the canonical ResourceSpec JSON nearly identically:

```nix
d2b.zones."<zone>".resources."<name>" = {
  type = "<ResourceType>";   # required; matches canonical spec
  spec = {
    # exact ResourceType spec fields - same keys and nesting as canonical JSON
  };
  # Optional authoritative metadata fields:
  # metadata.ownerRef = "ResourceType/name";   # authoritative ownership
  # metadata.labels   = { key = "value"; };    # optional presentation
  # metadata.annotations = { key = "value"; }; # optional presentation
  # Derived (not authored): metadata.name, metadata.zone, apiVersion
  # Omitted (read-only / core-managed): status, UID, generation, revision,
  #   timestamps, managedBy, configurationGeneration
};
```

Nix option types, defaults, and docs for `spec.*` are generated from the same
ResourceTypeSchema JSON the runtime uses. Build validation compares the canonical
rendered JSON against the schema - there is no second bespoke Nix vocabulary and
Provider-specific fields are never renamed or renested. The Zone self-resource is
runtime-created with `spec = {}`; it is not authored through Nix. Child resources
live under `d2b.zones."<zone>".resources.*`.

### Artifact catalog

Derivation-valued inputs - Provider binaries, NixOS system images, and other
executables - are registered in a separate global artifact catalog, not inside
any ResourceSpec. ResourceSpecs use plain bounded IDs to reference artifacts.
`Artifact` is not a ResourceType; `artifactId` is not a `*Ref` field.

```nix
# Artifact catalog - derivations and their type/trust metadata live here only.
# Store paths are private catalog implementation data; they never appear in any
# resource spec, status field, or audit record.
d2b.artifacts."volume-local-provider" = {
  package = pkgs.d2b-provider-volume-local;
  type = "provider";
};

d2b.artifacts."volume-virtiofs-provider" = {
  package = pkgs.d2b-provider-volume-virtiofs;
  type = "provider";
};
```

The Nix build validates the catalog: each entry must have a unique ID, a valid
`type`, and a trusted derivation. The build emits a private integrity-pinned
artifact catalog mapping each ID to its type, digest, and closure metadata.
Store paths are used only at activation time by the runtime; they never flow
into resource specs, status objects, or audit records.

### Provider installation

Both volume Providers must be installed as Provider resources in the Zone. The
`spec.artifactId` field is a plain bounded string matching a catalog entry with
`type = "provider"`. No derivation appears in the ResourceSpec.

```nix
d2b.zones."dev".resources."volume-local" = {
  type = "Provider";
  spec = {
    artifactId = "volume-local-provider";   # must exist in d2b.artifacts with type = "provider"
    config = {
      # Root config validated against volume-local's signed root-config.schema.json.
      # Each entry's "id" is the opaque value a Volume references via
      # source.settings.sourcePolicyId. Raw prefixes are resolved only inside
      # ProviderSupervisor's private VolumeSourceEffectPort adapter state; the
      # Provider controller itself never opens these paths directly.
      allowedHostPaths = [
        { id = "state-root";     prefix = config.d2b.site.stateDir;  volumeKinds = [ "durable" "state" "cache" ]; }
        { id = "ephemeral-root"; prefix = "/run/d2b";                volumeKinds = [ "ephemeral" "tmp" ]; }
      ];
      # No secrets in Provider root config; any credential must use Credential refs.
    };
  };
};

d2b.zones."dev".resources."volume-virtiofs" = {
  type = "Provider";
  spec = {
    artifactId = "volume-virtiofs-provider";  # must exist in d2b.artifacts with type = "provider"
    config = {};   # no root config; per-attachment settings come from Volume spec
  };
};
```

### Volume resource configuration - minimal state Volume

```nix
d2b.zones."dev".resources."work-state" = {
  type = "Volume";
  spec = {
    providerRef = "Provider/volume-local";
    source = {
      executionRef = "Host/host-system";
      settings = {
        kind = "local-path";
        sourcePolicyId = "state-root";
        # sourcePolicyId references the matching "id" in volume-local's
        # allowedHostPaths config; the operator authors only the opaque ID.
        # The raw prefix is resolved solely inside the private effect-adapter
        # state and never appears in public status.
      };
    };
    kind = "state";
    layout = [
      {
        path = "";
        type = "directory";
        ownerRef = "User/d2b-work-vm-runner";
        groupRef = "User/d2b-work-vm-runner";
        mode = "0700";
        sensitivity = "private";
        createPolicy = "create-if-never-provisioned";
        repairPolicy = "fail-closed";
        cleanupPolicy = "never";
      }
    ];
    views.controller = {
      path = "";
      rights = [ "read" "write" "create" "delete" "traverse" ];
    };
    attachments = [
      {
        executionRef = "Guest/work-vm";
        transport = "virtiofs";
        view = "controller";
        access = "read-write";
        mountPath = "/state";
      }
    ];
  };
};
```

### Canonical ResourceSpec JSON

The Nix resource compiler emits one canonical JSON object per Volume with
all fields normalized, defaults applied, and unknown fields absent. The example
above renders as:

```json
{
  "apiVersion": "resources.d2bus.org/v3",
  "type": "Volume",
  "metadata": {
    "name": "work-state",
    "zone": "dev",
    "ownerRef": null,
    "finalizers": []
  },
  "spec": {
    "providerRef": "Provider/volume-local",
    "source": {
      "executionRef": "Host/host-system",
      "settings": { "kind": "local-path", "sourcePolicyId": "state-root" }
    },
    "kind": "state",
    "layout": [
      {
        "path": "",
        "type": "directory",
        "ownerRef": "User/d2b-work-vm-runner",
        "groupRef": "User/d2b-work-vm-runner",
        "mode": "0700",
        "sensitivity": "private",
        "createPolicy": "create-if-never-provisioned",
        "repairPolicy": "fail-closed",
        "cleanupPolicy": "never",
        "adoptionPolicy": "adopt-with-live-owner-proof",
        "restartPolicy": "preserve-across-controller-restart",
        "leaseClass": "none",
        "noFollow": true,
        "recursive": false,
        "foreignChildPolicy": "preserve",
        "accessAcl": [],
        "defaultAcl": [],
        "invariants": ["no-symlink"]
      }
    ],
    "views": {
      "controller": {
        "path": "",
        "rights": ["create", "delete", "read", "traverse", "write"]
      }
    },
    "attachments": [
      {
        "executionRef": "Guest/work-vm",
        "transport": "virtiofs",
        "view": "controller",
        "access": "read-write",
        "mountPath": "/state",
        "settings": {
          "cache": "auto",
          "inodeFileHandles": "never",
          "posixAcl": false,
          "socketGroup": null,
          "threadPoolSize": null,
          "xattr": false
        }
      }
    ],
    "quota": null
  }
}
```

Rights are sorted lexicographically. All keys are sorted. Defaults are always
present. `sourcePolicyId` is a plain opaque bounded string in the emitted
JSON, exactly like any other spec field; there is no raw `hostPath` field,
injected or otherwise - a raw host path never exists anywhere in the Volume
ResourceSpec, envelope JSON, or emitted bundle.

### Nix eval/build validation

Every Volume resource is fully validated during NixOS eval (before `nix build`).
A failed assertion emits a structured `throw` that includes the Volume name,
field path, and error class - never host paths or secret values.

Validation steps in order:

1. **providerRef resolution**: `Provider/<name>` must appear as a resource of type `Provider` in `d2b.zones.<zone>.resources`.
2. **executionRef resolution**: `Host/<name>` or `Guest/<name>` must appear in `d2b.zones.<zone>.resources.*`.
3. **Provider artifact resolution**: the Provider resource's `spec.artifactId` must appear in `d2b.artifacts` with `type = "provider"`. A missing or wrong-type `artifactId` aborts the build; the error names the Provider resource and the missing/mismatched catalog ID.
4. **Volume source base schema**: `source.settings` is validated as part of the exact Volume base spec schema version and fingerprint implemented by the selected Provider's `ResourceApiBinding`. These source fields are ResourceType-common base fields, not Provider-specific settings. A constraint failure aborts the build; the error includes the base schema version and violated constraint, not the field value.
5. **Layout bounds**: ≤ 1024 entries; path uniqueness (no duplicates or overlaps); each path is relative, contains no `..` components, no leading `/`, no null bytes, no Unicode path-separator homoglyphs.
6. **Layout entry ownerRef/groupRef**: each `User/<name>` must appear as a resource of type `User` in `d2b.zones.<zone>.resources`.
7. **symlink target validation**: every entry with `type = "symlink"` must declare `target`; target is validated as a relative path with no `..` and no leading `/`; target path must resolve to a path under the Volume root.
8. **ACL principal validation**: every `accessAcl`/`defaultAcl` principal `ref` must be a `User/<name>` resolving to a configured User; bare numeric forms abort.
9. **Views bounds**: ≤ 64 Views; ViewName matches `^[a-z][a-z0-9-]*$`.
10. **Attachment bounds**: ≤ 64 attachments; each attachment `executionRef` resolves; each `view` name exists in the Volume's `views`; at most one `read-write` attachment; `shared-write` only if Provider declares `supportsSharedWrite: true`.
11. **block-image quota**: `source.settings.kind == "block-image"` requires `quota.maxBytes != null`.
12. **tmpfs quota**: `source.settings.kind == "tmpfs"` requires `quota.maxBytes != null` and `quota.maxInodes != null`.
13. **Attachment base schema**: every attachment `settings` object is validated by the Volume base spec schema. The typed virtiofs and virtio-blk mount options are ResourceType-common base fields; genuinely implementation-only desired settings belong only in the canonical `spec.provider.settings` envelope.
14. **Credential refs**: no secret values (raw keys, passwords, tokens) appear in Volume spec. If a future layout entry requires a secret (e.g., an encrypted-at-rest key), it must use `credentialRef: Credential/<name>`.
15. **Conflict detection**: two `local-path`/`block-image` Volumes bound to the
    same `sourcePolicyId` root may not declare overlapping resolved subtrees.
    The Nix resource compiler checks the set of all resolved host paths across
    Volumes in the Zone - using the private `allowedHostPaths` catalog entry
    each `sourcePolicyId` resolves to, never a spec-authored path - and aborts
    the build on overlap.

All validation errors are fatal and prevent `nix build`. They produce a structured JSON error block written to stderr, never to a path.

### Integrity-pinned Zone resource bundle

The Nix build emits one sorted, integrity-pinned Zone resource bundle per
NixOS generation:

```json
{
  "schemaVersion": 3,
  "bundleVersion": 1,
  "zone": "dev",
  "contentHash": "sha256:<64 lowercase hex over sorted canonical resources array>",
  "artifactCatalogDigest": "sha256:<64 lowercase hex>",
  "generatedAt": "1970-01-01T00:00:00.000Z",
  "resources": [
    { "apiVersion": "resources.d2bus.org/v3", "type": "Provider",
      "metadata": { "name": "volume-local", "zone": "dev" },
      "spec": { "artifactId": "volume-local-provider", "config": {} } },
    { "apiVersion": "resources.d2bus.org/v3", "type": "Provider",
      "metadata": { "name": "volume-virtiofs", "zone": "dev" },
      "spec": { "artifactId": "volume-virtiofs-provider", "config": {} } },
    { "apiVersion": "resources.d2bus.org/v3", "type": "User",
      "metadata": { "name": "d2b-work-vm-runner", "zone": "dev" }, "spec": { } },
    { "apiVersion": "resources.d2bus.org/v3", "type": "Volume",
      "metadata": { "name": "store-view-work-vm", "zone": "dev" }, "spec": { } },
    { "apiVersion": "resources.d2bus.org/v3", "type": "Volume",
      "metadata": { "name": "work-state", "zone": "dev" }, "spec": { } }
  ],
  "providerSchemaDigests": {
    "Provider/volume-local": "sha256:<64 lowercase hex>",
    "Provider/volume-virtiofs": "sha256:<64 lowercase hex>"
  }
}
```

The canonical bundle field set, digest preimages, and the four-member digest
chain are frozen in `ADR-046-nix-configuration` ("Zone resource bundle" and
"Digest chain"); this section does not restate or fork them. The block above
shows only the Volume-related entries as they appear inside the single
canonical `resources` array.

Resources are sorted by `(type, name)` lexicographically. The bundle
`contentHash` is the SHA-256 over that sorted canonical `resources` array (the
top-level `contentHash`, `artifactCatalogDigest`, and `generatedAt` fields are
excluded from the preimage); it is the generation identity. There is no
per-resource digest field and no separate `bundleDigest`/`resourceOrder` member:
the sorted array is self-ordering and the `contentHash` covers every resource
body. The configuration publication handler verifies `contentHash` and
`artifactCatalogDigest` before activation and rejects any modified or
partially-applied bundle.

The full resource JSON bodies are embedded inline in the `resources` array. When
core activates the bundle it sets `metadata.managedBy = "configuration"` and
`metadata.configurationGeneration = <runtime ordinal>` (the monotonic ordinal
the Zone daemon assigns at activation, recorded in its durable generation
record, not the bundle `contentHash`) on each activated resource. These are the
authoritative markers for configuration-owned resources; there is no
`configOwned` field in the bundle.

### Store-view Volume (Nix resource compiler output)

```nix
# Generated automatically per Guest; not written by operators
d2b.zones."dev".resources."store-view-work-vm" = {
  type = "Volume";
  spec = {
    providerRef = "Provider/volume-local";
    source = {
      executionRef = "Host/host-system";
      settings.kind = "local-path";
      settings.sourcePolicyId = "state-root";
      # Resolves via ProviderSupervisor's private VolumeSourceEffectPort
      # adapter state to "<storeStateDir>/work-vm/store-view"; the raw path
      # is never written to this spec by the compiler or the operator.
    };
    kind = "durable";
    layout = [
      { path = ""; type = "directory"; ownerRef = "User/d2bd"; groupRef = "User/users"; mode = "0755"; }
      { path = "live"; type = "directory"; invariants = [ "no-symlink" "broker-opaque-id-only" ]; cleanupPolicy = "never"; repairPolicy = "exact-owner"; ownerRef = "User/d2bd"; groupRef = "User/users"; mode = "0755"; }
      { path = "live/.d2b-marker-work-vm"; type = "file"; ownerRef = "User/d2bd"; groupRef = "User/users"; mode = "0444"; invariants = [ "no-symlink" "same-filesystem" "hardlink-farm-no-recursion" "broker-opaque-id-only" ]; repairPolicy = "exact-owner"; }
      { path = "meta"; type = "directory"; invariants = [ "no-symlink" "same-filesystem" "hardlink-farm-no-recursion" "broker-opaque-id-only" ]; repairPolicy = "exact-owner"; ownerRef = "User/d2bd"; groupRef = "User/users"; mode = "0755"; }
      { path = "meta/generations"; type = "directory"; invariants = [ "no-symlink" "same-filesystem" "hardlink-farm-no-recursion" "broker-opaque-id-only" ]; cleanupPolicy = "never"; repairPolicy = "exact-owner"; ownerRef = "User/d2bd"; groupRef = "User/users"; mode = "0755"; }
      { path = "meta/current"; type = "symlink"; target = "generations/0"; noFollow = false; invariants = [ "broker-opaque-id-only" ]; cleanupPolicy = "never"; repairPolicy = "exact-owner"; ownerRef = "User/d2bd"; groupRef = "User/users"; mode = "0777"; }
      { path = "state"; type = "directory"; invariants = [ "no-symlink" "broker-opaque-id-only" ]; repairPolicy = "exact-owner"; ownerRef = "User/d2bd"; groupRef = "User/users"; mode = "0700"; }  # host-only; NOT guest-served
      { path = "gcroots"; type = "directory"; invariants = [ "no-symlink" "same-filesystem" "hardlink-farm-no-recursion" "broker-opaque-id-only" ]; cleanupPolicy = "never"; repairPolicy = "exact-owner"; ownerRef = "User/d2bd"; groupRef = "User/users"; mode = "0755"; }  # at store-view root, NOT under meta/
      { path = "sync.lock"; type = "file"; ownerRef = "User/d2bd"; groupRef = "User/users"; mode = "0640"; leaseClass = "none"; invariants = [ "no-symlink" "broker-opaque-id-only" ]; restartPolicy = "preserve-across-controller-restart"; }
    ];
    views = {
      ro-store = { path = "live"; rights = [ "read" "traverse" ]; };
      meta = { path = "meta"; rights = [ "read" "traverse" ]; };
    };
    attachments = [
      {
        executionRef = "Guest/work-vm";
        transport = "virtiofs";
        view = "ro-store";
        access = "read-only";
        mountPath = "/nix/.ro-store";
        settings = { posixAcl = false; xattr = false; cache = "auto"; inodeFileHandles = "never"; };
      }
    ];
  };
};
```

## Cleanup contract

> Generic bundle lifecycle (non-blocking activation, `metadata.managedBy`,
> `configurationGeneration`, generation retention count) is specified in the Zone
> resource API spec. This section covers Volume-specific finalizer behavior,
> status, and tests only.

### Configuration-owned vs controller-created

A Volume's resource row carries `metadata.managedBy = "configuration"` and
`metadata.configurationGeneration = <generationId>` when it was created or last
updated by the configuration publication handler activating a Nix-emitted bundle.
Core sets these fields at activation time.

A Volume is **configuration-owned** if its resource row has
`metadata.managedBy = "configuration"`. It is **controller-created** if a
running controller created it (e.g., a Provider creating a nested Volume); such
rows carry `metadata.managedBy = "controller"` with the controller identity tracked
separately as an internal field.

The configuration handler manages the lifecycle of configuration-owned Volumes
only. It never issues Delete for controller-created Volumes in response to a
Nix generation change. Owner controllers handle their own children as their
parent resource changes.

### Removed Volume lifecycle

When a Volume is absent from the new Nix generation but its resource row carries
`metadata.managedBy = "configuration"` at the prior generation:

1. The configuration handler issues a normal async `Delete` for the Volume
   (sets `deletionRequestedAt`).
2. The Volume's phase becomes `Degraded` with a condition:
   ```yaml
   type: ConfigurationRemoved
   status: "True"
   reason: absent-from-configuration
   message: "Volume removed from Nix generation; pending finalizer drain"
   ```
3. volume-local requests Delete for every Export owned by the Volume and marks
   the corresponding aggregated attachment status `detaching`.
4. For each Export, volume-virtiofs deletes the Export-owned virtiofsd Process
   and Endpoint, confirms guest-mount absence, clears
   `volume-virtiofs.d2bus.org/export`, and allows the Export row to be deleted.
5. After every Export is gone, volume-local clears
   `volume-local/virtiofs-attachments` and executes layout cleanup per each
   entry's `cleanupPolicy`. Entries with `cleanupPolicy: never` are preserved.
   Entries with `cleanupPolicy: boot` or
   `cleanupPolicy: process-exit-with-proof` are removed.
6. When all finalizers drain, the resource-store transaction writes an
   event-only `Deleted` revision and removes the row and index atomically.
   The audit subsystem appends the deletion audit record afterward, using a
   dedup/exactly-once recovery key so a retried recovery never produces a
   duplicate audit entry.
7. Prior generation retention is governed by the Zone's `retainedGenerations`
   (default 3, range 1..16). No time-based TTL applies.

### Guest/Process children during Volume cleanup

When a Volume is being deleted:
- The Guest that used the Volume (via attachment) receives an
  `owned-resource-changed` trigger when the attachment `state` changes to
  `detaching`.
- The Guest controller reconciles: it marks its own status as Degraded if the
  Volume was required (`optional: false` in the Process mount).
- If a Process had the Volume mounted, the Process Provider (system-minijail/
  system-systemd) detects mount failure at the next health check or is notified
  via the Volume attachment status, and sets the Process phase to Failed/Degraded.
- Controller-created children (snapshot EphemeralProcess etc.) owned by the
  Volume receive Delete through the normal owner-child finalizer flow before
  the Volume itself is deleted.

### Controller-created resources are not touched by config cleanup

If a Volume's spec removes an attachment while the Volume remains in Nix,
volume-local deletes only the corresponding controller-created Export.
volume-virtiofs then drains that Export's Process and Endpoint children. The
configuration handler does not touch any of those controller-created resources.

A controller-created Volume has `metadata.managedBy = "controller"` and is
invisible to the configuration cleanup pass regardless of whether the new
generation bundle includes it.

### Prior generation retention

The Zone retains the last `retainedGenerations` prior generations (default 3,
range 1..16). Within the retained set, an operator may reactivate any prior
generation:
- The configuration handler re-activates the prior bundle (atomic single Zone
  revision) via `ActivateGeneration`.
- Resources absent from the new generation but present in the prior one (currently
  being deleted) have their `deletionRequestedAt` cleared if they have not yet
  reached `phase: Deleted`.
- Resources added by the aborted new generation receive Delete.
- Reactivation is non-blocking and follows the same activation flow.

When the retained count is exceeded the oldest generation's bundle record is
pruned from the store with a tamper-evident audit record. Pruning removes only
that historical bundle record. It never force-clears an undrained resource
finalizer: a resource that has not completed deletion remains in its current
non-terminal phase (Pending or Degraded) indefinitely, exactly as it would
outside a generation-retention prune, until its owning Provider controller
drains the outstanding effects/children and clears the finalizer through the
normal deletion flow.

### Status, errors, and audit for cleanup

Volume status during cleanup:

```yaml
status:
  phase: Degraded
  conditions:
    - type: ConfigurationRemoved
      status: "True"
      reason: absent-from-configuration
      observedGeneration: 4
    - type: FinalizersBlocked
      status: "False"
      reason: finalizers-draining
  attachmentStatuses:
    - executionRef: Guest/work-vm
      state: detaching
      exportReady: false
      guestMountReady: false
```

Audit record on removed-resource Delete:

```json
{
  "subject": "configuration-publication-handler",
  "zone": "dev",
  "verb": "delete",
  "resourceRef": "Volume/work-state",
  "triggerGenerationId": "<new bundle generationId>",
  "priorGenerationId": "<prior bundle generationId>",
  "reason": "absent-from-configuration",
  "outcome": "delete-requested",
  "correlationId": "<opaque>"
}
```

No host paths, secret content, spec body, or layout entry paths appear in the
audit record.

### Tests for removed-resource cleanup

| Test | Layer | Coverage |
| --- | --- | --- |
| `volume_removed_from_nix_generation_receives_async_delete` | unit (configuration handler) | Configuration-owned delete path |
| `controller_created_volume_not_deleted_by_config_change` | unit (configuration handler) | `managedBy` authority; controller-created invisible to cleanup |
| `volume_cleanup_does_not_block_new_generation_ready` | integration | Non-blocking activation |
| `volume_finalizer_drain_order_virtiofs_before_local` | integration | Child-first finalizer order |
| `volume_cleanup_never_policy_preserves_entries` | integration | `cleanupPolicy: never` honored |
| `prior_generation_reactivation_cancels_in_flight_delete` | integration | Generation reactivation |
| `config_owned_volume_with_controller_children_cleans_children_first` | integration | Owner-child flow |
| `cleanup_audit_record_contains_no_host_paths` | unit (audit) | Redaction |
| `guest_phase_degraded_when_required_volume_detaching` | integration | Guest response to Volume detach/deletion |
| `volume_status_degraded_with_configuration_removed_condition` | unit (status) | Status shape during cleanup |

## Implementation work items

### ADR046-volume-001

| Field | Value |
| --- | --- |
| Dependency/owner | W0 shared contract root; `d2b-contracts` |
| Current source | `packages/d2b-core/src/storage.rs`, `sync.rs`; `nixos-modules/storage-json.nix` |
| Reuse action | adapt |
| Destination | `packages/d2b-contracts/src/v3/volume.rs`, `volume_layout.rs`, `volume_attachment.rs` |
| Detailed design | Complete Volume ResourceSpec, LayoutEntry, all policy enums (values preserved from baseline), AclGrant, ViewSpec, AttachmentSpec, quota placeholder, strict serde unknown-field rejection, canonicalization, bounds Primary reuse disposition: `adapt`. Preserved source-plan detail: extract and adapt. |
| Integration | Provider dossiers/controller descriptors bind exact types; Nix resource compiler emits canonical JSON |
| Data migration | Full d2b 3.0 reset; storage.json rows migrated per table above |
| Validation | Golden JSON spec vectors; serde unknown-field; path anchor/depth/traversal validators; ACL grant bounds; policy enum coverage |
| Removal proof | `d2b-core/src/storage.rs` and `sync.rs` removed only after all Volume-successor consumers are live |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-volume-002

| Field | Value |
| --- | --- |
| Dependency/owner | ADR046-volume-001; volume-local Provider owner |
| Current source | `nixos-modules/storage-json.nix`, `nixos-modules/store.nix`, `packages/d2b-priv-broker/src/ops/swtpm_dir.rs`, `packages/d2b-priv-broker/src/ops/storage_contract.rs` (`reconcile_storage_scope`, `validate_lock_spec`), `packages/d2b-priv-broker/src/ops/store_sync.rs` (`run_store_sync`, `run_store_sync_repair`, `cleanup_store_view`, `prune_gcroots`), `packages/d2b-priv-broker/src/ops/store_sync_audit.rs`, `packages/d2b-priv-broker/src/ops/store_sync_export.rs`, `packages/d2b-priv-broker/src/ops/store_view_posture.rs` (`posture_store_view_matrix_paths`, `plant_live_marker_with_matrix_posture`), `packages/d2b-priv-broker/src/ops/state_dir.rs` (`PrepareStateDir`, `PrepareRuntimeDir`), `packages/d2b-host/src/hardlink_farm.rs` (`build_store_view`, `GenerationMarker`, `gcroots_dir`, `state_dir`), `packages/d2b-core/src/storage_lifecycle.rs` (`StorageLifecycleReport`, `StorageLifecycleIssue`), `packages/d2b-contract-tests/tests/storage_sync_contracts.rs`, `packages/d2bd/src/ownership_preflight.rs` |
| Reuse action | adapt |
| Destination | `packages/d2b-provider-volume-local/src/` (layout engine, store_view.rs, swtpm_volume.rs, broker op adapters); `packages/d2b-provider-volume-local/tests/` (hermetic layout/store-view/swtpm tests); `packages/d2b-provider-volume-local/integration/` (container Host-path and store-view FS fixtures); `packages/d2b-provider-volume-local/README.md` |
| Detailed design | volume-local controller: layout engine (provision/repair/cleanup/adopt per policy), store-view mode (hardlink farm from `hardlink_farm.rs`, private-NS sync, zero-length marker, `gcroots/` and `state/` at store-view root, `sync.lock` OFD), swtpm volume hardening (provisionIfNeverProvisioned + marker + fail-closed repair as in `swtpm_dir.rs`), path-free broker audit ops, storage lifecycle report, opaque BundleOpId contract preserved from `storage_contract.rs` Primary reuse disposition: `adapt`. Preserved source-plan detail: extract and adapt. |
| Integration | volume-local controller registered under Host/system-core; resource status written via ResourceClient |
| Data migration | Per-VM `storage.json` rows (scoped `"vm:<vm>"` → `ownerRef: Guest/<vm>`) replaced by Volume resources generated by Nix resource compiler; broker continues to own path operations |
| Validation | `tests/unit/nix/cases/per-vm-state-ownership.nix` adapted to Volume LayoutEntry matrix; `tests/unit/smoke/smoke-eval-tpm.nix` migrated to TPM Volume invariant; `d2b-contract-tests/tests/storage_sync_contracts.rs` parity tests adapted; new: store-view same-filesystem, zero-length marker existence, sync.lock preserve-OFD, gcroots at store-view root (not meta/), state/ dir existence, swtpm fail-closed-on-missing-after-provision, anchored-path validators |
| Removal proof | `nixos-modules/storage-json.nix` removed only after Volume resources replace all path rows and all consumers verified |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-volume-003

| Field | Value |
| --- | --- |
| Dependency/owner | ADR046-volume-001; volume-virtiofs Provider owner |
| Current source | `packages/d2b-host/src/virtiofsd_argv.rs` (`VirtiofsdArgvInput`, `generate_virtiofsd_argv`), `nixos-modules/minijail-profiles.nix` (virtiofsdProfiles; principals `d2b-<vm>-runner`, `d2b-<vm>-gctlfs`), `nixos-modules/processes-json.nix` (virtiofsdRunner shape; `roStoreSharedDir` sentinel), `packages/d2b-core/src/processes.rs` (`ProcessRole::Virtiofsd`, `VmProcessDag`; the virtiofsd dag node is a `ProcessRole::Virtiofsd` entry in a WorkloadId-keyed `VmProcessDag`), `packages/d2b-priv-broker/src/ops/spawn_runner.rs` (`SpawnRunnerPlan` for virtiofsd; current `SpawnRunnerPlanInput` carries `adr_carve_out` for virtiofsd swtpm path), `packages/d2b-priv-broker/src/sys.rs` (clone3/user-NS pre-establishment), ADR 0021 |
| Reuse action | adapt |
| Destination | `packages/d2b-provider-volume-virtiofs/src/` (controller, virtiofsd_argv.rs); `packages/d2b-provider-volume-virtiofs/tests/` (hermetic argv/lifecycle/ADR-0021 tests); `packages/d2b-provider-volume-virtiofs/integration/` (virtiofsd launch and guest-mount fixtures); `packages/d2b-provider-volume-virtiofs/README.md` |
| Detailed design | volume-virtiofs controller owns `virtiofs.d2bus.org.Export` lifecycle and status, reads the referenced Volume without mutation, and creates/updates/deletes the Export-owned virtiofsd Process and Endpoint; argv generation reuses the current 14 tests; ADR 0021 invariant (`capabilityClasses: []`, `startRoot: false`, `sandbox: chroot`, user-NS via `userNamespace.mappingClass: process-principal-root`); per-Export socket readiness check (`unix-socket-exists` readiness kind; current v2 socket path: `/run/d2b/vms/<vm>/<vm>-virtiofs-<tag>.sock`; v3: stable hash-derived private path under Zone runtime directory, never exposed in spec/status/API); guest-mount status observation; `volume-virtiofs.d2bus.org/export` finalizer drain. volume-local remains the sole Volume writer and translates Volume attachments to Exports. Primary reuse disposition: `adapt`. Preserved source-plan detail: extract and adapt. |
| Integration | volume-virtiofs registered under Host; volume-local creates one Export per virtiofs attachment; virtiofsd Process and Endpoint resources are owned by the Export; guest-control health integration feeds Export status, which volume-local aggregates into Volume status |
| Data migration | Current `processes-json.nix` virtiofsd `VmProcessDag` nodes (keyed by `WorkloadId` = current VM name, role `ProcessRole::Virtiofsd`) are replaced by Export-owned virtiofsd Process resources |
| Validation | Migrated `virtiofsd_argv` unit tests (14 tests); `tests/tools/gen-migration-ledger.sh` virtiofsd-argv-shape gate adapted; `minijail-validator-virtiofsd` gate adapted to Process sandbox spec; new: attachment lifecycle (create/ready/delete), ADR 0021 invariant rejection test, multi-attachment isolation, readOnly flag per access mode, store-view shared-dir = store-view/live (never /nix/store) |
| Removal proof | `nixos-modules/processes-json.nix` virtiofsdRunner block removed only after virtiofsd Process resources pass parity; `packages/d2bd/src/supervisor/dag.rs` `ProcessRole::Virtiofsd` path removed after controller lifecycle covers all cases |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-volume-004

| Field | Value |
| --- | --- |
| Dependency/owner | ADR046-volume-001; Nix integrator |
| Current source | `nixos-modules/storage-json.nix`, `nixos-modules/store.nix`, `nixos-modules/options-vms.nix` (`d2b.vms.<vm>.*` - current VM Nix option namespace; virtiofs shares and TPM enable are configured here), `nixos-modules/options-realms-workloads.nix` (`d2b.realms.<realm>.stateDir` - current realm workload state root), `packages/d2b-realm-core/src/workload.rs` (`WorkloadProviderKind::LocalVm`/`QemuMedia`/`UnsafeLocal` - informs which WorkloadIds need store-view Volumes vs. no Volume) |
| Reuse action | adapt |
| Destination | `nixos-modules/resources-volume.nix`, `nixos-modules/options-volumes.nix` |
| Detailed design | Nix resource compiler for Volume/LayoutEntry/View/Attachment from d2b.zones config; strict schema validation; emit canonical JSON per Volume; generate store-view Volume per Guest (from current `d2b.vms.<vm>` → future flat `d2b.zones.<zone>.resources.<name>` with `type = "Guest"`) with hardlink-farm layout (gcroots/, state/ at root per `hardlink_farm.rs`); generate swtpm Volume for TPM-enabled Guests; emit provider-neutral Volume attachment entries per virtiofs share, which volume-local translates to runtime Export resources; migration: store-view stateDir root configuration |
| Integration | `nixos-modules/default.nix` wires resources-volume.nix; Nix evaluation tests verify canonical output |
| Data migration | `d2b.vms.<vm>.shares` (virtiofs entries) → Volume attachments; `d2b.vms.<vm>.tpm.enable` → swtpm Volume |
| Validation | nix-unit cases for store-view Volume output (gcroots at root), TPM Volume spec, virtiofs attachment spec, anchored-path rejection; render parity with current storage.json path rows; canonical JSON golden vector; Provider schema validation rejection; symlink target validation; bundle digest coverage |
| Removal proof | Old `storage-json.nix` and `store.nix` emitters removed only after rendered Volume JSON passes all drift-check gates |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-volume-005

| Field | Value |
| --- | --- |
| Dependency/owner | ADR046-volume-002, ADR046-volume-003; respective Provider owners |
| Current source | N/A (no baseline evidence for block-image, quota enforcement, snapshots, or tmpfs Volume paths) |
| Reuse action | create |
| Destination | `packages/d2b-provider-volume-local/src/` (block-image, quota, snapshots, tmpfs, ACL reconciliation, single-writer admission and Export translation); `packages/d2b-provider-volume-local/tests/` (hermetic quota/tmpfs/ACL/block-image/snapshot/single-writer tests); `packages/d2b-provider-volume-local/integration/` (block-image virtio-blk, FS-without-quota fixture, tmpfs memory-budget, shared-write admission fixture); `packages/d2b-provider-volume-virtiofs/src/` (Export reconciliation and private socket path contract); `packages/d2b-provider-volume-virtiofs/tests/` (Export lifecycle, read-only projection, socket-path invariant, no Volume mutation); `packages/d2b-provider-volume-virtiofs/integration/` (Export-owned worker fixture) |
| Detailed design | (1) **block-image SourceKind**: add `SourceKind::BlockImage` to volume-local; manage raw/qcow2 image file lifecycle; emit virtio-blk attachment spec consumed by Guest Provider; `quota.maxBytes` required; add store-overlay.img migration path for current `DiskInit` plan-op. (2) **Quota hard enforcement**: implement `enforcement: hard` capability check in volume-local at Volume creation time; query backing FS for quota/limits support; test with no-project-quota fixture; enforce `maxBytes`/`maxInodes` via xfs project quota or ext4 per-dir quota where available. (3) **Volume snapshots/migrations**: design and implement EphemeralProcess templates in volume-local catalog for snapshot (copy-on-write or rsync capture) and content migration (atomic rename + sync); no CLI-only path; all operations surface through resource API. (4) **Single-writer enforcement**: volume-local checks the desired Export set while translating Volume attachments and rejects a second `read-write` Export before creation (`ResourceConflict`); `shared-write` mode is accepted only if the selected attachment Provider declares `supportsSharedWrite: true`. volume-virtiofs only enforces its Export spec and never writes Volume. (5) **tmpfs source**: implement tmpfs mount/unmount lifecycle in volume-local; `maxBytes` → `size=`, `maxInodes` → `nr_inodes=` mount options; charge memory against Host/Guest budget; cleanup unmounts on Volume deletion or restart. (6) **Bounds enforcement**: enforce max 1024 layout entries, 64 Views, 64 attachments at schema validation layer; add corresponding row to API request-size limit table in `ADR-046-resource-api-and-authorization`. (7) **File/symlink first-class lifecycle**: implement independent `createPolicy`/`repairPolicy`/`cleanupPolicy` for `file` and `symlink` entries; implement `target` field validation (relative, no `..`, must resolve within Volume root); `symlink` create writes the target link. (8) **ACL principal ResourceRef**: remove bare `{type,ref}` struct from AclGrant; implement `User/<name>` ResourceRef resolution with User resource watch and re-reconcile on User revision change. (9) **Continuous ACL reconciliation**: implement `foreignChildPolicy: preserve|fail` in broker reconcile loop; re-apply `accessAcl`/`defaultAcl` to all existing entries and children on every repair cycle; emit `ForeignAclViolation` condition when `foreignChildPolicy: fail` and unexpected entries found. (10) **virtiofsd socket path contract**: implement stable hash-derived private socket path in volume-virtiofs (deterministic hash of Zone name + Volume name + attachment executionRef); assert path never appears in public status, spec, audit, or CLI output; validate with a dedicated security invariant test. |
| Integration | Each sub-item produces a focused spec amendment; resolved decisions already reflected in spec revision 2 |
| Data migration | Per-sub-item; block-image and tmpfs are new capabilities with no legacy migration required |
| Validation | (1) `VirtioblkArgvInput` unit tests; block-image integration fixture. (2) Quota-enforcement fixture with FS-without-quota; hard-enforcement failure test. (3) EphemeralProcess snapshot lifecycle test; content-migration parity test. (4) Single-writer rejection test; shared-write capability gate test. (5) tmpfs mount/unmount lifecycle test; memory-budget accounting assertion. (6) Schema bound rejection tests (1025 entries, 65 views, 65 attachments). (7) File/symlink independent lifecycle tests; target validation (absolute rejected, `..` rejected, escape rejected). (8) ACL principal ResourceRef validation; numeric form rejected; User revision trigger test. (9) foreignChildPolicy preserve/fail tests; continuous repair cycle test. (10) Socket path invariant test; no-status-leak assertion. |
| Removal proof | None - net-new capabilities; no prior owner to remove |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-volume-006

| Field | Value |
| --- | --- |
| Dependency/owner | ADR046-volume-001, ADR046-volume-004; Nix integrator and core-controller config-publication owner |
| Current source | `nixos-modules/storage-json.nix` (current Nix eval-time validation via `lib.asserts`; schema checked by `d2b-contract-tests/tests/storage_sync_contracts.rs`); `packages/d2bd/src/` (current config activation / host-prepare dispatch) |
| Reuse action | create |
| Destination | `nixos-modules/resources-volume.nix` (Nix eval-time schema validation, canonical JSON emission, bundle digest); `packages/d2b-core-controller/src/configuration.rs` (config-publication handler cleanup logic); `packages/d2b-contracts/src/v3/zone_bundle.rs` (bundle index schema) |
| Detailed design | **Nix eval/build validation**: implement all 15 validation steps in §Nix eval/build validation as Nix assertions; abort build on any failure with structured error (Volume name + field path + error class); provider-specific settings schema (`root-config.schema.json`, `attachment.schema.json`) read from the private artifact catalog entry for each Provider's `artifactId` by the resource compiler; validate against `lib.evalModules`-compatible schema; emit canonical sorted JSON with all defaults materialized; emit Zone resource bundle with `contentHash` over the sorted `resources` array and `artifactCatalogDigest` anchoring the site artifact catalog (no per-resource `digest` and no separate `bundleDigest`). **Config-publication handler cleanup**: on new bundle activation, diff resources with `metadata.managedBy = "configuration"` between new and prior bundle; issue async Delete for resources absent from new bundle; mark deleted resources with `ConfigurationRemoved` condition; track pending-cleanup set in Zone status; Zone status is `Degraded/PendingCleanup` while prior-generation deletions are in progress; activation is immediate but Zone readiness reflects cleanup completion. **Config-owned vs controller-created distinction**: `metadata.managedBy = "configuration"` is the authoritative marker set by core at activation; the bundle carries full resource envelopes with no per-resource digest member; controller-created resources have `metadata.managedBy = "controller"` and are never touched by the configuration cleanup pass. **Prior generation retention**: retain `retainedGenerations` prior generations (default 3, range 1..16); no time-based TTL; when count is exceeded prune oldest generation from the store with a tamper-evident audit record. **Generation reactivation**: re-activate any retained prior bundle via `ActivateGeneration` operation; cancel in-flight Deletes for resources being reinstated; issue Deletes for resources added by the aborted new generation. |
| Integration | `nixos-modules/default.nix` wires resources-volume.nix; `d2b-core-controller` config-publication handler consumes the bundle; all Volume controllers observe `ConfigurationRemoved` condition and respond to finalizer triggers |
| Data migration | Full d2b 3.0 reset; no partial import of prior generation state |
| Validation | Tests per §Cleanup contract - Tests for removed-resource cleanup table (10 tests); nix-unit: `volume_canonical_json_golden_vector`, `volume_bundle_digest_covers_all_resources`, `provider_schema_validation_rejects_unknown_fields`, `symlink_target_escape_rejected_at_eval`, `tmpfs_without_quota_rejected_at_eval`, `layout_bounds_1025_entries_rejected`, `attachment_bounds_65_rejected`, `conflicting_host_paths_rejected`; integration: cleanup audit redaction, generation reactivation, prior-generation pruning |
| Removal proof | Old `storage-json.nix` schema assertions removed only after Nix eval-time Volume validation covers all prior `lib.asserts` paths; old config-activation code in `d2bd` removed after config-publication handler is live |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |
