# ADR 0046 Provider dossier: volume-virtiofs

| Field | Value |
| --- | --- |
| Spec ID | `ADR-046-provider-volume-virtiofs` |
| Parent | ADR 0046 |
| Status | Accepted |
| Version | 2 |
| Baseline | `b5ddbed67867d9244bf33390868101bd9b053e49` |
| Normative | Yes |
| Owners | `d2b-provider-volume-virtiofs` crate, volume-virtiofs controller, virtiofsd worker, Export lifecycle |
| Depends on | `ADR-046-resources-volume`, `ADR-046-provider-model-and-packaging`, `ADR-046-components-processes-and-sandbox`, `ADR-046-provider-state`, `ADR-046-componentsession-and-bus`, `ADR-046-resource-api-and-authorization`, `ADR-046-resource-reconciliation`, `ADR-046-nix-configuration`, `ADR-046-telemetry-audit-and-support`, `ADR-046-resources-host-guest-process-user` |
| Supersedes | `nixos-modules/processes-json.nix` virtiofsdRunner block; `nixos-modules/minijail-profiles.nix` virtiofsdProfiles; `packages/d2b-host/src/virtiofsd_argv.rs`; `ProcessRole::Virtiofsd` dag nodes in `packages/d2bd/src/supervisor/dag.rs` |
| ADR 0021 | Accepted invariant; fully governs virtiofsd sandbox; no exception or partial closure permitted |

---

## 1. Purpose

This dossier exhaustively specifies `Provider/volume-virtiofs` - the d2b v3 controller that
declares and reconciles `virtiofs.d2bus.org.Export` resources and owns every virtiofsd worker
Process. It is the authoritative reference for:

- the crate/package/provider identity and required crate layout;
- the `virtiofs.d2bus.org.Export` ResourceType owned by this Provider;
- the controller component descriptor and watch plan;
- the virtiofsd worker Process template (owned by Export);
- the ADR 0021 broker-pre-established user-namespace invariant, enforced in full;
- zero host capability classes and `startRoot: false`;
- the `--sandbox=chroot` / `--inode-file-handles=never` / `--readonly` argv contract;
- per-Export status, guest-mount readiness, export-socket privacy;
- the store-view farm attachment;
- Export lifecycle creation and deletion;
- Nix authoring, canonical ResourceSpec JSON, eval/build validation, and cleanup;
- d2b-bus access and RBAC;
- status/errors/audit/telemetry/performance budgets;
- exact implementation work items, test file layout, and removal proofs.

`Provider/volume-virtiofs` reconciles `virtiofs.d2bus.org.Export` resources only. It does not
reconcile Volume resources directly. `Provider/volume-local` controls Volume resources
(one controller per resource type). volume-local translates each
`Volume.spec.attachments[transport=virtiofs]` entry into one owned Export resource;
volume-virtiofs reconciles Export resources and creates the virtiofsd Process per Export;
volume-local reads Export.status to aggregate `Volume.status.attachmentStatuses`.

Layout provisioning, ACL reconciliation, store management, and single-writer admission belong
to `Provider/volume-local`.

---

## 2. Crate and package identity

| Field | Value |
| --- | --- |
| Crate path | `packages/d2b-provider-volume-virtiofs/` |
| Crate name | `d2b-provider-volume-virtiofs` |
| Provider resource name | `Provider/volume-virtiofs` |
| `artifactId` key | `volume-virtiofs-provider` |
| Package type | `provider` |
| ResourceTypes declared | `virtiofs.d2bus.org.Export` (full attachment lifecycle owner) |
| ResourceTypes consumed/managed | `Volume` (read-only; status aggregated from Export), `Process` (create/delete worker), `Endpoint` (create/delete exported endpoint child) |
| Attachment transports owned | `virtiofs` |
| Dependencies | `d2b-contracts` (v3 Export/Process/Volume types), `d2b-provider-toolkit` (ResourceClient, reconciler, fake seams), `d2b-session`, `d2b-bus`, `d2b-audit`, `d2b-telemetry` |
| Prohibited imports | `d2bd`, `d2b-priv-broker` internals, `d2b-provider-volume-local`, any other Provider's implementation |

**D089 desired-spec shape.** `Provider/volume-virtiofs` owns the
`virtiofs.d2bus.org.Export` ResourceType base spec; base fields include
`spec.providerRef`, `volumeRef`, `executionRef`, `view`, `access`, and
`mountPath`. Virtiofs-only desired tunables are carried only in the canonical
`spec.provider = { schemaId, schemaVersion, settings }` envelope, whose
`settings` object mirrors `status.provider.details`, is registered/signed in the
Provider manifest, deny-unknown, bounded, versioned/digested, validated against
`spec.providerRef` at Nix build and API admission, and cannot shadow base
fields. Shared fields are promoted to the Export base. The Provider implements
the exact base spec/status schema version/fingerprint, accepts the canonical
minimal base Spec, passes base conformance, and rejects an
unsupported optional base capability only via its signed capability matrix plus
provider-neutral `unsupported-capability`.
`spec.provider` aligns with `status.provider`. The `Provider` resource itself
keeps the D075 `spec.{artifactId, config}` exception.

### Required crate layout

```text
packages/d2b-provider-volume-virtiofs/
  src/
    main.rs / lib.rs          controller binary entry point
    controller.rs             volume-virtiofs-controller reconcile loop (Export-based)
    export.rs                 Export ResourceType DTOs and lifecycle state machine
    virtiofsd_argv.rs         argv generation (reuse from d2b-host/src/virtiofsd_argv.rs)
    socket_path.rs            private per-Export socket path derivation
    readiness.rs              export socket and guest-mount readiness probes
    user_ns.rs                ADR 0021 user-namespace conformance kit
    metrics.rs                bounded telemetry labels
    audit.rs                  volume-virtiofs audit record types
    error.rs                  typed error catalog
    tests/                    (colocated unit tests - allowed by workspace policy)
  tests/
    argv_golden.rs            migrated and extended virtiofsd_argv unit tests (≥14 tests)
    export_lifecycle.rs       Export create / ready / delete lifecycle
    adr021_invariant.rs       ADR 0021 rejection tests
    single_writer.rs          single-writer admission gate (volume-local side)
    shared_write.rs           shared-write capability gate
    readonly_flag.rs          --readonly per access mode
    multi_attachment.rs       multi-Export process isolation
    socket_path_privacy.rs    socket path never-in-status invariant
    schema_conformance.rs     ResourceType/controller/fault/redaction conformance
    fake_port.rs              fake-core/bus/supervisor seam tests
  integration/
    README.md                 integration fixture index and run instructions
    virtiofsd_launch/         virtiofsd process launch fixture
    guest_mount_readiness/    guest-control health probe fixture
    finalizer_drain/          finalizer drain under Guest restart
    store_view_readonly/      ro-store attachment with shared-dir=store-view/live
  README.md                   Provider identity, config schema, ResourceTypes, controllers/
                               workers, placement, deps/RBAC, ADR 0021 summary, socket
                               privacy, security invariants, state/telemetry, build/test/
                               integration commands, standalone-repo consumption
```

Workspace policy rejects a Provider crate missing any of `src/`, `tests/`, `integration/`,
or `README.md`. This is enforced by the workspace crate-layout gate
(`packages/xtask/src/workspace_policy.rs`).

---

## 3. Provider resource spec

### 3.1 Canonical Provider ResourceSpec (authored)

The authored Provider spec contains only `artifactId` and `config`. All other fields
(`resourceTypes`, `controllerComponents`, `workerTemplates`, `status`) are manifest-derived
or runtime-observed; they are not authored and setting them is an eval assertion error.

```yaml
apiVersion: resources.d2bus.org/v3
type: Provider
metadata:
  name: volume-virtiofs
  zone: dev
  uid: <store-generated>
  generation: 1
  ownerRef: null
  finalizers: []
spec:
  artifactId: volume-virtiofs-provider
  config: {}           # no root config; Export tunables live in spec.provider.settings
```

No root config is validated (empty `config: {}`). Every per-attachment option is declared
inside the Export spec's `spec.provider.settings` object and validated against the
Provider's signed spec settings schema at Nix eval time.

Manifest-derived fields (loaded by core ProviderDeployment directly from the
Provider's signed package manifest, never authored in Nix and never copied into
the Provider resource row):
- `exports`: declares `virtiofs.d2bus.org.Export` with its schema fingerprint;
- `components`: describes the volume-virtiofs-controller component and the
  virtiofsd-worker template;
- `dependencies`: lists required system Provider capabilities;
- `permissionClaims`: lists required RBAC claims.

### 3.2 Nix artifact catalog entry

```nix
d2b.artifacts."volume-virtiofs-provider" = {
  package = pkgs.d2b-provider-volume-virtiofs;
  type    = "provider";
};
```

The store path is private catalog implementation data. It never appears in any ResourceSpec,
status field, or audit record.

### 3.3 Nix Provider installation

```nix
d2b.zones."dev".resources."volume-virtiofs" = {
  type = "Provider";
  spec = {
    artifactId = "volume-virtiofs-provider";
    config = {};
  };
};
```

`spec.artifactId` must exist in `d2b.artifacts` with `type = "provider"`. A missing or
wrong-type entry aborts the Nix build with a structured error naming the Provider and the
missing catalog ID.

### 3.4 Controller Process (core-managed)

Core ProviderDeployment creates and manages the volume-virtiofs-controller Process when the
Provider is deployed. The dossier does not author this Process; it is a runtime artifact. The
controller binary is the entry point declared in the Provider's signed manifest under the
`volume-virtiofs-controller` component. The controller Process mounts no Provider state Volume;
its bounded non-secret operational state lives in the owning resource's `status` subresource and
the core Operation ledger (D087; see §3.5).

### 3.5 ProviderStateSet

The **ProviderStateSet** for `Provider/volume-virtiofs` is the optional,
query-time set of the *declared* Volume resources in the Zone with
`metadata.ownerRef: Provider/volume-virtiofs`. It is a query-time logical
grouping, not a separate ResourceType or stored artifact, and is empty for this
Provider:

```text
ProviderStateSet(zone, "volume-virtiofs") =
  { v : Volume | v.metadata.zone == zone
              && v.metadata.ownerRef == "Provider/volume-virtiofs" }
```

`Provider/volume-virtiofs` declares **no** Provider state Volume; its
`ProviderStateSet` is empty. The controller's authoritative reconcile state
rests entirely in the Export and Volume resources in the resource store and in
the core Operation ledger; generation counters and adoption markers are not
persisted in provider payload storage. Its bounded non-secret operational state -
per-attachment reconcile stage, virtiofsd Process readiness observations,
bounded counters, and closed-enum error detail - lives in the owning resource's
`status` subresource and the core Operation ledger (D087).

Because that operational state is fully derivable from the Export/Volume
resources, their `status`, the core Operation ledger, and independent external
observation (running virtiofsd re-adopted from declared cgroup leaves and fresh
pidfds), it fails the storage-need test: the controller declares no state
namespace, no state Volume, no state-view mount, and no dedicated
`User/volume-virtiofs-system` state-layout principal. There is no empty
identity-only Volume, and the controller Process mounts no state Volume.

---

## 4. Export ResourceType (`virtiofs.d2bus.org.Export`)

### 4.1 What an Export is

A `virtiofs.d2bus.org.Export` resource is the control-plane artifact that binds one virtiofs
attachment declaration to one running virtiofsd Process. There is one Export per
`Volume.spec.attachments[transport=virtiofs]` entry.

**Owner**: `volume-local` creates each Export when it observes a virtiofs attachment entry
in a Volume it reconciles. The Export's `ownerRef` is the Volume.

**Controller**: `Provider/volume-virtiofs` reconciles Exports. It creates and manages the
virtiofsd worker Process for each Export, updates Export status (exportReady, worker phase,
guestMountReady), and owns the `volume-virtiofs.d2bus.org/export` finalizer on each Export.

**Consumer**: `Provider/volume-local` reads Export status to populate
`Volume.status.attachmentStatuses`. volume-local does not interpret Export internal state;
it only consumes the public `exportReady` and `guestMountReady` booleans and the
`workerProcessRef` for diagnostic linking.

### 4.2 Export ResourceSpec

```yaml
apiVersion: resources.d2bus.org/v3
type: virtiofs.d2bus.org.Export
metadata:
  name: vol-work-state-x-work-vm
  zone: dev
  uid: <store-generated>
  generation: 1
  ownerRef: Volume/work-state
  finalizers: [volume-virtiofs.d2bus.org/export]
spec:
  providerRef: Provider/volume-virtiofs
  volumeRef: Volume/work-state
  executionRef: Guest/work-vm
  view: controller
  access: read-write          # read-only | read-write
  mountPath: /state
  provider:
    schemaId: volume-virtiofs.d2bus.org/Export/spec
    schemaVersion: "1.0"
    settings:
      posixAcl: false
      xattr: false
      cache: auto
      inodeFileHandles: never
      threadPoolSize: null      # null → resolved from Guest vcpu count
      socketGroup: null         # null → broker-default gid
status:
  phase: Ready                # Pending|Ready|Degraded|Failed|Unknown
  resource:
    exportReady: true         # export Endpoint resolvable and virtiofsd Process Ready
    guestMountReady: true     # guest-control probe returned MountReady
    endpointRef: Endpoint/vol-work-state-virtiofsd-work-vm
  provider:
    providerRef: Provider/volume-virtiofs
    schemaId: volume-virtiofs.d2bus.org/Export/status
    schemaVersion: 1.0.0
    observedProviderGeneration: 1
    details:
      workerProcessRef: Process/vol-work-state-virtiofsd-work-vm
  conditions:
    - type: WorkerReady
      status: "True"
      reason: process-ready
      observedGeneration: 1
    - type: ExportReady
      status: "True"
      reason: socket-exists
      observedGeneration: 1
    - type: GuestMountReady
      status: "True"
      reason: health-probe-ok
      observedGeneration: 1
  lastReconciledAt: 2026-07-22T00:00:01.000Z
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

| Field | Type | Required | Default | Constraints |
| --- | --- | --- | --- | --- |
| `volumeRef` | ResourceRef | Yes | - | `Volume/<name>` in same Zone; core verifies ownerRef consistency |
| `executionRef` | ResourceRef | Yes | - | `Guest/<name>` in same Zone |
| `view` | ViewName | Yes | - | Must exist in Volume's `views` map at Export create time |
| `access` | enum | No | `read-only` | `read-only` or `read-write`; `shared-write` is not supported in v3.0 |
| `mountPath` | absolute path | Yes | - | Guest-side mount path; no overlap with other mounts on same Guest |
| `provider.settings.*` | see §4.3 | No | see §4.3 | Validated against Provider's signed Export spec settings schema |

The Export references its visible exported endpoint through
`status.resource.endpointRef` after the Endpoint child exists. Export remains
the attachment lifecycle owner; consumers that need the stable endpoint use the
`Endpoint/<name>` ref, while lifecycle, deletion, and guest-mount readiness stay
on the Export.

```yaml
apiVersion: resources.d2bus.org/v3
type: Endpoint
metadata:
  name: vol-work-state-virtiofsd-work-vm
  zone: dev
  ownerRef: virtiofs.d2bus.org.Export/vol-work-state-x-work-vm
spec:
  providerRef: Provider/volume-virtiofs
  producerRef: Process/vol-work-state-virtiofsd-work-vm
  endpointClass: data
  transport: unix
  purpose: volume-virtiofs.d2bus.org/export
  serviceFingerprint: volume-virtiofs.d2bus.org/export.v1
  locality: cross-domain
  visibility: zone
  attachmentPolicy: launch-ticket-only
  consumerPolicy:
    allowedProviderComponents: [guest-runtime.d2bus.org/virtiofs]
    allowedOperations: [resolve]
  lifecyclePolicy: owner-ref-child
status:
  phase: Ready
  resource:
    readiness: Ready
    observedProducerGeneration: 1
    observedResourceGeneration: 1
    endpointGeneration: 1
    connectionAvailability: Available
    leaseAvailability: Available
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

### Endpoint resources (D092)

The exported virtiofs binding is a standard `Endpoint` child when it has visible
stable lifecycle and independent consumers. `Endpoint.spec` and
`Endpoint.status` never contain the virtiofsd socket path, host path, guest
mount path, CID, port, FD number, gid, or credential; authorized consumers
resolve `Endpoint/<name>` only through the EffectPort/LaunchTicket path, and
unauthorized callers receive `endpoint-resolve-denied`. Restarting the
virtiofsd producer Process bumps `endpointGeneration`, causing consumers to see
`dependency-changed`. The `virtiofs.d2bus.org.Export` resource still owns
attachment lifecycle, finalizers, guest-mount readiness, and deletion ordering.

### Retained opaque handles (D092)

The private virtiofsd socket path, `VolumeMountToken`, per-session named stream,
`OwnedTransport` byte-stream handle, transport connection handle, pidfd, FD
index, and `operationId` remain controller-internal or high-churn opaque handles
under the promotion test. They are not `Endpoint` resources.

### 4.3 `spec.provider.settings`

| Field | Type | Default | Constraints |
| --- | --- | --- | --- |
| `posixAcl` | bool | `false` | Passes `--posix-acl`; omitted for store-view shares |
| `xattr` | bool | `false` | Passes `--xattr` |
| `cache` | enum | `auto` | `auto` \| `always` \| `never`; maps to `--cache=<mode>` |
| `inodeFileHandles` | enum | `never` | `never` \| `prefer` \| `mandatory`; `never` is the only tested value in v3.0 |
| `threadPoolSize` | int or null | `null` | `null` resolves to target Guest's declared vcpu count; range 1-256 |
| `socketGroup` | int or null | `null` | `null` uses broker-default gid (vfd principal gid); explicit value must be authorized |

---

## 5. Volume-to-Export translation (volume-local responsibility)

`Provider/volume-local` is the sole controller for Volume resources. When volume-local
reconciles a Volume and observes `attachments[*].transport == "virtiofs"` entries, it
translates each such entry into one `virtiofs.d2bus.org.Export` resource:

```text
volume-local controller sees Volume spec with attachments[i].transport == "virtiofs"
→ compute desired Export set: one Export per virtiofs attachment entry
→ diff against existing Exports owned by this Volume (watch by ownerRef: Volume/<name>)
→ emit ResourceMutationBatch:
    Create Export for each new attachment (managedBy: controller; ownerRef: Volume/<name>)
    UpdateSpec Export for each changed attachment
    Delete Export for each removed attachment
→ set finalizer volume-local/virtiofs-attachments on Volume while any Export exists
→ read Export.status (exportReady, guestMountReady) and aggregate into
    Volume.status.attachmentStatuses per attachment entry
```

**Single-writer admission**: volume-local rejects the creation of a second `read-write`
Export for the same Volume before emitting the Create. If a `read-write` Export already
exists in `Ready` or `Pending` phase, volume-local writes `SingleWriterViolation: True` on
the Volume and returns `ResourceConflict`. This is an admission gate, not a race: the
constraint is enforced at translation time, not inside volume-virtiofs.

**volume-virtiofs does not write Volume resources**. It reads Volume.spec (for view
resolution and vcpu lookup) and receives Export specs to reconcile. Volume status is written
only by volume-local (aggregated from Export statuses).

---

## 6. Export reconciliation (volume-virtiofs responsibility)

### 6.1 Export reconcile loop

volume-virtiofs-controller watches `virtiofs.d2bus.org.Export` resources:

```text
On spec-generation-changed for an Export:
  1. Resolve View path from Volume.spec.views[Export.spec.view]
     (read-only Volume Get via ResourceClient)
  2. If store-view Export: check marker prerequisite (§9 step 4)
  3. Resolve threadPoolSize from Guest.spec.vcpus if null
  4. Ensure User/vol-<vol>-vfd exists (create if absent; ownerRef: Volume)
  5. Compute desired virtiofsd Process spec and Endpoint child spec
  6. Diff against existing Process and Endpoint owned by this Export
  7. Emit Create (or UpdateSpec) for the virtiofsd Process and exported Endpoint
  8. Update Export.status: phase=Pending, WorkerReady=False, ExportReady=False,
     endpointRef=Endpoint/<derived-name>

On owned-resource-changed (Process or Endpoint owned by Export):
  1. If Process.status.phase == Ready → poll export socket existence (§readiness)
  2. If socket present → set Endpoint.status.readiness=Ready and
     Export.status.exportReady=true, WorkerReady=True
  3. If socket present → send guest-control MountReady? probe
  4. If probe returns MountReady → set Export.status.guestMountReady=true
  5. If probe returns MountAbsent or timeout → set guestMountReady=false; phase=Unknown
  6. If Process.status.phase == Failed → set Export.status.phase=Failed and
     Endpoint.status.readiness=NotReady

On deletionRequestedAt set on Export:
  → Two-phase Export teardown (§6.2)
```

The controller never receives raw host paths, FDs, or broker authority. The Volume view root
is provided to the virtiofsd Process at launch time by core, resolved from the signed Export
spec and LaunchTicket - the virtiofs controller never handles FDs directly.

**Currency and upgrade (D091).** The controller implements `assess_update`,
`plan_upgrade`, and `execute_upgrade` for Export attachments and populates only
the universal `status.update`, never `status.provider`, with
`state: Current|UpdateAvailable|UpgradeRequired|Upgrading|Blocked|Unknown`,
`reasons` from `CoreGenerationChanged`, `ProviderGenerationChanged`,
`ArtifactChanged`, `ImageOrSystemGenerationChanged`, `SpecChanged`,
`DependencyChanged`, or `SecurityPolicyChanged`, observed/target
generation/digest IDs, `disruption: None|Reload|Restart|Recycle|Replace`,
`preserveState`, optional `operationId`, `lastAssessedAt`, and
`owned`/`dependencies` refs. It honors base `spec.updatePolicy` (manual
disruptive default; auto non-disruptive), while the Core Operation ledger owns
upgrade operation, idempotency, and progress. Disruptive attachment/Export
changes return `UpgradeRequired` rather than applying in place; the planner
recycles the virtiofsd Process with `disruption: Recycle`, preserves the
underlying source Volume data, and drains/restarts dependent Guest attachments.
Non-disruptive changes reconcile normally.

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

### 6.2 Two-phase Export teardown

```text
Phase 1 - virtiofsd Process teardown
  Export.deletionRequestedAt set (by volume-local when attachment removed or Volume deleted)
  → volume-virtiofs controller emits Delete for the owned virtiofsd Process
  → system-minijail (via injected effect port) sends SIGTERM; waits via pidfd
  → on process exit: store emits one Deleted revision event; row and index removed atomically
  → export socket removed by virtiofsd on clean exit; controller cleanup on unclean exit
  → controller sets Export.status: phase=Degraded, exportReady=false, workerProcessRef=null

Phase 2 - guest mount absent confirmation
  volume-virtiofs controller sends VirtioFsMountReady? probe to guest-control
  → probe returns MountAbsent
  → controller clears volume-virtiofs.d2bus.org/export finalizer on Export
  → core emits Deleted revision event for Export; row and index removed atomically
  → volume-local receives Export Deleted watch event
  → volume-local updates Volume.status.attachmentStatuses (entry removed)
  → when all Exports for a Volume are Deleted, volume-local clears
    volume-local/virtiofs-attachments finalizer, allowing Volume deletion to proceed
```

The controller does not forcibly unmount guest filesystems. If the Guest is unreachable,
the health probe times out and Export remains in `Degraded/Unknown` phase with the finalizer
held. If Guest runner absence is positively proved via pidfd (mount namespace observably
gone), the controller clears the finalizer with that proof in the audit record. If absence
is ambiguous, the finalizer is held until proof arrives or a full Zone reset is performed.
There is no time-based force-clear.

### 6.3 Export creation concurrency

Each Export's reconciliation is independent. Multiple Exports for the same Volume (different
Guests) are reconciled concurrently. One Export's virtiofsd failure does not affect sibling
Exports.

---

## 7. Owned virtiofsd Process template

### 7.1 Process resource shape

Each Export owns exactly one virtiofsd Process resource. The resource is named
`vol-<volume-name>-virtiofsd-<guest-name>` and carries `ownerRef: virtiofs.d2bus.org.Export/<export-name>`.

```yaml
apiVersion: resources.d2bus.org/v3
type: Process
metadata:
  name: vol-work-state-virtiofsd-work-vm
  zone: dev
  uid: <store-generated>
  generation: 1
  ownerRef: virtiofs.d2bus.org.Export/vol-work-state-x-work-vm
  finalizers: [system-minijail/process]
spec:
  providerRef: Provider/system-minijail
  executionRef: Host/host-system
  domain: system
  processClass: worker
  template: virtiofsd-worker
  sandbox:
    namespaceClasses: [user]       # user namespace only; no mount/pid/net classes
    capabilityClasses: []          # zero host capability classes; full caps inside NS only
    seccompClass: w1-virtiofsd
    startRoot: false               # system-minijail does NOT start virtiofsd as root
    noNewPrivileges: true          # PR_SET_NO_NEW_PRIVS before exec (required when startRoot=false)
    readOnlyRoot: true             # rootfs mounted read-only inside the user namespace
    userNamespace:
      mappingClass: process-principal-root
  readiness:
    initialDelay: "0s"
    timeout: "30s"
    failureThreshold: 3
    successThreshold: 1
    class: provider-defined        # virtiofsd-worker template defines unix-socket-exists check
  budget:
    cpu:
      request: "50m"
      limit: "500m"
    memory:
      request: "32Mi"
      limit: "128Mi"
    pids:
      limit: 64
    fds:
      limit: 256
  mounts: []
```

The user namespace mapping (`hostUid`/`hostGid`) is **not** in the public Process spec.
The signed virtiofsd-worker template declares the `process-principal-root` user namespace mapping class.
system-minijail resolves the UID/GID mapping privately from the `User/vol-<vol>-vfd`
principal when building the LaunchTicket and establishing the effect port - the controller
never receives or sets these values.

Private implementation data that lives exclusively in the LaunchTicket and effect port state,
never in the Process spec, status, or any public surface:
- the export socket path (derived in `socket_path.rs`; opaque in the signed LaunchTicket);
- the cgroup subtree placement (assigned by ProviderSupervisor from executionRef and
  component placement template);
- the `hostUid`/`hostGid` for the user-namespace single-entry mapping (resolved by
  system-minijail from the `User/vol-<vol>-vfd` principal at LaunchTicket build time);
- the Volume View root directory reference (routed by core from the signed Export spec;
  the virtiofsd controller never touches a file descriptor or host path).

### 7.2 ADR 0021 invariant: zero host capability classes and `startRoot: false`

The virtiofsd-worker Process template enforces the ADR 0021 invariant as a hard conformance
requirement:

- `sandbox.capabilityClasses: []` - no host capability class is requested; all capabilities
  are scoped inside the single-entry user namespace where virtiofsd holds in-namespace root.
- `sandbox.startRoot: false` - system-minijail does not start virtiofsd as root; the user
  namespace mapping places in-namespace UID/GID 0 at the stable host UID/GID of
  `User/vol-<vol>-vfd`, which has no privileges outside the namespace.
- `sandbox.namespaceClasses: [user]` - exactly one namespace class; no additional class.
- `--sandbox=chroot` always - `--sandbox=namespace` is never emitted.
- `noNewPrivileges: true`, `readOnlyRoot: true` - both required.

These constraints are checked by the conformance kit in `tests/adr021_invariant.rs` before
any LaunchTicket is issued. A template mutation adding any capability class or setting
`startRoot: true` is rejected at that conformance point.

Any change to this Process template that introduces a non-empty `sandbox.capabilityClasses`
list or sets `sandbox.startRoot: true` violates ADR 0021 and must be rejected by:

1. the workspace policy gate (`tests/unit/nix/cases/broker-caps.nix`);
2. the `minijail-validator-virtiofsd` gate (`tests/tools/gen-migration-ledger.sh`);
3. the hermetic Rust test `adr021_invariant.rs::virtiofsd_capability_classes_must_be_empty`.

### 7.3 Broker-pre-established user namespace (ADR 0021)

Before virtiofsd's first instruction, system-minijail (via the injected effect port)
performs the user namespace pre-establishment. The virtiofsd controller never calls the
broker directly; the effect is mediated entirely through the system-minijail Process
controller's LaunchTicket dispatch:

```text
system-minijail effect port (built from LaunchTicket):
  sync_pipe = pipe2(O_CLOEXEC)
  outcome = clone3({
      flags: CLONE_NEWUSER | CLONE_PIDFD,
      #       ^CLONE_NEWNS is intentionally absent; created lazily after sync
  })
  if outcome.is_child:
    close(sync_pipe.write_fd)           # prevent self-deadlock if broker dies
    read(sync_pipe.read_fd, 1 byte)     # blocks until parent writes uid_map
    prctl(PR_SET_NO_NEW_PRIVS, 1)
    # No CLONE_NEWNS in clone3 flags; virtiofsd --sandbox=chroot handles isolation
    setgid(0)                           # in-NS GID 0 → host_gid_for_zero
    setuid(0)                           # in-NS UID 0 → host_uid_for_zero
    # setgroups() SKIPPED - parent wrote setgroups=deny
    # supplementary groups MUST be empty (preflight enforces)
    capset(full_caps_inside_ns)
    execve(virtiofsd_binary, argv, env)
  else:  # parent
    write("/proc/<child_pid>/uid_map",   "0 <host_uid_for_zero> 1\n")
    write("/proc/<child_pid>/setgroups", "deny")
    write("/proc/<child_pid>/gid_map",   "0 <host_gid_for_zero> 1\n")
    close(sync_pipe.read_fd)
    write(sync_pipe.write_fd, 1 byte)   # unblock child
    return pidfd
```

Parent write ordering is strict: `uid_map` → `setgroups=deny` → `gid_map`. This matches
`man 7 user_namespaces`: writing `gid_map` requires either `CAP_SETGID` in the parent or
`setgroups=deny` first.

`CLONE_NEWNS` is intentionally absent from the `clone3` flags. virtiofsd does not require a
mount namespace for its `--sandbox=chroot` operation; `--sandbox=chroot` uses `pivot_root(2)`
with `CAP_SYS_ADMIN` inside the user NS.

The mapping is single-entry: in-NS UID/GID 0 → the stable UID/GID of `User/vol-<vol>-vfd`.
Only that single mapping is written. All other host UIDs are unmapped (overflow `65534`).

If a future share requires UID-preserving semantics for arbitrary host UIDs, a multi-entry
mapping is necessary. That is out of v3.0 scope and requires a new ADR section and work item.

### 7.4 Dedicated per-Volume principal

Each Volume that has at least one virtiofs attachment receives a dedicated system User
resource `User/vol-<volume-name>-vfd`. The volume-virtiofs controller creates this User
resource when reconciling the first Export for that Volume, if it does not already exist.
The User resource is owned by the Volume (`ownerRef: Volume/<name>`).

The User resource provides the stable UID/GID that system-minijail resolves when building
the LaunchTicket for the single-entry user namespace mapping and the export socket gid.

The gctl share for guest-control (`d2b-gctl`) uses a separate narrower principal
`User/vol-<vol>-gctlvfd`. The volume-virtiofs controller selects the principal by share type.

---

## 8. virtiofsd argv contract

### 8.1 Canonical argv shape

```text
virtiofsd
  --socket-path=<private-derived-path>
  --socket-group=<resolved-gid>
  --shared-dir=<volume-view-root-fd-path>
  --thread-pool-size=<N>
  --sandbox=chroot
  --inode-file-handles=never
  --cache=<mode>
  [--posix-acl]           # present only if Export.spec.provider.settings.posixAcl == true
  [--xattr]               # present only if Export.spec.provider.settings.xattr == true
  [--readonly]            # present only if access: read-only
```

No `--sandbox=namespace` is ever emitted.
No `--inode-file-handles=always` or `--inode-file-handles=prefer` is emitted in v3.0.
No free-form `extraArgs` pass-through is accepted; root config is empty.

### 8.2 `--socket-path` - private derived path

The export socket path is a **private implementation detail of volume-virtiofs**. It is:

- derived deterministically as:
  ```text
  <zone-runtime-dir>/vms/<guest-name>/vol-<sha256_trunc8(zone+volume+guest)>.vfd.sock
  ```
  where `sha256_trunc8` is the first 8 hex characters of the SHA-256 of the
  concatenated canonical form `<zone-name>\x00<volume-name>\x00<guest-name>`.
- no longer than 108 bytes (kernel `sun_path` limit);
- under `/run/d2b/vms/<guest-name>/` (the Zone/Guest runtime directory);
- never written to Export spec, Export status, process spec, process status, audit records,
  CLI output, telemetry labels, or log messages;
- opaque in the LaunchTicket; the controller derives the socket path only to build argv,
  passing it as a sealed field in the LaunchTicket, never exposing it post-launch.

### 8.3 `--shared-dir` - volume root FD path

The Volume view root directory reference is resolved by core from the signed Export spec and
provided to the LaunchTicket as an inherited FD. The argv generator uses `/proc/self/fd/<N>`
as the `--shared-dir` value so that virtiofsd inherits the open FD; the literal host path
never appears in any public surface. The virtiofsd controller never handles this FD.

For the store-view Volume, `--shared-dir` resolves to the `live/` subdirectory of the
hardlink farm (`store-view/live`) via the `ro-store` View. virtiofsd is **never** pointed
at `/nix/store` directly. `share.source == "/nix/store"` is the Nix eval-time sentinel that
triggers store-view substitution in the resource compiler; the running virtiofsd process sees
only `store-view/live`.

### 8.4 `--thread-pool-size`

`spec.provider.settings.threadPoolSize == null` (the default) causes the controller to read the target
Guest's declared `spec.vcpus` at reconciliation time and use that value. If the Guest spec
has not been reconciled yet, the controller requeues the Export reconciliation with a short
exponential backoff.

### 8.5 `--readonly`

`--readonly` is emitted when:
- `access: read-only` is declared on the Export; OR
- the named View's `rights` do not include `write`.

It is NOT emitted for `access: read-write` attachments.

### 8.6 Baseline source and migration

The current baseline is `packages/d2b-host/src/virtiofsd_argv.rs`:
- `VirtiofsdArgvInput` (11 fields): socket_path, socket_group, shared_dir,
  thread_pool_size, sandbox, inode_file_handles, cache, posix_acl, xattr,
  readonly, extra_args.
- `generate_virtiofsd_argv(input: &VirtiofsdArgvInput) -> Vec<String>` (14 unit tests;
  pinned golden `argv.txt` lines 166-184).

The 14 existing unit tests migrate verbatim to
`packages/d2b-provider-volume-virtiofs/tests/argv_golden.rs`. The `extra_args` field is
removed in v3 (Provider root config is empty; no free-form arg injection). A new test
`no_extra_args_ever_emitted` is added.

---

## 9. Store-view farm attachment

The per-Guest closure-only Nix store hardlink farm is served via virtiofs. The store-view
Volume is declared with:

- `Provider/volume-local`, `kind: durable`, `source.settings.kind: local-path`,
  and an opaque `source.settings.sourcePolicyId`;
- `views.ro-store = { path: "live", rights: ["read", "traverse"] }`;
- one attachment with `transport: virtiofs`, `view: ro-store`, `access: read-only`,
  `mountPath: /nix/.ro-store`.

volume-local translates this attachment to one Export owned by the store-view Volume.
volume-virtiofs reconciles the Export and creates the virtiofsd Process.

Key invariants enforced by the controller:

1. **`--shared-dir` = `store-view/live`**: virtiofsd is always pointed at the `live/`
   subdirectory, never at `/nix/store`. The `ro-store` View has `path: "live"` and the
   core LaunchTicket resolves the FD to that subtree.
2. **`--readonly` always emitted**: the `ro-store` View rights are `[read, traverse]` (no
   `write`); `access: read-only`; `--readonly` is unconditional for this attachment.
3. **`--posix-acl` and `--xattr` omitted**: `/nix/store` paths have no POSIX ACLs and d2b
   hardlink farms are d2b-managed; these flags are not needed.
4. **Marker file prerequisite**: virtiofsd is not started until
   `store-view/live/.d2b-marker-<guest>` exists (zero-length file, `d2bd:users 0444`). The
   controller checks for the marker via a bounded blocking adapter (e.g.,
   `tokio::task::spawn_blocking` wrapping an `fstatat(2)` relative to the zone runtime
   directory, or an async-safe fd-relative equivalent); no blocking syscall is issued on
   the async executor thread directly. If the marker is absent, the controller requeues
   the Export reconciliation with exponential backoff.

---

## 10. d2b-bus routing and RBAC

### 10.1 Bus route

volume-virtiofs-controller processes connect to the Zone resource API over:

```text
volume-virtiofs-controller (Process managed by core ProviderDeployment)
  → d2b-bus (local enrolled KK session)
  → ComponentSession (Noise_KK, authenticated as Provider/volume-virtiofs controller subject)
  → Zone d2b.resource.v3 service
  → redb coordinator
```

The controller never receives a direct redb handle, store path, or ambient socket. It uses
only the ResourceClient from `d2b-provider-toolkit` over the bus-provided route.

system-minijail uses an **injected effect port** (not a direct broker call from
volume-virtiofs). The virtiofsd controller emits Process Create/Delete via ResourceClient;
system-minijail's effect port adapter executes the LaunchTicket, user-namespace pre-
establishment, and pidfd supervision. volume-virtiofs never calls any broker operation
directly.

### 10.2 RBAC

The controller is authorized by its enrolled KK identity as `Provider/volume-virtiofs`
controller. Required Role rules:

```yaml
# volume-virtiofs controller
rules:
  - resourceTypes: [virtiofs.d2bus.org.Export]
    verbs: [get, list, watch, update-status, update-finalizers]
    zones: [<zone>]
  - resourceTypes: [Volume]
    verbs: [get, list, watch]      # read-only; no update-status; volume-local owns Volume status
    zones: [<zone>]
  - resourceTypes: [Process]
    verbs: [create, get, list, watch, update-spec, delete]
    zones: [<zone>]
    ownerConstraint: owned-by-export
  - resourceTypes: [User]
    verbs: [create, get, list, watch]
    zones: [<zone>]
    namePattern: vol-*-vfd
    ownerConstraint: owned-by-volume
  - resourceTypes: [Guest]
    verbs: [get]                   # vcpu-count resolution only
    zones: [<zone>]
```

volume-virtiofs may **not** write Volume spec or Volume status. It reads Volume.spec
(view resolution, vcpu lookup) but the Volume status subresource is the exclusive authority
of volume-local.

---

## 11. Controller component descriptor

```yaml
id: volume-virtiofs-controller
type: controller
providerId: volume-virtiofs
stateNamespaces: []          # no Provider state Volume; operational state in status/core ledger (D087)
mounts: []                   # controller mounts no Provider state Volume
resourceTypes:
  # Volume is intentionally absent: volume-virtiofs-controller does not own or create Volumes.
  # Provider/volume-local is the sole Volume reconciler. Volume appears only in watchSelectors (read-only, below).
  - type: virtiofs.d2bus.org.Export
    verbs: [create, update-spec, update-status, update-finalizers, delete, watch]
  - type: Process
    verbs: [create, update-spec, delete, watch]
  - type: User
    verbs: [create, watch]
watchSelectors:
  - resourceType: virtiofs.d2bus.org.Export
    filter: ""                         # all Exports in zone
  - resourceType: Process
    filter: ownerRef starts-with "virtiofs.d2bus.org.Export/"
    ownerType: virtiofs.d2bus.org.Export
  - resourceType: User
    filter: name starts-with "vol-" and name ends-with "-vfd"
  - resourceType: Volume
    filter: ""                         # read-only watch for view/vcpu resolution
  - resourceType: Guest
    filter: ""                         # read-only watch for vcpu-count resolution
ownerChildTriggers:
  - trigger: owned-resource-changed
    ownerType: virtiofs.d2bus.org.Export
    childTypes: [Process, User]
dependencySelectors:
  - resourceType: Guest
    purpose: vcpu-count-resolution
  - resourceType: User
    purpose: vfd-principal-uid-resolution
reconcileConcurrency: 16          # 16 parallel Export reconciliations
maxPendingResources: 1024
observeIntervalSeconds: 0         # event-driven only
finalizers:
  - volume-virtiofs.d2bus.org/export
serviceFingerprint: <sha256 of attachment.schema.json>
```

---

## 12. Error catalog

| Error code | Meaning | Retryable |
| --- | --- | --- |
| `virtiofsd-launch-failed` | LaunchTicket dispatch returned error or clone3 failed | yes, with backoff |
| `user-ns-sync-timeout` | child blocked on sync pipe; parent uid_map write timeout | yes, once |
| `export-socket-timeout` | socket did not appear within `readiness.timeout` | yes, with backoff |
| `guest-mount-probe-timeout` | guest-control health probe timed out | yes; Export phase → Unknown |
| `shared-write-unsupported` | shared-write requested but Provider does not declare supportsSharedWrite | no |
| `view-not-found` | Export references a View that does not exist in Volume spec | no |
| `execution-ref-not-found` | Export executionRef does not resolve to a Guest in this Zone | no; fails closed |
| `vcpu-count-unavailable` | Guest spec not yet reconciled; threadPoolSize cannot be resolved | yes; requeue |
| `vfd-user-creation-failed` | User resource for vfd principal could not be created | yes, with backoff |
| `store-view-marker-absent` | `live/.d2b-marker-<guest>` absent; farm not yet populated | yes; requeue |
| `process-adoption-ambiguous` | virtiofsd process identity ambiguous on controller restart | no; quarantine |
| `socket-cleanup-failed` | stale socket unlink failed; previous virtiofsd may still be running | yes, once |
| `adr021-violation-detected` | `capabilityClasses` non-empty or `startRoot: true` detected at preflight | no; halt |

All error messages are bounded at 512 bytes, UTF-8/control-character validated, and contain
no host paths, socket paths, guest paths, process data, terminal bytes, raw errno details,
or credential material.

---

## 13. Status conditions

Export-level status conditions (on `virtiofs.d2bus.org.Export`):

| Condition type | Normal value | Abnormal state |
| --- | --- | --- |
| `WorkerReady` | `"True"` / reason `process-ready` | `"False"` when virtiofsd not yet started or has crashed |
| `ExportReady` | `"True"` / reason `socket-exists` | `"False"` if socket absent or cleanup in progress |
| `GuestMountReady` | `"True"` / reason `health-probe-ok` | `"False"` / `Unknown` on probe timeout or Guest off |
| `FinalizerDraining` | `"False"` (not draining) | `"True"` while virtiofsd Process deletion is pending |

Per D088, `volume-virtiofs` contributes only bounded virtiofs-specific
attachment/export observations: Volume attachment readiness promoted for generic
consumers is `Volume.status.resource.attachmentStatuses`, identical to sibling
Volume implementations and written by `volume-local` from aggregated Export
status. Virtiofs worker/export detail stays in `status.provider.details`
with `providerRef: Provider/volume-virtiofs`, qualified `schemaId`
(`volume-virtiofs.d2bus.org/Export/status`), `schemaVersion`, and
`observedProviderGeneration`. Any status writer writes all present layers
atomically in one mutation; shared fields are never duplicated into
`status.provider`, and the strict, ≤32 KiB, redacted extension schema is
registered and signed in the Provider manifest.

Volume-level conditions (written by volume-local from aggregated Export statuses):

| Condition type | Normal value | Abnormal state |
| --- | --- | --- |
| `AttachmentsReady` | `"True"` | `"False"` or `Unknown` while any Export is not fully ready |
| `SingleWriterViolation` | absent | `"True"` if second read-write Export was rejected at admission |

---

## 14. Audit records

All volume-virtiofs audit records use the Zone-local audit stream
(`d2b-audit` over the private local Unix datagram socket).

### 14.1 Export create

```json
{
  "subject_digest": "sha256:<hex>",
  "zone": "dev",
  "verb": "create-virtiofsd-process",
  "resourceRef": "virtiofs.d2bus.org.Export/vol-work-state-x-work-vm",
  "volumeRefDigest": "sha256:<hex-of-Volume/work-state>",
  "executionRefDigest": "sha256:<hex-of-Guest/work-vm>",
  "workerTemplate": "virtiofsd-worker",
  "accessMode": "read-write",
  "view": "controller",
  "correlationId": "<opaque>",
  "outcome": "process-created"
}
```

### 14.2 Export delete

```json
{
  "subject_digest": "sha256:<hex>",
  "zone": "dev",
  "verb": "delete-virtiofsd-process",
  "resourceRef": "virtiofs.d2bus.org.Export/vol-work-state-x-work-vm",
  "virtiofsdProcessRefDigest": "sha256:<hex>",
  "reason": "export-deleted",
  "correlationId": "<opaque>",
  "outcome": "process-deletion-requested"
}
```

### 14.3 Export finalizer hold policy

If the Guest runner process absence can be positively proved (the runner process that owns the
Guest mount namespace is confirmed dead via pidfd, making the mount namespace observably gone),
the controller clears the Export finalizer with that proof recorded in the audit record
(verb: `finalizer-cleared-with-proof`).

If the Guest is unreachable or the absence is ambiguous, the Export remains in
`Degraded/Unknown` phase with the finalizer held. There is no time-based force-clear; the
finalizer is held until either the proof arrives or a full Zone reset. The audit record in
the ambiguous case carries `outcome: finalizer-held` and
`reason: guest-unreachable-ambiguous`.

Excluded from all audit records: socket paths, host paths, raw PIDs, PID FDs, cgroup paths,
mount paths inside guests, virtiofsd binary path, process argv, environment variables,
guest credential material, and layout entry content.

---

## 15. Telemetry

### 15.1 Lightweight bounded emitter

volume-virtiofs uses the Zone-local lightweight bounded emitter (`tracing` +
bounded in-process ring → private Unix datagram socket). It does not import
`opentelemetry_sdk` or `opentelemetry-otlp`. Emitted frames are consumed by
`Provider/observability-otel` if installed.

### 15.2 Metric labels

All metric labels are from the closed set below. No free-form values,
no host paths, no socket paths, no guest names beyond a stable opaque digest.

| Label | Values |
| --- | --- |
| `provider` | `volume-virtiofs` (literal constant) |
| `operation` | `export-create` \| `export-delete` \| `spawn-virtiofsd` \| `readiness-probe` \| `finalizer-drain` |
| `outcome` | `success` \| `error` \| `timeout` \| `conflict` \| `unknown` |
| `access_mode` | `read-only` \| `read-write` |
| `error_class` | stable error code from §12 Error catalog |

The `zone` and `execution` resource attributes are set at the OTEL resource level (from the
Process resource context) and are not repeated as metric labels.

VM name / Guest name is never a metric label or span attribute. It may appear
only in bounded OTEL resource attributes, re-stamped at the ingress boundary.

### 15.3 Key metrics

| Metric | Type | Description |
| --- | --- | --- |
| `d2b_volume_virtiofs_exports_total` | Counter | Total Export create attempts, labeled by outcome |
| `d2b_volume_virtiofs_export_deletes_total` | Counter | Total Export delete attempts, labeled by outcome |
| `d2b_volume_virtiofs_ready_exports` | Gauge | Current count of Exports with both exportReady and guestMountReady true |
| `d2b_volume_virtiofs_export_ready_seconds` | Histogram | Time from virtiofsd spawn to export socket appearing |
| `d2b_volume_virtiofs_mount_ready_seconds` | Histogram | Time from export socket ready to guest mount confirmed |
| `d2b_volume_virtiofs_process_restarts_total` | Counter | virtiofsd Process restart events, labeled by error_class |
| `d2b_volume_virtiofs_finalizer_drain_seconds` | Histogram | Time from Export deletion request to finalizer cleared |

### 15.4 Performance budgets

| Gate | Requirement |
| --- | --- |
| Export socket appears after virtiofsd spawn | p95 ≤ 500 ms for a warmed NixOS host |
| Guest mount confirmed (probe round trip) | p95 ≤ 2 s for a running Guest |
| Export status written after virtiofsd Ready | p95 ≤ 5 ms (matches core commit-to-handler budget) |
| Controller reconcile loop iteration (one Export) | p95 ≤ 10 ms excluding spawn and probe I/O |

---

## 16. Nix configuration

### 16.1 Artifact catalog entry

```nix
d2b.artifacts."volume-virtiofs-provider" = {
  package = pkgs.d2b-provider-volume-virtiofs;
  type    = "provider";
};
```

### 16.2 Provider resource

```nix
d2b.zones."dev".resources."volume-virtiofs" = {
  type = "Provider";
  spec = {
    artifactId = "volume-virtiofs-provider";
    config = {};
  };
};
```

### 16.3 Volume with virtiofs attachment (minimal state Volume)

```nix
d2b.zones."dev".resources."work-state" = {
  type = "Volume";
  spec = {
    providerRef = "Provider/volume-local";
    source = {
      executionRef = "Host/host-system";
      settings.kind = "local-path";
      settings.sourcePolicyId = "default-state";
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

volume-local translates the `transport = "virtiofs"` attachment into one
`virtiofs.d2bus.org.Export` resource automatically. No separate Export resource declaration
is required in Nix.

### 16.4 Canonical Export ResourceSpec JSON (attachment defaults materialized)

```json
{
  "apiVersion": "resources.d2bus.org/v3",
  "type": "virtiofs.d2bus.org.Export",
  "metadata": {
    "name": "vol-work-state-x-work-vm",
    "zone": "dev",
    "ownerRef": "Volume/work-state",
    "finalizers": ["volume-virtiofs.d2bus.org/export"]
  },
  "spec": {
    "providerRef": "Provider/volume-virtiofs",
    "volumeRef": "Volume/work-state",
    "executionRef": "Guest/work-vm",
    "view": "controller",
    "access": "read-write",
    "mountPath": "/state",
    "provider": {
      "schemaId": "volume-virtiofs.d2bus.org/Export/spec",
      "schemaVersion": "1.0",
      "settings": {
        "cache": "auto",
        "inodeFileHandles": "never",
        "posixAcl": false,
        "socketGroup": null,
        "threadPoolSize": null,
        "xattr": false
      }
    }
  },
  "status": {
    "observedGeneration": 0,
    "phase": "Pending",
    "conditions": [],
    "lastReconciledAt": null,
    "startedAt": null,
    "completedAt": null,
    "outcome": null,
    "resource": {},
    "update": {
      "state": "Unknown",
      "reasons": [],
      "observedGeneration": 0,
      "targetGeneration": 1,
      "disruption": "None",
      "preserveState": true,
      "operationId": null,
      "lastAssessedAt": null,
      "owned": { "count": 0, "refs": [] },
      "dependencies": { "count": 0, "refs": [] }
    }
  }
}
```

### 16.5 Eval/build validation

The following validations are fatal at Nix eval time for virtiofs attachments:

1. `transport = "virtiofs"` requires `Provider/volume-virtiofs` to be installed in the
   same Zone. Missing Provider aborts with a structured error naming the Volume and the
   missing Provider.
2. `view` must exist in the Volume's `views` map. Unknown view name aborts.
3. `access` must be compatible with the named View's declared `rights`. `read-write` on a
   View with only `[read, traverse]` aborts.
4. `shared-write` aborts unconditionally in v3.0 (Provider does not declare
   `supportsSharedWrite: true`).
5. `spec.provider.settings` is validated against the Provider's signed Export
   spec settings schema from the private artifact catalog entry. Unknown fields
   abort; out-of-range values abort.
6. `executionRef` must resolve to a `Guest/<name>` resource in the same Zone.
7. At most one `read-write` attachment per Volume at eval time. The Nix resource compiler
   rejects two simultaneous `read-write` entries at build time.
8. Credential refs: no secret values may appear in attachment settings.

### 16.6 Attachment schema JSON (volume-virtiofs signed schema)

The signed `attachment.schema.json` is part of the Provider package. Nix reads it from the
private artifact catalog entry for `volume-virtiofs-provider`. Its canonical form:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "VirtiofsAttachmentSettings",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "posixAcl":           { "type": "boolean", "default": false },
    "xattr":              { "type": "boolean", "default": false },
    "cache":              { "type": "string", "enum": ["auto", "always", "never"], "default": "auto" },
    "inodeFileHandles":   { "type": "string", "enum": ["never", "prefer", "mandatory"], "default": "never" },
    "threadPoolSize":     { "type": ["integer", "null"], "minimum": 1, "maximum": 256, "default": null },
    "socketGroup":        { "type": ["integer", "null"], "default": null }
  }
}
```

### 16.7 Store-view Volume (resource compiler output, generated per Guest)

```nix
# Auto-generated by the Nix resource compiler for each Guest with a VM runtime Provider.
# Operators do not write this resource directly.
d2b.zones."dev".resources."store-view-work-vm" = {
  type = "Volume";
  spec = {
    providerRef = "Provider/volume-local";
    source = {
      executionRef = "Host/host-system";
      settings.kind = "local-path";
      settings.sourcePolicyId = "store-view-work-vm";
      # hostPath for this sourcePolicyId is injected into the private catalog by the compiler
    };
    kind = "durable";
    layout = [
      { path = "";              type = "directory"; ownerRef = "User/d2bd"; groupRef = "User/users"; mode = "0755"; }
      { path = "live";          type = "directory"; invariants = ["no-symlink" "broker-opaque-id-only"]; cleanupPolicy = "never"; repairPolicy = "exact-owner"; ownerRef = "User/d2bd"; groupRef = "User/users"; mode = "0755"; }
      { path = "live/.d2b-marker-work-vm"; type = "file"; ownerRef = "User/d2bd"; groupRef = "User/users"; mode = "0444"; invariants = ["no-symlink" "same-filesystem" "hardlink-farm-no-recursion" "broker-opaque-id-only"]; repairPolicy = "exact-owner"; }
      { path = "meta";          type = "directory"; invariants = ["no-symlink" "same-filesystem" "hardlink-farm-no-recursion" "broker-opaque-id-only"]; repairPolicy = "exact-owner"; ownerRef = "User/d2bd"; groupRef = "User/users"; mode = "0755"; }
      { path = "meta/generations"; type = "directory"; invariants = ["no-symlink" "same-filesystem" "hardlink-farm-no-recursion" "broker-opaque-id-only"]; cleanupPolicy = "never"; repairPolicy = "exact-owner"; ownerRef = "User/d2bd"; groupRef = "User/users"; mode = "0755"; }
      { path = "meta/current";  type = "symlink"; target = "generations/0"; noFollow = false; invariants = ["broker-opaque-id-only"]; cleanupPolicy = "never"; repairPolicy = "exact-owner"; ownerRef = "User/d2bd"; groupRef = "User/users"; mode = "0777"; }
      { path = "state";         type = "directory"; invariants = ["no-symlink" "broker-opaque-id-only"]; repairPolicy = "exact-owner"; ownerRef = "User/d2bd"; groupRef = "User/users"; mode = "0700"; }
      { path = "gcroots";       type = "directory"; invariants = ["no-symlink" "same-filesystem" "hardlink-farm-no-recursion" "broker-opaque-id-only"]; cleanupPolicy = "never"; repairPolicy = "exact-owner"; ownerRef = "User/d2bd"; groupRef = "User/users"; mode = "0755"; }
      { path = "sync.lock";     type = "file"; ownerRef = "User/d2bd"; groupRef = "User/users"; mode = "0640"; leaseClass = "none"; invariants = ["no-symlink" "broker-opaque-id-only"]; restartPolicy = "preserve-across-controller-restart"; }
    ];
    views = {
      ro-store = { path = "live"; rights = [ "read" "traverse" ]; };
      meta     = { path = "meta"; rights = [ "read" "traverse" ]; };
    };
    attachments = [
      {
        executionRef = "Guest/work-vm";
        transport    = "virtiofs";
        view         = "ro-store";
        access       = "read-only";
        mountPath    = "/nix/.ro-store";
      }
    ];
  };
};
```

---

## 17. Cleanup contract

### 17.1 Volume deletion

When a Volume with virtiofs attachments is deleted:

1. volume-local controller observes `deletionRequestedAt` set on the Volume.
2. volume-local emits Delete for each owned Export resource.
3. volume-virtiofs controller observes `deletionRequestedAt` on each Export.
4. volume-virtiofs emits Delete for each owned virtiofsd Process resource.
5. system-minijail effect port sends SIGTERM to each virtiofsd process; waits via pidfd.
6. On process exit: store emits Deleted revision event for Process; row and index removed
   atomically.
7. volume-virtiofs controller queries guest-control health probe; waits for `MountAbsent`.
8. When mount absent confirmed, volume-virtiofs clears `volume-virtiofs.d2bus.org/export` finalizer.
9. Store emits Deleted revision event for Export; row and index removed atomically.
10. volume-local receives Export Deleted events; clears `volume-local/virtiofs-attachments`
    finalizer after all Exports for the Volume are deleted.
11. volume-local finalizer proceeds (child finalizers first).
12. After all finalizers cleared, volume-local emits Deleted revision event for the Volume;
    row and index removed atomically.

Controller-created User resources (`User/vol-<vol>-vfd`) are owned by the Volume
(`ownerRef: Volume/<name>`) and are deleted in the Volume's owner-child finalizer cascade,
after the last virtiofsd Process referencing them is deleted.

### 17.2 Attachment removal (Volume not deleted)

When a specific attachment entry is removed from the Volume spec while the Volume itself
remains:

1. volume-local detects attachment list change via `spec-generation-changed` hint.
2. volume-local deletes only the Export owned by that attachment.
3. volume-virtiofs drains the virtiofsd Process per the two-phase teardown (§6.2).
4. After Export deletion and guest mount absent confirmation, volume-virtiofs clears the
   Export finalizer; Export row is removed; volume-local updates
   `Volume.status.attachmentStatuses` (entry removed).
5. volume-local does not touch Exports for other Guests on the same Volume.

### 17.3 Configuration-removed condition

When a Volume is removed from the Nix configuration generation:

```yaml
status:
  phase: Degraded
  conditions:
    - type: ConfigurationRemoved
      status: "True"
      reason: absent-from-configuration
    - type: FinalizersBlocked
      status: "True"
      reason: finalizers-draining
  attachmentStatuses:
    - executionRef: Guest/work-vm
      state: detaching
      exportReady: false
      guestMountReady: false
```

### 17.4 Prior-generation retention

The Zone retains the last `retainedGenerations` generations (default 3, range 1-16).
A Volume that has been deleted but whose generation is within the retention window may be
reactivated via `ActivateGeneration`. Reactivation cancels in-flight Delete for the Volume
and its owned Exports and Processes; the controller reconciles from the retained spec.

---

## 18. Current-code fit

| Item | Evidence class | Treatment |
| --- | --- | --- |
| `packages/d2b-host/src/virtiofsd_argv.rs`: `VirtiofsdArgvInput`, `generate_virtiofsd_argv`, 14 unit tests, golden `argv.txt` | `implemented-and-reachable` | Extract to `d2b-provider-volume-virtiofs/src/virtiofsd_argv.rs`; migrate 14 tests to `tests/argv_golden.rs`; remove `extra_args` field |
| `nixos-modules/minijail-profiles.nix`: `virtiofsdProfiles`; principals `d2b-<vm>-runner`, `d2b-<vm>-gctlfs`; ADR 0021 user-NS exception | `generated-or-eval-contract` | Becomes `virtiofsd-worker` Process sandbox spec; ADR 0021 invariants fully preserved; principals → typed `User/<name>` ResourceRefs; no numeric form |
| `nixos-modules/processes-json.nix`: `virtiofsdRunner` shape; `roStoreSharedDir` redirect sentinel `share.source == "/nix/store"` → `store-view/live` | `generated-or-eval-contract` | Replaced by an Export-owned Process resource reconciled by volume-virtiofs; `store-view/live` redirect preserved in resource compiler |
| `packages/d2b-core/src/processes.rs`: `ProcessRole::Virtiofsd`, `VmProcessDag` virtiofsd entry | `generated-or-eval-contract` | Replaced by Process resource template `virtiofsd-worker` owned by virtiofs Export |
| `packages/d2b-priv-broker/src/ops/spawn_runner.rs`: `SpawnRunnerPlanInput`, `RunnerIsolationSpec`, `adr_carve_out` virtiofsd path | `implemented-and-reachable` | `SpawnRunnerPlanInput` → v3 `LaunchTicket` with typed sandbox spec; `adr_carve_out` field removed; ADR 0021 is no longer a carve-out but the normal path; broker invocation is mediated by system-minijail effect port, not called directly by volume-virtiofs |
| `packages/d2b-priv-broker/src/sys.rs`: `clone3_spawn_runner` user-NS pre-establishment | `implemented-and-reachable` | Remains in broker; exposed to system-minijail effect port adapter; volume-virtiofs never calls it directly; `user_ns.rs` in volume-virtiofs crate contains conformance kit only |
| `packages/d2bd/src/supervisor/dag.rs`: `ProcessRole::Virtiofsd` dag node supervised as entry under `WorkloadId`-keyed `VmProcessDag` | `implemented-and-reachable` | Replaced by Export controller lifecycle in v3; dag node retired after controller parity |
| `packages/d2b-contract-tests/tests/storage_sync_contracts.rs`: virtiofsd argv shape gate | `implemented-and-reachable` | Adapted to Process sandbox spec gate in `d2b-provider-volume-virtiofs/tests/schema_conformance.rs` |
| `tests/tools/gen-migration-ledger.sh` → `virtiofsd-argv-shape` gate | `implemented-and-reachable` | Adapted to validate Process template argv golden vector |
| `tests/tools/gen-migration-ledger.sh` → `minijail-validator-virtiofsd` gate | `implemented-and-reachable` | Adapted to enforce Process sandbox spec ADR 0021 invariants |
| `tests/unit/nix/cases/broker-caps.nix` | `implemented-and-reachable` | Adapted to v3 Process template capability policy gate |
| `packages/d2b-host/src/virtiofsd_argv.rs` (baseline): socket path format `/run/d2b/vms/<vm>/<vm>-virtiofs-<tag>.sock` | `implemented-and-reachable` | Replaced by private hash-derived path in `socket_path.rs`; new path format equally private |
| ADR 0021 (`docs/adr/0021-broker-user-namespace-for-virtiofsd.md`) | `implemented-and-reachable` | Full invariant preserved; user-NS pre-establishment is system-minijail effect port responsibility; not a carve-out |

**Main reuse**: `packages/d2b-session/` and `packages/d2b-session-unix/` from main commit
`a1cc0b2d` are the selected ComponentSession sources per `ADR-046-componentsession-and-bus`.
volume-virtiofs uses the toolkit ResourceClient, which wraps ComponentSession and d2b-bus;
it does not import session implementation internals directly.

---

## 19. Implementation work items

### ADR046-vvfs-001 - crate bootstrap and argv extraction

| Field | Value |
| --- | --- |
| Dependency/owner | ADR046-volume-001 (Volume contract types); ADR046-vvfs-export-001 (Export type); W1; volume-virtiofs Provider owner |
| Current source | `packages/d2b-host/src/virtiofsd_argv.rs` (VirtiofsdArgvInput, generate_virtiofsd_argv, 14 unit tests, golden argv.txt); `packages/d2b-host/src/lib.rs` (module declaration) |
| Reuse action | adapt |
| Destination | `packages/d2b-provider-volume-virtiofs/src/virtiofsd_argv.rs`; `packages/d2b-provider-volume-virtiofs/tests/argv_golden.rs` |
| Detailed design | Create crate skeleton with mandatory `src/`, `tests/`, `integration/`, `README.md`. Extract `VirtiofsdArgvInput` and `generate_virtiofsd_argv` with these changes: (1) replace `extra_args: Vec<String>` with nothing (removed); (2) replace `socket_path: String` with `socket_path: SocketPath` newtype backed by `socket_path.rs`; (3) add `shared_dir_fd: i32` replacing `shared_dir: String` (FD-based); (4) replace `socket_group: Option<u32>` with `socket_group: Option<Gid>`. Implement `socket_path.rs`: private path using SHA-256 of `<zone>\x00<volume>\x00<guest>`, truncated 8 hex chars, formatted as `<zone-runtime-dir>/vms/<guest>/vol-<hash>.vfd.sock`. Assert path length ≤ 108 bytes. Primary reuse disposition: `adapt`. Preserved source-plan detail: extract and adapt. |
| Integration | volume-virtiofs controller `export.rs` calls virtiofsd_argv.rs at spawn time; LaunchTicket carries resolved socket path as opaque sealed field |
| Data migration | v3.0 reset; socket path format changes |
| Validation | `tests/argv_golden.rs`: 14 migrated tests + `no_extra_args_ever_emitted`, `socket_path_is_not_in_args`, `shared_dir_is_fd_path`, `path_length_within_sunpath_limit`; `tests/socket_path_privacy.rs`: `socket_path_not_in_export_status`, `socket_path_not_in_volume_status`, `socket_path_not_in_audit_record`; `tests/schema_conformance.rs`: `process_spec_readiness_class_is_provider_defined`, `process_spec_readiness_has_no_kind_or_period_fields`, `process_spec_budget_cpu_request_limit_nested`, `process_spec_budget_memory_request_limit_nested`, `process_spec_budget_pids_limit_present`, `process_spec_budget_fds_limit_present`, `process_spec_sandbox_no_new_privileges_true`, `process_spec_sandbox_read_only_root_true`, `process_spec_no_host_uid_gid_in_spec` |
| Removal proof | `packages/d2b-host/src/virtiofsd_argv.rs` removed only after parity confirmed by argv-shape gate |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-vvfs-export-001 - Export ResourceType declaration

| Field | Value |
| --- | --- |
| Dependency/owner | ADR046-volume-001; W1; volume-virtiofs Provider owner |
| Current source | No analog; new ResourceType |
| Reuse action | create |
| Destination | `packages/d2b-provider-volume-virtiofs/src/export.rs`; `packages/d2b-contracts/src/v3/virtiofs_export.rs` |
| Detailed design | Declare `virtiofs.d2bus.org.Export` ResourceType in `d2b-contracts`. Base fields: `providerRef`, `volumeRef`, `executionRef`, `view`, `access`, `mountPath`; virtiofs tunables live under `spec.provider.settings` (as in §4.2). Status fields: top-level `phase`/`conditions`, `status.resource.exportReady`, `status.resource.guestMountReady`, and `status.provider.details.workerProcessRef`. Strict serde `deny_unknown_fields`. Implement the conformance test fixture that validates schema fingerprint stability. The Export spec JSON schema and provider status extension schema are signed and included in the Provider package. |
| Integration | `d2b-contracts` exports the Export DTO; volume-virtiofs controller and volume-local both import it for ResourceClient typed operations |
| Data migration | None; new type |
| Validation | `tests/schema_conformance.rs`: `export_schema_canonical_json_stable`, `export_spec_denied_unknown_fields`, `export_status_exportready_is_boolean_not_path`, `export_owner_must_be_volume` |
| Removal proof | N/A (new type) |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-vvfs-002 - ADR 0021 user-namespace conformance kit

| Field | Value |
| --- | --- |
| Dependency/owner | ADR046-vvfs-001; ADR046-volume-001; W1; broker/spawn owner |
| Current source | `packages/d2b-priv-broker/src/sys.rs` (`clone3_spawn_runner`, user-NS pre-establishment block); `packages/d2b-priv-broker/src/ops/spawn_runner.rs` (`SpawnRunnerPlanInput.user_namespace`, `RunnerIsolationSpec.user_namespace`); ADR 0021 implementation contract |
| Reuse action | extract |
| Destination | `packages/d2b-provider-volume-virtiofs/src/user_ns.rs` (conformance kit); `packages/d2b-provider-volume-virtiofs/tests/adr021_invariant.rs` |
| Detailed design | `user_ns.rs` contains only the conformance check and template descriptor assertion: verify that the virtiofsd-worker Process template declares `capabilityClasses: []`, `startRoot: false`, `noNewPrivileges: true`, `readOnlyRoot: true`, and `sandbox.userNamespace.mappingClass: process-principal-root`. `hostUid`/`hostGid` are NOT set by the controller - system-minijail resolves the mapping from the `User/vol-<vol>-vfd` principal when building the LaunchTicket via the effect port. The conformance check rejects any template mutation that adds host capability classes, sets `startRoot: true`, disables `noNewPrivileges`, or disables `readOnlyRoot`. The user-NS pre-establishment code itself remains in `d2b-priv-broker/src/sys.rs` and is invoked via the system-minijail effect port. Primary reuse disposition: `extract`. Preserved source-plan detail: extract conformance kit only; pre-establishment code stays in broker. |
| Integration | volume-virtiofs controller calls conformance check before emitting any Process Create; system-minijail requests launch through MinijailProcessEffectPort and the core/ProviderSupervisor adapter invokes the broker spawn path |
| Data migration | v3.0 reset; current `adr_carve_out` field in `SpawnRunnerPlanInput` removed; ADR 0021 path is now the default |
| Validation | `tests/adr021_invariant.rs`: `virtiofsd_capability_classes_must_be_empty`, `virtiofsd_start_root_must_be_false`, `virtiofsd_no_new_privileges_must_be_true`, `virtiofsd_read_only_root_must_be_true`, `process_spec_has_no_host_uid_gid`, `sandbox_namespace_never_emitted`, `user_ns_single_entry_single_uid_mapping`, `uid_map_write_ordering_uid_setgroups_gid`, `child_setuid_in_ns_not_host_uid`, `clone_newns_not_in_clone3_flags`, `child_exits_user_ns_sync_on_pipe_eof` |
| Removal proof | `adr_carve_out` field and virtiofsd-specific branch in current `SpawnRunnerPlanInput` removed only after v3 LaunchTicket covers all virtiofsd spawn cases |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-vvfs-003 - Export lifecycle controller

| Field | Value |
| --- | --- |
| Dependency/owner | ADR046-vvfs-001, ADR046-vvfs-002, ADR046-vvfs-export-001; ADR046-volume-001; W2; volume-virtiofs controller owner |
| Current source | `packages/d2bd/src/supervisor/dag.rs` (ProcessRole::Virtiofsd dag node); `nixos-modules/processes-json.nix` (virtiofsdRunner block; attachment-to-Process mapping) |
| Reuse action | adapt |
| Destination | `packages/d2b-provider-volume-virtiofs/src/controller.rs`; `packages/d2b-provider-volume-virtiofs/src/export.rs` |
| Detailed design | Implement volume-virtiofs-controller reconcile loop using toolkit ResourceClient. Watch selector: `virtiofs.d2bus.org.Export` resources (all in zone), owned Process resources, owned User resources, Volume resources (read-only for view/vcpu resolution), Guest resources (read-only for vcpu count). On `spec-generation-changed` for an Export: (1) resolve View from Volume; (2) check store-view marker if applicable; (3) resolve threadPoolSize from Guest vcpus; (4) ensure User/vol-<vol>-vfd; (5) diff against current Process; (6) emit Create/UpdateSpec. On `owned-resource-changed` for a Process: update Export status. On `deletionRequestedAt` for Export: two-phase teardown (§6.2). Primary reuse disposition: `adapt`. Preserved source-plan detail: extract and adapt. |
| Integration | volume-virtiofs controller registered by core ProviderDeployment; receives owned-resource-changed trigger from Export; emits Process resources consumed by system-minijail |
| Data migration | Current `ProcessRole::Virtiofsd` dag nodes replaced by Export → Process resource lifecycle |
| Validation | `tests/export_lifecycle.rs`: `export_create_spawns_virtiofsd_process`, `export_ready_when_socket_present`, `export_delete_terminates_virtiofsd`, `export_delete_waits_for_guest_mount_absent`, `export_delete_with_guest_unreachable_holds_finalizer_degraded`, `export_proof_of_ns_death_clears_finalizer`; `tests/multi_attachment.rs`: `two_guests_get_separate_exports_and_processes`, `process_failure_does_not_affect_sibling_export`; `tests/schema_conformance.rs`: `provider_state_set_volume_created_on_install`, `provider_state_set_volume_owner_ref_is_provider`, `provider_state_set_volume_layout_principal_is_user_not_component_principal`, `provider_state_set_no_cross_component_volume_sharing` |
| Removal proof | `ProcessRole::Virtiofsd` branch in `d2bd/src/supervisor/dag.rs` removed only after v3 controller passes all lifecycle tests |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-vvfs-004 - readiness and guest-mount probe

| Field | Value |
| --- | --- |
| Dependency/owner | ADR046-vvfs-003; guest-control integration owner; W2 |
| Current source | `packages/d2bd/src/vm_readiness.rs` (`ReadinessKind::UnixSocketExists`); guest-control vsock health protocol |
| Reuse action | adapt |
| Destination | `packages/d2b-provider-volume-virtiofs/src/readiness.rs`; `packages/d2b-provider-volume-virtiofs/integration/guest_mount_readiness/` |
| Detailed design | `unix-socket-exists` readiness: check file existence at the private socket path via a bounded blocking adapter (e.g., `tokio::task::spawn_blocking` wrapping `fstatat(2)` relative to the zone runtime `OwnedFd`, or an async-safe fd-relative equivalent); no blocking syscall on the async executor thread. Probe period 1 s; timeout 30 s. On socket present → set `Export.status.exportReady: true`. Guest-mount readiness: send `VirtioFsMountReady?` probe to guest-control health endpoint over vsock. Response `MountReady` sets `guestMountReady: true`. Response `MountAbsent` or timeout sets `guestMountReady: false`. The vsock health probe is async-native. If Guest is down, set Export `phase: Unknown`. All readiness probes (unix-socket-exists, guest-mount health) use bounded blocking adapters or async-safe fd-relative equivalents; no blocking I/O on the reconcile executor thread. Primary reuse disposition: `adapt`. Preserved source-plan detail: extract and adapt. |
| Integration | `readiness.rs` called from `controller.rs` reconcile loop; uses toolkit health probe client |
| Data migration | Current `UnixSocketExists` readiness kind adapted to FD-based path resolution |
| Validation | `tests/export_lifecycle.rs` (extended); `integration/guest_mount_readiness/`: virtiofsd launches, socket appears, guest-control probe returns MountReady, guestMountReady flips to true; probe returns MountAbsent on umount |
| Removal proof | Current `UnixSocketExists` readiness path in `d2bd` retired after volume-virtiofs readiness covers all cases |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-vvfs-005 - store-view attachment and marker prerequisite

| Field | Value |
| --- | --- |
| Dependency/owner | ADR046-vvfs-003, ADR046-vvfs-004; ADR046-volume-002 (store-view Volume); W3 |
| Current source | `packages/d2b-host/src/hardlink_farm.rs` (`live_dir()`, marker `live/.d2b-marker-<vm>`, zero-length); `nixos-modules/processes-json.nix` (`roStoreSharedDir` sentinel `share.source == "/nix/store"` → `store-view/live`); `nixos-modules/store.nix` (per-VM hardlink farm) |
| Reuse action | adapt |
| Destination | `packages/d2b-provider-volume-virtiofs/src/controller.rs` (pre-launch prerequisite check); `packages/d2b-provider-volume-virtiofs/integration/store_view_readonly/` |
| Detailed design | Before issuing Process Create for a store-view virtiofs Export, check that `live/.d2b-marker-<guest>` exists (zero-length, correct mode) via a bounded blocking adapter (e.g., `tokio::task::spawn_blocking` wrapping `fstatat(2)` relative to the zone runtime directory, or an async-safe fd-relative equivalent); no blocking syscall on the async executor thread directly. If absent, requeue with exponential backoff. Assert `--shared-dir` resolves to `store-view/live` (the `ro-store` View path), never to `/nix/store`. Validate in `integration/store_view_readonly/` that virtiofsd serves only paths under `store-view/live`. |
| Integration | Pre-launch check in controller.rs; store-view Export recognized by `view == "ro-store"` and `access == "read-only"` |
| Data migration | Current `roStoreSharedDir` redirect in `processes-json.nix` replaced by `ro-store` View definition in the store-view Volume resource |
| Validation | `integration/store_view_readonly/`: mount from guest reads closure paths; no host-store path escapes; `tests/argv_golden.rs`: `store_view_shared_dir_is_live_not_nix_store`; `tests/export_lifecycle.rs`: `store_view_launch_waits_for_marker` |
| Removal proof | `nixos-modules/processes-json.nix` `virtiofsdRunner` block and `roStoreSharedDir` sentinel removed only after store-view virtiofs Export resources pass parity gate |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-vvfs-006 - Nix resource compiler integration and cleanup

| Field | Value |
| --- | --- |
| Dependency/owner | ADR046-vvfs-001, ADR046-volume-004; Nix integrator; W3 |
| Current source | `nixos-modules/processes-json.nix` (virtiofsdRunner block); `nixos-modules/minijail-profiles.nix` (virtiofsdProfiles); `nixos-modules/options-vms.nix` (`d2b.vms.<vm>.shares.*`) |
| Reuse action | adapt |
| Destination | `nixos-modules/resources-volume.nix` (store-view and user Volume attachment emission); `nixos-modules/options-volumes.nix` (optional user-facing volume/attachment options) |
| Detailed design | Extend the Nix resource compiler to: (1) auto-emit a store-view Volume (with `ro-store` and `meta` Views, virtiofs ro-store attachment) per Guest that has a VM runtime Provider; (2) emit virtiofs attachment entries for explicitly configured user Volumes; (3) emit `User/vol-<vol>-vfd` resources for each Volume with virtiofs attachments; (4) emit `Provider/volume-virtiofs` as a Provider resource when any virtiofs attachment is configured. volume-local creates Export resources at runtime (not in Nix bundle); no `virtiofs.d2bus.org.Export` resources appear in the Nix-emitted bundle. All eval validation steps (§16.5) apply. |
| Integration | `nixos-modules/default.nix` wires resources-volume.nix; nix-unit tests verify canonical output |
| Data migration | `d2b.vms.<vm>.shares` virtiofs entries → Volume attachments; `d2b.vms.<vm>` store-view auto-emission replaces `nixos-modules/store.nix` virtiofsd portion |
| Validation | nix-unit: `store_view_volume_auto_emitted_per_guest`, `volume_virtiofs_attachment_canonical_json`, `virtiofs_provider_emitted_when_attachment_configured`, `vfd_user_emitted_per_volume`, `second_read_write_attachment_rejected_at_eval`, `transport_virtiofs_requires_provider_installed`; drift-check gate for `nixos-modules/processes-json.nix` virtiofsdRunner removal |
| Removal proof | `nixos-modules/processes-json.nix` virtiofsdRunner block, `nixos-modules/minijail-profiles.nix` virtiofsdProfiles removed only after Nix resource compiler produces parity output and all nix-unit cases pass |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

---

## 20. Integration test layout

The crate must contain the four mandatory top-level entries required by the workspace policy
gate: `src/`, `tests/`, `integration/`, and `README.md`. The `integration/` directory must
contain at least the four fixture subdirectories listed below, each with a `README.md` and
at least one Rust or shell test driver; empty directories fail the gate.

The `integration/README.md` at `packages/d2b-provider-volume-virtiofs/integration/README.md`
must document each fixture's purpose, run instructions, and prerequisites. No nested
`src/tests/integration/README.md` is required or created.

The four required fixture subdirectories and their coverage obligations:

| Subdirectory | Coverage |
| --- | --- |
| `virtiofsd_launch/` | Spawns a real virtiofsd process (from `pkgs/virtiofsd`) against a local tmpfs Volume. Asserts: process starts; export socket appears within 5 s; process exits cleanly on SIGTERM. Requirements: virtiofsd binary in PATH; `/dev/fuse` accessible. |
| `guest_mount_readiness/` | Uses a container/Host fixture with a running guest-control stub. Asserts: guest-control probe returns `MountReady` after virtiofsd starts; probe returns `MountAbsent` after socket removed. Requirements: podman; network access disabled. |
| `finalizer_drain/` | Simulates Guest restart during Export deletion. Asserts: volume-virtiofs Export finalizer is not cleared while Guest is unreachable and no pidfd proof is available; finalizer is cleared after Guest comes back and confirms `MountAbsent`; finalizer is cleared immediately when pidfd proof of mount-namespace death is present. Requirements: podman; guest-control stub container. |
| `store_view_readonly/` | Mounts a real store-view Volume (tmpfs-backed for CI) via virtiofsd. Asserts: `--shared-dir` resolves to `live/` not `/nix/store`; marker prerequisite gates launch; read-only flag set; no host-store paths accessible. Requirements: virtiofsd binary in PATH; `/dev/fuse` accessible; fake hardlink-farm marker fixture. |

### Fast hermetic execution and test placement (D094)

Per D094 and the repository's test-budget guidance, this Provider's `src/`
unit tests and `tests/*.rs` hermetic suite are fast, in-process, deterministic,
and parallel-safe: an individual normal test has an advisory wall-clock p95
diagnostic threshold of <=50 ms; gate enforcement is aggregate per-crate
process CPU only. There is no wall-clock
sleep, and `cargo test -p d2b-provider-volume-virtiofs --lib --tests` completes in ≤3 s warm-cache
execution time (compilation excluded). They use a deterministic fake clock/RNG
and the toolkit fakes/FakeEffectPort only - no process spawn, container,
network, DBus, systemd, broker daemon, Nix eval/build, KVM, USB/GPU/TPM
hardware, or live cloud, and no filesystem tree beyond tiny temp fixtures. Any
scenario needing those lives only in `integration/`, which keeps a lane
timeout/budget, parallel isolation, and fake external services by default; such
a need is re-placed into `integration/`, never given a sleep, larger timeout,
or `#[ignore]`. Bounded crypto/property tests are the only classified
exception, each named with a capped case count and a declared higher per-test
budget.

---

## 21. Removal proofs

| Current artifact | Removed after | Successor |
| --- | --- | --- |
| `packages/d2b-host/src/virtiofsd_argv.rs` | ADR046-vvfs-001 parity confirmed; argv-shape gate adapted | `packages/d2b-provider-volume-virtiofs/src/virtiofsd_argv.rs` |
| `nixos-modules/minijail-profiles.nix` virtiofsdProfiles block | ADR046-vvfs-006; Process template sandbox spec passes broker-caps gate | `packages/d2b-provider-volume-virtiofs/src/` Process template descriptor |
| `nixos-modules/processes-json.nix` virtiofsdRunner block and `roStoreSharedDir` sentinel | ADR046-vvfs-005, ADR046-vvfs-006; VmProcessDag parity gate passes | Export-owned Process resources reconciled by volume-virtiofs |
| `packages/d2bd/src/supervisor/dag.rs` `ProcessRole::Virtiofsd` branch | ADR046-vvfs-003; Export controller lifecycle covers all virtiofsd spawn/adopt/stop paths | volume-virtiofs Export lifecycle controller |
| `packages/d2b-priv-broker/src/ops/spawn_runner.rs` `adr_carve_out` virtiofsd field | ADR046-vvfs-002; v3 LaunchTicket handles all virtiofsd spawn cases without carve-out | Process spec `sandbox.namespaceClasses: [user]` + system-minijail effect port |
| `packages/d2b-core/src/processes.rs` `ProcessRole::Virtiofsd` enum variant | All volume-virtiofs work items complete; no remaining consumer | Process resource template `virtiofsd-worker` (owned by Export) |

No current path is removed until its resource/controller/Provider successor is integrated,
tested, and confirmed by parity gates. Removal is recorded in the CHANGELOG under the
relevant release section with `managedBy: configuration` confirmation.

Per D094, each replaced current-code test is retired with an explicit
keep/adapt/move/delete disposition and a removal gate: the minimum reusable
semantic assertions migrate into this crate's hermetic `tests/`, and the old
duplicate tests, shell gates, fixtures, static artifacts, CI jobs, and manifest
entries are deleted once successor coverage and the removal proof pass -
updating the fixed Bazel suites, closed gate manifests, flake/Nix-unit pins,
generated ledgers, and CI jobs.
Old and new suites never run in parallel indefinitely.
