# ADR 0046 Provider dossier: Provider/system-minijail

| Field | Value |
| --- | --- |
| Spec ID | `ADR-046-provider-system-minijail` |
| Parent | ADR 0046 |
| Status | Accepted |
| Version | 1 |
| Baseline | `b5ddbed67867d9244bf33390868101bd9b053e49` |
| Main reuse | `a1cc0b2da4a08ca3240a770a972fe4da6f912bef` |
| Normative | Yes |
| Owners | `d2b-provider-system-minijail` crate owner |
| Depends on | `ADR-046-terminology-and-identities`, `ADR-046-resource-object-model`, `ADR-046-resource-api-and-authorization`, `ADR-046-resource-reconciliation`, `ADR-046-components-processes-and-sandbox`, `ADR-046-provider-model-and-packaging`, `ADR-046-primitive-resource-composition`, `ADR-046-resources-host-guest-process-user`, `ADR-046-core-controllers`, `ADR-046-componentsession-and-bus`, `ADR-046-nix-configuration`, `ADR-046-telemetry-audit-and-support` |
| Supersedes | Current `d2b-priv-broker` SpawnRunner, `d2b-core` minijail profile, and `d2bd` supervisor pidfd/wait paths for minijail-spawned processes |
| Related ADRs | ADR 0021 (broker user namespace for virtiofsd), ADR 0011 (cgroup v2 delegation and pidfd handoff), ADR 0003 (minijail provisioning and sandbox interface), ADR 0034 (storage lifecycle for this Provider's zero state) |

---

## 1. Scope

This dossier defines the complete Provider/system-minijail specification: its
purpose, independently buildable crate, bootstrap exception, implemented
ResourceTypes, binaries and component inventory, root config schema, compiled
SandboxSpec contract (namespaces, capability classes, seccomp, mounts, cgroup
placement, user namespace pre-establishment), Process and EphemeralProcess
lifecycle, pidfd ownership and broker-parent wait/reap, adoption and quarantine rules,
restart and stop/finalize, effect port surface (MinijailProcessEffectPort),
d2b-bus RBAC, errors, status additions, audit events, telemetry labels, Nix
authoring examples, hard bounds and performance gates, current-code reuse
ledger, implementation work items, test inventory, and removal proof for every
superseded path.

Provider/system-minijail and Provider/system-systemd are the two Process
Provider implementations in the initial system Provider family. They implement
identical ResourceTypes - `Process` and `EphemeralProcess` - against one common
schema and one shared conformance suite. The compiled sandbox is the only
implementation-specific surface.

**D089 spec extension contract:** this Provider's implementation-only desired
configuration is carried in `spec.provider.settings` under
`system-minijail.d2bus.org/Process/spec` or
`system-minijail.d2bus.org/EphemeralProcess/spec`; each schema is registered/signed
in the manifest, deny-unknown, bounded, versioned, and validated against
`spec.providerRef` at Nix build and API admission. Base fields stay at `spec.*`;
shared semantics are promoted to the Process/EphemeralProcess base and never
placed in `spec.provider`. This Provider implements the exact base spec/status
schema version/fingerprint, accepts the canonical minimal valid base Spec, and
rejects an unsupported optional base capability only through its signed
capability matrix plus provider-neutral `unsupported-capability`.
`spec.provider` aligns with `status.provider` for `Provider/system-minijail`.

---

## 2. Provider identity

| Field | Value |
| --- | --- |
| `providerRef` | `Provider/system-minijail` |
| Crate | `packages/d2b-provider-system-minijail/` |
| Package identity | `system-minijail.d2bus.org` |
| Publisher | `d2bus.org` (first-party) |
| Implemented ResourceTypes | `Process`, `EphemeralProcess` |
| Supported Host/Guest Provider capabilities | `pidfd`, `cgroup-v2`, `user-namespace`, `minijail-seccomp` |
| Supported domains | `system` on any Host or Guest; `user` domain only if the Provider descriptor's conformance extension declares `user-domain-supported: true` for that Host/Guest placement |
| Bootstrap role | Fixed bootstrap controller - one of the two Providers without a Process resource |
| Wait/reap ownership | `d2b` (the privileged broker that called `clone3` and is the process's parent); not the non-parent ProviderSupervisor/controller and not systemd |
| Artifact catalog type | `provider` |

### Linux platform gate

Provider/system-minijail requires Linux **5.14 or newer**. Linux 5.14 is the
first supported baseline because intentional teardown depends on the cgroup v2
`cgroup.kill` file. Host reconciliation must verify the kernel release, a
delegated cgroup v2 leaf, and writable `cgroup.kill` semantics before this
Provider becomes Ready or any Process is placed on it. This mandatory platform
gate applies even when `Host.spec.provider.settings.kernelVersionMin` is null;
an operator may raise that minimum but cannot lower the Provider baseline.
Failure is `kernel-too-old` or `cgroup-kill-unavailable`, and no launch is
attempted. There is no PID/PGID fallback on older kernels.

The Provider crate mandatory layout:

```
packages/d2b-provider-system-minijail/
  src/                  # controller logic, sandbox_compiler, launch, adoption, pidfd observation/status relay, user_ns
  tests/                # hermetic Cargo integration tests
  integration/          # container/Host/Guest/broker integration scenarios
  README.md             # required Provider dossier - this file's canonical prose summary
```

Workspace policy rejects any of these four paths missing (`src/`, `tests/`,
`integration/`, `README.md`). A nested `integration/README.md` is not a
separate workspace-policy requirement. No other Provider
crate may import `d2b-provider-system-minijail` internals outside the declared
public API. The crate may not import another Provider's implementation
internals.

---

## 3. Bootstrap exception

Provider/system-minijail is one of exactly two Provider controllers in a Zone
that are not represented by a `Process` resource. The other is
`Provider/system-core`.

The bootstrap boundary is closed:

- Zone runtime and embedded store/resource API/bus endpoint start first.
- `Provider/system-core` (fixed core-controller) starts as the first process.
- `Provider/system-minijail` (fixed minijail controller) starts as the second
  process.
- Both use the compiled bootstrap authorization.
- system-minijail then launches every other Provider/controller/service/worker
  as a `Process` resource - including `Provider/system-systemd`.

This is the fixed bootstrap exception because no Process controller exists yet
to launch the first Process controller.

### Bootstrap authorization scope

system-minijail does not create Process or EphemeralProcess resources.
Those are created by owning controllers (e.g., `Provider/volume-virtiofs`
creates virtiofsd `Process` resources) or by the configuration publication
handler. system-minijail watches and reconciles existing resources where
`spec.providerRef = Provider/system-minijail`.

The compiled bootstrap authorization - not a stored Role/RoleBinding - grants
system-minijail exactly:

- `Process` get, list, and watch on the local Zone, restricted to resources
  whose `spec.providerRef` equals `Provider/system-minijail`;
- `Process` update-status and update-finalizers on those same resources;
- `EphemeralProcess` get, list, and watch on the local Zone, restricted to
  resources whose `spec.providerRef` equals `Provider/system-minijail`;
- `EphemeralProcess` update-status and update-finalizers on those same
  resources;
- `LaunchTicket` privilege from the fixed ProviderSupervisor;
- effect port calls via the injected `MinijailProcessEffectPort` (opaque
  Process/LaunchTicket/profile/resource IDs only; no broker service/client/DTO
  imported by the Provider crate).

It does not grant:

- `create` or `update-spec` on any ResourceType;
- any resource verb on a remote or parent Zone;
- any `Provider` create/update/delete;
- any `Role` or `RoleBinding` create/update/delete;
- any broker operation beyond what the `MinijailProcessEffectPort` privately
  authorizes; direct access to any broker service, client, or DTO is
  prohibited for the Provider crate;
- any host path, socket, or file descriptor outside the inherited bootstrap FD
  set.

The bootstrap authorization is non-configurable. No config field can widen it.
All bootstrap actions are structurally validated and audited. A wrong subject,
remote route, Provider generation, method, or purpose fails closed.

After the first stored Role/RoleBinding generation is activated, system-minijail
operates under the same native RBAC engine as all other controllers.

---

## 4. Component inventory

Provider/system-minijail contains one controller component and no service or
worker components.

### 4.1 `minijail-controller` (controller)

| Field | Value |
| --- | --- |
| Component ID | `minijail-controller` |
| Type | controller |
| `binaryRef` | `d2b-provider-system-minijail`; the component is `Launchable` (§4.9.3), so the derivation ships `bin/d2b-provider-system-minijail` and declares exactly one `package.executableDigests` entry keyed by that name |
| Exported ResourceTypes | `Process`, `EphemeralProcess` |
| Domain | `system` (default); `user` when descriptor declares `user-domain-supported` |
| Cardinality | 1 per Zone |
| Process placement | Fixed bootstrap; no Process resource parent |
| Config projection | Provider `spec.config` (fixed empty; no configurable fields) |
| State | None - `Provider/system-minijail` declares no Provider state Volume; `ProviderStateSet(zone, "system-minijail")` is empty. Bounded non-secret operational state (reconcile stage, per-Process launch/adoption observations, counters, closed-enum error detail) lives in the owning resource's `status` subresource and the core Operation ledger (D087); persisted restart/backoff/checkpoints are core `Process`/`EphemeralProcess` status and the core Operation ledger; running units are re-adopted from declared cgroup leaves and fresh pidfds. Live pidfds/FDs are process-local and non-persistent. The controller declares no state namespace, mounts no state Volume, and needs no dedicated state-layout `User/<name>` principal (D086 superseded by D087) |
| Permission claims | `Process` get/list/watch/update-status/update-finalizers (where `providerRef=Provider/system-minijail`); `EphemeralProcess` get/list/watch/update-status/update-finalizers (where `providerRef=Provider/system-minijail`); effect port calls via the injected `MinijailProcessEffectPort` (opaque IDs; no broker service/client/DTO imported) |
| Readiness | Ready when bootstrap authorization active, redb connection established, all pending adopted processes verified |
| Drain | Stop dispatching LaunchTickets; wait for inflight ProviderSupervisor operations; close ComponentSession |

There are no service, worker, or separate component binaries in this Provider.
The controller is the only binary entry point.

`Provider/system-minijail` is a bootstrap exception for Process creation only:
the Zone runtime starts its controller without a parent `Process` resource
(§11.3 step 5). It is not an in-process Provider. Unlike
`Provider/system-core`, whose handlers link into the `d2b-core-controller`
binary from another derivation, `system-minijail` builds and ships its own
executable, so its component descriptor carries a `binaryRef`, its artifact
ships a `bin/` directory, and its `package.executableDigests` is non-empty.
The `InProcessBootstrap` arm of `ComponentExecution` is admissible for this
Provider but is not used by it.

## 4.2 Endpoint resources (D092)

`Provider/system-minijail` conforms to the standard `Endpoint` base schema for
its fixed bootstrap controller service. The stable ComponentSession service used
for process launch/control is an owned `Endpoint` resource with `producerRef`;
ProviderSupervisor consumes it as `Endpoint/<name>`. Because the minijail
controller is a bootstrap fixed process rather than a `Process` resource, the
producer is the qualified fixed-controller resource below. Endpoint spec/status
never carries cgroup paths, profile paths, pidfds, fd numbers, socket paths,
Linux namespace details, or credentials. Resolution occurs only through an
authorized EffectPort/LaunchTicket; unauthorized resolution returns
`endpoint-resolve-denied`. Producer restart bumps
`Endpoint.status.endpointGeneration`, causing ProviderSupervisor to observe
`dependency-changed` and reconnect through a fresh authorized ticket.

```yaml
apiVersion: resources.d2bus.org/v3
type: Endpoint
metadata:
  name: system-minijail-process-control
  zone: dev
  ownerRef: Provider/system-minijail
spec:
  providerRef: Provider/system-minijail
  producerRef: system-minijail.d2bus.org/FixedController/minijail-controller
  endpointClass: control
  transport: unix
  purpose: system-minijail.d2bus.org/process-control
  serviceFingerprint: system-minijail.d2bus.org/ProcessControl.v3
  locality: host-local
  visibility: provider
  attachmentPolicy: component-session
  consumerPolicy:
    allowedProviderComponents: [system-core.d2bus.org/provider-supervisor]
    allowedOperations: [resolve]
  lifecyclePolicy: recycle-with-producer
status:
  resource:
    readiness: Ready
    observedProducerGeneration: 1
    observedResourceGeneration: 1
    endpointGeneration: 1
    connectionAvailability: available
    leaseAvailability: lease-required
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

## 4.3 Retained opaque handles (D092 promotion test)

- pidfds for Process/EphemeralProcess supervision are fresh process-local identity
  handles and are never persisted or resolved as resources.
- LaunchTicket fd indexes, cgroup directory fds, namespace/bootstrap fds, and
  inherited listener fds are per-launch attachment slots.
- Minijail profile digests, sandbox plan digests, cancellation tokens, and
  `operationId` values remain opaque verification/idempotency handles.
- `OwnedTransport`, ComponentSession IDs, and bootstrap IKpsk2/enrolled KK session
  handles are in-memory session capabilities behind Endpoint resolution.

---

## 5. Root config schema

`Provider/system-minijail` has a fixed empty, non-configurable `spec.config =
{}`. There are no operator-settable fields.

`Provider/system-minijail` declares **no** Provider state Volume for its
`minijail-controller` component. `ProviderStateSet(zone, "system-minijail")` is
the optional, query-time grouping of the *declared* Volume resources carrying
`ownerRef: Provider/system-minijail`; it is not a ResourceType or stored
artifact and is empty. Bounded non-secret operational state belongs in the
owning resource's `status` subresource and the core Operation ledger by default
(D087): persisted restart counts, backoff state, and operational checkpoints are
core resource/operation state (Process status and checkpoint records owned by
the resource API), not Provider-owned private state. Live pidfds and in-flight
FDs are process-local and non-persistent.

Because the `minijail-controller` component holds no durable payload that passes
the storage-need test - its operational state is fully derivable from spec,
`status`, the core Operation ledger, and external observation (running Processes
re-adopted from declared cgroup leaves and fresh pidfds) - it declares no state
namespace, no state Volume, no state-view mount, and no dedicated state-layout
`User/<name>` principal. There is no empty identity-only Volume.

### 5.1 No bootstrap-state exception

`Provider/system-minijail` is a fixed bootstrap controller that starts before
`Provider/volume-local` is ready. Because it declares no state Volume and
reaches Ready from resource `status`, the core Operation ledger, and external
process observation, it needs no state Volume before volume-local is ready - so
there is no bootstrap state-Volume cycle, no closed bootstrap storage mechanism,
no bootstrap `dirfd` delivery, and no bootstrap-storage exception (D086,
superseded by D087; see "No bootstrap state Volume" in
`ADR-046-components-processes-and-sandbox`). There is no hidden bootstrap store,
and no new public resource type, d2b-bus service, or broker operation is
introduced.

Process lifecycle defaults (drain timeout, restart backoff base/max) and
resource-level bounds (per-process `startDeadline`, `runtimeDeadline`, TTL
limits) are declared in the `Process` or `EphemeralProcess` spec by the owning
controller or configuration author. The fixed signed manifest owns concurrency
bounds and capability constraints; they are not operator-configurable.

No executable path, UID/GID, seccomp BPF program, minijail argument string,
cgroup path, socket address, or credential byte is a Provider config field.

---

## 6. Implemented ResourceTypes

### 6.1 `Process`

Provider/system-minijail implements the full `Process` ResourceType defined in
`ADR-046-resources-host-guest-process-user`. The common spec, common status,
common conditions, and common reconcile/finalize algorithm all apply without
modification. This section documents only minijail-specific behavior.

Selecting `Provider/system-minijail`:

```yaml
spec:
  providerRef: Provider/system-minijail
  executionRef: Host/host-system   # or Guest/<name>
  domain: system
  template: virtiofsd              # plain component template ID
  sandbox:
    namespaceClasses: [user, mount, pid]
    capabilityClasses: []
    seccompClass: strict
    noNewPrivileges: true
    startRoot: false
    environmentClass: minimal
    readOnlyRoot: true
    userNamespace:
      mappingClass: process-principal-root
```

`waitReapOwner` in status is always `"d2b"` for processes under this Provider;
the value means the process's privileged-broker parent, not the Provider
controller.

### 6.2 `EphemeralProcess`

Provider/system-minijail implements the full `EphemeralProcess` ResourceType.
`processClass` must be `worker`. All EphemeralProcess spec/status fields are
as defined in `ADR-046-resources-host-guest-process-user`. This section
documents only minijail-specific behavior.

`waitReapOwner` in status is always `"d2b"` and identifies the
privileged-broker parent as the sole wait/reap owner.

EphemeralProcess does not use `adoptionPolicy` or `adoptionState`. On a
controller restart, the controller attempts **continuation recovery** through
ProviderSupervisor. It locates the running one-shot by cgroup leaf membership,
reverifies its identity, and obtains a fresh duplicate pidfd from the still-live
broker parent. ProviderSupervisor may poll that pidfd for readability as a
liveness hint, but only the broker calls `waitid(P_PIDFD, ...)`, collects the
exit status, and reaps the child. The controller consumes the broker-relayed
terminal status. If identity verification and broker-parent ownership pass, the
EphemeralProcess remains in `Running` phase (no relaunch). If the candidate,
parent ownership, or terminal status is ambiguous, the EphemeralProcess is
written to `Unknown` phase and quarantined; it is never auto-TTL-cleaned while
the process may still be live or ambiguous. The operator resolves ambiguity
through normal resource management or a full Zone reset.

---

## 7. SandboxSpec compilation

The `SandboxSpec` in a Process or EphemeralProcess spec declares semantic
requirements. Provider/system-minijail compiles these into a verified
implementation-specific plan before spawning. The compiled plan's digest is
stored in `status.sandboxRevisionDigest`.

No raw capability bitmask, seccomp BPF bytecode, minijail argument string,
mount table row, or cgroup path fragment escapes the compilation step into any
public resource field, status, audit payload, log line, or metric label.

### 7.1 Namespace classes

`SandboxSpec.namespaceClasses` selects which Linux namespaces are new for the
spawned process. An empty list inherits all parent namespaces.

| `NamespaceClass` value | Linux namespace | Notes |
| --- | --- | --- |
| `user` | `CLONE_NEWUSER` | Requires `SandboxSpec.userNamespace` to be set; see §7.7. Cannot combine with `startRoot: false` on a plain system-domain process unless `userNamespace` is set. |
| `pid` | `CLONE_NEWPID` | Spawned process is PID 1 inside the namespace. |
| `mount` | `CLONE_NEWNS` | Required for read-only root or custom mount table. |
| `ipc` | `CLONE_NEWIPC` | Isolates SysV IPC and POSIX message queues. |
| `uts` | `CLONE_NEWUTS` | Isolates hostname and NIS domain. |
| `network` | `CLONE_NEWNET` | Isolates network interfaces; used only for fully network-isolated workers. Not used when the Process has a `networkUsage` ref to an active Network resource. |
| `cgroup` | `CLONE_NEWCGROUP` | New cgroup namespace. Not used when the broker must place the process into a pre-delegated cgroup leaf. |
| `time` | `CLONE_NEWTIME` | New time namespace. Available throughout this Provider's Linux ≥5.14 platform baseline. |

Combinations that the compiler rejects at spec admission:

- `user` without a `userNamespace` block;
- `network` combined with a non-null `networkUsage.networkRef`;
- `cgroup` when `Host.spec.provider.settings.capabilities` does not include
  `cgroup-v2`.

### 7.2 Capability classes

`SandboxSpec.capabilityClasses` selects semantic capability grants. The compiler
translates each class to the smallest Linux capability set needed. An empty
class list means no capabilities beyond the user-domain base set.

The capability class enumeration is closed. The Provider adds no value to this
list without a descriptor update approved in the Provider's provider-dossier
change.

| `CapabilityClass` value | Compiled to | Restriction |
| --- | --- | --- |
| `network-bind` | `CAP_NET_BIND_SERVICE` | Permitted for service processes needing ports <1024. |
| `network-raw` | `CAP_NET_RAW` | Requires explicit Provider descriptor carve-out. |
| `network-admin` | `CAP_NET_ADMIN` | Requires explicit Provider descriptor carve-out. Denied in user domain. |
| `sys-time` | `CAP_SYS_TIME` | Requires explicit Provider descriptor carve-out. |
| `sys-ptrace` | `CAP_SYS_PTRACE` | Requires explicit Provider descriptor carve-out. |
| `sys-admin` | `CAP_SYS_ADMIN` | Requires explicit Provider descriptor carve-out. Denied in user domain. Requires `startRoot: true`. |
| `dac-override` | `CAP_DAC_OVERRIDE` | Permitted for processes needing file access beyond DAC. |
| `fowner` | `CAP_FOWNER` | Permitted for file ownership operations. |
| `chown` | `CAP_CHOWN` | Permitted for chown. |
| `setuid` | `CAP_SETUID` | Permitted for privilege drop after exec. Denied in user domain. |
| `setgid` | `CAP_SETGID` | Permitted for privilege drop after exec. Denied in user domain. |
| `audit-write` | `CAP_AUDIT_WRITE` | Permitted only for system-domain worker processes with explicit carve-out. |
| `kill` | `CAP_KILL` | Permitted for narrow inter-process signal use. |

For virtiofsd-class processes (those with `userNamespace` set), the compiled
capability set is always empty in the host capability set. All required
capabilities run inside the user namespace as namespace-scoped grants, not as
host capabilities. This preserves the ADR 0021 zero-host-capability invariant.
See §7.7.

### 7.3 Seccomp classes

`SandboxSpec.seccompClass` selects the seccomp policy. Values:

| Value | Meaning |
| --- | --- |
| `strict` | Minimal allow-list compiled from the process class (`controller`, `service`, `worker`) and the owning Provider component's declared syscall profile. Default for all processes. |
| `permissive` | Log-only; all syscalls permitted but audited. Requires explicit Provider descriptor carve-out. Never used in production without carve-out approval. |
| `allow-all` | No seccomp filter. Requires explicit Provider descriptor carve-out and is rejected unless the descriptor declares `seccomp-allow-all-permitted: true`. |
| `<provider-class>` | Named profile from the Provider's compiled seccomp catalog (e.g., `virtiofsd`, `swtpm`, `security-key`). Resolved at compilation time to a versioned seccomp plan digest. |

Raw BPF programs are not accepted. The compiled seccomp plan is a broker-owned
artifact addressed by its digest. The digest is stored in
`status.sandboxRevisionDigest` together with the namespace and capability plan
digests.

### 7.4 Mount compilation

`Process.spec.mounts` declares Volume mounts. For each `MountSpec` entry:

1. The controller verifies the `volumeRef` target is `Ready`.
2. The `view` field selects a named view from the Volume's declared view table.
3. The `mountPath` is an absolute path inside the sandbox.
4. The `access` field (`read-only` or `read-write`) is enforced at mount time.

The broker translates the compiled mount table into a set of bind-mount
operations applied after namespace setup. No caller-supplied absolute host path
reaches the broker. All source paths come from the Volume Provider's
implementation through the trusted ProviderSupervisor ticket. A mount whose
Volume is not Ready at launch time and whose `required: true` aborts the launch
with `volume-not-ready`.

### 7.5 Environment classes

`SandboxSpec.environmentClass` selects what environment the process receives:

| Value | Meaning |
| --- | --- |
| `minimal` | Fixed approved environment set only. Enforced at the broker exec site. No inherited variables. Default. |
| `safe-inherited` | Inherits the declared safe subset from the owning Provider's component template. The safe subset is a static allow-list signed into the component descriptor. |
| `provider-defined` | The Provider's component template defines the exact environment. No caller extension is accepted. |

No environment variable from a caller resource payload reaches exec without
passing through the trusted bundle compilation step. Credential bytes, raw
paths, and socket addresses are not environment variables.

### 7.6 cgroup placement

The broker places the process directly into its declared cgroup leaf using
`CLONE_INTO_CGROUP`. This means the process is born in its final cgroup before
any instruction executes. The cgroup leaf path follows the shape defined in
`ADR-046-components-processes-and-sandbox`:

```text
z-<zone-id>/
  executions/
    e-<execution-id>/
      system/
        providers/
          p-<provider-id>/
            components/
              c-<component-id>/
                process/
```

Intermediate cgroup nodes are process-free. The cgroup leaf is created by the
broker under the delegated cgroup subtree before clone3 is called. After process
exit and pidfd-confirmed reap, the broker removes the leaf.

The compiled cgroup path is never a public resource field, status field, log
line, audit payload, or metric label.

### 7.7 User namespace pre-establishment (ADR 0021 model)

For processes whose `SandboxSpec.userNamespace` is set, the broker
pre-establishes a single-entry user namespace before the process's first
instruction runs. This implements the ADR 0021 zero-host-capability contract
for virtiofsd-class processes.

Pre-establishment sequence:

1. Broker calls `clone3(CLONE_NEWUSER | CLONE_PIDFD | CLONE_INTO_CGROUP)` with
   the target cgroup leaf FD and `CLONE_PIDFD` to obtain the pidfd atomically.
2. The child process blocks on a pipe sync (reading before exec).
3. The effect port resolves the exact host principal UID from `mappingClass`
   (e.g., `process-principal-root` maps to the component principal UID declared
   in the Provider descriptor for this process) and writes
   `/proc/<child-pid>/uid_map` mapping that UID to in-namespace UID 0. The
   Provider crate never observes the numeric host UID.
4. Likewise for `/proc/<child-pid>/gid_map`: the effect port resolves the GID
   from `mappingClass` and writes it privately. The resolved GID must not be 0
   (host root); the effect port enforces this before any write.
5. The broker writes the pipe sync byte, unblocking the child.
6. The child proceeds to exec the target binary.

The result: the process runs as in-namespace UID/GID 0 and may hold
in-namespace capabilities without holding any host capabilities. The host
capability set for this process is zero.

`UserNamespaceSpec.mappingClass` is validated at spec admission:

- `process-principal-root` is the only defined value in the initial enumeration.
  Additional values require a descriptor update.
- At spawn time, the effect port resolves the exact host UID/GID from
  `mappingClass` by looking up the component principal declared in the Provider
  descriptor. The resolved UID/GID must not be 0 (host root); the effect port
  enforces this invariant before writing uid_map/gid_map. The Provider crate
  never receives or stores the numeric host UID or GID; numeric IDs are confined
  to the effect port implementation (core/ProviderSupervisor).

The parent name-to-inode bindings for the uid_map/gid_map writes are
revalidated: the broker does not follow symlinks and rejects any interposition
attempt between the `/proc` open and the writes.

This model applies universally to all processes requesting `user` in
`namespaceClasses`. Non-user-namespace processes never receive a user namespace,
regardless of any `SandboxSpec` combination.

---

## 8. Process lifecycle

### 8.1 LaunchTicket

The Process controller authenticates a `LaunchTicket` from the
ProviderSupervisor. The ticket is bound to:

- `Process`/`EphemeralProcess` ResourceRef, UID, spec generation, revision;
- owning Provider/component/template name and digest;
- `executionRef`, domain, and resolved `userRef`;
- selected Process Provider (`Provider/system-minijail`);
- compiled sandbox plan digest (covering namespace, capability, seccomp, mount,
  environment, userNamespace, rlimit, umask, oom classes);
- compiled budget/cgroup placement digest;
- compiled mount table digest;
- compiled network/device/endpoint configuration digest;
- inherited FD table (only the fixed bootstrap or explicitly authorized set);
- operation ID, deadline, and cancellation token;
- expected process identity and readiness predicate.

The ProviderSupervisor:

1. Verifies the ticket against the current Process/EphemeralProcess resource
   generation and controller lease.
2. Resolves only trusted package/template/resource outputs. No caller payload
   field reaches exec unvalidated.
3. Calls the injected `MinijailProcessEffectPort` with opaque
   Process/LaunchTicket/profile IDs to request process spawn.
4. Returns the stable `processIdentityDigest` to the controller.

### 8.2 Spawn via MinijailProcessEffectPort

The minijail controller calls the injected `MinijailProcessEffectPort` with
opaque Process/LaunchTicket/profile/resource IDs. The Provider crate imports no
broker service, client, or DTO. The effect port, owned by core/ProviderSupervisor,
privately resolves these IDs and delegates to the privileged broker, which
remains the sole executor and audit owner of all privileged effects. The broker:

1. Validates the request against the compiled sandbox plan digest and the
   trusted bundle.
2. Verifies the executable path, executable hash, template generation, declared
   UID/GID, and cgroup placement before any exec call.
3. Creates the cgroup leaf under the delegated subtree.
4. Calls `clone3(CLONE_PIDFD | CLONE_INTO_CGROUP)` with the exact cgroup leaf
   FD to place the process directly in its cgroup. `CLONE_PIDFD` ensures the
   pidfd is obtained atomically at spawn time with no PID-reuse race.
5. For user-namespace processes: additionally passes `CLONE_NEWUSER` and
   performs the uid_map/gid_map pre-establishment (§7.7) before releasing
   the pipe sync.
6. Retains its parent-held pidfd and the sole wait/reap record. It returns a
   duplicate pidfd to ProviderSupervisor through the private, local effect-port
   attachment path for readiness polling and exact-main-process signaling. No
   raw pidfd reaches the Provider controller, d2b-bus, ComponentSession, ttrpc,
   status, audit, logs, or metrics.

The broker rejects any request that does not match the precompiled and
broker-verified plan digest. No environment variable, mount, capability, or
argument fragment from the caller resource payload reaches exec without passing
through this compilation step.

### 8.3 Pidfd ownership and wait/reap

d2b's privileged broker owns wait/reap for every process it spawns under this
Provider. The broker is the `clone3` caller and therefore the kernel parent; it
alone may call `waitid(P_PIDFD, ...)`, collect `siginfo_t`/exit status, and reap
the child. ProviderSupervisor and the Provider controller are non-parents.

Pidfd rules (invariant across all Process Providers; violation is a
`runtime-security-violation` audit event):

1. Every launched process has a broker-parent pidfd obtained atomically from
   `clone3(CLONE_PIDFD)`. The broker keeps it until the child has been reaped
   exactly once.
2. The pidfd is acquired only after the effect port (via the broker) verifies
   stable process identity: executable hash, template generation, cgroup
   placement, and provider-specific identity attributes.
3. The pidfd is never serialized to disk, never written to the resource store,
   never sent over d2b-bus, ComponentSession, or ttrpc, and never exposed in
   public status or audit payload.
4. ProviderSupervisor may hold a duplicate pidfd. It may use `AsyncFd`, `poll`,
   or an equivalent readiness mechanism to observe readability, but readability
   is only a terminal-liveness hint: it is not a wait, reap, or exit-status
   result. ProviderSupervisor never calls `waitid`/`waitpid` for this child.
5. The broker relays one typed terminal result, bound to the Process identity
   and operation, after its successful `waitid(P_PIDFD, ...)`. Only that result
   supplies `lastExitClass` or `outcome.exitCode`; the controller never derives
   either from pidfd readability.
6. A holder of a currently verified pidfd (the broker or ProviderSupervisor)
   may call `pidfd_send_signal` for the exact main process without being its
   parent. The Provider controller requests that effect through its opaque
   handle and never receives the raw fd. There is no PID, process-group, or PGID
   signaling fallback.
7. On ProviderSupervisor restart, its duplicate is closed and reacquired only
   after full re-verification. A Provider-controller restart does not transfer
   or invalidate the broker's parent-held pidfd; the controller merely
   reconnects to the broker-relayed status stream.
8. On continuation recovery, ProviderSupervisor locates the candidate process
   by cgroup leaf, verifies all stable identity fields against the stored
   `processIdentityDigest`, and requests a fresh duplicate pidfd from the
   still-live broker parent. See §8.5. A replacement broker that is not the
   child's parent cannot assume wait/reap ownership.

The broker drives `waitid(P_PIDFD, ...)` outside the Provider watch loop and
relays completion without a controller polling interval. ProviderSupervisor
may independently poll its duplicate to promptly request the broker result, but
must tolerate readability before the relay arrives and must not synthesize an
exit status.

All operations that involve blocking or latency-unbounded syscalls - including
pidfd duplication/re-verification, `/proc/<pid>/stat` reads, executable hash
computation, cgroup filesystem enumeration (leaf existence, occupant
detection), and broker terminal-status retrieval - are dispatched through a
bounded blocking adapter (`spawn_blocking` or equivalent) with an explicit
timeout, so the controller watch loop is never blocked. Adapter timeouts are
treated as adoption failures or launch errors, not silent hangs.

On broker-relayed wait completion:

- Exit code is recorded internally as the basis for `lastExitClass` and
  `outcome.exitCode` (EphemeralProcess).
- The cgroup leaf is released only after it is observed unpopulated. A
  lingering owned descendant is drained through §8.6 before restart or rmdir.
- ProviderSupervisor closes its duplicate; the broker closes its pidfd only
  after successful reap.
- The restart or finalize path is dispatched.

Neither ProviderSupervisor, the Provider controller, nor systemd owns wait/reap
for any process under this Provider.

### 8.4 Restart and backoff

For `Process` resources with `restartPolicy: always` or `restartPolicy:
on-failure`:

1. On process exit, classify exit: `clean-exit`, `crash`, `signal`,
   `timeout`, `unknown`.
2. Apply `restartPolicy` logic: `on-failure` skips restart on `clean-exit`.
3. Apply exponential backoff: starting at `restartPolicy.backoffBase` (Process
   spec field; e.g., `"1s"`), doubling on each consecutive crash, capped at
   `restartPolicy.backoffMax` (Process spec field; e.g., `"5m"`; maximum `"1h"`).
4. Backoff is reset to zero after a process has been running for at least one
   backoff period without exiting.
5. If `maxRestarts` is set and exceeded: write `Failed` phase;
   `reason: max-restarts-exceeded`; stop restarting.
6. Each restart increments `status.restartCount` and updates
   `status.lastRestartAt`.

`status.lastExitClass` and `status.adoptionState` are updated on each restart.

For `restartPolicy: never`: no restart. Write final phase `Succeeded` (if
`clean-exit`) or `Failed` (any other).

### 8.5 Adoption after controller restart

When the controller restarts, it performs adoption for each `Process` resource
whose `adoptionPolicy: adopt-on-restart` and current phase is non-terminal. A
controller restart is not a parent change: the still-live broker remains the
spawned process's parent and sole wait/reap owner.

Adoption algorithm:

1. Locate the candidate process by cgroup leaf path. The cgroup leaf path is
   derived from the stable UID/generation/zone identifiers, not stored on disk.
2. Via a bounded blocking adapter with an explicit timeout: read
   `/proc/<pid>/stat` bytes to obtain the start-time token and PID; verify
   cgroup membership (no migration during adoption window).
3. Verify that the start-time token, executable identity, and cgroup membership
   match the `processIdentityDigest` stored in the resource status.
4. Via a bounded blocking adapter: compute the executable content hash and
   verify it against the Provider template/bundle digest.
5. Verify that the broker serving the operation is the original recorded
   `clone3` parent and still owns the unreaped child record.

All steps 2-5 run outside the watch-loop task. A blocking-adapter timeout is
treated as an adoption failure (ambiguous result), not a clean success.

If all checks pass, ProviderSupervisor obtains a fresh duplicate pidfd from the
broker through the private effect-port attachment path. It may poll that
duplicate and use it for `pidfd_send_signal`; the broker remains the only
wait/reap owner. Set `adoptionState: adopted`. Continue supervising.

If any check fails, the broker-parent relationship is lost, or the result is
ambiguous:

- Set `adoptionState: quarantined`.
- Do **not** attempt to kill the process.
- Do **not** reuse the PID or cgroup leaf.
- Write `Degraded` phase with reason `adoption-ambiguous` or
  `adoption-identity-mismatch`.
- Emit a `runtime-security-violation` audit event (see §12).
- Await operator review.

A quarantined process is invisible to the controller. The controller does not
send signals, claim the cgroup leaf, or allocate new resources under the
quarantined identity. Quarantine **cannot** be resolved by deleting and
recreating the Process resource while the process may still be alive. Before
the controller will accept a new finalizer registration or reuse the cgroup
leaf, the operator must establish - through means external to d2b - that the
process is definitively absent (e.g., by confirming via OS-level inspection
that no process occupies the cgroup leaf and the leaf is empty). Alternatively,
the operator may perform a destructive full Zone reset, which terminates all
resident Zone processes. d2b never sends any signal to a quarantined or
ambiguous process identity.

When `adoptionPolicy: never-adopt`, no adoption attempt is made. A prior
running process whose cgroup leaf still exists after restart is quarantined
automatically per the ambiguous-identity path above (the controller will not
claim it as fresh).

### 8.6 Stop and finalize

The owning Provider controller registers finalizer
`process-system-minijail.d2bus.org/cleanup` on every Process and EphemeralProcess it
manages.

Finalizer algorithm on `deletion-requested`:

1. Reverify the exact main-process pidfd, broker-parent record, and anchored
   cgroup leaf identity. If any ownership proof is ambiguous, take the
   quarantine path below without signaling or writing `cgroup.kill`.
2. Request `SIGTERM` for the exact main process through
   `pidfd_send_signal`. The verified broker or ProviderSupervisor pidfd holder
   may perform the syscall; parenthood is not required for signaling. Wait up
   to `drainTimeout` (Process spec field; default `"10s"`; maximum `"300s"`) for
   the broker-relayed terminal status and graceful subtree drain.
3. After the main process exits or the grace deadline expires, the broker
   writes `1` to the anchored leaf's cgroup v2 `cgroup.kill`. This is mandatory
   for an intentional stop/finalize, including the case where the main process
   exited but left descendants. It terminates the owned subtree regardless of
   `setsid(2)` or process-group changes and creates no PGID-reuse race.
4. Wait boundedly for `cgroup.events` to report `populated 0` and for the
   original broker parent to relay its successful `waitid(P_PIDFD, ...)`
   result for the main child. Pidfd readability alone is not exit proof.
5. Only after both proofs, remove the leaf directory under the delegated
   subtree. No PID/PGID SIGKILL fallback is permitted.
6. Release any OFD locks/leases held by this process (through the Volume
   Provider, not directly by this Provider).
7. Clear the finalizer.

On ambiguous state (pidfd closed unexpectedly, broker no longer the parent,
cgroup identity mismatch, `cgroup.kill` unavailable/failing, leaf not becoming
unpopulated, or broker wait/reap status not confirmed), the finalizer is
**retained**; the resource is written to `Degraded` or `Unknown` phase with
condition `process-exit-unconfirmed`. No signal and no `cgroup.kill` write is
issued to an ambiguously owned candidate. The finalizer is never cleared
without both exact broker-relayed main-process exit proof and empty-leaf proof.
The resource remains in this state until ownership/exit is confirmed or the
operator performs a full Zone reset. Recording a success-shape finalized result
without those proofs is prohibited.

---

## 9. EphemeralProcess one-shot lifecycle

An `EphemeralProcess` under Provider/system-minijail follows the same spawn
path as a `Process` - LaunchTicket, ProviderSupervisor, broker
`clone3(CLONE_PIDFD | CLONE_INTO_CGROUP)`, pidfd ownership - but has no
restart, no adoption, and a terminal TTL.

One-shot lifecycle:

1. Spec admitted and committed: phase `Pending`.
2. All dependencies Ready; `startDeadline` countdown starts.
3. LaunchTicket dispatched: condition `Launching`.
4. Process starts: condition `Running`.
5. Process exits within `runtimeDeadline`:
   - exit 0 → phase `Succeeded`, `outcome.code: process-exited`,
     `outcome.exitCode: 0`.
   - non-zero → phase `Failed`, `outcome.code: process-exited`,
     `outcome.exitCode: <N>`.
   - killed by signal → `outcome.code: process-crashed`.
6. `startDeadline` exceeded without start: phase `Failed`,
   `outcome.code: start-deadline-exceeded`.
7. `runtimeDeadline` exceeded while running: use the §8.6 intentional-stop
   sequence (exact-main `SIGTERM`, bounded grace, mandatory leaf
   `cgroup.kill`, broker wait/reap, empty-leaf proof); phase `Failed`,
   `outcome.code: runtime-deadline-exceeded`.
8. After terminal phase: cleanup controller computes `cleanupEligibleAt`:
   - `Succeeded`: `completedAt + successfulTtl`.
   - `Failed`: `completedAt + failedTtl`.
9. When `cleanupEligibleAt <= now()`, no `incidentHold`, no active finalizers:
   normal `Delete` called with expected revision.
10. The resource row and index entry are removed atomically; the `ResourceDeleted`
    audit event is appended afterward with dedup (so the audit record is the
    final observable event, appended after removal, not the trigger for removal).

Controller restart during a running EphemeralProcess triggers **continuation
recovery**: ProviderSupervisor locates the one-shot by cgroup leaf membership,
reverifies its process identity and original broker-parent record, and obtains
a fresh duplicate pidfd from that broker. ProviderSupervisor may poll
readability; the broker alone waits/reaps and relays the exact exit status. The
EphemeralProcess remains in `Running` phase while verification succeeds (no
relaunch). If the candidate or parent relationship is ambiguous, verification
fails, or broker-relayed terminal status cannot be obtained, the
EphemeralProcess is written to `Unknown` phase and quarantined; it is **never**
auto-TTL-cleaned while the process may still be live or ambiguous.
`adoptionPolicy`/`adoptionState` do not apply; the term for this recovery is
**continuation recovery**, not adoption.

---

## 10. d2b-bus and ComponentSession

Provider/system-minijail communicates exclusively through d2b-bus over
ComponentSession. It does not hold a direct redb handle, an HTTP control plane,
or an ambient non-bus socket.

### 10.1 Session profile

The minijail controller uses the enrolled KK (`Noise_KK_25519_ChaChaPoly_SHA256`)
session profile for all post-bootstrap d2b-bus connections:

- Both static public keys known before handshake.
- Local private key is sealed/zeroizing.
- Static key registry maps the authenticated key to the `Provider/system-minijail`
  Zone-local subject.
- Prologue binds purpose, service package and schema fingerprint, route,
  limits, and reconnect generation.

During bootstrap, the one-time IKpsk2 (`Noise_IKpsk2_25519_ChaChaPoly_SHA256`)
session is used to authenticate the initial connect before enrollment:

- Single-use PSK bound to operation ID, replay nonce, expected subject, and
  expiry.
- PSK is consumed exactly once.
- Successful enrollment replaces bootstrap with an enrolled KK session.

### 10.2 Services used

| Service | Method/stream | Purpose |
| --- | --- | --- |
| `d2b.resource.v3` | `Watch`, `List`, `Get` | Watch/list Process and EphemeralProcess resources assigned to this controller instance |
| `d2b.resource.v3` | `UpdateStatus` | Write Process/EphemeralProcess status transitions |
| `d2b.resource.v3` | `UpdateFinalizers` | Clear finalizer after process exit |
| `d2b.resource.v3` | `Delete` | Delete EphemeralProcess after TTL expiry |
| `d2b.resource.v3` | `CommitBatch` | Batch status + finalizer updates in one Zone transaction |
| `d2b.controller.v3` | `RegisterController` | Register controller descriptor and watch plan |
| `d2b.controller.v3` | `ReportCheckpoint` | Report watch high-water mark |
| `d2b.supervisor.v3` | `IssueLaunchTicket`, `ReportSpawnResult`, `ReportExitEvent` | ProviderSupervisor ticket/result/exit protocol |

### 10.3 Fast path contract

After a Process resource is durably committed with all dependencies Ready:

- Store post-commit dispatcher emits a controller hint immediately after
  commit returns.
- p95 from durable commit to controller handler start: ≤5 ms.
- p95 from durable commit to launch attempt start: ≤20 ms.
- The controller launches the process in an independent async task without
  blocking the watch loop.
- The watch loop dispatches the next independent Process immediately.
- Status transitions (hint received → Launching → Ready) are async
  `UpdateStatus` calls with expected-revision preconditions; they do not hold
  the watch loop.

---

## 11. RBAC and broker operations

### 11.1 RBAC verbs on managed ResourceTypes

| Verb | ResourceType | Required grant | Notes |
| --- | --- | --- | --- |
| `get` | Process | `{resourceTypes:[Process], verbs:[get]}` | - |
| `list` | Process | `{resourceTypes:[Process], verbs:[list]}` | - |
| `watch` | Process | `{resourceTypes:[Process], verbs:[watch]}` | Controller watch stream |
| `create` | Process | `{resourceTypes:[Process], verbs:[create], executionRefs:[Host/<n>]}` | Config publication handler or owning controller only; **not** a bootstrap grant for system-minijail itself |
| `update-spec` | Process | `{resourceTypes:[Process], verbs:[update-spec]}` | Config publication handler or owning controller only; **not** a bootstrap grant for system-minijail itself |
| `update-status` | Process | `{resourceTypes:[Process], verbs:[update-status]}` | system-minijail controller only |
| `update-finalizers` | Process | `{resourceTypes:[Process], verbs:[update-finalizers]}` | system-minijail controller only |
| `delete` | Process | `{resourceTypes:[Process], verbs:[delete]}` | Blocked while finalizer exists |
| `get` | EphemeralProcess | `{resourceTypes:[EphemeralProcess], verbs:[get]}` | - |
| `list` | EphemeralProcess | `{resourceTypes:[EphemeralProcess], verbs:[list]}` | - |
| `watch` | EphemeralProcess | `{resourceTypes:[EphemeralProcess], verbs:[watch]}` | - |
| `create` | EphemeralProcess | `{resourceTypes:[EphemeralProcess], verbs:[create], executionRefs:[Host/<n>]}` | Owning controller only; **not** a bootstrap grant for system-minijail itself |
| `update-status` | EphemeralProcess | `{resourceTypes:[EphemeralProcess], verbs:[update-status]}` | system-minijail controller only |
| `update-finalizers` | EphemeralProcess | `{resourceTypes:[EphemeralProcess], verbs:[update-finalizers]}` | system-minijail controller only |
| `delete` | EphemeralProcess | `{resourceTypes:[EphemeralProcess], verbs:[delete]}` | Cleanup controller after TTL; blocked while `incidentHold` or active finalizers |

The `incident-hold-release` sub-verb is required to set `spec.incidentHold: false`
on an `EphemeralProcess` in `Failed` phase.

### 11.2 Effect port and broker operations

The minijail controller calls the injected `MinijailProcessEffectPort` with
opaque IDs; it does not hold a `d2b.broker.v3` connection and imports no broker
service, client, or DTO. The effect port implementation, owned by
core/ProviderSupervisor, privately invokes the following broker operations. The
broker remains the sole executor and audit owner:

| Operation | Purpose | Authority |
| --- | --- | --- |
| `SpawnRunner` | Clone3-spawn of a Process/EphemeralProcess with a pre-compiled sandbox plan | Scoped to the zone-delegated cgroup subtree and pre-verified plan digest |
| Broker wait/reap and terminal-status relay | Parent-only `waitid(P_PIDFD, ...)`, exact-once reap, and typed exit-status delivery to ProviderSupervisor | Only for the broker's own `clone3` children; non-parent callers cannot invoke wait/reap |
| User namespace uid_map/gid_map write | Write UID/GID mapping for user-namespace processes | Broker-internal; always part of SpawnRunner when `userNamespace` is set |
| Cgroup leaf create/observe | Create and manage the cgroup leaf for each process | Delegated cgroup subtree only; broker validates path against `z-<zone-id>/` prefix |
| Cgroup leaf kill | Write `1` to the anchored leaf's `cgroup.kill` after graceful exact-main signaling for an unambiguous intentional stop | Exact verified owned leaf only; Linux ≥5.14; forbidden for ambiguous/quarantined candidates |
| Cgroup leaf release | Remove cgroup leaf on process exit | Same delegation scope |

No direct path exists from the Provider crate to the broker socket. The
`MinijailProcessEffectPort` enforces the boundary: all spawn effects are carried
by opaque identifiers, and the effect port resolves them privately.

The broker exposes no arbitrary host-global operations through the effect port.
The broker's host-global mutation authority (firewall, network, device, storage)
is not available to this Provider.

The minijail controller writes status only on `Process` and `EphemeralProcess`
resources. `Provider/system-minijail` resource status is aggregated by core from
checkpoint and health events reported via `d2b.controller.v3`; the minijail
controller has no `Provider` update-status grant.

---

## 12. Errors

All stable error codes. No raw path, PID, argv, or capability bitmask appears
in any error message field. Message fields are redacted to a bounded safe
description.

### 12.1 Spec admission errors

| Code | Meaning |
| --- | --- |
| `user-namespace-missing-spec` | `namespaceClasses` includes `user` but `userNamespace` is null |
| `user-namespace-mapping-class-unknown` | `userNamespace.mappingClass` is not a recognized semantic class value |
| `network-namespace-with-network-ref` | `namespaceClasses` includes `network` and `networkUsage.networkRef` is non-null |
| `cgroup-namespace-unsupported` | `namespaceClasses` includes `cgroup` but Host lacks `cgroup-v2` capability |
| `user-domain-not-supported` | `domain: user` but the Provider component descriptor does not declare user-domain support for this Host/Guest placement |
| `capability-class-denied-user-domain` | `capabilityClasses` contains a class denied in user domain (`network-admin`, `sys-admin`, `setuid`, `setgid`) |
| `seccomp-allow-all-not-permitted` | `seccompClass: allow-all` without descriptor carve-out |
| `start-root-user-domain` | `startRoot: true` combined with `domain: user` |
| `start-root-without-carve-out` | `startRoot: true` without explicit Provider descriptor carve-out |
| `provider-class-unknown` | `seccompClass` names a class not in the Provider's compiled catalog |
| `budget-exceeds-execution-target` | Per-process budget fields exceed the executionRef aggregate remainder |
| `volume-domain-mismatch` | A `MountSpec` Volume's `sensitivityClass` is incompatible with the process domain/userRef |
| `execution-ref-not-ready` | `executionRef` target is not in Ready phase at admission time |
| `provider-not-ready` | `Provider/system-minijail` is not in Ready phase |
| `template-not-found` | `template` ID does not resolve in the owning Provider's component descriptor |
| `kernel-too-old` | Host kernel is older than the mandatory Linux 5.14 baseline |
| `cgroup-kill-unavailable` | The delegated cgroup v2 leaf does not expose writable `cgroup.kill`; Provider remains not Ready and no launch is attempted |

### 12.2 Launch errors

| Code | Meaning |
| --- | --- |
| `sandbox-plan-digest-mismatch` | Compiled plan digest at launch time differs from the digest at ticket issue time |
| `executable-hash-mismatch` | Binary content hash does not match the bundle-pinned template digest |
| `cgroup-leaf-create-failed` | Broker could not create the cgroup leaf under the delegated subtree |
| `clone3-failed` | Kernel returned an error from `clone3` |
| `user-ns-uid-map-failed` | Writing `uid_map` failed during user namespace setup |
| `user-ns-gid-map-failed` | Writing `gid_map` failed during user namespace setup |
| `broker-spawn-denied` | Broker refused the SpawnRunner request (admission check failed) |
| `volume-not-ready` | A required Volume mount is not Ready at launch time |
| `launch-ticket-expired` | LaunchTicket deadline exceeded before spawn completed |
| `launch-ticket-revoked` | LaunchTicket revoked by controller generation change |

### 12.3 Runtime and adoption errors

| Code | Meaning |
| --- | --- |
| `start-deadline-exceeded` | EphemeralProcess did not start within `startDeadline` |
| `runtime-deadline-exceeded` | Process or EphemeralProcess exceeded `runtimeDeadline` |
| `max-restarts-exceeded` | Process reached `restartPolicy.maxRestarts` |
| `adoption-ambiguous` | Multiple processes found in the cgroup leaf on adoption |
| `adoption-identity-mismatch` | Process identity does not match stored `processIdentityDigest` |
| `adoption-failed` | Adoption attempted but could not open pidfd after verification |
| `runtime-security-violation` | Pidfd invariant violated; emits audit event and quarantines |
| `broker-wait-owner-lost` | The original `clone3` broker parent cannot provide the exact wait/reap result; replacement broker/non-parent observation cannot substitute |
| `cgroup-kill-failed` | An unambiguous intentional teardown could not write `1` to the anchored leaf's `cgroup.kill` or the leaf did not become unpopulated |
| `process-exit-unconfirmed` | Process exit could not be confirmed by the original broker parent's relayed `waitid(P_PIDFD, ...)` result during finalize; finalizer retained; resource reports `Degraded`/`Unknown` pending operator resolution or full Zone reset |

---

## 13. Process and EphemeralProcess status additions

The following fields are specific to `Provider/system-minijail` as the
implementation. Per D088, ResourceType-common Process/EphemeralProcess
observation written by system-minijail lives in `status.resource`, while
bounded non-secret minijail-only observation lives in `status.provider.details`
with `providerRef: Provider/system-minijail`, qualified schema IDs
`system-minijail.d2bus.org/Process/status` or
`system-minijail.d2bus.org/EphemeralProcess/status`, `schemaVersion` (semver MAJOR.MINOR),
`observedProviderGeneration`, and a strict unknown-field-denied, ≤32 KiB,
redacted schema registered and signed in the Provider manifest. The controller
writes all present layers atomically in one status mutation, and shared fields
are promoted to `status.resource` rather than duplicated into
`status.provider`.

### Process status values

| Layer/path | Field | Written value |
| --- | --- | --- |
| `status.resource` | `providerImplementation` | `"system-minijail"` when required by cross-provider Process consumers |
| `status.resource` | `waitReapOwner` | `"d2b"` |
| `status.provider.details` | `sandboxRevisionDigest` | Opaque hex digest of the compiled sandbox plan (namespace + capability + seccomp + mount + environment + userNamespace + rlimit + umask classes and version). Max 128 chars. |
| `status.provider.details` | `adoptionState` | One of `adopted`, `fresh`, `quarantined`, `adoption-failed`. |

### EphemeralProcess status values

| Layer/path | Field | Written value |
| --- | --- | --- |
| `status.resource` | `providerImplementation` | `"system-minijail"` when required by cross-provider EphemeralProcess consumers |
| `status.resource` | `waitReapOwner` | `"d2b"` |
| `status.provider.details` | `sandboxRevisionDigest` | Same as Process. |
| `status.provider.details` | `cleanupEligibleAt` | Set after terminal phase + TTL; RFC 3339 UTC. |
| `status.provider.details` | `incidentHeld` | Mirrors `spec.incidentHold` at last reconcile. |

No PID, pidfd file descriptor number, cgroup leaf path, mount table entry,
socket address, argv, environment variable, capability bitmask, seccomp BPF
program fragment, or raw broker diagnostic appears in any status field.

**Currency and upgrade (D091).** The controller implements `assess_update`,
`plan_upgrade`, and `execute_upgrade` for Process and EphemeralProcess currency
and populates only the universal `status.update`, never `status.provider`, with
`state: Current|UpdateAvailable|UpgradeRequired|Upgrading|Blocked|Unknown`,
`reasons` from `CoreGenerationChanged`, `ProviderGenerationChanged`,
`ArtifactChanged`, `ImageOrSystemGenerationChanged`, `SpecChanged`,
`DependencyChanged`, or `SecurityPolicyChanged`, observed/target
generation/digest IDs, `disruption: None|Reload|Restart|Recycle|Replace`,
`preserveState`, optional `operationId`, `lastAssessedAt`, and
`owned`/`dependencies` refs. It honors base `spec.updatePolicy` (manual
disruptive default; auto non-disruptive), while the Core Operation ledger owns
upgrade operation, idempotency, and progress. Process Provider upgrades recycle
the controller realization; running workload Processes are re-adopted from
declared cgroup leaves with fresh pidfds and are not disrupted unless the plan
requires it. Disruptive changes return `UpgradeRequired` rather than applying in
place, non-disruptive changes reconcile normally, and the per-resource
single-flight serializes reconcile versus upgrade.

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

The minijail controller writes status only on `Process` and `EphemeralProcess`
resources. `Provider/system-minijail` resource status is aggregated by core;
the minijail controller has no `Provider` update-status grant.

---

## 14. Audit events

All audit records are committed before the operation they describe completes.
Audit is distinct from OTEL telemetry (§15). No OTEL pipeline carries audit
payloads.

### 14.1 Event catalog

| Event kind | Trigger | Required fields |
| --- | --- | --- |
| `ProcessLaunched` | Process transitions to Running (pidfd obtained) | `zone`, `resource_ref`, `resource_uid`, `resource_generation`, `provider`, `component`, `operation_id`, `subject_digest`, `execution_ref`, `domain`, `sandbox_plan_digest`, `adoption_state` |
| `ProcessExited` | Wait-confirmed process exit | `zone`, `resource_ref`, `resource_uid`, `provider`, `operation_id`, `exit_class`, `restart_count` |
| `ProcessAdopted` | Successful adoption after controller restart | `zone`, `resource_ref`, `resource_uid`, `provider`, `operation_id`, `subject_digest`, `adoption_state: adopted` |
| `ProcessQuarantined` | Ambiguous or mismatched adoption | `zone`, `resource_ref`, `resource_uid`, `provider`, `operation_id`, `reason` (one of `adoption-ambiguous`, `adoption-identity-mismatch`) |
| `ProcessFinalized` | Finalizer cleared after exact-main SIGTERM, anchored cgroup.kill, broker wait/reap, and empty-leaf proof | `zone`, `resource_ref`, `resource_uid`, `provider`, `operation_id`, `exit_confirmed: bool` |
| `EphemeralProcessLaunched` | EphemeralProcess transitions to Running | Same fields as `ProcessLaunched` |
| `EphemeralProcessCompleted` | EphemeralProcess reaches terminal phase | `zone`, `resource_ref`, `resource_uid`, `provider`, `operation_id`, `outcome_code`, `exit_code?` (only when `outcome_code: process-exited`) |
| `EphemeralProcessCleanupInitiated` | EphemeralProcess cleanup controller calls Delete | `zone`, `resource_ref`, `resource_uid`, `operation_id`, `cleanup_eligible_at` |
| `SandboxPlanCompiled` | Sandbox plan compiled before LaunchTicket issue | `zone`, `resource_ref`, `resource_uid`, `provider`, `sandbox_plan_digest`, `namespace_classes`, `seccomp_class` (class name only - no BPF), `user_namespace: bool`, `subject_digest` |
| `runtime-security-violation` | Any pidfd invariant violated | `zone`, `resource_ref`, `resource_uid`, `provider`, `violation_class`, `subject_digest`, `operation_id` |
| `BootstrapAuthorizationUsed` | Bootstrap authorization used for a resource verb | `zone`, `provider`, `operation_id`, `verb`, `resource_type`, `subject_digest` |

### 14.2 Redaction rules

The following fields must never appear in any audit record, log line, OTEL span
attribute, or metric label:

- PID or pidfd file descriptor number;
- cgroup leaf path;
- executable path or argv;
- raw seccomp BPF program bytes;
- capability bitmask;
- environment variable name or value;
- mount source path;
- uid_map/gid_map raw content;
- credential bytes;
- socket address or file descriptor number;
- resource name combined with subject name in a single audit field.

The `sandbox_plan_digest` field is an opaque hex string. It identifies the
compiled plan version without exposing implementation details.

The `exit_code` field is included only in `EphemeralProcessCompleted` when
`outcome_code: process-exited`. It is a bounded integer. It is never included
in metric labels.

---

## 15. Telemetry

### 15.1 SDK placement

Provider/system-minijail uses the lightweight bounded emitter (`tracing` crate
plus bounded in-process ring) to push frames over the Zone's local private
OTEL socket. It carries no `opentelemetry_sdk` or `opentelemetry-otlp`
dependency. Frames are drained and forwarded by `Provider/observability-otel`
when installed.

If `Provider/observability-otel` is absent or unready: the emitter ring fills
and oldest frames are dropped. `d2b_telemetry_drop_total` increments. Audit is
unaffected.

### 15.2 OTEL resource attributes

All v3 target additions are advisory; re-stamped authoritatively at the trusted
ingress boundary:

| Attribute | Value | Rule |
| --- | --- | --- |
| `service.name` | `d2b-provider-system-minijail` | Required |
| `service.version` | `CARGO_PKG_VERSION` | Required |
| `d2b.zone` | Zone name string | Advisory; not a metric label value |
| `d2b.provider` | `system-minijail` | Required for Provider processes |
| `d2b.component` | `minijail-controller` | Required |

The existing baseline attributes (`vm.name`, `vm.env`, `vm.role`, `host.name`,
`service.namespace`) are preserved in the allowlist and may be set by processes
supervised by this Provider.

No attribute outside the allowlist defined in
`ADR-046-telemetry-audit-and-support` may be stamped by this Provider.

### 15.3 Metric labels (closed set)

Metrics exposed by the minijail controller use only closed label sets.
**No metric uses a resource name, process name, subject name, PID, path,
capability, or argv as a label value.**

| Metric | Labels | Description |
| --- | --- | --- |
| `d2b_minijail_process_starts_total` | `{domain, outcome}` | Total process start attempts; `outcome` ∈ `{success, launch-failed, rejected}` |
| `d2b_minijail_process_restarts_total` | `{domain, exit_class}` | Total process restarts; `exit_class` ∈ `{clean-exit, crash, signal, timeout, unknown}` |
| `d2b_minijail_process_adoptions_total` | `{domain, adoption_state}` | Total adoption outcomes; `adoption_state` ∈ `{adopted, quarantined, adoption-failed, fresh}` |
| `d2b_minijail_process_active` | `{domain}` | Gauge: current non-terminal Process count |
| `d2b_minijail_ephemeral_starts_total` | `{domain, outcome_code}` | EphemeralProcess start attempts; `outcome_code` per §9 |
| `d2b_minijail_sandbox_compile_duration_seconds` | `{seccomp_class, user_namespace}` | Histogram: sandbox plan compilation latency |
| `d2b_minijail_launch_latency_ms` | `{domain}` | Histogram: hint-to-launch-attempt latency; gates ≤20 ms p95 |
| `d2b_minijail_hint_latency_ms` | `{component}` | Histogram: commit-to-hint latency; gates ≤5 ms p95 |
| `d2b_minijail_concurrent_launches` | `{component}` | Gauge: current inflight LaunchTickets |
| `d2b_telemetry_drop_total` | `{component}` | Telemetry ring overflow drops |

Label value constraints:

- `domain`: `system` or `user`.
- `outcome`, `adoption_state`, `exit_class`, `outcome_code`: closed enumerations as defined in §12 and §9.
- `seccomp_class`: class name string from the closed `seccompClass` enumeration or `<provider-class>` name (bounded identifier).
- `user_namespace`: `true` or `false`.
- `component`: `minijail-controller`.

No label contains a resource name, subject name, PID, capability bitmask, path,
or any compound identifier.

### 15.4 Async latency gate

The following latency thresholds are enforced as test pass/fail gates in the
integration test suite (see §18):

| Gate | Threshold | Metric |
| --- | --- | --- |
| p95 commit-to-handler-start | ≤5 ms | `d2b_minijail_hint_latency_ms` |
| p95 handler-to-launch-attempt | ≤20 ms | `d2b_minijail_launch_latency_ms` |

---

## 16. Nix configuration

### 16.1 Installing Provider/system-minijail

Provider/system-minijail is a system Provider. It is fixed in the bootstrap
sequence and is present by default in every Zone runtime. The `Provider/system-minijail`
resource itself is **runtime-created** by the core-controller during Zone
bootstrap (`managedBy: controller`); it is never authored in Nix by the
operator.

The operator's only Nix declaration is the artifact catalog entry, which
supplies the package derivation:

```nix
d2b.artifacts.system-minijail = {
  package = packages.d2b-provider-system-minijail;
  type    = "provider";
};
```

`Provider.spec.config` is fixed empty for this Provider. The operator does not
set any config fields. Process lifecycle defaults (drain timeout, restart
backoff base/max) are set in the `Process` or `EphemeralProcess` spec; fixed
manifest bounds are not operator-configurable.

The `d2b.artifacts.system-minijail` catalog entry is validated at build time:
`type` must be `"provider"`. The rendered artifact reference in the Provider
resource contains only the bounded `artifactId` string - not any Nix store path.

### 16.2 Selecting Provider/system-minijail for a Process

```nix
d2b.zones.dev.resources.virtiofsd-work = {
  type = "Process";
  spec = {
    providerRef   = "Provider/system-minijail";
    executionRef  = "Host/host-system";
    domain        = "system";
    processClass  = "worker";
    template      = "virtiofsd";
    ownerRef      = "Provider/volume-virtiofs";   # set via metadata not spec; shown here for clarity
    sandbox = {
      namespaceClasses  = ["user" "mount" "pid"];
      capabilityClasses = [];
      seccompClass      = "virtiofsd";
      noNewPrivileges   = true;
      startRoot         = false;
      environmentClass  = "minimal";
      readOnlyRoot      = true;
      userNamespace = {
        mappingClass = "process-principal-root";
      };
    };
    budget = {
      memory = { request = "32Mi"; limit = "128Mi"; };
      pids   = { limit = 32; };
    };
    mounts = [
      {
        volumeRef  = "Volume/work-store";
        view       = "ro-store";
        mountPath  = "/store";
        access     = "read-only";
        required   = true;
      }
    ];
  };
};
```

Rendered canonical JSON (excerpt):

```json
{
  "apiVersion": "resources.d2bus.org/v3",
  "type": "Process",
  "metadata": {
    "name": "virtiofsd-work",
    "zone": "dev"
  },
  "spec": {
    "providerRef": "Provider/system-minijail",
    "executionRef": "Host/host-system",
    "domain": "system",
    "processClass": "worker",
    "template": "virtiofsd",
    "sandbox": {
      "namespaceClasses": ["user", "mount", "pid"],
      "capabilityClasses": [],
      "seccompClass": "virtiofsd",
      "noNewPrivileges": true,
      "startRoot": false,
      "environmentClass": "minimal",
      "readOnlyRoot": true,
      "userNamespace": { "mappingClass": "process-principal-root" }
    },
    "budget": {
      "memory": { "request": "32Mi", "limit": "128Mi" },
      "pids": { "limit": 32 }
    },
    "mounts": [
      {
        "volumeRef": "Volume/work-store",
        "view": "ro-store",
        "mountPath": "/store",
        "access": "read-only",
        "required": true
      }
    ]
  }
}
```

No store path appears in the rendered JSON. The `template` field is a plain
bounded ID. No raw capability list, seccomp BPF, minijail argument string,
cgroup path, or socket address appears.

### 16.3 EphemeralProcess example

```nix
d2b.zones.dev.resources.swtpm-flush-abc123 = {
  type = "EphemeralProcess";
  spec = {
    providerRef      = "Provider/system-minijail";
    executionRef     = "Host/host-system";
    domain           = "system";
    processClass     = "worker";
    template         = "swtpm-flush";
    sandbox = {
      namespaceClasses  = ["pid" "mount"];
      capabilityClasses = [];
      seccompClass      = "swtpm";
      noNewPrivileges   = true;
      startRoot         = false;
      environmentClass  = "minimal";
      readOnlyRoot      = true;
    };
    startDeadline    = "60s";
    runtimeDeadline  = "120s";
    successfulTtl    = "1h";
    failedTtl        = "24h";
    incidentHold     = false;
  };
};
```

### 16.4 Eval-time validation rules

The Nix compiler enforces at eval time:

1. `providerRef` resolves to a declared `Provider/system-minijail` resource in
   the same Zone.
2. `executionRef` resolves to a declared `Host/<name>` or `Guest/<name>` in the
   same Zone.
3. `domain` is in `executionRef.allowedDomains`.
4. When `domain: user`, either `userRef` is set or the execution target has
   `defaultUserRef` set.
5. `sandbox.namespaceClasses` contains `user` only if `sandbox.userNamespace`
   is set.
6. `sandbox.userNamespace.mappingClass` is a recognized semantic class value
   (closed enumeration; currently only `process-principal-root`).
7. `sandbox.seccompClass` is one of the closed enum values or a named class
   identifier (bounded string).
8. No inline secret byte, raw host path, capability bitmask, or socket address
   appears in any spec field.
9. `processClass: controller` or `service` on an EphemeralProcess is rejected.

Missing required fields produce actionable eval errors with source location.

### 16.5 Build-time validation

The build:

1. Renders the canonical JSON ResourceSpec.
2. Validates it against the committed ResourceTypeSchema
   (`docs/reference/schemas/v3/core.d2bus.org_Process.schema.json` and
   `core.d2bus.org_EphemeralProcess.schema.json`).
3. Validates `spec.sandbox` against the signed Provider schema extension for
   minijail-specific fields.
4. Verifies no Nix store path appears in any rendered field.
5. Verifies two identical configs produce byte-identical generation IDs.

---

## 17. Hard bounds

| Bound | Value | Enforced by |
| --- | --- | --- |
| Minimum Linux version | 5.14 | Host platform gate before Provider Ready/placement; verifies delegated cgroup v2 `cgroup.kill` |
| Maximum concurrent inflight LaunchTickets per Zone | 64 (fixed manifest bound; not operator-configurable) | Controller semaphore; excess queued |
| LaunchTicket TTL | `spec.startDeadline` (1s..3600s; default 60s) | Controller ticker |
| Maximum runtimeDeadline | `spec.runtimeDeadline` max 86400s | Spec admission |
| Maximum failedTtl | 30 days | Spec admission |
| Maximum successfulTtl | 7 days | Spec admission |
| Maximum `drainTimeout` (Process spec field) | 300s | Spec admission; fixed bound |
| Maximum `restartPolicy.backoffMax` (Process spec field) | 1h | Spec admission; fixed bound |
| `processIdentityDigest` length | 128 chars | Status field |
| `sandboxRevisionDigest` length | 128 chars | Status field |
| `namespaceClasses` items | 0..8 unique | Spec admission |
| `capabilityClasses` items | 0..16 unique | Spec admission |
| `seccompClass` string length | 64 chars | Spec admission |
| `mounts` items | 0..64 | Spec admission |
| `template` length | 63 chars | Spec admission |
| `userNamespace.mappingClass` string length | 64 chars | Spec admission |

---

## 18. Test inventory

Each test path corresponds to a required file within the Provider crate layout
defined in `ADR-046-provider-model-and-packaging` and enforced by workspace
policy.

### Fast hermetic execution and test placement (D094)

Per D094 and the repository's test-budget guidance, this Provider's `src/`
unit tests and `tests/*.rs` hermetic suite are fast, in-process, deterministic,
and parallel-safe: an individual normal test has an advisory wall-clock p95
diagnostic threshold of <=50 ms; gate enforcement is aggregate per-crate
process CPU only. There is no wall-clock
sleep, and `cargo test -p d2b-provider-system-minijail --lib --tests` completes
in ≤3 s warm-cache execution time (compilation excluded). They use a
deterministic fake clock/RNG and the toolkit fakes/FakeEffectPort only - no
process spawn, container, network, DBus, systemd, broker daemon, Nix eval/build,
KVM, USB/GPU/TPM hardware, or live cloud, and no filesystem tree beyond tiny
temp fixtures. Any scenario needing those lives only in `integration/`, which
keeps a lane timeout/budget, parallel isolation, and fake external services by
default; such a need is re-placed into `integration/`, never given a sleep,
larger timeout, or `#[ignore]`. Bounded crypto/property tests are the only
classified exception, each named with a capped case count and a declared higher
per-test advisory threshold.

### 18.1 `src/` - colocated unit tests

Every module in `src/` includes `#[cfg(test)]` unit tests for:

- `sandbox_compiler.rs`: SandboxSpec → compiled plan round-trips; every
  NamespaceClass, CapabilityClass, and SeccompClass combination; user namespace
  block with valid/invalid mappingClass; every rejection condition in §12.1.
- `launch.rs`: opaque launch-request construction through
  `MinijailProcessEffectPort`; digest binding; expired/revoked request paths;
  no LaunchTicket internals or broker DTOs.
- `adoption.rs`: typed effect-observation handling for fresh adoption,
  successful identity match, ambiguous/multiple candidates, identity mismatch,
  and quarantine; the controller never reads `/proc`, enumerates cgroups, or
  receives a pidfd.
- `effect_result.rs`: typed core-relayed liveness and terminal-result
  classification; duplicate and mismatched results fail closed; no
  `AsyncFd`, `waitid`, `waitpid`, pidfd, PID, or PGID enters the Provider.
- `user_ns.rs`: conformance validation of the opaque user-namespace request
  only; uid_map/gid_map writes and pipe synchronization remain broker-internal.
- `metrics.rs`: no `zone` label in any emitted metric; closed label set
  enforcement; label value bounds.

### 18.2 `tests/` - hermetic Cargo integration tests

Files:

```
tests/
  sandbox_compilation.rs    # full SandboxSpec → plan round-trips against golden vectors
  lifecycle.rs              # Process: start → ready → crash → core-relayed terminal status → restart → typed stop request
  ephemeral_lifecycle.rs    # EphemeralProcess: start → succeed/fail → ttl → cleanup
  conformance.rs            # shared conformance matrix (run against fake EffectPort/supervisor)
  fault_injection.rs        # typed EffectPort launch/observe/stop/user-ns failures
  redaction.rs              # no PID/path/cap/argv in status/audit/metrics; no zone label
  schema.rs                 # rendered JSON validates against ResourceTypeSchema
  fast_path.rs              # ≤5 ms hint / ≤20 ms launch latency gates (1/10/100 concurrent)
  adoption_quarantine.rs    # adoption identity mismatch → quarantine, no kill; blocking-adapter timeout → adoption-failed; quarantine reuse rejected without external proof
  bootstrap_authz.rs        # bootstrap authorization scope; no widening; wrong subject fails
  status_state.rs           # status-first operational state: controller declares no state Volume; bounded observations written to status/core ledger within status bounds; no secret/path/argv/PID/unit content; restart re-derives observed state from cgroup leaves + fresh pidfds
  effect_timeout.rs         # bounded EffectPort timeout becomes typed error, not hang
  broker_wait_contract.rs   # Provider accepts only identity-bound typed terminal results
  cgroup_kill_finalize.rs   # graceful-stop then subtree-stop request ordering; no PID/PGID input
  platform_gate.rs          # typed unsupported-platform preflight result fails before launch
```

All tests pass under `cargo test -p d2b-provider-system-minijail`.

### 18.3 `integration/` - container and broker integration scenarios

Files:

```
integration/
  clone3_pidfd/             # clone3 CLONE_PIDFD | CLONE_INTO_CGROUP on a real cgroup leaf
  user_namespace/           # effect port user namespace pre-establishment; virtiofsd fixture
  adoption_restart/         # controller restart → adopt live process → verify digest; blocking-adapter path
  quarantine_scenario/      # identity mismatch on restart → quarantine, no signal; external proof required before reuse
  ephemeral_ttl/            # EphemeralProcess TTL and cleanup in real broker fixture
  concurrent_launch/        # fixed concurrency bound semaphore; 100 parallel launches
  latency_gate/             # ≤20 ms p95 launch-attempt start gate with real broker
  user_domain/              # user-domain Process via user supervisor (if descriptor declares support)
  status_state_restart/     # controller starts with no state Volume; reaches Ready from status/core ledger; restart re-derives observed state and gets fresh supervisor duplicates from the still-parent broker; no state-Volume mount
  broker_parent_reap/       # broker clone3 parent reaps exactly once and relays exit status; controller restart preserves parent
  cgroup_kill_subtree/      # setsid descendant + recycled-PGID fixture is killed only through anchored leaf cgroup.kill
  kernel_platform_gate/     # Linux >=5.14/cgroup.kill positive probe and fail-closed unsupported-kernel fixture
```

Each integration scenario:

- is invoked by the existing repository test orchestration (`make
  test-integration`);
- declares its fixture dependencies within its scenario directory;
- does not modify global host state or mount namespaces outside its declared
  fixture scope.

### 18.4 Required conformance coverage (shared with Provider/system-systemd)

The shared process conformance suite (`packages/d2b-process-conformance/src/`)
is run against both system-minijail and system-systemd providers:

| Scenario | system-minijail assertion |
| --- | --- |
| Start → Ready | pidfd obtained atomically via `clone3(CLONE_PIDFD)` |
| Crash → restart | `waitReapOwner: "d2b"` means broker parent; broker-relayed wait/reap status drives backoff |
| Drain: SIGTERM → exit | drainTimeout enforced; broker wait/reap result plus empty-leaf proof required |
| Drain: SIGTERM → forced subtree stop | broker writes `1` to anchored `cgroup.kill`; no PID/PGID SIGKILL fallback |
| Adoption: matching identity | `adoptionState: adopted`; ProviderSupervisor gets a verified duplicate from the still-parent broker |
| Adoption: mismatched identity | `adoptionState: quarantined`; no signal; external proof required before reuse |
| EphemeralProcess: Succeeded TTL | `cleanupEligibleAt` set; row removed on Delete |
| EphemeralProcess: Failed TTL | `failedTtl` applied |
| SandboxSpec virtiofsd profile | user namespace pre-established; zero host caps |
| Fast path: 1 process | p95 ≤20 ms |
| Fast path: 100 concurrent | p95 ≤20 ms; no queue starvation |
| PID never in status | No PID/pidfd in any status/audit/log |
| No static template units | No PID1 unit for any process |
| No zone metric labels | No `zone` label on any emitted metric; Zone is OTEL resource attribute only |
| Blocking-adapter isolation | `/proc` read, executable hash, cgroup enum, pidfd duplicate re-verification, and broker-status retrieval never block watch loop |
| Parent-only wait/reap | Only the `clone3` broker parent calls `waitid(P_PIDFD)` and reaps; ProviderSupervisor poll readability is not accepted as exit status |
| Pidfd signaling holder | Verified broker/ProviderSupervisor duplicate can `pidfd_send_signal` the exact main process; controller holds only an opaque handle |
| Descendant escape resistance | A descendant that calls `setsid(2)` and a recycled-PGID decoy cannot evade or be hit by teardown; only the verified leaf's `cgroup.kill` is used |
| Platform gate | Linux <5.14 or absent/unwritable leaf `cgroup.kill` keeps Provider not Ready and launches zero processes |
| Effect port boundary | Provider crate imports no broker service/client/DTO; all spawn effects via `MinijailProcessEffectPort` with opaque IDs |
| Provider status by core | Minijail controller writes no `Provider` resource status; core aggregates from checkpoint/health events |
| No state Volume | The minijail controller declares no Provider state Volume; bounded non-secret operational state lives in `status`/the core Operation ledger (D087); no bootstrap state Volume, no bootstrap storage mechanism, and no bootstrap-storage exception (D086 superseded by D087); running units re-adopted from cgroup leaves + fresh pidfds on restart |

---

## 19. Current-code reuse ledger

All evidence classes use the definitions from
`ADR-046-current-code-migration-map` (§0 Purpose and Notation).

The baseline is `b5ddbed67867d9244bf33390868101bd9b053e49`.

| Current symbol / path | Evidence class | Action | Destination |
| --- | --- | --- | --- |
| `packages/d2b-core/src/processes.rs` - `ProcessRole` (18 variants), `ProcessNode`, `RoleProfile`, `NamespaceSet`, `MountPolicy`, `CgroupPlacement`, `ReadinessPredicate` | production-reachable | EXTRACT/ADAPT | `packages/d2b-provider-system-minijail/src/sandbox_compiler.rs` - namespace/cap/mount class compilation; `packages/d2b-process/src/` - common spec types |
| `packages/d2b-core/src/minijail_profile.rs` - `MinijailProfile`, `UserNamespaceProfile`, `NamespaceSet`, `MountPolicy`, `BindMount`, `CgroupPlacement` | production-reachable | EXTRACT/ADAPT | `packages/d2b-provider-system-minijail/src/sandbox_compiler.rs` - compiled plan types; preserve typed fail-closed profile verification |
| `packages/d2b-core/src/process_builder.rs` | production-reachable | ADAPT | Core/ProviderSupervisor LaunchTicket builder; `packages/d2b-provider-system-minijail/src/launch.rs` submits only opaque launch requests through MinijailProcessEffectPort |
| `packages/d2b-priv-broker/src/ops/spawn_runner.rs` | production-reachable | ADAPT | Broker-side: retained as internal broker op invoked by `MinijailProcessEffectPort` implementation (owned by core/ProviderSupervisor); Provider-side: `packages/d2b-provider-system-minijail/src/launch.rs` calls `MinijailProcessEffectPort` with opaque IDs; Provider crate imports no broker service/client/DTO |
| `packages/d2bd/src/supervisor/pidfd_table.rs` - `PidfdTable`, `PidfdEntry`, `PidfdRegistration`, `WaitTermination`, `BrokerReapLog` | production-reachable | EXTRACT/ADAPT | Broker-side wait/reap remains in `d2b-priv-broker`; core/ProviderSupervisor alone polls verified duplicates and requests exact-main signaling; the Provider consumes only identity-bound typed observations and terminal results |
| `packages/d2bd/src/supervisor/*.rs` - `DagExecutor`, `NodeOutcome`, `NodeHistory`, `NodeBudget`, `SplitReadinessMode` | production-reachable | ADAPT | Core effect adapter performs `/proc`/cgroup discovery; `packages/d2b-provider-system-minijail/src/adoption.rs` applies adoption/quarantine semantics to its opaque typed observations |
| `packages/d2b-priv-broker/src/ops/swtpm_dir.rs` - user namespace uid_map/gid_map write sequence | production-reachable | ADAPT | Broker and core MinijailProcessEffectPort adapter retain the pre-establishment sequence, pipe sync, O_NOFOLLOW, and re-validation; Provider `user_ns.rs` validates only the opaque request contract |
| `packages/d2b-realm-core/src/ids.rs` - `RealmId`, `WorkloadId`, `PrincipalId` | production-reachable | ADAPT | Use v3 `ZoneId`, `ResourceRef`, `UserRef` from `d2b-contracts/src/v3/identity.rs` (ADR046-identities-001) |
| `packages/d2b-realm-core/src/workload.rs` - `WorkloadProviderKind`, `IsolationPosture`, `WorkloadExecutionPosture` | production-reachable | DELETE at cutover | Replaced by `Host`/`Guest`/`ExecutionPolicy`; evidence for `UnsafeLocal` → user-only Host mapping retained in migration map |
| `packages/d2b-core/src/storage.rs` - `StoragePathSpec` | production-reachable | Not consumed | Provider/system-minijail declares no state Volume; bounded non-secret operational state lives in `status`/the core Operation ledger (D087); no state-Volume creation or reconciliation on any path |
| `packages/d2b-realm-router` session types | dead-reachable | DELETE | Replaced by ComponentSession (`d2b-session`, `a1cc0b2d` reuse) |
| `packages/d2b-realm-transport` `LocalTcpTransport` | test-only | DELETE | No live socket; test conformance vectors replaced by v3 session tests |
| `packages/d2bd/src/realm_stubs.rs` | dead-reachable (explicitly dead_code-allowed) | DELETE | Stubs removed after v3 ComponentSession/bus integration |
| Main reuse `a1cc0b2d`: `packages/d2b-session/src/{handshake,bootstrap,record,engine,scheduler,streams,lifecycle,transport}.rs` | - (main, not baseline) | COPY/ADAPT | `packages/d2b-session/` - KK enrolled session for post-bootstrap bus; IKpsk2 for bootstrap; exact vectors preserved |
| Main reuse `a1cc0b2d`: `packages/d2b-session-unix/src/{adapter,socket,descriptor,pidfd,vsock,credit}.rs` | - (main, not baseline) | COPY/ADAPT | `packages/d2b-session-unix/` - Unix peer evidence, CLOEXEC FD validation |

No symbol from `d2b-realm-router` implementation types or `d2b-realm-transport`
live sockets is carried into v3 as architecture. Main `a1cc0b2d` ADR 0045
Provider types, endpoint roles, service inventory, realm process model, and
delivery assumptions are not copied.

---

## 20. Implementation work items

### ADR046-minijail-001 (Dependency: ADR046-process-001, ADR046-provider-001)

| Field | Value |
| --- | --- |
| Dependency/owner | `ADR046-process-001` (common spec/status types); `ADR046-provider-001` (toolkit/contracts); system-minijail Provider owner |
| Current source | `d2b-core/src/minijail_profile.rs`; `d2b-core/src/processes.rs` (NamespaceSet, MountPolicy, CgroupPlacement); `d2b-priv-broker/src/ops/spawn_runner.rs` |
| Reuse action | adapt |
| Destination | `packages/d2b-provider-system-minijail/src/sandbox_compiler.rs` |
| Detailed design | Accept `SandboxSpec` from common contracts; compile NamespaceClass/CapabilityClass/SeccompClass/UserNamespaceSpec/mount/environment/rlimit/umask into a versioned `CompiledSandboxPlan`; compute `sandboxRevisionDigest`; all rejection conditions from §12.1; no raw bitmask/BPF/argv/path in any output type; golden round-trip test vectors Primary reuse disposition: `adapt`. Preserved source-plan detail: EXTRACT/ADAPT. |
| Integration | LaunchTicket builder (ADR046-minijail-002); effect port integration (ADR046-minijail-003) |
| Data migration | Full reset; current `MinijailProfile` not import-compatible with v3 SandboxSpec |
| Validation | `tests/sandbox_compilation.rs`; `tests/schema.rs`; golden vectors |
| Removal proof | Current `MinijailProfile`/`NamespaceSet` types in `d2b-core` removed after all callers migrate to SandboxSpec |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-minijail-002 (Dependency: ADR046-minijail-001, ADR046-process-001)

| Field | Value |
| --- | --- |
| Dependency/owner | ADR046-minijail-001; common `LaunchTicket` contract |
| Current source | `d2b-core/src/process_builder.rs`; `d2bd/src/supervisor/*.rs` (ticket generation) |
| Reuse action | adapt |
| Destination | Provider-side opaque request builder in `packages/d2b-provider-system-minijail/src/launch.rs`; LaunchTicket construction and verification in core/ProviderSupervisor |
| Detailed design | Provider submits opaque Process/profile/budget/mount digest IDs through MinijailProcessEffectPort. Core constructs the LaunchTicket, verifies it on ProviderSupervisor receipt, performs the `d2b.supervisor.v3/IssueLaunchTicket` service call, and rejects expired/revoked/malformed tickets without exposing ticket internals or broker DTOs to the Provider. |
| Integration | `ProviderSupervisor` local adapter; minijail controller (ADR046-minijail-005) |
| Data migration | None - full d2b 3.0 reset; no prior state to migrate |
| Validation | `tests/lifecycle.rs`; `tests/fault_injection.rs`; `tests/fast_path.rs` |
| Removal proof | Current `process_builder.rs` removed after parity |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-minijail-003 (Dependency: ADR046-minijail-001)

| Field | Value |
| --- | --- |
| Dependency/owner | ADR046-minijail-001; broker integration owner |
| Current source | `d2b-priv-broker/src/ops/spawn_runner.rs`; `d2b-priv-broker/src/sys.rs` (`clone3_spawn_runner`, user namespace setup) |
| Reuse action | adapt |
| Destination | Broker-side: `d2b-priv-broker` retains `SpawnRunner` and user-namespace pre-establishment; core/ProviderSupervisor owns the `MinijailProcessEffectPort` implementation; Provider-side `packages/d2b-provider-system-minijail/src/launch.rs` calls the trait with opaque Process/profile/policy IDs and `user_ns.rs` validates only semantic request constraints |
| Detailed design | Linux ≥5.14 and delegated-leaf `cgroup.kill` platform gate; `clone3(CLONE_PIDFD | CLONE_INTO_CGROUP)` with pre-declared cgroup leaf FD; broker retained as child parent and sole `waitid(P_PIDFD)`/reap/exit-status owner; verified duplicate returned privately to ProviderSupervisor for poll/readiness and exact-main `pidfd_send_signal`; anchored `cgroup.kill` write for unambiguous intentional teardown; user namespace pre-establishment sequence (§7.7) when `userNamespace` set; host UID 0 rejection; parent name-to-inode re-validation; zero-host-capability invariant (ADR 0021); `MinijailProcessEffectPort` privately maps opaque IDs to SpawnRunner/OpenDevice/clone3/uid-map/FD effects; Provider crate imports no broker service/client/DTO |
| Integration | ADR046-minijail-002 (core-owned LaunchTicket); real cgroup/broker fixtures exercise the core adapter in `integration/clone3_pidfd/` and `integration/user_namespace/`, while the Provider observes only typed EffectPort results |
| Data migration | None - full d2b 3.0 reset; no prior state to migrate |
| Validation | `tests/fault_injection.rs`; `tests/platform_gate.rs`; `tests/broker_wait_contract.rs`; `tests/cgroup_kill_finalize.rs`; `integration/clone3_pidfd/`; `integration/user_namespace/`; `integration/broker_parent_reap/`; `integration/cgroup_kill_subtree/`; `integration/kernel_platform_gate/` |
| Removal proof | Old broker `SpawnRunner` direct-caller paths in `d2bd` removed after system-minijail Provider integration |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-minijail-004 (Dependency: ADR046-minijail-003)

| Field | Value |
| --- | --- |
| Dependency/owner | ADR046-minijail-003; wait/pidfd owner |
| Current source | `d2bd/src/supervisor/pidfd_table.rs` (PidfdTable, WaitTermination, BrokerReapLog) |
| Reuse action | adapt |
| Destination | Broker-side parent wait/reap and typed terminal relay in `packages/d2b-priv-broker/src/`; pidfd observation and signaling in core/ProviderSupervisor; typed outcome consumption in `packages/d2b-provider-system-minijail/src/effect_result.rs` |
| Detailed design | Broker that called `clone3` alone calls `waitid(P_PIDFD)`, collects exit status, and reaps exactly once; ProviderSupervisor `AsyncFd` readability is a hint only and never a wait/status source; controller consumes the identity-bound broker relay and holds no raw pidfd; ProviderSupervisor duplicate reacquisition is dispatched through a bounded blocking adapter with explicit timeout; pidfd never serialized; verified broker/ProviderSupervisor holder retains exact-main `pidfd_send_signal`; no PID/PGID fallback; graceful deadline followed by mandatory anchored leaf `cgroup.kill`; empty-leaf proof before rmdir; exit class classification (clean-exit/crash/signal/timeout/unknown) Primary reuse disposition: `adapt`. Preserved source-plan detail: EXTRACT/ADAPT. |
| Integration | Controller restart → adoption (ADR046-minijail-005); finalize (§8.6) |
| Data migration | None - full d2b 3.0 reset; no prior state to migrate |
| Validation | `tests/lifecycle.rs`; `tests/broker_wait_contract.rs` (only clone3 parent calls waitid/reaps; poll readability cannot supply status); `tests/cgroup_kill_finalize.rs` (setsid descendant and PGID reuse); `tests/redaction.rs` (PID never in log/status/audit); `tests/blocking_adapter.rs` (duplicate/status relay via adapter; timeout → error) |
| Removal proof | Old `PidfdTable` in `d2bd` supervisor removed after Provider integration |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-minijail-005 (Dependency: ADR046-minijail-002, ADR046-minijail-004, ADR046-session-001, ADR046-bus-001)

| Field | Value |
| --- | --- |
| Dependency/owner | All of ADR046-minijail-001 through ADR046-minijail-004; ComponentSession/d2b-bus (ADR046-session-001, ADR046-bus-001); bootstrap authz |
| Current source | `d2bd/src/supervisor/*.rs` (DagExecutor, NodeOutcome); `d2bd/src/supervisor/pidfd_table.rs`; `d2b-realm-core/src/allocator_engine.rs` (adoption/identity concepts) |
| Reuse action | adapt |
| Destination | `packages/d2b-provider-system-minijail/src/` - controller binary entry point; reconcile loop; adoption; quarantine; bootstrap authz; health/status; restart; finalize |
| Detailed design | Full Process/EphemeralProcess reconcile algorithm (§8); fast path ≤5/≤20 ms gates; spawn via `MinijailProcessEffectPort` (opaque IDs; no broker DTO imported); adoption algorithm (§8.5) consumes typed core-adapter observations after core performs `/proc` reads, cgroup enumeration, and original-broker-parent verification; quarantine on ambiguity; quarantine reuse blocked until externally established process-absence proof or full Zone reset; no stop request for quarantined/ambiguous identity; restart/backoff driven only by identity-bound typed terminal status; finalize (§8.6) requests graceful exact-main stop, bounded grace, mandatory subtree stop, broker wait/reap, and empty-leaf proof through the EffectPort, with no pidfd, PID, PGID, cgroup path, or kernel handle entering the Provider; EphemeralProcess continuation recovery (§9); bootstrap authz scope (§3); post-bootstrap RBAC; metric label closed-set enforcement (no `zone` label); controller writes status only on Process/EphemeralProcess resources; Provider resource status aggregated by core; the controller declares no Provider state Volume and mounts none - its bounded non-secret operational state lives in `status`/the core Operation ledger (§5.1, D087) and running units are re-adopted from core-reported observations on restart |
| Integration | Zone runtime startup (bootstrap); all v3 ResourceClient/bus/session paths |
| Data migration | Full reset; current DAG/role snapshot import not required |
| Validation | `tests/lifecycle.rs`; `tests/ephemeral_lifecycle.rs`; `tests/conformance.rs`; `tests/adoption_quarantine.rs`; `tests/broker_wait_contract.rs`; `tests/cgroup_kill_finalize.rs`; `tests/platform_gate.rs`; `tests/bootstrap_authz.rs`; `tests/fast_path.rs`; `tests/blocking_adapter.rs`; `integration/adoption_restart/`; `integration/quarantine_scenario/`; `integration/broker_parent_reap/`; `integration/cgroup_kill_subtree/`; `integration/kernel_platform_gate/`; `integration/latency_gate/`; shared conformance suite in `d2b-process-conformance` |
| Removal proof | Current `d2bd` DAG executor and direct spawn paths removed only after all ProcessRoles in the role-disposition table (ADR-046-components-processes-and-sandbox, §Representative baseline mapping) reach parity under system-minijail or system-systemd |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-minijail-006 (Dependency: ADR046-minijail-005)

| Field | Value |
| --- | --- |
| Dependency/owner | ADR046-minijail-005; Nix integrator; test infrastructure owner |
| Current source | `nixos-modules/processes-json.nix`; `nixos-modules/minijail-profiles.nix`; `packages/d2b-contract-tests/tests/policy_observability.rs` |
| Reuse action | adapt |
| Destination | `nixos-modules/` - v3 Nix `Process`/`EphemeralProcess` resource authoring; Provider catalog entry; `docs/reference/schemas/v3/core.d2bus.org_Process.schema.json`; `docs/reference/schemas/v3/core.d2bus.org_EphemeralProcess.schema.json`; `make test-drift` schema drift gate |
| Detailed design | Nix module accepts `d2b.zones.<zone>.resources.<name>` with `type = "Process"` or `"EphemeralProcess"`; eval-time validation rules (§16.4); build-time JSON validation (§16.5); artifact catalog integration; cleanup contract tests (§16.5) |
| Integration | `d2b.artifacts` catalog; Zone bundle emission; `make test-drift` |
| Data migration | Current `nixos-modules/processes-json.nix` and minijail profile Nix removed at cutover |
| Validation | `nix-unit` eval cases for every validation rule; schema drift gate; `tests/schema.rs` |
| Removal proof | `processes-json.nix`, `minijail-profiles.nix`, and `programs-json.nix` removed after v3 Nix parity |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

---

## 21. Removal proof

No current production path is removed until the exact Process Provider successor
is integrated and tested.

| Current path | Removed when |
| --- | --- |
| `d2bd` DAG executor direct minijail spawn paths | After ADR046-minijail-005 full lifecycle test parity (all ProcessRoles in disposition table) |
| `d2b-core/src/minijail_profile.rs` module | After ADR046-minijail-001 SandboxSpec compilation covers all current `MinijailProfile` callers |
| `d2b-core/src/process_builder.rs` | After ADR046-minijail-002 LaunchTicket builder replaces all current callers |
| `d2bd/src/supervisor/pidfd_table.rs` | After ADR046-minijail-004 broker-parent wait/reap plus non-parent observation/status relay replaces all current callers |
| `nixos-modules/processes-json.nix` | After ADR046-minijail-006 Nix Process resource authoring replaces all ProcessRole Nix emissions |
| `nixos-modules/minijail-profiles.nix` (virtiofsdProfiles) | After virtiofsd Process resources (Provider/volume-virtiofs) are fully validated under system-minijail |
| `d2b-realm-router` session implementation types | After ComponentSession (ADR046-session-001) replaces all Realm PeerSession routes |
| `d2bd/src/realm_stubs.rs` dead scaffolding | After bus/ComponentSession integration lands |
| `d2b-realm-core` WorkloadProviderKind/IsolationPosture public enums | After all consumers migrate to `Host`/`Guest`/`ExecutionPolicy` ResourceTypes at cutover |

Each removal requires a separate work item or disposition commit that
demonstrates test parity before deletion. No removal may occur as part of the
same commit as a new feature unless the feature directly replaces the removed
symbol with verified test coverage.

Per D094, each replaced current-code test is retired with an explicit
keep/adapt/move/delete disposition and a removal gate: the minimum reusable
semantic assertions migrate into this crate's hermetic `tests/`, and the old
duplicate tests, shell gates, fixtures, static artifacts, CI jobs, and manifest
entries are deleted once successor coverage and the removal proof pass -
updating the fixed Bazel suites, closed gate manifests, flake/Nix-unit pins,
generated ledgers, and CI jobs.
Old and new suites never run in parallel indefinitely.

---

## 22. Security invariants

The following invariants must hold at all times. Violation of any invariant
is a `runtime-security-violation` audit event and triggers quarantine or
process termination.

1. **Zero host capabilities for user-namespace processes.** Any process with
   `sandbox.userNamespace` set holds zero capabilities in the host capability
   set. In-namespace capabilities are namespace-scoped and do not grant host
   privilege. This preserves the ADR 0021 model for virtiofsd-class and
   comparable processes.

2. **No PID reuse in pidfd window.** The pidfd is obtained atomically from
   `clone3(CLONE_PIDFD)`. No window exists between clone and pidfd acquisition
   during which a PID could be reused.

3. **Cgroup-before-exec.** With `CLONE_INTO_CGROUP`, the process is placed in
   its cgroup leaf before any instruction executes. No window exists for the
   process to escape into an ancestor cgroup.

4. **No broad kill on quarantine; externally established proof required.**
   An ambiguous adoption or ambiguous finalize never issues any signal to the
   candidate process. Quarantine cannot be resolved by deleting/recreating the
   resource while the process may live. Cgroup leaf reuse and finalizer
   re-registration require externally established proof of process absence (OS
   inspection confirming the cgroup leaf is empty) or a destructive full Zone
   reset. The operator performs all process-absence verification through means
   external to d2b.

5. **Bootstrap authorization is non-configurable and contains no create verbs.**
   No operator config field widens the bootstrap authorization scope. The
   bootstrap grants cover only `get/list/watch/update-status/update-finalizers`
   on resources where `providerRef=Provider/system-minijail` - `create` verbs on
   any ResourceType are excluded. The `Provider/system-minijail` resource itself
   is runtime-created by the core-controller (`managedBy: controller`), not by
   system-minijail. A wrong subject, purpose, method, or Provider generation
   fails the bootstrap connection closed.

6. **Sandbox plan digest binding.** The compiled sandbox plan digest is bound
   into the LaunchTicket and re-verified by the broker at exec time. Any
   change between ticket issue and exec fails the spawn.

7. **UID/GID map write - effect port resolves principal; Provider never
   sees numeric IDs.** `userNamespace.mappingClass: process-principal-root`
   is the only public SandboxSpec field for user namespace identity. The core
   effect port resolves the exact host UID/GID for the declared Process
   component principal and enforces non-zero (non-root). It validates the
   parent name-to-inode binding for `/proc/<pid>/uid_map` and
   `/proc/<pid>/gid_map` writes with `O_NOFOLLOW` and re-verification before
   writing. No symlink or replacement can intercept the write. The Provider
   crate never holds or observes numeric host UID/GID values.

8. **No credential bytes in resource fields.** No credential byte, raw token,
   or secret appears in any Process/EphemeralProcess spec, status, audit
   record, log line, or metric label.

9. **Redaction before any external surface.** PID, pidfd number, cgroup path,
   argv, capability bitmask, mount source path, environment variable, and
   socket address are redacted from all Debug formatting, log events, audit
   records, and metric labels before reaching any external I/O path.

10. **Bootstrap provider cannot widen its own authorization.** system-minijail
    cannot grant itself additional RBAC verbs by creating Role or RoleBinding
    resources. Only the core-controller handles Role/RoleBinding creation, and
    it validates that no subject grants itself escalating verbs.

11. **Provider crate carries no broker service, client, or DTO.** The minijail
    controller crate imports no `d2b.broker.v3` service, client type, or broker
    DTO. All spawn effects flow exclusively through the injected
    `MinijailProcessEffectPort` with opaque identifiers. A compile-time
    dependency audit enforces this boundary; the effect port implementation
    remains owned by core/ProviderSupervisor and is the sole path to privileged
    broker operations.

12. **The minijail controller has no Provider state Volume.** Its signed
    component descriptor declares no state namespace, ProviderDeployment
    creates no state Volume, and the controller Process has no state-view
    mount or dedicated state-layout principal. Bounded non-secret observations
    remain in Process/EphemeralProcess status and the core Operation ledger.
    Running processes are re-observed from declared cgroup leaves and fresh
    pidfds; live pidfds and FDs are process-local and non-persistent and must
    never be serialized or reused across controller restarts without full
    re-verification.

13. **The `clone3` broker parent alone waits and reaps.** The broker retains
    the parent-held pidfd and alone calls `waitid(P_PIDFD, ...)`, collects the
    exit status, and reaps exactly once. ProviderSupervisor may poll a verified
    duplicate for readability and may use `pidfd_send_signal` on the exact main
    process, but it never waits/reaps or converts readability into an exit
    result. The Provider controller holds only an opaque handle and consumes
    the identity-bound broker relay. A replacement non-parent broker cannot
    claim wait/reap ownership.

14. **Intentional teardown uses the owned cgroup, never PGID ownership.** On
    Linux 5.14 or newer, after exact-main `SIGTERM` and the bounded graceful
    phase, the broker writes `1` to the reverified leaf's `cgroup.kill`, waits
    for `cgroup.events` `populated 0` and its own wait/reap result, and only then
    removes the leaf. This closes `setsid(2)` escape and PGID-reuse races. No
    PID/PGID SIGKILL fallback exists. An ambiguous/quarantined candidate is
    never signaled or subjected to `cgroup.kill`; its finalizer remains.
