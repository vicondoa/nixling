# ADR 0046 Provider dossier: system-systemd

| Field | Value |
| --- | --- |
| Spec ID | `ADR-046-provider-system-systemd` |
| Parent | ADR 0046 |
| Status | Accepted |
| Version | 1 |
| Baseline | `b5ddbed67867d9244bf33390868101bd9b053e49` |
| Normative | Yes |
| Owners | `d2b-provider-system-systemd` crate, Process contracts |
| Depends on | `ADR-046-provider-model-and-packaging`, `ADR-046-components-processes-and-sandbox`, `ADR-046-resources-host-guest-process-user`, `ADR-046-componentsession-and-bus`, `ADR-046-nix-configuration`, `ADR-046-telemetry-audit-and-support`, `ADR-046-current-code-migration-map` |
| Supersedes | Current `d2b-unsafe-local-helper` systemd scope runtime; current `d2bd` `supervisor/` VM process management; broker `SpawnRunner` (systemd-owned roles) |

---

## 1. Provider identity

| Field | Value |
| --- | --- |
| Canonical ResourceRef | `Provider/system-systemd` |
| ProviderType axis | Process, EphemeralProcess |
| Crate path | `packages/d2b-provider-system-systemd/` |
| Primary binary | `d2b-provider-system-systemd` (controller) |
| Nix artifact type | `"provider"` |

`Provider/system-systemd` is one of two first-party Process Provider
implementations, the other being `Provider/system-minijail`. Both implement the
identical `Process` and `EphemeralProcess` ResourceType schemas and the same
mandatory pidfd conformance contract (D022). They are independently installable
and replaceable; neither is the other's fallback. A Zone installs both; the
operator selects the appropriate Provider per-Process via `spec.providerRef`.

This Provider is not bootstrap-fixed. The fixed `Provider/system-minijail`
controller bootstraps and then reconciles the first `Provider/system-systemd`
controller `Process`. After that, `Provider/system-systemd` manages its own
ongoing reconcile lifecycle as an ordinary controller.

### Explicit exclusions

The following are NOT part of this Provider:

- `Provider/system-core`: reconciles Host and User only; does not launch Process
  resources.
- `Provider/system-minijail`: a separate, independently installed Process
  Provider; system-systemd does not fall back to it.
- Unsafe-local-specific Provider: there is no `Provider/unsafe-local`. The
  current `kind = "unsafe-local"` workload becomes a user-only `Host` resource
  reconciled by `Provider/system-core`. Its child Processes may use
  `Provider/system-systemd` with `domain=user` (D042).
- Per-workload static PID1 template units: forbidden. All units managed by this
  Provider are transient and exist only while the Process resource is
  non-terminal.
- Any function beyond Process and EphemeralProcess execution: Volume, Network,
  Device, Credential, and runtime Guest lifecycle are owned by their own
  Providers.

---

## 2. ResourceTypes implemented

| ResourceType | Lifecycle phases | Reconciler | Finalizer |
| --- | --- | --- | --- |
| `Process` | Pending → Launching → Ready → Degraded → Failed | system-systemd controller | `process-system-systemd.d2bus.org/cleanup` |
| `EphemeralProcess` | Pending → Ready → Succeeded\|Failed → (TTL cleanup) | system-systemd controller | `process-system-systemd.d2bus.org/cleanup` |

The ResourceType schemas are defined in
`ADR-046-resources-host-guest-process-user`. This Provider implements those
schemas exactly; it does not extend or modify the common spec or status fields.
No per-Provider ResourceType is registered. Only `Process` and
`EphemeralProcess` are owned by this controller.

**D089 desired-spec shape.** `Provider/system-systemd` reconciles only the
ResourceType base `spec.*` fields (including `spec.providerRef`) for
`Process` and `EphemeralProcess`; it carries no Provider-specific
`spec.provider` payload today. If a future implementation-only desired setting
is required, it must use the canonical `spec.provider = { schemaId,
schemaVersion, settings }` envelope, registered and signed in the Provider
manifest, deny-unknown, bounded, versioned/digested, validated against
`spec.providerRef` at Nix build and API admission, and forbidden to shadow base
fields. Shared fields are promoted to the ResourceType base. The Provider
implements the exact base spec/status schema version/fingerprint, accepts the
canonical minimal base Spec, passes base conformance, and rejects an
unsupported optional base capability only through its signed capability matrix plus
provider-neutral `unsupported-capability`.
`spec.provider` aligns with `status.provider`. The `Provider` resource itself
keeps the D075 `spec.{artifactId, config}` exception.

---

## 3. Process domains and placement

### Domain selection

`Provider/system-systemd` supports both `system` and `user` process domains on
any Host or Guest whose `allowedDomains` includes the chosen domain:

| Domain | Mechanism | Verification requirement |
| --- | --- | --- |
| `system` | Non-forking transient system service via effect port | InvocationID + cgroup leaf + MainPID + ExecMainStartTimestamp bound atomically |
| `user` | Non-forking transient user scope via effect port | Exact `userRef` UID verified by effect port implementation; per-user systemd manager reachable; scope identity verified identically |

Both domains use the same binding tuple (InvocationID, cgroup, MainPID,
start-time) before pidfd open. Neither domain uses a daemonizing unit type.
`Type=exec` is the mandatory systemd unit type; `Type=forking` and `Type=notify`
are forbidden. No compatibility fallback to `Type=simple` is permitted because
exec-ordering identity cannot be weakened.

### Supported executionRef targets

The controller descriptor declares compatibility with:

- `Host` targets (physical/local OS) - both `system` and `user` domains;
- `Guest` targets (VM, sandbox, cloud, remote) - both domains, subject to the
  selected runtime Provider exposing a systemd session inside the Guest.

A Guest runtime Provider that does not expose a systemd session fails
`CapabilitiesVerified` at the Host/Guest level; `Provider/system-systemd` fails
closed on missing capabilities rather than silently degrading.

### Effect port injection

The controller does not open ambient system or user DBus manager connections
and does not invoke `systemctl` or any raw DBus call. All transient unit
operations - `StartTransientUnit`, active-state observation, stop, kill, and
user-manager availability checks - are dispatched through a concrete
`SystemdProcessEffectPort` implementation injected into a controller generic
over the port type. The native async trait uses no trait object or
`async-trait` dependency. The effect port implementation is owned by the core
supervisor and process specs, not by this Provider crate.

The effect port:

- holds pre-opened system and per-user manager connections;
- owns exact same-UID verification before any user-domain operation;
- resolves the opaque `userRef`, `template`, and process identity tokens from
  the LaunchTicket into OS-level calls;
- binds the atomic identity tuple (`InvocationID`, `ControlGroup`, `MainPID`,
  `ExecMainStartTimestamp`), opens and re-verifies the pidfd, and returns only
  an opaque `ProcessIdentityHandle`, an identity digest, and a closed outcome;
- owns unit name computation (fixed hash-derived; opaque to the controller).

The controller receives only opaque handles, digests, typed results, and error
codes from the port; it never sees raw DBus paths, socket addresses, unit
names, cgroup strings, PIDs, pidfds, or systemd property fragments.

---

## 4. Provider spec config schema

The `Provider/system-systemd` spec is referenced through the Zone Nix
configuration using `spec.artifactId`:

```nix
d2b.artifacts.system-systemd = {
  package = pkgs.d2b-provider-system-systemd;
  type    = "provider";
};

d2b.zones.dev.resources.system-systemd = {
  type = "Provider";
  spec = {
    artifactId = "system-systemd";
    config     = {
      # All fields optional; shown with defaults
      launchTimeoutSec        = 30;             # u32; 1..3600; default 30
      terminationGraceSec     = 30;             # u32; 0..3600; default 30
      userManagerCheckTimeout = 5;              # u32; 1..60; default 5
      maxConcurrentLaunches   = 64;             # u32; 1..256; default 64
    };
  };
};
```

### Config field table

| Field | Type | Default | Bound | Description |
| --- | --- | --- | --- | --- |
| `launchTimeoutSec` | u32 | `30` | 1..3600 | Wall-clock seconds from `StartTransientUnit` call to `MainPID` appearing in the unit's active state. Expiry triggers `Degraded` with `reason: launch-timeout`. |
| `terminationGraceSec` | u32 | `30` | 0..3600 | Seconds to wait for graceful systemd drain before the core adapter requests a forced systemd stop. Overrides per-Process `drainTimeout` only when the Process value exceeds this bound. |
| `userManagerCheckTimeout` | u32 | `5` | 1..60 | Seconds before a per-user manager reachability check times out. Same-UID user-manager verification is mandatory; this bound controls the per-check deadline only. |
| `maxConcurrentLaunches` | u32 | `64` | 1..256 | Maximum number of in-flight `StartTransientUnit` calls at any one time across all Processes on this controller instance. Excess launches wait in the pending queue without blocking the controller-wide watch loop. |

Transient unit names are fixed hash-derived implementation details computed by the
controller from the process identity (execution ID, process UID, template generation
hash). They are not operator-configurable and never appear in public status fields,
audit records, error messages, or metric label values.

No secret bytes, credential material, host paths, unit property fragments,
cgroup paths, or raw capability lists appear in Provider config. Sensitive
process-level behavior is compiled from the `SandboxSpec` of each `Process`
resource, not from Provider config strings.

The Provider config schema is signed and hash-bound to the Provider resource
generation. Any config change increments the Provider generation and triggers a
cascade reconcile of all active Processes using this Provider.

---

## 5. Component descriptors and binaries

### 5.1 Controller

| Field | Value |
| --- | --- |
| Component ID | `systemd-controller` |
| Type | `controller` |
| Binary | `d2b-provider-system-systemd` |
| Execution domain | `system` |
| executionRef placement | one controller instance per execution target (e.g., `Host/<name>` or `Guest/<name>`) |
| Cgroup leaf | `z-<zone-id>/controller/executions/e-<exec-id>/system/providers/p-<provider-id>/components/c-systemd-controller/process/` |

The core `ProviderDeployment` creates the controller `Process` resource via
`Provider/system-minijail` (bootstrap). The controller owns a single async
reconcile loop watching `Process` and `EphemeralProcess` resources in its Zone.
One controller instance runs per execution target; multiple execution targets in
the same Zone each receive a separate controller instance on their respective
target.

All systemd manager interactions are dispatched through the injected
`SystemdProcessEffectPort` (§3 "Effect port injection"). The controller holds
no DBus connections itself.

#### Controller responsibilities

- Watch `Process` and `EphemeralProcess` resources filtered to
  `spec.providerRef = Provider/system-systemd`.
- For each new/updated `Process`: validate spec, compile sandbox, verify all
  dependencies, dispatch a `LaunchTicket` to the ProviderSupervisor
  asynchronously.
- For each running `Process`: subscribe to unit state transitions via the effect
  port; write process status on exit/restart/degraded.
- For each `EphemeralProcess`: launch once, wait for terminal state, record
  outcome and exitCode, begin TTL countdown.
- Maintain only opaque per-Process identity handles; core/ProviderSupervisor
  owns the non-persistent pidfd table.
- On controller restart: relist live `Process` resources, attempt adoption per
  the adoption algorithm; quarantine on identity mismatch.
- Respond to `desiredLifecycle=stopped`: invoke effect port `StopUnit`, then
  `KillUnit` if needed; verify unit reaches inactive/dead.

#### Fast path target (D030)

- p95 durable commit → controller handler start: ≤5 ms
- p95 durable commit → launch attempt start (first effect port `start` call):
  ≤20 ms
- Each `Process` reconcile runs in an independent async task; the watch loop is
  not blocked.

### 5.2 Canonical controller Process ResourceSpec

Core `ProviderDeployment` creates the following `Process` resource for each
execution target. This is the full canonical spec - no implicit or prose-only
fields:

```nix
# Created by core ProviderDeployment; operator does not declare this directly.
d2b.zones.<zone>.resources."system-systemd-controller-<target>" = {
  type = "Process";
  metadata.ownerRef = "Provider/system-systemd";
  spec = {
    providerRef  = "Provider/system-minijail";   # bootstrap provider
    executionRef = "Host/<execution-target>";     # one per execution target
    domain       = "system";
    processClass = "controller";
    template     = "system-systemd-controller-main";
    sandbox = {
      namespaceClasses  = [ "mount" "ipc" "network" ];
      capabilityClasses = [];
      seccompClass      = "strict";
      noNewPrivileges   = true;
      readOnlyRoot      = true;
      startRoot         = false;
      environmentClass  = "minimal";
      userNamespace     = null;
    };
    budget = {
      memory = { limit = "128Mi"; };
      cpu    = { request = "500m"; };
      pids   = { limit = 256; };
    };
    networkUsage = null;
    readiness    = {
      class            = "ready-condition";
      initialDelay     = "0s";
      timeout          = "30s";
      failureThreshold = 3;
      successThreshold = 1;
    };
    restartPolicy = {
      class             = "on-failure";
      backoffBase       = "1s";
      backoffMax        = "60s";
      backoffMultiplierMilli = 2000;
      maxRestarts       = null;
      resetAfter        = "300s";
    };
    mounts = [];
    adoptionPolicy = "adopt-on-restart";
    drainTimeout   = "30s";
  };
};
```

Canonical rendered JSON (schema mirror):

```json
{
  "apiVersion": "resources.d2bus.org/v3",
  "type": "Process",
  "metadata": {
    "name": "system-systemd-controller-<target>",
    "zone": "<zone>",
    "ownerRef": "Provider/system-systemd"
  },
  "spec": {
    "providerRef": "Provider/system-minijail",
    "executionRef": "Host/<execution-target>",
    "domain": "system",
    "processClass": "controller",
    "template": "system-systemd-controller-main",
    "configRef": null,
    "credentialRefs": [],
    "mounts": [],
    "sandbox": {
      "namespaceClasses": ["mount", "ipc", "network"],
      "capabilityClasses": [],
      "seccompClass": "strict",
      "noNewPrivileges": true,
      "startRoot": false,
      "environmentClass": "minimal",
      "readOnlyRoot": true,
      "umask": "0022",
      "oomScoreAdj": 0,
      "userNamespace": null
    },
    "budget": {
      "memory": {"limit": "128Mi"},
      "cpu": {"request": "500m"},
      "pids": {"limit": 256}
    },
    "networkUsage": null,
    "readiness": {
      "class": "ready-condition",
      "initialDelay": "0s",
      "timeout": "30s",
      "failureThreshold": 3,
      "successThreshold": 1
    },
    "desiredLifecycle": "running",
    "restartPolicy": {
      "class": "on-failure",
      "backoffBase": "1s",
      "backoffMax": "60s",
      "backoffMultiplierMilli": 2000,
      "maxRestarts": null,
      "resetAfter": "300s"
    },
    "adoptionPolicy": "adopt-on-restart",
    "drainTimeout": "30s"
  }
}
```

`networkUsage: null` is correct: the controller communicates via Unix socketpair
(ComponentSession to ProviderSupervisor and to d2b-bus) and via the injected
effect port (DBus is a Unix socket internally). Its stable control service
identity is an owned `Endpoint` resource, not an inline Process field.
`processClass: controller` is mandatory; `worker` and `service` are rejected by
ProviderDeployment for this resource.

The controller Process produces its stable process-control service identity as a
separate owned `Endpoint` resource:

```yaml
apiVersion: resources.d2bus.org/v3
type: Endpoint
metadata:
  name: system-systemd-process-control-<target>
  zone: <zone>
  ownerRef: Provider/system-systemd
spec:
  providerRef: Provider/system-systemd
  producerRef: Process/system-systemd-controller-<target>
  endpointClass: control
  transport: unix
  purpose: system-systemd.d2bus.org/process-control
  serviceFingerprint: system-systemd.d2bus.org/ProcessControl.v3
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

## 5.3 Endpoint resources (D092)

`Provider/system-systemd` conforms to the standard `Endpoint` base schema. The
stable ComponentSession service used for process launch/control is an owned
`Endpoint` resource with `producerRef`; ProviderSupervisor consumes it as
`Endpoint/<name>`. Endpoint spec/status never carries DBus paths, unit names,
cgroup paths, PIDs, pidfds, fd numbers, socket paths, or credentials. Resolution
occurs only through an authorized EffectPort/LaunchTicket; unauthorized
resolution returns `endpoint-resolve-denied`. Producer restart bumps
`Endpoint.status.endpointGeneration`, causing ProviderSupervisor to observe
`dependency-changed` and reconnect through a fresh authorized ticket.

## 5.4 Retained opaque handles (D092 promotion test)

- pidfds remain ephemeral core/ProviderSupervisor supervision/identity handles;
  the controller retains only opaque `ProcessIdentityHandle` values.
- LaunchTicket fd indexes, systemd manager handles, and inherited socketpairs are
  per-launch attachment slots, not stable endpoint identities.
- InvocationID/MainPID/unit identity tuples and cgroup observations are effect-port
  verification data and never public Endpoint status.
- `operationId`, cancellation tokens, and LaunchTicket identity tokens remain
  opaque per-operation correlation/authorization handles.
- `OwnedTransport` and ComponentSession IDs are in-memory capabilities behind
  Endpoint resolution.

---

## 6. Process launch algorithm (system-systemd conformance)

The following algorithm implements the system-systemd conformance requirements
from `ADR-046-resources-host-guest-process-user` §system-systemd conformance.
Every step is mandatory; any deviation is a runtime security violation.

### 6.1 Pre-launch

1. Receive `LaunchTicket` from ProviderSupervisor, bound to:
   - Process/EphemeralProcess ref, UID, revision, generation;
   - owner Provider/component/template;
   - executionRef, domain, userRef;
   - compiled sandbox digest;
   - sealed config digest;
   - expected process identity template generation;
   - operation/deadline/cancellation token.
2. Verify ticket signature against controller lease.
3. Re-read Process spec snapshot; verify revision matches ticket.
4. Resolve `spec.template` against the signed component descriptor of the owning
   resource's registered controller. Verify the template maps to an exact binary
   entry + content digest in the signed descriptor.
5. Validate that every semantic `SandboxSpec` class is supported and allowed by
   the signed descriptor; compute `sandboxRevisionDigest` over the canonical
   semantic spec, policy ID, and template generation. The Provider does not
   compile or receive systemd property fragments.
6. Verify all `mounts[].volumeRef` targets are Ready. Core resolves the opaque
   Volume refs to private mount attachments when constructing the LaunchTicket.

### 6.2 Launch

7. Invoke the effect port `start` operation, passing:
   - the `LaunchTicket` identity token (opaque; encodes domain, executionRef,
     userRef, template generation, and sandbox revision);
   - the opaque sandbox policy ID and `sandboxRevisionDigest`;
   - the `launchTimeoutSec` bound.
   The port selects the correct manager connection (system or per-user),
   verifies domain-specific preconditions, privately maps the signed semantic
   sandbox policy to systemd properties, constructs a transient unit with
   `Type=exec` (mandatory; the port rejects `Type=forking`, `Type=notify`, and
   `Type=oneshot`), and dispatches `StartTransientUnit`.
8. Receive an opaque start receipt; no unit name, InvocationID, PID, cgroup,
   property fragment, or manager handle crosses the EffectPort.

### 6.3 Identity binding

9. Core awaits active state within `launchTimeoutSec`, atomically reads and
   validates InvocationID, ControlGroup, MainPID, and
   ExecMainStartTimestamp, verifies expected cgroup placement and launch
   timing, opens and re-verifies the pidfd, and computes the identity digest.
10. The EffectPort returns only
    `IdentityBound { handle, processIdentityDigest }` or a closed failure such
    as `identity-mismatch`, `pid-reuse-detected`, or `pidfd-open-failed`.
11. The controller stores the opaque handle in memory and writes only
    `processIdentityDigest` to Process status. Missing or inconsistent identity
    causes quarantine without exposing the underlying values.

### 6.4 Pidfd acquisition

Pidfd acquisition, `/proc` re-verification, pidfd polling, and systemd
identity reads are core adapter responsibilities. The Provider never receives
or opens a pidfd and never reads `/proc`. systemd owns wait/reap and cgroup
termination. Stop and kill requests use only the opaque identity handle; core
re-verifies identity and reports a typed terminal observation.

### 6.5 Readiness

20. Subscribe to unit state transitions via the effect port watch stream on the
    `UnitHandle`.
21. When `readiness.class=ready-condition`: the Process is Ready when the `Ready`
    condition transitions to `True` (controller-internal; set when the port
    reports `ActiveState=active` and `MainPID` confirmed live).
22. When `readiness.class=provider-defined`: the controller checks the template's
    named readiness mechanism (e.g., `sd_notify READY=1` receipt signalled
    through the effect port) within `readiness.timeout`.
23. Failure to reach ready within `readiness.timeout` → write `Degraded` with
    `reason: readiness-timeout`; apply restart policy.

---

## 7. EphemeralProcess handling

`EphemeralProcess` uses the identical launch algorithm (§6) with these
differences:

- `spec.processClass` must be `worker`; `controller` and `service` are rejected
  at spec admission.
- No `restartPolicy`, `adoptionPolicy`, or `healthCheck` fields; the process
  runs once.
- `startDeadline`: the time from spec commit to effect port `start` call must
  not exceed this value. Expiry → `Failed` with `reason: start-deadline-exceeded`.
- `runtimeDeadline`: the time from first `ActiveState=active` to exit. Expiry →
  SIGTERM followed by SIGKILL; phase = `Failed` with `reason: runtime-deadline-exceeded`.
- On clean exit (exit code 0): phase = `Succeeded`; `completedAt` set; TTL
  countdown begins from `successfulTtl`.
- On non-zero/signal exit: phase = `Failed`; `completedAt` set; TTL countdown
  begins from `failedTtl`.
- TTL expiry triggers unit cleanup (stop if still active) and finalizer
  clearance. `incidentHold=true` blocks cleanup; operator must set it to false.

The outcome `code` and `exitCode` are written to `status.outcome` when the
unit's exit status is available from the effect port. `exitCode` is an optional
u32 in status only; it never appears in audit, metric labels, or log messages
with a resource-name label.

---

## 8. Restart and adoption

### 8.1 Restart

After a Process exits while `desiredLifecycle=running`:

1. Classify exit: `clean-exit` (exit code 0), `crash` (SIGSEGV/SIGABRT/
   hardware fault), `signal` (other signal), `timeout` (SIGKILL after drain).
2. Apply `restartPolicy.class`:
   - `never`: write `phase=Failed`; no restart.
   - `always`: restart unconditionally.
   - `on-failure`: restart if exit code ≠ 0.
   - `on-crash`: restart only if classified `crash`.
3. Increment `restartCount`; if `restartCount >= maxRestarts`: write `Failed`.
4. Apply exponential backoff:
   `delay = min(backoffBase * (backoffMultiplierMilli / 1000)^(restartCount-1), backoffMax)`.
5. After `resetAfter` duration of continuous `Ready` state, reset
   `restartCount = 0`.
6. Dispatch next launch at the end of backoff delay. Backoff does not hold the
   controller-wide queue.

### 8.2 Adoption after controller restart

On controller startup, the relist step finds `Process` resources with non-
terminal phase. For each:

1. Request EffectPort adoption using only the Process ref and stored
   `processIdentityDigest`.
2. Core locates the unit, reads and validates the full identity tuple, compares
   the digest, opens and re-verifies a fresh pidfd, and returns
   `Adopted { handle }`, `Quarantined`, or `NotFound`.
3. On `Adopted`, retain the opaque handle, write
   `adoptionState=adopted`, and resume typed EffectPort observation.
4. On `Quarantined`, write `adoptionState=quarantined` and do not issue any
   stop effect.
5. On `NotFound`, write `adoptionState=adoption-failed` and re-launch.

Quarantined processes are never killed by adoption logic. The operator resolves
them via explicit `delete` or `update-spec` with an acknowledged quarantine
acknowledgment field.

---

## 9. Drain and stop

On `desiredLifecycle=stopped` or `deletion-requested` (finalizer):

1. Invoke the effect port `stop` operation on the opaque identity handle.
2. Wait `drainTimeout` (per Process spec, capped at `terminationGraceSec` from
   Provider config when the Process value is larger).
3. If the unit has not reached inactive/dead, invoke the EffectPort forced-stop
   operation on that handle. Core re-verifies identity, asks systemd to kill the
   unit, waits for the core-held pidfd and unit state to agree on termination,
   and returns a typed outcome.
4. Release the opaque handle.
5. Clear finalizer `process-system-systemd.d2bus.org/cleanup`.

On ambiguous state (unit gone, cgroup empty, exit not confirmed via effect port):
emit audit condition `process-exit-unconfirmed`; record `finalized`; do not
block deletion indefinitely.

---

## 10. Sandbox validation and core mapping

The controller validates `Process.spec.sandbox` against signed semantic policy
and computes a deterministic `sandboxRevisionDigest`. It passes only the
opaque policy ID and digest through SystemdProcessEffectPort. The core adapter
owns the frozen mapping to systemd unit hardening properties:

The mapping from semantic sandbox classes to systemd properties:

| SandboxSpec field | Compiled systemd property |
| --- | --- |
| `namespaceClasses: [pid]` | `PrivatePIDs=yes` |
| `namespaceClasses: [mount]` | `PrivateMounts=yes`, `ProtectSystem=strict` |
| `namespaceClasses: [ipc]` | `PrivateIPC=yes` |
| `namespaceClasses: [uts]` | `ProtectHostname=yes` |
| `namespaceClasses: [network]` | `PrivateNetwork=yes` |
| `capabilityClasses: [network-bind]` | `AmbientCapabilities=CAP_NET_BIND_SERVICE`, `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` |
| `capabilityClasses: [network-admin]` | `AmbientCapabilities=CAP_NET_ADMIN`, `CapabilityBoundingSet=CAP_NET_ADMIN` |
| `seccompClass=strict` | `SystemCallFilter=@system-service` (or Provider's built-in minimal allowlist) |
| `seccompClass=permissive` | `SystemCallLog=yes` (log only; no filter) |
| `seccompClass=allow-all` | No `SystemCallFilter=`; requires explicit descriptor carve-out in Provider descriptor |
| `noNewPrivileges=true` | `NoNewPrivileges=yes` |
| `readOnlyRoot=true` | `ProtectSystem=strict`, `ReadWritePaths=` restricted to declared mounts |
| `environmentClass=minimal` | Inherited environment stripped to approved minimal set; no `LD_PRELOAD`, no `HOME`, no `USER` unless `safe-inherited` or `provider-defined` is set |
| `umask` | `UMask=<octal>` |
| `oomScoreAdj` | `OOMScoreAdjust=<val>` |

`userNamespace` in `SandboxSpec` carries a semantic `mappingClass` field.
`Provider/system-systemd` does not support user namespace setup. If
`userNamespace.mappingClass` is non-null for any Process assigned to
system-systemd, the controller rejects it at admission with
`reason: unsupported-user-namespace-mapping`. User namespace provisioning for
virtiofsd-class processes is exclusively `Provider/system-minijail`'s
responsibility (D051).

No raw systemd unit property fragment, `ExecStart=` override, or `Environment=`
assignment enters or leaves the Provider process. Core derives all properties
from the signed semantic policy and executable reference.

---

## 11. Bus services, messages, and streams

`Provider/system-systemd` exposes one controller ComponentSession service on
the d2b-bus for ProviderSupervisor integration. All sessions use Noise_NN with
Unix socketpair transport (purpose class: local).

### 11.1 ProviderSupervisor → controller service

Route key:
```text
(Zone, service=d2b.process.systemd.v1, method, target=Provider/system-systemd,
 schema_fingerprint, provider_generation)
```

| Method | Direction | Description |
| --- | --- | --- |
| `LaunchProcess` | request/response | Receive opaque Process/template/policy IDs; request launch through SystemdProcessEffectPort; return `processIdentityDigest` or error. |
| `StopProcess` | request/response | Receive `ProcessRef + pidfd-less stop request`; drain and stop unit; return outcome. |
| `AdoptProcess` | request/response | Receive `ProcessRef + adoptionCandidateDigest`; run adoption algorithm; return `adopted`/`quarantined`/`failed`. |
| `QueryProcessState` | request/response | Receive `ProcessRef`; return current typed process state (common phase + exit class); does not surface raw systemd `ActiveState`/`SubState` strings. |

No method accepts a pidfd from the caller. No method returns a pidfd to the
caller. All methods are bounded-latency; `LaunchProcess` is async (returns after
`StartTransientUnit` call, not after readiness).

### 11.2 Controller watch stream

The controller consumes a named stream watch of `Process` and `EphemeralProcess`
resources from the Zone runtime over d2b-bus:

- Stream kind: resource-watch;
- Delivery cursor: resource revision (not session sequence);
- Credit bound: per the fair-scheduling rules in ComponentSession spec;
- Reconnect: after reconnect, the controller relists from the stored last-seen
  revision and resumes watching.

### 11.3 Status writes

Status updates are async `UpdateStatus` calls over d2b-bus with expected
revision. The controller writes:

- `phase` transitions (Pending → Launching → Ready → Degraded → Failed);
- `processIdentityDigest`, `waitReapOwner`, `sandboxRevisionDigest`,
  `configRevisionDigest` after launch;
- `adoptionState` after adoption;
- `lastExitClass`, `restartCount`, `lastRestartAt` on exit;
- all `conditions[]` entries.

Status writes do not block the watch loop. Each write uses an independent async
task with expected-revision optimistic concurrency. The controller writes status
only to `Process` and `EphemeralProcess` resources; the framework aggregates
those into the Provider-level status using the common phase enum. Systemd
`ActiveState` and `SubState` are tracked internally as typed detail within
`ProcessEffect` audit records; they do not appear as raw strings in any
Provider or Process status field.

Per D088, the Process/EphemeralProcess universal `ResourceStatus` base remains
at top-level `status.*`, and ResourceType-common process observation written by
system-systemd lives in `status.resource`. Any bounded, non-secret
systemd-specific observation lives in `status.provider` with
`providerRef: Provider/system-systemd`, a qualified `schemaId` such as
`system-systemd.d2bus.org/Process/status` or
`system-systemd.d2bus.org/EphemeralProcess/status`, `schemaVersion` (semver MAJOR.MINOR),
`observedProviderGeneration`, and a strict unknown-field-denied, ≤32 KiB,
redacted `details` object registered and signed in the Provider manifest. Each
controller write updates all present layers atomically in one status mutation;
shared fields are promoted to `status.resource` and never copied into
`status.provider`.

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
the controller realization; core re-adopts running workload Processes from
cgroup leaves with fresh pidfds and returns opaque handles, without disruption
unless the plan requires it. Disruptive changes return `UpgradeRequired` rather than applying in place,
non-disruptive changes reconcile normally, and the per-resource single-flight
serializes reconcile versus upgrade.

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

---

## 12. RBAC and broker/effect boundaries

### 12.1 Role verbs this Provider uses

`Provider/system-systemd` requires `RoleBinding` grants for:

| Verb | ResourceType | Required for |
| --- | --- | --- |
| `update-status` | `Process` | Writing process status after launch, exit, restart |
| `update-status` | `EphemeralProcess` | Writing ephemeral process outcome/status |
| `get` | `Process` | Reading process spec during reconcile |
| `list` | `Process` | Startup relist for adoption |
| `watch` | `Process` | Ongoing reconcile watch |
| `get` | `EphemeralProcess` | Reading ephemeral spec |
| `list` | `EphemeralProcess` | Startup relist |
| `watch` | `EphemeralProcess` | Ongoing reconcile watch |
| `get` | `Host` | Verifying `executionRef` phase before launch |
| `watch` | `Host` | Detecting Host state transitions |
| `finalize` | `Process` | Clearing `process-system-systemd.d2bus.org/cleanup` finalizer |
| `finalize` | `EphemeralProcess` | Clearing finalizer after terminal state |

These RoleBindings are configuration-declared and evaluated by the native
Role/RoleBinding evaluator before any bus operation.

### 12.2 Broker operations

`Provider/system-systemd` uses no privileged broker operations and holds no
direct DBus manager connections. All systemd manager interactions - including
system and per-user `StartTransientUnit`, active-state observation, stop, kill,
and user-manager availability checks - are dispatched through the injected
`SystemdProcessEffectPort` whose implementation is owned by the core supervisor
spec. It does not invoke `BrokerOperation::SpawnRunner`, `CgroupSubtree`, or
any other broker op. Cgroup placement is systemd's responsibility once a
transient unit is active.

The ProviderSupervisor handles the LaunchTicket flow; it does not itself invoke
a broker op for system-systemd processes.

### 12.3 Effect boundaries

- This Provider does NOT create, modify, or delete Host, Guest, Volume, Network,
  Device, User, or Credential resources.
- This Provider does NOT hold Credential leases.
- This Provider does NOT hold DBus connections; all systemd manager interactions
  go through the injected `SystemdProcessEffectPort`.
- This Provider does NOT perform nftables, bridge, TAP, or other network
  mutations.
- This Provider DOES create and clear its own finalizer on Process and
  EphemeralProcess resources.
- This Provider DOES write process status via the authorized `update-status`
  verb.
- This Provider's controller process is itself a `Process` resource (launched by
  `Provider/system-minijail` during bootstrap) running in the system domain.

---

## 13. Lifecycle and drain

### 13.1 Provider lifecycle phases

| Phase | Meaning |
| --- | --- |
| `Pending` | Provider resource created; controller not yet running |
| `Ready` | Controller running; watch loop active; process launches accepted |
| `Degraded` | Controller running but effect port reports system or user manager unavailable; affected-domain launches suspended; remaining-domain launches continue |
| `Failed` | Controller process exited unrecoverably; Processes are orphaned until adoption |

The controller writes status only to `Process` and `EphemeralProcess` resources.
The framework aggregates those into the Provider-level status using the common
phase enum. Systemd `ActiveState` and `SubState` are tracked internally by the
effect port as typed detail exposed only through `ProcessEffect` audit records;
they never surface as raw strings in Provider or Process status fields.
Any implementation-specific bounded observation that is not audit-only follows
the D088 `status.provider.details` extension contract on the owned
Process/EphemeralProcess resource; fields needed by cross-provider Process
consumers are instead promoted to `status.resource`.

`ProviderStateSet` is the optional, query-time grouping of the *declared*
`Volume` resources in a Zone whose `metadata.ownerRef` resolves to
`Provider/system-systemd`. It is not a ResourceType or stored artifact and is
empty for this Provider.

`Provider/system-systemd` declares **no** Provider state Volume; its
`ProviderStateSet` is empty. Its bounded non-secret operational state -
controller/effect-port readiness, per-Process launch/adoption observations,
active-process counters, and closed-enum error detail - lives in the owning
resource's `status` subresource and the core Operation ledger (D087). Pidfds
remain ephemeral core/ProviderSupervisor state and opaque effect-port handles
remain controller-local; persisted restart
counts, backoff state, and checkpoints are core resource/operation state
(`Process`/`EphemeralProcess` status and the core Operation ledger), and running
units are re-adopted by core after restart from declared cgroup leaves and fresh
pidfds.

Because that operational state is fully derivable from spec, `status`, the core
Operation ledger, and external process observation, it fails the storage-need
test: the controller declares no state namespace, no state Volume, no
state-view mount, and no dedicated `User/<controller-system-user>` state-layout
principal. There is no empty identity-only Volume, and the controller Process
mounts no state Volume.

Example Provider status (framework-aggregated):

```yaml
# Aggregated by framework from controller-reported conditions.
status:
  phase: Ready           # common phase enum only
  conditions:
    - type: ControllerReady
      status: "True"
    - type: EffectPortReady
      status: "True"     # system manager reachable via effect port
    - type: UserEffectReady
      status: "True"     # False when user manager unreachable via port
  resource:
    activeProcessCount: 12
    activeEphemeralProcessCount: 3
```

Provider-level `status.resource` fields (core-derived per D085/D088, not
written by the systemd controller):

| Field | Type | Description |
| --- | --- | --- |
| `activeProcessCount` | u32 | Non-terminal `Process` resources managed by this controller |
| `activeEphemeralProcessCount` | u32 | Non-terminal `EphemeralProcess` resources |

No pidfd value, PID, cgroup path, unit name, or DBus path appears in Provider
status.

### 13.2 Drain

On Provider drain (`desiredLifecycle=stopped` on the Provider's own Process
resource):

1. Stop accepting new `LaunchProcess` requests.
2. Invoke effect port `stop` on all active opaque identity handles; wait up to
   `terminationGraceSec`.
3. Invoke the EffectPort forced-stop operation on each remaining opaque handle;
   core re-verifies identity and confirms termination using systemd state and
   its private pidfd.
4. Write `Degraded` phase to all owned Process resources with condition
   `reason: provider-drain`.
5. Release all opaque identity handles.
6. Exit cleanly.

Active Processes that exit during drain write their final status before the
controller exits. Processes that are mid-launch when drain starts are
aborted at the earliest safe point and their status is written `Failed`.

### 13.3 Upgrade

When the Provider resource generation changes (artifact or config update):

1. The controller receives a reconcile hint on its own Process resource.
2. It completes in-flight launches (bounded by `launchTimeoutSec`).
3. It exits cleanly.
4. `Provider/system-minijail` re-launches the updated controller binary.
5. The new controller restarts, relists, and adopts running Processes per §8.2.

No active child process is killed during a Provider upgrade. Running Processes
continue under systemd's supervision while the controller is restarting.

---

## 14. Error catalogue

All error codes are stable machine-readable strings. Bounded redacted messages
accompany each code in `status.conditions[].message` (max 512 chars, no paths/
argv/PIDs/names).

| Error code | Condition type | Meaning |
| --- | --- | --- |
| `launch-ticket-invalid` | `Launching` | LaunchTicket signature or binding check failed |
| `template-not-found` | `Launching` | `spec.template` not present in signed component descriptor |
| `sandbox-compile-error` | `Launching` | `SandboxSpec` contains an unsupported or invalid combination |
| `unsupported-user-namespace-mapping` | `Launching` | `userNamespace.mappingClass` is non-null; user namespace setup not supported by system-systemd |
| `dependency-not-ready` | `DependenciesReady` | A required Volume, Network, or Device is not Ready |
| `user-not-found` | `UserReady` | `spec.userRef` does not resolve to a Ready User |
| `user-manager-unavailable` | `UserReady` | Per-user systemd manager not reachable or not running |
| `system-bus-unavailable` | `ProviderReady` | System DBus manager not reachable |
| `launch-timeout` | `Launching` | `MainPID` did not appear within `launchTimeoutSec` |
| `identity-mismatch` | `Adopted` | InvocationID/cgroup/start-time tuple does not match stored digest |
| `pidfd-open-failed` | `Launching` | `pidfd_open(2)` failed (possible PID reuse race) |
| `pid-reuse-detected` | `Launching` | cgroup/PPid re-verification after pidfd open detected PID reuse |
| `readiness-timeout` | `Ready` | Process did not pass readiness check within `readiness.timeout` |
| `process-crashed` | `Ready` | Process exited with SIGSEGV/SIGABRT/hardware fault |
| `max-restarts-exceeded` | `Ready` | `restartCount >= restartPolicy.maxRestarts` |
| `runtime-deadline-exceeded` | `Ready` | EphemeralProcess ran past `runtimeDeadline` |
| `start-deadline-exceeded` | `Launching` | EphemeralProcess was not launched within `startDeadline` |
| `quarantined` | `Adopted` | Adoption identity check failed; process quarantined |
| `process-exit-unconfirmed` | finalizer | Process exit not confirmed through DBus before finalization |
| `provider-drain` | `Ready` | Process Degraded because Provider is draining |
| `runtime-security-violation` | `Launching` | Detected an invariant violation (any of: daemonizing unit type used, InvocationID absent, unit-name used as identity, incorrect cgroup placement) |

---

## 15. Telemetry

### 15.1 Metrics

All metric label values come from the closed sets specified in
`ADR-046-telemetry-audit-and-support`. No resource name, Zone name, PID,
cgroup path, user name, or unit name appears as a metric label value.

| Metric | Type | Labels | Buckets (s) | Notes |
| --- | --- | --- | --- | --- |
| `d2b_process_launch_total` | counter | `provider=systemd`, `domain={system,user}`, `outcome={ok,error,quota}` | - | Incremented once per `StartTransientUnit` call completion |
| `d2b_process_launch_duration_seconds` | histogram | `provider=systemd`, `domain` | 0.001, 0.005, 0.010, 0.015, 0.020, 0.030, 0.050, 0.1, 0.5, 2.0 | Commit → first OS call; p95 ≤20 ms target |
| `d2b_process_active` | gauge | `provider=systemd`, `domain` | - | Live non-terminal Process count |
| `d2b_process_restart_total` | counter | `provider=systemd`, `class={exited,signaled,killed}` | - | Per restart event |
| `d2b_process_adoption_total` | counter | `provider=systemd`, `outcome={ok,quarantine,error}` | - | Per adoption attempt |
| `d2b_process_stop_duration_seconds` | histogram | `provider=systemd`, `stop_class={graceful,forced}`, `outcome` | 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 30.0 | Drain time measurement |
| `d2b_process_pidfd_active` | gauge | (none) | - | Core-owned live entries in the ephemeral pidfd table |
| `d2b_provider_reconcile_total` | counter | `resource_type={Process,EphemeralProcess}`, `outcome={ok,requeue,conflict,error}` | - | |
| `d2b_provider_reconcile_duration_seconds` | histogram | `resource_type` | 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 2.0 | |
| `d2b_provider_component_phase` | gauge | `component_type=controller`, `phase` | - | Controller process phase |
| `d2b_controller_hint_to_handler_seconds` | histogram | `handler=systemd_process` | 0.001, 0.002, 0.005, 0.010, 0.015, 0.020, 0.030, 0.050 | p95 ≤5 ms target |

### 15.2 Spans

| Span name | Kind | Attributes |
| --- | --- | --- |
| `d2b.process.systemd.launch` | Internal | `domain`, `process_class`, `template_id_digest`, `outcome`, `operation_id` |
| `d2b.process.systemd.identity_bind` | Internal | `domain`, `outcome` |
| `d2b.process.systemd.pidfd_open` | Internal | `domain`, `outcome` (emitted by core effect adapter) |
| `d2b.process.systemd.stop` | Internal | `stop_class`, `domain`, `outcome` |
| `d2b.process.systemd.adopt` | Internal | `domain`, `outcome` |

Spans never carry: PID, unit name, cgroup path, user name, UID, executable path,
argv, environment variables, credential bytes, or resource `metadata.name`.
`template_id_digest` is SHA-256 of the template ID string, not the template ID
in plaintext. `operation_id` is an opaque correlation token only.

### 15.3 Audit

Audit records follow the `ProcessEffect` shape from
`ADR-046-telemetry-audit-and-support`. The `provider` field is `"system-systemd"`.

| Event kind | Trigger | Required fields |
| --- | --- | --- |
| `process-effect.launch` | Process launched (StartTransientUnit succeeded + identity bound) | `provider=system-systemd`, `domain`, `execution_ref_digest`, `process_uid`, `outcome` |
| `process-effect.stop` | Process stopped (unit inactive/dead confirmed) | same fields + `exit_class` |
| `process-effect.adopt` | Process adopted after controller restart | same fields + `adoption_outcome` |
| `process-effect.quarantine` | Process quarantined after identity mismatch | same fields + `quarantine_reason` |

For user-domain Processes on a user-only Host (`isolationPosture=none`):
`no_isolation=true` is added to every `ProcessEffect` record. It is absent for
all other Processes. It must not appear in OTEL metrics, span attributes, or log
fields.

No audit record carries: PID, unit name, cgroup path, user name, socket path,
argv, environment, or raw DBus error message. `execution_ref_digest` is
SHA-256 of the resolved `executionRef` ResourceRef string. `process_uid` is the
opaque resource UID.

---

## 16. Nix configuration

### 16.1 Artifact catalog entry

```nix
d2b.artifacts.system-systemd = {
  package = pkgs.d2b-provider-system-systemd;
  type    = "provider";
};
```

`pkgs.d2b-provider-system-systemd` is the Nix derivation built from
`packages/d2b-provider-system-systemd/`. It is the only place where the build
output appears; no store path enters any ResourceSpec, status, audit, or
telemetry field.

### 16.2 Provider ResourceSpec declaration

```nix
d2b.zones.dev.resources.system-systemd = {
  type = "Provider";
  spec = {
    artifactId = "system-systemd";      # bounded ID; matches d2b.artifacts entry
    config = {
      launchTimeoutSec        = 30;
      terminationGraceSec     = 30;
      userManagerCheckTimeout = 5;
      maxConcurrentLaunches   = 64;
    };
  };
};
```

Canonical rendered JSON (schema mirror):

```json
{
  "apiVersion": "resources.d2bus.org/v3",
  "type": "Provider",
  "metadata": {
    "name": "system-systemd",
    "zone": "dev"
  },
  "spec": {
    "artifactId": "system-systemd",
    "config": {
      "launchTimeoutSec": 30,
      "terminationGraceSec": 30,
      "userManagerCheckTimeout": 5,
      "maxConcurrentLaunches": 64
    }
  }
}
```

No store path, executable path, socket address, or secret value appears in the
rendered JSON. `artifactId` is a plain bounded string; it references the
artifact catalog at build time and carries no runtime path.

### 16.3 Process declaration using this Provider

```nix
d2b.zones.dev.resources.wayland-proxy = {
  type = "Process";
  metadata.ownerRef = "Provider/display-wayland";
  spec = {
    providerRef    = "Provider/system-systemd";
    executionRef   = "Host/host-system";
    domain         = "system";
    processClass   = "worker";
    template       = "wayland-proxy-main";
    sandbox = {
      namespaceClasses = [ "mount" "ipc" ];
      capabilityClasses = [];
      seccompClass     = "strict";
      noNewPrivileges  = true;
      startRoot        = false;
      readOnlyRoot     = true;
      environmentClass = "minimal";
    };
    budget = {
      memory = { limit = "128Mi"; };
      pids   = { limit = 64; };
    };
    telemetry = {
      metricsEnabled = true;
      tracingEnabled = true;
      logLevel       = "info";
    };
  };
};
```

Canonical rendered JSON:

```json
{
  "apiVersion": "resources.d2bus.org/v3",
  "type": "Process",
  "metadata": {
    "name": "wayland-proxy",
    "zone": "dev",
    "ownerRef": "Provider/display-wayland"
  },
  "spec": {
    "providerRef": "Provider/system-systemd",
    "executionRef": "Host/host-system",
    "domain": "system",
    "processClass": "worker",
    "template": "wayland-proxy-main",
    "configRef": null,
    "credentialRefs": [],
    "mounts": [],
    "sandbox": {
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
    },
    "budget": {
      "memory": {"limit": "128Mi"},
      "pids": {"limit": 64}
    },
    "telemetry": {
      "metricsEnabled": true,
      "tracingEnabled": true,
      "logLevel": "info",
      "sensitiveLabels": false
    },
    "desiredLifecycle": "running",
    "restartPolicy": {
      "class": "on-failure",
      "backoffBase": "1s",
      "backoffMax": "60s",
      "backoffMultiplierMilli": 2000,
      "maxRestarts": null,
      "resetAfter": "300s"
    },
    "adoptionPolicy": "adopt-on-restart",
    "drainTimeout": "30s"
  }
}
```

### 16.4 User-domain Process declaration

```nix
d2b.zones.dev.resources.shell-session = {
  type = "Process";
  spec = {
    providerRef  = "Provider/system-systemd";
    executionRef = "Host/laptop-shell";          # user-only Host (isolationPosture=none)
    domain       = "user";
    userRef      = "User/alice";
    processClass = "worker";
    template     = "shell-supervisor-main";
    sandbox = {
      namespaceClasses = [];
      capabilityClasses = [];
      seccompClass     = "strict";
      noNewPrivileges  = true;
      startRoot        = false;
      readOnlyRoot     = false;
      environmentClass = "safe-inherited";
    };
  };
};
```

For user-domain Processes on a user-only Host, the `no_isolation=true`
attribute is present in every `ProcessEffect` audit record (§15.3). The CLI/UI
renders the Host with the `⚠ no isolation boundary` warning. The spec itself
contains no `isolationPosture` field; the warning derives from the parent Host
resource status at runtime.

### 16.5 Nix eval and build validation rules

| Rule | Layer | Enforcement |
| --- | --- | --- |
| `spec.artifactId` exists in `d2b.artifacts` with `type = "provider"` | Build | Hard eval error if absent or wrong type |
| `spec.config.*` field names and value types match Provider schema | Build | JSON schema validation against signed Provider schema |
| `spec.config.launchTimeoutSec` in range 1..3600 | Eval | NixOS module `types.ints.between` |
| `spec.config.terminationGraceSec` in range 0..3600 | Eval | NixOS module `types.ints.between` |
| `spec.config.userManagerCheckTimeout` in range 1..60 | Eval | NixOS module `types.ints.between` |
| `spec.config.maxConcurrentLaunches` in range 1..256 | Eval | NixOS module `types.ints.between` |
| No store path in rendered JSON | Build | Schema enforces string-only `artifactId` |
| `Process.spec.providerRef = "Provider/system-systemd"` resolves to a Ready Provider | Eval (ref validation) | ResourceRef must be declared in same Zone |
| `Process.spec.domain = "user"` requires `userRef` or `executionRef.defaultUserRef` | Eval | ADR-046-resources-host-guest-process-user admission rules |
| `Process.spec.sandbox.userNamespace.mappingClass` must be null | Eval / Build | Enforcement by system-systemd Provider schema; non-null `mappingClass` rejects with `unsupported-user-namespace-mapping` |
| No secret bytes in any spec field | Eval / Build | `credentialRef: true` marker in schema for every credential-bearing field |

---

## 17. Current-code fit and migration

### 17.1 Current code anchors

Evidence class per `ADR-046-current-code-migration-map`:

| Current source | Evidence class | Current role |
| --- | --- | --- |
| `packages/d2b-unsafe-local-helper/src/systemd.rs` | `production-reachable` | `SystemdUserScopeManager`: creates/stops transient user scopes via zbus; `VerifiedScope` identity; `InvocationID` + `ControlGroup` + `MainPID` binding |
| `packages/d2b-unsafe-local-helper/src/runtime.rs` | `production-reachable` | `ScopeRuntime<M>`, `run_scope_supervisor`: user scope lifecycle supervision, backoff, snapshot |
| `packages/d2b-unsafe-local-helper/src/protocol.rs` | `production-reachable` | `HelperClient`/`HelperServer`: wire protocol between `d2bd` and helper (to be replaced by ComponentSession supervisor ticket) |
| `packages/d2b-unsafe-local-helper/src/environment.rs` | `production-reachable` | `ManagerEnvironment`: environment setup before user scope exec |
| `packages/d2bd/src/supervisor/` | `production-reachable` | `VmProcessDag` supervision, `ProcessRole`-based pidfd adoption, restart backoff, watchdog |
| `packages/d2bd/src/lib.rs` - `d2b_daemon_pidfd_table_size` metric, `SO_PEERCRED` admin socket | `production-reachable` | Live pidfd table gauge; admin process model |
| `packages/d2b-contracts/src/unsafe_local_wire.rs` | `production-reachable` | `DaemonToUnsafeLocalHelper`/`UnsafeLocalHelperToDaemon` wire types; `HelperLaunchRequest`; `HelperScopeState` |

### 17.2 Behavior retained

- DBus transient unit creation and `InvocationID` + `ControlGroup` + `MainPID`
  binding from `systemd.rs` is retained and adapted.
- `VerifiedScope` identity tuple (InvocationID, ControlGroup, MainPID) becomes
  the identity binding input for `processIdentityDigest` computation.
- Exponential backoff restart logic from `runtime.rs` is retained.
- `pidfd_open` after PID verification from `d2bd/src/supervisor/` is retained.
- `d2b_daemon_pidfd_table_size` gauge is adapted to `d2b_process_pidfd_active`
  (no resource-name label).

### 17.3 Required delta (ADR-only)

- Common `Process`/`EphemeralProcess` ResourceType and status schema (no
  ProcessRole enum).
- Provider/controller crate structure (`src/`, `tests/`, `integration/`,
  `README.md`).
- `LaunchTicket` signed binding and ProviderSupervisor integration.
- `sandboxRevisionDigest` and `processIdentityDigest` computation and write.
- d2b-bus ComponentSession service (`LaunchProcess`, `StopProcess`,
  `AdoptProcess`, `QueryProcessState`).
- `SystemdProcessEffectPort` trait and Provider-side fake; the production
  implementation is owned by core and owns DBus manager connections, unit name
  computation, UID verification, pidfds, identity binding, and
  start/observe/stop/adopt operations.
- User-domain execution via effect port; UID verification and manager-connection
  lifecycle owned by port implementation.
- ProviderStateSet: empty - the controller declares no Provider state Volume; bounded non-secret operational state lives in `status`/the core Operation ledger (D087); core re-adopts running units from cgroup leaves + fresh pidfds on restart and returns opaque handles.
- Async reconcile loop watching `Process` / `EphemeralProcess` resources.
- `system-systemd` conformance tests and shared conformance kit integration.

### 17.4 Reuse path (from main `a1cc0b2d`)

The effect port test double and controller session patterns are informed by
ComponentSession usage in main `a1cc0b2d`:

| Main source | Behavior selected | v3 destination |
| --- | --- | --- |
| `packages/d2b-session/src/engine.rs` | Async session establish/reconnect; owned transport | `d2b-provider-system-systemd/src/effect_port.rs` (test double session plumbing) |
| `packages/d2b-session-unix/src/adapter.rs` | Unix peer identity, socketpair adapter | `d2b-provider-system-systemd/src/effect_port.rs` (transport for test double) |

Excluded from reuse: v2 `EndpointRole`, `Realm` process model, delivery
assumptions. Copied behavior is independently re-tested against v3
`AuthenticatedSubjectContext`.

### 17.5 Replacement/deletion conditions

| Current artifact | Removal condition |
| --- | --- |
| `packages/d2b-unsafe-local-helper/src/systemd.rs` | Retained as implementation reference; `SystemdUserScopeManager` and `VerifiedScope` inform the effect port contract. Old caller (`d2b-unsafe-local-helper` binary) removed after user-domain Process path parity via effect port. |
| `packages/d2b-unsafe-local-helper/src/protocol.rs` (`HelperClient`/`HelperServer`) | Removed after all user-domain launch paths migrate to LaunchTicket/effect port flow. |
| `packages/d2b-contracts/src/unsafe_local_wire.rs` | Removed after `DaemonToUnsafeLocalHelper` protocol has no remaining callers. |
| `packages/d2bd/src/supervisor/` (`VmProcessDag`) | Removed per-role after each `Process` ResourceType successor is integrated and passes conformance. |
| Per-workload static PID1 template units (`nixos-modules/unsafe-local-helper.nix`) | Removed after user-only Host Process supervision migrates to system-systemd user-domain controller. |

---

## 18. Implementation work items

### ADR046-systemd-001

| Field | Value |
| --- | --- |
| Work item ID | `ADR046-systemd-001` |
| Dependency/owner | `ADR046-process-002`; Process contracts/supervisor owner; effect port interface owner |
| Current source | `packages/d2b-unsafe-local-helper/src/systemd.rs` - `SystemdUserScopeManager`, `VerifiedScope`; `packages/d2bd/src/supervisor/` - pidfd adoption, restart backoff |
| Reuse source | Main `a1cc0b2d`: `d2b-session/src/engine.rs`, `d2b-session-unix/src/adapter.rs` (effect port test double session/transport) |
| Reuse action | adapt |
| Destination | `packages/d2b-provider-system-systemd/src/controller.rs` (async reconcile loop), `src/launch.rs` (opaque launch requests via effect port), `src/effect_port.rs` (`SystemdProcessEffectPort` trait + fake), `src/adoption.rs` (typed adoption outcomes), `src/sandbox.rs` (semantic SandboxSpec validation); production DBus/pidfd/systemd-property implementation in core/ProviderSupervisor |
| Detailed design | Full §6 launch algorithm (effect port integration); §7 EphemeralProcess; §8 restart/adoption (effect port `locate_by_identity`); §9 drain (effect port `stop`/`kill`); §10 sandbox compilation; §11 bus services; ProviderSupervisor LaunchTicket integration Primary reuse disposition: `adapt`. Preserved source-plan detail: extract and adapt. |
| Integration | Core ProviderDeployment creates the controller Process via Provider/system-minijail with no state Volume or `/state` mount; the controller issues no Volume CRUD operations, watches Process/EphemeralProcess, and persists bounded non-secret observations only in owning-resource status and the core Operation ledger; ProviderSupervisor calls LaunchProcess; effect port implementation is injected by the core supervisor spec |
| Data migration | No state migration; controller relists and adopts on restart |
| Validation | `tests/conformance.rs` (shared conformance kit); `tests/identity_binding.rs` (InvocationID/cgroup/MainPID/start-time golden vectors via mock effect port); `tests/adoption.rs` (quarantine/identity-mismatch cases); `tests/restart.rs` (backoff/maxRestarts); latency assertions (p95 ≤5 ms hint→handler, ≤20 ms commit→effect port `start` call) |
| Removal proof | `VmProcessDag` supervisor roles removed per role disposition table after each succeeds in conformance |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-systemd-002

| Field | Value |
| --- | --- |
| Work item ID | `ADR046-systemd-002` |
| Dependency/owner | `ADR046-systemd-001`; Nix/package integrator |
| Current source | `nixos-modules/unsafe-local-helper.nix`; `nixos-modules/processes-json.nix` |
| Reuse action | adapt |
| Destination | `nixos-modules/` (Provider ResourceSpec emission for `system-systemd`); `packages/d2b-provider-system-systemd/` package derivation and catalog entry |
| Detailed design | §16 Nix configuration; `d2b.artifacts.system-systemd` catalog entry; Provider and Process ResourceSpec emission; eval/build validation rules; drift gate update (`xtask gen-nix-options` + `make test-drift`) |
| Integration | Zone configuration activates Provider/system-systemd; Process resources reference it via `spec.providerRef = "Provider/system-systemd"` |
| Data migration | No configuration compatibility path; full reset at v3 cutover |
| Validation | `tests/unit/nix/cases/provider-system-systemd.nix` (eval-time validation); `tests/unit/gates/drift-check.sh` covers generated option schema |
| Removal proof | `nixos-modules/unsafe-local-helper.nix` removed after user-domain Host/Process parity |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

### ADR046-systemd-003

| Field | Value |
| --- | --- |
| Work item ID | `ADR046-systemd-003` |
| Dependency/owner | `ADR046-systemd-001`; conformance kit / test infrastructure |
| Current source | `packages/d2bd/src/supervisor/` (existing process lifecycle tests); `packages/d2b-unsafe-local-helper/src/systemd.rs` (existing scope tests) |
| Reuse action | adapt |
| Destination | `packages/d2b-provider-system-systemd/tests/conformance.rs`, `tests/fault.rs`, `tests/ephemeral.rs`, `tests/sandbox_compile.rs`; `integration/host_scenario.rs`, `integration/guest_scenario.rs` |
| Detailed design | Full §19 test/integration requirements Primary reuse disposition: `adapt`. Preserved source-plan detail: copy/adapt. |
| Integration | `cargo test -p d2b-provider-system-systemd`; `make test-integration -- provider-system-systemd`; `make test-host-integration -- provider-system-systemd` |
| Data migration | None - full d2b 3.0 reset; no prior state to migrate |
| Validation | All conformance vectors pass; all fault injection scenarios reach expected phase/condition; all §19 Host and Guest test scenarios pass |
| Removal proof | No removal; tests are permanent |
| Implementation state | Planned |
| Evidence | The complete Destination and Validation obligations above have not both been verified in the indexed tree. |

---

## 19. Required crate layout and test/integration requirements

The crate at `packages/d2b-provider-system-systemd/` must contain exactly:

```
packages/d2b-provider-system-systemd/
├── src/
│   ├── main.rs                     # controller binary entry point
│   ├── controller.rs               # async reconcile loop, watch, dispatch
│   ├── launch.rs                   # §6 launch algorithm via effect port
│   ├── effect_port.rs              # SystemdProcessEffectPort trait + test double
│   ├── adoption.rs                 # §8.2 adoption algorithm
│   ├── sandbox.rs                  # §10 semantic SandboxSpec validation
│   ├── ephemeral.rs                # §7 EphemeralProcess lifecycle
│   ├── drain.rs                    # §13.2 drain/stop via effect port
│   ├── audit.rs                    # §15.3 ProcessEffect audit emission
│   ├── metrics.rs                  # §15.1 metric instruments
│   └── error.rs                    # §14 error catalogue
├── tests/
│   ├── conformance.rs              # shared conformance kit (`check_provider_conformance`)
│   ├── identity_binding.rs         # opaque identity receipt and mismatch/quarantine cases
│   ├── adoption.rs                 # adoption algorithm: adopted/quarantined/failed outcomes; restart scenarios
│   ├── restart.rs                  # backoff/maxRestarts/resetAfter correctness
│   ├── ephemeral.rs                # EphemeralProcess: TTL, startDeadline, runtimeDeadline
│   ├── sandbox_compile.rs          # semantic SandboxSpec validation: every class; unsupported `user` namespace rejection
│   └── fault.rs                    # fault injection: launch timeout, identity mismatch, effect port unavailable
├── integration/
│   ├── host_scenario.rs            # real controller vs real Zone runtime; system-domain Process lifecycle; Volume pre-created by ProviderDeployment; controller consumes dirfd only
│   ├── guest_scenario.rs           # controller inside a Guest; system-domain and user-domain Process lifecycle
│   ├── user_domain.rs              # real per-user scope via effect port; user-only Host no_isolation audit event emission
│   └── cleanup_scenario.rs         # generation change → async Delete; audit ordering contract
└── README.md                       # §20 Provider README (see below)
```

Workspace policy rejects any `packages/d2b-provider-system-systemd/` crate
missing any of the four top-level paths (`src/`, `tests/`, `integration/`,
`README.md`). It does not enforce specific file names within those directories;
the file names listed above are spec-required for implementation completeness
but are not workspace-policy-checked.

### test/ requirements

Every file in `tests/` is invoked by `cargo test -p d2b-provider-system-systemd`.
No container daemon, real Host, or real Guest is required; all tests use mocks
and `FakeProvider` fixtures from `d2b-provider-toolkit`:

| Test file | Required assertions |
| --- | --- |
| `conformance.rs` | `check_provider_conformance` returns zero `ConformanceError` for `Process` and `EphemeralProcess` ProviderType axes |
| `identity_binding.rs` | Mock EffectPort returns opaque `IdentityBound`, `identity-mismatch`, and `pid-reuse-detected` outcomes; Provider never receives tuple fields or a pidfd. Core adapter tests own the raw tuple golden vectors. |
| `adoption.rs` | Mock effect port `locate_by_identity` returns match → `adopted`; any mismatch → `quarantined` (unit NOT killed); absent unit → `adoption-failed` + effect port `stop`+`kill` attempt |
| `restart.rs` | `on-failure`: restart on non-zero, not on zero; `never`: no restart; backoff exponential; `maxRestarts` exceeded → `Failed`; `resetAfter` resets counter |
| `ephemeral.rs` | Zero exit → `Succeeded`, TTL countdown; non-zero exit → `Failed`; `runtimeDeadline` expiry → SIGTERM then SIGKILL → `Failed`; `startDeadline` expiry → `Failed`; `incidentHold=true` blocks cleanup |
| `sandbox_compile.rs` | Every semantic `NamespaceClass` and `capabilityClasses` value is accepted or rejected per signed policy; no systemd property fragment is produced; `userNamespace.mappingClass` non-null → `unsupported-user-namespace-mapping`; `seccompClass=allow-all` without descriptor carve-out → error. Core adapter tests own semantic-class-to-systemd-property mappings. |
| `fault.rs` | `launchTimeoutSec` expiry via mock port `await_active` → `Degraded` + `reason: launch-timeout`; effect port returns `EffectPortUnavailable` → `ProviderReady=False`; port returns `UserManagerUnavailable` → `UserEffectReady=False` for user-domain only |

### integration/ requirements

Files in `integration/` are fixtures or Rust programs invoked by existing
repository test orchestration (`make test-integration` /
`make test-host-integration`), NOT by `cargo test`:

| Integration file | Scenario | Required assertions |
| --- | --- | --- |
| `host_scenario.rs` | Real controller against Zone runtime in container | System-domain Process: Pending → Launching → Ready; SIGTERM drain → stopped; restart on crash; Provider drain stops all active Processes; core re-derives adoption after controller restart from cgroup leaves + fresh pidfds and returns opaque handles; controller declares no Provider state Volume and issues no Volume CRUD operations |
| `guest_scenario.rs` | Controller inside a Guest via runtime Provider | Same lifecycle; both system and user domain; Guest-hosted Processes visible in Zone resource watch |
| `user_domain.rs` | User-domain Process via real effect port on Host | User-domain Process Pending → Ready; effect port reports user manager unreachable → `UserEffectReady=False`; `no_isolation=true` in ProcessEffect audit for user-only Host |
| `cleanup_scenario.rs` | Nix generation change → async Delete | Process removed from Nix config → `ResourceDeletionRequested` audit event emitted; store `Deleted` revision and row/index removal are applied atomically in the same store transaction; `ResourceDeleted` audit record is appended separately after the atomic deletion (deduplicated on replay) and its append does not participate in the deletion transaction; no false delete for controller-managed children |

### Fast hermetic execution and test placement (D094)

Per D094 and the repository's test-budget guidance, this Provider's `src/`
unit tests and `tests/*.rs` hermetic suite are fast, in-process, deterministic,
and parallel-safe: an individual normal test has an advisory wall-clock p95
diagnostic threshold of <=50 ms; gate enforcement is aggregate per-crate
process CPU only. There is no wall-clock
sleep, and `cargo test -p d2b-provider-system-systemd --lib --tests` completes in ≤3 s warm-cache
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

Per D094, each replaced current-code test is retired with an explicit
keep/adapt/move/delete disposition and a removal gate: the minimum reusable
semantic assertions migrate into this crate's hermetic `tests/`, and the old
duplicate tests, shell gates, fixtures, static artifacts, CI jobs, and manifest
entries are deleted once successor coverage and the removal proof pass -
updating the fixed Bazel suites, closed gate manifests, flake/Nix-unit pins,
generated ledgers, and CI jobs.
Old and new suites never run in parallel indefinitely.

---

## 20. Provider README.md required content

The `packages/d2b-provider-system-systemd/README.md` must contain all sections
listed in the crate layout requirement (`ADR-046-current-code-migration-map` §0.3
and `ADR-046-provider-model-and-packaging` Provider dossier requirement):

| Section | Required content |
| --- | --- |
| Provider identity | `Provider/system-systemd`; ProviderType axis: Process, EphemeralProcess; crate path `packages/d2b-provider-system-systemd/` |
| Nix config schema | `d2b.zones.<zone>.resources.<name>` snippet with `spec.artifactId` and the four `spec.config.*` fields (`launchTimeoutSec`, `terminationGraceSec`, `userManagerCheckTimeout`, `maxConcurrentLaunches`); rendered canonical JSON; no unit-name or user-manager-enable fields (unit names are fixed hash-derived; user-manager verification is mandatory); no credential field (no `credentialRef: true` markers in this Provider) |
| ResourceTypes | Table: `Process` (phases Pending→Launching→Ready→Degraded→Failed, owner field, finalizer `process-system-systemd.d2bus.org/cleanup`); `EphemeralProcess` (phases Pending→Ready→Succeeded\|Failed, finalizer) |
| Controllers/services/workers/binaries | Binary `d2b-provider-system-systemd`; `systemd-controller` component (one instance per execution target); core ProviderDeployment creates controller Process via Provider/system-minijail; no user supervisor binary or entry point inside this crate; cgroup placement per §5.1 |
| Placement | Valid Host and Guest execution targets; `allowedDomains: [system, user]`; required `providerRef` chain (Provider/system-systemd must be Ready before any Process uses it); system and user domain both dispatched through injected `SystemdProcessEffectPort`; effect port implementation is core-owned |
| Dependencies and RBAC | Required RoleBinding verbs per §12.1 (no User RoleBindings; UID verification is effect port responsibility); no broker operations; ComponentSession on d2b-bus for ProviderSupervisor integration; no internal socketpair service |
| Security and state | No capabilities claimed; no secrets or credential leases; no direct DBus connections (all systemd interactions through injected effect port); the controller declares no Provider state Volume - bounded non-secret operational state lives in `status`/the core Operation ledger (D087); core-owned pidfds and controller-held opaque effect handles are ephemeral and not persisted; core re-adopts running units from cgroup leaves + fresh pidfds; no OFD locks; no raw systemd property fragments enter the Provider |
| Telemetry | Metric instruments per §15.1; span catalog per §15.2; audit `ProcessEffect` record per §15.3; `no_isolation=true` on user-only Host child ProcessEffect records only |
| Build/test/integration commands | `cargo test -p d2b-provider-system-systemd`; `make test-integration -- provider-system-systemd`; `make test-host-integration -- provider-system-systemd` |
| Standalone-repo future usage | Crate depends only on published crates and the d2b provider SDK subset (`d2b-contracts`, `d2b-provider-toolkit`); may be extracted to its own repository without copying daemon internals |

---

## 21. Current-code fit summary table

| Item | Treatment |
| --- | --- |
| Current anchor | `packages/d2b-unsafe-local-helper/src/systemd.rs` (production-reachable user scope creation/verification); `packages/d2bd/src/supervisor/` (production-reachable pidfd adoption/restart) |
| Evidence class | production-reachable (both anchors) |
| Behavior retained | Core EffectPort implementation retains DBus transient unit creation, InvocationID/ControlGroup/MainPID/ExecMainStartTimestamp binding, pidfd open and re-verification, and scope identity verification; Provider retains semantic restart/backoff decisions over opaque outcomes |
| Required delta | Process/EphemeralProcess ResourceType and status schema; LaunchTicket/ProviderSupervisor integration; sandboxRevisionDigest/processIdentityDigest; async reconcile loop; d2b-bus ComponentSession service; `SystemdProcessEffectPort` trait + test double (core implementation); no Provider state Volume (bounded non-secret operational state in status/core ledger, D087); conformance tests |
| Reuse path | `SystemdUserScopeManager`/`VerifiedScope` inform the core effect adapter contract and Provider fake; `d2bd/src/supervisor/` backoff logic informs Provider `src/adoption.rs` and `src/controller.rs`, while raw discovery and pidfd logic remain core-owned |
| Replacement/deletion | `d2b-unsafe-local-helper` binary and `unsafe_local_wire.rs` protocol types retained until user-domain Host Process launch parity via effect port confirmed; `VmProcessDag` roles removed per per-role disposition table after each process type achieves conformance |
| Feasibility proof | `SystemdUserScopeManager` demonstrates transient user scope + InvocationID binding is production-tested; pidfd adoption in `d2bd/src/supervisor/` demonstrates identity-mismatch quarantine path |
| Future owner | `ADR046-systemd-001` through `ADR046-systemd-003` |
