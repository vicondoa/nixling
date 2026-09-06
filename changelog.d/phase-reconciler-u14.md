### Changed

- Retried bounded transient StoreBackpressure/Timeout during Zone startup,
  activation, Core/provider relists, and Process composition with delayed
  async backoff, waitable bounded redb read admission, preserved typed store
  diagnostics, and readiness withheld on exhaustion.
- Live Cloud Hypervisor inputs and Wayland session lookups now validate exact
  StoreList snapshots against their returned revision, so status-only Provider
  updates do not invalidate unchanged typed configuration.
- Replaced only finished Core runner identities during reconciliation, keeping
  healthy Core and Provider siblings live and ensuring every required runner
  identity is present before reporting success.
- Preserved the last successful required Core runner identity set across failed
  replacement setup, keeping readiness fail-closed until every required
  identity has a live replacement.
- Added bounded relist recovery coverage for transient source backpressure,
  including typed exhaustion and the existing watch-backpressure no-relist
  path.
- Cleared deferred watch-hint state across relist recovery, fenced delayed
  pre-relist watch tasks from resurrecting stale work, and cleaned up newly
  spawned Core runners when task ownership is poisoned.
- Bounded transient Core/Provider source backpressure retries across startup,
  watch recovery, and per-resource passes; dead required Core runner tasks now
  withhold readiness until the next lifecycle reconciliation replaces them,
  with non-sensitive Zone/resource-operation diagnostics. Core admission
  backpressure now retries the watch without relisting, while a closed store
  watch maps to disconnect recovery; watch-hint queue pressure defers through
  the runner scheduler without blocking worker joins. Source-pressure
  exhaustion keeps its source classification instead of becoming a handler
  failure, and per-resource source retries remain limited to fresh-read
  recovery rather than authorization or post-effect persistence failures.
- Finalized the Zone Provider cutover with target-scoped activation and
  telemetry reconciliation, exact 27-Provider composition proof, and
  Provider-filtered descriptor validation.
- Materialized fixed Process Provider identities, re-armed controller-session
  reconciliation on Process changes, and gated Guest sessions on live VMM
  identity and Cloud Hypervisor API readiness.
- Allowed sparse Zones to attach only shared Provider runners backed by
  committed resources, while still refusing a missing Provider that owns work.
- Applied the same fail-closed ownership check to Credential, storage,
  interaction, Guest, and observability runner startup paths.
- Made sparse interaction composition explicitly absent-aware, kept present
  U9 Providers on filtered watches while refusing incomplete identity, accepted
  schema-valid system-core Users without a synthetic providerRef, and withheld
  daemon readiness on mandatory Process runner failure with bounded diagnostics.
- Bound Process assignment fences to the Core controller identity and aligned
  system Process finalizers with the canonical Provider finalizer namespace.
- Kept authenticated system-core status and finalizer projections local to
  resource audit while retaining broker evidence for desired-state mutations.
- Preserved that broker-evidence classification when pending audit outboxes
  are normalized during crash recovery.
- Replaced the inert host acceptance controller with an authenticated fd10
  ComponentSession fixture, made controller-session shutdown ownership explicit,
  and retried bounded watch revision conflicts during relist/open-watch recovery.
- Routed the acceptance controller through the Bazel-built host-tool bundle so
  the host VM lane does not rebuild its fixture controller through Nix.
- Reconnected the fd10 acceptance controller across daemon restarts, kept
  Ready Process observation read-only, and rebased exhausted Runner status
  projections to the exact target revision without killing the healthy runner.
- Derived Core Provider readiness from fenced controller Process/session
  evidence and admitted declared qualified ResourceTypes, including the
  virtiofs Export child type, before Provider-owned child reconciliation.
- Matched controller-session Provider generation evidence exactly, preserved
  Process phase and observed-generation ownership while persisting session
  projections, and retained live controller authority for retry when durable
  session clearing fails.
- Kept qualified API catalog admission limited to trusted U6-U9 declarations;
  unknown bundle ResourceTypes now fail closed instead of becoming implicit
  universal API bindings.
- Kept exhausted status conflicts inside a bounded persistence-only loop so
  retries retain effect identity without re-running accepted Process effects.
- Classified transient persistence timeouts as bounded status retries, kept
  integrity failures fail-closed, and threaded accepted effect identity into
  the production Core/Resource API ledger update.
- Continued status mutations under the accepted effect operation identity and
  retained the authority row across durable status retry and reopen.
- Reused the supplied effect operation on capability-miss status retries,
  rejecting identity mismatches instead of falling back to projection IDs.
- Validated capability-miss retries against the durable effect row and exact
  UID/generation/revision before reusing the supplied effect operation.
- Resumed pending or retryable authority rows on capability-miss retries and
  refused to report persistence success while the ledger remained nonterminal.
- Serialized controller-session fencing before durable evidence clearing,
  rebound evidence writes to the live system-core status client, and retried
  missing evidence for active sessions without starving unrelated controllers.
- Isolated stale controller-session admission markers, separated session
  evidence operation identities from Process status writes, and required
  Volume readiness to match the current Provider owner UID and the Volume's
  own Ready/observed-generation fence; owner generation remains an
  effect/write fence rather than a read-side readiness dependency.
- Fenced controller-session evidence by Process UID and generation, cleared
  stale teardown evidence without retaining a fenced live session, replaced
  Provider dependency census with owner-scoped child reads, and persisted
  Volume owner generations through the Resource API snapshot path.
- Kept fixed system-core and system-minijail Providers on declared Zone/Host
  readiness evidence, required explicit Provider-owned Volume progress, and
  rejected stale owner UID observations without requiring a matching child
  owner generation on the read side.
- Isolated missing Process owner identities and stale controller-session
  teardown from unrelated resources while preserving fail-closed effects and
  global store/authentication failures.
- Bound Provider-owned Process and Volume dependency reads to the exact owner
  UID while retaining stale rows only for that owner, and split global Host and
  Zone evidence from the owner-scoped query.
- Propagated missing Process owner identities through plan, effect, observe,
  and finalize retry paths, retrying transient owner reads without treating
  missing identity as convergence.
- Cleared stale controller-session evidence after teardown even when the
  current Process owner no longer matches, while retaining UID, generation,
  revision, conflict, and expiry fences for retry.
- Accepted legacy Process rows without owner-generation metadata for read-side
  Provider readiness, isolated Provider identity and session-evidence conflicts
  to the affected context, and kept ingress teardown ahead of durable session
  clearing with retryable session authority.
- Accepted legacy Process rows without owner-generation metadata for active
  controller-session evidence while retaining explicit owner-generation
  mismatch fences.
- Refreshed cached Process owner UIDs at each bounded reconcile boundary so
  owner delete/recreate cannot reuse a stale identity.
- Deferred transient Process owner identity refresh failures without removing
  desired rows or stopping live effects, and fenced stale stored owner
  incarnations before adoption or replacement.
- Kept controller-session evidence reads context-local for target store
  timeout, backpressure, unavailable, and revision errors while preserving
  global integrity failures for propagation.
- Kept post-teardown controller-session evidence clears context-local and
  retryable without restoring dead transport authority or aborting sibling
  Provider fencing.
- Preserved stored Process owner UID and generation on status-only session
  evidence writes, and selected Core-owned dependencies by bounded ownerRef
  filters so stale same-name children remain visible for Core fencing.
- Routed controller-session evidence through the assigned Process controller
  status path with exact UID, generation, revision, and assignment fences, while
  retaining a distinct evidence operation identity.
- Invalidated and rebuilt the assigned Process API with each system-core
  session rebind under the controller-session guard, preventing stale
  controller-session evidence from crossing assignment or session fences.
- Classified replayed `assignment-required` failures as retryable resource
  conflicts and kept their ResourceError wire representation valid.
- Routed Cloud Hypervisor Guest status, finalizer, and child mutations through
  the current U6 assignment fence instead of the unassigned system-core
  client.
- Preserved durable controller-session evidence when later Process status
  projections are committed from stale snapshots.

### Removed

- Removed the semantic Binding watch, whole-resource activation and Wayland
  cleanup loops, legacy HostJson Provider composition, dead scheduler flags,
  and placeholder Provider scaffold tests.
- Closed the Guest workspace mirror over the daemon's current Provider
  dependencies and synchronized its manifest and lock with the activation
  Provider's cryptographic dependency.
- Retained support-only config-nixos and typed ComponentSession
  stream/transport services outside the retired daemon reconciler paths.
- Keep controller-effect ledger rows in their Resource API owner instead of
  treating them as Host-global authority claims during restart recovery.
- Removed Cloud Hypervisor Guest's direct Volume Ready projection; StoreSync
  remains an effect while `volume-local` stays the sole Volume owner.
