### Changed

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
- Kept exhausted status conflicts inside a bounded persistence-only loop so
  retries retain effect identity without re-running accepted Process effects.
- Classified transient persistence timeouts as bounded status retries, kept
  integrity failures fail-closed, and threaded accepted effect identity into
  the production Core/Resource API ledger update.
- Continued status mutations under the accepted effect operation identity and
  retained the authority row across durable status retry and reopen.

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
