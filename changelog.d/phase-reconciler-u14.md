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
- Kept authenticated system-core status and finalizer projections local to
  resource audit while retaining broker evidence for desired-state mutations.
- Preserved that broker-evidence classification when pending audit outboxes
  are normalized during crash recovery.

### Removed

- Removed the semantic Binding watch, whole-resource activation and Wayland
  cleanup loops, legacy HostJson Provider composition, dead scheduler flags,
  and placeholder Provider scaffold tests.
- Closed the Guest workspace mirror over the daemon's current Provider
  dependencies and synchronized its manifest and lock with the activation
  Provider's cryptographic dependency.
- Retained support-only config-nixos and typed ComponentSession
  stream/transport services outside the retired daemon reconciler paths.
