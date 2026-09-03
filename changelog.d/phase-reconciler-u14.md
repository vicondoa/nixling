### Changed

- Finalized the Zone Provider cutover with target-scoped activation and
  telemetry reconciliation, exact 27-Provider composition proof, and
  Provider-filtered descriptor validation.

### Removed

- Removed the semantic Binding watch, whole-resource activation and Wayland
  cleanup loops, legacy HostJson Provider composition, dead scheduler flags,
  and placeholder Provider scaffold tests.
- Closed the Guest workspace mirror over the daemon's current Provider
  dependencies and synchronized its manifest and lock with the activation
  Provider's cryptographic dependency.
- Retained support-only config-nixos and typed ComponentSession
  stream/transport services outside the retired daemon reconciler paths.
