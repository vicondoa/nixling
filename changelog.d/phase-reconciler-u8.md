### Changed

- Cut Network and Device provider state through fresh, assignment-fenced
  reconciliation while preserving brokered network ownership, persistent TPM
  evidence, resource-backed USB and security-key bindings, and dependency-aware
  GPU worker upgrades.
- Bind the U8 registrations to typed Provider reconcilers, keep provider
  cleanup ahead of finalizer removal, and make shared Runner startup resolve
  every accepted Provider before spawning any runner.
- Complete production Provider wiring for Network child resources, device
  authority, dependency-aware GPU lifecycle, and typed cleanup before any
  shared Runner finalizer is removed.
- Make child readiness and cleanup durable across Resource API passes, with
  Core-issued GPU authority and identity fences instead of synthetic grants.
