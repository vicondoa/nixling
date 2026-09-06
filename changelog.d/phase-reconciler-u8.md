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
- Persist the four rendered Network config files through the owned Volume
  projection, with exact byte, provenance, owner, mode, assignment, and marker
  fencing.
- Route Network config through volume-local's typed materialization boundary and
  require its observed digest evidence before Network reports Ready.
- Parse the typed Volume content projection during normal volume-local
  reconciliation and retain fail-closed, restart-safe materialization behavior.
- Keep Core startup available before any U8 Provider rows exist while refusing
  partial U8 Provider enrollment.
