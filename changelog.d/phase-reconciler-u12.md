### Changed

- Cut observability Service/Binding and NixOS generation reconciliation onto
  the shared Runner, keeping ComponentSession stream-only and activation
  metadata Core-owned.
- Added fail-closed activation trust, artifact-catalog, redaction, ambient
  credential-chain, and zeroizing buffer boundaries.
- Hardened production startup and rebind handling so U12 runner attachment,
  exact-target reconciliation, finalizer enrollment, and trust verification
  fail closed without leaking untracked work.
