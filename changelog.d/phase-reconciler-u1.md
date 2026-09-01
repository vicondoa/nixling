### Changed

- Tightened shared resource reconciliation around bounded single-transaction
  mutations, fresh re-entry after commits, durable effect acceptance, and fair
  per-resource scheduling.
- Preserved newer queued operation identities when an ordinary reconciliation
  retry encounters a conflict.
