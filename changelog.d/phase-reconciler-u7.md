### Changed

- Cut storage Providers over to the shared Runner: `volume-local` is the sole
  Volume owner, `volume-virtiofs` owns qualified Export children, and anchored
  Volume effects preserve marker, lock, atomic-content, and restart-adoption
  invariants.
- Qualify the storage Provider finalizers for Resource API registration:
  `volume-local.d2bus.org/layout` and `volume-virtiofs.d2bus.org/export`.
