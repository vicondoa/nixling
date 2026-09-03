### Changed

- Attach Cloud Hypervisor, QEMU media, Azure Container Apps, and Azure VM
  Guest owners to filtered shared Runner reconciliation selected by the
  committed Guest provider reference.
- Preserve Guest child identity, dependency fencing, restart adoption, and
  finalizer-safe cleanup while removing the post-publication Cloud Hypervisor
  scheduler loop.
- Drive QEMU media, Azure Container Apps, and Azure VM Guest lifecycles through
  their typed controllers, advance one child mutation per pass, and drain
  deletion-requested children without issuing a second delete.
- Keep gateway-backed Guest runtime custody inside the configured Guest
  execution boundary with no Host fallback, and retain the typed Credential
  scope boundary for CredentialSession ownership.
- Requeue pending framework Guest progress on a bounded tick and exercise
  finalizer-only enrollment, controller readiness, child pacing, and
  non-Ready deletion through production shared Runner tests backed by a real
  Resource store.
