### Changed

- Attach Cloud Hypervisor, QEMU media, Azure Container Apps, and Azure VM
  Guest owners to filtered shared Runner reconciliation selected by the
  committed Guest provider reference.
- Preserve Guest child identity, dependency fencing, restart adoption, and
  finalizer-safe cleanup while removing the post-publication Cloud Hypervisor
  scheduler loop.
- Keep gateway-backed Guest runtime custody inside the configured Guest
  execution boundary with no Host fallback, and retain opaque credential
  acquisition for the pending CredentialSession integration.
