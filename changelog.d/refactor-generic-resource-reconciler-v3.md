### Fixed

- Waited for the shared controller-session guard during reconciliation so a
  wake that races system-core policy refresh cannot be lost before Provider
  bootstrap completes.
- Serialized system-core policy-session refresh with external Provider
  controller admission so pending bootstrap endpoints are retained and
  authenticated Cloud Hypervisor sessions remain available during public
  Resource reads.
- Refreshed missing Process Provider identities from the authoritative Zone
  store before launching late-created VMM and virtiofsd workers.
- Read controller Provider identities and their revision from one atomic Zone
  store snapshot so concurrent status commits do not abort startup admission.
- Serialized every Zone policy projection and carried the exact external
  Provider subjects through public refreshes and ZoneBus installation so
  controller session admission cannot be clobbered mid-handshake.
- Kept public Get/List reads on the installed policy projection, preserved the
  last-known-good projection across refresh and preflight failures, and
  requeued failed controller-session policy installs without losing their wake.
