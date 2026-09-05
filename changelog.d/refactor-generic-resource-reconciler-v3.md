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
- Preserved the installed projection across retryable system-core rebind
  failures, bounded controller-session retries without self-notify hot loops,
  and fenced live sessions whose bootstrap context was replaced.
- Kept rebind-pending state retryable across unchanged policy snapshots,
  rejected empty or partial post-fence session slots, and restored the fenced
  system-core and Provider runners after recovery.
- Woke the controller-session coordinator when a launch or adoption records a
  readable bootstrap endpoint, and made initial test-controller handshake
  failure terminal so one-shot bootstrap delivery cannot queue duplicates.
