### Changed

- Attached Secret Service, Entra, and managed-identity Credential rows to the
  shared Core source and Runner with ResourceService-backed status projection,
  bounded Provider-specific work, and exact finalizer cleanup ordering.
- Added same-Zone scoped ResourceService admission for Azure Relay credential
  reads while keeping typed ComponentSession delivery and credential custody
  inside the selected Guest.
- Finalization now accepts one durable typed revocation effect, records bounded
  revocation evidence, survives reconnect deduplication, and retains the
  Credential finalizer until managed-identity Process children are gone.

### Security

- Credential delivery remains bound to exact Zone, Guest, consumer, operation,
  and reconnect evidence; ambient cloud SDK credential-chain names are rejected,
  lease and delivery diagnostics stay redacted, and sensitive buffers are
  explicitly zeroized.

### Follow-up

- Managed-identity reconciliation now creates and observes the exact
  `mi-agent-<credential>` Process child through the Resource API, requires
  current Ready status before projecting Credential readiness, and drains
  owner-matched Process children before releasing the Credential finalizer.
  Owner-child mutations reuse the parent assignment fence, and Azure Relay
  Guest composition accepts an authenticated scoped Credential client without
  taking transport ownership of Resource rows or credential registries.
- Provider-filtered runners are now attached for all three providers before
  any Credential row exists, while standalone provider binaries refuse
  unauthenticated or ambient-chain startup instead of reporting readiness.
