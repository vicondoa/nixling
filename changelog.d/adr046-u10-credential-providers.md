### Changed

- Attached Secret Service, Entra, and managed-identity Credential rows to the
  shared Core source and Runner with ResourceService-backed status projection,
  bounded Provider-specific work, and exact finalizer cleanup ordering.
- Added same-Zone scoped ResourceService admission for Azure Relay credential
  reads while keeping typed ComponentSession delivery and credential custody
  inside the selected Guest.

### Security

- Credential delivery remains bound to exact Zone, Guest, consumer, operation,
  and reconnect evidence; ambient cloud SDK credential-chain names are rejected,
  lease and delivery diagnostics stay redacted, and sensitive buffers are
  explicitly zeroized.
