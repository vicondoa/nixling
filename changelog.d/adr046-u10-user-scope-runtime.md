### Changed

- Provider session bootstrap now carries the authenticated User placement
  claim separately from the Provider controller subject.
- Secret Service runtime construction requires that User claim and binds it
  into the exact Zone user-agent placement; Entra and managed-identity
  runtimes reject unexpected user-domain claims.

### Security

- Secret Service subprocess and fd11 backend routes keep Provider identity,
  User scope, Zone, Process, and generation fences separate and fail closed
  when the User claim is missing or malformed.
