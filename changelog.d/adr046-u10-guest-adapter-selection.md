### Changed

- Guest credential backend composition now selects separate Secret Service,
  Entra identity Endpoint, and managed-identity IMDS adapter boundaries by
  authenticated Provider and scope metadata.
- Production Guest mode composes the adapter-backed source; the explicit
  fail-closed supervisor remains available only for degraded and negative
  paths.

### Security

- Provider controller subjects remain Provider identities while Secret Service
  User placement is carried as a separate authenticated scope claim. Missing,
  malformed, cross-domain, or mismatched scope claims fail closed without Host
  credential fallback.
