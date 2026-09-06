Credential Providers now use Guest-local typed lease registries for Secret
Service, Entra, and managed identity operations. Lease metadata is
idempotent and opaque, while delivery material remains zeroizing and crosses
only the authenticated credential session; fail-closed backend composition is
reserved for explicit degraded and negative paths.
