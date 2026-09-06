### Changed

- Credential Provider Processes now receive a live Guest-local fd11 backend
  responder from the Guest supervisor, bound to the exact ComponentSession
  route and cancellable with Process/session teardown.
- Delivery keys are generated as one-use random key material by the Guest
  supervisor and transferred only through the authenticated Provider session;
  public Zone and generation identifiers no longer derive Noise_KK keys.

### Security

- Secret Service, Entra, and managed-identity backend requests are route- and
  operation-checked, use the enrolled Noise_KK policy, and fail closed as
  unavailable when the Guest-local source cannot answer. Sensitive response
  buffers and key handoff objects remain zeroizing and no Host backend peer is
  retained.
