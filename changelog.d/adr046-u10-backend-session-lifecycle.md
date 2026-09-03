### Changed

- Credential Provider runtimes preconnect their Guest-local Noise_KK backend
  before publishing readiness and execute typed acquire, inspect, refresh, and
  revoke requests through the live bounded session.
- The fd11 responder now binds the child peer credentials learned from the
  authenticated fd10 bootstrap rather than trusting the socket creator.

### Security

- Secret Service User scope is carried as a separate authenticated claim from
  the Provider controller subject, while Zone, Process, Provider, User, and
  session generations remain independently fenced.
