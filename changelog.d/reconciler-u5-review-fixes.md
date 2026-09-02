### Fixed

- Observe exact Process and EphemeralProcess identities after Runner relists,
  persist terminal exits, preserve restart and TTL decisions across passes,
  wait for Provider-owned OneShot DAG nodes, and durably fence Guest effect
  acceptance across reconnects.
- Keep liveness observations mutation-only, wake exact owners from retained
  pidfd authority, schedule persisted restart delays in the shared Runner, and
  fence each restart launch with a fresh lifecycle effect identity.
