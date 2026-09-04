### Fixed

- Preserve the durable accepted effect operation identity through Runner
  persistence-only retries, including failures after the status write, so
  transient watch operation IDs cannot kill the runner or create duplicate
  ledger effects.
