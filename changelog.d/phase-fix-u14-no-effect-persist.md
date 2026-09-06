### Fixed

- Keep transient startup and watch work IDs out of no-effect failure status
  persistence, while retaining accepted effect IDs through Runner retries.
- Recover ambiguous Store commit responses with an exact-target fresh read and
  idempotent operation replay so one resource cannot kill its shared Runner or
  duplicate status/effect work.
