### Changed

- Wire Core controller sources to production redb snapshots, watches, durable
  result commits, owner wakeups, finalizer handling, and effect lifecycle
  evidence.
- Bind adapter mutations through the single NativeAuthorizer seal path with
  explicit identity and assignment fences, preserve stable effect identity
  across resource revisions, and prove 10,000-resource relist under 100
  watches without duplicate authority rows.
