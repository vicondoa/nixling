### Changed

- Cut Host, User, Process, and EphemeralProcess ownership over to the shared
  Core Runner with typed system Provider handlers, bounded priority/fairness,
  exact runtime identity fencing, and asynchronous effect acceptance.
- Preserve broker-owned pidfd and cgroup adoption while making replacement,
  finalization, terminal exit, and EphemeralProcess TTL handling exact.

### Removed

- Removed the legacy Process snapshot/watch scheduler and direct one-shot
  completion wait from the Provider-owned lifecycle path.
