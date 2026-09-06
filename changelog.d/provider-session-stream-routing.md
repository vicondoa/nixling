### Fixed

- Keep named-stream data and terminal events on their owning
  ComponentSession stream when multiple streams share one session, including
  cancelled receives and local resets.
