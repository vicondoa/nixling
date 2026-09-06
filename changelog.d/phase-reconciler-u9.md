### Changed

- Route display, audio, and shell resource ownership through the shared
  asynchronous Runner while retaining clipboard and notification typed
  ComponentSession services and removing the legacy audio watch path. Start
  all U9 runners before Zone publication, isolate audio reconciliation per
  binding, preserve child-mutation evidence across repair and restart, and
  re-read exact AudioBinding dependencies during scheduled repair.
