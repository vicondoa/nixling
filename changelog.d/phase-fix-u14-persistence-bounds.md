### Fixed

- Bound ambiguous Store commit recovery and Runner persistence retries so
  persistent timeout or backpressure finishes the affected resource as
  uncertain without rerunning an accepted effect or starving siblings.
