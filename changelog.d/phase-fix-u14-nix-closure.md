### Fixed

- Keep private Provider package, catalog, and schema paths in explicit
  resource-compiler closures while preventing realized bundle data from
  carrying Nix store context into host configuration evaluation.
- Exercise a non-empty Provider compiler closure in the Nix-unit bundle case
  instead of relying solely on source-shape checks.
