# `d2b-provider-activation-nixos`

This is the canonical implementation crate for `Provider/activation-nixos`.
It owns the typed generation resource contract, finalizer-driven retention,
structured activation-runner boundary, and caller/target authorization policy.

See [Create a Provider](../../docs/how-to/create-provider.md) and the
[activation-nixos dossier](../../docs/specs/providers/ADR-046-provider-activation-nixos.md)
for the implementation contract.

## Provider identity

| Field | Value |
| --- | --- |
| Provider name | `activation-nixos` |
| Provider reference | `Provider/activation-nixos` |
| Package | `packages/d2b-provider-activation-nixos/` |

## Config schema

The Provider-specific configuration selects an artifact and a bounded
`retainedGenerations` window. Store paths, helper paths, and target-local
commands never cross the resource or Provider boundary.

## Exported resource types

The Provider exports
`activation-nixos.d2bus.org.NixosGeneration`. Its spec contains only the
Provider reference, Host or Guest execution reference, artifact ID, activation
mode, and optional prior-generation reference.

## Controllers / services / workers / binaries

`ActivationController` is the pure reconcile policy, the activation diagnostics
keep host-generation handoff checks with this owner, and `ActivationRunner` is
the typed target-local helper boundary. The existing activation helper accepts
bounded JSON and refuses raw command or path fallbacks.
The daemon attaches this controller to the shared Core `Runner`; it does not
open a separate scheduler or Guest ResourceService session.

## Placement and dependencies

The controller runs through the daemon's Process Provider. Runner requests are
typed and always use `startRoot = true`; no Provider-owned persistent unit is
created.

## RBAC requirements

Lifecycle and administrator callers must be authenticated for the exact
execution target. Ordinary users and foreign targets are refused before a
runner request is emitted.

## Security posture

The Provider never sees a store path or broker DTO. Refusal and helper failure
preserve the prior generation, and audit outcomes are closed codes. Activation
verification fails closed on trust epoch, revocation reference, deny state,
publisher root, signature ID, Ed25519, artifact digest, and the activation-time
artifact-catalog digest. Core alone publishes `managedBy` and
`configurationGeneration`.

## State and telemetry

Retention is finalizer-driven and has no TTL. Operational state is represented
by resource status and the core operation ledger; the Provider owns no state
Volume.

## Build and test

The activation Provider Nix module is `nix/default.nix`; the daemon and
broker retain only effect adapters and helper execution.

```bash
bazel test //packages/d2b-provider-activation-nixos:d2b_provider_activation_nixos_test
```

The current test targets are structural compile checks. Executable scenarios
belong to the owning implementation.
