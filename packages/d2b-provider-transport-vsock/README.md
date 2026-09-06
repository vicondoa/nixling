# `d2b-provider-transport-vsock`

## Provider identity

This crate implements `Provider/transport-vsock`, the child-Zone
carriage-acquisition Provider for allocator-backed native vsock sessions.

## Config schema

`spec.transportSettings` accepts `guestRef`, `portClass` (`d2b-link`), and
`connectTimeoutSeconds`. Raw `cid`, `port`, socket paths, and credentials are
rejected. The schema is
`docs/reference/schemas/v3/providers/transport-vsock.transport-binding.json`.

## Exported resource types

The Provider owns no ResourceType. ZoneLink state, status, finalizers, and
session generations remain owned by the child Zone core controller.

## Controllers / services / workers / binaries

`VsockTransportService` is one service component per installed Provider
instance. It opens, bridges, observes, and closes named streams. The native
guest relay controller owns only its effect-port lifecycle; it does not spawn
an independent persistent service.

Every open may carry the Core-owned reconnect generation. The service rejects
zero or mismatched generations and reconnects by opening a new carriage; it
does not retain ZoneLink state or schedule reconnects.

## Placement and dependencies

The Provider and ZoneLink are child-local. `childZoneName` self-matches, while
compiler-only `parentZone` selects the allocator and leaves the parent with
sealed route state only. The Provider receives opaque endpoint and binding
identities through `VsockEffectPort`; it never calls AF_VSOCK directly and
does not depend on `tokio-vsock`.

The optional empty service state volume uses `User/d2b-transport-vsock` and
broker-maintained identity. No `ComponentPrincipal` or parent-store
reciprocal resource is used.

## RBAC requirements

Only the child Zone core ZoneLink/delegation controller may invoke the
transport service. The relay's CID reservation is held across listener and
process effects and is released only after confirmed closure.

## Security posture

Guest, Zone, kernel-observed CID, boot identity, session generation, and HMAC
proof are checked before a session reaches `Ready`. Nonces are replay-fenced,
stale signatures and mismatched identities fail closed, and disconnects degrade
the session. Vsock descriptors never carry file attachments.

## State and telemetry

Operational state is bounded and in-memory: opaque transport handles, bridge
phase, close outcome, and byte counters. Debug, error, and lifecycle surfaces
omit raw CID, port, socket path, endpoint value, binding value, and proof
material.

## Build and test

```bash
bazel test //packages/d2b-provider-transport-vsock:all
```

The package integration targets cover host/guest descriptor parity and the
no-file-descriptor transport invariant. The full provider integration lane is
`make test-integration`.

See
[`docs/specs/providers/ADR-046-provider-transport-vsock.md`](../../docs/specs/providers/ADR-046-provider-transport-vsock.md)
for the complete Provider dossier.
