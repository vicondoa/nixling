# `d2b-provider-transport-unix`

This is the canonical crate root for `Provider/transport-unix`. It supplies
the authenticated local transport portal used by child ZoneLink controllers
and same-Zone ComponentSession callers.

See [Create a Provider](../../docs/how-to/create-provider.md) and the
[transport-unix dossier](../../docs/specs/providers/ADR-046-provider-transport-unix.md)
for the implementation contract.

## Provider identity

| Field | Value |
| --- | --- |
| Provider name | `transport-unix` |
| Provider reference | `Provider/transport-unix` |
| Package | `packages/d2b-provider-transport-unix/` |

## Config schema

The closed binding schema accepts an optional `socketKind` of `seqpacket` or
`stream`. It accepts no transport credentials, paths, raw descriptors, peer
identities, or broker role claims.

## Exported resource types

This Provider exports no ResourceType. It supplies only the authenticated local
transport portal consumed by ZoneLink and ComponentSession routing.

## Controllers / services / workers / binaries

`TransportService` owns one bounded `TransportPortal`. There are no standalone
workers or binaries: admission and broker access remain daemon-supervised.

## Transport admission

- `SO_TYPE` is checked against the declared seqpacket or stream route.
- Seqpacket routes enable `SO_PASSCRED`; stream routes never carry attachments.
- ZoneLink routes never carry attachments, even when their caller requests
  them.
- Local portal requests may bind the accepted socket to an expected kernel
  uid/gid; peer identity is evidence only and is not derived from payload.
- Every accepted descriptor and portal monitor duplicate is close-on-exec.
- The portal retains request-bound peer evidence and an owned monitor duplicate;
  callers receive the validated original descriptor exactly once.

## Lifecycle

The local handle table is bounded to 256 opaque entries. `close` is idempotent
and service finalization retires only monitor descriptors owned by that portal.
The existing Unix session listener adoption path remains the restart-safe owner
for inherited local listeners.

## Session substrate

The portal deliberately has no dependency on the session transport
implementation. It validates only the accepted descriptor and leaves framing,
attachment credits, descriptor identity, and pidfd validation to the owning
session runtime. It does not resolve a peer into a subject: subject resolution
remains owned by the authenticated Zone runtime.

## Placement and dependencies

The portal is a daemon-supervised, same-Zone service component. It holds no
host path, credential, remote registry, or ambient broker mutation handle.

## RBAC requirements

Only the authenticated Zone controller and transport service may construct the
request binding passed to the portal. Broker authority and accepted peer
evidence remain bound to that one request.

## Security posture

The implementation performs only fd-relative socket operations. It never
accepts a socket path, raw identity claim, caller-supplied descriptor number,
or payload-derived subject.

## State and telemetry

Audit and metric dimensions are closed enums. They contain no peer identity,
socket address, descriptor number, opaque handle, path, or payload.

## Build and test

```bash
bazel test //packages/d2b-provider-transport-unix:all-tests
```

The focused tests cover accepted-fd/peer/request binding, socket-kind and
attachment refusal, close-on-exec, and owned finalization.
