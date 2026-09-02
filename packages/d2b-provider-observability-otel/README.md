# `d2b-provider-observability-otel`

See [Create a Provider](../../docs/how-to/create-provider.md) for the
uniform crate layout, schema links, configuration, and test lanes.

## Provider identity

| Provider name | `observability-otel` |
| --- | --- |
| Resource reference | `Provider/observability-otel` |
| Role | Optional, non-bootstrap telemetry ingestion and export |
| Semantic services | `telemetry.d2bus.org.TelemetryService`, `telemetry.d2bus.org.TelemetryBinding` |

The Provider is optional and ordinary. Zone startup and authoritative audit
remain independent of its readiness.

## Config schema

The installation-wide configuration accepts only the bounded boolean
`selfMetrics.enable`. Per-binding routing, quota, redaction, and transport
settings belong to the provider-neutral resource contract and its strict
Provider extension rather than this root configuration. Unknown fields and
non-boolean values are rejected.

## Exported resource types

The Provider consumes the provider-neutral
`telemetry.d2bus.org.TelemetryService` and
`telemetry.d2bus.org.TelemetryBinding` contracts. Authority and projection
services carry the same semantic identity; Endpoint resources and socket
names remain private implementation details.

The closed metric-descriptor, metric-label, and OTEL resource-attribute
registry in `d2b-contracts` is the single-source contract for every telemetry
ingress. This Provider consumes that registry rather than maintaining a
parallel policy.

## Controllers / services / workers / binaries

The source contains the session-bound Provider agent, the
`TelemetryServiceController` and `TelemetryBindingController`, bounded emitter
socket, structural metric ingress gate, strict configuration parser, and
closed self-metric descriptors. Resource-backed Service/Binding mutation stays
on the daemon's authenticated `ResourceService` path; ComponentSession is
stream-only for telemetry frames. An authored telemetry Binding declares its
collector and forwarder `Process`/`Endpoint` children; Core owns resource
reconciliation and the generic Process Provider owns launch.

## Placement and dependencies

The Provider runs as an ordinary optional process in its owning Zone. Its
workspace dependencies are limited to the split provider, resource, and
Zone-session contracts plus `d2b-provider-toolkit` and the low-level `rustix`
fd-policy helper. The toolkit
supplies the diagnostic audit ring and session-facing values; authoritative
audit durability and core telemetry emission stay outside this crate.
This Provider does not and must not depend directly on `d2b-audit` or
`d2b-telemetry`; those ownership boundaries are deliberately refused.

## RBAC requirements

Resource admission, ComponentSession authority, bus authorization, and
cross-Zone projection routing remain core-owned. The Provider accepts only
already-admitted session context and never mints authority or widens a
caller's resource permissions.

## Security posture

Ingress validation is structural and occurs before capacity admission. Errors
use closed classes and do not echo rejected labels, values, paths, or
identities. The metric policy rejects identity keys, identity suffixes, and
trusted resource-identity canaries. OTEL telemetry never reads or writes the
authoritative audit sink, and journald filtering is opt-in and redacts
credential, secret, token, password, and path-shaped messages.

## State and telemetry

Emitter, ingress, quarantine, and diagnostic audit state is bounded and
in-memory. Export loss degrades telemetry only; it never blocks resource
mutation or audit durability. This crate does not claim production OTLP, vsock, journald, projection, or
cross-Zone share support; its ComponentSession surface is limited to typed
telemetry streams.

## Build and test

From `packages/`, run:

```bash
bazel test //packages/d2b-provider-observability-otel:d2b_provider_observability_otel_test
```

The crate's normal tests are hermetic and cover the retained agent, socket,
configuration, ingress, metric, and redaction foundations. Production
transport and exporter scenarios are intentionally not marked complete.
