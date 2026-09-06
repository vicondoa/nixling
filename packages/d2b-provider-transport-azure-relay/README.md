# `d2b-provider-transport-azure-relay`

Canonical implementation of `Provider/transport-azure-relay`.

## Provider identity

The implementation identifier is `azure-relay`. It carries opaque
ComponentSession byte streams and owns no ResourceType.

## Config schema

`RelayTransportConfig` requires a gateway Guest and Network. The signed
transport settings schema accepts only bare namespace and entity identifiers;
Credential refs are separate from settings.

## Exported resource types

No ResourceType is exported. ZoneLink desired state is interpreted by Core and
the Provider returns only an opaque carriage connection.

## Controllers / services / workers / binaries

`AzureRelayTransportProvider` opens bounded sender or listener connections
through the scoped `ScopedCredentialClient` boundary and
`RelaySocketConnector`. Scoped opens fence every lease to one same-Zone
Credential, Gateway Guest, ZoneLink, session, and reconnect generation;
`AzureRelaySocketConnector` keeps WebSocket/TLS state in the Guest. Core owns
ZoneLink reconnect scheduling; the Provider only performs bounded carriage
attempt retries and preserves backpressure. `GatewayGuestZoneLinkRuntime` can
be composed directly over the authenticated same-Zone Credential client;
transport retains only that typed capability and never owns Resource rows or
credential registries.

`RelayTransportService` exposes typed opaque open/close/observe handles without
owning a ResourceType, watch, scheduler, or universal RPC surface. The
scoped-client adapter is backed by the authenticated same-Zone
ResourceService/session gate.

## Placement and dependencies

Relay credentials, endpoint coordinates, and lease state remain inside the
Gateway Guest. The Host is an opaque intermediary and never terminates the
enrolled KK ComponentSession. Credential and transport diagnostics are
redacted, and a lease is revoked before a connected socket is returned. The
sealed-file constructor remains Guest-local bootstrap composition; the
`from_scoped_client` constructor is the ResourceService/session-bound path.

## RBAC requirements

Credentials are acquired for one role and one bounded deadline. Relay
authentication is carriage evidence only and never maps to local Admin.

## Security posture

Secrets, frames, endpoint coordinates, and lease diagnostics are redacted.
Bootstrap IKpsk2 continuation must be rejected until durable enrollment and a
distinct enrolled KK session are established.

## State and telemetry

Credit windows bound aggregate buffering. Reconnect delays are capped and
reset after a stable connection. Audit and metric labels are closed semantic
sets.

## Build and test

```text
bazel test //packages/d2b-provider-transport-azure-relay:all-tests
```

Tests use in-process socket objects and do not contact Azure Relay.
