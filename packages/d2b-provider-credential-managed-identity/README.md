# `d2b-provider-credential-managed-identity`

See [Create a Provider](../../docs/how-to/create-provider.md) for the
uniform crate layout, schema links, configuration, and test lanes.

## Provider identity

`Provider/credential-managed-identity` manages machine-local `Credential`
resources for one exact SDK consumer. Its controller is secret-free; a
co-located service owns the injected client and delivery endpoint. Provider
generation changes with its binary, descriptor, or config.

## Config schema

`clientId` is an inline `OpaqueAzureRef`, not a ResourceRef. It rejects secret
shapes. `imdsEndpointAlias` is exactly `azure-imds` or `azure-imds-aca`; URLs,
paths, hostnames, and custom aliases reject. `maxLeases` is bounded to 1-256.

```nix
d2b.zones.dev.resources.credential-managed-identity = {
  type = "Provider";
  spec = {
    artifactId = "credential-managed-identity-bin";
    config = {
      clientId = "client-1234";
      imdsEndpointAlias = "azure-imds-aca";
      maxLeases = 64;
    };
  };
};
```

## Exported resource types

The Provider manages `Credential`, projects bounded lease and health state, and
owns the Provider revoke finalizer. The controller creates no Provider state
Volume and holds no IMDS client.

## Controllers / services / workers / binaries

The Zone-wide `d2b-managed-identity-controller` binary is secret-free and
creates one co-located agent Process per admitted Credential binding. The
`d2b-managed-identity-agent` binary alone holds the injected
`ManagedIdentityCredentialClient`, serves live lease operations, and terminates
the sensitive delivery session. The controller has no client construction path.
The daemon composes both roles through the authenticated Zone runtime, shared
Runner, ComponentSession transport, and LaunchTicket effect-port client. The
standalone entrypoints do not invent a host-held token or ambient runtime
fallback.

## Placement and dependencies

`host-system` is accepted for a Host and `guest-agent` for a Guest. Every
placement is bound to one `Zone`; unbound or non-Zone placement references
reject closed before Provider construction or client dispatch.
`user-agent` rejects with `credential placement mismatch`. The client is
co-located with the exact `consumerRef` execution context. Host and Guest
dependencies must be Ready before acquisition.

## RBAC requirements

The authenticated Provider identity must match the exact SDK consumer.
`use-credential` requires the matching canonical operation subresource and
`Credential.spec.allowedOperations`; wildcards and aliases deny.
Administrative lifecycle requires ordinary CRUD plus the exact
`admin-credential` subresource.

## Security posture

The client retains token and IMDS response bytes. No environment credential,
developer-tool, keyring, path, or custom endpoint chain exists. Sensitive output
uses only the adapter-authorized Noise KK delivery binding. The Provider receives
that binding read-only and cannot select or alter its authority fields.

Opaque lease and source references use unkeyed digests. This does not make
low-entropy values resistant to offline guessing; no keying authority is
claimed or invented here.

## State and telemetry

There is no Provider state Volume. Status and the operation ledger retain only
opaque non-authorizing metadata. Authorized audit may retain
`resource_name_digest`; logs, errors, status, Debug, OTEL attributes, and metric
labels exclude Credential identity, client ID, endpoint details, and token or
response canaries. The test
`process_unique_managed_identity_canaries_are_absent_from_rendered_surfaces`
enforces this.

## Build and test

```bash
make test-rust
make test-integration
make test-host-integration
```

Container service lifecycle requires the container tier. Host and Guest
machine placement and ACA configuration migration require host integration.
No test contacts a live cloud or IMDS endpoint; see `integration/README.md`.

The crate remains a workspace package until a standalone Provider flake defines
a public compatibility contract. A future consumer must follow d2b's `nixpkgs`
input and use the same Credential service major.
