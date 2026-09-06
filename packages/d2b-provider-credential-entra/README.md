# `d2b-provider-credential-entra`

See [Create a Provider](../../docs/how-to/create-provider.md) for the
uniform crate layout, schema links, configuration, and test lanes.

## Provider identity

`Provider/credential-entra` manages `Credential` resources through a
same-Zone Entrablau identity Guest. The controller and helper are secret-free;
the identity-Guest Endpoint owns login state and token material. Provider
generation changes with its binary, descriptor, Endpoint contract, or config.

## Config schema

`tenantId` is an inline `OpaqueAzureRef` and rejects secret-shaped values.
`maxLeases` is bounded to 1-256. Login and token policy stays inside the
Entrablau Guest rather than an ambient Host credential chain.

```nix
d2b.zones.work.resources.credential-entra = {
  type = "Provider";
  spec = {
    artifactId = "credential-entra-bin";
    config = { tenantId = "tenant-1234"; maxLeases = 64; };
  };
};
```

## Exported resource types

The Provider manages `Credential`, projects interaction and lease observations,
and owns the Provider revoke finalizer. Login Endpoint state is observed, never
treated as local authority.

## Controllers / services / workers / binaries

The `d2bd` composition attaches secret-free Entra reconciliation to the shared
Runner and ResourceService. An injected `EntraCredentialClient` terminates at
the identity-Guest login/token Endpoint. No production client performs direct
Entra egress from the Host or controller.

## Placement and dependencies

`user-agent` and `guest-agent` are accepted only under a Guest. `host-system`
is rejected with `credential placement mismatch`. An exact `identityGuestRef`,
`loginEndpointRef`, Endpoint generation, and `consumerRef` are required. The
Endpoint has purpose `credential-entra.d2bus.org/entra-login-token`, canonical
`provider` visibility, and exact orchestration-plus-consumer policy.

## RBAC requirements

The authenticated consumer must match `consumerRef`. Each call requires the
same exact operation in `spec.allowedOperations` and `use-credential`
subresources. Endpoint resolution additionally requires `resolve` for both
`Provider/credential-entra` and the exact consumer. CRUD administration also
requires the matching `admin-credential` subresource.

## Security posture

Login, refresh-token, cookie, TPM, browser, and machine-credential state stays
inside the Entrablau Guest. Access tokens use only the adapter-authorized Noise
KK delivery route to the exact consumer. The Provider receives the binding
read-only and cannot select or alter its Credential, consumer, audience, route,
expiry, sequence, or limits. There is no Host login, default credential chain,
environment, D-Bus, browser, path, or direct-cloud fallback.

## State and telemetry

There is no Provider state Volume. Status contains bounded non-secret
interaction and lease observations. Only authorized bounded audit may retain
`resource_name_digest`; status, errors, logs, Debug, OTEL Resource and span
attributes, and metric labels contain no Credential identity or secret values.
The test
`process_unique_entra_secret_and_identity_canaries_are_absent_from_rendered_surfaces`
enforces this.

## Build and test

```bash
make test-rust
make test-integration
make test-host-integration
```

Container service lifecycle and cross-process routing require the container
tier. Guest placement and fake Entrablau login/token service composition require
host integration. No CI test contacts live Entra. A manual real identity-Guest
login remains a separate external obligation; see `integration/README.md`.

The crate remains in the monorepo until the Entrablau sibling and Provider
package publish a compatible flake surface. Standalone composition must follow
d2b's `nixpkgs` revision and the exact Credential and Endpoint service majors.
