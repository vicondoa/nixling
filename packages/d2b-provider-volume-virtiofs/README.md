# `d2b-provider-volume-virtiofs`

`Provider/volume-virtiofs` serves a Volume view to a Host or Guest over
virtiofs. It reconciles `virtiofs.d2bus.org.Export` resources and never
writes a Volume row.

See [Create a Provider](../../docs/how-to/create-provider.md) for the
uniform crate layout, schema links, configuration, and test lanes.

## Provider identity

| Field | Value |
| --- | --- |
| Provider name | `volume-virtiofs` |
| Publisher | first-party, `vicondoa/d2b` |
| Version | tracks the workspace version of this crate |
| Trust attestation | first-party admission; exact package digest resolved from the offline Nix artifact catalog |
| Conformance attestation | the hermetic conformance suite under `tests/` |
| ResourceTypes | `virtiofs.d2bus.org.Export`; read-only watch of `Volume` |
| Attachment transport | `virtiofs` |
| Worker template | `virtiofsd-worker` |
| Finalizer | `volume-virtiofs/export`, on an Export and nothing else |

The production controller is attached to the shared Core Runner with an
event-driven Export watch and a bounded 30-second repair interval. Its only
owned children are the Export's virtiofsd Process and private Endpoint;
volume-local remains the sole Volume owner.

## Config schema

| Field | Description | Default |
| --- | --- | --- |
| `threadPoolSize` | virtiofsd worker thread pool size. | the target vcpu count |
| `cache` | virtiofsd cache mode; one of `auto`, `always`, `never`. | `auto` |

There is no free-form extra-argument channel, and no config field carries a
path, a socket, or a credential.

## Exported resource types

| ResourceType | Role |
| --- | --- |
| `virtiofs.d2bus.org.Export` | sole writer: export lifecycle, worker plan, drain |
| `Volume` | read-only watch; never written |

## Controllers / services / workers / binaries

| Component | Type | Role |
| --- | --- | --- |
| `volume-virtiofs` controller | controller | reconciles `virtiofs.d2bus.org.Export` |
| `virtiofsd-worker` | worker template | one virtiofsd process per admitted export |

The flag envelope is adapted from the shipped host-side generator, with
three differences the Volume spec freezes:

```
virtiofsd
  --socket-path=<private, adapter-derived>
  --socket-group=<resolved>
  --shared-dir=<resolved from the Volume root descriptor>
  --thread-pool-size=<settings or target vcpu count>
  [--posix-acl]   # only when the attachment asks for it
  [--xattr]       # only when the attachment asks for it
  --cache=<auto|always|never>
  --sandbox=chroot
  --inode-file-handles=never
  [--readonly]    # read-only access, or a view granting no write right
```

`--sandbox` is always `chroot`, `--inode-file-handles` is always `never`,
and there is no free-form extra-argument channel. The public argv input
accepts only a private derived socket identity and an inherited Volume-view
descriptor number; the renderer emits `/proc/self/fd/<N>` and never accepts
`/nix/store` as a shared directory.

## Placement and dependencies

The controller and every worker are Host-placed: virtiofsd runs beside the
Volume root it serves. The Provider depends on `volume-local` only through
the read-only `Volume` watch; that dependency is asynchronous and a missing
Volume leaves the Export unadmitted rather than degrading the controller.

## RBAC requirements

The Provider requires a pre-installed Role granting write on
`virtiofs.d2bus.org.Export` and read on `Volume`, bound to the Provider's own
service identity. It requires no write grant on `Volume` and no wildcard
permission.

## Security posture

Every worker declares zero host capabilities, does not start as root,
runs a chroot sandbox with a read-only root, and receives its privileges
only inside a user namespace the broker pre-establishes through the
`process-principal-root` mapping class. A declared host capability, a
root start, `--sandbox=namespace`, or a writable root is rejected before
any launch is requested. This is the ADR 0021 invariant, and it is asserted
rather than assumed.

The export socket path is generated and private. Only its opaque
`SocketIdentity` is public. The path never appears in a spec field, a
status field, an audit record, or CLI output, and two Exports of one
Volume have distinct identities. Launch is gated by the store-view marker,
and the user-namespace conformance kit checks the ADR 0021 map-write order
without carrying host UID or GID values.

## State and telemetry

Export state is held in the Export resource and its status; the controller
keeps no durable state of its own. Status, audit, and telemetry name an
export by its opaque `SocketIdentity` and a closed outcome token. No socket
path, shared directory, resolved Volume root, argv, or numeric identifier is
emitted.

## Layout

| Path | Contents |
| --- | --- |
| `src/` | Export controller, worker plan, FD-based argv renderer, private socket derivation, readiness and ADR 0021 checks, effect port, colocated unit tests |
| `tests/` | hermetic Export lifecycle, sandbox, drain, and privacy conformance |
| `integration/` | virtiofsd launch and guest-mount fixtures |

## Build and test

```bash
bazel test //packages/d2b-provider-volume-virtiofs:d2b_provider_volume_virtiofs_test
```
