# `d2b-provider-volume-local`

`Provider/volume-local` is the sole writer of the `Volume` ResourceType.

## Provider identity

| Field | Value |
| --- | --- |
| Provider name | `volume-local` |
| Publisher | first-party, `vicondoa/d2b` |
| Version | tracks the workspace version of this crate |
| Trust attestation | first-party admission; exact package digest resolved from the offline Nix artifact catalog |
| Conformance attestation | the hermetic conformance suite under `tests/` |
| ResourceTypes | `Volume` (layout, views, attachment admission) |
| Attachment transport | none; virtiofs attachments are admitted here and served by `volume-virtiofs` |
| Source kinds | `local-path`, `block-image`, `tmpfs` |
| Finalizers | `volume-local/layout` |
| Shared write | not declared |

## Config schema

The Provider root config declares an allowlist of host roots. Each entry
carries an `id` plus the actual root. A Volume references only the `id`
through `spec.source.settings.sourcePolicyId`; the root itself is private
catalog data that never reaches this crate.

| Field | Description | Default |
| --- | --- | --- |
| `sourcePolicies` | Allowlist of `{ id, class, volumeKinds }` entries. The backing root is private bundle data and is never returned to controller code. | empty; a Volume naming an unknown `id` fails closed |

## Exported resource types

| ResourceType | Role |
| --- | --- |
| `Volume` | sole writer: layout, views, store-view mode, TPM state mode, attachment admission |

## Controllers / services / workers / binaries

| Component | Type | Role |
| --- | --- | --- |
| `volume-local` controller | controller | reconciles `Volume` layout, views, and attachment admission |

The controller performs no privileged mutation. It calls two injected
typed ports and nothing else:

- `VolumeSourceEffectPort` resolves the opaque source policy ID against
  the private allowlist and returns a non-clonable `VolumeRootHandle`.
  The resolved path never reaches controller code.
- `VolumeLayoutEffectPort` observes, provisions, repairs, re-applies
  ACLs for, and removes exactly one declared entry at a time.

ProviderSupervisor alone maps a port call onto a broker operation, and
the broker remains the sole privileged executor and audit owner.

No service, worker template, or standalone binary is declared.

The production `AnchoredVolumeEffectAdapter` is the fixed core-side adapter
behind those ports. It accepts only an already broker-resolved, anchored
directory FD, resolves typed User principals through trusted policy, and
performs single-entry `openat2`/fd-relative operations under an `O_CLOEXEC`
OFD lock. Layout replacement uses the existing `AtomicFilesystem` durable
sequence; content projections use the same sequence and publish evidence only
after complete readback. Marker identity is verified before mutation and a
foreign, missing, or replaced marker fails closed without a cleanup sweep.

`ContentProjection` is the generic typed content boundary for later Providers:
each bounded file declares an anchored name, User owner/group, exact mode,
SHA-256 digest, and a provenance tuple carrying resource, generation,
assignment, and session fences. `ContentMaterializationEvidence` is the
status-safe readback proof; it carries no file bytes or host paths.

## Placement and dependencies

The controller is Host-placed: every effect it requests resolves against a
host filesystem root. It declares no synchronous Provider dependency. The
`volume-virtiofs` Provider watches `Volume` read-only to serve an export;
that direction is one-way and this crate does not depend on it.

## RBAC requirements

The Provider requires a pre-installed Role granting write on `Volume` and
read on the resources it admits attachments against, bound to the Provider's
own service identity. It requires no wildcard permission and no cross-Zone
grant.

## Security posture

- A Volume source is an opaque policy ID, never a raw host path.
- Layout paths are anchored inside the Volume; a leading separator,
  a `..` component, a backslash, and a NUL byte are all rejected by the
  base contract before this crate sees the entry.
- `noFollow` is honoured fail-closed: a symlink met on a `noFollow` walk
  aborts the entry and requests no mutation.
- Ambiguity quarantines. An entry whose live owner cannot be proven is
  held and reported; it is never deleted, recreated, or reused.
- A `create-if-never-provisioned` entry that is absent after its
  provisioning marker exists fails closed. Guest TPM state is never
  silently re-provisioned.
- Store-view mode serves the guest the closure-only hardlink farm at
  `live/` only, read-only, and never the host store. `gcroots/` and
  `state/` are host-only and sit at the store-view root.
- The controller holds no capability, opens no socket, and spawns no
  process.

  Source admission also keeps source-specific policy in one place:
  block-image Volumes require a byte ceiling and `virtio-blk` attachments,
  tmpfs Volumes require byte and inode ceilings and render only the bounded
  `size=` and `nr_inodes=` options, and policy IDs are checked against the
  Provider's opaque source-policy catalog. ACL reconciliation is continuous
  and reports foreign-child violations without clearing foreign state.

## State and telemetry

Public status names an entry only by digest. No host path, source policy
ID, ACL value, numeric UID or GID, or socket path is public. Audit and
telemetry carry the same redaction: an entry is identified by digest and an
outcome by a closed reason token, never by a path or a resolved root.

Persistent and cache-class Volumes use an identity-bound marker under a
broker-maintained root outside the Volume tree. If that marker survives while
the Volume root is missing, startup fails closed with
`previously-provisioned-volume-state-missing`; it does not create an empty
replacement. A root with a different filesystem identity is rejected as
replaced.

Provider payload writes use canonical `StateEnvelope` documents, a soft quota
check, and the durable temporary-write, file-sync, replace, parent-sync
sequence. Payload digest validation currently fails closed until the shared v3
contract freezes a Provider-state digest domain.

Audit events use the closed `volume-*` event set and carry no content, path,
credential, or process fields. Metrics are the six `d2b_volume_state_*`
instruments and use only closed provider, schema-class, outcome, and trigger
labels. Zone identity appears only as the `d2b.zone` OTEL Resource attribute.

The Provider itself declares no payload state Volume. Its bounded controller
observations remain in resource status and the core Operation ledger, avoiding
a bootstrap storage cycle.

## Layout

| Path | Contents |
| --- | --- |
| `src/` | controller, source/quota/ACL admission, Export intents, layout engine, views, store-view mode, storage lifecycle diagnostics, TPM state mode, effect ports, colocated unit tests |
| `tests/` | hermetic layout, view, sharing, store-view, TPM, and status-redaction conformance |
| `integration/` | heavier Host-path and store-view filesystem fixtures |

## Build and test

The production Volume, store-view, and storage-contract Nix emitters live
under `nix/`; root module paths are compatibility shims only.

```bash
bazel test //packages/d2b-provider-volume-local:d2b_provider_volume_local_test
```

Host filesystem integration scenarios run through `make
test-host-integration` once the core Volume effect adapter is wired. The
Provider crate is intended to remain independently packageable; a standalone
repository must supply the same v3 contracts and injected core effect adapter.
