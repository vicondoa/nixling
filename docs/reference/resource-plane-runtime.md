# Zone resource-plane runtime

`d2bd` owns one [`ZoneResourceRuntime`](../../packages/d2bd/src/resource_runtime.rs)
for each configured Zone. A runtime is opened only from the broker's
`OpenZoneStore` response for the opaque `zone-store-<zone>` identifier. The
response must contain the matching store identity and exactly one
close-on-exec database descriptor; callers cannot provide a filesystem path.

## Startup and readiness

Opening a runtime consumes the descriptor with
`RedbResourceStore::provision_owned` or `RedbResourceStore::open_owned`,
rehydrates durable metadata, reconstructs the authority index, binds the
native Resource API, and starts the fixed system-core process when the
committed policy snapshot is available. The public readiness barrier requires
all of these conditions:

- the store is open and its identity is valid;
- the Resource API and local ComponentSession registration are ready;
- the trusted Provider path has been configured;
- durable Host-global authority recovery is complete; and
- system-core and its mandatory Host/User handlers report `Ready`.

`ZoneRuntimeReadiness::is_ready` and `ZoneResourceRuntime::require_ready`
enforce this conjunction. Opening a store deliberately leaves
`provider_path_ready` false because Provider catalog configuration is an
independent trusted-bundle step. A Zone is not published as ready before that
step completes.

This daemon-plane barrier is distinct from Guest readiness. A Cloud Hypervisor
Guest is Ready only after its authenticated ComponentSession, exact running
VMM Process identity, and live Cloud Hypervisor API socket are observed in the
Guest status projection; a live Runner task alone is not readiness evidence.

The status projection is emitted by the fixed system-core emitter. It contains
one `system-core-host` and one `system-core-user` handler record; missing,
duplicate, or `ProviderLifecycle` substitutions are refused.

The Wave 6 accounting contract is checked by
`policy_wave6_manifest.rs`. It contains all 258 Provider and integration work
items from the 27 Provider dossiers, maps each item once to a canonical
foundation or Provider package, and requires named validation and removal
proof. Dossier `Planned` labels are retained as source history only; they
cannot make an incomplete accounting row pass.

## Requests and authorization

The daemon resolves a request's `zoneRef` against its authoritative resource
plane. The field is a route assertion, not an authority or a way to select a
different store. Route, service, method, and readiness failures are typed.
Public `Get` and `List` requests bind the admitted local peer's `SO_PEERCRED`
uid into a request-scoped authenticated ComponentSession subject before
calling the same Resource API client used by the registered session path.
The uid is never accepted from the request envelope; it is included in the
transport and transcript bindings checked by the authorizer.
The fixed bootstrap Provider identities are materialized by the verified
bundle path and active configuration generation; they are not caller-selected
fallbacks. There is no public fallback to a static manifest, SSH, a raw broker
request, a caller-supplied path, or a provider override.

Typed shell requests are the separate authenticated Resource path and retain
the same Zone routing and admin checks. Other public Resource operations do not
become available merely because a store descriptor was opened.

## Provider lifecycle boundary

The daemon composes the shared `d2b_provider::ProviderRegistry` from the
trusted v3 catalog. A missing catalog is an explicit legacy compatibility
state; a present but malformed catalog is refused and never silently downgraded
to that state. A lifecycle request must resolve a registered Provider and a
published method before its typed effect port can run. Caller role, Zone,
capability, idempotency, and per-Guest ownership are checked before the effect.

The persistent dispatcher stores admitted lifecycle operations in the
daemon-owned `provider-lifecycle.json`. Replaying an applied idempotency key
returns `Duplicate`; a pending operation is reconciled against the real effect
boundary after restart before another effect can run. Authorization refusal
does not mutate the downstream state.

## Layer-1 Provider contract boundaries

The controller and effect-port boundaries are covered by hermetic owner-local
tests without mocking the layers they exercise:

| Resource | Hermetic boundary exercised | Layer-1 guarantees |
| --- | --- | --- |
| `Volume` | `VolumeLocalController` with a real temporary filesystem | activation, layout readiness, restart reconstruction, cleanup policy |
| `Network` | `NetworkReconciler` with a filesystem-backed network effect/resource boundary | dependency wait, policy refusal before effects, and ordered finalization |
| TPM `Device` | `TpmResourceController` with a real state directory and `swtpm`-shaped child process | state-volume creation, process/endpoint readiness, flush, and retained state on removal |
| Cloud Hypervisor `Guest` | `CloudHypervisorController` with typed Process Provider adoption outcomes and Resource API lifecycle snapshots | dependency gating, readiness, restart adoption, disruptive recycle, and finalization |

These adapters persist or inspect fixture state; they are not call-recording
mocks. This table is Layer-1 contract evidence only. It is not evidence of a
real `/etc/nixos` switch, d2b startup, Cloud Hypervisor boot, or ACA behavior.
Those host and remote acceptance lanes are separate; U20 owns only the
`/etc/nixos` switch, d2b startup, and Cloud Hypervisor Guest boot. ACA testing
is deferred until after U20.

The daemon composition loads the semantic Guest setup descriptor from the
integrity-pinned artifact catalog and binds the controller to an authenticated
Resource API session. A v3 Guest start, stop, or restart changes the
controller-owned VMM `Process` child; the Process Provider remains the only
launch, adoption, and stop effect owner. The retained VM/TPM/security-key/audio
connectors are legacy-only and cannot satisfy that v3 path.

## Store restart, backup, and restore

Normal daemon restart reopens the same broker-owned store row, validates its
immutable identity, and reconstructs durable policy, catalog, authority, and
controller metadata before the readiness barrier. Shutdown asks the store to
persist its clean-shutdown marker.

`RedbResourceStore::logical_backup` captures a validated MVCC image of logical
rows and store metadata. `restore_owned` requires an empty target descriptor and
an identity-matching provisioning marker, restores into a staged database, and
publishes only after current-schema and row-integrity validation. Restore
preserves each ResourceRef, UID, generation, canonical JSON, and payload
digest; the restored store keeps the same store identity and advances
`backup_generation`. Runtime adoption occurs only after that publication.

Current schema advancement uses the identity-validated backup boundary before
staging. It does not promise conversion or retention of v1/v2 host state.

Logical restore does not support schema downgrade. A backup whose physical
schema is not the current registered schema returns `upgrade-required` before
publication; there is no best-effort conversion or live adoption of an older
schema. See [resource-store-migration](./resource-store-migration.md) for the
staged publication and crash-recovery contract.
