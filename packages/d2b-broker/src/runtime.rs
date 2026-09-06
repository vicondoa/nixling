use std::env;
use std::fs;
use std::io;
#[cfg(not(feature = "layer1-bootstrap"))]
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
#[cfg(not(feature = "layer1-bootstrap"))]
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
#[cfg(not(feature = "layer1-bootstrap"))]
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::sys::{owned_fd_from_raw, path_safe, peer_credentials};
#[cfg(not(feature = "layer1-bootstrap"))]
use hmac::{Hmac, Mac};
#[cfg(not(feature = "layer1-bootstrap"))]
use nix::libc;
#[cfg(not(feature = "layer1-bootstrap"))]
use nix::sys::socket::{AddressFamily, SockType, socketpair};
use nix::sys::socket::{SockFlag, accept4};
#[cfg(not(feature = "layer1-bootstrap"))]
use nix::unistd::dup;
use serde_json::Value;
#[cfg(not(feature = "layer1-bootstrap"))]
use sha2::{Digest, Sha256};
#[cfg(not(feature = "layer1-bootstrap"))]
use tracing::info;
use tracing::warn;

use crate::audit::{AuditLog, AuditWriteClass};
#[cfg(not(feature = "layer1-bootstrap"))]
use crate::audit::{BROKER_VERSION, new_event_id, result_for_decision};
#[cfg(not(feature = "layer1-bootstrap"))]
use crate::ops::audit_op::{
    BrokerAuditRecordClass, OpAuditRecord, OperationFields, UsbAuditDeviceIdentity,
    UsbSerialCorrelation, UsbSerialCorrelationKeyRotationAudit,
};
#[cfg(feature = "layer1-bootstrap")]
use crate::protocol::{bind_seqpacket, connect_seqpacket, recv_json_frame, send_json_frame};
#[cfg(not(feature = "layer1-bootstrap"))]
use crate::protocol::{
    bind_seqpacket, recv_json_frame_with_fds, send_json_frame, send_json_frame_with_fds,
};

#[cfg(feature = "layer1-bootstrap")]
#[allow(unused_imports)]
use crate::bootstrap::manifest as manifest_api;
#[cfg(feature = "layer1-bootstrap")]
use crate::bootstrap::wire::{BrokerRequest, BrokerResponse, CallerRole, RequestEnvelope};
#[cfg(feature = "layer1-bootstrap")]
use d2b_contracts_broker::broker_wire::BrokerProfile;
#[cfg(not(feature = "layer1-bootstrap"))]
use d2b_contracts_broker::broker_wire::{
    AuditJoinContext, BrokerCallerRole as CallerRole, BrokerProfile, BrokerRequest,
    BrokerRequestEnvelope as RequestEnvelope, BrokerResponse, CanonicalAuditDigest, RunnerRole,
};
#[cfg(feature = "layer1-bootstrap")]
type AuditJoinContext = ();

#[cfg(not(feature = "layer1-bootstrap"))]
use d2b_core::bundle_resolver::BundleResolver;

/// Default socket path.  When `LISTEN_FDS=1` (socket activation) this path
/// is informational only; the broker adopts fd 3 from systemd and MUST NOT
/// bind or re-chown the path.  Pass `--socket-path` (or set
/// `D2B_BROKER_SOCKET_PATH`) to override the path used in non-activated
/// (test / legacy) mode.
const DEFAULT_SOCKET_PATH: &str = "/run/d2b/priv.sock";
const DEFAULT_GUEST_SOCKET_PATH: &str = "/run/d2b/guest-broker.sock";
/// Audit records land under
/// `/var/lib/d2b/audit/broker-<utc-date>.jsonl` (no more legacy
/// single `broker-audit.log` file). Override via `--audit-dir`.
const DEFAULT_AUDIT_DIR: &str = "/var/lib/d2b/audit";
const DEFAULT_GUEST_AUDIT_DIR: &str = "/var/lib/d2b/guest-audit";
/// Default audit retention. Matches the docs claim in
/// `docs/reference/daemon-api.md` "Audit" and `AGENTS.md` "Control
/// plane". Override via `--audit-retention-days` (broker flag) or the
/// NixOS module's `d2b.site.audit.retentionDays` option. Set to 0
/// to disable pruning.
const DEFAULT_AUDIT_RETENTION_DAYS: u32 = 30;
const DEFAULT_BUNDLE_PATH: &str = "/var/lib/d2b/current-bundle/manifest.json";
const DEFAULT_GUEST_BUNDLE_PATH: &str = "/etc/d2b/guest-bundle.json";
const DEFAULT_STATE_DIR: &str = "/var/lib/d2b";
const DEFAULT_GUEST_STATE_DIR: &str = "/var/lib/d2b/guest-broker";
const DEFAULT_ACTIVATION_HELPER_PATH: &str = "/run/current-system/sw/bin/d2b-activation-helper";
const CAPABILITIES: &[&str] = &[
    "Hello",
    "ValidateBundle",
    "ExportBrokerAudit",
    "ConsumeLifecycleLease",
    "MigrateLegacySwtpmState",
    "ApplyHostGenerationHandoff",
];
const DEFAULT_IPC_REQUESTS_PER_UID_PER_SECOND: u32 = 512;
const IPC_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(1);
const DEFAULT_IPC_RATE_LIMIT_MAX_BUCKETS: usize = 4096;
const MAX_MODULE_NAME_LEN: usize = 64;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Fixed process-start authority profile. Requests cannot change it.
    pub profile: BrokerProfile,
    /// Stable authority label binding this process instance's state, socket,
    /// audit root, and caller identity.
    pub authority_id: String,
    pub socket_path: PathBuf,
    pub audit_dir: PathBuf,
    pub audit_retention_days: u32,
    /// The broker reads the bundle manifest from this server-configured
    /// path. The daemon never names a bundle path on the wire (security:
    /// prevents path-traversal + symlink-confusion). Defaults to
    /// `/var/lib/d2b/current-bundle/manifest.json`; the NixOS module's
    /// `d2b.site.bundle.currentManifest` option overrides.
    pub bundle_path: PathBuf,
    pub state_dir: PathBuf,
    /// Trusted target-local activation helper. The daemon never supplies
    /// this path on the wire.
    pub activation_helper_path: PathBuf,
    pub d2bd_uid: u32,
    pub d2bd_gid: u32,
    /// Directory for the StoreSync-only observability JSONL export
    /// (ADR 0027). The broker appends a positive-allow-list projection of
    /// every terminal StoreSync audit record here; the host Nix/Alloy
    /// wiring grants the `alloy` identity focused read/traverse on this
    /// directory only. Defaults to
    /// `/var/lib/d2b/observability/store-sync`; override via
    /// `--store-sync-export-dir`.
    pub store_sync_export_dir: PathBuf,
    pub test_mode: bool,
}

#[derive(Debug, Clone)]
pub enum BrokerMode {
    Host(ServerConfig),
    Guest(ServerConfig),
    #[cfg(feature = "layer1-bootstrap")]
    ProbeHello {
        socket_path: PathBuf,
        test_uid: Option<u32>,
    },
    #[cfg(feature = "layer1-bootstrap")]
    ProbeStub {
        socket_path: PathBuf,
        test_uid: Option<u32>,
        operation: String,
    },
    #[cfg(feature = "layer1-bootstrap")]
    ProbeExportAudit {
        socket_path: PathBuf,
        test_uid: Option<u32>,
        caller_role: CallerRole,
    },
}

#[derive(Debug)]
pub enum RunError {
    Usage(String),
    Io(io::Error),
    Protocol(String),
}

impl From<io::Error> for RunError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

enum BrokerError {
    #[cfg_attr(feature = "layer1-bootstrap", allow(dead_code))]
    MinijailValidation {
        reason: String,
    },
    #[cfg_attr(feature = "layer1-bootstrap", allow(dead_code))]
    NoPidfd {
        runner_id: String,
    },
    /// The privileged implementation is staged but the bootstrap wire
    /// path does not carry the typed intent data required to call into
    /// `ops::*` yet. Emits a typed [`OpAuditRecord`] with
    /// `decision = "errored"` + `error_kind = "w3-pending-typed-wire"`.
    Unimplemented {
        operation: &'static str,
        target_wave: &'static str,
    },
    /// USBIP live device routing ops (`UsbipBind`, `UsbipUnbind`,
    /// `UsbipProxyReconcile`) were out of scope for the initial broker
    /// and were wired into the non-bootstrap real-wire dispatch later,
    /// so this variant is only constructed by the bootstrap dispatch arm.
    #[cfg_attr(not(feature = "layer1-bootstrap"), allow(dead_code))]
    UnknownOperation {
        operation: &'static str,
    },
    AuditRequiresAdmin,
    HostShutdownRestricted,
    #[cfg_attr(not(feature = "layer1-bootstrap"), allow(dead_code))]
    ValidateBundle(String),
    /// Broker started without a loadable bundle at
    /// `ServerConfig.bundle_path`; bundle-dependent real-wire ops cannot
    /// resolve their `BundleOpId` refs and refuse fail-closed.
    #[cfg_attr(feature = "layer1-bootstrap", allow(dead_code))]
    BundleResolverUnavailable,
    /// Bundle artifact at `ServerConfig.bundle_path` failed the
    /// tamper-resistance check (symlink / owner / mode / hash). Every
    /// incoming operation surfaces this error until the broker is
    /// restarted with a clean bundle.
    #[cfg_attr(feature = "layer1-bootstrap", allow(dead_code))]
    BundleTampered {
        path: String,
        reason: String,
    },
    /// The daemon-supplied `bundle_*_intent_ref` did not resolve
    /// against the bundle's intent table.
    #[cfg_attr(feature = "layer1-bootstrap", allow(dead_code))]
    BundleIntentMissing {
        kind: &'static str,
        intent_id: String,
    },
    #[cfg_attr(feature = "layer1-bootstrap", allow(dead_code))]
    StoreViewFilesystemMismatch {
        a: String,
        a_dev: u64,
        b: String,
        b_dev: u64,
    },
    #[cfg_attr(feature = "layer1-bootstrap", allow(dead_code))]
    StoreViewMarkerMissing {
        generation_dir: String,
    },
    #[cfg_attr(feature = "layer1-bootstrap", allow(dead_code))]
    UsbipDeviceNotAllowed {
        busid: String,
        vendor: u16,
        product: u16,
    },
    #[cfg_attr(feature = "layer1-bootstrap", allow(dead_code))]
    UsbipPolicyMismatch {
        busid: String,
        reason: &'static str,
    },
    /// `UsbipBind` refused because the busid lock is already held by a
    /// different VM. The daemon maps this to `LockConflict` via the
    /// wire kind `"Broker.UsbipLockConflict"` without string-matching on
    /// a redacted `LiveHandler` message.
    #[cfg_attr(feature = "layer1-bootstrap", allow(dead_code))]
    UsbipLockConflict {
        busid: String,
        owner: String,
    },
    /// `UsbipBind` refused because the physical USB device is absent in
    /// sysfs. The daemon maps this to `RuntimeAbsent` via the wire kind
    /// `"Broker.UsbipDeviceAbsent"`.
    #[cfg_attr(feature = "layer1-bootstrap", allow(dead_code))]
    UsbipDeviceAbsent {
        busid: String,
    },
    /// The live executor reported an error (nft/route/sysctl shellout
    /// failed, pidfd open failed, spawn preflight failed, etc).
    #[cfg_attr(feature = "layer1-bootstrap", allow(dead_code))]
    LiveHandler(String),
    #[cfg_attr(feature = "layer1-bootstrap", allow(dead_code))]
    CoexistenceRefused {
        manager: d2b_core::host_w3::FirewallManager,
        rationale: String,
    },
    #[cfg_attr(feature = "layer1-bootstrap", allow(dead_code))]
    NftScriptParseFailed(String),
    #[cfg_attr(feature = "layer1-bootstrap", allow(dead_code))]
    CarveoutOrderingViolation(String),
    #[cfg_attr(feature = "layer1-bootstrap", allow(dead_code))]
    NftablesDriftDetected {
        expected: String,
        observed: String,
    },
    /// `SpawnRunner` was called with `RunnerRole::OtelHostBridge`, but
    /// the bundle-resolved intent points at a VM whose name does not
    /// match `manifest._observability.vmName`. The bridge MUST forward
    /// only into the obs VM declared in the trusted bundle; any other
    /// target is a closed-set violation and the broker refuses
    /// fail-closed.
    #[cfg_attr(feature = "layer1-bootstrap", allow(dead_code))]
    OtelHostBridgeIntentInvalid {
        intent_vm: String,
        expected_obs_vm: String,
    },
    #[cfg_attr(feature = "layer1-bootstrap", allow(dead_code))]
    SpawnRunnerIntentMismatch {
        field: &'static str,
        requested: String,
        resolved: String,
    },
    /// A `StoreSync` attempt failed (or was denied) after the dispatch
    /// arm already emitted the signed ADR 0027 terminal
    /// `OperationFields::StoreSync` audit record. This variant carries the
    /// classified `error_stage` slug for the wire error envelope; its
    /// [`BrokerError::audit`] is a deliberate no-op so the generic dispatch
    /// error path never writes a SECOND record for the same attempt
    /// (exactly one terminal StoreSync record per attempt).
    #[cfg_attr(feature = "layer1-bootstrap", allow(dead_code))]
    StoreSyncFailed {
        error_stage: &'static str,
        message: String,
    },
    Protocol(String),
    PeerCredentialRefused {
        operation: &'static str,
    },
    ProfileOperationRefused {
        profile: BrokerProfile,
        operation: &'static str,
    },
    /// swtpm-dir first-run hardening (issue #64) refused to proceed.
    /// Carries the path-free [`OperationFields::PrepareSwtpmDir`] audit
    /// so the SpawnRunner dispatch arm emits exactly one terminal
    /// `PrepareSwtpmDir` record (its [`BrokerError::audit`] is a no-op,
    /// mirroring `StoreSyncFailed`). The wire envelope surfaces only the
    /// closed-set, path-free `reason` slug.
    #[cfg_attr(feature = "layer1-bootstrap", allow(dead_code))]
    SwtpmDirHardening {
        audit: crate::ops::audit_op::SwtpmDirAudit,
        reason: &'static str,
    },
    RequestValidation {
        operation: &'static str,
        reason: &'static str,
    },
    IpcRateLimited,
}

impl core::fmt::Debug for BrokerError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BrokerError(<redacted>)")
    }
}

pub fn parse_command<I>(args: I) -> Result<BrokerMode, RunError>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter();
    let subcommand = args
        .next()
        .ok_or_else(|| RunError::Usage("usage: d2b-broker [host|guest] [options]".to_owned()))?;
    #[cfg(feature = "layer1-bootstrap")]
    match subcommand.as_str() {
        "probe-hello" => {
            let (socket_path, test_uid) = parse_probe_flags(args.collect())?;
            return Ok(BrokerMode::ProbeHello {
                socket_path,
                test_uid,
            });
        }
        "probe-stub" => {
            let rest: Vec<String> = args.collect();
            let (socket_path, test_uid, operation) = parse_stub_flags(&rest)?;
            return Ok(BrokerMode::ProbeStub {
                socket_path,
                test_uid,
                operation,
            });
        }
        "probe-export-audit" => {
            let rest: Vec<String> = args.collect();
            let (socket_path, test_uid, caller_role) = parse_export_flags(&rest)?;
            return Ok(BrokerMode::ProbeExportAudit {
                socket_path,
                test_uid,
                caller_role,
            });
        }
        _ => {}
    }
    let profile = match subcommand.as_str() {
        "host" => BrokerProfile::Host,
        "guest" => BrokerProfile::Guest,
        other => {
            return Err(RunError::Usage(format!(
                "usage: d2b-broker [host|guest] [options] (unknown profile: {other})"
            )));
        }
    };
    // --socket-path is optional.  Resolution order:
    //   1. --socket-path flag (explicit override)
    //   2. D2B_BROKER_SOCKET_PATH env var
    //   3. DEFAULT_SOCKET_PATH constant ("/run/d2b/priv.sock")
    // Under SD_LISTEN_FDS=1 (socket activation) the resolved path is
    // informational only; the broker adopts fd 3 from systemd and
    // MUST NOT bind, fchmod, or fchown the socket path.
    let mut socket_path_override: Option<PathBuf> = None;
    let mut audit_dir = PathBuf::from(match profile {
        BrokerProfile::Host => DEFAULT_AUDIT_DIR,
        BrokerProfile::Guest => DEFAULT_GUEST_AUDIT_DIR,
    });
    let mut audit_retention_days = DEFAULT_AUDIT_RETENTION_DAYS;
    let mut bundle_path = PathBuf::from(match profile {
        BrokerProfile::Host => DEFAULT_BUNDLE_PATH,
        BrokerProfile::Guest => DEFAULT_GUEST_BUNDLE_PATH,
    });
    let mut state_dir = PathBuf::from(match profile {
        BrokerProfile::Host => DEFAULT_STATE_DIR,
        BrokerProfile::Guest => DEFAULT_GUEST_STATE_DIR,
    });
    let mut activation_helper_path = PathBuf::from(DEFAULT_ACTIVATION_HELPER_PATH);
    let mut store_sync_export_dir = match profile {
        BrokerProfile::Host => {
            PathBuf::from(crate::ops::store_sync_export::DEFAULT_STORE_SYNC_EXPORT_DIR)
        }
        BrokerProfile::Guest => PathBuf::from("/var/lib/d2b/guest-audit/store-sync"),
    };
    let mut authority_id = profile.as_str().to_owned();
    let mut d2bd_uid = None;
    let mut d2bd_gid = None;
    let mut test_mode = false;
    let rest: Vec<String> = args.collect();
    let mut index = 0;
    while index < rest.len() {
        match rest[index].as_str() {
            "--socket-path" => {
                index += 1;
                socket_path_override =
                    Some(PathBuf::from(expect_arg(&rest, index, "--socket-path")?));
            }
            "--audit-dir" => {
                index += 1;
                audit_dir = PathBuf::from(expect_arg(&rest, index, "--audit-dir")?);
            }
            "--audit-retention-days" => {
                index += 1;
                audit_retention_days = expect_arg(&rest, index, "--audit-retention-days")?
                    .parse()
                    .map_err(|_| {
                        RunError::Usage(
                            "invalid --audit-retention-days (expected a non-negative integer; 0 disables pruning)"
                                .to_owned(),
                        )
                    })?;
            }
            "--bundle-path" => {
                // Broker reads the bundle manifest from this
                // server-configured path so the daemon never
                // names a bundle path on the wire.
                index += 1;
                bundle_path = PathBuf::from(expect_arg(&rest, index, "--bundle-path")?);
            }
            "--state-dir" => {
                index += 1;
                state_dir = PathBuf::from(expect_arg(&rest, index, "--state-dir")?);
            }
            "--activation-helper-path" => {
                index += 1;
                activation_helper_path =
                    PathBuf::from(expect_arg(&rest, index, "--activation-helper-path")?);
            }
            "--store-sync-export-dir" => {
                index += 1;
                store_sync_export_dir =
                    PathBuf::from(expect_arg(&rest, index, "--store-sync-export-dir")?);
            }
            "--authority-id" => {
                index += 1;
                authority_id = expect_arg(&rest, index, "--authority-id")?.to_owned();
                if authority_id.is_empty() {
                    return Err(RunError::Usage(
                        "--authority-id must not be empty".to_owned(),
                    ));
                }
            }
            "--d2bd-uid" => {
                index += 1;
                d2bd_uid = Some(
                    expect_arg(&rest, index, "--d2bd-uid")?
                        .parse()
                        .map_err(|_| RunError::Usage("invalid --d2bd-uid".to_owned()))?,
                );
            }
            "--d2bd-gid" => {
                index += 1;
                d2bd_gid = Some(
                    expect_arg(&rest, index, "--d2bd-gid")?
                        .parse()
                        .map_err(|_| RunError::Usage("invalid --d2bd-gid".to_owned()))?,
                );
            }
            "--test-mode" => test_mode = true,
            other => {
                return Err(RunError::Usage(format!(
                    "unknown {} flag: {other}",
                    profile.as_str()
                )));
            }
        }
        index += 1;
    }

    // Resolve socket path: flag > env var > built-in default.
    let socket_path = socket_path_override
        .or_else(|| {
            let variable = match profile {
                BrokerProfile::Host => "D2B_BROKER_SOCKET_PATH",
                BrokerProfile::Guest => "D2B_GUEST_BROKER_SOCKET_PATH",
            };
            env::var(variable).ok().map(PathBuf::from)
        })
        .unwrap_or_else(|| {
            PathBuf::from(match profile {
                BrokerProfile::Host => DEFAULT_SOCKET_PATH,
                BrokerProfile::Guest => DEFAULT_GUEST_SOCKET_PATH,
            })
        });

    let fallback_uid = if test_mode {
        nix::unistd::Uid::current().as_raw()
    } else {
        env::var("D2BD_UID")
            .ok()
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| {
                RunError::Usage("missing d2bd uid: pass --d2bd-uid or set D2BD_UID".to_owned())
            })?
    };
    let fallback_gid = if test_mode {
        nix::unistd::Gid::current().as_raw()
    } else {
        env::var("D2BD_GID")
            .ok()
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| {
                RunError::Usage("missing d2bd gid: pass --d2bd-gid or set D2BD_GID".to_owned())
            })?
    };

    let config = ServerConfig {
        profile,
        authority_id,
        socket_path,
        audit_dir,
        audit_retention_days,
        bundle_path,
        state_dir,
        activation_helper_path,
        d2bd_uid: d2bd_uid.unwrap_or(fallback_uid),
        d2bd_gid: d2bd_gid.unwrap_or(fallback_gid),
        store_sync_export_dir,
        test_mode,
    };
    Ok(match profile {
        BrokerProfile::Host => BrokerMode::Host(config),
        BrokerProfile::Guest => BrokerMode::Guest(config),
    })
}

pub fn run(command: BrokerMode) -> Result<(), RunError> {
    match command {
        BrokerMode::Host(config) | BrokerMode::Guest(config) => run_server(config),
        #[cfg(feature = "layer1-bootstrap")]
        BrokerMode::ProbeHello {
            socket_path,
            test_uid,
        } => run_probe(
            socket_path,
            crate::bootstrap::wire::probe_hello(test_uid),
            true,
        ),
        #[cfg(feature = "layer1-bootstrap")]
        BrokerMode::ProbeStub {
            socket_path,
            test_uid,
            operation,
        } => {
            let request = crate::bootstrap::wire::probe_stub(&operation, test_uid)
                .ok_or_else(|| RunError::Usage(format!("unknown stub operation: {operation}")))?;
            run_probe(socket_path, request, true)
        }
        #[cfg(feature = "layer1-bootstrap")]
        BrokerMode::ProbeExportAudit {
            socket_path,
            test_uid,
            caller_role,
        } => run_probe(
            socket_path,
            crate::bootstrap::wire::probe_export_audit(test_uid, caller_role),
            false,
        ),
    }
}

/// Attempt to adopt a socket-activated listen fd from systemd's
/// `SD_LISTEN_FDS` protocol.
///
/// Returns:
/// - `None` if `LISTEN_PID` is absent or does not match this process's PID,
///   or if `LISTEN_FDS` is absent or not `"1"` - not socket-activated.
/// - `Some(Ok(fd))` when socket activation is valid and fd 3 has been
///   verified as an `AF_UNIX SOCK_SEQPACKET` listen socket.
/// - `Some(Err(_))` if `LISTEN_FDNAMES` is present but is not `"priv.sock"`,
///   or if the fd-level validation in `sys::adopt_listen_fd_from_fd3` fails.
///
/// The `LISTEN_*` vars are NOT unset after adoption. The `sd_listen_fds(3)`
/// protocol is self-scoping: a reader only honours the vars when
/// `LISTEN_PID` equals its own PID, so any spawned child (a different PID)
/// ignores inherited `LISTEN_*` regardless. The broker also never re-reads
/// them after this function, and per-runner processes receive an explicit
/// (non-inherited) environment via `execve`, so leaving the vars in the
/// broker's own short-lived environment is inert.
fn adopt_listen_fd() -> Option<Result<OwnedFd, RunError>> {
    // Step 1: LISTEN_PID must match this process.
    let listen_pid = env::var("LISTEN_PID").ok()?;
    if listen_pid != std::process::id().to_string() {
        return None;
    }

    // Step 2: LISTEN_FDS must be exactly "1".
    let listen_fds = env::var("LISTEN_FDS").ok()?;
    if listen_fds != "1" {
        return None;
    }

    // Step 3: If LISTEN_FDNAMES is present it must equal "priv.sock".
    if let Ok(fdnames) = env::var("LISTEN_FDNAMES")
        && fdnames != "priv.sock"
    {
        return Some(Err(RunError::Usage(format!(
            "socket activation: expected LISTEN_FDNAMES=priv.sock, \
                 got {fdnames:?}"
        ))));
    }

    // Steps 4-5: verify fd 3 + set CLOEXEC + wrap in OwnedFd (sys.rs). The
    // `LISTEN_*` vars are intentionally left in place; see the fn docs for
    // why that is inert (LISTEN_PID self-scoping + explicit runner env).
    Some(crate::sys::adopt_listen_fd_from_fd3().map_err(RunError::Io))
}

/// Send `READY=1` (and `MAINPID=<pid>`) to `$NOTIFY_SOCKET` via the
/// `sd_notify(3)` protocol.
///
/// Failures are logged at WARN level but are not fatal - the broker
/// continues serving even if the notification cannot be delivered.
/// This preserves behaviour in environments that do not use systemd
/// supervision (tests, containers).
fn sd_notify_ready() {
    use nix::sys::socket::{AddressFamily, MsgFlags, SockFlag, SockType, UnixAddr, sendto, socket};

    let notify_socket = match env::var("NOTIFY_SOCKET") {
        Ok(s) if !s.is_empty() => s,
        _ => return, // not under systemd supervision - skip silently
    };

    let addr: UnixAddr = if let Some(abstract_name) = notify_socket.strip_prefix('@') {
        // Abstract namespace: sd_notify passes "@ <name>" where the kernel
        // address has a leading NUL byte.
        match UnixAddr::new_abstract(abstract_name.as_bytes()) {
            Ok(a) => a,
            Err(err) => {
                warn!(
                    error = %err,
                    notify_result = "invalid",
                    "sd_notify: invalid abstract socket address; skipping"
                );
                return;
            }
        }
    } else {
        match UnixAddr::new(std::path::Path::new(&notify_socket)) {
            Ok(a) => a,
            Err(err) => {
                warn!(
                    error = %err,
                    notify_result = "invalid",
                    "sd_notify: invalid NOTIFY_SOCKET path; skipping"
                );
                return;
            }
        }
    };

    let sock = match socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC,
        None,
    ) {
        Ok(fd) => fd,
        Err(err) => {
            warn!(error = %err, "sd_notify: failed to create datagram socket; skipping");
            return;
        }
    };

    let msg = format!("READY=1\nMAINPID={}\n", std::process::id());
    match sendto(sock.as_raw_fd(), msg.as_bytes(), &addr, MsgFlags::empty()) {
        Ok(_) => tracing::info!(notify_result = "sent", "sd_notify: READY=1 sent"),
        Err(err) => warn!(error = %err, notify_result = "failed", "sd_notify: sendto failed"),
    }
}

fn run_server(config: ServerConfig) -> Result<(), RunError> {
    let listener = match adopt_listen_fd() {
        Some(Ok(fd)) => {
            // Socket-activated: systemd owns bind+listen+ACL.
            // We MUST NOT touch socket_path / fchmod / fchown.
            tracing::info!(
                activation_mode = "systemd",
                socket_owner = "systemd",
                "broker adopted socket-activated listen fd"
            );
            fd
        }
        Some(Err(err)) => return Err(err),
        None => {
            // Not socket-activated: legacy / test mode - bind ourselves.
            validate_socket_parent(&config.socket_path, config.test_mode)?;
            prepare_socket_path(&config.socket_path)?;
            // fchmod() on an AF_UNIX socket fd does not change the bound
            // path's mode on some kernels/filesystems (verified: a socket
            // bound under umask 0o022 stays 0o755 after fchmod 0o660), so
            // constrain the creation umask around bind() so the socket is
            // materialized at 0o660 directly. The fchmod below stays as a
            // belt-and-suspenders for kernels where it does take effect.
            // Production uses socket activation (systemd owns the mode);
            // this is only the non-socket-activated fallback, and the
            // broker is single-threaded at startup so the transient
            // process-wide umask change is race-free.
            let prev_umask = nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o117));
            let listener_result = bind_seqpacket(&config.socket_path);
            nix::sys::stat::umask(prev_umask);
            let listener = listener_result?;
            path_safe::fchmod(listener.as_fd(), 0o660)?;
            if !config.test_mode {
                path_safe::fchown(listener.as_fd(), Some(0), Some(config.d2bd_gid))?;
            }
            listener
        }
    };

    let audit_log = AuditLog::open(
        &config.audit_dir,
        config.d2bd_gid,
        config.test_mode,
        config.audit_retention_days,
    )?;
    #[cfg(not(feature = "layer1-bootstrap"))]
    let audit_log = Arc::new(audit_log);

    // Signal systemd that the broker is ready to accept connections.
    // Called after the listener is established and the audit log is open,
    // before entering the accept loop.  No-op when NOTIFY_SOCKET is absent.
    sd_notify_ready();

    // Load the bundle resolver from the configured `bundle_path` for
    // each accepted request. The broker is socket-activated but can
    // remain alive across `nixos-rebuild switch`; treating the bundle
    // as process-lifetime immutable made already-running brokers
    // dispatch stale runner intents after a switch. Per-request reload
    // keeps broker authority aligned with the current on-disk bundle
    // while preserving fail-closed tamper handling.

    // Start background SIGCHLD reap loop. The runtime handle must stay
    // alive for the broker's lifetime.
    #[cfg(not(feature = "layer1-bootstrap"))]
    let _sigchld_reaper_rt = start_sigchld_reaper(Arc::clone(&audit_log));
    let ipc_rate_limiter = Arc::new(Mutex::new(IpcRateLimiter::new(
        DEFAULT_IPC_REQUESTS_PER_UID_PER_SECOND,
    )));

    loop {
        let accepted = accept4(listener.as_raw_fd(), SockFlag::SOCK_CLOEXEC)
            .map_err(|err| io::Error::from_raw_os_error(err as i32));
        let connection = match accepted {
            Ok(fd) => owned_fd_from_raw(fd),
            Err(err) => {
                warn!(error = %err, "broker accept failed");
                return Err(RunError::Io(err));
            }
        };
        #[cfg(not(feature = "layer1-bootstrap"))]
        let (resolver, bundle_tamper) = {
            match try_load_resolver(&config.bundle_path) {
                BundleSlot::Loaded(r) => (Some(r.clone()), None),
                BundleSlot::Unavailable => (None, None),
                BundleSlot::Tampered { path, reason } => {
                    (None, Some((path.clone(), reason.clone())))
                }
            }
        };
        #[cfg(feature = "layer1-bootstrap")]
        let resolver: Option<()> = None;
        #[cfg(not(feature = "layer1-bootstrap"))]
        let audit_log_ref: &AuditLog = audit_log.as_ref();
        #[cfg(feature = "layer1-bootstrap")]
        let audit_log_ref: &AuditLog = &audit_log;
        if let Err(err) = handle_connection(
            connection,
            &config,
            audit_log_ref,
            resolver.as_ref(),
            #[cfg(not(feature = "layer1-bootstrap"))]
            bundle_tamper,
            &ipc_rate_limiter,
        ) {
            warn!(error = ?err, "broker request failed");
        }
    }
}

/// Outcome of a bundle load attempt at broker startup.
#[cfg(not(feature = "layer1-bootstrap"))]
#[derive(Debug)]
enum BundleSlot {
    /// Bundle loaded and verified successfully.
    Loaded(Arc<BundleResolver>),
    /// Bundle absent or unreadable; bundle-dependent ops return
    /// `BundleResolverUnavailable`.
    Unavailable,
    /// Bundle failed tamper-resistance check; every incoming operation
    /// immediately surfaces `BundleTampered` until the broker restarts.
    Tampered { path: String, reason: String },
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn try_load_resolver(bundle_path: &Path) -> BundleSlot {
    try_load_resolver_with_policy(
        bundle_path,
        &d2b_core::bundle_resolver::BundleVerifyPolicy::production(),
    )
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn try_load_resolver_with_policy(
    bundle_path: &Path,
    policy: &d2b_core::bundle_resolver::BundleVerifyPolicy,
) -> BundleSlot {
    use d2b_core::error::{BundleError, Error as CoreError};
    // Per the tracing contract, span attributes MUST NOT include
    // filesystem paths (high cardinality + can leak host layout). The
    // bundle path is bounded operational context handled by the typed
    // error envelope + audit log, not the trace. Keep traces to bounded
    // attrs: result/outcome/reason/intent-counts.
    match BundleResolver::load_with_policy(bundle_path, policy) {
        Ok(resolver) => {
            tracing::debug!(
                load_outcome = "ok",
                nft = resolver.nft_intent_ids().count(),
                route = resolver.route_intent_ids().count(),
                sysctl = resolver.sysctl_intent_ids().count(),
                hosts = resolver.hosts_intent_ids().count(),
                runners = resolver.runner_intent_ids().count(),
                "Bundle resolver loaded"
            );
            BundleSlot::Loaded(Arc::new(resolver))
        }
        Err(CoreError::Bundle(BundleError::Tampered { path, reason })) => {
            tracing::error!(
                load_outcome = "tampered",
                reason = %reason,
                "Bundle tamper-resistance check failed; all ops will be refused until broker restarts with a clean bundle"
            );
            BundleSlot::Tampered {
                path: path.display().to_string(),
                reason,
            }
        }
        Err(err) => {
            warn!(
                load_outcome = "unavailable",
                error_kind = ?err.kind(),
                "Bundle resolver could not load; bundle-dependent ops will fail closed"
            );
            BundleSlot::Unavailable
        }
    }
}

/// Bind a kernel-authenticated peer to this broker instance before any wire
/// bytes are decoded. Test mode keeps the existing simulated envelope UID
/// support, but still requires the actual local test process credentials.
fn peer_matches_instance(config: &ServerConfig, peer_uid: u32, peer_gid: u32) -> bool {
    if config.test_mode {
        return (peer_uid == nix::unistd::Uid::current().as_raw()
            && peer_gid == nix::unistd::Gid::current().as_raw())
            || peer_uid == 0;
    }
    (peer_uid == config.d2bd_uid && peer_gid == config.d2bd_gid)
        || (config.profile == BrokerProfile::Host && peer_uid == 0)
}

fn handle_connection(
    fd: OwnedFd,
    config: &ServerConfig,
    audit_log: &AuditLog,
    #[cfg(not(feature = "layer1-bootstrap"))] resolver: Option<&Arc<BundleResolver>>,
    #[cfg(feature = "layer1-bootstrap")] _resolver: Option<&()>,
    #[cfg(not(feature = "layer1-bootstrap"))] bundle_tamper: Option<(String, String)>,
    ipc_rate_limiter: &Arc<Mutex<IpcRateLimiter>>,
) -> io::Result<()> {
    let (peer_uid, peer_gid, peer_pid) = peer_credentials(fd.as_raw_fd())?;
    if !peer_matches_instance(config, peer_uid, peer_gid) {
        let _ = write_refusal_audit_bounded(
            audit_log,
            AuditWriteClass::Unprivileged,
            "PeerAuthentication",
            peer_uid,
            peer_gid,
            "peer-refused-before-decode",
            "broker-instance",
            "closed",
        );
        // Do not decode or synchronously drain an untrusted frame. Closing
        // the accepted socket is the fail-closed response and avoids letting
        // an unauthenticated peer hold a broker worker while it trickles
        // request bytes.
        return Ok(());
    }
    #[cfg(not(feature = "layer1-bootstrap"))]
    let (envelope, request_fds) = match recv_json_frame_with_fds::<RequestEnvelope>(fd.as_raw_fd())?
    {
        Some(envelope) => envelope,
        None => return Ok(()),
    };
    #[cfg(feature = "layer1-bootstrap")]
    let envelope = match recv_json_frame::<RequestEnvelope>(fd.as_raw_fd())? {
        Some(envelope) => envelope,
        None => return Ok(()),
    };
    let request = envelope.request;
    let effective_uid = if config.test_mode {
        envelope.test_peer_uid.unwrap_or(peer_uid)
    } else {
        peer_uid
    };
    let operation = request.op_name();
    let opaque_target_id = request.opaque_target_id();
    #[cfg(not(feature = "layer1-bootstrap"))]
    if !config.profile.allows_request(&request) {
        let error = BrokerError::ProfileOperationRefused {
            profile: config.profile,
            operation,
        };
        let _ = write_refusal_audit_bounded(
            audit_log,
            AuditWriteClass::Privileged,
            operation,
            peer_uid,
            peer_gid,
            "profile-operation-denied",
            opaque_target_id,
            "closed",
        );
        send_json_frame(fd.as_raw_fd(), &error.into_response())?;
        return Ok(());
    }
    #[cfg(not(feature = "layer1-bootstrap"))]
    if config.profile == BrokerProfile::Guest {
        if let Err(error) = validate_guest_process_binding(&request) {
            send_json_frame(fd.as_raw_fd(), &error.into_response())?;
            return Ok(());
        }
    }
    let (rate_role, rate_operation) = if effective_uid == config.d2bd_uid {
        (envelope.caller_role.for_display(), operation)
    } else {
        ("direct-broker-peer", "direct-broker-connect")
    };
    let rate_pool = if effective_uid == config.d2bd_uid {
        IpcRatePool::Daemon
    } else {
        IpcRatePool::Direct
    };
    let rate_allowed = ipc_rate_limiter
        .lock()
        .map_err(|_| io::Error::other("broker IPC rate limiter mutex poisoned"))?
        .check(rate_pool, effective_uid, rate_role, rate_operation);
    if !rate_allowed {
        if let Err(error) = write_refusal_audit_bounded(
            audit_log,
            if effective_uid == config.d2bd_uid {
                AuditWriteClass::Privileged
            } else {
                AuditWriteClass::Unprivileged
            },
            operation,
            effective_uid,
            peer_gid,
            "ipc-rate-limited",
            opaque_target_id,
            "closed",
        ) {
            tracing::error!(error = ?error, "broker rate-limit audit failed");
        }
        if effective_uid == config.d2bd_uid {
            send_json_frame(fd.as_raw_fd(), &BrokerError::IpcRateLimited.into_response())?;
        }
        return Ok(());
    }
    if effective_uid != config.d2bd_uid {
        if let Err(error) = write_refusal_audit_bounded(
            audit_log,
            AuditWriteClass::Unprivileged,
            operation,
            effective_uid,
            peer_gid,
            "peer-refused",
            opaque_target_id,
            "closed",
        ) {
            tracing::error!(error = ?error, "broker peer-refusal audit failed");
        }
        send_json_frame(
            fd.as_raw_fd(),
            &BrokerError::PeerCredentialRefused { operation }.into_response(),
        )?;
        return Ok(());
    }

    if let Err(error) = validate_broker_request(&request) {
        #[cfg(not(feature = "layer1-bootstrap"))]
        let audit_join = envelope.audit_join.clone();
        #[cfg(feature = "layer1-bootstrap")]
        let audit_join = None;
        let audit_context = DispatchAuditContext {
            peer_pid,
            peer_role: envelope.caller_role.for_display().to_owned(),
            verb: operation.to_owned(),
            request_fields: serde_json::json!({ "validation": "failed" }),
            started_at: Instant::now(),
            audit_join,
        };
        #[cfg(not(feature = "layer1-bootstrap"))]
        if let Err(audit_error) = error.audit(
            audit_log,
            effective_uid,
            peer_gid,
            &envelope.caller_role,
            &audit_context,
            resolver.map(std::sync::Arc::as_ref),
            operation,
            opaque_target_id,
        ) {
            tracing::error!(error = ?audit_error, "broker validation error audit failed");
        }
        #[cfg(feature = "layer1-bootstrap")]
        if let Err(audit_error) = error.audit(
            audit_log,
            effective_uid,
            peer_gid,
            &envelope.caller_role,
            &audit_context,
            operation,
            opaque_target_id,
        ) {
            tracing::error!(error = ?audit_error, "broker validation error audit failed");
        }
        send_json_frame(fd.as_raw_fd(), &error.into_response())?;
        return Ok(());
    }
    #[cfg(not(feature = "layer1-bootstrap"))]
    let audit_join = envelope.audit_join.as_ref();
    #[cfg(feature = "layer1-bootstrap")]
    let audit_join: Option<&AuditJoinContext> = None;
    let audit_context = DispatchAuditContext::from_request_with_join(
        &request,
        peer_pid,
        &envelope.caller_role,
        audit_join,
    )
    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, format!("{err:?}")))?;
    #[cfg(not(feature = "layer1-bootstrap"))]
    let dispatch_outcome = if let Some((path, reason)) = bundle_tamper {
        Err(BrokerError::BundleTampered { path, reason })
    } else {
        dispatch_request_with_request_fds(
            request,
            effective_uid,
            peer_gid,
            envelope.caller_role.clone(),
            &audit_context,
            config,
            audit_log,
            resolver,
            request_fds,
        )
    };
    #[cfg(feature = "layer1-bootstrap")]
    let dispatch_outcome = dispatch_request(
        request,
        effective_uid,
        peer_gid,
        envelope.caller_role.clone(),
        &audit_context,
        config,
        audit_log,
    )
    .map(DispatchResult::no_fds);

    let (response, fds) = match dispatch_outcome {
        Ok(result) => (result.response, result.fds),
        Err(error) => {
            #[cfg(not(feature = "layer1-bootstrap"))]
            if let Err(audit_error) = error.audit(
                audit_log,
                effective_uid,
                peer_gid,
                &envelope.caller_role,
                &audit_context,
                resolver.map(std::sync::Arc::as_ref),
                operation,
                opaque_target_id,
            ) {
                tracing::error!(error = ?audit_error, "broker terminal error audit failed");
            }
            #[cfg(feature = "layer1-bootstrap")]
            if let Err(audit_error) = error.audit(
                audit_log,
                effective_uid,
                peer_gid,
                &envelope.caller_role,
                &audit_context,
                operation,
                opaque_target_id,
            ) {
                tracing::error!(error = ?audit_error, "broker terminal error audit failed");
            }
            (error.into_response(), Vec::new())
        }
    };

    #[cfg(not(feature = "layer1-bootstrap"))]
    {
        if fds.is_empty() {
            send_json_frame(fd.as_raw_fd(), &response)?;
        } else {
            let raw_fds: Vec<i32> = fds.iter().map(|f| f.as_raw_fd()).collect();
            send_json_frame_with_fds(fd.as_raw_fd(), &response, &raw_fds)?;
            // Drop ownership: the SCM_RIGHTS send duplicated the fd
            // into the receiver's table; the broker's copy is the
            // OwnedFd in `fds` and will close on scope exit, which is
            // the intended lifecycle.
            drop(fds);
        }
    }
    #[cfg(feature = "layer1-bootstrap")]
    {
        let _ = fds; // layer1-bootstrap dispatch never returns fds
        send_json_frame(fd.as_raw_fd(), &response)?;
    }
    Ok(())
}

fn write_refusal_audit_bounded(
    audit_log: &AuditLog,
    audit_class: AuditWriteClass,
    operation: &str,
    caller_uid: u32,
    caller_gid: u32,
    disposition: &str,
    opaque_target_id: &str,
    outcome: &str,
) -> io::Result<()> {
    match audit_log.write_entry_with_class_and_caller_ids(
        audit_class,
        operation,
        caller_uid,
        caller_gid,
        disposition,
        opaque_target_id,
        outcome,
    ) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => Ok(()),
        Err(err) => Err(err),
    }
}

/// Real-wire dispatch results can carry zero-or-more `OwnedFd`s
/// alongside the JSON response. Bootstrap dispatch never carries fds.
#[cfg_attr(feature = "layer1-bootstrap", allow(dead_code))]
#[derive(Debug)]
struct DispatchResult {
    response: BrokerResponse,
    fds: Vec<OwnedFd>,
}

#[cfg_attr(feature = "layer1-bootstrap", allow(dead_code))]
impl DispatchResult {
    fn no_fds(response: BrokerResponse) -> Self {
        Self {
            response,
            fds: Vec::new(),
        }
    }

    fn with_fd(response: BrokerResponse, fd: OwnedFd) -> Self {
        Self {
            response,
            fds: vec![fd],
        }
    }

    fn with_fds(response: BrokerResponse, fds: Vec<OwnedFd>) -> Self {
        Self { response, fds }
    }
}

#[derive(Debug)]
struct IpcRateLimiter {
    max_requests_per_window: u32,
    max_buckets_per_pool: usize,
    daemon_buckets: std::collections::HashMap<IpcRateKey, IpcRateBucket>,
    direct_buckets: std::collections::HashMap<IpcRateKey, IpcRateBucket>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpcRatePool {
    Daemon,
    Direct,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct IpcRateKey {
    uid: u32,
    role: &'static str,
    operation: &'static str,
}

#[derive(Debug)]
struct IpcRateBucket {
    window_start: Instant,
    requests_this_window: u32,
}

impl IpcRateLimiter {
    fn new(max_requests_per_window: u32) -> Self {
        Self::with_limits(max_requests_per_window, DEFAULT_IPC_RATE_LIMIT_MAX_BUCKETS)
    }

    fn with_limits(max_requests_per_window: u32, max_buckets: usize) -> Self {
        Self {
            max_requests_per_window,
            max_buckets_per_pool: max_buckets,
            daemon_buckets: std::collections::HashMap::new(),
            direct_buckets: std::collections::HashMap::new(),
        }
    }

    fn check(
        &mut self,
        pool: IpcRatePool,
        uid: u32,
        role: &'static str,
        operation: &'static str,
    ) -> bool {
        self.check_at(pool, uid, role, operation, Instant::now())
    }

    fn check_at(
        &mut self,
        pool: IpcRatePool,
        uid: u32,
        role: &'static str,
        operation: &'static str,
        now: Instant,
    ) -> bool {
        let buckets = match pool {
            IpcRatePool::Daemon => &mut self.daemon_buckets,
            IpcRatePool::Direct => &mut self.direct_buckets,
        };
        Self::check_bucket_map(
            self.max_requests_per_window,
            self.max_buckets_per_pool,
            buckets,
            uid,
            role,
            operation,
            now,
        )
    }

    fn check_bucket_map(
        max_requests_per_window: u32,
        max_buckets: usize,
        buckets: &mut std::collections::HashMap<IpcRateKey, IpcRateBucket>,
        uid: u32,
        role: &'static str,
        operation: &'static str,
        now: Instant,
    ) -> bool {
        if max_requests_per_window == 0 {
            return false;
        }
        let key = IpcRateKey {
            uid,
            role,
            operation,
        };
        if !buckets.contains_key(&key) {
            Self::evict_expired(buckets, now);
            if buckets.len() >= max_buckets {
                return false;
            }
        }
        let bucket = buckets.entry(key).or_insert(IpcRateBucket {
            window_start: now,
            requests_this_window: 0,
        });
        if now.saturating_duration_since(bucket.window_start) >= IPC_RATE_LIMIT_WINDOW {
            bucket.window_start = now;
            bucket.requests_this_window = 0;
        }
        if bucket.requests_this_window >= max_requests_per_window {
            return false;
        }
        bucket.requests_this_window += 1;
        true
    }

    fn evict_expired(
        buckets: &mut std::collections::HashMap<IpcRateKey, IpcRateBucket>,
        now: Instant,
    ) {
        buckets.retain(|_, bucket| {
            now.saturating_duration_since(bucket.window_start) < IPC_RATE_LIMIT_WINDOW
        });
    }
}

#[cfg(feature = "layer1-bootstrap")]
fn validate_broker_request(_request: &BrokerRequest) -> Result<(), BrokerError> {
    Ok(())
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn validate_network_authority(scope_id: &str, intent_id: &str) -> Result<(), &'static str> {
    if scope_id.starts_with("env:")
        || intent_id.contains(":env:")
        || intent_id.starts_with("route:env:")
        || intent_id.starts_with("sysctl:env:")
        || intent_id.starts_with("bridge:env:")
        || intent_id.starts_with("nft-projection:env:")
        || intent_id.starts_with("bridge:zone:")
        || intent_id.starts_with("nft-projection:zone:")
        || intent_id.starts_with("route:zone:")
        || intent_id.starts_with("sysctl:zone:")
        || intent_id.starts_with("hosts:zone:")
    {
        return Err("legacy-network-authority");
    }
    Ok(())
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn validate_uid_network_authority(
    scope_id: &str,
    intent_id: &str,
    zone_uid: &d2b_contracts_resource::v3::ResourceUid,
    network_uid: &d2b_contracts_resource::v3::ResourceUid,
    network_generation: d2b_contracts_resource::v3::ResourceGeneration,
    attachment_generation: d2b_contracts_resource::v3::ResourceGeneration,
    bundle_generation: &d2b_contracts_resource::v3::ResourceBundleGenerationId,
) -> Result<(), &'static str> {
    let expected_scope = format!("network:{}:{}", zone_uid.as_str(), network_uid.as_str());
    if scope_id != expected_scope {
        return Err("network-scope-mismatch");
    }
    let fields = intent_id.split(':').collect::<Vec<_>>();
    let is_network_intent = matches!(
        fields.first().copied(),
        Some("network-bridge")
            | Some("network-firewall")
            | Some("network-hosts")
            | Some("network-route")
            | Some("network-sysctl")
            | Some("network-marker")
    );
    if !is_network_intent
        || fields.get(1).and_then(|value| {
            d2b_contracts_resource::v3::ResourceUid::parse((*value).to_owned()).ok()
        }) != Some(zone_uid.clone())
        || fields.get(2).and_then(|value| {
            d2b_contracts_resource::v3::ResourceUid::parse((*value).to_owned()).ok()
        }) != Some(network_uid.clone())
    {
        return Err("network-admission-mismatch");
    }
    if fields.get(3).is_none_or(|value| {
        value.len() != 16 || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    }) {
        return Err("network-admission-mismatch");
    }
    if network_generation.get() == 0
        || attachment_generation.get() == 0
        || bundle_generation.as_str().is_empty()
    {
        return Err("network-admission-mismatch");
    }
    Ok(())
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn validate_network_scope_provenance(
    scope_id: &str,
    zone_uid: &d2b_contracts_resource::v3::ResourceUid,
    network_uid: &d2b_contracts_resource::v3::ResourceUid,
    network_generation: d2b_contracts_resource::v3::ResourceGeneration,
    attachment_generation: d2b_contracts_resource::v3::ResourceGeneration,
    bundle_generation: &d2b_contracts_resource::v3::ResourceBundleGenerationId,
) -> Result<(), &'static str> {
    let expected_scope = format!("network:{}:{}", zone_uid.as_str(), network_uid.as_str());
    if scope_id != expected_scope
        || network_generation.get() == 0
        || attachment_generation.get() == 0
        || bundle_generation.as_str().is_empty()
    {
        return Err("network-admission-mismatch");
    }
    Ok(())
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn validate_tap_create_provenance(
    bundle_tap_intent_ref: &d2b_contracts::types::BundleOpId,
    vm_id: &d2b_contracts::types::VmId,
    role_id: &d2b_contracts::types::RoleId,
    attachment_id: &d2b_contracts_resource::v3::ResourceUid,
    zone_uid: &d2b_contracts_resource::v3::ResourceUid,
    network_uid: &d2b_contracts_resource::v3::ResourceUid,
    network_generation: d2b_contracts_resource::v3::ResourceGeneration,
    attachment_generation: d2b_contracts_resource::v3::ResourceGeneration,
    bundle_generation: &d2b_contracts_resource::v3::ResourceBundleGenerationId,
    admitted_interface_names: &[d2b_contracts_resource::v3::IfName],
) -> Result<(), &'static str> {
    validate_bundle_op_id(bundle_tap_intent_ref.as_str())?;
    if vm_id.as_str().is_empty()
        || network_generation.get() == 0
        || attachment_generation.get() == 0
        || bundle_generation.as_str().is_empty()
    {
        return Err("network-admission-mismatch");
    }
    let canonical_role_id = d2b_core::bundle_resolver::canonical_tap_role_id(role_id.as_str());
    if !matches!(
        canonical_role_id,
        "ch" | "qemu-media"
            | "net-vm-lan"
            | "uplink"
            | "workload-lan"
            | "network-attachment"
            | "runner-lan"
    ) {
        return Err("network-admission-mismatch");
    }
    let expected = d2b_core::bundle_resolver::intent_id_network_tap(
        zone_uid,
        network_uid,
        attachment_id,
        network_generation,
        attachment_generation,
        bundle_generation,
        canonical_role_id,
        vm_id.as_str(),
    );
    if bundle_tap_intent_ref.as_str() == expected {
        let (bridge_role, tap_role, tap_attachment) = if vm_id.as_str()
            == d2b_contracts_resource::v3::derive_network_child_name(network_uid, "vm")
        {
            (
                d2b_contracts_resource::v3::NetworkIfRole::LanBridge,
                d2b_contracts_resource::v3::NetworkIfRole::NetVmLanTap,
                None,
            )
        } else {
            match canonical_role_id {
                "net-vm-lan" => (
                    d2b_contracts_resource::v3::NetworkIfRole::LanBridge,
                    d2b_contracts_resource::v3::NetworkIfRole::NetVmLanTap,
                    None,
                ),
                "uplink" => (
                    d2b_contracts_resource::v3::NetworkIfRole::UplinkBridge,
                    d2b_contracts_resource::v3::NetworkIfRole::NetVmUplinkTap,
                    None,
                ),
                "ch" | "qemu-media" | "workload-lan" | "network-attachment" | "runner-lan" => (
                    d2b_contracts_resource::v3::NetworkIfRole::LanBridge,
                    d2b_contracts_resource::v3::NetworkIfRole::WorkloadGuestTap,
                    Some(attachment_id),
                ),
                _ => return Err("network-admission-mismatch"),
            }
        };
        let bridge = d2b_contracts_resource::v3::derive_network_ifname(
            zone_uid,
            network_uid,
            bridge_role,
            None,
        )
        .map_err(|_| "network-admission-mismatch")?;
        let tap = d2b_contracts_resource::v3::derive_network_ifname(
            zone_uid,
            network_uid,
            tap_role,
            tap_attachment,
        )
        .map_err(|_| "network-admission-mismatch")?;
        if admitted_interface_names
            .iter()
            .any(|ifname| ifname == &bridge)
            && admitted_interface_names.iter().any(|ifname| ifname == &tap)
        {
            Ok(())
        } else {
            Err("network-admission-mismatch")
        }
    } else {
        Err("network-admission-mismatch")
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn network_provenance(
    zone_uid: d2b_contracts_resource::v3::ResourceUid,
    network_uid: d2b_contracts_resource::v3::ResourceUid,
    network_generation: d2b_contracts_resource::v3::ResourceGeneration,
    attachment_generation: d2b_contracts_resource::v3::ResourceGeneration,
    bundle_generation: d2b_contracts_resource::v3::ResourceBundleGenerationId,
) -> d2b_contracts_resource::v3::NetworkProvenance {
    d2b_contracts_resource::v3::NetworkProvenance::new(
        zone_uid,
        network_uid,
        network_generation,
        attachment_generation,
        bundle_generation,
    )
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn require_installed_network_generation(
    resolver: &BundleResolver,
    provenance: &d2b_contracts_resource::v3::NetworkProvenance,
) -> Result<(), BrokerError> {
    let installed =
        resolver
            .installed_generation_identity()
            .ok_or(BrokerError::RequestValidation {
                operation: "NetworkEffect",
                reason: "installed-generation-unavailable",
            })?;
    if installed.as_str() != provenance.bundle_generation().as_str() {
        return Err(BrokerError::RequestValidation {
            operation: "NetworkEffect",
            reason: "stale-projection-generation",
        });
    }
    Ok(())
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn validate_broker_request(request: &BrokerRequest) -> Result<(), BrokerError> {
    // Shape-only defense in depth after d2bd has accepted and classified
    // the local peer. Do not add role/bundle authorization here: dispatch must
    // continue to resolve opaque ids through the trusted bundle, with d2bd
    // owning lifecycle authz classification.
    match request {
        BrokerRequest::ApplyNftables(req) => {
            validate_network_authority(req.scope_id.as_str(), req.bundle_nft_intent_ref.as_str())
                .map_err(|reason| BrokerError::RequestValidation {
                    operation: "ApplyNftables",
                    reason,
                })
        }
        BrokerRequest::ApplyNftablesProjection(req) => {
            validate_bundle_op_id(req.bundle_nft_projection_intent_ref.as_str())
                .and_then(|_| {
                    validate_uid_network_authority(
                        req.scope_id.as_str(),
                        req.bundle_nft_projection_intent_ref.as_str(),
                        &req.zone_uid,
                        &req.network_uid,
                        req.network_generation,
                        req.attachment_generation,
                        &req.expected_generation_id,
                    )
                })
                .map_err(|reason| BrokerError::RequestValidation {
                    operation: "ApplyNftablesProjection",
                    reason,
                })
        }
        BrokerRequest::CreateBridge(req) => {
            validate_bundle_op_id(req.bundle_bridge_intent_ref.as_str())
                .and_then(|_| {
                    validate_uid_network_authority(
                        req.scope_id.as_str(),
                        req.bundle_bridge_intent_ref.as_str(),
                        &req.zone_uid,
                        &req.network_uid,
                        req.network_generation,
                        req.attachment_generation,
                        &req.bundle_generation,
                    )
                })
                .map_err(|reason| BrokerError::RequestValidation {
                    operation: "CreateBridge",
                    reason,
                })
        }
        BrokerRequest::DeleteBridge(req) => {
            validate_bundle_op_id(req.bundle_bridge_intent_ref.as_str())
                .and_then(|_| {
                    validate_uid_network_authority(
                        req.scope_id.as_str(),
                        req.bundle_bridge_intent_ref.as_str(),
                        &req.zone_uid,
                        &req.network_uid,
                        req.network_generation,
                        req.attachment_generation,
                        &req.bundle_generation,
                    )
                })
                .map_err(|reason| BrokerError::RequestValidation {
                    operation: "DeleteBridge",
                    reason,
                })
        }
        BrokerRequest::ApplyRoute(req) => {
            validate_bundle_op_id(req.bundle_route_intent_ref.as_str())
                .and_then(|_| {
                    validate_uid_network_authority(
                        req.scope_id.as_str(),
                        req.bundle_route_intent_ref.as_str(),
                        &req.zone_uid,
                        &req.network_uid,
                        req.network_generation,
                        req.attachment_generation,
                        &req.bundle_generation,
                    )
                })
                .map_err(|reason| BrokerError::RequestValidation {
                    operation: "ApplyRoute",
                    reason,
                })
        }
        BrokerRequest::ApplySysctl(req) => {
            validate_bundle_op_id(req.bundle_sysctl_intent_ref.as_str())
                .and_then(|_| {
                    validate_uid_network_authority(
                        req.scope_id.as_str(),
                        req.bundle_sysctl_intent_ref.as_str(),
                        &req.zone_uid,
                        &req.network_uid,
                        req.network_generation,
                        req.attachment_generation,
                        &req.bundle_generation,
                    )
                })
                .map_err(|reason| BrokerError::RequestValidation {
                    operation: "ApplySysctl",
                    reason,
                })
        }
        BrokerRequest::UpdateHostsFile(req) => {
            validate_bundle_op_id(req.bundle_hosts_intent_ref.as_str())
                .and_then(|_| {
                    if req
                        .bundle_hosts_intent_ref
                        .as_str()
                        .starts_with("network-hosts:")
                    {
                        let (
                            Some(zone_uid),
                            Some(network_uid),
                            Some(network_generation),
                            Some(attachment_generation),
                            Some(bundle_generation),
                        ) = (
                            req.zone_uid.as_ref(),
                            req.network_uid.as_ref(),
                            req.network_generation,
                            req.attachment_generation,
                            req.bundle_generation.as_ref(),
                        )
                        else {
                            return Err("network-admission-mismatch");
                        };
                        validate_uid_network_authority(
                            &format!("network:{}:{}", zone_uid.as_str(), network_uid.as_str()),
                            req.bundle_hosts_intent_ref.as_str(),
                            zone_uid,
                            network_uid,
                            network_generation,
                            attachment_generation,
                            bundle_generation,
                        )
                    } else {
                        Ok(())
                    }
                })
                .map_err(|reason| BrokerError::RequestValidation {
                    operation: "UpdateHostsFile",
                    reason,
                })
        }
        BrokerRequest::ApplyNmUnmanaged(req) => {
            validate_bundle_op_id(req.bundle_nm_intent_ref.as_str())
                .and_then(|_| {
                    if req.scope_id.as_str().starts_with("network:")
                        && req.bundle_nm_intent_ref.as_str() != "nm-unmanaged:host"
                    {
                        Err("network-scope-mismatch")
                    } else {
                        Ok(())
                    }
                })
                .map_err(|reason| BrokerError::RequestValidation {
                    operation: "ApplyNmUnmanaged",
                    reason,
                })
        }
        BrokerRequest::SeedDnsmasqLease(req) => validate_network_scope_provenance(
            req.scope_id.as_str(),
            &req.zone_uid,
            &req.network_uid,
            req.network_generation,
            req.attachment_generation,
            &req.bundle_generation,
        )
        .map_err(|reason| BrokerError::RequestValidation {
            operation: "SeedDnsmasqLease",
            reason,
        }),
        BrokerRequest::CreatePersistentTap(req) => validate_tap_create_provenance(
            &req.bundle_tap_intent_ref,
            &req.vm_id,
            &req.role_id,
            &req.attachment_id,
            &req.zone_uid,
            &req.network_uid,
            req.network_generation,
            req.attachment_generation,
            &req.bundle_generation,
            &req.admitted_interface_names,
        )
        .map_err(|reason| BrokerError::RequestValidation {
            operation: "CreatePersistentTap",
            reason,
        }),
        BrokerRequest::CreateTapFd(req) => validate_tap_create_provenance(
            &req.bundle_tap_intent_ref,
            &req.vm_id,
            &req.role_id,
            &req.attachment_id,
            &req.zone_uid,
            &req.network_uid,
            req.network_generation,
            req.attachment_generation,
            &req.bundle_generation,
            &req.admitted_interface_names,
        )
        .map_err(|reason| BrokerError::RequestValidation {
            operation: "CreateTapFd",
            reason,
        }),
        BrokerRequest::SpawnRunner(req)
            if req.role == d2b_contracts_broker::broker_wire::RunnerRole::QemuMedia
                && req.network_tap_context.is_none() =>
        {
            Err(BrokerError::RequestValidation {
                operation: "SpawnRunner",
                reason: "network-admission-required",
            })
        }
        BrokerRequest::SetBridgePortFlags(req) if req.network_tap_context.is_none() => {
            Err(BrokerError::RequestValidation {
                operation: "SetBridgePortFlags",
                reason: "network-admission-required",
            })
        }
        BrokerRequest::ModprobeIfAllowed(req) => {
            validate_module_name(&req.module_name).map_err(|reason| {
                BrokerError::RequestValidation {
                    operation: "ModprobeIfAllowed",
                    reason,
                }
            })
        }
        BrokerRequest::UsbipBind(req) => {
            validate_bundle_op_id(req.bundle_usbip_bind_intent_ref.as_str()).map_err(|reason| {
                BrokerError::RequestValidation {
                    operation: "UsbipBind",
                    reason,
                }
            })
        }
        BrokerRequest::UsbipUnbind(req) => {
            validate_bundle_op_id(req.bundle_usbip_bind_intent_ref.as_str()).map_err(|reason| {
                BrokerError::RequestValidation {
                    operation: "UsbipUnbind",
                    reason,
                }
            })
        }
        BrokerRequest::UsbipProxyReconcile(req) => validate_scope_like_id(req.scope_id.as_str())
            .map_err(|reason| BrokerError::RequestValidation {
                operation: "UsbipProxyReconcile",
                reason,
            }),
        BrokerRequest::UsbipBindFirewallRule(req) => {
            validate_bundle_op_id(req.bundle_usbip_firewall_intent_ref.as_str()).map_err(|reason| {
                BrokerError::RequestValidation {
                    operation: "UsbipBindFirewallRule",
                    reason,
                }
            })
        }
        BrokerRequest::UsbipExplicitBind(req) => {
            validate_usbip_busid_wire(&req.bus_id).map_err(|reason| {
                BrokerError::RequestValidation {
                    operation: "UsbipExplicitBind",
                    reason,
                }
            })
        }
        BrokerRequest::UsbipExplicitFirewallRule(req) => validate_usbip_busid_wire(&req.bus_id)
            .map_err(|reason| BrokerError::RequestValidation {
                operation: "UsbipExplicitFirewallRule",
                reason,
            }),
        BrokerRequest::MigrateLegacySwtpmState(req) => {
            validate_bundle_op_id(req.bundle_legacy_swtpm_intent_ref.as_str()).map_err(|reason| {
                BrokerError::RequestValidation {
                    operation: "MigrateLegacySwtpmState",
                    reason,
                }
            })
        }
        BrokerRequest::PipeWireAudio(req) => {
            validate_small_wire_id(req.vm_id.as_str(), 128, "invalid-vm-id").map_err(|reason| {
                BrokerError::RequestValidation {
                    operation: "PipeWireAudio",
                    reason,
                }
            })?;
            validate_small_wire_id(req.role_id.as_str(), 128, "invalid-role-id").map_err(
                |reason| BrokerError::RequestValidation {
                    operation: "PipeWireAudio",
                    reason,
                },
            )?;
            validate_bundle_op_id(req.bundle_runner_intent_ref.as_str()).map_err(|reason| {
                BrokerError::RequestValidation {
                    operation: "PipeWireAudio",
                    reason,
                }
            })?;
            if let d2b_contracts_broker::broker_wire::PipeWireAudioAction::SetLevel { percent } =
                req.action
                && percent > 100
            {
                return Err(BrokerError::RequestValidation {
                    operation: "PipeWireAudio",
                    reason: "audio-level-out-of-range",
                });
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn validate_usbip_busid_wire(bus_id: &str) -> Result<(), &'static str> {
    d2b_contracts::usbip::validate_bus_id(bus_id).map_err(|_| "invalid-usbip-busid")
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn validate_module_name(module_name: &str) -> Result<(), &'static str> {
    if module_name.is_empty() {
        return Err("empty-module-name");
    }
    if module_name.len() > MAX_MODULE_NAME_LEN {
        return Err("module-name-too-long");
    }
    if module_name.contains('/') || module_name.contains('\\') || module_name.contains('\0') {
        return Err("invalid-module-name");
    }
    if module_name == "." || module_name == ".." || module_name.contains("..") {
        return Err("invalid-module-name");
    }
    if !module_name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err("invalid-module-name");
    }
    Ok(())
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn validate_scope_like_id(value: &str) -> Result<(), &'static str> {
    validate_small_wire_id(value, 128, "invalid-scope-id")
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn validate_bundle_op_id(value: &str) -> Result<(), &'static str> {
    validate_small_wire_id(value, 192, "invalid-bundle-op-id")
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn validate_small_wire_id(
    value: &str,
    max_len: usize,
    error: &'static str,
) -> Result<(), &'static str> {
    if value.is_empty() || value.len() > max_len {
        return Err(error);
    }
    if value.contains('/') || value.contains('\\') || value.contains('\0') || value.contains("..") {
        return Err(error);
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'-' | b'_' | b'.'))
    {
        return Err(error);
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct DispatchAuditContext {
    peer_pid: i32,
    peer_role: String,
    verb: String,
    request_fields: Value,
    started_at: Instant,
    audit_join: Option<AuditJoinContext>,
}

impl DispatchAuditContext {
    fn from_request(
        request: &BrokerRequest,
        peer_pid: i32,
        caller_role: &CallerRole,
    ) -> Result<Self, BrokerError> {
        #[cfg(feature = "layer1-bootstrap")]
        {
            Self::from_request_with_join(request, peer_pid, caller_role, None)
        }
        #[cfg(not(feature = "layer1-bootstrap"))]
        {
            let join = request
                .authoritative_audit_join()
                .map(|(zone_id, operation_identity)| AuditJoinContext {
                    zone_id: CanonicalAuditDigest::parse(zone_id)
                        .expect("authoritative zone digest"),
                    operation_identity: CanonicalAuditDigest::parse(operation_identity)
                        .expect("authoritative operation digest"),
                });
            Self::from_request_with_join(request, peer_pid, caller_role, join.as_ref())
        }
    }

    fn from_request_with_join(
        request: &BrokerRequest,
        peer_pid: i32,
        caller_role: &CallerRole,
        audit_join: Option<&AuditJoinContext>,
    ) -> Result<Self, BrokerError> {
        #[cfg(not(feature = "layer1-bootstrap"))]
        if matches!(request, BrokerRequest::OpenPeerPidfdFromAcceptedSocket(_))
            && audit_join.is_some()
        {
            return Err(BrokerError::Protocol("audit-join-not-permitted".to_owned()));
        }
        #[cfg(not(feature = "layer1-bootstrap"))]
        if audit_join.is_none() && Self::request_requires_audit_join(request) {
            return Err(BrokerError::Protocol("audit-join-required".to_owned()));
        }
        #[cfg(not(feature = "layer1-bootstrap"))]
        if let Some(supplied) = audit_join
            && let Some((zone_id, operation_identity)) = request.authoritative_audit_join()
        {
            let expected_zone = CanonicalAuditDigest::parse(zone_id)
                .map_err(|_| BrokerError::Protocol("audit zone identity invalid".to_owned()))?;
            let expected_operation =
                CanonicalAuditDigest::parse(operation_identity).map_err(|_| {
                    BrokerError::Protocol("audit operation identity invalid".to_owned())
                })?;
            if supplied.zone_id != expected_zone
                || supplied.operation_identity != expected_operation
            {
                return Err(BrokerError::Protocol("audit-join-mismatch".to_owned()));
            }
        }
        Ok(Self {
            peer_pid,
            peer_role: caller_role.for_display().to_owned(),
            verb: request.op_name().to_owned(),
            request_fields: request_fields_value(request)?,
            started_at: Instant::now(),
            audit_join: audit_join.cloned(),
        })
    }

    fn duration_us(&self) -> u64 {
        self.started_at.elapsed().as_micros() as u64
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    fn request_requires_audit_join(request: &BrokerRequest) -> bool {
        request.requires_authoritative_audit_join()
    }
}

fn request_fields_value(request: &BrokerRequest) -> Result<Value, BrokerError> {
    #[cfg(not(feature = "layer1-bootstrap"))]
    if let BrokerRequest::QemuMediaEnroll(req) = request {
        return Ok(serde_json::json!({
            "vmId": req.vm_id.as_str(),
            "mediaRef": req.media_ref.as_str(),
            "busIdProvided": true,
            "tracingSpanIdPresent": req.tracing_span_id.is_some(),
        }));
    }
    #[cfg(not(feature = "layer1-bootstrap"))]
    if let BrokerRequest::QemuMediaRefreshRegistry(req) = request {
        return Ok(serde_json::json!({
            "tracingSpanIdPresent": req.tracing_span_id.is_some(),
        }));
    }
    #[cfg(not(feature = "layer1-bootstrap"))]
    if let BrokerRequest::QemuMediaBoot(req) = request {
        return Ok(serde_json::json!({
            "vmId": req.vm_id.as_str(),
            "tracingSpanIdPresent": req.tracing_span_id.is_some(),
        }));
    }
    #[cfg(not(feature = "layer1-bootstrap"))]
    if let BrokerRequest::QemuMediaSystemPowerdown(req) | BrokerRequest::QemuMediaQuit(req) =
        request
    {
        return Ok(serde_json::json!({
            "vmId": req.vm_id.as_str(),
            "tracingSpanIdPresent": req.tracing_span_id.is_some(),
        }));
    }
    #[cfg(not(feature = "layer1-bootstrap"))]
    if let BrokerRequest::QemuMediaQueryStatus(req) = request {
        return Ok(serde_json::json!({
            "vmId": req.vm_id.as_str(),
            "shutdownContext": req.shutdown_context,
            "tracingSpanIdPresent": req.tracing_span_id.is_some(),
        }));
    }
    #[cfg(not(feature = "layer1-bootstrap"))]
    if let BrokerRequest::QemuMediaAttach(req) | BrokerRequest::QemuMediaDetach(req) = request {
        return Ok(serde_json::json!({
            "vmId": req.vm_id.as_str(),
            "busIdProvided": true,
            "tracingSpanIdPresent": req.tracing_span_id.is_some(),
        }));
    }
    #[cfg(not(feature = "layer1-bootstrap"))]
    if let BrokerRequest::UsbipBind(req) = request {
        return Ok(serde_json::json!({
            "bundleUsbipBindIntentRef": req.bundle_usbip_bind_intent_ref.as_str(),
            "tracingSpanIdPresent": req.tracing_span_id.is_some(),
        }));
    }
    #[cfg(not(feature = "layer1-bootstrap"))]
    if let BrokerRequest::UsbipUnbind(req) = request {
        return Ok(serde_json::json!({
            "bundleUsbipBindIntentRef": req.bundle_usbip_bind_intent_ref.as_str(),
            "preserveDurableClaim": req.preserve_durable_claim,
            "tracingSpanIdPresent": req.tracing_span_id.is_some(),
        }));
    }
    #[cfg(not(feature = "layer1-bootstrap"))]
    if let BrokerRequest::UsbipBindFirewallRule(req) = request {
        return Ok(serde_json::json!({
            "bundleUsbipFirewallIntentRef": req.bundle_usbip_firewall_intent_ref.as_str(),
            "tracingSpanIdPresent": req.tracing_span_id.is_some(),
        }));
    }
    #[cfg(not(feature = "layer1-bootstrap"))]
    if let BrokerRequest::UsbipProxyReconcile(req) = request {
        return Ok(serde_json::json!({
            "scopeId": req.scope_id.as_str(),
            "tracingSpanIdPresent": req.tracing_span_id.is_some(),
        }));
    }
    let mut value = serde_json::to_value(request)
        .map_err(|err| BrokerError::Protocol(format!("serialize request fields: {err}")))?;
    match &mut value {
        Value::Object(map) => {
            if let Some(payload) = map.remove("payload") {
                Ok(payload)
            } else {
                map.remove("kind");
                map.remove("request");
                Ok(value)
            }
        }
        _ => Ok(value),
    }
}

#[cfg(feature = "layer1-bootstrap")]
fn dispatch_request(
    request: BrokerRequest,
    caller_uid: u32,
    caller_gid: u32,
    caller_role: CallerRole,
    _audit_context: &DispatchAuditContext,
    _config: &ServerConfig,
    audit_log: &AuditLog,
) -> Result<BrokerResponse, BrokerError> {
    match request {
        BrokerRequest::Hello { .. } => {
            audit_log
                .write_entry_with_caller_ids(
                    "Hello",
                    caller_uid,
                    caller_gid,
                    "callable-read-only",
                    "daemon-handshake",
                    "ok",
                )
                .map_err(|err| BrokerError::Protocol(err.to_string()))?;
            Ok(hello_ok_response(_config.profile))
        }
        BrokerRequest::ValidateBundle { path } => {
            handle_validate_bundle(&path, caller_uid, caller_gid, audit_log)
        }
        BrokerRequest::ExportBrokerAudit { since, filter } => handle_export_broker_audit(
            since.as_deref(),
            filter.as_deref(),
            caller_uid,
            caller_gid,
            caller_role,
            audit_log,
        ),
        BrokerRequest::ApplyNftables { .. } => Err(BrokerError::Unimplemented {
            operation: "ApplyNftables",
            target_wave: "W3",
        }),
        BrokerRequest::ApplyNmUnmanaged { .. } => Err(BrokerError::Unimplemented {
            operation: "ApplyNmUnmanaged",
            target_wave: "W3",
        }),
        BrokerRequest::ApplyRoute { .. } => Err(BrokerError::Unimplemented {
            operation: "ApplyRoute",
            target_wave: "W3",
        }),
        BrokerRequest::ApplySysctl { .. } => Err(BrokerError::Unimplemented {
            operation: "ApplySysctl",
            target_wave: "W3",
        }),
        BrokerRequest::BindUnixSocket { .. } => Err(BrokerError::Unimplemented {
            operation: "BindUnixSocket",
            target_wave: "W5",
        }),
        BrokerRequest::CreateOrReconcileUsersGroups { .. } => Err(BrokerError::Unimplemented {
            operation: "CreateOrReconcileUsersGroups",
            target_wave: "W3",
        }),
        BrokerRequest::CreatePersistentTap { .. } => Err(BrokerError::Unimplemented {
            operation: "CreatePersistentTap",
            target_wave: "W3",
        }),
        BrokerRequest::CreateTapFd { .. } => Err(BrokerError::Unimplemented {
            operation: "CreateTapFd",
            target_wave: "W3",
        }),
        BrokerRequest::DelegateCgroupV2 { .. } => Err(BrokerError::Unimplemented {
            operation: "DelegateCgroupV2",
            target_wave: "W3",
        }),
        BrokerRequest::InjectSecretById { .. } => Err(BrokerError::Unimplemented {
            operation: "InjectSecretById",
            target_wave: "W8",
        }),
        BrokerRequest::LaunchMinijailChild { .. } => Err(BrokerError::Unimplemented {
            operation: "LaunchMinijailChild",
            target_wave: "W5",
        }),
        BrokerRequest::ModprobeIfAllowed { .. } => Err(BrokerError::Unimplemented {
            operation: "ModprobeIfAllowed",
            target_wave: "W3",
        }),
        BrokerRequest::OpenCgroupDir { .. } => Err(BrokerError::Unimplemented {
            operation: "OpenCgroupDir",
            target_wave: "W3",
        }),
        BrokerRequest::OpenDevice { .. } => Err(BrokerError::Unimplemented {
            operation: "OpenDevice",
            target_wave: "W3",
        }),
        BrokerRequest::OpenFuse { .. } => Err(BrokerError::Unimplemented {
            operation: "OpenFuse",
            target_wave: "W3",
        }),
        BrokerRequest::OpenKvm { .. } => Err(BrokerError::Unimplemented {
            operation: "OpenKvm",
            target_wave: "W3",
        }),
        BrokerRequest::OpenPidfd { .. } => Err(BrokerError::Unimplemented {
            operation: "OpenPidfd",
            target_wave: "W4-fu",
        }),
        BrokerRequest::OpenVhostNet { .. } => Err(BrokerError::Unimplemented {
            operation: "OpenVhostNet",
            target_wave: "W3",
        }),
        BrokerRequest::PauseBroker { .. } => Err(BrokerError::Unimplemented {
            operation: "PauseBroker",
            target_wave: "W4",
        }),
        BrokerRequest::PrepareRuntimeDir { .. } => Err(BrokerError::Unimplemented {
            operation: "PrepareRuntimeDir",
            target_wave: "W3",
        }),
        BrokerRequest::PrepareStateDir { .. } => Err(BrokerError::Unimplemented {
            operation: "PrepareStateDir",
            target_wave: "W3",
        }),
        BrokerRequest::PrepareStoreView { .. } => Err(BrokerError::Unimplemented {
            operation: "PrepareStoreView",
            target_wave: "W7",
        }),
        BrokerRequest::StoreSync { .. } => Err(BrokerError::Unimplemented {
            operation: "StoreSync",
            target_wave: "P2",
        }),
        BrokerRequest::ReadSecretById { .. } => Err(BrokerError::Unimplemented {
            operation: "ReadSecretById",
            target_wave: "W8",
        }),
        BrokerRequest::ResumeBroker { .. } => Err(BrokerError::Unimplemented {
            operation: "ResumeBroker",
            target_wave: "W4",
        }),
        BrokerRequest::RotateSecretById { .. } => Err(BrokerError::Unimplemented {
            operation: "RotateSecretById",
            target_wave: "W8",
        }),
        BrokerRequest::SetBridgePortFlags { .. } => Err(BrokerError::Unimplemented {
            operation: "SetBridgePortFlags",
            target_wave: "W3",
        }),
        BrokerRequest::SetSocketAcl { .. } => Err(BrokerError::Unimplemented {
            operation: "SetSocketAcl",
            target_wave: "W5",
        }),
        BrokerRequest::SetupMountNamespace { .. } => Err(BrokerError::Unimplemented {
            operation: "SetupMountNamespace",
            target_wave: "W7",
        }),
        BrokerRequest::SpawnRunner { .. } => Err(BrokerError::Unimplemented {
            operation: "SpawnRunner",
            target_wave: "W4-fu",
        }),
        BrokerRequest::UpdateHostsFile { .. } => Err(BrokerError::Unimplemented {
            operation: "UpdateHostsFile",
            target_wave: "W3",
        }),
        BrokerRequest::UsbipBind { .. } => Err(BrokerError::UnknownOperation {
            operation: "UsbipBind",
        }),
        BrokerRequest::UsbipBindFirewallRule { .. } => Err(BrokerError::Unimplemented {
            operation: "UsbipBindFirewallRule",
            target_wave: "W3",
        }),
        BrokerRequest::UsbipExplicitBind { .. } => Err(BrokerError::Unimplemented {
            operation: "UsbipExplicitBind",
            target_wave: "W5",
        }),
        BrokerRequest::UsbipExplicitFirewallRule { .. } => Err(BrokerError::Unimplemented {
            operation: "UsbipExplicitFirewallRule",
            target_wave: "W5",
        }),
        BrokerRequest::UsbipProxyReconcile { .. } => Err(BrokerError::UnknownOperation {
            operation: "UsbipProxyReconcile",
        }),
        BrokerRequest::UsbipUnbind { .. } => Err(BrokerError::UnknownOperation {
            operation: "UsbipUnbind",
        }),
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn request_accepts_fd(request: &BrokerRequest) -> bool {
    matches!(
        request,
        BrokerRequest::OpenPeerPidfdFromAcceptedSocket(_) | BrokerRequest::SpawnRunner(_)
    )
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn validate_spawn_runner_request_fds(
    role: RunnerRole,
    inherited_fd_count: u16,
    attached_fd_count: usize,
) -> Result<(), BrokerError> {
    const MAX_REQUEST_INHERITED_FDS: u16 = 256;
    if inherited_fd_count > MAX_REQUEST_INHERITED_FDS {
        return Err(BrokerError::Protocol(
            "SpawnRunner inherited fd count exceeds the bounded maximum".to_owned(),
        ));
    }
    match role {
        RunnerRole::ProviderController
            if (1..=2).contains(&inherited_fd_count)
                && attached_fd_count == usize::from(inherited_fd_count) + 1 =>
        {
            Ok(())
        }
        RunnerRole::ProviderController => Err(BrokerError::Protocol(
            "ProviderController requires one or two inherited fds".to_owned(),
        )),
        _ if inherited_fd_count == 0 && attached_fd_count == 0 => Ok(()),
        _ => Err(BrokerError::Protocol(
            "runner inherited fd count/attachment mismatch".to_owned(),
        )),
    }
}

/// Real-wire dispatch. Matches the opaque-ID
/// `d2b_contracts_broker::broker_wire::BrokerRequest` tuple-newtype shape and
/// wires the live executors into the dispatch arms that have a ready
/// implementation today.
///
/// This signature takes an `Option<&Arc<BundleResolver>>` and returns
/// `DispatchResult` (response + optional fds) so the bundle-dependent
/// arms can route through `BundleResolver::find_*_intent` and
/// `live_handlers::*`, transporting fds via SCM_RIGHTS on the response
/// frame.
#[cfg(not(feature = "layer1-bootstrap"))]
fn dispatch_request(
    request: BrokerRequest,
    caller_uid: u32,
    caller_gid: u32,
    caller_role: CallerRole,
    audit_context: &DispatchAuditContext,
    config: &ServerConfig,
    audit_log: &AuditLog,
    resolver: Option<&Arc<BundleResolver>>,
) -> Result<DispatchResult, BrokerError> {
    dispatch_request_with_request_fds(
        request,
        caller_uid,
        caller_gid,
        caller_role,
        audit_context,
        config,
        audit_log,
        resolver,
        Vec::new(),
    )
}

#[cfg(not(feature = "layer1-bootstrap"))]
#[allow(clippy::too_many_arguments)]
fn dispatch_request_with_request_fds(
    request: BrokerRequest,
    caller_uid: u32,
    caller_gid: u32,
    caller_role: CallerRole,
    audit_context: &DispatchAuditContext,
    config: &ServerConfig,
    audit_log: &AuditLog,
    resolver: Option<&Arc<BundleResolver>>,
    request_fds: Vec<OwnedFd>,
) -> Result<DispatchResult, BrokerError> {
    let backend = LiveDispatchBackend {
        daemon_uid: config.d2bd_uid,
        daemon_gid: config.d2bd_gid,
        state_dir: config.state_dir.clone(),
    };
    dispatch_request_with_backend_and_request_fds(
        request,
        caller_uid,
        caller_gid,
        caller_role,
        audit_context,
        config,
        audit_log,
        resolver,
        &backend,
        request_fds,
    )
}

#[cfg(not(feature = "layer1-bootstrap"))]
#[allow(clippy::too_many_arguments)]
fn dispatch_request_with_backend<B: DispatchBackend>(
    request: BrokerRequest,
    caller_uid: u32,
    caller_gid: u32,
    caller_role: CallerRole,
    audit_context: &DispatchAuditContext,
    config: &ServerConfig,
    audit_log: &AuditLog,
    resolver: Option<&Arc<BundleResolver>>,
    backend: &B,
) -> Result<DispatchResult, BrokerError> {
    dispatch_request_with_backend_and_request_fds(
        request,
        caller_uid,
        caller_gid,
        caller_role,
        audit_context,
        config,
        audit_log,
        resolver,
        backend,
        Vec::new(),
    )
}

#[cfg(not(feature = "layer1-bootstrap"))]
#[allow(clippy::too_many_arguments)]
fn dispatch_request_with_backend_and_request_fds<B: DispatchBackend>(
    request: BrokerRequest,
    caller_uid: u32,
    caller_gid: u32,
    caller_role: CallerRole,
    audit_context: &DispatchAuditContext,
    config: &ServerConfig,
    audit_log: &AuditLog,
    resolver: Option<&Arc<BundleResolver>>,
    backend: &B,
    mut request_fds: Vec<OwnedFd>,
) -> Result<DispatchResult, BrokerError> {
    use d2b_contracts_broker::broker_wire::BrokerRequest as RealBrokerRequest;
    use d2b_core::bundle_resolver::intent_id_legacy_runner;
    let bundle_metadata = audit_bundle_metadata(resolver.map(std::sync::Arc::as_ref));
    macro_rules! write_decision_op_record {
        ($($args:tt)*) => {
            write_decision_op_record_impl($($args)* audit_context)
        };
    }
    macro_rules! write_success_op_record {
        ($($args:tt)*) => {
            write_success_op_record_impl($($args)* audit_context)
        };
    }
    if !request_accepts_fd(&request) && !request_fds.is_empty() {
        return Err(BrokerError::Protocol(
            "unexpected request SCM_RIGHTS descriptor".to_owned(),
        ));
    }
    validate_broker_request(&request)?;
    if matches!(caller_role, CallerRole::HostShutdownUid { .. })
        && !matches!(
            request,
            RealBrokerRequest::Hello(_)
                | RealBrokerRequest::ConsumeLifecycleLease(_)
                | RealBrokerRequest::SignalRunner(_)
                | RealBrokerRequest::PollChildReaped
                | RealBrokerRequest::DeregisterRunnerPidfd(_)
                | RealBrokerRequest::CgroupKill(_)
                | RealBrokerRequest::StopSystemdUnit(_)
        )
    {
        return Err(BrokerError::HostShutdownRestricted);
    }
    match request {
        RealBrokerRequest::Hello(req) => {
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "Hello",
                "daemon-handshake",
                caller_uid,
                caller_gid,
                &caller_role,
                "daemon-handshake",
                "broker",
                None,
                OperationFields::Hello {
                    client_version: req.client_version,
                },
            )?;
            Ok(DispatchResult::no_fds(hello_ok_response(config.profile)))
        }
        RealBrokerRequest::ValidateBundle => {
            // The broker validates the server-configured bundle path.
            // The daemon never names a bundle path on the wire (security:
            // prevents path-traversal + symlink-confusion).
            // ServerConfig.bundle_path defaults to
            // `/var/lib/d2b/current-bundle/manifest.json` and is
            // operator-overridable via the `--bundle-path` flag (or the
            // NixOS module's `d2b.site.bundle.currentManifest`
            // option once that lands).
            manifest_api::validate_bundle(&config.bundle_path)
                .map_err(BrokerError::ValidateBundle)?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "ValidateBundle",
                "bundle",
                caller_uid,
                caller_gid,
                &caller_role,
                "bundle",
                "broker",
                None,
                OperationFields::ValidateBundle {},
            )?;
            Ok(DispatchResult::no_fds(validate_bundle_ok_response()))
        }
        RealBrokerRequest::ResourceActivationAudit(req) => {
            let op_fields = OperationFields::ResourceActivationAudit {};
            if !caller_role_is_admin(&caller_role) {
                write_decision_op_record!(
                    audit_log,
                    bundle_metadata,
                    "ResourceActivationAudit",
                    req.audit_join.operation_identity.as_str(),
                    caller_uid,
                    caller_gid,
                    &caller_role,
                    "resource-bundle",
                    req.audit_join.zone_id.as_str(),
                    None,
                    "denied-refused",
                    Some("audit-requires-admin"),
                    op_fields,
                )?;
                return Err(BrokerError::AuditRequiresAdmin);
            }
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "ResourceActivationAudit",
                req.audit_join.operation_identity.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                "resource-bundle",
                req.audit_join.zone_id.as_str(),
                None,
                op_fields,
            )?;
            Ok(DispatchResult::no_fds(
                BrokerResponse::ResourceActivationAudit(
                    d2b_contracts_broker::broker_wire::ResourceActivationAuditResponse {
                        recorded: true,
                    },
                ),
            ))
        }
        RealBrokerRequest::ExportBrokerAudit(req) => {
            // Real wire filter is a typed BrokerAuditFilter struct;
            // serialize to JSON so the daily-file export path keeps the
            // existing substring match semantics.
            let filter_json = req
                .filter
                .as_ref()
                .and_then(|f| serde_json::to_string(f).ok());
            let op_fields = OperationFields::ExportBrokerAudit {
                since: req.since.clone(),
                filter: filter_json.clone(),
            };
            if !caller_role_is_admin(&caller_role) {
                write_decision_op_record!(
                    audit_log,
                    bundle_metadata,
                    "ExportBrokerAudit",
                    "audit-log",
                    caller_uid,
                    caller_gid,
                    &caller_role,
                    "audit-log",
                    "broker",
                    None,
                    "denied-refused",
                    Some("audit-requires-admin"),
                    op_fields,
                )?;
                return Err(BrokerError::AuditRequiresAdmin);
            }
            let page = audit_log
                .export_page(
                    req.since.as_deref(),
                    filter_json.as_deref(),
                    req.cursor.as_ref(),
                    req.limit,
                )
                .map_err(|err| BrokerError::Protocol(err.to_string()))?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "ExportBrokerAudit",
                "audit-log",
                caller_uid,
                caller_gid,
                &caller_role,
                "audit-log",
                "broker",
                None,
                op_fields,
            )?;
            Ok(DispatchResult::no_fds(export_broker_audit_ok_response(
                page,
            )))
        }
        // Live bundle-dependent real-wire ops. Each one (1) resolves the
        // daemon's opaque BundleOpId via the trusted-bundle resolver,
        // (2) invokes the matching live_handlers::* executor against the
        // system executor, (3) writes the audit row, (4) returns an
        // Ack or fd-bearing response.
        RealBrokerRequest::ApplyNftables(req) => {
            let resolver = require_resolver(resolver)?;
            let intent = resolver
                .find_nft_intent(req.bundle_nft_intent_ref.as_str())
                .ok_or_else(|| BrokerError::BundleIntentMissing {
                    kind: "nft",
                    intent_id: req.bundle_nft_intent_ref.as_str().to_owned(),
                })?;
            let desired_hash = if req.destroy {
                None
            } else {
                let persisted_hash = persisted_nft_hash()
                    .map_err(|err| BrokerError::LiveHandler(err.to_string()))?;
                req.desired_hash
                    .clone()
                    .or(persisted_hash)
                    .or_else(|| resolver.host.nftables.table_hash_after_apply.clone())
            };
            backend.apply_nftables(resolver, intent, desired_hash.as_deref(), req.destroy)?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "ApplyNftables",
                req.bundle_nft_intent_ref.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                intent.scope_label.as_str(),
                req.scope_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::ApplyNftables {
                    bundle_nft_intent_ref: req.bundle_nft_intent_ref.as_str().to_owned(),
                    scope_id: req.scope_id.as_str().to_owned(),
                    desired_hash,
                    destroy: req.destroy,
                },
            )?;
            Ok(DispatchResult::no_fds(ack_response("ApplyNftables")))
        }
        RealBrokerRequest::ApplyRoute(req) => {
            let resolver = require_resolver(resolver)?;
            let provenance = network_provenance(
                req.zone_uid.clone(),
                req.network_uid.clone(),
                req.network_generation,
                req.attachment_generation,
                req.bundle_generation.clone(),
            );
            let intent = resolver
                .resolve_network_route_intent(req.bundle_route_intent_ref.as_str(), &provenance)
                .ok_or_else(|| BrokerError::BundleIntentMissing {
                    kind: "route",
                    intent_id: req.bundle_route_intent_ref.as_str().to_owned(),
                })?;
            require_installed_network_generation(resolver, &provenance)?;
            backend.apply_route(&config.state_dir, &intent, &provenance, req.destroy)?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "ApplyRoute",
                req.bundle_route_intent_ref.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                intent.destination.as_str(),
                req.scope_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::ApplyRoute {
                    bundle_route_intent_ref: req.bundle_route_intent_ref.as_str().to_owned(),
                    destination: intent.destination.clone(),
                    via: intent.via.clone(),
                    destroy: req.destroy,
                },
            )?;
            Ok(DispatchResult::no_fds(ack_response("ApplyRoute")))
        }
        RealBrokerRequest::ApplySysctl(req) => {
            let resolver = require_resolver(resolver)?;
            let provenance = network_provenance(
                req.zone_uid.clone(),
                req.network_uid.clone(),
                req.network_generation,
                req.attachment_generation,
                req.bundle_generation.clone(),
            );
            let intent = resolver
                .resolve_network_sysctl_intent(req.bundle_sysctl_intent_ref.as_str(), &provenance)
                .ok_or_else(|| BrokerError::BundleIntentMissing {
                    kind: "sysctl",
                    intent_id: req.bundle_sysctl_intent_ref.as_str().to_owned(),
                })?;
            let expected_marker = req
                .bundle_sysctl_intent_ref
                .as_str()
                .rsplit(':')
                .next()
                .map(|key| {
                    d2b_contracts_resource::v3::derive_network_ownership_marker(
                        &provenance,
                        &format!("sysctl:{key}"),
                    )
                });
            if intent.provenance.as_ref() != Some(&provenance)
                || intent.ownership_marker.as_deref() != expected_marker.as_deref()
            {
                return Err(BrokerError::RequestValidation {
                    operation: "ApplySysctl",
                    reason: "network-admission-mismatch",
                });
            }
            require_installed_network_generation(resolver, &provenance)?;
            backend.apply_sysctl(&intent, req.destroy)?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "ApplySysctl",
                req.bundle_sysctl_intent_ref.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                intent.key.as_str(),
                req.scope_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::ApplySysctl {
                    bundle_sysctl_intent_ref: req.bundle_sysctl_intent_ref.as_str().to_owned(),
                    key: intent.key.clone(),
                    destroy: req.destroy,
                },
            )?;
            Ok(DispatchResult::no_fds(ack_response("ApplySysctl")))
        }
        RealBrokerRequest::UpdateHostsFile(req) => {
            let resolver = require_resolver(resolver)?;
            let (intent, network_provenance) = if req
                .bundle_hosts_intent_ref
                .as_str()
                .starts_with("network-hosts:")
            {
                let provenance = network_provenance(
                    req.zone_uid.clone().ok_or(BrokerError::RequestValidation {
                        operation: "UpdateHostsFile",
                        reason: "network-admission-mismatch",
                    })?,
                    req.network_uid
                        .clone()
                        .ok_or(BrokerError::RequestValidation {
                            operation: "UpdateHostsFile",
                            reason: "network-admission-mismatch",
                        })?,
                    req.network_generation
                        .ok_or(BrokerError::RequestValidation {
                            operation: "UpdateHostsFile",
                            reason: "network-admission-mismatch",
                        })?,
                    req.attachment_generation
                        .ok_or(BrokerError::RequestValidation {
                            operation: "UpdateHostsFile",
                            reason: "network-admission-mismatch",
                        })?,
                    req.bundle_generation
                        .clone()
                        .ok_or(BrokerError::RequestValidation {
                            operation: "UpdateHostsFile",
                            reason: "network-admission-mismatch",
                        })?,
                );
                require_installed_network_generation(resolver, &provenance)?;
                (
                    resolver
                        .resolve_network_hosts_intent(
                            req.bundle_hosts_intent_ref.as_str(),
                            &provenance,
                        )
                        .ok_or_else(|| BrokerError::BundleIntentMissing {
                            kind: "hosts",
                            intent_id: req.bundle_hosts_intent_ref.as_str().to_owned(),
                        })?,
                    Some(provenance),
                )
            } else {
                (
                    resolver
                        .find_hosts_intent(req.bundle_hosts_intent_ref.as_str())
                        .ok_or_else(|| BrokerError::BundleIntentMissing {
                            kind: "hosts",
                            intent_id: req.bundle_hosts_intent_ref.as_str().to_owned(),
                        })?
                        .clone(),
                    None,
                )
            };
            if let Some(provenance) = network_provenance.as_ref() {
                let expected_marker = d2b_contracts_resource::v3::derive_network_ownership_marker(
                    provenance, "hosts",
                );
                if intent.provenance.as_ref() != Some(provenance)
                    || intent.ownership_marker.as_deref() != Some(expected_marker.as_str())
                {
                    return Err(BrokerError::RequestValidation {
                        operation: "UpdateHostsFile",
                        reason: "network-admission-mismatch",
                    });
                }
            }
            backend.update_hosts_file(&intent, req.destroy)?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "UpdateHostsFile",
                req.bundle_hosts_intent_ref.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                "hosts-file",
                "host",
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::UpdateHostsFile {
                    bundle_hosts_intent_ref: req.bundle_hosts_intent_ref.as_str().to_owned(),
                    destroy: req.destroy,
                },
            )?;
            Ok(DispatchResult::no_fds(ack_response("UpdateHostsFile")))
        }
        RealBrokerRequest::ApplyNmUnmanaged(req) => {
            let resolver = require_resolver(resolver)?;
            let intent = resolver
                .find_nm_unmanaged_intent(req.bundle_nm_intent_ref.as_str())
                .ok_or_else(|| BrokerError::BundleIntentMissing {
                    kind: "nm-unmanaged",
                    intent_id: req.bundle_nm_intent_ref.as_str().to_owned(),
                })?;
            backend.apply_nm_unmanaged(intent, req.destroy)?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "ApplyNmUnmanaged",
                req.bundle_nm_intent_ref.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                req.scope_id.as_str(),
                req.scope_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::ApplyNmUnmanaged {
                    bundle_nm_intent_ref: req.bundle_nm_intent_ref.as_str().to_owned(),
                    scope_id: req.scope_id.as_str().to_owned(),
                    destroy: req.destroy,
                },
            )?;
            Ok(DispatchResult::no_fds(ack_response("ApplyNmUnmanaged")))
        }
        RealBrokerRequest::ReconcileStorageScope(req) => {
            let resolver = require_resolver(resolver)?;
            let response = crate::ops::storage_contract::reconcile_storage_scope(
                resolver,
                &req.storage_ref,
                req.apply,
            )
            .map_err(|err| match err {
                crate::ops::storage_contract::StorageContractError::UnknownStorage(id) => {
                    BrokerError::BundleIntentMissing {
                        kind: "storage",
                        intent_id: id,
                    }
                }
                other => BrokerError::LiveHandler(other.to_string()),
            })?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "ReconcileStorageScope",
                req.storage_ref.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                response.scope.as_str(),
                req.storage_ref.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::ReconcileStorageScope {
                    storage_ref: response.storage_ref.as_str().to_owned(),
                    scope: response.scope.clone(),
                    kind: response.kind.clone(),
                    status: format!("{:?}", response.status),
                    applied: response.applied,
                    path_hash: response.path_hash.clone(),
                },
            )?;
            Ok(DispatchResult::no_fds(
                BrokerResponse::ReconcileStorageScope(response),
            ))
        }
        RealBrokerRequest::ValidateLockSpec(req) => {
            let resolver = require_resolver(resolver)?;
            let response =
                crate::ops::storage_contract::validate_lock_spec(resolver, &req.lock_ref).map_err(
                    |err| match err {
                        crate::ops::storage_contract::StorageContractError::UnknownLock(id) => {
                            BrokerError::BundleIntentMissing {
                                kind: "sync-lock",
                                intent_id: id,
                            }
                        }
                        other => BrokerError::LiveHandler(other.to_string()),
                    },
                )?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "ValidateLockSpec",
                req.lock_ref.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                response.scope.as_str(),
                req.lock_ref.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::ValidateLockSpec {
                    lock_ref: response.lock_ref.as_str().to_owned(),
                    scope: response.scope.clone(),
                    kind: response.kind.clone(),
                    cloexec_required: response.cloexec_required,
                    fd_passing_mechanism: response.fd_passing_mechanism.clone(),
                    order_key: response.order_key.clone(),
                },
            )?;
            Ok(DispatchResult::no_fds(BrokerResponse::ValidateLockSpec(
                response,
            )))
        }
        RealBrokerRequest::OpenPidfd(req) => {
            // OpenPidfd returns the pidfd and, for Provider controllers, the
            // broker-retained bootstrap endpoint.
            let runner_id = runner_registry_key(
                req.vm_id.as_str(),
                req.role_id.as_str(),
                req.resource_ref.as_ref(),
                req.resource_uid.as_ref(),
                req.zone_uid.as_ref(),
                req.runtime_scope,
            );
            let resolver = require_resolver(resolver)?;
            let intent_id = req
                .bundle_runner_intent_ref
                .as_ref()
                .map(|intent| intent.as_str().to_owned())
                .unwrap_or_else(|| {
                    runner_intent_id_for_open_pidfd(req.vm_id.as_str(), req.role_id.as_str())
                });
            if req.resource_ref.is_some() && req.bundle_runner_intent_ref.is_none() {
                return Err(BrokerError::SpawnRunnerIntentMismatch {
                    field: "bundle_runner_intent_ref",
                    requested: "missing".to_owned(),
                    resolved: "required-for-typed-process".to_owned(),
                });
            }
            let intent = resolver.find_runner_intent(&intent_id).ok_or_else(|| {
                BrokerError::BundleIntentMissing {
                    kind: "runner",
                    intent_id: intent_id.clone(),
                }
            })?;
            if intent.vm_name != req.vm_id.as_str()
                || (intent.role_id != req.role_id.as_str()
                    && !(matches!(
                        intent.role,
                        d2b_core::processes::ProcessRole::CloudHypervisorRunner
                    ) && req.role_id.as_str() == "ch-runner"))
            {
                return Err(BrokerError::LiveHandler(
                    "runner adoption intent mismatch".to_owned(),
                ));
            }
            let typed = typed_process_identity(
                req.resource_ref.as_ref(),
                req.resource_uid.as_ref(),
                req.zone_uid.as_ref(),
                req.generation,
                req.runtime_scope,
                &intent.role_id,
                req.guest_execution.as_ref(),
            )?;
            validate_typed_process_metadata(
                typed,
                req.owner_ref.as_ref(),
                req.provider_ref.as_ref(),
                req.provider_identity,
                req.template_identity,
                req.guest_execution.as_ref(),
                intent,
            )
            .inspect_err(|error| {
                tracing::warn!(
                    error = ?error,
                    "ObserveRunner typed Process metadata validation failed",
                );
            })?;
            if typed {
                let placement = private_cgroup_placement(
                    &intent.cgroup_placement,
                    req.vm_id.as_str(),
                    req.runtime_scope,
                    true,
                )?;
                if !proc_cgroup_matches(req.pid, &placement.subtree) {
                    return Err(BrokerError::LiveHandler(
                        "runner pidfd candidate cgroup mismatch".to_owned(),
                    ));
                }
                let broker_owned = runner_pidfd_registry()
                    .lock()
                    .ok()
                    .is_some_and(|registry| registry.contains_key(&runner_id))
                    && runner_metadata_registry()
                        .lock()
                        .ok()
                        .is_some_and(|registry| registry.contains_key(&runner_id));
                let executable = observe_runner_executable(
                    read_runner_executable(req.pid),
                    &intent.binary_path,
                )?;
                if !executable.is_verified_for_registered(broker_owned, true) {
                    return Err(BrokerError::LiveHandler(
                        "runner pidfd candidate executable mismatch".to_owned(),
                    ));
                }
            }
            let outcome =
                backend.open_pidfd(runner_id.as_str(), req.pid, req.expected_start_time_ticks)?;
            if let Err(error) = register_runner_metadata_from_open(runner_id.as_str(), &req, intent)
            {
                remove_runner_registration(runner_id.as_str());
                return Err(error);
            }
            if let Err(error) = write_success_op_record!(
                audit_log,
                bundle_metadata,
                "OpenPidfd",
                runner_id.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                req.vm_id.as_str(),
                req.role_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::OpenPidfd {
                    pid: req.pid,
                    expected_start_time_ticks: req.expected_start_time_ticks,
                },
            ) {
                remove_runner_registration(runner_id.as_str());
                remove_runner_metadata(runner_id.as_str());
                return Err(error);
            }
            let controller_bootstrap = controller_bootstrap_registry()
                .lock()
                .map_err(|_| {
                    BrokerError::Protocol("controller bootstrap registry mutex poisoned".to_owned())
                })?
                .get(&runner_id)
                .map(OwnedFd::try_clone)
                .transpose()
                .map_err(|error| BrokerError::LiveHandler(error.to_string()))?;
            let controller_bootstrap_fd_index = controller_bootstrap.as_ref().map(|_| 1);
            let response =
                BrokerResponse::OpenPidfd(d2b_contracts_broker::broker_wire::OpenPidfdResponse {
                    vm_id: req.vm_id.clone(),
                    role_id: req.role_id.clone(),
                    pid: outcome.pid,
                    verified_start_time_ticks: outcome.verified_start_time_ticks,
                    pidfd_index: 0,
                    controller_bootstrap_fd_index,
                });
            let mut response_fds = vec![outcome.pidfd];
            response_fds.extend(controller_bootstrap);
            Ok(DispatchResult::with_fds(response, response_fds))
        }
        RealBrokerRequest::ConsumeLifecycleLease(req) => {
            consume_lifecycle_lease(&req, &caller_role)?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "ConsumeLifecycleLease",
                "guest-lifecycle",
                caller_uid,
                caller_gid,
                &caller_role,
                "guest-lifecycle",
                "broker",
                None,
                OperationFields::ConsumeLifecycleLease {
                    operation_id: req.operation_id.clone(),
                    operation: format!("{:?}", req.operation),
                    policy_revision: req.policy_revision,
                    guest_generation: req.guest_generation,
                    provider_assignment_generation: req.provider_assignment_generation,
                    stop_only: req.stop_only,
                },
            )?;
            complete_lifecycle_lease(&req)?;
            Ok(DispatchResult::no_fds(
                BrokerResponse::ConsumeLifecycleLease(
                    d2b_contracts_broker::broker_wire::ConsumeLifecycleLeaseResponse {
                        consumed: true,
                    },
                ),
            ))
        }
        RealBrokerRequest::OpenPeerPidfdFromAcceptedSocket(_) => {
            if request_fds.len() != 1 {
                return Err(BrokerError::Protocol(
                    "accepted socket request must carry exactly one descriptor".to_owned(),
                ));
            }
            let accepted_socket = request_fds.pop().expect("checked descriptor count");
            let pidfd = crate::sys::peer_pidfd_from_accepted_socket(accepted_socket.as_raw_fd())
                .map_err(|_| BrokerError::Protocol("accepted-peer-pidfd-unavailable".to_owned()))?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "OpenPeerPidfdFromAcceptedSocket",
                "accepted-socket",
                caller_uid,
                caller_gid,
                &caller_role,
                "accepted-socket",
                "broker",
                None,
                OperationFields::OpenPeerPidfdFromAcceptedSocket {},
            )?;
            Ok(DispatchResult::with_fd(
                BrokerResponse::OpenPeerPidfdFromAcceptedSocket(
                    d2b_contracts_broker::broker_wire::OpenPeerPidfdFromAcceptedSocketResponse {
                        pidfd_index: 0,
                    },
                ),
                pidfd,
            ))
        }
        RealBrokerRequest::ObserveRunner(req) => {
            let resolver = require_resolver(resolver)?;
            let intent = resolver
                .find_runner_intent(req.bundle_runner_intent_ref.as_str())
                .ok_or_else(|| BrokerError::BundleIntentMissing {
                    kind: "runner",
                    intent_id: req.bundle_runner_intent_ref.as_str().to_owned(),
                })
                .inspect_err(|error| {
                    tracing::warn!(error = ?error, "ObserveRunner intent lookup failed");
                })?;
            let expected_role = runner_role_for_process_role(&intent.role).ok_or_else(|| {
                BrokerError::SpawnRunnerIntentMismatch {
                    field: "role",
                    requested: req.role.as_str().to_owned(),
                    resolved: format!("{:?}", intent.role),
                }
            })?;
            if req.vm_id.as_str() != intent.vm_name
                || req.role != expected_role
                || req.bundle_runner_intent_ref.as_str() != intent.intent_id
                || req.role_id.as_str()
                    != match intent.role {
                        d2b_core::processes::ProcessRole::CloudHypervisorRunner => "ch-runner",
                        _ => intent.role_id.as_str(),
                    }
            {
                tracing::warn!("ObserveRunner basic intent identity validation failed");
                return Err(BrokerError::LiveHandler(
                    "runner observation intent mismatch".to_owned(),
                ));
            }
            let typed = typed_process_identity(
                req.resource_ref.as_ref(),
                req.resource_uid.as_ref(),
                req.zone_uid.as_ref(),
                req.generation,
                req.runtime_scope,
                &intent.role_id,
                req.guest_execution.as_ref(),
            )
            .inspect_err(|error| {
                tracing::warn!(error = ?error, "ObserveRunner typed identity decoding failed");
            })?;
            validate_typed_process_metadata(
                typed,
                req.owner_ref.as_ref(),
                req.provider_ref.as_ref(),
                req.provider_identity,
                req.template_identity,
                req.guest_execution.as_ref(),
                intent,
            )?;
            let response = observe_registered_runner(&req, intent).inspect_err(|error| {
                tracing::warn!(error = ?error, "ObserveRunner registry observation failed");
            })?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "ObserveRunner",
                req.bundle_runner_intent_ref.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                req.vm_id.as_str(),
                req.role_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::ObserveRunner {
                    vm_id: req.vm_id.as_str().to_owned(),
                    role_id: req.role_id.as_str().to_owned(),
                    present: response.present,
                    cgroup_verified: response.cgroup_verified,
                    executable_verified: response.executable_verified,
                },
            )?;
            Ok(DispatchResult::no_fds(BrokerResponse::ObserveRunner(
                response,
            )))
        }
        RealBrokerRequest::PipeWireAudio(req) => {
            let resolver = require_resolver(resolver)?;
            let intent = resolver
                .find_runner_intent(req.bundle_runner_intent_ref.as_str())
                .ok_or_else(|| BrokerError::BundleIntentMissing {
                    kind: "runner",
                    intent_id: req.bundle_runner_intent_ref.as_str().to_owned(),
                })?;
            if req.vm_id.as_str() != intent.vm_name
                || req.role_id.as_str() != intent.role_id
                || req.bundle_runner_intent_ref.as_str() != intent.intent_id
                || intent.role != d2b_core::processes::ProcessRole::Audio
            {
                return Err(BrokerError::LiveHandler(
                    "audio effect intent mismatch".to_owned(),
                ));
            }

            let env_value = |key: &str| {
                intent
                    .env
                    .iter()
                    .find_map(|entry| entry.strip_prefix(&format!("{key}=")))
            };
            let response = match (
                env_value("WPCTL_PATH"),
                env_value("PW_DUMP_PATH"),
                env_value("PIPEWIRE_RUNTIME_DIR"),
            ) {
                (Some(wpctl_path), Some(pw_dump_path), Some(runtime_dir))
                    if Path::new(wpctl_path).is_absolute()
                        && Path::new(pw_dump_path).is_absolute()
                        && Path::new(runtime_dir).is_absolute() =>
                {
                    let dump = std::process::Command::new(pw_dump_path)
                        .env_clear()
                        .env("PIPEWIRE_RUNTIME_DIR", runtime_dir)
                        .env("XDG_RUNTIME_DIR", runtime_dir)
                        .stdin(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .output();
                    match dump.ok().filter(|output| output.status.success()) {
                        None => d2b_contracts_broker::broker_wire::PipeWireAudioResponse {
                            vm_id: req.vm_id.clone(),
                            role_id: req.role_id.clone(),
                            applied: false,
                            host_ready: false,
                            node_present: false,
                        },
                        Some(dump) => {
                            let node_id = serde_json::from_slice::<Value>(&dump.stdout)
                                .ok()
                                .and_then(|document| {
                                    let expected_app = format!("d2b-{}", intent.vm_name);
                                    let expected_class = match req.channel {
                                        d2b_contracts_broker::broker_wire::PipeWireAudioChannel::Speaker => {
                                            "Stream/Output/Audio"
                                        }
                                        d2b_contracts_broker::broker_wire::PipeWireAudioChannel::Microphone => {
                                            "Stream/Input/Audio"
                                        }
                                    };
                                    let mut matches =
                                        document.as_array()?.iter().filter_map(|entry| {
                                            let props = entry.get("info")?.get("props")?;
                                            if props.get("application.name")?.as_str()?
                                                != expected_app
                                                || props.get("media.class")?.as_str()?
                                                    != expected_class
                                            {
                                                return None;
                                            }
                                            entry.get("id").and_then(Value::as_u64)
                                        });
                                    let first = matches.next()?;
                                    if matches.next().is_some() {
                                        None
                                    } else {
                                        Some(first.to_string())
                                    }
                                });
                            match node_id {
                                None => d2b_contracts_broker::broker_wire::PipeWireAudioResponse {
                                    vm_id: req.vm_id.clone(),
                                    role_id: req.role_id.clone(),
                                    applied: false,
                                    host_ready: true,
                                    node_present: false,
                                },
                                Some(node_id) => {
                                    let mut command = std::process::Command::new(wpctl_path);
                                    command
                                        .env_clear()
                                        .env("PIPEWIRE_RUNTIME_DIR", runtime_dir)
                                        .env("XDG_RUNTIME_DIR", runtime_dir)
                                        .stdin(std::process::Stdio::null())
                                        .stdout(std::process::Stdio::null())
                                        .stderr(std::process::Stdio::null());
                                    let level_arg;
                                    match req.action {
                                        d2b_contracts_broker::broker_wire::PipeWireAudioAction::SetGrant {
                                            on,
                                        } => {
                                            command.args([
                                                "set-mute",
                                                &node_id,
                                                if on { "0" } else { "1" },
                                            ]);
                                        }
                                        d2b_contracts_broker::broker_wire::PipeWireAudioAction::SetLevel {
                                            percent,
                                        } => {
                                            level_arg = format!("{percent}%");
                                            command.args(["set-volume", &node_id, &level_arg]);
                                        }
                                    }
                                    let applied = command
                                        .output()
                                        .map(|output| output.status.success())
                                        .unwrap_or(false);
                                    d2b_contracts_broker::broker_wire::PipeWireAudioResponse {
                                        vm_id: req.vm_id.clone(),
                                        role_id: req.role_id.clone(),
                                        applied,
                                        host_ready: true,
                                        node_present: true,
                                    }
                                }
                            }
                        }
                    }
                }
                _ => d2b_contracts_broker::broker_wire::PipeWireAudioResponse {
                    vm_id: req.vm_id.clone(),
                    role_id: req.role_id.clone(),
                    applied: false,
                    host_ready: false,
                    node_present: false,
                },
            };
            let action = match req.action {
                d2b_contracts_broker::broker_wire::PipeWireAudioAction::SetGrant { on } => {
                    format!("grant:{}", if on { "on" } else { "off" })
                }
                d2b_contracts_broker::broker_wire::PipeWireAudioAction::SetLevel { percent } => {
                    format!("level:{percent}")
                }
            };
            let channel = match req.channel {
                d2b_contracts_broker::broker_wire::PipeWireAudioChannel::Speaker => "speaker",
                d2b_contracts_broker::broker_wire::PipeWireAudioChannel::Microphone => "microphone",
            };
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "PipeWireAudio",
                req.bundle_runner_intent_ref.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                req.vm_id.as_str(),
                req.role_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::PipeWireAudio {
                    vm_id: req.vm_id.as_str().to_owned(),
                    role_id: req.role_id.as_str().to_owned(),
                    channel: channel.to_owned(),
                    action,
                    applied: response.applied,
                    host_ready: response.host_ready,
                    node_present: response.node_present,
                },
            )?;
            Ok(DispatchResult::no_fds(BrokerResponse::PipeWireAudio(
                response,
            )))
        }
        RealBrokerRequest::StartSystemdUnit(req) => {
            let resolver = require_resolver_ref(resolver.map(std::sync::Arc::as_ref))?;
            let (identity, pidfd) = backend.start_systemd_unit(resolver, &req)?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "StartSystemdUnit",
                req.role_id.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                req.vm_id.as_str(),
                req.role_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::SystemdUnit {
                    vm_id: req.vm_id.as_str().to_owned(),
                    role_id: req.role_id.as_str().to_owned(),
                    role: req.role.as_str().to_owned(),
                    bundle_runner_intent_ref: req.bundle_runner_intent_ref.as_str().to_owned(),
                    domain: systemd_domain_name(req.domain).to_owned(),
                    action: "start".to_owned(),
                    stopped: None,
                },
            )?;
            Ok(DispatchResult::with_fd(
                BrokerResponse::StartSystemdUnit(
                    d2b_contracts_broker::broker_wire::StartTransientUnitResponse {
                        vm_id: req.vm_id,
                        role_id: req.role_id,
                        identity,
                        pidfd_index: 0,
                    },
                ),
                pidfd,
            ))
        }
        RealBrokerRequest::CheckSystemdUserManager(req) => {
            let resolver = require_resolver_ref(resolver.map(std::sync::Arc::as_ref))?;
            let available = backend.check_systemd_user_manager(resolver, &req)?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "CheckSystemdUserManager",
                req.role_id.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                req.vm_id.as_str(),
                req.role_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::SystemdUnit {
                    vm_id: req.vm_id.as_str().to_owned(),
                    role_id: req.role_id.as_str().to_owned(),
                    role: req.role.as_str().to_owned(),
                    bundle_runner_intent_ref: req.bundle_runner_intent_ref.as_str().to_owned(),
                    domain: systemd_domain_name(req.domain).to_owned(),
                    action: "check-user-manager".to_owned(),
                    stopped: None,
                },
            )?;
            Ok(DispatchResult::no_fds(
                BrokerResponse::CheckSystemdUserManager(
                    d2b_contracts_broker::broker_wire::CheckSystemdUserManagerResponse {
                        vm_id: req.vm_id,
                        role_id: req.role_id,
                        available,
                    },
                ),
            ))
        }
        RealBrokerRequest::ObserveSystemdUnit(req) => {
            let resolver = require_resolver_ref(resolver.map(std::sync::Arc::as_ref))?;
            let identity = backend.observe_systemd_unit(resolver, &req)?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "ObserveSystemdUnit",
                req.role_id.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                req.vm_id.as_str(),
                req.role_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::SystemdUnit {
                    vm_id: req.vm_id.as_str().to_owned(),
                    role_id: req.role_id.as_str().to_owned(),
                    role: req.role.as_str().to_owned(),
                    bundle_runner_intent_ref: req.bundle_runner_intent_ref.as_str().to_owned(),
                    domain: systemd_domain_name(req.domain).to_owned(),
                    action: "observe".to_owned(),
                    stopped: None,
                },
            )?;
            Ok(DispatchResult::no_fds(BrokerResponse::ObserveSystemdUnit(
                d2b_contracts_broker::broker_wire::ObserveSystemdUnitResponse {
                    vm_id: req.vm_id,
                    role_id: req.role_id,
                    present: identity.is_some(),
                    identity,
                },
            )))
        }
        RealBrokerRequest::OpenSystemdUnitPidfd(req) => {
            let resolver = require_resolver_ref(resolver.map(std::sync::Arc::as_ref))?;
            let (identity, pidfd) = backend.reopen_systemd_unit(resolver, &req)?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "OpenSystemdUnitPidfd",
                req.unit.role_id.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                req.unit.vm_id.as_str(),
                req.unit.role_id.as_str(),
                tracing_span_id_str(req.unit.tracing_span_id.as_ref()),
                OperationFields::SystemdUnit {
                    vm_id: req.unit.vm_id.as_str().to_owned(),
                    role_id: req.unit.role_id.as_str().to_owned(),
                    role: req.unit.role.as_str().to_owned(),
                    bundle_runner_intent_ref: req.unit.bundle_runner_intent_ref.as_str().to_owned(),
                    domain: systemd_domain_name(req.unit.domain).to_owned(),
                    action: "reopen".to_owned(),
                    stopped: None,
                },
            )?;
            Ok(DispatchResult::with_fd(
                BrokerResponse::OpenSystemdUnitPidfd(
                    d2b_contracts_broker::broker_wire::OpenSystemdUnitPidfdResponse {
                        vm_id: req.unit.vm_id,
                        role_id: req.unit.role_id,
                        identity,
                        pidfd_index: 0,
                    },
                ),
                pidfd,
            ))
        }
        RealBrokerRequest::StopSystemdUnit(req) => {
            let resolver = require_resolver_ref(resolver.map(std::sync::Arc::as_ref))?;
            backend.stop_systemd_unit(resolver, &req)?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "StopSystemdUnit",
                req.unit.role_id.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                req.unit.vm_id.as_str(),
                req.unit.role_id.as_str(),
                tracing_span_id_str(req.unit.tracing_span_id.as_ref()),
                OperationFields::SystemdUnit {
                    vm_id: req.unit.vm_id.as_str().to_owned(),
                    role_id: req.unit.role_id.as_str().to_owned(),
                    role: req.unit.role.as_str().to_owned(),
                    bundle_runner_intent_ref: req.unit.bundle_runner_intent_ref.as_str().to_owned(),
                    domain: systemd_domain_name(req.unit.domain).to_owned(),
                    action: "stop".to_owned(),
                    stopped: Some(true),
                },
            )?;
            Ok(DispatchResult::no_fds(BrokerResponse::StopSystemdUnit(
                d2b_contracts_broker::broker_wire::StopSystemdUnitResponse {
                    vm_id: req.unit.vm_id,
                    role_id: req.unit.role_id,
                    stopped: true,
                },
            )))
        }
        RealBrokerRequest::OpenZoneStore(req) => {
            // OpenZoneStore resolves one signed storage-row id and returns
            // exactly one owned database descriptor. The row and all path
            // components remain broker-local.
            let resolver = require_resolver_ref(resolver.map(std::sync::Arc::as_ref))?;
            let outcome = crate::live_handlers::live_open_zone_store(resolver, &req.zone_store_id)
                .map_err(|err| BrokerError::LiveHandler(err.to_string()))?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "OpenZoneStore",
                req.zone_store_id.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                "zone-store",
                req.zone_store_id.as_str(),
                None,
                OperationFields::OpenZoneStore {
                    zone_store_id: req.zone_store_id.as_str().to_owned(),
                    store_identity: outcome.response.store_identity.clone(),
                    disposition: outcome.response.disposition.as_str().to_owned(),
                    fd_count: 1,
                },
            )?;
            Ok(DispatchResult::with_fd(
                BrokerResponse::OpenZoneStore(outcome.response),
                outcome.database_fd,
            ))
        }
        RealBrokerRequest::CgroupKill(req) => {
            let resolver = require_resolver(resolver)?;
            crate::ops::cgroup::live_kill_runner_cgroup(resolver, &req)
                .map_err(|err| BrokerError::LiveHandler(err.to_string()))?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "CgroupKill",
                &format!("{}:{}", req.vm_id.as_str(), req.role_id.as_str()),
                caller_uid,
                caller_gid,
                &caller_role,
                req.vm_id.as_str(),
                req.role_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::CgroupKill {
                    vm_id: req.vm_id.as_str().to_owned(),
                    role_id: req.role_id.as_str().to_owned(),
                },
            )?;
            Ok(DispatchResult::no_fds(ack_response("CgroupKill")))
        }
        RealBrokerRequest::SignalRunner(req) => {
            // Boundary note: d2bd owns operator authz classification; the
            // broker admits only the daemon UID and records the forwarded
            // caller role for audit. Runtime safety for runner control is
            // constrained by the broker-owned pidfd registry: only registered
            // runner_ids can be signaled, with unknown ids rejected as NoPidfd
            // by the backend.
            let runner_id = runner_registry_key(
                req.vm_id.as_str(),
                req.role_id.as_str(),
                req.resource_ref.as_ref(),
                req.resource_uid.as_ref(),
                req.zone_uid.as_ref(),
                req.runtime_scope,
            );
            let registration = runner_metadata_registry()
                .lock()
                .map_err(|_| {
                    BrokerError::Protocol("runner metadata registry mutex poisoned".to_owned())
                })?
                .get(&runner_id)
                .cloned();
            let typed_process = req.resource_ref.is_some()
                || req.resource_uid.is_some()
                || req.zone_uid.is_some()
                || req.runtime_scope.is_some();
            if !typed_control_identity_complete(
                req.resource_ref.as_ref(),
                req.resource_uid.as_ref(),
                req.zone_uid.as_ref(),
                req.generation,
                req.runtime_scope,
                req.provider_ref.as_ref(),
                req.provider_identity,
                req.template_identity,
            ) {
                return Err(BrokerError::NoPidfd { runner_id });
            }
            if typed_process && registration.is_none() {
                return Err(BrokerError::NoPidfd { runner_id });
            }
            if let Some(registration) = registration
                && (registration.vm_id != req.vm_id.as_str()
                    || registration.role_id != req.role_id.as_str()
                    || !registration_matches(
                        &registration,
                        req.resource_ref.as_ref(),
                        req.resource_uid.as_ref(),
                        req.pid,
                        req.expected_start_time_ticks,
                        req.zone_uid.as_ref(),
                        req.generation,
                        req.runtime_scope,
                        req.owner_ref.as_ref(),
                        req.provider_ref.as_ref(),
                        req.provider_identity,
                        req.template_identity,
                        req.guest_execution.as_ref(),
                    ))
            {
                return Err(BrokerError::NoPidfd { runner_id });
            }
            match backend.signal_runner(runner_id.as_str(), req.signal) {
                Ok(()) => {}
                Err(BrokerError::NoPidfd { .. }) => {
                    let (Some(pid), Some(expected_start_time_ticks)) =
                        (req.pid, req.expected_start_time_ticks)
                    else {
                        return Err(BrokerError::NoPidfd {
                            runner_id: runner_id.clone(),
                        });
                    };
                    backend.open_pidfd(runner_id.as_str(), pid, expected_start_time_ticks)?;
                    backend.signal_runner(runner_id.as_str(), req.signal)?;
                }
                Err(err) => return Err(err),
            }
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "SignalRunner",
                runner_id.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                req.vm_id.as_str(),
                req.role_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::SignalRunner {
                    vm_id: req.vm_id.as_str().to_owned(),
                    role_id: req.role_id.as_str().to_owned(),
                    signal: runner_signal_name(req.signal).to_owned(),
                },
            )?;
            Ok(DispatchResult::no_fds(BrokerResponse::SignalRunner(
                d2b_contracts_broker::broker_wire::SignalRunnerResponse {
                    signaled: true,
                    vm_id: req.vm_id,
                    role_id: req.role_id,
                },
            )))
        }
        RealBrokerRequest::DeregisterRunnerPidfd(req) => {
            // Boundary note: d2bd owns operator authz classification; the
            // broker admits only the daemon UID and records the forwarded
            // caller role for audit. Runtime safety for runner control is
            // constrained by the broker-owned pidfd registry: only registered
            // runner_ids can be deregistered. The is_some() shape below
            // intentionally returns `removed: false` for unknown ids,
            // preserving idempotent cleanup without widening the registry
            // surface.
            let runner_id = runner_registry_key(
                req.vm_id.as_str(),
                req.role_id.as_str(),
                req.resource_ref.as_ref(),
                req.resource_uid.as_ref(),
                req.zone_uid.as_ref(),
                req.runtime_scope,
            );
            if !typed_control_identity_complete(
                req.resource_ref.as_ref(),
                req.resource_uid.as_ref(),
                req.zone_uid.as_ref(),
                req.generation,
                req.runtime_scope,
                req.provider_ref.as_ref(),
                req.provider_identity,
                req.template_identity,
            ) {
                return Err(BrokerError::NoPidfd {
                    runner_id: runner_id.clone(),
                });
            }
            let removed = runner_pidfd_registry()
                .lock()
                .map_err(|_| {
                    BrokerError::Protocol("runner pidfd registry mutex poisoned".to_owned())
                })?
                .get(&runner_id)
                .is_some_and(|_| {
                    runner_metadata_registry()
                        .lock()
                        .ok()
                        .and_then(|registry| registry.get(&runner_id).cloned())
                        .is_some_and(|registration| {
                            registration.vm_id == req.vm_id.as_str()
                                && registration.role_id == req.role_id.as_str()
                                && registration_matches(
                                    &registration,
                                    req.resource_ref.as_ref(),
                                    req.resource_uid.as_ref(),
                                    req.pid,
                                    req.expected_start_time_ticks,
                                    req.zone_uid.as_ref(),
                                    req.generation,
                                    req.runtime_scope,
                                    req.owner_ref.as_ref(),
                                    req.provider_ref.as_ref(),
                                    req.provider_identity,
                                    req.template_identity,
                                    req.guest_execution.as_ref(),
                                )
                        })
                });
            if removed {
                runner_pidfd_registry()
                    .lock()
                    .map_err(|_| {
                        BrokerError::Protocol("runner pidfd registry mutex poisoned".to_owned())
                    })?
                    .remove(&runner_id);
                remove_runner_metadata(&runner_id);
            }
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "DeregisterRunnerPidfd",
                runner_id.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                req.vm_id.as_str(),
                req.role_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::DeregisterRunnerPidfd {
                    vm_id: req.vm_id.as_str().to_owned(),
                    role_id: req.role_id.as_str().to_owned(),
                },
            )?;
            Ok(DispatchResult::no_fds(
                BrokerResponse::DeregisterRunnerPidfd(
                    d2b_contracts_broker::broker_wire::DeregisterRunnerPidfdResponse {
                        vm_id: req.vm_id,
                        role_id: req.role_id,
                        removed,
                    },
                ),
            ))
        }
        RealBrokerRequest::SpawnRunner(req) => {
            validate_spawn_runner_request_fds(req.role, req.inherited_fd_count, request_fds.len())?;
            let resolver = require_resolver(resolver)?;
            let intent = resolver
                .find_runner_intent(req.bundle_runner_intent_ref.as_str())
                .ok_or_else(|| BrokerError::BundleIntentMissing {
                    kind: "runner",
                    intent_id: req.bundle_runner_intent_ref.as_str().to_owned(),
                })?;
            if req.resource_ref.is_some() {
                let Some(bundle_content_identity) = req.bundle_content_identity.as_deref() else {
                    return Err(BrokerError::SpawnRunnerIntentMismatch {
                        field: "bundle_content_identity",
                        requested: "missing".to_owned(),
                        resolved: "required".to_owned(),
                    });
                };
                let resolved_bundle_content_identity =
                    resolver.bundle.bundle_hash.as_deref().ok_or_else(|| {
                        BrokerError::SpawnRunnerIntentMismatch {
                            field: "bundle_content_identity",
                            requested: bundle_content_identity.to_owned(),
                            resolved: "missing".to_owned(),
                        }
                    })?;
                if bundle_content_identity != resolved_bundle_content_identity {
                    return Err(BrokerError::SpawnRunnerIntentMismatch {
                        field: "bundle_content_identity",
                        requested: bundle_content_identity.to_owned(),
                        resolved: resolved_bundle_content_identity.to_owned(),
                    });
                }
            }
            if req.generation.is_some_and(|generation| generation == 0) {
                return Err(BrokerError::SpawnRunnerIntentMismatch {
                    field: "generation",
                    requested: "0".to_owned(),
                    resolved: "nonzero".to_owned(),
                });
            }
            match (&req.activation_input, req.role) {
                (Some(input), RunnerRole::ActivationNixos) => {
                    if input.target_generation == 0 {
                        return Err(BrokerError::SpawnRunnerIntentMismatch {
                            field: "activation_input.target_generation",
                            requested: "0".to_owned(),
                            resolved: "nonzero".to_owned(),
                        });
                    }
                    let Some(_generation) = req.generation else {
                        return Err(BrokerError::SpawnRunnerIntentMismatch {
                            field: "generation",
                            requested: "missing".to_owned(),
                            resolved: "required-for-activation-input".to_owned(),
                        });
                    };
                    let encoded = serde_json::to_vec(input).map_err(|_| {
                        BrokerError::SpawnRunnerIntentMismatch {
                            field: "activation_input",
                            requested: "unserializable".to_owned(),
                            resolved: "bounded-json".to_owned(),
                        }
                    })?;
                    if encoded.len() > d2b_contracts_resource::v3::MAX_ACTIVATION_RUNNER_INPUT_BYTES
                    {
                        return Err(BrokerError::SpawnRunnerIntentMismatch {
                            field: "activation_input",
                            requested: encoded.len().to_string(),
                            resolved: d2b_contracts_resource::v3::MAX_ACTIVATION_RUNNER_INPUT_BYTES
                                .to_string(),
                        });
                    }
                }
                (Some(_), _) => {
                    return Err(BrokerError::SpawnRunnerIntentMismatch {
                        field: "activation_input",
                        requested: "present".to_owned(),
                        resolved: "activation-nixos-role-only".to_owned(),
                    });
                }
                (None, RunnerRole::ActivationNixos) => {
                    return Err(BrokerError::SpawnRunnerIntentMismatch {
                        field: "activation_input",
                        requested: "missing".to_owned(),
                        resolved: "required-for-activation-nixos".to_owned(),
                    });
                }
                (None, _) => {}
            }
            if req.resource_ref.is_some()
                && (req.execution_ref.is_none()
                    || req.execution_domain.is_none()
                    || req.resource_uid.is_none()
                    || req
                        .provider_identity
                        .is_none_or(|identity| identity == [0; 32])
                    || req
                        .template_identity
                        .is_none_or(|identity| identity == [0; 32])
                    || req.generation.is_none())
            {
                return Err(BrokerError::SpawnRunnerIntentMismatch {
                    field: "process_identity",
                    requested: "incomplete".to_owned(),
                    resolved: "resource/provider/template/generation-required".to_owned(),
                });
            }
            if let Err(err) = resolver.validate_minijail_profiles() {
                write_decision_op_record!(
                    audit_log,
                    bundle_metadata,
                    "SpawnRunner",
                    req.bundle_runner_intent_ref.as_str(),
                    caller_uid,
                    caller_gid,
                    &caller_role,
                    req.vm_id.as_str(),
                    req.role_id.as_str(),
                    tracing_span_id_str(req.tracing_span_id.as_ref()),
                    "denied-refused",
                    Some("minijail-validation"),
                    OperationFields::SpawnRunner {
                        bundle_runner_intent_ref: req.bundle_runner_intent_ref.as_str().to_owned(),
                        vm_id: req.vm_id.as_str().to_owned(),
                        role_id: req.role_id.as_str().to_owned(),
                        role: req.role.as_str().to_owned(),
                        runtime_allocations: req.runtime_allocations.clone(),
                    },
                )?;
                return Err(BrokerError::MinijailValidation {
                    reason: err.to_string(),
                });
            }
            validate_spawn_runner_request_matches_intent(&req, intent)?;
            let typed_process = req.resource_ref.is_some();
            let cgroup_placement = private_cgroup_placement(
                &intent.cgroup_placement,
                req.vm_id.as_str(),
                req.runtime_scope,
                typed_process,
            )?;
            // Legacy VM DAG launches carry the trusted bundle profile but no
            // generic Process sandbox DTO. When a typed DTO is present, bind
            // it to that same profile; otherwise the trusted intent remains
            // the authoritative sandbox source.
            if let Some(plan) = &req.sandbox_plan {
                validate_sandbox_launch_plan(&req, intent, plan)?;
            }
            // When the daemon asks the broker to spawn the OtelHostBridge
            // runner (the replacement for the singleton
            // `d2b-otel-host-bridge.service`), the bundle-resolved
            // intent's vm_name MUST equal the obs VM declared in
            // manifest._observability.vmName. Any other target would let
            // a tampered or out-of-date bundle redirect host OTLP egress
            // at an arbitrary VM; refuse fail-closed and surface a typed
            // error envelope.
            if matches!(
                req.role,
                d2b_contracts_broker::broker_wire::RunnerRole::OtelHostBridge
            ) && intent.vm_name != resolver.manifest.observability.vm_name
            {
                let expected_obs_vm = resolver.manifest.observability.vm_name.clone();
                let intent_vm = intent.vm_name.clone();
                write_decision_op_record!(
                    audit_log,
                    bundle_metadata,
                    "SpawnRunner",
                    req.bundle_runner_intent_ref.as_str(),
                    caller_uid,
                    caller_gid,
                    &caller_role,
                    req.vm_id.as_str(),
                    req.role_id.as_str(),
                    tracing_span_id_str(req.tracing_span_id.as_ref()),
                    "denied-refused",
                    Some("otel-host-bridge-intent-invalid"),
                    OperationFields::SpawnRunner {
                        bundle_runner_intent_ref: req.bundle_runner_intent_ref.as_str().to_owned(),
                        vm_id: req.vm_id.as_str().to_owned(),
                        role_id: req.role_id.as_str().to_owned(),
                        role: req.role.as_str().to_owned(),
                        runtime_allocations: req.runtime_allocations.clone(),
                    },
                )?;
                return Err(BrokerError::OtelHostBridgeIntentInvalid {
                    intent_vm,
                    expected_obs_vm,
                });
            }
            apply_vm_start_prerequisites(
                backend,
                resolver,
                req.vm_id.as_str(),
                req.role_id.as_str(),
            )?;
            // The bundle resolver is the sole authority for trusted runner
            // argv. Provider-specific planning stays behind the composition
            // root and is never regenerated by this privileged adapter.
            let mut mount_policy = intent.mount_policy.clone();
            extend_usbip_backend_device_binds(
                resolver,
                req.vm_id.as_str(),
                req.role_id.as_str(),
                &req.role,
                &mut mount_policy,
            )?;
            let mut env = intent.env.clone();
            extend_audio_runner_pipewire_props(
                req.vm_id.as_str(),
                req.role_id.as_str(),
                &req.role,
                &mut env,
            )?;
            cleanup_cloud_hypervisor_stale_sockets(&req.role, &intent.argv)?;
            cleanup_video_stale_socket(&req.role, &intent.argv)?;
            cleanup_otel_host_bridge_stale_socket(&req.role, &intent.argv)?;
            let argv =
                bind_cloud_hypervisor_guest_uid(req.role, req.owner_uid.as_ref(), &intent.argv)?;
            let plan_input = crate::ops::spawn_runner::SpawnRunnerPlanInput {
                binary_path: intent.binary_path.clone(),
                argv,
                uid: intent.uid,
                gid: intent.gid,
                supplementary_groups: intent.supplementary_groups.clone(),
                env,
                capabilities: intent.capabilities.clone(),
                namespaces: intent.namespaces.clone(),
                seccomp_policy_ref: intent.seccomp_policy_ref.clone(),
                mount_policy,
                cgroup_placement,
                root_carve_out: intent.root_carve_out,
                skip_binary_exists_check: false,
                // Thread through the user-namespace spec from the
                // resolved intent (ADR 0021).
                user_namespace: intent.user_namespace.map(|spec| {
                    crate::ops::spawn_runner::UserNamespaceSpec {
                        host_uid_for_zero: spec.host_uid_for_zero,
                        host_gid_for_zero: spec.host_gid_for_zero,
                    }
                }),
                umask: intent.umask,
            };
            let runner_id = runner_registry_key(
                req.vm_id.as_str(),
                req.role_id.as_str(),
                req.resource_ref.as_ref(),
                req.resource_uid.as_ref(),
                req.zone_uid.as_ref(),
                req.runtime_scope,
            );
            let outcome = match backend.spawn_runner(
                runner_id.as_str(),
                &plan_input,
                resolver,
                &req,
                std::mem::take(&mut request_fds),
                audit_log,
            ) {
                Ok(outcome) => outcome,
                // swtpm-dir hardening fail-closed: emit the terminal
                // path-free PrepareSwtpmDir record here (exactly once),
                // then surface the closed-set reason on the wire. The
                // SpawnRunner success record is NOT written because the
                // runner was never spawned.
                Err(BrokerError::SwtpmDirHardening { audit, reason }) => {
                    write_decision_op_record!(
                        audit_log,
                        bundle_metadata,
                        "PrepareSwtpmDir",
                        req.bundle_runner_intent_ref.as_str(),
                        caller_uid,
                        caller_gid,
                        &caller_role,
                        req.vm_id.as_str(),
                        req.role_id.as_str(),
                        tracing_span_id_str(req.tracing_span_id.as_ref()),
                        "denied-refused",
                        Some(reason),
                        OperationFields::PrepareSwtpmDir(audit.clone()),
                    )?;
                    return Err(BrokerError::SwtpmDirHardening { audit, reason });
                }
                Err(other) => return Err(other),
            };
            if let Err(error) = register_runner_metadata(
                runner_id.as_str(),
                &req,
                intent,
                outcome.pid,
                outcome.start_time_ticks,
            ) {
                cleanup_spawned_runner_after_failure(runner_id.as_str(), outcome.pidfd.as_fd());
                return Err(error);
            }
            // On the success path, emit the terminal PrepareSwtpmDir
            // record (for the w1-swtpm role only) BEFORE the SpawnRunner
            // record so an operator sees the hardening disposition that
            // gated the spawn.
            if let Some(swtpm_audit) = &outcome.swtpm_dir_audit
                && let Err(error) = write_success_op_record!(
                    audit_log,
                    bundle_metadata,
                    "PrepareSwtpmDir",
                    req.bundle_runner_intent_ref.as_str(),
                    caller_uid,
                    caller_gid,
                    &caller_role,
                    req.vm_id.as_str(),
                    req.role_id.as_str(),
                    tracing_span_id_str(req.tracing_span_id.as_ref()),
                    OperationFields::PrepareSwtpmDir(swtpm_audit.clone()),
                )
            {
                cleanup_spawned_runner_after_failure(runner_id.as_str(), outcome.pidfd.as_fd());
                return Err(error);
            }
            if let Err(error) = write_success_op_record!(
                audit_log,
                bundle_metadata,
                "SpawnRunner",
                req.bundle_runner_intent_ref.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                req.vm_id.as_str(),
                req.role_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::SpawnRunner {
                    bundle_runner_intent_ref: req.bundle_runner_intent_ref.as_str().to_owned(),
                    vm_id: req.vm_id.as_str().to_owned(),
                    role_id: req.role_id.as_str().to_owned(),
                    role: req.role.as_str().to_owned(),
                    runtime_allocations: req.runtime_allocations.clone(),
                },
            ) {
                cleanup_spawned_runner_after_failure(runner_id.as_str(), outcome.pidfd.as_fd());
                return Err(error);
            }
            let controller_bootstrap_fd_index =
                (req.role == RunnerRole::ProviderController).then_some(1);
            let console_fd_index = if outcome.extra_response_fds.is_empty()
                || req.role == RunnerRole::ProviderController
            {
                None
            } else {
                Some(1)
            };
            let response = BrokerResponse::SpawnRunner(
                d2b_contracts_broker::broker_wire::SpawnRunnerResponse {
                    vm_id: req.vm_id.clone(),
                    role_id: req.role_id.clone(),
                    role: req.role,
                    resource_ref: req.resource_ref.clone(),
                    resource_uid: req.resource_uid.clone(),
                    zone_uid: req.zone_uid.clone(),
                    owner_ref: req.owner_ref.clone(),
                    runtime_scope: req.runtime_scope,
                    execution_ref: req.execution_ref.clone(),
                    execution_domain: req.execution_domain,
                    user_ref: req.user_ref.clone(),
                    guest_execution: req.guest_execution.clone(),
                    provider_identity: req.provider_identity,
                    template_identity: req.template_identity,
                    generation: req.generation,
                    bundle_content_identity: req.bundle_content_identity.clone(),
                    pid: outcome.pid,
                    start_time_ticks: outcome.start_time_ticks,
                    pidfd_index: 0,
                    controller_bootstrap_fd_index,
                    console_fd_index,
                },
            );
            let _ = intent_id_legacy_runner;
            let mut response_fds = Vec::with_capacity(1 + outcome.extra_response_fds.len());
            response_fds.push(outcome.pidfd);
            response_fds.extend(outcome.extra_response_fds);
            Ok(DispatchResult::with_fds(response, response_fds))
        }
        RealBrokerRequest::ApplyNftablesProjection(req) => {
            let resolver = require_resolver(resolver)?;
            let provenance = network_provenance(
                req.zone_uid.clone(),
                req.network_uid.clone(),
                req.network_generation,
                req.attachment_generation,
                req.expected_generation_id.clone(),
            );
            let intent = resolver
                .resolve_network_projection_intent(
                    req.bundle_nft_projection_intent_ref.as_str(),
                    &provenance,
                )
                .ok_or_else(|| BrokerError::BundleIntentMissing {
                    kind: "nft-projection",
                    intent_id: req.bundle_nft_projection_intent_ref.as_str().to_owned(),
                })?;
            let marker = resolver
                .resolve_network_marker_intent(&intent.ownership_marker_intent_ref, &provenance)
                .ok_or_else(|| BrokerError::BundleIntentMissing {
                    kind: "nft-ownership-marker",
                    intent_id: intent.ownership_marker_intent_ref.clone(),
                })?;
            let expected_marker = d2b_contracts_resource::v3::derive_network_ownership_marker(
                &provenance,
                "firewall",
            );
            if intent.provenance.as_ref() != Some(&provenance)
                || marker.provenance.as_ref() != Some(&provenance)
                || marker.marker != expected_marker
            {
                return Err(BrokerError::RequestValidation {
                    operation: "ApplyNftablesProjection",
                    reason: "network-admission-mismatch",
                });
            }
            let installed =
                resolver
                    .installed_generation_identity()
                    .ok_or(BrokerError::RequestValidation {
                        operation: "ApplyNftablesProjection",
                        reason: "installed-generation-unavailable",
                    })?;
            require_installed_network_generation(resolver, &provenance)?;
            let exec = crate::ops::exec_reconcile::SystemReconcileExecutor;
            let projection_digest = crate::ops::nft::apply_nftables_projection(
                &exec,
                &nft_binary_path(),
                &intent.script_body,
                &marker.marker,
                &intent.desired_hash,
                req.desired_hash.as_deref(),
                req.expected_generation_id.as_str(),
                installed.as_str(),
                req.action,
            )
            .map(|result| result.projection_digest)
            .map_err(|error| BrokerError::RequestValidation {
                operation: "ApplyNftablesProjection",
                reason: error.code(),
            })?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "ApplyNftablesProjection",
                req.bundle_nft_projection_intent_ref.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                intent.scope_label.as_str(),
                req.scope_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::ApplyNftablesProjection {
                    projection_digest,
                    expected_generation_id: req.expected_generation_id,
                    action: req.action,
                },
            )?;
            Ok(DispatchResult::no_fds(ack_response(
                "ApplyNftablesProjection",
            )))
        }
        RealBrokerRequest::CreateBridge(req) => {
            let resolver = require_resolver(resolver)?;
            let provenance = network_provenance(
                req.zone_uid.clone(),
                req.network_uid.clone(),
                req.network_generation,
                req.attachment_generation,
                req.bundle_generation.clone(),
            );
            let intent = resolver
                .resolve_network_bridge_intent(req.bundle_bridge_intent_ref.as_str(), &provenance)
                .ok_or_else(|| BrokerError::BundleIntentMissing {
                    kind: "bridge",
                    intent_id: req.bundle_bridge_intent_ref.as_str().to_owned(),
                })?;
            if intent.provenance.as_ref() != Some(&provenance) {
                return Err(BrokerError::RequestValidation {
                    operation: "CreateBridge",
                    reason: "network-admission-mismatch",
                });
            }
            require_installed_network_generation(resolver, &provenance)?;
            let bridge_intent_digest = crate::ops::network::create_bridge(
                &crate::ops::network::SystemBridgeBackend,
                &intent,
            )
            .map_err(|error| BrokerError::RequestValidation {
                operation: "CreateBridge",
                reason: error.code(),
            })?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "CreateBridge",
                req.bundle_bridge_intent_ref.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                intent.scope_label.as_str(),
                req.scope_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::CreateBridge {
                    bridge_intent_digest,
                },
            )?;
            Ok(DispatchResult::no_fds(ack_response("CreateBridge")))
        }
        RealBrokerRequest::DeleteBridge(req) => {
            let resolver = require_resolver(resolver)?;
            let provenance = network_provenance(
                req.zone_uid.clone(),
                req.network_uid.clone(),
                req.network_generation,
                req.attachment_generation,
                req.bundle_generation.clone(),
            );
            let intent = resolver
                .resolve_network_bridge_intent(req.bundle_bridge_intent_ref.as_str(), &provenance)
                .ok_or_else(|| BrokerError::BundleIntentMissing {
                    kind: "bridge",
                    intent_id: req.bundle_bridge_intent_ref.as_str().to_owned(),
                })?;
            if intent.provenance.as_ref() != Some(&provenance) {
                return Err(BrokerError::RequestValidation {
                    operation: "DeleteBridge",
                    reason: "network-admission-mismatch",
                });
            }
            require_installed_network_generation(resolver, &provenance)?;
            let bridge_intent_digest = crate::ops::network::delete_bridge(
                &crate::ops::network::SystemBridgeBackend,
                &intent,
            )
            .map_err(|error| BrokerError::RequestValidation {
                operation: "DeleteBridge",
                reason: error.code(),
            })?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "DeleteBridge",
                req.bundle_bridge_intent_ref.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                intent.scope_label.as_str(),
                req.scope_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::DeleteBridge {
                    bridge_intent_digest,
                },
            )?;
            Ok(DispatchResult::no_fds(ack_response("DeleteBridge")))
        }
        RealBrokerRequest::DeletePersistentTap(req) => {
            let resolver = require_resolver(resolver)?;
            let installed =
                resolver
                    .installed_generation_identity()
                    .ok_or(BrokerError::RequestValidation {
                        operation: "DeletePersistentTap",
                        reason: "installed-generation-unavailable",
                    })?;
            if installed.as_str() != req.expected_bundle_generation.as_str() {
                return Err(BrokerError::RequestValidation {
                    operation: "DeletePersistentTap",
                    reason: "stale-projection-generation",
                });
            }
            let realization =
                crate::ops::network::load_persistent_tap_realization(&config.state_dir, &req)
                    .map_err(|error| BrokerError::RequestValidation {
                        operation: "DeletePersistentTap",
                        reason: error.code(),
                    })?;
            let attachment_digest = crate::ops::network::delete_persistent_tap(
                &crate::ops::network::SystemPersistentTapBackend,
                &realization,
                &req,
            )
            .map_err(|error| BrokerError::RequestValidation {
                operation: "DeletePersistentTap",
                reason: error.code(),
            })?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "DeletePersistentTap",
                &attachment_digest,
                caller_uid,
                caller_gid,
                &caller_role,
                "network-attachment",
                "attachment",
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::DeletePersistentTap {
                    attachment_digest: attachment_digest.clone(),
                    expected_network_generation: req.expected_network_generation,
                    expected_attachment_generation: req.expected_attachment_generation,
                },
            )?;
            crate::ops::network::mark_persistent_tap_realization_deleted(
                &config.state_dir,
                &req.attachment_id,
            )
            .map_err(|error| BrokerError::RequestValidation {
                operation: "DeletePersistentTap",
                reason: error.code(),
            })?;
            Ok(DispatchResult::no_fds(ack_response("DeletePersistentTap")))
        }
        RealBrokerRequest::BindUnixSocket(_) => Err(BrokerError::Unimplemented {
            operation: "BindUnixSocket",
            target_wave: "W5",
        }),
        RealBrokerRequest::CreateOrReconcileUsersGroups(_) => Err(BrokerError::Unimplemented {
            operation: "CreateOrReconcileUsersGroups",
            target_wave: "W3",
        }),
        RealBrokerRequest::CreatePersistentTap(req) => {
            let resolver = require_resolver(resolver)?;
            let exec = live_exec(config);
            let outcome =
                match crate::ops::tap::live_create_persistent_tap(&exec, resolver, &req, audit_log)
                {
                    Ok(outcome) => outcome,
                    Err(error) => return Err(BrokerError::LiveHandler(error.to_string())),
                };
            if let Err(error) = crate::ops::network::persist_persistent_tap_realization(
                &config.state_dir,
                &req,
                &outcome.tap_ifname,
            ) {
                if let Err(cleanup) = crate::ops::network::PersistentTapBackend::delete_tap(
                    &crate::ops::network::SystemPersistentTapBackend,
                    outcome.tap_ifname.as_str(),
                ) {
                    return Err(BrokerError::RequestValidation {
                        operation: "CreatePersistentTap",
                        reason: cleanup.code(),
                    });
                }
                if let Err(cleanup) = crate::ops::network::remove_persistent_tap_realization(
                    &config.state_dir,
                    &req.attachment_id,
                ) {
                    return Err(BrokerError::RequestValidation {
                        operation: "CreatePersistentTap",
                        reason: cleanup.code(),
                    });
                }
                return Err(BrokerError::RequestValidation {
                    operation: "CreatePersistentTap",
                    reason: error.code(),
                });
            }
            let public_operation_id = format!("{}:{}", req.vm_id.as_str(), req.role_id.as_str());
            let bridge_ifname = outcome
                .bridge_ifname
                .as_ref()
                .map(|ifname| ifname.as_str().to_owned());
            let tap_ifname = outcome.tap_ifname.as_str().to_owned();
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "CreatePersistentTap",
                &public_operation_id,
                caller_uid,
                caller_gid,
                &caller_role,
                req.vm_id.as_str(),
                req.role_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::CreatePersistentTap {
                    vm_id: req.vm_id.as_str().to_owned(),
                    role_id: req.role_id.as_str().to_owned(),
                    tap_ifname,
                    bridge_ifname,
                },
            )?;
            let response = BrokerResponse::CreatePersistentTap(
                d2b_contracts_broker::broker_wire::TapReadyResponse {
                    bridge: outcome.bridge_ifname,
                    tap: outcome.tap_ifname,
                },
            );
            Ok(DispatchResult::no_fds(response))
        }
        RealBrokerRequest::CreateTapFd(req) => {
            let resolver = require_resolver(resolver)?;
            let exec = live_exec(config);
            let outcome = crate::ops::tap::live_create_tap_fd(&exec, resolver, &req, audit_log)
                .map_err(|err| BrokerError::LiveHandler(err.to_string()))?;
            let fd = outcome.fd.ok_or_else(|| {
                BrokerError::LiveHandler("CreateTapFd produced no tap fd".to_owned())
            })?;
            let public_operation_id = format!("{}:{}", req.vm_id.as_str(), req.role_id.as_str());
            let bridge_ifname = outcome
                .bridge_ifname
                .as_ref()
                .map(|ifname| ifname.as_str().to_owned());
            let tap_ifname = outcome.tap_ifname.as_str().to_owned();
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "CreateTapFd",
                &public_operation_id,
                caller_uid,
                caller_gid,
                &caller_role,
                req.vm_id.as_str(),
                req.role_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::CreateTapFd {
                    vm_id: req.vm_id.as_str().to_owned(),
                    role_id: req.role_id.as_str().to_owned(),
                    tap_ifname,
                    bridge_ifname,
                },
            )?;
            let response =
                BrokerResponse::CreateTapFd(d2b_contracts_broker::broker_wire::TapReadyResponse {
                    bridge: outcome.bridge_ifname,
                    tap: outcome.tap_ifname,
                });
            Ok(DispatchResult::with_fd(response, fd))
        }
        RealBrokerRequest::DelegateCgroupV2(req) => {
            let resolver = require_resolver(resolver)?;
            let exec = live_exec(config);
            crate::ops::cgroup::live_delegate_cgroup_v2(&exec, resolver, &req, audit_log)
                .map_err(|err| BrokerError::LiveHandler(err.to_string()))?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "DelegateCgroupV2",
                req.scope_id.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                req.scope_id.as_str(),
                req.scope_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::DelegateCgroupV2 {
                    scope_id: req.scope_id.as_str().to_owned(),
                },
            )?;
            Ok(DispatchResult::no_fds(ack_response("DelegateCgroupV2")))
        }
        RealBrokerRequest::InjectSecretById(_) => Err(BrokerError::Unimplemented {
            operation: "InjectSecretById",
            target_wave: "W8",
        }),
        RealBrokerRequest::LaunchMinijailChild(_) => Err(BrokerError::Unimplemented {
            operation: "LaunchMinijailChild",
            target_wave: "W5",
        }),
        RealBrokerRequest::ModprobeIfAllowed(req) => {
            let resolver = require_resolver(resolver)?;
            let exec = live_exec(config);
            let outcome =
                crate::ops::modprobe::live_modprobe_if_allowed(&exec, resolver, &req, audit_log)
                    .map_err(BrokerError::LiveHandler)?;
            let disposition = serde_json::to_value(outcome.disposition)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_else(|| "unknown".to_owned());
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "ModprobeIfAllowed",
                req.module_name.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                req.module_name.as_str(),
                "host",
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::ModprobeIfAllowed {
                    module_name: outcome.module_name,
                    matrix_entry_id: outcome.matrix_entry_id,
                    modules_disabled_sysctl: outcome.modules_disabled_sysctl,
                    disposition,
                },
            )?;
            Ok(DispatchResult::no_fds(ack_response("ModprobeIfAllowed")))
        }
        RealBrokerRequest::OpenCgroupDir(req) => {
            let resolver = require_resolver(resolver)?;
            let exec = live_exec(config);
            let outcome =
                crate::ops::cgroup::live_open_cgroup_dir(&exec, resolver, &req, audit_log)
                    .map_err(|err| BrokerError::LiveHandler(err.to_string()))?;
            let path_class = match req.path_class {
                d2b_contracts::types::PathClass::Runtime => "runtime",
                d2b_contracts::types::PathClass::Vm => "vm",
            };
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "OpenCgroupDir",
                req.scope_id.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                req.scope_id.as_str(),
                req.scope_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::OpenCgroupDir {
                    scope_id: req.scope_id.as_str().to_owned(),
                    path_class: path_class.to_owned(),
                    cgroup_path: outcome.cgroup_path.display().to_string(),
                },
            )?;
            Ok(DispatchResult::with_fd(
                ack_response("OpenCgroupDir"),
                outcome.fd,
            ))
        }
        RealBrokerRequest::OpenDevice(req) => {
            let resolver = require_resolver(resolver)?;
            let exec = live_exec(config);
            let outcome = crate::ops::device::live_open_device(&exec, resolver, &req, audit_log)
                .map_err(|err| BrokerError::LiveHandler(err.to_string()))?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "OpenDevice",
                req.role_id.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                req.role_id.as_str(),
                req.role_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::OpenDevice {
                    role_id: req.role_id.as_str().to_owned(),
                    device_class: outcome.device_class,
                    device_path: outcome.device_path.display().to_string(),
                    matrix_entry_id: outcome.matrix_entry_id,
                },
            )?;
            Ok(DispatchResult::with_fd(
                ack_response("OpenDevice"),
                outcome.fd,
            ))
        }
        RealBrokerRequest::OpenFuse(req) => {
            let resolver = require_resolver(resolver)?;
            let exec = live_exec(config);
            let outcome = crate::ops::device::live_open_fuse(&exec, resolver, &req, audit_log)
                .map_err(|err| BrokerError::LiveHandler(err.to_string()))?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "OpenFuse",
                req.role_id.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                req.role_id.as_str(),
                req.role_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::OpenFuse {
                    role_id: req.role_id.as_str().to_owned(),
                    device_class: outcome.device_class,
                    device_path: outcome.device_path.display().to_string(),
                    matrix_entry_id: outcome.matrix_entry_id,
                },
            )?;
            Ok(DispatchResult::with_fd(
                ack_response("OpenFuse"),
                outcome.fd,
            ))
        }
        RealBrokerRequest::OpenHidrawSecurityKey(req) => {
            let resolver = require_resolver(resolver)?;
            let outcome = crate::ops::security_key::live_open_hidraw_security_key(
                &req,
                &resolver.host.security_key_selectors,
                audit_log,
            )
            .map_err(|error| BrokerError::LiveHandler(error.to_string()))?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "OpenHidrawSecurityKey",
                req.vm_id.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                req.vm_id.as_str(),
                req.selector_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::OpenHidrawSecurityKey {
                    vm_id: req.vm_id.as_str().to_owned(),
                    selector_id: outcome.selector_label.clone(),
                    device_class: outcome.device_class.clone(),
                    resolved: true,
                },
            )?;
            Ok(DispatchResult::with_fd(
                BrokerResponse::OpenHidrawSecurityKey(
                    d2b_contracts_broker::broker_wire::OpenHidrawSecurityKeyResponse {
                        selector_resolved: outcome.selector_label,
                        device_class: outcome.device_class,
                    },
                ),
                outcome.fd,
            ))
        }
        RealBrokerRequest::SecurityKeyOpenDevice(_) => Err(BrokerError::Unimplemented {
            operation: "SecurityKeyOpenDevice",
            target_wave: "security-key-broker",
        }),
        RealBrokerRequest::SecurityKeyApplyUdevRules(_) => Err(BrokerError::Unimplemented {
            operation: "SecurityKeyApplyUdevRules",
            target_wave: "security-key-broker",
        }),
        RealBrokerRequest::OpenKvm(req) => {
            let resolver = require_resolver(resolver)?;
            let exec = live_exec(config);
            let outcome = crate::ops::device::live_open_kvm(&exec, resolver, &req, audit_log)
                .map_err(|err| BrokerError::LiveHandler(err.to_string()))?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "OpenKvm",
                req.role_id.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                req.role_id.as_str(),
                req.role_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::OpenKvm {
                    role_id: req.role_id.as_str().to_owned(),
                    device_class: outcome.device_class,
                    device_path: outcome.device_path.display().to_string(),
                    matrix_entry_id: outcome.matrix_entry_id,
                },
            )?;
            Ok(DispatchResult::with_fd(ack_response("OpenKvm"), outcome.fd))
        }
        RealBrokerRequest::QemuMediaEnroll(req) => {
            let resolver = require_resolver(resolver)?;
            let outcome = crate::ops::media::enroll(resolver, &req)
                .map_err(|err| BrokerError::LiveHandler(err.to_string()))?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "QemuMediaEnroll",
                req.media_ref.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                req.vm_id.as_str(),
                req.media_ref.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::QemuMediaEnroll {
                    vm_id: req.vm_id.as_str().to_owned(),
                    media_ref: req.media_ref.as_str().to_owned(),
                    read_only: outcome.response.read_only,
                    by_id_count: outcome.by_id_count,
                    udev_rule_written: outcome.response.udev_rule_written,
                    udev_reloaded: outcome.response.udev_reloaded,
                },
            )?;
            Ok(DispatchResult::no_fds(BrokerResponse::QemuMediaEnroll(
                outcome.response,
            )))
        }
        RealBrokerRequest::QemuMediaRefreshRegistry(req) => {
            let resolver = require_resolver(resolver)?;
            let outcome = crate::ops::media::refresh_registry(resolver)
                .map_err(|err| BrokerError::LiveHandler(err.to_string()))?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "QemuMediaRefreshRegistry",
                "qemu-media",
                caller_uid,
                caller_gid,
                &caller_role,
                "host",
                "qemu-media",
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::QemuMediaRefreshRegistry {
                    record_count: outcome.response.record_count,
                    redacted_index_written: outcome.response.redacted_index_written,
                    udev_rule_written: outcome.response.udev_rule_written,
                    udev_reloaded: outcome.response.udev_reloaded,
                },
            )?;
            Ok(DispatchResult::no_fds(
                BrokerResponse::QemuMediaRefreshRegistry(outcome.response),
            ))
        }
        RealBrokerRequest::QemuMediaBoot(req) => {
            let resolver = require_resolver(resolver)?;
            let outcome = crate::ops::media::boot(resolver, &req)
                .map_err(|err| BrokerError::LiveHandler(err.to_string()))?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "QemuMediaBoot",
                outcome.response.media_ref.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                outcome.response.vm_id.as_str(),
                outcome.response.media_ref.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::QemuMediaBoot {
                    vm_id: outcome.response.vm_id.as_str().to_owned(),
                    media_ref: outcome.response.media_ref.as_str().to_owned(),
                    slot: outcome.response.slot.clone(),
                    read_only: outcome.response.read_only,
                    registry_record_written: outcome.registry_record_written,
                    redacted_index_written: outcome.redacted_index_written,
                    udev_rule_written: outcome.udev_rule_written,
                    udev_reloaded: outcome.udev_reloaded,
                    qmp_commands: outcome.response.qmp_commands.clone(),
                },
            )?;
            Ok(DispatchResult::no_fds(BrokerResponse::QemuMediaBoot(
                outcome.response,
            )))
        }
        RealBrokerRequest::QemuMediaSystemPowerdown(req) => {
            let response = backend.qemu_media_system_powerdown(&req)?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "QemuMediaSystemPowerdown",
                response.vm_id.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                response.vm_id.as_str(),
                response.vm_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::QemuMediaSystemPowerdown {
                    vm_id: response.vm_id.as_str().to_owned(),
                    qmp_command: "system_powerdown".to_owned(),
                },
            )?;
            Ok(DispatchResult::no_fds(
                BrokerResponse::QemuMediaSystemPowerdown(response),
            ))
        }
        RealBrokerRequest::QemuMediaQueryStatus(req) => {
            let response = backend.qemu_media_query_status(&req)?;
            Ok(DispatchResult::no_fds(
                BrokerResponse::QemuMediaQueryStatus(response),
            ))
        }
        RealBrokerRequest::QemuMediaQuit(req) => {
            let response = backend.qemu_media_quit(&req)?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "QemuMediaQuit",
                response.vm_id.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                response.vm_id.as_str(),
                response.vm_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::QemuMediaQuit {
                    vm_id: response.vm_id.as_str().to_owned(),
                    qmp_command: "quit".to_owned(),
                },
            )?;
            Ok(DispatchResult::no_fds(BrokerResponse::QemuMediaQuit(
                response,
            )))
        }
        RealBrokerRequest::QemuMediaAttach(req) => {
            let resolver = require_resolver(resolver)?;
            let outcome = crate::ops::media::attach(resolver, &req)
                .map_err(|err| BrokerError::LiveHandler(err.to_string()))?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "QemuMediaAttach",
                outcome.response.media_ref.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                outcome.response.vm_id.as_str(),
                outcome.response.media_ref.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::QemuMediaAttach {
                    vm_id: outcome.response.vm_id.as_str().to_owned(),
                    media_ref: outcome.response.media_ref.as_str().to_owned(),
                    slot: outcome.response.slot.clone(),
                    read_only: outcome.response.read_only,
                    qmp_commands: outcome.response.qmp_commands.clone(),
                },
            )?;
            Ok(DispatchResult::no_fds(BrokerResponse::QemuMediaAttach(
                outcome.response,
            )))
        }
        RealBrokerRequest::QemuMediaDetach(req) => {
            let resolver = require_resolver(resolver)?;
            let outcome = crate::ops::media::detach(resolver, &req)
                .map_err(|err| BrokerError::LiveHandler(err.to_string()))?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "QemuMediaDetach",
                outcome.response.media_ref.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                outcome.response.vm_id.as_str(),
                outcome.response.media_ref.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::QemuMediaDetach {
                    vm_id: outcome.response.vm_id.as_str().to_owned(),
                    media_ref: outcome.response.media_ref.as_str().to_owned(),
                    slot: outcome.response.slot.clone(),
                    read_only: outcome.response.read_only,
                    qmp_commands: outcome.response.qmp_commands.clone(),
                },
            )?;
            Ok(DispatchResult::no_fds(BrokerResponse::QemuMediaDetach(
                outcome.response,
            )))
        }
        RealBrokerRequest::OpenVhostNet(req) => {
            let resolver = require_resolver(resolver)?;
            let exec = live_exec(config);
            let outcome = crate::ops::device::live_open_vhost_net(&exec, resolver, &req, audit_log)
                .map_err(|err| BrokerError::LiveHandler(err.to_string()))?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "OpenVhostNet",
                req.role_id.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                req.role_id.as_str(),
                req.role_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::OpenVhostNet {
                    role_id: req.role_id.as_str().to_owned(),
                    device_class: outcome.device_class,
                    device_path: outcome.device_path.display().to_string(),
                    matrix_entry_id: outcome.matrix_entry_id,
                },
            )?;
            Ok(DispatchResult::with_fd(
                ack_response("OpenVhostNet"),
                outcome.fd,
            ))
        }
        RealBrokerRequest::PauseBroker => Err(BrokerError::Unimplemented {
            operation: "PauseBroker",
            target_wave: "W4",
        }),
        RealBrokerRequest::PollChildReaped => {
            let notifications = drain_child_reap_buffer();
            audit_log
                .write_entry_with_caller_ids(
                    "PollChildReaped",
                    caller_uid,
                    caller_gid,
                    "allowed",
                    "pidfd-reap-buffer",
                    "success",
                )
                .map_err(|err| BrokerError::Protocol(err.to_string()))?;
            Ok(DispatchResult::no_fds(BrokerResponse::PollChildReaped(
                d2b_contracts_broker::broker_wire::PollChildReapedResponse { notifications },
            )))
        }
        RealBrokerRequest::PrepareRuntimeDir(req) => {
            let resolver = require_resolver(resolver)?;
            let intent = resolver
                .resolve_prepare_dir_intent(req.vm_id.as_str(), true)
                .ok_or_else(|| {
                    BrokerError::LiveHandler(format!(
                        "PrepareRuntimeDir: unknown subject {:?}",
                        req.vm_id.as_str()
                    ))
                })?;
            let exec = live_exec(config);
            crate::ops::state_dir::live_prepare_runtime_dir(&exec, resolver, &req, audit_log)
                .map_err(|err| BrokerError::LiveHandler(err.to_string()))?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "PrepareRuntimeDir",
                req.vm_id.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                req.vm_id.as_str(),
                req.vm_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::PrepareRuntimeDir {
                    vm_id: req.vm_id.as_str().to_owned(),
                    base_dir: intent.base_dir.display().to_string(),
                    owner_uid: intent.owner_uid,
                    owner_gid: intent.owner_gid,
                    mode: intent.mode,
                },
            )?;
            Ok(DispatchResult::no_fds(ack_response("PrepareRuntimeDir")))
        }
        RealBrokerRequest::PrepareStateDir(req) => {
            let resolver = require_resolver(resolver)?;
            let intent = resolver
                .resolve_prepare_dir_intent(req.vm_id.as_str(), false)
                .ok_or_else(|| {
                    BrokerError::LiveHandler(format!(
                        "PrepareStateDir: unknown subject {:?}",
                        req.vm_id.as_str()
                    ))
                })?;
            let exec = live_exec(config);
            match crate::ops::state_dir::live_prepare_state_dir(&exec, resolver, &req, audit_log) {
                Ok(()) => {}
                Err(crate::ops::state_dir::PrepareStateDirError::SwtpmDirHardening(error)) => {
                    write_decision_op_record!(
                        audit_log,
                        bundle_metadata,
                        "PrepareSwtpmDir",
                        req.vm_id.as_str(),
                        caller_uid,
                        caller_gid,
                        &caller_role,
                        req.vm_id.as_str(),
                        req.vm_id.as_str(),
                        tracing_span_id_str(req.tracing_span_id.as_ref()),
                        "denied-refused",
                        Some(error.reason),
                        OperationFields::PrepareSwtpmDir(error.audit.clone()),
                    )?;
                    return Err(BrokerError::SwtpmDirHardening {
                        audit: error.audit,
                        reason: error.reason,
                    });
                }
                Err(error) => return Err(BrokerError::LiveHandler(error.to_string())),
            }
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "PrepareStateDir",
                req.vm_id.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                req.vm_id.as_str(),
                req.vm_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::PrepareStateDir {
                    vm_id: req.vm_id.as_str().to_owned(),
                    base_dir: intent.base_dir.display().to_string(),
                    owner_uid: intent.owner_uid,
                    owner_gid: intent.owner_gid,
                    mode: intent.mode,
                },
            )?;
            Ok(DispatchResult::no_fds(ack_response("PrepareStateDir")))
        }
        RealBrokerRequest::MigrateLegacySwtpmState(req) => {
            if !caller_role_is_admin(&caller_role) {
                return Err(BrokerError::AuditRequiresAdmin);
            }
            let resolver = require_resolver(resolver)?;
            let intent = resolver
                .resolve_legacy_swtpm_intent(req.vm_id.as_str())
                .filter(|intent| intent.intent_id == req.bundle_legacy_swtpm_intent_ref.as_str())
                .ok_or_else(|| BrokerError::BundleIntentMissing {
                    kind: "legacy-swtpm",
                    intent_id: req.bundle_legacy_swtpm_intent_ref.as_str().to_owned(),
                })?;
            let paths = crate::ops::swtpm_migration::LegacyMigrationPaths::new(
                intent.source.clone(),
                intent.destination.clone(),
                intent.journal.clone(),
                intent.marker.clone(),
                (intent.owner_uid, intent.owner_gid),
            )
            .map_err(|error| BrokerError::LiveHandler(error.to_string()))?;
            tracing::warn!(
                ?paths,
                probe_only = req.probe_only,
                "TPM migration paths resolved"
            );
            let wire_outcome = if req.probe_only {
                match crate::ops::swtpm_migration::probe(&paths) {
                    Ok(crate::ops::swtpm_migration::LegacyInventoryState::NeverProvisioned) => {
                        d2b_contracts_broker::broker_wire::LegacySwtpmMigrationOutcome::NeverProvisioned
                    }
                    Ok(crate::ops::swtpm_migration::LegacyInventoryState::ValidLegacy) => {
                        d2b_contracts_broker::broker_wire::LegacySwtpmMigrationOutcome::AdoptionRequired
                    }
                    Ok(crate::ops::swtpm_migration::LegacyInventoryState::AlreadyCommitted) => {
                        d2b_contracts_broker::broker_wire::LegacySwtpmMigrationOutcome::AlreadyMigrated
                    }
                    Ok(
                        crate::ops::swtpm_migration::LegacyInventoryState::Missing
                        | crate::ops::swtpm_migration::LegacyInventoryState::Replaced
                        | crate::ops::swtpm_migration::LegacyInventoryState::Ambiguous
                        | crate::ops::swtpm_migration::LegacyInventoryState::Foreign,
                    )
                    | Err(crate::ops::swtpm_migration::LegacyMigrationError::InventoryInvalid)
                    | Err(crate::ops::swtpm_migration::LegacyMigrationError::ForeignOwner) => {
                        d2b_contracts_broker::broker_wire::LegacySwtpmMigrationOutcome::Ambiguous
                    }
                    Err(crate::ops::swtpm_migration::LegacyMigrationError::LockUnavailable) => {
                        d2b_contracts_broker::broker_wire::LegacySwtpmMigrationOutcome::Pending
                    }
                    Err(_) => d2b_contracts_broker::broker_wire::LegacySwtpmMigrationOutcome::Failed,
                }
            } else {
                let outcome = match crate::ops::swtpm_migration::migrate(&paths) {
                    Ok(outcome) => outcome,
                    Err(_) => crate::ops::swtpm_migration::LegacyMigrationOutcome::Failed,
                };
                match outcome {
                    crate::ops::swtpm_migration::LegacyMigrationOutcome::Migrated => {
                        d2b_contracts_broker::broker_wire::LegacySwtpmMigrationOutcome::Migrated
                    }
                    crate::ops::swtpm_migration::LegacyMigrationOutcome::AlreadyMigrated => {
                        d2b_contracts_broker::broker_wire::LegacySwtpmMigrationOutcome::AlreadyMigrated
                    }
                    crate::ops::swtpm_migration::LegacyMigrationOutcome::NotApplicable => {
                        d2b_contracts_broker::broker_wire::LegacySwtpmMigrationOutcome::NotApplicable
                    }
                    crate::ops::swtpm_migration::LegacyMigrationOutcome::Pending => {
                        d2b_contracts_broker::broker_wire::LegacySwtpmMigrationOutcome::Pending
                    }
                    crate::ops::swtpm_migration::LegacyMigrationOutcome::Failed => {
                        d2b_contracts_broker::broker_wire::LegacySwtpmMigrationOutcome::Failed
                    }
                    crate::ops::swtpm_migration::LegacyMigrationOutcome::Ambiguous => {
                        d2b_contracts_broker::broker_wire::LegacySwtpmMigrationOutcome::Ambiguous
                    }
                }
            };
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "MigrateLegacySwtpmState",
                req.vm_id.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                req.vm_id.as_str(),
                req.vm_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::MigrateLegacySwtpmState {
                    vm_id: req.vm_id.as_str().to_owned(),
                    outcome: wire_outcome.as_str().to_owned(),
                },
            )?;
            Ok(DispatchResult::no_fds(
                BrokerResponse::MigrateLegacySwtpmState(
                    d2b_contracts_broker::broker_wire::MigrateLegacySwtpmStateResponse {
                        outcome: wire_outcome,
                    },
                ),
            ))
        }
        RealBrokerRequest::PrepareStoreView(req) => {
            let resolver = require_resolver(resolver)?;
            let vm_name = lookup_vm_name(resolver, &req.vm_id);
            let intent = resolver
                .find_legacy_store_view_intent(&vm_name)
                .ok_or_else(|| BrokerError::BundleIntentMissing {
                    kind: "store-view",
                    intent_id: vm_name.clone(),
                })?;
            let outcome = backend.prepare_store_view(intent)?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "PrepareStoreView",
                req.vm_id.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                outcome.vm.as_str(),
                outcome.vm.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::PrepareStoreView {
                    vm: outcome.vm.clone(),
                    generation: outcome.generation,
                    hardlink_farm_path: outcome.hardlink_farm_path.display().to_string(),
                    view_root: outcome.target_view_path.display().to_string(),
                },
            )?;
            Ok(DispatchResult::no_fds(ack_response("PrepareStoreView")))
        }
        // Real-wire dispatch for the typed hardlink-farm op replacing
        // the retired per-VM `d2b-<vm>-store-sync.service` bash
        // oneshot. See the CRITICAL invariant in `ops/store_sync.rs`:
        // NEVER recursively chown/chmod/setfacl the per-VM `store/` path
        // - mutations propagate INTO `/nix/store` through the shared
        // hardlink inodes.
        RealBrokerRequest::StoreSync(req) => {
            let resolver = require_resolver(resolver)?;
            let vm_name = lookup_vm_name(resolver, &req.vm_id);
            let intent = resolver
                .find_store_view_intent(req.bundle_closure_ref.as_str())
                .filter(|intent| intent.vm == vm_name)
                .ok_or_else(|| BrokerError::BundleIntentMissing {
                    kind: "store-sync-closure",
                    intent_id: req.bundle_closure_ref.as_str().to_owned(),
                })?;
            let started = std::time::Instant::now();
            let result =
                crate::ops::store_sync::run_store_sync(intent, &vm_name, req.generation_token);
            let total_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

            // ADR 0027: every StoreSync attempt that reaches this handler
            // emits EXACTLY ONE terminal `OperationFields::StoreSync`
            // record. The audit context is derived from the trusted
            // resolved intent (NOT the run_store_sync outcome), so a
            // failure that aborts before any link accounting still emits a
            // fully-attributed record. `generation_id` is the
            // collision-free on-disk key. Successful attempts use the
            // StoreSync handler's per-phase timings; pre-handler failures
            // still carry the dispatch-level total only.
            let hardlink_farm_path_str = intent.hardlink_farm_path.display().to_string();
            let closure_count = u32::try_from(intent.closure_paths.len()).unwrap_or(u32::MAX);
            let target_env = resolver
                .find_manifest_vm(&vm_name)
                .and_then(|vm| vm.env.clone());
            let timings = match &result {
                Ok(outcome) => outcome.timings,
                Err(_) => crate::ops::store_sync_audit::StoreSyncTimings {
                    total_ms,
                    ..Default::default()
                },
            };
            let audit_ctx = crate::ops::store_sync_audit::StoreSyncAuditContext {
                vm: vm_name.clone(),
                vm_id: req.vm_id.as_str().to_owned(),
                env: target_env,
                bundle_closure_ref: req.bundle_closure_ref.as_str().to_owned(),
                hardlink_farm_path: hardlink_farm_path_str.clone(),
                generation_id: crate::ops::store_sync::generation_id_for_intent(intent),
                generation_token: req.generation_token,
                caller_principal: Some(format!(
                    "uid:{caller_uid}/role:{}",
                    audit_context.peer_role.as_str()
                )),
                closure_count,
                timings,
            };
            let audit_fields = crate::ops::store_sync::audit_fields_for_result(audit_ctx, &result);
            debug_assert!(
                audit_fields.validate().is_ok(),
                "StoreSync terminal audit record violates the signed schema: {:?}",
                audit_fields.validate()
            );

            // ADR 0027 observability export: project the host-confidential
            // terminal record down to the signed positive-allow-list and
            // append it to the alloy-readable export directory. Emitted
            // exactly once per terminal attempt (before the success/failure
            // match consumes `audit_fields`). Best-effort: the broker audit
            // record is the source of truth, so a failed export write must
            // never fail the StoreSync operation.
            let export_record =
                crate::ops::store_sync_export::StoreSyncObservabilityRecord::from_audit_fields(
                    &audit_fields,
                );
            if let Err(err) = crate::ops::store_sync_export::append_export_record(
                &config.store_sync_export_dir,
                &export_record,
            ) {
                warn!(
                    target_vm = %export_record.target_vm,
                    error = %err,
                    "failed to write StoreSync observability export record"
                );
            }

            match result {
                Ok(outcome) => {
                    write_success_op_record!(
                        audit_log,
                        bundle_metadata,
                        "StoreSync",
                        req.vm_id.as_str(),
                        caller_uid,
                        caller_gid,
                        &caller_role,
                        outcome.vm.as_str(),
                        outcome.vm.as_str(),
                        tracing_span_id_str(req.tracing_span_id.as_ref()),
                        OperationFields::StoreSync(audit_fields),
                    )?;
                    Ok(DispatchResult::no_fds(BrokerResponse::StoreSync(
                        d2b_contracts_broker::broker_wire::StoreSyncResponse {
                            vm: outcome.vm,
                            generation_id: outcome.generation_id,
                            generation_token: outcome.generation_token,
                            hardlink_farm_path: hardlink_farm_path_str,
                            closure_count: outcome.closure_count,
                            retained_generations: outcome.retained_generations,
                            swept_count: outcome.swept_count,
                            cleanup_deferred: outcome.cleanup_deferred,
                        },
                    )))
                }
                Err(err) => {
                    // Terminal failure record (decision = "errored",
                    // result = "error"). The `failed`/`denied` audit shape
                    // is carried in `operation_fields`; the header
                    // `error_kind` is the classified stage slug.
                    let error_kind = store_sync_error_kind(err.error_stage());
                    tracing::warn!(
                        error_stage = error_kind,
                        error = %err,
                        "StoreSync execution failed",
                    );
                    write_decision_op_record!(
                        audit_log,
                        bundle_metadata,
                        "StoreSync",
                        req.vm_id.as_str(),
                        caller_uid,
                        caller_gid,
                        &caller_role,
                        req.vm_id.as_str(),
                        vm_name.as_str(),
                        tracing_span_id_str(req.tracing_span_id.as_ref()),
                        "errored",
                        Some(error_kind),
                        OperationFields::StoreSync(audit_fields),
                    )?;
                    Err(BrokerError::StoreSyncFailed {
                        error_stage: error_kind,
                        message: err.to_string(),
                    })
                }
            }
        }
        RealBrokerRequest::StoreVerify(req) => {
            let resolver = require_resolver(resolver)?;
            let vm_name = lookup_vm_name(resolver, &req.vm_id);
            let response = if let Some(intent) = resolver.find_legacy_store_view_intent(&vm_name) {
                let initial =
                    crate::ops::store_verify::run_store_verify_read_only(intent, req.repair);
                if req.repair
                    && matches!(
                        initial.status,
                        d2b_contracts_broker::broker_wire::StoreVerifyStatus::Drift
                            | d2b_contracts_broker::broker_wire::StoreVerifyStatus::Unknown
                    )
                {
                    let sync_started = std::time::Instant::now();
                    let sync_result = crate::ops::store_sync::run_store_sync_repair(intent);
                    let sync_total_ms =
                        u64::try_from(sync_started.elapsed().as_millis()).unwrap_or(u64::MAX);
                    let hardlink_farm_path_str = intent.hardlink_farm_path.display().to_string();
                    let generation_token = u32::try_from(intent.generation).unwrap_or(u32::MAX);
                    let closure_count =
                        u32::try_from(intent.closure_paths.len()).unwrap_or(u32::MAX);
                    let target_env = resolver
                        .find_manifest_vm(&vm_name)
                        .and_then(|vm| vm.env.clone());
                    let timings = match &sync_result {
                        Ok(outcome) => outcome.timings,
                        Err(_) => crate::ops::store_sync_audit::StoreSyncTimings {
                            total_ms: sync_total_ms,
                            ..Default::default()
                        },
                    };
                    let sync_ctx = crate::ops::store_sync_audit::StoreSyncAuditContext {
                        vm: vm_name.clone(),
                        vm_id: req.vm_id.as_str().to_owned(),
                        env: target_env,
                        bundle_closure_ref: intent.intent_id.clone(),
                        hardlink_farm_path: hardlink_farm_path_str,
                        generation_id: crate::ops::store_sync::generation_id_for_intent(intent),
                        generation_token,
                        caller_principal: Some(format!(
                            "uid:{caller_uid}/role:{}",
                            audit_context.peer_role.as_str()
                        )),
                        closure_count,
                        timings,
                    };
                    let sync_audit_fields =
                        crate::ops::store_sync::audit_fields_for_result(sync_ctx, &sync_result);
                    debug_assert!(
                        sync_audit_fields.validate().is_ok(),
                        "StoreSync repair audit record violates signed schema: {:?}",
                        sync_audit_fields.validate()
                    );
                    let export_record = crate::ops::store_sync_export::StoreSyncObservabilityRecord::from_audit_fields(&sync_audit_fields);
                    if let Err(err) = crate::ops::store_sync_export::append_export_record(
                        &config.store_sync_export_dir,
                        &export_record,
                    ) {
                        warn!(
                            target_vm = %export_record.target_vm,
                            error = %err,
                            "failed to write StoreSync observability export record for StoreVerify repair"
                        );
                    }
                    match &sync_result {
                        Ok(outcome) => {
                            write_success_op_record!(
                                audit_log,
                                bundle_metadata,
                                "StoreSync",
                                req.vm_id.as_str(),
                                caller_uid,
                                caller_gid,
                                &caller_role,
                                outcome.vm.as_str(),
                                outcome.vm.as_str(),
                                tracing_span_id_str(req.tracing_span_id.as_ref()),
                                OperationFields::StoreSync(sync_audit_fields),
                            )?;
                        }
                        Err(err) => {
                            let error_kind = store_sync_error_kind(err.error_stage());
                            write_decision_op_record!(
                                audit_log,
                                bundle_metadata,
                                "StoreSync",
                                req.vm_id.as_str(),
                                caller_uid,
                                caller_gid,
                                &caller_role,
                                vm_name.as_str(),
                                vm_name.as_str(),
                                tracing_span_id_str(req.tracing_span_id.as_ref()),
                                "errored",
                                Some(error_kind),
                                OperationFields::StoreSync(sync_audit_fields),
                            )?;
                        }
                    }
                    crate::ops::store_verify::finish_repair_after_store_sync(
                        intent,
                        initial,
                        sync_result,
                    )
                } else {
                    initial
                }
            } else {
                crate::ops::store_verify::not_found(&vm_name)
            };
            let verify_status = serde_json::to_value(response.status)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_else(|| "failed".to_owned());
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "StoreVerify",
                req.vm_id.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                vm_name.as_str(),
                vm_name.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::StoreVerify {
                    vm: response.vm.clone(),
                    status: verify_status,
                    checked: response.checked,
                    drifted: response.drifted,
                    repaired: response.repaired,
                    repair_requested: req.repair,
                },
            )?;
            Ok(DispatchResult::no_fds(BrokerResponse::StoreVerify(
                response,
            )))
        }
        RealBrokerRequest::ReadSecretById(_) => Err(BrokerError::Unimplemented {
            operation: "ReadSecretById",
            target_wave: "W8",
        }),
        RealBrokerRequest::ResumeBroker => Err(BrokerError::Unimplemented {
            operation: "ResumeBroker",
            target_wave: "W4",
        }),
        RealBrokerRequest::RunHostInstall(req) => {
            let response = backend.run_host_install(&req, resolver.map(std::sync::Arc::as_ref))?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "RunHostInstall",
                req.bundle_installer_intent_ref.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                "host-installer",
                "host",
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::RunHostInstall {
                    bundle_installer_intent_ref: req
                        .bundle_installer_intent_ref
                        .as_str()
                        .to_owned(),
                    enable: req.enable,
                    start: req.start,
                    no_start: req.no_start,
                },
            )?;
            Ok(DispatchResult::no_fds(BrokerResponse::RunHostInstall(
                response,
            )))
        }
        RealBrokerRequest::RunMigrate(req) => {
            let resolver = require_resolver(resolver)?;
            let intent = resolver
                .find_migrate_intent(req.bundle_migrate_intent_ref.as_str())
                .ok_or_else(|| BrokerError::BundleIntentMissing {
                    kind: "migrate",
                    intent_id: req.bundle_migrate_intent_ref.as_str().to_owned(),
                })?;
            let outcome = backend.run_migrate(intent)?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "RunMigrate",
                req.bundle_migrate_intent_ref.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                "migrate",
                "host",
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::RunMigrate {
                    bundle_migrate_intent_ref: req.bundle_migrate_intent_ref.as_str().to_owned(),
                },
            )?;
            Ok(DispatchResult::no_fds(BrokerResponse::RunMigrate(
                d2b_contracts_broker::broker_wire::RunMigrateResponse {
                    migrated_vm_count: outcome.migrated_vm_count,
                    notes: outcome.notes,
                },
            )))
        }
        RealBrokerRequest::ApplyHostGenerationHandoff(req) => {
            let target = req.target.to_canonical_string();
            let fields = OperationFields::ApplyHostGenerationHandoff {
                target: target.clone(),
                source_generation: req.intent.source_generation,
                target_generation: req.intent.target_generation,
                state: "requested".to_owned(),
            };
            if !caller_role_is_admin(&caller_role)
                || !matches!(
                    req.caller_role,
                    d2b_contracts_broker::host_generation::HandoffCallerRole::Lifecycle
                        | d2b_contracts_broker::host_generation::HandoffCallerRole::Admin
                )
            {
                write_decision_op_record!(
                    audit_log,
                    bundle_metadata,
                    "ApplyHostGenerationHandoff",
                    &target,
                    caller_uid,
                    caller_gid,
                    &caller_role,
                    &target,
                    "host-generation",
                    None,
                    "denied-refused",
                    Some("handoff-requires-admin"),
                    fields,
                )?;
                return Err(BrokerError::AuditRequiresAdmin);
            }
            let response = backend.apply_host_generation_handoff(
                &config.state_dir,
                &config.activation_helper_path,
                &req,
            )?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "ApplyHostGenerationHandoff",
                &response.target.to_canonical_string(),
                caller_uid,
                caller_gid,
                &caller_role,
                &response.target.to_canonical_string(),
                "host-generation",
                None,
                OperationFields::ApplyHostGenerationHandoff {
                    target,
                    source_generation: response.source_generation,
                    target_generation: response.target_generation,
                    state: format!("{:?}", response.state).to_lowercase(),
                },
            )?;
            Ok(DispatchResult::no_fds(
                BrokerResponse::ApplyHostGenerationHandoff(response),
            ))
        }
        RealBrokerRequest::RunActivation(req) => {
            let resolver = require_resolver(resolver)?;
            let intent = resolver
                .find_activation_intent(req.bundle_activation_intent_ref.as_str())
                .ok_or_else(|| BrokerError::BundleIntentMissing {
                    kind: "activation",
                    intent_id: req.bundle_activation_intent_ref.as_str().to_owned(),
                })?;
            if intent.vm != req.vm {
                return Err(BrokerError::Protocol(format!(
                    "RunActivation vm mismatch: wire vm `{}` != intent vm `{}`",
                    req.vm, intent.vm,
                )));
            }
            let store_view_intent =
                resolver
                    .find_legacy_store_view_intent(&req.vm)
                    .ok_or_else(|| BrokerError::BundleIntentMissing {
                        kind: "store-view",
                        intent_id: req.vm.clone(),
                    })?;
            let outcome = backend.run_activation(intent, store_view_intent, req.phase, req.mode)?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "RunActivation",
                req.bundle_activation_intent_ref.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                req.vm.as_str(),
                req.vm.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::RunActivation {
                    bundle_activation_intent_ref: req
                        .bundle_activation_intent_ref
                        .as_str()
                        .to_owned(),
                    mode: activation_mode_name(req.mode).to_owned(),
                    vm: req.vm.clone(),
                },
            )?;
            Ok(DispatchResult::no_fds(BrokerResponse::RunActivation(
                d2b_contracts_broker::broker_wire::RunActivationResponse {
                    mode: outcome.mode,
                    vm: outcome.vm,
                    generation_number: outcome.generation_number,
                    guest_switch_script_path: outcome
                        .guest_switch_script_path
                        .as_ref()
                        .map(|path| path.display().to_string()),
                    summary: outcome.summary,
                },
            )))
        }
        RealBrokerRequest::RunGc(req) => {
            let resolver = require_resolver(resolver)?;
            let intent = resolver
                .find_gc_intent(req.bundle_gc_intent_ref.as_str())
                .ok_or_else(|| BrokerError::BundleIntentMissing {
                    kind: "gc",
                    intent_id: req.bundle_gc_intent_ref.as_str().to_owned(),
                })?;
            let outcome = backend.run_gc(intent, req.keep_generations)?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "RunGc",
                req.bundle_gc_intent_ref.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                "gc",
                "host",
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::RunGc {
                    bundle_gc_intent_ref: req.bundle_gc_intent_ref.as_str().to_owned(),
                    keep_generations: req.keep_generations,
                },
            )?;
            Ok(DispatchResult::no_fds(BrokerResponse::RunGc(
                d2b_contracts_broker::broker_wire::RunGcResponse {
                    keep_generations: outcome.keep_generations,
                    retained_store_path_count: outcome.retained_store_path_count,
                    summary: outcome.summary,
                },
            )))
        }
        RealBrokerRequest::RunKeysRotate(req) => {
            let resolver = require_resolver(resolver)?;
            let intent = resolver
                .find_keys_rotate_intent(req.bundle_keys_intent_ref.as_str())
                .ok_or_else(|| BrokerError::BundleIntentMissing {
                    kind: "keys-rotate",
                    intent_id: req.bundle_keys_intent_ref.as_str().to_owned(),
                })?;
            if intent.vm != req.vm {
                return Err(BrokerError::Protocol(format!(
                    "RunKeysRotate vm mismatch: wire vm `{}` != intent vm `{}`",
                    req.vm, intent.vm,
                )));
            }
            let outcome = backend.run_keys_rotate(intent)?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "RunKeysRotate",
                req.bundle_keys_intent_ref.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                req.vm.as_str(),
                req.vm.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::RunKeysRotate {
                    bundle_keys_intent_ref: req.bundle_keys_intent_ref.as_str().to_owned(),
                    vm: req.vm.clone(),
                },
            )?;
            Ok(DispatchResult::no_fds(BrokerResponse::RunKeysRotate(
                d2b_contracts_broker::broker_wire::RunKeysRotateResponse {
                    vm: outcome.vm,
                    key_path: outcome.key_path.display().to_string(),
                    public_key_fingerprint: outcome.public_key_fingerprint,
                },
            )))
        }
        RealBrokerRequest::RunHostKeyTrust(req) => {
            let resolver = require_resolver(resolver)?;
            let intent = resolver
                .find_host_key_trust_intent(req.bundle_trust_intent_ref.as_str())
                .ok_or_else(|| BrokerError::BundleIntentMissing {
                    kind: "host-key-trust",
                    intent_id: req.bundle_trust_intent_ref.as_str().to_owned(),
                })?;
            if intent.vm != req.vm {
                return Err(BrokerError::Protocol(format!(
                    "RunHostKeyTrust vm mismatch: wire vm `{}` != intent vm `{}`",
                    req.vm, intent.vm,
                )));
            }
            let outcome = backend.run_host_key_trust(intent)?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "RunHostKeyTrust",
                req.bundle_trust_intent_ref.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                req.vm.as_str(),
                req.vm.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::RunHostKeyTrust {
                    bundle_trust_intent_ref: req.bundle_trust_intent_ref.as_str().to_owned(),
                    vm: req.vm.clone(),
                },
            )?;
            Ok(DispatchResult::no_fds(BrokerResponse::RunHostKeyTrust(
                d2b_contracts_broker::broker_wire::RunHostKeyTrustResponse {
                    vm: outcome.vm,
                    static_ip: outcome.static_ip,
                    known_hosts_path: outcome.known_hosts_path.display().to_string(),
                    updated: outcome.updated,
                },
            )))
        }
        RealBrokerRequest::RunRotateKnownHost(req) => {
            let resolver = require_resolver(resolver)?;
            let intent = resolver
                .find_rotate_known_host_intent(req.bundle_rotate_known_host_intent_ref.as_str())
                .ok_or_else(|| BrokerError::BundleIntentMissing {
                    kind: "rotate-known-host",
                    intent_id: req.bundle_rotate_known_host_intent_ref.as_str().to_owned(),
                })?;
            if intent.vm != req.vm {
                return Err(BrokerError::Protocol(format!(
                    "RunRotateKnownHost vm mismatch: wire vm `{}` != intent vm `{}`",
                    req.vm, intent.vm,
                )));
            }
            let outcome = backend.run_rotate_known_host(intent)?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "RunRotateKnownHost",
                req.bundle_rotate_known_host_intent_ref.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                req.vm.as_str(),
                req.vm.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::RunRotateKnownHost {
                    bundle_rotate_known_host_intent_ref: req
                        .bundle_rotate_known_host_intent_ref
                        .as_str()
                        .to_owned(),
                    vm: req.vm.clone(),
                },
            )?;
            Ok(DispatchResult::no_fds(BrokerResponse::RunRotateKnownHost(
                d2b_contracts_broker::broker_wire::RunRotateKnownHostResponse {
                    vm: outcome.vm,
                    static_ip: outcome.static_ip,
                    known_hosts_path: outcome.known_hosts_path.display().to_string(),
                    removed: outcome.removed,
                },
            )))
        }
        RealBrokerRequest::RotateSecretById(_) => Err(BrokerError::Unimplemented {
            operation: "RotateSecretById",
            target_wave: "W8",
        }),
        RealBrokerRequest::SetBridgePortFlags(req) => {
            let resolver = require_resolver_ref(resolver.map(|resolver| resolver.as_ref()))?;
            let response = backend.set_bridge_port_flags(&req, resolver)?;
            let runner_id = format!("{}:{}", req.vm_id.as_str(), req.role_id.as_str());
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "SetBridgePortFlags",
                runner_id.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                req.vm_id.as_str(),
                req.role_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::SetBridgePortFlags {
                    vm: req.vm_id.as_str().to_owned(),
                    role: req.role_id.as_str().to_owned(),
                    ifname: response.port.as_str().to_owned(),
                    flags: serde_json::json!({
                        "isolated": response.isolated,
                        "neighSuppress": response.neigh_suppress,
                    }),
                },
            )?;
            Ok(DispatchResult::no_fds(BrokerResponse::SetBridgePortFlags(
                response,
            )))
        }
        RealBrokerRequest::SetSocketAcl(_) => Err(BrokerError::Unimplemented {
            operation: "SetSocketAcl",
            target_wave: "W5",
        }),
        RealBrokerRequest::SetupMountNamespace(req) => {
            let resolver = require_resolver(resolver)?;
            let vm_name = lookup_vm_name(resolver, &req.vm_id);
            let store_view_intent = resolver
                .find_legacy_store_view_intent(&vm_name)
                .ok_or_else(|| BrokerError::BundleIntentMissing {
                    kind: "store-view",
                    intent_id: vm_name.clone(),
                })?;
            let runner_intent_id =
                d2b_core::bundle_resolver::intent_id_legacy_runner(&vm_name, req.role_id.as_str());
            resolver
                .find_runner_intent(&runner_intent_id)
                .ok_or_else(|| BrokerError::BundleIntentMissing {
                    kind: "runner",
                    intent_id: runner_intent_id.clone(),
                })?;
            let outcome =
                backend.setup_mount_namespace(&vm_name, req.role_id.as_str(), store_view_intent)?;
            let runner_id = format!("{}:{}", req.vm_id.as_str(), req.role_id.as_str());
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "SetupMountNamespace",
                runner_id.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                outcome.vm.as_str(),
                req.role_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::SetupMountNamespace {
                    vm: outcome.vm.clone(),
                    role: outcome.role_id.clone(),
                    mount_count: 1,
                    mount_root: outcome.mount_root.display().to_string(),
                    mount_view_path: outcome.mount_view_path.display().to_string(),
                    source_view_path: store_view_intent.target_view_path.display().to_string(),
                },
            )?;
            Ok(DispatchResult::no_fds(ack_response("SetupMountNamespace")))
        }
        RealBrokerRequest::UsbipBind(req) => {
            let resolver = require_resolver(resolver)?;
            let intent = find_usbip_bind_intent_or_wildcard(
                resolver,
                req.bundle_usbip_bind_intent_ref.as_str(),
            )
            .ok_or_else(|| BrokerError::BundleIntentMissing {
                kind: "usbip-bind",
                intent_id: req.bundle_usbip_bind_intent_ref.as_str().to_owned(),
            })?;
            let same_vm_replay = match crate::ops::usbip_lock::peek_owner(&intent.lock_path) {
                Some(owner) if owner == intent.vm_name => true,
                Some(owner) => {
                    return Err(BrokerError::UsbipLockConflict {
                        busid: intent.bus_id.clone(),
                        owner,
                    });
                }
                None => false,
            };
            let inspection = crate::ops::usbip_host::enforce_usbip_physical_policy(
                &intent,
                usb_device_sysfs_root(),
            )
            .map_err(|err| map_usbip_host_inspection_error_for_intent(&intent, err))?;
            let expected_identity = (inspection.vendor, inspection.product);
            let (audit_device_identity, rotation_audit) = usb_audit_device_identity_for_busid(
                usb_device_sysfs_root(),
                &intent.bus_id,
                expected_identity,
                &config.state_dir,
                config.test_mode,
            )?;
            if let Some(rotation_audit) = rotation_audit
                && let Some(rotation_audit_dedupe_key) =
                    mark_usb_audit_serial_hmac_rotation_audit_logged(&rotation_audit)
            {
                let rotation_audit_context = DispatchAuditContext {
                    peer_pid: audit_context.peer_pid,
                    peer_role: audit_context.peer_role.clone(),
                    verb: "UsbSerialCorrelationKeyRotate".to_owned(),
                    request_fields: serde_json::json!({
                        "detectedDuring": "UsbipBind",
                        "tracingSpanIdPresent": req.tracing_span_id.is_some(),
                    }),
                    started_at: audit_context.started_at,
                    audit_join: audit_context.audit_join.clone(),
                };
                if let Err(err) = write_success_op_record_impl(
                    audit_log,
                    bundle_metadata,
                    "UsbSerialCorrelationKeyRotate",
                    "usb-audit-serial-hmac",
                    caller_uid,
                    caller_gid,
                    &caller_role,
                    "usb-audit-serial-hmac",
                    "host",
                    tracing_span_id_str(req.tracing_span_id.as_ref()),
                    OperationFields::UsbSerialCorrelationKeyRotate(rotation_audit),
                    &rotation_audit_context,
                ) {
                    unmark_usb_audit_serial_hmac_rotation_audit_logged(&rotation_audit_dedupe_key);
                    return Err(err);
                }
            }
            let expected_device_node = inspection.device_node;
            backend.usbip_bind(&intent)?;
            if let Err(grant_error) = grant_usbip_backend_device_acl(
                resolver,
                &intent,
                expected_identity,
                expected_device_node,
            ) {
                return Err(rollback_usbip_bind_after_acl_grant_failure(
                    backend,
                    &intent,
                    same_vm_replay,
                    grant_error,
                ));
            }
            let scope_id = format!("env:{}", intent.env);
            let audit_result = write_success_op_record!(
                audit_log,
                bundle_metadata,
                "UsbipBind",
                intent.intent_id.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                intent.vm_name.as_str(),
                scope_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::UsbipBind {
                    bus_id: intent.bus_id.clone(),
                    vm: intent.vm_name.clone(),
                    device_identity: Some(audit_device_identity),
                },
            );
            if let Err(audit_error) = audit_result {
                rollback_usbip_bind_after_audit_failure(backend, resolver, &intent, same_vm_replay);
                return Err(audit_error);
            }
            Ok(DispatchResult::no_fds(ack_response("UsbipBind")))
        }
        RealBrokerRequest::UsbipUnbind(req) => {
            let resolver = require_resolver(resolver)?;
            let intent = find_usbip_bind_intent_or_wildcard(
                resolver,
                req.bundle_usbip_bind_intent_ref.as_str(),
            )
            .ok_or_else(|| BrokerError::BundleIntentMissing {
                kind: "usbip-bind",
                intent_id: req.bundle_usbip_bind_intent_ref.as_str().to_owned(),
            })?;
            let had_matching_lock = match crate::ops::usbip_lock::peek_owner(&intent.lock_path) {
                Some(owner) if owner == intent.vm_name => true,
                Some(owner) => {
                    return Err(BrokerError::UsbipLockConflict {
                        busid: intent.bus_id.clone(),
                        owner,
                    });
                }
                None => false,
            };
            backend.usbip_unbind(&intent)?;
            if had_matching_lock {
                if let Err(revoke_error) = revoke_usbip_backend_device_acl(resolver, &intent) {
                    return Err(handle_usbip_acl_revoke_failure_after_unbind(
                        &intent,
                        req.preserve_durable_claim,
                        revoke_error,
                    ));
                }
                if !req.preserve_durable_claim {
                    crate::ops::usbip_lock::release_lock(&intent.lock_path, &intent.vm_name)
                        .map_err(|err| BrokerError::LiveHandler(err.to_string()))?;
                }
            }
            let scope_id = format!("env:{}", intent.env);
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "UsbipUnbind",
                intent.intent_id.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                intent.vm_name.as_str(),
                scope_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::UsbipUnbind {
                    bus_id: intent.bus_id.clone(),
                },
            )?;
            Ok(DispatchResult::no_fds(ack_response("UsbipUnbind")))
        }
        RealBrokerRequest::UsbipBindFirewallRule(req) => {
            // Render the carve-out through the canonical USBIP nft batch
            // helper so the existing table/chain ordering is preserved.
            let resolver = require_resolver(resolver)?;
            let intent = find_usbip_firewall_intent_or_wildcard(
                resolver,
                req.bundle_usbip_firewall_intent_ref.as_str(),
            )
            .ok_or_else(|| BrokerError::BundleIntentMissing {
                kind: "usbip-firewall",
                intent_id: req.bundle_usbip_firewall_intent_ref.as_str().to_owned(),
            })?;
            backend.usbip_bind_firewall_rule(resolver, &intent)?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "UsbipBindFirewallRule",
                req.bundle_usbip_firewall_intent_ref.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                intent.bus_id.as_str(),
                "usbip-firewall",
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::UsbipBindFirewallRule {
                    bundle_usbip_firewall_intent_ref: req
                        .bundle_usbip_firewall_intent_ref
                        .as_str()
                        .to_owned(),
                },
            )?;
            Ok(DispatchResult::no_fds(ack_response(
                "UsbipBindFirewallRule",
            )))
        }
        RealBrokerRequest::UsbipProxyReconcile(req) => {
            let resolver = require_resolver(resolver)?;
            let expectations: Vec<(String, String, std::path::PathBuf)> = resolver
                .usbip_bind_intent_ids()
                .filter_map(|id| {
                    resolver.find_usbip_bind_intent(id).map(|intent| {
                        (
                            intent.bus_id.clone(),
                            intent.vm_name.clone(),
                            intent.lock_path.clone(),
                        )
                    })
                })
                .collect();
            backend.usbip_proxy_reconcile(&expectations)?;
            reconcile_active_usbip_backend_acls(resolver)?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "UsbipProxyReconcile",
                req.scope_id.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                "usbip-proxy",
                req.scope_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::UsbipProxyReconcile {},
            )?;
            Ok(DispatchResult::no_fds(ack_response("UsbipProxyReconcile")))
        }
        // SeedDnsmasqLease + BindMount dispatch arms. The bundle
        // resolver vouches for the per-VM intent rows; the broker
        // validates the VM exists in the trusted manifest, records the
        // typed audit row, and acks. The actual filesystem mutation
        // (writing the leases file / performing the bind mount) stays
        // out of scope here - both targets live in subtrees the daemon
        // already owns (`/var/lib/d2b/dnsmasq/`, per-VM store farm),
        // and this removes the typed-Unimplemented wall so the host-prep
        // DAG executor exercises a real broker round trip in eval-only
        // test environments. Live filesystem handlers land later.
        RealBrokerRequest::SeedDnsmasqLease(req) => {
            if req.scope_id.as_str().starts_with("network:") {
                let resolver = require_resolver(resolver)?;
                let provenance = network_provenance(
                    req.zone_uid.clone(),
                    req.network_uid.clone(),
                    req.network_generation,
                    req.attachment_generation,
                    req.bundle_generation.clone(),
                );
                require_installed_network_generation(resolver, &provenance)?;
            }
            let expected_vm =
                d2b_contracts_resource::v3::derive_network_child_name(&req.network_uid, "vm");
            if req.vm_id.as_str() != expected_vm {
                return Err(BrokerError::RequestValidation {
                    operation: "SeedDnsmasqLease",
                    reason: "network-admission-mismatch",
                });
            }
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "SeedDnsmasqLease",
                req.vm_id.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                req.vm_id.as_str(),
                req.scope_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::SeedDnsmasqLease {
                    vm_id: req.vm_id.as_str().to_owned(),
                    scope_id: req.scope_id.as_str().to_owned(),
                },
            )?;
            Ok(DispatchResult::no_fds(ack_response("SeedDnsmasqLease")))
        }
        RealBrokerRequest::BindMountFromHardlinkFarm(req) => {
            let resolver = require_resolver(resolver)?;
            let vm_name = lookup_vm_name(resolver, &req.vm_id);
            let intent = if let Some(intent_ref) = req.bundle_store_view_intent_ref.as_ref() {
                resolver
                    .find_store_view_intent(intent_ref.as_str())
                    .filter(|intent| intent.vm == vm_name)
            } else {
                resolver.find_legacy_store_view_intent(&vm_name)
            }
            .ok_or_else(|| BrokerError::BundleIntentMissing {
                kind: "store-view",
                intent_id: req
                    .bundle_store_view_intent_ref
                    .as_ref()
                    .map_or_else(|| vm_name.clone(), |id| id.as_str().to_owned()),
            })?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "BindMountFromHardlinkFarm",
                vm_name.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                vm_name.as_str(),
                "host",
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::BindMountFromHardlinkFarm {
                    vm_id: vm_name.clone(),
                    bundle_store_view_intent_ref: req
                        .bundle_store_view_intent_ref
                        .as_ref()
                        .map(|id| id.as_str().to_owned()),
                    hardlink_farm_path: intent.hardlink_farm_path.display().to_string(),
                },
            )?;
            Ok(DispatchResult::no_fds(ack_response(
                "BindMountFromHardlinkFarm",
            )))
        }
        RealBrokerRequest::OwnershipMatrixCheck(_) => Err(BrokerError::Unimplemented {
            operation: "OwnershipMatrixCheck",
            target_wave: "P2",
        }),
        RealBrokerRequest::SshHostKeyPreflight(_) => Err(BrokerError::Unimplemented {
            operation: "SshHostKeyPreflight",
            target_wave: "P2",
        }),
        RealBrokerRequest::UsbipExplicitBind(req) => {
            // Explicit attach: bind a present sysfs busid to a USB-capable VM without
            // a bundle allowlist. The daemon has already performed:
            //   1. Sysfs presence check (fail-closed if device absent)
            //   2. USB-capable gate (RuntimeCapabilityGate::UsbHotplug)
            //   3. Active-claim exclusivity check (OFD lock read)
            // The broker acquires the per-busid OFD lock, runs `usbip bind`, and
            // grants the per-device ACL to the env's USBIP backend runner.
            let resolver = require_resolver(resolver)?;
            let lock_path = std::path::PathBuf::from(
                d2b_contracts::usbip::UsbipDaemonClaimRecord::lock_path_for_busid(&req.bus_id),
            );

            // Same-VM replay: lock is already held by this VM (e.g. daemon restart).
            let same_vm_replay = match crate::ops::usbip_lock::peek_owner(&lock_path) {
                Some(owner) if owner == req.vm => true,
                Some(owner) => {
                    return Err(BrokerError::UsbipLockConflict {
                        busid: req.bus_id.clone(),
                        owner,
                    });
                }
                None => false,
            };

            // Inspect the device: no allowlist check (explicit path bypasses it).
            let inspection = crate::ops::usbip_host::inspect_usbip_host_device(
                usb_device_sysfs_root(),
                &req.bus_id,
            )
            .map_err(|err| {
                BrokerError::LiveHandler(format!(
                    "explicit usbip bind sysfs inspection failed for bus_id={}: {err}",
                    req.bus_id
                ))
            })?;

            let expected_identity = (inspection.vendor, inspection.product);
            let expected_device_node = inspection.device_node;

            // Audit device identity (same helper as declared path).
            let (audit_device_identity, rotation_audit) = usb_audit_device_identity_for_busid(
                usb_device_sysfs_root(),
                &req.bus_id,
                expected_identity,
                &config.state_dir,
                config.test_mode,
            )?;

            // Emit serial key rotation audit if needed (same policy as UsbipBind).
            if let Some(rotation_audit) = rotation_audit
                && let Some(rotation_audit_dedupe_key) =
                    mark_usb_audit_serial_hmac_rotation_audit_logged(&rotation_audit)
            {
                let rotation_audit_context = DispatchAuditContext {
                    peer_pid: audit_context.peer_pid,
                    peer_role: audit_context.peer_role.clone(),
                    verb: "UsbSerialCorrelationKeyRotate".to_owned(),
                    request_fields: serde_json::json!({
                        "detectedDuring": "UsbipExplicitBind",
                        "tracingSpanIdPresent": req.tracing_span_id.is_some(),
                    }),
                    started_at: audit_context.started_at,
                    audit_join: audit_context.audit_join.clone(),
                };
                if let Err(err) = write_success_op_record_impl(
                    audit_log,
                    bundle_metadata,
                    "UsbSerialCorrelationKeyRotate",
                    "usb-audit-serial-hmac",
                    caller_uid,
                    caller_gid,
                    &caller_role,
                    "usb-audit-serial-hmac",
                    "host",
                    tracing_span_id_str(req.tracing_span_id.as_ref()),
                    OperationFields::UsbSerialCorrelationKeyRotate(rotation_audit),
                    &rotation_audit_context,
                ) {
                    unmark_usb_audit_serial_hmac_rotation_audit_logged(&rotation_audit_dedupe_key);
                    return Err(err);
                }
            }

            // Build synthetic intent for backend calls: usbip_bind/usbip_unbind
            // only use bus_id, lock_path, and vm_name - the empty allowlist is never
            // checked on the explicit path (no enforce_usbip_physical_policy call).
            let synthetic_intent = d2b_core::bundle_resolver::ResolvedUsbipBindIntent {
                intent_id: format!("explicit:{}:{}", req.env, req.bus_id),
                bus_id: req.bus_id.clone(),
                vm_name: req.vm.clone(),
                env: req.env.clone(),
                lock_path: lock_path.clone(),
                vendor_product_allowlist: vec![],
                dynamic_bus_id: true,
            };

            // Acquire OFD lock and run `usbip bind` via the standard live handler.
            backend.usbip_bind(&synthetic_intent)?;

            // Grant per-device ACL to the env's USBIP backend runner (no allowlist).
            if let Err(grant_error) = grant_explicit_usbip_backend_acl(
                resolver,
                &req.env,
                &req.bus_id,
                expected_identity,
                expected_device_node,
            ) {
                if !same_vm_replay {
                    match backend.usbip_unbind(&synthetic_intent) {
                        Ok(()) => {
                            if let Err(lock_error) =
                                crate::ops::usbip_lock::release_lock(&lock_path, &req.vm)
                            {
                                warn!(
                                    bus_id = %req.bus_id,
                                    vm = %req.vm,
                                    grant_error = ?grant_error,
                                    error = %lock_error,
                                    "UsbipExplicitBind ACL grant failed, rollback unbind succeeded, but lock rollback failed"
                                );
                            }
                        }
                        Err(rollback_error) => {
                            warn!(
                                bus_id = %req.bus_id,
                                vm = %req.vm,
                                grant_error = ?grant_error,
                                rollback_error = ?rollback_error,
                                "UsbipExplicitBind ACL grant failed and rollback unbind also failed"
                            );
                        }
                    }
                }
                return Err(grant_error);
            }

            let scope_id = format!("env:{}", req.env);
            let audit_result = write_success_op_record!(
                audit_log,
                bundle_metadata,
                "UsbipExplicitBind",
                req.bus_id.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                req.vm.as_str(),
                scope_id.as_str(),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::UsbipExplicitBind {
                    bus_id: req.bus_id.clone(),
                    vm: req.vm.clone(),
                    env: req.env.clone(),
                    device_identity: Some(audit_device_identity),
                },
            );
            if let Err(audit_error) = audit_result {
                if !same_vm_replay {
                    if let Err(revoke_err) =
                        revoke_explicit_usbip_backend_acl(resolver, &req.env, &req.bus_id)
                    {
                        warn!(
                            bus_id = %req.bus_id,
                            vm = %req.vm,
                            error = ?revoke_err,
                            "UsbipExplicitBind audit write failed and backend ACL rollback failed"
                        );
                    }
                    match backend.usbip_unbind(&synthetic_intent) {
                        Ok(()) => {
                            if let Err(lock_error) =
                                crate::ops::usbip_lock::release_lock(&lock_path, &req.vm)
                            {
                                warn!(
                                    bus_id = %req.bus_id,
                                    vm = %req.vm,
                                    error = %lock_error,
                                    "UsbipExplicitBind audit write failed and lock rollback failed"
                                );
                            }
                        }
                        Err(unbind_error) => {
                            warn!(
                                bus_id = %req.bus_id,
                                vm = %req.vm,
                                error = ?unbind_error,
                                "UsbipExplicitBind audit write failed and backend unbind rollback failed"
                            );
                        }
                    }
                }
                return Err(audit_error);
            }
            Ok(DispatchResult::no_fds(ack_response("UsbipExplicitBind")))
        }
        RealBrokerRequest::UsbipExplicitFirewallRule(req) => {
            // Explicit attach: install a per-busid nftables carve-out scoped to the
            // target VM's env bridge. The broker validates request IPs against the
            // env's declared host config values (cross-check to prevent rule spoofing),
            // validates anti-spoof bridge port flags, and atomically applies the
            // updated nft table preserving all currently active carve-outs.
            let resolver = require_resolver(resolver)?;

            let (_, rule_body) = build_explicit_usbip_rule_body(
                resolver,
                &req.env,
                &req.host_uplink_ip,
                &req.net_uplink_ip,
            )?;

            let host_nft_intent = resolver
                .find_nft_intent(&d2b_core::bundle_resolver::intent_id_nft_host())
                .ok_or_else(|| BrokerError::BundleIntentMissing {
                    kind: "nft",
                    intent_id: d2b_core::bundle_resolver::intent_id_nft_host(),
                })?;

            let decision = build_usbip_explicit_firewall_decision(
                resolver,
                host_nft_intent,
                &req.bus_id,
                &rule_body,
            )?;

            let nft_binary = nft_binary_path();
            let exec = crate::ops::exec_reconcile::SystemReconcileExecutor;
            let nft_script = decision.batch.render_nft_script();
            let expected_hash = persisted_nft_hash()
                .map_err(|err| BrokerError::LiveHandler(err.to_string()))?
                .or_else(|| resolver.host.nftables.table_hash_after_apply.clone());
            crate::ops::nft::apply_with_coexistence(
                &exec,
                &nft_binary,
                &nft_script,
                resolver.host.nftables.ownership_id.as_str(),
                resolver.host.firewall_coexistence_policy.as_ref(),
                expected_hash.as_deref(),
            )
            .map_err(|err| match err {
                crate::ops::nft::ApplyWithCoexistenceError::CoexistenceRefused {
                    manager,
                    rationale,
                } => BrokerError::CoexistenceRefused { manager, rationale },
                crate::ops::nft::ApplyWithCoexistenceError::ParseFailed(err) => {
                    BrokerError::NftScriptParseFailed(err.to_string())
                }
                crate::ops::nft::ApplyWithCoexistenceError::CarveoutOrderingViolation(err) => {
                    BrokerError::CarveoutOrderingViolation(match err {
                        d2b_host::nftables::NftError::ForeignNftRuleShadowsD2b { details } => {
                            details
                        }
                        other => other.to_string(),
                    })
                }
                crate::ops::nft::ApplyWithCoexistenceError::DriftDetected {
                    expected,
                    observed,
                } => BrokerError::NftablesDriftDetected { expected, observed },
                crate::ops::nft::ApplyWithCoexistenceError::ForeignOwnership => {
                    BrokerError::LiveHandler("foreign-nft-ownership".to_owned())
                }
                crate::ops::nft::ApplyWithCoexistenceError::ReconcileExec(err) => {
                    BrokerError::LiveHandler(err.to_string())
                }
            })?;
            crate::ops::nft::persist_live_nft_hash(
                &exec,
                &nft_binary,
                &resolver.host.nftables.family,
                &resolver.host.nftables.table,
                &nft_hash_sidecar_path(),
            )
            .map_err(|err| BrokerError::LiveHandler(err.to_string()))?;

            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "UsbipExplicitFirewallRule",
                req.bus_id.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                req.bus_id.as_str(),
                &format!("env:{}", req.env),
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::UsbipExplicitFirewallRule {
                    bus_id: req.bus_id.clone(),
                    env: req.env.clone(),
                },
            )?;
            Ok(DispatchResult::no_fds(ack_response(
                "UsbipExplicitFirewallRule",
            )))
        }
        // Disk-init dispatch. The broker resolves every `DiskInit`
        // plan-op from the trusted bundle for `vm_id` and creates the
        // disk images before the caller issues SpawnRunner. No
        // caller-supplied paths: the bundle is the only source of
        // `target_path`, `size_bytes`, `mode`, `owner_uid`, `owner_gid`.
        RealBrokerRequest::DiskInit(req) => {
            let resolver = require_resolver(resolver)?;
            let vm_name = lookup_vm_name(resolver, &req.vm_id);
            let summary = crate::ops::disk_init::live_disk_init(resolver.as_ref(), &vm_name)
                .map_err(|e| BrokerError::LiveHandler(e.to_string()))?;
            write_success_op_record!(
                audit_log,
                bundle_metadata,
                "DiskInit",
                vm_name.as_str(),
                caller_uid,
                caller_gid,
                &caller_role,
                vm_name.as_str(),
                "host",
                tracing_span_id_str(req.tracing_span_id.as_ref()),
                OperationFields::DiskInit {
                    vm_id: vm_name.clone(),
                    ops_total: summary.ops_total,
                    ops_created: summary.ops_created,
                    ops_skipped: summary.ops_skipped,
                    ops_repaired: Some(summary.ops_repaired),
                    ops_posture_repaired: Some(summary.ops_posture_repaired),
                    target_paths_hash: summary.target_paths_hash,
                },
            )?;
            Ok(DispatchResult::no_fds(ack_response("DiskInit")))
        }
    }
}

#[derive(Clone, Copy)]
struct AuditBundleMetadata<'a> {
    bundle_version: &'a str,
    bundle_hash: &'a str,
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn audit_bundle_metadata(resolver: Option<&BundleResolver>) -> AuditBundleMetadata<'_> {
    match resolver {
        Some(resolver) => AuditBundleMetadata {
            bundle_version: resolver.audit_bundle_version(),
            bundle_hash: resolver.audit_bundle_hash(),
        },
        None => AuditBundleMetadata {
            bundle_version: "unknown",
            bundle_hash: "",
        },
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn caller_role_authz_result(caller_role: &CallerRole) -> &'static str {
    match caller_role {
        CallerRole::AdminUid { .. } | CallerRole::RootUid { .. } => "admin",
        CallerRole::LauncherUid { .. } => "launcher",
        CallerRole::HostShutdownUid { .. } => "host-shutdown",
        CallerRole::NotAuthorized => "deny",
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn audit_timestamp_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(not(feature = "layer1-bootstrap"))]
#[allow(clippy::too_many_arguments)]
fn write_decision_op_record_impl(
    audit_log: &AuditLog,
    bundle_metadata: AuditBundleMetadata<'_>,
    operation: &str,
    public_operation_id: &str,
    peer_uid: u32,
    peer_gid: u32,
    caller_role: &CallerRole,
    subject_id: &str,
    scope_id: &str,
    tracing_span_id: Option<&str>,
    decision: &str,
    error_kind: Option<&str>,
    operation_fields: OperationFields,
    audit_context: &DispatchAuditContext,
) -> Result<(), BrokerError> {
    let operation_fields = serde_json::to_value(&operation_fields).map_err(|err| {
        BrokerError::Protocol(format!("serialize {operation} audit fields: {err}"))
    })?;
    let event_id = new_event_id()
        .map_err(|err| BrokerError::Protocol(format!("generate audit event id: {err}")))?;
    let (zone_id, operation_identity, public_operation_id) = if let Some(join) =
        audit_context.audit_join.as_ref()
    {
        let zone_id = d2b_audit::ZoneId::parse(join.zone_id.as_str())
            .map_err(|_| BrokerError::Protocol("audit zone identity invalid".to_owned()))?;
        let operation_identity = d2b_audit::OperationIdentity::parse(
            join.operation_identity.as_str(),
        )
        .map_err(|_| BrokerError::Protocol("audit operation identity invalid".to_owned()))?;
        let public_operation_id = operation_identity.as_str().to_owned();
        (zone_id, operation_identity, public_operation_id)
    } else {
        let zone_id = d2b_audit::ZoneId::derive(scope_id)
            .map_err(|_| BrokerError::Protocol("audit zone identity invalid".to_owned()))?;
        let operation_identity = d2b_audit::OperationIdentity::derive(public_operation_id)
            .map_err(|_| BrokerError::Protocol("audit operation identity invalid".to_owned()))?;
        (zone_id, operation_identity, public_operation_id.to_owned())
    };
    let record = OpAuditRecord {
        record_class: BrokerAuditRecordClass::Durability,
        ts_ms: audit_timestamp_ms(),
        broker_version: BROKER_VERSION,
        bundle_version: bundle_metadata.bundle_version,
        bundle_hash: bundle_metadata.bundle_hash,
        operation,
        public_operation_id: &public_operation_id,
        zone_id: &zone_id,
        operation_identity: &operation_identity,
        event_id: event_id.as_str(),
        peer_uid,
        peer_gid,
        peer_pid: audit_context.peer_pid,
        peer_role: audit_context.peer_role.as_str(),
        authz_result: caller_role_authz_result(caller_role),
        subject_id,
        scope_id,
        verb: audit_context.verb.as_str(),
        request_fields: audit_context.request_fields.clone(),
        decision,
        result: result_for_decision(decision),
        error_kind,
        tracing_span_id,
        duration_us: audit_context.duration_us(),
        operation_fields: Some(operation_fields),
        zone_operation_key: d2b_audit::ZoneOperationKey::new(
            zone_id.clone(),
            operation_identity.clone(),
        ),
    };
    audit_log
        .write_op_record(&record)
        .map_err(|err| BrokerError::Protocol(err.to_string()))
}

#[cfg(not(feature = "layer1-bootstrap"))]
#[allow(clippy::too_many_arguments)]
fn write_success_op_record_impl(
    audit_log: &AuditLog,
    bundle_metadata: AuditBundleMetadata<'_>,
    operation: &str,
    public_operation_id: &str,
    peer_uid: u32,
    peer_gid: u32,
    caller_role: &CallerRole,
    subject_id: &str,
    scope_id: &str,
    tracing_span_id: Option<&str>,
    operation_fields: OperationFields,
    audit_context: &DispatchAuditContext,
) -> Result<(), BrokerError> {
    write_decision_op_record_impl(
        audit_log,
        bundle_metadata,
        operation,
        public_operation_id,
        peer_uid,
        peer_gid,
        caller_role,
        subject_id,
        scope_id,
        tracing_span_id,
        "allowed",
        None,
        operation_fields,
        audit_context,
    )
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn activation_mode_name(mode: d2b_contracts_broker::broker_wire::ActivationMode) -> &'static str {
    match mode {
        d2b_contracts_broker::broker_wire::ActivationMode::Switch => "switch",
        d2b_contracts_broker::broker_wire::ActivationMode::Boot => "boot",
        d2b_contracts_broker::broker_wire::ActivationMode::Test => "test",
        d2b_contracts_broker::broker_wire::ActivationMode::Rollback => "rollback",
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn runner_signal_name(signal: d2b_contracts_broker::broker_wire::RunnerSignal) -> &'static str {
    match signal {
        d2b_contracts_broker::broker_wire::RunnerSignal::Term => "term",
        d2b_contracts_broker::broker_wire::RunnerSignal::Kill => "kill",
        d2b_contracts_broker::broker_wire::RunnerSignal::Quit => "quit",
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn systemd_domain_name(
    domain: d2b_contracts_broker::broker_wire::SystemdUnitDomain,
) -> &'static str {
    match domain {
        d2b_contracts_broker::broker_wire::SystemdUnitDomain::System => "system",
        d2b_contracts_broker::broker_wire::SystemdUnitDomain::User => "user",
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn runner_signal_number(signal: d2b_contracts_broker::broker_wire::RunnerSignal) -> i32 {
    match signal {
        d2b_contracts_broker::broker_wire::RunnerSignal::Term => libc::SIGTERM,
        d2b_contracts_broker::broker_wire::RunnerSignal::Kill => libc::SIGKILL,
        d2b_contracts_broker::broker_wire::RunnerSignal::Quit => libc::SIGQUIT,
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
const LIFECYCLE_LEASE_TTL_MS: u64 = 300_000;

#[cfg(not(feature = "layer1-bootstrap"))]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct LifecycleLeaseIdentity {
    zone_uid: String,
    guest_uid: String,
    guest_generation: u64,
    provider_assignment_generation: u64,
    policy_revision: u64,
    operation_id: String,
    operation: String,
    stop_only: bool,
}

#[cfg(not(feature = "layer1-bootstrap"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LifecycleLeaseState {
    Consumed,
    Completed,
}

#[cfg(not(feature = "layer1-bootstrap"))]
#[derive(Debug, Clone, Copy)]
struct LifecycleLeaseRecord {
    state: LifecycleLeaseState,
    expires_at_ms: u64,
    completed_at_ms: Option<u64>,
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn lifecycle_leases() -> &'static Mutex<BTreeMap<LifecycleLeaseIdentity, LifecycleLeaseRecord>> {
    static LEASES: OnceLock<Mutex<BTreeMap<LifecycleLeaseIdentity, LifecycleLeaseRecord>>> =
        OnceLock::new();
    LEASES.get_or_init(|| Mutex::new(BTreeMap::new()))
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn lifecycle_lease_identity(
    request: &d2b_contracts_broker::broker_wire::ConsumeLifecycleLeaseRequest,
) -> LifecycleLeaseIdentity {
    LifecycleLeaseIdentity {
        zone_uid: request.zone_uid.as_str().to_owned(),
        guest_uid: request.guest_uid.as_str().to_owned(),
        guest_generation: request.guest_generation,
        provider_assignment_generation: request.provider_assignment_generation,
        policy_revision: request.policy_revision,
        operation_id: request.operation_id.clone(),
        operation: format!("{:?}", request.operation),
        stop_only: request.stop_only,
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn lifecycle_lease_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn consume_lifecycle_lease(
    request: &d2b_contracts_broker::broker_wire::ConsumeLifecycleLeaseRequest,
    caller_role: &CallerRole,
) -> Result<(), BrokerError> {
    if request.guest_generation == 0
        || request.provider_assignment_generation == 0
        || request.policy_revision == 0
        || request.operation_id.is_empty()
        || request.operation_id.len() > 128
        || request.operation_id.chars().any(char::is_control)
    {
        return Err(BrokerError::LiveHandler(
            "lifecycle-lease-invalid".to_owned(),
        ));
    }
    let is_shutdown = matches!(caller_role, CallerRole::HostShutdownUid { .. });
    if request.stop_only != is_shutdown
        || (is_shutdown
            && !matches!(
                request.operation,
                d2b_contracts_broker::broker_wire::LifecycleLeaseOperation::Stop
            ))
    {
        return Err(BrokerError::HostShutdownRestricted);
    }
    if matches!(caller_role, CallerRole::NotAuthorized) {
        return Err(BrokerError::LiveHandler(
            "lifecycle-lease-caller-denied".to_owned(),
        ));
    }
    let now = lifecycle_lease_now_ms();
    let identity = lifecycle_lease_identity(request);
    let mut leases = lifecycle_leases()
        .lock()
        .map_err(|_| BrokerError::Protocol("lifecycle lease registry poisoned".to_owned()))?;
    leases.retain(|_, record| record.expires_at_ms > now);
    if let Some(record) = leases.get(&identity) {
        let detail = match record.state {
            LifecycleLeaseState::Consumed => "lifecycle-lease-in-progress",
            LifecycleLeaseState::Completed => "lifecycle-lease-replayed",
        };
        return Err(BrokerError::LiveHandler(detail.to_owned()));
    }
    leases.insert(
        identity,
        LifecycleLeaseRecord {
            state: LifecycleLeaseState::Consumed,
            expires_at_ms: now.saturating_add(LIFECYCLE_LEASE_TTL_MS),
            completed_at_ms: None,
        },
    );
    Ok(())
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn complete_lifecycle_lease(
    request: &d2b_contracts_broker::broker_wire::ConsumeLifecycleLeaseRequest,
) -> Result<(), BrokerError> {
    let now = lifecycle_lease_now_ms();
    let identity = lifecycle_lease_identity(request);
    let mut leases = lifecycle_leases()
        .lock()
        .map_err(|_| BrokerError::Protocol("lifecycle lease registry poisoned".to_owned()))?;
    let Some(record) = leases.get_mut(&identity) else {
        return Err(BrokerError::Protocol(
            "lifecycle lease completion record missing".to_owned(),
        ));
    };
    record.state = LifecycleLeaseState::Completed;
    record.completed_at_ms = Some(now);
    record.expires_at_ms = now.saturating_add(LIFECYCLE_LEASE_TTL_MS);
    Ok(())
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn runner_pidfd_registry() -> &'static Mutex<HashMap<String, OwnedFd>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, OwnedFd>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn controller_bootstrap_registry() -> &'static Mutex<HashMap<String, OwnedFd>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, OwnedFd>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(not(feature = "layer1-bootstrap"))]
#[derive(Clone)]
struct RunnerRegistration {
    vm_id: String,
    role_id: String,
    resource_ref: Option<d2b_contracts_resource::v3::ResourceRef>,
    resource_uid: Option<d2b_contracts_resource::v3::ResourceUid>,
    zone_uid: Option<d2b_contracts_resource::v3::ResourceUid>,
    generation: Option<u64>,
    runtime_scope: Option<[u8; 32]>,
    owner_ref: Option<d2b_contracts_resource::v3::ResourceRef>,
    provider_ref: Option<d2b_contracts_resource::v3::ResourceRef>,
    provider_identity: Option<[u8; 32]>,
    template_identity: Option<[u8; 32]>,
    role: d2b_contracts_broker::broker_wire::RunnerRole,
    bundle_runner_intent_ref: String,
    pid: i32,
    start_time_ticks: u64,
    binary_path: PathBuf,
    cgroup_subtree: String,
    guest_execution: Option<d2b_contracts_broker::broker_wire::GuestExecutionBinding>,
}

#[cfg(not(feature = "layer1-bootstrap"))]
impl std::fmt::Debug for RunnerRegistration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RunnerRegistration(<redacted>)")
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn runner_metadata_registry() -> &'static Mutex<HashMap<String, RunnerRegistration>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, RunnerRegistration>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn register_runner_metadata(
    runner_id: &str,
    request: &d2b_contracts_broker::broker_wire::SpawnRunnerRequest,
    intent: &d2b_core::bundle_resolver::ResolvedRunnerIntent,
    pid: i32,
    start_time_ticks: u64,
) -> Result<(), BrokerError> {
    let cgroup_placement = private_cgroup_placement(
        &intent.cgroup_placement,
        request.vm_id.as_str(),
        request.runtime_scope,
        request.resource_ref.is_some(),
    )?;
    let mut registry = runner_metadata_registry()
        .lock()
        .map_err(|_| BrokerError::Protocol("runner metadata registry mutex poisoned".to_owned()))?;
    registry.insert(
        runner_id.to_owned(),
        RunnerRegistration {
            vm_id: request.vm_id.as_str().to_owned(),
            role_id: request.role_id.as_str().to_owned(),
            resource_ref: request.resource_ref.clone(),
            resource_uid: request.resource_uid.clone(),
            zone_uid: request.zone_uid.clone(),
            generation: request.generation,
            runtime_scope: request.runtime_scope,
            owner_ref: request.owner_ref.clone(),
            provider_ref: request.provider_ref.clone(),
            provider_identity: request.provider_identity,
            template_identity: request.template_identity,
            role: request.role,
            bundle_runner_intent_ref: request.bundle_runner_intent_ref.as_str().to_owned(),
            pid,
            start_time_ticks,
            binary_path: intent.binary_path.clone(),
            cgroup_subtree: cgroup_placement.subtree,
            guest_execution: request.guest_execution.clone(),
        },
    );
    Ok(())
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn register_runner_metadata_from_open(
    runner_id: &str,
    request: &d2b_contracts_broker::broker_wire::OpenPidfdRequest,
    intent: &d2b_core::bundle_resolver::ResolvedRunnerIntent,
) -> Result<(), BrokerError> {
    let role = runner_role_for_process_role(&intent.role).ok_or_else(|| {
        BrokerError::SpawnRunnerIntentMismatch {
            field: "role",
            requested: request.role_id.as_str().to_owned(),
            resolved: format!("{:?}", intent.role),
        }
    })?;
    let cgroup_placement = private_cgroup_placement(
        &intent.cgroup_placement,
        request.vm_id.as_str(),
        request.runtime_scope,
        request.resource_ref.is_some(),
    )?;
    let mut registry = runner_metadata_registry()
        .lock()
        .map_err(|_| BrokerError::Protocol("runner metadata registry mutex poisoned".to_owned()))?;
    registry.insert(
        runner_id.to_owned(),
        RunnerRegistration {
            vm_id: request.vm_id.as_str().to_owned(),
            role_id: request.role_id.as_str().to_owned(),
            resource_ref: request.resource_ref.clone(),
            resource_uid: request.resource_uid.clone(),
            zone_uid: request.zone_uid.clone(),
            generation: request.generation,
            runtime_scope: request.runtime_scope,
            owner_ref: request.owner_ref.clone(),
            provider_ref: request.provider_ref.clone(),
            provider_identity: request.provider_identity,
            template_identity: request.template_identity,
            role,
            bundle_runner_intent_ref: intent.intent_id.clone(),
            pid: request.pid,
            start_time_ticks: request.expected_start_time_ticks,
            binary_path: intent.binary_path.clone(),
            cgroup_subtree: cgroup_placement.subtree,
            guest_execution: request.guest_execution.clone(),
        },
    );
    Ok(())
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn runner_registry_key(
    vm_id: &str,
    role_id: &str,
    resource_ref: Option<&d2b_contracts_resource::v3::ResourceRef>,
    resource_uid: Option<&d2b_contracts_resource::v3::ResourceUid>,
    zone_uid: Option<&d2b_contracts_resource::v3::ResourceUid>,
    runtime_scope: Option<[u8; 32]>,
) -> String {
    match (resource_ref, resource_uid, zone_uid, runtime_scope) {
        (Some(_), Some(_), Some(_), Some(runtime_scope)) => {
            let mut rendered = String::with_capacity(64);
            for byte in runtime_scope {
                rendered.push_str(&format!("{byte:02x}"));
            }
            format!("scope:{rendered}")
        }
        _ => format!("{vm_id}:{role_id}"),
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn runner_intent_id_for_open_pidfd(vm_id: &str, role_id: &str) -> String {
    let process_role_id = match role_id {
        "ch-runner" => "cloud-hypervisor",
        other => other,
    };
    d2b_core::bundle_resolver::intent_id_legacy_runner(vm_id, process_role_id)
}

#[cfg(not(feature = "layer1-bootstrap"))]
#[allow(clippy::too_many_arguments)]
fn registration_matches(
    registration: &RunnerRegistration,
    resource_ref: Option<&d2b_contracts_resource::v3::ResourceRef>,
    resource_uid: Option<&d2b_contracts_resource::v3::ResourceUid>,
    pid: Option<i32>,
    start_time_ticks: Option<u64>,
    zone_uid: Option<&d2b_contracts_resource::v3::ResourceUid>,
    generation: Option<u64>,
    runtime_scope: Option<[u8; 32]>,
    owner_ref: Option<&d2b_contracts_resource::v3::ResourceRef>,
    provider_ref: Option<&d2b_contracts_resource::v3::ResourceRef>,
    provider_identity: Option<[u8; 32]>,
    template_identity: Option<[u8; 32]>,
    guest_execution: Option<&d2b_contracts_broker::broker_wire::GuestExecutionBinding>,
) -> bool {
    let strict = resource_ref.is_some();
    let owner_matches = if strict {
        registration.owner_ref.as_ref() == owner_ref
    } else {
        owner_ref.is_none_or(|owner| registration.owner_ref.as_ref() == Some(owner))
    };
    let provider_ref_matches = if strict {
        registration.provider_ref.as_ref() == provider_ref
    } else {
        provider_ref.is_none_or(|provider| registration.provider_ref.as_ref() == Some(provider))
    };
    let provider_identity_matches = if strict {
        registration.provider_identity == provider_identity
    } else {
        provider_identity.is_none_or(|identity| registration.provider_identity == Some(identity))
    };
    let template_identity_matches = if strict {
        registration.template_identity == template_identity
    } else {
        template_identity.is_none_or(|identity| registration.template_identity == Some(identity))
    };
    registration.resource_ref.as_ref() == resource_ref
        && registration.resource_uid.as_ref() == resource_uid
        && pid.is_none_or(|pid| registration.pid == pid)
        && start_time_ticks.is_none_or(|ticks| registration.start_time_ticks == ticks)
        && registration.zone_uid.as_ref() == zone_uid
        && generation.is_none_or(|generation| registration.generation == Some(generation))
        && runtime_scope.is_none_or(|scope| registration.runtime_scope == Some(scope))
        && owner_matches
        && provider_ref_matches
        && provider_identity_matches
        && template_identity_matches
        && registration.guest_execution.as_ref() == guest_execution
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn rebind_guest_execution_registration(
    registration: &mut RunnerRegistration,
    requested: Option<&d2b_contracts_broker::broker_wire::GuestExecutionBinding>,
) -> Result<bool, BrokerError> {
    if requested.is_some_and(|binding| !binding.is_valid()) {
        return Err(BrokerError::LiveHandler(
            "guest runner execution binding changed".to_owned(),
        ));
    }
    if registration.guest_execution.as_ref() == requested {
        return Ok(false);
    }

    let (Some(current), Some(next)) = (registration.guest_execution.as_ref(), requested) else {
        return Err(BrokerError::LiveHandler(
            "guest runner execution binding changed".to_owned(),
        ));
    };
    if current.target_uid != next.target_uid
        || current.boot_identity_digest != next.boot_identity_digest
        || current.assignment_epoch != next.assignment_epoch
        || current.provider_generation != next.provider_generation
        || current.controller_generation != next.controller_generation
    {
        return Err(BrokerError::LiveHandler(
            "guest runner execution binding changed".to_owned(),
        ));
    }
    if next.session_generation <= current.session_generation {
        return Err(BrokerError::LiveHandler(
            "guest runner session generation is not newer".to_owned(),
        ));
    }

    registration.guest_execution = Some(next.clone());
    Ok(true)
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn remove_runner_metadata(runner_id: &str) {
    if let Ok(mut registry) = runner_metadata_registry().lock() {
        registry.remove(runner_id);
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn observe_registered_runner(
    request: &d2b_contracts_broker::broker_wire::ObserveRunnerRequest,
    intent: &d2b_core::bundle_resolver::ResolvedRunnerIntent,
) -> Result<d2b_contracts_broker::broker_wire::ObserveRunnerResponse, BrokerError> {
    let cgroup_placement = private_cgroup_placement(
        &intent.cgroup_placement,
        request.vm_id.as_str(),
        request.runtime_scope,
        request.resource_ref.is_some(),
    )?;
    let runner_id = runner_registry_key(
        request.vm_id.as_str(),
        request.role_id.as_str(),
        request.resource_ref.as_ref(),
        request.resource_uid.as_ref(),
        request.zone_uid.as_ref(),
        request.runtime_scope,
    );
    let registered = (|| -> Result<
        Option<d2b_contracts_broker::broker_wire::ObserveRunnerResponse>,
        BrokerError,
    > {
        // Keep the lock order aligned with deregistration: pidfd registry
        // first, metadata second. This makes the binding update atomic with
        // the live pidfd registration.
        let pidfd_registry = runner_pidfd_registry().lock().map_err(|_| {
            BrokerError::Protocol("runner pidfd registry mutex poisoned".to_owned())
        })?;
        let mut metadata_registry = runner_metadata_registry().lock().map_err(|_| {
            BrokerError::Protocol("runner metadata registry mutex poisoned".to_owned())
        })?;
        let registration = match metadata_registry.get(&runner_id).cloned() {
            Some(registration) => registration,
            None => return Ok(None),
        };
        let mut observed_registration = registration.clone();
        let rebound = rebind_guest_execution_registration(
            &mut observed_registration,
            request.guest_execution.as_ref(),
        )?;
        let pidfd_registered = pidfd_registry.contains_key(&runner_id);
        if !pidfd_registered
            || observed_registration.vm_id != request.vm_id.as_str()
            || observed_registration.role_id != request.role_id.as_str()
            || observed_registration.role != request.role
            || !registration_matches(
                &observed_registration,
                request.resource_ref.as_ref(),
                request.resource_uid.as_ref(),
                None,
                None,
                request.zone_uid.as_ref(),
                request.generation,
                request.runtime_scope,
                request.owner_ref.as_ref(),
                request.provider_ref.as_ref(),
                request.provider_identity,
                request.template_identity,
                request.guest_execution.as_ref(),
            )
            || observed_registration.bundle_runner_intent_ref
                != request.bundle_runner_intent_ref.as_str()
            || observed_registration.pid <= 0
            || observed_registration.start_time_ticks == 0
            || observed_registration.binary_path != intent.binary_path
            || observed_registration.cgroup_subtree != cgroup_placement.subtree
        {
            Ok(None)
        } else {
            let Some(start_time_ticks) = read_proc_start_time_ticks(observed_registration.pid)?
            else {
                let pidfd = duplicate_runner_pidfd(&pidfd_registry, &runner_id);
                drop(metadata_registry);
                drop(pidfd_registry);
                return Ok(Some(
                    reap_registered_runner_after_observation(
                        request,
                        &runner_id,
                        &observed_registration,
                        pidfd,
                    ),
                ));
            };
            if start_time_ticks != observed_registration.start_time_ticks {
                return Err(BrokerError::LiveHandler(
                    "runner process identity changed".to_owned(),
                ));
            }
            let cgroup_verified = proc_cgroup_matches(
                observed_registration.pid,
                &observed_registration.cgroup_subtree,
            );
            let executable_observation = observe_runner_executable(
                read_runner_executable(observed_registration.pid),
                &observed_registration.binary_path,
            )?;
            if executable_observation == RunnerExecutableObservation::Vanished {
                let pidfd = duplicate_runner_pidfd(&pidfd_registry, &runner_id);
                drop(metadata_registry);
                drop(pidfd_registry);
                return Ok(Some(
                    reap_registered_runner_after_observation(
                        request,
                        &runner_id,
                        &observed_registration,
                        pidfd,
                    ),
                ));
            }
            let Some(current_start_time_ticks) =
                read_proc_start_time_ticks(observed_registration.pid)?
            else {
                let pidfd = duplicate_runner_pidfd(&pidfd_registry, &runner_id);
                drop(metadata_registry);
                drop(pidfd_registry);
                return Ok(Some(
                    reap_registered_runner_after_observation(
                        request,
                        &runner_id,
                        &observed_registration,
                        pidfd,
                    ),
                ));
            };
            if current_start_time_ticks != start_time_ticks {
                return Err(BrokerError::LiveHandler(
                    "runner process identity changed".to_owned(),
                ));
            }
            let executable_verified =
                executable_observation.is_verified_for_registered(pidfd_registered, cgroup_verified);
            if pidfd_registered && cgroup_verified && executable_verified {
                tracing::debug!(
                    runner_id,
                    pid = observed_registration.pid,
                    "ObserveRunner found a verified registered runner",
                );
            } else {
                tracing::warn!(
                    runner_id,
                    pid = observed_registration.pid,
                    pidfd_registered,
                    cgroup_verified,
                    executable_verified,
                    "ObserveRunner registered runner verification is incomplete",
                );
            }
            if rebound {
                if let Some(stored) = metadata_registry.get_mut(&runner_id) {
                    stored.guest_execution = observed_registration.guest_execution.clone();
                } else {
                    return Err(BrokerError::LiveHandler(
                        "runner registration disappeared".to_owned(),
                    ));
                }
            }
            Ok(Some(
                d2b_contracts_broker::broker_wire::ObserveRunnerResponse {
                    vm_id: request.vm_id.clone(),
                    role_id: request.role_id.clone(),
                    present: true,
                    pid: observed_registration.pid,
                    start_time_ticks,
                    cgroup_verified,
                    executable_verified,
                },
            ))
        }
    })()?;
    registered.map_or_else(
        || discover_runner_candidate(request, intent, &cgroup_placement.subtree),
        Ok,
    )
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn discover_runner_candidate(
    request: &d2b_contracts_broker::broker_wire::ObserveRunnerRequest,
    intent: &d2b_core::bundle_resolver::ResolvedRunnerIntent,
    cgroup_subtree: &str,
) -> Result<d2b_contracts_broker::broker_wire::ObserveRunnerResponse, BrokerError> {
    let mut candidates = Vec::new();
    let entries =
        fs::read_dir("/proc").map_err(|error| BrokerError::LiveHandler(error.to_string()))?;
    for entry in entries {
        let entry = entry.map_err(|error| BrokerError::LiveHandler(error.to_string()))?;
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|value| value.parse::<i32>().ok()) else {
            continue;
        };
        let cgroup_verified = pid > 0 && proc_cgroup_matches(pid, cgroup_subtree);
        if !cgroup_verified {
            continue;
        }
        let Some(start_time_ticks) = read_proc_start_time_ticks(pid)? else {
            continue;
        };
        if start_time_ticks == 0 {
            continue;
        }
        let executable_observation =
            observe_runner_executable(read_runner_executable(pid), &intent.binary_path)?;
        if executable_observation == RunnerExecutableObservation::Vanished {
            continue;
        }
        let Some(current_start_time_ticks) = read_proc_start_time_ticks(pid)? else {
            continue;
        };
        if current_start_time_ticks != start_time_ticks {
            continue;
        }
        let executable_verified = executable_observation.is_verified_for_discovery();
        candidates.push((pid, start_time_ticks, executable_verified));
    }
    if !candidates.is_empty() {
        tracing::warn!(
            cgroup_subtree,
            candidate_count = candidates.len(),
            candidate_pids = ?candidates
                .iter()
                .map(|(pid, _, _)| *pid)
                .collect::<Vec<_>>(),
            executable_verified = ?candidates
                .iter()
                .map(|(_, _, verified)| *verified)
                .collect::<Vec<_>>(),
            "ObserveRunner discovered unregistered cgroup candidates",
        );
    }
    let Some((pid, start_time_ticks, executable_verified)) = select_runner_candidate(candidates)?
    else {
        return Ok(absent_runner_response(request));
    };
    Ok(d2b_contracts_broker::broker_wire::ObserveRunnerResponse {
        vm_id: request.vm_id.clone(),
        role_id: request.role_id.clone(),
        present: true,
        pid,
        start_time_ticks,
        cgroup_verified: true,
        executable_verified,
    })
}

#[cfg(not(feature = "layer1-bootstrap"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunnerExecutableObservation {
    Matching,
    Mismatch,
    PermissionDenied,
    Vanished,
}

#[cfg(not(feature = "layer1-bootstrap"))]
impl RunnerExecutableObservation {
    fn is_verified(self, broker_owned_provenance: bool) -> bool {
        match self {
            Self::Matching => true,
            Self::PermissionDenied => broker_owned_provenance,
            Self::Mismatch | Self::Vanished => false,
        }
    }

    fn is_verified_for_discovery(self) -> bool {
        self.is_verified(false)
    }

    fn is_verified_for_registered(self, pidfd_registered: bool, cgroup_verified: bool) -> bool {
        self.is_verified(pidfd_registered && cgroup_verified)
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn observe_runner_executable(
    executable: io::Result<PathBuf>,
    expected: &Path,
) -> Result<RunnerExecutableObservation, BrokerError> {
    match executable {
        Ok(path) => Ok(classify_executable_path(&path, expected)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Ok(RunnerExecutableObservation::Vanished)
        }
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            Ok(RunnerExecutableObservation::PermissionDenied)
        }
        Err(error) => Err(BrokerError::LiveHandler(error.to_string())),
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn classify_executable_path(actual: &Path, expected: &Path) -> RunnerExecutableObservation {
    let actual = match fs::canonicalize(actual) {
        Ok(actual) => actual,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            return RunnerExecutableObservation::PermissionDenied;
        }
        Err(_) => return RunnerExecutableObservation::Mismatch,
    };
    let Some(expected) = fs::canonicalize(expected).ok() else {
        return RunnerExecutableObservation::Mismatch;
    };
    if actual == expected {
        return RunnerExecutableObservation::Matching;
    }

    let Ok(script) = fs::read_to_string(&expected) else {
        return RunnerExecutableObservation::Mismatch;
    };
    if !script.starts_with("#!") {
        return RunnerExecutableObservation::Mismatch;
    }
    let mut target = None;
    for line in script.lines().map(str::trim) {
        let Some(exec) = line.strip_prefix("exec \"$here/") else {
            continue;
        };
        let Some((relative, _)) = exec.split_once('"') else {
            return RunnerExecutableObservation::Mismatch;
        };
        let relative_path = Path::new(relative);
        if relative.is_empty()
            || relative.contains('$')
            || relative_path
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return RunnerExecutableObservation::Mismatch;
        }
        let Some(parent) = expected.parent() else {
            return RunnerExecutableObservation::Mismatch;
        };
        if target.replace(parent.join(relative_path)).is_some() {
            return RunnerExecutableObservation::Mismatch;
        }
    }
    if target
        .and_then(|target| fs::canonicalize(target).ok())
        .is_some_and(|target| target == actual)
    {
        RunnerExecutableObservation::Matching
    } else {
        RunnerExecutableObservation::Mismatch
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn executable_paths_match(actual: &Path, expected: &Path) -> bool {
    classify_executable_path(actual, expected) == RunnerExecutableObservation::Matching
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn duplicate_runner_pidfd(registry: &HashMap<String, OwnedFd>, runner_id: &str) -> Option<OwnedFd> {
    let pidfd = registry.get(runner_id)?;
    match dup(pidfd.as_raw_fd()).map(owned_fd_from_raw) {
        Ok(pidfd) => Some(pidfd),
        Err(error) => {
            warn!(runner_id = %runner_id, error = %error, "duplicate runner pidfd failed");
            None
        }
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn present_unverified_runner_response(
    request: &d2b_contracts_broker::broker_wire::ObserveRunnerRequest,
    registration: &RunnerRegistration,
) -> d2b_contracts_broker::broker_wire::ObserveRunnerResponse {
    d2b_contracts_broker::broker_wire::ObserveRunnerResponse {
        vm_id: request.vm_id.clone(),
        role_id: request.role_id.clone(),
        present: true,
        pid: registration.pid,
        start_time_ticks: registration.start_time_ticks,
        cgroup_verified: false,
        executable_verified: false,
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn reap_registered_runner_after_observation(
    request: &d2b_contracts_broker::broker_wire::ObserveRunnerRequest,
    runner_id: &str,
    registration: &RunnerRegistration,
    pidfd: Option<OwnedFd>,
) -> d2b_contracts_broker::broker_wire::ObserveRunnerResponse {
    let Some(pidfd) = pidfd else {
        return present_unverified_runner_response(request, registration);
    };
    match targeted_reap_runner(runner_id, pidfd.as_fd()) {
        TargetedReapOutcome::Reaped | TargetedReapOutcome::AlreadyReaped => {
            absent_runner_response(request)
        }
        TargetedReapOutcome::StillAlive | TargetedReapOutcome::Failed => {
            present_unverified_runner_response(request, registration)
        }
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn absent_runner_response(
    request: &d2b_contracts_broker::broker_wire::ObserveRunnerRequest,
) -> d2b_contracts_broker::broker_wire::ObserveRunnerResponse {
    d2b_contracts_broker::broker_wire::ObserveRunnerResponse {
        vm_id: request.vm_id.clone(),
        role_id: request.role_id.clone(),
        present: false,
        pid: 0,
        start_time_ticks: 0,
        cgroup_verified: false,
        executable_verified: false,
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn select_runner_candidate(
    candidates: impl IntoIterator<Item = (i32, u64, bool)>,
) -> Result<Option<(i32, u64, bool)>, BrokerError> {
    let mut candidate = None;
    for next in candidates {
        if candidate.replace(next).is_some() {
            return Err(BrokerError::LiveHandler(
                "runner adoption candidate ambiguous".to_owned(),
            ));
        }
    }
    Ok(candidate)
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn read_runner_executable(pid: i32) -> io::Result<PathBuf> {
    fs::read_link(format!("/proc/{pid}/exe"))
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn read_proc_start_time_ticks(pid: i32) -> Result<Option<u64>, BrokerError> {
    let content = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(BrokerError::LiveHandler(error.to_string())),
    };
    let close = content
        .trim_end_matches('\n')
        .rfind(')')
        .ok_or_else(|| BrokerError::LiveHandler("malformed proc stat".to_owned()))?;
    let mut fields = content[close + 1..].split_whitespace();
    let state = fields
        .next()
        .ok_or_else(|| BrokerError::LiveHandler("malformed proc stat".to_owned()))?;
    if matches!(state, "Z" | "X") {
        return Ok(None);
    }
    fields
        .nth(18)
        .ok_or_else(|| BrokerError::LiveHandler("malformed proc stat".to_owned()))?
        .parse::<u64>()
        .map(Some)
        .map_err(|_| BrokerError::LiveHandler("invalid proc start time".to_owned()))
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn proc_cgroup_matches(pid: i32, expected_subtree: &str) -> bool {
    if expected_subtree.is_empty() {
        return false;
    }
    let Ok(content) = fs::read_to_string(format!("/proc/{pid}/cgroup")) else {
        return false;
    };
    let expected = expected_subtree.trim_start_matches('/');
    content.lines().any(|line| {
        let Some((_, path)) = line.split_once("::") else {
            return false;
        };
        let actual = path.trim_start_matches('/');
        actual == expected || actual.ends_with(&format!("/{expected}"))
    })
}

/// In-memory ring buffer for `ChildReaped` notifications.
/// Capped at 256 entries (oldest dropped on overflow). Protected by
/// a `std::sync::Mutex` so both the tokio reap task and the synchronous
/// accept loop can access it safely.
#[cfg(not(feature = "layer1-bootstrap"))]
fn child_reap_buffer() -> &'static Mutex<
    std::collections::VecDeque<d2b_contracts_broker::broker_wire::ChildReapedNotification>,
> {
    use std::collections::VecDeque;

    static BUFFER: OnceLock<
        Mutex<VecDeque<d2b_contracts_broker::broker_wire::ChildReapedNotification>>,
    > = OnceLock::new();
    BUFFER.get_or_init(|| Mutex::new(VecDeque::with_capacity(256)))
}

#[cfg(not(feature = "layer1-bootstrap"))]
const CHILD_REAP_BUFFER_CAP: usize = 256;

/// Push one notification to the ring buffer.
/// If the buffer is full, drops the oldest entry and logs a warning.
#[cfg(not(feature = "layer1-bootstrap"))]
fn push_child_reap_notification(notif: d2b_contracts_broker::broker_wire::ChildReapedNotification) {
    let mut buf = match child_reap_buffer().lock() {
        Ok(g) => g,
        Err(_) => {
            tracing::warn!("child_reap_buffer mutex poisoned; dropping ChildReaped notification");
            return;
        }
    };
    if buf.len() >= CHILD_REAP_BUFFER_CAP {
        let dropped = buf.pop_front();
        tracing::warn!(
            dropped_runner_id = dropped
                .as_ref()
                .map(|d| d.runner_id.as_str())
                .unwrap_or("?"),
            "child_reap_buffer overflow: dropped oldest ChildReaped event"
        );
    }
    buf.push_back(notif);
}

/// Drain the ring buffer (used by PollChildReaped handler).
#[cfg(not(feature = "layer1-bootstrap"))]
fn drain_child_reap_buffer() -> Vec<d2b_contracts_broker::broker_wire::ChildReapedNotification> {
    match child_reap_buffer().lock() {
        Ok(mut buf) => buf.drain(..).collect(),
        Err(_) => {
            tracing::warn!("child_reap_buffer mutex poisoned; returning empty drain");
            Vec::new()
        }
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn register_runner_pidfd(runner_id: &str, pidfd: &OwnedFd) -> Result<(), BrokerError> {
    let duplicated = dup(pidfd.as_raw_fd())
        .map(owned_fd_from_raw)
        .map_err(|err| BrokerError::Protocol(format!("dup pidfd for {runner_id}: {err}")))?;
    let mut registry = runner_pidfd_registry()
        .lock()
        .map_err(|_| BrokerError::Protocol("runner pidfd registry mutex poisoned".to_owned()))?;
    registry.insert(runner_id.to_owned(), duplicated);
    Ok(())
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn remove_runner_registration(runner_id: &str) {
    if let Ok(mut registry) = runner_pidfd_registry().lock() {
        registry.remove(runner_id);
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn remove_runner_registries(runner_id: &str) -> bool {
    // Keep this order aligned with observation and deregistration so reap
    // cleanup cannot deadlock with a concurrent registry update.
    let Ok(mut pidfd_registry) = runner_pidfd_registry().lock() else {
        return false;
    };
    let Ok(mut metadata_registry) = runner_metadata_registry().lock() else {
        return false;
    };
    pidfd_registry.remove(runner_id);
    metadata_registry.remove(runner_id);
    if let Ok(mut bootstrap_registry) = controller_bootstrap_registry().lock() {
        bootstrap_registry.remove(runner_id);
    }
    true
}

/// Refuse to start a SECOND live runner for an already-registered
/// `runner_id` (legacy `<vm>:<role>` or typed opaque runtime scope).
/// Checked BEFORE the child is spawned so a duplicate is never created:
/// rejecting AFTER the spawn would leak an
/// orphan child (a non-blocking targeted reap is a no-op for a live
/// process), and reaping that orphan would also pollute the existing
/// same-`runner_id` registry entry + push a spurious `ChildReaped` for the
/// live runner. A `runner_id` has at most one live registration - the
/// daemon serializes per-VM lifecycle (per-VM start flock + DAG) and a live
/// entry is cleared on exit (SIGCHLD reaper) or on down/stop - so a
/// legitimate re-spawn never collides here; a collision is a
/// concurrent/duplicate spawn and must fail closed. See issue #64
/// work-review (W1fu1/fu2).
#[cfg(not(feature = "layer1-bootstrap"))]
fn reserve_runner_id_for_spawn(runner_id: &str) -> Result<(), BrokerError> {
    let registry = runner_pidfd_registry()
        .lock()
        .map_err(|_| BrokerError::Protocol("runner pidfd registry mutex poisoned".to_owned()))?;
    if registry.contains_key(runner_id) {
        return Err(BrokerError::Protocol(format!(
            "runner {runner_id} already has an active registration; refusing duplicate spawn"
        )));
    }
    Ok(())
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn signal_registered_runner(
    runner_id: &str,
    signal: d2b_contracts_broker::broker_wire::RunnerSignal,
) -> Result<(), BrokerError> {
    let registry = runner_pidfd_registry()
        .lock()
        .map_err(|_| BrokerError::Protocol("runner pidfd registry mutex poisoned".to_owned()))?;
    let pidfd = registry
        .get(runner_id)
        .ok_or_else(|| BrokerError::NoPidfd {
            runner_id: runner_id.to_owned(),
        })?;
    crate::sys::pidfd_sys::pidfd_send_signal(pidfd.as_fd(), runner_signal_number(signal))
        .map_err(|err| BrokerError::LiveHandler(format!("pidfd_send_signal({runner_id}): {err}")))
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn tracing_span_id_str(
    tracing_span_id: Option<&d2b_contracts::types::TracingSpanId>,
) -> Option<&str> {
    tracing_span_id.map(d2b_contracts::types::TracingSpanId::as_str)
}

/// Maps a classified [`crate::ops::store_sync_audit::ErrorStage`] to the
/// stable header `error_kind` slug recorded on the terminal StoreSync
/// failure/denial audit record (ADR 0027). The full signed shape lives in
/// `operation_fields`; this slug is the coarse, greppable category.
#[cfg(not(feature = "layer1-bootstrap"))]
fn store_sync_error_kind(stage: crate::ops::store_sync_audit::ErrorStage) -> &'static str {
    use crate::ops::store_sync_audit::ErrorStage;
    match stage {
        ErrorStage::None => "store-sync-failed",
        ErrorStage::Authz => "store-sync-authz-denied",
        ErrorStage::Lock => "store-sync-lock-failed",
        ErrorStage::Probe => "store-sync-probe-failed",
        ErrorStage::Verify => "store-sync-verify-failed",
        ErrorStage::Stage => "store-sync-stage-failed",
        ErrorStage::Rename => "store-sync-rename-failed",
        ErrorStage::Metadata => "store-sync-metadata-failed",
        ErrorStage::Integrity => "store-sync-integrity-failed",
        ErrorStage::CurrentSwap => "store-sync-current-swap-failed",
        ErrorStage::Marker => "store-sync-marker-failed",
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
trait DispatchBackend {
    fn apply_nftables(
        &self,
        resolver: &BundleResolver,
        intent: &d2b_core::bundle_resolver::ResolvedNftIntent,
        desired_hash: Option<&str>,
        destroy: bool,
    ) -> Result<(), BrokerError>;

    fn apply_route(
        &self,
        state_dir: &Path,
        intent: &d2b_core::bundle_resolver::ResolvedRouteIntent,
        provenance: &d2b_contracts_resource::v3::NetworkProvenance,
        destroy: bool,
    ) -> Result<(), BrokerError>;

    fn apply_sysctl(
        &self,
        intent: &d2b_core::bundle_resolver::ResolvedSysctlIntent,
        destroy: bool,
    ) -> Result<(), BrokerError>;

    fn update_hosts_file(
        &self,
        intent: &d2b_core::bundle_resolver::ResolvedHostsIntent,
        destroy: bool,
    ) -> Result<(), BrokerError>;

    fn apply_nm_unmanaged(
        &self,
        intent: &d2b_core::bundle_resolver::ResolvedNmUnmanagedIntent,
        destroy: bool,
    ) -> Result<(), BrokerError>;

    fn prepare_store_view(
        &self,
        intent: &d2b_core::bundle_resolver::ResolvedStoreViewIntent,
    ) -> Result<crate::live_handlers::StoreViewOutcome, BrokerError>;

    fn set_bridge_port_flags(
        &self,
        req: &d2b_contracts_broker::broker_wire::SetBridgePortFlagsRequest,
        resolver: &BundleResolver,
    ) -> Result<d2b_contracts_broker::broker_wire::BridgePortFlagsResponse, BrokerError>;

    fn setup_mount_namespace(
        &self,
        vm_name: &str,
        role_id: &str,
        store_view_intent: &d2b_core::bundle_resolver::ResolvedStoreViewIntent,
    ) -> Result<crate::live_handlers::MountNamespaceOutcome, BrokerError>;

    fn open_pidfd(
        &self,
        runner_id: &str,
        pid: i32,
        expected_start_time_ticks: u64,
    ) -> Result<crate::live_handlers::OpenPidfdResult, BrokerError>;

    fn start_systemd_unit(
        &self,
        resolver: &BundleResolver,
        request: &d2b_contracts_broker::broker_wire::StartTransientUnitRequest,
    ) -> Result<
        (
            d2b_contracts_broker::broker_wire::SystemdUnitIdentity,
            OwnedFd,
        ),
        BrokerError,
    >;

    fn check_systemd_user_manager(
        &self,
        resolver: &BundleResolver,
        request: &d2b_contracts_broker::broker_wire::CheckSystemdUserManagerRequest,
    ) -> Result<bool, BrokerError>;

    fn observe_systemd_unit(
        &self,
        resolver: &BundleResolver,
        request: &d2b_contracts_broker::broker_wire::ObserveSystemdUnitRequest,
    ) -> Result<Option<d2b_contracts_broker::broker_wire::SystemdUnitIdentity>, BrokerError>;

    fn reopen_systemd_unit(
        &self,
        resolver: &BundleResolver,
        request: &d2b_contracts_broker::broker_wire::OpenSystemdUnitPidfdRequest,
    ) -> Result<
        (
            d2b_contracts_broker::broker_wire::SystemdUnitIdentity,
            OwnedFd,
        ),
        BrokerError,
    >;

    fn stop_systemd_unit(
        &self,
        resolver: &BundleResolver,
        request: &d2b_contracts_broker::broker_wire::StopSystemdUnitRequest,
    ) -> Result<(), BrokerError>;

    fn signal_runner(
        &self,
        runner_id: &str,
        signal: d2b_contracts_broker::broker_wire::RunnerSignal,
    ) -> Result<(), BrokerError>;

    fn spawn_runner(
        &self,
        runner_id: &str,
        plan_input: &crate::ops::spawn_runner::SpawnRunnerPlanInput,
        resolver: &BundleResolver,
        req: &d2b_contracts_broker::broker_wire::SpawnRunnerRequest,
        request_fds: Vec<OwnedFd>,
        audit_log: &crate::audit::AuditLog,
    ) -> Result<crate::live_handlers::SpawnRunnerResult, BrokerError>;

    fn run_host_install(
        &self,
        req: &d2b_contracts_broker::broker_wire::RunHostInstallRequest,
        resolver: Option<&BundleResolver>,
    ) -> Result<d2b_contracts_broker::broker_wire::RunHostInstallResponse, BrokerError>;

    fn run_migrate(
        &self,
        intent: &d2b_core::bundle_resolver::ResolvedMigrateIntent,
    ) -> Result<crate::live_handlers::MigrateOutcome, BrokerError>;

    fn run_activation(
        &self,
        intent: &d2b_core::bundle_resolver::ResolvedActivationIntent,
        store_view_intent: &d2b_core::bundle_resolver::ResolvedStoreViewIntent,
        phase: d2b_contracts_broker::broker_wire::ActivationPhase,
        mode: d2b_contracts_broker::broker_wire::ActivationMode,
    ) -> Result<crate::live_handlers::ActivationOutcome, BrokerError>;

    fn apply_host_generation_handoff(
        &self,
        state_dir: &std::path::Path,
        helper_path: &std::path::Path,
        request: &d2b_contracts_broker::host_generation::ApplyHostGenerationHandoff,
    ) -> Result<d2b_contracts_broker::broker_wire::ApplyHostGenerationHandoffResponse, BrokerError>;

    fn run_gc(
        &self,
        intent: &d2b_core::bundle_resolver::ResolvedGcIntent,
        keep_generations: Option<u32>,
    ) -> Result<crate::live_handlers::GcOutcome, BrokerError>;

    fn run_keys_rotate(
        &self,
        intent: &d2b_core::bundle_resolver::ResolvedKeysRotateIntent,
    ) -> Result<crate::live_handlers::KeysRotateOutcome, BrokerError>;

    fn run_host_key_trust(
        &self,
        intent: &d2b_core::bundle_resolver::ResolvedHostKeyTrustIntent,
    ) -> Result<crate::live_handlers::HostKeyTrustOutcome, BrokerError>;

    fn run_rotate_known_host(
        &self,
        intent: &d2b_core::bundle_resolver::ResolvedRotateKnownHostIntent,
    ) -> Result<crate::live_handlers::RotateKnownHostOutcome, BrokerError>;

    fn usbip_bind(
        &self,
        intent: &d2b_core::bundle_resolver::ResolvedUsbipBindIntent,
    ) -> Result<(), BrokerError>;

    fn usbip_unbind(
        &self,
        intent: &d2b_core::bundle_resolver::ResolvedUsbipBindIntent,
    ) -> Result<(), BrokerError>;

    fn usbip_bind_firewall_rule(
        &self,
        resolver: &BundleResolver,
        intent: &d2b_core::bundle_resolver::ResolvedUsbipFirewallIntent,
    ) -> Result<(), BrokerError>;

    fn usbip_proxy_reconcile(
        &self,
        expectations: &[(String, String, PathBuf)],
    ) -> Result<(), BrokerError>;

    fn qemu_media_system_powerdown(
        &self,
        req: &d2b_contracts_broker::broker_wire::QemuMediaLifecycleRequest,
    ) -> Result<d2b_contracts_broker::broker_wire::QemuMediaLifecycleResponse, BrokerError>;

    fn qemu_media_query_status(
        &self,
        req: &d2b_contracts_broker::broker_wire::QemuMediaQueryStatusRequest,
    ) -> Result<d2b_contracts_broker::broker_wire::QemuMediaQueryStatusResponse, BrokerError>;

    fn qemu_media_quit(
        &self,
        req: &d2b_contracts_broker::broker_wire::QemuMediaLifecycleRequest,
    ) -> Result<d2b_contracts_broker::broker_wire::QemuMediaLifecycleResponse, BrokerError>;
}

#[cfg(not(feature = "layer1-bootstrap"))]
struct LiveDispatchBackend {
    daemon_uid: u32,
    daemon_gid: u32,
    state_dir: PathBuf,
}

#[cfg(not(feature = "layer1-bootstrap"))]
struct RunnerPreopenedFds {
    child_fds: Vec<std::os::fd::OwnedFd>,
    response_fds: Vec<std::os::fd::OwnedFd>,
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn prepare_runner_preopened_fds(
    _plan_input: &crate::ops::spawn_runner::SpawnRunnerPlanInput,
    resolver: &BundleResolver,
    req: &d2b_contracts_broker::broker_wire::SpawnRunnerRequest,
    audit_log: &crate::audit::AuditLog,
    daemon_uid: u32,
    daemon_gid: u32,
) -> Result<RunnerPreopenedFds, BrokerError> {
    if req.role == d2b_contracts_broker::broker_wire::RunnerRole::CloudHypervisor {
        let typed_resource = req.resource_ref.is_some()
            && req.resource_uid.is_some()
            && req.zone_uid.is_some()
            && req.runtime_scope.is_some();
        if typed_resource && req.network_tap_context.is_none() {
            return Ok(RunnerPreopenedFds {
                child_fds: Vec::new(),
                response_fds: Vec::new(),
            });
        }
        let runner_intent = resolver
            .find_runner_intent(req.bundle_runner_intent_ref.as_str())
            .ok_or_else(|| BrokerError::BundleIntentMissing {
                kind: "runner",
                intent_id: req.bundle_runner_intent_ref.as_str().to_owned(),
            })?;
        let intents = resolver
            .resolve_macvtap_intents(req.vm_id.as_str(), runner_intent.role_id.as_str())
            .map_err(BrokerError::LiveHandler)?;
        if intents.is_empty() {
            return Ok(RunnerPreopenedFds {
                child_fds: Vec::new(),
                response_fds: Vec::new(),
            });
        }
        let mut child_fds = Vec::with_capacity(intents.len());
        for (offset, intent) in intents.into_iter().enumerate() {
            // The inherited-fd contract assigns each macvtap intent the fd
            // RENDER_NODE_INHERITED_FD + index, in declaration order.
            let expected_fd =
                crate::sys::pidfd_sys::RENDER_NODE_INHERITED_FD + offset as libc::c_int;
            if intent.fd != expected_fd {
                return Err(BrokerError::LiveHandler(format!(
                    "macvtap fd contract mismatch for {}: processes.json declares fd {}, broker would install fd {}",
                    intent.ifname.as_str(),
                    intent.fd,
                    expected_fd
                )));
            }
            let fd = crate::ops::tap::live_create_macvtap_fd(&intent)
                .map_err(|err| BrokerError::LiveHandler(err.to_string()))?;
            child_fds.push(fd);
        }
        let _ = audit_log;
        let _ = daemon_uid;
        let _ = daemon_gid;
        return Ok(RunnerPreopenedFds {
            child_fds,
            response_fds: Vec::new(),
        });
    }

    if req.role != d2b_contracts_broker::broker_wire::RunnerRole::QemuMedia {
        return Ok(RunnerPreopenedFds {
            child_fds: Vec::new(),
            response_fds: Vec::new(),
        });
    }

    let tap_context = req
        .network_tap_context
        .as_ref()
        .ok_or(BrokerError::RequestValidation {
            operation: "CreateTapFd",
            reason: "network-admission-required",
        })?;
    let tap_role_id =
        d2b_core::bundle_resolver::canonical_tap_role_id(req.role_id.as_str()).to_owned();
    let exec = crate::ops::exec_reconcile::SystemLiveExec::new(daemon_uid, daemon_gid);
    let outcome = crate::ops::tap::live_create_tap_fd(
        &exec,
        resolver,
        &d2b_contracts_broker::broker_wire::CreateTapFdRequest {
            vm_id: req.vm_id.clone(),
            role_id: d2b_contracts::types::RoleId::new(tap_role_id.clone()),
            bundle_tap_intent_ref: d2b_contracts::types::BundleOpId::new(
                d2b_core::bundle_resolver::intent_id_network_tap(
                    &tap_context.zone_uid,
                    &tap_context.network_uid,
                    &tap_context.attachment_id,
                    tap_context.network_generation,
                    tap_context.attachment_generation,
                    &tap_context.bundle_generation,
                    &tap_role_id,
                    req.vm_id.as_str(),
                ),
            ),
            attachment_id: tap_context.attachment_id.clone(),
            network_generation: tap_context.network_generation,
            attachment_generation: tap_context.attachment_generation,
            zone_uid: tap_context.zone_uid.clone(),
            network_uid: tap_context.network_uid.clone(),
            bundle_generation: tap_context.bundle_generation.clone(),
            admitted_interface_names: tap_context.admitted_interface_names.clone(),
            tracing_span_id: req.tracing_span_id.clone(),
        },
        audit_log,
    )
    .map_err(|err| BrokerError::LiveHandler(err.to_string()))?;

    let reconcile = crate::ops::exec_reconcile::SystemReconcileExecutor;
    let _bridge_flags = dispatch_set_bridge_port_flags_inner(
        &d2b_contracts_broker::broker_wire::SetBridgePortFlagsRequest {
            vm_id: req.vm_id.clone(),
            role_id: d2b_contracts::types::RoleId::new("workload-lan"),
            network_tap_context: req.network_tap_context.clone(),
            tracing_span_id: req.tracing_span_id.clone(),
        },
        resolver,
        &reconcile,
    )?;

    let tap_fd = outcome
        .fd
        .ok_or_else(|| BrokerError::LiveHandler("qemu-media tap fd missing".to_owned()))?;
    let (qemu_console_fd, daemon_console_fd) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
    )
    .map_err(|err| BrokerError::LiveHandler(format!("qemu-media console socketpair: {err}")))?;
    Ok(RunnerPreopenedFds {
        child_fds: vec![tap_fd, qemu_console_fd],
        response_fds: vec![daemon_console_fd],
    })
}

#[cfg(not(feature = "layer1-bootstrap"))]
impl DispatchBackend for LiveDispatchBackend {
    fn apply_nftables(
        &self,
        resolver: &BundleResolver,
        intent: &d2b_core::bundle_resolver::ResolvedNftIntent,
        desired_hash: Option<&str>,
        destroy: bool,
    ) -> Result<(), BrokerError> {
        let nft_binary = nft_binary_path();
        let exec = crate::ops::exec_reconcile::SystemReconcileExecutor;
        let destroy_script;
        let script_body = if destroy {
            destroy_script = render_nft_destroy_script(
                &resolver.host.nftables.family,
                &resolver.host.nftables.table,
            );
            destroy_script.as_str()
        } else {
            intent.script_body.as_str()
        };
        let persisted_hash = if destroy {
            None
        } else {
            persisted_nft_hash()
                .map_err(|err| BrokerError::LiveHandler(err.to_string()))?
                .or_else(|| resolver.host.nftables.table_hash_after_apply.clone())
        };
        let expected_hash = if destroy {
            None
        } else {
            desired_hash.or(persisted_hash.as_deref())
        };
        let _new_hash = crate::ops::nft::apply_with_coexistence(
            &exec,
            &nft_binary,
            script_body,
            intent.ownership_id.as_str(),
            resolver.host.firewall_coexistence_policy.as_ref(),
            expected_hash,
        )
        .map_err(|err| match err {
            crate::ops::nft::ApplyWithCoexistenceError::CoexistenceRefused {
                manager,
                rationale,
            } => BrokerError::CoexistenceRefused { manager, rationale },
            crate::ops::nft::ApplyWithCoexistenceError::ParseFailed(err) => {
                BrokerError::NftScriptParseFailed(err.to_string())
            }
            crate::ops::nft::ApplyWithCoexistenceError::CarveoutOrderingViolation(err) => {
                BrokerError::CarveoutOrderingViolation(match err {
                    d2b_host::nftables::NftError::ForeignNftRuleShadowsD2b { details } => details,
                    other => other.to_string(),
                })
            }
            crate::ops::nft::ApplyWithCoexistenceError::DriftDetected { expected, observed } => {
                BrokerError::NftablesDriftDetected { expected, observed }
            }
            crate::ops::nft::ApplyWithCoexistenceError::ForeignOwnership => {
                BrokerError::LiveHandler("foreign-nft-ownership".to_owned())
            }
            crate::ops::nft::ApplyWithCoexistenceError::ReconcileExec(err) => {
                BrokerError::LiveHandler(err.to_string())
            }
        })?;
        crate::ops::nft::persist_live_nft_hash(
            &exec,
            &nft_binary,
            &resolver.host.nftables.family,
            &resolver.host.nftables.table,
            &nft_hash_sidecar_path(),
        )
        .map_err(|err| BrokerError::LiveHandler(err.to_string()))?;
        Ok(())
    }

    fn apply_route(
        &self,
        state_dir: &Path,
        intent: &d2b_core::bundle_resolver::ResolvedRouteIntent,
        provenance: &d2b_contracts_resource::v3::NetworkProvenance,
        destroy: bool,
    ) -> Result<(), BrokerError> {
        let ip_binary = ip_binary_path();
        let exec = crate::ops::exec_reconcile::SystemReconcileExecutor;
        crate::ops::route::apply_with_preflight_owned(
            &exec, &ip_binary, state_dir, intent, provenance, destroy,
        )
        .map_err(|err| BrokerError::LiveHandler(err.to_string()))
    }

    fn apply_sysctl(
        &self,
        intent: &d2b_core::bundle_resolver::ResolvedSysctlIntent,
        destroy: bool,
    ) -> Result<(), BrokerError> {
        let exec = crate::ops::exec_reconcile::SystemReconcileExecutor;
        let value = if destroy {
            destroy_sysctl_value(&intent.key)?
        } else {
            intent.value.as_str()
        };
        crate::ops::sysctl::apply_with_readback(&exec, &intent.key, value)
            .map_err(|err| BrokerError::LiveHandler(err.to_string()))
    }

    fn update_hosts_file(
        &self,
        intent: &d2b_core::bundle_resolver::ResolvedHostsIntent,
        destroy: bool,
    ) -> Result<(), BrokerError> {
        let exec = crate::ops::exec_reconcile::SystemReconcileExecutor;
        if destroy {
            crate::ops::hosts::remove_marker_block(&exec, intent)
                .map_err(|err| BrokerError::LiveHandler(err.to_string()))
        } else {
            crate::ops::hosts::write_marker_block(&exec, intent)
                .map_err(|err| BrokerError::LiveHandler(err.to_string()))
        }
    }

    fn apply_nm_unmanaged(
        &self,
        intent: &d2b_core::bundle_resolver::ResolvedNmUnmanagedIntent,
        destroy: bool,
    ) -> Result<(), BrokerError> {
        let exec = crate::ops::exec_reconcile::SystemReconcileExecutor;
        if destroy {
            crate::ops::nm::remove_with_reload(intent)
                .map_err(|err| BrokerError::LiveHandler(err.to_string()))
        } else {
            crate::ops::nm::apply_with_reload(&exec, intent)
                .map_err(|err| BrokerError::LiveHandler(err.to_string()))
        }
    }

    fn prepare_store_view(
        &self,
        intent: &d2b_core::bundle_resolver::ResolvedStoreViewIntent,
    ) -> Result<crate::live_handlers::StoreViewOutcome, BrokerError> {
        let exec = crate::ops::exec_reconcile::SystemReconcileExecutor;
        crate::live_handlers::live_prepare_store_view(&exec, intent)
            .map_err(map_activation_live_error)
    }

    fn set_bridge_port_flags(
        &self,
        req: &d2b_contracts_broker::broker_wire::SetBridgePortFlagsRequest,
        resolver: &BundleResolver,
    ) -> Result<d2b_contracts_broker::broker_wire::BridgePortFlagsResponse, BrokerError> {
        let exec = crate::ops::exec_reconcile::SystemReconcileExecutor;
        dispatch_set_bridge_port_flags_inner(req, resolver, &exec)
    }

    fn setup_mount_namespace(
        &self,
        vm_name: &str,
        role_id: &str,
        store_view_intent: &d2b_core::bundle_resolver::ResolvedStoreViewIntent,
    ) -> Result<crate::live_handlers::MountNamespaceOutcome, BrokerError> {
        let exec = crate::ops::exec_reconcile::SystemReconcileExecutor;
        crate::live_handlers::live_setup_mount_namespace(
            &exec,
            vm_name,
            &store_view_intent.hardlink_farm_path,
            role_id,
            &store_view_intent.target_view_path,
        )
        .map_err(map_activation_live_error)
    }

    fn open_pidfd(
        &self,
        runner_id: &str,
        pid: i32,
        expected_start_time_ticks: u64,
    ) -> Result<crate::live_handlers::OpenPidfdResult, BrokerError> {
        let outcome = crate::live_handlers::live_open_pidfd(pid, expected_start_time_ticks)
            .map_err(|err| BrokerError::LiveHandler(err.to_string()))?;
        register_runner_pidfd(runner_id, &outcome.pidfd)?;
        Ok(outcome)
    }

    fn start_systemd_unit(
        &self,
        resolver: &BundleResolver,
        request: &d2b_contracts_broker::broker_wire::StartTransientUnitRequest,
    ) -> Result<
        (
            d2b_contracts_broker::broker_wire::SystemdUnitIdentity,
            OwnedFd,
        ),
        BrokerError,
    > {
        crate::ops::systemd::start(resolver, request)
            .map_err(|error| BrokerError::LiveHandler(error.to_string()))
    }

    fn check_systemd_user_manager(
        &self,
        resolver: &BundleResolver,
        request: &d2b_contracts_broker::broker_wire::CheckSystemdUserManagerRequest,
    ) -> Result<bool, BrokerError> {
        crate::ops::systemd::check_user_manager(resolver, request)
            .map_err(|error| BrokerError::LiveHandler(error.to_string()))
    }

    fn observe_systemd_unit(
        &self,
        resolver: &BundleResolver,
        request: &d2b_contracts_broker::broker_wire::ObserveSystemdUnitRequest,
    ) -> Result<Option<d2b_contracts_broker::broker_wire::SystemdUnitIdentity>, BrokerError> {
        crate::ops::systemd::observe(resolver, request)
            .map_err(|error| BrokerError::LiveHandler(error.to_string()))
    }

    fn reopen_systemd_unit(
        &self,
        resolver: &BundleResolver,
        request: &d2b_contracts_broker::broker_wire::OpenSystemdUnitPidfdRequest,
    ) -> Result<
        (
            d2b_contracts_broker::broker_wire::SystemdUnitIdentity,
            OwnedFd,
        ),
        BrokerError,
    > {
        crate::ops::systemd::reopen(resolver, request)
            .map_err(|error| BrokerError::LiveHandler(error.to_string()))
    }

    fn stop_systemd_unit(
        &self,
        resolver: &BundleResolver,
        request: &d2b_contracts_broker::broker_wire::StopSystemdUnitRequest,
    ) -> Result<(), BrokerError> {
        crate::ops::systemd::stop(resolver, request)
            .map_err(|error| BrokerError::LiveHandler(error.to_string()))
    }

    fn signal_runner(
        &self,
        runner_id: &str,
        signal: d2b_contracts_broker::broker_wire::RunnerSignal,
    ) -> Result<(), BrokerError> {
        signal_registered_runner(runner_id, signal)
    }

    fn spawn_runner(
        &self,
        runner_id: &str,
        plan_input: &crate::ops::spawn_runner::SpawnRunnerPlanInput,
        resolver: &BundleResolver,
        req: &d2b_contracts_broker::broker_wire::SpawnRunnerRequest,
        mut request_fds: Vec<OwnedFd>,
        audit_log: &crate::audit::AuditLog,
    ) -> Result<crate::live_handlers::SpawnRunnerResult, BrokerError> {
        // Reserve the runner_id BEFORE spawning the child: refuse a
        // duplicate active registration up front so we never create an
        // orphan child (see `reserve_runner_id_for_spawn`).
        #[cfg(not(feature = "layer1-bootstrap"))]
        reserve_runner_id_for_spawn(runner_id)?;
        let preopened = prepare_runner_preopened_fds(
            plan_input,
            resolver,
            req,
            audit_log,
            self.daemon_uid,
            self.daemon_gid,
        )?;
        let (controller_bootstrap_response, retained_controller_bootstrap) =
            if req.role == d2b_contracts_broker::broker_wire::RunnerRole::ProviderController {
                let retained = request_fds.pop().ok_or_else(|| {
                    BrokerError::Protocol(
                        "ProviderController bootstrap escrow fd is missing".to_owned(),
                    )
                })?;
                let response = retained.try_clone().map_err(|error| {
                    BrokerError::LiveHandler(format!(
                        "Provider controller bootstrap duplicate: {error}"
                    ))
                })?;
                (Some(response), Some(retained))
            } else {
                (None, None)
            };
        if !request_fds.is_empty() && !preopened.child_fds.is_empty() {
            return Err(BrokerError::Protocol(
                "request inherited fds cannot combine with broker-preopened fds".to_owned(),
            ));
        }
        let mut outcome = crate::live_handlers::live_spawn_runner(
            plan_input,
            preopened.child_fds,
            request_fds,
            req.activation_input.as_ref(),
            &self.state_dir,
        )
        .map_err(|err| {
            // Log the actual LiveHandlerError detail before wrapping it
            // in the opaque BrokerError::LiveHandler envelope so
            // operators can see WHY the spawn failed in journalctl.
            tracing::error!(
                runner_id = %runner_id,
                error = %err,
                "live_spawn_runner failed"
            );
            // swtpm-dir hardening fail-closed carries a structured,
            // path-free audit that the dispatch arm must emit as a
            // terminal PrepareSwtpmDir record; preserve it instead of
            // collapsing to the opaque LiveHandler envelope.
            match err {
                crate::live_handlers::LiveHandlerError::SwtpmDirHardening { audit, reason } => {
                    BrokerError::SwtpmDirHardening { audit, reason }
                }
                other => BrokerError::LiveHandler(other.to_string()),
            }
        })?;
        outcome.extra_response_fds = preopened.response_fds;
        outcome
            .extra_response_fds
            .extend(controller_bootstrap_response);
        register_runner_pidfd(runner_id, &outcome.pidfd).inspect_err(|_err| {
            // Registration failed: the broker is about to drop this
            // just-spawned child's pidfd. Reap it now (targeted,
            // non-blocking) so a child that has already exited cannot
            // leak as a zombie. Best-effort; the registry entry is
            // already absent on the failure path.
            #[cfg(not(feature = "layer1-bootstrap"))]
            targeted_reap_runner(runner_id, outcome.pidfd.as_fd());
        })?;
        if let Some(bootstrap) = retained_controller_bootstrap {
            controller_bootstrap_registry()
                .lock()
                .map_err(|_| {
                    BrokerError::Protocol("controller bootstrap registry mutex poisoned".to_owned())
                })?
                .insert(runner_id.to_owned(), bootstrap);
        }
        // Close the registration-window race: if the child exited
        // between clone3 and the registry insertion above, its SIGCHLD
        // may have already been coalesced/consumed by a reap pass that
        // ran before the entry existed. A targeted, generation-exact
        // (pidfd-keyed) non-blocking reap here guarantees the child is
        // reaped regardless of SIGCHLD timing.
        #[cfg(not(feature = "layer1-bootstrap"))]
        targeted_reap_runner(runner_id, outcome.pidfd.as_fd());
        Ok(outcome)
    }

    fn run_host_install(
        &self,
        req: &d2b_contracts_broker::broker_wire::RunHostInstallRequest,
        resolver: Option<&BundleResolver>,
    ) -> Result<d2b_contracts_broker::broker_wire::RunHostInstallResponse, BrokerError> {
        let exec = crate::ops::exec_reconcile::SystemReconcileExecutor;
        dispatch_run_host_install_response_inner(req, resolver, &exec)
    }

    fn run_migrate(
        &self,
        intent: &d2b_core::bundle_resolver::ResolvedMigrateIntent,
    ) -> Result<crate::live_handlers::MigrateOutcome, BrokerError> {
        let exec = crate::ops::exec_reconcile::SystemReconcileExecutor;
        crate::live_handlers::live_run_migrate(&exec, intent)
            .map_err(|err| BrokerError::LiveHandler(err.to_string()))
    }

    fn run_activation(
        &self,
        intent: &d2b_core::bundle_resolver::ResolvedActivationIntent,
        store_view_intent: &d2b_core::bundle_resolver::ResolvedStoreViewIntent,
        phase: d2b_contracts_broker::broker_wire::ActivationPhase,
        mode: d2b_contracts_broker::broker_wire::ActivationMode,
    ) -> Result<crate::live_handlers::ActivationOutcome, BrokerError> {
        let exec = crate::ops::exec_reconcile::SystemReconcileExecutor;
        crate::live_handlers::live_run_activation(&exec, intent, store_view_intent, phase, mode)
            .map_err(map_activation_live_error)
    }

    fn apply_host_generation_handoff(
        &self,
        state_dir: &std::path::Path,
        helper_path: &std::path::Path,
        request: &d2b_contracts_broker::host_generation::ApplyHostGenerationHandoff,
    ) -> Result<d2b_contracts_broker::broker_wire::ApplyHostGenerationHandoffResponse, BrokerError>
    {
        crate::ops::host_generation_handoff::apply_with_helper(state_dir, helper_path, request)
            .map_err(|error| BrokerError::LiveHandler(error.to_string()))
    }

    fn run_gc(
        &self,
        intent: &d2b_core::bundle_resolver::ResolvedGcIntent,
        keep_generations: Option<u32>,
    ) -> Result<crate::live_handlers::GcOutcome, BrokerError> {
        let exec = crate::ops::exec_reconcile::SystemReconcileExecutor;
        crate::live_handlers::live_run_gc(&exec, intent, keep_generations)
            .map_err(|err| BrokerError::LiveHandler(err.to_string()))
    }

    fn run_keys_rotate(
        &self,
        intent: &d2b_core::bundle_resolver::ResolvedKeysRotateIntent,
    ) -> Result<crate::live_handlers::KeysRotateOutcome, BrokerError> {
        let exec = crate::ops::exec_reconcile::SystemReconcileExecutor;
        crate::live_handlers::live_run_keys_rotate(&exec, intent)
            .map_err(|err| BrokerError::LiveHandler(err.to_string()))
    }

    fn run_host_key_trust(
        &self,
        intent: &d2b_core::bundle_resolver::ResolvedHostKeyTrustIntent,
    ) -> Result<crate::live_handlers::HostKeyTrustOutcome, BrokerError> {
        let exec = crate::ops::exec_reconcile::SystemReconcileExecutor;
        crate::live_handlers::live_run_trust(&exec, intent)
            .map_err(|err| BrokerError::LiveHandler(err.to_string()))
    }

    fn run_rotate_known_host(
        &self,
        intent: &d2b_core::bundle_resolver::ResolvedRotateKnownHostIntent,
    ) -> Result<crate::live_handlers::RotateKnownHostOutcome, BrokerError> {
        let exec = crate::ops::exec_reconcile::SystemReconcileExecutor;
        crate::live_handlers::live_run_rotate_known_host(&exec, intent)
            .map_err(|err| BrokerError::LiveHandler(err.to_string()))
    }

    fn usbip_bind(
        &self,
        intent: &d2b_core::bundle_resolver::ResolvedUsbipBindIntent,
    ) -> Result<(), BrokerError> {
        let usbip_binary = usbip_binary_path();
        let exec = crate::ops::exec_reconcile::SystemReconcileExecutor;
        crate::live_handlers::live_usbip_bind(
            &exec,
            &usbip_binary,
            usb_device_sysfs_root(),
            &intent.bus_id,
            &intent.lock_path,
            &intent.vm_name,
            self.daemon_uid,
            self.daemon_gid,
        )
        .map_err(|err| BrokerError::LiveHandler(err.to_string()))
    }

    fn usbip_unbind(
        &self,
        intent: &d2b_core::bundle_resolver::ResolvedUsbipBindIntent,
    ) -> Result<(), BrokerError> {
        let usbip_binary = usbip_binary_path();
        let exec = crate::ops::exec_reconcile::SystemReconcileExecutor;
        crate::live_handlers::live_usbip_unbind(
            &exec,
            &usbip_binary,
            usb_device_sysfs_root(),
            &intent.bus_id,
            &intent.lock_path,
            &intent.vm_name,
        )
        .map_err(|err| BrokerError::LiveHandler(err.to_string()))
    }

    fn usbip_bind_firewall_rule(
        &self,
        resolver: &BundleResolver,
        intent: &d2b_core::bundle_resolver::ResolvedUsbipFirewallIntent,
    ) -> Result<(), BrokerError> {
        let host_nft_intent = resolver
            .find_nft_intent(&d2b_core::bundle_resolver::intent_id_nft_host())
            .ok_or_else(|| BrokerError::BundleIntentMissing {
                kind: "nft",
                intent_id: d2b_core::bundle_resolver::intent_id_nft_host(),
            })?;
        let decision = build_usbip_firewall_decision(resolver, host_nft_intent, intent)?;
        let nft_binary = nft_binary_path();
        let exec = crate::ops::exec_reconcile::SystemReconcileExecutor;
        let nft_script = decision.batch.render_nft_script();
        let expected_hash = persisted_nft_hash()
            .map_err(|err| BrokerError::LiveHandler(err.to_string()))?
            .or_else(|| resolver.host.nftables.table_hash_after_apply.clone());
        crate::ops::nft::apply_with_coexistence(
            &exec,
            &nft_binary,
            &nft_script,
            resolver.host.nftables.ownership_id.as_str(),
            resolver.host.firewall_coexistence_policy.as_ref(),
            expected_hash.as_deref(),
        )
        .map_err(|err| match err {
            crate::ops::nft::ApplyWithCoexistenceError::CoexistenceRefused {
                manager,
                rationale,
            } => BrokerError::CoexistenceRefused { manager, rationale },
            crate::ops::nft::ApplyWithCoexistenceError::ParseFailed(err) => {
                BrokerError::NftScriptParseFailed(err.to_string())
            }
            crate::ops::nft::ApplyWithCoexistenceError::CarveoutOrderingViolation(err) => {
                BrokerError::CarveoutOrderingViolation(match err {
                    d2b_host::nftables::NftError::ForeignNftRuleShadowsD2b { details } => details,
                    other => other.to_string(),
                })
            }
            crate::ops::nft::ApplyWithCoexistenceError::DriftDetected { expected, observed } => {
                BrokerError::NftablesDriftDetected { expected, observed }
            }
            crate::ops::nft::ApplyWithCoexistenceError::ForeignOwnership => {
                BrokerError::LiveHandler("foreign-nft-ownership".to_owned())
            }
            crate::ops::nft::ApplyWithCoexistenceError::ReconcileExec(err) => {
                BrokerError::LiveHandler(err.to_string())
            }
        })?;
        crate::ops::nft::persist_live_nft_hash(
            &exec,
            &nft_binary,
            &resolver.host.nftables.family,
            &resolver.host.nftables.table,
            &nft_hash_sidecar_path(),
        )
        .map_err(|err| BrokerError::LiveHandler(err.to_string()))?;
        Ok(())
    }

    fn usbip_proxy_reconcile(
        &self,
        expectations: &[(String, String, PathBuf)],
    ) -> Result<(), BrokerError> {
        crate::live_handlers::live_usbip_proxy_reconcile(expectations)
            .map_err(|err| BrokerError::LiveHandler(err.to_string()))
    }

    fn qemu_media_system_powerdown(
        &self,
        req: &d2b_contracts_broker::broker_wire::QemuMediaLifecycleRequest,
    ) -> Result<d2b_contracts_broker::broker_wire::QemuMediaLifecycleResponse, BrokerError> {
        crate::ops::media::system_powerdown(req)
            .map_err(|err| BrokerError::LiveHandler(err.to_string()))
    }

    fn qemu_media_query_status(
        &self,
        req: &d2b_contracts_broker::broker_wire::QemuMediaQueryStatusRequest,
    ) -> Result<d2b_contracts_broker::broker_wire::QemuMediaQueryStatusResponse, BrokerError> {
        crate::ops::media::query_status(req)
            .map_err(|err| BrokerError::LiveHandler(err.to_string()))
    }

    fn qemu_media_quit(
        &self,
        req: &d2b_contracts_broker::broker_wire::QemuMediaLifecycleRequest,
    ) -> Result<d2b_contracts_broker::broker_wire::QemuMediaLifecycleResponse, BrokerError> {
        crate::ops::media::quit(req).map_err(|err| BrokerError::LiveHandler(err.to_string()))
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn require_resolver_ref(resolver: Option<&BundleResolver>) -> Result<&BundleResolver, BrokerError> {
    resolver.ok_or(BrokerError::BundleResolverUnavailable)
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn require_resolver(
    resolver: Option<&Arc<BundleResolver>>,
) -> Result<&Arc<BundleResolver>, BrokerError> {
    resolver.ok_or(BrokerError::BundleResolverUnavailable)
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn live_exec(config: &ServerConfig) -> crate::ops::exec_reconcile::SystemLiveExec {
    crate::ops::exec_reconcile::SystemLiveExec::new(config.d2bd_uid, config.d2bd_gid)
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn dispatch_set_bridge_port_flags_inner(
    req: &d2b_contracts_broker::broker_wire::SetBridgePortFlagsRequest,
    resolver: &BundleResolver,
    executor: &dyn crate::ops::exec_reconcile::ReconcileExecutor,
) -> Result<d2b_contracts_broker::broker_wire::BridgePortFlagsResponse, BrokerError> {
    let context = req
        .network_tap_context
        .as_ref()
        .ok_or(BrokerError::RequestValidation {
            operation: "SetBridgePortFlags",
            reason: "network-admission-required",
        })?;
    let installed =
        resolver
            .installed_generation_identity()
            .ok_or(BrokerError::RequestValidation {
                operation: "SetBridgePortFlags",
                reason: "installed-generation-unavailable",
            })?;
    if installed.as_str() != context.bundle_generation.as_str()
        || context.network_generation.get() == 0
        || context.attachment_generation.get() == 0
    {
        return Err(BrokerError::RequestValidation {
            operation: "SetBridgePortFlags",
            reason: "stale-projection-generation",
        });
    }
    crate::ops::tap::live_set_bridge_port_flags(executor, resolver, req)
        .map_err(|err| BrokerError::LiveHandler(err.to_string()))
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn map_activation_live_error(error: crate::live_handlers::LiveHandlerError) -> BrokerError {
    match error {
        crate::live_handlers::LiveHandlerError::ReconcileExec(
            crate::ops::exec_reconcile::ReconcileExecError::DifferentFilesystem {
                a,
                a_dev,
                b,
                b_dev,
            },
        ) => BrokerError::StoreViewFilesystemMismatch { a, a_dev, b, b_dev },
        crate::live_handlers::LiveHandlerError::ReconcileExec(
            crate::ops::exec_reconcile::ReconcileExecError::MarkerMissing { generation_dir },
        ) => BrokerError::StoreViewMarkerMissing { generation_dir },
        other => BrokerError::LiveHandler(other.to_string()),
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn dispatch_run_host_install_intent_inner(
    req: &d2b_contracts_broker::broker_wire::RunHostInstallRequest,
    intent: &d2b_core::bundle_resolver::ResolvedInstallerIntent,
    host_runtime: Option<&d2b_core::bundle_resolver::HostRuntimeArtifact>,
    executor: &dyn crate::ops::exec_reconcile::ReconcileExecutor,
) -> Result<d2b_contracts_broker::broker_wire::RunHostInstallResponse, BrokerError> {
    let outcome = crate::live_handlers::live_run_host_install_with_runtime(
        executor,
        intent,
        req.enable,
        req.start,
        req.no_start,
        host_runtime,
    )
    .map_err(|err| BrokerError::LiveHandler(err.to_string()))?;
    Ok(d2b_contracts_broker::broker_wire::RunHostInstallResponse {
        installed: outcome.installed,
        enabled: outcome.enabled,
        started: outcome.started,
        artifacts_written: outcome.artifacts_written,
    })
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn dispatch_run_host_install_response_inner(
    req: &d2b_contracts_broker::broker_wire::RunHostInstallRequest,
    resolver: Option<&BundleResolver>,
    executor: &dyn crate::ops::exec_reconcile::ReconcileExecutor,
) -> Result<d2b_contracts_broker::broker_wire::RunHostInstallResponse, BrokerError> {
    let resolver = require_resolver_ref(resolver)?;
    let intent = resolver
        .find_installer_intent(req.bundle_installer_intent_ref.as_str())
        .ok_or_else(|| BrokerError::BundleIntentMissing {
            kind: "installer",
            intent_id: req.bundle_installer_intent_ref.as_str().to_owned(),
        })?;
    let host_runtime = d2b_core::bundle_resolver::HostRuntimeArtifact::new(resolver.host_runtime());
    dispatch_run_host_install_intent_inner(req, intent, Some(&host_runtime), executor)
}

#[cfg(not(feature = "layer1-bootstrap"))]
/// Shared helper: resolve + execute `RunHostInstall` against an injected
/// executor and map failures onto the broker wire envelope.
/// The live server uses the inner form so it can write the audit row
/// only after a successful install; integration tests use this wrapper
/// to assert the typed negative-path responses directly.
pub fn dispatch_run_host_install_response(
    req: &d2b_contracts_broker::broker_wire::RunHostInstallRequest,
    resolver: Option<&BundleResolver>,
    executor: &dyn crate::ops::exec_reconcile::ReconcileExecutor,
) -> BrokerResponse {
    match dispatch_run_host_install_response_inner(req, resolver, executor) {
        Ok(response) => BrokerResponse::RunHostInstall(response),
        Err(err) => err.into_response(),
    }
}

/// Test helper: load the bundle at `bundle_path` through the same
/// `try_load_resolver` path as the broker's `serve` loop and convert the
/// resulting `BundleSlot` into a `BrokerResponse`. Returns
/// `BrokerResponse::Error { kind: "bundle-tampered" }` when the bundle
/// fails its tamper-resistance check, and
/// `BrokerResponse::Error { kind: "Broker.BundleResolverUnavailable" }` when
/// the bundle is absent or unreadable. Exposed for the
/// `bundle_tampered_broker` integration test.
#[cfg(not(feature = "layer1-bootstrap"))]
pub fn probe_bundle_load_response(bundle_path: &std::path::Path) -> BrokerResponse {
    match try_load_resolver(bundle_path) {
        BundleSlot::Loaded(_) => BrokerResponse::ValidateBundle(
            d2b_contracts_broker::broker_wire::ValidateBundleResponse { valid: true },
        ),
        BundleSlot::Unavailable => BrokerError::BundleResolverUnavailable.into_response(),
        BundleSlot::Tampered { path, reason } => {
            BrokerError::BundleTampered { path, reason }.into_response()
        }
    }
}

/// Like [`probe_bundle_load_response`] but uses an explicit [`BundleVerifyPolicy`].
/// Tests that need to control uid/gid/mode requirements (e.g. to avoid requiring
/// root in CI) pass `current_user_policy()` so the uid check passes and only the
/// intended tamper reason fires.
#[cfg(not(feature = "layer1-bootstrap"))]
pub fn probe_bundle_load_response_with_policy(
    bundle_path: &std::path::Path,
    policy: &d2b_core::bundle_resolver::BundleVerifyPolicy,
) -> BrokerResponse {
    match try_load_resolver_with_policy(bundle_path, policy) {
        BundleSlot::Loaded(_) => BrokerResponse::ValidateBundle(
            d2b_contracts_broker::broker_wire::ValidateBundleResponse { valid: true },
        ),
        BundleSlot::Unavailable => BrokerError::BundleResolverUnavailable.into_response(),
        BundleSlot::Tampered { path, reason } => {
            BrokerError::BundleTampered { path, reason }.into_response()
        }
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
/// Variant for tests that inject a pre-resolved installer intent with
/// writable artifact paths while still exercising the dispatch-layer
/// success/error envelope mapping.
pub fn dispatch_run_host_install_response_for_intent(
    req: &d2b_contracts_broker::broker_wire::RunHostInstallRequest,
    intent: &d2b_core::bundle_resolver::ResolvedInstallerIntent,
    host_runtime: Option<&d2b_core::bundle_resolver::HostRuntimeArtifact>,
    executor: &dyn crate::ops::exec_reconcile::ReconcileExecutor,
) -> BrokerResponse {
    match dispatch_run_host_install_intent_inner(req, intent, host_runtime, executor) {
        Ok(response) => BrokerResponse::RunHostInstall(response),
        Err(err) => err.into_response(),
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
pub fn dispatch_run_activation_response_for_intent(
    req: &d2b_contracts_broker::broker_wire::RunActivationRequest,
    intent: &d2b_core::bundle_resolver::ResolvedActivationIntent,
    store_view_intent: &d2b_core::bundle_resolver::ResolvedStoreViewIntent,
    executor: &dyn crate::ops::exec_reconcile::ReconcileExecutor,
) -> BrokerResponse {
    if intent.vm != req.vm {
        return BrokerError::Protocol(format!(
            "RunActivation vm mismatch: wire vm `{}` != intent vm `{}`",
            req.vm, intent.vm,
        ))
        .into_response();
    }
    match crate::live_handlers::live_run_activation(
        executor,
        intent,
        store_view_intent,
        req.phase,
        req.mode,
    )
    .map_err(map_activation_live_error)
    {
        Ok(outcome) => BrokerResponse::RunActivation(
            d2b_contracts_broker::broker_wire::RunActivationResponse {
                mode: outcome.mode,
                vm: outcome.vm,
                generation_number: outcome.generation_number,
                guest_switch_script_path: outcome
                    .guest_switch_script_path
                    .as_ref()
                    .map(|path| path.display().to_string()),
                summary: outcome.summary,
            },
        ),
        Err(err) => err.into_response(),
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn nft_binary_path() -> PathBuf {
    PathBuf::from(env::var("D2B_BROKER_NFT_BINARY").unwrap_or_else(|_| "/usr/sbin/nft".to_owned()))
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn nft_hash_sidecar_path() -> PathBuf {
    PathBuf::from(
        env::var("D2B_BROKER_NFT_HASH_PATH")
            .unwrap_or_else(|_| crate::ops::nft::DEFAULT_NFT_HASH_SIDECAR_PATH.to_owned()),
    )
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn persisted_nft_hash() -> Result<Option<String>, crate::ops::exec_reconcile::ReconcileExecError> {
    crate::ops::nft::read_persisted_nft_hash(&nft_hash_sidecar_path())
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn ip_binary_path() -> PathBuf {
    PathBuf::from(env::var("D2B_BROKER_IP_BINARY").unwrap_or_else(|_| "/usr/sbin/ip".to_owned()))
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn render_nft_destroy_script(family: &str, table: &str) -> String {
    format!("table {family} {table} {{\n}}\n")
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn destroy_sysctl_value(key: &str) -> Result<&'static str, BrokerError> {
    crate::ops::sysctl::destroy_value_for_key(key)
        .ok_or_else(|| BrokerError::Protocol(format!("unsupported host-destroy sysctl key: {key}")))
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn usbip_binary_path() -> PathBuf {
    PathBuf::from(
        env::var("D2B_BROKER_USBIP_BINARY").unwrap_or_else(|_| "/usr/sbin/usbip".to_owned()),
    )
}

/// Best-effort lookup of the human-readable VM name carried in the
/// bundle's `processes.vms[*].vm` list. The wire `VmId` is a transparent
/// opaque string; the bundle index is the `processes.vms[*].vm` field.
/// We use the wire value as both the opaque key and the human-readable
/// name today - the daemon emits them identically.
#[cfg(not(feature = "layer1-bootstrap"))]
fn lookup_vm_name(_resolver: &Arc<BundleResolver>, vm_id: &d2b_contracts::types::VmId) -> String {
    vm_id.as_str().to_owned()
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn apply_vm_start_prerequisites<B: DispatchBackend>(
    backend: &B,
    resolver: &Arc<BundleResolver>,
    vm_name: &str,
    role_id: &str,
) -> Result<(), BrokerError> {
    for intent in resolver.resolve_vm_start_prerequisites(vm_name, role_id) {
        for action in &intent.actions {
            execute_vm_start_action(backend, &intent, action)?;
        }
    }
    Ok(())
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn execute_vm_start_action<B: DispatchBackend>(
    backend: &B,
    intent: &d2b_core::bundle_resolver::ResolvedVmStartIntent,
    action: &d2b_core::bundle_resolver::ResolvedVmStartAction,
) -> Result<(), BrokerError> {
    match action {
        d2b_core::bundle_resolver::ResolvedVmStartAction::PrepareRuntimeDir(dir)
        | d2b_core::bundle_resolver::ResolvedVmStartAction::PrepareStateDir(dir) => {
            crate::ops::state_dir::prepare_dir(&crate::ops::state_dir::PrepareDirRequest {
                kind: if matches!(
                    action,
                    d2b_core::bundle_resolver::ResolvedVmStartAction::PrepareRuntimeDir(_)
                ) {
                    crate::ops::state_dir::DirKind::RuntimeDir
                } else {
                    crate::ops::state_dir::DirKind::StateDir
                },
                base_dir: dir.base_dir.clone(),
                vm_id_or_scope: intent.vm_name.clone(),
                mode: dir.mode,
                owner_uid: dir.owner_uid,
                owner_gid: dir.owner_gid,
                created_paths: Vec::new(),
            })
            .map(|_| ())
            .map_err(|err| {
                BrokerError::LiveHandler(format!(
                    "prepare vm-start directory {} for {}:{} failed: {err}",
                    dir.base_dir.display(),
                    intent.vm_name,
                    intent.role_id
                ))
            })
        }
        d2b_core::bundle_resolver::ResolvedVmStartAction::PrepareStoreView(store_view) => {
            backend.prepare_store_view(store_view).map(|_| ())
        }
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
#[cfg(test)]
static TEST_USB_SYSFS_ROOT: OnceLock<PathBuf> = OnceLock::new();

#[cfg(not(feature = "layer1-bootstrap"))]
fn usb_device_sysfs_root() -> &'static Path {
    #[cfg(test)]
    if let Some(path) = TEST_USB_SYSFS_ROOT.get() {
        return path.as_path();
    }
    Path::new("/sys/bus/usb/devices")
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn read_usb_device_identity(sysfs_root: &Path, bus_id: &str) -> Result<(u16, u16), BrokerError> {
    if d2b_contracts::usbip::validate_bus_id(bus_id).is_err() {
        return Err(BrokerError::Protocol(format!(
            "invalid USB bus_id for sysfs lookup: {bus_id:?}"
        )));
    }
    let device_dir = sysfs_root.join(bus_id);
    let vendor = read_hex_u16(device_dir.join("idVendor"), bus_id)?;
    let product = read_hex_u16(device_dir.join("idProduct"), bus_id)?;
    Ok((vendor, product))
}

#[cfg(not(feature = "layer1-bootstrap"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UsbAuditSerialHmacKeySlot {
    Current,
    Previous,
}

#[cfg(not(feature = "layer1-bootstrap"))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct UsbAuditSerialHmacKey {
    slot: UsbAuditSerialHmacKeySlot,
    key_id: String,
    key: Vec<u8>,
}

#[cfg(not(feature = "layer1-bootstrap"))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct UsbAuditSerialHmacKeyring {
    current: UsbAuditSerialHmacKey,
    previous: Option<UsbAuditSerialHmacKey>,
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn usb_audit_device_identity_for_busid(
    sysfs_root: &Path,
    bus_id: &str,
    identity: (u16, u16),
    state_dir: &Path,
    test_mode: bool,
) -> Result<
    (
        UsbAuditDeviceIdentity,
        Option<UsbSerialCorrelationKeyRotationAudit>,
    ),
    BrokerError,
> {
    let serial = read_usb_serial_for_audit(sysfs_root, bus_id);
    let keyring = match serial.as_deref() {
        Some(_) => Some(usb_audit_serial_hmac_keyring(state_dir, test_mode)?),
        None => None,
    };
    let rotation_audit = keyring
        .as_ref()
        .and_then(usb_serial_correlation_key_rotation_audit);
    Ok((
        usb_audit_device_identity(identity, serial.as_deref(), keyring.as_ref()),
        rotation_audit,
    ))
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn usb_audit_device_identity(
    identity: (u16, u16),
    serial: Option<&str>,
    keyring: Option<&UsbAuditSerialHmacKeyring>,
) -> UsbAuditDeviceIdentity {
    let serial = serial.map(str::trim).filter(|value| !value.is_empty());
    UsbAuditDeviceIdentity {
        vendor_id: Some(d2b_contracts::usbip::format_usb_hex_id(identity.0)),
        product_id: Some(d2b_contracts::usbip::format_usb_hex_id(identity.1)),
        serial_observed: serial.is_some(),
        serial_correlation: serial.and_then(|serial| {
            keyring.and_then(|keys| usb_serial_correlation(serial, &keys.current))
        }),
        previous_serial_correlation: serial.and_then(|serial| {
            keyring.and_then(|keys| {
                keys.previous
                    .as_ref()
                    .and_then(|key| usb_serial_correlation(serial, key))
            })
        }),
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn usb_serial_correlation(
    serial: &str,
    key: &UsbAuditSerialHmacKey,
) -> Option<UsbSerialCorrelation> {
    if key.key_id.is_empty() || key.key.len() < USB_AUDIT_SERIAL_HMAC_KEY_BYTES {
        return None;
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(&key.key).ok()?;
    mac.update(b"d2b-usb-audit-serial-v1\0");
    mac.update(serial.as_bytes());
    Some(UsbSerialCorrelation {
        key_id: key.key_id.clone(),
        hmac_sha256: lower_hex(&mac.finalize().into_bytes()),
    })
}

#[cfg(not(feature = "layer1-bootstrap"))]
const USB_AUDIT_SERIAL_HMAC_KEY_BYTES: usize = 32;
#[cfg(not(feature = "layer1-bootstrap"))]
const USB_AUDIT_SERIAL_HMAC_RANDOM_BYTES: usize = USB_AUDIT_SERIAL_HMAC_KEY_BYTES + 16;
#[cfg(not(feature = "layer1-bootstrap"))]
const USB_AUDIT_SERIAL_HMAC_KEY_DIR: &str = "usb-audit-serial-hmac";
#[cfg(not(feature = "layer1-bootstrap"))]
const USB_AUDIT_SERIAL_HMAC_CURRENT_KEY_FILE: &str = "current.key";
#[cfg(not(feature = "layer1-bootstrap"))]
const USB_AUDIT_SERIAL_HMAC_PREVIOUS_KEY_FILE: &str = "previous.key";
#[cfg(not(feature = "layer1-bootstrap"))]
const USB_AUDIT_SERIAL_HMAC_KEY_MAGIC: &str = "d2b-usb-audit-serial-hmac-v1";
#[cfg(not(feature = "layer1-bootstrap"))]
const USB_AUDIT_SERIAL_CORRELATION_VERSION: &str = "d2b-usb-audit-serial-v1";
#[cfg(not(feature = "layer1-bootstrap"))]
const USB_AUDIT_SERIAL_HMAC_PREVIOUS_KEY_GRACE_WINDOW_SECONDS: u64 = 30 * 24 * 60 * 60;
#[cfg(not(feature = "layer1-bootstrap"))]
static USB_AUDIT_SERIAL_HMAC_ROTATION_LOGGED: OnceLock<Mutex<HashMap<String, ()>>> =
    OnceLock::new();
#[cfg(not(feature = "layer1-bootstrap"))]
static USB_AUDIT_SERIAL_HMAC_ROTATION_AUDIT_LOGGED: OnceLock<Mutex<HashMap<String, ()>>> =
    OnceLock::new();

#[cfg(not(feature = "layer1-bootstrap"))]
fn usb_serial_correlation_key_rotation_audit(
    keyring: &UsbAuditSerialHmacKeyring,
) -> Option<UsbSerialCorrelationKeyRotationAudit> {
    keyring
        .previous
        .as_ref()
        .map(|previous| UsbSerialCorrelationKeyRotationAudit {
            previous_key_id: previous.key_id.clone(),
            current_key_id: keyring.current.key_id.clone(),
            active_key_count: 2,
            grace_window_seconds: USB_AUDIT_SERIAL_HMAC_PREVIOUS_KEY_GRACE_WINDOW_SECONDS,
            correlation_version: USB_AUDIT_SERIAL_CORRELATION_VERSION.to_owned(),
        })
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn usb_audit_serial_hmac_rotation_dedupe_key(
    audit: &UsbSerialCorrelationKeyRotationAudit,
) -> String {
    format!("{}|{}", audit.previous_key_id, audit.current_key_id)
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn mark_usb_audit_serial_hmac_rotation_audit_logged(
    audit: &UsbSerialCorrelationKeyRotationAudit,
) -> Option<String> {
    let dedupe_key = usb_audit_serial_hmac_rotation_dedupe_key(audit);
    let logged =
        USB_AUDIT_SERIAL_HMAC_ROTATION_AUDIT_LOGGED.get_or_init(|| Mutex::new(HashMap::new()));
    let Ok(mut logged) = logged.lock() else {
        return Some(dedupe_key);
    };
    if logged.insert(dedupe_key.clone(), ()).is_some() {
        return None;
    }
    Some(dedupe_key)
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn unmark_usb_audit_serial_hmac_rotation_audit_logged(dedupe_key: &str) {
    let Some(logged) = USB_AUDIT_SERIAL_HMAC_ROTATION_AUDIT_LOGGED.get() else {
        return;
    };
    if let Ok(mut logged) = logged.lock() {
        logged.remove(dedupe_key);
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn log_usb_audit_serial_hmac_rotation_window(keyring: &UsbAuditSerialHmacKeyring) {
    let Some(audit) = usb_serial_correlation_key_rotation_audit(keyring) else {
        return;
    };
    let dedupe_key = usb_audit_serial_hmac_rotation_dedupe_key(&audit);
    let logged = USB_AUDIT_SERIAL_HMAC_ROTATION_LOGGED.get_or_init(|| Mutex::new(HashMap::new()));
    let Ok(mut logged) = logged.lock() else {
        return;
    };
    if logged.insert(dedupe_key, ()).is_some() {
        return;
    }
    info!(
        event = "usb_serial_correlation_key_rotation_window",
        previous_key_id = %audit.previous_key_id,
        current_key_id = %audit.current_key_id,
        active_key_count = audit.active_key_count,
        grace_window_seconds = audit.grace_window_seconds,
        correlation_version = %audit.correlation_version,
        "USB audit serial HMAC key rotation window active"
    );
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn usb_audit_serial_hmac_keyring(
    state_dir: &Path,
    test_mode: bool,
) -> Result<UsbAuditSerialHmacKeyring, BrokerError> {
    let key_dir = usb_audit_serial_hmac_key_dir(state_dir);
    ensure_usb_audit_serial_hmac_key_dir(&key_dir, test_mode)?;
    let current = match read_usb_audit_serial_hmac_key_file(
        &key_dir.join(USB_AUDIT_SERIAL_HMAC_CURRENT_KEY_FILE),
        UsbAuditSerialHmacKeySlot::Current,
        test_mode,
    )? {
        Some(key) => key,
        None => create_usb_audit_serial_hmac_key(&key_dir, test_mode)?,
    };
    let previous = read_usb_audit_serial_hmac_key_file(
        &key_dir.join(USB_AUDIT_SERIAL_HMAC_PREVIOUS_KEY_FILE),
        UsbAuditSerialHmacKeySlot::Previous,
        test_mode,
    )?;

    let keyring = UsbAuditSerialHmacKeyring { current, previous };
    log_usb_audit_serial_hmac_rotation_window(&keyring);
    Ok(keyring)
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn usb_audit_serial_hmac_key_dir(state_dir: &Path) -> PathBuf {
    state_dir
        .join("secrets")
        .join(USB_AUDIT_SERIAL_HMAC_KEY_DIR)
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn ensure_usb_audit_serial_hmac_key_dir(
    key_dir: &Path,
    test_mode: bool,
) -> Result<(), BrokerError> {
    let state_secrets = key_dir.parent().ok_or_else(|| {
        BrokerError::LiveHandler("USB audit serial HMAC key directory has no parent".to_owned())
    })?;
    let owner = if test_mode { None } else { Some(0) };
    crate::sys::path_safe::ensure_dir(state_secrets, 0o700, owner, owner).map_err(|err| {
        BrokerError::LiveHandler(format!(
            "prepare USB audit serial HMAC secrets directory failed: {err}"
        ))
    })?;
    crate::sys::path_safe::ensure_dir(key_dir, 0o700, owner, owner).map_err(|err| {
        BrokerError::LiveHandler(format!(
            "prepare USB audit serial HMAC key directory failed: {err}"
        ))
    })?;
    Ok(())
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn read_usb_audit_serial_hmac_key_file(
    path: &Path,
    slot: UsbAuditSerialHmacKeySlot,
    test_mode: bool,
) -> Result<Option<UsbAuditSerialHmacKey>, BrokerError> {
    let fd = match nix::fcntl::open(
        path,
        nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_CLOEXEC | nix::fcntl::OFlag::O_NOFOLLOW,
        nix::sys::stat::Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(nix::errno::Errno::ENOENT) => return Ok(None),
        Err(err) => {
            return Err(BrokerError::LiveHandler(format!(
                "open USB audit serial HMAC key failed: {err}"
            )));
        }
    };
    let mut file = fs::File::from(owned_fd_from_raw(fd));
    validate_usb_audit_serial_hmac_key_metadata(&file, test_mode)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).map_err(|err| {
        BrokerError::LiveHandler(format!("read USB audit serial HMAC key failed: {err}"))
    })?;
    parse_usb_audit_serial_hmac_key(&contents, slot).map(Some)
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn validate_usb_audit_serial_hmac_key_metadata(
    file: &fs::File,
    test_mode: bool,
) -> Result<(), BrokerError> {
    let metadata = file.metadata().map_err(|err| {
        BrokerError::LiveHandler(format!("stat USB audit serial HMAC key failed: {err}"))
    })?;
    if !metadata.is_file() || metadata.mode() & 0o077 != 0 || (!test_mode && metadata.uid() != 0) {
        return Err(BrokerError::LiveHandler(
            "USB audit serial HMAC key must be a root-only regular file".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn create_usb_audit_serial_hmac_key(
    key_dir: &Path,
    test_mode: bool,
) -> Result<UsbAuditSerialHmacKey, BrokerError> {
    let key = generate_usb_audit_serial_hmac_key()?;
    let dir_fd = crate::sys::path_safe::open_dir_path_safe(key_dir).map_err(|err| {
        BrokerError::LiveHandler(format!(
            "open USB audit serial HMAC key directory failed: {err}"
        ))
    })?;
    match write_new_usb_audit_serial_hmac_key_file(&dir_fd, &key) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
        Err(err) => {
            return Err(BrokerError::LiveHandler(format!(
                "create USB audit serial HMAC key failed: {err}"
            )));
        }
    }
    read_usb_audit_serial_hmac_key_file(
        &key_dir.join(USB_AUDIT_SERIAL_HMAC_CURRENT_KEY_FILE),
        UsbAuditSerialHmacKeySlot::Current,
        test_mode,
    )?
    .ok_or_else(|| {
        BrokerError::LiveHandler("USB audit serial HMAC key disappeared after creation".to_owned())
    })
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn write_new_usb_audit_serial_hmac_key_file(
    dir_fd: &OwnedFd,
    key: &UsbAuditSerialHmacKey,
) -> io::Result<()> {
    let fd = crate::sys::path_safe::create_file_at_safe(
        dir_fd,
        USB_AUDIT_SERIAL_HMAC_CURRENT_KEY_FILE,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o400,
    )?;
    let mut file = fs::File::from(fd);
    std::io::Write::write_all(&mut file, render_usb_audit_serial_hmac_key(key).as_bytes())?;
    crate::sys::path_safe::fchmod(file.as_fd(), 0o400)?;
    file.sync_all()?;
    rustix::fs::fsync(dir_fd).map_err(|err| io::Error::from_raw_os_error(err.raw_os_error()))?;
    Ok(())
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn generate_usb_audit_serial_hmac_key() -> Result<UsbAuditSerialHmacKey, BrokerError> {
    let random = read_high_entropy_bytes(USB_AUDIT_SERIAL_HMAC_RANDOM_BYTES)?;
    let (key, id_bytes) = random.split_at(USB_AUDIT_SERIAL_HMAC_KEY_BYTES);
    Ok(UsbAuditSerialHmacKey {
        slot: UsbAuditSerialHmacKeySlot::Current,
        key_id: format!("usb-audit-{}", lower_hex(id_bytes)),
        key: key.to_vec(),
    })
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn read_high_entropy_bytes(len: usize) -> Result<Vec<u8>, BrokerError> {
    let mut file = fs::File::open("/dev/urandom").map_err(|err| {
        BrokerError::LiveHandler(format!(
            "open kernel CSPRNG for USB audit key failed: {err}"
        ))
    })?;
    let mut bytes = vec![0u8; len];
    file.read_exact(&mut bytes).map_err(|err| {
        BrokerError::LiveHandler(format!(
            "read kernel CSPRNG for USB audit key failed: {err}"
        ))
    })?;
    Ok(bytes)
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn render_usb_audit_serial_hmac_key(key: &UsbAuditSerialHmacKey) -> String {
    format!(
        "{USB_AUDIT_SERIAL_HMAC_KEY_MAGIC}\nkey_id={}\nkey_hex={}\n",
        key.key_id,
        lower_hex(&key.key)
    )
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn parse_usb_audit_serial_hmac_key(
    contents: &str,
    slot: UsbAuditSerialHmacKeySlot,
) -> Result<UsbAuditSerialHmacKey, BrokerError> {
    let mut lines = contents.lines();
    if lines.next() != Some(USB_AUDIT_SERIAL_HMAC_KEY_MAGIC) {
        return Err(BrokerError::LiveHandler(
            "USB audit serial HMAC key has invalid magic".to_owned(),
        ));
    }
    let mut key_id = None;
    let mut key_hex = None;
    for line in lines {
        if let Some(value) = line.strip_prefix("key_id=") {
            key_id = Some(value.to_owned());
        } else if let Some(value) = line.strip_prefix("key_hex=") {
            key_hex = Some(value.to_owned());
        }
    }
    let key_id = key_id
        .filter(|value| usb_audit_key_id_is_safe(value))
        .ok_or_else(|| {
            BrokerError::LiveHandler("USB audit serial HMAC key id is invalid".to_owned())
        })?;
    let key = decode_fixed_hex_key(
        &key_hex.ok_or_else(|| {
            BrokerError::LiveHandler("USB audit serial HMAC key material is missing".to_owned())
        })?,
        USB_AUDIT_SERIAL_HMAC_KEY_BYTES,
    )?;
    Ok(UsbAuditSerialHmacKey { slot, key_id, key })
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn usb_audit_key_id_is_safe(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn decode_fixed_hex_key(value: &str, len: usize) -> Result<Vec<u8>, BrokerError> {
    if value.len() != len * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(BrokerError::LiveHandler(
            "USB audit serial HMAC key material is invalid".to_owned(),
        ));
    }
    (0..value.len())
        .step_by(2)
        .map(|idx| {
            u8::from_str_radix(&value[idx..idx + 2], 16).map_err(|err| {
                BrokerError::LiveHandler(format!("parse USB audit serial HMAC key failed: {err}"))
            })
        })
        .collect()
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let byte = *byte;
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn read_usb_serial_for_audit(sysfs_root: &Path, bus_id: &str) -> Option<String> {
    if d2b_contracts::usbip::validate_bus_id(bus_id).is_err() {
        return None;
    }
    let path = sysfs_root.join(bus_id).join("serial");
    match fs::read_to_string(path) {
        Ok(raw) => {
            let trimmed = raw.trim().to_owned();
            (!trimmed.is_empty()).then_some(trimmed)
        }
        Err(_) => None,
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn usb_device_node_for_busid(sysfs_root: &Path, bus_id: &str) -> Result<PathBuf, BrokerError> {
    d2b_contracts::usbip::validate_bus_id(bus_id)
        .map_err(|err| BrokerError::LiveHandler(format!("invalid usbip bus_id: {err:?}")))?;
    let device_dir = sysfs_root.join(bus_id);
    let busnum = read_usb_decimal_attr(&device_dir, "busnum", bus_id)?;
    let devnum = read_usb_decimal_attr(&device_dir, "devnum", bus_id)?;
    Ok(PathBuf::from(format!(
        "/dev/bus/usb/{busnum:03}/{devnum:03}"
    )))
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn read_usb_decimal_attr(device_dir: &Path, attr: &str, bus_id: &str) -> Result<u16, BrokerError> {
    let path = device_dir.join(attr);
    let raw = fs::read_to_string(&path).map_err(|err| {
        BrokerError::LiveHandler(format!(
            "read USB {attr} for bus_id={bus_id} at {} failed: {err}",
            path.display()
        ))
    })?;
    raw.trim().parse::<u16>().map_err(|err| {
        BrokerError::LiveHandler(format!(
            "parse USB {attr} for bus_id={bus_id} at {} failed: {err}",
            path.display()
        ))
    })
}

#[cfg(all(test, not(feature = "layer1-bootstrap")))]
#[derive(Debug, Clone, PartialEq, Eq)]
enum TestUsbipBackendAclEvent {
    Grant { uid: u32 },
    Revoke { uid: u32 },
}

#[cfg(all(test, not(feature = "layer1-bootstrap")))]
fn test_usbip_backend_acl_events() -> &'static Mutex<Vec<TestUsbipBackendAclEvent>> {
    static EVENTS: OnceLock<Mutex<Vec<TestUsbipBackendAclEvent>>> = OnceLock::new();
    EVENTS.get_or_init(|| Mutex::new(Vec::new()))
}

#[cfg(all(test, not(feature = "layer1-bootstrap")))]
fn take_test_usbip_backend_acl_events() -> Vec<TestUsbipBackendAclEvent> {
    let mut events = test_usbip_backend_acl_events()
        .lock()
        .expect("test USBIP ACL event lock");
    std::mem::take(&mut *events)
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn rollback_usbip_bind_after_audit_failure<B: DispatchBackend>(
    backend: &B,
    resolver: &Arc<BundleResolver>,
    intent: &d2b_core::bundle_resolver::ResolvedUsbipBindIntent,
    same_vm_replay: bool,
) {
    if same_vm_replay {
        return;
    }
    if let Err(revoke_error) = revoke_usbip_backend_device_acl(resolver, intent) {
        warn!(
            bus_id = %intent.bus_id,
            vm = %intent.vm_name,
            error = ?revoke_error,
            "UsbipBind audit write failed and backend ACL rollback failed"
        );
    }
    match backend.usbip_unbind(intent) {
        Ok(()) => {
            if let Err(lock_error) =
                crate::ops::usbip_lock::release_lock(&intent.lock_path, &intent.vm_name)
            {
                warn!(
                    bus_id = %intent.bus_id,
                    vm = %intent.vm_name,
                    error = %lock_error,
                    "UsbipBind audit write failed and lock rollback failed"
                );
            }
        }
        Err(unbind_error) => {
            warn!(
                bus_id = %intent.bus_id,
                vm = %intent.vm_name,
                error = ?unbind_error,
                "UsbipBind audit write failed and backend unbind rollback failed"
            );
        }
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn rollback_usbip_bind_after_acl_grant_failure<B: DispatchBackend>(
    backend: &B,
    intent: &d2b_core::bundle_resolver::ResolvedUsbipBindIntent,
    same_vm_replay: bool,
    grant_error: BrokerError,
) -> BrokerError {
    if same_vm_replay {
        return grant_error;
    }
    match backend.usbip_unbind(intent) {
        Ok(()) => {
            if let Err(lock_error) =
                crate::ops::usbip_lock::release_lock(&intent.lock_path, &intent.vm_name)
            {
                warn!(
                    bus_id = %intent.bus_id,
                    vm = %intent.vm_name,
                    grant_error = ?grant_error,
                    error = %lock_error,
                    "UsbipBind ACL grant failed, rollback unbind succeeded, but lock rollback failed"
                );
            }
        }
        Err(rollback_error) => {
            warn!(
                bus_id = %intent.bus_id,
                vm = %intent.vm_name,
                grant_error = ?grant_error,
                rollback_error = ?rollback_error,
                "UsbipBind ACL grant failed and rollback unbind also failed"
            );
        }
    }
    grant_error
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn handle_usbip_acl_revoke_failure_after_unbind(
    intent: &d2b_core::bundle_resolver::ResolvedUsbipBindIntent,
    preserve_durable_claim: bool,
    revoke_error: BrokerError,
) -> BrokerError {
    if preserve_durable_claim {
        return revoke_error;
    }

    // `backend.usbip_unbind` succeeded before the ACL revoke was attempted.
    // Release the host-session claim on revoke failure unless a best-effort
    // live recheck proves the device is still attached to usbip-host. If the
    // recheck itself fails, trust the successful unbind result and release to
    // avoid converting an ACL cleanup error into a stale busid lock.
    match crate::ops::usbip_host::inspect_usbip_driver_binding(
        usb_device_sysfs_root(),
        &intent.bus_id,
    ) {
        Ok(crate::ops::usbip_host::UsbipDriverBinding::BoundToUsbipHost) => {
            warn!(
                bus_id = %intent.bus_id,
                vm = %intent.vm_name,
                revoke_error = ?revoke_error,
                "UsbipUnbind ACL revoke failed after unbind, but device still appears bound to usbip-host; preserving lock for manual recovery"
            );
            return revoke_error;
        }
        Ok(observed) => {
            warn!(
                bus_id = %intent.bus_id,
                vm = %intent.vm_name,
                observed = ?observed,
                revoke_error = ?revoke_error,
                "UsbipUnbind ACL revoke failed after unbind; releasing lock because device is no longer bound to usbip-host"
            );
        }
        Err(inspect_error) => {
            warn!(
                bus_id = %intent.bus_id,
                vm = %intent.vm_name,
                inspect_error = %inspect_error,
                revoke_error = ?revoke_error,
                "UsbipUnbind ACL revoke failed after unbind and post-unbind inspection failed; releasing lock based on successful unbind"
            );
        }
    }

    if let Err(lock_error) =
        crate::ops::usbip_lock::release_lock(&intent.lock_path, &intent.vm_name)
    {
        return BrokerError::LiveHandler(format!(
            "USBIP ACL revoke failed after successful unbind and lock release failed: revoke_error={revoke_error:?}; lock_error={lock_error}"
        ));
    }
    revoke_error
}

#[cfg(not(feature = "layer1-bootstrap"))]
const USBIP_BACKEND_ACL_GRANT_ATTEMPTS: usize = 20;

#[cfg(not(feature = "layer1-bootstrap"))]
const USBIP_BACKEND_ACL_GRANT_RETRY_SLEEP: std::time::Duration =
    std::time::Duration::from_millis(100);

#[cfg(not(feature = "layer1-bootstrap"))]
fn retry_usbip_backend_acl_grant<V, G, R, S>(
    uid: u32,
    mut verify_device_node: V,
    mut grant_acl: G,
    mut revoke_acl: R,
    mut sleep: S,
) -> Result<(), BrokerError>
where
    V: FnMut() -> Result<PathBuf, BrokerError>,
    G: FnMut(&Path, u32) -> Result<(), BrokerError>,
    R: FnMut(&Path, u32) -> Result<(), BrokerError>,
    S: FnMut(),
{
    let mut last_error = None;

    for _ in 0..USBIP_BACKEND_ACL_GRANT_ATTEMPTS {
        let device_node = match verify_device_node() {
            Ok(device_node) => device_node,
            Err(error) => {
                last_error = Some(error);
                sleep();
                continue;
            }
        };

        if let Err(error) = grant_acl(&device_node, uid) {
            last_error = Some(error);
            sleep();
            continue;
        }

        match verify_device_node() {
            Ok(current_device_node) if current_device_node == device_node => return Ok(()),
            Ok(current_device_node) => {
                let _ = revoke_acl(&device_node, uid);
                last_error = Some(BrokerError::LiveHandler(format!(
                    "USBIP device node changed while granting backend ACL: granted {}, observed {}; retrying",
                    device_node.display(),
                    current_device_node.display(),
                )));
            }
            Err(error) => {
                let _ = revoke_acl(&device_node, uid);
                last_error = Some(error);
            }
        }
        sleep();
    }

    Err(last_error.unwrap_or_else(|| {
        BrokerError::LiveHandler("grant USBIP backend device ACL failed".to_owned())
    }))
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn grant_usbip_backend_device_acl(
    resolver: &Arc<BundleResolver>,
    intent: &d2b_core::bundle_resolver::ResolvedUsbipBindIntent,
    expected_identity: (u16, u16),
    _expected_device_node: PathBuf,
) -> Result<(), BrokerError> {
    let runner = usbip_backend_runner_intent(resolver, intent)?;
    #[cfg(test)]
    {
        let _ = expected_identity;
        test_usbip_backend_acl_events()
            .lock()
            .map_err(|_| BrokerError::Protocol("test USBIP ACL event mutex poisoned".to_owned()))?
            .push(TestUsbipBackendAclEvent::Grant { uid: runner.uid });
        Ok(())
    }
    #[cfg(not(test))]
    {
        fn verify_usbip_device_node(
            intent: &d2b_core::bundle_resolver::ResolvedUsbipBindIntent,
            expected_identity: (u16, u16),
        ) -> Result<PathBuf, BrokerError> {
            let inspection = crate::ops::usbip_host::enforce_usbip_physical_policy(
                intent,
                usb_device_sysfs_root(),
            )
            .map_err(|err| map_usbip_host_inspection_error_for_intent(intent, err))?;
            let current_identity = (inspection.vendor, inspection.product);
            let current_device_node = inspection.device_node;
            if current_identity != expected_identity {
                return Err(BrokerError::LiveHandler(format!(
                    "USBIP device identity changed while granting backend ACL for bus_id={}: expected {:?}, observed {:?} at {}",
                    intent.bus_id,
                    expected_identity,
                    current_identity,
                    current_device_node.display(),
                )));
            }
            Ok(current_device_node)
        }
        retry_usbip_backend_acl_grant(
            runner.uid,
            || verify_usbip_device_node(intent, expected_identity),
            |device_node, uid| {
                crate::live_handlers::live_grant_verified_device_acl(device_node, uid)
                    .map_err(|err| BrokerError::LiveHandler(err.to_string()))
            },
            |device_node, uid| {
                crate::live_handlers::live_revoke_verified_device_acl(device_node, uid)
                    .map_err(|err| BrokerError::LiveHandler(err.to_string()))
            },
            || std::thread::sleep(USBIP_BACKEND_ACL_GRANT_RETRY_SLEEP),
        )
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn revoke_usbip_backend_device_acl(
    resolver: &Arc<BundleResolver>,
    intent: &d2b_core::bundle_resolver::ResolvedUsbipBindIntent,
) -> Result<(), BrokerError> {
    let runner = usbip_backend_runner_intent(resolver, intent)?;
    #[cfg(test)]
    {
        test_usbip_backend_acl_events()
            .lock()
            .map_err(|_| BrokerError::Protocol("test USBIP ACL event mutex poisoned".to_owned()))?
            .push(TestUsbipBackendAclEvent::Revoke { uid: runner.uid });
        Ok(())
    }
    #[cfg(not(test))]
    {
        let inspection =
            crate::ops::usbip_host::enforce_usbip_physical_policy(intent, usb_device_sysfs_root())
                .map_err(|err| map_usbip_host_inspection_error_for_intent(intent, err))?;
        let device_node = inspection.device_node;
        crate::live_handlers::live_revoke_verified_device_acl(&device_node, runner.uid)
            .map_err(|err| BrokerError::LiveHandler(err.to_string()))
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn reconcile_active_usbip_backend_acls(resolver: &Arc<BundleResolver>) -> Result<(), BrokerError> {
    for intent in active_locked_usbip_bind_intents(resolver)? {
        let inspection = match crate::ops::usbip_host::enforce_usbip_physical_policy(
            &intent,
            usb_device_sysfs_root(),
        ) {
            Ok(inspection) => inspection,
            Err(crate::ops::usbip_host::UsbipHostInspectionError::DeviceMissing { bus_id }) => {
                tracing::debug!(
                    bus_id = %bus_id,
                    vm = %intent.vm_name,
                    "USBIP proxy reconcile skipped backend ACL refresh for absent device"
                );
                continue;
            }
            Err(
                crate::ops::usbip_host::UsbipHostInspectionError::DeviceDepartedDuringInspection {
                    bus_id,
                },
            ) => {
                tracing::debug!(
                    bus_id = %bus_id,
                    vm = %intent.vm_name,
                    "USBIP proxy reconcile skipped backend ACL refresh for device that departed during inspection"
                );
                continue;
            }
            Err(err) => return Err(map_usbip_host_inspection_error_for_intent(&intent, err)),
        };
        grant_usbip_backend_device_acl(
            resolver,
            &intent,
            (inspection.vendor, inspection.product),
            inspection.device_node,
        )?;
    }
    Ok(())
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn usbip_backend_runner_intent<'a>(
    resolver: &'a Arc<BundleResolver>,
    intent: &d2b_core::bundle_resolver::ResolvedUsbipBindIntent,
) -> Result<&'a d2b_core::bundle_resolver::ResolvedRunnerIntent, BrokerError> {
    let runner_id = d2b_core::bundle_resolver::intent_id_legacy_runner(
        &format!("sys-{}-usbipd", intent.env),
        "backend",
    );
    resolver
        .find_runner_intent(&runner_id)
        .ok_or(BrokerError::BundleIntentMissing {
            kind: "runner",
            intent_id: runner_id,
        })
}

/// Resolve the env USBIP backend runner UID for the explicit attach path.
/// Returns the UID of the `sys-<env>-usbipd/backend` runner so the broker
/// can grant the per-device ACL without needing a full `ResolvedUsbipBindIntent`.
#[cfg(not(feature = "layer1-bootstrap"))]
fn explicit_usbip_backend_uid(
    resolver: &Arc<BundleResolver>,
    env: &str,
) -> Result<u32, BrokerError> {
    let runner_id =
        d2b_core::bundle_resolver::intent_id_legacy_runner(&format!("sys-{env}-usbipd"), "backend");
    resolver
        .find_runner_intent(&runner_id)
        .map(|r| r.uid)
        .ok_or(BrokerError::BundleIntentMissing {
            kind: "runner",
            intent_id: runner_id,
        })
}

/// Validate and build the scoped nftables rule body for an explicit USBIP
/// attach. Cross-checks the request IPs against the env's declared host config
/// values to prevent the daemon from installing rules for a different env's
/// bridge. Returns the rule body string on success.
#[cfg(not(feature = "layer1-bootstrap"))]
fn build_explicit_usbip_rule_body(
    resolver: &BundleResolver,
    env: &str,
    req_host_uplink_ip: &str,
    req_net_uplink_ip: &str,
) -> Result<(String, String), BrokerError> {
    use std::net::IpAddr;
    let env_config = resolver.find_host_env(env).ok_or_else(|| {
        BrokerError::LiveHandler(format!(
            "explicit USBIP firewall: env {env:?} not found in host config"
        ))
    })?;

    // Validate anti-spoof bridge port flags (uplink must be isolated+neigh_suppress,
    // no MAC learning, no unknown-unicast flood).
    let uplink_flags = env_config
        .bridge_port_flags
        .iter()
        .find(|f| f.role == d2b_core::host::TapRole::Uplink)
        .ok_or_else(|| {
            BrokerError::LiveHandler(format!(
                "explicit USBIP firewall: env {env:?} has no uplink bridge port flags"
            ))
        })?;
    if !uplink_flags.isolated
        || !uplink_flags.neigh_suppress
        || uplink_flags.resolved_learning()
        || uplink_flags.resolved_unicast_flood()
    {
        return Err(BrokerError::LiveHandler(format!(
            "explicit USBIP firewall: env {env:?} uplink bridge port flags fail anti-spoof validation (isolated={} neigh_suppress={} learning={} unicast_flood={})",
            uplink_flags.isolated,
            uplink_flags.neigh_suppress,
            uplink_flags.resolved_learning(),
            uplink_flags.resolved_unicast_flood(),
        )));
    }

    // Cross-check request IPs against the env's declared values. This prevents
    // a compromised daemon from installing a carve-out scoped to the wrong env.
    let env_host_ip = env_config.host_uplink_ip.as_deref().ok_or_else(|| {
        BrokerError::LiveHandler(format!(
            "explicit USBIP firewall: env {env:?} has no host_uplink_ip in host config"
        ))
    })?;
    let env_net_ip = env_config.net_uplink_ip.as_deref().ok_or_else(|| {
        BrokerError::LiveHandler(format!(
            "explicit USBIP firewall: env {env:?} has no net_uplink_ip in host config"
        ))
    })?;
    if req_host_uplink_ip != env_host_ip || req_net_uplink_ip != env_net_ip {
        return Err(BrokerError::LiveHandler(format!(
            "explicit USBIP firewall: request IPs do not match env {env:?} declared IPs (host_uplink_ip: req={req_host_uplink_ip:?} env={env_host_ip:?}; net_uplink_ip: req={req_net_uplink_ip:?} env={env_net_ip:?})"
        )));
    }

    // Validate the IPs are non-loopback, non-unspecified IPv4.
    fn safe_ipv4(value: &str) -> Option<String> {
        match value.parse::<IpAddr>().ok()? {
            IpAddr::V4(addr)
                if !addr.is_unspecified() && !addr.is_loopback() && !addr.is_multicast() =>
            {
                Some(addr.to_string())
            }
            _ => None,
        }
    }
    let host_ip = safe_ipv4(req_host_uplink_ip).ok_or_else(|| {
        BrokerError::LiveHandler(format!(
            "explicit USBIP firewall: host_uplink_ip {req_host_uplink_ip:?} is not a valid non-loopback IPv4"
        ))
    })?;
    let net_ip = safe_ipv4(req_net_uplink_ip).ok_or_else(|| {
        BrokerError::LiveHandler(format!(
            "explicit USBIP firewall: net_uplink_ip {req_net_uplink_ip:?} is not a valid non-loopback IPv4"
        ))
    })?;

    let bridge_ifname = env_config.bridge.as_str();
    // Validate the bridge ifname is safe for nft literals.
    if bridge_ifname.contains('"') || bridge_ifname.contains('\\') || bridge_ifname.contains('\0') {
        return Err(BrokerError::LiveHandler(format!(
            "explicit USBIP firewall: env {env:?} bridge ifname contains unsafe characters"
        )));
    }

    let rule_body = format!(
        "iifname \"{bridge_ifname}\" ip saddr {net_ip} ip daddr {host_ip} ip protocol tcp tcp dport 3240 accept"
    );
    Ok((bridge_ifname.to_owned(), rule_body))
}

/// Grant the per-device ACL to the env's USBIP backend runner for the explicit
/// attach path. Unlike `grant_usbip_backend_device_acl` this does NOT check a
/// vendor/product allowlist; the explicit path carries no bundle allowlist.
/// Retries up to 20 times with 100ms sleep (same policy as the declared path).
#[cfg(not(feature = "layer1-bootstrap"))]
fn grant_explicit_usbip_backend_acl(
    resolver: &Arc<BundleResolver>,
    env: &str,
    bus_id: &str,
    expected_identity: (u16, u16),
    _expected_device_node: PathBuf,
) -> Result<(), BrokerError> {
    let backend_uid = explicit_usbip_backend_uid(resolver, env)?;
    #[cfg(test)]
    {
        let _ = bus_id;
        let _ = expected_identity;
        test_usbip_backend_acl_events()
            .lock()
            .map_err(|_| BrokerError::Protocol("test USBIP ACL event mutex poisoned".to_owned()))?
            .push(TestUsbipBackendAclEvent::Grant { uid: backend_uid });
        Ok(())
    }
    #[cfg(not(test))]
    {
        retry_usbip_backend_acl_grant(
            backend_uid,
            || verify_explicit_usbip_device_stable(bus_id, expected_identity),
            |device_node, uid| {
                crate::live_handlers::live_grant_verified_device_acl(device_node, uid)
                    .map_err(|err| BrokerError::LiveHandler(err.to_string()))
            },
            |device_node, uid| {
                crate::live_handlers::live_revoke_verified_device_acl(device_node, uid)
                    .map_err(|err| BrokerError::LiveHandler(err.to_string()))
            },
            || std::thread::sleep(USBIP_BACKEND_ACL_GRANT_RETRY_SLEEP),
        )
    }
}

/// Stability check for explicit USBIP device ACL grant. Uses
/// `inspect_usbip_host_device` (no allowlist check) to verify the device at
/// `bus_id` still matches `expected_identity` and `expected_device_node`.
#[cfg(all(not(feature = "layer1-bootstrap"), not(test)))]
fn verify_explicit_usbip_device_stable(
    bus_id: &str,
    expected_identity: (u16, u16),
) -> Result<PathBuf, BrokerError> {
    let inspection =
        crate::ops::usbip_host::inspect_usbip_host_device(usb_device_sysfs_root(), bus_id)
            .map_err(|err| {
                BrokerError::LiveHandler(format!(
                    "explicit USBIP device stability check failed for bus_id={bus_id}: {err}"
                ))
            })?;
    let current_identity = (inspection.vendor, inspection.product);
    let current_device_node = inspection.device_node;
    if current_identity != expected_identity {
        return Err(BrokerError::LiveHandler(format!(
            "USBIP device identity changed while granting backend ACL for bus_id={bus_id}: expected {:?}, observed {:?} at {}",
            expected_identity,
            current_identity,
            current_device_node.display(),
        )));
    }
    Ok(current_device_node)
}

/// Revoke the per-device ACL from the env's USBIP backend runner for the
/// explicit attach path rollback. Best-effort; failures are logged only.
#[cfg(not(feature = "layer1-bootstrap"))]
fn revoke_explicit_usbip_backend_acl(
    resolver: &Arc<BundleResolver>,
    env: &str,
    bus_id: &str,
) -> Result<(), BrokerError> {
    let backend_uid = explicit_usbip_backend_uid(resolver, env)?;
    #[cfg(test)]
    {
        let _ = bus_id;
        test_usbip_backend_acl_events()
            .lock()
            .map_err(|_| BrokerError::Protocol("test USBIP ACL event mutex poisoned".to_owned()))?
            .push(TestUsbipBackendAclEvent::Revoke { uid: backend_uid });
        Ok(())
    }
    #[cfg(not(test))]
    {
        let inspection =
            crate::ops::usbip_host::inspect_usbip_host_device(usb_device_sysfs_root(), bus_id)
                .map_err(|err| {
                    BrokerError::LiveHandler(format!(
                        "explicit USBIP revoke inspection failed for bus_id={bus_id}: {err}"
                    ))
                })?;
        crate::live_handlers::live_revoke_verified_device_acl(&inspection.device_node, backend_uid)
            .map_err(|err| BrokerError::LiveHandler(err.to_string()))
    }
}

/// Collect rule bodies for all currently active explicit USBIP carve-outs
/// (busids locked in `/run/d2b/locks/usbip/` that are neither declared
/// in the bundle as static intents nor resolvable via the wildcard
/// `pending` fallback). Used by `build_usbip_explicit_firewall_decision`
/// to preserve existing explicit carve-outs when atomically replacing the
/// nftables state.
///
/// Entries for `excluding_bus_id` are skipped (caller adds its own carveout).
#[cfg(not(feature = "layer1-bootstrap"))]
fn collect_active_explicit_usbip_carveouts(
    resolver: &BundleResolver,
    excluding_bus_id: &str,
) -> Vec<(String, String)> {
    let Ok(entries) = std::fs::read_dir("/run/d2b/locks/usbip") else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let bus_id = entry.file_name().into_string().ok()?;
            d2b_contracts::usbip::validate_bus_id(&bus_id).ok()?;
            if bus_id == excluding_bus_id {
                return None;
            }
            // Skip busids that are handled by the declared (static or wildcard) path.
            if static_usbip_busid_owner(resolver, &bus_id).is_some() {
                return None;
            }
            let vm = crate::ops::usbip_lock::peek_owner(&entry.path())?;
            if find_wildcard_usbip_bind_intent_for(resolver, &vm, &bus_id).is_some() {
                return None;
            }
            // Pure explicit busid - reconstruct rule body from manifest + host config.
            let vm_entry = resolver.find_manifest_vm(&vm)?;
            let env = vm_entry.env.as_deref()?;
            let env_config = resolver.find_host_env(env)?;
            let host_ip = env_config.host_uplink_ip.as_deref()?;
            let net_ip = env_config.net_uplink_ip.as_deref()?;
            // Validate bridge port flags fail-closed: skip carveout if anti-spoof
            // invariants are no longer satisfied (operator may have changed bridge config).
            let uplink_flags = env_config
                .bridge_port_flags
                .iter()
                .find(|f| f.role == d2b_core::host::TapRole::Uplink)?;
            if !uplink_flags.isolated
                || !uplink_flags.neigh_suppress
                || uplink_flags.resolved_learning()
                || uplink_flags.resolved_unicast_flood()
            {
                return None;
            }
            let bridge_ifname = env_config.bridge.as_str();
            if bridge_ifname.contains('"')
                || bridge_ifname.contains('\\')
                || bridge_ifname.contains('\0')
            {
                return None;
            }
            let rule_body = format!(
                "iifname \"{bridge_ifname}\" ip saddr {net_ip} ip daddr {host_ip} ip protocol tcp tcp dport 3240 accept"
            );
            Some((bus_id, rule_body))
        })
        .collect()
}

/// Build the nft firewall decision for an explicit USBIP attach. Starts from
/// the host nft base, preserves all currently-active declared and explicit
/// carve-outs, and inserts the new carve-out for `bus_id`.
#[cfg(not(feature = "layer1-bootstrap"))]
fn build_usbip_explicit_firewall_decision(
    resolver: &BundleResolver,
    host_nft_intent: &d2b_core::bundle_resolver::ResolvedNftIntent,
    bus_id: &str,
    rule_body: &str,
) -> Result<crate::ops::usbip_firewall::UsbipBindFirewallRuleDecision, BrokerError> {
    let mut batch = d2b_host::nftables::NftBatch::parse(host_nft_intent.script_body.as_str())
        .map_err(|err| BrokerError::NftScriptParseFailed(err.to_string()))?;
    let mut inserted = std::collections::BTreeSet::<String>::new();

    // Add carveouts for all declared (statically locked) USBIP busids.
    for id in resolver.usbip_bind_intent_ids() {
        let Some(bind_intent) = resolver.find_usbip_bind_intent(id) else {
            continue;
        };
        let Some(owner) = crate::ops::usbip_lock::peek_owner(&bind_intent.lock_path) else {
            continue;
        };
        if owner != bind_intent.vm_name {
            continue;
        }
        let firewall_id = d2b_core::bundle_resolver::intent_id_usbip_firewall(
            &bind_intent.env,
            &bind_intent.bus_id,
        );
        if !inserted.insert(firewall_id.clone()) {
            continue;
        }
        let Some(active_firewall) = resolver.find_usbip_firewall_intent(&firewall_id) else {
            continue;
        };
        batch
            .add_usbip_carveout_expr(
                d2b_host::nftables::ChainHook::Input,
                &d2b_host::nftables::BusId::new(active_firewall.bus_id.as_str()),
                active_firewall.nft_rule_body.as_str(),
            )
            .map_err(|err| BrokerError::LiveHandler(err.to_string()))?;
    }

    // Add carveouts for active dynamic (declared wildcard) USBIP busids.
    for bind_intent in active_dynamic_usbip_bind_intents(resolver) {
        let firewall_id = d2b_core::bundle_resolver::intent_id_usbip_firewall(
            &bind_intent.env,
            &bind_intent.bus_id,
        );
        if !inserted.insert(firewall_id.clone()) {
            continue;
        }
        let Some(active_firewall) = find_usbip_firewall_intent_or_wildcard(resolver, &firewall_id)
        else {
            continue;
        };
        batch
            .add_usbip_carveout_expr(
                d2b_host::nftables::ChainHook::Input,
                &d2b_host::nftables::BusId::new(active_firewall.bus_id.as_str()),
                active_firewall.nft_rule_body.as_str(),
            )
            .map_err(|err| BrokerError::LiveHandler(err.to_string()))?;
    }

    // Add carveouts for currently active explicit busids (not in bundle, but locked).
    // Reconstructed on-the-fly from the lock owner's manifest entry + env host config.
    for (explicit_bus_id, explicit_rule_body) in
        collect_active_explicit_usbip_carveouts(resolver, bus_id)
    {
        let carveout_id = format!("explicit:{explicit_bus_id}");
        if !inserted.insert(carveout_id) {
            continue;
        }
        batch
            .add_usbip_carveout_expr(
                d2b_host::nftables::ChainHook::Input,
                &d2b_host::nftables::BusId::new(explicit_bus_id.as_str()),
                explicit_rule_body.as_str(),
            )
            .map_err(|err| BrokerError::LiveHandler(err.to_string()))?;
    }

    // Insert the new explicit carveout last.
    crate::ops::usbip_firewall::bind_firewall_rule(
        batch,
        &d2b_host::nftables::BusId::new(bus_id),
        rule_body,
    )
    .map_err(|err| BrokerError::LiveHandler(err.to_string()))
}

fn runner_role_for_process_role(
    role: &d2b_core::processes::ProcessRole,
) -> Option<d2b_contracts_broker::broker_wire::RunnerRole> {
    use d2b_contracts_broker::broker_wire::RunnerRole;
    use d2b_core::processes::ProcessRole;

    match role {
        ProcessRole::ProviderController => Some(RunnerRole::ProviderController),
        ProcessRole::SwtpmPreStartFlush => Some(RunnerRole::SwtpmFlush),
        ProcessRole::Swtpm => Some(RunnerRole::Swtpm),
        ProcessRole::Virtiofsd => Some(RunnerRole::Virtiofsd),
        ProcessRole::Video => Some(RunnerRole::Video),
        ProcessRole::Gpu | ProcessRole::GpuRenderNode => Some(RunnerRole::Gpu),
        ProcessRole::Audio => Some(RunnerRole::Audio),
        ProcessRole::CloudHypervisorRunner => Some(RunnerRole::CloudHypervisor),
        ProcessRole::QemuMediaRunner => Some(RunnerRole::QemuMedia),
        ProcessRole::ActivationNixosRunner => Some(RunnerRole::ActivationNixos),
        ProcessRole::VsockRelay => Some(RunnerRole::VsockRelay),
        ProcessRole::OtelHostBridge => Some(RunnerRole::OtelHostBridge),
        ProcessRole::Usbip => Some(RunnerRole::Usbip),
        ProcessRole::WaylandProxy => Some(RunnerRole::WaylandProxy),
        ProcessRole::HostReconcile
        | ProcessRole::StoreVirtiofsPreflight
        | ProcessRole::ComponentSessionHealth
        | ProcessRole::SecurityKeyFrontend => None,
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn validate_guest_process_binding(
    request: &d2b_contracts_broker::broker_wire::BrokerRequest,
) -> Result<(), BrokerError> {
    use d2b_contracts_broker::broker_wire::BrokerRequest;

    let binding = match request {
        BrokerRequest::SpawnRunner(request) => request.guest_execution.as_ref(),
        BrokerRequest::OpenPidfd(request) => request.guest_execution.as_ref(),
        BrokerRequest::ObserveRunner(request) => request.guest_execution.as_ref(),
        BrokerRequest::StartSystemdUnit(request)
        | BrokerRequest::ObserveSystemdUnit(request)
        | BrokerRequest::CheckSystemdUserManager(request) => request.guest_execution.as_ref(),
        BrokerRequest::OpenSystemdUnitPidfd(request) => request.unit.guest_execution.as_ref(),
        BrokerRequest::StopSystemdUnit(request) => request.unit.guest_execution.as_ref(),
        BrokerRequest::SignalRunner(request) => request.guest_execution.as_ref(),
        BrokerRequest::DeregisterRunnerPidfd(request) => request.guest_execution.as_ref(),
        _ => None,
    };
    let Some(binding) = binding else {
        return Ok(());
    };
    if !binding.is_valid() {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "guest_execution",
            requested: "invalid".to_owned(),
            resolved: "nonzero-target-session-boot-assignment-generations".to_owned(),
        });
    }
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|_| {
        BrokerError::SpawnRunnerIntentMismatch {
            field: "guest_execution.boot_identity_digest",
            requested: "present".to_owned(),
            resolved: "kernel-boot-identity-unavailable".to_owned(),
        }
    })?;
    let mut digest = Sha256::new();
    digest.update(b"d2b-kernel-boot-id-v1\0");
    digest.update(boot_id.trim().as_bytes());
    let expected: [u8; 32] = digest.finalize().into();
    if binding.boot_identity_digest != expected {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "guest_execution.boot_identity_digest",
            requested: "mismatch".to_owned(),
            resolved: "kernel-boot-identity".to_owned(),
        });
    }
    Ok(())
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn validate_sandbox_launch_plan(
    req: &d2b_contracts_broker::broker_wire::SpawnRunnerRequest,
    intent: &d2b_core::bundle_resolver::ResolvedRunnerIntent,
    plan: &d2b_contracts_broker::broker_wire::SandboxLaunchPlan,
) -> Result<(), BrokerError> {
    if plan.domain
        != req
            .execution_domain
            .unwrap_or(d2b_contracts_resource::v3::execution_policy::ExecutionDomain::System)
    {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "sandbox_plan.domain",
            requested: format!("{:?}", plan.domain),
            resolved: "request-domain".to_owned(),
        });
    }
    if !plan.no_new_privileges {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "sandbox_plan.no_new_privileges",
            requested: "false".to_owned(),
            resolved: "true".to_owned(),
        });
    }
    if plan.start_root != intent.root_carve_out {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "sandbox_plan.start_root",
            requested: plan.start_root.to_string(),
            resolved: intent.root_carve_out.to_string(),
        });
    }
    if !plan.read_only_root {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "sandbox_plan.read_only_root",
            requested: "false".to_owned(),
            resolved: "unsupported".to_owned(),
        });
    }
    if plan.oom_score_adj != 0 {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "sandbox_plan.oom_score_adj",
            requested: plan.oom_score_adj.to_string(),
            resolved: "unsupported".to_owned(),
        });
    }
    if plan.environment_class != d2b_contracts_resource::v3::process::EnvironmentClass::Minimal {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "sandbox_plan.environment_class",
            requested: format!("{:?}", plan.environment_class),
            resolved: "minimal-only".to_owned(),
        });
    }
    let expected_namespaces = &intent.namespaces;
    let requested_namespaces = |class| match class {
        d2b_contracts_resource::v3::process::NamespaceClass::User => expected_namespaces.user,
        d2b_contracts_resource::v3::process::NamespaceClass::Pid => expected_namespaces.pid,
        d2b_contracts_resource::v3::process::NamespaceClass::Mount => expected_namespaces.mount,
        d2b_contracts_resource::v3::process::NamespaceClass::Ipc => expected_namespaces.ipc,
        d2b_contracts_resource::v3::process::NamespaceClass::Uts => expected_namespaces.uts,
        d2b_contracts_resource::v3::process::NamespaceClass::Network => expected_namespaces.net,
        d2b_contracts_resource::v3::process::NamespaceClass::Cgroup
        | d2b_contracts_resource::v3::process::NamespaceClass::Time => false,
    };
    for class in &plan.namespace_classes {
        if !requested_namespaces(*class) {
            tracing::warn!(
                requested = ?plan.namespace_classes,
                trusted = ?intent.namespaces,
                rejected = ?class,
                "SpawnRunner namespace contract mismatch",
            );
            return Err(BrokerError::SpawnRunnerIntentMismatch {
                field: "sandbox_plan.namespace_classes",
                requested: format!("{class:?}"),
                resolved: "bundle-profile".to_owned(),
            });
        }
    }
    if plan.namespace_classes.iter().any(|class| {
        matches!(
            class,
            d2b_contracts_resource::v3::process::NamespaceClass::User
        )
    }) != expected_namespaces.user
    {
        tracing::warn!(
            requested = ?plan.namespace_classes,
            trusted = ?intent.namespaces,
            "SpawnRunner user namespace contract mismatch",
        );
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "sandbox_plan.namespace_classes",
            requested: "user".to_owned(),
            resolved: "bundle-profile".to_owned(),
        });
    }
    if plan.user_namespace.is_some() != intent.user_namespace.is_some()
        || plan.user_namespace.is_some_and(|spec| {
            spec.mapping_class
                != d2b_contracts_resource::v3::process::MappingClass::ProcessPrincipalRoot
        })
    {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "sandbox_plan.user_namespace",
            requested: format!("{:?}", plan.user_namespace),
            resolved: "bundle-profile".to_owned(),
        });
    }
    if let Some(umask) = &plan.umask {
        let parsed =
            u32::from_str_radix(umask, 8).map_err(|_| BrokerError::SpawnRunnerIntentMismatch {
                field: "sandbox_plan.umask",
                requested: umask.clone(),
                resolved: "valid-octal".to_owned(),
            })?;
        if intent.umask != Some(parsed) {
            return Err(BrokerError::SpawnRunnerIntentMismatch {
                field: "sandbox_plan.umask",
                requested: umask.clone(),
                resolved: intent
                    .umask
                    .map_or_else(|| "inherit".to_owned(), |value| format!("{value:o}")),
            });
        }
    } else if intent.umask.is_some() {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "sandbox_plan.umask",
            requested: "inherit".to_owned(),
            resolved: "bundle-profile".to_owned(),
        });
    }
    if plan.capability_classes.iter().any(|class| {
        !intent
            .capabilities
            .iter()
            .any(|capability| capability_matches(*class, capability))
    }) {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "sandbox_plan.capability_classes",
            requested: "mismatch".to_owned(),
            resolved: "bundle-profile".to_owned(),
        });
    }
    if plan.seccomp_class.as_str() != "strict" || intent.seccomp_policy_ref.is_none() {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "sandbox_plan.seccomp_class",
            requested: plan.seccomp_class.as_str().to_owned(),
            resolved: "strict".to_owned(),
        });
    }
    let expected_namespaces = [
        (
            d2b_contracts_resource::v3::process::NamespaceClass::User,
            expected_namespaces.user,
        ),
        (
            d2b_contracts_resource::v3::process::NamespaceClass::Pid,
            expected_namespaces.pid,
        ),
        (
            d2b_contracts_resource::v3::process::NamespaceClass::Mount,
            expected_namespaces.mount,
        ),
        (
            d2b_contracts_resource::v3::process::NamespaceClass::Ipc,
            expected_namespaces.ipc,
        ),
        (
            d2b_contracts_resource::v3::process::NamespaceClass::Uts,
            expected_namespaces.uts,
        ),
        (
            d2b_contracts_resource::v3::process::NamespaceClass::Network,
            expected_namespaces.net,
        ),
    ]
    .into_iter()
    .filter_map(|(class, enabled)| enabled.then_some(class))
    .collect::<BTreeSet<_>>();
    let actual_namespaces = plan
        .namespace_classes
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if actual_namespaces != expected_namespaces
        || actual_namespaces.len() != plan.namespace_classes.len()
    {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "sandbox_plan.namespace_classes",
            requested: "mismatch".to_owned(),
            resolved: "bundle-profile".to_owned(),
        });
    }
    let expected_capabilities = intent
        .capabilities
        .iter()
        .filter_map(|capability| match capability.as_str() {
            "CAP_NET_BIND_SERVICE" => {
                Some(d2b_contracts_resource::v3::process::CapabilityClass::NetworkBind)
            }
            "CAP_NET_RAW" => Some(d2b_contracts_resource::v3::process::CapabilityClass::NetworkRaw),
            "CAP_NET_ADMIN" => {
                Some(d2b_contracts_resource::v3::process::CapabilityClass::NetworkAdmin)
            }
            "CAP_SYS_TIME" => Some(d2b_contracts_resource::v3::process::CapabilityClass::SysTime),
            "CAP_SYS_PTRACE" => {
                Some(d2b_contracts_resource::v3::process::CapabilityClass::SysPtrace)
            }
            "CAP_SYS_ADMIN" => Some(d2b_contracts_resource::v3::process::CapabilityClass::SysAdmin),
            "CAP_DAC_OVERRIDE" => {
                Some(d2b_contracts_resource::v3::process::CapabilityClass::DacOverride)
            }
            "CAP_FOWNER" => Some(d2b_contracts_resource::v3::process::CapabilityClass::Fowner),
            "CAP_CHOWN" => Some(d2b_contracts_resource::v3::process::CapabilityClass::Chown),
            "CAP_SETUID" => Some(d2b_contracts_resource::v3::process::CapabilityClass::Setuid),
            "CAP_SETGID" => Some(d2b_contracts_resource::v3::process::CapabilityClass::Setgid),
            "CAP_AUDIT_WRITE" => {
                Some(d2b_contracts_resource::v3::process::CapabilityClass::AuditWrite)
            }
            "CAP_KILL" => Some(d2b_contracts_resource::v3::process::CapabilityClass::Kill),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let actual_capabilities = plan
        .capability_classes
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if actual_capabilities != expected_capabilities
        || actual_capabilities.len() != plan.capability_classes.len()
    {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "sandbox_plan.capability_classes",
            requested: "mismatch".to_owned(),
            resolved: "bundle-profile".to_owned(),
        });
    }
    Ok(())
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn capability_matches(
    class: d2b_contracts_resource::v3::process::CapabilityClass,
    capability: &str,
) -> bool {
    let expected = match class {
        d2b_contracts_resource::v3::process::CapabilityClass::NetworkBind => "CAP_NET_BIND_SERVICE",
        d2b_contracts_resource::v3::process::CapabilityClass::NetworkRaw => "CAP_NET_RAW",
        d2b_contracts_resource::v3::process::CapabilityClass::NetworkAdmin => "CAP_NET_ADMIN",
        d2b_contracts_resource::v3::process::CapabilityClass::SysTime => "CAP_SYS_TIME",
        d2b_contracts_resource::v3::process::CapabilityClass::SysPtrace => "CAP_SYS_PTRACE",
        d2b_contracts_resource::v3::process::CapabilityClass::SysAdmin => "CAP_SYS_ADMIN",
        d2b_contracts_resource::v3::process::CapabilityClass::DacOverride => "CAP_DAC_OVERRIDE",
        d2b_contracts_resource::v3::process::CapabilityClass::Fowner => "CAP_FOWNER",
        d2b_contracts_resource::v3::process::CapabilityClass::Chown => "CAP_CHOWN",
        d2b_contracts_resource::v3::process::CapabilityClass::Setuid => "CAP_SETUID",
        d2b_contracts_resource::v3::process::CapabilityClass::Setgid => "CAP_SETGID",
        d2b_contracts_resource::v3::process::CapabilityClass::AuditWrite => "CAP_AUDIT_WRITE",
        d2b_contracts_resource::v3::process::CapabilityClass::Kill => "CAP_KILL",
    };
    capability == expected
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn typed_process_identity(
    resource_ref: Option<&d2b_contracts_resource::v3::ResourceRef>,
    resource_uid: Option<&d2b_contracts_resource::v3::ResourceUid>,
    zone_uid: Option<&d2b_contracts_resource::v3::ResourceUid>,
    generation: Option<u64>,
    runtime_scope: Option<[u8; 32]>,
    intent_role_id: &str,
    guest_execution: Option<&d2b_contracts_broker::broker_wire::GuestExecutionBinding>,
) -> Result<bool, BrokerError> {
    let typed = resource_ref.is_some()
        || resource_uid.is_some()
        || zone_uid.is_some()
        || runtime_scope.is_some();
    if !typed {
        return Ok(false);
    }
    let (Some(resource_ref), Some(resource_uid), Some(zone_uid), Some(generation), Some(scope)) = (
        resource_ref,
        resource_uid,
        zone_uid,
        generation,
        runtime_scope,
    ) else {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "process_identity",
            requested: "incomplete".to_owned(),
            resolved: "resource/zone/uid/generation/scope-required".to_owned(),
        });
    };
    if generation == 0 || scope == [0; 32] {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "process_identity",
            requested: "invalid".to_owned(),
            resolved: "nonzero-resource/zone/uid/generation/scope".to_owned(),
        });
    }
    if !matches!(
        resource_ref.resource_type().as_str(),
        "Process" | "EphemeralProcess"
    ) {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "resource_ref",
            requested: resource_ref.to_canonical_string(),
            resolved: "Process-or-EphemeralProcess".to_owned(),
        });
    }
    let expected = private_runtime_scope(
        zone_uid,
        guest_execution.map(|binding| &binding.target_uid),
        resource_ref,
        resource_uid,
        intent_role_id,
        generation,
    );
    if scope != expected {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "runtime_scope",
            requested: "mismatch".to_owned(),
            resolved: "zone-resource-generation-role-commitment".to_owned(),
        });
    }
    Ok(true)
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn typed_control_identity_complete(
    resource_ref: Option<&d2b_contracts_resource::v3::ResourceRef>,
    resource_uid: Option<&d2b_contracts_resource::v3::ResourceUid>,
    zone_uid: Option<&d2b_contracts_resource::v3::ResourceUid>,
    generation: Option<u64>,
    runtime_scope: Option<[u8; 32]>,
    provider_ref: Option<&d2b_contracts_resource::v3::ResourceRef>,
    provider_identity: Option<[u8; 32]>,
    template_identity: Option<[u8; 32]>,
) -> bool {
    let typed = resource_ref.is_some()
        || resource_uid.is_some()
        || zone_uid.is_some()
        || generation.is_some()
        || runtime_scope.is_some()
        || provider_ref.is_some()
        || provider_identity.is_some()
        || template_identity.is_some();
    if !typed {
        return true;
    }
    resource_ref.is_some()
        && resource_uid.is_some()
        && zone_uid.is_some()
        && generation.is_some_and(|generation| generation > 0)
        && runtime_scope.is_some_and(|scope| scope != [0; 32])
        && provider_ref.is_some()
        && provider_identity.is_some_and(|identity| identity != [0; 32])
        && template_identity.is_some_and(|identity| identity != [0; 32])
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn private_runtime_scope(
    zone_uid: &d2b_contracts_resource::v3::ResourceUid,
    guest_uid: Option<&d2b_contracts_resource::v3::ResourceUid>,
    resource_ref: &d2b_contracts_resource::v3::ResourceRef,
    resource_uid: &d2b_contracts_resource::v3::ResourceUid,
    role_id: &str,
    generation: u64,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"d2b-process-runtime-scope-v1");
    let resource_ref = resource_ref.to_canonical_string();
    for value in [
        zone_uid.as_str(),
        guest_uid.map(|uid| uid.as_str()).unwrap_or(""),
        resource_ref.as_str(),
        resource_uid.as_str(),
        role_id,
    ] {
        digest.update(value.as_bytes());
        digest.update([0]);
    }
    digest.update(generation.to_le_bytes());
    digest.finalize().into()
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn validate_typed_process_metadata(
    typed: bool,
    owner_ref: Option<&d2b_contracts_resource::v3::ResourceRef>,
    provider_ref: Option<&d2b_contracts_resource::v3::ResourceRef>,
    provider_identity: Option<[u8; 32]>,
    template_identity: Option<[u8; 32]>,
    guest_execution: Option<&d2b_contracts_broker::broker_wire::GuestExecutionBinding>,
    intent: &d2b_core::bundle_resolver::ResolvedRunnerIntent,
) -> Result<(), BrokerError> {
    if !typed {
        return Ok(());
    }
    let execution_is_guest = intent.execution_ref.starts_with("Guest/");
    if execution_is_guest != guest_execution.is_some()
        || guest_execution.is_some_and(|binding| !binding.is_valid())
    {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "guest_execution",
            requested: "mismatch".to_owned(),
            resolved: "bundle-execution-target".to_owned(),
        });
    }
    let Some(provider_identity) = provider_identity else {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "provider_identity",
            requested: "missing".to_owned(),
            resolved: "signed-process-provider".to_owned(),
        });
    };
    if provider_identity == [0; 32] {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "provider_identity",
            requested: "zero".to_owned(),
            resolved: "signed-process-provider".to_owned(),
        });
    }
    let Some(provider_ref) = provider_ref else {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "provider_ref",
            requested: "missing".to_owned(),
            resolved: "signed-process-provider".to_owned(),
        });
    };
    if provider_ref.resource_type().as_str() != "Provider"
        || !matches!(
            provider_ref.name().as_str(),
            "system-minijail" | "system-systemd"
        )
    {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "provider_ref",
            requested: "invalid".to_owned(),
            resolved: "fixed-process-provider".to_owned(),
        });
    }
    let mut provider_digest = Sha256::new();
    provider_digest.update(b"d2b-process-provider-v1");
    provider_digest.update(provider_ref.name().as_str().as_bytes());
    let expected_provider_identity: [u8; 32] = provider_digest.finalize().into();
    if provider_identity != expected_provider_identity {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "provider_identity",
            requested: "mismatch".to_owned(),
            resolved: "signed-process-provider".to_owned(),
        });
    }
    let expected_template = if intent.role == d2b_core::processes::ProcessRole::ProviderController {
        intent.profile_id.as_str()
    } else {
        intent.role_id.as_str()
    };
    let mut digest = Sha256::new();
    digest.update(b"d2b-process-template-v1");
    digest.update(expected_template.as_bytes());
    let expected_template: [u8; 32] = digest.finalize().into();
    if template_identity != Some(expected_template) {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "template_identity",
            requested: "mismatch".to_owned(),
            resolved: "bundle-process-template".to_owned(),
        });
    }
    if owner_ref.is_some_and(|owner| {
        !matches!(
            owner.resource_type().as_str(),
            "Guest" | "Host" | "Provider"
        )
    }) {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "owner_ref",
            requested: "invalid".to_owned(),
            resolved: "Guest-or-Host-or-Provider".to_owned(),
        });
    }
    if intent.role == d2b_core::processes::ProcessRole::ProviderController {
        let expected_owner = intent
            .owner_ref
            .as_deref()
            .map(d2b_contracts_resource::v3::ResourceRef::parse)
            .transpose()
            .map_err(|_| BrokerError::SpawnRunnerIntentMismatch {
                field: "owner_ref",
                requested: "invalid".to_owned(),
                resolved: "bundle-owner".to_owned(),
            })?;
        if owner_ref != expected_owner.as_ref() {
            return Err(BrokerError::SpawnRunnerIntentMismatch {
                field: "owner_ref",
                requested: "mismatch".to_owned(),
                resolved: "bundle-owner".to_owned(),
            });
        }
    }
    Ok(())
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn runtime_scope_segment(scope: [u8; 32]) -> String {
    let mut rendered = String::with_capacity(64);
    for byte in scope {
        rendered.push_str(&format!("{byte:02x}"));
    }
    format!("process-{rendered}")
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn private_cgroup_placement(
    placement: &d2b_core::minijail_profile::CgroupPlacement,
    vm_name: &str,
    runtime_scope: Option<[u8; 32]>,
    typed: bool,
) -> Result<d2b_core::minijail_profile::CgroupPlacement, BrokerError> {
    if !typed {
        return Ok(placement.clone());
    }
    let Some(runtime_scope) = runtime_scope else {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "cgroup_commitment",
            requested: "missing".to_owned(),
            resolved: "runtime-scope-required".to_owned(),
        });
    };
    let components = Path::new(&placement.subtree)
        .components()
        .collect::<Vec<_>>();
    if components
        .iter()
        .any(|component| !matches!(component, std::path::Component::Normal(_)))
        || !matches!(
            components.first(),
            Some(std::path::Component::Normal(value)) if *value == "d2b.slice"
        )
    {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "cgroup_commitment",
            requested: placement.subtree.clone(),
            resolved: "d2b.slice/<zone>/<guest>/<role>".to_owned(),
        });
    }
    let segment = |index: usize| {
        components.get(index).and_then(|component| match component {
            std::path::Component::Normal(value) => value.to_str(),
            _ => None,
        })
    };
    let role_start = if components.len() >= 4 && segment(2) == Some(vm_name) {
        3
    } else if components.len() >= 3 && segment(1) == Some(vm_name) {
        2
    } else {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "cgroup_commitment",
            requested: placement.subtree.clone(),
            resolved: "d2b.slice/<zone>/<guest>/<role>".to_owned(),
        });
    };
    let role_path = components[role_start..]
        .iter()
        .filter_map(|component| match component {
            std::path::Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/");
    if role_path.is_empty() {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "cgroup_commitment",
            requested: placement.subtree.clone(),
            resolved: "d2b.slice/<zone>/<guest>/<role>".to_owned(),
        });
    }
    let mut private = placement.clone();
    private.subtree = format!(
        "d2b.slice/{}/{role_path}",
        runtime_scope_segment(runtime_scope)
    );
    Ok(private)
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn validate_spawn_runner_request_matches_intent(
    req: &d2b_contracts_broker::broker_wire::SpawnRunnerRequest,
    intent: &d2b_core::bundle_resolver::ResolvedRunnerIntent,
) -> Result<(), BrokerError> {
    if req.vm_id.as_str() != intent.vm_name {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "vm_id",
            requested: req.vm_id.as_str().to_owned(),
            resolved: intent.vm_name.clone(),
        });
    }
    if let Some(execution_ref) = &req.execution_ref {
        let expected = d2b_contracts_resource::v3::ResourceRef::parse(&intent.execution_ref)
            .map_err(|_| BrokerError::SpawnRunnerIntentMismatch {
                field: "execution_ref",
                requested: execution_ref.to_canonical_string(),
                resolved: "invalid-bundle-reference".to_owned(),
            })?;
        if execution_ref != &expected {
            return Err(BrokerError::SpawnRunnerIntentMismatch {
                field: "execution_ref",
                requested: execution_ref.to_canonical_string(),
                resolved: expected.to_canonical_string(),
            });
        }
    }
    let expected_domain = match intent.execution_domain {
        d2b_core::processes::ProcessExecutionDomain::System => {
            d2b_contracts_resource::v3::execution_policy::ExecutionDomain::System
        }
        d2b_core::processes::ProcessExecutionDomain::User => {
            d2b_contracts_resource::v3::execution_policy::ExecutionDomain::User
        }
    };
    if req
        .execution_domain
        .is_some_and(|domain| domain != expected_domain)
    {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "execution_domain",
            requested: format!("{:?}", req.execution_domain),
            resolved: format!("{expected_domain:?}"),
        });
    }
    let expected_user = intent
        .user_ref
        .as_deref()
        .map(d2b_contracts_resource::v3::ResourceRef::parse)
        .transpose()
        .map_err(|_| BrokerError::SpawnRunnerIntentMismatch {
            field: "user_ref",
            requested: "invalid-bundle-reference".to_owned(),
            resolved: "invalid-bundle-reference".to_owned(),
        })?;
    if req.user_ref != expected_user {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "user_ref",
            requested: format!("{:?}", req.user_ref),
            resolved: format!("{expected_user:?}"),
        });
    }

    let expected_role_id = match intent.role {
        d2b_core::processes::ProcessRole::CloudHypervisorRunner => "ch-runner",
        _ => intent.role_id.as_str(),
    };
    if req.role_id.as_str() != expected_role_id {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "role_id",
            requested: req.role_id.as_str().to_owned(),
            resolved: expected_role_id.to_owned(),
        });
    }
    let Some(expected_role) = runner_role_for_process_role(&intent.role) else {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "role",
            requested: req.role.as_str().to_owned(),
            resolved: format!("{:?}", intent.role),
        });
    };
    if req.role != expected_role {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "role",
            requested: req.role.as_str().to_owned(),
            resolved: expected_role.as_str().to_owned(),
        });
    }
    let typed = typed_process_identity(
        req.resource_ref.as_ref(),
        req.resource_uid.as_ref(),
        req.zone_uid.as_ref(),
        req.generation,
        req.runtime_scope,
        &intent.role_id,
        req.guest_execution.as_ref(),
    )?;
    validate_typed_process_metadata(
        typed,
        req.owner_ref.as_ref(),
        req.provider_ref.as_ref(),
        req.provider_identity,
        req.template_identity,
        req.guest_execution.as_ref(),
        intent,
    )?;
    if typed {
        if !req.runtime_allocations.is_empty()
            || req.workload_identity.is_some()
            || req.network_tap_context.is_some()
        {
            return Err(BrokerError::SpawnRunnerIntentMismatch {
                field: "runtime_allocations",
                requested: "caller-supplied-runtime-state".to_owned(),
                resolved: "bundle-authoritative-runtime".to_owned(),
            });
        }
    }
    Ok(())
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn read_hex_u16(path: PathBuf, bus_id: &str) -> Result<u16, BrokerError> {
    let raw = fs::read_to_string(&path).map_err(|err| {
        BrokerError::LiveHandler(format!(
            "read USB identity for bus_id={bus_id} at {} failed: {err}",
            path.display()
        ))
    })?;
    u16::from_str_radix(raw.trim().trim_start_matches("0x"), 16).map_err(|err| {
        BrokerError::LiveHandler(format!(
            "parse USB identity for bus_id={bus_id} at {} failed: {err}",
            path.display()
        ))
    })
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn enforce_usbip_allowlist(
    intent: &d2b_core::bundle_resolver::ResolvedUsbipBindIntent,
    sysfs_root: &Path,
) -> Result<(u16, u16), BrokerError> {
    let inspection = crate::ops::usbip_host::enforce_usbip_physical_policy(intent, sysfs_root)
        .map_err(|err| map_usbip_host_inspection_error_for_intent(intent, err))?;
    Ok((inspection.vendor, inspection.product))
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn map_usbip_host_inspection_error_for_intent(
    intent: &d2b_core::bundle_resolver::ResolvedUsbipBindIntent,
    err: crate::ops::usbip_host::UsbipHostInspectionError,
) -> BrokerError {
    match err {
        crate::ops::usbip_host::UsbipHostInspectionError::AllowlistMismatch {
            bus_id,
            vendor,
            product,
        } => BrokerError::UsbipDeviceNotAllowed {
            busid: bus_id,
            vendor,
            product,
        },
        crate::ops::usbip_host::UsbipHostInspectionError::AllowlistMissing { .. } => {
            BrokerError::UsbipPolicyMismatch {
                busid: intent.bus_id.clone(),
                reason: "vendor/product allowlist is missing",
            }
        }
        crate::ops::usbip_host::UsbipHostInspectionError::TopologyIncomplete { bus_id, .. } => {
            BrokerError::UsbipPolicyMismatch {
                busid: bus_id,
                reason: "declared physical topology is incomplete",
            }
        }
        crate::ops::usbip_host::UsbipHostInspectionError::TopologyMismatch { bus_id, .. } => {
            BrokerError::UsbipPolicyMismatch {
                busid: bus_id,
                reason: "observed physical topology does not match the declaration",
            }
        }
        crate::ops::usbip_host::UsbipHostInspectionError::DeviceMissing { bus_id }
        | crate::ops::usbip_host::UsbipHostInspectionError::DeviceDepartedDuringInspection {
            bus_id,
            ..
        } => BrokerError::UsbipDeviceAbsent { busid: bus_id },
        other => BrokerError::LiveHandler(other.to_string()),
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn extend_usbip_backend_device_binds(
    resolver: &BundleResolver,
    vm_id: &str,
    role_id: &str,
    role: &d2b_contracts_broker::broker_wire::RunnerRole,
    mount_policy: &mut d2b_core::minijail_profile::MountPolicy,
) -> Result<(), BrokerError> {
    if !matches!(role, d2b_contracts_broker::broker_wire::RunnerRole::Usbip)
        || role_id != "backend"
        || !vm_id.starts_with("sys-")
        || !vm_id.ends_with("-usbipd")
    {
        return Ok(());
    }
    let env = vm_id
        .strip_prefix("sys-")
        .and_then(|value| value.strip_suffix("-usbipd"))
        .ok_or_else(|| BrokerError::LiveHandler(format!("invalid USBIP backend vm_id {vm_id}")))?;
    let mut binds = std::collections::BTreeSet::new();
    for id in resolver.usbip_bind_intent_ids() {
        let Some(intent) = resolver.find_usbip_bind_intent(id) else {
            continue;
        };
        if intent.env != env {
            continue;
        }
        let Some(owner) = crate::ops::usbip_lock::peek_owner(&intent.lock_path) else {
            continue;
        };
        if owner != intent.vm_name {
            continue;
        }
        let inspection =
            crate::ops::usbip_host::enforce_usbip_physical_policy(intent, usb_device_sysfs_root())
                .map_err(|err| map_usbip_host_inspection_error_for_intent(intent, err))?;
        let device_node = inspection.device_node;
        binds.insert(device_node.display().to_string());
    }
    for intent in active_dynamic_usbip_bind_intents(resolver) {
        if intent.env != env {
            continue;
        }
        let inspection =
            crate::ops::usbip_host::enforce_usbip_physical_policy(&intent, usb_device_sysfs_root())
                .map_err(|err| map_usbip_host_inspection_error_for_intent(&intent, err))?;
        let device_node = inspection.device_node;
        binds.insert(device_node.display().to_string());
    }
    if binds.is_empty() {
        return Err(BrokerError::LiveHandler(format!(
            "USBIP backend {vm_id}:{role_id} has no active locked busid device node to bind"
        )));
    }
    mount_policy.device_binds = binds.into_iter().collect();
    Ok(())
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn extend_audio_runner_pipewire_props(
    vm_id: &str,
    role_id: &str,
    role: &d2b_contracts_broker::broker_wire::RunnerRole,
    env: &mut Vec<String>,
) -> Result<(), BrokerError> {
    if !matches!(role, d2b_contracts_broker::broker_wire::RunnerRole::Audio) || role_id != "audio" {
        return Ok(());
    }
    let state_path = PathBuf::from(format!("/var/lib/d2b/vms/{vm_id}/state/audio-state.json"));
    let bytes = fs::read(&state_path).map_err(|err| {
        BrokerError::LiveHandler(format!(
            "audio runner {vm_id}:{role_id} could not read {}: {err}",
            state_path.display()
        ))
    })?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|err| {
        BrokerError::LiveHandler(format!(
            "audio runner {vm_id}:{role_id} could not parse {}: {err}",
            state_path.display()
        ))
    })?;
    let mic = audio_state_value(&value, "mic", vm_id, role_id)?;
    let speaker = audio_state_value(&value, "speaker", vm_id, role_id)?;
    let input_target = audio_input_target_node(env, vm_id, role_id)?;
    let target_prop = if mic == "on" {
        input_target
            .as_deref()
            .map(|target| format!(" target.object = \"{target}\""))
            .unwrap_or_default()
    } else {
        String::new()
    };
    env.retain(|entry| !entry.starts_with("PIPEWIRE_PROPS="));
    env.push(format!(
        "PIPEWIRE_PROPS={{ application.name = \"d2b-{vm_id}\" node.name = \"d2b-{vm_id}\" node.description = \"d2b {vm_id}\" d2b.vm = \"{vm_id}\" d2b.mic = \"{mic}\" d2b.speaker = \"{speaker}\"{target_prop} }}"
    ));
    Ok(())
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn audio_input_target_node(
    env: &[String],
    vm_id: &str,
    role_id: &str,
) -> Result<Option<String>, BrokerError> {
    let Some(raw) = env
        .iter()
        .find_map(|entry| entry.strip_prefix("D2B_AUDIO_INPUT_TARGET_NODE="))
    else {
        return Ok(None);
    };
    if raw.is_empty() || raw.contains('"') || raw.contains('\n') {
        return Err(BrokerError::LiveHandler(format!(
            "audio runner {vm_id}:{role_id} has invalid D2B_AUDIO_INPUT_TARGET_NODE"
        )));
    }
    Ok(Some(raw.to_owned()))
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn audio_state_value<'a>(
    value: &'a Value,
    key: &str,
    vm_id: &str,
    role_id: &str,
) -> Result<&'a str, BrokerError> {
    let state = value.get(key).and_then(Value::as_str).ok_or_else(|| {
        BrokerError::LiveHandler(format!(
            "audio runner {vm_id}:{role_id} state missing string key {key:?}"
        ))
    })?;
    match state {
        "on" | "off" => Ok(state),
        other => Err(BrokerError::LiveHandler(format!(
            "audio runner {vm_id}:{role_id} state key {key:?} has invalid value {other:?}"
        ))),
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn cleanup_cloud_hypervisor_stale_sockets(
    role: &d2b_contracts_broker::broker_wire::RunnerRole,
    argv: &[String],
) -> Result<(), BrokerError> {
    if !matches!(
        role,
        d2b_contracts_broker::broker_wire::RunnerRole::CloudHypervisor
    ) {
        return Ok(());
    }
    for path in cloud_hypervisor_socket_paths(argv) {
        cleanup_stale_unix_socket(&path)?;
    }
    Ok(())
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn bind_cloud_hypervisor_guest_uid(
    role: RunnerRole,
    owner_uid: Option<&d2b_contracts_resource::v3::ResourceUid>,
    argv: &[String],
) -> Result<Vec<String>, BrokerError> {
    if role != RunnerRole::CloudHypervisor {
        return Ok(argv.to_vec());
    }
    let owner_uid = owner_uid.ok_or_else(|| BrokerError::SpawnRunnerIntentMismatch {
        field: "owner_uid",
        requested: "missing".to_owned(),
        resolved: "required-for-cloud-hypervisor".to_owned(),
    })?;
    let mut bound = argv.to_vec();
    let cmdline_index = bound
        .iter()
        .position(|argument| argument == "--cmdline")
        .and_then(|index| bound.get(index + 1).map(|_| index + 1))
        .ok_or_else(|| BrokerError::SpawnRunnerIntentMismatch {
            field: "argv",
            requested: "cloud-hypervisor-without-cmdline".to_owned(),
            resolved: "cmdline-required".to_owned(),
        })?;
    if bound[cmdline_index]
        .split_ascii_whitespace()
        .any(|argument| argument.starts_with("d2b.guest_uid="))
    {
        return Err(BrokerError::SpawnRunnerIntentMismatch {
            field: "argv",
            requested: "prebound-guest-uid".to_owned(),
            resolved: "broker-owned".to_owned(),
        });
    }
    bound[cmdline_index].push_str(" d2b.guest_uid=");
    bound[cmdline_index].push_str(owner_uid.as_str());
    Ok(bound)
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn cleanup_video_stale_socket(
    role: &d2b_contracts_broker::broker_wire::RunnerRole,
    argv: &[String],
) -> Result<(), BrokerError> {
    if !matches!(role, d2b_contracts_broker::broker_wire::RunnerRole::Video) {
        return Ok(());
    }
    let path = video_socket_path(argv)?;
    if !path.starts_with("/run/d2b-video/") {
        return Err(BrokerError::LiveHandler(format!(
            "video socket preflight refusing non-d2b socket path {}",
            path.display()
        )));
    }
    cleanup_stale_unix_socket_without_probe(&path, "video socket preflight")
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn video_socket_path(argv: &[String]) -> Result<PathBuf, BrokerError> {
    let mut iter = argv.iter();
    while let Some(arg) = iter.next() {
        if arg == "--socket-path" {
            let Some(path) = iter.next() else {
                break;
            };
            return Ok(PathBuf::from(path));
        }
        if let Some(path) = arg.strip_prefix("--socket-path=") {
            return Ok(PathBuf::from(path));
        }
    }
    Err(BrokerError::LiveHandler(
        "video socket preflight could not find --socket-path in runner argv".to_owned(),
    ))
}

// The OtelHostBridge runner is `socat UNIX-LISTEN:<host-egress.sock>,...`.
// socat does not unlink a pre-existing socket path before binding, so a
// stale `host-egress.sock` left behind by a prior bridge instance (e.g.
// after the obs VM is restarted, draining and respawning the bridge)
// makes the fresh socat exit immediately with "address in use". The
// readiness probe only checks the socket *file* exists, so the stale
// socket masks the failure and host telemetry silently stops flowing.
// Mirror the cloud-hypervisor / video preflight: drop a provably-stale
// (non-listening) socket before spawn so obs-VM restarts self-heal.
#[cfg(not(feature = "layer1-bootstrap"))]
fn cleanup_otel_host_bridge_stale_socket(
    role: &d2b_contracts_broker::broker_wire::RunnerRole,
    argv: &[String],
) -> Result<(), BrokerError> {
    if !matches!(
        role,
        d2b_contracts_broker::broker_wire::RunnerRole::OtelHostBridge
    ) {
        return Ok(());
    }
    let path = otel_host_bridge_socket_path(argv)?;
    if !path.starts_with("/run/d2b/otel/") {
        return Err(BrokerError::LiveHandler(format!(
            "otel-host-bridge socket preflight refusing non-d2b socket path {}",
            path.display()
        )));
    }
    cleanup_stale_unix_socket_without_probe(&path, "otel-host-bridge socket preflight")
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn otel_host_bridge_socket_path(argv: &[String]) -> Result<PathBuf, BrokerError> {
    for arg in argv {
        if let Some(rest) = arg.strip_prefix("UNIX-LISTEN:") {
            let path = rest.split(',').next().unwrap_or(rest);
            if !path.is_empty() {
                return Ok(PathBuf::from(path));
            }
        }
    }
    Err(BrokerError::LiveHandler(
        "otel-host-bridge socket preflight could not find UNIX-LISTEN socket in runner argv"
            .to_owned(),
    ))
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn cloud_hypervisor_socket_paths(argv: &[String]) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let mut iter = argv.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--api-socket" => {
                if let Some(path) = iter.next() {
                    paths.push(PathBuf::from(path));
                }
            }
            "--vsock" => {
                if let Some(spec) = iter.next() {
                    for field in spec.split(',') {
                        if let Some(path) = field.strip_prefix("socket=") {
                            paths.push(PathBuf::from(path));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    paths
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn cleanup_stale_unix_socket(path: &Path) -> Result<(), BrokerError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(BrokerError::LiveHandler(format!(
                "cloud-hypervisor socket preflight could not stat {}: {err}",
                path.display()
            )));
        }
    };
    if !metadata.file_type().is_socket() {
        return Err(BrokerError::LiveHandler(format!(
            "cloud-hypervisor socket preflight refusing to remove non-socket path {}",
            path.display()
        )));
    }
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => Err(BrokerError::LiveHandler(format!(
            "cloud-hypervisor socket preflight found active listener at {}",
            path.display()
        ))),
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
            ) =>
        {
            fs::remove_file(path).map_err(|remove_err| {
                BrokerError::LiveHandler(format!(
                    "cloud-hypervisor socket preflight could not remove stale {}: {remove_err}",
                    path.display()
                ))
            })
        }
        Err(err) => Err(BrokerError::LiveHandler(format!(
            "cloud-hypervisor socket preflight could not prove {} stale: {err}",
            path.display()
        ))),
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn cleanup_stale_unix_socket_without_probe(path: &Path, context: &str) -> Result<(), BrokerError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(BrokerError::LiveHandler(format!(
                "{context} could not stat {}: {err}",
                path.display()
            )));
        }
    };
    if !metadata.file_type().is_socket() {
        return Err(BrokerError::LiveHandler(format!(
            "{context} refusing to remove non-socket path {}",
            path.display()
        )));
    }
    if unix_socket_listening_path(path) {
        return Err(BrokerError::LiveHandler(format!(
            "{context} found active listener at {}",
            path.display()
        )));
    }
    fs::remove_file(path).map_err(|remove_err| {
        BrokerError::LiveHandler(format!(
            "{context} could not remove stale {}: {remove_err}",
            path.display()
        ))
    })
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn unix_socket_listening_path(path: &Path) -> bool {
    const SO_ACCEPTCON: u64 = 0x0001_0000;
    let expected = path.to_string_lossy();
    let Ok(contents) = fs::read_to_string("/proc/net/unix") else {
        return false;
    };
    contents.lines().skip(1).any(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 8 {
            return false;
        }
        let flags = u64::from_str_radix(fields[3], 16).unwrap_or(0);
        let socket_type = fields[4];
        let socket_path = fields[7];
        socket_path == expected && socket_type == "0001" && (flags & SO_ACCEPTCON) != 0
    })
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn build_usbip_firewall_decision(
    resolver: &BundleResolver,
    host_nft_intent: &d2b_core::bundle_resolver::ResolvedNftIntent,
    current: &d2b_core::bundle_resolver::ResolvedUsbipFirewallIntent,
) -> Result<crate::ops::usbip_firewall::UsbipBindFirewallRuleDecision, BrokerError> {
    let mut batch = d2b_host::nftables::NftBatch::parse(host_nft_intent.script_body.as_str())
        .map_err(|err| BrokerError::NftScriptParseFailed(err.to_string()))?;
    let mut inserted = std::collections::BTreeSet::<String>::new();

    for id in resolver.usbip_bind_intent_ids() {
        let Some(bind_intent) = resolver.find_usbip_bind_intent(id) else {
            continue;
        };
        let Some(owner) = crate::ops::usbip_lock::peek_owner(&bind_intent.lock_path) else {
            continue;
        };
        if owner != bind_intent.vm_name {
            continue;
        }
        let firewall_id = d2b_core::bundle_resolver::intent_id_usbip_firewall(
            &bind_intent.env,
            &bind_intent.bus_id,
        );
        if !inserted.insert(firewall_id.clone()) || firewall_id == current.intent_id {
            continue;
        }
        let Some(active_firewall) = resolver.find_usbip_firewall_intent(&firewall_id) else {
            return Err(BrokerError::BundleIntentMissing {
                kind: "usbip-firewall",
                intent_id: firewall_id,
            });
        };
        batch
            .add_usbip_carveout_expr(
                d2b_host::nftables::ChainHook::Input,
                &d2b_host::nftables::BusId::new(active_firewall.bus_id.as_str()),
                active_firewall.nft_rule_body.as_str(),
            )
            .map_err(|err| BrokerError::LiveHandler(err.to_string()))?;
    }
    for bind_intent in active_dynamic_usbip_bind_intents(resolver) {
        let firewall_id = d2b_core::bundle_resolver::intent_id_usbip_firewall(
            &bind_intent.env,
            &bind_intent.bus_id,
        );
        if !inserted.insert(firewall_id.clone()) || firewall_id == current.intent_id {
            continue;
        }
        let Some(active_firewall) = find_usbip_firewall_intent_or_wildcard(resolver, &firewall_id)
        else {
            return Err(BrokerError::BundleIntentMissing {
                kind: "usbip-firewall",
                intent_id: firewall_id,
            });
        };
        batch
            .add_usbip_carveout_expr(
                d2b_host::nftables::ChainHook::Input,
                &d2b_host::nftables::BusId::new(active_firewall.bus_id.as_str()),
                active_firewall.nft_rule_body.as_str(),
            )
            .map_err(|err| BrokerError::LiveHandler(err.to_string()))?;
    }

    crate::ops::usbip_firewall::bind_firewall_rule(
        batch,
        &d2b_host::nftables::BusId::new(current.bus_id.as_str()),
        current.nft_rule_body.as_str(),
    )
    .map_err(|err| BrokerError::LiveHandler(err.to_string()))
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn find_usbip_firewall_intent_or_wildcard(
    resolver: &BundleResolver,
    intent_id: &str,
) -> Option<d2b_core::bundle_resolver::ResolvedUsbipFirewallIntent> {
    if let Some(intent) = resolver.find_usbip_firewall_intent(intent_id) {
        return Some(intent.clone());
    }
    let (env, bus_id) = parse_usbip_firewall_intent_id(intent_id)?;
    d2b_contracts::usbip::validate_bus_id(&bus_id).ok()?;
    let pending_id = d2b_core::bundle_resolver::intent_id_usbip_firewall(&env, "pending");
    let source = resolver.find_usbip_firewall_intent(&pending_id)?;
    Some(d2b_core::bundle_resolver::ResolvedUsbipFirewallIntent {
        intent_id: intent_id.to_owned(),
        bus_id,
        env,
        nft_rule_body: source.nft_rule_body.clone(),
        desired_hash: source.desired_hash.clone(),
    })
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn parse_usbip_firewall_intent_id(intent_id: &str) -> Option<(String, String)> {
    let rest = intent_id.strip_prefix("usbip-fw:env:")?;
    let (env, bus_id) = rest.split_once(":bus:")?;
    if env.is_empty() || bus_id.is_empty() {
        None
    } else {
        Some((env.to_owned(), bus_id.to_owned()))
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn active_dynamic_usbip_bind_intents(
    resolver: &BundleResolver,
) -> Vec<d2b_core::bundle_resolver::ResolvedUsbipBindIntent> {
    let Ok(entries) = std::fs::read_dir("/run/d2b/locks/usbip") else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let bus_id = entry.file_name().into_string().ok()?;
            d2b_contracts::usbip::validate_bus_id(&bus_id).ok()?;
            let owner = crate::ops::usbip_lock::peek_owner(&entry.path())?;
            find_wildcard_usbip_bind_intent_for(resolver, &owner, &bus_id)
        })
        .collect()
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn active_locked_usbip_bind_intents(
    resolver: &BundleResolver,
) -> Result<Vec<d2b_core::bundle_resolver::ResolvedUsbipBindIntent>, BrokerError> {
    let mut out = Vec::new();
    for id in resolver.usbip_bind_intent_ids() {
        let Some(intent) = resolver.find_usbip_bind_intent(id) else {
            continue;
        };
        let Some(owner) = crate::ops::usbip_lock::peek_owner(&intent.lock_path) else {
            continue;
        };
        if owner != intent.vm_name {
            return Err(BrokerError::LiveHandler(format!(
                "usbip proxy reconcile refused foreign lock for opaque intent {}",
                intent.intent_id
            )));
        }
        out.push(intent.clone());
    }
    out.extend(active_dynamic_usbip_bind_intents(resolver));
    Ok(out)
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn find_usbip_bind_intent_or_wildcard(
    resolver: &BundleResolver,
    intent_id: &str,
) -> Option<d2b_core::bundle_resolver::ResolvedUsbipBindIntent> {
    if let Some(intent) = resolver.find_usbip_bind_intent(intent_id) {
        return Some(intent.clone());
    }
    let (env, vm, bus_id) = parse_usbip_bind_intent_id(intent_id)?;
    d2b_contracts::usbip::validate_bus_id(&bus_id).ok()?;
    if static_usbip_busid_owner(resolver, &bus_id).is_some() {
        return None;
    }
    let pending_id = d2b_core::bundle_resolver::intent_id_usbip_bind(&env, &vm, "pending");
    let source = resolver.find_usbip_bind_intent(&pending_id)?;
    Some(dynamic_usbip_bind_intent(source, &bus_id))
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn parse_usbip_bind_intent_id(intent_id: &str) -> Option<(String, String, String)> {
    let rest = intent_id.strip_prefix("usbip-bind:env:")?;
    let (env, rest) = rest.split_once(":vm:")?;
    let (vm, bus_id) = rest.split_once(":bus:")?;
    if env.is_empty() || vm.is_empty() || bus_id.is_empty() {
        None
    } else {
        Some((env.to_owned(), vm.to_owned(), bus_id.to_owned()))
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn find_usbip_bind_intent_for(
    resolver: &BundleResolver,
    vm_name: &str,
    bus_id: &str,
) -> Option<d2b_core::bundle_resolver::ResolvedUsbipBindIntent> {
    let exact = resolver.usbip_bind_intent_ids().find_map(|id| {
        let intent = resolver.find_usbip_bind_intent(id)?;
        if intent.vm_name == vm_name && intent.bus_id == bus_id {
            Some(intent.clone())
        } else {
            None
        }
    });
    exact.or_else(|| {
        if static_usbip_busid_owner(resolver, bus_id).is_some() {
            None
        } else {
            find_wildcard_usbip_bind_intent_for(resolver, vm_name, bus_id)
        }
    })
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn find_usbip_bind_intent_by_busid(
    resolver: &BundleResolver,
    bus_id: &str,
) -> Option<d2b_core::bundle_resolver::ResolvedUsbipBindIntent> {
    let exact = resolver.usbip_bind_intent_ids().find_map(|id| {
        let intent = resolver.find_usbip_bind_intent(id)?;
        if intent.bus_id == bus_id {
            Some(intent.clone())
        } else {
            None
        }
    });
    exact.or_else(|| {
        let lock_path = usbip_lock_path_for_busid(bus_id);
        let owner = crate::ops::usbip_lock::peek_owner(&lock_path)?;
        find_wildcard_usbip_bind_intent_for(resolver, &owner, bus_id)
    })
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn find_wildcard_usbip_bind_intent_for(
    resolver: &BundleResolver,
    vm_name: &str,
    bus_id: &str,
) -> Option<d2b_core::bundle_resolver::ResolvedUsbipBindIntent> {
    d2b_contracts::usbip::validate_bus_id(bus_id).ok()?;
    if static_usbip_busid_owner(resolver, bus_id).is_some() {
        return None;
    }
    resolver.usbip_bind_intent_ids().find_map(|id| {
        let source = resolver.find_usbip_bind_intent(id)?;
        if source.vm_name == vm_name && source.bus_id == "pending" {
            Some(dynamic_usbip_bind_intent(source, bus_id))
        } else {
            None
        }
    })
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn static_usbip_busid_owner(resolver: &BundleResolver, bus_id: &str) -> Option<String> {
    resolver.usbip_bind_intent_ids().find_map(|id| {
        let intent = resolver.find_usbip_bind_intent(id)?;
        if intent.bus_id == bus_id && intent.bus_id != "pending" {
            Some(intent.vm_name.clone())
        } else {
            None
        }
    })
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn dynamic_usbip_bind_intent(
    source: &d2b_core::bundle_resolver::ResolvedUsbipBindIntent,
    bus_id: &str,
) -> d2b_core::bundle_resolver::ResolvedUsbipBindIntent {
    d2b_core::bundle_resolver::ResolvedUsbipBindIntent {
        intent_id: d2b_core::bundle_resolver::intent_id_usbip_bind(
            &source.env,
            &source.vm_name,
            bus_id,
        ),
        bus_id: bus_id.to_owned(),
        vm_name: source.vm_name.clone(),
        env: source.env.clone(),
        lock_path: usbip_lock_path_for_busid(bus_id),
        vendor_product_allowlist: source.vendor_product_allowlist.clone(),
        dynamic_bus_id: true,
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn usbip_lock_path_for_busid(bus_id: &str) -> PathBuf {
    PathBuf::from(format!("/run/d2b/locks/usbip/{bus_id}"))
}

// Route ValidateBundle through `d2b_core::manifest::validate_bundle`,
// which parses the configured bundle path as a v0.4 manifest. The
// bootstrap path keeps its own loose "file exists" check in
// `crate::bootstrap::manifest` because the legacy probe-* test harnesses
// pre-date the v0.4 schema.
#[cfg(not(feature = "layer1-bootstrap"))]
use d2b_core::manifest as manifest_api;

#[cfg(feature = "layer1-bootstrap")]
fn handle_validate_bundle(
    path: &Path,
    caller_uid: u32,
    caller_gid: u32,
    audit_log: &AuditLog,
) -> Result<BrokerResponse, BrokerError> {
    crate::bootstrap::manifest::validate_bundle(path)
        .map_err(|err| BrokerError::ValidateBundle(err.to_string()))?;
    audit_log
        .write_entry_with_caller_ids(
            "ValidateBundle",
            caller_uid,
            caller_gid,
            "callable-read-only",
            "bundle",
            "ok",
        )
        .map_err(|err| BrokerError::Protocol(err.to_string()))?;
    Ok(validate_bundle_ok_response())
}

#[cfg(feature = "layer1-bootstrap")]
fn handle_export_broker_audit(
    since: Option<&str>,
    filter: Option<&str>,
    caller_uid: u32,
    caller_gid: u32,
    caller_role: CallerRole,
    audit_log: &AuditLog,
) -> Result<BrokerResponse, BrokerError> {
    if !caller_role_is_admin(&caller_role) {
        audit_log
            .write_entry_with_caller_ids(
                "ExportBrokerAudit",
                caller_uid,
                caller_gid,
                "callable-read-only",
                "audit-log",
                "denied",
            )
            .map_err(|err| BrokerError::Protocol(err.to_string()))?;
        return Err(BrokerError::AuditRequiresAdmin);
    }
    let lines = audit_log
        .export_lines(since, filter)
        .map_err(|err| BrokerError::Protocol(err.to_string()))?;
    audit_log
        .write_entry_with_caller_ids(
            "ExportBrokerAudit",
            caller_uid,
            caller_gid,
            "callable-read-only",
            "audit-log",
            "ok",
        )
        .map_err(|err| BrokerError::Protocol(err.to_string()))?;
    Ok(export_broker_audit_ok_response(lines))
}

fn validate_socket_parent(path: &Path, test_mode: bool) -> Result<(), RunError> {
    let parent = path.parent().ok_or_else(|| {
        RunError::Usage(format!(
            "socket path must have a parent directory: {}",
            path.display()
        ))
    })?;
    let metadata = fs::symlink_metadata(parent)?;
    if metadata.file_type().is_symlink() {
        return Err(RunError::Usage(format!(
            "socket parent must not be a symlink: {}",
            parent.display()
        )));
    }
    if !metadata.is_dir() {
        return Err(RunError::Usage(format!(
            "socket parent must be a directory: {}",
            parent.display()
        )));
    }
    let expected_uid = if test_mode {
        nix::unistd::Uid::current().as_raw()
    } else {
        0
    };
    if metadata.uid() != expected_uid {
        return Err(RunError::Usage(format!(
            "socket parent owner mismatch for {}: expected uid {} but saw {}",
            parent.display(),
            expected_uid,
            metadata.uid()
        )));
    }
    Ok(())
}

fn prepare_socket_path(path: &Path) -> io::Result<()> {
    if fs::symlink_metadata(path).is_ok() {
        path_safe::remove_nofollow(path)?;
    }
    Ok(())
}

#[cfg(feature = "layer1-bootstrap")]
fn run_probe(
    socket_path: PathBuf,
    request: RequestEnvelope,
    expect_response: bool,
) -> Result<(), RunError> {
    let socket = connect_seqpacket(&socket_path)?;
    send_json_frame(socket.as_raw_fd(), &request)?;
    let response = recv_json_frame::<BrokerResponse>(socket.as_raw_fd())?;
    if let Some(response) = response {
        println!(
            "{}",
            serde_json::to_string(&response).map_err(|err| RunError::Protocol(err.to_string()))?
        );
        Ok(())
    } else if expect_response {
        Err(RunError::Protocol(
            "connection closed before response".to_owned(),
        ))
    } else {
        Err(RunError::Protocol(
            "connection closed before export response".to_owned(),
        ))
    }
}

#[cfg(feature = "layer1-bootstrap")]
fn parse_probe_flags(rest: Vec<String>) -> Result<(PathBuf, Option<u32>), RunError> {
    let mut socket_path = PathBuf::from(DEFAULT_SOCKET_PATH);
    let mut test_uid = None;
    let mut index = 0;
    while index < rest.len() {
        match rest[index].as_str() {
            "--socket-path" => {
                index += 1;
                socket_path = PathBuf::from(expect_arg(&rest, index, "--socket-path")?);
            }
            "--test-uid" => {
                index += 1;
                test_uid = Some(
                    expect_arg(&rest, index, "--test-uid")?
                        .parse()
                        .map_err(|_| RunError::Usage("invalid --test-uid".to_owned()))?,
                );
            }
            other => return Err(RunError::Usage(format!("unknown probe flag: {other}"))),
        }
        index += 1;
    }
    Ok((socket_path, test_uid))
}

#[cfg(feature = "layer1-bootstrap")]
fn parse_stub_flags(rest: &[String]) -> Result<(PathBuf, Option<u32>, String), RunError> {
    let mut socket_path = PathBuf::from(DEFAULT_SOCKET_PATH);
    let mut test_uid = None;
    let mut operation = None;
    let mut index = 0;
    while index < rest.len() {
        match rest[index].as_str() {
            "--socket-path" => {
                index += 1;
                socket_path = PathBuf::from(expect_arg(rest, index, "--socket-path")?);
            }
            "--test-uid" => {
                index += 1;
                test_uid = Some(
                    expect_arg(rest, index, "--test-uid")?
                        .parse()
                        .map_err(|_| RunError::Usage("invalid --test-uid".to_owned()))?,
                );
            }
            "--operation" => {
                index += 1;
                operation = Some(expect_arg(rest, index, "--operation")?.to_owned());
            }
            other => return Err(RunError::Usage(format!("unknown probe-stub flag: {other}"))),
        }
        index += 1;
    }
    Ok((
        socket_path,
        test_uid,
        operation.ok_or_else(|| RunError::Usage("missing --operation".to_owned()))?,
    ))
}

#[cfg(feature = "layer1-bootstrap")]
fn parse_export_flags(rest: &[String]) -> Result<(PathBuf, Option<u32>, CallerRole), RunError> {
    let mut socket_path = PathBuf::from(DEFAULT_SOCKET_PATH);
    let mut test_uid = None;
    let mut caller_role = None;
    let mut index = 0;
    while index < rest.len() {
        match rest[index].as_str() {
            "--socket-path" => {
                index += 1;
                socket_path = PathBuf::from(expect_arg(rest, index, "--socket-path")?);
            }
            "--test-uid" => {
                index += 1;
                test_uid = Some(
                    expect_arg(rest, index, "--test-uid")?
                        .parse()
                        .map_err(|_| RunError::Usage("invalid --test-uid".to_owned()))?,
                );
            }
            "--caller-role" => {
                index += 1;
                caller_role = crate::bootstrap::wire::caller_role_from_cli(expect_arg(
                    rest,
                    index,
                    "--caller-role",
                )?);
            }
            other => {
                return Err(RunError::Usage(format!(
                    "unknown probe-export-audit flag: {other}"
                )));
            }
        }
        index += 1;
    }
    Ok((
        socket_path,
        test_uid,
        caller_role.ok_or_else(|| RunError::Usage("missing --caller-role".to_owned()))?,
    ))
}

fn expect_arg<'a>(args: &'a [String], index: usize, flag: &str) -> Result<&'a str, RunError> {
    args.get(index)
        .map(String::as_str)
        .ok_or_else(|| RunError::Usage(format!("missing value for {flag}")))
}

fn caller_role_is_admin(caller_role: &CallerRole) -> bool {
    #[cfg(feature = "layer1-bootstrap")]
    {
        caller_role.is_admin_uid()
    }
    #[cfg(not(feature = "layer1-bootstrap"))]
    {
        matches!(
            caller_role,
            CallerRole::AdminUid { .. } | CallerRole::RootUid { .. }
        )
    }
}

impl BrokerError {
    #[allow(clippy::too_many_arguments)]
    fn audit(
        &self,
        audit_log: &AuditLog,
        caller_uid: u32,
        caller_gid: u32,
        caller_role: &CallerRole,
        audit_context: &DispatchAuditContext,
        #[cfg(not(feature = "layer1-bootstrap"))] resolver: Option<&BundleResolver>,
        operation: &str,
        opaque_target_id: &str,
    ) -> io::Result<()> {
        #[cfg(not(feature = "layer1-bootstrap"))]
        let bundle_metadata = audit_bundle_metadata(resolver);
        #[cfg(not(feature = "layer1-bootstrap"))]
        let authz_result = caller_role_authz_result(caller_role);
        #[cfg(feature = "layer1-bootstrap")]
        let bundle_metadata = AuditBundleMetadata {
            bundle_version: "unknown",
            bundle_hash: "",
        };
        #[cfg(feature = "layer1-bootstrap")]
        let authz_result = "launcher";
        #[cfg(feature = "layer1-bootstrap")]
        let _ = caller_role;
        #[cfg(not(feature = "layer1-bootstrap"))]
        let supplied_join = audit_context
            .audit_join
            .as_ref()
            .map(|join| (join.zone_id.as_str(), join.operation_identity.as_str()));
        #[cfg(feature = "layer1-bootstrap")]
        let supplied_join = None;
        let has_typed_terminal = matches!(
            self,
            Self::Unimplemented { .. }
                | Self::UnknownOperation { .. }
                | Self::UsbipDeviceNotAllowed { .. }
                | Self::UsbipPolicyMismatch { .. }
                | Self::CoexistenceRefused { .. }
                | Self::NftScriptParseFailed(_)
                | Self::CarveoutOrderingViolation(_)
                | Self::NftablesDriftDetected { .. }
                | Self::StoreSyncFailed { .. }
                | Self::SwtpmDirHardening { .. }
                | Self::RequestValidation { .. }
                | Self::ProfileOperationRefused { .. }
        );
        let has_request_payload = !audit_context
            .request_fields
            .as_object()
            .is_some_and(|object| object.is_empty());
        if !has_typed_terminal && has_request_payload {
            let (typed_public_operation_id, typed_scope_id) = supplied_join
                .map_or((operation, opaque_target_id), |(_, operation_identity)| {
                    (operation_identity, operation_identity)
                });
            audit_log.record_with_join(
                operation,
                typed_public_operation_id,
                caller_uid,
                caller_gid,
                audit_context.peer_pid,
                audit_context.peer_role.as_str(),
                authz_result,
                "",
                typed_scope_id,
                audit_context.verb.as_str(),
                audit_context.request_fields.clone(),
                "error",
                Some("broker-error"),
                None,
                bundle_metadata.bundle_version,
                bundle_metadata.bundle_hash,
                audit_context.duration_us(),
                Some(serde_json::json!({ "error_class": "broker-error" })),
                supplied_join,
            )?;
        }
        match self {
            Self::Unimplemented {
                operation: op,
                target_wave,
            } => {
                // Legacy short-record (preserved for the export-audit /
                // socket-acl gates).
                audit_log.write_entry_with_caller_ids(
                    operation,
                    caller_uid,
                    caller_gid,
                    "stubbed-unimplemented",
                    opaque_target_id,
                    "denied",
                )?;
                // Typed [`OpAuditRecord`] record for every decision.
                audit_log.record_with_join(
                    op,
                    opaque_target_id,
                    caller_uid,
                    caller_gid,
                    audit_context.peer_pid,
                    audit_context.peer_role.as_str(),
                    authz_result,
                    "",
                    opaque_target_id,
                    audit_context.verb.as_str(),
                    audit_context.request_fields.clone(),
                    "errored",
                    Some("w3-pending-typed-wire"),
                    None,
                    bundle_metadata.bundle_version,
                    bundle_metadata.bundle_hash,
                    audit_context.duration_us(),
                    Some(serde_json::json!({ "target_wave": target_wave })),
                    supplied_join,
                )?;
            }
            Self::UnknownOperation { operation: op } => {
                audit_log.write_entry_with_caller_ids(
                    operation,
                    caller_uid,
                    caller_gid,
                    "unknown-operation",
                    opaque_target_id,
                    "denied",
                )?;
                audit_log.record_with_join(
                    op,
                    opaque_target_id,
                    caller_uid,
                    caller_gid,
                    audit_context.peer_pid,
                    audit_context.peer_role.as_str(),
                    authz_result,
                    "",
                    opaque_target_id,
                    audit_context.verb.as_str(),
                    audit_context.request_fields.clone(),
                    "denied-unknown",
                    Some("unknown-operation"),
                    None,
                    bundle_metadata.bundle_version,
                    bundle_metadata.bundle_hash,
                    audit_context.duration_us(),
                    Some(serde_json::json!({
                        "reason": "broker does not yet implement USBIP live-device-routing ops",
                        "target_wave": "W6"
                    })),
                    supplied_join,
                )?;
            }
            Self::MinijailValidation { reason } => {
                audit_log.write_error_entry_with_caller_ids(
                    operation,
                    caller_uid,
                    caller_gid,
                    "minijail-validation-failed",
                    opaque_target_id,
                    "Broker.MinijailValidation",
                    reason,
                )?;
            }
            Self::NoPidfd { runner_id } => {
                audit_log.write_error_entry_with_caller_ids(
                    operation,
                    caller_uid,
                    caller_gid,
                    "runner-pidfd-missing",
                    runner_id,
                    "Broker.NoPidfd",
                    &format!("no pidfd registered for runner `{runner_id}`"),
                )?;
            }
            Self::ValidateBundle(message) => {
                audit_log.write_error_entry_with_caller_ids(
                    operation,
                    caller_uid,
                    caller_gid,
                    "bundle-validation-failed",
                    opaque_target_id,
                    "Broker.ValidateBundleFailed",
                    message,
                )?;
            }
            Self::BundleResolverUnavailable => {
                audit_log.write_error_entry_with_caller_ids(
                    operation,
                    caller_uid,
                    caller_gid,
                    "bundle-resolver-unavailable",
                    opaque_target_id,
                    "Broker.BundleResolverUnavailable",
                    "Broker started without a loadable bundle at ServerConfig.bundle_path. Bundle-dependent real-wire ops cannot resolve their BundleOpId refs.",
                )?;
            }
            Self::BundleTampered { path, reason } => {
                audit_log.write_error_entry_with_caller_ids(
                    operation,
                    caller_uid,
                    caller_gid,
                    "bundle-tampered",
                    opaque_target_id,
                    "Broker.BundleTampered",
                    &format!("bundle artifact {path} failed tamper-resistance check: {reason}"),
                )?;
            }
            Self::BundleIntentMissing { kind, intent_id } => {
                audit_log.write_error_entry_with_caller_ids(
                    operation,
                    caller_uid,
                    caller_gid,
                    "bundle-intent-missing",
                    intent_id,
                    "Broker.BundleIntentMissing",
                    &format!("no {kind} intent in the trusted bundle for opaque id `{intent_id}`"),
                )?;
            }
            Self::StoreViewFilesystemMismatch { a, a_dev, b, b_dev } => {
                audit_log.write_error_entry_with_caller_ids(
                    operation,
                    caller_uid,
                    caller_gid,
                    "store-view-fs-mismatch",
                    opaque_target_id,
                    "Broker.StoreViewFilesystemMismatch",
                    &format!(
                        "paths on different filesystems: {a} (dev={a_dev}) vs {b} (dev={b_dev})"
                    ),
                )?;
            }
            Self::StoreViewMarkerMissing { generation_dir } => {
                audit_log.write_error_entry_with_caller_ids(
                    operation,
                    caller_uid,
                    caller_gid,
                    "store-view-marker-missing",
                    opaque_target_id,
                    "Broker.StoreViewMarkerMissing",
                    &format!("generation {generation_dir} lacks marker.json"),
                )?;
            }
            Self::UsbipDeviceNotAllowed {
                busid,
                vendor,
                product,
            } => {
                audit_log.write_entry_with_caller_ids(
                    operation,
                    caller_uid,
                    caller_gid,
                    "usbip-device-not-allowed",
                    busid,
                    "denied",
                )?;
                audit_log.record_with_join(
                    operation,
                    busid,
                    caller_uid,
                    caller_gid,
                    audit_context.peer_pid,
                    audit_context.peer_role.as_str(),
                    authz_result,
                    "",
                    busid,
                    audit_context.verb.as_str(),
                    audit_context.request_fields.clone(),
                    "denied-refused",
                    Some("usbip-device-not-allowed"),
                    None,
                    bundle_metadata.bundle_version,
                    bundle_metadata.bundle_hash,
                    audit_context.duration_us(),
                    Some(serde_json::json!({
                        "vendor": format!("{vendor:04x}"),
                        "product": format!("{product:04x}"),
                    })),
                    supplied_join,
                )?;
            }
            Self::UsbipPolicyMismatch { busid, reason } => {
                audit_log.write_entry_with_caller_ids(
                    operation,
                    caller_uid,
                    caller_gid,
                    "usbip-policy-mismatch",
                    busid,
                    "denied",
                )?;
                audit_log.record_with_join(
                    operation,
                    busid,
                    caller_uid,
                    caller_gid,
                    audit_context.peer_pid,
                    audit_context.peer_role.as_str(),
                    authz_result,
                    "",
                    busid,
                    audit_context.verb.as_str(),
                    audit_context.request_fields.clone(),
                    "denied-policy",
                    Some("usbip-policy-mismatch"),
                    None,
                    bundle_metadata.bundle_version,
                    bundle_metadata.bundle_hash,
                    audit_context.duration_us(),
                    Some(serde_json::json!({
                        "reason": reason,
                    })),
                    supplied_join,
                )?;
            }
            Self::UsbipLockConflict { busid, owner } => {
                audit_log.write_error_entry_with_caller_ids(
                    operation,
                    caller_uid,
                    caller_gid,
                    "usbip-lock-conflict",
                    busid,
                    "Broker.UsbipLockConflict",
                    &format!("UsbipBind refused: busid {busid} is already claimed by {owner}"),
                )?;
            }
            Self::UsbipDeviceAbsent { busid } => {
                audit_log.write_error_entry_with_caller_ids(
                    operation,
                    caller_uid,
                    caller_gid,
                    "usbip-device-absent",
                    busid,
                    "Broker.UsbipDeviceAbsent",
                    &format!("UsbipBind refused: USB device {busid} is not present in sysfs"),
                )?;
            }
            Self::LiveHandler(message) => {
                // Surface the operator-facing root cause (errno / path /
                // stderr) in the broker journal, not just the
                // `Broker.LiveHandlerFailed` wrapper kind. The same
                // detail is recorded in the audit log; an operator
                // reading `journalctl -u d2b-broker` should not
                // have to cross-reference the audit jsonl to learn why a
                // runner spawn failed.
                tracing::warn!(
                    operation = operation,
                    error_kind = "Broker.LiveHandlerFailed",
                    detail = %message,
                    "broker live-handler op failed"
                );
                audit_log.write_error_entry_with_caller_ids(
                    operation,
                    caller_uid,
                    caller_gid,
                    "live-handler-error",
                    opaque_target_id,
                    "Broker.LiveHandlerFailed",
                    message,
                )?;
            }
            Self::Protocol(message) => {
                audit_log.write_error_entry_with_caller_ids(
                    operation,
                    caller_uid,
                    caller_gid,
                    "protocol-error",
                    opaque_target_id,
                    "Broker.Protocol",
                    message,
                )?;
            }
            Self::ProfileOperationRefused { profile, operation } => {
                audit_log.write_entry_with_caller_ids(
                    operation,
                    caller_uid,
                    caller_gid,
                    "profile-operation-denied",
                    opaque_target_id,
                    "denied",
                )?;
                audit_log.record_with_join(
                    operation,
                    opaque_target_id,
                    caller_uid,
                    caller_gid,
                    audit_context.peer_pid,
                    audit_context.peer_role.as_str(),
                    authz_result,
                    "",
                    opaque_target_id,
                    audit_context.verb.as_str(),
                    audit_context.request_fields.clone(),
                    "denied-refused",
                    Some("profile-operation-denied"),
                    None,
                    bundle_metadata.bundle_version,
                    bundle_metadata.bundle_hash,
                    audit_context.duration_us(),
                    Some(serde_json::json!({ "profile": profile.as_str() })),
                    supplied_join,
                )?;
            }
            Self::CoexistenceRefused { manager, rationale } => {
                audit_log.write_entry_with_caller_ids(
                    operation,
                    caller_uid,
                    caller_gid,
                    "coexistence-refused",
                    opaque_target_id,
                    "denied",
                )?;
                audit_log.record_with_join(
                    operation,
                    opaque_target_id,
                    caller_uid,
                    caller_gid,
                    audit_context.peer_pid,
                    audit_context.peer_role.as_str(),
                    authz_result,
                    "",
                    opaque_target_id,
                    audit_context.verb.as_str(),
                    audit_context.request_fields.clone(),
                    "denied-refused",
                    Some("coexistence-refused"),
                    None,
                    bundle_metadata.bundle_version,
                    bundle_metadata.bundle_hash,
                    audit_context.duration_us(),
                    Some(serde_json::json!({
                        "manager": format!("{manager:?}"),
                        "rationale": rationale,
                    })),
                    supplied_join,
                )?;
            }
            Self::NftScriptParseFailed(detail) => {
                audit_log.write_entry_with_caller_ids(
                    operation,
                    caller_uid,
                    caller_gid,
                    "nft-script-parse-failed",
                    opaque_target_id,
                    "errored",
                )?;
                audit_log.record_with_join(
                    operation,
                    opaque_target_id,
                    caller_uid,
                    caller_gid,
                    audit_context.peer_pid,
                    audit_context.peer_role.as_str(),
                    authz_result,
                    "",
                    opaque_target_id,
                    audit_context.verb.as_str(),
                    audit_context.request_fields.clone(),
                    "errored",
                    Some("nft-script-parse-failed"),
                    None,
                    bundle_metadata.bundle_version,
                    bundle_metadata.bundle_hash,
                    audit_context.duration_us(),
                    Some(serde_json::json!({ "detail": detail })),
                    supplied_join,
                )?;
            }
            Self::CarveoutOrderingViolation(detail) => {
                audit_log.write_entry_with_caller_ids(
                    operation,
                    caller_uid,
                    caller_gid,
                    "nft-carveout-ordering-violation",
                    opaque_target_id,
                    "denied",
                )?;
                audit_log.record_with_join(
                    operation,
                    opaque_target_id,
                    caller_uid,
                    caller_gid,
                    audit_context.peer_pid,
                    audit_context.peer_role.as_str(),
                    authz_result,
                    "",
                    opaque_target_id,
                    audit_context.verb.as_str(),
                    audit_context.request_fields.clone(),
                    "denied-refused",
                    Some("nft-carveout-ordering-violation"),
                    None,
                    bundle_metadata.bundle_version,
                    bundle_metadata.bundle_hash,
                    audit_context.duration_us(),
                    Some(serde_json::json!({ "detail": detail })),
                    supplied_join,
                )?;
            }
            Self::NftablesDriftDetected { expected, observed } => {
                audit_log.write_entry_with_caller_ids(
                    operation,
                    caller_uid,
                    caller_gid,
                    "nftables-drift-detected",
                    opaque_target_id,
                    "denied",
                )?;
                audit_log.record_with_join(
                    operation,
                    opaque_target_id,
                    caller_uid,
                    caller_gid,
                    audit_context.peer_pid,
                    audit_context.peer_role.as_str(),
                    authz_result,
                    "",
                    opaque_target_id,
                    audit_context.verb.as_str(),
                    audit_context.request_fields.clone(),
                    "denied-refused",
                    Some("nftables-drift-detected"),
                    None,
                    bundle_metadata.bundle_version,
                    bundle_metadata.bundle_hash,
                    audit_context.duration_us(),
                    Some(serde_json::json!({
                        "expected": expected,
                        "observed": observed,
                    })),
                    supplied_join,
                )?;
            }
            Self::OtelHostBridgeIntentInvalid {
                intent_vm,
                expected_obs_vm,
            } => {
                audit_log.write_error_entry_with_caller_ids(
                    operation,
                    caller_uid,
                    caller_gid,
                    "otel-host-bridge-intent-invalid",
                    opaque_target_id,
                    "Broker.OtelHostBridgeIntentInvalid",
                    &format!(
                        "OtelHostBridge runner intent points at VM `{intent_vm}` but the trusted bundle declares the obs VM as `{expected_obs_vm}` (closed-set)"
                    ),
                )?;
            }
            Self::SpawnRunnerIntentMismatch {
                field,
                requested,
                resolved,
            } => {
                audit_log.write_error_entry_with_caller_ids(
                    operation,
                    caller_uid,
                    caller_gid,
                    "spawn-runner-intent-mismatch",
                    opaque_target_id,
                    "Broker.SpawnRunnerIntentMismatch",
                    &format!(
                        "SpawnRunner {field} mismatch: request `{requested}` does not match trusted bundle intent `{resolved}`"
                    ),
                )?;
            }
            // The StoreSync dispatch arm already wrote the signed terminal
            // `OperationFields::StoreSync` record (ADR 0027: exactly one
            // terminal record per attempt). Writing the generic error entry
            // here would emit a duplicate, so this is a deliberate no-op.
            Self::StoreSyncFailed { .. } => {}
            // The SpawnRunner dispatch arm already wrote the terminal
            // path-free `PrepareSwtpmDir` record for the fail-closed
            // hardening step; writing the generic error entry here would
            // duplicate it, so this is a deliberate no-op (mirrors
            // `StoreSyncFailed`).
            Self::SwtpmDirHardening { .. } => {}
            Self::RequestValidation {
                operation: op,
                reason,
            } => {
                audit_log.write_entry_with_caller_ids(
                    operation,
                    caller_uid,
                    caller_gid,
                    "request-validation-failed",
                    opaque_target_id,
                    "denied",
                )?;
                audit_log.record_with_join(
                    op,
                    opaque_target_id,
                    caller_uid,
                    caller_gid,
                    audit_context.peer_pid,
                    audit_context.peer_role.as_str(),
                    authz_result,
                    "",
                    opaque_target_id,
                    audit_context.verb.as_str(),
                    audit_context.request_fields.clone(),
                    "denied-refused",
                    Some("request-validation-failed"),
                    None,
                    bundle_metadata.bundle_version,
                    bundle_metadata.bundle_hash,
                    audit_context.duration_us(),
                    Some(serde_json::json!({ "reason": reason })),
                    supplied_join,
                )?;
            }
            Self::IpcRateLimited => {
                audit_log.write_entry_with_caller_ids(
                    operation,
                    caller_uid,
                    caller_gid,
                    "ipc-rate-limited",
                    opaque_target_id,
                    "denied",
                )?;
            }
            _ => {}
        }
        Ok(())
    }

    fn into_response(self) -> BrokerResponse {
        match self {
            Self::Unimplemented {
                operation,
                target_wave,
            } => unimplemented_response(operation, target_wave),
            Self::UnknownOperation { operation } => error_response(
                "unknown-operation",
                operation,
                Some("W6"),
                &format!("{operation} is USBIP live-device-routing and is not yet implemented."),
                "USBIP live-device-routing is not yet implemented; only `UsbipBindFirewallRule` skeleton support ships today.",
            ),
            Self::AuditRequiresAdmin => authz_audit_requires_admin_response(),
            Self::HostShutdownRestricted => error_response(
                "host-shutdown-restricted",
                "HostShutdown",
                None,
                "host shutdown capability permits only stop",
                "retry only the stop operation during host shutdown",
            ),
            Self::MinijailValidation { reason } => error_response(
                "Broker.MinijailValidation",
                "SpawnRunner",
                Some("W17"),
                &reason,
                "Fix the bundle's minijail profile invariants and retry SpawnRunner.",
            ),
            Self::NoPidfd { runner_id } => error_response(
                "Broker.NoPidfd",
                "SignalRunner",
                Some("W4"),
                &format!("no pidfd registered for runner `{runner_id}`"),
                "Open or spawn the runner first so the broker can retain a pidfd for signaling.",
            ),
            Self::ValidateBundle(message) => error_response(
                "Broker.ValidateBundleFailed",
                "ValidateBundle",
                None,
                &message,
                "Fix the bundle inputs and retry via d2b_core::manifest::validate_bundle.",
            ),
            Self::BundleResolverUnavailable => error_response(
                "Broker.BundleResolverUnavailable",
                "BundleResolver",
                Some("W12"),
                "broker operation failed; details are available only in the redacted audit channel",
                "Restore the trusted bundle at the broker-configured bundle path and retry; the broker reloads the bundle on the next request.",
            ),
            Self::BundleTampered { .. } => error_response(
                "bundle-tampered",
                "BundleResolver",
                None,
                "Trusted bundle failed integrity checks; privileged operations are refused.",
                "rebuild the bundle from a trusted source (nixos-rebuild switch) and verify ownership root:d2bd 0640; refuse to run mutating verbs until the bundle is restored",
            ),
            Self::BundleIntentMissing { kind, .. } => error_response(
                "Broker.BundleIntentMissing",
                "BundleResolver",
                Some("W12"),
                &format!("trusted bundle does not contain the requested {kind} intent"),
                "broker operation failed; details are available only in the redacted audit channel",
            ),
            Self::StoreViewFilesystemMismatch { a, a_dev, b, b_dev } => error_response(
                "Broker.StoreViewFilesystemMismatch",
                "PrepareStoreView",
                Some("W7"),
                &format!("paths on different filesystems: {a} (dev={a_dev}) vs {b} (dev={b_dev})"),
                "Keep /nix/store and the VM store-view root on the same filesystem, then retry.",
            ),
            Self::StoreViewMarkerMissing { generation_dir } => error_response(
                "Broker.StoreViewMarkerMissing",
                "PrepareStoreView",
                Some("W7"),
                &format!("generation {generation_dir} lacks marker.json"),
                "Rebuild the store-view generation through the trusted broker/native path, then retry.",
            ),
            Self::UsbipDeviceNotAllowed { .. } => error_response(
                "Broker.UsbipDeviceNotAllowed",
                "UsbipBind",
                Some("W6"),
                "UsbipBind refused because the selected device is outside the trusted bundle allowlist",
                "Allow the device's vendor:product in host.json or bind an approved USB device before retrying.",
            ),
            Self::UsbipPolicyMismatch { reason, .. } => error_response(
                "Broker.UsbipPolicyMismatch",
                "UsbipBind",
                None,
                &format!(
                    "UsbipBind refused before device exposure because the required USB policy check failed: {reason}"
                ),
                "Fix the USBIP declaration, physical port/topology, and vendor:product allowlist, rebuild the trusted bundle, then retry.",
            ),
            Self::UsbipLockConflict { busid, .. } => error_response(
                "Broker.UsbipLockConflict",
                "UsbipBind",
                None,
                &format!("UsbipBind refused: busid {busid} is already claimed by another VM"),
                "Stop the VM currently holding this busid or use `d2b usb detach` to release the claim, then retry.",
            ),
            Self::UsbipDeviceAbsent { busid } => error_response(
                "Broker.UsbipDeviceAbsent",
                "UsbipBind",
                None,
                &format!("UsbipBind refused: USB device {busid} is not present in sysfs"),
                "Confirm the physical device is connected and recognized by the host kernel, then retry.",
            ),
            Self::LiveHandler(message) => error_response(
                "Broker.LiveHandlerFailed",
                "LiveHandler",
                Some("W12"),
                &public_live_handler_message(&message),
                "Inspect the broker audit log for the failing live executor's underlying syscall.",
            ),
            Self::CoexistenceRefused { manager, rationale } => error_response(
                "Broker.CoexistenceRefused",
                "ApplyNftables",
                Some("W12"),
                &format!(
                    "ApplyNftables refused by host.json firewall coexistence policy for {manager:?}: {rationale}"
                ),
                "Adjust host.json firewallCoexistencePolicy or remove the conflicting managed firewall before retrying.",
            ),
            Self::NftScriptParseFailed(detail) => error_response(
                "Broker.NftScriptParseFailed",
                "ApplyNftables",
                Some("W12"),
                &format!(
                    "ApplyNftables refused because the resolver-emitted `inet d2b` script could not be parsed: {detail}"
                ),
                "Inspect the emitted nftables script and regenerate the trusted bundle before retrying.",
            ),
            Self::CarveoutOrderingViolation(detail) => error_response(
                "Broker.CarveoutOrderingViolation",
                "ApplyNftables",
                Some("W12"),
                &format!(
                    "ApplyNftables refused because a specific USBIP carve-out would be shadowed by a broader forward-chain rule: {detail}"
                ),
                "Reorder the emitted forward-chain rules so per-busid carve-outs sit before any broad allow/drop rules.",
            ),
            Self::NftablesDriftDetected { expected, observed } => error_response(
                "Broker.NftablesDriftDetected",
                "ApplyNftables",
                Some("W12"),
                &format!(
                    "ApplyNftables refused because the canonical `inet d2b` hash no longer matches host.json (expected={expected}, observed={observed})"
                ),
                "Investigate out-of-band nftables changes or refresh host.json with the last applied table hash before retrying.",
            ),
            Self::Protocol(message) => error_response(
                "Broker.Protocol",
                "Broker",
                None,
                &public_protocol_message(&message),
                "Inspect the private broker socket framing and retry.",
            ),
            Self::PeerCredentialRefused { operation } => error_response(
                "Broker.PeerCredentialRefused",
                operation,
                None,
                "broker peer credential check refused the private request",
                "Ensure only d2bd connects to d2b-broker.socket; restart d2bd after host credential changes.",
            ),
            Self::ProfileOperationRefused { profile, operation } => error_response(
                "Broker.ProfileOperationDenied",
                operation,
                None,
                &format!(
                    "broker profile `{}` does not admit this effect class",
                    profile.as_str()
                ),
                "Use the fixed effect adapter for the authority that owns this operation; the active broker profile cannot be changed by a request.",
            ),
            Self::OtelHostBridgeIntentInvalid {
                intent_vm,
                expected_obs_vm,
            } => error_response(
                "Broker.OtelHostBridgeIntentInvalid",
                "SpawnRunner",
                Some("P1"),
                &format!(
                    "OtelHostBridge runner intent points at VM `{intent_vm}` but the trusted bundle declares the obs VM as `{expected_obs_vm}` (closed-set)"
                ),
                "Rebuild the bundle so the OtelHostBridge runner intent's vm_name matches manifest._observability.vmName, then retry SpawnRunner.",
            ),
            Self::SpawnRunnerIntentMismatch {
                field,
                requested,
                resolved,
            } => {
                tracing::warn!(field, "SpawnRunner trusted intent mismatch");
                error_response(
                    "Broker.SpawnRunnerIntentMismatch",
                    "SpawnRunner",
                    Some("P1"),
                    &format!(
                        "SpawnRunner {field} mismatch: request `{requested}` does not match trusted bundle intent `{resolved}`"
                    ),
                    "Use the BundleOpId that matches the requested VM/role; daemon and broker versions may be out of sync.",
                )
            }
            Self::StoreSyncFailed {
                error_stage,
                message,
            } => error_response(
                "Broker.StoreSyncFailed",
                "StoreSync",
                None,
                &format!("StoreSync failed ({error_stage}): {message}"),
                "Inspect the signed StoreSync audit record (operation_fields.error_stage) for the failing phase; retry after resolving the underlying condition.",
            ),
            Self::SwtpmDirHardening { reason, .. } => error_response(
                "Broker.SwtpmDirHardening",
                "PrepareSwtpmDir",
                None,
                // PATH-FREE: only the closed-set reason slug reaches the
                // wire envelope.
                &format!("swtpm-dir hardening refused: {reason}"),
                "Inspect the signed PrepareSwtpmDir audit record (operation_fields.fail_reason) for the refusal cause; do NOT delete or recreate the per-VM swtpm state dir - that destroys the TPM2 NVRAM and forces IdP re-enrollment.",
            ),
            Self::RequestValidation { operation, reason } => error_response(
                "Broker.RequestValidation",
                operation,
                None,
                &format!("broker request validation failed: {reason}"),
                "Regenerate the daemon request from the trusted d2b bundle and retry.",
            ),
            Self::IpcRateLimited => error_response(
                "Broker.IpcRateLimited",
                "Broker",
                None,
                "broker IPC request rate limit exceeded",
                "Retry after the current rate-limit window; persistent failures indicate a daemon bug or local DoS.",
            ),
        }
    }
}

fn public_live_handler_message(message: &str) -> String {
    let lower = message.to_ascii_lowercase();
    if lower.contains("usbip") || lower.contains("/sys/bus/usb") {
        "privileged USB host operation failed; details are available only in the broker audit log"
            .to_owned()
    } else {
        "privileged host operation failed; details are available only in the broker audit log"
            .to_owned()
    }
}

fn public_protocol_message(message: &str) -> String {
    if message.contains("usb")
        || message.contains("USB")
        || message.contains('/')
        || message.contains("..")
    {
        "broker rejected a malformed private request".to_owned()
    } else {
        message.to_owned()
    }
}

fn profile_capabilities(profile: BrokerProfile) -> Vec<String> {
    match profile {
        BrokerProfile::Host => CAPABILITIES.iter().map(|item| (*item).to_owned()).collect(),
        BrokerProfile::Guest => profile
            .operations()
            .iter()
            .map(|item| (*item).to_owned())
            .collect(),
    }
}

fn hello_ok_response(profile: BrokerProfile) -> BrokerResponse {
    #[cfg(feature = "layer1-bootstrap")]
    {
        BrokerResponse::HelloOk {
            server_version: "0.0.0-w2-bootstrap".to_owned(),
            selected_version: "0.0.0-test".to_owned(),
            capabilities: profile_capabilities(profile),
        }
    }
    #[cfg(not(feature = "layer1-bootstrap"))]
    {
        BrokerResponse::Hello(d2b_contracts_broker::broker_wire::HelloResponse {
            server_version: "0.0.0-w2".to_owned(),
            selected_version: "0.0.0-w2".to_owned(),
            capabilities: profile_capabilities(profile),
        })
    }
}

fn validate_bundle_ok_response() -> BrokerResponse {
    #[cfg(feature = "layer1-bootstrap")]
    {
        BrokerResponse::ValidateBundleOk { valid: true }
    }
    #[cfg(not(feature = "layer1-bootstrap"))]
    {
        BrokerResponse::ValidateBundle(d2b_contracts_broker::broker_wire::ValidateBundleResponse {
            valid: true,
        })
    }
}

#[cfg(feature = "layer1-bootstrap")]
fn export_broker_audit_ok_response(lines: Vec<String>) -> BrokerResponse {
    BrokerResponse::ExportBrokerAuditOk { lines }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn export_broker_audit_ok_response(
    page: d2b_contracts_broker::broker_wire::ExportBrokerAuditResponse,
) -> BrokerResponse {
    BrokerResponse::ExportBrokerAudit(page)
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn ack_response(operation: &str) -> BrokerResponse {
    BrokerResponse::Ack(d2b_contracts_broker::broker_wire::AckResponse {
        accepted: true,
        operation: operation.to_owned(),
    })
}

fn unimplemented_response(operation: &str, target_wave: &str) -> BrokerResponse {
    error_response(
        "Broker.Unimplemented",
        operation,
        Some(target_wave),
        &format!("{operation} is intentionally stubbed and performs no host mutation."),
        &format!(
            "The privileged host implementation for {operation} is not yet available; retry once it lands."
        ),
    )
}

fn authz_audit_requires_admin_response() -> BrokerResponse {
    error_response(
        "authz-audit-requires-admin",
        "ExportBrokerAudit",
        None,
        "ExportBrokerAudit requires caller_role: AdminUid { uid } from d2bd.",
        "Have d2bd verify d2b.site.adminUsers before forwarding the audit export request.",
    )
}

fn error_response(
    kind: &str,
    operation: &str,
    target_wave: Option<&str>,
    message: &str,
    remediation: &str,
) -> BrokerResponse {
    let message = redact_public_detail(message);
    let remediation = redact_public_detail(remediation);
    #[cfg(feature = "layer1-bootstrap")]
    {
        BrokerResponse::Error {
            kind: kind.to_owned(),
            operation: operation.to_owned(),
            target_wave: target_wave.map(str::to_owned),
            message,
            remediation,
        }
    }
    #[cfg(not(feature = "layer1-bootstrap"))]
    {
        BrokerResponse::Error(d2b_contracts_broker::broker_wire::BrokerErrorResponse {
            kind: kind.to_owned(),
            operation: operation.to_owned(),
            target_wave: target_wave.map(str::to_owned),
            message,
            action: remediation,
        })
    }
}

fn redact_public_detail(detail: &str) -> String {
    if d2b_contracts_resource::v3::is_canonical_digest(detail) {
        return detail.to_owned();
    }
    if matches!(
        detail,
        "broker operation failed; details are available only in the redacted audit channel"
            | "Trusted bundle failed integrity checks; privileged operations are refused."
            | "privileged host operation failed; details are available only in the broker audit log"
            | "privileged USB host operation failed; details are available only in the broker audit log"
            | "Inspect the broker audit log for the failing live executor's underlying syscall."
            | "Restore the trusted bundle at the broker-configured bundle path and retry; the broker reloads the bundle on the next request."
            | "rebuild the bundle from a trusted source (nixos-rebuild switch) and verify ownership root:d2bd 0640; refuse to run mutating verbs until the bundle is restored"
    ) || detail.starts_with("trusted bundle does not contain the requested ")
    {
        return detail.to_owned();
    }
    d2b_contracts_resource::v3::canonical_digest("d2b:broker-public-error:v1", detail.as_bytes())
}

/// Start a background tokio runtime that listens for SIGCHLD and reaps
/// broker-spawned children via `waitid(P_PIDFD, WEXITED|WNOHANG)`.
///
/// The runtime runs in a dedicated OS thread so the main synchronous
/// accept loop is not blocked. The pidfd registry Mutex is safe to lock
/// from a tokio task (no signal-context access; no async Mutex needed).
///
/// Returns the `tokio::runtime::Runtime` handle - must stay alive for
/// the duration of the broker process (bind it to a local in `run_server`).
#[cfg(not(feature = "layer1-bootstrap"))]
fn start_sigchld_reaper(audit_log: Arc<AuditLog>) -> tokio::runtime::Runtime {
    // Publish the audit handle so the targeted post-spawn reap can
    // write the same forensic ChildReaped record the SIGCHLD loop does.
    let _ = broker_audit_log_handle().set(Arc::clone(&audit_log));

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_name("d2b-broker-reaper")
        .enable_all()
        .build()
        .expect("broker sigchld reaper tokio runtime");

    let sigchld = rt.block_on(async {
        use tokio::signal::unix::{SignalKind, signal};

        signal(SignalKind::child())
    });

    let mut sigchld = match sigchld {
        Ok(s) => s,
        Err(err) => {
            tracing::error!(
                error = %err,
                "broker: failed to install SIGCHLD handler; pidfd reap loop disabled"
            );
            return rt;
        }
    };

    rt.spawn(async move {
        loop {
            if sigchld.recv().await.is_none() {
                break;
            }
            reap_all_pidfds(audit_log.as_ref());
        }
    });

    rt
}

/// Iterate the pidfd registry and call
/// `waitid(P_PIDFD, WEXITED|WNOHANG)` on each entry. Entries whose child
/// has exited are removed from the registry, a `ChildReaped` notification
/// is pushed to the ring buffer, and a forensics record is appended to the
/// audit log.
#[cfg(not(feature = "layer1-bootstrap"))]
fn reap_all_pidfds(audit_log: &AuditLog) {
    use d2b_contracts_broker::broker_wire::{
        ChildExitKind, ChildExitStatus, ChildReapedNotification,
    };
    use nix::errno::Errno;
    use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid};

    let runner_ids: Vec<String> = match runner_pidfd_registry().lock() {
        Ok(reg) => reg.keys().cloned().collect(),
        Err(_) => {
            tracing::warn!("runner_pidfd_registry mutex poisoned in reap loop");
            return;
        }
    };

    for runner_id in runner_ids {
        let pidfd_dup = {
            let reg = match runner_pidfd_registry().lock() {
                Ok(r) => r,
                Err(_) => {
                    tracing::warn!("runner_pidfd_registry mutex poisoned in reap loop");
                    continue;
                }
            };
            let Some(pidfd) = reg.get(&runner_id) else {
                continue;
            };
            match dup(pidfd.as_raw_fd()).map(owned_fd_from_raw) {
                Ok(d) => d,
                Err(err) => {
                    tracing::warn!(runner_id = %runner_id, error = %err, "reap_all_pidfds: dup pidfd failed");
                    continue;
                }
            }
        };

        let wait_flags = WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG;
        match waitid(Id::PIDFd(pidfd_dup.as_fd()), wait_flags) {
            Ok(WaitStatus::Exited(pid, code)) => {
                let notif = ChildReapedNotification {
                    runner_id: runner_id.clone(),
                    pid: pid.as_raw(),
                    exit_status: ChildExitStatus {
                        kind: ChildExitKind::Exited,
                        code: Some(code),
                        signal: None,
                    },
                    reaped_at_ms: reaped_at_ms_now(),
                };
                remove_and_notify(&runner_id, notif, audit_log);
            }
            Ok(WaitStatus::Signaled(pid, sig, _)) => {
                let sig_num = sig as libc::c_int;
                let notif = ChildReapedNotification {
                    runner_id: runner_id.clone(),
                    pid: pid.as_raw(),
                    exit_status: ChildExitStatus {
                        kind: if sig_num == libc::SIGKILL {
                            ChildExitKind::Killed
                        } else {
                            ChildExitKind::Signaled
                        },
                        code: None,
                        signal: Some(sig_num),
                    },
                    reaped_at_ms: reaped_at_ms_now(),
                };
                remove_and_notify(&runner_id, notif, audit_log);
            }
            Ok(WaitStatus::StillAlive) | Ok(_) => {}
            Err(Errno::ECHILD) => {
                tracing::debug!(
                    runner_id = %runner_id,
                    "reap_all_pidfds: ECHILD (already reaped); removing stale registry entry"
                );
                let _ = remove_runner_registries(&runner_id);
            }
            Err(err) => {
                tracing::warn!(runner_id = %runner_id, error = %err, "reap_all_pidfds: waitid failed");
            }
        }
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn reaped_at_ms_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// Process-global handle to the broker's audit log, set when the
/// SIGCHLD reaper starts. Lets the targeted post-spawn reap
/// ([`targeted_reap_runner`]) write the same forensic `ChildReaped`
/// audit record the SIGCHLD loop writes, without threading an
/// `AuditLog` reference through the `DispatchBackend::spawn_runner`
/// trait boundary.
#[cfg(not(feature = "layer1-bootstrap"))]
fn broker_audit_log_handle() -> &'static OnceLock<Arc<AuditLog>> {
    static HANDLE: OnceLock<Arc<AuditLog>> = OnceLock::new();
    &HANDLE
}

/// Targeted, non-blocking reap of a SINGLE broker-spawned child,
/// keyed by its pidfd. Closes two zombie-leak windows around pidfd
/// registration that the SIGCHLD loop alone cannot guarantee to cover:
///
/// 1. the child exits in the window between `clone3` and the registry
///    insertion (its SIGCHLD may have already been coalesced/consumed
///    by a reap pass that ran before the entry existed); and
/// 2. registration itself fails and the broker is about to drop the
///    pidfd - without an explicit reap the child would zombie.
///
/// `waitid(P_PIDFD, WEXITED|WNOHANG)` is inherently generation-exact:
/// a pidfd can never refer to a reused PID, so this is the
/// strongest possible start-time/generation key (no separate
/// start_time_ticks comparison is required). On a real exit the child
/// is reaped, removed from the registry, a `ChildReaped` notification
/// is pushed for the daemon's rollback to confirm, and a forensic
/// audit record is appended. `ECHILD` means the SIGCHLD loop already
/// reaped it (also a clean terminal state); `StillAlive` leaves the
/// child for the SIGCHLD loop.
#[cfg(not(feature = "layer1-bootstrap"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetedReapOutcome {
    Reaped,
    AlreadyReaped,
    StillAlive,
    Failed,
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn targeted_reap_runner(
    runner_id: &str,
    pidfd: std::os::fd::BorrowedFd<'_>,
) -> TargetedReapOutcome {
    use d2b_contracts_broker::broker_wire::{
        ChildExitKind, ChildExitStatus, ChildReapedNotification,
    };
    use nix::errno::Errno;
    use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid};

    let wait_flags = WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG;
    match waitid(Id::PIDFd(pidfd), wait_flags) {
        Ok(WaitStatus::Exited(pid, code)) => {
            let notif = ChildReapedNotification {
                runner_id: runner_id.to_owned(),
                pid: pid.as_raw(),
                exit_status: ChildExitStatus {
                    kind: ChildExitKind::Exited,
                    code: Some(code),
                    signal: None,
                },
                reaped_at_ms: reaped_at_ms_now(),
            };
            if deliver_targeted_reap(runner_id, notif) {
                TargetedReapOutcome::Reaped
            } else {
                TargetedReapOutcome::Failed
            }
        }
        Ok(WaitStatus::Signaled(pid, sig, _)) => {
            let sig_num = sig as libc::c_int;
            let notif = ChildReapedNotification {
                runner_id: runner_id.to_owned(),
                pid: pid.as_raw(),
                exit_status: ChildExitStatus {
                    kind: if sig_num == libc::SIGKILL {
                        ChildExitKind::Killed
                    } else {
                        ChildExitKind::Signaled
                    },
                    code: None,
                    signal: Some(sig_num),
                },
                reaped_at_ms: reaped_at_ms_now(),
            };
            if deliver_targeted_reap(runner_id, notif) {
                TargetedReapOutcome::Reaped
            } else {
                TargetedReapOutcome::Failed
            }
        }
        Ok(WaitStatus::StillAlive) | Ok(_) => {
            // Still running: the SIGCHLD loop will reap it on exit.
            TargetedReapOutcome::StillAlive
        }
        Err(Errno::ECHILD) => {
            // Already reaped by the SIGCHLD loop; drop any stale entry.
            if remove_runner_registries(runner_id) {
                TargetedReapOutcome::AlreadyReaped
            } else {
                TargetedReapOutcome::Failed
            }
        }
        Err(err) => {
            tracing::warn!(runner_id = %runner_id, error = %err, "targeted_reap_runner: waitid failed");
            TargetedReapOutcome::Failed
        }
    }
}

/// Remove the registry entry, push the `ChildReaped` notification, and
/// write the forensic audit record when the process-global audit
/// handle is available. Mirrors [`remove_and_notify`] but resolves the
/// audit log from the global handle instead of a passed reference.
#[cfg(not(feature = "layer1-bootstrap"))]
fn deliver_targeted_reap(
    runner_id: &str,
    notif: d2b_contracts_broker::broker_wire::ChildReapedNotification,
) -> bool {
    match broker_audit_log_handle().get() {
        Some(audit_log) => remove_and_notify(runner_id, notif, audit_log.as_ref()),
        None => {
            // No audit handle (e.g. a unit test that didn't start the
            // reaper): still reap + notify so the child can't zombie.
            let removed = remove_runner_registries(runner_id);
            push_child_reap_notification(notif);
            tracing::info!(
                runner_id = %runner_id,
                "broker: child reaped via targeted post-spawn reap (no audit handle)"
            );
            removed
        }
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn remove_and_notify(
    runner_id: &str,
    notif: d2b_contracts_broker::broker_wire::ChildReapedNotification,
    audit_log: &AuditLog,
) -> bool {
    let removed = remove_runner_registries(runner_id);
    if !removed {
        tracing::warn!(
            runner_id = %runner_id,
            "reap: failed to clear runner registration"
        );
    }
    if let Err(err) = audit_log.write_child_reaped(&notif) {
        tracing::warn!(runner_id = %runner_id, error = %err, "reap: audit write_child_reaped failed");
    }
    tracing::info!(
        runner_id = %runner_id,
        pid = notif.pid,
        exit_status = ?notif.exit_status,
        "broker: child reaped via SIGCHLD handler",
    );
    push_child_reap_notification(notif);
    removed
}

/// Kill and synchronously reap a child when a post-spawn commit step fails.
/// The broker must not return an error while leaving a live process or stale
/// runner identity behind: the caller will retry the lifecycle operation and
/// the next attempt must be able to reserve the same runner id.
#[cfg(not(feature = "layer1-bootstrap"))]
fn cleanup_spawned_runner_after_failure(runner_id: &str, pidfd: std::os::fd::BorrowedFd<'_>) {
    remove_runner_metadata(runner_id);
    if let Err(err) = crate::sys::pidfd_sys::pidfd_send_signal(pidfd, libc::SIGKILL) {
        tracing::debug!(
            runner_id = %runner_id,
            error = %err,
            "spawn rollback: pidfd SIGKILL failed; child may already have exited"
        );
    }

    use nix::errno::Errno;
    use nix::sys::wait::{Id, WaitPidFlag, waitid};
    match waitid(Id::PIDFd(pidfd), WaitPidFlag::WEXITED) {
        Ok(_) | Err(Errno::ECHILD) => {}
        Err(err) => {
            tracing::warn!(
                runner_id = %runner_id,
                error = %err,
                "spawn rollback: blocking pidfd reap failed"
            );
        }
    }
    if let Ok(mut registry) = runner_pidfd_registry().lock() {
        registry.remove(runner_id);
    }
}

#[cfg(not(feature = "layer1-bootstrap"))]
fn cleanup_registered_runner_after_failure(runner_id: &str) {
    let pidfd = runner_pidfd_registry().lock().ok().and_then(|registry| {
        registry
            .get(runner_id)
            .and_then(|fd| dup(fd.as_raw_fd()).ok().map(owned_fd_from_raw))
    });
    if let Some(pidfd) = pidfd {
        cleanup_spawned_runner_after_failure(runner_id, pidfd.as_fd());
    } else {
        remove_runner_metadata(runner_id);
        remove_runner_registration(runner_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(feature = "layer1-bootstrap"))]
    use crate::ops::exec_reconcile::{FakeReconcileExecutor, ReconcileOp};
    #[cfg(not(feature = "layer1-bootstrap"))]
    use d2b_contracts::types::BundleOpId;
    #[cfg(not(feature = "layer1-bootstrap"))]
    use d2b_contracts_broker::broker_wire::{
        ActivationMode, ActivationPhase, GuestExecutionBinding, RunActivationRequest,
        RunActivationResponse,
    };
    #[cfg(not(feature = "layer1-bootstrap"))]
    use d2b_core::bundle_resolver::{ResolvedActivationIntent, ResolvedStoreViewIntent};
    use nix::unistd::Gid;
    #[cfg(not(feature = "layer1-bootstrap"))]
    use serde::Serialize;
    use serde_json::Value;
    #[cfg(not(feature = "layer1-bootstrap"))]
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    #[cfg(not(feature = "layer1-bootstrap"))]
    use std::os::fd::OwnedFd;
    #[cfg(not(feature = "layer1-bootstrap"))]
    use std::path::Path;
    use std::path::PathBuf;
    #[cfg(not(feature = "layer1-bootstrap"))]
    use std::sync::Arc;
    #[cfg(not(feature = "layer1-bootstrap"))]
    use std::sync::MutexGuard;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[cfg(not(feature = "layer1-bootstrap"))]
    static TEST_USB_SYSFS_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    #[test]
    fn public_error_details_fail_closed_for_paths_and_attacker_text() {
        assert_eq!(
            redact_public_detail("failed at /private/host/path"),
            d2b_contracts_resource::v3::canonical_digest(
                "d2b:broker-public-error:v1",
                b"failed at /private/host/path"
            )
        );
        assert_eq!(
            redact_public_detail("attacker error text"),
            d2b_contracts_resource::v3::canonical_digest(
                "d2b:broker-public-error:v1",
                b"attacker error text"
            )
        );
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn network_request_validation_rejects_legacy_and_mixed_scope_refs() {
        let zone_uid =
            d2b_contracts_resource::v3::ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000")
                .unwrap();
        let network_uid =
            d2b_contracts_resource::v3::ResourceUid::parse("223e4567-e89b-42d3-a456-426614174001")
                .unwrap();
        let network_generation = d2b_contracts_resource::v3::ResourceGeneration::new(4).unwrap();
        let attachment_generation = d2b_contracts_resource::v3::ResourceGeneration::new(7).unwrap();
        let bundle_generation = d2b_contracts_resource::v3::ResourceBundleGenerationId::parse(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        assert_eq!(
            validate_uid_network_authority(
                "network:123e4567-e89b-42d3-a456-426614174000:223e4567-e89b-42d3-a456-426614174001",
                &format!(
                    "network-route:123e4567-e89b-42d3-a456-426614174000:223e4567-e89b-42d3-a456-426614174001:{}:0",
                    d2b_core::bundle_resolver::network_name_token("work")
                ),
                &zone_uid,
                &network_uid,
                network_generation,
                attachment_generation,
                &bundle_generation,
            ),
            Ok(())
        );
        assert_eq!(
            validate_uid_network_authority(
                "network:123e4567-e89b-42d3-a456-426614174000:223e4567-e89b-42d3-a456-426614174001",
                "route:zone:work:network:net:0",
                &zone_uid,
                &network_uid,
                network_generation,
                attachment_generation,
                &bundle_generation,
            ),
            Err("network-admission-mismatch")
        );
        assert_eq!(
            validate_uid_network_authority(
                "network:123e4567-e89b-42d3-a456-426614174000:223e4567-e89b-42d3-a456-426614174001",
                "network-route:323e4567-e89b-42d3-a456-426614174002:423e4567-e89b-42d3-a456-426614174003:work:0",
                &zone_uid,
                &network_uid,
                network_generation,
                attachment_generation,
                &bundle_generation,
            ),
            Err("network-admission-mismatch")
        );
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn network_request_validation_rejects_swapped_projection_sysctl_and_hosts_refs() {
        use d2b_contracts::types::{BundleOpId, ScopeId};
        use d2b_contracts_broker::broker_wire::{
            ApplyNftablesProjectionRequest, ApplySysctlRequest, NftablesProjectionAction,
            UpdateHostsFileRequest,
        };
        use d2b_contracts_resource::v3::{
            ResourceBundleGenerationId, ResourceGeneration, ResourceUid,
        };

        let zone_uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let network_uid = ResourceUid::parse("223e4567-e89b-42d3-a456-426614174001").unwrap();
        let other_network_uid = ResourceUid::parse("323e4567-e89b-42d3-a456-426614174002").unwrap();
        let network_generation = ResourceGeneration::new(4).unwrap();
        let attachment_generation = ResourceGeneration::new(7).unwrap();
        let bundle_generation = ResourceBundleGenerationId::parse(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        let scope_id = ScopeId::new(format!(
            "network:{}:{}",
            zone_uid.as_str(),
            network_uid.as_str()
        ));
        let other_token = d2b_core::bundle_resolver::network_name_token("other");

        let projection = BrokerRequest::ApplyNftablesProjection(ApplyNftablesProjectionRequest {
            bundle_nft_projection_intent_ref: BundleOpId::new(format!(
                "network-firewall:{}:{}:{}",
                zone_uid.as_str(),
                other_network_uid.as_str(),
                other_token
            )),
            scope_id: scope_id.clone(),
            action: NftablesProjectionAction::Apply,
            zone_uid: zone_uid.clone(),
            network_uid: network_uid.clone(),
            network_generation,
            attachment_generation,
            expected_generation_id: bundle_generation.clone(),
            desired_hash: None,
            tracing_span_id: None,
        });
        assert!(matches!(
            validate_broker_request(&projection),
            Err(BrokerError::RequestValidation {
                operation: "ApplyNftablesProjection",
                reason: "network-admission-mismatch",
            })
        ));

        let sysctl = BrokerRequest::ApplySysctl(ApplySysctlRequest {
            bundle_sysctl_intent_ref: BundleOpId::new(format!(
                "network-sysctl:{}:{}:{}:lan:disable-ipv6",
                zone_uid.as_str(),
                other_network_uid.as_str(),
                other_token
            )),
            scope_id: scope_id.clone(),
            zone_uid: zone_uid.clone(),
            network_uid: network_uid.clone(),
            network_generation,
            attachment_generation,
            bundle_generation: bundle_generation.clone(),
            destroy: false,
            tracing_span_id: None,
        });
        assert!(matches!(
            validate_broker_request(&sysctl),
            Err(BrokerError::RequestValidation {
                operation: "ApplySysctl",
                reason: "network-admission-mismatch",
            })
        ));

        let hosts = BrokerRequest::UpdateHostsFile(UpdateHostsFileRequest {
            bundle_hosts_intent_ref: BundleOpId::new(format!(
                "network-hosts:{}:{}:{}",
                zone_uid.as_str(),
                other_network_uid.as_str(),
                other_token
            )),
            zone_uid: Some(zone_uid),
            network_uid: Some(network_uid),
            network_generation: Some(network_generation),
            attachment_generation: Some(attachment_generation),
            bundle_generation: Some(bundle_generation),
            destroy: false,
            tracing_span_id: None,
        });
        assert!(matches!(
            validate_broker_request(&hosts),
            Err(BrokerError::RequestValidation {
                operation: "UpdateHostsFile",
                reason: "network-admission-mismatch",
            })
        ));
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn tap_create_rejects_the_all_none_legacy_shape() {
        let request = serde_json::from_value::<BrokerRequest>(serde_json::json!({
            "kind": "CreatePersistentTap",
            "payload": {
                "roleId": "network-attachment",
                "vmId": "guest"
            }
        }));
        assert!(request.is_err());
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn lifecycle_lease_registry_tracks_completion_and_expiry() {
        use d2b_contracts_broker::broker_wire::{
            ConsumeLifecycleLeaseRequest, LifecycleLeaseOperation,
        };

        let uid = |value: &str| {
            d2b_contracts_resource::v3::ResourceUid::parse(value).expect("valid lifecycle UID")
        };
        let request = ConsumeLifecycleLeaseRequest {
            zone_uid: uid("11111111-1111-4111-8111-111111111111"),
            guest_uid: uid("22222222-2222-4222-8222-222222222222"),
            guest_generation: 1,
            provider_assignment_generation: 1,
            policy_revision: 1,
            operation_id: format!("runtime-lease-{}", std::process::id()),
            operation: LifecycleLeaseOperation::Start,
            stop_only: false,
        };
        let caller = CallerRole::AdminUid { uid: 1000 };
        consume_lifecycle_lease(&request, &caller).expect("consume lifecycle lease");
        let identity = lifecycle_lease_identity(&request);
        assert_eq!(
            lifecycle_leases()
                .lock()
                .expect("lifecycle lease lock")
                .get(&identity)
                .map(|record| record.state),
            Some(LifecycleLeaseState::Consumed)
        );
        complete_lifecycle_lease(&request).expect("complete lifecycle lease");
        assert_eq!(
            lifecycle_leases()
                .lock()
                .expect("lifecycle lease lock")
                .get(&identity)
                .map(|record| record.state),
            Some(LifecycleLeaseState::Completed)
        );

        let expired = ConsumeLifecycleLeaseRequest {
            operation_id: format!("runtime-expired-{}", std::process::id()),
            ..request
        };
        lifecycle_leases()
            .lock()
            .expect("lifecycle lease lock")
            .insert(
                lifecycle_lease_identity(&expired),
                LifecycleLeaseRecord {
                    state: LifecycleLeaseState::Completed,
                    expires_at_ms: 0,
                    completed_at_ms: Some(0),
                },
            );
        consume_lifecycle_lease(&expired, &caller).expect("expired lease can be reissued");
    }

    #[test]
    fn swtpm_hardening_failure_uses_the_typed_path_free_operation() {
        let error = BrokerError::SwtpmDirHardening {
            audit: crate::ops::audit_op::SwtpmDirAudit {
                vm_id: "work-vm".to_owned(),
                base_dir_hash: "fnv1a64:0000000000000000".to_owned(),
                result: crate::ops::audit_op::SwtpmDirResult::FailedClosed,
                mode: 0o700,
                owner_uid: 1000,
                owner_gid: 1000,
                marker_result: crate::ops::audit_op::SwtpmMarkerResult::FailedClosed,
                fail_reason: Some("swtpm-dir-marker-mismatch".to_owned()),
            },
            reason: "swtpm-dir-marker-mismatch",
        };

        #[cfg(feature = "layer1-bootstrap")]
        assert!(matches!(
            error.into_response(),
            BrokerResponse::Error {
                kind,
                operation,
                message,
                ..
            } if kind == "Broker.SwtpmDirHardening"
                && operation == "PrepareSwtpmDir"
                && !message.contains('/')
        ));
        #[cfg(not(feature = "layer1-bootstrap"))]
        assert!(matches!(
            error.into_response(),
            BrokerResponse::Error(response)
                if response.kind == "Broker.SwtpmDirHardening"
                    && response.operation == "PrepareSwtpmDir"
                    && !response.message.contains('/')
        ));
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    fn usb_sysfs_test_lock() -> MutexGuard<'static, ()> {
        TEST_USB_SYSFS_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn runner_role_mapping_covers_video_and_spawnable_roles() {
        use d2b_contracts_broker::broker_wire::RunnerRole;
        use d2b_core::processes::ProcessRole;

        let cases = [
            (
                ProcessRole::SwtpmPreStartFlush,
                Some(RunnerRole::SwtpmFlush),
            ),
            (ProcessRole::Swtpm, Some(RunnerRole::Swtpm)),
            (ProcessRole::Virtiofsd, Some(RunnerRole::Virtiofsd)),
            (ProcessRole::Video, Some(RunnerRole::Video)),
            (ProcessRole::Gpu, Some(RunnerRole::Gpu)),
            (ProcessRole::GpuRenderNode, Some(RunnerRole::Gpu)),
            (ProcessRole::Audio, Some(RunnerRole::Audio)),
            (
                ProcessRole::CloudHypervisorRunner,
                Some(RunnerRole::CloudHypervisor),
            ),
            (ProcessRole::QemuMediaRunner, Some(RunnerRole::QemuMedia)),
            (ProcessRole::VsockRelay, Some(RunnerRole::VsockRelay)),
            (ProcessRole::Usbip, Some(RunnerRole::Usbip)),
            (ProcessRole::HostReconcile, None),
            (ProcessRole::StoreVirtiofsPreflight, None),
            (ProcessRole::ComponentSessionHealth, None),
        ];

        for (role, expected) in cases {
            assert_eq!(runner_role_for_process_role(&role), expected);
        }
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    fn guest_execution_binding(session_generation: u64) -> GuestExecutionBinding {
        GuestExecutionBinding {
            target_uid: d2b_contracts_resource::v3::ResourceUid::parse(
                "123e4567-e89b-42d3-a456-426614174000",
            )
            .expect("Guest UID"),
            boot_identity_digest: [7; 32],
            session_generation,
            assignment_epoch: 3,
            provider_generation: 4,
            controller_generation: 5,
        }
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    fn guest_runner_registration(binding: GuestExecutionBinding) -> RunnerRegistration {
        RunnerRegistration {
            vm_id: "guest-vm".to_owned(),
            role_id: "guest-process".to_owned(),
            resource_ref: None,
            resource_uid: None,
            zone_uid: None,
            owner_ref: None,
            provider_ref: None,
            provider_identity: None,
            template_identity: None,
            generation: None,
            runtime_scope: None,
            role: d2b_contracts_broker::broker_wire::RunnerRole::CloudHypervisor,
            bundle_runner_intent_ref: "runner:guest-vm:guest-process".to_owned(),
            pid: 1,
            start_time_ticks: 1,
            binary_path: PathBuf::from("/bin/true"),
            cgroup_subtree: "d2b.slice/guest-vm/guest-process".to_owned(),
            guest_execution: Some(binding),
        }
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn guest_runner_registration_rebinds_to_a_newer_session() {
        let mut registration = guest_runner_registration(guest_execution_binding(1));
        let next = guest_execution_binding(2);

        assert!(
            rebind_guest_execution_registration(&mut registration, Some(&next))
                .expect("newer session generation rebinds")
        );
        assert_eq!(registration.guest_execution, Some(next.clone()));
        assert!(
            !rebind_guest_execution_registration(&mut registration, Some(&next))
                .expect("same binding remains an exact match")
        );
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn guest_runner_registration_rejects_stale_or_changed_bindings() {
        for generation in [1, 0] {
            let mut registration = guest_runner_registration(guest_execution_binding(2));
            let stale = guest_execution_binding(generation);
            assert!(
                rebind_guest_execution_registration(&mut registration, Some(&stale)).is_err(),
                "session generation {generation} must not replace generation 2"
            );
        }

        let mut registration = guest_runner_registration(guest_execution_binding(2));
        for changed in [
            {
                let mut binding = guest_execution_binding(3);
                binding.target_uid = d2b_contracts_resource::v3::ResourceUid::parse(
                    "223e4567-e89b-42d3-a456-426614174000",
                )
                .expect("Guest UID");
                binding
            },
            {
                let mut binding = guest_execution_binding(3);
                binding.boot_identity_digest = [8; 32];
                binding
            },
            {
                let mut binding = guest_execution_binding(3);
                binding.assignment_epoch = 4;
                binding
            },
            {
                let mut binding = guest_execution_binding(3);
                binding.provider_generation = 5;
                binding
            },
            {
                let mut binding = guest_execution_binding(3);
                binding.controller_generation = 6;
                binding
            },
        ] {
            assert!(
                rebind_guest_execution_registration(&mut registration, Some(&changed)).is_err(),
                "non-session binding changes must not be accepted as a reconnect"
            );
            assert_eq!(
                registration.guest_execution,
                Some(guest_execution_binding(2))
            );
        }
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn qemu_media_enroll_request_fields_redact_raw_busid() {
        let request = BrokerRequest::QemuMediaEnroll(
            d2b_contracts_broker::broker_wire::QemuMediaEnrollRequest {
                vm_id: d2b_contracts::types::VmId::new("media"),
                media_ref: d2b_contracts::types::MediaRef::new("installer-usb"),
                bus_id: "1-2.3".to_owned(),
                tracing_span_id: Some(d2b_contracts::types::TracingSpanId::new(
                    "usb-start-0000000000000001",
                )),
            },
        );

        let fields = request_fields_value(&request).expect("redacted fields");
        assert_eq!(fields["vmId"], "media");
        assert_eq!(fields["mediaRef"], "installer-usb");
        assert_eq!(fields["busIdProvided"], true);
        let rendered = fields.to_string();
        assert!(!rendered.contains("1-2.3"));
        assert!(!rendered.contains("/dev/"));
        assert!(!rendered.contains("usb-Vendor_SecretSerial"));
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn qemu_media_hotplug_request_fields_redact_runtime_busid() {
        let request = BrokerRequest::QemuMediaAttach(
            d2b_contracts_broker::broker_wire::QemuMediaHotplugRequest {
                vm_id: d2b_contracts::types::VmId::new("media"),
                bus_id: "1-2.3".to_owned(),
                tracing_span_id: None,
            },
        );

        let fields = request_fields_value(&request).expect("redacted fields");
        assert_eq!(fields["vmId"], "media");
        assert_eq!(fields["busIdProvided"], true);
        let rendered = fields.to_string();
        assert!(!rendered.contains("1-2.3"));
        assert!(!rendered.contains("/dev/"));
        assert!(!rendered.contains("usb-Vendor_SecretSerial"));
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn usbip_request_fields_project_trace_presence_without_trace_value() {
        let trace = d2b_contracts::types::TracingSpanId::new("usb-start-0000000000000001");
        let requests = [
            BrokerRequest::UsbipBind(d2b_contracts_broker::broker_wire::UsbipBindRequest {
                bundle_usbip_bind_intent_ref: d2b_contracts::types::BundleOpId::new(
                    "usbip-bind:env:work:vm:corp-vm:bus:1-2.3",
                ),
                tracing_span_id: Some(trace.clone()),
            }),
            BrokerRequest::UsbipUnbind(d2b_contracts_broker::broker_wire::UsbipUnbindRequest {
                bundle_usbip_bind_intent_ref: d2b_contracts::types::BundleOpId::new(
                    "usbip-bind:env:work:vm:corp-vm:bus:1-2.3",
                ),
                preserve_durable_claim: true,
                tracing_span_id: Some(trace.clone()),
            }),
            BrokerRequest::UsbipBindFirewallRule(
                d2b_contracts_broker::broker_wire::UsbipBindFirewallRuleRequest {
                    bundle_usbip_firewall_intent_ref: d2b_contracts::types::BundleOpId::new(
                        "usbip-fw:env:work:bus:1-2.3",
                    ),
                    tracing_span_id: Some(trace.clone()),
                },
            ),
            BrokerRequest::UsbipProxyReconcile(
                d2b_contracts_broker::broker_wire::UsbipProxyReconcileRequest {
                    scope_id: d2b_contracts::types::ScopeId::new("vm:corp-vm"),
                    tracing_span_id: Some(trace.clone()),
                },
            ),
        ];

        for request in requests {
            let fields = request_fields_value(&request).expect("bounded USBIP fields");
            assert_eq!(fields["tracingSpanIdPresent"], true);
            assert!(
                !fields.to_string().contains(trace.as_str()),
                "request_fields must carry only trace presence"
            );
        }
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn qemu_media_boot_request_fields_are_vm_only() {
        let request =
            BrokerRequest::QemuMediaBoot(d2b_contracts_broker::broker_wire::QemuMediaBootRequest {
                vm_id: d2b_contracts::types::VmId::new("media"),
                tracing_span_id: None,
            });

        let fields = request_fields_value(&request).expect("redacted fields");
        assert_eq!(fields["vmId"], "media");
        let rendered = fields.to_string();
        assert!(!rendered.contains("bus"));
        assert!(!rendered.contains("/dev/"));
        assert!(!rendered.contains("usb-Vendor_SecretSerial"));
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn qemu_media_lifecycle_request_fields_are_bounded() {
        let request = BrokerRequest::QemuMediaQueryStatus(
            d2b_contracts_broker::broker_wire::QemuMediaQueryStatusRequest {
                vm_id: d2b_contracts::types::VmId::new("media"),
                shutdown_context: true,
                tracing_span_id: None,
            },
        );

        let fields = request_fields_value(&request).expect("bounded fields");
        assert_eq!(fields["vmId"], "media");
        assert_eq!(fields["shutdownContext"], true);
        let rendered = fields.to_string();
        assert!(!rendered.contains("return"));
        assert!(!rendered.contains("status\":\""));
        assert!(!rendered.contains("/dev/"));
    }

    struct AuditCase {
        error: BrokerError,
        operation: &'static str,
        target_id: String,
        decision: &'static str,
        error_kind: &'static str,
        error_message: String,
    }

    fn test_audit_dir(test_name: &str) -> PathBuf {
        let root = crate::test_scratch_root().join("runtime-audit-tests");
        crate::sys::path_safe::ensure_dir(&root, 0o750, None, None)
            .expect("create audit test root");
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        root.join(format!("{test_name}-{}-{unique}", std::process::id()))
    }

    #[test]
    fn parse_command_rejects_removed_realm_metadata_flags() {
        for flag in ["--realm-controllers-path", "--realm-identity-path"] {
            let error = parse_command([
                "host".to_owned(),
                flag.to_owned(),
                "/etc/d2b/retired-realm-metadata.json".to_owned(),
                "--test-mode".to_owned(),
            ])
            .expect_err("retired realm metadata flags must be rejected");

            assert!(
                matches!(
                    error,
                    RunError::Usage(ref message) if message == &format!("unknown host flag: {flag}")
                ),
                "unexpected parser error for {flag}: {error:?}"
            );
        }
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    fn write_json_file<T: Serialize>(path: &Path, value: &T) {
        use std::os::unix::fs::PermissionsExt;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent directories for test json");
        }
        let mut body = serde_json::to_vec_pretty(value).expect("serialize test json");
        body.push(b'\n');
        fs::write(path, body).expect("write test json");
        // Bundle artifacts must be mode 0640 per BundleVerifyPolicy.
        let mut perms = fs::metadata(path).expect("stat test json").permissions();
        perms.set_mode(0o640);
        fs::set_permissions(path, perms).expect("chmod test json to 0640");
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    struct TestBundle {
        bundle_path: PathBuf,
        manifest_path: PathBuf,
        host_path: PathBuf,
        processes_path: PathBuf,
        resolver: Arc<BundleResolver>,
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    fn build_test_bundle(root: &Path) -> TestBundle {
        use d2b_contracts_resource::v3::IfName;
        use d2b_core::bundle::{Bundle, BundleClosureRef, BundleGeneration};
        use d2b_core::closures::{ClosureGeneration, ClosureMetadata};
        use d2b_core::host::{
            BridgePortFlags, ChNetHandoffMode, CloudHypervisorCapability, FdOwnershipEntry,
            HostChConfig, HostJson, HostsFileOwnership, IfNameMapping, Ipv6SysctlEntry,
            KernelModulesEntry, LanPolicy, NetEnv, NetworkManagerUnmanaged, NftChain,
            NftablesModel, OwnershipRule, SitePolicy, TapRole, UsbipBusidLock, UsbipLockOwner,
            UsbipLockScope, VendorProductPair,
        };
        use d2b_core::manifest_v04::{
            ManifestMeta, ManifestV04, ObservabilityMeta, VmEntry, VmLanPolicy, VmObservability,
        };
        use d2b_core::minijail_profile::CgroupPlacement;
        use d2b_core::processes::{
            NodeId, ProcessNode, ProcessRole, ProcessesJson, VmProcessDag, VmProcessInvariants,
        };
        use d2b_core::runtime::RuntimeMetadata;
        use d2b_core::test_support::RoleProfileBuilder;

        let bundle_dir = root.join("bundle");
        let bundle_path = bundle_dir.join("bundle.json");
        let manifest_path = bundle_dir.join("vms.json");
        let host_path = bundle_dir.join("host.json");
        let processes_path = bundle_dir.join("processes.json");
        let closure_path = bundle_dir.join("closures/corp-vm.json");

        let host = HostJson {
            schema_version: "v2".to_owned(),
            security_key_selectors: Vec::new(),
            site: SitePolicy {
                allow_unsafe_east_west: false,
            },
            environments: vec![NetEnv {
                env: "work".to_owned(),
                bridge: IfName::new("nlworkbr0").expect("bridge ifname"),
                host_uplink_ip: Some("192.0.2.1".to_owned()),
                net_uplink_ip: Some("192.0.2.2".to_owned()),
                mtu: 1500,
                mss_clamp: Some(1460),
                lan: LanPolicy {
                    allow_east_west: false,
                    effective_east_west: false,
                },
                net_vm_forward_blocklist: vec!["0.0.0.0/0".to_owned()],
                external_network: None,
                bridge_port_flags: vec![
                    BridgePortFlags {
                        role: TapRole::WorkloadLan,
                        isolated: true,
                        neigh_suppress: true,
                        learning: None,
                        unicast_flood: None,
                        rule: "isolated workload bridge port".to_owned(),
                    },
                    BridgePortFlags {
                        role: TapRole::Uplink,
                        isolated: true,
                        neigh_suppress: true,
                        learning: Some(false),
                        unicast_flood: Some(false),
                        rule: "uplink point-to-point anti-spoofing".to_owned(),
                    },
                ],
                ipv6_sysctls: vec![Ipv6SysctlEntry {
                    if_name: IfName::new("nlworktap0").expect("sysctl ifname"),
                    disable_ipv6: 1,
                    accept_ra: 0,
                    autoconf: 0,
                    addr_gen_mode: 1,
                    arp_ignore: 1,
                }],
                usbip_busid_locks: vec![UsbipBusidLock {
                    vm: "corp-vm".to_owned(),
                    lock_owner: UsbipLockOwner::Daemon,
                    scope: UsbipLockScope::PerBusid,
                    bus_ids: vec!["1-2.3".to_owned()],
                    vendor_product_allowlist: vec![VendorProductPair {
                        vendor: 0x1050,
                        product: 0x0407,
                    }],
                }],
                usbip_backend_port: Some(3241),
            }],
            nftables: NftablesModel {
                family: "inet".to_owned(),
                table: "d2b".to_owned(),
                chains: vec![NftChain {
                    name: "input".to_owned(),
                    hook: Some("input".to_owned()),
                    priority: Some(0),
                    policy: Some("accept".to_owned()),
                    purpose: "test input chain".to_owned(),
                }],
                table_hash_after_apply: Some("fnv1a64:beadbeadbeadbead".to_owned()),
                ownership_id: "ownership-1".to_owned(),
            },
            network_manager: NetworkManagerUnmanaged {
                file_path: "/etc/NetworkManager/conf.d/00-d2b-unmanaged.conf".to_owned(),
                match_criteria: vec!["interface-name:d2b-*".to_owned()],
                reload_behavior: "atomic-reload".to_owned(),
                ownership: OwnershipRule {
                    owner: "root".to_owned(),
                    group: "root".to_owned(),
                    mode: "0644".to_owned(),
                    drift_policy: "replace".to_owned(),
                },
            },
            hosts_file: HostsFileOwnership {
                start_marker: "# d2b-managed begin".to_owned(),
                end_marker: "# d2b-managed end".to_owned(),
                rule: "replace-managed-block".to_owned(),
            },
            kernel_modules: Vec::<KernelModulesEntry>::new(),
            fd_ownership: Vec::<FdOwnershipEntry>::new(),
            runtime_providers: Vec::new(),
            vm_runtimes: Vec::new(),
            cloud_hypervisor_capabilities: Vec::<CloudHypervisorCapability>::new(),
            if_name_mappings: Vec::<IfNameMapping>::new(),
            qemu_media: None,
            ch: Some(HostChConfig {
                net_handoff_mode: ChNetHandoffMode::TapFd,
            }),
            firewall_coexistence_policy: None,
        };

        let processes = ProcessesJson {
            schema_version: "v2".to_owned(),
            vms: vec![
                VmProcessDag {
                    workload_identity: None,
                    vm: "corp-vm".to_owned(),
                    nodes: vec![ProcessNode {
                        execution_ref: None,
                        execution_domain: None,
                        user_ref: None,
                        id: NodeId("ch-runner".to_owned()),
                        role: ProcessRole::CloudHypervisorRunner,
                        unit: Some("d2b@corp-vm.service".to_owned()),
                        binary_path: None,
                        argv: Vec::new(),
                        env: Vec::new(),
                        profile: RoleProfileBuilder::new()
                            .with_profile_id("profile-ch")
                            .with_uid(1001)
                            .with_gid(1001)
                            .with_namespaces(d2b_core::minijail_profile::NamespaceSet {
                                mount: true,
                                pid: false,
                                net: false,
                                ipc: false,
                                uts: false,
                                user: false,
                            })
                            .with_seccomp_policy_ref(Some("profile-ch.seccomp"))
                            .with_read_only_paths(vec!["/nix/store".to_owned()])
                            .with_cgroup_placement(CgroupPlacement {
                                subtree: "d2b.slice/corp-vm/ch-runner".to_owned(),
                                controllers: vec!["cpu".to_owned(), "memory".to_owned()],
                                delegated: true,
                            })
                            .build(),
                        readiness: Vec::new(),
                        plan_ops: Vec::new(),
                        network_interfaces: Vec::new(),
                    }],
                    edges: Vec::new(),
                    invariants: VmProcessInvariants {
                        swtpm_pre_start_flush: true,
                        per_vm_audit_pipeline: true,
                        usbip_gating: true,
                        tpm_ownership_migration_without_running_vm_mutation: true,
                    },
                },
                VmProcessDag {
                    workload_identity: None,
                    vm: "sys-work-usbipd".to_owned(),
                    nodes: vec![ProcessNode {
                        execution_ref: None,
                        execution_domain: None,
                        user_ref: None,
                        id: NodeId("backend".to_owned()),
                        role: ProcessRole::Usbip,
                        unit: None,
                        binary_path: Some("/run/current-system/sw/bin/usbipd".to_owned()),
                        argv: vec!["usbipd".to_owned(), "-D".to_owned()],
                        env: Vec::new(),
                        profile: RoleProfileBuilder::new()
                            .with_profile_id("profile-usbip")
                            .with_uid(1002)
                            .with_gid(1002)
                            .with_cgroup_placement(CgroupPlacement {
                                subtree: "d2b.slice/sys-work-usbipd/backend".to_owned(),
                                controllers: vec!["cpu".to_owned(), "memory".to_owned()],
                                delegated: false,
                            })
                            .build(),
                        readiness: Vec::new(),
                        plan_ops: Vec::new(),
                        network_interfaces: Vec::new(),
                    }],
                    edges: Vec::new(),
                    invariants: VmProcessInvariants {
                        swtpm_pre_start_flush: true,
                        per_vm_audit_pipeline: true,
                        usbip_gating: true,
                        tpm_ownership_migration_without_running_vm_mutation: true,
                    },
                },
            ],
        };

        let manifest = ManifestV04 {
            manifest: ManifestMeta {
                manifest_version: 6,
            },
            observability: ObservabilityMeta {
                enabled: false,
                obs_vsock_cid: 3,
                obs_vsock_host_socket: "/run/d2b/obs.sock".to_owned(),
                signoz_otlp_grpc_port: 4317,
                signoz_otlp_http_port: 4318,
                signoz_url: "http://127.0.0.1:8080".to_owned(),
                vm_name: "obs".to_owned(),
            },
            vms: BTreeMap::from([(
                "corp-vm".to_owned(),
                VmEntry {
                    api_socket: Some("/run/d2b/vms/corp-vm/api.sock".to_owned()),
                    audio: false,
                    audio_service: Some(String::new()),
                    audio_state_file: Some(String::new()),
                    bridge: Some("br-work".to_owned()),
                    env: Some("work".to_owned()),
                    mtu: Some(1500),
                    mss_clamp: Some(1460),
                    lan: Some(VmLanPolicy {
                        allow_east_west: false,
                        effective_east_west: false,
                    }),
                    gpu_socket: Some(String::new()),
                    graphics: false,
                    is_net_vm: false,
                    name: "corp-vm".to_owned(),
                    net_vm: Some("sys-work-net".to_owned()),
                    observability: VmObservability {
                        agent_socket: Some("/run/d2b/vms/corp-vm/agent.sock".to_owned()),
                        enabled: false,
                        vsock_cid: Some(17),
                        vsock_host_socket: Some("/run/d2b/vms/corp-vm/agent-host.sock".to_owned()),
                    },
                    runtime: RuntimeMetadata::local_nixos(),
                    autostart: true,
                    security_key: false,
                    lifecycle: Default::default(),
                    shell: None,
                    ssh_user: Some("alice".to_owned()),
                    state_dir: "/var/lib/d2b/vms/corp-vm".to_owned(),
                    static_ip: Some("192.0.2.10".to_owned()),
                    tap: "tap-corp-vm".to_owned(),
                    tpm: false,
                    tpm_socket: Some(String::new()),
                    usbip_yubikey: true,
                    usbipd_host_ip: Some("192.0.2.1".to_owned()),
                },
            )]),
        };

        let closure = ClosureMetadata {
            schema_version: "v2".to_owned(),
            vm: "corp-vm".to_owned(),
            toplevel: "/nix/store/corp-vm-system".to_owned(),
            closure_paths: vec!["/nix/store/corp-vm-system".to_owned()],
            db_dump_path: "/nix/store/corp-vm-registration".to_owned(),
            declared_runner: "/run/current-system/sw/bin/cloud-hypervisor".to_owned(),
            runner_parity_path: "/run/current-system/sw/bin/cloud-hypervisor".to_owned(),
            runner_parity_ok: true,
            generation: ClosureGeneration {
                host_generation: Some(42),
                vm_generation: Some("42".to_owned()),
                source_revision: Some("deadbeef".to_owned()),
                generated_at: Some("2026-01-01T00:00:00Z".to_owned()),
            },
        };

        let bundle = Bundle {
            bundle_version: 3,
            schema_version: "v2".to_owned(),
            public_manifest_path: "vms.json".to_owned(),
            host_path: "host.json".to_owned(),
            processes_path: "processes.json".to_owned(),
            privileges_path: "privileges.json".to_owned(),
            storage_path: None,
            sync_path: None,
            allocator_path: None,
            realm_controllers_path: None,
            realm_identity_path: None,
            realm_workloads_launcher_v2_path: None,
            unsafe_local_workloads_path: None,
            closures: vec![BundleClosureRef {
                vm: "corp-vm".to_owned(),
                path: "closures/corp-vm.json".to_owned(),
            }],
            minijail_profiles: Vec::new(),
            managed_keys: Default::default(),
            generation: BundleGeneration {
                generator: "unit-test".to_owned(),
                source_revision: Some("deadbeef".to_owned()),
                generated_at: Some("2026-01-01T00:00:00Z".to_owned()),
            },
            bundle_hash: None,
            artifact_hashes: None,
        };

        write_json_file(&manifest_path, &manifest);
        write_json_file(&host_path, &host);
        write_json_file(&processes_path, &processes);
        write_json_file(&closure_path, &closure);

        // schemaVersion v2 bundles MUST carry a bundleHash field. Inject
        // it by replicating the bundle_resolver canonical-hash recipe:
        // sha256( serde_json::to_vec( bundle as Value with
        // artifactHashes=null and no bundleHash ) ).
        {
            use std::os::unix::fs::PermissionsExt;
            let mut as_value: serde_json::Value =
                serde_json::to_value(&bundle).expect("serialize test bundle to value");
            if let serde_json::Value::Object(map) = &mut as_value {
                map.remove("bundleHash");
                map.insert("artifactHashes".to_owned(), serde_json::Value::Null);
            }
            let canonical = serde_json::to_vec(&as_value).expect("canonical-serialize test bundle");
            let digest = {
                use sha2::Digest as _;
                let raw: [u8; 32] = sha2::Sha256::digest(&canonical).into();
                let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
                format!("sha256:{hex}")
            };
            if let serde_json::Value::Object(map) = &mut as_value {
                map.insert("bundleHash".to_owned(), serde_json::Value::String(digest));
            }
            let with_hash = serde_json::to_vec(&as_value).expect("re-serialize test bundle");
            if let Some(parent) = bundle_path.parent() {
                fs::create_dir_all(parent).expect("create parent directories for test bundle");
            }
            fs::write(&bundle_path, with_hash).expect("write test bundle.json");
            fs::set_permissions(&bundle_path, fs::Permissions::from_mode(0o640))
                .expect("chmod test bundle.json to 0640");
        }

        let resolver = Arc::new(
            BundleResolver::load_with_policy(
                &bundle_path,
                &d2b_core::bundle_resolver::BundleVerifyPolicy::for_tests(),
            )
            .expect("load test bundle"),
        );
        TestBundle {
            bundle_path,
            manifest_path,
            host_path,
            processes_path,
            resolver,
        }
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn broker_bundle_load_sees_rewritten_processes_without_restart() {
        use d2b_core::bundle_resolver::{BundleVerifyPolicy, intent_id_legacy_runner};
        use d2b_core::minijail_profile::{CgroupPlacement, WritablePath};
        use d2b_core::processes::{NodeId, ProcessNode, ProcessRole, ProcessesJson};
        use d2b_core::test_support::RoleProfileBuilder;

        let root = test_audit_dir("bundle-freshness");
        let bundle = build_test_bundle(&root);
        let policy = BundleVerifyPolicy::for_tests();

        let first = match try_load_resolver_with_policy(&bundle.bundle_path, &policy) {
            BundleSlot::Loaded(resolver) => resolver,
            other => panic!("initial bundle should load, got {other:?}"),
        };
        let video_intent = intent_id_legacy_runner("corp-vm", "video");
        assert!(
            first.find_runner_intent(&video_intent).is_none(),
            "fixture starts without a video runner"
        );

        let mut processes: ProcessesJson =
            serde_json::from_slice(&fs::read(&bundle.processes_path).expect("read processes.json"))
                .expect("parse processes.json");
        processes.vms[0].nodes.push(ProcessNode {
            execution_ref: None,
            execution_domain: None,
            user_ref: None,
            id: NodeId("video".to_owned()),
            role: ProcessRole::Video,
            unit: None,
            binary_path: Some("/nix/store/test-crosvm-video/bin/crosvm".to_owned()),
            argv: vec![
                "d2b-corp-vm-video".to_owned(),
                "device".to_owned(),
                "video-decoder".to_owned(),
                "--socket-path".to_owned(),
                "/run/d2b-video/corp-vm/video.sock".to_owned(),
                "--backend".to_owned(),
                "vaapi".to_owned(),
            ],
            env: Vec::new(),
            profile: RoleProfileBuilder::new()
                .with_profile_id("profile-video")
                .with_uid(1002)
                .with_gid(1002)
                .with_seccomp_policy_ref(Some("w1-video"))
                .with_writable_paths(vec![WritablePath {
                    path: "/run/d2b-video/corp-vm".to_owned(),
                    purpose: "test video socket".to_owned(),
                }])
                .with_device_binds(vec!["/dev/dri/renderD128".to_owned()])
                .with_cgroup_placement(CgroupPlacement {
                    subtree: "d2b.slice/corp-vm/video".to_owned(),
                    controllers: vec!["cpu".to_owned(), "memory".to_owned()],
                    delegated: false,
                })
                .with_umask(Some(7))
                .build(),
            readiness: Vec::new(),
            plan_ops: Vec::new(),
            network_interfaces: Vec::new(),
        });
        write_json_file(&bundle.processes_path, &processes);

        let second = match try_load_resolver_with_policy(&bundle.bundle_path, &policy) {
            BundleSlot::Loaded(resolver) => resolver,
            other => panic!("rewritten bundle should load, got {other:?}"),
        };
        let intent = second
            .find_runner_intent(&video_intent)
            .expect("per-request reload must see newly written video runner intent");
        assert_eq!(intent.role, ProcessRole::Video);
        assert_eq!(intent.umask, Some(7));
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    fn build_invalid_minijail_test_bundle(root: &Path) -> TestBundle {
        use d2b_core::processes::ProcessesJson;

        let mut bundle = build_test_bundle(root);
        let mut processes: ProcessesJson =
            serde_json::from_slice(&fs::read(&bundle.processes_path).expect("read processes.json"))
                .expect("parse processes.json");
        let profile = &mut processes.vms[0].nodes[0].profile;
        profile.uid = 0;
        profile.gid = 0;
        write_json_file(&bundle.processes_path, &processes);
        bundle.resolver = Arc::new(
            BundleResolver::load_with_policy(
                &bundle.bundle_path,
                &d2b_core::bundle_resolver::BundleVerifyPolicy::for_tests(),
            )
            .expect("reload invalid bundle"),
        );
        bundle
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    fn set_usbip_allowlist(
        bundle: &mut TestBundle,
        allowlist: Vec<d2b_core::host::VendorProductPair>,
    ) {
        let mut host: d2b_core::host::HostJson =
            serde_json::from_slice(&fs::read(&bundle.host_path).expect("read host.json"))
                .expect("parse host.json");
        host.environments[0].usbip_busid_locks[0].vendor_product_allowlist = allowlist;
        write_json_file(&bundle.host_path, &host);
        bundle.resolver = Arc::new(
            BundleResolver::load_with_policy(
                &bundle.bundle_path,
                &d2b_core::bundle_resolver::BundleVerifyPolicy::for_tests(),
            )
            .expect("reload bundle"),
        );
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    fn prepare_test_usb_sysfs_device(vendor: &str, product: &str, devpath: &str) -> PathBuf {
        let root = crate::test_scratch_root().join("runtime-usb-sysfs-root");
        TEST_USB_SYSFS_ROOT
            .set(root.clone())
            .unwrap_or_else(|_| assert_eq!(TEST_USB_SYSFS_ROOT.get(), Some(&root)));
        let device_dir = root.join("1-2.3");
        fs::create_dir_all(&device_dir).expect("create fake USB sysfs device");
        fs::write(device_dir.join("idVendor"), format!("{vendor}\n")).expect("write vendor");
        fs::write(device_dir.join("idProduct"), format!("{product}\n")).expect("write product");
        fs::write(device_dir.join("busnum"), b"1\n").expect("write busnum");
        fs::write(device_dir.join("devnum"), b"7\n").expect("write devnum");
        fs::write(device_dir.join("devpath"), format!("{devpath}\n")).expect("write devpath");
        let _ = fs::remove_file(device_dir.join("driver"));
        let _ = fs::remove_file(device_dir.join("serial"));
        root
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    fn test_server_config(root: &Path, manifest_path: &Path) -> ServerConfig {
        ServerConfig {
            profile: BrokerProfile::Host,
            authority_id: "test-host".to_owned(),
            socket_path: root.join("broker.sock"),
            audit_dir: root.join("audit"),
            audit_retention_days: 14,
            bundle_path: manifest_path.to_path_buf(),
            state_dir: root.join("state"),
            activation_helper_path: root.join("activation-helper"),
            d2bd_uid: 1000,
            d2bd_gid: Gid::current().as_raw(),
            store_sync_export_dir: root.join("observability").join("store-sync"),
            test_mode: true,
        }
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    fn test_usbip_intent_with_lock(
        root: &Path,
        bundle: &TestBundle,
    ) -> d2b_core::bundle_resolver::ResolvedUsbipBindIntent {
        let mut intent = find_usbip_bind_intent_for(&bundle.resolver, "corp-vm", "1-2.3")
            .expect("bundle usbip bind intent");
        let lock_dir = root.join("locks");
        fs::create_dir_all(&lock_dir).expect("create USBIP lock dir");
        intent.lock_path = lock_dir.join("1-2.3");
        intent
    }

    /// Read the StoreSync observability export lines the dispatch arm
    /// appended for `config` (today's rotated file). Returns the parsed
    /// records plus the raw JSON objects so tests can assert both the
    /// typed shape and the exact serialized key-set.
    #[cfg(not(feature = "layer1-bootstrap"))]
    fn read_store_sync_export(
        config: &ServerConfig,
    ) -> Vec<(
        crate::ops::store_sync_export::StoreSyncObservabilityRecord,
        serde_json::Map<String, serde_json::Value>,
    )> {
        let date = crate::audit::utc_date_string();
        let path = config
            .store_sync_export_dir
            .join(format!("store-sync-{date}.jsonl"));
        let contents = match fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(err) if err.kind() == io::ErrorKind::NotFound => String::new(),
            Err(err) => panic!("read store-sync export {}: {err}", path.display()),
        };
        contents
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                let record: crate::ops::store_sync_export::StoreSyncObservabilityRecord =
                    serde_json::from_str(line).expect("parse export record");
                let obj = serde_json::from_str::<serde_json::Value>(line)
                    .expect("parse export json")
                    .as_object()
                    .expect("export record is a json object")
                    .clone();
                (record, obj)
            })
            .collect()
    }

    /// Assert the exported JSON object's key-set equals the signed
    /// allow-list and that no redaction field leaked.
    #[cfg(not(feature = "layer1-bootstrap"))]
    fn assert_export_allow_list(obj: &serde_json::Map<String, serde_json::Value>) {
        use crate::ops::store_sync_export::{EXPORTED_KEYS, REDACTED_KEYS};
        let mut actual: Vec<&str> = obj.keys().map(String::as_str).collect();
        actual.sort_unstable();
        let mut expected: Vec<&str> = EXPORTED_KEYS.to_vec();
        expected.sort_unstable();
        assert_eq!(
            actual, expected,
            "export key-set must equal the signed allow-list"
        );
        for redacted in REDACTED_KEYS {
            assert!(
                !obj.contains_key(*redacted),
                "redacted key {redacted:?} leaked into export surface"
            );
        }
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn executable_identity_accepts_trusted_symlink_paths() {
        let expected = Path::new("/proc/self/exe");
        let actual = fs::read_link(expected).expect("read current executable");
        assert!(executable_paths_match(&actual, expected));
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn executable_identity_accepts_static_wrapper_exec_target() {
        let root = tempfile::tempdir().expect("tempdir");
        let wrapper = root.path().join("cloud-hypervisor");
        let real = root.path().join(".cloud-hypervisor-real");
        fs::write(
            &wrapper,
            "#!/bin/sh\nexec \"$here/.cloud-hypervisor-real\" \"$@\"\n",
        )
        .expect("write wrapper");
        fs::write(&real, b"trusted executable").expect("write executable");

        assert!(executable_paths_match(&real, &wrapper));
        assert!(!executable_paths_match(
            &root.path().join("other"),
            &wrapper
        ));
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn executable_observation_keeps_permission_denied_distinct_from_a_mismatch() {
        let observed = observe_runner_executable(
            Err(io::Error::from(io::ErrorKind::PermissionDenied)),
            Path::new("/nix/store/provider-controller/bin/controller"),
        )
        .expect("permission-denied observation");
        assert_eq!(observed, RunnerExecutableObservation::PermissionDenied);
        assert!(!observed.is_verified_for_discovery());
        assert!(observed.is_verified_for_registered(true, true));
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn typed_process_cgroup_scope_is_private_and_collision_safe() {
        let placement = d2b_core::minijail_profile::CgroupPlacement {
            subtree: "d2b.slice/corp-vm/cloud-hypervisor".to_owned(),
            controllers: vec!["cpu".to_owned()],
            delegated: false,
        };
        let first = private_cgroup_placement(&placement, "corp-vm", Some([1; 32]), true)
            .expect("private cgroup placement");
        let second = private_cgroup_placement(&placement, "corp-vm", Some([2; 32]), true)
            .expect("private cgroup placement");
        assert_ne!(first.subtree, second.subtree);
        assert!(!first.subtree.contains("corp-vm"));
        assert!(first.subtree.starts_with("d2b.slice/process-"));
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn typed_zone_guest_cgroup_scope_is_private_and_collision_safe() {
        let placement = d2b_core::minijail_profile::CgroupPlacement {
            subtree: "d2b.slice/work/desktop/cloud-hypervisor".to_owned(),
            controllers: vec!["cpu".to_owned()],
            delegated: false,
        };
        let first = private_cgroup_placement(&placement, "desktop", Some([1; 32]), true)
            .expect("private Zone/Guest cgroup placement");
        let second = private_cgroup_placement(&placement, "desktop", Some([2; 32]), true)
            .expect("private Zone/Guest cgroup placement");
        assert_ne!(first.subtree, second.subtree);
        assert!(!first.subtree.contains("work"));
        assert!(!first.subtree.contains("desktop"));
        assert!(first.subtree.ends_with("/cloud-hypervisor"));
        assert!(first.subtree.starts_with("d2b.slice/process-"));
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn typed_runner_registry_keys_use_opaque_runtime_scope() {
        let resource_ref =
            d2b_contracts_resource::v3::ResourceRef::parse("Process/worker").expect("resource ref");
        let uid =
            d2b_contracts_resource::v3::ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000")
                .expect("resource uid");
        let zone_uid =
            d2b_contracts_resource::v3::ResourceUid::parse("223e4567-e89b-42d3-a456-426614174001")
                .expect("zone uid");
        let first = runner_registry_key(
            "corp-vm",
            "worker",
            Some(&resource_ref),
            Some(&uid),
            Some(&zone_uid),
            Some([1; 32]),
        );
        let second = runner_registry_key(
            "corp-vm",
            "worker",
            Some(&resource_ref),
            Some(&uid),
            Some(&zone_uid),
            Some([2; 32]),
        );
        assert_ne!(first, second);
        assert!(first.starts_with("scope:"));
        assert!(!first.contains("corp-vm"));
        assert!(!first.contains("Process/worker"));
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn typed_process_metadata_rejects_substituted_provider_and_template() {
        let intent = d2b_core::test_support::ResolvedRunnerIntentBuilder::new()
            .with_role_id("cloud-hypervisor")
            .with_role(d2b_core::processes::ProcessRole::CloudHypervisorRunner)
            .with_execution_ref("Host/host-system")
            .build();
        let provider_ref =
            d2b_contracts_resource::v3::ResourceRef::parse("Provider/system-minijail")
                .expect("provider ref");
        let mut provider_digest = Sha256::new();
        provider_digest.update(b"d2b-process-provider-v1");
        provider_digest.update(b"system-minijail");
        let provider_identity: [u8; 32] = provider_digest.finalize().into();
        let mut template_digest = Sha256::new();
        template_digest.update(b"d2b-process-template-v1");
        template_digest.update(b"cloud-hypervisor");
        let template_identity: [u8; 32] = template_digest.finalize().into();

        assert!(
            validate_typed_process_metadata(
                true,
                None,
                Some(&provider_ref),
                Some(provider_identity),
                Some(template_identity),
                None,
                &intent,
            )
            .is_ok()
        );
        assert!(
            validate_typed_process_metadata(
                true,
                None,
                Some(&provider_ref),
                Some([9; 32]),
                Some(template_identity),
                None,
                &intent,
            )
            .is_err()
        );
        assert!(
            validate_typed_process_metadata(
                true,
                None,
                Some(&provider_ref),
                Some(provider_identity),
                Some([9; 32]),
                None,
                &intent,
            )
            .is_err()
        );
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn typed_spawn_allowlist_rejects_identity_and_runtime_substitutions() {
        use d2b_contracts::types::{BundleOpId, RoleId, VmId};
        use d2b_contracts_broker::broker_wire::{
            RunnerAllocation, RunnerAllocationKind, SpawnRunnerRequest,
        };
        use d2b_contracts_resource::v3::{ResourceRef, execution_policy::ExecutionDomain};

        let intent = d2b_core::test_support::ResolvedRunnerIntentBuilder::new()
            .with_intent_id("runner:corp-vm:cloud-hypervisor")
            .with_vm_name("corp-vm")
            .with_role_id("cloud-hypervisor")
            .with_role(d2b_core::processes::ProcessRole::CloudHypervisorRunner)
            .with_execution_ref("Host/host-system")
            .with_cgroup_placement(d2b_core::minijail_profile::CgroupPlacement {
                subtree: "d2b.slice/corp-vm/cloud-hypervisor".to_owned(),
                controllers: vec!["cpu".to_owned()],
                delegated: false,
            })
            .build();
        let zone_uid =
            d2b_contracts_resource::v3::ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000")
                .expect("zone uid");
        let resource_uid =
            d2b_contracts_resource::v3::ResourceUid::parse("223e4567-e89b-42d3-a456-426614174001")
                .expect("resource uid");
        let resource_ref =
            d2b_contracts_resource::v3::ResourceRef::parse("Process/cloud-hypervisor")
                .expect("resource ref");
        let runtime_scope = private_runtime_scope(
            &zone_uid,
            None,
            &resource_ref,
            &resource_uid,
            &intent.role_id,
            1,
        );
        let mut provider_digest = Sha256::new();
        provider_digest.update(b"d2b-process-provider-v1");
        provider_digest.update(b"system-minijail");
        let provider_identity: [u8; 32] = provider_digest.finalize().into();
        let mut template_digest = Sha256::new();
        template_digest.update(b"d2b-process-template-v1");
        template_digest.update(b"cloud-hypervisor");
        let template_identity: [u8; 32] = template_digest.finalize().into();
        let request = || SpawnRunnerRequest {
            vm_id: VmId::new("corp-vm"),
            role_id: RoleId::new("ch-runner"),
            resource_ref: Some(resource_ref.clone()),
            resource_uid: Some(resource_uid.clone()),
            zone_uid: Some(zone_uid.clone()),
            owner_ref: None,
            owner_uid: None,
            provider_ref: Some(
                d2b_contracts_resource::v3::ResourceRef::parse("Provider/system-minijail")
                    .expect("provider ref"),
            ),
            bundle_content_identity: Some("sha256:bundle".to_owned()),
            provider_identity: Some(provider_identity),
            template_identity: Some(template_identity),
            generation: Some(1),
            runtime_scope: Some(runtime_scope),
            activation_input: None,
            sandbox_plan: None,
            role: RunnerRole::CloudHypervisor,
            bundle_runner_intent_ref: BundleOpId::new(intent.intent_id.clone()),
            execution_ref: Some(ResourceRef::parse("Host/host-system").expect("execution ref")),
            execution_domain: Some(ExecutionDomain::System),
            user_ref: None,
            guest_execution: None,
            runtime_allocations: Vec::new(),
            tracing_span_id: None,
            workload_identity: None,
            inherited_fd_count: 0,
            network_tap_context: None,
        };

        let valid = request();
        assert!(validate_spawn_runner_request_matches_intent(&valid, &intent).is_ok());

        let mut mutations = Vec::new();
        let mut provider = valid.clone();
        provider.provider_identity = Some([9; 32]);
        mutations.push(provider);
        let mut template = valid.clone();
        template.template_identity = Some([9; 32]);
        mutations.push(template);
        let mut scope = valid.clone();
        scope.runtime_scope = Some([9; 32]);
        mutations.push(scope);
        let mut generation = valid.clone();
        generation.generation = Some(2);
        mutations.push(generation);
        let mut allocations = valid;
        allocations.runtime_allocations = vec![RunnerAllocation {
            kind: RunnerAllocationKind::VsockCid,
            opaque_ref: "cid:attacker".to_owned(),
        }];
        mutations.push(allocations);

        for mutation in mutations {
            assert!(
                validate_spawn_runner_request_matches_intent(&mutation, &intent).is_err(),
                "mutated SpawnRunner request must fail before clone"
            );
        }
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn open_pidfd_maps_cloud_hypervisor_compat_role_to_bundle_intent() {
        assert_eq!(
            runner_intent_id_for_open_pidfd("acceptance-guest", "ch-runner"),
            "runner:vm:acceptance-guest:role:cloud-hypervisor"
        );
        assert_eq!(
            runner_intent_id_for_open_pidfd("acceptance-guest", "swtpm"),
            "runner:vm:acceptance-guest:role:swtpm"
        );
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    fn dummy_fd() -> OwnedFd {
        std::fs::File::open("/dev/null")
            .expect("open /dev/null for dummy fd")
            .into()
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    fn is_uuid_v4_like(value: &str) -> bool {
        let chars: Vec<char> = value.chars().collect();
        chars.len() == 36
            && matches!(chars.get(8), Some('-'))
            && matches!(chars.get(13), Some('-'))
            && matches!(chars.get(18), Some('-'))
            && matches!(chars.get(23), Some('-'))
            && matches!(chars.get(14), Some('4'))
            && matches!(chars.get(19), Some('8' | '9' | 'a' | 'b'))
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[derive(Default)]
    struct FakeDispatchBackend {
        registered_runners: Mutex<std::collections::BTreeSet<String>>,
        usbip_events: Mutex<Vec<FakeUsbipEvent>>,
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum FakeUsbipEvent {
        Bind { intent_id: String },
        Unbind { intent_id: String },
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    impl FakeDispatchBackend {
        fn remember_runner(&self, runner_id: &str) -> Result<(), BrokerError> {
            self.registered_runners
                .lock()
                .map_err(|_| {
                    BrokerError::Protocol("fake runner registry mutex poisoned".to_owned())
                })?
                .insert(runner_id.to_owned());
            Ok(())
        }

        fn has_runner(&self, runner_id: &str) -> Result<bool, BrokerError> {
            Ok(self
                .registered_runners
                .lock()
                .map_err(|_| {
                    BrokerError::Protocol("fake runner registry mutex poisoned".to_owned())
                })?
                .contains(runner_id))
        }

        fn push_usbip_event(&self, event: FakeUsbipEvent) -> Result<(), BrokerError> {
            self.usbip_events
                .lock()
                .map_err(|_| BrokerError::Protocol("fake USBIP event mutex poisoned".to_owned()))?
                .push(event);
            Ok(())
        }

        fn take_usbip_events(&self) -> Vec<FakeUsbipEvent> {
            let mut events = self.usbip_events.lock().expect("fake USBIP event lock");
            std::mem::take(&mut *events)
        }
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    impl DispatchBackend for FakeDispatchBackend {
        fn apply_nftables(
            &self,
            _resolver: &BundleResolver,
            _intent: &d2b_core::bundle_resolver::ResolvedNftIntent,
            _desired_hash: Option<&str>,
            _destroy: bool,
        ) -> Result<(), BrokerError> {
            Ok(())
        }

        fn apply_route(
            &self,
            _state_dir: &Path,
            _intent: &d2b_core::bundle_resolver::ResolvedRouteIntent,
            _provenance: &d2b_contracts_resource::v3::NetworkProvenance,
            _destroy: bool,
        ) -> Result<(), BrokerError> {
            Ok(())
        }

        fn apply_sysctl(
            &self,
            _intent: &d2b_core::bundle_resolver::ResolvedSysctlIntent,
            _destroy: bool,
        ) -> Result<(), BrokerError> {
            Ok(())
        }

        fn update_hosts_file(
            &self,
            _intent: &d2b_core::bundle_resolver::ResolvedHostsIntent,
            _destroy: bool,
        ) -> Result<(), BrokerError> {
            Ok(())
        }

        fn apply_nm_unmanaged(
            &self,
            _intent: &d2b_core::bundle_resolver::ResolvedNmUnmanagedIntent,
            _destroy: bool,
        ) -> Result<(), BrokerError> {
            Ok(())
        }

        fn prepare_store_view(
            &self,
            intent: &d2b_core::bundle_resolver::ResolvedStoreViewIntent,
        ) -> Result<crate::live_handlers::StoreViewOutcome, BrokerError> {
            Ok(crate::live_handlers::StoreViewOutcome {
                vm: intent.vm.clone(),
                generation: intent.generation,
                hardlink_farm_path: intent.hardlink_farm_path.clone(),
                target_view_path: intent.target_view_path.clone(),
            })
        }

        fn set_bridge_port_flags(
            &self,
            req: &d2b_contracts_broker::broker_wire::SetBridgePortFlagsRequest,
            _resolver: &BundleResolver,
        ) -> Result<d2b_contracts_broker::broker_wire::BridgePortFlagsResponse, BrokerError>
        {
            Ok(d2b_contracts_broker::broker_wire::BridgePortFlagsResponse {
                bridge: d2b_contracts_resource::v3::IfName::new("nlworkbr0")
                    .expect("fake bridge ifname"),
                isolated: true,
                neigh_suppress: true,
                port: d2b_contracts_resource::v3::IfName::new(&format!(
                    "tap-{}",
                    req.vm_id.as_str()
                ))
                .expect("fake tap ifname"),
            })
        }

        fn setup_mount_namespace(
            &self,
            vm_name: &str,
            role_id: &str,
            store_view_intent: &d2b_core::bundle_resolver::ResolvedStoreViewIntent,
        ) -> Result<crate::live_handlers::MountNamespaceOutcome, BrokerError> {
            let _ = store_view_intent;
            let mount_root = PathBuf::from(format!("/run/d2b/mountns/{vm_name}/{role_id}"));
            Ok(crate::live_handlers::MountNamespaceOutcome {
                vm: vm_name.to_owned(),
                role_id: role_id.to_owned(),
                mount_root: mount_root.clone(),
                mount_view_path: mount_root.join("nix/store"),
            })
        }

        fn open_pidfd(
            &self,
            runner_id: &str,
            pid: i32,
            expected_start_time_ticks: u64,
        ) -> Result<crate::live_handlers::OpenPidfdResult, BrokerError> {
            self.remember_runner(runner_id)?;
            Ok(crate::live_handlers::OpenPidfdResult {
                pidfd: dummy_fd(),
                pid,
                verified_start_time_ticks: expected_start_time_ticks,
            })
        }

        fn start_systemd_unit(
            &self,
            _resolver: &BundleResolver,
            _request: &d2b_contracts_broker::broker_wire::StartTransientUnitRequest,
        ) -> Result<
            (
                d2b_contracts_broker::broker_wire::SystemdUnitIdentity,
                OwnedFd,
            ),
            BrokerError,
        > {
            Err(BrokerError::Unimplemented {
                operation: "StartSystemdUnit",
                target_wave: "W6",
            })
        }

        fn check_systemd_user_manager(
            &self,
            _resolver: &BundleResolver,
            _request: &d2b_contracts_broker::broker_wire::CheckSystemdUserManagerRequest,
        ) -> Result<bool, BrokerError> {
            Err(BrokerError::Unimplemented {
                operation: "CheckSystemdUserManager",
                target_wave: "W6",
            })
        }

        fn observe_systemd_unit(
            &self,
            _resolver: &BundleResolver,
            _request: &d2b_contracts_broker::broker_wire::ObserveSystemdUnitRequest,
        ) -> Result<Option<d2b_contracts_broker::broker_wire::SystemdUnitIdentity>, BrokerError>
        {
            Err(BrokerError::Unimplemented {
                operation: "ObserveSystemdUnit",
                target_wave: "W6",
            })
        }

        fn reopen_systemd_unit(
            &self,
            _resolver: &BundleResolver,
            _request: &d2b_contracts_broker::broker_wire::OpenSystemdUnitPidfdRequest,
        ) -> Result<
            (
                d2b_contracts_broker::broker_wire::SystemdUnitIdentity,
                OwnedFd,
            ),
            BrokerError,
        > {
            Err(BrokerError::Unimplemented {
                operation: "OpenSystemdUnitPidfd",
                target_wave: "W6",
            })
        }

        fn stop_systemd_unit(
            &self,
            _resolver: &BundleResolver,
            _request: &d2b_contracts_broker::broker_wire::StopSystemdUnitRequest,
        ) -> Result<(), BrokerError> {
            Err(BrokerError::Unimplemented {
                operation: "StopSystemdUnit",
                target_wave: "W6",
            })
        }

        fn signal_runner(
            &self,
            runner_id: &str,
            _signal: d2b_contracts_broker::broker_wire::RunnerSignal,
        ) -> Result<(), BrokerError> {
            if self.has_runner(runner_id)? {
                Ok(())
            } else {
                Err(BrokerError::NoPidfd {
                    runner_id: runner_id.to_owned(),
                })
            }
        }

        fn spawn_runner(
            &self,
            runner_id: &str,
            _plan_input: &crate::ops::spawn_runner::SpawnRunnerPlanInput,
            _resolver: &BundleResolver,
            _req: &d2b_contracts_broker::broker_wire::SpawnRunnerRequest,
            request_fds: Vec<OwnedFd>,
            _audit_log: &crate::audit::AuditLog,
        ) -> Result<crate::live_handlers::SpawnRunnerResult, BrokerError> {
            drop(request_fds);
            self.remember_runner(runner_id)?;
            Ok(crate::live_handlers::SpawnRunnerResult {
                pidfd: dummy_fd(),
                extra_response_fds: Vec::new(),
                pid: 4242,
                start_time_ticks: 123456,
                used_fork_fallback: false,
                swtpm_dir_audit: None,
            })
        }

        fn run_host_install(
            &self,
            req: &d2b_contracts_broker::broker_wire::RunHostInstallRequest,
            _resolver: Option<&BundleResolver>,
        ) -> Result<d2b_contracts_broker::broker_wire::RunHostInstallResponse, BrokerError>
        {
            Ok(d2b_contracts_broker::broker_wire::RunHostInstallResponse {
                installed: true,
                enabled: req.enable,
                started: req.start && !req.no_start,
                artifacts_written: vec!["/etc/systemd/system/d2bd.service".to_owned()],
            })
        }

        fn run_migrate(
            &self,
            intent: &d2b_core::bundle_resolver::ResolvedMigrateIntent,
        ) -> Result<crate::live_handlers::MigrateOutcome, BrokerError> {
            Ok(crate::live_handlers::MigrateOutcome {
                migrated_vm_count: intent.vms.len() as u32,
                notes: intent.notes.clone(),
            })
        }

        fn run_activation(
            &self,
            intent: &d2b_core::bundle_resolver::ResolvedActivationIntent,
            store_view_intent: &d2b_core::bundle_resolver::ResolvedStoreViewIntent,
            phase: d2b_contracts_broker::broker_wire::ActivationPhase,
            mode: d2b_contracts_broker::broker_wire::ActivationMode,
        ) -> Result<crate::live_handlers::ActivationOutcome, BrokerError> {
            Ok(crate::live_handlers::ActivationOutcome {
                phase,
                mode,
                vm: intent.vm.clone(),
                generation_number: intent.generation_number,
                summary: "activation complete".to_owned(),
                prepared_store_view: Some(crate::live_handlers::StoreViewOutcome {
                    vm: store_view_intent.vm.clone(),
                    generation: store_view_intent.generation,
                    hardlink_farm_path: store_view_intent.hardlink_farm_path.clone(),
                    target_view_path: store_view_intent.target_view_path.clone(),
                }),
                guest_switch_script_path: Some(PathBuf::from(format!(
                    "/nix/store/{}/bin/switch-to-configuration",
                    store_view_intent
                        .target_view_path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("alpha-system")
                ))),
                activation_script_mode: activation_mode_name(mode).to_owned(),
                rollback_marker_written: None,
                current_generation_updated: if phase
                    == d2b_contracts_broker::broker_wire::ActivationPhase::Prepare
                {
                    None
                } else {
                    intent
                        .generation_number
                        .or(Some(store_view_intent.generation))
                },
            })
        }

        fn apply_host_generation_handoff(
            &self,
            state_dir: &std::path::Path,
            helper_path: &std::path::Path,
            request: &d2b_contracts_broker::host_generation::ApplyHostGenerationHandoff,
        ) -> Result<
            d2b_contracts_broker::broker_wire::ApplyHostGenerationHandoffResponse,
            BrokerError,
        > {
            crate::ops::host_generation_handoff::apply_with_helper(state_dir, helper_path, request)
                .map_err(|error| BrokerError::LiveHandler(error.to_string()))
        }

        fn run_gc(
            &self,
            intent: &d2b_core::bundle_resolver::ResolvedGcIntent,
            keep_generations: Option<u32>,
        ) -> Result<crate::live_handlers::GcOutcome, BrokerError> {
            Ok(crate::live_handlers::GcOutcome {
                keep_generations,
                retained_store_path_count: intent.retained_store_paths.len() as u32,
                summary: "gc complete".to_owned(),
            })
        }

        fn run_keys_rotate(
            &self,
            intent: &d2b_core::bundle_resolver::ResolvedKeysRotateIntent,
        ) -> Result<crate::live_handlers::KeysRotateOutcome, BrokerError> {
            Ok(crate::live_handlers::KeysRotateOutcome {
                vm: intent.vm.clone(),
                key_path: intent.key_path.clone(),
                public_key_fingerprint: "SHA256:test-fingerprint".to_owned(),
            })
        }

        fn run_host_key_trust(
            &self,
            intent: &d2b_core::bundle_resolver::ResolvedHostKeyTrustIntent,
        ) -> Result<crate::live_handlers::HostKeyTrustOutcome, BrokerError> {
            Ok(crate::live_handlers::HostKeyTrustOutcome {
                vm: intent.vm.clone(),
                static_ip: intent.static_ip.clone(),
                known_hosts_path: intent.known_hosts_path.clone(),
                updated: true,
            })
        }

        fn run_rotate_known_host(
            &self,
            intent: &d2b_core::bundle_resolver::ResolvedRotateKnownHostIntent,
        ) -> Result<crate::live_handlers::RotateKnownHostOutcome, BrokerError> {
            Ok(crate::live_handlers::RotateKnownHostOutcome {
                vm: intent.vm.clone(),
                static_ip: intent.static_ip.clone(),
                known_hosts_path: intent.known_hosts_path.clone(),
                removed: true,
            })
        }

        fn usbip_bind(
            &self,
            intent: &d2b_core::bundle_resolver::ResolvedUsbipBindIntent,
        ) -> Result<(), BrokerError> {
            self.push_usbip_event(FakeUsbipEvent::Bind {
                intent_id: intent.intent_id.clone(),
            })?;
            Ok(())
        }

        fn usbip_unbind(
            &self,
            intent: &d2b_core::bundle_resolver::ResolvedUsbipBindIntent,
        ) -> Result<(), BrokerError> {
            self.push_usbip_event(FakeUsbipEvent::Unbind {
                intent_id: intent.intent_id.clone(),
            })?;
            Ok(())
        }

        fn usbip_bind_firewall_rule(
            &self,
            _resolver: &BundleResolver,
            _intent: &d2b_core::bundle_resolver::ResolvedUsbipFirewallIntent,
        ) -> Result<(), BrokerError> {
            Ok(())
        }

        fn usbip_proxy_reconcile(
            &self,
            _expectations: &[(String, String, PathBuf)],
        ) -> Result<(), BrokerError> {
            Ok(())
        }

        fn qemu_media_system_powerdown(
            &self,
            req: &d2b_contracts_broker::broker_wire::QemuMediaLifecycleRequest,
        ) -> Result<d2b_contracts_broker::broker_wire::QemuMediaLifecycleResponse, BrokerError>
        {
            Ok(
                d2b_contracts_broker::broker_wire::QemuMediaLifecycleResponse {
                    vm_id: req.vm_id.clone(),
                    command:
                        d2b_contracts_broker::broker_wire::QemuMediaLifecycleAction::SystemPowerdown,
                },
            )
        }

        fn qemu_media_query_status(
            &self,
            req: &d2b_contracts_broker::broker_wire::QemuMediaQueryStatusRequest,
        ) -> Result<d2b_contracts_broker::broker_wire::QemuMediaQueryStatusResponse, BrokerError>
        {
            let status = if req.shutdown_context {
                d2b_contracts_broker::broker_wire::QemuMediaVmStatus::ConnectionLostDuringShutdown
            } else {
                d2b_contracts_broker::broker_wire::QemuMediaVmStatus::Running
            };
            Ok(
                d2b_contracts_broker::broker_wire::QemuMediaQueryStatusResponse {
                    vm_id: req.vm_id.clone(),
                    status,
                },
            )
        }

        fn qemu_media_quit(
            &self,
            req: &d2b_contracts_broker::broker_wire::QemuMediaLifecycleRequest,
        ) -> Result<d2b_contracts_broker::broker_wire::QemuMediaLifecycleResponse, BrokerError>
        {
            Ok(
                d2b_contracts_broker::broker_wire::QemuMediaLifecycleResponse {
                    vm_id: req.vm_id.clone(),
                    command: d2b_contracts_broker::broker_wire::QemuMediaLifecycleAction::Quit,
                },
            )
        }
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn qemu_media_lifecycle_dispatch_audits_mutations_but_not_status_poll() {
        use d2b_contracts::types::{TracingSpanId, VmId};
        use d2b_contracts_broker::broker_wire::{
            BrokerCallerRole, BrokerRequest, QemuMediaLifecycleAction, QemuMediaLifecycleRequest,
            QemuMediaQueryStatusRequest, QemuMediaVmStatus,
        };

        let root = test_audit_dir("qemu-lifecycle-dispatch-audit");
        let bundle = build_test_bundle(&root);
        let config = test_server_config(&root, &bundle.manifest_path);
        let (log, capture) = AuditLog::open_capturing(
            &config.audit_dir,
            Gid::current().as_raw(),
            true,
            config.audit_retention_days,
        )
        .expect("open capturing audit log");
        let backend = FakeDispatchBackend::default();
        let caller_role = BrokerCallerRole::AdminUid { uid: 1000 };
        let caller_gid = Gid::current().as_raw();

        let dispatch = |request: BrokerRequest| {
            let audit_context = DispatchAuditContext::from_request(&request, 4242, &caller_role)
                .expect("audit context");
            dispatch_request_with_backend(
                request,
                1000,
                caller_gid,
                caller_role.clone(),
                &audit_context,
                &config,
                &log,
                Some(&bundle.resolver),
                &backend,
            )
            .expect("dispatch succeeds")
        };

        let powerdown = dispatch(BrokerRequest::QemuMediaSystemPowerdown(
            QemuMediaLifecycleRequest {
                vm_id: VmId::new("media"),
                tracing_span_id: Some(TracingSpanId::new("span-powerdown")),
            },
        ));
        match powerdown.response {
            BrokerResponse::QemuMediaSystemPowerdown(response) => {
                assert_eq!(response.command, QemuMediaLifecycleAction::SystemPowerdown);
            }

            other => panic!("expected QemuMediaSystemPowerdown, got {other:?}"),
        }

        let before_query = capture.lock().expect("capture before query").len();
        let query = dispatch(BrokerRequest::QemuMediaQueryStatus(
            QemuMediaQueryStatusRequest {
                vm_id: VmId::new("media"),
                shutdown_context: true,
                tracing_span_id: Some(TracingSpanId::new("span-query")),
            },
        ));
        match query.response {
            BrokerResponse::QemuMediaQueryStatus(response) => {
                assert_eq!(
                    response.status,
                    QemuMediaVmStatus::ConnectionLostDuringShutdown
                );
            }
            other => panic!("expected QemuMediaQueryStatus, got {other:?}"),
        }
        assert_eq!(
            capture.lock().expect("capture after query").len(),
            before_query,
            "query-status polling must not emit success audit records"
        );

        let quit = dispatch(BrokerRequest::QemuMediaQuit(QemuMediaLifecycleRequest {
            vm_id: VmId::new("media"),
            tracing_span_id: Some(TracingSpanId::new("span-quit")),
        }));
        match quit.response {
            BrokerResponse::QemuMediaQuit(response) => {
                assert_eq!(response.command, QemuMediaLifecycleAction::Quit);
            }
            other => panic!("expected QemuMediaQuit, got {other:?}"),
        }

        let records = capture.lock().expect("capture final");
        let qmp_records: Vec<_> = records
            .iter()
            .filter(|record| record.operation.starts_with("QemuMedia"))
            .collect();
        assert_eq!(qmp_records.len(), 2);
        assert_eq!(qmp_records[0].operation, "QemuMediaSystemPowerdown");
        assert_eq!(qmp_records[1].operation, "QemuMediaQuit");

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn accepted_peer_pidfd_refuses_missing_or_multiple_request_descriptors() {
        use d2b_contracts_broker::broker_wire::{BrokerCallerRole, BrokerRequest};

        let root = test_audit_dir("accepted-peer-pidfd-request-fds");
        let bundle = build_test_bundle(&root);
        let config = test_server_config(&root, &bundle.manifest_path);
        let (log, _) = AuditLog::open_capturing(
            &config.audit_dir,
            Gid::current().as_raw(),
            true,
            config.audit_retention_days,
        )
        .expect("open capturing audit log");
        let backend = FakeDispatchBackend::default();
        let caller_role = BrokerCallerRole::AdminUid { uid: 1000 };
        let request = BrokerRequest::OpenPeerPidfdFromAcceptedSocket(
            d2b_contracts_broker::broker_wire::OpenPeerPidfdFromAcceptedSocketRequest {},
        );
        let audit_context = DispatchAuditContext::from_request(&request, 4242, &caller_role)
            .expect("audit context");

        for request_fds in [Vec::new(), vec![dummy_fd(), dummy_fd()]] {
            let error = dispatch_request_with_backend_and_request_fds(
                request.clone(),
                1000,
                Gid::current().as_raw(),
                caller_role.clone(),
                &audit_context,
                &config,
                &log,
                Some(&bundle.resolver),
                &backend,
                request_fds,
            )
            .expect_err("request fd count must be exact");
            assert!(
                matches!(error, BrokerError::Protocol(message) if message == "accepted socket request must carry exactly one descriptor")
            );
        }
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn accepted_peer_pidfd_refuses_caller_supplied_audit_join() {
        use d2b_contracts_broker::broker_wire::{
            AuditJoinContext, BrokerCallerRole, CanonicalAuditDigest,
        };

        let request = BrokerRequest::OpenPeerPidfdFromAcceptedSocket(
            d2b_contracts_broker::broker_wire::OpenPeerPidfdFromAcceptedSocketRequest {},
        );
        let audit_join = AuditJoinContext {
            zone_id: CanonicalAuditDigest::parse(d2b_contracts_resource::v3::canonical_digest(
                "d2b:test-zone",
                b"forged zone",
            ))
            .expect("canonical zone digest"),
            operation_identity: CanonicalAuditDigest::parse(
                d2b_contracts_resource::v3::canonical_digest(
                    "d2b:test-operation",
                    b"forged operation",
                ),
            )
            .expect("canonical operation digest"),
        };

        let error = DispatchAuditContext::from_request_with_join(
            &request,
            4242,
            &BrokerCallerRole::AdminUid { uid: 1000 },
            Some(&audit_join),
        )
        .expect_err("accepted-socket authority must not accept an audit join");
        assert!(
            matches!(error, BrokerError::Protocol(message) if message == "audit-join-not-permitted")
        );
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn dispatch_run_activation_response_for_intent_uses_native_sequence() {
        let root = test_audit_dir("run-activation-native");
        let source_view = root.join("source-view/alpha-system");
        fs::create_dir_all(source_view.join("bin")).expect("create source view");
        fs::write(
            source_view.join("bin/switch-to-configuration"),
            b"#!/bin/sh\n",
        )
        .expect("write switch-to-configuration");
        let intent = ResolvedActivationIntent {
            intent_id: "activation:vm:alpha".to_owned(),
            vm: "alpha".to_owned(),
            target_generation_path: root.join("declared-generation"),
            generation_number: Some(7),
        };
        let store_view_intent = ResolvedStoreViewIntent {
            intent_id: "store-view:vm:alpha".to_owned(),
            vm: "alpha".to_owned(),
            generation: 7,
            hardlink_farm_path: root.join("store-view"),
            target_view_path: root.join("store-view/live/alpha-system"),
            closure_paths: vec![source_view],
            db_dump_path: root.join("db.dump"),
        };
        let request = RunActivationRequest {
            bundle_activation_intent_ref: BundleOpId::new("activation:vm:alpha"),
            mode: ActivationMode::Switch,
            system_artifact_id: None,
            phase: ActivationPhase::Prepare,
            vm: "alpha".to_owned(),
            tracing_span_id: None,
        };
        let exec = FakeReconcileExecutor::new();

        let response = dispatch_run_activation_response_for_intent(
            &request,
            &intent,
            &store_view_intent,
            &exec,
        );

        assert!(matches!(
            response,
            BrokerResponse::RunActivation(RunActivationResponse {
                mode: ActivationMode::Switch,
                ref vm,
                generation_number: Some(7),
                guest_switch_script_path: Some(ref path),
                ..
            }) if vm == "alpha" && path == "/nix/store/alpha-system/bin/switch-to-configuration"
        ));
        let log = exec.take_log();
        assert_eq!(log.len(), 1);
        assert!(matches!(
            &log[0],
            ReconcileOp::PrepareStoreView { vm, generation, .. }
                if vm == "alpha" && *generation == 7
        ));
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    #[cfg_attr(
        not(test_root),
        ignore = "v1.1.1fu11: requires write access to /var/lib/d2b/runtime/ which only root can do; run with --cfg test_root in a privileged test environment"
    )]
    fn dispatch_request_writes_typed_op_audit_records_for_all_live_arms() {
        use d2b_contracts::types::{BundleOpId, RoleId, ScopeId, TracingSpanId, VmId};
        use d2b_contracts_broker::broker_wire::{
            ActivationMode, BrokerAuditFilter, BrokerCallerRole, BrokerRequest, RunnerAllocation,
            RunnerAllocationKind, RunnerRole, RunnerSignal,
        };
        use d2b_core::bundle_resolver::{
            intent_id_activation, intent_id_gc_host, intent_id_hosts_host,
            intent_id_installer_host, intent_id_keys_rotate, intent_id_legacy_runner,
            intent_id_migrate_host, intent_id_nft_host, intent_id_nm_unmanaged_host,
            intent_id_rotate_known_host, intent_id_route_env, intent_id_sysctl, intent_id_trust,
            intent_id_usbip_firewall,
        };

        let root = test_audit_dir("dispatch-typed-op-audit");
        let bundle = build_test_bundle(&root);
        let config = test_server_config(&root, &bundle.manifest_path);
        let (log, capture) = AuditLog::open_capturing(
            &config.audit_dir,
            Gid::current().as_raw(),
            true,
            config.audit_retention_days,
        )
        .expect("open capturing audit log");
        let backend = FakeDispatchBackend::default();
        let caller_role = BrokerCallerRole::AdminUid { uid: 1000 };
        let caller_gid = Gid::current().as_raw();
        let peer_pid = 4242;
        let _usb_sysfs_guard = usb_sysfs_test_lock();
        prepare_test_usb_sysfs_device("1050", "0407", "2.3");

        let assert_dispatch = |request: BrokerRequest,
                               operation: &str,
                               expected_fields: OperationFields,
                               expected_tracing: Option<&str>| {
            let expected_request_fields = request_fields_value(&request).expect("request fields");
            let audit_context =
                DispatchAuditContext::from_request(&request, peer_pid, &caller_role)
                    .expect("audit context");
            let before = capture.lock().expect("capture lock before dispatch").len();
            let result = dispatch_request_with_backend(
                request,
                1000,
                caller_gid,
                caller_role.clone(),
                &audit_context,
                &config,
                &log,
                Some(&bundle.resolver),
                &backend,
            )
            .expect("dispatch succeeds");
            let records = capture.lock().expect("capture lock after dispatch");
            assert_eq!(
                records.len(),
                before + 1,
                "{operation} should add one audit record"
            );
            let record = records[before].clone();
            drop(records);
            assert_eq!(record.operation, operation);
            assert_eq!(
                record.bundle_version,
                bundle.resolver.audit_bundle_version()
            );
            assert_eq!(record.bundle_hash, bundle.resolver.audit_bundle_hash());
            assert_eq!(record.peer_uid, 1000);
            assert_eq!(record.peer_gid, caller_gid);
            assert_eq!(record.peer_pid, peer_pid);
            assert_eq!(record.peer_role, caller_role.for_display());
            assert_eq!(record.authz_result, "admin");
            assert_eq!(record.verb, operation);
            assert_eq!(record.request_fields, expected_request_fields);
            assert_eq!(record.decision, "allowed");
            assert_eq!(record.result, "success");
            assert_eq!(record.error_kind, None);
            assert_eq!(record.tracing_span_id.as_deref(), expected_tracing);
            assert!(is_uuid_v4_like(&record.event_id));
            let fields = OperationFields::from_operation_value(
                operation,
                record.operation_fields.expect("operation fields present"),
            )
            .expect("deserialize operation fields");
            assert_eq!(
                fields, expected_fields,
                "unexpected operation_fields for {operation}"
            );
            result
        };

        let assert_ack = |result: DispatchResult, operation: &str| {
            assert!(result.fds.is_empty(), "{operation} should not return fds");
            match result.response {
                BrokerResponse::Ack(response) => {
                    assert!(response.accepted);
                    assert_eq!(response.operation, operation);
                }
                other => panic!("expected Ack for {operation}, got {other:?}"),
            }
        };

        let hello = assert_dispatch(
            BrokerRequest::Hello(d2b_contracts_broker::broker_wire::HelloRequest {
                client_version: "1.2.3".to_owned(),
                supported_features: vec!["typed-audit".to_owned()],
            }),
            "Hello",
            OperationFields::Hello {
                client_version: "1.2.3".to_owned(),
            },
            Some("usb-start-0000000000000001"),
        );
        match hello.response {
            BrokerResponse::Hello(response) => {
                assert_eq!(response.selected_version, "0.0.0-w2");
                assert!(response.capabilities.contains(&"Hello".to_owned()));
            }
            other => panic!("expected Hello response, got {other:?}"),
        }

        let validate_bundle = assert_dispatch(
            BrokerRequest::ValidateBundle,
            "ValidateBundle",
            OperationFields::ValidateBundle {},
            None,
        );
        match validate_bundle.response {
            BrokerResponse::ValidateBundle(response) => assert!(response.valid),
            other => panic!("expected ValidateBundle response, got {other:?}"),
        }

        let export_filter = BrokerAuditFilter {
            env: Some("work".to_owned()),
            operation: Some("Run".to_owned()),
            vm: Some("corp-vm".to_owned()),
            role: None,
            outcome: None,
            severity: None,
        };
        let export_filter_json = serde_json::to_string(&export_filter).expect("serialize filter");
        let export = assert_dispatch(
            BrokerRequest::ExportBrokerAudit(
                d2b_contracts_broker::broker_wire::ExportBrokerAuditRequest {
                    since: Some("2026-01-01T00:00:00Z".to_owned()),
                    filter: Some(export_filter),
                    cursor: None,
                    limit: 256,
                },
            ),
            "ExportBrokerAudit",
            OperationFields::ExportBrokerAudit {
                since: Some("2026-01-01T00:00:00Z".to_owned()),
                filter: Some(export_filter_json),
            },
            None,
        );
        match export.response {
            BrokerResponse::ExportBrokerAudit(response) => {
                assert_eq!(response.entries.len(), 0)
            }
            other => panic!("expected ExportBrokerAudit response, got {other:?}"),
        }

        assert_ack(
            assert_dispatch(
                BrokerRequest::ApplyNftables(
                    d2b_contracts_broker::broker_wire::ApplyNftablesRequest {
                        bundle_nft_intent_ref: BundleOpId::new(intent_id_nft_host()),
                        scope_id: ScopeId::new("host"),
                        desired_hash: Some("fnv1a64:feedfacefeedface".to_owned()),
                        destroy: false,
                        tracing_span_id: Some(TracingSpanId::new("span-nft")),
                    },
                ),
                "ApplyNftables",
                OperationFields::ApplyNftables {
                    bundle_nft_intent_ref: intent_id_nft_host(),
                    scope_id: "host".to_owned(),
                    desired_hash: Some("fnv1a64:feedfacefeedface".to_owned()),
                    destroy: false,
                },
                Some("span-nft"),
            ),
            "ApplyNftables",
        );

        assert_ack(
            assert_dispatch(
                BrokerRequest::ApplyRoute(d2b_contracts_broker::broker_wire::ApplyRouteRequest {
                    bundle_route_intent_ref: BundleOpId::new(intent_id_route_env("work", 0)),
                    scope_id: ScopeId::new("env:work"),
                    zone_uid: d2b_contracts_resource::v3::ResourceUid::parse(
                        "223e4567-e89b-42d3-a456-426614174001",
                    )
                    .unwrap(),
                    network_uid: d2b_contracts_resource::v3::ResourceUid::parse(
                        "323e4567-e89b-42d3-a456-426614174002",
                    )
                    .unwrap(),
                    network_generation: d2b_contracts_resource::v3::ResourceGeneration::new(4)
                        .unwrap(),
                    attachment_generation: d2b_contracts_resource::v3::ResourceGeneration::new(7)
                        .unwrap(),
                    bundle_generation: d2b_contracts_resource::v3::ResourceBundleGenerationId::parse(
                        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    )
                    .unwrap(),
                    destroy: false,
                    tracing_span_id: Some(TracingSpanId::new("span-route")),
                }),
                "ApplyRoute",
                OperationFields::ApplyRoute {
                    bundle_route_intent_ref: intent_id_route_env("work", 0),
                    destination: "0.0.0.0/0".to_owned(),
                    via: None,
                    destroy: false,
                },
                Some("span-route"),
            ),
            "ApplyRoute",
        );

        assert_ack(
            assert_dispatch(
                BrokerRequest::ApplySysctl(d2b_contracts_broker::broker_wire::ApplySysctlRequest {
                    bundle_sysctl_intent_ref: BundleOpId::new(intent_id_sysctl(
                        "work",
                        "nlworktap0",
                        "disable_ipv6",
                    )),
                    scope_id: ScopeId::new("env:work"),
                    zone_uid: d2b_contracts_resource::v3::ResourceUid::parse(
                        "223e4567-e89b-42d3-a456-426614174001",
                    )
                    .unwrap(),
                    network_uid: d2b_contracts_resource::v3::ResourceUid::parse(
                        "323e4567-e89b-42d3-a456-426614174002",
                    )
                    .unwrap(),
                    network_generation: d2b_contracts_resource::v3::ResourceGeneration::new(4)
                        .unwrap(),
                    attachment_generation: d2b_contracts_resource::v3::ResourceGeneration::new(7)
                        .unwrap(),
                    bundle_generation: d2b_contracts_resource::v3::ResourceBundleGenerationId::parse(
                        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    )
                    .unwrap(),
                    destroy: false,
                    tracing_span_id: Some(TracingSpanId::new("span-sysctl")),
                }),
                "ApplySysctl",
                OperationFields::ApplySysctl {
                    bundle_sysctl_intent_ref: intent_id_sysctl(
                        "work",
                        "nlworktap0",
                        "disable_ipv6",
                    ),
                    key: "net.ipv6.conf.nlworktap0.disable_ipv6".to_owned(),
                    destroy: false,
                },
                Some("span-sysctl"),
            ),
            "ApplySysctl",
        );

        assert_ack(
            assert_dispatch(
                BrokerRequest::UpdateHostsFile(
                    d2b_contracts_broker::broker_wire::UpdateHostsFileRequest {
                        bundle_hosts_intent_ref: BundleOpId::new(intent_id_hosts_host()),
                        zone_uid: None,
                        network_uid: None,
                        network_generation: None,
                        attachment_generation: None,
                        bundle_generation: None,
                        destroy: false,
                        tracing_span_id: Some(TracingSpanId::new("span-hosts")),
                    },
                ),
                "UpdateHostsFile",
                OperationFields::UpdateHostsFile {
                    bundle_hosts_intent_ref: intent_id_hosts_host(),
                    destroy: false,
                },
                Some("span-hosts"),
            ),
            "UpdateHostsFile",
        );

        assert_ack(
            assert_dispatch(
                BrokerRequest::ApplyNmUnmanaged(
                    d2b_contracts_broker::broker_wire::ApplyNmUnmanagedRequest {
                        bundle_nm_intent_ref: BundleOpId::new(intent_id_nm_unmanaged_host()),
                        scope_id: ScopeId::new("host"),
                        destroy: false,
                        tracing_span_id: Some(TracingSpanId::new("span-nm")),
                    },
                ),
                "ApplyNmUnmanaged",
                OperationFields::ApplyNmUnmanaged {
                    bundle_nm_intent_ref: intent_id_nm_unmanaged_host(),
                    scope_id: "host".to_owned(),
                    destroy: false,
                },
                Some("span-nm"),
            ),
            "ApplyNmUnmanaged",
        );

        assert_ack(
            assert_dispatch(
                BrokerRequest::PrepareStoreView(
                    d2b_contracts_broker::broker_wire::PrepareStoreViewRequest {
                        vm_id: VmId::new("corp-vm"),
                        tracing_span_id: Some(TracingSpanId::new("span-store-view")),
                    },
                ),
                "PrepareStoreView",
                OperationFields::PrepareStoreView {
                    vm: "corp-vm".to_owned(),
                    generation: 42,
                    hardlink_farm_path: "/var/lib/d2b/vms/corp-vm/store-view".to_owned(),
                    view_root: "/var/lib/d2b/vms/corp-vm/store-view/generations/42/corp-vm-system"
                        .to_owned(),
                },
                Some("span-store-view"),
            ),
            "PrepareStoreView",
        );

        let set_bridge_port_flags = assert_dispatch(
            BrokerRequest::SetBridgePortFlags(
                d2b_contracts_broker::broker_wire::SetBridgePortFlagsRequest {
                    vm_id: VmId::new("corp-vm"),
                    role_id: RoleId::new("lan"),
                    network_tap_context: None,
                    tracing_span_id: Some(TracingSpanId::new("span-bridge-flags")),
                },
            ),
            "SetBridgePortFlags",
            OperationFields::SetBridgePortFlags {
                vm: "corp-vm".to_owned(),
                role: "lan".to_owned(),
                ifname: "tap-corp-vm".to_owned(),
                flags: serde_json::json!({
                    "isolated": true,
                    "neighSuppress": true,
                }),
            },
            Some("span-bridge-flags"),
        );
        match set_bridge_port_flags.response {
            BrokerResponse::SetBridgePortFlags(response) => {
                assert_eq!(response.bridge.as_str(), "nlworkbr0");
                assert_eq!(response.port.as_str(), "tap-corp-vm");
                assert!(response.isolated);
                assert!(response.neigh_suppress);
            }
            other => panic!("expected SetBridgePortFlags response, got {other:?}"),
        }

        assert_ack(
            assert_dispatch(
                BrokerRequest::SetupMountNamespace(
                    d2b_contracts_broker::broker_wire::SetupMountNamespaceRequest {
                        vm_id: VmId::new("corp-vm"),
                        role_id: RoleId::new("ch-runner"),
                        tracing_span_id: Some(TracingSpanId::new("span-mount-ns")),
                    },
                ),
                "SetupMountNamespace",
                OperationFields::SetupMountNamespace {
                    vm: "corp-vm".to_owned(),
                    role: "ch-runner".to_owned(),
                    mount_count: 1,
                    mount_root: "/run/d2b/mountns/corp-vm/ch-runner".to_owned(),
                    mount_view_path: "/run/d2b/mountns/corp-vm/ch-runner/nix/store".to_owned(),
                    source_view_path:
                        "/var/lib/d2b/vms/corp-vm/store-view/generations/42/corp-vm-system"
                            .to_owned(),
                },
                Some("span-mount-ns"),
            ),
            "SetupMountNamespace",
        );

        let open_pidfd = assert_dispatch(
            BrokerRequest::OpenPidfd(d2b_contracts_broker::broker_wire::OpenPidfdRequest {
                vm_id: VmId::new("corp-vm"),
                role_id: RoleId::new("ch-runner"),
                bundle_runner_intent_ref: None,
                pid: 4242,
                expected_start_time_ticks: 123456,
                resource_ref: None,
                resource_uid: None,
                zone_uid: None,
                owner_ref: None,
                provider_ref: None,
                provider_identity: None,
                template_identity: None,
                generation: None,
                runtime_scope: None,
                guest_execution: None,
                tracing_span_id: Some(TracingSpanId::new("span-pidfd")),
            }),
            "OpenPidfd",
            OperationFields::OpenPidfd {
                pid: 4242,
                expected_start_time_ticks: 123456,
            },
            Some("span-pidfd"),
        );
        assert_eq!(open_pidfd.fds.len(), 1);
        match open_pidfd.response {
            BrokerResponse::OpenPidfd(response) => {
                assert_eq!(response.vm_id.as_str(), "corp-vm");
                assert_eq!(response.role_id.as_str(), "ch-runner");
                assert_eq!(response.pid, 4242);
                assert_eq!(response.verified_start_time_ticks, 123456);
            }
            other => panic!("expected OpenPidfd response, got {other:?}"),
        }

        let signal_runner = assert_dispatch(
            BrokerRequest::SignalRunner(d2b_contracts_broker::broker_wire::SignalRunnerRequest {
                vm_id: VmId::new("corp-vm"),
                role_id: RoleId::new("ch-runner"),
                signal: RunnerSignal::Term,
                pid: None,
                expected_start_time_ticks: None,
                resource_ref: None,
                resource_uid: None,
                zone_uid: None,
                owner_ref: None,
                provider_ref: None,
                provider_identity: None,
                template_identity: None,
                generation: None,
                runtime_scope: None,
                guest_execution: None,
                tracing_span_id: Some(TracingSpanId::new("span-signal")),
            }),
            "SignalRunner",
            OperationFields::SignalRunner {
                vm_id: "corp-vm".to_owned(),
                role_id: "ch-runner".to_owned(),
                signal: "term".to_owned(),
            },
            Some("span-signal"),
        );
        match signal_runner.response {
            BrokerResponse::SignalRunner(response) => {
                assert!(response.signaled);
                assert_eq!(response.vm_id.as_str(), "corp-vm");
                assert_eq!(response.role_id.as_str(), "ch-runner");
            }
            other => panic!("expected SignalRunner response, got {other:?}"),
        }

        let spawn_runner = assert_dispatch(
            BrokerRequest::SpawnRunner(d2b_contracts_broker::broker_wire::SpawnRunnerRequest {
                execution_ref: None,
                execution_domain: None,
                user_ref: None,
                guest_execution: None,
                resource_ref: None,
                resource_uid: None,
                zone_uid: None,
                owner_ref: None,
                owner_uid: None,
                provider_ref: None,
                bundle_content_identity: None,
                provider_identity: None,
                template_identity: None,
                generation: None,
                runtime_scope: None,
                activation_input: None,
                sandbox_plan: None,
                workload_identity: None,
                inherited_fd_count: 0,
                vm_id: VmId::new("corp-vm"),
                role_id: RoleId::new("ch-runner"),
                role: RunnerRole::CloudHypervisor,
                bundle_runner_intent_ref: BundleOpId::new(intent_id_legacy_runner(
                    "corp-vm",
                    "ch-runner",
                )),
                runtime_allocations: vec![RunnerAllocation {
                    kind: RunnerAllocationKind::VsockCid,
                    opaque_ref: "cid:42".to_owned(),
                }],
                tracing_span_id: Some(TracingSpanId::new("span-spawn")),
                network_tap_context: None,
            }),
            "SpawnRunner",
            OperationFields::SpawnRunner {
                bundle_runner_intent_ref: intent_id_legacy_runner("corp-vm", "ch-runner"),
                vm_id: "corp-vm".to_owned(),
                role_id: "ch-runner".to_owned(),
                role: RunnerRole::CloudHypervisor.as_str().to_owned(),
                runtime_allocations: vec![RunnerAllocation {
                    kind: RunnerAllocationKind::VsockCid,
                    opaque_ref: "cid:42".to_owned(),
                }],
            },
            Some("span-spawn"),
        );
        assert_eq!(spawn_runner.fds.len(), 1);
        match spawn_runner.response {
            BrokerResponse::SpawnRunner(response) => {
                assert_eq!(response.vm_id.as_str(), "corp-vm");
                assert_eq!(response.role_id.as_str(), "ch-runner");
                assert_eq!(response.role, RunnerRole::CloudHypervisor);
                assert_eq!(response.pid, 4242);
                assert_eq!(response.start_time_ticks, 123456);
            }
            other => panic!("expected SpawnRunner response, got {other:?}"),
        }

        let run_host_install = assert_dispatch(
            BrokerRequest::RunHostInstall(
                d2b_contracts_broker::broker_wire::RunHostInstallRequest {
                    bundle_installer_intent_ref: BundleOpId::new(intent_id_installer_host()),
                    enable: true,
                    start: true,
                    no_start: false,
                    tracing_span_id: Some(TracingSpanId::new("span-install")),
                },
            ),
            "RunHostInstall",
            OperationFields::RunHostInstall {
                bundle_installer_intent_ref: intent_id_installer_host(),
                enable: true,
                start: true,
                no_start: false,
            },
            Some("span-install"),
        );
        match run_host_install.response {
            BrokerResponse::RunHostInstall(response) => {
                assert!(response.installed);
                assert!(response.enabled);
                assert!(response.started);
            }
            other => panic!("expected RunHostInstall response, got {other:?}"),
        }

        let run_migrate = assert_dispatch(
            BrokerRequest::RunMigrate(d2b_contracts_broker::broker_wire::RunMigrateRequest {
                bundle_migrate_intent_ref: BundleOpId::new(intent_id_migrate_host()),
                tracing_span_id: Some(TracingSpanId::new("span-migrate")),
            }),
            "RunMigrate",
            OperationFields::RunMigrate {
                bundle_migrate_intent_ref: intent_id_migrate_host(),
            },
            Some("span-migrate"),
        );
        match run_migrate.response {
            BrokerResponse::RunMigrate(response) => assert_eq!(response.migrated_vm_count, 1),
            other => panic!("expected RunMigrate response, got {other:?}"),
        }

        let run_activation = assert_dispatch(
            BrokerRequest::RunActivation(d2b_contracts_broker::broker_wire::RunActivationRequest {
                bundle_activation_intent_ref: BundleOpId::new(intent_id_activation("corp-vm")),
                mode: ActivationMode::Switch,
                system_artifact_id: None,
                phase: ActivationPhase::MetadataOnly,
                vm: "corp-vm".to_owned(),
                tracing_span_id: Some(TracingSpanId::new("span-activation")),
            }),
            "RunActivation",
            OperationFields::RunActivation {
                bundle_activation_intent_ref: intent_id_activation("corp-vm"),
                mode: "switch".to_owned(),
                vm: "corp-vm".to_owned(),
            },
            Some("span-activation"),
        );
        match run_activation.response {
            BrokerResponse::RunActivation(response) => {
                assert_eq!(response.mode, ActivationMode::Switch);
                assert_eq!(response.vm, "corp-vm");
                assert_eq!(response.generation_number, Some(42));
            }
            other => panic!("expected RunActivation response, got {other:?}"),
        }

        let run_gc = assert_dispatch(
            BrokerRequest::RunGc(d2b_contracts_broker::broker_wire::RunGcRequest {
                bundle_gc_intent_ref: BundleOpId::new(intent_id_gc_host()),
                keep_generations: Some(3),
                tracing_span_id: Some(TracingSpanId::new("span-gc")),
            }),
            "RunGc",
            OperationFields::RunGc {
                bundle_gc_intent_ref: intent_id_gc_host(),
                keep_generations: Some(3),
            },
            Some("span-gc"),
        );
        match run_gc.response {
            BrokerResponse::RunGc(response) => {
                assert_eq!(response.keep_generations, Some(3));
                assert_eq!(response.retained_store_path_count, 1);
            }
            other => panic!("expected RunGc response, got {other:?}"),
        }

        let run_keys_rotate = assert_dispatch(
            BrokerRequest::RunKeysRotate(d2b_contracts_broker::broker_wire::RunKeysRotateRequest {
                bundle_keys_intent_ref: BundleOpId::new(intent_id_keys_rotate("corp-vm")),
                vm: "corp-vm".to_owned(),
                tracing_span_id: Some(TracingSpanId::new("span-keys")),
            }),
            "RunKeysRotate",
            OperationFields::RunKeysRotate {
                bundle_keys_intent_ref: intent_id_keys_rotate("corp-vm"),
                vm: "corp-vm".to_owned(),
            },
            Some("span-keys"),
        );
        match run_keys_rotate.response {
            BrokerResponse::RunKeysRotate(response) => {
                assert_eq!(response.vm, "corp-vm");
                assert_eq!(response.public_key_fingerprint, "SHA256:test-fingerprint");
            }
            other => panic!("expected RunKeysRotate response, got {other:?}"),
        }

        let run_host_key_trust = assert_dispatch(
            BrokerRequest::RunHostKeyTrust(
                d2b_contracts_broker::broker_wire::RunHostKeyTrustRequest {
                    bundle_trust_intent_ref: BundleOpId::new(intent_id_trust("corp-vm")),
                    vm: "corp-vm".to_owned(),
                    tracing_span_id: Some(TracingSpanId::new("span-trust")),
                },
            ),
            "RunHostKeyTrust",
            OperationFields::RunHostKeyTrust {
                bundle_trust_intent_ref: intent_id_trust("corp-vm"),
                vm: "corp-vm".to_owned(),
            },
            Some("span-trust"),
        );
        match run_host_key_trust.response {
            BrokerResponse::RunHostKeyTrust(response) => {
                assert_eq!(response.vm, "corp-vm");
                assert_eq!(response.static_ip, "192.0.2.10");
                assert!(response.updated);
            }
            other => panic!("expected RunHostKeyTrust response, got {other:?}"),
        }

        let run_rotate_known_host = assert_dispatch(
            BrokerRequest::RunRotateKnownHost(
                d2b_contracts_broker::broker_wire::RunRotateKnownHostRequest {
                    bundle_rotate_known_host_intent_ref: BundleOpId::new(
                        intent_id_rotate_known_host("corp-vm"),
                    ),
                    vm: "corp-vm".to_owned(),
                    tracing_span_id: Some(TracingSpanId::new("span-rotate-known-host")),
                },
            ),
            "RunRotateKnownHost",
            OperationFields::RunRotateKnownHost {
                bundle_rotate_known_host_intent_ref: intent_id_rotate_known_host("corp-vm"),
                vm: "corp-vm".to_owned(),
            },
            Some("span-rotate-known-host"),
        );
        match run_rotate_known_host.response {
            BrokerResponse::RunRotateKnownHost(response) => {
                assert_eq!(response.vm, "corp-vm");
                assert_eq!(response.static_ip, "192.0.2.10");
                assert!(response.removed);
            }
            other => panic!("expected RunRotateKnownHost response, got {other:?}"),
        }

        assert_ack(
            assert_dispatch(
                BrokerRequest::UsbipBind(d2b_contracts_broker::broker_wire::UsbipBindRequest {
                    bundle_usbip_bind_intent_ref: BundleOpId::new(
                        d2b_core::bundle_resolver::intent_id_usbip_bind("work", "corp-vm", "1-2.3"),
                    ),
                    tracing_span_id: Some(TracingSpanId::new("usb-start-0000000000000001")),
                }),
                "UsbipBind",
                OperationFields::UsbipBind {
                    bus_id: "1-2.3".to_owned(),
                    vm: "corp-vm".to_owned(),
                    device_identity: Some(UsbAuditDeviceIdentity {
                        vendor_id: Some("1050".to_owned()),
                        product_id: Some("0407".to_owned()),
                        serial_observed: false,
                        serial_correlation: None,
                        previous_serial_correlation: None,
                    }),
                },
                Some("usb-start-0000000000000001"),
            ),
            "UsbipBind",
        );

        assert_ack(
            assert_dispatch(
                BrokerRequest::UsbipUnbind(d2b_contracts_broker::broker_wire::UsbipUnbindRequest {
                    bundle_usbip_bind_intent_ref: BundleOpId::new(
                        d2b_core::bundle_resolver::intent_id_usbip_bind("work", "corp-vm", "1-2.3"),
                    ),
                    preserve_durable_claim: false,
                    tracing_span_id: Some(TracingSpanId::new("usb-stop-0000000000000002")),
                }),
                "UsbipUnbind",
                OperationFields::UsbipUnbind {
                    bus_id: "1-2.3".to_owned(),
                },
                Some("usb-stop-0000000000000002"),
            ),
            "UsbipUnbind",
        );

        assert_ack(
            assert_dispatch(
                BrokerRequest::UsbipProxyReconcile(
                    d2b_contracts_broker::broker_wire::UsbipProxyReconcileRequest {
                        scope_id: ScopeId::new("global"),
                        tracing_span_id: Some(TracingSpanId::new("usb-proxy-0000000000000003")),
                    },
                ),
                "UsbipProxyReconcile",
                OperationFields::UsbipProxyReconcile {},
                Some("usb-proxy-0000000000000003"),
            ),
            "UsbipProxyReconcile",
        );

        assert_ack(
            assert_dispatch(
                BrokerRequest::UsbipBindFirewallRule(
                    d2b_contracts_broker::broker_wire::UsbipBindFirewallRuleRequest {
                        bundle_usbip_firewall_intent_ref: BundleOpId::new(
                            intent_id_usbip_firewall("work", "1-2.3"),
                        ),
                        tracing_span_id: Some(TracingSpanId::new("span-usbip-fw")),
                    },
                ),
                "UsbipBindFirewallRule",
                OperationFields::UsbipBindFirewallRule {
                    bundle_usbip_firewall_intent_ref: intent_id_usbip_firewall("work", "1-2.3"),
                },
                Some("span-usbip-fw"),
            ),
            "UsbipBindFirewallRule",
        );

        let qemu_powerdown = assert_dispatch(
            BrokerRequest::QemuMediaSystemPowerdown(
                d2b_contracts_broker::broker_wire::QemuMediaLifecycleRequest {
                    vm_id: VmId::new("media"),
                    tracing_span_id: Some(TracingSpanId::new("span-qmp-powerdown")),
                },
            ),
            "QemuMediaSystemPowerdown",
            OperationFields::QemuMediaSystemPowerdown {
                vm_id: "media".to_owned(),
                qmp_command: "system_powerdown".to_owned(),
            },
            Some("span-qmp-powerdown"),
        );
        match qemu_powerdown.response {
            BrokerResponse::QemuMediaSystemPowerdown(response) => {
                assert_eq!(
                    response.command,
                    d2b_contracts_broker::broker_wire::QemuMediaLifecycleAction::SystemPowerdown
                );
            }
            other => panic!("expected QemuMediaSystemPowerdown response, got {other:?}"),
        }

        let before_query = capture.lock().expect("capture before query").len();
        let query_context = DispatchAuditContext::from_request(
            &BrokerRequest::QemuMediaQueryStatus(
                d2b_contracts_broker::broker_wire::QemuMediaQueryStatusRequest {
                    vm_id: VmId::new("media"),
                    shutdown_context: true,
                    tracing_span_id: Some(TracingSpanId::new("span-qmp-status")),
                },
            ),
            peer_pid,
            &caller_role,
        )
        .expect("query audit context");
        let query_result = dispatch_request_with_backend(
            BrokerRequest::QemuMediaQueryStatus(
                d2b_contracts_broker::broker_wire::QemuMediaQueryStatusRequest {
                    vm_id: VmId::new("media"),
                    shutdown_context: true,
                    tracing_span_id: Some(TracingSpanId::new("span-qmp-status")),
                },
            ),
            1000,
            caller_gid,
            caller_role.clone(),
            &query_context,
            &config,
            &log,
            Some(&bundle.resolver),
            &backend,
        )
        .expect("query status succeeds without success audit");
        match query_result.response {
            BrokerResponse::QemuMediaQueryStatus(response) => {
                assert_eq!(
                    response.status,
                    d2b_contracts_broker::broker_wire::QemuMediaVmStatus::ConnectionLostDuringShutdown
                );
            }
            other => panic!("expected QemuMediaQueryStatus response, got {other:?}"),
        }
        assert_eq!(
            capture.lock().expect("capture after query").len(),
            before_query,
            "read-only query-status must suppress success audit"
        );

        let qemu_quit = assert_dispatch(
            BrokerRequest::QemuMediaQuit(
                d2b_contracts_broker::broker_wire::QemuMediaLifecycleRequest {
                    vm_id: VmId::new("media"),
                    tracing_span_id: Some(TracingSpanId::new("span-qmp-quit")),
                },
            ),
            "QemuMediaQuit",
            OperationFields::QemuMediaQuit {
                vm_id: "media".to_owned(),
                qmp_command: "quit".to_owned(),
            },
            Some("span-qmp-quit"),
        );
        match qemu_quit.response {
            BrokerResponse::QemuMediaQuit(response) => {
                assert_eq!(
                    response.command,
                    d2b_contracts_broker::broker_wire::QemuMediaLifecycleAction::Quit
                );
            }
            other => panic!("expected QemuMediaQuit response, got {other:?}"),
        }

        assert_ack(
            assert_dispatch(
                BrokerRequest::SeedDnsmasqLease(
                    d2b_contracts_broker::broker_wire::SeedDnsmasqLeaseRequest {
                        vm_id: VmId::new(
                            d2b_contracts_resource::v3::derive_network_child_name(
                                &d2b_contracts_resource::v3::ResourceUid::parse(
                                    "323e4567-e89b-42d3-a456-426614174002",
                                )
                                .unwrap(),
                                "vm",
                            ),
                        ),
                        scope_id: ScopeId::new("env:work"),
                        zone_uid: d2b_contracts_resource::v3::ResourceUid::parse(
                            "223e4567-e89b-42d3-a456-426614174001",
                        )
                        .unwrap(),
                        network_uid: d2b_contracts_resource::v3::ResourceUid::parse(
                            "323e4567-e89b-42d3-a456-426614174002",
                        )
                        .unwrap(),
                        network_generation: d2b_contracts_resource::v3::ResourceGeneration::new(4)
                            .unwrap(),
                        attachment_generation:
                            d2b_contracts_resource::v3::ResourceGeneration::new(7).unwrap(),
                        bundle_generation:
                            d2b_contracts_resource::v3::ResourceBundleGenerationId::parse(
                                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                            )
                            .unwrap(),
                        tracing_span_id: Some(TracingSpanId::new("span-dnsmasq")),
                    },
                ),
                "SeedDnsmasqLease",
                OperationFields::SeedDnsmasqLease {
                    vm_id: d2b_contracts_resource::v3::derive_network_child_name(
                        &d2b_contracts_resource::v3::ResourceUid::parse(
                            "323e4567-e89b-42d3-a456-426614174002",
                        )
                        .unwrap(),
                        "vm",
                    ),
                    scope_id: "env:work".to_owned(),
                },
                Some("span-dnsmasq"),
            ),
            "SeedDnsmasqLease",
        );

        assert_ack(
            assert_dispatch(
                BrokerRequest::BindMountFromHardlinkFarm(
                    d2b_contracts_broker::broker_wire::BindMountFromHardlinkFarmRequest {
                        vm_id: VmId::new("corp-vm"),
                        bundle_store_view_intent_ref: None,
                        tracing_span_id: Some(TracingSpanId::new("span-bind-mount")),
                    },
                ),
                "BindMountFromHardlinkFarm",
                OperationFields::BindMountFromHardlinkFarm {
                    vm_id: "corp-vm".to_owned(),
                    bundle_store_view_intent_ref: None,
                    hardlink_farm_path: "/var/lib/d2b/vms/corp-vm/store-view".to_owned(),
                },
                Some("span-bind-mount"),
            ),
            "BindMountFromHardlinkFarm",
        );

        assert_eq!(
            capture.lock().expect("capture final lock").len(),
            29,
            "expected one typed audit record per live dispatch arm"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn spawn_runner_rejects_invalid_minijail_profile() {
        use d2b_contracts::types::{BundleOpId, RoleId, TracingSpanId, VmId};
        use d2b_contracts_broker::broker_wire::{
            BrokerCallerRole, BrokerRequest, RunnerAllocation, RunnerAllocationKind, RunnerRole,
        };
        use d2b_core::bundle_resolver::intent_id_legacy_runner;

        let root = test_audit_dir("spawn-runner-invalid-minijail");
        let bundle = build_invalid_minijail_test_bundle(&root);
        let config = test_server_config(&root, &bundle.manifest_path);
        let (log, capture) = AuditLog::open_capturing(
            &config.audit_dir,
            Gid::current().as_raw(),
            true,
            config.audit_retention_days,
        )
        .expect("open capturing audit log");
        let backend = FakeDispatchBackend::default();
        let caller_role = BrokerCallerRole::AdminUid { uid: 1000 };
        let caller_gid = Gid::current().as_raw();
        let request =
            BrokerRequest::SpawnRunner(d2b_contracts_broker::broker_wire::SpawnRunnerRequest {
                execution_ref: None,
                execution_domain: None,
                user_ref: None,
                guest_execution: None,
                resource_ref: None,
                resource_uid: None,
                zone_uid: None,
                owner_ref: None,
                owner_uid: None,
                provider_ref: None,
                bundle_content_identity: None,
                provider_identity: None,
                template_identity: None,
                generation: None,
                runtime_scope: None,
                activation_input: None,
                sandbox_plan: None,
                workload_identity: None,
                inherited_fd_count: 0,
                vm_id: VmId::new("corp-vm"),
                role_id: RoleId::new("ch-runner"),
                role: RunnerRole::CloudHypervisor,
                bundle_runner_intent_ref: BundleOpId::new(intent_id_legacy_runner(
                    "corp-vm",
                    "ch-runner",
                )),
                runtime_allocations: vec![RunnerAllocation {
                    kind: RunnerAllocationKind::VsockCid,
                    opaque_ref: "cid:42".to_owned(),
                }],
                tracing_span_id: Some(TracingSpanId::new("span-invalid-spawn")),
                network_tap_context: None,
            });
        let expected_request_fields = request_fields_value(&request).expect("request fields");
        let audit_context = DispatchAuditContext::from_request(&request, 5150, &caller_role)
            .expect("audit context");

        let error = dispatch_request_with_backend(
            request,
            1000,
            caller_gid,
            caller_role.clone(),
            &audit_context,
            &config,
            &log,
            Some(&bundle.resolver),
            &backend,
        )
        .expect_err("invalid minijail profile should be denied");
        match error {
            BrokerError::MinijailValidation { reason } => {
                assert!(reason.contains("uid=0 gid=0"));
                assert!(reason.contains("profile-ch"));
            }
            other => panic!("expected MinijailValidation, got {other:?}"),
        }

        let records = capture.lock().expect("capture lock");
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.operation, "SpawnRunner");
        assert_eq!(record.decision, "denied-refused");
        assert_eq!(record.result, "denied");
        assert_eq!(record.error_kind.as_deref(), Some("minijail-validation"));
        assert_eq!(record.request_fields, expected_request_fields);
        assert_eq!(record.peer_pid, 5150);
        let fields = OperationFields::from_operation_value(
            "SpawnRunner",
            record.operation_fields.clone().expect("operation fields"),
        )
        .expect("deserialize operation fields");
        assert_eq!(
            fields,
            OperationFields::SpawnRunner {
                bundle_runner_intent_ref: intent_id_legacy_runner("corp-vm", "ch-runner"),
                vm_id: "corp-vm".to_owned(),
                role_id: "ch-runner".to_owned(),
                role: RunnerRole::CloudHypervisor.as_str().to_owned(),
                runtime_allocations: vec![RunnerAllocation {
                    kind: RunnerAllocationKind::VsockCid,
                    opaque_ref: "cid:42".to_owned(),
                }],
            }
        );

        let _ = fs::remove_dir_all(&root);
    }

    /// Build a `corp-vm` bundle whose resolved store-view intent points at
    /// tempdir-backed closure + farm paths (rooted under `root`, single
    /// filesystem) so a full `StoreSync` dispatch round-trip runs
    /// unprivileged. `host_generation` controls the resolved generation so
    /// a mismatching wire token can deterministically force a pre-lock
    /// failure. Returns the bundle plus the per-VM hardlink-farm root.
    #[cfg(not(feature = "layer1-bootstrap"))]
    fn store_sync_dispatch_bundle(root: &Path, host_generation: u32) -> (TestBundle, PathBuf) {
        use d2b_core::closures::{ClosureGeneration, ClosureMetadata};
        use d2b_core::manifest_v04::ManifestV04;

        let mut bundle = build_test_bundle(root);

        let store_src = root.join("nix-store-mock");
        fs::create_dir_all(&store_src).expect("create fake nix store");
        let toplevel = store_src.join("aaaaaaaaaaaaaaaa-corp-vm-system");
        fs::create_dir_all(&toplevel).expect("create fake toplevel");
        fs::write(toplevel.join("hello"), "payload").expect("write fake toplevel payload");
        let db_dump = root.join("corp-vm-registration");
        fs::write(&db_dump, "db-dump").expect("write fake db dump");
        let state_dir = root.join("state").join("corp-vm");
        let farm_path = state_dir.join("store-view");
        fs::create_dir_all(&farm_path).expect("create per-vm farm root");

        let closure_path = bundle
            .bundle_path
            .parent()
            .expect("bundle dir")
            .join("closures/corp-vm.json");
        let closure = ClosureMetadata {
            schema_version: "v2".to_owned(),
            vm: "corp-vm".to_owned(),
            toplevel: toplevel.display().to_string(),
            closure_paths: vec![toplevel.display().to_string()],
            db_dump_path: db_dump.display().to_string(),
            declared_runner: "/run/current-system/sw/bin/cloud-hypervisor".to_owned(),
            runner_parity_path: "/run/current-system/sw/bin/cloud-hypervisor".to_owned(),
            runner_parity_ok: true,
            generation: ClosureGeneration {
                host_generation: Some(u64::from(host_generation)),
                vm_generation: Some(host_generation.to_string()),
                source_revision: Some("deadbeef".to_owned()),
                generated_at: Some("2026-01-01T00:00:00Z".to_owned()),
            },
        };
        write_json_file(&closure_path, &closure);

        let mut manifest: ManifestV04 =
            serde_json::from_slice(&fs::read(&bundle.manifest_path).expect("read manifest"))
                .expect("parse manifest");
        manifest
            .vms
            .get_mut("corp-vm")
            .expect("corp-vm manifest entry")
            .state_dir = state_dir.display().to_string();
        write_json_file(&bundle.manifest_path, &manifest);

        bundle.resolver = Arc::new(
            BundleResolver::load_with_policy(
                &bundle.bundle_path,
                &d2b_core::bundle_resolver::BundleVerifyPolicy::for_tests(),
            )
            .expect("reload store-sync dispatch bundle"),
        );
        (bundle, farm_path)
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    fn store_sync_request(
        generation_token: u32,
    ) -> d2b_contracts_broker::broker_wire::BrokerRequest {
        use d2b_contracts::types::{BundleClosureRef, TracingSpanId, VmId};
        use d2b_contracts_broker::broker_wire::{BrokerRequest, StoreSyncRequest};
        use d2b_core::bundle_resolver::intent_id_legacy_store_view;

        BrokerRequest::StoreSync(StoreSyncRequest {
            vm_id: VmId::new("corp-vm"),
            bundle_closure_ref: BundleClosureRef::new(intent_id_legacy_store_view("corp-vm")),
            generation_token,
            tracing_span_id: Some(TracingSpanId::new("span-store-sync")),
        })
    }

    /// W3 success emission must survive the W4 dispatch-arm refactor: the
    /// first (non-fast) sync emits EXACTLY ONE allowed terminal record with
    /// the deferred-cleanup `ok_non_fast_path` shape.
    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn store_sync_dispatch_emits_single_success_record() {
        use crate::ops::store_sync_audit::{
            AuthzOutcome, CleanupReason, CleanupStatus, ErrorStage, SyncStatus,
        };
        use d2b_contracts_broker::broker_wire::BrokerCallerRole;

        let root = test_audit_dir("store-sync-dispatch-success");
        let (bundle, _farm) = store_sync_dispatch_bundle(&root, 7);
        let config = test_server_config(&root, &bundle.manifest_path);
        let (log, capture) = AuditLog::open_capturing(
            &config.audit_dir,
            Gid::current().as_raw(),
            true,
            config.audit_retention_days,
        )
        .expect("open capturing audit log");
        let backend = FakeDispatchBackend::default();
        let caller_role = BrokerCallerRole::AdminUid { uid: 1000 };
        let caller_gid = Gid::current().as_raw();

        let request = store_sync_request(7);
        let audit_context = DispatchAuditContext::from_request(&request, 4242, &caller_role)
            .expect("audit context");
        let before = capture.lock().expect("capture lock before").len();
        let result = dispatch_request_with_backend(
            request,
            1000,
            caller_gid,
            caller_role.clone(),
            &audit_context,
            &config,
            &log,
            Some(&bundle.resolver),
            &backend,
        )
        .expect("store sync succeeds");
        match result.response {
            BrokerResponse::StoreSync(resp) => {
                assert_eq!(resp.vm, "corp-vm");
                assert_eq!(resp.generation_token, 7);
                assert!(!resp.cleanup_deferred);
            }
            other => panic!("expected StoreSync response, got {other:?}"),
        }

        let records = capture.lock().expect("capture lock after");
        assert_eq!(records.len(), before + 1, "exactly one terminal record");
        let record = records[before].clone();
        drop(records);
        assert_eq!(record.operation, "StoreSync");
        assert_eq!(record.decision, "allowed");
        assert_eq!(record.result, "success");
        assert_eq!(record.error_kind, None);
        let fields = match OperationFields::from_operation_value(
            "StoreSync",
            record.operation_fields.clone().expect("operation fields"),
        )
        .expect("deserialize store-sync fields")
        {
            OperationFields::StoreSync(fields) => fields,
            other => panic!("expected StoreSync fields, got {other:?}"),
        };
        fields.validate().expect("signed schema holds");
        assert_eq!(fields.sync_status, SyncStatus::Ok);
        assert_eq!(fields.env.as_deref(), Some("work"));
        assert_eq!(fields.error_stage, ErrorStage::None);
        assert_eq!(fields.cleanup_status, CleanupStatus::Completed);
        assert_eq!(fields.cleanup_reason, CleanupReason::None);
        assert_eq!(fields.authz_outcome, AuthzOutcome::Allow);
        assert!(!fields.fast_path);
        assert_eq!(
            fields.linked_count + fields.skipped_count,
            fields.closure_count
        );

        // ADR 0027 observability export: exactly one StoreSync-only
        // record, projected to the signed allow-list (redaction fields
        // absent), carrying the terminal success shape with the target
        // VM in JSON content (not a Loki label).
        let exported = read_store_sync_export(&config);
        assert_eq!(exported.len(), 1, "exactly one exported record on success");
        let (export_record, export_obj) = &exported[0];
        assert_export_allow_list(export_obj);
        assert_eq!(export_record.target_vm, "corp-vm");
        assert_eq!(export_record.target_env.as_deref(), Some("work"));
        assert_eq!(export_record.vm_id, "corp-vm");
        assert_eq!(export_record.generation_token, 7);
        assert_eq!(export_record.sync_status, SyncStatus::Ok);
        assert_eq!(export_record.error_stage, ErrorStage::None);
        assert_eq!(export_record.cleanup_status, CleanupStatus::Completed);
        assert_eq!(export_record.authz_outcome, AuthzOutcome::Allow);
        assert!(!export_record.fast_path);

        let _ = fs::remove_dir_all(&root);
    }

    /// A second sync of the same closure must take the fast path and still
    /// emit EXACTLY ONE allowed record carrying `skipped_fast_path` +
    /// `fast_path`.
    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn store_sync_dispatch_fast_path_emits_single_skipped_record() {
        use crate::ops::store_sync_audit::{CleanupReason, CleanupStatus, SyncStatus};
        use d2b_contracts_broker::broker_wire::BrokerCallerRole;

        let root = test_audit_dir("store-sync-dispatch-fast-path");
        let (bundle, _farm) = store_sync_dispatch_bundle(&root, 7);
        let config = test_server_config(&root, &bundle.manifest_path);
        let (log, capture) = AuditLog::open_capturing(
            &config.audit_dir,
            Gid::current().as_raw(),
            true,
            config.audit_retention_days,
        )
        .expect("open capturing audit log");
        let backend = FakeDispatchBackend::default();
        let caller_role = BrokerCallerRole::AdminUid { uid: 1000 };
        let caller_gid = Gid::current().as_raw();

        let dispatch_once = || {
            let request = store_sync_request(7);
            let audit_context = DispatchAuditContext::from_request(&request, 4242, &caller_role)
                .expect("audit ctx");
            dispatch_request_with_backend(
                request,
                1000,
                caller_gid,
                caller_role.clone(),
                &audit_context,
                &config,
                &log,
                Some(&bundle.resolver),
                &backend,
            )
            .expect("store sync succeeds")
        };

        // Publish generation 7, then re-sync it (fast path).
        let _ = dispatch_once();
        let before_fast = capture.lock().expect("capture lock").len();
        let _ = dispatch_once();

        let records = capture.lock().expect("capture lock after fast path");
        assert_eq!(
            records.len(),
            before_fast + 1,
            "fast-path re-sync emits exactly one record"
        );
        let record = records[before_fast].clone();
        drop(records);
        assert_eq!(record.operation, "StoreSync");
        assert_eq!(record.decision, "allowed");
        assert_eq!(record.result, "success");
        let fields = match OperationFields::from_operation_value(
            "StoreSync",
            record.operation_fields.clone().expect("operation fields"),
        )
        .expect("deserialize store-sync fields")
        {
            OperationFields::StoreSync(fields) => fields,
            other => panic!("expected StoreSync fields, got {other:?}"),
        };
        fields.validate().expect("signed schema holds");
        assert_eq!(fields.sync_status, SyncStatus::Ok);
        assert!(fields.fast_path);
        assert_eq!(fields.cleanup_status, CleanupStatus::SkippedFastPath);
        assert_eq!(fields.cleanup_reason, CleanupReason::FastPath);
        assert_eq!(fields.linked_count, 0);
        assert_eq!(fields.skipped_count, fields.closure_count);
        assert_eq!(fields.swept_count, 0);

        // ADR 0027 observability export: each terminal attempt exports
        // exactly one record, so the publish + fast-path re-sync produce
        // two lines; the second carries the pure fast-path shape.
        let exported = read_store_sync_export(&config);
        assert_eq!(
            exported.len(),
            2,
            "publish + fast-path re-sync export one record each"
        );
        let (fast_record, fast_obj) = &exported[1];
        assert_export_allow_list(fast_obj);
        assert_eq!(fast_record.sync_status, SyncStatus::Ok);
        assert!(fast_record.fast_path, "second export is the fast path");
        assert_eq!(fast_record.cleanup_status, CleanupStatus::SkippedFastPath);
        assert_eq!(fast_record.cleanup_reason, CleanupReason::FastPath);
        assert_eq!(fast_record.linked_count, 0);
        assert_eq!(fast_record.skipped_count, fast_record.closure_count);

        let _ = fs::remove_dir_all(&root);
    }

    /// A deterministic pre-lock failure (wire generation token does not
    /// match the resolved closure generation) must emit EXACTLY ONE signed
    /// `failed` terminal record (decision = errored), leak no guest
    /// metadata, and NOT produce a duplicate record when the outer
    /// error-audit path runs.
    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn store_sync_dispatch_failure_emits_single_signed_failure_record() {
        use crate::ops::store_sync_audit::{
            AuthzOutcome, CleanupReason, CleanupStatus, ErrorStage, SyncStatus,
        };
        use d2b_contracts_broker::broker_wire::BrokerCallerRole;

        let root = test_audit_dir("store-sync-dispatch-failure");
        // Resolved generation is 7; the wire asks for 8 → GenerationMismatch
        // before lock/filesystem side effects (error_stage = probe).
        let (bundle, farm) = store_sync_dispatch_bundle(&root, 7);
        let config = test_server_config(&root, &bundle.manifest_path);
        let (log, capture) = AuditLog::open_capturing(
            &config.audit_dir,
            Gid::current().as_raw(),
            true,
            config.audit_retention_days,
        )
        .expect("open capturing audit log");
        let backend = FakeDispatchBackend::default();
        let caller_role = BrokerCallerRole::AdminUid { uid: 1000 };
        let caller_gid = Gid::current().as_raw();

        let request = store_sync_request(8);
        let audit_context = DispatchAuditContext::from_request(&request, 4242, &caller_role)
            .expect("audit context");
        let before = capture.lock().expect("capture lock before").len();
        let error = dispatch_request_with_backend(
            request,
            1000,
            caller_gid,
            caller_role.clone(),
            &audit_context,
            &config,
            &log,
            Some(&bundle.resolver),
            &backend,
        )
        .expect_err("generation mismatch must fail");
        match &error {
            BrokerError::StoreSyncFailed {
                error_stage,
                message,
            } => {
                assert_eq!(*error_stage, "store-sync-probe-failed");
                assert!(message.contains("generation"), "message: {message}");
            }
            other => panic!("expected StoreSyncFailed, got {other:?}"),
        }

        let after_dispatch = capture.lock().expect("capture lock after dispatch").len();
        assert_eq!(
            after_dispatch,
            before + 1,
            "failure emits exactly one terminal record"
        );

        let record = {
            let records = capture.lock().expect("capture lock for record");
            records[before].clone()
        };
        assert_eq!(record.operation, "StoreSync");
        assert_eq!(record.decision, "errored");
        assert_eq!(record.result, "error");
        assert_eq!(
            record.error_kind.as_deref(),
            Some("store-sync-probe-failed")
        );
        let fields = match OperationFields::from_operation_value(
            "StoreSync",
            record.operation_fields.clone().expect("operation fields"),
        )
        .expect("deserialize store-sync fields")
        {
            OperationFields::StoreSync(fields) => fields,
            other => panic!("expected StoreSync fields, got {other:?}"),
        };
        fields.validate().expect("signed schema holds for failure");
        assert_eq!(fields.sync_status, SyncStatus::Failed);
        assert_eq!(fields.error_stage, ErrorStage::Probe);
        assert_eq!(fields.cleanup_status, CleanupStatus::NotAttempted);
        assert_eq!(fields.cleanup_reason, CleanupReason::None);
        assert_eq!(fields.authz_outcome, AuthzOutcome::Allow);
        assert!(!fields.fast_path);

        // No guest-served metadata may be planted by a pre-lock failure.
        assert!(
            !farm.join("meta").exists(),
            "pre-lock failure must not write guest metadata"
        );
        assert!(!farm.join("live").exists());
        assert!(!farm.join("state").exists());

        // ADR 0027 observability export: a failed terminal attempt also
        // exports EXACTLY ONE allow-list record (failed shape, classified
        // error_stage, no host-only fields). The export sink is separate
        // from the broker audit log, so the duplicate-suppression on the
        // outer error path does not touch it.
        let exported = read_store_sync_export(&config);
        assert_eq!(exported.len(), 1, "exactly one exported record on failure");
        let (export_record, export_obj) = &exported[0];
        assert_export_allow_list(export_obj);
        assert_eq!(export_record.target_vm, "corp-vm");
        assert_eq!(export_record.sync_status, SyncStatus::Failed);
        assert_eq!(export_record.error_stage, ErrorStage::Probe);
        assert_eq!(export_record.cleanup_status, CleanupStatus::NotAttempted);
        assert_eq!(export_record.cleanup_reason, CleanupReason::None);
        assert_eq!(export_record.authz_outcome, AuthzOutcome::Allow);

        // The outer error-audit path must NOT write a second (duplicate)
        // record: BrokerError::StoreSyncFailed.audit() is a no-op because
        // the terminal record was already emitted in the dispatch arm.
        error
            .audit(
                &log,
                1000,
                caller_gid,
                &CallerRole::AdminUid { uid: 1000 },
                &audit_context,
                Some(&bundle.resolver),
                "StoreSync",
                "corp-vm",
            )
            .expect("outer error audit");
        let after_outer = capture.lock().expect("capture lock after outer").len();
        assert_eq!(
            after_outer,
            before + 1,
            "outer error-audit must not duplicate the terminal StoreSync record"
        );
        // The export is likewise emitted exactly once across the whole
        // failure path (the outer audit no-op cannot re-export).
        assert_eq!(
            read_store_sync_export(&config).len(),
            1,
            "outer error-audit must not duplicate the StoreSync export record"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn store_verify_repair_emits_store_sync_audit_and_export() {
        use crate::ops::store_sync_audit::SyncStatus;
        use d2b_contracts::types::{TracingSpanId, VmId};
        use d2b_contracts_broker::broker_wire::{
            BrokerCallerRole, BrokerRequest, BrokerResponse, StoreVerifyRequest, StoreVerifyStatus,
        };

        let root = test_audit_dir("store-verify-repair-audit");
        let (bundle, farm) = store_sync_dispatch_bundle(&root, 7);
        let config = test_server_config(&root, &bundle.manifest_path);
        let (log, capture) = AuditLog::open_capturing(
            &config.audit_dir,
            Gid::current().as_raw(),
            true,
            config.audit_retention_days,
        )
        .expect("open capturing audit log");
        let backend = FakeDispatchBackend::default();
        let caller_role = BrokerCallerRole::AdminUid { uid: 1000 };
        let caller_gid = Gid::current().as_raw();

        // First publish a clean generation.
        let sync_request = store_sync_request(7);
        let sync_context = DispatchAuditContext::from_request(&sync_request, 4242, &caller_role)
            .expect("sync audit context");
        dispatch_request_with_backend(
            sync_request,
            1000,
            caller_gid,
            caller_role.clone(),
            &sync_context,
            &config,
            &log,
            Some(&bundle.resolver),
            &backend,
        )
        .expect("initial store sync succeeds");

        // Corrupt one existing top-level basename so --repair must run a
        // StoreSync republish and then an exchange repair.
        let live = farm.join("live/aaaaaaaaaaaaaaaa-corp-vm-system");
        fs::remove_dir_all(&live).expect("remove live top-level");
        fs::create_dir_all(&live).expect("create drifted live top-level");
        fs::write(live.join("payload"), b"drifted").expect("write drift");

        let before = capture.lock().expect("capture before verify").len();
        let verify_request = BrokerRequest::StoreVerify(StoreVerifyRequest {
            vm_id: VmId::new("corp-vm"),
            repair: true,
            tracing_span_id: Some(TracingSpanId::new("span-store-verify-repair")),
        });
        let verify_context =
            DispatchAuditContext::from_request(&verify_request, 4243, &caller_role)
                .expect("verify audit context");
        let result = dispatch_request_with_backend(
            verify_request,
            1000,
            caller_gid,
            caller_role,
            &verify_context,
            &config,
            &log,
            Some(&bundle.resolver),
            &backend,
        )
        .expect("store verify repair succeeds");
        match result.response {
            BrokerResponse::StoreVerify(response) => {
                assert_eq!(response.status, StoreVerifyStatus::Repaired);
                assert_eq!(response.repaired, 1);
            }
            other => panic!("expected StoreVerify response, got {other:?}"),
        }

        let records = capture.lock().expect("capture after verify");
        let new_records = &records[before..];
        assert_eq!(
            new_records.len(),
            2,
            "repair writes StoreSync + StoreVerify records"
        );
        assert_eq!(new_records[0].operation, "StoreSync");
        assert_eq!(new_records[1].operation, "StoreVerify");
        let sync_fields = match OperationFields::from_operation_value(
            "StoreSync",
            new_records[0]
                .operation_fields
                .clone()
                .expect("store sync fields"),
        )
        .expect("deserialize repair StoreSync fields")
        {
            OperationFields::StoreSync(fields) => fields,
            other => panic!("expected StoreSync fields, got {other:?}"),
        };
        assert_eq!(sync_fields.sync_status, SyncStatus::Ok);
        assert!(
            !sync_fields.fast_path,
            "repair StoreSync is forced non-fast-path"
        );
        drop(records);

        let exported = read_store_sync_export(&config);
        assert!(
            exported
                .iter()
                .any(|(record, _)| record.generation_token == 7
                    && record.sync_status == SyncStatus::Ok),
            "repair StoreSync should be represented in StoreSync export"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn otel_host_bridge_socket_path_extracts_unix_listen_target() {
        let argv = vec![
            "/run/current-system/sw/bin/socat".to_owned(),
            "-d".to_owned(),
            "-d".to_owned(),
            "UNIX-LISTEN:/run/d2b/otel/host-egress.sock,fork,reuseaddr,mode=0660".to_owned(),
            "EXEC:\"/run/current-system/sw/bin/d2b-ch-vsock-connect \
             /var/lib/d2b/vms/sys-obs/vsock.sock 14317\""
                .to_owned(),
        ];
        let path = otel_host_bridge_socket_path(&argv).expect("extract UNIX-LISTEN target");
        assert_eq!(
            path,
            PathBuf::from("/run/d2b/otel/host-egress.sock"),
            "the socket path is the UNIX-LISTEN target stripped of socat options"
        );
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn otel_host_bridge_socket_path_errors_without_unix_listen() {
        let argv = vec![
            "/run/current-system/sw/bin/socat".to_owned(),
            "-d".to_owned(),
        ];
        assert!(
            otel_host_bridge_socket_path(&argv).is_err(),
            "argv without a UNIX-LISTEN address must be rejected"
        );
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn cleanup_otel_host_bridge_stale_socket_noop_for_other_role() {
        use d2b_contracts_broker::broker_wire::RunnerRole;
        // A non-bridge role must short-circuit Ok before touching argv or
        // the filesystem, even with an otherwise-dangerous argv.
        let argv = vec!["UNIX-LISTEN:/etc/shadow,fork".to_owned()];
        cleanup_otel_host_bridge_stale_socket(&RunnerRole::CloudHypervisor, &argv)
            .expect("non-bridge role is a no-op");
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn cleanup_otel_host_bridge_stale_socket_rejects_path_outside_otel_runtime_dir() {
        use d2b_contracts_broker::broker_wire::RunnerRole;
        // The prefix guard must refuse any socket outside the d2b OTel
        // runtime dir so a malformed bundle can never unlink an arbitrary
        // path before the guarded `cleanup_stale_unix_socket_without_probe`.
        let argv = vec!["UNIX-LISTEN:/tmp/evil.sock,fork".to_owned()];
        assert!(
            cleanup_otel_host_bridge_stale_socket(&RunnerRole::OtelHostBridge, &argv).is_err(),
            "socket path outside /run/d2b/otel/ must be refused"
        );
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn spawn_runner_rejects_otel_host_bridge_role_for_non_bridge_intent() {
        // The broker MUST refuse a request that claims
        // `RunnerRole::OtelHostBridge` while referencing a bundle intent
        // for another role. OtelHostBridge is now represented in the
        // process graph, so the normal closed-set intent matching path
        // catches this before the obs-VM-specific check.
        use d2b_contracts::types::{BundleOpId, RoleId, TracingSpanId, VmId};
        use d2b_contracts_broker::broker_wire::{
            BrokerCallerRole, BrokerRequest, RunnerAllocation, RunnerAllocationKind, RunnerRole,
        };
        use d2b_core::bundle_resolver::intent_id_legacy_runner;

        let root = test_audit_dir("spawn-runner-otel-host-bridge-wrong-vm");
        let bundle = build_test_bundle(&root);
        let config = test_server_config(&root, &bundle.manifest_path);
        let (log, capture) = AuditLog::open_capturing(
            &config.audit_dir,
            Gid::current().as_raw(),
            true,
            config.audit_retention_days,
        )
        .expect("open capturing audit log");
        let backend = FakeDispatchBackend::default();
        let caller_role = BrokerCallerRole::AdminUid { uid: 1000 };
        let caller_gid = Gid::current().as_raw();
        let request =
            BrokerRequest::SpawnRunner(d2b_contracts_broker::broker_wire::SpawnRunnerRequest {
                execution_ref: None,
                execution_domain: None,
                user_ref: None,
                guest_execution: None,
                resource_ref: None,
                resource_uid: None,
                zone_uid: None,
                owner_ref: None,
                owner_uid: None,
                provider_ref: None,
                bundle_content_identity: None,
                provider_identity: None,
                template_identity: None,
                generation: None,
                runtime_scope: None,
                activation_input: None,
                sandbox_plan: None,
                workload_identity: None,
                inherited_fd_count: 0,
                vm_id: VmId::new("corp-vm"),
                role_id: RoleId::new("ch-runner"),
                // Use the existing corp-vm runner intent but assert
                // it as an OtelHostBridge spawn - closed-set
                // validation must refuse because corp-vm != "obs".
                role: RunnerRole::OtelHostBridge,
                bundle_runner_intent_ref: BundleOpId::new(intent_id_legacy_runner(
                    "corp-vm",
                    "ch-runner",
                )),
                runtime_allocations: vec![RunnerAllocation {
                    kind: RunnerAllocationKind::VsockCid,
                    opaque_ref: "cid:42".to_owned(),
                }],
                tracing_span_id: Some(TracingSpanId::new("span-otel-bridge-refusal")),
                network_tap_context: None,
            });
        let audit_context = DispatchAuditContext::from_request(&request, 5152, &caller_role)
            .expect("audit context");

        let error = dispatch_request_with_backend(
            request,
            1000,
            caller_gid,
            caller_role.clone(),
            &audit_context,
            &config,
            &log,
            Some(&bundle.resolver),
            &backend,
        )
        .expect_err("otel host bridge role for non-bridge intent must be denied");
        match error {
            BrokerError::SpawnRunnerIntentMismatch {
                field,
                requested,
                resolved,
            } => {
                assert_eq!(field, "role");
                assert_eq!(requested, "otel-host-bridge");
                assert_eq!(resolved, "cloud-hypervisor");
            }
            other => panic!("expected SpawnRunnerIntentMismatch, got {other:?}"),
        }

        let records = capture.lock().expect("capture lock");
        assert_eq!(
            records.len(),
            0,
            "intent mismatch is rejected before the OtelHostBridge-specific audit branch"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn spawn_runner_rejects_otel_host_bridge_intent_for_non_obs_vm() {
        use d2b_contracts::types::{BundleOpId, RoleId, TracingSpanId, VmId};
        use d2b_contracts_broker::broker_wire::{
            BrokerCallerRole, BrokerRequest, RunnerAllocation, RunnerAllocationKind, RunnerRole,
        };
        use d2b_core::bundle_resolver::{BundleVerifyPolicy, intent_id_legacy_runner};
        use d2b_core::minijail_profile::{CgroupPlacement, WritablePath};
        use d2b_core::processes::{NodeId, ProcessNode, ProcessRole, ProcessesJson};
        use d2b_core::test_support::RoleProfileBuilder;

        let root = test_audit_dir("spawn-runner-otel-host-bridge-non-obs-vm");
        let bundle = build_test_bundle(&root);
        let mut processes: ProcessesJson =
            serde_json::from_slice(&fs::read(&bundle.processes_path).expect("read processes.json"))
                .expect("parse processes.json");
        processes.vms[0].nodes.push(ProcessNode {
            execution_ref: None,
            execution_domain: None,
            user_ref: None,
            id: NodeId("otel-host-bridge".to_owned()),
            role: ProcessRole::OtelHostBridge,
            unit: None,
            binary_path: Some("/nix/store/test-socat/bin/socat".to_owned()),
            argv: vec![
                "d2b-otel-host-bridge".to_owned(),
                "-d".to_owned(),
                "-d".to_owned(),
                "UNIX-LISTEN:/run/d2b/otel/host-egress.sock,fork,reuseaddr,mode=0660"
                    .to_owned(),
                "EXEC:\"/run/current-system/sw/bin/d2b-ch-vsock-connect /var/lib/d2b/vms/corp-vm/vsock.sock 14317\""
                    .to_owned(),
            ],
            env: Vec::new(),
            profile: RoleProfileBuilder::new()
                .with_profile_id("profile-otel-host-bridge")
                .with_uid(1003)
                .with_gid(1003)
                .with_seccomp_policy_ref(Some("w1-otel-host-bridge"))
                .with_writable_paths(vec![WritablePath {
                    path: "/run/d2b/otel".to_owned(),
                    purpose: "host otel bridge runtime".to_owned(),
                }])
                .with_cgroup_placement(CgroupPlacement {
                    subtree: "d2b.slice/corp-vm/otel-host-bridge".to_owned(),
                    controllers: vec!["cpu".to_owned(), "memory".to_owned()],
                    delegated: false,
                })
                .build(),
            readiness: Vec::new(),
            plan_ops: Vec::new(),
                network_interfaces: Vec::new(),
        });
        write_json_file(&bundle.processes_path, &processes);
        let resolver = match try_load_resolver_with_policy(
            &bundle.bundle_path,
            &BundleVerifyPolicy::for_tests(),
        ) {
            BundleSlot::Loaded(resolver) => resolver,
            other => panic!("rewritten bundle should load, got {other:?}"),
        };

        let config = test_server_config(&root, &bundle.manifest_path);
        let (log, capture) = AuditLog::open_capturing(
            &config.audit_dir,
            Gid::current().as_raw(),
            true,
            config.audit_retention_days,
        )
        .expect("open capturing audit log");
        let backend = FakeDispatchBackend::default();
        let caller_role = BrokerCallerRole::AdminUid { uid: 1000 };
        let caller_gid = Gid::current().as_raw();
        let intent_ref = intent_id_legacy_runner("corp-vm", "otel-host-bridge");
        let request =
            BrokerRequest::SpawnRunner(d2b_contracts_broker::broker_wire::SpawnRunnerRequest {
                execution_ref: None,
                execution_domain: None,
                user_ref: None,
                guest_execution: None,
                resource_ref: None,
                resource_uid: None,
                zone_uid: None,
                owner_ref: None,
                owner_uid: None,
                provider_ref: None,
                bundle_content_identity: None,
                provider_identity: None,
                template_identity: None,
                generation: None,
                runtime_scope: None,
                activation_input: None,
                sandbox_plan: None,
                workload_identity: None,
                inherited_fd_count: 0,
                vm_id: VmId::new("corp-vm"),
                role_id: RoleId::new("otel-host-bridge"),
                role: RunnerRole::OtelHostBridge,
                bundle_runner_intent_ref: BundleOpId::new(intent_ref.clone()),
                runtime_allocations: vec![RunnerAllocation {
                    kind: RunnerAllocationKind::VsockCid,
                    opaque_ref: "cid:1000".to_owned(),
                }],
                tracing_span_id: Some(TracingSpanId::new("span-otel-bridge-wrong-vm")),
                network_tap_context: None,
            });
        let audit_context = DispatchAuditContext::from_request(&request, 5153, &caller_role)
            .expect("audit context");

        let error = dispatch_request_with_backend(
            request,
            1000,
            caller_gid,
            caller_role.clone(),
            &audit_context,
            &config,
            &log,
            Some(&resolver),
            &backend,
        )
        .expect_err("otel host bridge intent for non-obs vm must be denied");
        match error {
            BrokerError::OtelHostBridgeIntentInvalid {
                intent_vm,
                expected_obs_vm,
            } => {
                assert_eq!(intent_vm, "corp-vm");
                assert_eq!(expected_obs_vm, "obs");
            }
            other => panic!("expected OtelHostBridgeIntentInvalid, got {other:?}"),
        }

        let records = capture.lock().expect("capture lock");
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.operation, "SpawnRunner");
        assert_eq!(record.decision, "denied-refused");
        assert_eq!(record.result, "denied");
        assert_eq!(
            record.error_kind.as_deref(),
            Some("otel-host-bridge-intent-invalid")
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn signal_runner_returns_no_pidfd_for_unknown_runner() {
        use d2b_contracts::types::{RoleId, VmId};
        use d2b_contracts_broker::broker_wire::{BrokerCallerRole, BrokerRequest, RunnerSignal};

        let root = test_audit_dir("signal-runner-missing-pidfd");
        let bundle = build_test_bundle(&root);
        let config = test_server_config(&root, &bundle.manifest_path);
        let (log, capture) = AuditLog::open_capturing(
            &config.audit_dir,
            Gid::current().as_raw(),
            true,
            config.audit_retention_days,
        )
        .expect("open capturing audit log");
        let backend = FakeDispatchBackend::default();
        let caller_role = BrokerCallerRole::AdminUid { uid: 1000 };
        let caller_gid = Gid::current().as_raw();
        let request =
            BrokerRequest::SignalRunner(d2b_contracts_broker::broker_wire::SignalRunnerRequest {
                vm_id: VmId::new("corp-vm"),
                role_id: RoleId::new("missing"),
                signal: RunnerSignal::Term,
                pid: None,
                expected_start_time_ticks: None,
                resource_ref: None,
                resource_uid: None,
                zone_uid: None,
                owner_ref: None,
                provider_ref: None,
                provider_identity: None,
                template_identity: None,
                generation: None,
                runtime_scope: None,
                guest_execution: None,
                tracing_span_id: None,
            });
        let audit_context = DispatchAuditContext::from_request(&request, 5151, &caller_role)
            .expect("audit context");

        let error = dispatch_request_with_backend(
            request,
            1000,
            caller_gid,
            caller_role,
            &audit_context,
            &config,
            &log,
            Some(&bundle.resolver),
            &backend,
        )
        .expect_err("missing pidfd should fail");
        assert!(matches!(
            error,
            BrokerError::NoPidfd { ref runner_id } if runner_id == "corp-vm:missing"
        ));
        assert_eq!(capture.lock().expect("capture lock").len(), 0);

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn usbip_bind_rejects_device_outside_allowlist() {
        let root = test_audit_dir("usbip-allowlist");
        let mut bundle = build_test_bundle(&root);
        set_usbip_allowlist(
            &mut bundle,
            vec![d2b_core::host::VendorProductPair {
                vendor: 0x1050,
                product: 0x0407,
            }],
        );
        let sysfs_root = root.join("usb-sysfs");
        let device_dir = sysfs_root.join("1-2.3");
        fs::create_dir_all(&device_dir).expect("create fake usb sysfs dir");
        fs::write(device_dir.join("idVendor"), b"abcd\n").expect("write fake vendor id");
        fs::write(device_dir.join("idProduct"), b"1234\n").expect("write fake product id");
        fs::write(device_dir.join("busnum"), b"1\n").expect("write fake bus number");
        fs::write(device_dir.join("devnum"), b"7\n").expect("write fake device number");
        fs::write(device_dir.join("devpath"), b"2.3\n").expect("write fake port path");

        let intent = find_usbip_bind_intent_for(&bundle.resolver, "corp-vm", "1-2.3")
            .expect("bundle usbip bind intent");
        let err = enforce_usbip_allowlist(&intent, &sysfs_root)
            .expect_err("device outside allowlist must be rejected");
        match err {
            BrokerError::UsbipDeviceNotAllowed {
                busid,
                vendor,
                product,
            } => {
                assert_eq!(busid, "1-2.3");
                assert_eq!(vendor, 0xabcd);
                assert_eq!(product, 0x1234);
            }
            other => panic!("expected UsbipDeviceNotAllowed, got {other:?}"),
        }

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn usbip_bind_rejects_missing_allowlist_as_required_policy() {
        let root = test_audit_dir("usbip-missing-allowlist");
        let mut bundle = build_test_bundle(&root);
        set_usbip_allowlist(&mut bundle, Vec::new());
        let sysfs_root = root.join("usb-sysfs");
        let device_dir = sysfs_root.join("1-2.3");
        fs::create_dir_all(&device_dir).expect("create fake usb sysfs dir");
        fs::write(device_dir.join("idVendor"), b"1050\n").expect("write fake vendor id");
        fs::write(device_dir.join("idProduct"), b"0407\n").expect("write fake product id");
        fs::write(device_dir.join("busnum"), b"1\n").expect("write fake bus number");
        fs::write(device_dir.join("devnum"), b"7\n").expect("write fake device number");
        fs::write(device_dir.join("devpath"), b"2.3\n").expect("write fake port path");

        let intent = find_usbip_bind_intent_for(&bundle.resolver, "corp-vm", "1-2.3")
            .expect("bundle usbip bind intent");
        let err = enforce_usbip_allowlist(&intent, &sysfs_root)
            .expect_err("missing required allowlist must fail closed");
        match err {
            BrokerError::UsbipPolicyMismatch { busid, reason } => {
                assert_eq!(busid, "1-2.3");
                assert!(reason.contains("allowlist"));
            }
            other => panic!("expected UsbipPolicyMismatch, got {other:?}"),
        }

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn usbip_bind_rejects_topology_mismatch_as_required_policy() {
        let root = test_audit_dir("usbip-topology-policy");
        let mut bundle = build_test_bundle(&root);
        set_usbip_allowlist(
            &mut bundle,
            vec![d2b_core::host::VendorProductPair {
                vendor: 0x1050,
                product: 0x0407,
            }],
        );
        let sysfs_root = root.join("usb-sysfs");
        let device_dir = sysfs_root.join("1-2.3");
        fs::create_dir_all(&device_dir).expect("create fake usb sysfs dir");
        fs::write(device_dir.join("idVendor"), b"1050\n").expect("write fake vendor id");
        fs::write(device_dir.join("idProduct"), b"0407\n").expect("write fake product id");
        fs::write(device_dir.join("busnum"), b"1\n").expect("write fake bus number");
        fs::write(device_dir.join("devnum"), b"7\n").expect("write fake device number");
        fs::write(device_dir.join("devpath"), b"2.4\n").expect("write fake mismatched port path");

        let intent = find_usbip_bind_intent_for(&bundle.resolver, "corp-vm", "1-2.3")
            .expect("bundle usbip bind intent");
        let err = enforce_usbip_allowlist(&intent, &sysfs_root)
            .expect_err("topology mismatch must fail closed as policy");
        match &err {
            BrokerError::UsbipPolicyMismatch { busid, reason } => {
                assert_eq!(busid, "1-2.3");
                assert!(reason.contains("topology"));
            }
            other => panic!("expected UsbipPolicyMismatch, got {other:?}"),
        }

        let BrokerResponse::Error(response) = err.into_response() else {
            panic!("expected broker error response");
        };
        let rendered = format!("{} {}", response.message, response.action);
        assert!(response.kind.contains("PolicyMismatch"));
        assert!(
            rendered
                .split_whitespace()
                .any(d2b_contracts_resource::v3::is_canonical_digest)
        );
        assert!(!rendered.contains("1-2.3"), "{rendered}");
        assert!(!rendered.contains("/sys/"), "{rendered}");

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn usb_broker_ipc_refuses_non_daemon_so_peercred_before_dispatch() {
        use d2b_contracts::types::{BundleOpId, ScopeId};
        use d2b_contracts_broker::broker_wire::{
            BrokerCallerRole, BrokerRequestEnvelope, UsbipBindFirewallRuleRequest,
            UsbipBindRequest, UsbipProxyReconcileRequest, UsbipUnbindRequest,
        };
        use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
        use nix::unistd::Uid;
        use std::os::fd::AsRawFd;
        use std::sync::Mutex;

        let root = test_audit_dir("usb-peercred-refused");
        fs::create_dir_all(&root).expect("create audit test dir");
        let actual_uid = Uid::current().as_raw();
        let caller_gid = Gid::current().as_raw();
        let configured_daemon_uid = if actual_uid == 0 { 1 } else { 0 };
        let mut config = test_server_config(&root, &root.join("unused-bundle.json"));
        config.test_mode = false;
        config.d2bd_uid = configured_daemon_uid;
        let log = AuditLog::open(
            &config.audit_dir,
            Gid::current().as_raw(),
            true,
            config.audit_retention_days,
        )
        .expect("open audit log");
        let limiter = Arc::new(Mutex::new(IpcRateLimiter::new(64)));

        let requests = vec![
            BrokerRequest::UsbipBind(UsbipBindRequest {
                bundle_usbip_bind_intent_ref: BundleOpId::new(
                    "usbip-bind:env:work:vm:corp-vm:bus:1-2.3",
                ),
                tracing_span_id: None,
            }),
            BrokerRequest::UsbipUnbind(UsbipUnbindRequest {
                bundle_usbip_bind_intent_ref: BundleOpId::new(
                    "usbip-bind:env:work:vm:corp-vm:bus:1-2.3",
                ),
                preserve_durable_claim: false,
                tracing_span_id: None,
            }),
            BrokerRequest::UsbipBindFirewallRule(UsbipBindFirewallRuleRequest {
                bundle_usbip_firewall_intent_ref: BundleOpId::new("usbip-fw:env:work:bus:1-2.3"),
                tracing_span_id: None,
            }),
            BrokerRequest::UsbipProxyReconcile(UsbipProxyReconcileRequest {
                scope_id: ScopeId::new("env:work"),
                tracing_span_id: None,
            }),
        ];
        let mut operations = Vec::new();

        for request in requests {
            let operation = request.op_name();
            operations.push(operation);
            let envelope = BrokerRequestEnvelope {
                request,
                caller_role: BrokerCallerRole::AdminUid {
                    uid: configured_daemon_uid,
                },
                // Ignored because config.test_mode=false: the broker must use the
                // kernel SO_PEERCRED uid, not a caller-supplied envelope field.
                test_peer_uid: Some(configured_daemon_uid),
                audit_join: None,
            };
            let (client, server) = socketpair(
                AddressFamily::Unix,
                SockType::SeqPacket,
                None,
                SockFlag::SOCK_CLOEXEC,
            )
            .expect("socketpair");
            crate::protocol::send_json_frame(client.as_raw_fd(), &envelope)
                .expect("send broker request");
            handle_connection(server, &config, &log, None, None, &limiter)
                .expect("handle refused peer");
            let response = crate::protocol::recv_json_frame::<BrokerResponse>(client.as_raw_fd());
            assert!(
                matches!(
                    response,
                    Err(ref error) if error.kind() == io::ErrorKind::ConnectionReset
                ) || matches!(response, Ok(None)),
                "unauthenticated peers must be closed before request decoding: {response:?}"
            );
        }

        let audit = fs::read_to_string(log.current_daily_path()).expect("read audit log");
        for _operation in operations {
            assert!(audit.contains(r#""op":"PeerAuthentication""#), "{audit}");
        }
        assert_eq!(
            audit
                .matches(r#""disposition":"peer-refused-before-decode""#)
                .count(),
            4,
            "{audit}"
        );
        assert!(
            audit.contains(&format!("\"caller_uid\":{actual_uid}")),
            "{audit}"
        );
        assert!(
            audit.contains(&format!("\"caller_gid\":{caller_gid}")),
            "{audit}"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn usb_broker_ipc_validation_rejects_traversal_and_oversized_inputs() {
        use d2b_contracts::types::{BundleOpId, ScopeId};
        use d2b_contracts_broker::broker_wire::{
            ModprobeIfAllowedRequest, UsbipBindFirewallRuleRequest, UsbipBindRequest,
            UsbipProxyReconcileRequest, UsbipUnbindRequest,
        };

        let cases = vec![
            (
                BrokerRequest::UsbipBind(UsbipBindRequest {
                    bundle_usbip_bind_intent_ref: BundleOpId::new(
                        "usbip-bind:env:work:vm:corp-vm:bus:../1-2",
                    ),
                    tracing_span_id: None,
                }),
                "UsbipBind",
                "invalid-bundle-op-id",
            ),
            (
                BrokerRequest::UsbipUnbind(UsbipUnbindRequest {
                    bundle_usbip_bind_intent_ref: BundleOpId::new(
                        "usbip-bind:env:work:vm:corp-vm:bus:1-2/serial",
                    ),
                    preserve_durable_claim: false,
                    tracing_span_id: None,
                }),
                "UsbipUnbind",
                "invalid-bundle-op-id",
            ),
            (
                BrokerRequest::ModprobeIfAllowed(ModprobeIfAllowedRequest {
                    module_name: "../usbip-host".to_owned(),
                    tracing_span_id: None,
                }),
                "ModprobeIfAllowed",
                "invalid-module-name",
            ),
            (
                BrokerRequest::ModprobeIfAllowed(ModprobeIfAllowedRequest {
                    module_name: "x".repeat(MAX_MODULE_NAME_LEN + 1),
                    tracing_span_id: None,
                }),
                "ModprobeIfAllowed",
                "module-name-too-long",
            ),
            (
                BrokerRequest::UsbipProxyReconcile(UsbipProxyReconcileRequest {
                    scope_id: ScopeId::new("../global"),
                    tracing_span_id: None,
                }),
                "UsbipProxyReconcile",
                "invalid-scope-id",
            ),
            (
                BrokerRequest::UsbipBindFirewallRule(UsbipBindFirewallRuleRequest {
                    bundle_usbip_firewall_intent_ref: BundleOpId::new(
                        "usbip-fw:env:work:bus:../1-2",
                    ),
                    tracing_span_id: None,
                }),
                "UsbipBindFirewallRule",
                "invalid-bundle-op-id",
            ),
        ];

        for (request, expected_operation, expected_reason) in cases {
            match validate_broker_request(&request) {
                Err(BrokerError::RequestValidation { operation, reason }) => {
                    assert_eq!(operation, expected_operation);
                    assert_eq!(reason, expected_reason);
                }
                other => {
                    panic!("expected RequestValidation for {expected_operation}, got {other:?}")
                }
            }
        }
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn usb_broker_ipc_validation_is_shape_only_not_authorization() {
        use d2b_contracts::types::{BundleOpId, ScopeId};
        use d2b_contracts_broker::broker_wire::{
            UsbipBindFirewallRuleRequest, UsbipBindRequest, UsbipProxyReconcileRequest,
        };

        let requests = [
            BrokerRequest::UsbipBind(UsbipBindRequest {
                bundle_usbip_bind_intent_ref: BundleOpId::new(
                    "usbip-bind:env:not-in-this-bundle:vm:not-in-this-bundle:bus:1-2.3",
                ),
                tracing_span_id: None,
            }),
            BrokerRequest::UsbipProxyReconcile(UsbipProxyReconcileRequest {
                scope_id: ScopeId::new("env:not-in-this-bundle"),
                tracing_span_id: None,
            }),
            BrokerRequest::UsbipBindFirewallRule(UsbipBindFirewallRuleRequest {
                bundle_usbip_firewall_intent_ref: BundleOpId::new(
                    "usbip-fw:env:not-in-this-bundle:bus:1-2.3",
                ),
                tracing_span_id: None,
            }),
        ];

        for request in requests {
            validate_broker_request(&request).expect(
                "broker IPC validation must remain shape-only; bundle/lifecycle authorization is enforced by daemon classification plus resolver dispatch",
            );
        }
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn tap_create_validation_binds_every_identity_component_before_dispatch() {
        use d2b_contracts::types::{BundleOpId, RoleId, VmId};
        use d2b_contracts_broker::broker_wire::CreatePersistentTapRequest;
        use d2b_contracts_resource::v3::{
            ResourceBundleGenerationId, ResourceGeneration, ResourceUid,
        };

        let zone_uid =
            ResourceUid::parse("223e4567-e89b-42d3-a456-426614174001").expect("zone uid");
        let network_uid =
            ResourceUid::parse("323e4567-e89b-42d3-a456-426614174002").expect("network uid");
        let attachment_id =
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").expect("attachment uid");
        let role_id = RoleId::new("runner-lan");
        let bundle_generation = ResourceBundleGenerationId::parse(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .expect("bundle generation");
        let admitted_interface_names = vec![
            d2b_contracts_resource::v3::derive_network_ifname(
                &zone_uid,
                &network_uid,
                d2b_contracts_resource::v3::NetworkIfRole::LanBridge,
                None,
            )
            .unwrap(),
            d2b_contracts_resource::v3::derive_network_ifname(
                &zone_uid,
                &network_uid,
                d2b_contracts_resource::v3::NetworkIfRole::WorkloadGuestTap,
                Some(&attachment_id),
            )
            .unwrap(),
        ];
        let request = CreatePersistentTapRequest {
            role_id: role_id.clone(),
            vm_id: VmId::new("corp-vm"),
            bundle_tap_intent_ref: BundleOpId::new(
                d2b_core::bundle_resolver::intent_id_network_tap(
                    &zone_uid,
                    &network_uid,
                    &attachment_id,
                    ResourceGeneration::new(4).unwrap(),
                    ResourceGeneration::new(7).unwrap(),
                    &bundle_generation,
                    role_id.as_str(),
                    "corp-vm",
                ),
            ),
            attachment_id: attachment_id.clone(),
            network_generation: ResourceGeneration::new(4).unwrap(),
            attachment_generation: ResourceGeneration::new(7).unwrap(),
            zone_uid: zone_uid.clone(),
            network_uid: network_uid.clone(),
            bundle_generation: bundle_generation.clone(),
            admitted_interface_names: admitted_interface_names.clone(),
            tracing_span_id: None,
        };
        assert!(
            validate_broker_request(&BrokerRequest::CreatePersistentTap(request.clone())).is_ok()
        );

        let cases = [
            (
                "zone",
                CreatePersistentTapRequest {
                    zone_uid: ResourceUid::parse("423e4567-e89b-42d3-a456-426614174003").unwrap(),
                    ..request.clone()
                },
            ),
            (
                "network",
                CreatePersistentTapRequest {
                    network_uid: ResourceUid::parse("523e4567-e89b-42d3-a456-426614174004")
                        .unwrap(),
                    ..request.clone()
                },
            ),
            (
                "attachment",
                CreatePersistentTapRequest {
                    attachment_id: ResourceUid::parse("623e4567-e89b-42d3-a456-426614174005")
                        .unwrap(),
                    ..request.clone()
                },
            ),
            (
                "network-generation",
                CreatePersistentTapRequest {
                    network_generation: ResourceGeneration::new(5).unwrap(),
                    ..request.clone()
                },
            ),
            (
                "attachment-generation",
                CreatePersistentTapRequest {
                    attachment_generation: ResourceGeneration::new(8).unwrap(),
                    ..request.clone()
                },
            ),
            (
                "bundle-generation",
                CreatePersistentTapRequest {
                    bundle_generation: ResourceBundleGenerationId::parse(
                        "sha256:1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    )
                    .unwrap(),
                    ..request.clone()
                },
            ),
            (
                "role",
                CreatePersistentTapRequest {
                    role_id: RoleId::new("runner-uplink"),
                    ..request.clone()
                },
            ),
            (
                "admitted-interfaces",
                CreatePersistentTapRequest {
                    admitted_interface_names: Vec::new(),
                    ..request.clone()
                },
            ),
        ];
        for (field, swapped) in cases {
            assert!(
                matches!(
                    validate_broker_request(&BrokerRequest::CreatePersistentTap(swapped)),
                    Err(BrokerError::RequestValidation {
                        operation: "CreatePersistentTap",
                        reason: "network-admission-mismatch",
                    })
                ),
                "swapped {field} identity must be refused"
            );
        }
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn tap_fd_validation_requires_the_same_complete_identity() {
        use d2b_contracts::types::{BundleOpId, RoleId, VmId};
        use d2b_contracts_broker::broker_wire::CreateTapFdRequest;
        use d2b_contracts_resource::v3::{
            ResourceBundleGenerationId, ResourceGeneration, ResourceUid,
        };

        let zone_uid =
            ResourceUid::parse("223e4567-e89b-42d3-a456-426614174001").expect("zone uid");
        let network_uid =
            ResourceUid::parse("323e4567-e89b-42d3-a456-426614174002").expect("network uid");
        let attachment_id =
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").expect("attachment uid");
        let role_id = RoleId::new("runner-lan");
        let network_generation = ResourceGeneration::new(4).unwrap();
        let attachment_generation = ResourceGeneration::new(7).unwrap();
        let bundle_generation = ResourceBundleGenerationId::parse(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        let admitted_interface_names = vec![
            d2b_contracts_resource::v3::derive_network_ifname(
                &zone_uid,
                &network_uid,
                d2b_contracts_resource::v3::NetworkIfRole::LanBridge,
                None,
            )
            .unwrap(),
            d2b_contracts_resource::v3::derive_network_ifname(
                &zone_uid,
                &network_uid,
                d2b_contracts_resource::v3::NetworkIfRole::WorkloadGuestTap,
                Some(&attachment_id),
            )
            .unwrap(),
        ];
        let request = CreateTapFdRequest {
            role_id: role_id.clone(),
            vm_id: VmId::new("corp-vm"),
            bundle_tap_intent_ref: BundleOpId::new(
                d2b_core::bundle_resolver::intent_id_network_tap(
                    &zone_uid,
                    &network_uid,
                    &attachment_id,
                    network_generation,
                    attachment_generation,
                    &bundle_generation,
                    role_id.as_str(),
                    "corp-vm",
                ),
            ),
            attachment_id,
            network_generation,
            attachment_generation,
            zone_uid,
            network_uid,
            bundle_generation,
            admitted_interface_names,
            tracing_span_id: None,
        };
        assert!(validate_broker_request(&BrokerRequest::CreateTapFd(request)).is_ok());
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn usb_broker_public_errors_are_fail_secure() {
        let sensitive = [
            BrokerError::LiveHandler(
                "read USB identity for bus_id=1-2.3 at /sys/bus/usb/devices/1-2.3/idVendor failed: serial ABC"
                    .to_owned(),
            ),
            BrokerError::BundleTampered {
                path: "/var/lib/d2b/current-bundle/manifest.json".to_owned(),
                reason: "mode 0666".to_owned(),
            },
            BrokerError::BundleResolverUnavailable,
            BrokerError::BundleIntentMissing {
                kind: "usbip-bind",
                intent_id: "vm=corp-vm bus=1-2.3".to_owned(),
            },
            BrokerError::UsbipDeviceNotAllowed {
                busid: "1-2.3".to_owned(),
                vendor: 0xabcd,
                product: 0x1234,
            },
            BrokerError::UsbipPolicyMismatch {
                busid: "1-2.3".to_owned(),
                reason: "observed physical topology does not match the declaration",
            },
            BrokerError::PeerCredentialRefused {
                operation: "UsbipBind",
            },
        ];

        for error in sensitive {
            let BrokerResponse::Error(response) = error.into_response() else {
                panic!("expected broker error response");
            };
            let rendered = format!("{} {}", response.message, response.action);
            assert!(!rendered.contains("/sys/"), "{rendered}");
            assert!(
                !rendered.contains("/var/lib/d2b/current-bundle"),
                "{rendered}"
            );
            assert!(!rendered.contains("1-2.3"), "{rendered}");
            assert!(!rendered.contains("abcd"), "{rendered}");
            assert!(!rendered.contains("1234"), "{rendered}");
            assert!(!rendered.contains("ABC"), "{rendered}");
        }
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn usb_audit_identity_keeps_vid_pid_and_redacts_raw_serial() {
        let identity = usb_audit_device_identity(
            (0x1050, 0x0407),
            Some("serial-should-never-serialize"),
            None,
        );

        assert_eq!(identity.vendor_id.as_deref(), Some("1050"));
        assert_eq!(identity.product_id.as_deref(), Some("0407"));
        assert!(identity.serial_observed);
        assert_eq!(identity.serial_correlation, None);
        assert_eq!(identity.previous_serial_correlation, None);

        let encoded = serde_json::to_string(&identity).expect("audit identity serializes");
        assert!(encoded.contains("1050"));
        assert!(encoded.contains("0407"));
        assert!(encoded.contains("serialObserved"));
        assert!(!encoded.contains("serial-should-never-serialize"));
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn usb_audit_identity_uses_deterministic_hmac_serial_correlation() {
        let keyring = UsbAuditSerialHmacKeyring {
            current: UsbAuditSerialHmacKey {
                slot: UsbAuditSerialHmacKeySlot::Current,
                key_id: "audit-key-v1".to_owned(),
                key: b"0123456789abcdef0123456789abcdef".to_vec(),
            },
            previous: None,
        };
        let left = usb_audit_device_identity((0x1050, 0x0407), Some("serial-a"), Some(&keyring))
            .serial_correlation
            .expect("serial correlation present");
        let same = usb_audit_device_identity((0x1050, 0x0407), Some("serial-a"), Some(&keyring))
            .serial_correlation
            .expect("serial correlation present");
        let right = usb_audit_device_identity((0x1050, 0x0407), Some("serial-b"), Some(&keyring))
            .serial_correlation
            .expect("serial correlation present");

        assert_eq!(left.key_id, "audit-key-v1");
        assert_eq!(left, same);
        assert_ne!(left.hmac_sha256, right.hmac_sha256);
        assert_eq!(left.hmac_sha256.len(), 64);
        assert!(
            left.hmac_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        );
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn usb_audit_identity_emits_current_and_previous_key_correlations() {
        let keyring = UsbAuditSerialHmacKeyring {
            current: UsbAuditSerialHmacKey {
                slot: UsbAuditSerialHmacKeySlot::Current,
                key_id: "audit-key-current".to_owned(),
                key: b"current-current-current-current-32".to_vec(),
            },
            previous: Some(UsbAuditSerialHmacKey {
                slot: UsbAuditSerialHmacKeySlot::Previous,
                key_id: "audit-key-previous".to_owned(),
                key: b"fedcba9876543210fedcba9876543210".to_vec(),
            }),
        };

        let identity =
            usb_audit_device_identity((0x1050, 0x0407), Some("same-serial"), Some(&keyring));
        let current = identity
            .serial_correlation
            .expect("current correlation present");
        let previous = identity
            .previous_serial_correlation
            .expect("previous correlation present");

        assert_eq!(current.key_id, "audit-key-current");
        assert_eq!(previous.key_id, "audit-key-previous");
        assert_ne!(current.hmac_sha256, previous.hmac_sha256);
        assert_eq!(current.hmac_sha256.len(), 64);
        assert_eq!(previous.hmac_sha256.len(), 64);
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn usb_audit_rotation_event_is_scrubbed_and_bounded() {
        let keyring = UsbAuditSerialHmacKeyring {
            current: UsbAuditSerialHmacKey {
                slot: UsbAuditSerialHmacKeySlot::Current,
                key_id: "audit-key-current".to_owned(),
                key: b"current-secret-material-never-log".to_vec(),
            },
            previous: Some(UsbAuditSerialHmacKey {
                slot: UsbAuditSerialHmacKeySlot::Previous,
                key_id: "audit-key-previous".to_owned(),
                key: b"previous-secret-material-never-log".to_vec(),
            }),
        };

        let audit = usb_serial_correlation_key_rotation_audit(&keyring)
            .expect("previous slot opens a rotation window");
        assert_eq!(audit.previous_key_id, "audit-key-previous");
        assert_eq!(audit.current_key_id, "audit-key-current");
        assert_eq!(audit.active_key_count, 2);
        assert_eq!(audit.grace_window_seconds, 30 * 24 * 60 * 60);
        assert_eq!(audit.correlation_version, "d2b-usb-audit-serial-v1");

        let encoded = serde_json::to_value(OperationFields::UsbSerialCorrelationKeyRotate(audit))
            .expect("rotation event serializes");
        let obj = encoded.as_object().expect("object fields");
        let observed: BTreeSet<&str> = obj.keys().map(String::as_str).collect();
        assert_eq!(
            observed,
            [
                "activeKeyCount",
                "correlationVersion",
                "currentKeyId",
                "graceWindowSeconds",
                "previousKeyId",
            ]
            .into_iter()
            .collect()
        );
        let rendered = encoded.to_string();
        assert!(rendered.contains("audit-key-current"));
        assert!(rendered.contains("audit-key-previous"));
        assert!(!rendered.contains("secret-material"));
        assert!(!rendered.contains("key_hex"));
        assert!(!rendered.contains("same-serial"));
        assert!(!rendered.contains("1-2.3"));
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn usbip_bind_audit_failure_rolls_back_backend_bind_and_acl() {
        use d2b_contracts_broker::broker_wire::{BrokerCallerRole, BrokerRequest};

        let root = test_audit_dir("usbip-bind-audit-failure-rollback");
        let bundle = build_test_bundle(&root);
        let config = test_server_config(&root, &bundle.manifest_path);
        let _usb_sysfs_guard = usb_sysfs_test_lock();
        let _ = take_test_usbip_backend_acl_events();
        prepare_test_usb_sysfs_device("1050", "0407", "2.3");

        let log = AuditLog::open_with_write_limit(
            &config.audit_dir,
            Gid::current().as_raw(),
            true,
            config.audit_retention_days,
            0,
        )
        .expect("open rate-limited audit log");
        let backend = FakeDispatchBackend::default();
        let caller_role = BrokerCallerRole::AdminUid { uid: 1000 };
        let caller_gid = Gid::current().as_raw();
        let intent_id = d2b_core::bundle_resolver::intent_id_usbip_bind("work", "corp-vm", "1-2.3");
        let request =
            BrokerRequest::UsbipBind(d2b_contracts_broker::broker_wire::UsbipBindRequest {
                bundle_usbip_bind_intent_ref: BundleOpId::new(intent_id.as_str()),
                tracing_span_id: None,
            });
        let audit_context = DispatchAuditContext::from_request(&request, 4242, &caller_role)
            .expect("audit context");

        let result = dispatch_request_with_backend(
            request,
            1000,
            caller_gid,
            caller_role,
            &audit_context,
            &config,
            &log,
            Some(&bundle.resolver),
            &backend,
        )
        .expect("privileged audit is never rate limited");
        assert_eq!(
            backend.take_usbip_events(),
            vec![FakeUsbipEvent::Bind { intent_id }],
            "privileged success remains durable despite the unprivileged write limit"
        );
        assert_eq!(
            take_test_usbip_backend_acl_events(),
            vec![TestUsbipBackendAclEvent::Grant { uid: 1002 }],
            "successful bind retains its backend ACL"
        );

        let audit = fs::read_to_string(log.current_daily_path()).expect("read audit log");
        assert!(
            audit.contains(r#""operation":"UsbipBind""#),
            "privileged terminal record must be present: {audit}"
        );
        let _ = result;

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn usbip_bind_acl_grant_failure_releases_lock_after_successful_rollback_unbind() {
        let root = test_audit_dir("usbip-bind-acl-grant-failure-lock-release");
        let bundle = build_test_bundle(&root);
        let intent = test_usbip_intent_with_lock(&root, &bundle);
        crate::ops::usbip_lock::acquire_lock(
            &intent.lock_path,
            &intent.vm_name,
            nix::unistd::Uid::current().as_raw(),
            nix::unistd::Gid::current().as_raw(),
        )
        .expect("seed post-bind lock");
        let backend = FakeDispatchBackend::default();

        let error = rollback_usbip_bind_after_acl_grant_failure(
            &backend,
            &intent,
            false,
            BrokerError::LiveHandler("grant failed".to_owned()),
        );

        assert!(matches!(
            error,
            BrokerError::LiveHandler(ref message) if message == "grant failed"
        ));
        assert_eq!(
            backend.take_usbip_events(),
            vec![FakeUsbipEvent::Unbind {
                intent_id: intent.intent_id.clone()
            }],
            "grant failure rollback must unbind a fresh backend bind"
        );
        assert_eq!(
            crate::ops::usbip_lock::peek_owner(&intent.lock_path),
            None,
            "grant failure with successful rollback unbind must release the busid lock"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn usbip_bind_acl_grant_failure_does_not_rollback_same_vm_replay() {
        let root = test_audit_dir("usbip-bind-acl-grant-failure-replay-preserve");
        let bundle = build_test_bundle(&root);
        let intent = test_usbip_intent_with_lock(&root, &bundle);
        crate::ops::usbip_lock::acquire_lock(
            &intent.lock_path,
            &intent.vm_name,
            nix::unistd::Uid::current().as_raw(),
            nix::unistd::Gid::current().as_raw(),
        )
        .expect("seed same-VM replay lock");
        let backend = FakeDispatchBackend::default();

        let error = rollback_usbip_bind_after_acl_grant_failure(
            &backend,
            &intent,
            true,
            BrokerError::LiveHandler("grant failed".to_owned()),
        );

        assert!(matches!(
            error,
            BrokerError::LiveHandler(ref message) if message == "grant failed"
        ));
        assert_eq!(
            backend.take_usbip_events(),
            Vec::new(),
            "same-VM replay grant failure must not unbind an already-active claim"
        );
        assert_eq!(
            crate::ops::usbip_lock::peek_owner(&intent.lock_path),
            Some(intent.vm_name.clone()),
            "same-VM replay grant failure must preserve the durable claim"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn usbip_bind_audit_failure_does_not_rollback_same_vm_replay() {
        let _usb_sysfs_guard = usb_sysfs_test_lock();
        let root = test_audit_dir("usbip-bind-audit-failure-replay-preserve");
        let bundle = build_test_bundle(&root);
        let intent = test_usbip_intent_with_lock(&root, &bundle);
        let _ = take_test_usbip_backend_acl_events();
        crate::ops::usbip_lock::acquire_lock(
            &intent.lock_path,
            &intent.vm_name,
            nix::unistd::Uid::current().as_raw(),
            nix::unistd::Gid::current().as_raw(),
        )
        .expect("seed same-VM replay lock");
        grant_usbip_backend_device_acl(
            &bundle.resolver,
            &intent,
            (0x1050, 0x0407),
            PathBuf::from("/dev/bus/usb/001/002"),
        )
        .expect("seed same-VM replay ACL grant");
        let backend = FakeDispatchBackend::default();

        rollback_usbip_bind_after_audit_failure(&backend, &bundle.resolver, &intent, true);

        assert_eq!(
            backend.take_usbip_events(),
            Vec::new(),
            "same-VM replay audit failure must not unbind an already-active claim"
        );
        assert_eq!(
            take_test_usbip_backend_acl_events(),
            vec![TestUsbipBackendAclEvent::Grant { uid: 1002 }],
            "same-VM replay audit failure must not revoke an existing backend ACL"
        );
        assert_eq!(
            crate::ops::usbip_lock::peek_owner(&intent.lock_path),
            Some(intent.vm_name.clone()),
            "same-VM replay audit failure must preserve the durable claim"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn usbip_proxy_reconcile_skips_absent_locked_device_acl_refresh() {
        let _usb_sysfs_guard = usb_sysfs_test_lock();
        let root = test_audit_dir("usbip-proxy-reconcile-absent-device");
        let bundle = build_test_bundle(&root);
        let intent = test_usbip_intent_with_lock(&root, &bundle);
        let _ = take_test_usbip_backend_acl_events();
        let sysfs_root = crate::test_scratch_root().join("runtime-usb-sysfs-root");
        TEST_USB_SYSFS_ROOT
            .set(sysfs_root.clone())
            .unwrap_or_else(|_| assert_eq!(TEST_USB_SYSFS_ROOT.get(), Some(&sysfs_root)));
        let _ = fs::remove_dir_all(&sysfs_root);
        crate::ops::usbip_lock::acquire_lock(
            &intent.lock_path,
            &intent.vm_name,
            nix::unistd::Uid::current().as_raw(),
            nix::unistd::Gid::current().as_raw(),
        )
        .expect("seed lock for absent device");

        reconcile_active_usbip_backend_acls(&bundle.resolver)
            .expect("absent locked hardware should not make proxy reconcile fail");

        assert_eq!(
            take_test_usbip_backend_acl_events(),
            Vec::new(),
            "reconcile must not grant an ACL when the locked USB hardware is absent"
        );
        assert_eq!(
            crate::ops::usbip_lock::peek_owner(&intent.lock_path),
            Some(intent.vm_name.clone()),
            "reconcile preserves the durable claim for later device return"
        );

        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&sysfs_root);
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn usbip_unbind_acl_revoke_failure_releases_lock_when_device_is_unbound() {
        let _usb_sysfs_guard = usb_sysfs_test_lock();
        let root = test_audit_dir("usbip-unbind-acl-revoke-failure-release");
        let bundle = build_test_bundle(&root);
        let intent = test_usbip_intent_with_lock(&root, &bundle);
        prepare_test_usb_sysfs_device("1050", "0407", "2.3");
        crate::ops::usbip_lock::acquire_lock(
            &intent.lock_path,
            &intent.vm_name,
            nix::unistd::Uid::current().as_raw(),
            nix::unistd::Gid::current().as_raw(),
        )
        .expect("seed lock");

        let error = handle_usbip_acl_revoke_failure_after_unbind(
            &intent,
            false,
            BrokerError::LiveHandler("revoke failed".to_owned()),
        );

        assert!(matches!(
            error,
            BrokerError::LiveHandler(ref message) if message == "revoke failed"
        ));
        assert_eq!(
            crate::ops::usbip_lock::peek_owner(&intent.lock_path),
            None,
            "after successful unbind, an ACL revoke error must not leak the busid lock when the device is no longer bound"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn usbip_unbind_acl_revoke_failure_preserves_lock_when_device_still_bound() {
        use std::os::unix::fs::symlink;

        let _usb_sysfs_guard = usb_sysfs_test_lock();
        let root = test_audit_dir("usbip-unbind-acl-revoke-failure-preserve-bound");
        let bundle = build_test_bundle(&root);
        let intent = test_usbip_intent_with_lock(&root, &bundle);
        let sysfs_root = prepare_test_usb_sysfs_device("1050", "0407", "2.3");
        let driver_root = sysfs_root
            .parent()
            .expect("USB sysfs root has bus parent")
            .join("drivers")
            .join("usbip-host");
        fs::create_dir_all(&driver_root).expect("create usbip-host driver root");
        symlink(&driver_root, sysfs_root.join("1-2.3").join("driver")).expect("driver symlink");
        crate::ops::usbip_lock::acquire_lock(
            &intent.lock_path,
            &intent.vm_name,
            nix::unistd::Uid::current().as_raw(),
            nix::unistd::Gid::current().as_raw(),
        )
        .expect("seed lock");

        let error = handle_usbip_acl_revoke_failure_after_unbind(
            &intent,
            false,
            BrokerError::LiveHandler("revoke failed".to_owned()),
        );

        assert!(matches!(
            error,
            BrokerError::LiveHandler(ref message) if message == "revoke failed"
        ));
        assert_eq!(
            crate::ops::usbip_lock::peek_owner(&intent.lock_path),
            Some(intent.vm_name.clone()),
            "if post-unbind inspection still sees usbip-host, preserve the lock for manual recovery"
        );

        let _ = fs::remove_dir_all(&root);
    }

    // ------------------------------------------------------------------
    // retry_usbip_backend_acl_grant unit tests
    // ------------------------------------------------------------------

    /// Helper that tracks grant/revoke calls for retry function unit tests.
    #[cfg(not(feature = "layer1-bootstrap"))]
    #[derive(Default, Debug)]
    struct AclCallLog {
        grants: Vec<PathBuf>,
        revokes: Vec<PathBuf>,
        sleeps: usize,
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn retry_acl_grant_succeeds_immediately_when_node_is_stable() {
        use std::cell::RefCell;
        let log = RefCell::new(AclCallLog::default());
        let node = PathBuf::from("/dev/bus/usb/001/007");
        let result = retry_usbip_backend_acl_grant(
            1002,
            || Ok(node.clone()),
            |path, _uid| {
                log.borrow_mut().grants.push(path.to_owned());
                Ok(())
            },
            |path, _uid| {
                log.borrow_mut().revokes.push(path.to_owned());
                Ok(())
            },
            || log.borrow_mut().sleeps += 1,
        );
        assert!(result.is_ok(), "stable node must succeed immediately");
        let log = log.into_inner();
        assert_eq!(log.grants, vec![node], "exactly one grant");
        assert!(log.revokes.is_empty(), "no revoke on clean success");
        assert_eq!(log.sleeps, 0, "no sleep on first-attempt success");
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn retry_acl_grant_converges_after_transient_node_change() {
        // Simulate a device re-enumeration: first verify returns node A,
        // post-grant verify returns node B (different /dev node, same
        // VID/PID identity from the caller's perspective). The retry then
        // observes stable node B and succeeds.
        use std::cell::RefCell;
        let node_a = PathBuf::from("/dev/bus/usb/001/009");
        let node_b = PathBuf::from("/dev/bus/usb/001/010");
        let log = RefCell::new(AclCallLog::default());
        // verify_device_node: first call → A, second call (post-grant re-check) → B,
        // third call (retry pre-grant) → B, fourth call (post-grant re-check) → B.
        let call_count = RefCell::new(0usize);
        let result = retry_usbip_backend_acl_grant(
            1002,
            || {
                let n = *call_count.borrow();
                *call_count.borrow_mut() += 1;
                match n {
                    0 => Ok(node_a.clone()), // first pre-grant verify → A
                    1 => Ok(node_b.clone()), // post-grant verify → B (changed!)
                    _ => Ok(node_b.clone()), // subsequent calls → B (stable)
                }
            },
            |path, _uid| {
                log.borrow_mut().grants.push(path.to_owned());
                Ok(())
            },
            |path, _uid| {
                log.borrow_mut().revokes.push(path.to_owned());
                Ok(())
            },
            || log.borrow_mut().sleeps += 1,
        );
        assert!(result.is_ok(), "must converge after transient node change");
        let log = log.into_inner();
        // First attempt: grant A, post-grant verify sees B → revoke A, sleep.
        // Second attempt: grant B, post-grant verify sees B → success.
        assert!(
            log.grants.contains(&node_a),
            "first grant is for the initial node A"
        );
        assert!(
            log.grants.contains(&node_b),
            "retry grant is for the stable node B"
        );
        assert_eq!(
            log.revokes,
            vec![node_a.clone()],
            "must revoke old grant on A when re-verify sees B"
        );
        assert_eq!(log.sleeps, 1, "exactly one sleep between attempts");
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn retry_acl_grant_fails_when_verify_permanently_fails() {
        use std::cell::RefCell;
        let log = RefCell::new(AclCallLog::default());
        let err_msg = "identity changed: VID/PID mismatch";
        let result = retry_usbip_backend_acl_grant(
            1002,
            || Err(BrokerError::LiveHandler(err_msg.to_owned())),
            |path, _uid| {
                log.borrow_mut().grants.push(path.to_owned());
                Ok(())
            },
            |path, _uid| {
                log.borrow_mut().revokes.push(path.to_owned());
                Ok(())
            },
            || log.borrow_mut().sleeps += 1,
        );
        assert!(result.is_err(), "must fail when verify never succeeds");
        let log = log.into_inner();
        assert!(log.grants.is_empty(), "no grants when verify always fails");
        assert!(log.revokes.is_empty(), "no revokes when grant never ran");
        assert_eq!(
            log.sleeps, USBIP_BACKEND_ACL_GRANT_ATTEMPTS,
            "must sleep once per attempt"
        );
        match result.unwrap_err() {
            BrokerError::LiveHandler(msg) => {
                assert_eq!(msg, err_msg, "last error from verify must be propagated")
            }
            other => panic!("expected LiveHandler, got {other:?}"),
        }
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn retry_acl_grant_revokes_before_every_retry_on_post_grant_verify_failure() {
        // Grant succeeds, but post-grant verify always returns a different
        // node. The function must revoke on every attempt before giving up.
        use std::cell::RefCell;
        let base = "/dev/bus/usb/001/";
        let log = RefCell::new(AclCallLog::default());
        let counter = RefCell::new(0u32);
        let result = retry_usbip_backend_acl_grant(
            1002,
            || {
                let n = *counter.borrow();
                *counter.borrow_mut() += 1;
                // Each call returns a unique node so post-grant verify
                // always sees a "changed" path.
                Ok(PathBuf::from(format!("{base}{n:03}")))
            },
            |path, _uid| {
                log.borrow_mut().grants.push(path.to_owned());
                Ok(())
            },
            |path, _uid| {
                log.borrow_mut().revokes.push(path.to_owned());
                Ok(())
            },
            || log.borrow_mut().sleeps += 1,
        );
        assert!(result.is_err(), "must fail when node never stabilizes");
        let log = log.into_inner();
        assert_eq!(
            log.grants.len(),
            USBIP_BACKEND_ACL_GRANT_ATTEMPTS,
            "one grant attempt per retry round"
        );
        assert_eq!(
            log.revokes.len(),
            USBIP_BACKEND_ACL_GRANT_ATTEMPTS,
            "must revoke once per grant when post-grant verify always disagrees"
        );
        // Every granted node must eventually be revoked.
        for granted in &log.grants {
            assert!(
                log.revokes.contains(granted),
                "granted node {granted:?} must be revoked"
            );
        }
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn retry_acl_grant_tolerates_benign_enoent_during_revoke() {
        // After a node change the old node may already be gone (kernel
        // removes /dev/bus/usb/B/D during re-enumeration). Revoke errors
        // must not prevent the retry from proceeding or propagating the
        // real error.
        use std::cell::RefCell;
        let node_a = PathBuf::from("/dev/bus/usb/001/021");
        let node_b = PathBuf::from("/dev/bus/usb/001/022");
        let call_count = RefCell::new(0usize);
        let log = RefCell::new(AclCallLog::default());
        // Revoke always fails with "not found" - benign during re-enum.
        let result = retry_usbip_backend_acl_grant(
            1002,
            || {
                let n = *call_count.borrow();
                *call_count.borrow_mut() += 1;
                match n {
                    0 => Ok(node_a.clone()),
                    1 => Ok(node_b.clone()), // post-grant re-check sees B
                    _ => Ok(node_b.clone()), // stable from here on
                }
            },
            |path, _uid| {
                log.borrow_mut().grants.push(path.to_owned());
                Ok(())
            },
            |path, _uid| {
                log.borrow_mut().revokes.push(path.to_owned());
                // Simulate ENOENT: old node already removed.
                Err(BrokerError::LiveHandler(
                    "No such file or directory".to_owned(),
                ))
            },
            || log.borrow_mut().sleeps += 1,
        );
        // The revoke error must not surface as the final result; the
        // retry on node B must succeed.
        assert!(
            result.is_ok(),
            "benign revoke ENOENT must not abort the retry loop"
        );
        let log = log.into_inner();
        assert!(
            log.revokes.contains(&node_a),
            "attempted revoke on the stale node A"
        );
        assert!(log.grants.contains(&node_b), "retry grant on stable node B");
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn usb_audit_rotation_audit_dedupe_suppresses_repeats_and_allows_retry() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let audit = UsbSerialCorrelationKeyRotationAudit {
            previous_key_id: format!("audit-key-previous-dedupe-{unique}"),
            current_key_id: format!("audit-key-current-dedupe-{unique}"),
            active_key_count: 2,
            grace_window_seconds: USB_AUDIT_SERIAL_HMAC_PREVIOUS_KEY_GRACE_WINDOW_SECONDS,
            correlation_version: USB_AUDIT_SERIAL_CORRELATION_VERSION.to_owned(),
        };

        let dedupe_key = mark_usb_audit_serial_hmac_rotation_audit_logged(&audit)
            .expect("first rotation audit for key pair is allowed");
        assert!(mark_usb_audit_serial_hmac_rotation_audit_logged(&audit).is_none());

        unmark_usb_audit_serial_hmac_rotation_audit_logged(&dedupe_key);
        let retry_dedupe_key = mark_usb_audit_serial_hmac_rotation_audit_logged(&audit)
            .expect("failed audit write can clear the marker and retry");
        assert_eq!(retry_dedupe_key, dedupe_key);
        unmark_usb_audit_serial_hmac_rotation_audit_logged(&retry_dedupe_key);
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn usbip_bind_with_previous_serial_hmac_key_emits_one_rotation_audit_record_per_key_pair() {
        use d2b_contracts::types::TracingSpanId;
        use d2b_contracts_broker::broker_wire::{BrokerCallerRole, BrokerRequest};
        use std::os::unix::fs::PermissionsExt;

        let root = test_audit_dir("usb-serial-hmac-rotation-audit");
        let bundle = build_test_bundle(&root);
        let config = test_server_config(&root, &bundle.manifest_path);
        let key_dir = usb_audit_serial_hmac_key_dir(&config.state_dir);
        fs::create_dir_all(&key_dir).expect("create key dir");

        let current_secret = b"current-secret-material-12345678";
        let previous_secret = b"previous-secret-material-1234567";
        assert_eq!(current_secret.len(), USB_AUDIT_SERIAL_HMAC_KEY_BYTES);
        assert_eq!(previous_secret.len(), USB_AUDIT_SERIAL_HMAC_KEY_BYTES);
        let _usb_sysfs_guard = usb_sysfs_test_lock();

        let write_key = |file_name: &str, key: &UsbAuditSerialHmacKey| {
            let path = key_dir.join(file_name);
            fs::write(&path, render_usb_audit_serial_hmac_key(key)).expect("write key");
            let mut perms = fs::metadata(&path).expect("stat key").permissions();
            perms.set_mode(0o400);
            fs::set_permissions(&path, perms).expect("chmod key");
        };
        write_key(
            USB_AUDIT_SERIAL_HMAC_CURRENT_KEY_FILE,
            &UsbAuditSerialHmacKey {
                slot: UsbAuditSerialHmacKeySlot::Current,
                key_id: "audit-key-current".to_owned(),
                key: current_secret.to_vec(),
            },
        );
        write_key(
            USB_AUDIT_SERIAL_HMAC_PREVIOUS_KEY_FILE,
            &UsbAuditSerialHmacKey {
                slot: UsbAuditSerialHmacKeySlot::Previous,
                key_id: "audit-key-previous".to_owned(),
                key: previous_secret.to_vec(),
            },
        );

        let sysfs_root = prepare_test_usb_sysfs_device("1050", "0407", "2.3");
        fs::write(
            sysfs_root.join("1-2.3").join("serial"),
            "raw-usb-serial-never-log\n",
        )
        .expect("write fake serial");

        let (log, capture) = AuditLog::open_capturing(
            &config.audit_dir,
            Gid::current().as_raw(),
            true,
            config.audit_retention_days,
        )
        .expect("open capturing audit log");
        let backend = FakeDispatchBackend::default();
        let caller_role = BrokerCallerRole::AdminUid { uid: 1000 };
        let caller_gid = Gid::current().as_raw();
        let make_request = |span_id: &str| {
            BrokerRequest::UsbipBind(d2b_contracts_broker::broker_wire::UsbipBindRequest {
                bundle_usbip_bind_intent_ref: BundleOpId::new(
                    d2b_core::bundle_resolver::intent_id_usbip_bind("work", "corp-vm", "1-2.3"),
                ),
                tracing_span_id: Some(TracingSpanId::new(span_id)),
            })
        };
        let request = make_request("span-usb-rotate");
        let audit_context = DispatchAuditContext::from_request(&request, 4242, &caller_role)
            .expect("audit context");

        let dispatch = dispatch_request_with_backend(
            request,
            1000,
            caller_gid,
            caller_role.clone(),
            &audit_context,
            &config,
            &log,
            Some(&bundle.resolver),
            &backend,
        )
        .expect("dispatch succeeds");
        match dispatch.response {
            BrokerResponse::Ack(response) => {
                assert!(response.accepted);
                assert_eq!(response.operation, "UsbipBind");
            }
            other => panic!("expected UsbipBind ack, got {other:?}"),
        }

        let records = capture.lock().expect("capture lock").clone();
        assert_eq!(records.len(), 2);
        let rotation_record = records
            .iter()
            .find(|record| record.operation == "UsbSerialCorrelationKeyRotate")
            .expect("rotation audit record");
        assert!(d2b_contracts_resource::v3::is_canonical_digest(
            &rotation_record.public_operation_id
        ));
        assert_eq!(rotation_record.subject_id, "usb-audit-serial-hmac");
        assert_eq!(rotation_record.scope_id, "host");
        assert_eq!(rotation_record.verb, "UsbSerialCorrelationKeyRotate");
        assert_eq!(
            rotation_record.request_fields,
            serde_json::json!({
                "detectedDuring": "UsbipBind",
                "tracingSpanIdPresent": true,
            })
        );
        assert_eq!(
            rotation_record.tracing_span_id.as_deref(),
            Some("span-usb-rotate")
        );
        let rotation_fields = OperationFields::from_operation_value(
            "UsbSerialCorrelationKeyRotate",
            rotation_record
                .operation_fields
                .clone()
                .expect("rotation fields"),
        )
        .expect("parse rotation fields");
        assert_eq!(
            rotation_fields,
            OperationFields::UsbSerialCorrelationKeyRotate(UsbSerialCorrelationKeyRotationAudit {
                previous_key_id: "audit-key-previous".to_owned(),
                current_key_id: "audit-key-current".to_owned(),
                active_key_count: 2,
                grace_window_seconds: 30 * 24 * 60 * 60,
                correlation_version: "d2b-usb-audit-serial-v1".to_owned(),
            })
        );

        let bind_record = records
            .iter()
            .find(|record| record.operation == "UsbipBind")
            .expect("bind audit record");
        let bind_fields = OperationFields::from_operation_value(
            "UsbipBind",
            bind_record.operation_fields.clone().expect("bind fields"),
        )
        .expect("parse bind fields");
        let OperationFields::UsbipBind {
            device_identity: Some(device_identity),
            ..
        } = bind_fields
        else {
            panic!("expected UsbipBind device identity");
        };
        assert!(device_identity.serial_observed);
        assert!(device_identity.serial_correlation.is_some());
        assert!(device_identity.previous_serial_correlation.is_some());

        let rotation_json = serde_json::to_string(rotation_record).expect("serialize rotation");
        assert!(!rotation_json.contains("raw-usb-serial-never-log"));
        assert!(!rotation_json.contains("1-2.3"));
        assert!(!rotation_json.contains("key_hex"));

        let exported = log.export_lines(None, None).expect("export audit lines");
        let rendered = exported.join("\n");
        assert!(rendered.contains("UsbSerialCorrelationKeyRotate"));
        assert!(!rendered.contains("raw-usb-serial-never-log"));
        assert!(!rendered.contains("current-secret-material-12345678"));
        assert!(!rendered.contains("previous-secret-material-1234567"));
        assert!(!rendered.contains(&lower_hex(current_secret)));
        assert!(!rendered.contains(&lower_hex(previous_secret)));
        assert!(!rendered.contains("key_hex"));

        let repeat_request = make_request("span-usb-rotate-repeat");
        let repeat_audit_context =
            DispatchAuditContext::from_request(&repeat_request, 4242, &caller_role)
                .expect("repeat audit context");
        dispatch_request_with_backend(
            repeat_request,
            1000,
            caller_gid,
            caller_role,
            &repeat_audit_context,
            &config,
            &log,
            Some(&bundle.resolver),
            &backend,
        )
        .expect("repeat dispatch succeeds");

        let records_after_repeat = capture.lock().expect("capture lock").clone();
        assert_eq!(records_after_repeat.len(), 3);
        assert_eq!(
            records_after_repeat
                .iter()
                .filter(|record| record.operation == "UsbSerialCorrelationKeyRotate")
                .count(),
            1
        );
        assert_eq!(
            records_after_repeat
                .iter()
                .filter(|record| record.operation == "UsbipBind")
                .count(),
            2
        );
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn usb_audit_serial_hmac_keyring_creates_root_only_current_key_and_reads_previous() {
        use std::os::unix::fs::PermissionsExt;

        let state_dir = test_audit_dir("usb-audit-hmac-keyring");
        fs::create_dir_all(&state_dir).expect("create state dir");
        let key_dir = usb_audit_serial_hmac_key_dir(&state_dir);
        fs::create_dir_all(&key_dir).expect("create key dir");
        let previous = UsbAuditSerialHmacKey {
            slot: UsbAuditSerialHmacKeySlot::Previous,
            key_id: "audit-key-previous".to_owned(),
            key: b"fedcba9876543210fedcba9876543210".to_vec(),
        };
        let previous_path = key_dir.join(USB_AUDIT_SERIAL_HMAC_PREVIOUS_KEY_FILE);
        fs::write(&previous_path, render_usb_audit_serial_hmac_key(&previous))
            .expect("write previous key");
        let mut perms = fs::metadata(&previous_path)
            .expect("stat previous key")
            .permissions();
        perms.set_mode(0o400);
        fs::set_permissions(&previous_path, perms).expect("chmod previous key");

        let keyring = usb_audit_serial_hmac_keyring(&state_dir, true).expect("keyring loads");
        assert_eq!(keyring.current.slot, UsbAuditSerialHmacKeySlot::Current);
        assert!(keyring.current.key_id.starts_with("usb-audit-"));
        assert_eq!(keyring.current.key.len(), USB_AUDIT_SERIAL_HMAC_KEY_BYTES);
        assert_eq!(keyring.previous, Some(previous));

        let current_path = key_dir.join(USB_AUDIT_SERIAL_HMAC_CURRENT_KEY_FILE);
        let mode = fs::metadata(&current_path)
            .expect("stat current key")
            .mode()
            & 0o777;
        assert_eq!(mode, 0o400);

        let first_current = keyring.current.clone();
        let loaded_again =
            usb_audit_serial_hmac_keyring(&state_dir, true).expect("keyring loads again");
        assert_eq!(loaded_again.current, first_current);
    }

    #[test]
    fn broker_ipc_rate_limiter_refuses_excess_uid_requests() {
        let mut limiter = IpcRateLimiter::new(2);
        assert!(limiter.check(IpcRatePool::Daemon, 1000, "d2b-admin", "UsbipBind"));
        assert!(limiter.check(IpcRatePool::Daemon, 1000, "d2b-admin", "UsbipBind"));
        assert!(!limiter.check(IpcRatePool::Daemon, 1000, "d2b-admin", "UsbipBind"));
        assert!(
            limiter.check(IpcRatePool::Daemon, 1001, "d2b-admin", "UsbipBind"),
            "other UIDs have independent buckets"
        );
    }

    #[test]
    fn broker_ipc_rate_limiter_keys_on_stable_role_and_operation() {
        let mut limiter = IpcRateLimiter::new(1);
        assert!(limiter.check(IpcRatePool::Daemon, 1000, "d2b-admin", "UsbipBind"));
        assert!(
            !limiter.check(IpcRatePool::Daemon, 1000, "d2b-admin", "UsbipBind"),
            "same stable uid/role/op bucket must be limited"
        );
        assert!(
            limiter.check(IpcRatePool::Daemon, 1000, "d2b-admin", "UsbipUnbind"),
            "distinct USB operations have independent stable buckets"
        );
        assert!(
            limiter.check(IpcRatePool::Daemon, 1000, "launcher-uid", "UsbipBind"),
            "forwarded caller roles have independent stable buckets"
        );
    }

    #[test]
    fn broker_ipc_rate_limiter_caps_bucket_growth_fail_closed() {
        let now = Instant::now();
        let mut limiter = IpcRateLimiter::with_limits(64, 2);

        assert!(limiter.check_at(IpcRatePool::Daemon, 1000, "d2b-admin", "UsbipBind", now));
        assert!(limiter.check_at(IpcRatePool::Daemon, 1001, "d2b-admin", "UsbipBind", now));
        assert_eq!(limiter.daemon_buckets.len(), 2);
        for uid in 1002..1100 {
            assert!(
                !limiter.check_at(IpcRatePool::Daemon, uid, "d2b-admin", "UsbipBind", now),
                "new UID buckets must fail closed once the cap is reached"
            );
        }
        assert_eq!(
            limiter.daemon_buckets.len(),
            2,
            "refused peers must not allocate unbounded buckets"
        );
        assert!(
            limiter.check_at(IpcRatePool::Daemon, 1000, "d2b-admin", "UsbipBind", now),
            "existing users keep their bucket while new buckets are refused"
        );
    }

    #[test]
    fn broker_ipc_rate_limiter_direct_peer_flood_preserves_daemon_capacity() {
        let now = Instant::now();
        let mut limiter = IpcRateLimiter::with_limits(64, 2);

        assert!(limiter.check_at(
            IpcRatePool::Direct,
            1000,
            "direct-broker-peer",
            "direct-broker-connect",
            now
        ));
        assert!(limiter.check_at(
            IpcRatePool::Direct,
            1001,
            "direct-broker-peer",
            "direct-broker-connect",
            now
        ));
        assert!(
            !limiter.check_at(
                IpcRatePool::Direct,
                1002,
                "direct-broker-peer",
                "direct-broker-connect",
                now
            ),
            "direct peers should fail closed once their own pool is full"
        );
        assert_eq!(limiter.direct_buckets.len(), 2);

        assert!(
            limiter.check_at(IpcRatePool::Daemon, 4242, "d2b-admin", "UsbipBind", now),
            "daemon-forwarded requests must retain reserved bucket capacity"
        );
        assert_eq!(limiter.daemon_buckets.len(), 1);
        assert_eq!(limiter.direct_buckets.len(), 2);
    }

    #[test]
    fn broker_ipc_rate_limiter_evicts_expired_buckets_before_allocating() {
        let now = Instant::now();
        let after_window = now + IPC_RATE_LIMIT_WINDOW + Duration::from_millis(1);
        let mut limiter = IpcRateLimiter::with_limits(64, 2);

        assert!(limiter.check_at(IpcRatePool::Daemon, 1000, "d2b-admin", "UsbipBind", now));
        assert!(limiter.check_at(IpcRatePool::Daemon, 1001, "d2b-admin", "UsbipBind", now));
        assert_eq!(limiter.daemon_buckets.len(), 2);

        assert!(
            limiter.check_at(
                IpcRatePool::Daemon,
                1002,
                "d2b-admin",
                "UsbipBind",
                after_window
            ),
            "expired buckets should be reclaimed for later callers"
        );
        assert_eq!(
            limiter.daemon_buckets.len(),
            1,
            "expired UID buckets must not accumulate after eviction"
        );
        assert!(
            limiter.daemon_buckets.contains_key(&IpcRateKey {
                uid: 1002,
                role: "d2b-admin",
                operation: "UsbipBind",
            }),
            "only the fresh caller should remain after eviction"
        );
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    #[test]
    fn usbip_static_busid_owner_is_global_authority() {
        let root = test_audit_dir("usbip-static-owner");
        let bundle = build_test_bundle(&root);

        assert_eq!(
            static_usbip_busid_owner(&bundle.resolver, "1-2.3").as_deref(),
            Some("corp-vm")
        );
        assert!(
            find_wildcard_usbip_bind_intent_for(&bundle.resolver, "other-vm", "1-2.3").is_none(),
            "wildcard fallback must not claim a statically assigned busid"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn broker_error_audit_records_error_kind_and_message_for_errored_variants() {
        let audit_dir = test_audit_dir("broker-error-audit");
        fs::create_dir_all(&audit_dir).expect("create audit dir");
        let cases = vec![
            AuditCase {
                error: BrokerError::BundleResolverUnavailable,
                operation: "RunHostInstall",
                target_id: "operation".to_owned(),
                decision: "bundle-resolver-unavailable",
                error_kind: "Broker.BundleResolverUnavailable",
                error_message: "Broker started without a loadable bundle at ServerConfig.bundle_path. Bundle-dependent real-wire ops cannot resolve their BundleOpId refs.".to_owned(),
            },
            AuditCase {
                error: BrokerError::BundleIntentMissing {
                    kind: "installer",
                    intent_id: "installer:missing".to_owned(),
                },
                operation: "RunHostInstall",
                target_id: "installer:missing".to_owned(),
                decision: "bundle-intent-missing",
                error_kind: "Broker.BundleIntentMissing",
                error_message:
                    "no installer intent in the trusted bundle for opaque id `installer:missing`"
                        .to_owned(),
            },
            AuditCase {
                error: BrokerError::LiveHandler(
                    "systemctl enable d2bd failed: Unit d2bd.service does not exist"
                        .to_owned(),
                ),
                operation: "RunHostInstall",
                target_id: "operation".to_owned(),
                decision: "live-handler-error",
                error_kind: "Broker.LiveHandlerFailed",
                error_message:
                    "systemctl enable d2bd failed: Unit d2bd.service does not exist"
                        .to_owned(),
            },
            AuditCase {
                error: BrokerError::UsbipLockConflict {
                    busid: "1-2.3".to_owned(),
                    owner: "other-vm".to_owned(),
                },
                operation: "UsbipBind",
                target_id: "1-2.3".to_owned(),
                decision: "usbip-lock-conflict",
                error_kind: "Broker.UsbipLockConflict",
                error_message: "UsbipBind refused: busid 1-2.3 is already claimed by other-vm"
                    .to_owned(),
            },
            AuditCase {
                error: BrokerError::UsbipDeviceAbsent {
                    busid: "1-2.4".to_owned(),
                },
                operation: "UsbipBind",
                target_id: "1-2.4".to_owned(),
                decision: "usbip-device-absent",
                error_kind: "Broker.UsbipDeviceAbsent",
                error_message: "UsbipBind refused: USB device 1-2.4 is not present in sysfs"
                    .to_owned(),
            },
            AuditCase {
                error: BrokerError::ValidateBundle("bundle digest mismatch".to_owned()),
                operation: "ValidateBundle",
                target_id: "bundle".to_owned(),
                decision: "bundle-validation-failed",
                error_kind: "Broker.ValidateBundleFailed",
                error_message: "bundle digest mismatch".to_owned(),
            },
            AuditCase {
                error: BrokerError::Protocol("read request frame failed: unexpected EOF".to_owned()),
                operation: "RunHostInstall",
                target_id: "operation".to_owned(),
                decision: "protocol-error",
                error_kind: "Broker.Protocol",
                error_message: "read request frame failed: unexpected EOF".to_owned(),
            },
        ];

        let caller_gid = Gid::current().as_raw();
        let exported = {
            fs::create_dir_all(&audit_dir).expect("create audit dir");
            let log = AuditLog::open(&audit_dir, caller_gid, true, 14).expect("open audit log");
            for case in &cases {
                let audit_context = DispatchAuditContext {
                    peer_pid: 4242,
                    peer_role: CallerRole::AdminUid { uid: 1000 }.for_display().to_owned(),
                    verb: case.operation.to_owned(),
                    request_fields: Value::Object(Default::default()),
                    started_at: Instant::now(),
                    audit_join: None,
                };
                #[cfg(not(feature = "layer1-bootstrap"))]
                case.error
                    .audit(
                        &log,
                        1000,
                        caller_gid,
                        &CallerRole::AdminUid { uid: 1000 },
                        &audit_context,
                        None,
                        case.operation,
                        &case.target_id,
                    )
                    .expect("audit error");
                #[cfg(feature = "layer1-bootstrap")]
                case.error
                    .audit(
                        &log,
                        1000,
                        caller_gid,
                        &CallerRole::AdminUid { uid: 1000 },
                        &audit_context,
                        case.operation,
                        &case.target_id,
                    )
                    .expect("audit error");
            }
            log.export_lines(None, None).expect("export audit lines")
        };

        assert_eq!(exported.len(), cases.len());
        for (case, line) in cases.iter().zip(exported.iter()) {
            let value: Value = serde_json::from_str(line).expect("parse audit line");
            assert_eq!(
                value.get("op").and_then(Value::as_str),
                Some(case.operation)
            );
            assert_eq!(value.get("caller_uid").and_then(Value::as_u64), Some(1000));
            assert_eq!(
                value.get("caller_gid").and_then(Value::as_u64),
                Some(u64::from(caller_gid))
            );
            assert_eq!(
                value.get("disposition").and_then(Value::as_str),
                Some(case.decision)
            );
            assert_eq!(
                value.get("opaque_target_id").and_then(Value::as_str),
                Some(case.target_id.as_str())
            );
            assert_eq!(
                value.get("outcome").and_then(Value::as_str),
                Some("errored")
            );
            assert_eq!(
                value.get("error_kind").and_then(Value::as_str),
                Some(case.error_kind)
            );
            let error_message = value
                .get("error_message")
                .and_then(Value::as_str)
                .expect("redacted error message");
            assert!(error_message.starts_with("sha256:"));
            assert_ne!(error_message, case.error_message);
        }

        let _ = fs::remove_dir_all(&audit_dir);
    }

    #[cfg(not(feature = "layer1-bootstrap"))]
    mod reap_tests {
        use super::*;
        use d2b_contracts_broker::broker_wire::{
            ChildExitKind, ChildExitStatus, ChildReapedNotification,
        };
        use nix::sys::signal::{Signal, kill};
        use nix::unistd::Pid;
        use std::process::Command;
        use std::sync::{Mutex, MutexGuard, OnceLock};
        use std::time::{Duration, Instant};

        struct ReapTestGuard {
            _lock: MutexGuard<'static, ()>,
        }

        impl ReapTestGuard {
            fn new() -> Self {
                static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
                let lock = LOCK
                    .get_or_init(|| Mutex::new(()))
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                clear_reap_state();
                Self { _lock: lock }
            }
        }

        impl Drop for ReapTestGuard {
            fn drop(&mut self) {
                clear_reap_state();
            }
        }

        fn clear_reap_state() {
            let _ = drain_child_reap_buffer();
            if let Ok(mut registry) = runner_pidfd_registry().lock() {
                registry.clear();
            }
            if let Ok(mut registry) = runner_metadata_registry().lock() {
                registry.clear();
            }
        }

        fn start_test_reaper(test_name: &str) -> tokio::runtime::Runtime {
            let audit_dir = test_audit_dir(test_name);
            fs::create_dir_all(&audit_dir).expect("create reap audit dir");
            let audit_log = AuditLog::open(&audit_dir, Gid::current().as_raw(), true, 0)
                .expect("open reap audit log");
            let rt = start_sigchld_reaper(Arc::new(audit_log));
            std::thread::sleep(Duration::from_millis(50));
            rt
        }

        fn wait_for_notification(
            runner_id: &str,
            timeout: Duration,
        ) -> Option<ChildReapedNotification> {
            let deadline = Instant::now() + timeout;
            while Instant::now() < deadline {
                let found = child_reap_buffer()
                    .lock()
                    .expect("child_reap_buffer lock")
                    .iter()
                    .find(|n| n.runner_id == runner_id)
                    .cloned();
                if found.is_some() {
                    return found;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            None
        }

        fn observe_request() -> d2b_contracts_broker::broker_wire::ObserveRunnerRequest {
            d2b_contracts_broker::broker_wire::ObserveRunnerRequest {
                vm_id: d2b_contracts::types::VmId::new("reap-vm"),
                role_id: d2b_contracts::types::RoleId::new("ch-runner"),
                role: d2b_contracts_broker::broker_wire::RunnerRole::CloudHypervisor,
                bundle_runner_intent_ref: d2b_contracts::types::BundleOpId::new(
                    "runner:reap-vm:role:cloud-hypervisor",
                ),
                resource_ref: None,
                resource_uid: None,
                zone_uid: None,
                owner_ref: None,
                provider_ref: None,
                provider_identity: None,
                template_identity: None,
                generation: None,
                runtime_scope: None,
                guest_execution: None,
                tracing_span_id: None,
            }
        }

        fn test_runner_registration(pid: i32, start_time_ticks: u64) -> RunnerRegistration {
            RunnerRegistration {
                vm_id: "reap-vm".to_owned(),
                role_id: "ch-runner".to_owned(),
                resource_ref: None,
                resource_uid: None,
                zone_uid: None,
                generation: None,
                runtime_scope: None,
                owner_ref: None,
                provider_ref: None,
                provider_identity: None,
                template_identity: None,
                role: d2b_contracts_broker::broker_wire::RunnerRole::CloudHypervisor,
                bundle_runner_intent_ref: "runner:reap-vm:role:cloud-hypervisor".to_owned(),
                pid,
                start_time_ticks,
                binary_path: PathBuf::from("/nix/store/current-provider-controller/bin/controller"),
                cgroup_subtree: "d2b.slice/reap-vm/ch-runner".to_owned(),
                guest_execution: None,
            }
        }

        #[test]
        fn registered_observation_keeps_live_runner_registered_until_reaped() {
            let _guard = ReapTestGuard::new();

            let child = Command::new("sleep")
                .arg("600")
                .spawn()
                .expect("spawn sleep child");
            let pid = child.id() as i32;
            let runner_id = "reap-vm:ch-runner";
            let pidfd = crate::sys::pidfd_sys::pidfd_open(pid, 0).expect("pidfd_open");
            let start_time_ticks = read_proc_start_time_ticks(pid)
                .expect("read start time")
                .expect("live child");
            runner_pidfd_registry()
                .lock()
                .expect("registry lock")
                .insert(
                    runner_id.to_owned(),
                    pidfd.try_clone().expect("clone pidfd"),
                );
            runner_metadata_registry()
                .lock()
                .expect("metadata lock")
                .insert(
                    runner_id.to_owned(),
                    test_runner_registration(pid, start_time_ticks),
                );

            let registration = test_runner_registration(pid, start_time_ticks);
            let response = reap_registered_runner_after_observation(
                &observe_request(),
                runner_id,
                &registration,
                Some(pidfd),
            );
            assert!(response.present);
            assert!(!response.cgroup_verified);
            assert!(!response.executable_verified);
            assert!(
                runner_pidfd_registry()
                    .lock()
                    .expect("registry lock")
                    .contains_key(runner_id),
                "StillAlive must preserve the exact pidfd registration"
            );
            assert!(
                runner_metadata_registry()
                    .lock()
                    .expect("metadata lock")
                    .contains_key(runner_id),
                "StillAlive must preserve runner metadata"
            );

            kill(Pid::from_raw(pid), Signal::SIGKILL).expect("kill child");
            let _ = nix::sys::wait::waitpid(Pid::from_raw(pid), None);
            std::mem::forget(child);
        }

        #[test]
        fn registered_observation_reports_absent_only_after_exact_reap() {
            let _guard = ReapTestGuard::new();

            let child = Command::new("true").spawn().expect("spawn true child");
            let pid = child.id() as i32;
            let runner_id = "reap-vm:ch-runner";
            let pidfd = crate::sys::pidfd_sys::pidfd_open(pid, 0).expect("pidfd_open");
            runner_pidfd_registry()
                .lock()
                .expect("registry lock")
                .insert(
                    runner_id.to_owned(),
                    pidfd.try_clone().expect("clone pidfd"),
                );
            runner_metadata_registry()
                .lock()
                .expect("metadata lock")
                .insert(runner_id.to_owned(), test_runner_registration(pid, 1));
            std::mem::forget(child);

            let registration = test_runner_registration(pid, 1);
            let request = observe_request();
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut response = present_unverified_runner_response(&request, &registration);
            while response.present && Instant::now() < deadline {
                let retained_pidfd = runner_pidfd_registry()
                    .lock()
                    .expect("registry lock")
                    .get(runner_id)
                    .and_then(|pidfd| dup(pidfd.as_raw_fd()).ok().map(owned_fd_from_raw));
                response = reap_registered_runner_after_observation(
                    &request,
                    runner_id,
                    &registration,
                    retained_pidfd,
                );
                if response.present {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }

            assert!(!response.present, "reap must precede an absent response");
            assert!(
                !runner_pidfd_registry()
                    .lock()
                    .expect("registry lock")
                    .contains_key(runner_id),
                "reaped runner must be removed from pidfd registry"
            );
            assert!(
                !runner_metadata_registry()
                    .lock()
                    .expect("metadata lock")
                    .contains_key(runner_id),
                "reaped runner must be removed from metadata registry"
            );
        }

        #[test]
        fn reap_loop_processes_exited_child() {
            let _guard = ReapTestGuard::new();
            let _rt = start_test_reaper("reap-exited-child");

            let child = Command::new("sleep")
                .arg("1")
                .spawn()
                .expect("spawn sleep child");
            let pid = child.id() as i32;
            let runner_id = format!("test-vm:test-role-{pid}");
            {
                let pidfd = crate::sys::pidfd_sys::pidfd_open(pid, 0).expect("pidfd_open");
                runner_pidfd_registry()
                    .lock()
                    .expect("registry lock")
                    .insert(runner_id.clone(), pidfd);
            }
            std::mem::forget(child);

            let notif = wait_for_notification(&runner_id, Duration::from_secs(3))
                .expect("ChildReaped notification should appear within 3 s");
            assert_eq!(notif.exit_status.kind, ChildExitKind::Exited);
            assert_eq!(notif.exit_status.code, Some(0));
        }

        #[test]
        fn reap_loop_signaled_sigterm() {
            let _guard = ReapTestGuard::new();
            let _rt = start_test_reaper("reap-signaled-sigterm");

            let child = Command::new("sleep")
                .arg("600")
                .spawn()
                .expect("spawn sleep child");
            let pid = child.id() as i32;
            let runner_id = format!("test-vm:sigterm-{pid}");
            {
                let pidfd = crate::sys::pidfd_sys::pidfd_open(pid, 0).expect("pidfd_open");
                runner_pidfd_registry()
                    .lock()
                    .expect("registry lock")
                    .insert(runner_id.clone(), pidfd);
            }
            kill(Pid::from_raw(pid), Signal::SIGTERM).expect("kill SIGTERM");
            std::mem::forget(child);

            let notif = wait_for_notification(&runner_id, Duration::from_secs(2))
                .expect("ChildReaped notification for SIGTERM");
            assert_eq!(notif.exit_status.kind, ChildExitKind::Signaled);
            assert_eq!(notif.exit_status.signal, Some(libc::SIGTERM));
        }

        #[test]
        fn reap_loop_killed_sigkill() {
            let _guard = ReapTestGuard::new();
            let _rt = start_test_reaper("reap-killed-sigkill");

            let child = Command::new("sleep")
                .arg("600")
                .spawn()
                .expect("spawn sleep child");
            let pid = child.id() as i32;
            let runner_id = format!("test-vm:sigkill-{pid}");
            {
                let pidfd = crate::sys::pidfd_sys::pidfd_open(pid, 0).expect("pidfd_open");
                runner_pidfd_registry()
                    .lock()
                    .expect("registry lock")
                    .insert(runner_id.clone(), pidfd);
            }
            kill(Pid::from_raw(pid), Signal::SIGKILL).expect("kill SIGKILL");
            std::mem::forget(child);

            let notif = wait_for_notification(&runner_id, Duration::from_secs(2))
                .expect("ChildReaped notification for SIGKILL");
            assert_eq!(notif.exit_status.kind, ChildExitKind::Killed);
            assert_eq!(notif.exit_status.signal, Some(libc::SIGKILL));
        }

        #[test]
        fn reap_loop_concurrent_stress_8_children() {
            let _guard = ReapTestGuard::new();
            let _rt = start_test_reaper("reap-concurrent-stress");

            let mut runner_ids = Vec::new();
            for i in 0..8 {
                let child = Command::new("sleep")
                    .arg("1")
                    .spawn()
                    .expect("spawn stress child");
                let pid = child.id() as i32;
                let runner_id = format!("test-vm:stress-{i}-{pid}");
                let pidfd = crate::sys::pidfd_sys::pidfd_open(pid, 0).expect("pidfd_open");
                runner_pidfd_registry()
                    .lock()
                    .expect("registry lock")
                    .insert(runner_id.clone(), pidfd);
                runner_ids.push(runner_id);
                std::mem::forget(child);
            }

            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                let found = child_reap_buffer()
                    .lock()
                    .expect("child_reap_buffer lock")
                    .iter()
                    .filter(|n| runner_ids.iter().any(|id| id == &n.runner_id))
                    .count();
                if found == runner_ids.len() {
                    break;
                }
                if Instant::now() >= deadline {
                    panic!(
                        "only {found}/{} children reaped within 3 s",
                        runner_ids.len()
                    );
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }

        #[test]
        fn targeted_reap_reaps_already_exited_child() {
            // No SIGCHLD reaper is started: the targeted post-spawn
            // reap alone must reap a child that has already exited,
            // closing the registration-window zombie leak.
            let _guard = ReapTestGuard::new();

            let child = Command::new("true").spawn().expect("spawn true child");
            let pid = child.id() as i32;
            let runner_id = format!("test-vm:targeted-exited-{pid}");
            let pidfd = crate::sys::pidfd_sys::pidfd_open(pid, 0).expect("pidfd_open");
            let registry_dup = pidfd.try_clone().expect("dup pidfd for registry");
            runner_pidfd_registry()
                .lock()
                .expect("registry lock")
                .insert(runner_id.clone(), registry_dup);
            std::mem::forget(child);

            // The child exits ~immediately; loop the targeted reap until
            // it observes the exit (deterministic, no background loop).
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut reaped = None;
            let mut outcome = TargetedReapOutcome::StillAlive;
            while Instant::now() < deadline {
                outcome = targeted_reap_runner(&runner_id, pidfd.as_fd());
                if let Some(n) = child_reap_buffer()
                    .lock()
                    .expect("child_reap_buffer lock")
                    .iter()
                    .find(|n| n.runner_id == runner_id)
                    .cloned()
                {
                    reaped = Some(n);
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }

            let notif = reaped.expect("targeted reap should reap the exited child");
            assert_eq!(outcome, TargetedReapOutcome::Reaped);
            assert_eq!(notif.exit_status.kind, ChildExitKind::Exited);
            assert_eq!(notif.exit_status.code, Some(0));
            // Registry entry must be gone so the SIGCHLD loop won't
            // double-reap a since-reused PID.
            assert!(
                !runner_pidfd_registry()
                    .lock()
                    .expect("registry lock")
                    .contains_key(&runner_id),
                "registry entry must be removed after targeted reap"
            );
        }

        #[test]
        fn targeted_reap_leaves_running_child_for_sigchld_loop() {
            // A still-running child must NOT be reaped by the targeted
            // pass: it stays registered for the SIGCHLD loop.
            let _guard = ReapTestGuard::new();

            let child = Command::new("sleep")
                .arg("600")
                .spawn()
                .expect("spawn sleep child");
            let pid = child.id() as i32;
            let runner_id = format!("test-vm:targeted-alive-{pid}");
            let pidfd = crate::sys::pidfd_sys::pidfd_open(pid, 0).expect("pidfd_open");
            let registry_dup = pidfd.try_clone().expect("dup pidfd for registry");
            runner_pidfd_registry()
                .lock()
                .expect("registry lock")
                .insert(runner_id.clone(), registry_dup);

            let outcome = targeted_reap_runner(&runner_id, pidfd.as_fd());
            assert_eq!(outcome, TargetedReapOutcome::StillAlive);

            assert!(
                child_reap_buffer()
                    .lock()
                    .expect("child_reap_buffer lock")
                    .iter()
                    .all(|n| n.runner_id != runner_id),
                "running child must not be reaped by targeted pass"
            );
            assert!(
                runner_pidfd_registry()
                    .lock()
                    .expect("registry lock")
                    .contains_key(&runner_id),
                "running child must remain registered"
            );

            // Clean up the still-running child.
            kill(Pid::from_raw(pid), Signal::SIGKILL).expect("kill SIGKILL");
            let _ = nix::sys::wait::waitpid(Pid::from_raw(pid), None);
            std::mem::forget(child);
        }

        #[test]
        fn targeted_reap_reports_signaled_child() {
            let _guard = ReapTestGuard::new();

            let child = Command::new("sleep")
                .arg("600")
                .spawn()
                .expect("spawn sleep child");
            let pid = child.id() as i32;
            let runner_id = format!("test-vm:targeted-signaled-{pid}");
            let pidfd = crate::sys::pidfd_sys::pidfd_open(pid, 0).expect("pidfd_open");
            let registry_dup = pidfd.try_clone().expect("dup pidfd for registry");
            runner_pidfd_registry()
                .lock()
                .expect("registry lock")
                .insert(runner_id.clone(), registry_dup);
            std::mem::forget(child);

            kill(Pid::from_raw(pid), Signal::SIGKILL).expect("kill SIGKILL");

            let deadline = Instant::now() + Duration::from_secs(3);
            let mut reaped = None;
            let mut outcome = TargetedReapOutcome::StillAlive;
            while Instant::now() < deadline {
                outcome = targeted_reap_runner(&runner_id, pidfd.as_fd());
                if let Some(n) = child_reap_buffer()
                    .lock()
                    .expect("child_reap_buffer lock")
                    .iter()
                    .find(|n| n.runner_id == runner_id)
                    .cloned()
                {
                    reaped = Some(n);
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }

            let notif = reaped.expect("targeted reap should observe the signaled child");
            assert_eq!(outcome, TargetedReapOutcome::Reaped);
            assert_eq!(notif.exit_status.kind, ChildExitKind::Killed);
            assert_eq!(notif.exit_status.signal, Some(libc::SIGKILL));
        }

        #[test]
        fn targeted_reap_echild_clears_stale_registry_entry() {
            // If the SIGCHLD loop already reaped the child, a later
            // targeted reap sees ECHILD and must drop the stale entry
            // rather than leaving a dangling pidfd.
            let _guard = ReapTestGuard::new();

            let child = Command::new("true").spawn().expect("spawn true child");
            let pid = child.id() as i32;
            let runner_id = format!("test-vm:targeted-echild-{pid}");
            let pidfd = crate::sys::pidfd_sys::pidfd_open(pid, 0).expect("pidfd_open");
            let registry_dup = pidfd.try_clone().expect("dup pidfd for registry");
            runner_pidfd_registry()
                .lock()
                .expect("registry lock")
                .insert(runner_id.clone(), registry_dup);
            runner_metadata_registry()
                .lock()
                .expect("metadata lock")
                .insert(runner_id.clone(), test_runner_registration(pid, 1));

            // Reap the child out-of-band so the pidfd waitid yields ECHILD.
            let _ = nix::sys::wait::waitpid(Pid::from_raw(pid), None);
            std::mem::forget(child);

            let outcome = targeted_reap_runner(&runner_id, pidfd.as_fd());
            assert_eq!(outcome, TargetedReapOutcome::AlreadyReaped);

            assert!(
                !runner_pidfd_registry()
                    .lock()
                    .expect("registry lock")
                    .contains_key(&runner_id),
                "ECHILD must clear the stale registry entry"
            );
            assert!(
                !runner_metadata_registry()
                    .lock()
                    .expect("metadata lock")
                    .contains_key(&runner_id),
                "ECHILD must clear stale runner metadata"
            );
        }

        #[test]
        fn reap_buffer_overflow_drops_oldest() {
            let _guard = ReapTestGuard::new();

            for i in 0..=CHILD_REAP_BUFFER_CAP {
                push_child_reap_notification(ChildReapedNotification {
                    runner_id: format!("overflow-{i}"),
                    pid: i as i32,
                    exit_status: ChildExitStatus {
                        kind: ChildExitKind::Exited,
                        code: Some(0),
                        signal: None,
                    },
                    reaped_at_ms: 0,
                });
            }

            let drained = drain_child_reap_buffer();
            assert_eq!(drained.len(), CHILD_REAP_BUFFER_CAP);
            assert!(!drained.iter().any(|n| n.runner_id == "overflow-0"));
            assert!(drained.iter().any(|n| n.runner_id == "overflow-256"));
        }
    }
}
