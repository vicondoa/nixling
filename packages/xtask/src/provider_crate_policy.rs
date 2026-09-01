//! Provider crate layout policy.
//!
//! Cargo metadata is the source of truth for workspace membership. The
//! filesystem scan is intentionally separate: a Provider-shaped crate can
//! exist under `packages/` without appearing in the workspace member list,
//! and that omission must fail closed rather than making the crate invisible
//! to this policy.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use serde::{Deserialize, Serialize};

const PROVIDER_PREFIX: &str = "d2b-provider-";
const NON_PROVIDER_PREFIXED: &[&str] = &[
    "d2b-provider",
    "d2b-provider-config-nixos",
    "d2b-provider-supervisor",
    "d2b-provider-toolkit",
];

/// One row in the accepted Provider catalog.
///
/// The matrix is deliberately kept beside the workspace policy.  Cargo
/// metadata proves which crates exist, while this closed table proves that a
/// crate, dossier, owner-local test, and aggregate target describe the same
/// accepted Provider identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProviderMatrixRow {
    pub(crate) identity: &'static str,
    pub(crate) crate_name: &'static str,
    pub(crate) source_path: &'static str,
    pub(crate) test_path: &'static str,
    pub(crate) dossier_path: &'static str,
    pub(crate) bazel_target: &'static str,
    pub(crate) unit: &'static str,
    pub(crate) bootstrap: bool,
}

/// The closed initial Provider matrix from the generic reconciler plan.
pub(crate) const PROVIDER_MATRIX: &[ProviderMatrixRow] = &[
    ProviderMatrixRow {
        identity: "system-core",
        crate_name: "d2b-provider-system-core",
        source_path: "packages/d2b-provider-system-core/src/host_reconciler.rs",
        test_path: "packages/d2b-provider-system-core/tests/host_reconciliation.rs",
        dossier_path: "docs/specs/providers/ADR-046-provider-system-core.md",
        bazel_target: "//packages/d2b-provider-system-core:all-tests",
        unit: "U5",
        bootstrap: true,
    },
    ProviderMatrixRow {
        identity: "system-systemd",
        crate_name: "d2b-provider-system-systemd",
        source_path: "packages/d2b-provider-system-systemd/src/controller.rs",
        test_path: "packages/d2b-provider-system-systemd/tests/controller.rs",
        dossier_path: "docs/specs/providers/ADR-046-provider-system-systemd.md",
        bazel_target: "//packages/d2b-provider-system-systemd:all-tests",
        unit: "U5",
        bootstrap: false,
    },
    ProviderMatrixRow {
        identity: "system-minijail",
        crate_name: "d2b-provider-system-minijail",
        source_path: "packages/d2b-provider-system-minijail/src/launch.rs",
        test_path: "packages/d2b-provider-system-minijail/tests/conformance.rs",
        dossier_path: "docs/specs/providers/ADR-046-provider-system-minijail.md",
        bazel_target: "//packages/d2b-provider-system-minijail:all-tests",
        unit: "U5",
        bootstrap: true,
    },
    ProviderMatrixRow {
        identity: "runtime-cloud-hypervisor",
        crate_name: "d2b-provider-runtime-cloud-hypervisor",
        source_path: "packages/d2b-provider-runtime-cloud-hypervisor/src/controller.rs",
        test_path: "packages/d2b-provider-runtime-cloud-hypervisor/tests/reconcile_state_machine_test.rs",
        dossier_path: "docs/specs/providers/ADR-046-provider-runtime-cloud-hypervisor.md",
        bazel_target: "//packages/d2b-provider-runtime-cloud-hypervisor:all-tests",
        unit: "U6",
        bootstrap: false,
    },
    ProviderMatrixRow {
        identity: "runtime-qemu-media",
        crate_name: "d2b-provider-runtime-qemu-media",
        source_path: "packages/d2b-provider-runtime-qemu-media/src/controller/reconcile.rs",
        test_path: "packages/d2b-provider-runtime-qemu-media/tests/lifecycle.rs",
        dossier_path: "docs/specs/providers/ADR-046-provider-runtime-qemu-media.md",
        bazel_target: "//packages/d2b-provider-runtime-qemu-media:all-tests",
        unit: "U6",
        bootstrap: false,
    },
    ProviderMatrixRow {
        identity: "runtime-azure-container-apps",
        crate_name: "d2b-provider-runtime-azure-container-apps",
        source_path: "packages/d2b-provider-runtime-azure-container-apps/src/controller.rs",
        test_path: "packages/d2b-provider-runtime-azure-container-apps/tests/provider_lifecycle.rs",
        dossier_path: "docs/specs/providers/ADR-046-provider-runtime-azure-container-apps.md",
        bazel_target: "//packages/d2b-provider-runtime-azure-container-apps:all-tests",
        unit: "U6",
        bootstrap: false,
    },
    ProviderMatrixRow {
        identity: "runtime-azure-virtual-machine",
        crate_name: "d2b-provider-runtime-azure-virtual-machine",
        source_path: "packages/d2b-provider-runtime-azure-virtual-machine/src/controller/mod.rs",
        test_path: "packages/d2b-provider-runtime-azure-virtual-machine/tests/lifecycle_hermetic.rs",
        dossier_path: "docs/specs/providers/ADR-046-provider-runtime-azure-virtual-machine.md",
        bazel_target: "//packages/d2b-provider-runtime-azure-virtual-machine:all-tests",
        unit: "U6",
        bootstrap: false,
    },
    ProviderMatrixRow {
        identity: "volume-local",
        crate_name: "d2b-provider-volume-local",
        source_path: "packages/d2b-provider-volume-local/src/controller.rs",
        test_path: "packages/d2b-provider-volume-local/tests/volume_local.rs",
        dossier_path: "docs/specs/providers/ADR-046-provider-volume-local.md",
        bazel_target: "//packages/d2b-provider-volume-local:all-tests",
        unit: "U7",
        bootstrap: false,
    },
    ProviderMatrixRow {
        identity: "volume-virtiofs",
        crate_name: "d2b-provider-volume-virtiofs",
        source_path: "packages/d2b-provider-volume-virtiofs/src/controller.rs",
        test_path: "packages/d2b-provider-volume-virtiofs/tests/lifecycle.rs",
        dossier_path: "docs/specs/providers/ADR-046-provider-volume-virtiofs.md",
        bazel_target: "//packages/d2b-provider-volume-virtiofs:all-tests",
        unit: "U7",
        bootstrap: false,
    },
    ProviderMatrixRow {
        identity: "network-local",
        crate_name: "d2b-provider-network-local",
        source_path: "packages/d2b-provider-network-local/src/controller.rs",
        test_path: "packages/d2b-provider-network-local/tests/reconcile.rs",
        dossier_path: "docs/specs/providers/ADR-046-provider-network-local.md",
        bazel_target: "//packages/d2b-provider-network-local:all-tests",
        unit: "U8",
        bootstrap: false,
    },
    ProviderMatrixRow {
        identity: "device-tpm",
        crate_name: "d2b-provider-device-tpm",
        source_path: "packages/d2b-provider-device-tpm/src/resource_controller.rs",
        test_path: "packages/d2b-provider-device-tpm/tests/resource_controller.rs",
        dossier_path: "docs/specs/providers/ADR-046-provider-device-tpm.md",
        bazel_target: "//packages/d2b-provider-device-tpm:all-tests",
        unit: "U8",
        bootstrap: false,
    },
    ProviderMatrixRow {
        identity: "device-usbip",
        crate_name: "d2b-provider-device-usbip",
        source_path: "packages/d2b-provider-device-usbip/src/controller.rs",
        test_path: "packages/d2b-provider-device-usbip/tests/service_binding_lifecycle.rs",
        dossier_path: "docs/specs/providers/ADR-046-provider-device-usbip.md",
        bazel_target: "//packages/d2b-provider-device-usbip:all-tests",
        unit: "U8",
        bootstrap: false,
    },
    ProviderMatrixRow {
        identity: "device-security-key",
        crate_name: "d2b-provider-device-security-key",
        source_path: "packages/d2b-provider-device-security-key/src/controller.rs",
        test_path: "packages/d2b-provider-device-security-key/tests/lease_state_machine.rs",
        dossier_path: "docs/specs/providers/ADR-046-provider-device-security-key.md",
        bazel_target: "//packages/d2b-provider-device-security-key:all-tests",
        unit: "U8",
        bootstrap: false,
    },
    ProviderMatrixRow {
        identity: "device-gpu",
        crate_name: "d2b-provider-device-gpu",
        source_path: "packages/d2b-provider-device-gpu/src/controller.rs",
        test_path: "packages/d2b-provider-device-gpu/tests/combined_reconcile.rs",
        dossier_path: "docs/specs/providers/ADR-046-provider-device-gpu.md",
        bazel_target: "//packages/d2b-provider-device-gpu:all-tests",
        unit: "U8",
        bootstrap: false,
    },
    ProviderMatrixRow {
        identity: "display-wayland",
        crate_name: "d2b-provider-display-wayland",
        source_path: "packages/d2b-provider-display-wayland/src/controller.rs",
        test_path: "packages/d2b-provider-display-wayland/tests/provider_behavior.rs",
        dossier_path: "docs/specs/providers/ADR-046-provider-display-wayland.md",
        bazel_target: "//packages/d2b-provider-display-wayland:all-tests",
        unit: "U9",
        bootstrap: false,
    },
    ProviderMatrixRow {
        identity: "audio-pipewire",
        crate_name: "d2b-provider-audio-pipewire",
        source_path: "packages/d2b-provider-audio-pipewire/src/controller.rs",
        test_path: "packages/d2b-provider-audio-pipewire/tests/controller.rs",
        dossier_path: "docs/specs/providers/ADR-046-provider-audio-pipewire.md",
        bazel_target: "//packages/d2b-provider-audio-pipewire:all-tests",
        unit: "U9",
        bootstrap: false,
    },
    ProviderMatrixRow {
        identity: "clipboard-wayland",
        crate_name: "d2b-provider-clipboard-wayland",
        source_path: "packages/d2b-provider-clipboard-wayland/src/controller/mod.rs",
        test_path: "packages/d2b-provider-clipboard-wayland/tests/provider_behavior.rs",
        dossier_path: "docs/specs/providers/ADR-046-provider-clipboard-wayland.md",
        bazel_target: "//packages/d2b-provider-clipboard-wayland:all-tests",
        unit: "U9",
        bootstrap: false,
    },
    ProviderMatrixRow {
        identity: "notification-desktop",
        crate_name: "d2b-provider-notification-desktop",
        source_path: "packages/d2b-provider-notification-desktop/src/controller.rs",
        test_path: "packages/d2b-provider-notification-desktop/tests/provider_behavior.rs",
        dossier_path: "docs/specs/providers/ADR-046-provider-notification-desktop.md",
        bazel_target: "//packages/d2b-provider-notification-desktop:all-tests",
        unit: "U9",
        bootstrap: false,
    },
    ProviderMatrixRow {
        identity: "shell-terminal",
        crate_name: "d2b-provider-shell-terminal",
        source_path: "packages/d2b-provider-shell-terminal/src/service/controller.rs",
        test_path: "packages/d2b-provider-shell-terminal/tests/controller_reconcile.rs",
        dossier_path: "docs/specs/providers/ADR-046-provider-shell-terminal.md",
        bazel_target: "//packages/d2b-provider-shell-terminal:all-tests",
        unit: "U9",
        bootstrap: false,
    },
    ProviderMatrixRow {
        identity: "credential-secret-service",
        crate_name: "d2b-provider-credential-secret-service",
        source_path: "packages/d2b-provider-credential-secret-service/src/controller.rs",
        test_path: "packages/d2b-provider-credential-secret-service/tests/session.rs",
        dossier_path: "docs/specs/providers/ADR-046-provider-credential-secret-service.md",
        bazel_target: "//packages/d2b-provider-credential-secret-service:all-tests",
        unit: "U10",
        bootstrap: false,
    },
    ProviderMatrixRow {
        identity: "credential-entra",
        crate_name: "d2b-provider-credential-entra",
        source_path: "packages/d2b-provider-credential-entra/src/controller.rs",
        test_path: "packages/d2b-provider-credential-entra/tests/controller.rs",
        dossier_path: "docs/specs/providers/ADR-046-provider-credential-entra.md",
        bazel_target: "//packages/d2b-provider-credential-entra:all-tests",
        unit: "U10",
        bootstrap: false,
    },
    ProviderMatrixRow {
        identity: "credential-managed-identity",
        crate_name: "d2b-provider-credential-managed-identity",
        source_path: "packages/d2b-provider-credential-managed-identity/src/controller.rs",
        test_path: "packages/d2b-provider-credential-managed-identity/tests/binding.rs",
        dossier_path: "docs/specs/providers/ADR-046-provider-credential-managed-identity.md",
        bazel_target: "//packages/d2b-provider-credential-managed-identity:all-tests",
        unit: "U10",
        bootstrap: false,
    },
    ProviderMatrixRow {
        identity: "transport-unix",
        crate_name: "d2b-provider-transport-unix",
        source_path: "packages/d2b-provider-transport-unix/src/portal.rs",
        test_path: "packages/d2b-provider-transport-unix/tests/transport.rs",
        dossier_path: "docs/specs/providers/ADR-046-provider-transport-unix.md",
        bazel_target: "//packages/d2b-provider-transport-unix:all-tests",
        unit: "U11",
        bootstrap: false,
    },
    ProviderMatrixRow {
        identity: "transport-vsock",
        crate_name: "d2b-provider-transport-vsock",
        source_path: "packages/d2b-provider-transport-vsock/src/service.rs",
        test_path: "packages/d2b-provider-transport-vsock/tests/service.rs",
        dossier_path: "docs/specs/providers/ADR-046-provider-transport-vsock.md",
        bazel_target: "//packages/d2b-provider-transport-vsock:all-tests",
        unit: "U11",
        bootstrap: false,
    },
    ProviderMatrixRow {
        identity: "transport-azure-relay",
        crate_name: "d2b-provider-transport-azure-relay",
        source_path: "packages/d2b-provider-transport-azure-relay/src/relay_transport.rs",
        test_path: "packages/d2b-provider-transport-azure-relay/tests/fake_relay_transport.rs",
        dossier_path: "docs/specs/providers/ADR-046-provider-transport-azure-relay.md",
        bazel_target: "//packages/d2b-provider-transport-azure-relay:all-tests",
        unit: "U11",
        bootstrap: false,
    },
    ProviderMatrixRow {
        identity: "observability-otel",
        crate_name: "d2b-provider-observability-otel",
        source_path: "packages/d2b-provider-observability-otel/src/controller.rs",
        test_path: "packages/d2b-provider-observability-otel/tests/binding_controller.rs",
        dossier_path: "docs/specs/providers/ADR-046-provider-observability-otel.md",
        bazel_target: "//packages/d2b-provider-observability-otel:all-tests",
        unit: "U12",
        bootstrap: false,
    },
    ProviderMatrixRow {
        identity: "activation-nixos",
        crate_name: "d2b-provider-activation-nixos",
        source_path: "packages/d2b-provider-activation-nixos/src/controller.rs",
        test_path: "packages/d2b-provider-activation-nixos/tests/reconcile.rs",
        dossier_path: "docs/specs/providers/ADR-046-provider-activation-nixos.md",
        bazel_target: "//packages/d2b-provider-activation-nixos:all-tests",
        unit: "U12",
        bootstrap: false,
    },
];
// These exact README-only integration placeholders are recorded in the
// existing Provider-state canon. They are not exemptions from the four
// required paths or the README sections, and new crates cannot join the set.
const README_ONLY_INTEGRATION_RATCHET: &[&str] = &[
    "d2b-provider-credential-entra",
    "d2b-provider-credential-managed-identity",
    "d2b-provider-credential-secret-service",
    "d2b-provider-system-core",
    "d2b-provider-system-minijail",
    "d2b-provider-system-systemd",
    "d2b-provider-volume-virtiofs",
];

const REQUIRED_PATHS: &[&str] = &["src", "tests", "integration", "README.md"];
const REQUIRED_README_SECTIONS: &[&str] = &[
    "Provider identity",
    "Config schema",
    "Exported resource types",
    "Controllers / services / workers / binaries",
    "Placement and dependencies",
    "RBAC requirements",
    "Security posture",
    "State and telemetry",
    "Build and test",
];

#[derive(Debug, Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoPackage>,
    workspace_members: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CargoPackage {
    id: String,
    name: String,
    manifest_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WorkspaceMember {
    package_name: String,
    crate_dir: PathBuf,
    manifest_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OnDiskProvider {
    directory_name: String,
    manifest_path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProviderNameKind {
    NonProvider,
    Provider,
    Malformed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct Diagnostic {
    error: &'static str,
    #[serde(rename = "crate")]
    crate_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    missing: Option<Vec<String>>,
}

impl Diagnostic {
    fn path_missing(crate_name: &str, missing: Vec<String>) -> Self {
        Self {
            error: "missing-provider-crate-path",
            crate_name: diagnostic_name(crate_name),
            missing: Some(missing),
        }
    }

    fn readme_sections_missing(crate_name: &str, missing: Vec<String>) -> Self {
        Self {
            error: "missing-provider-readme-section",
            crate_name: diagnostic_name(crate_name),
            missing: Some(missing),
        }
    }

    fn simple(error: &'static str, crate_name: &str) -> Self {
        Self {
            error,
            crate_name: diagnostic_name(crate_name),
            missing: None,
        }
    }

    fn matrix_path(error: &'static str, crate_name: &str, path: &str) -> Self {
        Self {
            error,
            crate_name: diagnostic_name(crate_name),
            missing: Some(vec![path.to_owned()]),
        }
    }

    fn render(&self) -> String {
        serde_json::to_string(self).expect("fixed Provider policy diagnostic serializes")
    }
}

/// Check the normative layout of every Provider workspace member and ensure
/// every Provider-shaped crate on disk is represented by Cargo metadata.
pub fn check(repo_root: &Path) -> Result<(), String> {
    let repo_root = repo_root
        .canonicalize()
        .map_err(|_| "provider-crate-layout-input-unreadable".to_owned())?;
    let members = cargo_workspace_members(&repo_root)?;
    check_members(&repo_root, members.clone())?;
    check_closed_matrix(&repo_root, &members)
}

fn check_closed_matrix(
    repo_root: &Path,
    members: &[WorkspaceMember],
) -> Result<(), String> {
    let expected: BTreeSet<&str> = PROVIDER_MATRIX
        .iter()
        .map(|row| row.crate_name)
        .collect();
    let actual: BTreeSet<&str> = members
        .iter()
        .filter(|member| provider_name_kind(&member.package_name) == ProviderNameKind::Provider)
        .map(|member| member.package_name.as_str())
        .collect();
    let mut violations = Vec::new();

    for crate_name in expected.difference(&actual) {
        violations.push(Diagnostic::simple(
            "provider-matrix-row-missing",
            crate_name,
        ));
    }
    for crate_name in actual.difference(&expected) {
        violations.push(Diagnostic::simple(
            "provider-matrix-row-unexpected",
            crate_name,
        ));
    }

    for row in PROVIDER_MATRIX {
        let Some(member) = members
            .iter()
            .find(|member| member.package_name == row.crate_name)
        else {
            continue;
        };

        let dossier = repo_root.join(row.dossier_path);
        if !dossier.is_file() {
            violations.push(Diagnostic::matrix_path(
                "provider-matrix-dossier-missing",
                row.crate_name,
                row.dossier_path,
            ));
        } else {
            let expected_spec_id = format!("| Spec ID | `ADR-046-provider-{}` |", row.identity);
            let spec_id_count = fs::read_to_string(&dossier)
                .map(|text| {
                    text.lines()
                        .filter(|line| line.trim() == expected_spec_id)
                        .count()
                })
                .unwrap_or(0);
            if spec_id_count != 1 {
                violations.push(Diagnostic::simple(
                    "provider-matrix-dossier-identity-mismatch",
                    row.crate_name,
                ));
            }
        }

        let build = member.crate_dir.join("BUILD.bazel");
        let has_aggregate_target = fs::read_to_string(&build)
            .map(|text| text.contains("name = \"all-tests\""))
            .unwrap_or(false);
        if !has_aggregate_target {
            violations.push(Diagnostic::matrix_path(
                "provider-matrix-test-target-missing",
                row.crate_name,
                row.bazel_target,
            ));
        }
    }

    violations.sort_by(|left, right| {
        left.crate_name
            .cmp(&right.crate_name)
            .then_with(|| left.error.cmp(right.error))
            .then_with(|| left.missing.cmp(&right.missing))
    });
    violations.dedup();

    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations
            .iter()
            .map(Diagnostic::render)
            .collect::<Vec<_>>()
            .join("\n"))
    }
}

fn check_members(repo_root: &Path, members: Vec<WorkspaceMember>) -> Result<(), String> {
    let on_disk = on_disk_providers(&repo_root)?;
    let has_provider_member = members
        .iter()
        .any(|member| provider_name_kind(&member.package_name) == ProviderNameKind::Provider);
    if !has_provider_member && on_disk.is_empty() {
        return Err("provider-crate-layout-empty-scope".to_owned());
    }

    let member_by_manifest: BTreeMap<PathBuf, &WorkspaceMember> = members
        .iter()
        .map(|member| (member.manifest_path.clone(), member))
        .collect();
    let mut violations = Vec::new();

    for member in &members {
        match provider_name_kind(&member.package_name) {
            ProviderNameKind::Provider => {
                if !is_provider_directory(&repo_root, &member.crate_dir, &member.package_name) {
                    violations.push(Diagnostic::simple(
                        "provider-crate-location-invalid",
                        &member.package_name,
                    ));
                } else {
                    violations.extend(inspect_crate(member)?);
                }
            }
            ProviderNameKind::Malformed => violations.push(Diagnostic::simple(
                "provider-crate-name-invalid",
                &member.package_name,
            )),
            ProviderNameKind::NonProvider => {}
        }
    }

    for crate_on_disk in on_disk {
        match member_by_manifest.get(&crate_on_disk.manifest_path) {
            None => violations.push(Diagnostic::simple(
                "provider-crate-not-workspace-member",
                &crate_on_disk.directory_name,
            )),
            Some(member) => {
                if member.package_name != crate_on_disk.directory_name {
                    violations.push(Diagnostic::simple(
                        "provider-crate-name-mismatch",
                        &crate_on_disk.directory_name,
                    ));
                }
                if provider_name_kind(&crate_on_disk.directory_name) == ProviderNameKind::Malformed
                {
                    violations.push(Diagnostic::simple(
                        "provider-crate-name-invalid",
                        &crate_on_disk.directory_name,
                    ));
                }
            }
        }
    }

    violations.sort_by(|left, right| {
        left.crate_name
            .cmp(&right.crate_name)
            .then_with(|| left.error.cmp(right.error))
            .then_with(|| left.missing.cmp(&right.missing))
    });
    violations.dedup();

    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations
            .iter()
            .map(Diagnostic::render)
            .collect::<Vec<_>>()
            .join("\n"))
    }
}

fn cargo_workspace_members(repo_root: &Path) -> Result<Vec<WorkspaceMember>, String> {
    let metadata = cargo_metadata(repo_root)?;
    let packages_by_id: BTreeMap<&str, &CargoPackage> = metadata
        .packages
        .iter()
        .map(|package| (package.id.as_str(), package))
        .collect();

    let mut members = Vec::new();
    for member_id in metadata.workspace_members {
        let package = packages_by_id
            .get(member_id.as_str())
            .ok_or_else(|| "provider-crate-layout-metadata-member-missing".to_owned())?;
        let manifest_path = package
            .manifest_path
            .canonicalize()
            .map_err(|_| "provider-crate-layout-member-invalid".to_owned())?;
        let crate_dir = manifest_path
            .parent()
            .ok_or_else(|| "provider-crate-layout-member-invalid".to_owned())?
            .to_owned();
        members.push(WorkspaceMember {
            package_name: package.name.clone(),
            crate_dir,
            manifest_path,
        });
    }
    if members.is_empty() {
        return Err("provider-crate-layout-members-empty".to_owned());
    }
    Ok(members)
}

fn cargo_metadata(repo_root: &Path) -> Result<CargoMetadata, String> {
    let cargo = std::env::var_os("CARGO")
        .map(PathBuf::from)
        .map(|path| {
            if path.is_relative() {
                std::env::current_dir()
                    .map(|current| current.join(path))
                    .unwrap_or_else(|_| PathBuf::from("cargo"))
            } else {
                path
            }
        })
        .unwrap_or_else(|| PathBuf::from("cargo"));
    let mut command = Command::new(cargo);
    if let Some(tmpdir) = std::env::var_os("TEST_TMPDIR") {
        let cargo_home = PathBuf::from(tmpdir).join("cargo-home");
        fs::create_dir_all(&cargo_home)
            .map_err(|_| "provider-crate-layout-metadata-home-unavailable".to_owned())?;
        command.env("CARGO_HOME", cargo_home);
    }
    let output = command
        .current_dir(repo_root)
        .args([
            "metadata",
            "--no-deps",
            "--format-version",
            "1",
            "--manifest-path",
        ])
        .arg(repo_root.join("Cargo.toml"))
        .output()
        .map_err(|_| "provider-crate-layout-metadata-unavailable".to_owned())?;
    if !output.status.success() {
        return Err("provider-crate-layout-metadata-failed".to_owned());
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|_| "provider-crate-layout-metadata-malformed".to_owned())
}

fn on_disk_providers(repo_root: &Path) -> Result<Vec<OnDiskProvider>, String> {
    let packages_dir = repo_root.join("packages");
    let entries = fs::read_dir(&packages_dir)
        .map_err(|_| "provider-crate-layout-packages-unreadable".to_owned())?;
    let mut providers = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| "provider-crate-layout-packages-unreadable".to_owned())?;
        let file_type = entry
            .file_type()
            .map_err(|_| "provider-crate-layout-packages-unreadable".to_owned())?;
        if !file_type.is_dir() {
            continue;
        }
        let directory_name = entry
            .file_name()
            .to_str()
            .ok_or_else(|| "provider-crate-layout-member-invalid".to_owned())?
            .to_owned();
        if !directory_name.starts_with(PROVIDER_PREFIX) {
            continue;
        }
        let manifest_path = entry.path().join("Cargo.toml");
        if !manifest_path.is_file() {
            continue;
        }
        if matches!(
            provider_name_kind(&directory_name),
            ProviderNameKind::NonProvider
        ) {
            continue;
        }
        providers.push(OnDiskProvider {
            directory_name,
            manifest_path: manifest_path
                .canonicalize()
                .map_err(|_| "provider-crate-layout-member-invalid".to_owned())?,
        });
    }
    providers.sort_by(|left, right| left.directory_name.cmp(&right.directory_name));
    Ok(providers)
}

fn provider_name_kind(name: &str) -> ProviderNameKind {
    if NON_PROVIDER_PREFIXED.contains(&name) {
        return ProviderNameKind::NonProvider;
    }
    let Some(rest) = name.strip_prefix(PROVIDER_PREFIX) else {
        return ProviderNameKind::NonProvider;
    };
    let segments: Vec<_> = rest.split('-').collect();
    if segments.len() < 2 || segments.iter().any(|segment| !valid_name_segment(segment)) {
        ProviderNameKind::Malformed
    } else {
        ProviderNameKind::Provider
    }
}

fn valid_name_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment.len() <= 64
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn diagnostic_name(name: &str) -> String {
    if name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        name.to_owned()
    } else {
        "<invalid-provider-crate>".to_owned()
    }
}

fn is_provider_directory(repo_root: &Path, crate_dir: &Path, package_name: &str) -> bool {
    let Some(packages_dir) = repo_root.join("packages").canonicalize().ok() else {
        return false;
    };
    crate_dir.parent() == Some(packages_dir.as_path())
        && crate_dir
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name == package_name)
}

fn inspect_crate(member: &WorkspaceMember) -> Result<Vec<Diagnostic>, String> {
    let crate_name = &member.package_name;
    let mut violations = Vec::new();
    let mut missing = Vec::new();

    for required in REQUIRED_PATHS {
        let path = member.crate_dir.join(required);
        let present = if *required == "README.md" {
            path.is_file()
        } else {
            path.is_dir()
        };
        if !present {
            missing.push((*required).to_owned());
        }
    }
    if member.crate_dir.join("src").is_dir() && !contains_rust_file(&member.crate_dir.join("src"))?
    {
        missing.push("src/*.rs".to_owned());
    }
    if member.crate_dir.join("tests").is_dir()
        && !contains_rust_file(&member.crate_dir.join("tests"))?
    {
        missing.push("tests/*.rs".to_owned());
    }

    let integration = member.crate_dir.join("integration");
    if integration.is_dir() {
        if !integration.join("README.md").is_file() {
            missing.push("integration/README.md".to_owned());
        }
        let has_rust_scenario = integration_has_rust_scenario(&integration)?;
        if !has_rust_scenario && !README_ONLY_INTEGRATION_RATCHET.contains(&crate_name.as_str()) {
            missing.push("integration/*.rs".to_owned());
        }
        if has_rust_scenario && README_ONLY_INTEGRATION_RATCHET.contains(&crate_name.as_str()) {
            return Err("provider-crate-layout-stale-exemption".to_owned());
        }
    }

    missing.sort();
    missing.dedup();
    if !missing.is_empty() {
        violations.push(Diagnostic::path_missing(crate_name, missing));
    }

    let readme = member.crate_dir.join("README.md");
    if readme.is_file() {
        let text = fs::read_to_string(&readme)
            .map_err(|_| "provider-crate-layout-readme-unreadable".to_owned())?;
        let present: BTreeSet<String> = text.lines().filter_map(heading_text).collect();
        let missing_sections = REQUIRED_README_SECTIONS
            .iter()
            .filter(|section| !present.contains(&section.to_lowercase()))
            .map(|section| format!("README.md section: {section}"))
            .collect::<Vec<_>>();
        if !missing_sections.is_empty() {
            violations.push(Diagnostic::readme_sections_missing(
                crate_name,
                missing_sections,
            ));
        }
    }

    Ok(violations)
}

fn heading_text(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let stripped = trimmed.strip_prefix('#')?;
    Some(stripped.trim_start_matches('#').trim().to_lowercase())
}

fn contains_rust_file(root: &Path) -> Result<bool, String> {
    let entries =
        fs::read_dir(root).map_err(|_| "provider-crate-layout-source-unreadable".to_owned())?;
    for entry in entries {
        let entry = entry.map_err(|_| "provider-crate-layout-source-unreadable".to_owned())?;
        let file_type = entry
            .file_type()
            .map_err(|_| "provider-crate-layout-source-unreadable".to_owned())?;
        if file_type.is_file()
            && entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "rs")
        {
            return Ok(true);
        }
        if file_type.is_dir() && contains_rust_file(&entry.path())? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn integration_has_rust_scenario(integration: &Path) -> Result<bool, String> {
    let entries = fs::read_dir(integration)
        .map_err(|_| "provider-crate-layout-integration-unreadable".to_owned())?;
    for entry in entries {
        let entry = entry.map_err(|_| "provider-crate-layout-integration-unreadable".to_owned())?;
        let file_type = entry
            .file_type()
            .map_err(|_| "provider-crate-layout-integration-unreadable".to_owned())?;
        if file_type.is_file()
            && entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "rs")
        {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use crate::repo_root;

    use super::*;

    static FIXTURE_COUNTER: AtomicU32 = AtomicU32::new(0);

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            let serial = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "d2b-provider-layout-{}-{serial}-{label}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&root).unwrap();
            write_package(&root, "d2b-core");
            write_package(&root, "d2b-provider-fixture-example");
            let provider = root.join("packages/d2b-provider-fixture-example");
            fs::create_dir_all(provider.join("integration")).unwrap();
            fs::create_dir_all(provider.join("tests")).unwrap();
            fs::write(
                provider.join("tests/scenario.rs"),
                "#[test]\nfn fixture() {}\n",
            )
            .unwrap();
            fs::write(
                provider.join("integration/README.md"),
                "# integration fixtures\n",
            )
            .unwrap();
            fs::write(
                provider.join("integration/scenario.rs"),
                "//! integration-target: container\n",
            )
            .unwrap();
            fs::write(
                provider.join("README.md"),
                required_readme("fixture-example"),
            )
            .unwrap();
            fs::write(
                root.join("Cargo.toml"),
                "[workspace]\nmembers = [\n    \"packages/d2b-core\",\n    \"packages/d2b-provider-fixture-example\",\n]\n",
            )
            .unwrap();
            Self { root }
        }

        fn provider_dir(&self) -> PathBuf {
            self.root.join("packages/d2b-provider-fixture-example")
        }

        fn add_package(&self, name: &str) -> PathBuf {
            write_package(&self.root, name);
            self.root.join("packages").join(name)
        }

        fn set_members(&self, members: &[&str]) {
            let mut manifest = String::from("[workspace]\nmembers = [\n");
            for member in members {
                manifest.push_str(&format!("    \"packages/{member}\",\n"));
            }
            manifest.push_str("]\n");
            fs::write(self.root.join("Cargo.toml"), manifest).unwrap();
        }
    }

    fn manifest_workspace_members(root: &Path) -> Result<Vec<WorkspaceMember>, String> {
        let workspace = fs::read_to_string(root.join("Cargo.toml"))
            .map_err(|_| "provider-crate-layout-metadata-unavailable".to_owned())?;
        let mut members = Vec::new();
        let mut in_members = false;
        for line in workspace.lines() {
            let trimmed = line.trim();
            if trimmed == "members = [" {
                in_members = true;
                continue;
            }
            if !in_members {
                continue;
            }
            if trimmed == "]" {
                break;
            }
            let relative = trimmed.trim_end_matches(',').trim_matches('"');
            let manifest_path = root
                .join(relative)
                .join("Cargo.toml")
                .canonicalize()
                .map_err(|_| "provider-crate-layout-member-invalid".to_owned())?;
            let manifest = fs::read_to_string(&manifest_path)
                .map_err(|_| "provider-crate-layout-member-invalid".to_owned())?;
            let package_name = manifest
                .lines()
                .find_map(|line| line.trim().strip_prefix("name = \""))
                .and_then(|name| name.strip_suffix('"'))
                .ok_or_else(|| "provider-crate-layout-member-invalid".to_owned())?
                .to_owned();
            members.push(WorkspaceMember {
                package_name,
                crate_dir: manifest_path.parent().unwrap().to_owned(),
                manifest_path,
            });
        }
        Ok(members)
    }

    fn check_fixture(root: &Path) -> Result<(), String> {
        let root = root.canonicalize().unwrap();
        check_members(&root, manifest_workspace_members(&root)?)
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn write_package(root: &Path, name: &str) {
        let package = root.join("packages").join(name);
        fs::create_dir_all(package.join("src")).unwrap();
        fs::write(package.join("src/lib.rs"), "").unwrap();
        fs::write(
            package.join("Cargo.toml"),
            format!("[package]\nname = \"{name}\"\nversion = \"0.0.0\"\nedition = \"2024\"\n"),
        )
        .unwrap();
    }

    fn required_readme(identity: &str) -> String {
        let mut readme = String::new();
        for section in REQUIRED_README_SECTIONS {
            readme.push_str(&format!("## {section}\n\n"));
            if *section == "Provider identity" {
                readme.push_str(&format!("| Provider name | `{identity}` |\n\n"));
            }
        }
        readme
    }

    #[test]
    fn conforming_tree_is_idempotent_and_non_provider_members_are_ignored() {
        let fixture = Fixture::new("clean");
        assert_eq!(check_fixture(&fixture.root), Ok(()));
        assert_eq!(check_fixture(&fixture.root), Ok(()));
    }

    #[test]
    fn the_provider_matrix_is_closed_and_has_two_bootstrap_rows() {
        assert_eq!(PROVIDER_MATRIX.len(), 27);

        let identities: BTreeSet<_> = PROVIDER_MATRIX
            .iter()
            .map(|row| row.identity)
            .collect();
        let crates: BTreeSet<_> = PROVIDER_MATRIX
            .iter()
            .map(|row| row.crate_name)
            .collect();
        assert_eq!(identities.len(), PROVIDER_MATRIX.len());
        assert_eq!(crates.len(), PROVIDER_MATRIX.len());
        assert_eq!(
            PROVIDER_MATRIX
                .iter()
                .filter(|row| row.bootstrap)
                .map(|row| row.identity)
                .collect::<Vec<_>>(),
            vec!["system-core", "system-minijail"]
        );
        for row in PROVIDER_MATRIX {
            assert_eq!(row.crate_name, format!("d2b-provider-{}", row.identity));
            assert!(row.bazel_target.ends_with(":all-tests"));
            assert!(row.dossier_path.ends_with(&format!(
                "ADR-046-provider-{}.md",
                row.identity
            )));
            assert!(row.source_path.starts_with("packages/"));
            assert!(row.test_path.starts_with("packages/"));
            assert!(matches!(row.unit, "U5" | "U6" | "U7" | "U8" | "U9" | "U10" | "U11" | "U12"));
        }
    }

    #[test]
    fn the_committed_tree_matches_every_provider_matrix_row() {
        let root = repo_root().expect("resolve repository root");
        let members = cargo_workspace_members(root).expect("read workspace metadata");
        assert_eq!(
            check_closed_matrix(root, &members),
            Ok(()),
            "the committed Provider matrix must have one dossier and aggregate target per row"
        );
    }

    #[test]
    fn every_provider_prefixed_name_has_one_explicit_classification() {
        let root = repo_root().expect("resolve repository root");
        let members = manifest_workspace_members(root).expect("read workspace manifest");
        let mut names: BTreeSet<String> = members
            .into_iter()
            .map(|member| member.package_name)
            .filter(|name| name.starts_with(PROVIDER_PREFIX))
            .collect();
        for entry in fs::read_dir(root.join("packages")).expect("read packages directory") {
            let entry = entry.expect("read package entry");
            if entry.file_type().expect("read package entry type").is_dir() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with(PROVIDER_PREFIX) {
                    names.insert(name);
                }
            }
        }

        assert!(
            !names.is_empty(),
            "Provider-name classification must inspect a non-empty scope"
        );
        for name in names {
            let kind = provider_name_kind(&name);
            match kind {
                ProviderNameKind::NonProvider => {
                    assert!(
                        NON_PROVIDER_PREFIXED.contains(&name.as_str()),
                        "{name} is not an explicit non-Provider helper"
                    );
                }
                ProviderNameKind::Provider => {
                    assert!(
                        name.strip_prefix(PROVIDER_PREFIX)
                            .is_some_and(|suffix| suffix.split('-').count() >= 2),
                        "{name} is not a two-segment Provider identity"
                    );
                }
                ProviderNameKind::Malformed => {
                    assert!(
                        name.starts_with(PROVIDER_PREFIX),
                        "{name} is malformed but not Provider-prefixed"
                    );
                }
            }
        }
    }

    #[test]
    fn readme_only_integration_ratchet_is_exactly_the_scaffolded_set() {
        let expected = [
            "d2b-provider-credential-entra",
            "d2b-provider-credential-managed-identity",
            "d2b-provider-credential-secret-service",
            "d2b-provider-system-core",
            "d2b-provider-system-minijail",
            "d2b-provider-system-systemd",
            "d2b-provider-volume-virtiofs",
        ];
        assert_eq!(
            README_ONLY_INTEGRATION_RATCHET, &expected,
            "README-only integration coverage must remain an explicit closed set"
        );
        let root = repo_root().expect("resolve repository root");
        for name in expected {
            let integration = root.join("packages").join(name).join("integration");
            assert!(
                integration.join("README.md").is_file(),
                "{name} must retain its integration scaffold README"
            );
            assert!(
                !integration_has_rust_scenario(&integration).expect("inspect integration scaffold"),
                "{name} must leave executable integration wiring to its owning implementation"
            );
        }
    }

    #[test]
    fn integration_readme_and_rust_scenario_are_both_required() {
        let fixture = Fixture::new("integration");
        fs::remove_file(fixture.provider_dir().join("integration/README.md")).unwrap();
        fs::remove_file(fixture.provider_dir().join("integration/scenario.rs")).unwrap();

        let error = check_fixture(&fixture.root).unwrap_err();
        eprintln!("synthetic perturbation rejected: {error}");
        assert_eq!(
            error,
            r#"{"error":"missing-provider-crate-path","crate":"d2b-provider-fixture-example","missing":["integration/*.rs","integration/README.md"]}"#
        );
    }

    #[test]
    fn an_on_disk_provider_omitted_from_workspace_is_rejected() {
        let fixture = Fixture::new("non-member");
        let omitted = fixture.add_package("d2b-provider-fixture-omitted");
        fs::create_dir_all(omitted.join("tests")).unwrap();
        fs::create_dir_all(omitted.join("integration")).unwrap();
        fs::write(
            omitted.join("README.md"),
            required_readme("fixture-omitted"),
        )
        .unwrap();

        let error = check_fixture(&fixture.root).unwrap_err();
        assert!(error.contains("provider-crate-not-workspace-member"));
        assert!(error.contains("d2b-provider-fixture-omitted"));
    }

    #[test]
    fn a_malformed_provider_name_is_rejected_instead_of_ignored() {
        let fixture = Fixture::new("malformed");
        fixture.add_package("d2b-provider-fixture");
        fixture.set_members(&[
            "d2b-core",
            "d2b-provider-fixture-example",
            "d2b-provider-fixture",
        ]);

        let error = check_fixture(&fixture.root).unwrap_err();
        assert!(error.contains("provider-crate-name-invalid"));
        assert!(error.contains("d2b-provider-fixture"));
    }

    #[test]
    fn empty_provider_scope_fails_closed() {
        let fixture = Fixture::new("empty");
        fixture.set_members(&["d2b-core"]);
        assert_eq!(
            check_fixture(&fixture.root),
            Err(
                r#"{"error":"provider-crate-not-workspace-member","crate":"d2b-provider-fixture-example"}"#
                    .to_owned()
            )
        );
    }

    #[test]
    fn caller_supplied_workspace_paths_are_never_rendered() {
        let fixture = Fixture::new("redaction");
        let marker = format!("caller-secret-{}", std::process::id());
        fs::write(
            fixture.root.join("Cargo.toml"),
            format!("[workspace]\nmembers = [\n    \"../{marker}\",\n]\n"),
        )
        .unwrap();
        let error = check_fixture(&fixture.root).unwrap_err();
        assert!(!error.contains(&marker));
    }
}
