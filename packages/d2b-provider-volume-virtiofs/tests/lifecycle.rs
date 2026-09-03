//! Hermetic Export lifecycle, sandbox, and privacy conformance.

use d2b_contracts_resource::v3::ResourceRef;
use d2b_contracts_resource::v3::execution_policy::BoundedToken;
use d2b_provider_volume_virtiofs::testing::{PortCall, ScriptedPort, block_on, fixtures};
use d2b_provider_volume_virtiofs::{
    EXPORT_FINALIZER, EXPORT_RESOURCE_TYPE, ExportPhase, ExportSpec, LaunchedWorker,
    VirtiofsExportController, VirtiofsExportEffectPort, VirtiofsExportError, VirtiofsdWorkerPlan,
    virtiofs_runner_contract,
};

struct DefaultMarkerPort {
    inner: ScriptedPort,
}

impl VirtiofsExportEffectPort for &DefaultMarkerPort {
    async fn launch_worker(
        &self,
        export: &ExportSpec,
        plan: &VirtiofsdWorkerPlan,
    ) -> Result<LaunchedWorker, VirtiofsExportError> {
        (&self.inner).launch_worker(export, plan).await
    }

    async fn observe_socket(&self, worker: &LaunchedWorker) -> Result<bool, VirtiofsExportError> {
        (&self.inner).observe_socket(worker).await
    }

    async fn observe_guest_mount(&self, export: &ExportSpec) -> Result<bool, VirtiofsExportError> {
        (&self.inner).observe_guest_mount(export).await
    }

    async fn delete_worker(&self, worker: &LaunchedWorker) -> Result<(), VirtiofsExportError> {
        (&self.inner).delete_worker(worker).await
    }
}

fn reconcile(
    port: &ScriptedPort,
    access: &str,
) -> d2b_provider_volume_virtiofs::ExportStatusReport {
    let controller = VirtiofsExportController::new(port);
    block_on(controller.reconcile(
        &fixtures::export(access),
        &fixtures::store_view_volume(),
        4,
        fixtures::principal(),
    ))
    .expect("reconcile reports")
}

#[test]
fn the_default_marker_probe_fails_closed_before_a_store_view_launch() {
    let port = DefaultMarkerPort {
        inner: ScriptedPort::serving(),
    };
    let controller = VirtiofsExportController::new(&port);
    let report = block_on(controller.reconcile(
        &fixtures::export("read-only"),
        &fixtures::store_view_volume(),
        4,
        fixtures::principal(),
    ))
    .expect("reconcile reports");
    assert_eq!(report.phase, ExportPhase::Pending);
    assert!(report.worker_process_ref.is_none());
    assert!(!port.inner.calls().contains(&PortCall::LaunchWorker));
}

#[test]
fn an_export_reaches_ready_only_when_the_host_serves_and_the_guest_mounts() {
    let port = ScriptedPort::serving();
    let report = reconcile(&port, "read-only");
    assert_eq!(report.phase, ExportPhase::Ready);
    assert!(report.export_ready);
    assert!(report.guest_mount_ready);
    assert!(report.reason.is_none());
    assert_eq!(
        port.calls(),
        vec![
            PortCall::ObserveStoreViewMarker,
            PortCall::LaunchWorker,
            PortCall::ObserveSocket,
            PortCall::ObserveGuestMount,
        ]
    );
}

#[test]
fn a_socket_that_never_listens_holds_the_export_pending() {
    let port = ScriptedPort::serving().socket_never_ready();
    let report = reconcile(&port, "read-only");
    assert_eq!(report.phase, ExportPhase::Pending);
    assert!(!report.export_ready);
    assert_eq!(report.reason, Some(VirtiofsExportError::ExportNotReady));
    // The guest is never probed while the host side is not serving.
    assert!(!port.calls().contains(&PortCall::ObserveGuestMount));
}

#[test]
fn a_store_view_waits_for_its_zero_length_marker_before_launch() {
    let port = ScriptedPort::serving().store_view_marker_missing();
    let report = reconcile(&port, "read-only");
    assert_eq!(report.phase, ExportPhase::Pending);
    assert_eq!(
        report.reason,
        Some(VirtiofsExportError::StoreViewMarkerMissing)
    );
    assert_eq!(port.calls(), vec![PortCall::ObserveStoreViewMarker]);
}

#[test]
fn a_serving_host_whose_guest_does_not_mount_is_degraded() {
    let port = ScriptedPort::serving().guest_never_mounts();
    let report = reconcile(&port, "read-only");
    assert_eq!(report.phase, ExportPhase::Degraded);
    assert!(report.export_ready);
    assert!(!report.guest_mount_ready);
    assert_eq!(report.reason, Some(VirtiofsExportError::GuestMountNotReady));
}

#[test]
fn a_read_only_export_launches_a_read_only_worker() {
    let port = ScriptedPort::serving();
    reconcile(&port, "read-only");
    let plans = port.launched_plans();
    assert_eq!(plans.len(), 1);
    assert!(plans[0].readonly);
    assert_eq!(plans[0].thread_pool_size, 4);
}

#[test]
fn a_write_export_over_a_read_only_view_never_launches_a_worker() {
    let port = ScriptedPort::serving();
    let report = reconcile(&port, "read-write");
    assert_eq!(report.phase, ExportPhase::Failed);
    assert_eq!(
        report.reason,
        Some(VirtiofsExportError::ViewRightsInsufficient)
    );
    assert!(port.calls().is_empty());
    assert!(report.worker_process_ref.is_none());
}

#[test]
fn an_export_naming_an_undeclared_view_is_rejected() {
    let export = ExportSpec::new(
        fixtures::volume_ref(),
        ResourceRef::parse("Guest/work-vm").expect("valid ref"),
        BoundedToken::parse("absent").expect("valid token"),
        d2b_contracts_resource::v3::volume::AttachmentAccess::ReadOnly,
        d2b_contracts_resource::v3::volume::AttachmentSettings::default(),
    )
    .expect("conformant Export");
    let port = ScriptedPort::serving();
    let controller = VirtiofsExportController::new(&port);
    assert_eq!(
        block_on(controller.reconcile(
            &export,
            &fixtures::store_view_volume(),
            4,
            fixtures::principal(),
        ))
        .unwrap_err(),
        VirtiofsExportError::ViewNotFound
    );
    assert!(port.calls().is_empty());
}

#[test]
fn two_exports_of_one_volume_have_distinct_socket_identities() {
    let work = fixtures::export("read-only");
    let other = ExportSpec::new(
        fixtures::volume_ref(),
        ResourceRef::parse("Guest/personal-vm").expect("valid ref"),
        BoundedToken::parse("ro-store").expect("valid token"),
        d2b_contracts_resource::v3::volume::AttachmentAccess::ReadOnly,
        d2b_contracts_resource::v3::volume::AttachmentSettings::default(),
    )
    .expect("conformant Export");
    let zone = fixtures::zone();
    assert_ne!(work.socket_identity(&zone), other.socket_identity(&zone));
    assert_eq!(work.socket_identity(&zone), work.socket_identity(&zone));
}

#[test]
fn a_drain_deletes_the_worker_before_confirming_the_mount_is_gone() {
    let port = ScriptedPort::serving();
    let export = fixtures::export("read-only");
    let controller = VirtiofsExportController::new(&port);
    let report = block_on(controller.reconcile(
        &export,
        &fixtures::store_view_volume(),
        4,
        fixtures::principal(),
    ))
    .expect("reconcile reports");
    let worker = d2b_provider_volume_virtiofs::LaunchedWorker {
        process_ref: report.worker_process_ref.expect("worker exists"),
        socket: report.socket.expect("socket exists"),
    };
    assert!(block_on(controller.drain(&export, &worker)).is_ok());
    let calls = port.calls();
    let deleted = calls
        .iter()
        .position(|call| *call == PortCall::DeleteWorker)
        .expect("worker deleted");
    let confirmed = calls
        .iter()
        .rposition(|call| *call == PortCall::ObserveGuestMount)
        .expect("mount confirmed");
    assert!(deleted < confirmed);
}

#[test]
fn a_mount_that_survives_deletion_blocks_the_drain() {
    let port = ScriptedPort::serving().mount_survives_delete();
    let export = fixtures::export("read-only");
    let controller = VirtiofsExportController::new(&port);
    let worker = d2b_provider_volume_virtiofs::LaunchedWorker {
        process_ref: ResourceRef::parse("Process/vol-work-state-virtiofsd-work-vm")
            .expect("valid ref"),
        socket: export.socket_identity(&fixtures::zone()),
    };
    assert_eq!(
        block_on(controller.drain(&export, &worker)).unwrap_err(),
        VirtiofsExportError::DrainIncomplete
    );
}

/// Fragments that must never appear in a public Export status document.
const FORBIDDEN_STATUS_FRAGMENTS: [&str; 8] = [
    "/run",
    "/nix",
    ".sock",
    "shared-dir",
    "socket-path",
    "socket-group",
    "uid",
    "gid",
];

#[test]
fn public_export_status_carries_no_socket_path_shared_dir_or_argv() {
    let port = ScriptedPort::serving();
    let report = reconcile(&port, "read-only");
    let rendered = serde_json::to_string(&report)
        .expect("status serializes")
        .to_ascii_lowercase();
    for fragment in FORBIDDEN_STATUS_FRAGMENTS {
        assert!(
            !rendered.contains(fragment),
            "public status carries the forbidden fragment {fragment}"
        );
    }
    assert!(rendered.contains("volume-virtiofs"));
    assert_eq!(
        format!("{:?}", report.socket.expect("socket")),
        "SocketIdentity(<redacted>)"
    );
}

#[test]
fn the_provider_owns_only_the_export_resource_type_and_finalizer() {
    assert_eq!(EXPORT_RESOURCE_TYPE, "virtiofs.d2bus.org.Export");
    assert_eq!(EXPORT_FINALIZER, "volume-virtiofs/export");
    let port = ScriptedPort::serving();
    let controller = VirtiofsExportController::new(&port);
    assert_eq!(controller.finalizer(), EXPORT_FINALIZER);
    assert_eq!(controller.provider().as_str(), "volume-virtiofs");
}

#[test]
fn a_virtio_blk_attachment_is_not_translated_into_an_export() {
    let attachment: d2b_contracts_resource::v3::volume::VolumeAttachment =
        serde_json::from_value(serde_json::json!({
            "executionRef": "Guest/work-vm",
            "transport": "virtio-blk",
            "view": "ro-store",
            "access": "read-only",
            "mountPath": "/state",
        }))
        .expect("conformant attachment");
    assert_eq!(
        ExportSpec::from_attachment(fixtures::volume_ref(), &attachment).unwrap_err(),
        VirtiofsExportError::InvalidExport
    );
}

#[test]
fn resource_export_spec_and_children_keep_one_qualified_owner() {
    let spec = serde_json::json!({
        "providerRef": "Provider/volume-virtiofs",
        "volumeRef": "Volume/work-state",
        "executionRef": "Guest/work-vm",
        "view": "ro-store",
        "access": "read-only",
        "mountPath": "/nix/.ro-store",
        "provider": {
            "schemaId": "volume-virtiofs.d2bus.org/Export/spec",
            "schemaVersion": "1.0",
            "settings": {}
        }
    });
    let export = ExportSpec::from_resource_spec(&spec).expect("resource Export spec");
    assert_eq!(
        export.provider_ref().to_canonical_string(),
        "Provider/volume-virtiofs"
    );
    assert_ne!(
        export.worker_process_ref().unwrap(),
        export.endpoint_ref().unwrap()
    );
    let contract = virtiofs_runner_contract();
    assert_eq!(contract.resource_type, EXPORT_RESOURCE_TYPE);
    assert_eq!(contract.finalizer, EXPORT_FINALIZER);
    assert!(contract.watched_configuration_is_dependency);
}
