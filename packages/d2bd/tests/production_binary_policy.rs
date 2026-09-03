use std::{env, fs, path::PathBuf};

fn read_required_d2bd_source(relative: &str) -> String {
    let manifest_root =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap_or_else(|| ".".into()));
    let mut candidates = vec![manifest_root.join(relative)];
    if let Some(repo_root) = env::var_os("D2B_REPO_ROOT") {
        candidates.push(PathBuf::from(repo_root).join("packages/d2bd").join(relative));
    }
    for path in candidates {
        match fs::read_to_string(&path) {
            Ok(source) => return source,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("read required d2bd source {}: {error}", path.display()),
        }
    }
    panic!("required d2bd source is missing: {relative}");
}

#[test]
fn production_binary_contains_no_peer_override_surface() {
    let binary = fs::read(env!("CARGO_BIN_EXE_d2bd")).expect("read production d2bd binary");
    let rendered = String::from_utf8_lossy(&binary);
    assert!(
        !rendered.contains("D2BD_TEST_PEER_"),
        "production d2bd must not contain the peer override environment surface"
    );
    assert!(
        !rendered.contains("peer_override_from_env"),
        "production d2bd must not contain the peer override implementation"
    );
    for retired in [
        "run_exec_owner",
        "dispatch_exec_management",
        "dispatch_read_guest_config",
        "exec_owner_io",
        "load_gateway_file_config",
        "relay_auth_snippet_from_config",
        "gateway_deps_from_config",
        "display_listener_from_config",
        "run_device_binding_watch",
        "device_binding_watch_task",
        "reconcile_semantic_binding_resources",
        "reconcile_wayland_session_deletion",
        "spawn_usbip_reconcile_after_vm_start",
        "UsbipBackgroundReconcileGuard",
        "configure_from_host",
        "compose_host_runtime",
        "reconcile_snapshot",
        "list_activation_snapshot",
        "legacy_scheduler_disabled",
        "CoreRegisteredSource",
        "AcceptanceBatch",
    ] {
        assert!(
            !rendered.contains(retired),
            "production d2bd must not retain retired component-session path {retired}"
        );
    }
    let source = read_required_d2bd_source("src/composition.rs");
    assert!(
        !source.contains("BrokerRequest::OpenHidrawSecurityKey"),
        "production d2bd must not own the security-key hidraw opener"
    );
    let source_paths = [
        "src/composition.rs",
        "src/resource_runtime.rs",
        "src/process_resource_runtime.rs",
        "src/activation_resource_runtime.rs",
        "src/audio_resource_runtime.rs",
        "src/semantic_binding_resource_runtime.rs",
        "src/provider_registry.rs",
    ]
    .into_iter()
    .map(read_required_d2bd_source)
    .collect::<Vec<_>>();
    for retired in [
        "run_process_watch",
        "run_activation_watch",
        "run_audio_watch",
        "run_semantic_binding_watch",
        "run_device_binding_watch",
        "device_binding_watch_task",
        "reconcile_semantic_binding_resources",
        "reconcile_wayland_session_deletion",
        "spawn_usbip_reconcile_after_vm_start",
        "UsbipBackgroundReconcileGuard",
        "configure_from_host",
        "compose_host_runtime",
        "reconcile_snapshot",
        "list_activation_snapshot",
        "list_process_snapshot",
        "list_process_snapshot_backend",
        "legacy_scheduler_disabled",
        "CoreRegisteredSource",
        "AcceptanceBatch",
    ] {
        assert!(
            !source_paths.iter().any(|source| source.contains(retired)),
            "d2bd source retains retired cutover path {retired}"
        );
    }
}
