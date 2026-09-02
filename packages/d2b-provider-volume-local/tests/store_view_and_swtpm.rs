//! Store-view farm and TPM state invariants, plus status redaction.

use d2b_contracts_resource::v3::volume::VolumeSpec;
use d2b_provider_volume_local::testing::{ScriptedPort, block_on, fixtures};
use d2b_provider_volume_local::{
    GCROOTS_DIR, LIVE_DIR, REJECTED_GCROOTS_DIR, STATE_DIR, VolumeLocalController,
    VolumeLocalError, VolumeLocalProfile, assert_ro_store_attachment, assert_store_view_layout,
    assert_swtpm_volume, marker_path,
};

fn without_entry(path: &str) -> VolumeSpec {
    let mut rendered =
        serde_json::to_value(fixtures::store_view_volume()).expect("fixture serializes");
    let layout = rendered["layout"].as_array().expect("layout array").clone();
    rendered["layout"] = serde_json::Value::Array(
        layout
            .into_iter()
            .filter(|entry| entry["path"] != path)
            .collect(),
    );
    serde_json::from_value(rendered).expect("still a conformant Volume spec")
}

#[test]
fn the_canonical_store_view_layout_is_accepted() {
    assert!(
        assert_store_view_layout(
            &fixtures::volume_uid(),
            &fixtures::store_view_volume(),
            &fixtures::guest(),
        )
        .is_ok()
    );
}

#[test]
fn the_readiness_marker_is_required_under_the_live_farm() {
    let marker = marker_path(&fixtures::guest());
    assert!(marker.starts_with(LIVE_DIR));
    assert_eq!(
        assert_store_view_layout(
            &fixtures::volume_uid(),
            &without_entry(&marker),
            &fixtures::guest(),
        )
        .unwrap_err(),
        VolumeLocalError::InvariantViolated
    );
}

#[test]
fn gcroots_and_state_live_at_the_store_view_root() {
    for path in [GCROOTS_DIR, STATE_DIR] {
        assert_eq!(
            assert_store_view_layout(
                &fixtures::volume_uid(),
                &without_entry(path),
                &fixtures::guest(),
            )
            .unwrap_err(),
            VolumeLocalError::InvariantViolated
        );
    }

    // The retired path-row emitter placed GC roots under `meta/`. The
    // shipped hardlink farm places them at the root, so the nested form
    // is rejected outright.
    let mut rendered =
        serde_json::to_value(fixtures::store_view_volume()).expect("fixture serializes");
    let nested = serde_json::json!({
        "path": REJECTED_GCROOTS_DIR,
        "type": "directory",
        "ownerRef": "User/d2bd",
        "groupRef": "User/d2bd",
        "mode": "0755",
    });
    rendered["layout"]
        .as_array_mut()
        .expect("layout array")
        .push(nested);
    let spec: VolumeSpec = serde_json::from_value(rendered).expect("conformant Volume spec");
    assert_eq!(
        assert_store_view_layout(&fixtures::volume_uid(), &spec, &fixtures::guest()).unwrap_err(),
        VolumeLocalError::InvariantViolated
    );
}

#[test]
fn the_guest_is_served_the_farm_and_never_a_wider_subtree() {
    assert!(assert_ro_store_attachment(&fixtures::store_view_volume()).is_ok());

    let mut rendered =
        serde_json::to_value(fixtures::store_view_volume()).expect("fixture serializes");
    rendered["views"]["ro-store"]["path"] = serde_json::json!("");
    let spec: VolumeSpec = serde_json::from_value(rendered).expect("conformant Volume spec");
    assert_eq!(
        assert_ro_store_attachment(&spec).unwrap_err(),
        VolumeLocalError::InvariantViolated
    );
}

#[test]
fn a_writable_store_view_attachment_is_rejected() {
    let mut rendered =
        serde_json::to_value(fixtures::store_view_volume()).expect("fixture serializes");
    rendered["views"]["ro-store"]["rights"] = serde_json::json!(["read", "traverse", "write"]);
    rendered["attachments"][0]["access"] = serde_json::json!("read-write");
    let spec: VolumeSpec = serde_json::from_value(rendered).expect("conformant Volume spec");
    assert_eq!(
        assert_ro_store_attachment(&spec).unwrap_err(),
        VolumeLocalError::InvariantViolated
    );
}

#[test]
fn the_tpm_volume_declares_the_fail_closed_state_posture() {
    assert!(assert_swtpm_volume(&fixtures::volume_uid(), &fixtures::swtpm_volume()).is_ok());

    let mut rendered = serde_json::to_value(fixtures::swtpm_volume()).expect("fixture serializes");
    rendered["layout"][0]["createPolicy"] = serde_json::json!("create-if-absent");
    let spec: VolumeSpec = serde_json::from_value(rendered).expect("conformant Volume spec");
    assert_eq!(
        assert_swtpm_volume(&fixtures::volume_uid(), &spec).unwrap_err(),
        VolumeLocalError::InvalidSpec
    );
}

#[test]
fn the_tpm_volume_is_secret_and_never_publishes_its_path() {
    let mut rendered = serde_json::to_value(fixtures::swtpm_volume()).expect("fixture serializes");
    rendered["layout"][0]["sensitivity"] = serde_json::json!("private");
    let spec: VolumeSpec = serde_json::from_value(rendered).expect("conformant Volume spec");
    assert_eq!(
        assert_swtpm_volume(&fixtures::volume_uid(), &spec).unwrap_err(),
        VolumeLocalError::InvalidSpec
    );
}

/// Fragments that must never appear in a public Volume status document.
const FORBIDDEN_STATUS_FRAGMENTS: [&str; 19] = [
    "pid",
    "pidfd",
    "unit",
    "invocation",
    "cgroup",
    "path",
    "argv",
    "command",
    "binary",
    "env",
    "sourcepolicyid",
    "state-root",
    "uid",
    "gid",
    "socket",
    "acl",
    "marker",
    "sync.lock",
    "gcroots",
];

#[test]
fn public_status_carries_no_path_policy_id_or_numeric_identity() {
    let port = ScriptedPort::empty();
    let controller = VolumeLocalController::new(VolumeLocalProfile::shipped(), &port, &port);
    let report =
        block_on(controller.reconcile(
            &fixtures::volume_uid(),
            &fixtures::store_view_volume(),
            None,
            None,
        ))
            .expect("reconcile succeeds");
    let rendered = serde_json::to_string(&report)
        .expect("status serializes")
        .to_ascii_lowercase();
    for fragment in FORBIDDEN_STATUS_FRAGMENTS {
        assert!(
            !rendered.contains(fragment),
            "public status carries the forbidden fragment {fragment}"
        );
    }
    assert!(rendered.contains("volume-local"));
}
