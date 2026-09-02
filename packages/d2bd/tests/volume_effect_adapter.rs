//! Production Volume controller and anchored effect-adapter composition.

use d2b_contracts_resource::v3::{ResourceGeneration, ResourceRef, ResourceUid};
use d2b_provider_volume_local::{
    ContentFile, ContentProjection, ContentProvenance, VolumeLocalController, VolumeLocalError,
    VolumeLocalProfile,
};
use d2bd::resource_runtime::{AnchoredVolumeEffectAdapter, FdRootResolver};

fn volume_uid() -> ResourceUid {
    ResourceUid::parse("6f9619ff-8b86-4d01-b42d-00cf4fc964ff").expect("volume uid")
}

fn volume_spec() -> d2b_contracts_resource::v3::volume::VolumeSpec {
    serde_json::from_value(serde_json::json!({
        "source": {
            "executionRef": "Host/host-system",
            "settings": { "kind": "local-path", "sourcePolicyId": "state-root" }
        },
        "kind": "state",
        "layout": [{
            "path": "",
            "type": "directory",
            "ownerRef": "User/d2bd",
            "groupRef": "User/d2bd",
            "mode": "0700"
        }],
        "views": {
            "controller": {
                "path": "",
                "rights": ["read", "write", "create", "delete", "traverse"]
            }
        }
    }))
    .expect("Volume spec")
}

fn adapter_root(
    name: &str,
) -> (
    std::path::PathBuf,
    AnchoredVolumeEffectAdapter<FdRootResolver>,
) {
    let base = std::path::PathBuf::from(
        std::env::var_os("CARGO_TARGET_TMPDIR").unwrap_or_else(|| "target/u7-volume-tests".into()),
    )
    .join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).expect("volume root");
    let resolver =
        FdRootResolver::new(std::fs::File::open(&base).expect("open root"), volume_uid())
            .expect("root resolver");
    (base, AnchoredVolumeEffectAdapter::new(resolver))
}

#[test]
fn production_controller_materializes_and_adopts_a_marker_bound_root() {
    let (base, adapter) = adapter_root("production");
    let controller = VolumeLocalController::new(VolumeLocalProfile::shipped(), &adapter, &adapter);
    let uid = volume_uid();
    let spec = volume_spec();

    let first = d2b_provider_volume_local::testing::block_on(controller.reconcile(&uid, &spec))
        .expect("first reconcile");
    let restarted = d2b_provider_volume_local::testing::block_on(controller.reconcile(&uid, &spec))
        .expect("restart adoption");
    assert_eq!(
        first.layout_phase,
        d2b_provider_volume_local::LayoutPhase::Ready
    );
    assert_eq!(
        restarted.layout_phase,
        d2b_provider_volume_local::LayoutPhase::Ready
    );
    assert!(base.join(".d2b-volume-marker").is_file());
    let _ = std::fs::remove_dir_all(base);
}

#[test]
fn production_content_status_is_published_only_after_full_readback() {
    let (base, adapter) = adapter_root("content");
    let controller = VolumeLocalController::new(VolumeLocalProfile::shipped(), &adapter, &adapter);
    let uid = volume_uid();
    let spec = volume_spec();
    d2b_provider_volume_local::testing::block_on(controller.reconcile(&uid, &spec))
        .expect("layout reconcile");
    let owner = ResourceRef::parse("User/d2bd").expect("owner");
    let projection = ContentProjection::new(
        uid.clone(),
        ContentProvenance::new(
            ResourceRef::parse("Network/work").expect("network"),
            ResourceUid::parse("7f9619ff-8b86-4d01-b42d-00cf4fc964ff").expect("network uid"),
            ResourceGeneration::new(3).expect("generation"),
            "assignment-7",
            None,
        )
        .expect("provenance"),
        "network:config:owned",
        [ContentFile::new(
            "config",
            owner.clone(),
            owner,
            "0640",
            b"declared\n".to_vec(),
        )
        .expect("content file")],
    )
    .expect("projection");

    let evidence = d2b_provider_volume_local::testing::block_on(controller.reconcile_content(
        &uid,
        &spec,
        &projection,
    ))
    .expect("materialization evidence");
    let adopted = d2b_provider_volume_local::testing::block_on(controller.reconcile_content(
        &uid,
        &spec,
        &projection,
    ))
    .expect("restart evidence");
    assert!(evidence.matches(&projection));
    assert_eq!(adopted, evidence);
    assert_eq!(
        std::fs::read(base.join("config")).expect("readback"),
        b"declared\n"
    );
    let _ = std::fs::remove_dir_all(base);
}

#[test]
fn foreign_marker_is_preserved_and_blocks_the_controller() {
    let (base, adapter) = adapter_root("foreign-marker");
    std::fs::write(base.join(".d2b-volume-marker"), b"foreign-marker").expect("foreign marker");
    let controller = VolumeLocalController::new(VolumeLocalProfile::shipped(), &adapter, &adapter);
    let error = d2b_provider_volume_local::testing::block_on(
        controller.reconcile(&volume_uid(), &volume_spec()),
    )
    .expect_err("foreign marker must fail closed");
    assert_eq!(error, VolumeLocalError::EffectFailed);
    assert_eq!(
        std::fs::read(base.join(".d2b-volume-marker")).expect("marker readback"),
        b"foreign-marker"
    );
    let _ = std::fs::remove_dir_all(base);
}
