use std::collections::{BTreeMap, BTreeSet};

use d2b_contracts_resource::v3::{
    ControllerGeneration, ResourceGeneration, ResourceRef, ZoneId, identity::ReconnectGeneration,
};
use d2b_core_controller::{ControllerIdentity, core_controller_descriptors};
use d2bd::resource_runtime::{
    U7_SHARED_PROVIDER_RUNNERS, compose_shared_volume_runner_descriptors,
    U8_SHARED_PROVIDER_RUNNERS, U6_SHARED_PROVIDER_RUNNERS,
    compose_shared_guest_runner_descriptors, compose_shared_provider_runner_descriptors,
};

fn controller_identity() -> ControllerIdentity {
    ControllerIdentity::new(
        ZoneId::parse("work").expect("valid Zone"),
        ResourceRef::parse("Process/d2b-core-controller").expect("valid controller ref"),
        ControllerGeneration::new(1).expect("valid controller generation"),
        ResourceRef::parse("Provider/system-core").expect("valid Provider ref"),
        ResourceGeneration::new(1).expect("valid Provider generation"),
        ResourceRef::parse("Process/d2b-core-controller").expect("valid Process ref"),
        ResourceRef::parse("Host/host-system").expect("valid Host ref"),
        None,
    )
    .expect("valid Core controller identity")
}

#[test]
fn core_composition_exposes_one_runner_descriptor_per_fixed_resource_owner() {
    let descriptors =
        core_controller_descriptors(controller_identity()).expect("fixed descriptors compose");
    assert_eq!(descriptors.len(), 9);
    assert!(
        descriptors
            .iter()
            .all(|(_, descriptor)| descriptor.identity().controller_ref()
                == &ResourceRef::parse("Process/d2b-core-controller").unwrap())
    );
    assert_eq!(
        descriptors
            .iter()
            .map(|(_, descriptor)| descriptor
                .resource_types()
                .next()
                .expect("one ResourceType per Core descriptor")
                .as_str())
            .collect::<Vec<_>>(),
        vec![
            "Zone",
            "ZoneLink",
            "Provider",
            "Role",
            "RoleBinding",
            "Quota",
            "EmergencyPolicy",
            "ResourceExport",
            "ResourceImport",
        ]
    );
}

#[test]
fn volume_composition_builds_exact_runner_descriptors_and_fences() {
    let generations = U7_SHARED_PROVIDER_RUNNERS
        .iter()
        .map(|registration| {
            (
                ResourceRef::parse(registration.provider_ref).unwrap(),
                ResourceGeneration::new(7).unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let descriptors = compose_shared_volume_runner_descriptors(
        U7_SHARED_PROVIDER_RUNNERS,
        ZoneId::parse("work").unwrap(),
        ControllerGeneration::new(3).unwrap(),
        &generations,
        ReconnectGeneration::new(5).unwrap(),
    )
    .expect("U7 descriptors");

    assert_eq!(descriptors.len(), 2);
    for (registration, descriptor) in descriptors {
        assert_eq!(
            descriptor.resource_types().next().unwrap().as_str(),
            registration.resource_type
        );
        assert_eq!(
            descriptor.finalizers(),
            &[registration.finalizer.to_owned()]
        );
        assert_eq!(
            descriptor
                .watch_selectors()
                .iter()
                .find(|selector| selector.field() == d2b_core_controller::SelectorField::Spec)
                .and_then(|selector| selector.exact_value()),
            Some(registration.provider_ref)
        );
        assert_eq!(
            descriptor.execution().resync().observe_interval_ticks(),
            Some(registration.repair_interval_secs * 1_000)
        );
    }
}

#[test]
fn volume_composition_refuses_to_spawn_when_a_provider_identity_is_missing() {
    let missing = ResourceRef::parse("Provider/volume-virtiofs").unwrap();
    let generations = U7_SHARED_PROVIDER_RUNNERS
        .iter()
        .filter_map(|registration| {
            let provider = ResourceRef::parse(registration.provider_ref).unwrap();
            (provider != missing).then_some((provider, ResourceGeneration::new(7).unwrap()))
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        compose_shared_volume_runner_descriptors(
            U7_SHARED_PROVIDER_RUNNERS,
            ZoneId::parse("work").unwrap(),
            ControllerGeneration::new(3).unwrap(),
            &generations,
            ReconnectGeneration::new(5).unwrap(),
        ),
        Err(d2bd::resource_runtime::ResourceRuntimeError::HandlerNotReady)
    );
}

#[test]
fn guest_composition_builds_one_filtered_runner_per_runtime_provider() {
    let generations = U6_SHARED_PROVIDER_RUNNERS
        .iter()
        .map(|registration| {
            (
                ResourceRef::parse(registration.provider_ref).unwrap(),
                ResourceGeneration::new(7).unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let descriptors = compose_shared_guest_runner_descriptors(
        U6_SHARED_PROVIDER_RUNNERS,
        ZoneId::parse("work").unwrap(),
        ControllerGeneration::new(3).unwrap(),
        &generations,
        ReconnectGeneration::new(5).unwrap(),
    )
    .expect("U6 descriptors");

    assert_eq!(descriptors.len(), 4);
    let controllers = descriptors
        .iter()
        .map(|(_, descriptor)| descriptor.identity().controller_ref().clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(controllers.len(), 4);
    for (registration, descriptor) in descriptors {
        assert_eq!(descriptor.resource_types().next().unwrap().as_str(), "Guest");
        assert_eq!(
            descriptor
                .watch_selectors()
                .iter()
                .find(|selector| {
                    selector.field() == d2b_core_controller::SelectorField::Spec
                })
                .and_then(|selector| selector.exact_value()),
            Some(registration.provider_ref)
        );
        assert!(
            descriptor
                .dependency_selectors()
                .iter()
                .any(|selector| selector.resource_type().as_str() == "Process")
        );
        assert_eq!(
            descriptor.execution().resync().observe_interval_ticks(),
            Some(registration.repair_interval_ticks)
        );
        assert_eq!(
            descriptor.execution().resync().resync_interval_ticks(),
            registration.repair_interval_ticks
        );
    }
}

#[test]
fn provider_composition_builds_real_runner_descriptors_with_exact_fences() {
    let provider_generations = U8_SHARED_PROVIDER_RUNNERS
        .iter()
        .map(|registration| {
            (
                ResourceRef::parse(registration.provider_ref).unwrap(),
                ResourceGeneration::new(7).unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let descriptors = compose_shared_provider_runner_descriptors(
        U8_SHARED_PROVIDER_RUNNERS,
        ZoneId::parse("work").unwrap(),
        ControllerGeneration::new(3).unwrap(),
        &provider_generations,
        ReconnectGeneration::new(5).unwrap(),
    )
    .unwrap();

    assert_eq!(descriptors.len(), U8_SHARED_PROVIDER_RUNNERS.len());
    let controllers = descriptors
        .iter()
        .map(|(_, descriptor)| descriptor.identity().controller_ref().clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(controllers.len(), descriptors.len());
    for (registration, descriptor) in descriptors {
        assert_eq!(
            descriptor
                .resource_types()
                .next()
                .unwrap()
                .as_str(),
            registration.resource_type
        );
        assert_eq!(
            descriptor.finalizers(),
            &[registration.finalizer.to_owned()]
        );
        assert_eq!(
            descriptor
                .watch_selectors()
                .iter()
                .find(|selector| selector.field()
                    == d2b_core_controller::SelectorField::Spec)
                .and_then(|selector| selector.exact_value()),
            Some(registration.provider_ref)
        );
        assert_eq!(
            descriptor.execution().resync().observe_interval_ticks(),
            Some(registration.repair_interval_ticks)
        );
        assert_eq!(
            descriptor.execution().resync().resync_interval_ticks(),
            registration.repair_interval_ticks
        );
    }
}

#[test]
fn provider_composition_rejects_a_missing_accepted_provider_before_runner_spawn() {
    let missing = ResourceRef::parse("Provider/device-gpu").unwrap();
    let mut provider_generations = U8_SHARED_PROVIDER_RUNNERS
        .iter()
        .filter_map(|registration| {
            let provider_ref = ResourceRef::parse(registration.provider_ref).unwrap();
            (provider_ref != missing)
                .then_some((provider_ref, ResourceGeneration::new(7).unwrap()))
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        compose_shared_provider_runner_descriptors(
            U8_SHARED_PROVIDER_RUNNERS,
            ZoneId::parse("work").unwrap(),
            ControllerGeneration::new(3).unwrap(),
            &provider_generations,
            ReconnectGeneration::new(5).unwrap(),
        ),
        Err(d2bd::resource_runtime::ResourceRuntimeError::HandlerNotReady)
    );
    provider_generations.insert(missing, ResourceGeneration::new(8).unwrap());
    assert_eq!(
        compose_shared_provider_runner_descriptors(
            U8_SHARED_PROVIDER_RUNNERS,
            ZoneId::parse("work").unwrap(),
            ControllerGeneration::new(3).unwrap(),
            &provider_generations,
            ReconnectGeneration::new(5).unwrap(),
        )
        .unwrap()
        .len(),
        U8_SHARED_PROVIDER_RUNNERS.len()
    );
}

#[test]
fn u8_reconcile_dispatch_has_no_legacy_production_call_sites() {
    let source = include_str!("../src/composition.rs");
    assert!(!source.contains("match dispatch_wave6_resource_reconcile("));
    assert!(!source.contains("return Ok(dispatch_device_tpm_reconcile("));
    assert!(!source.contains("security_key_effect_port::dispatch_reconcile("));
    assert!(!source.contains("if usbip_start_reconciles_synchronously("));
    assert!(!source.contains("cleanup_usbip_before_vm_stop(state"));
    assert!(!source.contains("let scheduled = spawn_usbip_reconcile_after_vm_start("));
}
