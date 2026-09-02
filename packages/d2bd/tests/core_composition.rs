use std::collections::BTreeMap;

use d2b_contracts_resource::v3::{
    ControllerGeneration, ResourceGeneration, ResourceRef, ZoneId, identity::ReconnectGeneration,
};
use d2b_core_controller::{ControllerIdentity, core_controller_descriptors};
use d2bd::resource_runtime::{
    U7_SHARED_PROVIDER_RUNNERS, compose_shared_volume_runner_descriptors,
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
