use d2b_contracts_resource::v3::{
    ControllerGeneration, ResourceGeneration, ResourceRef, ZoneId,
};
use d2b_core_controller::{ControllerIdentity, core_controller_descriptors};

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
