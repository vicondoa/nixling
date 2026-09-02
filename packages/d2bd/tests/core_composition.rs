use d2b_contracts_resource::v3::{
    ControllerGeneration, ResourceGeneration, ResourceRef, ZoneId,
};
use d2b_core_controller::{ControllerIdentity, core_controller_descriptors};
use d2bd::provider_registry::{
    ALL_ACCEPTED_PROVIDER_IDENTITIES, accepted_provider_bindings,
    compose_all_27_provider_registry,
};

const SCHEMA_FINGERPRINT: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000001";

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
fn provider_composition_admits_the_closed_27_row_catalog() {
    let bindings =
        accepted_provider_bindings(ZoneId::parse("work").unwrap(), SCHEMA_FINGERPRINT)
            .expect("accepted Provider rows");
    assert_eq!(bindings.len(), ALL_ACCEPTED_PROVIDER_IDENTITIES.len());
    assert_eq!(bindings.len(), 27);
    let registry = compose_all_27_provider_registry(
        ZoneId::parse("work").unwrap(),
        1,
        SCHEMA_FINGERPRINT,
    )
    .expect("all Provider rows compose");
    assert_eq!(registry.snapshot().descriptors().len(), 27);
    for provider in ALL_ACCEPTED_PROVIDER_IDENTITIES {
        let reference = ResourceRef::parse(&format!("Provider/{provider}")).unwrap();
        assert!(registry.descriptor(&reference).is_some(), "{provider}");
    }
}
