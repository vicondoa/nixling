use d2b_contracts_provider::v3::credential::{CredentialMethod, PlacementBinding};
use d2b_contracts_resource::v3::ResourceRef;
use d2b_provider_credential_managed_identity::{
    AGENT_BINARY, CONTROLLER_BINARY, ManagedIdentityController, ManagedIdentityPlacement,
    ManagedIdentityRoute, agent_binary_entrypoint, controller_binary_entrypoint,
};

fn controller(binding: PlacementBinding, execution: &str) -> ManagedIdentityController {
    ManagedIdentityController::new(
        ManagedIdentityPlacement::new(
            binding,
            ResourceRef::parse(execution).unwrap(),
            ResourceRef::parse("Zone/dev").unwrap(),
        )
        .unwrap(),
    )
}

#[test]
fn admitted_ready_credentials_spawn_a_co_located_agent_without_egress() {
    for (binding, execution) in [
        (PlacementBinding::HostSystem, "Host/azure-vm"),
        (PlacementBinding::GuestAgent, "Guest/aca-sandbox"),
    ] {
        let agent = controller(binding, execution)
            .plan_agent(
                ResourceRef::parse("Credential/aca-relay-mi").unwrap(),
                true,
                true,
            )
            .unwrap()
            .unwrap();
        assert_eq!(agent.binary(), AGENT_BINARY);
        assert_eq!(agent.owner_ref().resource_type().as_str(), "Credential");
        assert_eq!(agent.execution_ref().to_canonical_string(), execution);
        assert_eq!(agent.placement(), binding);
        assert!(!agent.allow_egress());
        assert!(agent.requires_effect_port_client());
    }
}

#[test]
fn unresolved_or_unadmitted_credentials_do_not_spawn_an_agent() {
    let controller = controller(PlacementBinding::GuestAgent, "Guest/aca-sandbox");
    let credential = ResourceRef::parse("Credential/aca-relay-mi").unwrap();
    assert!(
        controller
            .plan_agent(credential.clone(), false, true)
            .unwrap()
            .is_none()
    );
    assert!(
        controller
            .plan_agent(credential, true, false)
            .unwrap()
            .is_none()
    );
}

#[test]
fn live_methods_route_to_the_agent_and_stored_inspection_stays_secret_free() {
    for method in [
        CredentialMethod::AcquireToken,
        CredentialMethod::RefreshToken,
        CredentialMethod::RevokeToken,
        CredentialMethod::InspectMetadata,
    ] {
        assert_eq!(
            ManagedIdentityController::route(method, true),
            ManagedIdentityRoute::Agent
        );
    }
    assert_eq!(
        ManagedIdentityController::route(CredentialMethod::InspectMetadata, false),
        ManagedIdentityRoute::ControllerStoredMetadata
    );
}

#[test]
fn teardown_releases_the_finalizer_only_after_revocation_and_process_deletion() {
    let stop = ManagedIdentityController::teardown_plan(true, false, false);
    assert!(stop.stop_agent);
    assert!(!stop.delete_agent);
    assert!(!stop.clear_provider_revoke);

    let delete = ManagedIdentityController::teardown_plan(false, true, false);
    assert!(!delete.stop_agent);
    assert!(delete.delete_agent);
    assert!(!delete.clear_provider_revoke);

    let clear = ManagedIdentityController::teardown_plan(false, true, true);
    assert!(!clear.stop_agent);
    assert!(!clear.delete_agent);
    assert!(clear.clear_provider_revoke);
}

#[test]
fn the_two_role_specific_binaries_exist_and_fail_closed_until_runtime_registration() {
    assert_eq!(CONTROLLER_BINARY, "d2b-managed-identity-controller");
    assert_eq!(AGENT_BINARY, "d2b-managed-identity-agent");
    assert_ne!(controller_binary_entrypoint(), 0);
    assert_ne!(agent_binary_entrypoint(), 0);
}
