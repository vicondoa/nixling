use d2b_contracts_resource::v3::{ResourceRef, ResourceUid};
use d2b_provider_device_security_key::{
    GuestCid, LeaseState, PhysicalAuthorityLease, PhysicalUsbBackingClaim, PhysicalUsbBackingToken,
    RelayLaunchTicket, SecurityKeyBindingAdmission, SecurityKeyCidTranslator,
    SecurityKeyController, SecurityKeyEffectError, SecurityKeyEffectPort, SecurityKeyLease,
    SecurityKeyOpenIntent, SecurityKeySessionId, DEFAULT_SESSION_RING_SIZE,
};

struct FakePort {
    opens: usize,
    releases: usize,
    conflict: bool,
    release_error: Option<SecurityKeyEffectError>,
}

impl SecurityKeyEffectPort for FakePort {
    fn claim_physical_backing(
        &mut self,
        _: &PhysicalUsbBackingClaim,
    ) -> Result<PhysicalAuthorityLease, SecurityKeyEffectError> {
        if self.conflict {
            Err(SecurityKeyEffectError::PhysicalUsbBackingConflict)
        } else {
            Ok(PhysicalAuthorityLease::from_core([1; 16]))
        }
    }

    fn open_hidraw(
        &mut self,
        _: &SecurityKeyOpenIntent,
    ) -> Result<RelayLaunchTicket, SecurityKeyEffectError> {
        self.opens += 1;
        Ok(RelayLaunchTicket::from_core([2; 16]))
    }

    fn release_physical_backing(
        &mut self,
        _: PhysicalAuthorityLease,
    ) -> Result<(), SecurityKeyEffectError> {
        self.releases += 1;
        self.release_error.take().map_or(Ok(()), Err)
    }
}

fn uid(value: &str) -> ResourceUid {
    ResourceUid::parse(value).unwrap()
}

#[test]
fn acquire_complete_and_cancel_follow_closed_lease_transitions() {
    let backing = PhysicalUsbBackingClaim::from_core(PhysicalUsbBackingToken::from_core([7; 32]));
    let mut lease = SecurityKeyLease::new(uid("123e4567-e89b-42d3-a456-426614174000"), backing);
    let mut port = FakePort {
        opens: 0,
        releases: 0,
        conflict: false,
        release_error: None,
    };
    lease
        .acquire(
            SecurityKeySessionId::from_core([3; 16]),
            uid("223e4567-e89b-42d3-a456-426614174001"),
            &mut port,
        )
        .unwrap();
    assert_eq!(lease.state(), LeaseState::Active);
    lease.cancel(&mut port).unwrap();
    assert_eq!(lease.state(), LeaseState::Cancelled);
    assert_eq!(port.opens, 1);
    assert_eq!(port.releases, 1);
}

#[test]
fn failed_release_retains_authority_until_a_retry_succeeds() {
    let backing = PhysicalUsbBackingClaim::from_core(PhysicalUsbBackingToken::from_core([8; 32]));
    let mut lease = SecurityKeyLease::new(uid("123e4567-e89b-42d3-a456-426614174000"), backing);
    let mut port = FakePort {
        opens: 0,
        releases: 0,
        conflict: false,
        release_error: Some(SecurityKeyEffectError::Transient),
    };
    lease
        .acquire(
            SecurityKeySessionId::from_core([6; 16]),
            uid("223e4567-e89b-42d3-a456-426614174001"),
            &mut port,
        )
        .unwrap();
    assert_eq!(
        lease.cancel(&mut port),
        Err(
            d2b_provider_device_security_key::SecurityKeyLeaseError::Effect(
                SecurityKeyEffectError::Transient
            )
        )
    );
    assert_eq!(lease.state(), LeaseState::Active);
    assert_eq!(port.releases, 1);

    lease.cancel(&mut port).unwrap();
    assert_eq!(lease.state(), LeaseState::Cancelled);
    assert_eq!(port.releases, 2);
}

#[test]
fn cid_translation_round_trips_without_exposing_session_material() {
    let guest = GuestCid::new(0x0102_0304).unwrap();
    let translator = SecurityKeyCidTranslator::from_core(0x1020_3040).unwrap();
    let relay = translator.to_relay(guest);
    assert_eq!(translator.to_guest(relay).unwrap(), guest);
}

#[test]
fn stale_binding_assignment_quarantines_completion_before_release() {
    let device = uid("123e4567-e89b-42d3-a456-426614174000");
    let binding = SecurityKeyBindingAdmission::new(
        uid("223e4567-e89b-42d3-a456-426614174001"),
        device.clone(),
        uid("323e4567-e89b-42d3-a456-426614174002"),
        uid("423e4567-e89b-42d3-a456-426614174003"),
        uid("523e4567-e89b-42d3-a456-426614174004"),
        uid("623e4567-e89b-42d3-a456-426614174005"),
        4,
    )
    .unwrap();
    let physical = PhysicalUsbBackingToken::from_core([7; 32]);
    let admission = d2b_provider_device_security_key::SecurityKeyAdmission::from_core(
        ResourceRef::parse("Zone/work").unwrap(),
        device.clone(),
        ResourceRef::parse("Guest/guest-a").unwrap(),
        physical,
    );
    let mut controller =
        SecurityKeyController::new_authorized(device, admission, DEFAULT_SESSION_RING_SIZE)
            .unwrap();
    controller.bind_resource_admission(binding.clone()).unwrap();
    let mut port = FakePort {
        opens: 0,
        releases: 0,
        conflict: false,
        release_error: None,
    };
    let session = SecurityKeySessionId::from_core([3; 16]);
    controller
        .acquire_authorized(
            session,
            uid("123e4567-e89b-42d3-a456-426614174000"),
            &ResourceRef::parse("Guest/guest-a").unwrap(),
            &mut port,
        )
        .unwrap();

    let stale = SecurityKeyBindingAdmission::new(
        uid("223e4567-e89b-42d3-a456-426614174001"),
        uid("123e4567-e89b-42d3-a456-426614174000"),
        uid("323e4567-e89b-42d3-a456-426614174002"),
        uid("423e4567-e89b-42d3-a456-426614174003"),
        uid("523e4567-e89b-42d3-a456-426614174004"),
        uid("623e4567-e89b-42d3-a456-426614174005"),
        5,
    )
    .unwrap();
    assert_eq!(
        controller.complete_authorized(session, &stale, &mut port),
        Err(d2b_provider_device_security_key::SecurityKeyControllerError::Admission)
    );
    assert_eq!(
        controller.phase(),
        d2b_provider_device_security_key::SecurityKeyPhase::Quarantined
    );
    assert_eq!(port.releases, 0);
}

#[test]
fn security_key_runner_contract_disables_legacy_scheduling() {
    let contract = d2b_provider_device_security_key::security_key_runner_contract();
    assert_eq!(
        contract.service_resource_type(),
        d2b_provider_device_security_key::SECURITY_KEY_SERVICE_RESOURCE_TYPE
    );
    assert_eq!(
        contract.binding_resource_type(),
        d2b_provider_device_security_key::SECURITY_KEY_BINDING_RESOURCE_TYPE
    );
    assert!(contract.legacy_scheduler_disabled());
    assert!(contract.watched_configuration_is_dependency());
    assert!((30..=60).contains(&contract.repair_interval_secs()));
}

#[test]
fn binding_children_are_resource_backed_without_volume_ownership() {
    let device = uid("123e4567-e89b-42d3-a456-426614174000");
    let binding_admission = SecurityKeyBindingAdmission::new(
        uid("223e4567-e89b-42d3-a456-426614174001"),
        device.clone(),
        uid("323e4567-e89b-42d3-a456-426614174002"),
        uid("423e4567-e89b-42d3-a456-426614174003"),
        uid("523e4567-e89b-42d3-a456-426614174004"),
        uid("623e4567-e89b-42d3-a456-426614174005"),
        4,
    )
    .unwrap();
    let admission = d2b_provider_device_security_key::SecurityKeyAdmission::from_core(
        ResourceRef::parse("Zone/work").unwrap(),
        device.clone(),
        ResourceRef::parse("Guest/guest-a").unwrap(),
        PhysicalUsbBackingToken::from_core([7; 32]),
    );
    let mut controller =
        SecurityKeyController::new_authorized(device, admission, DEFAULT_SESSION_RING_SIZE)
            .unwrap();
    controller.bind_resource_admission(binding_admission).unwrap();
    let binding = ResourceRef::parse(
        "security-key.d2bus.org.SecurityKeyBinding/key",
    )
    .unwrap();
    let service = ResourceRef::parse(
        "security-key.d2bus.org.SecurityKeyService/key",
    )
    .unwrap();
    let guest = ResourceRef::parse("Guest/guest-a").unwrap();
    let user = ResourceRef::parse("User/alice").unwrap();
    let admission = controller.binding_admission().unwrap().clone();
    assert!(!SecurityKeyController::owns_child(
        &binding,
        &service,
        &guest,
        &ResourceRef::parse("Volume/foreign").unwrap(),
    )
    .unwrap());
    let result = controller
        .reconcile_binding_with_admission(
            &admission,
            &binding,
            &service,
            &guest,
            &user,
            d2b_provider_device_security_key::SecurityKeyReconcileOutcome::Active,
        )
        .unwrap();
    assert_eq!(result.children.iter().count(), 2);
}
