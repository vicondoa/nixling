use d2b_contracts_resource::v3::{ResourceRef, ResourceUid};
use d2b_provider_device_usbip::{
    AttachProcessIdentity, AttachmentObservation, BindingIdentity, BindingLifecycle,
    BindingLifecycleError, BindingPort, BindingProxyLease, BindingSlotLease, ServiceLifecycle,
    ServiceLifecycleError, ServicePhase, ServicePort, UsbipBindingController, UsbipBindingPhase,
    UsbipBindingAdmission, UsbipSupervisor, binding_child_resources,
};

fn uid(value: &str) -> ResourceUid {
    ResourceUid::parse(value).unwrap()
}

#[test]
fn explicit_binding_children_are_resource_backed_and_ordered_for_teardown() {
    let children = binding_child_resources(
        &ResourceRef::parse("usb.d2bus.org.UsbBinding/keyboard").unwrap(),
        &ResourceRef::parse("usb.d2bus.org.UsbService/usb-bus").unwrap(),
        &ResourceRef::parse("Guest/guest-a").unwrap(),
    )
    .unwrap();

    assert_eq!(children.iter().count(), 2);
    assert_eq!(children.at(d2b_contracts_provider::v3::semantic_services::child_resources::BindingChildPlacement::Host).count(), 0);
    assert_eq!(children.at(d2b_contracts_provider::v3::semantic_services::child_resources::BindingChildPlacement::Guest).count(), 2);
    assert_eq!(
        children
            .teardown_order()
            .iter()
            .map(|child| child.role())
            .collect::<Vec<_>>(),
        vec!["guest-endpoint", "guest-proxy"]
    );
    assert_eq!(
        children.child("guest-endpoint").unwrap().producer_ref(),
        Some(children.child("guest-proxy").unwrap().resource_ref())
    );
}

#[test]
fn binding_controller_only_observes_core_managed_children() {
    let binding = ResourceRef::parse("usb.d2bus.org.UsbBinding/keyboard").unwrap();
    let service = ResourceRef::parse("usb.d2bus.org.UsbService/usb-bus").unwrap();
    let target = ResourceRef::parse("Guest/guest-a").unwrap();
    let mut controller = UsbipBindingController::new(&binding, &service, &target).unwrap();

    assert_eq!(controller.phase(), UsbipBindingPhase::Pending);
    assert_eq!(
        controller.observe_children(true).unwrap().phase,
        UsbipBindingPhase::Ready
    );
    controller.finalize();
    assert_eq!(controller.phase(), UsbipBindingPhase::Deleted);
    assert!(controller.observe_children(true).is_err());
}

struct FakePort {
    calls: Vec<&'static str>,
    fail_physical: bool,
    fail_relay: bool,
    observation: AttachmentObservation,
}

impl Default for FakePort {
    fn default() -> Self {
        Self {
            calls: Vec::new(),
            fail_physical: false,
            fail_relay: false,
            observation: AttachmentObservation::Matching {
                slot: BindingSlotLease::from_adapter([4; 16]),
                proxy: BindingProxyLease::from_adapter([5; 16]),
            },
        }
    }
}

impl ServicePort for FakePort {
    fn reserve_physical(
        &mut self,
        _: &ResourceUid,
    ) -> Result<d2b_provider_device_usbip::PhysicalAuthorityLease, ServiceLifecycleError> {
        self.calls.push("reserve-physical");
        if self.fail_physical {
            Err(ServiceLifecycleError::PhysicalAuthorityConflict)
        } else {
            Ok(d2b_provider_device_usbip::PhysicalAuthorityLease::from_adapter([1; 16]))
        }
    }

    fn reserve_relay(
        &mut self,
        _: &ResourceUid,
    ) -> Result<d2b_provider_device_usbip::ServiceRelayLease, ServiceLifecycleError> {
        self.calls.push("reserve-relay");
        if self.fail_relay {
            Err(ServiceLifecycleError::RelayAuthorityConflict)
        } else {
            Ok(d2b_provider_device_usbip::ServiceRelayLease::from_adapter(
                [2; 16],
            ))
        }
    }

    fn bind_owned(
        &mut self,
        _: &d2b_provider_device_usbip::PhysicalAuthorityLease,
    ) -> Result<d2b_provider_device_usbip::OwnedBusBinding, ServiceLifecycleError> {
        self.calls.push("bind");
        Ok(d2b_provider_device_usbip::OwnedBusBinding::from_adapter(
            [3; 16],
        ))
    }

    fn unbind_owned(
        &mut self,
        _: &d2b_provider_device_usbip::OwnedBusBinding,
    ) -> Result<(), ServiceLifecycleError> {
        self.calls.push("unbind");
        Ok(())
    }

    fn release_relay(
        &mut self,
        _: d2b_provider_device_usbip::ServiceRelayLease,
    ) -> Result<(), ServiceLifecycleError> {
        self.calls.push("release-relay");
        Ok(())
    }

    fn release_physical(
        &mut self,
        _: d2b_provider_device_usbip::PhysicalAuthorityLease,
    ) -> Result<(), ServiceLifecycleError> {
        self.calls.push("release-physical");
        Ok(())
    }
}

impl BindingPort for FakePort {
    fn acquire_slot(
        &mut self,
        _: &BindingIdentity,
    ) -> Result<BindingSlotLease, BindingLifecycleError> {
        self.calls.push("slot");
        Ok(BindingSlotLease::from_adapter([4; 16]))
    }

    fn start_proxy(
        &mut self,
        _: &BindingIdentity,
        _: &BindingSlotLease,
    ) -> Result<BindingProxyLease, BindingLifecycleError> {
        self.calls.push("proxy");
        Ok(BindingProxyLease::from_adapter([5; 16]))
    }

    fn ensure_attach_process(
        &mut self,
        _: &BindingIdentity,
        _: &BindingProxyLease,
    ) -> Result<AttachProcessIdentity, BindingLifecycleError> {
        self.calls.push("ensure-attach-process");
        Ok(AttachProcessIdentity::from_adapter(7, 11))
    }

    fn observe_attach_process(
        &mut self,
        _: &BindingIdentity,
        _: &AttachProcessIdentity,
    ) -> Result<AttachmentObservation, BindingLifecycleError> {
        self.calls.push("observe-attach-process");
        Ok(self.observation.clone())
    }

    fn delete_guest_endpoint(
        &mut self,
        _: &BindingIdentity,
        _: &BindingProxyLease,
    ) -> Result<(), BindingLifecycleError> {
        self.calls.push("delete-guest-endpoint");
        Ok(())
    }

    fn delete_attach_process(
        &mut self,
        _: &BindingIdentity,
        _: &AttachProcessIdentity,
    ) -> Result<(), BindingLifecycleError> {
        self.calls.push("delete-attach-process");
        Ok(())
    }

    fn close_proxy(
        &mut self,
        _: &BindingIdentity,
        _: &BindingProxyLease,
    ) -> Result<(), BindingLifecycleError> {
        self.calls.push("close-proxy");
        Ok(())
    }

    fn release_slot(
        &mut self,
        _: &BindingIdentity,
        _: &BindingSlotLease,
    ) -> Result<(), BindingLifecycleError> {
        self.calls.push("release-slot");
        Ok(())
    }
}

#[test]
fn wrong_zone_and_opt_out_refuse_before_authority_or_bind() {
    let service_zone = uid("123e4567-e89b-42d3-a456-426614174000");
    let mut port = FakePort::default();
    let mut service = ServiceLifecycle::new(
        service_zone.clone(),
        uid("223e4567-e89b-42d3-a456-426614174001"),
    );

    assert_eq!(
        service.activate(false, service_zone.clone(), &mut port),
        Err(ServiceLifecycleError::ZoneNotOptedIn)
    );
    assert!(port.calls.is_empty());
    assert_eq!(
        service.activate(true, uid("323e4567-e89b-42d3-a456-426614174002"), &mut port),
        Err(ServiceLifecycleError::WrongZone)
    );
    assert!(port.calls.is_empty());
}

#[test]
fn authority_conflicts_happen_before_bind() {
    let zone = uid("123e4567-e89b-42d3-a456-426614174000");
    let mut physical_conflict = FakePort {
        fail_physical: true,
        ..Default::default()
    };
    let mut service =
        ServiceLifecycle::new(zone.clone(), uid("223e4567-e89b-42d3-a456-426614174001"));
    assert_eq!(
        service.activate(true, zone.clone(), &mut physical_conflict),
        Err(ServiceLifecycleError::PhysicalAuthorityConflict)
    );
    assert_eq!(physical_conflict.calls, ["reserve-physical"]);

    let mut relay_conflict = FakePort {
        fail_relay: true,
        ..Default::default()
    };
    let mut service =
        ServiceLifecycle::new(zone.clone(), uid("223e4567-e89b-42d3-a456-426614174001"));
    assert_eq!(
        service.activate(true, zone, &mut relay_conflict),
        Err(ServiceLifecycleError::RelayAuthorityConflict)
    );
    assert_eq!(relay_conflict.calls, ["reserve-physical", "reserve-relay"]);
}

#[test]
fn matching_restart_adopts_and_stale_identity_quarantines_without_effects() {
    let zone = uid("123e4567-e89b-42d3-a456-426614174000");
    let mut port = FakePort::default();
    let service = ServiceLifecycle::new(zone.clone(), uid("223e4567-e89b-42d3-a456-426614174001"));
    let mut supervisor = UsbipSupervisor::new(service);
    supervisor
        .add_binding(BindingLifecycle::new(
            zone.clone(),
            zone.clone(),
            BindingIdentity::from_controller(uid("323e4567-e89b-42d3-a456-426614174002")),
        ))
        .unwrap();
    supervisor
        .adopt_binding(0, AttachProcessIdentity::from_adapter(7, 11), &mut port)
        .unwrap();
    assert_eq!(port.calls, ["observe-attach-process"]);
    supervisor.finalize(&mut port).unwrap();
    assert_eq!(
        port.calls,
        [
            "observe-attach-process",
            "delete-guest-endpoint",
            "delete-attach-process",
            "close-proxy",
            "release-slot"
        ]
    );

    let service = ServiceLifecycle::new(zone.clone(), uid("423e4567-e89b-42d3-a456-426614174003"));
    let mut supervisor = UsbipSupervisor::new(service);
    supervisor
        .add_binding(BindingLifecycle::new(
            zone.clone(),
            zone,
            BindingIdentity::from_controller(uid("523e4567-e89b-42d3-a456-426614174004")),
        ))
        .unwrap();
    port.calls.clear();
    port.observation = AttachmentObservation::StaleIdentity;
    supervisor
        .adopt_binding(0, AttachProcessIdentity::from_adapter(8, 12), &mut port)
        .unwrap();
    assert_eq!(port.calls, ["observe-attach-process"]);
    assert_eq!(
        supervisor.activate_binding(0, &mut port),
        Err(BindingLifecycleError::Quarantined)
    );
    assert_eq!(
        supervisor.finalize(&mut port),
        Err(d2b_provider_device_usbip::SupervisorFinalizeError::Binding(
            BindingLifecycleError::Quarantined
        ))
    );
    assert_eq!(port.calls, ["observe-attach-process"]);
}

#[test]
fn binding_is_not_attached_until_the_guest_process_is_ready() {
    let zone = uid("123e4567-e89b-42d3-a456-426614174000");
    let mut port = FakePort {
        observation: AttachmentObservation::Missing,
        ..Default::default()
    };
    let mut service =
        ServiceLifecycle::new(zone.clone(), uid("223e4567-e89b-42d3-a456-426614174001"));
    service.activate(true, zone.clone(), &mut port).unwrap();
    port.calls.clear();
    let mut supervisor = UsbipSupervisor::new(service);
    supervisor
        .add_binding(BindingLifecycle::new(
            zone.clone(),
            zone,
            BindingIdentity::from_controller(uid("323e4567-e89b-42d3-a456-426614174002")),
        ))
        .unwrap();

    assert_eq!(
        supervisor.activate_binding(0, &mut port),
        Err(BindingLifecycleError::Transient)
    );
    assert_eq!(
        port.calls,
        [
            "slot",
            "proxy",
            "ensure-attach-process",
            "observe-attach-process",
        ]
    );
}

#[test]
fn missing_restart_identity_drops_slot_and_proxy_before_reactivate() {
    let zone = uid("123e4567-e89b-42d3-a456-426614174000");
    let mut port = FakePort::default();
    let mut service =
        ServiceLifecycle::new(zone.clone(), uid("223e4567-e89b-42d3-a456-426614174001"));
    service.activate(true, zone.clone(), &mut port).unwrap();
    let mut supervisor = UsbipSupervisor::new(service);
    supervisor
        .add_binding(BindingLifecycle::new(
            zone.clone(),
            zone,
            BindingIdentity::from_controller(uid("323e4567-e89b-42d3-a456-426614174002")),
        ))
        .unwrap();
    supervisor.activate_binding(0, &mut port).unwrap();
    port.calls.clear();
    port.observation = AttachmentObservation::Missing;
    supervisor
        .adopt_binding(0, AttachProcessIdentity::from_adapter(7, 11), &mut port)
        .unwrap();
    port.observation = AttachmentObservation::Matching {
        slot: BindingSlotLease::from_adapter([4; 16]),
        proxy: BindingProxyLease::from_adapter([5; 16]),
    };
    supervisor.activate_binding(0, &mut port).unwrap();
    assert_eq!(
        port.calls,
        [
            "observe-attach-process",
            "slot",
            "proxy",
            "ensure-attach-process",
            "observe-attach-process",
        ]
    );
}

#[test]
fn binding_closes_its_process_before_service_unbinds_and_releases_authority() {
    let zone = uid("123e4567-e89b-42d3-a456-426614174000");
    let mut port = FakePort::default();
    let mut service =
        ServiceLifecycle::new(zone.clone(), uid("223e4567-e89b-42d3-a456-426614174001"));
    service.activate(true, zone.clone(), &mut port).unwrap();
    let binding = BindingLifecycle::new(
        zone.clone(),
        zone,
        BindingIdentity::from_controller(uid("323e4567-e89b-42d3-a456-426614174002")),
    );
    let mut supervisor = UsbipSupervisor::new(service);
    supervisor.add_binding(binding).unwrap();
    supervisor.activate_binding(0, &mut port).unwrap();
    supervisor.finalize(&mut port).unwrap();

    assert_eq!(supervisor.service().phase(), ServicePhase::Closed);
    assert_eq!(
        port.calls,
        [
            "reserve-physical",
            "reserve-relay",
            "bind",
            "slot",
            "proxy",
            "ensure-attach-process",
            "observe-attach-process",
            "delete-guest-endpoint",
            "delete-attach-process",
            "close-proxy",
            "release-slot",
            "unbind",
            "release-relay",
            "release-physical",
        ]
    );
}

#[test]
fn one_binding_can_finalize_without_unbinding_the_shared_service() {
    let zone = uid("123e4567-e89b-42d3-a456-426614174000");
    let mut port = FakePort::default();
    let mut service =
        ServiceLifecycle::new(zone.clone(), uid("223e4567-e89b-42d3-a456-426614174001"));
    service.activate(true, zone.clone(), &mut port).unwrap();
    let mut supervisor = UsbipSupervisor::new(service);
    for value in [
        "323e4567-e89b-42d3-a456-426614174002",
        "423e4567-e89b-42d3-a456-426614174003",
    ] {
        supervisor
            .add_binding(BindingLifecycle::new(
                zone.clone(),
                zone.clone(),
                BindingIdentity::from_controller(uid(value)),
            ))
            .unwrap();
    }
    supervisor.activate_binding(0, &mut port).unwrap();
    supervisor.activate_binding(1, &mut port).unwrap();
    supervisor.finalize_binding(0, &mut port).unwrap();

    assert_eq!(supervisor.service().phase(), ServicePhase::Bound);
    assert!(!port.calls.contains(&"unbind"));

    supervisor.finalize(&mut port).unwrap();
    assert_eq!(supervisor.service().phase(), ServicePhase::Closed);
}

#[test]
fn foreign_zone_binding_is_refused_before_recovery_observation() {
    let service_zone = uid("123e4567-e89b-42d3-a456-426614174000");
    let foreign_zone = uid("223e4567-e89b-42d3-a456-426614174001");
    let service = ServiceLifecycle::new(
        service_zone.clone(),
        uid("323e4567-e89b-42d3-a456-426614174002"),
    );
    let mut supervisor = UsbipSupervisor::new(service);
    assert_eq!(
        supervisor.add_binding(BindingLifecycle::new(
            service_zone,
            foreign_zone,
            BindingIdentity::from_controller(uid("423e4567-e89b-42d3-a456-426614174003")),
        )),
        Err(BindingLifecycleError::WrongZone)
    );
    let mut port = FakePort::default();
    assert_eq!(
        supervisor.adopt_binding(0, AttachProcessIdentity::from_adapter(7, 11), &mut port),
        Err(BindingLifecycleError::AdmissionDenied)
    );
    assert!(port.calls.is_empty());
}

#[test]
fn binding_admission_fences_stale_assignment_and_rejects_volume_ownership() {
    let binding = ResourceRef::parse("usb.d2bus.org.UsbBinding/keyboard").unwrap();
    let service = ResourceRef::parse("usb.d2bus.org.UsbService/usb-bus").unwrap();
    let target = ResourceRef::parse("Guest/guest-a").unwrap();
    let admission = UsbipBindingAdmission::new(
        uid("123e4567-e89b-42d3-a456-426614174000"),
        uid("223e4567-e89b-42d3-a456-426614174001"),
        uid("323e4567-e89b-42d3-a456-426614174002"),
        uid("423e4567-e89b-42d3-a456-426614174003"),
        d2b_contracts_resource::v3::ResourceGeneration::new(2).unwrap(),
        7,
    )
    .unwrap();
    let mut controller =
        UsbipBindingController::new_admitted(&binding, &service, &target, admission.clone())
            .unwrap();

    assert!(!controller.owns_child(&ResourceRef::parse("Volume/foreign").unwrap()));
    controller.observe_children_with_admission(admission.clone(), true).unwrap();

    let stale = UsbipBindingAdmission::new(
        uid("123e4567-e89b-42d3-a456-426614174000"),
        uid("223e4567-e89b-42d3-a456-426614174001"),
        uid("323e4567-e89b-42d3-a456-426614174002"),
        uid("423e4567-e89b-42d3-a456-426614174003"),
        d2b_contracts_resource::v3::ResourceGeneration::new(2).unwrap(),
        8,
    )
    .unwrap();
    assert_eq!(
        controller.observe_children_with_admission(stale, true),
        Err(d2b_provider_device_usbip::UsbipBindingControllerError::StaleAssignment)
    );
}

#[test]
fn usbip_runner_contract_keeps_service_and_binding_on_one_runner() {
    let contract = d2b_provider_device_usbip::usbip_runner_contract();
    assert_eq!(
        contract.service_resource_type(),
        d2b_provider_device_usbip::USB_SERVICE_RESOURCE_TYPE
    );
    assert_eq!(
        contract.binding_resource_type(),
        d2b_provider_device_usbip::USB_BINDING_RESOURCE_TYPE
    );
    assert!(contract.legacy_scheduler_disabled());
    assert!(contract.watched_configuration_is_dependency());
    assert!((30..=60).contains(&contract.repair_interval_secs()));
}
