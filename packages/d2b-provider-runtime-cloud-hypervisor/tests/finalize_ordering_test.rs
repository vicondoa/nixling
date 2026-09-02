use d2b_contracts_resource::v3::{ResourceRef, ResourceUid, ZoneRevision};
use d2b_provider_runtime_cloud_hypervisor::{
    ChildRole, FencedChild, FinalizationBlockReason, FinalizationDisposition, FinalizationStep,
    GuestFinalizationInput, ProcessState, SessionState, UpgradeReason, plan_finalization,
    plan_upgrade,
};

const GUEST_UID: &str = "123e4567-e89b-42d3-a456-426614174000";

fn uid(seed: u8) -> ResourceUid {
    ResourceUid::parse(format!("323e4567-e89b-42d3-a456-4266141740{seed:02}")).unwrap()
}

fn child(role: ChildRole, name: &str, seed: u8) -> FencedChild {
    FencedChild::new(
        role,
        ResourceRef::parse(&format!("{}/{}", role.resource_type(), name)).unwrap(),
        uid(seed),
        ZoneRevision::new(4),
    )
    .unwrap()
}

#[test]
fn deletion_is_session_first_then_vmm_and_reverse_direct_children_with_finalizer_last() {
    let guest_uid = ResourceUid::parse(GUEST_UID).unwrap();
    let children = vec![
        child(ChildRole::SystemVolume, "gateway-system", 4),
        child(ChildRole::VmmProcess, "gateway-vmm", 3),
        child(ChildRole::GuestControlEndpoint, "gateway-guest-control", 2),
        child(ChildRole::ChApiEndpoint, "gateway-ch-api", 1),
    ];
    let input = |session, drained, process, children| {
        GuestFinalizationInput::new(
            guest_uid.clone(),
            session,
            drained,
            process,
            children,
            false,
            false,
            false,
        )
        .unwrap()
    };

    let plan = plan_finalization(input(
        SessionState::Active,
        false,
        ProcessState::Running {
            identity_verified: true,
        },
        children.clone(),
    ))
    .unwrap();
    assert_eq!(plan.disposition(), FinalizationDisposition::Progressing);
    assert!(matches!(plan.steps(), [FinalizationStep::DrainGuestLocal]));

    let plan = plan_finalization(input(
        SessionState::Active,
        true,
        ProcessState::Running {
            identity_verified: true,
        },
        children.clone(),
    ))
    .unwrap();
    assert!(matches!(plan.steps(), [FinalizationStep::CloseSession]));

    let plan = plan_finalization(input(
        SessionState::Closed,
        true,
        ProcessState::Running {
            identity_verified: true,
        },
        children.clone(),
    ))
    .unwrap();
    assert!(matches!(plan.steps(), [FinalizationStep::StopVmm { .. }]));

    let mut remaining = children;
    for expected_role in [
        ChildRole::ChApiEndpoint,
        ChildRole::GuestControlEndpoint,
        ChildRole::VmmProcess,
        ChildRole::SystemVolume,
    ] {
        let plan = plan_finalization(input(
            SessionState::Closed,
            true,
            ProcessState::Stopped,
            remaining.clone(),
        ))
        .unwrap();
        assert!(matches!(
            plan.steps(),
            [FinalizationStep::DeleteChild(child)] if child.role() == expected_role
        ));
        remaining.retain(|child| child.role() != expected_role);
    }

    let plan = plan_finalization(input(
        SessionState::Closed,
        true,
        ProcessState::Absent,
        remaining,
    ))
    .unwrap();
    assert_eq!(plan.disposition(), FinalizationDisposition::Complete);
    assert!(matches!(
        plan.steps(),
        [FinalizationStep::ClearGuestFinalizer]
    ));
}

#[test]
fn dead_session_needs_process_and_volume_absence_proof() {
    let safe = GuestFinalizationInput::new(
        ResourceUid::parse(GUEST_UID).unwrap(),
        SessionState::Dead,
        false,
        ProcessState::Absent,
        Vec::new(),
        false,
        false,
        false,
    )
    .unwrap();
    let safe_plan = plan_finalization(safe).unwrap();
    assert_eq!(safe_plan.disposition(), FinalizationDisposition::Complete);
    assert!(matches!(
        safe_plan.steps().last(),
        Some(FinalizationStep::ClearGuestFinalizer)
    ));

    let blocked = GuestFinalizationInput::new(
        ResourceUid::parse(GUEST_UID).unwrap(),
        SessionState::Dead,
        false,
        ProcessState::Running {
            identity_verified: false,
        },
        Vec::new(),
        false,
        true,
        false,
    )
    .unwrap();
    let blocked_plan = plan_finalization(blocked).unwrap();
    assert_eq!(
        blocked_plan.disposition(),
        FinalizationDisposition::Blocked(FinalizationBlockReason::SessionUnavailable)
    );
    assert!(
        !blocked_plan
            .steps()
            .iter()
            .any(|step| matches!(step, FinalizationStep::ClearGuestFinalizer))
    );

    let running = GuestFinalizationInput::new(
        ResourceUid::parse(GUEST_UID).unwrap(),
        SessionState::Dead,
        false,
        ProcessState::Running {
            identity_verified: true,
        },
        vec![child(ChildRole::VmmProcess, "gateway-vmm", 3)],
        false,
        false,
        false,
    )
    .unwrap();
    let running_plan = plan_finalization(running).unwrap();
    assert!(matches!(
        running_plan.steps(),
        [FinalizationStep::StopVmm { .. }]
    ));

    let pending_child = GuestFinalizationInput::new(
        ResourceUid::parse(GUEST_UID).unwrap(),
        SessionState::Closed,
        true,
        ProcessState::Stopped,
        vec![child(ChildRole::ChApiEndpoint, "gateway-ch-api", 1).with_deletion_requested(true)],
        false,
        false,
        false,
    )
    .unwrap();
    assert_eq!(
        plan_finalization(pending_child).unwrap().disposition(),
        FinalizationDisposition::Blocked(FinalizationBlockReason::TransitiveDescendant)
    );
}

#[test]
fn child_cleanup_finalizer_does_not_block_the_first_delete_request() {
    let pending = child(ChildRole::ChApiEndpoint, "gateway-ch-api", 1)
        .with_finalizers_pending(true);
    let input = GuestFinalizationInput::new(
        ResourceUid::parse(GUEST_UID).unwrap(),
        SessionState::Closed,
        true,
        ProcessState::Stopped,
        vec![pending],
        false,
        false,
        false,
    )
    .unwrap();
    let plan = plan_finalization(input).unwrap();
    assert!(matches!(
        plan.steps(),
        [FinalizationStep::DeleteChild(child)] if child.role() == ChildRole::ChApiEndpoint
    ));
}

#[test]
fn already_requested_child_with_cleared_finalizers_is_left_for_platform_removal() {
    let requested = child(ChildRole::ChApiEndpoint, "gateway-ch-api", 1)
        .with_deletion_requested(true);
    let input = GuestFinalizationInput::new(
        ResourceUid::parse(GUEST_UID).unwrap(),
        SessionState::Closed,
        true,
        ProcessState::Stopped,
        vec![requested],
        false,
        false,
        false,
    )
    .unwrap();
    let plan = plan_finalization(input).unwrap();
    assert_eq!(
        plan.disposition(),
        FinalizationDisposition::Blocked(FinalizationBlockReason::TransitiveDescendant)
    );
    assert!(matches!(
        plan.steps(),
        [FinalizationStep::WaitForDescendants]
    ));
}

#[test]
fn already_requested_child_with_a_cleanup_finalizer_only_waits_for_platform_removal() {
    let requested = child(ChildRole::ChApiEndpoint, "gateway-ch-api", 1)
        .with_deletion_requested(true)
        .with_finalizers_pending(true);
    let input = GuestFinalizationInput::new(
        ResourceUid::parse(GUEST_UID).unwrap(),
        SessionState::Closed,
        true,
        ProcessState::Stopped,
        vec![requested],
        false,
        false,
        false,
    )
    .unwrap();
    let plan = plan_finalization(input).unwrap();
    assert_eq!(
        plan.disposition(),
        FinalizationDisposition::Blocked(FinalizationBlockReason::ChildFinalizer)
    );
    assert!(!plan
        .steps()
        .iter()
        .any(|step| matches!(step, FinalizationStep::DeleteChild(_))));
}

#[test]
fn disruptive_upgrade_preserves_durable_volume_and_advances_session_generation() {
    let durable = child(ChildRole::SystemVolume, "gateway-system", 4);
    let process = child(ChildRole::VmmProcess, "gateway-vmm", 3);
    let endpoint = child(ChildRole::ChApiEndpoint, "gateway-ch-api", 1);
    let plan = plan_upgrade(
        ResourceRef::parse("Guest/gateway").unwrap(),
        ResourceUid::parse(GUEST_UID).unwrap(),
        vec![durable.clone(), process, endpoint],
        Some(9),
        UpgradeReason::ImageOrSystemGenerationChanged,
    )
    .unwrap();
    assert_eq!(plan.reason(), UpgradeReason::ImageOrSystemGenerationChanged);
    assert!(plan.preserve_state());
    assert_eq!(plan.durable_volumes(), &[durable]);
    assert_eq!(plan.next_session_generation(), 10);
    assert!(!d2b_provider_runtime_cloud_hypervisor::session_generation_is_fresh(Some(9), 9));
    assert!(
        d2b_provider_runtime_cloud_hypervisor::session_generation_is_fresh(
            Some(9),
            plan.next_session_generation()
        )
    );
    assert!(
        plan.transient_children()
            .iter()
            .all(|child| child.role() != ChildRole::SystemVolume)
    );
    assert!(matches!(
        plan.steps().get(2),
        Some(FinalizationStep::InvalidateSession { .. })
    ));
}
