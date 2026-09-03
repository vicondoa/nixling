use d2b_provider_shell_terminal::{
    AdoptionDecision, CallerOrigin, ExecutionTarget, InMemoryShellAuthority, OpenSessionRequest,
    PoolSpec, Role, ShellPool, ShellSession, ShellTerminalController, Subject, SupervisorCandidate,
    SupervisorIdentity,
};
use std::sync::Arc;

fn pool() -> ShellPool {
    ShellPool::new(
        "guest-alice",
        "dev",
        PoolSpec::new(
            ExecutionTarget::guest("work"),
            "alice",
            "artifact://shells/bash-login",
            1,
            1,
            4096,
        )
        .unwrap(),
    )
    .unwrap()
}

fn controller() -> ShellTerminalController {
    ShellTerminalController::new(Arc::new(InMemoryShellAuthority::new()))
}

#[test]
fn controller_creates_one_pool_derived_session_without_provider_state() {
    assert!(OpenSessionRequest::new("guest_alice", "main", None).is_err());
    let mut controller = controller();
    controller.insert_pool(pool()).unwrap();
    let request = Subject::new("dev", CallerOrigin::Local, [Role::ZoneAdmin]);
    let opened = controller
        .open_session(
            &request,
            OpenSessionRequest::new("guest-alice", "main", None).unwrap(),
        )
        .unwrap();

    assert_eq!(opened.session().workload_user(), "alice");
    assert_eq!(opened.supervisor_generation(), 1);
    assert!(controller.provider_state_is_empty());
    assert_eq!(controller.session_count("guest-alice"), 1);
}

#[test]
fn opening_a_session_creates_and_finalizing_deletes_its_process_resource() {
    let authority = Arc::new(InMemoryShellAuthority::new());
    let mut controller = ShellTerminalController::new(authority.clone());
    controller.insert_pool(pool()).unwrap();
    let admin = Subject::new("dev", CallerOrigin::Local, [Role::ZoneAdmin]);
    let opened = controller
        .open_session(
            &admin,
            OpenSessionRequest::new("guest-alice", "main", None).unwrap(),
        )
        .unwrap();

    let process = authority
        .supervisor_process_resource(opened.session().name())
        .expect("session supervisor Process resource");
    assert_eq!(
        process.resource_ref().to_canonical_string(),
        "Process/guest-alice-main"
    );
    assert_eq!(
        process.owner_ref().to_canonical_string(),
        "shell-terminal.d2bus.org.ShellSession/guest-alice-main"
    );
    assert_eq!(
        process
            .spec()
            .execution()
            .execution_ref()
            .to_canonical_string(),
        "Guest/work"
    );
    assert_eq!(
        process
            .spec()
            .execution()
            .user_ref()
            .expect("user-domain supervisor")
            .to_canonical_string(),
        "User/alice"
    );

    controller
        .finalize_session(&admin, opened.session().name(), None)
        .unwrap();
    assert!(
        authority
            .supervisor_process_resource(opened.session().name())
            .is_none(),
        "finalization must delete the target-local Process resource"
    );
}

#[test]
fn shell_session_declares_a_process_child_for_its_supervisor() {
    let pool = pool();
    let session =
        ShellSession::from_pool(&pool, "guest-alice-main", "main", None).expect("valid session");
    assert_eq!(
        session.supervisor_process_ref().to_canonical_string(),
        "Process/guest-alice-main"
    );
    assert_eq!(
        session.supervisor_execution_ref().to_canonical_string(),
        "Guest/work"
    );
    assert_eq!(
        session.supervisor_user_ref().to_canonical_string(),
        "User/alice"
    );
}

#[test]
fn unauthorized_requests_fail_before_resource_lookup() {
    let mut controller = controller();
    let viewer = Subject::new("dev", CallerOrigin::Local, [Role::Viewer]);
    assert!(matches!(
        controller.open_session(
            &viewer,
            OpenSessionRequest::new("missing", "main", None).unwrap(),
        ),
        Err(d2b_provider_shell_terminal::ShellTerminalError::NotAuthorized)
    ));
    assert!(matches!(
        controller.restart_supervisor(&viewer, "missing-main", None),
        Err(d2b_provider_shell_terminal::ShellTerminalError::NotAuthorized)
    ));
}

#[test]
fn restored_sessions_block_recreation_after_controller_restart() {
    let authority = Arc::new(InMemoryShellAuthority::new());
    let mut first_controller = ShellTerminalController::new(authority.clone());
    first_controller.insert_pool(pool()).unwrap();
    let admin = Subject::new("dev", CallerOrigin::Local, [Role::ZoneAdmin]);
    let opened = first_controller
        .open_session(
            &admin,
            OpenSessionRequest::new("guest-alice", "main", None).unwrap(),
        )
        .unwrap();
    assert!(
        authority
            .supervisor_process_resource(opened.session().name())
            .is_some()
    );
    let identity =
        SupervisorIdentity::new([1; 32], [2; 32], opened.supervisor_generation()).unwrap();
    let mut old_supervisor = opened.start_supervisor(identity.clone()).unwrap();
    let old_attachment = old_supervisor
        .attach(
            &admin,
            d2b_provider_shell_terminal::AttachRequest::new(opened.supervisor_generation(), 0)
                .unwrap(),
        )
        .unwrap()
        .attachment();

    let mut recovered_controller = ShellTerminalController::new(authority.clone());
    recovered_controller.restore_pool(pool(), 1).unwrap();
    assert_eq!(
        recovered_controller
            .restore_session(
                opened.session().clone(),
                &identity,
                &[SupervisorCandidate::new(
                    opened.session().name(),
                    identity.clone(),
                )],
            )
            .unwrap(),
        AdoptionDecision::Adopted
    );
    assert_eq!(recovered_controller.session_count("guest-alice"), 1);
    assert!(matches!(
        recovered_controller.open_session(
            &admin,
            OpenSessionRequest::new("guest-alice", "main", None).unwrap(),
        ),
        Err(d2b_provider_shell_terminal::ShellTerminalError::CapacityExceeded)
    ));
    let restarted = recovered_controller
        .restart_supervisor(&admin, opened.session().name(), Some(&identity))
        .unwrap();
    let new_identity =
        SupervisorIdentity::new([3; 32], [4; 32], restarted.supervisor_generation()).unwrap();
    let mut new_supervisor = restarted.start_supervisor(new_identity.clone()).unwrap();
    assert!(matches!(
        old_supervisor.attach(
            &admin,
            d2b_provider_shell_terminal::AttachRequest::new(opened.supervisor_generation(), 0,)
                .unwrap(),
        ),
        Err(d2b_provider_shell_terminal::ShellTerminalError::StaleSessionGeneration)
    ));
    assert!(matches!(
        new_supervisor.attach(
            &admin,
            d2b_provider_shell_terminal::AttachRequest::new(restarted.supervisor_generation(), 0,)
                .unwrap(),
        ),
        Err(d2b_provider_shell_terminal::ShellTerminalError::CapacityExceeded)
    ));
    old_supervisor.detach(&admin, old_attachment).unwrap();
    let new_attachment = new_supervisor
        .attach(
            &admin,
            d2b_provider_shell_terminal::AttachRequest::new(restarted.supervisor_generation(), 0)
                .unwrap(),
        )
        .unwrap()
        .attachment();
    new_supervisor.detach(&admin, new_attachment).unwrap();
    recovered_controller
        .finalize_session(&admin, opened.session().name(), Some(&new_identity))
        .unwrap();
    assert!(
        authority
            .supervisor_process_resource(opened.session().name())
            .is_none()
    );
}

#[test]
fn duplicate_supervisor_start_is_rejected_by_daemon_authority() {
    let mut controller = controller();
    controller.insert_pool(pool()).unwrap();
    let admin = Subject::new("dev", CallerOrigin::Local, [Role::ZoneAdmin]);
    let opened = controller
        .open_session(
            &admin,
            OpenSessionRequest::new("guest-alice", "main", None).unwrap(),
        )
        .unwrap();
    let identity =
        SupervisorIdentity::new([1; 32], [2; 32], opened.supervisor_generation()).unwrap();
    let _supervisor = opened.start_supervisor(identity.clone()).unwrap();

    assert!(matches!(
        opened.start_supervisor(identity),
        Err(d2b_provider_shell_terminal::ShellTerminalError::SupervisorAmbiguous)
    ));
}

#[test]
fn restarted_session_advances_generation_and_rejects_old_capability() {
    let mut controller = controller();
    controller.insert_pool(pool()).unwrap();
    let admin = Subject::new("dev", CallerOrigin::Local, [Role::ZoneAdmin]);
    let opened = controller
        .open_session(
            &admin,
            OpenSessionRequest::new("guest-alice", "main", None).unwrap(),
        )
        .unwrap();

    let restarted = controller
        .restart_supervisor(&admin, opened.session().name(), None)
        .unwrap();
    assert_eq!(restarted.supervisor_generation(), 2);
    let mut supervisor = restarted
        .start_supervisor(SupervisorIdentity::new([3; 32], [4; 32], 2).unwrap())
        .unwrap();
    assert!(matches!(
        supervisor.attach_with_capability(&admin, opened.capability()),
        Err(d2b_provider_shell_terminal::ShellTerminalError::StaleSessionGeneration)
    ));
}

#[test]
fn mismatched_retiring_identity_cannot_advance_generation() {
    let mut controller = controller();
    controller.insert_pool(pool()).unwrap();
    let admin = Subject::new("dev", CallerOrigin::Local, [Role::ZoneAdmin]);
    let opened = controller
        .open_session(
            &admin,
            OpenSessionRequest::new("guest-alice", "main", None).unwrap(),
        )
        .unwrap();
    let claimed =
        SupervisorIdentity::new([1; 32], [2; 32], opened.supervisor_generation()).unwrap();
    let _supervisor = opened.start_supervisor(claimed.clone()).unwrap();
    let mismatched = SupervisorIdentity::new([3; 32], [4; 32], claimed.generation()).unwrap();

    assert!(matches!(
        controller.restart_supervisor(&admin, opened.session().name(), Some(&mismatched)),
        Err(d2b_provider_shell_terminal::ShellTerminalError::SupervisorAmbiguous)
    ));
    let restarted = controller
        .restart_supervisor(&admin, opened.session().name(), Some(&claimed))
        .unwrap();
    assert_eq!(restarted.supervisor_generation(), 2);
}

#[test]
fn restored_pool_attachment_count_blocks_new_attachments() {
    let restored_pool = ShellPool::new(
        "guest-alice",
        "dev",
        PoolSpec::new(
            ExecutionTarget::guest("work"),
            "alice",
            "artifact://shells/bash-login",
            2,
            1,
            4096,
        )
        .unwrap(),
    )
    .unwrap();
    let mut controller = controller();
    controller.restore_pool(restored_pool, 1).unwrap();
    let admin = Subject::new("dev", CallerOrigin::Local, [Role::ZoneAdmin]);
    let opened = controller
        .open_session(
            &admin,
            OpenSessionRequest::new("guest-alice", "main", None).unwrap(),
        )
        .unwrap();
    let mut supervisor = opened
        .start_supervisor(
            SupervisorIdentity::new([1; 32], [2; 32], opened.supervisor_generation()).unwrap(),
        )
        .unwrap();

    assert!(matches!(
        supervisor.attach(
            &admin,
            d2b_provider_shell_terminal::AttachRequest::new(opened.supervisor_generation(), 0,)
                .unwrap(),
        ),
        Err(d2b_provider_shell_terminal::ShellTerminalError::CapacityExceeded)
    ));
    controller
        .reconcile_pool_attachments("guest-alice", 0)
        .unwrap();
    assert!(
        supervisor
            .attach(
                &admin,
                d2b_provider_shell_terminal::AttachRequest::new(opened.supervisor_generation(), 0,)
                    .unwrap(),
            )
            .is_ok()
    );
}

#[test]
fn recovery_authorities_refuse_different_pool_or_session() {
    let authority = Arc::new(InMemoryShellAuthority::new());
    let mut controller = ShellTerminalController::new(authority.clone());
    let source_pool = pool();
    controller.insert_pool(source_pool.clone()).unwrap();
    let admin = Subject::new("dev", CallerOrigin::Local, [Role::ZoneAdmin]);
    let _first = controller
        .open_session(
            &admin,
            OpenSessionRequest::new("guest-alice", "main", None).unwrap(),
        )
        .unwrap();
    let different_pool = ShellPool::new(
        "guest-alice",
        "dev",
        PoolSpec::new(
            ExecutionTarget::guest("work"),
            "bob",
            "artifact://shells/bash-login",
            1,
            1,
            4096,
        )
        .unwrap(),
    )
    .unwrap();
    let mut recovered_controller = ShellTerminalController::new(authority.clone());
    assert!(
        recovered_controller
            .restore_pool(different_pool, 0)
            .is_err()
    );

    let foreign_session =
        ShellSession::from_pool(&source_pool, "guest-alice-other", "other", None).unwrap();
    let identity = SupervisorIdentity::new([1; 32], [2; 32], 1).unwrap();
    let mut session_recovery = ShellTerminalController::new(authority);
    session_recovery.restore_pool(source_pool, 0).unwrap();
    assert_eq!(
        session_recovery
            .restore_session(
                foreign_session.clone(),
                &identity,
                &[SupervisorCandidate::new(
                    foreign_session.name(),
                    identity.clone(),
                )],
            )
            .unwrap(),
        AdoptionDecision::Ambiguous
    );
    assert!(matches!(
        session_recovery.restart_supervisor(&admin, foreign_session.name(), None),
        Err(d2b_provider_shell_terminal::ShellTerminalError::SupervisorAmbiguous)
    ));
}

#[test]
fn ambiguous_recovery_cannot_advance_daemon_session_generation() {
    let authority = Arc::new(InMemoryShellAuthority::new());
    let mut first_controller = ShellTerminalController::new(authority.clone());
    first_controller.insert_pool(pool()).unwrap();
    let admin = Subject::new("dev", CallerOrigin::Local, [Role::ZoneAdmin]);
    let opened = first_controller
        .open_session(
            &admin,
            OpenSessionRequest::new("guest-alice", "main", None).unwrap(),
        )
        .unwrap();
    let expected = SupervisorIdentity::new([1; 32], [2; 32], 1).unwrap();
    let stale = SupervisorIdentity::new([3; 32], [4; 32], 2).unwrap();

    let mut recovered_controller = ShellTerminalController::new(authority);
    recovered_controller.restore_pool(pool(), 0).unwrap();
    assert_eq!(
        recovered_controller
            .restore_session(
                opened.session().clone(),
                &expected,
                &[SupervisorCandidate::new(opened.session().name(), stale)],
            )
            .unwrap(),
        AdoptionDecision::StaleGeneration
    );
    assert!(matches!(
        recovered_controller.restart_supervisor(&admin, opened.session().name(), None),
        Err(d2b_provider_shell_terminal::ShellTerminalError::SupervisorAmbiguous)
    ));
}

#[test]
fn daemon_authority_enforces_session_capacity_across_controllers() {
    let authority = Arc::new(InMemoryShellAuthority::new());
    let mut first_controller = ShellTerminalController::new(authority.clone());
    first_controller.insert_pool(pool()).unwrap();
    let admin = Subject::new("dev", CallerOrigin::Local, [Role::ZoneAdmin]);
    first_controller
        .open_session(
            &admin,
            OpenSessionRequest::new("guest-alice", "main", None).unwrap(),
        )
        .unwrap();

    let mut recovered_controller = ShellTerminalController::new(authority);
    recovered_controller.restore_pool(pool(), 0).unwrap();
    assert!(matches!(
        recovered_controller.open_session(
            &admin,
            OpenSessionRequest::new("guest-alice", "other", None).unwrap(),
        ),
        Err(d2b_provider_shell_terminal::ShellTerminalError::CapacityExceeded)
    ));
}

#[test]
fn finalization_retires_authority_after_owned_attachments_close() {
    let mut controller = controller();
    controller.insert_pool(pool()).unwrap();
    let admin = Subject::new("dev", CallerOrigin::Local, [Role::ZoneAdmin]);
    let opened = controller
        .open_session(
            &admin,
            OpenSessionRequest::new("guest-alice", "main", None).unwrap(),
        )
        .unwrap();
    let identity =
        SupervisorIdentity::new([1; 32], [2; 32], opened.supervisor_generation()).unwrap();
    let mut supervisor = opened.start_supervisor(identity.clone()).unwrap();
    let attachment = supervisor
        .attach(
            &admin,
            d2b_provider_shell_terminal::AttachRequest::new(opened.supervisor_generation(), 0)
                .unwrap(),
        )
        .unwrap()
        .attachment();

    assert!(matches!(
        controller.finalize_session(&admin, opened.session().name(), Some(&identity)),
        Err(d2b_provider_shell_terminal::ShellTerminalError::CapacityExceeded)
    ));
    supervisor.detach(&admin, attachment).unwrap();
    controller
        .finalize_session(&admin, opened.session().name(), Some(&identity))
        .unwrap();
    assert!(
        controller
            .open_session(
                &admin,
                OpenSessionRequest::new("guest-alice", "other", None).unwrap(),
            )
            .is_ok()
    );
}

#[test]
fn controller_and_open_result_debug_are_redacted() {
    let mut controller = controller();
    controller.insert_pool(pool()).unwrap();
    let admin = Subject::new("dev", CallerOrigin::Local, [Role::ZoneAdmin]);
    let opened = controller
        .open_session(
            &admin,
            OpenSessionRequest::new("guest-alice", "main", None).unwrap(),
        )
        .unwrap();

    let rendered = format!("{opened:?}");
    assert!(!rendered.contains("guest-alice"));
    assert!(!rendered.contains("alice"));
    assert!(!rendered.contains("artifact://"));
    let controller_rendered = format!("{controller:?}");
    assert!(!controller_rendered.contains("guest-alice"));
    assert!(!controller_rendered.contains("alice"));
    assert!(!format!("{:?}", pool()).contains("guest-alice"));
    assert!(!format!("{:?}", opened.session()).contains("artifact://"));
    assert!(
        !format!(
            "{:?}",
            OpenSessionRequest::new("guest-alice", "main", None).unwrap()
        )
        .contains("guest-alice")
    );
    assert!(
        !format!(
            "{:?}",
            Subject::new("dev", CallerOrigin::Local, [Role::ZoneAdmin])
        )
        .contains("dev")
    );
}

#[test]
fn attachment_reconciliation_needs_proven_stale_handles() {
    let mut controller = controller();
    controller.insert_pool(pool()).unwrap();
    let admin = Subject::new("dev", CallerOrigin::Local, [Role::ZoneAdmin]);
    let opened = controller
        .open_session(
            &admin,
            OpenSessionRequest::new("guest-alice", "main", None).unwrap(),
        )
        .unwrap();
    let mut supervisor = opened
        .start_supervisor(
            SupervisorIdentity::new([1; 32], [2; 32], opened.supervisor_generation()).unwrap(),
        )
        .unwrap();
    let attachment = supervisor
        .attach(
            &admin,
            d2b_provider_shell_terminal::AttachRequest::new(opened.supervisor_generation(), 0)
                .unwrap(),
        )
        .unwrap()
        .attachment();

    assert!(
        controller
            .reconcile_pool_attachments("guest-alice", 0)
            .is_err()
    );
    controller
        .retire_pool_attachments("guest-alice", &[attachment], 0)
        .unwrap();
    assert!(
        supervisor
            .attach(
                &admin,
                d2b_provider_shell_terminal::AttachRequest::new(opened.supervisor_generation(), 0,)
                    .unwrap(),
            )
            .is_ok()
    );
}

#[test]
fn stale_retirement_preserves_the_authoritative_attachment_total() {
    let two_attachment_pool = ShellPool::new(
        "guest-alice",
        "dev",
        PoolSpec::new(
            ExecutionTarget::guest("work"),
            "alice",
            "artifact://shells/bash-login",
            2,
            2,
            4096,
        )
        .unwrap(),
    )
    .unwrap();
    let mut controller = controller();
    controller.insert_pool(two_attachment_pool).unwrap();
    let admin = Subject::new("dev", CallerOrigin::Local, [Role::ZoneAdmin]);
    let opened = controller
        .open_session(
            &admin,
            OpenSessionRequest::new("guest-alice", "main", None).unwrap(),
        )
        .unwrap();
    let mut supervisor = opened
        .start_supervisor(
            SupervisorIdentity::new([1; 32], [2; 32], opened.supervisor_generation()).unwrap(),
        )
        .unwrap();
    let first = supervisor
        .attach(
            &admin,
            d2b_provider_shell_terminal::AttachRequest::new(opened.supervisor_generation(), 0)
                .unwrap(),
        )
        .unwrap()
        .attachment();
    supervisor
        .attach(
            &admin,
            d2b_provider_shell_terminal::AttachRequest::new(opened.supervisor_generation(), 0)
                .unwrap(),
        )
        .unwrap();

    controller
        .retire_pool_attachments("guest-alice", &[first.clone(), first], 1)
        .unwrap();
    assert!(
        supervisor
            .attach(
                &admin,
                d2b_provider_shell_terminal::AttachRequest::new(opened.supervisor_generation(), 0)
                    .unwrap(),
            )
            .is_ok()
    );
}

#[test]
fn daemon_authority_fences_separate_controller_and_supervisor_processes() {
    let authority = Arc::new(InMemoryShellAuthority::new());
    let mut first_controller = ShellTerminalController::new(authority.clone());
    first_controller.insert_pool(pool()).unwrap();
    let admin = Subject::new("dev", CallerOrigin::Local, [Role::ZoneAdmin]);
    let opened = first_controller
        .open_session(
            &admin,
            OpenSessionRequest::new("guest-alice", "main", None).unwrap(),
        )
        .unwrap();
    let identity =
        SupervisorIdentity::new([1; 32], [2; 32], opened.supervisor_generation()).unwrap();
    let mut old_supervisor = opened.start_supervisor(identity.clone()).unwrap();
    let old_attachment = old_supervisor
        .attach(
            &admin,
            d2b_provider_shell_terminal::AttachRequest::new(opened.supervisor_generation(), 0)
                .unwrap(),
        )
        .unwrap()
        .attachment();

    let mut recovered_controller = ShellTerminalController::new(authority);
    recovered_controller.restore_pool(pool(), 1).unwrap();
    assert_eq!(
        recovered_controller
            .restore_session(
                opened.session().clone(),
                &identity,
                &[SupervisorCandidate::new(
                    opened.session().name(),
                    identity.clone(),
                )],
            )
            .unwrap(),
        AdoptionDecision::Adopted
    );
    let restarted = recovered_controller
        .restart_supervisor(&admin, opened.session().name(), Some(&identity))
        .unwrap();
    let mut new_supervisor = restarted
        .start_supervisor(
            SupervisorIdentity::new([3; 32], [4; 32], restarted.supervisor_generation()).unwrap(),
        )
        .unwrap();

    assert!(matches!(
        old_supervisor.attach(
            &admin,
            d2b_provider_shell_terminal::AttachRequest::new(opened.supervisor_generation(), 0)
                .unwrap(),
        ),
        Err(d2b_provider_shell_terminal::ShellTerminalError::StaleSessionGeneration)
    ));
    assert!(matches!(
        new_supervisor.attach(
            &admin,
            d2b_provider_shell_terminal::AttachRequest::new(restarted.supervisor_generation(), 0)
                .unwrap(),
        ),
        Err(d2b_provider_shell_terminal::ShellTerminalError::CapacityExceeded)
    ));
    old_supervisor.detach(&admin, old_attachment).unwrap();
    assert!(
        new_supervisor
            .attach(
                &admin,
                d2b_provider_shell_terminal::AttachRequest::new(
                    restarted.supervisor_generation(),
                    0,
                )
                .unwrap(),
            )
            .is_ok()
    );
}

#[test]
fn daemon_authority_replays_capabilities_once_across_supervisors() {
    let authority = Arc::new(InMemoryShellAuthority::new());
    let mut first_controller = ShellTerminalController::new(authority.clone());
    first_controller.insert_pool(pool()).unwrap();
    let admin = Subject::new("dev", CallerOrigin::Local, [Role::ZoneAdmin]);
    let opened = first_controller
        .open_session(
            &admin,
            OpenSessionRequest::new("guest-alice", "main", None).unwrap(),
        )
        .unwrap();
    let identity =
        SupervisorIdentity::new([1; 32], [2; 32], opened.supervisor_generation()).unwrap();
    let mut first_supervisor = opened.start_supervisor(identity.clone()).unwrap();

    let mut recovered_controller = ShellTerminalController::new(authority);
    recovered_controller.restore_pool(pool(), 0).unwrap();
    assert_eq!(
        recovered_controller
            .restore_session(
                opened.session().clone(),
                &identity,
                &[SupervisorCandidate::new(
                    opened.session().name(),
                    identity.clone(),
                )],
            )
            .unwrap(),
        AdoptionDecision::Adopted
    );
    let restarted = recovered_controller
        .restart_supervisor(&admin, opened.session().name(), Some(&identity))
        .unwrap();
    let mut second_supervisor = restarted
        .start_supervisor(
            SupervisorIdentity::new([3; 32], [4; 32], restarted.supervisor_generation()).unwrap(),
        )
        .unwrap();
    let replayed_capability = restarted.capability();

    assert!(matches!(
        first_supervisor.attach_with_capability(&admin, opened.capability()),
        Err(d2b_provider_shell_terminal::ShellTerminalError::StaleSessionGeneration)
    ));
    assert!(
        second_supervisor
            .attach_with_capability(&admin, replayed_capability.clone())
            .is_ok()
    );
    assert!(matches!(
        second_supervisor.attach_with_capability(&admin, replayed_capability),
        Err(d2b_provider_shell_terminal::ShellTerminalError::CapabilityReused)
    ));
}

#[test]
fn shell_runner_contract_keeps_pool_and_session_on_one_cutover() {
    let contract = d2b_provider_shell_terminal::shell_runner_contract();
    assert_eq!(
        contract.pool_resource_type(),
        "shell-terminal.d2bus.org.ShellPool"
    );
    assert_eq!(
        contract.session_resource_type(),
        "shell-terminal.d2bus.org.ShellSession"
    );
    assert_eq!(
        contract.pool_finalizer(),
        "shell-terminal.d2bus.org/pool-finalizer"
    );
    assert_eq!(
        contract.session_finalizer(),
        "shell-terminal.d2bus.org/session-finalizer"
    );
    assert_eq!(contract.repair_interval_secs(), 30);
    assert!(contract.watched_configuration_is_dependency());
}
