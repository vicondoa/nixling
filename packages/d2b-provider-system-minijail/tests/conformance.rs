//! The shared Process conformance suite run against `system-minijail`,
//! plus the minijail-specific pidfd, wait-ownership, and adoption
//! obligations.

use d2b_contracts_resource::v3::ResourceGeneration;
use d2b_contracts_resource::v3::identity::ReconnectGeneration;
use d2b_process_conformance::suite;
use d2b_process_conformance::testing::{PortCall, ScriptedEffectPort, block_on, fixtures};
use d2b_process_conformance::{
    AdoptionOutcome, ConfigurationDigest, IdentityBinding, ProcessConformanceError,
    ProcessIdentityDigest, ProcessPhaseClass, ProcessProvider, ReadinessExpectation, StopClass,
    WaitReapOwner,
};
use d2b_provider_system_minijail::launch::{
    MinijailReconcileAction, MinijailReconcileResult, reconcile as reconcile_action,
};
use d2b_provider_system_minijail::{MinijailProcessProvider, PROVIDER_NAME};

fn required() -> Vec<IdentityBinding> {
    vec![
        IdentityBinding::Pid,
        IdentityBinding::ProcessStartTime,
        IdentityBinding::Cgroup,
        IdentityBinding::Executable,
        IdentityBinding::Template,
        IdentityBinding::Generation,
    ]
}

fn provider(port: ScriptedEffectPort) -> MinijailProcessProvider<ScriptedEffectPort> {
    MinijailProcessProvider::new(port)
}

fn launching() -> MinijailProcessProvider<ScriptedEffectPort> {
    provider(ScriptedEffectPort::launching(
        required(),
        WaitReapOwner::Local,
    ))
}

#[test]
fn typed_handler_dispatches_start_without_waiting_for_terminal_exit() {
    let provider = launching();
    let ticket = fixtures::ticket_builder()
        .selected_provider(PROVIDER_NAME)
        .expected_identity(required())
        .build()
        .expect("conformant ticket");
    let result = block_on(reconcile_action(
        &provider,
        MinijailReconcileAction::Start(&ticket),
    ))
    .expect("typed start");
    assert!(matches!(result, MinijailReconcileResult::Started(_)));
    assert_eq!(provider.port().calls(), vec![PortCall::Launch]);
}

#[test]
fn shared_conformance_holds() {
    suite::assert_launch_is_locality_neutral(&launching(), PROVIDER_NAME);
    suite::assert_foreign_provider_selection_is_rejected(&launching());
    suite::assert_domain_support_matches_the_profile(&launching(), PROVIDER_NAME);
    suite::assert_status_is_redacted(&launching(), PROVIDER_NAME);
    suite::assert_incomplete_launch_identity_fails_closed(provider, PROVIDER_NAME);
    suite::assert_adoption_verifies_identity_before_opening_a_pidfd(provider, PROVIDER_NAME);
    suite::assert_finalizer_requires_verified_stop(WaitReapOwner::Local);
}

#[test]
fn d2b_owns_wait_and_reap() {
    assert_eq!(
        launching().profile().wait_reap_owner(),
        WaitReapOwner::Local
    );
    let mismatched = provider(ScriptedEffectPort::launching(
        required(),
        WaitReapOwner::ServiceManager,
    ));
    let ticket = fixtures::ticket_builder()
        .selected_provider(PROVIDER_NAME)
        .expected_identity(required())
        .build()
        .expect("conformant ticket");
    assert_eq!(
        block_on(mismatched.launch(&ticket)).unwrap_err(),
        ProcessConformanceError::WaitOwnerMismatch
    );
    assert_eq!(mismatched.port().calls(), vec![PortCall::Launch]);
}

#[test]
fn the_user_domain_is_admitted_only_by_the_descriptor() {
    let ticket = |provider_name: &str| {
        fixtures::ticket_builder()
            .selected_provider(provider_name)
            .expected_identity(required())
            .domain(d2b_contracts_resource::v3::execution_policy::ExecutionDomain::User)
            .user_ref(Some(
                d2b_contracts_resource::v3::ResourceRef::parse("User/alice")
                    .expect("valid reference"),
            ))
            .build()
            .expect("conformant ticket")
    };

    let default = launching();
    assert_eq!(
        block_on(default.launch(&ticket(PROVIDER_NAME))).unwrap_err(),
        ProcessConformanceError::DomainNotSupported
    );

    let admitted = MinijailProcessProvider::with_user_domain(
        ScriptedEffectPort::launching(required(), WaitReapOwner::Local),
        true,
    );
    assert!(block_on(admitted.launch(&ticket(PROVIDER_NAME))).is_ok());
}

#[test]
fn a_reused_pid_without_a_matching_start_time_is_quarantined() {
    // The daemon's pidfd table already treats a pid whose start time does
    // not match as a different process. The same rule is an adoption
    // ambiguity here: quarantine, and never open a pidfd.
    let stale: Vec<IdentityBinding> = required()
        .into_iter()
        .filter(|binding| *binding != IdentityBinding::ProcessStartTime)
        .collect();
    let provider = provider(
        ScriptedEffectPort::launching(required(), WaitReapOwner::Local)
            .with_candidate(stale, WaitReapOwner::Local),
    );
    let ticket = fixtures::ticket_builder()
        .selected_provider(PROVIDER_NAME)
        .expected_identity(required())
        .build()
        .expect("conformant ticket");
    let outcome = block_on(provider.adopt(&ticket)).expect("adoption reports");
    assert!(matches!(outcome, AdoptionOutcome::Quarantined(_)));
    let calls = provider.port().calls();
    assert!(!calls.contains(&PortCall::OpenPidfd));
    suite::assert_pidfd_open_follows_verification(&calls);
}

#[test]
fn a_fully_verified_candidate_is_adopted_after_observation() {
    let provider = provider(
        ScriptedEffectPort::launching(required(), WaitReapOwner::Local)
            .with_candidate(required(), WaitReapOwner::Local),
    );
    let ticket = fixtures::ticket_builder()
        .selected_provider(PROVIDER_NAME)
        .expected_identity(required())
        .build()
        .expect("conformant ticket");
    assert!(matches!(
        block_on(provider.adopt(&ticket)).expect("adoption reports"),
        AdoptionOutcome::Adopted(_)
    ));
    let calls = provider.port().calls();
    assert_eq!(calls, vec![PortCall::Observe, PortCall::OpenPidfd]);
    suite::assert_pidfd_open_follows_verification(&calls);
}

#[test]
fn a_readable_stale_candidate_is_exposed_for_exact_replacement() {
    let stale: Vec<IdentityBinding> = required()
        .into_iter()
        .filter(|binding| *binding != IdentityBinding::Executable)
        .collect();
    let provider = provider(
        ScriptedEffectPort::launching(required(), WaitReapOwner::Local)
            .with_candidate(stale, WaitReapOwner::Local),
    );
    let ticket = fixtures::ticket_builder()
        .selected_provider(PROVIDER_NAME)
        .expected_identity(required())
        .build()
        .expect("conformant ticket");

    let candidate = match block_on(provider.adopt(&ticket)).expect("adoption reports") {
        AdoptionOutcome::Stale { candidate } => candidate,
        other => panic!("expected stale candidate, observed {other:?}"),
    };
    block_on(provider.stop_stale(&candidate)).expect("exact stale stop");
    assert_eq!(
        provider.port().calls(),
        vec![
            PortCall::Observe,
            PortCall::OpenPidfd,
            PortCall::Stop(StopClass::Terminate),
        ]
    );
}

#[test]
fn malformed_readiness_is_rejected_before_effect_dispatch() {
    let provider = provider(ScriptedEffectPort::launching(
        required(),
        WaitReapOwner::Local,
    ));
    let ticket = fixtures::ticket_builder()
        .selected_provider(PROVIDER_NAME)
        .expected_identity(required())
        .build()
        .expect("conformant ticket")
        .with_readiness(ReadinessExpectation::Condition { timeout_ms: 0 });

    assert_eq!(
        block_on(provider.launch(&ticket)).unwrap_err(),
        ProcessConformanceError::InvalidTicket
    );
    assert!(provider.port().calls().is_empty());
}

#[test]
fn readiness_is_verified_before_reporting_ready() {
    let provider = provider(
        ScriptedEffectPort::launching(required(), WaitReapOwner::Local)
            .with_candidate(required(), WaitReapOwner::Local),
    );
    let ticket = fixtures::ticket_builder()
        .selected_provider(PROVIDER_NAME)
        .expected_identity(required())
        .build()
        .expect("conformant ticket")
        .with_readiness(ReadinessExpectation::condition(1_000).expect("bounded readiness"));

    let report = block_on(provider.launch(&ticket)).expect("ready launch");
    assert_eq!(report.phase, ProcessPhaseClass::Ready);
    assert_eq!(
        provider.port().calls(),
        vec![PortCall::Launch, PortCall::Observe]
    );
}

#[test]
fn a_readiness_timeout_stops_the_exact_launched_identity() {
    let provider = launching();
    let ticket = fixtures::ticket_builder()
        .selected_provider(PROVIDER_NAME)
        .expected_identity(required())
        .build()
        .expect("conformant ticket")
        .with_readiness(ReadinessExpectation::condition(1_000).expect("bounded readiness"));

    assert_eq!(
        block_on(provider.launch(&ticket)).unwrap_err(),
        ProcessConformanceError::DeadlineExceeded
    );
    assert_eq!(
        provider.port().calls(),
        vec![
            PortCall::Launch,
            PortCall::Observe,
            PortCall::Stop(StopClass::Terminate)
        ]
    );
}

#[test]
fn an_adoption_identity_seal_mismatch_is_quarantined_before_pidfd_open() {
    let provider = provider(
        ScriptedEffectPort::launching(required(), WaitReapOwner::Local)
            .with_candidate(required(), WaitReapOwner::Local),
    );
    let ticket = fixtures::ticket_builder()
        .selected_provider(PROVIDER_NAME)
        .expected_identity(required())
        .build()
        .expect("conformant ticket")
        .with_expected_identity_digest(ProcessIdentityDigest::from_bytes([0x22; 32]))
        .expect("nonzero identity seal");

    assert!(matches!(
        block_on(provider.adopt(&ticket)).expect("adoption result"),
        AdoptionOutcome::Quarantined(report)
            if report.phase == ProcessPhaseClass::Unknown
    ));
    assert_eq!(provider.port().calls(), vec![PortCall::Observe]);
}

#[test]
fn a_launch_identity_seal_mismatch_fails_closed_without_signalling() {
    let provider = launching();
    let ticket = fixtures::ticket_builder()
        .selected_provider(PROVIDER_NAME)
        .expected_identity(required())
        .build()
        .expect("conformant ticket")
        .with_expected_identity_digest(ProcessIdentityDigest::from_bytes([0x22; 32]))
        .expect("nonzero identity seal");

    assert_eq!(
        block_on(provider.launch(&ticket)).unwrap_err(),
        ProcessConformanceError::TerminalEvidenceMismatch
    );
    assert_eq!(provider.port().calls(), vec![PortCall::Launch]);
}

#[test]
fn stopping_a_zero_identity_is_rejected_without_an_effect() {
    let provider = launching();
    let identity = ProcessIdentityDigest::from_bytes([0; 32]);

    assert_eq!(
        block_on(provider.stop(&identity, StopClass::Terminate)).unwrap_err(),
        ProcessConformanceError::IdentityUnverified
    );
    assert!(provider.port().calls().is_empty());
}

#[test]
fn controller_authority_requires_a_committed_revision_before_launch() {
    let controller_ticket = fixtures::ticket_builder()
        .selected_provider(PROVIDER_NAME)
        .expected_identity(required())
        .build()
        .expect("conformant ticket")
        .with_controller_launch_binding(
            ResourceGeneration::new(2).expect("provider generation"),
            ReconnectGeneration::new(4).expect("session generation"),
            ConfigurationDigest::from_bytes([1; 32]),
            ConfigurationDigest::from_bytes([2; 32]),
        )
        .expect("controller binding");
    let provider = launching();
    assert_eq!(
        block_on(provider.launch(&controller_ticket)).unwrap_err(),
        ProcessConformanceError::InvalidTicket
    );
    assert!(provider.port().calls().is_empty());

    let assignment_ticket = fixtures::ticket_builder()
        .selected_provider(PROVIDER_NAME)
        .expected_identity(required())
        .build()
        .expect("conformant ticket")
        .with_assignment_binding(
            ResourceGeneration::new(2).expect("provider generation"),
            ReconnectGeneration::new(4).expect("session generation"),
            9,
            ConfigurationDigest::from_bytes([3; 32]),
        )
        .expect("assignment binding");
    let provider = launching();
    assert_eq!(
        block_on(provider.launch(&assignment_ticket)).unwrap_err(),
        ProcessConformanceError::InvalidTicket
    );
    assert!(provider.port().calls().is_empty());
}
