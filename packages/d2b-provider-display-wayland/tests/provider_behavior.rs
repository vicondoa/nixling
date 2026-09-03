use d2b_contracts_resource::v3::ResourceRef;
use d2b_provider_display_wayland::{
    DisplayAuditKind, DisplayAuditOutcome, DisplayController, DisplayIdentity,
    DisplayLabelPosition, DisplayProviderDescriptor, DisplayTelemetryField, DisplayTelemetryFrame,
    DisplayUserPortal, FilterInput, Phase, PolicyWarning, PrincipalPool, ProcessObservation,
    ProxyReadinessFailure, ProxyReadinessStage, ProxyReadinessState, WaylandPolicy,
    WaylandPolicySnapshot, WaylandSessionSpec,
};

fn refs() -> (ResourceRef, ResourceRef, ResourceRef, ResourceRef) {
    (
        ResourceRef::parse("Guest/work-vm").unwrap(),
        ResourceRef::parse("Host/host-system").unwrap(),
        ResourceRef::parse("User/alice").unwrap(),
        ResourceRef::parse("display-wayland.d2bus.org.WaylandPolicy/default").unwrap(),
    )
}

fn identity() -> DisplayIdentity {
    DisplayIdentity::new("work-vm", "#7fc8ff", "#45475a", "#f38ba8")
        .unwrap()
        .with_label_position(DisplayLabelPosition::TopLeft)
}

#[test]
fn wayland_session_accepts_the_canonical_debug_logging_filter_field() {
    let value = serde_json::json!({
        "guestRef": "Guest/work-vm",
        "hostRef": "Host/host-system",
        "userRef": "User/alice",
        "policyRef": "display-wayland.d2bus.org.WaylandPolicy/default",
        "identity": {
            "label": "work-vm",
            "activeColor": "#7fc8ff",
            "inactiveColor": "#45475a",
            "urgentColor": "#f38ba8",
            "borderEnabled": true,
            "borderWidth": 2,
            "labelEnabled": true,
            "labelText": "work-vm",
            "labelPosition": "top-left"
        },
        "crossDomainTrusted": true,
        "reconnectGeneration": 1,
        "virglVideo": false,
        "filter": {
            "debugLogging": false,
            "allowGlobals": [],
            "denyGlobals": [],
            "maxVersions": {},
            "dmabufAllow": [],
            "dmabufDeny": []
        }
    });

    let spec = serde_json::from_value::<WaylandSessionSpec>(value).unwrap();
    let encoded = serde_json::to_value(spec).unwrap();
    assert_eq!(encoded["filter"]["debugLogging"], false);
}

fn policy_for(spec: &WaylandSessionSpec) -> WaylandPolicySnapshot {
    WaylandPolicySnapshot::from_test_core(
        spec.policy_ref().clone(),
        d2b_contracts_resource::v3::ZoneId::parse("local").unwrap(),
        1,
        FilterInput::default(),
        FilterInput::default(),
    )
    .unwrap()
}

fn reconcile(
    controller: &mut DisplayController,
    spec: &WaylandSessionSpec,
    dependencies: d2b_provider_display_wayland::DependencyState,
    observation: ProcessObservation,
) -> Result<
    d2b_provider_display_wayland::ReconcileResult,
    d2b_provider_display_wayland::WaylandSpecError,
> {
    let policy = policy_for(spec);
    controller.reconcile_with_policy(spec, dependencies, observation, None, &policy)
}

fn reconcile_with_evidence(
    controller: &mut DisplayController,
    spec: &WaylandSessionSpec,
    dependencies: d2b_provider_display_wayland::DependencyState,
    observation: ProcessObservation,
    evidence: d2b_provider_display_wayland::WorkerRestartEvidence,
) -> Result<
    d2b_provider_display_wayland::ReconcileResult,
    d2b_provider_display_wayland::WaylandSpecError,
> {
    let policy = policy_for(spec);
    controller.reconcile_with_policy_and_evidence(
        spec,
        dependencies,
        observation,
        evidence,
        None,
        &policy,
    )
}

#[test]
fn session_rejects_untrusted_cross_domain_and_invalid_identity() {
    let (guest, host, user, policy) = refs();
    assert!(
        WaylandSessionSpec::new(
            guest.clone(),
            host.clone(),
            user.clone(),
            policy.clone(),
            identity(),
            false,
        )
        .is_err()
    );
    assert!(DisplayIdentity::new("Work VM", "#7fc8ff", "#45475a", "#f38ba8").is_err());
    assert!(DisplayIdentity::new("work-vm", "red", "#45475a", "#f38ba8").is_err());
}

#[test]
fn policy_layering_is_closed_and_clipboard_globals_are_virtualized() {
    let defaults = FilterInput::default();
    let zone = FilterInput::new(
        ["zwp_linux_dmabuf_v1"],
        ["zwp_pointer_constraints_v1", "zwp_linux_dmabuf_v1"],
        Vec::<(String, u32)>::new(),
        Vec::<String>::new(),
    )
    .unwrap();
    let session = FilterInput::new(
        ["zwp_pointer_constraints_v1", "wl_data_device_manager"],
        Vec::<String>::new(),
        Vec::<(String, u32)>::new(),
        Vec::<String>::new(),
    )
    .unwrap();
    let compiled = WaylandPolicy::compile(&defaults, &zone, &session).unwrap();
    assert!(compiled.is_allowed("wl_compositor"));
    assert!(!compiled.is_allowed("zwp_linux_dmabuf_v1"));
    assert!(
        compiled
            .warnings()
            .contains(&PolicyWarning::ClipboardBoundaryIgnored)
    );
    assert!(
        WaylandPolicy::compile(
            &defaults,
            &FilterInput::new(
                ["unknown_global"],
                Vec::<String>::new(),
                Vec::<(String, u32)>::new(),
                Vec::<String>::new(),
            )
            .unwrap(),
            &FilterInput::default(),
        )
        .is_err()
    );
}

#[test]
fn dmabuf_rules_are_compiled_and_digest_bound() {
    let defaults = FilterInput::default();
    let zone = FilterInput::new(
        Vec::<String>::new(),
        Vec::<String>::new(),
        Vec::<(String, u32)>::new(),
        ["format-x"],
    )
    .unwrap()
    .with_dmabuf_deny(["format-y"])
    .unwrap();
    let compiled = WaylandPolicy::compile(&defaults, &zone, &defaults).unwrap();
    assert!(compiled.dmabuf_allowed().contains(&"format-x".to_owned()));
    assert!(compiled.dmabuf_denied().contains(&"format-y".to_owned()));
    assert!(compiled.is_dmabuf_allowed("format-x"));
    assert!(!compiled.is_dmabuf_allowed("format-y"));
}

#[test]
fn principal_pool_is_opaque_and_fails_closed_when_exhausted() {
    let mut pool = PrincipalPool::new(["corp-vm"], 1).unwrap();
    assert_eq!(
        PrincipalPool::principal_for("dev", "corp-vm"),
        "d2b-wlp-e57e8feb6155"
    );
    let lease = pool.acquire_dynamic().unwrap();
    assert!(pool.acquire_dynamic().is_err());
    assert!(format!("{lease:?}").contains("REDACTED"));
    pool.release(lease).unwrap();
    assert!(pool.acquire_dynamic().is_ok());
}

#[test]
fn readiness_event_is_bounded_and_path_free() {
    let event = d2b_provider_display_wayland::ProxyReadinessEvent::failed(
        ProxyReadinessStage::Upstream,
        ProxyReadinessFailure::UpstreamUnavailable,
    );
    let json = serde_json::to_string(&event).unwrap();
    assert_eq!(event.state, ProxyReadinessState::Failed);
    assert!(!json.contains("socket"));
    assert!(!json.contains("path"));
    assert!(json.contains("upstream-unavailable"));
}

#[test]
fn display_descriptor_is_status_first_and_publishes_typed_services() {
    let descriptor = DisplayProviderDescriptor::default();
    assert!(descriptor.validate().is_ok());
    assert!(!descriptor.provider_state_volume);
    assert!(
        descriptor
            .service_packages()
            .contains(&"d2b.display.host-clipboard.v3")
    );
}

#[test]
fn controller_status_transitions_pending_ready_and_failed() {
    let (guest, host, user, policy) = refs();
    let spec = WaylandSessionSpec::new(guest, host, user, policy, identity(), true).unwrap();
    let mut controller = d2b_provider_display_wayland::DisplayController::new(4);
    let pending = reconcile(
        &mut controller,
        &spec,
        d2b_provider_display_wayland::DependencyState::default(),
        d2b_provider_display_wayland::ProcessObservation::default(),
    )
    .unwrap();
    assert_eq!(pending.status.phase, Phase::Pending);
    let ready = reconcile(
        &mut controller,
        &spec,
        d2b_provider_display_wayland::DependencyState::ready(),
        d2b_provider_display_wayland::ProcessObservation::ready_for_session(&spec, 1, 1),
    )
    .unwrap();
    assert_eq!(ready.status.phase, Phase::Ready);
    let failed = reconcile_with_evidence(
        &mut controller,
        &spec,
        d2b_provider_display_wayland::DependencyState::ready(),
        d2b_provider_display_wayland::ProcessObservation::proxy_failed(5),
        d2b_provider_display_wayland::WorkerRestartEvidence::for_test(1_000, Some(0), None, 1),
    )
    .unwrap();
    assert_eq!(failed.status.phase, Phase::Failed);
}

#[test]
fn failed_reconcile_retains_the_session_principal_until_cleanup() {
    let (guest, host, user, policy) = refs();
    let first = WaylandSessionSpec::new(guest, host, user, policy, identity(), true).unwrap();
    let second = WaylandSessionSpec::new(
        ResourceRef::parse("Guest/second").unwrap(),
        ResourceRef::parse("Host/host-system").unwrap(),
        ResourceRef::parse("User/alice").unwrap(),
        ResourceRef::parse("display-wayland.d2bus.org.WaylandPolicy/default").unwrap(),
        DisplayIdentity::new("second", "#7fc8ff", "#45475a", "#f38ba8").unwrap(),
        true,
    )
    .unwrap();
    let mut controller = d2b_provider_display_wayland::DisplayController::new(1);
    let first_status = reconcile(
        &mut controller,
        &first,
        d2b_provider_display_wayland::DependencyState::ready(),
        ProcessObservation::ready_for_session(&first, 1, 1),
    )
    .unwrap()
    .status;
    assert!(first_status.principal.is_some());
    assert_eq!(
        reconcile_with_evidence(
            &mut controller,
            &first,
            d2b_provider_display_wayland::DependencyState::ready(),
            ProcessObservation::proxy_failed(5),
            d2b_provider_display_wayland::WorkerRestartEvidence::for_test(1_000, Some(0), None, 1,),
        )
        .unwrap()
        .status
        .phase,
        Phase::Failed
    );
    assert_eq!(
        reconcile(
            &mut controller,
            &second,
            d2b_provider_display_wayland::DependencyState::ready(),
            ProcessObservation::ready_for_session(&second, 1, 1),
        )
        .unwrap()
        .status
        .phase,
        Phase::Failed
    );
}

#[test]
fn mutable_session_fields_reuse_the_same_principal() {
    let (guest, host, user, policy) = refs();
    let first = WaylandSessionSpec::new(guest, host, user, policy, identity(), true).unwrap();
    let changed = WaylandSessionSpec::new(
        ResourceRef::parse("Guest/work-vm").unwrap(),
        ResourceRef::parse("Host/host-system").unwrap(),
        ResourceRef::parse("User/alice").unwrap(),
        ResourceRef::parse("display-wayland.d2bus.org.WaylandPolicy/changed").unwrap(),
        DisplayIdentity::new("work-vm", "#a6e3a1", "#45475a", "#f38ba8").unwrap(),
        true,
    )
    .unwrap();
    let mut controller = d2b_provider_display_wayland::DisplayController::new(1);
    let first_principal = reconcile(
        &mut controller,
        &first,
        d2b_provider_display_wayland::DependencyState::ready(),
        ProcessObservation::ready_for_session(&first, 1, 1),
    )
    .unwrap()
    .status
    .principal;
    let changed_principal = reconcile(
        &mut controller,
        &changed,
        d2b_provider_display_wayland::DependencyState::ready(),
        ProcessObservation::ready_for_session(&changed, 1, 1),
    )
    .unwrap()
    .status
    .principal;
    assert_eq!(first_principal, changed_principal);
}

#[test]
fn readiness_cannot_be_reused_for_a_different_host_or_user_binding() {
    let (guest, host, user, policy) = refs();
    let spec = WaylandSessionSpec::new(guest, host, user, policy, identity(), true).unwrap();
    let retargeted = WaylandSessionSpec::new(
        ResourceRef::parse("Guest/work-vm").unwrap(),
        ResourceRef::parse("Host/other-host").unwrap(),
        ResourceRef::parse("User/bob").unwrap(),
        ResourceRef::parse("display-wayland.d2bus.org.WaylandPolicy/default").unwrap(),
        identity(),
        true,
    )
    .unwrap();
    let mut controller = d2b_provider_display_wayland::DisplayController::new(2);
    assert_eq!(
        reconcile(
            &mut controller,
            &retargeted,
            d2b_provider_display_wayland::DependencyState::ready(),
            ProcessObservation::ready_for_session(&spec, 1, 1),
        )
        .unwrap()
        .status
        .phase,
        Phase::Pending
    );
}

#[test]
fn wire_deserialization_reuses_display_validation() {
    let value = serde_json::to_value(identity()).unwrap();
    let mut invalid_identity = value;
    invalid_identity["label"] = serde_json::json!("Work VM");
    assert!(serde_json::from_value::<DisplayIdentity>(invalid_identity).is_err());
}

#[test]
fn distinct_authenticated_sessions_do_not_share_display_principals() {
    let (_, host, user, policy) = refs();
    let first = WaylandSessionSpec::new(
        ResourceRef::parse("Guest/first").unwrap(),
        host.clone(),
        user.clone(),
        policy.clone(),
        identity(),
        true,
    )
    .unwrap();
    let second = WaylandSessionSpec::new(
        ResourceRef::parse("Guest/second").unwrap(),
        host,
        user,
        policy,
        identity(),
        true,
    )
    .unwrap();
    let mut controller = d2b_provider_display_wayland::DisplayController::new(2);
    let first_status = reconcile(
        &mut controller,
        &first,
        d2b_provider_display_wayland::DependencyState::ready(),
        ProcessObservation::ready_for_session(&first, 1, 1),
    )
    .unwrap()
    .status;
    let second_status = reconcile(
        &mut controller,
        &second,
        d2b_provider_display_wayland::DependencyState::ready(),
        ProcessObservation::ready_for_session(&second, 1, 1),
    )
    .unwrap()
    .status;
    assert_ne!(first_status.principal, second_status.principal);
}

#[test]
fn portal_is_same_uid_and_finalizer_is_fail_closed() {
    let user = ResourceRef::parse("User/alice").unwrap();
    let portal = DisplayUserPortal::new(user.clone(), 1000, 1).unwrap();
    assert_eq!(portal.active_sessions(), 0);
    assert!(DisplayUserPortal::new(ResourceRef::parse("Guest/work").unwrap(), 1000, 1).is_err());
    assert_eq!(
        d2b_provider_display_wayland::DisplayController::finalizer(),
        "display-wayland.d2bus.org/proxy-stopped"
    );
}

#[test]
fn audit_and_telemetry_reject_identity_bearing_surfaces() {
    let marker = "window-title-canary";
    let record = d2b_provider_display_wayland::DisplayAuditRecord::new(
        DisplayAuditKind::ProxyStarted,
        DisplayAuditOutcome::Success,
        "dev",
        marker,
        "alice",
        "operation-1",
    );
    assert!(!record.to_wire_record().contains(marker));
    let frame =
        DisplayTelemetryFrame::new("dev", d2b_provider_display_wayland::MetricOutcome::Success);
    assert!(
        DisplayTelemetryFrame::validate_collector_fields(frame.metric_labels().to_vec()).is_ok()
    );
    assert!(
        DisplayTelemetryFrame::validate_collector_fields([DisplayTelemetryField {
            key: "window_title",
            value: marker.to_owned(),
        }])
        .is_err()
    );
    let warning = d2b_provider_display_wayland::DisplayAuditRecord::new(
        DisplayAuditKind::PolicyAdvisory,
        DisplayAuditOutcome::Denied,
        "dev",
        "resource",
        "alice",
        "operation-1",
    )
    .with_warning("bad\nwarning", "interface=bad\n");
    let wire = warning.to_wire_record();
    assert!(!wire.contains('\n'));
    assert!(!wire.contains(":interface=bad"));
}

#[test]
fn display_runner_contract_disables_legacy_scheduling() {
    let contract = d2b_provider_display_wayland::display_runner_contract();
    assert_eq!(
        contract.session_resource_type(),
        "display-wayland.d2bus.org.WaylandSession"
    );
    assert_eq!(
        contract.policy_resource_type(),
        "display-wayland.d2bus.org.WaylandPolicy"
    );
    assert_eq!(
        contract.finalizer(),
        "display-wayland.d2bus.org/proxy-stopped"
    );
    assert_eq!(contract.repair_interval_secs(), 30);
    assert_eq!(contract.max_repair_interval_secs(), 60);
    assert!(contract.legacy_scheduler_disabled());
    assert!(contract.watched_configuration_is_dependency());
}
