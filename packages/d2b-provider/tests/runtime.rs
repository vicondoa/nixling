//! Hermetic proofs for the v3 Provider registry, its ZonePath-keyed session
//! identity, and forwarding admission.

use std::time::Duration;

use d2b_contracts_provider::v3::SpecifiedProviderMethod;
use d2b_contracts_resource::v3::ZoneRevision;
use d2b_contracts_resource::v3::identity::{
    AuthenticatedSubjectContext, BindingDigest, EvidenceClass, Locality, ReconnectGeneration,
    ServiceName, SessionBinding, SessionPurpose, TranscriptHash, TransportBinding,
};
use d2b_contracts_resource::v3::{
    ConfigurationGeneration, ResourceGeneration, ResourceName, ResourceRef, ResourceTypeName,
    ResourceUid, SchemaFingerprint,
};
use d2b_contracts_zone_session::v3::{
    component_session::{OperationClass, OperationId},
    zone_routing::{ZoneLabelId, ZonePath},
};
use d2b_provider::{
    AdmissionOptions, CancellationToken, ForwardTarget, PROVIDER_SCHEMA_VERSION,
    ProviderCapabilitySet, ProviderClass, ProviderDescriptor, ProviderForwardRequest,
    ProviderImplementationId, ProviderMethodName, ProviderRegistry, ProviderRegistryBuilder,
    ProviderRegistryManager, ProviderRuntimeError, RegistryBuildError, RegistryDrainPolicy,
    RegistryLifecycle, RegistryLimits, SessionIdentity, ZoneRouteFailClosedReason,
    admit_provider_forward,
};
use d2b_zone_routing::engine::{ZoneRouteAdmission, ZoneRouteAdmissionExpectation};

const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const UID: &str = "123e4567-e89b-42d3-a456-426614174000";

fn zone(labels: &[&str]) -> ZonePath {
    ZonePath::new(
        labels
            .iter()
            .map(|label| ZoneLabelId::parse(*label).expect("valid zone label"))
            .collect(),
    )
    .expect("valid zone path")
}

fn provider_ref(name: &str) -> ResourceRef {
    ResourceRef::parse(&format!("Provider/{name}")).expect("valid Provider ref")
}

fn service() -> ServiceName {
    ServiceName::parse("d2b.provider.v3").expect("valid service name")
}

fn generation(value: u64) -> ConfigurationGeneration {
    ConfigurationGeneration::new(value).expect("nonzero generation")
}

fn provider_generation(value: u64) -> ResourceGeneration {
    ResourceGeneration::new(value).expect("nonzero generation")
}

fn method(name: &str) -> ProviderMethodName {
    ProviderMethodName::parse(name).expect("valid method token")
}

fn capabilities(names: &[&str]) -> ProviderCapabilitySet {
    ProviderCapabilitySet::new(names.iter().map(|name| method(name))).expect("valid capabilities")
}

fn descriptor(
    zone_path: &ZonePath,
    name: &str,
    registry_generation: u64,
    methods: &[&str],
) -> ProviderDescriptor {
    ProviderDescriptor::new(
        zone_path.clone(),
        provider_ref(name),
        ProviderClass::Runtime,
        ProviderImplementationId::parse("runtime-fake").expect("valid implementation token"),
        generation(registry_generation),
        provider_generation(7),
        service(),
        capabilities(methods),
    )
    .expect("valid descriptor")
}

/// Build the authenticated evidence a Zone runtime would have established.
fn subject(provider: Option<&str>, service_name: ServiceName) -> AuthenticatedSubjectContext {
    let binding = SessionBinding::new(
        SchemaFingerprint::parse(DIGEST).expect("valid fingerprint"),
        TransportBinding::new(
            Locality::Local,
            BindingDigest::parse(DIGEST).expect("valid digest"),
        ),
        ReconnectGeneration::new(1).expect("nonzero reconnect generation"),
        TranscriptHash::from_bytes([0u8; 32]),
    );
    let context = AuthenticatedSubjectContext::new(
        ResourceRef::parse("Process/caller").expect("valid subject ref"),
        ResourceUid::parse(UID).expect("valid uid"),
        ResourceRef::parse("Zone/work").expect("valid zone ref"),
        EvidenceClass::UnixPeer,
        SessionPurpose::parse("provider-invoke").expect("valid purpose"),
        service_name,
        binding,
    );
    match provider {
        Some(name) => context
            .with_provider_ref(provider_ref(name))
            .with_provider_generation(provider_generation(7)),
        None => context,
    }
}

fn identity(zone_path: &ZonePath, provider: &str) -> SessionIdentity {
    SessionIdentity::from_authenticated(zone_path.clone(), &subject(Some(provider), service()))
        .expect("authenticated evidence carries the provider binding")
}

fn registry(zone_path: &ZonePath, gen_value: u64) -> ProviderRegistry<&'static str> {
    let mut builder = ProviderRegistryBuilder::new(zone_path.clone(), generation(gen_value));
    builder
        .register_instance(
            descriptor(zone_path, "runtime-a", gen_value, &["start", "stop"]),
            "runtime-a-instance",
        )
        .expect("descriptor registers");
    builder.finish().expect("registry seals")
}

fn admission(zone_path: &ZonePath, provider: &str, requested: &str) -> AdmissionOptions {
    AdmissionOptions {
        identity: identity(zone_path, provider),
        expected_method: method(requested),
        deadline_after: Duration::from_secs(2),
        caller_cancellation: CancellationToken::new(),
    }
}

fn drain_policy() -> RegistryDrainPolicy {
    RegistryDrainPolicy {
        drain_deadline_ms: 100,
        cancel_in_flight_at_deadline: true,
        close_provider_sessions: true,
    }
}

#[test]
fn the_descriptor_publishes_the_v3_schema_version() {
    assert_eq!(PROVIDER_SCHEMA_VERSION, 3);
    let work = zone(&["work"]);
    assert_eq!(
        descriptor(&work, "runtime-a", 1, &["start"]).schema_version(),
        PROVIDER_SCHEMA_VERSION
    );
}

#[test]
fn the_eleven_provider_families_are_preserved() {
    assert_eq!(ProviderClass::ALL.len(), 11);
    let mut seen: Vec<&str> = ProviderClass::ALL.iter().map(|c| c.as_str()).collect();
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen.len(), 11);
}

#[test]
fn registry_limits_reject_a_zero_cap_and_a_per_provider_cap_above_the_total() {
    assert_eq!(
        RegistryLimits {
            total_in_flight: 0,
            per_provider_in_flight: 1,
        }
        .validate(),
        Err(RegistryBuildError::BoundExceeded)
    );
    assert_eq!(
        RegistryLimits {
            total_in_flight: 4,
            per_provider_in_flight: 0,
        }
        .validate(),
        Err(RegistryBuildError::BoundExceeded)
    );
    assert_eq!(
        RegistryLimits {
            total_in_flight: 4,
            per_provider_in_flight: 5,
        }
        .validate(),
        Err(RegistryBuildError::BoundExceeded)
    );
    let ok = RegistryLimits {
        total_in_flight: 4,
        per_provider_in_flight: 4,
    };
    assert_eq!(ok.validate(), Ok(ok));
    let default = RegistryLimits::default();
    assert_eq!(default.total_in_flight, 256);
    assert_eq!(default.per_provider_in_flight, 32);
}

#[test]
fn a_generation_with_no_instance_does_not_seal() {
    let work = zone(&["work"]);
    let builder: ProviderRegistryBuilder<&'static str> =
        ProviderRegistryBuilder::new(work, generation(1));
    assert_eq!(
        builder.finish().err(),
        Some(RegistryBuildError::EmptyRegistry)
    );
}

#[test]
fn a_failed_step_aborts_the_whole_build_transaction() {
    let work = zone(&["work"]);
    let mut builder = ProviderRegistryBuilder::new(work.clone(), generation(1));
    assert_eq!(
        builder
            .register_instance(descriptor(&work, "runtime-a", 2, &["start"]), "a")
            .err(),
        Some(RegistryBuildError::GenerationMismatch)
    );
    assert_eq!(
        builder
            .register_instance(descriptor(&work, "runtime-b", 1, &["start"]), "b")
            .err(),
        Some(RegistryBuildError::TransactionAborted)
    );
    assert_eq!(
        builder.finish().err(),
        Some(RegistryBuildError::TransactionAborted)
    );
}

#[test]
fn a_descriptor_from_another_zone_is_refused() {
    let work = zone(&["work"]);
    let personal = zone(&["personal"]);
    let mut builder = ProviderRegistryBuilder::new(work, generation(1));
    assert_eq!(
        builder
            .register_instance(descriptor(&personal, "runtime-a", 1, &["start"]), "a")
            .err(),
        Some(RegistryBuildError::ZoneMismatch)
    );
}

#[test]
fn a_duplicate_provider_reference_is_refused() {
    let work = zone(&["work"]);
    let mut builder = ProviderRegistryBuilder::new(work.clone(), generation(1));
    builder
        .register_instance(descriptor(&work, "runtime-a", 1, &["start"]), "a")
        .expect("first registers");
    assert_eq!(
        builder
            .register_instance(descriptor(&work, "runtime-a", 1, &["start"]), "a-again")
            .err(),
        Some(RegistryBuildError::DuplicateProvider)
    );
}

#[test]
fn a_session_identity_requires_authenticated_provider_evidence() {
    let work = zone(&["work"]);
    assert_eq!(
        SessionIdentity::from_authenticated(work, &subject(None, service())).err(),
        Some(ProviderRuntimeError::MissingProviderBinding)
    );
}

#[test]
fn provider_identity_can_bind_an_exact_reconnect_generation() {
    let work = zone(&["work"]);
    let identity = identity(&work, "runtime-a");
    assert_eq!(
        identity.session_generation(),
        ReconnectGeneration::new(1).unwrap()
    );
    let descriptor = descriptor(&work, "runtime-a", 1, &["start"])
        .with_session_generation(ReconnectGeneration::new(2).unwrap())
        .unwrap();
    assert_eq!(
        identity.matches_descriptor(&descriptor),
        Err(ProviderRuntimeError::SessionIdentityMismatch)
    );
}

// The v3 ZonePath routing proof: the identity is keyed by the Zone's path,
// and a registry admits only calls whose path is exactly its own.
#[test]
fn admission_requires_the_exact_zone_path() {
    let work = zone(&["work"]);
    let nested = zone(&["work", "payments"]);
    let registry = registry(&work, 1);

    let admitted = registry
        .admit(admission(&work, "runtime-a", "start"))
        .expect("the local Zone path is admitted");
    assert_eq!(admitted.instance, "runtime-a-instance");
    assert_eq!(admitted.context.identity().zone(), &work);
    drop(admitted);

    assert_eq!(
        registry
            .admit(admission(&nested, "runtime-a", "start"))
            .err(),
        Some(ProviderRuntimeError::SessionIdentityMismatch)
    );
}

#[test]
fn admission_requires_an_installed_provider_and_a_published_method() {
    let work = zone(&["work"]);
    let registry = registry(&work, 1);
    assert_eq!(
        registry.admit(admission(&work, "runtime-z", "start")).err(),
        Some(ProviderRuntimeError::UnknownProvider)
    );
    assert_eq!(
        registry.admit(admission(&work, "runtime-a", "drain")).err(),
        Some(ProviderRuntimeError::CapabilityDenied)
    );
}

#[test]
fn a_session_identity_from_another_service_does_not_match_the_descriptor() {
    let work = zone(&["work"]);
    let registry = registry(&work, 1);
    let other = ServiceName::parse("d2b.other.v3").expect("valid service name");
    let identity = SessionIdentity::from_authenticated(work, &subject(Some("runtime-a"), other))
        .expect("authenticated evidence carries the provider binding");
    let options = AdmissionOptions {
        identity,
        expected_method: method("start"),
        deadline_after: Duration::from_secs(2),
        caller_cancellation: CancellationToken::new(),
    };
    assert_eq!(
        registry.admit(options).err(),
        Some(ProviderRuntimeError::SessionIdentityMismatch)
    );
}

#[test]
fn the_in_flight_permit_is_released_when_the_admission_is_dropped() {
    let work = zone(&["work"]);
    let mut builder = ProviderRegistryBuilder::new(work.clone(), generation(1));
    builder
        .limits(RegistryLimits {
            total_in_flight: 1,
            per_provider_in_flight: 1,
        })
        .expect("valid limits");
    builder
        .register_instance(descriptor(&work, "runtime-a", 1, &["start"]), "a")
        .expect("descriptor registers");
    let registry = builder.finish().expect("registry seals");

    let held = registry
        .admit(admission(&work, "runtime-a", "start"))
        .expect("first admission");
    assert_eq!(
        registry.admit(admission(&work, "runtime-a", "start")).err(),
        Some(ProviderRuntimeError::InFlightLimit)
    );
    drop(held);
    registry
        .admit(admission(&work, "runtime-a", "start"))
        .expect("the permit was released on drop");
}

#[test]
fn an_invalid_drain_policy_is_refused() {
    for policy in [
        RegistryDrainPolicy {
            drain_deadline_ms: 0,
            cancel_in_flight_at_deadline: true,
            close_provider_sessions: true,
        },
        RegistryDrainPolicy {
            drain_deadline_ms: d2b_provider::MAX_REGISTRY_DRAIN_MS + 1,
            cancel_in_flight_at_deadline: true,
            close_provider_sessions: true,
        },
        RegistryDrainPolicy {
            drain_deadline_ms: 100,
            cancel_in_flight_at_deadline: false,
            close_provider_sessions: true,
        },
        RegistryDrainPolicy {
            drain_deadline_ms: 100,
            cancel_in_flight_at_deadline: true,
            close_provider_sessions: false,
        },
    ] {
        assert_eq!(
            policy.validate(),
            Err(ProviderRuntimeError::InvalidDrainPolicy)
        );
    }
}

#[tokio::test]
async fn shutdown_drains_then_retires_and_refuses_a_second_transition() {
    let work = zone(&["work"]);
    let registry = registry(&work, 1);
    assert_eq!(registry.lifecycle(), RegistryLifecycle::Accepting);

    let report = registry
        .shutdown(&drain_policy())
        .await
        .expect("shutdown succeeds");
    assert!(report.drained);
    assert_eq!(report.unresolved_in_flight, 0);
    assert_eq!(registry.lifecycle(), RegistryLifecycle::Retired);
    assert_eq!(registry.snapshot().lifecycle(), RegistryLifecycle::Retired);
    assert_eq!(
        registry.admit(admission(&work, "runtime-a", "start")).err(),
        Some(ProviderRuntimeError::NotAccepting)
    );
    assert_eq!(
        registry.shutdown(&drain_policy()).await.err(),
        Some(ProviderRuntimeError::InvalidLifecycleTransition)
    );
}

#[tokio::test]
async fn shutdown_reports_an_unresolved_call_and_cancels_its_context() {
    let work = zone(&["work"]);
    let registry = registry(&work, 1);
    let held = registry
        .admit(admission(&work, "runtime-a", "start"))
        .expect("admission");

    let report = registry
        .shutdown(&drain_policy())
        .await
        .expect("shutdown succeeds");
    assert!(!report.drained);
    assert_eq!(report.unresolved_in_flight, 1);
    assert!(held.context.is_cancelled());
    assert_eq!(
        held.context.remaining().err(),
        Some(ProviderRuntimeError::Cancelled)
    );
}

#[tokio::test]
async fn publish_swaps_the_generation_and_drains_the_outgoing_one() {
    let work = zone(&["work"]);
    let manager = ProviderRegistryManager::new(registry(&work, 1));
    let outgoing = manager.current();

    let report = manager
        .publish(registry(&work, 2), drain_policy())
        .await
        .expect("publish succeeds");
    assert!(report.drained);
    assert_eq!(outgoing.lifecycle(), RegistryLifecycle::Retired);
    assert_eq!(manager.current().snapshot().generation().get(), 2);
    manager
        .current()
        .admit(admission(&work, "runtime-a", "start"))
        .expect("the replacement generation admits");
}

#[tokio::test]
async fn publish_refuses_a_stale_generation_and_a_foreign_zone() {
    let work = zone(&["work"]);
    let personal = zone(&["personal"]);
    let manager = ProviderRegistryManager::new(registry(&work, 2));

    assert_eq!(
        manager
            .publish(registry(&work, 2), drain_policy())
            .await
            .err(),
        Some(ProviderRuntimeError::InvalidLifecycleTransition)
    );
    assert_eq!(
        manager
            .publish(registry(&personal, 3), drain_policy())
            .await
            .err(),
        Some(ProviderRuntimeError::InvalidLifecycleTransition)
    );
    assert_eq!(manager.current().lifecycle(), RegistryLifecycle::Accepting);
}

fn forward_request(zone_path: &ZonePath, hops: u32) -> ProviderForwardRequest {
    let request = ProviderForwardRequest::new(
        identity(zone_path, "runtime-a"),
        ForwardTarget::named(
            ResourceTypeName::parse("Process").expect("standard type"),
            ResourceName::parse("worker").expect("valid name"),
        ),
        ZoneLabelId::parse("payments").expect("valid label"),
        hops,
    );
    request.with_admissions(
        route_admission(zone_path, OperationClass::Invoke, "get"),
        route_admission(zone_path, OperationClass::Relay, "relay"),
    )
}

fn route_admission(
    zone_path: &ZonePath,
    verb: OperationClass,
    capability: &str,
) -> ZoneRouteAdmission {
    let child = ZonePath::new(vec![
        ZoneLabelId::parse("payments").expect("valid label"),
        zone_path.labels()[0].clone(),
    ])
    .expect("valid child path");
    let edge = d2b_contracts_zone_session::v3::zone_routing::ZoneTreeEdge::new(
        zone_path.clone(),
        child.clone(),
    )
    .expect("direct edge");
    let expectation = ZoneRouteAdmissionExpectation::new(
        ResourceUid::parse("11111111-1111-4111-8111-111111111111").expect("valid link UID"),
        edge,
        d2b_contracts_zone_session::v3::zone_routing::ZoneLinkControllerGeneration::parse(
            "controller-1",
        )
        .expect("valid controller generation"),
        ReconnectGeneration::new(7).expect("valid reconnect generation"),
        ResourceUid::parse("22222222-2222-4222-8222-222222222222").expect("valid source UID"),
        ResourceUid::parse("33333333-3333-4333-8333-333333333333").expect("valid target UID"),
        OperationId::new(vec![0x11; 16]).expect("valid operation ID"),
        verb,
        d2b_contracts_zone_session::v3::zone_routing::ZoneRouteCapability::parse(capability)
            .expect("valid capability"),
        ZoneRevision::new(9),
    )
    .expect("valid route admission expectation")
    .for_zones(zone_path.clone(), child);
    ZoneRouteAdmission::for_test(expectation, 1_500, 4_000)
}

// A Provider states where it wants to go. It never states that it may relay:
// forwarding is admitted only by the two runtime-issued route admissions.
#[test]
fn a_provider_cannot_self_assert_relay() {
    let work = zone(&["work"]);
    let request = ProviderForwardRequest::new(
        identity(&work, "runtime-a"),
        ForwardTarget::named(
            ResourceTypeName::parse("Process").expect("standard type"),
            ResourceName::parse("worker").expect("valid name"),
        ),
        ZoneLabelId::parse("payments").expect("valid label"),
        4,
    );

    assert_eq!(
        admit_provider_forward(&request).err(),
        Some(ZoneRouteFailClosedReason::ZoneLinkDisconnected)
    );

    // A Provider that publishes a method literally named `relay` still gets no
    // relay grant: capability publication is not authorization.
    let mut builder = ProviderRegistryBuilder::new(work.clone(), generation(1));
    builder
        .register_instance(descriptor(&work, "runtime-a", 1, &["relay"]), "a")
        .expect("descriptor registers");
    let registry = builder.finish().expect("registry seals");
    registry
        .admit(admission(&work, "runtime-a", "relay"))
        .expect("the provider may invoke its own method named relay");
    assert_eq!(
        admit_provider_forward(&request).err(),
        Some(ZoneRouteFailClosedReason::ZoneLinkDisconnected)
    );
}

#[test]
fn each_forward_requires_relay_plus_the_target_verb() {
    let work = zone(&["work"]);
    let request = forward_request(&work, 4);

    let forwarded =
        admit_provider_forward(&request).expect("both independent admissions admit the hop");
    assert_eq!(forwarded.forwarded_remaining_hops(), 3);
    assert_eq!(forwarded.target(), request.target());
    assert_eq!(forwarded.next_hop(), request.next_hop());
}

#[test]
fn every_hop_re_evaluates_both_grants_and_the_budget() {
    let work = zone(&["work"]);
    let mut remaining = 2;
    for _ in 0..2 {
        let request = forward_request(&work, remaining);
        remaining = admit_provider_forward(&request)
            .expect("hop admits")
            .forwarded_remaining_hops();
    }
    assert_eq!(remaining, 0);
    assert_eq!(
        admit_provider_forward(&forward_request(&work, remaining)).err(),
        Some(ZoneRouteFailClosedReason::HopLimitExceeded)
    );
}

#[test]
fn a_disconnected_uplink_and_an_attachment_offer_fail_closed() {
    let work = zone(&["work"]);
    let disconnected = ProviderForwardRequest::new(
        identity(&work, "runtime-a"),
        ForwardTarget::nameless(ResourceTypeName::parse("Process").expect("standard type")),
        ZoneLabelId::parse("payments").expect("valid label"),
        4,
    );
    assert_eq!(
        admit_provider_forward(&disconnected).err(),
        Some(ZoneRouteFailClosedReason::ZoneLinkDisconnected)
    );
    assert_eq!(
        admit_provider_forward(&forward_request(&work, 4).with_attachment_offer(true),).err(),
        Some(ZoneRouteFailClosedReason::AttachmentNotPermittedOverZoneLink)
    );
}

#[test]
fn redacted_debug_surfaces_leak_no_identity_or_target() {
    let work = zone(&["work"]);
    let identity = identity(&work, "runtime-a");
    assert_eq!(format!("{identity:?}"), "SessionIdentity(<redacted>)");

    let descriptor = descriptor(&work, "runtime-a", 1, &["start"]);
    let rendered = format!("{descriptor:?}");
    assert!(!rendered.contains("runtime-a"));
    assert!(!rendered.contains("work"));

    let request = forward_request(&work, 4);
    let rendered = format!("{request:?}");
    assert!(!rendered.contains("worker"));
    assert!(!rendered.contains("payments"));
}

#[test]
fn descriptor_repair_policy_is_bounded_or_explicitly_proven_safe_to_opt_out() {
    let device = descriptor(&zone(&["work"]), "device-gpu", 1, &["observe"]);
    assert_eq!(
        device.repair_policy().retry_after_ms(),
        d2b_provider::DEFAULT_REPAIR_INTERVAL_MS
    );
    assert_eq!(
        device.repair_policy().max_elapsed_ms(),
        d2b_provider::MAX_DEVICE_REPAIR_WINDOW_MS
    );
    assert!(device.repair_policy().has_bounded_repair());

    let opt_out = d2b_provider::RepairPolicy::opt_out();
    assert!(opt_out.has_opt_out_evidence());
    assert!(opt_out.validate(ProviderClass::Runtime).is_ok());
    assert!(
        d2b_provider::RepairPolicy::opt_out_without_restart_relist()
            .validate(ProviderClass::Runtime)
            .is_err()
    );
}

#[test]
fn operation_ledger_rebinds_matching_rows_without_reaccepting_or_changing_desired_generation() {
    let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
    let other_uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174001").unwrap();
    let desired = ResourceGeneration::new(4).unwrap();
    let next_desired = ResourceGeneration::new(5).unwrap();
    let first_session = ReconnectGeneration::new(1).unwrap();
    let next_session = ReconnectGeneration::new(2).unwrap();
    let later_session = ReconnectGeneration::new(3).unwrap();
    let operation = OperationId::new(vec![0x41; 16]).unwrap();
    let later_operation = OperationId::new(vec![0x42; 16]).unwrap();
    let mut ledger = d2b_provider::OperationLedger::new();

    assert_eq!(
        ledger.admit(uid.clone(), desired, operation.clone(), first_session),
        Ok(d2b_provider::OperationLedgerAdmission::New)
    );
    assert_eq!(
        ledger.admit(uid.clone(), desired, operation.clone(), next_session),
        Ok(d2b_provider::OperationLedgerAdmission::Existing)
    );
    let row = ledger.row(&operation).unwrap();
    assert_eq!(row.resource_uid(), &uid);
    assert_eq!(row.desired_generation(), desired);
    assert_eq!(row.session_generation(), next_session);
    assert_eq!(row.state(), d2b_provider::OperationLedgerState::Accepted);
    ledger
        .transition(
            &uid,
            desired,
            &operation,
            next_session,
            d2b_provider::OperationLedgerState::Running,
        )
        .unwrap();
    assert_eq!(
        ledger.admit(uid.clone(), desired, later_operation, later_session),
        Ok(d2b_provider::OperationLedgerAdmission::New)
    );
    assert_eq!(
        ledger.admit(uid.clone(), desired, operation.clone(), later_session),
        Ok(d2b_provider::OperationLedgerAdmission::Existing)
    );
    assert_eq!(
        ledger.row(&operation).unwrap().state(),
        d2b_provider::OperationLedgerState::Running
    );
    assert_eq!(
        ledger.admit(uid.clone(), desired, operation.clone(), next_session),
        Err(d2b_provider::OperationLedgerError::StaleSessionGeneration)
    );
    assert_eq!(
        ledger.admit(uid.clone(), next_desired, operation.clone(), later_session),
        Err(d2b_provider::OperationLedgerError::DesiredGenerationMismatch)
    );
    assert_eq!(
        ledger.admit(uid.clone(), desired, operation.clone(), next_session),
        Err(d2b_provider::OperationLedgerError::StaleSessionGeneration)
    );
    assert_eq!(
        ledger.admit(other_uid, desired, operation, later_session),
        Err(d2b_provider::OperationLedgerError::OperationIdReplay)
    );
    assert_eq!(ledger.len(), 2);
}

#[test]
fn typed_transport_descriptor_requires_only_the_carriage_methods() {
    let work = zone(&["work"]);
    let capabilities =
        ProviderCapabilitySet::from_specified(SpecifiedProviderMethod::TRANSPORT_CARRIAGE)
            .expect("typed transport methods");
    let descriptor = ProviderDescriptor::new_transport(
        work.clone(),
        provider_ref("transport-unix"),
        ProviderImplementationId::parse("transport-unix").unwrap(),
        generation(1),
        provider_generation(1),
        capabilities,
    )
    .expect("typed transport descriptor");
    assert_eq!(
        descriptor.boundary(),
        d2b_contracts_zone_session::v3::component_session::ComponentSessionBoundary::Transport
    );
    assert!(
        descriptor
            .capabilities()
            .contains_specified_method(SpecifiedProviderMethod::OpenTransport)
    );

    let wrong = ProviderCapabilitySet::new([method("open-transport")]).unwrap();
    assert_eq!(
        ProviderDescriptor::new_transport(
            work,
            provider_ref("transport-unix"),
            ProviderImplementationId::parse("transport-unix").unwrap(),
            generation(1),
            provider_generation(1),
            wrong,
        )
        .unwrap_err(),
        RegistryBuildError::InvalidDescriptor
    );
}

#[test]
fn resource_and_service_only_provider_descriptors_use_different_boundaries() {
    let work = zone(&["work"]);
    let resource = ProviderDescriptor::new(
        work.clone(),
        provider_ref("resource-owner"),
        ProviderClass::Runtime,
        ProviderImplementationId::parse("resource-owner").unwrap(),
        generation(1),
        provider_generation(1),
        ServiceName::parse("d2b.resource.v3").unwrap(),
        capabilities(&["get"]),
    )
    .expect("resource service descriptor");
    assert_eq!(
        resource.boundary(),
        d2b_contracts_zone_session::v3::component_session::ComponentSessionBoundary::ResourceService
    );
    let service = ProviderDescriptor::new_service_session(
        work.clone(),
        provider_ref("display-wayland"),
        ProviderClass::Display,
        ProviderImplementationId::parse("display-wayland").unwrap(),
        generation(1),
        provider_generation(1),
        ServiceName::parse("d2b.display.v3").unwrap(),
        capabilities(&["observe"]),
    )
    .expect("service-only descriptor");
    assert_eq!(
        service.boundary(),
        d2b_contracts_zone_session::v3::component_session::ComponentSessionBoundary::ServiceStream
    );
    assert_eq!(
        ProviderDescriptor::new_service_session(
            work,
            provider_ref("resource-service"),
            ProviderClass::Display,
            ProviderImplementationId::parse("resource-service").unwrap(),
            generation(1),
            provider_generation(1),
            ServiceName::parse("d2b.resource.v3").unwrap(),
            capabilities(&["observe"]),
        )
        .unwrap_err(),
        RegistryBuildError::InvalidDescriptor
    );
}
