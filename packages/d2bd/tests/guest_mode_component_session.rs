use d2b_contracts_resource::v3::{
    ResourceName, ResourceRef, ResourceTypeName, ResourceUid, SchemaFingerprint, ZoneId,
    identity::{ReconnectGeneration, SessionPurpose},
};
use d2b_contracts_zone_session::v3::component_session::{
    ComponentSessionBoundary, EndpointPolicy, EndpointPurpose, EndpointRole, ServicePackage,
};
use d2b_session::{
    HandshakeCredentials, Secret32, SessionAuthorizationRequest, SessionEngine, SessionVerb,
    x25519_public_key,
};
use d2b_session_unix::FramedVsockTransport;
use d2bd_runtime::{
    guest_mode::{
        BootIdentity, GUEST_COMPONENT_SESSION_PORT, GUEST_COMPONENT_SESSION_PURPOSE, GuestIdentity,
        GuestRuntime, reject_legacy_guest_prelude,
    },
    guest_resource_runtime::{GuestResourceRuntime, GuestResourceRuntimeError},
    target_runtime::{AdmissionBudget, AdmissionKind, AdmissionLimits, ControllerAssignmentKey},
};
use std::time::Instant;

fn identity_in_zone(generation: u64, zone: &str) -> GuestIdentity {
    GuestIdentity::new(
        ResourceRef::parse("Guest/workload").expect("Guest ref"),
        ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").expect("Guest UID"),
        ZoneId::parse(zone).expect("Zone"),
        BootIdentity::from_kernel_boot_id("boot-id-u3").expect("boot ID"),
        SessionPurpose::parse(GUEST_COMPONENT_SESSION_PURPOSE).expect("purpose"),
        SchemaFingerprint::parse(
            "sha256:0000000000000000000000000000000000000000000000000000000000000001",
        )
        .expect("schema"),
        ReconnectGeneration::new(generation).expect("generation"),
        1,
        1,
        1,
    )
    .expect("Guest identity")
}

fn identity(generation: u64) -> GuestIdentity {
    identity_in_zone(generation, "work")
}

async fn runtime() -> (GuestRuntime, tempfile::TempDir) {
    let state_dir = tempfile::tempdir().expect("state directory");
    let runtime = GuestRuntime::new(
        identity(1),
        "/run/d2b/guest-broker.sock".into(),
        997,
        AdmissionLimits::guest_default(),
        state_dir.path(),
    )
    .await
    .expect("Guest runtime");
    (runtime, state_dir)
}

async fn rejected_parent_handshake(
    runtime: &GuestRuntime,
    policy: EndpointPolicy,
    expected_parent_public: [u8; 32],
) {
    let parent_private_bytes = [2_u8; 32];
    let guest_private_bytes = [3_u8; 32];
    let guest_public = x25519_public_key(&guest_private_bytes).expect("Guest public key");
    let parent_private = Secret32::new(parent_private_bytes).expect("parent private key");
    let guest_private = Secret32::new(guest_private_bytes).expect("Guest private key");
    let (left, right) = tokio::io::duplex(16 * 1024);
    let parent = tokio::spawn(async move {
        SessionEngine::establish_initiator(
            FramedVsockTransport::new(left),
            policy,
            HandshakeCredentials::Kk {
                local_private: parent_private,
                remote_public: guest_public,
            },
            Instant::now(),
        )
        .await
    });
    let result = runtime
        .establish_component_session(
            FramedVsockTransport::new(right),
            guest_private,
            expected_parent_public,
        )
        .await;
    assert!(
        result.is_err(),
        "mismatched parent session must fail closed"
    );
    let _ = parent.await;
}

#[tokio::test]
async fn guest_resource_runtime_is_target_local() {
    let state_dir = tempfile::tempdir().expect("state directory");
    let runtime = GuestResourceRuntime::new(identity(1), state_dir.path())
        .await
        .expect("Guest resource runtime");
    assert!(runtime.is_target_local());
}

#[tokio::test]
async fn guest_runtime_owns_one_target_local_resource_runtime() {
    let (runtime, _state_dir) = runtime().await;
    assert!(runtime.resource_runtime().is_target_local());
}

#[test]
fn component_session_uses_fixed_vsock_port_and_identity_binding() {
    let identity = identity(3);
    let policy = identity.endpoint_policy();
    assert_eq!(GUEST_COMPONENT_SESSION_PORT, 14_318);
    assert_eq!(policy.reconnect_generation, 3);
    assert_ne!(policy.transport_binding.channel_binding, [0; 32]);
    let reconnect = identity.endpoint_policy_for_generation(4);
    assert_eq!(reconnect.reconnect_generation, 4);
    assert_eq!(
        policy.transport_binding.channel_binding,
        reconnect.transport_binding.channel_binding
    );
}

#[test]
fn reconnect_and_stream_admission_refuse_floods_before_state_allocation() {
    let budget = AdmissionBudget::new(AdmissionLimits {
        max_sessions: 1,
        max_reconnects_per_window: 1,
        max_controllers: 1,
        max_watches: 1,
        max_streams: 1,
        reconnect_window: std::time::Duration::from_secs(60),
    })
    .expect("valid budget");
    let session = budget.try_admit(AdmissionKind::Session).expect("session");
    assert!(budget.try_admit(AdmissionKind::Session).is_err());
    let stream = budget.try_admit(AdmissionKind::Stream).expect("stream");
    assert!(budget.try_admit(AdmissionKind::Stream).is_err());
    drop(session);
    drop(stream);
    assert!(
        budget
            .try_admit_reconnect(std::time::Instant::now())
            .is_ok()
    );
    assert!(
        budget
            .try_admit_reconnect(std::time::Instant::now())
            .is_err()
    );
}

#[test]
fn old_component_session_prelude_is_rejected() {
    assert!(reject_legacy_guest_prelude(b"CONNECT 14318\n").is_err());
    assert!(reject_legacy_guest_prelude(b"D2BGC-old").is_err());
}

#[tokio::test]
async fn reconnect_revokes_stale_assignments_and_drops_the_new_lease() {
    let (runtime, _state_dir) = runtime().await;
    let first = runtime
        .admit_generation_for_tests(1)
        .expect("first session");
    let key = |generation| ControllerAssignmentKey {
        zone: ZoneId::parse("work").expect("Zone"),
        provider: ResourceRef::new(
            ResourceTypeName::parse("Provider").expect("Provider type"),
            ResourceName::parse("system-systemd").expect("Provider name"),
        ),
        target: ResourceRef::new(
            ResourceTypeName::parse("Guest").expect("Guest type"),
            ResourceName::parse("workload").expect("Guest name"),
        ),
        provider_generation: 1,
        controller_generation: 1,
        session_generation: generation,
        assignment_epoch: generation,
    };
    let stale = runtime.admit_assignment(key(1)).expect("first assignment");
    let second = runtime
        .admit_generation_for_tests(2)
        .expect("new generation");
    assert!(!stale.is_active());
    let current = runtime.admit_assignment(key(2)).expect("new assignment");
    drop(second);
    drop(current);
    assert_eq!(runtime.deployment().active_assignments().unwrap(), 0);
    drop(first);
}

#[tokio::test]
async fn disconnected_generation_cannot_be_reused() {
    let (runtime, _state_dir) = runtime().await;
    let lease = runtime
        .admit_generation_for_tests(1)
        .expect("first session");
    drop(lease);
    assert!(
        runtime.admit_generation_for_tests(1).is_err(),
        "disconnect must advance the reconnect high-water mark"
    );
}

#[tokio::test]
async fn wrong_zone_link_purpose_role_and_service_fail_closed() {
    for mismatch in ["purpose", "role", "service"] {
        let (runtime, _state_dir) = runtime().await;
        let mut policy = identity(1).endpoint_policy();
        match mismatch {
            "purpose" => policy.purpose = EndpointPurpose::ResourceService,
            "role" => policy.responder_role = EndpointRole::Component,
            "service" => policy.service = ServicePackage::ControllerV3,
            _ => unreachable!("test mismatch is closed"),
        }
        let parent_public = x25519_public_key(&[2_u8; 32]).expect("parent public key");
        rejected_parent_handshake(&runtime, policy, parent_public).await;
    }
}

#[tokio::test]
async fn peer_and_zone_binding_substitution_fail_closed() {
    let (first_runtime, _state_dir) = runtime().await;
    let policy = identity(1).endpoint_policy();
    let substituted_parent_public =
        x25519_public_key(&[9_u8; 32]).expect("substituted parent public key");
    rejected_parent_handshake(&first_runtime, policy, substituted_parent_public).await;

    let (runtime, _state_dir) = runtime().await;
    let mut policy = identity(1).endpoint_policy();
    policy.transport_binding.channel_binding[0] ^= 1;
    let parent_public = x25519_public_key(&[2_u8; 32]).expect("parent public key");
    rejected_parent_handshake(&runtime, policy, parent_public).await;
}

#[tokio::test]
async fn authenticated_guest_session_binds_readiness_and_stale_binding_fails_closed() {
    let (runtime, _state_dir) = runtime().await;
    let previous = runtime
        .admit_generation_for_tests(1)
        .expect("initial Guest session");
    drop(previous);
    let parent_private_bytes = [2_u8; 32];
    let guest_private_bytes = [3_u8; 32];
    let parent_public = x25519_public_key(&parent_private_bytes).expect("parent public key");
    let guest_public = x25519_public_key(&guest_private_bytes).expect("Guest public key");
    let parent_private = Secret32::new(parent_private_bytes).expect("parent private key");
    let guest_private = Secret32::new(guest_private_bytes).expect("Guest private key");
    let policy = identity(2).endpoint_policy();
    let parent_policy = policy.clone();
    let (left, right) = tokio::io::duplex(16 * 1024);
    let parent = tokio::spawn(async move {
        SessionEngine::establish_initiator_with_generation_discovery(
            FramedVsockTransport::new(left),
            d2b_session::contract::EndpointPolicyIdentity::from(&parent_policy),
            HandshakeCredentials::Kk {
                local_private: parent_private,
                remote_public: guest_public,
            },
            Instant::now(),
        )
        .await
    });
    let (mut session, lease) = runtime
        .establish_component_session(
            FramedVsockTransport::new(right),
            guest_private,
            parent_public,
        )
        .await
        .expect("Guest accepts newer generation");
    let parent = parent.await.expect("parent task").expect("parent session");
    assert_eq!(lease.generation(), 2);
    assert_eq!(parent.generation(), 2);
    let state_dir = tempfile::tempdir().expect("state directory");
    let resource_runtime = GuestResourceRuntime::new(identity(2), state_dir.path())
        .await
        .expect("target-local resource runtime");
    let route = session.route_binding();
    assert_eq!(route.zone(), &ZoneId::parse("work").expect("Zone"));
    assert_eq!(route.subject_ref(), identity(2).guest_ref());
    assert_eq!(route.subject_uid(), identity(2).guest_uid());
    assert_eq!(route.service().as_str(), "d2b.resource.v3");
    assert_eq!(route.purpose_class(), policy.purpose_class);
    assert_eq!(route.initiator_role(), policy.initiator_role);
    assert_eq!(route.responder_role(), policy.responder_role);
    assert_eq!(route.endpoint_locality(), policy.transport_binding.locality);
    assert_eq!(route.transport_class(), policy.transport_binding.transport);
    let descriptor = route
        .component_descriptor(ComponentSessionBoundary::ResourceService)
        .expect("typed ResourceService descriptor");
    assert!(descriptor.is_resource_service());
    assert_eq!(descriptor.reconnect_generation(), 2);
    let resource_session = resource_runtime
        .bind_session(&route)
        .expect("authenticated session binds Resource API");
    assert_eq!(resource_session.generation(), 2);
    assert_eq!(
        resource_runtime
            .bind_seed_session(
                &route,
                SchemaFingerprint::parse(format!("sha256:{}", "0".repeat(64)))
                    .expect("zero descriptor digest"),
                ["Process"].into_iter().map(|resource_type| {
                    ResourceTypeName::parse(resource_type).expect("seed type")
                }),
            )
            .expect_err("zero descriptor evidence must be refused"),
        GuestResourceRuntimeError::SeedPolicy
    );
    let seed_session = resource_runtime
        .bind_seed_session(
            &route,
            SchemaFingerprint::parse(
                "sha256:0000000000000000000000000000000000000000000000000000000000000002",
            )
            .expect("seed descriptor digest"),
            ["Process", "Endpoint"]
                .into_iter()
                .map(|resource_type| ResourceTypeName::parse(resource_type).expect("seed type")),
        )
        .expect("seed session");
    let seed_services = seed_session.ttrpc_services();
    let seed_service = seed_services
        .get("d2b.resource.v3.ResourceService")
        .expect("seed ResourceService");
    assert_eq!(seed_services.len(), 1);
    assert!(seed_service.methods.contains_key("CommitBatch"));
    assert!(seed_service.methods.contains_key("Watch"));
    assert_eq!(seed_service.methods.len(), 2);
    assert!(seed_service.streams.is_empty());

    let authenticated_services = resource_session.ttrpc_services();
    let authenticated_service = authenticated_services
        .get("d2b.resource.v3.ResourceService")
        .expect("authenticated ResourceService");
    assert_eq!(authenticated_services.len(), 1);
    for method in [
        "Get",
        "List",
        "Watch",
        "Create",
        "UpdateSpec",
        "UpdateStatus",
        "UpdateMetadata",
        "UpdateFinalizers",
        "Delete",
        "CommitBatch",
        "ResolveRef",
        "InspectSchema",
        "Upgrade",
    ] {
        assert!(
            authenticated_service.methods.contains_key(method),
            "authenticated ResourceService lacks {method}"
        );
    }
    assert!(
        authenticated_service.methods.len() > seed_service.methods.len(),
        "seed method restriction must not leak into authenticated sessions"
    );
    let wrong_service = SessionAuthorizationRequest::new(
        SessionVerb::Invoke,
        d2b_contracts_resource::v3::identity::ServiceName::parse("d2b.controller.v3")
            .expect("service"),
        "ResourceService/Get",
        ZoneId::parse("work").expect("Zone"),
        Some(ResourceRef::parse("Guest/other").expect("target")),
    )
    .expect("authorization request");
    assert_eq!(
        session
            .authorize(wrong_service, 2)
            .await
            .expect_err("wrong service or target must fail closed")
            .code(),
        d2b_session::contract::SessionErrorCode::PolicyDenied
    );
    let wrong_zone = SessionAuthorizationRequest::new(
        SessionVerb::Invoke,
        d2b_contracts_resource::v3::identity::ServiceName::parse("d2b.resource.v3")
            .expect("service"),
        "ResourceService/Get",
        ZoneId::parse("personal").expect("Zone"),
        None,
    )
    .expect("authorization request");
    assert_eq!(
        session
            .authorize(wrong_zone, 2)
            .await
            .expect_err("wrong target Zone must fail closed")
            .code(),
        d2b_session::contract::SessionErrorCode::PolicyDenied
    );
    assert!(matches!(
        identity_in_zone(2, "personal").validate_route(&route),
        Err(d2bd_runtime::guest_mode::GuestModeError::SessionBindingMismatch)
    ));

    drop(session);
    assert!(!route.liveness().is_live());
    assert_eq!(
        runtime
            .resource_runtime()
            .bind_session(&route)
            .expect_err("a dropped authenticated session must fail closed"),
        GuestResourceRuntimeError::SessionBinding
    );

    let invalid_state_dir = tempfile::tempdir().expect("state directory");
    let invalid_runtime = GuestResourceRuntime::new(identity(3), invalid_state_dir.path())
        .await
        .expect("target-local resource runtime");
    assert_eq!(
        invalid_runtime
            .bind_session(&route)
            .expect_err("stale session binding must fail closed"),
        GuestResourceRuntimeError::SessionBinding
    );
}
