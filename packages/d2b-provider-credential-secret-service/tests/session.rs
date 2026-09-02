mod common;

use d2b_contracts_provider::v3::credential::{
    CredentialAuthorization, CredentialMethod, CredentialProvider, CredentialResourceVerb,
    CredentialRotationPolicy, CredentialServiceErrorCode, OperationClass, PlacementBinding,
    RolePermission, RotationPolicyClass, dispatch_authorized_provider,
};
use d2b_contracts_provider::v3::credential_controller::{
    CredentialControllerHandlers, CredentialReconcileInput,
};
use d2b_contracts_resource::v3::{ResourceGeneration, ResourceRef, ZoneId};
use d2b_provider_credential_secret_service::{
    LockPolicy, PROVIDER_KIND, PROVIDER_REVOKE_FINALIZER, SecretServiceConfig,
    SecretServiceController, SecretServiceCredentialProvider, SecretServiceCredentialProviderFactory,
    SecretServicePlacement,
};

use common::{FakeOo7Port, delivery, request, setup};

#[test]
fn unauthenticated_authorization_cannot_reach_the_port() {
    let (provider, port) = setup(64);
    let authorization = CredentialAuthorization::new(
        CredentialMethod::AcquireToken,
        Some(delivery(CredentialMethod::AcquireToken, 1)),
    )
    .unwrap();
    assert_eq!(
        provider
            .dispatch(
                CredentialMethod::AcquireToken,
                &request("unauthenticated"),
                &authorization,
            )
            .unwrap_err()
            .code(),
        CredentialServiceErrorCode::OperationDenied
    );
    assert_eq!(
        port.issue_calls.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

#[test]
fn one_session_capability_rejects_clone_replay_and_disconnects_owned_lease() {
    let (provider, port) = setup(64);
    let capability = provider
        .issue_session_capability(ResourceGeneration::new(1).unwrap())
        .unwrap();
    let authorization = CredentialAuthorization::new(
        CredentialMethod::AcquireToken,
        Some(delivery(CredentialMethod::AcquireToken, 1)),
    )
    .unwrap()
    .with_session_proof(capability);
    dispatch_authorized_provider(
        &provider,
        CredentialMethod::AcquireToken,
        &request("session-owned"),
        &authorization,
    )
    .unwrap();
    dispatch_authorized_provider(
        &provider,
        CredentialMethod::AcquireToken,
        &request("session-owned-2"),
        &authorization,
    )
    .unwrap();

    provider.disconnect(&authorization).unwrap();
    provider.disconnect(&authorization).unwrap();
    assert_eq!(
        port.revoke_calls.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        provider
            .dispatch(
                CredentialMethod::InspectMetadata,
                &request("after-disconnect"),
                &authorization,
            )
            .unwrap_err()
            .code(),
        CredentialServiceErrorCode::OperationDenied
    );
}

#[test]
fn foreign_exact_match_authority_is_refused() {
    let (provider, _) = setup(64);
    let (foreign_provider, _) = setup(64);
    let authorization = CredentialAuthorization::new(
        CredentialMethod::AcquireToken,
        Some(delivery(CredentialMethod::AcquireToken, 1)),
    )
    .unwrap()
    .with_session_proof(
        foreign_provider
            .issue_session_capability(ResourceGeneration::new(1).unwrap())
            .unwrap(),
    );
    assert_eq!(
        provider
            .dispatch(
                CredentialMethod::AcquireToken,
                &request("foreign-authority"),
                &authorization,
            )
            .unwrap_err()
            .code(),
        CredentialServiceErrorCode::OperationDenied
    );
}

#[test]
fn absent_consumer_uses_only_the_canonical_provider_reference() {
    let port = std::sync::Arc::new(common::FakeOo7Port::new());
    let provider = SecretServiceCredentialProviderFactory::new(
        SecretServiceConfig::new("login collection", 64, LockPolicy::FailClosed).unwrap(),
        SecretServicePlacement::new(
            ZoneId::parse("user-zone").unwrap(),
            PlacementBinding::UserAgent,
            ResourceRef::parse("Host/workstation").unwrap(),
            ResourceRef::parse("User/alice").unwrap(),
        )
        .unwrap(),
        None,
        port,
    )
    .unwrap()
    .construct()
    .expect("test provider authority must be constructible");
    assert_eq!(
        provider.consumer_ref().to_canonical_string(),
        d2b_provider_credential_secret_service::PROVIDER_REF
    );
    let own_authorization = CredentialAuthorization::new(
        CredentialMethod::AcquireToken,
        Some(common::delivery_for_consumer(
            CredentialMethod::AcquireToken,
            1,
            ResourceRef::parse("Credential/local-keyring").unwrap(),
            ResourceRef::parse("Provider/credential-secret-service").unwrap(),
        )),
    )
    .unwrap()
    .with_session_proof(
        provider
            .issue_session_capability(ResourceGeneration::new(1).unwrap())
            .unwrap(),
    );
    provider
        .dispatch(
            CredentialMethod::AcquireToken,
            &request("canonical-consumer"),
            &own_authorization,
        )
        .unwrap();
    let (_, foreign_port) = setup(64);
    let authorization = CredentialAuthorization::new(
        CredentialMethod::AcquireToken,
        Some(delivery(CredentialMethod::AcquireToken, 1)),
    )
    .unwrap()
    .with_session_proof(
        SecretServiceCredentialProviderFactory::new(
            SecretServiceConfig::new("login collection", 64, LockPolicy::FailClosed).unwrap(),
            SecretServicePlacement::new(
                ZoneId::parse("user-zone").unwrap(),
                PlacementBinding::UserAgent,
                ResourceRef::parse("Host/workstation").unwrap(),
                ResourceRef::parse("User/alice").unwrap(),
            )
            .unwrap(),
            Some(ResourceRef::parse("Provider/shell-terminal").unwrap()),
            foreign_port,
        )
        .unwrap()
        .construct()
        .expect("foreign provider authority must be constructible")
        .issue_session_capability(ResourceGeneration::new(1).unwrap())
        .unwrap(),
    );
    assert_eq!(
        provider
            .dispatch(
                CredentialMethod::AcquireToken,
                &request("consumer-none"),
                &authorization,
            )
            .unwrap_err()
            .code(),
        CredentialServiceErrorCode::OperationDenied
    );
}

#[test]
fn provider_generation_is_checked_before_admission() {
    let port = std::sync::Arc::new(common::FakeOo7Port::new());
    let provider = SecretServiceCredentialProviderFactory::new(
        SecretServiceConfig::new("login collection", 64, LockPolicy::FailClosed).unwrap(),
        SecretServicePlacement::new(
            ZoneId::parse("user-zone").unwrap(),
            PlacementBinding::UserAgent,
            ResourceRef::parse("Host/workstation").unwrap(),
            ResourceRef::parse("User/alice").unwrap(),
        )
        .unwrap(),
        Some(ResourceRef::parse("Provider/shell-terminal").unwrap()),
        port,
    )
    .unwrap()
    .with_generation(ResourceGeneration::new(2).unwrap())
    .construct()
    .expect("test provider authority must be constructible");
    assert!(
        provider
            .issue_session_capability(ResourceGeneration::new(1).unwrap())
            .is_err()
    );
    assert!(
        provider
            .issue_session_capability(ResourceGeneration::new(2).unwrap())
            .is_ok()
    );
}

#[test]
fn foreign_bindings_are_refused() {
    let (provider, _) = setup(64);
    for (zone, workload, consumer, subject) in [
        (
            "other-zone",
            "Host/workstation",
            "Provider/shell-terminal",
            "User/alice",
        ),
        (
            "user-zone",
            "Host/other-workstation",
            "Provider/shell-terminal",
            "User/alice",
        ),
        (
            "user-zone",
            "Host/workstation",
            "Provider/other-consumer",
            "User/alice",
        ),
        (
            "user-zone",
            "Host/workstation",
            "Provider/shell-terminal",
            "User/bob",
        ),
    ] {
        let foreign = provider_for_binding(
            ZoneId::parse(zone).unwrap(),
            ResourceRef::parse(workload).unwrap(),
            ResourceRef::parse(subject).unwrap(),
            ResourceRef::parse(consumer).unwrap(),
            std::sync::Arc::new(common::FakeOo7Port::new()),
        );
        let authorization = CredentialAuthorization::new(
            CredentialMethod::AcquireToken,
            Some(delivery(CredentialMethod::AcquireToken, 1)),
        )
        .unwrap()
        .with_session_proof(
            foreign
                .issue_session_capability(ResourceGeneration::new(1).unwrap())
                .unwrap(),
        );
        assert_eq!(
            provider
                .dispatch(
                    CredentialMethod::AcquireToken,
                    &request("wrong-binding"),
                    &authorization,
                )
                .unwrap_err()
                .code(),
            CredentialServiceErrorCode::OperationDenied
        );
    }
}

#[test]
fn disconnect_revokes_only_the_owned_workload_leases() {
    let port = std::sync::Arc::new(FakeOo7Port::new());
    let first = provider_for(
        ZoneId::parse("user-zone").unwrap(),
        ResourceRef::parse("Host/workstation").unwrap(),
        port.clone(),
    );
    let second = provider_for(
        ZoneId::parse("other-zone").unwrap(),
        ResourceRef::parse("Host/other-workstation").unwrap(),
        port.clone(),
    );
    let first_capability = std::sync::Arc::new(
        first
            .issue_session_capability(ResourceGeneration::new(1).unwrap())
            .unwrap(),
    );
    let second_capability = std::sync::Arc::new(
        second
            .issue_session_capability(ResourceGeneration::new(1).unwrap())
            .unwrap(),
    );
    let first_auth = CredentialAuthorization::new(
        CredentialMethod::AcquireToken,
        Some(delivery(CredentialMethod::AcquireToken, 1)),
    )
    .unwrap()
    .with_shared_session_proof(first_capability.clone());
    let second_auth = CredentialAuthorization::new(
        CredentialMethod::AcquireToken,
        Some(delivery(CredentialMethod::AcquireToken, 1)),
    )
    .unwrap()
    .with_shared_session_proof(second_capability.clone());

    dispatch_authorized_provider(
        &first,
        CredentialMethod::AcquireToken,
        &request("first-lease"),
        &first_auth,
    )
    .unwrap();
    dispatch_authorized_provider(
        &second,
        CredentialMethod::AcquireToken,
        &request("second-lease"),
        &second_auth,
    )
    .unwrap();

    first.disconnect(&first_auth).unwrap();
    let second_inspect_auth = CredentialAuthorization::new(CredentialMethod::InspectMetadata, None)
        .unwrap()
        .with_shared_session_proof(second_capability);
    dispatch_authorized_provider(
        &second,
        CredentialMethod::InspectMetadata,
        &request("second-inspect"),
        &second_inspect_auth,
    )
    .unwrap();
    assert_eq!(
        port.revoke_calls.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    second.finalize_session(&second_auth).unwrap();
    assert_eq!(
        port.revoke_calls.load(std::sync::atomic::Ordering::SeqCst),
        2
    );
}

#[test]
fn shared_controller_admission_uses_the_exact_finalizer_and_operation_class() {
    let controller = SecretServiceController::new(
        SecretServiceConfig::new("login collection", 64, LockPolicy::FailClosed).unwrap(),
    );
    let input = CredentialReconcileInput::new(
        d2b_contracts_resource::v3::ResourceUid::parse(
            "123e4567-e89b-42d3-a456-426614174000",
        )
        .unwrap(),
        CredentialRotationPolicy::new(RotationPolicyClass::OnExpiry, None, 1_000).unwrap(),
        None,
        1,
        20_000,
        [OperationClass::AcquireToken],
        RolePermission::new(CredentialResourceVerb::UseCredential, "acquire-token"),
        true,
        0,
        64,
        10,
        20,
        None,
    )
    .unwrap();
    let decision = controller.reconcile_handler(&input).unwrap();
    let call = decision.call.expect("first pass must accept acquisition");
    assert_eq!(call.subresource(), "acquire-token");
    assert_eq!(PROVIDER_KIND.as_str(), "credential-secret-service");
    assert_eq!(
        PROVIDER_REVOKE_FINALIZER,
        "credential.d2bus.org/provider-revoke"
    );
}

#[test]
fn finalize_releases_leases_and_prevents_later_minting() {
    let (provider, port) = setup(64);
    let capability = provider
        .issue_session_capability(ResourceGeneration::new(1).unwrap())
        .unwrap();
    let authorization = CredentialAuthorization::new(
        CredentialMethod::AcquireToken,
        Some(delivery(CredentialMethod::AcquireToken, 1)),
    )
    .unwrap()
    .with_session_proof(capability);
    provider
        .dispatch(
            CredentialMethod::AcquireToken,
            &request("finalize"),
            &authorization,
        )
        .unwrap();
    provider.finalize_session(&authorization).unwrap();
    provider.finalize_session(&authorization).unwrap();
    assert!(
        provider
            .issue_session_capability(ResourceGeneration::new(1).unwrap())
            .is_err()
    );
    assert_eq!(
        provider
            .dispatch(
                CredentialMethod::InspectMetadata,
                &request("after-finalize"),
                &authorization,
            )
            .unwrap_err()
            .code(),
        CredentialServiceErrorCode::OperationDenied
    );
    assert_eq!(
        port.revoke_calls.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
}

fn provider_for(
    zone: ZoneId,
    workload: ResourceRef,
    port: std::sync::Arc<FakeOo7Port>,
) -> SecretServiceCredentialProvider {
    provider_for_binding(
        zone,
        workload,
        ResourceRef::parse("User/alice").unwrap(),
        ResourceRef::parse("Provider/shell-terminal").unwrap(),
        port,
    )
}

fn provider_for_binding(
    zone: ZoneId,
    workload: ResourceRef,
    subject: ResourceRef,
    consumer: ResourceRef,
    port: std::sync::Arc<FakeOo7Port>,
) -> SecretServiceCredentialProvider {
    SecretServiceCredentialProviderFactory::new(
        SecretServiceConfig::new("login collection", 64, LockPolicy::FailClosed).unwrap(),
        SecretServicePlacement::new(zone, PlacementBinding::UserAgent, workload, subject).unwrap(),
        Some(consumer),
        port,
    )
    .unwrap()
    .construct()
    .expect("test provider authority must be constructible")
}
