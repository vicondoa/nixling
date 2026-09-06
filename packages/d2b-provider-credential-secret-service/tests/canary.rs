mod common;

use d2b_contracts_provider::v3::credential::{
    CredentialInteractionState, CredentialLeaseHandle, CredentialLeaseStatus, CredentialMethod,
    CredentialRequest, CredentialResponse, CredentialServiceErrorCode, CredentialSourceVersion,
    CredentialStatus, PlacementBinding, encode_outer,
};
use d2b_contracts_provider::v3::credential_controller::{
    CredentialAuditOutcome, CredentialTelemetryOperation, CredentialTelemetryOutcome,
};
use d2b_contracts_resource::v3::{ResourceGeneration, ResourceRef};
use d2b_provider_credential_secret_service::SecretServiceController;

use common::{Admission, ProviderHarness, setup};

#[test]
fn process_unique_secret_service_canaries_are_absent_from_every_rendered_surface() {
    let nonce = format!("{:x}", std::process::id());
    let credential_name = format!("credential-name-{nonce}");
    let credential_ref = format!("Credential/{credential_name}");
    let credential_uid = format!("credential-uid-{nonce}");
    let credential_digest = format!("credential-digest-{nonce}");
    let (provider, port) = setup(64);
    let config_debug = format!("{:?}", provider.config());
    let placement_debug = format!("{:?}", provider.placement());
    let session_debug = format!(
        "{:?}",
        provider
            .issue_session_capability(ResourceGeneration::new(1).unwrap())
            .unwrap()
    );
    let controller = SecretServiceController::new(provider.config().clone());
    let operation_id = format!("{}-{credential_uid}", port.object_path_canary);
    let idempotency_key = format!("{}-{credential_digest}", port.credential_canary);
    let request = CredentialRequest::new(
        ResourceRef::parse(&credential_ref).unwrap(),
        &operation_id,
        &idempotency_key,
        common::EXPIRY,
        15_000,
    )
    .unwrap();
    let request_debug = format!("{request:?}");
    let provider_debug = format!("{provider:?}");
    let server = ProviderHarness::new(provider, Admission);
    let response = server
        .call(CredentialMethod::AcquireToken, request)
        .unwrap();
    let CredentialResponse::AcquireToken(delivery) = &response else {
        panic!("acquire response");
    };
    assert_eq!(
        delivery.metadata.lease_handle,
        CredentialLeaseHandle::parse(&port.credential_canary).unwrap()
    );
    assert_eq!(
        delivery.metadata.source_version,
        CredentialSourceVersion::parse(&port.object_path_canary).unwrap()
    );
    assert_eq!(
        port.observed_request.lock().unwrap().as_ref(),
        Some(&(
            credential_ref.clone(),
            operation_id.clone(),
            idempotency_key.clone(),
        ))
    );
    let status = CredentialStatus::new(
        CredentialInteractionState::NotRequired,
        None,
        None,
        Some(
            CredentialLeaseStatus::new(
                delivery.metadata.lease_handle.clone(),
                delivery.metadata.state,
                delivery.metadata.rotation_generation,
                delivery.metadata.source_version.clone(),
                delivery.metadata.expires_at_unix_ms,
                1,
                None,
                None,
                PlacementBinding::UserAgent,
            )
            .unwrap(),
        ),
    )
    .unwrap();
    let (error_provider, error_port) = setup(64);
    *error_port.issue_error.lock().unwrap() =
        Some(d2b_provider_credential_secret_service::SecretServicePortError::Unavailable);
    let error = ProviderHarness::new(error_provider, Admission)
        .call(
            CredentialMethod::AcquireToken,
            CredentialRequest::new(
                ResourceRef::parse(&credential_ref).unwrap(),
                &operation_id,
                &idempotency_key,
                common::EXPIRY,
                15_000,
            )
            .unwrap(),
        )
        .unwrap_err();
    assert_eq!(
        error.code(),
        CredentialServiceErrorCode::ProviderUnavailable
    );
    assert_eq!(
        error_port.observed_request.lock().unwrap().as_ref(),
        Some(&(
            credential_ref.clone(),
            operation_id.clone(),
            idempotency_key.clone(),
        ))
    );
    let (ambiguous_provider, ambiguous_port) = setup(64);
    *ambiguous_port.issue_error.lock().unwrap() =
        Some(d2b_provider_credential_secret_service::SecretServicePortError::CompletionUnknown);
    let ambiguous_error = ProviderHarness::new(ambiguous_provider, Admission)
        .call(
            CredentialMethod::AcquireToken,
            CredentialRequest::new(
                ResourceRef::parse(&credential_ref).unwrap(),
                &operation_id,
                &idempotency_key,
                common::EXPIRY,
                15_000,
            )
            .unwrap(),
        )
        .unwrap_err();
    assert_eq!(
        ambiguous_error.code(),
        CredentialServiceErrorCode::InvariantFailure
    );
    let surfaces = [
        config_debug,
        placement_debug,
        session_debug,
        provider_debug,
        request_debug,
        format!("{response:?}"),
        String::from_utf8_lossy(&encode_outer(delivery).unwrap()).into_owned(),
        format!("{:?}", delivery.metadata.lease_handle),
        delivery.metadata.lease_handle.to_string(),
        format!("{:?}", delivery.metadata.source_version),
        delivery.metadata.source_version.to_string(),
        format!("{status:?}"),
        serde_json::to_string(&status).unwrap(),
        format!("{error:?}"),
        error.to_string(),
        format!("{ambiguous_error:?}"),
        ambiguous_error.to_string(),
        format!(
            "{:?}",
            controller
                .authorized_service_audit(
                    true,
                    "user-zone",
                    credential_uid.as_bytes(),
                    credential_name.as_bytes(),
                    CredentialMethod::AcquireToken,
                    CredentialAuditOutcome::Success,
                    1,
                    Some(credential_digest.as_bytes()),
                )
                .unwrap()
        ),
        format!(
            "{:?}",
            controller
                .telemetry(
                    "user-zone",
                    CredentialTelemetryOperation::AcquireToken,
                    CredentialTelemetryOutcome::Success,
                    1,
                )
                .unwrap()
        ),
    ];
    for surface in surfaces {
        for canary in [
            port.credential_canary.as_str(),
            port.object_path_canary.as_str(),
        ] {
            assert!(
                !surface.contains(canary),
                "secret-service canary reached a rendered surface"
            );
        }
    }
}
