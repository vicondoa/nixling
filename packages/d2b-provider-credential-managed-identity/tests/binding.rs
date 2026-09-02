mod common;

use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use d2b_contracts_provider::v3::credential::{
    CredentialAuthorization, CredentialLeaseState, CredentialMethod, CredentialRequest,
    CredentialResponse, CredentialServiceErrorCode, CredentialSessionBinding,
    MAX_PROVIDER_LEASE_LIFETIME_MS, dispatch_authorized_provider,
};
use d2b_contracts_resource::v3::ResourceRef;
use d2b_contracts_resource::v3::identity::Locality;
use d2b_provider_credential_managed_identity::{
    ManagedIdentityCredentialProvider, ManagedIdentityCredentialProviderFactory,
    PROVIDER_KIND, PROVIDER_REVOKE_FINALIZER, ManagedIdentityController,
    ManagedIdentityTeardownPlan,
};

use common::{
    authenticated_session, authenticated_session_with_expiry, authenticated_session_with_locality,
    authorization_for, delivery_for_timing, delivery_for_timing_with_provider_generation, request,
    setup, setup_with_max_leases,
};

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn dispatch(
    provider: &ManagedIdentityCredentialProvider,
    method: CredentialMethod,
    request: &CredentialRequest,
    session: CredentialSessionBinding,
) -> Result<CredentialResponse, d2b_contracts_provider::v3::credential::CredentialServiceError> {
    let authorization = authorization_for(method, session, request.credential_ref().clone())?;
    dispatch_authorized_provider(provider, method, request, &authorization)
}

fn dispatch_without_session(
    provider: &ManagedIdentityCredentialProvider,
    method: CredentialMethod,
    request: &CredentialRequest,
) -> Result<CredentialResponse, d2b_contracts_provider::v3::credential::CredentialServiceError> {
    let delivery = method
        .requires_delivery()
        .then(|| common::delivery_for(method, 1, request.credential_ref().clone()));
    let authorization = CredentialAuthorization::new(method, delivery)?;
    dispatch_authorized_provider(provider, method, request, &authorization)
}

fn restart_provider(
    provider: &ManagedIdentityCredentialProvider,
    client: Arc<common::FakeClient>,
) -> ManagedIdentityCredentialProvider {
    ManagedIdentityCredentialProviderFactory::new(
        provider.config().clone(),
        provider.placement().clone(),
        provider.consumer_ref().clone(),
        client,
    )
    .unwrap()
    .construct()
}

#[test]
fn lease_operations_bind_to_authenticated_zone_workload_subject_and_session() {
    let (provider, client) = setup();
    let acquire_request = request("binding-acquire");
    let good_session = authenticated_session(
        "Provider/workload-a",
        "Zone/dev",
        "Guest/aca-sandbox",
        "Provider/runtime-azure-container-apps",
        1,
        1,
    );
    dispatch(
        &provider,
        CredentialMethod::AcquireToken,
        &acquire_request,
        good_session.clone(),
    )
    .unwrap();

    let mismatches = [
        authenticated_session(
            "Provider/workload-b",
            "Zone/dev",
            "Guest/aca-sandbox",
            "Provider/runtime-azure-container-apps",
            1,
            1,
        ),
        authenticated_session(
            "Provider/workload-a",
            "Zone/other",
            "Guest/aca-sandbox",
            "Provider/runtime-azure-container-apps",
            1,
            1,
        ),
        authenticated_session(
            "Provider/workload-a",
            "Zone/dev",
            "Guest/other",
            "Provider/runtime-azure-container-apps",
            1,
            1,
        ),
        authenticated_session(
            "Provider/workload-a",
            "Zone/dev",
            "Guest/aca-sandbox",
            "Provider/runtime-azure-container-apps",
            2,
            1,
        ),
        authenticated_session(
            "Provider/workload-a",
            "Zone/dev",
            "Guest/aca-sandbox",
            "Provider/runtime-azure-container-apps",
            1,
            2,
        ),
    ];
    for session in mismatches {
        assert_eq!(
            dispatch(
                &provider,
                CredentialMethod::RefreshToken,
                &request("binding-refresh"),
                session,
            )
            .unwrap_err()
            .code(),
            CredentialServiceErrorCode::OperationDenied
        );
    }

    assert_eq!(
        client
            .refresh_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert_eq!(
        dispatch_without_session(
            &provider,
            CredentialMethod::RefreshToken,
            &request("binding-no-session"),
        )
        .unwrap_err()
        .code(),
        CredentialServiceErrorCode::OperationDenied
    );
}

#[test]
fn wrong_zone_acquire_is_denied_before_first_client_call() {
    let (provider, client) = setup();
    let wrong_zone = authenticated_session(
        "Provider/workload-a",
        "Zone/other",
        "Guest/aca-sandbox",
        "Provider/runtime-azure-container-apps",
        1,
        1,
    );
    assert_eq!(
        dispatch(
            &provider,
            CredentialMethod::AcquireToken,
            &request("wrong-zone-first"),
            wrong_zone,
        )
        .unwrap_err()
        .code(),
        CredentialServiceErrorCode::OperationDenied
    );
    assert_eq!(
        client.issue_calls.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

#[test]
fn non_local_sessions_are_denied_before_first_client_call() {
    for locality in [Locality::AdjacentZone, Locality::Remote] {
        let (provider, client) = setup();
        let session = authenticated_session_with_locality(
            "Provider/workload-a",
            "Zone/dev",
            "Guest/aca-sandbox",
            "Provider/runtime-azure-container-apps",
            (1, 1),
            common::session_expiry(),
            locality,
        );
        assert_eq!(
            dispatch(
                &provider,
                CredentialMethod::AcquireToken,
                &request("non-local-session"),
                session,
            )
            .unwrap_err()
            .code(),
            CredentialServiceErrorCode::OperationDenied
        );
        assert_eq!(
            client.issue_calls.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }
}

#[test]
fn delivery_session_provider_generation_must_match_authenticated_subject() {
    let (provider, client) = setup();
    let request = request("delivery-generation-mismatch");
    let session = authenticated_session(
        "Provider/workload-a",
        "Zone/dev",
        "Guest/aca-sandbox",
        "Provider/runtime-azure-container-apps",
        1,
        1,
    );
    let delivery = delivery_for_timing_with_provider_generation(
        CredentialMethod::AcquireToken,
        1,
        request.credential_ref().clone(),
        common::EXPIRY,
        15_000,
        2,
    );
    let authorization =
        CredentialAuthorization::new(CredentialMethod::AcquireToken, Some(delivery))
            .unwrap()
            .with_authenticated_session(session)
            .unwrap();
    assert_eq!(
        dispatch_authorized_provider(
            &provider,
            CredentialMethod::AcquireToken,
            &request,
            &authorization,
        )
        .unwrap_err()
        .code(),
        CredentialServiceErrorCode::OperationDenied
    );
    assert_eq!(
        client.issue_calls.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

#[test]
fn authorization_subject_must_match_authenticated_session() {
    let (provider, client) = setup();
    let request = request("authorization-subject-mismatch");
    let session = authenticated_session(
        "Provider/workload-a",
        "Zone/dev",
        "Guest/aca-sandbox",
        "Provider/runtime-azure-container-apps",
        1,
        1,
    );
    let mismatched_subject = authenticated_session(
        "Provider/workload-b",
        "Zone/dev",
        "Guest/aca-sandbox",
        "Provider/runtime-azure-container-apps",
        1,
        1,
    )
    .authenticated_subject()
    .clone();
    let authorization = CredentialAuthorization::new_for_subject(
        CredentialMethod::AcquireToken,
        Some(common::delivery_for(
            CredentialMethod::AcquireToken,
            1,
            request.credential_ref().clone(),
        )),
        mismatched_subject,
    )
    .unwrap()
    .with_authenticated_session(session)
    .unwrap();
    assert_eq!(
        dispatch_authorized_provider(
            &provider,
            CredentialMethod::AcquireToken,
            &request,
            &authorization,
        )
        .unwrap_err()
        .code(),
        CredentialServiceErrorCode::OperationDenied
    );
    assert_eq!(
        client.issue_calls.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

#[test]
fn expired_sessions_and_leases_fail_closed() {
    let (provider, client) = setup();
    let expired_session = authenticated_session_with_expiry(
        "Provider/workload-a",
        "Zone/dev",
        "Guest/aca-sandbox",
        "Provider/runtime-azure-container-apps",
        1,
        1,
        now_unix_ms().saturating_sub(1),
    );
    assert_eq!(
        dispatch(
            &provider,
            CredentialMethod::AcquireToken,
            &request("expired-session"),
            expired_session,
        )
        .unwrap_err()
        .code(),
        CredentialServiceErrorCode::DeadlineExceeded
    );
    assert_eq!(
        client.issue_calls.load(std::sync::atomic::Ordering::SeqCst),
        0
    );

    let expires_soon = now_unix_ms() + 5;
    let lease_request = CredentialRequest::new(
        ResourceRef::parse("Credential/aca-relay-mi").unwrap(),
        "operation-expiring",
        "expiring-lease",
        expires_soon,
        expires_soon.saturating_sub(1),
    )
    .unwrap();
    let session = authenticated_session(
        "Provider/workload-a",
        "Zone/dev",
        "Guest/aca-sandbox",
        "Provider/runtime-azure-container-apps",
        1,
        1,
    );
    dispatch(
        &provider,
        CredentialMethod::AcquireToken,
        &lease_request,
        session.clone(),
    )
    .unwrap();
    thread::sleep(Duration::from_millis(10));
    assert_eq!(
        dispatch(
            &provider,
            CredentialMethod::RefreshToken,
            &request("expired-lease-refresh"),
            session,
        )
        .unwrap_err()
        .code(),
        CredentialServiceErrorCode::LeaseExpired
    );
}

#[test]
fn expired_lease_reacquire_replaces_predecessor_before_refresh() {
    let (provider, client) = setup();
    let session = authenticated_session(
        "Provider/workload-a",
        "Zone/dev",
        "Guest/aca-sandbox",
        "Provider/runtime-azure-container-apps",
        1,
        1,
    );
    let expiry = now_unix_ms() + 5;
    let first_request = CredentialRequest::new(
        ResourceRef::parse("Credential/aca-relay-mi").unwrap(),
        "expire-reacquire-first",
        "expire-reacquire-first",
        expiry,
        expiry - 1,
    )
    .unwrap();
    let first = dispatch(
        &provider,
        CredentialMethod::AcquireToken,
        &first_request,
        session.clone(),
    )
    .unwrap();
    let CredentialResponse::AcquireToken(first) = first else {
        panic!("acquire response");
    };
    assert_eq!(first.metadata.rotation_generation, 1);

    thread::sleep(Duration::from_millis(20));
    let reacquired = dispatch(
        &provider,
        CredentialMethod::AcquireToken,
        &request("expire-reacquire-second"),
        session.clone(),
    )
    .unwrap();
    let CredentialResponse::AcquireToken(reacquired) = reacquired else {
        panic!("reacquire response");
    };
    assert_eq!(reacquired.metadata.rotation_generation, 2);

    let refreshed = dispatch(
        &provider,
        CredentialMethod::RefreshToken,
        &request("expire-reacquire-refresh"),
        session,
    )
    .unwrap();
    let CredentialResponse::RefreshToken(refreshed) = refreshed else {
        panic!("refresh response");
    };
    assert_eq!(refreshed.metadata.rotation_generation, 3);
    assert_eq!(
        client.issue_calls.load(std::sync::atomic::Ordering::SeqCst),
        2
    );
    assert_eq!(
        client
            .refresh_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
}

#[test]
fn revoked_lease_reacquire_targets_only_the_current_record() {
    let (provider, client) = setup();
    let session = authenticated_session(
        "Provider/workload-a",
        "Zone/dev",
        "Guest/aca-sandbox",
        "Provider/runtime-azure-container-apps",
        1,
        1,
    );
    dispatch(
        &provider,
        CredentialMethod::AcquireToken,
        &request("revoke-reacquire-first"),
        session.clone(),
    )
    .unwrap();
    dispatch(
        &provider,
        CredentialMethod::RevokeToken,
        &request("revoke-reacquire-revoke-first"),
        session.clone(),
    )
    .unwrap();
    let reacquired = dispatch(
        &provider,
        CredentialMethod::AcquireToken,
        &request("revoke-reacquire-second"),
        session.clone(),
    )
    .unwrap();
    let CredentialResponse::AcquireToken(reacquired) = reacquired else {
        panic!("reacquire response");
    };
    assert_eq!(reacquired.metadata.rotation_generation, 2);

    dispatch(
        &provider,
        CredentialMethod::RevokeToken,
        &request("revoke-reacquire-revoke-second"),
        session.clone(),
    )
    .unwrap();
    assert_eq!(
        client
            .revoke_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        2
    );
    assert_eq!(
        dispatch(
            &provider,
            CredentialMethod::RefreshToken,
            &request("revoke-reacquire-refresh"),
            session,
        )
        .unwrap_err()
        .code(),
        CredentialServiceErrorCode::LeaseRevoked
    );
    assert_eq!(
        client
            .refresh_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

#[test]
fn reconnect_reacquire_replaces_stale_session_before_refresh() {
    let (provider, client) = setup();
    let first_session = authenticated_session(
        "Provider/workload-a",
        "Zone/dev",
        "Guest/aca-sandbox",
        "Provider/runtime-azure-container-apps",
        1,
        1,
    );
    let reconnected_session = authenticated_session(
        "Provider/workload-a",
        "Zone/dev",
        "Guest/aca-sandbox",
        "Provider/runtime-azure-container-apps",
        1,
        2,
    );
    dispatch(
        &provider,
        CredentialMethod::AcquireToken,
        &request("reconnect-first"),
        first_session.clone(),
    )
    .unwrap();
    let reacquired = dispatch(
        &provider,
        CredentialMethod::AcquireToken,
        &request("reconnect-second"),
        reconnected_session.clone(),
    )
    .unwrap();
    let CredentialResponse::AcquireToken(reacquired) = reacquired else {
        panic!("reacquire response");
    };
    assert_eq!(reacquired.metadata.rotation_generation, 2);
    assert_eq!(
        client
            .revoke_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );

    assert_eq!(
        dispatch(
            &provider,
            CredentialMethod::RefreshToken,
            &request("reconnect-stale-refresh"),
            first_session.clone(),
        )
        .unwrap_err()
        .code(),
        CredentialServiceErrorCode::OperationDenied
    );
    assert_eq!(
        dispatch(
            &provider,
            CredentialMethod::InspectMetadata,
            &request("reconnect-stale-inspect"),
            first_session,
        )
        .unwrap_err()
        .code(),
        CredentialServiceErrorCode::OperationDenied
    );
    let refreshed = dispatch(
        &provider,
        CredentialMethod::RefreshToken,
        &request("reconnect-current-refresh"),
        reconnected_session,
    )
    .unwrap();
    let CredentialResponse::RefreshToken(refreshed) = refreshed else {
        panic!("refresh response");
    };
    assert_eq!(refreshed.metadata.rotation_generation, 3);
    assert_eq!(
        client
            .inspect_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        client
            .refresh_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
}

#[test]
fn inspect_returns_terminal_metadata_without_reopening_a_revoked_lease() {
    let (provider, client) = setup();
    let session = authenticated_session(
        "Provider/workload-a",
        "Zone/dev",
        "Guest/aca-sandbox",
        "Provider/runtime-azure-container-apps",
        1,
        1,
    );
    dispatch(
        &provider,
        CredentialMethod::AcquireToken,
        &request("terminal-inspect-acquire"),
        session.clone(),
    )
    .unwrap();
    dispatch(
        &provider,
        CredentialMethod::RevokeToken,
        &request("terminal-inspect-revoke"),
        session.clone(),
    )
    .unwrap();
    let inspect_calls_before = client
        .inspect_calls
        .load(std::sync::atomic::Ordering::SeqCst);
    let response = dispatch(
        &provider,
        CredentialMethod::InspectMetadata,
        &request("terminal-inspect"),
        session,
    )
    .unwrap();
    let CredentialResponse::InspectMetadata(response) = response else {
        panic!("inspect response");
    };
    assert_eq!(
        response.metadata.state,
        d2b_contracts_provider::v3::credential::CredentialLeaseState::Revoked
    );
    assert_eq!(
        client
            .inspect_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        inspect_calls_before
    );
}

#[test]
fn inspect_returns_client_discovered_terminal_metadata() {
    let (provider, client) = setup();
    let session = authenticated_session(
        "Provider/workload-a",
        "Zone/dev",
        "Guest/aca-sandbox",
        "Provider/runtime-azure-container-apps",
        1,
        1,
    );
    dispatch(
        &provider,
        CredentialMethod::AcquireToken,
        &request("client-terminal-inspect-acquire"),
        session.clone(),
    )
    .unwrap();
    client.inspection.lock().unwrap().as_mut().unwrap().state = CredentialLeaseState::Revoked;
    let response = dispatch(
        &provider,
        CredentialMethod::InspectMetadata,
        &request("client-terminal-inspect"),
        session,
    )
    .unwrap();
    let CredentialResponse::InspectMetadata(response) = response else {
        panic!("inspect response");
    };
    assert_eq!(response.metadata.state, CredentialLeaseState::Revoked);
}

#[test]
fn invalid_issue_grant_is_revoked_before_acquire_returns_error() {
    let (provider, client) = setup();
    *client.issue_expiry_override.lock().unwrap() = Some(0);
    let session = authenticated_session(
        "Provider/workload-a",
        "Zone/dev",
        "Guest/aca-sandbox",
        "Provider/runtime-azure-container-apps",
        1,
        1,
    );
    assert_eq!(
        dispatch(
            &provider,
            CredentialMethod::AcquireToken,
            &request("invalid-issue-grant"),
            session,
        )
        .unwrap_err()
        .code(),
        CredentialServiceErrorCode::InvariantFailure
    );
    assert_eq!(
        client.issue_calls.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        client
            .revoke_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert!(provider.export_checkpoints().unwrap().is_empty());
}

#[test]
fn unresolved_issue_cleanup_is_checkpointed_without_shadowing_reacquire() {
    let (provider, client) = setup();
    *client.issue_expiry_override.lock().unwrap() = Some(0);
    *client.revoke_error.lock().unwrap() =
        Some(d2b_provider_credential_managed_identity::ManagedIdentityClientError::Unavailable);
    let session = authenticated_session(
        "Provider/workload-a",
        "Zone/dev",
        "Guest/aca-sandbox",
        "Provider/runtime-azure-container-apps",
        1,
        1,
    );
    assert_eq!(
        dispatch(
            &provider,
            CredentialMethod::AcquireToken,
            &request("unresolved-issue-cleanup"),
            session.clone(),
        )
        .unwrap_err()
        .code(),
        CredentialServiceErrorCode::InvariantFailure
    );
    let checkpoints = provider.export_checkpoints().unwrap();
    assert_eq!(checkpoints.len(), 1);
    assert_eq!(
        checkpoints[0].metadata().state,
        CredentialLeaseState::Active
    );

    let restored = restart_provider(&provider, client.clone());
    restored.restore_checkpoints(checkpoints.clone()).unwrap();
    restored.restore_checkpoints(checkpoints).unwrap();
    assert_eq!(restored.export_checkpoints().unwrap().len(), 1);

    *client.issue_expiry_override.lock().unwrap() = None;
    *client.revoke_error.lock().unwrap() = None;
    assert!(matches!(
        dispatch(
            &restored,
            CredentialMethod::AcquireToken,
            &request("unresolved-issue-reacquire"),
            session,
        )
        .unwrap(),
        CredentialResponse::AcquireToken(_)
    ));
    assert_eq!(restored.export_checkpoints().unwrap().len(), 1);
}

#[test]
fn unresolved_refresh_cleanup_is_checkpointed_and_finalized() {
    let (provider, client) = setup();
    let session = authenticated_session(
        "Provider/workload-a",
        "Zone/dev",
        "Guest/aca-sandbox",
        "Provider/runtime-azure-container-apps",
        1,
        1,
    );
    dispatch(
        &provider,
        CredentialMethod::AcquireToken,
        &request("unresolved-refresh-acquire"),
        session.clone(),
    )
    .unwrap();
    *client.refresh_expiry_override.lock().unwrap() = Some(0);
    *client.revoke_error.lock().unwrap() =
        Some(d2b_provider_credential_managed_identity::ManagedIdentityClientError::Unavailable);
    assert_eq!(
        dispatch(
            &provider,
            CredentialMethod::RefreshToken,
            &request("unresolved-refresh"),
            session.clone(),
        )
        .unwrap_err()
        .code(),
        CredentialServiceErrorCode::InvariantFailure
    );
    let checkpoints = provider.export_checkpoints().unwrap();
    assert_eq!(checkpoints.len(), 2);

    let restored = restart_provider(&provider, client.clone());
    restored.restore_checkpoints(checkpoints.clone()).unwrap();
    restored.restore_checkpoints(checkpoints).unwrap();
    assert_eq!(restored.export_checkpoints().unwrap().len(), 2);

    *client.refresh_expiry_override.lock().unwrap() = None;
    *client.revoke_error.lock().unwrap() = None;
    assert_eq!(restored.revoke_owned_handles(&session, 15_000).unwrap(), 2);
    assert_eq!(
        restored
            .export_checkpoints()
            .unwrap()
            .iter()
            .filter(|checkpoint| checkpoint.metadata().state == CredentialLeaseState::Revoked)
            .count(),
        2
    );
}

#[test]
fn cleanup_only_records_do_not_consume_restore_capacity() {
    let (provider, client) = setup_with_max_leases(1);
    let session = authenticated_session(
        "Provider/workload-a",
        "Zone/dev",
        "Guest/aca-sandbox",
        "Provider/runtime-azure-container-apps",
        1,
        1,
    );
    dispatch(
        &provider,
        CredentialMethod::AcquireToken,
        &request("capacity-cleanup-acquire"),
        session.clone(),
    )
    .unwrap();
    *client.refresh_expiry_override.lock().unwrap() = Some(0);
    *client.revoke_error.lock().unwrap() =
        Some(d2b_provider_credential_managed_identity::ManagedIdentityClientError::Unavailable);
    assert_eq!(
        dispatch(
            &provider,
            CredentialMethod::RefreshToken,
            &request("capacity-cleanup-refresh"),
            session.clone(),
        )
        .unwrap_err()
        .code(),
        CredentialServiceErrorCode::InvariantFailure
    );
    let checkpoints = provider.export_checkpoints().unwrap();
    assert_eq!(checkpoints.len(), 2);
    let restored = restart_provider(&provider, client);
    restored.restore_checkpoints(checkpoints).unwrap();
    assert_eq!(restored.export_checkpoints().unwrap().len(), 2);
}

#[test]
fn cleanup_only_records_do_not_open_a_spare_live_lease_slot() {
    let (provider, client) = setup_with_max_leases(1);
    *client.issue_expiry_override.lock().unwrap() = Some(0);
    *client.revoke_error.lock().unwrap() =
        Some(d2b_provider_credential_managed_identity::ManagedIdentityClientError::Unavailable);
    let owner_a = authenticated_session(
        "Provider/workload-a",
        "Zone/dev",
        "Guest/aca-sandbox",
        "Provider/runtime-azure-container-apps",
        1,
        1,
    );
    assert_eq!(
        dispatch(
            &provider,
            CredentialMethod::AcquireToken,
            &request("capacity-cleanup-slot-a"),
            owner_a.clone(),
        )
        .unwrap_err()
        .code(),
        CredentialServiceErrorCode::InvariantFailure
    );
    *client.issue_expiry_override.lock().unwrap() = None;
    *client.revoke_error.lock().unwrap() = None;
    let owner_b = authenticated_session(
        "Provider/workload-b",
        "Zone/dev",
        "Guest/aca-sandbox",
        "Provider/runtime-azure-container-apps",
        1,
        1,
    );
    assert!(matches!(
        dispatch(
            &provider,
            CredentialMethod::AcquireToken,
            &request("capacity-cleanup-slot-b"),
            owner_b,
        )
        .unwrap(),
        CredentialResponse::AcquireToken(_)
    ));
    assert_eq!(
        dispatch(
            &provider,
            CredentialMethod::AcquireToken,
            &request("capacity-cleanup-slot-a-retry"),
            owner_a,
        )
        .unwrap_err()
        .code(),
        CredentialServiceErrorCode::ProviderUnavailable
    );
}

#[test]
fn session_expiry_reacquire_revokes_the_previous_handle() {
    let (provider, client) = setup();
    let first_session = authenticated_session_with_expiry(
        "Provider/workload-a",
        "Zone/dev",
        "Guest/aca-sandbox",
        "Provider/runtime-azure-container-apps",
        1,
        1,
        now_unix_ms() + 80,
    );
    dispatch(
        &provider,
        CredentialMethod::AcquireToken,
        &request("session-expiry-first"),
        first_session,
    )
    .unwrap();
    thread::sleep(Duration::from_millis(120));
    let successor = authenticated_session(
        "Provider/workload-a",
        "Zone/dev",
        "Guest/aca-sandbox",
        "Provider/runtime-azure-container-apps",
        1,
        2,
    );
    assert!(matches!(
        dispatch(
            &provider,
            CredentialMethod::AcquireToken,
            &request("session-expiry-reacquire"),
            successor,
        )
        .unwrap(),
        CredentialResponse::AcquireToken(_)
    ));
    assert_eq!(
        client
            .revoke_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
}

#[test]
fn lease_lifetime_is_capped_by_provider_maximum() {
    let (provider, _) = setup();
    let now = now_unix_ms();
    let requested_expiry = now + MAX_PROVIDER_LEASE_LIFETIME_MS * 2;
    let request = CredentialRequest::new(
        ResourceRef::parse("Credential/aca-relay-mi").unwrap(),
        "operation-capped",
        "capped-lease",
        requested_expiry,
        requested_expiry - 1,
    )
    .unwrap();
    let session_expiry = requested_expiry;
    let session = authenticated_session_with_expiry(
        "Provider/workload-a",
        "Zone/dev",
        "Guest/aca-sandbox",
        "Provider/runtime-azure-container-apps",
        1,
        1,
        session_expiry,
    );
    let delivery = delivery_for_timing(
        CredentialMethod::AcquireToken,
        1,
        request.credential_ref().clone(),
        requested_expiry,
        requested_expiry - 1,
    );
    let authorization =
        CredentialAuthorization::new(CredentialMethod::AcquireToken, Some(delivery))
            .unwrap()
            .with_authenticated_session(session)
            .unwrap();
    let CredentialResponse::AcquireToken(response) = dispatch_authorized_provider(
        &provider,
        CredentialMethod::AcquireToken,
        &request,
        &authorization,
    )
    .unwrap() else {
        panic!("acquire response");
    };
    let completed_at = now_unix_ms();
    assert!(response.metadata.expires_at_unix_ms <= completed_at + MAX_PROVIDER_LEASE_LIFETIME_MS);
}

#[test]
fn checkpoints_restore_is_idempotent_and_refreshes_without_secret_material() {
    let (provider, client) = setup();
    let session = authenticated_session(
        "Provider/workload-a",
        "Zone/dev",
        "Guest/aca-sandbox",
        "Provider/runtime-azure-container-apps",
        1,
        1,
    );
    dispatch(
        &provider,
        CredentialMethod::AcquireToken,
        &request("checkpoint-acquire"),
        session.clone(),
    )
    .unwrap();
    let checkpoints = provider.export_checkpoints().unwrap();
    assert_eq!(checkpoints.len(), 1);
    let checkpoint_debug = format!("{checkpoints:?}");
    for marker in [
        client.token_canary.as_str(),
        client.endpoint_canary.as_str(),
        "Credential/aca-relay-mi",
        "checkpoint-acquire",
        "Provider/workload-a",
        "Zone/dev",
        "Guest/aca-sandbox",
        "Provider/runtime-azure-container-apps",
    ] {
        assert!(
            !checkpoint_debug.contains(marker),
            "managed-identity checkpoint leaked marker {marker}"
        );
    }

    let restored = restart_provider(&provider, client.clone());
    restored.restore_checkpoints(checkpoints.clone()).unwrap();
    restored.restore_checkpoints(checkpoints).unwrap();
    assert_eq!(restored.export_checkpoints().unwrap().len(), 1);
    assert!(matches!(
        dispatch(
            &restored,
            CredentialMethod::RefreshToken,
            &request("checkpoint-refresh"),
            session,
        )
        .unwrap(),
        CredentialResponse::RefreshToken(_)
    ));
    assert_eq!(
        client
            .refresh_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
}

#[test]
fn finalization_revokes_only_the_callers_owned_handles() {
    let (provider, client) = setup();
    let owner_a = authenticated_session(
        "Provider/workload-a",
        "Zone/dev",
        "Guest/aca-sandbox",
        "Provider/runtime-azure-container-apps",
        1,
        1,
    );
    let owner_b = authenticated_session(
        "Provider/workload-b",
        "Zone/dev",
        "Guest/aca-sandbox",
        "Provider/runtime-azure-container-apps",
        1,
        1,
    );
    dispatch(
        &provider,
        CredentialMethod::AcquireToken,
        &CredentialRequest::new(
            ResourceRef::parse("Credential/shared").unwrap(),
            "operation-owner-a",
            "owner-a",
            common::EXPIRY,
            15_000,
        )
        .unwrap(),
        owner_a.clone(),
    )
    .unwrap();
    dispatch(
        &provider,
        CredentialMethod::AcquireToken,
        &CredentialRequest::new(
            ResourceRef::parse("Credential/shared").unwrap(),
            "operation-owner-b",
            "owner-b",
            common::EXPIRY,
            15_000,
        )
        .unwrap(),
        owner_b.clone(),
    )
    .unwrap();

    assert_eq!(provider.revoke_owned_handles(&owner_a, 15_000).unwrap(), 1);
    assert_eq!(
        client
            .revoke_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    let checkpoints = provider.export_checkpoints().unwrap();
    assert_eq!(
        checkpoints
            .iter()
            .filter(|checkpoint| checkpoint.metadata().state
                == d2b_contracts_provider::v3::credential::CredentialLeaseState::Revoked)
            .count(),
        1
    );
    assert_eq!(
        checkpoints
            .iter()
            .filter(|checkpoint| checkpoint.metadata().state
                == d2b_contracts_provider::v3::credential::CredentialLeaseState::Active)
            .count(),
        1
    );
    assert!(matches!(
        dispatch(
            &provider,
            CredentialMethod::RefreshToken,
            &CredentialRequest::new(
                ResourceRef::parse("Credential/shared").unwrap(),
                "operation-owner-b-refresh",
                "owner-b-refresh",
                common::EXPIRY,
                15_000,
            )
            .unwrap(),
            owner_b,
        )
        .unwrap(),
        CredentialResponse::RefreshToken(_)
    ));
}

#[test]
fn controller_cleanup_keeps_the_finalizer_until_agent_deletion_is_observed() {
    assert_eq!(
        ManagedIdentityController::teardown_plan(true, false, false),
        ManagedIdentityTeardownPlan {
            stop_agent: true,
            delete_agent: false,
            clear_provider_revoke: false,
        }
    );
    assert_eq!(
        ManagedIdentityController::teardown_plan(false, true, false),
        ManagedIdentityTeardownPlan {
            stop_agent: false,
            delete_agent: true,
            clear_provider_revoke: false,
        }
    );
    assert_eq!(
        ManagedIdentityController::teardown_plan(false, true, true),
        ManagedIdentityTeardownPlan {
            stop_agent: false,
            delete_agent: false,
            clear_provider_revoke: true,
        }
    );
    assert_eq!(PROVIDER_KIND.as_str(), "credential-managed-identity");
    assert_eq!(
        PROVIDER_REVOKE_FINALIZER,
        "credential.d2bus.org/provider-revoke"
    );
}

#[test]
fn ambient_sdk_chain_names_are_rejected_before_imds_use() {
    assert!(
        d2b_provider_credential_managed_identity::reject_ambient_credential_chain(["PATH"])
            .is_ok()
    );
    assert!(
        d2b_provider_credential_managed_identity::reject_ambient_credential_chain(
            ["AZURE_FEDERATED_TOKEN_FILE"]
        )
        .is_err()
    );
}
