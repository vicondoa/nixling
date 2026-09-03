mod common;

use d2b_contracts_provider::v3::credential::{
    AudienceToken, CredentialAuthorization, CredentialLeaseHandle, CredentialLeaseState,
    CredentialMethod, CredentialProvider, CredentialRequest, CredentialResourceVerb,
    CredentialResponse, CredentialRotationPolicy, CredentialServiceErrorCode,
    CredentialSessionBinding, CredentialSourceVersion, DeliveryRouteDigest,
    DeliverySessionParams, OperationClass, PlacementBinding, RolePermission,
    RotationPolicyClass, dispatch_authorized_provider,
};
use d2b_contracts_provider::v3::credential_controller::{
    CredentialControllerHandlers, CredentialReconcileInput,
};
use d2b_contracts_resource::v3::{
    ControllerGeneration, ResourceGeneration, ResourceRef, ResourceUid, SchemaFingerprint, ZoneId,
    identity::{
        AuthenticatedSubjectContext, BindingDigest, EvidenceClass, Locality, ReconnectGeneration,
        ServiceName, SessionBinding, SessionPurpose, TranscriptHash, TransportBinding,
    },
};
use d2b_contracts_zone_session::v3::component_session::{
    EndpointRole, Locality as ComponentLocality, PurposeClass, TransportClass,
};
use d2b_provider_credential_secret_service::{
    LockPolicy, PROVIDER_KIND, PROVIDER_REVOKE_FINALIZER, SecretServiceConfig,
    SecretServiceController, SecretServiceCredentialProvider, SecretServiceCredentialProviderFactory,
    SecretServiceFuture, SecretServiceLeaseGrant, SecretServiceLeaseInspection,
    SecretServiceLeaseRef, SecretServiceLeaseRenewal, SecretServiceLeaseRequest,
    SecretServiceLeaseRevocation, SecretServicePlacement, SecretServiceState,
    SecretServicePortError, Oo7SecretServicePort,
};
use d2b_provider_toolkit::{
    AuthenticatedSessionRouteBinding, CredentialAuthorizationSource,
    CredentialDeliveryKeyMaterial, GuestCredentialBackend, GuestCredentialBackendHandler,
    GuestCredentialBackendHandlerError, GuestCredentialBackendHandlerFuture,
    GuestCredentialBackendReply, credential_service, spawn_guest_credential_backend_responder,
};

use common::{FakeOo7Port, delivery, request, setup};
use d2b_session::x25519_public_key;
use d2b_session_unix::{SeqpacketSocket, prearmed_seqpacket_pair};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};

struct TwoUserPort {
    leases: Mutex<BTreeMap<ResourceRef, CredentialLeaseState>>,
}

impl TwoUserPort {
    fn state_for(&self, user_ref: &ResourceRef) -> CredentialLeaseState {
        self.leases
            .lock()
            .unwrap()
            .get(user_ref)
            .copied()
            .unwrap_or(CredentialLeaseState::Revoked)
    }
}

impl Oo7SecretServicePort for TwoUserPort {
    fn state(&self) -> SecretServiceFuture<'_, SecretServiceState> {
        Box::pin(async { Ok(SecretServiceState::Unlocked) })
    }

    fn issue_lease(
        &self,
        request: &SecretServiceLeaseRequest,
    ) -> SecretServiceFuture<'_, SecretServiceLeaseGrant> {
        let user_ref = request.user_ref().clone();
        let expiry = request.requested_expiry_unix_ms();
        let lease_handle = format!("lease-{}", user_ref.name().as_str());
        let source_version = format!("source-{}", user_ref.name().as_str());
        self.leases
            .lock()
            .unwrap()
            .insert(user_ref, CredentialLeaseState::Active);
        Box::pin(async move {
            Ok(SecretServiceLeaseGrant {
                lease_handle: CredentialLeaseHandle::parse(lease_handle).unwrap(),
                source_version: CredentialSourceVersion::parse(source_version).unwrap(),
                rotation_generation: 1,
                expires_at_unix_ms: expiry,
            })
        })
    }

    fn inspect_lease(
        &self,
        lease: &SecretServiceLeaseRef,
    ) -> SecretServiceFuture<'_, SecretServiceLeaseInspection> {
        let state = self.state_for(lease.user_ref());
        let source_version =
            CredentialSourceVersion::parse(format!("source-{}", lease.user_ref().name().as_str()))
                .unwrap();
        let expiry = lease.metadata().expires_at_unix_ms;
        Box::pin(async move {
            Ok(SecretServiceLeaseInspection {
                state,
                source_version,
                rotation_generation: 1,
                expires_at_unix_ms: expiry,
            })
        })
    }

    fn refresh_lease(
        &self,
        lease: &SecretServiceLeaseRef,
    ) -> SecretServiceFuture<'_, SecretServiceLeaseRenewal> {
        let user_ref = lease.user_ref().clone();
        let expiry = lease.metadata().expires_at_unix_ms;
        let lease_handle = format!("lease-{}-refreshed", user_ref.name().as_str());
        let source_version = format!("source-{}-refreshed", user_ref.name().as_str());
        self.leases
            .lock()
            .unwrap()
            .insert(user_ref, CredentialLeaseState::Active);
        Box::pin(async move {
            Ok(SecretServiceLeaseGrant {
                lease_handle: CredentialLeaseHandle::parse(lease_handle).unwrap(),
                source_version: CredentialSourceVersion::parse(source_version).unwrap(),
                rotation_generation: 2,
                expires_at_unix_ms: expiry,
            })
        })
    }

    fn revoke_lease(
        &self,
        lease: &SecretServiceLeaseRef,
    ) -> SecretServiceFuture<'_, SecretServiceLeaseRevocation> {
        let user_ref = lease.user_ref().clone();
        let was_active = self.state_for(&user_ref) == CredentialLeaseState::Active;
        self.leases
            .lock()
            .unwrap()
            .insert(user_ref, CredentialLeaseState::Revoked);
        Box::pin(async move {
            Ok(if was_active {
                SecretServiceLeaseRevocation::Revoked
            } else {
                SecretServiceLeaseRevocation::AlreadyRevoked
            })
        })
    }
}

struct PreconnectedBackend;

impl GuestCredentialBackendHandler for PreconnectedBackend {
    fn handle(
        &self,
        _route: &AuthenticatedSessionRouteBinding,
        _user_ref: Option<&ResourceRef>,
        operation: &str,
        _fields: serde_json::Value,
    ) -> GuestCredentialBackendHandlerFuture<'_> {
        let operation = operation.to_owned();
        Box::pin(async move {
            tokio::task::yield_now().await;
            let response = match operation.as_str() {
                "secret-service.state" => GuestCredentialBackendReply::new(
                    Some("unlocked".to_owned()),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                ),
                "secret-service.issue-lease" => {
                    GuestCredentialBackendReply::with_sensitive_bytes(
                        Some("ready".to_owned()),
                        Some("current-thread-lease".to_owned()),
                        Some("current-thread-source".to_owned()),
                        Some(1),
                        Some(20_000),
                        None,
                        Some(b"current-thread-secret"),
                    )
                }
                "secret-service.inspect-lease" => GuestCredentialBackendReply::new(
                    Some("active".to_owned()),
                    Some("current-thread-lease".to_owned()),
                    Some("current-thread-source".to_owned()),
                    Some(1),
                    Some(20_000),
                    None,
                    None,
                ),
                "secret-service.revoke-lease" => GuestCredentialBackendReply::new(
                    Some("revoked".to_owned()),
                    Some("current-thread-lease".to_owned()),
                    Some("current-thread-source".to_owned()),
                    Some(1),
                    Some(20_000),
                    Some("revoked".to_owned()),
                    None,
                ),
                _ => return Err(GuestCredentialBackendHandlerError::Denied),
            };
            Ok(response)
        })
    }
}

struct ExistingRuntimePort {
    backend: Arc<GuestCredentialBackend>,
    revoke_calls: AtomicUsize,
}

fn backend_lease_handle(value: &str) -> Result<CredentialLeaseHandle, SecretServicePortError> {
    CredentialLeaseHandle::from_opaque_digest(value.to_owned())
        .or_else(|_| CredentialLeaseHandle::parse(value))
        .map_err(|_| SecretServicePortError::Unavailable)
}

async fn backend_response(
    backend: Arc<GuestCredentialBackend>,
    operation: &'static str,
    fields: serde_json::Value,
) -> Result<d2b_provider_toolkit::GuestCredentialBackendResponse, SecretServicePortError> {
    backend
        .request(operation, fields)
        .await
        .map_err(|_| SecretServicePortError::Unavailable)
}

impl Oo7SecretServicePort for ExistingRuntimePort {
    fn state(&self) -> SecretServiceFuture<'_, SecretServiceState> {
        Box::pin(async { Err(SecretServicePortError::Unavailable) })
    }

    fn state_for_user(&self, user_ref: &ResourceRef) -> SecretServiceFuture<'_, SecretServiceState> {
        let backend = Arc::clone(&self.backend);
        let fields = serde_json::json!({
            "collectionAlias": "login",
            "userRef": user_ref.to_canonical_string(),
        });
        Box::pin(async move {
            let response = backend_response(backend, "secret-service.state", fields).await?;
            match response.state() {
                Some("unlocked") => Ok(SecretServiceState::Unlocked),
                _ => Err(SecretServicePortError::Locked),
            }
        })
    }

    fn issue_lease(
        &self,
        request: &SecretServiceLeaseRequest,
    ) -> SecretServiceFuture<'_, SecretServiceLeaseGrant> {
        let backend = Arc::clone(&self.backend);
        let fields = serde_json::json!({
            "collectionAlias": "login",
            "userRef": request.user_ref().to_canonical_string(),
            "credentialRef": request.credential_ref().to_canonical_string(),
            "operationId": request.operation_id(),
            "idempotencyKey": request.idempotency_key(),
            "requestedExpiryUnixMs": request.requested_expiry_unix_ms(),
        })
        ;
        Box::pin(async move {
            let mut response =
                backend_response(backend, "secret-service.issue-lease", fields).await?;
            response.clear_bytes();
            Ok(SecretServiceLeaseGrant {
                lease_handle: backend_lease_handle(
                    response
                        .lease_handle()
                        .ok_or(SecretServicePortError::CompletionUnknown)?,
                )?,
                source_version: CredentialSourceVersion::parse(
                    response
                        .source_version()
                        .ok_or(SecretServicePortError::CompletionUnknown)?,
                )
                .map_err(|_| SecretServicePortError::CompletionUnknown)?,
                rotation_generation: response
                    .rotation_generation()
                    .ok_or(SecretServicePortError::CompletionUnknown)?,
                expires_at_unix_ms: response
                    .expires_at_unix_ms()
                    .ok_or(SecretServicePortError::CompletionUnknown)?,
            })
        })
    }

    fn inspect_lease(
        &self,
        lease: &SecretServiceLeaseRef,
    ) -> SecretServiceFuture<'_, SecretServiceLeaseInspection> {
        let backend = Arc::clone(&self.backend);
        let fields = serde_json::json!({
            "collectionAlias": "login",
            "userRef": lease.user_ref().to_canonical_string(),
            "credentialRef": lease.credential_ref().to_canonical_string(),
            "leaseHandle": lease.metadata().lease_handle.as_opaque_str(),
        })
        ;
        Box::pin(async move {
            let response =
                backend_response(backend, "secret-service.inspect-lease", fields).await?;
            Ok(SecretServiceLeaseInspection {
                state: match response.state() {
                    Some("active") => CredentialLeaseState::Active,
                    Some("revoked") => CredentialLeaseState::Revoked,
                    Some("expired") => CredentialLeaseState::Expired,
                    _ => return Err(SecretServicePortError::CompletionUnknown),
                },
                source_version: CredentialSourceVersion::parse(
                    response
                        .source_version()
                        .ok_or(SecretServicePortError::CompletionUnknown)?,
                )
                .map_err(|_| SecretServicePortError::CompletionUnknown)?,
                rotation_generation: response
                    .rotation_generation()
                    .ok_or(SecretServicePortError::CompletionUnknown)?,
                expires_at_unix_ms: response
                    .expires_at_unix_ms()
                    .ok_or(SecretServicePortError::CompletionUnknown)?,
            })
        })
    }

    fn refresh_lease(
        &self,
        lease: &SecretServiceLeaseRef,
    ) -> SecretServiceFuture<'_, SecretServiceLeaseRenewal> {
        let backend = Arc::clone(&self.backend);
        let fields = serde_json::json!({
            "collectionAlias": "login",
            "userRef": lease.user_ref().to_canonical_string(),
            "credentialRef": lease.credential_ref().to_canonical_string(),
            "leaseHandle": lease.metadata().lease_handle.as_opaque_str(),
        })
        ;
        Box::pin(async move {
            let mut response =
                backend_response(backend, "secret-service.refresh-lease", fields).await?;
            response.clear_bytes();
            Ok(SecretServiceLeaseGrant {
                lease_handle: backend_lease_handle(
                    response
                        .lease_handle()
                        .ok_or(SecretServicePortError::CompletionUnknown)?,
                )?,
                source_version: CredentialSourceVersion::parse(
                    response
                        .source_version()
                        .ok_or(SecretServicePortError::CompletionUnknown)?,
                )
                .map_err(|_| SecretServicePortError::CompletionUnknown)?,
                rotation_generation: response
                    .rotation_generation()
                    .ok_or(SecretServicePortError::CompletionUnknown)?,
                expires_at_unix_ms: response
                    .expires_at_unix_ms()
                    .ok_or(SecretServicePortError::CompletionUnknown)?,
            })
        })
    }

    fn revoke_lease(
        &self,
        lease: &SecretServiceLeaseRef,
    ) -> SecretServiceFuture<'_, SecretServiceLeaseRevocation> {
        self.revoke_calls.fetch_add(1, Ordering::SeqCst);
        let backend = Arc::clone(&self.backend);
        let fields = serde_json::json!({
            "collectionAlias": "login",
            "userRef": lease.user_ref().to_canonical_string(),
            "credentialRef": lease.credential_ref().to_canonical_string(),
            "leaseHandle": lease.metadata().lease_handle.as_opaque_str(),
        });
        Box::pin(async move {
            let response =
                backend_response(backend, "secret-service.revoke-lease", fields).await?;
            match response.outcome() {
                Some("revoked") => Ok(SecretServiceLeaseRevocation::Revoked),
                Some("already-revoked") => Ok(SecretServiceLeaseRevocation::AlreadyRevoked),
                _ => Err(SecretServicePortError::CompletionUnknown),
            }
        })
    }
}

fn provider_route() -> AuthenticatedSessionRouteBinding {
    let provider_ref = ResourceRef::parse("Provider/credential-secret-service").unwrap();
    let context = AuthenticatedSubjectContext::new(
        provider_ref.clone(),
        ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap(),
        ResourceRef::parse("Zone/dev").unwrap(),
        EvidenceClass::UnixPeer,
        SessionPurpose::parse("provider-control").unwrap(),
        ServiceName::parse("d2b.credential.v3").unwrap(),
        SessionBinding::new(
            SchemaFingerprint::parse(format!("sha256:{}", "3".repeat(64))).unwrap(),
            TransportBinding::new(
                Locality::Local,
                BindingDigest::parse(format!("sha256:{}", "4".repeat(64))).unwrap(),
            ),
            ReconnectGeneration::new(1).unwrap(),
            TranscriptHash::from_bytes([5; 32]),
        ),
    )
    .with_execution_ref(ResourceRef::parse("Guest/test").unwrap())
    .with_process_ref(
        ResourceRef::parse("Process/credential-secret-service-controller").unwrap(),
    )
    .with_provider_ref(provider_ref)
    .with_provider_generation(ResourceGeneration::new(1).unwrap())
    .with_controller_generation(ControllerGeneration::new(1).unwrap());
    AuthenticatedSessionRouteBinding::from_authenticated_peer(
        context,
        ComponentLocality::HostLocal,
        PurposeClass::Local,
        EndpointRole::Provider,
        EndpointRole::ZoneController,
        TransportClass::InheritedSocketpair,
    )
    .unwrap()
}

struct UserAuthorization;

impl CredentialAuthorizationSource for UserAuthorization {
    fn authorize(
        &self,
        method: CredentialMethod,
        request: &CredentialRequest,
        route: &AuthenticatedSessionRouteBinding,
    ) -> Result<CredentialAuthorization, d2b_contracts_provider::v3::credential::CredentialServiceError>
    {
        let delivery = if method.requires_delivery() {
            Some(
                DeliverySessionParams::new(
                    request.credential_ref().clone(),
                    ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap(),
                    ResourceGeneration::new(1).unwrap(),
                    ResourceRef::parse("Provider/credential-secret-service").unwrap(),
                    ResourceGeneration::new(1).unwrap(),
                    AudienceToken::parse("user-session").unwrap(),
                    method.operation_class(),
                    request.requested_expiry_unix_ms(),
                    request.deadline_unix_ms(),
                    DeliveryRouteDigest::parse(format!("sha256:{}", "a".repeat(64))).unwrap(),
                    4_096,
                    1,
                )
                .unwrap(),
            )
        } else {
            None
        };
        CredentialAuthorization::new_for_subject(method, delivery, route.context().clone())?
            .with_user_ref(Some(ResourceRef::parse("User/alice").unwrap()))?
            .with_authenticated_session(
                CredentialSessionBinding::new(
                    route.context().clone(),
                    request.deadline_unix_ms(),
                )?,
            )
    }
}

fn service_request(method: &str, request: &CredentialRequest) -> ttrpc::Request {
    ttrpc::Request {
        service: "d2b.credential.v3.CredentialService".to_owned(),
        method: method.to_owned(),
        metadata: vec![
            ttrpc::proto::KeyValue {
                key: "d2b.credential.zone".to_owned(),
                value: "dev".to_owned(),
                ..Default::default()
            },
            ttrpc::proto::KeyValue {
                key: "d2b.credential.provider".to_owned(),
                value: "Provider/credential-secret-service".to_owned(),
                ..Default::default()
            },
            ttrpc::proto::KeyValue {
                key: "d2b.credential.uid".to_owned(),
                value: "123e4567-e89b-42d3-a456-426614174000".to_owned(),
                ..Default::default()
            },
            ttrpc::proto::KeyValue {
                key: "d2b.credential.generation".to_owned(),
                value: "1".to_owned(),
                ..Default::default()
            },
            ttrpc::proto::KeyValue {
                key: "d2b.credential.provider-generation".to_owned(),
                value: "1".to_owned(),
                ..Default::default()
            },
            ttrpc::proto::KeyValue {
                key: "d2b.credential.controller-generation".to_owned(),
                value: "1".to_owned(),
                ..Default::default()
            },
            ttrpc::proto::KeyValue {
                key: "d2b.credential.session-generation".to_owned(),
                value: "1".to_owned(),
                ..Default::default()
            },
            ttrpc::proto::KeyValue {
                key: "d2b.credential.user-ref".to_owned(),
                value: "User/alice".to_owned(),
                ..Default::default()
            },
        ],
        payload: d2b_contracts_provider::v3::credential::encode_outer(request).unwrap(),
        ..Default::default()
    }
}

fn ttrpc_context() -> ttrpc::r#async::TtrpcContext {
    ttrpc::r#async::TtrpcContext {
        mh: ttrpc::proto::MessageHeader::new_request(1, 0),
        metadata: std::collections::HashMap::new(),
        timeout_nano: 0,
    }
}

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
fn dynamic_user_scope_isolates_leases_and_revocation() {
    let port = Arc::new(TwoUserPort {
        leases: Mutex::new(BTreeMap::new()),
    });
    let provider_port: Arc<dyn Oo7SecretServicePort> = port.clone();
    let provider = SecretServiceCredentialProviderFactory::new(
        SecretServiceConfig::new("login collection", 64, LockPolicy::FailClosed).unwrap(),
        SecretServicePlacement::new_dynamic(
            ZoneId::parse("user-zone").unwrap(),
            PlacementBinding::UserAgent,
            ResourceRef::parse("Host/workstation").unwrap(),
        )
        .unwrap(),
        Some(ResourceRef::parse("Provider/shell-terminal").unwrap()),
        provider_port,
    )
    .unwrap()
    .construct()
    .unwrap();
    let alice = ResourceRef::parse("User/alice").unwrap();
    let bob = ResourceRef::parse("User/bob").unwrap();
    let credential = ResourceRef::parse("Credential/shared").unwrap();
    let acquire = |user: &ResourceRef, operation: &str, sequence: u64| {
        let request = CredentialRequest::new(
            credential.clone(),
            operation,
            format!("{operation}-idempotency"),
            20_000,
            15_000,
        )
        .unwrap();
        let authorization = CredentialAuthorization::new(
            CredentialMethod::AcquireToken,
            Some(common::delivery_for_consumer(
                CredentialMethod::AcquireToken,
                sequence,
                credential.clone(),
                ResourceRef::parse("Provider/shell-terminal").unwrap(),
            )),
        )
        .unwrap()
        .with_user_ref(Some(user.clone()))
        .unwrap();
        dispatch_authorized_provider(
            &provider,
            CredentialMethod::AcquireToken,
            &request,
            &authorization,
        )
        .unwrap()
    };
    acquire(&alice, "alice-acquire", 1);
    acquire(&bob, "bob-acquire", 2);

    let revoke_request = CredentialRequest::new(
        credential.clone(),
        "alice-revoke",
        "alice-revoke-idempotency",
        20_000,
        15_000,
    )
    .unwrap();
    let revoke_authorization = CredentialAuthorization::new(
        CredentialMethod::RevokeToken,
        None,
    )
    .unwrap()
    .with_user_ref(Some(alice.clone()))
    .unwrap();
    let revoked = dispatch_authorized_provider(
        &provider,
        CredentialMethod::RevokeToken,
        &revoke_request,
        &revoke_authorization,
    )
    .unwrap();
    assert!(matches!(revoked, CredentialResponse::RevokeToken(_)));
    assert_eq!(port.state_for(&alice), CredentialLeaseState::Revoked);
    assert_eq!(port.state_for(&bob), CredentialLeaseState::Active);

    let inspect_request = CredentialRequest::new(
        credential,
        "bob-inspect",
        "bob-inspect-idempotency",
        20_000,
        15_000,
    )
    .unwrap();
    let inspect_authorization = CredentialAuthorization::new(
        CredentialMethod::InspectMetadata,
        None,
    )
    .unwrap()
    .with_user_ref(Some(bob))
    .unwrap();
    let inspected = dispatch_authorized_provider(
        &provider,
        CredentialMethod::InspectMetadata,
        &inspect_request,
        &inspect_authorization,
    )
    .unwrap();
    let CredentialResponse::InspectMetadata(inspected) = inspected else {
        panic!("expected metadata inspection");
    };
    assert_eq!(inspected.metadata.state, CredentialLeaseState::Active);
}

#[tokio::test(flavor = "current_thread")]
async fn current_thread_service_dispatch_drives_preconnected_backend_without_deadlock() {
    let route = provider_route();
    let (client_fd, server_fd) = prearmed_seqpacket_pair().unwrap();
    let client_socket = SeqpacketSocket::from_parent_prearmed(client_fd).unwrap();
    let server_socket = SeqpacketSocket::from_parent_prearmed(server_fd).unwrap();
    let provider_private = [7_u8; 32];
    let backend_private = [9_u8; 32];
    let backend_public = x25519_public_key(&backend_private).unwrap();
    let provider_public = x25519_public_key(&provider_private).unwrap();
    let backend = GuestCredentialBackend::from_socket_for_test_with_route(
        client_socket,
        route.clone(),
        CredentialDeliveryKeyMaterial::new(provider_private, backend_public).unwrap(),
    )
    .unwrap();
    let responder = spawn_guest_credential_backend_responder(
        server_socket,
        CredentialDeliveryKeyMaterial::new(backend_private, provider_public).unwrap(),
        Arc::new(PreconnectedBackend),
    )
    .unwrap();
    responder.bind_route(route.clone()).unwrap();
    let port = Arc::new(ExistingRuntimePort {
        backend,
        revoke_calls: AtomicUsize::new(0),
    });
    let provider = SecretServiceCredentialProviderFactory::new(
        SecretServiceConfig::new("login collection", 64, LockPolicy::FailClosed).unwrap(),
        SecretServicePlacement::new_dynamic(
            ZoneId::parse("dev").unwrap(),
            PlacementBinding::UserAgent,
            ResourceRef::parse("Guest/test").unwrap(),
        )
        .unwrap(),
        Some(ResourceRef::parse("Provider/credential-secret-service").unwrap()),
        port.clone(),
    )
    .unwrap()
    .construct()
    .unwrap();
    let services = credential_service(
        Arc::new(provider),
        Arc::new(UserAuthorization),
        route,
    );
    let acquire_request = CredentialRequest::new(
        ResourceRef::parse("Credential/current-thread").unwrap(),
        "current-thread-acquire",
        "current-thread-acquire-idempotency",
        20_000,
        15_000,
    )
    .unwrap();
    let acquire = services
        .get("d2b.credential.v3.CredentialService")
        .unwrap()
        .methods
        .get("AcquireToken")
        .unwrap()
        .handler(ttrpc_context(), service_request("AcquireToken", &acquire_request));
    let acquired = tokio::time::timeout(std::time::Duration::from_secs(2), acquire)
        .await
        .expect("AcquireToken must not deadlock")
        .unwrap();
    let acquired: d2b_contracts_provider::v3::credential::DeliveryResponse =
        d2b_contracts_provider::v3::credential::decode_outer(&acquired.payload).unwrap();
    assert_eq!(acquired.metadata.state, CredentialLeaseState::Active);
    let revoke_request = CredentialRequest::new(
        ResourceRef::parse("Credential/current-thread").unwrap(),
        "current-thread-revoke",
        "current-thread-revoke-idempotency",
        20_000,
        15_000,
    )
    .unwrap();
    let revoke = services
        .get("d2b.credential.v3.CredentialService")
        .unwrap()
        .methods
        .get("RevokeToken")
        .unwrap()
        .handler(ttrpc_context(), service_request("RevokeToken", &revoke_request));
    let revoked = tokio::time::timeout(std::time::Duration::from_secs(2), revoke)
        .await
        .expect("RevokeToken must not deadlock")
        .unwrap();
    let revoked: d2b_contracts_provider::v3::credential::MetadataResponse =
        d2b_contracts_provider::v3::credential::decode_outer(&revoked.payload).unwrap();
    assert_eq!(revoked.metadata.state, CredentialLeaseState::Revoked);
    assert_eq!(port.revoke_calls.load(Ordering::SeqCst), 1);
    responder.cancel();
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
