//! Typed `d2b.credential.v3` ComponentSession service support.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use d2b_contracts_provider::v3::credential::{
    CredentialAuthorization, CredentialMethod, CredentialProvider, CredentialRequest,
    CredentialResponse, CredentialServiceError, CredentialServiceErrorCode,
    CredentialSessionBinding, DeliveryResponse, MetadataResponse, decode_outer,
    dispatch_authorized_provider, encode_outer,
};
use d2b_session::{AuthenticatedComponentSession, AuthenticatedSessionRouteBinding, Cancellation};

use crate::{
    ProviderAdmission, ProviderEntrypoint, ProviderRuntimeError, ProviderSessionAdmission,
};

const CREDENTIAL_SERVICE: &str = "d2b.credential.v3.CredentialService";

/// Constructs method authorization from the authenticated ComponentSession
/// route. Delivery-bearing methods require a Provider-specific authorizer.
pub trait CredentialAuthorizationSource: Send + Sync + 'static {
    /// Build the exact authorization result for one typed Credential request.
    fn authorize(
        &self,
        method: CredentialMethod,
        request: &CredentialRequest,
        route: &AuthenticatedSessionRouteBinding,
    ) -> Result<CredentialAuthorization, CredentialServiceError>;
}

/// Default authorization source for metadata and revocation operations.
#[derive(Debug, Default)]
pub struct RouteCredentialAuthorization;

impl CredentialAuthorizationSource for RouteCredentialAuthorization {
    fn authorize(
        &self,
        method: CredentialMethod,
        request: &CredentialRequest,
        route: &AuthenticatedSessionRouteBinding,
    ) -> Result<CredentialAuthorization, CredentialServiceError> {
        if !matches!(
            method,
            CredentialMethod::RevokeToken | CredentialMethod::InspectMetadata
        ) {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::OperationDenied,
            ));
        }
        let session =
            CredentialSessionBinding::new(route.context().clone(), request.deadline_unix_ms())?;
        CredentialAuthorization::new_for_subject(method, None, route.context().clone())?
            .with_authenticated_session(session)
    }
}

struct CredentialMethodHandler<P, A> {
    provider: Arc<P>,
    authorizer: Arc<A>,
    route: AuthenticatedSessionRouteBinding,
    method: CredentialMethod,
}

#[async_trait]
impl<P, A> ttrpc::r#async::MethodHandler for CredentialMethodHandler<P, A>
where
    P: CredentialProvider + 'static,
    A: CredentialAuthorizationSource,
{
    async fn handler(
        &self,
        _context: ttrpc::r#async::TtrpcContext,
        request: ttrpc::Request,
    ) -> ttrpc::Result<ttrpc::Response> {
        if !self.route.liveness().is_live() || request.service != CREDENTIAL_SERVICE {
            return Err(rpc_error(CredentialServiceError::new(
                CredentialServiceErrorCode::OperationDenied,
            )));
        }
        let expected_provider = self
            .route
            .provider_ref()
            .map(d2b_contracts_resource::v3::ResourceRef::to_canonical_string);
        if metadata_value(&request, "d2b.credential.zone") != Some(self.route.zone().as_str())
            || metadata_value(&request, "d2b.credential.provider")
                != expected_provider.as_deref()
            || metadata_value(&request, "d2b.credential.session-generation")
                .and_then(|value| value.parse::<u64>().ok())
                != Some(self.route.reconnect_generation().get())
            || metadata_value(&request, "d2b.credential.uid")
                .and_then(|value| {
                    d2b_contracts_resource::v3::ResourceUid::parse(value.to_owned()).ok()
                })
                .is_none()
            || metadata_value(&request, "d2b.credential.generation")
                .and_then(|value| value.parse::<u64>().ok())
                .is_none_or(|value| value == 0)
            || metadata_value(&request, "d2b.credential.provider-generation")
                .and_then(|value| value.parse::<u64>().ok())
                .is_none_or(|value| value == 0)
            || metadata_value(&request, "d2b.credential.controller-generation")
                .and_then(|value| value.parse::<u64>().ok())
                .is_none_or(|value| value == 0)
        {
            return Err(rpc_error(CredentialServiceError::new(
                CredentialServiceErrorCode::OperationDenied,
            )));
        }
        let request = decode_outer::<CredentialRequest>(&request.payload).map_err(rpc_error)?;
        let authorization = self
            .authorizer
            .authorize(self.method, &request, &self.route)
            .map_err(rpc_error)?;
        let response = dispatch_authorized_provider(
            self.provider.as_ref(),
            self.method,
            &request,
            &authorization,
        )
        .map_err(rpc_error)?;
        let payload = match response {
            CredentialResponse::AcquireToken(response)
            | CredentialResponse::RefreshToken(response)
            | CredentialResponse::SignChallenge(response) => {
                encode_outer::<DeliveryResponse>(&response).map_err(rpc_error)?
            }
            CredentialResponse::RevokeToken(response)
            | CredentialResponse::InspectMetadata(response) => {
                encode_outer::<MetadataResponse>(&response).map_err(rpc_error)?
            }
        };
        let mut response = ttrpc::Response::new();
        response.set_status(ttrpc::get_status(ttrpc::Code::OK, ""));
        response.payload = payload;
        Ok(response)
    }
}

fn metadata_value<'a>(request: &'a ttrpc::Request, key: &str) -> Option<&'a str> {
    request
        .metadata
        .iter()
        .find(|value| value.key == key)
        .map(|value| value.value.as_str())
}

/// Build the typed Credential service map for an authenticated route.
pub fn credential_service<P, A>(
    provider: Arc<P>,
    authorizer: Arc<A>,
    route: AuthenticatedSessionRouteBinding,
) -> HashMap<String, ttrpc::r#async::Service>
where
    P: CredentialProvider + 'static,
    A: CredentialAuthorizationSource,
{
    let mut methods = HashMap::new();
    for (name, method) in [
        ("AcquireToken", CredentialMethod::AcquireToken),
        ("RefreshToken", CredentialMethod::RefreshToken),
        ("RevokeToken", CredentialMethod::RevokeToken),
        ("SignChallenge", CredentialMethod::SignChallenge),
        ("InspectMetadata", CredentialMethod::InspectMetadata),
    ] {
        let handler = CredentialMethodHandler {
            provider: Arc::clone(&provider),
            authorizer: Arc::clone(&authorizer),
            route: route.clone(),
            method,
        };
        methods.insert(
            name.to_owned(),
            Box::new(handler) as Box<dyn ttrpc::r#async::MethodHandler + Send + Sync>,
        );
    }
    HashMap::from([(
        CREDENTIAL_SERVICE.to_owned(),
        ttrpc::r#async::Service {
            methods,
            streams: HashMap::new(),
        },
    )])
}

/// Run one authenticated, supervised typed Credential service.
pub async fn run_authenticated_credential_provider<P, A>(
    entrypoint: ProviderEntrypoint,
    registration: ProviderAdmission,
    session_admission: ProviderSessionAdmission,
    session: AuthenticatedComponentSession<()>,
    provider: Arc<P>,
    authorizer: Arc<A>,
    cancellation: Cancellation,
) -> Result<(), ProviderRuntimeError>
where
    P: CredentialProvider + 'static,
    A: CredentialAuthorizationSource,
{
    if session.route_binding().service().as_str() != "d2b.credential.v3" {
        return Err(ProviderRuntimeError::SessionUnauthenticated);
    }
    entrypoint
        .publish_authenticated_ready(&registration, session_admission, &session)
        .map_err(|_| ProviderRuntimeError::NotAccepting)?;
    let route = session.route_binding();
    let driver = Arc::new(session.into_authenticated_driver());
    let serving =
        d2b_session::serve_ttrpc_services(driver, credential_service(provider, authorizer, route));
    let result = tokio::select! {
        result = serving => result.map_err(|_| ProviderRuntimeError::SessionLoopFailed),
        _ = cancellation.cancelled() => Ok(()),
    };
    drop(registration);
    if !entrypoint.drain(Duration::from_secs(5)) {
        return Err(ProviderRuntimeError::SessionLoopFailed);
    }
    result
}

fn rpc_error(error: CredentialServiceError) -> ttrpc::Error {
    let code = match error.code() {
        CredentialServiceErrorCode::Malformed | CredentialServiceErrorCode::Oversize => {
            ttrpc::Code::INVALID_ARGUMENT
        }
        CredentialServiceErrorCode::DeadlineExceeded => ttrpc::Code::DEADLINE_EXCEEDED,
        CredentialServiceErrorCode::OperationDenied => ttrpc::Code::PERMISSION_DENIED,
        CredentialServiceErrorCode::ProviderUnavailable => ttrpc::Code::UNAVAILABLE,
        CredentialServiceErrorCode::LeaseExpired | CredentialServiceErrorCode::LeaseRevoked => {
            ttrpc::Code::FAILED_PRECONDITION
        }
        CredentialServiceErrorCode::InvariantFailure => ttrpc::Code::INTERNAL,
    };
    ttrpc::Error::RpcStatus(ttrpc::get_status(code, error.code().as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use d2b_contracts_provider::v3::credential::{
        CredentialLeaseHandle, CredentialLeaseState, CredentialMetadata, CredentialOutcomeCode,
        CredentialSourceVersion,
    };
    use d2b_contracts_resource::v3::ResourceRef;

    struct FakeCredentialProvider;

    impl CredentialProvider for FakeCredentialProvider {
        fn dispatch(
            &self,
            method: CredentialMethod,
            _request: &CredentialRequest,
            _authorization: &CredentialAuthorization,
        ) -> Result<CredentialResponse, CredentialServiceError> {
            assert_eq!(method, CredentialMethod::RevokeToken);
            Ok(CredentialResponse::RevokeToken(MetadataResponse {
                metadata: CredentialMetadata {
                    lease_handle: CredentialLeaseHandle::parse("lease").unwrap(),
                    rotation_generation: 1,
                    source_version: CredentialSourceVersion::parse("source").unwrap(),
                    expires_at_unix_ms: u64::MAX,
                    state: CredentialLeaseState::Revoked,
                    outcome: CredentialOutcomeCode::Revoked,
                },
            }))
        }
    }

    fn route(dead: bool) -> AuthenticatedSessionRouteBinding {
        if dead {
            AuthenticatedSessionRouteBinding::for_test_dead(
                Some(ResourceRef::parse("Provider/credential-managed-identity").unwrap()),
                "d2b.credential.v3",
                7,
                Some(1),
                Some(1),
            )
        } else {
            AuthenticatedSessionRouteBinding::for_test(
                Some(ResourceRef::parse("Provider/credential-managed-identity").unwrap()),
                "d2b.credential.v3",
                7,
                Some(1),
                Some(1),
            )
        }
    }

    fn request() -> ttrpc::Request {
        let typed = CredentialRequest::new(
            ResourceRef::parse("Credential/example").unwrap(),
            "revoke-operation",
            "revoke-idempotency",
            u64::MAX,
            u64::MAX,
        )
        .unwrap();
        ttrpc::Request {
            service: CREDENTIAL_SERVICE.to_owned(),
            method: "RevokeToken".to_owned(),
            metadata: vec![
                ttrpc::proto::KeyValue {
                    key: "d2b.credential.zone".to_owned(),
                    value: "dev".to_owned(),
                    ..Default::default()
                },
                ttrpc::proto::KeyValue {
                    key: "d2b.credential.provider".to_owned(),
                    value: "Provider/credential-managed-identity".to_owned(),
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
                    value: "7".to_owned(),
                    ..Default::default()
                },
            ],
            payload: encode_outer(&typed).unwrap(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn credential_service_dispatches_a_valid_typed_revoke() {
        let service = credential_service(
            Arc::new(FakeCredentialProvider),
            Arc::new(RouteCredentialAuthorization),
            route(false),
        );
        let method = service
            .get(CREDENTIAL_SERVICE)
            .unwrap()
            .methods
            .get("RevokeToken")
            .unwrap();
        let response = method.handler(test_context(), request()).await.unwrap();
        let metadata: MetadataResponse = decode_outer(&response.payload).unwrap();
        assert_eq!(metadata.metadata.state, CredentialLeaseState::Revoked);
        assert_eq!(metadata.metadata.outcome, CredentialOutcomeCode::Revoked);
    }

    #[tokio::test]
    async fn credential_service_refuses_a_stale_authenticated_route() {
        let service = credential_service(
            Arc::new(FakeCredentialProvider),
            Arc::new(RouteCredentialAuthorization),
            route(true),
        );
        let method = service
            .get(CREDENTIAL_SERVICE)
            .unwrap()
            .methods
            .get("RevokeToken")
            .unwrap();
        assert!(method.handler(test_context(), request()).await.is_err());
    }

    fn test_context() -> ttrpc::r#async::TtrpcContext {
        ttrpc::r#async::TtrpcContext {
            mh: ttrpc::proto::MessageHeader::new_request(1, 0),
            metadata: std::collections::HashMap::new(),
            timeout_nano: 0,
        }
    }
}
