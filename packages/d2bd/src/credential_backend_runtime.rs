//! Guest-local credential backend responder composition.
//!
//! The Host daemon never creates or retains a backend peer. Guest mode
//! composes this responder beside the Guest-local Process supervisor, while
//! the Provider child receives only an inherited endpoint and one-use
//! delivery-key handoff.

use std::{future::Future, pin::Pin, sync::Arc};

use d2b_contracts_resource::v3::ResourceRef;
use d2b_provider_toolkit::{
    CredentialDeliveryKeyHandoff, CredentialDeliveryKeyMaterial, GuestCredentialBackendHandler,
    GuestCredentialBackendHandlerError, GuestCredentialBackendHandlerFuture,
    GuestCredentialBackendReply, GuestCredentialBackendResponderLease,
    spawn_guest_credential_backend_responder,
};
use d2b_session::{AuthenticatedSessionRouteBinding, x25519_public_key};

use crate::process_provider_runtime::{
    GuestCredentialBackendLease, GuestCredentialBackendPreparation,
    GuestCredentialBackendSupervisor, ProcessResourceContext,
};

const SECRET_SERVICE_PROVIDER: &str = "credential-secret-service";
const ENTRA_PROVIDER: &str = "credential-entra";
const MANAGED_IDENTITY_PROVIDER: &str = "credential-managed-identity";

/// A typed operation dispatched by the Guest-local credential source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackendOperation {
    State,
    IssueLease,
    InspectLease,
    RefreshLease,
    RevokeLease,
}

impl BackendOperation {
    fn parse(provider: &str, operation: &str) -> Option<Self> {
        let (prefix, method) = operation.rsplit_once('.')?;
        if prefix != provider.strip_prefix("credential-").unwrap_or(provider) {
            return None;
        }
        match method {
            "state" => Some(Self::State),
            "issue-lease" => Some(Self::IssueLease),
            "inspect-lease" => Some(Self::InspectLease),
            "refresh-lease" => Some(Self::RefreshLease),
            "revoke-lease" => Some(Self::RevokeLease),
            _ => None,
        }
    }
}

/// Typed Guest-local backend request passed to the source implementation.
#[derive(Clone)]
pub(crate) struct GuestCredentialBackendRequest {
    pub(crate) provider_ref: ResourceRef,
    pub(crate) process_ref: ResourceRef,
    pub(crate) execution_ref: ResourceRef,
    pub(crate) operation: BackendOperation,
    pub(crate) fields: serde_json::Value,
}

impl std::fmt::Debug for GuestCredentialBackendRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GuestCredentialBackendRequest")
            .field("provider_ref", &"<redacted>")
            .field("process_ref", &"<redacted>")
            .field("execution_ref", &"<redacted>")
            .field("operation", &self.operation)
            .field("fields", &"<redacted>")
            .finish()
    }
}

/// Source-side failure. The responder maps it to a bounded unavailable RPC
/// and the Provider preserves the resulting uncertain operation state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GuestCredentialBackendSourceError {
    Unavailable,
    Denied,
    Malformed,
}

pub(crate) type GuestCredentialBackendSourceFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<GuestCredentialBackendReply, GuestCredentialBackendSourceError>>
            + Send
            + 'a,
    >,
>;

/// Guest-owned source of Secret Service, Entra Endpoint, and IMDS operations.
///
/// A consumer can provide the actual Guest-local Endpoint/IMDS/Secret
/// Service adapter. d2b's default source is fail-closed: it validates the
/// typed request and reports the attempted backend operation unavailable
/// rather than manufacturing a token or lease.
pub(crate) trait GuestCredentialBackendSource: Send + Sync + 'static {
    fn execute(
        &self,
        request: GuestCredentialBackendRequest,
    ) -> GuestCredentialBackendSourceFuture<'_>;
}

/// Fail-closed production source used until the Guest supplies its
/// provider-specific local Endpoint implementation.
#[derive(Debug, Default)]
pub(crate) struct GuestLocalCredentialBackend;

impl GuestCredentialBackendSource for GuestLocalCredentialBackend {
    fn execute(
        &self,
        request: GuestCredentialBackendRequest,
    ) -> GuestCredentialBackendSourceFuture<'_> {
        Box::pin(async move {
            let _ = (
                request.provider_ref,
                request.process_ref,
                request.execution_ref,
                request.operation,
                request.fields,
            );
            Err(GuestCredentialBackendSourceError::Unavailable)
        })
    }
}

struct SourceHandler {
    source: Arc<dyn GuestCredentialBackendSource>,
}

impl GuestCredentialBackendHandler for SourceHandler {
    fn handle(
        &self,
        route: &AuthenticatedSessionRouteBinding,
        operation: &str,
        fields: serde_json::Value,
    ) -> GuestCredentialBackendHandlerFuture<'_> {
        let source = Arc::clone(&self.source);
        let route = route.clone();
        let operation = operation.to_owned();
        Box::pin(async move {
            let provider_ref = route
                .provider_ref()
                .cloned()
                .ok_or(GuestCredentialBackendHandlerError::Denied)?;
            let provider_name = provider_ref.name().as_str();
            let Some(operation_kind) = BackendOperation::parse(provider_name, &operation) else {
                return Err(GuestCredentialBackendHandlerError::Denied);
            };
            let process_ref = route
                .context()
                .process_ref()
                .cloned()
                .ok_or(GuestCredentialBackendHandlerError::Denied)?;
            let execution_ref = route
                .context()
                .execution_ref()
                .cloned()
                .filter(|reference| reference.resource_type().as_str() == "Guest")
                .ok_or(GuestCredentialBackendHandlerError::Denied)?;
            validate_fields(provider_name, operation_kind, &route, &fields).map_err(|error| {
                match error {
                    GuestCredentialBackendSourceError::Denied => {
                        GuestCredentialBackendHandlerError::Denied
                    }
                    GuestCredentialBackendSourceError::Malformed => {
                        GuestCredentialBackendHandlerError::Malformed
                    }
                    GuestCredentialBackendSourceError::Unavailable => {
                        GuestCredentialBackendHandlerError::Unavailable
                    }
                }
            })?;
            source
                .execute(GuestCredentialBackendRequest {
                    provider_ref,
                    process_ref,
                    execution_ref,
                    operation: operation_kind,
                    fields,
                })
                .await
                .map_err(|error| match error {
                    GuestCredentialBackendSourceError::Unavailable => {
                        GuestCredentialBackendHandlerError::Unavailable
                    }
                    GuestCredentialBackendSourceError::Denied => {
                        GuestCredentialBackendHandlerError::Denied
                    }
                    GuestCredentialBackendSourceError::Malformed => {
                        GuestCredentialBackendHandlerError::Malformed
                    }
                })
        })
    }
}

fn validate_fields(
    provider: &str,
    operation: BackendOperation,
    route: &AuthenticatedSessionRouteBinding,
    fields: &serde_json::Value,
) -> Result<(), GuestCredentialBackendSourceError> {
    let object = fields
        .as_object()
        .ok_or(GuestCredentialBackendSourceError::Malformed)?;
    match provider {
        SECRET_SERVICE_PROVIDER => {
            if object
                .get("userRef")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| ResourceRef::parse(value).ok())
                != Some(route.subject_ref().clone())
            {
                return Err(GuestCredentialBackendSourceError::Denied);
            }
        }
        ENTRA_PROVIDER => {
            if object
                .get("identityGuestRef")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| ResourceRef::parse(value).ok())
                != route.context().execution_ref().cloned()
            {
                return Err(GuestCredentialBackendSourceError::Denied);
            }
            if object.get("loginEndpointRef").is_some_and(|value| {
                value
                    .as_str()
                    .and_then(|value| ResourceRef::parse(value).ok())
                    .is_none_or(|reference| reference.resource_type().as_str() != "Endpoint")
            }) {
                return Err(GuestCredentialBackendSourceError::Malformed);
            }
        }
        MANAGED_IDENTITY_PROVIDER => {
            if object
                .get("imdsEndpointAlias")
                .and_then(serde_json::Value::as_str)
                .is_none_or(|alias| !matches!(alias, "azure-imds" | "azure-imds-aca"))
            {
                return Err(GuestCredentialBackendSourceError::Denied);
            }
        }
        _ => return Err(GuestCredentialBackendSourceError::Denied),
    }
    if operation == BackendOperation::State {
        return Ok(());
    }
    let credential_ref = object
        .get("credentialRef")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| ResourceRef::parse(value).ok())
        .ok_or(GuestCredentialBackendSourceError::Malformed)?;
    if credential_ref.resource_type().as_str() != "Credential" {
        return Err(GuestCredentialBackendSourceError::Denied);
    }
    match operation {
        BackendOperation::IssueLease => {
            for key in ["operationId", "idempotencyKey", "requestedExpiryUnixMs"] {
                if !object.contains_key(key) {
                    return Err(GuestCredentialBackendSourceError::Malformed);
                }
            }
        }
        BackendOperation::InspectLease
        | BackendOperation::RefreshLease
        | BackendOperation::RevokeLease => {
            if object
                .get("leaseHandle")
                .and_then(serde_json::Value::as_str)
                .is_none()
            {
                return Err(GuestCredentialBackendSourceError::Malformed);
            }
        }
        BackendOperation::State => {}
    }
    Ok(())
}

struct ProductionGuestCredentialBackendLease {
    expected_zone: d2b_contracts_resource::v3::ZoneId,
    expected_provider: ResourceRef,
    expected_process: ResourceRef,
    expected_execution: ResourceRef,
    expected_provider_generation: d2b_contracts_resource::v3::ResourceGeneration,
    expected_controller_generation: d2b_contracts_resource::v3::ControllerGeneration,
    responder: Arc<GuestCredentialBackendResponderLease>,
}

impl GuestCredentialBackendLease for ProductionGuestCredentialBackendLease {
    fn bind_route(&self, route: &AuthenticatedSessionRouteBinding) -> Result<(), String> {
        let route_provider = route
            .provider_ref()
            .ok_or_else(|| "provider-backend-route-missing".to_owned())?;
        let route_process = route
            .context()
            .process_ref()
            .ok_or_else(|| "provider-backend-process-missing".to_owned())?;
        let route_execution = route
            .context()
            .execution_ref()
            .ok_or_else(|| "provider-backend-execution-missing".to_owned())?;
        if route.zone() != &self.expected_zone
            || route_provider != &self.expected_provider
            || route_process != &self.expected_process
            || route_execution != &self.expected_execution
            || route.provider_generation() != Some(self.expected_provider_generation)
            || route.controller_generation() != Some(self.expected_controller_generation)
            || route_execution.resource_type().as_str() != "Guest"
            || !route.liveness().is_live()
        {
            return Err("provider-backend-route-mismatch".to_owned());
        }
        self.responder
            .bind_route(route.clone())
            .map_err(|_| "provider-backend-route-bind-failed".to_owned())
    }

    fn cancel(&self) {
        self.responder.cancel();
    }
}

impl Drop for ProductionGuestCredentialBackendLease {
    fn drop(&mut self) {
        self.responder.cancel();
    }
}

/// Guest-mode implementation of the Process Provider backend supervisor.
pub(crate) struct ProductionGuestCredentialBackendSupervisor {
    handler: Arc<dyn GuestCredentialBackendHandler>,
}

impl ProductionGuestCredentialBackendSupervisor {
    pub(crate) fn new(source: Arc<dyn GuestCredentialBackendSource>) -> Arc<Self> {
        Arc::new(Self {
            handler: Arc::new(SourceHandler { source }),
        })
    }

    /// Compose the production fail-closed source. Actual Guest integrations
    /// may replace the source without changing Process/fd/session wiring.
    pub(crate) fn fail_closed() -> Arc<Self> {
        Self::new(Arc::new(GuestLocalCredentialBackend))
    }
}

impl GuestCredentialBackendSupervisor for ProductionGuestCredentialBackendSupervisor {
    fn prepare(
        &self,
        context: &ProcessResourceContext<'_>,
    ) -> Result<GuestCredentialBackendPreparation, String> {
        if context.guest_execution.is_none()
            || context
                .execution_ref
                .as_ref()
                .is_none_or(|reference| reference.resource_type().as_str() != "Guest")
        {
            return Err("provider-backend-guest-context-required".to_owned());
        }
        let provider_ref = context
            .controller_provider_ref
            .as_ref()
            .or_else(|| context.owner_ref.as_ref())
            .filter(|reference| {
                reference.resource_type().as_str() == "Provider"
                    && matches!(
                        reference.name().as_str(),
                        SECRET_SERVICE_PROVIDER | ENTRA_PROVIDER | MANAGED_IDENTITY_PROVIDER
                    )
            })
            .cloned()
            .ok_or_else(|| "provider-backend-provider-missing".to_owned())?;
        let execution_ref = context
            .execution_ref
            .clone()
            .ok_or_else(|| "provider-backend-execution-missing".to_owned())?;
        let process_ref = context.resource_ref.clone();
        let provider_generation = context
            .provider_generation
            .ok_or_else(|| "provider-backend-provider-generation-missing".to_owned())?;
        let mut provider_private = [0_u8; 32];
        let mut backend_private = [0_u8; 32];
        getrandom::getrandom(&mut provider_private)
            .map_err(|_| "provider-backend-key-unavailable".to_owned())?;
        getrandom::getrandom(&mut backend_private)
            .map_err(|_| "provider-backend-key-unavailable".to_owned())?;
        if provider_private == [0; 32] || backend_private == [0; 32] {
            return Err("provider-backend-key-invalid".to_owned());
        }
        let backend_public = x25519_public_key(&backend_private)
            .map_err(|_| "provider-backend-key-invalid".to_owned())?;
        let delivery_key_handoff =
            CredentialDeliveryKeyHandoff::new(provider_private, backend_public)
                .map_err(|_| "provider-backend-key-invalid".to_owned())?;
        let backend_keys = CredentialDeliveryKeyMaterial::new(
            backend_private,
            *delivery_key_handoff.provider_public(),
        )
        .map_err(|_| "provider-backend-key-invalid".to_owned())?;
        let (child_endpoint, responder_endpoint) = d2b_session_unix::prearmed_seqpacket_pair()
            .map_err(|_| "provider-backend-socket-unavailable".to_owned())?;
        let responder = spawn_guest_credential_backend_responder(
            d2b_session_unix::SeqpacketSocket::from_parent_prearmed(responder_endpoint)
                .map_err(|_| "provider-backend-socket-unavailable".to_owned())?,
            backend_keys,
            Arc::clone(&self.handler),
        )
        .map_err(|_| "provider-backend-responder-unavailable".to_owned())?;
        let lease = Arc::new(ProductionGuestCredentialBackendLease {
            expected_zone: context.zone.clone(),
            expected_provider: provider_ref,
            expected_process: process_ref,
            expected_execution: execution_ref,
            expected_provider_generation: provider_generation,
            expected_controller_generation: context.controller_generation,
            responder,
        });
        Ok(GuestCredentialBackendPreparation {
            child_endpoint,
            delivery_key_handoff,
            lease,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use d2b_contracts_resource::v3::{
        ControllerGeneration, ResourceGeneration, ResourceUid, SchemaFingerprint, ZoneId,
        ZoneRevision,
        identity::{
            AuthenticatedSubjectContext, BindingDigest, EvidenceClass, Locality,
            ReconnectGeneration, ServiceName, SessionBinding, SessionPurpose, TranscriptHash,
            TransportBinding,
        },
    };
    use d2b_contracts_zone_session::v3::component_session::{
        EndpointRole, Locality as ComponentLocality, PurposeClass, TransportClass,
    };
    use d2b_process_conformance::{ConfigurationDigest, GuestExecutionBinding};
    use d2b_provider_toolkit::{GuestCredentialBackend, GuestCredentialBackendReply};

    struct TestSource;

    impl GuestCredentialBackendSource for TestSource {
        fn execute(
            &self,
            request: GuestCredentialBackendRequest,
        ) -> GuestCredentialBackendSourceFuture<'_> {
            Box::pin(async move {
                let response = match request.operation {
                    BackendOperation::IssueLease => GuestCredentialBackendReply::new(
                        Some("ready".to_owned()),
                        Some("guest-lease".to_owned()),
                        Some("guest-source".to_owned()),
                        Some(1),
                        Some(2_000),
                        None,
                        None,
                    ),
                    BackendOperation::InspectLease => GuestCredentialBackendReply::new(
                        Some("active".to_owned()),
                        Some("guest-lease".to_owned()),
                        Some("guest-source".to_owned()),
                        Some(1),
                        Some(2_000),
                        None,
                        None,
                    ),
                    BackendOperation::RefreshLease => GuestCredentialBackendReply::new(
                        Some("ready".to_owned()),
                        Some("guest-lease".to_owned()),
                        Some("guest-source".to_owned()),
                        Some(2),
                        Some(3_000),
                        None,
                        None,
                    ),
                    BackendOperation::RevokeLease => GuestCredentialBackendReply::new(
                        Some("revoked".to_owned()),
                        Some("guest-lease".to_owned()),
                        Some("guest-source".to_owned()),
                        Some(2),
                        Some(3_000),
                        Some("revoked".to_owned()),
                        None,
                    ),
                    BackendOperation::State => GuestCredentialBackendReply::new(
                        Some("ready".to_owned()),
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                    ),
                };
                Ok(response)
            })
        }
    }

    fn route() -> AuthenticatedSessionRouteBinding {
        let provider_ref =
            ResourceRef::parse("Provider/credential-managed-identity").expect("provider");
        let context = AuthenticatedSubjectContext::new(
            provider_ref.clone(),
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").expect("subject UID"),
            ResourceRef::parse("Zone/dev").expect("Zone"),
            EvidenceClass::UnixPeer,
            SessionPurpose::parse("provider-control").expect("purpose"),
            ServiceName::parse("d2b.credential.v3").expect("service"),
            SessionBinding::new(
                SchemaFingerprint::parse(
                    "sha256:3333333333333333333333333333333333333333333333333333333333333333",
                )
                .expect("schema"),
                TransportBinding::new(
                    Locality::Local,
                    BindingDigest::parse(
                        "sha256:3434343434343434343434343434343434343434343434343434343434343434",
                    )
                    .expect("binding"),
                ),
                ReconnectGeneration::new(1).expect("generation"),
                TranscriptHash::from_bytes([5; 32]),
            ),
        )
        .with_execution_ref(ResourceRef::parse("Guest/test").expect("execution"))
        .with_process_ref(ResourceRef::parse("Process/credential-controller").expect("process"))
        .with_provider_ref(provider_ref)
        .with_provider_generation(ResourceGeneration::new(1).expect("provider generation"))
        .with_controller_generation(ControllerGeneration::new(1).expect("controller generation"));
        AuthenticatedSessionRouteBinding::from_authenticated_peer(
            context,
            ComponentLocality::GuestLocal,
            PurposeClass::Enrolled,
            EndpointRole::Provider,
            EndpointRole::GuestAgent,
            TransportClass::InheritedSocketpair,
        )
        .expect("route")
    }

    #[tokio::test(flavor = "current_thread")]
    async fn supervisor_serves_bound_guest_backend_and_cancels_it() {
        let zone = ZoneId::parse("dev").expect("zone");
        let process_ref = ResourceRef::parse("Process/credential-controller").expect("process");
        let process_uid =
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").expect("process UID");
        let process_provider =
            ResourceRef::parse("Provider/system-minijail").expect("process provider");
        let provider_ref =
            ResourceRef::parse("Provider/credential-managed-identity").expect("owner provider");
        let provider_uid =
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174001").expect("provider UID");
        let zone_uid =
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174002").expect("zone UID");
        let execution_ref = ResourceRef::parse("Guest/test").expect("execution");
        let guest_binding = GuestExecutionBinding::new(
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174003").expect("guest UID"),
            ConfigurationDigest::from_bytes([7; 32]),
            ReconnectGeneration::new(1).expect("session"),
            1,
            ResourceGeneration::new(1).expect("provider"),
            ControllerGeneration::new(1).expect("controller"),
        )
        .expect("guest binding");
        let context = ProcessResourceContext::new(
            zone,
            &process_ref,
            &process_uid,
            ResourceGeneration::new(1).expect("resource generation"),
            ZoneRevision::new(1),
            &process_provider,
            ControllerGeneration::new(1).expect("controller generation"),
            None,
        )
        .with_guest_execution(Some(&guest_binding))
        .with_lifecycle_identity(
            Some(zone_uid),
            Some(1),
            Some(ResourceGeneration::new(1).expect("assignment")),
        )
        .with_owner_ref(Some(provider_ref.clone()))
        .with_provider_identity(
            Some(&provider_uid),
            Some(ResourceGeneration::new(1).expect("provider generation")),
        )
        .with_controller_provider_ref(Some(provider_ref))
        .with_execution_ref(&execution_ref);
        let supervisor = ProductionGuestCredentialBackendSupervisor::new(Arc::new(TestSource));
        let preparation = supervisor.prepare(&context).expect("backend preparation");
        let second_preparation = supervisor.prepare(&context).expect("second preparation");
        let client_socket =
            d2b_session_unix::SeqpacketSocket::from_parent_prearmed(preparation.child_endpoint)
                .expect("child backend socket");
        let route = route();
        assert_ne!(
            preparation.delivery_key_handoff.provider_public(),
            second_preparation.delivery_key_handoff.provider_public()
        );
        second_preparation.lease.cancel();
        preparation
            .lease
            .bind_route(&route)
            .expect("backend route binding");
        let backend = GuestCredentialBackend::from_socket_for_test_with_route(
            client_socket,
            route,
            preparation.delivery_key_handoff.into_material(),
        )
        .expect("provider backend client");
        let response = backend
            .request(
                "managed-identity.issue-lease",
                serde_json::json!({
                    "credentialRef": "Credential/test",
                    "operationId": "operation-1",
                    "idempotencyKey": "idempotency-1",
                    "requestedExpiryUnixMs": 2_000,
                    "imdsEndpointAlias": "azure-imds",
                }),
            )
            .await
            .expect("issue response");
        assert_eq!(response.state(), Some("ready"));
        assert!(response.into_bytes().is_none());
        let response = backend
            .request(
                "managed-identity.inspect-lease",
                serde_json::json!({
                    "credentialRef": "Credential/test",
                    "leaseHandle": "guest-lease",
                    "imdsEndpointAlias": "azure-imds",
                }),
            )
            .await
            .expect("inspect response");
        assert_eq!(response.state(), Some("active"));
        let response = backend
            .request(
                "managed-identity.revoke-lease",
                serde_json::json!({
                    "credentialRef": "Credential/test",
                    "leaseHandle": "guest-lease",
                    "imdsEndpointAlias": "azure-imds",
                }),
            )
            .await
            .expect("revoke response");
        assert_eq!(response.outcome(), Some("revoked"));
        preparation.lease.cancel();
    }
}
