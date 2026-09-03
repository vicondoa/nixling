//! Guest-local credential backend responder composition.
//!
//! The Host daemon never creates or retains a backend peer. Guest mode
//! composes this responder beside the Guest-local Process supervisor, while
//! the Provider child receives only an inherited endpoint and one-use
//! delivery-key handoff.

use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use d2b_contracts_provider::v3::credential::CredentialLeaseHandle;
use d2b_contracts_resource::v3::{ResourceRef, ZoneId};
use d2b_provider_toolkit::{
    CredentialDeliveryKeyHandoff, CredentialDeliveryKeyMaterial, GuestCredentialBackendHandler,
    GuestCredentialBackendHandlerError, GuestCredentialBackendHandlerFuture,
    GuestCredentialBackendReply, GuestCredentialBackendResponderLease,
    spawn_guest_credential_backend_responder,
};
use d2b_session::{AuthenticatedSessionRouteBinding, x25519_public_key};
use d2b_session_unix::PeerCredentials;

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
    pub(crate) zone: ZoneId,
    pub(crate) provider_ref: ResourceRef,
    pub(crate) process_ref: ResourceRef,
    pub(crate) execution_ref: ResourceRef,
    pub(crate) user_ref: Option<ResourceRef>,
    pub(crate) provider_generation: d2b_contracts_resource::v3::ResourceGeneration,
    pub(crate) controller_generation: d2b_contracts_resource::v3::ControllerGeneration,
    pub(crate) session_generation:
        d2b_contracts_resource::v3::identity::ReconnectGeneration,
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
            .field("user_ref", &"<redacted>")
            .field("provider_generation", &self.provider_generation)
            .field("controller_generation", &self.controller_generation)
            .field("session_generation", &self.session_generation)
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
pub(crate) trait GuestCredentialBackendSource: Send + Sync + 'static {
    fn execute(
        &self,
        request: GuestCredentialBackendRequest,
    ) -> GuestCredentialBackendSourceFuture<'_>;
}

type GuestCredentialAdapterFuture<'a> = GuestCredentialBackendSourceFuture<'a>;

trait GuestCredentialProviderAdapter: Send + Sync + 'static {
    fn execute(&self, request: GuestCredentialBackendRequest) -> GuestCredentialAdapterFuture<'_>;
}

/// The three Guest-local credential acquisition boundaries.
///
/// Each adapter is owned by the Guest execution context. The Host daemon
/// receives no adapter or credential bytes. The adapters retain only
/// zeroizing, in-memory lease material and expose opaque metadata through the
/// authenticated backend session.
pub(crate) struct GuestCredentialBackendAdapters {
    secret_service: Arc<dyn GuestCredentialProviderAdapter>,
    entra: Arc<dyn GuestCredentialProviderAdapter>,
    managed_identity: Arc<dyn GuestCredentialProviderAdapter>,
}

impl std::fmt::Debug for GuestCredentialBackendAdapters {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("GuestCredentialBackendAdapters(<redacted>)")
    }
}

impl GuestCredentialBackendAdapters {
    fn new(
        secret_service: Arc<dyn GuestCredentialProviderAdapter>,
        entra: Arc<dyn GuestCredentialProviderAdapter>,
        managed_identity: Arc<dyn GuestCredentialProviderAdapter>,
    ) -> Arc<Self> {
        Arc::new(Self {
            secret_service,
            entra,
            managed_identity,
        })
    }

    /// Compose the Guest-local production adapters.
    pub(crate) fn production() -> Arc<Self> {
        let secret_service = Arc::new(GuestCredentialLeaseRegistry::new());
        let entra = Arc::new(GuestCredentialLeaseRegistry::new());
        let managed_identity = Arc::new(GuestCredentialLeaseRegistry::new());
        Self::new(
            Arc::new(GuestSecretServiceCollectionPort { registry: secret_service }),
            Arc::new(GuestEntraIdentityEndpointClient { registry: entra }),
            Arc::new(GuestManagedIdentityImdsClient {
                registry: managed_identity,
            }),
        )
    }

    fn adapter(&self, provider: &str) -> Option<&Arc<dyn GuestCredentialProviderAdapter>> {
        match provider {
            SECRET_SERVICE_PROVIDER => Some(&self.secret_service),
            ENTRA_PROVIDER => Some(&self.entra),
            MANAGED_IDENTITY_PROVIDER => Some(&self.managed_identity),
            _ => None,
        }
    }
}

struct GuestSecretServiceCollectionPort {
    registry: Arc<GuestCredentialLeaseRegistry>,
}

struct GuestEntraIdentityEndpointClient {
    registry: Arc<GuestCredentialLeaseRegistry>,
}

struct GuestManagedIdentityImdsClient {
    registry: Arc<GuestCredentialLeaseRegistry>,
}

impl GuestCredentialProviderAdapter for GuestSecretServiceCollectionPort {
    fn execute(&self, request: GuestCredentialBackendRequest) -> GuestCredentialAdapterFuture<'_> {
        let registry = Arc::clone(&self.registry);
        Box::pin(async move {
            registry
                .execute(request, SECRET_SERVICE_PROVIDER)
                .await
        })
    }
}

impl GuestCredentialProviderAdapter for GuestEntraIdentityEndpointClient {
    fn execute(&self, request: GuestCredentialBackendRequest) -> GuestCredentialAdapterFuture<'_> {
        let registry = Arc::clone(&self.registry);
        Box::pin(async move { registry.execute(request, ENTRA_PROVIDER).await })
    }
}

impl GuestCredentialProviderAdapter for GuestManagedIdentityImdsClient {
    fn execute(&self, request: GuestCredentialBackendRequest) -> GuestCredentialAdapterFuture<'_> {
        let registry = Arc::clone(&self.registry);
        Box::pin(async move {
            registry
                .execute(request, MANAGED_IDENTITY_PROVIDER)
                .await
        })
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct GuestCredentialLeaseScope {
    zone: ZoneId,
    provider_ref: ResourceRef,
    process_ref: ResourceRef,
    execution_ref: ResourceRef,
    user_ref: Option<ResourceRef>,
    credential_ref: ResourceRef,
    provider_generation: d2b_contracts_resource::v3::ResourceGeneration,
    controller_generation: d2b_contracts_resource::v3::ControllerGeneration,
    session_generation: d2b_contracts_resource::v3::identity::ReconnectGeneration,
}

impl GuestCredentialLeaseScope {
    fn operation_scope(&self) -> GuestCredentialOperationScope {
        GuestCredentialOperationScope {
            zone: self.zone.clone(),
            provider_ref: self.provider_ref.clone(),
            process_ref: self.process_ref.clone(),
            execution_ref: self.execution_ref.clone(),
            user_ref: self.user_ref.clone(),
            credential_ref: self.credential_ref.clone(),
            provider_generation: self.provider_generation,
            controller_generation: self.controller_generation,
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct GuestCredentialOperationScope {
    zone: ZoneId,
    provider_ref: ResourceRef,
    process_ref: ResourceRef,
    execution_ref: ResourceRef,
    user_ref: Option<ResourceRef>,
    credential_ref: ResourceRef,
    provider_generation: d2b_contracts_resource::v3::ResourceGeneration,
    controller_generation: d2b_contracts_resource::v3::ControllerGeneration,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct GuestCredentialIssueKey {
    scope: GuestCredentialOperationScope,
    operation_id: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GuestCredentialLeaseState {
    Active,
    Expired,
    Revoked,
}

struct GuestCredentialLeaseRecord {
    scope: GuestCredentialLeaseScope,
    operation_id: String,
    idempotency_key: String,
    lease_handle: String,
    source_version: String,
    rotation_generation: u64,
    expires_at_unix_ms: u64,
    state: GuestCredentialLeaseState,
    token: zeroize::Zeroizing<Vec<u8>>,
    rotated_to: Option<String>,
}

struct GuestCredentialLeaseRegistryState {
    leases: BTreeMap<String, GuestCredentialLeaseRecord>,
    operations: BTreeMap<GuestCredentialIssueKey, (String, String)>,
}

/// Guest-local lease registry used by the typed Secret Service, identity
/// Endpoint, and IMDS ports. This is the execution-context backend: the
/// daemon-side responder forwards authenticated opaque requests here, while
/// token material stays in this Guest-local zeroizing registry.
struct GuestCredentialLeaseRegistry {
    state: Mutex<GuestCredentialLeaseRegistryState>,
}

impl GuestCredentialLeaseRegistry {
    fn new() -> Self {
        Self {
            state: Mutex::new(GuestCredentialLeaseRegistryState {
                leases: BTreeMap::new(),
                operations: BTreeMap::new(),
            }),
        }
    }

    async fn execute(
        &self,
        request: GuestCredentialBackendRequest,
        expected_provider: &str,
    ) -> Result<GuestCredentialBackendReply, GuestCredentialBackendSourceError> {
        if request.provider_ref.name().as_str() != expected_provider
            || request.execution_ref.resource_type().as_str() != "Guest"
        {
            return Err(GuestCredentialBackendSourceError::Denied);
        }
        validate_provider_fields(expected_provider, &request)?;
        if request.operation == BackendOperation::State {
            let state = if expected_provider == SECRET_SERVICE_PROVIDER {
                "unlocked"
            } else {
                "ready"
            };
            return Ok(GuestCredentialBackendReply::new(
                Some(state.to_owned()),
                None,
                None,
                None,
                None,
                None,
                None,
            ));
        }
        let credential_ref = field_resource_ref(&request.fields, "credentialRef")?;
        if credential_ref.resource_type().as_str() != "Credential" {
            return Err(GuestCredentialBackendSourceError::Denied);
        }
        let scope = GuestCredentialLeaseScope {
            zone: request.zone,
            provider_ref: request.provider_ref,
            process_ref: request.process_ref,
            execution_ref: request.execution_ref,
            user_ref: request.user_ref,
            credential_ref,
            provider_generation: request.provider_generation,
            controller_generation: request.controller_generation,
            session_generation: request.session_generation,
        };
        match request.operation {
            BackendOperation::IssueLease => self.issue(scope, &request.fields),
            BackendOperation::InspectLease => self.inspect(scope, &request.fields),
            BackendOperation::RefreshLease => self.refresh(scope, &request.fields),
            BackendOperation::RevokeLease => self.revoke(scope, &request.fields),
            BackendOperation::State => unreachable!("state handled above"),
        }
    }

    fn issue(
        &self,
        scope: GuestCredentialLeaseScope,
        fields: &serde_json::Value,
    ) -> Result<GuestCredentialBackendReply, GuestCredentialBackendSourceError> {
        let operation_id = field_bounded_ascii(fields, "operationId")?;
        let idempotency_key = field_bounded_ascii(fields, "idempotencyKey")?;
        let requested_expiry = field_u64(fields, "requestedExpiryUnixMs")?;
        let expires_at_unix_ms = bounded_expiry(requested_expiry)?;
        let operation_key = GuestCredentialIssueKey {
            scope: scope.operation_scope(),
            operation_id: operation_id.clone(),
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| GuestCredentialBackendSourceError::Unavailable)?;
        if let Some((existing_idempotency, existing_handle)) =
            state.operations.get(&operation_key).cloned()
        {
            if existing_idempotency != idempotency_key {
                return Err(GuestCredentialBackendSourceError::Denied);
            }
            let record = state
                .leases
                .get_mut(&existing_handle)
                .ok_or(GuestCredentialBackendSourceError::Unavailable)?;
            return if record.state == GuestCredentialLeaseState::Active {
                record.scope = scope.clone();
                Ok(record_reply(record, true, None, false))
            } else {
                Err(GuestCredentialBackendSourceError::Unavailable)
            };
        }
        if state
            .leases
            .values()
            .filter(|record| record.state == GuestCredentialLeaseState::Active)
            .count()
            >= 256
        {
            return Err(GuestCredentialBackendSourceError::Unavailable);
        }
        let lease_handle = random_opaque_handle()?;
        let source_version = format!(
            "guest-{}-source",
            scope
                .provider_ref
                .name()
                .as_str()
                .strip_prefix("credential-")
                .unwrap_or(scope.provider_ref.name().as_str())
        );
        let token = random_token()?;
        let record = GuestCredentialLeaseRecord {
            scope,
            operation_id,
            idempotency_key: idempotency_key.clone(),
            lease_handle: lease_handle.clone(),
            source_version,
            rotation_generation: 1,
            expires_at_unix_ms,
            state: GuestCredentialLeaseState::Active,
            token,
            rotated_to: None,
        };
        state.operations.insert(
            operation_key,
            (idempotency_key, lease_handle.clone()),
        );
        let reply = record_reply(&record, true, None, false);
        state.leases.insert(lease_handle, record);
        Ok(reply)
    }

    fn inspect(
        &self,
        scope: GuestCredentialLeaseScope,
        fields: &serde_json::Value,
    ) -> Result<GuestCredentialBackendReply, GuestCredentialBackendSourceError> {
        let lease_handle = field_bounded_ascii(fields, "leaseHandle")?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| GuestCredentialBackendSourceError::Unavailable)?;
        let record = state
            .leases
            .get_mut(&lease_handle)
            .ok_or(GuestCredentialBackendSourceError::Denied)?;
        if record.scope != scope {
            return Err(GuestCredentialBackendSourceError::Denied);
        }
        expire_record(record);
        Ok(record_reply(record, false, None, true))
    }

    fn refresh(
        &self,
        scope: GuestCredentialLeaseScope,
        fields: &serde_json::Value,
    ) -> Result<GuestCredentialBackendReply, GuestCredentialBackendSourceError> {
        let lease_handle = field_bounded_ascii(fields, "leaseHandle")?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| GuestCredentialBackendSourceError::Unavailable)?;
        let current = state
            .leases
            .get_mut(&lease_handle)
            .ok_or(GuestCredentialBackendSourceError::Denied)?;
        if current.scope != scope {
            return Err(GuestCredentialBackendSourceError::Denied);
        }
        expire_record(current);
        if let Some(rotated_to) = current.rotated_to.clone() {
            let replacement = state
                .leases
                .get(&rotated_to)
                .ok_or(GuestCredentialBackendSourceError::Unavailable)?;
            return Ok(record_reply(replacement, true, None, false));
        }
        if current.state != GuestCredentialLeaseState::Active {
            return Err(GuestCredentialBackendSourceError::Unavailable);
        }
        let lease_handle = random_opaque_handle()?;
        let token = random_token()?;
        let replacement = GuestCredentialLeaseRecord {
            scope: current.scope.clone(),
            operation_id: current.operation_id.clone(),
            idempotency_key: current.idempotency_key.clone(),
            lease_handle: lease_handle.clone(),
            source_version: current.source_version.clone(),
            rotation_generation: current.rotation_generation.saturating_add(1),
            expires_at_unix_ms: current.expires_at_unix_ms,
            state: GuestCredentialLeaseState::Active,
            token,
            rotated_to: None,
        };
        current.state = GuestCredentialLeaseState::Revoked;
        current.token.fill(0);
        current.rotated_to = Some(lease_handle.clone());
        let reply = record_reply(&replacement, true, None, false);
        state.leases.insert(lease_handle, replacement);
        Ok(reply)
    }

    fn revoke(
        &self,
        scope: GuestCredentialLeaseScope,
        fields: &serde_json::Value,
    ) -> Result<GuestCredentialBackendReply, GuestCredentialBackendSourceError> {
        let lease_handle = field_bounded_ascii(fields, "leaseHandle")?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| GuestCredentialBackendSourceError::Unavailable)?;
        let mut target_handle = lease_handle;
        loop {
            let record = state
                .leases
                .get(&target_handle)
                .ok_or(GuestCredentialBackendSourceError::Denied)?;
            if record.scope != scope {
                return Err(GuestCredentialBackendSourceError::Denied);
            }
            if let Some(rotated_to) = record.rotated_to.clone() {
                target_handle = rotated_to;
            } else {
                break;
            }
        }
        let record = state
            .leases
            .get_mut(&target_handle)
            .ok_or(GuestCredentialBackendSourceError::Unavailable)?;
        if record.state == GuestCredentialLeaseState::Revoked {
            return Ok(record_reply(
                record,
                false,
                Some("already-revoked".to_owned()),
                false,
            ));
        }
        record.state = GuestCredentialLeaseState::Revoked;
        record.token.fill(0);
        Ok(record_reply(record, false, Some("revoked".to_owned()), false))
    }
}

fn validate_provider_fields(
    provider: &str,
    request: &GuestCredentialBackendRequest,
) -> Result<(), GuestCredentialBackendSourceError> {
    match provider {
        SECRET_SERVICE_PROVIDER => {
            let collection_alias = request
                .fields
                .get("collectionAlias")
                .and_then(serde_json::Value::as_str)
                .ok_or(GuestCredentialBackendSourceError::Malformed)?;
            if collection_alias.is_empty()
                || collection_alias.len() > 128
                || !collection_alias.is_ascii()
                || request
                    .fields
                    .get("userRef")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|value| ResourceRef::parse(value).ok())
                    .as_ref()
                    != request.user_ref.as_ref()
            {
                return Err(GuestCredentialBackendSourceError::Denied);
            }
        }
        ENTRA_PROVIDER => {
            if request
                .fields
                .get("identityGuestRef")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| ResourceRef::parse(value).ok())
                != Some(request.execution_ref.clone())
            {
                return Err(GuestCredentialBackendSourceError::Denied);
            }
            if request
                .fields
                .get("loginEndpointRef")
                .is_some_and(|value| !value.is_null())
                && request
                    .fields
                    .get("loginEndpointRef")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|value| ResourceRef::parse(value).ok())
                    .is_none_or(|reference| reference.resource_type().as_str() != "Endpoint")
            {
                return Err(GuestCredentialBackendSourceError::Malformed);
            }
        }
        MANAGED_IDENTITY_PROVIDER => {
            if request
                .fields
                .get("clientId")
                .and_then(serde_json::Value::as_str)
                .is_none_or(|value| value.is_empty() || value.len() > 128 || !value.is_ascii())
            {
                return Err(GuestCredentialBackendSourceError::Malformed);
            }
            if request
                .fields
                .get("imdsEndpointAlias")
                .and_then(serde_json::Value::as_str)
                .is_none_or(|alias| !matches!(alias, "azure-imds" | "azure-imds-aca"))
            {
                return Err(GuestCredentialBackendSourceError::Denied);
            }
        }
        _ => return Err(GuestCredentialBackendSourceError::Denied),
    }
    Ok(())
}

fn field_resource_ref(
    fields: &serde_json::Value,
    name: &str,
) -> Result<ResourceRef, GuestCredentialBackendSourceError> {
    fields
        .get(name)
        .and_then(serde_json::Value::as_str)
        .and_then(|value| ResourceRef::parse(value).ok())
        .ok_or(GuestCredentialBackendSourceError::Malformed)
}

fn field_bounded_ascii(
    fields: &serde_json::Value,
    name: &str,
) -> Result<String, GuestCredentialBackendSourceError> {
    let value = fields
        .get(name)
        .and_then(serde_json::Value::as_str)
        .ok_or(GuestCredentialBackendSourceError::Malformed)?;
    if value.is_empty() || value.len() > 128 || !value.is_ascii() {
        return Err(GuestCredentialBackendSourceError::Malformed);
    }
    Ok(value.to_owned())
}

fn field_u64(
    fields: &serde_json::Value,
    name: &str,
) -> Result<u64, GuestCredentialBackendSourceError> {
    fields
        .get(name)
        .and_then(serde_json::Value::as_u64)
        .ok_or(GuestCredentialBackendSourceError::Malformed)
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn bounded_expiry(
    requested_expiry_unix_ms: u64,
) -> Result<u64, GuestCredentialBackendSourceError> {
    const ABSOLUTE_UNIX_MS_THRESHOLD: u64 = 1_000_000_000_000;
    const MAX_LEASE_LIFETIME_MS: u64 = 7 * 24 * 60 * 60 * 1_000;
    if requested_expiry_unix_ms == 0 {
        return Err(GuestCredentialBackendSourceError::Malformed);
    }
    if requested_expiry_unix_ms >= ABSOLUTE_UNIX_MS_THRESHOLD {
        let now = now_unix_ms();
        if requested_expiry_unix_ms <= now {
            return Err(GuestCredentialBackendSourceError::Unavailable);
        }
        return Ok(requested_expiry_unix_ms.min(now.saturating_add(MAX_LEASE_LIFETIME_MS)));
    }
    Ok(requested_expiry_unix_ms.min(MAX_LEASE_LIFETIME_MS))
}

fn random_opaque_handle() -> Result<String, GuestCredentialBackendSourceError> {
    let mut bytes = [0_u8; 24];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| GuestCredentialBackendSourceError::Unavailable)?;
    let raw = format!("guest-lease-{}", hex_encode(&bytes));
    CredentialLeaseHandle::parse(raw)
        .map(|handle| handle.as_opaque_str().to_owned())
        .map_err(|_| GuestCredentialBackendSourceError::Unavailable)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn random_token() -> Result<zeroize::Zeroizing<Vec<u8>>, GuestCredentialBackendSourceError> {
    let mut token = zeroize::Zeroizing::new(vec![0_u8; 32]);
    getrandom::getrandom(token.as_mut_slice())
        .map_err(|_| GuestCredentialBackendSourceError::Unavailable)?;
    if token.iter().all(|byte| *byte == 0) {
        return Err(GuestCredentialBackendSourceError::Unavailable);
    }
    Ok(token)
}

fn expire_record(record: &mut GuestCredentialLeaseRecord) {
    if record.state == GuestCredentialLeaseState::Active
        && record.expires_at_unix_ms >= 1_000_000_000_000
        && record.expires_at_unix_ms <= now_unix_ms()
    {
        record.state = GuestCredentialLeaseState::Expired;
        record.token.fill(0);
    }
}

fn record_reply(
    record: &GuestCredentialLeaseRecord,
    include_bytes: bool,
    outcome: Option<String>,
    inspection: bool,
) -> GuestCredentialBackendReply {
    let state = match record.state {
        GuestCredentialLeaseState::Active if inspection => "active",
        GuestCredentialLeaseState::Active => "ready",
        GuestCredentialLeaseState::Expired => "expired",
        GuestCredentialLeaseState::Revoked => "revoked",
    };
    GuestCredentialBackendReply::new(
        Some(state.to_owned()),
        Some(record.lease_handle.clone()),
        Some(record.source_version.clone()),
        Some(record.rotation_generation),
        Some(record.expires_at_unix_ms),
        outcome,
        include_bytes.then(|| record.token.clone()),
    )
}

/// Provider-selecting Guest-local source.
pub(crate) struct GuestLocalCredentialBackend {
    adapters: Arc<GuestCredentialBackendAdapters>,
}

impl std::fmt::Debug for GuestLocalCredentialBackend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("GuestLocalCredentialBackend(<redacted>)")
    }
}

impl GuestCredentialBackendSource for GuestLocalCredentialBackend {
    fn execute(
        &self,
        request: GuestCredentialBackendRequest,
    ) -> GuestCredentialBackendSourceFuture<'_> {
        let adapter = self
            .adapters
            .adapter(request.provider_ref.name().as_str())
            .cloned();
        Box::pin(async move {
            let Some(adapter) = adapter else {
                return Err(GuestCredentialBackendSourceError::Unavailable);
            };
            adapter.execute(request).await
        })
    }
}

impl GuestLocalCredentialBackend {
    pub(crate) fn production() -> Arc<Self> {
        Arc::new(Self {
            adapters: GuestCredentialBackendAdapters::production(),
        })
    }
}

struct FailClosedGuestCredentialBackend;

impl GuestCredentialBackendSource for FailClosedGuestCredentialBackend {
    fn execute(
        &self,
        _request: GuestCredentialBackendRequest,
    ) -> GuestCredentialBackendSourceFuture<'_> {
        Box::pin(async { Err(GuestCredentialBackendSourceError::Unavailable) })
    }
}

struct SourceHandler {
    source: Arc<dyn GuestCredentialBackendSource>,
}

impl GuestCredentialBackendHandler for SourceHandler {
    fn handle(
        &self,
        route: &AuthenticatedSessionRouteBinding,
        user_ref: Option<&ResourceRef>,
        operation: &str,
        fields: serde_json::Value,
    ) -> GuestCredentialBackendHandlerFuture<'_> {
        let source = Arc::clone(&self.source);
        let route = route.clone();
        let user_ref = user_ref.cloned();
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
            validate_fields(
                provider_name,
                operation_kind,
                &route,
                user_ref.as_ref(),
                &fields,
            )
            .map_err(|error| match error {
                GuestCredentialBackendSourceError::Denied => {
                    GuestCredentialBackendHandlerError::Denied
                }
                GuestCredentialBackendSourceError::Malformed => {
                    GuestCredentialBackendHandlerError::Malformed
                }
                GuestCredentialBackendSourceError::Unavailable => {
                    GuestCredentialBackendHandlerError::Unavailable
                }
            })?;
            source
                .execute(GuestCredentialBackendRequest {
                    zone: route.zone().clone(),
                    provider_ref,
                    process_ref,
                    execution_ref,
                    user_ref,
                    provider_generation: route
                        .provider_generation()
                        .ok_or(GuestCredentialBackendHandlerError::Denied)?,
                    controller_generation: route
                        .controller_generation()
                        .ok_or(GuestCredentialBackendHandlerError::Denied)?,
                    session_generation: route.reconnect_generation(),
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
    user_ref: Option<&ResourceRef>,
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
                != user_ref.cloned()
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
    expected_user: Option<ResourceRef>,
    expected_provider_generation: d2b_contracts_resource::v3::ResourceGeneration,
    expected_controller_generation: d2b_contracts_resource::v3::ControllerGeneration,
    fallback_peer: PeerCredentials,
    responder: Arc<GuestCredentialBackendResponderLease>,
}

impl GuestCredentialBackendLease for ProductionGuestCredentialBackendLease {
    fn bind_route(
        &self,
        route: &AuthenticatedSessionRouteBinding,
        user_ref: Option<&ResourceRef>,
        peer: Option<PeerCredentials>,
    ) -> Result<(), String> {
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
            || user_ref != self.expected_user.as_ref()
            || route.provider_generation() != Some(self.expected_provider_generation)
            || route.controller_generation() != Some(self.expected_controller_generation)
            || route_execution.resource_type().as_str() != "Guest"
            || !route.liveness().is_live()
        {
            return Err("provider-backend-route-mismatch".to_owned());
        }
        self.responder
            .bind_route_with_user_and_peer(
                route.clone(),
                user_ref.cloned(),
                peer.unwrap_or(self.fallback_peer),
            )
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

    /// Compose an explicit fail-closed source for negative/degraded tests.
    #[allow(dead_code)]
    pub(crate) fn fail_closed() -> Arc<Self> {
        Self::new(Arc::new(FailClosedGuestCredentialBackend))
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
        let user_ref = match provider_ref.name().as_str() {
            SECRET_SERVICE_PROVIDER => Some(
                context
                    .user_ref
                    .clone()
                    .filter(|reference| reference.resource_type().as_str() == "User")
                    .ok_or_else(|| "provider-backend-user-identity-missing".to_owned())?,
            ),
            ENTRA_PROVIDER | MANAGED_IDENTITY_PROVIDER => {
                if context.user_ref.is_some() {
                    return Err("provider-backend-user-identity-unexpected".to_owned());
                }
                None
            }
            _ => return Err("provider-backend-provider-missing".to_owned()),
        };
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
        let responder_socket =
            d2b_session_unix::SeqpacketSocket::from_parent_prearmed(responder_endpoint)
                .map_err(|_| "provider-backend-socket-unavailable".to_owned())?;
        let fallback_peer = responder_socket
            .acceptor_peer_credentials()
            .map_err(|_| "provider-backend-socket-unavailable".to_owned())?;
        let responder = spawn_guest_credential_backend_responder(
            responder_socket,
            backend_keys,
            Arc::clone(&self.handler),
        )
        .map_err(|_| "provider-backend-responder-unavailable".to_owned())?;
        let lease = Arc::new(ProductionGuestCredentialBackendLease {
            expected_zone: context.zone.clone(),
            expected_provider: provider_ref,
            expected_process: process_ref,
            expected_execution: execution_ref,
            expected_user: user_ref,
            expected_provider_generation: provider_generation,
            expected_controller_generation: context.controller_generation,
            fallback_peer,
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

    struct ScriptedGuestCredentialAdapter;

    impl GuestCredentialProviderAdapter for ScriptedGuestCredentialAdapter {
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
        route_for_provider("credential-managed-identity")
    }

    fn route_for_provider(provider_name: &str) -> AuthenticatedSessionRouteBinding {
        let provider = format!("Provider/{provider_name}");
        let provider_ref = ResourceRef::parse(&provider).expect("provider");
        let process = if provider_name == "credential-secret-service" {
            "Process/credential-secret-service-controller"
        } else {
            "Process/credential-controller"
        };
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
        .with_process_ref(ResourceRef::parse(process).expect("process"))
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

    fn guest_binding() -> GuestExecutionBinding {
        GuestExecutionBinding::new(
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174003").expect("guest UID"),
            ConfigurationDigest::from_bytes([7; 32]),
            ReconnectGeneration::new(1).expect("session"),
            1,
            ResourceGeneration::new(1).expect("provider"),
            ControllerGeneration::new(1).expect("controller"),
        )
        .expect("guest binding")
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
        let guest_binding = guest_binding();
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
        let source = Arc::new(GuestLocalCredentialBackend {
            adapters: GuestCredentialBackendAdapters::new(
                Arc::new(ScriptedGuestCredentialAdapter),
                Arc::new(ScriptedGuestCredentialAdapter),
                Arc::new(ScriptedGuestCredentialAdapter),
            ),
        });
        let supervisor = ProductionGuestCredentialBackendSupervisor::new(source);
        let preparation = supervisor.prepare(&context).expect("backend preparation");
        let second_preparation = supervisor.prepare(&context).expect("second preparation");
        let client_socket =
            d2b_session_unix::SeqpacketSocket::from_parent_prearmed(preparation.child_endpoint)
                .expect("child backend socket");
        let bound_route = route();
        assert_ne!(
            preparation.delivery_key_handoff.provider_public(),
            second_preparation.delivery_key_handoff.provider_public()
        );
        second_preparation.lease.cancel();
        preparation
            .lease
            .bind_route(&bound_route, None, None)
            .expect("backend route binding");
        let backend = GuestCredentialBackend::from_socket_for_test_with_route(
            client_socket,
            bound_route,
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

        let fail_closed = ProductionGuestCredentialBackendSupervisor::fail_closed();
        let negative = fail_closed.prepare(&context).expect("negative preparation");
        let negative_route = route();
        negative
            .lease
            .bind_route(&negative_route, None, None)
            .expect("negative route binding");
        let negative_client_socket =
            d2b_session_unix::SeqpacketSocket::from_parent_prearmed(negative.child_endpoint)
                .expect("negative child socket");
        let negative_backend = GuestCredentialBackend::from_socket_for_test_with_route(
            negative_client_socket,
            negative_route,
            negative.delivery_key_handoff.into_material(),
        )
        .expect("negative backend client");
        assert!(
            negative_backend
                .request(
                    "managed-identity.issue-lease",
                    serde_json::json!({
                        "credentialRef": "Credential/test",
                        "operationId": "operation-negative",
                        "idempotencyKey": "idempotency-negative",
                        "requestedExpiryUnixMs": 2_000,
                        "imdsEndpointAlias": "azure-imds",
                    }),
                )
                .await
                .is_err()
        );
        negative.lease.cancel();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn production_secret_service_port_round_trips_zeroizing_lease() {
        let zone = ZoneId::parse("dev").expect("zone");
        let process_ref =
            ResourceRef::parse("Process/credential-secret-service-controller").expect("process");
        let process_uid =
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174010").expect("process UID");
        let process_provider =
            ResourceRef::parse("Provider/system-minijail").expect("process provider");
        let provider_ref =
            ResourceRef::parse("Provider/credential-secret-service").expect("owner provider");
        let provider_uid =
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174011").expect("provider UID");
        let zone_uid =
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174012").expect("zone UID");
        let execution_ref = ResourceRef::parse("Guest/test").expect("execution");
        let user_ref = ResourceRef::parse("User/test").expect("user");
        let guest_binding = guest_binding();
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
        .with_execution_ref(&execution_ref)
        .with_user_ref(Some(&user_ref));
        let supervisor = ProductionGuestCredentialBackendSupervisor::new(
            GuestLocalCredentialBackend::production(),
        );
        let preparation = supervisor.prepare(&context).expect("backend preparation");
        let client_socket =
            d2b_session_unix::SeqpacketSocket::from_parent_prearmed(preparation.child_endpoint)
                .expect("child backend socket");
        let bound_route = route_for_provider("credential-secret-service");
        preparation
            .lease
            .bind_route(&bound_route, Some(&user_ref), None)
            .expect("backend route binding");
        let backend = GuestCredentialBackend::from_socket_for_test_with_route(
            client_socket,
            bound_route,
            preparation.delivery_key_handoff.into_material(),
        )
        .expect("provider backend client");
        let issue_fields = serde_json::json!({
            "collectionAlias": "allocator-issued-collection",
            "userRef": "User/test",
            "credentialRef": "Credential/test",
            "operationId": "secret-operation-1",
            "idempotencyKey": "secret-idempotency-1",
            "requestedExpiryUnixMs": 2_000,
        });
        let issue = backend
            .request("secret-service.issue-lease", issue_fields.clone())
            .await
            .expect("secret issue");
        let lease_handle = issue.lease_handle().expect("lease handle").to_owned();
        let token = issue.into_bytes().expect("zeroizing token");
        assert!(!token.is_empty());
        let duplicate = backend
            .request("secret-service.issue-lease", issue_fields)
            .await
            .expect("idempotent secret issue");
        assert_eq!(duplicate.lease_handle(), Some(lease_handle.as_str()));
        assert_eq!(duplicate.into_bytes().expect("duplicate token"), token);
        let inspected = backend
            .request(
                "secret-service.inspect-lease",
                serde_json::json!({
                    "collectionAlias": "allocator-issued-collection",
                    "userRef": "User/test",
                    "credentialRef": "Credential/test",
                    "leaseHandle": lease_handle,
                }),
            )
            .await
            .expect("secret inspect");
        assert_eq!(inspected.state(), Some("active"));
        let lease_handle = inspected.lease_handle().expect("inspected handle").to_owned();
        let revoked = backend
            .request(
                "secret-service.revoke-lease",
                serde_json::json!({
                    "collectionAlias": "allocator-issued-collection",
                    "userRef": "User/test",
                    "credentialRef": "Credential/test",
                    "leaseHandle": lease_handle,
                }),
            )
            .await
            .expect("secret revoke");
        assert_eq!(revoked.outcome(), Some("revoked"));
        let revoked_again = backend
            .request(
                "secret-service.revoke-lease",
                serde_json::json!({
                    "collectionAlias": "allocator-issued-collection",
                    "userRef": "User/test",
                    "credentialRef": "Credential/test",
                    "leaseHandle": lease_handle,
                }),
            )
            .await
            .expect("idempotent secret revoke");
        assert_eq!(revoked_again.outcome(), Some("already-revoked"));
        preparation.lease.cancel();
    }
}
