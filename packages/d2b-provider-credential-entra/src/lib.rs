//! Entra Credential Provider backed by an injected identity-Guest client.
//!
//! The Provider retains no token, login cookie, machine credential, or browser
//! state. Production clients terminate at the configured Entrablau Endpoint;
//! there is no Host login, ambient credential chain, or direct Entra fallback.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod controller;
mod service;

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use d2b_contracts_provider::v3::credential::{
    CREDENTIAL_SERVICE_NAME, CredentialLeaseHandle, CredentialLeaseState, CredentialMetadata,
    CredentialOutcomeCode, CredentialServiceError, CredentialServiceErrorCode,
    CredentialSourceVersion, OpaqueAzureRef, PlacementBinding,
};
use d2b_contracts_resource::v3::ResourceRef;
use d2b_provider_toolkit::{
    AuthenticatedSessionRouteBinding, GuestCredentialBackend, GuestCredentialBackendResponse,
    ProviderFd10Spec, ProviderRuntimeError, ProviderSessionMetadata, RouteCredentialAuthorization,
    run_from_fd10 as run_provider_from_fd10,
};

pub use controller::{
    EntraController, EntraEndpointPolicy, EntraStatusProjection, PROVIDER_KIND,
    PROVIDER_REVOKE_FINALIZER,
};

/// Canonical Provider reference.
pub const PROVIDER_REF: &str = "Provider/credential-entra";
/// Canonical identity-Guest login Endpoint purpose.
pub const LOGIN_ENDPOINT_PURPOSE: &str = "credential-entra.d2bus.org/entra-login-token";
/// Authenticated ComponentSession purpose accepted by this Provider.
pub const CREDENTIAL_SESSION_PURPOSE: &str = "credential";
/// Maximum active leases per Provider instance.
pub const MAX_LOCAL_LEASES: u32 = 256;
/// Maximum refresh failures retained for one Credential before retry stops.
pub const MAX_REFRESH_ATTEMPTS: u16 = 3;
const ABSOLUTE_UNIX_MILLIS_THRESHOLD: u64 = 1_000_000_000_000;

/// Reject ambient SDK credential-chain environment names.
pub fn reject_ambient_credential_chain(
    keys: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<(), EntraProviderError> {
    d2b_contracts_provider::v3::credential_controller::reject_ambient_credential_chain(keys)
        .map_err(|_| EntraProviderError::InvalidConfig)
}

/// Reject ambient SDK credential-chain variables in this process.
pub fn reject_process_environment_credential_chain(
) -> Result<(), EntraProviderError> {
    reject_ambient_credential_chain(
        std::env::vars_os().filter_map(|(key, _value)| key.into_string().ok()),
    )
}

/// Enter the supervised Provider runtime through the inherited fd 10 handoff.
pub fn run_from_fd10() -> i32 {
    if reject_process_environment_credential_chain().is_err() {
        return 1;
    }
    let Ok(provider_ref) = ResourceRef::parse(PROVIDER_REF) else {
        return 1;
    };
    let Ok(purpose) =
        d2b_contracts_resource::v3::identity::SessionPurpose::parse("provider-control")
    else {
        return 1;
    };
    run_provider_from_fd10::<EntraCredentialProvider, RouteCredentialAuthorization, _>(
        ProviderFd10Spec::new(
            "d2b-provider-credential-entra",
            provider_ref,
            CREDENTIAL_SERVICE_NAME,
            purpose,
        ),
        runtime_provider,
    )
}

/// Return the supervised controller process status.
pub fn controller_binary_entrypoint() -> i32 {
    run_from_fd10()
}

fn runtime_provider(
    route: &AuthenticatedSessionRouteBinding,
    metadata: &ProviderSessionMetadata,
    backend: Arc<GuestCredentialBackend>,
) -> Result<
    (
        Arc<EntraCredentialProvider>,
        Arc<RouteCredentialAuthorization>,
    ),
    ProviderRuntimeError,
> {
    if metadata.user_ref().is_some() {
        return Err(ProviderRuntimeError::SessionUnauthenticated);
    }
    let provider_ref = route
        .provider_ref()
        .cloned()
        .ok_or(ProviderRuntimeError::SessionUnauthenticated)?;
    let zone_ref = route.context().zone_ref().clone();
    let execution_ref = route
        .context()
        .execution_ref()
        .filter(|reference| reference.resource_type().as_str() == "Guest")
        .cloned()
        .ok_or(ProviderRuntimeError::SessionUnauthenticated)?;
    let endpoint_generation = route
        .provider_generation()
        .ok_or(ProviderRuntimeError::SessionUnauthenticated)?
        .get();
    let identity_guest_ref = execution_ref.clone();
    let placement = EntraPlacement::new_runtime_in_zone(
        zone_ref,
        PlacementBinding::GuestAgent,
        execution_ref,
        endpoint_generation,
    )
    .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    let config = EntraConfig::new("allocator-issued-tenant", MAX_LOCAL_LEASES)
        .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    let provider = EntraCredentialProviderFactory::new(
        config,
        placement,
        provider_ref,
        Arc::new(GuestEntraClient {
            backend,
            identity_guest_ref,
            login_endpoint_ref: None,
        }),
    )
    .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?
    .construct();
    Ok((Arc::new(provider), Arc::new(RouteCredentialAuthorization)))
}

struct GuestEntraClient {
    backend: Arc<GuestCredentialBackend>,
    identity_guest_ref: ResourceRef,
    login_endpoint_ref: Option<ResourceRef>,
}

impl EntraCredentialClient for GuestEntraClient {
    fn state(&self) -> EntraFuture<'_, EntraClientState> {
        let backend = Arc::clone(&self.backend);
        let fields = serde_json::json!({
            "identityGuestRef": self.identity_guest_ref.to_canonical_string(),
            "loginEndpointRef": self
                .login_endpoint_ref
                .as_ref()
                .map(ResourceRef::to_canonical_string),
        });
        Box::pin(async move {
            let response = backend
                .request("entra.state", fields)
                .await
                .map_err(|_| EntraClientError::Unavailable)?;
            match response.state() {
                Some("ready") => Ok(EntraClientState::Ready),
                Some("interaction-required") => Ok(EntraClientState::InteractionRequired),
                _ => Err(EntraClientError::Unavailable),
            }
        })
    }

    fn issue_lease(&self, request: &EntraLeaseRequest) -> EntraFuture<'_, EntraLeaseGrant> {
        let backend = Arc::clone(&self.backend);
        let fields = serde_json::json!({
            "identityGuestRef": self.identity_guest_ref.to_canonical_string(),
            "loginEndpointRef": self
                .login_endpoint_ref
                .as_ref()
                .map(ResourceRef::to_canonical_string),
            "credentialRef": request.credential_ref().to_canonical_string(),
            "operationId": request.operation_id(),
            "idempotencyKey": request.idempotency_key(),
            "requestedExpiryUnixMs": request.requested_expiry_unix_ms(),
            "endpointGeneration": request.endpoint_generation(),
        });
        Box::pin(async move {
            let response = backend
                .request("entra.issue-lease", fields)
                .await
                .map_err(|_| EntraClientError::Unavailable)?;
            entra_grant(response)
        })
    }

    fn inspect_lease(&self, lease: &EntraLeaseRef) -> EntraFuture<'_, EntraLeaseInspection> {
        let backend = Arc::clone(&self.backend);
        let fields = serde_json::json!({
            "identityGuestRef": self.identity_guest_ref.to_canonical_string(),
            "loginEndpointRef": self
                .login_endpoint_ref
                .as_ref()
                .map(ResourceRef::to_canonical_string),
            "credentialRef": lease.credential_ref().to_canonical_string(),
            "leaseHandle": lease.metadata().lease_handle.as_opaque_str(),
            "endpointGeneration": lease.endpoint_generation(),
        });
        Box::pin(async move {
            let response = backend
                .request("entra.inspect-lease", fields)
                .await
                .map_err(|_| EntraClientError::Unavailable)?;
            entra_inspection(response)
        })
    }

    fn refresh_lease(&self, lease: &EntraLeaseRef) -> EntraFuture<'_, EntraLeaseRenewal> {
        let backend = Arc::clone(&self.backend);
        let fields = serde_json::json!({
            "identityGuestRef": self.identity_guest_ref.to_canonical_string(),
            "loginEndpointRef": self
                .login_endpoint_ref
                .as_ref()
                .map(ResourceRef::to_canonical_string),
            "credentialRef": lease.credential_ref().to_canonical_string(),
            "leaseHandle": lease.metadata().lease_handle.as_opaque_str(),
            "endpointGeneration": lease.endpoint_generation(),
        });
        Box::pin(async move {
            let response = backend
                .request("entra.refresh-lease", fields)
                .await
                .map_err(|_| EntraClientError::Unavailable)?;
            entra_grant(response)
        })
    }

    fn revoke_lease(&self, lease: &EntraLeaseRef) -> EntraFuture<'_, EntraLeaseRevocation> {
        let backend = Arc::clone(&self.backend);
        let fields = serde_json::json!({
            "identityGuestRef": self.identity_guest_ref.to_canonical_string(),
            "loginEndpointRef": self
                .login_endpoint_ref
                .as_ref()
                .map(ResourceRef::to_canonical_string),
            "credentialRef": lease.credential_ref().to_canonical_string(),
            "leaseHandle": lease.metadata().lease_handle.as_opaque_str(),
            "endpointGeneration": lease.endpoint_generation(),
        });
        Box::pin(async move {
            let response = backend
                .request("entra.revoke-lease", fields)
                .await
                .map_err(|_| EntraClientError::Unavailable)?;
            match response.outcome() {
                Some("revoked") => Ok(EntraLeaseRevocation::Revoked),
                Some("already-revoked") => Ok(EntraLeaseRevocation::AlreadyRevoked),
                _ => Err(EntraClientError::Unavailable),
            }
        })
    }
}

fn entra_grant(
    mut response: GuestCredentialBackendResponse,
) -> Result<EntraLeaseGrant, EntraClientError> {
    response.clear_bytes();
    Ok(EntraLeaseGrant {
        lease_handle: CredentialLeaseHandle::parse(
            response
                .lease_handle()
                .ok_or(EntraClientError::Unavailable)?,
        )
        .map_err(|_| EntraClientError::Unavailable)?,
        source_version: CredentialSourceVersion::parse(
            response
                .source_version()
                .ok_or(EntraClientError::Unavailable)?,
        )
        .map_err(|_| EntraClientError::Unavailable)?,
        rotation_generation: response
            .rotation_generation()
            .ok_or(EntraClientError::Unavailable)?,
        expires_at_unix_ms: response
            .expires_at_unix_ms()
            .ok_or(EntraClientError::Unavailable)?,
    })
}

fn entra_inspection(
    response: GuestCredentialBackendResponse,
) -> Result<EntraLeaseInspection, EntraClientError> {
    let state = match response.state() {
        Some("active") => CredentialLeaseState::Active,
        Some("expired") => CredentialLeaseState::Expired,
        Some("revoked") => CredentialLeaseState::Revoked,
        Some("unknown") => CredentialLeaseState::Unknown,
        _ => return Err(EntraClientError::Unavailable),
    };
    Ok(EntraLeaseInspection {
        state,
        source_version: CredentialSourceVersion::parse(
            response
                .source_version()
                .ok_or(EntraClientError::Unavailable)?,
        )
        .map_err(|_| EntraClientError::Unavailable)?,
        rotation_generation: response
            .rotation_generation()
            .ok_or(EntraClientError::Unavailable)?,
        expires_at_unix_ms: response
            .expires_at_unix_ms()
            .ok_or(EntraClientError::Unavailable)?,
    })
}

/// Boxed asynchronous result returned by the injected identity-Guest client.
pub type EntraFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, EntraClientError>> + Send + 'a>>;

/// Exact-consumer ownership policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntraCredentialOwner {
    /// Only the configured consumer may be admitted.
    ExactConsumer,
}

/// Closed client state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntraClientState {
    /// Login state can issue leases.
    Ready,
    /// User interaction is required inside the identity Guest.
    InteractionRequired,
}

/// Closed identity-Guest client failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntraClientError {
    /// Login interaction is required.
    InteractionRequired,
    /// Policy denied the operation.
    Denied,
    /// The identity Guest or Endpoint is unavailable.
    Unavailable,
    /// The Endpoint generation differs from the admitted generation.
    GenerationMismatch,
    /// The lease expired.
    LeaseExpired,
    /// The lease was revoked.
    LeaseRevoked,
    /// Completion is ambiguous and must not be replayed automatically.
    CompletionUnknown,
}

impl fmt::Display for EntraClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InteractionRequired | Self::Unavailable => "credential-provider-unavailable",
            Self::Denied => "credential-operation-denied",
            Self::GenerationMismatch | Self::CompletionUnknown => "credential-invariant-failure",
            Self::LeaseExpired => "credential-lease-expired",
            Self::LeaseRevoked => "credential-lease-revoked",
        })
    }
}

impl std::error::Error for EntraClientError {}

/// Validated non-secret Provider configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct EntraConfig {
    tenant_id: OpaqueAzureRef,
    max_leases: u32,
}

impl EntraConfig {
    /// Validate the inline tenant identifier and lease bound.
    pub fn new(tenant_id: impl Into<String>, max_leases: u32) -> Result<Self, EntraProviderError> {
        let tenant_id = OpaqueAzureRef::parse(tenant_id.into())
            .map_err(|_| EntraProviderError::InvalidConfig)?;
        if !(1..=MAX_LOCAL_LEASES).contains(&max_leases) {
            return Err(EntraProviderError::InvalidConfig);
        }
        Ok(Self {
            tenant_id,
            max_leases,
        })
    }

    /// Borrow the validated tenant ID for the injected Endpoint client.
    pub const fn tenant_id(&self) -> &OpaqueAzureRef {
        &self.tenant_id
    }

    /// Return the active-lease ceiling.
    pub const fn max_leases(&self) -> u32 {
        self.max_leases
    }
}

impl fmt::Debug for EntraConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EntraConfig")
            .field("tenant_id", &"<redacted>")
            .field("max_leases", &self.max_leases)
            .finish()
    }
}

/// Closed construction failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntraProviderError {
    /// Configuration is invalid.
    InvalidConfig,
    /// Host-system or non-Guest placement was requested.
    InvalidPlacement,
    /// A required identity Guest or login Endpoint reference is invalid.
    InvalidEndpoint,
    /// The exact consumer is not a Provider reference.
    InvalidConsumer,
}

impl fmt::Display for EntraProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfig => "credential schema is invalid",
            Self::InvalidPlacement => "credential placement mismatch",
            Self::InvalidEndpoint => "credential endpoint is invalid",
            Self::InvalidConsumer => "credential consumer mismatch",
        })
    }
}

impl std::error::Error for EntraProviderError {}

/// Identity-Guest placement and Endpoint binding.
#[derive(Clone, PartialEq, Eq)]
pub struct EntraPlacement {
    binding: PlacementBinding,
    zone_ref: Option<ResourceRef>,
    execution_ref: ResourceRef,
    identity_guest_ref: ResourceRef,
    login_endpoint_ref: Option<ResourceRef>,
    endpoint_generation: u64,
}

impl EntraPlacement {
    /// Validate user-agent or guest-agent placement inside a Guest.
    pub fn new(
        binding: PlacementBinding,
        execution_ref: ResourceRef,
        identity_guest_ref: ResourceRef,
        login_endpoint_ref: ResourceRef,
        endpoint_generation: u64,
    ) -> Result<Self, EntraProviderError> {
        if !matches!(
            binding,
            PlacementBinding::UserAgent | PlacementBinding::GuestAgent
        ) || execution_ref.resource_type().as_str() != "Guest"
        {
            return Err(EntraProviderError::InvalidPlacement);
        }
        if identity_guest_ref.resource_type().as_str() != "Guest"
            || login_endpoint_ref.resource_type().as_str() != "Endpoint"
            || endpoint_generation == 0
        {
            return Err(EntraProviderError::InvalidEndpoint);
        }
        Ok(Self {
            binding,
            zone_ref: None,
            execution_ref,
            identity_guest_ref,
            login_endpoint_ref: Some(login_endpoint_ref),
            endpoint_generation,
        })
    }

    /// Validate placement with an authoritative Zone binding.
    pub fn new_in_zone(
        zone_ref: ResourceRef,
        binding: PlacementBinding,
        execution_ref: ResourceRef,
        identity_guest_ref: ResourceRef,
        login_endpoint_ref: ResourceRef,
        endpoint_generation: u64,
    ) -> Result<Self, EntraProviderError> {
        if zone_ref.resource_type().as_str() != "Zone" {
            return Err(EntraProviderError::InvalidEndpoint);
        }
        let mut placement = Self::new(
            binding,
            execution_ref,
            identity_guest_ref,
            login_endpoint_ref,
            endpoint_generation,
        )?;
        placement.zone_ref = Some(zone_ref);
        Ok(placement)
    }

    /// Bind a runtime controller to the exact Guest execution while leaving
    /// Endpoint resolution to the Guest-local typed client.
    pub fn new_runtime_in_zone(
        zone_ref: ResourceRef,
        binding: PlacementBinding,
        execution_ref: ResourceRef,
        endpoint_generation: u64,
    ) -> Result<Self, EntraProviderError> {
        if zone_ref.resource_type().as_str() != "Zone"
            || !matches!(
                binding,
                PlacementBinding::UserAgent | PlacementBinding::GuestAgent
            )
            || execution_ref.resource_type().as_str() != "Guest"
            || endpoint_generation == 0
        {
            return Err(EntraProviderError::InvalidEndpoint);
        }
        Ok(Self {
            binding,
            zone_ref: Some(zone_ref),
            identity_guest_ref: execution_ref.clone(),
            execution_ref,
            login_endpoint_ref: None,
            endpoint_generation,
        })
    }

    /// Return the placement binding.
    pub const fn binding(&self) -> PlacementBinding {
        self.binding
    }

    /// Borrow the authoritative Zone binding, when configured.
    pub const fn zone_ref(&self) -> Option<&ResourceRef> {
        self.zone_ref.as_ref()
    }

    /// Reject a request resolved against a different Zone.
    pub fn validate_zone(&self, zone_ref: &ResourceRef) -> Result<(), EntraProviderError> {
        if zone_ref.resource_type().as_str() != "Zone" || self.zone_ref.as_ref() != Some(zone_ref) {
            return Err(EntraProviderError::InvalidEndpoint);
        }
        Ok(())
    }

    /// Borrow the consumer execution Guest.
    pub const fn execution_ref(&self) -> &ResourceRef {
        &self.execution_ref
    }

    /// Borrow the identity Guest.
    pub const fn identity_guest_ref(&self) -> &ResourceRef {
        &self.identity_guest_ref
    }

    /// Borrow the login Endpoint.
    pub const fn login_endpoint_ref(&self) -> Option<&ResourceRef> {
        self.login_endpoint_ref.as_ref()
    }

    /// Return the admitted Endpoint generation.
    pub const fn endpoint_generation(&self) -> u64 {
        self.endpoint_generation
    }
}

impl fmt::Debug for EntraPlacement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EntraPlacement(<redacted>)")
    }
}

/// Opaque lease request passed to the identity-Guest client.
#[derive(Clone, PartialEq, Eq)]
pub struct EntraLeaseRequest {
    credential_ref: ResourceRef,
    operation_id: String,
    idempotency_key: String,
    requested_expiry_unix_ms: u64,
    endpoint_generation: u64,
}

impl EntraLeaseRequest {
    /// Borrow the routed Credential reference.
    pub const fn credential_ref(&self) -> &ResourceRef {
        &self.credential_ref
    }

    /// Borrow the operation identifier.
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Borrow the idempotency key.
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    /// Return requested expiry.
    pub const fn requested_expiry_unix_ms(&self) -> u64 {
        self.requested_expiry_unix_ms
    }

    /// Return the admitted Endpoint generation.
    pub const fn endpoint_generation(&self) -> u64 {
        self.endpoint_generation
    }
}

impl fmt::Debug for EntraLeaseRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EntraLeaseRequest(<redacted>)")
    }
}

/// Opaque lease reference for inspect, refresh, and revoke.
#[derive(Clone, PartialEq, Eq)]
pub struct EntraLeaseRef {
    credential_ref: ResourceRef,
    metadata: CredentialMetadata,
    endpoint_generation: u64,
}

impl EntraLeaseRef {
    /// Borrow the routed Credential reference.
    pub const fn credential_ref(&self) -> &ResourceRef {
        &self.credential_ref
    }

    /// Borrow current metadata.
    pub const fn metadata(&self) -> &CredentialMetadata {
        &self.metadata
    }

    /// Return the admitted Endpoint generation.
    pub const fn endpoint_generation(&self) -> u64 {
        self.endpoint_generation
    }
}

impl fmt::Debug for EntraLeaseRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EntraLeaseRef(<redacted>)")
    }
}

/// Non-secret lease grant.
#[derive(Clone, PartialEq, Eq)]
pub struct EntraLeaseGrant {
    /// Opaque lease handle.
    pub lease_handle: CredentialLeaseHandle,
    /// Opaque source version.
    pub source_version: CredentialSourceVersion,
    /// Rotation generation.
    pub rotation_generation: u64,
    /// Absolute expiry.
    pub expires_at_unix_ms: u64,
}

impl fmt::Debug for EntraLeaseGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EntraLeaseGrant(<redacted>)")
    }
}

/// Non-secret lease inspection.
#[derive(Clone, PartialEq, Eq)]
pub struct EntraLeaseInspection {
    /// Closed lease state.
    pub state: CredentialLeaseState,
    /// Opaque source version.
    pub source_version: CredentialSourceVersion,
    /// Rotation generation.
    pub rotation_generation: u64,
    /// Absolute expiry.
    pub expires_at_unix_ms: u64,
}

impl fmt::Debug for EntraLeaseInspection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EntraLeaseInspection(<redacted>)")
    }
}

/// Non-secret lease renewal.
pub type EntraLeaseRenewal = EntraLeaseGrant;

/// Idempotent revoke result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntraLeaseRevocation {
    /// This call revoked the lease.
    Revoked,
    /// The lease was already revoked.
    AlreadyRevoked,
}

/// Injected identity-Guest client retaining all token and login material.
pub trait EntraCredentialClient: Send + Sync {
    /// Observe client readiness.
    fn state(&self) -> EntraFuture<'_, EntraClientState>;
    /// Issue one lease.
    fn issue_lease(&self, request: &EntraLeaseRequest) -> EntraFuture<'_, EntraLeaseGrant>;
    /// Inspect one lease.
    fn inspect_lease(&self, lease: &EntraLeaseRef) -> EntraFuture<'_, EntraLeaseInspection>;
    /// Refresh one lease.
    fn refresh_lease(&self, lease: &EntraLeaseRef) -> EntraFuture<'_, EntraLeaseRenewal>;
    /// Revoke one lease.
    fn revoke_lease(&self, lease: &EntraLeaseRef) -> EntraFuture<'_, EntraLeaseRevocation>;
}

/// Factory bound to one exact consumer and identity-Guest Endpoint.
pub struct EntraCredentialProviderFactory {
    config: EntraConfig,
    placement: EntraPlacement,
    consumer_ref: ResourceRef,
    client: Arc<dyn EntraCredentialClient>,
}

impl EntraCredentialProviderFactory {
    /// Validate and construct a factory.
    pub fn new(
        config: EntraConfig,
        placement: EntraPlacement,
        consumer_ref: ResourceRef,
        client: Arc<dyn EntraCredentialClient>,
    ) -> Result<Self, EntraProviderError> {
        if consumer_ref.resource_type().as_str() != "Provider" {
            return Err(EntraProviderError::InvalidConsumer);
        }
        if placement.zone_ref.is_none() {
            return Err(EntraProviderError::InvalidEndpoint);
        }
        Ok(Self {
            config,
            placement,
            consumer_ref,
            client,
        })
    }

    /// Construct the service Provider.
    pub fn construct(self) -> EntraCredentialProvider {
        EntraCredentialProvider {
            config: self.config,
            placement: self.placement,
            consumer_ref: self.consumer_ref,
            client: self.client,
            leases: Mutex::new(BTreeMap::new()),
            cleanup_leases: Mutex::new(BTreeMap::new()),
            lifecycle: Mutex::new(BTreeMap::new()),
            mutation_gate: Mutex::new(()),
        }
    }
}

impl fmt::Debug for EntraCredentialProviderFactory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EntraCredentialProviderFactory(<redacted>)")
    }
}

#[derive(Clone)]
struct LeaseRecord {
    idempotency_key: String,
    pending_acquire_idempotency: Option<String>,
    metadata: CredentialMetadata,
    refresh_attempts: u16,
    health: EntraResourceHealth,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EntraLifecycleState {
    Draining,
    Finalized,
}

/// Typed non-secret health for one Entra Credential resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntraResourceHealth {
    /// The owning resource has a usable lease and no transient failure.
    Ready,
    /// The owning resource is degraded after a bounded refresh failure.
    Degraded,
    /// The owning resource has no usable lease after revocation.
    Revoked,
}

/// Result of revoking all handles owned by one Credential resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntraOwnedHandleCleanup {
    /// Number of handles successfully revoked by this call.
    pub revoked: u32,
    /// Number of handles that remain owned after this call.
    pub remaining: u32,
}

/// Entra implementation of the prepared Credential service.
pub struct EntraCredentialProvider {
    config: EntraConfig,
    placement: EntraPlacement,
    consumer_ref: ResourceRef,
    client: Arc<dyn EntraCredentialClient>,
    leases: Mutex<BTreeMap<String, LeaseRecord>>,
    cleanup_leases: Mutex<BTreeMap<String, Vec<LeaseRecord>>>,
    lifecycle: Mutex<BTreeMap<String, EntraLifecycleState>>,
    mutation_gate: Mutex<()>,
}

impl EntraCredentialProvider {
    /// Return exact-consumer ownership.
    pub const fn owner(&self) -> EntraCredentialOwner {
        EntraCredentialOwner::ExactConsumer
    }

    /// Borrow the exact consumer required at authenticated admission.
    pub const fn consumer_ref(&self) -> &ResourceRef {
        &self.consumer_ref
    }

    /// Test an authenticated Provider reference against the exact consumer.
    pub fn authorizes_consumer(&self, authenticated_provider_ref: &ResourceRef) -> bool {
        authenticated_provider_ref == &self.consumer_ref
    }

    /// Borrow the identity-Guest placement.
    pub const fn placement(&self) -> &EntraPlacement {
        &self.placement
    }

    /// Borrow validated configuration.
    pub const fn config(&self) -> &EntraConfig {
        &self.config
    }

    /// Reject a stale observed Endpoint generation.
    pub fn validate_endpoint_generation(
        &self,
        observed_generation: u64,
    ) -> Result<(), CredentialServiceError> {
        if observed_generation == self.placement.endpoint_generation() {
            Ok(())
        } else {
            Err(CredentialServiceError::new(
                CredentialServiceErrorCode::InvariantFailure,
            ))
        }
    }

    /// Return the active lease count without exposing lease identity.
    pub fn active_lease_count(&self) -> u32 {
        let primary = self
            .leases
            .lock()
            .map(|leases| {
                leases
                    .values()
                    .filter(|record| record.metadata.state == CredentialLeaseState::Active)
                    .count()
            })
            .unwrap_or(0);
        let cleanup = self
            .cleanup_leases
            .lock()
            .map(|leases| {
                leases
                    .values()
                    .flatten()
                    .filter(|record| record.metadata.state == CredentialLeaseState::Active)
                    .count()
            })
            .unwrap_or(0);
        (primary + cleanup) as u32
    }

    /// Return the typed health of one Credential resource.
    pub fn resource_health(&self, credential_ref: &ResourceRef) -> Option<EntraResourceHealth> {
        let key = credential_ref.to_canonical_string();
        self.cleanup_leases
            .lock()
            .ok()
            .and_then(|leases| {
                leases
                    .get(&key)
                    .and_then(|records| records.first())
                    .map(|record| record.health)
            })
            .or_else(|| {
                self.leases
                    .lock()
                    .ok()
                    .and_then(|leases| leases.get(&key).map(|record| record.health))
            })
    }

    /// Return the bounded refresh retry position for one Credential resource.
    pub fn refresh_retry_state(&self, credential_ref: &ResourceRef) -> Option<(u16, u16)> {
        let key = credential_ref.to_canonical_string();
        self.cleanup_leases
            .lock()
            .ok()
            .and_then(|leases| {
                leases
                    .get(&key)
                    .and_then(|records| records.first())
                    .map(|record| (record.refresh_attempts, MAX_REFRESH_ATTEMPTS))
            })
            .or_else(|| {
                self.leases.lock().ok().and_then(|leases| {
                    leases
                        .get(&key)
                        .map(|record| (record.refresh_attempts, MAX_REFRESH_ATTEMPTS))
                })
            })
    }

    /// Revoke all handles owned by one Credential before finalization clears
    /// its Provider finalizer.
    pub fn revoke_owned_handles(
        &self,
        credential_ref: &ResourceRef,
        deadline_ms: u64,
    ) -> Result<EntraOwnedHandleCleanup, CredentialServiceError> {
        if credential_ref.resource_type().as_str() != "Credential" {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::Malformed,
            ));
        }
        let _mutation = self.mutation_guard()?;
        let key = credential_ref.to_canonical_string();
        let already_finalized = self
            .lifecycle
            .lock()
            .map_err(|_| CredentialServiceError::new(CredentialServiceErrorCode::InvariantFailure))?
            .get(&key)
            == Some(&EntraLifecycleState::Finalized);
        if already_finalized {
            return Ok(EntraOwnedHandleCleanup {
                revoked: 0,
                remaining: 0,
            });
        }
        let deadline = Self::operation_deadline(deadline_ms)?;
        self.lifecycle
            .lock()
            .map_err(|_| CredentialServiceError::new(CredentialServiceErrorCode::InvariantFailure))?
            .insert(key.clone(), EntraLifecycleState::Draining);
        let primary = self
            .leases
            .lock()
            .map_err(|_| CredentialServiceError::new(CredentialServiceErrorCode::InvariantFailure))?
            .get(&key)
            .cloned();
        let cleanup = self
            .cleanup_leases
            .lock()
            .map_err(|_| CredentialServiceError::new(CredentialServiceErrorCode::InvariantFailure))?
            .get(&key)
            .cloned()
            .unwrap_or_default();
        if primary.is_none() && cleanup.is_empty() {
            self.lifecycle
                .lock()
                .map_err(|_| {
                    CredentialServiceError::new(CredentialServiceErrorCode::InvariantFailure)
                })?
                .insert(key, EntraLifecycleState::Finalized);
            return Ok(EntraOwnedHandleCleanup {
                revoked: 0,
                remaining: 0,
            });
        }
        let mut revoked = 0;
        for record in primary.iter().chain(cleanup.iter()) {
            if record.metadata.state == CredentialLeaseState::Revoked {
                continue;
            }
            let lease = EntraLeaseRef {
                credential_ref: credential_ref.clone(),
                metadata: record.metadata.clone(),
                endpoint_generation: self.placement.endpoint_generation(),
            };
            if let Err(error) = Self::poll_client(self.client.revoke_lease(&lease), deadline)
                && !matches!(
                    error.code(),
                    CredentialServiceErrorCode::LeaseExpired
                        | CredentialServiceErrorCode::LeaseRevoked
                )
            {
                return Err(error);
            }
            revoked += 1;
        }
        if primary.is_some() {
            let mut leases = self.leases.lock().map_err(|_| {
                CredentialServiceError::new(CredentialServiceErrorCode::InvariantFailure)
            })?;
            if let Some(record) = leases.get_mut(&key) {
                record.metadata.state = CredentialLeaseState::Revoked;
                record.metadata.outcome = CredentialOutcomeCode::Revoked;
                record.health = EntraResourceHealth::Revoked;
                record.refresh_attempts = 0;
                record.pending_acquire_idempotency = None;
            }
        }
        self.cleanup_leases
            .lock()
            .map_err(|_| CredentialServiceError::new(CredentialServiceErrorCode::InvariantFailure))?
            .remove(&key);
        self.lifecycle
            .lock()
            .map_err(|_| CredentialServiceError::new(CredentialServiceErrorCode::InvariantFailure))?
            .insert(key, EntraLifecycleState::Finalized);
        Ok(EntraOwnedHandleCleanup {
            revoked,
            remaining: 0,
        })
    }

    pub(crate) fn mutation_guard(&self) -> Result<MutexGuard<'_, ()>, CredentialServiceError> {
        match self.mutation_gate.try_lock() {
            Ok(guard) => Ok(guard),
            Err(TryLockError::WouldBlock) => Err(CredentialServiceError::new(
                CredentialServiceErrorCode::ProviderUnavailable,
            )),
            Err(TryLockError::Poisoned(_)) => Err(CredentialServiceError::new(
                CredentialServiceErrorCode::InvariantFailure,
            )),
        }
    }

    pub(crate) fn operation_deadline(deadline_ms: u64) -> Result<Instant, CredentialServiceError> {
        Self::time_bound_instant(deadline_ms)
    }

    pub(crate) fn now_unix_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
            .unwrap_or(0)
    }

    pub(crate) const fn is_absolute_unix_ms(value_ms: u64) -> bool {
        value_ms >= ABSOLUTE_UNIX_MILLIS_THRESHOLD
    }

    pub(crate) fn is_expired_unix_ms(value_ms: u64) -> bool {
        Self::is_absolute_unix_ms(value_ms) && value_ms <= Self::now_unix_ms()
    }

    pub(crate) fn time_bound_instant(value_ms: u64) -> Result<Instant, CredentialServiceError> {
        let now = Instant::now();
        let now_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CredentialServiceError::new(CredentialServiceErrorCode::InvariantFailure))?
            .as_millis()
            .try_into()
            .map_err(|_| {
                CredentialServiceError::new(CredentialServiceErrorCode::InvariantFailure)
            })?;
        Self::time_bound_instant_at(value_ms, now, now_unix_ms)
    }

    pub(crate) fn time_bounds_not_after(
        later_ms: u64,
        earlier_ms: u64,
    ) -> Result<bool, CredentialServiceError> {
        let now = Instant::now();
        let now_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CredentialServiceError::new(CredentialServiceErrorCode::InvariantFailure))?
            .as_millis()
            .try_into()
            .map_err(|_| {
                CredentialServiceError::new(CredentialServiceErrorCode::InvariantFailure)
            })?;
        let later = Self::time_bound_instant_at(later_ms, now, now_unix_ms)?;
        let earlier = Self::time_bound_instant_at(earlier_ms, now, now_unix_ms)?;
        Ok(later <= earlier)
    }

    fn time_bound_instant_at(
        value_ms: u64,
        now: Instant,
        now_unix_ms: u64,
    ) -> Result<Instant, CredentialServiceError> {
        if value_ms >= ABSOLUTE_UNIX_MILLIS_THRESHOLD {
            let remaining_ms = value_ms.checked_sub(now_unix_ms).ok_or_else(|| {
                CredentialServiceError::new(CredentialServiceErrorCode::DeadlineExceeded)
            })?;
            now.checked_add(Duration::from_millis(remaining_ms))
                .ok_or_else(|| {
                    CredentialServiceError::new(CredentialServiceErrorCode::DeadlineExceeded)
                })
        } else {
            now.checked_add(Duration::from_millis(value_ms))
                .ok_or_else(|| {
                    CredentialServiceError::new(CredentialServiceErrorCode::DeadlineExceeded)
                })
        }
    }

    pub(crate) fn poll_client<T: Send>(
        mut future: EntraFuture<'_, T>,
        deadline: Instant,
    ) -> Result<T, CredentialServiceError> {
        if tokio::runtime::Handle::try_current().is_ok() {
            let remaining = deadline.checked_duration_since(Instant::now()).ok_or_else(|| {
                CredentialServiceError::new(CredentialServiceErrorCode::DeadlineExceeded)
            })?;
            return std::thread::scope(|scope| {
                let task = scope.spawn(move || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|_| {
                            CredentialServiceError::new(
                                CredentialServiceErrorCode::InvariantFailure,
                            )
                        })?;
                    runtime.block_on(async {
                        tokio::time::timeout(remaining, future)
                            .await
                            .map_err(|_| {
                                CredentialServiceError::new(
                                    CredentialServiceErrorCode::DeadlineExceeded,
                                )
                            })?
                            .map_err(Self::map_client_error)
                    })
                });
                match task.join() {
                    Ok(result) => result,
                    Err(_) => Err(CredentialServiceError::new(
                        CredentialServiceErrorCode::InvariantFailure,
                    )),
                }
            });
        }
        struct ThreadWake(Thread);
        impl Wake for ThreadWake {
            fn wake(self: Arc<Self>) {
                self.0.unpark();
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.0.unpark();
            }
        }
        let waker = Waker::from(Arc::new(ThreadWake(thread::current())));
        let mut context = Context::from_waker(&waker);
        loop {
            if Instant::now() >= deadline {
                return Err(CredentialServiceError::new(
                    CredentialServiceErrorCode::DeadlineExceeded,
                ));
            }
            match future.as_mut().poll(&mut context) {
                Poll::Ready(result) => return result.map_err(Self::map_client_error),
                Poll::Pending => {
                    let remaining =
                        deadline
                            .checked_duration_since(Instant::now())
                            .ok_or_else(|| {
                                CredentialServiceError::new(
                                    CredentialServiceErrorCode::DeadlineExceeded,
                                )
                            })?;
                    thread::park_timeout(remaining);
                }
            }
        }
    }

    pub(crate) fn map_client_error(error: EntraClientError) -> CredentialServiceError {
        let code = match error {
            EntraClientError::InteractionRequired | EntraClientError::Unavailable => {
                CredentialServiceErrorCode::ProviderUnavailable
            }
            EntraClientError::Denied => CredentialServiceErrorCode::OperationDenied,
            EntraClientError::LeaseExpired => CredentialServiceErrorCode::LeaseExpired,
            EntraClientError::LeaseRevoked => CredentialServiceErrorCode::LeaseRevoked,
            EntraClientError::GenerationMismatch | EntraClientError::CompletionUnknown => {
                CredentialServiceErrorCode::InvariantFailure
            }
        };
        CredentialServiceError::new(code)
    }

    pub(crate) fn grant_metadata(
        grant: EntraLeaseGrant,
        requested_expiry_unix_ms: u64,
    ) -> Result<CredentialMetadata, CredentialServiceError> {
        let metadata = Self::committed_grant_metadata(grant)?;
        if metadata.expires_at_unix_ms > requested_expiry_unix_ms {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::InvariantFailure,
            ));
        }
        Ok(metadata)
    }

    pub(crate) fn committed_grant_metadata(
        grant: EntraLeaseGrant,
    ) -> Result<CredentialMetadata, CredentialServiceError> {
        if grant.rotation_generation == 0 || grant.expires_at_unix_ms == 0 {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::InvariantFailure,
            ));
        }
        if Self::is_expired_unix_ms(grant.expires_at_unix_ms) {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::InvariantFailure,
            ));
        }
        Ok(CredentialMetadata {
            lease_handle: grant.lease_handle,
            rotation_generation: grant.rotation_generation,
            source_version: grant.source_version,
            expires_at_unix_ms: grant.expires_at_unix_ms,
            state: CredentialLeaseState::Active,
            outcome: CredentialOutcomeCode::Success,
        })
    }

    pub(crate) fn ensure_lifecycle_active(&self, key: &str) -> Result<(), CredentialServiceError> {
        if self
            .lifecycle
            .lock()
            .map_err(|_| CredentialServiceError::new(CredentialServiceErrorCode::InvariantFailure))?
            .contains_key(key)
        {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::ProviderUnavailable,
            ));
        }
        Ok(())
    }

    pub(crate) fn adopt_committed_refresh(
        &self,
        key: &str,
        idempotency_key: &str,
        grant: EntraLeaseGrant,
    ) -> Result<bool, CredentialServiceError> {
        let metadata = match Self::committed_grant_metadata(grant) {
            Ok(metadata) => metadata,
            Err(_) => return Ok(false),
        };
        let mut leases = self.leases.lock().map_err(|_| {
            CredentialServiceError::new(CredentialServiceErrorCode::InvariantFailure)
        })?;
        let Some(record) = leases.get_mut(key) else {
            return Ok(false);
        };
        record.idempotency_key = idempotency_key.to_owned();
        record.metadata = metadata;
        record.refresh_attempts = 0;
        record.health = EntraResourceHealth::Degraded;
        Ok(true)
    }

    pub(crate) fn record_refresh_failure(&self, key: &str) {
        if let Ok(mut leases) = self.leases.lock()
            && let Some(record) = leases.get_mut(key)
        {
            record.refresh_attempts = record
                .refresh_attempts
                .saturating_add(1)
                .min(MAX_REFRESH_ATTEMPTS);
            record.health = EntraResourceHealth::Degraded;
        }
    }
}

impl fmt::Debug for EntraCredentialProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EntraCredentialProvider(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_id_reuses_opaque_cloud_reference_validation() {
        assert!(EntraConfig::new("tenant-1234", 64).is_ok());
        assert!(EntraConfig::new("SharedAccessKey=abc/def+ghi==", 64).is_err());
    }

    #[test]
    fn exact_consumer_guard_is_independent_of_request_fields() {
        let expected = ResourceRef::parse("Provider/runtime-azure-container-apps").unwrap();
        let other = ResourceRef::parse("Provider/other").unwrap();
        assert_ne!(expected, other);
    }

    #[test]
    fn host_system_placement_is_rejected() {
        assert_eq!(
            EntraPlacement::new(
                PlacementBinding::HostSystem,
                ResourceRef::parse("Host/workstation").unwrap(),
                ResourceRef::parse("Guest/identity").unwrap(),
                ResourceRef::parse("Endpoint/entra-login").unwrap(),
                1,
            ),
            Err(EntraProviderError::InvalidPlacement)
        );
    }

    #[test]
    fn operation_deadline_accepts_absolute_unix_milliseconds() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        assert!(EntraCredentialProvider::operation_deadline(now + 1_000).is_ok());
        assert_eq!(
            EntraCredentialProvider::operation_deadline(now - 1)
                .unwrap_err()
                .code(),
            CredentialServiceErrorCode::DeadlineExceeded
        );
    }
}
