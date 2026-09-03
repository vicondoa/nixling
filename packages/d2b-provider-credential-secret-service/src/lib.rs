//! User-session Secret Service Credential Provider.
//!
//! Credential material remains inside the injected [`Oo7SecretServicePort`].
//! This crate handles only validated configuration, opaque lease metadata, and
//! adapter-authorized delivery bindings.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod controller;
mod service;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use d2b_contracts_provider::v3::credential::{
    CREDENTIAL_SERVICE_NAME, CredentialAuthorization, CredentialLeaseHandle, CredentialLeaseState,
    CredentialMetadata, CredentialOutcomeCode, CredentialServiceError, CredentialServiceErrorCode,
    CredentialSourceVersion, PlacementBinding,
};
use d2b_contracts_resource::v3::{ResourceGeneration, ResourceRef, ZoneId};
use d2b_provider_toolkit::{
    AuthenticatedSessionRouteBinding, GuestCredentialBackend, GuestCredentialBackendResponse,
    ProviderFd10Spec, ProviderRuntimeError, ProviderSessionMetadata, RouteCredentialAuthorization,
    run_from_fd10 as run_provider_from_fd10,
};

pub use controller::{
    PROVIDER_KIND, PROVIDER_REVOKE_FINALIZER, SecretServiceController,
    SecretServiceControllerHealth, SecretServiceStatusProjection,
};

/// Canonical Provider reference.
pub const PROVIDER_REF: &str = "Provider/credential-secret-service";
/// Maximum active leases supported by one Provider instance.
pub const MAX_LOCAL_LEASES: u32 = 256;
/// Maximum bytes in a Secret Service collection alias.
pub const MAX_COLLECTION_ALIAS_BYTES: usize = 128;
const ABSOLUTE_UNIX_MS_THRESHOLD: u64 = 1_000_000_000_000;

/// Reject ambient SDK credential-chain environment names.
pub fn reject_ambient_credential_chain(
    keys: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<(), SecretServiceProviderError> {
    d2b_contracts_provider::v3::credential_controller::reject_ambient_credential_chain(keys)
        .map_err(|_| SecretServiceProviderError::InvalidConfig)
}

/// Reject ambient SDK credential-chain variables in this process.
pub fn reject_process_environment_credential_chain(
) -> Result<(), SecretServiceProviderError> {
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
    run_provider_from_fd10::<SecretServiceCredentialProvider, RouteCredentialAuthorization, _>(
        ProviderFd10Spec::new(
            "d2b-provider-credential-secret-service",
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
        Arc<SecretServiceCredentialProvider>,
        Arc<RouteCredentialAuthorization>,
    ),
    ProviderRuntimeError,
> {
    let provider_ref = route
        .provider_ref()
        .cloned()
        .ok_or(ProviderRuntimeError::SessionUnauthenticated)?;
    let execution_ref = route
        .context()
        .execution_ref()
        .filter(|reference| reference.resource_type().as_str() == "Guest")
        .cloned()
        .ok_or(ProviderRuntimeError::SessionUnauthenticated)?;
    if route.subject_ref() != &provider_ref
        || route.subject_ref().resource_type().as_str() != "Provider"
    {
        return Err(ProviderRuntimeError::SessionUnauthenticated);
    }
    let user_ref = metadata
        .user_ref()
        .cloned()
        .filter(|reference| reference.resource_type().as_str() == "User")
        .ok_or(ProviderRuntimeError::SessionUnauthenticated)?;
    let placement = SecretServicePlacement::new(
        route.zone().clone(),
        PlacementBinding::UserAgent,
        execution_ref,
        user_ref.clone(),
    )
    .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    let config = SecretServiceConfig::new(
        "allocator-issued-collection",
        MAX_LOCAL_LEASES,
        LockPolicy::FailClosed,
    )
    .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    let collection_alias = config.collection_alias().to_owned();
    let provider = SecretServiceCredentialProviderFactory::new(
        config,
        placement,
        Some(provider_ref),
        Arc::new(GuestSecretServicePort {
            backend,
            collection_alias,
            user_ref,
        }),
    )
    .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?
    .with_generation(
        route
            .provider_generation()
            .ok_or(ProviderRuntimeError::SessionUnauthenticated)?,
    )
    .construct()
    .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    Ok((Arc::new(provider), Arc::new(RouteCredentialAuthorization)))
}

struct GuestSecretServicePort {
    backend: Arc<GuestCredentialBackend>,
    collection_alias: String,
    user_ref: ResourceRef,
}

impl Oo7SecretServicePort for GuestSecretServicePort {
    fn state(&self) -> SecretServiceFuture<'_, SecretServiceState> {
        let backend = Arc::clone(&self.backend);
        let fields = serde_json::json!({
            "collectionAlias": self.collection_alias,
            "userRef": self.user_ref.to_canonical_string(),
        });
        Box::pin(async move {
            let response = backend
                .request("secret-service.state", fields)
                .await
                .map_err(|_| SecretServicePortError::Unavailable)?;
            Ok(match response.state() {
                Some("unlocked") => SecretServiceState::Unlocked,
                _ => SecretServiceState::Locked,
            })
        })
    }

    fn issue_lease(
        &self,
        request: &SecretServiceLeaseRequest,
    ) -> SecretServiceFuture<'_, SecretServiceLeaseGrant> {
        let backend = Arc::clone(&self.backend);
        let fields = serde_json::json!({
            "collectionAlias": self.collection_alias,
            "userRef": self.user_ref.to_canonical_string(),
            "credentialRef": request.credential_ref().to_canonical_string(),
            "operationId": request.operation_id(),
            "idempotencyKey": request.idempotency_key(),
            "requestedExpiryUnixMs": request.requested_expiry_unix_ms(),
        });
        Box::pin(async move {
            let response = backend
                .request("secret-service.issue-lease", fields)
                .await
                .map_err(|_| SecretServicePortError::Unavailable)?;
            secret_service_grant(response)
        })
    }

    fn inspect_lease(
        &self,
        lease: &SecretServiceLeaseRef,
    ) -> SecretServiceFuture<'_, SecretServiceLeaseInspection> {
        let backend = Arc::clone(&self.backend);
        let fields = serde_json::json!({
            "collectionAlias": self.collection_alias,
            "userRef": self.user_ref.to_canonical_string(),
            "credentialRef": lease.credential_ref().to_canonical_string(),
            "leaseHandle": lease.metadata().lease_handle.as_opaque_str(),
        });
        Box::pin(async move {
            let response = backend
                .request("secret-service.inspect-lease", fields)
                .await
                .map_err(|_| SecretServicePortError::Unavailable)?;
            secret_service_inspection(response)
        })
    }

    fn refresh_lease(
        &self,
        lease: &SecretServiceLeaseRef,
    ) -> SecretServiceFuture<'_, SecretServiceLeaseRenewal> {
        let backend = Arc::clone(&self.backend);
        let fields = serde_json::json!({
            "collectionAlias": self.collection_alias,
            "userRef": self.user_ref.to_canonical_string(),
            "credentialRef": lease.credential_ref().to_canonical_string(),
            "leaseHandle": lease.metadata().lease_handle.as_opaque_str(),
        });
        Box::pin(async move {
            let response = backend
                .request("secret-service.refresh-lease", fields)
                .await
                .map_err(|_| SecretServicePortError::Unavailable)?;
            secret_service_grant(response)
        })
    }

    fn revoke_lease(
        &self,
        lease: &SecretServiceLeaseRef,
    ) -> SecretServiceFuture<'_, SecretServiceLeaseRevocation> {
        let backend = Arc::clone(&self.backend);
        let fields = serde_json::json!({
            "collectionAlias": self.collection_alias,
            "userRef": self.user_ref.to_canonical_string(),
            "credentialRef": lease.credential_ref().to_canonical_string(),
            "leaseHandle": lease.metadata().lease_handle.as_opaque_str(),
        });
        Box::pin(async move {
            let response = backend
                .request("secret-service.revoke-lease", fields)
                .await
                .map_err(|_| SecretServicePortError::Unavailable)?;
            match response.outcome() {
                Some("revoked") => Ok(SecretServiceLeaseRevocation::Revoked),
                Some("already-revoked") => Ok(SecretServiceLeaseRevocation::AlreadyRevoked),
                _ => Err(SecretServicePortError::Unavailable),
            }
        })
    }
}

fn secret_service_grant(
    mut response: GuestCredentialBackendResponse,
) -> Result<SecretServiceLeaseGrant, SecretServicePortError> {
    response.clear_bytes();
    Ok(SecretServiceLeaseGrant {
        lease_handle: parse_backend_lease_handle(
            response
                .lease_handle()
                .ok_or(SecretServicePortError::Unavailable)?,
        )?,
        source_version: CredentialSourceVersion::parse(
            response
                .source_version()
                .ok_or(SecretServicePortError::Unavailable)?,
        )
        .map_err(|_| SecretServicePortError::Unavailable)?,
        rotation_generation: response
            .rotation_generation()
            .ok_or(SecretServicePortError::Unavailable)?,
        expires_at_unix_ms: response
            .expires_at_unix_ms()
            .ok_or(SecretServicePortError::Unavailable)?,
    })
}

fn parse_backend_lease_handle(
    value: &str,
) -> Result<CredentialLeaseHandle, SecretServicePortError> {
    CredentialLeaseHandle::from_opaque_digest(value.to_owned())
        .or_else(|_| CredentialLeaseHandle::parse(value))
        .map_err(|_| SecretServicePortError::Unavailable)
}

fn secret_service_inspection(
    response: GuestCredentialBackendResponse,
) -> Result<SecretServiceLeaseInspection, SecretServicePortError> {
    let state = match response.state() {
        Some("active") => CredentialLeaseState::Active,
        Some("expired") => CredentialLeaseState::Expired,
        Some("revoked") => CredentialLeaseState::Revoked,
        Some("unknown") => CredentialLeaseState::Unknown,
        _ => return Err(SecretServicePortError::Unavailable),
    };
    Ok(SecretServiceLeaseInspection {
        state,
        source_version: CredentialSourceVersion::parse(
            response
                .source_version()
                .ok_or(SecretServicePortError::Unavailable)?,
        )
        .map_err(|_| SecretServicePortError::Unavailable)?,
        rotation_generation: response
            .rotation_generation()
            .ok_or(SecretServicePortError::Unavailable)?,
        expires_at_unix_ms: response
            .expires_at_unix_ms()
            .ok_or(SecretServicePortError::Unavailable)?,
    })
}

/// A boxed asynchronous result returned by the injected port.
pub type SecretServiceFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, SecretServicePortError>> + Send + 'a>>;

/// The only supported process owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretServiceOwner {
    /// The authenticated user-domain process.
    Userd,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum OperationKind {
    Acquire,
    Inspect,
    Refresh,
    Revoke,
}

pub(crate) enum SecretServicePollError {
    Port(SecretServicePortError),
    Deadline,
}

fn invariant_error() -> CredentialServiceError {
    CredentialServiceError::new(CredentialServiceErrorCode::InvariantFailure)
}

/// Locked-keyring behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockPolicy {
    /// Fail each operation while the keyring is locked.
    FailClosed,
    /// Project degraded health while the keyring is locked.
    FailDegraded,
}

/// Closed Secret Service state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretServiceState {
    /// The backing collection is locked.
    Locked,
    /// The backing collection is ready.
    Unlocked,
}

/// Closed backing-service failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretServicePortError {
    /// The backing collection is locked.
    Locked,
    /// The requested secret is absent from the backing collection.
    Missing,
    /// Backing policy denied the operation.
    Denied,
    /// The backing service is unavailable.
    Unavailable,
    /// The lease expired.
    LeaseExpired,
    /// The lease was revoked.
    LeaseRevoked,
    /// Completion is ambiguous and must not be replayed automatically.
    CompletionUnknown,
}

impl fmt::Display for SecretServicePortError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Locked | Self::Missing | Self::Unavailable => "credential-provider-unavailable",
            Self::Denied => "credential-operation-denied",
            Self::LeaseExpired => "credential-lease-expired",
            Self::LeaseRevoked => "credential-lease-revoked",
            Self::CompletionUnknown => "credential-invariant-failure",
        })
    }
}

impl std::error::Error for SecretServicePortError {}

/// Provider configuration containing no credential material.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretServiceConfig {
    collection_alias: String,
    max_leases: u32,
    lock_policy: LockPolicy,
}

impl SecretServiceConfig {
    /// Validate configuration. Collection aliases may contain spaces but not
    /// controls, quotes, or backslashes.
    pub fn new(
        collection_alias: impl Into<String>,
        max_leases: u32,
        lock_policy: LockPolicy,
    ) -> Result<Self, SecretServiceProviderError> {
        let collection_alias = collection_alias.into();
        if collection_alias.is_empty()
            || collection_alias.len() > MAX_COLLECTION_ALIAS_BYTES
            || !collection_alias
                .bytes()
                .all(|byte| matches!(byte, 0x20..=0x7e) && !matches!(byte, b'"' | b'\\'))
            || !(1..=MAX_LOCAL_LEASES).contains(&max_leases)
        {
            return Err(SecretServiceProviderError::InvalidConfig);
        }
        Ok(Self {
            collection_alias,
            max_leases,
            lock_policy,
        })
    }

    /// Return the configured lease limit.
    pub const fn max_leases(&self) -> u32 {
        self.max_leases
    }

    /// Return locked-keyring behavior.
    pub const fn lock_policy(&self) -> LockPolicy {
        self.lock_policy
    }

    /// Borrow the validated collection alias for the injected port.
    pub fn collection_alias(&self) -> &str {
        &self.collection_alias
    }
}

impl fmt::Debug for SecretServiceConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretServiceConfig")
            .field("collection_alias", &"<redacted>")
            .field("max_leases", &self.max_leases)
            .field("lock_policy", &self.lock_policy)
            .finish()
    }
}

/// Construction failures with no caller-controlled fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretServiceProviderError {
    /// Configuration failed validation.
    InvalidConfig,
    /// Only user-agent placement is accepted.
    InvalidPlacement,
    /// The execution or user reference has the wrong ResourceType.
    InvalidScope,
    /// The declared consumer is not a Provider reference.
    InvalidConsumer,
    /// The provider-owned session authority could not allocate an identity.
    AuthorityUnavailable,
}

impl fmt::Display for SecretServiceProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfig => "credential schema is invalid",
            Self::InvalidPlacement | Self::InvalidScope => "credential placement mismatch",
            Self::InvalidConsumer => "credential consumer mismatch",
            Self::AuthorityUnavailable => "credential provider unavailable",
        })
    }
}

impl std::error::Error for SecretServiceProviderError {}

/// User-domain placement fixed by the Provider factory.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretServicePlacement {
    zone: ZoneId,
    execution_ref: ResourceRef,
    user_ref: ResourceRef,
}

impl SecretServicePlacement {
    /// Validate user-agent placement on a Host or Guest execution context.
    pub fn new(
        zone: ZoneId,
        binding: PlacementBinding,
        execution_ref: ResourceRef,
        user_ref: ResourceRef,
    ) -> Result<Self, SecretServiceProviderError> {
        if binding != PlacementBinding::UserAgent {
            return Err(SecretServiceProviderError::InvalidPlacement);
        }
        if !matches!(execution_ref.resource_type().as_str(), "Host" | "Guest")
            || user_ref.resource_type().as_str() != "User"
        {
            return Err(SecretServiceProviderError::InvalidScope);
        }
        Ok(Self {
            zone,
            execution_ref,
            user_ref,
        })
    }

    /// Borrow the fixed Zone binding.
    pub const fn zone(&self) -> &ZoneId {
        &self.zone
    }

    /// Borrow the fixed execution context.
    pub const fn execution_ref(&self) -> &ResourceRef {
        &self.execution_ref
    }

    /// Borrow the fixed user identity.
    pub const fn user_ref(&self) -> &ResourceRef {
        &self.user_ref
    }
}

impl fmt::Debug for SecretServicePlacement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretServicePlacement(<redacted>)")
    }
}

/// Opaque acquire request passed to the Secret Service adapter.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretServiceLeaseRequest {
    credential_ref: ResourceRef,
    operation_id: String,
    idempotency_key: String,
    requested_expiry_unix_ms: u64,
}

impl SecretServiceLeaseRequest {
    /// Borrow the routed Credential reference.
    pub const fn credential_ref(&self) -> &ResourceRef {
        &self.credential_ref
    }

    /// Borrow the operation identifier.
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Borrow the replay-safe idempotency key.
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    /// Return the requested absolute expiry.
    pub const fn requested_expiry_unix_ms(&self) -> u64 {
        self.requested_expiry_unix_ms
    }
}

impl fmt::Debug for SecretServiceLeaseRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretServiceLeaseRequest(<redacted>)")
    }
}

/// Opaque lease reference passed to inspect, refresh, and revoke calls.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretServiceLeaseRef {
    credential_ref: ResourceRef,
    metadata: CredentialMetadata,
}

impl SecretServiceLeaseRef {
    /// Borrow the routed Credential reference.
    pub const fn credential_ref(&self) -> &ResourceRef {
        &self.credential_ref
    }

    /// Borrow the current non-secret metadata.
    pub const fn metadata(&self) -> &CredentialMetadata {
        &self.metadata
    }
}

impl fmt::Debug for SecretServiceLeaseRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretServiceLeaseRef(<redacted>)")
    }
}

/// Non-secret metadata returned after the port retains credential material.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretServiceLeaseGrant {
    /// Opaque non-authorizing lease handle.
    pub lease_handle: CredentialLeaseHandle,
    /// Opaque source version.
    pub source_version: CredentialSourceVersion,
    /// Monotonic rotation generation.
    pub rotation_generation: u64,
    /// Absolute lease expiry.
    pub expires_at_unix_ms: u64,
}

impl fmt::Debug for SecretServiceLeaseGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretServiceLeaseGrant(<redacted>)")
    }
}

/// Non-secret lease inspection.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretServiceLeaseInspection {
    /// Closed lease state.
    pub state: CredentialLeaseState,
    /// Opaque source version.
    pub source_version: CredentialSourceVersion,
    /// Monotonic rotation generation.
    pub rotation_generation: u64,
    /// Absolute lease expiry.
    pub expires_at_unix_ms: u64,
}

impl fmt::Debug for SecretServiceLeaseInspection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretServiceLeaseInspection(<redacted>)")
    }
}

/// Non-secret refresh result.
pub type SecretServiceLeaseRenewal = SecretServiceLeaseGrant;

/// Idempotent revoke result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretServiceLeaseRevocation {
    /// This call revoked the lease.
    Revoked,
    /// The lease was already revoked.
    AlreadyRevoked,
}

/// Asynchronous semantic boundary implemented by the `oo7` adapter.
///
/// No method accepts or returns credential bytes, object paths, endpoints,
/// file descriptors, or arbitrary diagnostics.
pub trait Oo7SecretServicePort: Send + Sync {
    /// Observe locked or unlocked state.
    fn state(&self) -> SecretServiceFuture<'_, SecretServiceState>;
    /// Retain a new credential lease and return opaque metadata.
    fn issue_lease(
        &self,
        request: &SecretServiceLeaseRequest,
    ) -> SecretServiceFuture<'_, SecretServiceLeaseGrant>;
    /// Inspect one retained lease.
    fn inspect_lease(
        &self,
        lease: &SecretServiceLeaseRef,
    ) -> SecretServiceFuture<'_, SecretServiceLeaseInspection>;
    /// Refresh one retained lease.
    fn refresh_lease(
        &self,
        lease: &SecretServiceLeaseRef,
    ) -> SecretServiceFuture<'_, SecretServiceLeaseRenewal>;
    /// Revoke one retained lease.
    fn revoke_lease(
        &self,
        lease: &SecretServiceLeaseRef,
    ) -> SecretServiceFuture<'_, SecretServiceLeaseRevocation>;
    /// Revoke a lease whose issue completion was ambiguous, using the
    /// original idempotency key instead of replaying issuance.
    fn revoke_ambiguous_lease(
        &self,
        _request: &SecretServiceLeaseRequest,
    ) -> SecretServiceFuture<'_, SecretServiceLeaseRevocation> {
        Box::pin(async { Err(SecretServicePortError::Unavailable) })
    }
    /// Revoke the prior and any rotated lease associated with a refresh whose
    /// completion was ambiguous, using the operation identity without
    /// replaying refresh.
    fn revoke_ambiguous_refresh(
        &self,
        _lease: &SecretServiceLeaseRef,
        _operation_id: &str,
        _idempotency_key: &str,
    ) -> SecretServiceFuture<'_, SecretServiceLeaseRevocation> {
        Box::pin(async { Err(SecretServicePortError::Unavailable) })
    }
}

#[derive(Clone, PartialEq, Eq)]
struct SessionBinding {
    zone: ZoneId,
    workload: ResourceRef,
    subject: ResourceRef,
    consumer: ResourceRef,
    generation: ResourceGeneration,
}

#[derive(Clone)]
struct AuthoritySession {
    binding: SessionBinding,
    consumed_presentation: Option<u64>,
}

struct SessionAuthorityState {
    next_capability: AtomicU64,
    next_presentation: AtomicU64,
    sessions: Mutex<BTreeMap<u64, AuthoritySession>>,
}

#[derive(Clone)]
struct SessionAuthority {
    identity: u64,
    state: Arc<SessionAuthorityState>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionAuthorityError {
    Invalid,
    AlreadyConsumed,
    Released,
    Exhausted,
    InvalidBinding,
}

impl SessionAuthority {
    fn new() -> Result<Self, SecretServiceProviderError> {
        let identity = next_counter(&NEXT_AUTHORITY_ID)
            .map_err(|_| SecretServiceProviderError::AuthorityUnavailable)?;
        Ok(Self {
            identity,
            state: Arc::new(SessionAuthorityState {
                next_capability: AtomicU64::new(0),
                next_presentation: AtomicU64::new(0),
                sessions: Mutex::new(BTreeMap::new()),
            }),
        })
    }

    fn issue(
        &self,
        binding: SessionBinding,
    ) -> Result<SecretServiceSessionCapability, SessionAuthorityError> {
        if !matches!(binding.workload.resource_type().as_str(), "Host" | "Guest")
            || binding.subject.resource_type().as_str() != "User"
            || binding.consumer.resource_type().as_str() != "Provider"
        {
            return Err(SessionAuthorityError::InvalidBinding);
        }
        let capability_id = next_counter(&self.state.next_capability)
            .map_err(|_| SessionAuthorityError::Exhausted)?;
        let presentation = next_counter(&self.state.next_presentation)
            .map_err(|_| SessionAuthorityError::Exhausted)?;
        self.state
            .sessions
            .lock()
            .map_err(|_| SessionAuthorityError::Invalid)?
            .insert(
                capability_id,
                AuthoritySession {
                    binding: binding.clone(),
                    consumed_presentation: None,
                },
            );
        Ok(SecretServiceSessionCapability {
            authority: self.clone(),
            capability_id,
            presentation,
            binding,
        })
    }

    fn consume(
        &self,
        capability: &SecretServiceSessionCapability,
    ) -> Result<(), SessionAuthorityError> {
        if capability.authority.identity != self.identity {
            return Err(SessionAuthorityError::Invalid);
        }
        let mut sessions = self
            .state
            .sessions
            .lock()
            .map_err(|_| SessionAuthorityError::Invalid)?;
        let record = sessions
            .get_mut(&capability.capability_id)
            .ok_or(SessionAuthorityError::Released)?;
        if record.binding != capability.binding {
            return Err(SessionAuthorityError::Invalid);
        }
        if record.consumed_presentation.is_some() {
            return Err(SessionAuthorityError::AlreadyConsumed);
        }
        record.consumed_presentation = Some(capability.presentation);
        Ok(())
    }

    fn release_key(&self, key: SessionKey) -> Result<(), SessionAuthorityError> {
        if key.authority != self.identity {
            return Err(SessionAuthorityError::Invalid);
        }
        let mut sessions = self
            .state
            .sessions
            .lock()
            .map_err(|_| SessionAuthorityError::Invalid)?;
        let record = sessions
            .get(&key.capability_id)
            .ok_or(SessionAuthorityError::Released)?;
        if record.consumed_presentation != Some(key.presentation) {
            return Err(SessionAuthorityError::Invalid);
        }
        sessions.remove(&key.capability_id);
        Ok(())
    }

    fn discard_unconsumed(&self, capability: &SecretServiceSessionCapability) {
        if capability.authority.identity != self.identity {
            return;
        }
        if let Ok(mut sessions) = self.state.sessions.lock()
            && sessions
                .get(&capability.capability_id)
                .is_some_and(|record| record.consumed_presentation.is_none())
        {
            sessions.remove(&capability.capability_id);
        }
    }

    fn clear(&self) -> Result<(), SessionAuthorityError> {
        self.state
            .sessions
            .lock()
            .map_err(|_| SessionAuthorityError::Invalid)?
            .clear();
        Ok(())
    }

    fn discard_key(&self, key: SessionKey) -> Result<(), SessionAuthorityError> {
        if key.authority != self.identity {
            return Err(SessionAuthorityError::Invalid);
        }
        let mut sessions = self
            .state
            .sessions
            .lock()
            .map_err(|_| SessionAuthorityError::Invalid)?;
        let Some(record) = sessions.get(&key.capability_id) else {
            return Ok(());
        };
        if record.consumed_presentation.is_some() {
            return Err(SessionAuthorityError::Invalid);
        }
        sessions.remove(&key.capability_id);
        Ok(())
    }
}

static NEXT_AUTHORITY_ID: AtomicU64 = AtomicU64::new(0);

fn next_counter(counter: &AtomicU64) -> Result<u64, SessionAuthorityError> {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let next = current
            .checked_add(1)
            .ok_or(SessionAuthorityError::Exhausted)?;
        match counter.compare_exchange(current, next, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => return Ok(next),
            Err(observed) => current = observed,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct SessionKey {
    authority: u64,
    capability_id: u64,
    presentation: u64,
}

impl fmt::Debug for SessionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionKey(<redacted>)")
    }
}

/// Provider-owned, non-Clone session capability.
///
/// The capability has no public constructor. It is issued only by the
/// provider that retains its authority, and the provider authenticates the
/// authority identity before admitting it.
///
/// ```compile_fail
/// # use d2b_provider_credential_secret_service::SecretServiceSessionCapability;
/// fn cannot_clone(capability: SecretServiceSessionCapability) {
///     let _ = capability.clone();
/// }
/// ```
pub struct SecretServiceSessionCapability {
    authority: SessionAuthority,
    capability_id: u64,
    presentation: u64,
    binding: SessionBinding,
}

impl SecretServiceSessionCapability {
    fn session_key(&self) -> SessionKey {
        SessionKey {
            authority: self.authority.identity,
            capability_id: self.capability_id,
            presentation: self.presentation,
        }
    }

    fn binding(&self) -> &SessionBinding {
        &self.binding
    }
}

impl Drop for SecretServiceSessionCapability {
    fn drop(&mut self) {
        self.authority.discard_unconsumed(self);
    }
}

impl fmt::Debug for SecretServiceSessionCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretServiceSessionCapability(<redacted>)")
    }
}

/// Factory fixed to one user placement and exact consumer.
pub struct SecretServiceCredentialProviderFactory {
    config: SecretServiceConfig,
    placement: SecretServicePlacement,
    consumer_ref: ResourceRef,
    generation: ResourceGeneration,
    port: Arc<dyn Oo7SecretServicePort>,
}

impl SecretServiceCredentialProviderFactory {
    /// Build a factory. A present consumer must be a Provider reference;
    /// absence selects this Provider's canonical reference.
    pub fn new(
        config: SecretServiceConfig,
        placement: SecretServicePlacement,
        consumer_ref: Option<ResourceRef>,
        port: Arc<dyn Oo7SecretServicePort>,
    ) -> Result<Self, SecretServiceProviderError> {
        let consumer_ref = match consumer_ref {
            Some(reference) => reference,
            None => ResourceRef::parse(PROVIDER_REF)
                .map_err(|_| SecretServiceProviderError::InvalidConsumer)?,
        };
        if consumer_ref.resource_type().as_str() != "Provider" {
            return Err(SecretServiceProviderError::InvalidConsumer);
        }
        Ok(Self {
            config,
            placement,
            consumer_ref,
            generation: ResourceGeneration::new(1)
                .map_err(|_| SecretServiceProviderError::InvalidScope)?,
            port,
        })
    }

    /// Pin the authority-issued session generation for this Provider.
    pub fn with_generation(mut self, generation: ResourceGeneration) -> Self {
        self.generation = generation;
        self
    }

    /// Construct the service Provider.
    pub fn construct(self) -> Result<SecretServiceCredentialProvider, SecretServiceProviderError> {
        Ok(SecretServiceCredentialProvider {
            config: self.config,
            placement: self.placement,
            consumer_ref: self.consumer_ref,
            generation: self.generation,
            port: self.port,
            authority: SessionAuthority::new()?,
            sessions: Mutex::new(BTreeMap::new()),
            leases: Mutex::new(BTreeMap::new()),
            ambiguous_operations: Mutex::new(BTreeSet::new()),
            ambiguous_acquires: Mutex::new(BTreeMap::new()),
            ambiguous_refreshes: Mutex::new(BTreeMap::new()),
            mutation_gate: Mutex::new(()),
            finalized: AtomicBool::new(false),
        })
    }
}

impl fmt::Debug for SecretServiceCredentialProviderFactory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretServiceCredentialProviderFactory(<redacted>)")
    }
}

#[derive(Clone)]
struct LeaseRecord {
    refresh_results: BTreeMap<String, CredentialMetadata>,
    metadata: CredentialMetadata,
}

#[derive(Clone)]
struct AmbiguousRefreshRecord {
    lease: SecretServiceLeaseRef,
    operation_id: String,
    idempotency_key: String,
}

/// Secret Service implementation of the prepared Credential service.
pub struct SecretServiceCredentialProvider {
    config: SecretServiceConfig,
    placement: SecretServicePlacement,
    consumer_ref: ResourceRef,
    generation: ResourceGeneration,
    port: Arc<dyn Oo7SecretServicePort>,
    authority: SessionAuthority,
    sessions: Mutex<BTreeMap<SessionKey, ()>>,
    leases: Mutex<BTreeMap<(SessionKey, String), LeaseRecord>>,
    ambiguous_operations: Mutex<BTreeSet<(SessionKey, String, String, OperationKind)>>,
    ambiguous_acquires: Mutex<BTreeMap<(SessionKey, String, String), SecretServiceLeaseRequest>>,
    ambiguous_refreshes: Mutex<BTreeMap<(SessionKey, String, String), AmbiguousRefreshRecord>>,
    mutation_gate: Mutex<()>,
    finalized: AtomicBool,
}

impl SecretServiceCredentialProvider {
    /// Return the fixed owner classification.
    pub const fn owner(&self) -> SecretServiceOwner {
        SecretServiceOwner::Userd
    }

    /// Borrow the exact consumer expected by authenticated admission.
    pub const fn consumer_ref(&self) -> &ResourceRef {
        &self.consumer_ref
    }

    /// Borrow the fixed placement.
    pub const fn placement(&self) -> &SecretServicePlacement {
        &self.placement
    }

    /// Borrow validated configuration.
    pub const fn config(&self) -> &SecretServiceConfig {
        &self.config
    }

    /// Issue one authority-backed capability for this exact placement and
    /// configured consumer.
    pub fn issue_session_capability(
        &self,
        generation: ResourceGeneration,
    ) -> Result<SecretServiceSessionCapability, SecretServiceProviderError> {
        let _lifecycle = self
            .blocking_mutation_guard()
            .map_err(|_| SecretServiceProviderError::AuthorityUnavailable)?;
        if self.finalized.load(Ordering::Acquire) || generation != self.generation {
            return Err(SecretServiceProviderError::InvalidScope);
        }
        self.authority
            .issue(SessionBinding {
                zone: self.placement.zone().clone(),
                workload: self.placement.execution_ref().clone(),
                subject: self.placement.user_ref().clone(),
                consumer: self.consumer_ref.clone(),
                generation,
            })
            .map_err(|_| SecretServiceProviderError::AuthorityUnavailable)
    }

    pub(crate) fn authorize_session_locked(
        &self,
        authorization: &CredentialAuthorization,
    ) -> Result<SessionKey, CredentialServiceError> {
        if self.finalized.load(Ordering::Acquire) {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::OperationDenied,
            ));
        }
        let capability = self.session_capability(authorization)?;
        let key = capability.session_key();
        let mut sessions = self.sessions.lock().map_err(|_| {
            CredentialServiceError::new(CredentialServiceErrorCode::InvariantFailure)
        })?;
        if sessions.contains_key(&key) {
            return Ok(key);
        }
        self.authority.consume(capability).map_err(|_| {
            CredentialServiceError::new(CredentialServiceErrorCode::OperationDenied)
        })?;
        sessions.insert(key, ());
        Ok(key)
    }

    pub(crate) fn authorize_controller_session_locked(
        &self,
        authorization: &CredentialAuthorization,
    ) -> Result<SessionKey, CredentialServiceError> {
        if self.finalized.load(Ordering::Acquire) || !self.authorizes_controller_session(authorization)
        {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::OperationDenied,
            ));
        }
        let key = SessionKey {
            authority: self.authority.identity,
            capability_id: 0,
            presentation: 0,
        };
        self.sessions
            .lock()
            .map_err(|_| CredentialServiceError::new(CredentialServiceErrorCode::InvariantFailure))?
            .insert(key, ());
        Ok(key)
    }

    fn authorizes_controller_session(
        &self,
        authorization: &CredentialAuthorization,
    ) -> bool {
        let Some(session) = authorization.authenticated_session() else {
            return false;
        };
        let subject = session.authenticated_subject();
        authorization.authenticated_subject_context() == Some(subject)
            && matches!(
                subject.subject_ref().resource_type().as_str(),
                "Provider" | "User"
            )
            && subject
                .provider_ref()
                .is_some_and(|provider| provider.to_canonical_string() == PROVIDER_REF)
            && subject.zone_ref().name().as_str() == self.placement.zone().as_str()
            && subject.transport_binding().locality()
                == d2b_contracts_resource::v3::identity::Locality::Local
            && subject.service().as_str() == CREDENTIAL_SERVICE_NAME
            && subject.session_purpose().as_str() == "provider-control"
            && subject.provider_generation() == Some(self.generation)
            && subject
                .process_ref()
                .is_some_and(|process| process.resource_type().as_str() == "Process")
    }

    pub(crate) fn session_capability<'a>(
        &self,
        authorization: &'a CredentialAuthorization,
    ) -> Result<&'a SecretServiceSessionCapability, CredentialServiceError> {
        let capability = authorization
            .session_proof::<SecretServiceSessionCapability>()
            .ok_or_else(|| {
                CredentialServiceError::new(CredentialServiceErrorCode::OperationDenied)
            })?;
        if capability.authority.identity != self.authority.identity
            || &capability.binding().zone != self.placement.zone()
            || &capability.binding().workload != self.placement.execution_ref()
            || &capability.binding().subject != self.placement.user_ref()
            || capability.binding().consumer != self.consumer_ref
            || capability.binding().generation != self.generation
        {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::OperationDenied,
            ));
        }
        Ok(capability)
    }

    pub(crate) fn map_port_error(error: SecretServicePortError) -> CredentialServiceError {
        let code = match error {
            SecretServicePortError::Locked
            | SecretServicePortError::Missing
            | SecretServicePortError::Unavailable => {
                CredentialServiceErrorCode::ProviderUnavailable
            }
            SecretServicePortError::Denied => CredentialServiceErrorCode::OperationDenied,
            SecretServicePortError::LeaseExpired => CredentialServiceErrorCode::LeaseExpired,
            SecretServicePortError::LeaseRevoked => CredentialServiceErrorCode::LeaseRevoked,
            SecretServicePortError::CompletionUnknown => {
                CredentialServiceErrorCode::InvariantFailure
            }
        };
        CredentialServiceError::new(code)
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

    pub(crate) fn blocking_mutation_guard(
        &self,
    ) -> Result<MutexGuard<'_, ()>, CredentialServiceError> {
        self.mutation_gate
            .lock()
            .map_err(|_| CredentialServiceError::new(CredentialServiceErrorCode::InvariantFailure))
    }

    pub(crate) fn release_session_key(
        &self,
        key: SessionKey,
    ) -> Result<(), CredentialServiceError> {
        self.authority
            .release_key(key)
            .map_err(|_| CredentialServiceError::new(CredentialServiceErrorCode::InvariantFailure))
    }

    pub(crate) fn discard_session_key(
        &self,
        key: SessionKey,
    ) -> Result<(), CredentialServiceError> {
        self.authority
            .discard_key(key)
            .map_err(|_| CredentialServiceError::new(CredentialServiceErrorCode::InvariantFailure))
    }

    pub(crate) fn now_unix_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
            .unwrap_or(0)
    }

    pub(crate) const fn is_absolute_unix_ms(value: u64) -> bool {
        value >= ABSOLUTE_UNIX_MS_THRESHOLD
    }

    pub(crate) fn operation_deadline(deadline_ms: u64) -> Result<Instant, CredentialServiceError> {
        let duration_ms = if Self::is_absolute_unix_ms(deadline_ms) {
            deadline_ms.saturating_sub(Self::now_unix_ms())
        } else {
            deadline_ms
        };
        if duration_ms == 0 {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::DeadlineExceeded,
            ));
        }
        Instant::now()
            .checked_add(Duration::from_millis(duration_ms))
            .ok_or_else(|| {
                CredentialServiceError::new(CredentialServiceErrorCode::DeadlineExceeded)
            })
    }

    pub(crate) fn poll_port<T: Send>(
        future: SecretServiceFuture<'_, T>,
        deadline: Instant,
    ) -> Result<T, CredentialServiceError> {
        Self::poll_port_raw(future, deadline).map_err(|error| match error {
            SecretServicePollError::Port(error) => Self::map_port_error(error),
            SecretServicePollError::Deadline => {
                CredentialServiceError::new(CredentialServiceErrorCode::DeadlineExceeded)
            }
        })
    }

    pub(crate) fn poll_port_raw<T: Send>(
        mut future: SecretServiceFuture<'_, T>,
        deadline: Instant,
    ) -> Result<T, SecretServicePollError> {
        if tokio::runtime::Handle::try_current().is_ok() {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(SecretServicePollError::Deadline)?;
            return std::thread::scope(|scope| {
                let task = scope.spawn(move || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|_| SecretServicePollError::Deadline)?;
                    runtime.block_on(async {
                        tokio::time::timeout(remaining, future)
                            .await
                            .map_err(|_| SecretServicePollError::Deadline)?
                            .map_err(SecretServicePollError::Port)
                    })
                });
                match task.join() {
                    Ok(result) => result,
                    Err(_) => Err(SecretServicePollError::Port(
                        SecretServicePortError::CompletionUnknown,
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
                return Err(SecretServicePollError::Deadline);
            }
            match future.as_mut().poll(&mut context) {
                Poll::Ready(result) => {
                    return result.map_err(SecretServicePollError::Port);
                }
                Poll::Pending => {
                    let remaining = deadline
                        .checked_duration_since(Instant::now())
                        .ok_or(SecretServicePollError::Deadline)?;
                    if remaining.is_zero() {
                        return Err(SecretServicePollError::Deadline);
                    }
                    thread::park_timeout(remaining);
                }
            }
        }
    }

    pub(crate) fn ensure_unlocked(&self, deadline: Instant) -> Result<(), CredentialServiceError> {
        if Self::poll_port(self.port.state(), deadline)? == SecretServiceState::Locked {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::ProviderUnavailable,
            ));
        }
        Self::deadline_remaining(deadline)
    }

    pub(crate) fn deadline_remaining(deadline: Instant) -> Result<(), CredentialServiceError> {
        if Instant::now() >= deadline {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::DeadlineExceeded,
            ));
        }
        Ok(())
    }

    pub(crate) fn has_ambiguous_credential(
        &self,
        session_key: SessionKey,
        credential: &str,
    ) -> Result<bool, CredentialServiceError> {
        Ok(self
            .ambiguous_operations
            .lock()
            .map_err(|_| invariant_error())?
            .iter()
            .any(|(key, candidate, _, _)| *key == session_key && candidate == credential))
    }

    pub(crate) fn ambiguous_lease_count(&self) -> Result<usize, CredentialServiceError> {
        let tracked = self
            .leases
            .lock()
            .map_err(|_| invariant_error())?
            .values()
            .filter(|record| {
                matches!(
                    record.metadata.state,
                    CredentialLeaseState::Active | CredentialLeaseState::Unknown
                )
            })
            .count();
        let pending = self
            .ambiguous_acquires
            .lock()
            .map_err(|_| invariant_error())?
            .len();
        Ok(tracked.saturating_add(pending))
    }

    pub(crate) fn mark_ambiguous(
        &self,
        session_key: SessionKey,
        credential: &str,
        idempotency_key: &str,
        operation: OperationKind,
    ) -> Result<(), CredentialServiceError> {
        self.ambiguous_operations
            .lock()
            .map_err(|_| invariant_error())?
            .insert((
                session_key,
                credential.to_owned(),
                idempotency_key.to_owned(),
                operation,
            ));
        Ok(())
    }

    pub(crate) fn remember_ambiguous_acquire(
        &self,
        session_key: SessionKey,
        request: SecretServiceLeaseRequest,
    ) -> Result<(), CredentialServiceError> {
        let credential = request.credential_ref().to_canonical_string();
        self.mark_ambiguous(
            session_key,
            &credential,
            request.idempotency_key(),
            OperationKind::Acquire,
        )?;
        self.ambiguous_acquires
            .lock()
            .map_err(|_| invariant_error())?
            .insert(
                (
                    session_key,
                    credential,
                    request.idempotency_key().to_owned(),
                ),
                request,
            );
        Ok(())
    }

    pub(crate) fn remember_ambiguous_refresh(
        &self,
        session_key: SessionKey,
        request: &d2b_contracts_provider::v3::credential::CredentialRequest,
        lease: SecretServiceLeaseRef,
    ) -> Result<(), CredentialServiceError> {
        let credential = request.credential_ref().to_canonical_string();
        self.mark_ambiguous(
            session_key,
            &credential,
            request.idempotency_key(),
            OperationKind::Refresh,
        )?;
        self.ambiguous_refreshes
            .lock()
            .map_err(|_| invariant_error())?
            .insert(
                (
                    session_key,
                    credential,
                    request.idempotency_key().to_owned(),
                ),
                AmbiguousRefreshRecord {
                    lease,
                    operation_id: request.operation_id().to_owned(),
                    idempotency_key: request.idempotency_key().to_owned(),
                },
            );
        Ok(())
    }

    pub(crate) fn ambiguous_acquires(
        &self,
        session_key: SessionKey,
    ) -> Result<Vec<(String, String, SecretServiceLeaseRequest)>, CredentialServiceError> {
        Ok(self
            .ambiguous_acquires
            .lock()
            .map_err(|_| invariant_error())?
            .iter()
            .filter(|((key, _, _), _)| *key == session_key)
            .map(|((_, credential, idempotency), request)| {
                (credential.clone(), idempotency.clone(), request.clone())
            })
            .collect())
    }

    pub(crate) fn ambiguous_refreshes(
        &self,
        session_key: SessionKey,
    ) -> Result<Vec<(String, String, AmbiguousRefreshRecord)>, CredentialServiceError> {
        Ok(self
            .ambiguous_refreshes
            .lock()
            .map_err(|_| invariant_error())?
            .iter()
            .filter(|((key, _, _), _)| *key == session_key)
            .map(|((_, credential, idempotency), record)| {
                (credential.clone(), idempotency.clone(), record.clone())
            })
            .collect())
    }

    pub(crate) fn clear_ambiguous_operation(
        &self,
        session_key: SessionKey,
        credential: &str,
        idempotency_key: &str,
        operation: OperationKind,
    ) -> Result<(), CredentialServiceError> {
        self.ambiguous_operations
            .lock()
            .map_err(|_| invariant_error())?
            .retain(|(key, candidate, candidate_key, candidate_operation)| {
                *key != session_key
                    || candidate != credential
                    || candidate_key != idempotency_key
                    || *candidate_operation != operation
            });
        Ok(())
    }

    pub(crate) fn clear_ambiguous_acquire(
        &self,
        session_key: SessionKey,
        credential: &str,
        idempotency_key: &str,
    ) -> Result<(), CredentialServiceError> {
        self.ambiguous_acquires
            .lock()
            .map_err(|_| invariant_error())?
            .remove(&(
                session_key,
                credential.to_owned(),
                idempotency_key.to_owned(),
            ));
        self.clear_ambiguous_operation(
            session_key,
            credential,
            idempotency_key,
            OperationKind::Acquire,
        )
    }

    pub(crate) fn clear_ambiguous_refresh(
        &self,
        session_key: SessionKey,
        credential: &str,
        idempotency_key: &str,
    ) -> Result<(), CredentialServiceError> {
        self.ambiguous_refreshes
            .lock()
            .map_err(|_| invariant_error())?
            .remove(&(
                session_key,
                credential.to_owned(),
                idempotency_key.to_owned(),
            ));
        self.clear_ambiguous_operation(
            session_key,
            credential,
            idempotency_key,
            OperationKind::Refresh,
        )
    }

    pub(crate) fn clear_ambiguous_session(
        &self,
        session_key: SessionKey,
    ) -> Result<(), CredentialServiceError> {
        self.ambiguous_operations
            .lock()
            .map_err(|_| invariant_error())?
            .retain(|(key, _, _, _)| *key != session_key);
        self.ambiguous_acquires
            .lock()
            .map_err(|_| invariant_error())?
            .retain(|(key, _, _), _| *key != session_key);
        self.ambiguous_refreshes
            .lock()
            .map_err(|_| invariant_error())?
            .retain(|(key, _, _), _| *key != session_key);
        Ok(())
    }

    pub(crate) fn clear_ambiguous_for_credential(
        &self,
        session_key: SessionKey,
        credential: &str,
    ) -> Result<(), CredentialServiceError> {
        self.ambiguous_operations
            .lock()
            .map_err(|_| invariant_error())?
            .retain(|(key, candidate, _, _)| *key != session_key || candidate != credential);
        self.ambiguous_acquires
            .lock()
            .map_err(|_| invariant_error())?
            .retain(|(key, candidate, _), _| *key != session_key || candidate != credential);
        self.ambiguous_refreshes
            .lock()
            .map_err(|_| invariant_error())?
            .retain(|(key, candidate, _), _| *key != session_key || candidate != credential);
        Ok(())
    }

    pub(crate) fn has_ambiguous_session(
        &self,
        session_key: SessionKey,
    ) -> Result<bool, CredentialServiceError> {
        Ok(self
            .ambiguous_operations
            .lock()
            .map_err(|_| invariant_error())?
            .iter()
            .any(|(key, _, _, _)| *key == session_key))
    }

    fn metadata_from_grant(
        grant: &SecretServiceLeaseGrant,
        state: CredentialLeaseState,
        outcome: CredentialOutcomeCode,
    ) -> CredentialMetadata {
        CredentialMetadata {
            lease_handle: grant.lease_handle.clone(),
            rotation_generation: grant.rotation_generation,
            source_version: grant.source_version.clone(),
            expires_at_unix_ms: grant.expires_at_unix_ms,
            state,
            outcome,
        }
    }

    pub(crate) fn grant_metadata(
        grant: SecretServiceLeaseGrant,
        requested_expiry_unix_ms: u64,
    ) -> Result<CredentialMetadata, CredentialServiceError> {
        if grant.rotation_generation == 0
            || grant.expires_at_unix_ms == 0
            || grant.expires_at_unix_ms > requested_expiry_unix_ms
        {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::InvariantFailure,
            ));
        }
        Ok(Self::metadata_from_grant(
            &grant,
            CredentialLeaseState::Active,
            CredentialOutcomeCode::Success,
        ))
    }

    pub(crate) fn unknown_metadata(grant: &SecretServiceLeaseGrant) -> CredentialMetadata {
        Self::metadata_from_grant(
            grant,
            CredentialLeaseState::Unknown,
            CredentialOutcomeCode::Success,
        )
    }
}

impl fmt::Debug for SecretServiceCredentialProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretServiceCredentialProvider(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use d2b_contracts_provider::v3::credential::CredentialMethod;
    use d2b_contracts_resource::v3::identity::{
        AuthenticatedSubjectContext, BindingDigest, EvidenceClass, Locality,
        ReconnectGeneration, ServiceName, SessionBinding as AuthSessionBinding, SessionPurpose,
        TranscriptHash,
        TransportBinding,
    };
    use d2b_contracts_zone_session::v3::component_session::{
        EndpointRole, Locality as ComponentLocality, PurposeClass, TransportClass,
    };
    use d2b_provider_toolkit::ProviderSessionMetadata;
    use d2b_session_unix::{SeqpacketSocket, prearmed_seqpacket_pair};
    use std::sync::Arc;
    use std::thread;

    fn production_provider_route() -> AuthenticatedSessionRouteBinding {
        let provider_ref = ResourceRef::parse(PROVIDER_REF).unwrap();
        let context = AuthenticatedSubjectContext::new(
            provider_ref.clone(),
            d2b_contracts_resource::v3::ResourceUid::parse(
                "123e4567-e89b-42d3-a456-426614174000",
            )
            .unwrap(),
            ResourceRef::parse("Zone/dev").unwrap(),
            EvidenceClass::UnixPeer,
            SessionPurpose::parse("provider-control").unwrap(),
            ServiceName::parse(CREDENTIAL_SERVICE_NAME).unwrap(),
            AuthSessionBinding::new(
                d2b_contracts_resource::v3::SchemaFingerprint::parse(
                    "sha256:3333333333333333333333333333333333333333333333333333333333333333",
                )
                .unwrap(),
                TransportBinding::new(
                    Locality::Local,
                    BindingDigest::parse(
                        "sha256:3434343434343434343434343434343434343434343434343434343434343434",
                    )
                    .unwrap(),
                ),
                ReconnectGeneration::new(1).unwrap(),
                TranscriptHash::from_bytes([0x5a; 32]),
            ),
        )
        .with_execution_ref(ResourceRef::parse("Guest/test").unwrap())
        .with_provider_ref(provider_ref)
        .with_process_ref(ResourceRef::parse("Process/credential-controller").unwrap())
        .with_provider_generation(ResourceGeneration::new(1).unwrap())
        .with_controller_generation(
            d2b_contracts_resource::v3::ControllerGeneration::new(1).unwrap(),
        );
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

    #[tokio::test(flavor = "current_thread")]
    async fn runtime_provider_uses_authenticated_user_scope_claim() {
        let route = production_provider_route();
        let user_ref = ResourceRef::parse("User/alice").unwrap();
        let metadata =
            ProviderSessionMetadata::from_route_with_user(&route, Some(&user_ref)).unwrap();
        let (client_fd, _server_fd) = prearmed_seqpacket_pair().unwrap();
        let backend =
            GuestCredentialBackend::from_socket_for_test(SeqpacketSocket::from_parent_prearmed(
                client_fd,
            )
            .unwrap());
        let (provider, _) = runtime_provider(&route, &metadata, backend).unwrap();
        assert_eq!(provider.placement().user_ref(), &user_ref);
        assert_eq!(provider.placement().zone().as_str(), "dev");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn runtime_provider_rejects_missing_user_scope_claim_without_subject_spoof() {
        let route = production_provider_route();
        let metadata = ProviderSessionMetadata::from_route(&route).unwrap();
        let (client_fd, _server_fd) = prearmed_seqpacket_pair().unwrap();
        let backend =
            GuestCredentialBackend::from_socket_for_test(SeqpacketSocket::from_parent_prearmed(
                client_fd,
            )
            .unwrap());
        assert!(runtime_provider(&route, &metadata, backend).is_err());
    }

    #[test]
    fn collection_alias_accepts_spaces_and_rejects_unsafe_text() {
        assert!(SecretServiceConfig::new("login collection", 64, LockPolicy::FailClosed).is_ok());
        for rejected in ["", "bad\nname", "bad\\name", "bad\"name"] {
            assert!(SecretServiceConfig::new(rejected, 64, LockPolicy::FailClosed).is_err());
        }
    }

    #[test]
    fn placement_is_user_agent_only() {
        let host = ResourceRef::parse("Host/workstation").unwrap();
        let user = ResourceRef::parse("User/alice").unwrap();
        assert!(
            SecretServicePlacement::new(
                ZoneId::parse("user-zone").unwrap(),
                PlacementBinding::UserAgent,
                host.clone(),
                user.clone(),
            )
            .is_ok()
        );
        assert_eq!(
            SecretServicePlacement::new(
                ZoneId::parse("user-zone").unwrap(),
                PlacementBinding::HostSystem,
                host,
                user,
            ),
            Err(SecretServiceProviderError::InvalidPlacement)
        );
    }

    #[test]
    fn configuration_debug_redacts_collection_alias() {
        let marker = format!("collection-canary-{:x}", std::process::id());
        let config = SecretServiceConfig::new(&marker, 64, LockPolicy::FailClosed).unwrap();
        assert!(!format!("{config:?}").contains(&marker));
        assert_eq!(config.collection_alias(), marker);
    }

    #[test]
    fn session_key_and_capability_debug_are_redacted() {
        let marker = format!("session-key-canary-{:x}", std::process::id());
        let workload = format!("Host/{marker}");
        let key = SessionKey {
            authority: 7,
            capability_id: 11,
            presentation: 13,
        };
        assert_eq!(format!("{key:?}"), "SessionKey(<redacted>)");

        let capability = SecretServiceSessionCapability {
            authority: SessionAuthority {
                identity: 7,
                state: Arc::new(SessionAuthorityState {
                    next_capability: AtomicU64::new(0),
                    next_presentation: AtomicU64::new(0),
                    sessions: Mutex::new(BTreeMap::new()),
                }),
            },
            capability_id: 11,
            presentation: 13,
            binding: SessionBinding {
                zone: ZoneId::parse("user-zone").unwrap(),
                workload: ResourceRef::parse(&workload).unwrap(),
                subject: ResourceRef::parse("User/alice").unwrap(),
                consumer: ResourceRef::parse("Provider/shell-terminal").unwrap(),
                generation: ResourceGeneration::new(1).unwrap(),
            },
        };
        let debug = format!("{capability:?}");
        assert_eq!(debug, "SecretServiceSessionCapability(<redacted>)");
        assert!(!debug.contains(&marker));
    }

    #[test]
    fn same_presentation_concurrent_first_admission_is_idempotent() {
        struct NoopPort;

        impl Oo7SecretServicePort for NoopPort {
            fn state(&self) -> SecretServiceFuture<'_, SecretServiceState> {
                Box::pin(async { Ok(SecretServiceState::Unlocked) })
            }

            fn issue_lease(
                &self,
                _request: &SecretServiceLeaseRequest,
            ) -> SecretServiceFuture<'_, SecretServiceLeaseGrant> {
                Box::pin(async { Err(SecretServicePortError::Unavailable) })
            }

            fn inspect_lease(
                &self,
                _lease: &SecretServiceLeaseRef,
            ) -> SecretServiceFuture<'_, SecretServiceLeaseInspection> {
                Box::pin(async { Err(SecretServicePortError::Unavailable) })
            }

            fn refresh_lease(
                &self,
                _lease: &SecretServiceLeaseRef,
            ) -> SecretServiceFuture<'_, SecretServiceLeaseRenewal> {
                Box::pin(async { Err(SecretServicePortError::Unavailable) })
            }

            fn revoke_lease(
                &self,
                _lease: &SecretServiceLeaseRef,
            ) -> SecretServiceFuture<'_, SecretServiceLeaseRevocation> {
                Box::pin(async { Err(SecretServicePortError::Unavailable) })
            }
        }

        let provider = SecretServiceCredentialProviderFactory::new(
            SecretServiceConfig::new("login", 8, LockPolicy::FailClosed).unwrap(),
            SecretServicePlacement::new(
                ZoneId::parse("user-zone").unwrap(),
                PlacementBinding::UserAgent,
                ResourceRef::parse("Host/workstation").unwrap(),
                ResourceRef::parse("User/alice").unwrap(),
            )
            .unwrap(),
            None,
            Arc::new(NoopPort),
        )
        .unwrap()
        .construct()
        .unwrap();
        let capability = Arc::new(
            provider
                .issue_session_capability(ResourceGeneration::new(1).unwrap())
                .unwrap(),
        );
        let authorization = Arc::new(
            CredentialAuthorization::new(CredentialMethod::InspectMetadata, None)
                .unwrap()
                .with_shared_session_proof(capability),
        );
        let provider = Arc::new(provider);
        let first = {
            let provider = provider.clone();
            let authorization = authorization.clone();
            thread::spawn(move || provider.authorize_session_locked(&authorization))
        };
        let second = {
            let provider = provider.clone();
            let authorization = authorization.clone();
            thread::spawn(move || provider.authorize_session_locked(&authorization))
        };
        let first = first.join().unwrap().unwrap();
        let second = second.join().unwrap().unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn counter_exhaustion_is_fallible() {
        let counter = AtomicU64::new(u64::MAX);
        assert_eq!(
            next_counter(&counter),
            Err(SessionAuthorityError::Exhausted)
        );
    }

    #[test]
    fn absolute_deadlines_use_unix_milliseconds() {
        let now = SecretServiceCredentialProvider::now_unix_ms();
        let deadline = SecretServiceCredentialProvider::operation_deadline(now + 100);
        assert!(deadline.is_ok());
        assert!(
            SecretServiceCredentialProvider::operation_deadline(now.saturating_sub(1)).is_err()
        );
    }

    #[test]
    fn poll_port_raw_does_not_start_after_deadline() {
        let deadline = Instant::now();
        let result = SecretServiceCredentialProvider::poll_port_raw(
            Box::pin(async { Ok::<_, SecretServicePortError>(SecretServiceState::Unlocked) }),
            deadline,
        );
        assert!(matches!(result, Err(SecretServicePollError::Deadline)));
    }

    #[test]
    fn ambient_sdk_chain_names_are_rejected_without_reading_values() {
        assert!(reject_ambient_credential_chain(["PATH", "RUST_LOG"]).is_ok());
        assert!(reject_ambient_credential_chain(["AZURE_CLIENT_SECRET"]).is_err());
    }
}
