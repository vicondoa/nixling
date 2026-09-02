//! Managed identity Credential Provider for an exact SDK consumer.
//!
//! The injected client owns IMDS access and all token bytes. This crate has no
//! ambient credential chain, environment fallback, endpoint URL input, or
//! developer-tool fallback.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod agent;
mod audit;
mod controller;
mod service;
mod telemetry;

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use d2b_contracts_provider::v3::credential::{
    CREDENTIAL_SERVICE_NAME, CredentialAuthorization, CredentialLeaseHandle, CredentialLeaseState,
    CredentialMetadata, CredentialMethod, CredentialOutcomeCode, CredentialRequest,
    CredentialServiceError, CredentialServiceErrorCode, CredentialSessionBinding,
    CredentialSourceVersion, MAX_PROVIDER_LEASE_LIFETIME_MS, OpaqueAzureRef, PlacementBinding,
};
use d2b_contracts_resource::v3::ResourceRef;
use d2b_contracts_resource::v3::identity::{AuthenticatedSubjectContext, Locality};
use d2b_provider_toolkit::{
    AllocatorSessionBinding, AuthenticatedComponentSession, Cancellation,
    CredentialAuthorizationSource, ProviderAdmission, ProviderAgentBootstrap, ProviderEntrypoint,
    ProviderLifecycle, ProviderRuntimeError,
    run_authenticated_credential_provider,
};

pub use agent::ManagedIdentityAgent;
pub use audit::{
    ManagedIdentityAuditError, ManagedIdentityAuditOperation, ManagedIdentityAuditOutcome,
    ManagedIdentityAuditRecord,
};
pub use controller::{
    AgentProcessSpec, ManagedIdentityController, ManagedIdentityRoute,
    ManagedIdentityStatusProjection, ManagedIdentityTeardownPlan, PROVIDER_KIND,
    PROVIDER_REVOKE_FINALIZER,
};
pub use telemetry::{
    ManagedIdentityTelemetryFrame, ManagedIdentityTelemetryOperation,
    ManagedIdentityTelemetryOutcome, TelemetryField, TelemetryFrameError,
};

/// Canonical Provider reference.
pub const PROVIDER_REF: &str = "Provider/credential-managed-identity";
/// Maximum active leases per Provider instance.
pub const MAX_LOCAL_LEASES: u32 = 256;
/// Secret-free controller binary declared by the Provider dossier.
pub const CONTROLLER_BINARY: &str = "d2b-managed-identity-controller";
/// Co-located client-holding agent binary declared by the Provider dossier.
pub const AGENT_BINARY: &str = "d2b-managed-identity-agent";
/// Session purpose expected for Credential service calls.
pub const CREDENTIAL_SESSION_PURPOSE: &str = "credential-delivery";
/// Small values remain accepted as relative test/runtime deadlines for
/// compatibility with the bootstrap service contract.
const ABSOLUTE_UNIX_MS_THRESHOLD: u64 = 1_000_000_000_000;

/// Reject ambient SDK credential-chain environment names.
pub fn reject_ambient_credential_chain(
    keys: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<(), ManagedIdentityProviderError> {
    d2b_contracts_provider::v3::credential_controller::reject_ambient_credential_chain(keys)
        .map_err(|_| ManagedIdentityProviderError::InvalidConfig)
}

/// Reject ambient SDK credential-chain variables in this process.
pub fn reject_process_environment_credential_chain(
) -> Result<(), ManagedIdentityProviderError> {
    reject_ambient_credential_chain(
        std::env::vars_os().filter_map(|(key, _value)| key.into_string().ok()),
    )
}

/// Return the fail-closed status used when the controller is not registered by
/// `d2bd`.
pub fn controller_binary_entrypoint() -> i32 {
    standalone_entrypoint(CONTROLLER_BINARY)
}

/// Return the fail-closed status used when the agent is not registered by
/// `d2bd`.
pub fn agent_binary_entrypoint() -> i32 {
    standalone_entrypoint(AGENT_BINARY)
}

fn standalone_entrypoint(name: &'static str) -> i32 {
    if reject_process_environment_credential_chain().is_err() {
        return 1;
    }
    let Ok(provider_ref) = ResourceRef::parse(PROVIDER_REF) else {
        return 1;
    };
    let Ok(entrypoint) =
        ProviderEntrypoint::with_provider(name, provider_ref, CREDENTIAL_SERVICE_NAME)
    else {
        return 1;
    };
    if entrypoint.lifecycle() != ProviderLifecycle::Starting || entrypoint.admit().is_err() {
        return 1;
    }
    // A standalone Provider has no allocator-issued authenticated session.
    // Refuse readiness instead of serving an unauthenticated or ambient path.
    1
}

/// Serve the managed-identity Agent after the daemon has admitted the
/// allocator-issued ComponentSession.
pub async fn run_authenticated_agent<A>(
    bootstrap: ProviderAgentBootstrap,
    binding: AllocatorSessionBinding,
    entrypoint: ProviderEntrypoint,
    registration: ProviderAdmission,
    session: AuthenticatedComponentSession<()>,
    agent: Arc<ManagedIdentityAgent>,
    authorizer: Arc<A>,
    cancellation: Cancellation,
) -> Result<(), ProviderRuntimeError>
where
    A: CredentialAuthorizationSource,
{
    bootstrap
        .admit(binding)
        .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    let session_admission = entrypoint.admit_authenticated(&session)?;
    run_authenticated_credential_provider(
        entrypoint,
        registration,
        session_admission,
        session,
        agent,
        authorizer,
        cancellation,
    )
    .await
}

/// Boxed asynchronous result returned by the injected IMDS client.
pub type ManagedIdentityFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ManagedIdentityClientError>> + Send + 'a>>;

/// Exact-consumer ownership policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedIdentityCredentialOwner {
    /// Only the authenticated configured SDK consumer may be admitted.
    ExactSdkConsumer,
}

/// Closed IMDS endpoint categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImdsEndpointAlias {
    /// Standard Azure Instance Metadata Service.
    AzureImds,
    /// Azure Container Apps sidecar metadata service.
    AzureImdsAca,
}

impl ImdsEndpointAlias {
    /// Parse a closed alias without accepting a URL or path.
    pub fn parse(value: &str) -> Result<Self, ManagedIdentityProviderError> {
        match value {
            "azure-imds" => Ok(Self::AzureImds),
            "azure-imds-aca" => Ok(Self::AzureImdsAca),
            _ => Err(ManagedIdentityProviderError::InvalidConfig),
        }
    }

    /// Return the stable alias.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AzureImds => "azure-imds",
            Self::AzureImdsAca => "azure-imds-aca",
        }
    }
}

/// Closed injected-client state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedIdentityClientState {
    /// IMDS can issue leases.
    Ready,
    /// IMDS is unavailable.
    Unavailable,
}

/// Closed client failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedIdentityClientError {
    /// Policy denied the operation.
    Denied,
    /// IMDS is unavailable.
    Unavailable,
    /// The lease expired.
    LeaseExpired,
    /// The lease was revoked.
    LeaseRevoked,
    /// Completion is ambiguous and must not be replayed automatically.
    CompletionUnknown,
}

impl fmt::Display for ManagedIdentityClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Denied => "credential-operation-denied",
            Self::Unavailable => "credential-provider-unavailable",
            Self::LeaseExpired => "credential-lease-expired",
            Self::LeaseRevoked => "credential-lease-revoked",
            Self::CompletionUnknown => "credential-invariant-failure",
        })
    }
}

impl std::error::Error for ManagedIdentityClientError {}

/// Validated non-secret client configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct ManagedIdentityClientConfig {
    client_id: OpaqueAzureRef,
    endpoint_alias: ImdsEndpointAlias,
    max_leases: u32,
}

impl ManagedIdentityClientConfig {
    /// Validate the inline client ID, closed alias, and lease ceiling.
    pub fn new(
        client_id: impl Into<String>,
        endpoint_alias: &str,
        max_leases: u32,
    ) -> Result<Self, ManagedIdentityProviderError> {
        let client_id = OpaqueAzureRef::parse(client_id.into())
            .map_err(|_| ManagedIdentityProviderError::InvalidConfig)?;
        let endpoint_alias = ImdsEndpointAlias::parse(endpoint_alias)?;
        if !(1..=MAX_LOCAL_LEASES).contains(&max_leases) {
            return Err(ManagedIdentityProviderError::InvalidConfig);
        }
        Ok(Self {
            client_id,
            endpoint_alias,
            max_leases,
        })
    }

    /// Borrow the validated client ID for the injected client.
    pub const fn client_id(&self) -> &OpaqueAzureRef {
        &self.client_id
    }

    /// Return the closed endpoint category.
    pub const fn endpoint_alias(&self) -> ImdsEndpointAlias {
        self.endpoint_alias
    }

    /// Return the active-lease ceiling.
    pub const fn max_leases(&self) -> u32 {
        self.max_leases
    }
}

impl fmt::Debug for ManagedIdentityClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedIdentityClientConfig")
            .field("client_id", &"<redacted>")
            .field("endpoint_alias", &self.endpoint_alias)
            .field("max_leases", &self.max_leases)
            .finish()
    }
}

/// Closed construction failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedIdentityProviderError {
    /// Configuration is invalid.
    InvalidConfig,
    /// User-agent or incompatible machine placement was requested.
    InvalidPlacement,
    /// The exact consumer is not a Provider reference.
    InvalidConsumer,
}

impl fmt::Display for ManagedIdentityProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfig => "credential schema is invalid",
            Self::InvalidPlacement => "credential placement mismatch",
            Self::InvalidConsumer => "credential consumer mismatch",
        })
    }
}

impl std::error::Error for ManagedIdentityProviderError {}

/// Machine-local Host or Guest placement.
#[derive(Clone, PartialEq, Eq)]
pub struct ManagedIdentityPlacement {
    binding: PlacementBinding,
    execution_ref: ResourceRef,
    zone_ref: ResourceRef,
}

impl ManagedIdentityPlacement {
    /// Validate host-system or guest-agent placement bound to one Zone.
    pub fn new(
        binding: PlacementBinding,
        execution_ref: ResourceRef,
        zone_ref: ResourceRef,
    ) -> Result<Self, ManagedIdentityProviderError> {
        let valid = matches!(
            (binding, execution_ref.resource_type().as_str()),
            (PlacementBinding::HostSystem, "Host") | (PlacementBinding::GuestAgent, "Guest")
        );
        if !valid || zone_ref.resource_type().as_str() != "Zone" {
            return Err(ManagedIdentityProviderError::InvalidPlacement);
        }
        Ok(Self {
            binding,
            execution_ref,
            zone_ref,
        })
    }

    /// Validate machine placement and bind it to one Zone.
    pub fn in_zone(
        binding: PlacementBinding,
        execution_ref: ResourceRef,
        zone_ref: ResourceRef,
    ) -> Result<Self, ManagedIdentityProviderError> {
        Self::new(binding, execution_ref, zone_ref)
    }

    /// Return the placement binding.
    pub const fn binding(&self) -> PlacementBinding {
        self.binding
    }

    /// Borrow the execution context.
    pub const fn execution_ref(&self) -> &ResourceRef {
        &self.execution_ref
    }

    /// Borrow the Zone bound to this placement.
    pub const fn zone_ref(&self) -> &ResourceRef {
        &self.zone_ref
    }
}

impl fmt::Debug for ManagedIdentityPlacement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ManagedIdentityPlacement(<redacted>)")
    }
}

/// Opaque acquire request passed to the injected client.
#[derive(Clone, PartialEq, Eq)]
pub struct ManagedIdentityLeaseRequest {
    credential_ref: ResourceRef,
    operation_id: String,
    idempotency_key: String,
    requested_expiry_unix_ms: u64,
    rotation_generation: u64,
}

impl ManagedIdentityLeaseRequest {
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

    /// Return the nonzero rotation generation requested by the Provider.
    pub const fn rotation_generation(&self) -> u64 {
        self.rotation_generation
    }
}

impl fmt::Debug for ManagedIdentityLeaseRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ManagedIdentityLeaseRequest(<redacted>)")
    }
}

/// Opaque lease reference for inspect, refresh, and revoke.
#[derive(Clone, PartialEq, Eq)]
pub struct ManagedIdentityLeaseRef {
    credential_ref: ResourceRef,
    metadata: CredentialMetadata,
}

impl ManagedIdentityLeaseRef {
    /// Borrow the routed Credential reference.
    pub const fn credential_ref(&self) -> &ResourceRef {
        &self.credential_ref
    }

    /// Borrow current metadata.
    pub const fn metadata(&self) -> &CredentialMetadata {
        &self.metadata
    }
}

impl fmt::Debug for ManagedIdentityLeaseRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ManagedIdentityLeaseRef(<redacted>)")
    }
}

/// Non-secret lease grant.
#[derive(Clone, PartialEq, Eq)]
pub struct ManagedIdentityLeaseGrant {
    /// Opaque lease handle.
    pub lease_handle: CredentialLeaseHandle,
    /// Opaque source version.
    pub source_version: CredentialSourceVersion,
    /// Rotation generation.
    pub rotation_generation: u64,
    /// Absolute expiry.
    pub expires_at_unix_ms: u64,
}

impl fmt::Debug for ManagedIdentityLeaseGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ManagedIdentityLeaseGrant(<redacted>)")
    }
}

/// Non-secret lease inspection.
#[derive(Clone, PartialEq, Eq)]
pub struct ManagedIdentityLeaseInspection {
    /// Closed lease state.
    pub state: CredentialLeaseState,
    /// Opaque source version.
    pub source_version: CredentialSourceVersion,
    /// Rotation generation.
    pub rotation_generation: u64,
    /// Absolute expiry.
    pub expires_at_unix_ms: u64,
}

impl fmt::Debug for ManagedIdentityLeaseInspection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ManagedIdentityLeaseInspection(<redacted>)")
    }
}

/// Non-secret lease renewal.
pub type ManagedIdentityLeaseRenewal = ManagedIdentityLeaseGrant;

/// Idempotent revoke result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedIdentityLeaseRevocation {
    /// This call marked the lease revoked.
    Revoked,
    /// The lease was already revoked.
    AlreadyRevoked,
}

/// Injected client that owns IMDS access and token bytes.
pub trait ManagedIdentityCredentialClient: Send + Sync {
    /// Observe IMDS readiness.
    fn state(&self) -> ManagedIdentityFuture<'_, ManagedIdentityClientState>;
    /// Issue one lease.
    fn issue_lease(
        &self,
        request: &ManagedIdentityLeaseRequest,
    ) -> ManagedIdentityFuture<'_, ManagedIdentityLeaseGrant>;
    /// Inspect one lease.
    fn inspect_lease(
        &self,
        lease: &ManagedIdentityLeaseRef,
    ) -> ManagedIdentityFuture<'_, ManagedIdentityLeaseInspection>;
    /// Refresh one lease.
    fn refresh_lease(
        &self,
        lease: &ManagedIdentityLeaseRef,
    ) -> ManagedIdentityFuture<'_, ManagedIdentityLeaseRenewal>;
    /// Revoke one lease locally.
    fn revoke_lease(
        &self,
        lease: &ManagedIdentityLeaseRef,
    ) -> ManagedIdentityFuture<'_, ManagedIdentityLeaseRevocation>;
}

/// Factory bound to one machine placement and exact SDK consumer.
pub struct ManagedIdentityCredentialProviderFactory {
    config: ManagedIdentityClientConfig,
    placement: ManagedIdentityPlacement,
    consumer_ref: ResourceRef,
    client: Arc<dyn ManagedIdentityCredentialClient>,
}

impl ManagedIdentityCredentialProviderFactory {
    /// Validate and construct the factory.
    pub fn new(
        config: ManagedIdentityClientConfig,
        placement: ManagedIdentityPlacement,
        consumer_ref: ResourceRef,
        client: Arc<dyn ManagedIdentityCredentialClient>,
    ) -> Result<Self, ManagedIdentityProviderError> {
        if consumer_ref.resource_type().as_str() != "Provider" {
            return Err(ManagedIdentityProviderError::InvalidConsumer);
        }
        Ok(Self {
            config,
            placement,
            consumer_ref,
            client,
        })
    }

    /// Construct the service Provider.
    pub fn construct(self) -> ManagedIdentityCredentialProvider {
        ManagedIdentityCredentialProvider {
            config: self.config,
            placement: self.placement,
            consumer_ref: self.consumer_ref,
            client: self.client,
            leases: Mutex::new(BTreeMap::new()),
            mutation_gate: Mutex::new(()),
        }
    }
}

impl fmt::Debug for ManagedIdentityCredentialProviderFactory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ManagedIdentityCredentialProviderFactory(<redacted>)")
    }
}

#[derive(Clone)]
struct LeaseRecord {
    idempotency_key: String,
    metadata: CredentialMetadata,
    authenticated_subject: AuthenticatedSubjectContext,
    session_expires_at_unix_ms: u64,
    cleanup_only: bool,
}

/// Non-secret restart checkpoint for one managed-identity lease.
///
/// The checkpoint contains only opaque metadata and authenticated ownership
/// evidence. Token bytes remain exclusively inside the injected client.
#[derive(Clone, PartialEq, Eq)]
pub struct ManagedIdentityLeaseCheckpoint {
    credential_ref: ResourceRef,
    idempotency_key: String,
    metadata: CredentialMetadata,
    authenticated_subject: AuthenticatedSubjectContext,
    session_expires_at_unix_ms: u64,
    cleanup_only: bool,
}

impl ManagedIdentityLeaseCheckpoint {
    /// Borrow the Credential reference.
    pub const fn credential_ref(&self) -> &ResourceRef {
        &self.credential_ref
    }

    /// Borrow the non-secret idempotency key.
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    /// Borrow the non-secret lease metadata.
    pub const fn metadata(&self) -> &CredentialMetadata {
        &self.metadata
    }

    /// Borrow the authenticated owner context.
    pub const fn authenticated_subject(&self) -> &AuthenticatedSubjectContext {
        &self.authenticated_subject
    }

    /// Return the session expiry captured with this checkpoint.
    pub const fn session_expires_at_unix_ms(&self) -> u64 {
        self.session_expires_at_unix_ms
    }

    /// Whether this checkpoint exists only to retain an unresolved cleanup
    /// handle and must not satisfy a caller acquire or lease operation.
    pub const fn cleanup_only(&self) -> bool {
        self.cleanup_only
    }
}

impl fmt::Debug for ManagedIdentityLeaseCheckpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ManagedIdentityLeaseCheckpoint(<redacted>)")
    }
}

/// Managed identity implementation of the prepared Credential service.
pub struct ManagedIdentityCredentialProvider {
    config: ManagedIdentityClientConfig,
    placement: ManagedIdentityPlacement,
    consumer_ref: ResourceRef,
    client: Arc<dyn ManagedIdentityCredentialClient>,
    leases: Mutex<BTreeMap<String, Vec<LeaseRecord>>>,
    mutation_gate: Mutex<()>,
}

impl ManagedIdentityCredentialProvider {
    /// Return exact SDK-consumer ownership.
    pub const fn owner(&self) -> ManagedIdentityCredentialOwner {
        ManagedIdentityCredentialOwner::ExactSdkConsumer
    }

    /// Borrow the exact consumer required at authenticated admission.
    pub const fn consumer_ref(&self) -> &ResourceRef {
        &self.consumer_ref
    }

    /// Check an authenticated Provider identity against the exact consumer.
    pub fn authorizes_consumer(&self, authenticated_provider_ref: &ResourceRef) -> bool {
        authenticated_provider_ref == &self.consumer_ref
    }

    /// Borrow machine placement.
    pub const fn placement(&self) -> &ManagedIdentityPlacement {
        &self.placement
    }

    /// Borrow validated client configuration.
    pub const fn config(&self) -> &ManagedIdentityClientConfig {
        &self.config
    }

    /// Return the current Unix millisecond clock used for bounded expiry
    /// checks.
    pub(crate) fn now_unix_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
            .unwrap_or(0)
    }

    /// Whether a value uses the absolute Unix millisecond representation.
    pub(crate) const fn is_absolute_unix_ms(value: u64) -> bool {
        value >= ABSOLUTE_UNIX_MS_THRESHOLD
    }

    /// Whether an absolute Unix millisecond value has elapsed.
    pub(crate) fn is_expired(value: u64, now_unix_ms: u64) -> bool {
        Self::is_absolute_unix_ms(value) && value <= now_unix_ms
    }

    fn context_matches_provider(&self, subject: &AuthenticatedSubjectContext) -> bool {
        subject.provider_ref() == Some(&self.consumer_ref)
            && subject.execution_ref() == Some(self.placement.execution_ref())
            && subject.zone_ref() == self.placement.zone_ref()
            && subject.transport_binding().locality() == Locality::Local
            && subject.service().as_str() == CREDENTIAL_SERVICE_NAME
            && subject.session_purpose().as_str() == CREDENTIAL_SESSION_PURPOSE
            && subject.provider_generation().is_some()
    }

    /// Validate the authenticated ComponentSession binding for one method.
    pub(crate) fn validate_authenticated_session<'a>(
        &self,
        method: CredentialMethod,
        request: &CredentialRequest,
        authorization: &'a CredentialAuthorization,
    ) -> Result<&'a CredentialSessionBinding, CredentialServiceError> {
        let session = authorization.authenticated_session().ok_or_else(|| {
            CredentialServiceError::new(CredentialServiceErrorCode::OperationDenied)
        })?;
        let now = Self::now_unix_ms();
        if Self::is_expired(session.expires_at_unix_ms(), now) {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::DeadlineExceeded,
            ));
        }

        let subject = session.authenticated_subject();
        if !self.context_matches_provider(subject) {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::OperationDenied,
            ));
        }
        if authorization
            .authenticated_subject_context()
            .is_some_and(|authorized_subject| authorized_subject != subject)
        {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::OperationDenied,
            ));
        }

        if method.requires_delivery() {
            let delivery = authorization.delivery_session_params().ok_or_else(|| {
                CredentialServiceError::new(CredentialServiceErrorCode::OperationDenied)
            })?;
            if delivery.credential_ref() != request.credential_ref()
                || delivery.consumer_provider_ref() != &self.consumer_ref
                || delivery.operation_class() != method.operation_class()
            {
                return Err(CredentialServiceError::new(
                    CredentialServiceErrorCode::OperationDenied,
                ));
            }
            if subject.provider_generation() != Some(delivery.consumer_component_generation()) {
                return Err(CredentialServiceError::new(
                    CredentialServiceErrorCode::OperationDenied,
                ));
            }
            if Self::is_expired(delivery.expiry_unix_ms(), now)
                || Self::is_expired(delivery.deadline_unix_ms(), now)
            {
                return Err(CredentialServiceError::new(
                    CredentialServiceErrorCode::DeadlineExceeded,
                ));
            }
            if Self::is_absolute_unix_ms(session.expires_at_unix_ms())
                && Self::is_absolute_unix_ms(delivery.expiry_unix_ms())
                && session.expires_at_unix_ms() > delivery.expiry_unix_ms()
            {
                return Err(CredentialServiceError::new(
                    CredentialServiceErrorCode::OperationDenied,
                ));
            }
        }
        Ok(session)
    }

    /// Compare stable ownership dimensions while deliberately ignoring the
    /// reconnect transcript that identifies one concrete ComponentSession.
    pub(crate) fn same_owner(
        left: &AuthenticatedSubjectContext,
        right: &AuthenticatedSubjectContext,
    ) -> bool {
        left.subject_ref() == right.subject_ref()
            && left.subject_uid() == right.subject_uid()
            && left.zone_ref() == right.zone_ref()
            && left.execution_ref() == right.execution_ref()
            && left.provider_ref() == right.provider_ref()
            && left.provider_generation() == right.provider_generation()
            && left.service() == right.service()
            && left.session_purpose() == right.session_purpose()
    }

    /// Compare the complete authenticated session, including transcript and
    /// reconnect generation.
    pub(crate) fn same_session(
        left: &AuthenticatedSubjectContext,
        right: &AuthenticatedSubjectContext,
    ) -> bool {
        left == right
    }

    /// Mark absolute-time active leases expired before a new operation.
    pub(crate) fn mark_expired_locked(
        leases: &mut BTreeMap<String, Vec<LeaseRecord>>,
        now_unix_ms: u64,
    ) {
        for records in leases.values_mut() {
            for record in records {
                if !record.cleanup_only
                    && record.metadata.state == CredentialLeaseState::Active
                    && (Self::is_expired(record.metadata.expires_at_unix_ms, now_unix_ms)
                        || Self::is_expired(record.session_expires_at_unix_ms, now_unix_ms))
                {
                    record.metadata.state = CredentialLeaseState::Expired;
                }
            }
        }
    }

    /// Count active leases across all Credential owners.
    pub(crate) fn active_lease_count(leases: &BTreeMap<String, Vec<LeaseRecord>>) -> usize {
        leases
            .values()
            .flat_map(|records| records.iter())
            .filter(|record| {
                !record.cleanup_only && record.metadata.state == CredentialLeaseState::Active
            })
            .count()
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
        let now_unix_ms = Self::now_unix_ms();
        let duration_ms = if Self::is_absolute_unix_ms(deadline_ms) {
            deadline_ms.saturating_sub(now_unix_ms)
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

    pub(crate) fn bounded_expiry(
        requested_expiry_unix_ms: u64,
        session_expiry_unix_ms: u64,
        delivery_expiry_unix_ms: u64,
    ) -> Result<u64, CredentialServiceError> {
        let absolute = Self::is_absolute_unix_ms(requested_expiry_unix_ms)
            || Self::is_absolute_unix_ms(session_expiry_unix_ms)
            || Self::is_absolute_unix_ms(delivery_expiry_unix_ms);
        if !absolute {
            return Ok(requested_expiry_unix_ms
                .min(session_expiry_unix_ms)
                .min(delivery_expiry_unix_ms)
                .min(MAX_PROVIDER_LEASE_LIFETIME_MS));
        }
        let now = Self::now_unix_ms();
        let to_absolute = |value: u64| {
            if Self::is_absolute_unix_ms(value) {
                Some(value)
            } else {
                now.checked_add(value)
            }
        };
        let bounded = to_absolute(requested_expiry_unix_ms)
            .and_then(|requested| {
                to_absolute(session_expiry_unix_ms).and_then(|session| {
                    to_absolute(delivery_expiry_unix_ms)
                        .map(|delivery| requested.min(session).min(delivery))
                })
            })
            .ok_or_else(|| {
                CredentialServiceError::new(CredentialServiceErrorCode::InvariantFailure)
            })?;
        let provider_max = now
            .checked_add(MAX_PROVIDER_LEASE_LIFETIME_MS)
            .ok_or_else(|| {
                CredentialServiceError::new(CredentialServiceErrorCode::InvariantFailure)
            })?;
        let bounded = bounded.min(provider_max);
        if bounded <= now {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::DeadlineExceeded,
            ));
        }
        Ok(bounded)
    }

    pub(crate) fn poll_client<T>(
        mut future: ManagedIdentityFuture<'_, T>,
        deadline: Instant,
    ) -> Result<T, CredentialServiceError> {
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
            match future.as_mut().poll(&mut context) {
                Poll::Ready(result) => return result.map_err(Self::map_client_error),
                Poll::Pending => {
                    let now = Instant::now();
                    let remaining = deadline.checked_duration_since(now).ok_or_else(|| {
                        CredentialServiceError::new(CredentialServiceErrorCode::DeadlineExceeded)
                    })?;
                    thread::park_timeout(remaining);
                }
            }
        }
    }

    pub(crate) fn map_client_error(error: ManagedIdentityClientError) -> CredentialServiceError {
        let code = match error {
            ManagedIdentityClientError::Denied => CredentialServiceErrorCode::OperationDenied,
            ManagedIdentityClientError::Unavailable => {
                CredentialServiceErrorCode::ProviderUnavailable
            }
            ManagedIdentityClientError::LeaseExpired => CredentialServiceErrorCode::LeaseExpired,
            ManagedIdentityClientError::LeaseRevoked => CredentialServiceErrorCode::LeaseRevoked,
            ManagedIdentityClientError::CompletionUnknown => {
                CredentialServiceErrorCode::InvariantFailure
            }
        };
        CredentialServiceError::new(code)
    }

    pub(crate) fn grant_metadata(
        grant: ManagedIdentityLeaseGrant,
        requested_expiry_unix_ms: u64,
        minimum_rotation_generation: u64,
    ) -> Result<CredentialMetadata, CredentialServiceError> {
        let now_unix_ms = Self::now_unix_ms();
        let max_expiry = if Self::is_absolute_unix_ms(requested_expiry_unix_ms) {
            now_unix_ms
                .checked_add(MAX_PROVIDER_LEASE_LIFETIME_MS)
                .ok_or_else(|| {
                    CredentialServiceError::new(CredentialServiceErrorCode::InvariantFailure)
                })?
        } else {
            MAX_PROVIDER_LEASE_LIFETIME_MS
        };
        if grant.rotation_generation == 0
            || minimum_rotation_generation == 0
            || grant.rotation_generation < minimum_rotation_generation
            || grant.expires_at_unix_ms == 0
            || grant.expires_at_unix_ms > requested_expiry_unix_ms
            || grant.expires_at_unix_ms > max_expiry
            || Self::is_expired(grant.expires_at_unix_ms, now_unix_ms)
        {
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

    /// Export bounded, non-secret lease checkpoints for a restart.
    pub fn export_checkpoints(
        &self,
    ) -> Result<Vec<ManagedIdentityLeaseCheckpoint>, CredentialServiceError> {
        let leases = self.leases.lock().map_err(|_| {
            CredentialServiceError::new(CredentialServiceErrorCode::InvariantFailure)
        })?;
        Ok(leases
            .iter()
            .flat_map(|(credential_ref, records)| {
                records.iter().map(|record| ManagedIdentityLeaseCheckpoint {
                    credential_ref: ResourceRef::parse(credential_ref)
                        .expect("lease map keys are validated Credential refs"),
                    idempotency_key: record.idempotency_key.clone(),
                    metadata: record.metadata.clone(),
                    authenticated_subject: record.authenticated_subject.clone(),
                    session_expires_at_unix_ms: record.session_expires_at_unix_ms,
                    cleanup_only: record.cleanup_only,
                })
            })
            .collect())
    }

    /// Restore bounded lease metadata after a Provider restart.
    ///
    /// The injected client and all token bytes are intentionally absent from
    /// the checkpoint. Active records are revalidated by the next live
    /// inspect/refresh operation before they can be used.
    pub fn restore_checkpoints(
        &self,
        checkpoints: impl IntoIterator<Item = ManagedIdentityLeaseCheckpoint>,
    ) -> Result<(), CredentialServiceError> {
        let now = Self::now_unix_ms();
        let mut restored: Vec<(String, LeaseRecord)> = Vec::new();
        for checkpoint in checkpoints {
            let ManagedIdentityLeaseCheckpoint {
                credential_ref,
                idempotency_key,
                metadata,
                authenticated_subject,
                session_expires_at_unix_ms,
                cleanup_only,
            } = checkpoint;
            if credential_ref.resource_type().as_str() != "Credential"
                || !self.context_matches_provider(&authenticated_subject)
                || (!cleanup_only
                    && (metadata.rotation_generation == 0 || metadata.expires_at_unix_ms == 0))
                || idempotency_key.is_empty()
                || session_expires_at_unix_ms == 0
            {
                return Err(CredentialServiceError::new(
                    CredentialServiceErrorCode::InvariantFailure,
                ));
            }
            let mut metadata = metadata;
            if !cleanup_only
                && metadata.state == CredentialLeaseState::Active
                && (Self::is_expired(metadata.expires_at_unix_ms, now)
                    || Self::is_expired(session_expires_at_unix_ms, now))
            {
                metadata.state = CredentialLeaseState::Expired;
            }
            let key = credential_ref.to_canonical_string();
            let record = LeaseRecord {
                idempotency_key,
                metadata,
                authenticated_subject,
                session_expires_at_unix_ms,
                cleanup_only,
            };
            if let Some((_, existing)) = restored.iter_mut().find(|(existing_key, existing)| {
                existing_key == &key && Self::same_record_identity(existing, &record)
            }) {
                *existing = record;
            } else {
                restored.push((key, record));
            }
        }
        let _mutation = self.mutation_guard()?;
        let mut leases = self.leases.lock().map_err(|_| {
            CredentialServiceError::new(CredentialServiceErrorCode::InvariantFailure)
        })?;
        let mut next = leases.clone();
        for records in next.values_mut() {
            Self::deduplicate_records(records);
        }
        Self::mark_expired_locked(&mut next, now);
        for (credential_ref, record) in &restored {
            if let Some(records) = next.get_mut(credential_ref) {
                records.retain(|existing| !Self::same_record_identity(existing, record));
            }
        }
        for (credential_ref, record) in restored {
            next.entry(credential_ref).or_default().push(record);
        }
        next.retain(|_, records| !records.is_empty());
        if Self::active_lease_count(&next) > self.config.max_leases() as usize {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::ProviderUnavailable,
            ));
        }
        *leases = next;
        Ok(())
    }

    pub(crate) fn deduplicate_records(records: &mut Vec<LeaseRecord>) {
        let mut deduplicated: Vec<LeaseRecord> = Vec::with_capacity(records.len());
        for record in records.drain(..) {
            if let Some(index) = deduplicated.iter().position(|existing| {
                !existing.cleanup_only
                    && !record.cleanup_only
                    && Self::same_owner(
                        &existing.authenticated_subject,
                        &record.authenticated_subject,
                    )
            }) {
                if record.metadata.state == CredentialLeaseState::Active
                    || deduplicated[index].metadata.state != CredentialLeaseState::Active
                {
                    deduplicated[index] = record;
                }
            } else {
                deduplicated.push(record);
            }
        }
        *records = deduplicated;
    }

    pub(crate) fn same_record_identity(left: &LeaseRecord, right: &LeaseRecord) -> bool {
        Self::same_owner(&left.authenticated_subject, &right.authenticated_subject)
            && if left.cleanup_only || right.cleanup_only {
                left.cleanup_only
                    && right.cleanup_only
                    && left.metadata.lease_handle == right.metadata.lease_handle
            } else {
                true
            }
    }

    /// Revoke every active handle owned by one authenticated workload.
    ///
    /// Stable owner dimensions select the records; a different workload,
    /// subject, Zone, or Provider generation is never touched.
    pub fn revoke_owned_handles(
        &self,
        session: &CredentialSessionBinding,
        deadline_unix_ms: u64,
    ) -> Result<usize, CredentialServiceError> {
        let now = Self::now_unix_ms();
        if Self::is_expired(session.expires_at_unix_ms(), now)
            || !self.context_matches_provider(session.authenticated_subject())
        {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::OperationDenied,
            ));
        }
        let deadline = Self::operation_deadline(deadline_unix_ms)?;
        let _mutation = self.mutation_guard()?;
        let owned = {
            let mut leases = self.leases.lock().map_err(|_| {
                CredentialServiceError::new(CredentialServiceErrorCode::InvariantFailure)
            })?;
            Self::mark_expired_locked(&mut leases, now);
            leases
                .iter()
                .flat_map(|(credential_ref, records)| {
                    records
                        .iter()
                        .filter(|record| {
                            matches!(
                                record.metadata.state,
                                CredentialLeaseState::Active | CredentialLeaseState::Expired
                            ) && Self::same_owner(
                                &record.authenticated_subject,
                                session.authenticated_subject(),
                            )
                        })
                        .map(|record| {
                            (
                                credential_ref.clone(),
                                record.authenticated_subject.clone(),
                                record.metadata.clone(),
                            )
                        })
                })
                .collect::<Vec<_>>()
        };

        let mut revoked = 0;
        for (credential_ref, authenticated_subject, metadata) in owned {
            let lease = ManagedIdentityLeaseRef {
                credential_ref: ResourceRef::parse(&credential_ref).map_err(|_| {
                    CredentialServiceError::new(CredentialServiceErrorCode::InvariantFailure)
                })?,
                metadata: metadata.clone(),
            };
            let _ = Self::poll_client(self.client.revoke_lease(&lease), deadline)?;
            let mut leases = self.leases.lock().map_err(|_| {
                CredentialServiceError::new(CredentialServiceErrorCode::InvariantFailure)
            })?;
            let records = leases.get_mut(&credential_ref).ok_or_else(invariant)?;
            for record in records {
                if record.metadata == metadata
                    && record.authenticated_subject == authenticated_subject
                {
                    record.metadata.state = CredentialLeaseState::Revoked;
                    record.metadata.outcome = CredentialOutcomeCode::Revoked;
                    revoked += 1;
                }
            }
        }
        Ok(revoked)
    }
}

impl fmt::Debug for ManagedIdentityCredentialProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ManagedIdentityCredentialProvider(<redacted>)")
    }
}

fn invariant() -> CredentialServiceError {
    CredentialServiceError::new(CredentialServiceErrorCode::InvariantFailure)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_id_and_alias_validation_fail_closed() {
        assert!(ManagedIdentityClientConfig::new("client-1234", "azure-imds", 64).is_ok());
        assert!(
            ManagedIdentityClientConfig::new("SharedAccessKey=abc/def+ghi==", "azure-imds", 64,)
                .is_err()
        );
        assert!(ManagedIdentityClientConfig::new("client-1234", "http://imds", 64).is_err());
    }

    #[test]
    fn user_agent_placement_is_rejected() {
        assert_eq!(
            ManagedIdentityPlacement::new(
                PlacementBinding::UserAgent,
                ResourceRef::parse("Host/workstation").unwrap(),
                ResourceRef::parse("Zone/dev").unwrap(),
            ),
            Err(ManagedIdentityProviderError::InvalidPlacement)
        );
    }

    #[test]
    fn client_id_is_redacted_from_debug() {
        let marker = format!("client-canary-{:x}", std::process::id());
        let config = ManagedIdentityClientConfig::new(&marker, "azure-imds", 64).unwrap();
        assert!(!format!("{config:?}").contains(&marker));
        assert_eq!(config.client_id().as_str(), marker);
    }

    #[test]
    fn poll_client_accepts_ready_result_at_deadline() {
        let future: ManagedIdentityFuture<'_, u8> = Box::pin(async { Ok(7) });
        assert_eq!(
            ManagedIdentityCredentialProvider::poll_client(future, Instant::now()).unwrap(),
            7
        );
    }
}
