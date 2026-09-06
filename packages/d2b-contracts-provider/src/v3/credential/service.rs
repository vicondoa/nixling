//! Neutral provider-facing DTO and sensitive-record contracts.

use core::fmt;
use std::any::Any;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use super::{
    AudienceToken, CredentialLeaseHandle, CredentialLeaseState, CredentialSourceVersion,
    OperationClass,
};
use d2b_contracts_resource::v3::identity::{AuthenticatedSubjectContext, TranscriptHash};
use d2b_contracts_resource::v3::{ResourceGeneration, ResourceRef, ResourceUid};

const MAX_PROTECTED_PLAINTEXT_BYTES: u32 = u16::MAX as u32 - 16;

/// Canonical service package routed by the Zone bus.
pub const CREDENTIAL_SERVICE_NAME: &str = "d2b.credential.v3";
/// The only Noise profile admitted for sensitive Credential delivery.
pub const CREDENTIAL_DELIVERY_NOISE_PROFILE: &str = "Noise_KK_25519_ChaChaPoly_SHA256";
/// Maximum encoded bytes accepted for one outer service message.
pub const MAX_CREDENTIAL_MESSAGE_BYTES: usize = 512 * 1024;
/// Fixed accepted version of the delivery-session binding.
pub const DELIVERY_BINDING_SCHEMA_VERSION: u32 = 1;
/// Conservative maximum plaintext bytes in one delivery record.
pub const MAX_DELIVERY_RECORD_BYTES: usize = MAX_PROTECTED_PLAINTEXT_BYTES as usize;

const MAX_OPERATION_ID_BYTES: usize = 128;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 64;
const ROUTE_DIGEST_BYTES: usize = 71;

/// One of the service's exactly five operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialMethod {
    /// Acquire a new token lease.
    AcquireToken,
    /// Refresh an existing token lease.
    RefreshToken,
    /// Revoke an existing token lease.
    RevokeToken,
    /// Sign one challenge without exporting a key.
    SignChallenge,
    /// Inspect only non-secret lease metadata.
    InspectMetadata,
}

impl CredentialMethod {
    /// Return the single operation class derived from this method.
    pub const fn operation_class(self) -> OperationClass {
        match self {
            Self::AcquireToken => OperationClass::AcquireToken,
            Self::RefreshToken => OperationClass::RefreshToken,
            Self::RevokeToken => OperationClass::RevokeToken,
            Self::SignChallenge => OperationClass::SignChallenge,
            Self::InspectMetadata => OperationClass::InspectMetadata,
        }
    }

    /// Return the exact Role subresource required by this method.
    pub const fn subresource(self) -> &'static str {
        match self {
            Self::AcquireToken => "acquire-token",
            Self::RefreshToken => "refresh-token",
            Self::RevokeToken => "revoke-token",
            Self::SignChallenge => "sign-challenge",
            Self::InspectMetadata => "inspect-metadata",
        }
    }

    /// Whether this operation establishes a sensitive delivery channel.
    pub const fn requires_delivery(self) -> bool {
        matches!(
            self,
            Self::AcquireToken | Self::RefreshToken | Self::SignChallenge
        )
    }
}

/// Administrative Credential lifecycle action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialAdminAction {
    /// Create a Credential resource.
    Create,
    /// Replace a Credential resource spec.
    UpdateSpec,
    /// Request deletion of a Credential resource.
    Delete,
}

/// Resource verbs used by Credential admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialResourceVerb {
    /// Read a resource.
    Get,
    /// Create a resource.
    Create,
    /// Replace a resource spec.
    UpdateSpec,
    /// Request resource deletion.
    Delete,
    /// Invoke one exact Credential operation.
    UseCredential,
    /// Supplement one exact administrative Credential action.
    AdminCredential,
}

impl CredentialAdminAction {
    /// Return the ordinary CRUD verb that remains independently required.
    pub const fn ordinary_verb(self) -> CredentialResourceVerb {
        match self {
            Self::Create => CredentialResourceVerb::Create,
            Self::UpdateSpec => CredentialResourceVerb::UpdateSpec,
            Self::Delete => CredentialResourceVerb::Delete,
        }
    }

    /// Return the exact supplemental `admin-credential` subresource.
    pub const fn subresource(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::UpdateSpec => "update-spec",
            Self::Delete => "delete",
        }
    }
}

/// One exact Role permission supplied by the trusted authorization layer.
#[derive(Clone, PartialEq, Eq)]
pub struct RolePermission {
    verb: CredentialResourceVerb,
    subresource: String,
}

impl RolePermission {
    /// Construct one exact verb/subresource pair.
    pub fn new(verb: CredentialResourceVerb, subresource: impl Into<String>) -> Self {
        Self {
            verb,
            subresource: subresource.into(),
        }
    }

    /// Return the resource verb.
    pub const fn verb(&self) -> CredentialResourceVerb {
        self.verb
    }

    /// Borrow the exact subresource.
    pub fn subresource(&self) -> &str {
        &self.subresource
    }
}

impl fmt::Debug for RolePermission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RolePermission")
            .field("verb", &self.verb)
            .field("subresource", &"<redacted>")
            .finish()
    }
}

/// Closed service failures that carry no caller-controlled diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialServiceErrorCode {
    /// A request failed strict decoding or field validation.
    Malformed,
    /// An outer message exceeded its fixed bound.
    Oversize,
    /// The operation deadline was absent or not after requested expiry.
    DeadlineExceeded,
    /// RBAC, allowed-operation, or consumer policy denied the operation.
    OperationDenied,
    /// The Provider process is unavailable, including a locked backing service.
    ProviderUnavailable,
    /// The referenced lease has expired.
    LeaseExpired,
    /// The referenced lease has been revoked.
    LeaseRevoked,
    /// A Provider response violated the service contract.
    InvariantFailure,
}

impl CredentialServiceErrorCode {
    /// Return the canonical wire-stable Credential error code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malformed | Self::Oversize => "credential-schema-invalid",
            Self::DeadlineExceeded => "deadline-exceeded",
            Self::OperationDenied => "credential-operation-denied",
            Self::ProviderUnavailable => "credential-provider-unavailable",
            Self::LeaseExpired => "credential-lease-expired",
            Self::LeaseRevoked => "credential-lease-revoked",
            Self::InvariantFailure => "credential-invariant-failure",
        }
    }
}

/// A field-free service error safe for errors, logs, and diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialServiceError {
    code: CredentialServiceErrorCode,
}

impl CredentialServiceError {
    /// Construct an error from its stable closed code.
    pub const fn new(code: CredentialServiceErrorCode) -> Self {
        Self { code }
    }

    /// Return the stable error code.
    pub const fn code(self) -> CredentialServiceErrorCode {
        self.code
    }
}

impl fmt::Display for CredentialServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code.as_str())
    }
}

impl std::error::Error for CredentialServiceError {}

/// Shared strict request shape for all five methods.
///
/// There is deliberately no caller-selected operation-class field. The server
/// derives it from the selected method.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialRequest {
    credential_ref: ResourceRef,
    operation_id: String,
    idempotency_key: String,
    requested_expiry_unix_ms: u64,
    deadline_unix_ms: u64,
}

impl CredentialRequest {
    /// Construct and validate one bounded request.
    pub fn new(
        credential_ref: ResourceRef,
        operation_id: impl Into<String>,
        idempotency_key: impl Into<String>,
        requested_expiry_unix_ms: u64,
        deadline_unix_ms: u64,
    ) -> Result<Self, CredentialServiceError> {
        let operation_id = operation_id.into();
        let idempotency_key = idempotency_key.into();
        if credential_ref.resource_type().as_str() != "Credential"
            || !valid_request_id(&operation_id, MAX_OPERATION_ID_BYTES)
            || !valid_request_id(&idempotency_key, MAX_IDEMPOTENCY_KEY_BYTES)
            || requested_expiry_unix_ms == 0
            || deadline_unix_ms == 0
            || deadline_unix_ms > requested_expiry_unix_ms
        {
            return Err(malformed());
        }
        Ok(Self {
            credential_ref,
            operation_id,
            idempotency_key,
            requested_expiry_unix_ms,
            deadline_unix_ms,
        })
    }

    /// Borrow the target Credential reference for trusted routing.
    pub const fn credential_ref(&self) -> &ResourceRef {
        &self.credential_ref
    }

    /// Borrow the operation ID for trusted dispatch.
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Borrow the idempotency key for trusted dispatch.
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    /// Return the requested absolute expiry.
    pub const fn requested_expiry_unix_ms(&self) -> u64 {
        self.requested_expiry_unix_ms
    }

    /// Return the hard call deadline.
    pub const fn deadline_unix_ms(&self) -> u64 {
        self.deadline_unix_ms
    }
}

impl fmt::Debug for CredentialRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CredentialRequest(<redacted>)")
    }
}

/// Closed non-secret operation outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialOutcomeCode {
    /// The operation completed successfully.
    Success,
    /// Revocation changed an active lease to revoked.
    Revoked,
    /// The lease was already revoked.
    AlreadyRevoked,
}

/// Common non-secret response metadata.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialMetadata {
    /// One-way lease-handle representation.
    pub lease_handle: CredentialLeaseHandle,
    /// Current rotation generation.
    pub rotation_generation: u64,
    /// One-way source-version representation.
    pub source_version: CredentialSourceVersion,
    /// Absolute lease expiry.
    pub expires_at_unix_ms: u64,
    /// Current closed lease state.
    pub state: CredentialLeaseState,
    /// Closed service outcome.
    pub outcome: CredentialOutcomeCode,
}

impl fmt::Debug for CredentialMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CredentialMetadata(<redacted>)")
    }
}

/// One-way digest of the bus-authorized route parameters.
#[derive(Clone, PartialEq, Eq)]
pub struct DeliveryRouteDigest(String);

impl DeliveryRouteDigest {
    /// Parse exactly one `sha256:` lowercase digest.
    pub fn parse(value: impl Into<String>) -> Result<Self, CredentialServiceError> {
        let value = value.into();
        let valid = d2b_contracts_resource::v3::resource_schema::is_canonical_digest(&value)
            && value.len() == ROUTE_DIGEST_BYTES;
        if valid {
            Ok(Self(value))
        } else {
            Err(malformed())
        }
    }

    /// Borrow the authorized wire representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for DeliveryRouteDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeliveryRouteDigest(<redacted>)")
    }
}

/// Parameters authorized before establishing one end-to-end delivery session.
#[derive(Clone, PartialEq, Eq)]
pub struct DeliverySessionParams {
    credential_ref: ResourceRef,
    credential_uid: ResourceUid,
    credential_generation: ResourceGeneration,
    consumer_provider_ref: ResourceRef,
    consumer_component_generation: ResourceGeneration,
    audience: AudienceToken,
    operation_class: OperationClass,
    expiry_unix_ms: u64,
    deadline_unix_ms: u64,
    route_digest: DeliveryRouteDigest,
    schema_version: u32,
    max_token_bytes: u32,
    sequence: u64,
}

impl DeliverySessionParams {
    /// Construct a binding preimage for one sensitive-output method.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        credential_ref: ResourceRef,
        credential_uid: ResourceUid,
        credential_generation: ResourceGeneration,
        consumer_provider_ref: ResourceRef,
        consumer_component_generation: ResourceGeneration,
        audience: AudienceToken,
        operation_class: OperationClass,
        expiry_unix_ms: u64,
        deadline_unix_ms: u64,
        route_digest: DeliveryRouteDigest,
        max_token_bytes: u32,
        sequence: u64,
    ) -> Result<Self, CredentialServiceError> {
        if credential_ref.resource_type().as_str() != "Credential"
            || consumer_provider_ref.resource_type().as_str() != "Provider"
            || !matches!(
                operation_class,
                OperationClass::AcquireToken
                    | OperationClass::RefreshToken
                    | OperationClass::SignChallenge
            )
            || expiry_unix_ms == 0
            || deadline_unix_ms == 0
            || deadline_unix_ms > expiry_unix_ms
            || max_token_bytes == 0
            || max_token_bytes as usize > MAX_DELIVERY_RECORD_BYTES
            || sequence == 0
        {
            return Err(malformed());
        }
        Ok(Self {
            credential_ref,
            credential_uid,
            credential_generation,
            consumer_provider_ref,
            consumer_component_generation,
            audience,
            operation_class,
            expiry_unix_ms,
            deadline_unix_ms,
            route_digest,
            schema_version: DELIVERY_BINDING_SCHEMA_VERSION,
            max_token_bytes,
            sequence,
        })
    }

    /// Return the method-derived operation class.
    pub const fn operation_class(&self) -> OperationClass {
        self.operation_class
    }

    /// Borrow the Credential reference bound into this delivery session.
    pub const fn credential_ref(&self) -> &ResourceRef {
        &self.credential_ref
    }

    /// Borrow the consumer Provider reference bound into this delivery session.
    pub const fn consumer_provider_ref(&self) -> &ResourceRef {
        &self.consumer_provider_ref
    }

    /// Return the Credential UID bound into this delivery session.
    pub const fn credential_uid(&self) -> &ResourceUid {
        &self.credential_uid
    }

    /// Return the Credential generation bound into this delivery session.
    pub const fn credential_generation(&self) -> ResourceGeneration {
        self.credential_generation
    }

    /// Return the consumer component generation bound into this delivery
    /// session.
    pub const fn consumer_component_generation(&self) -> ResourceGeneration {
        self.consumer_component_generation
    }

    /// Borrow the audience token bound into this delivery session.
    pub const fn audience(&self) -> &AudienceToken {
        &self.audience
    }

    /// Return the absolute delivery-session expiry.
    pub const fn expiry_unix_ms(&self) -> u64 {
        self.expiry_unix_ms
    }

    /// Return the hard delivery-session deadline.
    pub const fn deadline_unix_ms(&self) -> u64 {
        self.deadline_unix_ms
    }

    /// Borrow the authorized route digest.
    pub const fn route_digest(&self) -> &DeliveryRouteDigest {
        &self.route_digest
    }

    /// Return the fixed binding schema version.
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Return the maximum plaintext record size.
    pub const fn max_token_bytes(&self) -> u32 {
        self.max_token_bytes
    }

    /// Return the replay-safe sequence number.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Complete the binding after the KK handshake supplies a transcript hash.
    pub fn complete(self, transcript_digest: TranscriptHash) -> DeliverySessionBinding {
        DeliverySessionBinding {
            params: self,
            transcript_digest,
        }
    }
}

impl fmt::Debug for DeliverySessionParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeliverySessionParams(<redacted>)")
    }
}

/// Provider and lease observations mapped to the stable service error set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialFailureState {
    /// The backing credential service is locked.
    Locked,
    /// The Provider process or backing service is unavailable.
    Unavailable,
    /// The authenticated caller was denied by policy.
    Denied,
    /// The lease is past its expiry.
    Expired,
    /// The lease was revoked.
    Revoked,
}

/// Map one observed failure state to its canonical closed service error.
pub const fn error_for_failure_state(state: CredentialFailureState) -> CredentialServiceError {
    let code = match state {
        CredentialFailureState::Locked | CredentialFailureState::Unavailable => {
            CredentialServiceErrorCode::ProviderUnavailable
        }
        CredentialFailureState::Denied => CredentialServiceErrorCode::OperationDenied,
        CredentialFailureState::Expired => CredentialServiceErrorCode::LeaseExpired,
        CredentialFailureState::Revoked => CredentialServiceErrorCode::LeaseRevoked,
    };
    CredentialServiceError::new(code)
}

/// Full delivery-session binding after Noise handshake completion.
#[derive(Clone, PartialEq, Eq)]
pub struct DeliverySessionBinding {
    params: DeliverySessionParams,
    transcript_digest: TranscriptHash,
}

impl DeliverySessionBinding {
    /// Borrow the pre-handshake parameters.
    pub const fn params(&self) -> &DeliverySessionParams {
        &self.params
    }

    /// Borrow the Noise transcript binding.
    pub const fn transcript_digest(&self) -> &TranscriptHash {
        &self.transcript_digest
    }
}

impl fmt::Debug for DeliverySessionBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeliverySessionBinding(<redacted>)")
    }
}

/// Response shape used for sensitive-output operations.
#[derive(Clone, PartialEq, Eq)]
pub struct DeliveryResponse {
    /// Non-secret lease metadata.
    pub metadata: CredentialMetadata,
    /// Parameters for the separate end-to-end delivery session.
    pub delivery_session_params: DeliverySessionParams,
}

impl fmt::Debug for DeliveryResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeliveryResponse(<redacted>)")
    }
}

/// Response shape for methods that never establish a delivery channel.
#[derive(Clone, PartialEq, Eq)]
pub struct MetadataResponse {
    /// Non-secret lease metadata.
    pub metadata: CredentialMetadata,
}

/// Outer response for `AcquireToken`.
pub type AcquireTokenResponse = DeliveryResponse;
/// Outer response for `RefreshToken`.
pub type RefreshTokenResponse = DeliveryResponse;
/// Outer response for `RevokeToken`.
pub type RevokeTokenResponse = MetadataResponse;
/// Outer response for `SignChallenge`.
pub type SignChallengeResponse = DeliveryResponse;
/// Outer response for `InspectMetadata`.
pub type InspectMetadataResponse = MetadataResponse;

impl fmt::Debug for MetadataResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MetadataResponse(<redacted>)")
    }
}

/// Method-specific service result.
#[derive(Clone, PartialEq, Eq)]
pub enum CredentialResponse {
    /// Response to `AcquireToken`.
    AcquireToken(DeliveryResponse),
    /// Response to `RefreshToken`.
    RefreshToken(DeliveryResponse),
    /// Response to `RevokeToken`.
    RevokeToken(MetadataResponse),
    /// Response to `SignChallenge`.
    SignChallenge(DeliveryResponse),
    /// Response to `InspectMetadata`.
    InspectMetadata(MetadataResponse),
}

impl CredentialResponse {
    /// Return the response method.
    pub const fn method(&self) -> CredentialMethod {
        match self {
            Self::AcquireToken(_) => CredentialMethod::AcquireToken,
            Self::RefreshToken(_) => CredentialMethod::RefreshToken,
            Self::RevokeToken(_) => CredentialMethod::RevokeToken,
            Self::SignChallenge(_) => CredentialMethod::SignChallenge,
            Self::InspectMetadata(_) => CredentialMethod::InspectMetadata,
        }
    }

    /// Borrow delivery parameters only for a sensitive-output method.
    pub fn delivery_session_params(&self) -> Option<&DeliverySessionParams> {
        match self {
            Self::AcquireToken(response)
            | Self::RefreshToken(response)
            | Self::SignChallenge(response) => Some(&response.delivery_session_params),
            Self::RevokeToken(_) | Self::InspectMetadata(_) => None,
        }
    }
}

impl fmt::Debug for CredentialResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CredentialResponse::{:?}(<redacted>)", self.method())
    }
}

/// Authorization result derived by the authenticated service adapter.
///
/// For sensitive-output methods this carries the complete delivery binding
/// constructed during route authorization. The Provider may use it but cannot
/// replace any of its authority-bearing fields.
pub struct CredentialAuthorization {
    delivery_session_params: Option<DeliverySessionParams>,
    authenticated_subject: Option<AuthenticatedSubjectContext>,
    user_ref: Option<ResourceRef>,
    session_proof: Option<Arc<dyn Any + Send + Sync>>,
    authenticated_session: Option<CredentialSessionBinding>,
}

impl Clone for CredentialAuthorization {
    fn clone(&self) -> Self {
        Self {
            delivery_session_params: self.delivery_session_params.clone(),
            authenticated_subject: self.authenticated_subject.clone(),
            user_ref: self.user_ref.clone(),
            session_proof: self.session_proof.clone(),
            authenticated_session: self.authenticated_session.clone(),
        }
    }
}

impl PartialEq for CredentialAuthorization {
    fn eq(&self, other: &Self) -> bool {
        self.delivery_session_params == other.delivery_session_params
            && self.authenticated_subject == other.authenticated_subject
            && self.user_ref == other.user_ref
            && match (&self.session_proof, &other.session_proof) {
                (None, None) => true,
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                _ => false,
            }
            && self.authenticated_session == other.authenticated_session
    }
}

impl Eq for CredentialAuthorization {}

impl fmt::Debug for CredentialAuthorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CredentialAuthorization(<redacted>)")
    }
}

impl CredentialAuthorization {
    /// Construct an authorization result for one exact method.
    pub fn new(
        method: CredentialMethod,
        delivery_session_params: Option<DeliverySessionParams>,
    ) -> Result<Self, CredentialServiceError> {
        if delivery_session_params.is_some() != method.requires_delivery()
            || delivery_session_params
                .as_ref()
                .is_some_and(|params| params.operation_class() != method.operation_class())
        {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::InvariantFailure,
            ));
        }
        Ok(Self {
            delivery_session_params,
            authenticated_subject: None,
            user_ref: None,
            session_proof: None,
            authenticated_session: None,
        })
    }

    /// Construct an authorization result carrying trusted subject context.
    pub fn new_for_subject(
        method: CredentialMethod,
        delivery_session_params: Option<DeliverySessionParams>,
        authenticated_subject: AuthenticatedSubjectContext,
    ) -> Result<Self, CredentialServiceError> {
        let mut authorization = Self::new(method, delivery_session_params)?;
        authorization.authenticated_subject = Some(authenticated_subject);
        Ok(authorization)
    }

    /// Attach the authenticated Provider session established by the
    /// ComponentSession adapter.
    pub fn with_authenticated_session(
        mut self,
        session: CredentialSessionBinding,
    ) -> Result<Self, CredentialServiceError> {
        self.authenticated_session = Some(session);
        Ok(self)
    }

    /// Borrow the adapter-authorized delivery binding, when the method needs one.
    pub const fn delivery_session_params(&self) -> Option<&DeliverySessionParams> {
        self.delivery_session_params.as_ref()
    }

    /// Borrow trusted subject context supplied by the authenticated adapter.
    pub const fn authenticated_subject_context(&self) -> Option<&AuthenticatedSubjectContext> {
        self.authenticated_subject.as_ref()
    }

    /// Borrow the exact authenticated User scope claim, when one was supplied.
    pub const fn user_ref(&self) -> Option<&ResourceRef> {
        self.user_ref.as_ref()
    }

    /// Attach an exact User scope claim without changing the authenticated
    /// Provider subject.
    pub fn with_user_ref(
        mut self,
        user_ref: Option<ResourceRef>,
    ) -> Result<Self, CredentialServiceError> {
        if user_ref
            .as_ref()
            .is_some_and(|reference| reference.resource_type().as_str() != "User")
        {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::OperationDenied,
            ));
        }
        self.user_ref = user_ref;
        Ok(self)
    }

    /// Borrow the authenticated session, when the adapter supplied one.
    pub const fn authenticated_session(&self) -> Option<&CredentialSessionBinding> {
        self.authenticated_session.as_ref()
    }

    /// Attach one provider-owned authenticated session proof.
    ///
    /// The proof is intentionally erased at this contract boundary. Each
    /// Provider downcasts it to its own private proof type and authenticates
    /// that proof against its retained authority.
    pub fn with_session_proof<T>(mut self, proof: T) -> Self
    where
        T: Any + Send + Sync,
    {
        self.session_proof = Some(Arc::new(proof));
        self
    }

    /// Attach a shared provider-owned session proof to another authorization.
    pub fn with_shared_session_proof<T>(mut self, proof: Arc<T>) -> Self
    where
        T: Any + Send + Sync,
    {
        self.session_proof = Some(proof);
        self
    }

    /// Borrow a provider-owned session proof of the requested concrete type.
    pub fn session_proof<T>(&self) -> Option<&T>
    where
        T: Any + Send + Sync,
    {
        self.session_proof
            .as_deref()
            .and_then(|proof| proof.downcast_ref::<T>())
    }
}

/// Authenticated, bounded lifetime context for one Credential service session.
///
/// The subject context is established by the ComponentSession adapter and
/// cannot be reconstructed from a peer payload. The expiry is deliberately
/// carried separately from the identity context because it belongs to the
/// service admission decision rather than to the durable subject identity.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialSessionBinding {
    authenticated_subject: AuthenticatedSubjectContext,
    expires_at_unix_ms: u64,
}

impl CredentialSessionBinding {
    /// Bind an authenticated subject context to a nonzero session expiry.
    pub fn new(
        authenticated_subject: AuthenticatedSubjectContext,
        expires_at_unix_ms: u64,
    ) -> Result<Self, CredentialServiceError> {
        if expires_at_unix_ms == 0 {
            return Err(malformed());
        }
        Ok(Self {
            authenticated_subject,
            expires_at_unix_ms,
        })
    }

    /// Borrow the authenticated subject context.
    pub const fn authenticated_subject(&self) -> &AuthenticatedSubjectContext {
        &self.authenticated_subject
    }

    /// Return the absolute session expiry.
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }
}

impl fmt::Debug for CredentialSessionBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialSessionBinding(<redacted>)")
    }
}

/// Provider-side implementation of the five service methods.
#[async_trait::async_trait]
pub trait CredentialProvider: Send + Sync {
    /// Dispatch one already-admitted exact method.
    fn dispatch(
        &self,
        method: CredentialMethod,
        request: &CredentialRequest,
        authorization: &CredentialAuthorization,
    ) -> Result<CredentialResponse, CredentialServiceError>;

    /// Dispatch one method without blocking the ComponentSession runtime.
    async fn dispatch_async(
        &self,
        method: CredentialMethod,
        request: &CredentialRequest,
        authorization: &CredentialAuthorization,
    ) -> Result<CredentialResponse, CredentialServiceError> {
        self.dispatch(method, request, authorization)
    }
}

/// Dispatch to a Provider and enforce the authorization-owned response shape.
pub fn dispatch_authorized_provider<P: CredentialProvider + ?Sized>(
    provider: &P,
    method: CredentialMethod,
    request: &CredentialRequest,
    authorization: &CredentialAuthorization,
) -> Result<CredentialResponse, CredentialServiceError> {
    let response = provider.dispatch(method, request, authorization)?;
    if response.method() != method
        || response.delivery_session_params() != authorization.delivery_session_params()
    {
        return Err(CredentialServiceError::new(
            CredentialServiceErrorCode::InvariantFailure,
        ));
    }
    Ok(response)
}

/// Dispatch asynchronously and enforce the authorization-owned response shape.
pub async fn dispatch_authorized_provider_async<P: CredentialProvider + ?Sized>(
    provider: &P,
    method: CredentialMethod,
    request: &CredentialRequest,
    authorization: &CredentialAuthorization,
) -> Result<CredentialResponse, CredentialServiceError> {
    let response = provider
        .dispatch_async(method, request, authorization)
        .await?;
    if response.method() != method
        || response.delivery_session_params() != authorization.delivery_session_params()
    {
        return Err(CredentialServiceError::new(
            CredentialServiceErrorCode::InvariantFailure,
        ));
    }
    Ok(response)
}

/// One plaintext delivery record whose storage is erased on clear and drop.
pub struct SensitiveDeliveryRecord {
    bytes: Vec<AtomicU8>,
    cleared: bool,
}

impl SensitiveDeliveryRecord {
    /// Construct one bounded, non-empty plaintext record.
    pub fn new(mut bytes: Vec<u8>, max_token_bytes: u32) -> Result<Self, CredentialServiceError> {
        if bytes.is_empty()
            || bytes.len() > max_token_bytes as usize
            || bytes.len() > MAX_DELIVERY_RECORD_BYTES
        {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::Oversize,
            ));
        }
        let retained = bytes.iter().copied().map(AtomicU8::new).collect();
        bytes.fill(0);
        Ok(Self {
            bytes: retained,
            cleared: false,
        })
    }

    /// Copy plaintext into an exact-size caller buffer while the record is live.
    ///
    /// The caller owns and must erase the destination after use.
    pub fn copy_to(&self, destination: &mut [u8]) -> Result<(), CredentialServiceError> {
        if self.cleared {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::InvariantFailure,
            ));
        }
        if destination.len() != self.bytes.len() {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::Malformed,
            ));
        }
        for (destination, source) in destination.iter_mut().zip(&self.bytes) {
            *destination = source.load(Ordering::SeqCst);
        }
        Ok(())
    }

    /// Erase the retained plaintext immediately.
    pub fn clear(&mut self) {
        for byte in &self.bytes {
            byte.store(0, Ordering::SeqCst);
        }
        self.cleared = true;
    }

    /// Whether explicit extraction cleanup has erased this record.
    pub const fn is_cleared(&self) -> bool {
        self.cleared
    }

    /// Whether every retained plaintext byte has been erased.
    pub fn is_zeroized(&self) -> bool {
        self.bytes
            .iter()
            .all(|byte| byte.load(Ordering::SeqCst) == 0)
    }
}

impl fmt::Debug for SensitiveDeliveryRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SensitiveDeliveryRecord(<redacted>)")
    }
}

impl Drop for SensitiveDeliveryRecord {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Strict protobuf codec implemented by every outer service DTO.
pub trait CredentialWire: Sized {
    /// Append the canonical protobuf encoding.
    fn encode_wire(&self, output: &mut Vec<u8>);
    /// Decode one complete message and reject unknown or duplicate fields.
    fn decode_wire(bytes: &[u8]) -> Result<Self, CredentialServiceError>;
}

/// Strictly encode an outer DTO with a fixed message-size ceiling.
pub fn encode_outer<T: CredentialWire>(value: &T) -> Result<Vec<u8>, CredentialServiceError> {
    let mut bytes = Vec::new();
    value.encode_wire(&mut bytes);
    if bytes.len() > MAX_CREDENTIAL_MESSAGE_BYTES {
        Err(CredentialServiceError::new(
            CredentialServiceErrorCode::Oversize,
        ))
    } else {
        Ok(bytes)
    }
}

/// Strictly decode an outer DTO with a fixed message-size ceiling.
pub fn decode_outer<T: CredentialWire>(bytes: &[u8]) -> Result<T, CredentialServiceError> {
    if bytes.len() > MAX_CREDENTIAL_MESSAGE_BYTES {
        return Err(CredentialServiceError::new(
            CredentialServiceErrorCode::Oversize,
        ));
    }
    T::decode_wire(bytes)
}

/// Authorize one service method against exact spec and Role operation classes.
pub fn authorize_operation(
    method: CredentialMethod,
    allowed_operations: &[OperationClass],
    permission: &RolePermission,
) -> Result<(), CredentialServiceError> {
    let operation = method.operation_class();
    if permission.verb() != CredentialResourceVerb::UseCredential
        || permission.subresource() != method.subresource()
        || !allowed_operations.contains(&operation)
    {
        Err(CredentialServiceError::new(
            CredentialServiceErrorCode::OperationDenied,
        ))
    } else {
        Ok(())
    }
}

/// Require ordinary CRUD and exact supplemental administrative permission.
pub fn authorize_admin(
    action: CredentialAdminAction,
    ordinary_permission: &RolePermission,
    admin_permission: &RolePermission,
) -> Result<(), CredentialServiceError> {
    if ordinary_permission.verb() != action.ordinary_verb()
        || !ordinary_permission.subresource().is_empty()
        || admin_permission.verb() != CredentialResourceVerb::AdminCredential
        || admin_permission.subresource() != action.subresource()
    {
        Err(CredentialServiceError::new(
            CredentialServiceErrorCode::OperationDenied,
        ))
    } else {
        Ok(())
    }
}

impl CredentialWire for CredentialRequest {
    fn encode_wire(&self, output: &mut Vec<u8>) {
        write_string(output, 1, &self.credential_ref.to_canonical_string());
        write_string(output, 2, &self.operation_id);
        write_string(output, 3, &self.idempotency_key);
        write_u64(output, 4, self.requested_expiry_unix_ms);
        write_u64(output, 5, self.deadline_unix_ms);
    }

    fn decode_wire(bytes: &[u8]) -> Result<Self, CredentialServiceError> {
        let mut reader = WireReader::new(bytes);
        let mut credential_ref = None;
        let mut operation_id = None;
        let mut idempotency_key = None;
        let mut requested_expiry = None;
        let mut deadline = None;
        while let Some((field, wire)) = reader.key()? {
            match (field, wire) {
                (1, 2) => set_once(
                    &mut credential_ref,
                    ResourceRef::parse(reader.string()?).ok(),
                )?,
                (2, 2) => set_once(&mut operation_id, Some(reader.string()?.to_owned()))?,
                (3, 2) => set_once(&mut idempotency_key, Some(reader.string()?.to_owned()))?,
                (4, 0) => set_once(&mut requested_expiry, Some(reader.varint()?))?,
                (5, 0) => set_once(&mut deadline, Some(reader.varint()?))?,
                _ => return Err(malformed()),
            }
        }
        Self::new(
            credential_ref.ok_or_else(malformed)?,
            operation_id.ok_or_else(malformed)?,
            idempotency_key.ok_or_else(malformed)?,
            requested_expiry.ok_or_else(malformed)?,
            deadline.ok_or_else(malformed)?,
        )
    }
}

impl CredentialWire for CredentialMetadata {
    fn encode_wire(&self, output: &mut Vec<u8>) {
        write_string(output, 1, self.lease_handle.as_opaque_str());
        write_u64(output, 2, self.rotation_generation);
        write_string(output, 3, self.source_version.as_opaque_str());
        write_u64(output, 4, self.expires_at_unix_ms);
        write_u64(output, 5, lease_state_code(self.state));
        write_u64(output, 6, outcome_code(self.outcome));
    }

    fn decode_wire(bytes: &[u8]) -> Result<Self, CredentialServiceError> {
        let mut reader = WireReader::new(bytes);
        let mut lease_handle = None;
        let mut rotation_generation = None;
        let mut source_version = None;
        let mut expires_at = None;
        let mut state = None;
        let mut outcome = None;
        while let Some((field, wire)) = reader.key()? {
            match (field, wire) {
                (1, 2) => set_once(
                    &mut lease_handle,
                    CredentialLeaseHandle::from_opaque_digest(reader.string()?).ok(),
                )?,
                (2, 0) => set_once(&mut rotation_generation, Some(reader.varint()?))?,
                (3, 2) => set_once(
                    &mut source_version,
                    CredentialSourceVersion::from_opaque_digest(reader.string()?).ok(),
                )?,
                (4, 0) => set_once(&mut expires_at, Some(reader.varint()?))?,
                (5, 0) => set_once(&mut state, decode_lease_state(reader.varint()?))?,
                (6, 0) => set_once(&mut outcome, decode_outcome(reader.varint()?))?,
                _ => return Err(malformed()),
            }
        }
        let value = Self {
            lease_handle: lease_handle.ok_or_else(malformed)?,
            rotation_generation: rotation_generation.ok_or_else(malformed)?,
            source_version: source_version.ok_or_else(malformed)?,
            expires_at_unix_ms: expires_at.ok_or_else(malformed)?,
            state: state.ok_or_else(malformed)?,
            outcome: outcome.ok_or_else(malformed)?,
        };
        if value.rotation_generation == 0 || value.expires_at_unix_ms == 0 {
            return Err(malformed());
        }
        Ok(value)
    }
}

impl CredentialWire for DeliverySessionParams {
    fn encode_wire(&self, output: &mut Vec<u8>) {
        write_string(output, 1, &self.credential_ref.to_canonical_string());
        write_string(output, 2, &self.credential_uid.to_canonical_string());
        write_u64(output, 3, self.credential_generation.get());
        write_string(output, 4, &self.consumer_provider_ref.to_canonical_string());
        write_u64(output, 5, self.consumer_component_generation.get());
        write_string(output, 6, self.audience.as_str());
        write_u64(output, 7, operation_code(self.operation_class));
        write_u64(output, 8, self.expiry_unix_ms);
        write_u64(output, 9, self.deadline_unix_ms);
        write_string(output, 10, self.route_digest.as_str());
        write_u64(output, 11, u64::from(self.schema_version));
        write_u64(output, 12, u64::from(self.max_token_bytes));
        write_u64(output, 13, self.sequence);
    }

    fn decode_wire(bytes: &[u8]) -> Result<Self, CredentialServiceError> {
        let mut reader = WireReader::new(bytes);
        let mut credential_ref = None;
        let mut credential_uid = None;
        let mut credential_generation = None;
        let mut consumer_ref = None;
        let mut consumer_generation = None;
        let mut audience = None;
        let mut operation = None;
        let mut expiry = None;
        let mut deadline = None;
        let mut route_digest = None;
        let mut schema_version = None;
        let mut max_token_bytes = None;
        let mut sequence = None;
        while let Some((field, wire)) = reader.key()? {
            match (field, wire) {
                (1, 2) => set_once(
                    &mut credential_ref,
                    ResourceRef::parse(reader.string()?).ok(),
                )?,
                (2, 2) => set_once(
                    &mut credential_uid,
                    ResourceUid::parse(reader.string()?).ok(),
                )?,
                (3, 0) => set_once(
                    &mut credential_generation,
                    ResourceGeneration::new(reader.varint()?).ok(),
                )?,
                (4, 2) => set_once(&mut consumer_ref, ResourceRef::parse(reader.string()?).ok())?,
                (5, 0) => set_once(
                    &mut consumer_generation,
                    ResourceGeneration::new(reader.varint()?).ok(),
                )?,
                (6, 2) => set_once(&mut audience, AudienceToken::parse(reader.string()?).ok())?,
                (7, 0) => set_once(&mut operation, decode_operation(reader.varint()?))?,
                (8, 0) => set_once(&mut expiry, Some(reader.varint()?))?,
                (9, 0) => set_once(&mut deadline, Some(reader.varint()?))?,
                (10, 2) => set_once(
                    &mut route_digest,
                    DeliveryRouteDigest::parse(reader.string()?).ok(),
                )?,
                (11, 0) => set_once(&mut schema_version, u32::try_from(reader.varint()?).ok())?,
                (12, 0) => set_once(&mut max_token_bytes, u32::try_from(reader.varint()?).ok())?,
                (13, 0) => set_once(&mut sequence, Some(reader.varint()?))?,
                _ => return Err(malformed()),
            }
        }
        if schema_version != Some(DELIVERY_BINDING_SCHEMA_VERSION) {
            return Err(malformed());
        }
        Self::new(
            credential_ref.ok_or_else(malformed)?,
            credential_uid.ok_or_else(malformed)?,
            credential_generation.ok_or_else(malformed)?,
            consumer_ref.ok_or_else(malformed)?,
            consumer_generation.ok_or_else(malformed)?,
            audience.ok_or_else(malformed)?,
            operation.ok_or_else(malformed)?,
            expiry.ok_or_else(malformed)?,
            deadline.ok_or_else(malformed)?,
            route_digest.ok_or_else(malformed)?,
            max_token_bytes.ok_or_else(malformed)?,
            sequence.ok_or_else(malformed)?,
        )
    }
}

impl CredentialWire for DeliveryResponse {
    fn encode_wire(&self, output: &mut Vec<u8>) {
        write_message(output, 1, &self.metadata);
        write_message(output, 2, &self.delivery_session_params);
    }

    fn decode_wire(bytes: &[u8]) -> Result<Self, CredentialServiceError> {
        let mut reader = WireReader::new(bytes);
        let mut metadata = None;
        let mut delivery = None;
        while let Some((field, wire)) = reader.key()? {
            match (field, wire) {
                (1, 2) => set_once(
                    &mut metadata,
                    CredentialMetadata::decode_wire(reader.bytes()?).ok(),
                )?,
                (2, 2) => set_once(
                    &mut delivery,
                    DeliverySessionParams::decode_wire(reader.bytes()?).ok(),
                )?,
                _ => return Err(malformed()),
            }
        }
        Ok(Self {
            metadata: metadata.ok_or_else(malformed)?,
            delivery_session_params: delivery.ok_or_else(malformed)?,
        })
    }
}

impl CredentialWire for MetadataResponse {
    fn encode_wire(&self, output: &mut Vec<u8>) {
        write_message(output, 1, &self.metadata);
    }

    fn decode_wire(bytes: &[u8]) -> Result<Self, CredentialServiceError> {
        let mut reader = WireReader::new(bytes);
        let Some((1, 2)) = reader.key()? else {
            return Err(malformed());
        };
        let metadata = CredentialMetadata::decode_wire(reader.bytes()?)?;
        if reader.key()?.is_some() {
            return Err(malformed());
        }
        Ok(Self { metadata })
    }
}

fn malformed() -> CredentialServiceError {
    CredentialServiceError::new(CredentialServiceErrorCode::Malformed)
}

fn valid_request_id(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b':'))
}

fn set_once<T>(slot: &mut Option<T>, value: Option<T>) -> Result<(), CredentialServiceError> {
    let value = value.ok_or_else(malformed)?;
    if slot.replace(value).is_some() {
        Err(malformed())
    } else {
        Ok(())
    }
}

fn operation_code(value: OperationClass) -> u64 {
    match value {
        OperationClass::AcquireToken => 1,
        OperationClass::RefreshToken => 2,
        OperationClass::RevokeToken => 3,
        OperationClass::SignChallenge => 4,
        OperationClass::InspectMetadata => 5,
    }
}

fn decode_operation(value: u64) -> Option<OperationClass> {
    match value {
        1 => Some(OperationClass::AcquireToken),
        2 => Some(OperationClass::RefreshToken),
        3 => Some(OperationClass::RevokeToken),
        4 => Some(OperationClass::SignChallenge),
        5 => Some(OperationClass::InspectMetadata),
        _ => None,
    }
}

fn lease_state_code(value: CredentialLeaseState) -> u64 {
    match value {
        CredentialLeaseState::Active => 1,
        CredentialLeaseState::Expired => 2,
        CredentialLeaseState::Revoked => 3,
        CredentialLeaseState::Unknown => 4,
    }
}

fn decode_lease_state(value: u64) -> Option<CredentialLeaseState> {
    match value {
        1 => Some(CredentialLeaseState::Active),
        2 => Some(CredentialLeaseState::Expired),
        3 => Some(CredentialLeaseState::Revoked),
        4 => Some(CredentialLeaseState::Unknown),
        _ => None,
    }
}

fn outcome_code(value: CredentialOutcomeCode) -> u64 {
    match value {
        CredentialOutcomeCode::Success => 1,
        CredentialOutcomeCode::Revoked => 2,
        CredentialOutcomeCode::AlreadyRevoked => 3,
    }
}

fn decode_outcome(value: u64) -> Option<CredentialOutcomeCode> {
    match value {
        1 => Some(CredentialOutcomeCode::Success),
        2 => Some(CredentialOutcomeCode::Revoked),
        3 => Some(CredentialOutcomeCode::AlreadyRevoked),
        _ => None,
    }
}

fn write_key(output: &mut Vec<u8>, field: u32, wire: u8) {
    write_varint(output, u64::from((field << 3) | u32::from(wire)));
}

fn write_varint(output: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        output.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

fn write_u64(output: &mut Vec<u8>, field: u32, value: u64) {
    write_key(output, field, 0);
    write_varint(output, value);
}

fn write_string(output: &mut Vec<u8>, field: u32, value: &str) {
    write_key(output, field, 2);
    write_varint(output, value.len() as u64);
    output.extend_from_slice(value.as_bytes());
}

fn write_message<T: CredentialWire>(output: &mut Vec<u8>, field: u32, value: &T) {
    let mut nested = Vec::new();
    value.encode_wire(&mut nested);
    write_key(output, field, 2);
    write_varint(output, nested.len() as u64);
    output.extend_from_slice(&nested);
}

struct WireReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> WireReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn key(&mut self) -> Result<Option<(u32, u8)>, CredentialServiceError> {
        if self.offset == self.bytes.len() {
            return Ok(None);
        }
        let start = self.offset;
        let key = self.varint()?;
        if varint_len(key) != self.offset - start {
            return Err(malformed());
        }
        let field = u32::try_from(key >> 3).map_err(|_| malformed())?;
        let wire = (key & 7) as u8;
        if field == 0 {
            return Err(malformed());
        }
        Ok(Some((field, wire)))
    }

    fn varint(&mut self) -> Result<u64, CredentialServiceError> {
        let mut value = 0_u64;
        for shift in (0..=63).step_by(7) {
            let byte = *self.bytes.get(self.offset).ok_or_else(malformed)?;
            self.offset += 1;
            if shift == 63 && byte > 1 {
                return Err(malformed());
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(malformed())
    }

    fn bytes(&mut self) -> Result<&'a [u8], CredentialServiceError> {
        let start = self.offset;
        let raw_length = self.varint()?;
        if varint_len(raw_length) != self.offset - start {
            return Err(malformed());
        }
        let length = usize::try_from(raw_length).map_err(|_| malformed())?;
        let end = self.offset.checked_add(length).ok_or_else(malformed)?;
        let value = self.bytes.get(self.offset..end).ok_or_else(malformed)?;
        self.offset = end;
        Ok(value)
    }

    fn string(&mut self) -> Result<&'a str, CredentialServiceError> {
        core::str::from_utf8(self.bytes()?).map_err(|_| malformed())
    }
}

fn varint_len(mut value: u64) -> usize {
    let mut length = 1;
    while value >= 0x80 {
        value >>= 7;
        length += 1;
    }
    length
}
