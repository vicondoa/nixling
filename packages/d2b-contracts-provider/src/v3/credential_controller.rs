//! Neutral Credential controller, audit, and telemetry contracts.
//!
//! Provider implementations receive authorization-owned service bindings
//! separately. Controller call plans intentionally contain no delivery binding
//! field, so a controller cannot propose or replace one.

use core::fmt;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::sync::{Mutex, MutexGuard};

use sha2::{Digest, Sha256};

use super::credential::{
    CredentialLeaseState, CredentialMethod, CredentialRevocationPolicy, CredentialRotationPolicy,
    OperationClass, PlacementBinding, RevocationAction, RolePermission, RotationPolicyClass,
};
use d2b_contracts_resource::v3::ResourceUid;

/// Fixed interval between Credential metadata observations.
pub const CREDENTIAL_OBSERVE_INTERVAL_MS: u64 = 30_000;
/// Maximum active leases owned by one Credential Provider controller instance.
pub const MAX_LOCAL_CREDENTIAL_LEASES: u32 = 256;
/// Finalizer owned by Credential Provider controllers.
pub const CREDENTIAL_PROVIDER_REVOKE_FINALIZER: &str = "credential.d2bus.org/provider-revoke";

const FORBIDDEN_AMBIENT_CREDENTIAL_KEYS: &[&str] = &[
    "AWS_ACCESS_KEY_ID",
    "AWS_CONFIG_FILE",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_EC2_METADATA_SERVICE_ENDPOINT",
    "AWS_PROFILE",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AZURE_CLIENT_CERTIFICATE_PATH",
    "AZURE_CLIENT_ID",
    "AZURE_CLIENT_SECRET",
    "AZURE_FEDERATED_TOKEN_FILE",
    "AZURE_TENANT_ID",
    "AZURE_USERNAME",
    "AZURE_PASSWORD",
    "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE",
    "CLOUDSDK_CONFIG",
    "GCE_METADATA_HOST",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_GHA_CREDS_PATH",
    "GOOGLE_OAUTH_ACCESS_TOKEN",
    "IDENTITY_ENDPOINT",
    "MSI_ENDPOINT",
];

/// Reject ambient cloud SDK credential-chain environment names.
///
/// Values are intentionally never inspected. Provider processes must acquire
/// credentials only through their injected client and authenticated session.
pub fn reject_ambient_credential_chain(
    keys: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<(), CredentialControllerError> {
    if keys
        .into_iter()
        .any(|key| FORBIDDEN_AMBIENT_CREDENTIAL_KEYS.contains(&key.as_ref()))
    {
        return Err(CredentialControllerError::OperationDenied);
    }
    Ok(())
}

/// Closed controller contract failures with no caller-controlled diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialControllerError {
    /// An input violated a fixed controller invariant.
    InvalidInput,
    /// The exact Role subresource or allowed operation was absent.
    OperationDenied,
    /// The service call deadline was absent or already elapsed.
    DeadlineExceeded,
    /// The same Credential is already being handled by this controller.
    AlreadyRunning,
}

impl fmt::Display for CredentialControllerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "credential-invariant-failure",
            Self::OperationDenied => "credential-operation-denied",
            Self::DeadlineExceeded => "deadline-exceeded",
            Self::AlreadyRunning => "credential-queue-pressure",
        })
    }
}

impl std::error::Error for CredentialControllerError {}

/// A bounded, redacted idempotency key used only in a service request.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialIdempotencyKey([u8; 32]);

impl CredentialIdempotencyKey {
    /// Derive a stable key from Credential UID, rotation generation, and the
    /// method-derived operation class. No resource name or secret is accepted.
    pub fn derive(
        credential_uid: &ResourceUid,
        rotation_generation: u64,
        method: CredentialMethod,
    ) -> Result<Self, CredentialControllerError> {
        if rotation_generation == 0 {
            return Err(CredentialControllerError::InvalidInput);
        }
        let mut hasher = Sha256::new();
        hasher.update(credential_uid.as_str().as_bytes());
        hasher.update(rotation_generation.to_le_bytes());
        hasher.update(method.subresource().as_bytes());
        Ok(Self(hasher.finalize().into()))
    }

    /// Render the fixed 64-character request value.
    ///
    /// This value is Credential-derived and must not be logged, audited without
    /// a second one-way digest, or attached to telemetry.
    pub fn request_value(&self) -> String {
        let mut rendered = String::with_capacity(64);
        for byte in self.0 {
            write!(&mut rendered, "{byte:02x}").expect("writing to a String cannot fail");
        }
        rendered
    }
}

impl fmt::Debug for CredentialIdempotencyKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialIdempotencyKey(<redacted>)")
    }
}

impl fmt::Display for CredentialIdempotencyKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialIdempotencyKey(<redacted>)")
    }
}

/// One authorization-checked Credential service call planned by a controller.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialControllerCall {
    method: CredentialMethod,
    idempotency_key: CredentialIdempotencyKey,
    deadline_unix_ms: u64,
}

impl CredentialControllerCall {
    /// Build a call only when both policy and the exact `use-credential`
    /// Role subresource admit the method.
    pub fn authorize(
        credential_uid: &ResourceUid,
        rotation_generation: u64,
        method: CredentialMethod,
        allowed_operations: &[OperationClass],
        role_permission: &RolePermission,
        now_unix_ms: u64,
        deadline_unix_ms: u64,
    ) -> Result<Self, CredentialControllerError> {
        if deadline_unix_ms == 0 || deadline_unix_ms <= now_unix_ms {
            return Err(CredentialControllerError::DeadlineExceeded);
        }
        if role_permission.verb() != super::credential::CredentialResourceVerb::UseCredential
            || role_permission.subresource() != method.subresource()
            || !allowed_operations.contains(&method.operation_class())
        {
            return Err(CredentialControllerError::OperationDenied);
        }
        Ok(Self {
            method,
            idempotency_key: CredentialIdempotencyKey::derive(
                credential_uid,
                rotation_generation,
                method,
            )?,
            deadline_unix_ms,
        })
    }

    /// Return the method selected by controller policy.
    pub const fn method(&self) -> CredentialMethod {
        self.method
    }

    /// Return the exact Role subresource already checked for this call.
    pub const fn subresource(&self) -> &'static str {
        self.method.subresource()
    }

    /// Borrow the redacted request-only idempotency key.
    pub const fn idempotency_key(&self) -> &CredentialIdempotencyKey {
        &self.idempotency_key
    }

    /// Return the hard absolute service-call deadline.
    pub const fn deadline_unix_ms(&self) -> u64 {
        self.deadline_unix_ms
    }
}

impl fmt::Debug for CredentialControllerCall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialControllerCall")
            .field("method", &self.method)
            .field("idempotency_key", &"<redacted>")
            .field("deadline_unix_ms", &self.deadline_unix_ms)
            .finish()
    }
}

/// Closed condition projection owned by the Credential controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialControllerConditions {
    /// An active replacement-capable lease is available.
    pub credential_ready: bool,
    /// Proactive rotation is due.
    pub rotation_due: bool,
    /// The Provider process or its backing client is unavailable.
    pub provider_unavailable: bool,
    /// The prior lease was revoked and no replacement is active.
    pub lease_revoked: bool,
}

/// Closed handler disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialControllerDisposition {
    /// No further work is currently required.
    Converged,
    /// A service call must complete before convergence.
    Pending,
    /// The resource remains usable only in a degraded state.
    Degraded,
    /// Work must resume at a bounded later time.
    Requeue,
    /// The current retry budget is exhausted.
    Failed,
    /// The owned finalizer may be cleared.
    Finalized,
}

/// Closed controller outcome code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialControllerOutcome {
    /// The handler converged or planned ordinary work.
    Success,
    /// The Provider was unreachable.
    ProviderUnavailable,
    /// The active lease ceiling prevented acquisition.
    QueuePressure,
    /// Proactive rotation exhausted its bounded retry budget.
    RotationFailed,
    /// Drain policy is waiting for natural expiry.
    WaitingForExpiry,
}

/// Result of one controller handler pass.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialControllerDecision {
    /// Optional authorization-checked service call.
    pub call: Option<CredentialControllerCall>,
    /// Condition values projected by this pass.
    pub conditions: CredentialControllerConditions,
    /// Async-loop disposition.
    pub disposition: CredentialControllerDisposition,
    /// Stable typed outcome.
    pub outcome: CredentialControllerOutcome,
    /// Fixed observe delay when the pass schedules observation.
    pub observe_after_ms: Option<u64>,
}

impl fmt::Debug for CredentialControllerDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialControllerDecision")
            .field("call", &self.call)
            .field("conditions", &self.conditions)
            .field("disposition", &self.disposition)
            .field("outcome", &self.outcome)
            .field("observe_after_ms", &self.observe_after_ms)
            .finish()
    }
}

/// Bounded retry position supplied by the controller runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialRetryState {
    attempt: u16,
    max_attempts: u16,
}

impl CredentialRetryState {
    /// Construct a non-empty bounded retry position.
    pub fn new(attempt: u16, max_attempts: u16) -> Result<Self, CredentialControllerError> {
        if attempt == 0 || max_attempts == 0 || attempt > max_attempts {
            return Err(CredentialControllerError::InvalidInput);
        }
        Ok(Self {
            attempt,
            max_attempts,
        })
    }

    /// Whether this attempt consumed the final permitted retry.
    pub const fn exhausted(self) -> bool {
        self.attempt == self.max_attempts
    }
}

/// Input to a Credential reconcile pass.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialReconcileInput {
    credential_uid: ResourceUid,
    rotation: CredentialRotationPolicy,
    lease_state: Option<CredentialLeaseState>,
    rotation_generation: u64,
    expires_at_unix_ms: u64,
    allowed_operations: Vec<OperationClass>,
    role_permission: RolePermission,
    provider_reachable: bool,
    active_leases: u32,
    provider_lease_limit: u32,
    now_unix_ms: u64,
    call_deadline_unix_ms: u64,
    prior_rotation_failure: Option<CredentialRetryState>,
}

impl CredentialReconcileInput {
    /// Construct one validated reconcile snapshot.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        credential_uid: ResourceUid,
        rotation: CredentialRotationPolicy,
        lease_state: Option<CredentialLeaseState>,
        rotation_generation: u64,
        expires_at_unix_ms: u64,
        allowed_operations: impl IntoIterator<Item = OperationClass>,
        role_permission: RolePermission,
        provider_reachable: bool,
        active_leases: u32,
        provider_lease_limit: u32,
        now_unix_ms: u64,
        call_deadline_unix_ms: u64,
        prior_rotation_failure: Option<CredentialRetryState>,
    ) -> Result<Self, CredentialControllerError> {
        let allowed_operations: Vec<_> = allowed_operations.into_iter().collect();
        let unique: BTreeSet<_> = allowed_operations.iter().copied().collect();
        if rotation_generation == 0
            || active_leases > MAX_LOCAL_CREDENTIAL_LEASES
            || !(1..=MAX_LOCAL_CREDENTIAL_LEASES).contains(&provider_lease_limit)
            || unique.len() != allowed_operations.len()
        {
            return Err(CredentialControllerError::InvalidInput);
        }
        Ok(Self {
            credential_uid,
            rotation,
            lease_state,
            rotation_generation,
            expires_at_unix_ms,
            allowed_operations,
            role_permission,
            provider_reachable,
            active_leases,
            provider_lease_limit,
            now_unix_ms,
            call_deadline_unix_ms,
            prior_rotation_failure,
        })
    }

    /// Borrow the canonical store-generated identity used for single-flight.
    pub const fn credential_uid(&self) -> &ResourceUid {
        &self.credential_uid
    }
}

impl fmt::Debug for CredentialReconcileInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialReconcileInput(<redacted>)")
    }
}

/// Input to the fixed scheduled-observe handler.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialObserveInput {
    credential_uid: ResourceUid,
    lease_state: Option<CredentialLeaseState>,
    rotation_generation: u64,
    allowed_operations: Vec<OperationClass>,
    role_permission: RolePermission,
    provider_reachable: bool,
    now_unix_ms: u64,
    call_deadline_unix_ms: u64,
}

impl CredentialObserveInput {
    /// Construct one observe snapshot.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        credential_uid: ResourceUid,
        lease_state: Option<CredentialLeaseState>,
        rotation_generation: u64,
        allowed_operations: impl IntoIterator<Item = OperationClass>,
        role_permission: RolePermission,
        provider_reachable: bool,
        now_unix_ms: u64,
        call_deadline_unix_ms: u64,
    ) -> Result<Self, CredentialControllerError> {
        if rotation_generation == 0 {
            return Err(CredentialControllerError::InvalidInput);
        }
        Ok(Self {
            credential_uid,
            lease_state,
            rotation_generation,
            allowed_operations: allowed_operations.into_iter().collect(),
            role_permission,
            provider_reachable,
            now_unix_ms,
            call_deadline_unix_ms,
        })
    }

    /// Borrow the canonical store-generated identity used for single-flight.
    pub const fn credential_uid(&self) -> &ResourceUid {
        &self.credential_uid
    }
}

impl fmt::Debug for CredentialObserveInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialObserveInput(<redacted>)")
    }
}

/// Input to deletion finalization or Provider-generation drain.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialRevocationInput {
    credential_uid: ResourceUid,
    lease_state: Option<CredentialLeaseState>,
    rotation_generation: u64,
    action: RevocationAction,
    expires_at_unix_ms: u64,
    allowed_operations: Vec<OperationClass>,
    role_permission: RolePermission,
    now_unix_ms: u64,
    call_deadline_unix_ms: u64,
}

impl CredentialRevocationInput {
    /// Construct one revocation snapshot.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        credential_uid: ResourceUid,
        lease_state: Option<CredentialLeaseState>,
        rotation_generation: u64,
        action: RevocationAction,
        expires_at_unix_ms: u64,
        allowed_operations: impl IntoIterator<Item = OperationClass>,
        role_permission: RolePermission,
        now_unix_ms: u64,
        call_deadline_unix_ms: u64,
    ) -> Result<Self, CredentialControllerError> {
        if rotation_generation == 0 {
            return Err(CredentialControllerError::InvalidInput);
        }
        Ok(Self {
            credential_uid,
            lease_state,
            rotation_generation,
            action,
            expires_at_unix_ms,
            allowed_operations: allowed_operations.into_iter().collect(),
            role_permission,
            now_unix_ms,
            call_deadline_unix_ms,
        })
    }

    /// Borrow the canonical store-generated identity used for single-flight.
    pub const fn credential_uid(&self) -> &ResourceUid {
        &self.credential_uid
    }
}

impl fmt::Debug for CredentialRevocationInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialRevocationInput(<redacted>)")
    }
}

/// Health snapshot shared by all Credential controller implementations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialControllerHealth {
    /// Closed health state.
    pub state: CredentialControllerHealthState,
    /// Whether the provider process can currently be reached.
    pub provider_process_reachable: bool,
    /// Active leases only; revoked and expired leases are excluded.
    pub active_leases: u32,
    /// Number of locked backing entries, when meaningful to the Provider.
    pub locked_count: u32,
}

/// Closed controller health state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialControllerHealthState {
    /// The provider is reachable and no locked entries are reported.
    Ready,
    /// The provider is reachable but reports a bounded degraded state.
    Degraded,
    /// The provider process is unreachable.
    Unavailable,
}

impl CredentialControllerHealth {
    /// Derive health while enforcing the global active-lease ceiling.
    pub fn derive(
        provider_process_reachable: bool,
        active_leases: u32,
        locked_count: u32,
    ) -> Result<Self, CredentialControllerError> {
        if active_leases > MAX_LOCAL_CREDENTIAL_LEASES {
            return Err(CredentialControllerError::InvalidInput);
        }
        let state = if !provider_process_reachable {
            CredentialControllerHealthState::Unavailable
        } else if locked_count > 0 {
            CredentialControllerHealthState::Degraded
        } else {
            CredentialControllerHealthState::Ready
        };
        Ok(Self {
            state,
            provider_process_reachable,
            active_leases,
            locked_count,
        })
    }
}

/// Common handler surface implemented by each Credential Provider controller.
pub trait CredentialControllerHandlers {
    /// Reconcile desired policy and current lease state.
    fn reconcile_handler(
        &self,
        input: &CredentialReconcileInput,
    ) -> Result<CredentialControllerDecision, CredentialControllerError>;

    /// Plan the fixed 30-second metadata observation.
    fn observe(
        &self,
        input: &CredentialObserveInput,
    ) -> Result<CredentialControllerDecision, CredentialControllerError>;

    /// Execute the owner-delete revocation policy.
    fn finalize(
        &self,
        input: &CredentialRevocationInput,
    ) -> Result<CredentialControllerDecision, CredentialControllerError>;

    /// Execute the Provider-generation revocation policy.
    fn drain(
        &self,
        input: &CredentialRevocationInput,
    ) -> Result<CredentialControllerDecision, CredentialControllerError>;

    /// Project bounded controller health.
    fn health(
        &self,
        provider_process_reachable: bool,
        active_leases: u32,
        locked_count: u32,
    ) -> Result<CredentialControllerHealth, CredentialControllerError> {
        CredentialControllerHealth::derive(provider_process_reachable, active_leases, locked_count)
    }
}

/// Apply the shared Credential reconcile state machine.
pub fn reconcile_credential(
    input: &CredentialReconcileInput,
) -> Result<CredentialControllerDecision, CredentialControllerError> {
    let rotation_due = input.lease_state == Some(CredentialLeaseState::Active)
        && input.rotation.policy() == RotationPolicyClass::Proactive
        && input.rotation.proactive_window_ms().is_some_and(|window| {
            input.now_unix_ms.saturating_add(window) >= input.expires_at_unix_ms
        });
    let mut conditions = conditions(
        input.lease_state,
        rotation_due,
        !input.provider_reachable,
        false,
    );
    if !input.provider_reachable {
        return Ok(CredentialControllerDecision {
            call: None,
            conditions,
            disposition: CredentialControllerDisposition::Degraded,
            outcome: CredentialControllerOutcome::ProviderUnavailable,
            observe_after_ms: Some(CREDENTIAL_OBSERVE_INTERVAL_MS),
        });
    }

    if rotation_due
        && input
            .prior_rotation_failure
            .is_some_and(CredentialRetryState::exhausted)
    {
        conditions.credential_ready = false;
        return Ok(CredentialControllerDecision {
            call: None,
            conditions,
            disposition: CredentialControllerDisposition::Failed,
            outcome: CredentialControllerOutcome::RotationFailed,
            observe_after_ms: Some(CREDENTIAL_OBSERVE_INTERVAL_MS),
        });
    }

    let method = match input.lease_state {
        None => Some(CredentialMethod::AcquireToken),
        Some(CredentialLeaseState::Active) if rotation_due => Some(CredentialMethod::AcquireToken),
        Some(CredentialLeaseState::Active)
            if input.rotation.policy() == RotationPolicyClass::OnExpiry
                && input.now_unix_ms >= input.expires_at_unix_ms =>
        {
            Some(CredentialMethod::AcquireToken)
        }
        Some(CredentialLeaseState::Expired | CredentialLeaseState::Revoked)
            if input.rotation.policy() != RotationPolicyClass::OnDemand =>
        {
            Some(CredentialMethod::AcquireToken)
        }
        Some(CredentialLeaseState::Unknown) => Some(CredentialMethod::InspectMetadata),
        _ => None,
    };

    let Some(method) = method else {
        return Ok(CredentialControllerDecision {
            call: None,
            conditions,
            disposition: CredentialControllerDisposition::Converged,
            outcome: CredentialControllerOutcome::Success,
            observe_after_ms: Some(CREDENTIAL_OBSERVE_INTERVAL_MS),
        });
    };

    if method == CredentialMethod::AcquireToken && input.active_leases >= input.provider_lease_limit
    {
        return Ok(CredentialControllerDecision {
            call: None,
            conditions,
            disposition: CredentialControllerDisposition::Requeue,
            outcome: CredentialControllerOutcome::QueuePressure,
            observe_after_ms: Some(CREDENTIAL_OBSERVE_INTERVAL_MS),
        });
    }

    let call_generation = if method == CredentialMethod::AcquireToken && input.lease_state.is_some()
    {
        input
            .rotation_generation
            .checked_add(1)
            .ok_or(CredentialControllerError::InvalidInput)?
    } else {
        input.rotation_generation
    };
    let call = CredentialControllerCall::authorize(
        &input.credential_uid,
        call_generation,
        method,
        &input.allowed_operations,
        &input.role_permission,
        input.now_unix_ms,
        input.call_deadline_unix_ms,
    )?;
    Ok(CredentialControllerDecision {
        call: Some(call),
        conditions,
        disposition: CredentialControllerDisposition::Pending,
        outcome: CredentialControllerOutcome::Success,
        observe_after_ms: Some(CREDENTIAL_OBSERVE_INTERVAL_MS),
    })
}

/// Apply the fixed scheduled-observe policy.
pub fn observe_credential(
    input: &CredentialObserveInput,
) -> Result<CredentialControllerDecision, CredentialControllerError> {
    let conditions = conditions(input.lease_state, false, !input.provider_reachable, false);
    if !input.provider_reachable {
        return Ok(CredentialControllerDecision {
            call: None,
            conditions,
            disposition: CredentialControllerDisposition::Degraded,
            outcome: CredentialControllerOutcome::ProviderUnavailable,
            observe_after_ms: Some(CREDENTIAL_OBSERVE_INTERVAL_MS),
        });
    }
    let call = input
        .lease_state
        .map(|_| {
            CredentialControllerCall::authorize(
                &input.credential_uid,
                input.rotation_generation,
                CredentialMethod::InspectMetadata,
                &input.allowed_operations,
                &input.role_permission,
                input.now_unix_ms,
                input.call_deadline_unix_ms,
            )
        })
        .transpose()?;
    Ok(CredentialControllerDecision {
        disposition: if call.is_some() {
            CredentialControllerDisposition::Pending
        } else {
            CredentialControllerDisposition::Converged
        },
        call,
        conditions,
        outcome: CredentialControllerOutcome::Success,
        observe_after_ms: Some(CREDENTIAL_OBSERVE_INTERVAL_MS),
    })
}

/// Apply one owner-delete or Provider-generation revocation policy.
pub fn revoke_credential(
    input: &CredentialRevocationInput,
) -> Result<CredentialControllerDecision, CredentialControllerError> {
    let conditions = conditions(input.lease_state, false, false, false);
    if matches!(
        input.lease_state,
        None | Some(CredentialLeaseState::Expired | CredentialLeaseState::Revoked)
    ) {
        return Ok(CredentialControllerDecision {
            call: None,
            conditions,
            disposition: CredentialControllerDisposition::Finalized,
            outcome: CredentialControllerOutcome::Success,
            observe_after_ms: None,
        });
    }
    if input.action == RevocationAction::DrainLeases {
        return Ok(CredentialControllerDecision {
            call: None,
            conditions,
            disposition: if input.now_unix_ms >= input.expires_at_unix_ms {
                CredentialControllerDisposition::Finalized
            } else {
                CredentialControllerDisposition::Requeue
            },
            outcome: if input.now_unix_ms >= input.expires_at_unix_ms {
                CredentialControllerOutcome::Success
            } else {
                CredentialControllerOutcome::WaitingForExpiry
            },
            observe_after_ms: None,
        });
    }
    let call = CredentialControllerCall::authorize(
        &input.credential_uid,
        input.rotation_generation,
        CredentialMethod::RevokeToken,
        &input.allowed_operations,
        &input.role_permission,
        input.now_unix_ms,
        input.call_deadline_unix_ms,
    )?;
    Ok(CredentialControllerDecision {
        call: Some(call),
        conditions,
        disposition: CredentialControllerDisposition::Pending,
        outcome: CredentialControllerOutcome::Success,
        observe_after_ms: None,
    })
}

fn conditions(
    lease_state: Option<CredentialLeaseState>,
    rotation_due: bool,
    provider_unavailable: bool,
    rotation_failed: bool,
) -> CredentialControllerConditions {
    CredentialControllerConditions {
        credential_ready: lease_state == Some(CredentialLeaseState::Active)
            && !provider_unavailable
            && !rotation_failed,
        rotation_due,
        provider_unavailable,
        lease_revoked: lease_state == Some(CredentialLeaseState::Revoked),
    }
}

/// Per-controller single-flight registry keyed only by canonical resource UID.
#[derive(Default)]
pub struct CredentialSingleFlight {
    running: Mutex<BTreeSet<ResourceUid>>,
}

impl CredentialSingleFlight {
    /// Construct an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enter one Credential handler or reject a concurrent duplicate.
    pub fn try_enter(
        &self,
        credential_uid: ResourceUid,
    ) -> Result<CredentialSingleFlightGuard<'_>, CredentialControllerError> {
        let mut running = self.lock()?;
        if !running.insert(credential_uid.clone()) {
            return Err(CredentialControllerError::AlreadyRunning);
        }
        drop(running);
        Ok(CredentialSingleFlightGuard {
            registry: self,
            credential_uid: Some(credential_uid),
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, BTreeSet<ResourceUid>>, CredentialControllerError> {
        self.running
            .lock()
            .map_err(|_| CredentialControllerError::InvalidInput)
    }
}

impl fmt::Debug for CredentialSingleFlight {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialSingleFlight(<redacted>)")
    }
}

/// RAII release for one single-flight Credential handler.
pub struct CredentialSingleFlightGuard<'registry> {
    registry: &'registry CredentialSingleFlight,
    credential_uid: Option<ResourceUid>,
}

impl Drop for CredentialSingleFlightGuard<'_> {
    fn drop(&mut self) {
        if let Some(credential_uid) = self.credential_uid.take()
            && let Ok(mut running) = self.registry.running.lock()
        {
            running.remove(&credential_uid);
        }
    }
}

impl fmt::Debug for CredentialSingleFlightGuard<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialSingleFlightGuard(<redacted>)")
    }
}

/// Fixed Credential Provider identity used by audit and telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialProviderKind {
    /// Secret Service implementation.
    SecretService,
    /// Entra identity-Guest implementation.
    Entra,
    /// Managed identity implementation.
    ManagedIdentity,
}

impl CredentialProviderKind {
    /// Return the closed Provider label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SecretService => "credential-secret-service",
            Self::Entra => "credential-entra",
            Self::ManagedIdentity => "credential-managed-identity",
        }
    }

    const fn component(self) -> &'static str {
        match self {
            Self::SecretService => "secret-service-controller",
            Self::Entra => "entra-controller",
            Self::ManagedIdentity => "managed-identity-agent",
        }
    }

    const fn service_name(self) -> &'static str {
        match self {
            Self::SecretService => "d2b-credential-secret-service",
            Self::Entra => "d2b-credential-entra",
            Self::ManagedIdentity => "d2b-managed-identity-agent",
        }
    }
}

/// Closed Credential audit operation catalogue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialAuditOperation {
    /// Credential resource creation.
    ResourceCreate,
    /// Credential spec update.
    ResourceUpdate,
    /// Credential resource deletion.
    ResourceDelete,
    /// Token acquisition.
    AcquireToken,
    /// Token refresh.
    RefreshToken,
    /// Lease revocation.
    RevokeToken,
    /// Challenge signing.
    SignChallenge,
    /// Metadata inspection.
    InspectMetadata,
    /// Login observation.
    ObserveLogin,
    /// Login start.
    BeginLogin,
    /// Login cancellation.
    CancelLogin,
    /// Controller reconciliation.
    Reconcile,
    /// Scheduled observation.
    Observe,
    /// Owner-delete finalization.
    Finalize,
    /// Provider-generation drain.
    Drain,
    /// Controller health observation.
    Health,
    /// Lease rotation.
    Rotation,
    /// Provider-generation-change revocation.
    ProviderGenerationRevocation,
    /// Managed identity agent start.
    AgentStart,
    /// Managed identity agent stop.
    AgentStop,
}

impl CredentialAuditOperation {
    /// Return the stable operation token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ResourceCreate => "resource-create",
            Self::ResourceUpdate => "resource-update",
            Self::ResourceDelete => "resource-delete",
            Self::AcquireToken => "acquire-token",
            Self::RefreshToken => "refresh-token",
            Self::RevokeToken => "revoke-token",
            Self::SignChallenge => "sign-challenge",
            Self::InspectMetadata => "inspect-metadata",
            Self::ObserveLogin => "observe-login",
            Self::BeginLogin => "begin-login",
            Self::CancelLogin => "cancel-login",
            Self::Reconcile => "reconcile",
            Self::Observe => "observe",
            Self::Finalize => "finalize",
            Self::Drain => "drain",
            Self::Health => "health",
            Self::Rotation => "rotation",
            Self::ProviderGenerationRevocation => "provider-generation-revocation",
            Self::AgentStart => "agent-start",
            Self::AgentStop => "agent-stop",
        }
    }
}

/// Closed Credential audit outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialAuditOutcome {
    /// The operation completed.
    Success,
    /// Authorization denied the operation before identity-bearing audit.
    Denied,
    /// The Provider was unavailable.
    ProviderUnavailable,
    /// The lease was already revoked.
    AlreadyRevoked,
    /// Rotation exhausted its retry budget.
    RotationFailed,
    /// Capacity applied backpressure.
    QueuePressure,
    /// An invariant rejected the result.
    InvariantFailure,
}

impl CredentialAuditOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Denied => "denied",
            Self::ProviderUnavailable => "provider-unavailable",
            Self::AlreadyRevoked => "already-revoked",
            Self::RotationFailed => "rotation-failed",
            Self::QueuePressure => "queue-pressure",
            Self::InvariantFailure => "invariant-failure",
        }
    }
}

/// Validated one-way digest admitted to a Credential audit record.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialAuditDigest(String);

impl CredentialAuditDigest {
    /// Parse exactly `sha256:` followed by 64 lowercase hexadecimal digits.
    pub fn parse(value: impl Into<String>) -> Result<Self, CredentialObservabilityError> {
        let value = value.into();
        if valid_sha256(&value) {
            Ok(Self(value))
        } else {
            Err(CredentialObservabilityError::InvalidAuditRecord)
        }
    }

    /// Hash an authorized bounded identity without retaining its source bytes.
    pub fn after_authorization(value: &[u8]) -> Self {
        let digest: [u8; 32] = Sha256::digest(value).into();
        let mut rendered = String::with_capacity(71);
        rendered.push_str("sha256:");
        for byte in digest {
            write!(&mut rendered, "{byte:02x}").expect("writing to a String cannot fail");
        }
        Self(rendered)
    }

    /// Borrow the canonical audit-only digest.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CredentialAuditDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialAuditDigest(<redacted>)")
    }
}

impl fmt::Display for CredentialAuditDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialAuditDigest(<redacted>)")
    }
}

/// One authorized bounded Credential audit record.
pub struct CredentialAuditRecord {
    provider: CredentialProviderKind,
    zone: String,
    resource_name_digest: CredentialAuditDigest,
    subject_digest: Option<CredentialAuditDigest>,
    operation: CredentialAuditOperation,
    outcome: CredentialAuditOutcome,
    rotation_generation: u64,
    prior_rotation_generation: Option<u64>,
    idempotency_key_digest: Option<CredentialAuditDigest>,
}

impl CredentialAuditRecord {
    /// Emit one caller-initiated service record only after authorization.
    /// Denial returns no identity-bearing record and does not inspect identity.
    #[allow(clippy::too_many_arguments)]
    pub fn authorized_service(
        authorized: bool,
        provider: CredentialProviderKind,
        zone: impl Into<String>,
        subject_digest: impl Into<String>,
        resource_name_digest: impl Into<String>,
        method: CredentialMethod,
        outcome: CredentialAuditOutcome,
        rotation_generation: u64,
        idempotency_key_digest: Option<String>,
    ) -> Result<Option<Self>, CredentialObservabilityError> {
        if !authorized {
            return Ok(None);
        }
        let operation = match method {
            CredentialMethod::AcquireToken => CredentialAuditOperation::AcquireToken,
            CredentialMethod::RefreshToken => CredentialAuditOperation::RefreshToken,
            CredentialMethod::RevokeToken => CredentialAuditOperation::RevokeToken,
            CredentialMethod::SignChallenge => CredentialAuditOperation::SignChallenge,
            CredentialMethod::InspectMetadata => CredentialAuditOperation::InspectMetadata,
        };
        let zone = validate_zone(zone.into())?;
        if rotation_generation == 0 {
            return Err(CredentialObservabilityError::InvalidAuditRecord);
        }
        Ok(Some(Self {
            provider,
            zone,
            resource_name_digest: CredentialAuditDigest::parse(resource_name_digest)?,
            subject_digest: Some(CredentialAuditDigest::parse(subject_digest)?),
            operation,
            outcome,
            rotation_generation,
            prior_rotation_generation: None,
            idempotency_key_digest: idempotency_key_digest
                .map(CredentialAuditDigest::parse)
                .transpose()?,
        }))
    }

    /// Emit one controller-owned event with no caller subject field.
    #[allow(clippy::too_many_arguments)]
    pub fn controller_event(
        provider: CredentialProviderKind,
        zone: impl Into<String>,
        resource_name_digest: CredentialAuditDigest,
        operation: CredentialAuditOperation,
        outcome: CredentialAuditOutcome,
        rotation_generation: u64,
        prior_rotation_generation: Option<u64>,
        idempotency_key_digest: Option<CredentialAuditDigest>,
    ) -> Result<Self, CredentialObservabilityError> {
        if rotation_generation == 0 || prior_rotation_generation.is_some_and(|prior| prior == 0) {
            return Err(CredentialObservabilityError::InvalidAuditRecord);
        }
        Ok(Self {
            provider,
            zone: validate_zone(zone.into())?,
            resource_name_digest,
            subject_digest: None,
            operation,
            outcome,
            rotation_generation,
            prior_rotation_generation,
            idempotency_key_digest,
        })
    }

    /// Render the bounded Zone audit payload.
    pub fn to_wire_record(&self) -> String {
        let mut record = format!(
            "provider={} zone={} resource_name_digest={} operation={} outcome={} rotation_generation={}",
            self.provider.as_str(),
            self.zone,
            self.resource_name_digest.as_str(),
            self.operation.as_str(),
            self.outcome.as_str(),
            self.rotation_generation
        );
        if let Some(subject) = &self.subject_digest {
            write!(
                &mut record,
                " subject_digest={} authorization_decision=allowed role_subresource=use-credential/{}",
                subject.as_str(),
                self.operation.as_str()
            )
                .expect("writing to a String cannot fail");
        }
        if let Some(prior) = self.prior_rotation_generation {
            write!(&mut record, " prior_rotation_generation={prior}")
                .expect("writing to a String cannot fail");
        }
        if let Some(idempotency) = &self.idempotency_key_digest {
            write!(
                &mut record,
                " idempotency_key_digest={}",
                idempotency.as_str()
            )
            .expect("writing to a String cannot fail");
        }
        record
    }
}

impl fmt::Debug for CredentialAuditRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialAuditRecord(<redacted>)")
    }
}

/// Closed telemetry operation set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialTelemetryOperation {
    /// Token acquisition.
    AcquireToken,
    /// Token refresh.
    RefreshToken,
    /// Lease revocation.
    RevokeToken,
    /// Challenge signing.
    SignChallenge,
    /// Metadata inspection.
    InspectMetadata,
    /// Controller reconciliation.
    Reconcile,
    /// Lease rotation.
    Rotation,
}

impl CredentialTelemetryOperation {
    /// Return the operation-class label value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AcquireToken => "acquire-token",
            Self::RefreshToken => "refresh-token",
            Self::RevokeToken => "revoke-token",
            Self::SignChallenge => "sign-challenge",
            Self::InspectMetadata => "inspect-metadata",
            Self::Reconcile => "reconcile",
            Self::Rotation => "rotation",
        }
    }

    const fn span_name(self) -> &'static str {
        match self {
            Self::AcquireToken => "d2b.credential.acquire_token",
            Self::RefreshToken => "d2b.credential.refresh_token",
            Self::RevokeToken => "d2b.credential.revoke_token",
            Self::SignChallenge => "d2b.credential.sign_challenge",
            Self::InspectMetadata => "d2b.credential.inspect_metadata",
            Self::Reconcile => "d2b.credential.reconcile",
            Self::Rotation => "d2b.credential.rotation",
        }
    }
}

/// Closed telemetry outcome values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialTelemetryOutcome {
    /// The operation completed.
    Success,
    /// The Provider was unavailable.
    ProviderUnavailable,
    /// Policy denied the operation.
    Denied,
    /// The lease expired.
    LeaseExpired,
    /// The lease was revoked.
    LeaseRevoked,
    /// Rotation exhausted its retry budget.
    RotationFailed,
    /// Capacity applied backpressure.
    QueuePressure,
    /// A fixed invariant rejected the result.
    InvariantFailure,
}

impl CredentialTelemetryOutcome {
    /// Return the stable closed value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::ProviderUnavailable => "provider-unavailable",
            Self::Denied => "denied",
            Self::LeaseExpired => "lease-expired",
            Self::LeaseRevoked => "lease-revoked",
            Self::RotationFailed => "rotation-failed",
            Self::QueuePressure => "queue-pressure",
            Self::InvariantFailure => "invariant-failure",
        }
    }
}

/// One telemetry field exposed to collector contract validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialTelemetryField {
    /// Closed field key.
    pub key: &'static str,
    /// Value validated against the key's closed domain.
    pub value: String,
}

/// Metric instrument type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialMetricKind {
    /// Monotonic event count.
    Counter,
    /// Current aggregate value.
    Gauge,
}

/// One fixed Credential metric descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialMetricDescriptor {
    /// Stable instrument name.
    pub name: &'static str,
    /// Instrument kind.
    pub kind: CredentialMetricKind,
    /// Exact label-key set.
    pub label_keys: &'static [&'static str],
}

/// Complete fixed Credential metric catalogue.
pub const CREDENTIAL_METRICS: &[CredentialMetricDescriptor] = &[
    CredentialMetricDescriptor {
        name: "d2b_credential_operations_total",
        kind: CredentialMetricKind::Counter,
        label_keys: &[
            "provider",
            "operation_class",
            "placement_binding",
            "outcome",
        ],
    },
    CredentialMetricDescriptor {
        name: "d2b_credential_lease_expiry_seconds",
        kind: CredentialMetricKind::Gauge,
        label_keys: &["provider", "placement_binding"],
    },
    CredentialMetricDescriptor {
        name: "d2b_credential_rotation_total",
        kind: CredentialMetricKind::Counter,
        label_keys: &["provider", "policy", "outcome"],
    },
    CredentialMetricDescriptor {
        name: "d2b_credential_provider_health",
        kind: CredentialMetricKind::Gauge,
        label_keys: &["provider"],
    },
    CredentialMetricDescriptor {
        name: "d2b_credential_active_leases",
        kind: CredentialMetricKind::Gauge,
        label_keys: &["provider", "placement_binding"],
    },
];

/// Provider/placement aggregate used by expiry and active-lease gauges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialLeaseAggregate {
    /// Closed Provider label.
    pub provider: CredentialProviderKind,
    /// Closed placement label.
    pub placement: PlacementBinding,
    /// Minimum whole seconds remaining, or zero when there is no active lease.
    pub minimum_expiry_seconds: u64,
    /// Number of active leases in this aggregate.
    pub active_leases: u32,
}

impl CredentialLeaseAggregate {
    /// Aggregate active lease expiries without accepting any Credential identity.
    pub fn from_active_expiries(
        provider: CredentialProviderKind,
        placement: PlacementBinding,
        now_unix_ms: u64,
        expiries_unix_ms: impl IntoIterator<Item = u64>,
    ) -> Result<Self, CredentialObservabilityError> {
        let mut active_leases = 0_u32;
        let mut minimum_expiry_seconds = None;
        for expiry in expiries_unix_ms {
            if expiry <= now_unix_ms {
                continue;
            }
            active_leases = active_leases
                .checked_add(1)
                .ok_or(CredentialObservabilityError::ForbiddenTelemetryField)?;
            if active_leases > MAX_LOCAL_CREDENTIAL_LEASES {
                return Err(CredentialObservabilityError::ForbiddenTelemetryField);
            }
            let seconds = expiry.saturating_sub(now_unix_ms) / 1_000;
            minimum_expiry_seconds =
                Some(minimum_expiry_seconds.map_or(seconds, |current: u64| current.min(seconds)));
        }
        Ok(Self {
            provider,
            placement,
            minimum_expiry_seconds: minimum_expiry_seconds.unwrap_or(0),
            active_leases,
        })
    }

    /// Return the two closed labels shared by both aggregate gauges.
    pub fn labels(&self) -> [CredentialTelemetryField; 2] {
        [
            field("provider", self.provider.as_str()),
            field("placement_binding", placement_label(self.placement)),
        ]
    }
}

/// Complete Resource, span, and operation-metric frame.
pub struct CredentialTelemetryFrame {
    span_name: &'static str,
    resource_attributes: Vec<CredentialTelemetryField>,
    span_attributes: Vec<CredentialTelemetryField>,
    metric_labels: Vec<CredentialTelemetryField>,
}

impl CredentialTelemetryFrame {
    /// Build one frame entirely from trusted closed values.
    pub fn new(
        provider: CredentialProviderKind,
        zone: impl Into<String>,
        operation: CredentialTelemetryOperation,
        outcome: CredentialTelemetryOutcome,
        placement: PlacementBinding,
        rotation_generation: u64,
        service_version: &'static str,
    ) -> Result<Self, CredentialObservabilityError> {
        if rotation_generation == 0 {
            return Err(CredentialObservabilityError::ForbiddenTelemetryField);
        }
        let zone = validate_zone(zone.into())?;
        let placement = placement_label(placement).to_owned();
        let operation_value = operation.as_str().to_owned();
        let outcome_value = outcome.as_str().to_owned();
        let provider_value = provider.as_str().to_owned();
        let frame = Self {
            span_name: operation.span_name(),
            resource_attributes: vec![
                field("d2b.zone", zone),
                field("d2b.provider", provider_value.clone()),
                field("d2b.component", provider.component()),
                field("service.name", provider.service_name()),
                field("service.namespace", "d2b"),
                field("service.version", service_version),
            ],
            span_attributes: vec![
                field("d2b.credential.provider", provider_value.clone()),
                field("d2b.credential.operation_class", operation_value.clone()),
                field("d2b.credential.placement_binding", placement.clone()),
                field("d2b.credential.outcome", outcome_value.clone()),
                field(
                    "d2b.credential.rotation_generation",
                    rotation_generation.to_string(),
                ),
            ],
            metric_labels: vec![
                field("provider", provider_value),
                field("operation_class", operation_value),
                field("placement_binding", placement),
                field("outcome", outcome_value),
            ],
        };
        Self::validate_collector_fields(frame.all_fields())?;
        Ok(frame)
    }

    /// Return the fixed span name.
    pub const fn span_name(&self) -> &'static str {
        self.span_name
    }

    /// Borrow generic collector-allowlisted Resource attributes.
    pub fn resource_attributes(&self) -> &[CredentialTelemetryField] {
        &self.resource_attributes
    }

    /// Borrow the closed span attributes.
    pub fn span_attributes(&self) -> &[CredentialTelemetryField] {
        &self.span_attributes
    }

    /// Borrow the closed operation metric labels.
    pub fn metric_labels(&self) -> &[CredentialTelemetryField] {
        &self.metric_labels
    }

    /// Return every frame field for collector validation.
    pub fn all_fields(&self) -> Vec<CredentialTelemetryField> {
        self.resource_attributes
            .iter()
            .chain(&self.span_attributes)
            .chain(&self.metric_labels)
            .cloned()
            .collect()
    }

    /// Reject a complete frame when any key or value is outside its closed
    /// semantic domain. The whole frame is rejected, not field-filtered.
    pub fn validate_collector_fields(
        fields: impl IntoIterator<Item = CredentialTelemetryField>,
    ) -> Result<(), CredentialObservabilityError> {
        for field in fields {
            if forbidden_telemetry_key(field.key)
                || contains_sensitive_shape(&field.value)
                || !allowed_telemetry_value(field.key, &field.value)
            {
                return Err(CredentialObservabilityError::ForbiddenTelemetryField);
            }
        }
        Ok(())
    }
}

impl fmt::Debug for CredentialTelemetryFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialTelemetryFrame(<redacted>)")
    }
}

/// Observability construction failure that never echoes input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialObservabilityError {
    /// An audit field was malformed or sensitive.
    InvalidAuditRecord,
    /// A telemetry key or value was not in the closed set.
    ForbiddenTelemetryField,
}

impl fmt::Display for CredentialObservabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidAuditRecord => "credential audit record is invalid",
            Self::ForbiddenTelemetryField => "credential telemetry frame is invalid",
        })
    }
}

impl std::error::Error for CredentialObservabilityError {}

/// Detect high-risk string shapes before an observable string field is stored.
pub fn contains_sensitive_shape(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    lower.contains("http://")
        || lower.contains("https://")
        || lower.contains("/subscriptions/")
        || lower.contains("secret-canary")
        || lower.contains("token-canary")
        || lower.contains("credential-name")
        || lower.contains("credential/")
        || lower.contains("credential-uid")
        || lower.contains("credential-digest")
        || lower.contains("password=")
        || lower.contains("bearer ")
        || lower.contains("provider-code=")
        || lower.contains("provider_code=")
        || lower.contains("provider-message=")
        || lower.contains("provider_message=")
        || lower.contains("correlation_id=")
        || raw.contains('{')
        || raw.contains('}')
        || raw
            .split(|character: char| !(character.is_ascii_hexdigit() || character == '-'))
            .any(looks_like_uuid)
}

fn field(key: &'static str, value: impl Into<String>) -> CredentialTelemetryField {
    CredentialTelemetryField {
        key,
        value: value.into(),
    }
}

fn validate_zone(value: String) -> Result<String, CredentialObservabilityError> {
    if value.is_empty()
        || value.len() > 63
        || !value.as_bytes()[0].is_ascii_lowercase()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || contains_sensitive_shape(&value)
    {
        return Err(CredentialObservabilityError::ForbiddenTelemetryField);
    }
    Ok(value)
}

fn placement_label(placement: PlacementBinding) -> &'static str {
    match placement {
        PlacementBinding::UserAgent => "user-agent",
        PlacementBinding::HostSystem => "host-system",
        PlacementBinding::GuestAgent => "guest-agent",
    }
}

fn forbidden_telemetry_key(key: &str) -> bool {
    matches!(
        key,
        "vm" | "zone"
            | "zone_id"
            | "zone_uid"
            | "credential_name"
            | "credential_ref"
            | "credential_uid"
            | "credential_digest"
            | "resource_name_digest"
            | "d2b.credential.name"
            | "d2b.credential.ref"
            | "d2b.credential.uid"
            | "d2b.credential.digest"
    ) || key.contains("resource_name")
}

fn allowed_telemetry_value(key: &str, value: &str) -> bool {
    match key {
        "d2b.zone" => validate_zone(value.to_owned()).is_ok(),
        "d2b.provider" | "d2b.credential.provider" | "provider" => matches!(
            value,
            "credential-secret-service" | "credential-entra" | "credential-managed-identity"
        ),
        "d2b.component" => matches!(
            value,
            "secret-service-controller" | "entra-controller" | "managed-identity-agent"
        ),
        "service.name" => matches!(
            value,
            "d2b-credential-secret-service" | "d2b-credential-entra" | "d2b-managed-identity-agent"
        ),
        "service.namespace" => value == "d2b",
        "service.version" => {
            !value.is_empty()
                && value.len() <= 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
        }
        "d2b.credential.operation_class" | "operation_class" => matches!(
            value,
            "acquire-token"
                | "refresh-token"
                | "revoke-token"
                | "sign-challenge"
                | "inspect-metadata"
                | "reconcile"
                | "rotation"
        ),
        "d2b.credential.placement_binding" | "placement_binding" => {
            matches!(value, "user-agent" | "host-system" | "guest-agent")
        }
        "d2b.credential.outcome" | "outcome" => matches!(
            value,
            "success"
                | "provider-unavailable"
                | "denied"
                | "lease-expired"
                | "lease-revoked"
                | "rotation-failed"
                | "queue-pressure"
                | "invariant-failure"
        ),
        "d2b.credential.rotation_generation" => {
            value.parse::<u64>().is_ok_and(|generation| generation > 0)
        }
        "policy" => matches!(value, "proactive" | "on-expiry" | "on-demand"),
        _ => false,
    }
}

fn valid_sha256(value: &str) -> bool {
    d2b_contracts_resource::v3::resource_schema::is_canonical_digest(value)
}

fn looks_like_uuid(token: &str) -> bool {
    let mut parts = token.split('-');
    matches!(
        (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next()
        ),
        (Some(a), Some(b), Some(c), Some(d), Some(e), None)
            if a.len() == 8
                && b.len() == 4
                && c.len() == 4
                && d.len() == 4
                && e.len() == 12
                && [a, b, c, d, e]
                    .into_iter()
                    .all(|part| part.bytes().all(|byte| byte.is_ascii_hexdigit()))
    )
}

/// Select the owner-delete policy from one Credential revocation spec.
pub const fn owner_delete_action(policy: CredentialRevocationPolicy) -> RevocationAction {
    policy.on_owner_delete
}

/// Select the Provider-generation policy from one Credential revocation spec.
pub const fn provider_generation_action(policy: CredentialRevocationPolicy) -> RevocationAction {
    policy.on_provider_generation
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v3::credential::{CredentialResourceVerb, CredentialRotationPolicy};

    const UID: &str = "123e4567-e89b-42d3-a456-426614174000";

    fn uid() -> ResourceUid {
        ResourceUid::parse(UID).unwrap()
    }

    fn permission(method: CredentialMethod) -> RolePermission {
        RolePermission::new(CredentialResourceVerb::UseCredential, method.subresource())
    }

    fn rotation(policy: RotationPolicyClass) -> CredentialRotationPolicy {
        CredentialRotationPolicy::new(
            policy,
            (policy == RotationPolicyClass::Proactive).then_some(100),
            1_000,
        )
        .unwrap()
    }

    #[test]
    fn exact_subresources_and_deadlines_are_required() {
        for method in [
            CredentialMethod::AcquireToken,
            CredentialMethod::RefreshToken,
            CredentialMethod::RevokeToken,
            CredentialMethod::SignChallenge,
            CredentialMethod::InspectMetadata,
        ] {
            assert!(
                CredentialControllerCall::authorize(
                    &uid(),
                    1,
                    method,
                    &[method.operation_class()],
                    &permission(method),
                    10,
                    20,
                )
                .is_ok()
            );
            assert_eq!(
                CredentialControllerCall::authorize(
                    &uid(),
                    1,
                    method,
                    &[method.operation_class()],
                    &RolePermission::new(CredentialResourceVerb::UseCredential, "credential"),
                    10,
                    20,
                )
                .unwrap_err(),
                CredentialControllerError::OperationDenied
            );
            assert_eq!(
                CredentialControllerCall::authorize(
                    &uid(),
                    1,
                    method,
                    &[method.operation_class()],
                    &permission(method),
                    20,
                    20,
                )
                .unwrap_err(),
                CredentialControllerError::DeadlineExceeded
            );
        }
    }

    #[test]
    fn idempotency_keys_are_stable_bounded_and_redacted() {
        let first =
            CredentialIdempotencyKey::derive(&uid(), 7, CredentialMethod::AcquireToken).unwrap();
        let duplicate =
            CredentialIdempotencyKey::derive(&uid(), 7, CredentialMethod::AcquireToken).unwrap();
        let next =
            CredentialIdempotencyKey::derive(&uid(), 8, CredentialMethod::AcquireToken).unwrap();
        assert_eq!(first, duplicate);
        assert_ne!(first, next);
        assert_eq!(first.request_value().len(), 64);
        assert!(!format!("{first:?}").contains(&first.request_value()));
        assert!(!first.to_string().contains(&first.request_value()));
    }

    #[test]
    fn rotation_policy_matrix_is_closed() {
        let cases = [
            (RotationPolicyClass::Proactive, 950, true),
            (RotationPolicyClass::OnExpiry, 950, false),
            (RotationPolicyClass::OnExpiry, 1_000, true),
            (RotationPolicyClass::OnDemand, 1_500, false),
        ];
        for (policy, now, should_call) in cases {
            let input = CredentialReconcileInput::new(
                uid(),
                rotation(policy),
                Some(CredentialLeaseState::Active),
                1,
                1_000,
                [OperationClass::AcquireToken],
                permission(CredentialMethod::AcquireToken),
                true,
                1,
                MAX_LOCAL_CREDENTIAL_LEASES,
                now,
                2_000,
                None,
            )
            .unwrap();
            assert_eq!(
                reconcile_credential(&input).unwrap().call.is_some(),
                should_call
            );
        }
    }

    #[test]
    fn capacity_excludes_terminal_leases_and_single_flight_releases() {
        let registry = CredentialSingleFlight::new();
        let guard = registry.try_enter(uid()).unwrap();
        assert_eq!(
            registry.try_enter(uid()).unwrap_err(),
            CredentialControllerError::AlreadyRunning
        );
        drop(guard);
        assert!(registry.try_enter(uid()).is_ok());

        let input = CredentialReconcileInput::new(
            uid(),
            rotation(RotationPolicyClass::OnExpiry),
            None,
            1,
            1_000,
            [OperationClass::AcquireToken],
            permission(CredentialMethod::AcquireToken),
            true,
            MAX_LOCAL_CREDENTIAL_LEASES,
            MAX_LOCAL_CREDENTIAL_LEASES,
            10,
            20,
            None,
        )
        .unwrap();
        assert_eq!(
            reconcile_credential(&input).unwrap().outcome,
            CredentialControllerOutcome::QueuePressure
        );
    }

    #[test]
    fn finalizer_and_generation_drain_share_the_revocation_policy() {
        let immediate = CredentialRevocationInput::new(
            uid(),
            Some(CredentialLeaseState::Active),
            1,
            RevocationAction::Immediate,
            1_000,
            [OperationClass::RevokeToken],
            permission(CredentialMethod::RevokeToken),
            10,
            20,
        )
        .unwrap();
        assert_eq!(
            revoke_credential(&immediate)
                .unwrap()
                .call
                .unwrap()
                .method(),
            CredentialMethod::RevokeToken
        );
        let drain = CredentialRevocationInput::new(
            uid(),
            Some(CredentialLeaseState::Active),
            1,
            RevocationAction::DrainLeases,
            1_000,
            [OperationClass::RevokeToken],
            permission(CredentialMethod::RevokeToken),
            10,
            20,
        )
        .unwrap();
        assert_eq!(
            revoke_credential(&drain).unwrap().outcome,
            CredentialControllerOutcome::WaitingForExpiry
        );
    }

    #[test]
    fn ambient_sdk_chain_names_are_rejected_without_reading_values() {
        assert!(
            reject_ambient_credential_chain(["RUST_LOG", "PATH"]).is_ok()
        );
        assert_eq!(
            reject_ambient_credential_chain(["AZURE_CLIENT_SECRET"]).unwrap_err(),
            CredentialControllerError::OperationDenied
        );
        assert_eq!(
            reject_ambient_credential_chain(["AWS_SESSION_TOKEN"]).unwrap_err(),
            CredentialControllerError::OperationDenied
        );
    }

    #[test]
    fn audit_denial_is_identity_silent_and_telemetry_values_are_closed() {
        let denied = CredentialAuditRecord::authorized_service(
            false,
            CredentialProviderKind::Entra,
            "zone-secret-canary",
            "subject-secret-canary",
            "Credential/name-secret-canary",
            CredentialMethod::AcquireToken,
            CredentialAuditOutcome::Denied,
            1,
            None,
        )
        .unwrap();
        assert!(denied.is_none());

        let frame = CredentialTelemetryFrame::new(
            CredentialProviderKind::Entra,
            "dev",
            CredentialTelemetryOperation::AcquireToken,
            CredentialTelemetryOutcome::Success,
            PlacementBinding::GuestAgent,
            1,
            "1.0.0",
        )
        .unwrap();
        assert!(CredentialTelemetryFrame::validate_collector_fields(frame.all_fields()).is_ok());
        assert_eq!(
            CredentialTelemetryFrame::validate_collector_fields([CredentialTelemetryField {
                key: "outcome",
                value: "credential-name-secret-canary".to_owned(),
            }]),
            Err(CredentialObservabilityError::ForbiddenTelemetryField)
        );
    }
}
