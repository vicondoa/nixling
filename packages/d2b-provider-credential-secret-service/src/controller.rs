//! Pure status and health projection for the Secret Service controller.

#[path = "audit.rs"]
mod audit;
#[path = "telemetry.rs"]
mod telemetry;

use d2b_contracts_provider::v3::credential::{
    CredentialInteractionState, CredentialLeaseStatus, CredentialMetadata, CredentialServiceError,
    CredentialStatus, PlacementBinding,
};
use d2b_contracts_provider::v3::credential_controller::{
    CredentialAuditOutcome, CredentialAuditRecord, CredentialControllerDecision,
    CredentialControllerError, CredentialControllerHandlers, CredentialControllerHealth,
    CredentialObservabilityError, CredentialObserveInput, CredentialReconcileInput,
    CredentialRevocationInput, CredentialSingleFlight, CredentialTelemetryFrame,
    CredentialProviderKind, CredentialTelemetryOperation, CredentialTelemetryOutcome,
    observe_credential,
    reconcile_credential, revoke_credential,
};

use crate::{LockPolicy, SecretServiceConfig, SecretServiceState};

/// Finalizer owned by the Secret Service Credential controller.
pub const PROVIDER_REVOKE_FINALIZER: &str =
    d2b_contracts_provider::v3::credential_controller::CREDENTIAL_PROVIDER_REVOKE_FINALIZER;
/// Provider identity used by the shared controller registration.
pub const PROVIDER_KIND: CredentialProviderKind =
    CredentialProviderKind::SecretService;

/// Closed controller health state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretServiceControllerHealth {
    /// The injected port is ready.
    Ready,
    /// The keyring is locked under degraded policy.
    Degraded,
    /// Operations fail closed while the keyring is locked.
    Unavailable,
}

/// Status projection plus closed health.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretServiceStatusProjection {
    /// Common Credential status.
    pub status: CredentialStatus,
    /// Closed controller health.
    pub health: SecretServiceControllerHealth,
}

impl core::fmt::Debug for SecretServiceStatusProjection {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SecretServiceStatusProjection(<redacted>)")
    }
}

/// Stateless status-first controller projection.
pub struct SecretServiceController {
    config: SecretServiceConfig,
    single_flight: CredentialSingleFlight,
}

impl SecretServiceController {
    /// Construct the projection controller.
    pub fn new(config: SecretServiceConfig) -> Self {
        Self {
            config,
            single_flight: CredentialSingleFlight::new(),
        }
    }

    /// Project current lease metadata and port state without credential bytes.
    pub fn reconcile(
        &self,
        state: SecretServiceState,
        metadata: Option<&CredentialMetadata>,
    ) -> Result<SecretServiceStatusProjection, CredentialServiceError> {
        let health = match (state, self.config.lock_policy()) {
            (SecretServiceState::Unlocked, _) => SecretServiceControllerHealth::Ready,
            (SecretServiceState::Locked, LockPolicy::FailClosed) => {
                SecretServiceControllerHealth::Unavailable
            }
            (SecretServiceState::Locked, LockPolicy::FailDegraded) => {
                SecretServiceControllerHealth::Degraded
            }
        };
        let lease = metadata
            .map(|metadata| {
                CredentialLeaseStatus::new(
                    metadata.lease_handle.clone(),
                    metadata.state,
                    metadata.rotation_generation,
                    metadata.source_version.clone(),
                    metadata.expires_at_unix_ms,
                    1,
                    None,
                    None,
                    PlacementBinding::UserAgent,
                )
            })
            .transpose()
            .map_err(|_| {
                super::SecretServiceCredentialProvider::map_port_error(
                    super::SecretServicePortError::CompletionUnknown,
                )
            })?;
        let status =
            CredentialStatus::new(CredentialInteractionState::NotRequired, None, None, lease)
                .map_err(|_| {
                    super::SecretServiceCredentialProvider::map_port_error(
                        super::SecretServicePortError::CompletionUnknown,
                    )
                })?;
        Ok(SecretServiceStatusProjection { status, health })
    }

    /// Build a caller-initiated audit record after the authorization decision.
    #[allow(clippy::too_many_arguments)]
    pub fn authorized_service_audit(
        &self,
        authorized: bool,
        zone: &str,
        subject_identity: &[u8],
        credential_name: &[u8],
        method: d2b_contracts_provider::v3::credential::CredentialMethod,
        outcome: CredentialAuditOutcome,
        rotation_generation: u64,
        idempotency_key: Option<&[u8]>,
    ) -> Result<Option<CredentialAuditRecord>, CredentialObservabilityError> {
        audit::authorized_service_record(
            authorized,
            zone,
            subject_identity,
            credential_name,
            method,
            outcome,
            rotation_generation,
            idempotency_key,
        )
    }

    /// Build one complete closed Credential telemetry frame.
    pub fn telemetry(
        &self,
        zone: &str,
        operation: CredentialTelemetryOperation,
        outcome: CredentialTelemetryOutcome,
        rotation_generation: u64,
    ) -> Result<CredentialTelemetryFrame, CredentialObservabilityError> {
        telemetry::frame(zone, operation, outcome, rotation_generation)
    }
}

impl core::fmt::Debug for SecretServiceController {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SecretServiceController(<redacted>)")
    }
}

impl CredentialControllerHandlers for SecretServiceController {
    fn reconcile_handler(
        &self,
        input: &CredentialReconcileInput,
    ) -> Result<CredentialControllerDecision, CredentialControllerError> {
        let _guard = self
            .single_flight
            .try_enter(input.credential_uid().clone())?;
        reconcile_credential(input)
    }

    fn observe(
        &self,
        input: &CredentialObserveInput,
    ) -> Result<CredentialControllerDecision, CredentialControllerError> {
        let _guard = self
            .single_flight
            .try_enter(input.credential_uid().clone())?;
        observe_credential(input)
    }

    fn finalize(
        &self,
        input: &CredentialRevocationInput,
    ) -> Result<CredentialControllerDecision, CredentialControllerError> {
        let _guard = self
            .single_flight
            .try_enter(input.credential_uid().clone())?;
        revoke_credential(input)
    }

    fn drain(
        &self,
        input: &CredentialRevocationInput,
    ) -> Result<CredentialControllerDecision, CredentialControllerError> {
        let _guard = self
            .single_flight
            .try_enter(input.credential_uid().clone())?;
        revoke_credential(input)
    }

    fn health(
        &self,
        provider_process_reachable: bool,
        active_leases: u32,
        locked_count: u32,
    ) -> Result<CredentialControllerHealth, CredentialControllerError> {
        CredentialControllerHealth::derive(provider_process_reachable, active_leases, locked_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_policy_drives_closed_controller_health() {
        let closed = SecretServiceController::new(
            SecretServiceConfig::new("login", 64, LockPolicy::FailClosed).unwrap(),
        );
        let degraded = SecretServiceController::new(
            SecretServiceConfig::new("login", 64, LockPolicy::FailDegraded).unwrap(),
        );
        assert_eq!(
            closed
                .reconcile(SecretServiceState::Locked, None)
                .unwrap()
                .health,
            SecretServiceControllerHealth::Unavailable
        );
        assert_eq!(
            degraded
                .reconcile(SecretServiceState::Locked, None)
                .unwrap()
                .health,
            SecretServiceControllerHealth::Degraded
        );
        assert_eq!(
            closed
                .reconcile(SecretServiceState::Unlocked, None)
                .unwrap()
                .health,
            SecretServiceControllerHealth::Ready
        );
    }
}
