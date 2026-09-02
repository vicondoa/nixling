//! Secret-free Entra controller projections.

#[path = "audit.rs"]
mod audit;
#[path = "telemetry.rs"]
mod telemetry;

use d2b_contracts_provider::v3::credential::CREDENTIAL_SERVICE_NAME;
use d2b_contracts_provider::v3::credential::{
    CredentialInteractionState, CredentialLeaseStatus, CredentialMetadata, CredentialServiceError,
    CredentialServiceErrorCode, CredentialStatus,
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
use d2b_contracts_resource::v3::ResourceRef;
use d2b_contracts_resource::v3::identity::{AuthenticatedSubjectContext, Locality};

use crate::{
    CREDENTIAL_SESSION_PURPOSE, EntraClientState, EntraPlacement, EntraResourceHealth,
    LOGIN_ENDPOINT_PURPOSE, MAX_REFRESH_ATTEMPTS, PROVIDER_REF,
};

/// Finalizer owned by the Entra Credential controller.
pub const PROVIDER_REVOKE_FINALIZER: &str =
    d2b_contracts_provider::v3::credential_controller::CREDENTIAL_PROVIDER_REVOKE_FINALIZER;
/// Provider identity used by the shared controller registration.
pub const PROVIDER_KIND: CredentialProviderKind = CredentialProviderKind::Entra;

/// Canonical provider-visible Endpoint policy for the Entrablau service.
#[derive(Clone, PartialEq, Eq)]
pub struct EntraEndpointPolicy {
    provider_ref: ResourceRef,
    consumer_ref: ResourceRef,
    execution_ref: ResourceRef,
}

impl EntraEndpointPolicy {
    /// Require canonical provider visibility and exact provider, consumer,
    /// and Guest execution references.
    pub fn new(
        visibility: &str,
        provider_ref: ResourceRef,
        consumer_ref: ResourceRef,
        execution_ref: ResourceRef,
    ) -> Result<Self, CredentialServiceError> {
        if visibility != "provider"
            || provider_ref.to_canonical_string() != PROVIDER_REF
            || consumer_ref.resource_type().as_str() != "Provider"
            || execution_ref.resource_type().as_str() != "Guest"
        {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::OperationDenied,
            ));
        }
        Ok(Self {
            provider_ref,
            consumer_ref,
            execution_ref,
        })
    }

    /// Return the fixed Endpoint purpose.
    pub const fn purpose(&self) -> &'static str {
        LOGIN_ENDPOINT_PURPOSE
    }

    /// Check one exact subject against the two allowed subjects.
    pub fn allows_subject(&self, subject: &ResourceRef) -> bool {
        subject == &self.provider_ref || subject == &self.consumer_ref
    }

    /// Check a trusted authenticated subject without accepting relay authority.
    pub fn allows_authenticated_subject(&self, subject: &AuthenticatedSubjectContext) -> bool {
        subject.transport_binding().locality() == Locality::Local
            && self.allows_subject(subject.subject_ref())
            && subject.execution_ref() == Some(&self.execution_ref)
            && subject
                .provider_ref()
                .is_some_and(|provider| provider == &self.provider_ref)
            && subject.provider_generation().is_some()
            && subject.service().as_str() == CREDENTIAL_SERVICE_NAME
            && subject.session_purpose().as_str() == CREDENTIAL_SESSION_PURPOSE
    }
}

impl core::fmt::Debug for EntraEndpointPolicy {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("EntraEndpointPolicy(<redacted>)")
    }
}

/// Common status plus client state.
#[derive(Clone, PartialEq, Eq)]
pub struct EntraStatusProjection {
    /// Credential common status.
    pub status: CredentialStatus,
    /// Closed client state.
    pub client_state: EntraClientState,
    /// Typed owning-resource health.
    pub resource_health: EntraResourceHealth,
    /// Bounded refresh retry position.
    pub refresh_attempts: u16,
}

impl core::fmt::Debug for EntraStatusProjection {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("EntraStatusProjection(<redacted>)")
    }
}

/// Stateless status-first Entra controller.
pub struct EntraController {
    placement: EntraPlacement,
    single_flight: CredentialSingleFlight,
}

impl EntraController {
    /// Bind the controller to one identity-Guest placement.
    pub fn new(placement: EntraPlacement) -> Self {
        Self {
            placement,
            single_flight: CredentialSingleFlight::new(),
        }
    }

    /// Project bounded non-secret state.
    pub fn reconcile(
        &self,
        client_state: EntraClientState,
        metadata: Option<&CredentialMetadata>,
    ) -> Result<EntraStatusProjection, CredentialServiceError> {
        self.reconcile_with_health(client_state, metadata, EntraResourceHealth::Ready, 0)
    }

    /// Project bounded non-secret state with owning-resource health.
    pub fn reconcile_with_health(
        &self,
        client_state: EntraClientState,
        metadata: Option<&CredentialMetadata>,
        resource_health: EntraResourceHealth,
        refresh_attempts: u16,
    ) -> Result<EntraStatusProjection, CredentialServiceError> {
        if refresh_attempts > MAX_REFRESH_ATTEMPTS {
            return Err(invariant());
        }
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
                    self.placement.binding(),
                )
            })
            .transpose()
            .map_err(|_| invariant())?;
        let interaction = match client_state {
            EntraClientState::Ready => CredentialInteractionState::NotRequired,
            EntraClientState::InteractionRequired => CredentialInteractionState::Required,
        };
        let status =
            CredentialStatus::new(interaction, None, None, lease).map_err(|_| invariant())?;
        Ok(EntraStatusProjection {
            status,
            client_state,
            resource_health,
            refresh_attempts,
        })
    }

    /// Project status only for an authorized local subject.
    pub fn project_for_subject(
        &self,
        policy: &EntraEndpointPolicy,
        subject: &AuthenticatedSubjectContext,
        client_state: EntraClientState,
        metadata: Option<&CredentialMetadata>,
        resource_health: EntraResourceHealth,
        refresh_attempts: u16,
    ) -> Result<EntraStatusProjection, CredentialServiceError> {
        if !policy.allows_authenticated_subject(subject)
            || self.placement.validate_zone(subject.zone_ref()).is_err()
            || subject.execution_ref() != Some(self.placement.execution_ref())
        {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::OperationDenied,
            ));
        }
        self.reconcile_with_health(client_state, metadata, resource_health, refresh_attempts)
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
        telemetry::frame(
            zone,
            operation,
            outcome,
            self.placement.binding(),
            rotation_generation,
        )
    }
}

impl core::fmt::Debug for EntraController {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("EntraController(<redacted>)")
    }
}

impl CredentialControllerHandlers for EntraController {
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

fn invariant() -> CredentialServiceError {
    CredentialServiceError::new(CredentialServiceErrorCode::InvariantFailure)
}

#[cfg(test)]
mod tests {
    use super::*;
    use d2b_contracts_provider::v3::credential::PlacementBinding;

    fn controller() -> EntraController {
        EntraController::new(
            EntraPlacement::new_in_zone(
                ResourceRef::parse("Zone/work").unwrap(),
                PlacementBinding::GuestAgent,
                ResourceRef::parse("Guest/consumer").unwrap(),
                ResourceRef::parse("Guest/identity").unwrap(),
                ResourceRef::parse("Endpoint/entra-login").unwrap(),
                1,
            )
            .unwrap(),
        )
    }

    #[test]
    fn client_state_projects_interaction_required_without_a_denial() {
        let required = controller()
            .reconcile(EntraClientState::InteractionRequired, None)
            .unwrap();
        assert_eq!(
            required.status.interaction_state(),
            CredentialInteractionState::Required
        );
        let ready = controller()
            .reconcile(EntraClientState::Ready, None)
            .unwrap();
        assert_eq!(
            ready.status.interaction_state(),
            CredentialInteractionState::NotRequired
        );
    }
}
