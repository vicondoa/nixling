//! Secret-free managed identity controller projections.

use d2b_contracts_provider::v3::credential::{
    CredentialInteractionState, CredentialLeaseStatus, CredentialMetadata, CredentialMethod,
    CredentialServiceError, CredentialServiceErrorCode, CredentialStatus,
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

use crate::{AGENT_BINARY, ManagedIdentityClientState, ManagedIdentityPlacement};

/// Finalizer owned by the managed-identity Credential controller.
pub const PROVIDER_REVOKE_FINALIZER: &str =
    d2b_contracts_provider::v3::credential_controller::CREDENTIAL_PROVIDER_REVOKE_FINALIZER;
/// Provider identity used by the shared controller registration.
pub const PROVIDER_KIND: CredentialProviderKind =
    CredentialProviderKind::ManagedIdentity;

/// Service route selected by the secret-free controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedIdentityRoute {
    /// Use stored non-secret status without an IMDS call.
    ControllerStoredMetadata,
    /// Route the live operation to the co-located agent.
    Agent,
}

/// Canonical controller-created agent Process projection.
#[derive(Clone, PartialEq, Eq)]
pub struct AgentProcessSpec {
    owner_ref: ResourceRef,
    execution_ref: ResourceRef,
    placement: d2b_contracts_provider::v3::credential::PlacementBinding,
}

impl AgentProcessSpec {
    /// Return the fixed agent binary.
    pub const fn binary(&self) -> &'static str {
        AGENT_BINARY
    }

    /// Borrow the Credential owner reference.
    pub const fn owner_ref(&self) -> &ResourceRef {
        &self.owner_ref
    }

    /// Borrow the exact co-location target.
    pub const fn execution_ref(&self) -> &ResourceRef {
        &self.execution_ref
    }

    /// Return the machine placement.
    pub const fn placement(&self) -> d2b_contracts_provider::v3::credential::PlacementBinding {
        self.placement
    }

    /// Agent network egress is always disabled; the injected effect port owns
    /// endpoint access.
    pub const fn allow_egress(&self) -> bool {
        false
    }

    /// The agent requires an explicit client supplied through an effect port.
    pub const fn requires_effect_port_client(&self) -> bool {
        true
    }
}

impl core::fmt::Debug for AgentProcessSpec {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AgentProcessSpec(<redacted>)")
    }
}

/// Ordered teardown effects owned by the controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagedIdentityTeardownPlan {
    /// Whether the agent must first drain and stop.
    pub stop_agent: bool,
    /// Whether the controller may delete the agent Process.
    pub delete_agent: bool,
    /// Whether revocation and Process deletion permit finalizer release.
    pub clear_provider_revoke: bool,
}

/// Common status plus closed client state.
#[derive(Clone, PartialEq, Eq)]
pub struct ManagedIdentityStatusProjection {
    /// Credential common status.
    pub status: CredentialStatus,
    /// Closed client state.
    pub client_state: ManagedIdentityClientState,
}

impl core::fmt::Debug for ManagedIdentityStatusProjection {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ManagedIdentityStatusProjection(<redacted>)")
    }
}

/// Stateless status-first controller that holds no IMDS client.
pub struct ManagedIdentityController {
    placement: ManagedIdentityPlacement,
    single_flight: CredentialSingleFlight,
}

impl ManagedIdentityController {
    /// Bind the secret-free controller to machine placement.
    pub fn new(placement: ManagedIdentityPlacement) -> Self {
        Self {
            placement,
            single_flight: CredentialSingleFlight::new(),
        }
    }

    /// Route live client operations to the agent while permitting a stored
    /// metadata projection at the controller.
    pub const fn route(method: CredentialMethod, live: bool) -> ManagedIdentityRoute {
        match (method, live) {
            (CredentialMethod::InspectMetadata, false) => {
                ManagedIdentityRoute::ControllerStoredMetadata
            }
            _ => ManagedIdentityRoute::Agent,
        }
    }

    /// Create the agent projection only after admission and dependency
    /// readiness. The controller receives no client while doing so.
    pub fn plan_agent(
        &self,
        credential_ref: ResourceRef,
        admitted: bool,
        dependencies_ready: bool,
    ) -> Result<Option<AgentProcessSpec>, CredentialServiceError> {
        if credential_ref.resource_type().as_str() != "Credential" {
            return Err(invariant());
        }
        if !admitted || !dependencies_ready {
            return Ok(None);
        }
        Ok(Some(AgentProcessSpec {
            owner_ref: credential_ref,
            execution_ref: self.placement.execution_ref().clone(),
            placement: self.placement.binding(),
        }))
    }

    /// Preserve finalizer ordering: stop, delete, then clear only after the
    /// revocation and Process-deletion observations both succeed.
    pub const fn teardown_plan(
        agent_running: bool,
        revocation_confirmed: bool,
        process_deleted: bool,
    ) -> ManagedIdentityTeardownPlan {
        ManagedIdentityTeardownPlan {
            stop_agent: agent_running,
            delete_agent: !agent_running && revocation_confirmed && !process_deleted,
            clear_provider_revoke: revocation_confirmed && process_deleted,
        }
    }

    /// Project bounded non-secret lease state.
    pub fn reconcile(
        &self,
        client_state: ManagedIdentityClientState,
        metadata: Option<&CredentialMetadata>,
    ) -> Result<ManagedIdentityStatusProjection, CredentialServiceError> {
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
        let status =
            CredentialStatus::new(CredentialInteractionState::NotRequired, None, None, lease)
                .map_err(|_| invariant())?;
        Ok(ManagedIdentityStatusProjection {
            status,
            client_state,
        })
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
        crate::audit::authorized_service_record(
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
        crate::telemetry::credential_frame(
            zone,
            operation,
            outcome,
            self.placement.binding(),
            rotation_generation,
        )
    }
}

impl core::fmt::Debug for ManagedIdentityController {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ManagedIdentityController(<redacted>)")
    }
}

impl CredentialControllerHandlers for ManagedIdentityController {
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

    #[test]
    fn ready_and_unavailable_are_closed_status_observations() {
        let controller = ManagedIdentityController::new(
            ManagedIdentityPlacement::new(
                PlacementBinding::HostSystem,
                ResourceRef::parse("Host/azure-vm").unwrap(),
                ResourceRef::parse("Zone/dev").unwrap(),
            )
            .unwrap(),
        );
        assert_eq!(
            controller
                .reconcile(ManagedIdentityClientState::Ready, None)
                .unwrap()
                .client_state,
            ManagedIdentityClientState::Ready
        );
        assert_eq!(
            controller
                .reconcile(ManagedIdentityClientState::Unavailable, None)
                .unwrap()
                .client_state,
            ManagedIdentityClientState::Unavailable
        );
    }

    #[test]
    fn agent_is_planned_only_after_admission_and_dependency_readiness() {
        let controller = ManagedIdentityController::new(
            ManagedIdentityPlacement::new(
                PlacementBinding::GuestAgent,
                ResourceRef::parse("Guest/aca-sandbox").unwrap(),
                ResourceRef::parse("Zone/dev").unwrap(),
            )
            .unwrap(),
        );
        let credential = ResourceRef::parse("Credential/aca-relay-mi").unwrap();
        assert!(
            controller
                .plan_agent(credential.clone(), false, true)
                .unwrap()
                .is_none()
        );
        let agent = controller
            .plan_agent(credential, true, true)
            .unwrap()
            .unwrap();
        assert_eq!(agent.binary(), AGENT_BINARY);
        assert!(!agent.allow_egress());
        assert!(agent.requires_effect_port_client());
    }
}
