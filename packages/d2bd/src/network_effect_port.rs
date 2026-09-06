//! Core-owned production adapter for `Provider/network-local`.
//!
//! The provider receives no broker socket or raw host intent. This module
//! resolves the provider's opaque context into the existing typed broker wire
//! operations and maps only closed broker outcomes back to the provider.

use d2b_contracts_broker::broker_wire::{
    ApplyNftablesProjectionRequest, ApplyNmUnmanagedRequest, ApplyRouteRequest, ApplySysctlRequest,
    BrokerCallerRole, BrokerRequest, BrokerResponse, CreateBridgeRequest, DeleteBridgeRequest,
    DeletePersistentTapRequest, NftablesProjectionAction, SeedDnsmasqLeaseRequest,
    UpdateHostsFileRequest,
};
use d2b_provider_network_local::{
    broker::{BrokerNetworkEffectPort, NetworkBroker, NetworkBrokerError, NetworkEffectContext},
    controller::FirewallDigest,
};

use crate::ServerState;

/// A Core adapter that sends one typed request through the authenticated
/// daemon-to-broker transport.
#[allow(dead_code)]
pub(crate) struct DaemonNetworkBroker<'a> {
    state: &'a ServerState,
    caller_role: BrokerCallerRole,
}

#[allow(dead_code)]
impl<'a> DaemonNetworkBroker<'a> {
    /// Bind the adapter to the current daemon request and caller role.
    pub(crate) const fn new(state: &'a ServerState, caller_role: BrokerCallerRole) -> Self {
        Self { state, caller_role }
    }

    fn dispatch(&self, request: BrokerRequest) -> Result<(), NetworkBrokerError> {
        match crate::dispatch_broker_request_as(self.state, request, self.caller_role.clone()) {
            Ok(BrokerResponse::Error(error)) => {
                tracing::warn!(
                    broker_kind = %error.kind,
                    broker_operation = %error.operation,
                    "Network broker rejected a typed effect request"
                );
                Err(map_broker_error(&error.kind, &error.message))
            }
            Ok(BrokerResponse::Ack(_)) => Ok(()),
            Ok(_) => Err(NetworkBrokerError::Rejected),
            Err(_) => Err(NetworkBrokerError::Transport),
        }
    }
}

/// The production provider effect-port type.
#[allow(dead_code)]
pub(crate) type DaemonNetworkEffectPort<'a> = BrokerNetworkEffectPort<DaemonNetworkBroker<'a>>;

/// Construct a production Network effect port for one Core-resolved context.
#[allow(dead_code)]
pub(crate) fn production_port<'a>(
    state: &'a ServerState,
    caller_role: BrokerCallerRole,
    context: NetworkEffectContext,
) -> DaemonNetworkEffectPort<'a> {
    BrokerNetworkEffectPort::new(DaemonNetworkBroker::new(state, caller_role), context)
}

impl NetworkBroker for DaemonNetworkBroker<'_> {
    fn create_bridge(&self, context: &NetworkEffectContext) -> Result<(), NetworkBrokerError> {
        let provenance = context.provenance()?;
        for intent_ref in context.bridge_intent_refs() {
            self.dispatch(BrokerRequest::CreateBridge(CreateBridgeRequest {
                bundle_bridge_intent_ref: intent_ref.clone(),
                scope_id: context.scope_id().clone(),
                zone_uid: provenance.zone_uid().clone(),
                network_uid: provenance.network_uid().clone(),
                network_generation: provenance.network_generation(),
                attachment_generation: provenance.attachment_generation(),
                bundle_generation: provenance.bundle_generation().clone(),
                tracing_span_id: None,
            }))?;
        }
        Ok(())
    }

    fn delete_bridge(&self, context: &NetworkEffectContext) -> Result<(), NetworkBrokerError> {
        let provenance = context.provenance()?;
        for intent_ref in context.bridge_intent_refs() {
            self.dispatch(BrokerRequest::DeleteBridge(DeleteBridgeRequest {
                bundle_bridge_intent_ref: intent_ref.clone(),
                scope_id: context.scope_id().clone(),
                zone_uid: provenance.zone_uid().clone(),
                network_uid: provenance.network_uid().clone(),
                network_generation: provenance.network_generation(),
                attachment_generation: provenance.attachment_generation(),
                bundle_generation: provenance.bundle_generation().clone(),
                tracing_span_id: None,
            }))?;
        }
        Ok(())
    }

    fn apply_projection(
        &self,
        context: &NetworkEffectContext,
        action: NftablesProjectionAction,
    ) -> Result<FirewallDigest, NetworkBrokerError> {
        let provenance = context.provenance()?;
        self.dispatch(BrokerRequest::ApplyNftablesProjection(
            ApplyNftablesProjectionRequest {
                bundle_nft_projection_intent_ref: context.projection_intent_ref().clone(),
                scope_id: context.scope_id().clone(),
                action,
                zone_uid: provenance.zone_uid().clone(),
                network_uid: provenance.network_uid().clone(),
                network_generation: provenance.network_generation(),
                attachment_generation: provenance.attachment_generation(),
                expected_generation_id: context.expected_generation_id().clone(),
                desired_hash: None,
                tracing_span_id: None,
            },
        ))?;
        Ok(FirewallDigest::new(context.projection_digest()))
    }

    fn apply_nm_unmanaged(&self, context: &NetworkEffectContext) -> Result<(), NetworkBrokerError> {
        self.dispatch(BrokerRequest::ApplyNmUnmanaged(ApplyNmUnmanagedRequest {
            bundle_nm_intent_ref: context.nm_intent_ref().clone(),
            scope_id: context.scope_id().clone(),
            destroy: false,
            tracing_span_id: None,
        }))
    }

    fn apply_routes(&self, context: &NetworkEffectContext) -> Result<(), NetworkBrokerError> {
        let provenance = context.provenance()?;
        for intent_ref in context.route_intent_refs() {
            self.dispatch(BrokerRequest::ApplyRoute(ApplyRouteRequest {
                bundle_route_intent_ref: intent_ref.clone(),
                scope_id: context.scope_id().clone(),
                zone_uid: provenance.zone_uid().clone(),
                network_uid: provenance.network_uid().clone(),
                network_generation: provenance.network_generation(),
                attachment_generation: provenance.attachment_generation(),
                bundle_generation: provenance.bundle_generation().clone(),
                destroy: false,
                tracing_span_id: None,
            }))?;
        }
        Ok(())
    }

    fn remove_routes(&self, context: &NetworkEffectContext) -> Result<(), NetworkBrokerError> {
        let provenance = context.provenance()?;
        for intent_ref in context.route_intent_refs() {
            self.dispatch(BrokerRequest::ApplyRoute(ApplyRouteRequest {
                bundle_route_intent_ref: intent_ref.clone(),
                scope_id: context.scope_id().clone(),
                zone_uid: provenance.zone_uid().clone(),
                network_uid: provenance.network_uid().clone(),
                network_generation: provenance.network_generation(),
                attachment_generation: provenance.attachment_generation(),
                bundle_generation: provenance.bundle_generation().clone(),
                destroy: true,
                tracing_span_id: None,
            }))?;
        }
        Ok(())
    }

    fn apply_sysctls(&self, context: &NetworkEffectContext) -> Result<(), NetworkBrokerError> {
        let provenance = context.provenance()?;
        for intent_ref in context.sysctl_intent_refs() {
            self.dispatch(BrokerRequest::ApplySysctl(ApplySysctlRequest {
                bundle_sysctl_intent_ref: intent_ref.clone(),
                scope_id: context.scope_id().clone(),
                zone_uid: provenance.zone_uid().clone(),
                network_uid: provenance.network_uid().clone(),
                network_generation: provenance.network_generation(),
                attachment_generation: provenance.attachment_generation(),
                bundle_generation: provenance.bundle_generation().clone(),
                destroy: false,
                tracing_span_id: None,
            }))?;
        }
        Ok(())
    }

    fn update_hosts(&self, context: &NetworkEffectContext) -> Result<(), NetworkBrokerError> {
        let provenance = context.provenance()?;
        self.dispatch(BrokerRequest::UpdateHostsFile(UpdateHostsFileRequest {
            bundle_hosts_intent_ref: context.hosts_intent_ref().clone(),
            zone_uid: Some(provenance.zone_uid().clone()),
            network_uid: Some(provenance.network_uid().clone()),
            network_generation: Some(provenance.network_generation()),
            attachment_generation: Some(provenance.attachment_generation()),
            bundle_generation: Some(provenance.bundle_generation().clone()),
            destroy: false,
            tracing_span_id: None,
        }))
    }

    fn seed_dhcp(&self, context: &NetworkEffectContext) -> Result<(), NetworkBrokerError> {
        let provenance = context.provenance()?;
        self.dispatch(BrokerRequest::SeedDnsmasqLease(SeedDnsmasqLeaseRequest {
            vm_id: context.dnsmasq_vm_id().clone(),
            scope_id: context.scope_id().clone(),
            zone_uid: provenance.zone_uid().clone(),
            network_uid: provenance.network_uid().clone(),
            network_generation: provenance.network_generation(),
            attachment_generation: provenance.attachment_generation(),
            bundle_generation: provenance.bundle_generation().clone(),
            tracing_span_id: None,
        }))
    }

    fn delete_persistent_tap(
        &self,
        context: &NetworkEffectContext,
        handle: &d2b_contracts_resource::v3::network::AttachmentHandle,
        fence: &d2b_contracts_resource::v3::network::AttachmentGenerationFence,
    ) -> Result<(), NetworkBrokerError> {
        let proof = context
            .network_admission()
            .ok_or(NetworkBrokerError::NetworkAdmissionRequired)?;
        if handle.opaque_id() != fence.attachment_uid() {
            return Err(NetworkBrokerError::NetworkAdmissionMismatch);
        }
        self.dispatch(BrokerRequest::DeletePersistentTap(
            DeletePersistentTapRequest {
                attachment_id: handle.opaque_id().clone(),
                expected_zone_uid: proof.key().zone_uid().clone(),
                expected_network_uid: proof.key().network_uid().clone(),
                expected_network_generation: fence.network_generation(),
                expected_attachment_generation: fence.attachment_generation(),
                expected_bundle_generation: proof.key().bundle_generation().clone(),
                tracing_span_id: None,
            },
        ))
    }
}

#[allow(dead_code)]
fn map_broker_error(kind: &str, message: &str) -> NetworkBrokerError {
    if message.contains("nm-managed-foreign-conflict")
        || message.contains("foreign route")
        || message.contains("foreign-bridge-ownership-marker")
        || message.contains("foreign-tap-ownership-marker")
        || message.contains("foreign-nft-ownership")
        || message.contains("foreign ownership marker")
    {
        return NetworkBrokerError::ForeignOwnership;
    }
    let reason = message
        .split_once("failed: ")
        .map_or(message, |(_, reason)| reason);
    if reason.contains("stale-bundle-generation") {
        return NetworkBrokerError::StaleGeneration;
    }
    if reason.contains("network-zone-unknown") {
        return NetworkBrokerError::NetworkAdmissionMismatch;
    }
    match (kind, reason) {
        ("Broker.NftablesDriftDetected", _)
        | ("Broker.StaleProjectionGeneration", _)
        | ("Broker.RequestValidation", "stale-projection-generation")
        | ("Broker.RequestValidation", "stale-network-generation") => {
            NetworkBrokerError::StaleGeneration
        }
        ("Broker.ForeignOwnership", _)
        | ("Broker.RequestValidation", "foreign-nft-rule-preserved")
        | ("Broker.RequestValidation", "nm-managed-foreign-conflict")
        | ("Broker.RequestValidation", "attachment-ownership-conflict") => {
            NetworkBrokerError::ForeignOwnership
        }
        ("Broker.RequestValidation", "stale-attachment-generation") => {
            NetworkBrokerError::StaleAttachmentGeneration
        }
        ("Broker.RequestValidation", "network-admission-required") => {
            NetworkBrokerError::NetworkAdmissionRequired
        }
        ("Broker.RequestValidation", "network-admission-mismatch")
        | ("Broker.RequestValidation", "network-scope-invalid")
        | ("Broker.RequestValidation", "network-scope-required")
        | ("Broker.RequestValidation", "network-scope-mismatch") => {
            NetworkBrokerError::NetworkAdmissionMismatch
        }
        ("Broker.RequestValidation", "network-interface-collision") => {
            NetworkBrokerError::NetworkInterfaceCollision
        }
        ("Broker.RequestValidation", "network-route-collision") => {
            NetworkBrokerError::NetworkRouteCollision
        }
        ("Broker.RequestValidation", "network-admission-conflict")
        | ("Broker.RequestValidation", "legacy-network-authority") => {
            NetworkBrokerError::NetworkAdmissionConflict
        }
        ("Broker.RequestValidation", "attachment-delete-failed")
        | ("Broker.RequestValidation", "network-broker-transient") => NetworkBrokerError::Transient,
        ("Broker.Transient", _) | (_, "network-effect-transient") => NetworkBrokerError::Transient,
        (_, "east-west-host-opt-in-required") => NetworkBrokerError::EastWestHostOptInRequired,
        _ => NetworkBrokerError::Rejected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_validation_reasons_keep_provider_retry_and_block_states() {
        assert_eq!(
            map_broker_error(
                "Broker.RequestValidation",
                "broker request validation failed: stale-projection-generation",
            ),
            NetworkBrokerError::StaleGeneration
        );
        assert_eq!(
            map_broker_error(
                "Broker.RequestValidation",
                "broker request validation failed: stale-attachment-generation",
            ),
            NetworkBrokerError::StaleAttachmentGeneration
        );
        assert_eq!(
            map_broker_error(
                "Broker.RequestValidation",
                "broker request validation failed: attachment-ownership-conflict",
            ),
            NetworkBrokerError::ForeignOwnership
        );
        assert_eq!(
            map_broker_error(
                "Broker.LiveHandler",
                "broker live handler failed: nm-managed-foreign-conflict",
            ),
            NetworkBrokerError::ForeignOwnership
        );
        assert_eq!(
            map_broker_error(
                "Broker.RequestValidation",
                "broker request validation failed: east-west-host-opt-in-required",
            ),
            NetworkBrokerError::EastWestHostOptInRequired
        );
    }
}
