#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::Arc;

use d2b_contracts::types::VmId;
use d2b_contracts_broker::broker_wire::{
    BrokerRequest, BrokerResponse, OpenHidrawSecurityKeyRequest,
};
use d2b_contracts_resource::v3::{ResourceRef, ResourceUid};
use d2b_core::bundle_resolver::BundleResolver;
use d2b_core::processes::{ProcessRole, ReadinessPredicate};
use d2b_provider_device_security_key::{
    DEFAULT_SESSION_RING_SIZE, PROVIDER_REF, PhysicalAuthorityLease, PhysicalUsbBackingClaim,
    PhysicalUsbBackingToken, RelayLaunchTicket, SecurityKeyAdmission, SecurityKeyController,
    SecurityKeyEffectError, SecurityKeyEffectPort, SecurityKeyOpenIntent, SecurityKeySessionId,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::resource_runtime::{
    ResourceRuntimeError, SecurityKeyDeviceAdmissionRequest, ZoneResourceRuntime,
};
use crate::{PeerIdentity, PeerRole, ServerState};

pub(crate) fn is_reconcile_request(request: &Value) -> bool {
    request.get("method").and_then(Value::as_str) == Some("Reconcile")
        && request.get("resourceType").and_then(Value::as_str) == Some("Device")
        && request.get("providerRef").and_then(Value::as_str) == Some(PROVIDER_REF)
}

pub(crate) fn dispatch_reconcile(
    state: &ServerState,
    peer: &PeerIdentity,
    runtime: &ZoneResourceRuntime,
    request: &Value,
) -> Result<Value, ResourceRuntimeError> {
    if !matches!(peer.role, PeerRole::Admin) {
        return Err(ResourceRuntimeError::AuthenticationUnavailable);
    }
    let vm_id = request
        .get("vmId")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 64)
        .ok_or(ResourceRuntimeError::RequestInvalid)?;
    let selector_id = request
        .get("selectorId")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 63)
        .ok_or(ResourceRuntimeError::RequestInvalid)?;
    let operation_id = request
        .get("operationId")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .ok_or(ResourceRuntimeError::RequestInvalid)?;
    let device_uid = request
        .get("resourceUid")
        .and_then(Value::as_str)
        .and_then(|value| ResourceUid::parse(value).ok())
        .ok_or(ResourceRuntimeError::RequestInvalid)?;
    let device_ref = request
        .get("deviceRef")
        .and_then(Value::as_str)
        .and_then(|value| ResourceRef::parse(value).ok())
        .filter(|reference| reference.resource_type().as_str() == "Device")
        .ok_or(ResourceRuntimeError::RequestInvalid)?;
    let zone_ref = request
        .get("zoneRef")
        .and_then(Value::as_str)
        .and_then(|value| ResourceRef::parse(value).ok())
        .filter(|reference| reference.resource_type().as_str() == "Zone")
        .ok_or(ResourceRuntimeError::RouteMismatch)?;
    let holder_ref = request
        .get("holderRef")
        .and_then(Value::as_str)
        .and_then(|value| ResourceRef::parse(value).ok())
        .filter(|reference| reference.resource_type().as_str() == "Guest")
        .ok_or(ResourceRuntimeError::RequestInvalid)?;
    let admitted = crate::block_on_future(runtime.security_key_device_is_admitted(
        SecurityKeyDeviceAdmissionRequest {
            device_uid: &device_uid,
            device_ref: &device_ref,
            request_zone_ref: &zone_ref,
            holder_ref: &holder_ref,
            vm_id,
            selector_id,
            operation_id,
        },
    ))?;
    let backing = backing_token(&admitted.selector_id);
    if state
        .security_key_sessions
        .lock()
        .has_live_claim(vm_id, &backing)
    {
        return Ok(json!({
            "resourceType": "Device",
            "provider": PROVIDER_REF,
            "outcome": "active"
        }));
    }
    let resolver = crate::load_bundle_resolver(state)
        .map_err(|_| ResourceRuntimeError::ProviderPathUnavailable)?;
    let target = relay_target(&resolver, vm_id)?;
    let admission = SecurityKeyAdmission::from_core(
        admitted.zone_ref.clone(),
        admitted.device_uid.clone(),
        admitted.holder_ref.clone(),
        backing,
    );
    let mut controller = SecurityKeyController::new_authorized(
        admitted.device_uid.clone(),
        admission,
        DEFAULT_SESSION_RING_SIZE,
    )
    .map_err(|_| ResourceRuntimeError::ProviderPathUnavailable)?;
    let mut effect = LiveSecurityKeyEffectPort {
        state,
        vm_id: VmId::new(vm_id),
        selector_id: admitted.selector_id,
        device_ref: device_ref.clone(),
        zone_ref: admitted.zone_ref.clone(),
        device_uid: admitted.device_uid.clone(),
        holder_ref: admitted.holder_ref.clone(),
        target,
        caller_role: crate::broker_caller_role_for_peer(peer),
        claimed_backing: None,
    };
    controller
        .acquire_authorized(
            session_id(operation_id, &admitted.device_uid),
            admitted.device_uid,
            &admitted.holder_ref,
            &mut effect,
        )
        .map_err(|_| ResourceRuntimeError::ProviderPathUnavailable)?;
    Ok(json!({
        "resourceType": "Device",
        "provider": PROVIDER_REF,
        "outcome": "active"
    }))
}

struct RelayTarget {
    socket_path: PathBuf,
    uid: u32,
    gid: u32,
}

/// Resolve the retained legacy security-key frontend. v3 Guest lifecycle
/// requests never use this connector or its process-DAG locator.
fn relay_target(
    resolver: &BundleResolver,
    vm_id: &str,
) -> Result<RelayTarget, ResourceRuntimeError> {
    let node = resolver
        .find_process_vm(vm_id)
        .and_then(|dag| {
            dag.nodes
                .iter()
                .find(|node| node.role == ProcessRole::SecurityKeyFrontend)
        })
        .ok_or(ResourceRuntimeError::ProviderPathUnavailable)?;
    let socket_path = node
        .readiness
        .iter()
        .find_map(|predicate| match predicate {
            ReadinessPredicate::UnixSocketExists(path)
            | ReadinessPredicate::UnixSocketListening(path) => Some(PathBuf::from(path)),
            _ => None,
        })
        .ok_or(ResourceRuntimeError::ProviderPathUnavailable)?;
    Ok(RelayTarget {
        socket_path,
        uid: node.profile.uid,
        gid: node.profile.gid,
    })
}

struct LiveSecurityKeyEffectPort<'a> {
    state: &'a ServerState,
    vm_id: VmId,
    selector_id: String,
    device_ref: ResourceRef,
    zone_ref: ResourceRef,
    device_uid: ResourceUid,
    holder_ref: ResourceRef,
    target: RelayTarget,
    caller_role: d2b_contracts_broker::broker_wire::BrokerCallerRole,
    claimed_backing: Option<PhysicalUsbBackingToken>,
}

impl SecurityKeyEffectPort for LiveSecurityKeyEffectPort<'_> {
    fn claim_physical_backing(
        &mut self,
        claim: &PhysicalUsbBackingClaim,
    ) -> Result<PhysicalAuthorityLease, SecurityKeyEffectError> {
        if claim.device_uid() != Some(&self.device_uid)
            || claim.zone_ref() != Some(&self.zone_ref)
            || claim.holder_ref() != Some(&self.holder_ref)
        {
            return Err(SecurityKeyEffectError::AuthorizationDenied);
        }
        let backing = claim.token().clone();
        if !self
            .state
            .security_key_sessions
            .lock()
            .claim_backing(self.vm_id.as_str(), backing.clone())
        {
            return Err(SecurityKeyEffectError::PhysicalUsbBackingConflict);
        }
        self.claimed_backing = Some(backing);
        Ok(PhysicalAuthorityLease::from_core(ticket_bytes(
            b"d2b:security-key-lease/v1",
            self.selector_id.as_bytes(),
        )))
    }

    fn open_hidraw(
        &mut self,
        intent: &SecurityKeyOpenIntent,
    ) -> Result<RelayLaunchTicket, SecurityKeyEffectError> {
        if intent.device_uid() != &self.device_uid
            || intent.backing().device_uid() != Some(&self.device_uid)
            || intent.backing().zone_ref() != Some(&self.zone_ref)
            || intent.backing().holder_ref() != Some(&self.holder_ref)
        {
            return Err(SecurityKeyEffectError::AuthorizationDenied);
        }
        let (response, fds) = crate::dispatch_broker_request_with_fds_timeout_as(
            self.state,
            BrokerRequest::OpenHidrawSecurityKey(OpenHidrawSecurityKeyRequest {
                vm_id: self.vm_id.clone(),
                selector_id: self.selector_id.clone(),
                device_ref: self.device_ref.clone(),
                authority_key: d2b_contracts_broker::broker_wire::security_key_authority_binding(
                    &self.device_ref,
                    &self.selector_id,
                ),
                tracing_span_id: None,
            }),
            self.caller_role.clone(),
            std::time::Duration::from_secs(30),
        )
        .map_err(|_| SecurityKeyEffectError::BrokerInaccessible)?;
        if !matches!(response, BrokerResponse::OpenHidrawSecurityKey(_)) || fds.len() != 1 {
            crate::close_received_fds(&fds);
            return Err(SecurityKeyEffectError::EffectRejected);
        }
        let fd = match crate::duplicate_received_fd(&fds, 0, "security-key hidraw") {
            Ok(fd) => fd,
            Err(_) => {
                crate::close_received_fds(&fds);
                return Err(SecurityKeyEffectError::EffectRejected);
            }
        };
        crate::close_received_fds(&fds);
        let listener = crate::security_key::bind_accept_socket(&self.target.socket_path)
            .map_err(|_| SecurityKeyEffectError::Transient)?;
        let mut relay_state = crate::security_key::SecurityKeyState::new(self.selector_id.clone());
        relay_state.enable_vm(self.vm_id.as_str());
        let state = Arc::new(parking_lot::Mutex::new(relay_state));
        let abort = crate::security_key::spawn_accept_loop(
            listener,
            self.vm_id.as_str().to_owned(),
            self.target.uid,
            self.target.gid,
            Arc::clone(&state),
            crate::security_key::HidrawDevice::from_owned_fd(fd),
        )
        .map_err(|_| SecurityKeyEffectError::Transient)?;
        self.state.security_key_sessions.lock().register(
            self.vm_id.as_str().to_owned(),
            crate::security_key::SkAcceptHandle { state, abort },
        );
        Ok(RelayLaunchTicket::from_core(ticket_bytes(
            b"d2b:security-key-relay/v1",
            intent.device_uid().as_str().as_bytes(),
        )))
    }

    fn release_physical_backing(
        &mut self,
        _lease: PhysicalAuthorityLease,
    ) -> Result<(), SecurityKeyEffectError> {
        if let Some(backing) = self.claimed_backing.take() {
            self.state
                .security_key_sessions
                .lock()
                .release_backing(self.vm_id.as_str(), &backing);
        }
        Ok(())
    }
}

fn backing_token(selector_id: &str) -> PhysicalUsbBackingToken {
    PhysicalUsbBackingToken::from_core(ticket_bytes32(
        b"d2b:security-key-backing/v1",
        selector_id.as_bytes(),
    ))
}

fn session_id(operation: &str, device_uid: &ResourceUid) -> SecurityKeySessionId {
    SecurityKeySessionId::from_core(ticket_bytes(
        b"d2b:security-key-session/v1",
        format!("{}:{operation}", device_uid.as_str()).as_bytes(),
    ))
}

fn ticket_bytes(domain: &[u8], value: &[u8]) -> [u8; 16] {
    let digest = Sha256::new()
        .chain_update(domain)
        .chain_update([0])
        .chain_update(value)
        .finalize();
    let mut out = [0; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

fn ticket_bytes32(domain: &[u8], value: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(domain)
        .chain_update([0])
        .chain_update(value)
        .finalize()
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_request_requires_exact_device_selector_binding() {
        let request = json!({
            "method": "Reconcile",
            "resourceType": "Device",
            "providerRef": "Provider/device-security-key",
            "deviceRef": "Device/key-a",
            "selectorId": "key-b"
        });
        assert!(is_reconcile_request(&request));
        let device = ResourceRef::parse(request["deviceRef"].as_str().unwrap()).unwrap();
        assert_ne!(
            device.name().as_str(),
            request["selectorId"].as_str().unwrap()
        );
    }
}
