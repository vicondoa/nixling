//! Durable Zone-owned reconciliation for AudioService and AudioBinding rows.
//!
//! Audio policy resources are durable store objects.  This module is the
//! daemon-side owner that relists them after restart, validates their
//! relationships, and keeps one controller per binding until finalization.
//! Host effects still flow through the broker-backed mediator in
//! `audio_dispatch`; this registry owns policy state, not privileged handles.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use d2b_contracts_provider::v3::semantic_services::child_resources::BindingChildSet;
#[cfg(test)]
use d2b_contracts_resource::v3::ZoneRevision;
use d2b_contracts_resource::v3::{ResourceEnvelope, ResourceRef, ResourceTypeName, ZoneId};
use d2b_provider_audio_pipewire::{
    AudioArbitrationState, AudioBindingController, AudioBindingPhase, AudioBindingSpec,
    AudioBindingStatus, AudioControllerError, AudioEnforcementPosture, AudioLastSetApplied,
    AudioMediator, AudioServiceRole, AudioServiceSpec, GuestAudioReadiness, HostAudioReadiness,
    MicDecision, resource_type::PROVIDER_REF, shared_microphone_arbiter,
    validate_audio_binding_in_zone, validate_audio_service,
};
use d2b_resource_store::{StoreListRequest, StoreOperationContext, StoreProjection, StoredResource};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};

use crate::ServerState;
use crate::audio_dispatch::{DaemonAudioMediator, audio_capability_for_vm};
use crate::binding_child_resource_runtime::BindingChildOwner;

pub(crate) const AUDIO_SERVICE_TYPE: &str = "audio.d2bus.org.AudioService";
pub(crate) const AUDIO_BINDING_TYPE: &str = "audio.d2bus.org.AudioBinding";
const GUEST_TYPE: &str = "Guest";
type DecodedAudioBinding = (String, (StoredResource, AudioBindingSpec));

/// One relisted audio resource snapshot.
#[derive(Debug, Clone, Default)]
pub(crate) struct AudioResourceSnapshot {
    pub services: Vec<StoredResource>,
    pub bindings: Vec<StoredResource>,
    pub guests: Vec<StoredResource>,
}

/// Stable errors for the daemon-owned audio resource path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AudioResourceRuntimeError {
    /// A resource body was malformed or used an unexpected provider.
    InvalidResource,
    /// A binding referred to a different or missing Zone resource.
    InvalidRelationship,
    /// A controller finalizer or effect failed.
    Controller(AudioControllerError),
}

impl core::fmt::Display for AudioResourceRuntimeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidResource => "audio-resource-invalid",
            Self::InvalidRelationship => "audio-resource-relationship-invalid",
            Self::Controller(error) => match error {
                AudioControllerError::Admission => "audio-controller-admission-failed",
                AudioControllerError::Mediator(_) => "audio-controller-effect-failed",
            },
        })
    }
}

impl std::error::Error for AudioResourceRuntimeError {}

/// Daemon-owned status for one durable AudioBinding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AudioBindingRuntimeStatus {
    pub resource: ResourceRef,
    pub status: AudioBindingStatus,
}

pub(crate) fn audio_binding_status_value(status: AudioBindingStatus) -> serde_json::Value {
    serde_json::json!({
        "phase": match status.phase {
            AudioBindingPhase::Pending => "Pending",
            AudioBindingPhase::Ready => "Ready",
            AudioBindingPhase::Degraded => "Degraded",
            AudioBindingPhase::Deleted => "Deleted",
        },
        "hostReadiness": match status.host_readiness {
            HostAudioReadiness::Ready => "Ready",
            HostAudioReadiness::Unavailable => "Unavailable",
        },
        "guestReadiness": match status.guest_readiness {
            GuestAudioReadiness::Ready => "Ready",
            GuestAudioReadiness::Unavailable => "Unavailable",
        },
        "microphone": status.microphone.map(|decision| match decision {
            MicDecision::Granted => "Granted",
            MicDecision::Queued => "Queued",
            MicDecision::QueueFull => "QueueFull",
        }),
        "channels": {
            "speaker": {
                "grant": status.channels.speaker.grant.as_wire_str(),
                "level": status.channels.speaker.level,
                "liveEnforced": status.channels.speaker.live_enforced,
            },
            "mic": {
                "grant": status.channels.mic.grant.as_wire_str(),
                "gain": status.channels.mic.gain,
                "liveEnforced": status.channels.mic.live_enforced,
                "arbitrationState": match status.channels.mic.arbitration_state {
                    AudioArbitrationState::Inactive => "inactive",
                    AudioArbitrationState::Queued => "queued",
                    AudioArbitrationState::Active => "active",
                    AudioArbitrationState::Blocked => "blocked",
                },
            },
        },
        "enforcementPosture": match status.enforcement_posture {
            AudioEnforcementPosture::HostAndGuest => "HostAndGuest",
            AudioEnforcementPosture::HostOnly => "HostOnly",
            AudioEnforcementPosture::GuestOnly => "GuestOnly",
            AudioEnforcementPosture::None => "None",
        },
        "lastSetApplied": match status.last_set_applied {
            AudioLastSetApplied::HostAndGuest => "HostAndGuest",
            AudioLastSetApplied::HostOnly => "HostOnly",
            AudioLastSetApplied::GuestOnly => "GuestOnly",
            AudioLastSetApplied::OfflineOnly => "OfflineOnly",
        },
    })
}

struct AudioBindingRecord {
    spec: AudioBindingSpec,
    lease: d2b_provider_audio_pipewire::AudioLeaseId,
    controller: Option<AudioBindingController<DaemonAudioMediator>>,
    status: AudioBindingStatus,
    children: Option<BindingChildSet>,
}

/// One Zone's durable audio controller registry.
pub(crate) struct AudioResourceRuntime {
    zone: ZoneId,
    state: Arc<ServerState>,
    services: BTreeMap<String, AudioServiceSpec>,
    service_microphones: BTreeMap<String, d2b_provider_audio_pipewire::SharedMicrophoneArbiter>,
    bindings: BTreeMap<String, AudioBindingRecord>,
}

impl core::fmt::Debug for AudioResourceRuntime {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AudioResourceRuntime")
            .field("zone", &self.zone)
            .field("service_count", &self.services.len())
            .field("service_authority_count", &self.service_microphones.len())
            .field("binding_count", &self.bindings.len())
            .finish()
    }
}

impl AudioResourceRuntime {
    pub(crate) fn new(zone: ZoneId, state: Arc<ServerState>) -> Self {
        Self {
            zone,
            state,
            services: BTreeMap::new(),
            service_microphones: BTreeMap::new(),
            bindings: BTreeMap::new(),
        }
    }

    /// Reconcile the complete durable snapshot. Removed bindings are
    /// finalized before service authority is replaced or released.
    pub(crate) fn reconcile(
        &mut self,
        snapshot: AudioResourceSnapshot,
    ) -> Result<(), AudioResourceRuntimeError> {
        let services = decode_services(&self.zone, &snapshot.services)?;
        self.service_microphones
            .retain(|service_ref, _| services.contains_key(service_ref));
        let guests = decode_guest_names(&snapshot.guests)?;
        let bindings = decode_bindings(&self.zone, &snapshot.bindings)?;
        validate_relationships(&services, &bindings, &guests)?;
        let manifest = crate::load_json::<d2b_core::manifest_v04::ManifestV04>(
            &self.state.config.artifacts.public_manifest_path,
        )
        .ok();
        let active_targets = bindings
            .iter()
            .filter(|(_, (resource, _))| !deletion_requested(resource))
            .map(|(_, (_, spec))| spec.target_ref.clone())
            .collect::<BTreeSet<_>>();

        let desired_keys = bindings
            .iter()
            .map(|(key, _)| key.clone())
            .collect::<BTreeSet<_>>();
        let removed = self
            .bindings
            .keys()
            .filter(|key| !desired_keys.contains(*key))
            .cloned()
            .collect::<Vec<_>>();
        for key in removed {
            let promoted = if let Some(record) = self.bindings.get_mut(&key) {
                if let Some(controller) = record.controller.as_mut() {
                    controller
                        .finalize_shared(record.lease)
                        .map_err(AudioResourceRuntimeError::Controller)?
                } else {
                    None
                }
            } else {
                None
            };
            if let Some(promoted) = promoted {
                self.activate_promoted(promoted)?;
            }
            self.bindings.remove(&key);
        }

        for (key, (resource, spec)) in bindings {
            if deletion_requested(&resource) {
                if !self.bindings.contains_key(&key) && !active_targets.contains(&spec.target_ref) {
                    self.revoke_unmanaged_binding(&spec, manifest.as_ref())?;
                }
                let promoted = if let Some(record) = self.bindings.get_mut(&key) {
                    if let Some(controller) = record.controller.as_mut() {
                        controller
                            .finalize_shared(record.lease)
                            .map_err(AudioResourceRuntimeError::Controller)?
                    } else {
                        None
                    }
                } else {
                    None
                };
                if let Some(promoted) = promoted {
                    self.activate_promoted(promoted)?;
                }
                self.bindings.remove(&key);
                continue;
            }
            let service = services
                .get(&spec.service_ref.to_canonical_string())
                .ok_or(AudioResourceRuntimeError::InvalidRelationship)?;
            if let Some(record) = self.bindings.get_mut(&key)
                && record.spec == spec
                && let Some(controller) = record.controller.as_mut()
            {
                let children = AudioBindingController::<DaemonAudioMediator>::child_resources(
                    &resource.resource_ref,
                    &spec,
                )
                .map_err(|_| AudioResourceRuntimeError::InvalidRelationship)?;
                match controller.reconcile(&spec, self.zone.as_str(), record.lease) {
                    Ok(result) => {
                        record.status = result.status;
                    }
                    Err(AudioControllerError::Admission) => {
                        return Err(AudioResourceRuntimeError::InvalidRelationship);
                    }
                    Err(AudioControllerError::Mediator(_)) => {
                        record.status = unavailable_status(
                            AudioBindingPhase::Degraded,
                            controller.mediator().host_readiness(),
                            controller.mediator().guest_readiness(),
                        );
                    }
                }
                record.children = Some(children);
                continue;
            }
            let promoted = if let Some(old) = self.bindings.get_mut(&key) {
                if let Some(controller) = old.controller.as_mut() {
                    controller
                        .finalize_shared(old.lease)
                        .map_err(AudioResourceRuntimeError::Controller)?
                } else {
                    None
                }
            } else {
                None
            };
            if let Some(promoted) = promoted {
                self.activate_promoted(promoted)?;
            }
            self.bindings.remove(&key);

            let lease = lease_for(&resource.resource_ref);
            let children = AudioBindingController::<DaemonAudioMediator>::child_resources(
                &resource.resource_ref,
                &spec,
            )
            .map_err(|_| AudioResourceRuntimeError::InvalidRelationship)?;
            let (controller, status) = {
                let capability = manifest
                    .as_ref()
                    .and_then(|manifest| manifest.vms.get(spec.target_ref.name().as_str()))
                    .and_then(audio_capability_for_vm);
                match capability {
                    None => (
                        None,
                        unavailable_status(
                            AudioBindingPhase::Degraded,
                            HostAudioReadiness::Unavailable,
                            GuestAudioReadiness::Unavailable,
                        ),
                    ),
                    Some(capability) => {
                        let capability = if service.service_role == AudioServiceRole::Projection {
                            d2b_core::provider_capabilities::AudioProviderCapability {
                                host_enforcement:
                                    d2b_core::provider_capabilities::AudioHostEnforcementKind::None,
                                ..capability
                            }
                        } else {
                            capability
                        };
                        let mediator = DaemonAudioMediator::new(
                            self.state.as_ref(),
                            spec.target_ref.name().as_str(),
                            capability,
                            d2b_contracts_broker::broker_wire::BrokerCallerRole::AdminUid {
                                uid: self.state.daemon_uid,
                            },
                        );
                        let microphone = self
                            .service_microphones
                            .entry(spec.service_ref.to_canonical_string())
                            .or_insert_with(|| shared_microphone_arbiter(64))
                            .clone();
                        let mut controller =
                            AudioBindingController::with_shared_microphone(mediator, microphone);
                        let result = controller.reconcile(&spec, self.zone.as_str(), lease);
                        match result {
                            Ok(result) => (Some(controller), result.status),
                            Err(AudioControllerError::Admission) => {
                                return Err(AudioResourceRuntimeError::InvalidRelationship);
                            }
                            Err(AudioControllerError::Mediator(_)) => {
                                let mediator = controller.mediator();
                                let host_readiness = mediator.host_readiness();
                                let guest_readiness = mediator.guest_readiness();
                                (
                                    Some(controller),
                                    unavailable_status(
                                        AudioBindingPhase::Degraded,
                                        host_readiness,
                                        guest_readiness,
                                    ),
                                )
                            }
                        }
                    }
                }
            };
            self.bindings.insert(
                key,
                AudioBindingRecord {
                    spec,
                    lease,
                    controller,
                    status,
                    children: Some(children),
                },
            );
        }
        self.services = services;
        Ok(())
    }

    fn revoke_unmanaged_binding(
        &self,
        spec: &AudioBindingSpec,
        manifest: Option<&d2b_core::manifest_v04::ManifestV04>,
    ) -> Result<(), AudioResourceRuntimeError> {
        let capability = manifest
            .and_then(|manifest| manifest.vms.get(spec.target_ref.name().as_str()))
            .and_then(audio_capability_for_vm)
            .ok_or(AudioResourceRuntimeError::Controller(
                AudioControllerError::Mediator(
                    d2b_provider_audio_pipewire::AudioMediatorError::ProviderSessionUnavailable,
                ),
            ))?;
        let mediator = DaemonAudioMediator::new(
            self.state.as_ref(),
            spec.target_ref.name().as_str(),
            capability,
            d2b_contracts_broker::broker_wire::BrokerCallerRole::AdminUid {
                uid: self.state.daemon_uid,
            },
        );
        AudioBindingController::new(mediator)
            .revoke_unmanaged()
            .map_err(AudioResourceRuntimeError::Controller)
    }

    fn activate_promoted(
        &mut self,
        lease: d2b_provider_audio_pipewire::AudioLeaseId,
    ) -> Result<(), AudioResourceRuntimeError> {
        let Some(record) = self
            .bindings
            .values_mut()
            .find(|record| record.lease == lease)
        else {
            return Ok(());
        };
        let Some(controller) = record.controller.as_mut() else {
            return Ok(());
        };
        controller
            .activate_promoted_microphone(lease)
            .map_err(AudioResourceRuntimeError::Controller)
    }

    pub(crate) fn statuses(&self) -> Vec<AudioBindingRuntimeStatus> {
        self.bindings
            .iter()
            .filter_map(|(key, record)| {
                ResourceRef::parse(key)
                    .ok()
                    .map(|resource| AudioBindingRuntimeStatus {
                        resource,
                        status: record.status,
                    })
            })
            .collect()
    }

    /// Return whether one authored AudioService is currently admitted.
    pub(crate) fn service_is_ready(&self, service_ref: &ResourceRef) -> bool {
        self.services
            .contains_key(&service_ref.to_canonical_string())
    }

    /// Return the latest in-memory phase for one authored AudioBinding.
    pub(crate) fn binding_phase(
        &self,
        binding_ref: &ResourceRef,
    ) -> Option<AudioBindingPhase> {
        self.bindings
            .get(&binding_ref.to_canonical_string())
            .map(|record| record.status.phase)
    }

    /// Return the currently declared children for one authored Binding.
    pub(crate) fn children_for(&self, binding_ref: &ResourceRef) -> Option<&BindingChildSet> {
        self.bindings
            .get(&binding_ref.to_canonical_string())
            .and_then(|record| record.children.as_ref())
    }

    /// Build Core-owned child reconciliation owners from the complete
    /// authoritative Binding relist.
    pub(crate) fn child_owners(
        &self,
        bindings: &[StoredResource],
    ) -> Result<Vec<BindingChildOwner>, AudioResourceRuntimeError> {
        bindings
            .iter()
            .map(|resource| {
                let desired = if deletion_requested(resource) {
                    None
                } else {
                    Some(
                        self.children_for(&resource.resource_ref)
                            .cloned()
                            .ok_or(AudioResourceRuntimeError::InvalidRelationship)?,
                    )
                };
                Ok(BindingChildOwner {
                    resource: resource.clone(),
                    desired,
                    fenced: false,
                })
            })
            .collect()
    }
}

fn unavailable_status(
    phase: AudioBindingPhase,
    host_readiness: HostAudioReadiness,
    guest_readiness: GuestAudioReadiness,
) -> AudioBindingStatus {
    AudioBindingStatus {
        phase,
        host_readiness,
        guest_readiness,
        microphone: None::<MicDecision>,
        channels: d2b_provider_audio_pipewire::AudioBindingChannels {
            speaker: d2b_provider_audio_pipewire::AudioSpeakerStatus {
                grant: d2b_provider_audio_pipewire::AudioGrant::Off,
                level: None,
                live_enforced: false,
            },
            mic: d2b_provider_audio_pipewire::AudioMicrophoneStatus {
                grant: d2b_provider_audio_pipewire::AudioGrant::Off,
                gain: None,
                live_enforced: false,
                arbitration_state: AudioArbitrationState::Inactive,
            },
        },
        enforcement_posture: AudioEnforcementPosture::None,
        last_set_applied: AudioLastSetApplied::OfflineOnly,
    }
}

fn lease_for(resource: &ResourceRef) -> d2b_provider_audio_pipewire::AudioLeaseId {
    let digest = Sha256::digest(resource.to_canonical_string().as_bytes());
    let value = u64::from_be_bytes(digest[..8].try_into().expect("fixed digest width"));
    d2b_provider_audio_pipewire::AudioLeaseId::new(value.max(1))
}

fn deletion_requested(resource: &StoredResource) -> bool {
    serde_json::from_slice::<serde_json::Value>(&resource.canonical_json)
        .ok()
        .and_then(|value| value.get("metadata").cloned())
        .and_then(|metadata| metadata.get("deletionRequestedAt").cloned())
        .is_some_and(|value| !value.is_null())
}

fn decode_services(
    zone: &ZoneId,
    resources: &[StoredResource],
) -> Result<BTreeMap<String, AudioServiceSpec>, AudioResourceRuntimeError> {
    let mut services = BTreeMap::new();
    for resource in resources {
        if !is_audio_resource(resource, zone)? {
            continue;
        }
        let spec: AudioServiceSpec = decode_spec(resource)?;
        if validate_audio_service(&spec).is_err() {
            return Err(AudioResourceRuntimeError::InvalidResource);
        }
        let key = resource.resource_ref.to_canonical_string();
        if services.insert(key, spec).is_some() {
            return Err(AudioResourceRuntimeError::InvalidResource);
        }
    }
    Ok(services)
}

fn decode_bindings(
    zone: &ZoneId,
    resources: &[StoredResource],
) -> Result<Vec<DecodedAudioBinding>, AudioResourceRuntimeError> {
    let mut bindings = Vec::new();
    for resource in resources {
        if !is_audio_resource(resource, zone)? {
            continue;
        }
        let mut spec: AudioBindingSpec = decode_spec(resource)?;
        spec.zone = zone.as_str().to_owned();
        validate_audio_binding_in_zone(&spec, zone.as_str())
            .map_err(|_| AudioResourceRuntimeError::InvalidResource)?;
        let key = resource.resource_ref.to_canonical_string();
        bindings.push((key, (resource.clone(), spec)));
    }
    Ok(bindings)
}

fn is_audio_resource(
    resource: &StoredResource,
    zone: &ZoneId,
) -> Result<bool, AudioResourceRuntimeError> {
    if resource.resource_ref.resource_type().as_str() != AUDIO_SERVICE_TYPE
        && resource.resource_ref.resource_type().as_str() != AUDIO_BINDING_TYPE
    {
        return Err(AudioResourceRuntimeError::InvalidResource);
    }
    if resource.zone != *zone {
        return Err(AudioResourceRuntimeError::InvalidResource);
    }
    let envelope = ResourceEnvelope::from_json(&resource.canonical_json)
        .map_err(|_| AudioResourceRuntimeError::InvalidResource)?;
    Ok(envelope
        .spec()
        .provider_ref()
        .is_some_and(|provider| provider.to_canonical_string() == PROVIDER_REF))
}

fn decode_guest_names(
    resources: &[StoredResource],
) -> Result<BTreeSet<String>, AudioResourceRuntimeError> {
    resources
        .iter()
        .map(|resource| {
            if resource.resource_ref.resource_type().as_str() != GUEST_TYPE {
                return Err(AudioResourceRuntimeError::InvalidResource);
            }
            Ok(resource.resource_ref.to_canonical_string())
        })
        .collect()
}

fn validate_relationships(
    services: &BTreeMap<String, AudioServiceSpec>,
    bindings: &[(String, (StoredResource, AudioBindingSpec))],
    guests: &BTreeSet<String>,
) -> Result<(), AudioResourceRuntimeError> {
    for (_, (resource, spec)) in bindings {
        if (!deletion_requested(resource)
            && (!services.contains_key(&spec.service_ref.to_canonical_string())
                || !guests.contains(&spec.target_ref.to_canonical_string())))
            || resource.resource_ref.resource_type().as_str() != AUDIO_BINDING_TYPE
        {
            return Err(AudioResourceRuntimeError::InvalidRelationship);
        }
    }
    Ok(())
}

fn decode_spec<T: DeserializeOwned>(
    resource: &StoredResource,
) -> Result<T, AudioResourceRuntimeError> {
    let envelope = ResourceEnvelope::from_json(&resource.canonical_json)
        .map_err(|_| AudioResourceRuntimeError::InvalidResource)?;
    let mut spec = serde_json::to_value(envelope.spec().base())
        .map_err(|_| AudioResourceRuntimeError::InvalidResource)?;
    if let Some(provider_ref) = envelope.spec().provider_ref() {
        let object = spec
            .as_object_mut()
            .ok_or(AudioResourceRuntimeError::InvalidResource)?;
        object.insert(
            "providerRef".to_owned(),
            serde_json::Value::String(provider_ref.to_canonical_string()),
        );
    }
    serde_json::from_value(spec).map_err(|_| AudioResourceRuntimeError::InvalidResource)
}

/// Build a store list request for one audio resource type.
pub(crate) fn audio_list_request(
    zone: &ZoneId,
    resource_type: ResourceTypeName,
    suffix: &'static str,
) -> StoreListRequest {
    StoreListRequest {
        operation: StoreOperationContext {
            operation_id: format!("audio-resource-reconcile:{suffix}"),
            idempotency_key: None,
            correlation_id: format!("audio-resource-reconcile:{suffix}"),
            trace_id: None,
            deadline_ms: 10_000,
        },
        zone: zone.clone(),
        resource_types: vec![resource_type],
        resource_names: Vec::new(),
        filters: Vec::new(),
        page_size: 256,
        cursor: None,
        projection: StoreProjection::Full,
    }
}

/// Relist all pages for one resource type before a controller transition.
pub(crate) async fn list_audio_resources(
    store: &d2b_resource_store_redb::RedbResourceStore,
    zone: &ZoneId,
    resource_type: ResourceTypeName,
    suffix: &'static str,
) -> Result<Vec<StoredResource>, AudioResourceRuntimeError> {
    let mut request = audio_list_request(zone, resource_type, suffix);
    let mut resources = Vec::new();
    loop {
        let result = store
            .list(request.clone())
            .await
            .map_err(|_| AudioResourceRuntimeError::InvalidResource)?;
        resources.extend(result.resources);
        let Some(cursor) = result.next_cursor else {
            break;
        };
        request.cursor = Some(cursor);
    }
    Ok(resources)
}

#[cfg(test)]
pub(crate) fn audio_binding_status_projection(
    resource: &StoredResource,
    children: &[StoredResource],
) -> Result<serde_json::Value, AudioResourceRuntimeError> {
    let spec: AudioBindingSpec = decode_spec(resource)?;
    let status = unavailable_status(
        AudioBindingPhase::Degraded,
        HostAudioReadiness::Unavailable,
        GuestAudioReadiness::Unavailable,
    );
    audio_binding_status_projection_with_status(
        resource,
        children,
        &AudioBindingStatus {
            channels: d2b_provider_audio_pipewire::AudioBindingChannels {
                speaker: d2b_provider_audio_pipewire::AudioSpeakerStatus {
                    grant: spec.grants.speaker,
                    level: spec.grants.speaker_level,
                    live_enforced: false,
                },
                mic: d2b_provider_audio_pipewire::AudioMicrophoneStatus {
                    grant: spec.grants.mic,
                    gain: spec.grants.mic_gain,
                    live_enforced: false,
                    arbitration_state: AudioArbitrationState::Inactive,
                },
            },
            ..status
        },
    )
}

pub(crate) fn audio_binding_status_projection_with_status(
    resource: &StoredResource,
    children: &[StoredResource],
    status: &AudioBindingStatus,
) -> Result<serde_json::Value, AudioResourceRuntimeError> {
    let spec: AudioBindingSpec = decode_spec(resource)?;
    let realization_refs = children
        .iter()
        .filter(|child| {
            matches!(
                child.resource_ref.resource_type().as_str(),
                "Process" | "EphemeralProcess" | "Endpoint"
            ) && !deletion_requested(child)
                && ResourceEnvelope::from_json(&child.canonical_json)
                    .ok()
                    .and_then(|envelope| envelope.metadata().owner_ref().cloned())
                    .is_some_and(|owner| owner == resource.resource_ref)
        })
        .map(|child| child.resource_ref.to_canonical_string())
        .collect::<Vec<_>>();
    let typed_status = audio_binding_status_value(*status);
    Ok(serde_json::json!({
        "channels": typed_status["channels"],
        "enforcementPosture": typed_status["enforcementPosture"],
        "lastSetApplied": typed_status["lastSetApplied"],
        "observedServiceRef": spec.service_ref.to_canonical_string(),
        "realizationRefs": realization_refs
    }))
}

pub(crate) async fn list_audio_snapshot(
    store: &d2b_resource_store_redb::RedbResourceStore,
    zone: &ZoneId,
) -> Result<AudioResourceSnapshot, AudioResourceRuntimeError> {
    let services = list_audio_resources(
        store,
        zone,
        ResourceTypeName::parse(AUDIO_SERVICE_TYPE).expect("static audio service type"),
        "service",
    )
    .await?;
    let bindings = list_audio_resources(
        store,
        zone,
        ResourceTypeName::parse(AUDIO_BINDING_TYPE).expect("static audio binding type"),
        "binding",
    )
    .await?;
    let guests = list_audio_resources(
        store,
        zone,
        ResourceTypeName::parse(GUEST_TYPE).expect("static guest type"),
        "guest",
    )
    .await?;
    Ok(AudioResourceSnapshot {
        services,
        bindings,
        guests,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use d2b_contracts_resource::v3::CanonicalJsonValue;

    fn stored_audio_resource(resource_ref: &str, spec: serde_json::Value) -> StoredResource {
        let resource_ref = ResourceRef::parse(resource_ref).unwrap();
        let zone = ZoneId::parse("dev").unwrap();
        let value = serde_json::json!({
            "apiVersion": "resources.d2bus.org/v3",
            "type": resource_ref.resource_type().as_str(),
            "metadata": {
                "name": resource_ref.name().as_str(),
                "zone": zone.as_str(),
                "ownerRef": null,
                "labels": {},
                "annotations": {},
                "finalizers": [],
                "managedBy": "controller",
                "configurationGeneration": 1,
                "deletionRequestedAt": null,
                "createdAt": "2026-08-19T00:00:00.000Z",
                "updatedAt": "2026-08-19T00:00:00.000Z",
                "generation": 1,
                "revision": 1,
                "uid": "123e4567-e89b-42d3-a456-426614174000"
            },
            "spec": spec,
            "status": {
                "observedGeneration": 0,
                "phase": "Pending",
                "conditions": [],
                "lastReconciledAt": null,
                "startedAt": null,
                "completedAt": null,
                "outcome": null,
                "update": {
                    "dependencies": {"count": 0, "refs": []},
                    "disruption": "None",
                    "lastAssessedAt": null,
                    "observedGeneration": 0,
                    "operationId": null,
                    "owned": {"count": 0, "refs": []},
                    "preserveState": true,
                    "reasons": [],
                    "state": "Unknown",
                    "targetGeneration": 1
                },
                "resource": {}
            }
        });
        let canonical = CanonicalJsonValue::parse(&serde_json::to_vec(&value).unwrap())
            .unwrap()
            .to_canonical_bytes();
        StoredResource {
            resource_ref,
            zone,
            uid: d2b_contracts_resource::v3::ResourceUid::parse(
                "123e4567-e89b-42d3-a456-426614174000",
            )
            .unwrap(),
            generation: d2b_contracts_resource::v3::ResourceGeneration::new(1).unwrap(),
            revision: ZoneRevision::new(1),
            canonical_json: canonical,
            payload_digest: "sha256:test".to_owned(),
        }
    }

    #[test]
    fn audio_lease_identity_is_stable_and_nonzero() {
        let resource = ResourceRef::parse("audio.d2bus.org.AudioBinding/mic").unwrap();
        assert_eq!(lease_for(&resource), lease_for(&resource));
        assert_ne!(
            lease_for(&resource),
            lease_for(&ResourceRef::parse("audio.d2bus.org.AudioBinding/other").unwrap())
        );
    }

    #[test]
    fn projection_status_never_claims_host_readiness() {
        let status = unavailable_status(
            AudioBindingPhase::Degraded,
            HostAudioReadiness::Unavailable,
            GuestAudioReadiness::Unavailable,
        );
        assert_eq!(status.phase, AudioBindingPhase::Degraded);
        assert_eq!(status.host_readiness, HostAudioReadiness::Unavailable);
        assert_eq!(status.guest_readiness, GuestAudioReadiness::Unavailable);
    }

    #[test]
    fn audio_status_projection_is_stable_and_separates_readiness() {
        let status = audio_binding_status_value(unavailable_status(
            AudioBindingPhase::Degraded,
            HostAudioReadiness::Ready,
            GuestAudioReadiness::Unavailable,
        ));
        assert_eq!(status["phase"], "Degraded");
        assert_eq!(status["hostReadiness"], "Ready");
        assert_eq!(status["guestReadiness"], "Unavailable");
        assert!(status["microphone"].is_null());
        assert_eq!(status["channels"]["speaker"]["grant"], "off");
        assert_eq!(status["channels"]["mic"]["grant"], "off");
        assert_eq!(status["channels"]["mic"]["arbitrationState"], "inactive");
        assert_eq!(status["enforcementPosture"], "None");
        assert_eq!(status["lastSetApplied"], "OfflineOnly");
    }

    #[test]
    fn audio_resource_projection_matches_the_frozen_status_schema() {
        let binding = AudioBindingSpec::new(
            ResourceRef::parse("audio.d2bus.org.AudioService/owner").unwrap(),
            ResourceRef::parse("Guest/work").unwrap(),
            "dev",
        )
        .unwrap();
        let resource = stored_audio_resource(
            "audio.d2bus.org.AudioBinding/work",
            serde_json::to_value(binding).unwrap(),
        );
        let projection = audio_binding_status_projection(&resource, &[]).unwrap();
        let names = projection
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        d2b_contracts_provider::v3::semantic_services::SemanticFamily::Audio
            .contract()
            .binding()
            .status()
            .validate_names(names)
            .expect("audio projection matches the frozen status schema");
        assert_eq!(
            projection["observedServiceRef"],
            "audio.d2bus.org.AudioService/owner"
        );
        assert_eq!(projection["realizationRefs"], serde_json::json!([]));
        assert_eq!(projection["channels"]["speaker"]["grant"], "off");
        assert_eq!(projection["channels"]["mic"]["grant"], "off");
        assert_eq!(projection["enforcementPosture"], "None");
        assert_eq!(projection["lastSetApplied"], "OfflineOnly");
    }

    #[test]
    fn relationship_validation_rejects_missing_guest_and_cross_service() {
        let zone = ZoneId::parse("dev").unwrap();
        let service_ref = ResourceRef::parse("audio.d2bus.org.AudioService/owner").unwrap();
        let guest_ref = ResourceRef::parse("Guest/vm").unwrap();
        let binding_ref = ResourceRef::parse("audio.d2bus.org.AudioBinding/mic").unwrap();
        let service =
            AudioServiceSpec::owner(ResourceRef::parse("Endpoint/audio").unwrap(), zone.as_str())
                .unwrap();
        let binding =
            AudioBindingSpec::new(service_ref.clone(), guest_ref.clone(), zone.as_str()).unwrap();
        let resource = StoredResource {
            resource_ref: binding_ref.clone(),
            zone: zone.clone(),
            uid: d2b_contracts_resource::v3::ResourceUid::parse(
                "123e4567-e89b-42d3-a456-426614174000",
            )
            .unwrap(),
            generation: d2b_contracts_resource::v3::ResourceGeneration::new(1).unwrap(),
            revision: ZoneRevision::new(1),
            canonical_json: br#"{"metadata":{}}"#.to_vec(),
            payload_digest: String::new(),
        };
        let bindings = vec![(
            resource.resource_ref.to_canonical_string(),
            (resource, binding),
        )];
        let mut services = BTreeMap::new();
        services.insert(service_ref.to_canonical_string(), service);
        assert_eq!(
            validate_relationships(&services, &bindings, &BTreeSet::new()),
            Err(AudioResourceRuntimeError::InvalidRelationship)
        );
        assert_eq!(
            validate_relationships(
                &services,
                &bindings,
                &BTreeSet::from([guest_ref.to_canonical_string()])
            ),
            Ok(())
        );
        let mut deleting_resource = bindings[0].1.0.clone();
        deleting_resource.canonical_json =
            br#"{"metadata":{"deletionRequestedAt":"2026-08-15T00:00:00Z"}}"#.to_vec();
        let deleting_bindings = vec![(
            binding_ref.to_canonical_string(),
            (deleting_resource, bindings[0].1.1.clone()),
        )];
        assert_eq!(
            validate_relationships(&BTreeMap::new(), &deleting_bindings, &BTreeSet::new()),
            Ok(())
        );
    }

    #[test]
    fn audio_decoder_reads_reserved_provider_ref_from_resource_spec() {
        let zone = ZoneId::parse("dev").unwrap();
        let spec =
            AudioServiceSpec::owner(ResourceRef::parse("Endpoint/audio").unwrap(), zone.as_str())
                .unwrap();
        let resource = stored_audio_resource(
            "audio.d2bus.org.AudioService/owner",
            serde_json::to_value(spec).unwrap(),
        );

        let services = decode_services(&zone, &[resource]).unwrap();
        assert_eq!(
            services
                .get("audio.d2bus.org.AudioService/owner")
                .unwrap()
                .provider_ref,
            PROVIDER_REF
        );
    }

    #[test]
    fn audio_decoder_ignores_a_foreign_provider_resource() {
        let zone = ZoneId::parse("dev").unwrap();
        let resource = stored_audio_resource(
            "audio.d2bus.org.AudioService/foreign",
            serde_json::json!({
                "providerRef": "Provider/other",
                "implementationDetail": true
            }),
        );

        assert!(decode_services(&zone, &[resource]).unwrap().is_empty());
    }
}
