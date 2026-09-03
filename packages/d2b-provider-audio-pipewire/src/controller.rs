//! AudioService and AudioBinding reconciliation through typed ports.

use crate::{
    AudioBindingSpec, AudioChannel, AudioGrant, AudioLeaseId, AudioMediator, AudioMediatorError,
    AudioReadiness, GuestAudioReadiness, HostAudioReadiness, MicDecision, SharedMicrophoneArbiter,
    SpeakerMixer, validate_audio_binding_in_zone, validate_audio_service,
};
use d2b_contracts_provider::v3::semantic_services::{
    SemanticFamily,
    child_resources::{
        BindingChildKind, BindingChildPlacement, BindingChildRequest, BindingChildSet,
        explicit_binding_children,
    },
};
use d2b_contracts_resource::v3::{ExecutionDomain, ResourceRef};

const AUDIO_PROVIDER_REF: &str = "Provider/audio-pipewire";

/// Default shared-Runner repair interval for audio resources.
pub const AUDIO_REPAIR_INTERVAL_SECS: u64 = 300;
/// Exact finalizer for an AudioService authority.
pub const AUDIO_SERVICE_FINALIZER: &str = "audio.d2bus.org/service-finalizer";
/// Exact finalizer for an AudioBinding authority.
pub const AUDIO_BINDING_FINALIZER: &str = "audio.d2bus.org/binding-finalizer";

/// The cutover contract for AudioService and AudioBinding owners.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AudioRunnerContract {
    service_resource_type: &'static str,
    binding_resource_type: &'static str,
    service_finalizer: &'static str,
    binding_finalizer: &'static str,
    repair_interval_secs: u64,
    legacy_scheduler_disabled: bool,
    watched_configuration_is_dependency: bool,
}

impl AudioRunnerContract {
    /// Return the provider-neutral Service ResourceType.
    pub const fn service_resource_type(self) -> &'static str {
        self.service_resource_type
    }

    /// Return the provider-neutral Binding ResourceType.
    pub const fn binding_resource_type(self) -> &'static str {
        self.binding_resource_type
    }

    /// Return the AudioService finalizer.
    pub const fn service_finalizer(self) -> &'static str {
        self.service_finalizer
    }

    /// Return the AudioBinding finalizer.
    pub const fn binding_finalizer(self) -> &'static str {
        self.binding_finalizer
    }

    /// Return the bounded repair interval.
    pub const fn repair_interval_secs(self) -> u64 {
        self.repair_interval_secs
    }

    /// Whether the legacy audio scheduler is disabled.
    pub const fn legacy_scheduler_disabled(self) -> bool {
        self.legacy_scheduler_disabled
    }

    /// Whether watched configuration is dependency-only.
    pub const fn watched_configuration_is_dependency(self) -> bool {
        self.watched_configuration_is_dependency
    }
}

/// Return the shared-Runner contract for audio-pipewire.
pub const fn audio_runner_contract() -> AudioRunnerContract {
    AudioRunnerContract {
        service_resource_type: "audio.d2bus.org.AudioService",
        binding_resource_type: "audio.d2bus.org.AudioBinding",
        service_finalizer: AUDIO_SERVICE_FINALIZER,
        binding_finalizer: AUDIO_BINDING_FINALIZER,
        repair_interval_secs: AUDIO_REPAIR_INTERVAL_SECS,
        legacy_scheduler_disabled: true,
        watched_configuration_is_dependency: true,
    }
}

const AUDIO_BINDING_CHILD_REQUESTS: [BindingChildRequest; 4] = [
    BindingChildRequest::process(
        BindingChildKind::Process,
        BindingChildPlacement::Host,
        "host-effect",
        "Provider/system-minijail",
        "vhost-user-sound-worker",
        ExecutionDomain::System,
        "worker",
    ),
    BindingChildRequest::endpoint(BindingChildPlacement::Host, "host-endpoint", "host-effect"),
    BindingChildRequest::process(
        BindingChildKind::Process,
        BindingChildPlacement::Guest,
        "guest-agent",
        "Provider/system-systemd",
        "guest-audio-agent",
        ExecutionDomain::System,
        "service",
    ),
    BindingChildRequest::endpoint(
        BindingChildPlacement::Guest,
        "guest-endpoint",
        "guest-agent",
    ),
];

/// Closed AudioBinding lifecycle phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioBindingPhase {
    /// Dependencies are still converging.
    Pending,
    /// Both host and guest readiness are established.
    Ready,
    /// A dependency or mediator is temporarily unavailable.
    Degraded,
    /// The binding is being removed.
    Deleted,
}

/// Per-channel observed speaker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AudioSpeakerStatus {
    /// Last desired speaker grant.
    pub grant: AudioGrant,
    /// Last desired speaker level.
    pub level: Option<crate::LevelPercent>,
    /// Whether the speaker state is currently enforced.
    pub live_enforced: bool,
}

/// Per-channel observed microphone state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AudioMicrophoneStatus {
    /// Last desired microphone grant.
    pub grant: AudioGrant,
    /// Last desired microphone gain.
    pub gain: Option<crate::LevelPercent>,
    /// Whether the microphone state is currently enforced.
    pub live_enforced: bool,
    /// Current Service-level arbitration state.
    pub arbitration_state: AudioArbitrationState,
}

/// Closed microphone arbitration state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioArbitrationState {
    /// This Binding does not request microphone capture.
    Inactive,
    /// This Binding is waiting for the Service microphone lease.
    Queued,
    /// This Binding owns the Service microphone lease.
    Active,
    /// The Service could not admit this Binding.
    Blocked,
}

/// The channels projected by an AudioBinding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AudioBindingChannels {
    /// Speaker observation.
    pub speaker: AudioSpeakerStatus,
    /// Microphone observation.
    pub mic: AudioMicrophoneStatus,
}

/// Aggregate host/guest enforcement posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioEnforcementPosture {
    /// Both host and guest enforcement are available.
    HostAndGuest,
    /// Only host enforcement is available.
    HostOnly,
    /// Only guest enforcement is available.
    GuestOnly,
    /// No enforcement is currently available.
    None,
}

/// Where the most recent mutable audio setting was applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioLastSetApplied {
    /// Applied to both host and guest.
    HostAndGuest,
    /// Applied to the host only.
    HostOnly,
    /// Applied to the guest only.
    GuestOnly,
    /// No setting was applied in the current reconcile.
    OfflineOnly,
}

/// Typed AudioBinding status projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AudioBindingStatus {
    /// Provider lifecycle phase.
    pub phase: AudioBindingPhase,
    /// Host readiness remains distinct from guest readiness.
    pub host_readiness: HostAudioReadiness,
    /// Guest readiness remains distinct from host readiness.
    pub guest_readiness: GuestAudioReadiness,
    /// Mic arbitration result.
    pub microphone: Option<MicDecision>,
    /// Last observed channel state.
    pub channels: AudioBindingChannels,
    /// Aggregate host/guest enforcement posture.
    pub enforcement_posture: AudioEnforcementPosture,
    /// Application path for the most recent setting.
    pub last_set_applied: AudioLastSetApplied,
}

/// Typed controller failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioControllerError {
    /// Resource admission failed.
    Admission,
    /// The mediator refused a grant or level.
    Mediator(AudioMediatorError),
}

impl core::fmt::Display for AudioControllerError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Admission => "audio-controller-admission-failed",
            Self::Mediator(error) => error.code(),
        })
    }
}

impl std::error::Error for AudioControllerError {}

/// Controller result including separate readiness observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AudioReconcileResult {
    /// Projected status.
    pub status: AudioBindingStatus,
    /// Whether a host-side effect was attempted.
    pub host_effect_applied: bool,
    /// Whether a guest-side effect was attempted.
    pub guest_effect_applied: bool,
}

/// Reconcile output including the child resources owned by the Binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioReconcileResultWithChildren {
    /// Readiness and effect observations.
    pub result: AudioReconcileResult,
    /// UID-free Process and Endpoint intents.
    pub children: BindingChildSet,
}

/// AudioBinding controller over existing audio policy and mediator ports.
#[derive(Debug)]
pub struct AudioBindingController<M: AudioMediator> {
    mediator: M,
    microphone: SharedMicrophoneArbiter,
    activate_promoted: bool,
    microphone_effect_applied: bool,
    speaker: SpeakerMixer,
}

impl<M: AudioMediator> AudioBindingController<M> {
    /// Construct a controller with bounded arbitration state.
    pub fn new(mediator: M) -> Self {
        Self {
            mediator,
            microphone: crate::shared_microphone_arbiter(64),
            activate_promoted: true,
            microphone_effect_applied: false,
            speaker: SpeakerMixer::new(64),
        }
    }

    /// Construct a controller sharing one AudioService microphone authority.
    pub fn with_shared_microphone(mediator: M, microphone: SharedMicrophoneArbiter) -> Self {
        Self {
            mediator,
            microphone,
            activate_promoted: false,
            microphone_effect_applied: false,
            speaker: SpeakerMixer::new(64),
        }
    }

    /// Borrow the mediator for status or test inspection.
    pub const fn mediator(&self) -> &M {
        &self.mediator
    }

    /// Build the explicit Host and Guest child resources for one Binding.
    ///
    /// The Binding and Service references are required inputs. A Ready
    /// Service cannot produce these children without an authored Binding.
    pub fn child_resources(
        binding_ref: &ResourceRef,
        binding: &AudioBindingSpec,
    ) -> Result<BindingChildSet, AudioControllerError> {
        crate::validate_audio_binding(binding).map_err(|_| AudioControllerError::Admission)?;
        explicit_binding_children(
            SemanticFamily::Audio,
            binding_ref.clone(),
            binding.service_ref.clone(),
            binding.target_ref.clone(),
            ResourceRef::parse(AUDIO_PROVIDER_REF).expect("audio Provider reference is canonical"),
            &AUDIO_BINDING_CHILD_REQUESTS,
        )
        .map_err(|_| AudioControllerError::Admission)
    }

    /// Reconcile a Binding and return the resource-backed child intents.
    pub fn reconcile_with_children(
        &mut self,
        binding_ref: &ResourceRef,
        binding: &AudioBindingSpec,
        service_zone: &str,
        lease: AudioLeaseId,
    ) -> Result<AudioReconcileResultWithChildren, AudioControllerError> {
        validate_audio_binding_in_zone(binding, service_zone)
            .map_err(|_| AudioControllerError::Admission)?;
        let children = Self::child_resources(binding_ref, binding)?;
        let result = self.reconcile(binding, service_zone, lease)?;
        Ok(AudioReconcileResultWithChildren { result, children })
    }

    /// Return the active microphone lease for status and recovery.
    pub fn active_microphone_lease(&self) -> Option<AudioLeaseId> {
        match self.microphone.lock() {
            Ok(arbiter) => arbiter.active(),
            Err(poisoned) => poisoned.into_inner().active(),
        }
    }

    /// Reconcile one binding without opening a host handle itself.
    pub fn reconcile(
        &mut self,
        binding: &AudioBindingSpec,
        service_zone: &str,
        lease: AudioLeaseId,
    ) -> Result<AudioReconcileResult, AudioControllerError> {
        validate_audio_binding_in_zone(binding, service_zone)
            .map_err(|_| AudioControllerError::Admission)?;
        let host_readiness = self.mediator.host_readiness();
        let guest_readiness = self.mediator.guest_readiness();
        let mut microphone = None;
        let mut host_effect_applied = false;
        let mut guest_effect_applied = false;
        let mut speaker_live_enforced = false;
        let mut microphone_live_enforced = false;

        if binding.grants.mic == AudioGrant::On {
            let already_active = self.active_microphone_lease() == Some(lease);
            let decision = match self.microphone.lock() {
                Ok(mut arbiter) => arbiter.request(lease),
                Err(poisoned) => poisoned.into_inner().request(lease),
            };
            microphone = Some(decision);
            let needs_effect = decision == MicDecision::Granted
                && (!already_active || !self.microphone_effect_applied);
            if needs_effect {
                self.mediator
                    .set_channel_grant(AudioChannel::Microphone, AudioGrant::On)
                    .map_err(|error| {
                        if !already_active {
                            match self.microphone.lock() {
                                Ok(mut arbiter) => {
                                    arbiter.release(lease);
                                }
                                Err(poisoned) => {
                                    poisoned.into_inner().release(lease);
                                }
                            }
                        } else {
                            match self.microphone.lock() {
                                Ok(mut arbiter) => arbiter.requeue_active(lease),
                                Err(poisoned) => poisoned.into_inner().requeue_active(lease),
                            }
                        }
                        AudioControllerError::Mediator(error)
                    })?;
                self.microphone_effect_applied = true;
                host_effect_applied = true;
                guest_effect_applied = guest_readiness == GuestAudioReadiness::Ready;
                microphone_live_enforced = true;
            } else {
                microphone_live_enforced = self.microphone_effect_applied;
            }
        } else {
            let was_active = self.active_microphone_lease() == Some(lease);
            self.release_microphone(lease)?;
            if was_active {
                host_effect_applied = true;
                guest_effect_applied = guest_readiness == GuestAudioReadiness::Ready;
                microphone_live_enforced = true;
            }
        }
        if binding.grants.speaker == AudioGrant::On {
            let transition = self
                .speaker
                .set_grant(lease, true)
                .map_err(|_| AudioControllerError::Admission)?;
            if transition {
                if let Err(error) = self
                    .mediator
                    .set_channel_grant(AudioChannel::Speaker, AudioGrant::On)
                {
                    let _ = self.speaker.set_grant(lease, false);
                    return Err(AudioControllerError::Mediator(error));
                }
                host_effect_applied = true;
                guest_effect_applied |= guest_readiness == GuestAudioReadiness::Ready;
                speaker_live_enforced = true;
            } else {
                speaker_live_enforced = true;
            }
        } else if self.speaker.has_grant(lease) {
            let last = self.speaker.is_last_grant(lease);
            if last {
                self.mediator
                    .set_channel_grant(AudioChannel::Speaker, AudioGrant::Off)
                    .map_err(AudioControllerError::Mediator)?;
            }
            self.speaker
                .set_grant(lease, false)
                .map_err(|_| AudioControllerError::Admission)?;
            if last {
                host_effect_applied = true;
                guest_effect_applied |= guest_readiness == GuestAudioReadiness::Ready;
                speaker_live_enforced = true;
            }
        }
        if let Some(level) = binding.grants.speaker_level {
            self.speaker
                .can_set_level(lease, level.get())
                .map_err(|_| AudioControllerError::Admission)?;
            if self.speaker.level(lease) != Some(level.get()) {
                self.mediator
                    .set_channel_level(AudioChannel::Speaker, level)
                    .map_err(AudioControllerError::Mediator)?;
                host_effect_applied = true;
                guest_effect_applied |= guest_readiness == GuestAudioReadiness::Ready;
                speaker_live_enforced = true;
            }
            self.speaker
                .set_level(lease, level.get())
                .map_err(|_| AudioControllerError::Admission)?;
            if self.speaker.level(lease) == Some(level.get()) {
                speaker_live_enforced = speaker_live_enforced || self.speaker.has_grant(lease);
            }
        }
        if let Some(gain) = binding.grants.mic_gain
            && microphone == Some(MicDecision::Granted)
        {
            self.mediator
                .set_channel_level(AudioChannel::Microphone, gain)
                .map_err(AudioControllerError::Mediator)?;
            host_effect_applied = true;
            guest_effect_applied |= guest_readiness == GuestAudioReadiness::Ready;
            microphone_live_enforced = true;
        }

        let phase = match microphone {
            Some(MicDecision::Queued) => AudioBindingPhase::Pending,
            Some(MicDecision::QueueFull) => AudioBindingPhase::Degraded,
            _ if self.mediator.readiness() == AudioReadiness::Ready => AudioBindingPhase::Ready,
            _ => AudioBindingPhase::Degraded,
        };
        let arbitration_state = match microphone {
            Some(MicDecision::Granted) => AudioArbitrationState::Active,
            Some(MicDecision::Queued) => AudioArbitrationState::Queued,
            Some(MicDecision::QueueFull) => AudioArbitrationState::Blocked,
            None => AudioArbitrationState::Inactive,
        };
        let enforcement_posture = match (
            host_effect_applied || speaker_live_enforced || microphone_live_enforced,
            guest_effect_applied,
        ) {
            (true, true) => AudioEnforcementPosture::HostAndGuest,
            (true, false) => AudioEnforcementPosture::HostOnly,
            (false, true) => AudioEnforcementPosture::GuestOnly,
            (false, false) => AudioEnforcementPosture::None,
        };
        let last_set_applied = match (host_effect_applied, guest_effect_applied) {
            (true, true) => AudioLastSetApplied::HostAndGuest,
            (true, false) => AudioLastSetApplied::HostOnly,
            (false, true) => AudioLastSetApplied::GuestOnly,
            (false, false) => AudioLastSetApplied::OfflineOnly,
        };
        Ok(AudioReconcileResult {
            status: AudioBindingStatus {
                phase,
                host_readiness,
                guest_readiness,
                microphone,
                channels: AudioBindingChannels {
                    speaker: AudioSpeakerStatus {
                        grant: binding.grants.speaker,
                        level: binding.grants.speaker_level,
                        live_enforced: speaker_live_enforced,
                    },
                    mic: AudioMicrophoneStatus {
                        grant: binding.grants.mic,
                        gain: binding.grants.mic_gain,
                        live_enforced: microphone_live_enforced,
                        arbitration_state,
                    },
                },
                enforcement_posture,
                last_set_applied,
            },
            host_effect_applied,
            guest_effect_applied,
        })
    }

    /// Finalize one binding with mute-before-release ordering.
    pub fn finalize(
        &mut self,
        lease: AudioLeaseId,
    ) -> Result<Option<AudioLeaseId>, AudioControllerError> {
        self.finalize_inner(lease)
    }

    /// Finalize a binding whose microphone authority is shared with other
    /// controllers.
    ///
    /// The next lease is returned but is not enabled through this binding's
    /// mediator. The daemon reconciles the promoted binding so the effect is
    /// applied to the correct target.
    pub fn finalize_shared(
        &mut self,
        lease: AudioLeaseId,
    ) -> Result<Option<AudioLeaseId>, AudioControllerError> {
        self.finalize_inner(lease)
    }

    /// Revoke effects after restart when no in-memory controller state can be
    /// adopted. The caller must first establish that no surviving Binding
    /// still owns the target's authority.
    pub fn revoke_unmanaged(&mut self) -> Result<(), AudioControllerError> {
        self.mediator
            .set_channel_grant(AudioChannel::Microphone, AudioGrant::Off)
            .map_err(AudioControllerError::Mediator)?;
        self.mediator
            .set_channel_grant(AudioChannel::Speaker, AudioGrant::Off)
            .map_err(AudioControllerError::Mediator)?;
        Ok(())
    }

    /// Apply the microphone effect for a lease promoted by another shared
    /// controller's finalization.
    pub fn activate_promoted_microphone(
        &mut self,
        lease: AudioLeaseId,
    ) -> Result<(), AudioControllerError> {
        if self.active_microphone_lease() != Some(lease) {
            return Ok(());
        }
        if let Err(error) = self
            .mediator
            .set_channel_grant(AudioChannel::Microphone, AudioGrant::On)
        {
            match self.microphone.lock() {
                Ok(mut arbiter) => arbiter.requeue_active(lease),
                Err(poisoned) => poisoned.into_inner().requeue_active(lease),
            }
            return Err(AudioControllerError::Mediator(error));
        }
        self.microphone_effect_applied = true;
        Ok(())
    }

    fn finalize_inner(
        &mut self,
        lease: AudioLeaseId,
    ) -> Result<Option<AudioLeaseId>, AudioControllerError> {
        let promoted = self.release_microphone(lease)?;
        if self.speaker.is_last_grant(lease) {
            self.mediator
                .set_channel_grant(AudioChannel::Speaker, AudioGrant::Off)
                .map_err(AudioControllerError::Mediator)?;
        }
        self.speaker.remove(lease);
        Ok(promoted)
    }

    fn release_microphone(
        &mut self,
        lease: AudioLeaseId,
    ) -> Result<Option<AudioLeaseId>, AudioControllerError> {
        if self.active_microphone_lease() != Some(lease) {
            match self.microphone.lock() {
                Ok(mut arbiter) => {
                    arbiter.release(lease);
                }
                Err(poisoned) => {
                    poisoned.into_inner().release(lease);
                }
            }
            return Ok(None);
        }
        self.mediator
            .set_channel_grant(AudioChannel::Microphone, AudioGrant::Off)
            .map_err(AudioControllerError::Mediator)?;
        self.microphone_effect_applied = false;
        let next = match self.microphone.lock() {
            Ok(mut arbiter) => {
                arbiter.release(lease);
                arbiter.next_lease()
            }
            Err(poisoned) => {
                let mut arbiter = poisoned.into_inner();
                arbiter.release(lease);
                arbiter.next_lease()
            }
        };
        let Some(next) = next else {
            return Ok(None);
        };
        if self.activate_promoted
            && let Err(error) = self
                .mediator
                .set_channel_grant(AudioChannel::Microphone, AudioGrant::On)
        {
            match self.microphone.lock() {
                Ok(mut arbiter) => arbiter.requeue_active(next),
                Err(poisoned) => poisoned.into_inner().requeue_active(next),
            }
            return Err(AudioControllerError::Mediator(error));
        }
        if self.activate_promoted {
            self.microphone_effect_applied = true;
        }
        Ok(Some(next))
    }
}

/// Validate an AudioService before controller registration.
pub fn register_service(service: &crate::AudioServiceSpec) -> Result<(), AudioControllerError> {
    validate_audio_service(service).map_err(|_| AudioControllerError::Admission)
}
