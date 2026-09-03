//! Audio-pipewire Provider contracts and controller-side policy.

#![deny(missing_docs)]

pub mod argv;
#[allow(missing_docs)]
pub mod audio_argv;
mod audio_policy;
pub mod authority;
pub mod controller;
pub mod manifest;
pub mod mediator;
pub mod resource_type;
#[allow(missing_docs)]
pub mod state;
pub mod telemetry;

pub use argv::{AudioComponentTemplate, AudioTemplateError, RenderedAudioTemplate};
pub use audio_policy::{
    AudioGrant, AudioPolicyError, AudioPolicyState, LevelPercent, LevelPercentError,
    parse_audio_state,
};
pub use authority::{
    AudioAuthorityError, AudioLeaseId, MicDecision, MicrophoneArbiter, SharedMicrophoneArbiter,
    SpeakerMixer, shared_microphone_arbiter,
};
pub use controller::{
    AudioArbitrationState, AudioBindingChannels, AudioBindingController, AudioBindingPhase,
    AudioBindingStatus, AudioControllerError, AudioEnforcementPosture, AudioLastSetApplied,
    AudioMicrophoneStatus, AudioReconcileResult, AudioReconcileResultWithChildren,
    AudioRunnerContract, AudioSpeakerStatus, audio_runner_contract, register_service,
};
pub use manifest::AudioManifest;
pub use mediator::{
    AudioChannel, AudioMediator, AudioMediatorError, AudioReadiness, FakeAudioMediator,
    GuestAudioReadiness, HostAudioReadiness,
};
pub use resource_type::{
    AudioAdmissionError, AudioBindingSpec, AudioGrants, AudioServiceRole, AudioServiceSpec,
    ProviderExtension, validate_audio_binding, validate_audio_binding_in_zone,
    validate_audio_service,
};
pub use state::{
    AudioStateIoError, AudioStateLock, acquire_audio_state_lock, audio_lock_path, audio_state_path,
    read_audio_state_locked, read_audio_state_unlocked, write_audio_state_locked,
    write_audio_state_unlocked,
};
