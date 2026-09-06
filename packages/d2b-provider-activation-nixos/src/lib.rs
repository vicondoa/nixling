//! Activation-NixOS Provider lifecycle and typed effect boundaries.

#![deny(missing_docs)]

pub mod controller;
pub mod diagnostics;
pub mod manifest;
pub mod runner;

pub use controller::{
    ActivationApplicationVerifier, ActivationCaller, ActivationController, ActivationError,
    ActivationTrust, ActivationTrustExpectation, ActivationVerificationError, CallerRole,
    FailClosedActivationVerifier, GenerationObservation, GenerationPhase, RetentionPlan,
    RunnerRequest, RunnerResult, SignedActivationApplicationVerifier, TrustStatus,
    activation_runner_name, activation_runner_ref, activation_runner_spec,
};
pub use manifest::ActivationManifest;
pub use runner::{
    ActivationHelper, ActivationRunner, ActivationRunnerError, ActivationRunnerRequest,
    ActivationRunnerResult, RunnerOutcomeCode,
};
