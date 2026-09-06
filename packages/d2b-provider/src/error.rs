//! Typed registry build and runtime errors.

use std::{error::Error, fmt};

/// Why a registry generation could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryBuildError {
    /// A descriptor failed its own contract validation.
    InvalidDescriptor,
    /// The descriptor does not name the `Provider` ResourceType.
    NotAProviderRef,
    /// The descriptor publishes an unsupported schema version.
    UnsupportedSchemaVersion,
    /// Two instances claim the same `Provider/<name>` reference.
    DuplicateProvider,
    /// The instance does not match the descriptor it registered under.
    DescriptorMismatch,
    /// The descriptor's registry generation is not this generation.
    GenerationMismatch,
    /// The descriptor's Zone is not this registry's Zone.
    ZoneMismatch,
    /// A declared bound was exceeded.
    BoundExceeded,
    /// The registry generation configured no instance.
    EmptyRegistry,
    /// A previous step failed, so the whole build is abandoned.
    TransactionAborted,
    /// The Provider resource row selects a different artifact than the
    /// manifest supplied with it.
    ArtifactSelectionMismatch,
    /// The artifact failed production trust admission or the exact Provider
    /// API compatibility check.
    ArtifactNotAdmissible,
    /// The registry descriptor publishes a method the signed component
    /// graph does not export.
    UnsignedPublishedMethod,
    /// The Provider resource row has not reached Ready, so no `providerRef`
    /// resolves to it.
    ProviderNotReady,
}

impl fmt::Display for RegistryBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidDescriptor => "provider descriptor failed contract validation",
            Self::NotAProviderRef => "provider descriptor does not reference a Provider resource",
            Self::UnsupportedSchemaVersion => "provider descriptor schema version is unsupported",
            Self::DuplicateProvider => "duplicate provider instance",
            Self::DescriptorMismatch => "provider instance does not match its descriptor",
            Self::GenerationMismatch => "provider generation does not match registry generation",
            Self::ZoneMismatch => "provider descriptor Zone does not match registry Zone",
            Self::BoundExceeded => "provider registry bound exceeded",
            Self::EmptyRegistry => "provider registry has no configured instances",
            Self::TransactionAborted => "provider registry transaction was aborted",
            Self::ArtifactSelectionMismatch => {
                "provider resource selects a different artifact than the manifest"
            }
            Self::ArtifactNotAdmissible => "provider artifact failed trust or compatibility",
            Self::UnsignedPublishedMethod => {
                "provider publishes a method its signed component graph does not export"
            }
            Self::ProviderNotReady => "provider resource is not Ready",
        })
    }
}

impl Error for RegistryBuildError {}

/// Why a runtime admission, forward, or lifecycle transition was refused.
///
/// Every variant is a closed reason. None of them carries a resource name,
/// path, socket, principal, or payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderRuntimeError {
    /// The registry generation is draining or retired.
    NotAccepting,
    /// No instance in this generation matches the request.
    UnknownProvider,
    /// The Provider does not publish the requested method.
    CapabilityDenied,
    /// The global or per-provider in-flight cap is reached.
    InFlightLimit,
    /// The caller or the registry cancelled the operation.
    Cancelled,
    /// The operation deadline is absent, out of range, or already passed.
    DeadlineExpired,
    /// The authenticated session identity does not match the descriptor.
    SessionIdentityMismatch,
    /// The authenticated subject carries no Provider binding.
    MissingProviderBinding,
    /// The requested lifecycle transition is not legal from the current state.
    InvalidLifecycleTransition,
    /// The drain policy is not a valid policy.
    InvalidDrainPolicy,
}

impl fmt::Display for ProviderRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotAccepting => "provider registry is not accepting",
            Self::UnknownProvider => "provider is not registered in this generation",
            Self::CapabilityDenied => "provider does not publish the requested method",
            Self::InFlightLimit => "provider in-flight limit reached",
            Self::Cancelled => "provider operation was cancelled",
            Self::DeadlineExpired => "provider operation deadline expired",
            Self::SessionIdentityMismatch => "session identity does not match the provider",
            Self::MissingProviderBinding => "authenticated subject carries no provider binding",
            Self::InvalidLifecycleTransition => "invalid registry lifecycle transition",
            Self::InvalidDrainPolicy => "invalid registry drain policy",
        })
    }
}

impl Error for ProviderRuntimeError {}
