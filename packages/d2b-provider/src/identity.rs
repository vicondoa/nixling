//! Provider identity, family, and capability publication.

use std::collections::BTreeSet;

use d2b_contracts_provider::v3::SpecifiedProviderMethod;
use d2b_contracts_resource::v3::execution_policy::{BoundedToken, PrimitiveSpecError};

use crate::error::RegistryBuildError;

/// The v3 Provider contract schema version.
///
/// The ADR45 registry published schema version 2; the v3 Provider resource
/// model republishes the same registry contract at version 3.
pub const PROVIDER_SCHEMA_VERSION: u32 = 3;

/// The maximum number of Provider instances one registry generation admits.
pub const MAX_PROVIDER_REGISTRY_ENTRIES: usize = 256;

/// The maximum number of methods one Provider descriptor may publish.
pub const MAX_PROVIDER_CAPABILITIES: usize = 64;

/// The `Provider` standard ResourceType name.
pub const PROVIDER_RESOURCE_TYPE: &str = "Provider";

/// The eleven Provider families the registry indexes.
///
/// The set is the one frozen by `ADR-046-zone-routing` for the reused
/// `ProviderInstance` sum type; a twelfth family is a new decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProviderClass {
    /// Runtime execution targets.
    Runtime,
    /// Infrastructure composition.
    Infrastructure,
    /// Transport carriage.
    Transport,
    /// Substrate provisioning.
    Substrate,
    /// Credential custody.
    Credential,
    /// Display surfaces.
    Display,
    /// Network fabric.
    Network,
    /// Storage and volumes.
    Storage,
    /// Devices.
    Device,
    /// Audio.
    Audio,
    /// Observability.
    Observability,
}

impl ProviderClass {
    /// Every Provider family, in a deterministic order.
    pub const ALL: [Self; 11] = [
        Self::Runtime,
        Self::Infrastructure,
        Self::Transport,
        Self::Substrate,
        Self::Credential,
        Self::Display,
        Self::Network,
        Self::Storage,
        Self::Device,
        Self::Audio,
        Self::Observability,
    ];

    /// The stable lowercase family token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Runtime => "runtime",
            Self::Infrastructure => "infrastructure",
            Self::Transport => "transport",
            Self::Substrate => "substrate",
            Self::Credential => "credential",
            Self::Display => "display",
            Self::Network => "network",
            Self::Storage => "storage",
            Self::Device => "device",
            Self::Audio => "audio",
            Self::Observability => "observability",
        }
    }
}

/// The signed-artifact implementation selector inside one Provider family.
///
/// This is a bounded opaque token. It never carries a package path, store
/// path, or executable name.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProviderImplementationId(BoundedToken);

impl ProviderImplementationId {
    /// Parse one bounded implementation token.
    pub fn parse(value: impl Into<String>) -> Result<Self, PrimitiveSpecError> {
        BoundedToken::parse(value).map(Self)
    }

    /// Borrow the canonical token.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl std::fmt::Debug for ProviderImplementationId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProviderImplementationId(<redacted>)")
    }
}

/// One exported method name on a Provider's service.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProviderMethodName(BoundedToken);

impl ProviderMethodName {
    /// Parse one bounded method token.
    pub fn parse(value: impl Into<String>) -> Result<Self, PrimitiveSpecError> {
        BoundedToken::parse(value).map(Self)
    }

    /// Borrow the canonical token.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl std::fmt::Debug for ProviderMethodName {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProviderMethodName(<redacted>)")
    }
}

/// The bounded, deduplicated set of methods one descriptor publishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderCapabilitySet(BTreeSet<ProviderMethodName>);

impl ProviderCapabilitySet {
    /// Build a bounded, non-empty capability set.
    pub fn new(
        methods: impl IntoIterator<Item = ProviderMethodName>,
    ) -> Result<Self, RegistryBuildError> {
        let methods: BTreeSet<_> = methods.into_iter().collect();
        if methods.is_empty() || methods.len() > MAX_PROVIDER_CAPABILITIES {
            return Err(RegistryBuildError::BoundExceeded);
        }
        Ok(Self(methods))
    }

    /// Build the exact capability set for specified Provider methods.
    pub fn from_specified(
        methods: impl IntoIterator<Item = SpecifiedProviderMethod>,
    ) -> Result<Self, RegistryBuildError> {
        Self::new(
            methods
                .into_iter()
                .map(specified_method_name)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| RegistryBuildError::InvalidDescriptor)?,
        )
    }

    /// Whether the set contains the exact specified Provider method.
    pub fn contains_specified_method(&self, method: SpecifiedProviderMethod) -> bool {
        specified_method_name(method).is_ok_and(|method| self.contains_method(&method))
    }

    /// Whether this Provider publishes the exact method.
    pub fn contains_method(&self, method: &ProviderMethodName) -> bool {
        self.0.contains(method)
    }

    /// The published methods in canonical order.
    pub fn methods(&self) -> impl Iterator<Item = &ProviderMethodName> {
        self.0.iter()
    }

    /// The number of published methods.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the set is empty. A constructed set never is.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

fn specified_method_name(
    method: SpecifiedProviderMethod,
) -> Result<ProviderMethodName, RegistryBuildError> {
    ProviderMethodName::parse(match method {
        SpecifiedProviderMethod::AssessUpdate => "assess-update",
        SpecifiedProviderMethod::PlanUpgrade => "plan-upgrade",
        SpecifiedProviderMethod::ExecuteUpgrade => "execute-upgrade",
        SpecifiedProviderMethod::OpenTransport => "open-transport",
        SpecifiedProviderMethod::CloseTransport => "close-transport",
        SpecifiedProviderMethod::ObserveTransport => "observe-transport",
        _ => return Err(RegistryBuildError::InvalidDescriptor),
    })
    .map_err(|_| RegistryBuildError::InvalidDescriptor)
}
