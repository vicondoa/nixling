//! The v3 Provider descriptor.

use d2b_contracts_provider::v3::SpecifiedProviderMethod;
use d2b_contracts_resource::v3::identity::ServiceName;
use d2b_contracts_resource::v3::{
    ConfigurationGeneration, ResourceGeneration, ResourceRef, identity::ReconnectGeneration,
};
use d2b_contracts_zone_session::v3::component_session::{ComponentSessionBoundary, ServicePackage};
use d2b_contracts_zone_session::v3::zone_routing::ZonePath;

use crate::{
    error::RegistryBuildError,
    identity::{
        PROVIDER_RESOURCE_TYPE, PROVIDER_SCHEMA_VERSION, ProviderCapabilitySet, ProviderClass,
        ProviderImplementationId,
    },
};

/// Default retry interval for bounded Provider repair.
pub const DEFAULT_REPAIR_INTERVAL_MS: u32 = 30_000;
/// Maximum repair window for Device and GPU Providers.
pub const MAX_DEVICE_REPAIR_WINDOW_MS: u32 = 60_000;
/// Maximum repair window for audio and notification Providers.
pub const MAX_AUDIO_NOTIFICATION_REPAIR_WINDOW_MS: u32 = 5 * 60 * 1_000;
/// Maximum repair window for any Provider descriptor.
pub const MAX_REPAIR_WINDOW_MS: u32 = MAX_AUDIO_NOTIFICATION_REPAIR_WINDOW_MS;

/// The bounded repair contract attached to one Provider descriptor.
///
/// An opt-out is accepted only when all three alternate convergence paths
/// are durably available: owner wakeups, watch recovery, and restart relist.
/// The toolkit remains neutral and does not implement any of those paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairPolicy {
    /// Retry repair at a bounded interval for a bounded total window.
    Bounded {
        /// Minimum delay between repair attempts.
        retry_after_ms: u32,
        /// Maximum time spent in declared repair.
        max_elapsed_ms: u32,
    },
    /// Explicit evidence that the owner, watch, and restart paths converge.
    OptOut {
        /// The owner wakeup path is durable.
        wakeup_on_change: bool,
        /// Watch recovery is durable.
        watch_recovery: bool,
        /// Restart relist is durable.
        restart_relist: bool,
    },
}

impl RepairPolicy {
    /// Build a bounded repair policy.
    pub const fn bounded(
        retry_after_ms: u32,
        max_elapsed_ms: u32,
    ) -> Result<Self, RegistryBuildError> {
        if retry_after_ms == 0
            || max_elapsed_ms == 0
            || retry_after_ms > max_elapsed_ms
            || max_elapsed_ms > MAX_REPAIR_WINDOW_MS
        {
            return Err(RegistryBuildError::InvalidDescriptor);
        }
        Ok(Self::Bounded {
            retry_after_ms,
            max_elapsed_ms,
        })
    }

    /// Build the fully evidenced repair opt-out.
    pub const fn opt_out() -> Self {
        Self::OptOut {
            wakeup_on_change: true,
            watch_recovery: true,
            restart_relist: true,
        }
    }

    /// Build an intentionally incomplete opt-out for rejection tests.
    pub const fn opt_out_without_restart_relist() -> Self {
        Self::OptOut {
            wakeup_on_change: true,
            watch_recovery: true,
            restart_relist: false,
        }
    }

    /// Select the fixed default for a Provider family.
    pub const fn default_for(class: ProviderClass) -> Self {
        match class {
            ProviderClass::Device => Self::Bounded {
                retry_after_ms: DEFAULT_REPAIR_INTERVAL_MS,
                max_elapsed_ms: MAX_DEVICE_REPAIR_WINDOW_MS,
            },
            ProviderClass::Audio | ProviderClass::Display => Self::Bounded {
                retry_after_ms: MAX_AUDIO_NOTIFICATION_REPAIR_WINDOW_MS,
                max_elapsed_ms: MAX_AUDIO_NOTIFICATION_REPAIR_WINDOW_MS,
            },
            _ => Self::Bounded {
                retry_after_ms: DEFAULT_REPAIR_INTERVAL_MS,
                max_elapsed_ms: MAX_DEVICE_REPAIR_WINDOW_MS,
            },
        }
    }

    /// Validate this policy against the Provider family.
    pub const fn validate(self, class: ProviderClass) -> Result<(), RegistryBuildError> {
        match self {
            Self::Bounded {
                retry_after_ms,
                max_elapsed_ms,
            } => {
                if retry_after_ms == 0
                    || max_elapsed_ms == 0
                    || retry_after_ms > max_elapsed_ms
                    || max_elapsed_ms > MAX_REPAIR_WINDOW_MS
                    || (matches!(class, ProviderClass::Device)
                        && (retry_after_ms > DEFAULT_REPAIR_INTERVAL_MS
                            || max_elapsed_ms > MAX_DEVICE_REPAIR_WINDOW_MS))
                {
                    Err(RegistryBuildError::InvalidDescriptor)
                } else {
                    Ok(())
                }
            }
            Self::OptOut {
                wakeup_on_change,
                watch_recovery,
                restart_relist,
            } if wakeup_on_change && watch_recovery && restart_relist => Ok(()),
            Self::OptOut { .. } => Err(RegistryBuildError::InvalidDescriptor),
        }
    }

    /// Return the bounded retry interval, or zero for an opt-out.
    pub const fn retry_after_ms(self) -> u32 {
        match self {
            Self::Bounded { retry_after_ms, .. } => retry_after_ms,
            Self::OptOut { .. } => 0,
        }
    }

    /// Return the bounded repair window, or zero for an opt-out.
    pub const fn max_elapsed_ms(self) -> u32 {
        match self {
            Self::Bounded { max_elapsed_ms, .. } => max_elapsed_ms,
            Self::OptOut { .. } => 0,
        }
    }

    /// Whether this descriptor has a bounded repair window.
    pub const fn has_bounded_repair(self) -> bool {
        matches!(self, Self::Bounded { .. })
    }

    /// Whether all opt-out convergence evidence is present.
    pub const fn has_opt_out_evidence(self) -> bool {
        matches!(
            self,
            Self::OptOut {
                wakeup_on_change: true,
                watch_recovery: true,
                restart_relist: true
            }
        )
    }
}

/// What one installed Provider publishes to its Zone's registry generation.
///
/// The descriptor is derived from the Provider's signed manifest and catalog
/// entry. It names the Provider only by its Zone path and its
/// `Provider/<name>` reference; it carries no package, executable, path,
/// socket, or credential.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderDescriptor {
    schema_version: u32,
    zone: ZonePath,
    provider_ref: ResourceRef,
    class: ProviderClass,
    implementation_id: ProviderImplementationId,
    registry_generation: ConfigurationGeneration,
    provider_generation: ResourceGeneration,
    service: ServiceName,
    capabilities: ProviderCapabilitySet,
    boundary: ComponentSessionBoundary,
    repair_policy: RepairPolicy,
    session_generation: Option<ReconnectGeneration>,
}

impl ProviderDescriptor {
    /// Build a descriptor at the current Provider schema version.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        zone: ZonePath,
        provider_ref: ResourceRef,
        class: ProviderClass,
        implementation_id: ProviderImplementationId,
        registry_generation: ConfigurationGeneration,
        provider_generation: ResourceGeneration,
        service: ServiceName,
        capabilities: ProviderCapabilitySet,
    ) -> Result<Self, RegistryBuildError> {
        let boundary = if class == ProviderClass::Transport {
            ComponentSessionBoundary::Transport
        } else if service.as_str() == ServicePackage::ResourceV3.as_str() {
            ComponentSessionBoundary::ResourceService
        } else {
            ComponentSessionBoundary::ServiceStream
        };
        let descriptor = Self {
            schema_version: PROVIDER_SCHEMA_VERSION,
            zone,
            provider_ref,
            class,
            implementation_id,
            registry_generation,
            provider_generation,
            service,
            capabilities,
            boundary,
            repair_policy: RepairPolicy::default_for(class),
            session_generation: None,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    /// Re-check every descriptor invariant.
    pub fn validate(&self) -> Result<(), RegistryBuildError> {
        if self.schema_version != PROVIDER_SCHEMA_VERSION {
            return Err(RegistryBuildError::UnsupportedSchemaVersion);
        }
        if self.provider_ref.resource_type().as_str() != PROVIDER_RESOURCE_TYPE {
            return Err(RegistryBuildError::NotAProviderRef);
        }
        if self.capabilities.is_empty() {
            return Err(RegistryBuildError::InvalidDescriptor);
        }
        self.repair_policy.validate(self.class)?;
        let transport_methods_match = self.capabilities
            == ProviderCapabilitySet::from_specified(SpecifiedProviderMethod::TRANSPORT_CARRIAGE)
                .map_err(|_| RegistryBuildError::InvalidDescriptor)?;
        match (self.boundary, self.class) {
            (ComponentSessionBoundary::ResourceService, class)
                if class != ProviderClass::Transport
                    && self.service.as_str() == ServicePackage::ResourceV3.as_str() => {}
            (ComponentSessionBoundary::ServiceStream, class)
                if class != ProviderClass::Transport
                    && self.service.as_str() != ServicePackage::ResourceV3.as_str() => {}
            (ComponentSessionBoundary::Transport, ProviderClass::Transport)
                if self.service.as_str() == ServicePackage::ProviderV3.as_str()
                    && transport_methods_match => {}
            _ => return Err(RegistryBuildError::InvalidDescriptor),
        }
        Ok(())
    }

    /// Set the exact typed ComponentSession boundary.
    pub fn with_boundary(
        mut self,
        boundary: ComponentSessionBoundary,
    ) -> Result<Self, RegistryBuildError> {
        self.boundary = boundary;
        self.validate()?;
        Ok(self)
    }

    /// Set an explicit bounded repair or opt-out policy.
    pub fn with_repair_policy(
        mut self,
        repair_policy: RepairPolicy,
    ) -> Result<Self, RegistryBuildError> {
        repair_policy.validate(self.class)?;
        self.repair_policy = repair_policy;
        Ok(self)
    }

    /// Bind this descriptor to one exact ComponentSession generation.
    pub fn with_session_generation(
        mut self,
        session_generation: ReconnectGeneration,
    ) -> Result<Self, RegistryBuildError> {
        self.session_generation = Some(session_generation);
        self.validate()?;
        Ok(self)
    }

    /// Construct a Provider descriptor for a service-only ComponentSession.
    #[allow(clippy::too_many_arguments)]
    pub fn new_service_session(
        zone: ZonePath,
        provider_ref: ResourceRef,
        class: ProviderClass,
        implementation_id: ProviderImplementationId,
        registry_generation: ConfigurationGeneration,
        provider_generation: ResourceGeneration,
        service: ServiceName,
        capabilities: ProviderCapabilitySet,
    ) -> Result<Self, RegistryBuildError> {
        Self::new(
            zone,
            provider_ref,
            class,
            implementation_id,
            registry_generation,
            provider_generation,
            service,
            capabilities,
        )?
        .with_boundary(ComponentSessionBoundary::ServiceStream)
    }

    /// Construct the exact Transport Provider carriage descriptor.
    pub fn new_transport(
        zone: ZonePath,
        provider_ref: ResourceRef,
        implementation_id: ProviderImplementationId,
        registry_generation: ConfigurationGeneration,
        provider_generation: ResourceGeneration,
        capabilities: ProviderCapabilitySet,
    ) -> Result<Self, RegistryBuildError> {
        let expected =
            ProviderCapabilitySet::from_specified(SpecifiedProviderMethod::TRANSPORT_CARRIAGE)?;
        if capabilities != expected {
            return Err(RegistryBuildError::InvalidDescriptor);
        }
        let descriptor = Self {
            schema_version: PROVIDER_SCHEMA_VERSION,
            zone,
            provider_ref,
            class: ProviderClass::Transport,
            implementation_id,
            registry_generation,
            provider_generation,
            service: ServiceName::parse(ServicePackage::ProviderV3.as_str())
                .map_err(|_| RegistryBuildError::InvalidDescriptor)?,
            capabilities,
            boundary: ComponentSessionBoundary::Transport,
            repair_policy: RepairPolicy::default_for(ProviderClass::Transport),
            session_generation: None,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    /// The published schema version.
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// The Zone this Provider is installed in.
    pub const fn zone(&self) -> &ZonePath {
        &self.zone
    }

    /// The `Provider/<name>` reference.
    pub const fn provider_ref(&self) -> &ResourceRef {
        &self.provider_ref
    }

    /// The Provider family.
    pub const fn class(&self) -> ProviderClass {
        self.class
    }

    /// The signed implementation selector.
    pub const fn implementation_id(&self) -> &ProviderImplementationId {
        &self.implementation_id
    }

    /// The registry generation this descriptor was published into.
    pub const fn registry_generation(&self) -> ConfigurationGeneration {
        self.registry_generation
    }

    /// The Provider resource generation.
    pub const fn provider_generation(&self) -> ResourceGeneration {
        self.provider_generation
    }

    /// The service the published methods belong to.
    pub const fn service(&self) -> &ServiceName {
        &self.service
    }

    /// The published capability set.
    pub const fn capabilities(&self) -> &ProviderCapabilitySet {
        &self.capabilities
    }

    /// Return the exact typed ComponentSession boundary.
    pub const fn boundary(&self) -> ComponentSessionBoundary {
        self.boundary
    }

    /// Return the declared repair policy.
    pub const fn repair_policy(&self) -> RepairPolicy {
        self.repair_policy
    }

    /// Return the optional session generation selected by the owner.
    pub const fn session_generation(&self) -> Option<ReconnectGeneration> {
        self.session_generation
    }
}

impl std::fmt::Debug for ProviderDescriptor {
    /// The Zone path and the exact service are routing detail, so the
    /// descriptor renders only its family, generations, and capability count.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderDescriptor")
            .field("schema_version", &self.schema_version)
            .field("class", &self.class)
            .field("registry_generation", &self.registry_generation)
            .field("provider_generation", &self.provider_generation)
            .field("capability_count", &self.capabilities.len())
            .field("boundary", &self.boundary)
            .field("repair_policy", &self.repair_policy)
            .field("has_session_generation", &self.session_generation.is_some())
            .finish_non_exhaustive()
    }
}
