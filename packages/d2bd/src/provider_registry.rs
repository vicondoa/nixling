//! Production Provider composition for `d2bd`.
//!
//! The runtime registry is [`d2b_provider::ProviderRegistry`].  This module
//! owns only the daemon composition seam: it validates the v3 bundle identity,
//! turns trusted host-catalog rows into descriptor-bound Provider instances,
//! and associates Guest runtime rows with those instances.  It deliberately
//! does not define a second registry or a second session authority.

use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use d2b_contracts_broker::broker_wire::BrokerCallerRole;
use d2b_contracts_provider::v3::{ComponentType, ControllerInstanceScope, ProviderManifest};
use d2b_contracts_resource::v3::identity::ServiceName;
use d2b_contracts_resource::v3::{
    ConfigurationGeneration, ControllerGeneration, ResourceGeneration, ResourceName, ResourceRef,
    SchemaFingerprint, ZoneId, ZoneRevision, identity::ReconnectGeneration,
};
use d2b_contracts_zone_session::v3::zone_routing::{ZoneLabelId, ZonePath};
use d2b_core::host::HostJson;
use d2b_provider::instance::ProviderInstance;
use d2b_provider::{
    ProviderCapabilitySet, ProviderClass, ProviderDescriptor, ProviderImplementationId,
    ProviderMethodName, ProviderRegistry, ProviderRegistryBuilder, ProviderRegistryManager,
    RegistryBuildError,
};
use sha2::{Digest, Sha256};

use crate::process_provider_runtime::{
    ProductionProcessProviders, ProviderAdoption, ProviderLaunch,
};
use crate::provider_effects::{
    EffectDispatch, GuestLifecycleOperation, GuestLifecycleRequest, LifecycleAuthorization,
    ProviderEffectError, ProviderLifecycleDispatch, ProviderLifecycleEffectPort,
};
use d2b_process_conformance::ConfigurationDigest;
use d2bd_runtime::target_runtime::{
    ControllerProcessResource, DaemonMode, DeploymentError, ProviderDeployment,
};

/// Version of the v3 Provider bundle artifact.
pub const PROVIDER_BUNDLE_VERSION: u32 = 3;

/// Schema identity of the v3 Provider bundle artifact.
pub const PROVIDER_BUNDLE_SCHEMA_VERSION: &str = "v3";

/// Registry limits and snapshots are owned by the shared Provider crate.
pub use d2b_provider::{MAX_PROVIDER_REGISTRY_ENTRIES, ProviderRegistrySnapshot};

/// Mint a unique operation identity for one lifecycle attempt. The immutable
/// Guest identity is carried by the sealed authorization lease; the nonce
/// keeps a fresh attempt distinct from a previously consumed broker lease.
pub(crate) fn next_lifecycle_operation_id(
    operation: &str,
    guest: &str,
    request_fingerprint: &str,
) -> String {
    static NEXT_ATTEMPT: AtomicU64 = AtomicU64::new(1);
    let attempt = NEXT_ATTEMPT.fetch_add(1, Ordering::Relaxed);
    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut random = [0_u8; 16];
    let nonce = if getrandom::getrandom(&mut random).is_ok() {
        random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    } else {
        format!("{}:{now_ns}:{attempt}", std::process::id())
    };
    d2b_contracts_resource::v3::canonical_digest(
        "d2bd:provider-lifecycle:v2",
        format!("{operation}:{guest}:{request_fingerprint}:{nonce}").as_bytes(),
    )
}

/// Closed Provider composition failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderCompositionError {
    /// The bundle version is not the v3 version.
    BundleVersionMismatch,
    /// The schema identity is not the v3 identity.
    BundleSchemaMismatch,
    /// A Provider reference was not a Provider resource.
    ProviderRefInvalid,
    /// A Provider reference belongs to another Zone.
    ProviderZoneMismatch,
    /// A Provider name was repeated in one snapshot.
    DuplicateProvider,
    /// The registry bound more than its fixed entry limit.
    RegistryBoundExceeded,
    /// A lifecycle operation was requested for an unregistered Provider.
    ProviderNotRegistered,
    /// A generation was zero.
    GenerationInvalid,
    /// A Zone path could not be derived from the daemon's Zone identity.
    ZonePathInvalid,
    /// The host catalog could not be fingerprinted.
    CatalogFingerprintInvalid,
    /// The registry state lock was poisoned.
    StateUnavailable,
    /// A signed controller manifest could not be admitted for deployment.
    ControllerManifestInvalid,
    /// A target-local controller Process could not be created.
    ControllerDeployment(DeploymentError),
    /// The fixed Process adapter or broker rejected a controller effect.
    ControllerEffectRejected,
    /// The Process adapter could not prove an unambiguous controller
    /// identity; reuse is forbidden until repair.
    ControllerEffectAmbiguous,
    /// The shared Provider registry rejected a descriptor or instance.
    RegistryBuild(RegistryBuildError),
}

impl ProviderCompositionError {
    /// Stable identity-free failure code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::BundleVersionMismatch => "provider-bundle-version-mismatch",
            Self::BundleSchemaMismatch => "provider-bundle-schema-mismatch",
            Self::ProviderRefInvalid => "provider-ref-invalid",
            Self::ProviderZoneMismatch => "provider-zone-mismatch",
            Self::DuplicateProvider => "provider-duplicate",
            Self::RegistryBoundExceeded => "provider-registry-bound-exceeded",
            Self::ProviderNotRegistered => "provider-not-registered",
            Self::GenerationInvalid => "provider-generation-invalid",
            Self::ZonePathInvalid => "provider-zone-path-invalid",
            Self::CatalogFingerprintInvalid => "provider-catalog-fingerprint-invalid",
            Self::StateUnavailable => "provider-registry-state-unavailable",
            Self::ControllerManifestInvalid => "provider-controller-manifest-invalid",
            Self::ControllerDeployment(_) => "provider-controller-deployment-rejected",
            Self::ControllerEffectRejected => "provider-controller-effect-rejected",
            Self::ControllerEffectAmbiguous => "provider-controller-effect-ambiguous",
            Self::RegistryBuild(_) => "provider-registry-build-rejected",
        }
    }
}

impl core::fmt::Display for ProviderCompositionError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ProviderCompositionError {}

impl From<RegistryBuildError> for ProviderCompositionError {
    fn from(error: RegistryBuildError) -> Self {
        match error {
            RegistryBuildError::NotAProviderRef => Self::ProviderRefInvalid,
            RegistryBuildError::ZoneMismatch => Self::ProviderZoneMismatch,
            RegistryBuildError::DuplicateProvider => Self::DuplicateProvider,
            RegistryBuildError::BoundExceeded => Self::RegistryBoundExceeded,
            RegistryBuildError::GenerationMismatch => Self::GenerationInvalid,
            other => Self::RegistryBuild(other),
        }
    }
}

/// One Provider binding from the trusted catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderBinding {
    zone: ZoneId,
    resource: ResourceRef,
    artifact_id: ResourceName,
    schema_fingerprint: SchemaFingerprint,
    capability_methods: Option<Vec<String>>,
}

impl ProviderBinding {
    /// Construct and validate a Zone-local Provider binding.
    pub fn new(
        zone: ZoneId,
        resource: ResourceRef,
        artifact_id: ResourceName,
        schema_fingerprint: impl Into<String>,
    ) -> Result<Self, ProviderCompositionError> {
        if resource.resource_type().as_str() != "Provider" {
            return Err(ProviderCompositionError::ProviderRefInvalid);
        }
        let schema_fingerprint = SchemaFingerprint::parse(schema_fingerprint.into())
            .map_err(|_| ProviderCompositionError::BundleSchemaMismatch)?;
        Ok(Self {
            zone,
            resource,
            artifact_id,
            schema_fingerprint,
            capability_methods: None,
        })
    }

    /// Narrow the methods exposed by this trusted Provider descriptor.
    pub fn with_capability_methods(
        mut self,
        methods: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.capability_methods = Some(methods.into_iter().map(Into::into).collect());
        self
    }

    /// Borrow the binding Zone.
    pub const fn zone(&self) -> &ZoneId {
        &self.zone
    }

    /// Borrow the Provider ResourceRef.
    pub const fn resource(&self) -> &ResourceRef {
        &self.resource
    }

    /// Borrow the selected artifact ID.
    pub const fn artifact_id(&self) -> &ResourceName {
        &self.artifact_id
    }

    /// Borrow the signed schema fingerprint.
    pub const fn schema_fingerprint(&self) -> &SchemaFingerprint {
        &self.schema_fingerprint
    }

    fn descriptor(
        &self,
        zone: &ZonePath,
        generation: u64,
    ) -> Result<ProviderDescriptor, ProviderCompositionError> {
        let registry_generation = ConfigurationGeneration::new(generation)
            .map_err(|_| ProviderCompositionError::GenerationInvalid)?;
        let provider_generation = ResourceGeneration::new(generation)
            .map_err(|_| ProviderCompositionError::GenerationInvalid)?;
        let implementation_id = ProviderImplementationId::parse(self.artifact_id.as_str())
            .map_err(|_| ProviderCompositionError::BundleSchemaMismatch)?;
        let service = ServiceName::parse("d2b.provider.v3")
            .map_err(|_| ProviderCompositionError::BundleSchemaMismatch)?;
        let methods = self.capability_methods.clone().unwrap_or_else(|| {
            ["start", "stop", "restart"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        });
        let methods = methods
            .into_iter()
            .map(|method| {
                ProviderMethodName::parse(method)
                    .map_err(|_| ProviderCompositionError::BundleSchemaMismatch)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let capabilities =
            ProviderCapabilitySet::new(methods).map_err(ProviderCompositionError::from)?;
        ProviderDescriptor::new(
            zone.clone(),
            self.resource.clone(),
            ProviderClass::Runtime,
            implementation_id,
            registry_generation,
            provider_generation,
            service,
            capabilities,
        )
        .map_err(ProviderCompositionError::from)
    }
}

/// Convert a Zone resource identity to the shared Provider registry's
/// authenticated routing path.
pub fn zone_path(zone: &ZoneId) -> Result<ZonePath, ProviderCompositionError> {
    let label =
        ZoneLabelId::parse(zone.as_str()).map_err(|_| ProviderCompositionError::ZonePathInvalid)?;
    ZonePath::new(vec![label]).map_err(|_| ProviderCompositionError::ZonePathInvalid)
}

/// Compose one shared Provider registry from exact daemon bindings.
pub fn compose_provider_registry(
    zone: ZoneId,
    generation: u64,
    bindings: impl IntoIterator<Item = ProviderBinding>,
) -> Result<ProviderRegistry<ProviderInstance>, ProviderCompositionError> {
    let zone_path = zone_path(&zone)?;
    let mut builder = ProviderRegistryBuilder::new(
        zone_path.clone(),
        ConfigurationGeneration::new(generation)
            .map_err(|_| ProviderCompositionError::GenerationInvalid)?,
    );
    let mut count = 0usize;
    for binding in bindings {
        if binding.zone() != &zone {
            return Err(ProviderCompositionError::ProviderZoneMismatch);
        }
        count = count.saturating_add(1);
        if count > MAX_PROVIDER_REGISTRY_ENTRIES {
            return Err(ProviderCompositionError::RegistryBoundExceeded);
        }
        let descriptor = binding.descriptor(&zone_path, generation)?;
        let instance = ProviderInstance::new(
            descriptor.provider_ref().clone(),
            descriptor.provider_generation(),
        )
        .map_err(ProviderCompositionError::from)?;
        builder
            .register_instance(descriptor, instance)
            .map_err(ProviderCompositionError::from)?;
    }
    builder.finish().map_err(ProviderCompositionError::from)
}

/// Validate the v3 bundle version and schema before composition.
pub fn validate_provider_bundle_version(
    version: u32,
    schema: &str,
) -> Result<(), ProviderCompositionError> {
    if version != PROVIDER_BUNDLE_VERSION {
        return Err(ProviderCompositionError::BundleVersionMismatch);
    }
    if schema != PROVIDER_BUNDLE_SCHEMA_VERSION {
        return Err(ProviderCompositionError::BundleSchemaMismatch);
    }
    Ok(())
}

/// Create the target-local controller Process resources advertised by one
/// signed Provider manifest.
///
/// This function is deliberately an intent-only step. It never resolves a
/// binary or starts a child. Launches are admitted later through the fixed
/// Process Provider and the mode-bound broker.
#[allow(clippy::too_many_arguments)]
pub fn deploy_target_local_controllers(
    deployment: &ProviderDeployment,
    zone: ZoneId,
    provider_ref: ResourceRef,
    manifest: &ProviderManifest,
    resource_generation: ResourceGeneration,
    provider_generation: ResourceGeneration,
    controller_generation: ControllerGeneration,
    target_session_generation: ReconnectGeneration,
    resource_revision: ZoneRevision,
    target: ResourceRef,
    process_provider_ref: ResourceRef,
    target_ready: bool,
) -> Result<Vec<ControllerProcessResource>, ProviderCompositionError> {
    manifest
        .validate_installation_contract()
        .map_err(|_| ProviderCompositionError::ControllerManifestInvalid)?;
    if provider_ref.resource_type().as_str() != "Provider"
        || provider_ref.name().as_str() != manifest.artifact_id().as_str()
    {
        return Err(ProviderCompositionError::ControllerManifestInvalid);
    }
    let target_kind = match target.resource_type().as_str() {
        "Host" => d2b_contracts_provider::v3::ControllerTargetKind::Host,
        "Guest" => d2b_contracts_provider::v3::ControllerTargetKind::Guest,
        _ => return Err(ProviderCompositionError::ControllerManifestInvalid),
    };
    let expected_kind = match deployment.mode() {
        DaemonMode::Host => d2b_contracts_provider::v3::ControllerTargetKind::Host,
        DaemonMode::Guest => d2b_contracts_provider::v3::ControllerTargetKind::Guest,
    };
    if target_kind != expected_kind {
        return Err(ProviderCompositionError::ControllerManifestInvalid);
    }
    let mut resources = Vec::new();
    for descriptor in manifest.components() {
        if descriptor.component_type() != ComponentType::Controller
            || matches!(
                descriptor.instance_scope(),
                Some(ControllerInstanceScope::ZoneSingleton)
            )
            || !descriptor.supported_target_kinds().contains(&target_kind)
        {
            continue;
        }
        resources.push(
            deployment
                .create_controller_process(
                    zone.clone(),
                    provider_ref.clone(),
                    descriptor,
                    resource_generation,
                    provider_generation,
                    controller_generation,
                    target_session_generation,
                    resource_revision,
                    target.clone(),
                    process_provider_ref.clone(),
                    target_ready,
                )
                .map_err(ProviderCompositionError::ControllerDeployment)?,
        );
    }
    Ok(resources)
}

/// Launch one previously created target-local controller Process through the
/// fixed, mode-bound Process Provider adapter.
pub(crate) async fn launch_target_local_controller(
    providers: &ProductionProcessProviders,
    resource: &ControllerProcessResource,
    target_readiness_digest: ConfigurationDigest,
    timeout: std::time::Duration,
) -> Result<ProviderLaunch, ProviderCompositionError> {
    providers
        .launch_controller(resource, target_readiness_digest, timeout)
        .await
        .map_err(|error| {
            if error.contains("ambiguous")
                || error.contains("identity")
                || error.contains("deadline")
                || error.contains("fate")
            {
                ProviderCompositionError::ControllerEffectAmbiguous
            } else {
                ProviderCompositionError::ControllerEffectRejected
            }
        })
}

/// Adopt one target-local controller Process through the same fixed adapter
/// used for its launch.
pub(crate) async fn adopt_target_local_controller(
    providers: &ProductionProcessProviders,
    resource: &ControllerProcessResource,
    target_readiness_digest: ConfigurationDigest,
) -> Result<ProviderAdoption, ProviderCompositionError> {
    providers
        .adopt_controller(resource, target_readiness_digest)
        .await
        .map_err(|error| {
            if error.contains("ambiguous")
                || error.contains("identity")
                || error.contains("deadline")
                || error.contains("fate")
            {
                ProviderCompositionError::ControllerEffectAmbiguous
            } else {
                ProviderCompositionError::ControllerEffectRejected
            }
        })
}

/// Launch one deployed controller and commit its running identity back to the
/// ProviderDeployment state machine.
pub async fn launch_deployed_controller(
    deployment: &ProviderDeployment,
    providers: &ProductionProcessProviders,
    process_ref: &ResourceRef,
    target_readiness: SchemaFingerprint,
    timeout: std::time::Duration,
) -> Result<ProviderLaunch, ProviderCompositionError> {
    let context = deployment
        .begin_controller_launch(process_ref, target_readiness.clone())
        .map_err(ProviderCompositionError::ControllerDeployment)?;
    let readiness = configuration_digest(&target_readiness);
    let result =
        launch_target_local_controller(providers, context.resource(), readiness, timeout).await;
    match result {
        Ok(launch) => {
            let identity = identity_commitment(launch.identity);
            match deployment.controller_launch_succeeded(process_ref, identity) {
                Ok(()) => Ok(launch),
                Err(error) => {
                    let _ = deployment.controller_launch_failed(process_ref, true);
                    Err(ProviderCompositionError::ControllerDeployment(error))
                }
            }
        }
        Err(error) => {
            let _ = deployment.controller_launch_failed(
                process_ref,
                matches!(error, ProviderCompositionError::ControllerEffectAmbiguous),
            );
            Err(error)
        }
    }
}

/// Adopt one deployed controller after restart, quarantining an ambiguous
/// child rather than handing it to a replacement controller.
pub async fn adopt_deployed_controller(
    deployment: &ProviderDeployment,
    providers: &ProductionProcessProviders,
    process_ref: &ResourceRef,
    target_readiness: SchemaFingerprint,
) -> Result<ProviderAdoption, ProviderCompositionError> {
    let resource = deployment
        .controller_process(process_ref)
        .map_err(ProviderCompositionError::ControllerDeployment)?;
    let adoption = match adopt_target_local_controller(
        providers,
        &resource,
        configuration_digest(&target_readiness),
    )
    .await
    {
        Ok(adoption) => adoption,
        Err(error) => {
            if matches!(error, ProviderCompositionError::ControllerEffectAmbiguous) {
                let _ = deployment.quarantine_controller(process_ref);
            }
            return Err(error);
        }
    };
    match adoption {
        ProviderAdoption::Adopted(report) => {
            match deployment.controller_adopted(process_ref, identity_commitment(report.identity)) {
                Ok(()) => Ok(ProviderAdoption::Adopted(report)),
                Err(error) => {
                    let _ = deployment.quarantine_controller(process_ref);
                    Err(ProviderCompositionError::ControllerDeployment(error))
                }
            }
        }
        ProviderAdoption::Quarantined(report) => {
            deployment
                .quarantine_controller(process_ref)
                .map_err(ProviderCompositionError::ControllerDeployment)?;
            Ok(ProviderAdoption::Quarantined(report))
        }
        ProviderAdoption::ControllerBootstrapMissing => {
            Ok(ProviderAdoption::ControllerBootstrapMissing)
        }
        ProviderAdoption::Stale { candidate } => Ok(ProviderAdoption::Stale { candidate }),
        ProviderAdoption::Absent => Ok(ProviderAdoption::Absent),
    }
}

fn configuration_digest(value: &SchemaFingerprint) -> ConfigurationDigest {
    let mut digest = Sha256::new();
    digest.update(b"d2bd-controller-readiness-v1\0");
    digest.update(value.as_str().as_bytes());
    ConfigurationDigest::from_bytes(digest.finalize().into())
}

fn identity_commitment(identity: d2b_process_conformance::ProcessIdentityDigest) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"d2bd-controller-process-identity-v1\0");
    digest.update(identity.to_hex().as_bytes());
    digest.finalize().into()
}

/// Result of routing a lifecycle request through the configured Provider
/// runtime.
#[derive(Debug, PartialEq, Eq)]
pub enum ProviderRuntimeDispatch<T> {
    /// The v3 registry admitted the request and the typed effect ran, or the
    /// exact idempotency key was already accepted.
    Active(EffectDispatch<T>),
}

#[derive(Debug)]
struct ActiveProviderRuntime {
    zone: ZoneId,
    registry: ProviderRegistryManager<ProviderInstance>,
    routes: BTreeMap<String, ResourceRef>,
    lifecycle: ProviderLifecycleDispatch,
}

#[derive(Debug)]
enum ProviderRuntimeState {
    /// A validated v3 Provider registry and Guest route index.
    Active(ActiveProviderRuntime),
    /// The catalog is absent or failed validation; all lifecycle effects
    /// refuse until the daemon is rebuilt with a valid catalog.
    Refused(ProviderCompositionError),
}

/// Daemon-owned Provider composition and lifecycle routing state.
#[derive(Debug)]
pub struct ProviderRuntime {
    state: RwLock<ProviderRuntimeState>,
    lifecycle_state_path: Option<PathBuf>,
    process_providers: RwLock<Option<Arc<ProductionProcessProviders>>>,
}

impl ProviderRuntime {
    /// Start unavailable until a trusted Provider catalog is supplied.
    pub fn new() -> Self {
        Self {
            state: RwLock::new(ProviderRuntimeState::Refused(
                ProviderCompositionError::ProviderNotRegistered,
            )),
            lifecycle_state_path: None,
            process_providers: RwLock::new(None),
        }
    }

    /// Construct a Provider runtime whose lifecycle admission boundary is
    /// persisted under the daemon-owned state directory.
    pub fn new_persistent(
        state_path: impl Into<PathBuf>,
    ) -> Result<Self, ProviderCompositionError> {
        let state_path = state_path.into();
        if !state_path.is_absolute() {
            return Err(ProviderCompositionError::StateUnavailable);
        }
        if let Some(parent) = state_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|_| ProviderCompositionError::StateUnavailable)?;
        }
        Ok(Self {
            state: RwLock::new(ProviderRuntimeState::Refused(
                ProviderCompositionError::ProviderNotRegistered,
            )),
            lifecycle_state_path: Some(state_path),
            process_providers: RwLock::new(None),
        })
    }

    /// Compose the v3 catalog from the trusted host artifact.
    ///
    /// An absent or malformed catalog is stored as refused; lifecycle
    /// dispatch remains unavailable until a valid catalog is installed. The
    /// Zone identity is supplied by the committed topology rather than a
    /// built-in root name.
    pub fn configure_from_host(
        &self,
        host: &HostJson,
        zone: &ZoneId,
    ) -> Result<(), ProviderCompositionError> {
        if host.runtime_providers.is_empty() {
            let error = ProviderCompositionError::ProviderNotRegistered;
            let mut state = self
                .state
                .write()
                .map_err(|_| ProviderCompositionError::StateUnavailable)?;
            *state = ProviderRuntimeState::Refused(error);
            return Err(error);
        }
        let next = match self.compose_host_runtime(host, zone) {
            Ok(active) => ProviderRuntimeState::Active(active),
            Err(error) => {
                let mut state = self
                    .state
                    .write()
                    .map_err(|_| ProviderCompositionError::StateUnavailable)?;
                *state = ProviderRuntimeState::Refused(error);
                return Err(error);
            }
        };
        let mut state = self
            .state
            .write()
            .map_err(|_| ProviderCompositionError::StateUnavailable)?;
        *state = next;
        Ok(())
    }

    /// Construct an active runtime from exact bindings and Guest routes.
    ///
    /// This is also the narrow seam used by the daemon's registration tests;
    /// every production catalog goes through the same shared
    /// `d2b_provider::ProviderRegistry` builder.
    pub fn from_bindings(
        zone: ZoneId,
        generation: u64,
        bindings: impl IntoIterator<Item = ProviderBinding>,
        routes: impl IntoIterator<Item = (String, ResourceRef)>,
    ) -> Result<Self, ProviderCompositionError> {
        let registry = compose_provider_registry(zone.clone(), generation, bindings)?;
        let mut route_index = BTreeMap::new();
        for (guest, provider_ref) in routes {
            if provider_ref.resource_type().as_str() != "Provider" {
                return Err(ProviderCompositionError::ProviderRefInvalid);
            }
            if registry.descriptor(&provider_ref).is_none() {
                return Err(ProviderCompositionError::ProviderNotRegistered);
            }
            if route_index.insert(guest, provider_ref).is_some() {
                return Err(ProviderCompositionError::DuplicateProvider);
            }
        }
        Ok(Self {
            state: RwLock::new(ProviderRuntimeState::Active(ActiveProviderRuntime {
                zone: zone.clone(),
                registry: ProviderRegistryManager::new(registry),
                routes: route_index,
                lifecycle: ProviderLifecycleDispatch::new(zone),
            })),
            lifecycle_state_path: None,
            process_providers: RwLock::new(None),
        })
    }

    /// Attach the daemon-owned concrete process Provider supervisors.
    pub fn attach_process_providers(
        &self,
        providers: Arc<ProductionProcessProviders>,
    ) -> Result<(), ProviderCompositionError> {
        self.process_providers
            .write()
            .map_err(|_| ProviderCompositionError::StateUnavailable)
            .map(|mut current| {
                *current = Some(providers);
            })
    }

    /// Whether the fixed process Provider path is composed and available.
    pub fn process_providers_ready(&self) -> bool {
        self.process_providers
            .read()
            .map(|providers| providers.is_some())
            .unwrap_or(false)
    }

    /// Borrow the daemon-owned process Provider composition.
    pub fn process_providers(&self) -> Option<Arc<ProductionProcessProviders>> {
        self.process_providers
            .read()
            .ok()
            .and_then(|providers| providers.clone())
    }

    /// Number of Provider descriptors in the active registry.
    pub fn registered_provider_count(&self) -> usize {
        self.state
            .read()
            .ok()
            .and_then(|state| match &*state {
                ProviderRuntimeState::Active(active) => {
                    Some(active.registry.current().snapshot().descriptors().len())
                }
                ProviderRuntimeState::Refused(_) => None,
            })
            .unwrap_or(0)
    }

    /// Route one Guest lifecycle request through registry admission and a
    /// descriptor-bound typed effect port.
    pub fn dispatch_lifecycle<P: ProviderLifecycleEffectPort>(
        &self,
        caller: &BrokerCallerRole,
        guest_name: &str,
        operation: GuestLifecycleOperation,
        idempotency_key: impl Into<String>,
        authorization: LifecycleAuthorization,
        effect: &P,
    ) -> Result<ProviderRuntimeDispatch<P::Output>, ProviderEffectError> {
        let state = self
            .state
            .read()
            .map_err(|_| ProviderEffectError::StateUnavailable)?;
        let ProviderRuntimeState::Active(active) = &*state else {
            return match &*state {
                ProviderRuntimeState::Refused(error) => {
                    let _ = error.code();
                    Err(ProviderEffectError::RegistryUnavailable)
                }
                ProviderRuntimeState::Active(_) => unreachable!("active state matched above"),
            };
        };
        let provider_ref = active
            .routes
            .get(guest_name)
            .ok_or(ProviderEffectError::ProviderNotRegistered)?;
        let registry = active.registry.current();
        let descriptor = registry
            .descriptor(provider_ref)
            .ok_or(ProviderEffectError::ProviderNotRegistered)?;
        let method = ProviderMethodName::parse(operation.as_str())
            .map_err(|_| ProviderEffectError::ProviderCapabilityDenied)?;
        if !descriptor.capabilities().contains_method(&method) {
            return Err(ProviderEffectError::ProviderCapabilityDenied);
        }
        let guest = ResourceRef::parse(&format!("Guest/{guest_name}"))
            .map_err(|_| ProviderEffectError::GuestRefInvalid)?;
        let request = GuestLifecycleRequest::new(
            active.zone.clone(),
            guest,
            operation,
            idempotency_key,
            authorization,
        )?;
        active
            .lifecycle
            .dispatch(caller, &request, effect)
            .map(ProviderRuntimeDispatch::Active)
    }

    /// Route a v3 Guest lifecycle request from its committed ProviderRef.
    ///
    /// Unlike the retained legacy VM route above, this path never consults
    /// the Host manifest's name-only Guest map. The Resource API has already
    /// authenticated the Guest and supplied its exact Provider identity.
    pub fn dispatch_v3_lifecycle<P: ProviderLifecycleEffectPort>(
        &self,
        caller: &BrokerCallerRole,
        provider_ref: &ResourceRef,
        guest_ref: ResourceRef,
        operation: GuestLifecycleOperation,
        idempotency_key: impl Into<String>,
        authorization: LifecycleAuthorization,
        effect: &P,
    ) -> Result<ProviderRuntimeDispatch<P::Output>, ProviderEffectError> {
        let state = self
            .state
            .read()
            .map_err(|_| ProviderEffectError::StateUnavailable)?;
        let ProviderRuntimeState::Active(active) = &*state else {
            return Err(ProviderEffectError::RegistryUnavailable);
        };
        if provider_ref.resource_type().as_str() != "Provider"
            || guest_ref.resource_type().as_str() != "Guest"
            || authorization.guest_ref() != &guest_ref
        {
            return Err(ProviderEffectError::GuestRefInvalid);
        }
        let registry = active.registry.current();
        let descriptor = registry
            .descriptor(provider_ref)
            .ok_or(ProviderEffectError::ProviderNotRegistered)?;
        let method = ProviderMethodName::parse(operation.as_str())
            .map_err(|_| ProviderEffectError::ProviderCapabilityDenied)?;
        if !descriptor.capabilities().contains_method(&method) {
            return Err(ProviderEffectError::ProviderCapabilityDenied);
        }
        let request = GuestLifecycleRequest::new(
            active.zone.clone(),
            guest_ref,
            operation,
            idempotency_key,
            authorization,
        )?;
        active
            .lifecycle
            .dispatch(caller, &request, effect)
            .map(ProviderRuntimeDispatch::Active)
    }

    /// Check the latest v3 lifecycle admission without consulting the
    /// legacy Host manifest route table.
    pub(crate) fn lifecycle_admission_is_latest_v3(
        &self,
        caller: &BrokerCallerRole,
        provider_ref: &ResourceRef,
        operation: GuestLifecycleOperation,
        authorization: &LifecycleAuthorization,
    ) -> Result<bool, ProviderEffectError> {
        let state = self
            .state
            .read()
            .map_err(|_| ProviderEffectError::StateUnavailable)?;
        let ProviderRuntimeState::Active(active) = &*state else {
            return Err(ProviderEffectError::RegistryUnavailable);
        };
        let registry = active.registry.current();
        let descriptor = registry
            .descriptor(provider_ref)
            .ok_or(ProviderEffectError::ProviderNotRegistered)?;
        let method = ProviderMethodName::parse(operation.as_str())
            .map_err(|_| ProviderEffectError::ProviderCapabilityDenied)?;
        if !descriptor.capabilities().contains_method(&method) {
            return Err(ProviderEffectError::ProviderCapabilityDenied);
        }
        let request = GuestLifecycleRequest::new(
            active.zone.clone(),
            authorization.guest_ref().clone(),
            operation,
            authorization.operation_id().to_owned(),
            authorization.clone(),
        )?;
        active.lifecycle.is_latest(caller, &request)
    }

    /// Return the latest durable v3 lifecycle intent for one exact Provider
    /// and Guest authorization identity.
    pub(crate) fn latest_v3_lifecycle_operation(
        &self,
        provider_ref: &ResourceRef,
        zone_uid: &d2b_contracts_resource::v3::ResourceUid,
        guest_ref: &ResourceRef,
        guest_uid: &d2b_contracts_resource::v3::ResourceUid,
        guest_generation: ResourceGeneration,
        provider_assignment_generation: ResourceGeneration,
        policy_revision: u64,
    ) -> Result<Option<GuestLifecycleOperation>, ProviderEffectError> {
        let state = self
            .state
            .read()
            .map_err(|_| ProviderEffectError::StateUnavailable)?;
        let ProviderRuntimeState::Active(active) = &*state else {
            return Err(ProviderEffectError::RegistryUnavailable);
        };
        if provider_ref.resource_type().as_str() != "Provider"
            || guest_ref.resource_type().as_str() != "Guest"
            || active.registry.current().descriptor(provider_ref).is_none()
        {
            return Err(ProviderEffectError::ProviderNotRegistered);
        }
        active.lifecycle.latest_operation_for_identity(
            zone_uid,
            guest_ref,
            guest_uid,
            guest_generation,
            provider_assignment_generation,
            policy_revision,
        )
    }

    fn compose_host_runtime(
        &self,
        host: &HostJson,
        zone: &ZoneId,
    ) -> Result<ActiveProviderRuntime, ProviderCompositionError> {
        let zone = zone.clone();
        let mut bindings = Vec::with_capacity(host.runtime_providers.len());
        let mut provider_refs = BTreeMap::new();
        for metadata in &host.runtime_providers {
            let name = ResourceName::parse(metadata.provider.id.clone())
                .map_err(|_| ProviderCompositionError::ProviderRefInvalid)?;
            let provider_ref = ResourceRef::parse(&format!("Provider/{}", name.as_str()))
                .map_err(|_| ProviderCompositionError::ProviderRefInvalid)?;
            let fingerprint = runtime_catalog_fingerprint(metadata)?;
            bindings.push(ProviderBinding::new(
                zone.clone(),
                provider_ref.clone(),
                name,
                fingerprint,
            )?);
            if provider_refs
                .insert(metadata.provider.id.clone(), provider_ref)
                .is_some()
            {
                return Err(ProviderCompositionError::DuplicateProvider);
            }
        }
        let registry = compose_provider_registry(zone.clone(), 1, bindings)?;
        let mut routes = BTreeMap::new();
        for row in &host.vm_runtimes {
            let provider_ref = provider_refs
                .get(&row.runtime.provider.id)
                .ok_or(ProviderCompositionError::ProviderNotRegistered)?
                .clone();
            if routes.insert(row.vm.clone(), provider_ref).is_some() {
                return Err(ProviderCompositionError::DuplicateProvider);
            }
        }
        Ok(ActiveProviderRuntime {
            zone: zone.clone(),
            registry: ProviderRegistryManager::new(registry),
            routes,
            lifecycle: match &self.lifecycle_state_path {
                Some(path) => ProviderLifecycleDispatch::new_persistent(
                    zone.clone(),
                    path.with_file_name("provider-lifecycle.json"),
                )
                .map_err(|_| ProviderCompositionError::StateUnavailable)?,
                None => ProviderLifecycleDispatch::new(zone.clone()),
            },
        })
    }
}

impl Default for ProviderRuntime {
    fn default() -> Self {
        Self::new()
    }
}

fn runtime_catalog_fingerprint(
    metadata: &d2b_core::runtime::RuntimeMetadata,
) -> Result<String, ProviderCompositionError> {
    let bytes = serde_json::to_vec(metadata)
        .map_err(|_| ProviderCompositionError::CatalogFingerprintInvalid)?;
    let digest = Sha256::digest(bytes);
    Ok(format!("sha256:{digest:x}"))
}

/// Keep the ResourceType identity available to callers without accepting a
/// free-form type alias.
pub fn provider_resource_type() -> d2b_contracts_resource::v3::identity::ResourceTypeName {
    d2b_contracts_resource::v3::identity::ResourceTypeName::parse("Provider")
        .expect("Provider is in the v3 catalog")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider_effects::{EffectDispatch, ProviderLifecycleEffectPort};
    use d2b_contracts_provider::v3::{
        ArtifactDigest, ArtifactDigestSet, BinaryRef, CompatibilityRange, ComponentDescriptor,
        ComponentExecution, ComponentTargetCapability, ComponentType, ControllerInstanceScope,
        ControllerTargetKind, EffectPortClass, PolicyEvaluation, ResourceApiBinding,
        RevocationState, SignatureState, TargetRuntimeArtifacts, TrustEvidence, UpgradeDisposition,
        UpgradePolicy,
    };
    use d2b_contracts_resource::v3::{
        ResourceTypeName, SchemaVersion,
        execution_policy::{BoundedToken, ExecutionDomain},
    };

    const FINGERPRINT: &str =
        "sha256:0000000000000000000000000000000000000000000000000000000000000001";

    fn zone() -> ZoneId {
        ZoneId::parse("work").expect("Zone")
    }

    fn binding(name: &str) -> ProviderBinding {
        ProviderBinding::new(
            zone(),
            ResourceRef::parse(&format!("Provider/{name}")).expect("Provider ref"),
            ResourceName::parse(name).expect("Provider name"),
            FINGERPRINT,
        )
        .expect("binding")
    }

    fn authorization(operation_id: &str) -> LifecycleAuthorization {
        LifecycleAuthorization::for_test(
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
            1,
            1,
            1,
            operation_id,
        )
    }

    fn controller_manifest() -> ProviderManifest {
        let digest = ArtifactDigest::parse(format!("sha256:{}", "a".repeat(64))).unwrap();
        let fingerprint = SchemaFingerprint::parse(format!("sha256:{}", "b".repeat(64))).unwrap();
        let process = ResourceTypeName::parse("Process").unwrap();
        let component = ComponentDescriptor::new(
            BoundedToken::parse("process-controller").unwrap(),
            ComponentType::Controller,
            [process.clone()],
            [BoundedToken::parse("reconcile").unwrap()],
            [ExecutionDomain::System],
            8,
            digest.clone(),
            [],
            false,
        )
        .unwrap()
        .with_execution(ComponentExecution::Launchable {
            binary_ref: BinaryRef::parse("process-controller").unwrap(),
        })
        .with_controller_placement(
            ControllerInstanceScope::PerResourceTarget,
            [ControllerTargetKind::Host, ControllerTargetKind::Guest],
        )
        .unwrap()
        .with_target_capabilities([
            ComponentTargetCapability::new(
                ControllerTargetKind::Host,
                digest.clone(),
                [EffectPortClass::Process],
            )
            .unwrap(),
            ComponentTargetCapability::new(
                ControllerTargetKind::Guest,
                digest.clone(),
                [EffectPortClass::Process],
            )
            .unwrap(),
        ])
        .unwrap();
        let binding = ResourceApiBinding::new_with_placement(
            process,
            SchemaVersion::new(1, 0).unwrap(),
            fingerprint.clone(),
            SchemaVersion::new(1, 0).unwrap(),
            fingerprint.clone(),
            Default::default(),
            None,
            None,
            d2b_contracts_resource::v3::PlacementAnchor::ExecutionRef,
        )
        .unwrap();
        let trust = TrustEvidence {
            publisher: BoundedToken::parse("trusted").unwrap(),
            root_epoch: 1,
            publisher_trusted: true,
            signature: SignatureState::Valid,
            revocation: RevocationState::Clear,
            emergency_deny: false,
            provenance: PolicyEvaluation::Accepted,
            sbom: PolicyEvaluation::Accepted,
            license: PolicyEvaluation::Accepted,
            vulnerability: PolicyEvaluation::Accepted,
            conformance: PolicyEvaluation::Accepted,
            support_channel: BoundedToken::parse("stable").unwrap(),
        };
        ProviderManifest::new(
            d2b_contracts_resource::v3::ArtifactId::parse("provider-runtime").unwrap(),
            ArtifactDigestSet {
                executable: digest.clone(),
                config: digest.clone(),
                schema: digest.clone(),
                service: digest.clone(),
            },
            trust,
            CompatibilityRange {
                api_major: 3,
                api_minor: 0,
                descriptor_fingerprint: fingerprint,
                state_schema_version: SchemaVersion::new(1, 0).unwrap(),
            },
            [component],
            [binding],
            [],
            UpgradePolicy {
                drain_before_upgrade: true,
                max_automatic_disposition: UpgradeDisposition::InPlace,
                preserves_durable_state: true,
            },
        )
        .unwrap()
        .with_target_runtime_artifacts([
            TargetRuntimeArtifacts::new(ControllerTargetKind::Host, digest.clone(), digest.clone())
                .unwrap(),
            TargetRuntimeArtifacts::new(ControllerTargetKind::Guest, digest.clone(), digest)
                .unwrap(),
        ])
        .unwrap()
    }

    struct RecordingEffect;

    impl ProviderLifecycleEffectPort for RecordingEffect {
        type Output = &'static str;

        fn apply(
            &self,
            _request: &GuestLifecycleRequest,
        ) -> Result<Self::Output, ProviderEffectError> {
            Ok("broker-effect-dispatched")
        }
    }

    #[test]
    fn registration_uses_the_shared_registry_and_resolves_exact_provider() {
        validate_provider_bundle_version(3, "v3").expect("v3 gate");
        assert!(validate_provider_bundle_version(2, "v2").is_err());
        let registry = compose_provider_registry(zone(), 1, [binding("system-core")])
            .expect("shared registry composition");
        let snapshot = registry.snapshot();
        assert_eq!(snapshot.generation().get(), 1);
        assert_eq!(snapshot.descriptors().len(), 1);
        assert!(
            registry
                .descriptor(&ResourceRef::parse("Provider/system-core").expect("Provider ref"))
                .is_some()
        );
    }

    #[test]
    fn non_provider_resource_ref_cannot_enter_registry() {
        let error = ProviderBinding::new(
            zone(),
            ResourceRef::parse("Guest/workstation").expect("Guest ref"),
            ResourceName::parse("guest").expect("resource name"),
            FINGERPRINT,
        )
        .expect_err("non-Provider ref must fail");
        assert_eq!(error, ProviderCompositionError::ProviderRefInvalid);
    }

    #[test]
    fn active_registration_reaches_the_typed_effect_and_unknown_routes_refuse() {
        let provider = ResourceRef::parse("Provider/runtime").expect("Provider ref");
        let runtime = ProviderRuntime::from_bindings(
            zone(),
            1,
            [binding("runtime")],
            [("workstation".to_owned(), provider)],
        )
        .expect("runtime composition");
        assert_eq!(runtime.registered_provider_count(), 1);
        let effect = RecordingEffect;
        let caller = BrokerCallerRole::AdminUid { uid: 1000 };
        let result = runtime
            .dispatch_lifecycle(
                &caller,
                "workstation",
                GuestLifecycleOperation::Start,
                "operation-1",
                authorization("operation-1"),
                &effect,
            )
            .expect("lifecycle dispatch");
        assert_eq!(
            result,
            ProviderRuntimeDispatch::Active(EffectDispatch::Dispatched("broker-effect-dispatched"))
        );
        assert_eq!(
            runtime.dispatch_lifecycle(
                &caller,
                "unknown",
                GuestLifecycleOperation::Start,
                "operation-2",
                authorization("operation-2"),
                &effect
            ),
            Err(ProviderEffectError::ProviderNotRegistered)
        );
        assert_eq!(
            runtime.dispatch_lifecycle(
                &BrokerCallerRole::NotAuthorized,
                "workstation",
                GuestLifecycleOperation::Stop,
                "operation-3",
                authorization("operation-3"),
                &effect
            ),
            Err(ProviderEffectError::CallerRoleDenied)
        );
    }

    #[test]
    fn lifecycle_operation_ids_are_unique_per_attempt() {
        let first = next_lifecycle_operation_id("start", "workstation", "same-request");
        let second = next_lifecycle_operation_id("start", "workstation", "same-request");
        assert_ne!(first, second);
        assert!(first.len() <= 128);
        assert!(second.len() <= 128);
    }

    #[test]
    fn unconfigured_runtime_refuses_without_a_legacy_lifecycle_path() {
        let runtime = ProviderRuntime::new();
        let effect = RecordingEffect;
        assert_eq!(
            runtime.dispatch_lifecycle(
                &BrokerCallerRole::AdminUid { uid: 1000 },
                "workstation",
                GuestLifecycleOperation::Start,
                "unconfigured",
                authorization("unconfigured"),
                &effect,
            ),
            Err(ProviderEffectError::RegistryUnavailable)
        );
    }

    #[test]
    fn missing_restart_capability_refuses_before_the_effect_port() {
        let runtime = ProviderRuntime::from_bindings(
            zone(),
            1,
            [binding("runtime").with_capability_methods(["start", "stop"])],
            [(
                "workstation".to_owned(),
                ResourceRef::parse("Provider/runtime").expect("Provider ref"),
            )],
        )
        .expect("runtime composition");
        let effect = RecordingEffect;
        assert_eq!(
            runtime.dispatch_lifecycle(
                &BrokerCallerRole::AdminUid { uid: 1000 },
                "workstation",
                GuestLifecycleOperation::Restart,
                "operation-restart",
                authorization("operation-restart"),
                &effect,
            ),
            Err(ProviderEffectError::ProviderCapabilityDenied)
        );
    }

    #[test]
    fn signed_manifest_deployment_creates_one_target_local_controller_process() {
        let deployment = ProviderDeployment::new(
            DaemonMode::Guest,
            d2bd_runtime::target_runtime::AdmissionLimits::guest_default(),
        )
        .expect("deployment");
        let resources = deploy_target_local_controllers(
            &deployment,
            zone(),
            ResourceRef::parse("Provider/provider-runtime").unwrap(),
            &controller_manifest(),
            ResourceGeneration::new(1).unwrap(),
            ResourceGeneration::new(2).unwrap(),
            ControllerGeneration::new(3).unwrap(),
            ReconnectGeneration::new(4).unwrap(),
            ZoneRevision::new(5),
            ResourceRef::parse("Guest/workload").unwrap(),
            ResourceRef::parse("Provider/system-systemd").unwrap(),
            true,
        )
        .expect("target-local controller deployment");
        assert_eq!(resources.len(), 1);
        assert_eq!(
            resources[0].process_spec().execution().process_class(),
            d2b_contracts_resource::v3::process::ProcessClass::Controller
        );
        assert_eq!(
            deployment.controller_phase(resources[0].process_ref()),
            Some(d2bd_runtime::target_runtime::ControllerProcessPhase::Pending)
        );
    }

    #[test]
    fn v3_lifecycle_does_not_require_the_legacy_guest_route_map() {
        let provider_ref = ResourceRef::parse("Provider/runtime").expect("Provider ref");
        let runtime = ProviderRuntime::from_bindings(zone(), 1, [binding("runtime")], [])
            .expect("runtime composition");
        let effect = RecordingEffect;
        let result = runtime
            .dispatch_v3_lifecycle(
                &BrokerCallerRole::AdminUid { uid: 1000 },
                &provider_ref,
                ResourceRef::parse("Guest/workstation").expect("Guest ref"),
                GuestLifecycleOperation::Start,
                "v3-start",
                authorization("v3-start"),
                &effect,
            )
            .expect("v3 lifecycle dispatch");
        assert_eq!(
            result,
            ProviderRuntimeDispatch::Active(EffectDispatch::Dispatched("broker-effect-dispatched"))
        );
    }
}
