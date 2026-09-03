//! USB Service firewall and relay lifecycle controller.

use d2b_contracts_provider::v3::semantic_services::child_resources::BindingChildSet;
use d2b_contracts_resource::v3::{ResourceGeneration, ResourceRef, ResourceUid};

use crate::binding_child_resources;
use crate::firewall::{
    FirewallConfirmationKind, FirewallDigest, FirewallGenerationFence, FirewallProjectionAction,
    FirewallProjectionIntent, FirewallToken, RelayAuthorityLease, UsbipEffectError,
    UsbipEffectPort,
};

/// Default descriptor repair interval.
pub const USBIP_REPAIR_INTERVAL_SECS: u64 = 30;
/// Maximum descriptor repair interval.
pub const USBIP_MAX_REPAIR_INTERVAL_SECS: u64 = 60;
/// Service finalizer owned by the USBIP Provider.
pub const USBIP_SERVICE_FINALIZER: &str = "device-usbip.d2bus.org/service-finalizer";
/// Binding finalizer owned by the USBIP Provider.
pub const USBIP_BINDING_FINALIZER: &str = "device-usbip.d2bus.org/binding-finalizer";

/// The cutover contract for the USB Service and Binding owners.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsbipRunnerContract {
    service_resource_type: &'static str,
    binding_resource_type: &'static str,
    repair_interval_secs: u64,
    watched_configuration_is_dependency: bool,
}

impl UsbipRunnerContract {
    /// Return the provider-neutral Service ResourceType.
    pub const fn service_resource_type(self) -> &'static str {
        self.service_resource_type
    }

    /// Return the provider-neutral Binding ResourceType.
    pub const fn binding_resource_type(self) -> &'static str {
        self.binding_resource_type
    }

    /// Return the bounded repair interval.
    pub const fn repair_interval_secs(self) -> u64 {
        self.repair_interval_secs
    }

    /// Whether watched configuration is treated as a dependency.
    pub const fn watched_configuration_is_dependency(self) -> bool {
        self.watched_configuration_is_dependency
    }
}

/// Return the one shared-Runner registration for USBIP.
pub const fn usbip_runner_contract() -> UsbipRunnerContract {
    UsbipRunnerContract {
        service_resource_type: crate::USB_SERVICE_RESOURCE_TYPE,
        binding_resource_type: crate::USB_BINDING_RESOURCE_TYPE,
        repair_interval_secs: USBIP_REPAIR_INTERVAL_SECS,
        watched_configuration_is_dependency: true,
    }
}

/// Closed USB Binding lifecycle phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbipBindingPhase {
    /// Child resources are being admitted.
    Pending,
    /// Child resources are ready for attachment observation.
    Ready,
    /// A child resource or attachment is temporarily unavailable.
    Degraded,
    /// Child resources are draining.
    Deleted,
}

/// Exact Core admission for one USB Binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbipBindingAdmission {
    zone_uid: ResourceUid,
    binding_uid: ResourceUid,
    service_uid: ResourceUid,
    guest_uid: ResourceUid,
    service_generation: ResourceGeneration,
    assignment_epoch: u64,
}

impl UsbipBindingAdmission {
    /// Construct an admission bound to one Zone, Service, Guest, and
    /// assignment generation.
    pub fn new(
        zone_uid: ResourceUid,
        binding_uid: ResourceUid,
        service_uid: ResourceUid,
        guest_uid: ResourceUid,
        service_generation: ResourceGeneration,
        assignment_epoch: u64,
    ) -> Result<Self, UsbipBindingControllerError> {
        if assignment_epoch == 0 {
            return Err(UsbipBindingControllerError::InvalidAdmission);
        }
        Ok(Self {
            zone_uid,
            binding_uid,
            service_uid,
            guest_uid,
            service_generation,
            assignment_epoch,
        })
    }

    /// Borrow the admitted Zone identity.
    pub const fn zone_uid(&self) -> &ResourceUid {
        &self.zone_uid
    }

    /// Borrow the Binding UID.
    pub const fn binding_uid(&self) -> &ResourceUid {
        &self.binding_uid
    }

    /// Borrow the Service UID.
    pub const fn service_uid(&self) -> &ResourceUid {
        &self.service_uid
    }

    /// Borrow the Guest UID.
    pub const fn guest_uid(&self) -> &ResourceUid {
        &self.guest_uid
    }

    /// Return the admitted Service generation.
    pub const fn service_generation(&self) -> ResourceGeneration {
        self.service_generation
    }

    /// Return the exact assignment epoch.
    pub const fn assignment_epoch(&self) -> u64 {
        self.assignment_epoch
    }
}

/// USB Binding reconcile output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbipBindingReconcileResult {
    /// Binding lifecycle phase.
    pub phase: UsbipBindingPhase,
    /// UID-free Process and Endpoint intents.
    pub children: BindingChildSet,
}

/// Controller-level errors for USB Binding child admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbipBindingControllerError {
    /// Binding, Service, target, or Provider references were not admitted.
    Admission,
    /// The Core assignment admission was malformed.
    InvalidAdmission,
    /// A newer assignment must be read before this Binding can continue.
    StaleAssignment,
    /// Reconciliation was requested after finalization.
    Finalized,
}

impl core::fmt::Display for UsbipBindingControllerError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Admission => "usbip-binding-controller-admission-failed",
            Self::InvalidAdmission => "usbip-binding-controller-admission-invalid",
            Self::StaleAssignment => "usbip-binding-controller-assignment-stale",
            Self::Finalized => "usbip-binding-controller-finalized",
        })
    }
}

impl std::error::Error for UsbipBindingControllerError {}

/// Provider-owned USB Binding controller.
///
/// This controller declares and observes child resources. Host bind,
/// attachment launch, adoption, signalling, and reap stay behind the generic
/// resource runtime and the typed lifecycle port.
pub struct UsbipBindingController {
    binding_ref: ResourceRef,
    service_ref: ResourceRef,
    target_ref: ResourceRef,
    children: BindingChildSet,
    phase: UsbipBindingPhase,
    admission: Option<UsbipBindingAdmission>,
}

impl core::fmt::Debug for UsbipBindingController {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("UsbipBindingController")
            .field("phase", &self.phase)
            .field("binding_ref", &self.binding_ref)
            .field("service_ref", &self.service_ref)
            .field("target_ref", &self.target_ref)
            .field("children", &self.children)
            .field("has_admission", &self.admission.is_some())
            .finish()
    }
}

impl UsbipBindingController {
    /// Construct a Binding controller from explicit authored references.
    pub fn new(
        binding_ref: &ResourceRef,
        service_ref: &ResourceRef,
        target_ref: &ResourceRef,
    ) -> Result<Self, UsbipBindingControllerError> {
        if binding_ref.resource_type().as_str() != crate::USB_BINDING_RESOURCE_TYPE
            || service_ref.resource_type().as_str() != crate::USB_SERVICE_RESOURCE_TYPE
            || target_ref.resource_type().as_str() != "Guest"
        {
            return Err(UsbipBindingControllerError::Admission);
        }
        let children = binding_child_resources(binding_ref, service_ref, target_ref)
            .map_err(|_| UsbipBindingControllerError::Admission)?;
        Ok(Self {
            binding_ref: binding_ref.clone(),
            service_ref: service_ref.clone(),
            target_ref: target_ref.clone(),
            children,
            phase: UsbipBindingPhase::Pending,
            admission: None,
        })
    }

    /// Construct a Binding controller from exact Core assignment evidence.
    pub fn new_admitted(
        binding_ref: &ResourceRef,
        service_ref: &ResourceRef,
        target_ref: &ResourceRef,
        admission: UsbipBindingAdmission,
    ) -> Result<Self, UsbipBindingControllerError> {
        let mut controller = Self::new(binding_ref, service_ref, target_ref)?;
        controller.validate_admission(&admission)?;
        controller.admission = Some(admission);
        Ok(controller)
    }

    /// Return the current Binding lifecycle phase.
    pub const fn phase(&self) -> UsbipBindingPhase {
        self.phase
    }

    /// Borrow the current child intents.
    pub const fn children(&self) -> &BindingChildSet {
        &self.children
    }

    /// Borrow the exact Core assignment admission, when one was supplied.
    pub const fn admission(&self) -> Option<&UsbipBindingAdmission> {
        self.admission.as_ref()
    }

    /// Whether a ResourceRef is one of this Binding's Process/Endpoint
    /// children. Volume ownership is never admitted by this controller.
    pub fn owns_child(&self, resource_ref: &ResourceRef) -> bool {
        matches!(
            resource_ref.resource_type().as_str(),
            "Process" | "Endpoint"
        ) && self.children.resource_refs().any(|current| current == resource_ref)
    }

    /// Observe Core-managed child readiness without spawning a feature
    /// process.
    pub fn observe_children(
        &mut self,
        ready: bool,
    ) -> Result<UsbipBindingReconcileResult, UsbipBindingControllerError> {
        if self.phase == UsbipBindingPhase::Deleted {
            return Err(UsbipBindingControllerError::Finalized);
        }
        self.phase = if ready {
            UsbipBindingPhase::Ready
        } else {
            UsbipBindingPhase::Degraded
        };
        Ok(UsbipBindingReconcileResult {
            phase: self.phase,
            children: self.children.clone(),
        })
    }

    /// Observe children after rechecking the exact assignment fence.
    pub fn observe_children_with_admission(
        &mut self,
        admission: UsbipBindingAdmission,
        ready: bool,
    ) -> Result<UsbipBindingReconcileResult, UsbipBindingControllerError> {
        self.validate_admission(&admission)?;
        if self.admission.is_none() {
            self.admission = Some(admission);
        }
        self.observe_children(ready)
    }

    /// Mark the Binding deleted after Endpoint, then Process children drain.
    pub fn finalize(&mut self) {
        self.phase = UsbipBindingPhase::Deleted;
    }

    /// Mark the Binding deleted after validating its current assignment.
    pub fn finalize_with_admission(
        &mut self,
        admission: UsbipBindingAdmission,
    ) -> Result<(), UsbipBindingControllerError> {
        self.validate_admission(&admission)?;
        self.finalize();
        Ok(())
    }

    fn validate_admission(
        &self,
        admission: &UsbipBindingAdmission,
    ) -> Result<(), UsbipBindingControllerError> {
        if admission.assignment_epoch() == 0 {
            return Err(UsbipBindingControllerError::InvalidAdmission);
        }
        if let Some(current) = self.admission.as_ref() {
            if current.zone_uid() != admission.zone_uid()
                || current.binding_uid() != admission.binding_uid()
                || current.service_uid() != admission.service_uid()
                || current.guest_uid() != admission.guest_uid()
                || current.service_generation() != admission.service_generation()
            {
                return Err(UsbipBindingControllerError::Admission);
            }
            if current.assignment_epoch() != admission.assignment_epoch() {
                return Err(UsbipBindingControllerError::StaleAssignment);
            }
        }
        Ok(())
    }
}

/// Zone-scoped opaque resource identity.
#[derive(Clone, PartialEq, Eq)]
pub struct ScopedResourceUid {
    zone_uid: ResourceUid,
    resource_uid: ResourceUid,
}

impl ScopedResourceUid {
    /// Bind an opaque resource identity to its exact Zone.
    pub const fn new(zone_uid: ResourceUid, resource_uid: ResourceUid) -> Self {
        Self {
            zone_uid,
            resource_uid,
        }
    }

    /// Borrow the Zone identity for equality checks only.
    pub const fn zone_uid(&self) -> &ResourceUid {
        &self.zone_uid
    }

    /// Borrow the opaque resource identity for the Core adapter.
    pub const fn resource_uid(&self) -> &ResourceUid {
        &self.resource_uid
    }
}

impl core::fmt::Debug for ScopedResourceUid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ScopedResourceUid(<redacted>)")
    }
}

/// Network dependency surface visible to the Provider.
#[derive(Clone, PartialEq, Eq)]
pub struct NetworkDependency {
    identity: ScopedResourceUid,
    generation: ResourceGeneration,
    ready: bool,
    assignment_epoch: Option<u64>,
}

impl NetworkDependency {
    /// Construct the bounded identity/readiness/generation projection.
    pub const fn new(
        identity: ScopedResourceUid,
        generation: ResourceGeneration,
        ready: bool,
    ) -> Self {
        Self {
            identity,
            generation,
            ready,
            assignment_epoch: None,
        }
    }

    /// Borrow the scoped Network identity.
    pub const fn identity(&self) -> &ScopedResourceUid {
        &self.identity
    }

    /// Return the observed Network generation.
    pub const fn generation(&self) -> ResourceGeneration {
        self.generation
    }

    /// Whether the Network is Ready for the relay dependency.
    pub const fn ready(&self) -> bool {
        self.ready
    }

    /// Bind the dependency to an exact Core assignment epoch.
    pub fn with_assignment_epoch(
        mut self,
        assignment_epoch: u64,
    ) -> Result<Self, UsbipEffectError> {
        if assignment_epoch == 0 {
            return Err(UsbipEffectError::StaleAssignment);
        }
        self.assignment_epoch = Some(assignment_epoch);
        Ok(self)
    }

    /// Return the assignment epoch, when Core supplied one.
    pub const fn assignment_epoch(&self) -> Option<u64> {
        self.assignment_epoch
    }
}

impl core::fmt::Debug for NetworkDependency {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NetworkDependency")
            .field("identity", &self.identity)
            .field("generation", &self.generation)
            .field("ready", &self.ready)
            .finish()
    }
}

/// Closed USB Service firewall lifecycle phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbipServicePhase {
    /// Waiting for a Ready Network dependency.
    WaitingForNetwork,
    /// Acquiring relay authority or applying the projection.
    Applying,
    /// Relay and firewall projection are confirmed Ready.
    Ready,
    /// Observation found ownership-scoped drift.
    Drifted,
    /// Projection removal is in progress while authority stays retained.
    Releasing,
    /// A terminal safe-mutation failure blocked progress.
    Blocked,
}

/// Closed controller operation label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbipOperation {
    /// Acquire or share relay authority.
    AcquireRelay,
    /// Apply one projection.
    ApplyFirewall,
    /// Observe one projection.
    ObserveFirewall,
    /// Remove one projection.
    RemoveFirewall,
    /// Release relay authority.
    ReleaseRelay,
}

impl UsbipOperation {
    const fn label(self) -> &'static str {
        match self {
            Self::AcquireRelay => "acquire-relay",
            Self::ApplyFirewall => "apply-firewall",
            Self::ObserveFirewall => "observe-firewall",
            Self::RemoveFirewall => "remove-firewall",
            Self::ReleaseRelay => "release-relay",
        }
    }
}

/// Closed controller outcome label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbipOutcome {
    /// Operation converged.
    Success,
    /// Operation is safe to retry.
    Retry,
    /// Operation was blocked fail closed.
    Blocked,
}

impl UsbipOutcome {
    const fn label(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Retry => "retry",
            Self::Blocked => "blocked",
        }
    }
}

/// Bounded metric labels whose keys and values come from closed sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsbipMetricLabels {
    /// Fixed Provider label.
    pub provider: &'static str,
    /// Fixed semantic component label.
    pub component: &'static str,
    /// Closed operation label.
    pub operation: &'static str,
    /// Closed outcome label.
    pub outcome: &'static str,
    /// Closed error label or `none`.
    pub error: &'static str,
}

impl UsbipMetricLabels {
    /// Project controller state without any resource, Zone, device, caller, or
    /// supplied identity value.
    pub const fn new(
        operation: UsbipOperation,
        outcome: UsbipOutcome,
        error: Option<UsbipEffectError>,
    ) -> Self {
        Self {
            provider: "device-usbip",
            component: "service-controller",
            operation: operation.label(),
            outcome: outcome.label(),
            error: match error {
                Some(error) => error.code(),
                None => "none",
            },
        }
    }
}

struct FirewallLease {
    token: FirewallToken,
    digest: FirewallDigest,
    fence: FirewallGenerationFence,
}

impl core::fmt::Debug for FirewallLease {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FirewallLease(<redacted>)")
    }
}

/// USB Service controller state for one physical backing and Network relay.
pub struct UsbipController {
    service: ScopedResourceUid,
    service_generation: ResourceGeneration,
    device_uid: ResourceUid,
    network: Option<NetworkDependency>,
    phase: UsbipServicePhase,
    relay: Option<RelayAuthorityLease>,
    firewall: Option<FirewallLease>,
    last_error: Option<UsbipEffectError>,
    network_assignment_epoch: Option<u64>,
}

impl UsbipController {
    /// Construct one authority-Service controller with no acquired effect state.
    pub const fn new(
        service: ScopedResourceUid,
        service_generation: ResourceGeneration,
        device_uid: ResourceUid,
    ) -> Self {
        Self {
            service,
            service_generation,
            device_uid,
            network: None,
            phase: UsbipServicePhase::WaitingForNetwork,
            relay: None,
            firewall: None,
            last_error: None,
            network_assignment_epoch: None,
        }
    }

    /// Return the closed lifecycle phase.
    pub const fn phase(&self) -> UsbipServicePhase {
        self.phase
    }

    /// Return the last closed error class.
    pub const fn last_error(&self) -> Option<UsbipEffectError> {
        self.last_error
    }

    /// Whether relay authority is currently retained.
    pub const fn relay_authority_retained(&self) -> bool {
        self.relay.is_some()
    }

    /// Whether firewall token/status is currently retained.
    pub const fn firewall_status_retained(&self) -> bool {
        self.firewall.is_some()
    }

    /// Reconcile the Ready Network dependency, relay authority, and exact
    /// ownership-scoped firewall projection.
    pub fn reconcile<P: UsbipEffectPort>(
        &mut self,
        network: NetworkDependency,
        port: &mut P,
    ) -> Result<(), UsbipControllerError> {
        self.validate_network(&network)?;
        self.phase = UsbipServicePhase::Applying;
        self.network = Some(network.clone());
        self.network_assignment_epoch = network.assignment_epoch();
        if self.relay.is_none() {
            match port.acquire_relay(network.identity().resource_uid()) {
                Ok(lease) => self.relay = Some(lease),
                Err(error) => return self.effect_failed(error),
            }
        }
        let fence = FirewallGenerationFence::new(network.generation(), self.service_generation);
        let intent = FirewallProjectionIntent::new(
            self.device_uid.clone(),
            network.identity().resource_uid().clone(),
            FirewallProjectionAction::Apply,
            fence.clone(),
        );
        match port.mutate_firewall(&intent, None) {
            Ok(confirmation) => {
                let Some((token, digest)) = confirmation.into_applied() else {
                    return self.effect_failed(UsbipEffectError::EffectRejected);
                };
                self.firewall = Some(FirewallLease {
                    token,
                    digest,
                    fence,
                });
                self.last_error = None;
                self.phase = UsbipServicePhase::Ready;
                Ok(())
            }
            Err(error) => self.effect_failed(error),
        }
    }

    /// Observe only this Service's USBIP ownership projection.
    pub fn observe<P: UsbipEffectPort>(
        &mut self,
        port: &mut P,
    ) -> Result<(), UsbipControllerError> {
        let network = self
            .network
            .as_ref()
            .ok_or(UsbipControllerError::InvalidState)?;
        let firewall = self
            .firewall
            .as_mut()
            .ok_or(UsbipControllerError::InvalidState)?;
        let intent = FirewallProjectionIntent::new(
            self.device_uid.clone(),
            network.identity().resource_uid().clone(),
            FirewallProjectionAction::Apply,
            firewall.fence.clone(),
        );
        match port.observe_firewall(&intent, &firewall.token) {
            Ok(observation) if observation.matches_expected() => {
                firewall.digest = observation.digest().clone();
                self.phase = UsbipServicePhase::Ready;
                self.last_error = None;
                Ok(())
            }
            Ok(_) => {
                self.phase = UsbipServicePhase::Drifted;
                Err(UsbipControllerError::FirewallDrift)
            }
            Err(error) => self.effect_failed(error),
        }
    }

    /// Remove the exact projection, then release relay authority only after a
    /// confirmed removal or ownership-validated absence.
    pub fn finalize<P: UsbipEffectPort>(
        &mut self,
        port: &mut P,
    ) -> Result<(), UsbipControllerError> {
        self.phase = UsbipServicePhase::Releasing;
        if let Some(firewall) = self.firewall.as_ref() {
            let network = self
                .network
                .as_ref()
                .ok_or(UsbipControllerError::InvalidState)?;
            let intent = FirewallProjectionIntent::new(
                self.device_uid.clone(),
                network.identity().resource_uid().clone(),
                FirewallProjectionAction::Remove,
                firewall.fence.clone(),
            );
            match port.mutate_firewall(&intent, Some(&firewall.token)) {
                Ok(confirmation)
                    if matches!(
                        confirmation.kind(),
                        FirewallConfirmationKind::Removed
                            | FirewallConfirmationKind::ValidatedAbsent
                    ) =>
                {
                    self.firewall = None;
                }
                Ok(_) => return self.effect_failed(UsbipEffectError::EffectRejected),
                Err(error) => return self.effect_failed(error),
            }
        }
        if let Some(relay) = self.relay.take()
            && let Err(error) = port.release_relay(relay.clone())
        {
            self.relay = Some(relay);
            return self.effect_failed(error);
        }
        self.network = None;
        self.network_assignment_epoch = None;
        self.last_error = None;
        self.phase = UsbipServicePhase::WaitingForNetwork;
        Ok(())
    }

    fn validate_network(
        &mut self,
        network: &NetworkDependency,
    ) -> Result<(), UsbipControllerError> {
        if self.service.zone_uid() != network.identity().zone_uid() {
            return self.effect_failed(UsbipEffectError::WrongZone);
        }
        if !network.ready() {
            return self.effect_failed(UsbipEffectError::NetworkNotReady);
        }
        if network.assignment_epoch() == Some(0)
            || self
                .network_assignment_epoch
                .zip(network.assignment_epoch())
                .is_some_and(|(current, next)| next < current)
        {
            return self.effect_failed(UsbipEffectError::StaleAssignment);
        }
        Ok(())
    }

    fn effect_failed<T>(&mut self, error: UsbipEffectError) -> Result<T, UsbipControllerError> {
        self.last_error = Some(error);
        self.phase = match error {
            UsbipEffectError::Transient
            | UsbipEffectError::FirewallGenerationMismatch
            | UsbipEffectError::StaleAssignment => {
                if self.firewall.is_some() {
                    UsbipServicePhase::Releasing
                } else {
                    UsbipServicePhase::Applying
                }
            }
            UsbipEffectError::WrongZone
            | UsbipEffectError::RelayAuthorityConflict
            | UsbipEffectError::FirewallForeignConflict
            | UsbipEffectError::EffectRejected
            | UsbipEffectError::UnknownProjectionAction => UsbipServicePhase::Blocked,
            UsbipEffectError::NetworkNotReady => UsbipServicePhase::WaitingForNetwork,
        };
        Err(UsbipControllerError::Effect(error))
    }
}

impl core::fmt::Debug for UsbipController {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UsbipController")
            .field("phase", &self.phase)
            .field("has_network", &self.network.is_some())
            .field("has_relay", &self.relay.is_some())
            .field("has_firewall", &self.firewall.is_some())
            .field("last_error", &self.last_error)
            .finish()
    }
}

/// Closed controller failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbipControllerError {
    /// The controller state did not admit the requested transition.
    InvalidState,
    /// Ownership-scoped observation differs from desired state.
    FirewallDrift,
    /// An injected semantic effect failed.
    Effect(UsbipEffectError),
}

impl UsbipControllerError {
    /// Return the stable identity-free code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidState => "invalid-state",
            Self::FirewallDrift => "firewall-drift",
            Self::Effect(error) => error.code(),
        }
    }
}

impl core::fmt::Display for UsbipControllerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for UsbipControllerError {}
