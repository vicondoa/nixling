//! Security-key Device controller facade.

use core::fmt;
use d2b_contracts_provider::v3::semantic_services::{
    SemanticFamily,
    child_resources::{
        BindingChildKind, BindingChildPlacement, BindingChildRequest, BindingChildSet,
        explicit_binding_children, explicit_binding_children_with_user,
    },
};
use d2b_contracts_resource::v3::{ExecutionDomain, ResourceRef, ResourceUid};

use crate::effect_port::{
    DeviceId, InventoryEffectError, InventoryObservation, ObservationPolicyId,
    SecurityKeyInventoryEffectPort,
};
use crate::{
    PhysicalUsbBackingClaim, SecurityKeyAdmission, SecurityKeyEffectError, SecurityKeyEffectPort,
    SecurityKeyLease, SecurityKeyLeaseError, SecurityKeySessionId, SessionRecord, SessionResult,
    SessionRing, SECURITY_KEY_BINDING_RESOURCE_TYPE, SECURITY_KEY_SERVICE_RESOURCE_TYPE,
};
const SECURITY_KEY_PROVIDER_REF: &str = "Provider/device-security-key";

const SECURITY_KEY_BINDING_CHILD_REQUESTS: [BindingChildRequest; 2] = [
    BindingChildRequest::process(
        BindingChildKind::Process,
        BindingChildPlacement::Guest,
        "guest-frontend",
        "Provider/system-systemd",
        "sk-frontend",
        ExecutionDomain::User,
        "service",
    ),
    BindingChildRequest::endpoint(
        BindingChildPlacement::Guest,
        "guest-endpoint",
        "guest-frontend",
    ),
];

const SECURITY_KEY_BINDING_CHILD_REQUESTS_WITH_USER: [BindingChildRequest; 2] = [
    BindingChildRequest::process_for_user(
        BindingChildKind::Process,
        BindingChildPlacement::Guest,
        "guest-frontend",
        "Provider/system-systemd",
        "sk-frontend",
        "service",
    ),
    BindingChildRequest::endpoint(
        BindingChildPlacement::Guest,
        "guest-endpoint",
        "guest-frontend",
    ),
];

/// Default descriptor repair interval.
pub const SECURITY_KEY_REPAIR_INTERVAL_SECS: u64 = 30;
/// Maximum descriptor repair interval.
pub const SECURITY_KEY_MAX_REPAIR_INTERVAL_SECS: u64 = 60;
/// Authority Service finalizer owned by this Provider.
pub const SECURITY_KEY_SERVICE_FINALIZER: &str =
    "device-security-key.d2bus.org/service-finalizer";
/// Consumer Binding finalizer owned by this Provider.
pub const SECURITY_KEY_BINDING_FINALIZER: &str =
    "device-security-key.d2bus.org/binding-finalizer";

/// Lifecycle phase retained by the resource-backed controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityKeyPhase {
    /// No physical effect has been admitted.
    Pending,
    /// A session or child realization is active.
    Active,
    /// The last session completed and released authority.
    Completed,
    /// A stale or ambiguous fence requires fresh Core admission.
    Quarantined,
}

/// Exact Core assignment admission for one SecurityKey Binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityKeyBindingAdmission {
    zone_uid: ResourceUid,
    device_uid: ResourceUid,
    service_uid: ResourceUid,
    binding_uid: ResourceUid,
    guest_uid: ResourceUid,
    user_uid: ResourceUid,
    assignment_epoch: u64,
}

impl SecurityKeyBindingAdmission {
    /// Construct a Binding admission bound to one Device and assignment.
    pub fn new(
        zone_uid: ResourceUid,
        device_uid: ResourceUid,
        service_uid: ResourceUid,
        binding_uid: ResourceUid,
        guest_uid: ResourceUid,
        user_uid: ResourceUid,
        assignment_epoch: u64,
    ) -> Result<Self, SecurityKeyControllerError> {
        if assignment_epoch == 0 {
            return Err(SecurityKeyControllerError::Admission);
        }
        Ok(Self {
            zone_uid,
            device_uid,
            service_uid,
            binding_uid,
            guest_uid,
            user_uid,
            assignment_epoch,
        })
    }

    /// Borrow the admitted Zone identity.
    pub const fn zone_uid(&self) -> &ResourceUid {
        &self.zone_uid
    }

    /// Borrow the admitted Device identity.
    pub const fn device_uid(&self) -> &ResourceUid {
        &self.device_uid
    }

    /// Borrow the admitted Service identity.
    pub const fn service_uid(&self) -> &ResourceUid {
        &self.service_uid
    }

    /// Borrow the admitted Binding identity.
    pub const fn binding_uid(&self) -> &ResourceUid {
        &self.binding_uid
    }

    /// Borrow the admitted Guest identity.
    pub const fn guest_uid(&self) -> &ResourceUid {
        &self.guest_uid
    }

    /// Borrow the admitted User identity.
    pub const fn user_uid(&self) -> &ResourceUid {
        &self.user_uid
    }

    /// Return the exact assignment epoch.
    pub const fn assignment_epoch(&self) -> u64 {
        self.assignment_epoch
    }
}

/// The cutover contract for SecurityKey Service and Binding owners.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityKeyRunnerContract {
    service_resource_type: &'static str,
    binding_resource_type: &'static str,
    repair_interval_secs: u64,
    legacy_scheduler_disabled: bool,
    watched_configuration_is_dependency: bool,
}

impl SecurityKeyRunnerContract {
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

    /// Whether legacy security-key scheduling is disabled.
    pub const fn legacy_scheduler_disabled(self) -> bool {
        self.legacy_scheduler_disabled
    }

    /// Whether watched configuration is treated as a dependency.
    pub const fn watched_configuration_is_dependency(self) -> bool {
        self.watched_configuration_is_dependency
    }
}

/// Return the one shared-Runner registration for SecurityKey.
pub const fn security_key_runner_contract() -> SecurityKeyRunnerContract {
    SecurityKeyRunnerContract {
        service_resource_type: SECURITY_KEY_SERVICE_RESOURCE_TYPE,
        binding_resource_type: SECURITY_KEY_BINDING_RESOURCE_TYPE,
        repair_interval_secs: SECURITY_KEY_REPAIR_INTERVAL_SECS,
        legacy_scheduler_disabled: true,
        watched_configuration_is_dependency: true,
    }
}

/// Controller-level failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityKeyControllerError {
    /// Lease state rejected the requested operation.
    Lease(SecurityKeyLeaseError),
    /// Binding or Service references failed semantic admission.
    Admission,
    /// Session ring could not be created.
    RingCapacity,
    /// An effect failed while recording a terminal session.
    Effect(SecurityKeyEffectError),
}

impl fmt::Display for SecurityKeyControllerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Lease(error) => error.code(),
            Self::Admission => "security-key-controller-admission-failed",
            Self::RingCapacity => "security-key-session-ring-capacity-out-of-range",
            Self::Effect(error) => error.code(),
        })
    }
}

impl std::error::Error for SecurityKeyControllerError {}

/// Combined reconcile outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityKeyReconcileOutcome {
    /// The lease and relay are active.
    Active,
    /// The terminal session was recorded and authority released.
    Completed,
}

/// Reconcile output including the child resources owned by a Binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityKeyReconcileResultWithChildren {
    /// Lease/session outcome.
    pub outcome: SecurityKeyReconcileOutcome,
    /// UID-free Process and Endpoint intents.
    pub children: BindingChildSet,
}

/// Device-security-key controller state.
pub struct SecurityKeyController {
    lease: SecurityKeyLease,
    ring: SessionRing,
    phase: SecurityKeyPhase,
    binding_admission: Option<SecurityKeyBindingAdmission>,
}

impl SecurityKeyController {
    /// Construct a controller with a bounded session ring.
    pub fn new(
        holder: ResourceUid,
        backing: PhysicalUsbBackingClaim,
        ring_capacity: usize,
    ) -> Result<Self, SecurityKeyControllerError> {
        Ok(Self {
            lease: SecurityKeyLease::new(holder, backing),
            ring: SessionRing::new(ring_capacity)
                .map_err(|_| SecurityKeyControllerError::RingCapacity)?,
            phase: SecurityKeyPhase::Pending,
            binding_admission: None,
        })
    }

    /// Construct a controller from one exact Core Device admission.
    pub fn new_authorized(
        device_uid: ResourceUid,
        admission: SecurityKeyAdmission,
        ring_capacity: usize,
    ) -> Result<Self, SecurityKeyControllerError> {
        Ok(Self {
            lease: SecurityKeyLease::new_authorized(device_uid, admission)
                .map_err(SecurityKeyControllerError::Lease)?,
            ring: SessionRing::new(ring_capacity)
                .map_err(|_| SecurityKeyControllerError::RingCapacity)?,
            phase: SecurityKeyPhase::Pending,
            binding_admission: None,
        })
    }

    /// Borrow the underlying lease state.
    pub const fn lease(&self) -> &SecurityKeyLease {
        &self.lease
    }

    /// Return the resource-backed lifecycle phase.
    pub const fn phase(&self) -> SecurityKeyPhase {
        self.phase
    }

    /// Borrow the exact Binding assignment admission.
    pub const fn binding_admission(&self) -> Option<&SecurityKeyBindingAdmission> {
        self.binding_admission.as_ref()
    }

    /// Bind this controller to fresh Core Service/Binding assignment evidence.
    pub fn bind_resource_admission(
        &mut self,
        admission: SecurityKeyBindingAdmission,
    ) -> Result<(), SecurityKeyControllerError> {
        if admission.device_uid() != self.lease.holder() || admission.assignment_epoch() == 0 {
            self.phase = SecurityKeyPhase::Quarantined;
            return Err(SecurityKeyControllerError::Admission);
        }
        if self
            .binding_admission
            .as_ref()
            .is_some_and(|current| current != &admission)
        {
            self.phase = SecurityKeyPhase::Quarantined;
            return Err(SecurityKeyControllerError::Admission);
        }
        self.binding_admission = Some(admission);
        Ok(())
    }

    /// Quarantine the controller until Core supplies fresh matching evidence.
    pub fn quarantine(&mut self) {
        self.phase = SecurityKeyPhase::Quarantined;
    }

    /// Build the explicit Host relay and Guest frontend children for one
    /// authored security-key Binding.
    ///
    /// `target_ref` is the Guest execution target extracted from the Binding's
    /// target object. The caller must provide the authored Binding and its
    /// existing Service; a Service alone never creates consumer children.
    pub fn child_resources(
        binding_ref: &ResourceRef,
        service_ref: &ResourceRef,
        target_ref: &ResourceRef,
    ) -> Result<BindingChildSet, SecurityKeyControllerError> {
        if target_ref.resource_type().as_str() != "Guest" {
            return Err(SecurityKeyControllerError::Admission);
        }
        explicit_binding_children(
            SemanticFamily::SecurityKey,
            binding_ref.clone(),
            service_ref.clone(),
            target_ref.clone(),
            ResourceRef::parse(SECURITY_KEY_PROVIDER_REF)
                .expect("security-key Provider reference is canonical"),
            &SECURITY_KEY_BINDING_CHILD_REQUESTS,
        )
        .map_err(|_| SecurityKeyControllerError::Admission)
    }

    /// Build security-key children while binding the frontend to the
    /// authored workload User identity.
    pub fn child_resources_for_user(
        binding_ref: &ResourceRef,
        service_ref: &ResourceRef,
        target_ref: &ResourceRef,
        user_ref: &ResourceRef,
    ) -> Result<BindingChildSet, SecurityKeyControllerError> {
        if target_ref.resource_type().as_str() != "Guest"
            || user_ref.resource_type().as_str() != "User"
        {
            return Err(SecurityKeyControllerError::Admission);
        }
        explicit_binding_children_with_user(
            SemanticFamily::SecurityKey,
            binding_ref.clone(),
            service_ref.clone(),
            target_ref.clone(),
            ResourceRef::parse(SECURITY_KEY_PROVIDER_REF)
                .expect("security-key Provider reference is canonical"),
            Some(user_ref.clone()),
            &SECURITY_KEY_BINDING_CHILD_REQUESTS_WITH_USER,
        )
        .map_err(|_| SecurityKeyControllerError::Admission)
    }

    /// Return the session outcome together with the explicit Binding children.
    pub fn reconcile_with_children(
        &mut self,
        binding_ref: &ResourceRef,
        service_ref: &ResourceRef,
        target_ref: &ResourceRef,
        outcome: SecurityKeyReconcileOutcome,
    ) -> Result<SecurityKeyReconcileResultWithChildren, SecurityKeyControllerError> {
        let children = Self::child_resources(binding_ref, service_ref, target_ref)?;
        self.phase = match outcome {
            SecurityKeyReconcileOutcome::Active => SecurityKeyPhase::Active,
            SecurityKeyReconcileOutcome::Completed => SecurityKeyPhase::Completed,
        };
        Ok(SecurityKeyReconcileResultWithChildren { outcome, children })
    }

    /// Return the reconcile output with an explicit workload User identity.
    pub fn reconcile_with_children_for_user(
        &mut self,
        binding_ref: &ResourceRef,
        service_ref: &ResourceRef,
        target_ref: &ResourceRef,
        user_ref: &ResourceRef,
        outcome: SecurityKeyReconcileOutcome,
    ) -> Result<SecurityKeyReconcileResultWithChildren, SecurityKeyControllerError> {
        let children =
            Self::child_resources_for_user(binding_ref, service_ref, target_ref, user_ref)?;
        self.phase = match outcome {
            SecurityKeyReconcileOutcome::Active => SecurityKeyPhase::Active,
            SecurityKeyReconcileOutcome::Completed => SecurityKeyPhase::Completed,
        };
        Ok(SecurityKeyReconcileResultWithChildren { outcome, children })
    }

    /// Reconcile a resource-backed Binding only with its current Core
    /// admission and explicit Guest/User target.
    pub fn reconcile_binding_with_admission(
        &mut self,
        admission: &SecurityKeyBindingAdmission,
        binding_ref: &ResourceRef,
        service_ref: &ResourceRef,
        target_ref: &ResourceRef,
        user_ref: &ResourceRef,
        outcome: SecurityKeyReconcileOutcome,
    ) -> Result<SecurityKeyReconcileResultWithChildren, SecurityKeyControllerError> {
        if self.binding_admission.as_ref() != Some(admission)
            || binding_ref.resource_type().as_str() != SECURITY_KEY_BINDING_RESOURCE_TYPE
            || service_ref.resource_type().as_str() != SECURITY_KEY_SERVICE_RESOURCE_TYPE
            || target_ref.resource_type().as_str() != "Guest"
            || user_ref.resource_type().as_str() != "User"
        {
            self.phase = SecurityKeyPhase::Quarantined;
            return Err(SecurityKeyControllerError::Admission);
        }
        self.reconcile_with_children_for_user(
            binding_ref,
            service_ref,
            target_ref,
            user_ref,
            outcome,
        )
    }

    /// Whether a child belongs to this Binding's Process/Endpoint set.
    pub fn owns_child(
        binding_ref: &ResourceRef,
        service_ref: &ResourceRef,
        target_ref: &ResourceRef,
        child_ref: &ResourceRef,
    ) -> Result<bool, SecurityKeyControllerError> {
        if binding_ref.resource_type().as_str() != SECURITY_KEY_BINDING_RESOURCE_TYPE
            || service_ref.resource_type().as_str() != SECURITY_KEY_SERVICE_RESOURCE_TYPE
            || target_ref.resource_type().as_str() != "Guest"
        {
            return Err(SecurityKeyControllerError::Admission);
        }
        let children = Self::child_resources(binding_ref, service_ref, target_ref)?;
        Ok(matches!(
            child_ref.resource_type().as_str(),
            "Process" | "Endpoint"
        ) && children.resource_refs().any(|current| current == child_ref))
    }

    /// Observe the exact physical Device through Core's injected port.
    pub async fn observe_inventory<P: SecurityKeyInventoryEffectPort>(
        &self,
        device_id: &DeviceId,
        policy_id: &ObservationPolicyId,
        port: &P,
    ) -> Result<InventoryObservation, InventoryEffectError> {
        port.observe_inventory(device_id, policy_id).await
    }

    /// Start a session through the authority-before-open sequence.
    pub fn acquire<P: SecurityKeyEffectPort>(
        &mut self,
        session: SecurityKeySessionId,
        device_uid: ResourceUid,
        port: &mut P,
    ) -> Result<SecurityKeyReconcileOutcome, SecurityKeyControllerError> {
        self.lease
            .acquire(session, device_uid, port)
            .map_err(|error| {
                if matches!(
                    error,
                    SecurityKeyLeaseError::AuthorizationDenied
                        | SecurityKeyLeaseError::Effect(
                            SecurityKeyEffectError::AuthorizationDenied
                        )
                ) {
                    self.phase = SecurityKeyPhase::Quarantined;
                }
                SecurityKeyControllerError::Lease(error)
            })?;
        self.ring
            .push(SessionRecord::new(session, SessionResult::InProgress));
        self.phase = SecurityKeyPhase::Active;
        Ok(SecurityKeyReconcileOutcome::Active)
    }

    /// Acquire a session after exact Device and holder revalidation.
    pub fn acquire_authorized<P: SecurityKeyEffectPort>(
        &mut self,
        session: SecurityKeySessionId,
        device_uid: ResourceUid,
        holder: &ResourceRef,
        port: &mut P,
    ) -> Result<SecurityKeyReconcileOutcome, SecurityKeyControllerError> {
        self.lease
            .acquire_authorized(session, device_uid, holder, port)
            .map_err(|error| {
                if matches!(
                    error,
                    SecurityKeyLeaseError::AuthorizationDenied
                        | SecurityKeyLeaseError::Effect(
                            SecurityKeyEffectError::AuthorizationDenied
                        )
                ) {
                    self.phase = SecurityKeyPhase::Quarantined;
                }
                SecurityKeyControllerError::Lease(error)
            })?;
        self.ring
            .push(SessionRecord::new(session, SessionResult::InProgress));
        self.phase = SecurityKeyPhase::Active;
        Ok(SecurityKeyReconcileOutcome::Active)
    }

    /// Rebind the controller to fresh Core admission evidence after a
    /// completed session.
    pub fn rebind_authorized(
        &mut self,
        device_uid: ResourceUid,
        admission: SecurityKeyAdmission,
    ) -> Result<(), SecurityKeyControllerError> {
        self.lease
            .rebind_authorized(device_uid, admission)
            .map_err(SecurityKeyControllerError::Lease)
    }

    /// Complete and record the active session.
    pub fn complete<P: SecurityKeyEffectPort>(
        &mut self,
        port: &mut P,
    ) -> Result<SecurityKeyReconcileOutcome, SecurityKeyControllerError> {
        let session = self
            .lease
            .session()
            .copied()
            .ok_or(SecurityKeyControllerError::Lease(
                SecurityKeyLeaseError::InvalidTransition,
            ))?;
        self.lease
            .complete(port)
            .map_err(SecurityKeyControllerError::Lease)?;
        self.ring
            .push(SessionRecord::new(session, SessionResult::Success));
        self.phase = SecurityKeyPhase::Completed;
        Ok(SecurityKeyReconcileOutcome::Completed)
    }

    /// Complete a session only when the current assignment fence still
    /// matches the admission used to start it.
    pub fn complete_authorized(
        &mut self,
        session: SecurityKeySessionId,
        admission: &SecurityKeyBindingAdmission,
        port: &mut impl SecurityKeyEffectPort,
    ) -> Result<SecurityKeyReconcileOutcome, SecurityKeyControllerError> {
        if self.binding_admission.as_ref() != Some(admission)
            || self.lease.session() != Some(&session)
        {
            self.phase = SecurityKeyPhase::Quarantined;
            return Err(SecurityKeyControllerError::Admission);
        }
        self.complete(port)
    }
}

impl fmt::Debug for SecurityKeyController {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecurityKeyController")
            .field("lease", &self.lease)
            .field("ring", &self.ring)
            .field("phase", &self.phase)
            .field("has_binding_admission", &self.binding_admission.is_some())
            .finish()
    }
}
