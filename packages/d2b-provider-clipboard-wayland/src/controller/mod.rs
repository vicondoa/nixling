//! Clipboard controller placement and lifecycle projections.

use crate::DISPLAY_PROVIDER_REF;
use d2b_contracts_resource::v3::identity::{EvidenceClass, Locality};
use d2b_contracts_resource::v3::{ResourceRef, ZoneId};
use d2b_provider_toolkit::AuthenticatedSessionRouteBinding;
use sha2::{Digest, Sha256};

/// The bounded repair interval for the clipboard ComponentSession runtime.
pub const CLIPBOARD_REPAIR_INTERVAL_SECS: u64 = 300;

/// The cutover contract for the clipboard service-only runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClipboardRunnerContract {
    service_package: &'static str,
    repair_interval_secs: u64,
    legacy_scheduler_disabled: bool,
    watched_configuration_is_dependency: bool,
    component_session_only: bool,
}

impl ClipboardRunnerContract {
    /// Return the management service package.
    pub const fn service_package(self) -> &'static str {
        self.service_package
    }

    /// Return the bounded repair interval.
    pub const fn repair_interval_secs(self) -> u64 {
        self.repair_interval_secs
    }

    /// Whether legacy clipboard scheduling is disabled.
    pub const fn legacy_scheduler_disabled(self) -> bool {
        self.legacy_scheduler_disabled
    }

    /// Whether configuration is dependency-only.
    pub const fn watched_configuration_is_dependency(self) -> bool {
        self.watched_configuration_is_dependency
    }

    /// Whether clipboard state remains on typed ComponentSession streams.
    pub const fn component_session_only(self) -> bool {
        self.component_session_only
    }
}

/// Return the service-only clipboard cutover contract.
pub const fn clipboard_runner_contract() -> ClipboardRunnerContract {
    ClipboardRunnerContract {
        service_package: crate::MANAGEMENT_SERVICE,
        repair_interval_secs: CLIPBOARD_REPAIR_INTERVAL_SECS,
        legacy_scheduler_disabled: true,
        watched_configuration_is_dependency: true,
        component_session_only: true,
    }
}

/// Display dependency state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyStatus {
    /// Dependency is Ready.
    Ready,
    /// No display Provider was configured; host-only mode.
    Absent,
    /// Dependency exists but is not Ready.
    Degraded,
}

/// Authenticated evidence that the display Provider is Ready for one User
/// and Zone generation.
#[derive(Clone, PartialEq, Eq)]
pub struct DisplayDependencyEvidence {
    pub(crate) provider_ref: ResourceRef,
    pub(crate) zone: ZoneId,
    pub(crate) host_execution_ref: ResourceRef,
    pub(crate) user_ref: ResourceRef,
    pub(crate) provider_generation: u64,
    pub(crate) reconnect_generation: u64,
    pub(crate) controller_generation: u64,
    pub(crate) session_digest: [u8; 32],
}

impl DisplayDependencyEvidence {
    /// Consume a Core-authenticated display route.
    ///
    /// The route binding is produced by the sealed ComponentSession
    /// authority. Its Provider generation is the only readiness generation
    /// accepted here; lexical Provider, User, and Zone values are never
    /// accepted as authority inputs.
    pub fn from_authenticated_route(
        route: AuthenticatedSessionRouteBinding,
    ) -> Result<Self, &'static str> {
        let Some(provider_ref) = route.provider_ref() else {
            return Err("clipboard-display-unauthenticated");
        };
        let Some(provider_generation) = route.provider_generation() else {
            return Err("clipboard-display-unauthenticated");
        };
        if provider_ref.to_canonical_string() != DISPLAY_PROVIDER_REF
            || route.service().as_str() != "d2b.display.v3"
            || route.evidence_class() != EvidenceClass::UnixPeer
            || route.locality() != Locality::Local
            || route.subject_ref().resource_type().as_str() != "User"
            || route.reconnect_generation().get() == 0
            || provider_generation.get() == 0
        {
            return Err("clipboard-display-unauthenticated");
        }
        let Some(host_execution_ref) = route.context().execution_ref() else {
            return Err("clipboard-display-unauthenticated");
        };
        let Some(controller_generation) = route.controller_generation() else {
            return Err("clipboard-display-unauthenticated");
        };
        if host_execution_ref.resource_type().as_str() != "Host" || controller_generation.get() == 0
        {
            return Err("clipboard-display-unauthenticated");
        }
        let mut digest = Sha256::new();
        digest.update(provider_ref.to_canonical_string().as_bytes());
        digest.update([0]);
        digest.update(route.zone().as_str().as_bytes());
        digest.update([0]);
        digest.update(host_execution_ref.to_canonical_string().as_bytes());
        digest.update([0]);
        digest.update(route.subject_ref().to_canonical_string().as_bytes());
        digest.update([0]);
        digest.update(provider_generation.get().to_be_bytes());
        digest.update([0]);
        digest.update(route.reconnect_generation().get().to_be_bytes());
        digest.update([0]);
        digest.update(controller_generation.get().to_be_bytes());
        let mut session_digest = [0; 32];
        session_digest.copy_from_slice(&digest.finalize());
        Ok(Self {
            provider_ref: provider_ref.clone(),
            zone: route.zone().clone(),
            host_execution_ref: host_execution_ref.clone(),
            user_ref: route.subject_ref().clone(),
            provider_generation: provider_generation.get(),
            reconnect_generation: route.reconnect_generation().get(),
            controller_generation: controller_generation.get(),
            session_digest,
        })
    }

    /// Consume a daemon-authenticated display route plus the committed User
    /// resource that owns the host observer projection.
    pub fn from_committed_display_route(
        route: AuthenticatedSessionRouteBinding,
        user_ref: ResourceRef,
    ) -> Result<Self, &'static str> {
        let Some(provider_ref) = route.provider_ref() else {
            return Err("clipboard-display-unauthenticated");
        };
        let Some(provider_generation) = route.provider_generation() else {
            return Err("clipboard-display-unauthenticated");
        };
        if provider_ref.to_canonical_string() != DISPLAY_PROVIDER_REF
            || route.service().as_str() != "d2b.display.v3"
            || route.evidence_class() != EvidenceClass::UnixPeer
            || route.locality() != Locality::Local
            || route.subject_ref().resource_type().as_str() != "Guest"
            || user_ref.resource_type().as_str() != "User"
            || route.reconnect_generation().get() == 0
            || provider_generation.get() == 0
        {
            return Err("clipboard-display-unauthenticated");
        }
        let Some(host_execution_ref) = route.context().execution_ref() else {
            return Err("clipboard-display-unauthenticated");
        };
        let Some(controller_generation) = route.controller_generation() else {
            return Err("clipboard-display-unauthenticated");
        };
        if host_execution_ref.resource_type().as_str() != "Host" || controller_generation.get() == 0
        {
            return Err("clipboard-display-unauthenticated");
        }
        let mut digest = Sha256::new();
        digest.update(provider_ref.to_canonical_string().as_bytes());
        digest.update([0]);
        digest.update(route.zone().as_str().as_bytes());
        digest.update([0]);
        digest.update(host_execution_ref.to_canonical_string().as_bytes());
        digest.update([0]);
        digest.update(user_ref.to_canonical_string().as_bytes());
        digest.update([0]);
        digest.update(provider_generation.get().to_be_bytes());
        digest.update([0]);
        digest.update(route.reconnect_generation().get().to_be_bytes());
        digest.update([0]);
        digest.update(controller_generation.get().to_be_bytes());
        let mut session_digest = [0; 32];
        session_digest.copy_from_slice(&digest.finalize());
        Ok(Self {
            provider_ref: provider_ref.clone(),
            zone: route.zone().clone(),
            host_execution_ref: host_execution_ref.clone(),
            user_ref,
            provider_generation: provider_generation.get(),
            reconnect_generation: route.reconnect_generation().get(),
            controller_generation: controller_generation.get(),
            session_digest,
        })
    }

    /// Borrow the authenticated display Provider reference.
    pub const fn provider_ref(&self) -> &ResourceRef {
        &self.provider_ref
    }

    /// Borrow the authenticated Zone.
    pub const fn zone(&self) -> &ZoneId {
        &self.zone
    }

    /// Borrow the authenticated Host execution reference.
    pub const fn host_execution_ref(&self) -> &ResourceRef {
        &self.host_execution_ref
    }

    /// Borrow the authenticated User.
    pub const fn user_ref(&self) -> &ResourceRef {
        &self.user_ref
    }

    /// Return the Ready generation.
    pub const fn generation(&self) -> u64 {
        self.provider_generation
    }

    /// Return the display reconnect generation.
    pub const fn reconnect_generation(&self) -> u64 {
        self.reconnect_generation
    }

    /// Return the Core controller generation.
    pub const fn controller_generation(&self) -> u64 {
        self.controller_generation
    }

    /// Return the opaque digest binding this display dependency session.
    pub const fn session_digest(&self) -> [u8; 32] {
        self.session_digest
    }
}

impl core::fmt::Debug for DisplayDependencyEvidence {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DisplayDependencyEvidence(REDACTED)")
    }
}

/// Core-created clipboard Process projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessPlan {
    /// Process template.
    pub template: &'static str,
    /// Process domain.
    pub domain: &'static str,
    /// Execution reference.
    pub execution_ref: ResourceRef,
    /// Optional user reference.
    pub user_ref: Option<ResourceRef>,
    /// Whether a Provider state Volume is mounted.
    pub mounts_state_volume: bool,
}

/// Clipboard controller.
pub struct ClipboardController {
    execution_ref: ResourceRef,
    user_ref: ResourceRef,
}

impl ClipboardController {
    /// Construct a controller for Host/system and User placement.
    pub fn new(
        execution_ref: impl AsRef<str>,
        user_ref: impl AsRef<str>,
    ) -> Result<Self, &'static str> {
        let execution_ref = ResourceRef::parse(execution_ref.as_ref())
            .map_err(|_| "clipboard-placement-invalid")?;
        let user_ref =
            ResourceRef::parse(user_ref.as_ref()).map_err(|_| "clipboard-placement-invalid")?;
        if execution_ref.resource_type().as_str() != "Host"
            || user_ref.resource_type().as_str() != "User"
        {
            return Err("clipboard-placement-invalid");
        }
        Ok(Self {
            execution_ref,
            user_ref,
        })
    }

    /// Return display dependency state for authenticated evidence.
    pub fn dependency_status(
        &self,
        display: Option<&DisplayDependencyEvidence>,
    ) -> DependencyStatus {
        let Some(display) = display else {
            return DependencyStatus::Absent;
        };
        if display.provider_ref().to_canonical_string() == DISPLAY_PROVIDER_REF
            && display.user_ref() == &self.user_ref
            && display.host_execution_ref() == &self.execution_ref
            && display.generation() != 0
        {
            DependencyStatus::Ready
        } else {
            DependencyStatus::Degraded
        }
    }

    /// Return the two Core-created component plans.
    pub fn plan_processes(&self) -> Vec<ProcessPlan> {
        vec![
            ProcessPlan {
                template: "clipboard-controller",
                domain: "system",
                execution_ref: self.execution_ref.clone(),
                user_ref: None,
                mounts_state_volume: false,
            },
            ProcessPlan {
                template: "clipd-host",
                domain: "user",
                execution_ref: self.execution_ref.clone(),
                user_ref: Some(self.user_ref.clone()),
                mounts_state_volume: false,
            },
        ]
    }

    /// Clipboard has no Provider state Volume.
    pub const fn provider_state_set_empty(&self) -> bool {
        true
    }
}

impl core::fmt::Debug for ClipboardController {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ClipboardController(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dependency(provider_ref: &str) -> DisplayDependencyEvidence {
        DisplayDependencyEvidence {
            provider_ref: ResourceRef::parse(provider_ref).unwrap(),
            zone: ZoneId::parse("work").unwrap(),
            host_execution_ref: ResourceRef::parse("Host/host-system").unwrap(),
            user_ref: ResourceRef::parse("User/alice").unwrap(),
            provider_generation: 1,
            reconnect_generation: 1,
            controller_generation: 1,
            session_digest: [1; 32],
        }
    }

    #[test]
    fn dependency_status_requires_the_canonical_display_provider() {
        let controller = ClipboardController::new("Host/host-system", "User/alice").unwrap();
        assert_eq!(
            controller.dependency_status(Some(&dependency(DISPLAY_PROVIDER_REF))),
            DependencyStatus::Ready
        );
        assert_eq!(
            controller.dependency_status(Some(&dependency("Provider/other"))),
            DependencyStatus::Degraded
        );
    }
}
