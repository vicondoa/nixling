//! Common long-lived Provider entrypoint lifecycle.
//!
//! Provider binaries are supervised children.  They must publish readiness
//! only after their local service registration has completed, remain alive
//! while the supervisor owns them, and stop admitting work before they drain.

use std::{
    fmt,
    io::{self, Write},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};

use d2b_contracts_provider::v3::{
    ComponentDescriptor, ComponentExecution, ComponentType, ControllerTargetKind, EffectPortClass,
};
use d2b_contracts_resource::v3::{
    ControllerGeneration, ResourceGeneration, ResourceRef, ResourceUid,
};
use d2b_contracts_zone_session::v3::component_session::OperationId;
use d2b_provider::{
    OperationLedger, OperationLedgerAdmission, OperationLedgerError, OperationLedgerRow,
};
use d2b_session::{AuthenticatedComponentSession, AuthenticatedSessionRouteBinding};

const STARTING: u8 = 0;
const READY: u8 = 1;
const DRAINING: u8 = 2;
const STOPPED: u8 = 3;

/// A bounded Provider lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderLifecycle {
    /// Local service registration is still in progress.
    Starting,
    /// The service has completed registration and accepts work.
    Ready,
    /// New work is refused while admitted work drains.
    Draining,
    /// The process has completed its drain.
    Stopped,
}

impl ProviderLifecycle {
    const fn from_u8(value: u8) -> Self {
        match value {
            READY => Self::Ready,
            DRAINING => Self::Draining,
            STOPPED => Self::Stopped,
            _ => Self::Starting,
        }
    }
}

/// Stable failures encountered while bootstrapping a Provider process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderRuntimeError {
    /// The Provider name is empty or exceeds the wire bound.
    InvalidName,
    /// Readiness was requested after the process began draining.
    NotAccepting,
    /// The readiness announcement could not be written.
    ReadinessIo,
    /// The Provider has no authenticated ComponentSession route.
    SessionUnauthenticated,
    /// The generated Provider service loop failed after readiness.
    SessionLoopFailed,
    /// A signed controller descriptor is not launchable on the requested
    /// target.
    ControllerDescriptorInvalid,
}

impl fmt::Display for ProviderRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidName => "provider-runtime-name-invalid",
            Self::NotAccepting => "provider-runtime-not-accepting",
            Self::ReadinessIo => "provider-runtime-readiness-io",
            Self::SessionUnauthenticated => "provider-runtime-session-unauthenticated",
            Self::SessionLoopFailed => "provider-runtime-session-loop-failed",
            Self::ControllerDescriptorInvalid => "provider-runtime-controller-descriptor-invalid",
        })
    }
}

impl std::error::Error for ProviderRuntimeError {}

struct RuntimeState {
    admitted: usize,
    ready_route: Option<AuthenticatedSessionRouteBinding>,
}

/// A non-cloneable process lifecycle owner.
///
/// The owner is deliberately small and transport-neutral.  Generated
/// ComponentSession servers own request admission; this type owns only the
/// process boundary and readiness/drain handshake around them.
pub struct ProviderEntrypoint {
    name: &'static str,
    provider_ref: Option<ResourceRef>,
    execution_ref: Option<ResourceRef>,
    process_ref: Option<ResourceRef>,
    target_kind: Option<ControllerTargetKind>,
    provider_generation: Option<ResourceGeneration>,
    controller_generation: Option<ControllerGeneration>,
    service: Option<&'static str>,
    lifecycle: AtomicU8,
    state: Arc<(Mutex<RuntimeState>, Condvar)>,
}

/// A non-authorizing admission proof derived from one authenticated
/// ComponentSession route.
///
/// This proof carries only redacted routing metadata and is consumed when the
/// entrypoint publishes readiness. It cannot be constructed from a subject,
/// Provider name, or Zone string.
pub struct ProviderSessionAdmission {
    route: AuthenticatedSessionRouteBinding,
}

/// A route source that has already crossed the authenticated session boundary.
///
/// Both the full session candidate and the provider-side route metadata
/// snapshot implement this trait. It exposes no driver or authorization
/// capability.
pub trait AuthenticatedRoute {
    /// Snapshot the authenticated routing metadata.
    fn route_binding(&self) -> AuthenticatedSessionRouteBinding;
}

impl<C> AuthenticatedRoute for AuthenticatedComponentSession<C> {
    fn route_binding(&self) -> AuthenticatedSessionRouteBinding {
        AuthenticatedComponentSession::route_binding(self)
    }
}

impl AuthenticatedRoute for AuthenticatedSessionRouteBinding {
    fn route_binding(&self) -> AuthenticatedSessionRouteBinding {
        self.clone()
    }
}

impl ProviderSessionAdmission {
    /// Borrow the authenticated routing metadata.
    pub const fn route(&self) -> &AuthenticatedSessionRouteBinding {
        &self.route
    }

    /// Return the authenticated Provider generation.
    pub const fn provider_generation(
        &self,
    ) -> Option<d2b_contracts_resource::v3::ResourceGeneration> {
        self.route.provider_generation()
    }

    /// Return the authenticated controller generation.
    pub const fn controller_generation(
        &self,
    ) -> Option<d2b_contracts_resource::v3::ControllerGeneration> {
        self.route.controller_generation()
    }

    /// Return the authenticated ComponentSession generation.
    pub const fn reconnect_generation(
        &self,
    ) -> d2b_contracts_resource::v3::identity::ReconnectGeneration {
        self.route.reconnect_generation()
    }

    /// Admit or rejoin one operation under this exact session generation.
    ///
    /// The ledger owns operation identity and desired-generation checks; this
    /// proof supplies only the authenticated reconnect generation.
    pub fn admit_operation(
        &self,
        ledger: &mut OperationLedger,
        resource_uid: ResourceUid,
        desired_generation: ResourceGeneration,
        operation_id: OperationId,
    ) -> Result<OperationLedgerAdmission, OperationLedgerError> {
        if !self.route.liveness().is_live() {
            return Err(OperationLedgerError::SessionNotLive);
        }
        ledger.admit(
            resource_uid,
            desired_generation,
            operation_id,
            self.reconnect_generation(),
        )
    }

    /// Rebind one matching operation row to this session generation.
    pub fn rebind_operation<'a>(
        &self,
        ledger: &'a mut OperationLedger,
        resource_uid: ResourceUid,
        desired_generation: ResourceGeneration,
        operation_id: OperationId,
    ) -> Result<&'a OperationLedgerRow, OperationLedgerError> {
        if !self.route.liveness().is_live() {
            return Err(OperationLedgerError::SessionNotLive);
        }
        ledger.rebind(
            resource_uid,
            desired_generation,
            operation_id,
            self.reconnect_generation(),
        )
    }
}

impl fmt::Debug for ProviderSessionAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderSessionAdmission(REDACTED)")
    }
}

impl fmt::Debug for ProviderEntrypoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderEntrypoint")
            .field("name", &self.name)
            .field(
                "provider_ref",
                &self.provider_ref.as_ref().map(|_| "<redacted>"),
            )
            .field("service", &self.service.map(|_| "<redacted>"))
            .field("lifecycle", &self.lifecycle())
            .finish()
    }
}

impl ProviderEntrypoint {
    /// Construct a process lifecycle owner for one fixed Provider binary.
    pub fn new(name: &'static str) -> Result<Self, ProviderRuntimeError> {
        if name.is_empty() || name.len() > 128 || !name.is_ascii() {
            return Err(ProviderRuntimeError::InvalidName);
        }
        Ok(Self {
            name,
            provider_ref: None,
            execution_ref: None,
            process_ref: None,
            target_kind: None,
            provider_generation: None,
            controller_generation: None,
            service: None,
            lifecycle: AtomicU8::new(STARTING),
            state: Arc::new((
                Mutex::new(RuntimeState {
                    admitted: 0,
                    ready_route: None,
                }),
                Condvar::new(),
            )),
        })
    }

    /// Construct a target-local controller lifecycle from a signed component
    /// descriptor.
    ///
    /// The descriptor is an admission input only. This method never resolves
    /// an executable or starts a process; the fixed Process Provider and its
    /// effect adapter own that boundary.
    pub fn from_signed_controller(
        name: &'static str,
        provider_ref: ResourceRef,
        service: &'static str,
        descriptor: &ComponentDescriptor,
        target: ControllerTargetKind,
    ) -> Result<Self, ProviderRuntimeError> {
        if descriptor.component_type() != ComponentType::Controller
            || !matches!(
                descriptor.execution(),
                ComponentExecution::Launchable { .. }
            )
            || !matches!(
                target,
                ControllerTargetKind::Host | ControllerTargetKind::Guest
            )
            || !descriptor.supported_target_kinds().contains(&target)
        {
            return Err(ProviderRuntimeError::ControllerDescriptorInvalid);
        }
        let Some(capability) = descriptor.target_capability(target) else {
            return Err(ProviderRuntimeError::ControllerDescriptorInvalid);
        };
        if !capability
            .required_effect_classes()
            .contains(&EffectPortClass::Process)
            || is_zero_digest(descriptor.config_digest().as_str())
            || is_zero_digest(capability.artifact_digest().as_str())
        {
            return Err(ProviderRuntimeError::ControllerDescriptorInvalid);
        }
        let mut runtime = Self::with_provider(name, provider_ref, service)?;
        runtime.target_kind = Some(target);
        Ok(runtime)
    }

    /// Construct a lifecycle owner bound to one compiled Provider identity
    /// and service package.
    pub fn with_provider(
        name: &'static str,
        provider_ref: ResourceRef,
        service: &'static str,
    ) -> Result<Self, ProviderRuntimeError> {
        let mut runtime = Self::new(name)?;
        if provider_ref.resource_type().as_str() != "Provider" || service.is_empty() {
            return Err(ProviderRuntimeError::InvalidName);
        }
        runtime.provider_ref = Some(provider_ref);
        runtime.service = Some(service);
        Ok(runtime)
    }

    /// Bind this lifecycle owner to one exact Host or Guest execution target.
    pub fn with_execution_target(
        mut self,
        execution_ref: ResourceRef,
    ) -> Result<Self, ProviderRuntimeError> {
        let target_kind = match execution_ref.resource_type().as_str() {
            "Host" => ControllerTargetKind::Host,
            "Guest" => ControllerTargetKind::Guest,
            _ => return Err(ProviderRuntimeError::InvalidName),
        };
        if self.execution_ref.is_some()
            || self
                .target_kind
                .is_some_and(|expected| expected != target_kind)
        {
            return Err(ProviderRuntimeError::InvalidName);
        }
        self.execution_ref = Some(execution_ref);
        self.target_kind = Some(target_kind);
        Ok(self)
    }

    /// Bind this lifecycle owner to the exact controller Process identity.
    pub fn with_controller_process(
        mut self,
        process_ref: ResourceRef,
    ) -> Result<Self, ProviderRuntimeError> {
        if process_ref.resource_type().as_str() != "Process" || self.process_ref.is_some() {
            return Err(ProviderRuntimeError::InvalidName);
        }
        self.process_ref = Some(process_ref);
        Ok(self)
    }

    /// Bind this lifecycle owner to one exact Provider and controller
    /// generation.
    pub fn with_generations(
        mut self,
        provider_generation: ResourceGeneration,
        controller_generation: ControllerGeneration,
    ) -> Result<Self, ProviderRuntimeError> {
        if self.provider_generation.is_some() || self.controller_generation.is_some() {
            return Err(ProviderRuntimeError::InvalidName);
        }
        self.provider_generation = Some(provider_generation);
        self.controller_generation = Some(controller_generation);
        Ok(self)
    }

    /// Return the current process lifecycle.
    pub fn lifecycle(&self) -> ProviderLifecycle {
        ProviderLifecycle::from_u8(self.lifecycle.load(Ordering::Acquire))
    }

    /// Admit one local service registration.
    pub fn admit(&self) -> Result<ProviderAdmission, ProviderRuntimeError> {
        let (lock, _) = &*self.state;
        let mut state = lock
            .lock()
            .map_err(|_| ProviderRuntimeError::NotAccepting)?;
        // Drain takes the lifecycle transition before it waits on this lock.
        // Checking only before locking would let a registration slip into a
        // draining process after the supervisor had fenced new work.
        if self.lifecycle() != ProviderLifecycle::Starting {
            return Err(ProviderRuntimeError::NotAccepting);
        }
        state.admitted = state.admitted.saturating_add(1);
        Ok(ProviderAdmission {
            state: Arc::clone(&self.state),
        })
    }

    /// Publish process readiness after all local registrations have completed.
    ///
    /// This is kept private to the lifecycle module so an embedded Provider
    /// cannot bypass authenticated ComponentSession admission. Production
    /// callers must use [`Self::publish_authenticated_ready`].
    #[cfg(test)]
    fn publish_ready(&self) -> Result<(), ProviderRuntimeError> {
        let mut stdout = io::stdout().lock();
        self.publish_ready_to(&mut stdout)
    }

    /// Derive a route-bound session admission from an authenticated session.
    pub fn admit_authenticated<R>(
        &self,
        session: &R,
    ) -> Result<ProviderSessionAdmission, ProviderRuntimeError>
    where
        R: AuthenticatedRoute,
    {
        if self.lifecycle() != ProviderLifecycle::Starting {
            return Err(ProviderRuntimeError::NotAccepting);
        }
        let Some(expected_provider) = &self.provider_ref else {
            return Err(ProviderRuntimeError::SessionUnauthenticated);
        };
        let Some(expected_service) = self.service else {
            return Err(ProviderRuntimeError::SessionUnauthenticated);
        };
        let route = session.route_binding();
        if route.provider_ref() != Some(expected_provider)
            || route.service().as_str() != expected_service
        {
            return Err(ProviderRuntimeError::SessionUnauthenticated);
        }
        self.validate_authenticated_route(&route)?;
        Ok(ProviderSessionAdmission { route })
    }

    /// Validate redacted route evidence before assignment or readiness.
    pub fn validate_authenticated_route(
        &self,
        route: &AuthenticatedSessionRouteBinding,
    ) -> Result<(), ProviderRuntimeError> {
        if !route.liveness().is_live() || !self.route_matches_expected(route) {
            return Err(ProviderRuntimeError::SessionUnauthenticated);
        }
        Ok(())
    }

    /// Admit a reconnecting controller session without widening its
    /// Provider, subject, target, or controller-generation identity.
    pub fn admit_authenticated_reconnect<C>(
        &self,
        session: &AuthenticatedComponentSession<C>,
    ) -> Result<ProviderSessionAdmission, ProviderRuntimeError> {
        if self.lifecycle() != ProviderLifecycle::Ready {
            return Err(ProviderRuntimeError::NotAccepting);
        }
        let route = session.route_binding();
        let previous = self
            .ready_route()
            .ok_or(ProviderRuntimeError::SessionUnauthenticated)?;
        if !route.liveness().is_live()
            || !self.route_matches_expected(&route)
            || !same_controller_identity(&previous, &route)
            || route.reconnect_generation() <= previous.reconnect_generation()
        {
            return Err(ProviderRuntimeError::SessionUnauthenticated);
        }
        Ok(ProviderSessionAdmission { route })
    }

    /// Publish readiness only after both local registration and authenticated
    /// ComponentSession route admission have succeeded.
    pub fn publish_authenticated_ready<R>(
        &self,
        registration: &ProviderAdmission,
        session: ProviderSessionAdmission,
        live_session: &R,
    ) -> Result<(), ProviderRuntimeError>
    where
        R: AuthenticatedRoute,
    {
        let live_route = live_session.route_binding();
        self.validate_authenticated_ready(registration, &session, &live_route)?;
        let route = session.route.clone();
        drop(session);
        let mut stdout = io::stdout().lock();
        self.publish_ready_to(&mut stdout)?;
        let (lock, _) = &*self.state;
        let mut state = lock
            .lock()
            .map_err(|_| ProviderRuntimeError::NotAccepting)?;
        state.ready_route = Some(route);
        Ok(())
    }

    /// Return whether this controller completed authenticated readiness.
    pub fn is_controller_ready(&self) -> bool {
        self.lifecycle() == ProviderLifecycle::Ready
            && self
                .state
                .0
                .lock()
                .ok()
                .is_some_and(|state| {
                    state
                        .ready_route
                        .as_ref()
                        .is_some_and(|route| route.liveness().is_live())
                })
    }

    /// Check that assignment authority is bound to the exact ready session.
    pub fn is_ready_for_route(&self, route: &AuthenticatedSessionRouteBinding) -> bool {
        if self.lifecycle() != ProviderLifecycle::Ready {
            return false;
        }
        self.state
            .0
            .lock()
            .ok()
            .and_then(|state| state.ready_route.clone())
            .is_some_and(|ready| ready.liveness().is_live() && ready == *route)
    }

    /// Return redacted routing metadata for the current ready session.
    pub fn ready_route(&self) -> Option<AuthenticatedSessionRouteBinding> {
        if self.lifecycle() != ProviderLifecycle::Ready {
            return None;
        }
        self.state
            .0
            .lock()
            .ok()
            .and_then(|state| state.ready_route.clone())
    }

    /// Replace the retained route after Core has revoked the prior
    /// generation and admitted an authenticated reconnect.
    pub fn rebind_authenticated_route(
        &self,
        admission: ProviderSessionAdmission,
    ) -> Result<(), ProviderRuntimeError> {
        if self.lifecycle() != ProviderLifecycle::Ready
            || !self.route_matches_expected(&admission.route)
        {
            return Err(ProviderRuntimeError::SessionUnauthenticated);
        }
        let (lock, _) = &*self.state;
        let mut state = lock
            .lock()
            .map_err(|_| ProviderRuntimeError::NotAccepting)?;
        let Some(previous) = state.ready_route.as_ref() else {
            return Err(ProviderRuntimeError::SessionUnauthenticated);
        };
        if !admission.route.liveness().is_live()
            || !same_controller_identity(previous, &admission.route)
            || admission.route.reconnect_generation() <= previous.reconnect_generation()
        {
            return Err(ProviderRuntimeError::SessionUnauthenticated);
        }
        state.ready_route = Some(admission.route);
        Ok(())
    }

    fn publish_ready_to<W: Write>(&self, writer: &mut W) -> Result<(), ProviderRuntimeError> {
        let (lock, _) = &*self.state;
        let state = lock
            .lock()
            .map_err(|_| ProviderRuntimeError::NotAccepting)?;
        if state.admitted == 0 || self.lifecycle() != ProviderLifecycle::Starting {
            return Err(ProviderRuntimeError::NotAccepting);
        }
        writeln!(writer, "D2B_PROVIDER_READY {}", self.name)
            .and_then(|()| writer.flush())
            .map_err(|_| ProviderRuntimeError::ReadinessIo)?;
        self.transition_ready()
    }

    fn validate_authenticated_ready(
        &self,
        registration: &ProviderAdmission,
        session: &ProviderSessionAdmission,
        live_route: &AuthenticatedSessionRouteBinding,
    ) -> Result<(), ProviderRuntimeError> {
        let (lock, _) = &*self.state;
        let state = lock
            .lock()
            .map_err(|_| ProviderRuntimeError::NotAccepting)?;
        if !Arc::ptr_eq(&registration.state, &self.state)
            || state.admitted == 0
            || self.lifecycle() != ProviderLifecycle::Starting
            || !live_route.liveness().is_live()
            || !session.route.liveness().is_live()
            || !self.route_matches_expected(live_route)
            || session.route.reconnect_generation().get() == 0
            || session.route.controller_generation().is_none()
            || session.route != *live_route
        {
            return Err(ProviderRuntimeError::SessionUnauthenticated);
        }
        Ok(())
    }

    fn route_matches_expected(&self, route: &AuthenticatedSessionRouteBinding) -> bool {
        self.provider_ref
            .as_ref()
            .is_some_and(|expected| route.provider_ref() == Some(expected))
            && self
                .service
                .is_some_and(|expected| route.service().as_str() == expected)
            && route.provider_generation().is_some()
            && route.controller_generation().is_some()
            && route.reconnect_generation().get() != 0
            && self
                .provider_generation
                .is_none_or(|expected| route.provider_generation() == Some(expected))
            && self
                .controller_generation
                .is_none_or(|expected| route.controller_generation() == Some(expected))
            && self
                .execution_ref
                .as_ref()
                .is_none_or(|expected| route.context().execution_ref() == Some(expected))
            && self.target_kind.is_none_or(|expected| {
                route
                    .context()
                    .execution_ref()
                    .is_some_and(|reference| match expected {
                        ControllerTargetKind::Host => reference.resource_type().as_str() == "Host",
                        ControllerTargetKind::Guest => {
                            reference.resource_type().as_str() == "Guest"
                        }
                        ControllerTargetKind::Zone => false,
                    })
            })
            && self
                .process_ref
                .as_ref()
                .is_none_or(|expected| route.context().process_ref() == Some(expected))
    }

    fn transition_ready(&self) -> Result<(), ProviderRuntimeError> {
        if self
            .lifecycle
            .compare_exchange(STARTING, READY, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(ProviderRuntimeError::NotAccepting);
        }
        Ok(())
    }

    /// Stop accepting registrations and wait for local registrations to drain.
    pub fn drain(&self, timeout: Duration) -> bool {
        let (lock, idle) = &*self.state;
        let guard = lock.lock();
        let Ok(mut state) = guard else {
            return false;
        };
        let prior = self.lifecycle.swap(DRAINING, Ordering::AcqRel);
        if prior == STOPPED {
            return true;
        }
        let result = idle
            .wait_timeout_while(state, timeout, |state| state.admitted != 0)
            .ok();
        let Some((new_state, wait)) = result else {
            return false;
        };
        state = new_state;
        let drained = state.admitted == 0 && !wait.timed_out();
        if drained {
            self.lifecycle.store(STOPPED, Ordering::Release);
            state.ready_route = None;
        }
        drained
    }
}

pub(crate) fn same_controller_identity(
    left: &AuthenticatedSessionRouteBinding,
    right: &AuthenticatedSessionRouteBinding,
) -> bool {
    left.zone() == right.zone()
        && left.subject_ref() == right.subject_ref()
        && left.subject_uid() == right.subject_uid()
        && left.evidence_class() == right.evidence_class()
        && left.locality() == right.locality()
        && left.service() == right.service()
        && left.schema() == right.schema()
        && left.provider_ref() == right.provider_ref()
        && left.provider_generation() == right.provider_generation()
        && left.controller_generation() == right.controller_generation()
        && left.context().zone_ref() == right.context().zone_ref()
        && left.context().session_purpose() == right.context().session_purpose()
        && left.context().transport_binding() == right.context().transport_binding()
        && left.context().execution_ref() == right.context().execution_ref()
        && left.context().process_ref() == right.context().process_ref()
}

fn is_zero_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| !hex.is_empty() && hex.bytes().all(|byte| byte == b'0'))
}

/// One local registration held until its service is fully drained.
pub struct ProviderAdmission {
    state: Arc<(Mutex<RuntimeState>, Condvar)>,
}

impl fmt::Debug for ProviderAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderAdmission(REDACTED)")
    }
}

impl Drop for ProviderAdmission {
    fn drop(&mut self) {
        let (lock, idle) = &*self.state;
        if let Ok(mut state) = lock.lock() {
            state.admitted = state.admitted.saturating_sub(1);
            if state.admitted == 0 {
                idle.notify_all();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use d2b_contracts_provider::v3::{
        ArtifactDigest, BinaryRef, ComponentTargetCapability, EffectPortClass,
    };
    use d2b_contracts_resource::v3::execution_policy::{BoundedToken, ExecutionDomain};
    use d2b_contracts_resource::v3::identity::ResourceTypeName;
    use d2b_contracts_resource::v3::{ResourceGeneration, ResourceRef, ResourceUid};
    use d2b_contracts_zone_session::v3::component_session::OperationId;

    fn signed_controller_descriptor() -> ComponentDescriptor {
        let digest = ArtifactDigest::parse(format!("sha256:{}", "a".repeat(64))).unwrap();
        ComponentDescriptor::new(
            BoundedToken::parse("controller").unwrap(),
            ComponentType::Controller,
            [ResourceTypeName::parse("Volume").unwrap()],
            [BoundedToken::parse("reconcile").unwrap()],
            [ExecutionDomain::System],
            1,
            digest.clone(),
            [],
            false,
        )
        .unwrap()
        .with_execution(ComponentExecution::Launchable {
            binary_ref: BinaryRef::parse("controller").unwrap(),
        })
        .with_controller_placement(
            d2b_contracts_provider::v3::ControllerInstanceScope::PerResourceTarget,
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
                digest,
                [EffectPortClass::Process],
            )
            .unwrap(),
        ])
        .unwrap()
    }

    #[test]
    fn readiness_is_not_published_before_registration() {
        let runtime = ProviderEntrypoint::new("Provider/test").unwrap();
        assert_eq!(runtime.lifecycle(), ProviderLifecycle::Starting);
        let admission = runtime.admit().unwrap();
        assert!(runtime.publish_ready().is_ok());
        assert_eq!(runtime.lifecycle(), ProviderLifecycle::Ready);
        assert!(!runtime.is_controller_ready());
        drop(admission);
        assert!(runtime.drain(Duration::from_millis(10)));
        assert_eq!(runtime.lifecycle(), ProviderLifecycle::Stopped);
    }

    #[test]
    fn readiness_io_failure_does_not_enter_ready_state() {
        struct FailingWriter;

        impl Write for FailingWriter {
            fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("readiness output failed"))
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let runtime = ProviderEntrypoint::new("Provider/test").unwrap();
        let _admission = runtime.admit().unwrap();
        let mut writer = FailingWriter;
        assert_eq!(
            runtime.publish_ready_to(&mut writer),
            Err(ProviderRuntimeError::ReadinessIo)
        );
        assert_eq!(runtime.lifecycle(), ProviderLifecycle::Starting);
    }

    #[test]
    fn draining_refuses_new_registration() {
        let runtime = ProviderEntrypoint::new("Provider/test").unwrap();
        let admission = runtime.admit().unwrap();
        runtime.publish_ready().unwrap();
        assert!(!runtime.drain(Duration::from_millis(10)));
        assert_eq!(
            runtime.admit().unwrap_err().to_string(),
            "provider-runtime-not-accepting"
        );
        drop(admission);
        assert!(runtime.drain(Duration::from_millis(10)));
    }

    #[test]
    fn authenticated_readiness_requires_the_live_route_and_registration() {
        let runtime = ProviderEntrypoint::with_provider(
            "Provider/test",
            ResourceRef::parse("Provider/test").unwrap(),
            "d2b.provider.v3",
        )
        .unwrap();
        let registration = runtime.admit().unwrap();
        let route = AuthenticatedSessionRouteBinding::for_test(
            Some(ResourceRef::parse("Provider/test").unwrap()),
            "d2b.provider.v3",
            1,
            Some(1),
            Some(1),
        );
        let admission = ProviderSessionAdmission {
            route: route.clone(),
        };
        assert!(
            runtime
                .validate_authenticated_ready(&registration, &admission, &route)
                .is_ok()
        );

        let mismatched = AuthenticatedSessionRouteBinding::for_test(
            Some(ResourceRef::parse("Provider/test").unwrap()),
            "d2b.other.v3",
            1,
            Some(1),
            Some(1),
        );
        assert_eq!(
            runtime.validate_authenticated_ready(&registration, &admission, &mismatched,),
            Err(ProviderRuntimeError::SessionUnauthenticated)
        );
        let other_runtime = ProviderEntrypoint::new("Provider/other").unwrap();
        let other_registration = other_runtime.admit().unwrap();
        assert_eq!(
            runtime.validate_authenticated_ready(&other_registration, &admission, &route),
            Err(ProviderRuntimeError::SessionUnauthenticated)
        );
    }

    #[test]
    fn controller_readiness_requires_a_controller_generation() {
        let runtime = ProviderEntrypoint::with_provider(
            "Provider/test",
            ResourceRef::parse("Provider/test").unwrap(),
            "d2b.provider.v3",
        )
        .unwrap();
        let registration = runtime.admit().unwrap();
        let route = AuthenticatedSessionRouteBinding::for_test(
            Some(ResourceRef::parse("Provider/test").unwrap()),
            "d2b.provider.v3",
            1,
            Some(1),
            None,
        );
        let admission = ProviderSessionAdmission {
            route: route.clone(),
        };
        assert_eq!(
            runtime.validate_authenticated_route(&route),
            Err(ProviderRuntimeError::SessionUnauthenticated)
        );
        assert_eq!(
            runtime.validate_authenticated_ready(&registration, &admission, &route),
            Err(ProviderRuntimeError::SessionUnauthenticated)
        );
    }

    #[test]
    fn a_foreign_session_admission_cannot_publish_this_entrypoint_ready() {
        let runtime = ProviderEntrypoint::with_provider(
            "Provider/test",
            ResourceRef::parse("Provider/test").unwrap(),
            "d2b.provider.v3",
        )
        .unwrap();
        let foreign = ProviderEntrypoint::with_provider(
            "Provider/foreign",
            ResourceRef::parse("Provider/foreign").unwrap(),
            "d2b.provider.v3",
        )
        .unwrap();
        let registration = runtime.admit().unwrap();
        let foreign_registration = foreign.admit().unwrap();
        let foreign_route = AuthenticatedSessionRouteBinding::for_test(
            Some(ResourceRef::parse("Provider/foreign").unwrap()),
            "d2b.provider.v3",
            1,
            Some(1),
            Some(1),
        );
        let foreign_admission = ProviderSessionAdmission {
            route: foreign_route.clone(),
        };
        assert_eq!(
            runtime
                .validate_authenticated_ready(&registration, &foreign_admission, &foreign_route,),
            Err(ProviderRuntimeError::SessionUnauthenticated)
        );
        drop(foreign_registration);
    }

    #[test]
    fn reconnect_rebind_requires_the_same_controller_identity_and_a_new_generation() {
        let runtime = ProviderEntrypoint::with_provider(
            "Provider/test",
            ResourceRef::parse("Provider/test").unwrap(),
            "d2b.provider.v3",
        )
        .unwrap();
        let first = AuthenticatedSessionRouteBinding::for_test_dead(
            Some(ResourceRef::parse("Provider/test").unwrap()),
            "d2b.provider.v3",
            1,
            Some(1),
            Some(1),
        );
        runtime.transition_ready().unwrap();
        runtime.state.0.lock().unwrap().ready_route = Some(first.clone());

        let next = AuthenticatedSessionRouteBinding::for_test(
            Some(ResourceRef::parse("Provider/test").unwrap()),
            "d2b.provider.v3",
            2,
            Some(1),
            Some(1),
        );
        runtime
            .rebind_authenticated_route(ProviderSessionAdmission {
                route: next.clone(),
            })
            .expect("new reconnect generation");
        assert!(runtime.is_ready_for_route(&next));
        assert!(runtime.is_controller_ready());
        assert_eq!(
            runtime.rebind_authenticated_route(ProviderSessionAdmission { route: first }),
            Err(ProviderRuntimeError::SessionUnauthenticated)
        );
    }

    #[test]
    fn signed_controller_construction_rejects_non_launchable_or_unsupported_roles() {
        let descriptor = signed_controller_descriptor();
        let runtime = ProviderEntrypoint::from_signed_controller(
            "Provider/test",
            ResourceRef::parse("Provider/test").unwrap(),
            "d2b.provider.v3",
            &descriptor,
            ControllerTargetKind::Guest,
        )
        .expect("signed Guest controller");
        assert_eq!(runtime.lifecycle(), ProviderLifecycle::Starting);

        let targeted = ProviderEntrypoint::with_provider(
            "Provider/test",
            ResourceRef::parse("Provider/test").unwrap(),
            "d2b.provider.v3",
        )
        .unwrap()
        .with_execution_target(ResourceRef::parse("Guest/dev-vm").unwrap())
        .unwrap();
        let host_route = AuthenticatedSessionRouteBinding::for_test(
            Some(ResourceRef::parse("Provider/test").unwrap()),
            "d2b.provider.v3",
            1,
            Some(1),
            Some(1),
        );
        assert_eq!(
            runtime.validate_authenticated_route(&host_route),
            Err(ProviderRuntimeError::SessionUnauthenticated)
        );
        assert_eq!(
            targeted.validate_authenticated_route(&host_route),
            Err(ProviderRuntimeError::SessionUnauthenticated)
        );
        let generation_bound = ProviderEntrypoint::with_provider(
            "Provider/test",
            ResourceRef::parse("Provider/test").unwrap(),
            "d2b.provider.v3",
        )
        .unwrap()
        .with_generations(
            ResourceGeneration::new(2).unwrap(),
            ControllerGeneration::new(2).unwrap(),
        )
        .unwrap();
        assert_eq!(
            generation_bound.validate_authenticated_route(&host_route),
            Err(ProviderRuntimeError::SessionUnauthenticated)
        );
        let process_bound = ProviderEntrypoint::with_provider(
            "Provider/test",
            ResourceRef::parse("Provider/test").unwrap(),
            "d2b.provider.v3",
        )
        .unwrap()
        .with_controller_process(ResourceRef::parse("Process/controller").unwrap())
        .unwrap();
        assert_eq!(
            process_bound.validate_authenticated_route(&host_route),
            Err(ProviderRuntimeError::SessionUnauthenticated)
        );

        let invalid_target = ProviderEntrypoint::from_signed_controller(
            "Provider/test",
            ResourceRef::parse("Provider/test").unwrap(),
            "d2b.provider.v3",
            &descriptor,
            ControllerTargetKind::Zone,
        );
        assert!(matches!(
            invalid_target,
            Err(ProviderRuntimeError::ControllerDescriptorInvalid)
        ));

        let in_process = ComponentDescriptor::new(
            BoundedToken::parse("controller").unwrap(),
            ComponentType::Controller,
            [ResourceTypeName::parse("Volume").unwrap()],
            [BoundedToken::parse("reconcile").unwrap()],
            [ExecutionDomain::System],
            1,
            ArtifactDigest::parse(format!("sha256:{}", "b".repeat(64))).unwrap(),
            [],
            false,
        )
        .unwrap();
        assert!(matches!(
            ProviderEntrypoint::from_signed_controller(
                "Provider/test",
                ResourceRef::parse("Provider/test").unwrap(),
                "d2b.provider.v3",
                &in_process,
                ControllerTargetKind::Guest,
            ),
            Err(ProviderRuntimeError::ControllerDescriptorInvalid)
        ));
    }

    #[test]
    fn session_admission_rejoins_a_matching_operation_row() {
        let route = AuthenticatedSessionRouteBinding::for_test(
            Some(ResourceRef::parse("Provider/test").unwrap()),
            "d2b.provider.v3",
            4,
            Some(1),
            Some(1),
        );
        let admission = ProviderSessionAdmission { route };
        let mut ledger = OperationLedger::new();
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let operation = OperationId::new(vec![0x55; 16]).unwrap();
        let desired = ResourceGeneration::new(3).unwrap();

        assert_eq!(
            admission.admit_operation(&mut ledger, uid.clone(), desired, operation.clone()),
            Ok(OperationLedgerAdmission::New)
        );
        assert_eq!(
            admission.admit_operation(&mut ledger, uid.clone(), desired, operation.clone()),
            Ok(OperationLedgerAdmission::Existing)
        );
        let next = AuthenticatedSessionRouteBinding::for_test(
            Some(ResourceRef::parse("Provider/test").unwrap()),
            "d2b.provider.v3",
            5,
            Some(1),
            Some(1),
        );
        let next_admission = ProviderSessionAdmission { route: next };
        let row = next_admission
            .rebind_operation(&mut ledger, uid, desired, operation)
            .expect("new session generation rebinds the matching row");
        assert_eq!(row.session_generation().get(), 5);
    }

    #[test]
    fn dead_session_route_cannot_admit_or_rebind_an_operation() {
        let live_route = AuthenticatedSessionRouteBinding::for_test(
            Some(ResourceRef::parse("Provider/test").unwrap()),
            "d2b.provider.v3",
            4,
            Some(1),
            Some(1),
        );
        let live_admission = ProviderSessionAdmission { route: live_route };
        let mut ledger = OperationLedger::new();
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let operation = OperationId::new(vec![0x66; 16]).unwrap();
        let desired = ResourceGeneration::new(3).unwrap();

        assert_eq!(
            live_admission.admit_operation(
                &mut ledger,
                uid.clone(),
                desired,
                operation.clone(),
            ),
            Ok(OperationLedgerAdmission::New)
        );

        let dead_route = AuthenticatedSessionRouteBinding::for_test_dead(
            Some(ResourceRef::parse("Provider/test").unwrap()),
            "d2b.provider.v3",
            5,
            Some(1),
            Some(1),
        );
        let dead_admission = ProviderSessionAdmission { route: dead_route };
        assert_eq!(
            dead_admission.admit_operation(
                &mut ledger,
                uid.clone(),
                desired,
                operation.clone(),
            ),
            Err(OperationLedgerError::SessionNotLive)
        );
        assert_eq!(
            dead_admission.rebind_operation(&mut ledger, uid, desired, operation),
            Err(OperationLedgerError::SessionNotLive)
        );
        assert_eq!(
            ledger
                .row(&OperationId::new(vec![0x66; 16]).unwrap())
                .expect("original operation row remains")
                .session_generation()
                .get(),
            4
        );
    }
}
