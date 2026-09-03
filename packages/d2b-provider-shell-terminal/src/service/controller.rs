//! Pool/session controller lifecycle backed by daemon-owned authority.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use crate::{
    Authorizer, ShellPool, ShellSession, ShellTerminalError, Subject,
    resources::validate_name,
    service::supervisor::{Attachment, SessionCapability, SessionSupervisor, ShellAuthorityPort},
    session::{AdoptionDecision, SupervisorCandidate, SupervisorIdentity, adopt_supervisor},
};

/// Default shared-Runner repair interval for shell resources.
pub const SHELL_REPAIR_INTERVAL_SECS: u64 = 30;
/// Exact finalizer for shell pools.
pub const SHELL_POOL_FINALIZER: &str = "shell-terminal.d2bus.org/pool-finalizer";
/// Exact finalizer for shell sessions.
pub const SHELL_SESSION_FINALIZER: &str = "shell-terminal.d2bus.org/session-finalizer";

/// The cutover contract for ShellPool and ShellSession owners.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShellRunnerContract {
    pool_resource_type: &'static str,
    session_resource_type: &'static str,
    pool_finalizer: &'static str,
    session_finalizer: &'static str,
    repair_interval_secs: u64,
    watched_configuration_is_dependency: bool,
}

impl ShellRunnerContract {
    /// Return the ShellPool ResourceType.
    pub const fn pool_resource_type(self) -> &'static str {
        self.pool_resource_type
    }

    /// Return the ShellSession ResourceType.
    pub const fn session_resource_type(self) -> &'static str {
        self.session_resource_type
    }

    /// Return the ShellPool finalizer.
    pub const fn pool_finalizer(self) -> &'static str {
        self.pool_finalizer
    }

    /// Return the ShellSession finalizer.
    pub const fn session_finalizer(self) -> &'static str {
        self.session_finalizer
    }

    /// Return the bounded repair interval.
    pub const fn repair_interval_secs(self) -> u64 {
        self.repair_interval_secs
    }

    /// Whether legacy shell scheduling is disabled.

    /// Whether watched configuration is dependency-only.
    pub const fn watched_configuration_is_dependency(self) -> bool {
        self.watched_configuration_is_dependency
    }
}

/// Return the shared-Runner contract for shell-terminal.
pub const fn shell_runner_contract() -> ShellRunnerContract {
    ShellRunnerContract {
        pool_resource_type: "shell-terminal.d2bus.org.ShellPool",
        session_resource_type: "shell-terminal.d2bus.org.ShellSession",
        pool_finalizer: SHELL_POOL_FINALIZER,
        session_finalizer: SHELL_SESSION_FINALIZER,
        repair_interval_secs: SHELL_REPAIR_INTERVAL_SECS,
        watched_configuration_is_dependency: true,
    }
}

/// A validated request to create one pool-derived shell session.
#[derive(Clone, PartialEq, Eq)]
pub struct OpenSessionRequest {
    pool_name: String,
    session_name: String,
    output_ring_capacity: Option<u64>,
}

impl std::fmt::Debug for OpenSessionRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OpenSessionRequest(<redacted>)")
    }
}

impl OpenSessionRequest {
    /// Construct a bounded session request.
    pub fn new(
        pool_name: impl Into<String>,
        session_name: impl Into<String>,
        output_ring_capacity: Option<u64>,
    ) -> Result<Self, ShellTerminalError> {
        let pool_name = pool_name.into();
        let session_name = session_name.into();
        validate_name(&pool_name, 63)?;
        validate_name(&session_name, 32)?;
        Ok(Self {
            pool_name,
            session_name,
            output_ring_capacity,
        })
    }
}

/// A controller response carrying a session, its generation, and a one-shot capability.
#[derive(Clone)]
pub struct OpenSessionResult {
    session: ShellSession,
    supervisor_generation: u64,
    capability: SessionCapability,
    authority: Arc<dyn ShellAuthorityPort>,
}

impl std::fmt::Debug for OpenSessionResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpenSessionResult")
            .field("supervisor_generation", &self.supervisor_generation)
            .finish_non_exhaustive()
    }
}

impl OpenSessionResult {
    /// Borrow the newly-created session.
    pub const fn session(&self) -> &ShellSession {
        &self.session
    }

    /// Return the generation required by every supervisor request.
    pub const fn supervisor_generation(&self) -> u64 {
        self.supervisor_generation
    }

    /// Return the current request's one-shot supervisor capability.
    pub fn capability(&self) -> SessionCapability {
        self.capability.clone()
    }

    /// Build a supervisor after the process adapter proves identity.
    pub fn start_supervisor(
        &self,
        identity: SupervisorIdentity,
    ) -> Result<SessionSupervisor, ShellTerminalError> {
        if identity.generation() != self.supervisor_generation {
            return Err(ShellTerminalError::StaleSessionGeneration);
        }
        self.authority.ensure_supervisor_process(&self.session)?;
        self.authority.claim_supervisor(&self.session, &identity)?;
        Ok(SessionSupervisor::new(
            self.session.clone(),
            identity,
            Arc::clone(&self.authority),
        ))
    }
}

/// Bounded controller projection reconstructed from resource objects on restart.
pub struct ShellTerminalController {
    pools: BTreeMap<String, ShellPool>,
    sessions: BTreeMap<String, ShellSession>,
    trusted_sessions: BTreeSet<String>,
    authority: Arc<dyn ShellAuthorityPort>,
}

impl std::fmt::Debug for ShellTerminalController {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ShellTerminalController")
            .field("pool_count", &self.pools.len())
            .field("session_count", &self.sessions.len())
            .finish()
    }
}

impl ShellTerminalController {
    /// Bind the controller to the daemon-owned authority client.
    pub fn new(authority: Arc<dyn ShellAuthorityPort>) -> Self {
        Self {
            pools: BTreeMap::new(),
            sessions: BTreeMap::new(),
            trusted_sessions: BTreeSet::new(),
            authority,
        }
    }

    /// Insert a reconciled pool into the bounded controller projection.
    pub fn insert_pool(&mut self, pool: ShellPool) -> Result<(), ShellTerminalError> {
        self.restore_pool(pool, 0)
    }

    /// Restore a pool with the authoritative count of adopted attachments.
    ///
    /// Restored occupancy blocks new streams until the next status reconcile
    /// proves capacity. This intentionally favors refusal over potentially
    /// exceeding a pool's attachment limit after controller restart.
    pub fn restore_pool(
        &mut self,
        pool: ShellPool,
        attached_streams: u32,
    ) -> Result<(), ShellTerminalError> {
        if self.pools.contains_key(pool.name()) {
            return Err(ShellTerminalError::CapacityExceeded);
        }
        self.authority.restore_pool(&pool, attached_streams)?;
        self.pools.insert(pool.name().to_owned(), pool);
        Ok(())
    }

    /// Update remote occupancy without invalidating locally tracked streams.
    pub fn reconcile_pool_attachments(
        &self,
        pool_name: &str,
        attached_streams: u32,
    ) -> Result<(), ShellTerminalError> {
        self.authority.reconcile_pool_attachments(
            self.pools
                .get(pool_name)
                .ok_or(ShellTerminalError::CapacityExceeded)?,
            attached_streams,
        )
    }

    /// Retire attachment handles proved stale by the authoritative stream census.
    pub fn retire_pool_attachments(
        &self,
        pool_name: &str,
        stale_attachments: &[Attachment],
        attached_streams: u32,
    ) -> Result<(), ShellTerminalError> {
        self.authority.retire_proven_stale(
            self.pools
                .get(pool_name)
                .ok_or(ShellTerminalError::CapacityExceeded)?,
            stale_attachments,
            attached_streams,
        )
    }

    /// Restore a reconciled session before the controller admits new sessions.
    ///
    /// The session remains counted for capacity even when the supervisor is
    /// missing or ambiguous, preventing a restart from recreating a resource
    /// name while its earlier process may still exist.
    pub fn restore_session(
        &mut self,
        session: ShellSession,
        expected_identity: &SupervisorIdentity,
        candidates: &[SupervisorCandidate],
    ) -> Result<AdoptionDecision, ShellTerminalError> {
        if !self.pools.contains_key(session.pool_name())
            || self.sessions.contains_key(session.name())
        {
            return Err(ShellTerminalError::CapacityExceeded);
        }
        let decision = adopt_supervisor(session.name(), expected_identity, candidates);
        let authority_trusted = decision == AdoptionDecision::Adopted
            && self
                .authority
                .verify_recovery(&session, expected_identity)?;
        let decision = if decision == AdoptionDecision::Adopted && !authority_trusted {
            AdoptionDecision::Ambiguous
        } else {
            decision
        };
        if decision == AdoptionDecision::Adopted {
            self.trusted_sessions.insert(session.name().to_owned());
        }
        self.sessions.insert(session.name().to_owned(), session);
        Ok(decision)
    }

    /// Advance one reconciled session after its prior supervisor is retired.
    pub fn restart_supervisor(
        &mut self,
        subject: &Subject,
        session_name: &str,
        retiring_identity: Option<&SupervisorIdentity>,
    ) -> Result<OpenSessionResult, ShellTerminalError> {
        Authorizer::authorize_request(subject)?;
        let session = self
            .sessions
            .get(session_name)
            .cloned()
            .ok_or(ShellTerminalError::CapacityExceeded)?;
        let pool = self
            .pools
            .get(session.pool_name())
            .ok_or(ShellTerminalError::CapacityExceeded)?;
        Authorizer::authorize(subject, pool)?;
        if !self.trusted_sessions.contains(session_name) {
            return Err(ShellTerminalError::SupervisorAmbiguous);
        }
        let grant = self
            .authority
            .advance_session(&session, retiring_identity)?;
        self.authority.ensure_supervisor_process(&session)?;
        let supervisor_generation = grant.generation();
        let capability = grant.capability();
        Ok(OpenSessionResult {
            session,
            supervisor_generation,
            capability,
            authority: Arc::clone(&self.authority),
        })
    }

    /// Create a session after authorizing the current request and enforcing pool capacity.
    pub fn open_session(
        &mut self,
        subject: &Subject,
        request: OpenSessionRequest,
    ) -> Result<OpenSessionResult, ShellTerminalError> {
        Authorizer::authorize_request(subject)?;
        let pool = self
            .pools
            .get(&request.pool_name)
            .ok_or(ShellTerminalError::CapacityExceeded)?;
        Authorizer::authorize(subject, pool)?;
        if self.session_count(pool.name()) >= pool.active_session_capacity() {
            return Err(ShellTerminalError::CapacityExceeded);
        }
        let resource_name = format!("{}-{}", pool.name(), request.session_name);
        if self.sessions.contains_key(&resource_name) {
            return Err(ShellTerminalError::CapacityExceeded);
        }
        let session = ShellSession::from_pool(
            pool,
            resource_name.clone(),
            request.session_name,
            request.output_ring_capacity,
        )?;
        let grant = self.authority.open_session(&session)?;
        if let Err(error) = self.authority.ensure_supervisor_process(&session) {
            let _ = self.authority.finalize_session(&session, None);
            return Err(error);
        }
        let supervisor_generation = grant.generation();
        let capability = grant.capability();
        let result = OpenSessionResult {
            session: session.clone(),
            supervisor_generation,
            capability,
            authority: Arc::clone(&self.authority),
        };
        self.trusted_sessions.insert(resource_name.clone());
        self.sessions.insert(resource_name, session);
        Ok(result)
    }

    /// Return the number of sessions belonging to one pool.
    pub fn session_count(&self, pool_name: &str) -> u32 {
        self.sessions
            .values()
            .filter(|session| session.pool_name() == pool_name)
            .count()
            .try_into()
            .unwrap_or(u32::MAX)
    }

    /// Return whether the Provider correctly declares no persistent state set.
    pub const fn provider_state_is_empty(&self) -> bool {
        true
    }

    /// Finalize one session after its owned supervisor has stopped.
    pub fn finalize_session(
        &mut self,
        subject: &Subject,
        session_name: &str,
        identity: Option<&SupervisorIdentity>,
    ) -> Result<(), ShellTerminalError> {
        Authorizer::authorize_request(subject)?;
        let session = self
            .sessions
            .get(session_name)
            .cloned()
            .ok_or(ShellTerminalError::CapacityExceeded)?;
        let pool = self
            .pools
            .get(session.pool_name())
            .ok_or(ShellTerminalError::CapacityExceeded)?;
        Authorizer::authorize(subject, pool)?;
        self.authority.remove_supervisor_process(&session)?;
        self.authority.finalize_session(&session, identity)?;
        self.sessions.remove(session_name);
        self.trusted_sessions.remove(session_name);
        Ok(())
    }
}
