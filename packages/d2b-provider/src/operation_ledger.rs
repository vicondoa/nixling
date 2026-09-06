//! Session-aware Provider operation ledger.
//!
//! The ledger keeps effect identity separate from the reconnect generation.
//! A reconnect may rebind a matching row, but it may never turn an existing
//! operation ID into a second acceptance or change its desired generation.

use std::collections::BTreeMap;

use d2b_contracts_resource::v3::{ResourceGeneration, ResourceUid, identity::ReconnectGeneration};
use d2b_contracts_zone_session::v3::component_session::OperationId;

/// Maximum retained Provider operation rows.
pub const MAX_OPERATION_LEDGER_ROWS: usize = 4_096;

/// Durable state of one Provider operation row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OperationLedgerState {
    /// The operation was durably accepted but has not started.
    Accepted,
    /// The operation is currently being executed.
    Running,
    /// Execution outcome is ambiguous and requires observation or quarantine.
    Uncertain,
    /// Execution completed successfully.
    Completed,
    /// Execution reached a terminal failure.
    Failed,
}

impl OperationLedgerState {
    fn can_transition_to(self, next: Self) -> bool {
        match self {
            Self::Accepted => matches!(
                next,
                Self::Accepted | Self::Running | Self::Uncertain | Self::Completed | Self::Failed
            ),
            Self::Running => matches!(
                next,
                Self::Running | Self::Uncertain | Self::Completed | Self::Failed
            ),
            Self::Uncertain => matches!(
                next,
                Self::Uncertain | Self::Running | Self::Completed | Self::Failed
            ),
            Self::Completed | Self::Failed => next == self,
        }
    }
}

/// Why an operation could not be admitted or rebound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationLedgerError {
    /// The bounded ledger has no free row.
    CapacityExceeded,
    /// The operation ID was previously used for another resource identity.
    OperationIdReplay,
    /// The operation ID was previously bound to another desired generation.
    DesiredGenerationMismatch,
    /// A request used an older reconnect generation than the retained row.
    StaleSessionGeneration,
    /// A terminal row was asked to move to another state.
    InvalidStateTransition,
    /// A requested reconnect generation was zero.
    InvalidSessionGeneration,
    /// The authenticated session route owner is no longer live.
    SessionNotLive,
}

impl core::fmt::Display for OperationLedgerError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::CapacityExceeded => "provider-operation-ledger-capacity-exceeded",
            Self::OperationIdReplay => "provider-operation-id-replayed",
            Self::DesiredGenerationMismatch => "provider-operation-desired-generation-mismatch",
            Self::StaleSessionGeneration => "provider-operation-session-generation-stale",
            Self::InvalidStateTransition => "provider-operation-state-transition-invalid",
            Self::InvalidSessionGeneration => "provider-operation-session-generation-invalid",
            Self::SessionNotLive => "provider-operation-session-not-live",
        })
    }
}

impl std::error::Error for OperationLedgerError {}

/// Whether an admission created a row or rejoined an existing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationLedgerAdmission {
    /// A new operation row was inserted.
    New,
    /// An exact existing row was retained and, when newer, rebound.
    Existing,
}

/// One operation row retained across reconnect generations.
#[derive(Clone, PartialEq, Eq)]
pub struct OperationLedgerRow {
    resource_uid: ResourceUid,
    desired_generation: ResourceGeneration,
    operation_id: OperationId,
    session_generation: ReconnectGeneration,
    state: OperationLedgerState,
}

impl OperationLedgerRow {
    /// Borrow the exact resource UID.
    pub const fn resource_uid(&self) -> &ResourceUid {
        &self.resource_uid
    }

    /// Return the desired resource generation.
    pub const fn desired_generation(&self) -> ResourceGeneration {
        self.desired_generation
    }

    /// Borrow the operation ID.
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Return the reconnect generation currently bound to the row.
    pub const fn session_generation(&self) -> ReconnectGeneration {
        self.session_generation
    }

    /// Return the durable operation state.
    pub const fn state(&self) -> OperationLedgerState {
        self.state
    }
}

impl core::fmt::Debug for OperationLedgerRow {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("OperationLedgerRow")
            .field("resource_uid", &"<redacted>")
            .field("desired_generation", &self.desired_generation)
            .field("operation_id", &"<redacted>")
            .field("session_generation", &self.session_generation)
            .field("state", &self.state)
            .finish()
    }
}

/// Bounded Provider operation identity and reconnect ledger.
#[derive(Clone)]
pub struct OperationLedger {
    rows: BTreeMap<OperationId, OperationLedgerRow>,
    latest_session_by_uid: BTreeMap<ResourceUid, ReconnectGeneration>,
    capacity: usize,
}

impl Default for OperationLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for OperationLedger {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("OperationLedger")
            .field("row_count", &self.rows.len())
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl OperationLedger {
    /// Construct a ledger at the fixed row bound.
    pub fn new() -> Self {
        Self {
            rows: BTreeMap::new(),
            latest_session_by_uid: BTreeMap::new(),
            capacity: MAX_OPERATION_LEDGER_ROWS,
        }
    }

    /// Construct a ledger with a test or owner-local bound.
    pub fn with_capacity(capacity: usize) -> Result<Self, OperationLedgerError> {
        if capacity == 0 || capacity > MAX_OPERATION_LEDGER_ROWS {
            return Err(OperationLedgerError::CapacityExceeded);
        }
        Ok(Self {
            rows: BTreeMap::new(),
            latest_session_by_uid: BTreeMap::new(),
            capacity,
        })
    }

    /// Admit a new operation or rejoin its exact existing row.
    ///
    /// Rejoining with a newer session generation updates only the reconnect
    /// binding. Resource identity, desired generation, operation ID, and
    /// durable state remain unchanged.
    pub fn admit(
        &mut self,
        resource_uid: ResourceUid,
        desired_generation: ResourceGeneration,
        operation_id: OperationId,
        session_generation: ReconnectGeneration,
    ) -> Result<OperationLedgerAdmission, OperationLedgerError> {
        if session_generation.get() == 0 {
            return Err(OperationLedgerError::InvalidSessionGeneration);
        }
        if self
            .latest_session_by_uid
            .get(&resource_uid)
            .is_some_and(|latest| session_generation < *latest)
        {
            return Err(OperationLedgerError::StaleSessionGeneration);
        }
        if let Some(row) = self.rows.get_mut(&operation_id) {
            if row.resource_uid != resource_uid {
                return Err(OperationLedgerError::OperationIdReplay);
            }
            if row.desired_generation != desired_generation {
                return Err(OperationLedgerError::DesiredGenerationMismatch);
            }
            if session_generation < row.session_generation {
                return Err(OperationLedgerError::StaleSessionGeneration);
            }
            if session_generation > row.session_generation {
                row.session_generation = session_generation;
            }
            self.latest_session_by_uid
                .insert(resource_uid, session_generation);
            return Ok(OperationLedgerAdmission::Existing);
        }
        if self.rows.len() >= self.capacity {
            return Err(OperationLedgerError::CapacityExceeded);
        }
        self.latest_session_by_uid
            .insert(resource_uid.clone(), session_generation);
        self.rows.insert(
            operation_id.clone(),
            OperationLedgerRow {
                resource_uid,
                desired_generation,
                operation_id,
                session_generation,
                state: OperationLedgerState::Accepted,
            },
        );
        Ok(OperationLedgerAdmission::New)
    }

    /// Rebind one exact row to a newer session generation.
    pub fn rebind(
        &mut self,
        resource_uid: ResourceUid,
        desired_generation: ResourceGeneration,
        operation_id: OperationId,
        session_generation: ReconnectGeneration,
    ) -> Result<&OperationLedgerRow, OperationLedgerError> {
        if !self.rows.contains_key(&operation_id) {
            return Err(OperationLedgerError::OperationIdReplay);
        }
        self.admit(
            resource_uid,
            desired_generation,
            operation_id.clone(),
            session_generation,
        )?;
        self.rows
            .get(&operation_id)
            .ok_or(OperationLedgerError::OperationIdReplay)
    }

    /// Record a monotonic state transition for an exact operation row.
    pub fn transition(
        &mut self,
        resource_uid: &ResourceUid,
        desired_generation: ResourceGeneration,
        operation_id: &OperationId,
        session_generation: ReconnectGeneration,
        state: OperationLedgerState,
    ) -> Result<(), OperationLedgerError> {
        if self
            .latest_session_by_uid
            .get(resource_uid)
            .is_some_and(|latest| session_generation < *latest)
        {
            return Err(OperationLedgerError::StaleSessionGeneration);
        }
        let row = self
            .rows
            .get_mut(operation_id)
            .ok_or(OperationLedgerError::OperationIdReplay)?;
        if &row.resource_uid != resource_uid {
            return Err(OperationLedgerError::OperationIdReplay);
        }
        if row.desired_generation != desired_generation {
            return Err(OperationLedgerError::DesiredGenerationMismatch);
        }
        if session_generation < row.session_generation {
            return Err(OperationLedgerError::StaleSessionGeneration);
        }
        if !row.state.can_transition_to(state) {
            return Err(OperationLedgerError::InvalidStateTransition);
        }
        row.session_generation = session_generation;
        row.state = state;
        self.latest_session_by_uid
            .insert(resource_uid.clone(), session_generation);
        Ok(())
    }

    /// Borrow one operation row by its opaque ID.
    pub fn row(&self, operation_id: &OperationId) -> Option<&OperationLedgerRow> {
        self.rows.get(operation_id)
    }

    /// Return all retained rows in operation-ID order.
    pub fn rows(&self) -> impl Iterator<Item = &OperationLedgerRow> {
        self.rows.values()
    }

    /// Return the current row count.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether no rows are retained.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}
