//! Fixed isolated-handler catalog and aggregate health policy.

use std::collections::BTreeMap;

use d2b_contracts_resource::v3::resource_status::MAX_STATUS_COLLECTION_ENTRIES;
use d2b_contracts_resource::v3::{ResourceCurrencySet, ResourceRef, UpdateState};
use d2b_contracts_resource::v3::quota::QUOTA_DRAIN_FINALIZER;
use d2b_contracts_zone_session::v3::{
    EMERGENCY_DRAIN_FINALIZER, RESOURCE_EXPORT_DRAIN_FINALIZER,
    RESOURCE_IMPORT_DRAIN_FINALIZER, ZONE_LINK_DRAIN_FINALIZER,
};
use d2b_contracts_zone_session::v3::role::ROLE_BINDING_DRAIN_FINALIZER;

/// The Core finalizer used while Provider API bindings are withdrawn.
pub const CORE_PROVIDER_API_BINDING_FINALIZER: &str = "core.provider-api-binding";

/// Closed fixed core handler set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CoreHandlerKind {
    Configuration,
    ApiCatalog,
    Authorization,
    Provider,
    ControllerRegistration,
    Ownership,
    Watches,
    Cleanup,
    ZoneLinks,
    Budgets,
    Store,
}

impl CoreHandlerKind {
    /// Every fixed handler in deterministic order.
    pub const ALL: [Self; 11] = [
        Self::Configuration,
        Self::ApiCatalog,
        Self::Authorization,
        Self::Provider,
        Self::ControllerRegistration,
        Self::Ownership,
        Self::Watches,
        Self::Cleanup,
        Self::ZoneLinks,
        Self::Budgets,
        Self::Store,
    ];

    /// Whether this handler must be current before aggregate readiness.
    pub const fn mandatory(self) -> bool {
        matches!(
            self,
            Self::Configuration
                | Self::ApiCatalog
                | Self::Authorization
                | Self::Provider
                | Self::ControllerRegistration
                | Self::Ownership
                | Self::Store
        )
    }

    /// Return the fixed metric label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Configuration => "configuration",
            Self::ApiCatalog => "api-catalog",
            Self::Authorization => "authorization",
            Self::Provider => "provider",
            Self::ControllerRegistration => "controller-registration",
            Self::Ownership => "ownership",
            Self::Watches => "watches",
            Self::Cleanup => "cleanup",
            Self::ZoneLinks => "zone-links",
            Self::Budgets => "budgets",
            Self::Store => "store",
        }
    }

}

/// One fixed ResourceType owner hosted by the Core controller process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreResourceControllerRegistration {
    handler: CoreHandlerKind,
    resource_type: &'static str,
    finalizer: Option<&'static str>,
    consumes_owner_triggers: bool,
}

impl CoreResourceControllerRegistration {
    /// Return the Core handler that owns this ResourceType.
    pub const fn handler(self) -> CoreHandlerKind {
        self.handler
    }

    /// Return the canonical ResourceType spelling.
    pub const fn resource_type(self) -> &'static str {
        self.resource_type
    }

    /// Return the exact Core finalizer, when this ResourceType has one.
    pub const fn finalizer(self) -> Option<&'static str> {
        self.finalizer
    }

    /// Whether owner-child changes are delivered to this controller.
    pub const fn consumes_owner_triggers(self) -> bool {
        self.consumes_owner_triggers
    }
}

/// The closed ResourceType owner set hosted by the fixed Core process.
pub const CORE_RESOURCE_CONTROLLER_REGISTRATIONS: [CoreResourceControllerRegistration; 9] = [
    CoreResourceControllerRegistration {
        handler: CoreHandlerKind::Configuration,
        resource_type: "Zone",
        finalizer: None,
        consumes_owner_triggers: false,
    },
    CoreResourceControllerRegistration {
        handler: CoreHandlerKind::ZoneLinks,
        resource_type: "ZoneLink",
        finalizer: Some(ZONE_LINK_DRAIN_FINALIZER),
        consumes_owner_triggers: false,
    },
    CoreResourceControllerRegistration {
        handler: CoreHandlerKind::Provider,
        resource_type: "Provider",
        finalizer: Some(CORE_PROVIDER_API_BINDING_FINALIZER),
        consumes_owner_triggers: true,
    },
    CoreResourceControllerRegistration {
        handler: CoreHandlerKind::Authorization,
        resource_type: "Role",
        finalizer: None,
        consumes_owner_triggers: false,
    },
    CoreResourceControllerRegistration {
        handler: CoreHandlerKind::Authorization,
        resource_type: "RoleBinding",
        finalizer: Some(ROLE_BINDING_DRAIN_FINALIZER),
        consumes_owner_triggers: false,
    },
    CoreResourceControllerRegistration {
        handler: CoreHandlerKind::Budgets,
        resource_type: "Quota",
        finalizer: Some(QUOTA_DRAIN_FINALIZER),
        consumes_owner_triggers: false,
    },
    CoreResourceControllerRegistration {
        handler: CoreHandlerKind::Budgets,
        resource_type: "EmergencyPolicy",
        finalizer: Some(EMERGENCY_DRAIN_FINALIZER),
        consumes_owner_triggers: false,
    },
    CoreResourceControllerRegistration {
        handler: CoreHandlerKind::Ownership,
        resource_type: "ResourceExport",
        finalizer: Some(RESOURCE_EXPORT_DRAIN_FINALIZER),
        consumes_owner_triggers: true,
    },
    CoreResourceControllerRegistration {
        handler: CoreHandlerKind::Ownership,
        resource_type: "ResourceImport",
        finalizer: Some(RESOURCE_IMPORT_DRAIN_FINALIZER),
        consumes_owner_triggers: true,
    },
];

/// Closed handler phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandlerPhase {
    Pending,
    Recovering,
    Ready,
    Degraded,
    Failed,
    Unknown,
}

impl HandlerPhase {
    /// Return the fixed metric label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Recovering => "recovering",
            Self::Ready => "ready",
            Self::Degraded => "degraded",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
        }
    }
}

/// Closed stable handler outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandlerOutcome {
    None,
    Converged,
    Backpressure,
    Recovering,
    Refused,
    Failed,
    Ambiguous,
}

impl HandlerOutcome {
    /// Return the fixed metric label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Converged => "converged",
            Self::Backpressure => "backpressure",
            Self::Recovering => "recovering",
            Self::Refused => "refused",
            Self::Failed => "failed",
            Self::Ambiguous => "ambiguous",
        }
    }
}

/// Cardinality-safe metric label keys for handler metrics.
pub const CORE_HANDLER_METRIC_LABEL_KEYS: &[&str] = &["handler", "phase", "outcome"];

/// Bounded currency projection for one resource and its graph edges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrencyAggregation {
    self_state: UpdateState,
    owned: ResourceCurrencySet,
    dependencies: ResourceCurrencySet,
}

impl CurrencyAggregation {
    /// Return the resource's own currency.
    pub const fn self_state(&self) -> UpdateState {
        self.self_state
    }

    /// Borrow the bounded out-of-date owned-resource aggregate.
    pub const fn owned(&self) -> &ResourceCurrencySet {
        &self.owned
    }

    /// Borrow the bounded out-of-date dependency aggregate.
    pub const fn dependencies(&self) -> &ResourceCurrencySet {
        &self.dependencies
    }

    /// Aggregate non-current graph members with deterministic truncation.
    pub fn aggregate(
        self_state: UpdateState,
        owned: impl IntoIterator<Item = (ResourceRef, UpdateState)>,
        dependencies: impl IntoIterator<Item = (ResourceRef, UpdateState)>,
    ) -> Result<Self, CurrencyAggregationError> {
        Ok(Self {
            self_state,
            owned: aggregate_currency(owned)?,
            dependencies: aggregate_currency(dependencies)?,
        })
    }
}

fn aggregate_currency(
    entries: impl IntoIterator<Item = (ResourceRef, UpdateState)>,
) -> Result<ResourceCurrencySet, CurrencyAggregationError> {
    let mut refs = entries
        .into_iter()
        .filter_map(|(resource_ref, state)| (state != UpdateState::Current).then_some(resource_ref))
        .collect::<Vec<_>>();
    refs.sort();
    let count = u64::try_from(refs.len()).map_err(|_| CurrencyAggregationError)?;
    refs.dedup();
    if refs.len() as u64 != count {
        return Err(CurrencyAggregationError);
    }
    refs.truncate(MAX_STATUS_COLLECTION_ENTRIES);
    ResourceCurrencySet::new(count, refs).map_err(|_| CurrencyAggregationError)
}

/// Invalid currency aggregation input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CurrencyAggregationError;

impl core::fmt::Display for CurrencyAggregationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("controller-currency-aggregation-invalid")
    }
}

impl std::error::Error for CurrencyAggregationError {}

/// Bounded status for one isolated handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandlerStatus {
    pub phase: HandlerPhase,
    pub outcome: HandlerOutcome,
    pub observed_generation: u64,
    pub queued: u32,
    pub running: u32,
    pub last_watch_revision: u64,
    pub checkpoint_revision: u64,
    pub last_reconciled_tick: u64,
    pub retry_after_tick: Option<u64>,
}

impl HandlerStatus {
    /// Initial fail-closed status.
    pub const fn pending() -> Self {
        Self {
            phase: HandlerPhase::Pending,
            outcome: HandlerOutcome::None,
            observed_generation: 0,
            queued: 0,
            running: 0,
            last_watch_revision: 0,
            checkpoint_revision: 0,
            last_reconciled_tick: 0,
            retry_after_tick: None,
        }
    }

    fn validate(self) -> Result<Self, HandlerRegistryError> {
        if self.checkpoint_revision > self.last_watch_revision
            || self.phase == HandlerPhase::Ready && self.observed_generation == 0
        {
            return Err(HandlerRegistryError::InvalidStatus);
        }
        Ok(self)
    }
}

/// Aggregate process health.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggregateHealth {
    Pending,
    Ready,
    Degraded,
    Failed,
    Unknown,
}

/// Closed registry failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandlerRegistryError {
    InvalidStatus,
}

impl core::fmt::Display for HandlerRegistryError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("core-handler-status-invalid")
    }
}

impl std::error::Error for HandlerRegistryError {}

/// Fixed registry containing exactly one status slot per handler kind.
#[derive(Debug)]
pub struct CoreHandlerRegistry {
    handlers: BTreeMap<CoreHandlerKind, HandlerStatus>,
}

impl Default for CoreHandlerRegistry {
    fn default() -> Self {
        Self {
            handlers: CoreHandlerKind::ALL
                .into_iter()
                .map(|kind| (kind, HandlerStatus::pending()))
                .collect(),
        }
    }
}

impl CoreHandlerRegistry {
    /// Replace one handler's bounded status.
    pub fn update(
        &mut self,
        kind: CoreHandlerKind,
        status: HandlerStatus,
    ) -> Result<(), HandlerRegistryError> {
        self.handlers.insert(kind, status.validate()?);
        Ok(())
    }

    /// Borrow one fixed handler status.
    pub fn status(&self, kind: CoreHandlerKind) -> HandlerStatus {
        self.handlers[&kind]
    }

    /// Compute aggregate health without letting optional work block readiness.
    pub fn aggregate_health(&self) -> AggregateHealth {
        let mandatory = CoreHandlerKind::ALL
            .into_iter()
            .filter(|kind| kind.mandatory())
            .map(|kind| self.handlers[&kind].phase);
        let phases = mandatory.collect::<Vec<_>>();
        if phases.contains(&HandlerPhase::Failed) {
            return AggregateHealth::Failed;
        }
        if phases.contains(&HandlerPhase::Unknown) {
            return AggregateHealth::Unknown;
        }
        if phases.contains(&HandlerPhase::Degraded) {
            return AggregateHealth::Degraded;
        }
        if phases.iter().all(|phase| *phase == HandlerPhase::Ready) {
            return AggregateHealth::Ready;
        }
        AggregateHealth::Pending
    }

    /// Mark every handler as recovering after a process restart.
    pub fn begin_recovery(&mut self) {
        for status in self.handlers.values_mut() {
            status.phase = HandlerPhase::Recovering;
            status.outcome = HandlerOutcome::Recovering;
            status.running = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready() -> HandlerStatus {
        HandlerStatus {
            phase: HandlerPhase::Ready,
            outcome: HandlerOutcome::Converged,
            observed_generation: 1,
            queued: 0,
            running: 0,
            last_watch_revision: 3,
            checkpoint_revision: 3,
            last_reconciled_tick: 4,
            retry_after_tick: None,
        }
    }

    #[test]
    fn readiness_requires_every_mandatory_handler_only() {
        let mut registry = CoreHandlerRegistry::default();
        for kind in CoreHandlerKind::ALL {
            if kind.mandatory() {
                registry.update(kind, ready()).unwrap();
            }
        }
        registry
            .update(
                CoreHandlerKind::ZoneLinks,
                HandlerStatus {
                    phase: HandlerPhase::Degraded,
                    ..HandlerStatus::pending()
                },
            )
            .unwrap();
        assert_eq!(registry.aggregate_health(), AggregateHealth::Ready);
    }

    #[test]
    fn mandatory_unknown_never_becomes_ready() {
        let mut registry = CoreHandlerRegistry::default();
        for kind in CoreHandlerKind::ALL {
            if kind.mandatory() {
                registry.update(kind, ready()).unwrap();
            }
        }
        registry
            .update(
                CoreHandlerKind::Authorization,
                HandlerStatus {
                    phase: HandlerPhase::Unknown,
                    outcome: HandlerOutcome::Ambiguous,
                    ..HandlerStatus::pending()
                },
            )
            .unwrap();
        assert_eq!(registry.aggregate_health(), AggregateHealth::Unknown);
    }

    #[test]
    fn ready_without_an_observed_generation_is_rejected() {
        let mut registry = CoreHandlerRegistry::default();
        assert_eq!(
            registry
                .update(
                    CoreHandlerKind::Store,
                    HandlerStatus {
                        phase: HandlerPhase::Ready,
                        ..HandlerStatus::pending()
                    },
                )
                .unwrap_err(),
            HandlerRegistryError::InvalidStatus
        );
    }

    #[test]
    fn restart_marks_every_handler_recovering_without_preserving_running_counts() {
        let mut registry = CoreHandlerRegistry::default();
        registry
            .update(
                CoreHandlerKind::Provider,
                HandlerStatus {
                    running: 2,
                    ..ready()
                },
            )
            .unwrap();
        registry.begin_recovery();
        for kind in CoreHandlerKind::ALL {
            assert_eq!(registry.status(kind).phase, HandlerPhase::Recovering);
            assert_eq!(registry.status(kind).running, 0);
        }
    }

    #[test]
    fn handler_metric_labels_are_closed_and_identity_free() {
        assert_eq!(
            CORE_HANDLER_METRIC_LABEL_KEYS,
            &["handler", "phase", "outcome"]
        );
        for kind in CoreHandlerKind::ALL {
            assert!(!kind.label().contains("name"));
        }
    }

    #[test]
    fn currency_aggregation_counts_and_truncates_non_current_refs() {
        let owned = (0..70).map(|index| {
            (
                ResourceRef::parse(&format!("Process/owned-{index}")).unwrap(),
                UpdateState::UpdateAvailable,
            )
        });
        let aggregation = CurrencyAggregation::aggregate(
            UpdateState::Current,
            owned,
            [(
                ResourceRef::parse("Volume/current").unwrap(),
                UpdateState::Current,
            )],
        )
        .unwrap();
        assert_eq!(aggregation.self_state(), UpdateState::Current);
        assert_eq!(aggregation.owned().count(), 70);
        assert_eq!(
            aggregation.owned().refs().len(),
            MAX_STATUS_COLLECTION_ENTRIES
        );
        assert_eq!(aggregation.dependencies().count(), 0);
    }

    #[test]
    fn duplicate_currency_identity_is_rejected() {
        let target = ResourceRef::parse("Process/duplicate").unwrap();
        assert_eq!(
            CurrencyAggregation::aggregate(
                UpdateState::Current,
                [
                    (target.clone(), UpdateState::UpdateAvailable),
                    (target, UpdateState::UpgradeRequired),
                ],
                [],
            )
            .unwrap_err(),
            CurrencyAggregationError
        );
    }
}
