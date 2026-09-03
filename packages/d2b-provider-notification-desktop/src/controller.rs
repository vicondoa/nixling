//! Process placement controller for desktop notification components.

use crate::SessionEvidence;
use crate::{
    NotificationHostSinkIdentity, NotificationLifecyclePlan, NotificationLifecycleReceipt,
    NotificationSourceIdentity,
};
use d2b_contracts_resource::v3::identity::{EvidenceClass, Locality};
use d2b_contracts_resource::v3::{ResourceRef, ZoneId};
use d2b_provider_toolkit::AuthenticatedSessionRouteBinding;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

use crate::Category;

/// The bounded repair interval for the notification ComponentSession runtime.
pub const NOTIFICATION_REPAIR_INTERVAL_SECS: u64 = 300;

/// The cutover contract for the notification service-only runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotificationRunnerContract {
    service_package: &'static str,
    repair_interval_secs: u64,
    watched_configuration_is_dependency: bool,
    component_session_only: bool,
}

impl NotificationRunnerContract {
    /// Return the notification service package.
    pub const fn service_package(self) -> &'static str {
        self.service_package
    }

    /// Return the bounded repair interval.
    pub const fn repair_interval_secs(self) -> u64 {
        self.repair_interval_secs
    }

    /// Whether legacy notification scheduling is disabled.

    /// Whether configuration is dependency-only.
    pub const fn watched_configuration_is_dependency(self) -> bool {
        self.watched_configuration_is_dependency
    }

    /// Whether notification state remains on typed ComponentSession streams.
    pub const fn component_session_only(self) -> bool {
        self.component_session_only
    }
}

/// Return the service-only notification cutover contract.
pub const fn notification_runner_contract() -> NotificationRunnerContract {
    NotificationRunnerContract {
        service_package: crate::SERVICE_PACKAGE,
        repair_interval_secs: NOTIFICATION_REPAIR_INTERVAL_SECS,
        watched_configuration_is_dependency: true,
        component_session_only: true,
    }
}

const DISPLAY_PROVIDER_REF: &str = "Provider/display-wayland";
const DISPLAY_SERVICE_PACKAGE: &str = "d2b.display.v3";
const MAX_GUEST_SOURCES: usize = 16;
const MIN_MAX_PENDING_NOTIFICATIONS: usize = 8;
const MAX_MAX_PENDING_NOTIFICATIONS: usize = 1024;
const MIN_ACTION_NONCE_TTL_SECS: u64 = 30;
const MAX_ACTION_NONCE_TTL_SECS: u64 = 600;
const MIN_ACTION_NONCE_STORE_SIZE: usize = 64;
const MAX_ACTION_NONCE_STORE_SIZE: usize = 4096;
const MIN_ACKNOWLEDGE_TIMEOUT_SECS: u64 = 1;
const MAX_ACKNOWLEDGE_TIMEOUT_SECS: u64 = 86_400;

/// Readiness state reported by the authenticated display dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayDependencyState {
    /// The display endpoint accepted the current policy generation.
    Ready,
    /// The display endpoint is still starting.
    Pending,
    /// The display endpoint cannot serve this generation.
    Failed,
}

/// Same-Zone, route-authenticated display dependency evidence.
///
/// The constructor accepts only a route binding produced by the canonical
/// ComponentSession authority.  Provider configuration cannot manufacture a
/// ready dependency by passing a Provider reference or boolean.
#[derive(Clone, PartialEq, Eq)]
pub struct DisplayDependencyEvidence {
    provider_ref: ResourceRef,
    zone: ZoneId,
    host_execution_ref: ResourceRef,
    user_ref: ResourceRef,
    provider_generation: u64,
    reconnect_generation: u64,
    controller_generation: u64,
    state: DisplayDependencyState,
}

impl DisplayDependencyEvidence {
    /// Project authenticated Ready evidence from the display route.
    pub fn from_authenticated_route(
        route: AuthenticatedSessionRouteBinding,
    ) -> Result<Self, &'static str> {
        let provider_generation = route
            .provider_generation()
            .ok_or("display-dependency-unauthenticated")?
            .get();
        Self::from_route(route, DisplayDependencyState::Ready, provider_generation)
    }

    /// Project daemon-local display evidence when the ComponentSession route
    /// is bound to the authenticated Guest frontend and Core supplies the
    /// corresponding host User resource separately.
    pub fn from_daemon_route(
        route: AuthenticatedSessionRouteBinding,
        user_ref: ResourceRef,
    ) -> Result<Self, &'static str> {
        let provider_generation = route
            .provider_generation()
            .ok_or("display-dependency-unauthenticated")?
            .get();
        let Some(provider) = route.provider_ref() else {
            return Err("display-dependency-unauthenticated");
        };
        let Some(host_execution_ref) = route.context().execution_ref() else {
            return Err("display-dependency-unauthenticated");
        };
        let Some(controller_generation) = route.controller_generation() else {
            return Err("display-dependency-unauthenticated");
        };
        if provider.to_canonical_string() != DISPLAY_PROVIDER_REF
            || route.service().as_str() != DISPLAY_SERVICE_PACKAGE
            || route.evidence_class() != EvidenceClass::UnixPeer
            || route.locality() != Locality::Local
            || route.subject_ref().resource_type().as_str() != "Guest"
            || user_ref.resource_type().as_str() != "User"
            || host_execution_ref.resource_type().as_str() != "Host"
            || provider_generation == 0
            || route.reconnect_generation().get() == 0
            || controller_generation.get() == 0
        {
            return Err("display-dependency-unauthenticated");
        }
        Ok(Self {
            provider_ref: provider.clone(),
            zone: route.zone().clone(),
            host_execution_ref: host_execution_ref.clone(),
            user_ref,
            provider_generation,
            reconnect_generation: route.reconnect_generation().get(),
            controller_generation: controller_generation.get(),
            state: DisplayDependencyState::Ready,
        })
    }

    /// Resolve one display dependency from an authenticated display route.
    #[allow(dead_code)]
    pub(crate) fn from_route(
        route: AuthenticatedSessionRouteBinding,
        state: DisplayDependencyState,
        generation: u64,
    ) -> Result<Self, &'static str> {
        let Some(provider) = route.provider_ref() else {
            return Err("display-dependency-unauthenticated");
        };
        if route.service().as_str() != DISPLAY_SERVICE_PACKAGE
            || route.evidence_class() != EvidenceClass::UnixPeer
            || route.locality() != Locality::Local
            || provider.to_canonical_string() != DISPLAY_PROVIDER_REF
            || route.subject_ref().resource_type().as_str() != "User"
            || generation == 0
            || route.reconnect_generation().get() == 0
            || route
                .provider_generation()
                .is_none_or(|observed| observed.get() != generation)
        {
            return Err("display-dependency-unauthenticated");
        }
        let Some(host_execution_ref) = route.context().execution_ref() else {
            return Err("display-dependency-unauthenticated");
        };
        let Some(controller_generation) = route.controller_generation() else {
            return Err("display-dependency-unauthenticated");
        };
        if host_execution_ref.resource_type().as_str() != "Host" || controller_generation.get() == 0
        {
            return Err("display-dependency-unauthenticated");
        }
        Ok(Self {
            provider_ref: provider.clone(),
            zone: route.zone().clone(),
            host_execution_ref: host_execution_ref.clone(),
            user_ref: route.subject_ref().clone(),
            provider_generation: generation,
            reconnect_generation: route.reconnect_generation().get(),
            controller_generation: controller_generation.get(),
            state,
        })
    }

    /// Borrow the authenticated display Provider reference.
    pub const fn provider_ref(&self) -> &ResourceRef {
        &self.provider_ref
    }

    /// Borrow the authenticated dependency Zone.
    pub const fn zone(&self) -> &ZoneId {
        &self.zone
    }

    /// Borrow the authenticated Host execution reference.
    pub const fn host_execution_ref(&self) -> &ResourceRef {
        &self.host_execution_ref
    }

    /// Borrow the authenticated display user.
    pub const fn user_ref(&self) -> &ResourceRef {
        &self.user_ref
    }

    /// Return the Core-observed display readiness generation.
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

    /// Return the dependency readiness state.
    pub const fn state(&self) -> DisplayDependencyState {
        self.state
    }

    /// Whether the dependency is ready for source admission.
    pub const fn is_ready(&self) -> bool {
        matches!(self.state, DisplayDependencyState::Ready)
    }
}

impl core::fmt::Debug for DisplayDependencyEvidence {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DisplayDependencyEvidence(REDACTED)")
    }
}

fn display_fingerprint(display: &DisplayDependencyEvidence) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(display.provider_ref().to_canonical_string().as_bytes());
    digest.update([0]);
    digest.update(display.zone().as_str().as_bytes());
    digest.update([0]);
    digest.update(
        display
            .host_execution_ref()
            .to_canonical_string()
            .as_bytes(),
    );
    digest.update([0]);
    digest.update(display.user_ref().to_canonical_string().as_bytes());
    digest.update([0]);
    digest.update(display.generation().to_be_bytes());
    digest.update([0]);
    digest.update(display.reconnect_generation().to_be_bytes());
    digest.update([0]);
    digest.update(display.controller_generation().to_be_bytes());
    digest.update([display.is_ready() as u8]);
    digest.finalize().into()
}

fn sink_fingerprint(config: &NotificationProviderConfig) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update([config.dbus_sink_enabled() as u8]);
    digest.update(config.max_pending_notifications().to_be_bytes());
    digest.update(config.action_nonce_store_size().to_be_bytes());
    digest.update(config.action_nonce_ttl_secs().to_be_bytes());
    digest.update(config.acknowledge_timeout_secs().to_be_bytes());
    digest.update([config.observer_enabled() as u8]);
    for reference in [config.host_execution_ref(), config.host_user_ref()] {
        if let Some(reference) = reference {
            digest.update(reference.to_canonical_string().as_bytes());
        }
        digest.update([0]);
    }
    digest.finalize().into()
}

/// One configured Guest notification source.
#[derive(Clone, PartialEq, Eq)]
pub struct GuestSourceConfig {
    source_ref: ResourceRef,
    zone: ZoneId,
    categories: BTreeSet<Category>,
}

impl GuestSourceConfig {
    /// Validate one Guest source configuration.
    pub fn new(
        source_ref: ResourceRef,
        zone: ZoneId,
        categories: impl IntoIterator<Item = Category>,
    ) -> Result<Self, &'static str> {
        if source_ref.resource_type().as_str() != "Guest" {
            return Err("notification-source-ref-invalid");
        }
        let categories = categories.into_iter().collect::<BTreeSet<_>>();
        if categories.is_empty() {
            return Err("notification-category-set-empty");
        }
        Ok(Self {
            source_ref,
            zone,
            categories,
        })
    }

    /// Borrow the configured Guest reference.
    pub const fn source_ref(&self) -> &ResourceRef {
        &self.source_ref
    }

    /// Borrow the configured source Zone.
    pub const fn zone(&self) -> &ZoneId {
        &self.zone
    }

    /// Borrow the source category allowlist.
    pub fn categories(&self) -> &BTreeSet<Category> {
        &self.categories
    }
}

impl core::fmt::Debug for GuestSourceConfig {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("GuestSourceConfig")
            .field("source_ref", &"<redacted>")
            .field("zone", &"<redacted>")
            .field("category_count", &self.categories.len())
            .finish()
    }
}

/// Validated notification Provider configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationProviderConfig {
    guest_sources: Vec<GuestSourceConfig>,
    host_execution_ref: Option<ResourceRef>,
    host_user_ref: Option<ResourceRef>,
    display_wayland_ref: Option<ResourceRef>,
    max_pending_notifications: usize,
    action_nonce_ttl_secs: u64,
    action_nonce_store_size: usize,
    acknowledge_timeout_secs: u64,
    dbus_sink_enabled: bool,
    observer_enabled: bool,
}

impl NotificationProviderConfig {
    /// Validate bounded, unique Guest source configuration.
    pub fn new(guest_sources: Vec<GuestSourceConfig>) -> Result<Self, &'static str> {
        if guest_sources.len() > MAX_GUEST_SOURCES {
            return Err("notification-source-capacity");
        }
        let mut seen = BTreeSet::new();
        for source in &guest_sources {
            if !seen.insert(source.source_ref.clone()) {
                return Err("notification-source-duplicate");
            }
        }
        Ok(Self {
            guest_sources,
            host_execution_ref: None,
            host_user_ref: None,
            display_wayland_ref: None,
            max_pending_notifications: crate::DEFAULT_MAX_PENDING,
            action_nonce_ttl_secs: crate::DEFAULT_NONCE_TTL_SECS,
            action_nonce_store_size: crate::DEFAULT_NONCE_STORE_SIZE,
            acknowledge_timeout_secs: crate::DEFAULT_ACKNOWLEDGE_TIMEOUT_SECS,
            dbus_sink_enabled: true,
            observer_enabled: true,
        })
    }

    /// Enable or disable the host D-Bus sink process.
    pub const fn with_dbus_sink_enabled(mut self, enabled: bool) -> Self {
        self.dbus_sink_enabled = enabled;
        self
    }

    /// Return whether the host D-Bus sink is configured.
    pub const fn dbus_sink_enabled(&self) -> bool {
        self.dbus_sink_enabled
    }

    /// Enable or disable the authenticated observer stream.
    pub const fn with_observer_enabled(mut self, enabled: bool) -> Self {
        self.observer_enabled = enabled;
        self
    }

    /// Return whether the authenticated observer stream is configured.
    pub const fn observer_enabled(&self) -> bool {
        self.observer_enabled
    }

    /// Configure the maximum number of pending projections.
    pub fn with_max_pending_notifications(
        mut self,
        max_pending_notifications: usize,
    ) -> Result<Self, &'static str> {
        if !(MIN_MAX_PENDING_NOTIFICATIONS..=MAX_MAX_PENDING_NOTIFICATIONS)
            .contains(&max_pending_notifications)
        {
            return Err("notification-pending-capacity");
        }
        self.max_pending_notifications = max_pending_notifications;
        Ok(self)
    }

    /// Return the maximum number of pending projections.
    pub const fn max_pending_notifications(&self) -> usize {
        self.max_pending_notifications
    }

    /// Configure the action capability TTL.
    pub fn with_action_nonce_ttl_secs(
        mut self,
        action_nonce_ttl_secs: u64,
    ) -> Result<Self, &'static str> {
        if !(MIN_ACTION_NONCE_TTL_SECS..=MAX_ACTION_NONCE_TTL_SECS).contains(&action_nonce_ttl_secs)
        {
            return Err("notification-action-nonce-ttl");
        }
        self.action_nonce_ttl_secs = action_nonce_ttl_secs;
        Ok(self)
    }

    /// Return the action capability TTL.
    pub const fn action_nonce_ttl_secs(&self) -> u64 {
        self.action_nonce_ttl_secs
    }

    /// Configure the action capability store capacity.
    pub fn with_action_nonce_store_size(
        mut self,
        action_nonce_store_size: usize,
    ) -> Result<Self, &'static str> {
        if !(MIN_ACTION_NONCE_STORE_SIZE..=MAX_ACTION_NONCE_STORE_SIZE)
            .contains(&action_nonce_store_size)
        {
            return Err("notification-action-nonce-capacity");
        }
        self.action_nonce_store_size = action_nonce_store_size;
        Ok(self)
    }

    /// Return the action capability store capacity.
    pub const fn action_nonce_store_size(&self) -> usize {
        self.action_nonce_store_size
    }

    /// Configure the observer acknowledgement timeout.
    pub fn with_acknowledge_timeout_secs(
        mut self,
        acknowledge_timeout_secs: u64,
    ) -> Result<Self, &'static str> {
        if !(MIN_ACKNOWLEDGE_TIMEOUT_SECS..=MAX_ACKNOWLEDGE_TIMEOUT_SECS)
            .contains(&acknowledge_timeout_secs)
        {
            return Err("notification-acknowledge-timeout");
        }
        self.acknowledge_timeout_secs = acknowledge_timeout_secs;
        Ok(self)
    }

    /// Return the observer acknowledgement timeout.
    pub const fn acknowledge_timeout_secs(&self) -> u64 {
        self.acknowledge_timeout_secs
    }

    /// Bind the display Provider dependency selected by Core.
    pub fn with_display_wayland_ref(
        mut self,
        display_wayland_ref: Option<ResourceRef>,
    ) -> Result<Self, &'static str> {
        if display_wayland_ref
            .as_ref()
            .is_some_and(|provider| provider.to_canonical_string() != DISPLAY_PROVIDER_REF)
        {
            return Err("notification-display-provider-invalid");
        }
        self.display_wayland_ref = display_wayland_ref;
        Ok(self)
    }

    /// Borrow the configured display Provider dependency.
    pub fn display_wayland_ref(&self) -> Option<&ResourceRef> {
        self.display_wayland_ref.as_ref()
    }

    /// Bind the configured processes to the Core-resolved Host and User.
    pub fn with_host_binding(
        mut self,
        host_execution_ref: ResourceRef,
        host_user_ref: ResourceRef,
    ) -> Result<Self, &'static str> {
        if host_execution_ref.resource_type().as_str() != "Host"
            || host_user_ref.resource_type().as_str() != "User"
        {
            return Err("notification-host-binding-invalid");
        }
        self.host_execution_ref = Some(host_execution_ref);
        self.host_user_ref = Some(host_user_ref);
        Ok(self)
    }

    /// Borrow configured Guest sources.
    pub fn guest_sources(&self) -> &[GuestSourceConfig] {
        &self.guest_sources
    }

    fn host_execution_ref(&self) -> Option<&ResourceRef> {
        self.host_execution_ref.as_ref()
    }

    /// Borrow the committed Host User binding.
    pub fn host_user_ref(&self) -> Option<&ResourceRef> {
        self.host_user_ref.as_ref()
    }
}

/// Source process lifecycle change emitted by reconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceReconcileResult {
    /// Guest sources whose process endpoint must be started.
    pub start: Vec<ResourceRef>,
    /// Guest sources whose endpoint must be drained and stopped.
    pub stop: Vec<ResourceRef>,
    /// Whether the host sink must be started in this pass.
    pub start_host_sink: bool,
    /// Whether the host sink must be drained and stopped in this pass.
    pub stop_host_sink: bool,
    /// Authenticated endpoints whose source process must be started.
    pub start_endpoints: Vec<SourceEndpoint>,
    /// Authenticated endpoints whose source process must be drained.
    pub stop_endpoints: Vec<SourceEndpoint>,
    display_fingerprint: [u8; 32],
    host_sink_fingerprint: [u8; 32],
    source_error: Option<&'static str>,
}

impl SourceReconcileResult {
    fn digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        for source in &self.start {
            digest.update(source.to_canonical_string().as_bytes());
            digest.update([0]);
        }
        digest.update([1]);
        for source in &self.stop {
            digest.update(source.to_canonical_string().as_bytes());
            digest.update([0]);
        }
        digest.update([self.start_host_sink as u8, self.stop_host_sink as u8]);
        for endpoint in &self.start_endpoints {
            digest.update(endpoint.endpoint_digest().as_bytes());
            digest.update([0]);
        }
        digest.update([2]);
        for endpoint in &self.stop_endpoints {
            digest.update(endpoint.endpoint_digest().as_bytes());
            digest.update([0]);
        }
        digest.update(self.display_fingerprint);
        digest.update(self.host_sink_fingerprint);
        if let Some(error) = self.source_error {
            digest.update(error.as_bytes());
        }
        let bytes = digest.finalize();
        let mut result = [0; 32];
        result.copy_from_slice(&bytes);
        result
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum SourceEffectAcknowledgement {
    Source {
        start: bool,
        endpoint_digest: String,
        source_generation: u64,
        display_generation: u64,
    },
    HostSink {
        start: bool,
        display_fingerprint: [u8; 32],
        sink_fingerprint: [u8; 32],
    },
}

/// Typed acknowledgement that a complete source effect plan was applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceProcessEffectReceipt {
    plan_digest: [u8; 32],
    acknowledgements: Vec<SourceEffectAcknowledgement>,
}

impl SourceProcessEffectReceipt {
    fn builder(plan: &SourceReconcileResult) -> SourceProcessEffectReceiptBuilder {
        SourceProcessEffectReceiptBuilder {
            plan_digest: plan.digest(),
            display_fingerprint: plan.display_fingerprint,
            sink_fingerprint: plan.host_sink_fingerprint,
            expected: Self::expected_acknowledgements(plan),
            acknowledgements: Vec::new(),
        }
    }

    /// Bind the Provider acknowledgement to the supervisor's authoritative receipt.
    pub fn from_supervisor(
        plan: &SourceReconcileResult,
        lifecycle: &NotificationLifecyclePlan,
        receipt: &NotificationLifecycleReceipt,
    ) -> Result<Self, &'static str> {
        if !receipt.matches(lifecycle) {
            return Err("notification-supervisor-receipt-mismatch");
        }
        Ok(Self::complete(plan))
    }

    pub(crate) fn complete(plan: &SourceReconcileResult) -> Self {
        let mut builder = Self::builder(plan);
        for endpoint in &plan.start_endpoints {
            builder.acknowledge_source_start(endpoint);
        }
        for endpoint in &plan.stop_endpoints {
            builder.acknowledge_source_stop(endpoint);
        }
        if plan.start_host_sink {
            builder.acknowledge_host_sink_start();
        }
        if plan.stop_host_sink {
            builder.acknowledge_host_sink_stop();
        }
        builder
            .finish()
            .expect("complete acknowledgement set must match its plan")
    }

    fn expected_acknowledgements(plan: &SourceReconcileResult) -> Vec<SourceEffectAcknowledgement> {
        let mut acknowledgements = Vec::new();
        acknowledgements.extend(plan.start_endpoints.iter().map(|endpoint| {
            SourceEffectAcknowledgement::Source {
                start: true,
                endpoint_digest: endpoint.endpoint_digest().to_owned(),
                source_generation: endpoint.source_generation(),
                display_generation: endpoint.display_generation(),
            }
        }));
        acknowledgements.extend(plan.stop_endpoints.iter().map(|endpoint| {
            SourceEffectAcknowledgement::Source {
                start: false,
                endpoint_digest: endpoint.endpoint_digest().to_owned(),
                source_generation: endpoint.source_generation(),
                display_generation: endpoint.display_generation(),
            }
        }));
        if plan.start_host_sink {
            acknowledgements.push(SourceEffectAcknowledgement::HostSink {
                start: true,
                display_fingerprint: plan.display_fingerprint,
                sink_fingerprint: plan.host_sink_fingerprint,
            });
        }
        if plan.stop_host_sink {
            acknowledgements.push(SourceEffectAcknowledgement::HostSink {
                start: false,
                display_fingerprint: plan.display_fingerprint,
                sink_fingerprint: plan.host_sink_fingerprint,
            });
        }
        acknowledgements.sort();
        acknowledgements
    }

    fn matches(&self, plan: &SourceReconcileResult) -> bool {
        self.plan_digest == plan.digest()
            && self.acknowledgements == Self::expected_acknowledgements(plan)
    }

    fn no_effects(plan: &SourceReconcileResult) -> Result<Self, &'static str> {
        if !plan.start_endpoints.is_empty()
            || !plan.stop_endpoints.is_empty()
            || plan.start_host_sink
            || plan.stop_host_sink
        {
            return Err("notification-process-effect-incomplete");
        }
        Ok(Self {
            plan_digest: plan.digest(),
            acknowledgements: Vec::new(),
        })
    }
}

/// Builder for a complete, typed process-effect receipt.
///
/// Each acknowledgement method corresponds to one effect in the plan. The
/// builder refuses to mint a receipt unless the complete expected set was
/// observed, so an effect adapter cannot acknowledge only a plan digest.
struct SourceProcessEffectReceiptBuilder {
    plan_digest: [u8; 32],
    display_fingerprint: [u8; 32],
    sink_fingerprint: [u8; 32],
    expected: Vec<SourceEffectAcknowledgement>,
    acknowledgements: Vec<SourceEffectAcknowledgement>,
}

impl SourceProcessEffectReceiptBuilder {
    /// Acknowledge a Guest-source process start.
    fn acknowledge_source_start(&mut self, endpoint: &SourceEndpoint) {
        self.acknowledgements
            .push(SourceEffectAcknowledgement::Source {
                start: true,
                endpoint_digest: endpoint.endpoint_digest().to_owned(),
                source_generation: endpoint.source_generation(),
                display_generation: endpoint.display_generation(),
            });
    }

    /// Acknowledge a Guest-source process stop.
    fn acknowledge_source_stop(&mut self, endpoint: &SourceEndpoint) {
        self.acknowledgements
            .push(SourceEffectAcknowledgement::Source {
                start: false,
                endpoint_digest: endpoint.endpoint_digest().to_owned(),
                source_generation: endpoint.source_generation(),
                display_generation: endpoint.display_generation(),
            });
    }

    /// Acknowledge starting the host sink for this plan.
    fn acknowledge_host_sink_start(&mut self) {
        self.acknowledgements
            .push(SourceEffectAcknowledgement::HostSink {
                start: true,
                display_fingerprint: self.display_fingerprint,
                sink_fingerprint: self.sink_fingerprint,
            });
    }

    /// Acknowledge stopping the host sink for this plan.
    fn acknowledge_host_sink_stop(&mut self) {
        self.acknowledgements
            .push(SourceEffectAcknowledgement::HostSink {
                start: false,
                display_fingerprint: self.display_fingerprint,
                sink_fingerprint: self.sink_fingerprint,
            });
    }

    /// Finish the receipt only when every planned effect was acknowledged.
    fn finish(mut self) -> Result<SourceProcessEffectReceipt, &'static str> {
        self.acknowledgements.sort();
        if self.acknowledgements != self.expected {
            return Err("notification-process-effect-incomplete");
        }
        Ok(SourceProcessEffectReceipt {
            plan_digest: self.plan_digest,
            acknowledgements: self.acknowledgements,
        })
    }
}

/// Process/effect boundary used to make reconciliation transactional.
///
/// The controller computes the complete stop/start set first.  Ownership is
/// committed only after this port confirms that every requested process
/// effect was accepted.
pub trait SourceProcessEffectPort {
    /// Apply one complete reconciliation plan.
    fn apply(
        &mut self,
        plan: &SourceReconcileResult,
        lifecycle: &NotificationLifecyclePlan,
    ) -> Result<SourceProcessEffectReceipt, &'static str>;
}

/// Authenticated Guest source endpoint evidence.
#[derive(Clone, PartialEq, Eq)]
pub struct SourceEndpoint {
    source_ref: ResourceRef,
    zone: ZoneId,
    source_generation: u64,
    display_generation: u64,
    endpoint_digest: String,
}

impl SourceEndpoint {
    fn from_authenticated(
        source: &GuestSourceConfig,
        session: &SessionEvidence,
        display: &DisplayDependencyEvidence,
    ) -> Result<Self, &'static str> {
        session
            .admit_source()
            .map_err(|_| "notification-source-unauthenticated")?;
        if session.subject_ref() != source.source_ref() || session.zone() != source.zone() {
            return Err("notification-source-binding-mismatch");
        }
        let mut digest = Sha256::new();
        digest.update(source.source_ref().to_canonical_string().as_bytes());
        digest.update([0]);
        for category in source.categories() {
            digest.update(category.as_str().as_bytes());
            digest.update([0]);
        }
        digest.update(session.generation().to_be_bytes());
        digest.update([0]);
        digest.update(display.generation().to_be_bytes());
        digest.update([0]);
        digest.update(display.controller_generation().to_be_bytes());
        digest.update([0]);
        digest.update(display.reconnect_generation().to_be_bytes());
        digest.update([0]);
        digest.update(
            display
                .host_execution_ref()
                .to_canonical_string()
                .as_bytes(),
        );
        digest.update([0]);
        digest.update(display.user_ref().to_canonical_string().as_bytes());
        let endpoint_digest = format!(
            "sha256:{}",
            digest
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        Ok(Self {
            source_ref: source.source_ref().clone(),
            zone: source.zone().clone(),
            source_generation: session.generation(),
            display_generation: display.generation(),
            endpoint_digest,
        })
    }

    /// Borrow the exact configured Guest reference.
    pub const fn source_ref(&self) -> &ResourceRef {
        &self.source_ref
    }

    /// Borrow the configured Zone of the exact Guest source.
    pub const fn zone(&self) -> &ZoneId {
        &self.zone
    }

    /// Return the authenticated Guest reconnect generation.
    pub const fn source_generation(&self) -> u64 {
        self.source_generation
    }

    /// Return the display generation this endpoint consumes.
    pub const fn display_generation(&self) -> u64 {
        self.display_generation
    }

    /// Borrow the opaque endpoint correlation.
    pub fn endpoint_digest(&self) -> &str {
        &self.endpoint_digest
    }
}

impl core::fmt::Debug for SourceEndpoint {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SourceEndpoint(REDACTED)")
    }
}

/// A planned notification component process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessPlan {
    /// Stable process template.
    pub template: &'static str,
    /// Process execution domain.
    pub domain: &'static str,
    /// Whether a state Volume is mounted.
    pub mounts_state_volume: bool,
    /// Guest source reference for source processes, if this is a source plan.
    pub source_ref: Option<ResourceRef>,
    /// Authenticated execution reference for the process.
    pub execution_ref: ResourceRef,
    /// Authenticated User identity for user-domain processes.
    pub user_ref: Option<ResourceRef>,
    /// Whether the host sink exposes the authenticated observer stream.
    pub observer_enabled: bool,
}

/// Notification placement controller.
pub struct NotificationController {
    provider_ref: ResourceRef,
    active_sources: std::collections::BTreeMap<ResourceRef, SourceEndpoint>,
    active_display_fingerprint: Option<[u8; 32]>,
    host_sink_fingerprint: Option<[u8; 32]>,
    active_host_sink: Option<NotificationHostSinkIdentity>,
}

impl NotificationController {
    /// Construct a controller for one exact Provider instance.
    pub fn new(provider_ref: impl AsRef<str>) -> Result<Self, &'static str> {
        let provider_ref = ResourceRef::parse(provider_ref.as_ref())
            .map_err(|_| "notification-provider-ref-invalid")?;
        if provider_ref.to_canonical_string() != crate::PROVIDER_REF {
            return Err("notification-provider-ref-invalid");
        }
        Ok(Self {
            provider_ref,
            active_sources: std::collections::BTreeMap::new(),
            active_display_fingerprint: None,
            host_sink_fingerprint: None,
            active_host_sink: None,
        })
    }

    /// Plan component processes from typed display evidence and configuration.
    pub fn plan(
        &self,
        display: &DisplayDependencyEvidence,
        config: &NotificationProviderConfig,
    ) -> Result<Vec<ProcessPlan>, &'static str> {
        let host_execution_ref = config
            .host_execution_ref()
            .ok_or("notification-host-binding-missing")?;
        let host_user_ref = config.host_user_ref();
        if display.host_execution_ref() != host_execution_ref
            || (config.dbus_sink_enabled()
                && host_user_ref.is_none_or(|user| display.user_ref() != user))
        {
            return Err("notification-host-binding-mismatch");
        }
        if config.dbus_sink_enabled()
            && config.display_wayland_ref() != Some(display.provider_ref())
        {
            return Err("notification-display-provider-mismatch");
        }
        if config
            .guest_sources()
            .iter()
            .any(|source| source.zone() != display.zone())
        {
            return Err("notification-source-zone-mismatch");
        }
        let mut plans = vec![ProcessPlan {
            template: "notification-desktop-controller",
            domain: "system",
            mounts_state_volume: false,
            source_ref: None,
            execution_ref: host_execution_ref.clone(),
            user_ref: None,
            observer_enabled: false,
        }];
        if config.dbus_sink_enabled() && display.is_ready() {
            let host_user_ref = host_user_ref.ok_or("notification-host-binding-missing")?;
            plans.push(ProcessPlan {
                template: "notification-desktop-host-sink",
                domain: "user",
                mounts_state_volume: false,
                source_ref: None,
                execution_ref: host_execution_ref.clone(),
                user_ref: Some(host_user_ref.clone()),
                observer_enabled: config.observer_enabled(),
            });
        }
        if display.is_ready() {
            plans.extend(config.guest_sources().iter().map(|source| ProcessPlan {
                template: "notification-desktop-guest-source",
                domain: "guest",
                mounts_state_volume: false,
                source_ref: Some(source.source_ref().clone()),
                execution_ref: source.source_ref().clone(),
                user_ref: None,
                observer_enabled: false,
            }));
        }
        Ok(plans)
    }

    /// Reconcile configured Guest source endpoints and the host sink.
    pub fn reconcile_sources(
        &mut self,
        display: &DisplayDependencyEvidence,
        config: &NotificationProviderConfig,
        source_sessions: &[SessionEvidence],
    ) -> Result<SourceReconcileResult, &'static str> {
        let result = match self.plan_reconciliation(display, config, source_sessions) {
            Ok(result) => result,
            Err(error) => {
                self.clear_reconciliation();
                return Err(error);
            }
        };
        let source_error = result.source_error;
        self.commit_reconciliation(display, config, result.clone())?;
        source_error.map_or(Ok(result), Err)
    }

    /// Reconcile Guest sources through an effect port, committing ownership
    /// only after process effects succeed.
    pub fn reconcile_sources_with_effects<E: SourceProcessEffectPort>(
        &mut self,
        display: &DisplayDependencyEvidence,
        config: &NotificationProviderConfig,
        source_sessions: &[SessionEvidence],
        effects: &mut E,
    ) -> Result<SourceReconcileResult, &'static str> {
        let result = match self.plan_reconciliation(display, config, source_sessions) {
            Ok(result) => result,
            Err(error) => {
                self.apply_drain_with_effects(config, effects)?;
                return Err(error);
            }
        };
        let receipt = self.apply_with_effects(Some(display), config, &result, effects)?;
        if !receipt.matches(&result) {
            return Err("notification-process-effect-proof-mismatch");
        }
        let source_error = result.source_error;
        self.commit_reconciliation(display, config, result.clone())?;
        source_error.map_or(Ok(result), Err)
    }

    fn plan_reconciliation(
        &self,
        display: &DisplayDependencyEvidence,
        config: &NotificationProviderConfig,
        source_sessions: &[SessionEvidence],
    ) -> Result<SourceReconcileResult, &'static str> {
        self.plan(display, config)?;
        let mut endpoints = Vec::new();
        let mut source_error = None;
        if display.is_ready() {
            for source in config.guest_sources() {
                let mut matches = source_sessions
                    .iter()
                    .filter(|session| session.subject_ref() == source.source_ref());
                let Some(session) = matches.next() else {
                    source_error.get_or_insert("notification-source-unauthenticated");
                    continue;
                };
                if matches.next().is_some() {
                    source_error.get_or_insert("notification-source-ambiguous");
                    continue;
                }
                match SourceEndpoint::from_authenticated(source, session, display) {
                    Ok(endpoint) => endpoints.push(endpoint),
                    Err(error) => {
                        source_error.get_or_insert(error);
                    }
                }
            }
        }
        let configured = if source_error.is_some() {
            // A partial authenticated source set must never start the subset
            // that happened to validate.  Drain all owned source processes
            // until every configured source has fresh, unambiguous evidence.
            std::collections::BTreeMap::new()
        } else {
            endpoints
                .into_iter()
                .map(|endpoint| (endpoint.source_ref().clone(), endpoint))
                .collect::<std::collections::BTreeMap<_, _>>()
        };
        let start = configured
            .iter()
            .filter(|(source, endpoint)| {
                self.active_sources
                    .get(*source)
                    .is_none_or(|active| active != *endpoint)
            })
            .map(|(source, _)| source.clone())
            .collect::<Vec<_>>();
        let stop = self
            .active_sources
            .iter()
            .filter(|(source, active)| {
                configured
                    .get(*source)
                    .is_none_or(|endpoint| endpoint != *active)
            })
            .map(|(source, _)| source.clone())
            .collect::<Vec<_>>();
        let start_endpoints = start
            .iter()
            .filter_map(|source| configured.get(source).cloned())
            .collect::<Vec<_>>();
        let stop_endpoints = stop
            .iter()
            .filter_map(|source| self.active_sources.get(source).cloned())
            .collect::<Vec<_>>();
        let display_fingerprint = display_fingerprint(display);
        let host_sink_fingerprint = sink_fingerprint(config);
        let generation_changed = self
            .active_display_fingerprint
            .is_some_and(|fingerprint| fingerprint != display_fingerprint);
        let stop_host_sink = self.host_sink_fingerprint.is_some()
            && (!config.dbus_sink_enabled()
                || !display.is_ready()
                || generation_changed
                || self.host_sink_fingerprint != Some(host_sink_fingerprint));
        let start_host_sink = config.dbus_sink_enabled()
            && display.is_ready()
            && (generation_changed || self.host_sink_fingerprint != Some(host_sink_fingerprint));
        let result = SourceReconcileResult {
            start,
            stop,
            start_host_sink,
            stop_host_sink,
            start_endpoints,
            stop_endpoints,
            display_fingerprint,
            host_sink_fingerprint,
            source_error,
        };
        Ok(result)
    }

    fn drain_plan(&self) -> SourceReconcileResult {
        SourceReconcileResult {
            start: Vec::new(),
            stop: self.active_sources.keys().cloned().collect(),
            start_host_sink: false,
            stop_host_sink: self.host_sink_fingerprint.is_some(),
            start_endpoints: Vec::new(),
            stop_endpoints: self.active_sources.values().cloned().collect(),
            display_fingerprint: [0; 32],
            host_sink_fingerprint: [0; 32],
            source_error: None,
        }
    }

    fn clear_reconciliation(&mut self) {
        self.active_sources.clear();
        self.active_display_fingerprint = None;
        self.host_sink_fingerprint = None;
        self.active_host_sink = None;
    }

    fn apply_drain_with_effects<E: SourceProcessEffectPort>(
        &mut self,
        config: &NotificationProviderConfig,
        effects: &mut E,
    ) -> Result<(), &'static str> {
        let result = self.drain_plan();
        let receipt = self.apply_with_effects(None, config, &result, effects)?;
        if !receipt.matches(&result) {
            return Err("notification-process-effect-proof-mismatch");
        }
        self.clear_reconciliation();
        Ok(())
    }

    fn source_lifecycle_identity(
        &self,
        endpoint: &SourceEndpoint,
    ) -> Result<NotificationSourceIdentity, &'static str> {
        NotificationSourceIdentity::new(
            endpoint.zone().clone(),
            self.provider_ref.clone(),
            endpoint.source_ref().clone(),
            endpoint.source_generation(),
            endpoint.display_generation(),
            endpoint.endpoint_digest(),
        )
    }

    fn host_sink_identity(
        &self,
        display: &DisplayDependencyEvidence,
        config: &NotificationProviderConfig,
    ) -> Result<NotificationHostSinkIdentity, &'static str> {
        NotificationHostSinkIdentity::new(
            display.zone().clone(),
            self.provider_ref.clone(),
            config
                .host_execution_ref()
                .ok_or("notification-host-binding-missing")?
                .clone(),
            config
                .host_user_ref()
                .ok_or("notification-host-binding-missing")?
                .clone(),
            display.provider_ref().clone(),
            display.generation(),
            display.controller_generation(),
        )
    }

    fn lifecycle_plan(
        &self,
        display: Option<&DisplayDependencyEvidence>,
        config: &NotificationProviderConfig,
        result: &SourceReconcileResult,
    ) -> Result<Option<NotificationLifecyclePlan>, &'static str> {
        if result.start_endpoints.is_empty()
            && result.stop_endpoints.is_empty()
            && !result.start_host_sink
            && !result.stop_host_sink
        {
            return Ok(None);
        }
        let start_sources = result
            .start_endpoints
            .iter()
            .map(|endpoint| self.source_lifecycle_identity(endpoint))
            .collect::<Result<Vec<_>, _>>()?;
        let stop_sources = result
            .stop_endpoints
            .iter()
            .map(|endpoint| self.source_lifecycle_identity(endpoint))
            .collect::<Result<Vec<_>, _>>()?;
        let start_host_sink = result
            .start_host_sink
            .then(|| {
                self.host_sink_identity(
                    display.ok_or("notification-display-dependency-unavailable")?,
                    config,
                )
            })
            .transpose()?;
        let stop_host_sink = result
            .stop_host_sink
            .then(|| {
                self.active_host_sink
                    .clone()
                    .ok_or("notification-lifecycle-host-sink-missing")
            })
            .transpose()?;
        let zone = display
            .map(|display| display.zone().clone())
            .or_else(|| start_sources.first().map(|source| source.zone().clone()))
            .or_else(|| stop_sources.first().map(|source| source.zone().clone()))
            .or_else(|| stop_host_sink.as_ref().map(|sink| sink.zone().clone()))
            .ok_or("notification-lifecycle-zone-unavailable")?;
        Ok(Some(NotificationLifecyclePlan::new(
            zone,
            self.provider_ref.clone(),
            start_sources,
            stop_sources,
            start_host_sink,
            stop_host_sink,
        )?))
    }

    fn apply_with_effects<E: SourceProcessEffectPort>(
        &self,
        display: Option<&DisplayDependencyEvidence>,
        config: &NotificationProviderConfig,
        result: &SourceReconcileResult,
        effects: &mut E,
    ) -> Result<SourceProcessEffectReceipt, &'static str> {
        match self.lifecycle_plan(display, config, result)? {
            Some(lifecycle) => effects.apply(result, &lifecycle),
            None => SourceProcessEffectReceipt::no_effects(result),
        }
    }

    fn commit_reconciliation(
        &mut self,
        display: &DisplayDependencyEvidence,
        config: &NotificationProviderConfig,
        result: SourceReconcileResult,
    ) -> Result<(), &'static str> {
        for source in result.stop {
            self.active_sources.remove(&source);
        }
        for endpoint in result.start_endpoints {
            self.active_sources
                .insert(endpoint.source_ref().clone(), endpoint);
        }
        let fingerprint = display.is_ready().then(|| display_fingerprint(display));
        self.active_display_fingerprint = fingerprint;
        if result.stop_host_sink {
            self.host_sink_fingerprint = None;
            self.active_host_sink = None;
        }
        if result.start_host_sink {
            self.host_sink_fingerprint = Some(result.host_sink_fingerprint);
            self.active_host_sink = Some(self.host_sink_identity(display, config)?);
        }
        Ok(())
    }

    /// Reconcile from a Core-authenticated display route.
    ///
    /// `None` is the fail-closed dependency state and drains every owned
    /// source/sink endpoint. A route is accepted only when the sealed
    /// ComponentSession authority has bound the display Provider, local Unix
    /// evidence, a User subject, and a non-zero Provider generation.
    pub fn reconcile_authenticated_display(
        &mut self,
        display: Option<AuthenticatedSessionRouteBinding>,
        config: &NotificationProviderConfig,
        source_sessions: &[SessionEvidence],
    ) -> Result<SourceReconcileResult, &'static str> {
        let Some(proof) = display else {
            let result = self.drain_plan();
            self.clear_reconciliation();
            return Ok(result);
        };
        let evidence = match DisplayDependencyEvidence::from_authenticated_route(proof) {
            Ok(evidence) => evidence,
            Err(error) => {
                self.clear_reconciliation();
                return Err(error);
            }
        };
        self.reconcile_sources(&evidence, config, source_sessions)
    }

    /// Reconcile display and Guest-source ownership through the effect
    /// boundary, including fail-closed cleanup when the dependency vanishes.
    pub fn reconcile_authenticated_display_with_effects<E: SourceProcessEffectPort>(
        &mut self,
        display: Option<AuthenticatedSessionRouteBinding>,
        config: &NotificationProviderConfig,
        source_sessions: &[SessionEvidence],
        effects: &mut E,
    ) -> Result<SourceReconcileResult, &'static str> {
        let Some(proof) = display else {
            let result = self.drain_plan();
            let receipt = self.apply_with_effects(None, config, &result, effects)?;
            if !receipt.matches(&result) {
                return Err("notification-process-effect-proof-mismatch");
            }
            self.clear_reconciliation();
            return Ok(result);
        };
        let evidence = match DisplayDependencyEvidence::from_authenticated_route(proof) {
            Ok(evidence) => evidence,
            Err(error) => {
                self.apply_drain_with_effects(config, effects)?;
                return Err(error);
            }
        };
        self.reconcile_sources_with_effects(&evidence, config, source_sessions, effects)
    }

    /// Reconcile daemon-retained Guest display routes with Core's Host User
    /// binding while preserving all normal readiness and generation checks.
    pub fn reconcile_daemon_display_with_effects<E: SourceProcessEffectPort>(
        &mut self,
        display: Option<AuthenticatedSessionRouteBinding>,
        config: &NotificationProviderConfig,
        source_sessions: &[SessionEvidence],
        effects: &mut E,
    ) -> Result<SourceReconcileResult, &'static str> {
        let Some(proof) = display else {
            let result = self.drain_plan();
            let receipt = self.apply_with_effects(None, config, &result, effects)?;
            if !receipt.matches(&result) {
                return Err("notification-process-effect-proof-mismatch");
            }
            self.clear_reconciliation();
            return Ok(result);
        };
        let user_ref = config
            .host_user_ref()
            .ok_or("notification-host-binding-missing")?
            .clone();
        let evidence = match DisplayDependencyEvidence::from_daemon_route(proof, user_ref) {
            Ok(evidence) => evidence,
            Err(error) => {
                self.apply_drain_with_effects(config, effects)?;
                return Err(error);
            }
        };
        self.reconcile_sources_with_effects(&evidence, config, source_sessions, effects)
    }

    /// Drain and forget all source endpoints during shutdown or finalization.
    pub fn drain_sources(&mut self) -> Vec<ResourceRef> {
        let drained = self.active_sources.keys().cloned().collect();
        self.clear_reconciliation();
        drained
    }

    /// Notification state is transient and never has a Provider state Volume.
    pub const fn provider_state_set_empty(&self) -> bool {
        true
    }

    /// Borrow the exact Provider reference.
    pub const fn provider_ref(&self) -> &ResourceRef {
        &self.provider_ref
    }
}

impl core::fmt::Debug for NotificationController {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("NotificationController(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::{test_source, test_source_at};

    fn display(state: DisplayDependencyState) -> DisplayDependencyEvidence {
        DisplayDependencyEvidence {
            provider_ref: ResourceRef::parse(DISPLAY_PROVIDER_REF).unwrap(),
            zone: ZoneId::parse("work").unwrap(),
            host_execution_ref: ResourceRef::parse("Host/host-system").unwrap(),
            user_ref: ResourceRef::parse("User/alice").unwrap(),
            provider_generation: 4,
            reconnect_generation: 2,
            controller_generation: 3,
            state,
        }
    }

    fn source(name: &str) -> GuestSourceConfig {
        GuestSourceConfig::new(
            ResourceRef::parse(format!("Guest/{name}").as_str()).unwrap(),
            ZoneId::parse("work").unwrap(),
            [Category::SystemInfo],
        )
        .unwrap()
    }

    fn bound_config(sources: Vec<GuestSourceConfig>) -> NotificationProviderConfig {
        NotificationProviderConfig::new(sources)
            .unwrap()
            .with_host_binding(
                ResourceRef::parse("Host/host-system").unwrap(),
                ResourceRef::parse("User/alice").unwrap(),
            )
            .unwrap()
            .with_display_wayland_ref(Some(ResourceRef::parse(DISPLAY_PROVIDER_REF).unwrap()))
            .unwrap()
    }

    #[test]
    fn planning_requires_ready_same_zone_display_evidence() {
        let controller = NotificationController::new(crate::PROVIDER_REF).unwrap();
        let config = bound_config(vec![source("one")]);
        let pending_plans = controller
            .plan(&display(DisplayDependencyState::Pending), &config)
            .unwrap();
        assert_eq!(pending_plans.len(), 1);
        assert!(
            pending_plans
                .iter()
                .all(|plan| plan.template != "notification-desktop-host-sink")
        );
        let wrong_zone = GuestSourceConfig::new(
            ResourceRef::parse("Guest/two").unwrap(),
            ZoneId::parse("personal").unwrap(),
            [Category::SystemInfo],
        )
        .unwrap();
        let wrong_zone_config = bound_config(vec![wrong_zone]);
        assert_eq!(
            controller.plan(&display(DisplayDependencyState::Ready), &wrong_zone_config),
            Err("notification-source-zone-mismatch")
        );
    }

    #[test]
    fn configured_display_dependency_is_exact_and_bounded() {
        let base = NotificationProviderConfig::new(Vec::new()).unwrap();
        assert_eq!(
            base.clone()
                .with_display_wayland_ref(Some(ResourceRef::parse("Provider/another").unwrap())),
            Err("notification-display-provider-invalid")
        );
        assert_eq!(
            base.clone().with_max_pending_notifications(7).unwrap_err(),
            "notification-pending-capacity"
        );
        assert_eq!(
            base.clone().with_action_nonce_ttl_secs(29).unwrap_err(),
            "notification-action-nonce-ttl"
        );
        assert_eq!(
            base.with_action_nonce_store_size(63).unwrap_err(),
            "notification-action-nonce-capacity"
        );
    }

    #[test]
    fn ready_sink_requires_the_configured_display_dependency() {
        let controller = NotificationController::new(crate::PROVIDER_REF).unwrap();
        let config = NotificationProviderConfig::new(Vec::new())
            .unwrap()
            .with_host_binding(
                ResourceRef::parse("Host/host-system").unwrap(),
                ResourceRef::parse("User/alice").unwrap(),
            )
            .unwrap();
        assert_eq!(
            controller.plan(&display(DisplayDependencyState::Ready), &config),
            Err("notification-display-provider-mismatch")
        );
    }

    #[test]
    fn disabled_dbus_sink_never_plans_or_restarts_the_host_sink() {
        let mut controller = NotificationController::new(crate::PROVIDER_REF).unwrap();
        let config = bound_config(vec![source("one")]).with_dbus_sink_enabled(false);
        let dependency = display(DisplayDependencyState::Ready);
        let plans = controller.plan(&dependency, &config).unwrap();
        assert!(
            plans
                .iter()
                .all(|plan| plan.template != "notification-desktop-host-sink")
        );
        let result = controller
            .reconcile_sources(&dependency, &config, &[test_source("one")])
            .unwrap();
        assert!(!result.start_host_sink);
        assert!(!result.stop_host_sink);
    }

    #[test]
    fn source_reconciliation_starts_stops_and_drains_exact_endpoints() {
        let mut controller = NotificationController::new(crate::PROVIDER_REF).unwrap();
        let first = bound_config(vec![source("one")]);
        let second = bound_config(vec![source("two")]);
        let dependency = display(DisplayDependencyState::Ready);
        let first_result = controller
            .reconcile_sources(&dependency, &first, &[test_source("one")])
            .unwrap();
        assert_eq!(
            first_result.start,
            vec![ResourceRef::parse("Guest/one").unwrap()]
        );
        assert!(first_result.start_host_sink);
        assert!(!first_result.stop_host_sink);
        assert_eq!(
            controller
                .reconcile_sources(&dependency, &second, &[test_source("two")])
                .unwrap()
                .stop,
            vec![ResourceRef::parse("Guest/one").unwrap()]
        );
        let restarted = controller
            .reconcile_sources(
                &display(DisplayDependencyState::Ready),
                &second,
                &[test_source("two")],
            )
            .unwrap();
        assert!(!restarted.start_host_sink);
        assert!(!restarted.stop_host_sink);
        let changed_display = DisplayDependencyEvidence {
            controller_generation: 4,
            ..dependency.clone()
        };
        let route_restarted = controller
            .reconcile_sources(&changed_display, &second, &[test_source("two")])
            .unwrap();
        assert!(route_restarted.start_host_sink);
        assert!(route_restarted.stop_host_sink);
        let unavailable = controller
            .reconcile_sources(&display(DisplayDependencyState::Pending), &second, &[])
            .unwrap();
        assert!(unavailable.stop_host_sink);
        let recovered = controller
            .reconcile_sources(
                &display(DisplayDependencyState::Ready),
                &second,
                &[test_source("two")],
            )
            .unwrap();
        assert!(recovered.start_host_sink);
        assert_eq!(
            controller.drain_sources(),
            vec![ResourceRef::parse("Guest/two").unwrap()]
        );
        assert!(controller.drain_sources().is_empty());
    }

    #[test]
    fn source_generation_change_drains_and_restarts_the_exact_endpoint() {
        let mut controller = NotificationController::new(crate::PROVIDER_REF).unwrap();
        let config = bound_config(vec![source("one")]);
        let dependency = display(DisplayDependencyState::Ready);
        controller
            .reconcile_sources(&dependency, &config, &[test_source("one")])
            .unwrap();
        let changed = controller
            .reconcile_sources(&dependency, &config, &[test_source_at("one", 2)])
            .unwrap();
        assert_eq!(
            changed.start,
            vec![ResourceRef::parse("Guest/one").unwrap()]
        );
        assert_eq!(changed.stop, vec![ResourceRef::parse("Guest/one").unwrap()]);
        assert_eq!(changed.start_endpoints[0].source_generation(), 2);
        assert_eq!(changed.stop_endpoints[0].source_generation(), 1);
    }

    #[test]
    fn duplicate_authenticated_source_sessions_are_rejected() {
        let mut controller = NotificationController::new(crate::PROVIDER_REF).unwrap();
        let config = bound_config(vec![source("one")]);
        let dependency = display(DisplayDependencyState::Ready);
        assert_eq!(
            controller.reconcile_sources(
                &dependency,
                &config,
                &[test_source_at("one", 1), test_source_at("one", 2)],
            ),
            Err("notification-source-ambiguous")
        );
    }

    struct FailingEffects;

    impl SourceProcessEffectPort for FailingEffects {
        fn apply(
            &mut self,
            _plan: &SourceReconcileResult,
            _lifecycle: &NotificationLifecyclePlan,
        ) -> Result<SourceProcessEffectReceipt, &'static str> {
            Err("process-effect-failed")
        }
    }

    struct CompletingEffects;

    impl SourceProcessEffectPort for CompletingEffects {
        fn apply(
            &mut self,
            plan: &SourceReconcileResult,
            _lifecycle: &NotificationLifecyclePlan,
        ) -> Result<SourceProcessEffectReceipt, &'static str> {
            Ok(SourceProcessEffectReceipt::complete(plan))
        }
    }

    #[test]
    fn missing_authenticated_source_stops_owned_endpoint_before_refusing() {
        let mut controller = NotificationController::new(crate::PROVIDER_REF).unwrap();
        let config = bound_config(vec![source("one")]);
        let dependency = display(DisplayDependencyState::Ready);
        controller
            .reconcile_sources(&dependency, &config, &[test_source("one")])
            .unwrap();
        let mut effects = CompletingEffects;
        assert_eq!(
            controller.reconcile_sources_with_effects(&dependency, &config, &[], &mut effects),
            Err("notification-source-unauthenticated")
        );
        assert!(controller.drain_sources().is_empty());
    }

    struct RecordingEffects {
        plans: Vec<SourceReconcileResult>,
    }

    impl SourceProcessEffectPort for RecordingEffects {
        fn apply(
            &mut self,
            plan: &SourceReconcileResult,
            _lifecycle: &NotificationLifecyclePlan,
        ) -> Result<SourceProcessEffectReceipt, &'static str> {
            self.plans.push(plan.clone());
            Ok(SourceProcessEffectReceipt::complete(plan))
        }
    }

    #[test]
    fn partial_source_evidence_drains_without_starting_a_valid_subset() {
        let mut controller = NotificationController::new(crate::PROVIDER_REF).unwrap();
        let config = bound_config(vec![source("one"), source("two")]);
        let dependency = display(DisplayDependencyState::Ready);
        controller
            .reconcile_sources(
                &dependency,
                &bound_config(vec![source("one")]),
                &[test_source("one")],
            )
            .unwrap();
        let mut effects = RecordingEffects { plans: Vec::new() };
        assert_eq!(
            controller.reconcile_sources_with_effects(
                &dependency,
                &config,
                &[test_source("one")],
                &mut effects,
            ),
            Err("notification-source-unauthenticated")
        );
        let plan = &effects.plans[0];
        assert!(plan.start.is_empty());
        assert_eq!(plan.stop, vec![ResourceRef::parse("Guest/one").unwrap()]);
        assert!(plan.start_endpoints.is_empty());
        assert_eq!(
            plan.stop_endpoints
                .iter()
                .map(|endpoint| endpoint.source_ref().clone())
                .collect::<Vec<_>>(),
            vec![ResourceRef::parse("Guest/one").unwrap()]
        );
    }

    #[test]
    fn sink_policy_changes_restart_the_owned_host_sink() {
        let mut controller = NotificationController::new(crate::PROVIDER_REF).unwrap();
        let config = bound_config(vec![source("one")]);
        let dependency = display(DisplayDependencyState::Ready);
        controller
            .reconcile_sources(&dependency, &config, &[test_source("one")])
            .unwrap();
        let changed = config.clone().with_observer_enabled(false);
        let result = controller
            .reconcile_sources(&dependency, &changed, &[test_source("one")])
            .unwrap();
        assert!(result.stop_host_sink);
        assert!(result.start_host_sink);
    }

    #[test]
    fn reconciliation_commits_source_ownership_only_after_effects_succeed() {
        let mut controller = NotificationController::new(crate::PROVIDER_REF).unwrap();
        let first = bound_config(vec![source("one")]);
        let second = bound_config(vec![source("two")]);
        let dependency = display(DisplayDependencyState::Ready);
        controller
            .reconcile_sources(&dependency, &first, &[test_source("one")])
            .unwrap();
        let mut effects = FailingEffects;
        assert_eq!(
            controller.reconcile_sources_with_effects(
                &dependency,
                &second,
                &[test_source("two")],
                &mut effects,
            ),
            Err("process-effect-failed")
        );
        let retry = controller
            .reconcile_sources(&dependency, &second, &[test_source("two")])
            .unwrap();
        assert_eq!(retry.stop, vec![ResourceRef::parse("Guest/one").unwrap()]);
        assert_eq!(retry.start, vec![ResourceRef::parse("Guest/two").unwrap()]);
    }

    #[test]
    fn effect_receipts_bind_to_the_complete_plan_digest() {
        let plan = SourceReconcileResult {
            start: Vec::new(),
            stop: Vec::new(),
            start_host_sink: true,
            stop_host_sink: false,
            start_endpoints: Vec::new(),
            stop_endpoints: Vec::new(),
            display_fingerprint: [7; 32],
            host_sink_fingerprint: [8; 32],
            source_error: None,
        };
        let receipt = SourceProcessEffectReceipt::complete(&plan);
        assert!(receipt.matches(&plan));
        assert_eq!(
            SourceProcessEffectReceipt::builder(&plan).finish(),
            Err("notification-process-effect-incomplete")
        );
        let changed = SourceReconcileResult {
            stop_host_sink: true,
            ..plan
        };
        assert!(!receipt.matches(&changed));
    }
}
