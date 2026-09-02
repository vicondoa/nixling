//! Canonical controller registration, identity, target, and trigger contracts.

use std::collections::BTreeSet;

use d2b_contracts_resource::v3::{
    ControllerGeneration, ResourceGeneration, ResourceRef, ResourceTypeName, ResourceUid, ZoneId,
};

use crate::ContextError;

/// Closed reason set used for queue coalescing and dispatch selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TriggerReason {
    SpecGenerationChanged,
    OwnedResourceChanged,
    DependencyChanged,
    DependencyReady,
    DeletionRequested,
    FinalizerRequired,
    ControllerGenerationChanged,
    ProviderGenerationChanged,
    PolicyChanged,
    SecurityPolicyChanged,
    ArtifactOrImageChanged,
    ExecutionStatusChanged,
    ScheduledObserve,
    AssessUpdateDue,
    UpgradeRequested,
    ExpeditedMutation,
    RetryDue,
    ManualReconcile,
    StartupRelist,
}

impl TriggerReason {
    /// Whether this reason must survive convergence suppression.
    pub const fn is_non_droppable(self) -> bool {
        matches!(
            self,
            Self::SpecGenerationChanged
                | Self::OwnedResourceChanged
                | Self::DeletionRequested
                | Self::FinalizerRequired
                | Self::ControllerGenerationChanged
                | Self::ProviderGenerationChanged
                | Self::PolicyChanged
                | Self::SecurityPolicyChanged
                | Self::DependencyChanged
                | Self::DependencyReady
                | Self::ScheduledObserve
                | Self::AssessUpdateDue
                | Self::UpgradeRequested
                | Self::ExpeditedMutation
                | Self::RetryDue
                | Self::ManualReconcile
        )
    }

    /// Whether this reason requires the update-currency assessment path.
    pub const fn requires_update_assessment(self) -> bool {
        matches!(
            self,
            Self::SpecGenerationChanged
                | Self::ControllerGenerationChanged
                | Self::ProviderGenerationChanged
                | Self::SecurityPolicyChanged
                | Self::ArtifactOrImageChanged
                | Self::DependencyChanged
                | Self::AssessUpdateDue
        )
    }
}

/// Deterministic, duplicate-free trigger collection.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TriggerSet(BTreeSet<TriggerReason>);

impl TriggerSet {
    /// Construct a reason set from an iterator.
    pub fn new(reasons: impl IntoIterator<Item = TriggerReason>) -> Self {
        Self(reasons.into_iter().collect())
    }

    /// Add one reason.
    pub fn insert(&mut self, reason: TriggerReason) {
        self.0.insert(reason);
    }

    /// Merge all reasons from another admitted hint.
    pub fn union_with(&mut self, other: &Self) {
        self.0.extend(other.0.iter().copied());
    }

    /// Test whether a reason is present.
    pub fn contains(&self, reason: TriggerReason) -> bool {
        self.0.contains(&reason)
    }

    /// Return the number of distinct reasons.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether no reason is present.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterate in stable enum order.
    pub fn iter(&self) -> impl Iterator<Item = TriggerReason> + '_ {
        self.0.iter().copied()
    }

    /// Whether any reason requires update assessment.
    pub fn requires_update_assessment(&self) -> bool {
        self.0
            .iter()
            .any(|reason| reason.requires_update_assessment())
    }
}

impl From<BTreeSet<TriggerReason>> for TriggerSet {
    fn from(reasons: BTreeSet<TriggerReason>) -> Self {
        Self(reasons)
    }
}

impl From<TriggerSet> for BTreeSet<TriggerReason> {
    fn from(reasons: TriggerSet) -> Self {
        reasons.0
    }
}

/// Immutable identity for one resource incarnation.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResourceKey {
    zone: ZoneId,
    resource_ref: ResourceRef,
    uid: ResourceUid,
}

impl ResourceKey {
    /// Construct a Zone-local resource key.
    pub fn new(zone: ZoneId, resource_ref: ResourceRef, uid: ResourceUid) -> Self {
        Self {
            zone,
            resource_ref,
            uid,
        }
    }

    /// Borrow the Zone identity.
    pub const fn zone(&self) -> &ZoneId {
        &self.zone
    }

    /// Borrow the canonical resource reference.
    pub const fn resource_ref(&self) -> &ResourceRef {
        &self.resource_ref
    }

    /// Borrow the immutable resource UID.
    pub const fn uid(&self) -> &ResourceUid {
        &self.uid
    }
}

impl core::fmt::Debug for ResourceKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ResourceKey")
            .field("resource_type", self.resource_ref.resource_type())
            .field("has_zone", &true)
            .field("has_uid", &true)
            .finish()
    }
}

/// Authenticated controller and execution identity fixed at registration.
#[derive(Clone, PartialEq, Eq)]
pub struct ControllerIdentity {
    zone: ZoneId,
    controller_ref: ResourceRef,
    controller_generation: ControllerGeneration,
    provider_ref: ResourceRef,
    provider_generation: ResourceGeneration,
    process_ref: ResourceRef,
    host_ref: ResourceRef,
    guest_ref: Option<ResourceRef>,
}

impl ControllerIdentity {
    /// Construct an identity whose Zone is fixed by the registered session.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        zone: ZoneId,
        controller_ref: ResourceRef,
        controller_generation: ControllerGeneration,
        provider_ref: ResourceRef,
        provider_generation: ResourceGeneration,
        process_ref: ResourceRef,
        host_ref: ResourceRef,
        guest_ref: Option<ResourceRef>,
    ) -> Result<Self, ContextError> {
        if controller_ref.resource_type().as_str() != "Process"
            || provider_ref.resource_type().as_str() != "Provider"
            || process_ref.resource_type().as_str() != "Process"
            || host_ref.resource_type().as_str() != "Host"
            || guest_ref
                .as_ref()
                .is_some_and(|guest| guest.resource_type().as_str() != "Guest")
        {
            return Err(ContextError::InvalidControllerIdentity);
        }
        Ok(Self {
            zone,
            controller_ref,
            controller_generation,
            provider_ref,
            provider_generation,
            process_ref,
            host_ref,
            guest_ref,
        })
    }

    /// Borrow the authenticated Zone.
    pub const fn zone(&self) -> &ZoneId {
        &self.zone
    }

    /// Borrow the registered controller resource reference.
    pub const fn controller_ref(&self) -> &ResourceRef {
        &self.controller_ref
    }

    /// Return the controller generation.
    pub const fn controller_generation(&self) -> ControllerGeneration {
        self.controller_generation
    }

    /// Return the Provider generation.
    pub const fn provider_generation(&self) -> ResourceGeneration {
        self.provider_generation
    }

    /// Borrow the Provider reference bound to this controller session.
    pub const fn provider_ref(&self) -> &ResourceRef {
        &self.provider_ref
    }
}

impl core::fmt::Debug for ControllerIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ControllerIdentity")
            .field("controller_type", self.controller_ref.resource_type())
            .field("controller_generation", &self.controller_generation)
            .field("provider_type", self.provider_ref.resource_type())
            .field("provider_generation", &self.provider_generation)
            .field("process_type", self.process_ref.resource_type())
            .field("host_type", self.host_ref.resource_type())
            .field(
                "guest_type",
                &self.guest_ref.as_ref().map(ResourceRef::resource_type),
            )
            .field("has_zone", &true)
            .finish()
    }
}

/// Resource fields accepted by exact controller selectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SelectorField {
    Spec,
    Status,
    Metadata,
    Finalizers,
    Deletion,
}

/// One exact watch or dependency selector.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ControllerSelector {
    resource_type: ResourceTypeName,
    field: SelectorField,
    exact_value: Option<String>,
}

impl ControllerSelector {
    /// Construct an exact or whole-field selector.
    pub fn new(
        resource_type: ResourceTypeName,
        field: SelectorField,
        exact_value: Option<String>,
    ) -> Result<Self, DescriptorError> {
        if exact_value
            .as_ref()
            .is_some_and(|value| !valid_token(value, 256))
        {
            return Err(DescriptorError::InvalidSelector);
        }
        Ok(Self {
            resource_type,
            field,
            exact_value,
        })
    }

    /// Borrow the selected ResourceType.
    pub const fn resource_type(&self) -> &ResourceTypeName {
        &self.resource_type
    }

    /// Return the selected field.
    pub const fn field(&self) -> SelectorField {
        self.field
    }

    /// Borrow the exact selector value, if one is required.
    pub fn exact_value(&self) -> Option<&str> {
        self.exact_value.as_deref()
    }
}

impl core::fmt::Debug for ControllerSelector {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ControllerSelector")
            .field("resource_type", &self.resource_type)
            .field("field", &self.field)
            .field("has_exact_value", &self.exact_value.is_some())
            .finish()
    }
}

/// Closed mutation permissions declared at registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ControllerVerb {
    ReadSpec,
    WriteSpec,
    ReadStatus,
    WriteStatus,
    AddFinalizer,
    RemoveFinalizer,
}

/// One owned ResourceType version and its deadline/retry policy.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResourceRegistration {
    resource_type: ResourceTypeName,
    versions: Vec<u32>,
    deadline_ticks: u64,
    max_attempts: u32,
}

impl ResourceRegistration {
    /// Construct a bounded ResourceType registration.
    pub fn new(
        resource_type: ResourceTypeName,
        mut versions: Vec<u32>,
        deadline_ticks: u64,
        max_attempts: u32,
    ) -> Result<Self, DescriptorError> {
        versions.sort_unstable();
        let original_len = versions.len();
        versions.dedup();
        if versions.is_empty()
            || versions.len() != original_len
            || versions.contains(&0)
            || deadline_ticks == 0
            || max_attempts == 0
        {
            return Err(DescriptorError::InvalidResource);
        }
        Ok(Self {
            resource_type,
            versions,
            deadline_ticks,
            max_attempts,
        })
    }

    /// Borrow the registered ResourceType.
    pub const fn resource_type(&self) -> &ResourceTypeName {
        &self.resource_type
    }

    /// Borrow supported schema versions.
    pub fn versions(&self) -> &[u32] {
        &self.versions
    }

    /// Return the per-pass deadline in monotonic ticks.
    pub const fn deadline_ticks(&self) -> u64 {
        self.deadline_ticks
    }

    /// Return the retry attempt bound.
    pub const fn max_attempts(&self) -> u32 {
        self.max_attempts
    }
}

/// Observe and authoritative resync cadence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResyncPolicy {
    observe_interval_ticks: Option<u64>,
    resync_interval_ticks: u64,
}

impl ResyncPolicy {
    /// Construct a nonzero resync policy.
    pub fn new(
        observe_interval_ticks: Option<u64>,
        resync_interval_ticks: u64,
    ) -> Result<Self, DescriptorError> {
        if resync_interval_ticks == 0 || observe_interval_ticks == Some(0) {
            return Err(DescriptorError::InvalidExecution);
        }
        Ok(Self {
            observe_interval_ticks,
            resync_interval_ticks,
        })
    }

    /// Return optional observation cadence.
    pub const fn observe_interval_ticks(&self) -> Option<u64> {
        self.observe_interval_ticks
    }

    /// Return authoritative resync cadence.
    pub const fn resync_interval_ticks(&self) -> u64 {
        self.resync_interval_ticks
    }
}

/// Complete bounded execution and queue policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerExecutionPolicy {
    reconcile_concurrency: usize,
    observe_concurrency: usize,
    max_pending_resources: usize,
    max_expedited_per_resource: usize,
    initial_watch_credits: u32,
    resync: ResyncPolicy,
}

impl ControllerExecutionPolicy {
    /// Construct bounded execution policy.
    pub fn new(
        reconcile_concurrency: usize,
        observe_concurrency: usize,
        max_pending_resources: usize,
        max_expedited_per_resource: usize,
        initial_watch_credits: u32,
        resync: ResyncPolicy,
    ) -> Result<Self, DescriptorError> {
        if reconcile_concurrency == 0
            || observe_concurrency == 0
            || max_pending_resources == 0
            || max_expedited_per_resource == 0
            || initial_watch_credits == 0
            || reconcile_concurrency > max_pending_resources
            || observe_concurrency > max_pending_resources
        {
            return Err(DescriptorError::InvalidExecution);
        }
        Ok(Self {
            reconcile_concurrency,
            observe_concurrency,
            max_pending_resources,
            max_expedited_per_resource,
            initial_watch_credits,
            resync,
        })
    }

    /// Return the reconcile concurrency bound.
    pub const fn reconcile_concurrency(&self) -> usize {
        self.reconcile_concurrency
    }

    /// Return the observe concurrency bound.
    pub const fn observe_concurrency(&self) -> usize {
        self.observe_concurrency
    }

    /// Return the pending-resource bound.
    pub const fn max_pending_resources(&self) -> usize {
        self.max_pending_resources
    }

    /// Return the expedited per-resource bound.
    pub const fn max_expedited_per_resource(&self) -> usize {
        self.max_expedited_per_resource
    }

    /// Return initial watch credit.
    pub const fn initial_watch_credits(&self) -> u32 {
        self.initial_watch_credits
    }

    /// Return observe/resync policy.
    pub const fn resync(&self) -> ResyncPolicy {
        self.resync
    }
}

/// Complete signed controller registration shape.
#[derive(Clone, PartialEq, Eq)]
pub struct ControllerDescriptor {
    identity: ControllerIdentity,
    resources: Vec<ResourceRegistration>,
    provider_capabilities: Vec<String>,
    process_domains: Vec<String>,
    verbs: Vec<ControllerVerb>,
    watch_selectors: Vec<ControllerSelector>,
    dependency_selectors: Vec<ControllerSelector>,
    consumes_owner_triggers: bool,
    finalizers: Vec<String>,
    service_fingerprints: Vec<String>,
    schema_fingerprints: Vec<String>,
    execution: ControllerExecutionPolicy,
}

impl ControllerDescriptor {
    /// Construct the complete registration shape.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity: ControllerIdentity,
        mut resources: Vec<ResourceRegistration>,
        mut provider_capabilities: Vec<String>,
        mut process_domains: Vec<String>,
        mut verbs: Vec<ControllerVerb>,
        mut watch_selectors: Vec<ControllerSelector>,
        mut dependency_selectors: Vec<ControllerSelector>,
        consumes_owner_triggers: bool,
        mut finalizers: Vec<String>,
        mut service_fingerprints: Vec<String>,
        mut schema_fingerprints: Vec<String>,
        execution: ControllerExecutionPolicy,
    ) -> Result<Self, DescriptorError> {
        resources.sort();
        provider_capabilities.sort();
        process_domains.sort();
        verbs.sort();
        watch_selectors.sort();
        dependency_selectors.sort();
        finalizers.sort();
        service_fingerprints.sort();
        schema_fingerprints.sort();
        let owned: BTreeSet<_> = resources
            .iter()
            .map(|resource| resource.resource_type.clone())
            .collect();
        if resources.is_empty()
            || owned.len() != resources.len()
            || provider_capabilities.is_empty()
            || process_domains.is_empty()
            || verbs.is_empty()
            || watch_selectors.is_empty()
            || service_fingerprints.is_empty()
            || schema_fingerprints.is_empty()
            || !unique_tokens(&provider_capabilities, 128)
            || !unique_tokens(&process_domains, 128)
            || !unique_tokens(&finalizers, 256)
            || !unique_tokens(&service_fingerprints, 256)
            || !unique_tokens(&schema_fingerprints, 256)
            || !all_unique(&verbs)
            || !all_unique(&watch_selectors)
            || !all_unique(&dependency_selectors)
            || watch_selectors
                .iter()
                .any(|selector| !owned.contains(selector.resource_type()))
        {
            return Err(DescriptorError::InvalidRegistration);
        }
        Ok(Self {
            identity,
            resources,
            provider_capabilities,
            process_domains,
            verbs,
            watch_selectors,
            dependency_selectors,
            consumes_owner_triggers,
            finalizers,
            service_fingerprints,
            schema_fingerprints,
            execution,
        })
    }

    /// Borrow the registered identity.
    pub const fn identity(&self) -> &ControllerIdentity {
        &self.identity
    }

    /// Borrow ResourceType/version/retry declarations.
    pub fn resources(&self) -> &[ResourceRegistration] {
        &self.resources
    }

    /// Borrow owned ResourceTypes.
    pub fn resource_types(&self) -> impl Iterator<Item = &ResourceTypeName> {
        self.resources
            .iter()
            .map(ResourceRegistration::resource_type)
    }

    /// Borrow Provider capabilities.
    pub fn provider_capabilities(&self) -> &[String] {
        &self.provider_capabilities
    }

    /// Borrow supported process domains.
    pub fn process_domains(&self) -> &[String] {
        &self.process_domains
    }

    /// Borrow declared verbs.
    pub fn verbs(&self) -> &[ControllerVerb] {
        &self.verbs
    }

    /// Borrow exact watch selectors.
    pub fn watch_selectors(&self) -> &[ControllerSelector] {
        &self.watch_selectors
    }

    /// Borrow dependency selectors.
    pub fn dependency_selectors(&self) -> &[ControllerSelector] {
        &self.dependency_selectors
    }

    /// Whether owner-child triggers are consumed.
    pub const fn consumes_owner_triggers(&self) -> bool {
        self.consumes_owner_triggers
    }

    /// Borrow owned finalizers.
    pub fn finalizers(&self) -> &[String] {
        &self.finalizers
    }

    /// Borrow service fingerprints.
    pub fn service_fingerprints(&self) -> &[String] {
        &self.service_fingerprints
    }

    /// Borrow schema fingerprints.
    pub fn schema_fingerprints(&self) -> &[String] {
        &self.schema_fingerprints
    }

    /// Return the global handler semaphore bound.
    pub const fn reconcile_concurrency(&self) -> usize {
        self.execution.reconcile_concurrency()
    }

    /// Return the pending-resource bound.
    pub const fn max_pending_resources(&self) -> usize {
        self.execution.max_pending_resources()
    }

    /// Return the expedited per-resource bound.
    pub const fn max_expedited_per_resource(&self) -> usize {
        self.execution.max_expedited_per_resource()
    }

    /// Return initial watch credit.
    pub const fn initial_watch_credits(&self) -> u32 {
        self.execution.initial_watch_credits()
    }

    /// Return execution and resync policy.
    pub const fn execution(&self) -> &ControllerExecutionPolicy {
        &self.execution
    }
}

impl core::fmt::Debug for ControllerDescriptor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ControllerDescriptor")
            .field("identity", &self.identity)
            .field("resource_count", &self.resources.len())
            .field(
                "provider_capability_count",
                &self.provider_capabilities.len(),
            )
            .field("process_domain_count", &self.process_domains.len())
            .field("verb_count", &self.verbs.len())
            .field("watch_selector_count", &self.watch_selectors.len())
            .field(
                "dependency_selector_count",
                &self.dependency_selectors.len(),
            )
            .field("consumes_owner_triggers", &self.consumes_owner_triggers)
            .field("finalizer_count", &self.finalizers.len())
            .field(
                "service_fingerprint_count",
                &self.service_fingerprints.len(),
            )
            .field("schema_fingerprint_count", &self.schema_fingerprints.len())
            .field("execution", &self.execution)
            .finish()
    }
}

/// Invalid complete controller registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorError {
    InvalidSelector,
    InvalidResource,
    InvalidExecution,
    InvalidRegistration,
}

impl core::fmt::Display for DescriptorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::InvalidSelector => "controller selector is empty or oversized",
            Self::InvalidResource => "controller ResourceType policy is invalid",
            Self::InvalidExecution => "controller execution policy is invalid",
            Self::InvalidRegistration => "controller registration is empty, duplicated, or broad",
        })
    }
}

impl std::error::Error for DescriptorError {}

fn valid_token(value: &str, max_len: usize) -> bool {
    !value.is_empty() && value.len() <= max_len && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn unique_tokens(values: &[String], max_len: usize) -> bool {
    values.iter().all(|value| valid_token(value, max_len))
        && values.windows(2).all(|pair| pair[0] != pair[1])
}

fn all_unique<T: PartialEq>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] != pair[1])
}
