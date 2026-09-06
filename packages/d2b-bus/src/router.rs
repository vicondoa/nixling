//! Exact Zone router and the single-owner registration surface.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc, Mutex, MutexGuard, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use d2b_contracts_resource::v3::identity::{
    AuthenticatedSubjectContext, EvidenceClass, Locality, ServiceName, SessionBinding,
};
use d2b_contracts_resource::v3::process::PROCESS_RESOURCE_TYPE;
use d2b_contracts_resource::v3::{
    ControllerGeneration, MAX_FILTER_VALUES, MAX_LIST_FILTERS, MAX_LIST_RESOURCE_TYPES,
    ResourceGeneration, ResourceName, ResourceRef, ResourceTypeName, ResourceUid, ZoneId,
};
use d2b_core_controller::controller_assignment::{
    ASSIGNMENT_UID_FILTER, AssignmentIdentity, AssignmentVerb, OWNER_UID_FILTER,
    ScopedCommitTransport, ScopedResourceFilter, ScopedResourceMutation, ScopedResourceQuery,
    ScopedResourceScope,
};
use d2b_resource_api::authz::{
    ApiMethod, AuthorizationRequest, AuthorizationState, AuthorizationTarget, NativeAuthorizer,
    PolicySet, ResourceVerb, SessionVerb,
};
use d2b_resource_api::watch::{WatchFrame, WatchSink, WatchSinkError};
use d2b_session::{
    AuthenticatedComponentSession, AuthenticatedSessionRouteBinding, AuthenticatedTtrpcHandle,
    GENERATED_OPERATION_CATALOG, OperationKind, SessionAcceptor, SessionAuthorizationRequest,
    SessionCancellationHandle, SessionDriverHandle, SessionOperation,
    SessionRegistrationCapability,
    contract::{EndpointPolicy, ServicePackage},
    resource_operation, rewrite_ttrpc_stream_id, ttrpc_request_id, ttrpc_stream_id,
};
use d2b_session::{SessionAuthenticationBinding, TransportEvidence};
use d2b_session_unix::{PeerCredentials, VerifiedUnixPeer};
use tokio::sync::{Mutex as AsyncMutex, mpsc, oneshot};

use crate::{
    authorization::{AuthorizationError, BusAuthorizer},
    metrics::{
        BusBackpressureReason, BusDirection, BusDisconnectOutcome, BusRegistrationOutcome,
        BusRejectionOutcome, BusStreamKind, BusStreamOutcome, BusTelemetry, BusTransport,
        NoopBusTelemetry, route_outcome, transport_for_context,
    },
    operations::{
        CancelDeliveryAdmission, CancelDispatch, Cancellation, OperationError, OperationId,
        OperationSpec, OperationTable, PendingCancelDeliveries, SessionId, TombstoneEviction,
    },
    registry::{
        BusResponse, EndpointError, Registry, RegistryError, RouteKey, RouteTarget,
        SessionRegistration,
    },
    streams::{
        IncomingStream, OutgoingStream, StreamBridge, StreamError, StreamLimits, StreamName,
    },
};

#[cfg(feature = "production-rss-fixture")]
#[path = "production_rss.rs"]
pub mod production_rss;

/// Default maximum bytes in one method payload.
pub const DEFAULT_MAX_PAYLOAD_BYTES: usize = 1024 * 1024;
pub const DEFAULT_MAX_ROUTES_PER_SESSION: usize = 128;
pub const DEFAULT_MAX_TOTAL_ROUTES: usize = 4096;
const FIRST_CORRELATION_ID: u32 = RESERVED_CORRELATION_MAX + 1;
const DEFAULT_MAX_CORRELATIONS_PER_GENERATION: u64 =
    (u32::MAX as u64 - FIRST_CORRELATION_ID as u64) / 2 + 1;
const CANCEL_DELIVERY_TIMEOUT: Duration = Duration::from_secs(5);
const SYSTEM_CORE_PROVIDER_REF: &str = "Provider/system-core";
const SYSTEM_CORE_PROVIDER_UID: &str = "11111111-1111-4111-8111-111111111111";

/// Monotonic clock used for operation deadlines.
pub trait BusClock: Send + Sync + 'static {
    /// Return the current monotonic tick.
    fn now_tick(&self) -> u64;
}

/// A bus operation lease for daemon-local dispatch.
pub struct LocalOperationLease {
    inner: Option<OperationLease>,
}

impl LocalOperationLease {
    /// Finish the authorized local invocation.
    pub fn finish(mut self) -> Result<(), BusError> {
        self.inner
            .as_mut()
            .expect("local operation lease is live")
            .finish()
    }
}

struct SystemClock(Instant);

impl SystemClock {
    fn new() -> Self {
        Self(Instant::now())
    }
}

impl BusClock for SystemClock {
    fn now_tick(&self) -> u64 {
        u64::try_from(self.0.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// Deterministic monotonic clock for tests and embedded runtimes.
pub struct ManualClock(AtomicU64);

impl ManualClock {
    /// Construct a clock at one tick.
    pub const fn new(tick: u64) -> Self {
        Self(AtomicU64::new(tick))
    }

    /// Advance to an equal or later tick.
    pub fn advance_to(&self, tick: u64) {
        self.0.fetch_max(tick, Ordering::AcqRel);
    }
}

impl BusClock for ManualClock {
    fn now_tick(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }
}

impl core::fmt::Debug for ManualClock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ManualClock(<redacted>)")
    }
}

/// Frozen bounds for one Zone bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BusConfig {
    pub max_payload_bytes: usize,
    pub max_operations: usize,
    pub max_operations_per_session: usize,
    pub max_routes_per_session: usize,
    pub max_total_routes: usize,
    pub max_correlations_per_generation: u64,
    pub stream_limits: StreamLimits,
}

impl Default for BusConfig {
    fn default() -> Self {
        Self {
            max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
            max_operations: crate::operations::DEFAULT_MAX_OPERATIONS,
            max_operations_per_session: crate::operations::DEFAULT_MAX_OPERATIONS_PER_SESSION,
            max_routes_per_session: DEFAULT_MAX_ROUTES_PER_SESSION,
            max_total_routes: DEFAULT_MAX_TOTAL_ROUTES,
            max_correlations_per_generation: DEFAULT_MAX_CORRELATIONS_PER_GENERATION,
            stream_limits: StreamLimits::default(),
        }
    }
}

/// Exact indexed filter preserved in List and Watch calls.
#[derive(Clone, PartialEq, Eq)]
pub struct ResourceFilter {
    field: String,
    values: Vec<String>,
}

impl ResourceFilter {
    /// Construct a bounded exact-match filter.
    pub fn new(field: impl Into<String>, values: Vec<String>) -> Result<Self, BusError> {
        let field = field.into();
        if field.is_empty()
            || field.len() > 64
            || !field
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
            || values.is_empty()
            || values.len() > 64
            || values.iter().any(|value| {
                value.is_empty()
                    || value.len() > 128
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_graphic() || byte == b' ')
            })
        {
            return Err(BusError::InvalidResourceCall);
        }
        Ok(Self { field, values })
    }

    /// Borrow the exact indexed field.
    pub fn field(&self) -> &str {
        &self.field
    }

    /// Borrow the exact accepted values.
    pub fn values(&self) -> &[String] {
        &self.values
    }
}

impl core::fmt::Debug for ResourceFilter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ResourceFilter")
            .field("value_count", &self.values.len())
            .finish()
    }
}

/// Named or nameless List/Watch selector.
#[derive(Clone, PartialEq, Eq)]
pub struct ResourceQuery {
    resource_types: Vec<ResourceTypeName>,
    resource_names: Vec<ResourceName>,
    filters: Vec<ResourceFilter>,
    assignment: Option<AssignmentIdentity>,
    scope: Option<ScopedResourceScope>,
}

impl ResourceQuery {
    /// Construct a bounded query without rewriting selector order or filters.
    pub fn new(
        resource_types: Vec<ResourceTypeName>,
        resource_names: Vec<ResourceName>,
        filters: Vec<ResourceFilter>,
    ) -> Result<Self, BusError> {
        if resource_types.is_empty()
            || resource_types.len() > 64
            || resource_names.len() > 64
            || filters.len() > 64
        {
            return Err(BusError::InvalidResourceCall);
        }
        Ok(Self {
            resource_types,
            resource_names,
            filters,
            assignment: None,
            scope: None,
        })
    }

    /// Consume a controller-minted query without allowing its assignment
    /// filter to be dropped or widened.
    pub fn from_scoped(query: ScopedResourceQuery) -> Result<Self, BusError> {
        let (assignment, resource_types, resource_names, scoped_filters, scope) =
            query.into_parts_with_scope();
        if resource_types.is_empty()
            || resource_types.len() > MAX_LIST_RESOURCE_TYPES
            || resource_names.len() > MAX_FILTER_VALUES
            || scoped_filters.len() > MAX_LIST_FILTERS
            || scoped_filters.len() + usize::from(!resource_names.is_empty()) > MAX_LIST_FILTERS
        {
            return Err(BusError::InvalidResourceCall);
        }
        let filters = scoped_filters
            .into_iter()
            .map(resource_filter_from_scoped)
            .collect::<Result<Vec<_>, _>>()?;
        let query = Self {
            resource_types,
            resource_names,
            filters,
            assignment: Some(assignment),
            scope: Some(scope),
        };
        query.validate_scoped()?;
        Ok(query)
    }

    /// Borrow the ResourceType selector in its exact received order.
    pub fn resource_types(&self) -> &[ResourceTypeName] {
        &self.resource_types
    }

    /// Borrow the optional name selector in its exact received order.
    pub fn resource_names(&self) -> &[ResourceName] {
        &self.resource_names
    }

    /// Borrow the exact filters.
    pub fn filters(&self) -> &[ResourceFilter] {
        &self.filters
    }

    /// Borrow the assignment evidence, when this query is controller-scoped.
    pub const fn assignment(&self) -> Option<&AssignmentIdentity> {
        self.assignment.as_ref()
    }

    /// Borrow the controller-minted query scope, when present.
    pub const fn scope(&self) -> Option<&ScopedResourceScope> {
        self.scope.as_ref()
    }

    fn validate_scoped(&self) -> Result<(), BusError> {
        let (Some(assignment), Some(scope)) = (&self.assignment, &self.scope) else {
            return if self.assignment.is_none() && self.scope.is_none() {
                Ok(())
            } else {
                Err(BusError::InvalidResourceCall)
            };
        };
        let (bound_field, bound_value) = match scope {
            ScopedResourceScope::Primary => {
                (ASSIGNMENT_UID_FILTER, assignment.resource_uid().as_str())
            }
            ScopedResourceScope::OwnerChild(owner) => {
                if owner.owner_uid() != assignment.resource_uid()
                    || self.resource_types.is_empty()
                    || self
                        .resource_types
                        .iter()
                        .any(|resource_type| resource_type.as_str() != PROCESS_RESOURCE_TYPE)
                {
                    return Err(BusError::InvalidResourceCall);
                }
                (OWNER_UID_FILTER, owner.owner_uid().as_str())
            }
        };
        let bound_filters = self
            .filters
            .iter()
            .filter(|filter| filter.field == bound_field)
            .collect::<Vec<_>>();
        if bound_filters.len() != 1
            || bound_filters[0].values.len() != 1
            || bound_filters[0].values[0] != bound_value
        {
            return Err(BusError::InvalidResourceCall);
        }
        Ok(())
    }
}

impl core::fmt::Debug for ResourceQuery {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ResourceQuery")
            .field("resource_type_count", &self.resource_types.len())
            .field("resource_name_count", &self.resource_names.len())
            .field("filter_count", &self.filters.len())
            .finish()
    }
}

/// Closed resource-service call. Authorization targets are derived from this value.
#[derive(Clone, PartialEq, Eq)]
pub enum ResourceCall {
    Get(ResourceRef),
    List(ResourceQuery),
    Watch(ResourceQuery),
    Create(ResourceRef),
    UpdateSpec(ResourceRef),
    UpdateStatus(ResourceRef),
    UpdateMetadata(ResourceRef),
    UpdateFinalizers(ResourceRef),
    Delete(ResourceRef),
    CommitBatch(Vec<(ResourceRef, ResourceVerb)>),
    ScopedCommitBatch {
        assignment: AssignmentIdentity,
        mutations: Vec<ScopedResourceMutation>,
    },
    ResolveRef(ResourceRef),
    InspectSchema(ResourceTypeName),
    Upgrade(ResourceRef),
}

impl ResourceCall {
    /// Validate the closed Resource call admitted for Guest-local seeding.
    ///
    /// Guest bootstrap may submit one plain `CommitBatch` containing only
    /// descriptor-approved Create targets. Scoped controller batches and all
    /// other Resource verbs are refused before dispatch.
    pub fn validate_guest_local_seed(
        &self,
        approved_resource_types: &BTreeSet<ResourceTypeName>,
    ) -> Result<(), BusError> {
        let ResourceCall::CommitBatch(mutations) = self else {
            return Err(BusError::InvalidResourceCall);
        };
        if mutations.is_empty()
            || mutations.len() > 128
            || mutations.iter().any(|(target, verb)| {
                *verb != ResourceVerb::Create
                    || !approved_resource_types.contains(target.resource_type())
            })
        {
            return Err(BusError::InvalidResourceCall);
        }
        Ok(())
    }

    pub(crate) fn authorization_request(
        &self,
        zone: ZoneId,
    ) -> Result<AuthorizationRequest, BusError> {
        let (method, targets) = match self {
            Self::Get(target) => (
                ApiMethod::Get,
                vec![exact_target(target, ResourceVerb::Get, None)],
            ),
            Self::List(query) => {
                query.validate_scoped()?;
                (ApiMethod::List, query_targets(query, ResourceVerb::List))
            }
            Self::Watch(query) => {
                query.validate_scoped()?;
                (ApiMethod::Watch, query_targets(query, ResourceVerb::Watch))
            }
            Self::Create(target) => (
                ApiMethod::Create,
                vec![exact_target(target, ResourceVerb::Create, None)],
            ),
            Self::UpdateSpec(target) => (
                ApiMethod::UpdateSpec,
                vec![exact_target(target, ResourceVerb::UpdateSpec, None)],
            ),
            Self::UpdateStatus(target) => (
                ApiMethod::UpdateStatus,
                vec![exact_target(
                    target,
                    ResourceVerb::UpdateStatus,
                    Some("status"),
                )],
            ),
            Self::UpdateMetadata(target) => (
                ApiMethod::UpdateMetadata,
                vec![exact_target(target, ResourceVerb::UpdateMetadata, None)],
            ),
            Self::UpdateFinalizers(target) => (
                ApiMethod::UpdateFinalizers,
                vec![exact_target(
                    target,
                    ResourceVerb::UpdateFinalizers,
                    Some("finalizers"),
                )],
            ),
            Self::Delete(target) => (
                ApiMethod::Delete,
                vec![exact_target(target, ResourceVerb::Delete, None)],
            ),
            Self::CommitBatch(mutations) => {
                if mutations.is_empty()
                    || mutations.len() > 128
                    || mutations.iter().any(|(_, verb)| {
                        !matches!(
                            verb,
                            ResourceVerb::Create
                                | ResourceVerb::UpdateSpec
                                | ResourceVerb::UpdateStatus
                                | ResourceVerb::UpdateMetadata
                                | ResourceVerb::UpdateFinalizers
                                | ResourceVerb::Delete
                        )
                    })
                {
                    return Err(BusError::InvalidResourceCall);
                }
                (
                    ApiMethod::CommitBatch,
                    mutations
                        .iter()
                        .map(|(target, verb)| {
                            let subresource = match verb {
                                ResourceVerb::UpdateStatus => Some("status"),
                                ResourceVerb::UpdateFinalizers => Some("finalizers"),
                                _ => None,
                            };
                            exact_target(target, *verb, subresource)
                        })
                        .collect(),
                )
            }
            Self::ScopedCommitBatch {
                assignment,
                mutations,
            } => {
                if ScopedCommitTransport::new(assignment.clone(), mutations.clone()).is_err() {
                    return Err(BusError::InvalidResourceCall);
                }
                (
                    ApiMethod::CommitBatch,
                    mutations
                        .iter()
                        .map(|mutation| {
                            let subresource = match mutation.verb() {
                                AssignmentVerb::UpdateStatus => Some("status"),
                                AssignmentVerb::UpdateFinalizers => Some("finalizers"),
                                _ => None,
                            };
                            exact_target(
                                mutation.target(),
                                resource_verb_for_assignment(mutation.verb()),
                                subresource,
                            )
                        })
                        .collect(),
                )
            }
            Self::ResolveRef(target) => (
                ApiMethod::ResolveRef,
                vec![exact_target(target, ResourceVerb::Get, None)],
            ),
            Self::InspectSchema(resource_type) => (
                ApiMethod::InspectSchema,
                vec![AuthorizationTarget {
                    resource_type: resource_type.clone(),
                    resource_name: None,
                    verb: ResourceVerb::Get,
                    subresource: Some("schema".to_owned()),
                    execution_ref: None,
                }],
            ),
            Self::Upgrade(target) => (
                ApiMethod::Upgrade,
                vec![exact_target(target, ResourceVerb::UpdateSpec, None)],
            ),
        };
        Ok(AuthorizationRequest {
            method,
            zone,
            targets,
        })
    }

    pub(crate) fn expected_member(&self) -> &'static str {
        resource_operation(self.api_method()).member
    }

    const fn api_method(&self) -> ApiMethod {
        match self {
            Self::Get(_) => ApiMethod::Get,
            Self::List(_) => ApiMethod::List,
            Self::Watch(_) => ApiMethod::Watch,
            Self::Create(_) => ApiMethod::Create,
            Self::UpdateSpec(_) => ApiMethod::UpdateSpec,
            Self::UpdateStatus(_) => ApiMethod::UpdateStatus,
            Self::UpdateMetadata(_) => ApiMethod::UpdateMetadata,
            Self::UpdateFinalizers(_) => ApiMethod::UpdateFinalizers,
            Self::Delete(_) => ApiMethod::Delete,
            Self::CommitBatch(_) => ApiMethod::CommitBatch,
            Self::ScopedCommitBatch { .. } => ApiMethod::CommitBatch,
            Self::ResolveRef(_) => ApiMethod::ResolveRef,
            Self::InspectSchema(_) => ApiMethod::InspectSchema,
            Self::Upgrade(_) => ApiMethod::Upgrade,
        }
    }

    /// Borrow the assignment evidence attached to this resource call.
    pub fn assignment(&self) -> Option<&AssignmentIdentity> {
        match self {
            Self::List(query) | Self::Watch(query) => query.assignment(),
            Self::ScopedCommitBatch { assignment, .. } => Some(assignment),
            _ => None,
        }
    }

    /// Borrow the controller mutations carried by a scoped commit call.
    pub fn scoped_mutations(&self) -> Option<&[ScopedResourceMutation]> {
        match self {
            Self::ScopedCommitBatch { mutations, .. } => Some(mutations),
            _ => None,
        }
    }

    fn session_target(&self) -> Option<&ResourceRef> {
        match self {
            Self::Get(target)
            | Self::Create(target)
            | Self::UpdateSpec(target)
            | Self::UpdateStatus(target)
            | Self::UpdateMetadata(target)
            | Self::UpdateFinalizers(target)
            | Self::Delete(target)
            | Self::ResolveRef(target)
            | Self::Upgrade(target) => Some(target),
            Self::List(_)
            | Self::Watch(_)
            | Self::CommitBatch(_)
            | Self::ScopedCommitBatch { .. }
            | Self::InspectSchema(_) => None,
        }
    }

    fn matches_route_target(&self, route_target: &RouteTarget) -> bool {
        let RouteTarget::Resource(route_target) = route_target else {
            return true;
        };
        match self {
            Self::Get(target)
            | Self::Create(target)
            | Self::UpdateSpec(target)
            | Self::UpdateStatus(target)
            | Self::UpdateMetadata(target)
            | Self::UpdateFinalizers(target)
            | Self::Delete(target)
            | Self::ResolveRef(target)
            | Self::Upgrade(target) => target == route_target,
            Self::List(_)
            | Self::Watch(_)
            | Self::CommitBatch(_)
            | Self::ScopedCommitBatch { .. }
            | Self::InspectSchema(_) => false,
        }
    }
}

impl core::fmt::Debug for ResourceCall {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let kind = match self {
            Self::Get(_) => "Get",
            Self::List(_) => "List",
            Self::Watch(_) => "Watch",
            Self::Create(_) => "Create",
            Self::UpdateSpec(_) => "UpdateSpec",
            Self::UpdateStatus(_) => "UpdateStatus",
            Self::UpdateMetadata(_) => "UpdateMetadata",
            Self::UpdateFinalizers(_) => "UpdateFinalizers",
            Self::Delete(_) => "Delete",
            Self::CommitBatch(_) | Self::ScopedCommitBatch { .. } => "CommitBatch",
            Self::ResolveRef(_) => "ResolveRef",
            Self::InspectSchema(_) => "InspectSchema",
            Self::Upgrade(_) => "Upgrade",
        };
        write!(f, "ResourceCall::{kind}(<redacted>)")
    }
}

fn exact_target(
    target: &ResourceRef,
    verb: ResourceVerb,
    subresource: Option<&str>,
) -> AuthorizationTarget {
    AuthorizationTarget {
        resource_type: target.resource_type().clone(),
        resource_name: Some(target.name().clone()),
        verb,
        subresource: subresource.map(str::to_owned),
        execution_ref: None,
    }
}

fn query_targets(query: &ResourceQuery, verb: ResourceVerb) -> Vec<AuthorizationTarget> {
    query
        .resource_types
        .iter()
        .flat_map(|resource_type| {
            if query.resource_names.is_empty() {
                vec![AuthorizationTarget {
                    resource_type: resource_type.clone(),
                    resource_name: None,
                    verb,
                    subresource: None,
                    execution_ref: query
                        .assignment()
                        .and_then(|assignment| assignment.target().execution_ref())
                        .cloned(),
                }]
            } else {
                query
                    .resource_names
                    .iter()
                    .map(|name| AuthorizationTarget {
                        resource_type: resource_type.clone(),
                        resource_name: Some(name.clone()),
                        verb,
                        subresource: None,
                        execution_ref: query
                            .assignment()
                            .and_then(|assignment| assignment.target().execution_ref())
                            .cloned(),
                    })
                    .collect()
            }
        })
        .collect()
}

fn resource_filter_from_scoped(filter: ScopedResourceFilter) -> Result<ResourceFilter, BusError> {
    if filter.field().is_empty()
        || filter.field().len() > 64
        || !filter
            .field()
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        || filter.values().is_empty()
        || filter.values().len() > 64
        || (matches!(filter.field(), ASSIGNMENT_UID_FILTER | OWNER_UID_FILTER)
            && !filter.assignment_bound())
    {
        return Err(BusError::InvalidResourceCall);
    }
    Ok(ResourceFilter {
        field: filter.field().to_owned(),
        values: filter.values().to_vec(),
    })
}

fn resource_verb_for_assignment(verb: AssignmentVerb) -> ResourceVerb {
    match verb {
        AssignmentVerb::Get => ResourceVerb::Get,
        AssignmentVerb::List => ResourceVerb::List,
        AssignmentVerb::Watch => ResourceVerb::Watch,
        AssignmentVerb::Create => ResourceVerb::Create,
        AssignmentVerb::UpdateSpec => ResourceVerb::UpdateSpec,
        AssignmentVerb::UpdateStatus => ResourceVerb::UpdateStatus,
        AssignmentVerb::UpdateMetadata => ResourceVerb::UpdateMetadata,
        AssignmentVerb::UpdateFinalizers => ResourceVerb::UpdateFinalizers,
        AssignmentVerb::Delete => ResourceVerb::Delete,
        AssignmentVerb::CommitBatch => unreachable!("batch wrapper is not a mutation target"),
    }
}

/// Method invocation delivered only after exact route and authorization checks.
pub struct DeliveredInvocation {
    route: RouteKey,
    operation: OperationSpec,
    resource_call: Option<ResourceCall>,
    payload: Vec<u8>,
    cancellation: Cancellation,
}

impl DeliveredInvocation {
    /// Borrow the exact route.
    pub const fn route(&self) -> &RouteKey {
        &self.route
    }

    /// Borrow the operation metadata.
    pub const fn operation(&self) -> &OperationSpec {
        &self.operation
    }

    /// Borrow the exact resource call, when this is a resource-service request.
    pub const fn resource_call(&self) -> Option<&ResourceCall> {
        self.resource_call.as_ref()
    }

    /// Borrow the opaque service payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Borrow cancellation state.
    pub const fn cancellation(&self) -> &Cancellation {
        &self.cancellation
    }
}

impl core::fmt::Debug for DeliveredInvocation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeliveredInvocation")
            .field("route", &self.route)
            .field("operation", &self.operation)
            .field("resource_call", &self.resource_call)
            .field("payload_bytes", &self.payload.len())
            .finish()
    }
}

/// Stream open delivered only after exact route and authorization checks.
pub struct DeliveredStream {
    route: RouteKey,
    operation: OperationSpec,
    resource_call: Option<ResourceCall>,
    incoming: IncomingStream,
    cancellation: Cancellation,
}

impl DeliveredStream {
    /// Borrow the exact route.
    pub const fn route(&self) -> &RouteKey {
        &self.route
    }

    /// Borrow the operation metadata.
    pub const fn operation(&self) -> &OperationSpec {
        &self.operation
    }

    /// Borrow the exact resource call, when this is a resource stream.
    pub const fn resource_call(&self) -> Option<&ResourceCall> {
        self.resource_call.as_ref()
    }

    /// Borrow cancellation state.
    pub const fn cancellation(&self) -> &Cancellation {
        &self.cancellation
    }

    /// Consume the dispatch and retain the destination stream reader.
    pub fn into_incoming(self) -> IncomingStream {
        self.incoming
    }
}

impl core::fmt::Debug for DeliveredStream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeliveredStream")
            .field("route", &self.route)
            .field("operation", &self.operation)
            .field("resource_call", &self.resource_call)
            .field("incoming", &self.incoming)
            .finish()
    }
}

struct BusCore {
    zone: ZoneId,
    registry: Mutex<Registry>,
    authorizer: Arc<BusAuthorizer>,
    operations: Mutex<OperationTable>,
    cancel_deliveries: Arc<PendingCancelDeliveries>,
    streams: Arc<StreamBridge>,
    clock: Arc<dyn BusClock>,
    max_payload_bytes: usize,
    max_correlations_per_generation: u64,
    observer: Arc<dyn BusObserver>,
    metrics: Arc<dyn BusTelemetry>,
    active_sessions: Mutex<BTreeMap<BusTransport, u64>>,
    #[cfg(test)]
    invocation_hooks: Mutex<InvocationHooks>,
}

#[cfg(test)]
#[derive(Default)]
struct InvocationHooks {
    after_resolve: Option<Arc<InvocationHook>>,
    before_invoke: Option<Arc<InvocationHook>>,
    before_cancel_transition: Option<Arc<InvocationHook>>,
}

#[cfg(test)]
struct InvocationHook {
    reached: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

struct PendingCancelDeliveryLease {
    pending: Weak<PendingCancelDeliveries>,
    operation: OperationId,
    source: SessionId,
    cancellation: Cancellation,
}

impl Drop for PendingCancelDeliveryLease {
    fn drop(&mut self) {
        if let Some(pending) = self.pending.upgrade() {
            pending.complete(&self.operation, self.source, &self.cancellation);
        }
    }
}

/// Completion state for a cancellation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancellationOutcome {
    /// Local operation state is terminal, but remote notification is unconfirmed.
    LocalTerminal,
    /// The local session transport finished writing the cancellation request.
    ///
    /// This does not imply that the destination processed it or returned a
    /// `CancelAck`.
    LocallyTransmitted,
}

/// Correlated cancellation completion without retaining active operation quota.
pub struct CancellationReceipt {
    remote: Option<oneshot::Receiver<CancellationOutcome>>,
}

impl CancellationReceipt {
    fn local() -> Self {
        Self { remote: None }
    }

    fn pending(remote: oneshot::Receiver<CancellationOutcome>) -> Self {
        Self {
            remote: Some(remote),
        }
    }

    /// Return the state guaranteed when the receipt was issued.
    pub const fn local_outcome(&self) -> CancellationOutcome {
        CancellationOutcome::LocalTerminal
    }

    /// Wait for the correlated cancellation transmission result.
    pub async fn delivery_outcome(self) -> CancellationOutcome {
        match self.remote {
            Some(remote) => remote.await.unwrap_or(CancellationOutcome::LocalTerminal),
            None => CancellationOutcome::LocalTerminal,
        }
    }
}

impl core::fmt::Debug for CancellationReceipt {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CancellationReceipt")
            .field("local_outcome", &CancellationOutcome::LocalTerminal)
            .field("remote_pending", &self.remote.is_some())
            .finish()
    }
}

impl BusCore {
    fn session_metrics(&self, session: SessionId) -> (BusDirection, BusTransport) {
        let source = self.lock_registry().source(session).ok();
        (
            BusDirection::from_context(source.as_ref().and_then(|source| source.context.as_ref())),
            transport_for_context(source.as_ref().and_then(|source| source.context.as_ref())),
        )
    }

    fn record_session_registered(&self, session: SessionId) {
        let (direction, transport) = self.session_metrics(session);
        let active = {
            let mut sessions = self
                .active_sessions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let active = sessions.entry(transport).or_default();
            *active = active.saturating_add(1);
            *active
        };
        self.metrics
            .registration(direction, BusRegistrationOutcome::Accepted);
        self.metrics.session_active(transport, active);
    }

    fn record_route(
        &self,
        service: &ServiceName,
        direction: BusDirection,
        error: Option<&BusError>,
        duration_seconds: f64,
    ) {
        self.metrics
            .route(service, direction, route_outcome(error), duration_seconds);
        if let Some(error) = error {
            match rejection_outcome(error) {
                BusRejectionOutcome::Quota => self.metrics.backpressure(
                    direction,
                    BusStreamKind::Control,
                    BusBackpressureReason::Capacity,
                ),
                outcome => self.metrics.rejection(direction, outcome),
            }
        }
    }

    fn record_session_disconnected_values(
        &self,
        direction: BusDirection,
        transport: BusTransport,
        outcome: BusDisconnectOutcome,
    ) {
        let active = {
            let mut sessions = self
                .active_sessions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let active = sessions.entry(transport).or_default();
            *active = active.saturating_sub(1);
            *active
        };
        self.metrics.disconnect(direction, outcome);
        self.metrics.session_active(transport, active);
    }

    fn begin_cleanup_session(
        self: &Arc<Self>,
        session: SessionId,
    ) -> Option<crate::registry::SessionInvalidation> {
        let invalidation = self.lock_registry().invalidate(session);
        let (direction, transport) = self.session_metrics(session);
        let removed = self.lock_registry().remove(session);
        if removed {
            self.record_session_disconnected_values(
                direction,
                transport,
                BusDisconnectOutcome::Abandoned,
            );
        }
        let targets = self.lock_operations().cancel_session(session);
        self.streams.cancel_session(session);
        self.dispatch_cancel_targets(targets);
        self.cancel_deliveries.abort_destination(session);
        invalidation
    }

    async fn cleanup_session(self: &Arc<Self>, session: SessionId) {
        if let Some(invalidation) = self.begin_cleanup_session(session) {
            invalidation.await;
        }
    }

    fn dispatch_cancel_targets(self: &Arc<Self>, targets: Vec<CancelDispatch>) {
        for dispatch in targets {
            drop(self.dispatch_cancel_target(dispatch));
        }
    }

    fn dispatch_cancel_target(
        self: &Arc<Self>,
        dispatch: CancelDispatch,
    ) -> oneshot::Receiver<CancellationOutcome> {
        if let Some(eviction) = dispatch.tombstone_eviction {
            self.observe_tombstone_eviction(eviction);
        }
        let delivery = dispatch
            .target
            .endpoint
            .terminalize_cancel(&dispatch.operation, &dispatch.target.cancellation);
        let (completion, completed) = oneshot::channel();
        if dispatch.target.route.generations().session() != dispatch.target.generation {
            self.observe_error(BusEvent::Cancel, &BusError::SessionMismatch);
            let _ = completion.send(CancellationOutcome::LocalTerminal);
            return completed;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            drop(delivery);
            self.observer
                .record(BusEvent::Cancel, BusFailureReason::Abandoned);
            let _ = completion.send(CancellationOutcome::LocalTerminal);
            return completed;
        };
        let operation = dispatch.operation.clone();
        let source = dispatch.source;
        let cancellation = dispatch.target.cancellation.clone();
        let pending = Arc::clone(&self.cancel_deliveries);
        let pending_weak = Arc::downgrade(&pending);
        let observer = Arc::clone(&self.observer);
        let (start, started) = oneshot::channel();
        let task = runtime.spawn(async move {
            if started.await.is_err() {
                return;
            }
            let _pending = PendingCancelDeliveryLease {
                pending: pending_weak,
                operation: operation.clone(),
                source,
                cancellation,
            };
            let outcome = match tokio::time::timeout(CANCEL_DELIVERY_TIMEOUT, delivery).await {
                Ok(Ok(())) => CancellationOutcome::LocallyTransmitted,
                Ok(Err(error)) => {
                    observer.record(
                        BusEvent::Cancel,
                        BusFailureReason::from_error(&BusError::Endpoint(error)),
                    );
                    CancellationOutcome::LocalTerminal
                }
                Err(_) => {
                    observer.record(BusEvent::Cancel, BusFailureReason::Abandoned);
                    CancellationOutcome::LocalTerminal
                }
            };
            let _ = completion.send(outcome);
        });
        match pending.admit(&dispatch, task.abort_handle()) {
            CancelDeliveryAdmission::Admitted => {
                let _ = start.send(());
            }
            CancelDeliveryAdmission::Duplicate => {
                task.abort();
            }
            CancelDeliveryAdmission::Full => {
                task.abort();
                self.observer
                    .record(BusEvent::Cancel, BusFailureReason::Abandoned);
            }
        }
        completed
    }

    fn observe_error(&self, event: BusEvent, error: &BusError) {
        self.observer
            .record(event, BusFailureReason::from_error(error));
    }

    fn observe_tombstone_eviction(&self, eviction: TombstoneEviction) {
        let reason = match eviction {
            TombstoneEviction::PerSource => BusFailureReason::PerSourceRetention,
            TombstoneEviction::Global => BusFailureReason::GlobalRetention,
        };
        self.observer.record(BusEvent::TombstoneEviction, reason);
    }

    fn lock_registry(&self) -> MutexGuard<'_, Registry> {
        self.registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn lock_operations(&self) -> MutexGuard<'_, OperationTable> {
        self.operations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Administration handle for one self-contained Zone bus.
pub struct ZoneBus {
    core: Arc<BusCore>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusEvent {
    Invoke,
    OpenStream,
    Cancel,
    Cleanup,
    TombstoneEviction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusFailureReason {
    Authorization,
    Route,
    Session,
    Capacity,
    Backpressure,
    RouteRevoked,
    Deadline,
    Cancelled,
    Authentication,
    Generation,
    Transport,
    Protocol,
    Endpoint,
    Abandoned,
    StreamShed,
    PerSourceRetention,
    GlobalRetention,
}

impl BusFailureReason {
    const fn from_error(error: &BusError) -> Self {
        match error {
            BusError::Authorization(_) => Self::Authorization,
            BusError::InvalidResourceCall | BusError::RouteShape | BusError::Registry(_) => {
                Self::Route
            }
            BusError::SessionMismatch | BusError::SessionClosed => Self::Session,
            BusError::Cancelled => Self::Cancelled,
            BusError::Operation(OperationError::DeadlineExceeded) => Self::Deadline,
            BusError::Operation(OperationError::RouteRevoked) => Self::RouteRevoked,
            BusError::Operation(OperationError::CapacityExceeded)
            | BusError::Operation(OperationError::SessionCapacityExceeded)
            | BusError::Stream(StreamError::StreamCapacityExceeded)
            | BusError::Stream(StreamError::PrincipalCapacityExceeded) => Self::Capacity,
            BusError::Operation(_) | BusError::Stream(_) => Self::Backpressure,
            BusError::Endpoint(EndpointError::Session(failure)) => match failure.class() {
                crate::registry::EndpointFailureClass::Authentication => Self::Authentication,
                crate::registry::EndpointFailureClass::Authorization => Self::Authorization,
                crate::registry::EndpointFailureClass::Generation => Self::Generation,
                crate::registry::EndpointFailureClass::Backpressure => Self::Backpressure,
                crate::registry::EndpointFailureClass::Deadline => Self::Deadline,
                crate::registry::EndpointFailureClass::Cancellation => Self::Cancelled,
                crate::registry::EndpointFailureClass::Transport => Self::Transport,
                crate::registry::EndpointFailureClass::Protocol => Self::Protocol,
                crate::registry::EndpointFailureClass::Internal => Self::Endpoint,
            },
            BusError::Endpoint(_) | BusError::InvalidConfig => Self::Endpoint,
        }
    }
}

pub trait BusObserver: Send + Sync {
    fn record(&self, event: BusEvent, reason: BusFailureReason);
}

#[derive(Debug, Default)]
pub struct NoopBusObserver;

impl BusObserver for NoopBusObserver {
    fn record(&self, _event: BusEvent, _reason: BusFailureReason) {}
}

impl ZoneBus {
    /// Construct a bus with a process-monotonic clock.
    pub fn new(
        zone: ZoneId,
        authorizer: BusAuthorizer,
        config: BusConfig,
    ) -> Result<(Self, ZoneRegistrar), BusError> {
        Self::with_clock(zone, authorizer, config, Arc::new(SystemClock::new()))
    }

    pub fn with_observer(
        zone: ZoneId,
        authorizer: BusAuthorizer,
        config: BusConfig,
        observer: Arc<dyn BusObserver>,
    ) -> Result<(Self, ZoneRegistrar), BusError> {
        Self::with_clock_and_observer(
            zone,
            authorizer,
            config,
            Arc::new(SystemClock::new()),
            observer,
        )
    }

    /// Construct a bus with the system clock, observer, and telemetry handoff.
    pub fn with_observer_and_metrics(
        zone: ZoneId,
        authorizer: BusAuthorizer,
        config: BusConfig,
        observer: Arc<dyn BusObserver>,
        metrics: Arc<dyn BusTelemetry>,
    ) -> Result<(Self, ZoneRegistrar), BusError> {
        Self::with_clock_observer_and_metrics(
            zone,
            authorizer,
            config,
            Arc::new(SystemClock::new()),
            observer,
            metrics,
        )
    }

    /// Construct a bus and the Zone-runtime-only committed subject issuer.
    pub fn with_interaction_subject_issuer(
        zone: ZoneId,
        authorizer: BusAuthorizer,
        config: BusConfig,
    ) -> Result<(Self, ZoneRegistrar, CommittedInteractionSubjectIssuer), BusError> {
        Self::with_clock_observer_and_metrics_and_interaction_subject_issuer(
            zone,
            authorizer,
            config,
            Arc::new(SystemClock::new()),
            Arc::new(NoopBusObserver),
            Arc::new(NoopBusTelemetry),
        )
    }

    /// Construct a bus with an injected monotonic clock.
    pub fn with_clock(
        zone: ZoneId,
        authorizer: BusAuthorizer,
        config: BusConfig,
        clock: Arc<dyn BusClock>,
    ) -> Result<(Self, ZoneRegistrar), BusError> {
        Self::with_clock_and_observer(zone, authorizer, config, clock, Arc::new(NoopBusObserver))
    }

    pub fn with_clock_and_observer(
        zone: ZoneId,
        authorizer: BusAuthorizer,
        config: BusConfig,
        clock: Arc<dyn BusClock>,
        observer: Arc<dyn BusObserver>,
    ) -> Result<(Self, ZoneRegistrar), BusError> {
        let (bus, registrar, _) = Self::with_clock_observer_and_metrics_internal(
            zone,
            authorizer,
            config,
            clock,
            observer,
            Arc::new(NoopBusTelemetry),
            false,
        )?;
        Ok((bus, registrar))
    }

    /// Construct a bus with an observer and the bounded telemetry handoff.
    pub fn with_clock_observer_and_metrics(
        zone: ZoneId,
        authorizer: BusAuthorizer,
        config: BusConfig,
        clock: Arc<dyn BusClock>,
        observer: Arc<dyn BusObserver>,
        metrics: Arc<dyn BusTelemetry>,
    ) -> Result<(Self, ZoneRegistrar), BusError> {
        let (bus, registrar, _) = Self::with_clock_observer_and_metrics_internal(
            zone, authorizer, config, clock, observer, metrics, false,
        )?;
        Ok((bus, registrar))
    }

    /// Construct a bus with the opt-in committed subject issuer for the
    /// Zone-runtime composition path.
    pub fn with_clock_observer_and_metrics_and_interaction_subject_issuer(
        zone: ZoneId,
        authorizer: BusAuthorizer,
        config: BusConfig,
        clock: Arc<dyn BusClock>,
        observer: Arc<dyn BusObserver>,
        metrics: Arc<dyn BusTelemetry>,
    ) -> Result<(Self, ZoneRegistrar, CommittedInteractionSubjectIssuer), BusError> {
        let (bus, registrar, issuer) = Self::with_clock_observer_and_metrics_internal(
            zone, authorizer, config, clock, observer, metrics, true,
        )?;
        let issuer = issuer.ok_or(BusError::InvalidConfig)?;
        Ok((bus, registrar, issuer))
    }

    fn with_clock_observer_and_metrics_internal(
        zone: ZoneId,
        authorizer: BusAuthorizer,
        config: BusConfig,
        clock: Arc<dyn BusClock>,
        observer: Arc<dyn BusObserver>,
        metrics: Arc<dyn BusTelemetry>,
        issue_interaction_subject_issuer: bool,
    ) -> Result<
        (
            Self,
            ZoneRegistrar,
            Option<CommittedInteractionSubjectIssuer>,
        ),
        BusError,
    > {
        if config.max_payload_bytes == 0
            || config.max_routes_per_session == 0
            || config.max_total_routes == 0
            || config.max_routes_per_session > config.max_total_routes
            || config.max_correlations_per_generation == 0
            || config.max_correlations_per_generation > DEFAULT_MAX_CORRELATIONS_PER_GENERATION
        {
            return Err(BusError::InvalidConfig);
        }
        let interaction_subject_authority = if issue_interaction_subject_issuer {
            Some(Arc::new(InteractionSubjectAuthority {
                zone: zone.clone(),
                controller_generation: authorizer
                    .controller_generation()
                    .ok_or(BusError::InvalidConfig)?,
            }))
        } else {
            None
        };
        let operations =
            OperationTable::new(config.max_operations, config.max_operations_per_session)?;
        let streams = StreamBridge::with_observer_and_metrics(
            config.stream_limits,
            Arc::clone(&observer),
            Arc::clone(&metrics),
        )?;
        let core = Arc::new(BusCore {
            registry: Mutex::new(Registry::new(
                zone.clone(),
                config.max_routes_per_session,
                config.max_total_routes,
            )),
            zone,
            authorizer: Arc::new(authorizer),
            operations: Mutex::new(operations),
            cancel_deliveries: Arc::new(PendingCancelDeliveries::new(
                config.max_operations,
                config.max_operations_per_session,
            )),
            streams,
            clock,
            max_payload_bytes: config.max_payload_bytes,
            max_correlations_per_generation: config.max_correlations_per_generation,
            observer,
            metrics,
            active_sessions: Mutex::new(BTreeMap::new()),
            #[cfg(test)]
            invocation_hooks: Mutex::new(InvocationHooks::default()),
        });
        Ok((
            Self {
                core: Arc::clone(&core),
            },
            ZoneRegistrar {
                core,
                component_admission: ComponentSessionRegistrar {
                    identity: Arc::new(ComponentSessionAdmissionIdentity),
                },
                unix_subjects: AuthoritativeUnixSubjectResolver::deny_all(config.max_total_routes),
                interaction_subjects: interaction_subject_authority.as_ref().map(|authority| {
                    InteractionSubjectRegistrar {
                        authority: Arc::clone(authority),
                    }
                }),
            },
            interaction_subject_authority
                .map(|authority| CommittedInteractionSubjectIssuer { authority }),
        ))
    }

    /// Atomically install a new native policy and trusted runtime state.
    pub fn replace_policy(
        &self,
        policy: PolicySet,
        state: AuthorizationState,
    ) -> Result<(), BusError> {
        self.core.authorizer.replace_policy(policy, state)?;
        Ok(())
    }

    /// Borrow the native authorizer shared by this Zone bus.
    pub fn native_authorizer(&self) -> Arc<NativeAuthorizer> {
        self.core.authorizer.native_authorizer()
    }

    /// Fail closed for all new work while durable policy is unavailable.
    pub fn mark_policy_unavailable(&self) {
        self.core.authorizer.mark_policy_unavailable();
    }
}

impl core::fmt::Debug for ZoneBus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ZoneBus(<redacted>)")
    }
}

#[derive(Clone)]
enum UnixSubjectKind {
    #[cfg(test)]
    Host,
    Guest,
    Provider,
}

#[derive(Clone)]
pub(crate) struct UnixSubjectRecord {
    kind: UnixSubjectKind,
    subject_ref: ResourceRef,
    subject_uid: ResourceUid,
    zone_ref: ResourceRef,
    expected_peer: Option<PeerCredentials>,
    expected_peer_uid: Option<u32>,
    service: Option<ServicePackage>,
    provider_ref: Option<ResourceRef>,
    provider_generation: Option<ResourceGeneration>,
    process_ref: Option<ResourceRef>,
    controller_generation: Option<ControllerGeneration>,
    execution_ref: Option<ResourceRef>,
}

impl UnixSubjectRecord {
    #[cfg(test)]
    pub(crate) fn host(
        subject_ref: ResourceRef,
        subject_uid: ResourceUid,
        zone_ref: ResourceRef,
        expected_peer: PeerCredentials,
    ) -> d2b_session::Result<Self> {
        Self::new(
            UnixSubjectKind::Host,
            subject_ref,
            subject_uid,
            zone_ref,
            expected_peer,
        )
    }

    #[cfg(test)]
    pub(crate) fn guest(
        subject_ref: ResourceRef,
        subject_uid: ResourceUid,
        zone_ref: ResourceRef,
        expected_peer: PeerCredentials,
    ) -> d2b_session::Result<Self> {
        Self::new(
            UnixSubjectKind::Guest,
            subject_ref,
            subject_uid,
            zone_ref,
            expected_peer,
        )
    }

    #[cfg(test)]
    pub(crate) fn provider(
        subject_ref: ResourceRef,
        subject_uid: ResourceUid,
        zone_ref: ResourceRef,
        expected_peer: PeerCredentials,
        provider_generation: ResourceGeneration,
    ) -> d2b_session::Result<Self> {
        let mut config = Self::new(
            UnixSubjectKind::Provider,
            subject_ref,
            subject_uid,
            zone_ref,
            expected_peer,
        )?;
        config.provider_ref = Some(config.subject_ref.clone());
        config.provider_generation = Some(provider_generation);
        Ok(config)
    }

    fn new(
        kind: UnixSubjectKind,
        subject_ref: ResourceRef,
        subject_uid: ResourceUid,
        zone_ref: ResourceRef,
        expected_peer: PeerCredentials,
    ) -> d2b_session::Result<Self> {
        let expected_type = match kind {
            #[cfg(test)]
            UnixSubjectKind::Host => "Host",
            UnixSubjectKind::Guest => "Guest",
            UnixSubjectKind::Provider => "Provider",
        };
        if subject_ref.resource_type().as_str() != expected_type
            || zone_ref.resource_type().as_str() != "Zone"
        {
            return Err(d2b_session::SessionError::new(
                d2b_session::contract::SessionErrorCode::SubjectMismatch,
            ));
        }
        Ok(Self {
            kind,
            subject_ref,
            subject_uid,
            zone_ref,
            expected_peer: Some(expected_peer),
            expected_peer_uid: None,
            service: None,
            provider_ref: None,
            provider_generation: None,
            process_ref: None,
            controller_generation: None,
            execution_ref: None,
        })
    }

    fn guest_for_uid(
        subject_ref: ResourceRef,
        subject_uid: ResourceUid,
        zone_ref: ResourceRef,
        expected_peer_uid: u32,
    ) -> d2b_session::Result<Self> {
        if subject_ref.resource_type().as_str() != "Guest"
            || zone_ref.resource_type().as_str() != "Zone"
        {
            return Err(d2b_session::SessionError::new(
                d2b_session::contract::SessionErrorCode::SubjectMismatch,
            ));
        }
        Ok(Self {
            kind: UnixSubjectKind::Guest,
            subject_ref,
            subject_uid,
            zone_ref,
            expected_peer: None,
            expected_peer_uid: Some(expected_peer_uid),
            service: None,
            provider_ref: None,
            provider_generation: None,
            process_ref: None,
            controller_generation: None,
            execution_ref: None,
        })
    }

    pub(crate) fn provider_for_uid(
        subject_ref: ResourceRef,
        subject_uid: ResourceUid,
        zone_ref: ResourceRef,
        expected_peer_uid: u32,
    ) -> d2b_session::Result<Self> {
        if subject_ref.resource_type().as_str() != "Provider"
            || zone_ref.resource_type().as_str() != "Zone"
        {
            return Err(d2b_session::SessionError::new(
                d2b_session::contract::SessionErrorCode::SubjectMismatch,
            ));
        }
        Ok(Self {
            kind: UnixSubjectKind::Provider,
            subject_ref,
            subject_uid,
            zone_ref,
            expected_peer: None,
            expected_peer_uid: Some(expected_peer_uid),
            service: None,
            provider_ref: None,
            provider_generation: None,
            process_ref: None,
            controller_generation: None,
            execution_ref: None,
        })
    }

    pub(crate) fn with_provider(
        mut self,
        provider_ref: ResourceRef,
        generation: ResourceGeneration,
    ) -> d2b_session::Result<Self> {
        if provider_ref.resource_type().as_str() != "Provider" {
            return Err(d2b_session::SessionError::new(
                d2b_session::contract::SessionErrorCode::SubjectMismatch,
            ));
        }
        self.provider_ref = Some(provider_ref);
        self.provider_generation = Some(generation);
        Ok(self)
    }

    pub(crate) fn with_process_ref(
        mut self,
        process_ref: ResourceRef,
    ) -> d2b_session::Result<Self> {
        if process_ref.resource_type().as_str() != PROCESS_RESOURCE_TYPE {
            return Err(d2b_session::SessionError::new(
                d2b_session::contract::SessionErrorCode::SubjectMismatch,
            ));
        }
        self.process_ref = Some(process_ref);
        Ok(self)
    }

    pub(crate) fn with_controller_generation(mut self, generation: ControllerGeneration) -> Self {
        self.controller_generation = Some(generation);
        self
    }

    pub(crate) fn for_service(mut self, service: ServicePackage) -> Self {
        self.service = Some(service);
        self
    }

    pub(crate) fn with_execution_ref(
        mut self,
        execution_ref: ResourceRef,
    ) -> d2b_session::Result<Self> {
        if !matches!(execution_ref.resource_type().as_str(), "Host" | "Guest") {
            return Err(d2b_session::SessionError::new(
                d2b_session::contract::SessionErrorCode::SubjectMismatch,
            ));
        }
        self.execution_ref = Some(execution_ref);
        Ok(self)
    }

    pub(crate) fn bind(
        self,
        peer: VerifiedUnixPeer,
        evidence: &TransportEvidence,
        binding: &SessionAuthenticationBinding,
        expected_zone: &ZoneId,
    ) -> d2b_session::Result<AuthenticatedSubjectContext> {
        let expected_type = match self.kind {
            #[cfg(test)]
            UnixSubjectKind::Host => "Host",
            UnixSubjectKind::Guest => "Guest",
            UnixSubjectKind::Provider => "Provider",
        };
        peer.validate_transport(binding.transport_class())?;
        let peer_matches = if binding.service().as_str() == "d2b.resource.v3" {
            self.expected_peer
                .is_some_and(|expected| peer.credentials() == expected)
        } else {
            self.expected_peer
                .is_some_and(|expected| peer.credentials() == expected)
                || self
                    .expected_peer_uid
                    .is_some_and(|expected| peer.credentials().uid().as_raw() == expected)
        };
        if !peer_matches
            || evidence.class() != EvidenceClass::UnixPeer
            || binding.evidence_class() != EvidenceClass::UnixPeer
            || binding.transport_binding().locality() != Locality::Local
            || self.subject_ref.resource_type().as_str() != expected_type
            || self.zone_ref.name().as_str() != expected_zone.as_str()
            || self.process_ref.as_ref().is_some_and(|process_ref| {
                process_ref.resource_type().as_str() != PROCESS_RESOURCE_TYPE
            })
            || evidence.binding_digest() != binding.transport_binding().binding_digest()
        {
            return Err(d2b_session::SessionError::new(
                d2b_session::contract::SessionErrorCode::SubjectMismatch,
            ));
        }
        let provider_ref = if self.subject_ref.to_canonical_string() == SYSTEM_CORE_PROVIDER_REF {
            match binding.service().as_str() {
                "d2b.display.v3" => ResourceRef::parse("Provider/display-wayland").ok(),
                "d2b.clipboard.v3"
                | "d2b.clipboard.bridge.v3"
                | "d2b.clipboard.picker-coord.v3" => {
                    ResourceRef::parse("Provider/clipboard-wayland").ok()
                }
                "d2b.notification.v3" => ResourceRef::parse("Provider/notification-desktop").ok(),
                "d2b.config-nixos.v3" => ResourceRef::parse("Provider/config-nixos").ok(),
                _ => self.provider_ref,
            }
        } else {
            self.provider_ref
        };
        let subject_ref = self.subject_ref;
        let mut context = AuthenticatedSubjectContext::new(
            subject_ref.clone(),
            self.subject_uid,
            self.zone_ref,
            EvidenceClass::UnixPeer,
            binding.purpose().clone(),
            binding.service().clone(),
            SessionBinding::new(
                binding.schema_fingerprint().clone(),
                binding.transport_binding().clone(),
                binding.reconnect_generation(),
                binding.transcript_hash().clone(),
            ),
        );
        if binding.service().as_str() == "d2b.display.v3" {
            context = context.with_execution_ref(self.execution_ref.ok_or_else(|| {
                d2b_session::SessionError::new(
                    d2b_session::contract::SessionErrorCode::SubjectConfigurationMismatch,
                )
            })?);
        } else if let Some(execution_ref) = self.execution_ref {
            context = context.with_execution_ref(execution_ref);
        }
        if let (Some(provider_ref), Some(provider_generation)) =
            (provider_ref, self.provider_generation)
        {
            context = context
                .with_provider_ref(provider_ref)
                .with_provider_generation(provider_generation);
        }
        if let Some(process_ref) = self.process_ref {
            context = context.with_process_ref(process_ref);
        }
        if let Some(controller_generation) = self.controller_generation {
            context = context.with_controller_generation(controller_generation);
        }
        Ok(context)
    }
}

impl core::fmt::Debug for UnixSubjectRecord {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("UnixSubjectRecord(<redacted>)")
    }
}

struct AuthoritativeUnixSubjectResolver {
    subjects: Mutex<Vec<UnixSubjectRecord>>,
    max_subjects: usize,
}

impl AuthoritativeUnixSubjectResolver {
    fn deny_all(_max_subjects: usize) -> Self {
        Self {
            subjects: Mutex::new(Vec::new()),
            max_subjects: _max_subjects,
        }
    }

    fn resolve_for_service(
        &self,
        peer: PeerCredentials,
        service: &ServicePackage,
    ) -> d2b_session::Result<UnixSubjectRecord> {
        let mut subjects = self
            .subjects
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let matches = subjects
            .iter()
            .enumerate()
            .filter(|(_, subject)| {
                let peer_matches = if *service == ServicePackage::ResourceV3 {
                    subject
                        .expected_peer
                        .is_some_and(|expected| expected == peer)
                } else {
                    subject
                        .expected_peer
                        .is_some_and(|expected| expected == peer)
                        || subject
                            .expected_peer_uid
                            .is_some_and(|expected| peer.uid().as_raw() == expected)
                };
                peer_matches
                    && subject
                        .service
                        .as_ref()
                        .is_none_or(|expected| expected == service)
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(d2b_session::SessionError::new(
                d2b_session::contract::SessionErrorCode::SubjectConfigurationMismatch,
            ));
        }
        let index = matches[0];
        if subjects[index].expected_peer.is_some() {
            Ok(subjects.swap_remove(index))
        } else {
            Ok(subjects[index].clone())
        }
    }

    fn install(&self, subject: UnixSubjectRecord, zone: &ZoneId) -> d2b_session::Result<()> {
        if subject.zone_ref.name().as_str() != zone.as_str() {
            return Err(d2b_session::SessionError::new(
                d2b_session::contract::SessionErrorCode::SubjectConfigurationMismatch,
            ));
        }
        let mut subjects = self
            .subjects
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if subject.is_exact_resource_v3() {
            if let Some(index) = subjects
                .iter()
                .position(|existing| existing.has_same_exact_resource_v3_key(&subject))
            {
                subjects[index] = subject;
                return Ok(());
            }
        }
        if subjects.len() >= self.max_subjects {
            return Err(d2b_session::SessionError::new(
                d2b_session::contract::SessionErrorCode::SubjectConfigurationMismatch,
            ));
        }
        subjects.push(subject);
        Ok(())
    }

    fn install_many(
        &self,
        new_subjects: Vec<UnixSubjectRecord>,
        zone: &ZoneId,
    ) -> d2b_session::Result<()> {
        if new_subjects
            .iter()
            .any(|subject| subject.zone_ref.name().as_str() != zone.as_str())
        {
            return Err(d2b_session::SessionError::new(
                d2b_session::contract::SessionErrorCode::SubjectConfigurationMismatch,
            ));
        }
        let mut subjects = self
            .subjects
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if subjects.len().saturating_add(new_subjects.len()) > self.max_subjects {
            return Err(d2b_session::SessionError::new(
                d2b_session::contract::SessionErrorCode::SubjectConfigurationMismatch,
            ));
        }
        subjects.extend(new_subjects);
        Ok(())
    }
}

impl UnixSubjectRecord {
    fn is_exact_resource_v3(&self) -> bool {
        self.expected_peer.is_some() && self.service == Some(ServicePackage::ResourceV3)
    }

    fn has_same_exact_resource_v3_key(&self, other: &Self) -> bool {
        self.is_exact_resource_v3()
            && other.is_exact_resource_v3()
            && self.subject_ref == other.subject_ref
            && self.process_ref == other.process_ref
            && self.service == other.service
    }
}

impl core::fmt::Debug for AuthoritativeUnixSubjectResolver {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AuthoritativeUnixSubjectResolver(<redacted>)")
    }
}

struct InteractionSubjectAuthority {
    zone: ZoneId,
    controller_generation: ControllerGeneration,
}

struct InteractionSubjectRegistrar {
    authority: Arc<InteractionSubjectAuthority>,
}

struct CommittedInteractionSubjectInstallBody {
    zone: ZoneId,
    display_subject_ref: ResourceRef,
    display_subject_uid: ResourceUid,
    expected_peer_uid: u32,
    execution_ref: ResourceRef,
    display_generation: ResourceGeneration,
    clipboard_generation: Option<ResourceGeneration>,
    notification_generation: Option<ResourceGeneration>,
    clipboard_provider_uid: Option<ResourceUid>,
    notification_provider_uid: Option<ResourceUid>,
}

/// Opaque issuer for one Zone's committed interaction subject projection.
///
/// The issuer is returned only by the opt-in Zone-runtime bus constructor.
/// It is consumed when the Zone runtime seals its private committed identity.
///
/// ```compile_fail
/// use d2b_bus::CommittedInteractionSubjectIssuer;
///
/// fn clone(value: CommittedInteractionSubjectIssuer) {
///     let _ = value.clone();
/// }
/// ```
///
/// ```compile_fail
/// use d2b_bus::CommittedInteractionSubjectIssuer;
///
/// fn requires_default<T: Default>() {}
/// requires_default::<CommittedInteractionSubjectIssuer>();
/// ```
///
/// ```compile_fail
/// use d2b_bus::CommittedInteractionSubjectIssuer;
///
/// fn format(value: &CommittedInteractionSubjectIssuer) {
///     let _ = format!("{value:?}");
/// }
/// ```
pub struct CommittedInteractionSubjectIssuer {
    authority: Arc<InteractionSubjectAuthority>,
}

/// Opaque, single-use committed interaction subject installation capability.
///
/// The capability cannot be constructed, inspected, cloned, defaulted,
/// serialized, or formatted by downstream crates:
///
/// ```compile_fail
/// use d2b_bus::CommittedInteractionSubjectInstall;
///
/// let _ = CommittedInteractionSubjectInstall {};
/// ```
///
/// ```compile_fail
/// use d2b_bus::CommittedInteractionSubjectInstall;
///
/// fn inspect(value: &CommittedInteractionSubjectInstall) {
///     let _ = &value.body;
/// }
/// ```
///
/// ```compile_fail
/// use d2b_bus::CommittedInteractionSubjectInstall;
///
/// fn clone(value: CommittedInteractionSubjectInstall) {
///     let _ = value.clone();
/// }
/// ```
///
/// ```compile_fail
/// use d2b_bus::CommittedInteractionSubjectInstall;
///
/// fn requires_default<T: Default>() {}
/// requires_default::<CommittedInteractionSubjectInstall>();
/// ```
///
/// ```compile_fail
/// use d2b_bus::CommittedInteractionSubjectInstall;
///
/// fn serialize(value: &CommittedInteractionSubjectInstall) {
///     let _ = serde_json::to_string(value);
/// }
/// ```
///
/// ```compile_fail
/// use d2b_bus::CommittedInteractionSubjectInstall;
///
/// fn format(value: &CommittedInteractionSubjectInstall) {
///     let _ = format!("{value:?}");
///     let _ = format!("{value}");
/// }
/// ```
pub struct CommittedInteractionSubjectInstall {
    authority: Arc<InteractionSubjectAuthority>,
    body: CommittedInteractionSubjectInstallBody,
}

impl CommittedInteractionSubjectIssuer {
    /// Seal one verified Zone-runtime projection for this registrar instance.
    ///
    /// The controller generation is captured from the bus authorizer when the
    /// issuer is created and is deliberately absent from this API.
    pub fn seal(
        self,
        zone: ZoneId,
        display_subject_ref: ResourceRef,
        display_subject_uid: ResourceUid,
        expected_peer_uid: u32,
        execution_ref: ResourceRef,
        display_generation: ResourceGeneration,
        clipboard_generation: Option<ResourceGeneration>,
        notification_generation: Option<ResourceGeneration>,
        clipboard_provider_uid: Option<ResourceUid>,
        notification_provider_uid: Option<ResourceUid>,
    ) -> d2b_session::Result<CommittedInteractionSubjectInstall> {
        if self.authority.zone != zone {
            return Err(subject_configuration_mismatch());
        }
        Ok(CommittedInteractionSubjectInstall {
            authority: self.authority,
            body: CommittedInteractionSubjectInstallBody {
                zone,
                display_subject_ref,
                display_subject_uid,
                expected_peer_uid,
                execution_ref,
                display_generation,
                clipboard_generation,
                notification_generation,
                clipboard_provider_uid,
                notification_provider_uid,
            },
        })
    }
}

impl CommittedInteractionSubjectInstall {
    fn open(
        self,
        registrar: &InteractionSubjectRegistrar,
        expected_zone: &ZoneId,
    ) -> d2b_session::Result<CommittedInteractionSubjectInstallBody> {
        if !Arc::ptr_eq(&self.authority, &registrar.authority)
            || &self.body.zone != expected_zone
            || &registrar.authority.zone != expected_zone
        {
            return Err(subject_configuration_mismatch());
        }
        Ok(self.body)
    }
}

const _: fn() = || {
    trait CapabilityMustNotImplementCloneCopyDefaultDebugOrFrom<A> {
        fn some_item() {}
    }
    impl<T: ?Sized> CapabilityMustNotImplementCloneCopyDefaultDebugOrFrom<()> for T {}
    impl<T: Clone> CapabilityMustNotImplementCloneCopyDefaultDebugOrFrom<u8> for T {}
    impl<T: Copy> CapabilityMustNotImplementCloneCopyDefaultDebugOrFrom<u16> for T {}
    impl<T: Default> CapabilityMustNotImplementCloneCopyDefaultDebugOrFrom<u32> for T {}
    impl<T: core::fmt::Debug> CapabilityMustNotImplementCloneCopyDefaultDebugOrFrom<u64> for T {}
    impl<T: From<()>> CapabilityMustNotImplementCloneCopyDefaultDebugOrFrom<u128> for T {}
    let _ = <CommittedInteractionSubjectIssuer as CapabilityMustNotImplementCloneCopyDefaultDebugOrFrom<
        _,
    >>::some_item;
    let _ = <CommittedInteractionSubjectInstall as CapabilityMustNotImplementCloneCopyDefaultDebugOrFrom<
        _,
    >>::some_item;
};

fn subject_configuration_mismatch() -> d2b_session::SessionError {
    d2b_session::SessionError::new(
        d2b_session::contract::SessionErrorCode::SubjectConfigurationMismatch,
    )
}

/// Trusted committed state used to install an external Provider controller
/// Process subject for the ResourceV3 service.
pub struct CommittedControllerProcessSubjectInput {
    /// The Provider resource identity committed for the controller.
    pub provider_ref: ResourceRef,
    pub provider_uid: ResourceUid,
    /// The controller Process resource committed for this Provider.
    pub process_ref: ResourceRef,
    pub zone_ref: ResourceRef,
    /// The Host or Guest where the controller executes.
    pub execution_ref: ResourceRef,
    pub provider_generation: ResourceGeneration,
    pub controller_generation: ControllerGeneration,
}

/// Single, non-cloneable authority that consumes authenticated registrations.
pub struct ZoneRegistrar {
    core: Arc<BusCore>,
    component_admission: ComponentSessionRegistrar,
    unix_subjects: AuthoritativeUnixSubjectResolver,
    interaction_subjects: Option<InteractionSubjectRegistrar>,
}

struct ComponentSessionAdmissionIdentity;

struct ComponentSessionRegistrar {
    identity: Arc<ComponentSessionAdmissionIdentity>,
}

/// Single-use proof that a ComponentSession candidate was minted by one
/// concrete Zone registrar.
///
/// Downstream code cannot fabricate the proof or clone it:
///
/// ```compile_fail
/// use d2b_bus::ComponentSessionAdmission;
///
/// fn inspect(value: &ComponentSessionAdmission) {
///     let _ = &value.identity;
/// }
/// ```
///
/// The capability must not acquire general construction traits:
///
/// ```compile_fail
/// use d2b_bus::ComponentSessionAdmission;
///
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<ComponentSessionAdmission>();
/// ```
///
/// ```compile_fail
/// use d2b_bus::ComponentSessionAdmission;
///
/// fn requires_default<T: Default>() {}
/// requires_default::<ComponentSessionAdmission>();
/// ```
///
/// ```compile_fail
/// use d2b_bus::ComponentSessionAdmission;
///
/// let _: ComponentSessionAdmission = <() as Into<ComponentSessionAdmission>>::into(());
/// ```
pub struct ComponentSessionAdmission {
    identity: Arc<ComponentSessionAdmissionIdentity>,
}

const _: fn() = || {
    // Any guarded impl makes this assertion ambiguous. Remove the capability
    // trait impl instead of weakening this construction boundary.
    trait CapabilityMustNotImplementCloneCopyDefaultOrFrom<A> {
        fn some_item() {}
    }
    impl<T: ?Sized> CapabilityMustNotImplementCloneCopyDefaultOrFrom<()> for T {}
    impl<T: Clone> CapabilityMustNotImplementCloneCopyDefaultOrFrom<u8> for T {}
    impl<T: Copy> CapabilityMustNotImplementCloneCopyDefaultOrFrom<u16> for T {}
    impl<T: Default> CapabilityMustNotImplementCloneCopyDefaultOrFrom<u32> for T {}
    impl<T: From<Arc<ComponentSessionAdmissionIdentity>>>
        CapabilityMustNotImplementCloneCopyDefaultOrFrom<u64> for T
    {
    }
    impl<T: From<()>> CapabilityMustNotImplementCloneCopyDefaultOrFrom<u128> for T {}
    let _ =
        <ComponentSessionAdmission as CapabilityMustNotImplementCloneCopyDefaultOrFrom<_>>::some_item;
};

const _: fn() = || {
    // Any guarded impl makes this assertion ambiguous. Remove the capability
    // trait impl instead of weakening this construction boundary.
    trait CapabilityMustNotImplementCloneCopyDefaultOrFrom<A> {
        fn some_item() {}
    }
    impl<T: ?Sized> CapabilityMustNotImplementCloneCopyDefaultOrFrom<()> for T {}
    impl<T: Clone> CapabilityMustNotImplementCloneCopyDefaultOrFrom<u8> for T {}
    impl<T: Copy> CapabilityMustNotImplementCloneCopyDefaultOrFrom<u16> for T {}
    impl<T: Default> CapabilityMustNotImplementCloneCopyDefaultOrFrom<u32> for T {}
    impl<T: From<ComponentSessionAdmission>> CapabilityMustNotImplementCloneCopyDefaultOrFrom<u64>
        for T
    {
    }
    let _ = <SessionAcceptor<ComponentSessionAdmission> as CapabilityMustNotImplementCloneCopyDefaultOrFrom<_>>::some_item;
    let _ = <AuthenticatedComponentSession<ComponentSessionAdmission> as CapabilityMustNotImplementCloneCopyDefaultOrFrom<_>>::some_item;
};

#[cfg(any(
    d2b_capability_trait_mutation = "component-session-admission-clone",
    d2b_capability_trait_mutation = "component-session-admission-default",
    d2b_capability_trait_mutation = "component-session-admission-from-unit"
))]
macro_rules! mutate_component_session_admission_trait {
    (clone) => {
        impl Clone for ComponentSessionAdmission {
            fn clone(&self) -> Self {
                unreachable!()
            }
        }
    };
    (default) => {
        impl Default for ComponentSessionAdmission {
            fn default() -> Self {
                unreachable!()
            }
        }
    };
    (from_unit) => {
        impl From<()> for ComponentSessionAdmission {
            fn from(_value: ()) -> Self {
                unreachable!()
            }
        }
    };
}

#[cfg(d2b_capability_trait_mutation = "component-session-admission-clone")]
mutate_component_session_admission_trait!(clone);
#[cfg(d2b_capability_trait_mutation = "component-session-admission-default")]
mutate_component_session_admission_trait!(default);
#[cfg(d2b_capability_trait_mutation = "component-session-admission-from-unit")]
mutate_component_session_admission_trait!(from_unit);

impl core::fmt::Debug for ComponentSessionAdmission {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ComponentSessionAdmission(<redacted>)")
    }
}

impl SessionRegistrationCapability<ComponentSessionRegistrar> for ComponentSessionAdmission {
    type Error = BusError;

    fn consume(self, registrar: &ComponentSessionRegistrar) -> Result<(), Self::Error> {
        if Arc::ptr_eq(&self.identity, &registrar.identity) {
            Ok(())
        } else {
            Err(BusError::SessionMismatch)
        }
    }
}

impl ZoneRegistrar {
    /// Install the fixed system-core Provider subject for one verified peer.
    pub fn install_system_core_subject(
        &self,
        verified_peer: &VerifiedUnixPeer,
    ) -> d2b_session::Result<()> {
        let subject = UnixSubjectRecord::new(
            UnixSubjectKind::Provider,
            ResourceRef::parse(SYSTEM_CORE_PROVIDER_REF).expect("fixed Provider ref"),
            ResourceUid::parse(SYSTEM_CORE_PROVIDER_UID).expect("fixed Provider uid"),
            ResourceRef::parse(&format!("Zone/{}", self.core.zone.as_str()))
                .expect("fixed Zone ref"),
            verified_peer.credentials(),
        )?
        .for_service(ServicePackage::ResourceV3);
        self.unix_subjects.install(subject, &self.core.zone)
    }

    /// Install a committed external Provider controller Process subject for
    /// one exact verified peer.
    pub fn install_committed_controller_process_subject(
        &self,
        verified_peer: &VerifiedUnixPeer,
        committed: CommittedControllerProcessSubjectInput,
    ) -> d2b_session::Result<()> {
        self.install_committed_controller_process_subject_for_service(
            verified_peer,
            committed,
            ServicePackage::ResourceV3,
        )
    }

    /// Install an external Provider controller Process subject for one exact
    /// authenticated service package.
    pub fn install_committed_controller_process_subject_for_service(
        &self,
        verified_peer: &VerifiedUnixPeer,
        committed: CommittedControllerProcessSubjectInput,
        service: ServicePackage,
    ) -> d2b_session::Result<()> {
        let CommittedControllerProcessSubjectInput {
            provider_ref,
            provider_uid,
            process_ref,
            zone_ref,
            execution_ref,
            provider_generation,
            controller_generation,
        } = committed;
        let subject = UnixSubjectRecord::new(
            UnixSubjectKind::Provider,
            provider_ref.clone(),
            provider_uid,
            zone_ref,
            verified_peer.credentials(),
        )?
        .with_provider(provider_ref, provider_generation)?
        .with_process_ref(process_ref)?
        .with_controller_generation(controller_generation)
        .with_execution_ref(execution_ref)?
        .for_service(service);
        self.unix_subjects.install(subject, &self.core.zone)
    }

    #[cfg(test)]
    pub(crate) fn install_test_unix_subject(
        &self,
        subject: UnixSubjectRecord,
    ) -> d2b_session::Result<()> {
        self.unix_subjects.install(subject, &self.core.zone)
    }

    #[cfg(any(test, feature = "production-rss-fixture"))]
    pub(crate) fn register(
        &mut self,
        registration: SessionRegistration,
    ) -> Result<BusIngress, BusError> {
        let context = registration.context().ok_or(BusError::SessionMismatch)?;
        let direction = BusDirection::from_context(Some(context));
        if let Err(error) = self
            .core
            .authorizer
            .authorize_connect(context, &self.core.zone)
        {
            self.core
                .metrics
                .registration(direction, BusRegistrationOutcome::Rejected);
            return Err(error.into());
        }
        let session = match self.core.lock_registry().register(registration) {
            Ok(session) => session,
            Err(error) => {
                self.core
                    .metrics
                    .registration(direction, BusRegistrationOutcome::Rejected);
                return Err(error.into());
            }
        };
        self.core.record_session_registered(session);
        Ok(BusIngress {
            core: Arc::clone(&self.core),
            session,
            closed: false,
            incoming: empty_component_requests(),
            attachments: None,
        })
    }

    /// Replace a session with the exact next reconnect generation.
    #[cfg(test)]
    pub(crate) async fn reconnect(
        &mut self,
        mut previous: BusIngress,
        registration: SessionRegistration,
    ) -> Result<BusIngress, BusError> {
        if !Arc::ptr_eq(&self.core, &previous.core) || previous.closed {
            return Err(BusError::SessionMismatch);
        }
        let context = registration.context().ok_or(BusError::SessionMismatch)?;
        self.core
            .authorizer
            .authorize_connect(context, &self.core.zone)?;
        self.core
            .lock_registry()
            .validate_reconnect(previous.session, &registration)?;
        let previous_metrics = self.core.session_metrics(previous.session);
        let invalidation = self.core.lock_registry().invalidate(previous.session);
        if let Some(invalidation) = invalidation {
            invalidation.await;
        }
        let session = self
            .core
            .lock_registry()
            .reconnect(previous.session, registration)?;
        self.core.record_session_disconnected_values(
            previous_metrics.0,
            previous_metrics.1,
            BusDisconnectOutcome::Revoked,
        );
        self.core.record_session_registered(session);
        let targets = self.core.lock_operations().cancel_session(previous.session);
        self.core.streams.cancel_session(previous.session);
        self.core.dispatch_cancel_targets(targets);
        self.core
            .cancel_deliveries
            .abort_destination(previous.session);
        previous.closed = true;
        Ok(BusIngress {
            core: Arc::clone(&self.core),
            session,
            closed: false,
            incoming: empty_component_requests(),
            attachments: None,
        })
    }
}

struct ComponentEndpoint {
    session: AsyncMutex<AuthenticatedComponentSession<()>>,
    ttrpc: AuthenticatedTtrpcHandle,
    responses: Arc<ComponentResponses>,
    _response_task: Option<ComponentResponseTask>,
    clock: Arc<dyn BusClock>,
    locality: d2b_contracts_resource::v3::identity::Locality,
    generation: u64,
    cancellation: SessionCancellationHandle,
    activity: Mutex<ComponentActivity>,
    correlations: Mutex<CorrelationIds>,
}

type ComponentResponse = Result<Vec<u8>, EndpointError>;

#[derive(Default)]
struct ComponentResponseState {
    terminal: Option<EndpointError>,
    waiters: BTreeMap<d2b_session::contract::RequestId, oneshot::Sender<ComponentResponse>>,
    inbound_streams: BTreeSet<u32>,
}

struct ComponentResponses {
    generation: u64,
    ttrpc: AuthenticatedTtrpcHandle,
    requests: mpsc::Sender<Vec<u8>>,
    state: Mutex<ComponentResponseState>,
}

type ComponentRequestChannel = Arc<AsyncMutex<mpsc::Receiver<Vec<u8>>>>;

struct ComponentResponseTask(tokio::task::AbortHandle);

impl Drop for ComponentResponseTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl ComponentResponses {
    fn new(
        generation: u64,
        ttrpc: AuthenticatedTtrpcHandle,
    ) -> (Arc<Self>, ComponentRequestChannel) {
        let (requests, receiver) = mpsc::channel(32);
        (
            Arc::new(Self {
                generation,
                ttrpc,
                requests,
                state: Mutex::new(ComponentResponseState::default()),
            }),
            Arc::new(AsyncMutex::new(receiver)),
        )
    }

    fn spawn(self: &Arc<Self>) -> ComponentResponseTask {
        let dispatcher = Arc::clone(self);
        let task = tokio::spawn(async move { dispatcher.run().await });
        ComponentResponseTask(task.abort_handle())
    }

    async fn run(&self) {
        loop {
            match self.ttrpc.receive().await {
                #[cfg(test)]
                Ok(frame)
                    if ttrpc_request_id(self.generation, &frame)
                        .ok()
                        .is_some_and(|request_id| self.has_waiter(&request_id)) =>
                {
                    let request_id = match ttrpc_request_id(self.generation, &frame) {
                        Ok(request_id) => request_id,
                        Err(_) => {
                            self.terminate(EndpointError::Rejected);
                            return;
                        }
                    };
                    self.deliver(request_id, Ok(frame));
                }
                Ok(frame)
                    if d2b_session::ttrpc_is_request(&frame)
                        && ttrpc_request_id(self.generation, &frame)
                            .ok()
                            .is_some_and(|request_id| self.has_waiter(&request_id)) =>
                {
                    let request_id = match ttrpc_request_id(self.generation, &frame) {
                        Ok(request_id) => request_id,
                        Err(_) => {
                            self.terminate(EndpointError::Rejected);
                            return;
                        }
                    };
                    self.deliver(request_id, Ok(frame));
                }
                Ok(frame) if d2b_session::ttrpc_is_request(&frame) => {
                    let stream_id = match ttrpc_stream_id(&frame) {
                        Ok(stream_id) => stream_id,
                        Err(_) => {
                            self.terminate(EndpointError::Rejected);
                            return;
                        }
                    };
                    let accepted = {
                        let mut state = self
                            .state
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        state.inbound_streams.len() < 32 && state.inbound_streams.insert(stream_id)
                    };
                    if !accepted {
                        self.terminate(EndpointError::Rejected);
                        return;
                    }
                    if self.requests.send(frame).await.is_err() {
                        self.terminate(EndpointError::Rejected);
                        return;
                    }
                }
                Ok(response) if d2b_session::ttrpc_is_response(&response) => {
                    match ttrpc_request_id(self.generation, &response) {
                        Ok(request_id) => self.deliver(request_id, Ok(response)),
                        Err(_) => {
                            self.terminate(EndpointError::Rejected);
                            return;
                        }
                    }
                }
                #[cfg(test)]
                Ok(frame) if ttrpc_request_id(self.generation, &frame).is_ok() => {}
                Ok(_) => {
                    self.terminate(EndpointError::Rejected);
                    return;
                }
                Err(error) => {
                    self.terminate(EndpointError::from(error));
                    return;
                }
            }
        }
    }

    fn deliver(&self, request_id: d2b_session::contract::RequestId, response: ComponentResponse) {
        let sender = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.waiters.remove(&request_id)
        };
        if let Some(sender) = sender {
            let _ = sender.send(response);
        }
    }

    fn has_waiter(&self, request_id: &d2b_session::contract::RequestId) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .waiters
            .contains_key(request_id)
    }

    fn terminate(&self, error: EndpointError) {
        let waiters = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.terminal = Some(error);
            state.inbound_streams.clear();
            std::mem::take(&mut state.waiters)
        };
        for (_, sender) in waiters {
            let _ = sender.send(Err(error));
        }
    }

    async fn send_inbound_response(&self, frame: Vec<u8>) -> Result<(), EndpointError> {
        if !d2b_session::ttrpc_is_response(&frame) {
            return Err(EndpointError::Rejected);
        }
        let stream_id = ttrpc_stream_id(&frame).map_err(|_| EndpointError::Rejected)?;
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if state.terminal.is_some() || !state.inbound_streams.remove(&stream_id) {
                return Err(EndpointError::Rejected);
            }
        }
        self.ttrpc
            .send_response(frame)
            .await
            .map_err(EndpointError::from)
    }
}

const RESERVED_CORRELATION_MAX: u32 = 1024;

struct CorrelationIds {
    key: Option<u64>,
    issued: u64,
    limit: u64,
}

impl CorrelationIds {
    fn new(limit: u64) -> Self {
        Self {
            key: None,
            issued: 0,
            limit,
        }
    }

    #[cfg(test)]
    fn with_key(limit: u64, key: u64) -> Self {
        Self {
            key: Some(key),
            issued: 0,
            limit,
        }
    }

    fn allocate(&mut self) -> Result<u32, CorrelationAllocationError> {
        if self.issued >= self.limit {
            return Err(CorrelationAllocationError::ReconnectRequired);
        }
        let key = match self.key {
            Some(key) => key,
            None => {
                let mut bytes = [0_u8; 8];
                getrandom::fill(&mut bytes).map_err(|_| CorrelationAllocationError::Entropy)?;
                let key = u64::from_ne_bytes(bytes);
                self.key = Some(key);
                key
            }
        };
        let input = FIRST_CORRELATION_ID + (self.issued as u32) * 2;
        self.issued += 1;
        let mut candidate = permute_correlation(input, key);
        loop {
            if candidate > RESERVED_CORRELATION_MAX && candidate % 2 == 1 {
                return Ok(candidate);
            }
            candidate = permute_correlation(candidate, key);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CorrelationAllocationError {
    Entropy,
    ReconnectRequired,
}

fn permute_correlation(value: u32, key: u64) -> u32 {
    let mut left = (value >> 16) as u16;
    let mut right = value as u16;
    for round in 0..6_u64 {
        let next = left ^ correlation_round(right, key, round);
        left = right;
        right = next;
    }
    (u32::from(left) << 16) | u32::from(right)
}

fn correlation_round(value: u16, key: u64, round: u64) -> u16 {
    let mut mixed = key ^ u64::from(value) ^ (round + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    mixed ^= mixed >> 30;
    mixed = mixed.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    mixed ^= mixed >> 27;
    mixed = mixed.wrapping_mul(0x94d0_49bb_1331_11eb);
    mixed ^= mixed >> 31;
    (mixed ^ (mixed >> 16)) as u16
}

#[derive(Clone)]
struct ActiveComponentRequest {
    request_id: d2b_session::contract::RequestId,
    valid: Arc<AtomicBool>,
    attempt: Cancellation,
    write_guard: d2b_session::Cancellation,
}

#[derive(Default)]
struct ComponentActivity {
    revoked: bool,
    requests: BTreeMap<OperationId, Vec<ActiveComponentRequest>>,
}

impl ComponentActivity {
    fn insert(&mut self, operation: OperationId, request: ActiveComponentRequest) -> bool {
        if self.revoked {
            return false;
        }
        self.requests.entry(operation).or_default().push(request);
        true
    }

    fn remove(
        &mut self,
        operation: &OperationId,
        attempt: &Cancellation,
    ) -> Option<ActiveComponentRequest> {
        let requests = self.requests.get_mut(operation)?;
        let index = requests
            .iter()
            .position(|request| request.attempt.is_same_attempt(attempt))?;
        let request = requests.remove(index);
        if requests.is_empty() {
            self.requests.remove(operation);
        }
        Some(request)
    }

    fn revoke(&mut self) -> Vec<crate::registry::SessionInvalidation> {
        self.revoked = true;
        self.requests
            .values()
            .flat_map(|requests| requests.iter())
            .map(|request| {
                request.valid.store(false, Ordering::Release);
                let revocation = request.write_guard.cancel_and_wait();
                Box::pin(async move {
                    revocation.await;
                }) as crate::registry::SessionInvalidation
            })
            .collect()
    }
}

impl ComponentEndpoint {
    fn is_revoked(&self) -> bool {
        self.activity
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .revoked
    }

    fn remove_active(
        &self,
        operation: &OperationId,
        attempt: &Cancellation,
    ) -> Option<ActiveComponentRequest> {
        let mut activity = self
            .activity
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        activity.remove(operation, attempt)
    }
}

fn publish_component_request(
    activity: &Mutex<ComponentActivity>,
    responses: &Mutex<ComponentResponseState>,
    operation: OperationId,
    request: ActiveComponentRequest,
) -> Result<oneshot::Receiver<ComponentResponse>, EndpointError> {
    publish_component_request_with_hook(activity, responses, operation, request, || {})
}

fn publish_component_request_with_hook(
    activity: &Mutex<ComponentActivity>,
    responses: &Mutex<ComponentResponseState>,
    operation: OperationId,
    request: ActiveComponentRequest,
    after_publication_locks: impl FnOnce(),
) -> Result<oneshot::Receiver<ComponentResponse>, EndpointError> {
    let mut activity = activity
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut responses = responses
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    after_publication_locks();
    if request.attempt.is_cancelled() || activity.revoked {
        return Err(cancelled_endpoint());
    }
    if let Some(error) = responses.terminal {
        return Err(error);
    }
    if responses.waiters.contains_key(&request.request_id) {
        return Err(EndpointError::Internal);
    }
    let (sender, receiver) = oneshot::channel();
    responses.waiters.insert(request.request_id.clone(), sender);
    let inserted = activity.insert(operation, request);
    debug_assert!(
        inserted,
        "revocation cannot change while activity is locked"
    );
    Ok(receiver)
}

fn terminalize_component_request(
    activity: &Mutex<ComponentActivity>,
    responses: &Mutex<ComponentResponseState>,
    operation: &OperationId,
    attempt: &Cancellation,
) -> Option<ActiveComponentRequest> {
    let mut activity = activity
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut responses = responses
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let active = activity.remove(operation, attempt);
    if let Some(active) = &active {
        active.valid.store(false, Ordering::Release);
        active.write_guard.cancel();
        responses.waiters.remove(&active.request_id);
    }
    active
}

#[async_trait::async_trait]
impl crate::registry::BusEndpoint for ComponentEndpoint {
    fn invalidate_session(&self) -> crate::registry::SessionInvalidation {
        let writer_fence = self.cancellation.revoke_generation_writes();
        let revocations = self
            .activity
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .revoke();
        Box::pin(async move {
            writer_fence.await;
            for revocation in revocations {
                revocation.await;
            }
        })
    }

    async fn authorize(
        &self,
        route: &RouteKey,
        verb: d2b_resource_api::authz::SessionVerb,
        target: Option<&ResourceRef>,
        now_tick: u64,
    ) -> Result<(), EndpointError> {
        let request =
            if self.locality == d2b_contracts_resource::v3::identity::Locality::AdjacentZone {
                SessionAuthorizationRequest::relay(
                    route.service().clone(),
                    route.member().as_str(),
                    route.zone().clone(),
                    target.cloned(),
                    verb,
                    route.zone().clone(),
                )
            } else {
                SessionAuthorizationRequest::new(
                    verb,
                    route.service().clone(),
                    route.member().as_str(),
                    route.zone().clone(),
                    target.cloned(),
                )
            }
            .map_err(|_| EndpointError::Rejected)?;
        self.session
            .lock()
            .await
            .authorize(request, now_tick)
            .await
            .map(|_| ())
            .map_err(EndpointError::from)
    }

    async fn invoke(&self, request: DeliveredInvocation) -> Result<BusResponse, EndpointError> {
        if self.is_revoked() {
            return Err(cancelled_endpoint());
        }
        let ordinary = d2b_resource_api::authz::SessionVerb::Invoke;
        let operation = SessionOperation::method(
            request.route().service().clone(),
            request.route().member().as_str(),
        )
        .map_err(|_| EndpointError::Rejected)?;
        let verb = operation.required_verb(ordinary);
        let now_tick = self.clock.now_tick();
        let caller_stream_id =
            ttrpc_stream_id(request.payload()).map_err(|_| EndpointError::Rejected)?;
        let internal_stream_id = match self
            .correlations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .allocate()
        {
            Ok(stream_id) => stream_id,
            Err(CorrelationAllocationError::Entropy) => return Err(EndpointError::Internal),
            Err(CorrelationAllocationError::ReconnectRequired) => {
                let error = EndpointError::from(d2b_session::SessionError::new(
                    d2b_session::contract::SessionErrorCode::SessionDisconnected,
                ));
                self.responses.terminate(error);
                return Err(error);
            }
        };
        let mut outbound_frame = request.payload().to_vec();
        rewrite_ttrpc_stream_id(&mut outbound_frame, internal_stream_id)
            .map_err(|_| EndpointError::Rejected)?;
        if let Some((query, watch)) = match request.resource_call() {
            Some(ResourceCall::List(query)) if query.scope().is_some() => Some((query, false)),
            Some(ResourceCall::Watch(query)) if query.scope().is_some() => Some((query, true)),
            _ => None,
        } {
            let filters = query
                .filters
                .iter()
                .map(|filter| d2b_resource_store::StoreFilter {
                    field: filter.field.clone(),
                    values: filter.values.clone(),
                })
                .collect::<Vec<_>>();
            outbound_frame = d2b_resource_api::attach_scoped_query_frame(
                &outbound_frame,
                query.resource_types(),
                query.resource_names(),
                &filters,
                watch,
            )
            .map_err(|_| EndpointError::Rejected)?;
        }
        if let Some(ResourceCall::ScopedCommitBatch {
            assignment,
            mutations,
        }) = request.resource_call()
        {
            let transport = ScopedCommitTransport::new(assignment.clone(), mutations.clone())
                .map_err(|_| EndpointError::Rejected)?;
            outbound_frame =
                d2b_resource_api::attach_scoped_commit_frame(&outbound_frame, &transport)
                    .map_err(|_| EndpointError::Rejected)?;
        } else if matches!(request.resource_call(), Some(ResourceCall::CommitBatch(_))) {
            d2b_resource_api::reject_scoped_commit_frame(&outbound_frame)
                .map_err(|_| EndpointError::Rejected)?;
        }
        let request_id = ttrpc_request_id(self.generation, &outbound_frame)
            .map_err(|_| EndpointError::Rejected)?;
        let target = request
            .resource_call()
            .and_then(ResourceCall::session_target)
            .cloned();
        let authorization =
            if self.locality == d2b_contracts_resource::v3::identity::Locality::AdjacentZone {
                SessionAuthorizationRequest::relay(
                    request.route().service().clone(),
                    request.route().member().as_str(),
                    request.route().zone().clone(),
                    target,
                    verb,
                    request.route().zone().clone(),
                )
            } else {
                SessionAuthorizationRequest::new(
                    verb,
                    request.route().service().clone(),
                    request.route().member().as_str(),
                    request.route().zone().clone(),
                    target,
                )
            }
            .map_err(|_| EndpointError::Rejected)?;
        let permit = {
            let mut session = self.session.lock().await;
            session
                .authorize(authorization, now_tick)
                .await
                .map_err(EndpointError::from)?
        };
        let valid = Arc::new(AtomicBool::new(true));
        let attempt = request.cancellation().clone();
        let write_guard = self.ttrpc.attempt_guard();
        let response = publish_component_request(
            &self.activity,
            &self.responses.state,
            request.operation().id().clone(),
            ActiveComponentRequest {
                request_id: request_id.clone(),
                valid: Arc::clone(&valid),
                attempt: attempt.clone(),
                write_guard: write_guard.clone(),
            },
        )?;
        if let Err(error) = self
            .ttrpc
            .start(
                permit,
                request_id.clone(),
                outbound_frame,
                write_guard,
                now_tick,
            )
            .await
        {
            terminalize_component_request(
                &self.activity,
                &self.responses.state,
                request.operation().id(),
                &attempt,
            );
            return Err(EndpointError::from(error));
        }
        let response = response.await.unwrap_or(Err(EndpointError::Internal));
        self.remove_active(request.operation().id(), &attempt);
        match self.ttrpc.complete(request_id).await {
            Err(cleanup_error)
                if cleanup_error.code()
                    != d2b_contracts_zone_session::v3::component_session::SessionErrorCode::SessionDisconnected =>
            {
                return Err(EndpointError::from(cleanup_error));
            }
            _ => {}
        }
        let mut response = response?;
        rewrite_ttrpc_stream_id(&mut response, caller_stream_id)
            .map_err(|_| EndpointError::Rejected)?;
        if self.is_revoked() || !valid.load(Ordering::Acquire) {
            return Err(cancelled_endpoint());
        }
        Ok(BusResponse::new(response))
    }

    async fn open_stream(&self, _request: DeliveredStream) -> Result<(), EndpointError> {
        Err(EndpointError::Unavailable)
    }

    async fn send_inbound_response(&self, frame: Vec<u8>) -> Result<(), EndpointError> {
        if self.is_revoked() {
            return Err(cancelled_endpoint());
        }
        self.responses.send_inbound_response(frame).await
    }

    fn terminalize_cancel(
        &self,
        operation: &OperationId,
        attempt: &Cancellation,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), EndpointError>> + Send + 'static>,
    > {
        let Some(active) = terminalize_component_request(
            &self.activity,
            &self.responses.state,
            operation,
            attempt,
        ) else {
            return Box::pin(async { Ok(()) });
        };
        let delivery = self.cancellation.cancel(active.request_id);
        Box::pin(async move { delivery.await.map_err(EndpointError::from) })
    }
}

fn cancelled_endpoint() -> EndpointError {
    EndpointError::from(d2b_session::SessionError::new(
        d2b_session::contract::SessionErrorCode::Cancelled,
    ))
}

impl ZoneRegistrar {
    /// Mint a single-use acceptor bound to this registrar instance.
    pub fn component_session_acceptor(
        &self,
        policy: EndpointPolicy,
        verified_peer: VerifiedUnixPeer,
    ) -> d2b_session::Result<SessionAcceptor<ComponentSessionAdmission>> {
        verified_peer.validate_transport(policy.transport_binding.transport)?;
        let subject = self
            .unix_subjects
            .resolve_for_service(verified_peer.credentials(), &policy.service)?;
        let connect_authorizer = Arc::clone(&self.core.authorizer);
        let request_authorizer = Arc::clone(&self.core.authorizer);
        SessionAcceptor::from_verified_adapter(
            policy,
            self.core.zone.clone(),
            move |evidence, binding, expected_zone, now_tick| {
                let context = subject.bind(verified_peer, &evidence, binding, expected_zone)?;
                let lease =
                    connect_authorizer.authenticate_session(&context, expected_zone, now_tick)?;
                Ok((context, lease))
            },
            move |subject, request, previous_lease, now_tick| {
                request_authorizer.authorize_session(subject, request, previous_lease, now_tick)
            },
            ComponentSessionAdmission {
                identity: Arc::clone(&self.component_admission.identity),
            },
        )
    }

    /// Install a sealed daemon-owned interaction and Process/Shell subject
    /// projection from the Zone runtime.
    pub fn install_committed_interaction_subject(
        &self,
        committed: CommittedInteractionSubjectInstall,
    ) -> d2b_session::Result<()> {
        let interaction_subjects = self
            .interaction_subjects
            .as_ref()
            .ok_or_else(subject_configuration_mismatch)?;
        let CommittedInteractionSubjectInstallBody {
            zone,
            display_subject_ref,
            display_subject_uid,
            expected_peer_uid,
            execution_ref,
            display_generation,
            clipboard_generation,
            notification_generation,
            clipboard_provider_uid,
            notification_provider_uid,
        } = committed.open(interaction_subjects, &self.core.zone)?;
        let zone_ref = ResourceRef::parse(&format!("Zone/{}", zone.as_str()))
            .map_err(|_| subject_configuration_mismatch())?;
        let controller_generation = interaction_subjects.authority.controller_generation;
        let services = [(
            ServicePackage::DisplayV3,
            ResourceRef::parse("Provider/display-wayland").expect("fixed display Provider ref"),
            display_generation,
        )];
        let mut subjects = Vec::with_capacity(6);
        for (service, provider_ref, generation) in services {
            subjects.push(
                UnixSubjectRecord::guest_for_uid(
                    display_subject_ref.clone(),
                    display_subject_uid.clone(),
                    zone_ref.clone(),
                    expected_peer_uid,
                )?
                .with_provider(provider_ref, generation)?
                .with_controller_generation(controller_generation)
                .with_execution_ref(execution_ref.clone())?
                .for_service(service),
            );
        }
        // Process and ShellSession named streams use the generic Provider
        // package on the wire, but their listener identities are retained by
        // d2bd. Bind that package to the enrolled Guest's own execution
        // reference rather than borrowing the display Host route.
        subjects.push(
            UnixSubjectRecord::guest_for_uid(
                display_subject_ref.clone(),
                display_subject_uid.clone(),
                zone_ref.clone(),
                expected_peer_uid,
            )?
            .with_controller_generation(controller_generation)
            .with_execution_ref(display_subject_ref.clone())?
            .for_service(ServicePackage::ProviderV3),
        );
        if let Some(generation) = clipboard_generation {
            let (subject_ref, subject_uid, provider_ref) =
                if let Some(provider_uid) = clipboard_provider_uid {
                    (
                        ResourceRef::parse("Provider/clipboard-wayland")
                            .expect("fixed clipboard Provider ref"),
                        provider_uid,
                        ResourceRef::parse("Provider/clipboard-wayland")
                            .expect("fixed clipboard Provider ref"),
                    )
                } else {
                    (
                        display_subject_ref.clone(),
                        display_subject_uid.clone(),
                        ResourceRef::parse("Provider/clipboard-wayland")
                            .expect("fixed clipboard Provider ref"),
                    )
                };
            for service in [
                ServicePackage::ClipboardV3,
                ServicePackage::ClipboardBridgeV3,
                ServicePackage::ClipboardPickerCoordV3,
            ] {
                subjects.push(
                    if provider_uid_is_provider(&subject_ref) {
                        UnixSubjectRecord::provider_for_uid(
                            subject_ref.clone(),
                            subject_uid.clone(),
                            zone_ref.clone(),
                            expected_peer_uid,
                        )?
                    } else {
                        UnixSubjectRecord::guest_for_uid(
                            subject_ref.clone(),
                            subject_uid.clone(),
                            zone_ref.clone(),
                            expected_peer_uid,
                        )?
                    }
                    .with_provider(provider_ref.clone(), generation)?
                    .with_controller_generation(controller_generation)
                    .with_execution_ref(execution_ref.clone())?
                    .for_service(service),
                );
            }
        }
        if let Some(generation) = notification_generation {
            let (subject_ref, subject_uid, provider_ref) =
                if let Some(provider_uid) = notification_provider_uid {
                    (
                        ResourceRef::parse("Provider/notification-desktop")
                            .expect("fixed notification Provider ref"),
                        provider_uid,
                        ResourceRef::parse("Provider/notification-desktop")
                            .expect("fixed notification Provider ref"),
                    )
                } else {
                    (
                        display_subject_ref,
                        display_subject_uid,
                        ResourceRef::parse("Provider/notification-desktop")
                            .expect("fixed notification Provider ref"),
                    )
                };
            subjects.push(
                if provider_uid_is_provider(&subject_ref) {
                    UnixSubjectRecord::provider_for_uid(
                        subject_ref,
                        subject_uid,
                        zone_ref,
                        expected_peer_uid,
                    )?
                } else {
                    UnixSubjectRecord::guest_for_uid(
                        subject_ref,
                        subject_uid,
                        zone_ref.clone(),
                        expected_peer_uid,
                    )?
                }
                .with_provider(provider_ref, generation)?
                .with_controller_generation(controller_generation)
                .with_execution_ref(execution_ref)?
                .for_service(ServicePackage::NotificationV3),
            );
        }
        self.unix_subjects.install_many(subjects, &self.core.zone)?;
        Ok(())
    }

    /// Consume an authenticated candidate and install it only after native
    /// connect authorization succeeds.
    pub async fn register_component_session(
        &mut self,
        session: AuthenticatedComponentSession<ComponentSessionAdmission>,
    ) -> Result<BusIngress, BusError> {
        self.register_component_session_inner(session, true).await
    }

    /// Consume an authenticated candidate for a daemon-owned generated
    /// service. The registrar records the session and its exact identity, but
    /// returns the only transport reader to the service owner.
    pub async fn register_component_service_session(
        &mut self,
        session: AuthenticatedComponentSession<ComponentSessionAdmission>,
    ) -> Result<(BusIngress, d2b_session::SessionDriverHandle), BusError> {
        let mut ingress = self
            .register_component_session_inner(session, false)
            .await?;
        // The generated service owns the sole transport reader; the ingress
        // retains only the registrar cleanup authority.
        let driver = ingress
            .attachments
            .take()
            .map(|handle| handle.component_session_driver())
            .ok_or(BusError::SessionMismatch)?;
        Ok((ingress, driver))
    }

    async fn register_component_session_inner(
        &mut self,
        session: AuthenticatedComponentSession<ComponentSessionAdmission>,
        dispatch_inbound: bool,
    ) -> Result<BusIngress, BusError> {
        let (session, ttrpc) = session.consume_registration(&self.component_admission)?;
        let binding = session.route_binding();
        if binding.zone() != &self.core.zone {
            return Err(BusError::SessionMismatch);
        }
        if let Err(error) = self
            .core
            .authorizer
            .authorize_connect(binding.context(), &self.core.zone)
        {
            self.core.metrics.registration(
                BusDirection::from_context(Some(binding.context())),
                BusRegistrationOutcome::Rejected,
            );
            return Err(error.into());
        }
        let routes = if dispatch_inbound {
            routes_for_admitted_session(&binding)?
        } else {
            Vec::new()
        };
        let cancellation = session.cancellation_handle();
        let (responses, incoming) =
            ComponentResponses::new(binding.reconnect_generation().get(), ttrpc.clone());
        let response_task = dispatch_inbound.then(|| responses.spawn());
        let endpoint: Arc<dyn crate::registry::BusEndpoint> = Arc::new(ComponentEndpoint {
            session: AsyncMutex::new(session),
            ttrpc: ttrpc.clone(),
            responses,
            _response_task: response_task,
            clock: Arc::clone(&self.core.clock),
            locality: binding.locality(),
            generation: binding.reconnect_generation().get(),
            cancellation,
            activity: Mutex::new(ComponentActivity::default()),
            correlations: Mutex::new(CorrelationIds::new(
                self.core.max_correlations_per_generation,
            )),
        });
        let direction = BusDirection::from_context(Some(binding.context()));
        let registration = SessionRegistration::admitted(binding, routes, endpoint);
        let session = match self.core.lock_registry().register(registration) {
            Ok(session) => session,
            Err(error) => {
                self.core
                    .metrics
                    .registration(direction, BusRegistrationOutcome::Rejected);
                return Err(error.into());
            }
        };
        self.core.record_session_registered(session);
        Ok(BusIngress {
            core: Arc::clone(&self.core),
            session,
            closed: false,
            incoming,
            attachments: Some(ttrpc),
        })
    }

    pub async fn reconnect_component_session(
        &mut self,
        mut previous: BusIngress,
        session: AuthenticatedComponentSession<ComponentSessionAdmission>,
    ) -> Result<BusIngress, BusError> {
        if !Arc::ptr_eq(&self.core, &previous.core) || previous.closed {
            return Err(BusError::SessionMismatch);
        }
        let (session, ttrpc) = session.consume_registration(&self.component_admission)?;
        let binding = session.route_binding();
        if binding.zone() != &self.core.zone {
            return Err(BusError::SessionMismatch);
        }
        self.core
            .authorizer
            .authorize_connect(binding.context(), &self.core.zone)?;
        let routes = routes_for_admitted_session(&binding)?;
        let cancellation = session.cancellation_handle();
        let (responses, incoming) =
            ComponentResponses::new(binding.reconnect_generation().get(), ttrpc.clone());
        let response_task = responses.spawn();
        let endpoint: Arc<dyn crate::registry::BusEndpoint> = Arc::new(ComponentEndpoint {
            session: AsyncMutex::new(session),
            ttrpc: ttrpc.clone(),
            responses,
            _response_task: Some(response_task),
            clock: Arc::clone(&self.core.clock),
            locality: binding.locality(),
            generation: binding.reconnect_generation().get(),
            cancellation,
            activity: Mutex::new(ComponentActivity::default()),
            correlations: Mutex::new(CorrelationIds::new(
                self.core.max_correlations_per_generation,
            )),
        });
        let registration = SessionRegistration::admitted(binding, routes, endpoint);
        self.core
            .lock_registry()
            .validate_reconnect(previous.session, &registration)?;
        let previous_metrics = self.core.session_metrics(previous.session);
        let invalidation = self.core.lock_registry().invalidate(previous.session);
        if let Some(invalidation) = invalidation {
            invalidation.await;
        }
        let session = self
            .core
            .lock_registry()
            .reconnect(previous.session, registration)?;
        self.core.record_session_disconnected_values(
            previous_metrics.0,
            previous_metrics.1,
            BusDisconnectOutcome::Revoked,
        );
        self.core.record_session_registered(session);
        let targets = self.core.lock_operations().cancel_session(previous.session);
        self.core.streams.cancel_session(previous.session);
        self.core.dispatch_cancel_targets(targets);
        self.core
            .cancel_deliveries
            .abort_destination(previous.session);
        previous.closed = true;
        Ok(BusIngress {
            core: Arc::clone(&self.core),
            session,
            closed: false,
            incoming,
            attachments: Some(ttrpc),
        })
    }

    pub async fn disconnect_component_session(
        &mut self,
        registration: BusIngress,
    ) -> Result<(), BusError> {
        self.revoke(registration).await
    }
}

fn routes_for_admitted_session(
    binding: &AuthenticatedSessionRouteBinding,
) -> Result<Vec<RouteKey>, BusError> {
    let guest_provider_service = binding.subject_ref().resource_type().as_str() == "Guest"
        && matches!(
            binding.service().as_str(),
            "d2b.display.v3"
                | "d2b.clipboard.v3"
                | "d2b.clipboard.bridge.v3"
                | "d2b.clipboard.picker-coord.v3"
                | "d2b.notification.v3"
                | "d2b.config-nixos.v3"
        );
    if binding.provider_ref().is_none()
        || (binding.subject_ref().resource_type().as_str() != "Provider" && !guest_provider_service)
    {
        return Ok(Vec::new());
    }
    let target_ref = binding
        .provider_ref()
        .unwrap_or_else(|| binding.subject_ref())
        .clone();
    let target = if target_ref.resource_type().as_str() == "Provider" {
        RouteTarget::provider(target_ref)?
    } else {
        RouteTarget::resource(target_ref)?
    };
    let generations = crate::registry::RouteGenerations::new(
        binding.provider_generation(),
        binding.controller_generation(),
        binding.reconnect_generation(),
    );
    GENERATED_OPERATION_CATALOG
        .iter()
        .filter(|entry| entry.service == binding.service().as_str())
        .map(|entry| {
            let member = if entry.kind == OperationKind::Stream {
                crate::registry::RouteMember::stream(entry.member)?
            } else {
                crate::registry::RouteMember::method(entry.member)?
            };
            Ok(RouteKey::new(
                binding.zone().clone(),
                binding.service().clone(),
                member,
                target.clone(),
                binding.schema().clone(),
                generations,
            ))
        })
        .collect()
}

impl ZoneRegistrar {
    /// Revoke a session, its routes, operations, and streams.
    pub async fn revoke(&mut self, mut ingress: BusIngress) -> Result<(), BusError> {
        self.revoke_in_place(&mut ingress).await
    }

    /// Revoke a session while retaining the caller's ingress when the
    /// authority check fails.  Daemon finalizers use this form so a
    /// transient cleanup/revocation failure does not discard retry authority.
    pub async fn revoke_in_place(&mut self, ingress: &mut BusIngress) -> Result<(), BusError> {
        if !Arc::ptr_eq(&self.core, &ingress.core) || ingress.closed {
            return Err(BusError::SessionMismatch);
        }
        self.core.cleanup_session(ingress.session).await;
        ingress.closed = true;
        Ok(())
    }
}

fn provider_uid_is_provider(subject_ref: &ResourceRef) -> bool {
    subject_ref.resource_type().as_str() == "Provider"
}

impl core::fmt::Debug for ZoneRegistrar {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ZoneRegistrar(<redacted>)")
    }
}

/// Non-cloneable ingress bound to one consumed authenticated session.
pub struct BusIngress {
    core: Arc<BusCore>,
    session: SessionId,
    closed: bool,
    incoming: Arc<AsyncMutex<mpsc::Receiver<Vec<u8>>>>,
    attachments: Option<AuthenticatedTtrpcHandle>,
}

/// Receiver for request frames demultiplexed from one admitted ComponentSession.
#[derive(Clone)]
pub struct ComponentRequestReceiver {
    incoming: Arc<AsyncMutex<mpsc::Receiver<Vec<u8>>>>,
    attachments: Option<AuthenticatedTtrpcHandle>,
}

impl ComponentRequestReceiver {
    /// Receive the next request or fail when the authenticated session closes.
    pub async fn recv(&self) -> Result<Vec<u8>, BusError> {
        let mut incoming = self.incoming.lock().await;
        incoming.recv().await.ok_or(BusError::SessionMismatch)
    }

    /// Receive the next authenticated attachment batch from the same
    /// ComponentSession. The caller is responsible for checking descriptor
    /// request/service/method identity before consuming it.
    pub async fn recv_attachments(&self) -> Result<Vec<d2b_session::OwnedAttachment>, BusError> {
        self.attachments
            .as_ref()
            .ok_or(BusError::SessionMismatch)?
            .receive_attachments()
            .await
            .map_err(|_| BusError::SessionMismatch)
    }
}

#[cfg(any(test, feature = "production-rss-fixture"))]
fn empty_component_requests() -> Arc<AsyncMutex<mpsc::Receiver<Vec<u8>>>> {
    let (_sender, receiver) = mpsc::channel(1);
    Arc::new(AsyncMutex::new(receiver))
}

struct OperationLease {
    core: Arc<BusCore>,
    source: SessionId,
    operation: OperationId,
    cancellation: Cancellation,
    armed: bool,
}

impl OperationLease {
    fn new(
        core: Arc<BusCore>,
        source: SessionId,
        operation: OperationId,
        cancellation: Cancellation,
    ) -> Self {
        Self {
            core,
            source,
            operation,
            cancellation,
            armed: true,
        }
    }

    fn finish(&mut self) -> Result<(), BusError> {
        if !self.armed {
            return Ok(());
        }
        self.armed = false;
        self.core.lock_operations().finish(
            &self.operation,
            self.source,
            &self.cancellation,
            self.core.clock.now_tick(),
        )?;
        Ok(())
    }

    fn abort(&mut self) -> Option<CancelDispatch> {
        if !self.armed {
            return None;
        }
        self.armed = false;
        self.core
            .lock_operations()
            .abort(&self.operation, self.source, &self.cancellation)
    }
}

impl Drop for OperationLease {
    fn drop(&mut self) {
        let Some(dispatch) = self.abort() else {
            return;
        };
        self.core.dispatch_cancel_targets(vec![dispatch]);
    }
}

impl BusIngress {
    /// Clone the authenticated ComponentSession driver for a daemon-owned
    /// target-local named-stream owner.
    pub fn component_session_driver(&self) -> Option<SessionDriverHandle> {
        self.attachments
            .as_ref()
            .map(AuthenticatedTtrpcHandle::component_session_driver)
    }

    /// Clone the daemon-owned request receiver for one session loop.
    pub fn component_request_receiver(&self) -> ComponentRequestReceiver {
        ComponentRequestReceiver {
            incoming: Arc::clone(&self.incoming),
            attachments: self.attachments.clone(),
        }
    }

    /// Receive the next inbound ComponentSession request frame.
    ///
    /// Component response dispatch and inbound request dispatch share one
    /// authenticated transport. The registrar-owned response task demuxes
    /// request frames into this bounded queue so callers never read the
    /// session transport directly or bypass bus registration.
    pub async fn receive_component_request(&self) -> Result<Vec<u8>, BusError> {
        self.ensure_open()?;
        let mut incoming = self.incoming.lock().await;
        incoming.recv().await.ok_or(BusError::SessionMismatch)
    }

    /// Send one response for a request received on this authenticated
    /// ComponentSession. The response stream must still be fenced as an
    /// outstanding inbound request by the registrar-owned dispatcher.
    pub async fn send_component_response(&self, frame: Vec<u8>) -> Result<(), BusError> {
        self.ensure_open()?;
        if !d2b_session::ttrpc_is_response(&frame) {
            return Err(BusError::RouteShape);
        }
        let source = self.core.lock_registry().source(self.session)?;
        source
            .endpoint
            .send_inbound_response(frame)
            .await
            .map_err(BusError::Endpoint)
    }

    /// Begin one locally dispatched invocation after the same route and
    /// session authorization used for ordinary bus delivery.
    pub async fn begin_local_invoke(
        &self,
        route: RouteKey,
        operation: OperationSpec,
    ) -> Result<LocalOperationLease, BusError> {
        self.ensure_open()?;
        if !route.member().is_method() {
            return Err(BusError::RouteShape);
        }
        self.authorize_route(&route, None, SessionVerb::Invoke, false)
            .await?;
        let destination = self.core.lock_registry().resolve(&route)?;
        let now = self.core.clock.now_tick();
        let cancellation =
            self.core
                .lock_operations()
                .begin(&operation, self.session, destination, route, now)?;
        Ok(LocalOperationLease {
            inner: Some(OperationLease::new(
                Arc::clone(&self.core),
                self.session,
                operation.id().clone(),
                cancellation,
            )),
        })
    }

    async fn authorize_route(
        &self,
        route: &RouteKey,
        resource_call: Option<&ResourceCall>,
        verb: SessionVerb,
        stream: bool,
    ) -> Result<(), BusError> {
        let source = self.core.lock_registry().source(self.session)?;
        if let Some(context) = source.context.as_ref() {
            self.core
                .authorizer
                .authorize_dispatch(context, route, resource_call, stream)?;
        }
        if source.session_authorization {
            source
                .endpoint
                .authorize(
                    route,
                    verb,
                    resource_call.and_then(ResourceCall::session_target),
                    self.core.clock.now_tick(),
                )
                .await
                .map_err(BusError::Endpoint)
        } else {
            Ok(())
        }
    }

    /// Invoke a non-resource exact service method.
    pub async fn invoke(
        &self,
        route: RouteKey,
        operation: OperationSpec,
        payload: Vec<u8>,
    ) -> Result<BusResponse, BusError> {
        let service = route.service().clone();
        let direction = self.core.session_metrics(self.session).0;
        let started = Instant::now();
        let result = self.invoke_inner(route, operation, None, payload).await;
        self.core.record_route(
            &service,
            direction,
            result.as_ref().err(),
            started.elapsed().as_secs_f64(),
        );
        if let Err(error) = &result {
            self.core.observe_error(BusEvent::Invoke, error);
        }
        result
    }

    /// Invoke an exact ResourceService method.
    pub async fn invoke_resource(
        &self,
        route: RouteKey,
        operation: OperationSpec,
        call: ResourceCall,
        payload: Vec<u8>,
    ) -> Result<BusResponse, BusError> {
        let service = route.service().clone();
        let direction = self.core.session_metrics(self.session).0;
        let started = Instant::now();
        let result = self
            .invoke_inner(route, operation, Some(call), payload)
            .await;
        self.core.record_route(
            &service,
            direction,
            result.as_ref().err(),
            started.elapsed().as_secs_f64(),
        );
        if let Err(error) = &result {
            self.core.observe_error(BusEvent::Invoke, error);
        }
        result
    }

    /// Invoke one assignment-scoped atomic commit over the existing Resource
    /// bus route.
    pub async fn invoke_scoped_commit_batch(
        &self,
        route: RouteKey,
        operation: OperationSpec,
        assignment: AssignmentIdentity,
        mutations: Vec<ScopedResourceMutation>,
        payload: Vec<u8>,
    ) -> Result<BusResponse, BusError> {
        self.invoke_resource(
            route,
            operation,
            ResourceCall::ScopedCommitBatch {
                assignment,
                mutations,
            },
            payload,
        )
        .await
    }

    async fn invoke_inner(
        &self,
        route: RouteKey,
        operation: OperationSpec,
        resource_call: Option<ResourceCall>,
        payload: Vec<u8>,
    ) -> Result<BusResponse, BusError> {
        self.ensure_open()?;
        if !route.member().is_method() || payload.len() > self.core.max_payload_bytes {
            return Err(BusError::RouteShape);
        }
        validate_resource_route(&route, resource_call.as_ref())?;

        let ordinary = SessionVerb::Invoke;
        let session_operation =
            SessionOperation::method(route.service().clone(), route.member().as_str())
                .map_err(|_| BusError::RouteShape)?;
        self.authorize_route(
            &route,
            resource_call.as_ref(),
            session_operation.required_verb(ordinary),
            false,
        )
        .await?;
        let destination = self.core.lock_registry().resolve(&route)?;
        #[cfg(test)]
        self.wait_for_invocation_hook(true).await;
        let endpoint = destination.endpoint();
        let now = self.core.clock.now_tick();
        let cancellation = self.core.lock_operations().begin(
            &operation,
            self.session,
            destination,
            route.clone(),
            now,
        )?;
        let mut lease = OperationLease::new(
            Arc::clone(&self.core),
            self.session,
            operation.id().clone(),
            cancellation.clone(),
        );
        let delivered = DeliveredInvocation {
            route,
            operation: operation.clone(),
            resource_call,
            payload,
            cancellation: cancellation.clone(),
        };
        #[cfg(test)]
        self.wait_for_invocation_hook(false).await;
        let remaining = operation.deadline_tick().saturating_sub(now);
        enum InvokeOutcome {
            Cancelled,
            Deadline,
            Response(Result<BusResponse, EndpointError>),
        }
        let outcome = tokio::select! {
            biased;
            () = cancellation.cancelled() => InvokeOutcome::Cancelled,
            () = tokio::time::sleep(Duration::from_millis(remaining)) => InvokeOutcome::Deadline,
            response = endpoint.invoke(delivered) => InvokeOutcome::Response(response),
        };
        let response = match outcome {
            InvokeOutcome::Response(response) => response,
            InvokeOutcome::Cancelled => return Err(BusError::Cancelled),
            InvokeOutcome::Deadline => {
                if let Some(dispatch) = lease.abort() {
                    self.core.dispatch_cancel_targets(vec![dispatch]);
                }
                return Err(BusError::Operation(OperationError::DeadlineExceeded));
            }
        };
        lease.finish()?;
        let response = response.map_err(BusError::Endpoint)?;
        if response.as_bytes().len() > self.core.max_payload_bytes {
            return Err(BusError::RouteShape);
        }
        Ok(response)
    }

    /// Open a non-resource named stream.
    pub async fn open_stream(
        &self,
        route: RouteKey,
        operation: OperationSpec,
        stream: StreamName,
        initial_credit: usize,
    ) -> Result<BusStream, BusError> {
        let service = route.service().clone();
        let direction = self.core.session_metrics(self.session).0;
        let started = Instant::now();
        let result = self
            .open_stream_inner(route, operation, None, stream, initial_credit)
            .await;
        self.core.record_route(
            &service,
            direction,
            result.as_ref().err(),
            started.elapsed().as_secs_f64(),
        );
        if let Err(error) = &result {
            self.core.observe_error(BusEvent::OpenStream, error);
        }
        result
    }

    /// Open a resource-backed named stream while preserving its selector.
    pub async fn open_resource_stream(
        &self,
        route: RouteKey,
        operation: OperationSpec,
        call: ResourceCall,
        stream: StreamName,
        initial_credit: usize,
    ) -> Result<BusStream, BusError> {
        let service = route.service().clone();
        let direction = self.core.session_metrics(self.session).0;
        let started = Instant::now();
        let result = self
            .open_stream_inner(route, operation, Some(call), stream, initial_credit)
            .await;
        self.core.record_route(
            &service,
            direction,
            result.as_ref().err(),
            started.elapsed().as_secs_f64(),
        );
        if let Err(error) = &result {
            self.core.observe_error(BusEvent::OpenStream, error);
        }
        result
    }

    async fn open_stream_inner(
        &self,
        route: RouteKey,
        operation: OperationSpec,
        resource_call: Option<ResourceCall>,
        stream: StreamName,
        initial_credit: usize,
    ) -> Result<BusStream, BusError> {
        self.ensure_open()?;
        if !route.member().is_stream() {
            return Err(BusError::RouteShape);
        }
        validate_resource_route(&route, resource_call.as_ref())?;
        self.authorize_route(
            &route,
            resource_call.as_ref(),
            SessionVerb::OpenStream,
            true,
        )
        .await?;
        let destination = self.core.lock_registry().resolve(&route)?;
        let source_principal = self.core.lock_registry().principal(self.session)?;
        let destination_session = destination.destination();
        let destination_principal = destination.destination_principal();
        let endpoint = destination.endpoint();
        let direction = self.core.session_metrics(self.session).0;
        let (outgoing, incoming) = match self.core.streams.open(
            stream,
            self.session,
            source_principal,
            destination_session,
            destination_principal,
            direction,
            initial_credit,
        ) {
            Ok(handles) => handles,
            Err(error) => {
                self.core
                    .metrics
                    .stream_result(direction, BusStreamOutcome::Rejected);
                if matches!(
                    error,
                    StreamError::CreditExceeded
                        | StreamError::AggregateBackpressure
                        | StreamError::PrincipalBackpressure
                        | StreamError::StreamCapacityExceeded
                        | StreamError::PrincipalCapacityExceeded
                ) {
                    self.core.metrics.backpressure(
                        direction,
                        BusStreamKind::Stream,
                        rejection_backpressure_reason(error),
                    );
                }
                return Err(error.into());
            }
        };
        let now = self.core.clock.now_tick();
        let cancellation = self.core.lock_operations().begin(
            &operation,
            self.session,
            destination,
            route.clone(),
            now,
        )?;
        let lease = OperationLease::new(
            Arc::clone(&self.core),
            self.session,
            operation.id().clone(),
            cancellation.clone(),
        );
        let dispatch = DeliveredStream {
            route,
            operation: operation.clone(),
            resource_call,
            incoming,
            cancellation: cancellation.clone(),
        };
        let remaining = operation.deadline_tick().saturating_sub(now);
        enum StreamOutcome {
            Cancelled,
            Deadline,
            Opened(Result<(), EndpointError>),
        }
        let outcome = tokio::select! {
            biased;
            () = cancellation.cancelled() => StreamOutcome::Cancelled,
            () = tokio::time::sleep(Duration::from_millis(remaining)) => StreamOutcome::Deadline,
            result = endpoint.open_stream(dispatch) => StreamOutcome::Opened(result),
        };
        match outcome {
            StreamOutcome::Opened(result) => result.map_err(BusError::Endpoint)?,
            StreamOutcome::Cancelled => return Err(BusError::Cancelled),
            StreamOutcome::Deadline => {
                let mut lease = lease;
                if let Some(dispatch) = lease.abort() {
                    self.core.dispatch_cancel_targets(vec![dispatch]);
                }
                return Err(BusError::Operation(OperationError::DeadlineExceeded));
            }
        }
        Ok(BusStream {
            lease: Some(lease),
            cancellation,
            outgoing: Some(outgoing),
        })
    }

    /// Cancel one exact operation attempt owned by this ingress.
    pub async fn cancel(&self, operation: &OperationSpec) -> Result<CancellationReceipt, BusError> {
        let direction = self.core.session_metrics(self.session).0;
        let result = self.cancel_inner(operation).await;
        if let Err(error) = &result {
            self.core
                .metrics
                .rejection(direction, rejection_outcome(error));
            self.core.observe_error(BusEvent::Cancel, error);
        }
        result
    }

    async fn cancel_inner(
        &self,
        operation: &OperationSpec,
    ) -> Result<CancellationReceipt, BusError> {
        self.ensure_open()?;
        let Some(admission) = self
            .core
            .lock_operations()
            .cancel_admission(operation, self.session)?
        else {
            return Ok(CancellationReceipt::local());
        };
        let source = self.core.lock_registry().source(self.session)?;
        if let Some(context) = source.context.as_ref() {
            self.core
                .authorizer
                .authorize_cancel(context, &admission.route)?;
        }
        if source.session_authorization {
            source
                .endpoint
                .authorize(
                    &admission.route,
                    SessionVerb::Cancel,
                    None,
                    self.core.clock.now_tick(),
                )
                .await
                .map_err(BusError::Endpoint)?;
        }
        #[cfg(test)]
        self.wait_for_cancel_transition_hook().await;
        let Some(dispatch) =
            self.core
                .lock_operations()
                .cancel_admitted(operation, self.session, &admission)?
        else {
            return Ok(CancellationReceipt::local());
        };
        debug_assert!(dispatch.target.cancellation.is_cancelled());
        let completion = self.core.dispatch_cancel_target(dispatch);
        Ok(CancellationReceipt::pending(completion))
    }

    fn ensure_open(&self) -> Result<(), BusError> {
        if self.closed {
            Err(BusError::SessionClosed)
        } else {
            Ok(())
        }
    }

    #[cfg(test)]
    async fn wait_for_invocation_hook(&self, after_resolve: bool) {
        let hook = {
            let hooks = self
                .core
                .invocation_hooks
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if after_resolve {
                hooks.after_resolve.clone()
            } else {
                hooks.before_invoke.clone()
            }
        };
        if let Some(hook) = hook {
            hook.reached.notify_one();
            hook.release.notified().await;
        }
    }

    #[cfg(test)]
    async fn wait_for_cancel_transition_hook(&self) {
        let hook = self
            .core
            .invocation_hooks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .before_cancel_transition
            .clone();
        if let Some(hook) = hook {
            hook.reached.notify_one();
            hook.release.notified().await;
        }
    }
}

impl core::fmt::Debug for BusIngress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("BusIngress(<redacted>)")
    }
}

impl Drop for BusIngress {
    fn drop(&mut self) {
        if !self.closed {
            self.core
                .observer
                .record(BusEvent::Cleanup, BusFailureReason::Abandoned);
            if let Some(invalidation) = self.core.begin_cleanup_session(self.session)
                && let Ok(runtime) = tokio::runtime::Handle::try_current()
            {
                runtime.spawn(invalidation);
            }
            self.closed = true;
        }
    }
}

/// Source-side named stream that retains its operation lease.
pub struct BusStream {
    lease: Option<OperationLease>,
    cancellation: Cancellation,
    outgoing: Option<OutgoingStream>,
}

impl BusStream {
    /// Borrow the stream name.
    pub fn name(&self) -> &StreamName {
        self.outgoing
            .as_ref()
            .expect("open stream owns an outgoing handle")
            .name()
    }

    /// Send one frame after checking cancellation.
    pub async fn send(&self, payload: Vec<u8>) -> Result<(), BusError> {
        let result = if self.cancellation.is_cancelled() {
            Err(BusError::Cancelled)
        } else {
            self.outgoing.as_ref().map_or_else(
                || Err(BusError::SessionClosed),
                |outgoing| outgoing.send(payload).map_err(BusError::Stream),
            )
        };
        if let Err(error) = &result
            && let Some(lease) = self.lease.as_ref()
        {
            lease.core.observe_error(BusEvent::OpenStream, error);
        }
        result
    }

    async fn send_watch_payload(&self, payload: Vec<u8>) -> Result<(), BusError> {
        if self.cancellation.is_cancelled() {
            return Err(BusError::Cancelled);
        }
        let outgoing = self.outgoing.as_ref().ok_or(BusError::SessionClosed)?;
        tokio::select! {
            biased;
            () = self.cancellation.cancelled() => Err(BusError::Cancelled),
            result = outgoing.send_and_wait_ack(payload) => result.map_err(BusError::Stream),
        }
    }

    /// Close the stream and complete its operation lease.
    pub async fn close(mut self) -> Result<(), BusError> {
        self.finish()
    }

    fn finish(&mut self) -> Result<(), BusError> {
        if let Some(mut outgoing) = self.outgoing.take() {
            outgoing.close();
            if self.cancellation.is_cancelled() {
                return Err(BusError::Cancelled);
            }
            if let Some(mut lease) = self.lease.take() {
                lease.finish()?;
            }
        }
        Ok(())
    }
}

impl core::fmt::Debug for BusStream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("BusStream(<redacted>)")
    }
}

impl Drop for BusStream {
    fn drop(&mut self) {
        let core = self.lease.as_ref().map(|lease| Arc::clone(&lease.core));
        if let Err(error) = self.finish()
            && let Some(core) = core
        {
            core.observe_error(BusEvent::Cleanup, &error);
        }
    }
}

impl WatchSink for BusStream {
    #[allow(clippy::manual_async_fn)]
    fn send(
        &self,
        frame: WatchFrame,
    ) -> impl std::future::Future<Output = Result<(), WatchSinkError>> + Send {
        async move {
            match self.send_watch_payload(frame.payload().to_vec()).await {
                Ok(()) => Ok(()),
                Err(BusError::Stream(StreamError::FrameBounds)) => {
                    Err(WatchSinkError::FrameTooLarge)
                }
                Err(BusError::Stream(
                    StreamError::StreamClosed | StreamError::DirectionMismatch,
                ))
                | Err(BusError::Cancelled | BusError::SessionClosed) => Err(WatchSinkError::Closed),
                Err(_) => Err(WatchSinkError::Backpressure),
            }
        }
    }
}

fn rejection_outcome(error: &BusError) -> BusRejectionOutcome {
    match error {
        BusError::Authorization(_) => BusRejectionOutcome::Denied,
        BusError::Registry(RegistryError::RouteNotFound)
        | BusError::Operation(OperationError::OperationNotFound) => BusRejectionOutcome::NotFound,
        BusError::Operation(
            OperationError::CapacityExceeded | OperationError::SessionCapacityExceeded,
        )
        | BusError::Stream(
            StreamError::StreamCapacityExceeded
            | StreamError::PrincipalCapacityExceeded
            | StreamError::AggregateBackpressure
            | StreamError::PrincipalBackpressure
            | StreamError::CreditExceeded,
        ) => BusRejectionOutcome::Quota,
        _ => BusRejectionOutcome::Error,
    }
}

fn rejection_backpressure_reason(error: StreamError) -> BusBackpressureReason {
    match error {
        StreamError::CreditExceeded => BusBackpressureReason::Credit,
        StreamError::AggregateBackpressure | StreamError::PrincipalBackpressure => {
            BusBackpressureReason::BufferFull
        }
        StreamError::StreamCapacityExceeded | StreamError::PrincipalCapacityExceeded => {
            BusBackpressureReason::Capacity
        }
        _ => BusBackpressureReason::Capacity,
    }
}

fn validate_resource_route(
    route: &RouteKey,
    resource_call: Option<&ResourceCall>,
) -> Result<(), BusError> {
    match resource_call {
        Some(call)
            if route.service().as_str() == "d2b.resource.v3"
                && route.member().as_str() == call.expected_member()
                && call.matches_route_target(route.target()) =>
        {
            Ok(())
        }
        Some(_) => Err(BusError::InvalidResourceCall),
        None if route.service().as_str() != "d2b.resource.v3" => Ok(()),
        None => Err(BusError::InvalidResourceCall),
    }
}

/// Closed bus failure classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusError {
    InvalidConfig,
    InvalidResourceCall,
    RouteShape,
    SessionMismatch,
    SessionClosed,
    Cancelled,
    Authorization(AuthorizationError),
    Registry(RegistryError),
    Operation(OperationError),
    Stream(StreamError),
    Endpoint(EndpointError),
}

impl core::fmt::Display for BusError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidConfig => f.write_str("bus configuration is invalid"),
            Self::InvalidResourceCall => {
                f.write_str("resource call does not match its exact route")
            }
            Self::RouteShape => f.write_str("route member or payload shape is invalid"),
            Self::SessionMismatch => {
                f.write_str("session belongs to another registration authority")
            }
            Self::SessionClosed => f.write_str("session is closed"),
            Self::Cancelled => f.write_str("operation was cancelled"),
            Self::Authorization(error) => write!(f, "authorization failed: {error}"),
            Self::Registry(error) => write!(f, "route registry failed: {error}"),
            Self::Operation(error) => write!(f, "operation failed: {error}"),
            Self::Stream(error) => write!(f, "stream failed: {error}"),
            Self::Endpoint(error) => write!(f, "endpoint failed: {error}"),
        }
    }
}

impl std::error::Error for BusError {}

impl From<AuthorizationError> for BusError {
    fn from(value: AuthorizationError) -> Self {
        Self::Authorization(value)
    }
}

impl From<RegistryError> for BusError {
    fn from(value: RegistryError) -> Self {
        Self::Registry(value)
    }
}

impl From<OperationError> for BusError {
    fn from(value: OperationError) -> Self {
        Self::Operation(value)
    }
}

impl From<StreamError> for BusError {
    fn from(value: StreamError) -> Self {
        Self::Stream(value)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;

    use crate::metrics::BusRouteOutcome;
    use async_trait::async_trait;
    use d2b_contracts_resource::v3::identity::{
        AuthenticatedSubjectContext, BindingDigest, EvidenceClass, Locality, ReconnectGeneration,
        ServiceName, SessionBinding, SessionPurpose, TranscriptHash, TransportBinding,
    };
    use d2b_contracts_resource::v3::{
        CanonicalJsonValue, ConfigurationGeneration, ControllerGeneration,
        RESOURCE_ENVELOPE_DOMAIN_TAG, ResourceGeneration, ResourceRef, ResourceTypeName,
        ResourceUid, SchemaFingerprint, Timestamp, ZoneId, ZoneRevision, canonical_digest,
    };
    use d2b_controller_toolkit::{
        OperationContext, PendingQueue, PriorityLane, QueueHint, ResourceKey, TriggerReason,
        TriggerSet,
    };
    use d2b_resource_api::authz::{
        ApiCatalog, BindingScope, BootstrapPhase, BoundSubject, CompiledRole, CompiledRoleBinding,
        NativeAuthorizer, PolicyRule, RelayGrantAuthority, SessionVerb,
    };
    use d2b_resource_api::watch::WatchService;
    use d2b_resource_store::mutation_seal::{MutationSealBody, mutation_seal_pair};
    use d2b_resource_store::{
        AdmittedAuthorization, AdmittedAuthorizationTarget, AdmittedVerb, ExpectedRevision,
        PolicySnapshot, PreparedStoreMutation, ResourceMutationKind, StoreMutation,
        StoreOperationContext, StoreProjection, StoreSlot, StoreWatchRequest,
    };
    use d2b_resource_store_redb::{RedbResourceStore, StoreIdentity, write_provisioning_marker};
    use tokio::sync::Notify;

    use super::*;
    use crate::registry::{BusEndpoint, RouteGenerations, RouteMember, RouteTarget};

    const CALLER_UID: &str = "11111111-1111-4111-8111-111111111111";
    const ENDPOINT_UID: &str = "22222222-2222-4222-8222-222222222222";

    type RecordedCall = (RouteKey, Option<ResourceCall>, Vec<u8>);

    #[derive(Clone, Copy)]
    enum CancelDelivery {
        Succeed,
        Fail,
        Pending,
    }

    struct RecordingEndpoint {
        calls: Mutex<Vec<RecordedCall>>,
        incoming: Mutex<Vec<IncomingStream>>,
        active_requests: Mutex<BTreeMap<OperationId, ()>>,
        response_waiters: Mutex<BTreeMap<OperationId, ()>>,
        cancel_count: AtomicUsize,
        cancel_delivery: CancelDelivery,
        blocking: bool,
        response: Vec<u8>,
        started: Notify,
        release: Notify,
    }

    impl RecordingEndpoint {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                incoming: Mutex::new(Vec::new()),
                active_requests: Mutex::new(BTreeMap::new()),
                response_waiters: Mutex::new(BTreeMap::new()),
                cancel_count: AtomicUsize::new(0),
                cancel_delivery: CancelDelivery::Succeed,
                blocking: false,
                response: b"response".to_vec(),
                started: Notify::new(),
                release: Notify::new(),
            })
        }

        fn blocking() -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                incoming: Mutex::new(Vec::new()),
                active_requests: Mutex::new(BTreeMap::new()),
                response_waiters: Mutex::new(BTreeMap::new()),
                cancel_count: AtomicUsize::new(0),
                cancel_delivery: CancelDelivery::Succeed,
                blocking: true,
                response: b"response".to_vec(),
                started: Notify::new(),
                release: Notify::new(),
            })
        }

        fn oversized() -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                incoming: Mutex::new(Vec::new()),
                active_requests: Mutex::new(BTreeMap::new()),
                response_waiters: Mutex::new(BTreeMap::new()),
                cancel_count: AtomicUsize::new(0),
                cancel_delivery: CancelDelivery::Succeed,
                blocking: false,
                response: vec![0; DEFAULT_MAX_PAYLOAD_BYTES + 1],
                started: Notify::new(),
                release: Notify::new(),
            })
        }

        fn failing_cancel() -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                incoming: Mutex::new(Vec::new()),
                active_requests: Mutex::new(BTreeMap::new()),
                response_waiters: Mutex::new(BTreeMap::new()),
                cancel_count: AtomicUsize::new(0),
                cancel_delivery: CancelDelivery::Fail,
                blocking: true,
                response: b"response".to_vec(),
                started: Notify::new(),
                release: Notify::new(),
            })
        }

        fn pending_cancel() -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                incoming: Mutex::new(Vec::new()),
                active_requests: Mutex::new(BTreeMap::new()),
                response_waiters: Mutex::new(BTreeMap::new()),
                cancel_count: AtomicUsize::new(0),
                cancel_delivery: CancelDelivery::Pending,
                blocking: true,
                response: b"response".to_vec(),
                started: Notify::new(),
                release: Notify::new(),
            })
        }

        fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }

        fn cancellation_count(&self) -> usize {
            self.cancel_count.load(Ordering::Acquire)
        }

        fn has_active_request(&self, operation: &OperationId) -> bool {
            self.active_requests.lock().unwrap().contains_key(operation)
        }

        fn has_response_waiter(&self, operation: &OperationId) -> bool {
            self.response_waiters
                .lock()
                .unwrap()
                .contains_key(operation)
        }
    }

    #[async_trait]
    impl BusEndpoint for RecordingEndpoint {
        async fn invoke(&self, request: DeliveredInvocation) -> Result<BusResponse, EndpointError> {
            let operation = request.operation().id().clone();
            self.active_requests
                .lock()
                .unwrap()
                .insert(operation.clone(), ());
            self.response_waiters
                .lock()
                .unwrap()
                .insert(operation.clone(), ());
            self.calls.lock().unwrap().push((
                request.route().clone(),
                request.resource_call().cloned(),
                request.payload().to_vec(),
            ));
            if self.blocking {
                self.started.notify_one();
                self.release.notified().await;
            }
            self.active_requests.lock().unwrap().remove(&operation);
            self.response_waiters.lock().unwrap().remove(&operation);
            Ok(BusResponse::new(self.response.clone()))
        }

        async fn open_stream(&self, request: DeliveredStream) -> Result<(), EndpointError> {
            self.calls.lock().unwrap().push((
                request.route().clone(),
                request.resource_call().cloned(),
                Vec::new(),
            ));
            self.incoming.lock().unwrap().push(request.into_incoming());
            Ok(())
        }

        fn terminalize_cancel(
            &self,
            operation: &OperationId,
            _attempt: &Cancellation,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(), EndpointError>> + Send + 'static>,
        > {
            self.cancel_count.fetch_add(1, Ordering::AcqRel);
            self.active_requests.lock().unwrap().remove(operation);
            self.response_waiters.lock().unwrap().remove(operation);
            match self.cancel_delivery {
                CancelDelivery::Succeed => Box::pin(async { Ok(()) }),
                CancelDelivery::Fail => Box::pin(async { Err(EndpointError::Unavailable) }),
                CancelDelivery::Pending => Box::pin(std::future::pending()),
            }
        }
    }

    struct Harness {
        bus: ZoneBus,
        registrar: ZoneRegistrar,
        caller: BusIngress,
        endpoint_ingress: BusIngress,
        endpoint: Arc<RecordingEndpoint>,
        route: RouteKey,
        subjects: Vec<BoundSubject>,
        clock: Arc<ManualClock>,
    }

    struct HarnessSpec<'a> {
        service: &'a str,
        member: RouteMember,
        caller_ref: &'a str,
        locality: Locality,
        evidence: EvidenceClass,
        session_verbs: Vec<SessionVerb>,
        resource_verbs: Vec<ResourceVerb>,
        endpoint: Arc<RecordingEndpoint>,
    }

    #[derive(Default)]
    struct RecordingTelemetry {
        routes: AtomicUsize,
        registrations: AtomicUsize,
        streams: AtomicUsize,
        credits: AtomicUsize,
        backpressure: AtomicUsize,
        rejections: AtomicUsize,
        disconnects: AtomicUsize,
    }

    impl BusTelemetry for RecordingTelemetry {
        fn route(
            &self,
            _service: &ServiceName,
            _direction: BusDirection,
            _outcome: BusRouteOutcome,
            _duration_seconds: f64,
        ) {
            self.routes.fetch_add(1, Ordering::Relaxed);
        }

        fn session_active(&self, _transport: BusTransport, _active: u64) {}

        fn registration(&self, _direction: BusDirection, _outcome: BusRegistrationOutcome) {
            self.registrations.fetch_add(1, Ordering::Relaxed);
        }

        fn stream_active(&self, _direction: BusDirection, _active: u64) {
            self.streams.fetch_add(1, Ordering::Relaxed);
        }

        fn stream_result(&self, _direction: BusDirection, _outcome: BusStreamOutcome) {}

        fn credits(&self, _direction: BusDirection, bytes: u64) {
            if bytes > 0 {
                self.credits.fetch_add(1, Ordering::Relaxed);
            }
        }

        fn backpressure(
            &self,
            _direction: BusDirection,
            _kind: BusStreamKind,
            _reason: BusBackpressureReason,
        ) {
            self.backpressure.fetch_add(1, Ordering::Relaxed);
        }

        fn rejection(&self, _direction: BusDirection, _outcome: BusRejectionOutcome) {
            self.rejections.fetch_add(1, Ordering::Relaxed);
        }

        fn disconnect(&self, _direction: BusDirection, _outcome: BusDisconnectOutcome) {
            self.disconnects.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn component_activity_binds_reuse_and_revocation_to_exact_attempts() {
        fn write_guard(byte: u8) -> d2b_session::Cancellation {
            let mut requests = d2b_session::RequestRegistry::new(1).unwrap();
            requests
                .register(d2b_session::contract::RequestId::new(vec![byte; 16]).unwrap())
                .unwrap()
        }

        let operation = OperationId::parse("reused").unwrap();
        let first_attempt = Cancellation::new();
        let second_attempt = Cancellation::new();
        let first_valid = Arc::new(AtomicBool::new(true));
        let second_valid = Arc::new(AtomicBool::new(true));
        let second_write_guard = write_guard(2);
        let mut activity = ComponentActivity::default();
        assert!(activity.insert(
            operation.clone(),
            ActiveComponentRequest {
                request_id: d2b_session::contract::RequestId::new(vec![1; 16]).unwrap(),
                valid: first_valid,
                attempt: first_attempt.clone(),
                write_guard: write_guard(1),
            },
        ));
        assert!(activity.insert(
            operation.clone(),
            ActiveComponentRequest {
                request_id: d2b_session::contract::RequestId::new(vec![2; 16]).unwrap(),
                valid: Arc::clone(&second_valid),
                attempt: second_attempt.clone(),
                write_guard: second_write_guard.clone(),
            },
        ));

        let removed = activity.remove(&operation, &first_attempt).unwrap();
        assert!(removed.attempt.is_same_attempt(&first_attempt));
        assert!(
            activity.requests[&operation][0]
                .attempt
                .is_same_attempt(&second_attempt)
        );

        let _ = activity.revoke();
        assert!(!second_valid.load(Ordering::Acquire));
        assert!(second_write_guard.is_cancelled());
        assert!(!activity.insert(
            operation,
            ActiveComponentRequest {
                request_id: d2b_session::contract::RequestId::new(vec![3; 16]).unwrap(),
                valid: Arc::new(AtomicBool::new(true)),
                attempt: Cancellation::new(),
                write_guard: write_guard(3),
            },
        ));
    }

    #[test]
    fn component_cancel_terminalization_removes_activity_and_response_waiter() {
        let operation = OperationId::parse("component-cancel").unwrap();
        let attempt = Cancellation::new();
        let request_id = d2b_session::contract::RequestId::new(vec![7; 16]).unwrap();
        let valid = Arc::new(AtomicBool::new(true));
        let mut requests = d2b_session::RequestRegistry::new(1).unwrap();
        let write_guard = requests.register(request_id.clone()).unwrap();
        let activity = Mutex::new(ComponentActivity::default());
        let responses = Mutex::new(ComponentResponseState::default());
        let mut receiver = publish_component_request(
            &activity,
            &responses,
            operation.clone(),
            ActiveComponentRequest {
                request_id: request_id.clone(),
                valid: Arc::clone(&valid),
                attempt: attempt.clone(),
                write_guard: write_guard.clone(),
            },
        )
        .unwrap();

        let active =
            terminalize_component_request(&activity, &responses, &operation, &attempt).unwrap();

        assert!(active.attempt.is_same_attempt(&attempt));
        assert!(!valid.load(Ordering::Acquire));
        assert!(write_guard.is_cancelled());
        assert!(!activity.lock().unwrap().requests.contains_key(&operation));
        assert!(!responses.lock().unwrap().waiters.contains_key(&request_id));
        assert!(matches!(
            receiver.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Closed)
        ));
    }

    #[test]
    fn component_publication_rejects_an_already_cancelled_attempt_without_state() {
        let operation = OperationId::parse("component-pre-cancel").unwrap();
        let attempt = Cancellation::new();
        attempt.cancel();
        let request_id = d2b_session::contract::RequestId::new(vec![8; 16]).unwrap();
        let mut requests = d2b_session::RequestRegistry::new(1).unwrap();
        let write_guard = requests.register(request_id.clone()).unwrap();
        let activity = Mutex::new(ComponentActivity::default());
        let responses = Mutex::new(ComponentResponseState::default());

        let error = publish_component_request(
            &activity,
            &responses,
            operation.clone(),
            ActiveComponentRequest {
                request_id: request_id.clone(),
                valid: Arc::new(AtomicBool::new(true)),
                attempt,
                write_guard,
            },
        )
        .unwrap_err();

        assert_eq!(error, cancelled_endpoint());
        assert!(!activity.lock().unwrap().requests.contains_key(&operation));
        assert!(!responses.lock().unwrap().waiters.contains_key(&request_id));
    }

    #[test]
    fn component_cancellation_contending_during_publication_removes_all_state() {
        let operation = OperationId::parse("component-contended-cancel").unwrap();
        let attempt = Cancellation::new();
        let request_id = d2b_session::contract::RequestId::new(vec![10; 16]).unwrap();
        let mut requests = d2b_session::RequestRegistry::new(1).unwrap();
        let write_guard = requests.register(request_id.clone()).unwrap();
        let activity = Arc::new(Mutex::new(ComponentActivity::default()));
        let responses = Arc::new(Mutex::new(ComponentResponseState::default()));
        let (publication_locked, publication_reached) = std::sync::mpsc::sync_channel(0);
        let (release_publication, publication_release) = std::sync::mpsc::sync_channel(0);
        let (cancel_contending, cancellation_reached) = std::sync::mpsc::sync_channel(0);

        std::thread::scope(|scope| {
            let publish_activity = Arc::clone(&activity);
            let publish_responses = Arc::clone(&responses);
            let publish_operation = operation.clone();
            let publish_attempt = attempt.clone();
            let publish_request_id = request_id.clone();
            let publisher = scope.spawn(move || {
                publish_component_request_with_hook(
                    &publish_activity,
                    &publish_responses,
                    publish_operation,
                    ActiveComponentRequest {
                        request_id: publish_request_id,
                        valid: Arc::new(AtomicBool::new(true)),
                        attempt: publish_attempt,
                        write_guard,
                    },
                    || {
                        publication_locked.send(()).unwrap();
                        publication_release.recv().unwrap();
                    },
                )
            });

            publication_reached.recv().unwrap();
            let cancel_activity = Arc::clone(&activity);
            let cancel_responses = Arc::clone(&responses);
            let cancel_operation = operation.clone();
            let cancel_attempt = attempt.clone();
            let canceller = scope.spawn(move || {
                let activity_locked = matches!(
                    cancel_activity.try_lock(),
                    Err(std::sync::TryLockError::WouldBlock)
                );
                let responses_locked = matches!(
                    cancel_responses.try_lock(),
                    Err(std::sync::TryLockError::WouldBlock)
                );
                cancel_contending
                    .send((activity_locked, responses_locked))
                    .unwrap();
                terminalize_component_request(
                    &cancel_activity,
                    &cancel_responses,
                    &cancel_operation,
                    &cancel_attempt,
                )
            });

            let publication_locks = cancellation_reached.recv().unwrap();
            release_publication.send(()).unwrap();
            let mut receiver = publisher.join().unwrap().unwrap();
            let cancelled = canceller.join().unwrap().unwrap();
            assert_eq!(
                publication_locks,
                (true, true),
                "activity and response locks must both cover correlated publication"
            );
            assert!(cancelled.attempt.is_same_attempt(&attempt));
            assert!(matches!(
                receiver.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Closed)
            ));
        });

        assert!(!activity.lock().unwrap().requests.contains_key(&operation));
        assert!(!responses.lock().unwrap().waiters.contains_key(&request_id));
    }

    #[test]
    fn correlation_allocator_is_bounded_nonrepeating_and_requires_reconnect() {
        let mut correlations = CorrelationIds::with_key(4, 0x1234_5678_9abc_def0);
        let mut allocated = std::collections::BTreeSet::new();
        for _ in 0..4 {
            let correlation = correlations.allocate().unwrap();
            assert!(correlation > RESERVED_CORRELATION_MAX);
            assert_eq!(correlation % 2, 1);
            assert!(allocated.insert(correlation));
        }
        assert!(matches!(
            correlations.allocate(),
            Err(CorrelationAllocationError::ReconnectRequired)
        ));

        let mut next_generation = CorrelationIds::with_key(1, 0x0fed_cba9_8765_4321);
        let next = next_generation.allocate().unwrap();
        assert!(next > RESERVED_CORRELATION_MAX);
        assert_ne!(next, *allocated.iter().next().unwrap());
    }

    fn harness(spec: HarnessSpec<'_>) -> Harness {
        harness_with_config(spec, BusConfig::default())
    }

    fn harness_with_config(spec: HarnessSpec<'_>, config: BusConfig) -> Harness {
        harness_with_config_and_observer(spec, config, Arc::new(NoopBusObserver))
    }

    fn harness_with_config_and_observer(
        spec: HarnessSpec<'_>,
        config: BusConfig,
        observer: Arc<dyn BusObserver>,
    ) -> Harness {
        harness_with_config_and_observer_and_metrics(
            spec,
            config,
            observer,
            Arc::new(NoopBusTelemetry),
        )
    }

    fn harness_with_config_and_observer_and_metrics(
        spec: HarnessSpec<'_>,
        config: BusConfig,
        observer: Arc<dyn BusObserver>,
        metrics: Arc<dyn BusTelemetry>,
    ) -> Harness {
        let zone = ZoneId::parse("dev").unwrap();
        let schema = fingerprint('1');
        let generations = RouteGenerations::new(
            Some(ResourceGeneration::new(2).unwrap()),
            Some(ControllerGeneration::new(3).unwrap()),
            ReconnectGeneration::new(1).unwrap(),
        );
        let route = RouteKey::new(
            zone.clone(),
            ServiceName::parse(spec.service).unwrap(),
            spec.member,
            RouteTarget::provider(ResourceRef::parse("Provider/system-core").unwrap()).unwrap(),
            schema.clone(),
            generations,
        );
        let caller = context(
            spec.caller_ref,
            CALLER_UID,
            spec.service,
            schema.clone(),
            generations,
            spec.locality,
            spec.evidence,
        );
        let endpoint_context = context(
            "Provider/system-core",
            ENDPOINT_UID,
            spec.service,
            schema,
            generations,
            Locality::Local,
            EvidenceClass::EnrolledKk,
        );
        let subjects = vec![bound_subject(&caller), bound_subject(&endpoint_context)];
        let policy = policy(1, &subjects, &spec.session_verbs, &spec.resource_verbs);
        let native = NativeAuthorizer::new(ApiCatalog::standard(), Some(policy)).unwrap();
        let authorizer = BusAuthorizer::new(native, state(1)).unwrap();
        let clock = Arc::new(ManualClock::new(1));
        let (bus, mut registrar) = ZoneBus::with_clock_observer_and_metrics(
            zone,
            authorizer,
            config,
            clock.clone(),
            observer,
            metrics,
        )
        .unwrap();
        let endpoint_ingress = registrar
            .register(SessionRegistration::new(
                endpoint_context,
                vec![route.clone()],
                spec.endpoint.clone(),
            ))
            .unwrap();
        let caller = registrar
            .register(SessionRegistration::new(
                caller,
                Vec::new(),
                spec.endpoint.clone(),
            ))
            .unwrap();
        Harness {
            bus,
            registrar,
            caller,
            endpoint_ingress,
            endpoint: spec.endpoint,
            route,
            subjects,
            clock,
        }
    }

    fn replacement_endpoint_registration(harness: &Harness) -> SessionRegistration {
        let generations = RouteGenerations::new(
            harness.route.generations().provider(),
            harness.route.generations().controller(),
            ReconnectGeneration::new(2).unwrap(),
        );
        let route = RouteKey::new(
            harness.route.zone().clone(),
            harness.route.service().clone(),
            harness.route.member().clone(),
            harness.route.target().clone(),
            harness.route.schema().clone(),
            generations,
        );
        let endpoint = context(
            "Provider/system-core",
            ENDPOINT_UID,
            "d2b.resource.v3",
            harness.route.schema().clone(),
            generations,
            Locality::Local,
            EvidenceClass::EnrolledKk,
        );
        SessionRegistration::new(endpoint, vec![route], harness.endpoint.clone())
    }

    async fn wait_for_endpoint_cancellation(endpoint: &RecordingEndpoint) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while endpoint.cancellation_count() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("endpoint cancellation was not dispatched");
    }

    #[derive(Default)]
    struct CaptureObserver(Mutex<Vec<(BusEvent, BusFailureReason)>>);

    impl BusObserver for CaptureObserver {
        fn record(&self, event: BusEvent, reason: BusFailureReason) {
            self.0.lock().unwrap().push((event, reason));
        }
    }

    fn context(
        subject_ref: &str,
        uid: &str,
        service: &str,
        schema: SchemaFingerprint,
        generations: RouteGenerations,
        locality: Locality,
        evidence: EvidenceClass,
    ) -> AuthenticatedSubjectContext {
        AuthenticatedSubjectContext::new(
            ResourceRef::parse(subject_ref).unwrap(),
            ResourceUid::parse(uid).unwrap(),
            ResourceRef::parse("Zone/dev").unwrap(),
            evidence,
            SessionPurpose::parse("zone-bus").unwrap(),
            ServiceName::parse(service).unwrap(),
            SessionBinding::new(
                schema,
                TransportBinding::new(locality, digest('2')),
                generations.session(),
                TranscriptHash::from_bytes([3; 32]),
            ),
        )
        .with_provider_ref(ResourceRef::parse("Provider/system-core").unwrap())
        .with_provider_generation(generations.provider().unwrap())
        .with_controller_generation(generations.controller().unwrap())
    }

    fn fingerprint(value: char) -> SchemaFingerprint {
        SchemaFingerprint::parse(format!("sha256:{}", value.to_string().repeat(64))).unwrap()
    }

    fn digest(value: char) -> BindingDigest {
        BindingDigest::parse(format!("sha256:{}", value.to_string().repeat(64))).unwrap()
    }

    fn bound_subject(context: &AuthenticatedSubjectContext) -> BoundSubject {
        BoundSubject {
            subject_ref: context.subject_ref().clone(),
            subject_uid: context.subject_uid().clone(),
        }
    }

    fn policy(
        revision: u64,
        subjects: &[BoundSubject],
        session_verbs: &[SessionVerb],
        resource_verbs: &[ResourceVerb],
    ) -> PolicySet {
        let catalog = ApiCatalog::standard();
        let resource_types = (!resource_verbs.is_empty())
            .then(|| ResourceTypeName::parse("Host").unwrap())
            .into_iter();
        let rule = PolicyRule::new(
            &catalog,
            resource_types,
            resource_verbs.iter().copied(),
            session_verbs.iter().copied(),
            [],
            [],
            [ZoneId::parse("dev").unwrap()],
            [],
        )
        .unwrap();
        let role =
            CompiledRole::new(ResourceRef::parse("Role/bus-test").unwrap(), vec![rule]).unwrap();
        let relay_authority = if session_verbs.contains(&SessionVerb::Relay) {
            RelayGrantAuthority::CoreGenerated
        } else {
            RelayGrantAuthority::None
        };
        let binding = CompiledRoleBinding::new(
            role.role_ref.clone(),
            subjects.iter().cloned(),
            BindingScope::default(),
            relay_authority,
        )
        .unwrap();
        PolicySet::new(&catalog, revision, vec![role], vec![binding]).unwrap()
    }

    fn state(revision: u64) -> AuthorizationState {
        AuthorizationState {
            snapshot: PolicySnapshot {
                policy_revision: revision,
                api_catalog_revision: 1,
                active_configuration_revision: ConfigurationGeneration::new(1).unwrap(),
                controller_generation: Some(ControllerGeneration::new(3).unwrap()),
            },
            zone_policy_revision: ZoneRevision::new(revision),
            bootstrap_phase: BootstrapPhase::Disabled,
            now_tick: revision,
        }
    }

    fn subject_issuer_bus() -> (ZoneBus, ZoneRegistrar, CommittedInteractionSubjectIssuer) {
        ZoneBus::with_interaction_subject_issuer(
            ZoneId::parse("dev").unwrap(),
            BusAuthorizer::new(
                NativeAuthorizer::new(ApiCatalog::standard(), None).unwrap(),
                state(1),
            )
            .unwrap(),
            BusConfig::default(),
        )
        .unwrap()
    }

    fn subject_install(
        issuer: CommittedInteractionSubjectIssuer,
    ) -> CommittedInteractionSubjectInstall {
        issuer
            .seal(
                ZoneId::parse("dev").unwrap(),
                ResourceRef::parse("Guest/guest").unwrap(),
                ResourceUid::parse(CALLER_UID).unwrap(),
                42,
                ResourceRef::parse("Host/host-system").unwrap(),
                ResourceGeneration::new(2).unwrap(),
                None,
                None,
                None,
                None,
            )
            .unwrap()
    }

    #[test]
    fn committed_subject_install_is_instance_bound_and_default_deny() {
        let (_bus_a, registrar_a, issuer_a) = subject_issuer_bus();
        let (_bus_b, registrar_b, issuer_b) = subject_issuer_bus();

        assert_eq!(
            registrar_a
                .interaction_subjects
                .as_ref()
                .expect("opt-in subject registrar")
                .authority
                .controller_generation
                .get(),
            3
        );
        assert!(
            registrar_b
                .install_committed_interaction_subject(subject_install(issuer_a))
                .is_err(),
            "an install token must be rejected by another registrar"
        );
        assert!(
            registrar_b
                .unix_subjects
                .subjects
                .lock()
                .unwrap()
                .is_empty(),
            "cross-registrar rejection must precede subject mutation"
        );

        let (_default_bus, default_registrar) = ZoneBus::new(
            ZoneId::parse("dev").unwrap(),
            BusAuthorizer::new(
                NativeAuthorizer::new(ApiCatalog::standard(), None).unwrap(),
                state(1),
            )
            .unwrap(),
            BusConfig::default(),
        )
        .unwrap();
        assert!(
            default_registrar
                .install_committed_interaction_subject(subject_install(issuer_b))
                .is_err(),
            "default constructors must not expose committed subject installation"
        );
        assert!(
            default_registrar
                .unix_subjects
                .subjects
                .lock()
                .unwrap()
                .is_empty(),
            "default-deny rejection must precede subject mutation"
        );
    }

    fn operation(id: &str) -> OperationSpec {
        OperationSpec::new(OperationId::parse(id).unwrap(), 100).unwrap()
    }

    fn watch_store_identity() -> StoreIdentity {
        StoreIdentity::new(
            StoreSlot::new(0).unwrap(),
            ResourceUid::parse("33333333-3333-4333-8333-333333333333").unwrap(),
            ZoneId::parse("dev").unwrap(),
            ResourceUid::parse("44444444-4444-4444-8444-444444444444").unwrap(),
            Timestamp::parse("2026-07-31T00:00:00.000Z").unwrap(),
            d2b_resource_store::PolicySnapshot {
                policy_revision: 1,
                api_catalog_revision: 1,
                active_configuration_revision: ConfigurationGeneration::new(1).unwrap(),
                controller_generation: Some(ControllerGeneration::new(3).unwrap()),
            },
        )
    }

    async fn provision_watch_store() -> (
        tempfile::TempDir,
        Arc<RedbResourceStore>,
        d2b_resource_store::mutation_seal::MutationSealIssuer,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(directory.path().join("store.redb"))
            .unwrap();
        let mut marker = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(directory.path().join("store.marker"))
            .unwrap();
        let identity = watch_store_identity();
        write_provisioning_marker(&mut marker, &identity).unwrap();
        let (issuer, acceptor) = mutation_seal_pair(identity.seal_identity());
        let audit = Arc::new(
            d2b_audit::AuditSink::open(directory.path().join("audit"))
                .expect("open watch audit sink"),
        );
        let store =
            RedbResourceStore::provision_owned_with_audit(file, marker, identity, acceptor, audit)
                .await
                .unwrap();
        (directory, Arc::new(store), issuer)
    }

    fn watch_body(name: &str) -> Vec<u8> {
        let raw = format!(
            r#"{{"apiVersion":"resources.d2bus.org/v3","metadata":{{"configurationGeneration":1,"createdAt":"2026-07-22T00:00:00.000Z","deletionRequestedAt":null,"finalizers":[],"generation":1,"managedBy":"configuration","name":"{name}","ownerRef":null,"revision":1,"uid":"123e4567-e89b-42d3-a456-426614174000","updatedAt":"2026-07-22T00:00:00.000Z","zone":"dev"}},"spec":{{"providerRef":"Provider/system-core","updatePolicy":{{"disruptive":"manual","nonDisruptive":"automatic"}}}},"status":{{"completedAt":null,"conditions":[],"lastReconciledAt":null,"observedGeneration":0,"outcome":null,"phase":"Pending","resource":{{}},"startedAt":null,"update":{{"dependencies":{{"count":0,"refs":[]}},"disruption":"None","lastAssessedAt":null,"observedGeneration":0,"operationId":null,"owned":{{"count":0,"refs":[]}},"preserveState":true,"reasons":[],"state":"Unknown","targetGeneration":1}}}},"type":"Host"}}"#
        );
        let mut value = CanonicalJsonValue::parse(raw.as_bytes()).unwrap();
        let CanonicalJsonValue::Object(root) = &mut value else {
            unreachable!()
        };
        let CanonicalJsonValue::Object(metadata) = root.get_mut("metadata").unwrap() else {
            unreachable!()
        };
        metadata.remove("uid");
        value.to_canonical_bytes()
    }

    async fn commit_watch_resource(
        store: &RedbResourceStore,
        issuer: &d2b_resource_store::mutation_seal::MutationSealIssuer,
    ) -> ZoneRevision {
        let target = ResourceRef::parse("Host/bus-watch").unwrap();
        let canonical = watch_body("bus-watch");
        let digest = canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &canonical);
        let body = MutationSealBody {
            mutations: vec![PreparedStoreMutation::new(
                StoreMutation {
                    kind: ResourceMutationKind::Create,
                    zone: ZoneId::parse("dev").unwrap(),
                    target: target.clone(),
                    expected: ExpectedRevision::CreateAbsent,
                    expected_uid: None,
                    owner: None,
                    canonical_resource: Some(canonical),
                    add_finalizers: Vec::new(),
                    remove_finalizers: Vec::new(),
                    wait_for_reconcile: false,
                    reconcile_deadline_ms: None,
                    configuration_generation: None,
                    assignment: None,
                },
                None,
                Some(digest),
            )],
            authorization: AdmittedAuthorization {
                zone: ZoneId::parse("dev").unwrap(),
                subject_ref: ResourceRef::parse("Provider/system-core").unwrap(),
                subject_uid: ResourceUid::parse("55555555-5555-4555-8555-555555555555").unwrap(),
                targets: vec![AdmittedAuthorizationTarget {
                    resource_type: ResourceTypeName::parse("Host").unwrap(),
                    resource_name: Some(target.name().clone()),
                    verb: AdmittedVerb::Create,
                    subresource: None,
                    execution_ref: None,
                }],
            },
            policy_snapshot: d2b_resource_store::PolicySnapshot {
                policy_revision: 1,
                api_catalog_revision: 1,
                active_configuration_revision: ConfigurationGeneration::new(1).unwrap(),
                controller_generation: Some(ControllerGeneration::new(3).unwrap()),
            },
            operation: StoreOperationContext {
                operation_id: "bus-watch".to_owned(),
                idempotency_key: Some("bus-watch-key".to_owned()),
                correlation_id: "bus-watch-correlation".to_owned(),
                trace_id: None,
                deadline_ms: 1_000,
            },
        };
        store
            .commit_verified(issuer.seal(body))
            .await
            .unwrap()
            .revision
    }

    fn resource_harness(
        member: RouteMember,
        session_verbs: Vec<SessionVerb>,
        resource_verbs: Vec<ResourceVerb>,
        caller_ref: &str,
        locality: Locality,
        evidence: EvidenceClass,
    ) -> Harness {
        harness(HarnessSpec {
            service: "d2b.resource.v3",
            member,
            caller_ref,
            locality,
            evidence,
            session_verbs,
            resource_verbs,
            endpoint: RecordingEndpoint::new(),
        })
    }

    #[test]
    fn route_members_reject_wildcards_and_topic_shapes() {
        for invalid in [
            "",
            "*",
            "ResourceService/*",
            "ResourceService/Get?",
            "/ResourceService/Get",
            "ResourceService/Get/",
        ] {
            assert_eq!(
                RouteMember::method(invalid),
                Err(RegistryError::InvalidMember)
            );
            assert_eq!(
                RouteMember::stream(invalid),
                Err(RegistryError::InvalidMember)
            );
        }
    }

    #[test]
    fn consumed_session_identity_cannot_be_registered_twice() {
        let mut harness = resource_harness(
            RouteMember::method("ResourceService/Get").unwrap(),
            vec![SessionVerb::Connect, SessionVerb::Invoke],
            vec![ResourceVerb::Get],
            "User/alice",
            Locality::Local,
            EvidenceClass::UnixPeer,
        );
        let duplicate = context(
            "User/alice",
            CALLER_UID,
            "d2b.resource.v3",
            harness.route.schema().clone(),
            harness.route.generations(),
            Locality::Local,
            EvidenceClass::UnixPeer,
        );

        assert!(matches!(
            harness.registrar.register(SessionRegistration::new(
                duplicate,
                Vec::new(),
                harness.endpoint.clone(),
            )),
            Err(BusError::Registry(RegistryError::DuplicateSessionIdentity))
        ));
    }

    #[test]
    fn exact_route_cannot_be_claimed_by_a_second_identity() {
        let mut harness = resource_harness(
            RouteMember::method("ResourceService/Get").unwrap(),
            vec![SessionVerb::Connect, SessionVerb::Invoke],
            vec![ResourceVerb::Get],
            "User/alice",
            Locality::Local,
            EvidenceClass::UnixPeer,
        );
        let second = context(
            "User/bob",
            "33333333-3333-4333-8333-333333333333",
            "d2b.resource.v3",
            harness.route.schema().clone(),
            harness.route.generations(),
            Locality::Local,
            EvidenceClass::UnixPeer,
        );
        harness
            .bus
            .replace_policy(
                policy(
                    2,
                    &[
                        harness.subjects[0].clone(),
                        harness.subjects[1].clone(),
                        bound_subject(&second),
                    ],
                    &[SessionVerb::Connect, SessionVerb::Invoke],
                    &[ResourceVerb::Get],
                ),
                state(2),
            )
            .unwrap();

        assert!(matches!(
            harness.registrar.register(SessionRegistration::new(
                second,
                vec![harness.route.clone()],
                harness.endpoint.clone(),
            )),
            Err(BusError::Registry(RegistryError::DuplicateRoute))
        ));
    }

    #[tokio::test]
    async fn exact_routes_deliver_only_to_the_named_recipient() {
        let zone = ZoneId::parse("dev").unwrap();
        let schema = fingerprint('1');
        let generations = RouteGenerations::new(
            Some(ResourceGeneration::new(2).unwrap()),
            Some(ControllerGeneration::new(3).unwrap()),
            ReconnectGeneration::new(1).unwrap(),
        );
        let service = ServiceName::parse("d2b.resource.v3").unwrap();
        let member = RouteMember::method("ResourceService/Get").unwrap();
        let provider_a = ResourceRef::parse("Provider/recipient-a").unwrap();
        let provider_b = ResourceRef::parse("Provider/recipient-b").unwrap();
        let route_a = RouteKey::new(
            zone.clone(),
            service.clone(),
            member.clone(),
            RouteTarget::provider(provider_a.clone()).unwrap(),
            schema.clone(),
            generations,
        );
        let route_b = RouteKey::new(
            zone.clone(),
            service.clone(),
            member,
            RouteTarget::provider(provider_b.clone()).unwrap(),
            schema.clone(),
            generations,
        );
        let caller_context_a = context(
            "User/alice-a",
            CALLER_UID,
            service.as_str(),
            schema.clone(),
            generations,
            Locality::Local,
            EvidenceClass::UnixPeer,
        )
        .with_provider_ref(provider_a.clone());
        let caller_context_b = context(
            "User/alice-b",
            "55555555-5555-4555-8555-555555555555",
            service.as_str(),
            schema.clone(),
            generations,
            Locality::Local,
            EvidenceClass::UnixPeer,
        )
        .with_provider_ref(provider_b.clone());
        let endpoint_a_context = context(
            "Provider/recipient-a",
            "33333333-3333-4333-8333-333333333333",
            service.as_str(),
            schema.clone(),
            generations,
            Locality::Local,
            EvidenceClass::UnixPeer,
        )
        .with_provider_ref(provider_a.clone());
        let endpoint_b_context = context(
            "Provider/recipient-b",
            "44444444-4444-4444-8444-444444444444",
            service.as_str(),
            schema,
            generations,
            Locality::Local,
            EvidenceClass::UnixPeer,
        )
        .with_provider_ref(provider_b.clone());
        let endpoint_a = RecordingEndpoint::new();
        let endpoint_b = RecordingEndpoint::new();
        let subjects = [
            bound_subject(&caller_context_a),
            bound_subject(&caller_context_b),
            bound_subject(&endpoint_a_context),
            bound_subject(&endpoint_b_context),
        ];
        let native = NativeAuthorizer::new(
            ApiCatalog::standard(),
            Some(policy(
                1,
                &subjects,
                &[SessionVerb::Connect, SessionVerb::Invoke],
                &[ResourceVerb::Get],
            )),
        )
        .unwrap();
        let (bus, mut registrar) = ZoneBus::with_clock(
            zone,
            BusAuthorizer::new(native, state(1)).unwrap(),
            BusConfig::default(),
            Arc::new(ManualClock::new(1)),
        )
        .unwrap();
        let endpoint_a_ingress = registrar
            .register(SessionRegistration::new(
                endpoint_a_context,
                vec![route_a.clone()],
                endpoint_a.clone(),
            ))
            .unwrap();
        let endpoint_b_ingress = registrar
            .register(SessionRegistration::new(
                endpoint_b_context,
                vec![route_b.clone()],
                endpoint_b.clone(),
            ))
            .unwrap();
        let caller = registrar
            .register(SessionRegistration::new(
                caller_context_a,
                Vec::new(),
                RecordingEndpoint::new(),
            ))
            .unwrap();
        let caller_b = registrar
            .register(SessionRegistration::new(
                caller_context_b,
                Vec::new(),
                RecordingEndpoint::new(),
            ))
            .unwrap();

        caller
            .invoke_resource(
                route_a.clone(),
                operation("recipient-a"),
                ResourceCall::Get(ResourceRef::parse("Host/system").unwrap()),
                b"to-a".to_vec(),
            )
            .await
            .unwrap();
        assert_eq!(endpoint_a.call_count(), 1);
        assert_eq!(endpoint_b.call_count(), 0);
        assert_eq!(
            endpoint_a.calls.lock().unwrap()[0]
                .0
                .target()
                .resource_ref(),
            &provider_a
        );
        assert_eq!(endpoint_a.calls.lock().unwrap()[0].2, b"to-a".to_vec());

        assert_eq!(
            caller
                .invoke_resource(
                    route_b.clone(),
                    operation("wrong-recipient"),
                    ResourceCall::Get(ResourceRef::parse("Host/system").unwrap()),
                    b"must-not-deliver".to_vec(),
                )
                .await,
            Err(BusError::Authorization(
                AuthorizationError::SessionBindingMismatch
            ))
        );
        assert_eq!(endpoint_a.call_count(), 1);
        assert_eq!(endpoint_b.call_count(), 0);

        caller_b
            .invoke_resource(
                route_b.clone(),
                operation("recipient-b"),
                ResourceCall::Get(ResourceRef::parse("Host/system").unwrap()),
                b"to-b".to_vec(),
            )
            .await
            .unwrap();
        assert_eq!(endpoint_a.call_count(), 1);
        assert_eq!(endpoint_b.call_count(), 1);
        assert_eq!(
            endpoint_b.calls.lock().unwrap()[0]
                .0
                .target()
                .resource_ref(),
            &provider_b
        );
        assert_eq!(endpoint_b.calls.lock().unwrap()[0].2, b"to-b".to_vec());

        registrar.revoke(caller).await.unwrap();
        registrar.revoke(caller_b).await.unwrap();
        registrar.revoke(endpoint_a_ingress).await.unwrap();
        registrar.revoke(endpoint_b_ingress).await.unwrap();
        drop(bus);
    }

    #[tokio::test]
    async fn exact_route_is_required_and_no_direct_resource_fallback_exists() {
        let mut harness = resource_harness(
            RouteMember::method("ResourceService/Get").unwrap(),
            vec![SessionVerb::Connect, SessionVerb::Invoke],
            vec![ResourceVerb::Get],
            "User/alice",
            Locality::Local,
            EvidenceClass::UnixPeer,
        );
        let response = harness
            .caller
            .invoke_resource(
                harness.route.clone(),
                operation("exact"),
                ResourceCall::Get(ResourceRef::parse("Host/system").unwrap()),
                b"exact-payload".to_vec(),
            )
            .await
            .unwrap();
        assert_eq!(response.as_bytes(), b"response");
        assert_eq!(harness.endpoint.call_count(), 1);

        let resource_route = RouteKey::new(
            harness.route.zone().clone(),
            harness.route.service().clone(),
            harness.route.member().clone(),
            RouteTarget::resource(ResourceRef::parse("Host/system").unwrap()).unwrap(),
            harness.route.schema().clone(),
            harness.route.generations(),
        );
        let resource_endpoint = context(
            "User/resource-endpoint",
            "44444444-4444-4444-8444-444444444444",
            "d2b.resource.v3",
            harness.route.schema().clone(),
            harness.route.generations(),
            Locality::Local,
            EvidenceClass::UnixPeer,
        );
        harness
            .bus
            .replace_policy(
                policy(
                    2,
                    &[
                        harness.subjects[0].clone(),
                        harness.subjects[1].clone(),
                        bound_subject(&resource_endpoint),
                    ],
                    &[SessionVerb::Connect, SessionVerb::Invoke],
                    &[ResourceVerb::Get],
                ),
                state(2),
            )
            .unwrap();
        let resource_ingress = harness
            .registrar
            .register(SessionRegistration::new(
                resource_endpoint,
                vec![resource_route.clone()],
                harness.endpoint.clone(),
            ))
            .unwrap();
        assert_eq!(
            harness
                .caller
                .invoke_resource(
                    resource_route,
                    operation("wrong-resource"),
                    ResourceCall::Get(ResourceRef::parse("Host/other").unwrap()),
                    Vec::new(),
                )
                .await,
            Err(BusError::InvalidResourceCall)
        );
        assert_eq!(harness.endpoint.call_count(), 1);
        harness.registrar.revoke(resource_ingress).await.unwrap();

        let unregistered = RouteKey::new(
            harness.route.zone().clone(),
            harness.route.service().clone(),
            harness.route.member().clone(),
            RouteTarget::resource(ResourceRef::parse("Host/system").unwrap()).unwrap(),
            harness.route.schema().clone(),
            harness.route.generations(),
        );
        assert_eq!(
            harness
                .caller
                .invoke_resource(
                    unregistered,
                    operation("no-fallback"),
                    ResourceCall::Get(ResourceRef::parse("Host/system").unwrap()),
                    Vec::new(),
                )
                .await,
            Err(BusError::Registry(RegistryError::RouteNotFound))
        );
        assert_eq!(harness.endpoint.call_count(), 1);
    }

    #[tokio::test]
    async fn zone_mismatch_is_rejected_before_delivery() {
        let harness = resource_harness(
            RouteMember::method("ResourceService/Get").unwrap(),
            vec![SessionVerb::Connect, SessionVerb::Invoke],
            vec![ResourceVerb::Get],
            "User/alice",
            Locality::Local,
            EvidenceClass::UnixPeer,
        );
        let wrong_zone = RouteKey::new(
            ZoneId::parse("personal").unwrap(),
            harness.route.service().clone(),
            harness.route.member().clone(),
            harness.route.target().clone(),
            harness.route.schema().clone(),
            harness.route.generations(),
        );
        assert_eq!(
            harness
                .caller
                .invoke_resource(
                    wrong_zone,
                    operation("wrong-zone"),
                    ResourceCall::Get(ResourceRef::parse("Host/system").unwrap()),
                    Vec::new(),
                )
                .await,
            Err(BusError::Authorization(AuthorizationError::ZoneMismatch))
        );
        assert_eq!(harness.endpoint.call_count(), 0);
    }

    #[tokio::test]
    async fn diagnostics_require_the_exact_service_method_and_grant_no_invoke() {
        let exact = harness(HarnessSpec {
            service: "d2b.audit.v3",
            member: RouteMember::method("AuditService/Export").unwrap(),
            caller_ref: "User/alice",
            locality: Locality::Local,
            evidence: EvidenceClass::UnixPeer,
            session_verbs: vec![SessionVerb::Connect, SessionVerb::AuditExport],
            resource_verbs: Vec::new(),
            endpoint: RecordingEndpoint::new(),
        });
        assert!(
            exact
                .caller
                .invoke(exact.route.clone(), operation("audit-export"), Vec::new(),)
                .await
                .is_ok()
        );

        let near_miss = harness(HarnessSpec {
            service: "d2b.audit.v3",
            member: RouteMember::method("AuditService/Inspect").unwrap(),
            caller_ref: "User/alice",
            locality: Locality::Local,
            evidence: EvidenceClass::UnixPeer,
            session_verbs: vec![SessionVerb::Connect, SessionVerb::AuditExport],
            resource_verbs: Vec::new(),
            endpoint: RecordingEndpoint::new(),
        });
        assert_eq!(
            near_miss
                .caller
                .invoke(
                    near_miss.route.clone(),
                    operation("audit-near-miss"),
                    Vec::new(),
                )
                .await,
            Err(BusError::RouteShape)
        );
        assert_eq!(near_miss.endpoint.call_count(), 0);

        let support = harness(HarnessSpec {
            service: "d2b.support.v3",
            member: RouteMember::method("SupportService/GenerateBundle").unwrap(),
            caller_ref: "User/alice",
            locality: Locality::Local,
            evidence: EvidenceClass::UnixPeer,
            session_verbs: vec![SessionVerb::Connect, SessionVerb::SupportBundle],
            resource_verbs: Vec::new(),
            endpoint: RecordingEndpoint::new(),
        });
        assert!(
            support
                .caller
                .invoke(
                    support.route.clone(),
                    operation("support-bundle"),
                    Vec::new(),
                )
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn relay_and_target_verb_are_independently_required() {
        let no_relay = resource_harness(
            RouteMember::method("ResourceService/Get").unwrap(),
            vec![SessionVerb::Connect, SessionVerb::Invoke],
            vec![ResourceVerb::Get],
            "ZoneLink/parent",
            Locality::AdjacentZone,
            EvidenceClass::EnrolledKk,
        );
        assert_eq!(
            no_relay
                .caller
                .invoke_resource(
                    no_relay.route.clone(),
                    operation("relay-missing"),
                    ResourceCall::Get(ResourceRef::parse("Host/system").unwrap()),
                    Vec::new(),
                )
                .await,
            Err(BusError::Authorization(
                AuthorizationError::RelayGrantMissing
            ))
        );

        let no_target = resource_harness(
            RouteMember::method("ResourceService/Get").unwrap(),
            vec![
                SessionVerb::Connect,
                SessionVerb::Invoke,
                SessionVerb::Relay,
            ],
            Vec::new(),
            "ZoneLink/parent",
            Locality::AdjacentZone,
            EvidenceClass::EnrolledKk,
        );
        assert_eq!(
            no_target
                .caller
                .invoke_resource(
                    no_target.route.clone(),
                    operation("target-missing"),
                    ResourceCall::Get(ResourceRef::parse("Host/system").unwrap()),
                    Vec::new(),
                )
                .await,
            Err(BusError::Authorization(AuthorizationError::Native(
                d2b_resource_api::authz::AuthorizationDenial::RelayTargetGrantMissing
            )))
        );
    }

    #[test]
    fn scoped_owner_child_queries_reject_non_process_and_mismatched_scope() {
        let first = ScopedCommitTransport::decode(
            br#"{"version":1,"assignment":{"resourceUid":"123e4567-e89b-42d3-a456-426614174000","resourceRevision":7,"providerRef":"Provider/provider-runtime","providerGeneration":2,"controllerGeneration":3,"controllerRole":"Process/process-controller","target":{"kind":"zone","zone":"dev"},"sessionOwner":"Process/process-controller","sessionGeneration":1,"epoch":9},"mutations":[{"target":"Process/work","verb":"Create","scope":{"kind":"owner-child","ownerRef":"Guest/guest","ownerUid":"123e4567-e89b-42d3-a456-426614174000","ownerRevision":7,"ownerGeneration":1}}]}"#,
        )
        .unwrap();
        let second = ScopedCommitTransport::decode(
            br#"{"version":1,"assignment":{"resourceUid":"223e4567-e89b-42d3-a456-426614174001","resourceRevision":7,"providerRef":"Provider/provider-runtime","providerGeneration":2,"controllerGeneration":3,"controllerRole":"Process/process-controller","target":{"kind":"zone","zone":"dev"},"sessionOwner":"Process/process-controller","sessionGeneration":1,"epoch":10},"mutations":[{"target":"Process/work","verb":"Create","scope":{"kind":"owner-child","ownerRef":"Guest/guest","ownerUid":"223e4567-e89b-42d3-a456-426614174001","ownerRevision":7,"ownerGeneration":1}}]}"#,
        )
        .unwrap();
        let owner_uid = first.assignment().resource_uid().clone();
        let owner_scope = first.mutations()[0].scope().clone();
        let owner_filter =
            ResourceFilter::new(OWNER_UID_FILTER, vec![owner_uid.as_str().to_owned()]).unwrap();
        let zone = ZoneId::parse("dev").unwrap();

        let non_process = ResourceQuery {
            resource_types: vec![ResourceTypeName::parse("Host").unwrap()],
            resource_names: Vec::new(),
            filters: vec![owner_filter.clone()],
            assignment: Some(first.assignment().clone()),
            scope: Some(owner_scope.clone()),
        };
        assert_eq!(
            ResourceCall::List(non_process).authorization_request(zone.clone()),
            Err(BusError::InvalidResourceCall)
        );

        let mismatched_scope = ResourceQuery {
            resource_types: vec![ResourceTypeName::parse(PROCESS_RESOURCE_TYPE).unwrap()],
            resource_names: Vec::new(),
            filters: vec![owner_filter],
            assignment: Some(second.assignment().clone()),
            scope: Some(owner_scope),
        };
        assert_eq!(
            ResourceCall::Watch(mismatched_scope).authorization_request(zone),
            Err(BusError::InvalidResourceCall)
        );
    }

    #[test]
    fn unscoped_process_queries_remain_available_to_native_rbac() {
        let query = ResourceQuery::new(
            vec![ResourceTypeName::parse(PROCESS_RESOURCE_TYPE).unwrap()],
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        assert!(
            ResourceCall::List(query)
                .authorization_request(ZoneId::parse("dev").unwrap())
                .is_ok()
        );
    }

    #[test]
    fn adjacent_relay_identity_never_inherits_a_local_subject_grant() {
        let zone = ZoneId::parse("dev").unwrap();
        let schema = fingerprint('1');
        let generations = RouteGenerations::new(
            Some(ResourceGeneration::new(2).unwrap()),
            Some(ControllerGeneration::new(3).unwrap()),
            ReconnectGeneration::new(1).unwrap(),
        );
        let local = context(
            "User/alice",
            CALLER_UID,
            "d2b.resource.v3",
            schema.clone(),
            generations,
            Locality::Local,
            EvidenceClass::UnixPeer,
        );
        let relay = context(
            "ZoneLink/parent",
            ENDPOINT_UID,
            "d2b.resource.v3",
            schema,
            generations,
            Locality::AdjacentZone,
            EvidenceClass::EnrolledKk,
        );
        let native = NativeAuthorizer::new(
            ApiCatalog::standard(),
            Some(policy(
                1,
                &[bound_subject(&local)],
                &[SessionVerb::Connect, SessionVerb::Relay],
                &[],
            )),
        )
        .unwrap();
        let (_bus, mut registrar) = ZoneBus::new(
            zone,
            BusAuthorizer::new(native, state(1)).unwrap(),
            BusConfig::default(),
        )
        .unwrap();
        assert!(matches!(
            registrar.register(SessionRegistration::new(
                relay,
                Vec::new(),
                RecordingEndpoint::new(),
            )),
            Err(BusError::Authorization(
                AuthorizationError::SessionVerbMissing(SessionVerb::Connect)
            ))
        ));
    }

    #[test]
    fn provider_routes_reject_peer_self_assertion() {
        let zone = ZoneId::parse("dev").unwrap();
        let schema = fingerprint('1');
        let generations = RouteGenerations::new(
            Some(ResourceGeneration::new(2).unwrap()),
            Some(ControllerGeneration::new(3).unwrap()),
            ReconnectGeneration::new(1).unwrap(),
        );
        let forged = context(
            "Provider/attacker",
            CALLER_UID,
            "d2b.echo.v3",
            schema.clone(),
            generations,
            Locality::Local,
            EvidenceClass::EnrolledKk,
        );
        let subjects = vec![bound_subject(&forged)];
        let native = NativeAuthorizer::new(
            ApiCatalog::standard(),
            Some(policy(1, &subjects, &[SessionVerb::Connect], &[])),
        )
        .unwrap();
        let (bus, mut registrar) = ZoneBus::new(
            zone.clone(),
            BusAuthorizer::new(native, state(1)).unwrap(),
            BusConfig::default(),
        )
        .unwrap();
        let route = RouteKey::new(
            zone,
            ServiceName::parse("d2b.echo.v3").unwrap(),
            RouteMember::method("EchoService/Call").unwrap(),
            RouteTarget::provider(ResourceRef::parse("Provider/system-core").unwrap()).unwrap(),
            schema,
            generations,
        );
        let result = registrar.register(SessionRegistration::new(
            forged,
            vec![route],
            RecordingEndpoint::new(),
        ));
        assert!(matches!(
            result,
            Err(BusError::Registry(RegistryError::ProviderAssertion))
        ));
        drop(bus);
    }

    #[tokio::test]
    async fn list_and_watch_selectors_survive_an_adjacent_hop_exactly() {
        let mut list = resource_harness(
            RouteMember::method("ResourceService/List").unwrap(),
            vec![
                SessionVerb::Connect,
                SessionVerb::Invoke,
                SessionVerb::Relay,
            ],
            vec![ResourceVerb::List],
            "ZoneLink/parent",
            Locality::AdjacentZone,
            EvidenceClass::EnrolledKk,
        );
        let nameless = ResourceQuery::new(
            vec![ResourceTypeName::parse("Host").unwrap()],
            Vec::new(),
            vec![
                ResourceFilter::new("metadata.managedBy", vec!["configuration".to_owned()])
                    .unwrap(),
            ],
        )
        .unwrap();
        list.caller
            .invoke_resource(
                list.route.clone(),
                operation("list"),
                ResourceCall::List(nameless.clone()),
                Vec::new(),
            )
            .await
            .unwrap();
        assert_eq!(
            list.endpoint.calls.lock().unwrap()[0].1,
            Some(ResourceCall::List(nameless))
        );

        let watch_route = RouteKey::new(
            list.route.zone().clone(),
            list.route.service().clone(),
            RouteMember::method("ResourceService/Watch").unwrap(),
            list.route.target().clone(),
            list.route.schema().clone(),
            list.route.generations(),
        );
        let endpoint_context = context(
            "Provider/system-core",
            ENDPOINT_UID,
            "d2b.resource.v3",
            list.route.schema().clone(),
            list.route.generations(),
            Locality::Local,
            EvidenceClass::EnrolledKk,
        );
        list.registrar.revoke(list.endpoint_ingress).await.unwrap();
        list.endpoint_ingress = list
            .registrar
            .register(SessionRegistration::new(
                endpoint_context,
                vec![watch_route.clone()],
                list.endpoint.clone(),
            ))
            .unwrap();
        list.bus
            .replace_policy(
                policy(
                    2,
                    &list.subjects,
                    &[
                        SessionVerb::Connect,
                        SessionVerb::Invoke,
                        SessionVerb::Relay,
                    ],
                    &[ResourceVerb::Watch],
                ),
                state(2),
            )
            .unwrap();
        let named = ResourceQuery::new(
            vec![ResourceTypeName::parse("Host").unwrap()],
            vec![ResourceName::parse("system").unwrap()],
            vec![ResourceFilter::new("status.phase", vec!["Ready".to_owned()]).unwrap()],
        )
        .unwrap();
        list.caller
            .invoke_resource(
                watch_route,
                operation("watch"),
                ResourceCall::Watch(named.clone()),
                Vec::new(),
            )
            .await
            .unwrap();
        assert_eq!(
            list.endpoint.calls.lock().unwrap()[1].1,
            Some(ResourceCall::Watch(named))
        );
    }

    #[tokio::test]
    async fn policy_replacement_revokes_a_previously_authorized_route() {
        let harness = resource_harness(
            RouteMember::method("ResourceService/Get").unwrap(),
            vec![SessionVerb::Connect, SessionVerb::Invoke],
            vec![ResourceVerb::Get],
            "User/alice",
            Locality::Local,
            EvidenceClass::UnixPeer,
        );
        harness
            .caller
            .invoke_resource(
                harness.route.clone(),
                operation("before-revoke"),
                ResourceCall::Get(ResourceRef::parse("Host/system").unwrap()),
                Vec::new(),
            )
            .await
            .unwrap();
        harness
            .bus
            .replace_policy(
                policy(2, &harness.subjects, &[SessionVerb::Connect], &[]),
                state(2),
            )
            .unwrap();
        assert!(matches!(
            harness
                .caller
                .invoke_resource(
                    harness.route.clone(),
                    operation("after-revoke"),
                    ResourceCall::Get(ResourceRef::parse("Host/system").unwrap()),
                    Vec::new(),
                )
                .await,
            Err(BusError::Authorization(
                AuthorizationError::SessionVerbMissing(SessionVerb::Invoke)
            ))
        ));
        assert_eq!(harness.endpoint.call_count(), 1);
    }

    #[tokio::test]
    async fn reconnect_replaces_routes_and_refuses_the_old_generation() {
        let harness = resource_harness(
            RouteMember::method("ResourceService/Get").unwrap(),
            vec![SessionVerb::Connect, SessionVerb::Invoke],
            vec![ResourceVerb::Get],
            "User/alice",
            Locality::Local,
            EvidenceClass::UnixPeer,
        );
        let Harness {
            bus,
            mut registrar,
            caller,
            endpoint_ingress,
            endpoint,
            route,
            subjects: _,
            clock: _,
        } = harness;
        let generations = RouteGenerations::new(
            route.generations().provider(),
            route.generations().controller(),
            ReconnectGeneration::new(2).unwrap(),
        );
        let new_route = RouteKey::new(
            route.zone().clone(),
            route.service().clone(),
            route.member().clone(),
            route.target().clone(),
            route.schema().clone(),
            generations,
        );
        let new_endpoint = context(
            "Provider/system-core",
            ENDPOINT_UID,
            "d2b.resource.v3",
            route.schema().clone(),
            generations,
            Locality::Local,
            EvidenceClass::EnrolledKk,
        );
        let endpoint_ingress = registrar
            .reconnect(
                endpoint_ingress,
                SessionRegistration::new(new_endpoint, vec![new_route.clone()], endpoint.clone()),
            )
            .await
            .unwrap();
        let new_caller = context(
            "User/alice",
            CALLER_UID,
            "d2b.resource.v3",
            route.schema().clone(),
            generations,
            Locality::Local,
            EvidenceClass::UnixPeer,
        );
        let caller = registrar
            .reconnect(
                caller,
                SessionRegistration::new(new_caller, Vec::new(), endpoint.clone()),
            )
            .await
            .unwrap();
        assert_eq!(
            caller
                .invoke_resource(
                    route,
                    operation("old-generation"),
                    ResourceCall::Get(ResourceRef::parse("Host/system").unwrap()),
                    Vec::new(),
                )
                .await,
            Err(BusError::Authorization(
                AuthorizationError::SessionBindingMismatch
            ))
        );
        assert!(
            caller
                .invoke_resource(
                    new_route,
                    operation("new-generation"),
                    ResourceCall::Get(ResourceRef::parse("Host/system").unwrap()),
                    Vec::new(),
                )
                .await
                .is_ok()
        );
        drop(endpoint_ingress);
        drop(bus);
    }

    #[tokio::test]
    async fn revoke_between_resolution_and_begin_rejects_the_route_lease() {
        let harness = resource_harness(
            RouteMember::method("ResourceService/Get").unwrap(),
            vec![SessionVerb::Connect, SessionVerb::Invoke],
            vec![ResourceVerb::Get],
            "User/alice",
            Locality::Local,
            EvidenceClass::UnixPeer,
        );
        let hook = Arc::new(InvocationHook {
            reached: Notify::new(),
            release: Notify::new(),
        });
        harness
            .caller
            .core
            .invocation_hooks
            .lock()
            .unwrap()
            .after_resolve = Some(Arc::clone(&hook));
        let mut registrar = harness.registrar;
        let invoke = harness.caller.invoke_resource(
            harness.route,
            operation("revoke-before-begin"),
            ResourceCall::Get(ResourceRef::parse("Host/system").unwrap()),
            Vec::new(),
        );
        let revoke = async {
            hook.reached.notified().await;
            registrar.revoke(harness.endpoint_ingress).await.unwrap();
            hook.release.notify_one();
        };
        let (result, ()) = tokio::join!(invoke, revoke);
        assert_eq!(
            result,
            Err(BusError::Operation(OperationError::RouteRevoked))
        );
        assert_eq!(harness.endpoint.call_count(), 0);
    }

    #[tokio::test]
    async fn revoke_after_begin_cancels_before_endpoint_invocation() {
        let harness = resource_harness(
            RouteMember::method("ResourceService/Get").unwrap(),
            vec![SessionVerb::Connect, SessionVerb::Invoke],
            vec![ResourceVerb::Get],
            "User/alice",
            Locality::Local,
            EvidenceClass::UnixPeer,
        );
        let hook = Arc::new(InvocationHook {
            reached: Notify::new(),
            release: Notify::new(),
        });
        harness
            .caller
            .core
            .invocation_hooks
            .lock()
            .unwrap()
            .before_invoke = Some(Arc::clone(&hook));
        let mut registrar = harness.registrar;
        let invoke = harness.caller.invoke_resource(
            harness.route,
            operation("revoke-before-invoke"),
            ResourceCall::Get(ResourceRef::parse("Host/system").unwrap()),
            Vec::new(),
        );
        let revoke = async {
            hook.reached.notified().await;
            registrar.revoke(harness.endpoint_ingress).await.unwrap();
            hook.release.notify_one();
        };
        let (result, ()) = tokio::join!(invoke, revoke);
        assert_eq!(result, Err(BusError::Cancelled));
        assert_eq!(harness.endpoint.call_count(), 0);
        wait_for_endpoint_cancellation(&harness.endpoint).await;
    }

    #[tokio::test]
    async fn revoke_cancels_an_in_progress_endpoint_invocation() {
        let endpoint = RecordingEndpoint::blocking();
        let harness = harness(HarnessSpec {
            service: "d2b.resource.v3",
            member: RouteMember::method("ResourceService/Get").unwrap(),
            caller_ref: "User/alice",
            locality: Locality::Local,
            evidence: EvidenceClass::UnixPeer,
            session_verbs: vec![SessionVerb::Connect, SessionVerb::Invoke],
            resource_verbs: vec![ResourceVerb::Get],
            endpoint: endpoint.clone(),
        });
        let mut registrar = harness.registrar;
        let invoke = harness.caller.invoke_resource(
            harness.route,
            operation("revoke-in-progress"),
            ResourceCall::Get(ResourceRef::parse("Host/system").unwrap()),
            Vec::new(),
        );
        let revoke = async {
            endpoint.started.notified().await;
            registrar.revoke(harness.endpoint_ingress).await.unwrap();
        };
        let (result, ()) = tokio::join!(invoke, revoke);
        assert_eq!(result, Err(BusError::Cancelled));
        assert_eq!(endpoint.cancellation_count(), 1);
    }

    #[tokio::test]
    async fn reconnect_cancels_queued_and_in_progress_invocations() {
        for queued in [true, false] {
            let endpoint = RecordingEndpoint::blocking();
            let harness = harness(HarnessSpec {
                service: "d2b.resource.v3",
                member: RouteMember::method("ResourceService/Get").unwrap(),
                caller_ref: "User/alice",
                locality: Locality::Local,
                evidence: EvidenceClass::UnixPeer,
                session_verbs: vec![SessionVerb::Connect, SessionVerb::Invoke],
                resource_verbs: vec![ResourceVerb::Get],
                endpoint: endpoint.clone(),
            });
            let replacement = replacement_endpoint_registration(&harness);
            let hook = queued.then(|| {
                Arc::new(InvocationHook {
                    reached: Notify::new(),
                    release: Notify::new(),
                })
            });
            if let Some(hook) = &hook {
                harness
                    .caller
                    .core
                    .invocation_hooks
                    .lock()
                    .unwrap()
                    .before_invoke = Some(Arc::clone(hook));
            }
            let mut registrar = harness.registrar;
            let invoke = harness.caller.invoke_resource(
                harness.route,
                operation(if queued {
                    "reconnect-queued"
                } else {
                    "reconnect-in-progress"
                }),
                ResourceCall::Get(ResourceRef::parse("Host/system").unwrap()),
                Vec::new(),
            );
            let reconnect = async {
                if let Some(hook) = &hook {
                    hook.reached.notified().await;
                } else {
                    endpoint.started.notified().await;
                }
                registrar
                    .reconnect(harness.endpoint_ingress, replacement)
                    .await
                    .unwrap();
                if let Some(hook) = &hook {
                    hook.release.notify_one();
                }
            };
            let (result, ()) = tokio::join!(invoke, reconnect);
            assert_eq!(result, Err(BusError::Cancelled));
            wait_for_endpoint_cancellation(&endpoint).await;
            assert_eq!(endpoint.call_count(), usize::from(!queued));
        }
    }

    #[tokio::test]
    async fn cancellation_uses_the_pinned_reverse_route() {
        let endpoint = RecordingEndpoint::blocking();
        let harness = harness(HarnessSpec {
            service: "d2b.resource.v3",
            member: RouteMember::method("ResourceService/Get").unwrap(),
            caller_ref: "User/alice",
            locality: Locality::Local,
            evidence: EvidenceClass::UnixPeer,
            session_verbs: vec![
                SessionVerb::Connect,
                SessionVerb::Invoke,
                SessionVerb::Cancel,
            ],
            resource_verbs: vec![ResourceVerb::Get],
            endpoint: endpoint.clone(),
        });
        let id = OperationId::parse("cancel-operation").unwrap();
        let operation = OperationSpec::new(id, 100).unwrap();
        let invoke = harness.caller.invoke_resource(
            harness.route.clone(),
            operation.clone(),
            ResourceCall::Get(ResourceRef::parse("Host/system").unwrap()),
            Vec::new(),
        );
        let cancel = async {
            endpoint.started.notified().await;
            harness.caller.cancel(&operation).await
        };
        let (invoke_result, cancel_result) = tokio::join!(invoke, cancel);
        assert_eq!(invoke_result, Err(BusError::Cancelled));
        let receipt = cancel_result.unwrap();
        assert_eq!(receipt.local_outcome(), CancellationOutcome::LocalTerminal);
        assert_eq!(
            receipt.delivery_outcome().await,
            CancellationOutcome::LocallyTransmitted
        );
        assert_eq!(endpoint.cancel_count.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn cancellation_revalidates_the_attempt_after_authorization() {
        let endpoint = RecordingEndpoint::blocking();
        let harness = harness(HarnessSpec {
            service: "d2b.resource.v3",
            member: RouteMember::method("ResourceService/Get").unwrap(),
            caller_ref: "User/alice",
            locality: Locality::Local,
            evidence: EvidenceClass::UnixPeer,
            session_verbs: vec![
                SessionVerb::Connect,
                SessionVerb::Invoke,
                SessionVerb::Cancel,
            ],
            resource_verbs: vec![ResourceVerb::Get],
            endpoint: endpoint.clone(),
        });
        let hook = Arc::new(InvocationHook {
            reached: Notify::new(),
            release: Notify::new(),
        });
        harness
            .caller
            .core
            .invocation_hooks
            .lock()
            .unwrap()
            .before_cancel_transition = Some(Arc::clone(&hook));
        let id = OperationId::parse("cancel-admission-race").unwrap();
        let first_operation = OperationSpec::new(id.clone(), 100).unwrap();
        let mut first = Box::pin(harness.caller.invoke_resource(
            harness.route.clone(),
            first_operation.clone(),
            ResourceCall::Get(ResourceRef::parse("Host/system").unwrap()),
            Vec::new(),
        ));
        tokio::select! {
            result = &mut first => panic!("first attempt unexpectedly completed: {result:?}"),
            () = endpoint.started.notified() => {}
        }
        let mut cancel = Box::pin(harness.caller.cancel(&first_operation));
        tokio::select! {
            result = &mut cancel => panic!("cancel unexpectedly completed: {result:?}"),
            () = hook.reached.notified() => {}
        }

        endpoint.release.notify_one();
        assert!(first.await.is_ok());
        let mut replacement = Box::pin(harness.caller.invoke_resource(
            harness.route.clone(),
            OperationSpec::new(id.clone(), 100).unwrap(),
            ResourceCall::Get(ResourceRef::parse("Host/system").unwrap()),
            Vec::new(),
        ));
        tokio::select! {
            result = &mut replacement => {
                panic!("replacement attempt unexpectedly completed: {result:?}")
            }
            () = endpoint.started.notified() => {}
        }

        hook.release.notify_one();
        assert!(matches!(
            cancel.await,
            Err(BusError::Operation(OperationError::OperationNotFound))
        ));
        assert_eq!(endpoint.cancellation_count(), 0);
        endpoint.release.notify_one();
        assert!(replacement.await.is_ok());
    }

    #[tokio::test]
    async fn cancellation_delivery_failure_never_holds_operation_capacity() {
        let endpoint = RecordingEndpoint::failing_cancel();
        let harness = harness_with_config(
            HarnessSpec {
                service: "d2b.resource.v3",
                member: RouteMember::method("ResourceService/Get").unwrap(),
                caller_ref: "User/alice",
                locality: Locality::Local,
                evidence: EvidenceClass::UnixPeer,
                session_verbs: vec![
                    SessionVerb::Connect,
                    SessionVerb::Invoke,
                    SessionVerb::Cancel,
                ],
                resource_verbs: vec![ResourceVerb::Get],
                endpoint: endpoint.clone(),
            },
            BusConfig {
                max_operations: 1,
                max_operations_per_session: 1,
                ..BusConfig::default()
            },
        );

        for index in 0..3 {
            let id = OperationId::parse(format!("failed-cancel-{index}")).unwrap();
            let operation = OperationSpec::new(id.clone(), 100).unwrap();
            let invoke = harness.caller.invoke_resource(
                harness.route.clone(),
                operation.clone(),
                ResourceCall::Get(ResourceRef::parse("Host/system").unwrap()),
                Vec::new(),
            );
            let cancel = async {
                while endpoint.call_count() <= index {
                    tokio::task::yield_now().await;
                }
                harness.caller.cancel(&operation).await
            };
            let (invoke_result, cancel_result) = tokio::join!(invoke, cancel);
            assert_eq!(invoke_result, Err(BusError::Cancelled));
            let receipt = cancel_result.unwrap();
            assert_eq!(receipt.local_outcome(), CancellationOutcome::LocalTerminal);
            assert_eq!(
                receipt.delivery_outcome().await,
                CancellationOutcome::LocalTerminal
            );
            assert!(!endpoint.has_active_request(&id));
            assert!(!endpoint.has_response_waiter(&id));
            while endpoint.cancellation_count() <= index {
                tokio::task::yield_now().await;
            }
        }
        assert_eq!(endpoint.call_count(), 3);
        assert_eq!(endpoint.cancellation_count(), 3);
    }

    #[tokio::test]
    async fn full_cancel_delivery_pool_still_terminalizes_and_teardown_aborts_pending() {
        let endpoint = RecordingEndpoint::pending_cancel();
        let harness = harness_with_config(
            HarnessSpec {
                service: "d2b.resource.v3",
                member: RouteMember::method("ResourceService/Get").unwrap(),
                caller_ref: "User/alice",
                locality: Locality::Local,
                evidence: EvidenceClass::UnixPeer,
                session_verbs: vec![
                    SessionVerb::Connect,
                    SessionVerb::Invoke,
                    SessionVerb::Cancel,
                ],
                resource_verbs: vec![ResourceVerb::Get],
                endpoint: endpoint.clone(),
            },
            BusConfig {
                max_operations: 1,
                max_operations_per_session: 1,
                ..BusConfig::default()
            },
        );

        for index in 0..2 {
            let id = OperationId::parse(format!("pending-cancel-{index}")).unwrap();
            let operation = OperationSpec::new(id.clone(), 100).unwrap();
            let invoke = harness.caller.invoke_resource(
                harness.route.clone(),
                operation.clone(),
                ResourceCall::Get(ResourceRef::parse("Host/system").unwrap()),
                Vec::new(),
            );
            let cancel = async {
                while endpoint.call_count() <= index {
                    tokio::task::yield_now().await;
                }
                harness.caller.cancel(&operation).await
            };
            let (invoke_result, cancel_result) = tokio::join!(invoke, cancel);
            assert_eq!(invoke_result, Err(BusError::Cancelled));
            assert_eq!(
                cancel_result.unwrap().local_outcome(),
                CancellationOutcome::LocalTerminal
            );
            assert!(!endpoint.has_active_request(&id));
            assert!(!endpoint.has_response_waiter(&id));
            assert_eq!(harness.caller.core.cancel_deliveries.len(), 1);
        }

        let mut registrar = harness.registrar;
        registrar.revoke(harness.endpoint_ingress).await.unwrap();
        assert_eq!(harness.caller.core.cancel_deliveries.len(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn pending_cancel_delivery_has_a_fixed_timeout() {
        let endpoint = RecordingEndpoint::pending_cancel();
        let harness = harness_with_config(
            HarnessSpec {
                service: "d2b.resource.v3",
                member: RouteMember::method("ResourceService/Get").unwrap(),
                caller_ref: "User/alice",
                locality: Locality::Local,
                evidence: EvidenceClass::UnixPeer,
                session_verbs: vec![
                    SessionVerb::Connect,
                    SessionVerb::Invoke,
                    SessionVerb::Cancel,
                ],
                resource_verbs: vec![ResourceVerb::Get],
                endpoint: endpoint.clone(),
            },
            BusConfig {
                max_operations: 1,
                max_operations_per_session: 1,
                ..BusConfig::default()
            },
        );
        let id = OperationId::parse("timed-cancel").unwrap();
        let operation = OperationSpec::new(id, 100).unwrap();
        let invoke = harness.caller.invoke_resource(
            harness.route.clone(),
            operation.clone(),
            ResourceCall::Get(ResourceRef::parse("Host/system").unwrap()),
            Vec::new(),
        );
        let cancel = async {
            endpoint.started.notified().await;
            harness.caller.cancel(&operation).await
        };
        let (invoke_result, cancel_result) = tokio::join!(invoke, cancel);
        assert_eq!(invoke_result, Err(BusError::Cancelled));
        assert_eq!(
            cancel_result.unwrap().local_outcome(),
            CancellationOutcome::LocalTerminal
        );
        assert_eq!(harness.caller.core.cancel_deliveries.len(), 1);

        tokio::time::advance(CANCEL_DELIVERY_TIMEOUT + Duration::from_millis(1)).await;
        while harness.caller.core.cancel_deliveries.len() != 0 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn concurrent_invocations_saturate_the_operation_bound() {
        let endpoint = RecordingEndpoint::blocking();
        let harness = harness_with_config(
            HarnessSpec {
                service: "d2b.resource.v3",
                member: RouteMember::method("ResourceService/Get").unwrap(),
                caller_ref: "User/alice",
                locality: Locality::Local,
                evidence: EvidenceClass::UnixPeer,
                session_verbs: vec![SessionVerb::Connect, SessionVerb::Invoke],
                resource_verbs: vec![ResourceVerb::Get],
                endpoint: endpoint.clone(),
            },
            BusConfig {
                max_operations: 1,
                max_operations_per_session: 1,
                ..BusConfig::default()
            },
        );
        let first = harness.caller.invoke_resource(
            harness.route.clone(),
            operation("first-in-flight"),
            ResourceCall::Get(ResourceRef::parse("Host/system").unwrap()),
            Vec::new(),
        );
        let second = async {
            endpoint.started.notified().await;
            let result = harness
                .caller
                .invoke_resource(
                    harness.route.clone(),
                    operation("second-in-flight"),
                    ResourceCall::Get(ResourceRef::parse("Host/system").unwrap()),
                    Vec::new(),
                )
                .await;
            endpoint.release.notify_one();
            result
        };
        let (first_result, second_result) = tokio::join!(first, second);
        assert!(first_result.is_ok());
        assert_eq!(
            second_result,
            Err(BusError::Operation(OperationError::CapacityExceeded))
        );
        assert_eq!(endpoint.call_count(), 1);
    }

    #[tokio::test]
    async fn deadline_expires_before_endpoint_delivery() {
        let harness = resource_harness(
            RouteMember::method("ResourceService/Get").unwrap(),
            vec![SessionVerb::Connect, SessionVerb::Invoke],
            vec![ResourceVerb::Get],
            "User/alice",
            Locality::Local,
            EvidenceClass::UnixPeer,
        );
        harness.clock.advance_to(100);
        assert_eq!(
            harness
                .caller
                .invoke_resource(
                    harness.route.clone(),
                    operation("expired-before-delivery"),
                    ResourceCall::Get(ResourceRef::parse("Host/system").unwrap()),
                    Vec::new(),
                )
                .await,
            Err(BusError::Operation(OperationError::DeadlineExceeded))
        );
        assert_eq!(harness.endpoint.call_count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn active_deadline_cancels_a_hung_endpoint_and_reclaims_the_slot() {
        let endpoint = RecordingEndpoint::blocking();
        let harness = harness_with_config(
            HarnessSpec {
                service: "d2b.resource.v3",
                member: RouteMember::method("ResourceService/Get").unwrap(),
                caller_ref: "User/alice",
                locality: Locality::Local,
                evidence: EvidenceClass::UnixPeer,
                session_verbs: vec![SessionVerb::Connect, SessionVerb::Invoke],
                resource_verbs: vec![ResourceVerb::Get],
                endpoint: endpoint.clone(),
            },
            BusConfig {
                max_operations: 1,
                max_operations_per_session: 1,
                ..BusConfig::default()
            },
        );
        let result = harness
            .caller
            .invoke_resource(
                harness.route.clone(),
                OperationSpec::new(OperationId::parse("hung").unwrap(), 2).unwrap(),
                ResourceCall::Get(ResourceRef::parse("Host/system").unwrap()),
                Vec::new(),
            )
            .await;
        assert_eq!(
            result,
            Err(BusError::Operation(OperationError::DeadlineExceeded))
        );

        let second = harness.caller.invoke_resource(
            harness.route.clone(),
            OperationSpec::new(OperationId::parse("after-hung").unwrap(), 100).unwrap(),
            ResourceCall::Get(ResourceRef::parse("Host/system").unwrap()),
            Vec::new(),
        );
        let release = async {
            while endpoint.call_count() < 2 {
                tokio::task::yield_now().await;
            }
            endpoint.release.notify_one();
        };
        let (second, ()) = tokio::join!(second, release);
        assert!(second.is_ok());
    }

    #[tokio::test]
    async fn dropping_invoke_future_reclaims_capacity_and_retains_the_id_tombstone() {
        let harness = resource_harness(
            RouteMember::method("ResourceService/Get").unwrap(),
            vec![SessionVerb::Connect, SessionVerb::Invoke],
            vec![ResourceVerb::Get],
            "User/alice",
            Locality::Local,
            EvidenceClass::UnixPeer,
        );
        let hook = Arc::new(InvocationHook {
            reached: Notify::new(),
            release: Notify::new(),
        });
        harness
            .caller
            .core
            .invocation_hooks
            .lock()
            .unwrap()
            .before_invoke = Some(Arc::clone(&hook));
        let dropped_operation = operation("dropped-future");
        let mut invoke = Box::pin(harness.caller.invoke_resource(
            harness.route.clone(),
            dropped_operation.clone(),
            ResourceCall::Get(ResourceRef::parse("Host/system").unwrap()),
            Vec::new(),
        ));
        tokio::select! {
            result = &mut invoke => panic!("invoke unexpectedly completed: {result:?}"),
            () = hook.reached.notified() => {}
        }
        drop(invoke);
        harness
            .caller
            .core
            .invocation_hooks
            .lock()
            .unwrap()
            .before_invoke = None;
        while harness
            .caller
            .core
            .lock_operations()
            .cancel_admission(&dropped_operation, harness.caller.session)
            .is_ok_and(|admission| admission.is_some())
        {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            harness
                .caller
                .invoke_resource(
                    harness.route.clone(),
                    dropped_operation,
                    ResourceCall::Get(ResourceRef::parse("Host/system").unwrap()),
                    Vec::new(),
                )
                .await,
            Err(BusError::Operation(OperationError::RetainedOperationId))
        );
        assert!(
            harness
                .caller
                .invoke_resource(
                    harness.route.clone(),
                    operation("after-dropped-future"),
                    ResourceCall::Get(ResourceRef::parse("Host/system").unwrap()),
                    Vec::new(),
                )
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn oversized_endpoint_response_is_rejected_after_lease_cleanup() {
        let endpoint = RecordingEndpoint::oversized();
        let harness = harness(HarnessSpec {
            service: "d2b.resource.v3",
            member: RouteMember::method("ResourceService/Get").unwrap(),
            caller_ref: "User/alice",
            locality: Locality::Local,
            evidence: EvidenceClass::UnixPeer,
            session_verbs: vec![SessionVerb::Connect, SessionVerb::Invoke],
            resource_verbs: vec![ResourceVerb::Get],
            endpoint,
        });
        assert_eq!(
            harness
                .caller
                .invoke_resource(
                    harness.route.clone(),
                    operation("oversized-response"),
                    ResourceCall::Get(ResourceRef::parse("Host/system").unwrap()),
                    Vec::new(),
                )
                .await,
            Err(BusError::RouteShape)
        );
        assert_eq!(
            harness
                .caller
                .invoke_resource(
                    harness.route.clone(),
                    operation("oversized-response"),
                    ResourceCall::Get(ResourceRef::parse("Host/system").unwrap()),
                    Vec::new(),
                )
                .await,
            Err(BusError::RouteShape)
        );
        assert_eq!(harness.endpoint.call_count(), 2);
    }

    #[tokio::test]
    async fn bus_observer_receives_only_closed_failure_labels() {
        let observer = Arc::new(CaptureObserver::default());
        let harness = harness_with_config_and_observer(
            HarnessSpec {
                service: "d2b.resource.v3",
                member: RouteMember::method("ResourceService/Get").unwrap(),
                caller_ref: "User/alice",
                locality: Locality::Local,
                evidence: EvidenceClass::UnixPeer,
                session_verbs: vec![SessionVerb::Connect, SessionVerb::Invoke],
                resource_verbs: vec![ResourceVerb::Get],
                endpoint: RecordingEndpoint::new(),
            },
            BusConfig::default(),
            observer.clone(),
        );
        assert_eq!(
            harness
                .caller
                .invoke(
                    harness.route.clone(),
                    operation("observed-invalid-call"),
                    Vec::new(),
                )
                .await,
            Err(BusError::InvalidResourceCall)
        );
        harness
            .caller
            .core
            .observe_tombstone_eviction(TombstoneEviction::PerSource);
        harness
            .caller
            .core
            .observe_tombstone_eviction(TombstoneEviction::Global);
        assert_eq!(
            observer.0.lock().unwrap().as_slice(),
            &[
                (BusEvent::Invoke, BusFailureReason::Route),
                (
                    BusEvent::TombstoneEviction,
                    BusFailureReason::PerSourceRetention,
                ),
                (
                    BusEvent::TombstoneEviction,
                    BusFailureReason::GlobalRetention,
                ),
            ]
        );
    }

    #[test]
    fn endpoint_session_failures_preserve_actionable_details_and_closed_labels() {
        use crate::registry::EndpointFailureClass;
        use d2b_contracts_zone_session::v3::component_session::{Remediation, SessionErrorCode};

        let cases = [
            (
                SessionErrorCode::AuthenticationFailed,
                EndpointFailureClass::Authentication,
                BusFailureReason::Authentication,
                Remediation::ReEnrollPeer,
            ),
            (
                SessionErrorCode::PolicyDenied,
                EndpointFailureClass::Authorization,
                BusFailureReason::Authorization,
                Remediation::RepairConfiguration,
            ),
            (
                SessionErrorCode::GenerationMismatch,
                EndpointFailureClass::Generation,
                BusFailureReason::Generation,
                Remediation::ReplaceGeneration,
            ),
            (
                SessionErrorCode::QueueBackpressure,
                EndpointFailureClass::Backpressure,
                BusFailureReason::Backpressure,
                Remediation::ReduceLoad,
            ),
            (
                SessionErrorCode::DeadlineExpired,
                EndpointFailureClass::Deadline,
                BusFailureReason::Deadline,
                Remediation::RetryBounded,
            ),
            (
                SessionErrorCode::Cancelled,
                EndpointFailureClass::Cancellation,
                BusFailureReason::Cancelled,
                Remediation::None,
            ),
            (
                SessionErrorCode::SessionDisconnected,
                EndpointFailureClass::Transport,
                BusFailureReason::Transport,
                Remediation::RestartAgent,
            ),
            (
                SessionErrorCode::RecordMalformed,
                EndpointFailureClass::Protocol,
                BusFailureReason::Protocol,
                Remediation::RepairConfiguration,
            ),
            (
                SessionErrorCode::InternalInvariant,
                EndpointFailureClass::Internal,
                BusFailureReason::Endpoint,
                Remediation::RestartAgent,
            ),
        ];
        for (code, class, expected_label, remediation) in cases {
            let endpoint_error = EndpointError::from(d2b_session::SessionError::new(code));
            let EndpointError::Session(failure) = endpoint_error else {
                panic!("session errors preserve their endpoint failure");
            };
            assert_eq!(failure.class(), class);
            assert_eq!(failure.code(), code);
            assert_eq!(failure.remediation(), remediation);
            assert_eq!(
                BusFailureReason::from_error(&BusError::Endpoint(EndpointError::Session(failure))),
                expected_label
            );
            let display = EndpointError::Session(failure).to_string();
            assert!(display.contains(code.as_str()));
            assert!(display.contains(remediation.as_str()));
        }
        assert_eq!(
            BusFailureReason::from_error(&BusError::Operation(OperationError::RouteRevoked)),
            BusFailureReason::RouteRevoked
        );
    }

    #[tokio::test]
    async fn routed_named_stream_enforces_credit_and_preserves_watch_query() {
        let harness = resource_harness(
            RouteMember::stream("ResourceService/Watch").unwrap(),
            vec![SessionVerb::Connect, SessionVerb::OpenStream],
            vec![ResourceVerb::Watch],
            "User/alice",
            Locality::Local,
            EvidenceClass::UnixPeer,
        );
        let query = ResourceQuery::new(
            vec![ResourceTypeName::parse("Host").unwrap()],
            Vec::new(),
            vec![ResourceFilter::new("status.phase", vec!["Ready".to_owned()]).unwrap()],
        )
        .unwrap();
        let stream = harness
            .caller
            .open_resource_stream(
                harness.route.clone(),
                operation("watch-stream"),
                ResourceCall::Watch(query.clone()),
                StreamName::parse("watch:hosts").unwrap(),
                4,
            )
            .await
            .unwrap();
        assert_eq!(
            harness.endpoint.calls.lock().unwrap()[0].1,
            Some(ResourceCall::Watch(query))
        );
        stream.send(vec![1, 2, 3, 4]).await.unwrap();
        assert_eq!(
            stream.send(vec![5]).await,
            Err(BusError::Stream(StreamError::CreditExceeded))
        );
        let incoming = harness.endpoint.incoming.lock().unwrap().pop().unwrap();
        let frame = incoming.receive_next().await.unwrap();
        assert_eq!(frame.stream(), stream.name());
        assert_eq!(frame.payload(), &[1, 2, 3, 4]);
        incoming.grant(stream.name(), 1).await.unwrap();
        stream.send(vec![5]).await.unwrap();
        stream.close().await.unwrap();
    }

    #[tokio::test]
    async fn router_stream_and_disconnect_paths_emit_closed_bus_metrics() {
        let telemetry = Arc::new(RecordingTelemetry::default());
        let endpoint = RecordingEndpoint::new();
        let harness = harness_with_config_and_observer_and_metrics(
            HarnessSpec {
                service: "d2b.resource.v3",
                member: RouteMember::stream("ResourceService/Watch").unwrap(),
                caller_ref: "User/alice",
                locality: Locality::Local,
                evidence: EvidenceClass::UnixPeer,
                session_verbs: vec![SessionVerb::Connect, SessionVerb::OpenStream],
                resource_verbs: vec![ResourceVerb::Watch],
                endpoint,
            },
            BusConfig::default(),
            Arc::new(NoopBusObserver),
            telemetry.clone(),
        );
        let query = ResourceQuery::new(
            vec![ResourceTypeName::parse("Host").unwrap()],
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        let stream = harness
            .caller
            .open_resource_stream(
                harness.route.clone(),
                operation("metrics-watch"),
                ResourceCall::Watch(query),
                StreamName::parse("watch:metrics").unwrap(),
                4,
            )
            .await
            .unwrap();
        assert_eq!(
            stream.send(vec![1, 2, 3, 4, 5]).await,
            Err(BusError::Stream(StreamError::CreditExceeded))
        );
        stream.close().await.unwrap();
        let Harness {
            mut registrar,
            caller,
            endpoint_ingress,
            ..
        } = harness;
        registrar.revoke(caller).await.unwrap();
        registrar.revoke(endpoint_ingress).await.unwrap();

        assert!(telemetry.routes.load(Ordering::Relaxed) >= 1);
        assert!(telemetry.registrations.load(Ordering::Relaxed) >= 2);
        assert!(telemetry.streams.load(Ordering::Relaxed) >= 1);
        assert!(telemetry.credits.load(Ordering::Relaxed) >= 1);
        assert!(telemetry.backpressure.load(Ordering::Relaxed) >= 1);
        assert!(telemetry.disconnects.load(Ordering::Relaxed) >= 2);
    }

    #[tokio::test]
    async fn production_resource_watch_reaches_controller_over_bounded_named_stream() {
        let harness = resource_harness(
            RouteMember::stream("ResourceService/Watch").unwrap(),
            vec![SessionVerb::Connect, SessionVerb::OpenStream],
            vec![ResourceVerb::Watch],
            "User/alice",
            Locality::Local,
            EvidenceClass::UnixPeer,
        );
        let (_directory, store, issuer) = provision_watch_store().await;
        let watch_service = WatchService::new(Arc::clone(&store));
        let watch = watch_service
            .open(StoreWatchRequest {
                operation: d2b_resource_store::StoreOperationContext {
                    operation_id: "bus-watch-open".to_owned(),
                    idempotency_key: Some("bus-watch-open-key".to_owned()),
                    correlation_id: "bus-watch-open-correlation".to_owned(),
                    trace_id: None,
                    deadline_ms: 1_000,
                },
                zone: ZoneId::parse("dev").unwrap(),
                resource_types: vec![ResourceTypeName::parse("Host").unwrap()],
                resource_names: Vec::new(),
                filters: Vec::new(),
                after_revision: ZoneRevision::new(0),
                initial_credits: 4,
                projection: StoreProjection::Full,
            })
            .await
            .unwrap();
        let query = ResourceQuery::new(
            vec![ResourceTypeName::parse("Host").unwrap()],
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        let stream = harness
            .caller
            .open_resource_stream(
                harness.route.clone(),
                operation("watch-bus"),
                ResourceCall::Watch(query),
                StreamName::parse("watch:production").unwrap(),
                4 * 1024,
            )
            .await
            .unwrap();
        let incoming = harness.endpoint.incoming.lock().unwrap().pop().unwrap();
        let pump = tokio::spawn(async move {
            let mut watch = watch;
            watch.pump_to(&stream).await
        });

        let revision = commit_watch_resource(&store, &issuer).await;
        let frame = tokio::time::timeout(Duration::from_secs(1), incoming.receive_next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(frame.stream().as_str(), "watch:production");
        let payload: serde_json::Value = serde_json::from_slice(frame.payload()).unwrap();
        assert_eq!(payload["revision"].as_u64(), Some(revision.get()));
        assert_eq!(
            payload["entries"].as_array().map(Vec::len),
            Some(1),
            "the controller receives one committed change entry"
        );
        let entry = &payload["entries"][0];
        let key = ResourceKey::new(
            ZoneId::parse("dev").unwrap(),
            ResourceRef::parse(&format!(
                "{}/{}",
                entry["resource_type"].as_str().unwrap(),
                entry["resource_name"].as_str().unwrap()
            ))
            .unwrap(),
            ResourceUid::parse(entry["resource_uid"].as_str().unwrap()).unwrap(),
        );
        let queue = PendingQueue::new(4, 1);
        queue
            .push(
                QueueHint::new(
                    key,
                    revision,
                    TriggerSet::new([TriggerReason::SpecGenerationChanged]),
                    PriorityLane::Ordinary,
                    OperationContext::new(
                        "bus-controller-watch",
                        "bus-controller-watch-key",
                        "bus-controller-watch-correlation",
                        None,
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        let work = queue
            .pop_ready()
            .expect("controller consumer receives watch");
        assert_eq!(work.high_water_revision(), revision);
        assert!(
            work.reasons()
                .contains(TriggerReason::SpecGenerationChanged)
        );
        queue.finish(work.key()).unwrap();
        incoming
            .grant_frame(&frame, frame.payload().len())
            .await
            .unwrap();
        pump.abort();
        let _ = pump.await;
        tokio::task::yield_now().await;
        assert_eq!(store.watch_signals().unwrap().budget_used, 0);
    }

    #[test]
    fn debug_surfaces_redact_routes_payloads_and_identity() {
        let harness = resource_harness(
            RouteMember::method("ResourceService/Get").unwrap(),
            vec![SessionVerb::Connect, SessionVerb::Invoke],
            vec![ResourceVerb::Get],
            "User/sentinel-subject",
            Locality::Local,
            EvidenceClass::UnixPeer,
        );
        let source = harness
            .caller
            .core
            .lock_registry()
            .source(harness.caller.session)
            .unwrap();
        let subject = source.context.as_ref().unwrap().subject_ref();
        assert_eq!(subject.resource_type().as_str(), "User");
        assert_eq!(subject.name().as_str(), "sentinel-subject");
        assert_eq!(harness.route.service().as_str(), "d2b.resource.v3");
        assert_eq!(
            harness.route.target().resource_ref().name().as_str(),
            "system-core"
        );
        let rendered = format!(
            "{:?} {:?} {:?} {:?}",
            harness.bus, harness.registrar, harness.caller, harness.route
        );
        assert!(!rendered.contains("sentinel-subject"));
        assert!(!rendered.contains("system-core"));
        assert!(!rendered.contains("d2b.resource.v3"));
    }

    #[test]
    fn manual_clock_only_moves_forward() {
        let clock = ManualClock::new(7);
        clock.advance_to(3);
        assert_eq!(clock.now_tick(), 7);
        clock.advance_to(9);
        assert_eq!(clock.now_tick(), 9);
    }

    #[test]
    fn guest_local_seed_call_allows_only_approved_creates() {
        let approved = BTreeSet::from([ResourceTypeName::parse("Process").expect("Process type")]);
        let valid = ResourceCall::CommitBatch(vec![(
            ResourceRef::parse("Process/agent").expect("Process ref"),
            ResourceVerb::Create,
        )]);
        assert!(valid.validate_guest_local_seed(&approved).is_ok());

        let update = ResourceCall::CommitBatch(vec![(
            ResourceRef::parse("Process/agent").expect("Process ref"),
            ResourceVerb::UpdateSpec,
        )]);
        assert!(update.validate_guest_local_seed(&approved).is_err());
        let foreign = ResourceCall::CommitBatch(vec![(
            ResourceRef::parse("Zone/work").expect("Zone ref"),
            ResourceVerb::Create,
        )]);
        assert!(foreign.validate_guest_local_seed(&approved).is_err());
    }
}
