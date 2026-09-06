//! Async resource methods and admission ordering.

use std::{future::Future, sync::Arc};

use d2b_contracts_resource::resource_proto as wire;
use d2b_contracts_resource::v3::identity::AuthenticatedSubjectContext;
use d2b_contracts_resource::v3::process::PROCESS_RESOURCE_TYPE;
use d2b_contracts_resource::v3::{
    CanonicalJsonValue, ConfigurationGeneration, DEFAULT_LIST_PAGE_SIZE,
    DEFAULT_REQUEST_DEADLINE_MS, DEFAULT_WATCH_CREDITS, FinalizerId, MAX_BATCH_MUTATIONS,
    MAX_EXPEDITED_DEADLINE_MS, MAX_FILTER_VALUES, MAX_LIST_FILTERS, MAX_LIST_PAGE_SIZE,
    MAX_LIST_RESOURCE_TYPES, MAX_PAGE_CURSOR_BYTES, MAX_REQUEST_CANONICAL_BYTES,
    MAX_REQUEST_DEADLINE_MS, MAX_RESPONSE_CANONICAL_BYTES, MAX_WATCH_CREDITS, MAX_WATCH_FILTERS,
    MAX_WATCH_RESOURCE_TYPES, RESOURCE_ENVELOPE_DOMAIN_TAG, ResourceEnvelope, ResourceError,
    ResourceErrorKind, ResourceGeneration, ResourceName, ResourceRef, ResourceTypeName,
    ResourceUid, ZoneId, ZoneRevision, canonical_digest,
};
use d2b_core_controller::controller_assignment::{AssignmentVerb, ScopedResourceMutation};
use d2b_resource_store::{
    ExpectedRevision, ResourceMutationKind, StoreCommitResult, StoreFilter, StoreGetRequest,
    StoreInspectSchemaRequest, StoreListRequest, StoreListResult, StoreMutation,
    StoreOperationContext, StoreProjection, StoreResolveRequest, StoreWatchRequest, StoredResource,
};
use protobuf::{Message, MessageField};

use crate::{
    ResourceStoreBackend, StoreBindingError,
    authz::{
        ApiMethod, AuthorizationRequest, AuthorizationState, AuthorizationTarget, NativeAuthorizer,
        ResourceVerb, assignment_fence_for_mutation,
    },
    error::{map_store_error, map_store_error_with_revision_visibility, to_wire_error},
    store::CheckedResourceStore,
};

/// Trusted envelope created only after ComponentSession authentication.
///
/// Its authenticated subject cannot be inspected or replaced by downstream
/// callers:
///
/// ```compile_fail
/// use d2b_resource_api::TrustedRequest;
///
/// fn forge<T>(request: &TrustedRequest<T>) {
///     let _ = &request.subject;
/// }
/// ```
#[derive(Clone)]
pub struct TrustedRequest<T> {
    subject: Arc<AuthenticatedSubjectContext>,
    authorization_state: AuthorizationState,
    request: T,
}

impl<T> TrustedRequest<T> {
    /// Bind a decoded request to authenticated session and live policy state.
    pub(crate) fn from_session_capability(
        subject: Arc<AuthenticatedSubjectContext>,
        authorization_state: AuthorizationState,
        request: T,
    ) -> Self {
        Self {
            subject,
            authorization_state,
            request,
        }
    }

    pub const fn request(&self) -> &T {
        &self.request
    }
}

impl<T> core::fmt::Debug for TrustedRequest<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TrustedRequest(<redacted>)")
    }
}

/// Controller-owned upgrade dispatch seam.
pub trait UpgradeDispatcher: Send + Sync {
    fn dispatch(
        &self,
        request: AuthorizedUpgrade,
    ) -> impl Future<Output = Result<UpgradeResult, ResourceError>> + Send;
}

/// Authorized upgrade request passed to the owning controller.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizedUpgrade {
    pub operation: StoreOperationContext,
    pub zone: ZoneId,
    pub target: ResourceRef,
    pub action: UpgradeAction,
    pub recursive: bool,
    pub expected_revision: ZoneRevision,
}

impl core::fmt::Debug for AuthorizedUpgrade {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthorizedUpgrade")
            .field("action", &self.action)
            .field("recursive", &self.recursive)
            .field("operation", &"<redacted>")
            .field("zone", &"<redacted>")
            .field("target", &"<redacted>")
            .field("expected_revision", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeAction {
    Assess,
    Plan,
    Execute,
}

#[derive(Clone, PartialEq, Eq)]
pub struct UpgradeResult {
    pub resource: StoredResource,
    pub plan: Vec<d2b_resource_store::StoreResolvedIdentity>,
    pub revision: ZoneRevision,
}

impl core::fmt::Debug for UpgradeResult {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UpgradeResult")
            .field("resource", &"<redacted>")
            .field("plan_length", &self.plan.len())
            .field("revision", &"<redacted>")
            .finish()
    }
}

/// Default until the controller dispatch slice lands.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnavailableUpgradeDispatcher;

impl UpgradeDispatcher for UnavailableUpgradeDispatcher {
    async fn dispatch(&self, _request: AuthorizedUpgrade) -> Result<UpgradeResult, ResourceError> {
        Err(ResourceError::terminal(
            ResourceErrorKind::ResourceProviderUnavailable,
            "upgrade controller is unavailable",
        ))
    }
}

/// Resource API over one concrete store and one native authorization engine.
pub struct ResourceService<S, U = UnavailableUpgradeDispatcher> {
    store: CheckedResourceStore<S>,
    authorizer: Arc<NativeAuthorizer>,
    upgrade: Arc<U>,
    zone_uid: Option<ResourceUid>,
}

/// Store-derived identity and sealed authorization for one Guest lifecycle
/// effect.
pub struct GuestLifecycleAdmission {
    pub lease: crate::AuthorizationLease,
    pub guest_uid: ResourceUid,
    pub guest_generation: ResourceGeneration,
    pub provider_assignment_generation: ResourceGeneration,
}

impl core::fmt::Debug for GuestLifecycleAdmission {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("GuestLifecycleAdmission")
            .field("lease", &self.lease)
            .field("guest_uid", &"<redacted>")
            .field("guest_generation", &"<redacted>")
            .field("provider_assignment_generation", &"<redacted>")
            .finish()
    }
}

impl<S, U> core::fmt::Debug for ResourceService<S, U> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ResourceService(<redacted>)")
    }
}

impl<S, U> ResourceService<S, U> {
    pub(crate) fn checked_store(&self) -> crate::store::CheckedResourceStore<S> {
        self.store.clone()
    }

    pub(crate) fn authorizer_arc(&self) -> Arc<NativeAuthorizer> {
        Arc::clone(&self.authorizer)
    }

    pub(crate) fn zone_uid(&self) -> Option<ResourceUid> {
        self.zone_uid.clone()
    }
}

impl<S> ResourceService<S, UnavailableUpgradeDispatcher>
where
    S: ResourceStoreBackend,
{
    pub fn new(
        store: Arc<S>,
        authorizer: Arc<NativeAuthorizer>,
    ) -> Result<Self, StoreBindingError> {
        Self::new_with_zone_uid(store, authorizer, None)
    }

    /// Construct a session-scoped service over one persistent logical store.
    ///
    /// The backend must independently fence its authenticated session
    /// generation; this preserves only the store authority and seal identity.
    pub fn new_session_bound(
        store: Arc<S>,
        authorizer: Arc<NativeAuthorizer>,
    ) -> Result<Self, StoreBindingError> {
        let store_binding = authorizer.session_store_binding()?;
        Ok(Self {
            store: CheckedResourceStore::new(store, store_binding),
            authorizer,
            upgrade: Arc::new(UnavailableUpgradeDispatcher),
            zone_uid: None,
        })
    }

    /// Construct the Resource API with the immutable Zone UID supplied by the
    /// trusted Zone runtime. This identity is used only for sealed downstream
    /// authorization evidence.
    pub fn new_with_zone_uid(
        store: Arc<S>,
        authorizer: Arc<NativeAuthorizer>,
        zone_uid: Option<ResourceUid>,
    ) -> Result<Self, StoreBindingError> {
        let store_binding = authorizer.take_store_binding()?;
        Ok(Self {
            store: CheckedResourceStore::new(store, store_binding),
            authorizer,
            upgrade: Arc::new(UnavailableUpgradeDispatcher),
            zone_uid,
        })
    }
}

impl<S, U> ResourceService<S, U>
where
    S: ResourceStoreBackend,
    U: UpgradeDispatcher,
{
    /// Authenticate and authorize a Guest lifecycle operation against the
    /// current store row, returning the one-use downstream lease.
    pub async fn admit_guest_lifecycle(
        &self,
        subject: &crate::AuthenticatedSubjectContext,
        target: ResourceRef,
        operation_id: impl Into<String>,
    ) -> Result<GuestLifecycleAdmission, ResourceError> {
        if target.resource_type().as_str() != "Guest" {
            return Err(ResourceError::terminal(
                ResourceErrorKind::AuthorizationDenied,
                "Guest lifecycle target is invalid",
            ));
        }
        let operation_id = operation_id.into();
        let zone = ZoneId::parse(subject.claims().zone_ref().name().as_str()).map_err(|_| {
            ResourceError::terminal(
                ResourceErrorKind::AuthorizationDenied,
                "Guest lifecycle Zone is invalid",
            )
        })?;
        let trusted = TrustedRequest::from_session_capability(
            subject.claims().clone(),
            subject.authorization_state().clone(),
            (),
        );
        let current = self
            .store
            .get(StoreGetRequest {
                operation: runtime_operation(operation_id.clone()),
                zone: zone.clone(),
                target: target.clone(),
                expected_uid: None,
                projection: d2b_resource_store::StoreProjection::Full,
            })
            .await
            .map_err(map_store_error)?;
        if current.zone != zone || current.resource_ref != target {
            return Err(ResourceError::terminal(
                ResourceErrorKind::AuthorizationDenied,
                "Guest lifecycle identity does not match the current Zone",
            ));
        }
        let envelope = ResourceEnvelope::from_json(&current.canonical_json)
            .map_err(|_| schema_error("Guest lifecycle resource is invalid"))?;
        if envelope.resource_type().as_str() != "Guest"
            || envelope.metadata().zone() != &zone
            || envelope.metadata().uid() != &current.uid
            || envelope.metadata().generation() != current.generation
            || envelope.metadata().revision() != current.revision
            || envelope
                .digest()
                .map_err(|_| schema_error("Guest lifecycle resource digest is invalid"))?
                != current.payload_digest
        {
            return Err(ResourceError::terminal(
                ResourceErrorKind::AuthorizationDenied,
                "Guest lifecycle identity is not current",
            ));
        }
        let provider_ref = envelope
            .spec()
            .provider_ref()
            .cloned()
            .ok_or_else(|| schema_error("Guest lifecycle Provider is missing"))?;
        if provider_ref.resource_type().as_str() != "Provider" {
            return Err(schema_error("Guest lifecycle Provider is invalid"));
        }
        let provider = self
            .store
            .get(StoreGetRequest {
                operation: runtime_operation(format!("{operation_id}:provider")),
                zone: zone.clone(),
                target: provider_ref,
                expected_uid: None,
                projection: d2b_resource_store::StoreProjection::Full,
            })
            .await
            .map_err(map_store_error)?;
        if provider.zone != zone
            || provider.resource_ref.resource_type().as_str() != "Provider"
            || provider.generation.get() == 0
        {
            return Err(ResourceError::terminal(
                ResourceErrorKind::AuthorizationDenied,
                "Guest lifecycle Provider identity is not current",
            ));
        }
        let provider_envelope = ResourceEnvelope::from_json(&provider.canonical_json)
            .map_err(|_| schema_error("Guest lifecycle Provider resource is invalid"))?;
        if provider_envelope.resource_type().as_str() != "Provider"
            || provider_envelope.metadata().zone() != &zone
            || provider_envelope.metadata().uid() != &provider.uid
            || provider_envelope.metadata().generation() != provider.generation
            || provider_envelope.metadata().revision() != provider.revision
            || provider_envelope
                .digest()
                .map_err(|_| schema_error("Guest lifecycle Provider digest is invalid"))?
                != provider.payload_digest
        {
            return Err(ResourceError::terminal(
                ResourceErrorKind::AuthorizationDenied,
                "Guest lifecycle Provider identity is not current",
            ));
        }
        let grant = self.authorize(
            &trusted,
            AuthorizationRequest {
                method: ApiMethod::UpdateSpec,
                zone: zone.clone(),
                targets: vec![AuthorizationTarget {
                    resource_type: target.resource_type().clone(),
                    resource_name: Some(target.name().clone()),
                    verb: ResourceVerb::UpdateSpec,
                    subresource: None,
                    execution_ref: None,
                }],
            },
        )?;
        let zone_uid = self.zone_uid.clone().ok_or_else(|| {
            ResourceError::terminal(
                ResourceErrorKind::InternalIntegrityFailure,
                "Guest lifecycle Zone identity is unavailable",
            )
        })?;
        let lease = grant
            .issue_lifecycle_lease(
                zone_uid,
                current.uid.clone(),
                current.generation,
                provider.generation,
                operation_id,
            )
            .map_err(|_| {
                ResourceError::terminal(
                    ResourceErrorKind::InternalIntegrityFailure,
                    "Guest lifecycle lease admission failed",
                )
            })?;
        Ok(GuestLifecycleAdmission {
            lease,
            guest_uid: current.uid,
            guest_generation: current.generation,
            provider_assignment_generation: provider.generation,
        })
    }

    pub fn with_upgrade(
        store: Arc<S>,
        authorizer: Arc<NativeAuthorizer>,
        upgrade: Arc<U>,
    ) -> Result<Self, StoreBindingError> {
        let store_binding = authorizer.take_store_binding()?;
        Ok(Self {
            store: CheckedResourceStore::new(store, store_binding),
            authorizer,
            upgrade,
            zone_uid: None,
        })
    }

    /// Read one resource from the daemon-owned runtime session.
    ///
    /// This is the production adapter used by a Zone runtime that has already
    /// authenticated its fixed local controller session. It preserves the
    /// same native authorization and checked-store path as the generated RPC
    /// handlers; it does not expose the backend or a mutation seal.
    pub async fn get_runtime(
        &self,
        subject: AuthenticatedSubjectContext,
        authorization_state: AuthorizationState,
        target: ResourceRef,
        operation_id: impl Into<String>,
    ) -> Result<StoredResource, ResourceError> {
        let zone = ZoneId::parse(subject.zone_ref().name().as_str())
            .map_err(|_| ref_error("authenticated Zone is invalid"))?;
        let trusted =
            TrustedRequest::from_session_capability(Arc::new(subject), authorization_state, ());
        let identity = ParsedIdentity {
            zone: zone.clone(),
            resource_ref: target.clone(),
            uid: None,
            generation: None,
            revision: None,
        };
        let grant = self.authorize(
            &trusted,
            authorization_for_identity(ApiMethod::Get, ResourceVerb::Get, &identity),
        )?;
        let _ = grant;
        self.store
            .get(StoreGetRequest {
                operation: runtime_operation(operation_id),
                zone,
                target,
                expected_uid: None,
                projection: StoreProjection::Full,
            })
            .await
            .map_err(map_store_error)
    }

    /// List one ResourceType from the daemon-owned runtime session.
    pub async fn list_runtime(
        &self,
        subject: AuthenticatedSubjectContext,
        authorization_state: AuthorizationState,
        resource_type: ResourceTypeName,
        operation_id: impl Into<String>,
    ) -> Result<StoreListResult, ResourceError> {
        let zone = ZoneId::parse(subject.zone_ref().name().as_str())
            .map_err(|_| ref_error("authenticated Zone is invalid"))?;
        let trusted =
            TrustedRequest::from_session_capability(Arc::new(subject), authorization_state, ());
        let identity = AuthorizationRequest {
            method: ApiMethod::List,
            zone: zone.clone(),
            targets: vec![AuthorizationTarget {
                resource_type: resource_type.clone(),
                resource_name: None,
                verb: ResourceVerb::List,
                subresource: None,
                execution_ref: None,
            }],
        };
        let _ = self.authorize(&trusted, identity)?;
        self.store
            .list(StoreListRequest {
                operation: runtime_operation(operation_id),
                zone,
                resource_types: vec![resource_type],
                resource_names: Vec::new(),
                filters: Vec::new(),
                page_size: DEFAULT_LIST_PAGE_SIZE,
                cursor: None,
                projection: StoreProjection::Full,
            })
            .await
            .map_err(map_store_error)
    }
}

fn runtime_operation(operation_id: impl Into<String>) -> StoreOperationContext {
    let operation_id = operation_id.into();
    StoreOperationContext {
        operation_id: operation_id.clone(),
        idempotency_key: None,
        correlation_id: operation_id,
        trace_id: None,
        deadline_ms: DEFAULT_REQUEST_DEADLINE_MS,
    }
}

impl<S, U> ResourceService<S, U>
where
    S: ResourceStoreBackend,
    U: UpgradeDispatcher,
{
    pub async fn get(&self, trusted: TrustedRequest<wire::GetRequest>) -> wire::GetResponse {
        let identity = match parse_identity(trusted.request.target.as_ref()) {
            Ok(identity) => identity,
            Err(error) => return get_error(error),
        };
        let auth = authorization_for_identity(ApiMethod::Get, ResourceVerb::Get, &identity);
        if let Err(error) = self.authorize(&trusted, auth) {
            return get_error(error);
        }
        if let Err(error) = validate_request(&trusted.request) {
            return get_error(error);
        }
        let operation = match operation_context(
            trusted.request.meta.as_ref(),
            false,
            &trusted.authorization_state,
        ) {
            Ok(operation) => operation,
            Err(error) => return get_error(error),
        };
        let projection = match parse_projection(trusted.request.projection.as_ref()) {
            Ok(projection) => projection,
            Err(error) => return get_error(error),
        };
        match self
            .store
            .get(StoreGetRequest {
                operation,
                zone: identity.zone,
                target: identity.resource_ref,
                expected_uid: identity.uid,
                projection,
            })
            .await
        {
            Ok(resource) if resource.canonical_json.len() <= MAX_RESPONSE_CANONICAL_BYTES => {
                let mut response = wire::GetResponse::new();
                response.resource = MessageField::some(to_wire_resource(resource));
                response
            }
            Ok(_) => get_error(schema_error("resource response exceeds its byte bound")),
            Err(error) => get_error(map_store_error(error)),
        }
    }

    pub async fn list(&self, trusted: TrustedRequest<wire::ListRequest>) -> wire::ListResponse {
        let parsed = match parse_collection_request(
            &trusted.request.resource_types,
            &trusted.request.filters,
            MAX_LIST_RESOURCE_TYPES,
            MAX_LIST_FILTERS,
        ) {
            Ok(parsed) => parsed,
            Err(error) => return list_error(error),
        };
        let auth = AuthorizationRequest {
            method: ApiMethod::List,
            zone: subject_zone(&trusted),
            targets: collection_targets(&parsed, ResourceVerb::List),
        };
        if let Err(error) = self.authorize(&trusted, auth) {
            return list_error(error);
        }
        if let Err(error) = validate_request(&trusted.request) {
            return list_error(error);
        }
        let operation = match operation_context(
            trusted.request.meta.as_ref(),
            false,
            &trusted.authorization_state,
        ) {
            Ok(operation) => operation,
            Err(error) => return list_error(error),
        };
        let page_size = if trusted.request.page_size == 0 {
            DEFAULT_LIST_PAGE_SIZE
        } else {
            trusted.request.page_size
        };
        if page_size > MAX_LIST_PAGE_SIZE {
            return list_error(schema_error("page size exceeds its bound"));
        }
        let cursor = trusted
            .request
            .cursor
            .as_ref()
            .map(|cursor| cursor.value.clone())
            .filter(|cursor| !cursor.is_empty());
        if cursor
            .as_ref()
            .is_some_and(|cursor| cursor.len() > MAX_PAGE_CURSOR_BYTES)
        {
            return list_error(schema_error("page cursor exceeds its bound"));
        }
        let projection = match parse_projection(trusted.request.projection.as_ref()) {
            Ok(projection) => projection,
            Err(error) => return list_error(error),
        };
        match self
            .store
            .list(StoreListRequest {
                operation,
                zone: subject_zone(&trusted),
                resource_types: parsed.resource_types,
                resource_names: parsed.resource_names,
                filters: parsed.filters,
                page_size,
                cursor,
                projection,
            })
            .await
        {
            Ok(result) => {
                let mut response = wire::ListResponse::new();
                response.resources = result.resources.into_iter().map(to_wire_resource).collect();
                response.snapshot_revision = result.snapshot_revision.get();
                if let Some(cursor) = result.next_cursor {
                    let mut page = wire::PageCursor::new();
                    page.value = cursor;
                    response.next_cursor = MessageField::some(page);
                }
                response.truncated = result.truncated;
                if response.compute_size() as usize > MAX_RESPONSE_CANONICAL_BYTES {
                    list_error(schema_error(
                        "list store result was not truncated at the byte bound",
                    ))
                } else {
                    response
                }
            }
            Err(error) => list_error(map_store_error(error)),
        }
    }

    pub async fn watch(&self, trusted: TrustedRequest<wire::WatchRequest>) -> wire::WatchResponse {
        let parsed = match parse_collection_request(
            &trusted.request.resource_types,
            &trusted.request.filters,
            MAX_WATCH_RESOURCE_TYPES,
            MAX_WATCH_FILTERS,
        ) {
            Ok(parsed) => parsed,
            Err(error) => return watch_error(error),
        };
        let auth = AuthorizationRequest {
            method: ApiMethod::Watch,
            zone: subject_zone(&trusted),
            targets: collection_targets(&parsed, ResourceVerb::Watch),
        };
        if let Err(error) = self.authorize(&trusted, auth) {
            return watch_error(error);
        }
        if let Err(error) = validate_request(&trusted.request) {
            return watch_error(error);
        }
        let operation = match operation_context(
            trusted.request.meta.as_ref(),
            false,
            &trusted.authorization_state,
        ) {
            Ok(operation) => operation,
            Err(error) => return watch_error(error),
        };
        let credits = trusted
            .request
            .credits
            .as_ref()
            .map_or(DEFAULT_WATCH_CREDITS, |credits| credits.initial);
        if credits == 0 || credits > MAX_WATCH_CREDITS {
            return watch_error(schema_error("watch credits exceed their bound"));
        }
        let projection = match parse_projection(trusted.request.projection.as_ref()) {
            Ok(projection) => projection,
            Err(error) => return watch_error(error),
        };
        match self
            .store
            .watch(StoreWatchRequest {
                operation,
                zone: subject_zone(&trusted),
                resource_types: parsed.resource_types,
                resource_names: parsed.resource_names,
                filters: parsed.filters,
                after_revision: ZoneRevision::new(trusted.request.after_revision),
                initial_credits: credits,
                projection,
            })
            .await
        {
            Ok(receipt) => {
                let mut response = wire::WatchResponse::new();
                response.stream_name = receipt.stream_name;
                response.snapshot_revision = receipt.snapshot_revision.get();
                response
            }
            Err(error) => watch_error(map_store_error(error)),
        }
    }

    pub async fn create(
        &self,
        trusted: TrustedRequest<wire::CreateRequest>,
    ) -> wire::CreateResponse {
        match self
            .commit_one(&trusted, ApiMethod::Create, ResourceMutationKind::Create)
            .await
        {
            Ok(result) => mutation_response(result, trusted.request.mutation.as_ref(), true),
            Err(error) => create_error(error),
        }
    }

    pub async fn update_spec(
        &self,
        trusted: TrustedRequest<wire::UpdateSpecRequest>,
    ) -> wire::UpdateSpecResponse {
        match self
            .commit_one(
                &trusted,
                ApiMethod::UpdateSpec,
                ResourceMutationKind::UpdateSpec,
            )
            .await
        {
            Ok(result) => {
                let common = mutation_response(result, trusted.request.mutation.as_ref(), true);
                copy_update_spec_response(common)
            }
            Err(error) => update_spec_error(error),
        }
    }

    pub async fn update_status(
        &self,
        trusted: TrustedRequest<wire::UpdateStatusRequest>,
    ) -> wire::UpdateStatusResponse {
        match self
            .commit_one(
                &trusted,
                ApiMethod::UpdateStatus,
                ResourceMutationKind::UpdateStatus,
            )
            .await
        {
            Ok(result) => copy_update_status_response(mutation_response(
                result,
                trusted.request.mutation.as_ref(),
                false,
            )),
            Err(error) => update_status_error(error),
        }
    }

    pub async fn update_metadata(
        &self,
        trusted: TrustedRequest<wire::UpdateMetadataRequest>,
    ) -> wire::UpdateMetadataResponse {
        match self
            .commit_one(
                &trusted,
                ApiMethod::UpdateMetadata,
                ResourceMutationKind::UpdateMetadata,
            )
            .await
        {
            Ok(result) => copy_update_metadata_response(mutation_response(
                result,
                trusted.request.mutation.as_ref(),
                false,
            )),
            Err(error) => update_metadata_error(error),
        }
    }

    pub async fn update_finalizers(
        &self,
        trusted: TrustedRequest<wire::UpdateFinalizersRequest>,
    ) -> wire::UpdateFinalizersResponse {
        match self
            .commit_one(
                &trusted,
                ApiMethod::UpdateFinalizers,
                ResourceMutationKind::UpdateFinalizers,
            )
            .await
        {
            Ok(result) => copy_update_finalizers_response(mutation_response(
                result,
                trusted.request.mutation.as_ref(),
                false,
            )),
            Err(error) => update_finalizers_error(error),
        }
    }

    pub async fn delete(
        &self,
        trusted: TrustedRequest<wire::DeleteRequest>,
    ) -> wire::DeleteResponse {
        match self
            .commit_one(&trusted, ApiMethod::Delete, ResourceMutationKind::Delete)
            .await
        {
            Ok(result) => {
                let mut response = wire::DeleteResponse::new();
                response.revision = result.revision.get();
                if let Some(resource) = result.resources.into_iter().next() {
                    response.resource = MessageField::some(to_wire_identity(&resource));
                }
                if trusted
                    .request
                    .mutation
                    .as_ref()
                    .is_some_and(|mutation| mutation.wait_for_reconcile)
                {
                    response.error = MessageField::some(to_wire_error(&ResourceError::terminal(
                        ResourceErrorKind::ExpeditedReconcilePending,
                        "resource committed and reconcile remains pending",
                    )));
                }
                response
            }
            Err(error) => delete_error(error),
        }
    }

    pub async fn commit_batch(
        &self,
        trusted: TrustedRequest<wire::CommitBatchRequest>,
    ) -> wire::CommitBatchResponse {
        self.commit_batch_with_scope(trusted, None, None).await
    }

    /// Commit an integrity-verified configuration bundle from in-process Core.
    pub async fn commit_configuration_batch(
        &self,
        trusted: TrustedRequest<wire::CommitBatchRequest>,
        configuration_generation: ConfigurationGeneration,
    ) -> wire::CommitBatchResponse {
        self.commit_batch_with_scope(trusted, None, Some(configuration_generation))
            .await
    }

    pub(crate) fn invalid_commit_batch(reason: &'static str) -> wire::CommitBatchResponse {
        batch_error(schema_error(reason))
    }

    /// Commit one bus-authorized assignment batch while carrying the same
    /// lease evidence into every eligible store mutation.
    pub async fn commit_scoped_batch(
        &self,
        trusted: TrustedRequest<wire::CommitBatchRequest>,
        scoped_mutations: Vec<ScopedResourceMutation>,
    ) -> wire::CommitBatchResponse {
        self.commit_batch_with_scope(trusted, Some(scoped_mutations), None)
            .await
    }

    async fn commit_batch_with_scope(
        &self,
        trusted: TrustedRequest<wire::CommitBatchRequest>,
        scoped_mutations: Option<Vec<ScopedResourceMutation>>,
        configuration_generation: Option<ConfigurationGeneration>,
    ) -> wire::CommitBatchResponse {
        if trusted.request.mutations.is_empty() {
            return batch_error(schema_error("batch mutation count exceeds its bound"));
        }
        let routes = match trusted
            .request
            .mutations
            .iter()
            .map(|mutation| parse_mutation_route(mutation, None, &trusted))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(routes) => routes,
            Err(error) => return batch_error(error),
        };
        let batch_zone = subject_zone(&trusted);
        if routes.iter().any(|route| {
            route.identity.zone != batch_zone
                || route
                    .owner
                    .as_ref()
                    .is_some_and(|owner| owner.zone != batch_zone)
        }) {
            return batch_error(ResourceError::terminal(
                ResourceErrorKind::AuthorizationDenied,
                "batch route is outside the authenticated Zone",
            ));
        }
        let auth = AuthorizationRequest {
            method: ApiMethod::CommitBatch,
            zone: batch_zone,
            targets: routes
                .iter()
                .flat_map(|item| item.authorizations.iter().cloned())
                .collect(),
        };
        let grant = match self.authorize(&trusted, auth) {
            Ok(grant) => grant,
            Err(error) => return batch_error(error),
        };
        if let Err(error) = validate_request(&trusted.request) {
            return batch_error(error);
        }
        if trusted.request.mutations.len() > MAX_BATCH_MUTATIONS {
            return batch_error(schema_error("batch mutation count exceeds its bound"));
        }
        let mut parsed = match trusted
            .request
            .mutations
            .iter()
            .zip(&routes)
            .map(|(mutation, route)| parse_mutation(mutation, route, &trusted))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(parsed) => parsed,
            Err(error) => return batch_error(error),
        };
        if let Some(scoped_mutations) = scoped_mutations.as_deref() {
            if let Err(error) = attach_scoped_fences(&mut parsed, scoped_mutations, &routes) {
                return batch_error(error);
            }
        }
        for mutation in &mut parsed {
            mutation.store.configuration_generation = configuration_generation;
        }
        let operation = match operation_context(
            trusted.request.meta.as_ref(),
            true,
            &trusted.authorization_state,
        ) {
            Ok(operation) => operation,
            Err(error) => return batch_error(error),
        };
        let mutations = parsed.into_iter().map(|item| item.store).collect();
        let admitted = match self.zone_uid.as_ref() {
            Some(zone_uid) => grant.admit_with_zone_uid(mutations, operation, zone_uid.clone()),
            None => grant.admit(mutations, operation),
        };
        let admitted = match admitted {
            Ok(admitted) => admitted,
            Err(_) => {
                return batch_error(ResourceError::terminal(
                    ResourceErrorKind::InternalIntegrityFailure,
                    "admission-invariant-violated",
                ));
            }
        };
        match self.store.commit(admitted).await {
            Ok(result) => {
                let mut response = wire::CommitBatchResponse::new();
                response.resources = result.resources.into_iter().map(to_wire_resource).collect();
                response.revision = result.revision.get();
                if response.compute_size() as usize > MAX_RESPONSE_CANONICAL_BYTES {
                    let mut limited =
                        batch_error(schema_error("batch response exceeds its byte bound"));
                    limited.revision = response.revision;
                    limited
                } else {
                    response
                }
            }
            Err(error) => {
                let conflict_mutation_ordinal =
                    error.mutation_ordinal().map(|ordinal| ordinal.get());
                let mut response = batch_error(map_store_error_with_revision_visibility(
                    error,
                    self.can_read_revision(&trusted, &routes),
                ));
                response.conflict_mutation_ordinal = conflict_mutation_ordinal;
                response
            }
        }
    }

    pub async fn resolve_ref(
        &self,
        trusted: TrustedRequest<wire::ResolveRefRequest>,
    ) -> wire::ResolveRefResponse {
        let identity = match parse_identity(trusted.request.target.as_ref()) {
            Ok(identity) => identity,
            Err(error) => return resolve_error(error),
        };
        if let Err(error) = self.authorize(
            &trusted,
            authorization_for_identity(ApiMethod::ResolveRef, ResourceVerb::Get, &identity),
        ) {
            return resolve_error(error);
        }
        if let Err(error) = validate_request(&trusted.request) {
            return resolve_error(error);
        }
        let operation = match operation_context(
            trusted.request.meta.as_ref(),
            false,
            &trusted.authorization_state,
        ) {
            Ok(operation) => operation,
            Err(error) => return resolve_error(error),
        };
        match self
            .store
            .resolve_ref(StoreResolveRequest {
                operation,
                zone: identity.zone,
                target: identity.resource_ref,
                expected_uid: identity.uid,
            })
            .await
        {
            Ok(identity) => {
                let mut response = wire::ResolveRefResponse::new();
                response.resource = MessageField::some(to_wire_resolved_identity(identity));
                response
            }
            Err(error) => resolve_error(map_store_error(error)),
        }
    }

    pub async fn inspect_schema(
        &self,
        trusted: TrustedRequest<wire::InspectSchemaRequest>,
    ) -> wire::InspectSchemaResponse {
        let resource_type = match ResourceTypeName::parse(&trusted.request.resource_type) {
            Ok(resource_type) => resource_type,
            Err(_) => return inspect_error(ref_error("ResourceType is invalid")),
        };
        let auth = AuthorizationRequest {
            method: ApiMethod::InspectSchema,
            zone: subject_zone(&trusted),
            targets: vec![AuthorizationTarget {
                resource_type: resource_type.clone(),
                resource_name: None,
                verb: ResourceVerb::Get,
                subresource: Some("schema".to_owned()),
                execution_ref: None,
            }],
        };
        if let Err(error) = self.authorize(&trusted, auth) {
            return inspect_error(error);
        }
        if let Err(error) = validate_request(&trusted.request) {
            return inspect_error(error);
        }
        let operation = match operation_context(
            trusted.request.meta.as_ref(),
            false,
            &trusted.authorization_state,
        ) {
            Ok(operation) => operation,
            Err(error) => return inspect_error(error),
        };
        match self
            .store
            .inspect_schema(StoreInspectSchemaRequest {
                operation,
                zone: subject_zone(&trusted),
                resource_type,
            })
            .await
        {
            Ok(schema) => {
                let mut identity = wire::ResourceIdentity::new();
                identity.zone = subject_zone(&trusted).to_canonical_string();
                identity.resource_type = schema.resource_type.to_canonical_string();
                let mut body = wire::ResourceEnvelopeBytes::new();
                body.identity = MessageField::some(identity);
                body.canonical_json = schema.canonical_json;
                body.payload_digest = schema.payload_digest;
                let mut response = wire::InspectSchemaResponse::new();
                response.schema = MessageField::some(body);
                if response.compute_size() as usize > MAX_RESPONSE_CANONICAL_BYTES {
                    inspect_error(schema_error("schema response exceeds its byte bound"))
                } else {
                    response
                }
            }
            Err(error) => inspect_error(map_store_error(error)),
        }
    }

    pub async fn upgrade(
        &self,
        trusted: TrustedRequest<wire::UpgradeRequest>,
    ) -> wire::UpgradeResponse {
        let identity = match parse_identity(trusted.request.target.as_ref()) {
            Ok(identity) => identity,
            Err(error) => return upgrade_error(error),
        };
        let auth =
            authorization_for_identity(ApiMethod::Upgrade, ResourceVerb::UpdateSpec, &identity);
        if let Err(error) = self.authorize(&trusted, auth) {
            return upgrade_error(error);
        }
        if let Err(error) = validate_request(&trusted.request) {
            return upgrade_error(error);
        }
        let operation = match operation_context(
            trusted.request.meta.as_ref(),
            false,
            &trusted.authorization_state,
        ) {
            Ok(operation) => operation,
            Err(error) => return upgrade_error(error),
        };
        let expected_revision = match parse_precondition(trusted.request.precondition.as_ref()) {
            Ok(ExpectedRevision::Exact(revision)) => revision,
            _ => return upgrade_error(schema_error("upgrade requires an exact revision")),
        };
        let action = match trusted.request.action.enum_value() {
            Ok(wire::UpgradeAction::UPGRADE_ACTION_ASSESS) => UpgradeAction::Assess,
            Ok(wire::UpgradeAction::UPGRADE_ACTION_PLAN) => UpgradeAction::Plan,
            Ok(wire::UpgradeAction::UPGRADE_ACTION_EXECUTE) => UpgradeAction::Execute,
            _ => return upgrade_error(schema_error("upgrade action is unspecified")),
        };
        match self
            .upgrade
            .dispatch(AuthorizedUpgrade {
                operation,
                zone: identity.zone,
                target: identity.resource_ref,
                action,
                recursive: trusted.request.recursive,
                expected_revision,
            })
            .await
        {
            Ok(result) => {
                let mut response = wire::UpgradeResponse::new();
                response.resource = MessageField::some(to_wire_resource(result.resource));
                response.plan = result
                    .plan
                    .into_iter()
                    .map(to_wire_resolved_identity)
                    .collect();
                response.revision = result.revision.get();
                if response.compute_size() as usize > MAX_RESPONSE_CANONICAL_BYTES {
                    let mut limited =
                        upgrade_error(schema_error("upgrade response exceeds its byte bound"));
                    limited.revision = response.revision;
                    limited
                } else {
                    response
                }
            }
            Err(error) => upgrade_error(error),
        }
    }

    async fn commit_one<T>(
        &self,
        trusted: &TrustedRequest<T>,
        method: ApiMethod,
        expected_kind: ResourceMutationKind,
    ) -> Result<StoreCommitResult, ResourceError>
    where
        T: MutationRequest + StrictResourceRequest,
    {
        let mutation = trusted
            .mutation()
            .ok_or_else(|| schema_error("mutation is required"))?;
        let route = parse_mutation_route(mutation, Some(expected_kind), trusted)?;
        let grant = self.authorize(
            trusted,
            AuthorizationRequest {
                method,
                zone: route.identity.zone.clone(),
                targets: route.authorizations.clone(),
            },
        )?;
        validate_request(&trusted.request)?;
        let parsed = parse_mutation(mutation, &route, trusted)?;
        let operation = operation_context(trusted.meta(), true, &trusted.authorization_state)?;
        let admitted = match self.zone_uid.as_ref() {
            Some(zone_uid) => {
                grant.admit_with_zone_uid(vec![parsed.store], operation, zone_uid.clone())
            }
            None => grant.admit(vec![parsed.store], operation),
        }
        .map_err(|_| {
            ResourceError::terminal(
                ResourceErrorKind::InternalIntegrityFailure,
                "admission-invariant-violated",
            )
        })?;
        match self.store.commit(admitted).await {
            Ok(result) => Ok(result),
            Err(error) => Err(map_store_error_with_revision_visibility(
                error,
                self.can_read_revision(trusted, std::slice::from_ref(&route)),
            )),
        }
    }

    fn authorize<T>(
        &self,
        trusted: &TrustedRequest<T>,
        request: AuthorizationRequest,
    ) -> Result<crate::authz::AuthorizationGrant, ResourceError> {
        self.authorizer
            .authorize(&trusted.subject, &request, &trusted.authorization_state)
            .map_err(|denial| {
                ResourceError::terminal(
                    denial.resource_error_kind(),
                    // A closed reason per denial class, carrying no Zone,
                    // subject or resource value. Collapsing every class into
                    // one message left an operator unable to tell a Zone
                    // boundary rejection from an ordinary denial.
                    match denial {
                        crate::authz::AuthorizationDenial::ZoneMismatch => {
                            "zone-boundary authorization denied"
                        }
                        _ => match denial.resource_error_kind() {
                            ResourceErrorKind::RelayDenied => "relay authorization denied",
                            _ => "resource authorization denied",
                        },
                    },
                )
            })
    }

    fn can_read_revision<T>(
        &self,
        trusted: &TrustedRequest<T>,
        routes: &[ParsedMutationRoute],
    ) -> bool {
        self.authorizer
            .authorize(
                &trusted.subject,
                &AuthorizationRequest {
                    method: ApiMethod::Get,
                    zone: subject_zone(trusted),
                    targets: routes
                        .iter()
                        .map(|route| AuthorizationTarget {
                            resource_type: route.identity.resource_ref.resource_type().clone(),
                            resource_name: Some(route.identity.resource_ref.name().clone()),
                            verb: ResourceVerb::Get,
                            subresource: None,
                            execution_ref: trusted.subject.execution_ref().cloned(),
                        })
                        .collect(),
                },
                &trusted.authorization_state,
            )
            .is_ok()
    }
}

trait MutationRequest {
    fn meta(&self) -> Option<&wire::RequestMeta>;
    fn mutation(&self) -> Option<&wire::Mutation>;
}

trait StrictResourceRequest: Message {
    fn has_unknown_fields(&self) -> bool;
}

macro_rules! impl_mutation_request {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl MutationRequest for $ty {
                fn meta(&self) -> Option<&wire::RequestMeta> {
                    self.meta.as_ref()
                }

                fn mutation(&self) -> Option<&wire::Mutation> {
                    self.mutation.as_ref()
                }
            }
        )+
    };
}

impl_mutation_request!(
    wire::CreateRequest,
    wire::UpdateSpecRequest,
    wire::UpdateStatusRequest,
    wire::UpdateMetadataRequest,
    wire::UpdateFinalizersRequest,
    wire::DeleteRequest,
);

fn has_unknown<M: Message>(message: &M) -> bool {
    message
        .special_fields()
        .unknown_fields()
        .iter()
        .next()
        .is_some()
}

fn field_has_unknown<M: Message>(field: &MessageField<M>) -> bool {
    field.as_ref().is_some_and(has_unknown)
}

fn identity_has_unknown(field: &MessageField<wire::ResourceIdentity>) -> bool {
    field_has_unknown(field)
}

fn meta_has_unknown(field: &MessageField<wire::RequestMeta>) -> bool {
    field_has_unknown(field)
}

fn envelope_has_unknown(field: &MessageField<wire::ResourceEnvelopeBytes>) -> bool {
    field
        .as_ref()
        .is_some_and(|value| has_unknown(value) || identity_has_unknown(&value.identity))
}

fn mutation_has_unknown(value: &wire::Mutation) -> bool {
    has_unknown(value)
        || identity_has_unknown(&value.target)
        || field_has_unknown(&value.precondition)
        || envelope_has_unknown(&value.resource)
        || identity_has_unknown(&value.owner)
}

macro_rules! impl_strict_mutation_request {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl StrictResourceRequest for $ty {
                fn has_unknown_fields(&self) -> bool {
                    has_unknown(self)
                        || meta_has_unknown(&self.meta)
                        || self.mutation.as_ref().is_some_and(mutation_has_unknown)
                }
            }
        )+
    };
}

impl_strict_mutation_request!(
    wire::CreateRequest,
    wire::UpdateSpecRequest,
    wire::UpdateStatusRequest,
    wire::UpdateMetadataRequest,
    wire::UpdateFinalizersRequest,
    wire::DeleteRequest,
);

impl StrictResourceRequest for wire::GetRequest {
    fn has_unknown_fields(&self) -> bool {
        has_unknown(self)
            || meta_has_unknown(&self.meta)
            || identity_has_unknown(&self.target)
            || field_has_unknown(&self.projection)
    }
}

impl StrictResourceRequest for wire::ListRequest {
    fn has_unknown_fields(&self) -> bool {
        has_unknown(self)
            || meta_has_unknown(&self.meta)
            || self.filters.iter().any(has_unknown)
            || field_has_unknown(&self.cursor)
            || field_has_unknown(&self.projection)
    }
}

impl StrictResourceRequest for wire::WatchRequest {
    fn has_unknown_fields(&self) -> bool {
        has_unknown(self)
            || meta_has_unknown(&self.meta)
            || self.filters.iter().any(has_unknown)
            || field_has_unknown(&self.credits)
            || field_has_unknown(&self.projection)
    }
}

impl StrictResourceRequest for wire::CommitBatchRequest {
    fn has_unknown_fields(&self) -> bool {
        has_unknown(self)
            || meta_has_unknown(&self.meta)
            || self.mutations.iter().any(mutation_has_unknown)
    }
}

impl StrictResourceRequest for wire::ResolveRefRequest {
    fn has_unknown_fields(&self) -> bool {
        has_unknown(self) || meta_has_unknown(&self.meta) || identity_has_unknown(&self.target)
    }
}

impl StrictResourceRequest for wire::InspectSchemaRequest {
    fn has_unknown_fields(&self) -> bool {
        has_unknown(self) || meta_has_unknown(&self.meta)
    }
}

impl StrictResourceRequest for wire::UpgradeRequest {
    fn has_unknown_fields(&self) -> bool {
        has_unknown(self)
            || meta_has_unknown(&self.meta)
            || identity_has_unknown(&self.target)
            || field_has_unknown(&self.precondition)
    }
}

impl<T> TrustedRequest<T> {
    fn meta(&self) -> Option<&wire::RequestMeta>
    where
        T: MutationRequest,
    {
        self.request.meta()
    }

    fn mutation(&self) -> Option<&wire::Mutation>
    where
        T: MutationRequest,
    {
        self.request.mutation()
    }
}

struct ParsedIdentity {
    zone: ZoneId,
    resource_ref: ResourceRef,
    uid: Option<ResourceUid>,
    generation: Option<ResourceGeneration>,
    revision: Option<ZoneRevision>,
}

struct ParsedMutation {
    store: StoreMutation,
}

struct ParsedMutationRoute {
    identity: ParsedIdentity,
    owner: Option<ParsedIdentity>,
    kind: ResourceMutationKind,
    authorizations: Vec<AuthorizationTarget>,
}

fn attach_scoped_fences(
    parsed: &mut [ParsedMutation],
    scoped: &[ScopedResourceMutation],
    routes: &[ParsedMutationRoute],
) -> Result<(), ResourceError> {
    if scoped.is_empty() || scoped.len() != parsed.len() || scoped.len() != routes.len() {
        return Err(schema_error("scoped batch mutation count does not match"));
    }
    let assignment = scoped
        .first()
        .map(ScopedResourceMutation::assignment)
        .ok_or_else(|| schema_error("scoped batch assignment is missing"))?;
    for (ordinal, ((parsed, route), scoped)) in
        parsed.iter_mut().zip(routes).zip(scoped).enumerate()
    {
        if scoped.assignment() != assignment
            || scoped.target() != &route.identity.resource_ref
            || resource_mutation_kind_for_assignment(scoped.verb()) != Some(route.kind)
        {
            return Err(ResourceError::terminal(
                ResourceErrorKind::AuthorizationDenied,
                "scoped batch mutation is outside its assignment",
            ));
        }
        if let Some(scope) = scoped.scope().owner_child() {
            if route.identity.resource_ref.resource_type().as_str() != PROCESS_RESOURCE_TYPE {
                return Err(ResourceError::terminal(
                    ResourceErrorKind::AuthorizationDenied,
                    "scoped owner-child mutation is outside its owner",
                ));
            }
            if route.kind == ResourceMutationKind::Create {
                let owner = route
                    .owner
                    .as_ref()
                    .ok_or_else(|| schema_error("scoped owner-child create requires an owner"))?;
                if owner.resource_ref != *scope.owner_ref() {
                    return Err(ResourceError::terminal(
                        ResourceErrorKind::AuthorizationDenied,
                        "scoped owner-child mutation is outside its owner",
                    ));
                }
                if owner.uid.as_ref() != Some(scope.owner_uid())
                    || owner.generation != Some(scope.owner_generation())
                    || owner.revision != Some(scope.owner_revision())
                {
                    return Err(ResourceError::terminal(
                        ResourceErrorKind::AuthorizationDenied,
                        "scoped owner-child owner identity is stale",
                    ));
                }
            }
        }
        let mut fence = assignment_fence_for_mutation(scoped).map_err(|_| {
            ResourceError::terminal(
                ResourceErrorKind::InternalIntegrityFailure,
                "assignment-fence-invalid",
            )
        })?;
        // Keep the first fence at the admitted snapshot for stale-batch and
        // single-write fencing; later mutations follow the staged revision.
        if ordinal > 0 && scoped.scope().owner_child().is_none() {
            let ExpectedRevision::Exact(revision) = parsed.store.expected else {
                return Err(schema_error(
                    "scoped batch assignment requires an exact revision",
                ));
            };
            fence.resource_revision = revision;
        }
        parsed.store.assignment = Some(fence);
    }
    Ok(())
}

const fn resource_mutation_kind_for_assignment(
    verb: AssignmentVerb,
) -> Option<ResourceMutationKind> {
    match verb {
        AssignmentVerb::Create => Some(ResourceMutationKind::Create),
        AssignmentVerb::UpdateSpec => Some(ResourceMutationKind::UpdateSpec),
        AssignmentVerb::UpdateStatus => Some(ResourceMutationKind::UpdateStatus),
        AssignmentVerb::UpdateMetadata => Some(ResourceMutationKind::UpdateMetadata),
        AssignmentVerb::UpdateFinalizers => Some(ResourceMutationKind::UpdateFinalizers),
        AssignmentVerb::Delete => Some(ResourceMutationKind::Delete),
        AssignmentVerb::Get
        | AssignmentVerb::List
        | AssignmentVerb::Watch
        | AssignmentVerb::CommitBatch => None,
    }
}

impl core::fmt::Debug for ParsedIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ParsedIdentity")
            .field("zone", &"<redacted>")
            .field("resource_ref", &"<redacted>")
            .field("has_uid", &self.uid.is_some())
            .finish()
    }
}

impl core::fmt::Debug for ParsedMutation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ParsedMutation")
            .field("kind", &self.store.kind)
            .finish()
    }
}

impl core::fmt::Debug for ParsedMutationRoute {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ParsedMutationRoute")
            .field("identity", &self.identity)
            .field("has_owner", &self.owner.is_some())
            .field("kind", &self.kind)
            .field("authorization_count", &self.authorizations.len())
            .finish()
    }
}

fn parse_identity(value: Option<&wire::ResourceIdentity>) -> Result<ParsedIdentity, ResourceError> {
    let value = value.ok_or_else(|| ref_error("resource identity is required"))?;
    let zone = ZoneId::parse(&value.zone).map_err(|_| ref_error("resource Zone is invalid"))?;
    let resource_type = ResourceTypeName::parse(&value.resource_type)
        .map_err(|_| ref_error("ResourceType is invalid"))?;
    let name =
        ResourceName::parse(&value.name).map_err(|_| ref_error("resource name is invalid"))?;
    let uid = value
        .uid
        .as_ref()
        .map(|value| ResourceUid::parse(value.as_str()))
        .transpose()
        .map_err(|_| ref_error("resource UID is invalid"))?;
    let generation = value
        .generation
        .map(ResourceGeneration::new)
        .transpose()
        .map_err(|_| ref_error("resource generation is invalid"))?;
    let revision = match value.revision {
        Some(0) => return Err(ref_error("resource revision is invalid")),
        Some(revision) => Some(ZoneRevision::new(revision)),
        None => None,
    };
    Ok(ParsedIdentity {
        zone,
        resource_ref: ResourceRef::new(resource_type, name),
        uid,
        generation,
        revision,
    })
}

fn authorization_for_identity(
    method: ApiMethod,
    verb: ResourceVerb,
    identity: &ParsedIdentity,
) -> AuthorizationRequest {
    AuthorizationRequest {
        method,
        zone: identity.zone.clone(),
        targets: vec![AuthorizationTarget {
            resource_type: identity.resource_ref.resource_type().clone(),
            resource_name: Some(identity.resource_ref.name().clone()),
            verb,
            subresource: None,
            execution_ref: None,
        }],
    }
}

fn parse_mutation_route<T>(
    mutation: &wire::Mutation,
    expected_kind: Option<ResourceMutationKind>,
    trusted: &TrustedRequest<T>,
) -> Result<ParsedMutationRoute, ResourceError> {
    let identity = parse_identity(mutation.target.as_ref())?;
    let (kind, verb) = if let Some(kind) = expected_kind {
        (kind, mutation_verb(kind))
    } else {
        parse_mutation_kind(mutation)?
    };
    let owner = mutation
        .owner
        .as_ref()
        .map(|owner| parse_identity(Some(owner)))
        .transpose()?;
    let mut authorizations = vec![AuthorizationTarget {
        resource_type: identity.resource_ref.resource_type().clone(),
        resource_name: Some(identity.resource_ref.name().clone()),
        verb,
        subresource: match kind {
            ResourceMutationKind::UpdateStatus => Some("status".to_owned()),
            ResourceMutationKind::UpdateFinalizers => Some("finalizers".to_owned()),
            _ => None,
        },
        execution_ref: trusted.subject.execution_ref().cloned(),
    }];
    if identity.resource_ref.resource_type().as_str() == "Credential" {
        let subresource = match kind {
            ResourceMutationKind::Create => Some("create"),
            ResourceMutationKind::UpdateSpec => Some("update-spec"),
            ResourceMutationKind::Delete => Some("delete"),
            _ => None,
        };
        if let Some(subresource) = subresource {
            authorizations.push(AuthorizationTarget {
                resource_type: identity.resource_ref.resource_type().clone(),
                resource_name: Some(identity.resource_ref.name().clone()),
                verb: ResourceVerb::AdminCredential,
                subresource: Some(subresource.to_owned()),
                execution_ref: trusted.subject.execution_ref().cloned(),
            });
        }
    }
    if let Some(owner) = &owner {
        authorizations.push(AuthorizationTarget {
            resource_type: owner.resource_ref.resource_type().clone(),
            resource_name: Some(owner.resource_ref.name().clone()),
            verb: ResourceVerb::Get,
            subresource: Some("owner".to_owned()),
            execution_ref: trusted.subject.execution_ref().cloned(),
        });
    }
    Ok(ParsedMutationRoute {
        authorizations,
        identity,
        owner,
        kind,
    })
}

fn parse_mutation_kind(
    mutation: &wire::Mutation,
) -> Result<(ResourceMutationKind, ResourceVerb), ResourceError> {
    match mutation.kind.enum_value() {
        Ok(wire::MutationKind::MUTATION_KIND_CREATE) => {
            Ok((ResourceMutationKind::Create, ResourceVerb::Create))
        }
        Ok(wire::MutationKind::MUTATION_KIND_UPDATE_SPEC) => {
            Ok((ResourceMutationKind::UpdateSpec, ResourceVerb::UpdateSpec))
        }
        Ok(wire::MutationKind::MUTATION_KIND_UPDATE_STATUS) => Ok((
            ResourceMutationKind::UpdateStatus,
            ResourceVerb::UpdateStatus,
        )),
        Ok(wire::MutationKind::MUTATION_KIND_UPDATE_METADATA) => Ok((
            ResourceMutationKind::UpdateMetadata,
            ResourceVerb::UpdateMetadata,
        )),
        Ok(wire::MutationKind::MUTATION_KIND_UPDATE_FINALIZERS) => Ok((
            ResourceMutationKind::UpdateFinalizers,
            ResourceVerb::UpdateFinalizers,
        )),
        Ok(wire::MutationKind::MUTATION_KIND_DELETE) => {
            Ok((ResourceMutationKind::Delete, ResourceVerb::Delete))
        }
        _ => Err(schema_error("mutation kind is unspecified")),
    }
}

const fn mutation_verb(kind: ResourceMutationKind) -> ResourceVerb {
    match kind {
        ResourceMutationKind::Create => ResourceVerb::Create,
        ResourceMutationKind::UpdateSpec => ResourceVerb::UpdateSpec,
        ResourceMutationKind::UpdateStatus => ResourceVerb::UpdateStatus,
        ResourceMutationKind::UpdateMetadata => ResourceVerb::UpdateMetadata,
        ResourceMutationKind::UpdateFinalizers => ResourceVerb::UpdateFinalizers,
        ResourceMutationKind::Delete => ResourceVerb::Delete,
    }
}

fn parse_mutation<T>(
    mutation: &wire::Mutation,
    route: &ParsedMutationRoute,
    trusted: &TrustedRequest<T>,
) -> Result<ParsedMutation, ResourceError> {
    let (kind, _) = parse_mutation_kind(mutation)?;
    if route.kind != kind {
        return Err(schema_error("mutation kind does not match the API method"));
    }
    let identity = &route.identity;
    if route.owner.is_some()
        && !matches!(
            kind,
            ResourceMutationKind::Create | ResourceMutationKind::UpdateMetadata
        )
    {
        return Err(schema_error(
            "owner changes require Create or UpdateMetadata",
        ));
    }
    if route
        .owner
        .as_ref()
        .is_some_and(|owner| owner.zone != identity.zone)
    {
        return Err(ref_error("owner and resource Zones differ"));
    }
    let expected = parse_precondition(mutation.precondition.as_ref())?;
    if matches!(kind, ResourceMutationKind::Create)
        != matches!(expected, ExpectedRevision::CreateAbsent)
    {
        return Err(schema_error(
            "mutation precondition does not match its kind",
        ));
    }
    let expected_uid = mutation
        .precondition
        .as_ref()
        .and_then(|precondition| precondition.expected_uid.as_ref())
        .map(|value| ResourceUid::parse(value.as_str()))
        .transpose()
        .map_err(|_| ref_error("precondition UID is invalid"))?;
    if kind == ResourceMutationKind::Create && (identity.uid.is_some() || expected_uid.is_some()) {
        return Err(schema_error("resource UID is store-generated on create"));
    }
    if identity.uid.is_some() && expected_uid.is_some() && identity.uid != expected_uid {
        return Err(ref_error("identity and precondition UIDs differ"));
    }

    let needs_body = matches!(
        kind,
        ResourceMutationKind::Create
            | ResourceMutationKind::UpdateSpec
            | ResourceMutationKind::UpdateStatus
            | ResourceMutationKind::UpdateMetadata
    );
    let body = mutation.resource.as_ref();
    if needs_body != body.is_some() {
        return Err(schema_error("mutation body does not match its kind"));
    }
    let canonical_resource = if let Some(body) = body {
        if body.canonical_json.len()
            > d2b_contracts_resource::v3::resource::MAX_RESOURCE_ENVELOPE_BYTES
        {
            return Err(schema_error("resource envelope exceeds its byte bound"));
        }
        let body_identity = parse_identity(body.identity.as_ref())?;
        if body_identity.zone != identity.zone
            || body_identity.resource_ref != identity.resource_ref
            || (identity.uid.is_some() && body_identity.uid != identity.uid)
        {
            return Err(schema_error(
                "resource body identity does not match its target",
            ));
        }
        let (envelope, canonical_resource, payload_digest) = if kind == ResourceMutationKind::Create
        {
            parse_create_payload(&body.canonical_json)?
        } else {
            let envelope = ResourceEnvelope::from_json(&body.canonical_json)
                .map_err(|_| schema_error("resource envelope is malformed"))?;
            let canonical = envelope
                .canonical_bytes()
                .map_err(|_| schema_error("resource envelope is malformed"))?;
            let digest = envelope
                .digest()
                .map_err(|_| schema_error("resource envelope is malformed"))?;
            (envelope, canonical, digest)
        };
        if envelope.resource_type() != identity.resource_ref.resource_type()
            || envelope.metadata().name() != identity.resource_ref.name()
            || envelope.metadata().zone() != &identity.zone
            || identity
                .uid
                .as_ref()
                .is_some_and(|uid| uid != envelope.metadata().uid())
            || body.payload_digest != payload_digest
        {
            return Err(schema_error(
                "resource envelope identity or digest does not match",
            ));
        }
        if matches!(
            kind,
            ResourceMutationKind::Create | ResourceMutationKind::UpdateMetadata
        ) && route.owner.as_ref().map(|owner| &owner.resource_ref)
            != envelope.metadata().owner_ref()
        {
            return Err(schema_error("typed owner does not match resource metadata"));
        }
        Some(canonical_resource)
    } else {
        None
    };

    let mut add_finalizers = mutation
        .add_finalizers
        .iter()
        .map(FinalizerId::parse)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| schema_error("finalizer ID is invalid"))?;
    let mut remove_finalizers = mutation
        .remove_finalizers
        .iter()
        .map(FinalizerId::parse)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| schema_error("finalizer ID is invalid"))?;
    add_finalizers.sort();
    add_finalizers.dedup();
    remove_finalizers.sort();
    remove_finalizers.dedup();
    if matches!(kind, ResourceMutationKind::UpdateFinalizers) {
        if add_finalizers.is_empty() && remove_finalizers.is_empty() {
            return Err(schema_error("finalizer update is empty"));
        }
    } else if !add_finalizers.is_empty() || !remove_finalizers.is_empty() {
        return Err(schema_error("finalizers require UpdateFinalizers"));
    }

    if kind == ResourceMutationKind::UpdateStatus
        && (trusted.subject.controller_generation().is_none()
            || trusted.subject.controller_generation()
                != trusted.authorization_state.snapshot.controller_generation)
    {
        return Err(ResourceError::terminal(
            ResourceErrorKind::ResourceStatusOwnerMismatch,
            "status controller generation does not match",
        ));
    }
    if mutation.wait_for_reconcile {
        if trusted.authorization_state.snapshot.policy_revision == 0 {
            return Err(ResourceError::terminal(
                ResourceErrorKind::ExpeditedNotAuthorized,
                "expedited reconcile is disabled during bootstrap",
            ));
        }
        if !matches!(
            kind,
            ResourceMutationKind::Create
                | ResourceMutationKind::UpdateSpec
                | ResourceMutationKind::Delete
        ) {
            return Err(schema_error(
                "expedited reconcile is not valid for this mutation",
            ));
        }
        if mutation.reconcile_deadline_ms == 0
            || mutation.reconcile_deadline_ms > MAX_EXPEDITED_DEADLINE_MS
        {
            return Err(schema_error(
                "expedited reconcile deadline exceeds its bound",
            ));
        }
        let expedited_subject = trusted.subject.evidence_class()
            == d2b_contracts_resource::v3::identity::EvidenceClass::UnixPeer
            && (trusted.subject.subject_ref().resource_type().as_str() == "User"
                || trusted.subject.subject_ref().to_canonical_string() == "Provider/system-core");
        if !expedited_subject {
            return Err(ResourceError::terminal(
                ResourceErrorKind::ExpeditedNotAuthorized,
                "expedited reconcile is not authorized",
            ));
        }
    } else if mutation.reconcile_deadline_ms != 0 {
        return Err(schema_error("reconcile deadline requires expedited mode"));
    }

    Ok(ParsedMutation {
        store: StoreMutation {
            kind,
            zone: identity.zone.clone(),
            target: identity.resource_ref.clone(),
            expected,
            expected_uid: identity.uid.clone().or(expected_uid),
            owner: route.owner.as_ref().map(|owner| owner.resource_ref.clone()),
            canonical_resource,
            add_finalizers,
            remove_finalizers,
            wait_for_reconcile: mutation.wait_for_reconcile,
            reconcile_deadline_ms: mutation
                .wait_for_reconcile
                .then_some(mutation.reconcile_deadline_ms),
            configuration_generation: None,
            assignment: None,
        },
    })
}

fn parse_precondition(
    value: Option<&wire::Precondition>,
) -> Result<ExpectedRevision, ResourceError> {
    let value = value.ok_or_else(|| schema_error("precondition is required"))?;
    match value.kind.enum_value() {
        Ok(wire::PreconditionKind::PRECONDITION_KIND_CREATE_ABSENT)
            if value.expected_revision.is_none() =>
        {
            Ok(ExpectedRevision::CreateAbsent)
        }
        Ok(wire::PreconditionKind::PRECONDITION_KIND_EXACT_REVISION) => value
            .expected_revision
            .filter(|revision| *revision != 0)
            .map(|revision| ExpectedRevision::Exact(ZoneRevision::new(revision)))
            .ok_or_else(|| schema_error("exact precondition requires a nonzero revision")),
        _ => Err(schema_error(
            "precondition kind is unspecified or inconsistent",
        )),
    }
}

fn parse_create_payload(
    bytes: &[u8],
) -> Result<(ResourceEnvelope, Vec<u8>, String), ResourceError> {
    // Create admission validates with a non-authoritative placeholder; the store
    // must mint and inject the durable UID in the same transaction as insertion.
    let value = CanonicalJsonValue::parse(bytes)
        .map_err(|_| schema_error("create resource payload is malformed"))?;
    let canonical_resource = value.to_canonical_bytes();
    let mut validation_value = value;
    let CanonicalJsonValue::Object(root) = &mut validation_value else {
        return Err(schema_error("create resource payload is malformed"));
    };
    let Some(CanonicalJsonValue::Object(metadata)) = root.get_mut("metadata") else {
        return Err(schema_error("create resource metadata is required"));
    };
    if metadata.contains_key("uid") {
        return Err(schema_error(
            "create resource payload must not contain an authoritative UID",
        ));
    }
    metadata.insert(
        "uid".to_owned(),
        CanonicalJsonValue::String("00000000-0000-4000-8000-000000000000".to_owned()),
    );
    let envelope = ResourceEnvelope::from_json(&validation_value.to_canonical_bytes())
        .map_err(|_| schema_error("create resource payload is malformed"))?;
    let payload_digest = canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &canonical_resource);
    Ok((envelope, canonical_resource, payload_digest))
}

struct ParsedCollection {
    resource_types: Vec<ResourceTypeName>,
    resource_names: Vec<ResourceName>,
    filters: Vec<StoreFilter>,
}

fn collection_targets(parsed: &ParsedCollection, verb: ResourceVerb) -> Vec<AuthorizationTarget> {
    let target_count = if parsed.resource_names.is_empty() {
        parsed.resource_types.len()
    } else {
        parsed
            .resource_types
            .len()
            .checked_mul(parsed.resource_names.len())
            .expect("validated collection bounds cannot overflow")
    };
    let mut targets = Vec::with_capacity(target_count);
    for resource_type in &parsed.resource_types {
        if parsed.resource_names.is_empty() {
            targets.push(AuthorizationTarget {
                resource_type: resource_type.clone(),
                resource_name: None,
                verb,
                subresource: None,
                execution_ref: None,
            });
        } else {
            targets.extend(parsed.resource_names.iter().cloned().map(|resource_name| {
                AuthorizationTarget {
                    resource_type: resource_type.clone(),
                    resource_name: Some(resource_name),
                    verb,
                    subresource: None,
                    execution_ref: None,
                }
            }));
        }
    }
    targets
}

fn parse_collection_request(
    resource_types: &[String],
    filters: &[wire::ListFilter],
    max_resource_types: usize,
    max_filters: usize,
) -> Result<ParsedCollection, ResourceError> {
    if resource_types.is_empty() || resource_types.len() > max_resource_types {
        return Err(schema_error("ResourceType count exceeds its bound"));
    }
    let resource_types = resource_types
        .iter()
        .map(ResourceTypeName::parse)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ref_error("ResourceType is invalid"))?;
    if filters.len() > max_filters
        || filters
            .iter()
            .any(|filter| filter.values.len() > MAX_FILTER_VALUES)
    {
        return Err(schema_error("filter count exceeds its bound"));
    }
    let resource_names = filters
        .iter()
        .filter(|filter| filter.field == "metadata.name")
        .flat_map(|filter| filter.values.iter())
        .map(ResourceName::parse)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ref_error("resource-name filter is invalid"))?;
    Ok(ParsedCollection {
        resource_types,
        resource_names,
        filters: filters
            .iter()
            .map(|filter| StoreFilter {
                field: filter.field.clone(),
                values: filter.values.clone(),
            })
            .collect(),
    })
}

fn parse_projection(value: Option<&wire::Projection>) -> Result<StoreProjection, ResourceError> {
    match value.and_then(|projection| projection.kind.enum_value().ok()) {
        Some(wire::ProjectionKind::PROJECTION_KIND_FULL) => Ok(StoreProjection::Full),
        Some(wire::ProjectionKind::PROJECTION_KIND_BASE_ONLY) => Ok(StoreProjection::BaseOnly),
        Some(wire::ProjectionKind::PROJECTION_KIND_METADATA_ONLY) => {
            Ok(StoreProjection::MetadataOnly)
        }
        _ => Err(schema_error("projection is unspecified")),
    }
}

fn operation_context(
    meta: Option<&wire::RequestMeta>,
    mutation: bool,
    _state: &AuthorizationState,
) -> Result<StoreOperationContext, ResourceError> {
    let meta = meta.ok_or_else(|| schema_error("request metadata is required"))?;
    for value in [&meta.operation_id, &meta.correlation_id] {
        if !valid_id(value) {
            return Err(schema_error("operation metadata is invalid"));
        }
    }
    if mutation && !valid_id(&meta.idempotency_key) {
        return Err(schema_error("mutation idempotency key is required"));
    }
    if !meta.trace_id.is_empty() && !valid_id(&meta.trace_id) {
        return Err(schema_error("trace identity is invalid"));
    }
    let deadline_ms = if meta.deadline_ms == 0 {
        DEFAULT_REQUEST_DEADLINE_MS
    } else {
        meta.deadline_ms
    };
    if deadline_ms > MAX_REQUEST_DEADLINE_MS {
        return Err(schema_error("request deadline exceeds its bound"));
    }
    Ok(StoreOperationContext {
        operation_id: meta.operation_id.clone(),
        idempotency_key: mutation.then(|| meta.idempotency_key.clone()),
        correlation_id: meta.correlation_id.clone(),
        trace_id: (!meta.trace_id.is_empty()).then(|| meta.trace_id.clone()),
        deadline_ms,
    })
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn validate_request<T: StrictResourceRequest>(request: &T) -> Result<(), ResourceError> {
    if request.has_unknown_fields() {
        Err(schema_error("request contains unknown protobuf fields"))
    } else if request.compute_size() as usize > MAX_REQUEST_CANONICAL_BYTES {
        Err(schema_error("request exceeds its byte bound"))
    } else {
        Ok(())
    }
}

fn subject_zone<T>(trusted: &TrustedRequest<T>) -> ZoneId {
    ZoneId::parse(trusted.subject.zone_ref().name().as_str())
        .expect("authenticated Zone ref already carries a validated name")
}

fn to_wire_resource(resource: StoredResource) -> wire::ResourceEnvelopeBytes {
    let identity = to_wire_identity(&resource);
    let mut result = wire::ResourceEnvelopeBytes::new();
    result.identity = MessageField::some(identity);
    result.canonical_json = resource.canonical_json;
    result.payload_digest = resource.payload_digest;
    result
}

fn to_wire_identity(resource: &StoredResource) -> wire::ResourceIdentity {
    let mut identity = wire::ResourceIdentity::new();
    identity.zone = resource.zone.to_canonical_string();
    identity.resource_type = resource.resource_ref.resource_type().to_canonical_string();
    identity.name = resource.resource_ref.name().to_canonical_string();
    identity.uid = Some(resource.uid.as_str().to_owned());
    identity.generation = Some(resource.generation.get());
    identity.revision = Some(resource.revision.get());
    identity
}

fn to_wire_resolved_identity(
    resource: d2b_resource_store::StoreResolvedIdentity,
) -> wire::ResourceIdentity {
    let mut identity = wire::ResourceIdentity::new();
    identity.zone = resource.zone.to_canonical_string();
    identity.resource_type = resource.resource_ref.resource_type().to_canonical_string();
    identity.name = resource.resource_ref.name().to_canonical_string();
    identity.uid = Some(resource.uid.as_str().to_owned());
    identity.generation = Some(resource.generation.get());
    identity.revision = Some(resource.revision.get());
    identity
}

fn mutation_response(
    result: StoreCommitResult,
    mutation: Option<&wire::Mutation>,
    expedited_capable: bool,
) -> wire::CreateResponse {
    let mut response = wire::CreateResponse::new();
    response.revision = result.revision.get();
    if let Some(resource) = result.resources.into_iter().next() {
        response.resource = MessageField::some(to_wire_resource(resource));
    }
    if expedited_capable && mutation.is_some_and(|mutation| mutation.wait_for_reconcile) {
        response.error = MessageField::some(to_wire_error(&ResourceError::terminal(
            ResourceErrorKind::ExpeditedReconcilePending,
            "resource committed and reconcile remains pending",
        )));
    }
    response
}

fn copy_update_spec_response(value: wire::CreateResponse) -> wire::UpdateSpecResponse {
    let mut response = wire::UpdateSpecResponse::new();
    response.resource = value.resource;
    response.revision = value.revision;
    response.error = value.error;
    response.disposition = value.disposition;
    response.status_persistence = value.status_persistence;
    response.last_persisted_status_revision = value.last_persisted_status_revision;
    response.reconcile_projection = value.reconcile_projection;
    response
}

fn copy_update_status_response(value: wire::CreateResponse) -> wire::UpdateStatusResponse {
    let mut response = wire::UpdateStatusResponse::new();
    response.resource = value.resource;
    response.revision = value.revision;
    response.error = value.error;
    response
}

fn copy_update_metadata_response(value: wire::CreateResponse) -> wire::UpdateMetadataResponse {
    let mut response = wire::UpdateMetadataResponse::new();
    response.resource = value.resource;
    response.revision = value.revision;
    response.error = value.error;
    response
}

fn copy_update_finalizers_response(value: wire::CreateResponse) -> wire::UpdateFinalizersResponse {
    let mut response = wire::UpdateFinalizersResponse::new();
    response.resource = value.resource;
    response.revision = value.revision;
    response.error = value.error;
    response
}

fn schema_error(reason: &'static str) -> ResourceError {
    ResourceError::terminal(ResourceErrorKind::ResourceSchemaInvalid, reason)
}

fn ref_error(reason: &'static str) -> ResourceError {
    ResourceError::terminal(ResourceErrorKind::ResourceRefInvalid, reason)
}

macro_rules! response_error {
    ($name:ident, $ty:ty) => {
        fn $name(error: ResourceError) -> $ty {
            let mut response = <$ty>::new();
            response.error = MessageField::some(to_wire_error(&error));
            response
        }
    };
}

response_error!(get_error, wire::GetResponse);
response_error!(list_error, wire::ListResponse);
response_error!(watch_error, wire::WatchResponse);
response_error!(create_error, wire::CreateResponse);
response_error!(update_spec_error, wire::UpdateSpecResponse);
response_error!(update_status_error, wire::UpdateStatusResponse);
response_error!(update_metadata_error, wire::UpdateMetadataResponse);
response_error!(update_finalizers_error, wire::UpdateFinalizersResponse);
response_error!(delete_error, wire::DeleteResponse);
response_error!(batch_error, wire::CommitBatchResponse);
response_error!(resolve_error, wire::ResolveRefResponse);
response_error!(inspect_error, wire::InspectSchemaResponse);
response_error!(upgrade_error, wire::UpgradeResponse);

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::BTreeMap,
        sync::{
            Mutex,
            atomic::{AtomicU64, AtomicUsize, Ordering},
        },
    };

    use d2b_contracts_resource::v3::identity::{
        BindingDigest, EvidenceClass, Locality, ReconnectGeneration, ServiceName, SessionBinding,
        SessionPurpose, TranscriptHash, TransportBinding,
    };
    use d2b_contracts_resource::v3::{
        ConfigurationGeneration, ControllerGeneration, ResourceGeneration, ResourceUid,
        SchemaFingerprint, ZoneId,
    };
    use d2b_core_controller::controller_assignment::ScopedCommitTransport;
    use d2b_resource_store::mutation_seal::MutationSealAcceptor;
    use d2b_resource_store::{
        MutationOrdinal, StoreError, StoreErrorKind, StoreListResult, StoreResolvedIdentity,
        StoreSealIdentity, StoreSlot, StoreWatchReceipt, StoredSchema,
    };
    use protobuf::EnumOrUnknown;

    use crate::ResourceStoreBackend;
    use crate::authz::{
        ApiCatalog, BindingScope, BoundSubject, CompiledRole, CompiledRoleBinding, PolicyRule,
        PolicySet, RelayGrantAuthority,
    };

    const GOLDEN_HOST: &[u8] = br#"{"apiVersion":"resources.d2bus.org/v3","metadata":{"configurationGeneration":7,"createdAt":"2026-07-22T00:00:00.000Z","deletionRequestedAt":null,"finalizers":[],"generation":1,"managedBy":"configuration","name":"host-system","ownerRef":null,"revision":1,"uid":"123e4567-e89b-42d3-a456-426614174000","updatedAt":"2026-07-22T00:00:00.000Z","zone":"dev"},"spec":{"providerRef":"Provider/system-core","updatePolicy":{"disruptive":"manual","nonDisruptive":"automatic"}},"status":{"completedAt":null,"conditions":[],"lastReconciledAt":null,"observedGeneration":0,"outcome":null,"phase":"Pending","resource":{},"startedAt":null,"update":{"dependencies":{"count":0,"refs":[]},"disruption":"None","lastAssessedAt":null,"observedGeneration":0,"operationId":null,"owned":{"count":0,"refs":[]},"preserveState":true,"reasons":[],"state":"Unknown","targetGeneration":1}},"type":"Host"}"#;

    #[derive(Debug, Clone, Copy)]
    enum CommitMode {
        Success,
        Conflict,
    }

    struct FakeStore {
        debug_marker: &'static str,
        mode: Mutex<CommitMode>,
        commits: AtomicUsize,
        mutation_count: AtomicUsize,
        configuration_revision: AtomicU64,
        commit_resources: Mutex<Vec<StoredResource>>,
        schema_response: Mutex<Option<StoredSchema>>,
        last_canonical_resource: Mutex<Option<Vec<u8>>>,
        last_resource_uid: Mutex<Option<ResourceUid>>,
        last_payload_digest: Mutex<Option<String>>,
        uid_index: Mutex<BTreeMap<ResourceUid, ResourceRef>>,
        acceptor: Mutex<Option<MutationSealAcceptor>>,
    }

    impl FakeStore {
        fn new(mode: CommitMode) -> Self {
            Self {
                debug_marker: "",
                mode: Mutex::new(mode),
                commits: AtomicUsize::new(0),
                mutation_count: AtomicUsize::new(0),
                configuration_revision: AtomicU64::new(0),
                commit_resources: Mutex::new(Vec::new()),
                schema_response: Mutex::new(None),
                last_canonical_resource: Mutex::new(None),
                last_resource_uid: Mutex::new(None),
                last_payload_digest: Mutex::new(None),
                uid_index: Mutex::new(BTreeMap::new()),
                acceptor: Mutex::new(None),
            }
        }

        fn with_debug_marker(mode: CommitMode, debug_marker: &'static str) -> Self {
            Self {
                debug_marker,
                ..Self::new(mode)
            }
        }

        fn unavailable() -> StoreError {
            StoreError::new(
                StoreErrorKind::ResourcePlaneUnavailable,
                None,
                None,
                d2b_contracts_resource::v3::RetryClass::AfterDelay,
                "fake-unavailable",
            )
        }
    }

    impl ResourceStoreBackend for FakeStore {
        async fn get(&self, _request: StoreGetRequest) -> Result<StoredResource, StoreError> {
            Err(Self::unavailable())
        }

        async fn list(&self, _request: StoreListRequest) -> Result<StoreListResult, StoreError> {
            Err(Self::unavailable())
        }

        async fn watch(
            &self,
            _request: StoreWatchRequest,
        ) -> Result<StoreWatchReceipt, StoreError> {
            Err(Self::unavailable())
        }

        async fn resolve_ref(
            &self,
            _request: StoreResolveRequest,
        ) -> Result<StoreResolvedIdentity, StoreError> {
            Err(Self::unavailable())
        }

        async fn inspect_schema(
            &self,
            _request: StoreInspectSchemaRequest,
        ) -> Result<StoredSchema, StoreError> {
            self.schema_response
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(Self::unavailable)
        }

        async fn commit_verified(
            &self,
            mutation: d2b_resource_store::SealedMutation,
        ) -> Result<StoreCommitResult, StoreError> {
            let acceptor = self.acceptor.lock().unwrap();
            let Some(acceptor) = acceptor.as_ref() else {
                return Err(Self::unavailable());
            };
            let body = acceptor.open(mutation)?.into_body();
            let mutations = body.mutations;
            self.commits.fetch_add(1, Ordering::SeqCst);
            self.mutation_count.store(mutations.len(), Ordering::SeqCst);
            self.configuration_revision.store(
                body.policy_snapshot.active_configuration_revision.get(),
                Ordering::SeqCst,
            );
            let first = mutations.first();
            *self.last_canonical_resource.lock().unwrap() =
                first.and_then(|prepared| prepared.mutation().canonical_resource.clone());
            *self.last_resource_uid.lock().unwrap() =
                first.and_then(|prepared| prepared.resource_uid().cloned());
            *self.last_payload_digest.lock().unwrap() =
                first.and_then(|prepared| prepared.payload_digest().map(str::to_owned));
            match *self.mode.lock().unwrap() {
                CommitMode::Success => {
                    if let Some(prepared) = first
                        && let Some(uid) = prepared.resource_uid()
                    {
                        self.uid_index
                            .lock()
                            .unwrap()
                            .insert(uid.clone(), prepared.mutation().target.clone());
                    }
                    Ok(StoreCommitResult {
                        resources: self.commit_resources.lock().unwrap().clone(),
                        revision: ZoneRevision::new(9),
                    })
                }
                CommitMode::Conflict => Err(StoreError::batch_conflict(
                    ZoneRevision::new(8),
                    MutationOrdinal::new(u32::from(mutations.len() > 1)).unwrap(),
                    d2b_contracts_resource::v3::RetryClass::Reauthorize,
                    "revision-changed",
                )),
            }
        }
    }

    fn subject(controller_generation: Option<u64>) -> Arc<AuthenticatedSubjectContext> {
        let context = AuthenticatedSubjectContext::new(
            ResourceRef::parse("Provider/system-core").unwrap(),
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174001").unwrap(),
            ResourceRef::parse("Zone/dev").unwrap(),
            EvidenceClass::UnixPeer,
            SessionPurpose::parse("resource-api").unwrap(),
            ServiceName::parse("d2b.resource.v3").unwrap(),
            SessionBinding::new(
                SchemaFingerprint::parse(format!("sha256:{}", "1".repeat(64))).unwrap(),
                TransportBinding::new(
                    Locality::Local,
                    BindingDigest::parse(format!("sha256:{}", "2".repeat(64))).unwrap(),
                ),
                ReconnectGeneration::new(1).unwrap(),
                TranscriptHash::from_bytes([3; 32]),
            ),
        );
        Arc::new(match controller_generation {
            Some(value) => {
                context.with_controller_generation(ControllerGeneration::new(value).unwrap())
            }
            None => context,
        })
    }

    fn state(controller_generation: Option<u64>) -> AuthorizationState {
        AuthorizationState {
            snapshot: d2b_resource_store::PolicySnapshot {
                policy_revision: 4,
                api_catalog_revision: 5,
                active_configuration_revision: ConfigurationGeneration::new(6).unwrap(),
                controller_generation: controller_generation
                    .map(|value| ControllerGeneration::new(value).unwrap()),
            },
            zone_policy_revision: ZoneRevision::new(7),
            bootstrap_phase: crate::authz::BootstrapPhase::Disabled,
            now_tick: 1,
        }
    }

    fn authorizer(verbs: impl IntoIterator<Item = ResourceVerb>) -> Arc<NativeAuthorizer> {
        let context = subject(None);
        let catalog = ApiCatalog::standard();
        let verbs = verbs.into_iter().collect::<Vec<_>>();
        let subresources = if verbs.contains(&ResourceVerb::UpdateStatus) {
            vec!["status".to_owned()]
        } else if verbs.contains(&ResourceVerb::UpdateFinalizers) {
            vec!["finalizers".to_owned()]
        } else {
            Vec::new()
        };
        let role = CompiledRole::new(
            ResourceRef::parse("Role/test").unwrap(),
            vec![
                PolicyRule::new(
                    &catalog,
                    [ResourceTypeName::parse("Host").unwrap()],
                    verbs,
                    [],
                    subresources,
                    [ResourceName::parse("host-system").unwrap()],
                    [ZoneId::parse("dev").unwrap()],
                    [],
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let binding = CompiledRoleBinding::new(
            role.role_ref.clone(),
            [BoundSubject {
                subject_ref: context.subject_ref().clone(),
                subject_uid: context.subject_uid().clone(),
            }],
            BindingScope::default(),
            RelayGrantAuthority::None,
        )
        .unwrap();
        let authorizer = NativeAuthorizer::new(
            catalog.clone(),
            Some(PolicySet::new(&catalog, 4, vec![role], vec![binding]).unwrap()),
        )
        .unwrap();
        Arc::new(authorizer)
    }

    fn authorizer_for_subresource(verb: ResourceVerb, subresource: &str) -> Arc<NativeAuthorizer> {
        let context = subject(None);
        let catalog = ApiCatalog::standard();
        let role = CompiledRole::new(
            ResourceRef::parse("Role/test").unwrap(),
            vec![
                PolicyRule::new(
                    &catalog,
                    [ResourceTypeName::parse("Host").unwrap()],
                    [verb],
                    [],
                    [subresource.to_owned()],
                    [],
                    [ZoneId::parse("dev").unwrap()],
                    [],
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let binding = CompiledRoleBinding::new(
            role.role_ref.clone(),
            [BoundSubject {
                subject_ref: context.subject_ref().clone(),
                subject_uid: context.subject_uid().clone(),
            }],
            BindingScope::default(),
            RelayGrantAuthority::None,
        )
        .unwrap();
        let authorizer = NativeAuthorizer::new(
            catalog.clone(),
            Some(PolicySet::new(&catalog, 4, vec![role], vec![binding]).unwrap()),
        )
        .unwrap();
        Arc::new(authorizer)
    }

    fn test_store_identity() -> StoreSealIdentity {
        StoreSealIdentity::new(
            StoreSlot::new(0).unwrap(),
            ZoneId::parse("dev").unwrap(),
            ResourceUid::parse("11111111-1111-4111-8111-111111111111").unwrap(),
        )
    }

    fn checked_service(
        store: Arc<FakeStore>,
        authorizer: Arc<NativeAuthorizer>,
    ) -> ResourceService<FakeStore> {
        let acceptor = authorizer
            .take_store_seal(test_store_identity())
            .expect("test authorizer receives a store seal");
        *store.acceptor.lock().unwrap() = Some(acceptor);
        ResourceService::new(store, authorizer).unwrap()
    }

    fn checked_service_with_upgrade<U: UpgradeDispatcher + 'static>(
        store: Arc<FakeStore>,
        authorizer: Arc<NativeAuthorizer>,
        upgrade: Arc<U>,
    ) -> ResourceService<FakeStore, U> {
        let acceptor = authorizer
            .take_store_seal(test_store_identity())
            .expect("test authorizer receives a store seal");
        *store.acceptor.lock().unwrap() = Some(acceptor);
        ResourceService::with_upgrade(store, authorizer, upgrade).unwrap()
    }

    fn request_meta() -> MessageField<wire::RequestMeta> {
        let mut meta = wire::RequestMeta::new();
        meta.operation_id = "operation-1".to_owned();
        meta.idempotency_key = "idempotency-1".to_owned();
        meta.correlation_id = "correlation-1".to_owned();
        MessageField::some(meta)
    }

    fn identity() -> MessageField<wire::ResourceIdentity> {
        let mut identity = wire::ResourceIdentity::new();
        identity.zone = "dev".to_owned();
        identity.resource_type = "Host".to_owned();
        identity.name = "host-system".to_owned();
        MessageField::some(identity)
    }

    fn mutation(kind: wire::MutationKind) -> wire::Mutation {
        let mut mutation = wire::Mutation::new();
        mutation.kind = EnumOrUnknown::new(kind);
        mutation.target = identity();
        let mut precondition = wire::Precondition::new();
        if kind == wire::MutationKind::MUTATION_KIND_CREATE {
            precondition.kind =
                EnumOrUnknown::new(wire::PreconditionKind::PRECONDITION_KIND_CREATE_ABSENT);
        } else {
            precondition.kind =
                EnumOrUnknown::new(wire::PreconditionKind::PRECONDITION_KIND_EXACT_REVISION);
            precondition.expected_revision = Some(1);
        }
        mutation.precondition = MessageField::some(precondition);
        mutation
    }

    fn body(bytes: Vec<u8>) -> MessageField<wire::ResourceEnvelopeBytes> {
        let envelope = ResourceEnvelope::from_json(GOLDEN_HOST).unwrap();
        let mut body = wire::ResourceEnvelopeBytes::new();
        body.identity = identity();
        body.payload_digest = envelope.digest().unwrap();
        body.canonical_json = bytes;
        MessageField::some(body)
    }

    fn create_payload() -> Vec<u8> {
        let mut value = CanonicalJsonValue::parse(GOLDEN_HOST).unwrap();
        let CanonicalJsonValue::Object(root) = &mut value else {
            unreachable!()
        };
        let Some(CanonicalJsonValue::Object(metadata)) = root.get_mut("metadata") else {
            unreachable!()
        };
        metadata.remove("uid");
        value.to_canonical_bytes()
    }

    fn create_body(bytes: Vec<u8>) -> MessageField<wire::ResourceEnvelopeBytes> {
        let canonical = CanonicalJsonValue::parse(&bytes)
            .unwrap()
            .to_canonical_bytes();
        let mut body = wire::ResourceEnvelopeBytes::new();
        body.identity = identity();
        body.payload_digest = canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &canonical);
        body.canonical_json = bytes;
        MessageField::some(body)
    }

    fn stored_resource(bytes: usize) -> StoredResource {
        StoredResource {
            resource_ref: ResourceRef::parse("Host/host-system").unwrap(),
            zone: ZoneId::parse("dev").unwrap(),
            uid: ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap(),
            owner_uid: None,
            owner_generation: None,
            generation: ResourceGeneration::new(1).unwrap(),
            revision: ZoneRevision::new(9),
            canonical_json: vec![b'x'; bytes],
            payload_digest: format!("sha256:{}", "1".repeat(64)),
        }
    }

    fn trusted<T>(request: T, controller_generation: Option<u64>) -> TrustedRequest<T> {
        TrustedRequest::from_session_capability(
            subject(controller_generation),
            state(controller_generation),
            request,
        )
    }

    fn error_kind(error: &MessageField<wire::ResourceError>) -> wire::ResourceErrorKind {
        error.as_ref().unwrap().kind.enum_value().unwrap()
    }

    #[test]
    fn two_backends_cannot_share_both_admission_tokens() {
        let authorizer = authorizer([]);
        let first = checked_service(
            Arc::new(FakeStore::new(CommitMode::Success)),
            Arc::clone(&authorizer),
        );

        let second =
            ResourceService::new(Arc::new(FakeStore::new(CommitMode::Success)), authorizer);

        assert_eq!(second.unwrap_err(), StoreBindingError);
        drop(first);
    }

    #[test]
    fn service_new_rejects_an_authorizer_that_issued_no_seal() {
        let authorizer = Arc::new(NativeAuthorizer::new(ApiCatalog::standard(), None).unwrap());
        let result =
            ResourceService::new(Arc::new(FakeStore::new(CommitMode::Success)), authorizer);

        assert_eq!(result.unwrap_err(), StoreBindingError);
    }

    #[tokio::test]
    async fn native_authorization_precedes_body_validation() {
        let store = Arc::new(FakeStore::new(CommitMode::Success));
        let service = checked_service(Arc::clone(&store), authorizer([]));
        let mut request = wire::CreateRequest::new();
        request.meta = request_meta();
        let mut value = mutation(wire::MutationKind::MUTATION_KIND_CREATE);
        value.resource = body(b"{}".to_vec());
        request.mutation = MessageField::some(value);

        let response = service.create(trusted(request, None)).await;
        assert_eq!(
            error_kind(&response.error),
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_AUTHORIZATION_DENIED
        );
        assert_eq!(store.commits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn owner_reference_requires_an_independent_read_grant() {
        let store = Arc::new(FakeStore::new(CommitMode::Success));
        let service = checked_service(Arc::clone(&store), authorizer([ResourceVerb::Create]));
        let mut request = wire::CreateRequest::new();
        request.meta = request_meta();
        let mut value = mutation(wire::MutationKind::MUTATION_KIND_CREATE);
        value.resource = create_body(create_payload());
        let mut owner = wire::ResourceIdentity::new();
        owner.zone = "dev".to_owned();
        owner.resource_type = "Provider".to_owned();
        owner.name = "system-core".to_owned();
        value.owner = MessageField::some(owner);
        request.mutation = MessageField::some(value);

        let response = service.create(trusted(request, None)).await;
        assert_eq!(
            error_kind(&response.error),
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_AUTHORIZATION_DENIED
        );
        assert_eq!(store.commits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn malformed_and_oversize_envelopes_never_reach_the_store() {
        let store = Arc::new(FakeStore::new(CommitMode::Success));
        let service = checked_service(Arc::clone(&store), authorizer([ResourceVerb::Create]));
        for bytes in [
            b"{}".to_vec(),
            vec![b'x'; d2b_contracts_resource::v3::resource::MAX_RESOURCE_ENVELOPE_BYTES + 1],
        ] {
            let mut request = wire::CreateRequest::new();
            request.meta = request_meta();
            let mut value = mutation(wire::MutationKind::MUTATION_KIND_CREATE);
            value.resource = body(bytes);
            request.mutation = MessageField::some(value);
            let response = service.create(trusted(request, None)).await;
            assert_eq!(
                error_kind(&response.error),
                wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_SCHEMA_INVALID
            );
        }
        assert_eq!(store.commits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn store_receives_canonical_create_body_without_uid_or_fake_index_entry() {
        let store = Arc::new(FakeStore::new(CommitMode::Success));
        let service = checked_service(Arc::clone(&store), authorizer([ResourceVerb::Create]));
        let mut request = wire::CreateRequest::new();
        request.meta = request_meta();
        let mut value = mutation(wire::MutationKind::MUTATION_KIND_CREATE);
        let canonical_create = create_payload();
        let mut noncanonical = b"\n  ".to_vec();
        noncanonical.extend_from_slice(&canonical_create);
        noncanonical.push(b'\n');
        value.resource = create_body(noncanonical);
        request.mutation = MessageField::some(value);

        let response = service.create(trusted(request, None)).await;

        assert!(response.error.is_none());
        let stored = store
            .last_canonical_resource
            .lock()
            .unwrap()
            .clone()
            .expect("store received canonical bytes");
        assert_eq!(stored, canonical_create);
        let value = CanonicalJsonValue::parse(&stored).unwrap();
        let CanonicalJsonValue::Object(root) = value else {
            panic!("store received a non-object resource body");
        };
        let Some(CanonicalJsonValue::Object(metadata)) = root.get("metadata") else {
            panic!("store received a resource body without metadata");
        };
        assert!(!metadata.contains_key("uid"));
        assert!(store.last_resource_uid.lock().unwrap().is_none());
        let expected_digest = canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &canonical_create);
        assert_eq!(
            store.last_payload_digest.lock().unwrap().as_deref(),
            Some(expected_digest.as_str())
        );
        assert!(store.uid_index.lock().unwrap().is_empty());
        assert_eq!(store.commits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn create_rejects_every_caller_supplied_uid_field() {
        let store = Arc::new(FakeStore::new(CommitMode::Success));
        let service = checked_service(Arc::clone(&store), authorizer([ResourceVerb::Create]));
        for uid_location in 0..3 {
            let mut request = wire::CreateRequest::new();
            request.meta = request_meta();
            let mut value = mutation(wire::MutationKind::MUTATION_KIND_CREATE);
            value.resource = create_body(create_payload());
            if uid_location == 0 {
                value.target.mut_or_insert_default().uid =
                    Some("123e4567-e89b-42d3-a456-426614174000".to_owned());
            } else if uid_location == 1 {
                value.precondition.mut_or_insert_default().expected_uid =
                    Some("123e4567-e89b-42d3-a456-426614174000".to_owned());
            } else {
                value.resource = body(GOLDEN_HOST.to_vec());
            }
            request.mutation = MessageField::some(value);
            let response = service.create(trusted(request, None)).await;
            assert_eq!(
                error_kind(&response.error),
                wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_SCHEMA_INVALID
            );
        }
        assert_eq!(store.commits.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn expedited_reconcile_is_rejected_in_both_bootstrap_phases() {
        let phases = [
            crate::authz::BootstrapPhase::Unprovisioned {
                zone: ZoneId::parse("dev").unwrap(),
                controller_generation: ControllerGeneration::new(11).unwrap(),
                provider_generation: ResourceGeneration::new(12).unwrap(),
            },
            crate::authz::BootstrapPhase::Provisioned {
                zone: ZoneId::parse("dev").unwrap(),
                system_core_uid: ResourceUid::parse("123e4567-e89b-42d3-a456-426614174001")
                    .unwrap(),
                system_minijail_uid: ResourceUid::parse("123e4567-e89b-42d3-a456-426614174002")
                    .unwrap(),
                controller_generation: ControllerGeneration::new(11).unwrap(),
                provider_generation: ResourceGeneration::new(12).unwrap(),
            },
        ];

        for phase in phases {
            let mut authorization_state = state(None);
            authorization_state.snapshot.policy_revision = 0;
            authorization_state.bootstrap_phase = phase;
            let mut value = mutation(wire::MutationKind::MUTATION_KIND_CREATE);
            value.resource = create_body(create_payload());
            value.wait_for_reconcile = true;
            value.reconcile_deadline_ms = 1;
            let trusted =
                TrustedRequest::from_session_capability(subject(None), authorization_state, ());
            let route =
                parse_mutation_route(&value, Some(ResourceMutationKind::Create), &trusted).unwrap();

            let error = parse_mutation(&value, &route, &trusted).unwrap_err();
            assert_eq!(error.kind(), ResourceErrorKind::ExpeditedNotAuthorized);
        }
    }

    #[tokio::test]
    async fn unknown_protobuf_fields_are_rejected_after_authorization() {
        let store = Arc::new(FakeStore::new(CommitMode::Success));
        let service = checked_service(Arc::clone(&store), authorizer([ResourceVerb::Create]));
        let mut request = wire::CreateRequest::parse_from_bytes(&[0x98, 0x06, 0x01]).unwrap();
        request.meta = request_meta();
        let mut value = mutation(wire::MutationKind::MUTATION_KIND_CREATE);
        value.resource = create_body(create_payload());
        request.mutation = MessageField::some(value);

        let response = service.create(trusted(request, None)).await;
        assert_eq!(
            error_kind(&response.error),
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_SCHEMA_INVALID
        );
        assert_eq!(store.commits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn conflict_returns_only_safe_revision_metadata() {
        let store = Arc::new(FakeStore::new(CommitMode::Conflict));
        let service = checked_service(
            Arc::clone(&store),
            authorizer([ResourceVerb::Create, ResourceVerb::Get]),
        );
        let mut request = wire::CreateRequest::new();
        request.meta = request_meta();
        let mut value = mutation(wire::MutationKind::MUTATION_KIND_CREATE);
        value.resource = create_body(create_payload());
        request.mutation = MessageField::some(value);

        let response = service.create(trusted(request, None)).await;
        let error = response.error.as_ref().unwrap();
        assert_eq!(
            error.kind.enum_value().unwrap(),
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_CONFLICT
        );
        assert_eq!(error.current_revision, Some(8));
        assert!(response.resource.is_none());
    }

    #[tokio::test]
    async fn conflict_hides_revision_without_read_authority() {
        let store = Arc::new(FakeStore::new(CommitMode::Conflict));
        let service = checked_service(Arc::clone(&store), authorizer([ResourceVerb::Create]));
        let mut request = wire::CreateRequest::new();
        request.meta = request_meta();
        let mut value = mutation(wire::MutationKind::MUTATION_KIND_CREATE);
        value.resource = create_body(create_payload());
        request.mutation = MessageField::some(value);

        let response = service.create(trusted(request, None)).await;
        let error = response.error.as_ref().unwrap();
        assert_eq!(
            error.kind.enum_value().unwrap(),
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_CONFLICT
        );
        assert_eq!(error.current_revision, None);
        assert!(response.resource.is_none());
    }

    #[tokio::test]
    async fn batch_conflict_reports_the_stale_mutation_ordinal() {
        let store = Arc::new(FakeStore::new(CommitMode::Conflict));
        let service = checked_service(
            Arc::clone(&store),
            authorizer([ResourceVerb::Delete, ResourceVerb::Get]),
        );
        let mut request = wire::CommitBatchRequest::new();
        request.meta = request_meta();
        request.mutations = vec![
            mutation(wire::MutationKind::MUTATION_KIND_DELETE),
            mutation(wire::MutationKind::MUTATION_KIND_DELETE),
        ];

        let response = service.commit_batch(trusted(request, None)).await;

        assert_eq!(response.conflict_mutation_ordinal, Some(1));
        let error = response.error.as_ref().unwrap();
        assert_eq!(
            error.kind.enum_value().unwrap(),
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_CONFLICT
        );
        assert_eq!(error.current_revision, Some(8));
    }

    #[tokio::test]
    async fn status_owner_generation_is_checked_after_authorization() {
        let store = Arc::new(FakeStore::new(CommitMode::Success));
        let service = checked_service(Arc::clone(&store), authorizer([ResourceVerb::UpdateStatus]));
        let mut request = wire::UpdateStatusRequest::new();
        request.meta = request_meta();
        let mut value = mutation(wire::MutationKind::MUTATION_KIND_UPDATE_STATUS);
        value.resource = body(GOLDEN_HOST.to_vec());
        request.mutation = MessageField::some(value);

        let response = service.update_status(trusted(request, None)).await;
        assert_eq!(
            error_kind(&response.error),
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_STATUS_OWNER_MISMATCH
        );
        assert_eq!(store.commits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn finalizers_are_separate_and_batch_is_one_admitted_commit() {
        let store = Arc::new(FakeStore::new(CommitMode::Success));
        let authorizer = authorizer([ResourceVerb::UpdateMetadata, ResourceVerb::Delete]);
        let service = checked_service(Arc::clone(&store), authorizer);
        let mut request = wire::UpdateMetadataRequest::new();
        request.meta = request_meta();
        let mut value = mutation(wire::MutationKind::MUTATION_KIND_UPDATE_METADATA);
        value.resource = body(GOLDEN_HOST.to_vec());
        value.add_finalizers.push("core.cleanup".to_owned());
        request.mutation = MessageField::some(value);
        let response = service.update_metadata(trusted(request, None)).await;
        assert_eq!(
            error_kind(&response.error),
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_SCHEMA_INVALID
        );

        let mut batch = wire::CommitBatchRequest::new();
        batch.meta = request_meta();
        batch.mutations = vec![
            mutation(wire::MutationKind::MUTATION_KIND_DELETE),
            mutation(wire::MutationKind::MUTATION_KIND_DELETE),
        ];
        let response = service.commit_batch(trusted(batch, None)).await;
        assert!(response.error.is_none());
        assert_eq!(response.revision, 9);
        assert_eq!(store.commits.load(Ordering::SeqCst), 1);
        assert_eq!(store.mutation_count.load(Ordering::SeqCst), 2);
        assert_eq!(store.configuration_revision.load(Ordering::SeqCst), 6);
    }

    #[tokio::test]
    async fn mixed_zone_batch_is_rejected_before_admission() {
        let store = Arc::new(FakeStore::new(CommitMode::Success));
        let service = checked_service(Arc::clone(&store), authorizer([ResourceVerb::Delete]));
        let mut batch = wire::CommitBatchRequest::new();
        batch.meta = request_meta();
        let dev = mutation(wire::MutationKind::MUTATION_KIND_DELETE);
        let mut personal = mutation(wire::MutationKind::MUTATION_KIND_DELETE);
        personal.target.mut_or_insert_default().zone = "personal".to_owned();
        batch.mutations = vec![dev, personal];

        let response = service.commit_batch(trusted(batch, None)).await;

        assert_eq!(
            error_kind(&response.error),
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_AUTHORIZATION_DENIED
        );
        assert_eq!(store.commits.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn list_and_watch_validate_bounds_before_target_expansion() {
        let mut filters = Vec::new();
        let mut name_filter = wire::ListFilter::new();
        name_filter.field = "metadata.name".to_owned();
        name_filter.values = vec!["host-system".to_owned(); MAX_FILTER_VALUES.saturating_add(1)];
        filters.push(name_filter);
        assert!(
            parse_collection_request(
                &vec!["Host".to_owned(); MAX_LIST_RESOURCE_TYPES],
                &filters,
                MAX_LIST_RESOURCE_TYPES,
                MAX_LIST_FILTERS,
            )
            .is_err()
        );
        assert!(
            parse_collection_request(
                &vec!["Host".to_owned(); MAX_WATCH_RESOURCE_TYPES + 1],
                &[],
                MAX_WATCH_RESOURCE_TYPES,
                MAX_WATCH_FILTERS,
            )
            .is_err()
        );
    }

    #[test]
    fn collection_parser_preserves_owner_uid_filter_for_owned_processes() {
        let mut owner_filter = wire::ListFilter::new();
        owner_filter.field = "owner.resourceUid".to_owned();
        owner_filter.values = vec!["123e4567-e89b-42d3-a456-426614174000".to_owned()];
        let parsed = parse_collection_request(
            &[PROCESS_RESOURCE_TYPE.to_owned()],
            &[owner_filter],
            MAX_LIST_RESOURCE_TYPES,
            MAX_LIST_FILTERS,
        )
        .unwrap();
        assert_eq!(parsed.resource_types[0].as_str(), PROCESS_RESOURCE_TYPE);
        assert_eq!(parsed.filters[0].field, "owner.resourceUid");
        assert_eq!(
            parsed.filters[0].values,
            vec!["123e4567-e89b-42d3-a456-426614174000".to_owned()]
        );
    }

    #[test]
    fn scoped_owner_child_updates_and_deletes_keep_the_owner_fence() {
        for (kind, verb) in [
            (ResourceMutationKind::UpdateSpec, "UpdateSpec"),
            (ResourceMutationKind::Delete, "Delete"),
        ] {
            let transport = ScopedCommitTransport::decode(
                format!(
                    r#"{{"version":1,"assignment":{{"resourceUid":"123e4567-e89b-42d3-a456-426614174000","resourceRevision":7,"providerRef":"Provider/provider-runtime","providerGeneration":2,"controllerGeneration":3,"controllerRole":"Process/process-controller","target":{{"kind":"zone","zone":"dev"}},"sessionOwner":"Process/process-controller","sessionGeneration":1,"epoch":9}},"mutations":[{{"target":"Process/work","verb":"{verb}","scope":{{"kind":"owner-child","ownerRef":"Guest/guest","ownerUid":"123e4567-e89b-42d3-a456-426614174000","ownerRevision":7,"ownerGeneration":1}}}}]}}"#
                )
                .as_bytes(),
            )
            .unwrap();
            let target = ResourceRef::parse("Process/work").unwrap();
            let mut parsed = [ParsedMutation {
                store: StoreMutation {
                    kind,
                    zone: ZoneId::parse("dev").unwrap(),
                    target: target.clone(),
                    expected: ExpectedRevision::Exact(ZoneRevision::new(7)),
                    expected_uid: Some(
                        ResourceUid::parse("223e4567-e89b-42d3-a456-426614174001").unwrap(),
                    ),
                    owner: None,
                    canonical_resource: None,
                    add_finalizers: Vec::new(),
                    remove_finalizers: Vec::new(),
                    wait_for_reconcile: false,
                    reconcile_deadline_ms: None,
                    configuration_generation: None,
                    assignment: None,
                },
            }];
            let routes = [ParsedMutationRoute {
                identity: ParsedIdentity {
                    zone: ZoneId::parse("dev").unwrap(),
                    resource_ref: target,
                    uid: Some(ResourceUid::parse("223e4567-e89b-42d3-a456-426614174001").unwrap()),
                    generation: None,
                    revision: None,
                },
                owner: None,
                kind,
                authorizations: Vec::new(),
            }];
            attach_scoped_fences(&mut parsed, transport.mutations(), &routes).unwrap();
            assert!(matches!(
                &parsed[0].store.assignment.as_ref().unwrap().scope,
                d2b_resource_store::ResourceAssignmentScope::OwnerChild { .. }
            ));
        }
    }

    #[test]
    fn scoped_owner_child_create_requires_exact_owner_identity_and_process_target() {
        let transport = ScopedCommitTransport::decode(
            br#"{"version":1,"assignment":{"resourceUid":"123e4567-e89b-42d3-a456-426614174000","resourceRevision":7,"providerRef":"Provider/provider-runtime","providerGeneration":2,"controllerGeneration":3,"controllerRole":"Process/process-controller","target":{"kind":"zone","zone":"dev"},"sessionOwner":"Process/process-controller","sessionGeneration":1,"epoch":9},"mutations":[{"target":"Process/work","verb":"Create","scope":{"kind":"owner-child","ownerRef":"Guest/guest","ownerUid":"123e4567-e89b-42d3-a456-426614174000","ownerRevision":7,"ownerGeneration":1}}]}"#,
        )
        .unwrap();
        let owner_ref = ResourceRef::parse("Guest/guest").unwrap();
        let owner_uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let build = |target: ResourceRef,
                     owner_ref: ResourceRef,
                     owner_uid: Option<ResourceUid>,
                     owner_generation: Option<ResourceGeneration>,
                     owner_revision: Option<ZoneRevision>| {
            let parsed = [ParsedMutation {
                store: StoreMutation {
                    kind: ResourceMutationKind::Create,
                    zone: ZoneId::parse("dev").unwrap(),
                    target: target.clone(),
                    expected: ExpectedRevision::CreateAbsent,
                    expected_uid: None,
                    owner: Some(owner_ref.clone()),
                    canonical_resource: None,
                    add_finalizers: Vec::new(),
                    remove_finalizers: Vec::new(),
                    wait_for_reconcile: false,
                    reconcile_deadline_ms: None,
                    configuration_generation: None,
                    assignment: None,
                },
            }];
            let routes = [ParsedMutationRoute {
                identity: ParsedIdentity {
                    zone: ZoneId::parse("dev").unwrap(),
                    resource_ref: target,
                    uid: None,
                    generation: None,
                    revision: None,
                },
                owner: Some(ParsedIdentity {
                    zone: ZoneId::parse("dev").unwrap(),
                    resource_ref: owner_ref,
                    uid: owner_uid,
                    generation: owner_generation,
                    revision: owner_revision,
                }),
                kind: ResourceMutationKind::Create,
                authorizations: Vec::new(),
            }];
            (parsed, routes)
        };

        let (mut parsed, routes) = build(
            ResourceRef::parse("Process/work").unwrap(),
            owner_ref.clone(),
            Some(owner_uid.clone()),
            Some(ResourceGeneration::new(1).unwrap()),
            Some(ZoneRevision::new(7)),
        );
        attach_scoped_fences(&mut parsed, transport.mutations(), &routes).unwrap();
        let fence = parsed[0].store.assignment.as_ref().unwrap();
        assert_eq!(fence.resource_uid, owner_uid);
        assert_eq!(fence.resource_revision, ZoneRevision::new(7));
        assert!(matches!(
            &fence.scope,
            d2b_resource_store::ResourceAssignmentScope::OwnerChild {
                owner_ref,
                owner_uid,
                owner_revision,
                owner_generation,
            } if owner_ref == &ResourceRef::parse("Guest/guest").unwrap()
                && owner_uid.as_str() == "123e4567-e89b-42d3-a456-426614174000"
                && *owner_revision == ZoneRevision::new(7)
                && *owner_generation == ResourceGeneration::new(1).unwrap()
        ));

        for (owner_ref, owner_uid, owner_generation, owner_revision) in [
            (
                ResourceRef::parse("Guest/other").unwrap(),
                Some(owner_uid.clone()),
                Some(ResourceGeneration::new(1).unwrap()),
                Some(ZoneRevision::new(7)),
            ),
            (
                owner_ref.clone(),
                Some(ResourceUid::parse("223e4567-e89b-42d3-a456-426614174001").unwrap()),
                Some(ResourceGeneration::new(1).unwrap()),
                Some(ZoneRevision::new(7)),
            ),
            (
                owner_ref.clone(),
                Some(owner_uid.clone()),
                Some(ResourceGeneration::new(2).unwrap()),
                Some(ZoneRevision::new(7)),
            ),
            (
                owner_ref.clone(),
                Some(owner_uid.clone()),
                Some(ResourceGeneration::new(1).unwrap()),
                Some(ZoneRevision::new(8)),
            ),
        ] {
            let target = ResourceRef::parse("Process/work").unwrap();
            let (mut parsed, routes) = build(
                target,
                owner_ref,
                owner_uid,
                owner_generation,
                owner_revision,
            );
            let error =
                attach_scoped_fences(&mut parsed, transport.mutations(), &routes).unwrap_err();
            assert_eq!(error.kind(), ResourceErrorKind::AuthorizationDenied);
        }

        let (mut parsed, routes) = build(
            ResourceRef::parse("Host/work").unwrap(),
            ResourceRef::parse("Guest/guest").unwrap(),
            Some(ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap()),
            Some(ResourceGeneration::new(1).unwrap()),
            Some(ZoneRevision::new(7)),
        );
        let error = attach_scoped_fences(&mut parsed, transport.mutations(), &routes).unwrap_err();
        assert_eq!(error.kind(), ResourceErrorKind::AuthorizationDenied);
    }

    #[tokio::test]
    async fn batch_and_schema_responses_enforce_the_byte_limit() {
        let store = Arc::new(FakeStore::new(CommitMode::Success));
        store
            .commit_resources
            .lock()
            .unwrap()
            .extend((0..2).map(|_| stored_resource(MAX_RESPONSE_CANONICAL_BYTES / 2)));
        let batch_service = checked_service(Arc::clone(&store), authorizer([ResourceVerb::Delete]));
        let mut batch = wire::CommitBatchRequest::new();
        batch.meta = request_meta();
        batch
            .mutations
            .push(mutation(wire::MutationKind::MUTATION_KIND_DELETE));
        let response = batch_service.commit_batch(trusted(batch, None)).await;
        assert_eq!(
            error_kind(&response.error),
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_SCHEMA_INVALID
        );
        assert!(response.resources.is_empty());

        let schema_store = Arc::new(FakeStore::new(CommitMode::Success));
        *schema_store.schema_response.lock().unwrap() = Some(StoredSchema {
            resource_type: ResourceTypeName::parse("Host").unwrap(),
            canonical_json: vec![b'x'; MAX_RESPONSE_CANONICAL_BYTES],
            payload_digest: format!("sha256:{}", "1".repeat(64)),
        });
        let schema_service = checked_service(
            Arc::clone(&schema_store),
            authorizer_for_subresource(ResourceVerb::Get, "schema"),
        );
        let mut request = wire::InspectSchemaRequest::new();
        request.meta = request_meta();
        request.resource_type = "Host".to_owned();
        let response = schema_service.inspect_schema(trusted(request, None)).await;
        assert_eq!(
            error_kind(&response.error),
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_SCHEMA_INVALID
        );
        assert!(response.schema.is_none());
    }

    #[tokio::test]
    async fn upgrade_response_enforces_the_byte_limit() {
        #[derive(Debug)]
        struct OversizeUpgrade;

        impl UpgradeDispatcher for OversizeUpgrade {
            async fn dispatch(
                &self,
                _request: AuthorizedUpgrade,
            ) -> Result<UpgradeResult, ResourceError> {
                Ok(UpgradeResult {
                    resource: stored_resource(MAX_RESPONSE_CANONICAL_BYTES),
                    plan: Vec::new(),
                    revision: ZoneRevision::new(9),
                })
            }
        }

        let store = Arc::new(FakeStore::new(CommitMode::Success));
        let service = checked_service_with_upgrade(
            Arc::clone(&store),
            authorizer([ResourceVerb::UpdateSpec]),
            Arc::new(OversizeUpgrade),
        );
        let mut request = wire::UpgradeRequest::new();
        request.meta = request_meta();
        request.target = identity();
        request.action = EnumOrUnknown::new(wire::UpgradeAction::UPGRADE_ACTION_ASSESS);
        let mut precondition = wire::Precondition::new();
        precondition.kind =
            EnumOrUnknown::new(wire::PreconditionKind::PRECONDITION_KIND_EXACT_REVISION);
        precondition.expected_revision = Some(1);
        request.precondition = MessageField::some(precondition);
        let response = service.upgrade(trusted(request, None)).await;
        assert_eq!(
            error_kind(&response.error),
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_SCHEMA_INVALID
        );
        assert!(response.resource.is_none());
    }

    #[test]
    fn status_owner_matching_generation_is_representable() {
        let context = subject(Some(11));
        assert_eq!(
            context.controller_generation(),
            Some(ControllerGeneration::new(11).unwrap())
        );
        let _: ResourceGeneration = ResourceGeneration::new(11).unwrap();
    }

    #[test]
    fn service_debug_surfaces_redact_backend_and_resource_fields() {
        const EXPECTED_REVISION_SENTINEL: u64 = 4_294_967_290;
        const RESULT_REVISION_SENTINEL: u64 = 4_294_967_289;
        const ZONE_SENTINEL: &str = "service-zone-sentinel";
        const NAME_SENTINEL: &str = "service-name-sentinel";
        const REF_SENTINEL: &str = "service-ref-sentinel";
        const UID_SENTINEL: &str = "22222222-2222-4222-8222-222222222222";
        const PAYLOAD_SENTINEL: &str = "service-payload-sentinel";

        let store = Arc::new(FakeStore::with_debug_marker(
            CommitMode::Success,
            PAYLOAD_SENTINEL,
        ));
        assert_eq!(store.debug_marker, PAYLOAD_SENTINEL);
        let service = checked_service(Arc::clone(&store), authorizer([]));
        let upgrade = AuthorizedUpgrade {
            operation: StoreOperationContext {
                operation_id: PAYLOAD_SENTINEL.to_owned(),
                idempotency_key: Some(PAYLOAD_SENTINEL.to_owned()),
                correlation_id: PAYLOAD_SENTINEL.to_owned(),
                trace_id: Some(PAYLOAD_SENTINEL.to_owned()),
                deadline_ms: 1,
            },
            zone: ZoneId::parse(ZONE_SENTINEL).unwrap(),
            target: ResourceRef::parse(&format!("Host/{REF_SENTINEL}")).unwrap(),
            action: UpgradeAction::Plan,
            recursive: true,
            expected_revision: ZoneRevision::new(EXPECTED_REVISION_SENTINEL),
        };
        assert_eq!(upgrade.expected_revision.get(), EXPECTED_REVISION_SENTINEL);
        let mut resource = stored_resource(PAYLOAD_SENTINEL.len());
        resource.resource_ref = ResourceRef::parse(&format!("Host/{REF_SENTINEL}")).unwrap();
        resource.zone = ZoneId::parse(ZONE_SENTINEL).unwrap();
        resource.uid = ResourceUid::parse(UID_SENTINEL).unwrap();
        resource.canonical_json = PAYLOAD_SENTINEL.as_bytes().to_vec();
        resource.payload_digest = PAYLOAD_SENTINEL.to_owned();
        let result = UpgradeResult {
            resource,
            plan: Vec::new(),
            revision: ZoneRevision::new(RESULT_REVISION_SENTINEL),
        };
        let parsed_identity = ParsedIdentity {
            zone: ZoneId::parse(ZONE_SENTINEL).unwrap(),
            resource_ref: ResourceRef::parse(&format!("Host/{REF_SENTINEL}")).unwrap(),
            uid: Some(ResourceUid::parse(UID_SENTINEL).unwrap()),
            generation: None,
            revision: None,
        };
        let protected_mutation = StoreMutation {
            kind: ResourceMutationKind::UpdateSpec,
            zone: ZoneId::parse(ZONE_SENTINEL).unwrap(),
            target: ResourceRef::parse(&format!("Host/{REF_SENTINEL}")).unwrap(),
            expected: ExpectedRevision::Exact(ZoneRevision::new(1)),
            expected_uid: Some(ResourceUid::parse(UID_SENTINEL).unwrap()),
            owner: Some(ResourceRef::parse(&format!("Process/{REF_SENTINEL}")).unwrap()),
            canonical_resource: Some(PAYLOAD_SENTINEL.as_bytes().to_vec()),
            add_finalizers: Vec::new(),
            remove_finalizers: Vec::new(),
            wait_for_reconcile: false,
            reconcile_deadline_ms: None,
            configuration_generation: None,
            assignment: None,
        };
        let parsed_mutation = ParsedMutation {
            store: protected_mutation,
        };
        let parsed_route = ParsedMutationRoute {
            identity: ParsedIdentity {
                zone: ZoneId::parse(ZONE_SENTINEL).unwrap(),
                resource_ref: ResourceRef::parse(&format!("Host/{REF_SENTINEL}")).unwrap(),
                uid: Some(ResourceUid::parse(UID_SENTINEL).unwrap()),
                generation: None,
                revision: None,
            },
            owner: Some(ParsedIdentity {
                zone: ZoneId::parse(ZONE_SENTINEL).unwrap(),
                resource_ref: ResourceRef::parse(&format!("Process/{REF_SENTINEL}")).unwrap(),
                uid: Some(ResourceUid::parse(UID_SENTINEL).unwrap()),
                generation: None,
                revision: None,
            }),
            kind: ResourceMutationKind::UpdateSpec,
            authorizations: vec![AuthorizationTarget {
                resource_type: ResourceTypeName::parse("Host").unwrap(),
                resource_name: Some(ResourceName::parse(NAME_SENTINEL).unwrap()),
                verb: ResourceVerb::UpdateSpec,
                subresource: Some(PAYLOAD_SENTINEL.to_owned()),
                execution_ref: Some(
                    ResourceRef::parse(&format!("Process/{REF_SENTINEL}")).unwrap(),
                ),
            }],
        };
        let trusted_subject = Arc::new(AuthenticatedSubjectContext::new(
            ResourceRef::parse(&format!("User/{REF_SENTINEL}")).unwrap(),
            ResourceUid::parse(UID_SENTINEL).unwrap(),
            ResourceRef::parse(&format!("Zone/{ZONE_SENTINEL}")).unwrap(),
            EvidenceClass::UnixPeer,
            SessionPurpose::parse("service-debug-purpose").unwrap(),
            ServiceName::parse("service.debug.sentinel").unwrap(),
            SessionBinding::new(
                SchemaFingerprint::parse(format!("sha256:{}", "1".repeat(64))).unwrap(),
                TransportBinding::new(
                    Locality::Local,
                    BindingDigest::parse(format!("sha256:{}", "2".repeat(64))).unwrap(),
                ),
                ReconnectGeneration::new(1).unwrap(),
                TranscriptHash::from_bytes([3; 32]),
            ),
        ));
        let trusted_request = TrustedRequest::from_session_capability(
            trusted_subject,
            state(None),
            PAYLOAD_SENTINEL.to_owned(),
        );

        assert_eq!(format!("{service:?}"), "ResourceService(<redacted>)");
        assert_eq!(format!("{trusted_request:?}"), "TrustedRequest(<redacted>)");
        assert_eq!(
            format!("{upgrade:?}"),
            "AuthorizedUpgrade { action: Plan, recursive: true, \
             operation: \"<redacted>\", zone: \"<redacted>\", target: \"<redacted>\", \
             expected_revision: \"<redacted>\" }"
        );
        assert_eq!(
            format!("{result:?}"),
            "UpgradeResult { resource: \"<redacted>\", plan_length: 0, \
             revision: \"<redacted>\" }"
        );
        let identity_debug = "ParsedIdentity { zone: \"<redacted>\", \
                              resource_ref: \"<redacted>\", has_uid: true }";
        assert_eq!(format!("{parsed_identity:?}"), identity_debug);
        assert_eq!(
            format!("{parsed_mutation:?}"),
            "ParsedMutation { kind: UpdateSpec }"
        );
        assert_eq!(
            format!("{parsed_route:?}"),
            format!(
                "ParsedMutationRoute {{ identity: {identity_debug}, has_owner: true, \
                 kind: UpdateSpec, authorization_count: 1 }}"
            )
        );
    }
}
