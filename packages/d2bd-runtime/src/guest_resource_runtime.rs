//! Target-local Resource API for an authenticated Guest ComponentSession.
//!
//! Guest mode has no Zone store.  Controller-created Process-family resources
//! therefore live in this bounded in-memory store and are exposed only through
//! the currently admitted parent-Zone ComponentSession.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use d2b_contracts_resource::resource_proto as wire;
use d2b_contracts_resource::v3::{
    ConfigurationGeneration, ControllerGeneration, ResourceEnvelope, ResourceGeneration,
    ResourceName, ResourceRef, ResourceTypeName, ResourceUid, RetryClass, SchemaFingerprint,
    ZoneId, ZoneRevision,
    activation_nixos::NIXOS_GENERATION_RESOURCE_TYPE,
    resource_schema::{RESOURCE_ENVELOPE_DOMAIN_TAG, SCHEMA_DOMAIN_TAG},
};
use d2b_resource_api::{
    ResourceApiClient, ResourceBusAdapter, ResourceService, ResourceStoreBackend,
    authz::{
        ApiCatalog, AuthorizationState, BindingScope, BootstrapPhase, BoundSubject, CompiledRole,
        CompiledRoleBinding, NativeAuthorizer, PolicyRule, PolicySet, RelayGrantAuthority,
        ResourceVerb, SessionVerb,
    },
    service::UnavailableUpgradeDispatcher,
    watch::{ResourceWatch, WatchService},
};
use d2b_resource_store::{
    ExpectedRevision, MutationSealBody, ResourceMutationKind, SealedMutation, StoreCommitResult,
    StoreError, StoreErrorKind, StoreGetRequest, StoreInspectSchemaRequest, StoreListRequest,
    StoreListResult, StoreResolveRequest, StoreResolvedIdentity, StoreWatchReceipt,
    StoreWatchRequest, StoredResource, StoredSchema, mutation_seal::MutationSealAcceptor,
};
use d2b_resource_store_redb::{RedbResourceStore, StoreIdentity, write_provisioning_marker};
use protobuf::Message;
use ttrpc::{
    r#async::{MethodHandler, TtrpcContext},
    proto::{Request as TtrpcRequest, Response as TtrpcResponse},
};

use crate::{guest_mode::GuestIdentity, resource_runtime_support::store_identity};

#[cfg(test)]
const STORE_SLOT: u32 = 0;
const STORE_FILE_NAME: &str = "resource-store.redb";
const STORE_MARKER_NAME: &str = "resource-store.marker";
const ROLE_REF: &str = "Role/guest-component-session";
const WATCH_STREAM_PREFIX: &str = "guest-watch";
const SCHEMA_BYTES: &[u8] = br#"{"apiVersion":"d2b-cjson/v1","resourceType":"target-local"}"#;
const GUEST_SEED_DIGEST_DOMAIN: &str = "d2b-guest-local-seed-v1";
type CommitFence = Arc<dyn Fn() -> Result<(), StoreError> + Send + Sync>;

/// Target-local ResourceTypes accepted by the Guest-control seed API.
pub const GUEST_SEED_RESOURCE_TYPES: &[&str] = &[
    "Process",
    "EphemeralProcess",
    "Endpoint",
    NIXOS_GENERATION_RESOURCE_TYPE,
];

/// Authenticated target-local resource runtime for Guest mode.
#[derive(Clone)]
pub struct GuestResourceRuntime {
    identity: GuestIdentity,
    store: Arc<GuestResourceStore>,
    authorizer: Arc<NativeAuthorizer>,
    authorization_state: AuthorizationState,
    active_generation: Arc<Mutex<Option<u64>>>,
}

impl core::fmt::Debug for GuestResourceRuntime {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("GuestResourceRuntime(<redacted>)")
    }
}

impl GuestResourceRuntime {
    /// Build the target-local Resource API with Guest-owned durable state.
    pub async fn new(
        identity: GuestIdentity,
        state_dir: impl AsRef<Path>,
    ) -> Result<Self, GuestResourceRuntimeError> {
        let zone = identity.zone().clone();
        let activation_type = ResourceTypeName::parse(NIXOS_GENERATION_RESOURCE_TYPE)
            .map_err(|_| GuestResourceRuntimeError::Policy)?;
        let catalog = ApiCatalog::with_extensions([activation_type.clone()])
            .map_err(|_| GuestResourceRuntimeError::Policy)?;
        let resource_types = GUEST_SEED_RESOURCE_TYPES
            .iter()
            .copied()
            .map(ResourceTypeName::parse)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| GuestResourceRuntimeError::Policy)?;
        let resource_verbs = [
            ResourceVerb::Get,
            ResourceVerb::List,
            ResourceVerb::Watch,
            ResourceVerb::Create,
            ResourceVerb::UpdateSpec,
            ResourceVerb::UpdateStatus,
            ResourceVerb::UpdateMetadata,
            ResourceVerb::UpdateFinalizers,
            ResourceVerb::Delete,
        ];
        let session_verbs = [
            SessionVerb::Connect,
            SessionVerb::Invoke,
            SessionVerb::OpenStream,
            SessionVerb::Cancel,
            SessionVerb::Observe,
        ];
        let rules = resource_types
            .chunks(16)
            .map(|resource_types| {
                PolicyRule::new(
                    &catalog,
                    resource_types.iter().cloned(),
                    resource_verbs,
                    session_verbs,
                    [],
                    [],
                    [zone.clone()],
                    [],
                )
                .map_err(|_| GuestResourceRuntimeError::Policy)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let role_ref =
            ResourceRef::parse(ROLE_REF).map_err(|_| GuestResourceRuntimeError::Policy)?;
        let role = CompiledRole::new(role_ref.clone(), rules)
            .map_err(|_| GuestResourceRuntimeError::Policy)?;
        let binding_scope = BindingScope {
            zones: [zone.clone()].into_iter().collect(),
            ..BindingScope::default()
        };
        let binding = CompiledRoleBinding::new(
            role_ref,
            [BoundSubject {
                subject_ref: identity.guest_ref().clone(),
                subject_uid: identity.guest_uid().clone(),
            }],
            binding_scope,
            RelayGrantAuthority::None,
        )
        .map_err(|_| GuestResourceRuntimeError::Policy)?;
        let policy_revision = 1;
        let policy = PolicySet::new(&catalog, policy_revision, vec![role], vec![binding])
            .map_err(|_| GuestResourceRuntimeError::Policy)?;
        let authorization_state = AuthorizationState {
            snapshot: d2b_resource_store::PolicySnapshot {
                policy_revision,
                api_catalog_revision: 1,
                active_configuration_revision: ConfigurationGeneration::new(1)
                    .map_err(|_| GuestResourceRuntimeError::Policy)?,
                controller_generation: Some(
                    ControllerGeneration::new(identity.controller_generation())
                        .map_err(|_| GuestResourceRuntimeError::Policy)?,
                ),
            },
            zone_policy_revision: ZoneRevision::new(1),
            bootstrap_phase: BootstrapPhase::Disabled,
            now_tick: 1,
        };
        let authorizer = Arc::new(
            NativeAuthorizer::new(catalog, Some(policy))
                .map_err(|_| GuestResourceRuntimeError::Policy)?,
        );
        let store_identity =
            store_identity(&zone, &format!("guest-target:{}", identity.guest_uid()))
                .map_err(|_| GuestResourceRuntimeError::Store)?
                .with_revisions(authorization_state.snapshot.clone());
        let acceptor = authorizer
            .take_store_seal(store_identity.seal_identity())
            .map_err(|_| GuestResourceRuntimeError::Store)?;
        let backend = Arc::new(
            GuestResourceStore::open_durable(
                zone,
                identity.guest_ref().clone(),
                state_dir.as_ref(),
                store_identity,
                acceptor,
            )
            .await?,
        );
        let active_generation = Arc::new(Mutex::new(None));
        Ok(Self {
            identity,
            store: backend,
            authorizer,
            authorization_state,
            active_generation,
        })
    }

    /// This runtime is intentionally not backed by a local Zone store.
    pub const fn is_target_local(&self) -> bool {
        true
    }

    pub(crate) fn active_generation(&self) -> Arc<Mutex<Option<u64>>> {
        Arc::clone(&self.active_generation)
    }

    /// Bind the Resource API to one already authenticated session route.
    pub fn bind_session(
        &self,
        route: &d2b_session::AuthenticatedSessionRouteBinding,
    ) -> Result<GuestResourceSession, GuestResourceRuntimeError> {
        let (store, adapter) = self.bind_session_parts(route)?;
        Ok(GuestResourceSession {
            store,
            adapter,
            generation: route.reconnect_generation().get(),
        })
    }

    /// Bind the target-local Resource API to the narrow Guest seed contract.
    ///
    /// This capability exposes only `CommitBatch` mutations and revision
    /// watches for the descriptor's approved target-local ResourceTypes. The
    /// route and session generation remain sealed by the authenticated
    /// ComponentSession.
    pub fn bind_seed_session(
        &self,
        route: &d2b_session::AuthenticatedSessionRouteBinding,
        descriptor_digest: SchemaFingerprint,
        approved_types: impl IntoIterator<Item = ResourceTypeName>,
    ) -> Result<GuestResourceSeedSession, GuestResourceRuntimeError> {
        let approved_types = approved_types.into_iter().collect::<BTreeSet<_>>();
        if is_zero_fingerprint(&descriptor_digest)
            || approved_types.is_empty()
            || approved_types
                .iter()
                .any(|resource_type| !GUEST_SEED_RESOURCE_TYPES.contains(&resource_type.as_str()))
        {
            return Err(GuestResourceRuntimeError::SeedPolicy);
        }
        let (_store, adapter) = self.bind_session_parts(route)?;
        Ok(GuestResourceSeedSession {
            adapter,
            guest_ref: self.identity.guest_ref().clone(),
            guest_uid: self.identity.guest_uid().clone(),
            zone: self.identity.zone().clone(),
            descriptor_digest,
            approved_types,
            generation: route.reconnect_generation().get(),
        })
    }

    fn bind_session_parts(
        &self,
        route: &d2b_session::AuthenticatedSessionRouteBinding,
    ) -> Result<
        (
            Arc<SessionBoundStore>,
            Arc<ResourceBusAdapter<SessionBoundStore, UnavailableUpgradeDispatcher>>,
        ),
        GuestResourceRuntimeError,
    > {
        self.identity
            .validate_route(route)
            .map_err(|_| GuestResourceRuntimeError::SessionBinding)?;
        let subject = self
            .authorizer
            .issue_authenticated_subject(route.context().clone(), self.authorization_state.clone())
            .map_err(|_| GuestResourceRuntimeError::Authorization)?;
        let backend = Arc::new(SessionBoundStore {
            store: Arc::clone(&self.store),
            active_generation: Arc::clone(&self.active_generation),
            generation: route.reconnect_generation().get(),
        });
        let session_store = Arc::clone(&backend);
        let service = Arc::new(
            ResourceService::new_session_bound(backend, Arc::clone(&self.authorizer))
                .inspect_err(|error| {
                    tracing::warn!(
                        error = ?error,
                        "Guest Resource API service construction failed",
                    );
                })
                .map_err(|_| GuestResourceRuntimeError::Store)?,
        );
        let adapter = ResourceBusAdapter::bind_component_session(service, subject)
            .map_err(|_| GuestResourceRuntimeError::Authorization)?;
        Ok((session_store, Arc::new(adapter)))
    }
}

/// Resource API capability bound to one Guest session generation.
pub struct GuestResourceSession {
    store: Arc<SessionBoundStore>,
    adapter: Arc<ResourceBusAdapter<SessionBoundStore, UnavailableUpgradeDispatcher>>,
    generation: u64,
}

/// Narrow target-local Resource API capability used by Guest-local seeding.
pub struct GuestResourceSeedSession {
    adapter: Arc<ResourceBusAdapter<SessionBoundStore, UnavailableUpgradeDispatcher>>,
    guest_ref: ResourceRef,
    guest_uid: ResourceUid,
    zone: ZoneId,
    descriptor_digest: SchemaFingerprint,
    approved_types: BTreeSet<ResourceTypeName>,
    generation: u64,
}

impl core::fmt::Debug for GuestResourceSeedSession {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("GuestResourceSeedSession")
            .field("generation", &"<redacted>")
            .field("approved_type_count", &self.approved_types.len())
            .field("has_descriptor_digest", &true)
            .finish()
    }
}

impl GuestResourceSeedSession {
    /// Return the authenticated reconnect generation.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Borrow the descriptor digest bound to this seed capability.
    pub const fn descriptor_digest(&self) -> &SchemaFingerprint {
        &self.descriptor_digest
    }

    /// Borrow the closed ResourceType allowlist.
    pub fn approved_types(&self) -> &BTreeSet<ResourceTypeName> {
        &self.approved_types
    }

    /// Build the target-local server map with only seed mutation and watch
    /// methods exposed.
    pub fn ttrpc_services(&self) -> std::collections::HashMap<String, ttrpc::r#async::Service> {
        restricted_seed_services(
            Arc::clone(&self.adapter).ttrpc_services(),
            &self.guest_ref,
            &self.guest_uid,
            &self.zone,
            Some(&self.descriptor_digest),
            &self.approved_types,
        )
    }

    /// Validate one UID-free, descriptor-approved seed request.
    pub fn validate_commit_batch(
        &self,
        request: &wire::CommitBatchRequest,
    ) -> Result<(), GuestResourceRuntimeError> {
        validate_seed_request(
            request,
            &self.guest_ref,
            &self.guest_uid,
            &self.zone,
            Some(&self.descriptor_digest),
            &self.approved_types,
        )
    }

    /// Execute one validated target-local seed CommitBatch.
    pub async fn commit_batch(
        &self,
        request: wire::CommitBatchRequest,
    ) -> Result<wire::CommitBatchResponse, GuestResourceRuntimeError> {
        self.validate_commit_batch(&request)?;
        Ok(self.adapter.client().commit_batch(request).await)
    }

    /// Validate one revision-resumable target-local Watch request.
    pub fn validate_watch(
        &self,
        request: &wire::WatchRequest,
    ) -> Result<(), GuestResourceRuntimeError> {
        validate_watch_request(request, &self.approved_types)
    }

    /// Open a target-local Watch from an exact previous revision.
    pub async fn watch(
        &self,
        request: wire::WatchRequest,
    ) -> Result<wire::WatchResponse, GuestResourceRuntimeError> {
        self.validate_watch(&request)?;
        Ok(self.adapter.client().watch(request).await)
    }
}

impl core::fmt::Debug for GuestResourceSession {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("GuestResourceSession")
            .field("generation", &"<redacted>")
            .finish()
    }
}

impl GuestResourceSession {
    /// Return the authenticated reconnect generation for diagnostics.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Build the generated ResourceService map for the session server.
    pub fn ttrpc_services(&self) -> std::collections::HashMap<String, ttrpc::r#async::Service> {
        Arc::clone(&self.adapter).ttrpc_services()
    }

    /// Return the in-process client used by target-local controllers.
    pub fn client(&self) -> ResourceApiClient<SessionBoundStore, UnavailableUpgradeDispatcher> {
        self.adapter.client()
    }

    /// Return the store backend fenced to this authenticated session.
    ///
    /// Target-local controllers use the same backend as the bus adapter so
    /// relists and status mutations cannot outlive the session generation.
    pub fn store_backend(&self) -> Arc<SessionBoundStore> {
        Arc::clone(&self.store)
    }
}

/// Closed construction and binding failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestResourceRuntimeError {
    Policy,
    Store,
    StoreQuarantined,
    SessionBinding,
    Authorization,
    SeedPolicy,
    SeedInvalid,
}

impl core::fmt::Display for GuestResourceRuntimeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Policy => "guest-resource-policy-unavailable",
            Self::Store => "guest-resource-store-unavailable",
            Self::StoreQuarantined => "guest-resource-store-quarantined",
            Self::SessionBinding => "guest-resource-session-binding-invalid",
            Self::Authorization => "guest-resource-authorization-denied",
            Self::SeedPolicy => "guest-resource-seed-policy-invalid",
            Self::SeedInvalid => "guest-resource-seed-request-invalid",
        })
    }
}

impl std::error::Error for GuestResourceRuntimeError {}

fn is_zero_fingerprint(value: &SchemaFingerprint) -> bool {
    value
        .as_str()
        .strip_prefix("sha256:")
        .is_some_and(|hex| !hex.is_empty() && hex.bytes().all(|byte| byte == b'0'))
}

struct GuestStoreState {
    revision: u64,
    resources: BTreeMap<ResourceRef, StoredResource>,
    next_watch: u64,
}

enum GuestStoreBackend {
    Durable(Arc<RedbResourceStore>),
    #[allow(dead_code)]
    Memory {
        acceptor: MutationSealAcceptor,
        state: Mutex<GuestStoreState>,
    },
}

/// Target-local store owned by one Guest.
pub struct GuestResourceStore {
    zone: ZoneId,
    target: Option<ResourceRef>,
    backend: GuestStoreBackend,
}

impl core::fmt::Debug for GuestResourceStore {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("GuestResourceStore")
            .field("resource_count", &self.resource_count())
            .finish()
    }
}

impl GuestResourceStore {
    #[allow(dead_code)]
    fn new_in_memory(zone: ZoneId, acceptor: MutationSealAcceptor) -> Self {
        Self {
            zone,
            target: None,
            backend: GuestStoreBackend::Memory {
                acceptor,
                state: Mutex::new(GuestStoreState {
                    revision: 0,
                    resources: BTreeMap::new(),
                    next_watch: 0,
                }),
            },
        }
    }

    async fn open_durable(
        zone: ZoneId,
        target: ResourceRef,
        state_dir: &Path,
        identity: StoreIdentity,
        acceptor: MutationSealAcceptor,
    ) -> Result<Self, GuestResourceRuntimeError> {
        let metadata =
            fs::symlink_metadata(state_dir).map_err(|_| GuestResourceRuntimeError::Store)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.mode() & 0o002 != 0 {
            return Err(GuestResourceRuntimeError::Store);
        }
        let database_path = state_dir.join(STORE_FILE_NAME);
        let marker_path = state_dir.join(STORE_MARKER_NAME);
        let database_present = fs::symlink_metadata(&database_path)
            .map(|metadata| !metadata.file_type().is_symlink())
            .unwrap_or(false);
        let marker_present = fs::symlink_metadata(&marker_path)
            .map(|metadata| !metadata.file_type().is_symlink())
            .unwrap_or(false);
        if database_present != marker_present {
            return Err(GuestResourceRuntimeError::StoreQuarantined);
        }
        let database = open_owned_file(&database_path)?;
        let mut marker = open_owned_file(&marker_path)?;
        let database_empty = database
            .metadata()
            .map_err(|_| GuestResourceRuntimeError::Store)?
            .len()
            == 0;
        let marker_empty = marker
            .metadata()
            .map_err(|_| GuestResourceRuntimeError::Store)?
            .len()
            == 0;
        let store = if database_empty && marker_empty {
            write_provisioning_marker(&mut marker, &identity)
                .map_err(|_| GuestResourceRuntimeError::Store)?;
            RedbResourceStore::provision_owned(database, marker, identity, acceptor)
                .await
                .map_err(map_store_error)?
        } else if database_empty || marker_empty {
            return Err(GuestResourceRuntimeError::StoreQuarantined);
        } else {
            drop(marker);
            RedbResourceStore::open_owned(database, identity, acceptor)
                .await
                .map_err(map_store_error)?
        };
        Ok(Self {
            zone,
            target: Some(target),
            backend: GuestStoreBackend::Durable(Arc::new(store)),
        })
    }

    fn resource_count(&self) -> usize {
        match &self.backend {
            GuestStoreBackend::Durable(_) => 0,
            GuestStoreBackend::Memory { state, .. } => {
                state.lock().map(|state| state.resources.len()).unwrap_or(0)
            }
        }
    }

    fn is_target_local_type(resource_type: &ResourceTypeName) -> bool {
        matches!(
            resource_type.as_str(),
            "Process" | "EphemeralProcess" | "Endpoint" | NIXOS_GENERATION_RESOURCE_TYPE
        )
    }

    fn forbidden() -> StoreError {
        StoreError::new(
            StoreErrorKind::AuthorizationDenied,
            None,
            None,
            RetryClass::Never,
            "guest-target-resource-type-denied",
        )
    }

    fn unavailable(reason: &'static str) -> StoreError {
        StoreError::new(
            StoreErrorKind::ResourcePlaneUnavailable,
            None,
            None,
            RetryClass::AfterDelay,
            reason,
        )
    }

    fn invalid(reason: &'static str) -> StoreError {
        StoreError::new(
            StoreErrorKind::ResourceSchemaInvalid,
            None,
            None,
            RetryClass::Never,
            reason,
        )
    }

    fn not_found() -> StoreError {
        StoreError::new(
            StoreErrorKind::ResourceNotFound,
            None,
            None,
            RetryClass::Never,
            "guest-target-resource-not-found",
        )
    }

    async fn open_resource_watch(
        &self,
        request: StoreWatchRequest,
    ) -> Result<ResourceWatch, StoreError> {
        if request.zone != self.zone
            || request
                .resource_types
                .iter()
                .any(|resource_type| !Self::is_target_local_type(resource_type))
        {
            return Err(Self::forbidden());
        }
        match &self.backend {
            GuestStoreBackend::Durable(store) => {
                WatchService::new(Arc::clone(store)).open(request).await
            }
            GuestStoreBackend::Memory { .. } => {
                Err(Self::unavailable("guest-target-watch-unavailable"))
            }
        }
    }

    fn conflict(revision: u64) -> StoreError {
        StoreError::new(
            StoreErrorKind::ResourceConflict,
            Some(ZoneRevision::new(revision)),
            None,
            RetryClass::Reauthorize,
            "guest-target-resource-revision-changed",
        )
    }

    fn parse_resource(
        &self,
        target: &ResourceRef,
        canonical: &[u8],
    ) -> Result<(ResourceUid, ResourceGeneration), StoreError> {
        let envelope = parse_uid_free_envelope(canonical)
            .map_err(|_| Self::invalid("guest-target-resource-envelope-invalid"))?;
        let envelope_ref = ResourceRef::new(
            envelope.resource_type().clone(),
            envelope.metadata().name().clone(),
        );
        if &envelope_ref != target || envelope.metadata().zone() != &self.zone {
            return Err(Self::invalid("guest-target-resource-identity-mismatch"));
        }
        if matches!(
            target.resource_type().as_str(),
            "Process" | "EphemeralProcess" | NIXOS_GENERATION_RESOURCE_TYPE
        ) {
            let execution_ref = envelope
                .spec()
                .base()
                .get("executionRef")
                .and_then(|value| match value {
                    d2b_contracts_resource::v3::CanonicalJsonValue::String(value) => {
                        ResourceRef::parse(value).ok()
                    }
                    _ => None,
                })
                .ok_or_else(|| Self::invalid("guest-target-execution-ref-missing"))?;
            if self.target.as_ref() != Some(&execution_ref) {
                return Err(Self::invalid("guest-target-execution-ref-mismatch"));
            }
        }
        Ok((
            envelope.metadata().uid().clone(),
            envelope.metadata().generation(),
        ))
    }

    fn validate_mutation_body(&self, body: &MutationSealBody) -> Result<(), StoreError> {
        if body.authorization.zone != self.zone {
            return Err(Self::invalid("guest-target-authorization-zone-mismatch"));
        }
        for prepared in &body.mutations {
            let mutation = prepared.mutation();
            if mutation.zone != self.zone {
                return Err(Self::invalid("guest-target-resource-zone-mismatch"));
            }
            if !Self::is_target_local_type(mutation.target.resource_type()) {
                return Err(Self::forbidden());
            }
            if self.target.as_ref().is_some_and(|target| {
                !body.authorization.targets.iter().any(|authorization| {
                    authorization.resource_type == *mutation.target.resource_type()
                        && authorization
                            .resource_name
                            .as_ref()
                            .is_some_and(|name| name == mutation.target.name())
                        && authorization.execution_ref.as_ref() == Some(target)
                })
            }) {
                return Err(Self::invalid("guest-target-authorization-target-mismatch"));
            }
            if !matches!(
                mutation.target.resource_type().as_str(),
                "Process" | "EphemeralProcess" | NIXOS_GENERATION_RESOURCE_TYPE
            ) {
                continue;
            }
            if let Some(canonical) = mutation.canonical_resource.as_deref() {
                self.parse_resource(&mutation.target, canonical)?;
            }
        }
        Ok(())
    }

    async fn commit_verified_with_fence(
        &self,
        sealed: SealedMutation,
        commit_fence: Option<CommitFence>,
    ) -> Result<StoreCommitResult, StoreError> {
        match &self.backend {
            GuestStoreBackend::Durable(store) => {
                if let Some(commit_fence) = commit_fence {
                    store
                        .commit_verified_with_fence(
                            sealed,
                            |body| self.validate_mutation_body(body),
                            move || commit_fence(),
                        )
                        .await
                } else {
                    store
                        .commit_verified_with(sealed, |body| self.validate_mutation_body(body))
                        .await
                }
            }
            GuestStoreBackend::Memory { acceptor, state } => {
                let opened = acceptor.open(sealed)?;
                self.validate_mutation_body(opened.body())?;
                let body = opened.into_body();
                let mut state = state
                    .lock()
                    .map_err(|_| Self::unavailable("guest-target-store-poisoned"))?;
                let mut resources = state.resources.clone();
                let next_revision = state
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| Self::unavailable("guest-target-store-revision-exhausted"))?;
                let mut changed = Vec::new();
                for prepared in body.mutations {
                    let mutation = prepared.mutation();
                    if mutation.zone != self.zone {
                        return Err(Self::invalid("guest-target-resource-zone-mismatch"));
                    }
                    if !Self::is_target_local_type(mutation.target.resource_type()) {
                        return Err(Self::forbidden());
                    }
                    let current = resources.get(&mutation.target).cloned();
                    match mutation.expected {
                        ExpectedRevision::CreateAbsent if current.is_some() => {
                            return Err(StoreError::new(
                                StoreErrorKind::ResourceAlreadyExists,
                                Some(ZoneRevision::new(state.revision)),
                                None,
                                RetryClass::Never,
                                "guest-target-resource-already-exists",
                            ));
                        }
                        ExpectedRevision::Exact(expected)
                            if current
                                .as_ref()
                                .is_none_or(|resource| resource.revision != expected) =>
                        {
                            return Err(Self::conflict(state.revision));
                        }
                        _ => {}
                    }
                    if let Some(expected_uid) = mutation.expected_uid.as_ref()
                        && current
                            .as_ref()
                            .is_some_and(|resource| &resource.uid != expected_uid)
                    {
                        return Err(Self::conflict(state.revision));
                    }
                    if mutation.kind == ResourceMutationKind::Delete {
                        let removed = resources
                            .remove(&mutation.target)
                            .ok_or_else(Self::not_found)?;
                        changed.push(removed);
                        continue;
                    }
                    let canonical = mutation
                        .canonical_resource
                        .clone()
                        .or_else(|| {
                            current
                                .as_ref()
                                .map(|resource| resource.canonical_json.clone())
                        })
                        .ok_or_else(|| Self::invalid("guest-target-resource-body-missing"))?;
                    let (envelope_uid, generation) =
                        self.parse_resource(&mutation.target, &canonical)?;
                    let uid = prepared.resource_uid().cloned().unwrap_or(envelope_uid);
                    if current.as_ref().is_some_and(|resource| resource.uid != uid) {
                        return Err(Self::conflict(state.revision));
                    }
                    let payload_digest = prepared
                        .payload_digest()
                        .map(str::to_owned)
                        .unwrap_or_else(|| {
                            d2b_contracts_resource::v3::canonical_digest(
                                d2b_contracts_resource::v3::resource_schema::RESOURCE_ENVELOPE_DOMAIN_TAG,
                                &canonical,
                            )
                        });
                    let resource = StoredResource {
                        resource_ref: mutation.target.clone(),
                        zone: self.zone.clone(),
                        uid,
                        generation,
                        revision: ZoneRevision::new(next_revision),
                        canonical_json: canonical,
                        payload_digest,
                    };
                    resources.insert(mutation.target.clone(), resource.clone());
                    changed.push(resource);
                }
                state.revision = next_revision;
                state.resources = resources;
                Ok(StoreCommitResult {
                    resources: changed,
                    revision: ZoneRevision::new(next_revision),
                })
            }
        }
    }
}

impl ResourceStoreBackend for GuestResourceStore {
    async fn get(&self, request: StoreGetRequest) -> Result<StoredResource, StoreError> {
        if request.zone != self.zone {
            return Err(Self::not_found());
        }
        if !Self::is_target_local_type(request.target.resource_type()) {
            return Err(Self::forbidden());
        }
        match &self.backend {
            GuestStoreBackend::Durable(store) => store.get(request).await,
            GuestStoreBackend::Memory { state, .. } => {
                let state = state
                    .lock()
                    .map_err(|_| Self::unavailable("guest-target-store-poisoned"))?;
                let resource = state
                    .resources
                    .get(&request.target)
                    .ok_or_else(Self::not_found)?;
                if request
                    .expected_uid
                    .as_ref()
                    .is_some_and(|uid| uid != &resource.uid)
                {
                    return Err(Self::not_found());
                }
                Ok(resource.clone())
            }
        }
    }

    async fn list(&self, request: StoreListRequest) -> Result<StoreListResult, StoreError> {
        if request.zone != self.zone {
            return Err(Self::not_found());
        }
        if request
            .resource_types
            .iter()
            .any(|resource_type| !Self::is_target_local_type(resource_type))
        {
            return Err(Self::forbidden());
        }
        match &self.backend {
            GuestStoreBackend::Durable(store) => store.list(request).await,
            GuestStoreBackend::Memory { state, .. } => {
                let state = state
                    .lock()
                    .map_err(|_| Self::unavailable("guest-target-store-poisoned"))?;
                let mut resources = state
                    .resources
                    .values()
                    .filter(|resource| {
                        (request.resource_types.is_empty()
                            || request
                                .resource_types
                                .iter()
                                .any(|kind| kind == resource.resource_ref.resource_type()))
                            && (request.resource_names.is_empty()
                                || request
                                    .resource_names
                                    .iter()
                                    .any(|name| name == resource.resource_ref.name()))
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                let page_size = usize::try_from(request.page_size).unwrap_or(usize::MAX);
                let truncated = resources.len() > page_size;
                resources.truncate(page_size);
                Ok(StoreListResult {
                    resources,
                    snapshot_revision: ZoneRevision::new(state.revision),
                    next_cursor: None,
                    truncated,
                })
            }
        }
    }

    async fn watch(&self, request: StoreWatchRequest) -> Result<StoreWatchReceipt, StoreError> {
        if request.zone != self.zone {
            return Err(Self::not_found());
        }
        if request
            .resource_types
            .iter()
            .any(|resource_type| !Self::is_target_local_type(resource_type))
        {
            return Err(Self::forbidden());
        }
        match &self.backend {
            GuestStoreBackend::Durable(store) => store.watch(request).await,
            GuestStoreBackend::Memory { state, .. } => {
                let mut state = state
                    .lock()
                    .map_err(|_| Self::unavailable("guest-target-store-poisoned"))?;
                state.next_watch = state.next_watch.saturating_add(1);
                Ok(StoreWatchReceipt {
                    stream_name: format!("{WATCH_STREAM_PREFIX}-{}", state.next_watch),
                    snapshot_revision: ZoneRevision::new(state.revision),
                })
            }
        }
    }

    async fn resolve_ref(
        &self,
        request: StoreResolveRequest,
    ) -> Result<StoreResolvedIdentity, StoreError> {
        let resource = self
            .get(StoreGetRequest {
                operation: request.operation,
                zone: request.zone,
                target: request.target,
                expected_uid: request.expected_uid,
                projection: d2b_resource_store::StoreProjection::MetadataOnly,
            })
            .await?;
        Ok(StoreResolvedIdentity {
            zone: resource.zone,
            resource_ref: resource.resource_ref,
            uid: resource.uid,
            generation: resource.generation,
            revision: resource.revision,
        })
    }

    async fn inspect_schema(
        &self,
        request: StoreInspectSchemaRequest,
    ) -> Result<StoredSchema, StoreError> {
        if request.zone != self.zone {
            return Err(Self::not_found());
        }
        if !Self::is_target_local_type(&request.resource_type) {
            return Err(Self::forbidden());
        }
        match &self.backend {
            GuestStoreBackend::Durable(store) => store.inspect_schema(request).await,
            GuestStoreBackend::Memory { .. } => {
                let canonical = d2b_contracts_resource::v3::CanonicalJsonValue::parse(SCHEMA_BYTES)
                    .map_err(|_| Self::invalid("guest-target-schema-invalid"))?
                    .to_canonical_bytes();
                Ok(StoredSchema {
                    resource_type: request.resource_type,
                    payload_digest: d2b_contracts_resource::v3::canonical_digest(
                        SCHEMA_DOMAIN_TAG,
                        &canonical,
                    ),
                    canonical_json: canonical,
                })
            }
        }
    }

    async fn commit_verified(
        &self,
        sealed: SealedMutation,
    ) -> Result<StoreCommitResult, StoreError> {
        self.commit_verified_with_fence(sealed, None).await
    }
}

fn open_owned_file(path: &Path) -> Result<File, GuestResourceRuntimeError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| GuestResourceRuntimeError::Store)?;
    let metadata = file
        .metadata()
        .map_err(|_| GuestResourceRuntimeError::Store)?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(GuestResourceRuntimeError::Store);
    }
    Ok(file)
}

fn map_store_error(error: StoreError) -> GuestResourceRuntimeError {
    if error.kind() == StoreErrorKind::StoreQuarantined {
        GuestResourceRuntimeError::StoreQuarantined
    } else {
        GuestResourceRuntimeError::Store
    }
}

#[derive(Clone, Copy)]
enum GuestSeedMethod {
    CommitBatch,
    Watch,
}

struct GuestSeedMethodHandler {
    inner: Box<dyn MethodHandler + Send + Sync>,
    method: GuestSeedMethod,
    guest_ref: ResourceRef,
    guest_uid: ResourceUid,
    zone: ZoneId,
    descriptor_digest: Option<SchemaFingerprint>,
    approved_types: BTreeSet<ResourceTypeName>,
}

#[async_trait]
impl MethodHandler for GuestSeedMethodHandler {
    async fn handler(
        &self,
        context: TtrpcContext,
        request: TtrpcRequest,
    ) -> ttrpc::Result<TtrpcResponse> {
        match self.method {
            GuestSeedMethod::CommitBatch => {
                let request = wire::CommitBatchRequest::parse_from_bytes(&request.payload)
                    .map_err(|_| {
                        ttrpc::Error::Others("guest-resource-seed-request-invalid".to_owned())
                    })?;
                validate_seed_request(
                    &request,
                    &self.guest_ref,
                    &self.guest_uid,
                    &self.zone,
                    self.descriptor_digest.as_ref(),
                    &self.approved_types,
                )
                .map_err(|_| {
                    ttrpc::Error::Others("guest-resource-seed-request-invalid".to_owned())
                })?;
            }
            GuestSeedMethod::Watch => {
                let request =
                    wire::WatchRequest::parse_from_bytes(&request.payload).map_err(|_| {
                        ttrpc::Error::Others("guest-resource-seed-request-invalid".to_owned())
                    })?;
                validate_watch_request(&request, &self.approved_types).map_err(|_| {
                    ttrpc::Error::Others("guest-resource-seed-request-invalid".to_owned())
                })?;
            }
        }
        self.inner.handler(context, request).await
    }
}

fn restricted_seed_services(
    mut services: std::collections::HashMap<String, ttrpc::r#async::Service>,
    guest_ref: &ResourceRef,
    guest_uid: &ResourceUid,
    zone: &ZoneId,
    descriptor_digest: Option<&SchemaFingerprint>,
    approved_types: &BTreeSet<ResourceTypeName>,
) -> std::collections::HashMap<String, ttrpc::r#async::Service> {
    services.retain(|name, _| name == "d2b.resource.v3.ResourceService");
    let Some(service) = services.get_mut("d2b.resource.v3.ResourceService") else {
        return services;
    };
    let methods = std::mem::take(&mut service.methods);
    service.methods = methods
        .into_iter()
        .filter_map(|(name, inner)| {
            let method = match name.as_str() {
                "CommitBatch" if guest_seed_operation_is_admitted(name.as_str()) => {
                    GuestSeedMethod::CommitBatch
                }
                "Watch" => GuestSeedMethod::Watch,
                _ => return None,
            };
            Some((
                name,
                Box::new(GuestSeedMethodHandler {
                    inner,
                    method,
                    guest_ref: guest_ref.clone(),
                    guest_uid: guest_uid.clone(),
                    zone: zone.clone(),
                    descriptor_digest: descriptor_digest.cloned(),
                    approved_types: approved_types.clone(),
                }) as Box<dyn MethodHandler + Send + Sync>,
            ))
        })
        .collect();
    service.streams.clear();
    services
}

fn guest_seed_operation_is_admitted(method: &str) -> bool {
    d2b_session::SessionOperation::method(
        d2b_contracts_resource::v3::identity::ServiceName::parse("d2b.resource.v3")
            .expect("fixed Resource service"),
        format!("ResourceService/{method}"),
    )
    .is_ok_and(|operation| operation.is_guest_resource_commit_batch())
}

fn validate_seed_request(
    request: &wire::CommitBatchRequest,
    guest_ref: &ResourceRef,
    guest_uid: &ResourceUid,
    zone: &ZoneId,
    descriptor_digest: Option<&SchemaFingerprint>,
    approved_types: &BTreeSet<ResourceTypeName>,
) -> Result<(), GuestResourceRuntimeError> {
    let meta = request
        .meta
        .as_ref()
        .ok_or(GuestResourceRuntimeError::SeedInvalid)?;
    if !valid_seed_operation_id(&meta.operation_id)
        || !valid_seed_operation_id(&meta.idempotency_key)
        || meta.correlation_id != meta.operation_id
        || meta.trace_id != meta.operation_id
        || meta.deadline_ms == 0
        || request.mutations.is_empty()
        || request.mutations.len() > 128
        || !request.scoped_admission.is_empty()
    {
        return Err(GuestResourceRuntimeError::SeedInvalid);
    }
    let mut resource_digests = Vec::with_capacity(request.mutations.len());
    let mut seed_targets = Vec::with_capacity(request.mutations.len());
    for mutation in &request.mutations {
        if mutation.kind.enum_value() != Ok(wire::MutationKind::MUTATION_KIND_CREATE) {
            return Err(GuestResourceRuntimeError::SeedInvalid);
        }
        let target = mutation
            .target
            .as_ref()
            .ok_or(GuestResourceRuntimeError::SeedInvalid)?;
        let target_type = ResourceTypeName::parse(&target.resource_type)
            .map_err(|_| GuestResourceRuntimeError::SeedInvalid)?;
        if !approved_types.contains(&target_type)
            || target.zone != zone.as_str()
            || target.name.is_empty()
            || target.uid.is_some()
            || target.generation.is_some()
            || target.revision.is_some()
        {
            return Err(GuestResourceRuntimeError::SeedInvalid);
        }
        seed_targets.push((
            ResourceRef::new(
                target_type.clone(),
                ResourceName::parse(target.name.clone())
                    .map_err(|_| GuestResourceRuntimeError::SeedInvalid)?,
            ),
            ResourceVerb::Create,
        ));
        let owner = mutation
            .owner
            .as_ref()
            .ok_or(GuestResourceRuntimeError::SeedInvalid)?;
        if owner.zone != zone.as_str()
            || owner.resource_type != "Guest"
            || owner.name != guest_ref.name().as_str()
            || owner.uid.as_deref() != Some(guest_uid.as_str())
        {
            return Err(GuestResourceRuntimeError::SeedInvalid);
        }
        let precondition = mutation
            .precondition
            .as_ref()
            .ok_or(GuestResourceRuntimeError::SeedInvalid)?;
        if precondition.kind.enum_value()
            != Ok(wire::PreconditionKind::PRECONDITION_KIND_CREATE_ABSENT)
            || precondition.expected_revision.is_some()
            || precondition.expected_uid.is_some()
        {
            return Err(GuestResourceRuntimeError::SeedInvalid);
        }
        let resource = mutation
            .resource
            .as_ref()
            .ok_or(GuestResourceRuntimeError::SeedInvalid)?;
        if resource.identity.as_ref().is_none_or(|identity| {
            identity.zone != zone.as_str()
                || identity.resource_type != target.resource_type
                || identity.name != target.name
                || identity.uid.is_some()
                || identity.generation.is_some()
                || identity.revision.is_some()
        }) || resource.payload_digest
            != d2b_contracts_resource::v3::canonical_digest(
                RESOURCE_ENVELOPE_DOMAIN_TAG,
                &resource.canonical_json,
            )
        {
            return Err(GuestResourceRuntimeError::SeedInvalid);
        }
        validate_seed_payload(
            &resource.canonical_json,
            &target_type,
            &target.name,
            guest_ref,
            zone,
        )?;
        resource_digests.push((
            format!("{}/{}", target.resource_type, target.name),
            d2b_contracts_resource::v3::canonical_digest(
                GUEST_SEED_DIGEST_DOMAIN,
                &resource.canonical_json,
            ),
        ));
    }
    let call = d2b_bus::ResourceCall::CommitBatch(seed_targets);
    if call.validate_guest_local_seed(approved_types).is_err() {
        return Err(GuestResourceRuntimeError::SeedInvalid);
    }
    resource_digests.sort_unstable();
    if let Some(descriptor_digest) = descriptor_digest {
        let mut key_material = Vec::new();
        key_material.extend_from_slice(guest_uid.as_str().as_bytes());
        key_material.extend_from_slice(descriptor_digest.as_str().as_bytes());
        key_material.extend_from_slice(meta.operation_id.as_bytes());
        for (target, digest) in resource_digests {
            key_material.extend_from_slice(target.as_bytes());
            key_material.extend_from_slice(digest.as_bytes());
        }
        if meta.idempotency_key
            != d2b_contracts_resource::v3::canonical_digest(GUEST_SEED_DIGEST_DOMAIN, &key_material)
        {
            return Err(GuestResourceRuntimeError::SeedInvalid);
        }
    }
    Ok(())
}

fn validate_watch_request(
    request: &wire::WatchRequest,
    approved_types: &BTreeSet<ResourceTypeName>,
) -> Result<(), GuestResourceRuntimeError> {
    let meta = request
        .meta
        .as_ref()
        .ok_or(GuestResourceRuntimeError::SeedInvalid)?;
    if !valid_seed_operation_id(&meta.operation_id)
        || request.resource_types.is_empty()
        || request.resource_types.iter().any(|resource_type| {
            ResourceTypeName::parse(resource_type)
                .ok()
                .is_none_or(|resource_type| !approved_types.contains(&resource_type))
        })
        || request
            .credits
            .as_ref()
            .is_none_or(|credits| credits.initial == 0)
        || request
            .filters
            .iter()
            .any(|filter| filter.field != "metadata.name" || filter.values.is_empty())
    {
        return Err(GuestResourceRuntimeError::SeedInvalid);
    }
    Ok(())
}

fn validate_seed_payload(
    canonical: &[u8],
    target_type: &ResourceTypeName,
    target_name: &str,
    guest_ref: &ResourceRef,
    zone: &ZoneId,
) -> Result<(), GuestResourceRuntimeError> {
    let value = d2b_contracts_resource::v3::CanonicalJsonValue::parse(canonical)
        .map_err(|_| GuestResourceRuntimeError::SeedInvalid)?;
    if value.to_canonical_bytes() != canonical {
        return Err(GuestResourceRuntimeError::SeedInvalid);
    }
    parse_uid_free_envelope(canonical).map_err(|_| GuestResourceRuntimeError::SeedInvalid)?;
    let value: serde_json::Value =
        serde_json::from_slice(canonical).map_err(|_| GuestResourceRuntimeError::SeedInvalid)?;
    let object = value
        .as_object()
        .ok_or(GuestResourceRuntimeError::SeedInvalid)?;
    if object.get("apiVersion").and_then(serde_json::Value::as_str)
        != Some("resources.d2bus.org/v3")
        || !object.contains_key("status")
    {
        return Err(GuestResourceRuntimeError::SeedInvalid);
    }
    if object.get("type").and_then(serde_json::Value::as_str) != Some(target_type.as_str()) {
        return Err(GuestResourceRuntimeError::SeedInvalid);
    }
    let metadata = object
        .get("metadata")
        .and_then(serde_json::Value::as_object)
        .ok_or(GuestResourceRuntimeError::SeedInvalid)?;
    if metadata.get("uid").is_some()
        || metadata.get("name").and_then(serde_json::Value::as_str) != Some(target_name)
        || metadata.get("zone").and_then(serde_json::Value::as_str) != Some(zone.as_str())
        || metadata.get("ownerRef").and_then(serde_json::Value::as_str)
            != Some(guest_ref.to_canonical_string().as_str())
        || contains_seed_private_field(&value)
    {
        return Err(GuestResourceRuntimeError::SeedInvalid);
    }
    let spec = object
        .get("spec")
        .and_then(serde_json::Value::as_object)
        .ok_or(GuestResourceRuntimeError::SeedInvalid)?;
    let relationship = if target_type.as_str() == "Endpoint" {
        spec.get("producerRef")
    } else {
        spec.get("executionRef")
    };
    if relationship.and_then(serde_json::Value::as_str)
        != Some(guest_ref.to_canonical_string().as_str())
    {
        return Err(GuestResourceRuntimeError::SeedInvalid);
    }
    Ok(())
}

fn contains_seed_private_field(value: &serde_json::Value) -> bool {
    const PRIVATE_KEYS: &[&str] = &[
        "argv",
        "cid",
        "credential",
        "credentials",
        "environment",
        "endpoint",
        "fd",
        "gid",
        "hostpath",
        "key",
        "locator",
        "password",
        "path",
        "pid",
        "port",
        "secret",
        "socket",
        "socketpath",
        "storepath",
        "token",
        "uid",
        "vsock",
    ];
    match value {
        serde_json::Value::Object(object) => object.iter().any(|(key, value)| {
            PRIVATE_KEYS.contains(&key.to_ascii_lowercase().as_str())
                || contains_seed_private_field(value)
        }),
        serde_json::Value::Array(values) => values.iter().any(contains_seed_private_field),
        serde_json::Value::String(value) => value.starts_with('/') || value.contains("/nix/store/"),
        _ => false,
    }
}

fn valid_seed_operation_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
}

fn parse_uid_free_envelope(canonical: &[u8]) -> Result<ResourceEnvelope, ()> {
    if let Ok(envelope) = ResourceEnvelope::from_json(canonical) {
        return Ok(envelope);
    }
    let mut value: serde_json::Value = serde_json::from_slice(canonical).map_err(|_| ())?;
    let metadata = value
        .get_mut("metadata")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or(())?;
    if metadata.contains_key("uid") {
        return Err(());
    }
    metadata.insert(
        "uid".to_owned(),
        serde_json::Value::String("00000000-0000-4000-8000-000000000000".to_owned()),
    );
    let with_uid = serde_json::to_vec(&value).map_err(|_| ())?;
    let with_uid = d2b_contracts_resource::v3::CanonicalJsonValue::parse(&with_uid)
        .map_err(|_| ())?
        .to_canonical_bytes();
    ResourceEnvelope::from_json(&with_uid).map_err(|_| ())
}

pub struct SessionBoundStore {
    store: Arc<GuestResourceStore>,
    active_generation: Arc<Mutex<Option<u64>>>,
    generation: u64,
}

impl SessionBoundStore {
    fn ensure_current(&self) -> Result<(), StoreError> {
        let active = self
            .active_generation
            .lock()
            .map_err(|_| GuestResourceStore::unavailable("guest-target-session-state-poisoned"))?;
        if *active != Some(self.generation) {
            return Err(GuestResourceStore::unavailable(
                "guest-target-session-stale",
            ));
        }
        Ok(())
    }

    /// Open the current session's revision-resumable resource watch.
    pub async fn open_resource_watch(
        &self,
        request: StoreWatchRequest,
    ) -> Result<ResourceWatch, StoreError> {
        self.ensure_current()?;
        self.store.open_resource_watch(request).await
    }

    /// Verify that this session generation still owns its store.
    pub fn ensure_session_current(&self) -> Result<(), StoreError> {
        self.ensure_current()
    }
}

impl ResourceStoreBackend for SessionBoundStore {
    async fn get(&self, request: StoreGetRequest) -> Result<StoredResource, StoreError> {
        self.ensure_current()?;
        self.store.get(request).await
    }

    async fn list(&self, request: StoreListRequest) -> Result<StoreListResult, StoreError> {
        self.ensure_current()?;
        self.store.list(request).await
    }

    async fn watch(&self, request: StoreWatchRequest) -> Result<StoreWatchReceipt, StoreError> {
        self.ensure_current()?;
        self.store.watch(request).await
    }

    async fn resolve_ref(
        &self,
        request: StoreResolveRequest,
    ) -> Result<StoreResolvedIdentity, StoreError> {
        self.ensure_current()?;
        self.store.resolve_ref(request).await
    }

    async fn inspect_schema(
        &self,
        request: StoreInspectSchemaRequest,
    ) -> Result<StoredSchema, StoreError> {
        self.ensure_current()?;
        self.store.inspect_schema(request).await
    }

    async fn commit_verified(
        &self,
        mutation: SealedMutation,
    ) -> Result<StoreCommitResult, StoreError> {
        self.ensure_current()?;
        let active_generation = Arc::clone(&self.active_generation);
        let generation = self.generation;
        let commit_fence: CommitFence = Arc::new(move || {
            let active = active_generation.lock().map_err(|_| {
                GuestResourceStore::unavailable("guest-target-session-state-poisoned")
            })?;
            if *active == Some(generation) {
                Ok(())
            } else {
                Err(GuestResourceStore::unavailable(
                    "guest-target-session-stale",
                ))
            }
        });
        self.store
            .commit_verified_with_fence(mutation, Some(commit_fence))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use d2b_resource_store::mutation_seal::StoreSealIdentity;
    use protobuf::{EnumOrUnknown, MessageField};

    fn test_identity() -> GuestIdentity {
        GuestIdentity::new(
            ResourceRef::parse("Guest/work").expect("guest ref"),
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").expect("guest uid"),
            ZoneId::parse("work").expect("zone"),
            crate::guest_mode::BootIdentity::from_kernel_boot_id("u6-test-boot")
                .expect("boot identity"),
            d2b_contracts_resource::v3::identity::SessionPurpose::parse("zone-link")
                .expect("purpose"),
            d2b_contracts_resource::v3::SchemaFingerprint::parse(format!(
                "sha256:{}",
                "1".repeat(64)
            ))
            .expect("schema"),
            d2b_contracts_resource::v3::identity::ReconnectGeneration::new(1).expect("generation"),
            1,
            1,
            1,
        )
        .expect("identity")
    }

    #[tokio::test]
    async fn target_local_store_is_reopened_from_guest_state() {
        let directory = tempfile::tempdir().expect("state directory");
        let identity = test_identity();
        let first = GuestResourceRuntime::new(identity.clone(), directory.path())
            .await
            .expect("initial target-local runtime");
        assert!(directory.path().join("resource-store.redb").is_file());
        assert!(directory.path().join("resource-store.marker").is_file());
        drop(first);

        let second = GuestResourceRuntime::new(identity, directory.path())
            .await
            .expect("restarted target-local runtime");
        let listed = second
            .store
            .list(StoreListRequest {
                operation: d2b_resource_store::StoreOperationContext {
                    operation_id: "u6-reopen-list".to_owned(),
                    idempotency_key: None,
                    correlation_id: "u6-reopen-list".to_owned(),
                    trace_id: None,
                    deadline_ms: 1_000,
                },
                zone: ZoneId::parse("work").expect("zone"),
                resource_types: Vec::new(),
                resource_names: Vec::new(),
                filters: Vec::new(),
                page_size: 16,
                cursor: None,
                projection: d2b_resource_store::StoreProjection::MetadataOnly,
            })
            .await
            .expect("reopened store list");
        assert!(listed.resources.is_empty());
    }

    #[test]
    fn session_bound_store_rejects_an_old_session_generation() {
        let zone = ZoneId::parse("work").expect("zone");
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").expect("store UID");
        let store_identity = StoreSealIdentity::new(
            d2b_resource_store::StoreSlot::new(STORE_SLOT).expect("store slot"),
            zone.clone(),
            uid,
        );
        let (_, acceptor) = d2b_resource_store::mutation_seal::mutation_seal_pair(store_identity);
        let store = Arc::new(GuestResourceStore::new_in_memory(zone, acceptor));
        let active_generation = Arc::new(Mutex::new(Some(2)));
        let bound = SessionBoundStore {
            store,
            active_generation,
            generation: 1,
        };

        let error = bound
            .ensure_current()
            .expect_err("an older session generation must be fenced");
        assert_eq!(error.kind(), StoreErrorKind::ResourcePlaneUnavailable);
    }

    #[tokio::test]
    async fn partial_target_local_store_is_quarantined_without_repair() {
        let directory = tempfile::tempdir().expect("state directory");
        File::create(directory.path().join(STORE_FILE_NAME)).expect("database placeholder");
        let error = GuestResourceRuntime::new(test_identity(), directory.path())
            .await
            .expect_err("partial store must fail closed");
        assert_eq!(error, GuestResourceRuntimeError::StoreQuarantined);
        assert!(!directory.path().join(STORE_MARKER_NAME).exists());
    }

    #[test]
    fn target_local_store_rejects_zone_authority_types() {
        assert!(GuestResourceStore::is_target_local_type(
            &ResourceTypeName::parse("Process").expect("Process type")
        ));
        assert!(GuestResourceStore::is_target_local_type(
            &ResourceTypeName::parse("EphemeralProcess").expect("EphemeralProcess type")
        ));
        assert!(GuestResourceStore::is_target_local_type(
            &ResourceTypeName::parse("Endpoint").expect("Endpoint type")
        ));
        assert!(GuestResourceStore::is_target_local_type(
            &ResourceTypeName::parse(NIXOS_GENERATION_RESOURCE_TYPE)
                .expect("NixOS generation type")
        ));
        assert!(!GuestResourceStore::is_target_local_type(
            &ResourceTypeName::parse("Zone").expect("Zone type")
        ));
        assert!(!GuestResourceStore::is_target_local_type(
            &ResourceTypeName::parse("Role").expect("Role type")
        ));
    }

    #[tokio::test]
    async fn target_local_store_rejects_schema_reads_for_zone_types() {
        let zone = ZoneId::parse("work").expect("zone");
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").expect("store UID");
        let store_identity = StoreSealIdentity::new(
            d2b_resource_store::StoreSlot::new(STORE_SLOT).expect("store slot"),
            zone.clone(),
            uid,
        );
        let (_, acceptor) = d2b_resource_store::mutation_seal::mutation_seal_pair(store_identity);
        let store = GuestResourceStore::new_in_memory(zone.clone(), acceptor);
        let error = store
            .inspect_schema(StoreInspectSchemaRequest {
                operation: d2b_resource_store::StoreOperationContext {
                    operation_id: "schema".to_owned(),
                    idempotency_key: None,
                    correlation_id: "schema".to_owned(),
                    trace_id: None,
                    deadline_ms: 1,
                },
                zone,
                resource_type: ResourceTypeName::parse("Zone").expect("Zone type"),
            })
            .await
            .expect_err("Zone schema is not target-local");
        assert_eq!(error.kind(), StoreErrorKind::AuthorizationDenied);
    }

    #[tokio::test]
    async fn target_local_store_rejects_watches_for_zone_types() {
        let zone = ZoneId::parse("work").expect("zone");
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").expect("store UID");
        let store_identity = StoreSealIdentity::new(
            d2b_resource_store::StoreSlot::new(STORE_SLOT).expect("store slot"),
            zone.clone(),
            uid,
        );
        let (_, acceptor) = d2b_resource_store::mutation_seal::mutation_seal_pair(store_identity);
        let store = GuestResourceStore::new_in_memory(zone.clone(), acceptor);
        let error = store
            .watch(StoreWatchRequest {
                operation: d2b_resource_store::StoreOperationContext {
                    operation_id: "watch".to_owned(),
                    idempotency_key: None,
                    correlation_id: "watch".to_owned(),
                    trace_id: None,
                    deadline_ms: 1,
                },
                zone,
                resource_types: vec![ResourceTypeName::parse("Zone").expect("Zone type")],
                resource_names: Vec::new(),
                filters: Vec::new(),
                after_revision: ZoneRevision::new(0),
                initial_credits: 1,
                projection: d2b_resource_store::StoreProjection::MetadataOnly,
            })
            .await
            .expect_err("Zone watch is not target-local");
        assert_eq!(error.kind(), StoreErrorKind::AuthorizationDenied);
    }

    fn seed_request(kind: &str, name: &str) -> wire::CommitBatchRequest {
        let guest_ref = ResourceRef::parse("Guest/work").expect("guest ref");
        let guest_uid =
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").expect("guest uid");
        let zone = ZoneId::parse("work").expect("zone");
        let descriptor = SchemaFingerprint::parse(format!("sha256:{}", "d".repeat(64)))
            .expect("descriptor digest");
        let raw = format!(
            r#"{{"apiVersion":"resources.d2bus.org/v3","metadata":{{"createdAt":"2026-08-29T00:00:00.000Z","deletionRequestedAt":null,"finalizers":[],"generation":1,"managedBy":"controller","name":"{name}","ownerRef":"Guest/work","revision":1,"updatedAt":"2026-08-29T00:00:00.000Z","zone":"work"}},"spec":{{"executionRef":"Guest/work"}},"status":{{"completedAt":null,"conditions":[],"lastReconciledAt":null,"observedGeneration":0,"outcome":null,"phase":"Pending","resource":{{}},"update":{{"dependencies":{{"count":0,"refs":[]}},"disruption":"None","lastAssessedAt":null,"observedGeneration":0,"operationId":null,"owned":{{"count":0,"refs":[]}},"preserveState":true,"reasons":[],"state":"Unknown","targetGeneration":1}},"startedAt":null}},"type":"{kind}"}}"#
        );
        let payload = d2b_contracts_resource::v3::CanonicalJsonValue::parse(raw.as_bytes())
            .expect("canonical payload")
            .to_canonical_bytes();
        let mut target = wire::ResourceIdentity::new();
        target.zone = zone.as_str().to_owned();
        target.resource_type = kind.to_owned();
        target.name = name.to_owned();
        let mut owner = wire::ResourceIdentity::new();
        owner.zone = zone.as_str().to_owned();
        owner.resource_type = "Guest".to_owned();
        owner.name = guest_ref.name().as_str().to_owned();
        owner.uid = Some(guest_uid.as_str().to_owned());
        let mut precondition = wire::Precondition::new();
        precondition.kind =
            EnumOrUnknown::new(wire::PreconditionKind::PRECONDITION_KIND_CREATE_ABSENT);
        let mut body = wire::ResourceEnvelopeBytes::new();
        body.identity = MessageField::some(target.clone());
        body.canonical_json = payload.clone();
        body.payload_digest =
            d2b_contracts_resource::v3::canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &payload);
        let mut mutation = wire::Mutation::new();
        mutation.kind = EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_CREATE);
        mutation.target = MessageField::some(target);
        mutation.owner = MessageField::some(owner);
        mutation.precondition = MessageField::some(precondition);
        mutation.resource = MessageField::some(body);
        let resource_digest =
            d2b_contracts_resource::v3::canonical_digest(GUEST_SEED_DIGEST_DOMAIN, &payload);
        let mut key_material = Vec::new();
        key_material.extend_from_slice(guest_uid.as_str().as_bytes());
        key_material.extend_from_slice(descriptor.as_str().as_bytes());
        key_material.extend_from_slice(b"seed");
        key_material.extend_from_slice(format!("{kind}/{name}").as_bytes());
        key_material.extend_from_slice(resource_digest.as_bytes());
        let mut meta = wire::RequestMeta::new();
        meta.operation_id = "seed".to_owned();
        meta.idempotency_key =
            d2b_contracts_resource::v3::canonical_digest(GUEST_SEED_DIGEST_DOMAIN, &key_material);
        meta.correlation_id = "seed".to_owned();
        meta.trace_id = "seed".to_owned();
        meta.deadline_ms = 30_000;
        let mut request = wire::CommitBatchRequest::new();
        request.meta = MessageField::some(meta);
        request.mutations = vec![mutation];
        request
    }

    #[test]
    fn guest_seed_admission_is_commit_batch_only_and_descriptor_scoped() {
        let guest_ref = ResourceRef::parse("Guest/work").expect("guest ref");
        let guest_uid =
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").expect("guest uid");
        let zone = ZoneId::parse("work").expect("zone");
        let descriptor = SchemaFingerprint::parse(format!("sha256:{}", "d".repeat(64)))
            .expect("descriptor digest");
        let approved = GUEST_SEED_RESOURCE_TYPES
            .iter()
            .map(|resource_type| ResourceTypeName::parse(*resource_type).expect("seed type"))
            .collect::<BTreeSet<_>>();
        assert!(
            validate_seed_request(
                &seed_request("Process", "agent"),
                &guest_ref,
                &guest_uid,
                &zone,
                Some(&descriptor),
                &approved,
            )
            .is_ok()
        );
        assert!(
            validate_seed_request(
                &seed_request("Zone", "work"),
                &guest_ref,
                &guest_uid,
                &zone,
                Some(&descriptor),
                &approved,
            )
            .is_err()
        );
        let mut update = seed_request("Process", "agent");
        update.mutations[0].kind =
            EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_UPDATE_SPEC);
        assert!(
            validate_seed_request(
                &update,
                &guest_ref,
                &guest_uid,
                &zone,
                Some(&descriptor),
                &approved,
            )
            .is_err()
        );
    }

    #[test]
    fn target_local_create_validation_accepts_uid_free_envelopes() {
        let mut value: serde_json::Value = serde_json::from_str(
            r#"{
                "apiVersion":"resources.d2bus.org/v3",
                "metadata":{
                    "configurationGeneration":7,
                    "createdAt":"2026-07-22T00:00:00.000Z",
                    "deletionRequestedAt":null,
                    "finalizers":[],
                    "generation":1,
                    "managedBy":"configuration",
                    "name":"host-system",
                    "ownerRef":null,
                    "revision":1,
                    "uid":"123e4567-e89b-42d3-a456-426614174000",
                    "updatedAt":"2026-07-22T00:00:00.000Z",
                    "zone":"dev"
                },
                "spec":{
                    "providerRef":"Provider/system-core",
                    "updatePolicy":{"disruptive":"manual","nonDisruptive":"automatic"}
                },
                "status":{
                    "completedAt":null,
                    "conditions":[],
                    "lastReconciledAt":null,
                    "observedGeneration":0,
                    "outcome":null,
                    "phase":"Pending",
                    "resource":{},
                    "startedAt":null,
                    "update":{
                        "dependencies":{"count":0,"refs":[]},
                        "disruption":"None",
                        "lastAssessedAt":null,
                        "observedGeneration":0,
                        "operationId":null,
                        "owned":{"count":0,"refs":[]},
                        "preserveState":true,
                        "reasons":[],
                        "state":"Unknown",
                        "targetGeneration":1
                    }
                },
                "type":"Host"
            }"#,
        )
        .expect("golden resource");
        value["metadata"]
            .as_object_mut()
            .expect("metadata")
            .remove("uid");
        let bytes = d2b_contracts_resource::v3::CanonicalJsonValue::parse(
            &serde_json::to_vec(&value).expect("resource bytes"),
        )
        .expect("canonical resource")
        .to_canonical_bytes();
        let envelope = parse_uid_free_envelope(&bytes).expect("UID-free envelope");
        assert_eq!(
            envelope.metadata().uid().as_str(),
            "00000000-0000-4000-8000-000000000000"
        );
    }
}
