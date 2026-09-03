//! Hermetic production-store and authenticated-bus support for the reaction
//! benchmark in the parent `benches/` directory.
//!
//! The helper provisions an isolated redb store, opens a Resource-API watch,
//! and supplies the named-stream plumbing used to measure the complete
//! controller reaction path without touching a deployed daemon or host state.

use std::fs::OpenOptions;
use std::sync::{Arc, Mutex};

use d2b_bus::{
    BusConfig, OperationId, OperationSpec, ReceivedFrame, ResourceCall, ResourceQuery, StreamError,
    StreamLimits, StreamName, router::production_rss::ProductionWatchHarness,
};
use d2b_contracts_resource::resource_proto as wire;
use d2b_contracts_resource::v3::{
    CanonicalJsonValue, ConfigurationGeneration, RESOURCE_ENVELOPE_DOMAIN_TAG, ResourceRef,
    ResourceGeneration, ResourceTypeName, ResourceUid, Timestamp, ZoneId, ZoneRevision,
    canonical_digest,
};
use d2b_contracts_resource::v3::identity::{
    AuthenticatedSubjectContext as SessionClaims, BindingDigest, EvidenceClass,
    Locality, ReconnectGeneration, ServiceName, SessionBinding, SessionPurpose,
    TranscriptHash, TransportBinding,
};
use d2b_resource_api::{
    RedbBackend, ResourceApiClient, ResourceBusAdapter, ResourceService,
    authz::{
        ApiCatalog, AuthorizationState, BindingScope, BootstrapPhase, BoundSubject,
        CompiledRole, CompiledRoleBinding, NativeAuthorizer, PolicyRule, PolicySet,
        RelayGrantAuthority, ResourceVerb, SessionVerb,
    },
};
use d2b_resource_api::watch::{WatchPumpError, WatchService};
use d2b_resource_store::{
    PolicySnapshot, ResourceAssignmentFence, ResourceAssignmentScope, StoreError, StoreGetRequest,
    StoreOperationContext, StoreProjection, StoreSlot, StoreWatchRequest, StoredResource,
};
use d2b_resource_store_redb::{RedbResourceStore, StoreIdentity, write_provisioning_marker};
use d2b_core_controller::{
    SourceError,
    controller_assignment::ControllerAssignmentRegistry,
};
use tokio::task::JoinHandle;

pub const PROVIDER_IDS: [&str; 27] = [
    "system-core",
    "system-systemd",
    "system-minijail",
    "runtime-cloud-hypervisor",
    "runtime-qemu-media",
    "runtime-azure-container-apps",
    "runtime-azure-virtual-machine",
    "volume-local",
    "volume-virtiofs",
    "network-local",
    "device-tpm",
    "device-usbip",
    "device-security-key",
    "device-gpu",
    "display-wayland",
    "audio-pipewire",
    "clipboard-wayland",
    "notification-desktop",
    "shell-terminal",
    "credential-secret-service",
    "credential-entra",
    "credential-managed-identity",
    "transport-unix",
    "transport-vsock",
    "transport-azure-relay",
    "observability-otel",
    "activation-nixos",
];

pub struct NamedWatchConnection {
    incoming: d2b_bus::IncomingStream,
    pump: JoinHandle<Result<(), WatchPumpError>>,
}

impl NamedWatchConnection {
    pub async fn receive(&self) -> Result<ReceivedFrame, StreamError> {
        let frame = self.incoming.receive_next().await?;
        self.incoming
            .grant_frame(&frame, frame.payload().len())
            .await?;
        Ok(frame)
    }

    pub async fn abort(self) {
        self.pump.abort();
        let _ = self.pump.await;
    }
}

pub struct ProductionStore {
    _directory: tempfile::TempDir,
    store: Arc<RedbResourceStore>,
    claims: SessionClaims,
    provider_claims: std::collections::BTreeMap<String, SessionClaims>,
    authorizer: Arc<NativeAuthorizer>,
    service: Arc<ResourceService<RedbBackend>>,
    state: AuthorizationState,
    client: Arc<ResourceApiClient<RedbBackend, d2b_resource_api::service::UnavailableUpgradeDispatcher>>,
    core_authority: Arc<Mutex<CoreAssignmentAuthority>>,
}

#[derive(Clone)]
struct CoreAssignmentAuthority {
    provider_generation: ResourceGeneration,
    controller_generation: d2b_contracts_resource::v3::ControllerGeneration,
    session_generation: ReconnectGeneration,
    controller_role: ResourceRef,
    target: ResourceRef,
    epoch: u64,
}

impl ProductionStore {
    pub async fn provision() -> Arc<Self> {
        let directory = tempfile::tempdir().expect("create hermetic store directory");
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(directory.path().join("store.redb"))
            .expect("create hermetic redb file");
        let mut marker = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(directory.path().join("store.marker"))
            .expect("create hermetic store marker");
        let identity = store_identity();
        let state = core_state();
        let provider_claims = PROVIDER_IDS
            .iter()
            .enumerate()
            .map(|(index, provider)| {
                (
                    (*provider).to_owned(),
                    provider_subject_context(provider, index),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        let claims = provider_claims
            .get("system-core")
            .cloned()
            .expect("system-core subject is present");
        let mut assignment_registry = ControllerAssignmentRegistry::default();
        let core_assignment_epoch = assignment_registry
            .reserve_epoch_after(0)
            .expect("reserve Core assignment epoch");
        let policy = core_policy(provider_claims.values());
        let authorizer = Arc::new(
            NativeAuthorizer::new(ApiCatalog::standard(), Some(policy))
                .expect("construct production Core authorizer"),
        );
        write_provisioning_marker(&mut marker, &identity).expect("write store marker");
        let acceptor = authorizer
            .take_store_seal(identity.seal_identity())
            .expect("take production Core store seal");
        let store = RedbResourceStore::provision_owned(file, marker, identity, acceptor)
            .await
            .expect("provision production redb backend");
        let store = Arc::new(store);
        let backend = Arc::new(RedbBackend::from_arc(Arc::clone(&store)));
        let service = Arc::new(
            ResourceService::new(backend, Arc::clone(&authorizer))
                .expect("bind production Core ResourceService"),
        );
        let client_subject = authorizer
            .issue_authenticated_subject(claims.clone(), state.clone())
            .expect("issue authenticated Core subject");
        let client = Arc::new(
            ResourceBusAdapter::bind_component_session(Arc::clone(&service), client_subject)
                .expect("bind authenticated Core Resource API client")
                .client(),
        );
        let authority = CoreAssignmentAuthority {
            provider_generation: claims
                .provider_generation()
                .expect("Core Provider generation is authoritative"),
            controller_generation: claims
                .controller_generation()
                .expect("Core controller generation is authoritative"),
            session_generation: claims.reconnect_generation(),
            controller_role: claims
                .process_ref()
                .cloned()
                .expect("Core controller role is authoritative"),
            target: claims
                .execution_ref()
                .cloned()
                .expect("Core execution target is authoritative"),
            epoch: core_assignment_epoch,
        };
        Arc::new(Self {
            _directory: directory,
            store,
            claims,
            provider_claims,
            authorizer,
            service,
            state,
            client,
            core_authority: Arc::new(Mutex::new(authority)),
        })
    }

    pub fn store(&self) -> Arc<RedbResourceStore> {
        Arc::clone(&self.store)
    }

    pub fn core_registered_api(&self) -> d2b_resource_api::registered::RedbRegisteredControllerApi {
        self.core_registered_api_with_assignments(Vec::new())
    }

    pub fn core_registered_api_with_assignments(
        &self,
        assignments: Vec<(ResourceRef, ResourceAssignmentFence)>,
    ) -> d2b_resource_api::registered::RedbRegisteredControllerApi {
        self.provider_registered_api("system-core", assignments)
    }

    pub fn provider_registered_api(
        &self,
        provider: &str,
        assignments: Vec<(ResourceRef, ResourceAssignmentFence)>,
    ) -> d2b_resource_api::registered::RedbRegisteredControllerApi {
        let claims = self
            .provider_claims
            .get(provider)
            .cloned()
            .expect("requested Provider subject is in the closed catalog");
        let subject = self
            .authorizer
            .issue_authenticated_subject(claims, self.state.clone())
            .expect("issue authenticated Core source subject");
        self.service
            .registered_controller_api(subject, self.state.clone(), assignments)
            .expect("bind production Core source API")
    }

    pub fn authoritative_assignment(
        &self,
        resource: &StoredResource,
    ) -> ResourceAssignmentFence {
        let authority = self
            .core_authority
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        ResourceAssignmentFence {
            resource_uid: resource.uid.clone(),
            resource_revision: resource.revision,
            provider_generation: authority.provider_generation,
            controller_generation: authority.controller_generation,
            controller_role: authority.controller_role,
            target: authority.target,
            session_generation: authority.session_generation,
            epoch: authority.epoch,
            scope: ResourceAssignmentScope::Primary,
        }
    }

    pub fn set_core_authority_epoch(&self, epoch: u64) {
        self.core_authority
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .epoch = epoch;
    }

    pub fn durable_core_assignment_resolver(
        &self,
    ) -> d2b_resource_api::registered::AssignmentFenceResolver {
        let store = self.store();
        let authority = Arc::clone(&self.core_authority);
        Arc::new(move |target, uid, revision| {
            let store = Arc::clone(&store);
            let authority = Arc::clone(&authority);
            Box::pin(async move {
                if target.resource_type().as_str() != "Process" {
                    return Err(SourceError::Integrity);
                }
                let stored = 'read: {
                    for _ in 0..4 {
                        match store
                            .assignment_fence(
                                ZoneId::parse("dev").expect("fixed Zone"),
                                target.clone(),
                            )
                            .await
                        {
                            Ok(stored) => break 'read stored,
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    d2b_resource_store::StoreErrorKind::Backpressure
                                        | d2b_resource_store::StoreErrorKind::StoreBackpressure
                                ) =>
                            {
                                tokio::task::yield_now().await;
                            }
                            Err(error)
                                if error.kind()
                                    == d2b_resource_store::StoreErrorKind::Timeout =>
                            {
                                return Err(SourceError::Timeout);
                            }
                            Err(_) => return Err(SourceError::Unavailable),
                        }
                    }
                    return Err(SourceError::Backpressure);
                };
                let Some(stored) = stored else {
                    return Err(SourceError::Integrity);
                };
                let current = authority
                    .lock()
                    .map_err(|_| SourceError::Integrity)?
                    .clone();
                if stored.resource_uid != uid
                    || stored.resource_revision != revision
                    || stored.provider_generation != current.provider_generation
                    || stored.controller_generation != current.controller_generation
                    || stored.controller_role != current.controller_role
                    || stored.target != current.target
                    || stored.session_generation != current.session_generation
                    || stored.epoch != current.epoch
                {
                    return Err(SourceError::Integrity);
                }
                Ok(stored)
            })
        })
    }

    pub async fn commit_provider_catalog(&self) {
        let mut request = wire::CommitBatchRequest::new();
        let catalog_digest = canonical_digest(
            "d2b:reaction-provider-catalog/v1",
            PROVIDER_IDS.join("\0").as_bytes(),
        );
        let operation_id = format!(
            "{}{}",
            d2b_contracts_resource::v3::RESOURCE_BUNDLE_MATERIALIZATION_OPERATION_PREFIX,
            catalog_digest
        );
        request.meta = d2b_resource_api::protobuf::MessageField::some(request_meta(&operation_id));
        for (index, provider) in PROVIDER_IDS.iter().enumerate() {
            let target = ResourceRef::parse(&format!("Provider/{provider}"))
                .expect("fixed Provider reference");
            request.mutations.push(wire_mutation(
                wire::MutationKind::MUTATION_KIND_CREATE,
                wire::PreconditionKind::PRECONDITION_KIND_CREATE_ABSENT,
                &target,
                None,
                provider_body(index, provider),
            ));
        }
        let response = loop {
            let response = self.client.commit_batch(request.clone()).await;
            let retryable = response
                .error
                .as_ref()
                .is_some_and(|error| error.reason.as_str() == "redb-store-backpressure");
            if retryable {
                tokio::task::yield_now().await;
                continue;
            }
            break response;
        };
        if let Some(error) = response.error.as_ref() {
            panic!(
                "production Provider catalog commit failed: kind={:?} reason={} retry={:?}",
                error.kind,
                error.reason.as_str(),
                error.retry_class
            );
        }
    }

    pub async fn commit_process_batch(
        &self,
        profile: usize,
        start: usize,
        end: usize,
    ) -> Result<(Vec<StoredResource>, std::time::Instant), StoreError> {
        let mut request = wire::CommitBatchRequest::new();
        let operation_id = format!("reaction-create-{profile}-{start}");
        request.meta = d2b_resource_api::protobuf::MessageField::some(request_meta(&operation_id));
        for index in start..end {
            let target = process_ref(index);
            let canonical_resource = process_body(index);
            request.mutations.push(wire_mutation(
                wire::MutationKind::MUTATION_KIND_CREATE,
                wire::PreconditionKind::PRECONDITION_KIND_CREATE_ABSENT,
                &target,
                None,
                canonical_resource,
            ));
        }
        let response = loop {
            let response = self.client.commit_batch(request.clone()).await;
            let retryable = response
                .error
                .as_ref()
                .is_some_and(|error| error.reason.as_str() == "redb-store-backpressure");
            if retryable {
                tokio::task::yield_now().await;
                continue;
            }
            break response;
        };
        if let Some(error) = response.error.as_ref() {
            panic!(
                "production ResourceService create failed: kind={:?} reason={} retry={:?}",
                error.kind,
                error.reason.as_str(),
                error.retry_class
            );
        }
        let committed_at = std::time::Instant::now();
        let resources = stored_resources_from_response(&response);
        assert_eq!(resources.len(), end - start);
        Ok((resources, committed_at))
    }

    pub async fn commit_process_spec_update(
        &self,
        resources: &[StoredResource],
        operation_id: &str,
    ) -> Result<(Vec<StoredResource>, std::time::Instant), StoreError> {
        let mut request = wire::CommitBatchRequest::new();
        request.meta =
            d2b_resource_api::protobuf::MessageField::some(request_meta(operation_id));
        for resource in resources {
            request.mutations.push(wire_mutation(
                wire::MutationKind::MUTATION_KIND_UPDATE_SPEC,
                wire::PreconditionKind::PRECONDITION_KIND_EXACT_REVISION,
                &resource.resource_ref,
                Some((resource.uid.clone(), resource.revision.get())),
                process_spec_update_body(&resource.canonical_json),
            ));
        }
        let response = loop {
            let response = self.client.commit_batch(request.clone()).await;
            let retryable = response
                .error
                .as_ref()
                .is_some_and(|error| error.reason.as_str() == "redb-store-backpressure");
            if retryable {
                tokio::task::yield_now().await;
                continue;
            }
            break response;
        };
        if let Some(error) = response.error.as_ref() {
            panic!(
                "production ResourceService Process update failed: kind={:?} reason={} retry={:?}",
                error.kind,
                error.reason.as_str(),
                error.retry_class
            );
        }
        let resources = stored_resources_from_response(&response);
        let committed_at = std::time::Instant::now();
        Ok((
            resources,
            committed_at,
        ))
    }

    pub async fn commit_status(
        &self,
        target: &ResourceRef,
        candidate: &[u8],
        operation_id: &str,
    ) -> Result<ZoneRevision, StoreError> {
        let resource = self.store.get(get_request(target)).await?;
        let canonical = status_envelope(&resource, candidate);
        let mut request = wire::CommitBatchRequest::new();
        request.meta = d2b_resource_api::protobuf::MessageField::some(request_meta(operation_id));
        request.mutations.push(wire_mutation(
            wire::MutationKind::MUTATION_KIND_UPDATE_STATUS,
            wire::PreconditionKind::PRECONDITION_KIND_EXACT_REVISION,
            target,
            Some((resource.uid.clone(), resource.revision.get())),
            canonical,
        ));
        let response = self.client.commit_batch(request).await;
        if let Some(error) = response.error.as_ref() {
            panic!(
                "production ResourceService status failed: kind={:?} reason={} retry={:?}",
                error.kind,
                error.reason.as_str(),
                error.retry_class
            );
        }
        Ok(self.store.get(get_request(target)).await?.revision)
    }

    pub async fn get_resource(&self, target: &ResourceRef) -> Result<StoredResource, StoreError> {
        loop {
            match self.store.get(get_request(target)).await {
                Ok(resource) => return Ok(resource),
                Err(error)
                    if matches!(
                        error.kind(),
                        d2b_resource_store::StoreErrorKind::Backpressure
                            | d2b_resource_store::StoreErrorKind::StoreBackpressure
                            | d2b_resource_store::StoreErrorKind::Timeout
                    ) =>
                {
                    tokio::task::yield_now().await;
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub async fn assignment_fence(
        &self,
        target: &ResourceRef,
    ) -> Result<Option<ResourceAssignmentFence>, StoreError> {
        loop {
            match self.store.assignment_fence(
                ZoneId::parse("dev").expect("fixed Zone"),
                target.clone(),
            )
            .await
            {
                Ok(fence) => return Ok(fence),
                Err(error)
                    if matches!(
                        error.kind(),
                        d2b_resource_store::StoreErrorKind::Backpressure
                            | d2b_resource_store::StoreErrorKind::StoreBackpressure
                            | d2b_resource_store::StoreErrorKind::Timeout
                    ) =>
                {
                    tokio::task::yield_now().await;
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub async fn wait_for_newer_revision(
        &self,
        target: &ResourceRef,
        revision: ZoneRevision,
    ) -> Result<(), StoreError> {
        loop {
            match self.store.get(get_request(target)).await {
                Ok(resource) if resource.revision > revision => return Ok(()),
                Ok(_) => tokio::task::yield_now().await,
                Err(error)
                    if matches!(
                        error.kind(),
                        d2b_resource_store::StoreErrorKind::Backpressure
                            | d2b_resource_store::StoreErrorKind::StoreBackpressure
                            | d2b_resource_store::StoreErrorKind::Timeout
                    ) =>
                {
                    tokio::task::yield_now().await;
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub async fn shutdown(self) -> Result<(), StoreError> {
        let Self {
            _directory,
            store,
            claims: _claims,
            provider_claims: _provider_claims,
            authorizer: _authorizer,
            service,
            state: _state,
            client,
            core_authority: _core_authority,
        } = self;
        drop(client);
        drop(service);
        for _ in 0..1_000 {
            if Arc::strong_count(&store) == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        let store = Arc::try_unwrap(store)
            .unwrap_or_else(|store| {
                panic!(
                    "all production store handles released (remaining={})",
                    Arc::strong_count(&store)
                )
            });
        store.shutdown().await
    }
}

fn core_state() -> AuthorizationState {
    AuthorizationState {
        snapshot: PolicySnapshot {
            policy_revision: 1,
            api_catalog_revision: 1,
            active_configuration_revision: ConfigurationGeneration::new(1)
                .expect("fixed configuration generation"),
            controller_generation: Some(
                d2b_contracts_resource::v3::ControllerGeneration::new(3)
                    .expect("fixed controller generation"),
            ),
        },
        zone_policy_revision: ZoneRevision::new(1),
        bootstrap_phase: BootstrapPhase::Disabled,
        now_tick: 1,
    }
}

fn provider_subject_context(provider: &str, index: usize) -> SessionClaims {
    let subject_uid = if provider == "system-core" {
        "33333333-3333-4333-8333-333333333333".to_owned()
    } else {
        format!("44444444-4444-4444-8444-{index:012}")
    };
    SessionClaims::new(
        ResourceRef::parse(&format!("Provider/{provider}")).expect("fixed Provider subject"),
        ResourceUid::parse(subject_uid).expect("fixed Provider subject UID"),
        ResourceRef::parse("Zone/dev").expect("fixed Zone"),
        EvidenceClass::UnixPeer,
        SessionPurpose::parse("resource-api").expect("fixed session purpose"),
        ServiceName::parse("d2b.resource.v3").expect("fixed service"),
        SessionBinding::new(
            d2b_contracts_resource::v3::SchemaFingerprint::parse(format!(
                "sha256:{}",
                "1".repeat(64)
            ))
            .expect("fixed schema fingerprint"),
            TransportBinding::new(
                Locality::Local,
                BindingDigest::parse(format!("sha256:{}", "2".repeat(64)))
                    .expect("fixed binding digest"),
            ),
            ReconnectGeneration::new(1).expect("fixed reconnect generation"),
            TranscriptHash::from_bytes([3; 32]),
        ),
    )
    .with_execution_ref(ResourceRef::parse("Host/host-system").expect("fixed execution target"))
    .with_process_ref(ResourceRef::parse("Process/controller").expect("fixed controller role"))
    .with_provider_ref(
        ResourceRef::parse(&format!("Provider/{provider}")).expect("fixed Provider"),
    )
    .with_provider_generation(
        d2b_contracts_resource::v3::ResourceGeneration::new(1)
            .expect("fixed Provider generation"),
    )
    .with_controller_generation(
        d2b_contracts_resource::v3::ControllerGeneration::new(3)
            .expect("fixed controller generation"),
    )
}

fn core_policy<'a>(subjects: impl IntoIterator<Item = &'a SessionClaims>) -> PolicySet {
    let catalog = ApiCatalog::standard();
    let process = ResourceTypeName::parse("Process").expect("fixed Process ResourceType");
    let provider = ResourceTypeName::parse("Provider").expect("fixed Provider ResourceType");
    let zone = ZoneId::parse("dev").expect("fixed Zone");
    let rules = vec![
        PolicyRule::new(
            &catalog,
            [process.clone()],
            [
                ResourceVerb::Get,
                ResourceVerb::List,
                ResourceVerb::Watch,
                ResourceVerb::Create,
                ResourceVerb::UpdateSpec,
                ResourceVerb::Delete,
            ],
            [SessionVerb::Connect],
            [],
            [],
            [zone.clone()],
            [],
        )
        .expect("fixed Core read/create policy rule"),
        PolicyRule::new(
            &catalog,
            [process.clone()],
            [ResourceVerb::UpdateStatus],
            [],
            ["status".to_owned()],
            [],
            [zone.clone()],
            [],
        )
        .expect("fixed Core status policy rule"),
        PolicyRule::new(
            &catalog,
            [provider],
            [
                ResourceVerb::Get,
                ResourceVerb::List,
                ResourceVerb::Watch,
                ResourceVerb::Create,
                ResourceVerb::UpdateSpec,
            ],
            [SessionVerb::Connect],
            [],
            [],
            [zone.clone()],
            [],
        )
        .expect("fixed Core Provider catalog policy rule"),
        PolicyRule::new(
            &catalog,
            [process],
            [ResourceVerb::UpdateFinalizers],
            [],
            ["finalizers".to_owned()],
            [],
            [zone],
            [],
        )
        .expect("fixed Core finalizer policy rule"),
    ];
    let role = CompiledRole::new(
        ResourceRef::parse("Role/system-core").expect("fixed Core role"),
        rules,
    )
    .expect("fixed Core role");
    let binding = CompiledRoleBinding::new(
        role.role_ref.clone(),
        subjects.into_iter().map(|subject| BoundSubject {
            subject_ref: subject.subject_ref().clone(),
            subject_uid: subject.subject_uid().clone(),
        }),
        BindingScope::default(),
        RelayGrantAuthority::None,
    )
    .expect("fixed Core role binding");
    PolicySet::new(&catalog, 1, vec![role], vec![binding]).expect("fixed Core policy")
}

fn request_meta(operation_id: &str) -> wire::RequestMeta {
    let mut meta = wire::RequestMeta::new();
    meta.operation_id = operation_id.to_owned();
    meta.correlation_id = operation_id.to_owned();
    meta.idempotency_key = operation_id.to_owned();
    meta
}

fn wire_mutation(
    kind: wire::MutationKind,
    precondition_kind: wire::PreconditionKind,
    target: &ResourceRef,
    expected: Option<(ResourceUid, u64)>,
    canonical_resource: Vec<u8>,
) -> wire::Mutation {
    let mut identity = wire::ResourceIdentity::new();
    identity.zone = "dev".to_owned();
    identity.resource_type = target.resource_type().as_str().to_owned();
    identity.name = target.name().as_str().to_owned();
    if let Some((uid, revision)) = expected.as_ref() {
        identity.uid = Some(uid.as_str().to_owned());
        identity.revision = Some(*revision);
    }
    let mut body = wire::ResourceEnvelopeBytes::new();
    body.identity = d2b_resource_api::protobuf::MessageField::some(identity.clone());
    body.canonical_json = canonical_resource.clone();
    body.payload_digest = canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &canonical_resource);
    let mut precondition = wire::Precondition::new();
    precondition.kind = d2b_resource_api::protobuf::EnumOrUnknown::new(precondition_kind);
    if let Some((uid, revision)) = expected {
        precondition.expected_uid = Some(uid.as_str().to_owned());
        precondition.expected_revision = Some(revision);
    }
    let mut mutation = wire::Mutation::new();
    mutation.kind = d2b_resource_api::protobuf::EnumOrUnknown::new(kind);
    mutation.target = d2b_resource_api::protobuf::MessageField::some(identity);
    mutation.precondition = d2b_resource_api::protobuf::MessageField::some(precondition);
    mutation.resource = d2b_resource_api::protobuf::MessageField::some(body);
    mutation
}

fn stored_resources_from_response(
    response: &wire::CommitBatchResponse,
) -> Vec<StoredResource> {
    response
        .resources
        .iter()
        .map(|envelope| {
            let identity = envelope
                .identity
                .as_ref()
                .expect("production commit response carries resource identity");
            StoredResource {
                resource_ref: ResourceRef::parse(&format!(
                    "{}/{}",
                    identity.resource_type, identity.name
                ))
                .expect("production commit response carries valid resource reference"),
                zone: ZoneId::parse(identity.zone.clone())
                    .expect("production commit response carries valid Zone"),
                uid: ResourceUid::parse(
                    identity
                        .uid
                        .clone()
                        .expect("production commit response carries resource UID"),
                )
                .expect("production commit response carries valid resource UID"),
                generation: ResourceGeneration::new(
                    identity
                        .generation
                        .expect("production commit response carries generation"),
                )
                .expect("production commit response carries valid generation"),
                revision: ZoneRevision::new(
                    identity
                        .revision
                        .expect("production commit response carries revision"),
                ),
                canonical_json: envelope.canonical_json.clone(),
                payload_digest: envelope.payload_digest.clone(),
            }
        })
        .collect()
}

pub async fn open_named_watch(
    store: Arc<RedbResourceStore>,
    harness: &ProductionWatchHarness,
    request: StoreWatchRequest,
    id: &str,
) -> NamedWatchConnection {
    let watch = WatchService::new(store)
        .open(request)
        .await
        .expect("open production Resource-API watch");
    let bus_stream = harness
        .caller()
        .open_resource_stream(
            harness.route().clone(),
            OperationSpec::new(
                OperationId::parse(format!("reaction-bus-{id}"))
                    .expect("valid production bus operation"),
                30_000,
            )
            .expect("valid production bus operation"),
            ResourceCall::Watch(
                ResourceQuery::new(
                    vec![ResourceTypeName::parse("Host").expect("valid route ResourceType")],
                    Vec::new(),
                    Vec::new(),
                )
                .expect("valid production route query"),
            ),
            StreamName::parse(format!("reaction-watch:{id}"))
                .expect("valid production stream name"),
            2 * 1024 * 1024,
        )
        .await
        .expect("open authenticated production named stream");
    let incoming = harness
        .take_incoming()
        .expect("production controller incoming stream");
    let pump = tokio::spawn(async move {
        let mut watch = watch;
        watch.pump_to(&bus_stream).await
    });
    NamedWatchConnection { incoming, pump }
}

pub fn bus_config() -> BusConfig {
    BusConfig {
        stream_limits: StreamLimits {
            max_stream_credit: 2 * 1024 * 1024,
            max_aggregate_bytes: 8 * 1024 * 1024,
            max_streams: 128,
            max_frame_bytes: 1024 * 1024,
            max_streams_per_principal: 128,
            max_credit_per_principal: 8 * 1024 * 1024,
            max_queued_bytes_per_principal: 8 * 1024 * 1024,
        },
        ..BusConfig::default()
    }
}

fn store_identity() -> StoreIdentity {
    StoreIdentity::new(
        StoreSlot::new(0).expect("valid store slot"),
        ResourceUid::parse("11111111-1111-4111-8111-111111111111").expect("valid store UID"),
        ZoneId::parse("dev").expect("valid Zone"),
        ResourceUid::parse("22222222-2222-4222-8222-222222222222").expect("valid Zone UID"),
        Timestamp::parse("2026-07-31T00:00:00.000Z").expect("valid timestamp"),
        policy_snapshot(),
    )
}

fn process_ref(index: usize) -> ResourceRef {
    ResourceRef::parse(&format!("Process/ready-{index}")).expect("valid Process ref")
}

fn provider_body(index: usize, provider: &str) -> Vec<u8> {
    let raw = format!(
        r#"{{
            "apiVersion":"resources.d2bus.org/v3",
            "metadata":{{
                "configurationGeneration":1,
                "createdAt":"2026-07-22T00:00:00.000Z",
                "deletionRequestedAt":null,
                "finalizers":[],
                "generation":1,
                "managedBy":"configuration",
                "name":"{provider}",
                "ownerRef":null,
                "revision":1,
                "uid":"123e4567-e89b-42d3-a456-{index:012}",
                "updatedAt":"2026-07-22T00:00:00.000Z",
                "zone":"dev"
            }},
            "spec":{{
                "artifactId":"{provider}",
                "config":{{}}
            }},
            "status":{{
                "completedAt":null,
                "conditions":[],
                "lastReconciledAt":null,
                "observedGeneration":0,
                "outcome":null,
                "phase":"Pending",
                "resource":{{}},
                "startedAt":null,
                "update":{{
                    "dependencies":{{"count":0,"refs":[]}},
                    "disruption":"None",
                    "lastAssessedAt":null,
                    "observedGeneration":0,
                    "operationId":null,
                    "owned":{{"count":0,"refs":[]}},
                    "preserveState":true,
                    "reasons":[],
                    "state":"Unknown",
                    "targetGeneration":1
                }}
            }},
            "type":"Provider"
        }}"#
    );
    let mut value = CanonicalJsonValue::parse(raw.as_bytes()).expect("valid Provider envelope");
    let CanonicalJsonValue::Object(root) = &mut value else {
        panic!("Provider envelope is an object");
    };
    let CanonicalJsonValue::Object(metadata) = root
        .get_mut("metadata")
        .expect("Provider metadata is present")
    else {
        panic!("Provider metadata is an object");
    };
    metadata.remove("uid");
    value.to_canonical_bytes()
}

fn process_body(index: usize) -> Vec<u8> {
    let raw = format!(
        r#"{{
            "apiVersion":"resources.d2bus.org/v3",
            "metadata":{{
                "configurationGeneration":1,
                "createdAt":"2026-07-22T00:00:00.000Z",
                "deletionRequestedAt":null,
                "finalizers":[],
                "generation":1,
                "managedBy":"configuration",
                "name":"ready-{index}",
                "ownerRef":null,
                "revision":1,
                "uid":"123e4567-e89b-42d3-a456-426614174000",
                "updatedAt":"2026-07-22T00:00:00.000Z",
                "zone":"dev"
            }},
            "spec":{{
                "executionRef":"Host/host-system",
                "processClass":"worker",
                "providerRef":"Provider/system-minijail",
                "template":"reaction",
                "updatePolicy":{{
                    "disruptive":"manual",
                    "nonDisruptive":"automatic"
                }}
            }},
            "status":{{
                "completedAt":null,
                "conditions":[],
                "lastReconciledAt":null,
                "observedGeneration":0,
                "outcome":null,
                "phase":"Pending",
                "resource":{{}},
                "startedAt":null,
                "update":{{
                    "dependencies":{{"count":0,"refs":[]}},
                    "disruption":"None",
                    "lastAssessedAt":null,
                    "observedGeneration":0,
                    "operationId":null,
                    "owned":{{"count":0,"refs":[]}},
                    "preserveState":true,
                    "reasons":[],
                    "state":"Unknown",
                    "targetGeneration":1
                }}
            }},
            "type":"Process"
        }}"#
    );
    let mut value = CanonicalJsonValue::parse(raw.as_bytes()).expect("valid Process envelope");
    let CanonicalJsonValue::Object(root) = &mut value else {
        panic!("Process envelope is an object");
    };
    let CanonicalJsonValue::Object(metadata) = root
        .get_mut("metadata")
        .expect("Process metadata is present")
    else {
        panic!("Process metadata is an object");
    };
    metadata.remove("uid");
    value.to_canonical_bytes()
}

fn process_spec_update_body(canonical: &[u8]) -> Vec<u8> {
    let mut value = CanonicalJsonValue::parse(canonical).expect("stored Process is canonical");
    let CanonicalJsonValue::Object(root) = &mut value else {
        panic!("stored Process envelope is an object");
    };
    let CanonicalJsonValue::Object(spec) = root
        .get_mut("spec")
        .expect("stored Process spec is present")
    else {
        panic!("stored Process spec is an object");
    };
    let template = match spec.get("template") {
        Some(CanonicalJsonValue::String(value)) => format!("{value}-next"),
        _ => "reaction-updated".to_owned(),
    };
    spec.insert(
        "template".to_owned(),
        CanonicalJsonValue::String(template),
    );
    value.to_canonical_bytes()
}

fn status_envelope(resource: &StoredResource, candidate: &[u8]) -> Vec<u8> {
    let mut value =
        CanonicalJsonValue::parse(&resource.canonical_json).expect("stored envelope is canonical");
    let CanonicalJsonValue::Object(root) = &mut value else {
        panic!("stored envelope is an object");
    };
    let status = CanonicalJsonValue::parse(candidate).expect("status candidate is canonical");
    root.insert("status".to_owned(), status);
    value.to_canonical_bytes()
}

fn policy_snapshot() -> PolicySnapshot {
    core_state().snapshot
}

fn get_request(target: &ResourceRef) -> StoreGetRequest {
    StoreGetRequest {
        operation: operation_context(&format!("reaction-read-{}", target.name().as_str())),
        zone: ZoneId::parse("dev").expect("valid Zone"),
        target: target.clone(),
        expected_uid: None,
        projection: StoreProjection::Full,
    }
}

fn operation_context(id: &str) -> StoreOperationContext {
    StoreOperationContext {
        operation_id: id.to_owned(),
        idempotency_key: Some(format!("{id}-key")),
        correlation_id: format!("{id}-correlation"),
        trace_id: None,
        deadline_ms: 30_000,
    }
}
