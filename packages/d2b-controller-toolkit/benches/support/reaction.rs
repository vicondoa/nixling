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
    client: Arc<ResourceApiClient<RedbBackend, d2b_resource_api::service::UnavailableUpgradeDispatcher>>,
    core_assignment_epoch: u64,
    core_api: Mutex<Option<d2b_resource_api::registered::RedbRegisteredControllerApi>>,
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
        let subject_context = core_subject_context();
        let mut assignment_registry = ControllerAssignmentRegistry::default();
        let core_assignment_epoch = assignment_registry
            .reserve_epoch_after(0)
            .expect("reserve Core assignment epoch");
        let policy = core_policy(&subject_context);
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
            .issue_authenticated_subject(subject_context.clone(), state.clone())
            .expect("issue authenticated Core subject");
        let client = Arc::new(
            ResourceBusAdapter::bind_component_session(Arc::clone(&service), client_subject)
                .expect("bind authenticated Core Resource API client")
                .client(),
        );
        let subject = authorizer
            .issue_authenticated_subject(subject_context, state.clone())
            .expect("issue authenticated Core source subject");
        let core_api = service
            .registered_controller_api(subject, state.clone(), Vec::new())
            .expect("bind production Core source API");
        Arc::new(Self {
            _directory: directory,
            store,
            claims: core_subject_context(),
            client,
            core_assignment_epoch,
            core_api: Mutex::new(Some(core_api)),
        })
    }

    pub fn store(&self) -> Arc<RedbResourceStore> {
        Arc::clone(&self.store)
    }

    pub fn core_registered_api(&self) -> d2b_resource_api::registered::RedbRegisteredControllerApi {
        self.core_api
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .expect("take production Core source API once")
    }

    pub fn core_assignment_resolver(
        &self,
    ) -> d2b_resource_api::registered::AssignmentFenceResolver {
        let epoch = self.core_assignment_epoch;
        let provider_generation = self
            .claims
            .provider_generation()
            .expect("fixed Core Provider generation");
        let controller_generation = self
            .claims
            .controller_generation()
            .expect("fixed Core controller generation");
        let session_generation = self.claims.reconnect_generation();
        let controller_role =
            ResourceRef::parse("Process/controller").expect("fixed controller role");
        let execution_target =
            ResourceRef::parse("Host/host-system").expect("fixed execution target");
        Arc::new(move |target, uid, revision| {
            let provider_generation = provider_generation;
            let controller_generation = controller_generation;
            let session_generation = session_generation;
            let controller_role = controller_role.clone();
            let execution_target = execution_target.clone();
            Box::pin(async move {
                if target.resource_type().as_str() != "Process" {
                    return Err(SourceError::Integrity);
                }
                Ok(ResourceAssignmentFence {
                    resource_uid: uid,
                    resource_revision: revision,
                    provider_generation,
                    controller_generation,
                    controller_role,
                    target: execution_target,
                    session_generation,
                    epoch,
                    scope: ResourceAssignmentScope::Primary,
                })
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
        let resources = response
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
            .collect::<Vec<_>>();
        assert_eq!(resources.len(), end - start);
        Ok((resources, committed_at))
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

    pub async fn delete_process(&self, resource: &StoredResource) {
        let mut identity = wire::ResourceIdentity::new();
        identity.zone = resource.zone.to_canonical_string();
        identity.resource_type = resource.resource_ref.resource_type().as_str().to_owned();
        identity.name = resource.resource_ref.name().as_str().to_owned();
        identity.uid = Some(resource.uid.as_str().to_owned());
        identity.revision = Some(resource.revision.get());
        let mut precondition = wire::Precondition::new();
        precondition.kind = d2b_resource_api::protobuf::EnumOrUnknown::new(
            wire::PreconditionKind::PRECONDITION_KIND_EXACT_REVISION,
        );
        precondition.expected_uid = Some(resource.uid.as_str().to_owned());
        precondition.expected_revision = Some(resource.revision.get());
        let mut mutation = wire::Mutation::new();
        mutation.kind = d2b_resource_api::protobuf::EnumOrUnknown::new(
            wire::MutationKind::MUTATION_KIND_DELETE,
        );
        mutation.target = d2b_resource_api::protobuf::MessageField::some(identity);
        mutation.precondition = d2b_resource_api::protobuf::MessageField::some(precondition);
        let mut request = wire::CommitBatchRequest::new();
        request.meta = d2b_resource_api::protobuf::MessageField::some(request_meta(
            &format!("reaction-warmup-delete-{}", resource.resource_ref.name().as_str()),
        ));
        request.mutations.push(mutation);
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
                "production warmup Process delete failed: kind={:?} reason={} retry={:?}",
                error.kind,
                error.reason.as_str(),
                error.retry_class
            );
        }
    }

    pub async fn shutdown(self) -> Result<(), StoreError> {
        let Self {
            _directory,
            store,
            claims: _claims,
            client,
            core_assignment_epoch: _core_assignment_epoch,
            core_api,
        } = self;
        drop(client);
        drop(core_api);
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

fn core_subject_context() -> SessionClaims {
    SessionClaims::new(
        ResourceRef::parse("Provider/system-core").expect("fixed Core subject"),
        ResourceUid::parse("33333333-3333-4333-8333-333333333333")
            .expect("fixed Core subject UID"),
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
    .with_provider_ref(ResourceRef::parse("Provider/system-core").expect("fixed Provider"))
    .with_provider_generation(
        d2b_contracts_resource::v3::ResourceGeneration::new(1)
            .expect("fixed Provider generation"),
    )
    .with_controller_generation(
        d2b_contracts_resource::v3::ControllerGeneration::new(3)
            .expect("fixed controller generation"),
    )
}

fn core_policy(subject: &SessionClaims) -> PolicySet {
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
        [BoundSubject {
            subject_ref: subject.subject_ref().clone(),
            subject_uid: subject.subject_uid().clone(),
        }],
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
