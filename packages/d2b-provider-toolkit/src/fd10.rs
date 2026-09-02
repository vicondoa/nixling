//! Supervised Provider binary bootstrap over the inherited fd 10 handoff.

use std::{
    collections::VecDeque,
    sync::Arc,
    time::{Duration, Instant},
};

use d2b_contracts_provider::v3::credential::CredentialProvider;
use d2b_contracts_resource::v3::{
    ControllerGeneration, ResourceGeneration, ResourceRef, ResourceUid, SchemaFingerprint, ZoneId,
    identity::{
        AuthenticatedSubjectContext, EvidenceClass, ServiceName, SessionBinding, SessionPurpose,
        TranscriptHash, TransportBinding as IdentityTransportBinding,
    },
};
use d2b_contracts_zone_session::v3::{
    component_session::{
        EndpointPolicy, EndpointRole as ComponentEndpointRole, Locality as ComponentLocality,
        PurposeClass, TransportClass,
    },
    zone_routing::{ZoneLabelId, ZonePath},
};
use d2b_session::{
    AuthenticatedSessionRouteBinding, ComponentSessionDriver, HandshakeCredentials,
    SessionDriverHandle, SessionEngine, StreamEvent, StreamId,
};
use d2b_session_unix::{
    AncillaryCapacity, CONTROLLER_BOOTSTRAP_TIMEOUT, DescriptorPolicyResolver, PeerIdentityPolicy,
    SeqpacketSocket, UnixSeqpacketTransport, UnixSessionError,
    controller_bootstrap_attachment_policy, controller_credit_scopes,
    credential_provider_endpoint_policy, prearmed_seqpacket_pair,
};
use serde::{Deserialize, Serialize};

use crate::{
    AllocatorSessionBinding, ProviderAgentBootstrap, ProviderEntrypoint, ProviderRuntimeError,
    ProviderSessionAdmission, credential_service,
};

const PROVIDER_BOOTSTRAP_FD: i32 = 10;
/// Named stream carrying the authenticated Provider route bootstrap.
pub const PROVIDER_BOOTSTRAP_STREAM_ID: u16 = 0x0102;
/// Initial bounded credit for the Provider route bootstrap stream.
pub const PROVIDER_BOOTSTRAP_STREAM_CREDIT: u32 = 64 * 1024;
/// Named stream carrying the post-admission Provider readiness receipt.
pub const PROVIDER_READY_STREAM_ID: u16 = 0x0103;
/// Initial bounded credit for the Provider readiness stream.
pub const PROVIDER_READY_STREAM_CREDIT: u32 = 256;
/// Protected readiness receipt sent only after the typed service is live.
pub const PROVIDER_READY_MARKER: &[u8] = b"d2b-provider-ready-v1";
const PROVIDER_BOOTSTRAP_MAX_BYTES: usize = 64 * 1024;
const PROVIDER_BOOTSTRAP_PROTOCOL: &str = "d2b-provider-session-bootstrap-v1";

/// Exact static configuration compiled into one Provider binary.
pub struct ProviderFd10Spec {
    name: &'static str,
    provider_ref: ResourceRef,
    service: &'static str,
    accepted_purpose: SessionPurpose,
}

impl ProviderFd10Spec {
    /// Bind one binary to its immutable Provider service identity.
    pub fn new(
        name: &'static str,
        provider_ref: ResourceRef,
        service: &'static str,
        accepted_purpose: SessionPurpose,
    ) -> Self {
        Self {
            name,
            provider_ref,
            service,
            accepted_purpose,
        }
    }
}

/// Non-secret route metadata sent by d2bd after it authenticates the child
/// ComponentSession. The protected session remains the source of authority.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProviderSessionMetadata {
    protocol: String,
    zone: ZoneId,
    provider_ref: ResourceRef,
    subject_ref: ResourceRef,
    subject_uid: ResourceUid,
    zone_ref: ResourceRef,
    evidence_class: EvidenceClass,
    execution_ref: Option<ResourceRef>,
    process_ref: Option<ResourceRef>,
    provider_generation: Option<ResourceGeneration>,
    controller_generation: Option<ControllerGeneration>,
    session_purpose: SessionPurpose,
    service: ServiceName,
    schema_fingerprint: SchemaFingerprint,
    transport_binding: IdentityTransportBinding,
    reconnect_generation: d2b_contracts_resource::v3::identity::ReconnectGeneration,
    transcript_hash: TranscriptHash,
    endpoint_locality: ComponentLocality,
    purpose_class: PurposeClass,
    initiator_role: ComponentEndpointRole,
    responder_role: ComponentEndpointRole,
    transport_class: TransportClass,
}

impl ProviderSessionMetadata {
    /// Snapshot an authenticated route into bounded, non-secret wire metadata.
    pub fn from_route(
        route: &AuthenticatedSessionRouteBinding,
    ) -> Result<Self, ProviderRuntimeError> {
        let provider_ref = route
            .provider_ref()
            .cloned()
            .ok_or(ProviderRuntimeError::SessionUnauthenticated)?;
        Ok(Self {
            protocol: PROVIDER_BOOTSTRAP_PROTOCOL.to_owned(),
            zone: route.zone().clone(),
            provider_ref,
            subject_ref: route.subject_ref().clone(),
            subject_uid: route.subject_uid().clone(),
            zone_ref: route.context().zone_ref().clone(),
            evidence_class: route.evidence_class(),
            execution_ref: route.context().execution_ref().cloned(),
            process_ref: route.context().process_ref().cloned(),
            provider_generation: route.provider_generation(),
            controller_generation: route.controller_generation(),
            session_purpose: route.context().session_purpose().clone(),
            service: route.service().clone(),
            schema_fingerprint: route.schema().clone(),
            transport_binding: route.transport_binding().clone(),
            reconnect_generation: route.reconnect_generation(),
            transcript_hash: route.context().transcript_hash().clone(),
            endpoint_locality: route.endpoint_locality(),
            purpose_class: route.purpose_class(),
            initiator_role: route.initiator_role(),
            responder_role: route.responder_role(),
            transport_class: route.transport_class(),
        })
    }

    /// Encode the bounded route bootstrap.
    pub fn encode(&self) -> Result<Vec<u8>, ProviderRuntimeError> {
        let bytes =
            serde_json::to_vec(self).map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
        if bytes.len() > PROVIDER_BOOTSTRAP_MAX_BYTES {
            return Err(ProviderRuntimeError::SessionUnauthenticated);
        }
        Ok(bytes)
    }

    /// Decode and validate the bounded route bootstrap envelope.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProviderRuntimeError> {
        if bytes.len() > PROVIDER_BOOTSTRAP_MAX_BYTES {
            return Err(ProviderRuntimeError::SessionUnauthenticated);
        }
        let metadata: Self = serde_json::from_slice(bytes)
            .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
        if metadata.protocol != PROVIDER_BOOTSTRAP_PROTOCOL {
            return Err(ProviderRuntimeError::SessionUnauthenticated);
        }
        Ok(metadata)
    }

    fn allocator_binding(&self) -> Result<AllocatorSessionBinding, ProviderRuntimeError> {
        let zone = ZonePath::new(vec![
            ZoneLabelId::parse(self.zone.as_str())
                .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?,
        ])
        .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
        Ok(AllocatorSessionBinding::new(
            zone,
            self.provider_ref.clone(),
            self.session_purpose.clone(),
            self.transport_binding.clone(),
        ))
    }

    fn route(&self) -> Result<AuthenticatedSessionRouteBinding, ProviderRuntimeError> {
        if self.provider_ref.resource_type().as_str() != "Provider"
            || self.zone_ref.resource_type().as_str() != "Zone"
            || self.zone_ref.name().as_str() != self.zone.as_str()
            || self.provider_generation.is_none()
            || self.controller_generation.is_none()
            || self.reconnect_generation.get() == 0
            || self.transport_binding.locality()
                != d2b_contracts_resource::v3::identity::Locality::Local
        {
            return Err(ProviderRuntimeError::SessionUnauthenticated);
        }
        let session = SessionBinding::new(
            self.schema_fingerprint.clone(),
            self.transport_binding.clone(),
            self.reconnect_generation,
            self.transcript_hash.clone(),
        );
        let mut context = AuthenticatedSubjectContext::new(
            self.subject_ref.clone(),
            self.subject_uid.clone(),
            self.zone_ref.clone(),
            self.evidence_class,
            self.session_purpose.clone(),
            self.service.clone(),
            session,
        )
        .with_provider_ref(self.provider_ref.clone());
        if let Some(execution_ref) = self.execution_ref.clone() {
            context = context.with_execution_ref(execution_ref);
        }
        if let Some(process_ref) = self.process_ref.clone() {
            context = context.with_process_ref(process_ref);
        }
        if let Some(provider_generation) = self.provider_generation {
            context = context.with_provider_generation(provider_generation);
        }
        if let Some(controller_generation) = self.controller_generation {
            context = context.with_controller_generation(controller_generation);
        }
        AuthenticatedSessionRouteBinding::from_authenticated_peer(
            context,
            self.endpoint_locality,
            self.purpose_class,
            self.initiator_role,
            self.responder_role,
            self.transport_class,
        )
        .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)
    }
}

impl std::fmt::Debug for ProviderSessionMetadata {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProviderSessionMetadata(<redacted>)")
    }
}

/// Run one Provider's real supervised fd10 lifecycle.
pub fn run_from_fd10<P, A, F>(spec: ProviderFd10Spec, factory: F) -> i32
where
    P: CredentialProvider + 'static,
    A: crate::CredentialAuthorizationSource,
    F: FnOnce(&AuthenticatedSessionRouteBinding) -> Result<(Arc<P>, Arc<A>), ProviderRuntimeError>
        + Send
        + 'static,
{
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => return 1,
    };
    match runtime.block_on(run_from_fd10_async(spec, factory)) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

async fn run_from_fd10_async<P, A, F>(
    spec: ProviderFd10Spec,
    factory: F,
) -> Result<(), ProviderRuntimeError>
where
    P: CredentialProvider + 'static,
    A: crate::CredentialAuthorizationSource,
    F: FnOnce(&AuthenticatedSessionRouteBinding) -> Result<(Arc<P>, Arc<A>), ProviderRuntimeError>
        + Send
        + 'static,
{
    let bootstrap = SeqpacketSocket::from_inherited_fd(PROVIDER_BOOTSTRAP_FD)
        .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    let expected_peer = bootstrap
        .acceptor_peer_credentials()
        .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    let (daemon_endpoint, controller_endpoint) =
        prearmed_seqpacket_pair().map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    let controller_socket = SeqpacketSocket::from_parent_prearmed(controller_endpoint)
        .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    send_controller_bootstrap(&bootstrap, daemon_endpoint).await?;
    let policy = credential_provider_endpoint_policy();
    let transport = provider_transport(controller_socket, &policy, expected_peer)?;
    let engine = SessionEngine::establish_initiator(
        transport,
        policy,
        HandshakeCredentials::Nn,
        Instant::now(),
    )
    .await
    .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    let driver = engine.into_driver();
    let bootstrap_stream = StreamId::new(PROVIDER_BOOTSTRAP_STREAM_ID)
        .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    driver
        .open_named_stream(
            bootstrap_stream,
            PROVIDER_BOOTSTRAP_STREAM_CREDIT,
            PROVIDER_BOOTSTRAP_STREAM_CREDIT,
        )
        .await
        .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    let metadata = ProviderSessionMetadata::decode(&receive_route_metadata(&driver).await?)?;
    if metadata.provider_ref != spec.provider_ref
        || metadata.service.as_str() != spec.service
        || metadata.session_purpose != spec.accepted_purpose
        || metadata.reconnect_generation.get() != driver.generation()
    {
        return Err(ProviderRuntimeError::SessionUnauthenticated);
    }
    let route = metadata.route()?;
    let bootstrap_identity = ProviderAgentBootstrap::new(
        spec.provider_ref.clone(),
        ZonePath::new(vec![
            ZoneLabelId::parse(metadata.zone.as_str())
                .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?,
        ])
        .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?,
        spec.accepted_purpose.clone(),
    );
    bootstrap_identity
        .admit(metadata.allocator_binding()?)
        .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;

    let mut entrypoint =
        ProviderEntrypoint::with_provider(spec.name, spec.provider_ref, spec.service)?;
    if let Some(execution_ref) = route.context().execution_ref().cloned() {
        entrypoint = entrypoint.with_execution_target(execution_ref)?;
    }
    if let Some(process_ref) = route.context().process_ref().cloned() {
        entrypoint = entrypoint.with_controller_process(process_ref)?;
    }
    if let (Some(provider_generation), Some(controller_generation)) =
        (route.provider_generation(), route.controller_generation())
    {
        entrypoint = entrypoint.with_generations(provider_generation, controller_generation)?;
    }
    let registration = entrypoint.admit()?;
    let session_admission = entrypoint.admit_authenticated(&route)?;
    let (provider, authorizer) = factory(&route)?;
    serve_provider_route(
        entrypoint,
        registration,
        session_admission,
        Arc::new(driver),
        route,
        provider,
        authorizer,
    )
    .await
}

async fn send_controller_bootstrap(
    bootstrap: &SeqpacketSocket,
    daemon_endpoint: std::os::fd::OwnedFd,
) -> Result<(), ProviderRuntimeError> {
    let policy = controller_bootstrap_attachment_policy();
    let capacity = AncillaryCapacity::from_policy(policy)
        .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    let scopes =
        controller_credit_scopes().map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    let packet = d2b_session_unix::OutboundPacket::with_current_credentials(
        d2b_session_unix::CONTROLLER_BOOTSTRAP_PROTOCOL_MARKER.to_vec(),
        vec![Arc::new(daemon_endpoint)],
        d2b_contracts_zone_session::v3::component_session::LimitProfile::local_default(),
        capacity,
        &scopes,
    )
    .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    let mut queue = VecDeque::from([packet]);
    let sent = tokio::time::timeout(
        CONTROLLER_BOOTSTRAP_TIMEOUT,
        bootstrap.send_burst(&mut queue, capacity, 1),
    )
    .await
    .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?
    .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    if sent.sent.len() != 1 || !queue.is_empty() {
        return Err(ProviderRuntimeError::SessionUnauthenticated);
    }
    for packet in sent.sent {
        packet.acknowledge();
    }
    Ok(())
}

fn provider_transport(
    socket: SeqpacketSocket,
    policy: &EndpointPolicy,
    expected_peer: d2b_session_unix::PeerCredentials,
) -> Result<UnixSeqpacketTransport, ProviderRuntimeError> {
    let resolver: DescriptorPolicyResolver =
        Arc::new(|_| Err(UnixSessionError::DescriptorMismatch));
    UnixSeqpacketTransport::new(
        socket,
        policy.transport_binding.locality,
        policy.limits,
        policy.attachment_policy,
        controller_credit_scopes().map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?,
        resolver,
        PeerIdentityPolicy::inherited_socketpair(expected_peer),
    )
    .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)
}

async fn receive_route_metadata(
    driver: &SessionDriverHandle,
) -> Result<Vec<u8>, ProviderRuntimeError> {
    let stream = StreamId::new(PROVIDER_BOOTSTRAP_STREAM_ID)
        .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
    let mut bytes = Vec::new();
    loop {
        match driver
            .receive_named_stream_for(stream)
            .await
            .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?
        {
            StreamEvent::Data {
                stream: received,
                bytes: chunk,
            } if received == stream => {
                bytes.extend_from_slice(&chunk);
                if bytes.len() > PROVIDER_BOOTSTRAP_MAX_BYTES {
                    return Err(ProviderRuntimeError::SessionUnauthenticated);
                }
                driver
                    .grant_named_stream_credit(
                        stream,
                        u32::try_from(chunk.len())
                            .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?,
                    )
                    .await
                    .map_err(|_| ProviderRuntimeError::SessionUnauthenticated)?;
            }
            StreamEvent::RemoteClosed { stream: closed } if closed == stream => return Ok(bytes),
            StreamEvent::Reset { .. } => {
                return Err(ProviderRuntimeError::SessionUnauthenticated);
            }
            _ => return Err(ProviderRuntimeError::SessionUnauthenticated),
        }
    }
}

async fn serve_provider_route<P, A>(
    entrypoint: ProviderEntrypoint,
    registration: crate::ProviderAdmission,
    session_admission: ProviderSessionAdmission,
    driver: Arc<dyn ComponentSessionDriver>,
    route: AuthenticatedSessionRouteBinding,
    provider: Arc<P>,
    authorizer: Arc<A>,
) -> Result<(), ProviderRuntimeError>
where
    P: CredentialProvider + 'static,
    A: crate::CredentialAuthorizationSource,
{
    let services = credential_service(provider, authorizer, route.clone());
    let serving = tokio::spawn(d2b_session::serve_ttrpc_services(
        Arc::clone(&driver),
        services,
    ));
    tokio::task::yield_now().await;
    if serving.is_finished() {
        let _ = serving.await;
        return Err(ProviderRuntimeError::SessionLoopFailed);
    }
    if entrypoint
        .publish_authenticated_ready(&registration, session_admission, &route)
        .is_err()
    {
        serving.abort();
        let _ = serving.await;
        return Err(ProviderRuntimeError::SessionLoopFailed);
    }
    let ready_result = async {
        let stream = StreamId::new(PROVIDER_READY_STREAM_ID)
            .map_err(|_| ProviderRuntimeError::SessionLoopFailed)?;
        driver
            .open_named_stream(
                stream,
                PROVIDER_READY_STREAM_CREDIT,
                PROVIDER_READY_STREAM_CREDIT,
            )
            .await
            .map_err(|_| ProviderRuntimeError::SessionLoopFailed)?;
        driver
            .send_named_stream(stream, PROVIDER_READY_MARKER.to_vec())
            .await
            .map_err(|_| ProviderRuntimeError::SessionLoopFailed)?;
        driver
            .close_named_stream(stream)
            .await
            .map_err(|_| ProviderRuntimeError::SessionLoopFailed)
    }
    .await;
    if let Err(error) = ready_result {
        serving.abort();
        let _ = serving.await;
        return Err(error);
    }
    let result = serving
        .await
        .map_err(|_| ProviderRuntimeError::SessionLoopFailed)?
        .map_err(|_| ProviderRuntimeError::SessionLoopFailed);
    let _ = driver
        .close(
            d2b_contracts_zone_session::v3::component_session::CloseReason::Normal,
            d2b_contracts_zone_session::v3::component_session::Remediation::None,
        )
        .await;
    drop(registration);
    if !entrypoint.drain(Duration::from_secs(5)) {
        return Err(ProviderRuntimeError::SessionLoopFailed);
    }
    result
}
