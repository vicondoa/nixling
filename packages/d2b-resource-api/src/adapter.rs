//! Authenticated Resource API dispatch over a ComponentSession.
//!
//! The Zone runtime binds this adapter only after the d2b-bus session has
//! authenticated the subject and the live policy has granted `Connect`.

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use d2b_contracts_resource::resource_proto as wire;
use d2b_contracts_resource::v3::{ResourceName, ResourceTypeName};
use d2b_core_controller::controller_assignment::{
    AssignmentTransportError, ScopedCommitTransport, ScopedResourceMutation,
};
use d2b_resource_store::StoreFilter;
use protobuf::Message;
use ttrpc::proto::{
    MESSAGE_HEADER_LENGTH, MESSAGE_TYPE_REQUEST, MessageHeader, Request as TtrpcRequest,
};

use crate::{
    ResourceStoreBackend,
    authz::authenticated_relay_hop,
    client::ResourceApiClient,
    generated::d2b_resource_v3_ttrpc,
    identity::AuthenticatedSubjectContext,
    service::{ResourceService, TrustedRequest, UpgradeDispatcher},
};

/// Failure while attaching assignment evidence to a Resource CommitBatch
/// frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopedCommitFrameError {
    InvalidFrame,
    InvalidRequest,
    Assignment(AssignmentTransportError),
}

impl core::fmt::Display for ScopedCommitFrameError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFrame => "scoped-commit-frame-invalid",
            Self::InvalidRequest => "scoped-commit-request-invalid",
            Self::Assignment(error) => error.code(),
        })
    }
}

impl std::error::Error for ScopedCommitFrameError {}

/// Failure while attaching an admitted List or Watch selector to a ttrpc
/// frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopedQueryFrameError {
    InvalidFrame,
    InvalidRequest,
}

impl core::fmt::Display for ScopedQueryFrameError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFrame => "scoped-query-frame-invalid",
            Self::InvalidRequest => "scoped-query-request-invalid",
        })
    }
}

impl std::error::Error for ScopedQueryFrameError {}

/// Attach bus-admitted assignment evidence to the existing ttrpc CommitBatch
/// request without creating another transport.
pub fn attach_scoped_commit_frame(
    frame: &[u8],
    transport: &ScopedCommitTransport,
) -> Result<Vec<u8>, ScopedCommitFrameError> {
    let header_bytes: [u8; MESSAGE_HEADER_LENGTH] = frame
        .get(..MESSAGE_HEADER_LENGTH)
        .ok_or(ScopedCommitFrameError::InvalidFrame)?
        .try_into()
        .map_err(|_| ScopedCommitFrameError::InvalidFrame)?;
    let header = MessageHeader::from(header_bytes);
    let body_len =
        usize::try_from(header.length).map_err(|_| ScopedCommitFrameError::InvalidFrame)?;
    if header.type_ != MESSAGE_TYPE_REQUEST
        || frame.len() != MESSAGE_HEADER_LENGTH.saturating_add(body_len)
    {
        return Err(ScopedCommitFrameError::InvalidFrame);
    }
    let mut rpc = TtrpcRequest::parse_from_bytes(&frame[MESSAGE_HEADER_LENGTH..])
        .map_err(|_| ScopedCommitFrameError::InvalidRequest)?;
    if rpc.service != "d2b.resource.v3.ResourceService" || rpc.method != "CommitBatch" {
        return Err(ScopedCommitFrameError::InvalidRequest);
    }
    let mut request = wire::CommitBatchRequest::parse_from_bytes(&rpc.payload)
        .map_err(|_| ScopedCommitFrameError::InvalidRequest)?;
    if !request.scoped_admission.is_empty() {
        return Err(ScopedCommitFrameError::InvalidRequest);
    }
    request.scoped_admission = transport
        .encode()
        .map_err(ScopedCommitFrameError::Assignment)?;
    rpc.payload = request
        .write_to_bytes()
        .map_err(|_| ScopedCommitFrameError::InvalidRequest)?;
    let body = rpc
        .write_to_bytes()
        .map_err(|_| ScopedCommitFrameError::InvalidRequest)?;
    let mut header = header;
    header.length = u32::try_from(body.len()).map_err(|_| ScopedCommitFrameError::InvalidFrame)?;
    let mut result = Vec::with_capacity(MESSAGE_HEADER_LENGTH + body.len());
    result.extend_from_slice(&Vec::from(header));
    result.extend_from_slice(&body);
    Ok(result)
}

/// Attach an admitted List or Watch selector to the existing ttrpc request.
///
/// The selector inputs are transport-neutral so the resource API does not
/// depend on the message bus's query type.
pub fn attach_scoped_query_frame(
    frame: &[u8],
    resource_types: &[ResourceTypeName],
    resource_names: &[ResourceName],
    filters: &[StoreFilter],
    watch: bool,
) -> Result<Vec<u8>, ScopedQueryFrameError> {
    let header_bytes: [u8; MESSAGE_HEADER_LENGTH] = frame
        .get(..MESSAGE_HEADER_LENGTH)
        .ok_or(ScopedQueryFrameError::InvalidFrame)?
        .try_into()
        .map_err(|_| ScopedQueryFrameError::InvalidFrame)?;
    let header = MessageHeader::from(header_bytes);
    let body_len =
        usize::try_from(header.length).map_err(|_| ScopedQueryFrameError::InvalidFrame)?;
    if header.type_ != MESSAGE_TYPE_REQUEST
        || frame.len() != MESSAGE_HEADER_LENGTH.saturating_add(body_len)
    {
        return Err(ScopedQueryFrameError::InvalidFrame);
    }
    let mut rpc = TtrpcRequest::parse_from_bytes(&frame[MESSAGE_HEADER_LENGTH..])
        .map_err(|_| ScopedQueryFrameError::InvalidRequest)?;
    let expected_method = if watch { "Watch" } else { "List" };
    if rpc.service != "d2b.resource.v3.ResourceService" || rpc.method != expected_method {
        return Err(ScopedQueryFrameError::InvalidRequest);
    }
    let mut wire_filters = filters
        .iter()
        .map(|filter| {
            let mut wire = wire::ListFilter::new();
            wire.field = filter.field.clone();
            wire.values = filter.values.clone();
            wire
        })
        .collect::<Vec<_>>();
    if !resource_names.is_empty() {
        let mut names = wire::ListFilter::new();
        names.field = "metadata.name".to_owned();
        names.values = resource_names
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect();
        wire_filters.push(names);
    }
    let resource_types = resource_types
        .iter()
        .map(|resource_type| resource_type.as_str().to_owned())
        .collect();
    if watch {
        let mut request = wire::WatchRequest::parse_from_bytes(&rpc.payload)
            .map_err(|_| ScopedQueryFrameError::InvalidRequest)?;
        request.resource_types = resource_types;
        request.filters = wire_filters;
        rpc.payload = request
            .write_to_bytes()
            .map_err(|_| ScopedQueryFrameError::InvalidRequest)?;
    } else {
        let mut request = wire::ListRequest::parse_from_bytes(&rpc.payload)
            .map_err(|_| ScopedQueryFrameError::InvalidRequest)?;
        request.resource_types = resource_types;
        request.filters = wire_filters;
        rpc.payload = request
            .write_to_bytes()
            .map_err(|_| ScopedQueryFrameError::InvalidRequest)?;
    }
    let body = rpc
        .write_to_bytes()
        .map_err(|_| ScopedQueryFrameError::InvalidRequest)?;
    let mut header = header;
    header.length = u32::try_from(body.len()).map_err(|_| ScopedQueryFrameError::InvalidFrame)?;
    let mut result = Vec::with_capacity(MESSAGE_HEADER_LENGTH + body.len());
    result.extend_from_slice(&Vec::from(header));
    result.extend_from_slice(&body);
    Ok(result)
}

/// Decode the optional assignment evidence carried by a CommitBatch request.
pub fn decode_scoped_commit_request(
    request: &wire::CommitBatchRequest,
) -> Result<Option<ScopedCommitTransport>, AssignmentTransportError> {
    if request.scoped_admission.is_empty() {
        return Ok(None);
    }
    ScopedCommitTransport::decode(&request.scoped_admission).map(Some)
}

/// Reject assignment evidence supplied by an ordinary CommitBatch caller.
///
/// Scoped evidence is bus-owned. A plain ResourceCall must never be able to
/// smuggle the field through the same RPC and receive a storage fence.
pub fn reject_scoped_commit_frame(frame: &[u8]) -> Result<(), ScopedCommitFrameError> {
    let header_bytes: [u8; MESSAGE_HEADER_LENGTH] = frame
        .get(..MESSAGE_HEADER_LENGTH)
        .ok_or(ScopedCommitFrameError::InvalidFrame)?
        .try_into()
        .map_err(|_| ScopedCommitFrameError::InvalidFrame)?;
    let header = MessageHeader::from(header_bytes);
    let body_len =
        usize::try_from(header.length).map_err(|_| ScopedCommitFrameError::InvalidFrame)?;
    if header.type_ != MESSAGE_TYPE_REQUEST
        || frame.len() != MESSAGE_HEADER_LENGTH.saturating_add(body_len)
    {
        return Err(ScopedCommitFrameError::InvalidFrame);
    }
    let rpc = TtrpcRequest::parse_from_bytes(&frame[MESSAGE_HEADER_LENGTH..])
        .map_err(|_| ScopedCommitFrameError::InvalidRequest)?;
    if rpc.service != "d2b.resource.v3.ResourceService" || rpc.method != "CommitBatch" {
        return Err(ScopedCommitFrameError::InvalidRequest);
    }
    let request = wire::CommitBatchRequest::parse_from_bytes(&rpc.payload)
        .map_err(|_| ScopedCommitFrameError::InvalidRequest)?;
    if request.scoped_admission.is_empty() {
        Ok(())
    } else {
        Err(ScopedCommitFrameError::InvalidRequest)
    }
}

/// Failure to bind an authenticated ComponentSession route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdapterBindingError;

impl core::fmt::Display for AdapterBindingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("authenticated bus route is not valid for the resource API")
    }
}

impl std::error::Error for AdapterBindingError {}

/// Current production reachability of the resource service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceApiReachability {
    RegisteredOnAuthenticatedComponentSession,
}

pub const RESOURCE_API_REACHABILITY: ResourceApiReachability =
    ResourceApiReachability::RegisteredOnAuthenticatedComponentSession;

/// Session-scoped dispatcher registered on an authenticated Resource server.
pub struct ResourceBusAdapter<S, U> {
    service: Arc<ResourceService<S, U>>,
    session: AuthenticatedSubjectContext,
}

impl<S, U> core::fmt::Debug for ResourceBusAdapter<S, U> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ResourceBusAdapter(<redacted>)")
    }
}

impl<S, U> ResourceBusAdapter<S, U>
where
    S: ResourceStoreBackend,
    U: UpgradeDispatcher,
{
    /// Seal authenticated identity and policy state to one ComponentSession.
    pub fn bind_component_session(
        service: Arc<ResourceService<S, U>>,
        session: AuthenticatedSubjectContext,
    ) -> Result<Self, AdapterBindingError> {
        authenticated_relay_hop(session.claims()).map_err(|_| AdapterBindingError)?;
        Ok(Self { service, session })
    }

    /// Return an explicitly authenticated in-process contract client.
    pub fn client(&self) -> ResourceApiClient<S, U> {
        ResourceApiClient::from_session_capability(
            Arc::clone(&self.service),
            Arc::clone(self.session.claims()),
            self.session.authorization_state().clone(),
        )
    }

    /// Dispatch one scoped commit through the existing authenticated adapter.
    pub async fn scoped_commit_batch(
        &self,
        request: wire::CommitBatchRequest,
        scoped_mutations: Vec<ScopedResourceMutation>,
    ) -> wire::CommitBatchResponse {
        self.client()
            .scoped_commit_batch(request, scoped_mutations)
            .await
    }

    pub(crate) fn service(&self) -> &ResourceService<S, U> {
        &self.service
    }

    pub(crate) fn trusted<T>(&self, request: T) -> TrustedRequest<T> {
        TrustedRequest::from_session_capability(
            Arc::clone(self.session.claims()),
            self.session.authorization_state().clone(),
            request,
        )
    }
}

impl<S, U> ResourceBusAdapter<S, U>
where
    S: ResourceStoreBackend + 'static,
    U: UpgradeDispatcher + 'static,
{
    /// Build the generated service map for the authenticated session server.
    pub fn ttrpc_services(self: Arc<Self>) -> HashMap<String, ttrpc::r#async::Service> {
        d2b_resource_v3_ttrpc::create_resource_service(self)
    }
}

#[async_trait]
impl<S, U> d2b_resource_v3_ttrpc::ResourceService for ResourceBusAdapter<S, U>
where
    S: ResourceStoreBackend + 'static,
    U: UpgradeDispatcher + 'static,
{
    async fn get(
        &self,
        _ctx: &ttrpc::r#async::TtrpcContext,
        request: wire::GetRequest,
    ) -> ttrpc::Result<wire::GetResponse> {
        Ok(self.service().get(self.trusted(request)).await)
    }

    async fn list(
        &self,
        _ctx: &ttrpc::r#async::TtrpcContext,
        request: wire::ListRequest,
    ) -> ttrpc::Result<wire::ListResponse> {
        Ok(self.service().list(self.trusted(request)).await)
    }

    async fn watch(
        &self,
        _ctx: &ttrpc::r#async::TtrpcContext,
        request: wire::WatchRequest,
    ) -> ttrpc::Result<wire::WatchResponse> {
        Ok(self.service().watch(self.trusted(request)).await)
    }

    async fn create(
        &self,
        _ctx: &ttrpc::r#async::TtrpcContext,
        request: wire::CreateRequest,
    ) -> ttrpc::Result<wire::CreateResponse> {
        Ok(self.service().create(self.trusted(request)).await)
    }

    async fn update_spec(
        &self,
        _ctx: &ttrpc::r#async::TtrpcContext,
        request: wire::UpdateSpecRequest,
    ) -> ttrpc::Result<wire::UpdateSpecResponse> {
        Ok(self.service().update_spec(self.trusted(request)).await)
    }

    async fn update_status(
        &self,
        _ctx: &ttrpc::r#async::TtrpcContext,
        request: wire::UpdateStatusRequest,
    ) -> ttrpc::Result<wire::UpdateStatusResponse> {
        Ok(self.service().update_status(self.trusted(request)).await)
    }

    async fn update_metadata(
        &self,
        _ctx: &ttrpc::r#async::TtrpcContext,
        request: wire::UpdateMetadataRequest,
    ) -> ttrpc::Result<wire::UpdateMetadataResponse> {
        Ok(self.service().update_metadata(self.trusted(request)).await)
    }

    async fn update_finalizers(
        &self,
        _ctx: &ttrpc::r#async::TtrpcContext,
        request: wire::UpdateFinalizersRequest,
    ) -> ttrpc::Result<wire::UpdateFinalizersResponse> {
        Ok(self
            .service()
            .update_finalizers(self.trusted(request))
            .await)
    }

    async fn delete(
        &self,
        _ctx: &ttrpc::r#async::TtrpcContext,
        request: wire::DeleteRequest,
    ) -> ttrpc::Result<wire::DeleteResponse> {
        Ok(self.service().delete(self.trusted(request)).await)
    }

    async fn commit_batch(
        &self,
        _ctx: &ttrpc::r#async::TtrpcContext,
        request: wire::CommitBatchRequest,
    ) -> ttrpc::Result<wire::CommitBatchResponse> {
        let scoped = match decode_scoped_commit_request(&request) {
            Ok(scoped) => scoped,
            Err(_) => {
                return Ok(ResourceService::<S, U>::invalid_commit_batch(
                    "scoped commit transport is invalid",
                ));
            }
        };
        Ok(match scoped {
            Some(transport) => {
                self.client()
                    .scoped_commit_batch(request, transport.mutations().to_vec())
                    .await
            }
            None => self.service().commit_batch(self.trusted(request)).await,
        })
    }

    async fn resolve_ref(
        &self,
        _ctx: &ttrpc::r#async::TtrpcContext,
        request: wire::ResolveRefRequest,
    ) -> ttrpc::Result<wire::ResolveRefResponse> {
        Ok(self.service().resolve_ref(self.trusted(request)).await)
    }

    async fn inspect_schema(
        &self,
        _ctx: &ttrpc::r#async::TtrpcContext,
        request: wire::InspectSchemaRequest,
    ) -> ttrpc::Result<wire::InspectSchemaResponse> {
        Ok(self.service().inspect_schema(self.trusted(request)).await)
    }

    async fn upgrade(
        &self,
        _ctx: &ttrpc::r#async::TtrpcContext,
        request: wire::UpgradeRequest,
    ) -> ttrpc::Result<wire::UpgradeResponse> {
        Ok(self.service().upgrade(self.trusted(request)).await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeSet, sync::Mutex};

    use d2b_contracts_resource::v3::identity::{
        AuthenticatedSubjectContext as SessionClaims, BindingDigest, EvidenceClass, Locality,
        ReconnectGeneration, ServiceName, SessionBinding, SessionPurpose, TranscriptHash,
        TransportBinding,
    };
    use d2b_contracts_resource::v3::{
        CanonicalJsonValue, ConfigurationGeneration, ControllerGeneration,
        RESOURCE_ENVELOPE_DOMAIN_TAG, ResourceEnvelope, ResourceGeneration, ResourceName,
        ResourceRef, ResourceTypeName, ResourceUid, SchemaFingerprint, ZoneId, ZoneRevision,
        canonical_digest,
    };
    use d2b_core_controller::controller_assignment::{ScopedCommitTransport, ScopedResourceScope};
    use d2b_resource_store::mutation_seal::MutationSealAcceptor;
    use d2b_resource_store::{
        AdmittedVerb, PolicySnapshot, ResourceMutationKind, StoreCommitResult, StoreError,
        StoreGetRequest, StoreInspectSchemaRequest, StoreListRequest, StoreListResult,
        StoreResolveRequest, StoreResolvedIdentity, StoreSealIdentity, StoreSlot,
        StoreWatchReceipt, StoreWatchRequest, StoredResource, StoredSchema,
    };
    use protobuf::{EnumOrUnknown, Message, MessageField};
    use ttrpc::proto::{MessageHeader, Request as TtrpcRequest};

    use crate::ResourceStoreBackend;
    use crate::authz::{
        ApiCatalog, ApiMethod, AuthorizationState, BindingScope, BootstrapPhase, BoundSubject,
        CompiledRole, CompiledRoleBinding, NativeAuthorizer, PolicyRule, PolicySet,
        RelayGrantAuthority, ResourceVerb,
    };
    use crate::identity::issue_test_subject;
    use crate::service::{AuthorizedUpgrade, UpgradeResult};

    const GOLDEN_HOST: &[u8] = br#"{"apiVersion":"resources.d2bus.org/v3","metadata":{"configurationGeneration":7,"createdAt":"2026-07-22T00:00:00.000Z","deletionRequestedAt":null,"finalizers":[],"generation":1,"managedBy":"configuration","name":"host-system","ownerRef":null,"revision":1,"uid":"123e4567-e89b-42d3-a456-426614174000","updatedAt":"2026-07-22T00:00:00.000Z","zone":"dev"},"spec":{"providerRef":"Provider/system-core","updatePolicy":{"disruptive":"manual","nonDisruptive":"automatic"}},"status":{"completedAt":null,"conditions":[],"lastReconciledAt":null,"observedGeneration":0,"outcome":null,"phase":"Pending","resource":{},"startedAt":null,"update":{"dependencies":{"count":0,"refs":[]},"disruption":"None","lastAssessedAt":null,"observedGeneration":0,"operationId":null,"owned":{"count":0,"refs":[]},"preserveState":true,"reasons":[],"state":"Unknown","targetGeneration":1}},"type":"Host"}"#;

    #[derive(Debug)]
    struct UnreachableStore;

    impl UnreachableStore {
        fn paired(
            catalog: ApiCatalog,
            policy: Option<PolicySet>,
        ) -> (Arc<Self>, Arc<NativeAuthorizer>) {
            let authorizer = NativeAuthorizer::new(catalog, policy).unwrap();
            authorizer
                .take_store_seal(test_store_identity())
                .expect("test authorizer receives a store seal");
            (Arc::new(Self), Arc::new(authorizer))
        }
    }

    impl ResourceStoreBackend for UnreachableStore {
        async fn get(&self, _: StoreGetRequest) -> Result<StoredResource, StoreError> {
            unreachable!("authorization must run before the store")
        }

        async fn list(&self, _: StoreListRequest) -> Result<StoreListResult, StoreError> {
            unreachable!("authorization must run before the store")
        }

        async fn watch(&self, _: StoreWatchRequest) -> Result<StoreWatchReceipt, StoreError> {
            unreachable!("authorization must run before the store")
        }

        async fn resolve_ref(
            &self,
            _: StoreResolveRequest,
        ) -> Result<StoreResolvedIdentity, StoreError> {
            unreachable!("authorization must run before the store")
        }

        async fn inspect_schema(
            &self,
            _: StoreInspectSchemaRequest,
        ) -> Result<StoredSchema, StoreError> {
            unreachable!("authorization must run before the store")
        }

        async fn commit_verified(
            &self,
            _: d2b_resource_store::SealedMutation,
        ) -> Result<StoreCommitResult, StoreError> {
            unreachable!("authorization must run before the store")
        }
    }

    fn test_store_identity() -> StoreSealIdentity {
        StoreSealIdentity::new(
            StoreSlot::new(0).unwrap(),
            ZoneId::parse("dev").unwrap(),
            ResourceUid::parse("11111111-1111-4111-8111-111111111111").unwrap(),
        )
    }

    #[test]
    fn scoped_commit_frame_preserves_assignment_evidence_on_existing_rpc() {
        let transport = ScopedCommitTransport::decode(
            br#"{"version":1,"assignment":{"resourceUid":"123e4567-e89b-42d3-a456-426614174000","resourceRevision":7,"providerRef":"Provider/provider-runtime","providerGeneration":2,"controllerGeneration":3,"controllerRole":"Process/process-controller","target":{"kind":"zone","zone":"dev"},"sessionOwner":"Process/process-controller","sessionGeneration":1,"epoch":9},"mutations":[{"target":"Process/work","verb":"UpdateStatus"},{"target":"Process/work","verb":"UpdateFinalizers"}]}"#,
        )
        .unwrap();
        let request = d2b_contracts_resource::resource_proto::CommitBatchRequest::new();
        let rpc = TtrpcRequest {
            service: "d2b.resource.v3.ResourceService".to_owned(),
            method: "CommitBatch".to_owned(),
            payload: request.write_to_bytes().unwrap(),
            ..TtrpcRequest::default()
        };
        let body = rpc.write_to_bytes().unwrap();
        let mut frame = Vec::with_capacity(ttrpc::proto::MESSAGE_HEADER_LENGTH + body.len());
        let mut header = MessageHeader::new_request(1, body.len() as u32);
        header.length = body.len() as u32;
        frame.extend_from_slice(&Vec::from(header));
        frame.extend_from_slice(&body);

        let attached = attach_scoped_commit_frame(&frame, &transport).unwrap();
        let attached_body = &attached[ttrpc::proto::MESSAGE_HEADER_LENGTH..];
        let attached_rpc = TtrpcRequest::parse_from_bytes(attached_body).unwrap();
        let attached_request =
            d2b_contracts_resource::resource_proto::CommitBatchRequest::parse_from_bytes(
                &attached_rpc.payload,
            )
            .unwrap();
        let decoded = decode_scoped_commit_request(&attached_request)
            .unwrap()
            .unwrap();
        assert_eq!(decoded, transport);
        assert!(
            decoded
                .mutations()
                .iter()
                .all(|mutation| matches!(mutation.scope(), ScopedResourceScope::Primary))
        );
    }

    #[test]
    fn scoped_commit_frame_preserves_owner_child_scope() {
        let transport = ScopedCommitTransport::decode(
            br#"{"version":1,"assignment":{"resourceUid":"123e4567-e89b-42d3-a456-426614174000","resourceRevision":7,"providerRef":"Provider/provider-runtime","providerGeneration":2,"controllerGeneration":3,"controllerRole":"Process/process-controller","target":{"kind":"zone","zone":"dev"},"sessionOwner":"Process/process-controller","sessionGeneration":1,"epoch":9},"mutations":[{"target":"Process/work","verb":"UpdateSpec","scope":{"kind":"owner-child","ownerRef":"Guest/guest","ownerUid":"123e4567-e89b-42d3-a456-426614174000","ownerRevision":7,"ownerGeneration":1}}]}"#,
        )
        .unwrap();
        let scope = transport.mutations()[0].scope().owner_child().unwrap();
        assert_eq!(
            scope.owner_ref(),
            &ResourceRef::parse("Guest/guest").unwrap()
        );
        assert_eq!(
            scope.owner_uid().as_str(),
            "123e4567-e89b-42d3-a456-426614174000"
        );
        assert_eq!(scope.owner_revision(), ZoneRevision::new(7));
        assert_eq!(
            scope.owner_generation(),
            ResourceGeneration::new(1).unwrap()
        );
    }

    #[test]
    fn scoped_query_frame_rewrites_list_and_watch_selectors() {
        let resource_types = vec![
            ResourceTypeName::parse(d2b_contracts_resource::v3::process::PROCESS_RESOURCE_TYPE)
                .unwrap(),
        ];
        let owner_uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let filters = vec![StoreFilter {
            field: "owner.resourceUid".to_owned(),
            values: vec![owner_uid.as_str().to_owned()],
        }];

        for (method, watch) in [("List", false), ("Watch", true)] {
            let payload = if watch {
                let mut request = wire::WatchRequest::new();
                request.resource_types.push("Host".to_owned());
                request.filters.push(wire::ListFilter {
                    field: "metadata.name".to_owned(),
                    values: vec!["caller-supplied".to_owned()],
                    ..wire::ListFilter::default()
                });
                request.write_to_bytes().unwrap()
            } else {
                let mut request = wire::ListRequest::new();
                request.resource_types.push("Host".to_owned());
                request.filters.push(wire::ListFilter {
                    field: "metadata.name".to_owned(),
                    values: vec!["caller-supplied".to_owned()],
                    ..wire::ListFilter::default()
                });
                request.write_to_bytes().unwrap()
            };
            let rpc = TtrpcRequest {
                service: "d2b.resource.v3.ResourceService".to_owned(),
                method: method.to_owned(),
                payload,
                ..TtrpcRequest::default()
            };
            let body = rpc.write_to_bytes().unwrap();
            let header = MessageHeader::new_request(1, body.len() as u32);
            let mut frame = Vec::with_capacity(MESSAGE_HEADER_LENGTH + body.len());
            frame.extend_from_slice(&Vec::from(header));
            frame.extend_from_slice(&body);

            let rewritten =
                attach_scoped_query_frame(&frame, &resource_types, &[], &filters, watch).unwrap();
            let rpc = TtrpcRequest::parse_from_bytes(&rewritten[MESSAGE_HEADER_LENGTH..]).unwrap();
            if watch {
                let request = wire::WatchRequest::parse_from_bytes(&rpc.payload).unwrap();
                assert_eq!(
                    request.resource_types,
                    vec![d2b_contracts_resource::v3::process::PROCESS_RESOURCE_TYPE.to_owned()]
                );
                assert_eq!(request.filters.len(), 1);
                assert_eq!(request.filters[0].field, "owner.resourceUid");
                assert_eq!(
                    request.filters[0].values,
                    vec![owner_uid.as_str().to_owned()]
                );
            } else {
                let request = wire::ListRequest::parse_from_bytes(&rpc.payload).unwrap();
                assert_eq!(
                    request.resource_types,
                    vec![d2b_contracts_resource::v3::process::PROCESS_RESOURCE_TYPE.to_owned()]
                );
                assert_eq!(request.filters.len(), 1);
                assert_eq!(request.filters[0].field, "owner.resourceUid");
                assert_eq!(
                    request.filters[0].values,
                    vec![owner_uid.as_str().to_owned()]
                );
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ObservedTarget {
        resource_type: String,
        resource_name: Option<String>,
        verb: ResourceVerb,
        subresource: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct DispatchObservation {
        method: ApiMethod,
        operation_id: String,
        zone: String,
        targets: Vec<ObservedTarget>,
    }

    impl DispatchObservation {
        fn one(
            method: ApiMethod,
            operation_id: &str,
            zone: &ZoneId,
            resource_type: &ResourceTypeName,
            resource_name: Option<&ResourceName>,
            verb: ResourceVerb,
            subresource: Option<&str>,
        ) -> Self {
            Self {
                method,
                operation_id: operation_id.to_owned(),
                zone: zone.to_canonical_string(),
                targets: vec![ObservedTarget {
                    resource_type: resource_type.to_canonical_string(),
                    resource_name: resource_name.map(ResourceName::to_canonical_string),
                    verb,
                    subresource: subresource.map(str::to_owned),
                }],
            }
        }
    }

    struct RecordingStore {
        calls: Arc<Mutex<Vec<DispatchObservation>>>,
        acceptor: MutationSealAcceptor,
    }

    impl RecordingStore {
        fn new(
            calls: Arc<Mutex<Vec<DispatchObservation>>>,
            acceptor: MutationSealAcceptor,
        ) -> Arc<Self> {
            Arc::new(Self { calls, acceptor })
        }

        fn record(&self, observation: DispatchObservation) {
            self.calls.lock().unwrap().push(observation);
        }
    }

    impl ResourceStoreBackend for RecordingStore {
        async fn get(&self, request: StoreGetRequest) -> Result<StoredResource, StoreError> {
            self.record(DispatchObservation::one(
                ApiMethod::Get,
                &request.operation.operation_id,
                &request.zone,
                request.target.resource_type(),
                Some(request.target.name()),
                ResourceVerb::Get,
                None,
            ));
            Ok(stored_resource(101))
        }

        async fn list(&self, request: StoreListRequest) -> Result<StoreListResult, StoreError> {
            self.record(DispatchObservation {
                method: ApiMethod::List,
                operation_id: request.operation.operation_id,
                zone: request.zone.to_canonical_string(),
                targets: request
                    .resource_types
                    .iter()
                    .map(|resource_type| ObservedTarget {
                        resource_type: resource_type.to_canonical_string(),
                        resource_name: None,
                        verb: ResourceVerb::List,
                        subresource: None,
                    })
                    .collect(),
            });
            Ok(StoreListResult {
                resources: Vec::new(),
                snapshot_revision: ZoneRevision::new(102),
                next_cursor: None,
                truncated: false,
            })
        }

        async fn watch(&self, request: StoreWatchRequest) -> Result<StoreWatchReceipt, StoreError> {
            self.record(DispatchObservation {
                method: ApiMethod::Watch,
                operation_id: request.operation.operation_id,
                zone: request.zone.to_canonical_string(),
                targets: request
                    .resource_types
                    .iter()
                    .map(|resource_type| ObservedTarget {
                        resource_type: resource_type.to_canonical_string(),
                        resource_name: None,
                        verb: ResourceVerb::Watch,
                        subresource: None,
                    })
                    .collect(),
            });
            Ok(StoreWatchReceipt {
                stream_name: "watch-sentinel-103".to_owned(),
                snapshot_revision: ZoneRevision::new(103),
            })
        }

        async fn resolve_ref(
            &self,
            request: StoreResolveRequest,
        ) -> Result<StoreResolvedIdentity, StoreError> {
            self.record(DispatchObservation::one(
                ApiMethod::ResolveRef,
                &request.operation.operation_id,
                &request.zone,
                request.target.resource_type(),
                Some(request.target.name()),
                ResourceVerb::Get,
                None,
            ));
            Ok(StoreResolvedIdentity {
                zone: ZoneId::parse("dev").unwrap(),
                resource_ref: ResourceRef::parse("Host/resolve-sentinel").unwrap(),
                uid: ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap(),
                generation: ResourceGeneration::new(1).unwrap(),
                revision: ZoneRevision::new(111),
            })
        }

        async fn inspect_schema(
            &self,
            request: StoreInspectSchemaRequest,
        ) -> Result<StoredSchema, StoreError> {
            self.record(DispatchObservation::one(
                ApiMethod::InspectSchema,
                &request.operation.operation_id,
                &request.zone,
                &request.resource_type,
                None,
                ResourceVerb::Get,
                Some("schema"),
            ));
            Ok(StoredSchema {
                resource_type: ResourceTypeName::parse("Host").unwrap(),
                canonical_json: b"inspect-schema-sentinel-112".to_vec(),
                payload_digest: format!("sha256:{}", "1".repeat(64)),
            })
        }

        async fn commit_verified(
            &self,
            mutation: d2b_resource_store::SealedMutation,
        ) -> Result<StoreCommitResult, StoreError> {
            let opened = self.acceptor.open(mutation).unwrap();
            let body = opened.into_body();
            let operation_id = body.operation.operation_id;
            let authorization = body.authorization;
            let mutations = body.mutations;
            let (method, revision) = if mutations.len() > 1 {
                (ApiMethod::CommitBatch, 110)
            } else {
                match mutations[0].mutation().kind {
                    ResourceMutationKind::Create => (ApiMethod::Create, 104),
                    ResourceMutationKind::UpdateSpec => (ApiMethod::UpdateSpec, 105),
                    ResourceMutationKind::UpdateStatus => (ApiMethod::UpdateStatus, 106),
                    ResourceMutationKind::UpdateMetadata => (ApiMethod::UpdateMetadata, 107),
                    ResourceMutationKind::UpdateFinalizers => (ApiMethod::UpdateFinalizers, 108),
                    ResourceMutationKind::Delete => (ApiMethod::Delete, 109),
                }
            };
            self.record(DispatchObservation {
                method,
                operation_id,
                zone: authorization.zone.to_canonical_string(),
                targets: authorization
                    .targets
                    .iter()
                    .map(|target| ObservedTarget {
                        resource_type: target.resource_type.to_canonical_string(),
                        resource_name: target
                            .resource_name
                            .as_ref()
                            .map(ResourceName::to_canonical_string),
                        verb: admitted_verb(target.verb),
                        subresource: target.subresource.clone(),
                    })
                    .collect(),
            });
            Ok(StoreCommitResult {
                resources: Vec::new(),
                revision: ZoneRevision::new(revision),
            })
        }
    }

    #[derive(Debug)]
    struct RecordingUpgrade {
        calls: Arc<Mutex<Vec<DispatchObservation>>>,
    }

    impl UpgradeDispatcher for RecordingUpgrade {
        async fn dispatch(
            &self,
            request: AuthorizedUpgrade,
        ) -> Result<UpgradeResult, d2b_contracts_resource::v3::ResourceError> {
            self.calls.lock().unwrap().push(DispatchObservation::one(
                ApiMethod::Upgrade,
                &request.operation.operation_id,
                &request.zone,
                request.target.resource_type(),
                Some(request.target.name()),
                ResourceVerb::UpdateSpec,
                None,
            ));
            Ok(UpgradeResult {
                resource: stored_resource(113),
                plan: Vec::new(),
                revision: ZoneRevision::new(113),
            })
        }
    }

    const fn admitted_verb(verb: AdmittedVerb) -> ResourceVerb {
        match verb {
            AdmittedVerb::Get => ResourceVerb::Get,
            AdmittedVerb::List => ResourceVerb::List,
            AdmittedVerb::Watch => ResourceVerb::Watch,
            AdmittedVerb::Create => ResourceVerb::Create,
            AdmittedVerb::UpdateSpec => ResourceVerb::UpdateSpec,
            AdmittedVerb::UpdateStatus => ResourceVerb::UpdateStatus,
            AdmittedVerb::UpdateMetadata => ResourceVerb::UpdateMetadata,
            AdmittedVerb::UpdateFinalizers => ResourceVerb::UpdateFinalizers,
            AdmittedVerb::Delete => ResourceVerb::Delete,
            AdmittedVerb::UseCredential => ResourceVerb::UseCredential,
            AdmittedVerb::AdminCredential => ResourceVerb::AdminCredential,
        }
    }

    fn subject(locality: Locality, evidence: EvidenceClass) -> Arc<SessionClaims> {
        subject_named(locality, evidence, "alice")
    }

    fn subject_named(
        locality: Locality,
        evidence: EvidenceClass,
        name: &str,
    ) -> Arc<SessionClaims> {
        Arc::new(
            SessionClaims::new(
                ResourceRef::parse(&format!("User/{name}")).unwrap(),
                ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap(),
                ResourceRef::parse("Zone/dev").unwrap(),
                evidence,
                SessionPurpose::parse("resource-api").unwrap(),
                ServiceName::parse("d2b.resource.v3").unwrap(),
                SessionBinding::new(
                    SchemaFingerprint::parse(format!("sha256:{}", "1".repeat(64))).unwrap(),
                    TransportBinding::new(
                        locality,
                        BindingDigest::parse(format!("sha256:{}", "2".repeat(64))).unwrap(),
                    ),
                    ReconnectGeneration::new(1).unwrap(),
                    TranscriptHash::from_bytes([3; 32]),
                ),
            )
            .with_controller_generation(ControllerGeneration::new(8).unwrap()),
        )
    }

    fn state() -> AuthorizationState {
        AuthorizationState {
            snapshot: PolicySnapshot {
                policy_revision: 4,
                api_catalog_revision: 5,
                active_configuration_revision: ConfigurationGeneration::new(6).unwrap(),
                controller_generation: Some(ControllerGeneration::new(8).unwrap()),
            },
            zone_policy_revision: ZoneRevision::new(7),
            bootstrap_phase: BootstrapPhase::Disabled,
            now_tick: 1,
        }
    }

    fn denied_adapter()
    -> Arc<ResourceBusAdapter<UnreachableStore, crate::service::UnavailableUpgradeDispatcher>> {
        let (store, authorizer) = UnreachableStore::paired(ApiCatalog::standard(), None);
        let service = Arc::new(ResourceService::new(store, authorizer).unwrap());
        Arc::new(
            ResourceBusAdapter::bind_component_session(
                service,
                issue_test_subject(subject(Locality::Local, EvidenceClass::UnixPeer), state()),
            )
            .unwrap(),
        )
    }

    /// A recording adapter paired with the observation log it appends to.
    type RecordingAdapter = (
        Arc<ResourceBusAdapter<RecordingStore, RecordingUpgrade>>,
        Arc<Mutex<Vec<DispatchObservation>>>,
    );

    fn recording_adapter() -> RecordingAdapter {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let context = subject(Locality::Local, EvidenceClass::UnixPeer);
        let catalog = ApiCatalog::standard();
        let role = CompiledRole::new(
            ResourceRef::parse("Role/dispatch-test").unwrap(),
            vec![
                PolicyRule::new(
                    &catalog,
                    [ResourceTypeName::parse("Host").unwrap()],
                    [
                        ResourceVerb::Get,
                        ResourceVerb::List,
                        ResourceVerb::Watch,
                        ResourceVerb::Create,
                        ResourceVerb::UpdateSpec,
                        ResourceVerb::UpdateMetadata,
                        ResourceVerb::Delete,
                    ],
                    [],
                    [],
                    [],
                    [ZoneId::parse("dev").unwrap()],
                    [],
                )
                .unwrap(),
                PolicyRule::new(
                    &catalog,
                    [ResourceTypeName::parse("Host").unwrap()],
                    [ResourceVerb::UpdateStatus],
                    [],
                    ["status".to_owned()],
                    [],
                    [ZoneId::parse("dev").unwrap()],
                    [],
                )
                .unwrap(),
                PolicyRule::new(
                    &catalog,
                    [ResourceTypeName::parse("Host").unwrap()],
                    [ResourceVerb::UpdateFinalizers],
                    [],
                    ["finalizers".to_owned()],
                    [],
                    [ZoneId::parse("dev").unwrap()],
                    [],
                )
                .unwrap(),
                PolicyRule::new(
                    &catalog,
                    [ResourceTypeName::parse("Host").unwrap()],
                    [ResourceVerb::Get],
                    [],
                    ["schema".to_owned()],
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
        let policy = PolicySet::new(&catalog, 4, vec![role], vec![binding]).unwrap();
        let authorizer = NativeAuthorizer::new(catalog, Some(policy)).unwrap();
        let acceptor = authorizer
            .take_store_seal(test_store_identity())
            .expect("recording store receives a seal acceptor");
        let store = RecordingStore::new(Arc::clone(&calls), acceptor);
        let upgrade = Arc::new(RecordingUpgrade {
            calls: Arc::clone(&calls),
        });
        let service =
            Arc::new(ResourceService::with_upgrade(store, Arc::new(authorizer), upgrade).unwrap());
        (
            Arc::new(
                ResourceBusAdapter::bind_component_session(
                    service,
                    issue_test_subject(context, state()),
                )
                .unwrap(),
            ),
            calls,
        )
    }

    fn context() -> ttrpc::r#async::TtrpcContext {
        ttrpc::r#async::TtrpcContext {
            mh: Default::default(),
            metadata: HashMap::new(),
            timeout_nano: 0,
        }
    }

    fn identity() -> MessageField<wire::ResourceIdentity> {
        let mut identity = wire::ResourceIdentity::new();
        identity.zone = "dev".to_owned();
        identity.resource_type = "Host".to_owned();
        identity.name = "host-system".to_owned();
        MessageField::some(identity)
    }

    fn request_meta(method: &str) -> MessageField<wire::RequestMeta> {
        let mut meta = wire::RequestMeta::new();
        meta.operation_id = method.to_owned();
        meta.idempotency_key = format!("{method}-idempotency");
        meta.correlation_id = format!("{method}-correlation");
        MessageField::some(meta)
    }

    fn full_projection() -> MessageField<wire::Projection> {
        let mut projection = wire::Projection::new();
        projection.kind = EnumOrUnknown::new(wire::ProjectionKind::PROJECTION_KIND_FULL);
        MessageField::some(projection)
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
        if matches!(
            kind,
            wire::MutationKind::MUTATION_KIND_CREATE
                | wire::MutationKind::MUTATION_KIND_UPDATE_SPEC
                | wire::MutationKind::MUTATION_KIND_UPDATE_STATUS
                | wire::MutationKind::MUTATION_KIND_UPDATE_METADATA
        ) {
            mutation.resource = resource_body(kind == wire::MutationKind::MUTATION_KIND_CREATE);
        }
        if kind == wire::MutationKind::MUTATION_KIND_UPDATE_FINALIZERS {
            mutation
                .add_finalizers
                .push("resources.d2bus.org/dispatch-test".to_owned());
        }
        mutation
    }

    fn resource_body(create: bool) -> MessageField<wire::ResourceEnvelopeBytes> {
        let canonical_json = if create {
            let mut value = CanonicalJsonValue::parse(GOLDEN_HOST).unwrap();
            let CanonicalJsonValue::Object(root) = &mut value else {
                unreachable!()
            };
            let Some(CanonicalJsonValue::Object(metadata)) = root.get_mut("metadata") else {
                unreachable!()
            };
            metadata.remove("uid");
            value.to_canonical_bytes()
        } else {
            GOLDEN_HOST.to_vec()
        };
        let payload_digest = if create {
            canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &canonical_json)
        } else {
            ResourceEnvelope::from_json(&canonical_json)
                .unwrap()
                .digest()
                .unwrap()
        };
        let mut body = wire::ResourceEnvelopeBytes::new();
        body.identity = identity();
        body.canonical_json = canonical_json;
        body.payload_digest = payload_digest;
        MessageField::some(body)
    }

    fn stored_resource(revision: u64) -> StoredResource {
        StoredResource {
            resource_ref: ResourceRef::parse("Host/host-system").unwrap(),
            zone: ZoneId::parse("dev").unwrap(),
            uid: ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap(),
            owner_uid: None,
            owner_generation: None,
            generation: ResourceGeneration::new(1).unwrap(),
            revision: ZoneRevision::new(revision),
            canonical_json: format!("response-sentinel-{revision}").into_bytes(),
            payload_digest: format!("sha256:{revision:064x}"),
        }
    }

    #[test]
    fn authenticated_service_map_contains_the_exact_thirteen_method_surface() {
        assert_eq!(
            RESOURCE_API_REACHABILITY,
            ResourceApiReachability::RegisteredOnAuthenticatedComponentSession
        );
        let services = denied_adapter().ttrpc_services();
        assert_eq!(services.len(), 1);
        let methods = &services["d2b.resource.v3.ResourceService"].methods;
        let actual = methods.keys().cloned().collect::<BTreeSet<_>>();
        let expected = [
            "CommitBatch",
            "Create",
            "Delete",
            "Get",
            "InspectSchema",
            "List",
            "ResolveRef",
            "UpdateFinalizers",
            "UpdateMetadata",
            "UpdateSpec",
            "UpdateStatus",
            "Upgrade",
            "Watch",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn adapter_and_client_debug_redact_session_identity() {
        const MARKER: &str = "sentinel-observability-marker";

        let (store, authorizer) = UnreachableStore::paired(ApiCatalog::standard(), None);
        let service = Arc::new(ResourceService::new(store, authorizer).unwrap());
        let adapter = ResourceBusAdapter::bind_component_session(
            service,
            issue_test_subject(
                subject_named(Locality::Local, EvidenceClass::UnixPeer, MARKER),
                state(),
            ),
        )
        .unwrap();
        let adapter_debug = format!("{adapter:?}");
        let client_debug = format!("{:?}", adapter.client());

        assert!(!adapter_debug.contains(MARKER), "{adapter_debug}");
        assert!(!client_debug.contains(MARKER), "{client_debug}");
    }

    #[tokio::test]
    async fn authenticated_thirteen_method_adapter_pins_dispatch_targets_counts_and_sentinels() {
        let ctx = context();
        let (adapter, calls) = recording_adapter();

        let mut get = wire::GetRequest::new();
        get.meta = request_meta("get");
        get.target = identity();
        get.projection = full_projection();
        let get = d2b_resource_v3_ttrpc::ResourceService::get(&*adapter, &ctx, get)
            .await
            .unwrap();
        assert!(get.error.is_none(), "{get:?}");
        assert_eq!(
            get.resource
                .as_ref()
                .unwrap()
                .identity
                .as_ref()
                .unwrap()
                .revision,
            Some(101)
        );

        let mut list = wire::ListRequest::new();
        list.meta = request_meta("list");
        list.resource_types.push("Host".to_owned());
        list.projection = full_projection();
        let list = d2b_resource_v3_ttrpc::ResourceService::list(&*adapter, &ctx, list)
            .await
            .unwrap();
        assert_eq!(list.snapshot_revision, 102);

        let mut watch = wire::WatchRequest::new();
        watch.meta = request_meta("watch");
        watch.resource_types.push("Host".to_owned());
        watch.projection = full_projection();
        let watch = d2b_resource_v3_ttrpc::ResourceService::watch(&*adapter, &ctx, watch)
            .await
            .unwrap();
        assert_eq!(watch.stream_name, "watch-sentinel-103");
        assert_eq!(watch.snapshot_revision, 103);

        let mut create = wire::CreateRequest::new();
        create.meta = request_meta("create");
        create.mutation = MessageField::some(mutation(wire::MutationKind::MUTATION_KIND_CREATE));
        let create = d2b_resource_v3_ttrpc::ResourceService::create(&*adapter, &ctx, create)
            .await
            .unwrap();
        assert_eq!(create.revision, 104);

        let mut update_spec = wire::UpdateSpecRequest::new();
        update_spec.meta = request_meta("update-spec");
        update_spec.mutation =
            MessageField::some(mutation(wire::MutationKind::MUTATION_KIND_UPDATE_SPEC));
        let update_spec =
            d2b_resource_v3_ttrpc::ResourceService::update_spec(&*adapter, &ctx, update_spec)
                .await
                .unwrap();
        assert_eq!(update_spec.revision, 105);

        let mut update_status = wire::UpdateStatusRequest::new();
        update_status.meta = request_meta("update-status");
        update_status.mutation =
            MessageField::some(mutation(wire::MutationKind::MUTATION_KIND_UPDATE_STATUS));
        let update_status =
            d2b_resource_v3_ttrpc::ResourceService::update_status(&*adapter, &ctx, update_status)
                .await
                .unwrap();
        assert_eq!(update_status.revision, 106);

        let mut update_metadata = wire::UpdateMetadataRequest::new();
        update_metadata.meta = request_meta("update-metadata");
        update_metadata.mutation =
            MessageField::some(mutation(wire::MutationKind::MUTATION_KIND_UPDATE_METADATA));
        let update_metadata = d2b_resource_v3_ttrpc::ResourceService::update_metadata(
            &*adapter,
            &ctx,
            update_metadata,
        )
        .await
        .unwrap();
        assert_eq!(update_metadata.revision, 107);

        let mut update_finalizers = wire::UpdateFinalizersRequest::new();
        update_finalizers.meta = request_meta("update-finalizers");
        update_finalizers.mutation = MessageField::some(mutation(
            wire::MutationKind::MUTATION_KIND_UPDATE_FINALIZERS,
        ));
        let update_finalizers = d2b_resource_v3_ttrpc::ResourceService::update_finalizers(
            &*adapter,
            &ctx,
            update_finalizers,
        )
        .await
        .unwrap();
        assert_eq!(update_finalizers.revision, 108);

        let mut delete = wire::DeleteRequest::new();
        delete.meta = request_meta("delete");
        delete.mutation = MessageField::some(mutation(wire::MutationKind::MUTATION_KIND_DELETE));
        let delete = d2b_resource_v3_ttrpc::ResourceService::delete(&*adapter, &ctx, delete)
            .await
            .unwrap();
        assert_eq!(delete.revision, 109);

        let mut batch = wire::CommitBatchRequest::new();
        batch.meta = request_meta("commit-batch");
        batch.mutations = vec![
            mutation(wire::MutationKind::MUTATION_KIND_DELETE),
            mutation(wire::MutationKind::MUTATION_KIND_DELETE),
        ];
        let batch = d2b_resource_v3_ttrpc::ResourceService::commit_batch(&*adapter, &ctx, batch)
            .await
            .unwrap();
        assert_eq!(batch.revision, 110);

        let mut resolve = wire::ResolveRefRequest::new();
        resolve.meta = request_meta("resolve-ref");
        resolve.target = identity();
        let resolve = d2b_resource_v3_ttrpc::ResourceService::resolve_ref(&*adapter, &ctx, resolve)
            .await
            .unwrap();
        assert_eq!(resolve.resource.as_ref().unwrap().revision, Some(111));

        let mut inspect = wire::InspectSchemaRequest::new();
        inspect.meta = request_meta("inspect-schema");
        inspect.resource_type = "Host".to_owned();
        let inspect =
            d2b_resource_v3_ttrpc::ResourceService::inspect_schema(&*adapter, &ctx, inspect)
                .await
                .unwrap();
        assert_eq!(
            inspect.schema.as_ref().unwrap().canonical_json,
            b"inspect-schema-sentinel-112"
        );

        let mut upgrade = wire::UpgradeRequest::new();
        upgrade.meta = request_meta("upgrade");
        upgrade.target = identity();
        upgrade.action = EnumOrUnknown::new(wire::UpgradeAction::UPGRADE_ACTION_ASSESS);
        let mut precondition = wire::Precondition::new();
        precondition.kind =
            EnumOrUnknown::new(wire::PreconditionKind::PRECONDITION_KIND_EXACT_REVISION);
        precondition.expected_revision = Some(1);
        upgrade.precondition = MessageField::some(precondition);
        let upgrade = d2b_resource_v3_ttrpc::ResourceService::upgrade(&*adapter, &ctx, upgrade)
            .await
            .unwrap();
        assert_eq!(upgrade.revision, 113);

        let host = || ResourceTypeName::parse("Host").unwrap();
        let name = || ResourceName::parse("host-system").unwrap();
        let expected = vec![
            DispatchObservation::one(
                ApiMethod::Get,
                "get",
                &ZoneId::parse("dev").unwrap(),
                &host(),
                Some(&name()),
                ResourceVerb::Get,
                None,
            ),
            DispatchObservation::one(
                ApiMethod::List,
                "list",
                &ZoneId::parse("dev").unwrap(),
                &host(),
                None,
                ResourceVerb::List,
                None,
            ),
            DispatchObservation::one(
                ApiMethod::Watch,
                "watch",
                &ZoneId::parse("dev").unwrap(),
                &host(),
                None,
                ResourceVerb::Watch,
                None,
            ),
            DispatchObservation::one(
                ApiMethod::Create,
                "create",
                &ZoneId::parse("dev").unwrap(),
                &host(),
                Some(&name()),
                ResourceVerb::Create,
                None,
            ),
            DispatchObservation::one(
                ApiMethod::UpdateSpec,
                "update-spec",
                &ZoneId::parse("dev").unwrap(),
                &host(),
                Some(&name()),
                ResourceVerb::UpdateSpec,
                None,
            ),
            DispatchObservation::one(
                ApiMethod::UpdateStatus,
                "update-status",
                &ZoneId::parse("dev").unwrap(),
                &host(),
                Some(&name()),
                ResourceVerb::UpdateStatus,
                Some("status"),
            ),
            DispatchObservation::one(
                ApiMethod::UpdateMetadata,
                "update-metadata",
                &ZoneId::parse("dev").unwrap(),
                &host(),
                Some(&name()),
                ResourceVerb::UpdateMetadata,
                None,
            ),
            DispatchObservation::one(
                ApiMethod::UpdateFinalizers,
                "update-finalizers",
                &ZoneId::parse("dev").unwrap(),
                &host(),
                Some(&name()),
                ResourceVerb::UpdateFinalizers,
                Some("finalizers"),
            ),
            DispatchObservation::one(
                ApiMethod::Delete,
                "delete",
                &ZoneId::parse("dev").unwrap(),
                &host(),
                Some(&name()),
                ResourceVerb::Delete,
                None,
            ),
            DispatchObservation {
                method: ApiMethod::CommitBatch,
                operation_id: "commit-batch".to_owned(),
                zone: "dev".to_owned(),
                targets: vec![
                    ObservedTarget {
                        resource_type: "Host".to_owned(),
                        resource_name: Some("host-system".to_owned()),
                        verb: ResourceVerb::Delete,
                        subresource: None,
                    },
                    ObservedTarget {
                        resource_type: "Host".to_owned(),
                        resource_name: Some("host-system".to_owned()),
                        verb: ResourceVerb::Delete,
                        subresource: None,
                    },
                ],
            },
            DispatchObservation::one(
                ApiMethod::ResolveRef,
                "resolve-ref",
                &ZoneId::parse("dev").unwrap(),
                &host(),
                Some(&name()),
                ResourceVerb::Get,
                None,
            ),
            DispatchObservation::one(
                ApiMethod::InspectSchema,
                "inspect-schema",
                &ZoneId::parse("dev").unwrap(),
                &host(),
                None,
                ResourceVerb::Get,
                Some("schema"),
            ),
            DispatchObservation::one(
                ApiMethod::Upgrade,
                "upgrade",
                &ZoneId::parse("dev").unwrap(),
                &host(),
                Some(&name()),
                ResourceVerb::UpdateSpec,
                None,
            ),
        ];
        assert_eq!(*calls.lock().unwrap(), expected);
    }

    #[test]
    fn adapter_rejects_locality_evidence_mismatches() {
        let (store, authorizer) = UnreachableStore::paired(ApiCatalog::standard(), None);
        let service = Arc::new(ResourceService::new(store, authorizer).unwrap());
        for (locality, evidence) in [
            (Locality::AdjacentZone, EvidenceClass::BootstrapIkpsk2),
            (Locality::Remote, EvidenceClass::EnrolledKk),
        ] {
            assert!(
                ResourceBusAdapter::bind_component_session(
                    Arc::clone(&service),
                    issue_test_subject(subject(locality, evidence), state()),
                )
                .is_err()
            );
        }
    }
}
