//! Daemon-owned composition for authenticated interaction Providers.
//!
//! This is the only layer that may join a sealed ComponentSession admission
//! to process effects.  Provider crates receive authenticated sessions and
//! opaque evidence; they never construct a session, resolve a process, or
//! retain a persistent service unit.

use std::{
    collections::{BTreeMap, VecDeque},
    future::Future,
    os::fd::AsFd,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::PathBuf,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::process_resource_runtime::PROCESS_RESTART_ANNOTATION;
use crate::resource_runtime::{
    CommittedClipboardProviderConfiguration, CommittedInteractionIdentity,
    CommittedInteractionProviderConfiguration, CommittedNotificationProviderConfiguration,
};
use d2b_bus::{
    BusAuthorizer, BusConfig, BusError, BusIngress, ComponentRequestReceiver,
    ComponentSessionAdmission, OperationId, OperationSpec, RouteGenerations, RouteKey, RouteMember,
    RouteTarget, ZoneBus, ZoneRegistrar,
};
use d2b_contracts_resource::resource_proto as wire;
use d2b_contracts_resource::v3::identity::{EvidenceClass, ServiceName};
use d2b_contracts_resource::v3::{
    CanonicalJsonValue, RESOURCE_ENVELOPE_DOMAIN_TAG, ResourceEnvelope, ResourcePhase, ResourceRef,
    ResourceUid, ZoneId, ZoneRevision, canonical_digest,
    endpoint::{
        EndpointClass, EndpointConsumerPolicy, EndpointLifecyclePolicy, EndpointLocality,
        EndpointOperation, EndpointSpec, EndpointTransport, EndpointVisibility,
    },
    execution_policy::{BoundedText, BoundedToken},
    process::{ExecutionSpec, ProcessClass, ProcessSpec},
};
use d2b_contracts_zone_session::v3::component_session::{
    AttachmentKind, AttachmentPolicy, AttachmentPolicyKind, AttachmentPurpose, EndpointPolicy,
    EndpointPurpose, EndpointRole, IdentityEvidenceRequirement, LimitProfile,
    Locality as TransportLocality, MAX_LOGICAL_MESSAGE_BYTES, NoiseProfile, PurposeClass,
    ServicePackage, TransportBinding, TransportClass,
};
use d2b_process::ProcessLaunchEffectPort;
#[cfg(test)]
use d2b_process::{
    CompiledDigests, IdentityBinding, LaunchTicket as ProcessLaunchTicket, OperationBinding,
    StopClass,
};
#[cfg(test)]
use d2b_process_conformance::ReadinessExpectation;
use d2b_process_conformance::{
    AdoptionCandidate, LaunchedProcess, PidfdEvidence, ProcessConformanceError,
    ProcessIdentityDigest,
};
use d2b_provider_clipboard_wayland::{
    AttachmentClass, ClipboardProcessEffectPort, ClipboardServiceError,
};
use d2b_provider_display_wayland::{
    AuthenticatedDisplaySession, CleanupState, DependencyState, DisplayController,
    DisplayDependencyProof, DisplayLaunchBinding, DisplayProcessEffectPort, DisplayProcessRole,
    DisplayRuntime, DisplayRuntimeError, FilterInput, LaunchGrants, VolumeState,
    WaylandPolicySnapshot, WaylandSessionResourceStatus, WaylandSessionSpec, WorkerEffectError,
    WorkerLaunchReceipt, WorkerRestartEvidence, WorkerState,
};
#[cfg(test)]
use d2b_provider_notification_desktop::Category;
use d2b_provider_notification_desktop::{
    DesktopNotificationPort, NotificationHostSinkIdentity, NotificationLifecycleBackend,
    NotificationLifecycleObservation, NotificationLifecyclePlan, NotificationLifecycleSupervisor,
    NotificationProcessEffectPort, NotificationRequest, NotificationSourceIdentity,
    SourceProcessEffectPort, SourceProcessEffectReceipt, SourceReconcileResult,
};
use d2b_core_controller::OwnedChildIntent;
use d2b_resource_api::authz::{
    ApiCatalog, BindingScope, BootstrapPhase, BoundSubject, CompiledRole, CompiledRoleBinding,
    NativeAuthorizer, PolicyRule, PolicySet, SessionVerb,
};
use d2b_resource_api::{RedbBackend, ResourceApiClient, service::UnavailableUpgradeDispatcher};
use d2b_resource_store::{PolicySnapshot, StoredResource};
use d2b_session::{
    AuthenticatedSessionRouteBinding, ComponentSessionDriver, OwnedAttachment, OwnedTransport,
    SessionAcceptor, SessionEngine, TransportEvidence, operation_catalog_entry, ttrpc_stream_id,
};
use d2b_session_unix::{
    CreditPool, CreditScopeSet, PeerIdentityPolicy, SeqpacketSocket, UnixSeqpacketTransport,
    UnixSessionError, VerifiedPacket, VerifiedUnixPeer,
};
use notify_rust::{Notification as DesktopNotification, Urgency};
use protobuf::Message;
use rustix::net::{SocketFlags, accept_with};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use socket2::{Domain, SockAddr, Socket, Type};
use tokio::sync::Mutex as AsyncMutex;
use ttrpc::proto::{
    Code as TtrpcCode, MessageHeader, Request as TtrpcRequest, Response as TtrpcResponse,
    Status as TtrpcStatus,
};

/// Errors at the daemon's authenticated Provider admission seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InteractionAdmissionError {
    /// The session handshake or authentication failed.
    SessionAdmission,
    /// Zone registration rejected the authenticated candidate.
    Registration,
    /// The authenticated service could not install its daemon-owned runtime.
    ServiceUnavailable,
}

/// The fixed ComponentSession service identities accepted by the daemon.
///
/// Process attachment uses the generic Provider package on the wire, while
/// persistent shell attachment uses its provider-defined supervisor identity.
/// The listener identity is retained separately from the package so these
/// sessions cannot be confused with ordinary interaction Providers.
/// Generic Provider package used by Process/EphemeralProcess attachment.
pub(crate) const PROCESS_ATTACH_SERVICE: &str = ServicePackage::ProviderV3.as_str();
/// Per-session shell supervisor service used by ShellSession attachment.
pub(crate) const SHELL_SESSION_SERVICE: &str = d2b_provider_shell_terminal::SUPERVISOR_SERVICE;

const COMPONENT_SESSION_SERVICES: &[(&str, ServicePackage)] = &[
    (
        d2b_provider_display_wayland::SERVICE_PACKAGE,
        ServicePackage::DisplayV3,
    ),
    (
        d2b_provider_clipboard_wayland::MANAGEMENT_SERVICE,
        ServicePackage::ClipboardV3,
    ),
    (
        d2b_provider_clipboard_wayland::BRIDGE_SERVICE,
        ServicePackage::ClipboardBridgeV3,
    ),
    (
        d2b_provider_clipboard_wayland::PICKER_SERVICE,
        ServicePackage::ClipboardPickerCoordV3,
    ),
    (
        d2b_provider_notification_desktop::SERVICE_PACKAGE,
        ServicePackage::NotificationV3,
    ),
    (PROCESS_ATTACH_SERVICE, ServicePackage::ProviderV3),
    (SHELL_SESSION_SERVICE, ServicePackage::ProviderV3),
    (
        d2b_provider_config_nixos::SERVICE_PACKAGE,
        ServicePackage::ConfigNixosV3,
    ),
];

/// Return the exact ComponentSession policy for one daemon-owned service
/// listener. Each service has a distinct Unix socket so the handshake offer
/// cannot select a different Provider after the listener policy is chosen.
pub fn interaction_endpoint_policy(service: &str, generation: u64) -> Option<EndpointPolicy> {
    let (_, package) = COMPONENT_SESSION_SERVICES
        .iter()
        .find(|(candidate, _)| *candidate == service)?;
    let attachment_policy = AttachmentPolicy {
        kind: AttachmentPolicyKind::PacketAtomic,
        max_per_packet: 2,
        max_per_request: 2,
        max_per_operation: 2,
        max_per_session: 8,
        credentials_allowed: false,
    };
    Some(EndpointPolicy {
        purpose: EndpointPurpose::ProviderControl,
        purpose_class: PurposeClass::Local,
        initiator_role: EndpointRole::Provider,
        responder_role: EndpointRole::ZoneController,
        service: *package,
        schema_fingerprint: [0x11; 32],
        noise_profile: NoiseProfile::Nn25519ChaChaPolySha256,
        limits: LimitProfile::local_default(),
        transport_binding: TransportBinding {
            transport: TransportClass::UnixSeqpacket,
            locality: TransportLocality::HostLocal,
            channel_binding: [0x22; 32],
            identity_evidence: IdentityEvidenceRequirement::DirectionalUnix,
        },
        reconnect_generation: generation,
        attachment_policy,
    })
}

fn binding_digest(policy: &EndpointPolicy) -> d2b_contracts_resource::v3::identity::BindingDigest {
    d2b_contracts_resource::v3::identity::BindingDigest::parse(format!(
        "sha256:{}",
        policy
            .transport_binding
            .channel_binding
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ))
    .expect("fixed interaction channel binding is a valid digest")
}

/// A registered interaction session after the daemon has consumed its sealed
/// registration capability.
///
/// The live authority remains owned by the Zone bus endpoint.  Provider
/// runtimes receive only this authenticated route projection for dispatch and
/// evidence checks; they never mint or retain a second session authority.
pub struct RegisteredInteractionSession {
    ingress: BusIngress,
    route: AuthenticatedSessionRouteBinding,
    service_identity: String,
}

impl RegisteredInteractionSession {
    /// Borrow the registered bus ingress, whose drop closes the route.
    pub const fn ingress(&self) -> &BusIngress {
        &self.ingress
    }

    /// Borrow the authenticated route projection for Provider dispatch.
    pub const fn route(&self) -> &AuthenticatedSessionRouteBinding {
        &self.route
    }

    /// Return the exact service package admitted for this session.
    pub fn service(&self) -> &d2b_contracts_resource::v3::identity::ServiceName {
        self.route.service()
    }

    /// Return the fixed listener service identity admitted for this session.
    pub fn service_identity(&self) -> &str {
        &self.service_identity
    }

    /// Return the stable daemon-local key for this authenticated session.
    pub fn session_key(&self) -> String {
        interaction_session_key(&self.service_identity, &self.route)
    }

    /// Clone the daemon-owned request receiver demultiplexed by the bus.
    pub fn request_receiver(&self) -> ComponentRequestReceiver {
        self.ingress.component_request_receiver()
    }

    /// Clone the authenticated ComponentSession driver for daemon-owned
    /// target-local named-stream composition.
    pub fn component_session_driver(&self) -> Option<d2b_session::SessionDriverHandle> {
        self.ingress.component_session_driver()
    }
}

fn interaction_session_key(
    service_identity: &str,
    route: &AuthenticatedSessionRouteBinding,
) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        service_identity,
        route.zone().as_str(),
        route.service().as_str(),
        route.subject_uid().as_str(),
        route.reconnect_generation().get()
    )
}

impl core::fmt::Display for InteractionAdmissionError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::SessionAdmission => "interaction-session-admission-failed",
            Self::Registration => "interaction-session-registration-failed",
            Self::ServiceUnavailable => "interaction-service-unavailable",
        })
    }
}

impl std::error::Error for InteractionAdmissionError {}

impl From<BusError> for InteractionAdmissionError {
    fn from(_: BusError) -> Self {
        Self::Registration
    }
}

/// Authenticate one transport and register it in the Zone bus.
///
/// The registrar consumes the single-use admission capability.  No Provider
/// code can call this function with a fabricated subject or a caller-owned
/// session token.
pub async fn admit_and_register<T>(
    registrar: &mut ZoneRegistrar,
    acceptor: SessionAcceptor<ComponentSessionAdmission>,
    engine: SessionEngine<T>,
    evidence: TransportEvidence,
    now_tick: u64,
) -> Result<BusIngress, InteractionAdmissionError>
where
    T: OwnedTransport + 'static,
{
    Ok(
        admit_and_register_with_route(registrar, acceptor, engine, evidence, now_tick)
            .await?
            .ingress,
    )
}

/// Authenticate, register, and return the daemon-owned route projection for
/// Provider runtime dispatch.
pub async fn admit_and_register_with_route<T>(
    registrar: &mut ZoneRegistrar,
    acceptor: SessionAcceptor<ComponentSessionAdmission>,
    engine: SessionEngine<T>,
    evidence: TransportEvidence,
    now_tick: u64,
) -> Result<RegisteredInteractionSession, InteractionAdmissionError>
where
    T: OwnedTransport + 'static,
{
    admit_and_register_with_route_identity(registrar, acceptor, engine, evidence, now_tick, None)
        .await
}

/// Authenticate, register, and retain the fixed service identity of a
/// daemon-owned listener. This is distinct from the wire package because a
/// provider may expose more than one service over the generic Provider
/// package.
pub(crate) async fn admit_and_register_with_service<T>(
    registrar: &mut ZoneRegistrar,
    acceptor: SessionAcceptor<ComponentSessionAdmission>,
    engine: SessionEngine<T>,
    evidence: TransportEvidence,
    now_tick: u64,
    service_identity: &str,
) -> Result<RegisteredInteractionSession, InteractionAdmissionError>
where
    T: OwnedTransport + 'static,
{
    admit_and_register_with_route_identity(
        registrar,
        acceptor,
        engine,
        evidence,
        now_tick,
        Some(service_identity),
    )
    .await
}

async fn admit_and_register_with_route_identity<T>(
    registrar: &mut ZoneRegistrar,
    acceptor: SessionAcceptor<ComponentSessionAdmission>,
    engine: SessionEngine<T>,
    evidence: TransportEvidence,
    now_tick: u64,
    service_identity: Option<&str>,
) -> Result<RegisteredInteractionSession, InteractionAdmissionError>
where
    T: OwnedTransport + 'static,
{
    let session = acceptor
        .admit(engine, evidence, now_tick)
        .await
        .map_err(|_| InteractionAdmissionError::SessionAdmission)?;
    let route = session.route_binding();
    let service_identity = match service_identity {
        Some(service_identity)
            if COMPONENT_SESSION_SERVICES
                .iter()
                .any(|(candidate, package)| {
                    *candidate == service_identity && package.as_str() == route.service().as_str()
                }) =>
        {
            service_identity.to_owned()
        }
        Some(_) => return Err(InteractionAdmissionError::Registration),
        None => route.service().as_str().to_owned(),
    };
    let ingress = registrar
        .register_component_session(session)
        .await
        .map_err(InteractionAdmissionError::from)?;
    Ok(RegisteredInteractionSession {
        ingress,
        route,
        service_identity,
    })
}

/// The daemon-owned composition for one authenticated Provider or
/// Process/Shell session.
///
/// This object is intentionally the only place where a registered bus ingress,
/// Provider runtime state, and supervisor effect owner meet.  The Provider
/// crates never receive the registrar or supervisor directly.  Dropping the
/// composition without calling [`Self::finalize`] is safe but leaves the
/// ingress open until its normal owner is dropped; production shutdown calls
/// `finalize` before releasing the ingress.
pub struct InteractionComposition<S>
where
    S: ProcessLaunchEffectPort + Clone + Send + Sync + 'static,
{
    registrar: ZoneRegistrar,
    supervisor: S,
    sessions: BTreeMap<String, RegisteredInteractionSession>,
    display: Option<DisplayRuntime<DisplaySupervisorEffects<S>>>,
    clipboard: Option<d2b_provider_clipboard_wayland::ClipboardRuntime<InteractionDrainEffects>>,
    notification:
        Option<d2b_provider_notification_desktop::NotificationRuntime<InteractionDrainEffects>>,
    pending_picker_receipts: BTreeMap<String, d2b_provider_clipboard_wayland::PickerReceipt>,
    pending_guest_selection_events:
        BTreeMap<String, d2b_provider_clipboard_wayland::GuestSelectionEvent>,
    notification_port: Arc<Mutex<Box<dyn DesktopNotificationPort + Send>>>,
    display_resource_client:
        Option<Arc<ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>>>,
    display_resource_evidence: Option<CoreDisplayResourceEvidence>,
    interaction_identity: Option<CommittedInteractionIdentity>,
    clipboard_configuration: Option<CommittedClipboardProviderConfiguration>,
    notification_configuration: Option<CommittedNotificationProviderConfiguration>,
}

/// Daemon-owned collection of independently Zone-bound compositions.
pub struct InteractionRuntimeSet<S>
where
    S: ProcessLaunchEffectPort + Clone + Send + Sync + 'static,
{
    runtimes: BTreeMap<String, InteractionComposition<S>>,
}

impl<S> core::fmt::Debug for InteractionRuntimeSet<S>
where
    S: ProcessLaunchEffectPort + Clone + Send + Sync + 'static,
{
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("InteractionRuntimeSet")
            .field("zone_count", &self.runtimes.len())
            .finish()
    }
}

impl<S> InteractionRuntimeSet<S>
where
    S: ProcessLaunchEffectPort + Clone + Send + Sync + 'static,
{
    /// Construct an empty Zone runtime set.
    pub fn new() -> Self {
        Self {
            runtimes: BTreeMap::new(),
        }
    }

    /// Insert one fully Zone-bound runtime.
    pub fn insert(&mut self, zone: ZoneId, runtime: InteractionComposition<S>) {
        self.runtimes.insert(zone.as_str().to_owned(), runtime);
    }

    /// Return whether any Zone runtime is installed.
    pub fn is_empty(&self) -> bool {
        self.runtimes.is_empty()
    }

    /// Borrow the Zone names that already have a composed runtime.
    pub fn zone_names(&self) -> impl Iterator<Item = &str> {
        self.runtimes.keys().map(String::as_str)
    }

    fn runtime_for(&self, zone: &ZoneId) -> Option<&InteractionComposition<S>> {
        self.runtimes.get(zone.as_str())
    }

    fn runtime_for_mut(&mut self, zone: &ZoneId) -> Option<&mut InteractionComposition<S>> {
        self.runtimes.get_mut(zone.as_str())
    }

    /// Reconcile the committed WaylandSession for one exact VM before its
    /// process DAG waits on the Host proxy socket.
    pub(crate) fn reconcile_committed_display_for_vm_start(
        &mut self,
        zone: &ZoneId,
        vm: &str,
        session_ref: &ResourceRef,
        session_uid: &ResourceUid,
        spec: &WaylandSessionSpec,
    ) -> Result<d2b_provider_display_wayland::ReconcileResult, DisplayRuntimeError> {
        self.runtime_for_mut(zone)
            .ok_or(DisplayRuntimeError::SessionUnauthenticated)?
            .reconcile_committed_display_for_vm_start(vm, session_ref, session_uid, spec)
    }

    /// Find the sole authenticated ComponentSession owned by one exact
    /// execution target and service across the daemon's Zone compositions.
    /// Absent, stale, or ambiguous sources fail closed.
    pub fn component_session_driver_for_target(
        &self,
        service: &str,
        target: &ResourceRef,
    ) -> Option<d2b_session::SessionDriverHandle> {
        let mut drivers = self
            .runtimes
            .values()
            .filter_map(|runtime| runtime.component_session_driver_for_target(service, target));
        let driver = drivers.next()?;
        drivers.next().is_none().then_some(driver)
    }

    async fn remove_session(&mut self, zone: &ZoneId, session_key: &str) -> Result<(), String> {
        self.runtime_for_mut(zone)
            .ok_or_else(|| "interaction runtime unavailable".to_owned())?
            .remove_session(session_key)
            .await
    }

    /// Finalize every Zone composition, retaining failed state for retry.
    pub async fn finalize_async(
        &mut self,
        grace: d2b_provider_display_wayland::GraceState,
    ) -> Result<(), InteractionFinalizeError> {
        let zones = self.runtimes.keys().cloned().collect::<Vec<_>>();
        let mut failure = None;
        for zone in zones {
            if let Some(runtime) = self.runtimes.get_mut(&zone)
                && let Err(error) = runtime.finalize_async(grace).await
            {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

/// Resolve one exact service-owned ComponentSession without converting a
/// contended runtime lock into an absent source.
pub(crate) fn blocking_component_session_driver_for_service<S>(
    runtime: &Arc<AsyncMutex<Option<InteractionRuntimeSet<S>>>>,
    service: &str,
    target: &ResourceRef,
) -> Option<d2b_session::SessionDriverHandle>
where
    S: ProcessLaunchEffectPort + Clone + Send + Sync + 'static,
{
    let runtime = runtime.blocking_lock();
    runtime
        .as_ref()
        .and_then(|runtime| runtime.component_session_driver_for_target(service, target))
}

impl<S> Default for InteractionRuntimeSet<S>
where
    S: ProcessLaunchEffectPort + Clone + Send + Sync + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InteractionDispatchError {
    SessionUnavailable,
    MalformedRequest,
    ServiceMismatch,
    UnknownOperation,
    InvalidPayload,
    RuntimeFailure,
    ResponseFailed,
}

impl InteractionDispatchError {
    const fn code(self) -> TtrpcCode {
        match self {
            Self::SessionUnavailable => TtrpcCode::UNAUTHENTICATED,
            Self::MalformedRequest | Self::ServiceMismatch | Self::InvalidPayload => {
                TtrpcCode::INVALID_ARGUMENT
            }
            Self::UnknownOperation => TtrpcCode::UNIMPLEMENTED,
            Self::RuntimeFailure => TtrpcCode::FAILED_PRECONDITION,
            Self::ResponseFailed => TtrpcCode::UNAVAILABLE,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ClipboardCaptureRequest {
    mime: String,
    #[serde(default)]
    bytes: Option<Vec<u8>>,
    #[serde(default)]
    source_entry_digest: Option<String>,
    #[serde(default)]
    guest_ref: Option<ResourceRef>,
    #[serde(default)]
    zone: Option<ZoneId>,
}

#[derive(Debug, Deserialize)]
struct PickerCompletionRequest {
    entry_digest: String,
    mime_types: Vec<String>,
    selected_digest: Option<String>,
    #[serde(default)]
    guest_ref: Option<ResourceRef>,
    #[serde(default)]
    zone: Option<ZoneId>,
}

#[derive(Debug, Deserialize)]
struct PickerMaterializeRequest {
    operation_id: String,
    entry_digest: String,
    #[serde(default)]
    guest_ref: Option<ResourceRef>,
    #[serde(default)]
    zone: Option<ZoneId>,
}

#[derive(Debug, Deserialize)]
struct NotificationDeliverRequest {
    request: NotificationRequest,
    #[serde(default)]
    guest_ref: Option<ResourceRef>,
    #[serde(default)]
    zone: Option<ZoneId>,
}

fn daemon_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn daemon_monotonic_ms() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START
        .get_or_init(Instant::now)
        .elapsed()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

#[derive(Debug, Deserialize)]
struct DisplayReconcileRequest {
    spec: WaylandSessionSpec,
}

/// Committed Core/resource-plane evidence used to compile display policy.
///
/// Requests carry only the desired session shape.  Policy identity,
/// generation, and dependency readiness come from this daemon-owned snapshot,
/// which is replaced atomically when the resource plane commits a new revision.
#[derive(Clone)]
pub struct CoreDisplayResourceEvidence {
    policy_ref: ResourceRef,
    policy_generation: u64,
    defaults: FilterInput,
    zone_policy: FilterInput,
    dependencies: DependencyState,
    committed_policy: PolicySnapshot,
    observer_user_ref: ResourceRef,
    resource_revision: ZoneRevision,
    resource_ready: bool,
}

impl CoreDisplayResourceEvidence {
    /// Bind a display policy to a committed resource snapshot.
    #[allow(clippy::too_many_arguments)]
    pub fn from_committed_policy(
        policy_ref: ResourceRef,
        committed_policy: PolicySnapshot,
        policy_generation: u64,
        defaults: FilterInput,
        zone_policy: FilterInput,
        dependencies: DependencyState,
        observer_user_ref: ResourceRef,
        resource_revision: ZoneRevision,
        resource_ready: bool,
    ) -> Result<Self, &'static str> {
        if policy_ref.resource_type().as_str() != "display-wayland.d2bus.org.WaylandPolicy"
            || policy_generation == 0
            || committed_policy.policy_revision == 0
            || committed_policy.active_configuration_revision.get() == 0
            || committed_policy
                .controller_generation
                .is_some_and(|generation| generation.get() == 0)
            || observer_user_ref.resource_type().as_str() != "User"
            || resource_revision.get() == 0
            || !resource_ready
        {
            return Err("display-resource-evidence-invalid");
        }
        Ok(Self {
            policy_ref,
            policy_generation,
            defaults,
            zone_policy,
            dependencies,
            committed_policy,
            observer_user_ref,
            resource_revision,
            resource_ready,
        })
    }
}

fn interaction_route_for_member(
    binding: &AuthenticatedSessionRouteBinding,
    member: &str,
) -> Result<RouteKey, InteractionDispatchError> {
    let service = ServiceName::parse(binding.service().as_str())
        .map_err(|_| InteractionDispatchError::ServiceMismatch)?;
    let member = RouteMember::method(member.to_owned())
        .map_err(|_| InteractionDispatchError::UnknownOperation)?;
    let target_ref = binding
        .provider_ref()
        .unwrap_or_else(|| binding.subject_ref())
        .clone();
    let target = if target_ref.resource_type().as_str() == "Provider" {
        RouteTarget::provider(target_ref)
    } else {
        RouteTarget::resource(target_ref)
    }
    .map_err(|_| InteractionDispatchError::ServiceMismatch)?;
    Ok(RouteKey::new(
        binding.zone().clone(),
        service,
        member,
        target,
        binding.schema().clone(),
        RouteGenerations::new(
            binding.provider_generation(),
            binding.controller_generation(),
            binding.reconnect_generation(),
        ),
    ))
}

fn encode_interaction_response(
    stream_id: u32,
    code: TtrpcCode,
    payload: Vec<u8>,
) -> Result<Vec<u8>, InteractionDispatchError> {
    let mut status = TtrpcStatus::new();
    status.set_code(code);
    status.set_message(
        match code {
            TtrpcCode::OK => "",
            TtrpcCode::UNIMPLEMENTED => "interaction-operation-unsupported",
            TtrpcCode::UNAUTHENTICATED => "interaction-session-unavailable",
            TtrpcCode::INVALID_ARGUMENT => "interaction-request-invalid",
            TtrpcCode::FAILED_PRECONDITION => "interaction-runtime-rejected",
            TtrpcCode::UNAVAILABLE => "interaction-response-unavailable",
            _ => "interaction-request-failed",
        }
        .to_owned(),
    );
    let response = TtrpcResponse {
        status: protobuf::MessageField::some(status),
        payload,
        ..TtrpcResponse::default()
    };
    let bytes = response
        .write_to_bytes()
        .map_err(|_| InteractionDispatchError::ResponseFailed)?;
    if bytes.len() > MAX_LOGICAL_MESSAGE_BYTES as usize {
        return Err(InteractionDispatchError::ResponseFailed);
    }
    let length =
        u32::try_from(bytes.len()).map_err(|_| InteractionDispatchError::ResponseFailed)?;
    let mut frame = Vec::from(MessageHeader::new_response(stream_id, length));
    frame.extend_from_slice(&bytes);
    Ok(frame)
}

impl<S> core::fmt::Debug for InteractionComposition<S>
where
    S: ProcessLaunchEffectPort + Clone + Send + Sync + 'static,
{
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("InteractionComposition")
            .field("session_count", &self.sessions.len())
            .field("display_ready", &self.display.is_some())
            .field("clipboard_ready", &self.clipboard.is_some())
            .field("notification_ready", &self.notification.is_some())
            .finish()
    }
}

impl<S> InteractionComposition<S>
where
    S: ProcessLaunchEffectPort + Clone + Send + Sync + 'static,
{
    /// Join one daemon-owned registrar to its supervisor effect owner.
    pub fn new(registrar: ZoneRegistrar, supervisor: S) -> Self {
        Self::new_with_notification_port(
            registrar,
            supervisor,
            Box::new(InteractionNotificationPort::default()),
        )
    }

    /// Join one daemon-owned registrar to its supervisor and presentation
    /// effect owner.
    pub fn new_with_notification_port(
        registrar: ZoneRegistrar,
        supervisor: S,
        notification_port: Box<dyn DesktopNotificationPort + Send>,
    ) -> Self {
        Self {
            registrar,
            supervisor,
            sessions: BTreeMap::new(),
            display: None,
            clipboard: None,
            notification: None,
            pending_picker_receipts: BTreeMap::new(),
            pending_guest_selection_events: BTreeMap::new(),
            notification_port: Arc::new(Mutex::new(notification_port)),
            display_resource_client: None,
            display_resource_evidence: None,
            interaction_identity: None,
            clipboard_configuration: None,
            notification_configuration: None,
        }
    }
}

impl<S> InteractionComposition<S>
where
    S: ProcessLaunchEffectPort + Clone + Send + Sync + 'static,
{
    /// Borrow the registrar used for authenticated admission.
    pub const fn registrar(&self) -> &ZoneRegistrar {
        &self.registrar
    }

    /// Admit and register one ComponentSession, retaining only its route
    /// projection after the bus consumes the sealed authority.
    pub async fn admit_and_register<T>(
        &mut self,
        acceptor: SessionAcceptor<ComponentSessionAdmission>,
        engine: SessionEngine<T>,
        evidence: TransportEvidence,
        now_tick: u64,
    ) -> Result<&RegisteredInteractionSession, InteractionAdmissionError>
    where
        T: OwnedTransport + 'static,
    {
        self.admit_and_register_inner(acceptor, engine, evidence, now_tick, None)
            .await
    }

    /// Admit a ComponentSession while retaining the fixed service identity of
    /// the listener that accepted it.
    pub async fn admit_and_register_for_service<T>(
        &mut self,
        acceptor: SessionAcceptor<ComponentSessionAdmission>,
        engine: SessionEngine<T>,
        evidence: TransportEvidence,
        now_tick: u64,
        service_identity: &str,
    ) -> Result<&RegisteredInteractionSession, InteractionAdmissionError>
    where
        T: OwnedTransport + 'static,
    {
        self.admit_and_register_inner(acceptor, engine, evidence, now_tick, Some(service_identity))
            .await
    }

    async fn admit_and_register_inner<T>(
        &mut self,
        acceptor: SessionAcceptor<ComponentSessionAdmission>,
        engine: SessionEngine<T>,
        evidence: TransportEvidence,
        now_tick: u64,
        service_identity: Option<&str>,
    ) -> Result<&RegisteredInteractionSession, InteractionAdmissionError>
    where
        T: OwnedTransport + 'static,
    {
        let session = match service_identity {
            Some(service_identity) => {
                admit_and_register_with_service(
                    &mut self.registrar,
                    acceptor,
                    engine,
                    evidence,
                    now_tick,
                    service_identity,
                )
                .await?
            }
            None => {
                admit_and_register_with_route(
                    &mut self.registrar,
                    acceptor,
                    engine,
                    evidence,
                    now_tick,
                )
                .await?
            }
        };
        let service = session.service().as_str().to_owned();
        let session_key = session.session_key();
        if self.sessions.contains_key(&session_key) {
            let RegisteredInteractionSession { ingress, .. } = session;
            self.registrar
                .revoke(ingress)
                .await
                .map_err(|_| InteractionAdmissionError::Registration)?;
            return Err(InteractionAdmissionError::Registration);
        }
        if matches!(
            service.as_str(),
            d2b_provider_clipboard_wayland::MANAGEMENT_SERVICE
                | d2b_provider_clipboard_wayland::BRIDGE_SERVICE
                | d2b_provider_clipboard_wayland::PICKER_SERVICE
        ) && self.ensure_clipboard().is_err()
        {
            let RegisteredInteractionSession { ingress, .. } = session;
            let _ = self.registrar.revoke(ingress).await;
            return Err(InteractionAdmissionError::ServiceUnavailable);
        }
        self.sessions.insert(session_key.clone(), session);
        Ok(self
            .sessions
            .get(&session_key)
            .expect("session was just installed"))
    }

    /// Borrow the authenticated route retained after registration.
    pub fn route(&self) -> Option<&AuthenticatedSessionRouteBinding> {
        self.sessions
            .values()
            .next()
            .map(RegisteredInteractionSession::route)
    }

    /// Borrow the authenticated route for one exact service package.
    pub fn route_for_service(&self, service: &str) -> Option<&AuthenticatedSessionRouteBinding> {
        self.sessions
            .values()
            .find(|session| session.service().as_str() == service)
            .map(RegisteredInteractionSession::route)
    }

    /// Borrow every authenticated route for one service package.
    pub fn routes_for_service(&self, service: &str) -> Vec<AuthenticatedSessionRouteBinding> {
        self.sessions
            .values()
            .filter(|session| session.service().as_str() == service)
            .map(|session| session.route().clone())
            .collect()
    }

    /// Find the sole authenticated ComponentSession for one exact execution
    /// target and service. The route context is the only source of target
    /// identity; no caller-supplied session handle is accepted. Absent, stale,
    /// or ambiguous sources fail closed.
    pub fn component_session_driver_for_target(
        &self,
        service: &str,
        target: &ResourceRef,
    ) -> Option<d2b_session::SessionDriverHandle> {
        let mut drivers = self.sessions.values().filter_map(|session| {
            if session.service_identity() != service {
                return None;
            }
            let context = session.route().context();
            let target_matches = context.execution_ref() == Some(target)
                || (!matches!(service, PROCESS_ATTACH_SERVICE | SHELL_SESSION_SERVICE)
                    && context.execution_ref().is_none()
                    && context.subject_ref() == target);
            let driver = target_matches
                .then(|| session.component_session_driver())
                .flatten()?;
            (driver.generation() == session.route().reconnect_generation().get()).then_some(driver)
        });
        let driver = drivers.next()?;
        drivers.next().is_none().then_some(driver)
    }

    fn route_for_session(&self, session_key: &str) -> Option<&AuthenticatedSessionRouteBinding> {
        self.sessions
            .get(session_key)
            .map(RegisteredInteractionSession::route)
    }

    /// Return the number of live authenticated interaction sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Whether one exact interaction service has an admitted session.
    pub fn has_service_session(&self, service: &str) -> bool {
        self.sessions
            .values()
            .any(|session| session.service().as_str() == service)
    }

    fn has_session(&self, session_key: &str) -> bool {
        self.sessions.contains_key(session_key)
    }

    /// Install the latest committed Core/resource-plane display evidence.
    pub fn bind_display_resource_evidence(&mut self, evidence: CoreDisplayResourceEvidence) {
        self.display_resource_evidence = Some(evidence);
    }

    /// Route display worker lifecycle through the durable Process resources
    /// owned by the system-core Resource API client.
    pub(crate) fn bind_display_resource_client(
        &mut self,
        client: Arc<ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>>,
    ) {
        self.display_resource_client = Some(client);
    }

    /// Bind Core's sealed committed interaction Provider configuration.
    pub(crate) fn bind_interaction_provider_configuration(
        &mut self,
        configuration: &CommittedInteractionProviderConfiguration,
    ) -> Result<(), &'static str> {
        if !configuration.is_complete() {
            return Err("interaction-configuration-incomplete");
        }
        self.clipboard_configuration = configuration.clipboard().cloned();
        self.notification_configuration = configuration.notification().cloned();
        Ok(())
    }

    pub(crate) fn bind_interaction_identity(&mut self, identity: &CommittedInteractionIdentity) {
        self.interaction_identity = Some(identity.clone());
    }

    /// Receive and dispatch one request that was demultiplexed by the
    /// registrar-owned ComponentSession response task.
    ///
    /// The request's service/member are checked against the authenticated
    /// route before a local operation lease is minted. Runtime methods only
    /// receive route projections retained by this composition.
    pub async fn dispatch_component_request(
        &mut self,
        service: &str,
        frame: Vec<u8>,
    ) -> Result<(), String> {
        let session_key = self
            .sessions
            .iter()
            .find(|(_, session)| session.service().as_str() == service)
            .map(|(key, _)| key.clone())
            .ok_or("interaction-session-unavailable")?;
        self.dispatch_component_request_for_session(&session_key, frame, Vec::new())
            .await
    }

    /// Dispatch one authenticated request together with its separately
    /// demultiplexed attachment batch.
    pub async fn dispatch_component_request_with_attachments(
        &mut self,
        service: &str,
        frame: Vec<u8>,
        attachments: Vec<OwnedAttachment>,
    ) -> Result<(), String> {
        let session_key = self
            .sessions
            .iter()
            .find(|(_, session)| session.service().as_str() == service)
            .map(|(key, _)| key.clone())
            .ok_or("interaction-session-unavailable")?;
        self.dispatch_component_request_for_session(&session_key, frame, attachments)
            .await
    }

    async fn dispatch_component_request_for_session(
        &mut self,
        session_key: &str,
        frame: Vec<u8>,
        attachments: Vec<OwnedAttachment>,
    ) -> Result<(), String> {
        let service = self
            .route_for_session(session_key)
            .ok_or("interaction-session-unavailable")?
            .service()
            .as_str()
            .to_owned();
        let stream_id = ttrpc_stream_id(&frame).map_err(|_| "invalid-request-frame")?;
        let payload = frame
            .get(ttrpc::proto::MESSAGE_HEADER_LENGTH..)
            .ok_or("invalid-request-frame")?;
        let request = match TtrpcRequest::parse_from_bytes(payload) {
            Ok(request) => request,
            Err(_) => {
                self.send_component_response(
                    session_key,
                    encode_interaction_response(
                        stream_id,
                        InteractionDispatchError::MalformedRequest.code(),
                        Vec::new(),
                    )
                    .map_err(|_| "response-encode-failed")?,
                )
                .await?;
                return Ok(());
            }
        };
        if request.service != service {
            self.send_component_response(
                session_key,
                encode_interaction_response(
                    stream_id,
                    InteractionDispatchError::ServiceMismatch.code(),
                    Vec::new(),
                )
                .map_err(|_| "response-encode-failed")?,
            )
            .await?;
            return Ok(());
        }
        if operation_catalog_entry(
            &service,
            &request.method,
            d2b_session::OperationKind::Method,
        )
        .is_none()
        {
            self.send_component_response(
                session_key,
                encode_interaction_response(
                    stream_id,
                    InteractionDispatchError::UnknownOperation.code(),
                    Vec::new(),
                )
                .map_err(|_| "response-encode-failed")?,
            )
            .await?;
            return Ok(());
        };
        let route = {
            let registered = self
                .sessions
                .get(session_key)
                .ok_or("interaction-session-unavailable")?;
            interaction_route_for_member(registered.route(), &request.method)
                .map_err(|_| "interaction-route-invalid")?
        };
        let operation_id = OperationId::parse(
            format!(
                "interaction-{}-{stream_id}-{}",
                service.replace('.', "-"),
                request.method.replace('/', "-"),
            )
            .to_ascii_lowercase(),
        )
        .map_err(|_| "interaction-operation-invalid")?;
        validate_interaction_attachments(
            &attachments,
            &service,
            &request.method,
            &frame,
            &operation_id,
        )
        .map_err(|_| "interaction-attachment-mismatch")?;
        let operation = OperationSpec::new(operation_id, 60_000)
            .map_err(|_| "interaction-operation-invalid")?;
        let ingress = self
            .sessions
            .get(session_key)
            .ok_or("interaction-session-unavailable")?
            .ingress();
        let lease = match ingress.begin_local_invoke(route, operation).await {
            Ok(lease) => lease,
            Err(_) => {
                self.send_component_response(
                    session_key,
                    encode_interaction_response(
                        stream_id,
                        InteractionDispatchError::SessionUnavailable.code(),
                        Vec::new(),
                    )
                    .map_err(|_| "response-encode-failed")?,
                )
                .await?;
                return Ok(());
            }
        };
        let (code, response_payload, finalize_after_response) = match self
            .dispatch_interaction_operation(
                session_key,
                &service,
                &request.method,
                &request.payload,
                attachments,
            ) {
            Ok((payload, finalize_after_response)) => {
                (TtrpcCode::OK, payload, finalize_after_response)
            }
            Err(error) => (error.code(), Vec::new(), false),
        };
        self.send_component_response(
            session_key,
            encode_interaction_response(stream_id, code, response_payload)
                .map_err(|_| "response-encode-failed")?,
        )
        .await?;
        lease.finish().map_err(|_| "interaction-operation-failed")?;
        if finalize_after_response {
            tokio::time::sleep(Duration::from_millis(1)).await;
            self.finalize_async(d2b_provider_display_wayland::GraceState::Expired)
                .await
                .map_err(|_| "interaction-finalization-failed")?;
        }
        Ok(())
    }

    async fn send_component_response(&self, service: &str, frame: Vec<u8>) -> Result<(), String> {
        self.sessions
            .get(service)
            .ok_or("interaction-session-unavailable")?
            .ingress()
            .send_component_response(frame)
            .await
            .map_err(|_| "interaction-response-failed".to_owned())
    }

    fn dispatch_interaction_operation(
        &mut self,
        session_key: &str,
        service: &str,
        method: &str,
        payload: &[u8],
        attachments: Vec<OwnedAttachment>,
    ) -> Result<(Vec<u8>, bool), InteractionDispatchError> {
        match (service, method) {
            (d2b_provider_display_wayland::SERVICE_PACKAGE, "DisplayService/Observe") => Ok((
                serde_json::to_vec(&serde_json::json!({
                    "runtime_installed": self.display.is_some(),
                    "ready": self
                        .display
                        .as_ref()
                        .is_some_and(|runtime| runtime.is_ready()),
                }))
                .map_err(|_| InteractionDispatchError::RuntimeFailure)?,
                false,
            )),
            (d2b_provider_display_wayland::SERVICE_PACKAGE, "DisplayService/Finalize") => {
                if !payload.is_empty() {
                    return Err(InteractionDispatchError::InvalidPayload);
                }
                Ok((
                    serde_json::to_vec(&serde_json::json!({"accepted": true}))
                        .map_err(|_| InteractionDispatchError::RuntimeFailure)?,
                    true,
                ))
            }
            (d2b_provider_display_wayland::SERVICE_PACKAGE, "DisplayService/Reconcile") => {
                let request: DisplayReconcileRequest = serde_json::from_slice(payload)
                    .map_err(|_| InteractionDispatchError::InvalidPayload)?;
                let result = self
                    .reconcile_display_request(request)
                    .map_err(|_| InteractionDispatchError::RuntimeFailure)?;
                Ok((
                    serde_json::to_vec(&serde_json::json!({
                        "phase": format!("{:?}", result.status.phase),
                        "worker_actions": result.worker_actions.len(),
                    }))
                    .map_err(|_| InteractionDispatchError::RuntimeFailure)?,
                    false,
                ))
            }
            (
                d2b_provider_clipboard_wayland::BRIDGE_SERVICE,
                "ClipboardBridgeService/CaptureGuest",
            ) => {
                let request: ClipboardCaptureRequest = serde_json::from_slice(payload)
                    .map_err(|_| InteractionDispatchError::InvalidPayload)?;
                let bridge_route = self
                    .route_for_session(session_key)
                    .filter(|route| {
                        route.service().as_str() == d2b_provider_clipboard_wayland::BRIDGE_SERVICE
                    })
                    .cloned()
                    .ok_or(InteractionDispatchError::SessionUnavailable)?;
                let guest_ref = self
                    .select_committed_guest(
                        d2b_provider_clipboard_wayland::BRIDGE_SERVICE,
                        &bridge_route,
                        request.guest_ref.as_ref(),
                        request.zone.as_ref(),
                    )
                    .ok_or(InteractionDispatchError::SessionUnavailable)?;
                let bytes = self
                    .clipboard_payload(
                        request.bytes,
                        attachments,
                        bridge_route.clone(),
                        Some(&guest_ref),
                        None,
                        AttachmentClass::GuestTransfer,
                    )
                    .map_err(|_| InteractionDispatchError::RuntimeFailure)?;
                let token = self
                    .capture_guest_clipboard_route_for_guest(
                        bridge_route.clone(),
                        guest_ref.clone(),
                        &request.mime,
                        &bytes,
                        daemon_now_secs(),
                    )
                    .map_err(|_| InteractionDispatchError::RuntimeFailure)?;
                if let Some(clipboard) = self.clipboard.as_mut() {
                    let event =
                        if bridge_route.subject_ref().resource_type().as_str() == "Provider" {
                            clipboard.guest_selection_event_route_for_guest(
                                bridge_route,
                                guest_ref,
                                &token,
                                daemon_now_secs(),
                            )
                        } else {
                            clipboard.guest_selection_event_route(
                                bridge_route,
                                &token,
                                daemon_now_secs(),
                            )
                        }
                        .map_err(|_| InteractionDispatchError::RuntimeFailure)?;
                    if self.pending_guest_selection_events.len() >= 128 {
                        self.pending_guest_selection_events.pop_first();
                    }
                    self.pending_guest_selection_events
                        .insert(token.clone(), event);
                }
                if let Some(clipboard) = self.clipboard.as_mut() {
                    clipboard
                        .flush_audit(16)
                        .map_err(|_| InteractionDispatchError::RuntimeFailure)?;
                }
                Ok((
                    serde_json::to_vec(&serde_json::json!({"entry_digest": token}))
                        .map_err(|_| InteractionDispatchError::RuntimeFailure)?,
                    false,
                ))
            }
            (
                d2b_provider_display_wayland::SERVICE_PACKAGE,
                "ClipboardBridgeService/CaptureHost",
            ) => {
                let request: ClipboardCaptureRequest = serde_json::from_slice(payload)
                    .map_err(|_| InteractionDispatchError::InvalidPayload)?;
                let display_route = self
                    .route_for_session(session_key)
                    .filter(|route| {
                        route.service().as_str() == d2b_provider_display_wayland::SERVICE_PACKAGE
                    })
                    .cloned()
                    .ok_or(InteractionDispatchError::SessionUnavailable)?;
                let source_event = request
                    .source_entry_digest
                    .as_deref()
                    .and_then(|digest| self.pending_guest_selection_events.remove(digest));
                let observer_user_ref = self
                    .display_resource_evidence
                    .as_ref()
                    .ok_or(InteractionDispatchError::SessionUnavailable)?
                    .observer_user_ref
                    .clone();
                let bytes = self
                    .clipboard_payload(
                        request.bytes,
                        attachments,
                        display_route.clone(),
                        None,
                        Some(&observer_user_ref),
                        AttachmentClass::HostSelectionWrite,
                    )
                    .map_err(|_| InteractionDispatchError::RuntimeFailure)?;
                let token = self
                    .capture_host_clipboard_route(
                        display_route,
                        &request.mime,
                        &bytes,
                        source_event,
                        daemon_now_secs(),
                    )
                    .map_err(|_| InteractionDispatchError::RuntimeFailure)?;
                if let Some(clipboard) = self.clipboard.as_mut() {
                    clipboard
                        .flush_audit(16)
                        .map_err(|_| InteractionDispatchError::RuntimeFailure)?;
                }
                Ok((
                    serde_json::to_vec(&serde_json::json!({"entry_digest": token}))
                        .map_err(|_| InteractionDispatchError::RuntimeFailure)?,
                    false,
                ))
            }

            (d2b_provider_clipboard_wayland::MANAGEMENT_SERVICE, "ClipboardService/Drain")
            | (d2b_provider_clipboard_wayland::BRIDGE_SERVICE, "ClipboardBridgeService/Drain") => {
                if !payload.is_empty() {
                    return Err(InteractionDispatchError::InvalidPayload);
                }
                let route = self
                    .route_for_session(session_key)
                    .cloned()
                    .ok_or(InteractionDispatchError::SessionUnavailable)?;
                self.ensure_clipboard()
                    .map_err(|_| InteractionDispatchError::RuntimeFailure)?
                    .admit_route(route)
                    .map_err(|_| InteractionDispatchError::SessionUnavailable)?;
                self.clipboard
                    .as_mut()
                    .expect("clipboard runtime was just admitted")
                    .drain()
                    .map_err(|_| InteractionDispatchError::RuntimeFailure)?;
                Ok((
                    serde_json::to_vec(&serde_json::json!({"drained": true}))
                        .map_err(|_| InteractionDispatchError::RuntimeFailure)?,
                    false,
                ))
            }
            (d2b_provider_clipboard_wayland::PICKER_SERVICE, "ClipboardPickerService/Complete") => {
                let request: PickerCompletionRequest = serde_json::from_slice(payload)
                    .map_err(|_| InteractionDispatchError::InvalidPayload)?;
                let source_route = self
                    .route_for_session(session_key)
                    .filter(|route| {
                        route.service().as_str() == d2b_provider_clipboard_wayland::PICKER_SERVICE
                    })
                    .cloned()
                    .ok_or(InteractionDispatchError::SessionUnavailable)?;
                let destination_route = self
                    .route_for_service(d2b_provider_clipboard_wayland::BRIDGE_SERVICE)
                    .cloned()
                    .ok_or(InteractionDispatchError::SessionUnavailable)?;
                let guest_ref = self
                    .select_committed_guest(
                        d2b_provider_clipboard_wayland::PICKER_SERVICE,
                        &source_route,
                        request.guest_ref.as_ref(),
                        request.zone.as_ref(),
                    )
                    .ok_or(InteractionDispatchError::SessionUnavailable)?;
                let source = self
                    .ensure_clipboard()
                    .map_err(|_| InteractionDispatchError::RuntimeFailure)?
                    .admit_route(source_route.clone())
                    .map_err(|_| InteractionDispatchError::SessionUnavailable)?;
                let destination = self
                    .clipboard
                    .as_ref()
                    .expect("clipboard runtime was just admitted")
                    .admit_route(destination_route.clone())
                    .map_err(|_| InteractionDispatchError::SessionUnavailable)?;
                let source = if source.subject_ref().resource_type().as_str() == "Provider" {
                    d2b_provider_clipboard_wayland::AuthenticatedClipboardSession::
                        from_authenticated_route_for_guest(source_route, guest_ref.clone())
                        .map_err(|_| InteractionDispatchError::SessionUnavailable)?
                } else {
                    source
                };
                let destination =
                    if destination.subject_ref().resource_type().as_str() == "Provider" {
                        d2b_provider_clipboard_wayland::AuthenticatedClipboardSession::
                            from_authenticated_route_for_guest(destination_route, guest_ref)
                            .map_err(|_| InteractionDispatchError::SessionUnavailable)?
                    } else {
                        destination
                    };
                let picker_request = d2b_provider_clipboard_wayland::PickerRequest::from_sessions(
                    &source,
                    &destination,
                    request.mime_types,
                )
                .map_err(|_| InteractionDispatchError::InvalidPayload)?;
                let result = request.selected_digest.clone().map_or(
                    d2b_provider_clipboard_wayland::PickerResult::Cancelled,
                    d2b_provider_clipboard_wayland::PickerResult::Selected,
                );
                let receipt = self
                    .clipboard
                    .as_mut()
                    .expect("clipboard runtime was just admitted")
                    .complete_picker(
                        &source,
                        &destination,
                        &picker_request,
                        result,
                        request.entry_digest,
                        daemon_now_secs(),
                    )
                    .map_err(|_| InteractionDispatchError::RuntimeFailure)?;
                let operation_id = receipt.operation_id().to_owned();
                self.pending_picker_receipts
                    .insert(operation_id.clone(), receipt);
                Ok((
                    serde_json::to_vec(&serde_json::json!({
                        "completed": true,
                        "operation_id": operation_id,
                    }))
                    .map_err(|_| InteractionDispatchError::RuntimeFailure)?,
                    false,
                ))
            }
            (
                d2b_provider_clipboard_wayland::PICKER_SERVICE,
                "ClipboardPickerService/Materialize",
            ) => {
                let request: PickerMaterializeRequest = serde_json::from_slice(payload)
                    .map_err(|_| InteractionDispatchError::InvalidPayload)?;
                let source_route = self
                    .route_for_session(session_key)
                    .filter(|route| {
                        route.service().as_str() == d2b_provider_clipboard_wayland::PICKER_SERVICE
                    })
                    .cloned()
                    .ok_or(InteractionDispatchError::SessionUnavailable)?;
                let destination_route = self
                    .route_for_service(d2b_provider_clipboard_wayland::BRIDGE_SERVICE)
                    .cloned()
                    .ok_or(InteractionDispatchError::SessionUnavailable)?;
                let guest_ref = self
                    .select_committed_guest(
                        d2b_provider_clipboard_wayland::PICKER_SERVICE,
                        &source_route,
                        request.guest_ref.as_ref(),
                        request.zone.as_ref(),
                    )
                    .ok_or(InteractionDispatchError::SessionUnavailable)?;
                let source = self
                    .ensure_clipboard()
                    .map_err(|_| InteractionDispatchError::RuntimeFailure)?
                    .admit_route(source_route.clone())
                    .map_err(|_| InteractionDispatchError::SessionUnavailable)?;
                let destination = self
                    .clipboard
                    .as_ref()
                    .expect("clipboard runtime was just admitted")
                    .admit_route(destination_route.clone())
                    .map_err(|_| InteractionDispatchError::SessionUnavailable)?;
                let source = if source.subject_ref().resource_type().as_str() == "Provider" {
                    d2b_provider_clipboard_wayland::AuthenticatedClipboardSession::
                        from_authenticated_route_for_guest(source_route, guest_ref.clone())
                        .map_err(|_| InteractionDispatchError::SessionUnavailable)?
                } else {
                    source
                };
                let destination =
                    if destination.subject_ref().resource_type().as_str() == "Provider" {
                        d2b_provider_clipboard_wayland::AuthenticatedClipboardSession::
                            from_authenticated_route_for_guest(destination_route, guest_ref)
                            .map_err(|_| InteractionDispatchError::SessionUnavailable)?
                    } else {
                        destination
                    };
                let paste_route =
                    d2b_provider_clipboard_wayland::AuthenticatedPasteRoute::from_sessions(
                        &source,
                        &destination,
                    )
                    .map_err(|_| InteractionDispatchError::SessionUnavailable)?;
                let now_secs = daemon_now_secs();
                let receipt = self
                    .pending_picker_receipts
                    .get(&request.operation_id)
                    .ok_or(InteractionDispatchError::SessionUnavailable)?;
                self.clipboard
                    .as_ref()
                    .expect("clipboard runtime was just admitted")
                    .authorize_paste_after_picker(
                        &paste_route,
                        receipt,
                        &request.entry_digest,
                        now_secs,
                    )
                    .map_err(|_| InteractionDispatchError::RuntimeFailure)?;
                let receipt = self
                    .pending_picker_receipts
                    .remove(&request.operation_id)
                    .ok_or(InteractionDispatchError::SessionUnavailable)?;
                let bytes = self
                    .clipboard
                    .as_mut()
                    .expect("clipboard runtime was just admitted")
                    .materialize_after_picker(
                        &paste_route,
                        receipt,
                        &request.entry_digest,
                        now_secs,
                    )
                    .map_err(|_| InteractionDispatchError::RuntimeFailure)?;
                if bytes.len() > MAX_LOGICAL_MESSAGE_BYTES as usize {
                    return Err(InteractionDispatchError::RuntimeFailure);
                }
                let response = serde_json::to_vec(&serde_json::json!({
                    "materialized": true,
                    "entry_digest": request.entry_digest,
                    "bytes": bytes,
                }))
                .map_err(|_| InteractionDispatchError::RuntimeFailure)?;
                if response.len() > MAX_LOGICAL_MESSAGE_BYTES as usize {
                    return Err(InteractionDispatchError::RuntimeFailure);
                }
                Ok((response, false))
            }
            (d2b_provider_notification_desktop::SERVICE_PACKAGE, "NotificationService/Drain") => {
                if !payload.is_empty() {
                    return Err(InteractionDispatchError::InvalidPayload);
                }
                if self.route_for_session(session_key).is_none() {
                    return Err(InteractionDispatchError::SessionUnavailable);
                }
                self.ensure_notification()
                    .map_err(|_| InteractionDispatchError::RuntimeFailure)?
                    .drain()
                    .map_err(|_| InteractionDispatchError::RuntimeFailure)?;
                Ok((
                    serde_json::to_vec(&serde_json::json!({"drained": true}))
                        .map_err(|_| InteractionDispatchError::RuntimeFailure)?,
                    false,
                ))
            }
            (d2b_provider_notification_desktop::SERVICE_PACKAGE, "NotificationService/Deliver") => {
                let request: NotificationDeliverRequest = serde_json::from_slice(payload)
                    .map_err(|_| InteractionDispatchError::InvalidPayload)?;
                let source_route = self
                    .route_for_session(session_key)
                    .filter(|route| {
                        route.service().as_str()
                            == d2b_provider_notification_desktop::SERVICE_PACKAGE
                    })
                    .cloned()
                    .ok_or(InteractionDispatchError::SessionUnavailable)?;
                let guest_ref = self
                    .select_committed_guest(
                        d2b_provider_notification_desktop::SERVICE_PACKAGE,
                        &source_route,
                        request.guest_ref.as_ref(),
                        request.zone.as_ref(),
                    )
                    .ok_or(InteractionDispatchError::SessionUnavailable)?;
                let observer_route = self
                    .route_for_service(d2b_provider_display_wayland::SERVICE_PACKAGE)
                    .cloned()
                    .ok_or(InteractionDispatchError::SessionUnavailable)?;
                if !self
                    .display
                    .as_ref()
                    .is_some_and(|display| display.is_ready())
                {
                    return Err(InteractionDispatchError::RuntimeFailure);
                }
                let observer_user_ref = self
                    .display_resource_evidence
                    .as_ref()
                    .ok_or(InteractionDispatchError::SessionUnavailable)?
                    .observer_user_ref
                    .clone();
                let observer_evidence = d2b_provider_notification_desktop::SessionEvidence::
                    from_display_dependency_route(observer_route, observer_user_ref)
                    .map_err(|_| InteractionDispatchError::SessionUnavailable)?;
                self.ensure_notification()
                    .map_err(|_| InteractionDispatchError::RuntimeFailure)?;
                let mut notification_port = self
                    .notification_port
                    .lock()
                    .map_err(|_| InteractionDispatchError::RuntimeFailure)?;
                let result = if source_route.subject_ref().resource_type().as_str() == "Provider" {
                    self.notification
                        .as_mut()
                        .expect("notification runtime was just installed")
                        .deliver_evidence_for_guest(
                            &mut **notification_port,
                            source_route,
                            guest_ref,
                            &observer_evidence,
                            request.request,
                            daemon_now_secs(),
                        )
                } else {
                    let source_evidence =
                        d2b_provider_notification_desktop::SessionEvidence::from_daemon_route(
                            source_route,
                        )
                        .map_err(|_| InteractionDispatchError::SessionUnavailable)?;
                    self.notification
                        .as_mut()
                        .expect("notification runtime was just installed")
                        .deliver_evidence(
                            &mut **notification_port,
                            &source_evidence,
                            &observer_evidence,
                            request.request,
                            daemon_now_secs(),
                        )
                }
                .map_err(|_| InteractionDispatchError::RuntimeFailure)?;
                let response = match result {
                    d2b_provider_notification_desktop::NotificationResult::Accepted {
                        notification_id,
                        action_nonces,
                    } => serde_json::json!({
                        "accepted": true,
                        "notification_id": notification_id,
                        "action_count": action_nonces.len(),
                    }),
                    d2b_provider_notification_desktop::NotificationResult::CapacityExceeded => {
                        serde_json::json!({"accepted": false, "capacity_exceeded": true})
                    }
                    d2b_provider_notification_desktop::NotificationResult::SinkUnavailable => {
                        serde_json::json!({"accepted": false, "sink_unavailable": true})
                    }
                    d2b_provider_notification_desktop::NotificationResult::Rejected => {
                        serde_json::json!({"accepted": false, "rejected": true})
                    }
                };
                Ok((
                    serde_json::to_vec(&response)
                        .map_err(|_| InteractionDispatchError::RuntimeFailure)?,
                    false,
                ))
            }
            (d2b_provider_clipboard_wayland::MANAGEMENT_SERVICE, "ClipboardService/Reconcile") => {
                if !payload.is_empty() {
                    return Err(InteractionDispatchError::InvalidPayload);
                }
                self.reconcile_dependents()
                    .map_err(|_| InteractionDispatchError::RuntimeFailure)?;
                Ok((
                    serde_json::to_vec(&serde_json::json!({"reconciled": true}))
                        .map_err(|_| InteractionDispatchError::RuntimeFailure)?,
                    false,
                ))
            }
            (
                d2b_provider_notification_desktop::SERVICE_PACKAGE,
                "NotificationService/Reconcile",
            ) => {
                if !payload.is_empty() {
                    return Err(InteractionDispatchError::InvalidPayload);
                }
                self.reconcile_dependents()
                    .map_err(|_| InteractionDispatchError::RuntimeFailure)?;
                Ok((
                    serde_json::to_vec(&serde_json::json!({"reconciled": true}))
                        .map_err(|_| InteractionDispatchError::RuntimeFailure)?,
                    false,
                ))
            }
            _ => Err(InteractionDispatchError::UnknownOperation),
        }
    }

    fn clipboard_payload(
        &mut self,
        inline: Option<Vec<u8>>,
        attachments: Vec<OwnedAttachment>,
        route: AuthenticatedSessionRouteBinding,
        guest_ref: Option<&ResourceRef>,
        observer_user: Option<&ResourceRef>,
        attachment_class: AttachmentClass,
    ) -> Result<Vec<u8>, ClipboardServiceError> {
        if attachments.is_empty() {
            let bytes = inline.ok_or(ClipboardServiceError::AttachmentRejected)?;
            if bytes.len() > MAX_LOGICAL_MESSAGE_BYTES as usize {
                return Err(ClipboardServiceError::AttachmentRejected);
            }
            return Ok(bytes);
        }
        if inline.is_some() {
            return Err(ClipboardServiceError::AttachmentRejected);
        }
        for attachment in &attachments {
            let descriptor = attachment
                .descriptor()
                .ok_or(ClipboardServiceError::AttachmentRejected)?;
            if descriptor.service != ServicePackage::ClipboardBridgeV3
                || descriptor.kind != AttachmentKind::FileDescriptor
                || descriptor.purpose != AttachmentPurpose::ClipboardTransfer
            {
                return Err(ClipboardServiceError::AttachmentRejected);
            }
        }
        let packet = VerifiedPacket::from_bound_attachments(attachments)
            .map_err(|_| ClipboardServiceError::AttachmentRejected)?;
        let clipboard = self.ensure_clipboard()?;
        let session = match attachment_class {
            AttachmentClass::GuestTransfer => {
                let guest_ref = guest_ref
                    .cloned()
                    .ok_or(ClipboardServiceError::SessionUnauthenticated)?;
                if route.subject_ref().resource_type().as_str() == "Provider" {
                    d2b_provider_clipboard_wayland::AuthenticatedClipboardSession::
                        from_authenticated_route_for_guest(route, guest_ref)
                        .map_err(|_| ClipboardServiceError::SessionUnauthenticated)?
                } else {
                    clipboard
                        .admit_route(route)
                        .map_err(|_| ClipboardServiceError::SessionUnauthenticated)?
                }
            }
            AttachmentClass::HostSelectionRead | AttachmentClass::HostSelectionWrite => {
                d2b_provider_clipboard_wayland::AuthenticatedClipboardSession::
                    from_display_observer_route(route.clone())
                    .or_else(|_| {
                        observer_user
                            .cloned()
                            .ok_or(ClipboardServiceError::HostSessionInvalid)
                            .and_then(|user_ref| {
                                d2b_provider_clipboard_wayland::AuthenticatedClipboardSession::
                                    from_display_dependency_route(route, user_ref)
                            })
                    })?
            }
        };
        let verified =
            clipboard
                .host()
                .accept_verified_packet(&session, packet, attachment_class)?;
        let payloads = verified
            .read_all()
            .map_err(|_| ClipboardServiceError::AttachmentRejected)?;
        if payloads.len() != 1 {
            return Err(ClipboardServiceError::AttachmentRejected);
        }
        payloads
            .into_iter()
            .next()
            .ok_or(ClipboardServiceError::AttachmentRejected)
    }

    /// Project the retained authenticated route into the clipboard service
    /// identity without reconstructing ComponentSession authority.
    pub fn clipboard_session(
        &self,
    ) -> Result<d2b_provider_clipboard_wayland::AuthenticatedClipboardSession, ClipboardServiceError>
    {
        let route = self
            .route_for_service(d2b_provider_clipboard_wayland::BRIDGE_SERVICE)
            .ok_or(ClipboardServiceError::SessionUnauthenticated)?;
        d2b_provider_clipboard_wayland::AuthenticatedClipboardSession::from_authenticated_route(
            route.clone(),
        )
    }

    /// Project the retained authenticated route into notification evidence
    /// for source reconciliation and bounded dispatch.
    pub fn notification_session(
        &self,
    ) -> Result<
        d2b_provider_notification_desktop::SessionEvidence,
        d2b_provider_notification_desktop::AdmissionError,
    > {
        let route = self
            .route_for_service(d2b_provider_notification_desktop::SERVICE_PACKAGE)
            .ok_or(d2b_provider_notification_desktop::AdmissionError::SessionUnauthenticated)?;
        d2b_provider_notification_desktop::SessionEvidence::from_authenticated_route(route.clone())
    }

    fn ensure_clipboard(
        &mut self,
    ) -> Result<
        &mut d2b_provider_clipboard_wayland::ClipboardRuntime<InteractionDrainEffects>,
        ClipboardServiceError,
    > {
        if self.clipboard.is_none() {
            #[cfg(not(test))]
            let configuration = self
                .clipboard_configuration
                .as_ref()
                .ok_or(ClipboardServiceError::SessionUnauthenticated)?;
            #[cfg(test)]
            let configuration = self.clipboard_configuration.as_ref();
            #[cfg(not(test))]
            let policy = configuration.policy();
            #[cfg(test)]
            let policy = configuration.map_or_else(
                d2b_provider_clipboard_wayland::Policy::default,
                CommittedClipboardProviderConfiguration::policy,
            );
            #[cfg(not(test))]
            let audit_capacity = configuration.audit_capacity();
            #[cfg(test)]
            let audit_capacity =
                configuration.map_or(128, |configuration| configuration.audit_capacity());
            self.clipboard = Some(
                d2b_provider_clipboard_wayland::ClipboardRuntime::new(
                    policy,
                    audit_capacity,
                    None,
                    InteractionDrainEffects::default(),
                )
                .map_err(|error| match error {
                    d2b_provider_clipboard_wayland::ClipboardRuntimeError::Service(error) => error,
                    _ => ClipboardServiceError::SessionUnauthenticated,
                })?,
            );
        }
        Ok(self
            .clipboard
            .as_mut()
            .expect("clipboard runtime was installed"))
    }

    fn ensure_notification(
        &mut self,
    ) -> Result<
        &mut d2b_provider_notification_desktop::NotificationRuntime<InteractionDrainEffects>,
        &'static str,
    > {
        if self.notification.is_none() {
            let source_route = self
                .route_for_service(d2b_provider_notification_desktop::SERVICE_PACKAGE)
                .cloned()
                .ok_or("notification-source-session-unavailable")?;
            self.ensure_notification_for_source(&source_route)?;
            self.reconcile_dependents()
                .map_err(|_| "notification-display-dependency-unavailable")?;
        }
        Ok(self
            .notification
            .as_mut()
            .expect("notification runtime was installed"))
    }

    fn ensure_notification_for_source(
        &mut self,
        _source_route: &AuthenticatedSessionRouteBinding,
    ) -> Result<
        &mut d2b_provider_notification_desktop::NotificationRuntime<InteractionDrainEffects>,
        &'static str,
    > {
        if self.notification.is_none() {
            #[cfg(not(test))]
            let config = self
                .notification_configuration
                .as_ref()
                .ok_or("notification-configuration-unavailable")?
                .config();
            #[cfg(test)]
            let config = match self.notification_configuration.as_ref() {
                Some(configuration) => configuration.config(),
                None => {
                    let guest_refs =
                        if _source_route.subject_ref().resource_type().as_str() == "Guest" {
                            vec![_source_route.subject_ref().clone()]
                        } else {
                            self.interaction_identity
                                .as_ref()
                                .map(|identity| {
                                    identity.allowed_guest_sources().keys().cloned().collect()
                                })
                                .unwrap_or_default()
                        };
                    if guest_refs.is_empty() {
                        return Err("notification-guest-sources-unavailable");
                    }
                    let sources = guest_refs
                        .into_iter()
                        .map(|guest_ref| {
                            d2b_provider_notification_desktop::GuestSourceConfig::new(
                                guest_ref,
                                _source_route.zone().clone(),
                                Category::ALL,
                            )
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let display_route = self
                        .route_for_service(d2b_provider_display_wayland::SERVICE_PACKAGE)
                        .ok_or("notification-display-session-unavailable")?;
                    let host_execution_ref = display_route
                        .context()
                        .execution_ref()
                        .cloned()
                        .ok_or("notification-host-binding-missing")?;
                    let observer_user_ref = self
                        .display_resource_evidence
                        .as_ref()
                        .ok_or("notification-display-evidence-unavailable")?
                        .observer_user_ref
                        .clone();
                    d2b_provider_notification_desktop::NotificationProviderConfig::new(sources)?
                        .with_host_binding(host_execution_ref, observer_user_ref)?
                        .with_display_wayland_ref(Some(
                            ResourceRef::parse("Provider/display-wayland")
                                .map_err(|_| "notification-display-provider-invalid")?,
                        ))?
                }
            };
            self.notification = Some(
                d2b_provider_notification_desktop::NotificationRuntime::new(
                    config,
                    InteractionDrainEffects::new(Arc::clone(&self.notification_port)),
                )
                .map_err(|_| "notification-runtime-unavailable")?,
            );
        }
        Ok(self
            .notification
            .as_mut()
            .expect("notification runtime was installed"))
    }

    fn select_committed_guest(
        &self,
        service: &str,
        route: &AuthenticatedSessionRouteBinding,
        requested_guest: Option<&ResourceRef>,
        requested_zone: Option<&ZoneId>,
    ) -> Option<ResourceRef> {
        if requested_zone.is_some_and(|zone| zone != route.zone()) {
            return None;
        }
        let configured: Vec<ResourceRef> = match service {
            d2b_provider_clipboard_wayland::BRIDGE_SERVICE
            | d2b_provider_clipboard_wayland::PICKER_SERVICE
            | d2b_provider_clipboard_wayland::MANAGEMENT_SERVICE => self
                .clipboard_configuration
                .as_ref()
                .map(|configuration| configuration.guest_sources().cloned().collect())
                .unwrap_or_default(),
            d2b_provider_notification_desktop::SERVICE_PACKAGE => self
                .notification_configuration
                .as_ref()
                .map(|configuration| configuration.guest_sources().cloned().collect())
                .unwrap_or_default(),
            _ => return None,
        };
        let candidate = requested_guest
            .cloned()
            .or_else(|| (configured.len() == 1).then(|| configured[0].clone()))
            .or_else(|| {
                (route.subject_ref().resource_type().as_str() == "Guest")
                    .then(|| route.subject_ref().clone())
            })?;
        if candidate.resource_type().as_str() != "Guest"
            || (!configured.is_empty() && !configured.iter().any(|guest| guest == &candidate))
            || (route.subject_ref().resource_type().as_str() == "Guest"
                && route.subject_ref() != &candidate)
        {
            return None;
        }
        if let Some(identity) = &self.interaction_identity {
            if !identity.allowed_guest_sources().contains_key(&candidate) {
                return None;
            }
        } else if route.subject_ref().resource_type().as_str() == "Provider"
            && configured.is_empty()
        {
            return None;
        }
        Some(candidate)
    }

    /// Reconcile the dependent clipboard and notification runtimes after the
    /// display route has supplied a current authenticated dependency.
    pub fn reconcile_dependents(&mut self) -> Result<(), InteractionDependencyError> {
        if !self
            .display
            .as_ref()
            .is_some_and(|display| display.is_ready())
        {
            if let Some(clipboard) = self.clipboard.as_mut() {
                clipboard
                    .reconcile_display(None)
                    .map_err(InteractionDependencyError::Clipboard)?;
            }
            if let Some(notification) = self.notification.as_mut() {
                notification
                    .reconcile_daemon_routes(None, &[])
                    .map_err(InteractionDependencyError::Notification)?;
            }
            return Err(InteractionDependencyError::DisplayUnavailable);
        }
        let route = self
            .route_for_service(d2b_provider_display_wayland::SERVICE_PACKAGE)
            .ok_or(InteractionDependencyError::SessionUnauthenticated)?
            .clone();
        let observer_user_ref = self
            .display_resource_evidence
            .as_ref()
            .ok_or(InteractionDependencyError::DisplayUnavailable)?
            .observer_user_ref
            .clone();
        let clipboard_dependency =
            d2b_provider_clipboard_wayland::DisplayDependencyEvidence::from_committed_display_route(
                route.clone(),
                observer_user_ref.clone(),
            )
            .map_err(|_| InteractionDependencyError::DisplayUnavailable)?;
        if self
            .clipboard_configuration
            .as_ref()
            .is_some_and(|configuration| !configuration.matches_display(&clipboard_dependency))
        {
            return Err(InteractionDependencyError::DisplayUnavailable);
        }
        if let Some(clipboard) = self.clipboard.as_mut() {
            clipboard
                .reconcile_display(Some(clipboard_dependency))
                .map_err(InteractionDependencyError::Clipboard)?;
        }
        let source_routes =
            self.routes_for_service(d2b_provider_notification_desktop::SERVICE_PACKAGE);
        if let Some(notification) = self.notification.as_mut() {
            if let Some(configuration) = self.notification_configuration.as_ref() {
                let guest_refs = configuration.guest_sources().cloned().collect::<Vec<_>>();
                notification
                    .reconcile_daemon_routes_for_guests(Some(route), &source_routes, &guest_refs)
                    .map_err(InteractionDependencyError::Notification)?;
            } else if let Some(identity) = self.interaction_identity.as_ref() {
                let guest_refs = identity
                    .allowed_guest_sources()
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>();
                if source_routes
                    .iter()
                    .all(|source| source.subject_ref().resource_type().as_str() == "Guest")
                {
                    notification
                        .reconcile_daemon_routes(Some(route), &source_routes)
                        .map_err(InteractionDependencyError::Notification)?;
                } else {
                    notification
                        .reconcile_daemon_routes_for_guests(
                            Some(route),
                            &source_routes,
                            &guest_refs,
                        )
                        .map_err(InteractionDependencyError::Notification)?;
                }
            } else {
                notification
                    .reconcile_daemon_routes(Some(route), &source_routes)
                    .map_err(InteractionDependencyError::Notification)?;
            }
        }
        Ok(())
    }

    /// Dispatch a bounded Guest clipboard capture through the authenticated
    /// route retained by the daemon.
    pub fn capture_guest_clipboard(
        &mut self,
        mime: &str,
        bytes: &[u8],
        now_secs: u64,
    ) -> Result<String, ClipboardServiceError> {
        let route = self
            .route_for_service(d2b_provider_clipboard_wayland::BRIDGE_SERVICE)
            .ok_or(ClipboardServiceError::SessionUnauthenticated)?
            .clone();
        self.capture_guest_clipboard_route(route, mime, bytes, now_secs)
    }

    /// Dispatch a bounded Guest clipboard capture through one exact route.
    pub fn capture_guest_clipboard_route(
        &mut self,
        route: AuthenticatedSessionRouteBinding,
        mime: &str,
        bytes: &[u8],
        now_secs: u64,
    ) -> Result<String, ClipboardServiceError> {
        let guest = self
            .select_committed_guest(
                d2b_provider_clipboard_wayland::BRIDGE_SERVICE,
                &route,
                None,
                None,
            )
            .ok_or(ClipboardServiceError::SessionUnauthenticated)?;
        self.capture_guest_clipboard_route_for_guest(route, guest, mime, bytes, now_secs)
    }

    /// Dispatch a Guest clipboard capture through an authenticated Provider
    /// route and a committed Guest selector.
    pub fn capture_guest_clipboard_route_for_guest(
        &mut self,
        route: AuthenticatedSessionRouteBinding,
        guest_ref: ResourceRef,
        mime: &str,
        bytes: &[u8],
        now_secs: u64,
    ) -> Result<String, ClipboardServiceError> {
        if self
            .select_committed_guest(
                d2b_provider_clipboard_wayland::BRIDGE_SERVICE,
                &route,
                Some(&guest_ref),
                None,
            )
            .is_none()
        {
            return Err(ClipboardServiceError::SessionUnauthenticated);
        }
        let result = if route.subject_ref().resource_type().as_str() == "Provider" {
            self.ensure_clipboard()?
                .capture_guest_route_for_guest(route, guest_ref, mime, bytes, now_secs)
        } else {
            self.ensure_clipboard()?
                .capture_guest_route(route, mime, bytes, now_secs)
        };
        result.map_err(|error| match error {
            d2b_provider_clipboard_wayland::ClipboardRuntimeError::Service(error) => error,
            _ => ClipboardServiceError::SessionUnauthenticated,
        })
    }

    /// Dispatch a bounded host clipboard capture through the authenticated
    /// route retained by the daemon.
    pub fn capture_host_clipboard(
        &mut self,
        mime: &str,
        bytes: &[u8],
        source_event: Option<d2b_provider_clipboard_wayland::GuestSelectionEvent>,
        now_secs: u64,
    ) -> Result<String, ClipboardServiceError> {
        let route = self
            .route_for_service(d2b_provider_display_wayland::SERVICE_PACKAGE)
            .ok_or(ClipboardServiceError::SessionUnauthenticated)?
            .clone();
        self.capture_host_clipboard_route(route, mime, bytes, source_event, now_secs)
    }

    /// Dispatch a bounded host clipboard capture through an authenticated
    /// desktop User route.
    pub fn capture_host_clipboard_route(
        &mut self,
        route: AuthenticatedSessionRouteBinding,
        mime: &str,
        bytes: &[u8],
        source_event: Option<d2b_provider_clipboard_wayland::GuestSelectionEvent>,
        now_secs: u64,
    ) -> Result<String, ClipboardServiceError> {
        let observer_user = self
            .display_resource_evidence
            .as_ref()
            .map(|evidence| evidence.observer_user_ref.clone());
        self.ensure_clipboard()?
            .capture_host_route(
                route,
                mime,
                bytes,
                source_event,
                observer_user.as_ref(),
                now_secs,
            )
            .map_err(|error| match error {
                d2b_provider_clipboard_wayland::ClipboardRuntimeError::Service(error) => error,
                _ => ClipboardServiceError::SessionUnauthenticated,
            })
    }

    /// Reconcile the display runtime through the registered route and the
    /// daemon-owned supervisor effects.
    pub fn reconcile_display(
        &mut self,
        controller: d2b_provider_display_wayland::DisplayController,
        spec: &WaylandSessionSpec,
        dependencies: d2b_provider_display_wayland::DependencyState,
        supervision: d2b_provider_display_wayland::WorkerRestartEvidence,
        policy: &WaylandPolicySnapshot,
    ) -> Result<d2b_provider_display_wayland::ReconcileResult, DisplayRuntimeError> {
        let route = self
            .route_for_service(d2b_provider_display_wayland::SERVICE_PACKAGE)
            .ok_or(DisplayRuntimeError::SessionUnauthenticated)?
            .clone();
        let supervisor = self.supervisor.clone();
        let resource_client = self.display_resource_client.clone();
        let interaction_identity = self.interaction_identity.clone();
        let zone = route.zone().clone();
        let effects = match (resource_client, interaction_identity) {
            (Some(client), Some(identity)) => DisplaySupervisorEffects::new_with_resource_client(
                supervisor,
                client,
                zone.clone(),
                identity.wayland_session_ref().clone(),
                identity.wayland_session_uid().clone(),
            ),
            _ => {
                #[cfg(test)]
                {
                    DisplaySupervisorEffects::new(supervisor)
                }
                #[cfg(not(test))]
                {
                    return Err(DisplayRuntimeError::Effect(
                        WorkerEffectError::LaunchRejected,
                    ));
                }
            }
        };
        let runtime = self
            .display
            .get_or_insert_with(|| DisplayRuntime::new(controller, effects));
        let result =
            runtime.reconcile_registered(&route, spec, dependencies, supervision, policy)?;
        if result.status.phase == d2b_provider_display_wayland::Phase::Ready {
            self.reconcile_dependents()
                .map_err(|_| DisplayRuntimeError::ObservationUnavailable)?;
        }
        self.persist_display_status(zone, &result)?;
        Ok(result)
    }

    fn persist_display_status(
        &self,
        zone: ZoneId,
        result: &d2b_provider_display_wayland::ReconcileResult,
    ) -> Result<(), DisplayRuntimeError> {
        let (Some(client), Some(identity)) = (
            self.display_resource_client.clone(),
            self.interaction_identity.clone(),
        ) else {
            return Ok(());
        };
        let resource_ref = identity.wayland_session_ref().clone();
        let resource_uid = identity.wayland_session_uid().clone();
        let phase = format!("{:?}", result.status.phase);
        let projection = wayland_session_resource_projection(&result.status.resource);
        run_effect(move || async move {
            let response = client
                .get(resource_get_request(
                    &zone,
                    &resource_ref,
                    "display-wayland-status-get",
                ))
                .await;
            if response.error.is_some() {
                return Err(WorkerEffectError::WorkerUnavailable);
            }
            let resource = response
                .resource
                .0
                .ok_or(WorkerEffectError::WorkerUnavailable)?;
            let envelope = ResourceEnvelope::from_json(&resource.canonical_json)
                .map_err(|_| WorkerEffectError::WorkerUnavailable)?;
            if envelope.resource_type().as_str() != "display-wayland.d2bus.org.WaylandSession"
                || envelope.metadata().uid() != &resource_uid
                || envelope.metadata().zone() != &zone
                || ResourceRef::new(
                    envelope.resource_type().clone(),
                    envelope.metadata().name().clone(),
                ) != resource_ref
            {
                return Err(WorkerEffectError::LaunchRejected);
            }
            let stored = StoredResource {
                resource_ref,
                zone,
                uid: envelope.metadata().uid().clone(),
                generation: envelope.metadata().generation().clone(),
                revision: envelope.metadata().revision().clone(),
                canonical_json: resource.canonical_json,
                payload_digest: resource.payload_digest,
            };
            let status = serde_json::json!({ "phase": phase });
            d2bd_runtime::resource_runtime_support::persist_resource_status_with_projection(
                &client,
                &stored,
                &status,
                Some(&projection),
            )
            .await
            .map_err(|_| WorkerEffectError::WorkerUnavailable)
        })
        .map_err(DisplayRuntimeError::Effect)
    }

    fn reconcile_display_request(
        &mut self,
        request: DisplayReconcileRequest,
    ) -> Result<d2b_provider_display_wayland::ReconcileResult, DisplayRuntimeError> {
        let route = self
            .route_for_service(d2b_provider_display_wayland::SERVICE_PACKAGE)
            .ok_or(DisplayRuntimeError::SessionUnauthenticated)?
            .clone();
        let execution_ref = route
            .context()
            .execution_ref()
            .ok_or(DisplayRuntimeError::SessionMismatch)?;
        if request.spec.guest_ref() != route.subject_ref()
            || request.spec.host_ref() != execution_ref
        {
            return Err(DisplayRuntimeError::SessionMismatch);
        }
        let policy_generation = route
            .provider_generation()
            .map(|generation| generation.get())
            .ok_or(DisplayRuntimeError::InvalidPolicy)?;
        let evidence = self
            .display_resource_evidence
            .as_ref()
            .ok_or(DisplayRuntimeError::InvalidPolicy)?;
        if request.spec.policy_ref() != &evidence.policy_ref {
            return Err(DisplayRuntimeError::InvalidPolicy);
        }
        if request.spec.user_ref() != &evidence.observer_user_ref {
            return Err(DisplayRuntimeError::SessionMismatch);
        }
        if !evidence.resource_ready
            || evidence.resource_revision.get() == 0
            || policy_generation == 0
        {
            return Err(DisplayRuntimeError::InvalidPolicy);
        }
        if route
            .controller_generation()
            .map(|generation| generation.get())
            .is_some_and(|generation| {
                evidence
                    .committed_policy
                    .controller_generation
                    .is_some_and(|committed| committed.get() != generation)
            })
        {
            return Err(DisplayRuntimeError::InvalidPolicy);
        }
        let policy = WaylandPolicySnapshot::from_authenticated_route(
            &route,
            evidence.policy_ref.clone(),
            evidence.policy_generation,
            evidence.defaults.clone(),
            evidence.zone_policy.clone(),
        )
        .map_err(|_| DisplayRuntimeError::InvalidPolicy)?;
        let supervision = if let Some(display) = self.display.as_mut() {
            display.refresh_supervision()?;
            display.supervision()
        } else {
            WorkerRestartEvidence::from_supervisor(daemon_monotonic_ms(), None, None, 1)
        };
        self.reconcile_display(
            DisplayController::new(8),
            &request.spec,
            evidence.dependencies.clone(),
            supervision,
            &policy,
        )
    }

    /// Reconcile a committed display session as part of an exact VM start.
    ///
    /// This reuses the typed DisplayService/Reconcile path but takes its
    /// desired state only from the committed Zone resource. The live display
    /// route and the committed session identity must agree before any child
    /// Process resource can be created.
    pub(crate) fn reconcile_committed_display_for_vm_start(
        &mut self,
        vm: &str,
        session_ref: &ResourceRef,
        session_uid: &ResourceUid,
        spec: &WaylandSessionSpec,
    ) -> Result<d2b_provider_display_wayland::ReconcileResult, DisplayRuntimeError> {
        let expected_guest_name = format!("Guest/{vm}");
        let expected_guest = ResourceRef::parse(&expected_guest_name)
            .map_err(|_| DisplayRuntimeError::SessionMismatch)?;
        let identity = self
            .interaction_identity
            .as_ref()
            .ok_or(DisplayRuntimeError::SessionUnauthenticated)?;
        if identity.wayland_session_ref() != session_ref
            || identity.wayland_session_uid() != session_uid
            || identity.subject_ref() != &expected_guest
            || spec.guest_ref() != identity.subject_ref()
            || spec.host_ref() != identity.host_execution_ref()
            || spec.user_ref() != identity.user_ref()
        {
            return Err(DisplayRuntimeError::SessionMismatch);
        }
        self.reconcile_display_request(DisplayReconcileRequest { spec: spec.clone() })
    }

    /// Finalize display first, then drain clipboard/notification effects, and
    /// only then release the bus ingress.
    pub fn finalize(
        &mut self,
        grace: d2b_provider_display_wayland::GraceState,
    ) -> Result<d2b_provider_display_wayland::FinalizationReport, InteractionFinalizeError> {
        let (report, mut failure) = match self.display.as_mut() {
            Some(display) => match display.finalize(grace) {
                Ok(report) => {
                    let remove_runtime = report.decision.remove_finalizer;
                    if remove_runtime {
                        self.display = None;
                    }
                    (report, None)
                }
                Err(error) => (
                    d2b_provider_display_wayland::FinalizationReport::empty(),
                    Some(InteractionFinalizeError::Display(error)),
                ),
            },
            None => (
                d2b_provider_display_wayland::FinalizationReport::empty(),
                None,
            ),
        };
        if let Some(clipboard) = self.clipboard.as_mut()
            && let Err(error) = clipboard.finalize(std::iter::empty())
        {
            failure.get_or_insert(InteractionFinalizeError::Clipboard(error));
        }
        if let Some(notification) = self.notification.as_mut()
            && let Err(error) = notification.finalize()
        {
            failure.get_or_insert(InteractionFinalizeError::Notification(error));
        }
        if failure.is_none() {
            self.pending_picker_receipts.clear();
            self.pending_guest_selection_events.clear();
            self.sessions.clear();
        }
        failure.map_or(Ok(report), Err)
    }

    /// Finalize all runtimes and explicitly revoke every registered ingress.
    ///
    /// The synchronous [`Self::finalize`] method remains available for
    /// bounded unit callers.  Production shutdown uses this async form so
    /// bus cancellation and response tasks are joined before authority is
    /// released.
    pub async fn finalize_async(
        &mut self,
        grace: d2b_provider_display_wayland::GraceState,
    ) -> Result<d2b_provider_display_wayland::FinalizationReport, InteractionFinalizeError> {
        let (report, mut failure) = match self.display.as_mut() {
            Some(display) => match display.finalize(grace) {
                Ok(report) => {
                    let remove_runtime = report.decision.remove_finalizer;
                    if remove_runtime {
                        self.display = None;
                    }
                    (report, None)
                }
                Err(error) => (
                    d2b_provider_display_wayland::FinalizationReport::empty(),
                    Some(InteractionFinalizeError::Display(error)),
                ),
            },
            None => (
                d2b_provider_display_wayland::FinalizationReport::empty(),
                None,
            ),
        };
        if let Some(clipboard) = self.clipboard.as_mut()
            && let Err(error) = clipboard.finalize(std::iter::empty())
        {
            failure.get_or_insert(InteractionFinalizeError::Clipboard(error));
        }
        if let Some(notification) = self.notification.as_mut()
            && let Err(error) = notification.finalize()
        {
            failure.get_or_insert(InteractionFinalizeError::Notification(error));
        }
        if failure.is_none() {
            let services = self.sessions.keys().cloned().collect::<Vec<_>>();
            for service in services {
                let revoked = if let Some(session) = self.sessions.get_mut(&service) {
                    self.registrar
                        .revoke_in_place(&mut session.ingress)
                        .await
                        .is_ok()
                } else {
                    true
                };
                if !revoked {
                    failure.get_or_insert(InteractionFinalizeError::Registration);
                    break;
                }
                self.sessions.remove(&service);
            }
        }
        if failure.is_none() {
            self.pending_picker_receipts.clear();
            self.pending_guest_selection_events.clear();
        }
        failure.map_or(Ok(report), Err)
    }

    async fn remove_session(&mut self, session_key: &str) -> Result<(), String> {
        let Some(session) = self.sessions.get(session_key) else {
            return Ok(());
        };
        let service = session.service().as_str().to_owned();
        let last_for_service = self
            .sessions
            .values()
            .filter(|candidate| candidate.service().as_str() == service)
            .count()
            == 1;
        let last_clipboard_family = service.starts_with("d2b.clipboard.")
            && self
                .sessions
                .values()
                .filter(|candidate| candidate.service().as_str().starts_with("d2b.clipboard."))
                .count()
                == 1;
        let session = self
            .sessions
            .get_mut(session_key)
            .ok_or_else(|| "interaction-session-unavailable".to_owned())?;
        self.registrar
            .revoke_in_place(&mut session.ingress)
            .await
            .map_err(|_| "interaction-session-revocation-failed".to_owned())?;
        self.sessions.remove(session_key);
        let service_cleanup = match service.as_str() {
            d2b_provider_display_wayland::SERVICE_PACKAGE if last_for_service => {
                if let Some(display) = self.display.as_mut() {
                    let report = display
                        .finalize(d2b_provider_display_wayland::GraceState::Expired)
                        .map_err(|_| "display-finalization-failed".to_owned())?;
                    if report.decision.remove_finalizer {
                        self.display = None;
                    }
                } else {
                    self.display_resource_evidence = None;
                }
                self.display_resource_evidence = None;
                self.clipboard.as_mut().map_or(Ok(()), |clipboard| {
                    clipboard
                        .reconcile_display(None)
                        .map_err(|_| "clipboard-disconnect-reconcile-failed".to_owned())
                })?;
                self.notification.as_mut().map_or(Ok(()), |notification| {
                    notification
                        .reconcile_daemon_routes(None, &[])
                        .map(|_| ())
                        .map_err(|_| "notification-disconnect-reconcile-failed".to_owned())
                })
            }
            d2b_provider_display_wayland::SERVICE_PACKAGE => self
                .reconcile_dependents()
                .map_err(|_| "display-disconnect-reconcile-failed".to_owned()),
            d2b_provider_clipboard_wayland::MANAGEMENT_SERVICE
            | d2b_provider_clipboard_wayland::BRIDGE_SERVICE
            | d2b_provider_clipboard_wayland::PICKER_SERVICE
                if last_clipboard_family =>
            {
                self.clipboard.as_mut().map_or(Ok(()), |clipboard| {
                    clipboard
                        .finalize(std::iter::empty())
                        .map(|_| ())
                        .map_err(|_| "clipboard-finalization-failed".to_owned())
                })
            }
            d2b_provider_clipboard_wayland::MANAGEMENT_SERVICE
            | d2b_provider_clipboard_wayland::BRIDGE_SERVICE
            | d2b_provider_clipboard_wayland::PICKER_SERVICE => self
                .reconcile_dependents()
                .map_err(|_| "clipboard-disconnect-reconcile-failed".to_owned()),
            d2b_provider_notification_desktop::SERVICE_PACKAGE if last_for_service => {
                self.notification.as_mut().map_or(Ok(()), |notification| {
                    notification
                        .finalize()
                        .map(|_| ())
                        .map_err(|_| "notification-finalization-failed".to_owned())
                })
            }
            d2b_provider_notification_desktop::SERVICE_PACKAGE => self
                .reconcile_dependents()
                .map_err(|_| "notification-disconnect-reconcile-failed".to_owned()),
            _ => Ok(()),
        };
        service_cleanup.map_err(|_| "interaction-provider-cleanup-failed".to_owned())?;
        if last_clipboard_family {
            self.pending_picker_receipts.clear();
            self.pending_guest_selection_events.clear();
        }
        Ok(())
    }
}

/// Errors while propagating an authenticated display dependency to U22/U24.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InteractionDependencyError {
    /// No authenticated ComponentSession route was retained.
    SessionUnauthenticated,
    /// The display route did not satisfy the dependent Provider contract.
    DisplayUnavailable,
    /// Clipboard runtime reconciliation failed.
    Clipboard(d2b_provider_clipboard_wayland::ClipboardRuntimeError),
    /// Clipboard runtime could not be constructed.
    ClipboardUnavailable,
    /// Notification runtime admission or reconciliation failed.
    Notification(d2b_provider_notification_desktop::NotificationRuntimeError),
    /// Notification runtime could not be constructed.
    NotificationUnavailable,
}

/// Closed cleanup errors for the daemon composition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InteractionFinalizeError {
    /// Display runtime cleanup failed.
    Display(DisplayRuntimeError),
    /// Clipboard drain or authority release failed.
    Clipboard(d2b_provider_clipboard_wayland::ClipboardRuntimeError),
    /// Notification source/authority cleanup failed.
    Notification(d2b_provider_notification_desktop::NotificationRuntimeError),
    /// Bus ingress revocation failed.
    Registration,
    /// Finalization was requested before a display runtime was installed.
    NoDisplayRuntime,
}

impl core::fmt::Display for InteractionFinalizeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Display(_) => "interaction-display-finalization-failed",
            Self::Clipboard(_) => "interaction-clipboard-finalization-failed",
            Self::Notification(_) => "interaction-notification-finalization-failed",
            Self::Registration => "interaction-session-revocation-failed",
            Self::NoDisplayRuntime => "interaction-display-runtime-missing",
        })
    }
}

impl std::error::Error for InteractionFinalizeError {}

/// Process effect port used by the interaction composition when all display
/// children are reconciled through durable Process resources.
///
/// The interaction Provider never owns a launch-capable process adapter.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct UnavailableProcessEffectPort;

impl ProcessLaunchEffectPort for UnavailableProcessEffectPort {
    fn launch(
        &self,
        _ticket: &d2b_process_conformance::LaunchTicket,
    ) -> impl Future<Output = Result<LaunchedProcess, ProcessConformanceError>> + Send {
        async { Err(ProcessConformanceError::LaunchFailed) }
    }

    fn observe(
        &self,
        _ticket: &d2b_process_conformance::LaunchTicket,
    ) -> impl Future<Output = Result<Option<AdoptionCandidate>, ProcessConformanceError>> + Send
    {
        async { Err(ProcessConformanceError::LaunchFailed) }
    }

    fn open_pidfd(
        &self,
        _candidate: &AdoptionCandidate,
    ) -> impl Future<Output = Result<PidfdEvidence, ProcessConformanceError>> + Send {
        async { Err(ProcessConformanceError::PidfdUnavailable) }
    }

    fn stop(
        &self,
        _identity: &ProcessIdentityDigest,
        _class: d2b_process_conformance::StopClass,
    ) -> impl Future<Output = Result<(), ProcessConformanceError>> + Send {
        async { Err(ProcessConformanceError::StopUnavailable) }
    }
}

/// One daemon-owned effect adapter for display workers.
///
/// Production reconciliation materializes and observes the Host and Guest
/// Process children through the Resource API. The process effect port is
/// retained only for hermetic tests; no Provider receives a launch-capable
/// adapter in the production composition.
pub struct DisplaySupervisorEffects<S> {
    _supervisor: S,
    resource_client: Option<Arc<ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>>>,
    resource_zone: Option<ZoneId>,
    wayland_session_ref: Option<ResourceRef>,
    wayland_session_uid: Option<ResourceUid>,
    resource_processes: BTreeMap<DisplayProcessRole, DurableDisplayProcess>,
    resource_endpoints: BTreeMap<DisplayProcessRole, DurableDisplayEndpoint>,
    guest_subject: Option<ResourceRef>,
    host_execution_ref: Option<ResourceRef>,
    #[cfg(test)]
    identities: BTreeMap<DisplayProcessRole, LiveWorker>,
    #[cfg(test)]
    tickets: BTreeMap<DisplayProcessRole, ProcessLaunchTicket>,
    consumed_grants: BTreeMap<[u8; 32], u64>,
    last_failures: BTreeMap<DisplayProcessRole, u64>,
    session_digest: [u8; 32],
    reconnect_generation: u64,
    policy_generation: u64,
    teardown_generation: u64,
}

#[cfg(test)]
#[derive(Clone, Copy)]
struct LiveWorker {
    identity: ProcessIdentityDigest,
    policy_generation: u64,
    teardown_generation: u64,
    session_digest: [u8; 32],
}

#[derive(Clone)]
struct DurableDisplayProcess {
    resource_ref: ResourceRef,
    resource_uid: ResourceUid,
    generation: u64,
    revision: u64,
    restart_count: u64,
    deletion_requested: bool,
}

#[derive(Clone)]
struct DurableDisplayEndpoint {
    resource_ref: ResourceRef,
    resource_uid: ResourceUid,
    revision: u64,
    generation: u64,
    deletion_requested: bool,
}

impl<S> DisplaySupervisorEffects<S>
where
    S: ProcessLaunchEffectPort + Clone + Send + Sync + 'static,
{
    /// Construct a test-only display effect adapter.
    #[cfg(test)]
    pub fn new(supervisor: S) -> Self {
        Self::new_base(supervisor)
    }

    fn new_base(supervisor: S) -> Self {
        Self {
            _supervisor: supervisor,
            resource_client: None,
            resource_zone: None,
            wayland_session_ref: None,
            wayland_session_uid: None,
            resource_processes: BTreeMap::new(),
            resource_endpoints: BTreeMap::new(),
            guest_subject: None,
            host_execution_ref: None,
            #[cfg(test)]
            identities: BTreeMap::new(),
            #[cfg(test)]
            tickets: BTreeMap::new(),
            consumed_grants: BTreeMap::new(),
            last_failures: BTreeMap::new(),
            session_digest: [0; 32],
            reconnect_generation: 0,
            policy_generation: 0,
            teardown_generation: 0,
        }
    }

    /// Construct an effect adapter whose worker lifecycle is owned by the
    /// generic durable Process runtime.
    pub fn new_with_resource_client(
        supervisor: S,
        resource_client: Arc<ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>>,
        zone: ZoneId,
        wayland_session_ref: ResourceRef,
        wayland_session_uid: ResourceUid,
    ) -> Self {
        let mut effects = Self::new_base(supervisor);
        effects.resource_client = Some(resource_client);
        effects.resource_zone = Some(zone);
        effects.wayland_session_ref = Some(wayland_session_ref);
        effects.wayland_session_uid = Some(wayland_session_uid);
        effects
    }

    /// Return the number of locally tracked display workers.
    pub fn live_worker_count(&self) -> usize {
        #[cfg(test)]
        {
            return self.identities.len();
        }
        #[cfg(not(test))]
        {
            self.resource_processes.len()
        }
    }

    fn uses_durable_processes(&self) -> bool {
        self.resource_client.is_some()
            && self.resource_zone.is_some()
            && self.wayland_session_ref.is_some()
            && self.wayland_session_uid.is_some()
    }

    fn durable_process_ref(
        &self,
        role: DisplayProcessRole,
    ) -> Result<ResourceRef, WorkerEffectError> {
        let name = match role {
            DisplayProcessRole::HostProxy => "display-host-proxy",
            DisplayProcessRole::GuestFrontend => "display-guest-frontend",
        };
        let rendered = format!(
            "Process/{name}-{}",
            durable_display_suffix(
                self.wayland_session_uid
                    .as_ref()
                    .ok_or(WorkerEffectError::LaunchRejected)?,
                role,
            )
        );
        ResourceRef::parse(&rendered).map_err(|_| WorkerEffectError::LaunchRejected)
    }

    fn durable_endpoint_ref(
        &self,
        role: DisplayProcessRole,
    ) -> Result<ResourceRef, WorkerEffectError> {
        let rendered = format!(
            "Endpoint/display-endpoint-{}",
            durable_display_suffix(
                self.wayland_session_uid
                    .as_ref()
                    .ok_or(WorkerEffectError::LaunchRejected)?,
                role,
            )
        );
        ResourceRef::parse(&rendered).map_err(|_| WorkerEffectError::LaunchRejected)
    }

    fn durable_endpoint_payload(
        &self,
        role: DisplayProcessRole,
        producer_ref: &ResourceRef,
        generation: u64,
    ) -> Result<Vec<u8>, WorkerEffectError> {
        let zone = self
            .resource_zone
            .as_ref()
            .ok_or(WorkerEffectError::LaunchRejected)?;
        let owner_ref = self
            .wayland_session_ref
            .as_ref()
            .ok_or(WorkerEffectError::LaunchRejected)?;
        let provider_ref = ResourceRef::parse("Provider/display-wayland")
            .map_err(|_| WorkerEffectError::LaunchRejected)?;
        let (endpoint_class, transport, purpose, fingerprint) = match role {
            DisplayProcessRole::HostProxy => (
                EndpointClass::Data,
                EndpointTransport::FdAttachment,
                "wayland-cross-domain",
                "display-wayland-data-v3",
            ),
            DisplayProcessRole::GuestFrontend => (
                EndpointClass::Transport,
                EndpointTransport::Vsock,
                "guest-cross-domain",
                "guest-frontend-v3",
            ),
        };
        let endpoint_spec = EndpointSpec::new(
            provider_ref,
            producer_ref.clone(),
            endpoint_class,
            transport,
            BoundedToken::parse(purpose).map_err(|_| WorkerEffectError::LaunchRejected)?,
            Some(BoundedText::parse(fingerprint).map_err(|_| WorkerEffectError::LaunchRejected)?),
            EndpointLocality::CrossDomain,
            EndpointVisibility::Zone,
            d2b_contracts_resource::v3::endpoint::EndpointAttachmentPolicy::new(
                matches!(role, DisplayProcessRole::HostProxy),
                u16::from(matches!(role, DisplayProcessRole::HostProxy)),
            )
            .map_err(|_| WorkerEffectError::LaunchRejected)?,
            EndpointConsumerPolicy::new(Vec::new(), Vec::new(), vec![EndpointOperation::Resolve])
                .map_err(|_| WorkerEffectError::LaunchRejected)?,
            EndpointLifecyclePolicy::RecycleWithProducer,
        )
        .map_err(|_| WorkerEffectError::LaunchRejected)?;
        let endpoint_ref = self.durable_endpoint_ref(role)?;
        let payload = serde_json::json!({
        "apiVersion": "resources.d2bus.org/v3",
        "type": "Endpoint",
        "metadata": {
            "name": endpoint_ref.name().as_str(),
            "zone": zone.as_str(),
            "ownerRef": owner_ref.to_canonical_string(),
            "finalizers": [],
            "deletionRequestedAt": null,
            "createdAt": "1970-01-01T00:00:00.000Z",
            "updatedAt": "1970-01-01T00:00:00.000Z",
            "managedBy": "controller",
            "generation": generation.max(1),
            "revision": 1
        },
        "spec": endpoint_spec,
        "status": {
            "completedAt": null,
            "conditions": [],
            "lastReconciledAt": null,
            "observedGeneration": 0,
            "outcome": null,
            "phase": "Pending",
            "resource": {
                "readiness": "Pending",
                "observedProducerGeneration": 0,
                "observedResourceGeneration": generation.max(1),
                "endpointGeneration": 0,
                "connectionAvailability": "unavailable",
                "leaseAvailability": "lease-required"
            },
            "startedAt": null,
            "update": {
                "dependencies": {"count": 0, "refs": []},
                "disruption": "None",
                "lastAssessedAt": null,
                "observedGeneration": 0,
                "operationId": null,
                "owned": {"count": 0, "refs": []},
                "preserveState": true,
                "reasons": [],
                "state": "Unknown",
                "targetGeneration": generation.max(1)
            }
        }
        });
        let bytes = serde_json::to_vec(&payload).map_err(|_| WorkerEffectError::LaunchRejected)?;
        Ok(CanonicalJsonValue::parse(&bytes)
            .map_err(|_| WorkerEffectError::LaunchRejected)?
            .to_canonical_bytes())
    }

    fn durable_process_payload(
        &self,
        role: DisplayProcessRole,
        binding: &DisplayLaunchBinding,
    ) -> Result<Vec<u8>, WorkerEffectError> {
        self.durable_process_payload_for_generation(role, binding.policy_generation())
    }

    fn durable_process_payload_for_generation(
        &self,
        role: DisplayProcessRole,
        process_generation: u64,
    ) -> Result<Vec<u8>, WorkerEffectError> {
        let execution_ref = match role {
            DisplayProcessRole::HostProxy => self
                .host_execution_ref
                .as_ref()
                .ok_or(WorkerEffectError::LaunchRejected)?,
            DisplayProcessRole::GuestFrontend => self
                .guest_subject
                .as_ref()
                .ok_or(WorkerEffectError::LaunchRejected)?,
        }
        .clone();
        let template = match role {
            DisplayProcessRole::HostProxy => "wayland-proxy-worker",
            DisplayProcessRole::GuestFrontend => "wayland-frontend-worker",
        };
        let provider = match role {
            DisplayProcessRole::HostProxy => "Provider/system-minijail",
            DisplayProcessRole::GuestFrontend => "Provider/system-systemd",
        };
        let process = ProcessSpec::minimal(
            ExecutionSpec::minimal(
                execution_ref,
                ProcessClass::Worker,
                BoundedToken::parse(template).map_err(|_| WorkerEffectError::LaunchRejected)?,
            )
            .map_err(|_| WorkerEffectError::LaunchRejected)?,
        );
        let mut spec =
            serde_json::to_value(process).map_err(|_| WorkerEffectError::LaunchRejected)?;
        let spec_object = spec
            .as_object_mut()
            .ok_or(WorkerEffectError::LaunchRejected)?;
        spec_object.insert("providerRef".to_owned(), serde_json::json!(provider));
        spec_object.insert(
            "updatePolicy".to_owned(),
            serde_json::json!({
                "disruptive": "manual",
                "nonDisruptive": "automatic"
            }),
        );
        let process_ref = self.durable_process_ref(role)?;
        let owner_ref = self
            .wayland_session_ref
            .as_ref()
            .ok_or(WorkerEffectError::LaunchRejected)?;
        let generation = process_generation.max(1);
        let payload = serde_json::json!({
            "apiVersion": "resources.d2bus.org/v3",
            "type": "Process",
            "metadata": {
                "name": process_ref.name().as_str(),
                "zone": self.resource_zone.as_ref()
                    .ok_or(WorkerEffectError::LaunchRejected)?.as_str(),
                "ownerRef": owner_ref.to_canonical_string(),
                "annotations": {
                    PROCESS_RESTART_ANNOTATION: generation.to_string()
                },
                "finalizers": [],
                "deletionRequestedAt": null,
                "createdAt": "1970-01-01T00:00:00.000Z",
                "updatedAt": "1970-01-01T00:00:00.000Z",
                "managedBy": "controller",
                "generation": generation,
                "revision": 1
            },
            "spec": spec,
            "status": {
                "completedAt": null,
                "conditions": [],
                "lastReconciledAt": null,
                "observedGeneration": 0,
                "outcome": null,
                "phase": "Pending",
                "resource": {},
                "startedAt": null,
                "update": {
                    "dependencies": {"count": 0, "refs": []},
                    "disruption": "None",
                    "lastAssessedAt": null,
                    "observedGeneration": 0,
                    "operationId": null,
                    "owned": {"count": 0, "refs": []},
                    "preserveState": true,
                    "reasons": [],
                    "state": "Unknown",
                    "targetGeneration": generation
                }
            }
        });
        let bytes = serde_json::to_vec(&payload).map_err(|_| WorkerEffectError::LaunchRejected)?;
        CanonicalJsonValue::parse(&bytes)
            .map(|value| value.to_canonical_bytes())
            .map_err(|_| WorkerEffectError::LaunchRejected)
    }

    fn durable_state(
        &self,
        role: DisplayProcessRole,
    ) -> Result<Option<(WorkerState, DurableDisplayProcess)>, WorkerEffectError> {
        let Some(client) = self.resource_client.clone() else {
            return Ok(None);
        };
        let zone = self
            .resource_zone
            .clone()
            .ok_or(WorkerEffectError::WorkerUnavailable)?;
        let process_ref = self.durable_process_ref(role)?;
        let owner_ref = self
            .wayland_session_ref
            .clone()
            .ok_or(WorkerEffectError::WorkerUnavailable)?;
        let owner_uid = self
            .wayland_session_uid
            .clone()
            .ok_or(WorkerEffectError::WorkerUnavailable)?;
        let expected_execution_ref = match role {
            DisplayProcessRole::HostProxy => self
                .host_execution_ref
                .clone()
                .ok_or(WorkerEffectError::WorkerUnavailable)?,
            DisplayProcessRole::GuestFrontend => self
                .guest_subject
                .clone()
                .ok_or(WorkerEffectError::WorkerUnavailable)?,
        };
        let expected_generation = self.policy_generation.max(1);
        run_effect(move || async move {
            let response = client
                .get(resource_get_request(
                    &zone,
                    &process_ref,
                    "display-process-get",
                ))
                .await;
            if let Some(error) = response.error.as_ref() {
                if error.kind.enum_value_or_default()
                    == d2b_contracts_resource::resource_proto::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_NOT_FOUND
                {
                    return Ok(None);
                }
                return Err(WorkerEffectError::WorkerUnavailable);
            }
            let resource = response
                .resource
                .0
                .ok_or(WorkerEffectError::WorkerUnavailable)?;
            let envelope = ResourceEnvelope::from_json(&resource.canonical_json)
                .map_err(|_| WorkerEffectError::WorkerUnavailable)?;
            let owner_response = client
                .get(resource_get_request(&zone, &owner_ref, "display-owner-get"))
                .await;
            let owner_resource = owner_response
                .resource
                .0
                .ok_or(WorkerEffectError::WorkerUnavailable)?;
            if owner_resource.identity.uid.as_deref() != Some(owner_uid.as_str()) {
                return Err(WorkerEffectError::LaunchRejected);
            }
            let state = project_process_state(&envelope)?;
            if !durable_envelope_matches(
                &envelope,
                role,
                &process_ref,
                &zone,
                &owner_ref,
                &owner_uid,
                &expected_execution_ref,
            ) {
                return Err(WorkerEffectError::LaunchRejected);
            }
            let state = if display_policy_generation(&resource.canonical_json)
                == Some(expected_generation)
            {
                state
            } else {
                WorkerState::Starting
            };
            let record = DurableDisplayProcess {
                resource_ref: process_ref,
                resource_uid: envelope.metadata().uid().clone(),
                generation: envelope.metadata().generation().get(),
                revision: envelope.metadata().revision().get(),
                restart_count: process_restart_count(&resource.canonical_json),
                deletion_requested: metadata_deletion_requested(&resource.canonical_json),
            };
            Ok(Some((state, record)))
        })
    }

    fn ensure_durable_endpoint(
        &mut self,
        role: DisplayProcessRole,
        producer: &DurableDisplayProcess,
    ) -> Result<DurableDisplayEndpoint, WorkerEffectError> {
        let client = self
            .resource_client
            .clone()
            .ok_or(WorkerEffectError::LaunchRejected)?;
        let zone = self
            .resource_zone
            .clone()
            .ok_or(WorkerEffectError::LaunchRejected)?;
        let endpoint_ref = self.durable_endpoint_ref(role)?;
        let payload =
            self.durable_endpoint_payload(role, &producer.resource_ref, producer.generation)?;
        let owner_ref = self
            .wayland_session_ref
            .clone()
            .ok_or(WorkerEffectError::LaunchRejected)?;
        let owner_uid = self
            .wayland_session_uid
            .clone()
            .ok_or(WorkerEffectError::LaunchRejected)?;
        let producer_ref = producer.resource_ref.clone();
        let result = run_effect(move || async move {
            let owner = client
                .get(resource_get_request(
                    &zone,
                    &owner_ref,
                    "display-endpoint-owner-get",
                ))
                .await;
            let owner_resource = owner
                .resource
                .0
                .ok_or(WorkerEffectError::WorkerUnavailable)?;
            if owner_resource.identity.uid.as_deref() != Some(owner_uid.as_str()) {
                return Err(WorkerEffectError::LaunchRejected);
            }
            let get = client
                .get(resource_get_request(
                    &zone,
                    &endpoint_ref,
                    "display-endpoint-get",
                ))
                .await;
            if let Some(resource) = get.resource.0 {
                return endpoint_record_from_response(
                    endpoint_ref,
                    *resource,
                    role,
                    &zone,
                    &owner_ref,
                    &owner_uid,
                    &producer_ref,
                );
            }
            if let Some(error) = get.error.as_ref()
                && error.kind.enum_value_or_default()
                    != d2b_contracts_resource::resource_proto::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_NOT_FOUND
            {
                return Err(WorkerEffectError::WorkerUnavailable);
            }
            let target = resource_wire_identity(&zone, &endpoint_ref, None, None);
            let owner = resource_wire_identity(&zone, &owner_ref, Some(&owner_uid), None);
            let mut body = wire::ResourceEnvelopeBytes::new();
            body.identity = protobuf::MessageField::some(target.clone());
            body.canonical_json = payload.clone();
            body.payload_digest = canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &payload);
            let mut precondition = wire::Precondition::new();
            precondition.kind = protobuf::EnumOrUnknown::new(
                wire::PreconditionKind::PRECONDITION_KIND_CREATE_ABSENT,
            );
            let mut mutation = wire::Mutation::new();
            mutation.kind = protobuf::EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_CREATE);
            mutation.target = protobuf::MessageField::some(target);
            mutation.precondition = protobuf::MessageField::some(precondition);
            mutation.resource = protobuf::MessageField::some(body);
            mutation.owner = protobuf::MessageField::some(owner);
            let mut request = wire::CreateRequest::new();
            request.meta = protobuf::MessageField::some(resource_request_meta(
                &resource_operation_id_with_key(
                    "display-endpoint-create",
                    &zone,
                    &endpoint_ref,
                    &payload,
                ),
            ));
            request.mutation = protobuf::MessageField::some(mutation);
            let created = client.create(request).await;
            if let Some(resource) = created.resource.0 {
                return endpoint_record_from_response(
                    endpoint_ref,
                    *resource,
                    role,
                    &zone,
                    &owner_ref,
                    &owner_uid,
                    &producer_ref,
                );
            }
            if created.error.is_some() {
                let adopted = client
                    .get(resource_get_request(
                        &zone,
                        &endpoint_ref,
                        "display-endpoint-adopt-get",
                    ))
                    .await;
                if let Some(resource) = adopted.resource.0 {
                    return endpoint_record_from_response(
                        endpoint_ref,
                        *resource,
                        role,
                        &zone,
                        &owner_ref,
                        &owner_uid,
                        &producer_ref,
                    );
                }
            }
            Err(WorkerEffectError::WorkerUnavailable)
        })?;
        self.resource_endpoints.insert(role, result.clone());
        Ok(result)
    }

    fn ensure_wayland_session_finalizer(&self) -> Result<(), WorkerEffectError> {
        let client = self
            .resource_client
            .clone()
            .ok_or(WorkerEffectError::LaunchRejected)?;
        let zone = self
            .resource_zone
            .clone()
            .ok_or(WorkerEffectError::LaunchRejected)?;
        let session_ref = self
            .wayland_session_ref
            .clone()
            .ok_or(WorkerEffectError::LaunchRejected)?;
        run_effect(move || async move {
            let response = client
                .get(resource_get_request(
                    &zone,
                    &session_ref,
                    "display-session-finalizer-get",
                ))
                .await;
            let resource = response
                .resource
                .0
                .ok_or(WorkerEffectError::WorkerUnavailable)?;
            let envelope = ResourceEnvelope::from_json(&resource.canonical_json)
                .map_err(|_| WorkerEffectError::WorkerUnavailable)?;
            let has_finalizer = CanonicalJsonValue::parse(&resource.canonical_json)
                .ok()
                .and_then(|value| match value {
                    CanonicalJsonValue::Object(root) => root
                        .get("metadata")
                        .and_then(CanonicalJsonValue::as_object)
                        .and_then(|metadata| match metadata.get("finalizers") {
                            Some(CanonicalJsonValue::Array(finalizers)) => Some(finalizers),
                            _ => None,
                        })
                        .map(|finalizers| {
                            finalizers.iter().any(|finalizer| {
                                matches!(
                                    finalizer,
                                    CanonicalJsonValue::String(value)
                                        if value == d2b_provider_display_wayland::FINALIZER
                                )
                            })
                        }),
                    _ => None,
                })
                .ok_or(WorkerEffectError::WorkerUnavailable)?;
            if has_finalizer {
                return Ok(());
            }
            let mut mutation = wire::Mutation::new();
            mutation.kind =
                protobuf::EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_UPDATE_FINALIZERS);
            mutation.target = protobuf::MessageField::some(resource_wire_identity(
                &zone,
                &session_ref,
                Some(envelope.metadata().uid()),
                Some(envelope.metadata().revision().get()),
            ));
            let mut precondition = wire::Precondition::new();
            precondition.kind = protobuf::EnumOrUnknown::new(
                wire::PreconditionKind::PRECONDITION_KIND_EXACT_REVISION,
            );
            precondition.expected_revision = Some(envelope.metadata().revision().get());
            precondition.expected_uid = Some(envelope.metadata().uid().as_str().to_owned());
            mutation.precondition = protobuf::MessageField::some(precondition);
            mutation
                .add_finalizers
                .push(d2b_provider_display_wayland::FINALIZER.to_owned());
            let mut request = wire::UpdateFinalizersRequest::new();
            request.meta = protobuf::MessageField::some(resource_request_meta(
                &resource_operation_id_with_key(
                    "display-session-finalizer-add",
                    &zone,
                    &session_ref,
                    &resource.canonical_json,
                ),
            ));
            request.mutation = protobuf::MessageField::some(mutation);
            if client.update_finalizers(request).await.error.is_some() {
                return Err(WorkerEffectError::WorkerUnavailable);
            }
            Ok(())
        })
        .map_err(|_| WorkerEffectError::WorkerUnavailable)
    }

    fn update_durable_endpoint_status(
        &mut self,
        role: DisplayProcessRole,
        producer: &DurableDisplayProcess,
        state: WorkerState,
    ) -> Result<(), WorkerEffectError> {
        let endpoint = self.ensure_durable_endpoint(role, producer)?;
        if endpoint.deletion_requested {
            return Err(WorkerEffectError::CleanupIncomplete);
        }
        let client = self
            .resource_client
            .clone()
            .ok_or(WorkerEffectError::WorkerUnavailable)?;
        let zone = self
            .resource_zone
            .clone()
            .ok_or(WorkerEffectError::WorkerUnavailable)?;
        let endpoint_ref = endpoint.resource_ref.clone();
        let endpoint_uid = endpoint.resource_uid.clone();
        let status_endpoint_ref = endpoint_ref.clone();
        let status_endpoint_uid = endpoint_uid.clone();
        let endpoint_revision = endpoint.revision;
        let endpoint_generation = producer.restart_count.saturating_add(1).max(1);
        let desired_phase = match state {
            WorkerState::Ready { .. } => "Ready",
            WorkerState::Failed { .. } => "Failed",
            WorkerState::Terminal { deleted: true } => "Deleted",
            WorkerState::Terminal { deleted: false } => "Succeeded",
            WorkerState::Starting => "Pending",
        };
        let readiness = match state {
            WorkerState::Ready { .. } => "Ready",
            WorkerState::Failed { .. } => "Failed",
            WorkerState::Terminal { deleted: true } => "Deleted",
            WorkerState::Terminal { deleted: false } => "Unavailable",
            WorkerState::Starting => "Pending",
        };
        let connection = matches!(state, WorkerState::Ready { .. });
        let producer_ref = producer.resource_ref.clone();
        let producer_generation = producer.generation;
        let owner_ref = self
            .wayland_session_ref
            .clone()
            .ok_or(WorkerEffectError::WorkerUnavailable)?;
        let owner_uid = self
            .wayland_session_uid
            .clone()
            .ok_or(WorkerEffectError::WorkerUnavailable)?;
        let updated = run_effect(move || async move {
            let current = client
                .get(resource_get_request(
                    &zone,
                    &status_endpoint_ref,
                    "display-endpoint-status-get",
                ))
                .await;
            let current_resource = current
                .resource
                .0
                .ok_or(WorkerEffectError::WorkerUnavailable)?;
            let current_envelope = ResourceEnvelope::from_json(&current_resource.canonical_json)
                .map_err(|_| WorkerEffectError::WorkerUnavailable)?;
            if !durable_endpoint_matches(
                &current_envelope,
                role,
                &status_endpoint_ref,
                &zone,
                &owner_ref,
                &owner_uid,
                &producer_ref,
            ) {
                return Err(WorkerEffectError::LaunchRejected);
            }
            let mut value = CanonicalJsonValue::parse(&current_resource.canonical_json)
                .map_err(|_| WorkerEffectError::WorkerUnavailable)?;
            let CanonicalJsonValue::Object(root) = &mut value else {
                return Err(WorkerEffectError::WorkerUnavailable);
            };
            let Some(CanonicalJsonValue::Object(status)) = root.get_mut("status") else {
                return Err(WorkerEffectError::WorkerUnavailable);
            };
            let current_phase = status.get("phase").cloned();
            let current_generation = status
                .get("resource")
                .and_then(|resource| match resource {
                    CanonicalJsonValue::Object(resource_status) => {
                        resource_status.get("endpointGeneration")
                    }
                    _ => None,
                })
                .cloned();
            if matches!(current_phase, Some(CanonicalJsonValue::String(value)) if value == desired_phase)
                && matches!(current_generation, Some(CanonicalJsonValue::Integer(value)) if value == endpoint_generation as i64)
            {
                return Ok(current_resource);
            }
            status.insert(
                "phase".to_owned(),
                CanonicalJsonValue::String(desired_phase.to_owned()),
            );
            status.insert(
                "observedGeneration".to_owned(),
                CanonicalJsonValue::Integer(current_envelope.metadata().generation().get() as i64),
            );
            {
                let Some(CanonicalJsonValue::Object(resource_status)) = status.get_mut("resource")
                else {
                    return Err(WorkerEffectError::WorkerUnavailable);
                };
                resource_status.insert(
                    "readiness".to_owned(),
                    CanonicalJsonValue::String(readiness.to_owned()),
                );
                resource_status.insert(
                    "observedProducerGeneration".to_owned(),
                    CanonicalJsonValue::Integer(producer_generation as i64),
                );
                resource_status.insert(
                    "observedResourceGeneration".to_owned(),
                    CanonicalJsonValue::Integer(
                        current_envelope.metadata().generation().get() as i64
                    ),
                );
                resource_status.insert(
                    "endpointGeneration".to_owned(),
                    CanonicalJsonValue::Integer(endpoint_generation as i64),
                );
                resource_status.insert(
                    "connectionAvailability".to_owned(),
                    CanonicalJsonValue::String(
                        if connection {
                            "available"
                        } else {
                            "unavailable"
                        }
                        .to_owned(),
                    ),
                );
            }
            if let Some(CanonicalJsonValue::Object(update)) = status.get_mut("update") {
                update.insert(
                    "observedGeneration".to_owned(),
                    CanonicalJsonValue::Integer(
                        current_envelope.metadata().generation().get() as i64
                    ),
                );
            }
            let canonical = value.to_canonical_bytes();
            let mut operation_key =
                format!("{}:{}:", status_endpoint_uid.as_str(), endpoint_revision).into_bytes();
            operation_key.extend_from_slice(&canonical);
            let operation_id = resource_operation_id_with_key(
                "display-endpoint-status",
                &zone,
                &status_endpoint_ref,
                &operation_key,
            );
            let envelope = ResourceEnvelope::from_json(&canonical)
                .map_err(|_| WorkerEffectError::WorkerUnavailable)?;
            let mut resource = wire::ResourceEnvelopeBytes::new();
            resource.identity = protobuf::MessageField::some(resource_wire_identity(
                &zone,
                &status_endpoint_ref,
                Some(&status_endpoint_uid),
                Some(endpoint_revision),
            ));
            resource.canonical_json = canonical;
            resource.payload_digest = envelope
                .digest()
                .map_err(|_| WorkerEffectError::WorkerUnavailable)?;
            let mut mutation = wire::Mutation::new();
            mutation.kind =
                protobuf::EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_UPDATE_STATUS);
            mutation.target = protobuf::MessageField::some(resource_wire_identity(
                &zone,
                &status_endpoint_ref,
                Some(&status_endpoint_uid),
                Some(endpoint_revision),
            ));
            let mut precondition = wire::Precondition::new();
            precondition.kind = protobuf::EnumOrUnknown::new(
                wire::PreconditionKind::PRECONDITION_KIND_EXACT_REVISION,
            );
            precondition.expected_revision = Some(endpoint_revision);
            precondition.expected_uid = Some(status_endpoint_uid.as_str().to_owned());
            mutation.precondition = protobuf::MessageField::some(precondition);
            mutation.resource = protobuf::MessageField::some(resource);
            mutation.owner = protobuf::MessageField::some(resource_wire_identity(
                &zone,
                &owner_ref,
                Some(&owner_uid),
                None,
            ));
            let mut request = wire::UpdateStatusRequest::new();
            request.meta = protobuf::MessageField::some(resource_request_meta(&operation_id));
            request.mutation = protobuf::MessageField::some(mutation);
            let response = client.update_status(request).await;
            if response.error.is_some() {
                return Err(WorkerEffectError::WorkerUnavailable);
            }
            Ok(response
                .resource
                .0
                .ok_or(WorkerEffectError::WorkerUnavailable)?)
        })?;
        let envelope = ResourceEnvelope::from_json(&updated.canonical_json)
            .map_err(|_| WorkerEffectError::WorkerUnavailable)?;
        let endpoint_generation = envelope
            .status()
            .resource()
            .get("endpointGeneration")
            .and_then(|value| match value {
                CanonicalJsonValue::Integer(value) => u64::try_from(*value).ok(),
                _ => None,
            })
            .unwrap_or(endpoint_generation);
        self.resource_endpoints.insert(
            role,
            DurableDisplayEndpoint {
                resource_ref: endpoint_ref,
                resource_uid: endpoint_uid,
                revision: updated
                    .identity
                    .as_ref()
                    .and_then(|identity| identity.revision)
                    .unwrap_or(endpoint_revision),
                generation: endpoint_generation,
                deletion_requested: metadata_deletion_requested(&updated.canonical_json),
            },
        );
        Ok(())
    }

    fn stop_durable_endpoint(&mut self, role: DisplayProcessRole) -> Result<(), WorkerEffectError> {
        let endpoint_ref = self.durable_endpoint_ref(role)?;
        let owner_ref = self
            .wayland_session_ref
            .clone()
            .ok_or(WorkerEffectError::CleanupIncomplete)?;
        let owner_uid = self
            .wayland_session_uid
            .clone()
            .ok_or(WorkerEffectError::CleanupIncomplete)?;
        let producer_ref = self.durable_process_ref(role)?;
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let client = self
                .resource_client
                .clone()
                .ok_or(WorkerEffectError::CleanupIncomplete)?;
            let zone = self
                .resource_zone
                .clone()
                .ok_or(WorkerEffectError::CleanupIncomplete)?;
            let current_endpoint_ref = endpoint_ref.clone();
            let current_zone = zone.clone();
            let current = run_effect(move || async move {
                Ok(client
                    .get(resource_get_request(
                        &current_zone,
                        &current_endpoint_ref,
                        "display-endpoint-delete-reread",
                    ))
                    .await)
            })?;
            if current.resource.0.is_none() {
                let is_not_found = current.error.as_ref().is_some_and(|error| {
                    error.kind.enum_value_or_default()
                        == d2b_contracts_resource::resource_proto::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_NOT_FOUND
                });
                if is_not_found {
                    self.resource_endpoints.remove(&role);
                    return Ok(());
                }
                return Err(WorkerEffectError::CleanupIncomplete);
            }
            if current.error.is_some() {
                return Err(WorkerEffectError::CleanupIncomplete);
            }
            let current_record = endpoint_record_from_response(
                endpoint_ref.clone(),
                *current
                    .resource
                    .0
                    .ok_or(WorkerEffectError::CleanupIncomplete)?,
                role,
                &zone,
                &owner_ref,
                &owner_uid,
                &producer_ref,
            )?;
            self.resource_endpoints.insert(role, current_record.clone());
            if !current_record.deletion_requested {
                let uid = current_record.resource_uid.clone();
                let revision = current_record.revision;
                let target = current_record.resource_ref.clone();
                let delete_key = format!("{}:{}", uid.as_str(), revision);
                let client = self
                    .resource_client
                    .clone()
                    .ok_or(WorkerEffectError::CleanupIncomplete)?;
                let zone = self
                    .resource_zone
                    .clone()
                    .ok_or(WorkerEffectError::CleanupIncomplete)?;
                run_effect(move || async move {
                    let mut mutation = wire::Mutation::new();
                    mutation.kind =
                        protobuf::EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_DELETE);
                    mutation.target = protobuf::MessageField::some(resource_wire_identity(
                        &zone,
                        &target,
                        Some(&uid),
                        Some(revision),
                    ));
                    let mut precondition = wire::Precondition::new();
                    precondition.kind = protobuf::EnumOrUnknown::new(
                        wire::PreconditionKind::PRECONDITION_KIND_EXACT_REVISION,
                    );
                    precondition.expected_revision = Some(revision);
                    precondition.expected_uid = Some(uid.as_str().to_owned());
                    mutation.precondition = protobuf::MessageField::some(precondition);
                    let mut request = wire::DeleteRequest::new();
                    request.meta = protobuf::MessageField::some(resource_request_meta(
                        &resource_operation_id_with_key(
                            "display-endpoint-delete",
                            &zone,
                            &target,
                            delete_key.as_bytes(),
                        ),
                    ));
                    request.mutation = protobuf::MessageField::some(mutation);
                    if client.delete(request).await.error.is_some() {
                        return Err(WorkerEffectError::CleanupIncomplete);
                    }
                    Ok(())
                })?;
                continue;
            }
            if Instant::now() >= deadline {
                return Err(WorkerEffectError::CleanupIncomplete);
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    fn ensure_durable_process(
        &mut self,
        role: DisplayProcessRole,
        binding: &DisplayLaunchBinding,
    ) -> Result<WorkerLaunchReceipt, WorkerEffectError> {
        self.ensure_wayland_session_finalizer()?;
        let client = self
            .resource_client
            .clone()
            .ok_or(WorkerEffectError::LaunchRejected)?;
        let zone = self
            .resource_zone
            .clone()
            .ok_or(WorkerEffectError::LaunchRejected)?;
        let process_ref = self.durable_process_ref(role)?;
        let payload = self.durable_process_payload(role, binding)?;
        let owner_uid = self
            .wayland_session_uid
            .clone()
            .ok_or(WorkerEffectError::LaunchRejected)?;
        let owner_ref = self
            .wayland_session_ref
            .clone()
            .ok_or(WorkerEffectError::LaunchRejected)?;
        let expected_execution_ref = match role {
            DisplayProcessRole::HostProxy => self
                .host_execution_ref
                .clone()
                .ok_or(WorkerEffectError::LaunchRejected)?,
            DisplayProcessRole::GuestFrontend => self
                .guest_subject
                .clone()
                .ok_or(WorkerEffectError::LaunchRejected)?,
        };
        let expected_generation = binding.policy_generation().max(1);
        let result = run_effect(move || async move {
            let owner = client
                .get(resource_get_request(&zone, &owner_ref, "display-owner-get"))
                .await;
            let owner_resource = owner
                .resource
                .0
                .ok_or(WorkerEffectError::WorkerUnavailable)?;
            if owner_resource.identity.uid.as_deref() != Some(owner_uid.as_str()) {
                return Err(WorkerEffectError::LaunchRejected);
            }
            let get = client
                .get(resource_get_request(
                    &zone,
                    &process_ref,
                    "display-process-get",
                ))
                .await;
            if let Some(resource) = get.resource.0 {
                let resource = *resource;
                let envelope = ResourceEnvelope::from_json(&resource.canonical_json)
                    .map_err(|_| WorkerEffectError::WorkerUnavailable)?;
                if !durable_envelope_matches(
                    &envelope,
                    role,
                    &process_ref,
                    &zone,
                    &owner_ref,
                    &owner_uid,
                    &expected_execution_ref,
                ) {
                    return Err(WorkerEffectError::LaunchRejected);
                }
                let (resource, policy_replaced) =
                    if display_policy_generation(&resource.canonical_json)
                        == Some(expected_generation)
                    {
                        (resource, false)
                    } else {
                        let canonical_json = update_display_policy_annotation(
                            &resource.canonical_json,
                            expected_generation,
                        )?;
                        let uid = envelope.metadata().uid().clone();
                        let revision = envelope.metadata().revision().get();
                        let target =
                            resource_wire_identity(&zone, &process_ref, Some(&uid), Some(revision));
                        let mut body = wire::ResourceEnvelopeBytes::new();
                        body.identity = protobuf::MessageField::some(target.clone());
                        body.canonical_json = canonical_json.clone();
                        body.payload_digest = ResourceEnvelope::from_json(&body.canonical_json)
                            .map_err(|_| WorkerEffectError::WorkerUnavailable)?
                            .digest()
                            .map_err(|_| WorkerEffectError::WorkerUnavailable)?;
                        let mut precondition = wire::Precondition::new();
                        precondition.kind = protobuf::EnumOrUnknown::new(
                            wire::PreconditionKind::PRECONDITION_KIND_EXACT_REVISION,
                        );
                        precondition.expected_revision = Some(revision);
                        precondition.expected_uid = Some(uid.as_str().to_owned());
                        let mut mutation = wire::Mutation::new();
                        mutation.kind = protobuf::EnumOrUnknown::new(
                            wire::MutationKind::MUTATION_KIND_UPDATE_METADATA,
                        );
                        mutation.target = protobuf::MessageField::some(target);
                        mutation.precondition = protobuf::MessageField::some(precondition);
                        mutation.owner = protobuf::MessageField::some(resource_wire_identity(
                            &zone,
                            &owner_ref,
                            Some(&owner_uid),
                            None,
                        ));
                        mutation.resource = protobuf::MessageField::some(body);
                        let mut operation_key =
                            format!("{}:{}:", uid.as_str(), revision).into_bytes();
                        operation_key.extend_from_slice(&canonical_json);
                        let mut request = wire::UpdateMetadataRequest::new();
                        request.meta = protobuf::MessageField::some(resource_request_meta(
                            &resource_operation_id_with_key(
                                "display-process-policy-update",
                                &zone,
                                &process_ref,
                                &operation_key,
                            ),
                        ));
                        request.mutation = protobuf::MessageField::some(mutation);
                        let updated = client.update_metadata(request).await;
                        if updated.error.is_some() {
                            return Err(WorkerEffectError::WorkerUnavailable);
                        }
                        (
                            *updated
                                .resource
                                .0
                                .ok_or(WorkerEffectError::WorkerUnavailable)?,
                            true,
                        )
                    };
                let (state, record) = durable_record_from_response(
                    process_ref,
                    resource,
                    role,
                    expected_generation,
                    &zone,
                    &owner_ref,
                    &owner_uid,
                    &expected_execution_ref,
                )?;
                return Ok((
                    if policy_replaced {
                        WorkerState::Starting
                    } else {
                        state
                    },
                    record,
                ));
            }
            if let Some(error) = get.error.as_ref()
                && error.kind.enum_value_or_default()
                    != d2b_contracts_resource::resource_proto::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_NOT_FOUND
            {
                return Err(WorkerEffectError::WorkerUnavailable);
            }
            let target = resource_wire_identity(&zone, &process_ref, None, None);
            let owner = resource_wire_identity(&zone, &owner_ref, Some(&owner_uid), None);
            let mut body = wire::ResourceEnvelopeBytes::new();
            body.identity = protobuf::MessageField::some(target.clone());
            body.canonical_json = payload.clone();
            body.payload_digest = canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &payload);
            let mut precondition = wire::Precondition::new();
            precondition.kind = protobuf::EnumOrUnknown::new(
                wire::PreconditionKind::PRECONDITION_KIND_CREATE_ABSENT,
            );
            let mut mutation = wire::Mutation::new();
            mutation.kind = protobuf::EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_CREATE);
            mutation.target = protobuf::MessageField::some(target);
            mutation.precondition = protobuf::MessageField::some(precondition);
            mutation.resource = protobuf::MessageField::some(body);
            mutation.owner = protobuf::MessageField::some(owner);
            let mut request = wire::CreateRequest::new();
            request.meta = protobuf::MessageField::some(resource_request_meta(
                &resource_operation_id_with_key(
                    "display-process-create",
                    &zone,
                    &process_ref,
                    &payload,
                ),
            ));
            request.mutation = protobuf::MessageField::some(mutation);
            let created = client.create(request).await;
            if let Some(resource) = created.resource.0 {
                return durable_record_from_response(
                    process_ref,
                    *resource,
                    role,
                    expected_generation,
                    &zone,
                    &owner_ref,
                    &owner_uid,
                    &expected_execution_ref,
                );
            }
            if created.error.is_some() {
                let adopted = client
                    .get(resource_get_request(
                        &zone,
                        &process_ref,
                        "display-process-adopt-get",
                    ))
                    .await;
                if let Some(resource) = adopted.resource.0 {
                    return durable_record_from_response(
                        process_ref,
                        *resource,
                        role,
                        expected_generation,
                        &zone,
                        &owner_ref,
                        &owner_uid,
                        &expected_execution_ref,
                    );
                }
                return Err(WorkerEffectError::WorkerUnavailable);
            }
            Err(WorkerEffectError::WorkerUnavailable)
        })?;
        self.resource_processes.insert(role, result.1.clone());
        self.ensure_durable_endpoint(role, &result.1)?;
        self.update_durable_endpoint_status(role, &result.1, result.0)?;
        Ok(WorkerLaunchReceipt::from_supervisor(
            role,
            result.0,
            binding.policy_generation(),
            binding.teardown_generation(),
            self.session_digest,
        ))
    }

    fn stop_durable_process(
        &mut self,
        role: DisplayProcessRole,
    ) -> Result<WorkerLaunchReceipt, WorkerEffectError> {
        let state = self.durable_state(role)?;
        let Some((worker_state, record)) = state else {
            self.stop_durable_endpoint(role)?;
            self.resource_processes.remove(&role);
            return Ok(WorkerLaunchReceipt::from_supervisor(
                role,
                WorkerState::Terminal { deleted: true },
                self.policy_generation,
                self.teardown_generation,
                self.session_digest,
            ));
        };
        self.resource_processes.insert(role, record.clone());
        if !matches!(worker_state, WorkerState::Terminal { deleted: true })
            && !record.deletion_requested
        {
            let client = self
                .resource_client
                .clone()
                .ok_or(WorkerEffectError::CleanupIncomplete)?;
            let zone = self
                .resource_zone
                .clone()
                .ok_or(WorkerEffectError::CleanupIncomplete)?;
            let process_ref = record.resource_ref.clone();
            let uid = record.resource_uid.clone();
            let revision = record.revision;
            let delete_key = format!("{}:{}", uid.as_str(), revision);
            run_effect(move || async move {
                let mut mutation = wire::Mutation::new();
                mutation.kind =
                    protobuf::EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_DELETE);
                mutation.target = protobuf::MessageField::some(resource_wire_identity(
                    &zone,
                    &process_ref,
                    Some(&uid),
                    Some(revision),
                ));
                let mut precondition = wire::Precondition::new();
                precondition.kind = protobuf::EnumOrUnknown::new(
                    wire::PreconditionKind::PRECONDITION_KIND_EXACT_REVISION,
                );
                precondition.expected_revision = Some(revision);
                precondition.expected_uid = Some(uid.as_str().to_owned());
                mutation.precondition = protobuf::MessageField::some(precondition);
                let mut request = wire::DeleteRequest::new();
                request.meta = protobuf::MessageField::some(resource_request_meta(
                    &resource_operation_id_with_key(
                        "display-process-delete",
                        &zone,
                        &process_ref,
                        delete_key.as_bytes(),
                    ),
                ));
                request.mutation = protobuf::MessageField::some(mutation);
                let response = client.delete(request).await;
                if response.error.is_some() {
                    return Err(WorkerEffectError::CleanupIncomplete);
                }
                Ok(())
            })?;
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        let state = loop {
            let observed_state = match self.durable_state(role)? {
                None => {
                    self.resource_processes.remove(&role);
                    break WorkerState::Terminal { deleted: true };
                }
                Some((observed, current)) => {
                    self.resource_processes.insert(role, current);
                    observed
                }
            };
            if observed_state.is_terminal() && observed_state.is_deleted() {
                self.resource_processes.remove(&role);
                break observed_state;
            }
            if Instant::now() >= deadline {
                break observed_state;
            }
            thread::sleep(Duration::from_millis(50));
        };
        let mut process_deleted = false;
        if state.is_terminal() {
            self.stop_durable_endpoint(role)?;
            if let Some(record) = self.resource_processes.get(&role).cloned() {
                let client = self
                    .resource_client
                    .clone()
                    .ok_or(WorkerEffectError::CleanupIncomplete)?;
                let zone = self
                    .resource_zone
                    .clone()
                    .ok_or(WorkerEffectError::CleanupIncomplete)?;
                let process_ref = record.resource_ref.clone();
                let uid = record.resource_uid.clone();
                let revision = record.revision;
                let delete_key = format!("{}:{}", uid.as_str(), revision);
                run_effect(move || async move {
                    let mut mutation = wire::Mutation::new();
                    mutation.kind =
                        protobuf::EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_DELETE);
                    mutation.target = protobuf::MessageField::some(resource_wire_identity(
                        &zone,
                        &process_ref,
                        Some(&uid),
                        Some(revision),
                    ));
                    let mut precondition = wire::Precondition::new();
                    precondition.kind = protobuf::EnumOrUnknown::new(
                        wire::PreconditionKind::PRECONDITION_KIND_EXACT_REVISION,
                    );
                    precondition.expected_revision = Some(revision);
                    precondition.expected_uid = Some(uid.as_str().to_owned());
                    mutation.precondition = protobuf::MessageField::some(precondition);
                    let mut request = wire::DeleteRequest::new();
                    request.meta = protobuf::MessageField::some(resource_request_meta(
                        &resource_operation_id_with_key(
                            "display-process-drain",
                            &zone,
                            &process_ref,
                            delete_key.as_bytes(),
                        ),
                    ));
                    request.mutation = protobuf::MessageField::some(mutation);
                    let _ = client.delete(request).await;
                    Ok(())
                })?;
                let deadline = Instant::now() + Duration::from_secs(2);
                loop {
                    match self.durable_state(role)? {
                        None => {
                            self.resource_processes.remove(&role);
                            process_deleted = true;
                            break;
                        }
                        Some((_, current)) => {
                            self.resource_processes.insert(role, current);
                        }
                    }
                    if Instant::now() >= deadline {
                        break;
                    }
                    thread::sleep(Duration::from_millis(50));
                }
            }
        }
        if process_deleted {
            self.resource_processes.remove(&role);
            return Ok(WorkerLaunchReceipt::from_supervisor(
                role,
                WorkerState::Terminal { deleted: true },
                self.policy_generation,
                self.teardown_generation,
                self.session_digest,
            ));
        }
        Ok(WorkerLaunchReceipt::from_supervisor(
            role,
            state,
            self.policy_generation,
            self.teardown_generation,
            self.session_digest,
        ))
    }
}

impl<S> DisplayProcessEffectPort for DisplaySupervisorEffects<S>
where
    S: ProcessLaunchEffectPort + Clone + Send + Sync + 'static,
{
    fn bind_session(
        &mut self,
        session: &AuthenticatedDisplaySession,
        spec: &WaylandSessionSpec,
        policy_generation: u64,
        teardown_generation: u64,
    ) -> Result<(), WorkerEffectError> {
        self.session_digest = spec.session_digest(session.controller_generation());
        self.guest_subject = Some(session.guest_ref().clone());
        self.host_execution_ref = Some(session.host_ref().clone());
        self.reconnect_generation = session.reconnect_generation();
        self.policy_generation = policy_generation;
        self.teardown_generation = teardown_generation;
        Ok(())
    }

    fn current_observation(
        &mut self,
    ) -> Result<Option<d2b_provider_display_wayland::ProcessObservation>, WorkerEffectError> {
        if !self.uses_durable_processes() {
            return Ok(None);
        }
        let mut states = BTreeMap::new();
        for role in [
            DisplayProcessRole::HostProxy,
            DisplayProcessRole::GuestFrontend,
        ] {
            match self.durable_state(role) {
                Ok(Some((state, record))) => {
                    self.resource_processes.insert(role, record);
                    let producer = self
                        .resource_processes
                        .get(&role)
                        .cloned()
                        .ok_or(WorkerEffectError::WorkerUnavailable)?;
                    self.update_durable_endpoint_status(role, &producer, state)?;
                    states.insert(role, state);
                }
                Ok(None) => {
                    states.insert(role, WorkerState::Starting);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(Some(
            d2b_provider_display_wayland::ProcessObservation::from_daemon(
                states
                    .get(&DisplayProcessRole::HostProxy)
                    .copied()
                    .unwrap_or(WorkerState::Starting),
                states
                    .get(&DisplayProcessRole::GuestFrontend)
                    .copied()
                    .unwrap_or(WorkerState::Starting),
                VolumeState::Present,
                self.policy_generation,
                self.teardown_generation.max(1),
                self.session_digest,
            ),
        ))
    }

    fn resource_projection(
        &mut self,
    ) -> Result<Option<d2b_provider_display_wayland::WaylandSessionResourceStatus>, WorkerEffectError>
    {
        if !self.uses_durable_processes() {
            return Ok(None);
        }
        Ok(Some(
            d2b_provider_display_wayland::WaylandSessionResourceStatus {
                proxy_process_ref: self
                    .resource_processes
                    .get(&DisplayProcessRole::HostProxy)
                    .map(|process| process.resource_ref.clone()),
                guest_frontend_process_ref: self
                    .resource_processes
                    .get(&DisplayProcessRole::GuestFrontend)
                    .map(|process| process.resource_ref.clone()),
                wayland_endpoint_ref: self
                    .resource_endpoints
                    .get(&DisplayProcessRole::HostProxy)
                    .map(|endpoint| endpoint.resource_ref.clone()),
                wayland_endpoint_generation: self
                    .resource_endpoints
                    .get(&DisplayProcessRole::HostProxy)
                    .map(|endpoint| endpoint.generation),
                policy_digest: String::new(),
            },
        ))
    }

    fn current_supervision(&mut self) -> Result<WorkerRestartEvidence, WorkerEffectError> {
        if self.uses_durable_processes() {
            let observed_at_ms = daemon_monotonic_ms();
            let mut next_failures = self.last_failures.clone();
            for role in [
                DisplayProcessRole::HostProxy,
                DisplayProcessRole::GuestFrontend,
            ] {
                let previous_failure = self.last_failures.get(&role).copied();
                let failure = match self.durable_state(role) {
                    Ok(Some((WorkerState::Failed { .. }, record))) => {
                        self.resource_processes.insert(role, record);
                        Some(previous_failure.unwrap_or(observed_at_ms))
                    }
                    Ok(Some((state, record))) => {
                        self.resource_processes.insert(role, record);
                        if state.is_terminal() && !state.is_deleted() {
                            Some(previous_failure.unwrap_or(observed_at_ms))
                        } else {
                            None
                        }
                    }
                    Ok(None) if self.resource_processes.contains_key(&role) => {
                        Some(previous_failure.unwrap_or(observed_at_ms))
                    }
                    Ok(None) => None,
                    Err(error) => return Err(error),
                };
                if let Some(failure) = failure {
                    next_failures.insert(role, failure);
                } else {
                    next_failures.remove(&role);
                }
            }
            self.last_failures = next_failures;
            return Ok(WorkerRestartEvidence::from_supervisor(
                observed_at_ms,
                self.last_failures
                    .get(&DisplayProcessRole::HostProxy)
                    .copied(),
                self.last_failures
                    .get(&DisplayProcessRole::GuestFrontend)
                    .copied(),
                self.teardown_generation.max(1),
            ));
        }
        #[cfg(test)]
        {
            let observed_at_ms = daemon_monotonic_ms();
            for role in [
                DisplayProcessRole::HostProxy,
                DisplayProcessRole::GuestFrontend,
            ] {
                let Some(ticket) = self.tickets.get(&role).cloned() else {
                    continue;
                };
                let supervisor = self._supervisor.clone();
                let alive = run_effect(move || async move {
                    let Some(candidate) = supervisor
                        .observe(&ticket)
                        .await
                        .map_err(|_| WorkerEffectError::WorkerUnavailable)?
                    else {
                        return Ok(false);
                    };
                    Ok(supervisor.open_pidfd(&candidate).await.is_ok())
                })
                .unwrap_or(false);
                if alive {
                    self.last_failures.remove(&role);
                } else {
                    self.last_failures.insert(role, observed_at_ms);
                }
            }
            return Ok(WorkerRestartEvidence::from_supervisor(
                observed_at_ms,
                self.last_failures
                    .get(&DisplayProcessRole::HostProxy)
                    .copied(),
                self.last_failures
                    .get(&DisplayProcessRole::GuestFrontend)
                    .copied(),
                self.teardown_generation.max(1),
            ));
        }
        #[cfg(not(test))]
        Ok(WorkerRestartEvidence::from_supervisor(
            daemon_monotonic_ms(),
            None,
            None,
            self.teardown_generation.max(1),
        ))
    }

    fn issue_launch_grants(
        &mut self,
        session: &AuthenticatedDisplaySession,
        spec: &WaylandSessionSpec,
        policy: &WaylandPolicySnapshot,
        proof: Option<&DisplayDependencyProof>,
        teardown_generation: u64,
    ) -> Result<LaunchGrants, WorkerEffectError> {
        let session_digest = spec.session_digest(session.controller_generation());
        if let Some(proof) = proof
            && (proof.session_digest() != session_digest
                || proof.reconnect_generation() != session.reconnect_generation()
                || proof.controller_generation() != session.controller_generation()
                || proof.teardown_generation() != teardown_generation
                || proof.policy_generation() != policy.generation())
        {
            return Err(WorkerEffectError::GrantUnavailable);
        }
        self.session_digest = session_digest;
        self.guest_subject = Some(session.guest_ref().clone());
        self.host_execution_ref = Some(session.host_ref().clone());
        self.reconnect_generation = session.reconnect_generation();
        self.policy_generation = policy.generation();
        self.teardown_generation = teardown_generation;
        LaunchGrants::issue_for_supervisor_with_controller_generation(
            session_digest,
            session.reconnect_generation(),
            session.controller_generation(),
            teardown_generation,
        )
        .map_err(|_| WorkerEffectError::GrantUnavailable)
    }

    fn launch(
        &mut self,
        ticket: d2b_provider_display_wayland::LaunchTicket,
    ) -> Result<WorkerLaunchReceipt, WorkerEffectError> {
        if !ticket.is_current(self.teardown_generation)
            || ticket.policy_generation() != self.policy_generation
        {
            return Err(WorkerEffectError::LaunchRejected);
        }
        let binding = DisplayLaunchBinding::from_ticket(ticket);
        if self
            .consumed_grants
            .contains_key(&binding.attachment_digest())
        {
            return Err(WorkerEffectError::GrantUnavailable);
        }
        if self.uses_durable_processes() {
            let receipt = self.ensure_durable_process(binding.role(), &binding)?;
            self.consumed_grants
                .insert(binding.attachment_digest(), binding.teardown_generation());
            return Ok(receipt);
        }
        #[cfg(test)]
        {
            let execution_ref = match binding.role() {
                DisplayProcessRole::HostProxy => self.host_execution_ref.as_ref(),
                DisplayProcessRole::GuestFrontend => self.guest_subject.as_ref(),
            }
            .ok_or(WorkerEffectError::LaunchRejected)?;
            let process_ticket = process_ticket_for_session(
                &binding,
                execution_ref,
                self.guest_subject.as_ref(),
                self.session_digest,
            )?;
            let role = binding.role();
            if let Some(previous) = self.identities.get(&role).copied() {
                let supervisor = self._supervisor.clone();
                run_effect(move || async move {
                    supervisor
                        .stop(&previous.identity, StopClass::Terminate)
                        .await
                        .map_err(|_| WorkerEffectError::CleanupIncomplete)
                })?;
                self.identities.remove(&role);
            }
            let supervisor = self._supervisor.clone();
            let adoption_ticket = process_ticket.clone();
            let adopted = run_effect(move || {
                let supervisor = supervisor.clone();
                let process_ticket = adoption_ticket.clone();
                async move {
                    if let Some(candidate) = supervisor
                        .observe(&process_ticket)
                        .await
                        .map_err(|_| WorkerEffectError::WorkerUnavailable)?
                    {
                        match supervisor.open_pidfd(&candidate).await {
                            Ok(_) => Ok(candidate.identity),
                            Err(_) => Ok(supervisor
                                .launch(&process_ticket)
                                .await
                                .map_err(|_| WorkerEffectError::LaunchRejected)?
                                .identity),
                        }
                    } else {
                        Ok(supervisor
                            .launch(&process_ticket)
                            .await
                            .map_err(|_| WorkerEffectError::LaunchRejected)?
                            .identity)
                    }
                }
            })?;
            self.identities.insert(
                role,
                LiveWorker {
                    identity: adopted,
                    policy_generation: binding.policy_generation(),
                    teardown_generation: binding.teardown_generation(),
                    session_digest: self.session_digest,
                },
            );
            self.tickets.insert(role, process_ticket);
            self.consumed_grants
                .insert(binding.attachment_digest(), binding.teardown_generation());
            return Ok(WorkerLaunchReceipt::from_supervisor(
                role,
                WorkerState::Ready { generation: 1 },
                binding.policy_generation(),
                binding.teardown_generation(),
                self.session_digest,
            ));
        }
        #[cfg(not(test))]
        Err(WorkerEffectError::WorkerUnavailable)
    }

    fn stop(&mut self, role: DisplayProcessRole) -> Result<WorkerLaunchReceipt, WorkerEffectError> {
        if self.uses_durable_processes() {
            return self.stop_durable_process(role);
        }
        #[cfg(test)]
        if let Some(worker) = self.identities.get(&role).copied() {
            let supervisor = self._supervisor.clone();
            run_effect(move || async move {
                supervisor
                    .stop(&worker.identity, StopClass::Terminate)
                    .await
                    .map_err(|_| WorkerEffectError::CleanupIncomplete)
            })?;
            self.identities.remove(&role);
            self.tickets.remove(&role);
            self.last_failures.remove(&role);
            return Ok(WorkerLaunchReceipt::from_supervisor(
                role,
                WorkerState::Terminal { deleted: true },
                worker.policy_generation,
                worker.teardown_generation,
                worker.session_digest,
            ));
        }
        Ok(WorkerLaunchReceipt::from_supervisor(
            role,
            WorkerState::Terminal { deleted: true },
            self.policy_generation,
            self.teardown_generation,
            self.session_digest,
        ))
    }

    fn delete_runtime_volume(&mut self) -> Result<VolumeState, WorkerEffectError> {
        Ok(VolumeState::Deleted)
    }

    fn revoke_portal(&mut self) -> Result<CleanupState, WorkerEffectError> {
        Ok(CleanupState::Complete)
    }

    fn release_principal(&mut self) -> Result<CleanupState, WorkerEffectError> {
        Ok(CleanupState::Complete)
    }

    fn release_authority(&mut self) -> Result<CleanupState, WorkerEffectError> {
        Ok(CleanupState::Complete)
    }
}

/// Build the two display Process and Endpoint intents owned by one
/// WaylandSession. The intents contain only signed template metadata; actual
/// attachment grants remain ComponentSession/ProviderSupervisor state.
pub(crate) fn display_owned_child_intents(
    zone: &ZoneId,
    session_ref: &ResourceRef,
    session_uid: &ResourceUid,
    spec: &WaylandSessionSpec,
    process_generation: u64,
    controller_generation: u64,
) -> Result<Vec<OwnedChildIntent>, WorkerEffectError> {
    let mut effects = DisplaySupervisorEffects::new_base(UnavailableProcessEffectPort);
    effects.resource_zone = Some(zone.clone());
    effects.wayland_session_ref = Some(session_ref.clone());
    effects.wayland_session_uid = Some(session_uid.clone());
    effects.guest_subject = Some(spec.guest_ref().clone());
    effects.host_execution_ref = Some(spec.host_ref().clone());
    effects.session_digest = spec.session_digest(controller_generation);
    effects.policy_generation = process_generation.max(1);
    effects.teardown_generation = 1;

    let mut intents = Vec::with_capacity(4);
    for role in [
        DisplayProcessRole::HostProxy,
        DisplayProcessRole::GuestFrontend,
    ] {
        let process_ref = effects.durable_process_ref(role)?;
        let process = effects.durable_process_payload_for_generation(role, process_generation)?;
        let process_digest = canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &process);
        intents.push(
            OwnedChildIntent::new(process_ref.clone(), process, process_digest)
                .map_err(|_| WorkerEffectError::LaunchRejected)?
                .with_dependencies([session_ref.clone()])
                .map_err(|_| WorkerEffectError::LaunchRejected)?,
        );
        let endpoint_ref = effects.durable_endpoint_ref(role)?;
        let endpoint = effects.durable_endpoint_payload(role, &process_ref, process_generation)?;
        let endpoint_digest = canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &endpoint);
        intents.push(
            OwnedChildIntent::new(endpoint_ref, endpoint, endpoint_digest)
                .map_err(|_| WorkerEffectError::LaunchRejected)?
                .with_dependencies([process_ref])
                .map_err(|_| WorkerEffectError::LaunchRejected)?,
        );
    }
    Ok(intents)
}

/// Daemon-owned bounded drain state for clipboard and notification services.
#[derive(Default)]
pub struct InteractionDrainEffects {
    drained: bool,
    authority_released: bool,
    audit_events: usize,
    notification_lifecycle:
        Option<NotificationLifecycleSupervisor<InteractionNotificationLifecycleBackend>>,
    notification_recovered: bool,
}

/// Daemon-owned presentation adapter for the bounded desktop sink.  It
/// represents an already-admitted host presentation connection; no address,
/// bus name, or standalone service is stored here.
#[derive(Debug, Default)]
pub struct InteractionNotificationPort {
    next_id: u32,
    presented: VecDeque<d2b_provider_notification_desktop::SanitizedNotification>,
    active: bool,
}

impl DesktopNotificationPort for InteractionNotificationPort {
    fn activate(&mut self) -> Result<(), d2b_provider_notification_desktop::SinkError> {
        self.active = true;
        Ok(())
    }

    fn deactivate(&mut self) -> Result<(), d2b_provider_notification_desktop::SinkError> {
        self.active = false;
        self.presented.clear();
        Ok(())
    }

    fn notify(
        &mut self,
        notification: &d2b_provider_notification_desktop::SanitizedNotification,
    ) -> Result<u32, d2b_provider_notification_desktop::SinkError> {
        if !self.active || self.presented.len() >= 64 {
            return Err(d2b_provider_notification_desktop::SinkError::Unavailable);
        }
        self.presented.push_back(notification.clone());
        self.next_id = self.next_id.wrapping_add(1).max(1);
        Ok(self.next_id)
    }
}

/// Daemon-owned desktop presentation effect backed by the authenticated
/// session notification service.
#[derive(Debug, Default)]
pub struct NotifyRustNotificationPort {
    handles: VecDeque<notify_rust::NotificationHandle>,
    active: bool,
}

impl DesktopNotificationPort for NotifyRustNotificationPort {
    fn activate(&mut self) -> Result<(), d2b_provider_notification_desktop::SinkError> {
        self.active = true;
        Ok(())
    }

    fn deactivate(&mut self) -> Result<(), d2b_provider_notification_desktop::SinkError> {
        self.active = false;
        while let Some(handle) = self.handles.pop_front() {
            handle.close();
        }
        Ok(())
    }

    fn notify(
        &mut self,
        notification: &d2b_provider_notification_desktop::SanitizedNotification,
    ) -> Result<u32, d2b_provider_notification_desktop::SinkError> {
        if !self.active {
            return Err(d2b_provider_notification_desktop::SinkError::Unavailable);
        }
        let mut desktop = DesktopNotification::new();
        desktop
            .appname("d2bd")
            .summary(notification.summary())
            .body(notification.body())
            .urgency(match notification.urgency() {
                d2b_provider_notification_desktop::NotificationUrgency::Low => Urgency::Low,
                d2b_provider_notification_desktop::NotificationUrgency::Normal => Urgency::Normal,
                d2b_provider_notification_desktop::NotificationUrgency::Critical => {
                    Urgency::Critical
                }
            })
            .timeout(Duration::from_secs(u64::from(
                notification.expire_timeout_secs(),
            )));
        if let Some(icon) = notification.icon_ref() {
            desktop.icon(icon);
        }
        for (action_key, label) in notification.actions() {
            desktop.action(action_key, label);
        }
        let handle = desktop
            .show()
            .map_err(|_| d2b_provider_notification_desktop::SinkError::Unavailable)?;
        let id = handle.id();
        if self.handles.len() >= 64
            && let Some(old) = self.handles.pop_front()
        {
            old.close();
        }
        self.handles.push_back(handle);
        Ok(id)
    }
}

struct InteractionNotificationLifecycleState {
    sources: std::collections::BTreeSet<NotificationSourceIdentity>,
    host_sink: Option<NotificationHostSinkIdentity>,
}

struct InteractionNotificationLifecycleBackend {
    state: Mutex<InteractionNotificationLifecycleState>,
    port: Arc<Mutex<Box<dyn DesktopNotificationPort + Send>>>,
}

impl InteractionNotificationLifecycleBackend {
    fn new(port: Arc<Mutex<Box<dyn DesktopNotificationPort + Send>>>) -> Self {
        Self {
            state: Mutex::new(InteractionNotificationLifecycleState {
                sources: std::collections::BTreeSet::new(),
                host_sink: None,
            }),
            port,
        }
    }
}

impl NotificationLifecycleBackend for InteractionNotificationLifecycleBackend {
    fn start_source(&self, source: &NotificationSourceIdentity) -> Result<(), &'static str> {
        self.state
            .lock()
            .map_err(|_| "notification-source-lifecycle-unavailable")?
            .sources
            .insert(source.clone());
        Ok(())
    }

    fn stop_source(&self, source: &NotificationSourceIdentity) -> Result<(), &'static str> {
        if self
            .state
            .lock()
            .map_err(|_| "notification-source-lifecycle-unavailable")?
            .sources
            .remove(source)
        {
            Ok(())
        } else {
            Err("notification-source-lifecycle-mismatch")
        }
    }

    fn start_host_sink(&self, sink: &NotificationHostSinkIdentity) -> Result<(), &'static str> {
        self.port
            .lock()
            .map_err(|_| "notification-host-sink-unavailable")?
            .activate()
            .map_err(|_| "notification-host-sink-unavailable")?;
        self.state
            .lock()
            .map_err(|_| "notification-host-sink-unavailable")?
            .host_sink = Some(sink.clone());
        Ok(())
    }

    fn stop_host_sink(&self, sink: &NotificationHostSinkIdentity) -> Result<(), &'static str> {
        {
            let state = self
                .state
                .lock()
                .map_err(|_| "notification-host-sink-unavailable")?;
            if state.host_sink.as_ref() != Some(sink) {
                return Err("notification-host-sink-lifecycle-mismatch");
            }
        }
        self.port
            .lock()
            .map_err(|_| "notification-host-sink-unavailable")?
            .deactivate()
            .map_err(|_| "notification-host-sink-unavailable")?;
        self.state
            .lock()
            .map_err(|_| "notification-host-sink-unavailable")?
            .host_sink = None;
        Ok(())
    }

    fn observe(
        &self,
        _zone: &ZoneId,
        _provider_ref: &ResourceRef,
    ) -> Result<NotificationLifecycleObservation, &'static str> {
        let state = self
            .state
            .lock()
            .map_err(|_| "notification-source-lifecycle-unavailable")?;
        Ok(NotificationLifecycleObservation::new(
            state.sources.iter().cloned().collect(),
            state.host_sink.clone(),
        ))
    }
}

impl core::fmt::Debug for InteractionDrainEffects {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("InteractionDrainEffects(<redacted>)")
    }
}

impl InteractionDrainEffects {
    fn new(port: Arc<Mutex<Box<dyn DesktopNotificationPort + Send>>>) -> Self {
        Self {
            notification_lifecycle: Some(NotificationLifecycleSupervisor::new(
                InteractionNotificationLifecycleBackend::new(port),
            )),
            ..Self::default()
        }
    }

    /// Whether all daemon-owned workers have been drained.
    pub const fn drained(&self) -> bool {
        self.drained
    }

    /// Whether the final session authority release completed.
    pub const fn authority_released(&self) -> bool {
        self.authority_released
    }
}

impl ClipboardProcessEffectPort for InteractionDrainEffects {
    fn drain(&mut self) -> Result<(), ClipboardServiceError> {
        self.drained = true;
        Ok(())
    }

    fn release_authority(&mut self) -> Result<(), ClipboardServiceError> {
        if !self.drained {
            return Err(ClipboardServiceError::AuthorityReleaseIncomplete);
        }
        self.authority_released = true;
        Ok(())
    }
}

impl d2b_provider_clipboard_wayland::ClipboardAuditSink for InteractionDrainEffects {
    type Error = &'static str;

    fn publish(
        &mut self,
        event: &d2b_provider_clipboard_wayland::ClipboardAuditEvent,
    ) -> Result<(), Self::Error> {
        if event.to_wire().is_empty() {
            return Err("clipboard-audit-empty");
        }
        self.audit_events = self.audit_events.saturating_add(1);
        Ok(())
    }
}

impl SourceProcessEffectPort for InteractionDrainEffects {
    fn apply(
        &mut self,
        plan: &SourceReconcileResult,
        lifecycle: &NotificationLifecyclePlan,
    ) -> Result<SourceProcessEffectReceipt, &'static str> {
        let supervisor = self
            .notification_lifecycle
            .as_ref()
            .ok_or("notification-supervisor-unavailable")?;
        if !self.notification_recovered {
            supervisor.recover(lifecycle.zone(), lifecycle.provider_ref())?;
            self.notification_recovered = true;
        }
        let receipt = supervisor.apply(lifecycle)?;
        SourceProcessEffectReceipt::from_supervisor(plan, lifecycle, &receipt)
    }
}

impl NotificationProcessEffectPort for InteractionDrainEffects {
    fn release_authority(&mut self) -> Result<(), &'static str> {
        if self
            .notification_lifecycle
            .as_ref()
            .ok_or("notification-supervisor-unavailable")?
            .is_drained()?
        {
            self.authority_released = true;
            Ok(())
        } else {
            Err("notification-authority-release-incomplete")
        }
    }
}

/// Committed resource-plane state required to construct one interaction runtime.
pub(crate) struct ProductionInteractionResourceState<'a> {
    zone: ZoneId,
    committed_policy: PolicySnapshot,
    resource_revision: ZoneRevision,
    resource_ready: bool,
    configuration: Option<&'a CommittedInteractionProviderConfiguration>,
    identity: Option<&'a CommittedInteractionIdentity>,
    system_core_client: Option<Arc<ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>>>,
}

impl<'a> ProductionInteractionResourceState<'a> {
    /// Bind the exact committed state for one ready Zone.
    pub(crate) const fn new(
        zone: ZoneId,
        committed_policy: PolicySnapshot,
        resource_revision: ZoneRevision,
        resource_ready: bool,
        configuration: Option<&'a CommittedInteractionProviderConfiguration>,
        identity: Option<&'a CommittedInteractionIdentity>,
        system_core_client: Option<
            Arc<ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>>,
        >,
    ) -> Self {
        Self {
            zone,
            committed_policy,
            resource_revision,
            resource_ready,
            configuration,
            identity,
            system_core_client,
        }
    }
}

fn validate_production_interaction_resource_state<'b>(
    resource: &ProductionInteractionResourceState<'b>,
) -> Result<&'b CommittedInteractionIdentity, BusError> {
    let identity = resource.identity.ok_or(BusError::InvalidConfig)?;
    if identity.zone() != &resource.zone
        || identity.wayland_session_ref().resource_type().as_str()
            != "display-wayland.d2bus.org.WaylandSession"
        || identity.wayland_session_uid().as_str().is_empty()
        || identity.subject_ref().resource_type().as_str() != "Guest"
        || identity.host_execution_ref().resource_type().as_str() != "Host"
        || identity.user_ref().resource_type().as_str() != "User"
        || identity.display_provider_generation().get() == 0
        || identity.allowed_guest_sources().get(identity.subject_ref())
            != Some(identity.subject_uid())
    {
        return Err(BusError::InvalidConfig);
    }
    Ok(identity)
}

/// Construct the daemon-owned authenticated interaction composition for one
/// trusted Zone. The registrar is created here, rather than in Provider code,
/// and its resolver binds the verified local peer to committed resources.
pub(crate) fn production_interaction_composition(
    daemon_uid: u32,
    resource: ProductionInteractionResourceState<'_>,
) -> Result<InteractionComposition<UnavailableProcessEffectPort>, BusError> {
    let identity = validate_production_interaction_resource_state(&resource)?;
    let system_core_client = resource
        .system_core_client
        .clone()
        .ok_or(BusError::InvalidConfig)?;
    let catalog = ApiCatalog::standard();
    let rule = PolicyRule::new(
        &catalog,
        [],
        [],
        [
            SessionVerb::Connect,
            SessionVerb::Invoke,
            SessionVerb::OpenStream,
            SessionVerb::Cancel,
            SessionVerb::Observe,
            SessionVerb::AuditExport,
            SessionVerb::SupportBundle,
        ],
        [],
        [],
        [resource.zone.clone()],
        [],
    )
    .map_err(|_| BusError::InvalidConfig)?;
    let role = CompiledRole::new(
        ResourceRef::parse("Role/interaction-provider").expect("fixed role reference"),
        vec![rule],
    )
    .map_err(|_| BusError::InvalidConfig)?;
    let mut bound_subjects = vec![BoundSubject {
        subject_ref: identity.subject_ref().clone(),
        subject_uid: identity.subject_uid().clone(),
    }];
    if let Some(provider_uid) = identity.clipboard_provider_uid() {
        bound_subjects.push(BoundSubject {
            subject_ref: ResourceRef::parse("Provider/clipboard-wayland")
                .expect("fixed clipboard Provider reference"),
            subject_uid: provider_uid.clone(),
        });
    }
    if let Some(provider_uid) = identity.notification_provider_uid() {
        bound_subjects.push(BoundSubject {
            subject_ref: ResourceRef::parse("Provider/notification-desktop")
                .expect("fixed notification Provider reference"),
            subject_uid: provider_uid.clone(),
        });
    }
    let binding = CompiledRoleBinding::new(
        role.role_ref.clone(),
        bound_subjects,
        BindingScope::default(),
        d2b_resource_api::authz::RelayGrantAuthority::None,
    )
    .map_err(|_| BusError::InvalidConfig)?;
    let policy = PolicySet::new(
        &catalog,
        resource.committed_policy.policy_revision,
        vec![role],
        vec![binding],
    )
    .map_err(|_| BusError::InvalidConfig)?;
    let native =
        NativeAuthorizer::new(catalog, Some(policy)).map_err(|_| BusError::InvalidConfig)?;
    let state = d2b_resource_api::authz::AuthorizationState {
        snapshot: resource.committed_policy,
        zone_policy_revision: resource.resource_revision,
        bootstrap_phase: BootstrapPhase::Disabled,
        now_tick: 1,
    };
    let committed_policy = state.snapshot;
    let authorizer = BusAuthorizer::new(native, state).map_err(|_| BusError::InvalidConfig)?;
    let (_bus, registrar, issuer) = ZoneBus::with_interaction_subject_issuer(
        resource.zone.clone(),
        authorizer,
        BusConfig::default(),
    )?;
    let mut composition = InteractionComposition::new_with_notification_port(
        registrar,
        UnavailableProcessEffectPort,
        Box::new(NotifyRustNotificationPort::default()),
    );
    composition.bind_display_resource_client(system_core_client);
    composition
        .registrar
        .install_committed_interaction_subject(
            identity
                .seal_interaction_subject_install(issuer, daemon_uid)
                .map_err(|_| BusError::InvalidConfig)?,
        )
        .map_err(|_| BusError::InvalidConfig)?;
    composition.bind_interaction_identity(identity);
    if let Some(configuration) = resource.configuration {
        composition
            .bind_interaction_provider_configuration(configuration)
            .map_err(|_| BusError::InvalidConfig)?;
    }
    let observer_user_ref = identity.user_ref().clone();
    let policy_ref = ResourceRef::parse("display-wayland.d2bus.org.WaylandPolicy/display-wayland")
        .map_err(|_| BusError::InvalidConfig)?;
    let dependencies = DependencyState::ready().with_zone(resource.zone);
    let evidence = CoreDisplayResourceEvidence::from_committed_policy(
        policy_ref,
        committed_policy,
        committed_policy.policy_revision,
        FilterInput::default(),
        FilterInput::default(),
        dependencies,
        observer_user_ref,
        resource.resource_revision,
        resource.resource_ready,
    )
    .map_err(|_| BusError::InvalidConfig)?;
    composition.bind_display_resource_evidence(evidence);
    Ok(composition)
}

#[cfg(test)]
fn unix_guest_subject_uid(uid: u32) -> ResourceUid {
    let mut digest = Sha256::new();
    digest.update(b"d2b-unix-guest-subject-v1");
    digest.update(uid.to_be_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest.finalize()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    ResourceUid::parse(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ))
    .expect("digest-derived test guest UID is valid")
}

/// Bind and retain the daemon-owned ComponentSession listeners for all
/// interaction Provider service packages. Providers do not open these sockets
/// and no Provider-owned service unit is created.
pub fn spawn_interaction_listeners<S>(
    runtime: Arc<AsyncMutex<Option<InteractionRuntimeSet<S>>>>,
    state_dir: PathBuf,
    zone: ZoneId,
    expected_peer_uid: u32,
) -> Result<InteractionListenerSet, String>
where
    S: ProcessLaunchEffectPort + Clone + Send + Sync + 'static,
{
    spawn_interaction_listeners_with_stop(
        runtime,
        state_dir,
        zone,
        expected_peer_uid,
        Arc::new(AtomicBool::new(false)),
    )
}

/// Bind listeners using an existing shutdown token so independently
/// Zone-bound listener sets can be stopped as one daemon-owned group.
pub fn spawn_interaction_listeners_with_stop<S>(
    runtime: Arc<AsyncMutex<Option<InteractionRuntimeSet<S>>>>,
    state_dir: PathBuf,
    zone: ZoneId,
    expected_peer_uid: u32,
    stop: Arc<AtomicBool>,
) -> Result<InteractionListenerSet, String>
where
    S: ProcessLaunchEffectPort + Clone + Send + Sync + 'static,
{
    ensure_owned_state_dir(&state_dir, expected_peer_uid).map_err(|error| error.to_string())?;
    let state_metadata =
        std::fs::symlink_metadata(&state_dir).map_err(|error| error.to_string())?;
    if state_metadata.file_type().is_symlink()
        || !state_metadata.is_dir()
        || state_metadata.uid() != expected_peer_uid
        || state_metadata.mode() & 0o022 != 0
    {
        return Err("interaction-listener-state-directory-ownership".to_owned());
    }

    fn ensure_owned_state_dir(path: &std::path::Path, expected_uid: u32) -> std::io::Result<()> {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink()
                    || !metadata.is_dir()
                    || metadata.uid() != expected_uid
                    || metadata.mode() & 0o022 != 0
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "interaction listener state directory is not daemon-owned",
                    ));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if let Some(parent) = path.parent() {
                    let parent_metadata = std::fs::symlink_metadata(parent)?;
                    if parent_metadata.file_type().is_symlink()
                        || !parent_metadata.is_dir()
                        || parent_metadata.mode() & 0o002 != 0
                    {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            "interaction listener parent directory is unsafe",
                        ));
                    }
                }
                std::fs::create_dir_all(path)?;
                let metadata = std::fs::symlink_metadata(path)?;
                if metadata.file_type().is_symlink()
                    || !metadata.is_dir()
                    || metadata.uid() != expected_uid
                    || metadata.mode() & 0o022 != 0
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "interaction listener state directory ownership changed",
                    ));
                }
            }
            Err(error) => return Err(error),
        }
        Ok(())
    }
    let mut paths = Vec::with_capacity(COMPONENT_SESSION_SERVICES.len());
    let handlers = Arc::new(Mutex::new(Vec::new()));
    let active_handlers = Arc::new(AtomicUsize::new(0));
    let mut threads = Vec::with_capacity(COMPONENT_SESSION_SERVICES.len());
    for (service, _) in COMPONENT_SESSION_SERVICES {
        let slug = service.replace('.', "-");
        let path = state_dir.join(format!("interaction-{slug}.sock"));
        let listener = bind_interaction_listener(&path, expected_peer_uid)
            .map_err(|error| format!("bind interaction listener {}: {error}", path.display()))?;
        let runtime = Arc::clone(&runtime);
        let zone = zone.clone();
        let service = (*service).to_owned();
        let failure_stop = Arc::clone(&stop);
        let thread_name = format!("d2bd-interaction-{}", service.replace('.', "-"));
        let context = InteractionAcceptContext {
            runtime,
            zone,
            service,
            expected_peer_uid,
            stop: Arc::clone(&stop),
            handlers: Arc::clone(&handlers),
            active_handlers: Arc::clone(&active_handlers),
        };
        thread::Builder::new()
            .name(thread_name)
            .spawn(move || interaction_accept_loop(listener, context))
            .map(|thread| threads.push(thread))
            .map_err(|error| {
                failure_stop.store(true, Ordering::Release);
                for thread in threads.drain(..) {
                    let _ = thread.join();
                }
                error.to_string()
            })?;
        paths.push(path);
    }
    let socket_identities = paths
        .iter()
        .map(|path| {
            let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
            Ok((metadata.dev(), metadata.ino()))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let parent_identities = paths
        .iter()
        .map(|path| {
            let parent = path
                .parent()
                .ok_or_else(|| "interaction-listener-parent-missing".to_owned())?;
            let metadata = std::fs::symlink_metadata(parent).map_err(|error| error.to_string())?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err("interaction-listener-parent-invalid".to_owned());
            }
            Ok((metadata.dev(), metadata.ino()))
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(InteractionListenerSet {
        paths,
        socket_identities,
        parent_identities,
        stop,
        threads: Mutex::new(threads),
        handlers,
    })
}

/// Daemon-owned handles for the interaction listener set.
pub struct InteractionListenerSet {
    paths: Vec<PathBuf>,
    socket_identities: Vec<(u64, u64)>,
    parent_identities: Vec<(u64, u64)>,
    stop: Arc<AtomicBool>,
    threads: Mutex<Vec<thread::JoinHandle<()>>>,
    handlers: Arc<Mutex<Vec<thread::JoinHandle<()>>>>,
}

impl core::fmt::Debug for InteractionListenerSet {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("InteractionListenerSet")
            .field("listener_count", &self.paths.len())
            .field("stopping", &self.stop.load(Ordering::Acquire))
            .finish()
    }
}

impl InteractionListenerSet {
    /// Return the socket paths owned by this daemon listener set.
    pub fn paths(&self) -> &[PathBuf] {
        &self.paths
    }

    /// Borrow the shared daemon shutdown token.
    pub fn stop_token(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop)
    }

    /// Append another independently Zone-bound listener set.
    pub fn extend(&mut self, mut other: Self) {
        self.paths.append(&mut other.paths);
        self.socket_identities.append(&mut other.socket_identities);
        self.parent_identities.append(&mut other.parent_identities);
        let other_threads = std::mem::replace(&mut other.threads, Mutex::new(Vec::new()))
            .into_inner()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.threads
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .extend(other_threads);
        self.handlers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .append(
                &mut other
                    .handlers
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()),
            );
    }

    /// Stop accepting new sessions and join all listener loops.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Release);
        let mut threads = self
            .threads
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for thread in threads.drain(..) {
            let _ = thread.join();
        }
        let mut handlers = self
            .handlers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for handler in handlers.drain(..) {
            let _ = handler.join();
        }
        self.remove_socket_paths();
    }

    fn remove_socket_paths(&self) {
        for ((path, (device, inode)), (parent_device, parent_inode)) in self
            .paths
            .iter()
            .zip(&self.socket_identities)
            .zip(&self.parent_identities)
        {
            let parent_owned = path.parent().and_then(|parent| {
                std::fs::symlink_metadata(parent).ok().filter(|metadata| {
                    metadata.is_dir()
                        && !metadata.file_type().is_symlink()
                        && metadata.dev() == *parent_device
                        && metadata.ino() == *parent_inode
                })
            });
            if parent_owned.is_some()
                && std::fs::symlink_metadata(path).is_ok_and(|metadata| {
                    metadata.file_type().is_socket()
                        && metadata.dev() == *device
                        && metadata.ino() == *inode
                })
            {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

impl Drop for InteractionListenerSet {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let threads = self
            .threads
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for thread in threads.drain(..) {
            let _ = thread.join();
        }
        let mut handlers = self
            .handlers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for handler in handlers.drain(..) {
            let _ = handler.join();
        }
        for ((path, (device, inode)), (parent_device, parent_inode)) in self
            .paths
            .iter()
            .zip(&self.socket_identities)
            .zip(&self.parent_identities)
        {
            let parent_owned = path.parent().and_then(|parent| {
                std::fs::symlink_metadata(parent).ok().filter(|metadata| {
                    metadata.is_dir()
                        && !metadata.file_type().is_symlink()
                        && metadata.dev() == *parent_device
                        && metadata.ino() == *parent_inode
                })
            });
            if parent_owned.is_some()
                && std::fs::symlink_metadata(path).is_ok_and(|metadata| {
                    metadata.file_type().is_socket()
                        && metadata.dev() == *device
                        && metadata.ino() == *inode
                })
            {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

fn bind_interaction_listener(path: &std::path::Path, expected_uid: u32) -> std::io::Result<Socket> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() && metadata.uid() == expected_uid => {
            std::fs::remove_file(path)?
        }
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "interaction listener path is not a socket",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let listener = Socket::new(Domain::UNIX, Type::from(libc::SOCK_SEQPACKET), None)?;
    listener.set_nonblocking(true)?;
    listener.bind(&SockAddr::unix(path)?)?;
    listener.listen(32)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}

#[derive(Clone)]
struct InteractionAcceptContext<S>
where
    S: ProcessLaunchEffectPort + Clone + Send + Sync + 'static,
{
    runtime: Arc<AsyncMutex<Option<InteractionRuntimeSet<S>>>>,
    zone: ZoneId,
    service: String,
    expected_peer_uid: u32,
    stop: Arc<AtomicBool>,
    handlers: Arc<Mutex<Vec<thread::JoinHandle<()>>>>,
    active_handlers: Arc<AtomicUsize>,
}

fn interaction_accept_loop<S>(listener: Socket, context: InteractionAcceptContext<S>)
where
    S: ProcessLaunchEffectPort + Clone + Send + Sync + 'static,
{
    let InteractionAcceptContext {
        runtime,
        zone,
        service,
        expected_peer_uid,
        stop,
        handlers,
        active_handlers,
    } = context;
    while !stop.load(Ordering::Acquire) {
        reap_finished_handlers(&handlers);
        let socket = match accept_with(
            listener.as_fd(),
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        ) {
            Ok(accepted) => accepted,
            Err(rustix::io::Errno::INTR) => continue,
            Err(rustix::io::Errno::AGAIN) => {
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(error) => {
                tracing::warn!(%error, service = %service, "interaction listener accept failed");
                continue;
            }
        };
        let runtime = Arc::clone(&runtime);
        let zone = zone.clone();
        let service = service.clone();
        if !reserve_interaction_handler(&active_handlers) {
            continue;
        }
        let handler_active = Arc::clone(&active_handlers);
        let handler_stop = Arc::clone(&stop);
        let handler = thread::Builder::new()
            .name("d2bd-interaction-session".to_owned())
            .spawn(move || {
                let result = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|error| error.to_string())
                    .and_then(|runtime_handle| {
                        runtime_handle.block_on(admit_interaction_socket(
                            socket,
                            runtime,
                            zone,
                            service,
                            expected_peer_uid,
                            handler_stop,
                        ))
                    });
                if let Err(error) = result {
                    tracing::debug!(%error, "interaction ComponentSession refused");
                }
                handler_active.fetch_sub(1, Ordering::AcqRel);
            });
        if let Ok(handler) = handler {
            handlers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(handler);
        } else {
            active_handlers.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

const MAX_INTERACTION_HANDLERS: usize = 64;

fn reserve_interaction_handler(active_handlers: &AtomicUsize) -> bool {
    let mut active = active_handlers.load(Ordering::Acquire);
    loop {
        if active >= MAX_INTERACTION_HANDLERS {
            return false;
        }
        match active_handlers.compare_exchange_weak(
            active,
            active + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(current) => active = current,
        }
    }
}

fn reap_finished_handlers(handlers: &Mutex<Vec<thread::JoinHandle<()>>>) {
    let mut handlers = handlers
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut index = 0;
    while index < handlers.len() {
        if handlers[index].is_finished() {
            let _ = handlers.swap_remove(index).join();
        } else {
            index += 1;
        }
    }
}

async fn admit_interaction_socket<S>(
    socket: std::os::fd::OwnedFd,
    runtime: Arc<AsyncMutex<Option<InteractionRuntimeSet<S>>>>,
    zone: ZoneId,
    service: String,
    expected_peer_uid: u32,
    stop: Arc<AtomicBool>,
) -> Result<(), String>
where
    S: ProcessLaunchEffectPort + Clone + Send + Sync + 'static,
{
    let policy = interaction_endpoint_policy(&service, 1)
        .ok_or_else(|| "unknown interaction service".to_owned())?;
    let seqpacket = SeqpacketSocket::from_owned(socket).map_err(|error| error.to_string())?;
    let verified_peer =
        VerifiedUnixPeer::verify_seqpacket(&seqpacket).map_err(|error| error.to_string())?;
    if verified_peer.credentials().uid().as_raw() != expected_peer_uid {
        return Err("interaction-peer-uid-rejected".to_owned());
    }
    let expected_peer = verified_peer.credentials();
    let credits = CreditScopeSet::new(
        CreditPool::new(8).map_err(|error| format!("{error:?}"))?,
        CreditPool::new(8).map_err(|error| format!("{error:?}"))?,
        CreditPool::new(8).map_err(|error| format!("{error:?}"))?,
        CreditPool::new(8).map_err(|error| format!("{error:?}"))?,
        CreditPool::new(8).map_err(|error| format!("{error:?}"))?,
        CreditPool::new(8).map_err(|error| format!("{error:?}"))?,
    );
    let resolver: d2b_session_unix::DescriptorPolicyResolver = Arc::new(|descriptor| {
        let clipboard_service = matches!(
            descriptor.service,
            ServicePackage::ClipboardV3
                | ServicePackage::ClipboardBridgeV3
                | ServicePackage::ClipboardPickerCoordV3
        );
        if clipboard_service
            && descriptor.kind == AttachmentKind::FileDescriptor
            && descriptor.purpose == AttachmentPurpose::ClipboardTransfer
        {
            Ok(d2b_session_unix::DescriptorPolicy::ProviderValidatedFile)
        } else {
            Err(UnixSessionError::DescriptorMismatch)
        }
    });
    let transport = UnixSeqpacketTransport::new(
        seqpacket,
        TransportLocality::HostLocal,
        policy.limits,
        policy.attachment_policy,
        credits,
        resolver,
        PeerIdentityPolicy::accepted(expected_peer),
    )
    .map_err(|error| error.to_string())?;
    let engine = tokio::time::timeout(
        Duration::from_secs(5),
        SessionEngine::establish_responder(
            transport,
            policy.clone(),
            d2b_session::HandshakeCredentials::Nn,
            Instant::now(),
        ),
    )
    .await
    .map_err(|_| "interaction-handshake-timeout".to_owned())?
    .map_err(|error| error.to_string())?;
    let acceptor = {
        let guard = runtime.lock().await;
        let composition = guard
            .as_ref()
            .and_then(|set| set.runtime_for(&zone))
            .ok_or_else(|| "interaction runtime unavailable".to_owned())?;
        composition
            .registrar()
            .component_session_acceptor(policy, verified_peer)
            .map_err(|error| error.to_string())?
    };
    let evidence = TransportEvidence::new(
        EvidenceClass::UnixPeer,
        binding_digest(
            &interaction_endpoint_policy(&service, 1)
                .expect("service policy was already validated"),
        ),
    );
    let request_receiver = {
        let mut guard = runtime.lock().await;
        let composition = guard
            .as_mut()
            .and_then(|set| set.runtime_for_mut(&zone))
            .ok_or_else(|| "interaction runtime unavailable".to_owned())?;
        let registered = composition
            .admit_and_register_for_service(acceptor, engine, evidence, 1, &service)
            .await
            .map_err(|error| error.to_string())?;
        let session_key = registered.session_key();
        let session_driver = registered
            .component_session_driver()
            .ok_or_else(|| "interaction session driver unavailable".to_owned())?;
        (session_key, registered.request_receiver(), session_driver)
    };
    let (session_key, request_receiver, session_driver) = request_receiver;
    loop {
        let frame = tokio::select! {
            frame = request_receiver.recv() => match frame {
                Ok(frame) => frame,
                Err(_) => break,
            },
            control = session_driver.receive_control() => match control {
                Ok(d2b_session::SessionEvent::Close(_)) | Err(_) => break,
                Ok(_) => continue,
            },
            _ = tokio::time::sleep(Duration::from_millis(50)) => {
                if stop.load(Ordering::Acquire) {
                    break;
                }
                continue;
            }
        };
        let attachments = if request_accepts_clipboard_attachments(&frame) {
            tokio::time::timeout(Duration::from_secs(5), request_receiver.recv_attachments())
                .await
                .map_err(|_| "interaction-attachment-receive-timeout".to_owned())?
                .map_err(|_| "interaction-attachment-receive-failed".to_owned())?
        } else {
            Vec::new()
        };
        let mut guard = runtime.lock().await;
        let composition = guard
            .as_mut()
            .and_then(|set| set.runtime_for_mut(&zone))
            .ok_or_else(|| "interaction runtime unavailable".to_owned())?;
        if let Err(error) = composition
            .dispatch_component_request_for_session(&session_key, frame, attachments)
            .await
        {
            tracing::debug!(%error, service = %service, "interaction request rejected");
        }
        if !composition.has_session(&session_key) {
            break;
        }
    }
    let mut guard = runtime.lock().await;
    guard
        .as_mut()
        .ok_or_else(|| "interaction runtime unavailable".to_owned())?
        .remove_session(&zone, &session_key)
        .await?;
    Ok(())
}

fn request_accepts_clipboard_attachments(frame: &[u8]) -> bool {
    let Some(payload) = frame.get(ttrpc::proto::MESSAGE_HEADER_LENGTH..) else {
        return false;
    };
    let Ok(request) = TtrpcRequest::parse_from_bytes(payload) else {
        return false;
    };
    if !matches!(
        request.method.as_str(),
        "ClipboardBridgeService/CaptureGuest" | "ClipboardBridgeService/CaptureHost"
    ) {
        return false;
    }

    serde_json::from_slice::<ClipboardCaptureRequest>(&request.payload)
        .is_ok_and(|request| request.bytes.is_none())
}

fn clipboard_attachment_object_type_allowed(
    object_type: d2b_contracts_zone_session::v3::component_session::KernelObjectType,
) -> bool {
    matches!(
        object_type,
        d2b_contracts_zone_session::v3::component_session::KernelObjectType::UnixStreamSocket
            | d2b_contracts_zone_session::v3::component_session::KernelObjectType::UnixSeqpacketSocket
            | d2b_contracts_zone_session::v3::component_session::KernelObjectType::PipeRead
            | d2b_contracts_zone_session::v3::component_session::KernelObjectType::PipeWrite
            | d2b_contracts_zone_session::v3::component_session::KernelObjectType::Memfd
            | d2b_contracts_zone_session::v3::component_session::KernelObjectType::RegularFile
    )
}

fn validate_interaction_attachments(
    attachments: &[OwnedAttachment],
    service: &str,
    method: &str,
    frame: &[u8],
    operation_id: &OperationId,
) -> Result<(), ()> {
    if attachments.is_empty() {
        return Ok(());
    }
    let clipboard_method = matches!(
        (service, method),
        (
            d2b_provider_clipboard_wayland::BRIDGE_SERVICE,
            "ClipboardBridgeService/CaptureGuest" | "ClipboardBridgeService/CaptureHost"
        )
    );
    if !clipboard_method {
        return Err(());
    }
    let mut expected_generation = None;
    let mut expected_packet_sequence = None;
    for attachment in attachments {
        let descriptor = attachment.descriptor().ok_or(())?;
        if descriptor.service.as_str() != service
            || descriptor.kind != AttachmentKind::FileDescriptor
            || !clipboard_attachment_object_type_allowed(descriptor.object_type)
            || descriptor.access
                != d2b_contracts_zone_session::v3::component_session::AttachmentAccess::ReadOnly
            || descriptor.purpose != AttachmentPurpose::ClipboardTransfer
            || descriptor
                .operation_id
                .as_ref()
                .is_some_and(|id| id.as_bytes() != operation_id.as_str().as_bytes())
        {
            return Err(());
        }
        if expected_generation
            .replace(descriptor.reconnect_generation)
            .is_some_and(|generation| generation != descriptor.reconnect_generation)
            || expected_packet_sequence
                .replace(descriptor.packet_sequence)
                .is_some_and(|sequence| sequence != descriptor.packet_sequence)
        {
            return Err(());
        }
        let request_id = d2b_session::ttrpc_request_id(descriptor.reconnect_generation, frame)
            .map_err(|_| ())?;
        if descriptor.request_id != request_id {
            return Err(());
        }
    }
    Ok(())
}

#[cfg(test)]
fn process_ticket_for_session(
    binding: &DisplayLaunchBinding,
    execution_ref: &ResourceRef,
    target_ref: Option<&ResourceRef>,
    session_digest: [u8; 32],
) -> Result<ProcessLaunchTicket, WorkerEffectError> {
    let (role_name, template_name, selected_provider) = match binding.role() {
        DisplayProcessRole::HostProxy => ("host-proxy", "wayland-proxy", "system-minijail"),
        DisplayProcessRole::GuestFrontend => ("guest-frontend", "wayland-proxy", "system-systemd"),
    };
    let suffix = display_session_suffix(session_digest);
    let process_ref = ResourceRef::parse(&format!("Process/display-{role_name}-{suffix}"))
        .map_err(|_| WorkerEffectError::LaunchRejected)?;
    let owner_provider =
        d2b_contracts_resource::v3::execution_policy::BoundedToken::parse("display-wayland")
            .map_err(|_| WorkerEffectError::LaunchRejected)?;
    let component =
        d2b_contracts_resource::v3::execution_policy::BoundedToken::parse("process-controller")
            .map_err(|_| WorkerEffectError::LaunchRejected)?;
    let template = d2b_contracts_resource::v3::execution_policy::BoundedToken::parse(template_name)
        .map_err(|_| WorkerEffectError::LaunchRejected)?;
    let selected_provider =
        d2b_contracts_resource::v3::execution_policy::BoundedToken::parse(selected_provider)
            .map_err(|_| WorkerEffectError::LaunchRejected)?;
    let process_uid = session_resource_uid(session_digest, binding.role(), b"process");
    let operation_uid = session_resource_uid(session_digest, binding.role(), b"operation");
    let generation =
        d2b_contracts_resource::v3::ResourceGeneration::new(binding.policy_generation())
            .map_err(|_| WorkerEffectError::LaunchRejected)?;
    let controller_generation =
        d2b_contracts_resource::v3::ControllerGeneration::new(binding.controller_generation())
            .map_err(|_| WorkerEffectError::LaunchRejected)?;
    let digests = CompiledDigests {
        sandbox: configuration_digest(binding, b"sandbox"),
        budget: configuration_digest(binding, b"budget"),
        mounts: configuration_digest(binding, b"mounts"),
        devices: configuration_digest(binding, b"devices"),
        network: configuration_digest(binding, b"network"),
        endpoints: configuration_digest(binding, b"endpoints"),
        fd_table: configuration_digest(binding, b"fd-table"),
    };
    let operation = OperationBinding::new(operation_uid, 30_000)
        .map_err(|_| WorkerEffectError::LaunchRejected)?;
    let expected_identity = [
        IdentityBinding::Cgroup,
        IdentityBinding::Executable,
        IdentityBinding::Generation,
        IdentityBinding::Template,
    ]
    .into_iter()
    .collect();
    let ticket = ProcessLaunchTicket::new(
        process_ref,
        process_uid,
        generation,
        controller_generation,
        owner_provider,
        component,
        template,
        execution_ref.clone(),
        d2b_contracts_resource::v3::execution_policy::ExecutionDomain::System,
        None,
        selected_provider,
        digests,
        operation,
        expected_identity,
    )
    .map_err(|_| WorkerEffectError::LaunchRejected)?;
    let ticket = if let Some(target_ref) = target_ref {
        ticket
            .with_target_ref(target_ref.clone())
            .map_err(|_| WorkerEffectError::LaunchRejected)?
    } else {
        ticket
    };
    Ok(ticket.with_readiness(ReadinessExpectation::condition(1_000).expect("fixed readiness")))
}

#[cfg(test)]
fn configuration_digest(
    binding: &DisplayLaunchBinding,
    label: &[u8],
) -> d2b_process::ConfigurationDigest {
    let mut digest = Sha256::new();
    digest.update(b"d2bd-display-config-v1");
    digest.update(label);
    digest.update(binding.attachment_digest());
    digest.update(binding.policy_digest());
    digest.update(binding.policy_generation().to_be_bytes());
    digest.update(binding.teardown_generation().to_be_bytes());
    d2b_process::ConfigurationDigest::from_bytes(digest.finalize().into())
}

#[cfg(test)]
fn display_session_suffix(session_digest: [u8; 32]) -> String {
    let mut suffix = String::with_capacity(40);
    for byte in session_digest.iter().take(20) {
        suffix.push_str(&format!("{byte:02x}"));
    }
    suffix
}

#[cfg(test)]
fn session_resource_uid(
    session_digest: [u8; 32],
    role: DisplayProcessRole,
    label: &[u8],
) -> ResourceUid {
    let mut digest = Sha256::new();
    digest.update(b"d2bd-display-resource-v1");
    digest.update(label);
    digest.update((role as u8).to_be_bytes());
    digest.update(session_digest);
    let mut bytes: [u8; 16] = digest.finalize()[..16]
        .try_into()
        .expect("fixed digest length");
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    ResourceUid::parse(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ))
    .expect("uuid bytes are canonical")
}

fn durable_display_suffix(owner_uid: &ResourceUid, role: DisplayProcessRole) -> String {
    let mut digest = Sha256::new();
    digest.update(b"d2bd-durable-display-process-v1");
    digest.update(owner_uid.as_str().as_bytes());
    digest.update([role as u8]);
    let digest = digest.finalize();
    let mut suffix = String::with_capacity(40);
    for byte in digest.iter().take(20) {
        suffix.push_str(&format!("{byte:02x}"));
    }
    suffix
}

fn resource_wire_identity(
    zone: &ZoneId,
    resource_ref: &ResourceRef,
    uid: Option<&ResourceUid>,
    revision: Option<u64>,
) -> wire::ResourceIdentity {
    let mut identity = wire::ResourceIdentity::new();
    identity.zone = zone.as_str().to_owned();
    identity.resource_type = resource_ref.resource_type().as_str().to_owned();
    identity.name = resource_ref.name().as_str().to_owned();
    identity.uid = uid.map(|value| value.as_str().to_owned());
    identity.revision = revision;
    identity
}

fn resource_get_request(
    zone: &ZoneId,
    resource_ref: &ResourceRef,
    operation: &str,
) -> wire::GetRequest {
    let mut request = wire::GetRequest::new();
    request.meta = protobuf::MessageField::some(resource_request_meta(&resource_operation_id(
        operation,
        zone,
        resource_ref,
    )));
    request.target =
        protobuf::MessageField::some(resource_wire_identity(zone, resource_ref, None, None));
    request
}

fn wayland_session_resource_projection(
    resource: &WaylandSessionResourceStatus,
) -> serde_json::Value {
    let mut projection = serde_json::Map::new();
    if let Some(reference) = resource.proxy_process_ref.as_ref() {
        projection.insert(
            "proxyProcessRef".to_owned(),
            serde_json::Value::String(reference.to_canonical_string()),
        );
    }
    if let Some(reference) = resource.guest_frontend_process_ref.as_ref() {
        projection.insert(
            "guestFrontendProcessRef".to_owned(),
            serde_json::Value::String(reference.to_canonical_string()),
        );
    }
    if let Some(reference) = resource.wayland_endpoint_ref.as_ref() {
        projection.insert(
            "waylandEndpointRef".to_owned(),
            serde_json::Value::String(reference.to_canonical_string()),
        );
    }
    if let Some(generation) = resource.wayland_endpoint_generation {
        projection.insert(
            "waylandEndpointGeneration".to_owned(),
            serde_json::Value::Number(generation.into()),
        );
    }
    if !resource.policy_digest.is_empty() {
        projection.insert(
            "policyDigest".to_owned(),
            serde_json::Value::String(resource.policy_digest.clone()),
        );
    }
    serde_json::Value::Object(projection)
}

fn resource_operation_id(operation: &str, zone: &ZoneId, resource_ref: &ResourceRef) -> String {
    let scope = format!("{}:{}", zone.as_str(), resource_ref.to_canonical_string());
    let digest = Sha256::digest(scope.as_bytes());
    let digest = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{operation}:{digest}")
}

fn resource_operation_id_with_key(
    operation: &str,
    zone: &ZoneId,
    resource_ref: &ResourceRef,
    key: &[u8],
) -> String {
    let mut scope = Vec::with_capacity(
        zone.as_str().len() + resource_ref.to_canonical_string().len() + key.len() + 2,
    );
    scope.extend_from_slice(zone.as_str().as_bytes());
    scope.push(0);
    scope.extend_from_slice(resource_ref.to_canonical_string().as_bytes());
    scope.push(0);
    scope.extend_from_slice(key);
    let digest = Sha256::digest(scope);
    let digest = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{operation}:{digest}")
}

fn resource_request_meta(operation: &str) -> wire::RequestMeta {
    let mut meta = wire::RequestMeta::new();
    meta.operation_id = operation.to_owned();
    meta.idempotency_key = operation.to_owned();
    meta.correlation_id = operation.to_owned();
    meta.trace_id = operation.to_owned();
    meta.deadline_ms = 10_000;
    meta
}

fn project_process_state(envelope: &ResourceEnvelope) -> Result<WorkerState, WorkerEffectError> {
    let attempts = envelope
        .status()
        .resource()
        .get("restartCount")
        .and_then(|value| match value {
            CanonicalJsonValue::Integer(value) => u8::try_from(*value).ok(),
            _ => None,
        })
        .unwrap_or(0);
    Ok(match envelope.status().phase() {
        ResourcePhase::Ready => WorkerState::Ready {
            generation: envelope
                .status()
                .observed_generation()
                .get()
                .max(envelope.metadata().generation().get())
                .max(1),
        },
        ResourcePhase::Failed | ResourcePhase::Degraded => WorkerState::Failed { attempts },
        ResourcePhase::Deleted => WorkerState::Terminal { deleted: true },
        ResourcePhase::Succeeded => WorkerState::Terminal { deleted: false },
        ResourcePhase::Pending | ResourcePhase::Unknown => WorkerState::Starting,
    })
}

fn metadata_deletion_requested(bytes: &[u8]) -> bool {
    let Ok(CanonicalJsonValue::Object(root)) = CanonicalJsonValue::parse(bytes) else {
        return false;
    };
    matches!(
        root.get("metadata")
            .and_then(CanonicalJsonValue::as_object)
            .and_then(|metadata| metadata.get("deletionRequestedAt")),
        Some(value) if !matches!(value, CanonicalJsonValue::Null)
    )
}

fn durable_envelope_matches(
    envelope: &ResourceEnvelope,
    role: DisplayProcessRole,
    process_ref: &ResourceRef,
    zone: &ZoneId,
    owner_ref: &ResourceRef,
    owner_uid: &ResourceUid,
    expected_execution_ref: &ResourceRef,
) -> bool {
    let expected_provider = match role {
        DisplayProcessRole::HostProxy => "system-minijail",
        DisplayProcessRole::GuestFrontend => "system-systemd",
    };
    let expected_template = match role {
        DisplayProcessRole::HostProxy => "wayland-proxy-worker",
        DisplayProcessRole::GuestFrontend => "wayland-frontend-worker",
    };
    let Ok(process) =
        serde_json::from_slice::<ProcessSpec>(&envelope.spec().base().to_canonical_bytes())
    else {
        return false;
    };
    envelope.resource_type().as_str() == "Process"
        && ResourceRef::new(
            envelope.resource_type().clone(),
            envelope.metadata().name().clone(),
        ) == *process_ref
        && envelope.metadata().zone() == zone
        && envelope.metadata().owner_ref() == Some(owner_ref)
        && envelope.metadata().generation().get() != 0
        && envelope.spec().provider_ref().is_some_and(|provider| {
            provider.resource_type().as_str() == "Provider"
                && provider.name().as_str() == expected_provider
        })
        && process.execution().execution_ref() == expected_execution_ref
        && process.execution().template().as_str() == expected_template
        && !owner_uid.as_str().is_empty()
}

fn durable_endpoint_matches(
    envelope: &ResourceEnvelope,
    role: DisplayProcessRole,
    endpoint_ref: &ResourceRef,
    zone: &ZoneId,
    owner_ref: &ResourceRef,
    owner_uid: &ResourceUid,
    producer_ref: &ResourceRef,
) -> bool {
    let Ok(endpoint) = serde_json::from_slice::<EndpointSpec>(
        &envelope
            .spec()
            .base_with_provider_ref()
            .to_canonical_bytes(),
    ) else {
        return false;
    };
    let expected = match role {
        DisplayProcessRole::HostProxy => (
            EndpointClass::Data,
            EndpointTransport::FdAttachment,
            "wayland-cross-domain",
            "display-wayland-data-v3",
        ),
        DisplayProcessRole::GuestFrontend => (
            EndpointClass::Transport,
            EndpointTransport::Vsock,
            "guest-cross-domain",
            "guest-frontend-v3",
        ),
    };
    envelope.resource_type().as_str() == "Endpoint"
        && ResourceRef::new(
            envelope.resource_type().clone(),
            envelope.metadata().name().clone(),
        ) == *endpoint_ref
        && envelope.metadata().zone() == zone
        && envelope.metadata().owner_ref() == Some(owner_ref)
        && endpoint.provider_ref().to_canonical_string() == "Provider/display-wayland"
        && endpoint.producer_ref() == producer_ref
        && endpoint.endpoint_class() == expected.0
        && endpoint.transport() == expected.1
        && endpoint.purpose().as_str() == expected.2
        && endpoint
            .service_fingerprint()
            .is_some_and(|value| value.as_str() == expected.3)
        && endpoint.locality() == EndpointLocality::CrossDomain
        && endpoint.visibility() == EndpointVisibility::Zone
        && endpoint.consumer_policy().allowed_operations() == [EndpointOperation::Resolve]
        && endpoint.lifecycle_policy() == EndpointLifecyclePolicy::RecycleWithProducer
        && !owner_uid.as_str().is_empty()
}

fn endpoint_record_from_response(
    endpoint_ref: ResourceRef,
    resource: wire::ResourceEnvelopeBytes,
    role: DisplayProcessRole,
    zone: &ZoneId,
    owner_ref: &ResourceRef,
    owner_uid: &ResourceUid,
    producer_ref: &ResourceRef,
) -> Result<DurableDisplayEndpoint, WorkerEffectError> {
    let envelope = ResourceEnvelope::from_json(&resource.canonical_json)
        .map_err(|_| WorkerEffectError::WorkerUnavailable)?;
    if !durable_endpoint_matches(
        &envelope,
        role,
        &endpoint_ref,
        zone,
        owner_ref,
        owner_uid,
        producer_ref,
    ) {
        return Err(WorkerEffectError::LaunchRejected);
    }
    let generation = envelope
        .status()
        .resource()
        .get("endpointGeneration")
        .and_then(|value| match value {
            CanonicalJsonValue::Integer(value) => u64::try_from(*value).ok(),
            _ => None,
        })
        .unwrap_or(0);
    Ok(DurableDisplayEndpoint {
        resource_ref: endpoint_ref,
        resource_uid: envelope.metadata().uid().clone(),
        revision: envelope.metadata().revision().get(),
        generation,
        deletion_requested: metadata_deletion_requested(&resource.canonical_json),
    })
}

fn durable_record_from_response(
    process_ref: ResourceRef,
    resource: wire::ResourceEnvelopeBytes,
    role: DisplayProcessRole,
    expected_policy_generation: u64,
    zone: &ZoneId,
    owner_ref: &ResourceRef,
    owner_uid: &ResourceUid,
    expected_execution_ref: &ResourceRef,
) -> Result<(WorkerState, DurableDisplayProcess), WorkerEffectError> {
    let envelope = ResourceEnvelope::from_json(&resource.canonical_json)
        .map_err(|_| WorkerEffectError::WorkerUnavailable)?;
    if !durable_envelope_matches(
        &envelope,
        role,
        &process_ref,
        zone,
        owner_ref,
        owner_uid,
        expected_execution_ref,
    ) {
        return Err(WorkerEffectError::LaunchRejected);
    }
    let state = if display_policy_generation(&resource.canonical_json)
        == Some(expected_policy_generation)
    {
        project_process_state(&envelope)?
    } else {
        WorkerState::Starting
    };
    Ok((
        state,
        DurableDisplayProcess {
            resource_ref: process_ref,
            resource_uid: envelope.metadata().uid().clone(),
            generation: envelope.metadata().generation().get(),
            revision: envelope.metadata().revision().get(),
            restart_count: process_restart_count(&resource.canonical_json),
            deletion_requested: metadata_deletion_requested(&resource.canonical_json),
        },
    ))
}

fn display_policy_generation(bytes: &[u8]) -> Option<u64> {
    let value = CanonicalJsonValue::parse(bytes).ok()?;
    let CanonicalJsonValue::Object(root) = value else {
        return None;
    };
    let CanonicalJsonValue::Object(metadata) = root.get("metadata")? else {
        return None;
    };
    let CanonicalJsonValue::Object(annotations) = metadata.get("annotations")? else {
        return None;
    };
    let CanonicalJsonValue::String(value) = annotations.get(PROCESS_RESTART_ANNOTATION)? else {
        return None;
    };
    value.parse().ok()
}

fn process_restart_count(bytes: &[u8]) -> u64 {
    let Ok(CanonicalJsonValue::Object(root)) = CanonicalJsonValue::parse(bytes) else {
        return 0;
    };
    let Some(CanonicalJsonValue::Object(status)) = root.get("status") else {
        return 0;
    };
    let Some(CanonicalJsonValue::Object(resource)) = status.get("resource") else {
        return 0;
    };
    match resource.get("restartCount") {
        Some(CanonicalJsonValue::Integer(value)) => u64::try_from(*value).unwrap_or(0),
        _ => 0,
    }
}

fn update_display_policy_annotation(
    bytes: &[u8],
    policy_generation: u64,
) -> Result<Vec<u8>, WorkerEffectError> {
    let mut value =
        CanonicalJsonValue::parse(bytes).map_err(|_| WorkerEffectError::WorkerUnavailable)?;
    let CanonicalJsonValue::Object(root) = &mut value else {
        return Err(WorkerEffectError::WorkerUnavailable);
    };
    let Some(CanonicalJsonValue::Object(metadata)) = root.get_mut("metadata") else {
        return Err(WorkerEffectError::WorkerUnavailable);
    };
    if !metadata.contains_key("annotations") {
        metadata.insert(
            "annotations".to_owned(),
            CanonicalJsonValue::Object(BTreeMap::new()),
        );
    }
    let Some(CanonicalJsonValue::Object(annotations)) = metadata.get_mut("annotations") else {
        return Err(WorkerEffectError::WorkerUnavailable);
    };
    annotations.insert(
        PROCESS_RESTART_ANNOTATION.to_owned(),
        CanonicalJsonValue::String(policy_generation.to_string()),
    );
    Ok(value.to_canonical_bytes())
}

fn run_effect<T, F, Fut>(operation: F) -> Result<T, WorkerEffectError>
where
    T: Send + 'static,
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, WorkerEffectError>> + Send + 'static,
{
    thread::Builder::new()
        .name("d2bd-provider-effect".to_owned())
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| WorkerEffectError::WorkerUnavailable)?
                .block_on(operation())
        })
        .map_err(|_| WorkerEffectError::WorkerUnavailable)?
        .join()
        .map_err(|_| WorkerEffectError::WorkerUnavailable)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use d2b_contracts_resource::v3::ResourceGeneration;
    use d2b_contracts_zone_session::v3::component_session::RequestId;
    use d2b_process::{
        BackendLaunch, BackendObservation, ObservedIdentity, ProcessEffectBackend,
        ProcessEffectError, ProcessRequest, ProcessStopClass, WaitReapOwner,
    };
    use d2b_process_conformance::IdentityBinding;
    use d2b_provider_supervisor::ProviderSupervisor;
    use d2b_resource_api::authz::{
        ApiCatalog, BindingScope, BoundSubject, CompiledRole, CompiledRoleBinding,
        NativeAuthorizer, PolicyRule, PolicySet, SessionVerb,
    };
    use d2b_resource_store::PolicySnapshot;
    use d2b_session::ComponentSessionDriver;
    use d2b_session_unix::DescriptorPolicyResolver;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone, Default)]
    struct Backend {
        launches: std::sync::Arc<AtomicUsize>,
        observes: std::sync::Arc<AtomicUsize>,
        stops: std::sync::Arc<AtomicUsize>,
        requests: std::sync::Arc<std::sync::Mutex<Vec<ProcessRequest>>>,
    }

    impl ProcessEffectBackend for Backend {
        type Handle = ();

        fn launch(
            &self,
            request: ProcessRequest,
        ) -> Result<BackendLaunch<Self::Handle>, ProcessEffectError> {
            self.requests.lock().unwrap().push(request);
            let seed = self.launches.fetch_add(1, Ordering::AcqRel) as u8 + 1;
            Ok(BackendLaunch::new(
                BackendObservation::new(
                    ProcessIdentityDigest::from_bytes([seed; 32]),
                    ObservedIdentity::from_verified([IdentityBinding::Cgroup]),
                    WaitReapOwner::Local,
                ),
                (),
            ))
        }

        fn observe(
            &self,
            _request: ProcessRequest,
        ) -> Result<Option<BackendObservation>, ProcessEffectError> {
            self.observes.fetch_add(1, Ordering::AcqRel);
            Ok(None)
        }

        fn open_pidfd(
            &self,
            _observation: BackendObservation,
        ) -> Result<Self::Handle, ProcessEffectError> {
            Ok(())
        }

        fn stop(
            &self,
            _handle: &Self::Handle,
            _class: ProcessStopClass,
        ) -> Result<(), ProcessEffectError> {
            self.stops.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
    }

    type TestInteractionRuntime =
        Arc<AsyncMutex<Option<InteractionRuntimeSet<ProviderSupervisor<Backend>>>>>;

    #[test]
    fn durable_display_process_payloads_bind_owner_provider_template_and_target() {
        let supervisor = d2b_provider_supervisor::ProviderSupervisor::new(Backend::default());
        let mut effects = DisplaySupervisorEffects::new(supervisor);
        effects.resource_zone = Some(ZoneId::parse("work").unwrap());
        effects.wayland_session_ref = Some(
            ResourceRef::parse("display-wayland.d2bus.org.WaylandSession/display-wayland").unwrap(),
        );
        effects.wayland_session_uid =
            Some(ResourceUid::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap());
        effects.host_execution_ref = Some(ResourceRef::parse("Host/host-system").unwrap());
        effects.guest_subject = Some(ResourceRef::parse("Guest/work").unwrap());
        effects.session_digest = [42; 32];

        let host_ticket = d2b_provider_display_wayland::LaunchTicket::new_for_daemon(
            DisplayProcessRole::HostProxy,
            Some(d2b_provider_display_wayland::AttachmentGrantHandle::from_daemon([1; 32])),
            d2b_provider_display_wayland::AttachmentGrantHandle::from_daemon([2; 32]),
            "sha256:".to_owned() + &"a".repeat(64),
            7,
            "session",
            3,
        )
        .unwrap();
        let guest_ticket = d2b_provider_display_wayland::LaunchTicket::new_for_daemon(
            DisplayProcessRole::GuestFrontend,
            None,
            d2b_provider_display_wayland::AttachmentGrantHandle::from_daemon([3; 32]),
            "sha256:".to_owned() + &"b".repeat(64),
            7,
            "session",
            3,
        )
        .unwrap();
        let host_binding = DisplayLaunchBinding::from_ticket(host_ticket);
        let guest_binding = DisplayLaunchBinding::from_ticket(guest_ticket);

        let host_payload = serde_json::from_slice::<serde_json::Value>(
            &effects
                .durable_process_payload(DisplayProcessRole::HostProxy, &host_binding)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            host_payload["metadata"]["ownerRef"],
            "display-wayland.d2bus.org.WaylandSession/display-wayland"
        );
        assert_eq!(
            host_payload["spec"]["providerRef"],
            "Provider/system-minijail"
        );
        assert_eq!(host_payload["spec"]["executionRef"], "Host/host-system");
        assert_eq!(host_payload["spec"]["template"], "wayland-proxy-worker");

        let guest_payload = serde_json::from_slice::<serde_json::Value>(
            &effects
                .durable_process_payload(DisplayProcessRole::GuestFrontend, &guest_binding)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            guest_payload["spec"]["providerRef"],
            "Provider/system-systemd"
        );
        assert_eq!(guest_payload["spec"]["executionRef"], "Guest/work");
        assert_eq!(guest_payload["spec"]["template"], "wayland-frontend-worker");
        assert_ne!(
            effects
                .durable_process_ref(DisplayProcessRole::HostProxy)
                .unwrap(),
            effects
                .durable_process_ref(DisplayProcessRole::GuestFrontend)
                .unwrap()
        );
    }

    #[test]
    fn durable_display_process_names_survive_reconnects() {
        let owner_uid =
            ResourceUid::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("owner uid");
        let host = durable_display_suffix(&owner_uid, DisplayProcessRole::HostProxy);
        let guest = durable_display_suffix(&owner_uid, DisplayProcessRole::GuestFrontend);

        assert_eq!(
            host,
            durable_display_suffix(&owner_uid, DisplayProcessRole::HostProxy)
        );
        assert_eq!(
            guest,
            durable_display_suffix(&owner_uid, DisplayProcessRole::GuestFrontend)
        );
        assert_ne!(host, guest);
    }

    #[test]
    fn display_runner_child_intents_keep_stream_authority_out_of_resources() {
        let zone = ZoneId::parse("work").expect("zone");
        let session_ref =
            ResourceRef::parse("display-wayland.d2bus.org.WaylandSession/display-wayland")
                .expect("session ref");
        let session_uid =
            ResourceUid::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("session uid");
        let spec = WaylandSessionSpec::new(
            ResourceRef::parse("Guest/work").expect("guest"),
            ResourceRef::parse("Host/host-system").expect("host"),
            ResourceRef::parse("User/alice").expect("user"),
            ResourceRef::parse("display-wayland.d2bus.org.WaylandPolicy/default")
                .expect("policy"),
            d2b_provider_display_wayland::DisplayIdentity::new(
                "work",
                "#112233",
                "#223344",
                "#334455",
            )
            .expect("identity"),
            true,
        )
        .expect("session spec");
        let intents = display_owned_child_intents(
            &zone,
            &session_ref,
            &session_uid,
            &spec,
            4,
            3,
        );
        let intents = intents.expect("display child intents");
        assert_eq!(intents.len(), 4);
        assert_eq!(
            intents
                .iter()
                .filter(|intent| intent.target().resource_type().as_str() == "Process")
                .count(),
            2
        );
        assert_eq!(
            intents
                .iter()
                .filter(|intent| intent.target().resource_type().as_str() == "Endpoint")
                .count(),
            2
        );
        for intent in intents {
            let value: serde_json::Value =
                serde_json::from_slice(intent.canonical_resource()).expect("child resource");
            assert_eq!(
                value["metadata"]["ownerRef"],
                session_ref.to_canonical_string()
            );
            assert!(
                !value.to_string().contains("WAYLAND_DISPLAY")
                    && !value.to_string().contains("NIRI_SOCKET")
            );
        }
    }

    #[test]
    fn resource_operation_ids_are_valid_bounded_api_ids() {
        let zone = ZoneId::parse("work").expect("zone");
        let resource_ref =
            ResourceRef::parse("display-wayland.d2bus.org.WaylandSession/display-wayland")
                .expect("resource ref");
        let operation = resource_operation_id("display-process-create", &zone, &resource_ref);
        assert!(OperationId::parse(operation.clone()).is_ok());
        assert!(!operation.contains('/'));
        assert!(operation.len() <= 128);
        let first = resource_operation_id_with_key(
            "display-endpoint-delete",
            &zone,
            &resource_ref,
            b"uid-a:1",
        );
        let retry = resource_operation_id_with_key(
            "display-endpoint-delete",
            &zone,
            &resource_ref,
            b"uid-a:1",
        );
        let changed_revision = resource_operation_id_with_key(
            "display-endpoint-delete",
            &zone,
            &resource_ref,
            b"uid-a:2",
        );
        assert_eq!(first, retry);
        assert_ne!(first, changed_revision);
        assert!(OperationId::parse(first).is_ok());
    }

    #[test]
    fn durable_display_policy_annotation_is_canonical_and_fenced() {
        let original = br#"{"metadata":{"annotations":{"existing":"keep"}}}"#;
        let updated = update_display_policy_annotation(original, 17).expect("annotation update");
        let value = CanonicalJsonValue::parse(&updated).expect("canonical metadata");

        assert_eq!(display_policy_generation(&updated), Some(17));
        assert_eq!(
            value
                .as_object()
                .and_then(|root| root.get("metadata"))
                .and_then(CanonicalJsonValue::as_object)
                .and_then(|metadata| metadata.get("annotations"))
                .and_then(CanonicalJsonValue::as_object)
                .and_then(|annotations| annotations.get("existing")),
            Some(&CanonicalJsonValue::String("keep".to_owned()))
        );
    }

    #[test]
    fn display_stop_is_idempotent_when_worker_was_already_adopted_elsewhere() {
        let supervisor = d2b_provider_supervisor::ProviderSupervisor::new(Backend::default());
        let mut effects = DisplaySupervisorEffects::new(supervisor);
        effects.policy_generation = 1;
        effects.teardown_generation = 1;
        effects.session_digest = [9; 32];

        let receipt = effects.stop(DisplayProcessRole::GuestFrontend).unwrap();

        assert_eq!(receipt.state(), WorkerState::Terminal { deleted: true });
        assert_eq!(effects.live_worker_count(), 0);
    }

    #[test]
    fn interaction_response_is_a_correlated_ttrpc_response() {
        let frame = encode_interaction_response(41, TtrpcCode::OK, b"{\"ok\":true}".to_vec())
            .expect("response encoding");
        assert!(d2b_session::ttrpc_is_response(&frame));
        assert_eq!(d2b_session::ttrpc_stream_id(&frame).unwrap(), 41);
        let header = MessageHeader::from(&frame[..ttrpc::proto::MESSAGE_HEADER_LENGTH]);
        let response =
            TtrpcResponse::parse_from_bytes(&frame[ttrpc::proto::MESSAGE_HEADER_LENGTH..])
                .expect("response protobuf");
        assert_eq!(header.stream_id, 41);
        assert_eq!(response.status().code(), TtrpcCode::OK);
        assert_eq!(response.payload, b"{\"ok\":true}");
    }

    #[test]
    fn interaction_listener_policy_binds_service_and_transport() {
        let policy = interaction_endpoint_policy(d2b_provider_display_wayland::SERVICE_PACKAGE, 7)
            .expect("display policy");
        assert_eq!(policy.service, ServicePackage::DisplayV3,);
        assert_eq!(policy.reconnect_generation, 7);
        assert_eq!(
            policy.transport_binding.transport,
            TransportClass::UnixSeqpacket,
        );
        assert_eq!(
            interaction_endpoint_policy(PROCESS_ATTACH_SERVICE, 7)
                .expect("Process attach policy")
                .service,
            ServicePackage::ProviderV3,
        );
        assert_eq!(
            interaction_endpoint_policy(SHELL_SESSION_SERVICE, 7)
                .expect("shell supervisor policy")
                .service,
            ServicePackage::ProviderV3,
        );
    }

    #[test]
    fn clipboard_attachment_admission_matches_provider_safe_descriptor_kinds() {
        use d2b_contracts_zone_session::v3::component_session::KernelObjectType;

        for object_type in [
            KernelObjectType::UnixStreamSocket,
            KernelObjectType::UnixSeqpacketSocket,
            KernelObjectType::PipeRead,
            KernelObjectType::PipeWrite,
            KernelObjectType::Memfd,
            KernelObjectType::RegularFile,
        ] {
            assert!(clipboard_attachment_object_type_allowed(object_type));
        }
        for object_type in [
            KernelObjectType::Pidfd,
            KernelObjectType::Directory,
            KernelObjectType::Device,
            KernelObjectType::WaylandSocket,
        ] {
            assert!(!clipboard_attachment_object_type_allowed(object_type));
        }
    }

    #[test]
    fn listener_stop_removes_daemon_owned_socket_paths() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("interaction.sock");
        let listener = bind_interaction_listener(&path, rustix::process::geteuid().as_raw())
            .expect("listener socket");
        drop(listener);
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        let listeners = InteractionListenerSet {
            paths: vec![path.clone()],
            socket_identities: vec![(metadata.dev(), metadata.ino())],
            parent_identities: {
                let parent = std::fs::symlink_metadata(directory.path()).unwrap();
                vec![(parent.dev(), parent.ino())]
            },
            stop: Arc::new(AtomicBool::new(false)),
            threads: Mutex::new(Vec::new()),
            handlers: Arc::new(Mutex::new(Vec::new())),
        };

        assert!(path.exists());
        listeners.stop();
        assert!(!path.exists());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn process_session_lookup_owns_named_stream_and_disconnects_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let zone = ZoneId::parse("work").unwrap();
        let uid = nix::unistd::getuid().as_raw();
        let runtime = Arc::new(AsyncMutex::new(Some(test_interaction_runtime(&zone, uid))));
        let display_path = directory.path().join("display.sock");
        let display_listener = bind_interaction_listener(&display_path, uid).unwrap();
        let (display_client, display_server) = establish_test_client(
            &display_listener,
            &runtime,
            &zone,
            d2b_provider_display_wayland::SERVICE_PACKAGE,
            uid,
            &display_path,
        )
        .await;
        let process_path = directory.path().join("process.sock");
        let process_listener = bind_interaction_listener(&process_path, uid).unwrap();
        let (process_client, process_server) = establish_test_client(
            &process_listener,
            &runtime,
            &zone,
            PROCESS_ATTACH_SERVICE,
            uid,
            &process_path,
        )
        .await;
        for _ in 0..50 {
            if runtime
                .lock()
                .await
                .as_ref()
                .and_then(|set| set.runtime_for(&zone))
                .is_some_and(|composition| composition.session_count() == 2)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let target = ResourceRef::parse(&format!("Guest/uid-{uid}")).unwrap();
        let display_target = ResourceRef::parse("Host/host-system").unwrap();
        let missing = ResourceRef::parse("Guest/missing").unwrap();
        let guard = runtime.lock().await;
        let composition = guard
            .as_ref()
            .and_then(|set| set.runtime_for(&zone))
            .expect("runtime");
        assert!(
            composition
                .component_session_driver_for_target(PROCESS_ATTACH_SERVICE, &target,)
                .is_some(),
            "the enrolled Process session must expose its real driver"
        );
        assert!(
            composition
                .component_session_driver_for_target(
                    d2b_provider_display_wayland::SERVICE_PACKAGE,
                    &target,
                )
                .is_none(),
            "the display session must not own the Process target"
        );
        assert!(
            composition
                .component_session_driver_for_target(PROCESS_ATTACH_SERVICE, &display_target,)
                .is_none(),
            "a display-only target must not be treated as a Process source"
        );
        assert!(
            composition
                .component_session_driver_for_target(PROCESS_ATTACH_SERVICE, &missing,)
                .is_none(),
            "an absent target must remain fail-closed"
        );
        drop(guard);

        let stream = d2b_session::StreamId::new(0x101).unwrap();
        process_client
            .open_named_stream(stream, 64, 64)
            .await
            .unwrap();
        display_client
            .open_named_stream(stream, 64, 64)
            .await
            .unwrap();
        let process_driver = {
            let guard = runtime.lock().await;
            guard
                .as_ref()
                .and_then(|set| set.runtime_for(&zone))
                .and_then(|composition| {
                    composition.component_session_driver_for_target(PROCESS_ATTACH_SERVICE, &target)
                })
                .expect("Process session driver")
        };
        process_driver
            .open_named_stream(stream, 64, 64)
            .await
            .unwrap();
        process_driver
            .send_named_stream(stream, b"process-owner".to_vec())
            .await
            .unwrap();
        let event = tokio::time::timeout(
            Duration::from_secs(1),
            process_client.receive_named_stream(),
        )
        .await
        .expect("Process stream data timeout")
        .unwrap();
        assert!(matches!(
            event,
            d2b_session::StreamEvent::Data {
                stream: received,
                bytes
            } if received == stream && bytes == b"process-owner"
        ));
        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                display_client.receive_named_stream(),
            )
            .await
            .is_err(),
            "display interaction session must not receive Process data"
        );

        process_driver.reset_named_stream(stream).await.unwrap();
        let event = tokio::time::timeout(
            Duration::from_secs(1),
            process_client.receive_named_stream(),
        )
        .await
        .expect("Process stream reset timeout")
        .unwrap();
        assert!(matches!(
            event,
            d2b_session::StreamEvent::Reset { stream: received } if received == stream
        ));

        drop(process_client);
        for _ in 0..1_000 {
            if runtime
                .lock()
                .await
                .as_ref()
                .and_then(|set| set.runtime_for(&zone))
                .is_some_and(|composition| composition.session_count() == 1)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let guard = runtime.lock().await;
        let composition = guard
            .as_ref()
            .and_then(|set| set.runtime_for(&zone))
            .expect("runtime");
        assert!(
            composition
                .component_session_driver_for_target(PROCESS_ATTACH_SERVICE, &target)
                .is_none(),
            "a disconnected Process source must be removed rather than reused"
        );
        drop(guard);
        display_server.abort();
        process_server.abort();
        drop(display_listener);
        drop(process_listener);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn process_session_lookup_waits_for_runtime_contention() {
        let directory = tempfile::tempdir().unwrap();
        let zone = ZoneId::parse("work").unwrap();
        let uid = nix::unistd::getuid().as_raw();
        let runtime = Arc::new(AsyncMutex::new(Some(test_interaction_runtime(&zone, uid))));
        let path = directory.path().join("process.sock");
        let listener = bind_interaction_listener(&path, uid).unwrap();
        let (client, server) = establish_test_client(
            &listener,
            &runtime,
            &zone,
            PROCESS_ATTACH_SERVICE,
            uid,
            &path,
        )
        .await;
        for _ in 0..50 {
            if runtime
                .lock()
                .await
                .as_ref()
                .and_then(|set| set.runtime_for(&zone))
                .is_some_and(|composition| composition.session_count() == 1)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let target = ResourceRef::parse(&format!("Guest/uid-{uid}")).unwrap();
        let guard = runtime.lock().await;
        let lookup_runtime = Arc::clone(&runtime);
        let mut lookup = tokio::spawn(async move {
            tokio::task::spawn_blocking(move || {
                blocking_component_session_driver_for_service(
                    &lookup_runtime,
                    PROCESS_ATTACH_SERVICE,
                    &target,
                )
            })
            .await
            .unwrap()
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut lookup)
                .await
                .is_err(),
            "runtime contention must not be reported as an absent source"
        );
        drop(guard);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), &mut lookup)
                .await
                .expect("lookup release timeout")
                .expect("lookup task failed")
                .is_some(),
            "the enrolled Process source must resolve after contention clears"
        );
        client
            .close(
                d2b_contracts_zone_session::v3::component_session::CloseReason::Normal,
                d2b_contracts_zone_session::v3::component_session::Remediation::None,
            )
            .await
            .unwrap();
        server.abort();
        drop(listener);
    }

    fn test_interaction_composition(
        zone: &ZoneId,
        uid: u32,
    ) -> InteractionComposition<ProviderSupervisor<Backend>> {
        test_interaction_composition_with_identity(
            zone,
            uid,
            ResourceRef::parse(&format!("Guest/uid-{uid}")).unwrap(),
            unix_guest_subject_uid(uid),
            ResourceRef::parse("Host/host-system").unwrap(),
            ResourceRef::parse(&format!("User/uid-{uid}")).unwrap(),
            1,
            Some(1),
            Some(1),
            1,
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn test_interaction_composition_with_identity(
        zone: &ZoneId,
        transport_uid: u32,
        subject_ref: ResourceRef,
        subject_uid: ResourceUid,
        host_execution_ref: ResourceRef,
        observer_user_ref: ResourceRef,
        display_generation: u64,
        clipboard_generation: Option<u64>,
        notification_generation: Option<u64>,
        controller_generation: u64,
        clipboard_provider_uid: Option<ResourceUid>,
        notification_provider_uid: Option<ResourceUid>,
    ) -> InteractionComposition<ProviderSupervisor<Backend>> {
        let catalog = ApiCatalog::standard();
        let role = CompiledRole::new(
            ResourceRef::parse("Role/interaction-provider").expect("role reference"),
            vec![
                PolicyRule::new(
                    &catalog,
                    [],
                    [],
                    [
                        SessionVerb::Connect,
                        SessionVerb::Invoke,
                        SessionVerb::OpenStream,
                        SessionVerb::Cancel,
                        SessionVerb::Observe,
                        SessionVerb::AuditExport,
                        SessionVerb::SupportBundle,
                    ],
                    [],
                    [],
                    [zone.clone()],
                    [],
                )
                .expect("interaction policy rule"),
            ],
        )
        .expect("interaction role");
        let mut bound_subjects = vec![BoundSubject {
            subject_ref: subject_ref.clone(),
            subject_uid: subject_uid.clone(),
        }];
        if let Some(provider_uid) = clipboard_provider_uid.as_ref() {
            bound_subjects.push(BoundSubject {
                subject_ref: ResourceRef::parse("Provider/clipboard-wayland").unwrap(),
                subject_uid: provider_uid.clone(),
            });
        }
        if let Some(provider_uid) = notification_provider_uid.as_ref() {
            bound_subjects.push(BoundSubject {
                subject_ref: ResourceRef::parse("Provider/notification-desktop").unwrap(),
                subject_uid: provider_uid.clone(),
            });
        }
        let binding = CompiledRoleBinding::new(
            role.role_ref.clone(),
            bound_subjects,
            BindingScope::default(),
            d2b_resource_api::authz::RelayGrantAuthority::None,
        )
        .expect("interaction role binding");
        let policy = PolicySet::new(&catalog, display_generation, vec![role], vec![binding])
            .expect("interaction policy");
        let authorizer = BusAuthorizer::new(
            NativeAuthorizer::new(catalog, Some(policy)).unwrap(),
            d2b_resource_api::authz::AuthorizationState {
                snapshot: PolicySnapshot {
                    policy_revision: display_generation,
                    api_catalog_revision: 1,
                    active_configuration_revision:
                        d2b_contracts_resource::v3::ConfigurationGeneration::new(display_generation)
                            .unwrap(),
                    controller_generation: Some(
                        d2b_contracts_resource::v3::ControllerGeneration::new(
                            controller_generation,
                        )
                        .unwrap(),
                    ),
                },
                zone_policy_revision: ZoneRevision::new(display_generation),
                bootstrap_phase: BootstrapPhase::Disabled,
                now_tick: 1,
            },
        )
        .unwrap();
        let (_bus, registrar, issuer) =
            ZoneBus::with_clock_observer_and_metrics_and_interaction_subject_issuer(
                zone.clone(),
                authorizer,
                BusConfig::default(),
                Arc::new(d2b_bus::ManualClock::new(1)),
                Arc::new(d2b_bus::NoopBusObserver),
                Arc::new(d2b_bus::metrics::NoopBusTelemetry),
            )
            .unwrap();
        let interaction_identity = CommittedInteractionIdentity::for_test(
            zone.clone(),
            subject_ref.clone(),
            subject_uid.clone(),
            host_execution_ref.clone(),
            observer_user_ref.clone(),
            BTreeMap::from([(subject_ref.clone(), subject_uid.clone())]),
            ResourceGeneration::new(display_generation).unwrap(),
            clipboard_generation.map(|generation| ResourceGeneration::new(generation).unwrap()),
            clipboard_provider_uid.clone(),
            notification_generation.map(|generation| ResourceGeneration::new(generation).unwrap()),
            notification_provider_uid.clone(),
        );
        registrar
            .install_committed_interaction_subject(
                interaction_identity
                    .seal_interaction_subject_install(issuer, transport_uid)
                    .unwrap(),
            )
            .unwrap();
        let mut composition =
            InteractionComposition::new(registrar, ProviderSupervisor::new(Backend::default()));
        composition.bind_display_resource_evidence(
            CoreDisplayResourceEvidence::from_committed_policy(
                ResourceRef::parse("display-wayland.d2bus.org.WaylandPolicy/display-wayland")
                    .unwrap(),
                PolicySnapshot {
                    policy_revision: display_generation,
                    api_catalog_revision: 1,
                    active_configuration_revision:
                        d2b_contracts_resource::v3::ConfigurationGeneration::new(display_generation)
                            .unwrap(),
                    controller_generation: Some(
                        d2b_contracts_resource::v3::ControllerGeneration::new(
                            controller_generation,
                        )
                        .unwrap(),
                    ),
                },
                display_generation,
                FilterInput::default(),
                FilterInput::default(),
                DependencyState::ready().with_zone(zone.clone()),
                observer_user_ref.clone(),
                ZoneRevision::new(display_generation),
                true,
            )
            .unwrap(),
        );
        composition.bind_interaction_identity(&interaction_identity);
        composition
    }

    fn test_interaction_runtime(
        zone: &ZoneId,
        uid: u32,
    ) -> InteractionRuntimeSet<ProviderSupervisor<Backend>> {
        let mut runtimes = InteractionRuntimeSet::new();
        runtimes.insert(zone.clone(), test_interaction_composition(zone, uid));
        runtimes
    }

    fn committed_test_interaction_runtime(
        zone: &ZoneId,
        transport_uid: u32,
    ) -> InteractionRuntimeSet<ProviderSupervisor<Backend>> {
        let mut runtimes = InteractionRuntimeSet::new();
        runtimes.insert(
            zone.clone(),
            test_interaction_composition_with_identity(
                zone,
                transport_uid,
                ResourceRef::parse("Guest/work").unwrap(),
                ResourceUid::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap(),
                ResourceRef::parse("Host/host").unwrap(),
                ResourceRef::parse("User/alice").unwrap(),
                7,
                Some(11),
                Some(13),
                17,
                None,
                None,
            ),
        );
        runtimes
    }

    #[tokio::test(flavor = "current_thread")]
    async fn vm_start_display_reconcile_uses_the_committed_session_route() {
        let directory = tempfile::tempdir().expect("display reconciliation directory");
        let zone = ZoneId::parse("work").expect("zone");
        let uid = nix::unistd::getuid().as_raw();
        let runtime = Arc::new(AsyncMutex::new(Some(committed_test_interaction_runtime(
            &zone, uid,
        ))));
        let path = directory.path().join("display.sock");
        let listener = bind_interaction_listener(&path, uid).expect("display listener");
        let (_client, server) = establish_test_client(
            &listener,
            &runtime,
            &zone,
            d2b_provider_display_wayland::SERVICE_PACKAGE,
            uid,
            &path,
        )
        .await;
        for _ in 0..50 {
            if runtime
                .lock()
                .await
                .as_ref()
                .and_then(|set| set.runtime_for(&zone))
                .is_some_and(|composition| {
                    composition.has_service_session(d2b_provider_display_wayland::SERVICE_PACKAGE)
                })
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        let spec = WaylandSessionSpec::new(
            ResourceRef::parse("Guest/work").expect("guest"),
            ResourceRef::parse("Host/host").expect("host"),
            ResourceRef::parse("User/alice").expect("user"),
            ResourceRef::parse("display-wayland.d2bus.org.WaylandPolicy/display-wayland")
                .expect("policy"),
            d2b_provider_display_wayland::DisplayIdentity::new(
                "work", "#112233", "#223344", "#334455",
            )
            .expect("display identity"),
            true,
        )
        .expect("Wayland session");
        let session_ref =
            ResourceRef::parse("display-wayland.d2bus.org.WaylandSession/display-wayland")
                .expect("session ref");
        let session_uid =
            ResourceUid::parse("33333333-3333-4333-8333-333333333333").expect("session uid");

        let mut guard = runtime.lock().await;
        let composition = guard
            .as_mut()
            .and_then(|set| set.runtime_for_mut(&zone))
            .expect("committed interaction composition");
        let result = composition
            .reconcile_committed_display_for_vm_start("work", &session_ref, &session_uid, &spec)
            .expect("committed display reconciliation");
        assert_eq!(
            result.status.phase,
            d2b_provider_display_wayland::Phase::Ready
        );
        assert_eq!(result.worker_actions.len(), 0);
        assert_eq!(
            result.status.resource.proxy_process_ref, None,
            "the hermetic effect port has no Resource API; production must supply the durable projection"
        );
        assert!(
            composition
                .reconcile_committed_display_for_vm_start(
                    "other-vm",
                    &session_ref,
                    &session_uid,
                    &spec,
                )
                .is_err(),
            "a VM start for a different Guest must not reuse the committed session"
        );
        drop(guard);
        server.abort();
        drop(listener);
    }

    #[test]
    fn completed_display_finalization_discards_runtime_for_reconnect() {
        let zone = ZoneId::parse("dev").unwrap();
        let mut composition = test_interaction_composition(&zone, 42);
        composition.display = Some(DisplayRuntime::new(
            DisplayController::new(2),
            DisplaySupervisorEffects::new(ProviderSupervisor::new(Backend::default())),
        ));

        let report = composition
            .finalize(d2b_provider_display_wayland::GraceState::Active)
            .unwrap();

        assert!(report.decision.remove_finalizer);
        assert!(composition.display.is_none());
    }

    fn provider_bound_test_interaction_composition(
        zone: &ZoneId,
        transport_uid: u32,
        guest_sources: &[(&str, &str)],
    ) -> InteractionComposition<ProviderSupervisor<Backend>> {
        let first_guest = ResourceRef::parse(guest_sources[0].0).unwrap();
        let first_uid = ResourceUid::parse(guest_sources[0].1).unwrap();
        let clipboard_provider_uid =
            ResourceUid::parse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").unwrap();
        let notification_provider_uid =
            ResourceUid::parse("cccccccc-cccc-4ccc-8ccc-cccccccccccc").unwrap();
        let mut composition = test_interaction_composition_with_identity(
            zone,
            transport_uid,
            first_guest.clone(),
            first_uid.clone(),
            ResourceRef::parse("Host/host").unwrap(),
            ResourceRef::parse("User/alice").unwrap(),
            7,
            Some(11),
            Some(13),
            17,
            Some(clipboard_provider_uid.clone()),
            Some(notification_provider_uid.clone()),
        );
        let allowed_guest_sources = guest_sources
            .iter()
            .map(|(guest_ref, guest_uid)| {
                (
                    ResourceRef::parse(guest_ref).unwrap(),
                    ResourceUid::parse(*guest_uid).unwrap(),
                )
            })
            .collect();
        composition.bind_interaction_identity(&CommittedInteractionIdentity::for_test(
            zone.clone(),
            first_guest,
            first_uid,
            ResourceRef::parse("Host/host").unwrap(),
            ResourceRef::parse("User/alice").unwrap(),
            allowed_guest_sources,
            ResourceGeneration::new(7).unwrap(),
            Some(ResourceGeneration::new(11).unwrap()),
            Some(clipboard_provider_uid),
            Some(ResourceGeneration::new(13).unwrap()),
            Some(notification_provider_uid),
        ));
        composition
    }

    fn display_only_test_interaction_composition(
        zone: &ZoneId,
        transport_uid: u32,
    ) -> InteractionComposition<ProviderSupervisor<Backend>> {
        test_interaction_composition_with_identity(
            zone,
            transport_uid,
            ResourceRef::parse("Guest/work").unwrap(),
            ResourceUid::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap(),
            ResourceRef::parse("Host/host").unwrap(),
            ResourceRef::parse("User/alice").unwrap(),
            7,
            None,
            None,
            17,
            None,
            None,
        )
    }

    fn test_unix_transport(
        socket: SeqpacketSocket,
        peer: d2b_session_unix::PeerCredentials,
        policy: &EndpointPolicy,
    ) -> UnixSeqpacketTransport {
        let credits = CreditScopeSet::new(
            CreditPool::new(8).unwrap(),
            CreditPool::new(8).unwrap(),
            CreditPool::new(8).unwrap(),
            CreditPool::new(8).unwrap(),
            CreditPool::new(8).unwrap(),
            CreditPool::new(8).unwrap(),
        );
        let resolver: DescriptorPolicyResolver =
            Arc::new(|_| Err(UnixSessionError::DescriptorMismatch));
        UnixSeqpacketTransport::new(
            socket,
            TransportLocality::HostLocal,
            policy.limits,
            policy.attachment_policy,
            credits,
            resolver,
            PeerIdentityPolicy::accepted(peer),
        )
        .unwrap()
    }

    fn request_frame_for_test(
        service: &str,
        stream_id: u32,
        method: &str,
        request_payload: Vec<u8>,
    ) -> Vec<u8> {
        let request = TtrpcRequest {
            service: service.to_owned(),
            method: method.to_owned(),
            payload: request_payload,
            ..TtrpcRequest::default()
        };
        let payload = request.write_to_bytes().unwrap();
        let mut frame = Vec::from(MessageHeader::new_request(
            stream_id,
            u32::try_from(payload.len()).unwrap(),
        ));
        frame.extend_from_slice(&payload);
        frame
    }

    async fn establish_test_client(
        listener: &Socket,
        runtime: &TestInteractionRuntime,
        zone: &ZoneId,
        service: &str,
        uid: u32,
        path: &std::path::Path,
    ) -> (
        Arc<dyn ComponentSessionDriver>,
        tokio::task::JoinHandle<Result<(), String>>,
    ) {
        let client_socket =
            Socket::new(Domain::UNIX, Type::from(libc::SOCK_SEQPACKET), None).unwrap();
        client_socket
            .connect(&SockAddr::unix(path).unwrap())
            .expect("connect interaction listener");
        client_socket.set_nonblocking(true).unwrap();
        let accepted = loop {
            match accept_with(
                listener.as_fd(),
                SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            ) {
                Ok(accepted) => break accepted,
                Err(rustix::io::Errno::AGAIN) => thread::yield_now(),
                Err(error) => panic!("accept failed: {error}"),
            }
        };
        let server_runtime = Arc::clone(runtime);
        let server_zone = zone.clone();
        let server_service = service.to_owned();
        let server = tokio::spawn(async move {
            admit_interaction_socket(
                accepted,
                server_runtime,
                server_zone,
                server_service,
                uid,
                Arc::new(AtomicBool::new(false)),
            )
            .await
        });

        let policy = interaction_endpoint_policy(service, 1).unwrap();
        let client_seqpacket = SeqpacketSocket::from_owned(client_socket.into()).unwrap();
        let client_peer = client_seqpacket.acceptor_peer_credentials().unwrap();
        let transport = test_unix_transport(client_seqpacket, client_peer, &policy);
        let engine = tokio::time::timeout(
            Duration::from_secs(5),
            SessionEngine::establish_initiator(
                transport,
                policy,
                d2b_session::HandshakeCredentials::Nn,
                Instant::now(),
            ),
        )
        .await
        .expect("client handshake timeout")
        .unwrap_or_else(|error| panic!("client handshake failed for {service}: {error}"));
        (Arc::new(engine.into_driver()), server)
    }

    async fn dispatch_test_request(
        driver: &Arc<dyn ComponentSessionDriver>,
        service: &str,
        stream_id: u32,
        method: &str,
        request_payload: Vec<u8>,
    ) -> TtrpcResponse {
        let frame = request_frame_for_test(service, stream_id, method, request_payload);
        let request_id = d2b_session::ttrpc_request_id(1, &frame).unwrap();
        driver.start_ttrpc(request_id.clone(), frame).await.unwrap();
        let response = tokio::time::timeout(Duration::from_secs(5), driver.receive_ttrpc())
            .await
            .expect("interaction response timeout")
            .unwrap();
        assert!(driver.complete_ttrpc(request_id).await.unwrap());
        TtrpcResponse::parse_from_bytes(&response[ttrpc::proto::MESSAGE_HEADER_LENGTH..]).unwrap()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn hermetic_production_composition_dispatches_committed_interactions_and_ordered_shutdown()
     {
        let directory = tempfile::tempdir().unwrap();
        let zone = ZoneId::parse("work").unwrap();
        let uid = nix::unistd::getuid().as_raw();
        let runtime = Arc::new(AsyncMutex::new(Some(committed_test_interaction_runtime(
            &zone, uid,
        ))));
        let services = [
            d2b_provider_display_wayland::SERVICE_PACKAGE,
            d2b_provider_clipboard_wayland::BRIDGE_SERVICE,
            d2b_provider_clipboard_wayland::PICKER_SERVICE,
            d2b_provider_notification_desktop::SERVICE_PACKAGE,
        ];
        let mut clients = Vec::new();
        for service in services {
            let path = directory
                .path()
                .join(service.replace('.', "-"))
                .with_extension("sock");
            let listener = bind_interaction_listener(&path, uid).unwrap();
            let (client, server) =
                establish_test_client(&listener, &runtime, &zone, service, uid, &path).await;
            clients.push((service, path, listener, client, server));
        }
        {
            let guard = runtime.lock().await;
            let composition = guard
                .as_ref()
                .and_then(|set| set.runtime_for(&zone))
                .expect("committed interaction composition");
            let display_route = composition
                .route_for_service(d2b_provider_display_wayland::SERVICE_PACKAGE)
                .expect("display route");
            assert_eq!(
                display_route.subject_ref().to_canonical_string(),
                "Guest/work"
            );
            assert_eq!(
                display_route
                    .provider_generation()
                    .expect("display resource generation")
                    .get(),
                7
            );
            assert_eq!(
                display_route
                    .controller_generation()
                    .expect("controller generation")
                    .get(),
                17
            );
            assert_eq!(
                display_route
                    .context()
                    .execution_ref()
                    .expect("committed Host execution")
                    .to_canonical_string(),
                "Host/host"
            );
            let clipboard_route = composition
                .route_for_service(d2b_provider_clipboard_wayland::BRIDGE_SERVICE)
                .expect("clipboard route");
            assert_eq!(
                clipboard_route
                    .provider_generation()
                    .expect("clipboard resource generation")
                    .get(),
                11
            );
            let notification_route = composition
                .route_for_service(d2b_provider_notification_desktop::SERVICE_PACKAGE)
                .expect("notification route");
            assert_eq!(
                notification_route
                    .provider_generation()
                    .expect("notification resource generation")
                    .get(),
                13
            );
        }

        let (display_service, _, _, display, _) = &clients[0];
        let display_spec = WaylandSessionSpec::new(
            ResourceRef::parse("Guest/work").unwrap(),
            ResourceRef::parse("Host/host").unwrap(),
            ResourceRef::parse("User/alice").unwrap(),
            ResourceRef::parse("display-wayland.d2bus.org.WaylandPolicy/display-wayland").unwrap(),
            d2b_provider_display_wayland::DisplayIdentity::new(
                "test-display",
                "#112233",
                "#223344",
                "#334455",
            )
            .unwrap(),
            true,
        )
        .unwrap();
        let display_payload = serde_json::to_vec(&serde_json::json!({
            "spec": display_spec,
        }))
        .unwrap();
        let reconcile = dispatch_test_request(
            display,
            display_service,
            100,
            "DisplayService/Reconcile",
            display_payload,
        )
        .await;
        assert_eq!(reconcile.status().code(), TtrpcCode::OK);
        let wrong_user_spec = WaylandSessionSpec::new(
            ResourceRef::parse("Guest/work").unwrap(),
            ResourceRef::parse("Host/host").unwrap(),
            ResourceRef::parse("User/bob").unwrap(),
            ResourceRef::parse("display-wayland.d2bus.org.WaylandPolicy/display-wayland").unwrap(),
            d2b_provider_display_wayland::DisplayIdentity::new(
                "wrong-user-display",
                "#112233",
                "#223344",
                "#334455",
            )
            .unwrap(),
            true,
        )
        .unwrap();
        let wrong_user = dispatch_test_request(
            display,
            display_service,
            111,
            "DisplayService/Reconcile",
            serde_json::to_vec(&serde_json::json!({
                "spec": wrong_user_spec,
            }))
            .unwrap(),
        )
        .await;
        assert_eq!(wrong_user.status().code(), TtrpcCode::FAILED_PRECONDITION);
        let restart_reconcile = dispatch_test_request(
            display,
            display_service,
            112,
            "DisplayService/Reconcile",
            serde_json::to_vec(&serde_json::json!({
                "spec": display_spec,
            }))
            .unwrap(),
        )
        .await;
        assert_eq!(restart_reconcile.status().code(), TtrpcCode::OK);
        let restart_payload: serde_json::Value =
            serde_json::from_slice(&restart_reconcile.payload).unwrap();
        assert_eq!(restart_payload["phase"], "Ready");
        assert_eq!(restart_payload["worker_actions"], 0);
        let wrong_display_spec = WaylandSessionSpec::new(
            ResourceRef::parse("Guest/other").unwrap(),
            ResourceRef::parse("Host/host").unwrap(),
            ResourceRef::parse("User/alice").unwrap(),
            ResourceRef::parse("display-wayland.d2bus.org.WaylandPolicy/display-wayland").unwrap(),
            d2b_provider_display_wayland::DisplayIdentity::new(
                "wrong-display",
                "#112233",
                "#223344",
                "#334455",
            )
            .unwrap(),
            true,
        )
        .unwrap();
        let wrong_reconcile = dispatch_test_request(
            display,
            display_service,
            110,
            "DisplayService/Reconcile",
            serde_json::to_vec(&serde_json::json!({
                "spec": wrong_display_spec,
            }))
            .unwrap(),
        )
        .await;
        assert_eq!(
            wrong_reconcile.status().code(),
            TtrpcCode::FAILED_PRECONDITION
        );
        let observe = dispatch_test_request(
            display,
            display_service,
            101,
            "DisplayService/Observe",
            Vec::new(),
        )
        .await;
        assert_eq!(observe.status().code(), TtrpcCode::OK);
        assert!(
            String::from_utf8(observe.payload)
                .unwrap()
                .contains("\"ready\":true")
        );

        let (bridge_service, _, _, bridge, _) = &clients[1];
        let capture = dispatch_test_request(
            bridge,
            bridge_service,
            102,
            "ClipboardBridgeService/CaptureGuest",
            serde_json::to_vec(&serde_json::json!({
                "mime": "text/plain",
                "bytes": [99, 108, 105, 112],
                "now_secs": 100,
            }))
            .unwrap(),
        )
        .await;
        assert_eq!(capture.status().code(), TtrpcCode::OK);
        let capture_payload: serde_json::Value = serde_json::from_slice(&capture.payload).unwrap();
        let entry_digest = capture_payload["entry_digest"].as_str().unwrap().to_owned();

        let (picker_service, _, _, picker, _) = &clients[2];
        let completion_payload = serde_json::to_vec(&serde_json::json!({
            "entry_digest": entry_digest,
            "mime_types": ["text/plain"],
            "selected_digest": entry_digest,
            "now_secs": 101,
        }))
        .unwrap();
        let completion = dispatch_test_request(
            picker,
            picker_service,
            103,
            "ClipboardPickerService/Complete",
            completion_payload.clone(),
        )
        .await;
        assert_eq!(completion.status().code(), TtrpcCode::OK);
        let completion_value: serde_json::Value =
            serde_json::from_slice(&completion.payload).unwrap();
        let operation_id = completion_value["operation_id"].as_str().unwrap();
        let materialized = dispatch_test_request(
            picker,
            picker_service,
            104,
            "ClipboardPickerService/Materialize",
            serde_json::to_vec(&serde_json::json!({
                "operation_id": operation_id,
                "entry_digest": entry_digest,
            }))
            .unwrap(),
        )
        .await;
        assert_eq!(materialized.status().code(), TtrpcCode::OK);
        let materialized_value: serde_json::Value =
            serde_json::from_slice(&materialized.payload).unwrap();
        assert_eq!(
            materialized_value["bytes"],
            serde_json::json!([99, 108, 105, 112])
        );
        let replay = dispatch_test_request(
            picker,
            picker_service,
            105,
            "ClipboardPickerService/Complete",
            completion_payload,
        )
        .await;
        assert_eq!(replay.status().code(), TtrpcCode::FAILED_PRECONDITION);

        let (notification_service, _, _, notification, _) = &clients[3];
        let deliver = dispatch_test_request(
            notification,
            notification_service,
            106,
            "NotificationService/Deliver",
            serde_json::to_vec(&serde_json::json!({
                "request": {
                    "summary": "Update",
                    "body": "A bounded body",
                    "category": "system.info",
                    "actions": [{"id": "open", "label": "Open"}],
                    "idempotencyKey": "notification-1",
                },
                "now_secs": 101,
            }))
            .unwrap(),
        )
        .await;
        assert_eq!(deliver.status().code(), TtrpcCode::OK);
        let deliver_payload: serde_json::Value = serde_json::from_slice(&deliver.payload).unwrap();
        assert_eq!(deliver_payload["accepted"], true);
        assert_eq!(deliver_payload["action_count"], 1);
        assert!(deliver_payload.get("action_nonces").is_none());

        let action = dispatch_test_request(
            notification,
            notification_service,
            107,
            "NotificationService/InvokeAction",
            serde_json::to_vec(&serde_json::json!({
                "action_key": "guest-provided",
                "now_secs": 102,
            }))
            .unwrap(),
        )
        .await;
        assert_eq!(action.status().code(), TtrpcCode::UNIMPLEMENTED);
        let close = dispatch_test_request(
            notification,
            notification_service,
            108,
            "NotificationService/CloseObserver",
            Vec::new(),
        )
        .await;
        assert_eq!(close.status().code(), TtrpcCode::UNIMPLEMENTED);

        let finalize = dispatch_test_request(
            display,
            display_service,
            109,
            "DisplayService/Finalize",
            Vec::new(),
        )
        .await;
        assert_eq!(finalize.status().code(), TtrpcCode::OK);
        for (_, _, _, _, server) in clients {
            assert!(server.await.unwrap().is_ok());
        }
        assert_eq!(
            runtime
                .lock()
                .await
                .as_ref()
                .and_then(|set| set.runtime_for(&zone))
                .map_or(0, InteractionComposition::session_count),
            0
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn picker_materialize_rejects_guest_or_zone_without_consuming_receipt() {
        let directory = tempfile::tempdir().unwrap();
        let zone = ZoneId::parse("work").unwrap();
        let uid = nix::unistd::getuid().as_raw();
        let runtime = Arc::new(AsyncMutex::new(Some(committed_test_interaction_runtime(
            &zone, uid,
        ))));
        let services = [
            d2b_provider_display_wayland::SERVICE_PACKAGE,
            d2b_provider_clipboard_wayland::BRIDGE_SERVICE,
            d2b_provider_clipboard_wayland::PICKER_SERVICE,
        ];
        let mut clients = Vec::new();
        for service in services {
            let path = directory
                .path()
                .join(service.replace('.', "-"))
                .with_extension("sock");
            let listener = bind_interaction_listener(&path, uid).unwrap();
            let (client, server) =
                establish_test_client(&listener, &runtime, &zone, service, uid, &path).await;
            clients.push((service, path, listener, client, server));
        }

        let (display_service, _, _, display, _) = &clients[0];
        let display_spec = WaylandSessionSpec::new(
            ResourceRef::parse("Guest/work").unwrap(),
            ResourceRef::parse("Host/host").unwrap(),
            ResourceRef::parse("User/alice").unwrap(),
            ResourceRef::parse("display-wayland.d2bus.org.WaylandPolicy/display-wayland").unwrap(),
            d2b_provider_display_wayland::DisplayIdentity::new(
                "picker-materialize",
                "#112233",
                "#223344",
                "#334455",
            )
            .unwrap(),
            true,
        )
        .unwrap();
        let ready = dispatch_test_request(
            display,
            display_service,
            400,
            "DisplayService/Reconcile",
            serde_json::to_vec(&serde_json::json!({"spec": display_spec})).unwrap(),
        )
        .await;
        assert_eq!(ready.status().code(), TtrpcCode::OK);

        let (bridge_service, _, _, bridge, _) = &clients[1];
        let capture = dispatch_test_request(
            bridge,
            bridge_service,
            401,
            "ClipboardBridgeService/CaptureGuest",
            serde_json::to_vec(&serde_json::json!({
                "guest_ref": "Guest/work",
                "zone": "work",
                "mime": "text/plain",
                "bytes": [112, 105, 99, 107],
            }))
            .unwrap(),
        )
        .await;
        assert_eq!(capture.status().code(), TtrpcCode::OK);
        let capture_payload: serde_json::Value = serde_json::from_slice(&capture.payload).unwrap();
        let entry_digest = capture_payload["entry_digest"].as_str().unwrap().to_owned();

        let (picker_service, _, _, picker, _) = &clients[2];
        let completion = dispatch_test_request(
            picker,
            picker_service,
            402,
            "ClipboardPickerService/Complete",
            serde_json::to_vec(&serde_json::json!({
                "guest_ref": "Guest/work",
                "zone": "work",
                "entry_digest": entry_digest,
                "mime_types": ["text/plain"],
                "selected_digest": entry_digest,
            }))
            .unwrap(),
        )
        .await;
        assert_eq!(completion.status().code(), TtrpcCode::OK);
        let completion_payload: serde_json::Value =
            serde_json::from_slice(&completion.payload).unwrap();
        let operation_id = completion_payload["operation_id"]
            .as_str()
            .unwrap()
            .to_owned();

        let wrong_guest = dispatch_test_request(
            picker,
            picker_service,
            403,
            "ClipboardPickerService/Materialize",
            serde_json::to_vec(&serde_json::json!({
                "operation_id": operation_id,
                "entry_digest": entry_digest,
                "guest_ref": "Guest/third",
                "zone": "work",
            }))
            .unwrap(),
        )
        .await;
        assert_eq!(wrong_guest.status().code(), TtrpcCode::UNAUTHENTICATED);

        let wrong_zone = dispatch_test_request(
            picker,
            picker_service,
            404,
            "ClipboardPickerService/Materialize",
            serde_json::to_vec(&serde_json::json!({
                "operation_id": operation_id,
                "entry_digest": entry_digest,
                "guest_ref": "Guest/work",
                "zone": "other",
            }))
            .unwrap(),
        )
        .await;
        assert_eq!(wrong_zone.status().code(), TtrpcCode::UNAUTHENTICATED);

        let materialized = dispatch_test_request(
            picker,
            picker_service,
            405,
            "ClipboardPickerService/Materialize",
            serde_json::to_vec(&serde_json::json!({
                "operation_id": operation_id,
                "entry_digest": entry_digest,
                "guest_ref": "Guest/work",
                "zone": "work",
            }))
            .unwrap(),
        )
        .await;
        assert_eq!(materialized.status().code(), TtrpcCode::OK);
        let materialized_payload: serde_json::Value =
            serde_json::from_slice(&materialized.payload).unwrap();
        assert_eq!(
            materialized_payload["bytes"],
            serde_json::json!([112, 105, 99, 107])
        );

        let replay = dispatch_test_request(
            picker,
            picker_service,
            406,
            "ClipboardPickerService/Materialize",
            serde_json::to_vec(&serde_json::json!({
                "operation_id": operation_id,
                "entry_digest": entry_digest,
                "guest_ref": "Guest/work",
                "zone": "work",
            }))
            .unwrap(),
        )
        .await;
        assert_eq!(replay.status().code(), TtrpcCode::UNAUTHENTICATED);

        let finalize = dispatch_test_request(
            display,
            display_service,
            407,
            "DisplayService/Finalize",
            Vec::new(),
        )
        .await;
        assert_eq!(finalize.status().code(), TtrpcCode::OK);
        for (_, _, _, _, server) in clients {
            assert!(server.await.unwrap().is_ok());
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn provider_transport_authorizes_each_committed_guest_and_preserves_display() {
        let directory = tempfile::tempdir().unwrap();
        let zone = ZoneId::parse("work").unwrap();
        let uid = nix::unistd::getuid().as_raw();
        let runtime = Arc::new(AsyncMutex::new(Some({
            let mut runtimes = InteractionRuntimeSet::new();
            runtimes.insert(
                zone.clone(),
                provider_bound_test_interaction_composition(
                    &zone,
                    uid,
                    &[
                        ("Guest/alpha", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
                        ("Guest/beta", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
                    ],
                ),
            );
            runtimes
        })));
        let services = [
            d2b_provider_display_wayland::SERVICE_PACKAGE,
            d2b_provider_clipboard_wayland::BRIDGE_SERVICE,
            d2b_provider_notification_desktop::SERVICE_PACKAGE,
        ];
        let mut clients = Vec::new();
        for service in services {
            let path = directory
                .path()
                .join(service.replace('.', "-"))
                .with_extension("sock");
            let listener = bind_interaction_listener(&path, uid).unwrap();
            let (client, server) =
                establish_test_client(&listener, &runtime, &zone, service, uid, &path).await;
            clients.push((service, path, listener, client, server));
        }

        let (display_service, _, _, display, _) = &clients[0];
        let display_spec = WaylandSessionSpec::new(
            ResourceRef::parse("Guest/alpha").unwrap(),
            ResourceRef::parse("Host/host").unwrap(),
            ResourceRef::parse("User/alice").unwrap(),
            ResourceRef::parse("display-wayland.d2bus.org.WaylandPolicy/display-wayland").unwrap(),
            d2b_provider_display_wayland::DisplayIdentity::new(
                "provider-transport-display",
                "#112233",
                "#223344",
                "#334455",
            )
            .unwrap(),
            true,
        )
        .unwrap();
        let ready = dispatch_test_request(
            display,
            display_service,
            200,
            "DisplayService/Reconcile",
            serde_json::to_vec(&serde_json::json!({"spec": display_spec})).unwrap(),
        )
        .await;
        assert_eq!(ready.status().code(), TtrpcCode::OK);

        let (bridge_service, _, _, bridge, _) = &clients[1];
        for (stream_id, guest_ref) in [(201, "Guest/alpha"), (202, "Guest/beta")] {
            let response = dispatch_test_request(
                bridge,
                bridge_service,
                stream_id,
                "ClipboardBridgeService/CaptureGuest",
                serde_json::to_vec(&serde_json::json!({
                    "guest_ref": guest_ref,
                    "zone": "work",
                    "mime": "text/plain",
                    "bytes": [stream_id as u8],
                }))
                .unwrap(),
            )
            .await;
            assert_eq!(response.status().code(), TtrpcCode::OK);
        }
        let third_guest = dispatch_test_request(
            bridge,
            bridge_service,
            203,
            "ClipboardBridgeService/CaptureGuest",
            serde_json::to_vec(&serde_json::json!({
                "guest_ref": "Guest/third",
                "zone": "work",
                "mime": "text/plain",
                "bytes": [1],
            }))
            .unwrap(),
        )
        .await;
        assert_eq!(third_guest.status().code(), TtrpcCode::UNAUTHENTICATED);
        let wrong_zone = dispatch_test_request(
            bridge,
            bridge_service,
            204,
            "ClipboardBridgeService/CaptureGuest",
            serde_json::to_vec(&serde_json::json!({
                "guest_ref": "Guest/alpha",
                "zone": "other",
                "mime": "text/plain",
                "bytes": [1],
            }))
            .unwrap(),
        )
        .await;
        assert_eq!(wrong_zone.status().code(), TtrpcCode::UNAUTHENTICATED);

        let (notification_service, _, _, notification, _) = &clients[2];
        for (stream_id, guest_ref, key) in [
            (205, "Guest/alpha", "provider-alpha"),
            (206, "Guest/beta", "provider-beta"),
        ] {
            let response = dispatch_test_request(
                notification,
                notification_service,
                stream_id,
                "NotificationService/Deliver",
                serde_json::to_vec(&serde_json::json!({
                    "guest_ref": guest_ref,
                    "zone": "work",
                    "request": {
                        "summary": "Update",
                        "body": "A bounded body",
                        "category": "system.info",
                        "idempotencyKey": key,
                    },
                }))
                .unwrap(),
            )
            .await;
            assert_eq!(response.status().code(), TtrpcCode::OK);
        }
        let bad_notification = dispatch_test_request(
            notification,
            notification_service,
            207,
            "NotificationService/Deliver",
            serde_json::to_vec(&serde_json::json!({
                "guest_ref": "Guest/third",
                "zone": "work",
                "request": {
                    "summary": "Update",
                    "body": "A bounded body",
                    "category": "system.info",
                    "idempotencyKey": "provider-third",
                },
            }))
            .unwrap(),
        )
        .await;
        assert_eq!(bad_notification.status().code(), TtrpcCode::UNAUTHENTICATED);

        let display_observe = dispatch_test_request(
            display,
            display_service,
            208,
            "DisplayService/Observe",
            Vec::new(),
        )
        .await;
        assert_eq!(display_observe.status().code(), TtrpcCode::OK);
        assert!(
            String::from_utf8(display_observe.payload)
                .unwrap()
                .contains("\"ready\":true")
        );

        let finalize = dispatch_test_request(
            display,
            display_service,
            209,
            "DisplayService/Finalize",
            Vec::new(),
        )
        .await;
        assert_eq!(finalize.status().code(), TtrpcCode::OK);
        for (_, _, _, _, server) in clients {
            assert!(server.await.unwrap().is_ok());
        }
    }

    #[test]
    fn production_composition_refuses_missing_or_wrong_committed_identity() {
        let zone = ZoneId::parse("work").unwrap();
        let policy = PolicySnapshot {
            policy_revision: 7,
            api_catalog_revision: 1,
            active_configuration_revision:
                d2b_contracts_resource::v3::ConfigurationGeneration::new(7).unwrap(),
            controller_generation: Some(
                d2b_contracts_resource::v3::ControllerGeneration::new(17).unwrap(),
            ),
        };
        let missing = ProductionInteractionResourceState::new(
            zone.clone(),
            policy,
            ZoneRevision::new(7),
            true,
            None,
            None,
            None,
        );
        assert!(validate_production_interaction_resource_state(&missing).is_err());

        let guest_ref = ResourceRef::parse("Guest/work").unwrap();
        let guest_uid = ResourceUid::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap();
        let wrong_uid = ResourceUid::parse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").unwrap();
        let wrong = CommittedInteractionIdentity::for_test(
            zone.clone(),
            guest_ref.clone(),
            guest_uid.clone(),
            ResourceRef::parse("Host/host").unwrap(),
            ResourceRef::parse("User/alice").unwrap(),
            BTreeMap::from([(guest_ref, wrong_uid.clone())]),
            ResourceGeneration::new(7).unwrap(),
            None,
            None,
            None,
            None,
        );
        let wrong_state = ProductionInteractionResourceState::new(
            zone,
            policy,
            ZoneRevision::new(7),
            true,
            None,
            Some(&wrong),
            None,
        );
        assert!(validate_production_interaction_resource_state(&wrong_state).is_err());
        assert_ne!(wrong.subject_uid(), &wrong_uid);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn display_only_composition_is_ready_from_committed_wayland_identity() {
        let directory = tempfile::tempdir().unwrap();
        let zone = ZoneId::parse("work").unwrap();
        let uid = nix::unistd::getuid().as_raw();
        let runtime = Arc::new(AsyncMutex::new(Some({
            let mut runtimes = InteractionRuntimeSet::new();
            runtimes.insert(
                zone.clone(),
                display_only_test_interaction_composition(&zone, uid),
            );
            runtimes
        })));
        let service = d2b_provider_display_wayland::SERVICE_PACKAGE;
        let path = directory
            .path()
            .join(service.replace('.', "-"))
            .with_extension("sock");
        let listener = bind_interaction_listener(&path, uid).unwrap();
        let (client, server) =
            establish_test_client(&listener, &runtime, &zone, service, uid, &path).await;
        let display_spec = WaylandSessionSpec::new(
            ResourceRef::parse("Guest/work").unwrap(),
            ResourceRef::parse("Host/host").unwrap(),
            ResourceRef::parse("User/alice").unwrap(),
            ResourceRef::parse("display-wayland.d2bus.org.WaylandPolicy/display-wayland").unwrap(),
            d2b_provider_display_wayland::DisplayIdentity::new(
                "display-only",
                "#112233",
                "#223344",
                "#334455",
            )
            .unwrap(),
            true,
        )
        .unwrap();
        let reconcile = dispatch_test_request(
            &client,
            service,
            300,
            "DisplayService/Reconcile",
            serde_json::to_vec(&serde_json::json!({"spec": display_spec})).unwrap(),
        )
        .await;
        assert_eq!(reconcile.status().code(), TtrpcCode::OK);
        {
            let guard = runtime.lock().await;
            let composition = guard
                .as_ref()
                .and_then(|set| set.runtime_for(&zone))
                .unwrap();
            assert!(
                composition
                    .display
                    .as_ref()
                    .is_some_and(|display| display.is_ready())
            );
            let route = composition.route_for_service(service).unwrap();
            assert_eq!(
                route
                    .context()
                    .execution_ref()
                    .unwrap()
                    .to_canonical_string(),
                "Host/host"
            );
            assert_eq!(route.provider_generation().unwrap().get(), 7);
            assert!(
                !composition.has_service_session(d2b_provider_clipboard_wayland::BRIDGE_SERVICE)
            );
            assert!(
                !composition
                    .has_service_session(d2b_provider_notification_desktop::SERVICE_PACKAGE)
            );
        }
        let finalize =
            dispatch_test_request(&client, service, 301, "DisplayService/Finalize", Vec::new())
                .await;
        assert_eq!(finalize.status().code(), TtrpcCode::OK);
        assert!(server.await.unwrap().is_ok());
    }

    #[test]
    fn notification_presentation_effect_consumes_sanitized_payload_and_bounds_queue() {
        let request =
            NotificationRequest::new("Update", "A bounded body", Category::SystemInfo).unwrap();
        let sanitized = d2b_provider_notification_desktop::sanitize(&request).unwrap();
        let mut port = InteractionNotificationPort::default();
        port.activate().unwrap();
        for _ in 0..64 {
            port.notify(&sanitized).unwrap();
        }
        assert_eq!(port.presented.len(), 64);
        assert_eq!(port.presented.front().unwrap().summary(), "Update");
        assert_eq!(
            port.notify(&sanitized),
            Err(d2b_provider_notification_desktop::SinkError::Unavailable)
        );
    }

    #[test]
    fn notification_authority_release_refuses_active_effects() {
        let port: Arc<Mutex<Box<dyn DesktopNotificationPort + Send>>> =
            Arc::new(Mutex::new(Box::new(InteractionNotificationPort::default())));
        let mut effects = InteractionDrainEffects::new(port);
        let source = NotificationSourceIdentity::new(
            ZoneId::parse("work").unwrap(),
            ResourceRef::parse("Provider/notification-desktop").unwrap(),
            ResourceRef::parse("Guest/guest").unwrap(),
            1,
            1,
            "sha256:source",
        )
        .unwrap();
        let plan = NotificationLifecyclePlan::new(
            ZoneId::parse("work").unwrap(),
            ResourceRef::parse("Provider/notification-desktop").unwrap(),
            vec![source],
            Vec::new(),
            None,
            None,
        )
        .unwrap();
        effects
            .notification_lifecycle
            .as_ref()
            .unwrap()
            .apply(&plan)
            .unwrap();

        assert_eq!(
            d2b_provider_notification_desktop::NotificationProcessEffectPort::release_authority(
                &mut effects
            ),
            Err("notification-authority-release-incomplete")
        );
        assert!(!effects.authority_released());
    }

    #[test]
    fn listener_handler_reservations_are_bounded() {
        let active_handlers = Arc::new(AtomicUsize::new(0));
        let (sender, receiver) = std::sync::mpsc::channel();
        thread::scope(|scope| {
            for _ in 0..MAX_INTERACTION_HANDLERS + 16 {
                let active_handlers = Arc::clone(&active_handlers);
                let sender = sender.clone();
                scope.spawn(move || {
                    sender
                        .send(reserve_interaction_handler(&active_handlers))
                        .unwrap();
                });
            }
        });
        drop(sender);

        assert_eq!(
            receiver.into_iter().filter(|reserved| *reserved).count(),
            MAX_INTERACTION_HANDLERS
        );
        assert_eq!(
            active_handlers.load(Ordering::Acquire),
            MAX_INTERACTION_HANDLERS
        );
    }

    #[test]
    fn completed_listener_handlers_are_reaped() {
        let (sender, receiver) = std::sync::mpsc::channel();
        let handler = thread::spawn(move || sender.send(()).unwrap());
        receiver.recv().unwrap();
        while !handler.is_finished() {
            thread::yield_now();
        }
        let handlers = Mutex::new(vec![handler]);

        reap_finished_handlers(&handlers);

        assert!(handlers.lock().unwrap().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn hermetic_listener_authenticates_dispatches_finalizes_and_refuses_replay() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("interaction.sock");
        let zone = ZoneId::parse("work").unwrap();
        let uid = nix::unistd::getuid().as_raw();
        let listener = bind_interaction_listener(&path, uid).unwrap();
        let runtime = Arc::new(AsyncMutex::new(Some(test_interaction_runtime(&zone, uid))));

        let client_socket =
            Socket::new(Domain::UNIX, Type::from(libc::SOCK_SEQPACKET), None).unwrap();
        client_socket
            .connect(&SockAddr::unix(&path).unwrap())
            .unwrap();
        client_socket.set_nonblocking(true).unwrap();
        let accepted = loop {
            match accept_with(
                listener.as_fd(),
                SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            ) {
                Ok(accepted) => break accepted,
                Err(rustix::io::Errno::AGAIN) => thread::yield_now(),
                Err(error) => panic!("accept failed: {error}"),
            }
        };
        let server_runtime = Arc::clone(&runtime);
        let server_zone = zone.clone();
        let server = tokio::spawn(async move {
            admit_interaction_socket(
                accepted,
                server_runtime,
                server_zone,
                d2b_provider_display_wayland::SERVICE_PACKAGE.to_owned(),
                uid,
                Arc::new(AtomicBool::new(false)),
            )
            .await
        });

        let policy =
            interaction_endpoint_policy(d2b_provider_display_wayland::SERVICE_PACKAGE, 1).unwrap();
        let client_seqpacket = SeqpacketSocket::from_owned(client_socket.into()).unwrap();
        let client_peer = client_seqpacket.acceptor_peer_credentials().unwrap();
        let transport = test_unix_transport(client_seqpacket, client_peer, &policy);
        let engine = tokio::time::timeout(
            Duration::from_secs(5),
            SessionEngine::establish_initiator(
                transport,
                policy,
                d2b_session::HandshakeCredentials::Nn,
                Instant::now(),
            ),
        )
        .await
        .expect("client handshake timeout")
        .unwrap();
        let driver = engine.into_driver();

        let observe_frame = request_frame_for_test(
            d2b_provider_display_wayland::SERVICE_PACKAGE,
            41,
            "DisplayService/Observe",
            Vec::new(),
        );
        let observe_id = d2b_session::ttrpc_request_id(1, &observe_frame).unwrap();
        driver
            .start_ttrpc(observe_id.clone(), observe_frame)
            .await
            .unwrap();
        let observe_response = tokio::time::timeout(Duration::from_secs(5), driver.receive_ttrpc())
            .await
            .expect("observe response timeout")
            .unwrap();
        let observe_payload = &observe_response[ttrpc::proto::MESSAGE_HEADER_LENGTH..];
        let observe = TtrpcResponse::parse_from_bytes(observe_payload).unwrap();
        assert_eq!(observe.status().code(), TtrpcCode::OK);
        assert!(
            String::from_utf8(observe.payload)
                .unwrap()
                .contains("\"ready\":false")
        );
        assert!(driver.complete_ttrpc(observe_id).await.unwrap());

        let finalize_frame = request_frame_for_test(
            d2b_provider_display_wayland::SERVICE_PACKAGE,
            42,
            "DisplayService/Finalize",
            Vec::new(),
        );
        let finalize_id = d2b_session::ttrpc_request_id(1, &finalize_frame).unwrap();
        driver
            .start_ttrpc(finalize_id.clone(), finalize_frame)
            .await
            .unwrap();
        let finalize_response =
            tokio::time::timeout(Duration::from_secs(5), driver.receive_ttrpc())
                .await
                .expect("finalize response timeout")
                .unwrap();
        let finalize_payload = &finalize_response[ttrpc::proto::MESSAGE_HEADER_LENGTH..];
        let finalize = TtrpcResponse::parse_from_bytes(finalize_payload).unwrap();
        assert_eq!(finalize.status().code(), TtrpcCode::OK);
        assert!(server.await.unwrap().is_ok());
        assert_eq!(
            runtime
                .lock()
                .await
                .as_ref()
                .and_then(|set| set.runtime_for(&zone))
                .map_or(0, InteractionComposition::session_count),
            0
        );

        let replay_frame = request_frame_for_test(
            d2b_provider_display_wayland::SERVICE_PACKAGE,
            43,
            "DisplayService/Observe",
            Vec::new(),
        );
        let replay = RequestId::new(vec![0x43; 16]).unwrap();
        assert!(driver.start_ttrpc(replay, replay_frame,).await.is_err());
        drop(listener);
        std::fs::remove_file(&path).unwrap();
        assert!(!path.exists());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unix_listener_observes_real_peer_credentials_before_session_admission() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("interaction.sock");
        let listener = bind_interaction_listener(&path, nix::unistd::getuid().as_raw())
            .expect("listener socket");
        let client = Socket::new(Domain::UNIX, Type::from(libc::SOCK_SEQPACKET), None).unwrap();
        client.connect(&SockAddr::unix(&path).unwrap()).unwrap();
        let accepted = loop {
            match accept_with(
                listener.as_fd(),
                SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            ) {
                Ok(accepted) => break accepted,
                Err(rustix::io::Errno::AGAIN) => thread::yield_now(),
                Err(error) => panic!("accept failed: {error}"),
            }
        };
        let accepted = SeqpacketSocket::from_owned(accepted).unwrap();
        let peer = VerifiedUnixPeer::verify_seqpacket(&accepted).unwrap();
        assert_eq!(
            peer.credentials().uid().as_raw(),
            nix::unistd::getuid().as_raw()
        );
        drop(client);
        drop(accepted);
    }
}
