//! Provider-independent resource-plane construction and materialization helpers.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    future::Future,
    io::{self, Read},
    os::unix::fs::FileTypeExt,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::resource_api::{ParsedListRequest, ResourceRuntimeError};
use crate::target_runtime::{
    AdmissionError, AdmissionLimits, AssignmentLease, ControllerAssignmentKey, DaemonMode,
    DeploymentError, ProviderDeployment,
};
use crate::zone_authority::ZoneAuthorityIdentity;
use d2b_bus::{BusIngress, ZoneRegistrar};
use d2b_contracts_resource::resource_proto as wire;
use d2b_contracts_resource::v3::identity::STANDARD_RESOURCE_TYPES;
use d2b_contracts_resource::v3::identity::{
    AuthenticatedSubjectContext, BindingDigest, EvidenceClass, Locality as IdentityLocality,
    ReconnectGeneration, ServiceName, SessionBinding, SessionPurpose, TranscriptHash,
    TransportBinding,
};
use d2b_contracts_resource::v3::{
    CanonicalJsonObject, CanonicalJsonValue, ConfigurationGeneration, ControllerGeneration,
    MAX_PAGE_CURSOR_BYTES, MAX_RESPONSE_CANONICAL_BYTES, ManagedBy, ResourceEnvelope,
    ResourceError, ResourceErrorKind, ResourceErrorReason, ResourceGeneration, ResourceName,
    ResourcePhase, ResourceRef, ResourceTypeName, ResourceUid, RetryClass, SchemaFingerprint,
    Timestamp, ZoneId, ZoneRevision, host::HOST_PROVIDER_REF, user::UserSpec,
};
pub use d2b_contracts_resource::v3::{
    RESOURCE_BUNDLE_MATERIALIZATION_OPERATION_PREFIX, SYSTEM_CORE_BOOTSTRAP_ZONE_OPERATION_ID,
};
use d2b_contracts_zone_session::v3::{
    component_session::{EndpointPolicy, EndpointRole},
    resource_bundle::{BundleResource, BundleResourceMetadata, ResourceBundle},
    role::RoleSpec,
    role_binding::RoleBindingSpec,
    zone::validate_self_resource,
};
use d2b_core_controller::{
    authority::HostGlobalAuthorityIndex,
    controller_assignment::ControllerAssignmentRegistry,
    controllers::{CoreHandlerKind, HandlerOutcome, HandlerPhase, HandlerStatus},
    main::{
        CoreProcess, RecoverySnapshot, RuntimeReadiness as CoreRuntimeReadiness, StartupError,
        StartupStage,
    },
    SourceError,
    zone_status::ZoneRuntimeMetadata,
};

/// Provider-neutral Core assignment registry shared by Resource API and bus
/// admission for one Zone runtime.
pub type AssignmentRegistry = Arc<Mutex<ControllerAssignmentRegistry>>;

const TRANSIENT_STORE_READ_ATTEMPTS: usize = 4;
const TRANSIENT_STORE_READ_BUDGET: Duration = Duration::from_secs(1);
const TRANSIENT_STORE_LIST_BUDGET: Duration = Duration::from_secs(4);
const TRANSIENT_STORE_READ_BACKOFF: [Duration; 3] = [
    Duration::from_millis(5),
    Duration::from_millis(20),
    Duration::from_millis(80),
];

/// Retry only transient redb read pressure while preserving the original
/// typed store error for the caller's final mapping.
pub async fn retry_transient_store_read<T, F, Fut>(
    zone: &ZoneId,
    operation: &str,
    mut read: F,
) -> Result<T, StoreError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, StoreError>>,
{
    retry_transient_store_read_with_budget(
        zone,
        operation,
        &mut read,
        TRANSIENT_STORE_READ_BUDGET,
    )
    .await
}

/// Retry a bounded list page with enough budget for redb's one-second
/// transaction lifetime before a subsequent attempt.
pub async fn retry_transient_store_list<T, F, Fut>(
    zone: &ZoneId,
    operation: &str,
    mut read: F,
) -> Result<T, StoreError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, StoreError>>,
{
    retry_transient_store_read_with_budget(
        zone,
        operation,
        &mut read,
        TRANSIENT_STORE_LIST_BUDGET,
    )
    .await
}

async fn retry_transient_store_read_with_budget<T, F, Fut>(
    zone: &ZoneId,
    operation: &str,
    read: &mut F,
    budget: Duration,
) -> Result<T, StoreError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, StoreError>>,
{
    let deadline = tokio::time::Instant::now() + budget;
    for attempt in 1..=TRANSIENT_STORE_READ_ATTEMPTS {
        match read().await {
            Ok(value) => return Ok(value),
            Err(error)
                if matches!(
                    error.kind(),
                    StoreErrorKind::Backpressure
                        | StoreErrorKind::StoreBackpressure
                        | StoreErrorKind::Timeout
                ) && attempt < TRANSIENT_STORE_READ_ATTEMPTS =>
            {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    tracing::error!(
                        zone = %zone.as_str(),
                        operation,
                        attempt,
                        max_attempts = TRANSIENT_STORE_READ_ATTEMPTS,
                        store_error_kind = ?error.kind(),
                        reason_code = error.reason_code(),
                        "store read retry budget expired; returning last typed error",
                    );
                    return Err(error);
                }
                let backoff = TRANSIENT_STORE_READ_BACKOFF[attempt - 1].min(remaining);
                tracing::warn!(
                    zone = %zone.as_str(),
                    operation,
                    attempt,
                    max_attempts = TRANSIENT_STORE_READ_ATTEMPTS,
                    store_error_kind = ?error.kind(),
                    reason_code = error.reason_code(),
                    backoff_ms = backoff.as_millis(),
                    "transient store read pressure; retrying after bounded backoff",
                );
                tokio::time::sleep(backoff).await;
                if tokio::time::Instant::now() >= deadline {
                    tracing::error!(
                        zone = %zone.as_str(),
                        operation,
                        attempt,
                        max_attempts = TRANSIENT_STORE_READ_ATTEMPTS,
                        store_error_kind = ?error.kind(),
                        reason_code = error.reason_code(),
                        "store read retry budget expired; returning last typed error",
                    );
                    return Err(error);
                }
            }
            Err(error) => {
                tracing::error!(
                    zone = %zone.as_str(),
                    operation,
                    attempt,
                    max_attempts = TRANSIENT_STORE_READ_ATTEMPTS,
                    store_error_kind = ?error.kind(),
                    reason_code = error.reason_code(),
                    "store read failed after bounded transient retries",
                );
                return Err(error);
            }
        }
    }
    unreachable!("startup store retry loop always returns")
}

/// Fixed Provider identities required by the generated Process resources.
///
/// These rows are runtime-owned bootstrap materialization, not Nix-authored
/// declarations. Their durable UIDs and generations come from the Resource
/// API store while the materialization operation remains bound to the
/// verified bundle and active configuration generation.
pub const FIXED_BOOTSTRAP_PROVIDER_IDS: [&str; 3] =
    ["system-core", "system-minijail", "system-systemd"];

/// Construct one empty Zone assignment registry.
pub fn new_assignment_registry() -> AssignmentRegistry {
    Arc::new(Mutex::new(ControllerAssignmentRegistry::default()))
}

/// Shared target-local resource lifecycle owner.
///
/// Host and Guest use the same assignment/lease machinery; only the static
/// composition chooses the mode and its effect adapter.
#[derive(Debug, Clone)]
pub struct TargetResourceLifecycle {
    deployment: ProviderDeployment,
}

impl TargetResourceLifecycle {
    pub fn new(mode: DaemonMode, limits: AdmissionLimits) -> Result<Self, AdmissionError> {
        Ok(Self {
            deployment: ProviderDeployment::new(mode, limits)?,
        })
    }

    pub const fn mode(&self) -> DaemonMode {
        self.deployment.mode()
    }

    pub fn admit_controller(
        &self,
        assignment: ControllerAssignmentKey,
    ) -> Result<AssignmentLease, DeploymentError> {
        self.deployment.admit_assignment(assignment)
    }

    pub fn revoke_session(&self, generation: u64) -> Result<usize, DeploymentError> {
        self.deployment.revoke_session(generation)
    }

    pub fn active_assignments(&self) -> Result<usize, DeploymentError> {
        self.deployment.active_assignments()
    }
}
use d2b_resource_api::{
    RedbBackend, ResourceApiClient, ResourceBusAdapter, ResourceService,
    authz::{
        ApiCatalog, AuthorizationState, BindingScope, BootstrapPhase, BoundSubject, CompiledRole,
        CompiledRoleBinding, NativeAuthorizer, PolicyRule, PolicySet, RelayGrantAuthority,
        ResourceVerb, SessionVerb,
    },
    registered::RedbRegisteredControllerApi,
    service::UnavailableUpgradeDispatcher,
};
use d2b_resource_store::{
    PolicySnapshot, StoreError, StoreErrorKind, StoreListRequest, StoreListResult,
    StoreOperationContext, StoreProjection, StoreSlot, StoredResource,
};
use d2b_resource_store_redb::{RedbResourceStore, StoreIdentity, StoreRuntimeMetadata};
use d2b_session::{
    HandshakeCredentials, SessionEngine, SessionServerError, TransportEvidence,
    serve_ttrpc_services,
};
use d2b_session_unix::{
    CreditPool, CreditScopeSet, DescriptorPolicyResolver, PeerIdentityPolicy, SeqpacketSocket,
    UnixSeqpacketTransport, UnixSessionError, VerifiedUnixPeer, prearmed_seqpacket_pair,
};
use nix::unistd::{Uid, User};
use protobuf;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

#[cfg(feature = "test-support")]
const TEST_OPERATOR_SUBJECT_REF: &str = "User/d2bd-operator";
#[cfg(feature = "test-support")]
const TEST_OPERATOR_SUBJECT_UID: &str = "22222222-2222-4222-8222-222222222222";
const COMMITTED_POLICY_RESOURCE_TYPES: [&str; 8] = [
    "Role",
    "RoleBinding",
    "Zone",
    "User",
    "Provider",
    "Host",
    "Guest",
    "Process",
];
const ROLE_BINDING_SUBJECT_RESOURCE_TYPES: [&str; 6] =
    ["Zone", "User", "Provider", "Host", "Guest", "Process"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZoneRuntimeReadiness {
    pub store_ready: bool,
    pub resource_api_ready: bool,
    pub local_session_ready: bool,
    pub provider_path_ready: bool,
    pub authority_ready: bool,
    pub core_stage: StartupStage,
}

impl ZoneRuntimeReadiness {
    pub const fn is_ready(self) -> bool {
        self.store_ready
            && self.resource_api_ready
            && self.local_session_ready
            && self.provider_path_ready
            && self.authority_ready
            && matches!(self.core_stage, StartupStage::Ready)
    }
}

pub fn read_bounded(path: impl AsRef<Path>, limit: usize) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut bytes = Vec::with_capacity(limit.min(4096));
    file.by_ref()
        .take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bounded host probe exceeded limit",
        ));
    }
    String::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "host probe was not utf-8"))
}

pub fn is_socket(path: &Path) -> bool {
    fs::metadata(path)
        .map(|metadata| metadata.file_type().is_socket())
        .unwrap_or(false)
}

pub fn mark_core_handlers(
    core: &mut CoreProcess,
    phase: HandlerPhase,
    revision: u64,
) -> Result<(), ResourceRuntimeError> {
    let revision = revision.max(1);
    let status_for = |phase| HandlerStatus {
        phase,
        outcome: match phase {
            HandlerPhase::Ready => HandlerOutcome::Converged,
            HandlerPhase::Degraded => HandlerOutcome::Failed,
            HandlerPhase::Pending | HandlerPhase::Recovering => HandlerOutcome::Recovering,
            HandlerPhase::Failed => HandlerOutcome::Failed,
            HandlerPhase::Unknown => HandlerOutcome::Ambiguous,
        },
        observed_generation: revision,
        queued: 0,
        running: 0,
        last_watch_revision: revision,
        checkpoint_revision: revision,
        last_reconciled_tick: revision,
        retry_after_tick: None,
    };
    for kind in CoreHandlerKind::ALL {
        core.handlers_mut()
            .update(
                kind,
                status_for(if kind == CoreHandlerKind::Watches {
                    HandlerPhase::Ready
                } else {
                    phase
                }),
            )
            .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
    }
    Ok(())
}

pub fn local_user_subject_context(
    zone: &ZoneId,
    resolved_user: &ResolvedZoneUser,
    operation_id: &str,
) -> Result<AuthenticatedSubjectContext, ResourceRuntimeError> {
    if resolved_user.zone != *zone {
        return Err(ResourceRuntimeError::IdentityUnbound);
    }
    let zone_ref = ResourceRef::parse(&format!("Zone/{}", zone.as_str()))
        .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?;
    let schema_fingerprint = SchemaFingerprint::parse(format!("sha256:{}", "1".repeat(64)))
        .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?;

    let mut transport_digest = Sha256::new();
    transport_digest.update(b"d2bd-public-resource-transport\0");
    transport_digest.update(resolved_user.peer_uid.to_le_bytes());
    transport_digest.update(zone.as_str().as_bytes());
    transport_digest.update(resolved_user.generation.get().to_le_bytes());
    transport_digest.update(resolved_user.revision.get().to_le_bytes());
    let transport_digest =
        BindingDigest::parse(format!("sha256:{:x}", transport_digest.finalize()))
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?;

    let mut transcript_digest = Sha256::new();
    transcript_digest.update(b"d2bd-public-resource-transcript\0");
    transcript_digest.update(resolved_user.peer_uid.to_le_bytes());
    transcript_digest.update(zone.as_str().as_bytes());
    transcript_digest.update(resolved_user.generation.get().to_le_bytes());
    transcript_digest.update(resolved_user.revision.get().to_le_bytes());
    transcript_digest.update(operation_id.as_bytes());
    let transcript_digest = TranscriptHash::from_bytes(transcript_digest.finalize().into());

    let session = SessionBinding::new(
        schema_fingerprint,
        TransportBinding::new(IdentityLocality::Local, transport_digest),
        ReconnectGeneration::new(1).map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?,
        transcript_digest,
    );
    Ok(AuthenticatedSubjectContext::new(
        resolved_user.subject_ref.clone(),
        resolved_user.subject_uid.clone(),
        zone_ref,
        EvidenceClass::UnixPeer,
        SessionPurpose::parse("zone-bus")
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?,
        ServiceName::parse("d2b.resource.v3")
            .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?,
        session,
    ))
}

pub fn drive_core_startup(
    core: &mut CoreProcess,
    readiness: CoreRuntimeReadiness,
    recovery: RecoverySnapshot,
    authority_index: &HostGlobalAuthorityIndex,
) -> Result<StartupStage, ResourceRuntimeError> {
    core.start_production(readiness, recovery, authority_index)
        .map_err(map_startup_error)?;
    core.publish_readiness().map_err(map_startup_error)
}

pub fn host_phase_for_resource_count(count: usize) -> HandlerPhase {
    if count == 0 {
        HandlerPhase::Degraded
    } else {
        HandlerPhase::Ready
    }
}

pub fn map_startup_error(error: StartupError) -> ResourceRuntimeError {
    match error {
        StartupError::ControllerEndpointUnavailable => {
            ResourceRuntimeError::ControllerEndpointUnavailable
        }
        StartupError::AuthenticationUnavailable => ResourceRuntimeError::AuthenticationUnavailable,
        StartupError::WatchAdmissionUnavailable => ResourceRuntimeError::WatchUnavailable,
        StartupError::AuthorityRehydrationUnavailable => ResourceRuntimeError::AuthorityUnavailable,
        StartupError::MandatoryHandlerNotReady => ResourceRuntimeError::HandlerNotReady,
        StartupError::RuntimeNotReady | StartupError::InvalidRecoverySnapshot => {
            ResourceRuntimeError::CoreStartupFailed
        }
    }
}

pub fn runtime_policy(
    zone: &ZoneId,
    snapshot: &PolicySnapshot,
    current_revision: ZoneRevision,
    bundle_resource_types: &[ResourceTypeName],
) -> Result<(PolicySet, AuthorizationState), ResourceRuntimeError> {
    compile_committed_policy(
        zone,
        *snapshot,
        current_revision,
        bundle_resource_types,
        &[],
    )
}

/// Compile the runtime policy while adding exact committed Provider subjects
/// for external controller sessions.
pub fn runtime_policy_with_subjects(
    zone: &ZoneId,
    snapshot: &PolicySnapshot,
    current_revision: ZoneRevision,
    bundle_resource_types: &[ResourceTypeName],
    additional_subjects: impl IntoIterator<Item = BoundSubject>,
) -> Result<(PolicySet, AuthorizationState), ResourceRuntimeError> {
    compile_committed_policy_with_subjects(
        zone,
        *snapshot,
        current_revision,
        bundle_resource_types,
        &[],
        additional_subjects,
    )
}

/// Compile the complete native policy from committed Role and RoleBinding
/// resources, retaining only the fixed internal system-core grant.
pub fn compile_committed_policy(
    zone: &ZoneId,
    snapshot: PolicySnapshot,
    current_revision: ZoneRevision,
    bundle_resource_types: &[ResourceTypeName],
    resources: &[StoredResource],
) -> Result<(PolicySet, AuthorizationState), ResourceRuntimeError> {
    compile_committed_policy_with_subjects(
        zone,
        snapshot,
        current_revision,
        bundle_resource_types,
        resources,
        std::iter::empty(),
    )
}

/// Compile committed policy resources and add exact controller subjects.
pub fn compile_committed_policy_with_subjects(
    zone: &ZoneId,
    snapshot: PolicySnapshot,
    current_revision: ZoneRevision,
    bundle_resource_types: &[ResourceTypeName],
    resources: &[StoredResource],
    additional_subjects: impl IntoIterator<Item = BoundSubject>,
) -> Result<(PolicySet, AuthorizationState), ResourceRuntimeError> {
    if snapshot.policy_revision == 0
        || snapshot.api_catalog_revision == 0
        || snapshot.active_configuration_revision.get() == 0
    {
        return Err(ResourceRuntimeError::PolicyUnavailable);
    }
    let catalog = ApiCatalog::with_extensions(
        bundle_resource_types
            .iter()
            .filter(|resource_type| resource_type.as_str().contains(".d2bus.org."))
            .cloned(),
    )
    .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?;
    let mut resource_types = STANDARD_RESOURCE_TYPES
        .iter()
        .map(|name| ResourceTypeName::parse(*name))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?;
    for resource_type in bundle_resource_types {
        if !resource_types.contains(resource_type) {
            resource_types.push(resource_type.clone());
        }
    }
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
    ];
    let mut system_core_rules = Vec::new();
    for chunk in resource_types.chunks(16) {
        system_core_rules.push(
            PolicyRule::new(
                &catalog,
                chunk.iter().cloned(),
                resource_verbs,
                session_verbs,
                [],
                [],
                [zone.clone()],
                [],
            )
            .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?,
        );
    }
    system_core_rules.push(
        PolicyRule::new(
            &catalog,
            [ResourceTypeName::parse("Credential")
                .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?],
            [
                ResourceVerb::Create,
                ResourceVerb::UpdateSpec,
                ResourceVerb::Delete,
                ResourceVerb::AdminCredential,
            ],
            [],
            [
                "create".to_owned(),
                "update-spec".to_owned(),
                "delete".to_owned(),
            ],
            [],
            [zone.clone()],
            [],
        )
        .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?,
    );
    let role_ref = ResourceRef::parse("Role/system-core-runtime")
        .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?;
    let system_core_role = CompiledRole::new(role_ref.clone(), system_core_rules)
        .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?;
    let binding_scope = BindingScope {
        zones: [zone.clone()].into_iter().collect(),
        ..BindingScope::default()
    };
    #[allow(unused_mut)]
    let mut system_core_subjects = vec![BoundSubject {
        subject_ref: ResourceRef::parse("Provider/system-core")
            .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?,
        subject_uid: ResourceUid::parse("11111111-1111-4111-8111-111111111111")
            .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?,
    }];
    #[cfg(feature = "test-support")]
    system_core_subjects.push(BoundSubject {
        subject_ref: ResourceRef::parse(TEST_OPERATOR_SUBJECT_REF)
            .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?,
        subject_uid: ResourceUid::parse(TEST_OPERATOR_SUBJECT_UID)
            .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?,
    });
    let binding = CompiledRoleBinding::new(
        role_ref.clone(),
        system_core_subjects,
        binding_scope.clone(),
        RelayGrantAuthority::None,
    )
    .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?;
    let mut roles = vec![system_core_role];
    let mut bindings = vec![binding];
    let mut subject_evidence = BTreeMap::new();
    for resource in resources {
        let envelope = validated_stored_resource_envelope(resource, zone)?;
        if ROLE_BINDING_SUBJECT_RESOURCE_TYPES
            .contains(&resource.resource_ref.resource_type().as_str())
        {
            if subject_evidence
                .insert(
                    resource.resource_ref.clone(),
                    (
                        resource.uid.clone(),
                        resource_is_current(resource, &envelope),
                    ),
                )
                .is_some()
            {
                return Err(ResourceRuntimeError::AuthorizationUnavailable);
            }
        }
    }
    for resource in resources {
        let envelope = validated_stored_resource_envelope(resource, zone)?;
        if matches!(
            envelope.status().phase(),
            ResourcePhase::Deleted | ResourcePhase::Failed
        ) {
            continue;
        }
        let spec = envelope.spec().base().to_canonical_bytes();
        match resource.resource_ref.resource_type().as_str() {
            "Role" => {
                if resource.resource_ref == role_ref {
                    return Err(ResourceRuntimeError::AuthorizationUnavailable);
                }
                let role_spec = serde_json::from_slice::<RoleSpec>(&spec)
                    .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?;
                roles.push(
                    CompiledRole::from_spec(
                        resource.resource_ref.clone(),
                        &role_spec,
                        &catalog,
                        false,
                    )
                    .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?,
                );
            }
            "RoleBinding" => {
                let binding_spec = serde_json::from_slice::<RoleBindingSpec>(&spec)
                    .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?;
                binding_spec
                    .validate_zone(zone)
                    .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?;
                let role = resources
                    .iter()
                    .find(|candidate| candidate.resource_ref == *binding_spec.role_ref())
                    .and_then(|candidate| {
                        let envelope =
                            ResourceEnvelope::from_json(&candidate.canonical_json).ok()?;
                        if matches!(
                            envelope.status().phase(),
                            ResourcePhase::Deleted | ResourcePhase::Failed
                        ) {
                            return None;
                        }
                        let spec = envelope.spec().base().to_canonical_bytes();
                        serde_json::from_slice::<RoleSpec>(&spec).ok()
                    })
                    .ok_or(ResourceRuntimeError::AuthorizationUnavailable)?;
                binding_spec
                    .validate_scope_against_role(&role)
                    .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?;
                let resolved_subjects = binding_spec
                    .subjects()
                    .iter()
                    .filter_map(|subject_ref| {
                        subject_evidence
                            .get(subject_ref)
                            .and_then(|(subject_uid, current)| {
                                current.then(|| BoundSubject {
                                    subject_ref: subject_ref.clone(),
                                    subject_uid: subject_uid.clone(),
                                })
                            })
                    })
                    .collect::<Vec<_>>();
                if resolved_subjects.is_empty() {
                    continue;
                }
                bindings.push(
                    CompiledRoleBinding::from_spec_with_resolved_subjects(
                        &binding_spec,
                        resolved_subjects,
                        RelayGrantAuthority::None,
                    )
                    .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?,
                );
            }
            _ => {}
        }
    }
    let additional_subjects = additional_subjects.into_iter().collect::<BTreeSet<_>>();
    if !additional_subjects.is_empty() {
        let provider_role_ref = ResourceRef::parse("Role/provider-controller-runtime")
            .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?;
        let controller_verbs = [ResourceVerb::Get, ResourceVerb::List, ResourceVerb::Watch];
        let controller_rules = resource_types
            .chunks(16)
            .map(|chunk| {
                PolicyRule::new(
                    &catalog,
                    chunk.iter().cloned(),
                    controller_verbs,
                    session_verbs,
                    [],
                    [],
                    [zone.clone()],
                    [],
                )
                .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)
            })
            .collect::<Result<Vec<_>, _>>()?;
        roles.push(
            CompiledRole::new(provider_role_ref.clone(), controller_rules)
                .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?,
        );
        bindings.push(
            CompiledRoleBinding::new(
                provider_role_ref,
                additional_subjects,
                binding_scope,
                RelayGrantAuthority::None,
            )
            .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?,
        );
    }
    let policy = PolicySet::new(&catalog, snapshot.policy_revision, roles, bindings)
        .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?;
    let state = AuthorizationState {
        snapshot,
        zone_policy_revision: current_revision,
        bootstrap_phase: BootstrapPhase::Disabled,
        now_tick: 1,
    };
    Ok((policy, state))
}

fn validated_stored_resource_envelope(
    resource: &StoredResource,
    zone: &ZoneId,
) -> Result<ResourceEnvelope, ResourceRuntimeError> {
    if resource.zone != *zone {
        return Err(ResourceRuntimeError::AuthorizationUnavailable);
    }
    let envelope = ResourceEnvelope::from_json(&resource.canonical_json)
        .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?;
    if envelope.resource_type() != resource.resource_ref.resource_type()
        || envelope.metadata().zone() != zone
        || envelope.metadata().name() != resource.resource_ref.name()
        || envelope.metadata().uid() != &resource.uid
        || envelope.metadata().generation() != resource.generation
        || envelope.metadata().revision() != resource.revision
        || envelope
            .digest()
            .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?
            != resource.payload_digest
    {
        return Err(ResourceRuntimeError::AuthorizationUnavailable);
    }
    Ok(envelope)
}

fn resource_is_current(resource: &StoredResource, envelope: &ResourceEnvelope) -> bool {
    envelope.status().phase() == ResourcePhase::Ready
        && envelope.status().observed_generation().get() == resource.generation.get()
}

pub fn system_core_endpoint_policy() -> EndpointPolicy {
    d2b_session_unix::inherited_resource_v3_endpoint_policy(
        EndpointRole::ZoneController,
        EndpointRole::Component,
    )
}

pub fn unix_transport(
    socket: SeqpacketSocket,
    policy: &EndpointPolicy,
) -> Result<UnixSeqpacketTransport, ResourceRuntimeError> {
    let expected_peer = socket
        .acceptor_peer_credentials()
        .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?;
    let credits = CreditScopeSet::new(
        CreditPool::new(64).map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?,
        CreditPool::new(64).map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?,
        CreditPool::new(64).map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?,
        CreditPool::new(64).map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?,
        CreditPool::new(64).map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?,
        CreditPool::new(64).map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?,
    );
    let resolver: DescriptorPolicyResolver =
        std::sync::Arc::new(|_| Err(UnixSessionError::DescriptorMismatch));
    UnixSeqpacketTransport::new(
        socket,
        policy.transport_binding.locality,
        policy.limits,
        policy.attachment_policy,
        credits,
        resolver,
        PeerIdentityPolicy::inherited_socketpair(expected_peer),
    )
    .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)
}

pub async fn register_system_core_session(
    registrar: &mut ZoneRegistrar,
    api: Arc<ResourceService<RedbBackend>>,
    authorizer: Arc<NativeAuthorizer>,
    authz_state: AuthorizationState,
) -> Result<
    (
        BusIngress,
        tokio::task::JoinHandle<Result<(), SessionServerError>>,
        Arc<ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>>,
        AuthenticatedSubjectContext,
    ),
    ResourceRuntimeError,
> {
    let policy = system_core_endpoint_policy();
    let (initiator_fd, responder_fd) =
        prearmed_seqpacket_pair().map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?;
    let initiator_socket = SeqpacketSocket::from_parent_prearmed(initiator_fd)
        .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?;
    let responder_socket = SeqpacketSocket::from_parent_prearmed(responder_fd)
        .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?;
    let verified_peer = VerifiedUnixPeer::verify_inherited_seqpacket(&initiator_socket)
        .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?;
    registrar
        .install_system_core_subject(&verified_peer)
        .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?;
    let initiator = unix_transport(initiator_socket, &policy)?;
    let responder = unix_transport(responder_socket, &policy)?;
    let (initiator, responder) = tokio::join!(
        SessionEngine::establish_initiator(
            initiator,
            policy.clone(),
            HandshakeCredentials::Nn,
            std::time::Instant::now(),
        ),
        SessionEngine::establish_responder(
            responder,
            policy.clone(),
            HandshakeCredentials::Nn,
            std::time::Instant::now(),
        ),
    );
    let initiator = initiator.map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?;
    let responder = responder.map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?;
    let acceptor = registrar
        .component_session_acceptor(policy.clone(), verified_peer)
        .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?;
    let candidate = acceptor
        .admit(
            initiator,
            TransportEvidence::new(
                d2b_contracts_resource::v3::identity::EvidenceClass::UnixPeer,
                BindingDigest::parse(format!("sha256:{}", "22".repeat(32)))
                    .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?,
            ),
            1,
        )
        .await
        .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?;
    let controller_generation = authz_state
        .snapshot
        .controller_generation
        .ok_or(ResourceRuntimeError::AuthenticationUnavailable)?;
    let subject_context = candidate
        .route_binding()
        .context()
        .clone()
        .with_controller_generation(controller_generation);
    let subject = authorizer
        .issue_authenticated_subject(subject_context.clone(), authz_state.clone())
        .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?;
    let service = Arc::new(
        ResourceBusAdapter::bind_component_session(api, subject)
            .map_err(|_| ResourceRuntimeError::ResourceApiBindFailed)?,
    );
    let status_client = Arc::new(service.client());
    let services = Arc::clone(&service).ttrpc_services();
    let ingress = registrar
        .register_component_session(candidate)
        .await
        .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?;
    let service_task = tokio::spawn(serve_ttrpc_services(
        Arc::new(responder.into_driver()),
        services,
    ));
    Ok((ingress, service_task, status_client, subject_context))
}

#[derive(Debug, Clone, Copy)]
pub struct SystemCoreReconcileResult {
    pub core_phase: ResourcePhase,
    pub host_phase: HandlerPhase,
    pub user_phase: HandlerPhase,
    pub total_resource_count: u32,
    pub generation_cleanup_pending: bool,
    pub cleanup_pending_count: u32,
}

pub fn watch_needs_restart(slot: &mut Option<tokio::task::JoinHandle<()>>) -> bool {
    if slot.as_ref().is_some_and(|task| task.is_finished()) {
        *slot = None;
    }
    slot.is_none()
}

pub fn zone_runtime_metadata(
    store_metadata: &StoreRuntimeMetadata,
    total_resource_count: u32,
    generation_cleanup_pending: bool,
    cleanup_pending_count: u32,
    last_reconciled_at: Option<Timestamp>,
) -> ZoneRuntimeMetadata {
    ZoneRuntimeMetadata {
        api_catalog_revision: store_metadata.policy_snapshot.api_catalog_revision,
        policy_revision: store_metadata.policy_snapshot.policy_revision,
        configuration_revision: store_metadata
            .policy_snapshot
            .active_configuration_revision
            .get(),
        installed_provider_count: 0,
        ready_provider_count: 0,
        total_resource_count,
        active_configuration_generation: store_metadata
            .policy_snapshot
            .active_configuration_revision
            .get(),
        generation_cleanup_pending,
        cleanup_pending_count,
        last_reconciled_at,
    }
}

pub fn current_status_timestamp() -> Timestamp {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let seconds = millis / 1_000;
    let day = seconds / 86_400;
    let day_seconds = seconds % 86_400;
    let (year, month, day_of_month) = civil_from_days(day as i64);
    let hour = day_seconds / 3_600;
    let minute = (day_seconds % 3_600) / 60;
    let second = day_seconds % 60;
    Timestamp::parse(format!(
        "{year:04}-{month:02}-{day_of_month:02}T{hour:02}:{minute:02}:{second:02}.{:03}Z",
        millis % 1_000
    ))
    .expect("system timestamp formatter emits canonical UTC")
}

fn civil_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let month = (5 * doy + 2) / 153;
    let day = doy - (153 * month + 2) / 5 + 1;
    let month = month + if month < 10 { 3 } else { -9 };
    let year = year + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

pub fn handler_phase_to_zone_phase(
    phase: HandlerPhase,
) -> d2b_contracts_zone_session::v3::ZoneHandlerPhase {
    match phase {
        HandlerPhase::Ready => d2b_contracts_zone_session::v3::ZoneHandlerPhase::Ready,
        HandlerPhase::Degraded => d2b_contracts_zone_session::v3::ZoneHandlerPhase::Degraded,
        HandlerPhase::Failed => d2b_contracts_zone_session::v3::ZoneHandlerPhase::Failed,
        HandlerPhase::Unknown => d2b_contracts_zone_session::v3::ZoneHandlerPhase::Unknown,
        HandlerPhase::Pending | HandlerPhase::Recovering => {
            d2b_contracts_zone_session::v3::ZoneHandlerPhase::Pending
        }
    }
}

pub fn runtime_authorizer(
    bundle_resource_types: &[ResourceTypeName],
) -> Result<NativeAuthorizer, ResourceRuntimeError> {
    let catalog = ApiCatalog::with_extensions(
        bundle_resource_types
            .iter()
            .filter(|resource_type| resource_type.as_str().contains(".d2bus.org."))
            .cloned(),
    )
    .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?;
    NativeAuthorizer::new(catalog, None).map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)
}

/// Immutable User identity resolved from one Zone store and the host NSS
/// database. The OS uid is admission evidence only and is not retained.
pub struct ResolvedZoneUser {
    zone: ZoneId,
    peer_uid: u32,
    subject_ref: ResourceRef,
    subject_uid: ResourceUid,
    generation: ResourceGeneration,
    revision: ZoneRevision,
}

impl ResolvedZoneUser {
    pub const fn subject_ref(&self) -> &ResourceRef {
        &self.subject_ref
    }

    pub const fn subject_uid(&self) -> &ResourceUid {
        &self.subject_uid
    }

    pub const fn generation(&self) -> ResourceGeneration {
        self.generation
    }

    pub const fn revision(&self) -> ZoneRevision {
        self.revision
    }
}

impl core::fmt::Debug for ResolvedZoneUser {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ResolvedZoneUser")
            .field("generation", &self.generation)
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

/// Resolve a public peer uid to exactly one Ready User in one Zone.
///
/// The NSS callback keeps owner tests hermetic. Production uses the host NSS
/// database; no caller-supplied subject ref, resource uid, or username enters
/// the result.
pub(crate) fn resolve_zone_user_from_resources(
    zone: &ZoneId,
    peer_uid: u32,
    resources: &[StoredResource],
    nss_uid: impl Fn(&str) -> Option<u32>,
) -> Result<ResolvedZoneUser, ResourceRuntimeError> {
    let mut matches = Vec::new();
    for resource in resources {
        if resource.resource_ref.resource_type().as_str() != "User" {
            continue;
        }
        if resource.zone != *zone {
            return Err(ResourceRuntimeError::IdentityUnbound);
        }
        let envelope = ResourceEnvelope::from_json(&resource.canonical_json)
            .map_err(|_| ResourceRuntimeError::IdentityUnbound)?;
        if envelope.resource_type().as_str() != "User"
            || envelope.metadata().zone() != zone
            || envelope.metadata().name() != resource.resource_ref.name()
            || envelope.metadata().uid() != &resource.uid
            || envelope.metadata().generation() != resource.generation
            || envelope.metadata().revision() != resource.revision
        {
            return Err(ResourceRuntimeError::IdentityUnbound);
        }
        let user_spec =
            serde_json::from_slice::<UserSpec>(&envelope.spec().base().to_canonical_bytes())
                .map_err(|_| ResourceRuntimeError::IdentityUnbound)?;
        if nss_uid(user_spec.os_username().as_str()) != Some(peer_uid) {
            continue;
        }
        if envelope.status().phase() != ResourcePhase::Ready
            || envelope.status().observed_generation().get() != resource.generation.get()
        {
            return Err(ResourceRuntimeError::IdentityUnbound);
        }
        matches.push(ResolvedZoneUser {
            zone: zone.clone(),
            peer_uid,
            subject_ref: resource.resource_ref.clone(),
            subject_uid: resource.uid.clone(),
            generation: resource.generation,
            revision: resource.revision,
        });
    }
    if matches.len() == 1 {
        return Ok(matches.pop().expect("one resolved User match is present"));
    }
    Err(ResourceRuntimeError::IdentityUnbound)
}

/// Resolve a public peer uid from the complete User index of one Zone store.
pub async fn resolve_zone_user(
    store: &RedbResourceStore,
    zone: &ZoneId,
    peer_uid: u32,
    operation_id: &str,
) -> Result<ResolvedZoneUser, ResourceRuntimeError> {
    let user_type =
        ResourceTypeName::parse("User").map_err(|_| ResourceRuntimeError::IdentityUnbound)?;
    let mut resources = Vec::new();
    let mut cursor = None;
    loop {
        let request = StoreListRequest {
                operation: StoreOperationContext {
                    operation_id: operation_id.to_owned(),
                    idempotency_key: None,
                    correlation_id: operation_id.to_owned(),
                    trace_id: None,
                    deadline_ms: 30_000,
                },
                zone: zone.clone(),
                resource_types: vec![user_type.clone()],
                resource_names: Vec::new(),
                filters: Vec::new(),
                page_size: 500,
                cursor: cursor.clone(),
                projection: StoreProjection::Full,
            };
        let page = retry_transient_store_list(zone, operation_id, || {
            store.list(request.clone())
        })
        .await
            .map_err(|_| ResourceRuntimeError::IdentityUnbound)?;
        resources.extend(page.resources);
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    let canonical_name = User::from_uid(Uid::from_raw(peer_uid))
        .ok()
        .flatten()
        .map(|user| user.name);
    resolve_zone_user_from_resources(zone, peer_uid, &resources, |username| {
        let user = User::from_name(username).ok().flatten()?;
        (user.uid.as_raw() == peer_uid
            && canonical_name
                .as_deref()
                .is_some_and(|name| name == user.name.as_str()))
        .then_some(user.uid.as_raw())
    })
}

/// Read the committed policy and local RoleBinding subject rows for one Zone
/// in bounded pages.
pub async fn load_committed_policy_resources(
    store: &RedbResourceStore,
    zone: &ZoneId,
    operation_id: &str,
) -> Result<Vec<StoredResource>, ResourceRuntimeError> {
    let resource_types = COMMITTED_POLICY_RESOURCE_TYPES
        .into_iter()
        .map(|name| ResourceTypeName::parse(name))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?;
    let mut resources = Vec::new();
    for resource_type in resource_types {
        let mut cursor = None;
        loop {
            let request = StoreListRequest {
                    operation: StoreOperationContext {
                        operation_id: operation_id.to_owned(),
                        idempotency_key: None,
                        correlation_id: operation_id.to_owned(),
                        trace_id: None,
                        deadline_ms: 30_000,
                    },
                    zone: zone.clone(),
                    resource_types: vec![resource_type.clone()],
                    resource_names: Vec::new(),
                    filters: Vec::new(),
                    page_size: 500,
                    cursor: cursor.clone(),
                    projection: StoreProjection::Full,
                };
            let page = retry_transient_store_list(zone, operation_id, || {
                store.list(request.clone())
            })
            .await
                .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?;
            resources.extend(page.resources);
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
    }
    Ok(resources)
}

/// Immutable subject identity captured for a committed RoleBinding.
#[derive(Clone, PartialEq, Eq)]
pub struct PolicySubjectFingerprint {
    binding_uid: ResourceUid,
    binding_generation: ResourceGeneration,
    subject_uid: ResourceUid,
    subject_generation: ResourceGeneration,
}

impl PolicySubjectFingerprint {
    pub const fn binding_uid(&self) -> &ResourceUid {
        &self.binding_uid
    }

    pub const fn binding_generation(&self) -> ResourceGeneration {
        self.binding_generation
    }

    pub const fn subject_uid(&self) -> &ResourceUid {
        &self.subject_uid
    }

    pub const fn subject_generation(&self) -> ResourceGeneration {
        self.subject_generation
    }
}

/// Return whether a RoleBinding may refresh without silently inheriting a
/// recreated subject. A changed binding generation is the explicit rebind
/// ceremony that permits a new subject UID or generation.
pub fn policy_subject_fingerprint_allows_refresh(
    previous: Option<&PolicySubjectFingerprint>,
    current: &PolicySubjectFingerprint,
) -> bool {
    let Some(previous) = previous else {
        return true;
    };
    previous.binding_uid != current.binding_uid
        || previous.binding_generation != current.binding_generation
        || (previous.subject_uid == current.subject_uid
            && previous.subject_generation == current.subject_generation)
}

/// Capture RoleBinding-to-subject UID/generation pairs from one committed
/// policy snapshot. A same-name User recreation therefore changes the
/// fingerprint and must be accompanied by a new RoleBinding generation before
/// its grant can be installed again.
pub fn committed_policy_subject_fingerprints(
    resources: &[StoredResource],
) -> Result<BTreeMap<(ResourceRef, ResourceRef), PolicySubjectFingerprint>, ResourceRuntimeError> {
    committed_policy_subject_fingerprints_with_retained(resources, &BTreeMap::new())
}

/// Refresh RoleBinding subject fingerprints while retaining evidence for
/// subjects that are still authored but currently missing or unready.
///
/// Retained evidence is scoped to the binding UID/generation and to the
/// binding's current subject list. A changed binding identity therefore drops
/// the old evidence, while a subject removal or deleted binding cannot leave a
/// tombstone behind.
pub fn committed_policy_subject_fingerprints_with_retained(
    resources: &[StoredResource],
    previous: &BTreeMap<(ResourceRef, ResourceRef), PolicySubjectFingerprint>,
) -> Result<BTreeMap<(ResourceRef, ResourceRef), PolicySubjectFingerprint>, ResourceRuntimeError> {
    let mut by_ref = BTreeMap::new();
    for resource in resources {
        if by_ref
            .insert(resource.resource_ref.clone(), resource)
            .is_some()
        {
            return Err(ResourceRuntimeError::AuthorizationUnavailable);
        }
    }
    let mut authored_subjects = BTreeMap::new();
    let mut current_fingerprints = BTreeMap::new();
    for binding in resources
        .iter()
        .filter(|resource| resource.resource_ref.resource_type().as_str() == "RoleBinding")
    {
        let envelope = validated_stored_resource_envelope(binding, &binding.zone)?;
        if matches!(
            envelope.status().phase(),
            ResourcePhase::Deleted | ResourcePhase::Failed
        ) {
            continue;
        }
        let spec =
            serde_json::from_slice::<RoleBindingSpec>(&envelope.spec().base().to_canonical_bytes())
                .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?;
        spec.validate_zone(envelope.metadata().zone())
            .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?;
        for subject_ref in spec.subjects() {
            let key = (binding.resource_ref.clone(), subject_ref.clone());
            authored_subjects.insert(key.clone(), (binding.uid.clone(), binding.generation));
            let Some(subject) = by_ref.get(subject_ref) else {
                continue;
            };
            let subject_envelope =
                validated_stored_resource_envelope(subject, envelope.metadata().zone())?;
            if !resource_is_current(subject, &subject_envelope) {
                continue;
            }
            current_fingerprints.insert(
                key,
                PolicySubjectFingerprint {
                    binding_uid: binding.uid.clone(),
                    binding_generation: binding.generation,
                    subject_uid: subject.uid.clone(),
                    subject_generation: subject.generation,
                },
            );
        }
    }
    let mut fingerprints = BTreeMap::new();
    for (key, (binding_uid, binding_generation)) in authored_subjects {
        if let Some(current) = current_fingerprints.remove(&key) {
            fingerprints.insert(key, current);
        } else if let Some(previous) = previous.get(&key).filter(|previous| {
            previous.binding_uid == binding_uid && previous.binding_generation == binding_generation
        }) {
            fingerprints.insert(key, previous.clone());
        }
    }
    Ok(fingerprints)
}

/// Refresh RoleBinding subject fingerprints and reject a changed subject
/// identity unless the binding identity/generation also changed.
pub fn refreshed_policy_subject_fingerprints(
    resources: &[StoredResource],
    previous: &BTreeMap<(ResourceRef, ResourceRef), PolicySubjectFingerprint>,
) -> Result<BTreeMap<(ResourceRef, ResourceRef), PolicySubjectFingerprint>, ResourceRuntimeError> {
    let fingerprints = committed_policy_subject_fingerprints_with_retained(resources, previous)?;
    for (key, current) in &fingerprints {
        if !policy_subject_fingerprint_allows_refresh(previous.get(key), current) {
            return Err(ResourceRuntimeError::IdentityUnbound);
        }
    }
    Ok(fingerprints)
}

pub fn initial_policy_snapshot() -> Result<PolicySnapshot, ResourceRuntimeError> {
    Ok(PolicySnapshot {
        policy_revision: 1,
        api_catalog_revision: 1,
        active_configuration_revision: ConfigurationGeneration::new(1)
            .map_err(|_| ResourceRuntimeError::StoreOpenFailed)?,
        controller_generation: Some(
            ControllerGeneration::new(1).map_err(|_| ResourceRuntimeError::StoreOpenFailed)?,
        ),
    })
}

pub async fn ensure_bootstrap_host_resource(
    zone: &ZoneId,
    store: &RedbResourceStore,
    client: &ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>,
) -> Result<(), ResourceRuntimeError> {
    let host_type =
        ResourceTypeName::parse("Host").map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
    let request = StoreListRequest {
            operation: StoreOperationContext {
                operation_id: "system-core-bootstrap-list-host".to_owned(),
                idempotency_key: None,
                correlation_id: "system-core-bootstrap-list-host".to_owned(),
                trace_id: None,
                deadline_ms: 10_000,
            },
            zone: zone.clone(),
            resource_types: vec![host_type],
            resource_names: Vec::new(),
            filters: Vec::new(),
            page_size: 2,
            cursor: None,
            projection: StoreProjection::MetadataOnly,
        };
    let page = retry_transient_store_list(zone, "system-core-bootstrap-list-host", || {
        store.list(request.clone())
    })
    .await
        .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;
    if !page.resources.is_empty() {
        return Ok(());
    }

    let payload = CanonicalJsonValue::parse(
        &serde_json::to_vec(&json!({
            "apiVersion": "resources.d2bus.org/v3",
            "metadata": {
                "configurationGeneration": 1,
                "createdAt": "1970-01-01T00:00:00.000Z",
                "deletionRequestedAt": null,
                "finalizers": [],
                "generation": 1,
                "managedBy": "configuration",
                "name": "host-system",
                "ownerRef": null,
                "revision": 1,
                "updatedAt": "1970-01-01T00:00:00.000Z",
                "zone": zone.as_str()
            },
            "spec": {
                "providerRef": HOST_PROVIDER_REF,
                "updatePolicy": {
                    "disruptive": "manual",
                    "nonDisruptive": "automatic"
                }
            },
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
                    "targetGeneration": 1
                }
            },
            "type": "Host"
        }))
        .map_err(|_| ResourceRuntimeError::HandlerNotReady)?,
    )
    .map_err(|_| ResourceRuntimeError::HandlerNotReady)?
    .to_canonical_bytes();
    let mut identity = wire::ResourceIdentity::new();
    identity.zone = zone.as_str().to_owned();
    identity.resource_type = "Host".to_owned();
    identity.name = "host-system".to_owned();
    let mut body = wire::ResourceEnvelopeBytes::new();
    body.identity = protobuf::MessageField::some(identity.clone());
    body.payload_digest = d2b_contracts_resource::v3::canonical_digest(
        d2b_contracts_resource::v3::RESOURCE_ENVELOPE_DOMAIN_TAG,
        &payload,
    );
    body.canonical_json = payload;
    let mut precondition = wire::Precondition::new();
    precondition.kind =
        protobuf::EnumOrUnknown::new(wire::PreconditionKind::PRECONDITION_KIND_CREATE_ABSENT);
    let mut mutation = wire::Mutation::new();
    mutation.kind = protobuf::EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_CREATE);
    mutation.target = protobuf::MessageField::some(identity);
    mutation.precondition = protobuf::MessageField::some(precondition);
    mutation.resource = protobuf::MessageField::some(body);
    let mut request = wire::CreateRequest::new();
    let mut meta = wire::RequestMeta::new();
    meta.operation_id = "system-core-bootstrap-host".to_owned();
    meta.correlation_id = meta.operation_id.clone();
    meta.idempotency_key = meta.operation_id.clone();
    request.meta = protobuf::MessageField::some(meta);
    request.mutation = protobuf::MessageField::some(mutation);
    let response = client.create(request).await;
    if let Some(error) = response.error.as_ref() {
        tracing::error!(
            zone = %zone.as_str(),
            error_kind = ?error.kind,
            reason = %error.reason.as_str(),
            retry_class = ?error.retry_class,
            "bootstrap Host create failed",
        );
        return Err(ResourceRuntimeError::HandlerNotReady);
    }
    Ok(())
}

fn bootstrap_zone_resource_payload(zone: &ZoneId) -> Result<Vec<u8>, ResourceRuntimeError> {
    let bytes = serde_json::to_vec(&json!({
        "apiVersion": "resources.d2bus.org/v3",
        "metadata": {
            "name": zone.as_str(),
            "zone": zone.as_str(),
            "generation": 1,
            "revision": 1,
            "ownerRef": null,
            "finalizers": [],
            "deletionRequestedAt": null,
            "createdAt": "1970-01-01T00:00:00.000Z",
            "updatedAt": "1970-01-01T00:00:00.000Z",
            "managedBy": "controller"
        },
        "spec": {},
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
                "targetGeneration": 1
            }
        },
        "type": "Zone"
    }))
    .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
    let value =
        CanonicalJsonValue::parse(&bytes).map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
    Ok(value.to_canonical_bytes())
}

/// Ensure the store-owned Zone self-resource exists before publishing a
/// provisioned runtime.
pub async fn ensure_bootstrap_zone_resource(
    zone: &ZoneId,
    zone_uid: &ResourceUid,
    store: &RedbResourceStore,
    client: &ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>,
) -> Result<(), ResourceRuntimeError> {
    let zone_type =
        ResourceTypeName::parse("Zone").map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
    let request = StoreListRequest {
            operation: StoreOperationContext {
                operation_id: "system-core-bootstrap-list-zone".to_owned(),
                idempotency_key: None,
                correlation_id: "system-core-bootstrap-list-zone".to_owned(),
                trace_id: None,
                deadline_ms: 10_000,
            },
            zone: zone.clone(),
            resource_types: vec![zone_type.clone()],
            resource_names: Vec::new(),
            filters: Vec::new(),
            page_size: 2,
            cursor: None,
            projection: StoreProjection::Full,
        };
    let page = retry_transient_store_list(zone, "system-core-bootstrap-list-zone", || {
        store.list(request.clone())
    })
    .await
        .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;
    if !page.resources.is_empty() {
        return validate_zone_self_resource_rows(zone, zone_uid, &page.resources);
    }

    let payload = bootstrap_zone_resource_payload(zone)?;
    let identity = resource_identity(
        zone,
        &zone_type,
        &ResourceName::parse(zone.as_str()).map_err(|_| ResourceRuntimeError::HandlerNotReady)?,
        None,
    );
    let mut body = wire::ResourceEnvelopeBytes::new();
    body.identity = protobuf::MessageField::some(identity.clone());
    body.payload_digest = d2b_contracts_resource::v3::canonical_digest(
        d2b_contracts_resource::v3::RESOURCE_ENVELOPE_DOMAIN_TAG,
        &payload,
    );
    body.canonical_json = payload;
    let mut precondition = wire::Precondition::new();
    precondition.kind =
        protobuf::EnumOrUnknown::new(wire::PreconditionKind::PRECONDITION_KIND_CREATE_ABSENT);
    let mut mutation = wire::Mutation::new();
    mutation.kind = protobuf::EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_CREATE);
    mutation.target = protobuf::MessageField::some(identity);
    mutation.precondition = protobuf::MessageField::some(precondition);
    mutation.resource = protobuf::MessageField::some(body);
    let mut request = wire::CreateRequest::new();
    let mut meta = wire::RequestMeta::new();
    meta.operation_id = SYSTEM_CORE_BOOTSTRAP_ZONE_OPERATION_ID.to_owned();
    meta.correlation_id = meta.operation_id.clone();
    meta.idempotency_key = meta.operation_id.clone();
    request.meta = protobuf::MessageField::some(meta);
    request.mutation = protobuf::MessageField::some(mutation);
    let response = client.create(request).await;
    if let Some(error) = response.error.as_ref() {
        tracing::error!(
            zone = %zone.as_str(),
            error_kind = ?error.kind,
            reason = %error.reason.as_str(),
            retry_class = ?error.retry_class,
            "bootstrap Zone create failed",
        );
        return Err(ResourceRuntimeError::HandlerNotReady);
    }
    validate_zone_self_resource(store, zone, zone_uid, store.identity().store_uid()).await
}

/// Materialize the verified Nix Zone bundle through the authenticated
/// system-core Resource API before production reconciliation reads the store
/// as desired state.  The store remains the authority for UIDs, revisions,
/// ownership, and update generation; this function only supplies desired
/// state.
pub async fn materialize_zone_resource_bundle(
    zone: &ZoneId,
    bundle: &ResourceBundle,
    store: &RedbResourceStore,
    client: &ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>,
) -> Result<(), ResourceRuntimeError> {
    let mutations = plan_zone_resource_bundle(zone, bundle, store).await?;
    if mutations.is_empty() {
        return Ok(());
    }

    let operation_id = resource_bundle_materialization_operation_id(zone, bundle)?;
    let mut request = wire::CommitBatchRequest::new();
    let mut meta = wire::RequestMeta::new();
    meta.operation_id = operation_id.clone();
    meta.idempotency_key = operation_id.clone();
    meta.correlation_id = operation_id;
    request.meta = protobuf::MessageField::some(meta);
    request.mutations = mutations;
    let configuration_generation = retry_transient_store_read(
        zone,
        "resource-bundle-materialization-metadata",
        || store.runtime_metadata(),
    )
    .await
        .map_err(|_| ResourceRuntimeError::StoreReadFailed)?
        .policy_snapshot
        .active_configuration_revision;
    let response = client
        .commit_configuration_batch(request, configuration_generation)
        .await;
    if let Some(error) = response.error.as_ref() {
        tracing::error!(
            zone = %zone.as_str(),
            error_kind = ?error.kind,
            reason = %error.reason.as_str(),
            "authenticated Zone resource bundle materialization failed",
        );
        return Err(ResourceRuntimeError::HandlerNotReady);
    }
    Ok(())
}

/// Validate a bundle against the current store without issuing a mutation.
///
/// Composition uses this read-only pass for every local Zone before the
/// durable publication operation is prepared.  In particular, stale
/// configuration rows cannot be discovered only after an earlier Zone has
/// advanced.
pub async fn validate_zone_resource_bundle(
    zone: &ZoneId,
    bundle: &ResourceBundle,
    store: &RedbResourceStore,
) -> Result<(), ResourceRuntimeError> {
    let _ = plan_zone_resource_bundle(zone, bundle, store).await?;
    Ok(())
}

async fn plan_zone_resource_bundle(
    zone: &ZoneId,
    bundle: &ResourceBundle,
    store: &RedbResourceStore,
) -> Result<Vec<wire::Mutation>, ResourceRuntimeError> {
    bundle.verify().map_err(|error| {
        tracing::error!(
            zone = %zone,
            error = ?error,
            "resource bundle verification failed",
        );
        ResourceRuntimeError::HandlerNotReady
    })?;
    let bundle_zone_uid = bundle
        .zone_uid()
        .ok_or(ResourceRuntimeError::IdentityUnbound)?;
    if store.identity().zone() != zone || store.identity().zone_uid() != bundle_zone_uid {
        return Err(ResourceRuntimeError::HandlerNotReady);
    }
    let metadata = retry_transient_store_read(
        zone,
        "resource-bundle-materialization-metadata",
        || store.runtime_metadata(),
    )
    .await
        .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;
    let mut existing = BTreeMap::new();
    let mut cursor = None;
    loop {
        let request = StoreListRequest {
                operation: StoreOperationContext {
                    operation_id: "resource-bundle-materialization-list".to_owned(),
                    idempotency_key: None,
                    correlation_id: "resource-bundle-materialization-list".to_owned(),
                    trace_id: None,
                    deadline_ms: 10_000,
                },
                zone: zone.clone(),
                resource_types: Vec::new(),
                resource_names: Vec::new(),
                filters: Vec::new(),
                page_size: 256,
                cursor: cursor.clone(),
                projection: StoreProjection::Full,
            };
        let page = retry_transient_store_list(zone, "resource-bundle-materialization-list", || {
            store.list(request.clone())
        })
        .await
            .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;
        for resource in page.resources {
            existing.insert(resource.resource_ref.clone(), resource);
        }
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    reject_stale_guest_network_rows(&existing, bundle)?;

    let fixed_bootstrap_resources = fixed_bootstrap_provider_resources(zone, bundle)?;
    let mut pending = bundle.resources.iter().collect::<Vec<_>>();
    pending.extend(fixed_bootstrap_resources.iter());
    let mut ordered = Vec::with_capacity(pending.len());
    let mut admitted_refs = existing.keys().cloned().collect::<BTreeSet<_>>();
    while !pending.is_empty() {
        let Some(index) = pending.iter().position(|resource| {
            resource
                .metadata()
                .owner_ref()
                .is_none_or(|owner| admitted_refs.contains(owner))
        }) else {
            tracing::error!(
                zone = %zone,
                pending_resource_count = pending.len(),
                "resource bundle owner graph could not be ordered",
            );
            return Err(ResourceRuntimeError::HandlerNotReady);
        };
        let resource = pending.remove(index);
        let resource_ref = ResourceRef::new(
            resource.resource_type().clone(),
            resource.metadata().name().clone(),
        );
        admitted_refs.insert(resource_ref);
        ordered.push(resource);
    }

    let active_configuration_generation =
        metadata.policy_snapshot.active_configuration_revision.get();
    let mut mutations = Vec::new();
    for resource in ordered {
        let resource_ref = ResourceRef::new(
            resource.resource_type().clone(),
            resource.metadata().name().clone(),
        );
        if let Some(current) = existing.get(&resource_ref) {
            let current_envelope = ResourceEnvelope::from_json(&current.canonical_json)
                .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
            if current_envelope.metadata().managed_by() != ManagedBy::Configuration
                || current_envelope
                    .metadata()
                    .configuration_generation()
                    .is_none()
            {
                tracing::error!(
                    zone = %zone,
                    resource_type = %resource_ref.resource_type().as_str(),
                    resource_name = %resource_ref.name().as_str(),
                    managed_by = ?current_envelope.metadata().managed_by(),
                    configuration_generation = ?current_envelope.metadata().configuration_generation(),
                    "existing configured resource lost configuration ownership",
                );
                return Err(ResourceRuntimeError::HandlerNotReady);
            }
            if current_envelope.metadata().owner_ref() != resource.metadata().owner_ref() {
                tracing::error!(
                    zone = %zone,
                    resource_ref = %resource_ref,
                    current_owner = ?current_envelope.metadata().owner_ref(),
                    desired_owner = ?resource.metadata().owner_ref(),
                    "existing configured resource owner changed",
                );
                return Err(ResourceRuntimeError::HandlerNotReady);
            }
            let desired_spec = resource.spec().to_canonical_bytes();
            let current_spec = current_envelope
                .spec()
                .canonical_bytes()
                .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
            if desired_spec != current_spec {
                let payload = update_resource_payload(&current.canonical_json, resource)?;
                mutations.push(update_mutation(
                    zone,
                    &resource_ref,
                    current_envelope.metadata().uid(),
                    current_envelope.metadata().revision(),
                    payload,
                )?);
            }
        } else {
            let payload = create_resource_payload(zone, resource, active_configuration_generation)?;
            mutations.push(create_mutation(zone, resource, payload)?);
        }
    }
    Ok(mutations)
}

fn fixed_bootstrap_provider_resources(
    zone: &ZoneId,
    bundle: &ResourceBundle,
) -> Result<Vec<BundleResource>, ResourceRuntimeError> {
    let provider_type =
        ResourceTypeName::parse("Provider").map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
    let mut resources = Vec::new();
    for provider_name in FIXED_BOOTSTRAP_PROVIDER_IDS {
        let existing = bundle.resources.iter().find(|resource| {
            resource.resource_type() == &provider_type
                && resource.metadata().name().as_str() == provider_name
        });
        if let Some(resource) = existing {
            let artifact_id = resource
                .spec()
                .get("artifactId")
                .and_then(|value| match value {
                    CanonicalJsonValue::String(value) => Some(value.as_str()),
                    _ => None,
                })
                .ok_or(ResourceRuntimeError::HandlerNotReady)?;
            if artifact_id != provider_name {
                return Err(ResourceRuntimeError::HandlerNotReady);
            }
            continue;
        }
        let metadata = BundleResourceMetadata::new(
            ResourceName::parse(provider_name.to_owned())
                .map_err(|_| ResourceRuntimeError::HandlerNotReady)?,
            zone.clone(),
            None,
            BTreeMap::new(),
            BTreeMap::new(),
        );
        let spec = CanonicalJsonObject::parse(
            format!(r#"{{"artifactId":"{provider_name}","config":{{}}}}"#).as_bytes(),
        )
        .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
        resources.push(
            BundleResource::new(provider_type.clone(), metadata, spec)
                .map_err(|_| ResourceRuntimeError::HandlerNotReady)?,
        );
    }
    Ok(resources)
}

fn reject_stale_guest_network_rows(
    existing: &BTreeMap<ResourceRef, StoredResource>,
    bundle: &ResourceBundle,
) -> Result<(), ResourceRuntimeError> {
    let desired = bundle
        .resources
        .iter()
        .map(|resource| {
            ResourceRef::new(
                resource.resource_type().clone(),
                resource.metadata().name().clone(),
            )
        })
        .collect::<BTreeSet<_>>();
    if existing.keys().any(|resource_ref| {
        matches!(resource_ref.resource_type().as_str(), "Guest" | "Network")
            && !desired.contains(resource_ref)
    }) {
        return Err(ResourceRuntimeError::HandlerNotReady);
    }
    Ok(())
}

pub fn resource_bundle_materialization_operation_id(
    zone: &ZoneId,
    bundle: &ResourceBundle,
) -> Result<String, ResourceRuntimeError> {
    if &bundle.zone != zone {
        return Err(ResourceRuntimeError::HandlerNotReady);
    }
    if bundle.zone_uid().is_none() {
        return Err(ResourceRuntimeError::IdentityUnbound);
    }
    Ok(format!(
        "{RESOURCE_BUNDLE_MATERIALIZATION_OPERATION_PREFIX}{}",
        bundle.integrity().content_hash
    ))
}

/// Validate the immutable identity of an existing Zone self-resource.
pub async fn validate_zone_self_resource(
    store: &RedbResourceStore,
    zone: &ZoneId,
    zone_uid: &ResourceUid,
    store_uid: &ResourceUid,
) -> Result<(), ResourceRuntimeError> {
    if store.identity().zone_uid() != zone_uid || store.identity().store_uid() != store_uid {
        return Err(ResourceRuntimeError::HandlerNotReady);
    }
    let request = StoreListRequest {
            operation: StoreOperationContext {
                operation_id: "zone-self-resource-validation".to_owned(),
                idempotency_key: None,
                correlation_id: "zone-self-resource-validation".to_owned(),
                trace_id: None,
                deadline_ms: 10_000,
            },
            zone: zone.clone(),
            resource_types: vec![
                ResourceTypeName::parse("Zone")
                    .map_err(|_| ResourceRuntimeError::HandlerNotReady)?,
            ],
            resource_names: Vec::new(),
            filters: Vec::new(),
            page_size: 16,
            cursor: None,
            projection: StoreProjection::Full,
        };
    let page = retry_transient_store_list(zone, "zone-self-resource-validation", || {
        store.list(request.clone())
    })
    .await
        .map_err(|_| ResourceRuntimeError::StoreReadFailed)?;
    validate_zone_self_resource_rows(zone, zone_uid, &page.resources)
}

fn validate_zone_self_resource_rows(
    zone: &ZoneId,
    zone_uid: &ResourceUid,
    resources: &[StoredResource],
) -> Result<(), ResourceRuntimeError> {
    if resources.len() != 1 {
        return Err(ResourceRuntimeError::HandlerNotReady);
    }
    let resource = resources
        .first()
        .ok_or(ResourceRuntimeError::HandlerNotReady)?;
    let envelope = ResourceEnvelope::from_json(&resource.canonical_json)
        .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
    if envelope.resource_type().as_str() != "Zone" {
        return Err(ResourceRuntimeError::HandlerNotReady);
    }
    validate_self_resource(
        zone,
        zone_uid,
        envelope.metadata().name(),
        envelope.metadata().zone(),
        envelope.metadata().uid(),
        envelope.metadata().owner_ref(),
        envelope.metadata().finalizers(),
        resources.len(),
    )
    .map_err(|_| ResourceRuntimeError::HandlerNotReady)
}

fn create_resource_payload(
    zone: &ZoneId,
    resource: &d2b_contracts_zone_session::v3::resource_bundle::BundleResource,
    configuration_generation: u64,
) -> Result<Vec<u8>, ResourceRuntimeError> {
    let mut value =
        serde_json::to_value(resource).map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
    let root = value
        .as_object_mut()
        .ok_or(ResourceRuntimeError::HandlerNotReady)?;
    let metadata = root
        .get_mut("metadata")
        .and_then(Value::as_object_mut)
        .ok_or(ResourceRuntimeError::HandlerNotReady)?;
    metadata.insert(
        "configurationGeneration".to_owned(),
        Value::from(configuration_generation),
    );
    metadata.insert(
        "createdAt".to_owned(),
        Value::String("1970-01-01T00:00:00.000Z".to_owned()),
    );
    metadata.insert("deletionRequestedAt".to_owned(), Value::Null);
    metadata.insert("finalizers".to_owned(), Value::Array(Vec::new()));
    metadata.insert("generation".to_owned(), Value::from(1_u64));
    metadata.insert(
        "managedBy".to_owned(),
        Value::String("configuration".to_owned()),
    );
    metadata.insert("revision".to_owned(), Value::from(1_u64));
    metadata.insert(
        "updatedAt".to_owned(),
        Value::String("1970-01-01T00:00:00.000Z".to_owned()),
    );
    metadata.insert("zone".to_owned(), Value::String(zone.as_str().to_owned()));
    root.insert(
        "status".to_owned(),
        json!({
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
                "targetGeneration": 1
            }
        }),
    );
    let bytes = serde_json::to_vec(&value).map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
    CanonicalJsonValue::parse(&bytes)
        .map(|value| value.to_canonical_bytes())
        .map_err(|_| ResourceRuntimeError::HandlerNotReady)
}

fn update_resource_payload(
    current: &[u8],
    resource: &d2b_contracts_zone_session::v3::resource_bundle::BundleResource,
) -> Result<Vec<u8>, ResourceRuntimeError> {
    let mut value = serde_json::from_slice::<Value>(current)
        .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
    let desired_spec =
        serde_json::to_value(resource.spec()).map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
    value
        .as_object_mut()
        .and_then(|root| root.get_mut("spec"))
        .map(|spec| *spec = desired_spec)
        .ok_or(ResourceRuntimeError::HandlerNotReady)?;
    let bytes = serde_json::to_vec(&value).map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
    CanonicalJsonValue::parse(&bytes)
        .map(|value| value.to_canonical_bytes())
        .map_err(|_| ResourceRuntimeError::HandlerNotReady)
}

fn resource_identity(
    zone: &ZoneId,
    resource_type: &ResourceTypeName,
    name: &ResourceName,
    uid: Option<&ResourceUid>,
) -> wire::ResourceIdentity {
    let mut identity = wire::ResourceIdentity::new();
    identity.zone = zone.as_str().to_owned();
    identity.resource_type = resource_type.as_str().to_owned();
    identity.name = name.as_str().to_owned();
    identity.uid = uid.map(|uid| uid.as_str().to_owned());
    identity
}

fn resource_envelope_body(
    identity: wire::ResourceIdentity,
    payload: Vec<u8>,
    payload_digest: String,
) -> wire::ResourceEnvelopeBytes {
    let mut body = wire::ResourceEnvelopeBytes::new();
    body.identity = protobuf::MessageField::some(identity);
    body.canonical_json = payload;
    body.payload_digest = payload_digest;
    body
}

fn create_mutation(
    zone: &ZoneId,
    resource: &d2b_contracts_zone_session::v3::resource_bundle::BundleResource,
    payload: Vec<u8>,
) -> Result<wire::Mutation, ResourceRuntimeError> {
    let identity = resource_identity(
        zone,
        resource.resource_type(),
        resource.metadata().name(),
        None,
    );
    let mut precondition = wire::Precondition::new();
    precondition.kind =
        protobuf::EnumOrUnknown::new(wire::PreconditionKind::PRECONDITION_KIND_CREATE_ABSENT);
    let mut mutation = wire::Mutation::new();
    mutation.kind = protobuf::EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_CREATE);
    mutation.target = protobuf::MessageField::some(identity.clone());
    mutation.precondition = protobuf::MessageField::some(precondition);
    mutation.resource = protobuf::MessageField::some(resource_envelope_body(
        identity,
        payload.clone(),
        d2b_contracts_resource::v3::canonical_digest(
            d2b_contracts_resource::v3::RESOURCE_ENVELOPE_DOMAIN_TAG,
            &payload,
        ),
    ));
    if let Some(owner) = resource.metadata().owner_ref() {
        mutation.owner = protobuf::MessageField::some(resource_identity(
            zone,
            owner.resource_type(),
            owner.name(),
            None,
        ));
    }
    Ok(mutation)
}

fn update_mutation(
    zone: &ZoneId,
    resource_ref: &ResourceRef,
    uid: &ResourceUid,
    revision: ZoneRevision,
    payload: Vec<u8>,
) -> Result<wire::Mutation, ResourceRuntimeError> {
    let identity = resource_identity(
        zone,
        resource_ref.resource_type(),
        resource_ref.name(),
        Some(uid),
    );
    let envelope =
        ResourceEnvelope::from_json(&payload).map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
    let mut precondition = wire::Precondition::new();
    precondition.kind =
        protobuf::EnumOrUnknown::new(wire::PreconditionKind::PRECONDITION_KIND_EXACT_REVISION);
    precondition.expected_revision = Some(revision.get());
    let mut mutation = wire::Mutation::new();
    mutation.kind = protobuf::EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_UPDATE_SPEC);
    mutation.target = protobuf::MessageField::some(identity.clone());
    mutation.precondition = protobuf::MessageField::some(precondition);
    mutation.resource = protobuf::MessageField::some(resource_envelope_body(
        identity,
        payload,
        envelope
            .digest()
            .map_err(|_| ResourceRuntimeError::HandlerNotReady)?,
    ));
    Ok(mutation)
}

pub fn store_identity(
    zone: &ZoneId,
    store_identity: &str,
) -> Result<StoreIdentity, ResourceRuntimeError> {
    let store_uuid = stable_uid("store", store_identity);
    let zone_uid = stable_uid("zone", zone.as_str());
    let created_at = Timestamp::parse("1970-01-01T00:00:00.000Z")
        .map_err(|_| ResourceRuntimeError::StoreOpenFailed)?;
    let mut revisions = initial_policy_snapshot()?;
    revisions.policy_revision = 0;
    Ok(StoreIdentity::new(
        StoreSlot::new(0).map_err(|_| ResourceRuntimeError::StoreOpenFailed)?,
        store_uuid,
        zone.clone(),
        zone_uid,
        created_at,
        revisions,
    ))
}

/// Build the redb identity expected by a verified Zone authority tuple.
pub fn store_identity_for_authority(
    zone: &ZoneId,
    authority: &ZoneAuthorityIdentity,
) -> Result<StoreIdentity, ResourceRuntimeError> {
    let created_at = Timestamp::parse("1970-01-01T00:00:00.000Z")
        .map_err(|_| ResourceRuntimeError::StoreOpenFailed)?;
    let mut revisions = initial_policy_snapshot()?;
    revisions.policy_revision = 0;
    Ok(StoreIdentity::new(
        StoreSlot::new(0).map_err(|_| ResourceRuntimeError::StoreOpenFailed)?,
        authority.store_uid().clone(),
        zone.clone(),
        authority.zone_uid().clone(),
        created_at,
        revisions,
    )
    .with_store_epoch(authority.store_epoch()))
}

pub fn stable_uid(domain: &str, value: &str) -> ResourceUid {
    let mut digest = Sha256::new();
    digest.update(domain.as_bytes());
    digest.update([0]);
    digest.update(value.as_bytes());
    let mut bytes: [u8; 16] = digest.finalize()[..16]
        .try_into()
        .expect("fixed digest slice");
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let rendered = format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    );
    ResourceUid::parse(rendered).expect("stable UUID is valid")
}

pub fn resource_result_error(reason: &'static str) -> ResourceError {
    ResourceError::terminal(ResourceErrorKind::InternalIntegrityFailure, reason)
}

pub fn decode_resource_result(bytes: &[u8]) -> Result<Value, ResourceError> {
    if bytes.len() > MAX_RESPONSE_CANONICAL_BYTES {
        return Err(resource_result_error(
            "resource result exceeds its byte bound",
        ));
    }
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|_| resource_result_error("resource result is malformed"))?;
    if !value.is_object() {
        return Err(resource_result_error("resource result is not an object"));
    }
    Ok(value)
}

pub fn encode_list_result(result: StoreListResult) -> Result<Value, ResourceError> {
    let resources = result
        .resources
        .iter()
        .map(|resource| decode_resource_result(&resource.canonical_json))
        .collect::<Result<Vec<_>, _>>()?;
    if result
        .next_cursor
        .as_ref()
        .is_some_and(|cursor| cursor.len() > MAX_PAGE_CURSOR_BYTES)
    {
        return Err(resource_result_error(
            "resource result cursor exceeds its byte bound",
        ));
    }
    let mut response = Map::new();
    response.insert("resources".to_owned(), Value::Array(resources));
    response.insert(
        "snapshotRevision".to_owned(),
        Value::Number(result.snapshot_revision.get().into()),
    );
    response.insert("truncated".to_owned(), Value::Bool(result.truncated));
    if let Some(cursor) = result.next_cursor {
        response.insert("nextCursor".to_owned(), Value::String(cursor));
    }
    let value = Value::Object(response);
    let encoded = serde_json::to_vec(&value)
        .map_err(|_| resource_result_error("resource result could not be encoded"))?;
    if encoded.len() > MAX_RESPONSE_CANONICAL_BYTES {
        return Err(resource_result_error(
            "resource list result exceeds its byte bound",
        ));
    }
    Ok(value)
}

pub fn resource_error_envelope(error: &ResourceError) -> Value {
    let mut body = Map::new();
    body.insert(
        "kind".to_owned(),
        Value::String(error.kind().as_str().to_owned()),
    );
    body.insert(
        "errorClass".to_owned(),
        Value::String(error.kind().as_str().to_owned()),
    );
    body.insert(
        "retryClass".to_owned(),
        Value::String(retry_class_name(error.retry_class()).to_owned()),
    );
    body.insert(
        "message".to_owned(),
        Value::String(error.reason().as_str().to_owned()),
    );
    body.insert(
        "remediation".to_owned(),
        Value::String(resource_error_remediation(error.kind()).to_owned()),
    );
    if let Some(revision) = error.current_revision() {
        body.insert(
            "currentRevision".to_owned(),
            Value::Number(revision.get().into()),
        );
    }
    if let Some(retry_after_ms) = error.retry_after_ms() {
        body.insert(
            "retryAfterMs".to_owned(),
            Value::Number(retry_after_ms.into()),
        );
    }
    let mut envelope = Map::new();
    envelope.insert("type".to_owned(), Value::String("error".to_owned()));
    envelope.insert("error".to_owned(), Value::Object(body));
    Value::Object(envelope)
}

pub fn public_operation_id(request: &Value, peer_uid: u32, method: &str) -> String {
    request
        .get("operationId")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| {
            let resource_type = request
                .get("resourceType")
                .and_then(Value::as_str)
                .unwrap_or("resource");
            let target = request
                .get("resourceRef")
                .or_else(|| request.get("executionRef"))
                .and_then(Value::as_str)
                .unwrap_or("unaddressed");
            let digest = Sha256::digest(format!("{method}:{resource_type}:{target}").as_bytes());
            let suffix = digest
                .iter()
                .take(8)
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            format!("public-{peer_uid}-{method}-{resource_type}-{suffix}")
        })
}

/// Return a Resource API-safe operation identity for an internal mutation.
///
/// Resource references contain `/`, and controller-generated operation
/// identities are not allowed to carry arbitrary resource text. Hashing the
/// complete semantic identity keeps the operation stable while fitting the
/// bounded metadata-token contract.
pub fn bounded_operation_id(operation: &str) -> String {
    let digest = Sha256::digest(operation.as_bytes());
    format!("d2b-op-sha256:{digest:x}")
}

pub fn compatibility_error_envelope(error: ResourceRuntimeError) -> Value {
    let (kind, retry_class, reason) = match error {
        ResourceRuntimeError::AuthenticationUnavailable
        | ResourceRuntimeError::PolicyUnavailable
        | ResourceRuntimeError::IdentityUnbound => (
            ResourceErrorKind::AuthorizationDenied,
            RetryClass::Reauthorize,
            "authenticated local Zone session or policy is unavailable",
        ),
        ResourceRuntimeError::ControllerEndpointUnavailable
        | ResourceRuntimeError::WatchUnavailable
        | ResourceRuntimeError::AuthorityUnavailable
        | ResourceRuntimeError::HandlerNotReady
        | ResourceRuntimeError::ProviderPathUnavailable
        | ResourceRuntimeError::PlaneUnavailable
        | ResourceRuntimeError::CoreStartupFailed => (
            ResourceErrorKind::ResourcePlaneUnavailable,
            RetryClass::AfterDelay,
            "Zone resource runtime is not ready",
        ),
        ResourceRuntimeError::CapabilityUnavailable => (
            ResourceErrorKind::UnsupportedCapability,
            RetryClass::Never,
            "the requested resource operation is not registered",
        ),
        _ => (
            ResourceErrorKind::InternalIntegrityFailure,
            RetryClass::Never,
            "the public resource request was refused",
        ),
    };
    resource_error_envelope(
        &ResourceError::new(
            kind,
            None,
            None,
            retry_class,
            ResourceErrorReason::parse(reason).expect("fixed compatibility error reason"),
        )
        .expect("fixed compatibility error"),
    )
}

pub fn public_request_meta(operation_id: &str) -> wire::RequestMeta {
    let mut meta = wire::RequestMeta::new();
    meta.operation_id = operation_id.to_owned();
    meta.idempotency_key = operation_id.to_owned();
    meta.correlation_id = operation_id.to_owned();
    meta.trace_id = operation_id.to_owned();
    meta.deadline_ms = 30_000;
    meta
}

pub fn public_list_request(parsed: ParsedListRequest, operation_id: &str) -> wire::ListRequest {
    let mut request = wire::ListRequest::new();
    request.meta = protobuf::MessageField::some(public_request_meta(operation_id));
    request.resource_types = parsed
        .resource_types
        .into_iter()
        .map(|resource_type| resource_type.to_canonical_string())
        .collect();
    request.filters = parsed
        .filters
        .into_iter()
        .map(|filter| {
            let mut wire_filter = wire::ListFilter::new();
            wire_filter.field = filter.field;
            wire_filter.values = filter.values;
            wire_filter
        })
        .collect();
    if !parsed.resource_names.is_empty() {
        let mut name_filter = wire::ListFilter::new();
        name_filter.field = "metadata.name".to_owned();
        name_filter.values = parsed
            .resource_names
            .into_iter()
            .map(|name| name.to_canonical_string())
            .collect();
        request.filters.push(name_filter);
    }
    request.page_size = parsed.page_size;
    if let Some(cursor) = parsed.cursor {
        let mut page_cursor = wire::PageCursor::new();
        page_cursor.value = cursor;
        request.cursor = protobuf::MessageField::some(page_cursor);
    }
    let mut projection = wire::Projection::new();
    projection.kind = protobuf::EnumOrUnknown::new(match parsed.projection {
        StoreProjection::Full => wire::ProjectionKind::PROJECTION_KIND_FULL,
        StoreProjection::BaseOnly => wire::ProjectionKind::PROJECTION_KIND_BASE_ONLY,
        StoreProjection::MetadataOnly => wire::ProjectionKind::PROJECTION_KIND_METADATA_ONLY,
    });
    request.projection = protobuf::MessageField::some(projection);
    request
}

pub fn encode_public_resource(
    resource: &wire::ResourceEnvelopeBytes,
) -> Result<Value, ResourceRuntimeError> {
    if resource.canonical_json.len() > MAX_RESPONSE_CANONICAL_BYTES {
        return Err(ResourceRuntimeError::ResponseInvalid);
    }
    let value: Value = serde_json::from_slice(&resource.canonical_json)
        .map_err(|_| ResourceRuntimeError::ResponseInvalid)?;
    if !value.is_object() {
        return Err(ResourceRuntimeError::ResponseInvalid);
    }
    Ok(value)
}

pub fn public_api_error(error: &wire::ResourceError) -> Value {
    let kind = resource_error_kind_from_wire(error.kind.enum_value().ok());
    let retry_class = retry_class_from_wire(error.retry_class.enum_value().ok());
    let current_revision = matches!(
        kind,
        ResourceErrorKind::ResourceConflict
            | ResourceErrorKind::AuthorizationDenied
            | ResourceErrorKind::RevisionExpired
    )
    .then(|| error.current_revision.map(ZoneRevision::new))
    .flatten();
    let retry_after_ms = error.retry_after_ms.filter(|delay| {
        (1..=d2b_contracts_resource::v3::MAX_RESOURCE_ERROR_RETRY_AFTER_MS).contains(delay)
    });
    let retry_class = if retry_after_ms.is_some() {
        RetryClass::AfterDelay
    } else if retry_class == RetryClass::AfterDelay {
        RetryClass::Never
    } else {
        retry_class
    };
    let reason = ResourceErrorReason::parse("resource API returned a typed error")
        .expect("fixed public resource error reason");
    let error = ResourceError::new(kind, current_revision, retry_after_ms, retry_class, reason)
        .expect("fixed public resource error");
    resource_error_envelope(&error)
}

pub fn resource_error_kind_from_wire(kind: Option<wire::ResourceErrorKind>) -> ResourceErrorKind {
    match kind {
        Some(wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_NOT_FOUND) => {
            ResourceErrorKind::ResourceNotFound
        }
        Some(wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_ALREADY_EXISTS) => {
            ResourceErrorKind::ResourceAlreadyExists
        }
        Some(wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_CONFLICT) => {
            ResourceErrorKind::ResourceConflict
        }
        Some(wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_SCHEMA_INVALID) => {
            ResourceErrorKind::ResourceSchemaInvalid
        }
        Some(wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_REF_INVALID) => {
            ResourceErrorKind::ResourceRefInvalid
        }
        Some(wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_OWNER_CYCLE) => {
            ResourceErrorKind::ResourceOwnerCycle
        }
        Some(wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_OWNER_DEPTH) => {
            ResourceErrorKind::ResourceOwnerDepth
        }
        Some(wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_FINALIZER_DENIED) => {
            ResourceErrorKind::ResourceFinalizerDenied
        }
        Some(wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_PROVIDER_UNAVAILABLE) => {
            ResourceErrorKind::ResourceProviderUnavailable
        }
        Some(wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_CONTROLLER_MISMATCH) => {
            ResourceErrorKind::ResourceControllerMismatch
        }
        Some(wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_STATUS_OWNER_MISMATCH) => {
            ResourceErrorKind::ResourceStatusOwnerMismatch
        }
        Some(wire::ResourceErrorKind::RESOURCE_ERROR_KIND_STATUS_OVERSIZE) => {
            ResourceErrorKind::StatusOversize
        }
        Some(wire::ResourceErrorKind::RESOURCE_ERROR_KIND_STATUS_PROVIDER_SCHEMA_INVALID) => {
            ResourceErrorKind::StatusProviderSchemaInvalid
        }
        Some(wire::ResourceErrorKind::RESOURCE_ERROR_KIND_STATUS_PROVIDER_OVERLAP) => {
            ResourceErrorKind::StatusProviderOverlap
        }
        Some(wire::ResourceErrorKind::RESOURCE_ERROR_KIND_SPEC_PROVIDER_SCHEMA_INVALID) => {
            ResourceErrorKind::SpecProviderSchemaInvalid
        }
        Some(wire::ResourceErrorKind::RESOURCE_ERROR_KIND_SPEC_PROVIDER_SHADOW) => {
            ResourceErrorKind::SpecProviderShadow
        }
        Some(wire::ResourceErrorKind::RESOURCE_ERROR_KIND_UNSUPPORTED_CAPABILITY) => {
            ResourceErrorKind::UnsupportedCapability
        }
        Some(wire::ResourceErrorKind::RESOURCE_ERROR_KIND_EXPEDITED_NOT_AUTHORIZED) => {
            ResourceErrorKind::ExpeditedNotAuthorized
        }
        Some(wire::ResourceErrorKind::RESOURCE_ERROR_KIND_EXPEDITED_QUOTA_EXCEEDED) => {
            ResourceErrorKind::ExpeditedQuotaExceeded
        }
        Some(wire::ResourceErrorKind::RESOURCE_ERROR_KIND_EXPEDITED_RECONCILE_PENDING) => {
            ResourceErrorKind::ExpeditedReconcilePending
        }
        Some(wire::ResourceErrorKind::RESOURCE_ERROR_KIND_UPGRADE_REQUIRED) => {
            ResourceErrorKind::UpgradeRequired
        }
        Some(wire::ResourceErrorKind::RESOURCE_ERROR_KIND_ENDPOINT_RESOLVE_DENIED) => {
            ResourceErrorKind::EndpointResolveDenied
        }
        Some(wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RELAY_DENIED) => {
            ResourceErrorKind::RelayDenied
        }
        Some(wire::ResourceErrorKind::RESOURCE_ERROR_KIND_ROLE_RELAY_GRANT_RESTRICTED) => {
            ResourceErrorKind::RoleRelayGrantRestricted
        }
        Some(wire::ResourceErrorKind::RESOURCE_ERROR_KIND_AUTHORIZATION_DENIED) => {
            ResourceErrorKind::AuthorizationDenied
        }
        Some(wire::ResourceErrorKind::RESOURCE_ERROR_KIND_REVISION_EXPIRED) => {
            ResourceErrorKind::RevisionExpired
        }
        Some(wire::ResourceErrorKind::RESOURCE_ERROR_KIND_BACKPRESSURE) => {
            ResourceErrorKind::Backpressure
        }
        Some(wire::ResourceErrorKind::RESOURCE_ERROR_KIND_TIMEOUT) => ResourceErrorKind::Timeout,
        Some(wire::ResourceErrorKind::RESOURCE_ERROR_KIND_CANCELLED) => {
            ResourceErrorKind::Cancelled
        }
        Some(wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_PLANE_UNAVAILABLE) => {
            ResourceErrorKind::ResourcePlaneUnavailable
        }
        Some(wire::ResourceErrorKind::RESOURCE_ERROR_KIND_INTERNAL_INTEGRITY_FAILURE)
        | Some(wire::ResourceErrorKind::RESOURCE_ERROR_KIND_UNSPECIFIED)
        | None => ResourceErrorKind::InternalIntegrityFailure,
    }
}

pub fn retry_class_from_wire(retry_class: Option<wire::RetryClass>) -> RetryClass {
    match retry_class {
        Some(wire::RetryClass::RETRY_CLASS_IMMEDIATE) => RetryClass::Immediate,
        Some(wire::RetryClass::RETRY_CLASS_AFTER_DELAY) => RetryClass::AfterDelay,
        Some(wire::RetryClass::RETRY_CLASS_REAUTHORIZE) => RetryClass::Reauthorize,
        Some(wire::RetryClass::RETRY_CLASS_NEVER)
        | Some(wire::RetryClass::RETRY_CLASS_UNSPECIFIED)
        | None => RetryClass::Never,
    }
}

pub fn encode_public_get_response(
    response: wire::GetResponse,
) -> Result<Value, ResourceRuntimeError> {
    if let Some(error) = response.error.as_ref() {
        tracing::warn!(
            kind = ?error.kind,
            retry_class = ?error.retry_class,
            retry_after_ms = ?error.retry_after_ms,
            reason = %error.reason,
            "public Resource Get returned an API error"
        );
        return Ok(public_api_error(error));
    }
    let resource = response
        .resource
        .as_ref()
        .ok_or(ResourceRuntimeError::ResponseInvalid)?;
    encode_public_resource(resource)
}

pub fn encode_public_list_response(
    response: wire::ListResponse,
) -> Result<Value, ResourceRuntimeError> {
    if let Some(error) = response.error.as_ref() {
        return Ok(public_api_error(error));
    }
    let resources = response
        .resources
        .iter()
        .map(encode_public_resource)
        .collect::<Result<Vec<_>, _>>()?;
    let mut body = Map::new();
    body.insert("resources".to_owned(), Value::Array(resources));
    body.insert(
        "snapshotRevision".to_owned(),
        Value::Number(response.snapshot_revision.into()),
    );
    body.insert("truncated".to_owned(), Value::Bool(response.truncated));
    if let Some(cursor) = response.next_cursor.as_ref() {
        body.insert("nextCursor".to_owned(), Value::String(cursor.value.clone()));
    }
    Ok(Value::Object(body))
}

const fn retry_class_name(retry_class: RetryClass) -> &'static str {
    match retry_class {
        RetryClass::Never => "never",
        RetryClass::Immediate => "immediate",
        RetryClass::AfterDelay => "after-delay",
        RetryClass::Reauthorize => "reauthorize",
    }
}

const fn resource_error_remediation(kind: ResourceErrorKind) -> &'static str {
    match kind {
        ResourceErrorKind::AuthorizationDenied => {
            "authenticate an exact local Zone session and install its matching policy before retrying"
        }
        ResourceErrorKind::UnsupportedCapability => {
            "use a method exposed by the registered Zone service"
        }
        ResourceErrorKind::ResourcePlaneUnavailable => {
            "wait for Zone runtime readiness and retry after the authoritative plane is published"
        }
        ResourceErrorKind::InternalIntegrityFailure => "repair the resource result before retrying",
        _ => "follow the typed resource error retry policy",
    }
}

pub fn configuration_cleanup_pending(
    resource: &StoredResource,
    active_configuration_generation: u64,
) -> bool {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&resource.canonical_json) else {
        return false;
    };
    let Some(metadata) = value.get("metadata").and_then(serde_json::Value::as_object) else {
        return false;
    };
    metadata
        .get("managedBy")
        .and_then(serde_json::Value::as_str)
        == Some("configuration")
        && metadata
            .get("configurationGeneration")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|generation| generation < active_configuration_generation)
        && metadata
            .get("deletionRequestedAt")
            .is_some_and(|value| !value.is_null())
}

pub async fn persist_resource_status(
    client: &ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>,
    resource: &StoredResource,
    status: &serde_json::Value,
) -> Result<(), ResourceRuntimeError> {
    persist_resource_status_with_projection(client, resource, status, None).await
}

pub async fn persist_resource_status_with_projection(
    client: &ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>,
    resource: &StoredResource,
    status: &serde_json::Value,
    resource_projection: Option<&serde_json::Value>,
) -> Result<(), ResourceRuntimeError> {
    let mut value = CanonicalJsonValue::parse(&resource.canonical_json)
        .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
    let root = match &mut value {
        CanonicalJsonValue::Object(root) => root,
        _ => return Err(ResourceRuntimeError::HandlerNotReady),
    };
    let status_bytes =
        serde_json::to_vec(status).map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
    let desired_status = CanonicalJsonValue::parse(&status_bytes)
        .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
    let CanonicalJsonValue::Object(resource_status) = desired_status else {
        return Err(ResourceRuntimeError::HandlerNotReady);
    };
    let phase = resource_status
        .get("phase")
        .cloned()
        .ok_or(ResourceRuntimeError::HandlerNotReady)?;
    let Some(CanonicalJsonValue::Object(status)) = root.get_mut("status") else {
        return Err(ResourceRuntimeError::HandlerNotReady);
    };
    let previous_status = CanonicalJsonValue::Object(status.clone());
    let now = current_status_timestamp().as_str().to_owned();
    status.insert("phase".to_owned(), phase.clone());
    status.insert(
        "observedGeneration".to_owned(),
        CanonicalJsonValue::Integer(resource.generation.get() as i64),
    );
    status.insert(
        "lastReconciledAt".to_owned(),
        CanonicalJsonValue::String(now.clone()),
    );
    if matches!(
        phase,
        CanonicalJsonValue::String(ref phase) if phase == "Ready"
    ) && status
        .get("startedAt")
        .is_none_or(|value| matches!(value, CanonicalJsonValue::Null))
    {
        status.insert(
            "startedAt".to_owned(),
            CanonicalJsonValue::String(now.clone()),
        );
    }
    let resource_projection = select_resource_projection(resource_status, resource_projection)?;
    status.insert("resource".to_owned(), resource_projection);
    let Some(CanonicalJsonValue::Object(update)) = status.get_mut("update") else {
        return Err(ResourceRuntimeError::HandlerNotReady);
    };
    update.insert(
        "observedGeneration".to_owned(),
        CanonicalJsonValue::Integer(resource.generation.get() as i64),
    );
    update.insert("lastAssessedAt".to_owned(), CanonicalJsonValue::String(now));
    let candidate_status = CanonicalJsonValue::Object(status.clone());
    if status_semantically_equal(&previous_status, &candidate_status) {
        return Ok(());
    }
    persist_resource_status_candidate(client, resource, value, "system-core-status").await
}

/// Persist only the bounded controller-session evidence below `status.resource`.
///
/// Controller-session transport must not advance the owning Process status
/// generation or phase; the Process controller owns those fields.
pub async fn persist_resource_controller_session_evidence(
    api: &RedbRegisteredControllerApi,
    resource: &StoredResource,
    controller_session: Option<&serde_json::Value>,
) -> Result<(), ResourceRuntimeError> {
    let Some(value) = resource_controller_session_candidate(resource, controller_session)? else {
        return Ok(());
    };
    let operation = resource_status_operation_id(resource, "controller-session-evidence");
    api.persist_assigned_status(resource, value.to_canonical_bytes(), &operation)
        .await
        .map_err(assigned_status_source_error)
}

fn assigned_status_source_error(error: SourceError) -> ResourceRuntimeError {
    let kind = match error {
        SourceError::Conflict(_) => ResourceErrorKind::ResourceConflict,
        SourceError::Backpressure => ResourceErrorKind::Backpressure,
        SourceError::Timeout => ResourceErrorKind::Timeout,
        SourceError::Cancelled => ResourceErrorKind::Cancelled,
        SourceError::Unavailable => ResourceErrorKind::ResourcePlaneUnavailable,
        SourceError::Integrity => ResourceErrorKind::InternalIntegrityFailure,
    };
    ResourceRuntimeError::ResourceStatusUpdateFailed(kind)
}

fn resource_controller_session_candidate(
    resource: &StoredResource,
    controller_session: Option<&serde_json::Value>,
) -> Result<Option<CanonicalJsonValue>, ResourceRuntimeError> {
    let mut value = CanonicalJsonValue::parse(&resource.canonical_json)
        .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
    let root = match &mut value {
        CanonicalJsonValue::Object(root) => root,
        _ => return Err(ResourceRuntimeError::HandlerNotReady),
    };
    let Some(CanonicalJsonValue::Object(status)) = root.get_mut("status") else {
        return Err(ResourceRuntimeError::HandlerNotReady);
    };
    let previous_status = CanonicalJsonValue::Object(status.clone());
    let mut projection = match status.get("resource") {
        Some(CanonicalJsonValue::Object(projection)) => projection.clone(),
        Some(_) => return Err(ResourceRuntimeError::HandlerNotReady),
        None => BTreeMap::new(),
    };
    match controller_session {
        Some(controller_session) => {
            let bytes = serde_json::to_vec(controller_session)
                .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
            let controller_session = CanonicalJsonValue::parse(&bytes)
                .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
            if !matches!(controller_session, CanonicalJsonValue::Object(_)) {
                return Err(ResourceRuntimeError::HandlerNotReady);
            }
            projection.insert("controllerSession".to_owned(), controller_session);
        }
        None => {
            projection.remove("controllerSession");
        }
    }
    status.insert(
        "resource".to_owned(),
        CanonicalJsonValue::Object(projection),
    );
    let candidate_status = CanonicalJsonValue::Object(status.clone());
    if status_semantically_equal(&previous_status, &candidate_status) {
        return Ok(None);
    }
    Ok(Some(value))
}

async fn persist_resource_status_candidate(
    client: &ResourceApiClient<RedbBackend, UnavailableUpgradeDispatcher>,
    resource: &StoredResource,
    value: CanonicalJsonValue,
    operation_scope: &str,
) -> Result<(), ResourceRuntimeError> {
    let canonical = value.to_canonical_bytes();
    let envelope = ResourceEnvelope::from_json(&canonical)
        .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
    let digest = envelope
        .digest()
        .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
    let mut identity = wire::ResourceIdentity::new();
    identity.zone = resource.zone.to_canonical_string();
    identity.resource_type = resource.resource_ref.resource_type().to_canonical_string();
    identity.name = resource.resource_ref.name().to_canonical_string();
    identity.uid = Some(resource.uid.as_str().to_owned());
    identity.generation = Some(resource.generation.get());
    identity.revision = Some(resource.revision.get());

    let mut resource_bytes = wire::ResourceEnvelopeBytes::new();
    resource_bytes.identity = protobuf::MessageField::some(identity.clone());
    resource_bytes.canonical_json = canonical;
    resource_bytes.payload_digest = digest;

    let mut precondition = wire::Precondition::new();
    precondition.kind =
        protobuf::EnumOrUnknown::new(wire::PreconditionKind::PRECONDITION_KIND_EXACT_REVISION);
    precondition.expected_revision = Some(resource.revision.get());
    precondition.expected_uid = Some(resource.uid.as_str().to_owned());

    let operation = resource_status_operation_id(resource, operation_scope);
    let mut mutation = wire::Mutation::new();
    mutation.kind = protobuf::EnumOrUnknown::new(wire::MutationKind::MUTATION_KIND_UPDATE_STATUS);
    mutation.target = protobuf::MessageField::some(identity);
    mutation.precondition = protobuf::MessageField::some(precondition);
    mutation.resource = protobuf::MessageField::some(resource_bytes);

    let mut meta = wire::RequestMeta::new();
    meta.operation_id = operation.clone();
    meta.idempotency_key = operation.clone();
    meta.correlation_id = operation.clone();
    meta.trace_id = operation;
    meta.deadline_ms = 10_000;

    let mut request = wire::UpdateStatusRequest::new();
    request.meta = protobuf::MessageField::some(meta);
    request.mutation = protobuf::MessageField::some(mutation);
    let response = client.update_status(request).await;
    if let Some(error) = response.error.as_ref() {
        tracing::warn!(
            error_kind = ?error.kind,
            reason = %error.reason,
            "public Resource status update was refused"
        );
        return Err(ResourceRuntimeError::ResourceStatusUpdateFailed(
            resource_error_kind_from_wire(error.kind.enum_value().ok()),
        ));
    }
    if response.resource.is_none() {
        return Err(ResourceRuntimeError::StoreReadFailed);
    }
    Ok(())
}

fn resource_status_operation_id(resource: &StoredResource, operation_scope: &str) -> String {
    bounded_operation_id(&format!(
        "{operation_scope}-{}-{}-{}-{}",
        resource.resource_ref.to_canonical_string(),
        resource.uid.as_str(),
        resource.generation.get(),
        resource.revision.get()
    ))
}

fn status_semantically_equal(current: &CanonicalJsonValue, candidate: &CanonicalJsonValue) -> bool {
    fn without_reconciliation_timestamps(mut value: CanonicalJsonValue) -> CanonicalJsonValue {
        if let CanonicalJsonValue::Object(root) = &mut value {
            root.remove("lastReconciledAt");
            if let Some(CanonicalJsonValue::Object(update)) = root.get_mut("update") {
                update.remove("lastAssessedAt");
            }
        }
        value
    }

    without_reconciliation_timestamps(current.clone())
        == without_reconciliation_timestamps(candidate.clone())
}

fn select_resource_projection(
    resource_status: BTreeMap<String, CanonicalJsonValue>,
    resource_projection: Option<&serde_json::Value>,
) -> Result<CanonicalJsonValue, ResourceRuntimeError> {
    match resource_projection {
        Some(resource_projection) => {
            let bytes = serde_json::to_vec(resource_projection)
                .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
            CanonicalJsonValue::parse(&bytes).map_err(|_| ResourceRuntimeError::HandlerNotReady)
        }
        None => Ok(CanonicalJsonValue::Object(resource_status)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource_api::parse_list_request;
    use d2b_contracts_resource::v3::ResourceGeneration;
    use d2b_resource_api::authz::{
        ApiMethod, AuthorizationDenial, AuthorizationRequest, AuthorizationTarget,
    };
    use std::sync::atomic::Ordering;

    #[test]
    fn bootstrap_zone_create_body_is_complete_after_uid_placeholder() {
        let zone = ZoneId::parse("work").unwrap();
        let mut payload =
            CanonicalJsonValue::parse(&bootstrap_zone_resource_payload(&zone).unwrap()).unwrap();
        let CanonicalJsonValue::Object(root) = &mut payload else {
            unreachable!();
        };
        let CanonicalJsonValue::Object(metadata) = root.get_mut("metadata").unwrap() else {
            unreachable!();
        };
        assert!(!metadata.contains_key("uid"));
        metadata.insert(
            "uid".to_owned(),
            CanonicalJsonValue::String("00000000-0000-4000-8000-000000000000".to_owned()),
        );

        let envelope = ResourceEnvelope::from_json(&payload.to_canonical_bytes())
            .expect("bootstrap Zone create body must be a complete resource envelope");
        assert_eq!(envelope.resource_type().as_str(), "Zone");
        assert_eq!(envelope.metadata().name().as_str(), zone.as_str());
        assert_eq!(envelope.metadata().zone(), &zone);
        assert_eq!(
            envelope.metadata().generation(),
            ResourceGeneration::new(1).unwrap()
        );
        assert_eq!(envelope.metadata().revision(), ZoneRevision::new(1));
        assert_eq!(
            envelope.metadata().uid().as_str(),
            "00000000-0000-4000-8000-000000000000"
        );
        assert_eq!(envelope.metadata().managed_by(), ManagedBy::Controller);
    }

    #[tokio::test]
    async fn startup_store_reads_retry_transient_metadata_and_get_pressure() {
        let zone = ZoneId::parse("work").unwrap();
        for (operation, kind) in [
            ("runtime-metadata", StoreErrorKind::StoreBackpressure),
            ("shared-provider-runner-provider", StoreErrorKind::Backpressure),
        ] {
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let calls_for_read = Arc::clone(&calls);
            let result = retry_transient_store_read(&zone, operation, move || {
                let attempt = calls_for_read.fetch_add(1, Ordering::SeqCst);
                async move {
                    if attempt == 0 {
                        Err(StoreError::new(
                            kind,
                            None,
                            None,
                            RetryClass::Never,
                            "test-startup-store-read",
                        ))
                    } else {
                        Ok(attempt)
                    }
                }
            })
            .await;

            assert_eq!(result, Ok(1));
            assert_eq!(calls.load(Ordering::SeqCst), 2, "{operation}");
        }
    }

    #[tokio::test]
    async fn startup_store_list_timeout_retries_after_worker_lifetime() {
        let zone = ZoneId::parse("work").unwrap();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls_for_read = Arc::clone(&calls);
        let retry = tokio::spawn(async move {
            retry_transient_store_list(&zone, "startup-list-timeout", move || {
                let attempt = calls_for_read.fetch_add(1, Ordering::SeqCst);
                async move {
                    if attempt == 0 {
                        tokio::time::sleep(
                            d2b_resource_store_redb::LIST_READ_LIFETIME
                                + Duration::from_millis(25),
                        )
                        .await;
                        Err(StoreError::new(
                            StoreErrorKind::Timeout,
                            None,
                            None,
                            RetryClass::Never,
                            "redb-read-lifetime-exceeded",
                        ))
                    } else {
                        Ok(attempt)
                    }
                }
            })
            .await
        });
        tokio::task::yield_now().await;
        tokio::time::sleep(
            d2b_resource_store_redb::LIST_READ_LIFETIME + Duration::from_millis(25),
        )
        .await;
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(10)).await;
        for _ in 0..3 {
            tokio::task::yield_now().await;
        }
        assert_eq!(retry.await.unwrap(), Ok(1));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn startup_store_retry_uses_delayed_async_backoff() {
        let zone = ZoneId::parse("work").unwrap();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls_for_read = Arc::clone(&calls);
        let retry = tokio::spawn(async move {
            retry_transient_store_read(&zone, "startup-backoff", move || {
                let attempt = calls_for_read.fetch_add(1, Ordering::SeqCst);
                std::future::ready(if attempt < 2 {
                    Err(StoreError::new(
                        StoreErrorKind::Backpressure,
                        None,
                        None,
                        RetryClass::Never,
                        "test-startup-backpressure",
                    ))
                } else {
                    Ok(attempt)
                })
            })
            .await
        });

        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        tokio::time::sleep(Duration::from_millis(4)).await;
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        tokio::time::sleep(Duration::from_millis(5)).await;
        for _ in 0..3 {
            tokio::task::yield_now().await;
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        tokio::time::sleep(Duration::from_millis(10)).await;
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        tokio::time::sleep(Duration::from_millis(15)).await;
        for _ in 0..3 {
            tokio::task::yield_now().await;
        }
        assert_eq!(retry.await.unwrap(), Ok(2));
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn startup_store_read_exhaustion_preserves_typed_error_and_fails_closed() {
        let zone = ZoneId::parse("work").unwrap();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls_for_read = Arc::clone(&calls);
        let exhausted = retry_transient_store_read(&zone, "process-resource-reconcile", move || {
            calls_for_read.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Err::<(), _>(StoreError::new(
                StoreErrorKind::Timeout,
                None,
                None,
                RetryClass::Never,
                "test-startup-store-timeout",
            )))
        })
        .await
        .unwrap_err();
        assert_eq!(exhausted.kind(), StoreErrorKind::Timeout);
        assert_eq!(calls.load(Ordering::SeqCst), 4);

        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls_for_read = Arc::clone(&calls);
        let not_found =
            retry_transient_store_read(&zone, "interaction-presence-providers", move || {
                calls_for_read.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Err::<(), _>(StoreError::new(
                    StoreErrorKind::ResourceNotFound,
                    None,
                    None,
                    RetryClass::Never,
                    "test-startup-store-not-found",
                )))
            })
            .await
            .unwrap_err();
        assert_eq!(not_found.kind(), StoreErrorKind::ResourceNotFound);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        for kind in [
            StoreErrorKind::AuthorizationDenied,
            StoreErrorKind::StoreIntegrityFailure,
        ] {
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let calls_for_read = Arc::clone(&calls);
            let error = retry_transient_store_read(&zone, "runtime-integrity-check", move || {
                calls_for_read.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Err::<(), _>(StoreError::new(
                    kind,
                    None,
                    None,
                    RetryClass::Never,
                    "test-startup-store-non-transient",
                )))
            })
            .await
            .unwrap_err();
            assert_eq!(error.kind(), kind);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }

    fn user_resource(name: &str, uid: &str, os_username: &str, phase: &str) -> StoredResource {
        let zone = ZoneId::parse("work").unwrap();
        let value = json!({
            "apiVersion": "resources.d2bus.org/v3",
            "type": "User",
            "metadata": {
                "name": name,
                "zone": zone.as_str(),
                "uid": uid,
                "generation": 1,
                "revision": 1,
                "ownerRef": null,
                "finalizers": [],
                "deletionRequestedAt": null,
                "createdAt": "2026-08-26T00:00:00.000Z",
                "updatedAt": "2026-08-26T00:00:00.000Z",
                "managedBy": "configuration",
                "configurationGeneration": 1,
            },
            "spec": {
                "displayName": "",
                "groups": [],
                "osUsername": os_username,
            },
            "status": {
                "completedAt": null,
                "conditions": [],
                "lastReconciledAt": null,
                "observedGeneration": 1,
                "outcome": null,
                "phase": phase,
                "resource": {},
                "startedAt": null,
                "update": {
                    "dependencies": {"count": 0, "refs": []},
                    "disruption": "None",
                    "lastAssessedAt": null,
                    "observedGeneration": 1,
                    "operationId": null,
                    "owned": {"count": 0, "refs": []},
                    "preserveState": true,
                    "reasons": [],
                    "state": "Current",
                    "targetGeneration": 1,
                },
            },
        });
        let canonical_json = d2b_contracts_resource::v3::canonical_json_bytes(&value).unwrap();
        let envelope = ResourceEnvelope::from_json(&canonical_json).unwrap();
        StoredResource {
            resource_ref: ResourceRef::parse(&format!("User/{name}")).unwrap(),
            zone,
            uid: ResourceUid::parse(uid).unwrap(),
            owner_uid: None,
            owner_generation: None,
            generation: ResourceGeneration::new(1).unwrap(),
            revision: ZoneRevision::new(1),
            canonical_json,
            payload_digest: envelope.digest().unwrap(),
        }
    }

    fn policy_resource(resource_type: &str, name: &str, uid: &str, spec: Value) -> StoredResource {
        let zone = ZoneId::parse("work").unwrap();
        let value = json!({
            "apiVersion": "resources.d2bus.org/v3",
            "type": resource_type,
            "metadata": {
                "name": name,
                "zone": zone.as_str(),
                "uid": uid,
                "generation": 1,
                "revision": 1,
                "ownerRef": null,
                "finalizers": [],
                "deletionRequestedAt": null,
                "createdAt": "2026-08-26T00:00:00.000Z",
                "updatedAt": "2026-08-26T00:00:00.000Z",
                "managedBy": "configuration",
                "configurationGeneration": 1,
            },
            "spec": spec,
            "status": {
                "completedAt": null,
                "conditions": [],
                "lastReconciledAt": null,
                "observedGeneration": 1,
                "outcome": null,
                "phase": "Ready",
                "resource": {},
                "startedAt": null,
                "update": {
                    "dependencies": {"count": 0, "refs": []},
                    "disruption": "None",
                    "lastAssessedAt": null,
                    "observedGeneration": 1,
                    "operationId": null,
                    "owned": {"count": 0, "refs": []},
                    "preserveState": true,
                    "reasons": [],
                    "state": "Current",
                    "targetGeneration": 1,
                },
            },
        });
        let canonical_json = d2b_contracts_resource::v3::canonical_json_bytes(&value).unwrap();
        let envelope = ResourceEnvelope::from_json(&canonical_json).unwrap();
        StoredResource {
            resource_ref: ResourceRef::parse(&format!("{resource_type}/{name}")).unwrap(),
            zone,
            uid: ResourceUid::parse(uid).unwrap(),
            owner_uid: None,
            owner_generation: None,
            generation: ResourceGeneration::new(1).unwrap(),
            revision: ZoneRevision::new(1),
            canonical_json,
            payload_digest: envelope.digest().unwrap(),
        }
    }

    fn set_status(resource: &mut StoredResource, phase: &str, observed_generation: u64) {
        let mut value: Value = serde_json::from_slice(&resource.canonical_json).unwrap();
        value["status"]["phase"] = json!(phase);
        value["status"]["observedGeneration"] = json!(observed_generation);
        value["status"]["update"]["observedGeneration"] = json!(observed_generation);
        resource.canonical_json = d2b_contracts_resource::v3::canonical_json_bytes(&value).unwrap();
        resource.payload_digest = ResourceEnvelope::from_json(&resource.canonical_json)
            .unwrap()
            .digest()
            .unwrap();
    }

    fn set_identity(resource: &mut StoredResource, uid: &str, generation: u64) {
        let mut value: Value = serde_json::from_slice(&resource.canonical_json).unwrap();
        value["metadata"]["uid"] = json!(uid);
        value["metadata"]["generation"] = json!(generation);
        value["status"]["observedGeneration"] = json!(generation);
        value["status"]["update"]["observedGeneration"] = json!(generation);
        resource.uid = ResourceUid::parse(uid).unwrap();
        resource.generation = ResourceGeneration::new(generation).unwrap();
        resource.canonical_json = d2b_contracts_resource::v3::canonical_json_bytes(&value).unwrap();
        resource.payload_digest = ResourceEnvelope::from_json(&resource.canonical_json)
            .unwrap()
            .digest()
            .unwrap();
    }

    fn set_binding_subjects(resource: &mut StoredResource, subjects: &[&str]) {
        let mut value: Value = serde_json::from_slice(&resource.canonical_json).unwrap();
        value["spec"]["subjects"] = json!(subjects);
        resource.canonical_json = d2b_contracts_resource::v3::canonical_json_bytes(&value).unwrap();
        resource.payload_digest = ResourceEnvelope::from_json(&resource.canonical_json)
            .unwrap()
            .digest()
            .unwrap();
    }

    fn subject_context(subject_ref: &str, subject_uid: &str) -> AuthenticatedSubjectContext {
        AuthenticatedSubjectContext::new(
            ResourceRef::parse(subject_ref).unwrap(),
            ResourceUid::parse(subject_uid).unwrap(),
            ResourceRef::parse("Zone/work").unwrap(),
            EvidenceClass::UnixPeer,
            SessionPurpose::parse("resource-api").unwrap(),
            ServiceName::parse("d2b.resource.v3").unwrap(),
            SessionBinding::new(
                SchemaFingerprint::parse(format!("sha256:{}", "1".repeat(64))).unwrap(),
                TransportBinding::new(
                    IdentityLocality::Local,
                    BindingDigest::parse(format!("sha256:{}", "2".repeat(64))).unwrap(),
                ),
                ReconnectGeneration::new(1).unwrap(),
                TranscriptHash::from_bytes([3; 32]),
            ),
        )
    }

    fn policy_request(zone: &ZoneId) -> AuthorizationRequest {
        AuthorizationRequest {
            method: ApiMethod::Get,
            zone: zone.clone(),
            targets: vec![AuthorizationTarget {
                resource_type: ResourceTypeName::parse("Guest").unwrap(),
                resource_name: Some(ResourceName::parse("workstation").unwrap()),
                verb: ResourceVerb::Get,
                subresource: None,
                execution_ref: None,
            }],
        }
    }

    #[test]
    fn committed_policy_loader_uses_the_closed_local_subject_resource_set() {
        assert_eq!(
            ROLE_BINDING_SUBJECT_RESOURCE_TYPES,
            ["Zone", "User", "Provider", "Host", "Guest", "Process"]
        );
        assert_eq!(
            COMMITTED_POLICY_RESOURCE_TYPES,
            [
                "Role",
                "RoleBinding",
                "Zone",
                "User",
                "Provider",
                "Host",
                "Guest",
                "Process",
            ]
        );
    }

    #[test]
    fn system_core_policy_authorizes_credential_commit_batch_materialization() {
        let zone = ZoneId::parse("work").unwrap();
        let (policy, state) = compile_committed_policy(
            &zone,
            initial_policy_snapshot().unwrap(),
            ZoneRevision::new(7),
            &[],
            &[],
        )
        .unwrap();
        let authorizer = NativeAuthorizer::new(ApiCatalog::standard(), Some(policy)).unwrap();
        let system_core = subject_context(
            "Provider/system-core",
            "11111111-1111-4111-8111-111111111111",
        );
        let target = |resource_type: &str,
                      resource_name: &str,
                      verb: ResourceVerb,
                      subresource: Option<&str>| AuthorizationTarget {
            resource_type: ResourceTypeName::parse(resource_type).unwrap(),
            resource_name: Some(ResourceName::parse(resource_name).unwrap()),
            verb,
            subresource: subresource.map(str::to_owned),
            execution_ref: None,
        };
        let request = AuthorizationRequest {
            method: ApiMethod::CommitBatch,
            zone: zone.clone(),
            targets: vec![
                target("Credential", "relay-listen", ResourceVerb::Create, None),
                target(
                    "Credential",
                    "relay-listen",
                    ResourceVerb::AdminCredential,
                    Some("create"),
                ),
                target("Credential", "relay-send", ResourceVerb::Create, None),
                target(
                    "Credential",
                    "relay-send",
                    ResourceVerb::AdminCredential,
                    Some("create"),
                ),
                target(
                    "Process",
                    "relay-listener",
                    ResourceVerb::Get,
                    Some("owner"),
                ),
            ],
        };
        assert!(authorizer.authorize(&system_core, &request, &state).is_ok());

        let mut wrong_subresource = request.clone();
        wrong_subresource.targets[1].subresource = Some("read".to_owned());
        assert_eq!(
            authorizer
                .authorize(&system_core, &wrong_subresource, &state)
                .unwrap_err(),
            AuthorizationDenial::NoMatchingGrant
        );

        let mut wrong_verb = request;
        wrong_verb.targets[1].verb = ResourceVerb::UseCredential;
        assert_eq!(
            authorizer
                .authorize(&system_core, &wrong_verb, &state)
                .unwrap_err(),
            AuthorizationDenial::NoMatchingGrant
        );
    }

    #[test]
    fn public_peer_uid_resolves_to_one_ready_zone_local_user() {
        let zone = ZoneId::parse("work").unwrap();
        let user = user_resource(
            "alice",
            "123e4567-e89b-42d3-a456-426614174000",
            "alice",
            "Ready",
        );
        let resolved = resolve_zone_user_from_resources(&zone, 1000, &[user], |name| {
            (name == "alice").then_some(1000)
        })
        .unwrap();
        assert_eq!(resolved.subject_ref().to_canonical_string(), "User/alice");
        assert_eq!(
            resolved.subject_uid().as_str(),
            "123e4567-e89b-42d3-a456-426614174000"
        );
        assert_eq!(resolved.generation(), ResourceGeneration::new(1).unwrap());
        assert_eq!(resolved.revision(), ZoneRevision::new(1));
    }

    #[test]
    fn public_peer_uid_rejects_duplicate_or_stale_user_matches() {
        let zone = ZoneId::parse("work").unwrap();
        let first = user_resource(
            "alice",
            "123e4567-e89b-42d3-a456-426614174000",
            "alice",
            "Ready",
        );
        let second = user_resource(
            "alice-copy",
            "223e4567-e89b-42d3-a456-426614174000",
            "alice",
            "Ready",
        );
        assert!(
            resolve_zone_user_from_resources(&zone, 1000, &[first.clone(), second], |name| (name
                == "alice")
                .then_some(1000),)
            .is_err()
        );
        assert!(
            resolve_zone_user_from_resources(
                &zone,
                1000,
                &[user_resource(
                    "alice",
                    "323e4567-e89b-42d3-a456-426614174000",
                    "alice",
                    "Pending",
                )],
                |name| (name == "alice").then_some(1000),
            )
            .is_err()
        );
        assert!(
            resolve_zone_user_from_resources(&zone, 1001, &[first], |name| {
                (name == "alice").then_some(1000)
            })
            .is_err()
        );
        let mut stale = user_resource(
            "alice",
            "423e4567-e89b-42d3-a456-426614174000",
            "alice",
            "Ready",
        );
        let mut stale_value: Value = serde_json::from_slice(&stale.canonical_json).unwrap();
        stale_value["status"]["observedGeneration"] = json!(0);
        stale.canonical_json =
            d2b_contracts_resource::v3::canonical_json_bytes(&stale_value).unwrap();
        assert!(
            resolve_zone_user_from_resources(&zone, 1000, &[stale], |name| {
                (name == "alice").then_some(1000)
            })
            .is_err()
        );
    }

    #[test]
    fn committed_roles_and_bindings_compile_into_distinct_user_grants() {
        let zone = ZoneId::parse("work").unwrap();
        let users = [
            user_resource(
                "alice",
                "123e4567-e89b-42d3-a456-426614174000",
                "alice",
                "Ready",
            ),
            user_resource(
                "bob",
                "223e4567-e89b-42d3-a456-426614174000",
                "bob",
                "Ready",
            ),
        ];
        let alice_role = policy_resource(
            "Role",
            "alice-reader",
            "323e4567-e89b-42d3-a456-426614174000",
            json!({
                "rules": [{
                    "resourceTypes": ["Guest"],
                    "verbs": ["get"],
                    "subresources": [],
                    "resourceNames": ["workstation"],
                    "zones": ["work"],
                    "executionRefs": [],
                    "sessionVerbs": ["connect", "invoke"],
                }],
            }),
        );
        let bob_role = policy_resource(
            "Role",
            "bob-reader",
            "423e4567-e89b-42d3-a456-426614174000",
            json!({
                "rules": [{
                    "resourceTypes": ["Process"],
                    "verbs": ["get"],
                    "subresources": [],
                    "resourceNames": ["agent"],
                    "zones": ["work"],
                    "executionRefs": [],
                    "sessionVerbs": ["connect", "invoke"],
                }],
            }),
        );
        let alice_binding = policy_resource(
            "RoleBinding",
            "alice-binding",
            "523e4567-e89b-42d3-a456-426614174000",
            json!({
                "roleRef": "Role/alice-reader",
                "subjects": ["User/alice"],
                "externalPrincipalSelector": null,
                "scopeNarrowing": null,
            }),
        );
        let bob_binding = policy_resource(
            "RoleBinding",
            "bob-binding",
            "623e4567-e89b-42d3-a456-426614174000",
            json!({
                "roleRef": "Role/bob-reader",
                "subjects": ["User/bob"],
                "externalPrincipalSelector": null,
                "scopeNarrowing": null,
            }),
        );
        let mut resources = users.to_vec();
        resources.extend([alice_role, bob_role, alice_binding, bob_binding]);
        let (policy, state) = compile_committed_policy(
            &zone,
            initial_policy_snapshot().unwrap(),
            ZoneRevision::new(7),
            &[],
            &resources,
        )
        .unwrap();
        let authorizer = NativeAuthorizer::new(ApiCatalog::standard(), Some(policy)).unwrap();
        let alice_user = resolve_zone_user_from_resources(&zone, 1000, &resources, |name| {
            (name == "alice").then_some(1000)
        })
        .unwrap();
        let bob_user = resolve_zone_user_from_resources(&zone, 1001, &resources, |name| {
            (name == "bob").then_some(1001)
        })
        .unwrap();
        let alice_context = local_user_subject_context(&zone, &alice_user, "alice-op").unwrap();
        let bob_context = local_user_subject_context(&zone, &bob_user, "bob-op").unwrap();
        let alice_caps = authorizer
            .positive_capabilities(&alice_context, &zone, &state)
            .unwrap();
        let bob_caps = authorizer
            .positive_capabilities(&bob_context, &zone, &state)
            .unwrap();
        assert!(alice_caps.resources.iter().any(|target| {
            target.resource_type.as_str() == "Guest"
                && target
                    .resource_name
                    .as_ref()
                    .is_some_and(|name| name.as_str() == "workstation")
        }));
        assert!(!alice_caps.resources.iter().any(|target| {
            target.resource_type.as_str() == "Process"
                && target
                    .resource_name
                    .as_ref()
                    .is_some_and(|name| name.as_str() == "agent")
        }));
        assert!(bob_caps.resources.iter().any(|target| {
            target.resource_type.as_str() == "Process"
                && target
                    .resource_name
                    .as_ref()
                    .is_some_and(|name| name.as_str() == "agent")
        }));
        assert!(!bob_caps.resources.iter().any(|target| {
            target.resource_type.as_str() == "Guest"
                && target
                    .resource_name
                    .as_ref()
                    .is_some_and(|name| name.as_str() == "workstation")
        }));
    }

    #[test]
    fn committed_policy_compiles_all_closed_role_binding_subject_types() {
        let zone = ZoneId::parse("work").unwrap();
        let role = policy_resource(
            "Role",
            "all-subjects-reader",
            "733e4567-e89b-42d3-a456-426614174000",
            json!({
                "rules": [{
                    "resourceTypes": ["Guest"],
                    "verbs": ["get"],
                    "subresources": [],
                    "resourceNames": ["workstation"],
                    "zones": ["work"],
                    "executionRefs": [],
                    "sessionVerbs": ["connect", "invoke"],
                }],
            }),
        );
        let subjects = [
            ("Zone/work", "133e4567-e89b-42d3-a456-426614174000"),
            ("User/alice", "233e4567-e89b-42d3-a456-426614174000"),
            (
                "Provider/test-provider",
                "333e4567-e89b-42d3-a456-426614174000",
            ),
            ("Host/test-host", "433e4567-e89b-42d3-a456-426614174000"),
            ("Guest/test-guest", "533e4567-e89b-42d3-a456-426614174000"),
            (
                "Process/test-process",
                "633e4567-e89b-42d3-a456-426614174000",
            ),
        ];
        let binding = policy_resource(
            "RoleBinding",
            "all-subjects-binding",
            "833e4567-e89b-42d3-a456-426614174000",
            json!({
                "roleRef": "Role/all-subjects-reader",
                "subjects": subjects.iter().map(|(subject, _)| *subject).collect::<Vec<_>>(),
                "externalPrincipalSelector": null,
                "scopeNarrowing": null,
            }),
        );
        let mut resources = vec![role, binding];
        resources.extend(subjects.iter().map(|(subject, uid)| {
            let (resource_type, name) = subject.split_once('/').unwrap();
            policy_resource(resource_type, name, uid, json!({}))
        }));

        let (policy, state) = compile_committed_policy(
            &zone,
            initial_policy_snapshot().unwrap(),
            ZoneRevision::new(7),
            &[],
            &resources,
        )
        .unwrap();
        let authorizer = NativeAuthorizer::new(ApiCatalog::standard(), Some(policy)).unwrap();
        for (subject_ref, subject_uid) in subjects {
            let capabilities = authorizer
                .positive_capabilities(&subject_context(subject_ref, subject_uid), &zone, &state)
                .unwrap();
            assert!(
                capabilities.resources.iter().any(|target| {
                    target.resource_type.as_str() == "Guest"
                        && target
                            .resource_name
                            .as_ref()
                            .is_some_and(|name| name.as_str() == "workstation")
                }),
                "{subject_ref} should receive the RoleBinding grant"
            );
        }
    }

    #[test]
    fn missing_subject_does_not_invalidate_other_grants_or_authorize_missing_subject() {
        let zone = ZoneId::parse("work").unwrap();
        let role = policy_resource(
            "Role",
            "mixed-reader",
            "933e4567-e89b-42d3-a456-426614174000",
            json!({
                "rules": [{
                    "resourceTypes": ["Guest"],
                    "verbs": ["get"],
                    "subresources": [],
                    "resourceNames": ["workstation"],
                    "zones": ["work"],
                    "executionRefs": [],
                    "sessionVerbs": ["connect", "invoke"],
                }],
            }),
        );
        let binding = policy_resource(
            "RoleBinding",
            "mixed-binding",
            "a33e4567-e89b-42d3-a456-426614174000",
            json!({
                "roleRef": "Role/mixed-reader",
                "subjects": ["Host/valid-host", "Host/missing-host"],
                "externalPrincipalSelector": null,
                "scopeNarrowing": null,
            }),
        );
        let valid_subject = policy_resource(
            "Host",
            "valid-host",
            "b33e4567-e89b-42d3-a456-426614174000",
            json!({}),
        );
        let (policy, state) = compile_committed_policy(
            &zone,
            initial_policy_snapshot().unwrap(),
            ZoneRevision::new(7),
            &[],
            &[role, binding, valid_subject],
        )
        .unwrap();
        let authorizer = NativeAuthorizer::new(ApiCatalog::standard(), Some(policy)).unwrap();
        let valid_context =
            subject_context("Host/valid-host", "b33e4567-e89b-42d3-a456-426614174000");
        assert!(
            !authorizer
                .positive_capabilities(&valid_context, &zone, &state)
                .unwrap()
                .resources
                .is_empty()
        );
        let missing_context =
            subject_context("Host/missing-host", "c33e4567-e89b-42d3-a456-426614174000");
        assert!(
            authorizer
                .positive_capabilities(&missing_context, &zone, &state)
                .unwrap()
                .resources
                .is_empty()
        );
        assert_eq!(
            authorizer
                .authorize(&missing_context, &policy_request(&zone), &state)
                .unwrap_err(),
            AuthorizationDenial::NoMatchingGrant
        );
    }

    #[test]
    fn deleted_unready_or_stale_subjects_receive_no_grant() {
        for (phase, observed_generation) in [("Deleted", 1), ("Pending", 1), ("Ready", 0)] {
            let zone = ZoneId::parse("work").unwrap();
            let role = policy_resource(
                "Role",
                "subject-state-reader",
                "d33e4567-e89b-42d3-a456-426614174000",
                json!({
                    "rules": [{
                        "resourceTypes": ["Guest"],
                        "verbs": ["get"],
                        "subresources": [],
                        "resourceNames": ["workstation"],
                        "zones": ["work"],
                        "executionRefs": [],
                        "sessionVerbs": ["connect", "invoke"],
                    }],
                }),
            );
            let binding = policy_resource(
                "RoleBinding",
                "subject-state-binding",
                "e33e4567-e89b-42d3-a456-426614174000",
                json!({
                    "roleRef": "Role/subject-state-reader",
                    "subjects": ["Provider/stateful-subject"],
                    "externalPrincipalSelector": null,
                    "scopeNarrowing": null,
                }),
            );
            let mut subject = policy_resource(
                "Provider",
                "stateful-subject",
                "f33e4567-e89b-42d3-a456-426614174000",
                json!({}),
            );
            set_status(&mut subject, phase, observed_generation);
            let (policy, state) = compile_committed_policy(
                &zone,
                initial_policy_snapshot().unwrap(),
                ZoneRevision::new(7),
                &[],
                &[role, binding, subject],
            )
            .unwrap();
            let authorizer = NativeAuthorizer::new(ApiCatalog::standard(), Some(policy)).unwrap();
            let capabilities = authorizer
                .positive_capabilities(
                    &subject_context(
                        "Provider/stateful-subject",
                        "f33e4567-e89b-42d3-a456-426614174000",
                    ),
                    &zone,
                    &state,
                )
                .unwrap();
            assert!(
                capabilities.resources.is_empty(),
                "{phase} subject must not receive a grant"
            );
        }
    }

    #[test]
    fn missing_or_unready_subjects_do_not_create_policy_fingerprints() {
        let role = policy_resource(
            "Role",
            "fingerprint-reader",
            "033e4567-e89b-42d3-a456-426614174000",
            json!({
                "rules": [{
                    "resourceTypes": ["Guest"],
                    "verbs": ["get"],
                    "subresources": [],
                    "resourceNames": ["workstation"],
                    "zones": ["work"],
                    "executionRefs": [],
                    "sessionVerbs": ["connect", "invoke"],
                }],
            }),
        );
        let binding = policy_resource(
            "RoleBinding",
            "fingerprint-binding",
            "143e4567-e89b-42d3-a456-426614174000",
            json!({
                "roleRef": "Role/fingerprint-reader",
                "subjects": ["Provider/missing-subject", "Provider/unready-subject"],
                "externalPrincipalSelector": null,
                "scopeNarrowing": null,
            }),
        );
        let mut unready = policy_resource(
            "Provider",
            "unready-subject",
            "243e4567-e89b-42d3-a456-426614174000",
            json!({}),
        );
        set_status(&mut unready, "Pending", 1);
        assert!(
            committed_policy_subject_fingerprints(&[role, binding, unready])
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn recreated_subject_uid_is_fenced_until_binding_changes() {
        let binding = policy_resource(
            "RoleBinding",
            "provider-binding",
            "353e4567-e89b-42d3-a456-426614174000",
            json!({
                "roleRef": "Role/provider-reader",
                "subjects": ["Provider/system-provider"],
                "externalPrincipalSelector": null,
                "scopeNarrowing": null,
            }),
        );
        let role = policy_resource(
            "Role",
            "provider-reader",
            "463e4567-e89b-42d3-a456-426614174000",
            json!({
                "rules": [{
                    "resourceTypes": ["Guest"],
                    "verbs": ["get"],
                    "subresources": [],
                    "resourceNames": ["workstation"],
                    "zones": ["work"],
                    "executionRefs": [],
                    "sessionVerbs": ["connect", "invoke"],
                }],
            }),
        );
        let first_subject = policy_resource(
            "Provider",
            "system-provider",
            "573e4567-e89b-42d3-a456-426614174000",
            json!({}),
        );
        let recreated_subject = policy_resource(
            "Provider",
            "system-provider",
            "683e4567-e89b-42d3-a456-426614174000",
            json!({}),
        );
        let first =
            committed_policy_subject_fingerprints(&[role.clone(), binding.clone(), first_subject])
                .unwrap();
        let recreated =
            committed_policy_subject_fingerprints(&[role, binding, recreated_subject]).unwrap();
        let key = (
            ResourceRef::parse("RoleBinding/provider-binding").unwrap(),
            ResourceRef::parse("Provider/system-provider").unwrap(),
        );
        assert_ne!(first[&key].subject_uid(), recreated[&key].subject_uid());
        assert!(!policy_subject_fingerprint_allows_refresh(
            Some(&first[&key]),
            &recreated[&key],
        ));
    }

    #[test]
    fn unknown_or_cross_zone_role_binding_subjects_are_refused() {
        let zone = ZoneId::parse("work").unwrap();
        let role = policy_resource(
            "Role",
            "refusal-reader",
            "793e4567-e89b-42d3-a456-426614174000",
            json!({
                "rules": [{
                    "resourceTypes": ["Guest"],
                    "verbs": ["get"],
                    "subresources": [],
                    "resourceNames": ["workstation"],
                    "zones": ["work"],
                    "executionRefs": [],
                    "sessionVerbs": ["connect", "invoke"],
                }],
            }),
        );
        for subject in ["Quota/not-allowed", "Zone/other"] {
            let binding = policy_resource(
                "RoleBinding",
                "refusal-binding",
                "8a3e4567-e89b-42d3-a456-426614174000",
                json!({
                    "roleRef": "Role/refusal-reader",
                    "subjects": [subject],
                    "externalPrincipalSelector": null,
                    "scopeNarrowing": null,
                }),
            );
            assert_eq!(
                compile_committed_policy(
                    &zone,
                    initial_policy_snapshot().unwrap(),
                    ZoneRevision::new(7),
                    &[],
                    &[role.clone(), binding],
                )
                .unwrap_err(),
                ResourceRuntimeError::AuthorizationUnavailable
            );
        }
    }

    #[test]
    fn subject_store_evidence_must_match_uid_generation_and_revision() {
        let zone = ZoneId::parse("work").unwrap();
        let role = policy_resource(
            "Role",
            "evidence-reader",
            "9b3e4567-e89b-42d3-a456-426614174000",
            json!({
                "rules": [{
                    "resourceTypes": ["Guest"],
                    "verbs": ["get"],
                    "subresources": [],
                    "resourceNames": ["workstation"],
                    "zones": ["work"],
                    "executionRefs": [],
                    "sessionVerbs": ["connect", "invoke"],
                }],
            }),
        );
        let binding = policy_resource(
            "RoleBinding",
            "evidence-binding",
            "aa3e4567-e89b-42d3-a456-426614174000",
            json!({
                "roleRef": "Role/evidence-reader",
                "subjects": ["Host/evidence-host"],
                "externalPrincipalSelector": null,
                "scopeNarrowing": null,
            }),
        );
        let mut subject = policy_resource(
            "Host",
            "evidence-host",
            "ab3e4567-e89b-42d3-a456-426614174000",
            json!({}),
        );
        subject.revision = ZoneRevision::new(2);
        assert_eq!(
            compile_committed_policy(
                &zone,
                initial_policy_snapshot().unwrap(),
                ZoneRevision::new(7),
                &[],
                &[role, binding, subject],
            )
            .unwrap_err(),
            ResourceRuntimeError::AuthorizationUnavailable
        );
    }

    #[test]
    fn role_binding_fingerprint_changes_for_same_name_user_recreation() {
        let binding = policy_resource(
            "RoleBinding",
            "alice-binding",
            "523e4567-e89b-42d3-a456-426614174000",
            json!({
                "roleRef": "Role/alice-reader",
                "subjects": ["User/alice"],
                "externalPrincipalSelector": null,
                "scopeNarrowing": null,
            }),
        );
        let role = policy_resource(
            "Role",
            "alice-reader",
            "323e4567-e89b-42d3-a456-426614174000",
            json!({
                "rules": [{
                    "resourceTypes": ["Guest"],
                    "verbs": ["get"],
                    "subresources": [],
                    "resourceNames": ["workstation"],
                    "zones": ["work"],
                    "executionRefs": [],
                    "sessionVerbs": ["connect", "invoke"],
                }],
            }),
        );
        let first_user = user_resource(
            "alice",
            "123e4567-e89b-42d3-a456-426614174000",
            "alice",
            "Ready",
        );
        let second_user = user_resource(
            "alice",
            "223e4567-e89b-42d3-a456-426614174000",
            "alice",
            "Ready",
        );
        let first =
            committed_policy_subject_fingerprints(&[first_user, role.clone(), binding.clone()])
                .unwrap();
        let second = committed_policy_subject_fingerprints(&[second_user, role, binding]).unwrap();
        let key = (
            ResourceRef::parse("RoleBinding/alice-binding").unwrap(),
            ResourceRef::parse("User/alice").unwrap(),
        );
        assert_ne!(first[&key].subject_uid(), second[&key].subject_uid());
        assert!(!policy_subject_fingerprint_allows_refresh(
            Some(&first[&key]),
            &second[&key],
        ));
        assert!(policy_subject_fingerprint_allows_refresh(
            Some(&first[&key]),
            &first[&key],
        ));
    }

    #[test]
    fn multi_revision_subject_refresh_retains_fences_and_requires_rebinding() {
        let zone = ZoneId::parse("work").unwrap();
        let role = policy_resource(
            "Role",
            "fence-reader",
            "313e4567-e89b-42d3-a456-426614174000",
            json!({
                "rules": [{
                    "resourceTypes": ["Guest"],
                    "verbs": ["get"],
                    "subresources": [],
                    "resourceNames": ["workstation"],
                    "zones": ["work"],
                    "executionRefs": [],
                    "sessionVerbs": ["connect", "invoke"],
                }],
            }),
        );
        let binding = policy_resource(
            "RoleBinding",
            "fence-binding",
            "323e4567-e89b-42d3-a456-426614174000",
            json!({
                "roleRef": "Role/fence-reader",
                "subjects": ["Provider/fenced-subject"],
                "externalPrincipalSelector": null,
                "scopeNarrowing": null,
            }),
        );
        let subject_v1 = policy_resource(
            "Provider",
            "fenced-subject",
            "333e4567-e89b-42d3-a456-426614174000",
            json!({}),
        );
        let key = (
            ResourceRef::parse("RoleBinding/fence-binding").unwrap(),
            ResourceRef::parse("Provider/fenced-subject").unwrap(),
        );
        let first_resources = vec![role.clone(), binding.clone(), subject_v1.clone()];
        let first =
            refreshed_policy_subject_fingerprints(&first_resources, &BTreeMap::new()).unwrap();
        assert_eq!(
            first[&key].subject_uid().as_str(),
            "333e4567-e89b-42d3-a456-426614174000"
        );
        let (policy, state) = compile_committed_policy(
            &zone,
            initial_policy_snapshot().unwrap(),
            ZoneRevision::new(1),
            &[],
            &first_resources,
        )
        .unwrap();
        let authorizer = NativeAuthorizer::new(ApiCatalog::standard(), Some(policy)).unwrap();
        assert!(
            !authorizer
                .positive_capabilities(
                    &subject_context(
                        "Provider/fenced-subject",
                        "333e4567-e89b-42d3-a456-426614174000",
                    ),
                    &zone,
                    &state,
                )
                .unwrap()
                .resources
                .is_empty()
        );

        let missing_resources = vec![role.clone(), binding.clone()];
        let retained = refreshed_policy_subject_fingerprints(&missing_resources, &first).unwrap();
        assert_eq!(retained[&key].subject_uid(), first[&key].subject_uid());

        for phase in ["Pending", "Deleted"] {
            let mut absent_subject = subject_v1.clone();
            set_status(&mut absent_subject, phase, 1);
            let resources = vec![role.clone(), binding.clone(), absent_subject];
            let retained = refreshed_policy_subject_fingerprints(&resources, &first).unwrap();
            assert_eq!(retained[&key].subject_uid(), first[&key].subject_uid());
            let (policy, state) = compile_committed_policy(
                &zone,
                initial_policy_snapshot().unwrap(),
                ZoneRevision::new(2),
                &[],
                &resources,
            )
            .unwrap();
            let authorizer = NativeAuthorizer::new(ApiCatalog::standard(), Some(policy)).unwrap();
            assert!(
                authorizer
                    .positive_capabilities(
                        &subject_context(
                            "Provider/fenced-subject",
                            "333e4567-e89b-42d3-a456-426614174000",
                        ),
                        &zone,
                        &state,
                    )
                    .unwrap()
                    .resources
                    .is_empty(),
                "{phase} subject must lose its grant"
            );
        }

        let unrelated_role = policy_resource(
            "Role",
            "unrelated-reader",
            "343e4567-e89b-42d3-a456-426614174000",
            json!({
                "rules": [{
                    "resourceTypes": ["Guest"],
                    "verbs": ["get"],
                    "subresources": [],
                    "resourceNames": ["workstation"],
                    "zones": ["work"],
                    "executionRefs": [],
                    "sessionVerbs": ["connect", "invoke"],
                }],
            }),
        );
        let unrelated_binding = policy_resource(
            "RoleBinding",
            "unrelated-binding",
            "353e4567-e89b-42d3-a456-426614174000",
            json!({
                "roleRef": "Role/unrelated-reader",
                "subjects": ["Provider/unrelated-subject"],
                "externalPrincipalSelector": null,
                "scopeNarrowing": null,
            }),
        );
        let unrelated_subject = policy_resource(
            "Provider",
            "unrelated-subject",
            "363e4567-e89b-42d3-a456-426614174000",
            json!({}),
        );
        let unrelated_key = (
            ResourceRef::parse("RoleBinding/unrelated-binding").unwrap(),
            ResourceRef::parse("Provider/unrelated-subject").unwrap(),
        );
        let mut unrelated_resources = vec![
            role.clone(),
            binding.clone(),
            unrelated_role,
            unrelated_binding,
            unrelated_subject,
        ];
        let mut absent_subject = subject_v1.clone();
        set_status(&mut absent_subject, "Pending", 1);
        unrelated_resources.push(absent_subject);
        let refreshed =
            refreshed_policy_subject_fingerprints(&unrelated_resources, &first).unwrap();
        assert_eq!(refreshed[&key].subject_uid(), first[&key].subject_uid());
        assert_eq!(
            refreshed[&unrelated_key].subject_uid().as_str(),
            "363e4567-e89b-42d3-a456-426614174000"
        );
        let (policy, state) = compile_committed_policy(
            &zone,
            initial_policy_snapshot().unwrap(),
            ZoneRevision::new(3),
            &[],
            &unrelated_resources,
        )
        .unwrap();
        let authorizer = NativeAuthorizer::new(ApiCatalog::standard(), Some(policy)).unwrap();
        assert!(
            !authorizer
                .positive_capabilities(
                    &subject_context(
                        "Provider/unrelated-subject",
                        "363e4567-e89b-42d3-a456-426614174000",
                    ),
                    &zone,
                    &state,
                )
                .unwrap()
                .resources
                .is_empty()
        );
        assert!(
            authorizer
                .positive_capabilities(
                    &subject_context(
                        "Provider/fenced-subject",
                        "333e4567-e89b-42d3-a456-426614174000",
                    ),
                    &zone,
                    &state,
                )
                .unwrap()
                .resources
                .is_empty()
        );

        let subject_v2 = policy_resource(
            "Provider",
            "fenced-subject",
            "373e4567-e89b-42d3-a456-426614174000",
            json!({}),
        );
        assert!(matches!(
            refreshed_policy_subject_fingerprints(
                &[role.clone(), binding.clone(), subject_v2.clone()],
                &refreshed,
            ),
            Err(ResourceRuntimeError::IdentityUnbound)
        ));

        let mut rebound = binding.clone();
        set_identity(&mut rebound, "383e4567-e89b-42d3-a456-426614174000", 2);
        let rebound_resources = vec![role.clone(), rebound.clone(), subject_v2.clone()];
        let rebound_fingerprints =
            refreshed_policy_subject_fingerprints(&rebound_resources, &refreshed).unwrap();
        assert_eq!(
            rebound_fingerprints[&key].subject_uid().as_str(),
            "373e4567-e89b-42d3-a456-426614174000"
        );
        let (policy, state) = compile_committed_policy(
            &zone,
            initial_policy_snapshot().unwrap(),
            ZoneRevision::new(4),
            &[],
            &rebound_resources,
        )
        .unwrap();
        let authorizer = NativeAuthorizer::new(ApiCatalog::standard(), Some(policy)).unwrap();
        assert!(
            !authorizer
                .positive_capabilities(
                    &subject_context(
                        "Provider/fenced-subject",
                        "373e4567-e89b-42d3-a456-426614174000",
                    ),
                    &zone,
                    &state,
                )
                .unwrap()
                .resources
                .is_empty()
        );

        let mut removed = rebound;
        set_binding_subjects(&mut removed, &["Provider/other-subject"]);
        let removed_fingerprints = refreshed_policy_subject_fingerprints(
            &[role.clone(), removed, subject_v2],
            &rebound_fingerprints,
        )
        .unwrap();
        assert!(!removed_fingerprints.contains_key(&key));
        assert!(removed_fingerprints.is_empty());
        let deleted_fingerprints =
            refreshed_policy_subject_fingerprints(&[role], &rebound_fingerprints).unwrap();
        assert!(deleted_fingerprints.is_empty());
    }

    #[test]
    fn phase_only_status_preserves_existing_resource_projection() {
        let desired = CanonicalJsonValue::parse(br#"{"phase":"Ready"}"#).unwrap();
        let CanonicalJsonValue::Object(desired) = desired else {
            panic!("phase status must be an object");
        };
        let current = json!({
            "netVmRef": "Guest/net-work-net",
            "lanBridge": {"phase": "Ready"},
            "uplinkBridge": {"phase": "Ready"},
            "externalAttachment": null,
            "attachments": [],
        });
        let projection = select_resource_projection(desired, Some(&current)).unwrap();
        assert_eq!(
            projection.to_canonical_bytes(),
            CanonicalJsonValue::parse(
                br#"{"attachments":[],"externalAttachment":null,"lanBridge":{"phase":"Ready"},"netVmRef":"Guest/net-work-net","uplinkBridge":{"phase":"Ready"}}"#,
            )
            .unwrap()
            .to_canonical_bytes()
        );
        assert_eq!(
            select_resource_projection(
                CanonicalJsonValue::parse(br#"{"phase":"Pending"}"#)
                    .unwrap()
                    .as_object()
                    .unwrap()
                    .clone(),
                None,
            )
            .unwrap()
            .to_canonical_bytes(),
            br#"{"phase":"Pending"}"#
        );
    }

    #[test]
    fn controller_session_projection_preserves_stale_process_status() {
        let mut process = policy_resource(
            "Process",
            "controller",
            "123e4567-e89b-42d3-a456-426614174000",
            json!({
                "processClass": "controller",
                "providerRef": "Provider/system-minijail",
            }),
        );
        set_status(&mut process, "Ready", 0);
        let evidence = json!({
            "ready": true,
            "providerGeneration": 2,
            "processGeneration": 1,
        });
        let candidate = resource_controller_session_candidate(&process, Some(&evidence))
            .unwrap()
            .expect("new controller-session evidence changes the projection");
        let value: Value = serde_json::from_slice(&candidate.to_canonical_bytes()).unwrap();
        assert_eq!(value["status"]["phase"], "Ready");
        assert_eq!(value["status"]["observedGeneration"], 0);
        assert_eq!(value["status"]["update"]["observedGeneration"], 0);
        assert_eq!(value["status"]["resource"]["controllerSession"], evidence);
    }

    #[test]
    fn controller_session_clear_removes_evidence_without_rewriting_process_status() {
        let mut process = policy_resource(
            "Process",
            "controller",
            "123e4567-e89b-42d3-a456-426614174000",
            json!({
                "processClass": "controller",
                "providerRef": "Provider/system-minijail",
            }),
        );
        set_status(&mut process, "Ready", 0);
        let evidence = json!({
            "ready": true,
            "providerGeneration": 2,
            "processGeneration": 1,
        });
        let with_evidence = resource_controller_session_candidate(&process, Some(&evidence))
            .unwrap()
            .expect("session evidence should be written");
        let mut persisted = process.clone();
        persisted.canonical_json = with_evidence.to_canonical_bytes();

        let cleared = resource_controller_session_candidate(&persisted, None)
            .unwrap()
            .expect("stale session evidence should be removed");
        let value: Value = serde_json::from_slice(&cleared.to_canonical_bytes()).unwrap();
        assert!(value["status"]["resource"]["controllerSession"].is_null());
        assert_eq!(value["status"]["phase"], "Ready");
        assert_eq!(value["status"]["observedGeneration"], 0);
        assert_eq!(value["status"]["update"]["observedGeneration"], 0);
    }

    #[test]
    fn controller_session_evidence_uses_a_distinct_status_operation_identity() {
        let process = policy_resource(
            "Process",
            "controller",
            "123e4567-e89b-42d3-a456-426614174000",
            json!({
                "processClass": "controller",
                "providerRef": "Provider/system-minijail",
            }),
        );
        let status_operation = resource_status_operation_id(&process, "system-core-status");
        let evidence_operation =
            resource_status_operation_id(&process, "controller-session-evidence");
        assert_ne!(status_operation, evidence_operation);
        assert!(status_operation.starts_with("d2b-op-sha256:"));
        assert!(evidence_operation.starts_with("d2b-op-sha256:"));
    }

    #[test]
    fn controller_session_evidence_operation_identity_fences_recreates() {
        let process = policy_resource(
            "Process",
            "controller",
            "123e4567-e89b-42d3-a456-426614174000",
            json!({
                "processClass": "controller",
                "providerRef": "Provider/system-minijail",
            }),
        );
        let original = resource_status_operation_id(&process, "controller-session-evidence");

        let mut recreated = process.clone();
        set_identity(
            &mut recreated,
            "223e4567-e89b-42d3-a456-426614174001",
            1,
        );
        assert_ne!(
            original,
            resource_status_operation_id(&recreated, "controller-session-evidence")
        );

        let mut regenerated = process;
        set_identity(
            &mut regenerated,
            "123e4567-e89b-42d3-a456-426614174000",
            2,
        );
        assert_ne!(
            original,
            resource_status_operation_id(&regenerated, "controller-session-evidence")
        );
    }

    #[test]
    fn status_timestamp_only_changes_are_semantically_equal() {
        let current = CanonicalJsonValue::parse(
            br#"{"lastReconciledAt":"2026-08-19T00:00:00.000Z","phase":"Ready","update":{"lastAssessedAt":"2026-08-19T00:00:00.000Z","state":"Current"}}"#,
        )
        .unwrap();
        let candidate = CanonicalJsonValue::parse(
            br#"{"lastReconciledAt":"2026-08-19T00:01:00.000Z","phase":"Ready","update":{"lastAssessedAt":"2026-08-19T00:01:00.000Z","state":"Current"}}"#,
        )
        .unwrap();
        assert!(status_semantically_equal(&current, &candidate));
    }

    #[test]
    fn stable_identity_is_repeatable_and_uuid_v4_shaped() {
        let first = stable_uid("store", "sha256:aaa");
        assert_eq!(first, stable_uid("store", "sha256:aaa"));
        assert_ne!(first, stable_uid("store", "sha256:bbb"));
    }

    #[test]
    fn bundle_mutation_identity_requires_zone_uid() {
        let bundle = ResourceBundle::new(
            ZoneId::parse("work").unwrap(),
            Vec::new(),
            "sha256:".to_owned() + &"a".repeat(64),
            BTreeMap::new(),
            BTreeMap::new(),
            Timestamp::parse("2026-08-26T00:00:00.000Z").unwrap(),
        )
        .unwrap()
        .with_zone_uid(ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap());
        let operation =
            resource_bundle_materialization_operation_id(&ZoneId::parse("work").unwrap(), &bundle)
                .unwrap();
        assert!(operation.contains("resource-bundle-materialization:"));
        assert!(!operation.contains("123e4567-e89b-42d3-a456-426614174000"));
        assert_eq!(
            resource_bundle_materialization_operation_id(
                &ZoneId::parse("work").unwrap(),
                &ResourceBundle::new(
                    ZoneId::parse("work").unwrap(),
                    Vec::new(),
                    "sha256:".to_owned() + &"a".repeat(64),
                    BTreeMap::new(),
                    BTreeMap::new(),
                    Timestamp::parse("2026-08-26T00:00:00.000Z").unwrap(),
                )
                .unwrap(),
            ),
            Err(ResourceRuntimeError::IdentityUnbound)
        );
    }

    #[test]
    fn extra_guest_or_network_rows_are_rejected_before_materialization_planning() {
        let zone = ZoneId::parse("work").unwrap();
        let bundle = ResourceBundle::new(
            zone.clone(),
            Vec::new(),
            "sha256:".to_owned() + &"a".repeat(64),
            BTreeMap::new(),
            BTreeMap::new(),
            Timestamp::parse("2026-08-26T00:00:00.000Z").unwrap(),
        )
        .unwrap()
        .with_zone_uid(ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap());
        for (resource_type, digest) in [("Guest", 'b'), ("Network", 'c')] {
            let stale_ref_text = format!("{resource_type}/stale");
            let stale_ref = ResourceRef::parse(&stale_ref_text).unwrap();
            let stale = StoredResource {
                resource_ref: stale_ref.clone(),
                zone: zone.clone(),
                uid: ResourceUid::parse("223e4567-e89b-42d3-a456-426614174000").unwrap(),
                owner_uid: None,
                owner_generation: None,
                generation: ResourceGeneration::new(1).unwrap(),
                revision: ZoneRevision::new(1),
                canonical_json: Vec::new(),
                payload_digest: format!("sha256:{}", digest.to_string().repeat(64)),
            };
            let existing = BTreeMap::from([(stale_ref, stale)]);
            let before = existing.clone();
            assert_eq!(
                reject_stale_guest_network_rows(&existing, &bundle),
                Err(ResourceRuntimeError::HandlerNotReady)
            );
            assert_eq!(existing, before);
        }
    }

    #[test]
    fn core_progression_reaches_handler_gate_before_readiness_check() {
        let mut core = CoreProcess::new();
        let authority = HostGlobalAuthorityIndex::new_for_tests_ready();
        let result = drive_core_startup(
            &mut core,
            CoreRuntimeReadiness {
                store_ready: true,
                resource_api_ready: true,
                local_bus_ready: true,
                controller_endpoint_registered: true,
                authenticated_system_core_session: true,
            },
            RecoverySnapshot {
                startup_epoch: 0,
                checkpoint_revision: 0,
                active_configuration_revision: 1,
                provider_lease_count: 0,
                controller_lease_count: 0,
                ambiguous_operation_count: 0,
                watch_admitted: true,
            },
            &authority,
        );
        assert_eq!(result, Err(ResourceRuntimeError::HandlerNotReady));
        assert_eq!(core.stage(), StartupStage::ReconcilingSystemCore);
    }

    #[test]
    fn system_core_requires_a_host_but_accepts_multiple_host_resources() {
        assert_eq!(
            host_phase_for_resource_count(0),
            HandlerPhase::Degraded,
            "zero Host resources must not publish a ready handler"
        );
        assert_eq!(host_phase_for_resource_count(1), HandlerPhase::Ready);
        assert_eq!(host_phase_for_resource_count(2), HandlerPhase::Ready);
    }

    #[test]
    fn cleanup_pending_counts_only_deleted_prior_configuration_generations() {
        let mut resource = StoredResource {
            resource_ref: ResourceRef::parse("Host/host-system").unwrap(),
            zone: ZoneId::parse("dev").unwrap(),
            uid: ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap(),
            owner_uid: None,
            owner_generation: None,
            generation: ResourceGeneration::new(1).unwrap(),
            revision: ZoneRevision::new(1),
            canonical_json: br#"{"metadata":{"managedBy":"configuration","configurationGeneration":3,"deletionRequestedAt":"2026-08-15T00:00:00Z"}}"#.to_vec(),
            payload_digest: String::new(),
        };
        assert!(configuration_cleanup_pending(&resource, 4));
        resource.canonical_json =
            br#"{"metadata":{"managedBy":"configuration","configurationGeneration":4,"deletionRequestedAt":"2026-08-15T00:00:00Z"}}"#.to_vec();
        assert!(!configuration_cleanup_pending(&resource, 4));
        resource.canonical_json =
            br#"{"metadata":{"managedBy":"operator","configurationGeneration":3,"deletionRequestedAt":"2026-08-15T00:00:00Z"}}"#.to_vec();
        assert!(!configuration_cleanup_pending(&resource, 4));
    }

    #[tokio::test]
    async fn completed_watch_handles_are_cleared_for_bounded_restart() {
        let completed = tokio::spawn(async {});
        while !completed.is_finished() {
            tokio::task::yield_now().await;
        }
        let mut slot = Some(completed);
        assert!(watch_needs_restart(&mut slot));
        assert!(slot.is_none());

        let running = tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        });
        let mut slot = Some(running);
        assert!(!watch_needs_restart(&mut slot));
        slot.take().expect("running watch").abort();
    }

    #[tokio::test]
    async fn explicit_system_core_subject_preserves_component_registration() {
        let catalog = ApiCatalog::standard();
        let native = NativeAuthorizer::new(catalog, None).unwrap();
        let state = AuthorizationState {
            snapshot: PolicySnapshot {
                policy_revision: 1,
                api_catalog_revision: 1,
                active_configuration_revision: ConfigurationGeneration::new(1).unwrap(),
                controller_generation: None,
            },
            zone_policy_revision: ZoneRevision::new(1),
            bootstrap_phase: BootstrapPhase::Disabled,
            now_tick: 1,
        };
        let authorizer = d2b_bus::BusAuthorizer::new(native, state).unwrap();
        let (_bus, registrar) = d2b_bus::ZoneBus::new(
            ZoneId::parse("dev").unwrap(),
            authorizer,
            d2b_bus::BusConfig::default(),
        )
        .unwrap();
        let (initiator_fd, _responder_fd) = prearmed_seqpacket_pair().unwrap();
        let initiator_socket = SeqpacketSocket::from_parent_prearmed(initiator_fd).unwrap();
        let verified_peer =
            VerifiedUnixPeer::verify_inherited_seqpacket(&initiator_socket).unwrap();
        registrar
            .install_system_core_subject(&verified_peer)
            .unwrap();
        registrar
            .component_session_acceptor(system_core_endpoint_policy(), verified_peer)
            .unwrap();
    }

    #[test]
    fn list_preserves_typed_pagination_and_filters() {
        let request = json!({
            "resourceType": "Guest",
            "limit": 10,
            "pageToken": "opaque-cursor",
            "filters": [{
                "field": "metadata.name",
                "values": ["corp-vm"],
            }],
        });
        let parsed = parse_list_request(&request).unwrap();
        assert_eq!(parsed.page_size, 10);
        assert_eq!(parsed.cursor.as_deref(), Some("opaque-cursor"));
        assert_eq!(parsed.resource_types[0].as_str(), "Guest");
        assert_eq!(parsed.resource_names[0].as_str(), "corp-vm");
        assert_eq!(parsed.filters[0].field, "metadata.name");
    }

    #[test]
    fn list_refuses_query_fields_without_a_store_semantic() {
        let request = json!({
            "resourceType": "Guest",
            "executionRef": "Host/host-system",
        });
        assert_eq!(
            parse_list_request(&request),
            Err(ResourceRuntimeError::CapabilityUnavailable)
        );
    }

    #[test]
    fn list_rejects_conflicting_legacy_and_typed_pagination_aliases() {
        let request = json!({
            "resourceType": "Guest",
            "limit": 10,
            "pageSize": 20,
            "pageToken": "opaque-cursor",
            "cursor": "different-cursor",
        });
        assert_eq!(
            parse_list_request(&request),
            Err(ResourceRuntimeError::RequestInvalid)
        );
    }

    #[test]
    fn malformed_resource_results_fail_closed() {
        assert_eq!(
            decode_resource_result(br#"{"unterminated":"value""#)
                .unwrap_err()
                .kind(),
            ResourceErrorKind::InternalIntegrityFailure
        );
        assert_eq!(
            decode_resource_result(&vec![b' '; MAX_RESPONSE_CANONICAL_BYTES + 1])
                .unwrap_err()
                .kind(),
            ResourceErrorKind::InternalIntegrityFailure
        );
    }

    #[test]
    fn list_result_retains_the_store_cursor() {
        let result = encode_list_result(StoreListResult {
            resources: Vec::new(),
            snapshot_revision: ZoneRevision::new(7),
            next_cursor: Some("opaque-cursor".to_owned()),
            truncated: true,
        })
        .unwrap();
        assert_eq!(result["snapshotRevision"], 7);
        assert_eq!(result["nextCursor"], "opaque-cursor");
        assert!(result.get("nextPageToken").is_none());
        assert_eq!(result["truncated"], true);
    }

    #[test]
    fn resource_error_envelope_retains_kind_and_retry_metadata() {
        let error = ResourceError::new(
            ResourceErrorKind::ResourceConflict,
            Some(ZoneRevision::new(11)),
            Some(250),
            RetryClass::AfterDelay,
            d2b_contracts_resource::v3::ResourceErrorReason::parse("revision-changed").unwrap(),
        )
        .unwrap();
        let envelope = resource_error_envelope(&error);
        assert_eq!(envelope["error"]["kind"], "resource-conflict");
        assert_eq!(envelope["error"]["currentRevision"], 11);
        assert_eq!(envelope["error"]["retryAfterMs"], 250);
        assert_eq!(envelope["error"]["retryClass"], "after-delay");
    }

    #[test]
    fn public_api_error_preserves_not_found_and_plane_kinds() {
        let mut not_found = wire::ResourceError::new();
        not_found.kind = protobuf::EnumOrUnknown::new(
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_NOT_FOUND,
        );
        not_found.retry_class = protobuf::EnumOrUnknown::new(wire::RetryClass::RETRY_CLASS_NEVER);
        assert_eq!(
            public_api_error(&not_found)["error"]["kind"],
            "resource-not-found"
        );

        let mut unavailable = wire::ResourceError::new();
        unavailable.kind = protobuf::EnumOrUnknown::new(
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_PLANE_UNAVAILABLE,
        );
        unavailable.retry_class =
            protobuf::EnumOrUnknown::new(wire::RetryClass::RETRY_CLASS_AFTER_DELAY);
        assert_eq!(
            public_api_error(&unavailable)["error"]["kind"],
            "resource-plane-unavailable"
        );
    }

    #[test]
    fn public_operation_identity_includes_the_exact_target() {
        let first = public_operation_id(
            &json!({
                "resourceType": "Guest",
                "resourceRef": "Guest/workstation",
            }),
            1000,
            "Start",
        );
        let second = public_operation_id(
            &json!({
                "resourceType": "Guest",
                "resourceRef": "Guest/personal",
            }),
            1000,
            "Start",
        );
        assert_ne!(first, second);
        assert!(first.starts_with("public-1000-Start-Guest-"));
    }
}
