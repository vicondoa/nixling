//! Native Role and RoleBinding authorization evaluator.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard},
};

use d2b_contracts_resource::v3::identity::STANDARD_RESOURCE_TYPES;
use d2b_contracts_resource::v3::identity::{AuthenticatedSubjectContext, EvidenceClass, Locality};
use d2b_contracts_resource::v3::{
    ControllerGeneration, MAX_ROLE_BINDING_SUBJECTS, MAX_ROLE_RULE_EXECUTION_REFS,
    MAX_ROLE_RULE_RESOURCE_NAMES, MAX_ROLE_RULE_RESOURCE_TYPES, MAX_ROLE_RULE_VERBS,
    MAX_ROLE_RULES, ResourceErrorKind, ResourceGeneration, ResourceName, ResourceRef,
    ResourceTypeName, ResourceUid, ZoneId, ZoneRevision,
};
use d2b_contracts_zone_session::v3::{
    RoleBindingSpec, RoleResourceVerb, RoleRule, RoleSessionVerb, RoleSpec,
};
use d2b_core_controller::controller_assignment::{
    AssignmentError, AssignmentIdentity, AssignmentTarget, ScopedResourceMutation,
};
use d2b_core_controller::rbac::{AuthorizationCacheKey, PolicyRevisionSet, PositiveDecisionCache};
use d2b_resource_store::{
    AdmittedAuthorization, AdmittedAuthorizationTarget, AdmittedVerb, PolicySnapshot,
    ResourceAssignmentFence, ResourceAssignmentScope, StoreMutation, StoreOperationContext,
    StoreSealIdentity, StoreSlot,
};
use sha2::{Digest, Sha256};

use crate::admission::{
    AdmissionError, AdmissionIssuer, AdmissionPermit, AdmittedMutation, StoreAdmissionBinding,
    admission_pair,
};
use crate::store::StoreBindingError;

/// Why a native authorizer could not hand off its one store seal.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StoreSealHandoffError {
    AlreadyTaken {
        slot: StoreSlot,
        zone: d2b_contracts_resource::v3::ZoneId,
    },
    AuthorizerUnavailable {
        slot: StoreSlot,
        zone: d2b_contracts_resource::v3::ZoneId,
    },
}

impl core::fmt::Display for StoreSealHandoffError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AlreadyTaken { slot, .. } => write!(
                f,
                "native authorizer already yielded its store-seal acceptor, refused for store slot {slot}; construct one NativeAuthorizer per resource store"
            ),
            Self::AuthorizerUnavailable { slot, .. } => write!(
                f,
                "native authorizer store-seal state is poisoned at store slot {slot}; this process must not continue serving the zone"
            ),
        }
    }
}

impl std::error::Error for StoreSealHandoffError {}

const POSITIVE_CACHE_ENTRIES: usize = 4096;
const POSITIVE_CACHE_TICKS: u64 = 30;
const RESOURCE_SERVICE: &str = "d2b.resource.v3";
const BOOTSTRAP_PURPOSE: &str = "resource-bootstrap";

/// Immutable set of ResourceTypes installed for one API binding.
#[derive(Clone, PartialEq, Eq)]
pub struct ApiCatalog {
    resource_types: BTreeSet<ResourceTypeName>,
}

impl ApiCatalog {
    /// Construct the standard API catalog.
    pub fn standard() -> Self {
        Self {
            resource_types: STANDARD_RESOURCE_TYPES
                .into_iter()
                .map(|value| {
                    ResourceTypeName::parse(value)
                        .expect("the standard ResourceType catalog is validated")
                })
                .collect(),
        }
    }

    /// Extend the standard catalog with installed qualified ResourceTypes.
    pub fn with_extensions(
        extensions: impl IntoIterator<Item = ResourceTypeName>,
    ) -> Result<Self, AuthorizationPolicyError> {
        let mut catalog = Self::standard();
        for resource_type in extensions {
            if !resource_type.as_str().contains(".d2bus.org.")
                || !catalog.resource_types.insert(resource_type)
            {
                return Err(AuthorizationPolicyError::CatalogShape);
            }
        }
        Ok(catalog)
    }

    fn contains(&self, resource_type: &ResourceTypeName) -> bool {
        self.resource_types.contains(resource_type)
    }
}

impl Default for ApiCatalog {
    fn default() -> Self {
        Self::standard()
    }
}

impl core::fmt::Debug for ApiCatalog {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ApiCatalog")
            .field("resource_type_count", &self.resource_types.len())
            .finish()
    }
}

/// Resource methods distinguished from their authorization verb.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ApiMethod {
    Get,
    List,
    Watch,
    Create,
    UpdateSpec,
    UpdateStatus,
    UpdateMetadata,
    UpdateFinalizers,
    Delete,
    CommitBatch,
    ResolveRef,
    InspectSchema,
    Upgrade,
}

/// Closed resource authorization verbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResourceVerb {
    Get,
    List,
    Watch,
    Create,
    UpdateSpec,
    UpdateStatus,
    UpdateMetadata,
    UpdateFinalizers,
    Delete,
    UseCredential,
    AdminCredential,
}

impl ResourceVerb {
    fn admitted(self) -> AdmittedVerb {
        match self {
            Self::Get => AdmittedVerb::Get,
            Self::List => AdmittedVerb::List,
            Self::Watch => AdmittedVerb::Watch,
            Self::Create => AdmittedVerb::Create,
            Self::UpdateSpec => AdmittedVerb::UpdateSpec,
            Self::UpdateStatus => AdmittedVerb::UpdateStatus,
            Self::UpdateMetadata => AdmittedVerb::UpdateMetadata,
            Self::UpdateFinalizers => AdmittedVerb::UpdateFinalizers,
            Self::Delete => AdmittedVerb::Delete,
            Self::UseCredential => AdmittedVerb::UseCredential,
            Self::AdminCredential => AdmittedVerb::AdminCredential,
        }
    }

    fn tag(self) -> u8 {
        self as u8
    }
}

/// Closed ComponentSession authorization verbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SessionVerb {
    Connect,
    Invoke,
    OpenStream,
    Relay,
    Attach,
    Cancel,
    Observe,
    AuditExport,
    SupportBundle,
}

/// One exact target evaluated for a method or atomic batch.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizationTarget {
    pub resource_type: ResourceTypeName,
    pub resource_name: Option<ResourceName>,
    pub verb: ResourceVerb,
    pub subresource: Option<String>,
    pub execution_ref: Option<ResourceRef>,
}

/// Immutable method authorization input.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizationRequest {
    pub method: ApiMethod,
    pub zone: ZoneId,
    pub targets: Vec<AuthorizationTarget>,
}

/// Revision and bootstrap state captured from trusted runtime state.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizationState {
    pub snapshot: PolicySnapshot,
    pub zone_policy_revision: ZoneRevision,
    pub bootstrap_phase: BootstrapPhase,
    pub now_tick: u64,
}

/// Durable bootstrap-policy phase.
#[derive(Clone, PartialEq, Eq)]
pub enum BootstrapPhase {
    Unprovisioned {
        zone: ZoneId,
        controller_generation: ControllerGeneration,
        provider_generation: d2b_contracts_resource::v3::ResourceGeneration,
    },
    Provisioned {
        zone: ZoneId,
        system_core_uid: ResourceUid,
        system_minijail_uid: ResourceUid,
        controller_generation: ControllerGeneration,
        provider_generation: d2b_contracts_resource::v3::ResourceGeneration,
    },
    Disabled,
}

/// Trusted store facts from which the one-way bootstrap phase is derived.
///
/// The Zone runtime obtains these values from the same redb read snapshot used
/// for admission.  There is no constructor accepting Nix, environment,
/// caller, or API policy input.
#[derive(Clone, PartialEq, Eq)]
pub struct BootstrapStoreFacts {
    /// The store's self Zone name.
    zone: ZoneId,
    /// Durable `store_meta.policy_revision`.
    policy_revision: u64,
    /// Bootstrap Provider rows present in the `type_index`, by fixed name.
    bootstrap_provider_uids: BTreeMap<ResourceName, ResourceUid>,
    /// Current fixed core-controller generation.
    controller_generation: ControllerGeneration,
    /// Current bootstrap Provider generation.
    provider_generation: d2b_contracts_resource::v3::ResourceGeneration,
}

impl BootstrapStoreFacts {
    /// Construct facts only at the trusted Zone-store adapter boundary.
    #[allow(dead_code)]
    pub(crate) fn from_trusted_store(
        zone: ZoneId,
        policy_revision: u64,
        bootstrap_provider_uids: BTreeMap<ResourceName, ResourceUid>,
        controller_generation: ControllerGeneration,
        provider_generation: d2b_contracts_resource::v3::ResourceGeneration,
    ) -> Self {
        Self {
            zone,
            policy_revision,
            bootstrap_provider_uids,
            controller_generation,
            provider_generation,
        }
    }
}

impl core::fmt::Debug for BootstrapStoreFacts {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BootstrapStoreFacts")
            .field("policy_revision", &"<redacted>")
            .field(
                "bootstrap_provider_count",
                &self.bootstrap_provider_uids.len(),
            )
            .finish_non_exhaustive()
    }
}

/// Derive the bootstrap phase from trusted store state only.
///
/// A policy revision other than zero permanently disables bootstrap.  At
/// revision zero, the presence of both fixed Provider rows selects the
/// provisioned phase; a partial or empty index remains unprovisioned.
pub fn derive_bootstrap_phase(facts: &BootstrapStoreFacts) -> BootstrapPhase {
    if facts.policy_revision != 0 {
        return BootstrapPhase::Disabled;
    }
    let core = ResourceName::parse("system-core").ok();
    let minijail = ResourceName::parse("system-minijail").ok();
    match (
        core.and_then(|name| facts.bootstrap_provider_uids.get(&name)),
        minijail.and_then(|name| facts.bootstrap_provider_uids.get(&name)),
    ) {
        (Some(system_core_uid), Some(system_minijail_uid)) => BootstrapPhase::Provisioned {
            zone: facts.zone.clone(),
            system_core_uid: system_core_uid.clone(),
            system_minijail_uid: system_minijail_uid.clone(),
            controller_generation: facts.controller_generation,
            provider_generation: facts.provider_generation,
        },
        _ => BootstrapPhase::Unprovisioned {
            zone: facts.zone.clone(),
            controller_generation: facts.controller_generation,
            provider_generation: facts.provider_generation,
        },
    }
}

/// The only allowed durable bootstrap publication transition.
pub const fn bootstrap_policy_transition(old_revision: u64, new_revision: u64) -> bool {
    old_revision == 0 && new_revision == 1
}

/// Exact subject binding compiled from one RoleBinding.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BoundSubject {
    pub subject_ref: ResourceRef,
    pub subject_uid: ResourceUid,
}

/// Optional narrowing applied by a RoleBinding.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct BindingScope {
    pub zones: BTreeSet<ZoneId>,
    pub resource_names: BTreeSet<ResourceName>,
    pub execution_refs: BTreeSet<ResourceRef>,
}

/// Authority that created a relay-bearing binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayGrantAuthority {
    None,
    CoreGenerated,
    DurableLocalAdmin,
}

/// Validated evaluator projection of one Role rule.
#[derive(Clone, PartialEq, Eq)]
pub struct PolicyRule {
    resource_types: BTreeSet<ResourceTypeName>,
    resource_verbs: BTreeSet<ResourceVerb>,
    session_verbs: BTreeSet<SessionVerb>,
    subresources: BTreeSet<String>,
    resource_names: BTreeSet<ResourceName>,
    zones: BTreeSet<ZoneId>,
    execution_refs: BTreeSet<ResourceRef>,
}

impl core::fmt::Debug for AuthorizationTarget {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthorizationTarget")
            .field("verb", &self.verb)
            .field("resource_type", &"<redacted>")
            .field("has_resource_name", &self.resource_name.is_some())
            .field("has_subresource", &self.subresource.is_some())
            .field("has_execution_ref", &self.execution_ref.is_some())
            .finish()
    }
}

impl core::fmt::Debug for AuthorizationRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthorizationRequest")
            .field("method", &self.method)
            .field("zone", &"<redacted>")
            .field("target_count", &self.targets.len())
            .finish()
    }
}

impl core::fmt::Debug for AuthorizationState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthorizationState")
            .field("snapshot", &"<redacted>")
            .field("zone_policy_revision", &"<redacted>")
            .field("bootstrap_phase", &self.bootstrap_phase)
            .field("now_tick", &"<redacted>")
            .finish()
    }
}

impl core::fmt::Debug for BootstrapPhase {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Unprovisioned { .. } => "BootstrapPhase::Unprovisioned(<redacted>)",
            Self::Provisioned { .. } => "BootstrapPhase::Provisioned(<redacted>)",
            Self::Disabled => "BootstrapPhase::Disabled",
        })
    }
}

impl core::fmt::Debug for BoundSubject {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("BoundSubject(<redacted>)")
    }
}

impl core::fmt::Debug for BindingScope {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BindingScope")
            .field("zone_count", &self.zones.len())
            .field("resource_name_count", &self.resource_names.len())
            .field("execution_ref_count", &self.execution_refs.len())
            .finish()
    }
}

impl core::fmt::Debug for PolicyRule {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PolicyRule")
            .field("resource_type_count", &self.resource_types.len())
            .field("resource_verb_count", &self.resource_verbs.len())
            .field("session_verb_count", &self.session_verbs.len())
            .field("subresource_count", &self.subresources.len())
            .field("resource_name_count", &self.resource_names.len())
            .field("zone_count", &self.zones.len())
            .field("execution_ref_count", &self.execution_refs.len())
            .finish()
    }
}

impl PolicyRule {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        catalog: &ApiCatalog,
        resource_types: impl IntoIterator<Item = ResourceTypeName>,
        resource_verbs: impl IntoIterator<Item = ResourceVerb>,
        session_verbs: impl IntoIterator<Item = SessionVerb>,
        subresources: impl IntoIterator<Item = String>,
        resource_names: impl IntoIterator<Item = ResourceName>,
        zones: impl IntoIterator<Item = ZoneId>,
        execution_refs: impl IntoIterator<Item = ResourceRef>,
    ) -> Result<Self, AuthorizationPolicyError> {
        let rule = Self {
            resource_types: resource_types.into_iter().collect(),
            resource_verbs: resource_verbs.into_iter().collect(),
            session_verbs: session_verbs.into_iter().collect(),
            subresources: subresources.into_iter().collect(),
            resource_names: resource_names.into_iter().collect(),
            zones: zones.into_iter().collect(),
            execution_refs: execution_refs.into_iter().collect(),
        };
        if rule.resource_types.len() > MAX_ROLE_RULE_RESOURCE_TYPES
            || rule.resource_verbs.len() + rule.session_verbs.len() > MAX_ROLE_RULE_VERBS
            || rule.resource_names.len() > MAX_ROLE_RULE_RESOURCE_NAMES
            || rule.execution_refs.len() > MAX_ROLE_RULE_EXECUTION_REFS
            || rule
                .subresources
                .iter()
                .any(|value| value.is_empty() || value.len() > 128 || !value.is_ascii())
        {
            return Err(AuthorizationPolicyError::RuleBounds);
        }
        if rule
            .resource_types
            .iter()
            .any(|resource_type| !catalog.contains(resource_type))
        {
            return Err(AuthorizationPolicyError::UnknownResourceType);
        }
        if rule.resource_verbs.contains(&ResourceVerb::UseCredential)
            && (rule.resource_types.len() != 1
                || !rule
                    .resource_types
                    .iter()
                    .any(|resource_type| resource_type.as_str() == "Credential")
                || rule.subresources.is_empty())
        {
            return Err(AuthorizationPolicyError::CredentialScope);
        }
        if rule.resource_verbs.contains(&ResourceVerb::AdminCredential)
            && (rule.resource_types.len() != 1
                || !rule
                    .resource_types
                    .iter()
                    .any(|resource_type| resource_type.as_str() == "Credential")
                || rule.subresources.is_empty()
                || rule.subresources.iter().any(|subresource| {
                    !matches!(subresource.as_str(), "create" | "update-spec" | "delete")
                })
                || rule.subresources.iter().any(|subresource| {
                    let required = match subresource.as_str() {
                        "create" => ResourceVerb::Create,
                        "update-spec" => ResourceVerb::UpdateSpec,
                        "delete" => ResourceVerb::Delete,
                        _ => return true,
                    };
                    !rule.resource_verbs.contains(&required)
                }))
        {
            return Err(AuthorizationPolicyError::CredentialScope);
        }
        Ok(rule)
    }

    fn permits_target(&self, target: &AuthorizationTarget, zone: &ZoneId) -> bool {
        self.resource_types.contains(&target.resource_type)
            && self.resource_verbs.contains(&target.verb)
            && (self.zones.is_empty() || self.zones.contains(zone))
            && (self.resource_names.is_empty()
                || target
                    .resource_name
                    .as_ref()
                    .is_some_and(|name| self.resource_names.contains(name)))
            && (self.subresources.is_empty()
                || target
                    .subresource
                    .as_ref()
                    .is_some_and(|value| self.subresources.contains(value)))
            && (self.execution_refs.is_empty()
                || target
                    .execution_ref
                    .as_ref()
                    .is_some_and(|value| self.execution_refs.contains(value)))
    }

    fn permits_session_target(
        &self,
        target: &AuthorizationTarget,
        zone: &ZoneId,
        verb: SessionVerb,
    ) -> bool {
        self.session_verbs.contains(&verb)
            && (self.resource_types.is_empty()
                || self.resource_types.contains(&target.resource_type))
            && (self.zones.is_empty() || self.zones.contains(zone))
            && (self.resource_names.is_empty()
                || target
                    .resource_name
                    .as_ref()
                    .is_some_and(|name| self.resource_names.contains(name)))
            && (self.subresources.is_empty()
                || target
                    .subresource
                    .as_ref()
                    .is_some_and(|value| self.subresources.contains(value)))
            && (self.execution_refs.is_empty()
                || target
                    .execution_ref
                    .as_ref()
                    .is_some_and(|value| self.execution_refs.contains(value)))
    }

    /// Compile one public Role rule into the evaluator's private projection.
    ///
    /// The conversion is intentionally one-way.  The evaluator never exposes
    /// its internal sets as an alternate resource schema, and an explicit
    /// reviewed wildcard is represented as an empty private name set only
    /// after provenance has been checked by the caller.
    pub fn from_role_rule(
        catalog: &ApiCatalog,
        rule: &RoleRule,
        core_controller_generated: bool,
    ) -> Result<Self, AuthorizationPolicyError> {
        rule.validate_provenance(core_controller_generated)
            .map_err(|_| AuthorizationPolicyError::RoleSchema)?;
        let resource_names = if rule.resource_names().iter().any(|name| name == "*") {
            if !core_controller_generated || rule.resource_names().len() != 1 {
                return Err(AuthorizationPolicyError::WildcardRestricted);
            }
            Vec::new()
        } else {
            rule.resource_names()
                .iter()
                .map(|name| ResourceName::parse(name.clone()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| AuthorizationPolicyError::RoleSchema)?
        };
        let resource_verbs = rule
            .verbs()
            .iter()
            .copied()
            .map(role_resource_verb)
            .collect::<Vec<_>>();
        let session_verbs = rule
            .session_verbs()
            .iter()
            .copied()
            .map(role_session_verb)
            .collect::<Vec<_>>();
        Self::new(
            catalog,
            rule.resource_types().iter().cloned(),
            resource_verbs,
            session_verbs,
            rule.subresources()
                .iter()
                .map(|selector| selector.as_str().to_owned()),
            resource_names,
            rule.zones().iter().cloned(),
            rule.execution_refs().iter().cloned(),
        )
    }
}

fn role_resource_verb(value: RoleResourceVerb) -> ResourceVerb {
    match value {
        RoleResourceVerb::Get => ResourceVerb::Get,
        RoleResourceVerb::List => ResourceVerb::List,
        RoleResourceVerb::Watch => ResourceVerb::Watch,
        RoleResourceVerb::Create => ResourceVerb::Create,
        RoleResourceVerb::UpdateSpec => ResourceVerb::UpdateSpec,
        RoleResourceVerb::UpdateStatus => ResourceVerb::UpdateStatus,
        RoleResourceVerb::UpdateMetadata => ResourceVerb::UpdateMetadata,
        RoleResourceVerb::UpdateFinalizers => ResourceVerb::UpdateFinalizers,
        RoleResourceVerb::Delete => ResourceVerb::Delete,
        RoleResourceVerb::UseCredential => ResourceVerb::UseCredential,
        RoleResourceVerb::AdminCredential => ResourceVerb::AdminCredential,
    }
}

fn role_session_verb(value: RoleSessionVerb) -> SessionVerb {
    match value {
        RoleSessionVerb::Connect => SessionVerb::Connect,
        RoleSessionVerb::Invoke => SessionVerb::Invoke,
        RoleSessionVerb::OpenStream => SessionVerb::OpenStream,
        RoleSessionVerb::Relay => SessionVerb::Relay,
        RoleSessionVerb::Attach => SessionVerb::Attach,
        RoleSessionVerb::Cancel => SessionVerb::Cancel,
        RoleSessionVerb::Observe => SessionVerb::Observe,
        RoleSessionVerb::AuditExport => SessionVerb::AuditExport,
        RoleSessionVerb::SupportBundle => SessionVerb::SupportBundle,
    }
}

/// Validated evaluator projection of one Role.
#[derive(Clone, PartialEq, Eq)]
pub struct CompiledRole {
    pub role_ref: ResourceRef,
    pub rules: Vec<PolicyRule>,
}

impl core::fmt::Debug for CompiledRole {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CompiledRole")
            .field("role_ref", &"<redacted>")
            .field("rule_count", &self.rules.len())
            .finish()
    }
}

impl CompiledRole {
    pub fn new(
        role_ref: ResourceRef,
        rules: Vec<PolicyRule>,
    ) -> Result<Self, AuthorizationPolicyError> {
        if role_ref.resource_type().as_str() != "Role" || rules.len() > MAX_ROLE_RULES {
            return Err(AuthorizationPolicyError::RoleShape);
        }
        Ok(Self { role_ref, rules })
    }

    /// Compile a public Role resource.
    pub fn from_spec(
        role_ref: ResourceRef,
        spec: &RoleSpec,
        catalog: &ApiCatalog,
        core_controller_generated: bool,
    ) -> Result<Self, AuthorizationPolicyError> {
        let rules = spec
            .rules()
            .iter()
            .map(|rule| PolicyRule::from_role_rule(catalog, rule, core_controller_generated))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(role_ref, rules)
    }
}

/// Validated evaluator projection of one RoleBinding.
#[derive(Clone, PartialEq, Eq)]
pub struct CompiledRoleBinding {
    pub role_ref: ResourceRef,
    pub subjects: BTreeSet<BoundSubject>,
    pub scope: BindingScope,
    pub relay_authority: RelayGrantAuthority,
    narrowing: Option<Vec<PolicyRule>>,
}

impl core::fmt::Debug for CompiledRoleBinding {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CompiledRoleBinding")
            .field("role_ref", &"<redacted>")
            .field("subject_count", &self.subjects.len())
            .field("scope", &self.scope)
            .field("relay_authority", &self.relay_authority)
            .finish()
    }
}

impl CompiledRoleBinding {
    pub fn new(
        role_ref: ResourceRef,
        subjects: impl IntoIterator<Item = BoundSubject>,
        scope: BindingScope,
        relay_authority: RelayGrantAuthority,
    ) -> Result<Self, AuthorizationPolicyError> {
        let subjects = subjects.into_iter().collect::<Vec<_>>();
        let subject_count = subjects.len();
        let subjects = subjects.into_iter().collect::<BTreeSet<_>>();
        if role_ref.resource_type().as_str() != "Role"
            || subjects.is_empty()
            || subjects.len() != subject_count
            || subjects.len() > MAX_ROLE_BINDING_SUBJECTS
            || subjects.iter().any(|subject| {
                !matches!(
                    subject.subject_ref.resource_type().as_str(),
                    "Zone" | "ZoneLink" | "User" | "Provider" | "Host" | "Guest" | "Process"
                )
            })
            || scope.resource_names.len() > MAX_ROLE_RULE_RESOURCE_NAMES
            || scope.execution_refs.len() > MAX_ROLE_RULE_EXECUTION_REFS
        {
            return Err(AuthorizationPolicyError::BindingShape);
        }
        Ok(Self {
            role_ref,
            subjects,
            scope,
            relay_authority,
            narrowing: None,
        })
    }

    fn contains_subject(&self, context: &AuthenticatedSubjectContext) -> bool {
        self.subjects.contains(&BoundSubject {
            subject_ref: context.subject_ref().clone(),
            subject_uid: context.subject_uid().clone(),
        })
    }

    fn permits_scope(&self, target: &AuthorizationTarget, zone: &ZoneId) -> bool {
        (self.scope.zones.is_empty() || self.scope.zones.contains(zone))
            && (self.scope.resource_names.is_empty()
                || target
                    .resource_name
                    .as_ref()
                    .is_some_and(|name| self.scope.resource_names.contains(name)))
            && (self.scope.execution_refs.is_empty()
                || target
                    .execution_ref
                    .as_ref()
                    .is_some_and(|reference| self.scope.execution_refs.contains(reference)))
    }

    fn permits_narrowed_target(&self, target: &AuthorizationTarget, zone: &ZoneId) -> bool {
        self.narrowing
            .as_ref()
            .is_none_or(|rules| rules.iter().any(|rule| rule.permits_target(target, zone)))
    }

    fn permits_narrowed_session(
        &self,
        target: &AuthorizationTarget,
        zone: &ZoneId,
        verb: SessionVerb,
    ) -> bool {
        self.narrowing.as_ref().is_none_or(|rules| {
            rules
                .iter()
                .any(|rule| rule.permits_session_target(target, zone, verb))
        })
    }

    /// Compile a public RoleBinding after resolving each local subject UID.
    ///
    /// The resolver is owned by the Zone store. A missing UID is a typed
    /// refusal, never a name-only grant, so recreating a same-named subject
    /// cannot inherit the old binding.
    pub fn from_spec(
        spec: &RoleBindingSpec,
        subject_uids: impl Fn(&ResourceRef) -> Option<ResourceUid>,
        relay_authority: RelayGrantAuthority,
    ) -> Result<Self, AuthorizationPolicyError> {
        let subjects = spec
            .subjects()
            .iter()
            .map(|subject_ref| {
                let subject_uid =
                    subject_uids(subject_ref).ok_or(AuthorizationPolicyError::SubjectUnresolved)?;
                Ok(BoundSubject {
                    subject_ref: subject_ref.clone(),
                    subject_uid,
                })
            })
            .collect::<Result<Vec<_>, AuthorizationPolicyError>>()?;
        Self::from_spec_with_resolved_subjects(spec, subjects, relay_authority)
    }

    /// Compile a RoleBinding from the subset of subjects that currently have
    /// valid store evidence. Unresolved subjects are intentionally omitted so
    /// they cannot grant access or invalidate unrelated subjects in the same
    /// binding.
    pub fn from_spec_with_resolved_subjects(
        spec: &RoleBindingSpec,
        subjects: impl IntoIterator<Item = BoundSubject>,
        relay_authority: RelayGrantAuthority,
    ) -> Result<Self, AuthorizationPolicyError> {
        let subjects = subjects.into_iter().collect::<Vec<_>>();
        if subjects
            .iter()
            .any(|subject| !spec.subjects().contains(&subject.subject_ref))
        {
            return Err(AuthorizationPolicyError::BindingShape);
        }
        let mut scope = BindingScope::default();
        if let Some(narrowing) = spec.scope_narrowing() {
            for rule in narrowing.rules() {
                if rule.resource_names().iter().any(|name| name == "*") {
                    return Err(AuthorizationPolicyError::ScopeNotSubset);
                }
                scope.zones.extend(rule.zones().iter().cloned());
                for name in rule.resource_names() {
                    scope.resource_names.insert(
                        ResourceName::parse(name.clone())
                            .map_err(|_| AuthorizationPolicyError::ScopeNotSubset)?,
                    );
                }
                scope
                    .execution_refs
                    .extend(rule.execution_refs().iter().cloned());
            }
        }
        let mut binding = Self::new(spec.role_ref().clone(), subjects, scope, relay_authority)?;
        if let Some(narrowing) = spec.scope_narrowing() {
            let rules = narrowing
                .rules()
                .iter()
                .map(|rule| PolicyRule::from_role_rule(&ApiCatalog::standard(), rule, false))
                .collect::<Result<Vec<_>, _>>()?;
            binding.narrowing = Some(rules);
        }
        Ok(binding)
    }
}

/// One immutable installed policy revision.
#[derive(Clone, PartialEq, Eq)]
pub struct PolicySet {
    pub policy_revision: u64,
    catalog: ApiCatalog,
    roles: BTreeMap<ResourceRef, CompiledRole>,
    bindings: Vec<CompiledRoleBinding>,
}

impl core::fmt::Debug for PolicySet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PolicySet")
            .field("policy_revision", &"<redacted>")
            .field("catalog", &self.catalog)
            .field("role_count", &self.roles.len())
            .field("binding_count", &self.bindings.len())
            .finish()
    }
}

impl PolicySet {
    pub fn new(
        catalog: &ApiCatalog,
        policy_revision: u64,
        roles: Vec<CompiledRole>,
        bindings: Vec<CompiledRoleBinding>,
    ) -> Result<Self, AuthorizationPolicyError> {
        if policy_revision == 0 {
            return Err(AuthorizationPolicyError::PolicyRevisionZero);
        }
        let role_count = roles.len();
        let roles = roles
            .into_iter()
            .map(|role| (role.role_ref.clone(), role))
            .collect::<BTreeMap<_, _>>();
        if roles.len() != role_count {
            return Err(AuthorizationPolicyError::DuplicateRole);
        }
        for binding in &bindings {
            let role = roles
                .get(&binding.role_ref)
                .ok_or(AuthorizationPolicyError::MissingRole)?;
            let has_relay = role
                .rules
                .iter()
                .any(|rule| rule.session_verbs.contains(&SessionVerb::Relay));
            if has_relay && binding.relay_authority == RelayGrantAuthority::None {
                return Err(AuthorizationPolicyError::RelayGrantRestricted);
            }
        }
        Ok(Self {
            policy_revision,
            catalog: catalog.clone(),
            roles,
            bindings,
        })
    }
}

/// Positive exact capabilities, never inferred from a denial.
#[derive(Clone, PartialEq, Eq)]
pub struct PositiveCapabilities {
    pub resources: Vec<AuthorizationTarget>,
    pub session_verbs: BTreeSet<SessionVerb>,
}

impl core::fmt::Debug for PositiveCapabilities {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PositiveCapabilities")
            .field("resource_count", &self.resources.len())
            .field("session_verb_count", &self.session_verbs.len())
            .finish()
    }
}

/// Typed fail-closed authorization outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationDenial {
    PolicyUnavailable,
    PolicyRevisionChanged,
    ZoneMismatch,
    NoMatchingGrant,
    RelayOriginInvalid,
    RelayGrantMissing,
    RelayTargetGrantMissing,
    BootstrapDenied,
    UnknownResourceType,
}

impl AuthorizationDenial {
    pub const fn resource_error_kind(self) -> ResourceErrorKind {
        match self {
            Self::RelayOriginInvalid | Self::RelayGrantMissing => ResourceErrorKind::RelayDenied,
            Self::RelayTargetGrantMissing => ResourceErrorKind::AuthorizationDenied,
            _ => ResourceErrorKind::AuthorizationDenied,
        }
    }
}

/// Successful authorization evidence returned to the service.
pub struct AuthorizationGrant {
    permit: AdmissionPermit,
}

/// Convert Core's assignment identity to the storage-neutral mutation fence.
pub fn assignment_fence(
    identity: &AssignmentIdentity,
) -> Result<ResourceAssignmentFence, AssignmentError> {
    let target = match identity.target() {
        AssignmentTarget::Zone(zone) => ResourceRef::parse(&format!("Zone/{}", zone.as_str()))
            .map_err(|_| AssignmentError::TargetMismatch)?,
        AssignmentTarget::Execution { reference, .. } => reference.clone(),
    };
    Ok(ResourceAssignmentFence {
        resource_uid: identity.resource_uid().clone(),
        resource_revision: identity.resource_revision(),
        provider_generation: identity.provider_generation(),
        controller_generation: identity.controller_generation(),
        controller_role: identity.controller_role().clone(),
        target,
        session_generation: identity.session_generation(),
        epoch: identity.epoch().get(),
        scope: d2b_resource_store::ResourceAssignmentScope::Primary,
    })
}

/// Build a mutation fence from a controller-scoped mutation.
pub fn assignment_fence_for_mutation(
    mutation: &ScopedResourceMutation,
) -> Result<ResourceAssignmentFence, AssignmentError> {
    let mut fence = assignment_fence(mutation.assignment())?;
    if let Some(scope) = mutation.scope().owner_child() {
        fence.scope = ResourceAssignmentScope::OwnerChild {
            owner_ref: scope.owner_ref().clone(),
            owner_uid: scope.owner_uid().clone(),
            owner_revision: scope.owner_revision(),
            owner_generation: scope.owner_generation(),
        };
    }
    Ok(fence)
}

impl core::fmt::Debug for AuthorizationGrant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AuthorizationGrant(<redacted>)")
    }
}

/// Non-transferable authorization evidence for a downstream effect.
///
/// The issuer is private to this crate and the value has no serialization or
/// general construction path. A downstream owner may borrow the evidence only
/// while consuming the matching admitted mutation.
///
/// ```compile_fail
/// use d2b_resource_api::AuthorizationLease;
///
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<AuthorizationLease>();
/// ```
///
/// ```compile_fail
/// use d2b_resource_api::AuthorizationLease;
///
/// fn requires_default<T: Default>() {}
/// requires_default::<AuthorizationLease>();
/// ```
///
/// ```compile_fail
/// use d2b_resource_api::AuthorizationLease;
///
/// let _: AuthorizationLease = <() as Into<AuthorizationLease>>::into(());
/// ```
pub struct AuthorizationLease {
    #[allow(dead_code)]
    authority: Arc<LeaseAuthority>,
    subject_uid: ResourceUid,
    zone_uid: ResourceUid,
    object_uid: Option<ResourceUid>,
    object_generation: Option<ResourceGeneration>,
    operation: AdmittedVerb,
    policy_revision: u64,
    provider_assignment_generation: Option<ResourceGeneration>,
    operation_id: String,
}

struct LeaseAuthority;

impl core::fmt::Debug for AuthorizationLease {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AuthorizationLease")
            .field("subject_uid", &"<redacted>")
            .field("zone_uid", &"<redacted>")
            .field("has_object_uid", &self.object_uid.is_some())
            .field("has_object_generation", &self.object_generation.is_some())
            .field("operation", &self.operation)
            .field("policy_revision", &"<redacted>")
            .field(
                "has_provider_assignment_generation",
                &self.provider_assignment_generation.is_some(),
            )
            .field("operation_id", &"<redacted>")
            .finish()
    }
}

const _: fn() = || {
    trait CapabilityMustNotImplementCloneCopyDefaultOrFrom<A> {
        fn some_item() {}
    }
    impl<T: ?Sized> CapabilityMustNotImplementCloneCopyDefaultOrFrom<()> for T {}
    impl<T: Clone> CapabilityMustNotImplementCloneCopyDefaultOrFrom<u8> for T {}
    impl<T: Copy> CapabilityMustNotImplementCloneCopyDefaultOrFrom<u16> for T {}
    impl<T: Default> CapabilityMustNotImplementCloneCopyDefaultOrFrom<u32> for T {}
    impl<T: From<()>> CapabilityMustNotImplementCloneCopyDefaultOrFrom<u64> for T {}
    let _ = <AuthorizationLease as CapabilityMustNotImplementCloneCopyDefaultOrFrom<_>>::some_item;
};

impl AuthorizationLease {
    pub(crate) fn issue(
        subject_uid: ResourceUid,
        zone_uid: ResourceUid,
        object_uid: Option<ResourceUid>,
        object_generation: Option<ResourceGeneration>,
        operation: AdmittedVerb,
        policy_revision: u64,
        provider_assignment_generation: Option<ResourceGeneration>,
        operation_id: String,
    ) -> Result<Self, AdmissionError> {
        if policy_revision == 0
            || operation_id.is_empty()
            || operation_id.len() > 128
            || operation_id.chars().any(char::is_control)
        {
            return Err(AdmissionError::LeaseInvalid);
        }
        Ok(Self {
            authority: Arc::new(LeaseAuthority),
            subject_uid,
            zone_uid,
            object_uid,
            object_generation,
            operation,
            policy_revision,
            provider_assignment_generation,
            operation_id,
        })
    }

    pub const fn subject_uid(&self) -> &ResourceUid {
        &self.subject_uid
    }

    pub const fn zone_uid(&self) -> &ResourceUid {
        &self.zone_uid
    }

    pub const fn object_uid(&self) -> Option<&ResourceUid> {
        self.object_uid.as_ref()
    }

    pub const fn object_generation(&self) -> Option<ResourceGeneration> {
        self.object_generation
    }

    pub const fn operation(&self) -> AdmittedVerb {
        self.operation
    }

    pub const fn policy_revision(&self) -> u64 {
        self.policy_revision
    }

    pub const fn provider_assignment_generation(&self) -> Option<ResourceGeneration> {
        self.provider_assignment_generation
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }
}

impl AuthorizationGrant {
    /// Consume this positive authorization result into one exact Guest
    /// lifecycle lease. The caller must supply the current object and
    /// Provider assignment identity obtained from the trusted Zone store.
    pub(crate) fn issue_lifecycle_lease(
        self,
        zone_uid: ResourceUid,
        object_uid: ResourceUid,
        object_generation: ResourceGeneration,
        provider_assignment_generation: ResourceGeneration,
        operation_id: String,
    ) -> Result<AuthorizationLease, AdmissionError> {
        self.permit.issue_lifecycle_lease(
            zone_uid,
            object_uid,
            object_generation,
            provider_assignment_generation,
            operation_id,
        )
    }

    pub(crate) fn admit(
        self,
        mutations: Vec<StoreMutation>,
        operation: StoreOperationContext,
    ) -> Result<AdmittedMutation, AdmissionError> {
        self.permit.admit(mutations, operation)
    }

    pub(crate) fn admit_with_zone_uid(
        self,
        mutations: Vec<StoreMutation>,
        operation: StoreOperationContext,
        zone_uid: ResourceUid,
    ) -> Result<AdmittedMutation, AdmissionError> {
        self.permit
            .admit_with_zone_uid(mutations, operation, zone_uid)
    }
}

/// Single native evaluator and positive-decision cache.
pub struct NativeAuthorizer {
    catalog: ApiCatalog,
    policy: RwLock<Option<Arc<PolicySet>>>,
    cache: PositiveDecisionCache,
    admission: AdmissionIssuer,
    store_binding: Mutex<Option<StoreAdmissionBinding>>,
    session_store_binding: Option<StoreAdmissionBinding>,
    store_seal:
        std::sync::Arc<Mutex<Option<d2b_resource_store::mutation_seal::MutationSealIssuer>>>,
}

impl core::fmt::Debug for NativeAuthorizer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("NativeAuthorizer(<redacted>)")
    }
}

impl NativeAuthorizer {
    /// Build an evaluator carrying one single-owner store binding.
    pub fn new(
        catalog: ApiCatalog,
        policy: Option<PolicySet>,
    ) -> Result<Self, AuthorizationPolicyError> {
        let (admission, store_binding) = admission_pair();
        Self::from_issuer_with_binding(catalog, policy, admission, Some(store_binding))
    }

    #[cfg(test)]
    fn from_issuer(
        catalog: ApiCatalog,
        policy: Option<PolicySet>,
        admission: AdmissionIssuer,
    ) -> Result<Self, AuthorizationPolicyError> {
        Self::from_issuer_with_binding(catalog, policy, admission, None)
    }

    fn from_issuer_with_binding(
        catalog: ApiCatalog,
        policy: Option<PolicySet>,
        admission: AdmissionIssuer,
        store_binding: Option<StoreAdmissionBinding>,
    ) -> Result<Self, AuthorizationPolicyError> {
        if policy
            .as_ref()
            .is_some_and(|policy| policy.catalog != catalog)
        {
            return Err(AuthorizationPolicyError::CatalogMismatch);
        }
        Ok(Self {
            catalog,
            policy: RwLock::new(policy.map(Arc::new)),
            cache: PositiveDecisionCache::new(POSITIVE_CACHE_ENTRIES),
            admission,
            store_seal: store_binding
                .as_ref()
                .map(|binding| binding.seal_issuer())
                .unwrap_or_else(|| std::sync::Arc::new(Mutex::new(None))),
            session_store_binding: store_binding.clone(),
            store_binding: Mutex::new(store_binding),
        })
    }

    pub(super) fn take_store_binding(&self) -> Result<StoreAdmissionBinding, StoreBindingError> {
        let mut binding = self.store_binding.lock().map_err(|_| StoreBindingError)?;
        if !binding
            .as_ref()
            .is_some_and(StoreAdmissionBinding::has_seal_issuer)
        {
            return Err(StoreBindingError);
        }
        binding.take().ok_or(StoreBindingError)
    }

    pub(super) fn session_store_binding(&self) -> Result<StoreAdmissionBinding, StoreBindingError> {
        self.session_store_binding
            .as_ref()
            .filter(|binding| binding.has_seal_issuer())
            .cloned()
            .ok_or(StoreBindingError)
    }

    pub fn take_store_seal(
        &self,
        store: StoreSealIdentity,
    ) -> Result<d2b_resource_store::mutation_seal::MutationSealAcceptor, StoreSealHandoffError>
    {
        let slot = store.slot();
        let zone = store.zone().clone();
        let mut issuer =
            self.store_seal
                .lock()
                .map_err(|_| StoreSealHandoffError::AuthorizerUnavailable {
                    slot,
                    zone: zone.clone(),
                })?;
        if issuer.is_some() {
            return Err(StoreSealHandoffError::AlreadyTaken { slot, zone });
        }
        let (new_issuer, acceptor) = d2b_resource_store::mutation_seal::mutation_seal_pair(store);
        *issuer = Some(new_issuer);
        Ok(acceptor)
    }

    #[cfg(test)]
    pub(crate) fn test_store_seal_issuer_slot(
        &self,
    ) -> Arc<Mutex<Option<d2b_resource_store::mutation_seal::MutationSealIssuer>>> {
        Arc::clone(&self.store_seal)
    }

    pub fn replace_policy(
        &self,
        policy: PolicySet,
        state: &AuthorizationState,
    ) -> Result<(), AuthorizationPolicyError> {
        if policy.catalog != self.catalog {
            return Err(AuthorizationPolicyError::CatalogMismatch);
        }
        if policy.policy_revision != state.snapshot.policy_revision {
            return Err(AuthorizationPolicyError::PolicyStateRevisionMismatch);
        }
        let mut installed = self.write_policy();
        *installed = Some(Arc::new(policy));
        self.cache.clear();
        Ok(())
    }

    pub fn mark_policy_unavailable(&self) {
        *self.write_policy() = None;
        self.cache.clear();
    }

    /// Bind an already authenticated transport subject to this authorizer.
    ///
    /// The caller must supply claims issued by the ComponentSession
    /// authority.  This method only creates the Resource API capability after
    /// the live policy grants the subject a session connection, so generated
    /// handlers never receive an unbound or caller-authored identity.
    pub fn issue_authenticated_subject(
        &self,
        context: AuthenticatedSubjectContext,
        state: AuthorizationState,
    ) -> Result<crate::AuthenticatedSubjectContext, AuthorizationDenial> {
        let zone = ZoneId::parse(context.zone_ref().name().as_str())
            .map_err(|_| AuthorizationDenial::ZoneMismatch)?;
        let capabilities = self.positive_capabilities(&context, &zone, &state)?;
        if !capabilities.session_verbs.contains(&SessionVerb::Connect) {
            return Err(AuthorizationDenial::NoMatchingGrant);
        }
        Ok(crate::identity::AuthenticatedSubjectContext::issue(
            std::sync::Arc::new(context),
            state,
        ))
    }

    pub fn authorize(
        &self,
        context: &AuthenticatedSubjectContext,
        request: &AuthorizationRequest,
        state: &AuthorizationState,
    ) -> Result<AuthorizationGrant, AuthorizationDenial> {
        self.authorize_before_grant(context, request, state, || {})
    }

    fn authorize_before_grant(
        &self,
        context: &AuthenticatedSubjectContext,
        request: &AuthorizationRequest,
        state: &AuthorizationState,
        before_grant: impl FnOnce(),
    ) -> Result<AuthorizationGrant, AuthorizationDenial> {
        if request.targets.is_empty() {
            return Err(AuthorizationDenial::NoMatchingGrant);
        }
        if request
            .targets
            .iter()
            .any(|target| !self.catalog.contains(&target.resource_type))
        {
            return Err(AuthorizationDenial::UnknownResourceType);
        }
        if context.zone_ref().resource_type().as_str() != "Zone"
            || context.zone_ref().name().as_str() != request.zone.as_str()
        {
            return Err(AuthorizationDenial::ZoneMismatch);
        }
        let relay_hop = authenticated_relay_hop(context)?;
        if state.snapshot.policy_revision == 0 {
            return authorize_bootstrap(&self.admission, context, request, state, relay_hop);
        }

        let installed = self.read_policy();
        let policy = installed
            .as_ref()
            .ok_or(AuthorizationDenial::PolicyUnavailable)?;
        if policy.policy_revision != state.snapshot.policy_revision {
            return Err(AuthorizationDenial::PolicyRevisionChanged);
        }

        let cache_key = cache_key(context, request, relay_hop);
        let revisions = revision_set(state);
        if !self.cache.contains(&cache_key, revisions, state.now_tick) {
            evaluate_policy(policy, context, request, relay_hop)?;
            self.cache.insert_allow(
                cache_key,
                revisions,
                state.now_tick.saturating_add(POSITIVE_CACHE_TICKS),
                state.now_tick,
            );
        }
        before_grant();
        Ok(grant(
            &self.admission,
            context,
            request,
            state.snapshot,
            state.zone_policy_revision.get(),
        ))
    }

    pub fn positive_capabilities(
        &self,
        context: &AuthenticatedSubjectContext,
        zone: &ZoneId,
        state: &AuthorizationState,
    ) -> Result<PositiveCapabilities, AuthorizationDenial> {
        let policy = self
            .read_policy()
            .clone()
            .ok_or(AuthorizationDenial::PolicyUnavailable)?;
        if policy.policy_revision != state.snapshot.policy_revision {
            return Err(AuthorizationDenial::PolicyRevisionChanged);
        }
        let mut resources = Vec::new();
        let mut session_verbs = BTreeSet::new();
        for binding in policy
            .bindings
            .iter()
            .filter(|binding| binding.contains_subject(context))
            .filter(|binding| binding.scope.zones.is_empty() || binding.scope.zones.contains(zone))
        {
            let Some(role) = policy.roles.get(&binding.role_ref) else {
                continue;
            };
            for rule in &role.rules {
                if !rule.zones.is_empty() && !rule.zones.contains(zone) {
                    continue;
                }
                for verb in &rule.session_verbs {
                    if binding.narrowing.as_ref().is_none_or(|narrowing| {
                        narrowing
                            .iter()
                            .any(|narrowed| narrowed.session_verbs.contains(verb))
                    }) {
                        session_verbs.insert(*verb);
                    }
                }
                for resource_type in &rule.resource_types {
                    for verb in &rule.resource_verbs {
                        if rule.resource_names.is_empty() {
                            let target = AuthorizationTarget {
                                resource_type: resource_type.clone(),
                                resource_name: None,
                                verb: *verb,
                                subresource: None,
                                execution_ref: None,
                            };
                            if binding.permits_scope(&target, zone)
                                && binding.permits_narrowed_target(&target, zone)
                                && !resources.contains(&target)
                            {
                                resources.push(target);
                            }
                        } else {
                            for name in &rule.resource_names {
                                let target = AuthorizationTarget {
                                    resource_type: resource_type.clone(),
                                    resource_name: Some(name.clone()),
                                    verb: *verb,
                                    subresource: None,
                                    execution_ref: None,
                                };
                                if binding.permits_scope(&target, zone)
                                    && binding.permits_narrowed_target(&target, zone)
                                    && !resources.contains(&target)
                                {
                                    resources.push(target);
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(PositiveCapabilities {
            resources,
            session_verbs,
        })
    }

    fn read_policy(&self) -> RwLockReadGuard<'_, Option<Arc<PolicySet>>> {
        self.policy
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn write_policy(&self) -> RwLockWriteGuard<'_, Option<Arc<PolicySet>>> {
        self.policy
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

pub(crate) fn authenticated_relay_hop(
    context: &AuthenticatedSubjectContext,
) -> Result<bool, AuthorizationDenial> {
    match context.transport_binding().locality() {
        Locality::Local => Ok(false),
        Locality::AdjacentZone
            if context.evidence_class() == EvidenceClass::EnrolledKk
                && matches!(
                    context.subject_ref().resource_type().as_str(),
                    "Zone" | "ZoneLink"
                ) =>
        {
            Ok(true)
        }
        Locality::AdjacentZone | Locality::Remote => Err(AuthorizationDenial::RelayOriginInvalid),
    }
}

fn evaluate_policy(
    policy: &PolicySet,
    context: &AuthenticatedSubjectContext,
    request: &AuthorizationRequest,
    relay_hop: bool,
) -> Result<(), AuthorizationDenial> {
    if relay_hop {
        let relay_allowed = policy
            .bindings
            .iter()
            .filter(|binding| {
                binding.contains_subject(context)
                    && binding.relay_authority != RelayGrantAuthority::None
            })
            .any(|binding| {
                policy.roles.get(&binding.role_ref).is_some_and(|role| {
                    role.rules.iter().any(|rule| {
                        request.targets.iter().any(|target| {
                            rule.permits_session_target(target, &request.zone, SessionVerb::Relay)
                                && binding.permits_narrowed_session(
                                    target,
                                    &request.zone,
                                    SessionVerb::Relay,
                                )
                        })
                    })
                })
            });
        if !relay_allowed {
            return Err(AuthorizationDenial::RelayGrantMissing);
        }
    }

    for target in &request.targets {
        let allowed = policy
            .bindings
            .iter()
            .filter(|binding| {
                binding.contains_subject(context) && binding.permits_scope(target, &request.zone)
            })
            .any(|binding| {
                policy.roles.get(&binding.role_ref).is_some_and(|role| {
                    role.rules.iter().any(|rule| {
                        rule.permits_target(target, &request.zone)
                            && binding.permits_narrowed_target(target, &request.zone)
                    })
                })
            });
        if !allowed {
            return Err(if relay_hop {
                AuthorizationDenial::RelayTargetGrantMissing
            } else {
                AuthorizationDenial::NoMatchingGrant
            });
        }
    }
    Ok(())
}

fn grant(
    admission: &AdmissionIssuer,
    context: &AuthenticatedSubjectContext,
    request: &AuthorizationRequest,
    policy_snapshot: PolicySnapshot,
    zone_policy_revision: u64,
) -> AuthorizationGrant {
    AuthorizationGrant {
        permit: admission.record_allow_with_zone_policy_revision(
            AdmittedAuthorization {
                zone: request.zone.clone(),
                subject_ref: context.subject_ref().clone(),
                subject_uid: context.subject_uid().clone(),
                targets: request
                    .targets
                    .iter()
                    .map(|target| AdmittedAuthorizationTarget {
                        resource_type: target.resource_type.clone(),
                        resource_name: target.resource_name.clone(),
                        verb: target.verb.admitted(),
                        subresource: target.subresource.clone(),
                        execution_ref: target.execution_ref.clone(),
                    })
                    .collect(),
            },
            policy_snapshot,
            zone_policy_revision,
        ),
    }
}

fn cache_key(
    context: &AuthenticatedSubjectContext,
    request: &AuthorizationRequest,
    relay_hop: bool,
) -> AuthorizationCacheKey {
    let mut digest = Sha256::new();
    digest.update([request.method as u8]);
    digest.update(request.zone.as_str().as_bytes());
    digest.update([u8::from(relay_hop)]);
    digest.update([evidence_tag(context.evidence_class())]);
    digest.update([locality_tag(context.transport_binding().locality())]);
    digest.update(context.session_purpose().as_str().as_bytes());
    digest.update([0]);
    digest.update(context.service().as_str().as_bytes());
    if let Some(generation) = context.controller_generation() {
        digest.update([1]);
        digest.update(generation.get().to_be_bytes());
    } else {
        digest.update([0]);
    }
    if let Some(generation) = context.provider_generation() {
        digest.update([1]);
        digest.update(generation.get().to_be_bytes());
    } else {
        digest.update([0]);
    }
    for target in &request.targets {
        digest.update(target.resource_type.as_str().as_bytes());
        if let Some(name) = &target.resource_name {
            digest.update([0]);
            digest.update(name.as_str().as_bytes());
        }
        digest.update([target.verb.tag()]);
        if let Some(subresource) = &target.subresource {
            digest.update([0]);
            digest.update(subresource.as_bytes());
        }
        if let Some(execution_ref) = &target.execution_ref {
            digest.update([0]);
            digest.update(execution_ref.to_canonical_string().as_bytes());
        }
    }
    AuthorizationCacheKey::new(
        context.subject_ref().clone(),
        context.subject_uid().clone(),
        digest.finalize().into(),
    )
}

const fn evidence_tag(value: EvidenceClass) -> u8 {
    match value {
        EvidenceClass::UnixPeer => 1,
        EvidenceClass::EnrolledKk => 2,
        EvidenceClass::BootstrapIkpsk2 => 3,
        EvidenceClass::NativeVsock => 4,
    }
}

const fn locality_tag(value: Locality) -> u8 {
    match value {
        Locality::Local => 1,
        Locality::AdjacentZone => 2,
        Locality::Remote => 3,
    }
}

fn revision_set(state: &AuthorizationState) -> PolicyRevisionSet {
    PolicyRevisionSet {
        policy_revision: state.snapshot.policy_revision,
        api_catalog_revision: state.snapshot.api_catalog_revision,
        active_configuration_revision: state.snapshot.active_configuration_revision,
        zone_policy_revision: state.zone_policy_revision,
    }
}

#[derive(Debug, Clone, Copy)]
struct BootstrapRow {
    subject_name: &'static str,
    method: ApiMethod,
    resource_type: &'static str,
    verb: ResourceVerb,
}

const fn bootstrap_row(
    subject_name: &'static str,
    method: ApiMethod,
    resource_type: &'static str,
    verb: ResourceVerb,
) -> BootstrapRow {
    BootstrapRow {
        subject_name,
        method,
        resource_type,
        verb,
    }
}

const BOOTSTRAP_ROWS: &[BootstrapRow; 42] = &[
    bootstrap_row(
        "system-core",
        ApiMethod::Create,
        "Zone",
        ResourceVerb::Create,
    ),
    bootstrap_row(
        "system-core",
        ApiMethod::Create,
        "Provider",
        ResourceVerb::Create,
    ),
    bootstrap_row(
        "system-core",
        ApiMethod::Create,
        "Host",
        ResourceVerb::Create,
    ),
    bootstrap_row(
        "system-core",
        ApiMethod::Create,
        "User",
        ResourceVerb::Create,
    ),
    bootstrap_row(
        "system-core",
        ApiMethod::Create,
        "Role",
        ResourceVerb::Create,
    ),
    bootstrap_row(
        "system-core",
        ApiMethod::Create,
        "RoleBinding",
        ResourceVerb::Create,
    ),
    bootstrap_row(
        "system-core",
        ApiMethod::Create,
        "Process",
        ResourceVerb::Create,
    ),
    bootstrap_row(
        "system-core",
        ApiMethod::UpdateStatus,
        "Zone",
        ResourceVerb::UpdateStatus,
    ),
    bootstrap_row(
        "system-core",
        ApiMethod::UpdateStatus,
        "Provider",
        ResourceVerb::UpdateStatus,
    ),
    bootstrap_row(
        "system-core",
        ApiMethod::UpdateStatus,
        "Host",
        ResourceVerb::UpdateStatus,
    ),
    bootstrap_row(
        "system-core",
        ApiMethod::UpdateStatus,
        "User",
        ResourceVerb::UpdateStatus,
    ),
    bootstrap_row(
        "system-core",
        ApiMethod::UpdateStatus,
        "Process",
        ResourceVerb::UpdateStatus,
    ),
    bootstrap_row("system-core", ApiMethod::Get, "Zone", ResourceVerb::Get),
    bootstrap_row("system-core", ApiMethod::Get, "Provider", ResourceVerb::Get),
    bootstrap_row("system-core", ApiMethod::Get, "Host", ResourceVerb::Get),
    bootstrap_row("system-core", ApiMethod::Get, "User", ResourceVerb::Get),
    bootstrap_row("system-core", ApiMethod::Get, "Process", ResourceVerb::Get),
    bootstrap_row("system-core", ApiMethod::List, "Zone", ResourceVerb::List),
    bootstrap_row(
        "system-core",
        ApiMethod::List,
        "Provider",
        ResourceVerb::List,
    ),
    bootstrap_row("system-core", ApiMethod::List, "Host", ResourceVerb::List),
    bootstrap_row("system-core", ApiMethod::List, "User", ResourceVerb::List),
    bootstrap_row(
        "system-core",
        ApiMethod::List,
        "Process",
        ResourceVerb::List,
    ),
    bootstrap_row("system-core", ApiMethod::Watch, "Zone", ResourceVerb::Watch),
    bootstrap_row(
        "system-core",
        ApiMethod::Watch,
        "Provider",
        ResourceVerb::Watch,
    ),
    bootstrap_row("system-core", ApiMethod::Watch, "Host", ResourceVerb::Watch),
    bootstrap_row("system-core", ApiMethod::Watch, "User", ResourceVerb::Watch),
    bootstrap_row(
        "system-core",
        ApiMethod::Watch,
        "Process",
        ResourceVerb::Watch,
    ),
    bootstrap_row(
        "system-core",
        ApiMethod::ResolveRef,
        "Zone",
        ResourceVerb::Get,
    ),
    bootstrap_row(
        "system-core",
        ApiMethod::ResolveRef,
        "Provider",
        ResourceVerb::Get,
    ),
    bootstrap_row(
        "system-core",
        ApiMethod::ResolveRef,
        "Host",
        ResourceVerb::Get,
    ),
    bootstrap_row(
        "system-core",
        ApiMethod::ResolveRef,
        "User",
        ResourceVerb::Get,
    ),
    bootstrap_row(
        "system-core",
        ApiMethod::ResolveRef,
        "Process",
        ResourceVerb::Get,
    ),
    bootstrap_row(
        "system-core",
        ApiMethod::InspectSchema,
        "Provider",
        ResourceVerb::Get,
    ),
    bootstrap_row(
        "system-minijail",
        ApiMethod::Get,
        "Process",
        ResourceVerb::Get,
    ),
    bootstrap_row(
        "system-minijail",
        ApiMethod::Get,
        "EphemeralProcess",
        ResourceVerb::Get,
    ),
    bootstrap_row(
        "system-minijail",
        ApiMethod::List,
        "Process",
        ResourceVerb::List,
    ),
    bootstrap_row(
        "system-minijail",
        ApiMethod::List,
        "EphemeralProcess",
        ResourceVerb::List,
    ),
    bootstrap_row(
        "system-minijail",
        ApiMethod::Watch,
        "Process",
        ResourceVerb::Watch,
    ),
    bootstrap_row(
        "system-minijail",
        ApiMethod::Watch,
        "EphemeralProcess",
        ResourceVerb::Watch,
    ),
    bootstrap_row(
        "system-minijail",
        ApiMethod::UpdateStatus,
        "Process",
        ResourceVerb::UpdateStatus,
    ),
    bootstrap_row(
        "system-minijail",
        ApiMethod::UpdateStatus,
        "EphemeralProcess",
        ResourceVerb::UpdateStatus,
    ),
    bootstrap_row(
        "system-minijail",
        ApiMethod::InspectSchema,
        "Process",
        ResourceVerb::Get,
    ),
];

fn authorize_bootstrap(
    admission: &AdmissionIssuer,
    context: &AuthenticatedSubjectContext,
    request: &AuthorizationRequest,
    state: &AuthorizationState,
    relay_hop: bool,
) -> Result<AuthorizationGrant, AuthorizationDenial> {
    let (zone, core_uid, minijail_uid, controller_generation, provider_generation, unprovisioned) =
        match &state.bootstrap_phase {
            BootstrapPhase::Unprovisioned {
                zone,
                controller_generation,
                provider_generation,
            } => (
                zone,
                None,
                None,
                *controller_generation,
                *provider_generation,
                true,
            ),
            BootstrapPhase::Provisioned {
                zone,
                system_core_uid,
                system_minijail_uid,
                controller_generation,
                provider_generation,
            } => (
                zone,
                Some(system_core_uid),
                Some(system_minijail_uid),
                *controller_generation,
                *provider_generation,
                false,
            ),
            BootstrapPhase::Disabled => return Err(AuthorizationDenial::BootstrapDenied),
        };
    if relay_hop
        || &request.zone != zone
        || context.evidence_class() != EvidenceClass::UnixPeer
        || context.transport_binding().locality() != Locality::Local
        || context.session_purpose().as_str() != BOOTSTRAP_PURPOSE
        || context.service().as_str() != RESOURCE_SERVICE
        || context.controller_generation() != Some(controller_generation)
        || context.provider_generation() != Some(provider_generation)
        || context.subject_ref().resource_type().as_str() != "Provider"
    {
        return Err(AuthorizationDenial::BootstrapDenied);
    }
    let subject_name = context.subject_ref().name().as_str();
    let zone_name =
        ResourceName::parse(zone.as_str()).map_err(|_| AuthorizationDenial::BootstrapDenied)?;
    if !unprovisioned {
        let expected_uid = match subject_name {
            "system-core" => core_uid,
            "system-minijail" => minijail_uid,
            _ => None,
        };
        if expected_uid != Some(context.subject_uid()) {
            return Err(AuthorizationDenial::BootstrapDenied);
        }
    }
    for target in &request.targets {
        let allowed = BOOTSTRAP_ROWS.iter().any(|row| {
            row.subject_name == subject_name
                && row.method == request.method
                && row.resource_type == target.resource_type.as_str()
                && row.verb == target.verb
        });
        if !allowed {
            return Err(AuthorizationDenial::BootstrapDenied);
        }
        let compiled_name = match target.resource_type.as_str() {
            "Zone" => target
                .resource_name
                .as_ref()
                .is_none_or(|name| name == &zone_name),
            "Provider" => target
                .resource_name
                .as_ref()
                .is_none_or(|name| matches!(name.as_str(), "system-core" | "system-minijail")),
            _ => true,
        };
        if !compiled_name {
            return Err(AuthorizationDenial::BootstrapDenied);
        }
    }
    Ok(grant(
        admission,
        context,
        request,
        state.snapshot,
        state.zone_policy_revision.get(),
    ))
}

/// Invalid compiled policy projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationPolicyError {
    RuleBounds,
    UnknownResourceType,
    CatalogShape,
    CatalogMismatch,
    CredentialScope,
    RoleShape,
    BindingShape,
    MissingRole,
    DuplicateRole,
    RelayGrantRestricted,
    PolicyRevisionZero,
    PolicyStateRevisionMismatch,
    /// A public Role rule could not be represented by the private evaluator.
    RoleSchema,
    /// An explicit wildcard was not created by a fixed core controller role.
    WildcardRestricted,
    /// A RoleBinding subject did not resolve to an immutable UID.
    SubjectUnresolved,
    /// A scope narrowing would widen or ambiguously represent its Role.
    ScopeNotSubset,
}

impl core::fmt::Display for AuthorizationPolicyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::RuleBounds => "Role rule exceeds a frozen bound",
            Self::UnknownResourceType => "Role rule names an uninstalled ResourceType",
            Self::CatalogShape => "API catalog extension set is invalid",
            Self::CatalogMismatch => "policy was compiled for a different API catalog",
            Self::CredentialScope => "Credential verb requires an exact Credential subresource",
            Self::RoleShape => "Role evaluator projection is invalid",
            Self::BindingShape => "RoleBinding evaluator projection is invalid",
            Self::MissingRole => "RoleBinding references a missing Role",
            Self::DuplicateRole => "policy contains duplicate Role identities",
            Self::RelayGrantRestricted => "relay grant is not core or durable-admin authorized",
            Self::PolicyRevisionZero => "stored policy revision must be nonzero",
            Self::PolicyStateRevisionMismatch => {
                "installed policy revision does not match trusted runtime state"
            }
            Self::RoleSchema => "Role resource schema cannot be compiled",
            Self::WildcardRestricted => "Role wildcard requires fixed core provenance",
            Self::SubjectUnresolved => "RoleBinding subject is unresolved",
            Self::ScopeNotSubset => "RoleBinding scope narrowing is not a subset",
        })
    }
}

impl std::error::Error for AuthorizationPolicyError {}

#[cfg(test)]
mod tests {
    use super::*;
    use d2b_contracts_resource::v3::identity::{
        BindingDigest, ReconnectGeneration, ServiceName, SessionBinding, SessionPurpose,
        TranscriptHash, TransportBinding,
    };
    use d2b_contracts_resource::v3::{
        ConfigurationGeneration, ResourceGeneration, SchemaFingerprint,
    };

    fn test_issuer() -> AdmissionIssuer {
        crate::admission::admission_pair().0
    }

    fn subject(
        locality: Locality,
        evidence: EvidenceClass,
        subject_ref: &str,
    ) -> AuthenticatedSubjectContext {
        AuthenticatedSubjectContext::new(
            ResourceRef::parse(subject_ref).unwrap(),
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap(),
            ResourceRef::parse("Zone/dev").unwrap(),
            evidence,
            SessionPurpose::parse("resource-api").unwrap(),
            ServiceName::parse(RESOURCE_SERVICE).unwrap(),
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
    }

    fn state(revision: u64) -> AuthorizationState {
        AuthorizationState {
            snapshot: PolicySnapshot {
                policy_revision: revision,
                api_catalog_revision: 2,
                active_configuration_revision: ConfigurationGeneration::new(3).unwrap(),
                controller_generation: None,
            },
            zone_policy_revision: ZoneRevision::new(revision),
            bootstrap_phase: BootstrapPhase::Disabled,
            now_tick: 1,
        }
    }

    #[test]
    fn authorization_lease_binds_the_complete_downstream_identity() {
        let subject_uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let zone_uid = ResourceUid::parse("223e4567-e89b-42d3-a456-426614174000").unwrap();
        let object_uid = ResourceUid::parse("323e4567-e89b-42d3-a456-426614174000").unwrap();
        let lease = AuthorizationLease::issue(
            subject_uid.clone(),
            zone_uid.clone(),
            Some(object_uid.clone()),
            Some(ResourceGeneration::new(4).unwrap()),
            AdmittedVerb::UpdateSpec,
            7,
            Some(ResourceGeneration::new(9).unwrap()),
            "operation-lease".to_owned(),
        )
        .unwrap();
        assert_eq!(lease.subject_uid(), &subject_uid);
        assert_eq!(lease.zone_uid(), &zone_uid);
        assert_eq!(lease.object_uid(), Some(&object_uid));
        assert_eq!(
            lease.object_generation(),
            Some(ResourceGeneration::new(4).unwrap())
        );
        assert_eq!(lease.operation(), AdmittedVerb::UpdateSpec);
        assert_eq!(lease.policy_revision(), 7);
        assert_eq!(
            lease.provider_assignment_generation(),
            Some(ResourceGeneration::new(9).unwrap())
        );
        assert_eq!(lease.operation_id(), "operation-lease");
        let rendered = format!("{lease:?}");
        assert!(!rendered.contains("operation-lease"));
        assert!(!rendered.contains(subject_uid.as_str()));
        assert!(!rendered.contains(zone_uid.as_str()));
    }

    #[test]
    fn lifecycle_lease_is_issued_only_from_a_consumed_authorization_grant() {
        let zone = ZoneId::parse("dev").unwrap();
        let request = AuthorizationRequest {
            method: ApiMethod::UpdateSpec,
            zone: zone.clone(),
            targets: vec![AuthorizationTarget {
                resource_type: ResourceTypeName::parse("Guest").unwrap(),
                resource_name: Some(ResourceName::parse("workstation").unwrap()),
                verb: ResourceVerb::UpdateSpec,
                subresource: None,
                execution_ref: None,
            }],
        };
        let snapshot = state(7).snapshot;
        let grant = grant(
            &test_issuer(),
            &subject(Locality::Local, EvidenceClass::UnixPeer, "User/alice"),
            &request,
            snapshot,
            7,
        );
        let lease = grant
            .issue_lifecycle_lease(
                ResourceUid::parse("223e4567-e89b-42d3-a456-426614174000").unwrap(),
                ResourceUid::parse("323e4567-e89b-42d3-a456-426614174000").unwrap(),
                ResourceGeneration::new(4).unwrap(),
                ResourceGeneration::new(9).unwrap(),
                "guest-start".to_owned(),
            )
            .unwrap();
        assert_eq!(lease.operation(), AdmittedVerb::UpdateSpec);
        assert_eq!(lease.policy_revision(), 7);
        assert_eq!(lease.operation_id(), "guest-start");
        assert_eq!(
            lease.object_generation(),
            Some(ResourceGeneration::new(4).unwrap())
        );
        assert_eq!(
            lease.provider_assignment_generation(),
            Some(ResourceGeneration::new(9).unwrap())
        );
    }

    #[test]
    fn take_store_seal_rejects_a_second_call() {
        let authorizer = NativeAuthorizer::new(ApiCatalog::standard(), None).unwrap();
        let identity = StoreSealIdentity::new(
            StoreSlot::new(3).unwrap(),
            ZoneId::parse("dev").unwrap(),
            ResourceUid::parse("11111111-1111-4111-8111-111111111111").unwrap(),
        );
        authorizer
            .take_store_seal(identity.clone())
            .expect("first store-seal handoff");

        let error = authorizer
            .take_store_seal(identity)
            .err()
            .expect("second store-seal handoff must fail");
        match error {
            StoreSealHandoffError::AlreadyTaken { slot, .. } => {
                assert_eq!(slot, StoreSlot::new(3).unwrap())
            }
            StoreSealHandoffError::AuthorizerUnavailable { .. } => {
                panic!("a healthy authorizer reported poisoned seal state")
            }
        }
    }

    fn bootstrap_subject(subject_name: &str, subject_uid: &str) -> AuthenticatedSubjectContext {
        AuthenticatedSubjectContext::new(
            ResourceRef::parse(&format!("Provider/{subject_name}")).unwrap(),
            ResourceUid::parse(subject_uid).unwrap(),
            ResourceRef::parse("Zone/dev").unwrap(),
            EvidenceClass::UnixPeer,
            SessionPurpose::parse(BOOTSTRAP_PURPOSE).unwrap(),
            ServiceName::parse(RESOURCE_SERVICE).unwrap(),
            SessionBinding::new(
                SchemaFingerprint::parse(format!("sha256:{}", "1".repeat(64))).unwrap(),
                TransportBinding::new(
                    Locality::Local,
                    BindingDigest::parse(format!("sha256:{}", "2".repeat(64))).unwrap(),
                ),
                ReconnectGeneration::new(1).unwrap(),
                TranscriptHash::from_bytes([3; 32]),
            ),
        )
        .with_controller_generation(ControllerGeneration::new(11).unwrap())
        .with_provider_generation(ResourceGeneration::new(12).unwrap())
    }

    fn bootstrap_state(phase: BootstrapPhase) -> AuthorizationState {
        AuthorizationState {
            snapshot: PolicySnapshot {
                policy_revision: 0,
                api_catalog_revision: 1,
                active_configuration_revision: ConfigurationGeneration::new(1).unwrap(),
                controller_generation: Some(ControllerGeneration::new(11).unwrap()),
            },
            zone_policy_revision: ZoneRevision::new(0),
            bootstrap_phase: phase,
            now_tick: 1,
        }
    }

    #[test]
    fn bootstrap_phase_is_derived_only_from_policy_revision_and_fixed_provider_rows() {
        let zone = ZoneId::parse("dev").unwrap();
        let controller_generation = ControllerGeneration::new(11).unwrap();
        let provider_generation = ResourceGeneration::new(12).unwrap();
        let facts = BootstrapStoreFacts {
            zone: zone.clone(),
            policy_revision: 0,
            bootstrap_provider_uids: BTreeMap::new(),
            controller_generation,
            provider_generation,
        };
        assert!(matches!(
            derive_bootstrap_phase(&facts),
            BootstrapPhase::Unprovisioned { .. }
        ));

        let mut provisioned = facts.clone();
        provisioned.bootstrap_provider_uids.insert(
            ResourceName::parse("system-core").unwrap(),
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap(),
        );
        provisioned.bootstrap_provider_uids.insert(
            ResourceName::parse("system-minijail").unwrap(),
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174001").unwrap(),
        );
        assert!(matches!(
            derive_bootstrap_phase(&provisioned),
            BootstrapPhase::Provisioned { .. }
        ));

        provisioned.policy_revision = 1;
        assert_eq!(
            derive_bootstrap_phase(&provisioned),
            BootstrapPhase::Disabled
        );
        assert!(bootstrap_policy_transition(0, 1));
        assert!(!bootstrap_policy_transition(1, 2));
        assert!(!bootstrap_policy_transition(0, 2));
    }

    fn bootstrap_target(resource_type: &str, verb: ResourceVerb) -> AuthorizationTarget {
        let resource_name = match resource_type {
            "Zone" => "dev",
            "Provider" => "system-core",
            _ => "app",
        };
        AuthorizationTarget {
            resource_type: ResourceTypeName::parse(resource_type).unwrap(),
            resource_name: Some(ResourceName::parse(resource_name).unwrap()),
            verb,
            subresource: None,
            execution_ref: None,
        }
    }

    fn target(verb: ResourceVerb) -> AuthorizationTarget {
        AuthorizationTarget {
            resource_type: ResourceTypeName::parse("Process").unwrap(),
            resource_name: Some(ResourceName::parse("app").unwrap()),
            verb,
            subresource: None,
            execution_ref: None,
        }
    }

    fn policy(
        revision: u64,
        context: &AuthenticatedSubjectContext,
        target_verb: Option<ResourceVerb>,
        relay: bool,
    ) -> PolicySet {
        let catalog = ApiCatalog::standard();
        let mut rules = Vec::new();
        if let Some(verb) = target_verb {
            rules.push(
                PolicyRule::new(
                    &catalog,
                    [ResourceTypeName::parse("Process").unwrap()],
                    [verb],
                    [],
                    [],
                    [ResourceName::parse("app").unwrap()],
                    [ZoneId::parse("dev").unwrap()],
                    [],
                )
                .unwrap(),
            );
        }
        if relay {
            rules.push(
                PolicyRule::new(&catalog, [], [], [SessionVerb::Relay], [], [], [], []).unwrap(),
            );
        }
        let role = CompiledRole::new(ResourceRef::parse("Role/operator").unwrap(), rules).unwrap();
        let binding = CompiledRoleBinding::new(
            role.role_ref.clone(),
            [BoundSubject {
                subject_ref: context.subject_ref().clone(),
                subject_uid: context.subject_uid().clone(),
            }],
            BindingScope::default(),
            if relay {
                RelayGrantAuthority::CoreGenerated
            } else {
                RelayGrantAuthority::None
            },
        )
        .unwrap();
        PolicySet::new(&catalog, revision, vec![role], vec![binding]).unwrap()
    }

    fn request() -> AuthorizationRequest {
        AuthorizationRequest {
            method: ApiMethod::Get,
            zone: ZoneId::parse("dev").unwrap(),
            targets: vec![target(ResourceVerb::Get)],
        }
    }

    #[test]
    fn decision_matrix_and_positive_capabilities_are_exact() {
        let context = subject(Locality::Local, EvidenceClass::UnixPeer, "User/alice");
        let engine = NativeAuthorizer::from_issuer(
            ApiCatalog::standard(),
            Some(policy(4, &context, Some(ResourceVerb::Get), false)),
            test_issuer(),
        )
        .unwrap();
        assert!(engine.authorize(&context, &request(), &state(4)).is_ok());
        let caps = engine
            .positive_capabilities(&context, &ZoneId::parse("dev").unwrap(), &state(4))
            .unwrap();
        assert_eq!(caps.resources, vec![target(ResourceVerb::Get)]);
        assert_eq!(
            engine
                .authorize(
                    &context,
                    &AuthorizationRequest {
                        targets: vec![target(ResourceVerb::Delete)],
                        ..request()
                    },
                    &state(4),
                )
                .unwrap_err(),
            AuthorizationDenial::NoMatchingGrant
        );
    }

    #[test]
    fn revocation_and_policy_outage_fail_closed() {
        let context = subject(Locality::Local, EvidenceClass::UnixPeer, "User/alice");
        let engine = NativeAuthorizer::from_issuer(
            ApiCatalog::standard(),
            Some(policy(4, &context, Some(ResourceVerb::Get), false)),
            test_issuer(),
        )
        .unwrap();
        assert!(engine.authorize(&context, &request(), &state(4)).is_ok());
        engine
            .replace_policy(policy(5, &context, None, false), &state(5))
            .unwrap();
        assert_eq!(
            engine
                .authorize(&context, &request(), &state(5))
                .unwrap_err(),
            AuthorizationDenial::NoMatchingGrant
        );
        engine.mark_policy_unavailable();
        assert_eq!(
            engine
                .authorize(&context, &request(), &state(5))
                .unwrap_err(),
            AuthorizationDenial::PolicyUnavailable
        );
    }

    #[test]
    fn same_revision_policy_replacement_invalidates_a_cached_allow() {
        let context = subject(Locality::Local, EvidenceClass::UnixPeer, "User/alice");
        let engine = NativeAuthorizer::from_issuer(
            ApiCatalog::standard(),
            Some(policy(4, &context, Some(ResourceVerb::Get), false)),
            test_issuer(),
        )
        .unwrap();
        assert!(engine.authorize(&context, &request(), &state(4)).is_ok());

        engine
            .replace_policy(policy(4, &context, None, false), &state(4))
            .unwrap();

        assert_eq!(
            engine
                .authorize(&context, &request(), &state(4))
                .unwrap_err(),
            AuthorizationDenial::NoMatchingGrant
        );
    }

    #[test]
    fn replacement_and_permit_minting_are_linearized() {
        use std::sync::mpsc::{self, TryRecvError};

        let context = subject(Locality::Local, EvidenceClass::UnixPeer, "User/alice");
        let engine = Arc::new(
            NativeAuthorizer::from_issuer(
                ApiCatalog::standard(),
                Some(policy(4, &context, Some(ResourceVerb::Get), false)),
                test_issuer(),
            )
            .unwrap(),
        );
        assert!(engine.authorize(&context, &request(), &state(4)).is_ok());

        let (at_grant_tx, at_grant_rx) = mpsc::channel();
        let (release_grant_tx, release_grant_rx) = mpsc::channel();
        let authorizing_engine = Arc::clone(&engine);
        let authorizing_context = context.clone();
        let authorizing = std::thread::spawn(move || {
            authorizing_engine.authorize_before_grant(
                &authorizing_context,
                &request(),
                &state(4),
                || {
                    at_grant_tx.send(()).unwrap();
                    release_grant_rx.recv().unwrap();
                },
            )
        });
        at_grant_rx.recv().unwrap();
        assert!(
            engine.policy.try_write().is_err(),
            "permit minting released the policy guard before returning"
        );

        let (replacement_started_tx, replacement_started_rx) = mpsc::channel();
        let (replacement_done_tx, replacement_done_rx) = mpsc::channel();
        let replacing_engine = Arc::clone(&engine);
        let replacing_context = context.clone();
        let replacing = std::thread::spawn(move || {
            replacement_started_tx.send(()).unwrap();
            let result = replacing_engine
                .replace_policy(policy(4, &replacing_context, None, false), &state(4));
            replacement_done_tx.send(result).unwrap();
        });
        replacement_started_rx.recv().unwrap();
        assert_eq!(replacement_done_rx.try_recv(), Err(TryRecvError::Empty));

        release_grant_tx.send(()).unwrap();
        assert!(authorizing.join().unwrap().is_ok());
        replacement_done_rx.recv().unwrap().unwrap();
        replacing.join().unwrap();

        assert_eq!(
            engine
                .authorize(&context, &request(), &state(4))
                .unwrap_err(),
            AuthorizationDenial::NoMatchingGrant
        );
    }

    #[test]
    fn adjacent_route_cannot_disable_relay_admission() {
        let context = subject(
            Locality::AdjacentZone,
            EvidenceClass::EnrolledKk,
            "ZoneLink/parent",
        );
        let no_relay = NativeAuthorizer::from_issuer(
            ApiCatalog::standard(),
            Some(policy(4, &context, Some(ResourceVerb::Get), false)),
            test_issuer(),
        )
        .unwrap();
        assert_eq!(
            no_relay
                .authorize(&context, &request(), &state(4))
                .unwrap_err(),
            AuthorizationDenial::RelayGrantMissing
        );
        let no_target = NativeAuthorizer::from_issuer(
            ApiCatalog::standard(),
            Some(policy(4, &context, None, true)),
            test_issuer(),
        )
        .unwrap();
        assert_eq!(
            no_target
                .authorize(&context, &request(), &state(4))
                .unwrap_err(),
            AuthorizationDenial::RelayTargetGrantMissing
        );
        let both = NativeAuthorizer::from_issuer(
            ApiCatalog::standard(),
            Some(policy(4, &context, Some(ResourceVerb::Get), true)),
            test_issuer(),
        )
        .unwrap();
        assert!(both.authorize(&context, &request(), &state(4)).is_ok());
    }

    #[test]
    fn relay_rejects_untrusted_adjacent_and_remote_origins() {
        for (locality, evidence) in [
            (Locality::AdjacentZone, EvidenceClass::BootstrapIkpsk2),
            (Locality::Remote, EvidenceClass::EnrolledKk),
        ] {
            let context = subject(locality, evidence, "ZoneLink/parent");
            let engine = NativeAuthorizer::from_issuer(
                ApiCatalog::standard(),
                Some(policy(4, &context, Some(ResourceVerb::Get), true)),
                test_issuer(),
            )
            .unwrap();
            assert_eq!(
                engine
                    .authorize(&context, &request(), &state(4))
                    .unwrap_err(),
                AuthorizationDenial::RelayOriginInvalid
            );
        }
    }

    #[test]
    fn positive_cache_cannot_cross_authentication_evidence() {
        let enrolled = subject(
            Locality::AdjacentZone,
            EvidenceClass::EnrolledKk,
            "ZoneLink/parent",
        );
        let engine = NativeAuthorizer::from_issuer(
            ApiCatalog::standard(),
            Some(policy(4, &enrolled, Some(ResourceVerb::Get), true)),
            test_issuer(),
        )
        .unwrap();
        assert!(engine.authorize(&enrolled, &request(), &state(4)).is_ok());

        let bootstrap = subject(
            Locality::AdjacentZone,
            EvidenceClass::BootstrapIkpsk2,
            "ZoneLink/parent",
        );
        assert_eq!(
            engine
                .authorize(&bootstrap, &request(), &state(4))
                .unwrap_err(),
            AuthorizationDenial::RelayOriginInvalid
        );
    }

    #[test]
    fn parent_subject_cannot_cross_the_child_zone_boundary() {
        let context = subject(
            Locality::AdjacentZone,
            EvidenceClass::EnrolledKk,
            "ZoneLink/parent",
        );
        let engine = NativeAuthorizer::from_issuer(
            ApiCatalog::standard(),
            Some(policy(4, &context, Some(ResourceVerb::Get), true)),
            test_issuer(),
        )
        .unwrap();
        let mut wrong_zone = request();
        wrong_zone.zone = ZoneId::parse("other").unwrap();
        assert_eq!(
            engine
                .authorize(&context, &wrong_zone, &state(4))
                .unwrap_err(),
            AuthorizationDenial::ZoneMismatch
        );
    }

    #[test]
    fn closed_rule_bounds_and_relay_origin_are_validated() {
        let too_many_types = (0..=MAX_ROLE_RULE_RESOURCE_TYPES)
            .map(|index| ResourceTypeName::parse(format!("p{index}.d2bus.org.Type")).unwrap())
            .collect::<Vec<_>>();
        let extension_catalog = ApiCatalog::with_extensions(too_many_types.clone()).unwrap();
        assert_eq!(
            PolicyRule::new(
                &extension_catalog,
                too_many_types,
                [ResourceVerb::Get],
                [],
                [],
                [],
                [],
                [],
            ),
            Err(AuthorizationPolicyError::RuleBounds)
        );

        let context = subject(
            Locality::AdjacentZone,
            EvidenceClass::EnrolledKk,
            "ZoneLink/parent",
        );
        let relay_role = CompiledRole::new(
            ResourceRef::parse("Role/relay").unwrap(),
            vec![
                PolicyRule::new(
                    &ApiCatalog::standard(),
                    [],
                    [],
                    [SessionVerb::Relay],
                    [],
                    [],
                    [],
                    [],
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let binding = CompiledRoleBinding::new(
            relay_role.role_ref.clone(),
            [BoundSubject {
                subject_ref: context.subject_ref().clone(),
                subject_uid: context.subject_uid().clone(),
            }],
            BindingScope::default(),
            RelayGrantAuthority::None,
        )
        .unwrap();
        assert_eq!(
            PolicySet::new(&ApiCatalog::standard(), 4, vec![relay_role], vec![binding]),
            Err(AuthorizationPolicyError::RelayGrantRestricted)
        );

        assert_eq!(
            PolicyRule::new(
                &ApiCatalog::standard(),
                [ResourceTypeName::parse("Credential").unwrap()],
                [ResourceVerb::AdminCredential],
                [],
                ["create".to_owned()],
                [],
                [],
                [],
            ),
            Err(AuthorizationPolicyError::CredentialScope)
        );

        let invalid_subject = BoundSubject {
            subject_ref: ResourceRef::parse("Credential/signing").unwrap(),
            subject_uid: ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap(),
        };
        assert_eq!(
            CompiledRoleBinding::new(
                ResourceRef::parse("Role/operator").unwrap(),
                [invalid_subject],
                BindingScope::default(),
                RelayGrantAuthority::None,
            ),
            Err(AuthorizationPolicyError::BindingShape)
        );
    }

    #[test]
    fn uninstalled_resource_types_are_rejected_in_rules_and_targets() {
        let catalog = ApiCatalog::standard();
        let extension = ResourceTypeName::parse("example.d2bus.org.Widget").unwrap();
        assert_eq!(
            PolicyRule::new(
                &catalog,
                [extension.clone()],
                [ResourceVerb::Get],
                [],
                [],
                [],
                [],
                [],
            ),
            Err(AuthorizationPolicyError::UnknownResourceType)
        );

        let context = subject(Locality::Local, EvidenceClass::UnixPeer, "User/alice");
        let engine = NativeAuthorizer::from_issuer(catalog, None, test_issuer()).unwrap();
        let mut uninstalled = request();
        uninstalled.targets[0].resource_type = extension;
        assert_eq!(
            engine
                .authorize(&context, &uninstalled, &state(4))
                .unwrap_err(),
            AuthorizationDenial::UnknownResourceType
        );
    }

    #[test]
    fn configuration_revision_is_a_monotonic_ordinal_in_the_snapshot() {
        let snapshot = state(4).snapshot;
        assert_eq!(snapshot.active_configuration_revision.get(), 3);
        assert_eq!(
            snapshot
                .active_configuration_revision
                .checked_next()
                .unwrap()
                .get(),
            4
        );
        let _: Option<ConfigurationGeneration> = Some(snapshot.active_configuration_revision);
        let _: Option<ResourceGeneration> = None;
    }

    #[test]
    fn bootstrap_matrix_matches_literal_oracle_and_denies_every_dimension_near_miss() {
        const EXPECTED_BOOTSTRAP_ROWS: [(&str, ApiMethod, &str, ResourceVerb); 42] = [
            (
                "system-core",
                ApiMethod::Create,
                "Zone",
                ResourceVerb::Create,
            ),
            (
                "system-core",
                ApiMethod::Create,
                "Provider",
                ResourceVerb::Create,
            ),
            (
                "system-core",
                ApiMethod::Create,
                "Host",
                ResourceVerb::Create,
            ),
            (
                "system-core",
                ApiMethod::Create,
                "User",
                ResourceVerb::Create,
            ),
            (
                "system-core",
                ApiMethod::Create,
                "Role",
                ResourceVerb::Create,
            ),
            (
                "system-core",
                ApiMethod::Create,
                "RoleBinding",
                ResourceVerb::Create,
            ),
            (
                "system-core",
                ApiMethod::Create,
                "Process",
                ResourceVerb::Create,
            ),
            (
                "system-core",
                ApiMethod::UpdateStatus,
                "Zone",
                ResourceVerb::UpdateStatus,
            ),
            (
                "system-core",
                ApiMethod::UpdateStatus,
                "Provider",
                ResourceVerb::UpdateStatus,
            ),
            (
                "system-core",
                ApiMethod::UpdateStatus,
                "Host",
                ResourceVerb::UpdateStatus,
            ),
            (
                "system-core",
                ApiMethod::UpdateStatus,
                "User",
                ResourceVerb::UpdateStatus,
            ),
            (
                "system-core",
                ApiMethod::UpdateStatus,
                "Process",
                ResourceVerb::UpdateStatus,
            ),
            ("system-core", ApiMethod::Get, "Zone", ResourceVerb::Get),
            ("system-core", ApiMethod::Get, "Provider", ResourceVerb::Get),
            ("system-core", ApiMethod::Get, "Host", ResourceVerb::Get),
            ("system-core", ApiMethod::Get, "User", ResourceVerb::Get),
            ("system-core", ApiMethod::Get, "Process", ResourceVerb::Get),
            ("system-core", ApiMethod::List, "Zone", ResourceVerb::List),
            (
                "system-core",
                ApiMethod::List,
                "Provider",
                ResourceVerb::List,
            ),
            ("system-core", ApiMethod::List, "Host", ResourceVerb::List),
            ("system-core", ApiMethod::List, "User", ResourceVerb::List),
            (
                "system-core",
                ApiMethod::List,
                "Process",
                ResourceVerb::List,
            ),
            ("system-core", ApiMethod::Watch, "Zone", ResourceVerb::Watch),
            (
                "system-core",
                ApiMethod::Watch,
                "Provider",
                ResourceVerb::Watch,
            ),
            ("system-core", ApiMethod::Watch, "Host", ResourceVerb::Watch),
            ("system-core", ApiMethod::Watch, "User", ResourceVerb::Watch),
            (
                "system-core",
                ApiMethod::Watch,
                "Process",
                ResourceVerb::Watch,
            ),
            (
                "system-core",
                ApiMethod::ResolveRef,
                "Zone",
                ResourceVerb::Get,
            ),
            (
                "system-core",
                ApiMethod::ResolveRef,
                "Provider",
                ResourceVerb::Get,
            ),
            (
                "system-core",
                ApiMethod::ResolveRef,
                "Host",
                ResourceVerb::Get,
            ),
            (
                "system-core",
                ApiMethod::ResolveRef,
                "User",
                ResourceVerb::Get,
            ),
            (
                "system-core",
                ApiMethod::ResolveRef,
                "Process",
                ResourceVerb::Get,
            ),
            (
                "system-core",
                ApiMethod::InspectSchema,
                "Provider",
                ResourceVerb::Get,
            ),
            (
                "system-minijail",
                ApiMethod::Get,
                "Process",
                ResourceVerb::Get,
            ),
            (
                "system-minijail",
                ApiMethod::Get,
                "EphemeralProcess",
                ResourceVerb::Get,
            ),
            (
                "system-minijail",
                ApiMethod::List,
                "Process",
                ResourceVerb::List,
            ),
            (
                "system-minijail",
                ApiMethod::List,
                "EphemeralProcess",
                ResourceVerb::List,
            ),
            (
                "system-minijail",
                ApiMethod::Watch,
                "Process",
                ResourceVerb::Watch,
            ),
            (
                "system-minijail",
                ApiMethod::Watch,
                "EphemeralProcess",
                ResourceVerb::Watch,
            ),
            (
                "system-minijail",
                ApiMethod::UpdateStatus,
                "Process",
                ResourceVerb::UpdateStatus,
            ),
            (
                "system-minijail",
                ApiMethod::UpdateStatus,
                "EphemeralProcess",
                ResourceVerb::UpdateStatus,
            ),
            (
                "system-minijail",
                ApiMethod::InspectSchema,
                "Process",
                ResourceVerb::Get,
            ),
        ];

        let actual = BOOTSTRAP_ROWS
            .iter()
            .map(|row| (row.subject_name, row.method, row.resource_type, row.verb))
            .collect::<Vec<_>>();
        assert_eq!(actual.as_slice(), &EXPECTED_BOOTSTRAP_ROWS);

        let core_uid = "123e4567-e89b-42d3-a456-426614174000";
        let minijail_uid = "123e4567-e89b-42d3-a456-426614174001";
        let state = bootstrap_state(BootstrapPhase::Provisioned {
            zone: ZoneId::parse("dev").unwrap(),
            system_core_uid: ResourceUid::parse(core_uid).unwrap(),
            system_minijail_uid: ResourceUid::parse(minijail_uid).unwrap(),
            controller_generation: ControllerGeneration::new(11).unwrap(),
            provider_generation: ResourceGeneration::new(12).unwrap(),
        });
        let engine =
            NativeAuthorizer::from_issuer(ApiCatalog::standard(), None, test_issuer()).unwrap();

        for (subject_name, method, resource_type, verb) in EXPECTED_BOOTSTRAP_ROWS {
            let uid = if subject_name == "system-core" {
                core_uid
            } else {
                minijail_uid
            };
            let context = bootstrap_subject(subject_name, uid);
            let exact = AuthorizationRequest {
                method,
                zone: ZoneId::parse("dev").unwrap(),
                targets: vec![bootstrap_target(resource_type, verb)],
            };
            assert_eq!(
                engine.authorize(&context, &exact, &state).map(|_| ()),
                Ok(()),
                "bootstrap row did not authorize: {} {:?} {} {:?}",
                subject_name,
                method,
                resource_type,
                verb,
            );

            let wrong_subject =
                bootstrap_subject(subject_name, "123e4567-e89b-42d3-a456-426614174099");
            assert_eq!(
                engine
                    .authorize(&wrong_subject, &exact, &state)
                    .unwrap_err(),
                AuthorizationDenial::BootstrapDenied,
                "bootstrap subject near miss authorized: {subject_name} {method:?} {resource_type}"
            );

            let wrong_subject_name = bootstrap_subject("system-subject-near-miss", core_uid);
            let name_mismatch_state = bootstrap_state(BootstrapPhase::Unprovisioned {
                zone: ZoneId::parse("dev").unwrap(),
                controller_generation: ControllerGeneration::new(11).unwrap(),
                provider_generation: ResourceGeneration::new(12).unwrap(),
            });
            assert_eq!(
                engine
                    .authorize(&wrong_subject_name, &exact, &name_mismatch_state)
                    .unwrap_err(),
                AuthorizationDenial::BootstrapDenied,
                "bootstrap subject-name near miss authorized: \
                 {subject_name} {method:?} {resource_type}"
            );

            let mut wrong_verb = exact.clone();
            wrong_verb.targets[0].verb = ResourceVerb::UseCredential;
            assert_eq!(
                engine.authorize(&context, &wrong_verb, &state).unwrap_err(),
                AuthorizationDenial::BootstrapDenied,
                "bootstrap verb near miss authorized: {subject_name} {method:?} {resource_type}"
            );

            let mut wrong_method = exact.clone();
            wrong_method.method = ApiMethod::Delete;
            assert_eq!(
                engine
                    .authorize(&context, &wrong_method, &state)
                    .unwrap_err(),
                AuthorizationDenial::BootstrapDenied,
                "bootstrap method near miss authorized: {subject_name} {method:?} {resource_type}"
            );

            let mut wrong_resource_type = exact.clone();
            wrong_resource_type.targets[0].resource_type =
                ResourceTypeName::parse("Credential").unwrap();
            assert_eq!(
                engine
                    .authorize(&context, &wrong_resource_type, &state)
                    .unwrap_err(),
                AuthorizationDenial::BootstrapDenied,
                "bootstrap resource type near miss authorized: \
                 {subject_name} {method:?} {resource_type}"
            );

            let mut wrong_zone = exact;
            wrong_zone.zone = ZoneId::parse("personal").unwrap();
            assert_eq!(
                engine.authorize(&context, &wrong_zone, &state).unwrap_err(),
                AuthorizationDenial::ZoneMismatch,
                "bootstrap Zone near miss authorized: {subject_name} {method:?} {resource_type}"
            );
        }
    }

    #[test]
    fn bootstrap_zone_and_provider_names_are_compiled_in_both_phases() {
        let core_uid = "123e4567-e89b-42d3-a456-426614174000";
        let context = bootstrap_subject("system-core", core_uid);
        let engine =
            NativeAuthorizer::from_issuer(ApiCatalog::standard(), None, test_issuer()).unwrap();
        let phases = [
            BootstrapPhase::Unprovisioned {
                zone: ZoneId::parse("dev").unwrap(),
                controller_generation: ControllerGeneration::new(11).unwrap(),
                provider_generation: ResourceGeneration::new(12).unwrap(),
            },
            BootstrapPhase::Provisioned {
                zone: ZoneId::parse("dev").unwrap(),
                system_core_uid: ResourceUid::parse(core_uid).unwrap(),
                system_minijail_uid: ResourceUid::parse("123e4567-e89b-42d3-a456-426614174001")
                    .unwrap(),
                controller_generation: ControllerGeneration::new(11).unwrap(),
                provider_generation: ResourceGeneration::new(12).unwrap(),
            },
        ];

        for phase in phases {
            let state = bootstrap_state(phase);
            for resource_type in ["Zone", "Provider"] {
                let mut target = bootstrap_target(resource_type, ResourceVerb::Create);
                target.resource_name = Some(ResourceName::parse("attacker-selected").unwrap());
                let request = AuthorizationRequest {
                    method: ApiMethod::Create,
                    zone: ZoneId::parse("dev").unwrap(),
                    targets: vec![target],
                };
                assert_eq!(
                    engine.authorize(&context, &request, &state).unwrap_err(),
                    AuthorizationDenial::BootstrapDenied
                );
            }
        }
    }

    #[test]
    fn authorization_debug_surfaces_redact_policy_and_identity_fields() {
        const POLICY_REVISION_SENTINEL: u64 = 4_294_967_291;
        const ZONE_SENTINEL: &str = "authz-zone-sentinel";
        const NAME_SENTINEL: &str = "authz-name-sentinel";
        const REF_SENTINEL: &str = "authz-ref-sentinel";
        const UID_SENTINEL: &str = "33333333-3333-4333-8333-333333333333";
        const PAYLOAD_SENTINEL: &str = "authz-payload-sentinel";
        const TYPE_SENTINEL: &str = "authz-sentinel.d2bus.org.Widget";

        let extension = ResourceTypeName::parse(TYPE_SENTINEL).unwrap();
        let catalog = ApiCatalog::with_extensions([extension.clone()]).unwrap();
        let target = AuthorizationTarget {
            resource_type: extension.clone(),
            resource_name: Some(ResourceName::parse(NAME_SENTINEL).unwrap()),
            verb: ResourceVerb::Get,
            subresource: Some(PAYLOAD_SENTINEL.to_owned()),
            execution_ref: Some(ResourceRef::parse(&format!("Process/{REF_SENTINEL}")).unwrap()),
        };
        let request = AuthorizationRequest {
            method: ApiMethod::Get,
            zone: ZoneId::parse(ZONE_SENTINEL).unwrap(),
            targets: vec![target.clone()],
        };
        let mut protected_state = state(9);
        protected_state.bootstrap_phase = BootstrapPhase::Unprovisioned {
            zone: ZoneId::parse(ZONE_SENTINEL).unwrap(),
            controller_generation: ControllerGeneration::new(11).unwrap(),
            provider_generation: ResourceGeneration::new(12).unwrap(),
        };
        let bound_subject = BoundSubject {
            subject_ref: ResourceRef::parse(&format!("User/{REF_SENTINEL}")).unwrap(),
            subject_uid: ResourceUid::parse(UID_SENTINEL).unwrap(),
        };
        let scope = BindingScope {
            zones: BTreeSet::from([ZoneId::parse(ZONE_SENTINEL).unwrap()]),
            resource_names: BTreeSet::from([ResourceName::parse(NAME_SENTINEL).unwrap()]),
            execution_refs: BTreeSet::from([ResourceRef::parse(&format!(
                "Process/{REF_SENTINEL}"
            ))
            .unwrap()]),
        };
        let rule = PolicyRule::new(
            &catalog,
            [extension],
            [ResourceVerb::Get],
            [SessionVerb::Connect],
            [PAYLOAD_SENTINEL.to_owned()],
            [ResourceName::parse(NAME_SENTINEL).unwrap()],
            [ZoneId::parse(ZONE_SENTINEL).unwrap()],
            [ResourceRef::parse(&format!("Process/{REF_SENTINEL}")).unwrap()],
        )
        .unwrap();
        let role = CompiledRole::new(
            ResourceRef::parse(&format!("Role/{REF_SENTINEL}")).unwrap(),
            vec![rule.clone()],
        )
        .unwrap();
        let binding = CompiledRoleBinding::new(
            role.role_ref.clone(),
            [bound_subject.clone()],
            scope.clone(),
            RelayGrantAuthority::None,
        )
        .unwrap();
        let policy = PolicySet::new(
            &catalog,
            POLICY_REVISION_SENTINEL,
            vec![role.clone()],
            vec![binding.clone()],
        )
        .unwrap();
        assert_eq!(policy.policy_revision, POLICY_REVISION_SENTINEL);
        let capabilities = PositiveCapabilities {
            resources: vec![target.clone()],
            session_verbs: BTreeSet::from([SessionVerb::Connect]),
        };
        let context = subject(
            Locality::Local,
            EvidenceClass::UnixPeer,
            &format!("User/{REF_SENTINEL}"),
        );
        let grant = grant(
            &test_issuer(),
            &context,
            &request,
            protected_state.snapshot,
            protected_state.zone_policy_revision.get(),
        );
        let authorizer =
            NativeAuthorizer::from_issuer(catalog.clone(), Some(policy.clone()), test_issuer())
                .unwrap();

        let catalog_debug = format!(
            "ApiCatalog {{ resource_type_count: {} }}",
            catalog.resource_types.len()
        );
        assert_eq!(format!("{catalog:?}"), catalog_debug);
        assert_eq!(
            format!("{target:?}"),
            "AuthorizationTarget { verb: Get, resource_type: \"<redacted>\", \
             has_resource_name: true, has_subresource: true, has_execution_ref: true }"
        );
        assert_eq!(
            format!("{request:?}"),
            "AuthorizationRequest { method: Get, zone: \"<redacted>\", target_count: 1 }"
        );
        assert_eq!(
            format!("{protected_state:?}"),
            "AuthorizationState { snapshot: \"<redacted>\", \
             zone_policy_revision: \"<redacted>\", \
             bootstrap_phase: BootstrapPhase::Unprovisioned(<redacted>), \
             now_tick: \"<redacted>\" }"
        );
        assert_eq!(
            format!("{:?}", protected_state.bootstrap_phase),
            "BootstrapPhase::Unprovisioned(<redacted>)"
        );
        assert_eq!(format!("{bound_subject:?}"), "BoundSubject(<redacted>)");
        let scope_debug =
            "BindingScope { zone_count: 1, resource_name_count: 1, execution_ref_count: 1 }";
        assert_eq!(format!("{scope:?}"), scope_debug);
        assert_eq!(
            format!("{rule:?}"),
            "PolicyRule { resource_type_count: 1, resource_verb_count: 1, \
             session_verb_count: 1, subresource_count: 1, resource_name_count: 1, \
             zone_count: 1, execution_ref_count: 1 }"
        );
        assert_eq!(
            format!("{role:?}"),
            "CompiledRole { role_ref: \"<redacted>\", rule_count: 1 }"
        );
        assert_eq!(
            format!("{binding:?}"),
            format!(
                "CompiledRoleBinding {{ role_ref: \"<redacted>\", subject_count: 1, \
                 scope: {scope_debug}, relay_authority: None }}"
            )
        );
        assert_eq!(
            format!("{policy:?}"),
            format!(
                "PolicySet {{ policy_revision: \"<redacted>\", catalog: {catalog_debug}, \
                 role_count: 1, binding_count: 1 }}"
            )
        );
        assert_eq!(
            format!("{capabilities:?}"),
            "PositiveCapabilities { resource_count: 1, session_verb_count: 1 }"
        );
        assert_eq!(format!("{grant:?}"), "AuthorizationGrant(<redacted>)");
        assert_eq!(format!("{authorizer:?}"), "NativeAuthorizer(<redacted>)");
    }
}
