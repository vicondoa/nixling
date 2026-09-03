//! Build-time validation for one selected Provider artifact output.
//!
//! The compiler is intentionally split at the same boundary as the artifact
//! contract. [`compile_artifact`] consumes a directory that is already
//! anchored by the caller and only uses the injectable `d2b-core` artifact
//! traits below it. [`linux`] contains the production Linux adapter, while
//! tests can provide an in-memory adapter without creating a Nix store.
//!
//! A compiler diagnostic is a stable `d2b_core::error::Kind` plus a bounded
//! message. It never contains the selected store path, manifest bytes, config
//! bytes, key material, or process data.
//!
//! ```
//! let digest = d2b_resource_compiler::sha256_digest(b"provider");
//! assert_eq!(digest.as_str().len(), 71);
//! ```

use std::{
    collections::{BTreeMap, BTreeSet},
    convert::Infallible,
    fmt,
    path::{Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use d2b_contracts_provider::v3::{
    ArtifactDigest, ProviderManifest,
    provider::{
        BinaryRef, ComponentExecution, ComponentType, ControllerInstanceScope,
        ControllerTargetKind, EffectPortClass,
    },
};
use d2b_contracts_resource::v3::{
    ArtifactId, CanonicalJsonValue, ResourceName, ResourceRef, ResourceTypeName, ZoneId,
    canonical_digest, canonical_json_bytes,
    execution_policy::{BoundedToken, BudgetSpec, ExecutionDomain},
    process::{ExecutionSpec, ProcessClass, ProcessSpec, SandboxSpec, TelemetrySpec},
};
use d2b_contracts_zone_session::v3::resource_bundle::ProcessTemplateBinding;
use d2b_core::{
    error::Kind,
    provider_artifact::{
        AnchoredDir, Argv, Envp, LaunchError, LayoutDir, LayoutError, LayoutPath, ProcessLauncher,
        ReadableFile,
    },
};
use ring::signature::{ED25519, UnparsedPublicKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The fixed manifest path from ADR 0050 section 4.9.2.
pub const MANIFEST_PATH: &str = "share/d2b/provider/provider-manifest.json";
/// The fixed detached signature path from ADR 0050 section 4.9.2.
pub const SIGNATURE_PATH: &str = "share/d2b/provider/provider-manifest.json.sig";
/// The fixed root config schema path from ADR 0050 section 4.9.2.
pub const CONFIG_SCHEMA_PATH: &str = "share/d2b/provider/config-schema.json";
/// The closed directory containing the three required metadata files.
pub const PROVIDER_METADATA_DIR: &str = "share/d2b/provider";
/// The executable directory beneath one selected output.
pub const EXECUTABLE_DIR: &str = "bin";
/// The D101 domain tag for the canonical executable digest map.
pub const EXECUTABLE_SET_DOMAIN_TAG: &str = "d2b:v3:provider-executable-set";
/// The maximum diagnostic length required by the resource-plane contract.
pub const MAX_DIAGNOSTIC_BYTES: usize = 512;
const MAX_MANIFEST_BYTES: usize = 8 * 1024 * 1024;
const MAX_SCHEMA_BYTES: usize = 8 * 1024 * 1024;
const MAX_ENTRY_SAMPLE: usize = 4;
const MAX_ENTRY_BYTES: usize = 64;

/// The catalog values that are compared with the manifest and compiler
/// recomputations.
#[derive(Clone, PartialEq, Eq)]
pub struct CatalogDigests {
    package: ArtifactDigest,
    executable: ArtifactDigest,
    manifest: ArtifactDigest,
    config_schema: ArtifactDigest,
}

impl CatalogDigests {
    /// Construct the four Provider catalog digests used by Phase 2.
    pub const fn new(
        package: ArtifactDigest,
        executable: ArtifactDigest,
        manifest: ArtifactDigest,
        config_schema: ArtifactDigest,
    ) -> Self {
        Self {
            package,
            executable,
            manifest,
            config_schema,
        }
    }

    /// Return the catalog package content digest.
    pub const fn package(&self) -> &ArtifactDigest {
        &self.package
    }

    /// Return the catalog executable-set digest.
    pub const fn executable(&self) -> &ArtifactDigest {
        &self.executable
    }

    /// Return the catalog manifest digest.
    pub const fn manifest(&self) -> &ArtifactDigest {
        &self.manifest
    }

    /// Return the catalog config-schema digest.
    pub const fn config_schema(&self) -> &ArtifactDigest {
        &self.config_schema
    }
}

impl fmt::Debug for CatalogDigests {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CatalogDigests(<redacted>)")
    }
}

/// One catalog entry selecting exactly one Provider output.
///
/// The store path is retained only for the production adapter to open. It is
/// never copied into a diagnostic or a compiled result.
#[derive(Clone, PartialEq, Eq)]
pub struct ArtifactCatalogEntry {
    artifact_id: ArtifactId,
    store_path: PathBuf,
    publisher: String,
    signature_id: String,
    digests: CatalogDigests,
}

impl ArtifactCatalogEntry {
    /// Construct a catalog entry for one already-selected output.
    pub fn new(
        artifact_id: ArtifactId,
        store_path: impl Into<PathBuf>,
        publisher: impl Into<String>,
        signature_id: impl Into<String>,
        digests: CatalogDigests,
    ) -> Self {
        Self {
            artifact_id,
            store_path: store_path.into(),
            publisher: publisher.into(),
            signature_id: signature_id.into(),
            digests,
        }
    }

    /// Return the bounded artifact identifier.
    pub const fn artifact_id(&self) -> &ArtifactId {
        &self.artifact_id
    }

    /// Return the selected output path for the production adapter.
    pub fn store_path(&self) -> &Path {
        &self.store_path
    }

    /// Return the catalog publisher label.
    pub fn publisher(&self) -> &str {
        &self.publisher
    }

    /// Return the catalog signature identifier.
    pub fn signature_id(&self) -> &str {
        &self.signature_id
    }

    /// Return the catalog digest set.
    pub const fn digests(&self) -> &CatalogDigests {
        &self.digests
    }

    /// Replace the catalog digest set while retaining the selected output and
    /// its public trust labels.
    pub fn with_digests(mut self, digests: CatalogDigests) -> Self {
        self.digests = digests;
        self
    }
}

impl fmt::Debug for ArtifactCatalogEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactCatalogEntry")
            .field("artifact_id", &self.artifact_id)
            .field("publisher", &sanitize_token(&self.publisher))
            .field("signature_id", &sanitize_token(&self.signature_id))
            .field("digests", &self.digests)
            .finish_non_exhaustive()
    }
}

/// A public publisher-key lookup boundary.
///
/// Implementations return PEM SubjectPublicKeyInfo bytes for an Ed25519
/// verification key. Registration and signature-ID resolution are separate so
/// the compiler can report the four signature failure cases distinctly.
pub trait PublisherKeyResolver {
    /// Whether the publisher is registered in the selected Zone trust set.
    fn publisher_registered(&self, publisher: &str) -> bool;

    /// Resolve one signature identifier under a registered publisher.
    fn resolve_key<'a>(&'a self, publisher: &str, signature_id: &str) -> Option<&'a [u8]>;
}

/// A small in-memory public-key resolver useful for tests and embedding.
#[derive(Default)]
pub struct StaticPublisherKeys {
    registered: BTreeSet<String>,
    keys: BTreeMap<(String, String), Vec<u8>>,
}

impl StaticPublisherKeys {
    /// Register a publisher without adding a signature key.
    pub fn register_publisher(&mut self, publisher: impl Into<String>) {
        self.registered.insert(publisher.into());
    }

    /// Register one PEM SubjectPublicKeyInfo under a publisher and ID.
    pub fn insert_key(
        &mut self,
        publisher: impl Into<String>,
        signature_id: impl Into<String>,
        pem_spki: impl Into<Vec<u8>>,
    ) {
        let publisher = publisher.into();
        let signature_id = signature_id.into();
        self.registered.insert(publisher.clone());
        self.keys.insert((publisher, signature_id), pem_spki.into());
    }
}

impl PublisherKeyResolver for StaticPublisherKeys {
    fn publisher_registered(&self, publisher: &str) -> bool {
        self.registered.contains(publisher)
    }

    fn resolve_key<'a>(&'a self, publisher: &str, signature_id: &str) -> Option<&'a [u8]> {
        self.keys
            .get(&(publisher.to_owned(), signature_id.to_owned()))
            .map(Vec::as_slice)
    }
}

/// A bounded operator-facing compiler diagnostic.
#[derive(Clone, PartialEq, Eq)]
pub struct Diagnostic {
    kind: Kind,
    message: String,
}

impl Diagnostic {
    fn new(kind: Kind, message: impl AsRef<str>) -> Self {
        Self {
            kind,
            message: bound_message(message.as_ref()),
        }
    }

    /// Return the stable diagnostic kind.
    pub const fn kind(&self) -> Kind {
        self.kind
    }

    /// Return the reserved exit code for this diagnostic.
    pub const fn exit_code(&self) -> u8 {
        self.kind.exit_code()
    }

    /// Return the bounded, redacted message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Return the exact shared remediation for this diagnostic kind.
    pub const fn remediation(&self) -> &'static str {
        self.kind.remediation()
    }

    /// Return the stable kebab-case diagnostic code.
    pub const fn code(&self) -> &'static str {
        self.kind.as_str()
    }
}

impl fmt::Debug for Diagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Diagnostic")
            .field("kind", &self.kind)
            .field("message", &self.message)
            .finish()
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code(), self.message)
    }
}

impl std::error::Error for Diagnostic {}

/// The successfully verified, private compiler result.
#[derive(Clone, PartialEq, Eq)]
pub struct CompiledArtifact {
    artifact_id: ArtifactId,
    manifest: ProviderManifest,
    manifest_digest: ArtifactDigest,
    config_schema_digest: ArtifactDigest,
    config_schema_bytes: Vec<u8>,
    executable_digests: BTreeMap<String, ArtifactDigest>,
}

impl CompiledArtifact {
    /// Return the selected artifact identifier.
    pub const fn artifact_id(&self) -> &ArtifactId {
        &self.artifact_id
    }

    /// Return the verified signed manifest.
    pub const fn manifest(&self) -> &ProviderManifest {
        &self.manifest
    }

    /// Return the compiler digest of the raw manifest bytes.
    pub const fn manifest_digest(&self) -> &ArtifactDigest {
        &self.manifest_digest
    }

    /// Return the compiler digest of the canonical root config schema.
    pub const fn config_schema_digest(&self) -> &ArtifactDigest {
        &self.config_schema_digest
    }

    /// Return the verified canonical root config-schema bytes.
    pub fn config_schema_bytes(&self) -> &[u8] {
        &self.config_schema_bytes
    }

    /// Return the compiler digest for each enumerated executable.
    pub const fn executable_digests(&self) -> &BTreeMap<String, ArtifactDigest> {
        &self.executable_digests
    }
}

impl fmt::Debug for CompiledArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledArtifact")
            .field("artifact_id", &self.artifact_id)
            .field("manifest", &self.manifest)
            .field("manifest_digest", &self.manifest_digest)
            .field("config_schema_digest", &self.config_schema_digest)
            .field("executable_count", &self.executable_digests.len())
            .finish()
    }
}

/// One verified Provider artifact available to the static Process projector.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedProviderArtifact {
    artifact_id: ArtifactId,
    store_path: PathBuf,
    compiled: CompiledArtifact,
}

impl VerifiedProviderArtifact {
    /// Bind a verified compiler result to its selected package output.
    pub fn new(
        artifact_id: ArtifactId,
        store_path: impl Into<PathBuf>,
        compiled: CompiledArtifact,
    ) -> Self {
        Self {
            artifact_id,
            store_path: store_path.into(),
            compiled,
        }
    }

    /// Borrow the selected artifact ID.
    pub const fn artifact_id(&self) -> &ArtifactId {
        &self.artifact_id
    }

    /// Borrow the selected package output path.
    pub fn store_path(&self) -> &Path {
        &self.store_path
    }

    /// Borrow the verified artifact metadata.
    pub const fn compiled(&self) -> &CompiledArtifact {
        &self.compiled
    }
}

impl fmt::Debug for VerifiedProviderArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedProviderArtifact")
            .field("artifact_id", &self.artifact_id)
            .field("compiled", &self.compiled)
            .finish_non_exhaustive()
    }
}

/// Static controller resources and their private executable bindings.
#[derive(Clone, PartialEq, Eq)]
pub struct StaticControllerProjection {
    /// Ordinary Process resources to append to the Zone bundle.
    pub resources: Vec<serde_json::Value>,
    /// Private template metadata consumed by the generic Process resolver.
    pub templates: Vec<ProcessTemplateBinding>,
}

impl fmt::Debug for StaticControllerProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StaticControllerProjection")
            .field("resource_count", &self.resources.len())
            .field("template_count", &self.templates.len())
            .finish()
    }
}

/// Static controller projection refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaticControllerProjectionError {
    /// The Zone name is invalid.
    InvalidZone,
    /// A Provider resource did not have the expected identity/spec shape.
    InvalidProviderResource,
    /// The selected Provider artifact was not verified.
    VerifiedProviderMissing,
    /// A launchable controller had no explicit execution target.
    MissingControllerExecutionRef,
    /// The Provider controller execution reference was malformed.
    InvalidControllerExecutionRef,
    /// The target kind cannot host an ordinary Process.
    UnsupportedTargetKind,
    /// The controller execution target was not present in this bundle.
    ControllerTargetMissing,
    /// The manifest did not advertise the selected target for a component.
    ComponentTargetUnsupported,
    /// The signed binary was absent from the verified package.
    TemplateArtifactMissing,
    /// The signed target artifact differed from the verified package binary.
    ArtifactDigestMismatch,
    /// A generated Process identity collided with another resource.
    DuplicateProcessName,
    /// A generated template name could not be represented as a bounded token.
    InvalidTemplate,
    /// A generated Process spec could not be serialized.
    Serialization,
    /// A private template binding could not be constructed.
    TemplateBindingInvalid,
}

impl StaticControllerProjectionError {
    /// Stable compiler diagnostic code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidZone => "provider-controller-zone-invalid",
            Self::InvalidProviderResource => "provider-controller-provider-invalid",
            Self::VerifiedProviderMissing => "provider-controller-artifact-unverified",
            Self::MissingControllerExecutionRef => "provider-controller-execution-ref-missing",
            Self::InvalidControllerExecutionRef => "provider-controller-execution-ref-invalid",
            Self::UnsupportedTargetKind => "provider-controller-target-kind-unsupported",
            Self::ControllerTargetMissing => "provider-controller-target-missing",
            Self::ComponentTargetUnsupported => "provider-controller-target-unsupported",
            Self::TemplateArtifactMissing => "provider-controller-template-artifact-missing",
            Self::ArtifactDigestMismatch => "provider-controller-artifact-digest-mismatch",
            Self::DuplicateProcessName => "provider-controller-process-name-duplicate",
            Self::InvalidTemplate => "provider-controller-template-invalid",
            Self::Serialization => "provider-controller-process-serialization",
            Self::TemplateBindingInvalid => "provider-controller-template-binding-invalid",
        }
    }
}

impl fmt::Display for StaticControllerProjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for StaticControllerProjectionError {}

/// Project every admitted launchable Provider controller into an ordinary
/// Process resource and a private signed-package template binding.
///
/// The caller supplies only artifacts whose manifests have already passed the
/// signature, canonicality, and executable-set checks in [`compile_artifact`].
/// Bootstrap components remain in-process exceptions and are not projected.
pub fn project_static_controller_processes<'a, I>(
    zone: &str,
    resources: &[serde_json::Value],
    verified_artifacts: I,
) -> Result<StaticControllerProjection, StaticControllerProjectionError>
where
    I: IntoIterator<Item = &'a VerifiedProviderArtifact>,
{
    let zone_id =
        ZoneId::parse(zone.to_owned()).map_err(|_| StaticControllerProjectionError::InvalidZone)?;
    let mut artifacts = BTreeMap::new();
    for artifact in verified_artifacts {
        if artifacts
            .insert(artifact.artifact_id().as_str().to_owned(), artifact)
            .is_some()
        {
            return Err(StaticControllerProjectionError::VerifiedProviderMissing);
        }
    }

    let identities = resources
        .iter()
        .filter_map(resource_identity)
        .collect::<BTreeSet<_>>();
    let mut generated_identities = BTreeSet::new();
    let mut projected_resources = Vec::new();
    let mut templates = Vec::new();

    for resource in resources {
        if resource.get("type").and_then(serde_json::Value::as_str) != Some("Provider") {
            continue;
        }
        let provider_name = resource
            .get("metadata")
            .and_then(|metadata| metadata.get("name"))
            .and_then(serde_json::Value::as_str)
            .ok_or(StaticControllerProjectionError::InvalidProviderResource)?;
        if resource
            .get("metadata")
            .and_then(|metadata| metadata.get("zone"))
            .and_then(serde_json::Value::as_str)
            != Some(zone_id.as_str())
        {
            return Err(StaticControllerProjectionError::InvalidProviderResource);
        }
        let provider_ref = ResourceRef::parse(&format!("Provider/{provider_name}"))
            .map_err(|_| StaticControllerProjectionError::InvalidProviderResource)?;
        let spec = resource
            .get("spec")
            .and_then(serde_json::Value::as_object)
            .ok_or(StaticControllerProjectionError::InvalidProviderResource)?;
        let artifact_id = spec
            .get("artifactId")
            .and_then(serde_json::Value::as_str)
            .ok_or(StaticControllerProjectionError::InvalidProviderResource)?;
        let artifact = artifacts
            .get(artifact_id)
            .ok_or(StaticControllerProjectionError::VerifiedProviderMissing)?;
        if artifact.compiled().artifact_id().as_str() != artifact_id
            || artifact.compiled().manifest().artifact_id().as_str() != artifact_id
        {
            return Err(StaticControllerProjectionError::VerifiedProviderMissing);
        }
        if matches!(artifact_id, "system-core" | "system-minijail") {
            continue;
        }
        let launchable_controllers = artifact
            .compiled()
            .manifest()
            .components()
            .iter()
            .filter(|component| {
                component.component_type() == ComponentType::Controller
                    && component.execution().is_launchable()
            })
            .collect::<Vec<_>>();
        if launchable_controllers.is_empty() {
            continue;
        }

        let config = spec
            .get("config")
            .and_then(serde_json::Value::as_object)
            .ok_or(StaticControllerProjectionError::MissingControllerExecutionRef)?;
        let execution_ref = config
            .get("controllerExecutionRef")
            .ok_or(StaticControllerProjectionError::MissingControllerExecutionRef)?
            .as_str()
            .ok_or(StaticControllerProjectionError::InvalidControllerExecutionRef)?;
        let execution_ref = ResourceRef::parse(execution_ref)
            .map_err(|_| StaticControllerProjectionError::InvalidControllerExecutionRef)?;
        let target_kind = match execution_ref.resource_type().as_str() {
            "Host" => ControllerTargetKind::Host,
            "Guest" => ControllerTargetKind::Guest,
            _ => return Err(StaticControllerProjectionError::UnsupportedTargetKind),
        };
        if !identities.contains(&(
            execution_ref.resource_type().as_str().to_owned(),
            execution_ref.name().as_str().to_owned(),
        )) {
            return Err(StaticControllerProjectionError::ControllerTargetMissing);
        }

        for component in launchable_controllers {
            let scope = component
                .instance_scope()
                .ok_or(StaticControllerProjectionError::ComponentTargetUnsupported)?;
            if matches!(scope, ControllerInstanceScope::ZoneSingleton)
                || !component.supported_target_kinds().contains(&target_kind)
            {
                return Err(StaticControllerProjectionError::ComponentTargetUnsupported);
            }
            let capability = component
                .target_capability(target_kind)
                .ok_or(StaticControllerProjectionError::ComponentTargetUnsupported)?;
            if !capability
                .required_effect_classes()
                .contains(&EffectPortClass::Process)
            {
                return Err(StaticControllerProjectionError::ComponentTargetUnsupported);
            }
            let ComponentExecution::Launchable { binary_ref } = component.execution() else {
                continue;
            };
            let actual_digest = artifact
                .compiled()
                .executable_digests()
                .get(binary_ref.as_str())
                .ok_or(StaticControllerProjectionError::TemplateArtifactMissing)?;
            if actual_digest != capability.artifact_digest() {
                return Err(StaticControllerProjectionError::ArtifactDigestMismatch);
            }
            let template = static_controller_template_name(artifact_id, component)?;
            let process_name = static_controller_process_name(
                &zone_id,
                &provider_ref,
                component.component_id(),
                &execution_ref,
            )?;
            let process_ref = ResourceRef::new(
                ResourceTypeName::parse("Process")
                    .map_err(|_| StaticControllerProjectionError::InvalidTemplate)?,
                process_name,
            );
            let identity = ("Process".to_owned(), process_ref.name().as_str().to_owned());
            if !generated_identities.insert(identity.clone()) || identities.contains(&identity) {
                return Err(StaticControllerProjectionError::DuplicateProcessName);
            }
            projected_resources.push(static_controller_resource(
                &zone_id,
                &process_ref,
                &provider_ref,
                &execution_ref,
                &template,
            )?);
            let binary_path = artifact
                .store_path()
                .join(EXECUTABLE_DIR)
                .join(binary_ref.as_str());
            templates.push(
                ProcessTemplateBinding::new(
                    process_ref,
                    provider_ref.clone(),
                    execution_ref.clone(),
                    template,
                    artifact.artifact_id().clone(),
                    binary_ref.clone(),
                    actual_digest.clone(),
                    binary_path.to_string_lossy().into_owned(),
                )
                .map_err(|_| StaticControllerProjectionError::TemplateBindingInvalid)?,
            );
        }
    }

    append_managed_identity_agent_templates(
        &zone_id,
        resources,
        &artifacts,
        &mut generated_identities,
        &mut templates,
    )?;

    projected_resources
        .sort_by(|left, right| resource_sort_key(left).cmp(&resource_sort_key(right)));
    templates.sort_by(|left, right| {
        left.process_ref()
            .to_canonical_string()
            .cmp(&right.process_ref().to_canonical_string())
    });
    Ok(StaticControllerProjection {
        resources: projected_resources,
        templates,
    })
}

fn append_managed_identity_agent_templates<'a>(
    zone: &ZoneId,
    resources: &[serde_json::Value],
    artifacts: &BTreeMap<String, &'a VerifiedProviderArtifact>,
    generated_identities: &mut BTreeSet<(String, String)>,
    templates: &mut Vec<ProcessTemplateBinding>,
) -> Result<(), StaticControllerProjectionError> {
    let Some(provider) = resources.iter().find(|resource| {
        resource.get("type").and_then(Value::as_str) == Some("Provider")
            && resource
                .get("metadata")
                .and_then(|metadata| metadata.get("zone"))
                .and_then(Value::as_str)
                == Some(zone.as_str())
            && resource
                .get("metadata")
                .and_then(|metadata| metadata.get("name"))
                .and_then(Value::as_str)
                == Some("credential-managed-identity")
    }) else {
        return Ok(());
    };
    let provider_ref = ResourceRef::parse("Provider/credential-managed-identity")
        .map_err(|_| StaticControllerProjectionError::InvalidProviderResource)?;
    let artifact_id = provider
        .get("spec")
        .and_then(|spec| spec.get("artifactId"))
        .and_then(Value::as_str)
        .ok_or(StaticControllerProjectionError::InvalidProviderResource)?;
    let Some(artifact) = artifacts.get(artifact_id) else {
        return Ok(());
    };
    let binary_ref = BinaryRef::parse("d2b-managed-identity-agent")
        .map_err(|_| StaticControllerProjectionError::TemplateArtifactMissing)?;
    let Some(artifact_digest) = artifact.compiled().executable_digests().get(binary_ref.as_str())
    else {
        return Ok(());
    };
    let template = BoundedToken::parse("d2b-managed-identity-agent")
        .map_err(|_| StaticControllerProjectionError::InvalidTemplate)?;
    let target_refs = resources
        .iter()
        .filter_map(|resource| {
            let kind = resource.get("type").and_then(Value::as_str)?;
            if !matches!(kind, "Host" | "Guest")
                || resource
                    .get("metadata")
                    .and_then(|metadata| metadata.get("zone"))
                    .and_then(Value::as_str)
                    != Some(zone.as_str())
            {
                return None;
            }
            let name = resource
                .get("metadata")
                .and_then(|metadata| metadata.get("name"))
                .and_then(Value::as_str)?;
            ResourceRef::parse(&format!("{kind}/{name}")).ok()
        })
        .collect::<BTreeSet<_>>();
    for execution_ref in &target_refs {
        let process_ref = dynamic_agent_template_ref(execution_ref)?;
        let identity = ("Process".to_owned(), process_ref.name().as_str().to_owned());
        if !generated_identities.insert(identity.clone())
            || resources.iter().any(|candidate| {
                resource_identity(candidate).as_ref() == Some(&identity)
            })
        {
            return Err(StaticControllerProjectionError::DuplicateProcessName);
        }
        let binary_path = artifact
            .store_path()
            .join(EXECUTABLE_DIR)
            .join(binary_ref.as_str());
        templates.push(
            ProcessTemplateBinding::new_dynamic(
                process_ref,
                provider_ref.clone(),
                execution_ref.clone(),
                template.clone(),
                artifact.artifact_id().clone(),
                binary_ref.clone(),
                artifact_digest.clone(),
                binary_path.to_string_lossy().into_owned(),
            )
            .map_err(|_| StaticControllerProjectionError::TemplateBindingInvalid)?,
        );
    }
    Ok(())
}

fn dynamic_agent_template_ref(
    execution_ref: &ResourceRef,
) -> Result<ResourceRef, StaticControllerProjectionError> {
    let candidate = format!(
        "Process/d2b-mi-agent-template-{}-{}",
        execution_ref.resource_type().as_str().to_ascii_lowercase(),
        execution_ref.name().as_str()
    );
    if let Ok(process_ref) = ResourceRef::parse(&candidate) {
        return Ok(process_ref);
    }
    let digest = Sha256::digest(candidate.as_bytes());
    let suffix = digest
        .iter()
        .take(12)
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    ResourceRef::parse(&format!("Process/d2b-mi-agent-template-{suffix}"))
        .map_err(|_| StaticControllerProjectionError::InvalidTemplate)
}

fn resource_identity(resource: &serde_json::Value) -> Option<(String, String)> {
    Some((
        resource.get("type")?.as_str()?.to_owned(),
        resource.get("metadata")?.get("name")?.as_str()?.to_owned(),
    ))
}

/// Return the deterministic resource ordering key.
pub fn resource_sort_key(resource: &serde_json::Value) -> (String, String) {
    resource_identity(resource).unwrap_or_default()
}

fn static_controller_template_name(
    artifact_id: &str,
    component: &d2b_contracts_provider::v3::ComponentDescriptor,
) -> Result<BoundedToken, StaticControllerProjectionError> {
    let candidate = format!(
        "controller-{artifact_id}-{}",
        component.component_id().as_str()
    );
    if candidate.len() <= 63 {
        return BoundedToken::parse(candidate)
            .map_err(|_| StaticControllerProjectionError::InvalidTemplate);
    }
    let digest = Sha256::digest(candidate.as_bytes());
    let suffix = digest
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    BoundedToken::parse(format!("controller-{suffix}"))
        .map_err(|_| StaticControllerProjectionError::InvalidTemplate)
}

fn static_controller_process_name(
    zone: &ZoneId,
    provider_ref: &ResourceRef,
    component_id: &BoundedToken,
    execution_ref: &ResourceRef,
) -> Result<ResourceName, StaticControllerProjectionError> {
    let mut digest = Sha256::new();
    digest.update(b"d2b:v3:static-controller-process-v1");
    digest.update([0]);
    digest.update(zone.as_str().as_bytes());
    digest.update([0]);
    digest.update(provider_ref.to_canonical_string().as_bytes());
    digest.update([0]);
    digest.update(component_id.as_str().as_bytes());
    digest.update([0]);
    digest.update(execution_ref.to_canonical_string().as_bytes());
    let suffix = digest
        .finalize()
        .iter()
        .take(16)
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    ResourceName::parse(format!("controller-{suffix}"))
        .map_err(|_| StaticControllerProjectionError::InvalidTemplate)
}

fn static_controller_resource(
    zone: &ZoneId,
    process_ref: &ResourceRef,
    provider_ref: &ResourceRef,
    execution_ref: &ResourceRef,
    template: &BoundedToken,
) -> Result<serde_json::Value, StaticControllerProjectionError> {
    let execution = ExecutionSpec::new(
        execution_ref.clone(),
        Some(ExecutionDomain::System),
        None,
        ProcessClass::Controller,
        template.clone(),
        None,
        Vec::new(),
        Vec::new(),
        SandboxSpec::default(),
        BudgetSpec::default(),
        None,
        Vec::new(),
        TelemetrySpec::default(),
    )
    .map_err(|_| StaticControllerProjectionError::Serialization)?;
    let process = ProcessSpec::minimal(execution);
    let spec = serde_json::to_value(process)
        .map_err(|_| StaticControllerProjectionError::Serialization)?;
    let mut spec = spec
        .as_object()
        .cloned()
        .ok_or(StaticControllerProjectionError::Serialization)?;
    spec.insert(
        "providerRef".to_owned(),
        serde_json::Value::String("Provider/system-minijail".to_owned()),
    );
    Ok(serde_json::json!({
        "apiVersion": "resources.d2bus.org/v3",
        "type": "Process",
        "metadata": {
            "name": process_ref.name().as_str(),
            "zone": zone.as_str(),
            "ownerRef": provider_ref.to_canonical_string(),
        },
        "spec": spec,
    }))
}

/// Compile one already-anchored Provider output.
///
/// The method reads the detached signature and manifest before any other
/// artifact file, verifies the publisher signature, validates canonical bytes,
/// closes the metadata directory, and then validates the executable set.
pub fn compile_artifact<A, R>(
    entry: &ArtifactCatalogEntry,
    anchor: &A,
    keys: &R,
) -> Result<CompiledArtifact, Diagnostic>
where
    A: AnchoredDir,
    R: PublisherKeyResolver,
{
    compile_inner(entry, anchor, keys)
}

/// Alias with the resource-plane name used by the Phase 2 work item.
pub fn compile_provider_artifact<A, R>(
    entry: &ArtifactCatalogEntry,
    anchor: &A,
    keys: &R,
) -> Result<CompiledArtifact, Diagnostic>
where
    A: AnchoredDir,
    R: PublisherKeyResolver,
{
    compile_artifact(entry, anchor, keys)
}

/// Open the selected output with the production Linux adapter and compile it.
#[cfg(target_os = "linux")]
pub fn compile_linux_artifact<R>(
    entry: &ArtifactCatalogEntry,
    keys: &R,
) -> Result<CompiledArtifact, Diagnostic>
where
    R: PublisherKeyResolver,
{
    let anchor =
        linux::LinuxAnchoredDir::open(entry.store_path()).map_err(|error| match error {
            linux::AnchorError::Absent => Diagnostic::new(
                Kind::ProviderRequiredOutputAbsent,
                format!(
                    "provider artifact {} is missing required output {}",
                    artifact_name(entry),
                    MANIFEST_PATH
                ),
            ),
            linux::AnchorError::NotDirectory
            | linux::AnchorError::Refused
            | linux::AnchorError::Io => Diagnostic::new(
                Kind::ProviderRequiredOutputNotRegular,
                format!(
                    "provider artifact {} output {} is not a regular file (selected-output)",
                    artifact_name(entry),
                    MANIFEST_PATH
                ),
            ),
        })?;
    compile_artifact(entry, &anchor, keys)
}

/// Compute a raw SHA-256 artifact digest in the contract spelling.
pub fn sha256_digest(bytes: &[u8]) -> ArtifactDigest {
    let digest = Sha256::digest(bytes);
    digest_to_artifact_digest(&digest)
}

/// Compute the D101 digest over a complete executable name-to-digest map.
pub fn executable_set_digest(
    executable_digests: &BTreeMap<String, ArtifactDigest>,
) -> Result<ArtifactDigest, d2b_contracts_resource::v3::CanonicalJsonError> {
    let object: BTreeMap<String, String> = executable_digests
        .iter()
        .map(|(name, digest)| (name.clone(), digest.as_str().to_owned()))
        .collect();
    let bytes = canonical_json_bytes(&object)?;
    Ok(
        ArtifactDigest::parse(canonical_digest(EXECUTABLE_SET_DOMAIN_TAG, &bytes))
            .expect("canonical_digest always returns a contract digest"),
    )
}

/// Launch a verified component through an anchored executable descriptor.
///
/// This is the runtime half of the same path rule. It is kept here so the
/// open-time `ENOENT` and exec-time interpreter `ENOENT` remain distinct.
pub fn launch_component<A, L>(
    entry: &ArtifactCatalogEntry,
    component_id: &str,
    execution: &ComponentExecution,
    anchor: &A,
    launcher: &L,
    argv: &Argv,
    envp: &Envp,
) -> Result<Infallible, Diagnostic>
where
    A: AnchoredDir<Executable = L::Executable>,
    L: ProcessLauncher,
{
    let Some(binary_ref) = execution.binary_ref() else {
        return Err(component_execution_invalid(entry, component_id));
    };
    let path = format!("{EXECUTABLE_DIR}/{}", binary_ref.as_str());
    let executable = anchor
        .open_executable(LayoutPath::new(path.clone()))
        .map_err(|error| launcher_layout_error(entry, component_id, &path, error))?;
    launcher
        .exec_from(executable, argv, envp)
        .map_err(|error| launch_error(entry, component_id, binary_ref, error))
}

fn compile_inner<A, R>(
    entry: &ArtifactCatalogEntry,
    anchor: &A,
    keys: &R,
) -> Result<CompiledArtifact, Diagnostic>
where
    A: AnchoredDir,
    R: PublisherKeyResolver,
{
    let signature = open_bytes(
        anchor,
        SIGNATURE_PATH,
        64,
        entry,
        Kind::ProviderRequiredOutputNotRegular,
    )?;
    if signature.len() != 64 {
        return Err(Diagnostic::new(
            Kind::ProviderSignatureMalformed,
            format!(
                "provider artifact {} signature has {} bytes; expected 64",
                artifact_name(entry),
                signature.len()
            ),
        ));
    }

    let manifest_bytes = open_bytes(
        anchor,
        MANIFEST_PATH,
        MAX_MANIFEST_BYTES,
        entry,
        Kind::ProviderRequiredOutputNotRegular,
    )?;
    if !keys.publisher_registered(entry.publisher()) {
        return Err(Diagnostic::new(
            Kind::ProviderSignaturePublisherUnregistered,
            format!(
                "provider artifact {} publisher {} is not registered; register the public \
                 publisher key at d2b.zones.<zone>.trustedPublishers.{} or use a registered \
                 publisher",
                artifact_name(entry),
                safe_label(entry.publisher()),
                safe_label(entry.publisher())
            ),
        ));
    }
    let Some(public_key) = keys.resolve_key(entry.publisher(), entry.signature_id()) else {
        return Err(Diagnostic::new(
            Kind::ProviderSignatureIdUnresolvable,
            format!(
                "provider artifact {} signature {} cannot be resolved for publisher {}",
                artifact_name(entry),
                safe_label(entry.signature_id()),
                safe_label(entry.publisher())
            ),
        ));
    };
    if !verify_ed25519(public_key, &manifest_bytes, &signature) {
        return Err(Diagnostic::new(
            Kind::ProviderSignatureVerificationFailed,
            format!(
                "provider artifact {} signature verification failed for {}",
                artifact_name(entry),
                safe_label(entry.signature_id())
            ),
        ));
    }

    let manifest_digest = sha256_digest(&manifest_bytes);
    let manifest = parse_canonical_manifest(entry, &manifest_bytes)?;
    manifest.validate_installation_contract().map_err(|_| {
        Diagnostic::new(
            Kind::ProviderComponentExecutionInvalid,
            format!(
                "provider artifact {} has an invalid manifest installation contract",
                artifact_name(entry)
            ),
        )
    })?;
    compare_digest(
        entry,
        "manifest",
        "catalog",
        entry.digests().manifest(),
        "compiler",
        &manifest_digest,
    )?;
    if manifest.artifact_id() != entry.artifact_id() {
        return Err(digest_mismatch(
            entry,
            "artifact-id",
            "catalog",
            entry.artifact_id().as_str(),
            "manifest",
            manifest.artifact_id().as_str(),
        ));
    }
    if manifest.trust().publisher.as_str() != entry.publisher() {
        return Err(Diagnostic::new(
            Kind::ProviderSignatureVerificationFailed,
            format!(
                "provider artifact {} signature verification failed for {}",
                artifact_name(entry),
                safe_label(entry.signature_id())
            ),
        ));
    }

    let schema_bytes = open_bytes(
        anchor,
        CONFIG_SCHEMA_PATH,
        MAX_SCHEMA_BYTES,
        entry,
        Kind::ProviderRequiredOutputNotRegular,
    )?;
    let config_schema_digest = sha256_digest(&schema_bytes);
    compare_digest(
        entry,
        "config-schema",
        "catalog",
        entry.digests().config_schema(),
        "compiler",
        &config_schema_digest,
    )?;
    compare_digest(
        entry,
        "config-schema",
        "manifest",
        &manifest.digests().config,
        "compiler",
        &config_schema_digest,
    )?;
    ensure_canonical_schema(entry, &schema_bytes)?;

    let metadata_entries = anchor
        .entries(LayoutDir::new(PROVIDER_METADATA_DIR))
        .map_err(|error| metadata_directory_error(entry, error))?;
    check_metadata_closure(entry, metadata_entries)?;

    let raw_manifest: Value = serde_json::from_slice(&manifest_bytes).map_err(|_| {
        Diagnostic::new(
            Kind::ProviderManifestNotCanonical,
            canonical_message(entry, MANIFEST_PATH, 0, 0, manifest_bytes.len()),
        )
    })?;
    let declared_executables = declared_executable_digests(entry, &raw_manifest)?;
    let (executable_digests, executable_exists) =
        validate_executables(entry, anchor, &manifest, declared_executables)?;

    if executable_exists
        != manifest
            .components()
            .iter()
            .any(|component| matches!(component.execution(), ComponentExecution::Launchable { .. }))
    {
        return Err(Diagnostic::new(
            Kind::ProviderExecutableDeclarationInconsistent,
            format!(
                "provider artifact {} has an inconsistent executable declaration \
                 (launchable-components={}, executable-set={})",
                artifact_name(entry),
                manifest
                    .components()
                    .iter()
                    .filter(|component| {
                        matches!(component.execution(), ComponentExecution::Launchable { .. })
                    })
                    .count(),
                executable_digests.len()
            ),
        ));
    }

    let executable_digest = executable_set_digest(&executable_digests).map_err(|_| {
        Diagnostic::new(
            Kind::ProviderExecutableSetMismatch,
            format!(
                "provider artifact {} executable set differs (canonicalization failed)",
                artifact_name(entry)
            ),
        )
    })?;
    compare_digest(
        entry,
        "executable-set",
        "catalog",
        entry.digests().executable(),
        "compiler",
        &executable_digest,
    )?;
    compare_digest(
        entry,
        "executable-set",
        "manifest",
        &manifest.digests().executable,
        "compiler",
        &executable_digest,
    )?;

    Ok(CompiledArtifact {
        artifact_id: entry.artifact_id().clone(),
        manifest,
        manifest_digest,
        config_schema_digest,
        config_schema_bytes: schema_bytes,
        executable_digests,
    })
}

fn open_bytes<A: AnchoredDir>(
    anchor: &A,
    path: &str,
    max_len: usize,
    entry: &ArtifactCatalogEntry,
    fallback_kind: Kind,
) -> Result<Vec<u8>, Diagnostic> {
    let file = anchor
        .open_readable(LayoutPath::new(path))
        .map_err(|error| required_file_error(entry, path, error, fallback_kind))?;
    let len = usize::try_from(file.len()).unwrap_or(usize::MAX);
    if len > max_len {
        return Err(Diagnostic::new(
            Kind::ProviderRequiredOutputNotRegular,
            format!(
                "provider artifact {} output {} is not a regular file (bounded-size)",
                artifact_name(entry),
                path
            ),
        ));
    }
    let mut file = file;
    let mut bytes = vec![0_u8; len];
    let read = file
        .read_prefix(&mut bytes)
        .map_err(|error| required_file_error(entry, path, error, fallback_kind))?;
    if read != len {
        return Err(Diagnostic::new(
            Kind::ProviderRequiredOutputNotRegular,
            format!(
                "provider artifact {} output {} is not a regular file (short-read)",
                artifact_name(entry),
                path
            ),
        ));
    }
    file.read_to_digest()
        .map_err(|error| required_file_error(entry, path, error, fallback_kind))?;
    Ok(bytes)
}

fn parse_canonical_manifest(
    entry: &ArtifactCatalogEntry,
    bytes: &[u8],
) -> Result<ProviderManifest, Diagnostic> {
    let manifest = serde_json::from_slice::<ProviderManifest>(bytes).map_err(|_| {
        Diagnostic::new(
            Kind::ProviderManifestNotCanonical,
            canonical_message(entry, MANIFEST_PATH, 0, 0, bytes.len()),
        )
    })?;
    let expected = canonical_json_bytes(&manifest).map_err(|_| {
        Diagnostic::new(
            Kind::ProviderManifestNotCanonical,
            canonical_message(entry, MANIFEST_PATH, 0, 0, bytes.len()),
        )
    })?;
    if expected != bytes {
        let offset = first_mismatch(&expected, bytes);
        return Err(Diagnostic::new(
            Kind::ProviderManifestNotCanonical,
            canonical_message(entry, MANIFEST_PATH, offset, expected.len(), bytes.len()),
        ));
    }
    Ok(manifest)
}

fn ensure_canonical_schema(entry: &ArtifactCatalogEntry, bytes: &[u8]) -> Result<(), Diagnostic> {
    let value = CanonicalJsonValue::parse(bytes).map_err(|_| {
        Diagnostic::new(
            Kind::ProviderManifestNotCanonical,
            canonical_message(entry, CONFIG_SCHEMA_PATH, 0, 0, bytes.len()),
        )
    })?;
    let expected = canonical_json_bytes(&value).map_err(|_| {
        Diagnostic::new(
            Kind::ProviderManifestNotCanonical,
            canonical_message(entry, CONFIG_SCHEMA_PATH, 0, 0, bytes.len()),
        )
    })?;
    if expected != bytes {
        let offset = first_mismatch(&expected, bytes);
        return Err(Diagnostic::new(
            Kind::ProviderManifestNotCanonical,
            canonical_message(
                entry,
                CONFIG_SCHEMA_PATH,
                offset,
                expected.len(),
                bytes.len(),
            ),
        ));
    }
    Ok(())
}

fn check_metadata_closure(
    entry: &ArtifactCatalogEntry,
    entries: Vec<std::ffi::OsString>,
) -> Result<(), Diagnostic> {
    let expected = BTreeSet::from([
        "config-schema.json",
        "provider-manifest.json",
        "provider-manifest.json.sig",
    ]);
    let mut unexpected = Vec::new();
    for entry_name in entries {
        let Some(name) = entry_name.to_str() else {
            unexpected.push("<non-utf8>".to_owned());
            continue;
        };
        if !expected.contains(name) {
            unexpected.push(truncate_entry(name));
        }
    }
    if unexpected.is_empty() {
        return Ok(());
    }
    unexpected.sort();
    Err(Diagnostic::new(
        Kind::ProviderLayoutEntryUnexpected,
        format!(
            "provider artifact {} has unexpected layout entries [{}] ({} total); remove \
             unpinned entries from share/d2b/provider and rebuild",
            artifact_name(entry),
            unexpected
                .iter()
                .take(MAX_ENTRY_SAMPLE)
                .map(|name| format!("entry={name}"))
                .collect::<Vec<_>>()
                .join(","),
            unexpected.len()
        ),
    ))
}

fn declared_executable_digests(
    entry: &ArtifactCatalogEntry,
    value: &Value,
) -> Result<Option<BTreeMap<String, ArtifactDigest>>, Diagnostic> {
    let candidate = value
        .get("package")
        .and_then(|package| package.get("executableDigests"))
        .or_else(|| {
            value
                .get("digests")
                .and_then(|digests| digests.get("executableDigests"))
        });
    let Some(candidate) = candidate else {
        return Ok(None);
    };
    let Some(object) = candidate.as_object() else {
        return Err(executable_set_mismatch(entry, &[], 1));
    };
    let mut result = BTreeMap::new();
    for (name, value) in object {
        let Some(digest) = value.as_str() else {
            return Err(digest_mismatch(
                entry,
                "executable",
                "manifest",
                "<invalid>",
                "compiler",
                "<invalid>",
            ));
        };
        let digest = ArtifactDigest::parse(digest).map_err(|_| {
            digest_mismatch(
                entry,
                "executable",
                "manifest",
                "<invalid>",
                "compiler",
                "<invalid>",
            )
        })?;
        result.insert(name.clone(), digest);
    }
    Ok(Some(result))
}

fn validate_executables<A: AnchoredDir>(
    entry: &ArtifactCatalogEntry,
    anchor: &A,
    manifest: &ProviderManifest,
    declared: Option<BTreeMap<String, ArtifactDigest>>,
) -> Result<(BTreeMap<String, ArtifactDigest>, bool), Diagnostic> {
    let bin_entries = match anchor.entries(LayoutDir::new(EXECUTABLE_DIR)) {
        Ok(entries) => Some(entries),
        Err(LayoutError::Absent) => None,
        Err(error) => {
            return Err(executable_file_error(entry, "bin/", error, "directory"));
        }
    };
    let Some(bin_entries) = bin_entries else {
        let launchable_count = manifest
            .components()
            .iter()
            .filter(|component| {
                matches!(component.execution(), ComponentExecution::Launchable { .. })
            })
            .count();
        for component in manifest.components() {
            if let ComponentExecution::InProcessBootstrap = component.execution()
                && !is_bootstrap_artifact(entry)
            {
                return Err(component_execution_invalid(
                    entry,
                    component.component_id().as_str(),
                ));
            }
        }
        if launchable_count != 0 {
            return Err(Diagnostic::new(
                Kind::ProviderExecutableDeclarationInconsistent,
                format!(
                    "provider artifact {} has an inconsistent executable declaration \
                     (launchable-components={}, executable-set=0)",
                    artifact_name(entry),
                    launchable_count
                ),
            ));
        }
        ensure_component_refs(entry, manifest, &BTreeSet::new(), declared.as_ref())?;
        if let Some(ref declared) = declared
            && !declared.is_empty()
        {
            return Err(executable_set_mismatch(
                entry,
                &declared.keys().cloned().collect::<Vec<_>>(),
                declared.len(),
            ));
        }
        return Ok((BTreeMap::new(), false));
    };

    let launchable_count = manifest
        .components()
        .iter()
        .filter(|component| matches!(component.execution(), ComponentExecution::Launchable { .. }))
        .count();
    for component in manifest.components() {
        if let ComponentExecution::InProcessBootstrap = component.execution()
            && !is_bootstrap_artifact(entry)
        {
            return Err(component_execution_invalid(
                entry,
                component.component_id().as_str(),
            ));
        }
    }
    if bin_entries.is_empty() && launchable_count != 0 {
        return Err(Diagnostic::new(
            Kind::ProviderExecutableDeclarationInconsistent,
            format!(
                "provider artifact {} has an inconsistent executable declaration \
                 (launchable-components={}, executable-set=0)",
                artifact_name(entry),
                launchable_count
            ),
        ));
    }
    if bin_entries.is_empty() {
        return Err(Diagnostic::new(
            Kind::ProviderExecutableSetEmpty,
            format!(
                "provider artifact {} has an empty executable set; remove bin/ and declare an \
                 empty executable set, or install a launchable ELF and declare its digest",
                artifact_name(entry)
            ),
        ));
    }

    let mut names = BTreeSet::new();
    for entry_name in &bin_entries {
        let Some(name) = entry_name.to_str() else {
            return Err(invalid_executable_name(entry, "<non-utf8>"));
        };
        if BinaryRef::parse(name.to_owned()).is_err() {
            return Err(invalid_executable_name(entry, name));
        }
        names.insert(name.to_owned());
    }

    if let Some(declared) = declared.as_ref() {
        let declared_names: BTreeSet<_> = declared.keys().cloned().collect();
        if names != declared_names {
            let mut difference = Vec::new();
            for name in names.difference(&declared_names) {
                difference.push(format!("bin={}", truncate_entry(name)));
            }
            for name in declared_names.difference(&names) {
                difference.push(format!("manifest={}", truncate_entry(name)));
            }
            return Err(executable_set_mismatch(
                entry,
                &difference,
                difference.len(),
            ));
        }
    }

    let mut actual = BTreeMap::new();
    for name in &names {
        let path = format!("{EXECUTABLE_DIR}/{name}");
        let mut file = anchor
            .open_readable(LayoutPath::new(path.clone()))
            .map_err(|error| executable_file_error(entry, name, error, "entry"))?;
        let mut prefix = [0_u8; 18];
        let read = file
            .read_prefix(&mut prefix)
            .map_err(|error| executable_file_error(entry, name, error, "entry"))?;
        if !supported_elf(&prefix, read) {
            return Err(Diagnostic::new(
                Kind::ProviderExecutableNotElf,
                format!(
                    "provider artifact {} executable {} is not a supported ELF image \
                     (magic={}); package interpreted entry points with \
                     d2b.lib.buildProviderElfShim and rebuild",
                    artifact_name(entry),
                    truncate_entry(name),
                    magic_hex(&prefix[..read.min(4)])
                ),
            ));
        }
        let digest = file
            .read_to_digest()
            .map_err(|error| executable_file_error(entry, name, error, "entry"))?;
        actual.insert(name.clone(), digest_to_artifact_digest(&digest));
    }

    if let Some(ref declared) = declared {
        for (name, expected) in declared {
            let Some(actual_digest) = actual.get(name) else {
                continue;
            };
            if actual_digest != expected {
                return Err(digest_mismatch(
                    entry,
                    &format!("executable:{name}"),
                    "manifest",
                    expected.as_str(),
                    "compiler",
                    actual_digest.as_str(),
                ));
            }
        }
    }
    ensure_component_refs(entry, manifest, &names, declared.as_ref())?;
    Ok((actual, true))
}

fn ensure_component_refs(
    entry: &ArtifactCatalogEntry,
    manifest: &ProviderManifest,
    actual_names: &BTreeSet<String>,
    declared: Option<&BTreeMap<String, ArtifactDigest>>,
) -> Result<(), Diagnostic> {
    for component in manifest.components() {
        match component.execution() {
            ComponentExecution::Launchable { binary_ref } => {
                if !actual_names.contains(binary_ref.as_str())
                    || declared.is_some_and(|declared| !declared.contains_key(binary_ref.as_str()))
                {
                    return Err(Diagnostic::new(
                        Kind::ProviderBinaryRefUnresolved,
                        format!(
                            "provider artifact {} component {} references unknown binary {}",
                            artifact_name(entry),
                            safe_label(component.component_id().as_str()),
                            safe_label(binary_ref.as_str())
                        ),
                    ));
                }
            }
            ComponentExecution::InProcessBootstrap if !is_bootstrap_artifact(entry) => {
                return Err(component_execution_invalid(
                    entry,
                    component.component_id().as_str(),
                ));
            }
            ComponentExecution::InProcessBootstrap => {}
        }
    }
    Ok(())
}

fn compare_digest(
    entry: &ArtifactCatalogEntry,
    digest_name: &str,
    source_a: &str,
    value_a: &ArtifactDigest,
    source_b: &str,
    value_b: &ArtifactDigest,
) -> Result<(), Diagnostic> {
    if value_a == value_b {
        Ok(())
    } else {
        Err(digest_mismatch(
            entry,
            digest_name,
            source_a,
            value_a.as_str(),
            source_b,
            value_b.as_str(),
        ))
    }
}

fn digest_mismatch(
    entry: &ArtifactCatalogEntry,
    digest_name: &str,
    source_a: &str,
    value_a: &str,
    source_b: &str,
    value_b: &str,
) -> Diagnostic {
    Diagnostic::new(
        Kind::ProviderDigestMismatch,
        format!(
            "provider artifact {} digest {} differs between {} ({}) and {} ({})",
            artifact_name(entry),
            safe_label(digest_name),
            source_a,
            safe_label(value_a),
            source_b,
            safe_label(value_b)
        ),
    )
}

fn required_file_error(
    entry: &ArtifactCatalogEntry,
    path: &str,
    error: LayoutError,
    fallback_kind: Kind,
) -> Diagnostic {
    match error {
        LayoutError::Absent => Diagnostic::new(
            Kind::ProviderRequiredOutputAbsent,
            format!(
                "provider artifact {} is missing required output {}",
                artifact_name(entry),
                path
            ),
        ),
        LayoutError::NotRegular
        | LayoutError::SymlinkRefused
        | LayoutError::NotBeneath
        | LayoutError::NoDevice
        | LayoutError::NotExecutable
        | LayoutError::NotElf => Diagnostic::new(
            fallback_kind,
            format!(
                "provider artifact {} output {} is not a regular file ({})",
                artifact_name(entry),
                path,
                error.code()
            ),
        ),
    }
}

fn metadata_directory_error(entry: &ArtifactCatalogEntry, error: LayoutError) -> Diagnostic {
    match error {
        LayoutError::Absent => Diagnostic::new(
            Kind::ProviderRequiredOutputAbsent,
            format!(
                "provider artifact {} is missing required output {}",
                artifact_name(entry),
                MANIFEST_PATH
            ),
        ),
        _ => Diagnostic::new(
            Kind::ProviderRequiredOutputNotRegular,
            format!(
                "provider artifact {} output {} is not a regular file ({})",
                artifact_name(entry),
                PROVIDER_METADATA_DIR,
                error.code()
            ),
        ),
    }
}

fn executable_file_error(
    entry: &ArtifactCatalogEntry,
    name: &str,
    error: LayoutError,
    file_type: &str,
) -> Diagnostic {
    match error {
        LayoutError::NotExecutable => Diagnostic::new(
            Kind::ProviderExecutableNotExecutable,
            format!(
                "provider artifact {} executable {} has no execute bit (mode=execute-bit-missing)",
                artifact_name(entry),
                truncate_entry(name)
            ),
        ),
        LayoutError::NotElf => Diagnostic::new(
            Kind::ProviderExecutableNotElf,
            format!(
                "provider artifact {} executable {} is not a supported ELF image \
                 (magic=unknown); package interpreted entry points with \
                 d2b.lib.buildProviderElfShim and rebuild",
                artifact_name(entry),
                truncate_entry(name)
            ),
        ),
        _ => Diagnostic::new(
            Kind::ProviderExecutableNotRegular,
            format!(
                "provider artifact {} executable {} is not a regular file ({})",
                artifact_name(entry),
                truncate_entry(name),
                if file_type.is_empty() {
                    error.code()
                } else {
                    file_type
                }
            ),
        ),
    }
}

fn invalid_executable_name(entry: &ArtifactCatalogEntry, name: &str) -> Diagnostic {
    Diagnostic::new(
        Kind::ProviderExecutableNameInvalid,
        format!(
            "provider artifact {} executable name {} is invalid; use a UTF-8 executable \
             name matching ^[a-z][a-z0-9-]*$ and rebuild",
            artifact_name(entry),
            truncate_entry(name)
        ),
    )
}

fn executable_set_mismatch(
    entry: &ArtifactCatalogEntry,
    differences: &[String],
    count: usize,
) -> Diagnostic {
    let mut samples: Vec<_> = differences
        .iter()
        .map(|value| truncate_entry(value))
        .collect();
    samples.sort();
    Diagnostic::new(
        Kind::ProviderExecutableSetMismatch,
        format!(
            "provider artifact {} executable set differs ({} entries: {})",
            artifact_name(entry),
            count,
            samples
                .iter()
                .take(MAX_ENTRY_SAMPLE)
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(",")
        ),
    )
}

fn launcher_layout_error(
    entry: &ArtifactCatalogEntry,
    component_id: &str,
    path: &str,
    error: LayoutError,
) -> Diagnostic {
    match error {
        LayoutError::Absent => Diagnostic::new(
            Kind::ProviderRequiredOutputAbsent,
            format!(
                "provider artifact {} is missing required output {}",
                artifact_name(entry),
                path
            ),
        ),
        _ => Diagnostic::new(
            Kind::ProviderRequiredOutputNotRegular,
            format!(
                "provider artifact {} output {} is not a regular file ({}) for component {}",
                artifact_name(entry),
                path,
                error.code(),
                safe_label(component_id)
            ),
        ),
    }
}

fn launch_error(
    entry: &ArtifactCatalogEntry,
    component_id: &str,
    binary_ref: &BinaryRef,
    error: LaunchError,
) -> Diagnostic {
    let (kind, errno) = match error {
        LaunchError::FormatRejected => (Kind::ProviderLaunchFormatRejected, "ENOEXEC"),
        LaunchError::PermissionDenied => (Kind::ProviderLaunchPermissionDenied, "EACCES"),
        LaunchError::InterpreterUnresolvable => (Kind::ProviderLaunchFormatRejected, "ENOENT"),
    };
    Diagnostic::new(
        kind,
        format!(
            "provider artifact {} component {} binary {} was rejected by the kernel ({})",
            artifact_name(entry),
            safe_label(component_id),
            safe_label(binary_ref.as_str()),
            errno
        ),
    )
}

fn component_execution_invalid(entry: &ArtifactCatalogEntry, component_id: &str) -> Diagnostic {
    Diagnostic::new(
        Kind::ProviderComponentExecutionInvalid,
        format!(
            "provider artifact {} component {} has an invalid execution declaration; name the \
             component binary or remove the component when it is not launchable",
            artifact_name(entry),
            safe_label(component_id)
        ),
    )
}

fn is_bootstrap_artifact(entry: &ArtifactCatalogEntry) -> bool {
    matches!(
        entry.artifact_id().as_str(),
        "system-core" | "system-minijail"
    )
}

fn canonical_message(
    entry: &ArtifactCatalogEntry,
    path: &str,
    offset: usize,
    expected_len: usize,
    observed_len: usize,
) -> String {
    format!(
        "provider artifact {} output {} is not canonical at byte {} (expected {} bytes, \
         observed {} bytes); run d2b-provider-toolkit manifest emit --out <path>, then \
         d2b-provider-toolkit manifest verify <path>, and rebuild",
        artifact_name(entry),
        path,
        offset,
        expected_len,
        observed_len
    )
}

fn first_mismatch(expected: &[u8], observed: &[u8]) -> usize {
    expected
        .iter()
        .zip(observed)
        .position(|(left, right)| left != right)
        .unwrap_or_else(|| expected.len().min(observed.len()))
}

fn supported_elf(prefix: &[u8; 18], length: usize) -> bool {
    if length < 18 || prefix[..4] != [0x7f, b'E', b'L', b'F'] {
        return false;
    }
    if prefix[4] != 2 || prefix[6] != 1 {
        return false;
    }
    let expected_data = if cfg!(target_endian = "little") { 1 } else { 2 };
    if prefix[5] != expected_data {
        return false;
    }
    let object_type = if prefix[5] == 1 {
        u16::from_le_bytes([prefix[16], prefix[17]])
    } else {
        u16::from_be_bytes([prefix[16], prefix[17]])
    };
    matches!(object_type, 2 | 3)
}

fn verify_ed25519(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Some(public_key) = decode_ed25519_spki(public_key) else {
        return false;
    };
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(message, signature)
        .is_ok()
}

fn decode_ed25519_spki(pem: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(pem).ok()?;
    let mut lines = text.lines();
    if lines.next()? != "-----BEGIN PUBLIC KEY-----" {
        return None;
    }
    let mut encoded = String::new();
    let mut found_end = false;
    for line in lines {
        if line == "-----END PUBLIC KEY-----" {
            found_end = true;
            break;
        }
        encoded.push_str(line.trim());
    }
    if !found_end {
        return None;
    }
    let der = STANDARD.decode(encoded).ok()?;
    decode_spki_der(&der)
}

fn decode_spki_der(der: &[u8]) -> Option<Vec<u8>> {
    let mut cursor = 0;
    let sequence = der_value(der, &mut cursor, 0x30)?;
    if cursor != der.len() {
        return None;
    }
    let mut sequence_cursor = 0;
    let algorithm = der_value(sequence, &mut sequence_cursor, 0x30)?;
    let mut algorithm_cursor = 0;
    let oid = der_value(algorithm, &mut algorithm_cursor, 0x06)?;
    if oid != [0x2b, 0x65, 0x70] || algorithm_cursor != algorithm.len() {
        return None;
    }
    let bit_string = der_value(sequence, &mut sequence_cursor, 0x03)?;
    if sequence_cursor != sequence.len() || bit_string.first().copied()? != 0 {
        return None;
    }
    let key = &bit_string[1..];
    (key.len() == 32).then(|| key.to_vec())
}

fn der_value<'a>(bytes: &'a [u8], cursor: &mut usize, tag: u8) -> Option<&'a [u8]> {
    if bytes.get(*cursor)? != &tag {
        return None;
    }
    *cursor += 1;
    let length = match bytes.get(*cursor)? {
        length @ 0..=0x7f => {
            *cursor += 1;
            usize::from(*length)
        }
        first @ 0x81..=0x84 => {
            let count = usize::from(*first & 0x7f);
            *cursor += 1;
            let end = cursor.checked_add(count)?;
            let bytes = bytes.get(*cursor..end)?;
            *cursor = end;
            let mut length = 0_usize;
            for byte in bytes {
                length = length.checked_mul(256)?.checked_add(usize::from(*byte))?;
            }
            length
        }
        _ => return None,
    };
    let end = cursor.checked_add(length)?;
    let value = bytes.get(*cursor..end)?;
    *cursor = end;
    Some(value)
}

fn digest_to_artifact_digest(bytes: &[u8]) -> ArtifactDigest {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    ArtifactDigest::parse(format!("sha256:{hex}")).expect("SHA-256 is always 32 bytes")
}

fn artifact_name(entry: &ArtifactCatalogEntry) -> &str {
    entry.artifact_id().as_str()
}

fn safe_label(value: &str) -> String {
    sanitize_token(value)
}

fn sanitize_token(value: &str) -> String {
    let mut output = String::new();
    for character in value.chars() {
        if (character.is_ascii_graphic() && character != '/' && character != '\\')
            || character == ' '
        {
            output.push(character);
        } else {
            output.push('?');
        }
    }
    bound_message(&output)
}

fn truncate_entry(value: &str) -> String {
    let value = sanitize_token(value);
    if value.len() <= MAX_ENTRY_BYTES {
        value
    } else {
        let mut output = value[..MAX_ENTRY_BYTES - 3].to_owned();
        output.push_str("...");
        output
    }
}

fn magic_hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "empty".to_owned();
    }
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes.iter().take(4) {
        use fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn bound_message(value: &str) -> String {
    let mut output = String::new();
    for character in value.chars() {
        let character = if character.is_control() {
            ' '
        } else {
            character
        };
        if !character.is_ascii() {
            continue;
        }
        if output.len() + character.len_utf8() > MAX_DIAGNOSTIC_BYTES {
            break;
        }
        output.push(character);
    }
    if output.len() < value.len() && output.len() + 3 <= MAX_DIAGNOSTIC_BYTES {
        output.push_str("...");
    }
    output
}

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executable_set_digest_is_order_independent() {
        let mut first = BTreeMap::new();
        first.insert("b".to_owned(), sha256_digest(b"b"));
        first.insert("a".to_owned(), sha256_digest(b"a"));
        let mut second = BTreeMap::new();
        second.insert("a".to_owned(), sha256_digest(b"a"));
        second.insert("b".to_owned(), sha256_digest(b"b"));
        assert_eq!(
            executable_set_digest(&first).unwrap(),
            executable_set_digest(&second).unwrap()
        );
    }

    #[test]
    fn diagnostic_is_ascii_and_bounded() {
        let diagnostic = Diagnostic::new(
            Kind::ProviderLayoutEntryUnexpected,
            format!("{}\n\u{2014}", "x".repeat(700)),
        );
        assert!(diagnostic.message().is_ascii());
        assert!(diagnostic.message().len() <= MAX_DIAGNOSTIC_BYTES);
        assert!(!diagnostic.message().contains('\n'));
    }

    #[test]
    fn spki_decoder_accepts_ed25519_shape() {
        let der = [
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 1, 2, 3, 4, 5,
            6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
            29, 30, 31, 32,
        ];
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            STANDARD.encode(der)
        );
        assert_eq!(decode_ed25519_spki(pem.as_bytes()).unwrap().len(), 32);
    }
}
