//! Canonical Zone resource-bundle contracts.
//!
//! The Nix compiler emits a configuration bundle before runtime metadata
//! exists.  It therefore has a deliberately smaller resource item than the
//! live [`d2b_contracts_resource::v3::ResourceEnvelope`]: the item contains author metadata and
//! desired spec only, while UID, status, finalizers, and store paths remain
//! runtime or private-artifact concerns.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

use d2b_contracts_provider::v3::{ArtifactDigest, BinaryRef};
use d2b_contracts_resource::v3::{
    ArtifactId, ResourceRef, ResourceTypeName, ResourceUid, ZoneId,
    execution_policy::BoundedToken,
    resource_schema::{
        CanonicalJsonObject, CanonicalJsonValue, canonical_json_bytes, framed_canonical_digest,
        is_canonical_digest,
    },
};

/// The canonical domain tag used for the resource array content hash.
pub const RESOURCE_BUNDLE_CONTENT_DOMAIN_TAG: &str = "d2b:v3:resource-bundle";
/// The canonical domain tag used for an artifact-catalog preimage digest.
pub const ARTIFACT_CATALOG_DOMAIN_TAG: &str = "d2b:v3:artifact-catalog";
/// Maximum resources in one Zone bundle.
pub const MAX_BUNDLE_RESOURCES: usize = 16_384;
/// Maximum schema/provider fingerprint entries in a private bundle.
pub const MAX_BUNDLE_FINGERPRINTS: usize = 256;
/// Bundle schema version accepted by the Zone runtime.
pub const RESOURCE_BUNDLE_SCHEMA_VERSION: u32 = 3;
/// Bundle envelope version accepted by the Zone runtime.
pub const RESOURCE_BUNDLE_VERSION: u32 = 1;

/// Author-controlled metadata carried by a bundle resource item.
#[derive(Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BundleResourceMetadata {
    name: d2b_contracts_resource::v3::ResourceName,
    zone: ZoneId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner_ref: Option<ResourceRef>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    labels: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    annotations: BTreeMap<String, String>,
}

impl BundleResourceMetadata {
    /// Construct bundle metadata.
    pub fn new(
        name: d2b_contracts_resource::v3::ResourceName,
        zone: ZoneId,
        owner_ref: Option<ResourceRef>,
        labels: BTreeMap<String, String>,
        annotations: BTreeMap<String, String>,
    ) -> Self {
        Self {
            name,
            zone,
            owner_ref,
            labels,
            annotations,
        }
    }

    /// Borrow the derived resource name.
    pub const fn name(&self) -> &d2b_contracts_resource::v3::ResourceName {
        &self.name
    }

    /// Borrow the enclosing Zone.
    pub const fn zone(&self) -> &ZoneId {
        &self.zone
    }

    /// Borrow the optional owner reference.
    pub const fn owner_ref(&self) -> Option<&ResourceRef> {
        self.owner_ref.as_ref()
    }

    /// Borrow labels.
    pub const fn labels(&self) -> &BTreeMap<String, String> {
        &self.labels
    }

    /// Borrow annotations.
    pub const fn annotations(&self) -> &BTreeMap<String, String> {
        &self.annotations
    }
}

impl core::fmt::Debug for BundleResourceMetadata {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BundleResourceMetadata(<redacted>)")
    }
}

impl<'de> Deserialize<'de> for BundleResourceMetadata {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            name: d2b_contracts_resource::v3::ResourceName,
            zone: ZoneId,
            #[serde(default)]
            owner_ref: Option<ResourceRef>,
            #[serde(default)]
            labels: BTreeMap<String, String>,
            #[serde(default)]
            annotations: BTreeMap<String, String>,
        }
        let wire = Wire::deserialize(deserializer)?;
        Ok(Self::new(
            wire.name,
            wire.zone,
            wire.owner_ref,
            wire.labels,
            wire.annotations,
        ))
    }
}

/// One desired-state resource item in a Zone bundle.
#[derive(Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BundleResource {
    api_version: String,
    #[serde(rename = "type")]
    resource_type: ResourceTypeName,
    metadata: BundleResourceMetadata,
    spec: CanonicalJsonObject,
}

impl BundleResource {
    /// Construct one bundle item.
    pub fn new(
        resource_type: ResourceTypeName,
        metadata: BundleResourceMetadata,
        spec: CanonicalJsonObject,
    ) -> Result<Self, ResourceBundleError> {
        if metadata.owner_ref().is_some_and(|owner| {
            owner.resource_type() == &resource_type && owner.name() == metadata.name()
        }) {
            return Err(ResourceBundleError::SelfOwner);
        }
        reject_runtime_or_private_fields(&spec)?;
        Ok(Self {
            api_version: d2b_contracts_resource::v3::resource::RESOURCE_API_VERSION.to_owned(),
            resource_type,
            metadata,
            spec,
        })
    }

    /// Borrow the ResourceType.
    pub const fn resource_type(&self) -> &ResourceTypeName {
        &self.resource_type
    }

    /// Borrow item metadata.
    pub const fn metadata(&self) -> &BundleResourceMetadata {
        &self.metadata
    }

    /// Borrow the desired spec object.
    pub const fn spec(&self) -> &CanonicalJsonObject {
        &self.spec
    }

    /// Return the canonical `(type, name)` sorting key.
    pub fn sort_key(&self) -> (&str, &str) {
        (self.resource_type.as_str(), self.metadata.name().as_str())
    }
}

impl core::fmt::Debug for BundleResource {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BundleResource(<redacted>)")
    }
}

impl<'de> Deserialize<'de> for BundleResource {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            api_version: String,
            #[serde(rename = "type")]
            resource_type: ResourceTypeName,
            metadata: BundleResourceMetadata,
            spec: CanonicalJsonObject,
        }
        let wire = Wire::deserialize(deserializer)?;
        if wire.api_version != d2b_contracts_resource::v3::resource::RESOURCE_API_VERSION {
            return Err(serde::de::Error::custom(
                "bundle resource apiVersion mismatch",
            ));
        }
        Self::new(wire.resource_type, wire.metadata, wire.spec).map_err(serde::de::Error::custom)
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// Private binding from a generic supervised Process template to the signed
/// Provider package executable.
///
/// This metadata is carried by the integrity-pinned private Zone bundle, not
/// by the public Process resource spec. It is the runtime resolver's only
/// executable binding for static Provider controller Processes.
#[derive(Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessTemplateBinding {
    process_ref: ResourceRef,
    owner_ref: ResourceRef,
    execution_ref: ResourceRef,
    template: BoundedToken,
    artifact_id: ArtifactId,
    binary_ref: BinaryRef,
    artifact_digest: ArtifactDigest,
    binary_path: String,
    #[serde(default, skip_serializing_if = "is_false")]
    dynamic: bool,
}

impl ProcessTemplateBinding {
    /// Construct one private signed-package template binding.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        process_ref: ResourceRef,
        owner_ref: ResourceRef,
        execution_ref: ResourceRef,
        template: BoundedToken,
        artifact_id: ArtifactId,
        binary_ref: BinaryRef,
        artifact_digest: ArtifactDigest,
        binary_path: impl Into<String>,
    ) -> Result<Self, ResourceBundleError> {
        Self::new_inner(
            process_ref,
            owner_ref,
            execution_ref,
            template,
            artifact_id,
            binary_ref,
            artifact_digest,
            binary_path,
            false,
        )
    }

    /// Construct a private Provider component template for a
    /// controller-created Process that is intentionally absent from the
    /// declarative bundle.
    #[allow(clippy::too_many_arguments)]
    pub fn new_dynamic(
        process_ref: ResourceRef,
        owner_ref: ResourceRef,
        execution_ref: ResourceRef,
        template: BoundedToken,
        artifact_id: ArtifactId,
        binary_ref: BinaryRef,
        artifact_digest: ArtifactDigest,
        binary_path: impl Into<String>,
    ) -> Result<Self, ResourceBundleError> {
        Self::new_inner(
            process_ref,
            owner_ref,
            execution_ref,
            template,
            artifact_id,
            binary_ref,
            artifact_digest,
            binary_path,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_inner(
        process_ref: ResourceRef,
        owner_ref: ResourceRef,
        execution_ref: ResourceRef,
        template: BoundedToken,
        artifact_id: ArtifactId,
        binary_ref: BinaryRef,
        artifact_digest: ArtifactDigest,
        binary_path: impl Into<String>,
        dynamic: bool,
    ) -> Result<Self, ResourceBundleError> {
        let binary_path = binary_path.into();
        if process_ref.resource_type().as_str() != "Process"
            || owner_ref.resource_type().as_str() != "Provider"
            || !matches!(execution_ref.resource_type().as_str(), "Host" | "Guest")
            || binary_path.is_empty()
            || binary_path.len() > 4096
            || !binary_path.starts_with('/')
            || binary_path.contains('\0')
            || binary_path
                .split('/')
                .any(|segment| matches!(segment, "." | ".."))
            || !binary_path.ends_with(&format!("/bin/{}", binary_ref.as_str()))
        {
            return Err(ResourceBundleError::InvalidProcessTemplate);
        }
        Ok(Self {
            process_ref,
            owner_ref,
            execution_ref,
            template,
            artifact_id,
            binary_ref,
            artifact_digest,
            binary_path,
            dynamic,
        })
    }

    /// Borrow the bound Process resource reference.
    pub const fn process_ref(&self) -> &ResourceRef {
        &self.process_ref
    }

    /// Borrow the owning Provider reference.
    pub const fn owner_ref(&self) -> &ResourceRef {
        &self.owner_ref
    }

    /// Borrow the Process execution target.
    pub const fn execution_ref(&self) -> &ResourceRef {
        &self.execution_ref
    }

    /// Borrow the generic Process template name.
    pub const fn template(&self) -> &BoundedToken {
        &self.template
    }

    /// Borrow the selected Provider artifact ID.
    pub const fn artifact_id(&self) -> &ArtifactId {
        &self.artifact_id
    }

    /// Borrow the signed executable reference.
    pub const fn binary_ref(&self) -> &BinaryRef {
        &self.binary_ref
    }

    /// Borrow the signed executable digest.
    pub const fn artifact_digest(&self) -> &ArtifactDigest {
        &self.artifact_digest
    }

    /// Borrow the private package executable path.
    pub fn binary_path(&self) -> &str {
        &self.binary_path
    }

    /// Whether this binding is for a controller-created Process.
    pub const fn is_dynamic(&self) -> bool {
        self.dynamic
    }
}

impl core::fmt::Debug for ProcessTemplateBinding {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProcessTemplateBinding(<redacted>)")
    }
}

impl<'de> Deserialize<'de> for ProcessTemplateBinding {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            process_ref: ResourceRef,
            owner_ref: ResourceRef,
            execution_ref: ResourceRef,
            template: BoundedToken,
            artifact_id: ArtifactId,
            binary_ref: BinaryRef,
            artifact_digest: ArtifactDigest,
            binary_path: String,
            #[serde(default)]
            dynamic: bool,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new_inner(
            wire.process_ref,
            wire.owner_ref,
            wire.execution_ref,
            wire.template,
            wire.artifact_id,
            wire.binary_ref,
            wire.artifact_digest,
            wire.binary_path,
            wire.dynamic,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// Private integrity metadata carried alongside the public resource array.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BundleIntegrityPin {
    /// Digest of canonical JSON for the `resources` array.
    pub content_hash: String,
    /// Digest of the artifact-catalog preimage.
    pub artifact_catalog_digest: String,
    /// ResourceType schema fingerprints.
    #[serde(default)]
    pub schema_fingerprints: BTreeMap<String, String>,
    /// Selected Provider schema fingerprints.
    #[serde(default)]
    pub provider_schema_digests: BTreeMap<String, String>,
}

impl core::fmt::Debug for BundleIntegrityPin {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BundleIntegrityPin(<redacted>)")
    }
}

/// A complete Nix-authored Zone resource bundle.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceBundle {
    /// Bundle schema version.
    pub schema_version: u32,
    /// Bundle format version.
    pub bundle_version: u32,
    /// Enclosing Zone.
    pub zone: ZoneId,
    /// Immutable Zone self-resource identity when the bundle is bound.
    #[serde(default)]
    pub zone_uid: Option<ResourceUid>,
    /// Content/integrity pins.
    #[serde(flatten)]
    pub integrity: BundleIntegrityPin,
    /// Sorted desired-state resources.
    pub resources: Vec<BundleResource>,
    /// Private signed-package bindings for static controller Processes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub process_templates: Vec<ProcessTemplateBinding>,
    /// Stable generation timestamp supplied by the compiler.
    pub generated_at: d2b_contracts_resource::v3::Timestamp,
}

impl ResourceBundle {
    /// Build a canonical bundle and compute its content hash.
    pub fn new(
        zone: ZoneId,
        mut resources: Vec<BundleResource>,
        artifact_catalog_digest: String,
        schema_fingerprints: BTreeMap<String, String>,
        provider_schema_digests: BTreeMap<String, String>,
        generated_at: d2b_contracts_resource::v3::Timestamp,
    ) -> Result<Self, ResourceBundleError> {
        if resources.len() > MAX_BUNDLE_RESOURCES
            || schema_fingerprints.len() > MAX_BUNDLE_FINGERPRINTS
            || provider_schema_digests.len() > MAX_BUNDLE_FINGERPRINTS
        {
            return Err(ResourceBundleError::TooLarge);
        }
        if !is_digest(&artifact_catalog_digest) {
            return Err(ResourceBundleError::InvalidDigest);
        }
        for fingerprint in schema_fingerprints
            .values()
            .chain(provider_schema_digests.values())
        {
            if !is_digest(fingerprint) {
                return Err(ResourceBundleError::InvalidDigest);
            }
        }
        for resource in &resources {
            if resource.metadata().zone() != &zone {
                return Err(ResourceBundleError::ZoneMismatch);
            }
        }
        resources.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
        if resources
            .windows(2)
            .any(|pair| pair[0].sort_key() == pair[1].sort_key())
        {
            return Err(ResourceBundleError::DuplicateResource);
        }
        let content_hash = digest_resources(&resources)?;
        Ok(Self {
            schema_version: RESOURCE_BUNDLE_SCHEMA_VERSION,
            bundle_version: RESOURCE_BUNDLE_VERSION,
            zone,
            zone_uid: None,
            integrity: BundleIntegrityPin {
                content_hash,
                artifact_catalog_digest,
                schema_fingerprints,
                provider_schema_digests,
            },
            resources,
            process_templates: Vec::new(),
            generated_at,
        })
    }

    /// Bind the bundle to the immutable Zone self-resource identity.
    pub fn with_zone_uid(mut self, zone_uid: ResourceUid) -> Self {
        self.zone_uid = Some(zone_uid);
        self
    }

    /// Borrow the immutable Zone self-resource identity, when supplied.
    pub const fn zone_uid(&self) -> Option<&ResourceUid> {
        self.zone_uid.as_ref()
    }

    /// Attach private static Process template bindings to this bundle.
    pub fn with_process_templates(
        mut self,
        mut process_templates: Vec<ProcessTemplateBinding>,
    ) -> Result<Self, ResourceBundleError> {
        if process_templates.len() > MAX_BUNDLE_RESOURCES {
            return Err(ResourceBundleError::TooLarge);
        }
        process_templates.sort_by(|left, right| {
            left.process_ref()
                .to_canonical_string()
                .cmp(&right.process_ref().to_canonical_string())
        });
        if process_templates
            .windows(2)
            .any(|pair| pair[0].process_ref() == pair[1].process_ref())
        {
            return Err(ResourceBundleError::DuplicateProcessTemplate);
        }
        self.process_templates = process_templates;
        self.verify_process_templates()?;
        Ok(self)
    }

    /// Parse and verify a bundle through canonical duplicate-key decoding.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ResourceBundleError> {
        CanonicalJsonValue::parse(bytes).map_err(ResourceBundleError::CanonicalJson)?;
        let bundle: Self =
            serde_json::from_slice(bytes).map_err(|_| ResourceBundleError::Malformed)?;
        bundle.verify()?;
        Ok(bundle)
    }

    /// Verify ordering, Zone identity, and content hash.
    pub fn verify(&self) -> Result<(), ResourceBundleError> {
        if self.schema_version != RESOURCE_BUNDLE_SCHEMA_VERSION
            || self.bundle_version != RESOURCE_BUNDLE_VERSION
        {
            return Err(ResourceBundleError::UnsupportedVersion);
        }
        if !is_digest(&self.integrity.artifact_catalog_digest)
            || self
                .integrity
                .schema_fingerprints
                .values()
                .chain(self.integrity.provider_schema_digests.values())
                .any(|digest| !is_digest(digest))
        {
            return Err(ResourceBundleError::InvalidDigest);
        }
        for resource in &self.resources {
            if resource.metadata().zone() != &self.zone {
                return Err(ResourceBundleError::ZoneMismatch);
            }
        }
        if self
            .resources
            .windows(2)
            .any(|pair| pair[0].sort_key() >= pair[1].sort_key())
        {
            return Err(ResourceBundleError::UnsortedResources);
        }
        if digest_resources(&self.resources)? != self.integrity.content_hash {
            return Err(ResourceBundleError::ContentHashMismatch);
        }
        self.verify_process_templates()?;
        Ok(())
    }

    /// Borrow the bundle's integrity fields.
    pub const fn integrity(&self) -> &BundleIntegrityPin {
        &self.integrity
    }

    fn verify_process_templates(&self) -> Result<(), ResourceBundleError> {
        let resources = self
            .resources
            .iter()
            .map(|resource| {
                (
                    ResourceRef::new(
                        resource.resource_type().clone(),
                        resource.metadata().name().clone(),
                    ),
                    resource,
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut process_refs = std::collections::BTreeSet::new();
        for binding in &self.process_templates {
            if !process_refs.insert(binding.process_ref()) {
                return Err(ResourceBundleError::DuplicateProcessTemplate);
            }
            let Some(owner) = resources.get(binding.owner_ref()) else {
                return Err(ResourceBundleError::ProcessTemplateMismatch);
            };
            if owner.resource_type().as_str() != "Provider" {
                return Err(ResourceBundleError::ProcessTemplateMismatch);
            }
            let CanonicalJsonValue::String(owner_artifact_id) = owner
                .spec()
                .get("artifactId")
                .ok_or(ResourceBundleError::ProcessTemplateMismatch)?
            else {
                return Err(ResourceBundleError::ProcessTemplateMismatch);
            };
            if owner_artifact_id != binding.artifact_id().as_str() {
                return Err(ResourceBundleError::ProcessTemplateMismatch);
            }
            if binding.is_dynamic() {
                if binding.owner_ref().to_canonical_string()
                    != "Provider/credential-managed-identity"
                    || binding.template().as_str() != "d2b-managed-identity-agent"
                    || !binding
                        .process_ref()
                        .name()
                        .as_str()
                        .starts_with("d2b-mi-agent-template-")
                    || !resources.keys().any(|resource_ref| {
                        resource_ref == binding.execution_ref()
                    })
                {
                    return Err(ResourceBundleError::ProcessTemplateMismatch);
                }
                continue;
            }
            let Some(resource) = resources.get(binding.process_ref()) else {
                return Err(ResourceBundleError::ProcessTemplateMismatch);
            };
            if resource.resource_type().as_str() != "Process"
                || resource.metadata().owner_ref() != Some(binding.owner_ref())
            {
                return Err(ResourceBundleError::ProcessTemplateMismatch);
            }
            let CanonicalJsonValue::String(execution_ref) = resource
                .spec()
                .get("executionRef")
                .ok_or(ResourceBundleError::ProcessTemplateMismatch)?
            else {
                return Err(ResourceBundleError::ProcessTemplateMismatch);
            };
            let CanonicalJsonValue::String(template) = resource
                .spec()
                .get("template")
                .ok_or(ResourceBundleError::ProcessTemplateMismatch)?
            else {
                return Err(ResourceBundleError::ProcessTemplateMismatch);
            };
            if execution_ref != &binding.execution_ref().to_canonical_string()
                || template != binding.template().as_str()
            {
                return Err(ResourceBundleError::ProcessTemplateMismatch);
            }
            let CanonicalJsonValue::String(provider_ref) = resource
                .spec()
                .get("providerRef")
                .ok_or(ResourceBundleError::ProcessTemplateMismatch)?
            else {
                return Err(ResourceBundleError::ProcessTemplateMismatch);
            };
            if provider_ref != "Provider/system-minijail" {
                return Err(ResourceBundleError::ProcessTemplateMismatch);
            }
            let CanonicalJsonValue::String(process_class) = resource
                .spec()
                .get("processClass")
                .ok_or(ResourceBundleError::ProcessTemplateMismatch)?
            else {
                return Err(ResourceBundleError::ProcessTemplateMismatch);
            };
            if process_class != "controller" {
                return Err(ResourceBundleError::ProcessTemplateMismatch);
            }
        }
        Ok(())
    }
}

impl core::fmt::Debug for ResourceBundle {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ResourceBundle")
            .field("schema_version", &self.schema_version)
            .field("bundle_version", &self.bundle_version)
            .field("resource_count", &self.resources.len())
            .finish()
    }
}

/// Closed bundle validation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceBundleError {
    /// Canonical JSON could not be decoded.
    CanonicalJson(d2b_contracts_resource::v3::resource_schema::CanonicalJsonError),
    /// The JSON shape was not a bundle.
    Malformed,
    /// A runtime/private field appeared in a bundle item.
    ForbiddenField,
    /// A resource owns itself.
    SelfOwner,
    /// A resource belongs to another Zone.
    ZoneMismatch,
    /// A bundle contains duplicate `(type,name)` rows.
    DuplicateResource,
    /// A bundle exceeds a frozen bound.
    TooLarge,
    /// A digest is not a canonical sha256 value.
    InvalidDigest,
    /// The bundle format version is unsupported.
    UnsupportedVersion,
    /// Resource rows are not sorted.
    UnsortedResources,
    /// The recorded content hash differs from the resource array.
    ContentHashMismatch,
    /// A Process template binding is malformed.
    InvalidProcessTemplate,
    /// A Process template binding is duplicated.
    DuplicateProcessTemplate,
    /// A declarative Process template binding does not match its Process
    /// resource.
    ProcessTemplateMismatch,
    /// A canonical rendering operation failed.
    CanonicalJsonEncode(d2b_contracts_resource::v3::resource_schema::CanonicalJsonError),
}

impl core::fmt::Display for ResourceBundleError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::CanonicalJson(_) => "resource bundle canonical JSON is invalid",
            Self::Malformed => "resource bundle shape is invalid",
            Self::ForbiddenField => "resource bundle contains a forbidden field",
            Self::SelfOwner => "resource bundle resource owns itself",
            Self::ZoneMismatch => "resource bundle resource belongs to another Zone",
            Self::DuplicateResource => "resource bundle contains a duplicate resource",
            Self::TooLarge => "resource bundle exceeds a frozen bound",
            Self::InvalidDigest => "resource bundle contains an invalid digest",
            Self::UnsupportedVersion => "resource bundle version is unsupported",
            Self::UnsortedResources => "resource bundle resources are not sorted",
            Self::ContentHashMismatch => "resource bundle content hash does not match resources",
            Self::InvalidProcessTemplate => "resource bundle contains an invalid process template",
            Self::DuplicateProcessTemplate => {
                "resource bundle contains a duplicate process template"
            }
            Self::ProcessTemplateMismatch => {
                "resource bundle process template does not match its Process resource"
            }
            Self::CanonicalJsonEncode(_) => "resource bundle could not be rendered canonically",
        })
    }
}

impl std::error::Error for ResourceBundleError {}

fn digest_resources(resources: &[BundleResource]) -> Result<String, ResourceBundleError> {
    let bytes =
        canonical_json_bytes(&resources).map_err(ResourceBundleError::CanonicalJsonEncode)?;
    Ok(framed_canonical_digest(
        RESOURCE_BUNDLE_CONTENT_DOMAIN_TAG,
        &bytes,
    ))
}

fn is_digest(value: &str) -> bool {
    is_canonical_digest(value)
}

fn reject_runtime_or_private_fields(
    object: &CanonicalJsonObject,
) -> Result<(), ResourceBundleError> {
    fn walk(value: &CanonicalJsonValue) -> bool {
        match value {
            CanonicalJsonValue::Object(map) => map.iter().any(|(key, value)| {
                matches!(
                    key.as_str(),
                    "status"
                        | "storePath"
                        | "nixSystem"
                        | "schemaFingerprint"
                        | "providerSchemaFingerprint"
                        | "managedBy"
                        | "configurationGeneration"
                ) || walk(value)
            }),
            CanonicalJsonValue::Array(values) => values.iter().any(walk),
            _ => false,
        }
    }
    if walk(&CanonicalJsonValue::Object(object.clone().into_inner())) {
        Err(ResourceBundleError::ForbiddenField)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use d2b_contracts_resource::v3::{
        CanonicalJsonObject, ResourceName, ResourceTypeName, Timestamp, ZoneId,
    };

    fn resource(kind: &str, name: &str) -> BundleResource {
        BundleResource::new(
            ResourceTypeName::parse(kind).unwrap(),
            BundleResourceMetadata::new(
                ResourceName::parse(name).unwrap(),
                ZoneId::parse("dev").unwrap(),
                None,
                BTreeMap::new(),
                BTreeMap::new(),
            ),
            CanonicalJsonObject::empty(),
        )
        .unwrap()
    }

    fn timestamp() -> Timestamp {
        Timestamp::parse("2026-07-22T00:00:00.000Z").unwrap()
    }

    #[test]
    fn process_template_binding_rejects_mismatched_binary_path() {
        let process_ref = ResourceRef::parse("Process/controller").unwrap();
        let owner_ref = ResourceRef::parse("Provider/runtime").unwrap();
        let execution_ref = ResourceRef::parse("Host/host").unwrap();
        let template = BoundedToken::parse("controller-runtime").unwrap();
        let artifact_id = ArtifactId::parse("runtime").unwrap();
        let binary_ref = BinaryRef::parse("controller").unwrap();
        let digest = ArtifactDigest::parse(format!("sha256:{}", "a".repeat(64))).unwrap();
        assert_eq!(
            ProcessTemplateBinding::new(
                process_ref,
                owner_ref,
                execution_ref,
                template,
                artifact_id,
                binary_ref,
                digest,
                "/nix/store/runtime/bin/wrong",
            )
            .unwrap_err(),
            ResourceBundleError::InvalidProcessTemplate
        );
    }

    #[test]
    fn dynamic_process_template_binding_does_not_require_a_bundle_process() {
        let owner = BundleResource::new(
            ResourceTypeName::parse("Provider").unwrap(),
            BundleResourceMetadata::new(
                ResourceName::parse("credential-managed-identity").unwrap(),
                ZoneId::parse("dev").unwrap(),
                None,
                BTreeMap::new(),
                BTreeMap::new(),
            ),
            CanonicalJsonObject::parse(br#"{"artifactId":"runtime"}"#).unwrap(),
        )
        .unwrap();
        let binding = ProcessTemplateBinding::new_dynamic(
            ResourceRef::parse("Process/d2b-mi-agent-template-guest-dev").unwrap(),
            ResourceRef::parse("Provider/credential-managed-identity").unwrap(),
            ResourceRef::parse("Guest/dev").unwrap(),
            BoundedToken::parse("d2b-managed-identity-agent").unwrap(),
            ArtifactId::parse("runtime").unwrap(),
            BinaryRef::parse("d2b-managed-identity-agent").unwrap(),
            ArtifactDigest::parse(format!("sha256:{}", "a".repeat(64))).unwrap(),
            "/nix/store/runtime/bin/d2b-managed-identity-agent",
        )
        .unwrap();
        let resources = vec![owner, resource("Guest", "dev")];
        let content_hash = digest_resources(&resources).unwrap();
        let bundle = ResourceBundle::new(
            ZoneId::parse("dev").unwrap(),
            resources,
            content_hash,
            BTreeMap::new(),
            BTreeMap::new(),
            timestamp(),
        )
        .unwrap()
        .with_process_templates(vec![binding])
        .unwrap();
        assert!(bundle.process_templates[0].is_dynamic());
        let bytes = canonical_json_bytes(&bundle).unwrap();
        assert!(ResourceBundle::from_json(&bytes).is_ok());
    }

    #[test]
    fn bundle_sorts_rows_and_hashes_only_the_resource_array() {
        let zone_uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let bundle = ResourceBundle::new(
            ZoneId::parse("dev").unwrap(),
            vec![resource("Process", "z"), resource("Host", "a")],
            "sha256:".to_owned() + &"11".repeat(32),
            BTreeMap::new(),
            BTreeMap::new(),
            timestamp(),
        )
        .unwrap();
        let bundle = bundle.with_zone_uid(zone_uid.clone());
        assert_eq!(bundle.resources[0].resource_type().as_str(), "Host");
        assert_eq!(bundle.resources[1].metadata().name().as_str(), "z");
        assert_eq!(bundle.zone_uid(), Some(&zone_uid));
        let bytes = canonical_json_bytes(&bundle).unwrap();
        assert_eq!(ResourceBundle::from_json(&bytes).unwrap(), bundle);
    }

    #[test]
    fn bundle_accepts_nix_omitted_optional_metadata() {
        let bundle = ResourceBundle::new(
            ZoneId::parse("dev").unwrap(),
            vec![resource("Host", "a")],
            "sha256:".to_owned() + &"11".repeat(32),
            BTreeMap::new(),
            BTreeMap::new(),
            timestamp(),
        )
        .unwrap();
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            !value["resources"][0]["metadata"]
                .as_object()
                .unwrap()
                .contains_key("ownerRef")
        );
        assert_eq!(ResourceBundle::from_json(&bytes).unwrap(), bundle);
    }

    #[test]
    fn forbidden_private_fields_never_enter_a_resource_item() {
        let spec = CanonicalJsonObject::parse(
            br#"{"provider":{"settings":{"storePath":"/nix/store/x"}}}"#,
        )
        .unwrap();
        assert_eq!(
            BundleResource::new(
                ResourceTypeName::parse("Guest").unwrap(),
                BundleResourceMetadata::new(
                    ResourceName::parse("guest").unwrap(),
                    ZoneId::parse("dev").unwrap(),
                    None,
                    BTreeMap::new(),
                    BTreeMap::new(),
                ),
                spec,
            )
            .unwrap_err(),
            ResourceBundleError::ForbiddenField
        );
    }

    #[test]
    fn content_tampering_is_rejected() {
        let bundle = ResourceBundle::new(
            ZoneId::parse("dev").unwrap(),
            vec![resource("Host", "a")],
            "sha256:".to_owned() + &"11".repeat(32),
            BTreeMap::new(),
            BTreeMap::new(),
            timestamp(),
        )
        .unwrap();
        let mut value = serde_json::to_value(bundle).unwrap();
        value["resources"][0]["metadata"]["name"] = serde_json::json!("b");
        assert!(ResourceBundle::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
    }
}
