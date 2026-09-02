//! Azure Container Apps effect contracts.

#![allow(missing_docs)]

use std::{fmt, future::Future, pin::Pin};

use async_trait::async_trait;
use serde::{Deserialize, Deserializer, Serialize};

pub use d2b_contracts_provider::v3::credential::{CredentialLeaseHandle, OpaqueAzureRef};
pub use d2b_contracts_resource::v3::{ResourceRef, ResourceUid};

pub const MAX_ACA_RESOURCE_ID_LEN: usize = 60;
pub const MAX_ACA_CANDIDATES: usize = 8;
pub const MAX_ACA_READY_ATTEMPTS: u8 = 60;
pub const MAX_ACA_READY_INTERVAL_MS: u32 = 10_000;
pub const MAX_ACA_PLAN_TTL_MS: u32 = 300_000;
pub const MAX_ACA_COMPLETED_OPERATIONS: usize = 1_024;
pub const MAX_ACA_LEASE_CLEANUP_MS: u32 = 1_000;
pub const MAX_ACA_RETRY_AFTER_MS: u32 = 300_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcaTypeError {
    InvalidIdentifier,
    InvalidResourceBounds,
    InvalidReadinessPolicy,
    InvalidPlanTtl,
    InvalidOperationCapacity,
    CandidateBoundExceeded,
    InvalidExecutionBoundary,
}

impl fmt::Display for AcaTypeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidIdentifier => "aca-invalid-identifier",
            Self::InvalidResourceBounds => "aca-invalid-resource-bounds",
            Self::InvalidReadinessPolicy => "aca-invalid-readiness-policy",
            Self::InvalidPlanTtl => "aca-invalid-plan-ttl",
            Self::InvalidOperationCapacity => "aca-invalid-operation-capacity",
            Self::CandidateBoundExceeded => "aca-candidate-bound-exceeded",
            Self::InvalidExecutionBoundary => "aca-invalid-execution-boundary",
        })
    }
}

impl std::error::Error for AcaTypeError {}

fn valid_opaque_id(value: &str, max: usize, lowercase_lead: bool) -> bool {
    !value.is_empty()
        && value.len() <= max
        && (!lowercase_lead || value.as_bytes()[0].is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

macro_rules! opaque_id {
    ($name:ident, $max:expr, $lowercase_lead:expr) => {
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, AcaTypeError> {
                let value = value.into();
                if valid_opaque_id(&value, $max, $lowercase_lead) {
                    Ok(Self(value))
                } else {
                    Err(AcaTypeError::InvalidIdentifier)
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}

opaque_id!(AcaProfileId, 64, true);
opaque_id!(AcaConfiguredDiskId, 64, true);
opaque_id!(AcaConfiguredImageId, 64, true);
opaque_id!(AcaDiskImageName, 64, true);
opaque_id!(AcaManagedIdentityBindingId, 64, true);
opaque_id!(AcaSandboxId, MAX_ACA_RESOURCE_ID_LEN, false);
opaque_id!(AcaDiskImageId, MAX_ACA_RESOURCE_ID_LEN, false);
opaque_id!(AcaOperationId, 96, true);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcaCpuMillis(u16);

impl AcaCpuMillis {
    pub fn new(value: u16) -> Result<Self, AcaTypeError> {
        if (250..=4_000).contains(&value) && value.is_multiple_of(250) {
            Ok(Self(value))
        } else {
            Err(AcaTypeError::InvalidResourceBounds)
        }
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

impl<'de> Deserialize<'de> for AcaCpuMillis {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(u16::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcaMemoryMib(u32);

impl AcaMemoryMib {
    pub fn new(value: u32) -> Result<Self, AcaTypeError> {
        if (512..=16_384).contains(&value) && value.is_multiple_of(256) {
            Ok(Self(value))
        } else {
            Err(AcaTypeError::InvalidResourceBounds)
        }
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

impl<'de> Deserialize<'de> for AcaMemoryMib {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(u32::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum AcaDiskImageSource {
    ConfiguredDisk {
        binding_id: AcaConfiguredDiskId,
    },
    ConfiguredContainerImage {
        image_binding_id: AcaConfiguredImageId,
        disk_name: AcaDiskImageName,
        pull_identity_binding_id: Option<AcaManagedIdentityBindingId>,
    },
}

impl<'de> Deserialize<'de> for AcaDiskImageSource {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        enum RawAcaDiskImageSource {
            ConfiguredDisk {
                binding_id: AcaConfiguredDiskId,
            },
            ConfiguredContainerImage {
                image_binding_id: AcaConfiguredImageId,
                disk_name: AcaDiskImageName,
                pull_identity_binding_id: Option<AcaManagedIdentityBindingId>,
            },
        }

        match RawAcaDiskImageSource::deserialize(deserializer)? {
            RawAcaDiskImageSource::ConfiguredDisk { binding_id } => {
                Ok(Self::ConfiguredDisk { binding_id })
            }
            RawAcaDiskImageSource::ConfiguredContainerImage {
                image_binding_id,
                disk_name,
                pull_identity_binding_id,
            } => Ok(Self::ConfiguredContainerImage {
                image_binding_id,
                disk_name,
                pull_identity_binding_id,
            }),
        }
    }
}

impl fmt::Debug for AcaDiskImageSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ConfiguredDisk { .. } => "AcaDiskImageSource::ConfiguredDisk(<redacted>)",
            Self::ConfiguredContainerImage { .. } => {
                "AcaDiskImageSource::ConfiguredContainerImage(<redacted>)"
            }
        })
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcaSandboxProfile {
    profile_id: AcaProfileId,
    disk_image: AcaDiskImageSource,
    cpu: AcaCpuMillis,
    memory: AcaMemoryMib,
    auto_suspend_secs: u32,
    sandbox_identity_binding_id: Option<AcaManagedIdentityBindingId>,
}

impl<'de> Deserialize<'de> for AcaSandboxProfile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct RawAcaSandboxProfile {
            profile_id: AcaProfileId,
            disk_image: AcaDiskImageSource,
            cpu: AcaCpuMillis,
            memory: AcaMemoryMib,
            auto_suspend_secs: u32,
            sandbox_identity_binding_id: Option<AcaManagedIdentityBindingId>,
        }

        let raw = RawAcaSandboxProfile::deserialize(deserializer)?;
        Self::new(
            raw.profile_id,
            raw.disk_image,
            raw.cpu,
            raw.memory,
            raw.auto_suspend_secs,
            raw.sandbox_identity_binding_id,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl AcaSandboxProfile {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile_id: AcaProfileId,
        disk_image: AcaDiskImageSource,
        cpu: AcaCpuMillis,
        memory: AcaMemoryMib,
        auto_suspend_secs: u32,
        sandbox_identity_binding_id: Option<AcaManagedIdentityBindingId>,
    ) -> Result<Self, AcaTypeError> {
        AcaCpuMillis::new(cpu.get())?;
        AcaMemoryMib::new(memory.get())?;
        if !(60..=86_400).contains(&auto_suspend_secs) {
            return Err(AcaTypeError::InvalidResourceBounds);
        }
        Ok(Self {
            profile_id,
            disk_image,
            cpu,
            memory,
            auto_suspend_secs,
            sandbox_identity_binding_id,
        })
    }

    pub fn profile_id(&self) -> &AcaProfileId {
        &self.profile_id
    }

    pub fn disk_image(&self) -> &AcaDiskImageSource {
        &self.disk_image
    }

    pub const fn cpu(&self) -> AcaCpuMillis {
        self.cpu
    }

    pub const fn memory(&self) -> AcaMemoryMib {
        self.memory
    }

    pub const fn auto_suspend_secs(&self) -> u32 {
        self.auto_suspend_secs
    }

    pub fn sandbox_identity_binding_id(&self) -> Option<&AcaManagedIdentityBindingId> {
        self.sandbox_identity_binding_id.as_ref()
    }
}

impl fmt::Debug for AcaSandboxProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcaSandboxProfile")
            .field("profile_id", &"<redacted>")
            .field("disk_image", &self.disk_image)
            .field("cpu", &self.cpu)
            .field("memory", &self.memory)
            .field("auto_suspend_secs", &self.auto_suspend_secs)
            .field(
                "sandbox_identity",
                &self
                    .sandbox_identity_binding_id
                    .as_ref()
                    .map(|_| "<configured>"),
            )
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcaReadinessPolicy {
    attempts: u8,
    interval_ms: u32,
}

impl<'de> Deserialize<'de> for AcaReadinessPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct RawAcaReadinessPolicy {
            attempts: u8,
            interval_ms: u32,
        }

        let raw = RawAcaReadinessPolicy::deserialize(deserializer)?;
        Self::new(raw.attempts, raw.interval_ms).map_err(serde::de::Error::custom)
    }
}

impl AcaReadinessPolicy {
    pub fn new(attempts: u8, interval_ms: u32) -> Result<Self, AcaTypeError> {
        if attempts == 0
            || attempts > MAX_ACA_READY_ATTEMPTS
            || interval_ms == 0
            || interval_ms > MAX_ACA_READY_INTERVAL_MS
        {
            return Err(AcaTypeError::InvalidReadinessPolicy);
        }
        Ok(Self {
            attempts,
            interval_ms,
        })
    }

    pub const fn attempts(self) -> u8 {
        self.attempts
    }

    pub const fn interval_ms(self) -> u32 {
        self.interval_ms
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcaRuntimeConfig {
    profile: AcaSandboxProfile,
    readiness: AcaReadinessPolicy,
    plan_ttl_ms: u32,
    completed_operation_capacity: usize,
}

impl AcaRuntimeConfig {
    pub fn new(
        profile: AcaSandboxProfile,
        readiness: AcaReadinessPolicy,
        plan_ttl_ms: u32,
        completed_operation_capacity: usize,
    ) -> Result<Self, AcaTypeError> {
        let profile_check = &profile;
        AcaSandboxProfile::new(
            profile_check.profile_id().clone(),
            profile_check.disk_image().clone(),
            profile_check.cpu(),
            profile_check.memory(),
            profile_check.auto_suspend_secs(),
            profile_check.sandbox_identity_binding_id().cloned(),
        )?;
        AcaReadinessPolicy::new(readiness.attempts(), readiness.interval_ms())?;
        if plan_ttl_ms == 0 || plan_ttl_ms > MAX_ACA_PLAN_TTL_MS {
            return Err(AcaTypeError::InvalidPlanTtl);
        }
        if completed_operation_capacity == 0
            || completed_operation_capacity > MAX_ACA_COMPLETED_OPERATIONS
        {
            return Err(AcaTypeError::InvalidOperationCapacity);
        }
        Ok(Self {
            profile,
            readiness,
            plan_ttl_ms,
            completed_operation_capacity,
        })
    }

    pub fn profile(&self) -> &AcaSandboxProfile {
        &self.profile
    }

    pub const fn readiness(&self) -> AcaReadinessPolicy {
        self.readiness
    }

    pub const fn plan_ttl_ms(&self) -> u32 {
        self.plan_ttl_ms
    }

    pub const fn completed_operation_capacity(&self) -> usize {
        self.completed_operation_capacity
    }

    /// Revalidate values that may have arrived through a deserializer.
    pub fn validate(&self) -> Result<(), AcaTypeError> {
        let profile = self.profile();
        let profile = AcaSandboxProfile::new(
            profile.profile_id().clone(),
            profile.disk_image().clone(),
            profile.cpu(),
            profile.memory(),
            profile.auto_suspend_secs(),
            profile.sandbox_identity_binding_id().cloned(),
        )?;
        Self::new(
            profile,
            self.readiness,
            self.plan_ttl_ms,
            self.completed_operation_capacity,
        )
        .map(|_| ())
    }
}

impl<'de> Deserialize<'de> for AcaRuntimeConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct RawAcaRuntimeConfig {
            profile: AcaSandboxProfile,
            readiness: AcaReadinessPolicy,
            plan_ttl_ms: u32,
            completed_operation_capacity: usize,
        }

        let raw = RawAcaRuntimeConfig::deserialize(deserializer)?;
        Self::new(
            raw.profile,
            raw.readiness,
            raw.plan_ttl_ms,
            raw.completed_operation_capacity,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for AcaRuntimeConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcaRuntimeConfig")
            .field("profile", &self.profile)
            .field("readiness", &self.readiness)
            .field("plan_ttl_ms", &self.plan_ttl_ms)
            .field(
                "completed_operation_capacity",
                &self.completed_operation_capacity,
            )
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcaProviderConfig {
    pub gateway_execution_ref: ResourceRef,
    pub tenant_id: OpaqueAzureRef,
    pub client_id: OpaqueAzureRef,
    pub subscription_id: OpaqueAzureRef,
    pub control_credential_ref: ResourceRef,
    pub pull_credential_ref: Option<ResourceRef>,
    pub environment_id: AcaConfiguredImageId,
    pub resource_group_id: AcaConfiguredImageId,
    pub network_ref: Option<ResourceRef>,
    pub sandbox_transport_alias: AcaProfileId,
    pub defaults: AcaRuntimeConfig,
}

impl AcaProviderConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        gateway_execution_ref: ResourceRef,
        tenant_id: OpaqueAzureRef,
        client_id: OpaqueAzureRef,
        subscription_id: OpaqueAzureRef,
        control_credential_ref: ResourceRef,
        pull_credential_ref: Option<ResourceRef>,
        environment_id: AcaConfiguredImageId,
        resource_group_id: AcaConfiguredImageId,
        network_ref: Option<ResourceRef>,
        sandbox_transport_alias: AcaProfileId,
        defaults: AcaRuntimeConfig,
    ) -> Result<Self, AcaTypeError> {
        if gateway_execution_ref.resource_type().as_str() != "Guest"
            || control_credential_ref.resource_type().as_str() != "Credential"
            || pull_credential_ref
                .as_ref()
                .is_some_and(|reference| reference.resource_type().as_str() != "Credential")
            || network_ref
                .as_ref()
                .is_some_and(|reference| reference.resource_type().as_str() != "Network")
        {
            return Err(AcaTypeError::InvalidExecutionBoundary);
        }
        defaults.validate()?;
        Ok(Self {
            gateway_execution_ref,
            tenant_id,
            client_id,
            subscription_id,
            control_credential_ref,
            pull_credential_ref,
            environment_id,
            resource_group_id,
            network_ref,
            sandbox_transport_alias,
            defaults,
        })
    }

    /// Require a Credential scope to equal the gateway Guest exactly.
    pub fn validate_credential_scope(
        &self,
        execution_ref: &ResourceRef,
    ) -> Result<(), AcaTypeError> {
        if execution_ref != &self.gateway_execution_ref {
            return Err(AcaTypeError::InvalidExecutionBoundary);
        }
        Ok(())
    }

    /// Require every ACA controller effect to execute in the configured
    /// Gateway Guest. Host placement is never a valid fallback.
    pub fn validate_gateway_execution(
        &self,
        execution_ref: &ResourceRef,
    ) -> Result<(), AcaTypeError> {
        if self.gateway_execution_ref.resource_type().as_str() != "Guest"
            || execution_ref != &self.gateway_execution_ref
        {
            return Err(AcaTypeError::InvalidExecutionBoundary);
        }
        Ok(())
    }

    /// Revalidate a Provider configuration at the admission boundary.
    pub fn validate(&self) -> Result<(), AcaTypeError> {
        Self::new(
            self.gateway_execution_ref.clone(),
            self.tenant_id.clone(),
            self.client_id.clone(),
            self.subscription_id.clone(),
            self.control_credential_ref.clone(),
            self.pull_credential_ref.clone(),
            self.environment_id.clone(),
            self.resource_group_id.clone(),
            self.network_ref.clone(),
            self.sandbox_transport_alias.clone(),
            self.defaults.clone(),
        )
        .map(|_| ())
    }
}

impl<'de> Deserialize<'de> for AcaProviderConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct RawAcaProviderConfig {
            gateway_execution_ref: ResourceRef,
            tenant_id: OpaqueAzureRef,
            client_id: OpaqueAzureRef,
            subscription_id: OpaqueAzureRef,
            control_credential_ref: ResourceRef,
            pull_credential_ref: Option<ResourceRef>,
            environment_id: AcaConfiguredImageId,
            resource_group_id: AcaConfiguredImageId,
            network_ref: Option<ResourceRef>,
            sandbox_transport_alias: AcaProfileId,
            defaults: AcaRuntimeConfig,
        }

        let raw = RawAcaProviderConfig::deserialize(deserializer)?;
        Self::new(
            raw.gateway_execution_ref,
            raw.tenant_id,
            raw.client_id,
            raw.subscription_id,
            raw.control_credential_ref,
            raw.pull_credential_ref,
            raw.environment_id,
            raw.resource_group_id,
            raw.network_ref,
            raw.sandbox_transport_alias,
            raw.defaults,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for AcaProviderConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcaProviderConfig")
            .field("gateway_execution_ref", &"<redacted>")
            .field("tenant_id", &self.tenant_id)
            .field("client_id", &self.client_id)
            .field("subscription_id", &self.subscription_id)
            .field("control_credential_ref", &"<redacted>")
            .field(
                "pull_credential_ref",
                &self.pull_credential_ref.as_ref().map(|_| "<configured>"),
            )
            .field("environment_id", &self.environment_id)
            .field("resource_group_id", &self.resource_group_id)
            .field(
                "network_ref",
                &self.network_ref.as_ref().map(|_| "<configured>"),
            )
            .field("sandbox_transport_alias", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcaResourceBinding {
    pub guest_uid: ResourceUid,
    pub provider_generation: u64,
    pub config_fingerprint: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcaWorkloadQuery {
    pub binding: AcaResourceBinding,
    pub profile_id: AcaProfileId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcaDesiredDiskImage {
    pub source: AcaDiskImageSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcaDesiredSandbox {
    pub binding: AcaResourceBinding,
    pub profile: AcaSandboxProfile,
    pub disk_image: AcaDiskImageRecord,
    pub network_ref: Option<ResourceRef>,
    pub sandbox_transport_alias: AcaProfileId,
}

#[derive(Clone, PartialEq, Eq)]
pub struct AcaDiskImageRecord {
    pub id: AcaDiskImageId,
    pub generation: u64,
}

impl fmt::Debug for AcaDiskImageRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcaDiskImageRecord")
            .field("id", &"<redacted>")
            .field("generation", &self.generation)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcaDiskImageCandidates(Vec<AcaDiskImageRecord>);

impl AcaDiskImageCandidates {
    pub fn new(records: Vec<AcaDiskImageRecord>) -> Result<Self, AcaTypeError> {
        if records.len() > MAX_ACA_CANDIDATES {
            return Err(AcaTypeError::CandidateBoundExceeded);
        }
        Ok(Self(records))
    }

    pub fn as_slice(&self) -> &[AcaDiskImageRecord] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum AcaSandboxLifecycle {
    Creating,
    Running,
    Suspended,
    Stopping,
    Stopped,
    Failed,
    Unknown,
}

#[derive(Clone, PartialEq, Eq)]
pub struct AcaSandboxRecord {
    pub id: AcaSandboxId,
    pub lifecycle: AcaSandboxLifecycle,
    pub generation: u64,
}

impl fmt::Debug for AcaSandboxRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcaSandboxRecord")
            .field("id", &"<redacted>")
            .field("lifecycle", &self.lifecycle)
            .field("generation", &self.generation)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcaSandboxCandidates(Vec<AcaSandboxRecord>);

impl AcaSandboxCandidates {
    pub fn new(records: Vec<AcaSandboxRecord>) -> Result<Self, AcaTypeError> {
        if records.len() > MAX_ACA_CANDIDATES {
            return Err(AcaTypeError::CandidateBoundExceeded);
        }
        Ok(Self(records))
    }

    pub fn as_slice(&self) -> &[AcaSandboxRecord] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcaDeleteOutcome {
    Deleted,
    AlreadyAbsent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcaCredentialPurpose {
    Health,
    Ensure,
    Start,
    Stop,
    Inspect,
    Adopt,
    Destroy,
}

impl AcaCredentialPurpose {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Health => "health",
            Self::Ensure => "ensure",
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Inspect => "inspect",
            Self::Adopt => "adopt",
            Self::Destroy => "destroy",
        }
    }

    /// Return the closed SDK operation classes required for this purpose.
    pub const fn required_operations(self) -> &'static [&'static str] {
        match self {
            Self::Health => &["authenticate", "read"],
            Self::Ensure => &["authenticate", "discover", "read", "create"],
            Self::Start | Self::Stop => &["authenticate", "discover", "read", "power"],
            Self::Inspect | Self::Adopt => &["authenticate", "discover", "read"],
            Self::Destroy => &["authenticate", "discover", "read", "delete"],
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct AcaCredentialLease {
    metadata: CredentialLeaseHandle,
    expires_at_unix_ms: u64,
}

impl AcaCredentialLease {
    pub fn from_metadata(metadata: CredentialLeaseHandle, expires_at_unix_ms: u64) -> Self {
        Self {
            metadata,
            expires_at_unix_ms,
        }
    }

    pub const fn metadata(&self) -> &CredentialLeaseHandle {
        &self.metadata
    }

    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }
}

impl fmt::Debug for AcaCredentialLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcaCredentialLease")
            .field("metadata", &"<opaque>")
            .field("expires_at_unix_ms", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct AcaCredentialLeaseRequest {
    operation_id: AcaOperationId,
    purpose: AcaCredentialPurpose,
    requested_expiry_unix_ms: u64,
}

impl AcaCredentialLeaseRequest {
    pub fn new(
        operation_id: AcaOperationId,
        purpose: AcaCredentialPurpose,
        requested_expiry_unix_ms: u64,
    ) -> Self {
        Self {
            operation_id,
            purpose,
            requested_expiry_unix_ms,
        }
    }

    pub const fn operation_id(&self) -> &AcaOperationId {
        &self.operation_id
    }

    pub const fn purpose(&self) -> AcaCredentialPurpose {
        self.purpose
    }

    pub const fn requested_expiry_unix_ms(&self) -> u64 {
        self.requested_expiry_unix_ms
    }
}

impl fmt::Debug for AcaCredentialLeaseRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcaCredentialLeaseRequest")
            .field("operation_id", &"<redacted>")
            .field("purpose", &self.purpose)
            .field("requested_expiry_unix_ms", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct AcaControlContext {
    operation_id: AcaOperationId,
    deadline_remaining_ms: u32,
}

impl AcaControlContext {
    pub fn new(operation_id: AcaOperationId, deadline_remaining_ms: u32) -> Self {
        Self {
            operation_id,
            deadline_remaining_ms,
        }
    }

    pub const fn operation_id(&self) -> &AcaOperationId {
        &self.operation_id
    }

    pub const fn deadline_remaining_ms(&self) -> u32 {
        self.deadline_remaining_ms
    }
}

impl fmt::Debug for AcaControlContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcaControlContext")
            .field("operation_id", &"<redacted>")
            .field("deadline_remaining_ms", &self.deadline_remaining_ms)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcaControlHealth {
    Ready,
    Degraded,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcaControlErrorKind {
    Authentication,
    Authorization,
    RateLimited,
    Unavailable,
    Conflict,
    NotFound,
    InvalidResponse,
    Cancelled,
    DeadlineExpired,
    Ambiguous,
}

impl AcaControlErrorKind {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Authentication => "aca-control-authentication",
            Self::Authorization => "aca-control-authorization",
            Self::RateLimited => "aca-control-rate-limited",
            Self::Unavailable => "aca-control-unavailable",
            Self::Conflict => "aca-control-conflict",
            Self::NotFound => "aca-control-not-found",
            Self::InvalidResponse => "aca-control-invalid-response",
            Self::Cancelled => "aca-control-cancelled",
            Self::DeadlineExpired => "aca-control-deadline-expired",
            Self::Ambiguous => "aca-control-ambiguous",
        }
    }

    pub const fn retryable(self) -> bool {
        matches!(self, Self::RateLimited | Self::Unavailable)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcaControlError {
    kind: AcaControlErrorKind,
    retry_after_ms: Option<u32>,
}

impl AcaControlError {
    pub const fn new(kind: AcaControlErrorKind) -> Self {
        Self {
            kind,
            retry_after_ms: None,
        }
    }

    pub const fn with_retry_after_ms(mut self, retry_after_ms: u32) -> Self {
        self.retry_after_ms = Some(if retry_after_ms > MAX_ACA_RETRY_AFTER_MS {
            MAX_ACA_RETRY_AFTER_MS
        } else {
            retry_after_ms
        });
        self
    }

    pub const fn kind(self) -> AcaControlErrorKind {
        self.kind
    }

    pub const fn retry_after_ms(self) -> Option<u32> {
        self.retry_after_ms
    }

    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for AcaControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.kind.code())
    }
}

impl std::error::Error for AcaControlError {}

#[async_trait]
pub trait AcaCredentialLeaseClient: Send + Sync {
    async fn acquire(
        &self,
        request: &AcaCredentialLeaseRequest,
    ) -> Result<AcaCredentialLease, AcaControlError>;

    async fn revoke(&self, lease: &AcaCredentialLease) -> Result<(), AcaControlError>;
}

#[async_trait]
pub trait AcaControl: Send + Sync {
    async fn health(
        &self,
        lease: &AcaCredentialLease,
        context: &AcaControlContext,
    ) -> Result<AcaControlHealth, AcaControlError>;

    async fn find_sandboxes(
        &self,
        lease: &AcaCredentialLease,
        context: &AcaControlContext,
        query: &AcaWorkloadQuery,
    ) -> Result<AcaSandboxCandidates, AcaControlError>;

    async fn find_disk_images(
        &self,
        lease: &AcaCredentialLease,
        context: &AcaControlContext,
        desired: &AcaDesiredDiskImage,
    ) -> Result<AcaDiskImageCandidates, AcaControlError>;

    async fn create_disk_image(
        &self,
        lease: &AcaCredentialLease,
        context: &AcaControlContext,
        desired: &AcaDesiredDiskImage,
    ) -> Result<AcaDiskImageRecord, AcaControlError>;

    async fn create_sandbox(
        &self,
        lease: &AcaCredentialLease,
        context: &AcaControlContext,
        desired: &AcaDesiredSandbox,
    ) -> Result<AcaSandboxRecord, AcaControlError>;

    async fn resume_sandbox(
        &self,
        lease: &AcaCredentialLease,
        context: &AcaControlContext,
        sandbox_id: &AcaSandboxId,
    ) -> Result<AcaSandboxRecord, AcaControlError>;

    async fn stop_sandbox(
        &self,
        lease: &AcaCredentialLease,
        context: &AcaControlContext,
        sandbox_id: &AcaSandboxId,
    ) -> Result<AcaSandboxRecord, AcaControlError>;

    async fn delete_sandbox(
        &self,
        lease: &AcaCredentialLease,
        context: &AcaControlContext,
        sandbox_id: &AcaSandboxId,
    ) -> Result<AcaDeleteOutcome, AcaControlError>;
}

pub type BoxAcaFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, AcaControlError>> + Send + 'a>>;

#[cfg(test)]
mod tests {
    use super::{
        AcaConfiguredDiskId, AcaCpuMillis, AcaDiskImageSource, AcaMemoryMib, AcaProfileId,
        AcaProviderConfig, AcaReadinessPolicy, AcaRuntimeConfig, AcaSandboxProfile, ResourceRef,
    };

    #[test]
    fn runtime_config_deserialization_revalidates_constructor_bounds() {
        let valid = r#"{
            "profile": {
                "profileId": "default",
                "diskImage": {"configuredDisk": {"binding_id": "image-1"}},
                "cpu": 500,
                "memory": 2048,
                "autoSuspendSecs": 300,
                "sandboxIdentityBindingId": null
            },
            "readiness": {"attempts": 3, "intervalMs": 10},
            "planTtlMs": 1000,
            "completedOperationCapacity": 4
        }"#;
        let parsed = serde_json::from_str::<AcaRuntimeConfig>(valid);
        assert!(parsed.is_ok(), "{parsed:?}");

        let invalid = valid.replace("\"cpu\": 500", "\"cpu\": 251");
        assert!(serde_json::from_str::<AcaRuntimeConfig>(&invalid).is_err());
    }

    #[test]
    fn gateway_execution_validation_has_no_host_fallback() {
        let profile = AcaSandboxProfile::new(
            AcaProfileId::parse("default").unwrap(),
            AcaDiskImageSource::ConfiguredDisk {
                binding_id: AcaConfiguredDiskId::parse("image-1").unwrap(),
            },
            AcaCpuMillis::new(500).unwrap(),
            AcaMemoryMib::new(2_048).unwrap(),
            300,
            None,
        )
        .unwrap();
        let config = AcaProviderConfig::new(
            ResourceRef::parse("Guest/gateway").unwrap(),
            super::OpaqueAzureRef::parse("tenant").unwrap(),
            super::OpaqueAzureRef::parse("client").unwrap(),
            super::OpaqueAzureRef::parse("subscription").unwrap(),
            ResourceRef::parse("Credential/control").unwrap(),
            None,
            super::AcaConfiguredImageId::parse("environment").unwrap(),
            super::AcaConfiguredImageId::parse("resource-group").unwrap(),
            None,
            AcaProfileId::parse("relay").unwrap(),
            AcaRuntimeConfig::new(
                profile,
                AcaReadinessPolicy::new(1, 1).unwrap(),
                1,
                1,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(config
            .validate_gateway_execution(&ResourceRef::parse("Guest/gateway").unwrap())
            .is_ok());
        assert!(config
            .validate_gateway_execution(&ResourceRef::parse("Host/host-system").unwrap())
            .is_err());
    }
}
