//! Canonical Process ResourceSpec and LaunchTicket construction.

pub use d2b_contracts_resource::v3::ProcessSpec;
use d2b_contracts_resource::v3::{
    DesiredLifecycle, DeviceAccess, DeviceUsageSpec, EnvironmentClass, ExecutionSpec,
    HealthCheckClass, HealthCheckSpec, MountAccess, MountSpec, NamespaceClass, NetworkUsageSpec,
    ProcessClass, ReadinessClass, ReadinessSpec, RestartClass, RestartPolicySpec, SandboxSpec,
    TelemetrySpec,
};
use d2b_contracts_resource::v3::{
    ResourceRef,
    execution_policy::{BoundedToken, BudgetSpec, CountBudget, DurationMs, ExecutionDomain},
};
use serde::{Deserialize, Serialize};

/// Process template id.
pub const PROCESS_TEMPLATE: &str = "qemu-media-runner";

/// Attachment kind delivered through Core's private LaunchTicket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttachmentKind {
    /// KVM device fd.
    Kvm,
    /// Network tap fd.
    Tap,
    /// Media Volume fd.
    Media,
    /// Wayland display fd.
    Display,
    /// QMP Endpoint connection.
    Qmp,
    /// Serial Endpoint connection.
    Serial,
}

/// One opaque LaunchTicket slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttachmentSlot {
    /// Slot label.
    pub slot: String,
    /// Slot kind.
    pub kind: AttachmentKind,
    /// Authorizing ResourceRef.
    pub source_ref: ResourceRef,
}

/// Construct the canonical qemu-media worker Process base spec.
pub fn build_process_spec(
    execution_ref: ResourceRef,
    runtime_volume_ref: ResourceRef,
    device_ref: Option<ResourceRef>,
    network_refs: impl IntoIterator<Item = ResourceRef>,
) -> Result<ProcessSpec, ProcessSpecError> {
    if execution_ref.resource_type().as_str() != "Host"
        || runtime_volume_ref.resource_type().as_str() != "Volume"
        || device_ref
            .as_ref()
            .is_some_and(|reference| reference.resource_type().as_str() != "Device")
    {
        return Err(ProcessSpecError::InvalidReference);
    }
    let network_refs: Vec<_> = network_refs.into_iter().collect();
    if network_refs.len() > 1
        || network_refs
            .iter()
            .any(|reference| reference.resource_type().as_str() != "Network")
    {
        return Err(ProcessSpecError::InvalidReference);
    }

    let runtime_mount = MountSpec::new(
        runtime_volume_ref,
        BoundedToken::parse("runner").map_err(|_| ProcessSpecError::InvalidShape)?,
        "/run/qemu",
        MountAccess::ReadWrite,
        true,
    )
    .map_err(|_| ProcessSpecError::InvalidShape)?;
    let sandbox = SandboxSpec::new(
        vec![NamespaceClass::Pid, NamespaceClass::Mount],
        Vec::new(),
        BoundedToken::parse(PROCESS_TEMPLATE).map_err(|_| ProcessSpecError::InvalidShape)?,
        true,
        false,
        EnvironmentClass::Minimal,
        true,
        Some("0022".to_owned()),
        200,
        None,
    )
    .map_err(|_| ProcessSpecError::InvalidShape)?;
    let budget = BudgetSpec::new(
        None,
        None,
        Some(CountBudget { limit: Some(512) }),
        Some(CountBudget { limit: Some(1024) }),
        None,
        None,
        None,
    )
    .map_err(|_| ProcessSpecError::InvalidShape)?;
    let network_usage = network_refs
        .into_iter()
        .next()
        .map(|network_ref| NetworkUsageSpec::new(Some(network_ref), Vec::new(), true))
        .transpose()
        .map_err(|_| ProcessSpecError::InvalidShape)?;
    let device_usage = device_ref
        .map(|device_ref| {
            DeviceUsageSpec::new(device_ref, DeviceAccess::Shared, "kvm-acceleration")
        })
        .transpose()
        .map_err(|_| ProcessSpecError::InvalidShape)?
        .into_iter()
        .collect();
    let execution = ExecutionSpec::new(
        execution_ref,
        Some(ExecutionDomain::System),
        None,
        ProcessClass::Worker,
        BoundedToken::parse(PROCESS_TEMPLATE).map_err(|_| ProcessSpecError::InvalidShape)?,
        None,
        Vec::new(),
        vec![runtime_mount],
        sandbox,
        budget,
        network_usage,
        device_usage,
        TelemetrySpec::default(),
    )
    .map_err(|_| ProcessSpecError::InvalidShape)?;
    let process = ProcessSpec::new(
        execution,
        DesiredLifecycle::Running,
        RestartPolicySpec::new(
            RestartClass::Never,
            duration("1s", 0, 60_000)?,
            duration("60s", 1_000, 3_600_000)?,
            2_000,
            None,
            duration("300s", 0, 86_400_000)?,
        )
        .map_err(|_| ProcessSpecError::InvalidShape)?,
        ReadinessSpec::new(
            duration("0s", 0, 300_000)?,
            duration("30s", 1_000, 300_000)?,
            1,
            1,
            ReadinessClass::ProviderDefined,
        )
        .map_err(|_| ProcessSpecError::InvalidShape)?,
        HealthCheckSpec::new(
            true,
            duration("10s", 1_000, 3_600_000)?,
            duration("5s", 1_000, 60_000)?,
            3,
            HealthCheckClass::ProviderDefined,
        )
        .map_err(|_| ProcessSpecError::InvalidShape)?,
        d2b_contracts_resource::v3::AdoptionPolicy::AdoptOnRestart,
        duration("30s", 0, 3_600_000)?,
    )
    .map_err(|_| ProcessSpecError::InvalidShape)?;
    validate_process_spec(&process)?;
    Ok(process)
}

/// Validate a qemu-media Process against the canonical v3 Process contract.
pub fn validate_process_spec(process: &ProcessSpec) -> Result<(), ProcessSpecError> {
    let encoded = serde_json::to_vec(process).map_err(|_| ProcessSpecError::InvalidShape)?;
    let decoded: ProcessSpec =
        serde_json::from_slice(&encoded).map_err(|_| ProcessSpecError::InvalidShape)?;
    if decoded != *process {
        return Err(ProcessSpecError::InvalidShape);
    }
    let execution = process.execution();
    if execution.execution_ref().resource_type().as_str() != "Host"
        || execution.process_class() != ProcessClass::Worker
        || execution.template().as_str() != PROCESS_TEMPLATE
        || execution.sandbox().namespace_classes() != [NamespaceClass::Pid, NamespaceClass::Mount]
        || !execution.sandbox().capability_classes().is_empty()
        || !execution.sandbox().no_new_privileges()
        || execution.sandbox().start_root()
        || !execution.sandbox().read_only_root()
        || execution.sandbox().seccomp_class().as_str() != PROCESS_TEMPLATE
        || execution.device_usage().len() > 1
        || process.restart_policy().class() != RestartClass::Never
        || process.desired_lifecycle() != DesiredLifecycle::Running
    {
        return Err(ProcessSpecError::InvalidShape);
    }
    if execution.mounts().len() != 1
        || execution.mounts()[0].mount_path() != "/run/qemu"
        || execution.mounts()[0].view().as_str() != "runner"
    {
        return Err(ProcessSpecError::InvalidShape);
    }
    Ok(())
}

fn duration(value: &str, min_millis: u64, max_millis: u64) -> Result<DurationMs, ProcessSpecError> {
    DurationMs::parse(value, min_millis, max_millis).map_err(|_| ProcessSpecError::InvalidShape)
}

/// Opaque Core LaunchTicket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LaunchTicket {
    /// Process resource template.
    pub process: ProcessSpec,
    /// Authorized attachment slots.
    pub attachments: Vec<AttachmentSlot>,
}

impl LaunchTicket {
    /// Construct a ticket from already-authorized refs.
    pub fn new(
        process: ProcessSpec,
        media_refs: impl IntoIterator<Item = ResourceRef>,
        display_ref: Option<ResourceRef>,
    ) -> Result<Self, ProcessSpecError> {
        validate_process_spec(&process)?;
        let media_refs = media_refs.into_iter().collect::<Vec<_>>();
        if media_refs.len() > 4
            || media_refs
                .iter()
                .any(|reference| reference.resource_type().as_str() != "Volume")
            || {
                let mut seen = std::collections::BTreeSet::new();
                media_refs.iter().any(|reference| !seen.insert(reference))
            }
        {
            return Err(ProcessSpecError::InvalidReference);
        }
        let mut attachments = Vec::new();
        if let Some(device_ref) = process.execution().device_usage().first() {
            attachments.push(AttachmentSlot {
                slot: "kvm".to_owned(),
                kind: AttachmentKind::Kvm,
                source_ref: device_ref.device_ref().clone(),
            });
        }
        if let Some(network_ref) = process
            .execution()
            .network_usage()
            .and_then(|usage| usage.network_ref())
        {
            attachments.push(AttachmentSlot {
                slot: "tap-0".to_owned(),
                kind: AttachmentKind::Tap,
                source_ref: network_ref.clone(),
            });
        }
        for (index, reference) in media_refs.into_iter().enumerate() {
            attachments.push(AttachmentSlot {
                slot: format!("media-{index}"),
                kind: AttachmentKind::Media,
                source_ref: reference,
            });
        }
        if let Some(reference) = display_ref {
            if reference.resource_type().as_str() != "Endpoint" {
                return Err(ProcessSpecError::InvalidReference);
            }
            attachments.push(AttachmentSlot {
                slot: "display".to_owned(),
                kind: AttachmentKind::Display,
                source_ref: reference,
            });
        }
        let ticket = Self {
            process,
            attachments,
        };
        ticket.validate()?;
        Ok(ticket)
    }

    /// Validate unique slot labels and typed sources.
    pub fn validate(&self) -> Result<(), ProcessSpecError> {
        validate_process_spec(&self.process)?;
        let mut slots = std::collections::BTreeSet::new();
        for attachment in &self.attachments {
            if !valid_slot(&attachment.slot) || !slots.insert(&attachment.slot) {
                return Err(ProcessSpecError::DuplicateAttachmentSlot);
            }
            let expected = match attachment.kind {
                AttachmentKind::Kvm => "Device",
                AttachmentKind::Tap => "Network",
                AttachmentKind::Media => "Volume",
                AttachmentKind::Display | AttachmentKind::Qmp | AttachmentKind::Serial => {
                    "Endpoint"
                }
            };
            if attachment.source_ref.resource_type().as_str() != expected {
                return Err(ProcessSpecError::InvalidReference);
            }
        }
        Ok(())
    }
}

/// Process spec failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessSpecError {
    /// A reference has the wrong ResourceType.
    InvalidReference,
    /// The canonical Process shape was changed.
    InvalidShape,
    /// Two attachment slots have the same label.
    DuplicateAttachmentSlot,
}

fn valid_slot(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}
