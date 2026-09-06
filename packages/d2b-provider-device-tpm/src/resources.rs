//! Canonical child-resource builders for the TPM Provider.

use d2b_contracts_resource::v3::execution_policy::{BoundedToken, DurationMs, ExecutionDomain};
use d2b_contracts_resource::v3::{
    AdoptionPolicy, DesiredLifecycle, EphemeralProcessSpec, ExecutionSpec, HealthCheckClass,
    HealthCheckSpec, MappingClass, MountAccess, MountSpec, NamespaceClass, ProcessClass,
    ProcessSpec, ReadinessClass, ReadinessSpec, ResourceRef, ResourceUid, RestartClass,
    RestartPolicySpec, SandboxSpec, TelemetrySpec, UserNamespaceSpec,
};
use serde_json::{Value, json};

use crate::resource_effect::TpmResourceEffectError;

fn device_short(device_uid: &ResourceUid) -> String {
    device_uid
        .as_str()
        .bytes()
        .filter(|byte| byte.is_ascii_hexdigit())
        .take(32)
        .map(char::from)
        .collect()
}

/// Build the controller-created TPM state Volume spec.
///
/// The returned document contains only opaque policy references. In
/// particular, it has no host path, socket, UID, GID, or binary field.
pub fn build_tpm_state_volume_spec(
    device_uid: &ResourceUid,
    execution_ref: &ResourceRef,
) -> Result<Value, TpmResourceEffectError> {
    let short = device_short(device_uid);
    build_tpm_state_volume_spec_with_short(&short, execution_ref)
}

fn build_tpm_state_volume_spec_with_short(
    short: &str,
    execution_ref: &ResourceRef,
) -> Result<Value, TpmResourceEffectError> {
    if execution_ref.resource_type().as_str() != "Host" {
        return Err(TpmResourceEffectError::InvalidExecutionRef);
    }
    if short.len() != 32 {
        return Err(TpmResourceEffectError::InvalidDevice);
    }
    let owner = format!("User/device-{short}-swtpm-system");
    Ok(json!({
        "providerRef": "Provider/volume-local",
        "source": {
            "executionRef": execution_ref.to_canonical_string(),
            "settings": {
                "kind": "local-path",
                "sourcePolicyId": "tpm-state"
            }
        },
        "kind": "state",
        "layout": [{
            "path": "",
            "type": "directory",
            "ownerRef": owner,
            "groupRef": owner,
            "mode": "0700",
            "sensitivity": "secret-adjacent",
            "createPolicy": "create-if-never-provisioned",
            "repairPolicy": "fail-closed",
            "cleanupPolicy": "never",
            "adoptionPolicy": "quarantine-on-ambiguity",
            "restartPolicy": "preserve-across-controller-restart",
            "leaseClass": "none",
            "noFollow": true,
            "recursive": false,
            "foreignChildPolicy": "preserve",
            "accessAcl": [],
            "defaultAcl": [],
            "invariants": [
                "no-symlink",
                "broker-opaque-id-only",
                "scope-authorization-required"
            ],
            "target": null
        }],
        "views": {
            "swtpm-process": {
                "path": "",
                "rights": ["read", "write", "create", "traverse"]
            },
            "controller": {
                "path": "",
                "rights": ["read", "write", "create", "delete", "traverse"]
            }
        },
        "attachments": [],
        "quota": null
    }))
}

/// Build a complete controller-created TPM state Volume resource document.
pub fn build_tpm_state_volume_resource(
    device_uid: &ResourceUid,
    device_ref: &ResourceRef,
    zone: &str,
    execution_ref: &ResourceRef,
) -> Result<Value, TpmResourceEffectError> {
    if device_ref.resource_type().as_str() != "Device" {
        return Err(TpmResourceEffectError::InvalidDevice);
    }
    let short = device_short(device_uid);
    let spec = build_tpm_state_volume_spec_with_short(&short, execution_ref)?;
    Ok(serde_json::json!({
        "apiVersion": "resources.d2bus.org/v3",
        "type": "Volume",
        "metadata": {
            "name": format!("device-{short}-tpm-state"),
            "zone": zone,
            "ownerRef": device_ref.to_canonical_string(),
            "managedBy": "controller"
        },
        "spec": spec
    }))
}

/// Build the long-lived swtpm Process base spec.
pub fn build_swtpm_process_spec(
    device_uid: &ResourceUid,
    execution_ref: &ResourceRef,
) -> Result<Value, TpmResourceEffectError> {
    if execution_ref.resource_type().as_str() != "Host" {
        return Err(TpmResourceEffectError::InvalidExecutionRef);
    }
    let execution = swtpm_execution(
        device_uid,
        execution_ref,
        ProcessClass::Worker,
        "swtpm-socket",
        vec![swtpm_mount(device_uid)?],
    )?;
    serde_json::to_value(
        ProcessSpec::new(
            execution,
            DesiredLifecycle::Running,
            RestartPolicySpec::new(
                RestartClass::OnFailure,
                DurationMs::parse("1s", 0, 60_000).unwrap(),
                DurationMs::parse("60s", 1_000, 3_600_000).unwrap(),
                2_000,
                None,
                DurationMs::parse("300s", 0, 86_400_000).unwrap(),
            )
            .map_err(|_| TpmResourceEffectError::InvalidDevice)?,
            ReadinessSpec::new(
                DurationMs::parse("0s", 0, 3_600_000).unwrap(),
                DurationMs::parse("30s", 1_000, 3_600_000).unwrap(),
                3,
                1,
                ReadinessClass::ProviderDefined,
            )
            .map_err(|_| TpmResourceEffectError::InvalidDevice)?,
            HealthCheckSpec::new(
                false,
                DurationMs::parse("30s", 1_000, 3_600_000).unwrap(),
                DurationMs::parse("5s", 1_000, 3_600_000).unwrap(),
                3,
                HealthCheckClass::ProviderDefined,
            )
            .map_err(|_| TpmResourceEffectError::InvalidDevice)?,
            AdoptionPolicy::AdoptOnRestart,
            DurationMs::parse("30s", 0, 3_600_000).unwrap(),
        )
        .map_err(|_| TpmResourceEffectError::InvalidDevice)?,
    )
    .map_err(|_| TpmResourceEffectError::InvalidDevice)
}

/// Build the mandatory pre-start flush EphemeralProcess spec.
pub fn build_swtpm_flush_spec(
    device_uid: &ResourceUid,
    execution_ref: &ResourceRef,
) -> Result<Value, TpmResourceEffectError> {
    if execution_ref.resource_type().as_str() != "Host" {
        return Err(TpmResourceEffectError::InvalidExecutionRef);
    }
    let execution = swtpm_execution(
        device_uid,
        execution_ref,
        ProcessClass::Worker,
        "swtpm-init-flush",
        Vec::new(),
    )?;
    serde_json::to_value(
        EphemeralProcessSpec::new(
            execution,
            DurationMs::parse("30s", 1_000, 3_600_000).unwrap(),
            DurationMs::parse("60s", 1_000, 86_400_000).unwrap(),
            DurationMs::parse("1h", 0, 7 * 86_400_000).unwrap(),
            DurationMs::parse("24h", 0, 30 * 86_400_000).unwrap(),
            false,
        )
        .map_err(|_| TpmResourceEffectError::InvalidDevice)?,
    )
    .map_err(|_| TpmResourceEffectError::InvalidDevice)
}

fn swtpm_mount(device_uid: &ResourceUid) -> Result<MountSpec, TpmResourceEffectError> {
    let short = device_short(device_uid);
    MountSpec::new(
        ResourceRef::parse(&format!("Volume/device-{short}-tpm-state"))
            .map_err(|_| TpmResourceEffectError::InvalidDevice)?,
        BoundedToken::parse("swtpm-process").map_err(|_| TpmResourceEffectError::InvalidDevice)?,
        "/state",
        MountAccess::ReadWrite,
        true,
    )
    .map_err(|_| TpmResourceEffectError::InvalidDevice)
}

fn swtpm_execution(
    device_uid: &ResourceUid,
    execution_ref: &ResourceRef,
    process_class: ProcessClass,
    template: &str,
    mounts: Vec<MountSpec>,
) -> Result<ExecutionSpec, TpmResourceEffectError> {
    let principal = ResourceRef::parse(&format!(
        "User/device-{}-swtpm-system",
        device_short(device_uid)
    ))
    .map_err(|_| TpmResourceEffectError::InvalidDevice)?;
    ExecutionSpec::new(
        execution_ref.clone(),
        Some(ExecutionDomain::System),
        Some(principal),
        process_class,
        BoundedToken::parse(template).map_err(|_| TpmResourceEffectError::InvalidDevice)?,
        None,
        Vec::new(),
        mounts,
        SandboxSpec::new(
            vec![
                NamespaceClass::Pid,
                NamespaceClass::Mount,
                NamespaceClass::User,
            ],
            Vec::new(),
            BoundedToken::parse("strict").map_err(|_| TpmResourceEffectError::InvalidDevice)?,
            true,
            false,
            d2b_contracts_resource::v3::EnvironmentClass::Minimal,
            true,
            Some("0022".to_owned()),
            0,
            Some(UserNamespaceSpec {
                mapping_class: MappingClass::ProcessPrincipalRoot,
            }),
        )
        .map_err(|_| TpmResourceEffectError::InvalidDevice)?,
        Default::default(),
        None,
        Vec::new(),
        TelemetrySpec::default(),
    )
    .map_err(|_| TpmResourceEffectError::InvalidDevice)
}

#[cfg(test)]
mod tests {
    use super::*;
    use d2b_contracts_resource::v3::{EphemeralProcessSpec, ProcessSpec};

    fn device_uid() -> ResourceUid {
        ResourceUid::parse("6f9619ff-8b86-4d01-b42d-00cf4fc964ff").unwrap()
    }

    #[test]
    fn generated_process_specs_round_trip_through_v3_contracts() {
        let device = device_uid();
        let host = ResourceRef::parse("Host/host-system").unwrap();

        let process = build_swtpm_process_spec(&device, &host).unwrap();
        let process: ProcessSpec = serde_json::from_value(process).unwrap();
        assert_eq!(process.execution().process_class(), ProcessClass::Worker);
        assert_eq!(process.execution().mounts().len(), 1);
        assert_eq!(process.execution().mounts()[0].mount_path(), "/state");
        assert_eq!(
            process
                .execution()
                .user_ref()
                .unwrap()
                .to_canonical_string(),
            "User/device-6f9619ff8b864d01b42d00cf4fc964ff-swtpm-system"
        );
        assert_eq!(
            process.execution().sandbox().namespace_classes(),
            [
                NamespaceClass::Pid,
                NamespaceClass::Mount,
                NamespaceClass::User
            ]
        );
        assert!(process.execution().sandbox().user_namespace().is_some());
        let process_json = serde_json::to_value(&process).unwrap();
        assert_eq!(process_json["restartPolicy"]["class"], "on-failure");
        assert_eq!(process_json["healthCheck"]["enabled"], false);

        let flush = build_swtpm_flush_spec(&device, &host).unwrap();
        let flush: EphemeralProcessSpec = serde_json::from_value(flush).unwrap();
        assert_eq!(flush.execution().process_class(), ProcessClass::Worker);
        assert!(flush.execution().mounts().is_empty());
        let flush_json = serde_json::to_value(&flush).unwrap();
        assert_eq!(flush_json["startDeadline"], "30s");
        assert_eq!(flush_json["runtimeDeadline"], "60s");
    }

    #[test]
    fn state_volume_owner_is_the_authenticated_device_reference() {
        let device = device_uid();
        let device_ref = ResourceRef::parse("Device/vm-tpm").unwrap();
        let host = ResourceRef::parse("Host/host-system").unwrap();
        let resource = build_tpm_state_volume_resource(&device, &device_ref, "dev", &host).unwrap();

        assert_eq!(
            resource["metadata"]["ownerRef"],
            serde_json::json!("Device/vm-tpm")
        );
        assert_ne!(
            resource["metadata"]["ownerRef"],
            serde_json::json!(format!("Device/{device}"))
        );
    }

    #[test]
    fn state_child_names_preserve_the_full_device_incarnation() {
        let first = ResourceUid::parse("6f9619ff-8b86-4d01-b42d-00cf4fc964ff").unwrap();
        let second = ResourceUid::parse("6f9619ff-8b86-4d01-b42d-00cf4fc96500").unwrap();
        let device_ref = ResourceRef::parse("Device/vm-tpm").unwrap();
        let host = ResourceRef::parse("Host/host-system").unwrap();

        let first_resource =
            build_tpm_state_volume_resource(&first, &device_ref, "dev", &host).unwrap();
        let second_resource =
            build_tpm_state_volume_resource(&second, &device_ref, "dev", &host).unwrap();

        assert_ne!(
            first_resource["metadata"]["name"],
            second_resource["metadata"]["name"]
        );
    }

    #[test]
    fn flush_builder_rejects_non_host_execution_refs() {
        let device = device_uid();
        let zone = ResourceRef::parse("Zone/dev").unwrap();

        assert!(matches!(
            build_swtpm_flush_spec(&device, &zone),
            Err(TpmResourceEffectError::InvalidExecutionRef)
        ));
    }
}
