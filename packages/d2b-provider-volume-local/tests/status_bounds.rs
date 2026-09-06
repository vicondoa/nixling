use d2b_contracts_resource::v3::{
    CanonicalJsonObject, ConditionState, ExtensionSchemaId, ObservedGeneration,
    ProviderStatusExtension, ResourceCondition, ResourceCurrencySet, ResourceErrorKind,
    ResourceGeneration, ResourcePhase, ResourceRef, ResourceStatus, ResourceStatusError,
    ResourceUid, ResourceUpdateStatus, SchemaVersion, StatusCode, StatusMessage, Timestamp,
    UpdateDisruption, UpdateState, canonical_json_bytes,
    execution_policy::{BoundedToken, to_base_object},
    resource_status::{
        MAX_STATUS_BYTES, MAX_STATUS_COLLECTION_ENTRIES, MAX_STATUS_CONDITIONS,
        MAX_STATUS_LAYER_BYTES,
    },
    volume::{AttachmentAccess, VolumeKind},
};
use d2b_provider_volume_local::{
    AttachmentState, AttachmentStatus, ConditionSeverity, EntryCondition, EntryDigest, LayoutPhase,
    VolumeLocalError, VolumeStatusReport,
};

fn update_status() -> ResourceUpdateStatus {
    let empty = || ResourceCurrencySet::new(0, Vec::new()).unwrap();
    ResourceUpdateStatus::new(
        UpdateState::Current,
        Vec::new(),
        ObservedGeneration::new(1),
        ResourceGeneration::new(1).unwrap(),
        UpdateDisruption::None,
        true,
        None,
        None,
        empty(),
        empty(),
    )
    .unwrap()
}

fn report() -> VolumeStatusReport {
    let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
    VolumeStatusReport {
        provider: BoundedToken::parse("volume-local").unwrap(),
        kind: VolumeKind::State,
        layout_phase: LayoutPhase::Degraded,
        layout_conditions: vec![EntryCondition {
            entry: EntryDigest::derive(&uid, "private-entry"),
            reason: VolumeLocalError::EntryDrift,
            severity: ConditionSeverity::Degraded,
        }],
        attachment_statuses: vec![AttachmentStatus {
            execution_ref: ResourceRef::parse("Guest/work").unwrap(),
            view: BoundedToken::parse("main").unwrap(),
            access: AttachmentAccess::ReadWrite,
            state: AttachmentState::Pending,
            export_ready: false,
            guest_mount_ready: false,
        }],
        content: None,
    }
}

fn status_with_layers(
    resource: CanonicalJsonObject,
    provider: Option<ProviderStatusExtension>,
) -> Result<ResourceStatus, ResourceStatusError> {
    ResourceStatus::new(
        ObservedGeneration::new(1),
        ResourcePhase::Degraded,
        Vec::new(),
        None,
        None,
        None,
        None,
        update_status(),
        resource,
        provider,
    )
}

fn provider_extension(
    details: CanonicalJsonObject,
) -> Result<ProviderStatusExtension, ResourceStatusError> {
    ProviderStatusExtension::new(
        ResourceRef::parse("Provider/volume-local").unwrap(),
        ExtensionSchemaId::parse("volume-local.d2bus.org/Volume/status").unwrap(),
        SchemaVersion::new(1, 0).unwrap(),
        ResourceGeneration::new(1).unwrap(),
        details,
    )
}

fn object_with_strings(prefix: &str, count: usize, length: usize) -> CanonicalJsonObject {
    let fields = (0..count)
        .map(|index| format!(r#""{prefix}{index}":"{}""#, "x".repeat(length)))
        .collect::<Vec<_>>()
        .join(",");
    CanonicalJsonObject::parse(format!("{{{fields}}}").as_bytes()).unwrap()
}

fn typed_oversize(error: ResourceStatusError) -> ResourceErrorKind {
    assert!(matches!(
        error,
        ResourceStatusError::StatusStringTooLong
            | ResourceStatusError::TooManyConditions
            | ResourceStatusError::StatusCollectionTooLarge
            | ResourceStatusError::StatusLayerTooLarge
            | ResourceStatusError::StatusTooLarge
    ));
    ResourceErrorKind::StatusOversize
}

#[test]
fn volume_projection_is_admitted_by_the_canonical_status_bounds() {
    let resource = to_base_object(&report()).unwrap();
    assert!(resource.to_canonical_bytes().len() < MAX_STATUS_LAYER_BYTES);
    let status = status_with_layers(resource, None).unwrap();
    assert!(canonical_json_bytes(&status).unwrap().len() < MAX_STATUS_BYTES);
}

#[test]
fn total_and_provider_detail_caps_reject_with_status_oversize() {
    let provider_error = provider_extension(object_with_strings("detail", 9, 4_000))
        .expect_err("provider detail over 32 KiB must fail");
    assert_eq!(typed_oversize(provider_error).as_str(), "status-oversize");

    let resource = object_with_strings("resource", 8, 4_080);
    let details = object_with_strings("detail", 8, 4_080);
    assert!(resource.to_canonical_bytes().len() <= MAX_STATUS_LAYER_BYTES);
    assert!(details.to_canonical_bytes().len() <= MAX_STATUS_LAYER_BYTES);
    let provider = provider_extension(details).unwrap();
    let total_error = status_with_layers(resource, Some(provider))
        .expect_err("combined canonical status over 64 KiB must fail");
    assert_eq!(
        typed_oversize(total_error),
        ResourceErrorKind::StatusOversize
    );
}

#[test]
fn condition_list_and_map_cardinality_caps_are_typed_rejections() {
    let conditions = (0..=MAX_STATUS_CONDITIONS)
        .map(|index| {
            ResourceCondition::new(
                StatusCode::parse(format!("condition-{index}")).unwrap(),
                ConditionState::True,
                StatusCode::parse("observed").unwrap(),
                StatusMessage::parse("bounded").unwrap(),
                ObservedGeneration::new(1),
                Timestamp::parse("2026-07-22T00:00:01.000Z").unwrap(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        typed_oversize(
            ResourceStatus::new(
                ObservedGeneration::new(1),
                ResourcePhase::Ready,
                conditions,
                None,
                None,
                None,
                None,
                update_status(),
                CanonicalJsonObject::empty(),
                None,
            )
            .unwrap_err()
        ),
        ResourceErrorKind::StatusOversize
    );

    let values = (0..=MAX_STATUS_COLLECTION_ENTRIES)
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let list = CanonicalJsonObject::parse(format!("{{\"items\":[{values}]}}").as_bytes()).unwrap();
    assert_eq!(
        typed_oversize(provider_extension(list).unwrap_err()),
        ResourceErrorKind::StatusOversize
    );

    let fields = (0..=MAX_STATUS_COLLECTION_ENTRIES)
        .map(|index| format!("\"field-{index}\":{index}"))
        .collect::<Vec<_>>()
        .join(",");
    let map = CanonicalJsonObject::parse(format!("{{\"map\":{{{fields}}}}}").as_bytes()).unwrap();
    assert_eq!(
        typed_oversize(provider_extension(map).unwrap_err()),
        ResourceErrorKind::StatusOversize
    );
}

#[test]
fn volume_status_carries_only_the_bounded_public_projection() {
    let json = serde_json::to_value(report()).unwrap();
    let object = json.as_object().unwrap();
    assert_eq!(
        object.keys().map(String::as_str).collect::<Vec<_>>(),
        [
            "attachmentStatuses",
            "kind",
            "layoutConditions",
            "layoutPhase",
            "provider",
        ]
    );

    let rendered = serde_json::to_string(&json).unwrap();
    for forbidden in [
        "secret",
        "path",
        "argv",
        "pid",
        "unit",
        "stream",
        "ring",
        "private-entry",
    ] {
        assert!(
            !rendered.to_ascii_lowercase().contains(forbidden),
            "forbidden status content class was serialized"
        );
    }
}
