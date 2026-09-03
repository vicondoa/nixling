use d2b_contracts_resource::v3::{ResourceRef, ZoneId};
use d2b_provider_notification_desktop::{
    ActionNonceStore, ActionSpec, Category, GuestSourceConfig, NotificationController,
    NotificationProviderConfig, NotificationProviderDescriptor, NotificationRequest,
    NotificationUrgency,
};

#[test]
fn request_bounds_and_sanitization_are_closed() {
    let request = NotificationRequest::new(
        "hello\nworld",
        "body\twith content",
        Category::SecurityEvent,
    )
    .unwrap()
    .with_urgency(NotificationUrgency::Critical)
    .unwrap();
    let sanitized = request.sanitize().unwrap();
    assert_eq!(sanitized.summary(), "hello world");
    assert_eq!(sanitized.body(), "body with content");
    assert!(
        NotificationRequest::new("x", "y", Category::SecurityEvent)
            .unwrap()
            .with_icon_ref("../secret")
            .is_err()
    );
}

#[test]
fn action_ids_use_the_machine_id_bound() {
    assert!(ActionSpec::new("a".repeat(32), "label").is_ok());
    assert!(ActionSpec::new("a".repeat(33), "label").is_err());
    assert!(ActionSpec::new("open", "l".repeat(64)).is_ok());
    assert!(ActionSpec::new("open", "l".repeat(65)).is_err());
}

#[test]
fn wire_defaults_match_the_notification_contract() {
    let request: NotificationRequest = serde_json::from_value(serde_json::json!({
        "summary": "hello",
        "category": "system.info"
    }))
    .unwrap();
    assert_eq!(request.urgency(), NotificationUrgency::Normal);
    assert_eq!(request.expire_timeout_secs(), 0);
    assert!(request.actions().is_empty());
    assert!(request.icon_ref().is_none());
    assert_eq!(
        serde_json::to_value(request.category()).unwrap(),
        serde_json::json!("system.info")
    );
}

#[test]
fn action_nonces_are_single_use_ttl_bound_and_opaque() {
    let mut store = ActionNonceStore::new(2, 10);
    let nonce = store.register("session", "cancel", 100).unwrap();
    assert!(format!("{nonce:?}").contains("REDACTED"));
    let key = nonce.action_key();
    assert!(store.consume(&key, "session", 101).is_ok());
    assert!(store.consume(&key, "session", 101).is_err());
    let expired = store.register("session", "open", 100).unwrap();
    assert!(
        store
            .consume(&expired.action_key(), "session", 110)
            .is_err()
    );
    assert!(store.is_empty());
}

#[test]
fn action_id_mismatch_does_not_consume_a_live_capability() {
    let mut store = ActionNonceStore::new(2, 10);
    let nonce = store.register("session", "cancel", 100).unwrap();
    assert!(
        store
            .consume_for_action(&nonce.action_key(), "session", Some("open"), 101)
            .is_err()
    );
    assert!(
        store
            .consume_for_action(&nonce.action_key(), "session", Some("cancel"), 101)
            .is_ok()
    );
}

#[test]
fn controller_has_no_provider_state_volume_and_tracks_display_dependency() {
    let controller = NotificationController::new("Provider/notification-desktop").unwrap();
    assert!(controller.provider_state_set_empty());
    assert_eq!(
        controller.provider_ref().to_canonical_string(),
        "Provider/notification-desktop"
    );
    assert!(NotificationProviderConfig::new(Vec::new()).is_ok());
}

#[test]
fn notification_source_configuration_rejects_capacity_duplicates_and_bad_bindings() {
    let zone = ZoneId::parse("work").unwrap();
    let source = |name: &str| {
        GuestSourceConfig::new(
            ResourceRef::parse(format!("Guest/{name}").as_str()).unwrap(),
            zone.clone(),
            [Category::SystemInfo],
        )
        .unwrap()
    };
    assert_eq!(
        NotificationProviderConfig::new(vec![source("one"), source("one")]),
        Err("notification-source-duplicate")
    );
    let too_many = (0..17)
        .map(|index| source(format!("guest-{index}").as_str()))
        .collect();
    assert_eq!(
        NotificationProviderConfig::new(too_many),
        Err("notification-source-capacity")
    );
    assert_eq!(
        NotificationProviderConfig::new(vec![source("one")])
            .unwrap()
            .with_host_binding(
                ResourceRef::parse("Guest/not-a-host").unwrap(),
                ResourceRef::parse("User/alice").unwrap(),
            ),
        Err("notification-host-binding-invalid")
    );
}

#[test]
fn notification_descriptor_is_transient_and_stream_scoped() {
    let descriptor = NotificationProviderDescriptor::default();
    assert!(descriptor.validate().is_ok());
    assert_eq!(descriptor.streams().len(), 2);
    assert!(!descriptor.provider_state_volume);
}

#[test]
fn notification_component_contract_keeps_streams_out_of_resource_authority() {
    let contract = d2b_provider_notification_desktop::notification_runner_contract();
    assert_eq!(contract.service_package(), "d2b.notification.v3");
    assert_eq!(contract.repair_interval_secs(), 300);
    assert!(contract.component_session_only());
    assert!(contract.watched_configuration_is_dependency());
}
